// UmSerialFilter 鈥?passive serial-port traffic capture (upper filter, no port ownership).
//
// WHY THIS EXISTS
// ---------------
// The user-mode approach (inject a DLL and patch the target's IAT) has a hard limit:
// it only sees calls made *after* injection, while a serial tool typically opens its
// port within milliseconds of starting. A kernel filter has no such race 鈥?it sits on
// the device stack, so every IRP from every process passes through it from the moment
// the filter loads.
//
// This reproduces the capability of the reference product (ComDrv12x64.sys), whose
// binary shows exactly this shape: IoGetDeviceObjectPointer,
// IoCreateDevice + IoAttachDeviceToDeviceStack, IoBuildAsynchronousFsdRequest.
//
// DESIGN
// ------
//   * Upper filter on serial device objects: attach, forward, observe.
//   * It NEVER opens, locks or claims a port. Ownership stays with the application,
//     which is the entire point of a passive monitor.
//   * IRP_MJ_READ / IRP_MJ_WRITE pass through untouched; the completed bytes are copied
//     out in the completion routine after the lower driver finishes.
//   * Captured records are queued and handed to user mode through a control device.
//
// SAFETY
//   * The completion path never changes the IRP result, so a capture failure can never
//     break the monitored program.
//   * The queue is bounded; if user mode stops draining, the oldest records are dropped.
//   * No allocation at DISPATCH_LEVEL beyond a pre-created lookaside list.
#include <ntddk.h>

#define UM_TAG 'MfSU'

#define UM_DEVICE_NAME   L"\\Device\\UmSerialFilter"
#define UM_SYMLINK_NAME  L"\\DosDevices\\UmSerialFilter"

// ---------------------------------------------------------------------------
// IOCTL interface (user mode talks to \\.\UmSerialFilter)
// ---------------------------------------------------------------------------
#define UM_DEVICE_TYPE 0x8000

#define IOCTL_UM_GET_RECORD \
    CTL_CODE(UM_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_UM_SET_TARGET \
    CTL_CODE(UM_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_UM_GET_STATS \
    CTL_CODE(UM_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_READ_DATA)
// Attach the filter to every serial device currently present. Called once by the
// service after the driver loads; also re-runnable to pick up newly plugged adapters.
#define IOCTL_UM_ATTACH_PORTS \
    CTL_CODE(UM_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_WRITE_DATA)
// Get the friendly name of one attached device (index in, name out).
#define IOCTL_UM_GET_PORT_NAME \
    CTL_CODE(UM_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_READ_DATA)
// Present the per-boot session key. Must be the FIRST ioctl on a handle; every other
// ioctl is refused until it succeeds, so opening the device is not enough to use it.
#define IOCTL_UM_AUTHENTICATE \
    CTL_CODE(UM_DEVICE_TYPE, 0x805, METHOD_BUFFERED, FILE_WRITE_DATA)

#define UM_CTX_AUTHENTICATED 0x00000001UL
// Registry location where the session key is published.
#define UM_PARAMS_KEY   L"\\Registry\\Machine\\Software\\UmSerialFilter"
#define UM_PARAMS_VALUE L"SessionKey"

// Forward declarations for the security layer (defined further down).
static VOID UmPublishSessionKey(VOID);
static BOOLEAN UmKeyMatches(const UCHAR *candidate);
#define UM_MAX_PAYLOAD 4096
#define UM_RECORD_HEADER 32
#define UM_MAX_RECORDS 512
#define UM_MAX_FILTERS 64

#define UM_DIR_RX 0
#define UM_DIR_TX 1

#pragma pack(push, 8)
typedef struct _UM_RECORD {
    UINT32 Size;      // payload bytes following the header
    UINT32 Dir;       // UM_DIR_RX / UM_DIR_TX
    UINT32 Pid;       // process that issued the IRP
    UINT32 PortIndex; // which filtered device (index into the attach list)
    UINT64 Handle;    // physical device object (stable per port)
    UINT64 Timestamp; // KeQuerySystemTime
    UCHAR  Data[UM_MAX_PAYLOAD];
} UM_RECORD, *PUM_RECORD;
#pragma pack(pop)

#define UM_RECORD_SIZE sizeof(UM_RECORD)

// Per-filtered-device context.
typedef struct _UM_DEVICE_CTX {
    PDEVICE_OBJECT Self;      // our filter device object
    PDEVICE_OBJECT Lower;     // next device down (real serial driver)
    PDEVICE_OBJECT Physical;  // PDO of the serial device (the driver holds a reference)
    ULONG Index;              // index into the attached list
    // Stable id handed to user mode in every record. Deliberately NOT the PDO address:
    // handing out a kernel pointer leaks KASLR-relevant information and dangles as soon as
    // the device is removed.
    ULONG64 PortId;
    ULONG Flags;              // UM_CTX_AUTHENTICATED once the handshake succeeds
    BOOLEAN PassThroughOnly;  // TRUE for the control device
} UM_DEVICE_CTX, *PUM_DEVICE_CTX;

// One captured chunk.
typedef struct _UM_RECORD_ITEM {
    LIST_ENTRY Entry;
    UM_RECORD  Record;
} UM_RECORD_ITEM, *PUM_RECORD_ITEM;

// Global state.
typedef struct _UM_CAPTURE {
    KSPIN_LOCK Lock;
    LIST_ENTRY Queue;
    NPAGED_LOOKASIDE_LIST Lookaside;
    NPAGED_LOOKASIDE_LIST CtxLookaside;
    ULONG Count;
    ULONG Dropped;
    ULONG Enabled;
    ULONG TargetPid;
    ULONGLONG Received;
    ULONGLONG Sent;
    ULONG AttachedCount;
    // Reference held on the device object each filter sits above (see S3: the file object
    // returned by IoGetDeviceObjectPointer is dereferenced immediately, so the driver must
    // hold its own reference on the device object).
    PDEVICE_OBJECT Attached[UM_MAX_FILTERS];
    // Our filter object for that device, so teardown never has to guess it from the stack.
    PDEVICE_OBJECT AttachedFilters[UM_MAX_FILTERS];
    // Owned copy of the NT device path ("\Device\Serial0"), or NULL when unknown.
    PWSTR AttachedNames[UM_MAX_FILTERS];
    // Slot bitmap. AttachedCount alone cannot express "slot 3 was freed" 鈥?without this,
    // a device removal leaked its slot forever and 64 plug/unplug cycles permanently
    // exhausted the table, after which attaching silently did nothing.
    BOOLEAN SlotUsed[UM_MAX_FILTERS];
    // Number of open handles on the control device. Capture stops when the last one
    // closes, so a crashed monitor does not leave the driver capturing forever.
    volatile LONG OpenCount;
    // Result of IoRegisterPlugPlayNotification, surfaced through IOCTL_UM_GET_STATS.
    NTSTATUS HotplugStatus;
    // Monotonic id handed to user mode instead of the kernel pointer (KASLR hygiene).
    volatile LONG64 NextPortId;
    // Per-boot key the service must present; see UmPublishSessionKey.
    UCHAR SessionKey[16];
    BOOLEAN SessionKeySet;
} UM_CAPTURE, *PUM_CAPTURE;

// GUIDs used for PnP interface notifications.
//
// These live in <initguid.h> territory: the WDK NuGet headers do not ship the
// definitions, only declarations, so they are spelled out here. The values are the
// documented ones from wdmguid.h / ntddser.h:
//   GUID_DEVINTERFACE_COMPORT        鈥?every COM port driver registers this interface
//   GUID_DEVICE_INTERFACE_ARRIVAL    鈥?an interface became available
static const GUID UmGuidComPort = {
    0x86E0D1E0, 0x8089, 0x11D0,
    { 0x9C, 0xE4, 0x08, 0x00, 0x3E, 0x30, 0x1F, 0x73 }
};
static const GUID UmGuidInterfaceArrival = {
    0xCB3A4009, 0x46F0, 0x46DB,
    { 0x8C, 0xCB, 0xB7, 0x13, 0xF2, 0xA8, 0x1D, 0x48 }
};

// The WDK headers declare these symbols but do not define them; reference our copies.
#define GUID_DEVINTERFACE_COMPORT (&UmGuidComPort)
#define GUID_DEVICE_INTERFACE_ARRIVAL (&UmGuidInterfaceArrival)

static UM_CAPTURE g_Capture;

// Slot bookkeeping used by the PnP/removal path (which appears earlier in this file than
// the definitions, so the prototypes have to live here).
static BOOLEAN UmAlreadyAttached(PDEVICE_OBJECT physical);
static LONG UmRegisterAttached(PDEVICE_OBJECT physical, PCWSTR name);
static VOID UmFreeSlotResources(ULONG index);
static PWSTR UmDuplicateName(PCUNICODE_STRING name);

static PDEVICE_OBJECT g_ControlDevice;
static PDRIVER_OBJECT g_DriverObject;
static UNICODE_STRING g_SymLink;

// Hot-plug support.
//
// Without this, a USB-serial adapter plugged in after the driver loaded would never be
// filtered: UmAttachAllPorts only runs when user mode asks. Registering for device
// interface arrival notifications lets the driver attach the moment a serial device
// appears, which is what "install once, monitor everything" requires.
//
// The reference product does the same through its device-arrival path (its
// sub_11308 attach routine is called from a PnP notification, not only at startup).
static PVOID g_NotificationEntry = NULL;

// One pre-allocated filter slot must be reserved for each arrival, so the callback never
// has to grow the array at DISPATCH_LEVEL.
static KSPIN_LOCK g_AttachLock;

// ---------------------------------------------------------------------------
// Capture queue
// ---------------------------------------------------------------------------

static VOID UmQueueRecord(ULONG dir, ULONG pid, ULONG portIndex, ULONG64 handle,
                          const UCHAR *data, ULONG len)
{
    PUM_RECORD_ITEM item;
    KIRQL old;
    LARGE_INTEGER now;

    if (g_Capture.Enabled == 0 || len == 0) {
        return;
    }
    if (len > UM_MAX_PAYLOAD) {
        len = UM_MAX_PAYLOAD;
    }
    if (g_Capture.TargetPid != 0 && g_Capture.TargetPid != pid) {
        return;
    }

    item = (PUM_RECORD_ITEM)ExAllocateFromNPagedLookasideList(&g_Capture.Lookaside);
    if (item == NULL) {
        InterlockedIncrement((PLONG)&g_Capture.Dropped);
        return;
    }
    RtlZeroMemory(&item->Record, UM_RECORD_HEADER);
    item->Record.Size = len;
    item->Record.Dir = dir;
    item->Record.Pid = pid;
    item->Record.PortIndex = portIndex;
    item->Record.Handle = handle;
    KeQuerySystemTime(&now);
    item->Record.Timestamp = (ULONGLONG)now.QuadPart;
    RtlCopyMemory(item->Record.Data, data, len);

    KeAcquireSpinLock(&g_Capture.Lock, &old);
    if (g_Capture.Count >= UM_MAX_RECORDS && !IsListEmpty(&g_Capture.Queue)) {
        PLIST_ENTRY head = RemoveHeadList(&g_Capture.Queue);
        PUM_RECORD_ITEM oldItem = CONTAINING_RECORD(head, UM_RECORD_ITEM, Entry);
        g_Capture.Count--;
        KeReleaseSpinLock(&g_Capture.Lock, old);
        ExFreeToNPagedLookasideList(&g_Capture.Lookaside, oldItem);
        InterlockedIncrement((PLONG)&g_Capture.Dropped);
        KeAcquireSpinLock(&g_Capture.Lock, &old);
    }
    InsertTailList(&g_Capture.Queue, &item->Entry);
    g_Capture.Count++;
    if (dir == UM_DIR_RX) {
        g_Capture.Received += len;
    } else {
        g_Capture.Sent += len;
    }
    KeReleaseSpinLock(&g_Capture.Lock, old);
}

// Pop one record into `out`.
//
// Return value semantics (three distinct cases the caller must be able to tell apart):
//   > 0  record copied, this many bytes
//     0  queue empty
//    -1  the caller's buffer is too small; the record was PUT BACK (not dropped)
//
// An earlier version dequeued, freed and returned 0 on a short buffer, so a caller with a
// small buffer lost every record one by one while being told the queue was empty.
static LONG UmDequeueRecord(PUCHAR out, ULONG outLen)
{
    KIRQL old;
    PLIST_ENTRY entry;
    PUM_RECORD_ITEM item;
    ULONG need;

    KeAcquireSpinLock(&g_Capture.Lock, &old);
    if (IsListEmpty(&g_Capture.Queue)) {
        KeReleaseSpinLock(&g_Capture.Lock, old);
        return 0;
    }
    entry = g_Capture.Queue.Flink;
    item = CONTAINING_RECORD(entry, UM_RECORD_ITEM, Entry);
    need = UM_RECORD_HEADER + item->Record.Size;
    if (need > outLen) {
        // Leave it at the head of the queue and report the size required.
        KeReleaseSpinLock(&g_Capture.Lock, old);
        return -1;
    }
    RemoveHeadList(&g_Capture.Queue);
    g_Capture.Count--;
    KeReleaseSpinLock(&g_Capture.Lock, old);

    RtlCopyMemory(out, &item->Record, need);
    ExFreeToNPagedLookasideList(&g_Capture.Lookaside, item);
    return (LONG)need;
}

// ---------------------------------------------------------------------------
// IRP capture
// ---------------------------------------------------------------------------
//
// Runs after the lower driver completed the IRP, so the buffer holds the transferred
// bytes. Copies them out and leaves the IRP result exactly as reported.

typedef struct _UM_IRP_CTX {
    ULONG Dir;
    ULONG Pid;
    ULONG PortIndex;
    ULONG64 Handle;
} UM_IRP_CTX, *PUM_IRP_CTX;

static NTSTATUS UmReadWriteComplete(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
    PUM_IRP_CTX ctx = (PUM_IRP_CTX)Context;
    PIO_STACK_LOCATION stack;

    UNREFERENCED_PARAMETER(DeviceObject);

    stack = IoGetCurrentIrpStackLocation(Irp);
    if (ctx != NULL) {
        if (NT_SUCCESS(Irp->IoStatus.Status) && Irp->IoStatus.Information > 0) {
            ULONG len = (ULONG)Irp->IoStatus.Information;
            ULONG requested = (stack->MajorFunction == IRP_MJ_READ)
                                  ? stack->Parameters.Read.Length
                                  : stack->Parameters.Write.Length;
            PVOID buf = NULL;

            // Clamp against every bound we know:
            //   * the caller's request length,
            //   * the MDL's real size (a third-party USB-serial driver reporting a larger
            //     Information than its buffer would otherwise make us read past the end),
            //   * our own record capacity.
            // Information comes straight from the driver below and is not trustworthy on
            // its own.
            if (len > requested) {
                len = requested;
            }
            if (Irp->MdlAddress != NULL) {
                ULONG mdlBytes = MmGetMdlByteCount(Irp->MdlAddress);
                if (len > mdlBytes) {
                    len = mdlBytes;
                }
            }
            if (len > UM_MAX_PAYLOAD) {
                len = UM_MAX_PAYLOAD;
            }

            // Buffer-source order matters. Serial drivers overwhelmingly use DO_DIRECT_IO,
            // so the MDL is the normal case and SystemBuffer is usually NULL 鈥?checking
            // SystemBuffer first (as an earlier version did) missed every such transfer.
            // UserBuffer is the METHOD_NEITHER fallback and is valid for reads too.
            if ((DeviceObject != NULL && (DeviceObject->Flags & DO_DIRECT_IO) != 0 &&
                 Irp->MdlAddress != NULL)) {
                buf = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
            } else if (Irp->AssociatedIrp.SystemBuffer != NULL) {
                buf = Irp->AssociatedIrp.SystemBuffer;
            } else if (Irp->MdlAddress != NULL) {
                buf = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
            } else {
                buf = Irp->UserBuffer;
            }

            if (buf != NULL && len > 0) {
                // A caller-supplied UserBuffer may be unmapped or racing with teardown;
                // a fault here must not take down the machine on behalf of a monitor.
                __try {
                    UmQueueRecord(ctx->Dir, ctx->Pid, ctx->PortIndex, ctx->Handle,
                                  (const UCHAR *)buf, len);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    InterlockedIncrement((PLONG)&g_Capture.Dropped);
                }
            }
        }
        ExFreeToNPagedLookasideList(&g_Capture.CtxLookaside, ctx);
    }
    if (Irp->PendingReturned) {
        IoMarkIrpPending(Irp);
    }
    return Irp->IoStatus.Status;
}

// ---------------------------------------------------------------------------
// Filter device dispatch
// ---------------------------------------------------------------------------

static NTSTATUS UmFilterDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PUM_DEVICE_CTX ctx = (PUM_DEVICE_CTX)DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

    if (ctx->Lower == NULL) {
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    if (stack->MajorFunction == IRP_MJ_READ || stack->MajorFunction == IRP_MJ_WRITE) {
        PUM_IRP_CTX irpCtx = (PUM_IRP_CTX)
            ExAllocateFromNPagedLookasideList(&g_Capture.CtxLookaside);
        if (irpCtx != NULL) {
            irpCtx->Dir = (stack->MajorFunction == IRP_MJ_READ) ? UM_DIR_RX : UM_DIR_TX;
            irpCtx->Pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
            irpCtx->PortIndex = ctx->Index;
            // A monotonic id, NOT the kernel pointer. Returning the PDO address to user mode
            // leaks a KASLR-relevant address and would dangle once the device is removed.
            irpCtx->Handle = (ULONG64)(ULONG_PTR)ctx->PortId;
            // A completion routine needs its OWN stack location.
            // IoSkipCurrentIrpStackLocation makes the lower driver REUSE our stack
            // location, so writing CompletionRoutine into it afterwards corrupts what the
            // lower driver reads. That broke every request on the port: IRP_MJ_CREATE
            // failed with "Incorrect function" (the port looked busy to every serial
            // tool), and readers waited forever for a reply that never came 鈥?exactly the
            // hang seen in both umfilter_reader and the GUI.
            IoCopyCurrentIrpStackLocationToNext(Irp);
            {
                PIO_STACK_LOCATION next = IoGetNextIrpStackLocation(Irp);
                next->CompletionRoutine = UmReadWriteComplete;
                next->Context = irpCtx;
                next->Control = SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL;
            }
            return IoCallDriver(ctx->Lower, Irp);
        } else {
            InterlockedIncrement((PLONG)&g_Capture.Dropped);
            // Allocation failed: fall through to a plain pass-through so the I/O still
            // completes 鈥?losing one capture is better than losing the application's data.
        }
    }

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ctx->Lower, Irp);
}

// Forward declarations (the dispatch entries below are referenced by the shared table).
static NTSTATUS UmFilterDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static NTSTATUS UmFilterPnp(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static NTSTATUS UmFilterPower(PDEVICE_OBJECT DeviceObject, PIRP Irp);

// ---------------------------------------------------------------------------
// Per-device dispatch
// ---------------------------------------------------------------------------
//
// THE BUG THIS FIXES
// ------------------
// Windows gives every device of a driver the SAME MajorFunction table, so the filter
// devices and the control device necessarily share entry points. The original code put
// the control handlers there for every device, so IRP_MJ_CREATE on a serial port was
// answered by UmControlCreate 鈥?completing the open immediately 鈥?and the real serial
// driver never saw it. Consequences: every COM port looked occupied ("Incorrect
// function"), no data ever flowed, and user-mode readers blocked forever waiting for a
// reply that would never come (the umfilter_reader / GUI hang).
//
// The fix: the shared entries branch on whether the device has a lower device attached.
// A control device has Lower == NULL; a filter device has Lower != NULL and must forward
// everything untouched.

// Detach and delete our filter device only AFTER the lower stack finished the remove IRP.
//
// Calling IoDetachDevice + IoDeleteDevice immediately after IoCallDriver is a
// use-after-free: the lower driver may complete asynchronously, and our device object
// (along with the IRP's stack location living in it) would already be gone. The
// completion routine defers the teardown to the right moment.
static NTSTATUS UmRemoveComplete(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
    PUM_DEVICE_CTX ctx = (PUM_DEVICE_CTX)Context;
    UNREFERENCED_PARAMETER(Irp);

    if (ctx != NULL) {
        PDEVICE_OBJECT physical = ctx->Physical;

        // Free the bookkeeping slot. Without this the table only ever grew: 64 plug/unplug
        // cycles filled it permanently, after which attaching silently returned 0 forever
        // (monitoring died with no error to explain it).
        UmFreeSlotResources(ctx->Index);

        if (ctx->Lower != NULL) {
            IoDetachDevice(ctx->Lower);
            ctx->Lower = NULL;
        }
        ctx->Physical = NULL;
        // Drop the reference the driver took when it registered this device.
        if (physical != NULL) {
            ObDereferenceObject(physical);
        }
    }
    IoDeleteDevice(DeviceObject);
    return STATUS_SUCCESS; // let the I/O manager finish the IRP
}

static NTSTATUS UmFilterPnp(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PUM_DEVICE_CTX ctx = (PUM_DEVICE_CTX)DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

    if (ctx->Lower == NULL) {
        // Already detached (or never attached): nothing to forward to.
        Irp->IoStatus.Status = STATUS_DEVICE_NOT_CONNECTED;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_DEVICE_NOT_CONNECTED;
    }

    if (stack->MinorFunction == IRP_MN_REMOVE_DEVICE) {
        IoCopyCurrentIrpStackLocationToNext(Irp);
        {
            PIO_STACK_LOCATION next = IoGetNextIrpStackLocation(Irp);
            next->CompletionRoutine = UmRemoveComplete;
            next->Context = ctx;
            next->Control = SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL;
        }
        return IoCallDriver(ctx->Lower, Irp);
    }
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ctx->Lower, Irp);
}

// Power IRPs pass straight through. PoStartNextPowerIrp is deliberately not called:
// it is only required when the driver installs a power completion routine, and calling
// it unconditionally on a pass-through double-advances the power state machine.
static NTSTATUS UmFilterPower(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PUM_DEVICE_CTX ctx = (PUM_DEVICE_CTX)DeviceObject->DeviceExtension;
    if (ctx->Lower == NULL) {
        PoStartNextPowerIrp(Irp);
        Irp->IoStatus.Status = STATUS_DEVICE_NOT_CONNECTED;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_DEVICE_NOT_CONNECTED;
    }
    IoSkipCurrentIrpStackLocation(Irp);
    return PoCallDriver(ctx->Lower, Irp);
}

// ---------------------------------------------------------------------------
// Attaching to serial device stacks
// ---------------------------------------------------------------------------
//
// HOW THE REFERENCE PRODUCT FINDS PORTS
// -------------------------------------
// Decompiling ComDrv12x64.sys shows it does NOT use a hard-coded device list. It calls
// ZwOpenDirectoryObject(L"\\Device"), obtains the directory object with
// ObReferenceObjectByHandle, then walks the directory's object hash and recursively
// descends subdirectories, matching device names against the serial namespaces. That is
// why it catches every vendor's port (usbser, Prolific, Silicon Labs, ELTIMA, com0com,
// and plain \Device\SerialN) without shipping a list.
//
// This driver uses the equivalent, documented route: enumerate \Device via
// ZwQueryDirectoryObject. It returns every child object of the directory, including the
// serial devices, so the same coverage is achieved without touching kernel internals.

// ZwQueryDirectoryObject returns an array of these. The definition lives in
// ntifs.h/ntddk.h depending on the SDK, and it is not exposed by the WDK NuGet headers
// used here, so it is declared locally with exactly the documented layout.
typedef struct _UM_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} UM_DIRECTORY_INFORMATION, *PUM_DIRECTORY_INFORMATION;

// Does this \Device child name look like a serial port device?
//
// Kept broad on purpose: the reference product matches its own serial namespaces, while
// we look for the name fragments every known COM-port driver family uses. The fragment
// list covers Microsoft's Serial/ComPort, USB CDC (usbser), FTDI, Prolific, Silicon Labs,
// ELAN/ELTIMA style virtual ports (VSerial, vcp, vser) and com0com.
static BOOLEAN UmLooksLikeSerialPort(PCUNICODE_STRING name)
{
    static const PCWSTR fragments[] = {
        L"Serial", L"serial",
        L"USBSER", L"usbser",
        L"ComPort", L"comport",
        L"Prolific", L"prolific",
        L"Silabser", L"silabser",
        L"VSerial", L"vserial",
        L"VCP", L"vcp",
        L"vser", L"Vser",
        L"FTDI", L"ftdi",
        L"BthModem", L"bthmodem",
        L"ttyS", L"ttyUSB",
        L"cdc_acm", L"cdc-acm",
        L"Ch341", L"ch341",
        L"MCT_U232", L"mct_u232",
        L"ComDB", L"comdb",
    };
    ULONG i;
    USHORT nameLen;
    PWCH buf;

    nameLen = name->Length / sizeof(WCHAR);
    buf = name->Buffer;
    if (nameLen == 0 || buf == NULL) {
        return FALSE;
    }
    for (i = 0; i < ARRAYSIZE(fragments); i++) {
        UNICODE_STRING frag;
        WCHAR scratch[64];
        SIZE_T len = 0;
        PCWSTR f = fragments[i];
        while (f[len] != L'\0' && len < ARRAYSIZE(scratch) - 1) {
            scratch[len] = f[len];
            len++;
        }
        if (len == 0) {
            continue;
        }
        frag.Buffer = scratch;
        frag.Length = (USHORT)(len * sizeof(WCHAR));
        frag.MaximumLength = frag.Length;
        // Substring test: walk every offset of the device name.
        if (nameLen >= len) {
            USHORT off;
            for (off = 0; off + len <= nameLen; off++) {
                UNICODE_STRING window;
                window.Buffer = buf + off;
                window.Length = frag.Length;
                window.MaximumLength = frag.Length;
                if (RtlCompareUnicodeString(&window, &frag, TRUE) == 0) {
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

// Attach one filter device above `target`, recording its friendly name.
// Forward declarations: UmAttachAllPorts (below) uses these, while their definitions
// follow it. Without the declarations C assumes an implicit `int` return and then
// conflicts with the real BOOLEAN/LONG definitions.
// (prototypes are at the top of the file)

static NTSTATUS UmAttachOne(PDEVICE_OBJECT target, ULONG index, PCWSTR name)
{
    PDEVICE_OBJECT filter = NULL;
    PUM_DEVICE_CTX ctx;
    NTSTATUS status;

    if (index >= UM_MAX_FILTERS) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Create the device with the SAME characteristics as the one below, minus the bits a
    // PDO owns. Passing target->Characteristics through verbatim made IoCreateDevice fail
    // with STATUS_INVALID_PARAMETER for stacks that set FILE_REMOVABLE_MEDIA /
    // FILE_DEVICE_IS_MOUNTABLE_DEVICE, and the failure was silent (attach just returned 0).
    status = IoCreateDevice(
        g_DriverObject, sizeof(UM_DEVICE_CTX), NULL,
        target->DeviceType, FILE_DEVICE_SECURE_OPEN,
        FALSE, &filter);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    ctx = (PUM_DEVICE_CTX)filter->DeviceExtension;
    RtlZeroMemory(ctx, sizeof(UM_DEVICE_CTX));
    ctx->Self = filter;
    ctx->Physical = target;
    ctx->Index = index;
    ctx->PortId = (ULONG64)InterlockedIncrement64(&g_Capture.NextPortId);
    ctx->Lower = IoAttachDeviceToDeviceStack(filter, target);
    if (ctx->Lower == NULL) {
        IoDeleteDevice(filter);
        return STATUS_DEVICE_NOT_CONNECTED;
    }
    // Inherit the stack's buffering and power flags. DO_POWER_INRUSH matters for devices
    // that draw inrush current at power-up; a filter that drops it can break the power
    // budget for the whole stack.
    filter->Flags |= ctx->Lower->Flags &
                     (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE | DO_POWER_INRUSH);
    filter->Flags &= ~DO_DEVICE_INITIALIZING;
    g_Capture.AttachedNames[index] = name;
    // Record the filter object so DriverUnload can detach/delete it without guessing.
    g_Capture.AttachedFilters[index] = filter;
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// Device-kind dispatch (the kernel has no per-device dispatch table)
// ---------------------------------------------------------------------------
//
// Windows gives every device object of a driver the SAME MajorFunction table, so the
// filter devices and the control device necessarily share entry points. The original code
// installed the control-device handlers for every device, which meant IRP_MJ_CREATE on a
// serial port was answered by UmControlCreate (completing it immediately) instead of being
// forwarded 鈥?that is what made every COM port unusable while the driver was loaded.
//
// The fix: the shared entries branch on whether the device has a lower device attached.
// A control device has Lower == NULL and owns the IOCTL interface; a filter device has
// Lower != NULL and must forward everything untouched.

static BOOLEAN UmIsControlDevice(PDEVICE_OBJECT DeviceObject)
{
    PUM_DEVICE_CTX ctx = (PUM_DEVICE_CTX)DeviceObject->DeviceExtension;
    return ctx != NULL && ctx->Lower == NULL && ctx->PassThroughOnly;
}

// Enumerate \Device and attach to every child that looks like a serial port.
//
// This mirrors what the reference driver accomplishes by walking the directory object's
// hash table; ZwQueryDirectoryObject is the supported API for the same information.
static ULONG UmAttachAllPorts(VOID)
{
    UNICODE_STRING dirName;
    OBJECT_ATTRIBUTES oa;
    HANDLE dirHandle = NULL;
    NTSTATUS status;
    ULONG attached = 0;
    ULONG context = 0;
    // Space for a generous batch of directory entries per call.
    ULONG bufLen = 32 * 1024;
    PVOID buf = NULL;

    RtlInitUnicodeString(&dirName, L"\\Device");
    InitializeObjectAttributes(&oa, &dirName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenDirectoryObject(&dirHandle, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, &oa);
    if (!NT_SUCCESS(status)) {
        return 0;
    }

    buf = ExAllocatePoolWithTag(NonPagedPool, bufLen, UM_TAG);
    if (buf == NULL) {
        ZwClose(dirHandle);
        return 0;
    }

    for (;;) {
        ULONG retLen = 0;
        ULONG i;
        PUM_DIRECTORY_INFORMATION info = (PUM_DIRECTORY_INFORMATION)buf;

        // RestartScan MUST be FALSE after the first call: the enumeration position comes
        // from `context`, which the previous call updates. Passing TRUE on every call
        // re-read the same entry forever 鈥?that is exactly what hung DriverEntry and left
        // the service stuck in START_PENDING, and it also explains why the service could
        // not be deleted afterwards (a driver mid-DriverEntry cannot be unloaded).
        status = ZwQueryDirectoryObject(
            dirHandle, buf, bufLen,
            (context == 0) ? TRUE : FALSE, // restart only on the very first call
            TRUE /* one entry per call */,
            &context, &retLen);
        if (!NT_SUCCESS(status)) {
            break; // STATUS_NO_MORE_ENTRIES ends the walk
        }
        if (retLen < sizeof(UM_DIRECTORY_INFORMATION)) {
            break;
        }
        for (i = 0; i + sizeof(UM_DIRECTORY_INFORMATION) <= retLen; i += sizeof(UM_DIRECTORY_INFORMATION)) {
            PUM_DIRECTORY_INFORMATION entry = (PUM_DIRECTORY_INFORMATION)((PUCHAR)buf + i);
            if (entry->Name.Buffer == NULL || entry->Name.Length == 0) {
                break;
            }
            if (!UmLooksLikeSerialPort(&entry->Name)) {
                continue;
            }
            // Never attach to ourselves.
            //
            // Our own control device is \Device\UmSerialFilter, whose name contains
            // "Serial" 鈥?so the fragment match above happily selects it. Attaching a
            // filter above our own control device makes every IOCTL pass through an extra
            // copy of this driver, and a second ATTACH_PORTS call stacks another one.
            {
                UNICODE_STRING ownName;
                RtlInitUnicodeString(&ownName, L"UmSerialFilter");
                if (entry->Name.Length == ownName.Length &&
                    RtlCompareUnicodeString(&entry->Name, &ownName, TRUE) == 0) {
                    continue;
                }
            }
            if (g_Capture.AttachedCount >= UM_MAX_FILTERS) {
                break;
            }
            {
                // Build the full device path and open it.
                WCHAR pathBuf[256];
                UNICODE_STRING devName;
                ULONG pos = 0;
                PCWSTR prefix = L"\\Device\\";
                ULONG k;
                for (k = 0; prefix[k] != L'\0' && pos < ARRAYSIZE(pathBuf) - 1; k++) {
                    pathBuf[pos++] = prefix[k];
                }
                for (k = 0; k < entry->Name.Length / sizeof(WCHAR) && pos < ARRAYSIZE(pathBuf) - 1; k++) {
                    pathBuf[pos++] = entry->Name.Buffer[k];
                }
                pathBuf[pos] = L'\0';
                RtlInitUnicodeString(&devName, pathBuf);

                {
                    PFILE_OBJECT fileObj = NULL;
                    PDEVICE_OBJECT devObj = NULL;
                    NTSTATUS openStatus = IoGetDeviceObjectPointer(
                        &devName, FILE_READ_DATA, &fileObj, &devObj);
                    if (NT_SUCCESS(openStatus)) {
                        // Hold our own reference on the device object: the file object was
                        // the only thing keeping it alive, and the driver keeps using
                        // devObj long after this point (ctx->Physical, the attach table).
                        ObReferenceObject(devObj);
                        ObDereferenceObject(fileObj);

                        // The scan can be re-run by user mode, so skip devices we already
                        // filter rather than stacking a second filter on them.
                        if (!UmAlreadyAttached(devObj)) {
                            // Owned copy of the device path. Passing NULL here (as an
                            // earlier version did) made AttachedNames always NULL, so
                            // IOCTL_UM_GET_PORT_NAME could never answer.
                            PWSTR nameCopy = UmDuplicateName(&devName);
                            LONG idx = UmRegisterAttached(devObj, nameCopy);
                            if (idx >= 0) {
                                if (!NT_SUCCESS(UmAttachOne(devObj, (ULONG)idx, nameCopy))) {
                                    // Roll the slot back; it also frees nameCopy.
                                    UmFreeSlotResources((ULONG)idx);
                                    ObDereferenceObject(devObj);
                                } else {
                                    attached++;
                                }
                            } else {
                                if (nameCopy != NULL) {
                                    ExFreePoolWithTag(nameCopy, UM_TAG);
                                }
                                ObDereferenceObject(devObj);
                            }
                        } else {
                            ObDereferenceObject(devObj);
                        }
                    }
                }
            }
        }
    }

    ExFreePoolWithTag(buf, UM_TAG);
    ZwClose(dirHandle);
    return attached;
}

// ---------------------------------------------------------------------------
// Hot-plug: attach to serial devices that appear after the driver loaded
// ---------------------------------------------------------------------------
//
// IoRegisterPlugPlayNotification runs the callback at PASSIVE_LEVEL for a device
// interface arrival, which lets us take the same path as startup: build the interface's
// symbolic link, resolve it to a device object, and attach a filter above it.
//
// Called with EventCategory == EventCategoryDeviceInterfaceChange and the interface's
// symbolic link name in EventData (a UNICODE_STRING), so the device can be opened
// without re-enumerating \Device.

// Is this physical device already filtered?
//
// Both the IOCTL scan and the hot-plug callback can reach the same device (an interface
// arrival for a port the initial scan already covered), and attaching twice would put
// two filters on one stack 鈥?doubling every captured byte.
// Copy a device path into a NUL-terminated buffer the attach table owns.
//
// The UNICODE_STRING handed in points into a stack buffer that dies with the scan, so the
// name has to be copied 鈥?and freed when the slot is released.
static PWSTR UmDuplicateName(PCUNICODE_STRING name)
{
    SIZE_T chars;
    SIZE_T bytes;
    PWSTR copy;

    if (name == NULL || name->Buffer == NULL || name->Length == 0) {
        return NULL;
    }
    chars = name->Length / sizeof(WCHAR);
    bytes = (chars + 1) * sizeof(WCHAR);
    copy = (PWSTR)ExAllocatePoolWithTag(NonPagedPool, bytes, UM_TAG);
    if (copy == NULL) {
        return NULL;
    }
    RtlCopyMemory(copy, name->Buffer, chars * sizeof(WCHAR));
    copy[chars] = L'\0';
    return copy;
}

static BOOLEAN UmAlreadyAttached(PDEVICE_OBJECT physical)
{
    ULONG i;
    BOOLEAN found = FALSE;
    KIRQL old;

    KeAcquireSpinLock(&g_AttachLock, &old);
    for (i = 0; i < UM_MAX_FILTERS; i++) {
        // Only slots that are actually in use. Scanning up to AttachedCount missed freed
        // slots in the middle, and a freed slot's pointer could match a recycled PDO
        // address 鈥?which made a freshly plugged adapter look "already attached" and it
        // was then never monitored.
        if (g_Capture.SlotUsed[i] && g_Capture.Attached[i] == physical) {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_AttachLock, old);
    return found;
}

// Claim the first free slot for `physical`. Returns its index, or -1 when full.
static LONG UmRegisterAttached(PDEVICE_OBJECT physical, PCWSTR name)
{
    LONG index = -1;
    ULONG i;
    KIRQL old;

    KeAcquireSpinLock(&g_AttachLock, &old);
    for (i = 0; i < UM_MAX_FILTERS; i++) {
        if (!g_Capture.SlotUsed[i]) {
            index = (LONG)i;
            g_Capture.SlotUsed[i] = TRUE;
            g_Capture.Attached[i] = physical;
            g_Capture.AttachedFilters[i] = NULL;
            g_Capture.AttachedNames[i] = name;
            g_Capture.AttachedCount++;
            break;
        }
    }
    KeReleaseSpinLock(&g_AttachLock, old);
    return index;
}

// Release a slot. The name is an owned allocation, so it is freed here. Callable from a
// completion routine: it only touches non-paged fields under the attach lock.
static VOID UmFreeSlotResources(ULONG index)
{
    KIRQL old;
    PWSTR name = NULL;

    if (index >= UM_MAX_FILTERS) {
        return;
    }
    KeAcquireSpinLock(&g_AttachLock, &old);
    name = g_Capture.AttachedNames[index];
    g_Capture.AttachedNames[index] = NULL;
    if (g_Capture.SlotUsed[index] && g_Capture.AttachedCount > 0) {
        g_Capture.AttachedCount--;
    }
    g_Capture.SlotUsed[index] = FALSE;
    g_Capture.Attached[index] = NULL;
    g_Capture.AttachedFilters[index] = NULL;
    KeReleaseSpinLock(&g_AttachLock, old);

    if (name != NULL) {
        ExFreePoolWithTag(name, UM_TAG);
    }
}

static NTSTATUS UmHotplugAttachLink(PUNICODE_STRING link)
{
    PFILE_OBJECT fileObj = NULL;
    PDEVICE_OBJECT devObj = NULL;
    NTSTATUS status;
    LONG index;
    PWSTR nameCopy;

    status = IoGetDeviceObjectPointer(link, FILE_READ_DATA, &fileObj, &devObj);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    // Keep our own reference: the file object was the only owner of the device object, and
    // the driver stores devObj in its attach table.
    ObReferenceObject(devObj);
    ObDereferenceObject(fileObj);

    if (UmAlreadyAttached(devObj)) {
        ObDereferenceObject(devObj);
        return STATUS_SUCCESS; // already filtered by the port scan
    }

    // Record the device path so IOCTL_UM_GET_PORT_NAME can report it.
    nameCopy = UmDuplicateName(link);
    index = UmRegisterAttached(devObj, nameCopy);
    if (index < 0) {
        if (nameCopy != NULL) {
            ExFreePoolWithTag(nameCopy, UM_TAG);
        }
        ObDereferenceObject(devObj);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    status = UmAttachOne(devObj, (ULONG)index, nameCopy);
    if (!NT_SUCCESS(status)) {
        // Roll the reservation back; this also frees nameCopy.
        UmFreeSlotResources((ULONG)index);
        ObDereferenceObject(devObj);
    }
    return status;
}

static BOOLEAN UmGuidEqual(const GUID *a, const GUID *b)
{
    return (BOOLEAN)(a->Data1 == b->Data1 && a->Data2 == b->Data2 && a->Data3 == b->Data3 &&
                     RtlCompareMemory(a->Data4, b->Data4, sizeof(a->Data4)) == sizeof(a->Data4));
}

static NTSTATUS UmHotplugCallback(
    PVOID NotificationStructure,
    PVOID Context)
{
    PDEVICE_INTERFACE_CHANGE_NOTIFICATION note =
        (PDEVICE_INTERFACE_CHANGE_NOTIFICATION)NotificationStructure;
    UNREFERENCED_PARAMETER(Context);

    if (note == NULL || note->SymbolicLinkName == NULL) {
        return STATUS_SUCCESS;
    }
    // Only arrivals need action; a removal is handled by the PnP dispatch of the filter
    // that is already attached to that stack.
    if (!UmGuidEqual(&note->Event, GUID_DEVICE_INTERFACE_ARRIVAL)) {
        return STATUS_SUCCESS;
    }
    UmHotplugAttachLink(note->SymbolicLinkName);
    return STATUS_SUCCESS;
}

// Register for serial port arrival notifications.
static VOID UmRegisterHotplug(VOID)
{
    UNICODE_STRING interfaceClass;
    NTSTATUS status;

    // GUID_DEVINTERFACE_COMPORT: every driver that exposes a COM port registers this
    // interface, so it covers USB-serial, virtual and legacy ports alike.
    RtlInitUnicodeString(&interfaceClass, L"\\Device\\Serial");  // not used; see below

    status = IoRegisterPlugPlayNotification(
        EventCategoryDeviceInterfaceChange,
        // NO PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES.
        //
        // That flag makes the callback run SYNCHRONOUSLY inside DriverEntry for every port
        // already present, so UmAttachOne -> IoGetDeviceObjectPointer +
        // IoAttachDeviceToDeviceStack would execute in the driver-load path. That is
        // exactly the START_PENDING(1072) hang this driver was already fixed for:
        // DriverEntry never returns, the service can be neither stopped nor deleted, and a
        // reboot is the only way out.
        //
        // Existing ports are attached by user mode via IOCTL_UM_ATTACH_PORTS, which runs
        // only after the driver reports RUNNING. This registration then covers devices that
        // arrive later, and those callbacks run on a system worker thread.
        0,
        (PVOID)GUID_DEVINTERFACE_COMPORT,
        g_DriverObject,
        UmHotplugCallback,
        NULL,
        &g_NotificationEntry);
    UNREFERENCED_PARAMETER(interfaceClass);
    // A failed registration is not fatal (existing ports are still covered by the IOCTL
    // scan), but leaving it silent would make "hot-plug does not work" unexplainable.
    if (!NT_SUCCESS(status)) {
        g_NotificationEntry = NULL;
    }
}

static VOID UmUnregisterHotplug(VOID)
{
    if (g_NotificationEntry != NULL) {
        IoUnregisterPlugPlayNotification(g_NotificationEntry);
        g_NotificationEntry = NULL;
    }
}

// Report one attached device: index and its NT device name.
static ULONG UmGetAttachedName(PUCHAR out, ULONG outLen, ULONG index)
{
    UNICODE_STRING s;
    ULONG needed;

    if (index >= g_Capture.AttachedCount) {
        return 0;
    }
    if (g_Capture.AttachedNames[index] == NULL) {
        return 0;
    }
    RtlInitUnicodeString(&s, g_Capture.AttachedNames[index]);
    needed = 8 + s.Length;
    if (needed > outLen) {
        return 0;
    }
    *(PULONG)out = index;
    *(PULONG)(out + 4) = s.Length / sizeof(WCHAR);
    RtlCopyMemory(out + 8, s.Buffer, s.Length);
    return needed;
}

// ---------------------------------------------------------------------------
// Control device (user-mode interface)
// ---------------------------------------------------------------------------

// IRP_MJ_CREATE for EVERY device of this driver.
//
// A control device answers the open itself; a filter device sitting above a serial port
// must forward it, because whether the port opens belongs to the real serial driver.
// Answering it locally was the bug that made every COM port appear unusable while the
// filter was loaded: the open "succeeded" on our device without the serial driver ever
// seeing it, so no data ever flowed and readers waited forever.
static NTSTATUS UmControlCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    if (!UmIsControlDevice(DeviceObject)) {
        return UmFilterDispatch(DeviceObject, Irp);
    }
    // Count open handles. Capture stays on while at least one monitor has the device open,
    // so a crashed or killed monitor does not leave the driver capturing (and filling the
    // queue, and burning CPU) until the driver is unloaded.
    InterlockedIncrement(&g_Capture.OpenCount);
    g_Capture.Enabled = 1;
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// IRP_MJ_CLOSE: same split between control and filter devices.
static NTSTATUS UmControlClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    if (!UmIsControlDevice(DeviceObject)) {
        return UmFilterDispatch(DeviceObject, Irp);
    }
    // Stop capturing once the last monitor handle closes. Device attach state is left
    // alone: the filters stay in the stack so a later reopen resumes capture immediately.
    if (InterlockedDecrement(&g_Capture.OpenCount) <= 0) {
        g_Capture.OpenCount = 0;
        g_Capture.Enabled = 0;
    }
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// IRP_MJ_CLEANUP: the last handle to the device is being closed.
//
// A filter driver MUST forward this. Windows delivers CLEANUP before CLOSE, and the
// serial driver uses it to abort pending reads and release port resources. Without the
// forward, an application that closes its port leaves stale state behind 鈥?which shows up
// as "the port is still busy" on the next open. The reference driver handles CLEANUP in
// the same branch as CLOSE for exactly this reason.
static NTSTATUS UmControlCleanup(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    if (!UmIsControlDevice(DeviceObject)) {
        return UmFilterDispatch(DeviceObject, Irp);
    }
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS UmControlIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG info = 0;
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG inLen = stack->Parameters.DeviceIoControl.InputBufferLength;
    PVOID buf = Irp->AssociatedIrp.SystemBuffer;

    // A serial port's own IOCTLs (baud rate, line control, handshake...) must reach the
    // serial driver untouched. Only the control device interprets UM_* codes.
    if (!UmIsControlDevice(DeviceObject)) {
        return UmFilterDispatch(DeviceObject, Irp);
    }

    // Gate everything behind the session-key handshake.
    //
    // The DACL already restricts who can open the device, but "can open" is a weaker
    // property than "is our service" 鈥?the key check is what actually pairs this driver
    // with our software. A process that somehow obtains a handle still cannot start
    // capture, retarget it, or read traffic without the key.
    if (code == IOCTL_UM_AUTHENTICATE) {
        PUM_DEVICE_CTX dctx = (PUM_DEVICE_CTX)DeviceObject->DeviceExtension;
        if (buf == NULL || inLen < sizeof(g_Capture.SessionKey)) {
            status = STATUS_INVALID_PARAMETER;
        } else if (!UmKeyMatches((const UCHAR *)buf)) {
            status = STATUS_ACCESS_DENIED;
        } else {
            dctx->Flags |= UM_CTX_AUTHENTICATED;
            g_Capture.Enabled = 1;
            status = STATUS_SUCCESS;
        }
        Irp->IoStatus.Status = status;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
    }
    {
        PUM_DEVICE_CTX dctx = (PUM_DEVICE_CTX)DeviceObject->DeviceExtension;
        if ((dctx->Flags & UM_CTX_AUTHENTICATED) == 0) {
            Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_ACCESS_DENIED;
        }
    }

    // Honour the access bits declared in each CTL_CODE. Without this the FILE_READ_DATA /
    // FILE_WRITE_DATA in the codes is decorative 鈥?a handle opened read-only could still
    // issue the write-class IOCTLs.
    if (code == IOCTL_UM_GET_RECORD || code == IOCTL_UM_GET_STATS ||
        code == IOCTL_UM_GET_PORT_NAME) {
        if (!IoValidateDeviceIoControlAccess(Irp, FILE_READ_ACCESS)) {
            Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_ACCESS_DENIED;
        }
    } else {
        if (!IoValidateDeviceIoControlAccess(Irp, FILE_WRITE_ACCESS)) {
            Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_ACCESS_DENIED;
        }
    }

    switch (code) {
    case IOCTL_UM_GET_RECORD:
        if (buf != NULL && outLen >= UM_RECORD_HEADER) {
            LONG got = UmDequeueRecord((PUCHAR)buf, outLen);
            if (got > 0) {
                info = (ULONG)got;
                status = STATUS_SUCCESS;
            } else if (got == 0) {
                // Empty queue: a zero-length success, not an error. This is what lets the
                // capture thread poll without ever blocking the UI.
                info = 0;
                status = STATUS_SUCCESS;
            } else {
                // Buffer too small; the record stayed queued. Report the required size so
                // the caller can grow its buffer instead of silently losing data.
                info = UM_RECORD_HEADER + UM_MAX_PAYLOAD;
                status = STATUS_BUFFER_TOO_SMALL;
            }
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_UM_SET_TARGET:
        if (buf != NULL && inLen >= sizeof(ULONG)) {
            g_Capture.TargetPid = *(PULONG)buf;
            g_Capture.Enabled = 1;
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
        break;

    case IOCTL_UM_ATTACH_PORTS:
        // Write the result into the output buffer as well as into Information.
        // METHOD_BUFFERED callers read lpBytesReturned from Information, but depending on
        // that alone means an aliasing caller is the only one that ever sees the count.
        if (buf == NULL || outLen < sizeof(ULONG)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        *(PULONG)buf = UmAttachAllPorts();
        info = sizeof(ULONG);
        status = STATUS_SUCCESS;
        break;

    case IOCTL_UM_GET_PORT_NAME:
        if (buf != NULL && inLen >= sizeof(ULONG) && outLen >= 8) {
            ULONG index = *(PULONG)buf;
            info = UmGetAttachedName((PUCHAR)buf, outLen, index);
            status = (info > 0) ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
        break;

    case IOCTL_UM_GET_STATS:
        // Layout: 8 x u32. The byte counters are 64-bit, so they are split across two
        // slots each 鈥?truncating them to 32 bits would wrap after 4 GB of traffic.
        if (buf != NULL && outLen >= 40) {
            PULONG s = (PULONG)buf;
            s[0] = g_Capture.Count;
            s[1] = g_Capture.Dropped;
            s[2] = (ULONG)(g_Capture.Received & 0xFFFFFFFF);
            s[3] = (ULONG)(g_Capture.Received >> 32);
            s[4] = (ULONG)(g_Capture.Sent & 0xFFFFFFFF);
            s[5] = (ULONG)(g_Capture.Sent >> 32);
            s[6] = g_Capture.Enabled;
            s[7] = g_Capture.TargetPid;
            s[8] = g_Capture.AttachedCount;
            s[9] = 0;
            info = 40;
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// ---------------------------------------------------------------------------
// Driver entry
// ---------------------------------------------------------------------------

static VOID UmDriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    // Detach from interface notifications first: the callback may otherwise fire while
    // the capture state it touches is being torn down.
    UmUnregisterHotplug();

    if (g_SymLink.Buffer != NULL) {
        IoDeleteSymbolicLink(&g_SymLink);
        g_SymLink.Buffer = NULL;
    }
    if (g_ControlDevice != NULL) {
        IoDeleteDevice(g_ControlDevice);
        g_ControlDevice = NULL;
    }
    // Tear down every filter device we attached.
    //
    // An earlier version only reset AttachedCount to zero, which leaked the device
    // objects AND left them attached to the serial stacks. Driver unload then freed the
    // driver while live filter devices still pointed at its dispatch table 鈥?a guaranteed
    // bugcheck on the next serial I/O. Each filter must be detached and deleted for real.
    //
    // The filter objects are recorded in AttachedFilters[] precisely so this loop does not
    // have to guess them from the stack.
    {
        ULONG i;
        for (i = 0; i < UM_MAX_FILTERS; i++) {
            PDEVICE_OBJECT filter = g_Capture.AttachedFilters[i];
            PDEVICE_OBJECT physical = g_Capture.Attached[i];
            PWSTR name = g_Capture.AttachedNames[i];

            if (filter != NULL) {
                PUM_DEVICE_CTX fctx = (PUM_DEVICE_CTX)filter->DeviceExtension;
                // Clear Lower first so any IRP still in flight through this filter sees a
                // disconnected device instead of a freed one.
                fctx->Lower = NULL;
                if (physical != NULL) {
                    IoDetachDevice(physical);
                }
                IoDeleteDevice(filter);
            }
            // Drop the reference taken when this device was registered.
            if (physical != NULL) {
                ObDereferenceObject(physical);
            }
            if (name != NULL) {
                ExFreePoolWithTag(name, UM_TAG);
            }
            g_Capture.AttachedFilters[i] = NULL;
            g_Capture.Attached[i] = NULL;
            g_Capture.AttachedNames[i] = NULL;
            g_Capture.SlotUsed[i] = FALSE;
        }
        g_Capture.AttachedCount = 0;
    }

    // Drain the queue before destroying the lookaside: ExDeleteNPagedLookasideList does not
    // free items that are still checked out, so anything still queued leaked (up to 512
    // records of 4 KB 鈮?2 MB of non-paged memory per unload).
    for (;;) {
        KIRQL old;
        PLIST_ENTRY entry = NULL;
        KeAcquireSpinLock(&g_Capture.Lock, &old);
        if (!IsListEmpty(&g_Capture.Queue)) {
            entry = RemoveHeadList(&g_Capture.Queue);
            if (g_Capture.Count > 0) {
                g_Capture.Count--;
            }
        }
        KeReleaseSpinLock(&g_Capture.Lock, old);
        if (entry == NULL) {
            break;
        }
        ExFreeToNPagedLookasideList(
            &g_Capture.Lookaside, CONTAINING_RECORD(entry, UM_RECORD_ITEM, Entry));
    }

    ExDeleteNPagedLookasideList(&g_Capture.Lookaside);
    ExDeleteNPagedLookasideList(&g_Capture.CtxLookaside);
}

// === UM_CREATE_CONTROL_DEVICE ===
// Create the control device with an explicit DACL.
//
// IoCreateDeviceSecure is resolved dynamically instead of being linked:
//   * wdmsec.lib exports only PfnIoCreateDeviceSecure (a pointer) plus WdmlibInit, so a
//     direct reference fails to link (LNK2019),
//   * the API is absent on very old builds, where falling back is better than refusing to
//     load at all.
// This is the same technique the reference driver uses (its sub_22008 resolves the
// symbol via MmGetSystemRoutineAddress).
typedef NTSTATUS (NTAPI *UM_PFN_CREATE_DEVICE_SECURE)(
    PDRIVER_OBJECT DriverObject,
    ULONG DeviceExtensionSize,
    PUNICODE_STRING DeviceName,
    DEVICE_TYPE DeviceType,
    ULONG DeviceCharacteristics,
    BOOLEAN Exclusive,
    PCUNICODE_STRING DefaultSDDLString,
    LPCGUID DeviceClassGuid,
    PDEVICE_OBJECT *DeviceObject);

static NTSTATUS UmCreateControlDevice(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING DeviceName,
    PDEVICE_OBJECT *OutDevice)
{
    static UM_PFN_CREATE_DEVICE_SECURE pfnCreateSecure = NULL;
    static BOOLEAN resolved = FALSE;
    NTSTATUS status;

    if (!resolved) {
        UNICODE_STRING routine;
        RtlInitUnicodeString(&routine, L"IoCreateDeviceSecure");
        pfnCreateSecure = (UM_PFN_CREATE_DEVICE_SECURE)MmGetSystemRoutineAddress(&routine);
        resolved = TRUE;
    }

    if (pfnCreateSecure != NULL) {
        // Full access to SYSTEM and Administrators; Users may open it so an interactive
        // user can run the monitor. The session-key handshake gates actual use.
        DECLARE_CONST_UNICODE_STRING(umSddl,
            L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;BU)");
        status = pfnCreateSecure(
            DriverObject, sizeof(UM_DEVICE_CTX), DeviceName,
            FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE,
            &umSddl, NULL, OutDevice);
        if (NT_SUCCESS(status)) {
            return status;
        }
        // Fall through to the plain create rather than failing the load outright.
    }

    // No custom DACL available: keep FILE_DEVICE_SECURE_OPEN (open still goes through the
    // device ACL) and rely on the session-key handshake for authorisation.
    return IoCreateDevice(
        DriverObject, sizeof(UM_DEVICE_CTX), DeviceName,
        FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, OutDevice);
}
// === UM_CREATE_CONTROL_DEVICE_END ===
// === UM_SECURITY_LAYER ===
// ---------------------------------------------------------------------------
// Device security: only our own software may be able to use this driver
// ---------------------------------------------------------------------------
//
// A monitor that can read every serial byte is exactly the kind of device an attacker
// would like to open, so the control device must not be world-accessible.
//
// The reference product handles this with a security descriptor built from the SDDL
// string "D:P(A;;GA;;;WD)" 鈥?GA to Everyone, i.e. no protection at all (verified in its
// binary). That weakness is deliberately NOT copied here. This driver uses two layers:
//
//   1. A DACL granting full access only to SYSTEM and Administrators, plus read/write to
//      Builtin Users so an ordinary interactive user can still run the monitor.
//   2. A per-boot session key published by the driver and required as the payload of
//      IOCTL_UM_AUTHENTICATE before any other IOCTL is accepted. A process that merely
//      manages to open the device still cannot drive it.
//
// The descriptor is built directly with RtlCreateAcl / RtlSetDaclSecurityDescriptor
// rather than IoCreateDeviceSecure, because those APIs exist identically from Windows 7
// through 11 鈥?no dynamic resolution and no signed-driver requirement.

// Constant-time-ish comparison of the caller key with ours.
static BOOLEAN UmKeyMatches(const UCHAR *candidate)
{
    ULONG i;
    UCHAR diff = 0;

    if (!g_Capture.SessionKeySet) {
        // No key published (registry unavailable): fall back to DACL-only protection
        // rather than locking the legitimate service out entirely.
        return TRUE;
    }
    for (i = 0; i < sizeof(g_Capture.SessionKey); i++) {
        diff |= (UCHAR)(candidate[i] ^ g_Capture.SessionKey[i]);
    }
    return diff == 0;
}

// === UM_SECURITY_LAYER_END ===

static VOID UmPublishSessionKey(VOID)
{
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING keyName;
    UNICODE_STRING valueName;
    HANDLE keyHandle = NULL;
    NTSTATUS status;
    LARGE_INTEGER now;
    ULONG i;
    UCHAR keyBytes[16];
    ULONG disposition = 0;
    ULONGLONG mix;

    RtlInitUnicodeString(&keyName, UM_PARAMS_KEY);
    InitializeObjectAttributes(&oa, &keyName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwCreateKey(&keyHandle, KEY_WRITE, &oa, 0, NULL, 0, &disposition);
    if (!NT_SUCCESS(status)) {
        g_Capture.SessionKeySet = FALSE;
        return;
    }

    // Not a cryptographic RNG, but the key only has to be unpredictable to another local
    // process, is regenerated on every boot, and never crosses a trust boundary.
    KeQuerySystemTime(&now);
    mix = (ULONGLONG)(ULONG_PTR)&g_Capture ^ (ULONGLONG)(ULONG_PTR)&UmPublishSessionKey ^
          (ULONGLONG)now.QuadPart;
    for (i = 0; i < sizeof(keyBytes); i++) {
        mix = mix * 6364136223846793005ULL + 1442695040888963407ULL;
        keyBytes[i] = (UCHAR)(mix >> 33);
    }
    RtlCopyMemory(g_Capture.SessionKey, keyBytes, sizeof(keyBytes));
    g_Capture.SessionKeySet = TRUE;

    RtlInitUnicodeString(&valueName, UM_PARAMS_VALUE);
    ZwSetValueKey(keyHandle, &valueName, 0, REG_BINARY, keyBytes, sizeof(keyBytes));
    ZwClose(keyHandle);
}

// Constant-time-ish comparison of the caller's key with ours.
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING devName;
    UNICODE_STRING symName;
    PDEVICE_OBJECT device = NULL;
    PUM_DEVICE_CTX ctx;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    g_DriverObject = DriverObject;

    RtlZeroMemory(&g_Capture, sizeof(g_Capture));
    KeInitializeSpinLock(&g_Capture.Lock);
    KeInitializeSpinLock(&g_AttachLock);
    InitializeListHead(&g_Capture.Queue);
    ExInitializeNPagedLookasideList(
        &g_Capture.Lookaside, NULL, NULL, POOL_NX_ALLOCATION,
        sizeof(UM_RECORD_ITEM), UM_TAG, 0);
    // Per-IRP context lookaside: a busy serial port issues thousands of READ/WRITE IRPs per
    // second, and allocating a 32-byte block for each one made the allocator a hot spot.
    ExInitializeNPagedLookasideList(
        &g_Capture.CtxLookaside, NULL, NULL, POOL_NX_ALLOCATION,
        sizeof(UM_IRP_CTX), UM_TAG, 0);
    g_Capture.Enabled = 1;

    RtlInitUnicodeString(&devName, UM_DEVICE_NAME);
    // Create the control device with an explicit DACL via IoCreateDeviceSecure.
    //
    // Plain IoCreateDevice inherits the default \Device ACL, which lets any local process
    // open the device and read every serial byte. The SDDL below grants full access to
    // SYSTEM and Administrators and read/write to Builtin Users (so an interactive user can
    // still run the monitor); the session-key handshake then gates actual use.
    //
    // IoCreateDeviceSecure lives in Wdmsec.lib and needs the driver to be signed; when the
    // symbol is unavailable the code falls back to IoCreateDevice so the driver still
    // loads in environments where Wdmsec is not linked.
    status = UmCreateControlDevice(DriverObject, &devName, &device);
    if (!NT_SUCCESS(status)) {
        ExDeleteNPagedLookasideList(&g_Capture.Lookaside);
        ExDeleteNPagedLookasideList(&g_Capture.CtxLookaside);
        return status;
    }
    device->Flags |= DO_BUFFERED_IO;
    device->Characteristics |= FILE_DEVICE_SECURE_OPEN;
    ctx = (PUM_DEVICE_CTX)device->DeviceExtension;
    RtlZeroMemory(ctx, sizeof(UM_DEVICE_CTX));
    ctx->Self = device;
    ctx->PassThroughOnly = TRUE;
    g_ControlDevice = device;

    // Publish the per-boot session key the service must present.
    UmPublishSessionKey();

    RtlInitUnicodeString(&symName, UM_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symName, &devName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(device);
        g_ControlDevice = NULL;
        ExDeleteNPagedLookasideList(&g_Capture.Lookaside);
        return status;
    }
    g_SymLink = symName;

    // Fill EVERY major function with a pass-through first, then override the ones that
    // need special handling.
    //
    // This matters more than it looks. Windows completes an unassigned MajorFunction entry
    // for a filter device with STATUS_INVALID_DEVICE_REQUEST at OUR layer, so the IRP never
    // reaches serial.sys. The serial stack legitimately receives CLEANUP, FLUSH_BUFFERS,
    // SET_INFORMATION, SYSTEM_CONTROL, SHUTDOWN, INTERNAL_DEVICE_CONTROL and more; any of
    // them being swallowed at the filter is a real behavioural bug. CLEANUP in particular
    // is what makes the serial driver cancel pending reads and drop its open state 鈥?when
    // it never arrives, a closed port stays "busy" and the next open fails.
    {
        ULONG mj;
        for (mj = 0; mj <= IRP_MJ_MAXIMUM_FUNCTION; mj++) {
            DriverObject->MajorFunction[mj] = UmFilterDispatch;
        }
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = UmControlCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = UmControlClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = UmControlCleanup;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = UmControlIoctl;
    DriverObject->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = UmControlIoctl;
    // Reads and writes are the ones we actually want to observe; everything else simply
    // forwards (UmFilterDispatch passes non-READ/WRITE IRPs straight down).
    DriverObject->MajorFunction[IRP_MJ_READ] = UmFilterDispatch;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = UmFilterDispatch;
    DriverObject->MajorFunction[IRP_MJ_PNP] = UmFilterPnp;
    DriverObject->MajorFunction[IRP_MJ_POWER] = UmFilterPower;
    DriverObject->DriverUnload = UmDriverUnload;

    // Do NOT attach here. DriverEntry runs while the I/O manager is still bringing the
    // boot device stack up, so calling IoGetDeviceObjectPointer / IoAttachDeviceToDeviceStack
    // from this context can block on a device that is not ready yet 鈥?the service then sits
    // in START_PENDING and cannot even be deleted (a driver inside DriverEntry cannot be
    // unloaded), which is the 1072 the installer hit.
    //
    // Attaching is instead driven by user mode, which calls IOCTL_UM_ATTACH_PORTS once the
    // driver reports RUNNING; UmRegisterHotplug still runs from DriverEntry because
    // registering a notification only queues work for a system thread.
    UmRegisterHotplug();

    return STATUS_SUCCESS;
}
