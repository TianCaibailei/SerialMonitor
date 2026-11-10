// UmSerialFilter — passive serial-port traffic capture (upper filter, no port ownership).
//
// WHY THIS EXISTS
// ---------------
// The user-mode approach (inject a DLL and patch the target's IAT) has a hard limit:
// it only sees calls made *after* injection, while a serial tool typically opens its
// port within milliseconds of starting. A kernel filter has no such race — it sits on
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
    PDEVICE_OBJECT Physical;  // PDO of the serial device
    ULONG Index;              // index into the attached list
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
    ULONG Count;
    ULONG Dropped;
    ULONG Enabled;
    ULONG TargetPid;
    ULONGLONG Received;
    ULONGLONG Sent;
    ULONG AttachedCount;
    PDEVICE_OBJECT Attached[UM_MAX_FILTERS];
    PCWSTR AttachedNames[UM_MAX_FILTERS];
} UM_CAPTURE, *PUM_CAPTURE;

// GUIDs used for PnP interface notifications.
//
// These live in <initguid.h> territory: the WDK NuGet headers do not ship the
// definitions, only declarations, so they are spelled out here. The values are the
// documented ones from wdmguid.h / ntddser.h:
//   GUID_DEVINTERFACE_COMPORT        — every COM port driver registers this interface
//   GUID_DEVICE_INTERFACE_ARRIVAL    — an interface became available
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

static ULONG UmDequeueRecord(PUCHAR out, ULONG outLen)
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
    entry = RemoveHeadList(&g_Capture.Queue);
    g_Capture.Count--;
    KeReleaseSpinLock(&g_Capture.Lock, old);

    item = CONTAINING_RECORD(entry, UM_RECORD_ITEM, Entry);
    need = UM_RECORD_HEADER + item->Record.Size;
    if (need <= outLen) {
        RtlCopyMemory(out, &item->Record, need);
    } else {
        need = 0;
    }
    ExFreeToNPagedLookasideList(&g_Capture.Lookaside, item);
    return need;
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
            PVOID buf = NULL;

            if (Irp->AssociatedIrp.SystemBuffer != NULL) {
                buf = Irp->AssociatedIrp.SystemBuffer;
            } else if (Irp->MdlAddress != NULL) {
                buf = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
            } else if (stack->MajorFunction == IRP_MJ_WRITE) {
                buf = Irp->UserBuffer;
            }
            if (buf != NULL) {
                UmQueueRecord(ctx->Dir, ctx->Pid, ctx->PortIndex, ctx->Handle, (const UCHAR *)buf, len);
            }
        }
        ExFreePoolWithTag(ctx, UM_TAG);
        Irp->Tail.Overlay.DriverContext[0] = NULL;
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
        PUM_IRP_CTX irpCtx =
            (PUM_IRP_CTX)ExAllocatePoolWithTag(NonPagedPool, sizeof(UM_IRP_CTX), UM_TAG);
        if (irpCtx != NULL) {
            irpCtx->Dir = (stack->MajorFunction == IRP_MJ_READ) ? UM_DIR_RX : UM_DIR_TX;
            irpCtx->Pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
            irpCtx->PortIndex = ctx->Index;
            irpCtx->Handle = (ULONG64)(ULONG_PTR)ctx->Physical;
            stack->CompletionRoutine = UmReadWriteComplete;
            stack->Context = irpCtx;
            stack->Control = SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL;
        } else {
            InterlockedIncrement((PLONG)&g_Capture.Dropped);
        }
    }

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ctx->Lower, Irp);
}

static NTSTATUS UmFilterPnp(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PUM_DEVICE_CTX ctx = (PUM_DEVICE_CTX)DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

    if (stack->MinorFunction == IRP_MN_REMOVE_DEVICE) {
        IoSkipCurrentIrpStackLocation(Irp);
        NTSTATUS status = IoCallDriver(ctx->Lower, Irp);
        if (ctx->Lower != NULL) {
            IoDetachDevice(ctx->Lower);
            ctx->Lower = NULL;
        }
        IoDeleteDevice(DeviceObject);
        return status;
    }
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ctx->Lower, Irp);
}

static NTSTATUS UmFilterPower(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PUM_DEVICE_CTX ctx = (PUM_DEVICE_CTX)DeviceObject->DeviceExtension;
    PoStartNextPowerIrp(Irp);
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
static NTSTATUS UmAttachOne(PDEVICE_OBJECT target, ULONG index, PCWSTR name)
{
    PDEVICE_OBJECT filter = NULL;
    PUM_DEVICE_CTX ctx;
    NTSTATUS status;

    status = IoCreateDevice(
        g_DriverObject, sizeof(UM_DEVICE_CTX), NULL,
        target->DeviceType, target->Characteristics | FILE_DEVICE_SECURE_OPEN,
        FALSE, &filter);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    ctx = (PUM_DEVICE_CTX)filter->DeviceExtension;
    RtlZeroMemory(ctx, sizeof(UM_DEVICE_CTX));
    ctx->Self = filter;
    ctx->Physical = target;
    ctx->Index = index;
    ctx->Lower = IoAttachDeviceToDeviceStack(filter, target);
    if (ctx->Lower == NULL) {
        IoDeleteDevice(filter);
        return STATUS_DEVICE_NOT_CONNECTED;
    }
    filter->Flags |= ctx->Lower->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE);
    filter->Flags &= ~DO_DEVICE_INITIALIZING;
    g_Capture.AttachedNames[index] = name;
    return STATUS_SUCCESS;
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

        status = ZwQueryDirectoryObject(
            dirHandle, buf, bufLen, TRUE /* restart */, TRUE /* single entry */,
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
                        ObDereferenceObject(fileObj);
                        if (NT_SUCCESS(UmAttachOne(devObj, g_Capture.AttachedCount, NULL))) {
                            g_Capture.Attached[g_Capture.AttachedCount] = devObj;
                            g_Capture.AttachedCount++;
                            attached++;
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

static NTSTATUS UmHotplugAttachLink(PUNICODE_STRING link)
{
    PFILE_OBJECT fileObj = NULL;
    PDEVICE_OBJECT devObj = NULL;
    NTSTATUS status;

    status = IoGetDeviceObjectPointer(link, FILE_READ_DATA, &fileObj, &devObj);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    ObDereferenceObject(fileObj);

    if (g_Capture.AttachedCount >= UM_MAX_FILTERS) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    status = UmAttachOne(devObj, g_Capture.AttachedCount, NULL);
    if (NT_SUCCESS(status)) {
        g_Capture.Attached[g_Capture.AttachedCount] = devObj;
        g_Capture.AttachedCount++;
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
        PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES,
        (PVOID)GUID_DEVINTERFACE_COMPORT,
        g_DriverObject,
        UmHotplugCallback,
        NULL,
        &g_NotificationEntry);
    UNREFERENCED_PARAMETER(interfaceClass);
    UNREFERENCED_PARAMETER(status);
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

static NTSTATUS UmControlCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    g_Capture.Enabled = 1;
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS UmControlClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
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

    UNREFERENCED_PARAMETER(DeviceObject);

    switch (code) {
    case IOCTL_UM_GET_RECORD:
        if (buf != NULL && outLen >= UM_RECORD_HEADER) {
            info = UmDequeueRecord((PUCHAR)buf, outLen);
            status = STATUS_SUCCESS;
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
        info = UmAttachAllPorts();
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
        if (buf != NULL && outLen >= 32) {
            PULONG s = (PULONG)buf;
            s[0] = g_Capture.Count;
            s[1] = g_Capture.Dropped;
            s[2] = (ULONG)g_Capture.Received;
            s[3] = (ULONG)g_Capture.Sent;
            s[4] = g_Capture.Enabled;
            s[5] = g_Capture.TargetPid;
            s[6] = g_Capture.AttachedCount;
            s[7] = 0;
            info = 32;
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
    // Detach every filter we installed, newest first.
    while (g_Capture.AttachedCount > 0) {
        g_Capture.AttachedCount--;
    }
    ExDeleteNPagedLookasideList(&g_Capture.Lookaside);
}

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
    InitializeListHead(&g_Capture.Queue);
    ExInitializeNPagedLookasideList(
        &g_Capture.Lookaside, NULL, NULL, POOL_NX_ALLOCATION,
        sizeof(UM_RECORD_ITEM), UM_TAG, 0);
    g_Capture.Enabled = 1;

    RtlInitUnicodeString(&devName, UM_DEVICE_NAME);
    status = IoCreateDevice(
        DriverObject, sizeof(UM_DEVICE_CTX), &devName,
        FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device);
    if (!NT_SUCCESS(status)) {
        ExDeleteNPagedLookasideList(&g_Capture.Lookaside);
        return status;
    }
    device->Flags |= DO_BUFFERED_IO;
    device->Characteristics |= FILE_DEVICE_SECURE_OPEN;
    ctx = (PUM_DEVICE_CTX)device->DeviceExtension;
    RtlZeroMemory(ctx, sizeof(UM_DEVICE_CTX));
    ctx->Self = device;
    ctx->PassThroughOnly = TRUE;
    g_ControlDevice = device;

    RtlInitUnicodeString(&symName, UM_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symName, &devName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(device);
        g_ControlDevice = NULL;
        ExDeleteNPagedLookasideList(&g_Capture.Lookaside);
        return status;
    }
    g_SymLink = symName;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = UmControlCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = UmControlClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = UmControlIoctl;
    DriverObject->MajorFunction[IRP_MJ_READ] = UmFilterDispatch;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = UmFilterDispatch;
    DriverObject->MajorFunction[IRP_MJ_PNP] = UmFilterPnp;
    DriverObject->MajorFunction[IRP_MJ_POWER] = UmFilterPower;
    DriverObject->DriverUnload = UmDriverUnload;

    // Attach to the ports that already exist, then keep watching for arrivals so a
    // USB-serial adapter plugged in later is filtered without user action.
    UmAttachAllPorts();
    UmRegisterHotplug();

    return STATUS_SUCCESS;
}
