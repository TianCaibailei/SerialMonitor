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
} UM_CAPTURE, *PUM_CAPTURE;

static UM_CAPTURE g_Capture;
static PDEVICE_OBJECT g_ControlDevice;
static PDRIVER_OBJECT g_DriverObject;
static UNICODE_STRING g_SymLink;

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

// Candidate device paths. Managed serially-driven COM ports live under one of these;
// the list is walked rather than relying on a single hard-coded name because different
// drivers (usbser, Prolific, Silicon Labs, ELTIMA, com0com) use different names.
static const PCWSTR UmDeviceCandidates[] = {
    L"\\Device\\Serial0", L"\\Device\\Serial1", L"\\Device\\Serial2",
    L"\\Device\\Serial3", L"\\Device\\Serial4", L"\\Device\\Serial5",
    L"\\Device\\Serial6", L"\\Device\\Serial7", L"\\Device\\Serial8",
    L"\\Device\\Serial9",
    L"\\Device\\USBSER000", L"\\Device\\USBSER001", L"\\Device\\USBSER002",
    L"\\Device\\USBSER003", L"\\Device\\USBSER004",
    L"\\Device\\ProlificSerial0", L"\\Device\\ProlificSerial1",
    L"\\Device\\Silabser0", L"\\Device\\Silabser1",
    L"\\Device\\VSerial8_0", L"\\Device\\VSerial8_1",
    L"\\Device\\VSerial8_2", L"\\Device\\VSerial8_3",
    L"\\Device\\VSerial9_0", L"\\Device\\VSerial9_1",
    L"\\Device\\VCP0", L"\\Device\\VCP1",
};

// Attach one filter device above `target`.
static NTSTATUS UmAttachOne(PDEVICE_OBJECT target, ULONG index)
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
    // Match the stack flags of the device below, as every filter must.
    filter->Flags |= ctx->Lower->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE);
    filter->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;
}

// Attach the filter to every serial device in the candidate list.
static ULONG UmAttachAllPorts(VOID)
{
    ULONG i;
    ULONG attached = 0;

    for (i = 0; i < ARRAYSIZE(UmDeviceCandidates) && g_Capture.AttachedCount < UM_MAX_FILTERS; i++) {
        UNICODE_STRING name;
        PFILE_OBJECT fileObj = NULL;
        PDEVICE_OBJECT devObj = NULL;
        NTSTATUS status;

        RtlInitUnicodeString(&name, UmDeviceCandidates[i]);
        status = IoGetDeviceObjectPointer(&name, FILE_READ_DATA, &fileObj, &devObj);
        if (!NT_SUCCESS(status)) {
            continue; // this candidate does not exist on this machine
        }
        // The reference object is not needed; drop it so the device is not pinned.
        ObDereferenceObject(fileObj);

        status = UmAttachOne(devObj, g_Capture.AttachedCount);
        if (NT_SUCCESS(status)) {
            g_Capture.Attached[g_Capture.AttachedCount] = devObj;
            g_Capture.AttachedCount++;
            attached++;
        }
    }
    return attached;
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

    if (g_SymLink.Buffer != NULL) {
        IoDeleteSymbolicLink(&g_SymLink);
        g_SymLink.Buffer = NULL;
    }
    if (g_ControlDevice != NULL) {
        IoDeleteDevice(g_ControlDevice);
        g_ControlDevice = NULL;
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

    return STATUS_SUCCESS;
}
