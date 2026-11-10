// Minimal kernel driver used ONLY to prove the WDK NuGet toolchain works.
//
// It creates a device object, registers an IRP_MJ_CREATE handler and unloads cleanly —
// the smallest thing that exercises the kernel headers, the kernel import libraries and
// the driver linker settings. If this builds, the environment is usable for the real
// serial filter driver.
#include <ntddk.h>

#define DEVICE_NAME L"\\Device\\UmProbe"
#define SYMLINK_NAME L"\\DosDevices\\UmProbe"

static NTSTATUS ProbeCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static VOID ProbeUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING sym;
    RtlInitUnicodeString(&sym, SYMLINK_NAME);
    IoDeleteSymbolicLink(&sym);
    if (DriverObject->DeviceObject != NULL) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    UNICODE_STRING devName;
    UNICODE_STRING symName;
    PDEVICE_OBJECT device = NULL;

    RtlInitUnicodeString(&devName, DEVICE_NAME);
    RtlInitUnicodeString(&symName, SYMLINK_NAME);

    NTSTATUS status = IoCreateDevice(
        DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = IoCreateSymbolicLink(&symName, &devName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(device);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = ProbeCreate;
    DriverObject->DriverUnload = ProbeUnload;
    return STATUS_SUCCESS;
}
