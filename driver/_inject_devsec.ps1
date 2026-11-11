# Replace the direct IoCreateDeviceSecure call with a dynamically resolved one.
#
# WHY: wdmsec.lib does not export IoCreateDeviceSecure directly — it exports only
# PfnIoCreateDeviceSecure plus WdmlibInit, and linking the real symbol fails with
# LNK2019. The reference driver (ComDrv12x64.sys, sub_22008) resolves it at runtime with
# MmGetSystemRoutineAddress for exactly this reason, which also keeps the driver loadable
# on systems where the API is absent.
$ErrorActionPreference = 'Stop'
$path = 'E:\Documents\MonitorAnything\MonitorAnything\driver\umserialfilter\umserialfilter.c'
$src = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)

$marker = '// === UM_CREATE_CONTROL_DEVICE ==='
if ($src.Contains($marker)) {
    Write-Output '辅助函数已存在，跳过'
    exit 0
}

$block = @'
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

'@

$needle = '// === UM_SECURITY_LAYER ==='
if (-not $src.Contains($needle)) {
    throw '找不到安全层标记，无法确定插入位置'
}
$src = $src.Replace($needle, $block + $needle)
[System.IO.File]::WriteAllText($path, $src, (New-Object System.Text.UTF8Encoding $false))
Write-Output '已注入 UmCreateControlDevice'
