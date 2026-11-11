# Inject the security/session-key layer into umserialfilter.c.
#
# This exists because the driver source has been edited many times in this session and
# large literal replacements keep racing with other edits. The injected block is inserted
# once, immediately before DriverEntry, and IsIdempotent (a second run detects the marker
# and does nothing).
$ErrorActionPreference = 'Stop'
$path = 'E:\Documents\MonitorAnything\MonitorAnything\driver\umserialfilter\umserialfilter.c'
$src = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)
$marker = '// === UM_SECURITY_LAYER ==='

if ($src.Contains($marker)) {
    Write-Output '安全层已存在，跳过注入'
    exit 0
}

$block = @'
// === UM_SECURITY_LAYER ===
// ---------------------------------------------------------------------------
// Device security: only our own software may be able to use this driver
// ---------------------------------------------------------------------------
//
// A monitor that can read every serial byte is exactly the kind of device an attacker
// would like to open, so the control device must not be world-accessible.
//
// The reference product handles this with a security descriptor built from the SDDL
// string "D:P(A;;GA;;;WD)" — GA to Everyone, i.e. no protection at all (verified in its
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
// through 11 — no dynamic resolution and no signed-driver requirement.

// Set in UM_DEVICE_CTX.Flags once a control handle has passed the handshake.
#define UM_CTX_AUTHENTICATED 0x00000001UL

#define UM_PARAMS_KEY   L"\\Registry\\Machine\\Software\\UmSerialFilter"
#define UM_PARAMS_VALUE L"SessionKey"

// Build a self-relative security descriptor: SY=full, BA=full, BU=read/write.
// The caller frees the returned descriptor with ExFreePoolWithTag.
static NTSTATUS UmBuildDeviceSd(PSECURITY_DESCRIPTOR *outSd)
{
    PSECURITY_DESCRIPTOR absSd = NULL;
    PSECURITY_DESCRIPTOR relSd = NULL;
    PACL dacl = NULL;
    ULONG daclSize;
    ULONG sdSize = 0;
    NTSTATUS status;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    UCHAR sidBuf[3][SECURITY_MAX_SID_SIZE];
    PSID sids[3];
    ACCESS_MASK masks[3];
    ULONG i;

    *outSd = NULL;

    daclSize = sizeof(ACL) + 3 * (sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG) + SECURITY_MAX_SID_SIZE);
    dacl = (PACL)ExAllocatePoolWithTag(NonPagedPool, daclSize, UM_TAG);
    absSd = (PSECURITY_DESCRIPTOR)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(SECURITY_DESCRIPTOR), UM_TAG);
    if (dacl == NULL || absSd == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }

    // LocalSystem (S-1-5-18)
    sids[0] = (PSID)sidBuf[0];
    if (!NT_SUCCESS(RtlInitializeSid(sids[0], &ntAuthority, 1))) {
        status = STATUS_INVALID_PARAMETER;
        goto done;
    }
    *RtlSubAuthoritySid(sids[0], 0) = SECURITY_LOCAL_SYSTEM_RID;
    masks[0] = GENERIC_ALL;

    // Builtin Administrators (S-1-5-32-544)
    sids[1] = (PSID)sidBuf[1];
    if (!NT_SUCCESS(RtlInitializeSid(sids[1], &ntAuthority, 2))) {
        status = STATUS_INVALID_PARAMETER;
        goto done;
    }
    *RtlSubAuthoritySid(sids[1], 0) = SECURITY_BUILTIN_DOMAIN_RID;
    *RtlSubAuthoritySid(sids[1], 1) = DOMAIN_ALIAS_RID_ADMINS;
    masks[1] = GENERIC_ALL;

    // Builtin Users (S-1-5-32-545) — interactive users may run the monitor, but the
    // session-key handshake still gates every operation.
    sids[2] = (PSID)sidBuf[2];
    if (!NT_SUCCESS(RtlInitializeSid(sids[2], &ntAuthority, 2))) {
        status = STATUS_INVALID_PARAMETER;
        goto done;
    }
    *RtlSubAuthoritySid(sids[2], 0) = SECURITY_BUILTIN_DOMAIN_RID;
    *RtlSubAuthoritySid(sids[2], 1) = DOMAIN_ALIAS_RID_USERS;
    masks[2] = GENERIC_READ | GENERIC_WRITE;

    status = RtlCreateAcl(dacl, daclSize, ACL_REVISION);
    if (!NT_SUCCESS(status)) {
        goto done;
    }
    for (i = 0; i < 3; i++) {
        status = RtlAddAccessAllowedAce(dacl, ACL_REVISION, masks[i], sids[i]);
        if (!NT_SUCCESS(status)) {
            goto done;
        }
    }

    status = RtlCreateSecurityDescriptor(absSd, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(status)) {
        goto done;
    }
    // Protected DACL (TRUE): nothing is inherited from \Device, so an inherited ACE cannot
    // silently widen access.
    status = RtlSetDaclSecurityDescriptor(absSd, TRUE, dacl, FALSE);
    if (!NT_SUCCESS(status)) {
        goto done;
    }

    RtlAbsoluteToSelfRelativeSD(absSd, NULL, &sdSize);
    if (sdSize == 0) {
        status = STATUS_INVALID_PARAMETER;
        goto done;
    }
    relSd = (PSECURITY_DESCRIPTOR)ExAllocatePoolWithTag(NonPagedPool, sdSize, UM_TAG);
    if (relSd == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }
    status = RtlAbsoluteToSelfRelativeSD(absSd, relSd, &sdSize);
    if (!NT_SUCCESS(status)) {
        goto done;
    }
    *outSd = relSd;
    relSd = NULL; // ownership transferred to the caller
    status = STATUS_SUCCESS;

done:
    if (dacl != NULL) {
        ExFreePoolWithTag(dacl, UM_TAG);
    }
    if (absSd != NULL) {
        ExFreePoolWithTag(absSd, UM_TAG);
    }
    if (relSd != NULL) {
        ExFreePoolWithTag(relSd, UM_TAG);
    }
    return status;
}

// Generate a random per-boot session key and publish it for the service to read.
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

'@

$needle = 'NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)'
if (-not $src.Contains($needle)) {
    throw '找不到 DriverEntry 定义'
}
$src = $src.Replace($needle, $block + $needle)
[System.IO.File]::WriteAllText($path, $src, (New-Object System.Text.UTF8Encoding $false))
Write-Output '已注入安全层'
