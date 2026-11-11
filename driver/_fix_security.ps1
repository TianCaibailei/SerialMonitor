# Remove the unused hand-built security descriptor helper and hoist the auth macro.
#
# UmBuildDeviceSd was written before switching to IoCreateDeviceSecure (which takes an
# SDDL string and needs no manual ACL construction). Keeping it would require the whole
# ntifs/security type set, which the WDK NuGet headers do not expose — and it would be
# dead code anyway.
$ErrorActionPreference = 'Stop'
$path = 'E:\Documents\MonitorAnything\MonitorAnything\driver\umserialfilter\umserialfilter.c'
$src = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)

$startMarker = '// Build a self-relative security descriptor: SY=full, BA=full, BU=read/write.'
$endMarker = '// Generate a random per-boot session key and publish it for the service to read.'

$start = $src.IndexOf($startMarker)
if ($start -ge 0) {
    $end = $src.IndexOf($endMarker)
    if ($end -gt $start) {
        $src = $src.Substring(0, $start) + $src.Substring($end)
        Write-Output '已移除 UmBuildDeviceSd'
    }
} else {
    Write-Output 'UmBuildDeviceSd 已不存在'
}

# Move the auth flag up next to the other UM_ constants so it is visible everywhere.
$flagDef = '#define UM_CTX_AUTHENTICATED 0x00000001UL'
$src = $src.Replace($flagDef + "`r`n", '')
$src = $src.Replace($flagDef + "`n", '')
$anchor = '#define UM_MAX_PAYLOAD 4096'
if ($src.Contains($anchor) -and -not $src.Contains('#define UM_CTX_AUTHENTICATED 0x00000001UL' + "`r`n#define UM_MAX_PAYLOAD")) {
    $src = $src.Replace(
        $anchor,
        '#define UM_CTX_AUTHENTICATED 0x00000001UL' + "`r`n" +
        '// Registry location where the session key is published.' + "`r`n" +
        '#define UM_PARAMS_KEY   L"\Registry\Machine\Software\UmSerialFilter"' + "`r`n" +
        '#define UM_PARAMS_VALUE L"SessionKey"' + "`r`n`r`n" + $anchor)
    Write-Output '已上移认证宏定义'
}

$src = $src.Replace('#define UM_PARAMS_KEY   L"\\Registry\\Machine\\Software\\UmSerialFilter"' + "`r`n", '')
$src = $src.Replace('#define UM_PARAMS_VALUE L"SessionKey"' + "`r`n", '')

[System.IO.File]::WriteAllText($path, $src, (New-Object System.Text.UTF8Encoding $false))
Write-Output '完成'
