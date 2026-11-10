# Verify that the monitor can inject its hook into BOTH 64-bit and 32-bit targets.
#
# This is the acceptance test for the dual-architecture support:
#   * a 64-bit process gets monitor_hook.dll
#   * a 32-bit (WOW64) process gets monitor_hook_x86.dll via universal_injector_x86.exe
#   * in both cases the hook reports "patched" and "worker ready"
#
# Run: powershell -File verify-dual-arch.ps1
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe = Join-Path $root 'target\release\universal_monitor.exe'

function Get-Arch([string]$path) {
    $b = [System.IO.File]::ReadAllBytes($path)
    $pe = [BitConverter]::ToInt32($b, 0x3C)
    switch ([BitConverter]::ToUInt16($b, $pe + 4)) {
        0x014C { 'x86' }
        0x8664 { 'x64' }
        default { 'unknown' }
    }
}

function Test-Injection([string]$label, [string]$exePath, [string[]]$arguments) {
    Write-Output "=== $label ==="
    Remove-Item "$env:TEMP\um_hook_*.log" -ErrorAction SilentlyContinue
    Set-Content -Path "$env:TEMP\um_hook_debug" -Value '1'

    if ($arguments.Count -gt 0) { $target = Start-Process $exePath -PassThru -ArgumentList $arguments } else { $target = Start-Process $exePath -PassThru }
    Start-Sleep -Seconds 2
    Write-Output "  目标 PID = $($target.Id)"

    $out = & $exe '--inject-test' $target.Id 2>&1 | Out-String
    $ok = $out -match '注入成功' -and $out -match '模块已加载 = true'
    ($out -split "`n" | Where-Object { $_ -match '注入|模块' }) | ForEach-Object {
        Write-Output "  $($_.Trim())"
    }

    Start-Sleep -Seconds 2
    $hookOk = $false
    $hookLines = @()
    Get-ChildItem "$env:TEMP\um_hook_*.log" -ErrorAction SilentlyContinue | ForEach-Object {
        $lines = Get-Content $_.FullName
        $hookLines += $lines
        if (($lines | Select-String 'patched' -Quiet) -and ($lines | Select-String 'worker ready' -Quiet)) {
            $hookOk = $true
        }
    }
    Write-Output "  hook 日志: $($hookLines -join ', ')"

    try { if (-not $target.HasExited) { $target | Stop-Process -Force } } catch {}
    Remove-Item "$env:TEMP\um_hook_debug" -ErrorAction SilentlyContinue

    if ($ok -and $hookOk) {
        Write-Output "  结果: PASS"
        return $true
    }
    Write-Output "  结果: FAIL (注入=$ok hook=$hookOk)"
    return $false
}

Write-Output '=== 部署架构检查 ==='
$rel = Join-Path $root 'target\release'
foreach ($f in @('monitor_hook.dll', 'monitor_hook_x86.dll', 'universal_injector_x86.exe')) {
    $p = Join-Path $rel $f
    if (Test-Path $p) {
        Write-Output ('  {0,-30} {1}' -f $f, (Get-Arch $p))
    } else {
        Write-Output ('  {0,-30} 缺失' -f $f)
    }
}
Write-Output ''

# 64-bit target: Notepad is 64-bit on 64-bit Windows.
$a = Test-Injection '64 位目标 (notepad)' (Join-Path $env:WINDIR 'System32\notepad.exe') @()

# 32-bit target: the SysWOW64 copy of cmd runs as a WOW64 process.
$b = Test-Injection '32 位目标 (SysWOW64 cmd)' (Join-Path $env:WINDIR 'SysWOW64\cmd.exe') @('/k', 'title wow64test')

Write-Output ''
Write-Output '=== 总结 ==='
Write-Output "64 位注入: $(if ($a) { 'PASS' } else { 'FAIL' })"
Write-Output "32 位注入: $(if ($b) { 'PASS' } else { 'FAIL' })"
if ($a -and $b) {
    Write-Output 'PASS: 双架构注入均可用'
    exit 0
}
exit 1
