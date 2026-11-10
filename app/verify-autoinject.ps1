# Does the auto-attach path actually inject anything at all?
# Starts a simple long-lived process, waits for the auto-attach thread to notice it,
# and reports whether its hook DLL got loaded.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe = Join-Path $root 'target\release\universal_monitor.exe'

Write-Output '=== 1. 启动一个目标进程（不开串口）==='
$target = Start-Process powershell -PassThru -WindowStyle Hidden -ArgumentList @(
    '-NoProfile', '-Command', 'Start-Sleep -Seconds 60')
Write-Output "目标 PID=$($target.Id)"

Write-Output '=== 2. 启动监控（会自动附加所有新进程）==='
$mon = Start-Process $exe -PassThru -WindowStyle Hidden -ArgumentList @(
    '--headless-watch', 'COM6', '--result', (Join-Path $env:TEMP 'probe.json'))
Start-Sleep -Seconds 6

Write-Output '=== 3. 检查目标进程是否加载了 hook DLL ==='
$found = $false
for ($i = 0; $i -lt 10; $i++) {
    $mods = Get-Process -Id $target.Id -Module -ErrorAction SilentlyContinue | Where-Object { $_.ModuleName -like 'monitor_hook*' }
    if ($mods) { $found = $true; break }
    Start-Sleep -Milliseconds 800
}
if ($found) { Write-Output '结果: hook DLL 已加载到目标进程 (自动附加生效)' }
else { Write-Output '结果: hook DLL 未加载 (自动附加未生效)' }

foreach ($p in @($mon, $target)) { try { if (-not $p.HasExited) { $p | Stop-Process -Force } } catch {} }
