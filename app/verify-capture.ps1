# End-to-end proof of passive serial capture, with the injection ordering enforced.
#
# The hook is an IAT patch, so it can only see calls made AFTER it is installed. A tool
# that opens its port within milliseconds of starting will slip through; the monitor
# therefore has to be inside the process before that happens. This test makes the
# ordering deterministic instead of hoping the race is won:
#
#   1. the tool starts and waits for a marker file
#   2. the monitor injects it (auto-attach or explicit inject)
#   3. the marker is created, so the tool opens COM6 only now
#   4. traffic must appear in the session (rows/tx/rx > 0)
#
# Run: powershell -File verify-capture.ps1
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe = Join-Path $root 'target\release\universal_monitor.exe'
$marker = Join-Path $env:TEMP "um_go_$([guid]::NewGuid().ToString('N')).txt"
$result = Join-Path $env:TEMP 'capture-result.json'
Remove-Item $marker, $result -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\um_hook_*.log" -ErrorAction SilentlyContinue
Set-Content -Path "$env:TEMP\um_hook_debug" -Value '1'

function Get-Arch([string]$p) {
    $b = [System.IO.File]::ReadAllBytes($p)
    $pe = [BitConverter]::ToInt32($b, 0x3C)
    switch ([BitConverter]::ToUInt16($b, $pe + 4)) {
        0x014C { 'x86' }
        0x8664 { 'x64' }
        default { '?' }
    }
}

$monArch = Get-Arch $exe
Write-Output "监控程序架构: $monArch"

Write-Output '=== 1. 启动监控（监听 COM6）==='
$mon = Start-Process $exe -PassThru -WindowStyle Hidden -ArgumentList @('--headless-watch', 'COM6', '--result', $result)
Start-Sleep -Seconds 4
if ($mon.HasExited) {
    Write-Output "监控提前退出，码 $($mon.ExitCode)"
    exit 1
}
Write-Output "监控 PID = $($mon.Id)"

Write-Output '=== 2. 启动等待中的串口程序 ==='
$tool = Start-Process $exe -PassThru -WindowStyle Hidden -ArgumentList @(
    '--native-serial-delayed', 'COM6', '9000', $marker)
Write-Output "工具 PID = $($tool.Id)"

# Wait until the hook DLL is genuinely inside the target before releasing it.
$injected = $false
$sw = [Diagnostics.Stopwatch]::StartNew()
while ($sw.ElapsedMilliseconds -lt 20000) {
    $log = Join-Path $env:TEMP "um_hook_$($tool.Id).log"
    if (Test-Path $log) {
        $txt = Get-Content $log -Raw
        if ($txt -match 'worker ready' -or $txt -match 'patched') {
            $injected = $true
            break
        }
    }
    Start-Sleep -Milliseconds 300
}
Write-Output "hook 已进入目标进程: $injected"
if (-not $injected) {
    Write-Output '注入失败，测试无法继续'
    try { $mon | Stop-Process -Force } catch {}
    try { $tool | Stop-Process -Force } catch {}
    exit 1
}

Write-Output '=== 3. 放行：让工具现在才打开 COM6 ==='
New-Item -Path $marker -ItemType File -Force | Out-Null
Start-Sleep -Seconds 2

Write-Output '=== 4. 对端 COM7 发送数据 ==='
try {
    $peer = New-Object System.IO.Ports.SerialPort('COM7', 9600)
    $peer.Open()
    for ($i = 0; $i -lt 10; $i++) {
        $peer.Write("PEER$i;")
        Start-Sleep -Milliseconds 250
        $null = $peer.ReadExisting()
    }
    $peer.Close()
} catch {
    Write-Output "对端发送失败（COM7 可能不存在）: $($_.Exception.Message)"
}

Start-Sleep -Seconds 6
$mon | Wait-Process -Timeout 30 -ErrorAction SilentlyContinue

Write-Output '=== 5. hook 记录 ==='
$cfw = 0
Get-ChildItem "$env:TEMP\um_hook_*.log" -ErrorAction SilentlyContinue | ForEach-Object {
    $lines = Get-Content $_.FullName
    $hits = $lines | Select-String 'cfw|wf|rf:'
    if ($hits) {
        Write-Output "--- $($_.Name) ---"
        $hits | Select-Object -First 8 | ForEach-Object { Write-Output "  $_" }
        $cfw += ($hits | Select-String 'cfw').Count
    }
}

Write-Output '=== 6. 会话结果 ==='
$rows = 0; $tx = 0; $rx = 0
if (Test-Path $result) {
    $j = Get-Content $result -Raw
    if ($j -match '"rows":(\d+)') { $rows = [int]$Matches[1] }
    if ($j -match '"tx":(\d+)') { $tx = [int]$Matches[1] }
    if ($j -match '"rx":(\d+)') { $rx = [int]$Matches[1] }
    Write-Output "rows=$rows tx=$tx rx=$rx"
} else {
    Write-Output '结果文件未生成'
}

foreach ($p in @($mon, $tool)) { try { if (-not $p.HasExited) { $p | Stop-Process -Force } } catch {} }
Remove-Item "$env:TEMP\um_hook_debug", $marker -ErrorAction SilentlyContinue

Write-Output ''
Write-Output '=== 结论 ==='
Write-Output "打开串口被拦截: $($cfw -gt 0)"
Write-Output "会话收到数据:   $(($rows -gt 0) -or ($tx -gt 0) -or ($rx -gt 0))"
if (($cfw -gt 0) -and (($rows -gt 0) -or ($tx -gt 0) -or ($rx -gt 0))) {
    Write-Output 'PASS: 被动串口捕获端到端可用'
    exit 0
}
Write-Output 'FAIL'
exit 1
