# Reproduce the user's exact scenario:
#   1. start the monitor (passive listen on COM6)
#   2. start a serial tool that opens COM6 and sends data
#   3. start another serial tool that opens COM7 and sends data
#   4. assert the monitor's session received rows WITHOUT any manual attach step
#
# The monitor is started with a hidden --headless-watch hook that runs the same
# auto-attach service the UI uses, so this tests the real code path.
param(
    [string]$Exe = "$PSScriptRoot\target\release\universal_monitor.exe"
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$resultFile = Join-Path $env:TEMP 'watch-result.json'
Remove-Item $resultFile -ErrorAction SilentlyContinue

Write-Output '=== 1. 启动监控（监听 COM6，被动模式）==='
$mon = Start-Process $Exe -PassThru -ArgumentList @('--headless-watch', 'COM6', '--result', $resultFile) -WindowStyle Hidden
Start-Sleep -Milliseconds 2500
if ($mon.HasExited) {
    Write-Output "监控退出，码 $($mon.ExitCode)"
    exit 1
}
Write-Output "监控运行中 PID=$($mon.Id)"

Write-Output '=== 2. 启动串口工具 A（打开 COM6 发送数据）==='
$a = Start-Process powershell -PassThru -WindowStyle Hidden -ArgumentList @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $root 'tool-a.ps1')
)
Start-Sleep -Milliseconds 1200

Write-Output '=== 3. 启动串口工具 B（打开 COM7 发送数据）==='
$b = Start-Process powershell -PassThru -WindowStyle Hidden -ArgumentList @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $root 'tool-b.ps1')
)

Write-Output '=== 4. 等待监控收集数据（8 秒）==='
Start-Sleep -Seconds 8

Write-Output '=== 5. 读取监控结果 ==='
if (Test-Path $resultFile) {
    $res = Get-Content $resultFile -Raw | ConvertFrom-Json
    Write-Output "会话数: $($res.sessions)"
    Write-Output "捕获行数: $($res.rows)"
    Write-Output "TX 字节: $($res.tx)"
    Write-Output "RX 字节: $($res.rx)"
    Write-Output "附加进程: $($res.attached)"
    foreach ($n in $res.notices) { Write-Output "  · $n" }
} else {
    Write-Output '结果文件未生成（监控未收到数据）'
    $res = $null
}

foreach ($p in @($mon, $a, $b)) {
    try { if ($p -and -not $p.HasExited) { $p | Stop-Process -Force } } catch {}
}

Write-Output ''
Write-Output '=== 结论 ==='
if ($res -and $res.rows -gt 0) {
    Write-Output "PASS: 无需手动附加，监控自动捕获到 $($res.rows) 行数据"
} else {
    Write-Output 'FAIL: 未捕获到数据'
}
