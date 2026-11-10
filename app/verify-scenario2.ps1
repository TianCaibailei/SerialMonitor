# The real scenario, but with the monitor running so the hook can connect:
#   monitor (headless, watches COM6) starts FIRST
#   -> a serial tool starts and opens COM6
#   -> the monitor must show the traffic.
#
# This is exactly the user's workflow: monitor first, tools after.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe = Join-Path $root 'target\release\universal_monitor.exe'
$result = Join-Path $env:TEMP 'scenario-result.json'
Remove-Item $result -ErrorAction SilentlyContinue

Write-Output '=== 1. 启动监控（监听 COM6，自动附加）==='
$mon = Start-Process $exe -PassThru -WindowStyle Hidden -ArgumentList @('--headless-watch','COM6','--result',$result)
Start-Sleep -Milliseconds 3000
if ($mon.HasExited) { Write-Output "监控提前退出 $($mon.ExitCode)"; exit 1 }
Write-Output "监控 PID=$($mon.Id)"

Write-Output '=== 2. 启动串口工具（打开 COM6 并通信）==='
$tool = Start-Process powershell -PassThru -WindowStyle Hidden -ArgumentList @(
    '-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $root 'tool-a.ps1'))
Start-Sleep -Seconds 2

Write-Output '=== 3. 对端 COM7 发数据 ==='
$peer = New-Object System.IO.Ports.SerialPort('COM7', 9600)
$peer.Open()
for ($i = 0; $i -lt 10; $i++) {
    $peer.Write("PEER$i;")
    Start-Sleep -Milliseconds 300
    $null = $peer.ReadExisting()
}
$peer.Close()

Write-Output '=== 4. 等待监控收集 ==='
Start-Sleep -Seconds 3

$res = $null
if (Test-Path $result) {
    $res = Get-Content $result -Raw | ConvertFrom-Json
    Write-Output "行数=$($res.rows) TX=$($res.tx) RX=$($res.rx)"
    Write-Output "附加=$($res.attached)"
    foreach ($n in $res.notices) { Write-Output "  · $n" }
} else {
    Write-Output '无结果文件'
}

foreach ($p in @($mon, $tool)) { try { if (-not $p.HasExited) { $p | Stop-Process -Force } } catch {} }

Write-Output ''
if ($res -and $res.rows -gt 0) { Write-Output "PASS: 捕获 $($res.rows) 行" } else { Write-Output 'FAIL: 未捕获' }
