# Ground-truth test: monitor running, then a NEW process starts, monitor injects it
# as soon as it appears, and captures its port traffic.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe = Join-Path $root 'target\release\universal_monitor.exe'
$result = Join-Path $env:TEMP 'gt-result.json'
Remove-Item $result -ErrorAction SilentlyContinue

Write-Output '=== 启动监控（headless，监听 COM6）==='
$mon = Start-Process $exe -PassThru -WindowStyle Hidden -ArgumentList @('--headless-watch','COM6','--result',$result)
Start-Sleep -Milliseconds 2500
Write-Output "监控 PID=$($mon.Id) 存活=$(-not $mon.HasExited)"

Write-Output '=== 启动新进程（会被自动发现并注入）==='
$a = Start-Process powershell -PassThru -WindowStyle Hidden -ArgumentList @(
    '-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $root 'tool-a.ps1'))
Write-Output "工具 A PID=$($a.Id)"
Start-Sleep -Seconds 2

Write-Output '=== 对端发数据 ==='
$peer = New-Object System.IO.Ports.SerialPort('COM7', 9600)
$peer.Open()
for ($i = 0; $i -lt 8; $i++) { $peer.Write("P$i;"); Start-Sleep -Milliseconds 300; $null = $peer.ReadExisting() }
$peer.Close()
Start-Sleep -Seconds 3

if (Test-Path $result) {
    $res = Get-Content $result -Raw | ConvertFrom-Json
    Write-Output "行数=$($res.rows) TX=$($res.tx) RX=$($res.rx)"
    Write-Output "附加=$($res.attached)"
    foreach ($n in $res.notices) { Write-Output "  · $n" }
} else {
    Write-Output '无结果'
}
foreach ($p in @($mon,$a)) { try { if (-not $p.HasExited) { $p | Stop-Process -Force } } catch {} }
