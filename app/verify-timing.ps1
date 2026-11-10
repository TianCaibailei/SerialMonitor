# Deterministic timing test: the monitored process waits for a marker file before it
# opens the port, so injection is guaranteed to happen BEFORE the port is opened.
# If the hook still catches no reads/writes, the problem is the API path (.NET caching),
# not the injection timing.
param(
    [string]$MonitorExe = "$PSScriptRoot\target\release\universal_monitor.exe",
    [string]$Port = 'COM6',
    [string]$Peer = 'COM7'
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$marker = Join-Path $env:TEMP "go-$([guid]::NewGuid().ToString('N')).txt"
$result = Join-Path $env:TEMP 'timing-result.json'
Remove-Item $result, $marker -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\um_hook_*.log" -ErrorAction SilentlyContinue
Set-Content -Path "$env:TEMP\um_hook_debug" -Value '1'

Write-Output '=== 1. 启动监控 ==='
$mon = Start-Process $MonitorExe -PassThru -WindowStyle Hidden -ArgumentList @(
    '--headless-watch', $Port, '--result', $result)
Start-Sleep -Milliseconds 3500
Write-Output "监控存活=$(-not $mon.HasExited)"

Write-Output '=== 2. 启动延迟打开端口的程序 ==='
$tool = Start-Process powershell -PassThru -WindowStyle Hidden -ArgumentList @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command',
    "`$m='$marker'; while (-not (Test-Path `$m)) { Start-Sleep -Milliseconds 100 }; " +
    "`$p=New-Object System.IO.Ports.SerialPort('$Port',9600); `$p.Open(); " +
    "for (`$i=0; `$i -lt 30; `$i++) { `$p.Write(`"T`$i;`"); Start-Sleep -Milliseconds 250; `$null=`$p.ReadExisting() }; " +
    "`$p.Close()")
Write-Output "工具 PID=$($tool.Id)"

Write-Output '=== 3. 等自动附加注入，然后放行 ==='
Start-Sleep -Seconds 6
Write-Output '--- 此时 hook 日志 ---'
Get-ChildItem "$env:TEMP\um_hook_*.log" -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Output "文件: $($_.Name)"; Get-Content $_.FullName | Select-Object -First 5
}
New-Item -Path $marker -ItemType File -Force | Out-Null
Write-Output '=== 4. 端口已放行，等待通信 ==='

Write-Output '=== 5. 对端发数据 ==='
$peerPort = New-Object System.IO.Ports.SerialPort($Peer, 9600)
$peerPort.Open()
for ($i = 0; $i -lt 12; $i++) {
    $peerPort.Write("FROM-PEER$i;")
    Start-Sleep -Milliseconds 250
    $null = $peerPort.ReadExisting()
}
$peerPort.Close()

Start-Sleep -Seconds 3
$mon | Wait-Process -Timeout 25 -ErrorAction SilentlyContinue

Write-Output '=== 6. hook 日志（含 cfw/wf/rf）==='
Get-ChildItem "$env:TEMP\um_hook_*.log" -ErrorAction SilentlyContinue | ForEach-Object {
    $lines = Get-Content $_.FullName
    $hits = $lines | Select-String 'cfw|wf|rf:|com_label.*serial'
    if ($hits) {
        Write-Output "--- $($_.Name) ---"
        $hits | Select-Object -First 12
    }
}

Write-Output '=== 7. 结果 ==='
$res = $null
if (Test-Path $result) {
    $res = Get-Content $result -Raw | ConvertFrom-Json
    Write-Output "行数=$($res.rows) TX=$($res.tx) RX=$($res.rx)"
    Write-Output "附加=$($res.attached)"
}
foreach ($p in @($mon, $tool)) { try { if (-not $p.HasExited) { $p | Stop-Process -Force } } catch {} }
Remove-Item "$env:TEMP\um_hook_debug" -ErrorAction SilentlyContinue
Remove-Item $marker -ErrorAction SilentlyContinue

if ($res -and $res.rows -gt 0) { Write-Output 'PASS' } else { Write-Output 'FAIL' }
