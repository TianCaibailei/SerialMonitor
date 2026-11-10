# THE decisive test.
#
# The race is: a process opens its port within milliseconds of starting, while the
# auto-attach scanner needs ~100-200 ms to notice it. That made every previous test
# ambiguous. Here the SAME long-lived process is injected first and only then opens
# the port, so there is no race at all:
#
#   1. start a PowerShell that waits for a marker file
#   2. start the monitor, let auto-attach inject that PowerShell
#   3. create the marker -> the injected process opens COM6 and talks
#   4. hook records must appear (this proves the hook itself works)
#
# If step 4 passes, the only remaining issue is injection timing, and the fix is to
# attach before the serial tool is launched (or to use a kernel driver).
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe = Join-Path $root 'target\release\universal_monitor.exe'
$marker = Join-Path $env:TEMP "go-$([guid]::NewGuid().ToString('N')).txt"
$result = Join-Path $env:TEMP 'decisive.json'
Remove-Item $marker, $result -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\um_hook_*.log" -ErrorAction SilentlyContinue
Set-Content -Path "$env:TEMP\um_hook_debug" -Value '1'

Write-Output '=== 1. 启动等待中的串口程序（暂不打开端口）==='
$script = @"
`$m = '$marker'
while (-not (Test-Path `$m)) { Start-Sleep -Milliseconds 100 }
Write-Output 'OPENING'
`$p = New-Object System.IO.Ports.SerialPort('COM6', 9600)
`$p.Open()
for (`$i = 0; `$i -lt 40; `$i++) {
    `$p.Write("DEC`$i;")
    Start-Sleep -Milliseconds 250
    `$null = `$p.ReadExisting()
}
`$p.Close()
Write-Output 'DONE'
"@
$tool = Start-Process powershell -PassThru -WindowStyle Hidden -ArgumentList @('-NoProfile','-Command',$script)
Write-Output "工具 PID=$($tool.Id)（仍在等待）"

Write-Output '=== 2. 启动监控，让自动附加注入它 ==='
$mon = Start-Process $exe -PassThru -WindowStyle Hidden -ArgumentList @('--headless-watch','COM6','--result',$result)
$sw = [Diagnostics.Stopwatch]::StartNew()
$injected = $false
while ($sw.ElapsedMilliseconds -lt 15000) {
    $m = Get-Process -Id $tool.Id -Module -ErrorAction SilentlyContinue |
        Where-Object { $_.ModuleName -like 'monitor_hook*' }
    if ($m) { $injected = $true; break }
    Start-Sleep -Milliseconds 300
}
Write-Output "hook 已注入 = $injected"
if (-not $injected) { Write-Output '注入失败，无法继续'; exit 1 }

Write-Output '=== 3. 放行：让被注入的进程打开 COM6 ==='
New-Item -Path $marker -ItemType File -Force | Out-Null

Write-Output '=== 4. 对端发数据 ==='
Start-Sleep -Seconds 2
$peer = New-Object System.IO.Ports.SerialPort('COM7', 9600)
$peer.Open()
for ($i = 0; $i -lt 10; $i++) {
    $peer.Write("PEER$i;")
    Start-Sleep -Milliseconds 250
    $null = $peer.ReadExisting()
}
$peer.Close()

Start-Sleep -Seconds 3
$mon | Wait-Process -Timeout 25 -ErrorAction SilentlyContinue

Write-Output '=== 5. hook 记录（关键证据）==='
Get-ChildItem "$env:TEMP\um_hook_*.log" -ErrorAction SilentlyContinue | ForEach-Object {
    $c = Get-Content $_.FullName
    $hits = $c | Select-String 'cfw|wf|rf:'
    if ($hits) {
        Write-Output "--- $($_.Name) ---"
        $hits | Select-Object -First 10
    }
}

Write-Output '=== 6. 结果 ==='
if (Test-Path $result) { Get-Content $result -Raw }

foreach ($p in @($mon, $tool)) { try { if (-not $p.HasExited) { $p | Stop-Process -Force } } catch {} }
Remove-Item "$env:TEMP\um_hook_debug" -ErrorAction SilentlyContinue
Remove-Item $marker -ErrorAction SilentlyContinue
