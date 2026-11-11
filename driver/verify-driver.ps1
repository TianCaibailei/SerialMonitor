# Verify the driver is safe and working, in the right order.
#
# THE ORDER MATTERS. The first driver build broke serial ports while reporting success:
# it answered IRP_MJ_CREATE itself instead of forwarding it, so every COM port looked
# occupied even though nothing captured. Checking "did we capture data" first would have
# hidden that. This script therefore checks, in order:
#
#   1. the driver is loaded and running
#   2. serial ports can STILL be opened by a normal program   <- the non-negotiable one
#   3. the driver attached to them
#   4. traffic actually flows through
#
# Run elevated (needs to query the service):
#   powershell -ExecutionPolicy Bypass -File verify-driver.ps1
$ErrorActionPreference = 'Continue'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$reader = Join-Path $root 'umfilter_reader\umfilter_reader.exe'
$serviceName = 'UmSerialFilter'
$failed = 0

function Step([string]$n) {
    Write-Output ''
    Write-Output "=== $n ==="
}

function Fail([string]$msg) {
    Write-Output "  FAIL: $msg"
    $script:failed++
}

Step '1/4 驱动状态'
$q = & sc.exe query $serviceName 2>&1 | Out-String
if ($q -notmatch 'SERVICE_NAME') {
    Fail '服务不存在，请先运行 setup-driver.ps1'
    Write-Output ''
    Write-Output '后续检查跳过。'
    exit 1
}
if ($q -match 'RUNNING') {
    Write-Output '  驱动运行中 ✓'
} elseif ($q -match 'START_PENDING') {
    Fail '驱动卡在 START_PENDING（DriverEntry 未返回），需要重启'
    exit 1
} else {
    Fail '驱动未运行，请看 install-driver.ps1 的输出'
    exit 1
}

Step '2/4 串口是否仍可正常打开（最关键）'
$ports = [System.IO.Ports.SerialPort]::GetPortNames()
if ($ports.Count -eq 0) {
    Write-Output '  系统中没有串口，跳过此项'
} else {
    Write-Output "  发现串口: $($ports -join ', ')"
    $anyOk = $false
    foreach ($p in $ports) {
        try {
            $sp = New-Object System.IO.Ports.SerialPort($p, 9600)
            $sp.Open()
            $sp.Close()
            Write-Output "  $p 可打开 ✓"
            $anyOk = $true
        } catch {
            Write-Output "  $p 打不开: $($_.Exception.Message)"
        }
    }
    if (-not $anyOk) {
        Fail '所有串口都打不开 —— 驱动仍在破坏端口，需要停止驱动并反馈'
        Write-Output ''
        Write-Output '  停止驱动: sc stop UmSerialFilter'
        exit 1
    }
}

Step '3/4 驱动是否附加到串口'
$out = & $reader 3 2>&1 | Out-String
Write-Output $out.Trim()
if ($out -match '无法打开') {
    Fail '无法打开控制设备'
    exit 1
}
if ($out -match '附加到 0 个') {
    Fail '驱动没有附加到任何串口（端口名可能不在识别列表里）'
} elseif ($out -match '附加到 (\d+) 个') {
    Write-Output "  已附加 $($Matches[1]) 个串口 ✓"
}

Step '4/4 数据流验证'
Write-Output '  请现在用串口助手打开一个 COM 口并发送数据（10 秒内）…'
$out2 = & $reader 10 2>&1 | Out-String
Write-Output $out2.Trim()
if ($out2 -match 'PASS|记录 [1-9]') {
    Write-Output '  捕获到数据 ✓'
} else {
    Write-Output '  WARN: 没有捕获到数据'
    Write-Output '  （如果刚才没发送数据，这是正常的；重跑并确保有收发）'
}

Write-Output ''
Write-Output '=== 总结 ==='
if ($failed -eq 0) {
    Write-Output 'PASS: 驱动工作正常，且没有影响串口使用'
    exit 0
}
Write-Output "FAIL: $failed 项检查未通过"
exit 1
