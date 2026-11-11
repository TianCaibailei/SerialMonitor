# Emergency: stop/remove the UmSerialFilter driver so serial ports work again.
#
# WHY THIS EXISTS
# ---------------
# The first driver build answered IRP_MJ_CREATE for serial-port devices itself instead of
# forwarding it to the real serial driver. With that driver loaded, every COM port looks
# occupied and every serial application hangs waiting for data that never arrives.
#
# Until the fixed build is installed, this script gets the machine back to normal.
#
# Run elevated:  powershell -ExecutionPolicy Bypass -File fix-ports.ps1
$ErrorActionPreference = 'Continue'

$serviceName = 'UmSerialFilter'

function Test-Admin {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Output '需要管理员权限。请右键 PowerShell → 以管理员身份运行，然后重新执行。'
    exit 1
}

Write-Output '=== 1. 当前驱动状态 ==='
$q = & sc.exe query $serviceName 2>&1 | Out-String
Write-Output $q

if ($q -notmatch 'SERVICE_NAME') {
    Write-Output '服务不存在，串口应当是正常的。'
    Write-Output ''
    Write-Output '如果串口仍被占用，请重启电脑。'
    exit 0
}

Write-Output '=== 2. 结束卡住的用户态进程 ==='
foreach ($name in @('umfilter_reader', 'universal_monitor')) {
    Get-Process $name -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output "  结束 $($_.Name) (PID $($_.Id))"
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }
}
Start-Sleep -Seconds 1

Write-Output '=== 3. 停止驱动 ==='
if ($q -match 'START_PENDING') {
    Write-Output '  驱动卡在 START_PENDING，无法停止 —— 需要重启电脑。'
    Write-Output ''
    Write-Output '  重启后请直接运行: setup-driver.ps1'
    exit 1
}

$out = & sc.exe stop $serviceName 2>&1 | Out-String
Write-Output $out.Trim()
Start-Sleep -Seconds 2

$q2 = & sc.exe query $serviceName 2>&1 | Out-String
Write-Output '=== 4. 停止后状态 ==='
Write-Output $q2

Write-Output '=== 5. 验证串口 ==='
$found = $false
foreach ($port in [System.IO.Ports.SerialPort]::GetPortNames()) {
    $found = $true
    try {
        $p = New-Object System.IO.Ports.SerialPort($port, 9600)
        $p.Open()
        $p.Close()
        Write-Output "  $port 可打开 ✓"
    } catch {
        Write-Output "  $port 打不开: $($_.Exception.Message)"
    }
}
if (-not $found) {
    Write-Output '  系统中没有找到串口'
}

Write-Output ''
if ($q2 -match 'STOPPED') {
    Write-Output '驱动已停止，串口应已恢复。'
    Write-Output ''
    Write-Output '下一步: 安装修复后的驱动'
    Write-Output '  1. sc delete UmSerialFilter'
    Write-Output '  2. powershell -File build-driver.ps1 -Source umserialfilter\umserialfilter.c'
    Write-Output '  3. 签名（见 驱动启动失败诊断.md）'
    Write-Output '  4. powershell -File setup-driver.ps1'
}
