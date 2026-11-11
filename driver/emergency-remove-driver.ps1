# Emergency: make the machine safe after a driver bugcheck.
#
# Run elevated:  powershell -ExecutionPolicy Bypass -File emergency-remove-driver.ps1
#
# This removes every trace of UmSerialFilter so the machine cannot bugcheck in it again.
# It does NOT reinstall anything.
$ErrorActionPreference = 'Continue'

$serviceName = 'UmSerialFilter'
$sysName = 'umserialfilter.sys'

function Test-Admin {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Output '需要管理员权限。请右键 PowerShell → 以管理员身份运行。'
    exit 1
}

Write-Output '=== 1. 当前驱动状态 ==='
$q = & sc.exe query $serviceName 2>&1 | Out-String
Write-Output $q.Trim()

Write-Output ''
Write-Output '=== 2. 结束卡住的用户态进程 ==='
foreach ($n in @('universal_monitor', 'umfilter_reader')) {
    Get-Process $n -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output "  结束 $($_.Name) (PID $($_.Id))"
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }
}
Start-Sleep -Seconds 1

Write-Output ''
Write-Output '=== 3. 停止并删除服务 ==='
if ($q -match 'SERVICE_NAME') {
    if ($q -match 'START_PENDING') {
        Write-Output '  服务卡在 START_PENDING —— 只能重启，重启后本脚本会自动完成清理'
    } else {
        & sc.exe stop $serviceName 2>&1 | ForEach-Object { Write-Output "  $($_.Trim())" }
        Start-Sleep -Seconds 2
        & sc.exe delete $serviceName 2>&1 | ForEach-Object { Write-Output "  $($_.Trim())" }
    }
} else {
    Write-Output '  服务不存在 ✓'
}

Write-Output ''
Write-Output '=== 4. 确认驱动服务已完全移除 ==='
$still = & sc.exe query $serviceName 2>&1 | Out-String
if ($still -match 'SERVICE_NAME') {
    Write-Output '  WARNING: 服务仍存在，重启后再运行一次本脚本'
} else {
    Write-Output '  服务已移除 ✓'
}

Write-Output ''
Write-Output '=== 5. 确认没有加载中的驱动模块 ==='
$drv = Get-CimInstance Win32_SystemDriver -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
if ($drv) {
    Write-Output "  仍在注册表中: State=$($drv.State)"
} else {
    Write-Output '  注册表中已无此驱动 ✓'
}

Write-Output ''
Write-Output '=== 6. 串口可用性检查 ==='
$ports = [System.IO.Ports.SerialPort]::GetPortNames()
if ($ports.Count -eq 0) {
    Write-Output '  未发现串口'
} else {
    foreach ($p in $ports) {
        try {
            $sp = New-Object System.IO.Ports.SerialPort($p, 9600)
            $sp.Open()
            $sp.Close()
            Write-Output "  $p 可打开 ✓"
        } catch {
            Write-Output "  $p 打不开: $($_.Exception.Message)"
        }
    }
}

Write-Output ''
Write-Output '=== 7. 建议 ==='
Write-Output '  驱动已从系统中移除。若要继续调试，请先阅读 driver/崩溃分析与安全加固.md。'
Write-Output '  在驱动修好之前，不要再安装它。'
