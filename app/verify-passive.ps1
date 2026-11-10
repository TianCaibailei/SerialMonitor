# Passive-monitor proof: a program owns COM6 exclusively; the monitor must observe
# its traffic WITHOUT the monitor opening the port, and a third program must still
# be refused by the OS (proving the port is owned by the app, not by us).
#
# Run as: powershell -File verify-passive.ps1
$ErrorActionPreference = 'Stop'

Write-Output "=== 1. 目标程序独占打开 COM6 ==="
$owner = New-Object System.IO.Ports.SerialPort('COM6', 9600)
$owner.Open()
Write-Output "COM6 已被目标程序打开（独占）"

Write-Output ""
Write-Output "=== 2. 第三方程序尝试打开 COM6（应失败，证明确实被独占）==="
try {
    $thief = New-Object System.IO.Ports.SerialPort('COM6', 9600)
    $thief.Open()
    Write-Output "结果: 打开成功（端口未被独占）"
    $thief.Close()
} catch {
    Write-Output "结果: 打开被拒绝 -> $($_.Exception.Message)"
}

Write-Output ""
Write-Output "=== 3. 目标程序正常通信（真值 HELLO6789）==="
$peer = New-Object System.IO.Ports.SerialPort('COM7', 9600)
$peer.Open()
$peer.Write('HELLO6789')
Start-Sleep -Milliseconds 500
$received = $owner.ReadExisting()
Write-Output "目标程序收到: [$received]"

$owner.Write('REPLY123')
Start-Sleep -Milliseconds 500
$back = $peer.ReadExisting()
Write-Output "对端收到: [$back]"

$owner.Close()
$peer.Close()
Write-Output ""
Write-Output "测试完成"
