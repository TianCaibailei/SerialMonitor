# 串口捕获全链路验收脚本
#
# 覆盖用户报告的场景：串口助手先打开端口，监视软件再注入 —— 也就是
#   「程序已经在读写串口之后，我们才进去」
# 这正是之前完全抓不到数据的顺序。
#
# 用法（普通权限即可，不需要管理员）：
#   powershell -ExecutionPolicy Bypass -File verify-fixed.ps1
#
# 为什么不用 --inject-comtest：
#   那个测试要求「注入先于打开端口」，而现在入口级挂钩把顺序问题消除了，
#   真正需要验证的是反过来的顺序。这里用 tests\order_loop*.exe 构造它：
#   程序先打开端口、先开始连续收发，然后在流中途注入。
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe = Join-Path $root 'target\release\universal_monitor.exe'
$hookLog = "$env:TEMP\um_hook_debug"

if (-not (Test-Path $exe)) { Write-Output "缺少 $exe，请先编译"; exit 1 }

function Get-Arch([string]$p) {
    $b = [System.IO.File]::ReadAllBytes((Resolve-Path $p))
    $pe = [BitConverter]::ToInt32($b, 0x3C)
    switch ([BitConverter]::ToUInt16($b, $pe + 4)) { 0x014C { 'x86' } 0x8664 { 'x64' } default { '?' } }
}

function Test-Port([string]$com) {
    try { $p = New-Object System.IO.Ports.SerialPort($com, 9600); $p.Open(); $p.Close(); $true } catch { $false }
}

function Invoke-OrderCase([string]$label, [string]$probeExe, [string]$com, [string]$peer) {
    Write-Output ''
    Write-Output "### $label"
    $log = "$env:TEMP\vf_$([guid]::NewGuid().ToString('N')).log"
    $result = "$env:TEMP\vf_$([guid]::NewGuid().ToString('N')).json"
    $mon = Start-Process $exe -PassThru -WindowStyle Hidden -ArgumentList @('--headless-watch', $com, '--result', $result)
    Start-Sleep -Seconds 3
    $probe = Start-Process $probeExe -PassThru -WindowStyle Hidden -ArgumentList @($com, $log, 'gpa')

    # Wait until the probe PROVES it holds the port: this is the state the user's
    # serial assistant is in when the monitor is pointed at it.
    $opened = $false
    for ($i = 0; $i -lt 50; $i++) {
        if ((Get-Content $log -ErrorAction SilentlyContinue) -match 'OPENED') { $opened = $true; break }
        Start-Sleep -Milliseconds 200
    }
    if (-not $opened) {
        Write-Output "  FAIL 探针未能打开 $com（端口可能被占用）"
        Get-CimInstance Win32_Process -Filter "ProcessId=$($probe.Id)" | ForEach-Object { Invoke-CimMethod -InputObject $_ -MethodName Terminate -ErrorAction SilentlyContinue | Out-Null }
        try { $mon | Stop-Process -Force } catch {}
        return $false
    }
    Write-Output "  探针 PID=$($probe.Id) 已占用 $com，现在注入（顺序与用户场景一致）"
    Start-Sleep -Seconds 3

    $inj = & $exe '--inject-test' $probe.Id 2>&1 | Out-String
    $injOk = $inj -match '注入成功'
    Write-Output "  注入: $(if ($injOk) { '成功' } else { '失败' })"
    if (-not $injOk) { Write-Output ($inj -split "`n" | Where-Object { $_ -match '失败' }) }

    # Drive the peer end so the probe's reads return and its loop keeps going.
    try {
        $q = New-Object System.IO.Ports.SerialPort($peer, 9600)
        $q.Open()
        for ($i = 0; $i -lt 16; $i++) { $q.Write("VF$i;"); Start-Sleep -Milliseconds 250; $null = $q.ReadExisting() }
        $q.Close()
    } catch { Write-Output "  对端 $peer 发送失败: $($_.Exception.Message)" }

    Start-Sleep -Seconds 3
    $mon | Wait-Process -Timeout 60 -ErrorAction SilentlyContinue

    $rows = 0; $tx = 0; $rx = 0
    if (Test-Path $result) {
        $j = Get-Content $result -Raw
        if ($j -match '"rows":(\d+)') { $rows = [int]$Matches[1] }
        if ($j -match '"tx":(\d+)') { $tx = [int]$Matches[1] }
        if ($j -match '"rx":(\d+)') { $rx = [int]$Matches[1] }
    }
    Write-Output "  会话结果: rows=$rows tx=$tx rx=$rx"

    $hookLogFile = "$env:TEMP\um_hook_$($probe.Id).log"
    if (Test-Path $hookLogFile) {
        $label2 = (Get-Content $hookLogFile | Select-String 'COM\d' | Select-Object -First 1)
        if ($label2) { Write-Output "  端口识别: $($label2.Line.Trim())" }
    }

    Get-CimInstance Win32_Process -Filter "ProcessId=$($probe.Id)" | ForEach-Object { Invoke-CimMethod -InputObject $_ -MethodName Terminate -ErrorAction SilentlyContinue | Out-Null }
    try { $mon | Stop-Process -Force } catch {}
    Remove-Item $log, $result -ErrorAction SilentlyContinue

    $ok = $injOk -and $rows -gt 0 -and $tx -gt 0
    Write-Output "  -> $(if ($ok) { 'PASS' } else { 'FAIL' })"
    return $ok
}

Write-Output '=== 0. 产物架构 ==='
foreach ($f in @('monitor_hook.dll', 'monitor_hook_x86.dll', 'universal_injector_x86.exe', 'universal_monitor.exe')) {
    $p = Join-Path $root "target\release\$f"
    if (Test-Path $p) { Write-Output ('  {0,-28} {1}' -f $f, (Get-Arch $p)) } else { Write-Output ('  {0,-28} 缺失' -f $f) }
}

Write-Output ''
Write-Output '=== 1. 端口占用检查 ==='
$free = @()
foreach ($c in @('COM1', 'COM2')) {
    $isFree = Test-Port $c
    Write-Output "  $c 空闲=$isFree"
    if ($isFree) { $free += $c }
}
if ($free.Count -lt 2) {
    Write-Output '  COM1/COM2 未全部空闲，无法做回环测试（请关闭占用它们的程序）'
    exit 1
}

Write-Output ''
Write-Output '=== 2. 驱动谎报修复验证（连续跑两次，第二次才是真相）==='
& $exe '--driver-test' 1 2>&1 | Select-String '附加到' | ForEach-Object { Write-Output "  $($_.Line.Trim())" }
& $exe '--driver-test' 1 2>&1 | Select-String '附加到' | ForEach-Object { Write-Output "  $($_.Line.Trim())" }

Set-Content -Path $hookLog -Value '1'
Remove-Item "$env:TEMP\um_hook_*.log" -ErrorAction SilentlyContinue

$r32 = Invoke-OrderCase '32 位目标：先开端口、后注入（用户报告的场景）' (Join-Path $root 'tests\order_loop32.exe') 'COM1' 'COM2'
$r64 = Invoke-OrderCase '64 位目标：先开端口、后注入' (Join-Path $root 'tests\order_loop64.exe') 'COM1' 'COM2'

Remove-Item $hookLog -ErrorAction SilentlyContinue

Write-Output ''
Write-Output '=== 总结 ==='
Write-Output "32 位（先开后注入）: $(if ($r32) { 'PASS' } else { 'FAIL' })"
Write-Output "64 位（先开后注入）: $(if ($r64) { 'PASS' } else { 'FAIL' })"
if ($r32 -and $r64) { Write-Output 'PASS: 注入后可以捕获已打开端口的读写'; exit 0 }
exit 1
