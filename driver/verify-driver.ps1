# Verify the driver is safe and working, in the right order.
#
# THE ORDER MATTERS. An early build broke serial ports while reporting success: it answered
# IRP_MJ_CREATE itself instead of forwarding it, so every COM port looked occupied even
# though nothing captured. Checking "did we capture data" first would have hidden that.
# This script therefore checks, in order:
#
#   1. the driver is loaded and running
#   2. serial ports can STILL be opened by a normal program   <- the non-negotiable one
#   3. the driver attached to them and accepted our session key
#   4. traffic actually flows through
#
# Every child process runs with a hard timeout: a driver that refuses IOCTLs used to make
# step 3 hang forever, which looked like a frozen script rather than a failure.
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

# Run a native process with a timeout, returning its combined output.
# Start-Process + WaitForExit(ms) is used instead of & because a hung child would otherwise
# block the pipeline with no way out.
function Invoke-WithTimeout {
    param(
        [string]$Exe,
        [string[]]$Arguments = @(),
        [int]$Seconds = 20
    )
    $tmp = Join-Path $env:TEMP ("verify_" + [guid]::NewGuid().ToString('N') + ".txt")
    try {
        $p = Start-Process -FilePath $Exe -ArgumentList $Arguments -NoNewWindow -PassThru `
            -RedirectStandardOutput $tmp -RedirectStandardError "$tmp.err"
        if (-not $p.WaitForExit($Seconds * 1000)) {
            Write-Output "  （超时 ${Seconds}s，强制结束进程 PID $($p.Id)）"
            try { $p.Kill() } catch {}
            Start-Sleep -Milliseconds 300
            $text = ''
            if (Test-Path $tmp) { $text = Get-Content $tmp -Raw -ErrorAction SilentlyContinue }
            return [pscustomobject]@{ Output = "$text"; TimedOut = $true; ExitCode = -1 }
        }
        $text = ''
        if (Test-Path $tmp) { $text = Get-Content $tmp -Raw -ErrorAction SilentlyContinue }
        return [pscustomobject]@{ Output = "$text"; TimedOut = $false; ExitCode = $p.ExitCode }
    } finally {
        Remove-Item $tmp, "$tmp.err" -ErrorAction SilentlyContinue
    }
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
    Fail '驱动未运行，请看 setup-driver.ps1 的输出'
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

Step '3/4 驱动是否附加到串口并完成认证'
if (-not (Test-Path $reader)) {
    Fail "找不到 reader: $reader"
} else {
    $r = Invoke-WithTimeout -Exe $reader -Arguments @('3') -Seconds 25
    if ($r.TimedOut) {
        Fail 'reader 超时未返回 —— 驱动拒绝了 IOCTL 且没有快速失败'
        Write-Output ''
        Write-Output '  最可能的原因：加载的是不含认证逻辑的旧驱动，而新版 reader 在等握手。'
        Write-Output '  检查已安装驱动的大小（当前版本应为约 21,504 字节）：'
        $sys = Join-Path $root 'umserialfilter\umserialfilter.sys'
        if (Test-Path $sys) {
            Write-Output ("    {0}: {1:N0} 字节" -f $sys, (Get-Item $sys).Length)
        }
        Write-Output '  修复：重新运行 rebuild-all.ps1（会重新编译并同步文件名），再 setup-driver.ps1'
    } else {
        Write-Output $r.Output.TrimEnd()
        if ($r.Output -match '认证失败|无法从 HKLM') {
            Fail '会话密钥握手失败'
        } elseif ($r.Output -match '附加到 0 个') {
            Fail '驱动没有附加到任何串口（端口名可能不在识别列表里）'
        } elseif ($r.Output -match '附加到 (\d+) 个') {
            Write-Output "  已附加 $($Matches[1]) 个串口 ✓"
        } elseif ($r.Output -match '已连接过滤驱动') {
            Write-Output '  已连接驱动'
        } else {
            Fail '无法打开控制设备'
        }
    }
}

Step '4/4 数据流验证'
if ($failed -eq 0) {
    Write-Output '  请现在用串口助手打开一个 COM 口并发送数据（10 秒内）…'
    $r2 = Invoke-WithTimeout -Exe $reader -Arguments @('10') -Seconds 30
    if ($r2.TimedOut) {
        Fail '数据流验证超时'
    } else {
        Write-Output $r2.Output.TrimEnd()
        if ($r2.Output -match 'PASS|记录 [1-9]') {
            Write-Output '  捕获到数据 ✓'
        } else {
            Write-Output '  WARN: 没有捕获到数据'
            Write-Output '  （如果刚才没发送数据，这是正常的；重跑并确保有收发）'
        }
    }
} else {
    Write-Output '  跳过（前面的检查未通过）'
}

Write-Output ''
Write-Output '=== 总结 ==='
if ($failed -eq 0) {
    Write-Output 'PASS: 驱动工作正常，且没有影响串口使用'
    exit 0
}
Write-Output "FAIL: $failed 项检查未通过"
exit 1
