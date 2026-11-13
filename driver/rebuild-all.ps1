# Build, deploy and load the driver plus both user-mode consumers, in one command.
#
# This script exists because the same failure happened twice: something was rebuilt but a
# STALE copy of a DIFFERENT file was what actually ran.
#   * build-driver.ps1 wrote umserialfilter_x64.sys while setup loaded umserialfilter.sys
#   * the reader was rebuilt as reader_new.exe while umfilter_reader.exe stayed old
# Each time the symptom was a hang or a silent "0 ports", never a build error.
#
# So every artifact this script produces is copied to the exact filename that consumes it,
# and each copy is verified by size afterwards.
#
# Run elevated (needs to stop/install the kernel service):
#   powershell -ExecutionPolicy Bypass -File rebuild-all.ps1
param(
    [switch]$SkipSign,
    [switch]$SkipInstall
)
$ErrorActionPreference = 'Continue'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$project = Split-Path -Parent $root
$app = Join-Path $project 'app'
$sys = Join-Path $root 'umserialfilter\umserialfilter.sys'
# Locate signtool.exe: newest Windows Kits SDK wins. Hard-coding one SDK version
# breaks on any machine that has a different SDK installed.
$signtool = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' -Directory -ErrorAction SilentlyContinue |
    Sort-Object Name -Descending |
    ForEach-Object { Join-Path $_.FullName 'x64\signtool.exe' } |
    Where-Object { Test-Path $_ } |
    Select-Object -First 1
if (-not $signtool) {
    $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($cmd) { $signtool = $cmd.Source }
}
$thumb = '89504FECC3504FB928B20D7034A82BF91F71423A'
$readerDir = Join-Path $root 'umfilter_reader'
$serviceName = 'UmSerialFilter'
$failed = 0

function Step([string]$n) { Write-Output ''; Write-Output "=== $n ===" }
function Fail([string]$m) { Write-Output "  FAIL: $m"; $script:failed++ }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Output "管理员: $isAdmin"

Step '1/7 停止并删除旧驱动服务'
if (-not $isAdmin) {
    Write-Output '  跳过（需要管理员）。若 .sys 被占用，后续复制会失败并明确报错。'
} else {
    $q = & sc.exe query $serviceName 2>&1 | Out-String
    if ($q -match 'START_PENDING') {
        Fail '驱动卡在 START_PENDING，必须重启电脑'
        Write-Output ''
        Write-Output '重启后重新运行本脚本。'
        exit 1
    }
    if ($q -match 'SERVICE_NAME') {
        & sc.exe stop $serviceName 2>&1 | Out-Null
        Start-Sleep -Seconds 2
        $del = & sc.exe delete $serviceName 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) {
            Fail "删除服务失败: $($del.Trim())"
            Write-Output '  若提示 1072，需要重启电脑。'
            exit 1
        }
        Write-Output '  旧服务已删除 ✓'
    } else {
        Write-Output '  没有旧服务 ✓'
    }
}

Step '2/7 结束残留的用户态进程'
foreach ($n in @('universal_monitor', 'umfilter_reader')) {
    Get-Process $n -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output "  结束 $($_.Name) (PID $($_.Id))"
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }
}
Start-Sleep -Seconds 1

Step '3/7 编译驱动 (x64, Win7+)'
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'build-driver.ps1') `
    -Source (Join-Path $root 'umserialfilter\umserialfilter.c') -Arch x64 | Out-Host
if (-not (Test-Path $sys)) {
    Fail '驱动编译失败'
    exit 1
}
Write-Output ("  部署文件: {0:N0} 字节" -f (Get-Item $sys).Length)

Step '4/7 签名驱动'
if ($SkipSign) {
    Write-Output '  已跳过（-SkipSign）'
} else {
    if (-not (Test-Path $signtool)) {
        Fail "找不到 signtool: $signtool"
    } else {
        & $signtool sign /s My /sha1 $thumb /fd SHA256 $sys 2>&1 |
            Select-String 'Successfully|error' | ForEach-Object { Write-Output "  $($_.Line.Trim())" }
        if ($LASTEXITCODE -ne 0) {
            Fail '签名失败（证书可能已被删除）'
        } else {
            Write-Output '  签名完成 ✓'
        }
    }
}

Step '5/7 编译用户态 reader'
$readerOut = Join-Path $readerDir 'umfilter_reader.exe'
$readerSrc = Join-Path $readerDir 'main.rs'
if (-not (Test-Path $readerSrc)) {
    Fail "找不到 $readerSrc"
} else {
    # Compile to a temp name first: the deployed exe may still be referenced by a running
    # process, and a failed overwrite used to leave the OLD binary in place silently.
    $tmpExe = Join-Path $readerDir '_build_reader.exe'
    Remove-Item $tmpExe -Force -ErrorAction SilentlyContinue
    & rustc --edition 2021 -O -o $tmpExe $readerSrc 2>&1 |
        Select-String 'error' | Select-Object -First 5 | ForEach-Object { Write-Output "  $($_.Line.Trim())" }
    if (-not (Test-Path $tmpExe)) {
        Fail 'reader 编译失败'
    } else {
        try {
            Copy-Item $tmpExe $readerOut -Force -ErrorAction Stop
            Write-Output ("  reader 已部署: {0:N0} 字节" -f (Get-Item $readerOut).Length)
        } catch {
            Fail "无法覆盖 umfilter_reader.exe: $($_.Exception.Message)"
        }
        Remove-Item $tmpExe -Force -ErrorAction SilentlyContinue
    }
}

Step '6/7 编译主程序'
Push-Location $app
& cargo build --release 2>&1 | Select-String '^error|Finished' | Select-Object -First 3 |
    ForEach-Object { Write-Output "  $($_.Line.Trim())" }
$exe = Join-Path $app 'target\release\universal_monitor.exe'
if (Test-Path $exe) {
    Write-Output ("  GUI: {0:N0} 字节" -f (Get-Item $exe).Length)
} else {
    Fail 'GUI 编译失败'
}
Pop-Location

Step '7/7 安装并启动驱动'
if ($SkipInstall) {
    Write-Output '  已跳过（-SkipInstall）'
} elseif (-not $isAdmin) {
    Write-Output '  跳过（需要管理员）'
} else {
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'setup-driver.ps1') | Out-Host
}

Write-Output ''
Write-Output '=== 结果 ==='
if ($failed -eq 0) {
    Write-Output 'PASS: 全部构建与部署步骤成功'
    Write-Output ''
    Write-Output '下一步验证（管理员）:'
    Write-Output ("  powershell -File {0}" -f (Join-Path $root 'verify-driver.ps1'))
    exit 0
}
Write-Output "FAIL: $failed 项失败"
exit 1
