# One command to rebuild everything after a reboot.
#
# Run this after rebooting (the old driver must be unloaded first: it locks both
# umserialfilter.sys and universal_monitor.exe, so neither can be overwritten while the
# stale build is still loaded).
#
#   powershell -ExecutionPolicy Bypass -File rebuild-all.ps1
#
# Steps: clean old service -> build driver -> sign -> build GUI + hook -> install driver.
param(
    [switch]$SkipSign
)
$ErrorActionPreference = 'Continue'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$project = Split-Path -Parent $root
$app = Join-Path $project 'app'
$sys = Join-Path $root 'umserialfilter\umserialfilter.sys'
$signtool = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\signtool.exe'
$thumb = '89504FECC3504FB928B20D7034A82BF91F71423A'

function Step([string]$n) { Write-Output ''; Write-Output "=== $n ===" }

Step '0/6 环境检查'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Output "  管理员: $isAdmin"
if (-not $isAdmin) {
    Write-Output '  提示: 编译不需要管理员，但安装驱动需要。'
}

Step '1/6 清理旧驱动服务'
$q = & sc.exe query UmSerialFilter 2>&1 | Out-String
if ($q -match 'START_PENDING') {
    Write-Output '  驱动卡在 START_PENDING，必须重启电脑后才能继续。'
    exit 1
}
if ($q -match 'SERVICE_NAME') {
    & sc.exe stop UmSerialFilter 2>&1 | Out-Null
    Start-Sleep -Seconds 2
    $del = & sc.exe delete UmSerialFilter 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        Write-Output "  删除失败: $($del.Trim())"
        Write-Output '  若提示 1072，需要重启电脑。'
        exit 1
    }
    Write-Output '  旧服务已删除 ✓'
} else {
    Write-Output '  没有旧服务 ✓'
}

Step '2/6 结束残留进程'
foreach ($n in @('universal_monitor', 'umfilter_reader')) {
    Get-Process $n -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output "  结束 $($_.Name) (PID $($_.Id))"
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }
}
Start-Sleep -Seconds 1

Step '3/6 编译驱动'
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'build-driver.ps1') `
    -Source (Join-Path $root 'umserialfilter\umserialfilter.c') | Out-Host
if (-not (Test-Path $sys)) {
    Write-Output '  驱动编译失败'
    exit 1
}

Step '4/6 签名驱动'
if ($SkipSign) {
    Write-Output '  已跳过（-SkipSign）'
} else {
    if (-not (Test-Path $signtool)) {
        Write-Output "  找不到 signtool: $signtool"
        exit 1
    }
    & $signtool sign /s My /sha1 $thumb /fd SHA256 $sys 2>&1 | Select-String 'Successfully|error' | Out-Host
    if ($LASTEXITCODE -ne 0) {
        Write-Output '  签名失败：证书可能已被删除。重新创建见 安装与签名指南.md'
        exit 1
    }
    Write-Output '  签名完成 ✓'
}

Step '5/6 编译主程序'
Push-Location $app
# A stale universal_monitor.exe from the crashed run cannot be overwritten; if the
# process list is not clean, fall back to an alternate target directory.
& cargo build --release 2>&1 | Select-String '^error|Finished' | Select-Object -First 4 | Out-Host
$built = Test-Path (Join-Path $app 'target\release\universal_monitor.exe')
if (-not $built) {
    Write-Output '  目标目录被占用，改用独立 target 目录重试…'
    $env:CARGO_TARGET_DIR = Join-Path $project 'build_check'
    & cargo build --release 2>&1 | Select-String '^error|Finished' | Select-Object -First 4 | Out-Host
    Remove-Item Env:\CARGO_TARGET_DIR
    $alt = Join-Path $project 'build_check\release\universal_monitor.exe'
    if (Test-Path $alt) {
        Copy-Item $alt (Join-Path $app 'target\release\universal_monitor.exe') -Force -ErrorAction SilentlyContinue
        Write-Output '  已从备用目录取得可执行文件'
    }
}
Pop-Location

Step '6/6 编译 32 位组件'
Push-Location $app
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $app 'build-all.ps1') 2>&1 |
    Select-String 'PASS|x64|x86|字节' | Out-Host
Pop-Location

Write-Output ''
Write-Output '=== 完成 ==='
Write-Output '下一步（管理员）：'
Write-Output "  cd $root"
Write-Output '  powershell -ExecutionPolicy Bypass -File setup-driver.ps1'
Write-Output ''
Write-Output '安装后务必先跑验证（会先确认端口没被破坏，再验证捕获）：'
Write-Output '  powershell -ExecutionPolicy Bypass -File verify-driver.ps1'
