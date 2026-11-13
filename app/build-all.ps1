# Build and deploy the two hook DLLs and the 32-bit injector correctly.
#
# The trap this script exists for: `cargo build --release` builds the *host* (x64)
# binary named universal_injector_x86.exe and overwrites the 32-bit one in
# target/release. A 64-bit "x86 injector" then resolves a 64-bit LoadLibraryW and every
# 32-bit injection fails with "LoadLibraryW 返回 NULL" — which looks like a bug in the
# injector rather than a mis-deployed file.
#
# Run: powershell -File build-all.ps1
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

Write-Output '=== 1. 构建 64 位主程序与 hook ==='
& cargo build --release 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) { throw "64 位构建失败" }

Write-Output '=== 2. 构建 32 位 hook DLL ==='
& cargo build --release -p monitor_hook --target i686-pc-windows-msvc 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) { throw "32 位 hook 构建失败" }

Write-Output '=== 3. 构建 32 位注入器 ==='
# The injector lives in its own crate (so the host build cannot overwrite it), which
# means it must be selected with -p; `--bin` would not resolve inside the root package.
& cargo build --release -p universal_injector_x86 --target i686-pc-windows-msvc 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) { throw "32 位注入器构建失败" }

Write-Output '=== 4. 部署正确的架构文件 ==='
$rel = Join-Path $root 'target\release'
Copy-Item (Join-Path $root 'target\i686-pc-windows-msvc\release\monitor_hook.dll') `
    (Join-Path $rel 'monitor_hook_x86.dll') -Force
Copy-Item (Join-Path $root 'target\i686-pc-windows-msvc\release\universal_injector_x86.exe') `
    (Join-Path $rel 'universal_injector_x86.exe') -Force

# Verify the deployed files really are the intended architectures.
function Get-Arch([string]$path) {
    $b = [System.IO.File]::ReadAllBytes($path)
    $pe = [BitConverter]::ToInt32($b, 0x3C)
    $machine = [BitConverter]::ToUInt16($b, $pe + 4)
    switch ($machine) {
        0x014C { 'x86' }
        0x8664 { 'x64' }
        default { ('0x' + $machine.ToString('X4')) }
    }
}
Write-Output ''
Write-Output '=== 部署结果 ==='
foreach ($f in @('monitor_hook.dll', 'monitor_hook_x86.dll', 'universal_injector_x86.exe', 'universal_monitor.exe')) {
    $p = Join-Path $rel $f
    if (Test-Path $p) {
        '{0,-32} {1,-6} {2,8:N0} 字节' -f $f, (Get-Arch $p), (Get-Item $p).Length
    } else {
        '{0,-32} 缺失' -f $f
    }
}

$hookArch = Get-Arch (Join-Path $rel 'monitor_hook_x86.dll')
$injArch = Get-Arch (Join-Path $rel 'universal_injector_x86.exe')
if ($hookArch -ne 'x86' -or $injArch -ne 'x86') {
    Write-Output ''
    Write-Output "错误: 32 位文件架构不对 (hook=$hookArch, injector=$injArch)"
    exit 1
}
Write-Output ''
Write-Output 'PASS: 32 位 hook 与注入器均为 x86'
