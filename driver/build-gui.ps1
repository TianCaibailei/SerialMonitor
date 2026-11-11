# Build ONLY the GUI (plus the 32-bit injector helper, correctly cross-built).
#
# Use this when the kernel driver is already installed and working and only user-mode code
# changed. It never touches the .sys file, so it works while the driver is loaded — the
# driver holds its own image and cannot be overwritten, which is why rebuild-all.ps1 needs
# an elevated stop first.
#
#   powershell -ExecutionPolicy Bypass -File build-gui.ps1
#   powershell -ExecutionPolicy Bypass -File build-gui.ps1 -Run
#
# What it builds:
#   universal_monitor.exe        host architecture (x64)
#   universal_injector_x86.exe   ALWAYS i686, from its own crate
#
# That second line matters. When the injector lived in app/src/bin/, `cargo build --release`
# built it for the host and overwrote the deployed 32-bit binary; every 32-bit injection
# then failed with a 64-bit LoadLibraryW address. Building it from its own crate with an
# explicit --target makes that impossible.
param(
    [switch]$Run
)
$ErrorActionPreference = 'Stop'

# This script lives in driver\; the Rust app is a sibling directory.
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$project = Split-Path -Parent $root
$app = Join-Path $project 'app'
$rel = Join-Path $app 'target\release'
$gui = Join-Path $rel 'universal_monitor.exe'
$inj = Join-Path $rel 'universal_injector_x86.exe'

function Get-Arch([string]$path) {
    $b = [System.IO.File]::ReadAllBytes($path)
    $pe = [BitConverter]::ToInt32($b, 0x3C)
    switch ([BitConverter]::ToUInt16($b, $pe + 4)) {
        0x014C { 'x86' }
        0x8664 { 'x64' }
        default { '?' }
    }
}

Write-Output '=== 编译 GUI ==='
Push-Location $app
try {
    & cargo build --release
    if ($LASTEXITCODE -ne 0) { throw "cargo build 失败 (退出码 $LASTEXITCODE)" }

    Write-Output ''
    Write-Output '=== 编译 32 位注入器 (i686) ==='
    & cargo build --release --target i686-pc-windows-msvc -p universal_injector_x86
    if ($LASTEXITCODE -ne 0) { throw "注入器编译失败 (退出码 $LASTEXITCODE)" }
} finally {
    Pop-Location
}

# Deploy the injector: the cross-built artifact lives under the target matrix, and the
# deployed copy must stay x86 or 32-bit injection breaks silently.
$injBuilt = Join-Path $app 'target\i686-pc-windows-msvc\release\universal_injector_x86.exe'
if (Test-Path $injBuilt) {
    Copy-Item $injBuilt $inj -Force
    if ((Get-Arch $inj) -ne 'x86') {
        throw "部署后架构不对: $inj 是 $(Get-Arch $inj)，需要 x86"
    }
} else {
    Write-Output "  警告: 找不到 $injBuilt"
}

Write-Output ''
Write-Output '=== 产物 ==='
foreach ($f in @($gui, $inj)) {
    if (Test-Path $f) {
        Write-Output ('  {0,-30} {1,-4} {2,10:N0} 字节' -f (Split-Path $f -Leaf), (Get-Arch $f), (Get-Item $f).Length)
    } else {
        Write-Output ('  {0,-30} 缺失' -f (Split-Path $f -Leaf))
    }
}
Write-Output ''
Write-Output 'PASS: 编译完成'

if ($Run) {
    Write-Output ''
    Write-Output '=== 启动 GUI ==='
    Start-Process -FilePath $gui
}
