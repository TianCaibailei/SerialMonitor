# Build ONLY the GUI (no driver, no signing, no service changes).
#
# Use this when the kernel driver is already installed and working and only the UI changed.
# It never touches the .sys file, so it works while the driver is loaded — the driver holds
# its own image and cannot be overwritten, which is why rebuild-all.ps1 needs an elevated
# stop first.
#
#   powershell -ExecutionPolicy Bypass -File build-gui.ps1
#
# The result replaces app\target\release\universal_monitor.exe.
param(
    [switch]$Run
)
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$app = Join-Path $root 'app'
$out = Join-Path $app 'target\release\universal_monitor.exe'

Write-Output "=== 编译 GUI ==="
Push-Location $app
try {
    & cargo build --release
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build 失败 (退出码 $LASTEXITCODE)"
    }
} finally {
    Pop-Location
}

if (-not (Test-Path $out)) {
    throw "找不到产物: $out"
}
$item = Get-Item $out
Write-Output ''
Write-Output ('PASS: {0:N0} 字节  ({1})' -f $item.Length, $item.LastWriteTime)
Write-Output "      $out"

if ($Run) {
    Write-Output ''
    Write-Output '=== 启动 GUI ==='
    Start-Process -FilePath $out
}
