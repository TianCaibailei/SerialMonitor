# Build a kernel driver with the WDK obtained from NuGet.
#
# WHY NUGET: the WDK bootstrapper (wdksetup.exe) stalled repeatedly on this machine —
# its downloader gives up on a flaky link and then asks "prompt for source of package".
# The same content is published as NuGet packages, which download at ~20 MB/s here, so
# this script drives cl.exe/link.exe directly instead of installing the WDK MSI.
#
# Requirements: Visual Studio 2022 with the C++ workload.
#
# Usage: powershell -File build-driver.ps1 [-Source probe\probe.c] [-Out probe\probe.sys]
param(
    [string]$Source,
    [string]$Out
)
$ErrorActionPreference = 'Continue'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Source) { $Source = Join-Path $root 'probe\probe.c' }
if (-not $Out) { $Out = [System.IO.Path]::ChangeExtension($Source, '.sys') }

$wdkRoot = 'E:\tools\wdk-nuget\extracted'
$sdkRoot = 'E:\tools\wdk-nuget\sdk-extracted'
$ver = '10.0.26100.0'

$incKm     = Join-Path $wdkRoot "c\Include\$ver\km"
$incShared = Join-Path $wdkRoot "c\Include\$ver\shared"
$libKm     = Join-Path $wdkRoot "c\Lib\$ver\km\x64"
$sdkC      = Join-Path $sdkRoot 'c'

foreach ($p in @($incKm, $incShared, $libKm, $sdkC)) {
    if (-not (Test-Path $p)) { throw "缺少目录: $p" }
}
if (-not (Test-Path $Source)) { throw "源文件不存在: $Source" }

$vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
$vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsPath) { throw '找不到 Visual Studio C++ 工具链' }
$vcvars = Join-Path $vsPath 'VC\Auxiliary\Build\vcvars64.bat'

# Work in the source directory so cl/link can use plain relative names: prefixing
# /Fo and /OUT with absolute paths from a batch file proved fragile.
$workDir = Split-Path -Parent $Source
$srcName = Split-Path -Leaf $Source

$cl = @(
    '/nologo', '/c', '/kernel', '/GS-', '/Gz', '/Zp8', '/W4', '/WX-',
    '/D_WIN64', '/D_AMD64_', '/D_M_AMD64=100',
    '/DNTDDI_VERSION=0x0A00000C', '/D_WIN32_WINNT=0x0A00',
    '/I', $incKm,
    '/I', $incShared,
    '/I', (Join-Path $sdkC 'ucrt'),
    '/I', (Join-Path $sdkC 'um'),
    '/I', (Join-Path $sdkC 'shared'),
    $srcName
) -join ' '

$objName = [System.IO.Path]::ChangeExtension($srcName, '.obj')
$outName = Split-Path -Leaf $Out
$ln = @(
    '/nologo', '/DRIVER', '/SUBSYSTEM:NATIVE', '/ENTRY:GsDriverEntry', '/MACHINE:X64',
    "/OUT:$outName",
    "/LIBPATH:$libKm",
    'ntoskrnl.lib', 'hal.lib', 'wmilib.lib', 'BufferOverflowK.lib', 'ntstrsafe.lib',
    $objName
) -join ' '

$bat = Join-Path $env:TEMP 'build_driver.bat'
@"
@echo off
call "$vcvars" >nul 2>&1
if errorlevel 1 (echo VCVARS_FAILED & exit /b 1)
cd /d "$workDir"
if errorlevel 1 (echo CD_FAILED & exit /b 1)
cl $cl
if errorlevel 1 (echo COMPILE_FAILED & exit /b 1)
link $ln
if errorlevel 1 (echo LINK_FAILED & exit /b 1)
echo BUILD_OK
"@ | Set-Content -Path $bat -Encoding ASCII

Write-Output "=== 编译 $srcName ==="
& cmd /c $bat
$rc = $LASTEXITCODE
Write-Output ''
$outFull = Join-Path $workDir $outName
if ((Test-Path $outFull) -and $rc -eq 0) {
    Write-Output ("PASS: 驱动编译成功 {0} ({1:N0} 字节)" -f $outFull, (Get-Item $outFull).Length)
    exit 0
}
Write-Output "FAIL: 退出码 $rc"
exit 1
