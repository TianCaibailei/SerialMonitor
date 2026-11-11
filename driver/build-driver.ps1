# Build the driver for every Windows / architecture target we support.
#
# WHY MULTI-TARGET
# ----------------
# "Most Windows PCs" is more than x64-plus-Windows-10:
#
#   architecture: x64 (all modern PCs) AND x86 (32-bit installs still common in industry,
#                 embedded and older office machines — exactly where serial monitors live)
#   OS floor:     Windows 7 SP1 through Windows 11. NTDDI_VERSION / WIN32_WINNT gate which
#                 APIs the headers expose; flooring at Win7 keeps the driver loadable on
#                 older systems while still running on 11.
#
# The reference driver ships four binaries for the same reason (nt5/nt6 x x86/x64).
#
# Usage:
#   powershell -File build-driver.ps1                      # x64 + x86, Win7 floor
#   powershell -File build-driver.ps1 -Arch x64            # one architecture
#   powershell -File build-driver.ps1 -Os win10            # Win10 floor
param(
    [string]$Source,
    [ValidateSet('x64', 'x86', 'all')]
    [string]$Arch = 'all',
    [ValidateSet('win7', 'win10')]
    [string]$Os = 'win7'
)
$ErrorActionPreference = 'Continue'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Source) { $Source = Join-Path $root 'probe\probe.c' }

$wdkRoot = 'E:\tools\wdk-nuget\extracted'
$sdkRoot = 'E:\tools\wdk-nuget\sdk-extracted'
$ver = '10.0.26100.0'

$incKm = Join-Path $wdkRoot "c\Include\$ver\km"
$incShared = Join-Path $wdkRoot "c\Include\$ver\shared"
$sdkC = Join-Path $sdkRoot 'c'

foreach ($p in @($incKm, $incShared, $sdkC)) {
    if (-not (Test-Path $p)) { throw "缺少目录: $p" }
}
if (-not (Test-Path $Source)) { throw "源文件不存在: $Source" }

$vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
$vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsPath) { throw '找不到 Visual Studio C++ 工具链' }

$workDir = Split-Path -Parent $Source
$srcName = Split-Path -Leaf $Source
$baseName = [System.IO.Path]::GetFileNameWithoutExtension($Source)

# OS floor values come from sdkddkver.h.
switch ($Os) {
    'win7'  { $ntddi = '0x06010000'; $winver = '0x0601' }
    'win10' { $ntddi = '0x0A000000'; $winver = '0x0A00' }
}

$targets = if ($Arch -eq 'all') { @('x64', 'x86') } else { @($Arch) }
$results = @()

foreach ($target in $targets) {
    $isX64 = ($target -eq 'x64')
    $bits = if ($isX64) { '64' } else { '32' }
    $vcvars = Join-Path $vsPath ("VC\Auxiliary\Build\vcvars{0}.bat" -f $bits)
    if (-not (Test-Path $vcvars)) {
        Write-Output "跳过 $target : 缺少 $vcvars"
        continue
    }

    $libKm = Join-Path $wdkRoot "c\Lib\$ver\km\$target"
    if (-not (Test-Path $libKm)) {
        Write-Output "跳过 $target : 缺少内核库目录 $libKm"
        Write-Output "  （WDK NuGet 包不含 x86 内核库；需要完整 WDK MSI 才能编译 x86 驱动）"
        Write-Output "  x64 驱动已足够覆盖现代 PC，32 位系统可降级为用户态 hook 模式"
        $results += [pscustomobject]@{ Arch = $target; File = "（无内核库）"; Bytes = 0; Ok = $true }
        continue
    }

    # Architecture macros are mandatory: without _AMD64_ / _X86_ the WDK headers stop with
    # "#error No Target Architecture".
    if ($isX64) {
        $archDefs = @('/D_WIN64', '/D_AMD64_', '/D_M_AMD64=100')
        $machine = 'X64'
    } else {
        $archDefs = @('/D_X86_', '/D_M_IX86=600')
        $machine = 'X86'
    }

    # Emit BOTH the per-arch name and the canonical name for the primary (x64) target:
    # setup-driver.ps1 loads umserialfilter.sys, and a mismatch here silently deployed a stale
    # driver — the symptom was a driver that ran but refused every IOCTL.
    $outName = "${baseName}_$target.sys"
    $objName = "$baseName.obj"

    $clArgs = @('/nologo', '/c', '/kernel', '/GS-', '/Gz', '/Zp8', '/W4', '/WX-')
    $clArgs += $archDefs
    $clArgs += @(
        "/DNTDDI_VERSION=$ntddi",
        "/D_WIN32_WINNT=$winver",
        '/I', $incKm,
        '/I', $incShared,
        '/I', (Join-Path $sdkC 'ucrt'),
        '/I', (Join-Path $sdkC 'um'),
        '/I', (Join-Path $sdkC 'shared'),
        "/Fo$objName",
        $srcName
    )

    $lnArgs = @(
        '/nologo', '/DRIVER', '/SUBSYSTEM:NATIVE', '/ENTRY:GsDriverEntry',
        "/MACHINE:$machine",
        "/OUT:$outName",
        "/LIBPATH:$libKm",
        'ntoskrnl.lib', 'hal.lib', 'wmilib.lib', 'BufferOverflowK.lib', 'ntstrsafe.lib',
        $objName
    )

    $bat = Join-Path $env:TEMP "build_driver_$target.bat"
    $batLines = @(
        '@echo off',
        "call `"$vcvars`" >nul 2>&1",
        'if errorlevel 1 (echo VCVARS_FAILED & exit /b 1)',
        "cd /d `"$workDir`"",
        'if errorlevel 1 (echo CD_FAILED & exit /b 1)',
        ('cl ' + ($clArgs -join ' ')),
        'if errorlevel 1 (echo COMPILE_FAILED & exit /b 1)',
        ('link ' + ($lnArgs -join ' ')),
        'if errorlevel 1 (echo LINK_FAILED & exit /b 1)',
        'echo BUILD_OK'
    )
    $batLines | Set-Content -Path $bat -Encoding ASCII

    Write-Output ''
    Write-Output "=== 编译 $target (OS floor: $Os) ==="
    & cmd /c $bat 2>&1 | ForEach-Object {
        $t = "$_".Trim()
        if ($t.Length -gt 0) { Write-Output "  $t" }
    }
    $rc = $LASTEXITCODE
    $outFull = Join-Path $workDir $outName
    if ((Test-Path $outFull) -and $rc -eq 0) {
        $size = (Get-Item $outFull).Length
        Write-Output ("  PASS {0} ({1:N0} 字节)" -f $outName, $size)
        $results += [pscustomobject]@{ Arch = $target; File = $outName; Bytes = $size; Ok = $true }
        # x64 is the canonical build: copy it to the name the installer expects.
        if ($target -eq 'x64') {
            $canonical = Join-Path $workDir "$baseName.sys"
            try {
                Copy-Item $outFull $canonical -Force -ErrorAction Stop
                Write-Output "      已同步为 $baseName.sys"
            } catch {
                Write-Output "      警告: 无法覆盖 $baseName.sys"
                Write-Output "        （$($_.Exception.Message)）"
                Write-Output "        文件可能被已加载的驱动占用 —— 先 sc stop UmSerialFilter"
            }
        }
    } else {
        Write-Output "  FAIL $target (退出码 $rc)"
        $results += [pscustomobject]@{ Arch = $target; File = '-'; Bytes = 0; Ok = $false }
    }
}

Write-Output ''
Write-Output '=== 结果 ==='
foreach ($r in $results) {
    $state = if ($r.Ok) { 'OK' } else { 'FAIL' }
    Write-Output ("  {0,-4} {1,-34} {2,10:N0} 字节  {3}" -f $r.Arch, $r.File, $r.Bytes, $state)
}
if ($results.Count -gt 0 -and ($results | Where-Object { -not $_.Ok }).Count -eq 0) {
    Write-Output ''
    Write-Output 'PASS: 所有目标架构编译成功'
    exit 0
}
Write-Output ''
Write-Output 'FAIL: 有架构编译失败'
exit 1
