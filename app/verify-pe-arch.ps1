# verify-pe-arch.ps1 - check the PE machine type of build outputs.
#
# WHY: the 32-bit injector was once silently overwritten by a 64-bit build. A plain
# `cargo build` compiles the same file name for the HOST architecture, and the failure
# only shows up at runtime as "LoadLibraryW=0x7ffe..." (a 64-bit address inside a 32-bit
# target), which is very hard to diagnose. Reading the PE header catches it immediately.
#
# USAGE (from anywhere):
#   powershell -File app\verify-pe-arch.ps1
#   powershell -File app\verify-pe-arch.ps1 -AppDir app
#
# EXIT: 0 when every expected binary matches, 1 otherwise.

param(
    [string]$AppDir
)

$ErrorActionPreference = 'Stop'

if (-not $AppDir) {
    $AppDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}
$AppDir = (Resolve-Path $AppDir).Path

$MACHINE_X64  = 0x8664
$MACHINE_I386 = 0x014C

function Get-PeMachine([string]$Path) {
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $reader = New-Object System.IO.BinaryReader($stream)
        # e_lfanew at DOS header offset 0x3C
        $stream.Position = 0x3C
        $peOffset = $reader.ReadInt32()
        if ($peOffset -le 0 -or $peOffset -ge ($stream.Length - 4)) {
            throw "invalid PE offset $peOffset"
        }
        $stream.Position = $peOffset
        $signature = $reader.ReadUInt32()
        if ($signature -ne 0x00004550) {
            throw "not a PE file"
        }
        # COFF header follows the signature; Machine is its first field
        return [int]$reader.ReadUInt16()
    } finally {
        $stream.Dispose()
    }
}

$expectations = @(
    @{ Path = 'target\release\monitor_hook.dll';                              Machine = $MACHINE_X64;  Note = 'x64 hook DLL';          Optional = $false },
    @{ Path = 'target\release\universal_monitor.exe';                          Machine = $MACHINE_X64;  Note = 'x64 main exe';          Optional = $false },
    @{ Path = 'target\release\universal_injector_x86.exe';                     Machine = $MACHINE_I386; Note = 'x86 injector (opt)';    Optional = $true  },
    @{ Path = 'target\i686-pc-windows-msvc\release\monitor_hook.dll';          Machine = $MACHINE_I386; Note = 'x86 hook DLL';          Optional = $false },
    @{ Path = 'target\i686-pc-windows-msvc\release\universal_injector_x86.exe';Machine = $MACHINE_I386; Note = 'x86 injector';         Optional = $false }
)

$failures = 0
$report = @()
Write-Output "Verifying: $AppDir"
Write-Output "  OS: $([System.Environment]::OSVersion.VersionString)"
Write-Output "  PS: $($PSVersionTable.PSVersion)"
Write-Output "  CWD: $(Get-Location)"
Write-Output ''

# Diagnostics: when a file is missing, show what IS under target/ so a CI-only path
# mismatch is diagnosable from the log alone (the runner has no interactive access).
$releaseDir = Join-Path $AppDir 'target\release'
if (Test-Path $releaseDir) {
    $found = Get-ChildItem $releaseDir -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in '.exe', '.dll' } |
        Select-Object -ExpandProperty Name
    Write-Output ("  target\release contains: " + ($(if ($found) { $found -join ', ' } else { '(no exe/dll)' })))
} else {
    Write-Output '  target\release does NOT exist'
}
Write-Output ''

foreach ($e in $expectations) {
    $full = Join-Path $AppDir $e.Path
    Write-Output ("  probing {0}" -f $full)
    if (-not (Test-Path $full)) {
        if ($e.Optional) {
            Write-Output ("  SKIP  {0,-58} (not built)" -f $e.Path)
            continue
        }
        Write-Output ("  FAIL  {0,-58} missing" -f $e.Path)
        $failures++
        continue
    }
    try {
        $machine = Get-PeMachine $full
        if ($machine -eq $e.Machine) {
            $verdict = 'OK  '
        } else {
            $verdict = 'FAIL'
            $failures++
        }
        $line = ("  {0}  {1,-58} machine=0x{2:X4} expected=0x{3:X4}  {4}" -f $verdict, $e.Path, $machine, $e.Machine, $e.Note)
        Write-Output $line
        if ($verdict.Trim() -eq 'FAIL') { $report += "${($e.Path)}:0x$('{0:X4}' -f $machine)!=0x$('{0:X4}' -f $e.Machine)" }
    } catch {
        Write-Output ("  FAIL  {0,-58} {1}" -f $e.Path, $_.Exception.Message)
        $failures++
    }
}

Write-Output ''
if ($failures -eq 0) {
    Write-Output 'PASS: all binaries have the expected architecture'
    exit 0
}

# Surface the verdict where CI can read it without downloading logs:
# GitHub renders `::error::` lines as check annotations, which are readable through the
# public annotations API even when the full log requires authentication.
$summary = "PE arch check failed ($failures): see the listing above"
if ($env:GITHUB_ACTIONS -eq 'true') {
    $details = ($report -join ' | ')
    Write-Output "::error title=PE arch mismatch::$summary -- $details"
}
Write-Output "FAIL: $failures mismatch(es)"
exit 1
