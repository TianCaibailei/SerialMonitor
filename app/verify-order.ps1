# Compare two orders to isolate whether "attach after the port is open" is the problem.
#   A: inject -> then open the port and talk   (should be captured)
#   B: open the port -> then inject -> talk    (may be missed: cached API pointers)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$dll = Join-Path $root 'target\release\monitor_hook.dll'

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class Inj4 {
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint a, bool b, int pid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr VirtualAllocEx(IntPtr p, IntPtr a, uint s, uint t, uint pr);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool WriteProcessMemory(IntPtr p, IntPtr a, byte[] b, uint s, out UIntPtr w);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr GetProcAddress(IntPtr m, string n);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr GetModuleHandle(string n);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr CreateRemoteThread(IntPtr p, IntPtr a, uint s, IntPtr f, IntPtr param, uint c, IntPtr tid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr h);
    public static int Inject(int pid, string dllPath) {
        IntPtr h = OpenProcess(0x1F0FFF, false, pid);
        if (h == IntPtr.Zero) return -1;
        byte[] bytes = System.Text.Encoding.Unicode.GetBytes(dllPath + "\0");
        IntPtr mem = VirtualAllocEx(h, IntPtr.Zero, (uint)bytes.Length, 0x3000, 0x04);
        if (mem == IntPtr.Zero) { CloseHandle(h); return -2; }
        UIntPtr written;
        if (!WriteProcessMemory(h, mem, bytes, (uint)bytes.Length, out written)) { CloseHandle(h); return -3; }
        IntPtr loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryW");
        IntPtr t = CreateRemoteThread(h, IntPtr.Zero, 0, loadLib, mem, 0, IntPtr.Zero);
        if (t == IntPtr.Zero) { CloseHandle(h); return -4; }
        WaitForSingleObject(t, 10000);
        CloseHandle(t); CloseHandle(h);
        return 0;
    }
}
'@

function Test-Order([string]$label, [bool]$openFirst) {
    Write-Output "=== $label ==="
    Remove-Item "$env:TEMP\um_hook_*.log" -ErrorAction SilentlyContinue
    Set-Content -Path "$env:TEMP\um_hook_debug" -Value '1'

    # A long-lived child that waits for a marker file, so timing is deterministic.
    $marker = Join-Path $env:TEMP "go-$([guid]::NewGuid().ToString('N')).txt"
    $script = @"
`$ErrorActionPreference='Stop'
`$marker='$marker'
if (-not '$openFirst'.Equals('True')) { while (-not (Test-Path `$marker)) { Start-Sleep -Milliseconds 100 } }
`$p = New-Object System.IO.Ports.SerialPort('COM6',9600)
`$p.Open()
if ('$openFirst'.Equals('True')) { New-Item -Path `$marker -ItemType File -Force | Out-Null }
`$acc=''
for (`$i=0; `$i -lt 40; `$i++) { `$p.Write("CH[$label-`$i];"); Start-Sleep -Milliseconds 250; `$acc += `$p.ReadExisting() }
`$p.Close()
"@
    $child = Start-Process powershell -PassThru -WindowStyle Hidden -ArgumentList @('-NoProfile','-Command',$script)

    if ($openFirst) {
        # wait until the port is definitely open
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while ($sw.ElapsedMilliseconds -lt 12000) {
            try { $probe = New-Object System.IO.Ports.SerialPort('COM6',9600); $probe.Open(); $probe.Close(); Start-Sleep -Milliseconds 200 }
            catch { break }
        }
    } else {
        Start-Sleep -Milliseconds 800
    }

    $rc = [Inj4]::Inject($child.Id, (Resolve-Path $dll).Path)
    New-Item -Path $marker -ItemType File -Force | Out-Null
    Write-Output "注入 rc=$rc, PID=$($child.Id)"

    Start-Sleep -Seconds 7
    $log = Get-ChildItem "$env:TEMP\um_hook_*.log" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    $hits = 0
    if ($log) {
        $lines = Get-Content $log.FullName
        $hits = ($lines | Select-String -Pattern 'cfw:|wf|rf:|com_label.*serial' | Measure-Object).Count
        Write-Output "hook 日志行数=$($lines.Count) 匹配读写=$hits"
        $lines | Select-Object -First 8 | ForEach-Object { Write-Output "  $_" }
    } else {
        Write-Output '无 hook 日志'
    }
    try { if (-not $child.HasExited) { $child | Stop-Process -Force } } catch {}
    Remove-Item "$env:TEMP\um_hook_debug" -ErrorAction SilentlyContinue
    Remove-Item $marker -ErrorAction SilentlyContinue
    return $hits
}

$a = Test-Order 'A: 先注入后打开端口' $false
$b = Test-Order 'B: 先打开端口后注入' $true
Write-Output ''
Write-Output "A(先注入)=$a  B(后注入)=$b"
