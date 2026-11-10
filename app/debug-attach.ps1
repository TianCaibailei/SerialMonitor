# Debug the attach-after-open case step by step.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$dll = Join-Path $root 'target\release\monitor_hook.dll'
Remove-Item "$env:TEMP\um_hook_*.log" -ErrorAction SilentlyContinue
# Turn on hook diagnostics for the injected process.
Set-Content -Path "$env:TEMP\um_hook_debug" -Value '1'

Write-Output '=== 1. 进程先打开 COM6 ==='
$biz = Start-Process powershell -PassThru -WindowStyle Hidden -ArgumentList @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $root 'biz-program.ps1'),
    '-Port', 'COM6', '-Frames', '100', '-ResultFile', (Join-Path $env:TEMP 'dbg-biz.txt'))
$sw = [Diagnostics.Stopwatch]::StartNew()
while ($sw.ElapsedMilliseconds -lt 15000) {
    try { $p = New-Object System.IO.Ports.SerialPort('COM6', 9600); $p.Open(); $p.Close(); Start-Sleep -Milliseconds 250 }
    catch { break }
}
Write-Output "PID=$($biz.Id) 已持有端口"

Write-Output '=== 2. 注入 ==='
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class Inj3 {
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
$rc = [Inj3]::Inject($biz.Id, (Resolve-Path $dll).Path)
Write-Output "注入返回码: $rc"
Start-Sleep -Seconds 2

$log = Get-ChildItem "$env:TEMP\um_hook_*.log" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($log) { Write-Output "hook 日志 ($($log.Name)):"; Get-Content $log.FullName | Select-Object -First 25 } else { Write-Output 'hook 日志未生成 —— DLL 可能未加载' }

Write-Output '=== 3. 对端持续发数据 8 秒 ==='
$peer = New-Object System.IO.Ports.SerialPort('COM7', 9600)
$peer.Open()
$sw2 = [Diagnostics.Stopwatch]::StartNew()
$i = 0
while ($sw2.ElapsedMilliseconds -lt 8000) {
    $peer.Write("X$i;"); $i++
    Start-Sleep -Milliseconds 300
    $null = $peer.ReadExisting()
}
$peer.Close()
Start-Sleep -Milliseconds 500

$log2 = Get-ChildItem "$env:TEMP\um_hook_*.log" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($log2) { Write-Output "=== 最终日志 ($($log2.Name)) ==="; Get-Content $log2.FullName | Select-Object -Last 25 }
try { if (-not $biz.HasExited) { $biz | Stop-Process -Force } } catch {}
Remove-Item "$env:TEMP\um_hook_debug" -ErrorAction SilentlyContinue
