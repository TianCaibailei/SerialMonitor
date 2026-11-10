# Verify the injection-first approach: inject into a process that is ALREADY holding
# COM6 open, then make it talk. If the hook captures that traffic, we do not need to
# find port owners at all — injecting broadly and letting the hook decide is enough.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$dll = Join-Path $root 'target\release\monitor_hook.dll'

Write-Output '=== 1. 启动持有 COM6 的进程（先打开，后注入）==='
$biz = Start-Process powershell -PassThru -WindowStyle Hidden -ArgumentList @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $root 'biz-program.ps1'),
    '-Port', 'COM6', '-Frames', '60', '-ResultFile', (Join-Path $env:TEMP 'inject-first.txt')
)
# Wait until it holds the port
$sw = [Diagnostics.Stopwatch]::StartNew()
while ($sw.ElapsedMilliseconds -lt 12000) {
    try {
        $probe = New-Object System.IO.Ports.SerialPort('COM6', 9600)
        $probe.Open(); $probe.Close()
        Start-Sleep -Milliseconds 250
    } catch { break }
}
Write-Output "业务进程 PID=$($biz.Id)，已持有端口"

Write-Output '=== 2. 后注入 hook（模拟自动附加晚于端口打开）==='
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class Inj2 {
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
$rc = [Inj2]::Inject($biz.Id, (Resolve-Path $dll).Path)
Write-Output "注入返回码: $rc"

Write-Output '=== 3. 让对端持续发数据（触发业务进程读）==='
$peer = New-Object System.IO.Ports.SerialPort('COM7', 9600)
$peer.Open()
for ($i = 0; $i -lt 20; $i++) {
    $peer.Write("PEER$i;")
    Start-Sleep -Milliseconds 300
    $null = $peer.ReadExisting()
}
$peer.Close()

Start-Sleep -Milliseconds 500
try { if (-not $biz.HasExited) { $biz | Stop-Process -Force } } catch {}
Write-Output '=== 完成（结果见 hook 日志与 --headless-watch 的会话）==='
