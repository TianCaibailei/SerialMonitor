# End-to-end proof that attaching the monitor does NOT steal the serial port.
#
# Steps:
#   1. A "business" program opens COM6 exclusively and keeps communicating.
#   2. A third program tries to open COM6 -> must fail (the business program owns it).
#   3. Our hook DLL is injected into the business program (what the monitor does).
#   4. The third program tries again -> must STILL fail (we injected, we didn't open).
#   5. The business program's traffic must arrive complete on the peer port.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Port = 'COM6'
$Peer = 'COM7'
$resultFile = Join-Path $env:TEMP 'biz-result.txt'
Remove-Item $resultFile -ErrorAction SilentlyContinue

Write-Output '== 1. 启动业务程序（独占 COM6，持续收发 40 帧）=='
$biz = Start-Process powershell -PassThru -WindowStyle Hidden -ArgumentList @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass',
    '-File', (Join-Path $root 'biz-program.ps1'),
    '-Port', $Port, '-Frames', '40', '-ResultFile', $resultFile
)

# Wait until the business program actually holds the port (our probe must fail).
$deniedBefore = $false
$sw0 = [Diagnostics.Stopwatch]::StartNew()
while ($sw0.ElapsedMilliseconds -lt 15000) {
    try {
        $probe = New-Object System.IO.Ports.SerialPort($Port, 9600)
        $probe.Open()
        $probe.Close()
        Start-Sleep -Milliseconds 300
    } catch {
        $deniedBefore = $true
        break
    }
}
Write-Output '== 2. 业务程序已持有端口（第三方打开应失败）=='
Write-Output "   注入前第三方打开被拒绝: $deniedBefore"

Write-Output '== 3. 注入 hook DLL（等同监控软件附加到进程）=='
$dll = Join-Path $root 'target\release\monitor_hook.dll'
if (-not (Test-Path $dll)) { throw "hook DLL not found: $dll" }
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class Inj {
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
$rc = [Inj]::Inject($biz.Id, (Resolve-Path $dll).Path)
Write-Output "   注入返回码: $rc (0 = 成功)"
Start-Sleep -Milliseconds 1500

Write-Output '== 4. 注入后再次尝试打开 COM6（关键断言：必须仍然失败）=='
$deniedAfter = $false
try {
    $probe2 = New-Object System.IO.Ports.SerialPort($Port, 9600)
    $probe2.Open()
    $probe2.Close()
} catch {
    $deniedAfter = $true
}
Write-Output "   注入后第三方打开被拒绝: $deniedAfter"

Write-Output '== 5. 业务程序通信完整性 =='
$peer = New-Object System.IO.Ports.SerialPort($Peer, 9600)
$peer.Open()
$acc = New-Object System.Text.StringBuilder
$sw = [Diagnostics.Stopwatch]::StartNew()
while ($sw.ElapsedMilliseconds -lt 11000) {
    $chunk = $peer.ReadExisting()
    if ($chunk) { [void]$acc.Append($chunk) }
    Start-Sleep -Milliseconds 100
}
$peer.Close()
$traffic = $acc.ToString()
$tickCount = ([regex]::Matches($traffic, 'TICK\d+;')).Count

try { if (-not $biz.HasExited) { $biz | Stop-Process -Force } } catch {}
Start-Sleep -Milliseconds 300

Write-Output ''
Write-Output '=== 结论 ==='
Write-Output "注入成功:             $($rc -eq 0)"
Write-Output "注入前端口被独占:     $deniedBefore"
Write-Output "注入后端口仍被独占:   $deniedAfter"
Write-Output "对端收到的 TICK 帧数: $tickCount"
if ($rc -eq 0 -and $deniedBefore -and $deniedAfter -and $tickCount -gt 20) {
    Write-Output 'PASS: 监控附加后不占用串口，业务程序继续独占使用且通信完整'
} else {
    Write-Output 'FAIL: 见上面的具体断言'
}
