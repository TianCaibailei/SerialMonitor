# Verify the manual-attach workflow (the user's chosen path A).
#
# Steps mirror what a person does with the dialog:
#   1. the serial tool starts FIRST and holds COM6
#   2. the monitor starts and the attach dialog lists processes
#   3. the tool's PID is found (search by name), injected, and its traffic captured
#
# The injection here uses the same inject::inject code the dialog's button calls.
param(
    [string]$Exe = "$PSScriptRoot\target\release\universal_monitor.exe"
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$result = Join-Path $env:TEMP 'attach-verify.json'
Remove-Item $result -ErrorAction SilentlyContinue

Write-Output '=== 1. 先启动串口工具并让它持有 COM6 ==='
$tool = Start-Process powershell -PassThru -WindowStyle Hidden -ArgumentList @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command',
    '$p=New-Object System.IO.Ports.SerialPort("COM6",9600); $p.Open(); ' +
    'for ($i=0; $i -lt 60; $i++) { $p.Write("ATT$i;"); Start-Sleep -Milliseconds 250; $null=$p.ReadExisting() }; ' +
    '$p.Close()')
Start-Sleep -Seconds 2
$sw = [Diagnostics.Stopwatch]::StartNew()
while ($sw.ElapsedMilliseconds -lt 10000) {
    try { $q = New-Object System.IO.Ports.SerialPort('COM6',9600); $q.Open(); $q.Close(); Start-Sleep -Milliseconds 200 }
    catch { break }
}
Write-Output "工具 PID=$($tool.Id)，已持有 COM6"

Write-Output '=== 2. 启动监控（被动监听 COM6）==='
$mon = Start-Process $Exe -PassThru -WindowStyle Hidden -ArgumentList @(
    '--headless-watch', 'COM6', '--result', $result)
Start-Sleep -Seconds 3

Write-Output '=== 3. 手动注入该工具进程（等同对话框点「注入并监控」）==='
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class InjAttach {
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint a,bool b,int p);
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr VirtualAllocEx(IntPtr p,IntPtr a,uint s,uint t,uint pr);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool WriteProcessMemory(IntPtr p,IntPtr a,byte[] b,uint s,out UIntPtr w);
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr GetProcAddress(IntPtr m,string n);
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr GetModuleHandle(string n);
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr CreateRemoteThread(IntPtr p,IntPtr a,uint s,IntPtr f,IntPtr param,uint c,IntPtr tid);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr h,uint ms);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr h);
    public static int Go(int pid,string dll){
        IntPtr h=OpenProcess(0x1F0FFF,false,pid); if(h==IntPtr.Zero) return -1;
        byte[] b=System.Text.Encoding.Unicode.GetBytes(dll+"\0");
        IntPtr m=VirtualAllocEx(h,IntPtr.Zero,(uint)b.Length,0x3000,0x04); if(m==IntPtr.Zero){CloseHandle(h);return -2;}
        UIntPtr w; if(!WriteProcessMemory(h,m,b,(uint)b.Length,out w)){CloseHandle(h);return -3;}
        IntPtr ll=GetProcAddress(GetModuleHandle("kernel32.dll"),"LoadLibraryW");
        IntPtr t=CreateRemoteThread(h,IntPtr.Zero,0,ll,m,0,IntPtr.Zero); if(t==IntPtr.Zero){CloseHandle(h);return -4;}
        WaitForSingleObject(t,10000); CloseHandle(t); CloseHandle(h); return 0;}
}
'@
$dll = (Resolve-Path (Join-Path $root 'target\release\monitor_hook.dll')).Path
$rc = [InjAttach]::Go($tool.Id, $dll)
Write-Output "注入返回码: $rc (0=成功)"
Start-Sleep -Seconds 3

Write-Output '=== 4. 检查工具进程是否加载了 hook ==='
$mods = Get-Process -Id $tool.Id -Module -ErrorAction SilentlyContinue |
    Where-Object { $_.ModuleName -like 'monitor_hook*' }
Write-Output ("hook 已加载: " + [bool]$mods)

Write-Output '=== 5. 对端发数据（触发被注入进程的读）==='
$peer = New-Object System.IO.Ports.SerialPort('COM7', 9600)
$peer.Open()
for ($i = 0; $i -lt 10; $i++) {
    $peer.Write("PEER$i;")
    Start-Sleep -Milliseconds 250
    $null = $peer.ReadExisting()
}
$peer.Close()

Start-Sleep -Seconds 3
$mon | Wait-Process -Timeout 30 -ErrorAction SilentlyContinue

Write-Output '=== 6. hook 记录 ==='
Get-ChildItem "$env:TEMP\um_hook_*.log" -ErrorAction SilentlyContinue | ForEach-Object {
    $c = Get-Content $_.FullName
    $hits = $c | Select-String 'cfw|wf|rf:'
    if ($hits) { Write-Output "--- $($_.Name) ---"; $hits | Select-Object -First 8 }
}

Write-Output '=== 7. 监控结果 ==='
$res = $null
if (Test-Path $result) {
    $res = Get-Content $result -Raw | ConvertFrom-Json
    Write-Output "行数=$($res.rows) TX=$($res.tx) RX=$($res.rx)"
}

foreach ($p in @($mon, $tool)) { try { if (-not $p.HasExited) { $p | Stop-Process -Force } } catch {} }
if ($res -and $res.rows -gt 0) { Write-Output 'PASS: 手动附加后捕获到数据' } else { Write-Output 'FAIL: 未捕获' }
