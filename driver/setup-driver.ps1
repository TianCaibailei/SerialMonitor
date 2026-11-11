# One-shot setup for the UmSerialFilter driver.
#
# Handles the whole sequence a user needs, and explains each blocker instead of failing
# silently:
#   1. verify test-signing is enabled (required for an unsigned-in-flight driver)
#   2. import the test certificate into the machine trust stores
#   3. create + start the kernel service
#   4. verify capture works
#
# Run elevated:
#   powershell -ExecutionPolicy Bypass -File setup-driver.ps1
#
# If step 1 fails because Secure Boot blocks test-signing, the script stops and says
# exactly what to change in the firmware — that is the only step a person must do.
$ErrorActionPreference = 'Continue'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$sys = Join-Path $root 'umserialfilter\umserialfilter.sys'
$cer = Join-Path $root 'umfilter-test.cer'
$reader = Join-Path $root 'umfilter_reader\umfilter_reader.exe'
$serviceName = 'UmSerialFilter'

function Test-Admin {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-Step([string]$text) {
    Write-Output ''
    Write-Output "=== $text ==="
}

if (-not (Test-Admin)) {
    Write-Output '错误: 需要管理员权限。'
    Write-Output '请右键点击 PowerShell → 以管理员身份运行，然后重新执行本脚本。'
    exit 1
}

Write-Step '1/5 检查测试签名'
$ts = bcdedit /enum '{current}' 2>&1 | Select-String 'testsigning'
if (-not $ts) {
    # Try to enable it: if Secure Boot blocks the write, bcdedit reports it and the hint
    # below is the only thing the user has to act on.
    $out = bcdedit /set testsigning on 2>&1 | Out-String
    if ($out -match 'secure boot|安全引导|受安全引导') {
        Write-Output '测试签名无法开启: Secure Boot 保护了该设置。'
        Write-Output ''
        Write-Output '请执行（需要人工操作）:'
        Write-Output '  1. 重启进入 BIOS/UEFI 设置'
        Write-Output '  2. 找到 Security → Secure Boot，设为 Disabled'
        Write-Output '  3. 保存退出，进入 Windows 后重新运行本脚本'
        exit 1
    }
    Write-Output '已请求开启测试签名，需要重启后生效。'
    Write-Output '请重启电脑，然后重新运行本脚本。'
    exit 1
}
Write-Output '  测试签名已开启 ✓'

Write-Step '2/5 导入测试证书到信任区'
if (-not (Test-Path $cer)) {
    Write-Output "  证书不存在: $cer"
    exit 1
}
try {
    Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\Root -ErrorAction Stop | Out-Null
    Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher -ErrorAction Stop | Out-Null
    Write-Output '  证书已导入 Root 与 TrustedPublisher ✓'
} catch {
    Write-Output "  证书导入失败: $($_.Exception.Message)"
}

Write-Step '3/5 安装驱动服务'
if (-not (Test-Path $sys)) {
    Write-Output "  驱动文件不存在: $sys"
    exit 1
}
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing) {
    $state = (& sc.exe query $serviceName 2>&1 | Out-String)
    if ($state -match 'START_PENDING') {
        Write-Output '  服务卡在 START_PENDING，无法删除（1072）。'
        Write-Output '  请重启电脑后再运行本脚本。'
        exit 1
    }
    Write-Output '  服务已存在，删除后重建'
    & sc.exe stop $serviceName 2>&1 | Out-Null
    Start-Sleep -Seconds 1
    $del = & sc.exe delete $serviceName 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        Write-Output "  删除失败: $($del.Trim())"
        if ($del -match '1072|标记为删除') {
            Write-Output '  1072 = 服务已标记删除但未生效，需要重启电脑。'
        }
        exit 1
    }
    Start-Sleep -Seconds 1
}
$out = & sc.exe create $serviceName type= kernel start= demand binPath= $sys DisplayName= 'Universal Serial Monitor Filter' 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) {
    Write-Output "  创建失败: $out"
    exit 1
}
Write-Output '  服务已创建 ✓'

Write-Step '4/5 启动驱动'
# A driver whose DriverEntry never returns sits in START_PENDING forever, can be neither
# stopped nor deleted (1072), and keeps its .sys file locked. Detect that state explicitly
# instead of letting `sc start` look like a hang.
$out = & sc.exe start $serviceName 2>&1 | Out-String
$pending = $false
for ($i = 0; $i -lt 12; $i++) {
    Start-Sleep -Milliseconds 500
    $q = & sc.exe query $serviceName 2>&1 | Out-String
    if ($q -match 'START_PENDING') { $pending = $true; continue }
    if ($q -match 'RUNNING') { $pending = $false; break }
    if ($q -match 'STOPPED') { $pending = $false; break }
}
if ($pending) {
    Write-Output '  驱动卡在 START_PENDING —— DriverEntry 没有返回。'
    Write-Output ''
    Write-Output '  这是驱动内部的死循环或阻塞，不是权限/签名问题。'
    Write-Output '  此时服务既不能停止也不能删除（会返回 1072），只能:'
    Write-Output '    1. 重启电脑'
    Write-Output '    2. 重启后重新运行本脚本'
    exit 1
}

$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    Write-Output '  驱动已运行 ✓'
} else {
    $code = (& sc.exe query $serviceName 2>&1 | Select-String 'WIN32_EXIT_CODE') -replace '.*:\s*', ''
    Write-Output "  启动失败，退出码: $code"
    switch -Regex ($code) {
        '577' {
            Write-Output '  577 = 签名验证失败'
            Write-Output '     · 确认已重启（testsigning 需要重启才生效）'
            Write-Output '     · 确认证书已导入 TrustedPublisher'
        }
        '1275' { Write-Output '  1275 = 驱动被策略阻止（检查组策略或安全软件）' }
        default { Write-Output '  请检查事件查看器 → Windows 日志 → 系统' }
    }
    exit 1
}

Write-Step '5/5 验证捕获'
Write-Output '  驱动已就绪。现在可以:'
Write-Output ''
Write-Output '  A. 命令行验证（另开一个窗口，用串口工具收发数据）:'
Write-Output "     $reader 20"
Write-Output ''
Write-Output '  B. GUI 验证:'
Write-Output '     打开 universal_monitor.exe → 菜单「监控」→「启用驱动捕获(推荐)」'
Write-Output '     然后用任意串口调试助手打开 COM 口收发，数据会自动出现在表格里'
Write-Output ''
Write-Output '安装完成。'
