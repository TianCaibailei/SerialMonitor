# Install / manage the UmSerialFilter driver.
#
# Must run elevated. Loading an unsigned kernel driver requires test-signing mode:
#   bcdedit /set testsigning on    (then reboot)
#
# Usage:
#   powershell -File install-driver.ps1 -Action install
#   powershell -File install-driver.ps1 -Action start
#   powershell -File install-driver.ps1 -Action stop
#   powershell -File install-driver.ps1 -Action uninstall
#   powershell -File install-driver.ps1 -Action status
param(
    [ValidateSet('install', 'start', 'stop', 'uninstall', 'status')]
    [string]$Action = 'status'
)
$ErrorActionPreference = 'Continue'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$sys = Join-Path $root 'umserialfilter\umserialfilter.sys'
$serviceName = 'UmSerialFilter'
$displayName = 'Universal Serial Monitor Filter'

function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Output '错误: 需要管理员权限。请用管理员身份的 PowerShell 运行。'
        exit 1
    }
}

function Show-Status {
    Write-Output '=== 测试签名状态 ==='
    $ts = bcdedit /enum '{current}' 2>&1 | Select-String 'testsigning'
    if ($ts) { Write-Output $ts.Line.Trim() } else { Write-Output '  未开启 (testsigning 不在启动项里)' }

    Write-Output ''
    Write-Output '=== 服务状态 ==='
    $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($svc) {
        Get-CimInstance Win32_SystemDriver -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue |
            Select-Object Name, State, Started, PathName | Format-List
    } else {
        Write-Output '  服务未创建'
    }

    Write-Output ''
    Write-Output '=== 设备是否可打开 ==='
    Write-Output "  设备路径: \\.\$serviceName"
}

Assert-Admin

switch ($Action) {
    'status' {
        Show-Status
    }

    'install' {
        if (-not (Test-Path $sys)) { throw "找不到驱动文件: $sys" }

        # Signing state check: an unsigned driver cannot load unless test-signing is on.
        $ts = bcdedit /enum '{current}' 2>&1 | Select-String 'testsigning'
        if (-not $ts) {
            Write-Output '警告: 未开启测试签名，驱动将无法加载。'
            Write-Output '请先执行（需重启）:'
            Write-Output '  bcdedit /set testsigning on'
            Write-Output ''
        }

        $existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Output "服务已存在，先删除后重建"
            & sc.exe stop $serviceName | Out-Null
            Start-Sleep -Seconds 1
            & sc.exe delete $serviceName | Out-Null
            Start-Sleep -Seconds 1
        }

        Write-Output "创建服务: $serviceName"
        & sc.exe create $serviceName type= kernel start= demand binPath= $sys DisplayName= $displayName
        if ($LASTEXITCODE -ne 0) {
            Write-Output "创建服务失败 (退出码 $LASTEXITCODE)"
            exit 1
        }
        Write-Output '服务已创建'
    }

    'start' {
        Write-Output "启动 $serviceName …"
        & sc.exe start $serviceName
        $rc = $LASTEXITCODE
        Start-Sleep -Seconds 1
        $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') {
            Write-Output 'PASS: 驱动已运行'
            Write-Output ''
            Write-Output '现在可以运行用户态程序验证捕获:'
            Write-Output "  $root\umfilter_reader\umfilter_reader.exe 15"
        } else {
            Write-Output "FAIL: 驱动未运行 (sc 退出码 $rc)"
            Write-Output ''
            Write-Output '常见原因:'
            Write-Output '  577  签名验证失败 → 需要开启测试签名并重启'
            Write-Output '  1275  驱动被阻止加载 → 检查驱动签名策略'
            Write-Output '  2    找不到文件 → 检查 binPath'
            Write-Output ''
            Write-Output '最近的内核事件:'
            Get-WinEvent -FilterHashtable @{LogName = 'System'; ProviderName = 'Service Control Manager' } -MaxEvents 5 -ErrorAction SilentlyContinue |
                Select-Object TimeCreated, Message | Format-List
        }
    }

    'stop' {
        & sc.exe stop $serviceName
        Write-Output "已请求停止 $serviceName"
    }

    'uninstall' {
        & sc.exe stop $serviceName | Out-Null
        Start-Sleep -Seconds 1
        & sc.exe delete $serviceName
        Write-Output "已删除服务 $serviceName"
    }
}
