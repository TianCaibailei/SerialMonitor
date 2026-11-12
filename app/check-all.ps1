# check-all.ps1 — 本地一键跑完 CI 的全部门禁。
#
# 与 .github/workflows/ci.yml 保持同一套断言，避免「CI 绿、本地红」这种分歧：
#
#   1. cargo fmt --check        格式
#   2. cargo clippy -D warnings 静态检查（生产代码）
#   3. cargo test --workspace   单元测试 + 测试数量下限
#   4. 构建 x64 与 x86 注入器 + PE 架构校验
#   5. 文档齐备 + 私钥未入库
#
# 用法：
#   powershell -ExecutionPolicy Bypass -File app\check-all.ps1
#   powershell -ExecutionPolicy Bypass -File app\check-all.ps1 -SkipBuild   # 跳过交叉编译

param(
    [switch]$SkipBuild
)

# 注意：不要用 'Stop'。cargo 会把进度/警告写到 stderr，而 PowerShell 在 Stop 模式下
# 会把原生命令的 stderr 当成终止错误，导致脚本在第一步就退出。判断成败一律看
# $LASTEXITCODE。
$ErrorActionPreference = 'Continue'
Set-Location -Path $PSScriptRoot

$failures = New-Object System.Collections.Generic.List[string]

function Step([string]$name) {
    Write-Host ""
    Write-Host "=== $name ===" -ForegroundColor Cyan
}

function Fail([string]$msg) {
    $failures.Add($msg) | Out-Null
    Write-Host "  FAIL: $msg" -ForegroundColor Red
}

function Ok([string]$msg) {
    Write-Host "  OK: $msg" -ForegroundColor Green
}

# ---------------------------------------------------------------- 1. fmt
Step "1/5 cargo fmt --check"
cargo fmt --all -- --check
if ($LASTEXITCODE -ne 0) { Fail "格式检查未通过（运行 cargo fmt --all 修复）" } else { Ok "格式一致" }

# ---------------------------------------------------------------- 2. clippy
Step "2/5 cargo clippy -D warnings"
cargo clippy --workspace --lib --bins -- -D warnings
if ($LASTEXITCODE -ne 0) { Fail "clippy 未通过" } else { Ok "无 lint 问题" }

# ---------------------------------------------------------------- 3. tests
Step "3/5 cargo test"
$out = (cargo test --workspace --all-targets 2>&1 | Out-String)
Write-Host $out
if ($LASTEXITCODE -ne 0) {
    Fail "测试失败"
} else {
    # 单调防线：一个「全绿但跑了 0 个测试」的套件曾骗过这个仓库很久。
    $m = [regex]::Match($out, 'test result: ok\. (\d+) passed[^\r\n]*\r?\n[^\r\n]*\r?\n[^\r\n]*\r?\n[^\r\n]*')
    $total = 0
    foreach ($mm in [regex]::Matches($out, '(\d+) passed')) { $total += [int]$mm.Groups[1].Value }
    Write-Host "  统计到的 passed 总数: $total"
    $floor = 30
    if ($total -lt $floor) { Fail "测试数 $total 低于下限 $floor" } else { Ok "$total 个测试通过" }
}

# ---------------------------------------------------------------- 4. build + arch
if ($SkipBuild) {
    Step "4/5 构建与架构校验（已跳过）"
} else {
    Step "4/5 构建与 PE 架构校验"
    cargo build --release
    if ($LASTEXITCODE -ne 0) { Fail "x64 构建失败" }
    cargo build --release --target i686-pc-windows-msvc -p monitor_hook
    if ($LASTEXITCODE -ne 0) { Fail "x86 hook 构建失败" }
    cargo build --release --target i686-pc-windows-msvc -p universal_injector_x86
    if ($LASTEXITCODE -ne 0) { Fail "x86 注入器构建失败" }

    function Get-PeMachine([string]$path) {
        $fs = [System.IO.File]::OpenRead($path)
        try {
            $br = [System.IO.BinaryReader]::new($fs)
            $fs.Position = 0x3C
            $peOff = $br.ReadInt32()
            $fs.Position = $peOff
            if ($br.ReadUInt32() -ne 0x00004550) { throw "不是 PE 文件: $path" }
            return $br.ReadUInt16()
        } finally { $fs.Dispose() }
    }
    # 用绝对路径：PowerShell 的 Set-Location 不会同步 .NET 的当前目录，
    # 而 Get-PeMachine 走的是 .NET 文件 API，相对路径会解析到错误的位置。
    $root = $PSScriptRoot
    $expect = [ordered]@{
        'target\release\monitor_hook.dll'                                = 0x8664
        'target\release\universal_monitor.exe'                           = 0x8664
        'target\i686-pc-windows-msvc\release\monitor_hook.dll'           = 0x014C
        'target\i686-pc-windows-msvc\release\universal_injector_x86.exe' = 0x014C
    }
    foreach ($k in $expect.Keys) {
        $full = Join-Path $root $k
        if (-not (Test-Path $full)) { Fail "缺少产物: $k"; continue }
        $m = Get-PeMachine $full
        if ($m -eq $expect[$k]) {
            Ok ("{0} machine=0x{1:X4}" -f $k, $m)
        } else {
            Fail ("{0} machine=0x{1:X4}，期望 0x{2:X4}" -f $k, $m, $expect[$k])
        }
    }
}

# ---------------------------------------------------------------- 5. repo hygiene
Step "5/5 仓库卫生"
# 仓库根 = 本脚本所在目录的上一级。用绝对路径，理由同上（.NET 不同步 PowerShell 的 cwd）。
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$docs = @('docs\README.md', 'docs\技术手册.md', 'CHANGELOG.md', 'LICENSE', 'SECURITY.md')
$docsOk = $true
foreach ($d in $docs) {
    $full = Join-Path $repoRoot $d
    if (-not (Test-Path $full)) { Fail "缺失文档: $d"; $docsOk = $false }
    elseif ((Get-Item $full).Length -eq 0) { Fail "空文档: $d"; $docsOk = $false }
}
if ($docsOk) { Ok "关键文档齐备" }


$bad = git ls-files | Select-String -Pattern '\.(pfx|pvk|key|snk|pem)$'
if ($bad) {
    $bad | ForEach-Object { Fail "私钥/证书被版本库跟踪: $_" }
} else {
    Ok "版本库中没有私钥/证书"
}

# ---------------------------------------------------------------- summary
Write-Host ""
if ($failures.Count -eq 0) {
    Write-Host "================ 全部通过 ================" -ForegroundColor Green
    Set-Location -Path $PSScriptRoot
    exit 0
} else {
    Write-Host "================ 失败 $($failures.Count) 项 ================" -ForegroundColor Red
    $failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    Set-Location -Path $PSScriptRoot
    exit 1
}
