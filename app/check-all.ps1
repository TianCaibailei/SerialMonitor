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

    # 架构校验委托给单独的脚本：CI 与本地必须执行同一份逻辑，
    # 之前内联副本与 CI 不同步，导致"本地绿、CI 红"。
    powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'verify-pe-arch.ps1') -AppDir $PSScriptRoot
    if ($LASTEXITCODE -ne 0) { Fail "PE 架构校验未通过" } else { Ok "产物架构正确" }
}

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
