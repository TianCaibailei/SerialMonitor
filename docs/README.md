# 文档索引

> 先读 `技术手册.md`。其余按需查阅。

## 主文档

| 文档 | 内容 | 什么时候读 |
|---|---|---|
| **[技术手册.md](技术手册.md)** | 两条捕获路径的实现、显示编码机制、暂停语义、会话存档格式、关键参数、构建部署步骤、验收方法 | **首选**。日常开发、部署、排障都从这里开始 |
| [功能完整性闭环评估报告.md](功能完整性闭环评估报告.md) | 从 GUI 入口逐控件追溯闭环的审计结论与优先级路线图 | 规划下一阶段工作、判断"还差什么"时 |
| [逆向机制说明.md](逆向机制说明.md) | 参考产品 CommMonitor 的机制分析（含证据链） | 需要对照原设计、或扩展功能时 |
| [逆向取证记录.md](逆向取证记录.md) | 目标文件基本信息、导入库、工具可用性 | 复查逆向起点时 |
| [参考驱动复刻规格.md](参考驱动复刻规格.md) | 参考驱动 ComDrv12x64.sys 的复刻规格 | 修改驱动行为前 |
| [逆向对比报告.md](逆向对比报告.md) | 参考驱动 vs 本驱动的差异对比 | 评估实现完整度时 |

## 驱动专题

| 文档 | 内容 |
|---|---|
| [WDK-NUGET-GUIDE.md](WDK-NUGET-GUIDE.md) | 用 NuGet 方式装 WDK（本机采用，无需完整 WDK MSI） |
| [安装与签名指南.md](安装与签名指南.md) | 测试签名、`sc create` 安装、证书指纹等具体操作 |
| [签名与认证方案.md](签名与认证方案.md) | 签名/认证的可行方案与取舍 |
| [兼容性与安全设计.md](兼容性与安全设计.md) | 多版本 Windows / 双架构兼容性，以及安全边界 |

## 归档

`archive/` 存放历史问题的排查过程记录（某天某 bug 的根因分析与修复步骤）。

**内容已并入 `技术手册.md`**，仅在需要追溯"当时为什么这么改"时才查。
其中 `old-scripts/`（早期一次性验证脚本）已于本轮清理——它们的作用已被
`app/verify-fixed.ps1`、`app/verify-no-steal.ps1`、`app/verify-dual-arch.ps1`
三个仍在维护的验收脚本取代。

> 当前可运行的验收脚本只有 `app/` 与 `driver/` 下的这几个；`docs/archive/` 里的
> 内容**不要直接执行**，它们是历史快照，可能引用已删除的文件或过期路径。

---

## 代码结构

```
app/                      主程序（Rust + egui）
  src/                    UI、会话、解码层、注入器、驱动客户端
    text_codec.rs         字节 → 文本的唯一解码入口（UTF-8/GBK/UTF-16LE）
    protocol.rs           Modbus 解析 + 组帧（组帧仅供单元测试与逆向证据）
    session.rs            会话、过滤、速率、存档（.umses）
  hook/                   注入的 hook DLL（独立 crate，x64 + x86 双编译）
  x86_injector/           32 位注入器（独立 crate，防止被主构建覆盖）
  tests/                  诊断探针源码（验证用；编译产物不入库）
  verify-fixed.ps1        注入侧全链路验收脚本
  verify-no-steal.ps1     验证监控时端口不被占用
  verify-dual-arch.ps1    双架构产物校验
  build-all.ps1           一键构建全部注入侧产物并校验架构

driver/                   内核驱动（C）
  umserialfilter/         驱动源码
  build-driver.ps1        多架构/多 OS 下限构建
  rebuild-all.ps1         清理→编译→签名→安装→启动
  install-driver.ps1      安装/卸载（签名材料不入库，见 ../SECURITY.md）
  verify-driver.ps1       驱动验证

investigation.cany/       逆向证据账本（逐条证据与 sha256）
docs/                     本文档目录
```
