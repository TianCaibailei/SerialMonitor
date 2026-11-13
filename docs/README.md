# 文档索引

| 文档 | 内容 | 什么时候读 |
|---|---|---|
| **[技术手册.md](技术手册.md)** | 两条抓取路径的实现细节、显示编码机制、暂停语义、会话存档格式、关键参数、验收方法 | 想了解内部实现、或需要排障时 |
| [WDK-NUGET-GUIDE.md](WDK-NUGET-GUIDE.md) | 用 NuGet 组织驱动编译环境；另附未实践路线的参考 | 要编译内核驱动时 |
| [安装与签名指南.md](安装与签名指南.md) | 关闭安全启动、开启测试模式、生成证书与签名、安装与卸载 | 要安装内核驱动时 |

用户使用说明见仓库根的 [README.md](../README.md)。

---

## 代码结构

```
app/                      主程序（Rust + egui）
  src/                    界面、会话、解码、注入器、驱动客户端
    text_codec.rs         字节 → 文本的唯一解码入口（UTF-8/GBK/UTF-16LE）
    protocol.rs           Modbus 解析 + 组帧（组帧供单元测试使用）
    session.rs            会话、过滤、速率、存档（.umses）
  hook/                   注入的钩子 DLL（独立 crate，x64 + x86 双编译）
  x86_injector/           32 位注入器（独立 crate，防止被主构建覆盖）
  assets/                 编译期嵌入的资源（关于窗口的二维码）
  tests/                  诊断探针与界面测试
  verify-fixed.ps1        注入侧全链路验收脚本
  verify-no-steal.ps1     验证监控时端口不被占用
  verify-dual-arch.ps1    双架构产物校验
  build-all.ps1           一键构建全部注入侧产物并校验架构
  check-all.ps1           本地一键门禁（与 CI 同一套断言）

driver/                   内核过滤驱动（C）
  umserialfilter/         驱动源码
  build-driver.ps1        多架构 / 多 OS 下限构建（自动发现 WDK 路径）
  rebuild-all.ps1         清理 → 编译 → 签名 → 安装 → 启动
  install-driver.ps1      安装 / 卸载 / 状态查询
  verify-driver.ps1       驱动验证
  emergency-remove-driver.ps1  卸载不彻底时的强制清理

.github/workflows/ci.yml  CI 门禁（格式 / lint / 测试 / 架构 / 文档 / 密钥守卫）
```

## 开发约定

- 提交前跑 `app\check-all.ps1`，它执行与 CI 完全相同的五项检查。
- 修改协议解析时补充单元测试：`cargo test --bin universal_monitor`。
- 签名材料、编译产物、会话存档不入库，规则见 `.gitignore`。
