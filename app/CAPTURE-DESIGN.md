# 串口被动监控：实现原理、约束与验证

> 最后更新：2026-11-10 · 对应提交 `verify-capture.ps1` PASS

## 一、核心原理

参考软件 CommMonitor 用内核过滤驱动（`ComDrv12x64.sys`）实现，逆向确认其行为：

| 证据 | 含义 |
|---|---|
| `IoGetDeviceObjectPointer` + `IoAttachDeviceToDeviceStack` | 附着到串口设备栈，做上层过滤 |
| `IoBuildAsynchronousFsdRequest` + `IofCallDriver` | 构造并转发 FSD 请求（旁路镜像） |
| `ObReferenceObjectByHandle` + `PsGetCurrentProcessId` | 按句柄/进程识别数据来源 |

**关键点：驱动从不打开串口，只镜像 IRP。** 所以业务程序始终独占端口。

本项目的用户态替代方案：向目标进程注入 `monitor_hook.dll`，patch 其 IAT，
在保留原调用语义的前提下复制一份数据出来。

## 二、已验证的功能

| 能力 | 验证方式 | 结果 |
|---|---|---|
| 64 位进程注入 | `verify-dual-arch.ps1` | PASS |
| **32 位进程注入** | `verify-dual-arch.ps1` | PASS |
| 被动串口捕获（不占用端口） | `verify-capture.ps1` | PASS（rows=4 tx=15 rx=12） |
| 端口不被抢占 | `verify-no-steal.ps1` | PASS |

## 三、**最重要的约束：注入必须先于端口打开**

这是用户态 IAT hook 的固有性质，不是 bug：

```
程序启动 → 解析 API → 打开串口 → 开始读写
                ↑
         hook 必须在此之前完成
```

**为什么**：`.NET SerialPort` 和多数 C/C++ 串口库会在打开端口时把
`CreateFileW`/`ReadFile`/`WriteFile` 的函数地址缓存到自己的表里。之后
它们直接调用缓存的地址，绕过 IAT；此时再注入就看不到了。

**实测证据**（同一台机器、同一个 hook）：
- 先注入、后打开端口 → `cfw: \\.\COM6` 被捕获，rows=4 ✓
- 先打开端口、后注入 → 无任何记录 ✗（连 `com_label` 都不触发）

### 正确的使用顺序

1. 打开监控，新建「串口监听(不占用)」会话，选中目标串口
2. **先**在「附加到进程」中选中你的串口工具（可提前启动它但不让它打开端口）
3. 再让工具打开串口

或者：把工具关掉 → 附加 → 重新打开工具 → 打开串口。

自动附加会尽力在新进程启动后 120ms 内注入，但**不能保证**赶在端口打开之前，
因为程序打开串口可能只需要几十毫秒。

## 四、双架构注入

| 目标 | 使用的 DLL | 注入方式 |
|---|---|---|
| 64 位进程 | `monitor_hook.dll` (x64) | 内联 `CreateRemoteThread(LoadLibraryW)` |
| 32 位 (WOW64) | `monitor_hook_x86.dll` (x86) | 调用 `universal_injector_x86.exe` 助手 |

**为什么 32 位要独立进程**：64 位进程向 WOW64 目标调用
`CreateRemoteThread(LoadLibraryW)` 时，即使地址和路径都正确，`LoadLibrary`
仍返回 -1。让注入器本身是 32 位进程，所有地址天然有效。

## 五、构建

```powershell
# 一键构建并校验架构
powershell -File build-all.ps1
```

输出：
```
monitor_hook.dll          x64
monitor_hook_x86.dll      x86
universal_injector_x86.exe x86
universal_monitor.exe     x64
```

**注意**：`cargo build --release`（不带 `--target`）会用 64 位重新编译
`universal_injector_x86.exe` 并覆盖部署好的 32 位版本。必须用 `build-all.ps1`。

## 六、诊断命令

| 命令 | 用途 |
|---|---|
| `--list-procs` | 列出可注入进程（验证进程枚举） |
| `--inject-test <pid>` | 注入指定进程并验证模块是否加载 |
| `--holders COM6` | 探测串口候选进程 |
| `--native-serial-delayed COM6 9000 <marker>` | 等待标记后再打开串口，用于构造确定性时序 |
| `--headless-watch COM6 --result out.json` | 无界面运行监控，输出捕获统计 |

## 七、何时需要 B 方案（内核驱动）

若以下任一场景必须支持，则用户态方案无法满足，需要内核驱动：

1. **程序启动即打开串口**，来不及注入
2. **需要监控所有进程**（不想逐个附加）
3. **程序有反注入保护**
4. **需要捕获驱动层的 IOCTL**（如波特率切换等）

驱动方案需要：WDK 编译环境 + 测试签名（`bcdedit /set testsigning on` + 重启）
+ 管理员权限加载驱动。
