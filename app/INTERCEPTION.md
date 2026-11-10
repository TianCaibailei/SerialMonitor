# 串口拦截实现说明（本次修复）

> 2026-11-10 · 对应 commit `06ee765` / `627c995`

## 一、为什么必须"不占用串口"

参考软件 CommMonitor 的驱动 `ComDrv12x64.sys` 经逆向确认是**设备过滤驱动**：

| 证据（来自逆向） | 含义 |
|---|---|
| `IoGetDeviceObjectPointer` + `IoAttachDeviceToDeviceStack` + `IoDetachDevice` | 挂到串口设备栈上做上层过滤 |
| `IoBuildAsynchronousFsdRequest` + `IofCallDriver` + `IofCompleteRequest` | 主动构造并转发 FSD 请求（旁路读取） |
| `ObOpenObjectByPointer` / `ObReferenceObjectByHandle` / `PsGetCurrentProcessId` | 按句柄/进程识别数据来源 |
| `IoCreateSymbolicLink` + `RtlSetDaclSecurityDescriptor` | 暴露控制设备 `\\.\ComDrv12x` 并设置访问权限 |

**关键结论：驱动从不在 IRP 路径上"打开"串口，它只是镜像 IRP。** 所以原软件监控时，业务程序仍然完整独占串口——这正是它的核心价值，也是我们之前实现丢失的东西。

## 二、当前实现（用户态替代方案）

`monitor_hook.dll` 注入到被监控进程，patch 该进程的 kernel32 IAT：

| 被 hook 的 API | 用途 |
|---|---|
| `CreateFileW` / `CreateFileA` | 识别串口打开，建立 handle → COM 映射 |
| `ReadFile` / `WriteFile` | 同步与 overlapped I/O 捕获 |
| `GetOverlappedResult(Ex)` | overlapped 读完成时取数据 |
| `ReadFileEx` / `WriteFileEx` | 完成例程式异步 I/O（Qt 等库使用） |
| `CloseHandle` | 句柄关闭清理 |
| `GetProcAddress` | 让 .NET P/Invoke 等晚期绑定也命中钩子 |

数据经命名管道 `\\.\pipe\monitor_capture` 送到监控端，再由 `route_hook_data()` 路由进会话。

### 开发中踩到并修复的真实缺陷

| 缺陷 | 后果 | 修复 |
|---|---|---|
| 记录用被 patch 的 `WriteFile` 写管道 | **自递归死锁**，被监控进程卡死 | 用启动时保存的原始函数指针 |
| 诊断日志用 `std::fs` | 同样重入 hook 死锁 | 走原始指针写文件 |
| 串口路径只认 `serial`/`vcp` | **USB 转串口全部漏抓** | 扩展 16 种设备名（USBSER/Prolific/Silabs/FTDI/CDC/BthModem…） |
| 缺少 `ReadFileEx`/`WriteFileEx` | Qt 等异步串口库漏抓 | 补齐钩子，转发用户完成例程 |
| 非串口句柄每次读写都查系统调用 | 被监控程序日志 I/O 变慢 | 负缓存，一次判定终身有效 |
| `Mutex` poison 导致 panic | 带崩被监控进程 | 全部锁改为 poison 容错 |

## 三、验证结果

| 测试 | 命令 | 结果 |
|---|---|---|
| 双向捕获 | `universal_monitor.exe --inject-comtest COM6 COM7` | PASS `tx=7 rx=7` |
| **端口不被抢占** | `powershell -File verify-no-steal.ps1` | **PASS**：注入前/后第三方均无法打开 COM6，业务程序通信完整 |
| 全链路路由 | `universal_monitor.exe --hook-e2e COM6 COM7` | PASS：会话 2 行，TX 8 字节，RX 13 字节 |

## 四、驱动方案（第二条腿，待环境就绪）

### 4.1 环境现状

| 项目 | 状态 | 影响 |
|---|---|---|
| WDK | **未安装**（只有 Windows SDK） | 无法编译 `.sys` |
| 测试签名 | **未开启** | 未签名驱动无法加载 |
| 管理员权限 | **否** | 无法 `sc create` 装载驱动 |
| UEFI 固件 | 是 | 需 `bcdedit /set testsigning on` 并重启 |

### 4.2 驱动版设计（对应原驱动行为）

```c
// 上层设备过滤驱动：附着到每个串口设备栈
NTSTATUS DriverEntry(...) {
    // 1. 枚举 \Device\Serial0..N 与 USB 串口设备
    // 2. IoGetDeviceObjectPointer 取目标设备
    // 3. IoCreateDevice 创建设备对象，IoAttachDeviceToDeviceStack 挂载
    // 4. 设置 IRP_MJ_READ / IRP_MJ_WRITE 的 completion routine
}

NTSTATUS ReadCompletion(PDEVICE_OBJECT dev, PIRP irp, PVOID ctx) {
    // 复制 Irp->AssociatedIrp.SystemBuffer 中的实际字节
    // 通过 IoCreateNotificationEvent 或反向设备 IOCTL 送给用户态
    // 绝不修改 Irp->IoStatus —— 保持业务程序看到的数据不变
}
```

**核心原则**：completion routine 里只读不写，永远不改变 `IoStatus`/`Information`。

### 4.3 启用步骤（需要你做）

1. 安装 WDK（`winget install Microsoft.WindowsWDK.10.0.26100` 或官网下载）
2. 开启测试签名（管理员 PowerShell）：
   ```powershell
   bcdedit /set testsigning on
   ```
3. 重启系统
4. 用管理员权限加载驱动（`sc create` + `sc start`）

### 4.4 驱动方案 vs 用户态方案

| 维度 | 内核过滤驱动（原生方案） | 用户态注入（当前方案） |
|---|---|---|
| 串口占用 | 完全不占用 | 完全不占用 |
| 覆盖范围 | 全系统所有进程 | 仅被注入的进程 |
| 需附加操作 | 安装一次即可 | 每次要对目标程序注入 |
| 权限要求 | 管理员 + 驱动签名 | 无（同权限即可） |
| 稳定性风险 | 驱动 bug = 蓝屏 | DLL bug = 目标进程崩溃 |
| 开发门槛 | 高（WDK/C/签名） | 中（Rust） |

**建议**：用户态方案作为默认（零门槛、即开即用），驱动方案作为"全系统覆盖"的进阶选项。
