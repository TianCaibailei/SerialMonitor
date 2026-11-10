# WDK NuGet 方式安装与驱动开发指南

> 本机已验证：驱动编译成功（`probe.sys`，x64 NATIVE）· 2026-11-10

## 一、为什么用 NuGet 而不是官方安装器

| 方式 | 实测结果 |
|---|---|
| `wdksetup.exe` 静默安装 | ❌ 反复卡死/退出码 -1（下载器链路抖动即放弃） |
| `winget install Microsoft.Windows.WDK.10.0.26100` | ❌ 同样失败（底层还是 wdksetup） |
| **NuGet 包** | ✅ **105.7 MB / 4 秒下载，编译成功** |

原因：WDK 安装器并发下载 ~20 个 payload，任一个卡住就整体失败；
而 NuGet 是单文件直连，速度可达 **20-25 MB/s**。

---

## 二、方案 A：完全不用 VS 集成（已在本机跑通，最快）

我已把两个 NuGet 包下载并解压到 E 盘：

```
E:\tools\wdk-nuget\extracted\        ← WDK (105.7 MB)
    c\Include\10.0.26100.0\km\       ntddk.h, wdm.h, ntstrsafe.h...
    c\Include\10.0.26100.0\shared\   ntdef.h, ntddser.h(部分)...
    c\Lib\10.0.26100.0\km\x64\       ntoskrnl.lib, hal.lib, wmilib.lib, sercx\...
E:\tools\wdk-nuget\sdk-extracted\    ← SDK C++ (49.8 MB)
    c\ucrt\, c\um\, c\shared\        CRT 与用户态头文件
```

**直接用这个脚本编译驱动**：

```powershell
cd E:\Documents\MonitorAnything\MonitorAnything\driver
powershell -File build-driver.ps1 -Source probe\probe.c
```

已验证输出：
```
PASS: 驱动编译成功 probe.sys (5,120 字节)
PE 机器 = 0x8664 (x64)   子系统 = 1 (NATIVE)
```

**不需要装 WDK MSI，也不需要 VS 驱动工作负载。**

---

## 三、方案 B：用 VS 2022 + NuGet（你提到的方式）

按微软文档，这个流程需要 **VS 2026**。你的是 **VS 2022 (17.14)**，
26100 的 NuGet 包在 VS 2022 上**未经官方验证**，但可以尝试：

### 步骤

1. **安装 VS 工作负载**（VS Installer → 修改）
   - 勾选 **"使用 C++ 的桌面开发"**
   - 在"单个组件"中搜索并勾选（搜索框输入 `64 latest` 快速定位）：
     - `C++ Spectre-mitigated libraries for x64/x86 (Latest MSVC)`
     - `C++ ATL with Spectre mitigations for x64/x86 (Latest MSVC)`
   - 也可勾选 **"Windows 驱动程序开发"** 工作负载（如果可见）

2. **创建驱动项目**
   - VS → 新建项目 → 搜索 `Kernel Mode Driver (KMDF)`
   - 如果没有该模板，说明 WDK MSI 未安装，模板不可用 → **建议直接用方案 A**

3. **添加 NuGet 包**
   - 右键解决方案 → **管理 NuGet 程序包**
   - 包源选 `nuget.org`
   - 搜索 `WDK`，安装 **`Microsoft.Windows.WDK.x64`** 版本 `10.0.26100.6584`
   - 它会自动带上依赖 `Microsoft.Windows.SDK.cpp.x64`

4. **编译**
   - 重新生成解决方案，输出 `.sys`

### 注意事项

- **NuGet 方式不提供 VS 项目模板**，需要 `WDK MSI` 才有 `Kernel Mode Driver (KMDF)` 模板
- 若模板缺失，可以手工建 C++ 空项目 + 添加 NuGet 包 + 手动设置编译选项
  （编译选项见下节）
- `dotnet` 命令行方式不适用于 WDK

---

## 四、已调通的编译参数（可直接复用）

### 编译（cl.exe）

```
/nologo /c /kernel /GS- /Gz /Zp8 /W4 /WX-
/D_WIN64 /D_AMD64_ /D_M_AMD64=100
/DNTDDI_VERSION=0x0A00000C /D_WIN32_WINNT=0x0A00
/I <wdk>\c\Include\10.0.26100.0\km
/I <wdk>\c\Include\10.0.26100.0\shared
/I <sdk>\c\ucrt /I <sdk>\c\um /I <sdk>\c\shared
```

**关键点**：
- `_AMD64_` 和 `_M_AMD64=100` **必须定义**，否则 `ntdef.h` 报
  `#error "No Target Architecture"`
- `/kernel` 选择内核代码生成；`/GS-` 禁用栈保护（内核无 CRT）

### 链接（link.exe）

```
/nologo /DRIVER /SUBSYSTEM:NATIVE /ENTRY:GsDriverEntry /MACHINE:X64
/OUT:xxx.sys
/LIBPATH:<wdk>\c\Lib\10.0.26100.0\km\x64
ntoskrnl.lib hal.lib wmilib.lib BufferOverflowK.lib ntstrsafe.lib
```

`GsDriverEntry` 由 `BufferOverflowK.lib` 提供，它会调用你的 `DriverEntry`。

---

## 五、驱动加载（下一步，需要你操作）

编译出 `.sys` 只是第一步。**加载驱动需要**：

1. **开启测试签名**（管理员 PowerShell）
   ```powershell
   bcdedit /set testsigning on
   ```
   **然后重启电脑**

2. **创建服务并启动**（管理员 PowerShell）
   ```powershell
   sc create UmSerialFilter type= kernel binPath= "E:\...\driver.sys"
   sc start UmSerialFilter
   ```

3. 验证
   ```powershell
   sc query UmSerialFilter
   ```

> ⚠️ 未签名的驱动无法在默认配置的 Windows 11 上加载（会报
> `577 签名验证失败`）。测试签名模式是开发阶段的唯一选择。

---

## 六、当前进度与建议

| 项目 | 状态 |
|---|---|
| WDK 头文件/库 | ✅ 已就绪（NuGet，E 盘） |
| 驱动编译工具链 | ✅ 已验证（probe.sys 编译成功） |
| 串口过滤驱动本体 | ⏳ 待开发 |
| 测试签名 | ❌ 未开启（需你操作 + 重启） |
| 驱动加载 | ❌ 待测试签名后 |

**建议顺序**：
1. 你先决定：**开测试签名**（需重启）还是**继续用用户态方案**
2. 若开测试签名，我可以立即开发串口过滤驱动并用 `sc create` 加载测试
3. 若暂不开，当前用户态方案已可用（先附加再打开串口）
