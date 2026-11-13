# 驱动编译环境（WDK）

本项目的内核过滤驱动用 **NuGet 包 + 独立编译脚本** 的方式构建，不依赖完整安装
WDK MSI，也不要求 Visual Studio 的 WDK 集成。

本文说明这样做的原因、如何组织这套环境，以及另有哪条路线可供参考。

---

## 一、为什么选 NuGet 路线

WDK 官方安装器（`wdksetup.exe`、`winget install Microsoft.Windows.WDK.*`）会并发下载
约二十个 payload，任意一个网络抖动就会导致整体失败并回滚——在国内网络环境下这个
失败率相当高，且失败后很难定位是哪一个包的问题。

NuGet 包则是一个单独的 `.nupkg` 文件直连下载，可以断点续传、可以校验大小，
解压即得头文件与库。本项目采用这条路线。

| 路线 | 特点 | 适用 |
|---|---|---|
| **NuGet 包（本项目采用）** | 单文件下载、解压即用、无需 MSI | 只想编译驱动，不装完整 WDK |
| WDK MSI / winget | 官方标准、含 WDK 集成工具与调试器 | 需要完整开发环境（WinDbg、驱动模板等） |
| Visual Studio + WDK 扩展 | IDE 集成、图形化构建 | 长期做驱动开发、需要调试集成 |

后两条路线本项目**没有实践**，仅在此列出供参考。若你已经在 VS 中配置好 WDK，
可以直接用 MSBuild 编译 `driver/umserialfilter/umserialfilter.vcxproj`（如有）
或自行调用 `cl.exe`，不必使用下文的脚本。

---

## 二、组织编译环境

### 1. 下载两个 NuGet 包

需要的包（版本可自选，本项目使用 `10.0.26100.0`）：

- `Microsoft.Windows.WDK.x64`（或 `.arm64`）— 内核头文件与库
- `Microsoft.Windows.SDK.CPP` — 用户态 CRT 与共享头文件

从 [nuget.org](https://www.nuget.org/) 下载，或使用命令行：

```powershell
# 以任意目录为工作区
$dir = 'C:\wdk-nuget'
New-Item -ItemType Directory -Force $dir | Out-Null
cd $dir

Invoke-WebRequest -Uri 'https://www.nuget.org/api/v2/package/Microsoft.Windows.WDK.x64/10.0.26100.0' -OutFile 'wdk.nupkg'
Invoke-WebRequest -Uri 'https://www.nuget.org/api/v2/package/Microsoft.Windows.SDK.CPP/10.0.26100.0' -OutFile 'sdk.nupkg'
```

> `.nupkg` 就是 zip。把扩展名改成 `.zip` 解压，或用 `Expand-Archive`。

### 2. 解压到约定目录

```powershell
Expand-Archive wdk.nupkg -DestinationPath extracted
Expand-Archive sdk.nupkg -DestinationPath sdk-extracted
```

解压后的结构大致为：

```
extracted\
  c\Include\10.0.26100.0\km\        ntddk.h, wdm.h, ntstrsafe.h ...
  c\Include\10.0.26100.0\shared\    ntdef.h, ntddser.h ...
  c\Lib\10.0.26100.0\km\x64\        ntoskrnl.lib, hal.lib, wdmsec.lib ...
sdk-extracted\
  c\ucrt\  c\um\  c\shared\         CRT 与用户态头文件
```

### 3. 告诉构建脚本去哪里找

`driver/build-driver.ps1` 按以下顺序解析路径，**第一个命中者生效**：

| 顺序 | 位置 | 说明 |
|---|---|---|
| 1 | `-WdkRoot <path> -SdkRoot <path>` | 命令行参数，最明确 |
| 2 | 环境变量 `WDK_ROOT` / `WDK_SDK_ROOT` | 适合固定在机器上 |
| 3 | `<仓库>\.wdk\extracted` / `<仓库>\.wdk\sdk-extracted` | 随仓库放置，便于多人协作 |
| 4 | `E:\tools\wdk-nuget\...` | 早期本地布局，仅为兼容保留 |

推荐用环境变量，一次配置长期有效：

```powershell
setx WDK_ROOT     "C:\wdk-nuget\extracted"
setx WDK_SDK_ROOT "C:\wdk-nuget\sdk-extracted"
# 新开的终端才生效
```

### 4. 还需要 Visual Studio C++ 工具链

脚本通过 `vswhere.exe` 定位已安装的 VS，调用对应的 `vcvars64.bat` / `vcvars32.bat`
来获得 `cl.exe` 与链接器。只需安装 **“使用 C++ 的桌面开发”** 工作负载，
不需要 WDK 扩展。

---

## 三、编译

```powershell
cd MonitorAnything\driver

# x64 + x86，Windows 7 作为 API 下限
powershell -ExecutionPolicy Bypass -File build-driver.ps1

# 只编 x64
powershell -ExecutionPolicy Bypass -File build-driver.ps1 -Arch x64

# 以 Windows 10 为下限（可用更新的 API，但无法在 Win7 上加载）
powershell -ExecutionPolicy Bypass -File build-driver.ps1 -Os win10
```

产物：`driver/umserialfilter/umserialfilter.sys`（或 `_x64.sys`）。

### 关于操作系统下限

`NTDDI_VERSION` / `WIN32_WINNT` 决定头文件暴露哪些 API。本项目默认以 Windows 7 SP1
为下限，这样同一个二进制在 Win7 到 Win11 上都能加载。如果你只面向 Win10+，
用 `-Os win10` 可以选择更新实现细节。

### 关于 x86 内核库

NuGet 的 WDK 包**只包含 x64 内核库**，没有 x86 的 `ntoskrnl.lib`。脚本检测到缺失时
会明确提示并跳过 x86，不会产出坏文件。若确实需要 32 位驱动，请改用完整 WDK MSI。

> 32 位**用户态**产物（钩子与注入器）不受此限制，用 `app/build-all.ps1`
> 交叉编译即可，与驱动无关。

---

## 四、装好之后

编译只是第一步。驱动还需要签名与安装才能加载，且需要测试签名环境
（关闭安全启动、开启测试模式）。完整流程见
[安装与签名指南.md](安装与签名指南.md)。
