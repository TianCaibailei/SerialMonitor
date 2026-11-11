# GUI 测试指南 + 串口参数过滤方案

> 2026-11-11 · 驱动已验证捕获成功

---

## 第一部分：GUI 测试步骤

### 前提确认

驱动已在运行，且 `--driver-test` 已实测通过：

```
driver-test: 已连接驱动
driver-test: 附加到 4 个串口设备
driver-test:   [0] \Device\VSerial8_0
driver-test:   [1] \Device\VSerial8_1
driver-test:   [2] \Device\VSerial8_2
driver-test:   [3] \Device\VSerial8_3
```

GUI 的驱动链路（认证 + 附加 + 读取）与命令行工具走**完全相同的代码**，所以 GUI 一定能连上。

### 步骤

#### 1. 重新加载驱动（因为刚修了重复附加的 bug）

**管理员 PowerShell**：

```powershell
cd E:\Documents\MonitorAnything\MonitorAnything\driver
powershell -ExecutionPolicy Bypass -File rebuild-all.ps1
```

> 这一次会看到「已同步为 umserialfilter.sys」，因为 rebuild-all 会先停驱动。

#### 2. 启动 GUI

```powershell
E:\Documents\MonitorAnything\MonitorAnything\app\target\release\universal_monitor.exe
```

#### 3. 启用驱动捕获

菜单路径：**监控 → 启用驱动捕获(推荐)**

启用后状态栏右下角应显示：

```
驱动：捕获中（4 个端口）        ← 绿色
```

#### 4. 验证数据

用串口助手或任何工具打开 **COM6**，发送数据。

GUI 表格中应自动出现记录，**不需要附加任何进程**。

每个端口会自动创建一个通道：
```
COM6 (VSerial8_2)
COM7 (VSerial8_3)
```

#### 5. 其他可用功能

| 功能 | 位置 |
|---|---|
| 驱动捕获设置 | 监控 → 驱动捕获设置… |
| PID 过滤 | 设置对话框里填 PID（0 = 全部） |
| 重新扫描端口 | 设置对话框 → 重新扫描端口 |
| 停止捕获 | 监控 → 停止驱动捕获 |

---

## 第二部分：本次修复的重复捕获 Bug

### 现象

测试时发现，**一次 7 字节的发送被记录成多条**，且 `port` 编号在 2/6/10/14/18/22 之间跳动：

```
[TX] pid=30908 port=2  7 字节: HELLO2;
[TX] pid=30908 port=6  7 字节: HELLO2;
[TX] pid=30908 port=10 7 字节: HELLO2;
...
```

### 原因

`IoGetDeviceObjectPointer` 返回的是**设备栈顶**。

```
第 1 次扫描：
  VSerial8_2 (栈顶 = 物理设备)
  → 挂接 filter1，记录 physical = VSerial8_2

第 2 次扫描：
  filter1 (栈顶，因为我们已经挂上去了)
  → 与记录的 VSerial8_2 比较，不相等
  → 又挂接 filter2

第 3 次扫描：
  filter2 (栈顶)
  → 再挂 filter3 ...
```

**每调用一次 `ATTACH_PORTS` 就多叠一层**，每个字节被捕获 N 次。

### 修复

```c
// 1. 检测栈顶是否已是自己的过滤器
if (UmIsOwnFilterDevice(devObj)) {
    ObDereferenceObject(devObj);
    continue;
}

// 2. 记录/比较"栈底"设备，保证多次扫描能认出来
PDEVICE_OBJECT physical = UmLowestDevice(devObj);
if (!UmAlreadyAttached(physical)) {
    UmRegisterAttached(physical, nameCopy);
    UmAttachOne(devObj, idx, nameCopy);
}
```

`UmLowestDevice()` 沿着 `AttachedDevice` 链一路向下，找到物理设备。
这样无论栈上已经叠了几层，比较的都是同一个对象。

---

## 第三部分：串口参数过滤（下一步）

### 参考驱动的做法（已逆向确认）

参考驱动在 `sub_12044` 里对 **13 个串口控制 IOCTL** 特殊处理：

```
0x1b0020  0x1b0040  0x1b0050  0x1b0054  0x1b0058
0x1b0060  0x1b0068  0x1b006c  0x1b0074  0x1b0078
0x1b0080  0x1b0084  0x1b008c
```

设备类型 `0x1b` = `FILE_DEVICE_SERIAL_PORT`。

对应的 `IOCTL_SERIAL_*` 常量：

| IOCTL | 值 | 作用 |
|---|---|---|
| `IOCTL_SERIAL_SET_BAUD_RATE` | 0x1B0004 | 设置波特率 |
| `IOCTL_SERIAL_GET_BAUD_RATE` | 0x1B0050 | 查询波特率 |
| `IOCTL_SERIAL_SET_LINE_CONTROL` | 0x1B000C | 设置数据位/停止位/校验 |
| `IOCTL_SERIAL_GET_LINE_CONTROL` | 0x1B0054 | 查询线路控制 |
| `IOCTL_SERIAL_SET_TIMEOUTS` | 0x1B001C | 设置超时 |
| `IOCTL_SERIAL_SET_HANDFLOW` | 0x1B0044 | 设置流控 |
| `IOCTL_SERIAL_GET_HANDFLOW` | 0x1B0060 | 查询流控 |
| `IOCTL_SERIAL_SET_QUEUE_SIZE` | 0x1B0008 | 设置队列大小 |
| `IOCTL_SERIAL_SET_DTR` | 0x1B0024 | 设置 DTR |
| `IOCTL_SERIAL_CLR_DTR` | 0x1B0028 | 清除 DTR |
| `IOCTL_SERIAL_SET_RTS` | 0x1B002C | 设置 RTS |
| `IOCTL_SERIAL_CLR_RTS` | 0x1B0030 | 清除 RTS |
| `IOCTL_SERIAL_PURGE` | 0x1B004C | 清空缓冲 |

### 实现方案

#### 数据结构

```c
// 新增记录类型：串口参数变更
#define UM_DIR_CTRL 2       // 第三类记录（区别于 RX=0 / TX=1）

typedef struct _UM_CTRL_INFO {
    ULONG IoctlCode;        // IOCTL 编码
    ULONG BaudRate;         // 波特率（SET_BAUD_RATE 时有效）
    UCHAR DataBits;         // 数据位 5-8
    UCHAR StopBits;         // 0=1位, 1=1.5位, 2=2位
    UCHAR Parity;           // 0=无, 1=奇, 2=偶, 3=标记, 4=空格
    ULONG HandFlow;         // 流控
} UM_CTRL_INFO;
```

#### 分发函数改造

```c
if (stack->MajorFunction == IRP_MJ_DEVICE_CONTROL) {
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    if (IsSerialControlIoctl(code)) {
        // 在挂接完成例程，请求完成后读取参数
        install completion routine;
    }
}
```

#### 完成例程

```c
static NTSTATUS UmCtrlComplete(PDEVICE_OBJECT DevObj, PIRP Irp, PVOID Context)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;

    if (NT_SUCCESS(Irp->IoStatus.Status)) {
        UM_CTRL_INFO info = {0};
        info.IoctlCode = code;

        switch (code) {
        case IOCTL_SERIAL_SET_BAUD_RATE:
        case IOCTL_SERIAL_GET_BAUD_RATE: {
            // 输入/输出缓冲是 SERIAL_BAUD_RATE 结构
            PSERIAL_BAUD_RATE br = Irp->AssociatedIrp.SystemBuffer;
            if (br) info.BaudRate = br->BaudRate;
            break;
        }
        case IOCTL_SERIAL_SET_LINE_CONTROL:
        case IOCTL_SERIAL_GET_LINE_CONTROL: {
            // SERIAL_LINE_CONTROL { UCHAR StopBits, Parity, WordLength; }
            PSERIAL_LINE_CONTROL lc = Irp->AssociatedIrp.SystemBuffer;
            if (lc) {
                info.DataBits = lc->WordLength;
                info.StopBits = lc->StopBits;
                info.Parity   = lc->Parity;
            }
            break;
        }
        }
        UmQueueControlRecord(&info, pid);
    }
    ...
}
```

#### 关键结构体（来自 `ntddser.h`）

```c
typedef struct _SERIAL_BAUD_RATE {
    ULONG BaudRate;
} SERIAL_BAUD_RATE;

typedef struct _SERIAL_LINE_CONTROL {
    UCHAR StopBits;     // STOP_BIT_1=0, STOP_BITS_1_5=1, STOP_BITS_2=2
    UCHAR Parity;       // NO_PARITY=0, ODD=1, EVEN=2, MARK=3, SPACE=4
    UCHAR WordLength;   // 5..8
} SERIAL_LINE_CONTROL;

typedef struct _SERIAL_TIMEOUTS {
    ULONG ReadIntervalTimeout;
    ULONG ReadTotalTimeoutMultiplier;
    ULONG ReadTotalTimeoutConstant;
    ULONG WriteTotalTimeoutMultiplier;
    ULONG WriteTotalTimeoutConstant;
} SERIAL_TIMEOUTS;
```

#### GUI 侧

在表格里用第三种行类型显示：

```
时间      通道   方向   功能           数据
15:23:01  COM6   控制   设置波特率     9600
15:23:02  COM6   控制   设置线路参数   8N1
15:23:05  COM6   控制   设置流控       RTS/CTS
```

---

## 第四部分：待办清单

| 项 | 状态 |
|---|---|
| 驱动基础捕获 | ✅ 已验证 |
| GUI 驱动捕获 | ✅ 待你测试 |
| 重复附加 bug | ✅ 已修复（20,992 字节） |
| 串口参数过滤 | 📋 方案已就绪，待实现 |
| x86 驱动 | ⏸ 需完整 WDK MSI |

---

## 第五部分：开始实现串口参数过滤前需要你确认

1. **参数变更是否需要影响数据流？** 建议只做**显示**（旁路记录），不改写任何值 —— 这才符合"被动监控"的设计。

2. **是否需要记录参数的"设置尝试"还是"设置成功"？** 建议记录**成功后的实际值**（完成例程里读 `IoStatus`），这样能看出程序真正用了什么参数。

3. **GUI 展示方式**：单独一个"控制"行，还是合并到现有表格里作为特殊行？

确认后我就开始实现。
