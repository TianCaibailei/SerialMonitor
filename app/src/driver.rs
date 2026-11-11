// User-mode client for the UmSerialFilter kernel driver.
//
// The driver exposes one control device (\\.\UmSerialFilter) with a small IOCTL set:
//   IOCTL_UM_ATTACH_PORTS  — attach the filter to every serial device
//   IOCTL_UM_GET_PORT_NAME — friendly (NT) name of one attached device
//   IOCTL_UM_SET_TARGET    — enable capture, optionally limited to one PID
//   IOCTL_UM_GET_RECORD    — pop one captured chunk (blocks until one is queued)
//   IOCTL_UM_GET_STATS     — counters
//
// The monitor polls this interface from a background thread and turns each record into
// the same ChannelCfg/Session rows the user-mode hook produces, so the UI needs no
// driver-specific code path.
use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, Ordering};

extern "system" {
    fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        sa: *mut c_void,
        disp: u32,
        flags: u32,
        tmpl: *mut c_void,
    ) -> *mut c_void;
    fn DeviceIoControl(
        h: *mut c_void,
        code: u32,
        in_buf: *mut c_void,
        in_len: u32,
        out_buf: *mut c_void,
        out_len: u32,
        returned: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
    fn CloseHandle(h: *mut c_void) -> i32;
    fn GetLastError() -> u32;
}

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const OPEN_EXISTING: u32 = 3;
const INVALID: isize = -1;

const DEVICE_TYPE: u32 = 0x8000;
const FILE_READ_DATA: u32 = 0x0001;
const FILE_WRITE_DATA: u32 = 0x0002;

const fn ctl(func: u32, access: u32) -> u32 {
    (DEVICE_TYPE << 16) | (access << 14) | (func << 2)
}

pub const IOCTL_GET_RECORD: u32 = ctl(0x800, FILE_READ_DATA);
pub const IOCTL_SET_TARGET: u32 = ctl(0x801, FILE_WRITE_DATA);
pub const IOCTL_GET_STATS: u32 = ctl(0x802, FILE_READ_DATA);
pub const IOCTL_ATTACH_PORTS: u32 = ctl(0x803, FILE_WRITE_DATA);
pub const IOCTL_GET_PORT_NAME: u32 = ctl(0x804, FILE_READ_DATA);
// Present the per-boot session key. Must be the first IOCTL on a handle; the driver
// refuses everything else until it succeeds, which is what pairs this client with the
// driver (a process that merely opens the device cannot use it).
pub const IOCTL_AUTHENTICATE: u32 = ctl(0x805, FILE_WRITE_DATA);

pub const RECORD_HEADER: usize = 32;
pub const MAX_PAYLOAD: usize = 4096;
pub const CHANNEL_NAME: &str = "\\\\.\\UmSerialFilter";

// CreateFileW 的错误码。界面需要区分「还没安装」和「被签名策略拦住」，
// 因为两者的解决办法完全不同（前者 sc create，后者 testsigning + 重启）。
pub const ERROR_FILE_NOT_FOUND: u32 = 2;
pub const ERROR_PATH_NOT_FOUND: u32 = 3;
pub const ERROR_ACCESS_DENIED: u32 = 5;
pub const ERROR_INVALID_IMAGE_HASH: u32 = 577;

/// 一次捕获的统计计数（IOCTL_UM_GET_STATS 的 8 个 u32）。
#[derive(Clone, Debug, Default)]
pub struct DriverStats {
    pub records: u32,
    pub dropped: u32,
    pub received: u64,
    pub sent: u64,
    pub enabled: u32,
    pub target_pid: u32,
    pub attached: u32,
    /// Discovery diagnostics: how many candidates were rejected because the device type
    /// was not a serial port, and how many because the name did not match.
    pub rejected_type: u32,
    pub rejected_name: u32,
    pub accepted: u32,
}

impl DriverStats {
    /// 一行摘要，给设置对话框用。
    pub fn summary(&self) -> String {
        format!(
            "{} · 已附加 {} 个端口 · 队列 {} 条 · 丢弃 {} 条 · 收 {} / 发 {} 字节 · 目标 PID {}",
            if self.enabled != 0 { "采集已启用" } else { "采集已停用" },
            self.attached,
            self.records,
            self.dropped,
            self.received,
            self.sent,
            if self.target_pid == 0 {
                "全部".to_string()
            } else {
                self.target_pid.to_string()
            }
        )
    }
}

/// What kind of event a record describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordKind {
    /// Bytes the application read from the port.
    Rx,
    /// Bytes the application wrote to the port.
    Tx,
    /// A serial parameter change (baud rate, line control, handflow, timeouts).
    Control,
}

/// Decoded serial parameter change carried by a RecordKind::Control record.
#[derive(Clone, Copy, Debug, Default)]
pub struct ControlInfo {
    pub ioctl_code: u32,
    pub baud_rate: u32,
    pub hand_flow: u32,
    pub timeouts: [u32; 5],
    pub data_bits: u8,
    pub stop_bits: u8,
    pub parity: u8,
}

impl ControlInfo {
    pub fn summary(&self) -> String {
        const BAUD_SET: u32 = 0x001B_0004;
        const BAUD_GET: u32 = 0x001B_0050;
        const LINE_SET: u32 = 0x001B_000C;
        const LINE_GET: u32 = 0x001B_0054;
        const TO_SET: u32 = 0x001B_001C;
        const TO_GET: u32 = 0x001B_0058;
        const HF_SET: u32 = 0x001B_0044;
        const HF_GET: u32 = 0x001B_0060;

        match self.ioctl_code {
            BAUD_SET => format!("设置波特率 {}", self.baud_rate),
            BAUD_GET => format!("读取波特率 {}", self.baud_rate),
            LINE_SET | LINE_GET => {
                let parity = match self.parity {
                    1 => "O",
                    2 => "E",
                    3 => "M",
                    4 => "S",
                    _ => "N",
                };
                let stop = match self.stop_bits {
                    1 => "1.5",
                    2 => "2",
                    _ => "1",
                };
                format!("{}{}{}", self.data_bits, parity, stop)
            }
            TO_SET | TO_GET => format!(
                "超时 {}/{}/{}/{}/{}",
                self.timeouts[0], self.timeouts[1], self.timeouts[2],
                self.timeouts[3], self.timeouts[4]
            ),
            HF_SET | HF_GET => format!("流控 0x{:X}", self.hand_flow),
            other => format!("串口参数 0x{other:08X}"),
        }
    }
}

/// One record decoded from the driver's wire format.
#[derive(Clone, Debug)]
pub struct Record {
    pub kind: RecordKind,
    pub pid: u32,
    pub port_index: u32,
    pub handle: u64,
    pub timestamp: u64,
    pub data: Vec<u8>,
    /// Populated only for RecordKind::Control.
    pub control: Option<ControlInfo>,
}

impl Record {
    pub fn dir_tx(&self) -> bool {
        self.kind == RecordKind::Tx
    }
}

/// Map NT device paths to the COM numbers users recognise.
///
/// The driver reports `\Device\VSerial8_2`; the user thinks in terms of COM6. Windows
/// publishes the mapping under
/// `HKLM\HARDWARE\DEVICEMAP\SERIALCOMM` (value name = device path, data = `COM6`), so the
/// UI can read it once and label ports the way the user expects. Device paths that are
/// not listed fall back to their own short name.
pub fn com_names() -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();

    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(
            key: *mut c_void,
            sub: *const u16,
            options: u32,
            desired: u32,
            out: *mut *mut c_void,
        ) -> i32;
        fn RegEnumValueW(
            key: *mut c_void,
            index: u32,
            name: *mut u16,
            name_len: *mut u32,
            reserved: *mut u32,
            kind: *mut u32,
            data: *mut u8,
            data_len: *mut u32,
        ) -> i32;
        fn RegCloseKey(key: *mut c_void) -> i32;
    }

    const HKEY_LOCAL_MACHINE: *mut c_void = 0x8000_0002usize as *mut c_void;
    const KEY_READ: u32 = 0x2_0019;

    let sub = wide("HARDWARE\\DEVICEMAP\\SERIALCOMM");
    let mut hkey: *mut c_void = std::ptr::null_mut();
    if unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub.as_ptr(), 0, KEY_READ, &mut hkey) } != 0 {
        return out;
    }

    let mut index = 0u32;
    loop {
        let mut name = vec![0u16; 512];
        let mut name_len = name.len() as u32;
        let mut data = vec![0u8; 256];
        let mut data_len = data.len() as u32;
        let mut kind = 0u32;
        let rc = unsafe {
            RegEnumValueW(
                hkey,
                index,
                name.as_mut_ptr(),
                &mut name_len,
                std::ptr::null_mut(),
                &mut kind,
                data.as_mut_ptr(),
                &mut data_len,
            )
        };
        if rc != 0 {
            break;
        }
        // Value name is the device path, data is a NUL-terminated wide "COMx".
        let path = String::from_utf16_lossy(&name[..name_len as usize]);
        let units: Vec<u16> = data[..data_len as usize]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&u| u != 0)
            .collect();
        if !path.is_empty() && !units.is_empty() {
            out.insert(path, String::from_utf16_lossy(&units));
        }
        index += 1;
        if index > 256 {
            break;
        }
    }
    unsafe { RegCloseKey(hkey) };
    out
}

/// An attached port the driver knows about.
#[derive(Clone, Debug)]
pub struct DriverPort {
    pub index: u32,
    /// NT device path, e.g. "\Device\VSerial8_2".
    pub device: String,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ---------------------------------------------------------------------------
// Session key: read from HKLM\Software\UmSerialFilter\SessionKey
// ---------------------------------------------------------------------------
//
// The driver generates this at load time and publishes it there. HKLM is writable only by
// administrators, so reading it is how our software proves it is allowed to use the
// driver.

const AUTH_NO_KEY: u32 = 0xFFFF_FFFE;

static LAST_AUTH_ERROR: AtomicU32 = AtomicU32::new(0);

/// Why the last authenticate() failed (0 = no failure recorded).
pub fn last_auth_error() -> u32 {
    LAST_AUTH_ERROR.load(Ordering::Relaxed)
}

#[cfg(windows)]
fn read_session_key() -> Option<Vec<u8>> {
    use std::ffi::c_void;

    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(
            key: *mut c_void,
            sub: *const u16,
            options: u32,
            desired: u32,
            out: *mut *mut c_void,
        ) -> i32;
        fn RegQueryValueExW(
            key: *mut c_void,
            value: *const u16,
            reserved: *mut u32,
            kind: *mut u32,
            data: *mut u8,
            len: *mut u32,
        ) -> i32;
        fn RegCloseKey(key: *mut c_void) -> i32;
    }

    // HKEY_LOCAL_MACHINE = 0x80000002
    const HKEY_LOCAL_MACHINE: *mut c_void = 0x8000_0002usize as *mut c_void;
    const KEY_READ: u32 = 0x2_0019;
    const REG_BINARY: u32 = 3;

    let sub = wide("Software\\UmSerialFilter");
    let mut hkey: *mut c_void = std::ptr::null_mut();
    let rc = unsafe {
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub.as_ptr(), 0, KEY_READ, &mut hkey)
    };
    if rc != 0 || hkey.is_null() {
        return None;
    }

    let value = wide("SessionKey");
    let mut kind = 0u32;
    let mut buf = vec![0u8; 64];
    let mut len = buf.len() as u32;
    let rc = unsafe {
        RegQueryValueExW(
            hkey,
            value.as_ptr(),
            std::ptr::null_mut(),
            &mut kind,
            buf.as_mut_ptr(),
            &mut len,
        )
    };
    unsafe { RegCloseKey(hkey) };

    if rc != 0 || kind != REG_BINARY || len == 0 || len > 64 {
        return None;
    }
    buf.truncate(len as usize);
    Some(buf)
}

#[cfg(not(windows))]
fn read_session_key() -> Option<Vec<u8>> {
    None
}

/// 最近一次 CreateFileW 失败的 GetLastError 值。
///
/// 之所以用全局变量而不是改 `open()` 的签名：`open()` 的 `Option<DriverHandle>` 形态
/// 已经被 UI 和 diag 多处使用，为了让它们只关心「能不能用」，错误码单独旁路暴露。
static LAST_OPEN_ERROR: AtomicU32 = AtomicU32::new(0);

/// 上一次 `DriverHandle::open()` 失败时的 Win32 错误码（0 表示没有失败记录）。
pub fn last_error() -> u32 {
    LAST_OPEN_ERROR.load(Ordering::Relaxed)
}

/// Handle to the driver's control device.
pub struct DriverHandle {
    h: *mut c_void,
}

// The handle is only used from the capture thread; sending it across threads is safe
// because the kernel device object serialises IOCTLs internally.
unsafe impl Send for DriverHandle {}

impl DriverHandle {
    /// Open the control device. Returns None when the driver is not loaded.
    ///
    /// FILE_SHARE_READ | FILE_SHARE_WRITE matters: with share=0 the first open owns the
    /// device exclusively, so the capture thread holding the handle made every later
    /// probe from the UI fail with ERROR_SHARING_VIOLATION (32) — the settings dialog
    /// then showed "driver missing" even though it was running, and set_target/rescan
    /// silently did nothing.
    pub fn open() -> Option<Self> {
        let path = wide(CHANNEL_NAME);
        let h = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        if h as isize == INVALID {
            let err = unsafe { GetLastError() };
            LAST_OPEN_ERROR.store(err, Ordering::Relaxed);
            None
        } else {
            LAST_OPEN_ERROR.store(0, Ordering::Relaxed);
            let handle = DriverHandle { h };
            // Complete the handshake immediately: the driver refuses every other IOCTL
            // until it succeeds, so a handle that skipped this would look "open but dead".
            handle.authenticate();
            Some(handle)
        }
    }

    /// Present the per-boot session key to the driver.
    ///
    /// This is what pairs our software with our driver. The key lives under
    /// HKLM\Software\UmSerialFilter (writable only by administrators), so a process that
    /// merely obtains a handle to the device still cannot capture, retarget or read
    /// traffic. Returns true when the driver accepted the key.
    pub fn authenticate(&self) -> bool {
        let Some(key) = read_session_key() else {
            LAST_AUTH_ERROR.store(AUTH_NO_KEY, Ordering::Relaxed);
            return false;
        };
        match self.ioctl(IOCTL_AUTHENTICATE, Some(&key), 0) {
            Some(_) => {
                LAST_AUTH_ERROR.store(0, Ordering::Relaxed);
                true
            }
            None => {
                LAST_AUTH_ERROR.store(unsafe { GetLastError() }, Ordering::Relaxed);
                false
            }
        }
    }

    /// Is the driver present and usable?
    pub fn is_available() -> bool {
        Self::open().is_some()
    }

    fn ioctl(&self, code: u32, in_buf: Option<&[u8]>, out_len: usize) -> Option<(Vec<u8>, u32)> {
        let mut out = vec![0u8; out_len.max(1)];
        let mut returned = 0u32;
        let (in_ptr, in_len) = match in_buf {
            Some(b) => (b.as_ptr() as *mut c_void, b.len() as u32),
            None => (std::ptr::null_mut(), 0),
        };
        let ok = unsafe {
            DeviceIoControl(
                self.h,
                code,
                in_ptr,
                in_len,
                out.as_mut_ptr() as *mut c_void,
                out.len() as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            None
        } else {
            out.truncate(returned as usize);
            Some((out, returned))
        }
    }

    /// Ask the driver to attach to every serial device it can find, and return how
    /// many ports are attached in TOTAL.
    ///
    /// The driver's IOCTL returns how many it attached *during this call*, which is 0
    /// on every scan after the first — the ports are already attached, so nothing new
    /// happens. Every caller here wants "how many ports do I have", and treating the
    /// delta as a total made the program report "附加到 0 个串口设备" while it was in
    /// fact attached to all four and capturing perfectly.
    ///
    /// The total is read from the stats block, where the driver maintains it as a
    /// running count.
    pub fn attach_ports(&self) -> u32 {
        let newly = match self.ioctl(IOCTL_ATTACH_PORTS, None, 4) {
            Some((out, _)) if out.len() >= 4 => {
                u32::from_le_bytes([out[0], out[1], out[2], out[3]])
            }
            _ => 0,
        };
        // Prefer the authoritative total; fall back to the delta only if stats are
        // unavailable (an older driver without IOCTL_UM_GET_STATS).
        match self.stats() {
            Some(st) => st.attached,
            None => newly,
        }
    }

    /// Names of the attached ports, in index order.
    pub fn port_names(&self, count: u32) -> Vec<DriverPort> {
        let mut out = Vec::new();
        for index in 0..count {
            if let Some(name) = self.port_name(index) {
                out.push(DriverPort {
                    index,
                    device: name,
                });
            }
        }
        out
    }

    /// 查询单个端口的设备路径；驱动没有这个序号时返回 None。
    pub fn port_name(&self, index: u32) -> Option<String> {
        let inb = index.to_le_bytes();
        let (buf, n) = self.ioctl(IOCTL_GET_PORT_NAME, Some(&inb), 512)?;
        if n < 8 {
            return None;
        }
        let chars = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
        let need = 8 + chars * 2;
        if buf.len() < need || chars == 0 {
            return None;
        }
        let mut units = Vec::with_capacity(chars);
        for i in 0..chars {
            let o = 8 + i * 2;
            units.push(u16::from_le_bytes([buf[o], buf[o + 1]]));
        }
        Some(String::from_utf16_lossy(&units))
    }

    /// 驱动的计数器（含已附加端口数、目标 PID）。
    ///
    /// 线格式是 10 个 u32：队列 / 丢弃 / 收低 / 收高 / 发低 / 发高 / 启用 / 目标 PID /
    /// 已附加 / 保留。收发计数是 64 位的，分两格存放——只取低 32 位会在 4 GB 后回绕。
    pub fn stats(&self) -> Option<DriverStats> {
        let (buf, n) = self.ioctl(IOCTL_GET_STATS, None, 48)?;
        if n < 48 {
            return None;
        }
        let u = |o: usize| u32::from_le_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]]);
        let u64_at = |o: usize| u(o) as u64 | ((u(o + 4) as u64) << 32);
        Some(DriverStats {
            records: u(0),
            dropped: u(4),
            received: u64_at(8),
            sent: u64_at(16),
            enabled: u(24),
            target_pid: u(28),
            attached: u(32),
            rejected_type: u(36),
            rejected_name: u(40),
            accepted: u(44),
        })
    }

    /// Enable capture (pid 0 = every process).
    pub fn set_target(&self, pid: u32) {
        let b = pid.to_le_bytes();
        let _ = self.ioctl(IOCTL_SET_TARGET, Some(&b), 0);
    }

    /// Pop one record; None when the queue is empty.
    ///
    /// IMPORTANT: this IOCTL completes immediately with a zero-length result when the
    /// driver's queue is empty — it does NOT block. That is what makes the capture thread
    /// safe to run at 15 ms intervals. If it ever did block, the UI would freeze the
    /// moment a port went quiet, which is exactly the failure mode seen with the first
    /// driver build.
    pub fn next_record(&self) -> Option<Record> {
        let (buf, n) = self.ioctl(IOCTL_GET_RECORD, None, RECORD_HEADER + MAX_PAYLOAD)?;
        if n < RECORD_HEADER as u32 {
            return None;
        }
        let size = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let dir = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let pid = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let port_index = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let mut handle = [0u8; 8];
        handle.copy_from_slice(&buf[16..24]);
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&buf[24..32]);
        let handle = u64::from_le_bytes(handle);
        let timestamp = u64::from_le_bytes(ts);
        let take = size.min(MAX_PAYLOAD).min(buf.len().saturating_sub(RECORD_HEADER));
        let payload = &buf[RECORD_HEADER..RECORD_HEADER + take];

        // Direction 2 is a serial parameter change, not captured bytes. It travels in the
        // same queue so the UI can show it inline as its own row kind.
        let (kind, control) = if dir == 2 {
            const CTRL_SIZE: usize = 36;
            let mut info = ControlInfo::default();
            if payload.len() >= CTRL_SIZE {
                let u = |o: usize| {
                    u32::from_le_bytes([
                        payload[o], payload[o + 1], payload[o + 2], payload[o + 3],
                    ])
                };
                info.ioctl_code = u(0);
                info.baud_rate = u(4);
                info.hand_flow = u(8);
                for k in 0..5 {
                    info.timeouts[k] = u(12 + k * 4);
                }
                info.data_bits = payload[32];
                info.stop_bits = payload[33];
                info.parity = payload[34];
            }
            (RecordKind::Control, Some(info))
        } else if dir == 1 {
            (RecordKind::Tx, None)
        } else {
            (RecordKind::Rx, None)
        };

        Some(Record {
            kind,
            pid,
            port_index,
            handle,
            timestamp,
            data: payload.to_vec(),
            control,
        })
    }

    /// Frames the driver has queued right now (from IOCTL_UM_GET_STATS).
    ///
    /// Used by the UI to tell "capture is running but nothing is transmitted" apart from
    /// "the driver is not seeing traffic at all".
    pub fn queued(&self) -> Option<u32> {
        self.stats().map(|s| s.records)
    }
}

impl Drop for DriverHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.h) };
    }
}

/// 「驱动打不开」的可操作指引。
///
/// 只回一句「未检测到驱动」对用户没有帮助：失败原因通常只有三种（没装、签名被拒、
/// 权限不够），每种都要一条不同的命令。这里按 Win32 错误码分开写，界面直接显示。
pub fn open_failure_hint(err: u32) -> String {
    let mut s = String::new();
    match err {
        0 | ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => {
            // 控制设备不存在 = 服务没建或没起，这是最常见的一种。
            s.push_str("驱动未安装：控制设备 \\\\.\\UmSerialFilter 不存在（错误码 2/3）。\n");
        }
        ERROR_ACCESS_DENIED => {
            s.push_str("拒绝访问：驱动可能已加载，但当前进程没有打开控制设备的权限。\n");
            s.push_str("请用「以管理员身份运行」重新启动本程序。\n");
        }
        ERROR_INVALID_IMAGE_HASH => {
            s.push_str("签名验证失败（错误码 577）：驱动没有通过内核签名检查，无法加载。\n");
            s.push_str("解决办法：开启测试签名模式后重启——\n");
            s.push_str("    bcdedit /set testsigning on        (管理员，之后必须重启)\n");
            s.push_str("    bcdedit /enum {current}           (确认 testsigning 为 Yes)\n");
            s.push_str("测试签名会关闭部分驱动签名强制，仅建议在实验机上使用。\n");
        }
        _ => {
            s.push_str(&format!("打开控制设备失败，Win32 错误码 {err}。\n"));
        }
    }
    s.push_str("手动加载驱动（管理员命令行）：\n");
    s.push_str("    sc create UmSerialFilter type= kernel binPath= <umserialfilter.sys 的完整路径>\n");
    s.push_str("    sc start UmSerialFilter\n");
    s.push_str("    sc query UmSerialFilter            (确认 STATE = RUNNING)\n");
    s.push_str("也可以直接运行 driver\\install-driver.ps1。");
    s
}
