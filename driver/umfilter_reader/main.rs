// User-mode side of the UmSerialFilter driver: open the control device, authenticate with
// the per-boot session key, ask the driver to attach to every serial port, then drain
// captured records and print them.
//
// This is the tool used to prove the kernel filter actually captures traffic; the real
// monitor consumes the same IOCTL interface.
//
// Usage: umfilter_reader [seconds]
use std::ffi::c_void;

#[link(name = "advapi32")]
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

const IOCTL_GET_RECORD: u32 = ctl(0x800, FILE_READ_DATA);
const IOCTL_SET_TARGET: u32 = ctl(0x801, FILE_WRITE_DATA);
const IOCTL_GET_STATS: u32 = ctl(0x802, FILE_READ_DATA);
const IOCTL_ATTACH_PORTS: u32 = ctl(0x803, FILE_WRITE_DATA);
const IOCTL_AUTHENTICATE: u32 = ctl(0x805, FILE_WRITE_DATA);

const HKEY_LOCAL_MACHINE: *mut c_void = 0x8000_0002usize as *mut c_void;
const KEY_READ: u32 = 0x2_0019;
const REG_BINARY: u32 = 3;

const RECORD_HEADER: usize = 32;
const MAX_PAYLOAD: usize = 4096;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Read the per-boot session key the driver published under HKLM.
fn read_session_key() -> Option<Vec<u8>> {
    let sub = wide("Software\\UmSerialFilter");
    let mut hkey: *mut c_void = std::ptr::null_mut();
    let rc = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub.as_ptr(), 0, KEY_READ, &mut hkey) };
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

/// Run one IOCTL and return (ok, bytes_returned, last_error).
///
/// The output buffer and the bytes-returned out-parameter are kept separate. Passing the
/// same variable as both (as an earlier version of this tool did) is aliasing, and it also
/// meant a refused IOCTL left the variable holding stale data that the program then
/// printed as if it were a real result.
fn ioctl(h: *mut c_void, code: u32, input: Option<&[u8]>, out_len: usize) -> (bool, Vec<u8>, u32) {
    let mut out = vec![0u8; out_len.max(1)];
    let mut returned = 0u32;
    let (in_ptr, in_len) = match input {
        Some(b) => (b.as_ptr() as *mut c_void, b.len() as u32),
        None => (std::ptr::null_mut(), 0),
    };
    let ok = unsafe {
        DeviceIoControl(
            h,
            code,
            in_ptr,
            in_len,
            out.as_mut_ptr() as *mut c_void,
            out.len() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    let err = if ok == 0 { unsafe { GetLastError() } } else { 0 };
    out.truncate(returned as usize);
    (ok != 0, out, err)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let seconds: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(15);

    let path = wide(r"\\.\UmSerialFilter");
    let h = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            0 as *mut c_void,
            OPEN_EXISTING,
            0,
            0 as *mut c_void,
        )
    };
    if h as isize == INVALID {
        eprintln!("无法打开 \\\\.\\UmSerialFilter (err={})", unsafe { GetLastError() });
        eprintln!("请先加载驱动: sc create UmSerialFilter type= kernel binPath= <path>");
        std::process::exit(1);
    }
    println!("已连接过滤驱动");

    // Handshake first: the driver refuses every other IOCTL until the session key matches.
    match read_session_key() {
        Some(key) => {
            let (ok, _, err) = ioctl(h, IOCTL_AUTHENTICATE, Some(&key), 0);
            if ok {
                println!("认证成功（会话密钥已匹配）");
            } else {
                eprintln!("认证失败 (err={err})。");
                if err == 5 {
                    eprintln!("  错误 5 = 拒绝访问：密钥不匹配，或驱动是旧版本（不含认证逻辑）。");
                    eprintln!("  请确认已重新编译并用 setup-driver.ps1 重新加载驱动。");
                }
                unsafe { CloseHandle(h) };
                std::process::exit(1);
            }
        }
        None => {
            eprintln!("无法从 HKLM\\Software\\UmSerialFilter 读取会话密钥。");
            eprintln!("  驱动未发布密钥 — 可能是旧驱动，或当前用户无读取权限。");
            unsafe { CloseHandle(h) };
            std::process::exit(1);
        }
    }

    // Attach to every serial device the driver can find.
    let (ok, out, err) = ioctl(h, IOCTL_ATTACH_PORTS, None, 4);
    if !ok {
        eprintln!("附加串口失败 (err={err})");
        unsafe { CloseHandle(h) };
        std::process::exit(1);
    }
    let attached = if out.len() >= 4 {
        u32::from_le_bytes([out[0], out[1], out[2], out[3]])
    } else {
        0
    };
    println!("驱动已附加到 {attached} 个串口设备");

    // Capture everything.
    let target = 0u32.to_le_bytes();
    let (ok, _, err) = ioctl(h, IOCTL_SET_TARGET, Some(&target), 0);
    if !ok {
        eprintln!("设置捕获目标失败 (err={err})");
        unsafe { CloseHandle(h) };
        std::process::exit(1);
    }

    println!("开始收集 {seconds} 秒…");
    let start = std::time::Instant::now();
    let mut buf_len = RECORD_HEADER + MAX_PAYLOAD;
    let mut total_rx = 0usize;
    let mut total_tx = 0usize;
    let mut count = 0usize;
    let mut short_buffer_warned = false;

    while start.elapsed().as_secs() < seconds {
        let (ok, out, err) = ioctl(h, IOCTL_GET_RECORD, None, buf_len);
        if !ok {
            // 122 = ERROR_INSUFFICIENT_BUFFER: grow once and continue. Anything else is a
            // real failure and should not be spun on silently.
            if err == 122 {
                buf_len = (RECORD_HEADER + MAX_PAYLOAD).max(buf_len * 2);
                if !short_buffer_warned {
                    println!("缓冲区不足，扩大到 {buf_len} 字节");
                    short_buffer_warned = true;
                }
                continue;
            }
            eprintln!("读取记录失败 (err={err})");
            break;
        }
        if out.len() < RECORD_HEADER {
            std::thread::sleep(std::time::Duration::from_millis(20));
            continue;
        }
        let size = u32::from_le_bytes([out[0], out[1], out[2], out[3]]) as usize;
        let dir = u32::from_le_bytes([out[4], out[5], out[6], out[7]]);
        let pid = u32::from_le_bytes([out[8], out[9], out[10], out[11]]);
        let take = size.min(MAX_PAYLOAD).min(out.len() - RECORD_HEADER);
        let data = &out[RECORD_HEADER..RECORD_HEADER + take];
        count += 1;
        if dir == 0 {
            total_rx += take;
        } else {
            total_tx += take;
        }
        let preview: String = data
            .iter()
            .take(48)
            .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
            .collect();
        println!(
            "[{}] pid={pid} {} 字节: {preview}",
            if dir == 0 { "RX" } else { "TX" },
            take
        );
    }

    println!();
    println!("=== 统计 ===");
    println!("记录数: {count}");
    println!("RX 字节: {total_rx}");
    println!("TX 字节: {total_tx}");
    unsafe { CloseHandle(h) };
    if count > 0 {
        println!("PASS: 驱动捕获到串口数据");
        std::process::exit(0);
    }
    println!("FAIL: 未捕获到数据");
    std::process::exit(1);
}
