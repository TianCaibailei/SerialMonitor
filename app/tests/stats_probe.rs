// Read-only probe for UmSerialFilter's IOCTL_UM_GET_STATS (and attach counters).
//
// Purpose: answer "did the driver's \Device enumeration run at all?" without touching
// the driver, the service, or app/src. The three discovery counters (rejected_type /
// rejected_name / accepted) are only incremented inside UmAttachAllPorts, so:
//
//   stats all zero AND attach returns 0  -> enumeration never ran (or never reached a
//                                           candidate), i.e. the gate is elsewhere.
//   stats nonzero                        -> enumeration ran; the nonzero bucket says why.
//
// Build (no cargo, mirrors tests\x86_probe.rs):
//   rustc -O tests\stats_probe.rs -o tests\stats_probe.exe
//
// Run:
//   tests\stats_probe.exe            — read stats, then ATTACH_PORTS, then stats again
//   tests\stats_probe.exe --quiet    — only the two stat snapshots + attach count
use std::ffi::c_void;

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

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const OPEN_EXISTING: u32 = 3;
const INVALID: isize = -1;

const DEVICE_TYPE: u32 = 0x8000;
const FILE_READ_DATA: u32 = 0x0001;
const FILE_WRITE_DATA: u32 = 0x0002;

const fn ctl(func: u32, access: u32) -> u32 {
    (DEVICE_TYPE << 16) | (access << 14) | (func << 2)
}
const IOCTL_GET_STATS: u32 = ctl(0x802, FILE_READ_DATA);
const IOCTL_ATTACH_PORTS: u32 = ctl(0x803, FILE_WRITE_DATA);
const IOCTL_GET_PORT_NAME: u32 = ctl(0x804, FILE_READ_DATA);
const IOCTL_AUTHENTICATE: u32 = ctl(0x805, FILE_WRITE_DATA);

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn session_key() -> Option<Vec<u8>> {
    const HKEY_LOCAL_MACHINE: *mut c_void = 0x8000_0002usize as *mut c_void;
    const KEY_READ: u32 = 0x2_0019;
    const REG_BINARY: u32 = 3;
    let mut hkey: *mut c_void = std::ptr::null_mut();
    let sub = wide("Software\\UmSerialFilter");
    if unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub.as_ptr(), 0, KEY_READ, &mut hkey) } != 0 {
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
    if rc != 0 || kind != REG_BINARY || len == 0 {
        return None;
    }
    buf.truncate(len as usize);
    Some(buf)
}

struct Stats {
    raw: [u32; 12],
}

impl Stats {
    fn dump(&self, tag: &str) {
        let r = &self.raw;
        let received = r[2] as u64 | ((r[3] as u64) << 32);
        let sent = r[4] as u64 | ((r[5] as u64) << 32);
        println!("[{tag}] 队列={} 丢弃={} 收={} 发={} 启用={} 目标PID={} 已附加={}",
                 r[0], r[1], received, sent, r[6], r[7], r[8]);
        println!("[{tag}] 发现闸门: 类型不符={} 名称不符={} 通过={}",
                 r[9], r[10], r[11]);
        println!("[{tag}] raw = {:?}", r);
    }
}

fn get_stats(h: *mut c_void) -> Option<Stats> {
    let mut out = vec![0u8; 48];
    let mut ret = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            h,
            IOCTL_GET_STATS,
            std::ptr::null_mut(),
            0,
            out.as_mut_ptr() as *mut c_void,
            out.len() as u32,
            &mut ret,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        println!("   GET_STATS 失败, GetLastError={}", unsafe { GetLastError() });
        return None;
    }
    if ret < 48 {
        println!("   GET_STATS 只返回 {ret} 字节（驱动是旧版 9 槽布局？）");
    }
    let mut raw = [0u32; 12];
    for i in 0..12 {
        let o = i * 4;
        if o + 4 <= out.len() {
            raw[i] = u32::from_le_bytes([out[o], out[o + 1], out[o + 2], out[o + 3]]);
        }
    }
    Some(Stats { raw })
}

fn main() {
    let quiet = std::env::args().any(|a| a == "--quiet");

    let path = wide("\\\\.\\UmSerialFilter");
    let h = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0x3, // FILE_SHARE_READ | FILE_SHARE_WRITE
            std::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if h as isize == INVALID {
        println!("probe: 无法打开 \\\\.\\UmSerialFilter, GetLastError={}", unsafe { GetLastError() });
        std::process::exit(2);
    }
    println!("probe: 已打开控制设备");

    // Authenticate (required before any other IOCTL).
    match session_key() {
        Some(key) => {
            let mut ret = 0u32;
            let ok = unsafe {
                DeviceIoControl(
                    h,
                    IOCTL_AUTHENTICATE,
                    key.as_ptr() as *mut c_void,
                    key.len() as u32,
                    std::ptr::null_mut(),
                    0,
                    &mut ret,
                    std::ptr::null_mut(),
                )
            };
            println!("probe: 认证 {} (key {} 字节)",
                     if ok != 0 { "成功" } else { "失败" },
                     key.len());
            if ok == 0 {
                println!("probe: 认证 GetLastError={}（错误 5 = 会话密钥不匹配，驱动可能是上一代加载的）",
                         unsafe { GetLastError() });
            }
        }
        None => println!("probe: 读不到 HKLM\\Software\\UmSerialFilter\\SessionKey"),
    }

    // Snapshot BEFORE attach: this is the decisive measurement. The three discovery
    // counters live in the loaded image's data section and survive across IOCTLs, but are
    // rebuilt whenever the module is (re)loaded.
    if let Some(s) = get_stats(h) {
        s.dump("附加前");
    }

    if !quiet {
        // Ask the driver to scan now.
        let mut n: u32 = 0;
        let mut ret = 0u32;
        let ok = unsafe {
            DeviceIoControl(
                h,
                IOCTL_ATTACH_PORTS,
                std::ptr::null_mut(),
                0,
                &mut n as *mut u32 as *mut c_void,
                4,
                &mut ret,
                std::ptr::null_mut(),
            )
        };
        println!("probe: ATTACH_PORTS ok={} ret={} 本次新增附加={n} err={}",
                 ok, ret, unsafe { GetLastError() });

        if let Some(s) = get_stats(h) {
            s.dump("附加后");
        }

        // Read the names the driver thinks it has (index 0..attached).
        let attached = get_stats(h).map(|s| s.raw[8]).unwrap_or(0);
        for i in 0..attached.min(16) {
            let inb = i.to_le_bytes();
            let mut out = vec![0u8; 512];
            let mut ret = 0u32;
            let ok = unsafe {
                DeviceIoControl(
                    h,
                    IOCTL_GET_PORT_NAME,
                    inb.as_ptr() as *mut c_void,
                    4,
                    out.as_mut_ptr() as *mut c_void,
                    512,
                    &mut ret,
                    std::ptr::null_mut(),
                )
            };
            if ok != 0 && ret >= 8 {
                let chars =
                    u32::from_le_bytes([out[4], out[5], out[6], out[7]]) as usize;
                let units: Vec<u16> = (0..chars)
                    .map(|k| {
                        let o = 8 + k * 2;
                        u16::from_le_bytes([out[o], out[o + 1]])
                    })
                    .collect();
                println!("probe:   [{i}] {}", String::from_utf16_lossy(&units));
            } else {
                println!("probe:   [{i}] <无名称> ret={ret} err={}", unsafe { GetLastError() });
            }
        }
    }

    unsafe { CloseHandle(h) };
}
