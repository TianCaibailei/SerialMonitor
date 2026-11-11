// Read-only probe #3: hold the control device open and watch the counters live.
//
// The driver stops capturing as soon as the last control-device handle closes
// (UmControlClose: InterlockedDecrement(OpenCount) <= 0 -> Enabled = 0). Any probe that
// opens, samples and closes therefore measures a device that was never capturing, which
// is why a byte-counter test between two short probes shows no movement.
//
// This probe keeps the handle open for N seconds and samples IOCTL_UM_GET_STATS every
// 500 ms, so a serial write performed by another process during that window shows up as
// a delta. That separates:
//   "attached list is right but capture is dead"      -> RX/TX stay flat
//   "capture is fine, only the attach count is wrong"  -> RX/TX move
//
// Build:
//   rustc -O tests\hold_probe.rs -o tests\hold_probe.exe
// Run:
//   tests\hold_probe.exe 15
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
const IOCTL_GET_RECORD: u32 = ctl(0x800, FILE_READ_DATA);
const IOCTL_SET_TARGET: u32 = ctl(0x801, FILE_WRITE_DATA);
const IOCTL_GET_STATS: u32 = ctl(0x802, FILE_READ_DATA);
const IOCTL_ATTACH_PORTS: u32 = ctl(0x803, FILE_WRITE_DATA);
const IOCTL_AUTHENTICATE: u32 = ctl(0x805, FILE_WRITE_DATA);

const RECORD_HEADER: usize = 32;
const MAX_PAYLOAD: usize = 4096;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn session_key() -> Option<Vec<u8>> {
    const HKEY_LOCAL_MACHINE: *mut c_void = 0x8000_0002usize as *mut c_void;
    const KEY_READ: u32 = 0x2_0019;
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
    if rc != 0 || len == 0 {
        return None;
    }
    buf.truncate(len as usize);
    Some(buf)
}

fn stats(h: *mut c_void) -> Option<[u32; 12]> {
    let mut out = vec![0u8; 48];
    let mut ret = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            h,
            IOCTL_GET_STATS,
            std::ptr::null_mut(),
            0,
            out.as_mut_ptr() as *mut c_void,
            48,
            &mut ret,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return None;
    }
    let mut r = [0u32; 12];
    for i in 0..12 {
        r[i] = u32::from_le_bytes([out[i * 4], out[i * 4 + 1], out[i * 4 + 2], out[i * 4 + 3]]);
    }
    Some(r)
}

fn main() {
    let secs: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(15);

    let path = wide("\\\\.\\UmSerialFilter");
    let h = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            3,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if h as isize == INVALID {
        println!("hold: 无法打开控制设备, err={}", unsafe { GetLastError() });
        std::process::exit(2);
    }
    let Some(key) = session_key() else {
        println!("hold: 读不到 SessionKey");
        std::process::exit(2);
    };
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
    println!("hold: 认证={}", ok != 0);

    // Attach once and enable capture for every PID, exactly what the GUI does.
    let mut n: u32 = 0;
    unsafe {
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
    let pid0 = 0u32.to_le_bytes();
    unsafe {
        DeviceIoControl(
            h,
            IOCTL_SET_TARGET,
            pid0.as_ptr() as *mut c_void,
            4,
            std::ptr::null_mut(),
            0,
            &mut ret,
            std::ptr::null_mut(),
        )
    };
    println!("hold: attach 返回={n}，已 set_target(0)，保持句柄打开 {secs} 秒");

    let mut prev = stats(h).unwrap_or([0; 12]);
    println!(
        "hold: 起始 收={} 发={} 队列={} 已附加={} 通过={}",
        prev[2] as u64 | ((prev[3] as u64) << 32),
        prev[4] as u64 | ((prev[5] as u64) << 32),
        prev[0],
        prev[8],
        prev[11]
    );

    let start = std::time::Instant::now();
    let mut total_records = 0usize;
    while start.elapsed().as_secs() < secs {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let now = stats(h).unwrap_or([0; 12]);
        let rx = now[2] as u64 | ((now[3] as u64) << 32);
        let tx = now[4] as u64 | ((now[5] as u64) << 32);
        let prx = prev[2] as u64 | ((prev[3] as u64) << 32);
        let ptx = prev[4] as u64 | ((prev[5] as u64) << 32);
        if rx != prx || tx != ptx || now[0] != prev[0] {
            println!(
                "hold: t={:.1}s 收 {} -> {} (+{})  发 {} -> {} (+{})  队列={}",
                start.elapsed().as_secs_f64(),
                prx,
                rx,
                rx - prx,
                ptx,
                tx,
                tx - ptx,
                now[0]
            );
        }
        prev = now;

        // Drain one record so the queue cannot mask the counters.
        let mut out = vec![0u8; RECORD_HEADER + MAX_PAYLOAD];
        let mut rl = 0u32;
        let ok = unsafe {
            DeviceIoControl(
                h,
                IOCTL_GET_RECORD,
                std::ptr::null_mut(),
                0,
                out.as_mut_ptr() as *mut c_void,
                out.len() as u32,
                &mut rl,
                std::ptr::null_mut(),
            )
        };
        if ok != 0 && rl as usize >= RECORD_HEADER {
            total_records += 1;
            let size = u32::from_le_bytes([out[0], out[1], out[2], out[3]]) as usize;
            let dir = u32::from_le_bytes([out[4], out[5], out[6], out[7]]);
            let pid = u32::from_le_bytes([out[8], out[9], out[10], out[11]]);
            let port = u32::from_le_bytes([out[12], out[13], out[14], out[15]]);
            let take = size.min(MAX_PAYLOAD).min(out.len() - RECORD_HEADER);
            let preview: String = out[RECORD_HEADER..RECORD_HEADER + take]
                .iter()
                .take(24)
                .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
                .collect();
            println!(
                "hold: 记录 #{total_records} dir={dir} pid={pid} port={port} {take} 字节: {preview}"
            );
        }
    }

    println!("hold: 结束，共取到 {total_records} 条记录");
    unsafe { CloseHandle(h) };
}
