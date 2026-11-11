// Read-only probe #2 for UmSerialFilter: is the *driver's* view of \Device the same as a
// user-mode view, and what does ATTACH_PORTS actually return when ports are already
// attached?
//
// Why this exists
// ---------------
// IOCTL_UM_GET_STATS reports AttachedCount == 4 while IOCTL_UM_ATTACH_PORTS returns 0.
// That can only be one of:
//   (a) ATTACH_PORTS returns the number of NEWLY attached devices, not the total, or
//   (b) the scan really attaches nothing while the table still holds 4 stale slots.
// This probe separates them by watching the three discovery counters across repeated
// scans, and by listing \Device independently of the driver.
//
// It never writes to the driver beyond the session-key handshake / attach request, and
// never loads, starts or stops anything.
//
// Build:
//   rustc -O tests\discover_probe.rs -o tests\discover_probe.exe
// Run:
//   tests\discover_probe.exe
use std::ffi::c_void;

#[link(name = "ntdll")]
extern "system" {
    fn NtOpenDirectoryObject(handle: *mut *mut c_void, access: u32, oa: *mut u8) -> i32;
    fn NtQueryDirectoryObject(
        handle: *mut c_void,
        buf: *mut u8,
        len: u32,
        single: u8,
        restart: u8,
        context: *mut u32,
        retlen: *mut u32,
    ) -> i32;
    fn NtClose(handle: *mut c_void) -> i32;
}

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

/// OBJECT_DIRECTORY_INFORMATION { UNICODE_STRING Name; UNICODE_STRING TypeName; }
/// x64 UNICODE_STRING = { u16 Length; u16 MaximumLength; u32 pad; PWSTR Buffer }
#[repr(C)]
struct DirInfo {
    name_len: u16,
    name_max: u16,
    _pad1: u32,
    name_buf: *const u16,
    type_len: u16,
    type_max: u16,
    _pad2: u32,
    type_buf: *const u16,
}

fn list_device() -> (usize, Vec<String>, Vec<String>) {
    // \Device object directory, opened by a user-mode process. Read access is enough to
    // list: the DACL on \Device allows directory query to everyone.
    let name = wide("\\Device");
    // OBJECT_ATTRIBUTES (x64): Length, RootDirectory, ObjectName, Attributes,
    // SecurityDescriptor, SecurityQualityOfService
    let mut oa = [0u64; 6];
    oa[0] = 48; // sizeof(OBJECT_ATTRIBUTES)
    let uname = wide("\\Device");
    // UNICODE_STRING is embedded by pointer in OBJECT_ATTRIBUTES: ObjectName points at a
    // UNICODE_STRING struct, so build one on the stack.
    #[repr(C)]
    struct UStr {
        len: u16,
        max: u16,
        _pad: u32,
        buf: *const u16,
    }
    let mut us = UStr {
        len: (uname.len() as u16 - 1) * 2,
        max: (uname.len() as u16) * 2,
        _pad: 0,
        buf: uname.as_ptr(),
    };
    oa[2] = &mut us as *mut UStr as u64;
    oa[3] = 0x40; // OBJ_CASE_INSENSITIVE

    let mut dir: *mut c_void = std::ptr::null_mut();
    let st = unsafe { NtOpenDirectoryObject(&mut dir, 0x1 | 0x2, oa.as_mut_ptr() as *mut u8) };
    if st != 0 {
        println!("list_device: NtOpenDirectoryObject 失败 status=0x{st:08X} (name={:p})", name.as_ptr());
        return (0, Vec::new(), Vec::new());
    }

    let mut buf = vec![0u8; 512 * 1024];
    let mut ctx = 0u32;
    let mut retlen = 0u32;
    let st = unsafe {
        NtQueryDirectoryObject(
            dir,
            buf.as_mut_ptr(),
            buf.len() as u32,
            0, // all entries in one shot
            1, // restart
            &mut ctx,
            &mut retlen,
        )
    };
    unsafe { NtClose(dir) };
    if st != 0 {
        println!("list_device: NtQueryDirectoryObject 失败 status=0x{st:08X}");
        return (0, Vec::new(), Vec::new());
    }

    let mut total = 0usize;
    let mut serial: Vec<String> = Vec::new();
    let mut vserial: Vec<String> = Vec::new();
    let mut off = 0usize;
    while off + 32 <= retlen as usize {
        let e = unsafe { &*(buf.as_ptr().add(off) as *const DirInfo) };
        if e.name_buf.is_null() || e.name_len == 0 {
            break;
        }
        let chars = (e.name_len / 2) as usize;
        let s = unsafe { std::slice::from_raw_parts(e.name_buf, chars) };
        let n = String::from_utf16_lossy(s);
        total += 1;
        let lower = n.to_lowercase();
        if lower.starts_with("vserial") {
            vserial.push(n);
        } else if lower.starts_with("serial") {
            serial.push(n);
        }
        off += 32;
    }
    (total, serial, vserial)
}

fn session_key() -> Option<Vec<u8>> {
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

fn attach(h: *mut c_void) -> (u32, u32) {
    let mut n: u32 = 0xFFFF_FFFF;
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
    (if ok != 0 { n } else { 0xFFFF_FFFF }, ret)
}

fn main() {
    println!("=== 1. 用户态独立枚举 \\Device（不经过驱动）===");
    let (total, serial, vserial) = list_device();
    println!("\\Device 子对象总数 = {total}");
    println!("  前缀 Serial  : {serial:?}");
    println!("  前缀 VSerial : {vserial:?}");
    println!("  合计候选 = {}", serial.len() + vserial.len());

    println!();
    println!("=== 2. 打开控制设备并认证 ===");
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
        println!("无法打开控制设备, err={}", unsafe { GetLastError() });
        return;
    }
    let Some(key) = session_key() else {
        println!("读不到 SessionKey");
        return;
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
    println!("认证 = {}", ok != 0);

    println!();
    println!("=== 3. 连续 4 次 ATTACH_PORTS，每次看计数增量 ===");
    let mut prev = stats(h).unwrap_or([0; 12]);
    println!(
        "初始: attached={} accepted={} rejected_type={} rejected_name={}",
        prev[8], prev[11], prev[9], prev[10]
    );
    for i in 1..=4 {
        let (n, ret) = attach(h);
        let now = stats(h).unwrap_or([0; 12]);
        println!(
            "第 {i} 次: 返回={n} BytesReturned={ret} | attached: {} -> {} | accepted +{} | rejected_type +{} | rejected_name +{}",
            prev[8],
            now[8],
            now[11].wrapping_sub(prev[11]),
            now[9].wrapping_sub(prev[9]),
            now[10].wrapping_sub(prev[10])
        );
        prev = now;
    }

    println!();
    println!("=== 4. 按索引读回端口名（attached={}）===", prev[8]);
    for i in 0..prev[8].min(16) {
        let inb = i.to_le_bytes();
        let mut out = vec![0u8; 512];
        let mut rlen = 0u32;
        let ok = unsafe {
            DeviceIoControl(
                h,
                IOCTL_GET_PORT_NAME,
                inb.as_ptr() as *mut c_void,
                4,
                out.as_mut_ptr() as *mut c_void,
                512,
                &mut rlen,
                std::ptr::null_mut(),
            )
        };
        if ok != 0 && rlen >= 8 {
            let chars = u32::from_le_bytes([out[4], out[5], out[6], out[7]]) as usize;
            let units: Vec<u16> = (0..chars)
                .map(|k| u16::from_le_bytes([out[8 + k * 2], out[9 + k * 2]]))
                .collect();
            println!("  [{i}] {}", String::from_utf16_lossy(&units));
        } else {
            println!("  [{i}] <无> err={}", unsafe { GetLastError() });
        }
    }

    unsafe { CloseHandle(h) };
}
