// Native serial tool with a DELAY before opening the port.
//
// Purpose: separate "the hook cannot see serial I/O" from "the hook was installed too
// late". The program waits for a marker file, so an injector has time to get inside it
// BEFORE the port is opened — the only ordering under which an IAT hook can work.
//
// Run: native_serial_delayed <COMx> <milliseconds> <marker-file>
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
    fn WriteFile(
        h: *mut c_void,
        buf: *const u8,
        len: u32,
        written: *mut u32,
        ov: *mut c_void,
    ) -> i32;
    fn ReadFile(h: *mut c_void, buf: *mut u8, len: u32, read: *mut u32, ov: *mut c_void) -> i32;
    fn CloseHandle(h: *mut c_void) -> i32;
    fn Sleep(ms: u32);
}

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const OPEN_EXISTING: u32 = 3;
const INVALID: isize = -1;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn run(com: &str, millis: u64, marker: &str) -> i32 {
    println!("delayed-serial: 等待标记文件 {marker}");
    // Wait up to 60 s for the injector to say "you may go".
    for _ in 0..600 {
        if std::path::Path::new(marker).exists() {
            break;
        }
        unsafe { Sleep(100) };
    }
    println!("delayed-serial: 放行，开始打开 {com}");
    let path = wide(&format!(r"\\.\{com}"));
    let h = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if h as isize == INVALID {
        println!("delayed-serial: 打开 {com} 失败");
        return 2;
    }
    println!("delayed-serial: 已打开 {com}");
    let start = std::time::Instant::now();
    let mut i = 0u32;
    let mut rbuf = [0u8; 512];
    let mut rx_total = 0usize;
    while start.elapsed().as_millis() < millis as u128 {
        let msg = format!("DLY{i};");
        let mut written = 0u32;
        unsafe {
            WriteFile(
                h,
                msg.as_ptr(),
                msg.len() as u32,
                &mut written,
                std::ptr::null_mut(),
            )
        };
        let mut read = 0u32;
        unsafe {
            if ReadFile(
                h,
                rbuf.as_mut_ptr(),
                rbuf.len() as u32,
                &mut read,
                std::ptr::null_mut(),
            ) != 0
                && read > 0
            {
                rx_total += read as usize;
            }
        }
        i += 1;
        unsafe { Sleep(250) };
    }
    unsafe { CloseHandle(h) };
    println!("delayed-serial: 发送 {i} 帧, 收到 {rx_total} 字节");
    0
}
