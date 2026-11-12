// Does GetFileInformationByHandleEx(FileNameInfo) work on a SERIAL handle?
//
// This decides whether a port that was opened BEFORE injection can ever be
// identified. The hook's com_label() classifies an already-open handle by asking
// the object for its name; if that call fails on serial handles, com_label returns
// None - and, because the negative cache is only written on a *successful* lookup,
// the handle is silently re-probed and silently discarded on every single I/O.
// That is exactly the "opened the port before injecting, nothing is captured" case.
//
// Build: rustc --target i686-pc-windows-msvc -O tests\serial_name.rs -o tests\serial_name32.exe
//        rustc -O tests\serial_name.rs -o tests\serial_name64.exe
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
    fn GetFileInformationByHandleEx(h: *mut c_void, class: u32, buf: *mut c_void, size: u32)
        -> i32;
    fn GetFileType(h: *mut c_void) -> u32;
    fn DeviceIoControl(
        h: *mut c_void,
        code: u32,
        inbuf: *mut c_void,
        insize: u32,
        outbuf: *mut c_void,
        outsize: u32,
        ret: *mut u32,
        ov: *mut c_void,
    ) -> i32;
    fn CloseHandle(h: *mut c_void) -> i32;
    fn GetLastError() -> u32;
}

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const OPEN_EXISTING: u32 = 3;
const INVALID: isize = -1;

// IOCTL_SERIAL_GET_COMMSTATUS — a request only a real serial port answers.
const IOCTL_SERIAL_GET_COMMSTATUS: u32 = 0x001B_0058;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn main() {
    let com = std::env::args().nth(1).unwrap_or_else(|| "COM1".into());
    let bits = std::mem::size_of::<usize>() * 8;
    println!("=== {bits}-bit probe, port {com} ===");

    let path = wide(&format!(r"\\.\{}", com));
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
        println!("open failed err={}", unsafe { GetLastError() });
        return;
    }

    // 1) The call the hook relies on.
    let mut buf = [0u8; 1024];
    let ok = unsafe {
        GetFileInformationByHandleEx(h, 2 /* FileNameInfo */, buf.as_mut_ptr() as _, 1024)
    };
    let err = unsafe { GetLastError() };
    println!("GetFileInformationByHandleEx(FileNameInfo) ok={ok} err={err}");
    if ok != 0 {
        let chars = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize / 2;
        let mut units = Vec::new();
        for i in 0..chars {
            let b = i * 2 + 4;
            if b + 1 >= buf.len() {
                break;
            }
            units.push(u16::from_le_bytes([buf[b], buf[b + 1]]));
        }
        println!("  name = {}", String::from_utf16_lossy(&units));
    }

    // 2) Generic handle classification.
    println!("GetFileType = {:#x} (2 = FILE_TYPE_CHAR)", unsafe {
        GetFileType(h)
    });

    // 3) A serial-only IOCTL: succeeds iff this really is a serial port.
    let mut cs = [0u8; 32];
    let mut ret = 0u32;
    let ok2 = unsafe {
        DeviceIoControl(
            h,
            IOCTL_SERIAL_GET_COMMSTATUS,
            std::ptr::null_mut(),
            0,
            cs.as_mut_ptr() as _,
            cs.len() as u32,
            &mut ret,
            std::ptr::null_mut(),
        )
    };
    println!(
        "IOCTL_SERIAL_GET_COMMSTATUS ok={ok2} err={} ret={ret}",
        unsafe { GetLastError() }
    );

    unsafe { CloseHandle(h) };
}
