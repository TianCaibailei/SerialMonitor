// How do you turn a serial device path into a COM number WITHOUT opening the port?
//
// The hook needs the label "COM1" (not "\Device\VSerial8_0") because the session's
// channel is named after the COM number and routing matches on it.
//
// Build: rustc --target i686-pc-windows-msvc -O tests\dosname.rs -o tests\dosname32.exe
//        rustc -O tests\dosname.rs -o tests\dosname64.exe
use std::ffi::c_void;

extern "system" {
    fn QueryDosDeviceW(name: *const u16, target: *mut u16, max: u32) -> u32;
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn query(name: &str) -> Option<String> {
    let mut buf = [0u16; 512];
    let n = unsafe { QueryDosDeviceW(wide(name).as_ptr(), buf.as_mut_ptr(), 512) } as usize;
    if n == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&buf[..n.saturating_sub(1)]))
}

fn main() {
    println!("=== {}-bit ===", std::mem::size_of::<usize>() * 8);
    for n in 1..=8 {
        for form in [format!("COM{n}"), format!(r"\\.\COM{n}")] {
            match query(&form) {
                Some(v) => println!("QueryDosDevice({form:>10}) -> {v}"),
                None => {}
            }
        }
    }
}
