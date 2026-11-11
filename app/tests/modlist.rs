use std::ffi::c_void;
extern "system" {
    fn OpenProcess(a: u32, b: i32, pid: u32) -> *mut c_void;
    fn CloseHandle(h: *mut c_void) -> i32;
    fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> *mut c_void;
    fn Module32FirstW(s: *mut c_void, me: *mut u8) -> i32;
    fn Module32NextW(s: *mut c_void, me: *mut u8) -> i32;
}
fn main(){
    let pid: u32 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let log = std::env::args().nth(2).unwrap_or_else(|| "modlist.log".into());
    let mut out = String::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(0x8, pid);
        if snap as isize != -1 {
            let mut buf = [0u8; 1088];
            buf[0..4].copy_from_slice(&1088u32.to_le_bytes());
            if Module32FirstW(snap, buf.as_mut_ptr()) != 0 {
                loop {
                    let mut units = Vec::new();
                    for i in 0..256usize {
                        let o = 44 + i*2;
                        if o+1 >= buf.len() { break }
                        let u = u16::from_le_bytes([buf[o], buf[o+1]]);
                        if u == 0 { break }
                        units.push(u);
                    }
                    let name = String::from_utf16_lossy(&units);
                    let base = u32::from_le_bytes([buf[24],buf[25],buf[26],buf[27]]);
                    out.push_str(&format!("{name} base={base:#x}\n"));
                    for b in buf[44..].iter_mut() { *b = 0 }
                    if Module32NextW(snap, buf.as_mut_ptr()) == 0 { break }
                }
            }
            CloseHandle(snap);
        } else {
            out.push_str("snapshot failed\n");
        }
    }
    let _ = std::fs::write(&log, out);
}
