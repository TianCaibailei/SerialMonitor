// Probe the real PROCESSENTRY32W layout: dump the raw bytes of one entry and find
// where the UTF-16 name actually starts. If the struct field offsets are wrong (a
// classic x64 mistake: usize instead of u32), every process name comes back empty
// even though the PID is right.

use std::ffi::c_void;

// This probe deliberately declares the Toolhelp32 functions with `*mut u8` buffers: its
// whole purpose is to inspect the *raw bytes* of PROCESSENTRY32W so a wrong struct layout
// becomes visible. The differing signature from the typed declarations in `inject` is the
// point, not a mistake.
#[allow(clashing_extern_declarations)]
extern "system" {
    fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> *mut c_void;
    fn Process32FirstW(snap: *mut c_void, pe: *mut u8) -> i32;
    fn Process32NextW(snap: *mut c_void, pe: *mut u8) -> i32;
    fn CloseHandle(h: *mut c_void) -> i32;
    fn GetCurrentProcessId() -> u32;
}

pub fn probe_layout() -> i32 {
    let mut raw = [0u8; 568];
    let sz = 568u32;
    unsafe { std::ptr::copy_nonoverlapping(sz.to_le_bytes().as_ptr(), raw.as_mut_ptr(), 4) };
    let snap = unsafe { CreateToolhelp32Snapshot(0x2, 0) };
    if snap as isize == -1 {
        println!("probe: 快照失败");
        return 1;
    }
    if unsafe { Process32FirstW(snap, raw.as_mut_ptr()) } == 0 {
        println!("probe: Process32FirstW 失败, dwSize={sz}");
        unsafe { CloseHandle(snap) };
        return 1;
    }
    println!("probe: dwSize 传入 {sz} 成功");
    // Dump the first 120 bytes as hex+ascii to locate the name.
    for chunk in 0..6 {
        let start = chunk * 20;
        let bytes = &raw[start..start + 20];
        let hex: Vec<String> = bytes.iter().map(|b| format!("{b:02X}")).collect();
        let ascii: String = bytes
            .iter()
            .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
            .collect();
        println!("probe: +{start:03}  {}  |{ascii}|", hex.join(" "));
    }
    // Interpret offset 36 as UTF-16LE (the documented szExeFile offset with 9 DWORDs).
    let name36 = {
        let mut units = Vec::new();
        for i in 0..260usize {
            let o = 36 + i * 2;
            if o + 1 >= raw.len() {
                break;
            }
            let u = u16::from_le_bytes([raw[o], raw[o + 1]]);
            if u == 0 {
                break;
            }
            units.push(u);
        }
        String::from_utf16_lossy(&units)
    };
    println!("probe: offset 36 名称 = {name36:?}");
    let pid = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);
    println!("probe: pid@8 = {pid} (自身 {})", unsafe { GetCurrentProcessId() });
    unsafe { CloseHandle(snap) };
    0
}
