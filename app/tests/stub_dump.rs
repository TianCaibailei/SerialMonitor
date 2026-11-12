// Dump the first bytes of kernel32 file-I/O exports in the CURRENT process.
//
// Why: the hook installs byte-level entry patches, and the shape of those prologues
// determines how many bytes may be displaced safely. x64 and x86 differ (rel32 vs
// absolute FF 25, different syscall stubs), so this must be run as a 32-bit process
// to measure the 32-bit target's reality.
//
// Build:  rustc --target i686-pc-windows-msvc -O tests\stub_dump.rs -o tests\stub_dump32.exe
//         rustc -O tests\stub_dump.rs -o tests\stub_dump64.exe
use std::ffi::c_void;

extern "system" {
    fn GetModuleHandleW(name: *const u16) -> *mut c_void;
    fn GetProcAddress(h: *mut c_void, name: *const u8) -> *mut c_void;
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn main() {
    let ptr_size = std::mem::size_of::<usize>() * 8;
    println!("=== {} bit process ===", ptr_size);
    let ntdll = unsafe { GetModuleHandleW(wide("ntdll.dll").as_ptr()) };
    let k32 = unsafe { GetModuleHandleW(wide("kernel32.dll").as_ptr()) };
    println!("kernel32 base = {:?}", k32);

    for (label, module) in [("kernel32", k32), ("ntdll", ntdll)] {
        for name in [
            "CreateFileW",
            "CreateFileA",
            "ReadFile",
            "WriteFile",
            "CloseHandle",
            "GetProcAddress",
            "GetOverlappedResult",
            "ReadFileEx",
            "WriteFileEx",
            "NtReadFile",
            "NtWriteFile",
            "NtCreateFile",
        ] {
            let mut cname = name.as_bytes().to_vec();
            cname.push(0);
            let p = unsafe { GetProcAddress(module, cname.as_ptr()) };
            if p.is_null() {
                continue;
            }
            let bytes = unsafe { std::slice::from_raw_parts(p as *const u8, 16) };
            let hex: Vec<String> = bytes.iter().map(|b| format!("{:02X}", b)).collect();
            println!(
                "{:<10} {:<22} {:>#14x}  {}",
                label,
                name,
                p as usize,
                hex.join(" ")
            );
        }
    }
}
