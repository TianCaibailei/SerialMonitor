// 32-bit serial probe — reproduces the user's real ordering for a WOW64 target.
//
// Scenario it mimics (and the reason it exists):
//   the serial tool starts, resolves its kernel32 entry points and caches them,
//   THEN the monitor injects the hook, THEN the tool opens the port.
//
// Under that ordering IAT patching cannot work for a tool that keeps its own
// function pointers (UartAssist is UPX-packed and binds everything dynamically),
// so this probe must be able to call through cached pointers too.
//
// Build (32-bit, no cargo needed):
//   rustc --target i686-pc-windows-msvc -O tests\x86_probe.rs -o tests\x86_probe.exe
//
// Run:
//   x86_probe.exe COM1 <marker-file> iat   — call CreateFileW/WriteFile via the IAT
//   x86_probe.exe COM1 <marker-file> gpa   — resolve once via GetProcAddress, cache them
//
// It waits for the marker file BEFORE opening the port, so the test controls exactly
// when injection happens relative to the port open.
use std::ffi::c_void;

extern "system" {
    fn GetModuleHandleW(name: *const u16) -> *mut c_void;
    fn GetProcAddress(h: *mut c_void, name: *const u8) -> *mut c_void;
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

type CreateFileWFn = unsafe extern "system" fn(
    *const u16,
    u32,
    u32,
    *mut c_void,
    u32,
    u32,
    *mut c_void,
) -> *mut c_void;
type WriteFileFn =
    unsafe extern "system" fn(*mut c_void, *const u8, u32, *mut u32, *mut c_void) -> i32;
type ReadFileFn =
    unsafe extern "system" fn(*mut c_void, *mut u8, u32, *mut u32, *mut c_void) -> i32;

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const OPEN_EXISTING: u32 = 3;
const INVALID: isize = -1;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let com = args.get(1).cloned().unwrap_or_else(|| "COM1".into());
    let marker = args.get(2).cloned().unwrap_or_else(|| "go.txt".into());
    let mode = args.get(3).cloned().unwrap_or_else(|| "iat".into());

    // Resolve BEFORE waiting: this is the tool that "already started" when the
    // monitor injects, so a cached pointer is the realistic case.
    let (create, write, read): (CreateFileWFn, WriteFileFn, ReadFileFn) = if mode == "gpa" {
        unsafe {
            #[allow(non_snake_case)]
            let k32 = GetModuleHandleW(wide("kernel32.dll").as_ptr());
            let c = GetProcAddress(k32, b"CreateFileW\0".as_ptr());
            let w = GetProcAddress(k32, b"WriteFile\0".as_ptr());
            let r = GetProcAddress(k32, b"ReadFile\0".as_ptr());
            (
                std::mem::transmute(c),
                std::mem::transmute(w),
                std::mem::transmute(r),
            )
        }
    } else {
        (unsafe { CreateFileW }, unsafe { WriteFile }, unsafe {
            ReadFile
        })
    };

    // Report which addresses we cached, so the test can tell "hook replaced them"
    // from "we still hold kernel32's own entry point".
    println!(
        "probe32: mode={} cached CreateFileW={:?} WriteFile={:?} ReadFile={:?}",
        mode, create as usize, write as usize, read as usize
    );

    // Wait up to 60 s for the marker: the test injects during this window.
    for i in 0..600 {
        if std::path::Path::new(&marker).exists() {
            println!("probe32: marker seen after {} ms", i * 100);
            break;
        }
        unsafe { Sleep(100) };
    }
    let path = wide(&format!(r"\\.\{}", com));
    let h = unsafe {
        create(
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
        println!("probe32: open {com} FAILED");
        std::process::exit(2);
    }
    println!("probe32: opened {com} handle={:?}", h);
    unsafe {
        let msg = b"P32TX;";
        let mut w = 0u32;
        write(
            h,
            msg.as_ptr(),
            msg.len() as u32,
            &mut w,
            std::ptr::null_mut(),
        );
        println!("probe32: wrote {w} bytes");
        let mut buf = [0u8; 256];
        let mut r = 0u32;
        if read(
            h,
            buf.as_mut_ptr(),
            buf.len() as u32,
            &mut r,
            std::ptr::null_mut(),
        ) != 0
            && r > 0
        {
            println!("probe32: read {r} bytes");
        } else {
            println!("probe32: read 0 bytes (no peer traffic)");
        }
        // Stay open so the monitor has time to see the handle.
        Sleep(2500);
        CloseHandle(h);
    }
    println!("probe32: done");
}
