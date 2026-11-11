// Reproduces the USER'S EXACT ORDERING, which is the case that failed.
//
// The user does: open the serial tool -> open our monitor -> inject -> then open the
// port in the tool. This probe reverses the ordering the old tests enforced:
//
//   open the port FIRST, keep doing I/O, and only then get injected.
//
// With IAT hooking this can never be captured (the tool already resolved its
// pointers). With entry-point patching it must work, because the patch changes the
// function every caller points at, regardless of when they resolved it.
//
// Usage: setup_order32.exe COM1 [cache|iat] [logfile]
//   It opens the port, starts a write/read loop, and logs its PID so the caller can
//   inject afterwards. Every I/O iteration is logged, so the test can compare what
//   happened before injection with what happened after.
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
    fn WriteFile(h: *mut c_void, buf: *const u8, len: u32, written: *mut u32, ov: *mut c_void) -> i32;
    fn ReadFile(h: *mut c_void, buf: *mut u8, len: u32, read: *mut u32, ov: *mut c_void) -> i32;
    fn Sleep(ms: u32);
    fn GetCurrentProcessId() -> u32;
}

type CreateFileWFn =
    unsafe extern "system" fn(*const u16, u32, u32, *mut c_void, u32, u32, *mut c_void) -> *mut c_void;
type WriteFileFn = unsafe extern "system" fn(*mut c_void, *const u8, u32, *mut u32, *mut c_void) -> i32;
type ReadFileFn = unsafe extern "system" fn(*mut c_void, *mut u8, u32, *mut u32, *mut c_void) -> i32;

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const OPEN_EXISTING: u32 = 3;
const INVALID: isize = -1;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Append one line to the log file.
///
/// Writing to a file explicitly (rather than relying on stdout redirection) keeps the
/// probe launchable by any mechanism: the harness does not need to capture a pipe,
/// which on this machine requires elevation for a 32-bit child.
struct Log {
    path: String,
}

impl Log {
    fn new(path: &str) -> Self {
        let _ = std::fs::remove_file(path);
        Log { path: path.to_string() }
    }
    fn line(&self, text: &str) {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            let _ = writeln!(f, "{text}");
            let _ = f.flush();
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let com = args.get(1).cloned().unwrap_or_else(|| "COM1".into());
    let mode = args.get(2).cloned().unwrap_or_else(|| "cache".into());
    let logfile = args
        .get(3)
        .cloned()
        .unwrap_or_else(|| "setup_order.log".to_string());
    let log = Log::new(&logfile);

    // Cache the pointers BEFORE the port is opened — the worst case for IAT hooking.
    let (create, write, read): (CreateFileWFn, WriteFileFn, ReadFileFn) = if mode == "iat" {
        (CreateFileW, WriteFile, ReadFile)
    } else {
        unsafe {
            let k32 = GetModuleHandleW(wide("kernel32.dll").as_ptr());
            (
                std::mem::transmute(GetProcAddress(k32, b"CreateFileW\0".as_ptr())),
                std::mem::transmute(GetProcAddress(k32, b"WriteFile\0".as_ptr())),
                std::mem::transmute(GetProcAddress(k32, b"ReadFile\0".as_ptr())),
            )
        }
    };

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
        log.line(&format!("setup32: open {com} FAILED"));
        std::process::exit(2);
    }
    let pid = unsafe { GetCurrentProcessId() };
    log.line(&format!(
        "setup32: OPENED {com} handle={h:?} mode={mode} cachedCreateFileW={:#x} PID={pid}",
        create as usize
    ));
    // The test waits for this line before injecting: the port is provably open now.
    log.line("setup32: READY_FOR_INJECTION");

    let mut buf = [0u8; 256];
    for i in 0..80 {
        let msg = format!("ORD{i};");
        let mut wrote = 0u32;
        unsafe {
            write(h, msg.as_ptr(), msg.len() as u32, &mut wrote, std::ptr::null_mut());
        }
        let mut got = 0u32;
        let r = unsafe { read(h, buf.as_mut_ptr(), buf.len() as u32, &mut got, std::ptr::null_mut()) };
        log.line(&format!(
            "setup32: io #{i} wrote={wrote} read_ok={} read={got}",
            if r != 0 { 1 } else { 0 }
        ));
        unsafe { Sleep(250) };
    }
    log.line("setup32: done");
}
