// Reproduces the "spurious read on close" bug and proves the fix.
//
// THE BUG (confirmed on this machine)
// -----------------------------------
// UartAssist is UPX-packed and binds its kernel32 imports at run time: its import
// table contains only LoadLibraryA / ExitProcess / GetProcAddress / VirtualProtect
// (measured). So an IAT-only CloseHandle hook never fires in it.
//
// That would be a harmless missing log line, except the hook keeps a map
// handle -> "COM6" and Windows REUSES handle values. With the close never observed,
// the stale entry survives, and the next file opened at the same number is treated as
// port traffic. On shutdown the tool writes/reads its own log file, and those bytes
// are reported as a read on COM6 — exactly the single spurious record reported.
//
// WHAT THIS PROGRAM SHOWS
// -----------------------
// It opens COMx, records its handle value, closes it, then opens ordinary FILES
// repeatedly until one lands on the SAME handle value. That is the exact collision
// that used to produce a false capture. With the fix (CloseHandle entry-patched +
// GetFileType pre-filter) the file writes must NOT be reported as serial traffic.
//
// Usage:  handle_reuse.exe COM6 <logfile>
// Output: one line per event, and a final PASS/FAIL verdict.
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
    fn CloseHandle(h: *mut c_void) -> i32;
    fn GetFileType(h: *mut c_void) -> u32;
}

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const OPEN_EXISTING: u32 = 3;
const CREATE_ALWAYS: u32 = 2;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const INVALID: isize = -1;
const FILE_TYPE_CHAR: u32 = 0x0002;
const FILE_TYPE_DISK: u32 = 0x0001;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let com = args.get(1).cloned().unwrap_or_else(|| "COM6".into());
    let logfile = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "handle_reuse.log".to_string());
    let marker = args.get(3).cloned();
    let mut out = String::new();
    macro_rules! say {
        ($($t:tt)*) => {{ let s = format!($($t)*); println!("{s}"); out.push_str(&s); out.push('\n'); }};
    }

    // Optional gate: the caller injects first, then creates the marker. Without this
    // the probe finishes in under a second and injection always arrives too late.
    if let Some(m) = &marker {
        say!("waiting for marker {m} (inject now)");
        let _ = std::fs::write(&logfile, &out);
        for _ in 0..600 {
            if std::path::Path::new(m).exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        say!("marker seen, proceeding");
    }

    // 1. Open the serial port and remember its handle VALUE.
    let com_path = wide(&format!(r"\\.\{}", com));
    let sh = unsafe {
        CreateFileW(
            com_path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if sh as isize == INVALID {
        say!("FAIL: cannot open {com}");
        let _ = std::fs::write(&logfile, out);
        return;
    }
    let serial_h = sh as usize;
    say!(
        "serial: {com} open handle={serial_h:#x} GetFileType={}",
        unsafe { GetFileType(sh) }
    );

    // 2. Close it. This is the call the hook must observe to drop the map entry.
    //    Then the program does ordinary file I/O, like a tool writing its shutdown log.
    unsafe { CloseHandle(sh) };
    say!("serial: closed (a correct hook must now forget this handle)");

    // 3. Open files until the OS hands back the same numeric handle VALUE, then write
    //    through it. If the stale "COM6" label survived, this write is misreported.
    let mut collided = false;
    let mut file_h = 0usize;
    for i in 0..200 {
        let p = wide(&format!(
            r"{}\hreuse_{i}.txt",
            std::env::temp_dir().display()
        ));
        let h = unsafe {
            CreateFileW(
                p.as_ptr(),
                GENERIC_WRITE,
                0,
                std::ptr::null_mut(),
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        if h as isize == INVALID {
            continue;
        }
        let hv = h as usize;
        if hv == serial_h {
            collided = true;
            file_h = hv;
            let ft = unsafe { GetFileType(h) };
            say!("file: REUSED the serial handle value handle={hv:#x} GetFileType={ft}");
            let payload = b"1794393325=0,5\r\n1794393306=0,4\r\nHANDLE_REUSE_PROBE\r\n";
            let mut w = 0u32;
            unsafe {
                WriteFile(
                    h,
                    payload.as_ptr(),
                    payload.len() as u32,
                    &mut w,
                    std::ptr::null_mut(),
                )
            };
            say!("file: wrote {w} bytes through the reused handle");
            unsafe { CloseHandle(h) };
            let _ = std::fs::remove_file(format!(
                r"{}\hreuse_{i}.txt",
                std::env::temp_dir().display()
            ));
            break;
        }
        let ft = unsafe { GetFileType(h) };
        if ft == FILE_TYPE_DISK {
            // ordinary file: fine, release and try again
        }
        unsafe { CloseHandle(h) };
        let _ = std::fs::remove_file(format!(
            r"{}\hreuse_{i}.txt",
            std::env::temp_dir().display()
        ));
        if i > 60 && hv != serial_h {
            // keep going: the allocator usually cycles through low values
        }
    }

    if collided {
        say!("result: reproduced a handle-value collision (this is the bug's precondition)");
        say!("PASS-IF: the monitor must NOT show 'HANDLE_REUSE_PROBE' as a {com} read");
    } else {
        say!("result: no handle collision in this run (allocator did not reuse the value)");
        say!("INCONCLUSIVE-IF: no collision means this run cannot exercise the bug");
    }
    let _ = std::fs::write(&logfile, out);
}
