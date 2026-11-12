// Continuous-I/O serial probe for the USER'S ordering.
//
// The other probes do one write and one read, which is not enough to test this
// scenario: by the time the monitor injects, the single I/O has already happened and
// the process is idle, so "nothing captured" proves nothing.
//
// This one opens the port and then keeps writing/reading in a loop for the whole run,
// so any I/O that happens AFTER injection must be visible to the hook.
//
//   order_loop32.exe COM1 <logfile> [gpa|iat]
//
// Log format (one line each):
//   order: OPENED <com> pid=<n> label=<mode>
//   order: io #<i> wrote=<n> read=<n>
//   order: CLOSED
//
// It is modelled on x86_probe (known-injectable in this environment) and deliberately
// writes its log through the ORIGINAL WriteFile pointer rather than std::fs, so the
// probe behaves like a real serial tool and cannot be affected by the hook's state.
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
    fn GetCurrentProcessId() -> u32;
    fn SetCommTimeouts(h: *mut c_void, t: *mut c_void) -> i32;
    fn GetCommTimeouts(h: *mut c_void, t: *mut c_void) -> i32;
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
type CloseHandleFn = unsafe extern "system" fn(*mut c_void) -> i32;

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const OPEN_EXISTING: u32 = 3;
const OPEN_ALWAYS: u32 = 4;
const INVALID: isize = -1;
const FILE_APPEND_DATA: u32 = 0x0004;
const FILE_SHARE_RW: u32 = 0x7;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[repr(C)]
struct CommTimeouts {
    read_interval: u32,
    read_total_multiplier: u32,
    read_total_constant: u32,
    write_total_multiplier: u32,
    write_total_constant: u32,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let com = args.get(1).cloned().unwrap_or_else(|| "COM1".into());
    let logfile = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "order_loop.log".into());
    let mode = args.get(3).cloned().unwrap_or_else(|| "gpa".into());

    let (create, write, read, close): (CreateFileWFn, WriteFileFn, ReadFileFn, CloseHandleFn) =
        if mode == "iat" {
            (CreateFileW, WriteFile, ReadFile, CloseHandle)
        } else {
            unsafe {
                let k32 = GetModuleHandleW(wide("kernel32.dll").as_ptr());
                (
                    std::mem::transmute(GetProcAddress(k32, b"CreateFileW\0".as_ptr())),
                    std::mem::transmute(GetProcAddress(k32, b"WriteFile\0".as_ptr())),
                    std::mem::transmute(GetProcAddress(k32, b"ReadFile\0".as_ptr())),
                    std::mem::transmute(GetProcAddress(k32, b"CloseHandle\0".as_ptr())),
                )
            }
        };

    // Logger through the SAVED pointers, exactly like a real tool would do its own I/O.
    let log_path = wide(&logfile);
    let mut log = String::new();
    let mut emit = |s: &str, log: &mut String| {
        unsafe {
            let h = create(
                log_path.as_ptr(),
                FILE_APPEND_DATA,
                FILE_SHARE_RW,
                std::ptr::null_mut(),
                OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            );
            if h as isize != INVALID {
                let line = format!("{s}\n");
                let mut w = 0u32;
                write(
                    h,
                    line.as_ptr(),
                    line.len() as u32,
                    &mut w,
                    std::ptr::null_mut(),
                );
                close(h);
            }
        }
        log.push_str(s);
        log.push('\n');
        println!("{s}");
    };
    let _ = std::fs::remove_file(&logfile);

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
        emit("order: OPEN FAILED", &mut log);
        std::process::exit(2);
    }
    let pid = unsafe { GetCurrentProcessId() };
    emit(
        &format!(
            "order: OPENED {com} pid={pid} cached={:#x}",
            create as usize
        ),
        &mut log,
    );

    // Short read timeout so the loop advances even when no peer is talking.
    let mut to = CommTimeouts {
        read_interval: 0,
        read_total_multiplier: 0,
        read_total_constant: 50,
        write_total_multiplier: 0,
        write_total_constant: 100,
    };
    unsafe {
        let _ = SetCommTimeouts(h, &mut to as *mut _ as *mut c_void);
        let _ = GetCommTimeouts;
    }

    let mut buf = [0u8; 512];
    // ~40 s of continuous traffic: plenty of time to inject in the middle.
    for i in 0..160u32 {
        let msg = format!("L{i};");
        let mut wrote = 0u32;
        unsafe {
            write(
                h,
                msg.as_ptr(),
                msg.len() as u32,
                &mut wrote,
                std::ptr::null_mut(),
            )
        };
        let mut got = 0u32;
        let ok = unsafe {
            read(
                h,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut got,
                std::ptr::null_mut(),
            )
        };
        emit(
            &format!(
                "order: io #{i} wrote={wrote} read_ok={} read={got}",
                if ok != 0 { 1 } else { 0 }
            ),
            &mut log,
        );
        unsafe { Sleep(250) };
    }
    unsafe { close(h) };
    emit("order: CLOSED", &mut log);
}
