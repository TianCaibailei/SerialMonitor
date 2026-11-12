// monitor_hook — injected into a monitored process by 万能监控 (see src/inject.rs).
//
// PURPOSE
// -------
// The original CommMonitor intercepts serial traffic in a signed kernel filter
// driver (ComDrv12x64.sys) that attaches to the serial device stack with
// IoAttachDeviceToDeviceStack and mirrors every IRP. We cannot ship a kernel driver
// here (no test-signing on the target machine, code-signing enforcement on Win11
// x64), so this DLL reproduces the same *capability* from user space:
//
//   * it never opens the serial port itself, so the monitored program keeps full,
//     exclusive ownership of it — the whole point of a passive monitor;
//   * every port open/read/write/close that program performs passes through a hook;
//   * the original function is always called first and its results are never
//     altered; bytes are only *copied out* afterwards;
//   * captured records stream to the monitor over the named pipe
//     \\.\pipe\monitor_capture.
//
// WHAT IT HOOKS
// -------------
// kernel32 IAT entries of every module in the target process:
//   CreateFileW / CreateFileA          — port opens (handle -> port map)
//   ReadFile / WriteFile               — synchronous + overlapped I/O
//   GetOverlappedResult(Ex)            — overlapped read completions
//   ReadFileEx / WriteFileEx           — completion-routine I/O (Qt, C++ libs)
//   CloseHandle                        — port closes
//   GetProcAddress                     — late binders (.NET P/Invoke, LoadLibrary
//                                        users) that bypass the IAT entirely
//
// HARD-WON INVARIANTS (each of these caused a real failure while developing this):
//   1. Records to the monitor must be written with the ORIGINAL WriteFile pointer
//      saved at start-up. Calling the imported WriteFile from inside a hook whose
//      own IAT is patched re-enters the hook and deadlocks the target process.
//   2. Diagnostics must not use std::fs either, for the same reason; they go
//      through the saved pointers and are opt-in (a marker file in %TEMP%).
//   3. No lock is ever held across a pipe write. A blocked monitor must never
//      block the monitored program's I/O thread.
//   4. A poisoned mutex is recovered, never unwrapped: a panic in one hook thread
//      must not take the host process down with it.
//   5. The handle map caches NON-serial handles too, so ordinary file traffic pays
//      one lock and no system call.

#![allow(non_snake_case)]
// The hook declares every Win32 function it may intercept, plus the struct/layout mirrors
// used by the diagnostics, so some items are unused in any single build configuration.
#![allow(dead_code)]
// The hook patch table stores hook functions as raw addresses (`hook_X as usize`) so the
// inline trampoline can jump to them. Rustc flags each cast ("direct cast of function item
// into an integer"); that is the intended FFI pattern here, so the warning is accepted as
// known noise rather than silenced with a blanket allow.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

const PIPE_NAME: &str = r"\\.\pipe\monitor_capture";

// Record tags — must stay in sync with src/inject.rs.
const TAG_ATTACH: u32 = 1;
const TAG_OPEN: u32 = 2;
const TAG_CLOSE: u32 = 3;
const TAG_RX: u32 = 4;
const TAG_TX: u32 = 5;

const GENERIC_READWRITE: u32 = 0xC000_0000;
const FILE_APPEND_DATA: u32 = 0x0004;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const OPEN_ALWAYS: u32 = 4;
const OPEN_EXISTING: u32 = 3;
const INVALID_HANDLE: isize = -1;
const ERROR_PIPE_BUSY: u32 = 231;
const ERROR_IO_PENDING: u32 = 997;
const PAGE_READWRITE: u32 = 0x04;
const TH32CS_SNAPMODULE: u32 = 0x8;
const FILE_NAME_INFO_CLASS: u32 = 2;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const STATUS_PENDING_ISIZE: isize = 0x103; // OVERLAPPED.Internal while the IRP runs

extern "system" {
    fn GetModuleHandleW(name: *const u16) -> *mut std::ffi::c_void;
    fn GetProcAddress(h: *mut std::ffi::c_void, name: *const u8) -> *mut std::ffi::c_void;
    fn GetCurrentProcessId() -> u32;
    fn VirtualProtect(addr: *mut std::ffi::c_void, size: usize, prot: u32, old: *mut u32) -> i32;
    fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        sa: *mut std::ffi::c_void,
        disp: u32,
        flags: u32,
        tmpl: *mut std::ffi::c_void,
    ) -> *mut std::ffi::c_void;
    fn ReadFile(
        h: *mut std::ffi::c_void,
        buf: *mut u8,
        len: u32,
        read: *mut u32,
        ov: *mut std::ffi::c_void,
    ) -> i32;
    fn WriteFile(
        h: *mut std::ffi::c_void,
        buf: *const u8,
        len: u32,
        written: *mut u32,
        ov: *mut std::ffi::c_void,
    ) -> i32;
    fn CloseHandle(h: *mut std::ffi::c_void) -> i32;
    fn WaitNamedPipeW(name: *const u16, ms: u32) -> i32;
    fn GetLastError() -> u32;
    fn SetLastError(code: u32);
    fn GetFileInformationByHandleEx(
        h: *mut std::ffi::c_void,
        cls: u32,
        info: *mut std::ffi::c_void,
        size: u32,
    ) -> i32;
    fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> *mut std::ffi::c_void;
    fn Module32FirstW(snap: *mut std::ffi::c_void, me: *mut ModuleEntry32W) -> i32;
    fn Module32NextW(snap: *mut std::ffi::c_void, me: *mut ModuleEntry32W) -> i32;
}

#[repr(C)]
struct ModuleEntry32W {
    dwSize: u32,
    th32ModuleID: u32,
    th32ProcessID: u32,
    GlblcntUsage: u32,
    ProccntUsage: u32,
    modBaseAddr: *mut u8,
    modBaseSize: u32,
    hModule: *mut std::ffi::c_void,
    szModule: [u16; 256],
    szExePath: [u16; 260],
}

#[repr(C)]
struct ImportDesc {
    original_first_thunk: u32,
    time_stamp: u32,
    forwarder: u32,
    name_rva: u32,
    first_thunk: u32,
}

struct PipeState {
    h: isize,
}

impl PipeState {
    const fn dead() -> Self {
        PipeState { h: INVALID_HANDLE }
    }
}

// ---------------- state ----------------

/// handle -> Some(port label) for serial handles, None for handles already proven
/// not to be serial ports. The negative entries matter: a program writing its own
/// log files must not pay a GetFileInformationByHandleEx call per write.
static HANDLES: std::sync::LazyLock<Mutex<HashMap<usize, Option<String>>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));
static PIPE: Mutex<PipeState> = Mutex::new(PipeState::dead());

/// OVERLAPPED -> (handle, buffer, length) of reads that returned ERROR_IO_PENDING.
static PENDING_READS: std::sync::LazyLock<Mutex<HashMap<usize, (usize, usize, u32)>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// Context of an in-flight ReadFileEx/WriteFileEx, keyed by the caller's OVERLAPPED.
struct ExContext {
    user_routine: Option<unsafe extern "system" fn(u32, u32, *mut std::ffi::c_void)>,
    handle: usize,
    buf: usize,
    len: u32,
    is_read: bool,
    pub_ov: usize,
}
static EX_CONTEXTS: std::sync::LazyLock<Mutex<HashMap<usize, Box<ExContext>>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

static SELF_BASE: AtomicUsize = AtomicUsize::new(0);
static ORIG_CREATEFILEW: AtomicUsize = AtomicUsize::new(0);
static ORIG_CREATEFILEA: AtomicUsize = AtomicUsize::new(0);
static ORIG_READFILE: AtomicUsize = AtomicUsize::new(0);
static ORIG_WRITEFILE: AtomicUsize = AtomicUsize::new(0);
static ORIG_CLOSEHANDLE: AtomicUsize = AtomicUsize::new(0);
static ORIG_GETPROCADDRESS: AtomicUsize = AtomicUsize::new(0);
static ORIG_GETOVERLAPPEDRESULT: AtomicUsize = AtomicUsize::new(0);
static ORIG_GETOVERLAPPEDRESULTEX: AtomicUsize = AtomicUsize::new(0);
static ORIG_READFILEEX: AtomicUsize = AtomicUsize::new(0);
static ORIG_WRITEFILEEX: AtomicUsize = AtomicUsize::new(0);
static DLL_BASE: AtomicUsize = AtomicUsize::new(0);

// ---------------- poison-proof locks ----------------
//
// A panic in any hook thread must not poison the whole process; the maps are still
// sound after a panic (nothing is left half-mutated), so recovering is correct.

fn handles_lock() -> MutexGuard<'static, HashMap<usize, Option<String>>> {
    match HANDLES.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

fn pipe_lock() -> MutexGuard<'static, PipeState> {
    match PIPE.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

fn pending_lock() -> MutexGuard<'static, HashMap<usize, (usize, usize, u32)>> {
    match PENDING_READS.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

fn ex_lock() -> MutexGuard<'static, HashMap<usize, Box<ExContext>>> {
    match EX_CONTEXTS.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

// ---------------- small helpers ----------------

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_to_string(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut chars = Vec::new();
    let mut i = 0usize;
    unsafe {
        loop {
            let c = *p.add(i);
            if c == 0 || i > 32_768 {
                break;
            }
            chars.push(c);
            i += 1;
        }
    }
    String::from_utf16_lossy(&chars)
}

fn ansi_to_string(p: *const u8) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut bytes = Vec::new();
    let mut i = 0usize;
    unsafe {
        loop {
            let b = *p.add(i);
            if b == 0 || i > 4096 {
                break;
            }
            bytes.push(b);
            i += 1;
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn ansi_is(name: *const u8, s: &[u8]) -> bool {
    if name.is_null() {
        return false;
    }
    let mut i = 0usize;
    unsafe {
        while i < s.len() {
            if *name.add(i) != s[i] {
                return false;
            }
            i += 1;
        }
        *name.add(i) == 0
    }
}

/// "COM6", "\\.\COM6", "COM6:" → Some("COM6").
fn com_port_name(s: &str) -> Option<String> {
    let lower = s.to_lowercase();
    let t = lower.strip_prefix("\\\\.\\").unwrap_or(&lower);
    let t = t.trim_end_matches(':');
    if !t.starts_with("com") || t.len() < 4 || t.len() > 8 {
        return None;
    }
    if t[3..].chars().all(|c| c.is_ascii_digit()) {
        Some(t.to_uppercase())
    } else {
        None
    }
}

/// Device-path fragments that identify a handle as a serial port. The original
/// driver classified by device type (FILE_DEVICE_SERIAL_PORT); from user space we
/// read the device path, so this must cover every driver family that exposes a COM
/// port — not just Microsoft's own "Serial", which is why USB-serial adapters were
/// silently missed by earlier builds.
const SERIAL_PATH_MARKERS: &[&str] = &[
    "\\device\\serial",
    "usbser",
    "prolific",
    "silabser",
    "\\device\\vcp",
    "ftdibus",
    "ftdiser",
    "\\device\\comport",
    "bthmodem",
    "\\device\\vser",
    "\\device\\ttys",
    "cdc_acm",
    "\\device\\aries",
    "\\device\\ch341",
    "\\device\\mct_u232",
    "\\device\\bthfcom",
];

fn is_serial_path(path: &str) -> bool {
    SERIAL_PATH_MARKERS.iter().any(|m| path.contains(m))
}

/// Readable label for a serial device path. Prefers a real "COMn" in the path;
/// otherwise uses the device leaf so a non-COMn virtual port is still routable.
fn serial_label_from_path(path: &str) -> String {
    if let Some(pos) = path.find("com") {
        let rest = &path[pos + 3..];
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !digits.is_empty() {
            return format!("COM{digits}");
        }
    }
    let leaf = path.rsplit('\\').next().unwrap_or(path).trim_end_matches('\0').trim();
    if leaf.is_empty() {
        "COM?".to_string()
    } else {
        leaf.to_uppercase()
    }
}

// ---------------- opt-in diagnostics (never uses std::fs) ----------------

static DBG: AtomicUsize = AtomicUsize::new(0); // 0 unknown, 1 off, 2 on

fn dbg_on() -> bool {
    let st = DBG.load(Ordering::Relaxed);
    if st == 0 {
        let on = std::env::temp_dir().join("um_hook_debug").exists();
        DBG.store(if on { 2 } else { 1 }, Ordering::Relaxed);
        on
    } else {
        st == 2
    }
}

type CreateFileWFn = unsafe extern "system" fn(
    *const u16,
    u32,
    u32,
    *mut std::ffi::c_void,
    u32,
    u32,
    *mut std::ffi::c_void,
) -> *mut std::ffi::c_void;
type CreateFileAFn = unsafe extern "system" fn(
    *const u8,
    u32,
    u32,
    *mut std::ffi::c_void,
    u32,
    u32,
    *mut std::ffi::c_void,
) -> *mut std::ffi::c_void;
type ReadFileFn = unsafe extern "system" fn(
    *mut std::ffi::c_void,
    *mut u8,
    u32,
    *mut u32,
    *mut std::ffi::c_void,
) -> i32;
type WriteFileFn = unsafe extern "system" fn(
    *mut std::ffi::c_void,
    *const u8,
    u32,
    *mut u32,
    *mut std::ffi::c_void,
) -> i32;
type CloseHandleFn = unsafe extern "system" fn(*mut std::ffi::c_void) -> i32;
type GetProcAddressFn = unsafe extern "system" fn(*mut std::ffi::c_void, *const u8) -> *mut std::ffi::c_void;
type GetOverlappedResultFn =
    unsafe extern "system" fn(*mut std::ffi::c_void, *mut std::ffi::c_void, *mut u32, i32) -> i32;
type GetOverlappedResultExFn =
    unsafe extern "system" fn(*mut std::ffi::c_void, *mut std::ffi::c_void, *mut u32, u32, i32) -> i32;
type ReadFileExFn = unsafe extern "system" fn(
    *mut std::ffi::c_void,
    *mut u8,
    u32,
    *mut std::ffi::c_void,
    Option<unsafe extern "system" fn(u32, u32, *mut std::ffi::c_void)>,
) -> i32;
type WriteFileExFn = unsafe extern "system" fn(
    *mut std::ffi::c_void,
    *const u8,
    u32,
    *mut std::ffi::c_void,
    Option<unsafe extern "system" fn(u32, u32, *mut std::ffi::c_void)>,
) -> i32;

/// Append one diagnostic line through the SAVED original pointers (invariant 2).
///
/// Also must use the trampolines: once the entry points are byte-patched, the saved
/// addresses point at our own jump instructions, so calling them would re-enter the
/// hooks (and, with the handle map locked by our caller, deadlock).
fn dbg_note(msg: &str) {
    if !dbg_on() {
        return;
    }
    let create = orig_call_addr(&INLINE_CREATEFILEW, &ORIG_CREATEFILEW);
    let write = orig_call_addr(&INLINE_WRITEFILE, &ORIG_WRITEFILE);
    // Trampoline, not ORIG_CLOSEHANDLE: CloseHandle is entry-patched (see
    // INLINE_CLOSEHANDLE), so the raw pointer now holds our own jump. Calling it would
    // re-enter hook_CloseHandle from inside every diagnostic write — and, worse, would
    // run the hook's map removal while a caller may still be reasoning about that
    // handle. Always go through the trampoline for a function we have patched.
    let close = orig_call_addr(&INLINE_CLOSEHANDLE, &ORIG_CLOSEHANDLE);
    if create == 0 || write == 0 || close == 0 {
        return;
    }
    let path = std::env::temp_dir().join(format!("um_hook_{}.log", unsafe { GetCurrentProcessId() }));
    let wpath = wide(&path.to_string_lossy());
    let cf: CreateFileWFn = unsafe { std::mem::transmute(create) };
    let h = unsafe {
        cf(
            wpath.as_ptr(),
            FILE_APPEND_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null_mut(),
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if h as isize == INVALID_HANDLE {
        return;
    }
    let mut line = String::with_capacity(msg.len() + 2);
    line.push_str(msg);
    line.push_str("\r\n");
    let wf: WriteFileFn = unsafe { std::mem::transmute(write) };
    let mut written = 0u32;
    unsafe {
        wf(h, line.as_ptr(), line.len() as u32, &mut written, std::ptr::null_mut());
        let ch: CloseHandleFn = std::mem::transmute(close);
        ch(h);
    }
}

// ---------------- transport to the monitor ----------------

/// One blocking write of a whole record, through the ORIGINAL WriteFile
/// (invariant 1: the imported one is patched in the target and would re-enter).
fn pipe_write_blocking(payload: &[u8]) -> bool {
    let h = { pipe_lock().h };
    if h == INVALID_HANDLE {
        return false;
    }
    // MUST be the trampoline when the entry point is patched: ORIG_WRITEFILE then
    // points at our own jump, so calling it would re-enter hook_WriteFile and recurse
    // until the stack dies — inside the monitored program.
    let orig = orig_call_addr(&INLINE_WRITEFILE, &ORIG_WRITEFILE);
    if orig == 0 {
        return false;
    }
    let f: WriteFileFn = unsafe { std::mem::transmute(orig) };
    let mut written = 0u32;
    let ok = unsafe {
        f(
            h as *mut std::ffi::c_void,
            payload.as_ptr(),
            payload.len() as u32,
            &mut written,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 || written as usize != payload.len() {
        let mut st = pipe_lock();
        st.h = INVALID_HANDLE;
        return false;
    }
    true
}

/// Wire format: [tag u32][len u32][pid u32][payload].
///
/// No lock is held across the write (invariant 3): a monitor that stops draining
/// slows only this DLL's calling thread, and the pipe write is bounded by the
/// monitor's read loop, not by any lock of ours.
fn send_record(tag: u32, payload: &[u8]) {
    let pid = unsafe { GetCurrentProcessId() };
    let mut msg = Vec::with_capacity(12 + payload.len());
    msg.extend_from_slice(&tag.to_le_bytes());
    msg.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    msg.extend_from_slice(&pid.to_le_bytes());
    msg.extend_from_slice(payload);
    let _ = pipe_write_blocking(&msg);
}

fn send_attach(exe: &str) {
    send_record(TAG_ATTACH, exe.as_bytes());
}

fn send_open(handle: usize, port: &str) {
    let mut p = (handle as u64).to_le_bytes().to_vec();
    p.extend_from_slice(port.as_bytes());
    send_record(TAG_OPEN, &p);
}

fn send_close(handle: usize) {
    send_record(TAG_CLOSE, &(handle as u64).to_le_bytes());
}

fn send_io(tag: u32, handle: usize, data: &[u8]) {
    let mut p = (handle as u64).to_le_bytes().to_vec();
    p.extend_from_slice(data);
    send_record(tag, &p);
}

/// FILE_TYPE_DISK — the classification that keeps ordinary files out of capture.
const FILE_TYPE_DISK: u32 = 0x0001;

/// Look up (and register) the port label for a handle.
///
/// Two ways a serial handle becomes known:
///  1. CreateFileW/A was called *after* injection — the path is right there.
///  2. The handle was opened BEFORE injection — the common case for a tool the user
///     attached to, and the only case that ever needed discovery.
///
/// For case 2 the original implementation asked the object for its name with
/// GetFileInformationByHandleEx(FileNameInfo). MEASURED ON THIS MACHINE, that call
/// FAILS on serial handles with ERROR_INVALID_PARAMETER (87), in both architectures:
///
///   GetFileInformationByHandleEx(FileNameInfo) ok=0 err=87
///   GetFileType = 0x2 (FILE_TYPE_CHAR)
///   IOCTL_SERIAL_GET_COMMSTATUS        ok=1
///
/// So case 2 could never be identified, and because the failure path deliberately
/// does not write the negative cache (a transient failure must not blacklist a
/// handle), every single I/O re-probed, re-failed, and discarded the bytes.
///
/// The fix identifies the port the way a serial API does: query a serial-only IOCTL.
/// Only a real serial device answers IOCTL_SERIAL_GET_COMMSTATUS, which makes it a
/// positive, unambiguous test — no name parsing, no false positives on console
/// handles (which are also FILE_TYPE_CHAR).
///
/// A handle that has been CLOSED is a different matter and is handled separately:
/// Windows reuses handle values, so a stale "this is COM6" entry would mislabel an
/// unrelated file that happens to get the same number. See reuse_guard below.
unsafe fn com_label(h: *mut std::ffi::c_void) -> Option<String> {
    if h.is_null() || h as isize == INVALID_HANDLE {
        return None;
    }
    let key = h as usize;
    match handles_lock().get(&key) {
        Some(Some(label)) => return Some(label.clone()),
        Some(None) => return None, // negatively cached
        None => {}
    }
    // --- case 2: probe the device directly ---
    if let Some(label) = probe_serial_port(h) {
        handles_lock().insert(key, Some(label.clone()));
        dbg_note(&format!("com_label: h={:x} 串口探测命中 {}", key, label));
        send_open(key, &label);
        return Some(label);
    }
    // Not a serial port. Cache it so ordinary file traffic costs one probe, ever.
    //
    // No log line here on purpose: a program touches dozens of ordinary files, and one
    // line per handle drowned the port-open events that actually matter.
    handles_lock().insert(key, None);
    None
}

/// IOCTL_SERIAL_GET_COMMSTATUS — answered only by a serial driver.
const IOCTL_SERIAL_GET_COMMSTATUS: u32 = 0x001B_0058;

extern "system" {
    fn DeviceIoControl(
        h: *mut std::ffi::c_void,
        code: u32,
        inbuf: *mut std::ffi::c_void,
        insize: u32,
        outbuf: *mut std::ffi::c_void,
        outsize: u32,
        ret: *mut u32,
        ov: *mut std::ffi::c_void,
    ) -> i32;
    /// DOS device name of a COM port, e.g. `\\.\COM6` -> `\Device\VSerial8_2`.
    /// This only reads the device map; it does NOT open the port.
    fn QueryDosDeviceW(name: *const u16, target: *mut u16, max: u32) -> u32;
    /// Cheap handle classification: FILE_TYPE_DISK(1), FILE_TYPE_CHAR(2),
    /// FILE_TYPE_PIPE(3). Costs a syscall, so it is only consulted for handles the
    /// probe is about to test anyway.
    fn GetFileType(h: *mut std::ffi::c_void) -> u32;
    fn NtQueryObject(
        h: *mut std::ffi::c_void,
        class: u32,
        info: *mut std::ffi::c_void,
        len: u32,
        ret: *mut u32,
    ) -> i32;
}

/// Is this handle a serial port, and which COM number is it?
///
/// `IOCTL_SERIAL_GET_COMMSTATUS` is the discriminator: a console handle, a pipe, or
/// a file does not answer it, while every serial driver does. That makes it a
/// positive, unambiguous test — no name guessing, no false positives on
/// FILE_TYPE_CHAR handles like conhost's.
///
/// The label has to be "COM6" (not "\Device\VSerial8_2") because that is what the
/// session's channel is named, and routing matches on it.
unsafe fn probe_serial_port(h: *mut std::ffi::c_void) -> Option<String> {
    // Cheap pre-filter first: a disk file can never be a serial port, and this saves
    // the IOCTL on the (very common) case of a program reading its own log or config.
    // MEASURED: serial = FILE_TYPE_CHAR(2), disk file = FILE_TYPE_DISK(1).
    if GetFileType(h) == FILE_TYPE_DISK {
        return None;
    }
    let mut status = [0u8; 32];
    let mut ret = 0u32;
    let ok = DeviceIoControl(
        h,
        IOCTL_SERIAL_GET_COMMSTATUS,
        std::ptr::null_mut(),
        0,
        status.as_mut_ptr() as *mut std::ffi::c_void,
        status.len() as u32,
        &mut ret,
        std::ptr::null_mut(),
    );
    if ok == 0 {
        return None; // not a serial port
    }
    // Resolve the device path of THIS handle, then translate it to a COM number.
    //
    // NtQueryObject is safe here because the handle is our own, in our own process:
    // the well-known way it deadlocks is when it is called on another process's file
    // handle that has a pending I/O. A serial device object answers immediately.
    let device = object_device_name(h);
    if let Some(dev) = &device {
        if let Some(com) = com_number_for_device(dev) {
            return Some(com);
        }
    }
    // Could not name it: use a stable per-device label so captured bytes still reach
    // a channel instead of being dropped.
    let label = device
        .as_deref()
        .map(serial_label_from_path)
        .filter(|s| !s.is_empty());
    Some(label.unwrap_or_else(|| "COM?".to_string()))
}

/// `\Device\VSerial8_2` for a device handle, via NtQueryObject.
unsafe fn object_device_name(h: *mut std::ffi::c_void) -> Option<String> {
    let mut buf = [0u8; 1024];
    let mut ret = 0u32;
    let st = NtQueryObject(
        h,
        1, // ObjectNameInformation
        buf.as_mut_ptr() as *mut std::ffi::c_void,
        buf.len() as u32,
        &mut ret,
    );
    if st < 0 {
        return None;
    }
    // UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer; }
    //
    // Buffer follows the two USHORTs and is pointer-aligned, so its offset is
    // round_up(4, sizeof(usize)): 8 on x64, 4 on x86 — i.e. exactly sizeof(usize).
    // Hand-picked indices would silently read the wrong bytes on the other
    // architecture, and this code is compiled for both.
    let len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    if len == 0 || len > 512 {
        return None;
    }
    let buf_off = std::mem::size_of::<usize>();
    let ptr = *(buf.as_ptr().add(buf_off) as *const usize);
    if ptr == 0 {
        return None;
    }
    let mut units = Vec::with_capacity(len / 2);
    for i in 0..(len / 2) {
        units.push(*(ptr as *const u16).add(i));
    }
    // NtQueryObject returns the NT object path (`\Device\VSerial8_0`); strip any
    // trailing NUL/space so it compares equal to what QueryDosDevice reports.
    let s = String::from_utf16_lossy(&units);
    Some(s.trim_end_matches(['\0', ' ']).to_lowercase())
}

/// Translate `\device\vserial8_2` to `COM6` via the DOS device map.
///
/// MEASURED: the bare name works and the `\\.\`-prefixed form does not.
///
///   QueryDosDevice("COM1")     -> "\Device\VSerial8_0"
///   QueryDosDevice("\\.\COM1") -> (fails)
///
/// Reading this table never opens or disturbs a port, which is what a passive
/// monitor requires. The result also carries a trailing space, hence the trim.
unsafe fn com_number_for_device(device: &str) -> Option<String> {
    let want = device.trim_end_matches(['\0', ' ']);
    for n in 1..=256u32 {
        let mut target = [0u16; 512];
        let len = QueryDosDeviceW(wide(&format!("COM{n}")).as_ptr(), target.as_mut_ptr(), 512) as usize;
        if len == 0 {
            continue;
        }
        let name = String::from_utf16_lossy(&target[..len.saturating_sub(1)]).to_lowercase();
        if name.trim_end_matches(['\0', ' ']) == want {
            return Some(format!("COM{n}"));
        }
    }
    None
}


// ---------------- I/O hooks ----------------

unsafe extern "system" fn hook_CreateFileW(
    name: *const u16,
    access: u32,
    share: u32,
    sa: *mut std::ffi::c_void,
    disp: u32,
    flags: u32,
    tmpl: *mut std::ffi::c_void,
) -> *mut std::ffi::c_void {
    let f: CreateFileWFn =
        std::mem::transmute(orig_call_addr(&INLINE_CREATEFILEW, &ORIG_CREATEFILEW));
    let h = f(name, access, share, sa, disp, flags, tmpl);
    // Diagnostic: every port open the target performs, whether or not it is a serial
    // device. Kept because "the hook is loaded but the program never opened anything"
    // and "it opened a path we did not classify as serial" look identical without it.
    dbg_note(&format!("createfilew: {:?} -> h={:x}", wide_to_string(name), h as usize));
    let err = GetLastError(); // .NET and others inspect it right after we return
    if h as isize != INVALID_HANDLE {
        let s = wide_to_string(name);
        if let Some(port) = com_port_name(&s) {
            handles_lock().insert(h as usize, Some(port.clone()));
            send_open(h as usize, &port);
            dbg_note(&format!("cfw: {} -> h={:x}", s, h as usize));
        }
    }
    SetLastError(err);
    h
}

unsafe extern "system" fn hook_CreateFileA(
    name: *const u8,
    access: u32,
    share: u32,
    sa: *mut std::ffi::c_void,
    disp: u32,
    flags: u32,
    tmpl: *mut std::ffi::c_void,
) -> *mut std::ffi::c_void {
    // Trampoline, not the raw pointer: CreateFileA is entry-patched too, so calling
    // ORIG_CREATEFILEA directly would re-enter this hook.
    let f: CreateFileAFn =
        std::mem::transmute(orig_call_addr(&INLINE_CREATEFILEA, &ORIG_CREATEFILEA));
    let h = f(name, access, share, sa, disp, flags, tmpl);
    let err = GetLastError();
    if h as isize != INVALID_HANDLE {
        let s = ansi_to_string(name);
        if let Some(port) = com_port_name(&s) {
            handles_lock().insert(h as usize, Some(port.clone()));
            send_open(h as usize, &port);
            dbg_note(&format!("cfa: {} -> h={:x}", s, h as usize));
        }
    }
    SetLastError(err);
    h
}

/// Address to call for the original function: the trampoline when an inline patch is
/// installed (the real prologue now jumps to us, so calling it would recurse), else the
/// plain address resolved at start-up.
#[inline]
fn orig_call_addr(slot: &PatchSlot, fallback: &AtomicUsize) -> usize {
    let t = slot.trampoline.load(Ordering::Relaxed);
    if t != 0 {
        t
    } else {
        fallback.load(Ordering::Relaxed)
    }
}

unsafe extern "system" fn hook_ReadFile(
    h: *mut std::ffi::c_void,
    buf: *mut u8,
    len: u32,
    read: *mut u32,
    ov: *mut std::ffi::c_void,
) -> i32 {
    let f: ReadFileFn =
        std::mem::transmute(orig_call_addr(&INLINE_READFILE, &ORIG_READFILE));
    let ok = f(h, buf, len, read, ov);
    let err = GetLastError();
    if ok != 0 {
        let n = if read.is_null() { len } else { *read };
        if n > 0 && com_label(h).is_some() {
            let data = std::slice::from_raw_parts(buf, n as usize).to_vec();
            send_io(TAG_RX, h as usize, &data);
        }
    } else if err == ERROR_IO_PENDING && !ov.is_null() {
        // Overlapped read: bytes are known only when the app observes completion.
        let inserted = {
            let mut m = pending_lock();
            if m.len() < 512 {
                m.insert(ov as usize, (h as usize, buf as usize, len));
                true
            } else {
                false
            }
        };
        if inserted {
            let ov_addr = ov as usize;
            std::thread::spawn(move || watch_pending_read(ov_addr));
        }
    }
    SetLastError(err);
    ok
}

/// Completion watcher for one overlapped read. .NET's SerialStream waits on the
/// OVERLAPPED's event and reads InternalHigh instead of calling GetOverlappedResult,
/// so the only universal completion signal is the OVERLAPPED itself: Internal moves
/// from STATUS_PENDING to the final NTSTATUS. The event handle is never touched
/// (it may be auto-reset and consuming it would break the caller).
fn watch_pending_read(ov: usize) {
    let ovp = ov as *const u64; // Internal at +0, InternalHigh at +8
    let start = std::time::Instant::now();
    loop {
        let status = unsafe { *(ovp as *const isize) };
        if status != STATUS_PENDING_ISIZE {
            break;
        }
        if start.elapsed() > std::time::Duration::from_secs(60) {
            return; // abandoned I/O — leave the entry for CloseHandle cleanup
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    let n = unsafe { *ovp.offset(1) as usize };
    let entry = pending_lock().remove(&ov);
    if let Some((shandle, sbuf, slen)) = entry {
        if n > 0 && n <= slen as usize {
            let hp = shandle as *mut std::ffi::c_void;
            if unsafe { com_label(hp) }.is_some() {
                let data = unsafe { std::slice::from_raw_parts(sbuf as *const u8, n) }.to_vec();
                send_io(TAG_RX, shandle, &data);
            }
        }
    }
}

unsafe extern "system" fn hook_WriteFile(
    h: *mut std::ffi::c_void,
    buf: *const u8,
    len: u32,
    written: *mut u32,
    ov: *mut std::ffi::c_void,
) -> i32 {
    let f: WriteFileFn =
        std::mem::transmute(orig_call_addr(&INLINE_WRITEFILE, &ORIG_WRITEFILE));
    let ok = f(h, buf, len, written, ov);
    let err = GetLastError();
    if ok != 0 {
        let n = if written.is_null() { len } else { *written };
        if n > 0 && com_label(h).is_some() {
            let data = std::slice::from_raw_parts(buf, n as usize).to_vec();
            send_io(TAG_TX, h as usize, &data);
        }
    } else if err == ERROR_IO_PENDING && len > 0 {
        // Overlapped write: the bytes are known now and the buffer stays valid
        // until the caller observes completion.
        if com_label(h).is_some() {
            let data = std::slice::from_raw_parts(buf, len as usize).to_vec();
            send_io(TAG_TX, h as usize, &data);
        }
    }
    SetLastError(err);
    ok
}

unsafe extern "system" fn hook_GetOverlappedResult(
    h: *mut std::ffi::c_void,
    ov: *mut std::ffi::c_void,
    bytes: *mut u32,
    wait: i32,
) -> i32 {
    let f: GetOverlappedResultFn = std::mem::transmute(ORIG_GETOVERLAPPEDRESULT.load(Ordering::Relaxed));
    let ok = f(h, ov, bytes, wait);
    let err = GetLastError();
    if ok != 0 && !ov.is_null() {
        let stored = pending_lock().remove(&(ov as usize));
        if let Some((shandle, sbuf, _len)) = stored {
            let n = if bytes.is_null() { 0 } else { *bytes } as usize;
            if n > 0 && shandle == h as usize && com_label(h).is_some() {
                let data = std::slice::from_raw_parts(sbuf as *const u8, n).to_vec();
                send_io(TAG_RX, h as usize, &data);
            }
        }
    }
    SetLastError(err);
    ok
}

unsafe extern "system" fn hook_GetOverlappedResultEx(
    h: *mut std::ffi::c_void,
    ov: *mut std::ffi::c_void,
    bytes: *mut u32,
    ms: u32,
    alertable: i32,
) -> i32 {
    let f: GetOverlappedResultExFn = std::mem::transmute(ORIG_GETOVERLAPPEDRESULTEX.load(Ordering::Relaxed));
    let ok = f(h, ov, bytes, ms, alertable);
    let err = GetLastError();
    if ok != 0 && !ov.is_null() {
        let stored = pending_lock().remove(&(ov as usize));
        if let Some((shandle, sbuf, _len)) = stored {
            let n = if bytes.is_null() { 0 } else { *bytes } as usize;
            if n > 0 && shandle == h as usize && com_label(h).is_some() {
                let data = std::slice::from_raw_parts(sbuf as *const u8, n).to_vec();
                send_io(TAG_RX, h as usize, &data);
            }
        }
    }
    SetLastError(err);
    ok
}

// ---------------- completion-routine I/O (ReadFileEx / WriteFileEx) ----------------
//
// Qt's QSerialPort and several industrial C++ libraries use this pair: the call
// queues the I/O and the bytes are only known inside the caller's completion
// routine, which Windows runs on the thread that entered an alertable wait.
//
// We must not replace that routine (the app depends on it), so each call registers
// a small context carrying the caller's routine, then our own routine runs first,
// copies the bytes out, and forwards to theirs with their own OVERLAPPED.

unsafe extern "system" fn ex_completion(error: u32, transferred: u32, ov: *mut std::ffi::c_void) {
    let ctx = ex_lock().remove(&(ov as usize));
    let (user, handle, buf, len, is_read, pub_ov) = match ctx {
        Some(c) => (c.user_routine, c.handle, c.buf, c.len, c.is_read, c.pub_ov),
        None => (None, 0, 0, 0, false, 0),
    };
    if error == 0 && transferred > 0 && handle != 0 {
        let n = (transferred as usize).min(len as usize);
        if n > 0 && com_label(handle as *mut std::ffi::c_void).is_some() {
            let data = std::slice::from_raw_parts(buf as *const u8, n).to_vec();
            let tag = if is_read { TAG_RX } else { TAG_TX };
            send_io(tag, handle, &data);
        }
    }
    if let Some(f) = user {
        f(error, transferred, pub_ov as *mut std::ffi::c_void);
    }
}

unsafe extern "system" fn hook_ReadFileEx(
    h: *mut std::ffi::c_void,
    buf: *mut u8,
    len: u32,
    ov: *mut std::ffi::c_void,
    completion: Option<unsafe extern "system" fn(u32, u32, *mut std::ffi::c_void)>,
) -> i32 {
    // Trampoline, not the raw pointer: these entries are patched too.
    let orig = orig_call_addr(&INLINE_READFILEEX, &ORIG_READFILEEX);
    let f: ReadFileExFn = std::mem::transmute(orig);
    // Non-serial handles go straight through with the caller's own routine: no
    // allocation and no context, so ordinary async file I/O is untouched.
    if ov.is_null() || com_label(h).is_none() {
        return f(h, buf, len, ov, completion);
    }
    ex_lock().insert(
        ov as usize,
        Box::new(ExContext {
            user_routine: completion,
            handle: h as usize,
            buf: buf as usize,
            len,
            is_read: true,
            pub_ov: ov as usize,
        }),
    );
    let ok = f(h, buf, len, ov, Some(ex_completion));
    if ok == 0 {
        ex_lock().remove(&(ov as usize)); // I/O never started: don't leak the context
    }
    ok
}

unsafe extern "system" fn hook_WriteFileEx(
    h: *mut std::ffi::c_void,
    buf: *const u8,
    len: u32,
    ov: *mut std::ffi::c_void,
    completion: Option<unsafe extern "system" fn(u32, u32, *mut std::ffi::c_void)>,
) -> i32 {
    // Trampoline, not the raw pointer: these entries are patched too.
    let orig = orig_call_addr(&INLINE_WRITEFILEEX, &ORIG_WRITEFILEEX);
    let f: WriteFileExFn = std::mem::transmute(orig);
    if ov.is_null() || com_label(h).is_none() {
        return f(h, buf, len, ov, completion);
    }
    ex_lock().insert(
        ov as usize,
        Box::new(ExContext {
            user_routine: completion,
            handle: h as usize,
            buf: buf as usize,
            len,
            is_read: false,
            pub_ov: ov as usize,
        }),
    );
    let ok = f(h, buf, len, ov, Some(ex_completion));
    if ok == 0 {
        ex_lock().remove(&(ov as usize));
    }
    ok
}

unsafe extern "system" fn hook_CloseHandle(h: *mut std::ffi::c_void) -> i32 {
    // Remove the handle from BOTH caches before it is released, so its number can be
    // reused by an unrelated file without inheriting the serial label.
    let had = handles_lock().remove(&(h as usize));
    if matches!(had, Some(Some(_))) {
        send_close(h as usize);
    }
    pending_lock().retain(|_, v| v.0 != h as usize);
    // Trampoline, not the raw pointer: CloseHandle is entry-patched too, so calling
    // ORIG_CLOSEHANDLE directly would re-enter this hook forever.
    let f: CloseHandleFn = std::mem::transmute(orig_call_addr(&INLINE_CLOSEHANDLE, &ORIG_CLOSEHANDLE));
    f(h)
}

/// Late binders (LoadLibrary + GetProcAddress callers such as .NET P/Invoke) bypass
/// the IAT because they keep the resolved address. Substituting the hooked addresses
/// in this result makes them land in the hooks too. Matching is by address, so name
/// and ordinal forms both work.
unsafe extern "system" fn hook_GetProcAddress(
    h: *mut std::ffi::c_void,
    name: *const u8,
) -> *mut std::ffi::c_void {
    let f: GetProcAddressFn = std::mem::transmute(ORIG_GETPROCADDRESS.load(Ordering::Relaxed));
    let r = f(h, name);
    let err = GetLastError();
    let raddr = r as usize;
    if raddr != 0 {
        // Only exact matches against the addresses we actually resolved: a lookup
        // of an unrelated symbol is passed through untouched.
        let subs: [(usize, usize); 10] = [
            (ORIG_CREATEFILEW.load(Ordering::Relaxed), hook_CreateFileW as usize),
            (ORIG_CREATEFILEA.load(Ordering::Relaxed), hook_CreateFileA as usize),
            (ORIG_READFILE.load(Ordering::Relaxed), hook_ReadFile as usize),
            (ORIG_WRITEFILE.load(Ordering::Relaxed), hook_WriteFile as usize),
            (ORIG_CLOSEHANDLE.load(Ordering::Relaxed), hook_CloseHandle as usize),
            (ORIG_GETOVERLAPPEDRESULT.load(Ordering::Relaxed), hook_GetOverlappedResult as usize),
            (ORIG_GETOVERLAPPEDRESULTEX.load(Ordering::Relaxed), hook_GetOverlappedResultEx as usize),
            (ORIG_READFILEEX.load(Ordering::Relaxed), hook_ReadFileEx as usize),
            (ORIG_WRITEFILEEX.load(Ordering::Relaxed), hook_WriteFileEx as usize),
            (0, 0),
        ];
        for (orig, hook) in subs {
            if orig != 0 && raddr == orig {
                SetLastError(err);
                return hook as *mut std::ffi::c_void;
            }
        }
        let _ = ansi_is(name, b""); // keep the import used without changing behaviour
    }
    SetLastError(err);
    r
}

// ---------------- IAT patching ----------------

unsafe fn resolve_kernel32(name: &[u8]) -> usize {
    let k32 = wide("kernel32.dll");
    let h = GetModuleHandleW(k32.as_ptr());
    if h.is_null() {
        return 0;
    }
    let mut cname = name.to_vec();
    cname.push(0);
    GetProcAddress(h, cname.as_ptr()) as usize
}

/// Offset of the Import Directory entry inside the Optional Header.
///
/// This MUST depend on the image's own optional-header magic, not on the build
/// architecture of this DLL:
///
///   PE32  (magic 0x10B, every 32-bit module)  → 96 + 1*8  = 104
///   PE32+ (magic 0x20B, every 64-bit module)  → 112 + 1*8 = 120
///
/// DataDirectory[1] is the import table; each entry is 8 bytes.
///
/// History: this used to hard-code the PE32+ offset behind a `if magic != 0x20B
/// { return; }` guard. Inside a WOW64 target *every* module is PE32, so the guard
/// skipped every single module and the injected hook patched nothing at all — the
/// DLL loaded, logged "patched" and stayed silent forever. That is exactly the
/// "32-bit injection succeeds but nothing is ever captured" failure.
///
/// Returns None for an optional header this code does not understand.
unsafe fn import_dir_offset(opt: *const u8) -> Option<isize> {
    let magic = *(opt as *const u16);
    let dd = match magic {
        0x10B => 96,  // PE32
        0x20B => 112, // PE32+
        _ => return None,
    };
    Some(dd + 8) // DataDirectory[0] is the export table, [1] is imports
}

unsafe fn patch_iat(base: *mut u8, targets: &[(usize, usize)]) {
    if base.is_null() {
        return;
    }
    if base as usize == SELF_BASE.load(Ordering::Relaxed) {
        return; // never hook our own imports (invariant 1)
    }
    let e_lfanew = *(base.offset(0x3C) as *const u32) as isize;
    let opt = base.offset(e_lfanew).offset(0x18);
    let Some(imp_off) = import_dir_offset(opt) else {
        return; // unrecognised optional header: leave the module alone
    };
    let imp_rva = *(opt.offset(imp_off) as *const u32) as isize;
    if imp_rva == 0 {
        return;
    }
    let mut desc = base.offset(imp_rva) as *const ImportDesc;
    let mut guard = 0usize;
    while (*desc).original_first_thunk != 0 && guard < 4096 {
        guard += 1;
        let mut iat = base.offset((*desc).first_thunk as isize) as *mut usize;
        let mut g2 = 0usize;
        while *iat != 0 && g2 < 65536 {
            g2 += 1;
            for (orig, hook) in targets {
                if *orig != 0 && *iat == *orig {
                    let mut old = 0u32;
                    if VirtualProtect(iat as _, 8, PAGE_READWRITE, &mut old) != 0 {
                        *iat = *hook;
                        VirtualProtect(iat as _, 8, old, &mut old);
                    }
                }
            }
            iat = iat.offset(1);
        }
        desc = desc.offset(1);
    }
}

// ---------------- byte-level entry patching ----------------
//
// WHY THIS IS THE LOAD-BEARING MECHANISM
// --------------------------------------
// IAT hooking only redirects calls that go through a module's import slot, and
// GetProcAddress hooking only redirects bindings made *after* injection. Neither
// helps the case that actually matters here:
//
//   a serial tool started BEFORE the monitor, which resolved its kernel32 pointers
//   at start-up and keeps them in its own table.
//
// The tool the user reported (UartAssist) is the extreme version of this: it is
// UPX-packed and its KERNEL32 import table contains only
//     LoadLibraryA, ExitProcess, GetProcAddress, VirtualProtect
// — no CreateFileW / ReadFile / WriteFile at all. It binds them at runtime with
// GetProcAddress and caches the results. Measured on this machine:
//
//   UPX0 va=001C7000 vs=1C7000 rs=0   ← unpacking target, empty on disk
//   UPX1 va=001C8000 vs=9C000  rs=9BA00 entropy 8.00
//
// For a target like that the ONLY thing that works is overwriting the first bytes
// of the real kernel32 functions: whatever address the caller cached, it points at
// the same entry point, and that entry point now jumps to us.
//
// WHAT IS PATCHED, AND WHY ONLY THAT SHAPE
// ----------------------------------------
// kernel32's file APIs are API-set forwarder stubs. Measured in BOTH architectures
// on this machine:
//
//   x64  CreateFileW  0x7ffe28cd72c0  FF 25 E2 3C 03 00 CC CC CC ...
//   x86  CreateFileW  0x75dcea50      FF 25 74 12 E3 75 CC CC CC ...
//
// i.e. a 6-byte `FF 25 <disp>` indirect jump followed by int3 padding up to the next
// export. Every other prologue shape is refused: displacing instructions this code
// has not decoded would corrupt the function, and a crash inside the monitored
// program is far worse than missing a capture.
//
// The patch does not need a register (the arguments are already in rcx/rdx/r8/r9 on
// x64 and on the stack on x86), so it jumps through a pointer stored in the stub's
// own int3 padding:
//
//   target+0 .. +6   FF 25 <disp>        ; jmp [target+8]
//   target+8 .. +8+W the absolute hook address (W = 8 on x64, 4 on x86)
//
// Placing the pointer inside the padding is what makes this portable: the old code
// jumped through a pointer in the trampoline with a RIP-relative disp32, which only
// works when VirtualAlloc happens to return memory within ±2 GB of kernel32 — it
// usually does not. It is also why the previous version silently did nothing useful
// for longer prologues.
const PATCH_LEN: usize = 6;

#[repr(C)]
struct PatchSlot {
    target: AtomicUsize,
    trampoline: AtomicUsize,
}

static INLINE_CREATEFILEW: PatchSlot =
    PatchSlot { target: AtomicUsize::new(0), trampoline: AtomicUsize::new(0) };
static INLINE_CREATEFILEA: PatchSlot =
    PatchSlot { target: AtomicUsize::new(0), trampoline: AtomicUsize::new(0) };
static INLINE_READFILE: PatchSlot =
    PatchSlot { target: AtomicUsize::new(0), trampoline: AtomicUsize::new(0) };
static INLINE_WRITEFILE: PatchSlot =
    PatchSlot { target: AtomicUsize::new(0), trampoline: AtomicUsize::new(0) };
static INLINE_READFILEEX: PatchSlot =
    PatchSlot { target: AtomicUsize::new(0), trampoline: AtomicUsize::new(0) };
static INLINE_WRITEFILEEX: PatchSlot =
    PatchSlot { target: AtomicUsize::new(0), trampoline: AtomicUsize::new(0) };
/// CloseHandle MUST be entry-patched, not merely IAT-hooked.
///
/// A target that binds its imports at run time (UartAssist: UPX-packed, its
/// KERNEL32 import table holds only LoadLibraryA/ExitProcess/GetProcAddress/
/// VirtualProtect) never goes through any IAT slot, so the IAT hook for CloseHandle
/// never fires. The consequence is not a missed log line: the handle→port entry is
/// never removed from HANDLES, and because Windows reuses handle VALUES, a later file
/// opened at the same number inherits the stale "COM6" label. Its bytes are then
/// reported as serial traffic on that port.
///
/// That is exactly the reported symptom: closing the program produced one spurious
/// read whose content was the program's own log file.
static INLINE_CLOSEHANDLE: PatchSlot =
    PatchSlot { target: AtomicUsize::new(0), trampoline: AtomicUsize::new(0) };

extern "system" {
    fn VirtualAlloc(addr: *mut std::ffi::c_void, size: usize, ty: u32, protect: u32) -> *mut std::ffi::c_void;
    fn FlushInstructionCache(
        process: *mut std::ffi::c_void,
        addr: *const std::ffi::c_void,
        size: usize,
    ) -> i32;
    fn GetCurrentProcess() -> *mut std::ffi::c_void;
}

const MEM_COMMIT_RESERVE: u32 = 0x3000;
const PAGE_EXECUTE_READWRITE_INLINE: u32 = 0x40;
const PAGE_EXECUTE_READ_INLINE: u32 = 0x20;

/// Wide enough for the absolute pointer the patch stores after the jump.
const PTR_LEN: usize = std::mem::size_of::<usize>();
/// Bytes the target patch occupies: 6-byte jump + 2 alignment bytes + the pointer.
const PATCH_TOTAL: usize = 8 + PTR_LEN;

/// Is this the 6-byte `FF 25` indirect-jump forwarder, with enough int3 padding
/// after it to hold our pointer without touching the next export?
unsafe fn is_patchable_prologue(p: *const u8) -> bool {
    if *p != 0xFF || *p.add(1) != 0x25 {
        return false; // not the forwarder shape we know how to displace
    }
    // The pointer goes at +8, so +6..+8+P must all be padding.
    for i in PATCH_LEN..PATCH_TOTAL {
        if *p.add(i) != 0xCC {
            return false; // not padding: patching here could clobber real code
        }
    }
    true
}

/// Read the address a forwarder stub actually calls.
///
/// x64 stub: `FF 25 rel32` — jmp qword ptr [rip+rel32], rip = address of next insn.
/// x86 stub: `FF 25 abs32` — jmp dword ptr [abs32], the operand IS the slot address.
///
/// These must not be confused: treating the x86 form as RIP-relative reads a garbage
/// address and the trampoline jumps into nowhere.
unsafe fn resolve_forwarder(p: *const u8) -> usize {
    #[cfg(target_pointer_width = "64")]
    {
        let rel = i32::from_le_bytes([*p.add(2), *p.add(3), *p.add(4), *p.add(5)]) as isize;
        let slot = (p as isize) + 6 + rel;
        *(slot as *const usize)
    }
    #[cfg(target_pointer_width = "32")]
    {
        let slot = u32::from_le_bytes([*p.add(2), *p.add(3), *p.add(4), *p.add(5)]) as usize;
        *(slot as *const usize)
    }
}

/// Build a trampoline that jumps to `dest` without touching any register.
///
/// x64: `FF 25 00 00 00 00` (jmp qword ptr [rip+0]) followed by the 8-byte address —
///      14 bytes, position independent, no register clobbered.
/// x86: `68 <imm32> C3` (push imm32; ret) — 6 bytes. Equivalent to a jump and the
///      stack ends up exactly as it was, so the callee's return still works.
unsafe fn write_trampoline(tramp: *mut u8, dest: usize) -> usize {
    #[cfg(target_pointer_width = "64")]
    {
        tramp.write(0xFF);
        tramp.add(1).write(0x25);
        tramp.add(2).write(0x00);
        tramp.add(3).write(0x00);
        tramp.add(4).write(0x00);
        tramp.add(5).write(0x00);
        std::ptr::write_unaligned(tramp.add(6) as *mut u64, dest as u64);
        14
    }
    #[cfg(target_pointer_width = "32")]
    {
        tramp.write(0x68); // push imm32
        std::ptr::write_unaligned(tramp.add(1) as *mut u32, dest as u32);
        tramp.add(5).write(0xC3); // ret
        6
    }
}

/// Install `hook` at `target`, preserving the original destination in a trampoline.
///
/// Returns the trampoline address (what callers must use to reach the real function),
/// or 0 when the patch was refused. Idempotent: calling it twice returns the existing
/// trampoline instead of re-patching an already patched entry point.
unsafe fn patch_entry(target: usize, hook: usize, slot: &PatchSlot) -> usize {
    if target == 0 || hook == 0 {
        return 0;
    }
    // Already installed: the prologue now looks patchable too, so without this guard a
    // second call would displace our own jump and break the trampoline. This matters
    // because worker() and the re-patch loop both run.
    let existing = slot.trampoline.load(Ordering::Relaxed);
    if existing != 0 {
        return existing;
    }
    let p = target as *const u8;
    if !is_patchable_prologue(p) {
        dbg_note(&format!(
            "inline: 拒绝 patch {target:#x}, 前16字节 = {:02X?}",
            unsafe { std::slice::from_raw_parts(p, 16) }
        ));
        return 0;
    }
    let dest = resolve_forwarder(p);
    if dest == 0 {
        dbg_note(&format!("inline: {target:#x} 转发目标为 0，放弃"));
        return 0;
    }

    let tramp = VirtualAlloc(
        std::ptr::null_mut(),
        64,
        MEM_COMMIT_RESERVE,
        PAGE_EXECUTE_READWRITE_INLINE,
    ) as *mut u8;
    if tramp.is_null() {
        return 0;
    }
    let n = write_trampoline(tramp, dest);

    // Overwrite the stub: jump through the pointer we place in its own padding.
    let slot_addr = target + 8;
    let mut old = 0u32;
    if VirtualProtect(
        target as *mut std::ffi::c_void,
        PATCH_TOTAL,
        PAGE_EXECUTE_READWRITE_INLINE,
        &mut old,
    ) == 0
    {
        return 0;
    }
    std::ptr::write_unaligned(slot_addr as *mut usize, hook);

    let mut jmp = [0u8; PATCH_LEN];
    jmp[0] = 0xFF;
    jmp[1] = 0x25;
    #[cfg(target_pointer_width = "64")]
    {
        // RIP-relative: the next instruction starts at target+6, the slot is at target+8.
        let disp: i32 = 2;
        jmp[2..6].copy_from_slice(&disp.to_le_bytes());
    }
    #[cfg(target_pointer_width = "32")]
    {
        // Absolute: the operand is the address of the pointer itself.
        jmp[2..6].copy_from_slice(&(slot_addr as u32).to_le_bytes());
    }
    std::ptr::copy_nonoverlapping(jmp.as_ptr(), target as *mut u8, PATCH_LEN);

    let mut rel = 0u32;
    VirtualProtect(
        target as *mut std::ffi::c_void,
        PATCH_TOTAL,
        old.max(PAGE_EXECUTE_READ_INLINE),
        &mut rel,
    );
    FlushInstructionCache(GetCurrentProcess(), target as *const std::ffi::c_void, PATCH_TOTAL);

    slot.target.store(target, Ordering::Relaxed);
    slot.trampoline.store(tramp as usize, Ordering::Relaxed);
    dbg_note(&format!(
        "inline: patch {target:#x} -> hook {hook:#x}, 原目标 {dest:#x}, trampoline {:#x} ({n} 字节)",
        tramp as usize
    ));
    tramp as usize
}

/// Install the entry-point patches.
///
/// `silent_ok` is false for the first attempt (its refusal is worth a log line) and
/// true for the periodic retries, which would otherwise spam the log with the same
/// rejection every 3 seconds.
unsafe fn patch_all() {
    let targets: [(usize, usize); 9] = [
        (ORIG_CREATEFILEW.load(Ordering::Relaxed), hook_CreateFileW as usize),
        (ORIG_CREATEFILEA.load(Ordering::Relaxed), hook_CreateFileA as usize),
        (ORIG_READFILE.load(Ordering::Relaxed), hook_ReadFile as usize),
        (ORIG_WRITEFILE.load(Ordering::Relaxed), hook_WriteFile as usize),
        (ORIG_CLOSEHANDLE.load(Ordering::Relaxed), hook_CloseHandle as usize),
        (ORIG_GETPROCADDRESS.load(Ordering::Relaxed), hook_GetProcAddress as usize),
        (ORIG_GETOVERLAPPEDRESULT.load(Ordering::Relaxed), hook_GetOverlappedResult as usize),
        (ORIG_GETOVERLAPPEDRESULTEX.load(Ordering::Relaxed), hook_GetOverlappedResultEx as usize),
        (ORIG_READFILEEX.load(Ordering::Relaxed), hook_ReadFileEx as usize),
    ];
    if targets[..8].iter().any(|t| t.0 == 0) {
        return; // core functions must all be resolved before patching
    }
    let me_size = std::mem::size_of::<ModuleEntry32W>();
    let mut me = ModuleEntry32W {
        dwSize: me_size as u32,
        th32ModuleID: 0,
        th32ProcessID: 0,
        GlblcntUsage: 0,
        ProccntUsage: 0,
        modBaseAddr: std::ptr::null_mut(),
        modBaseSize: 0,
        hModule: std::ptr::null_mut(),
        szModule: [0; 256],
        szExePath: [0; 260],
    };
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if snap as isize == INVALID_HANDLE {
        return;
    }
    if Module32FirstW(snap, &mut me) != 0 {
        loop {
            patch_iat(me.modBaseAddr, &targets);
            if Module32NextW(snap, &mut me) == 0 {
                break;
            }
        }
    }
    CloseHandle(snap);
}

// ---------------- pipe connection ----------------

unsafe fn get_module_file_name(buf: *mut u16, len: u32) -> u32 {
    unsafe extern "system" {
        fn GetModuleFileNameW(h: *mut std::ffi::c_void, buf: *mut u16, len: u32) -> u32;
    }
    GetModuleFileNameW(std::ptr::null_mut(), buf, len)
}

unsafe fn pipe_connect_loop() {
    let name = wide(PIPE_NAME);
    let exe = {
        let mut buf = [0u16; 1024];
        let n = get_module_file_name(buf.as_mut_ptr(), 1024) as usize;
        String::from_utf16_lossy(&buf[..n.min(1024)])
    };
    loop {
        let h = CreateFileW(
            name.as_ptr(),
            GENERIC_READWRITE,
            0,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        );
        if h as isize != INVALID_HANDLE {
            {
                let mut st = pipe_lock();
                st.h = h as isize;
            }
            dbg_note("pipe connected");
            send_attach(&exe);
            // Stay until the monitor goes away; then reconnect.
            loop {
                std::thread::sleep(std::time::Duration::from_millis(1000));
                if pipe_lock().h == INVALID_HANDLE {
                    break;
                }
            }
            continue;
        }
        let err = GetLastError();
        dbg_note(&format!("pipe open failed err={}", err));
        if err == ERROR_PIPE_BUSY {
            WaitNamedPipeW(name.as_ptr(), 2000);
        } else {
            std::thread::sleep(std::time::Duration::from_millis(1000));
        }
    }
}

// ---------------- start-up ----------------

unsafe fn worker() {
    dbg_note("worker started");
    SELF_BASE.store(DLL_BASE.load(Ordering::Relaxed), Ordering::Relaxed);
    ORIG_CREATEFILEW.store(resolve_kernel32(b"CreateFileW"), Ordering::Relaxed);
    ORIG_CREATEFILEA.store(resolve_kernel32(b"CreateFileA"), Ordering::Relaxed);
    ORIG_READFILE.store(resolve_kernel32(b"ReadFile"), Ordering::Relaxed);
    ORIG_WRITEFILE.store(resolve_kernel32(b"WriteFile"), Ordering::Relaxed);
    ORIG_CLOSEHANDLE.store(resolve_kernel32(b"CloseHandle"), Ordering::Relaxed);
    ORIG_GETPROCADDRESS.store(resolve_kernel32(b"GetProcAddress"), Ordering::Relaxed);
    ORIG_GETOVERLAPPEDRESULT.store(resolve_kernel32(b"GetOverlappedResult"), Ordering::Relaxed);
    ORIG_GETOVERLAPPEDRESULTEX.store(resolve_kernel32(b"GetOverlappedResultEx"), Ordering::Relaxed);
    ORIG_READFILEEX.store(resolve_kernel32(b"ReadFileEx"), Ordering::Relaxed);
    ORIG_WRITEFILEEX.store(resolve_kernel32(b"WriteFileEx"), Ordering::Relaxed);
    // The pipe must be up before any record can be produced.
    std::thread::spawn(|| unsafe { pipe_connect_loop() });
    patch_all();
    dbg_note("patched");
    patch_entries();
    // Re-patch every 3 s: modules loaded after injection have untouched IATs.
    std::thread::spawn(|| loop {
        std::thread::sleep(std::time::Duration::from_millis(3000));
        unsafe { patch_all() };
    });
    dbg_note("worker ready");
}

/// Install the entry-point patches on the four file APIs that decide whether a
/// serial operation is visible at all.
///
/// THIS IS NOT OPTIONAL ANY MORE. It used to sit behind a `%TEMP%\um_hook_inline`
/// marker file, and the result was the failure the user reported: injection reported
/// success, the hook logged "patched"/"worker ready", and nothing was ever captured,
/// because IAT hooking alone cannot see a tool that cached its kernel32 pointers
/// before injection. UartAssist (UPX-packed, binds everything through GetProcAddress
/// at runtime) imports none of these functions, so without entry patches there is
/// literally nothing to redirect.
///
/// The patch is safe by construction: it only displaces the 6-byte `FF 25` forwarder
/// stub when the following bytes are int3 padding, it preserves the real destination
/// in a trampoline, and it does not touch a single register — so the target's calls
/// keep working with identical semantics whether or not capture is happening.
unsafe fn patch_entries() {
    let sites: [(&str, &AtomicUsize, usize, &PatchSlot); 7] = [
        (
            "CreateFileW",
            &ORIG_CREATEFILEW,
            hook_CreateFileW as usize,
            &INLINE_CREATEFILEW,
        ),
        (
            "CreateFileA",
            &ORIG_CREATEFILEA,
            hook_CreateFileA as usize,
            &INLINE_CREATEFILEA,
        ),
        ("ReadFile", &ORIG_READFILE, hook_ReadFile as usize, &INLINE_READFILE),
        ("WriteFile", &ORIG_WRITEFILE, hook_WriteFile as usize, &INLINE_WRITEFILE),
        // Qt's QSerialPort and several industrial C++ libraries use the asynchronous
        // pair; a tool that caches these pointers before injection is exactly the case
        // entry patching exists for.
        ("ReadFileEx", &ORIG_READFILEEX, hook_ReadFileEx as usize, &INLINE_READFILEEX),
        (
            "WriteFileEx",
            &ORIG_WRITEFILEEX,
            hook_WriteFileEx as usize,
            &INLINE_WRITEFILEEX,
        ),
        // See INLINE_CLOSEHANDLE: without this, closed serial handles stay in the map
        // and a reused handle number makes an unrelated file look like port traffic.
        (
            "CloseHandle",
            &ORIG_CLOSEHANDLE,
            hook_CloseHandle as usize,
            &INLINE_CLOSEHANDLE,
        ),
    ];
    for (name, orig, hook, slot) in sites {
        let target = orig.load(Ordering::Relaxed);
        let tramp = patch_entry(target, hook, slot);
        if tramp != 0 {
            // Prove the patch landed: the entry point must now begin with our jump.
            let now = std::slice::from_raw_parts(target as *const u8, PATCH_LEN);
            dbg_note(&format!(
                "inline {name}: trampoline={tramp:#x} 现指令={:02X?}",
                now
            ));
        } else {
            dbg_note(&format!("inline {name}: 未安装（形态不受支持），仅靠 IAT 挂钩"));
        }
    }
}

#[no_mangle]
extern "system" fn DllMain(
    dll_base: *mut std::ffi::c_void,
    reason: u32,
    _reserved: *mut std::ffi::c_void,
) -> i32 {
    if reason == 1 {
        // DLL_PROCESS_ATTACH.
        //
        // Nothing here may allocate or format: the loader holds the loader lock, and a
        // statically linked CRT has not finished its own initialisation for this module.
        // A fault here makes LoadLibrary return NULL, which is exactly the failure seen
        // when the DLL was force-loaded into a WOW64 target ("LoadLibraryA 返回 -1").
        //
        // So: store the base, start the worker with the raw CreateThread API, and return.
        // Everything that allocates, formats or takes locks runs in the worker.
        DLL_BASE.store(dll_base as usize, Ordering::Relaxed);
        unsafe {
            extern "system" {
                fn CreateThread(
                    sa: *mut std::ffi::c_void,
                    stack: usize,
                    start: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
                    param: *mut std::ffi::c_void,
                    flags: u32,
                    tid: *mut u32,
                ) -> *mut std::ffi::c_void;
                fn CloseHandle(h: *mut std::ffi::c_void) -> i32;
            }
            unsafe extern "system" fn thread_main(_: *mut std::ffi::c_void) -> u32 {
                worker();
                0
            }
            let h = CreateThread(
                std::ptr::null_mut(),
                0,
                thread_main,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
            );
            if !h.is_null() {
                CloseHandle(h);
            }
        }
    }
    1
}
