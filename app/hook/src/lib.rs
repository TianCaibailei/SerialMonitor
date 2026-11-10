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
    let close = ORIG_CLOSEHANDLE.load(Ordering::Relaxed);
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
    let orig = ORIG_WRITEFILE.load(Ordering::Relaxed);
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

/// Look up (and register) the port label for a handle. Handles opened after
/// injection are known from CreateFile; handles already open are classified once
/// via GetFileInformationByHandleEx(FileNameInfo) and then cached either way.
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
    let mut buf = [0u8; 1024];
    if GetFileInformationByHandleEx(h, FILE_NAME_INFO_CLASS, buf.as_mut_ptr() as _, 1024) == 0 {
        // Transient failure: do NOT cache, the handle may just be busy.
        return None;
    }
    let chars_len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize / 2;
    if chars_len == 0 || chars_len > 500 {
        return None;
    }
    let mut wide_chars = Vec::with_capacity(chars_len);
    for i in 0..chars_len {
        let b = i * 2 + 4;
        if b + 1 >= 1024 {
            return None;
        }
        wide_chars.push(u16::from_le_bytes([buf[b], buf[b + 1]]));
    }
    let path = String::from_utf16_lossy(&wide_chars).to_lowercase();
    if !is_serial_path(&path) {
        handles_lock().insert(key, None); // negative cache: not a serial port
        dbg_note(&format!("com_label: h={:x} not serial: {}", key, path));
        return None;
    }
    let label = serial_label_from_path(&path);
    handles_lock().insert(key, Some(label.clone()));
    dbg_note(&format!("com_label: h={:x} serial {} ({})", key, label, path));
    send_open(key, &label);
    Some(label)
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
    let f: CreateFileAFn = std::mem::transmute(ORIG_CREATEFILEA.load(Ordering::Relaxed));
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
    let orig = ORIG_READFILEEX.load(Ordering::Relaxed);
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
    let orig = ORIG_WRITEFILEEX.load(Ordering::Relaxed);
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
    let was_serial = matches!(handles_lock().remove(&(h as usize)), Some(Some(_)));
    if was_serial {
        send_close(h as usize);
    }
    pending_lock().retain(|_, v| v.0 != h as usize);
    let f: CloseHandleFn = std::mem::transmute(ORIG_CLOSEHANDLE.load(Ordering::Relaxed));
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

unsafe fn patch_iat(base: *mut u8, targets: &[(usize, usize)]) {
    if base.is_null() {
        return;
    }
    if base as usize == SELF_BASE.load(Ordering::Relaxed) {
        return; // never hook our own imports (invariant 1)
    }
    let e_lfanew = *(base.offset(0x3C) as *const u32) as isize;
    let opt = base.offset(e_lfanew).offset(0x18);
    if *(opt as *const u16) != 0x20B {
        return; // PE32+ (x64) only
    }
    let imp_rva = *(opt.offset(112 + 8) as *const u32) as isize;
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
// IAT hooking only redirects calls that go through a module's import slot. .NET's
// SerialStream (and any binder that caches a resolved address) calls the function
// pointer it obtained earlier, so those calls bypass the IAT entirely — verified on
// this machine: a .NET process injected while still starting showed
// `pipe connected / patched` but never `cfw: \\.\COMn`, i.e. its CreateFileW call
// went straight to kernel32.
//
// Patching the function's first bytes closes that gap: `mov rax, <hook>; jmp rax`
// covers every caller regardless of how it got the address. The stolen bytes are
// copied into a trampoline that jumps back, so the original behaviour is preserved.
//
// The patch is only installed when the first bytes are the well-known Windows
// prologue of those exports (`mov r10, rcx; mov eax, <syscall>` / `jmp`), because
// replacing 12 bytes of arbitrary instructions would corrupt the function.
const PATCH_LEN: usize = 12;

#[repr(C)]
struct PatchSlot {
    target: AtomicUsize,
    trampoline: AtomicUsize,
}

static INLINE_CREATEFILEW: PatchSlot =
    PatchSlot { target: AtomicUsize::new(0), trampoline: AtomicUsize::new(0) };
static INLINE_READFILE: PatchSlot =
    PatchSlot { target: AtomicUsize::new(0), trampoline: AtomicUsize::new(0) };
static INLINE_WRITEFILE: PatchSlot =
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

/// Does the function start like a Windows syscall stub we can safely displace?
///
/// Measured on this machine, kernel32's file APIs begin with
///     FF 25 <rel32>      jmp qword ptr [rip+rel32]
///     CC CC CC ...       int3 padding to the next export
/// i.e. a 6-byte indirect jump followed by padding. That is the easiest case to patch:
/// only those 6 bytes are used, so a 12-byte write would clobber a neighbouring export's
/// padding (harmless) but a 6-byte-safe write keeps the change minimal and exact.
///
/// Also accepted: `4C 8B D1` (mov r10, rcx — the ntdll syscall stub) and `E9` (a jmp
/// rel32 forwarder). Anything else is refused: replacing unknown instructions would
/// corrupt the function.
unsafe fn is_patchable_prologue(p: *const u8) -> bool {
    let b: [u8; 4] = [*p, *p.add(1), *p.add(2), *p.add(3)];
    if b[0] == 0xFF && b[1] == 0x25 {
        return true; // jmp qword ptr [rip+rel32] — API-set forwarder stub
    }
    if b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xD1 {
        return true; // mov r10, rcx
    }
    if b[0] == 0xE9 || b[0] == 0xEB {
        return true; // jmp rel32/rel8 forwarder
    }
    false
}

/// How many bytes must be displaced for this prologue.
fn prologue_len(p: *const u8) -> usize {
    let b = unsafe { [*p, *p.add(1)] };
    if b[0] == 0xFF && b[1] == 0x25 {
        return 6; // jmp qword ptr [rip+rel32]
    }
    12 // mov r10,rcx / jmp rel32
}

/// Resolve the absolute destination of an `FF 25 rel32` stub.
///
/// The displaced bytes cannot be copied into a trampoline verbatim: `[rip+rel32]` is
/// relative to the *original* instruction's address, so the copy would read the wrong
/// memory (and crash). Reading the destination now and jumping to it absolutely is the
/// correct equivalent, and these stubs are pure forwarders so nothing else is lost.
unsafe fn resolve_ff25_target(p: *const u8) -> usize {
    let rel = i32::from_le_bytes([*p.add(2), *p.add(3), *p.add(4), *p.add(5)]) as isize;
    // [rip + rel32] where rip is the address of the *next* instruction (p + 6).
    let slot = (p as isize) + 6 + rel;
    let dest = *(slot as *const u64);
    dest as usize
}

/// Install `hook` at `target`, preserving the displaced instructions in a trampoline.
/// Returns the trampoline address, or 0 when the patch was refused.
unsafe fn patch_entry(target: usize, hook: usize, slot: &PatchSlot) -> usize {
    if target == 0 || hook == 0 {
        return 0;
    }
    if !is_patchable_prologue(target as *const u8) {
        let p = target as *const u8;
        dbg_note(&format!(
            "inline: 拒绝 patch {target:#x}, 前16字节 = {:02X?}",
            unsafe { std::slice::from_raw_parts(p, 16) }
        ));
        return 0; // unexpected prologue: leave the function untouched
    }
    let patch_len = prologue_len(target as *const u8);
    let tramp = VirtualAlloc(
        std::ptr::null_mut(),
        patch_len + 16,
        MEM_COMMIT_RESERVE,
        PAGE_EXECUTE_READWRITE_INLINE,
    ) as *mut u8;
    if tramp.is_null() {
        return 0;
    }
    if patch_len == 6 {
        // FF 25 stub: jump to the resolved destination, then jump back to target+6.
        let dest = resolve_ff25_target(target as *const u8) as u64;
        let mut code = [0u8; 12];
        code[0] = 0x48;
        code[1] = 0xB8;
        code[2..10].copy_from_slice(&dest.to_le_bytes());
        code[10] = 0xFF;
        code[11] = 0xE0;
        std::ptr::copy_nonoverlapping(code.as_ptr(), tramp, 12);
        // The stub never returns to target+6 (it jump'd away); a return jump is
        // unreachable but harmless, so none is emitted.
    } else {
        // Position-independent prologue (mov r10,rcx / jmp rel32 of the ntdll stub):
        // copy verbatim and jump back. These contain no RIP-relative operand.
        std::ptr::copy_nonoverlapping(target as *const u8, tramp, patch_len);
        let back = (target + patch_len) as u64;
        let mut jmp_back = [0u8; 12];
        jmp_back[0] = 0x48;
        jmp_back[1] = 0xB8;
        jmp_back[2..10].copy_from_slice(&back.to_le_bytes());
        jmp_back[10] = 0xFF;
        jmp_back[11] = 0xE0;
        std::ptr::copy_nonoverlapping(jmp_back.as_ptr(), tramp.add(patch_len), 12);
    }

    // Overwrite the target's prologue with a jump to our hook.
    //
    // The patch MUST NOT clobber a register: the displaced stub is called with the
    // real arguments already in rcx/rdx/r8/r9, and `mov rax, hook; jmp rax` destroys
    // rax. Using `FF 25 <disp32>` (jmp qword ptr [rip+disp32]) touches no register at
    // all, which is exactly how the original API-set stub works. A 6-byte displacement
    // covers the 6-byte stub case; for the longer prologues 8 bytes of code are
    // needed, so a `jmp rel32` to a nearby stub is used instead.
    let mut old = 0u32;
    if VirtualProtect(target as *mut std::ffi::c_void, patch_len, PAGE_EXECUTE_READWRITE_INLINE, &mut old) == 0 {
        return 0;
    }
    if patch_len == 6 {
        // Reserve a pointer slot in the trampoline and jump through it.
        // Layout: [6 or 12 bytes: original prologue] [8 bytes: hook address]
        let hook_slot = tramp.add(patch_len + 12);
        std::ptr::write_unaligned(hook_slot as *mut u64, hook as u64);
        let disp = (hook_slot as isize) - ((target as isize) + 6);
        let mut jmp = [0u8; 6];
        jmp[0] = 0xFF;
        jmp[1] = 0x25;
        jmp[2..6].copy_from_slice(&(disp as i32).to_le_bytes());
        std::ptr::copy_nonoverlapping(jmp.as_ptr(), target as *mut u8, 6);
    } else {
        let mut jmp = [0u8; 12];
        jmp[0] = 0xFF;
        jmp[1] = 0x25;
        jmp[2] = 0x00;
        jmp[3] = 0x00;
        jmp[4] = 0x00;
        jmp[5] = 0x00;
        // For the 12-byte case the slot cannot be embedded in 6 bytes, so fall back to
        // a register-free `push [rip]; ret` shape via the trampoline pointer slot.
        let hook_slot = tramp.add(patch_len + 12);
        std::ptr::write_unaligned(hook_slot as *mut u64, hook as u64);
        let disp = (hook_slot as isize) - ((target as isize) + 6);
        jmp[2..6].copy_from_slice(&(disp as i32).to_le_bytes());
        // Pad the remaining bytes with int3 so a stray fall-through traps.
        for b in jmp.iter_mut().skip(6) {
            *b = 0xCC;
        }
        std::ptr::copy_nonoverlapping(jmp.as_ptr(), target as *mut u8, 12);
    }
    let mut rel = 0u32;
    VirtualProtect(target as *mut std::ffi::c_void, patch_len, old.max(PAGE_EXECUTE_READ_INLINE), &mut rel);
    FlushInstructionCache(GetCurrentProcess(), target as *const std::ffi::c_void, patch_len);

    slot.target.store(target, Ordering::Relaxed);
    slot.trampoline.store(tramp as usize, Ordering::Relaxed);
    tramp as usize
}

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
    // Byte-level patches are OPT-IN (create %TEMP%\um_hook_inline). They close the gap
    // for callers that cache API pointers (.NET P/Invoke), but displacing live kernel32
    // stubs is invasive: a mistake in the trampoline crashes the host process. Until the
    // trampoline is verified against every stub shape on a test machine, IAT hooking is
    // the default and this stays behind a marker file.
    if std::env::temp_dir().join("um_hook_inline").exists() {
        let t1 = patch_entry(
            ORIG_CREATEFILEW.load(Ordering::Relaxed),
            hook_CreateFileW as usize,
            &INLINE_CREATEFILEW,
        );
        let t2 = patch_entry(
            ORIG_READFILE.load(Ordering::Relaxed),
            hook_ReadFile as usize,
            &INLINE_READFILE,
        );
        let t3 = patch_entry(
            ORIG_WRITEFILE.load(Ordering::Relaxed),
            hook_WriteFile as usize,
            &INLINE_WRITEFILE,
        );
        dbg_note(&format!(
            "inline: CreateFileW tramp={:#x} ReadFile tramp={:#x} WriteFile tramp={:#x}",
            t1, t2, t3
        ));
        // Verify the patch really landed: the target's first bytes must now be our
        // jump (`48 B8 <hook>`), otherwise the write silently did not take effect.
        let p = ORIG_CREATEFILEW.load(Ordering::Relaxed) as *const u8;
        if t1 != 0 {
            let b = unsafe { std::slice::from_raw_parts(p, 12) };
            dbg_note(&format!("inline: CreateFileW 现字节 = {:02X?}", b));
        }
    }
    // Re-patch every 3 s: modules loaded after injection have untouched IATs.
    std::thread::spawn(|| loop {
        std::thread::sleep(std::time::Duration::from_millis(3000));
        unsafe { patch_all() };
    });
}

#[no_mangle]
extern "system" fn DllMain(
    dll_base: *mut std::ffi::c_void,
    reason: u32,
    _reserved: *mut std::ffi::c_void,
) -> i32 {
    if reason == 1 {
        // DLL_PROCESS_ATTACH: do nothing heavy under the loader lock; the worker
        // thread resolves the API addresses and patches the IATs.
        DLL_BASE.store(dll_base as usize, Ordering::Relaxed);
        std::thread::spawn(|| unsafe { worker() });
    }
    1
}
