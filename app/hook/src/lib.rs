// monitor_hook — injected into the monitored process by 万能监控 (inject.rs).
//
// This is the user-space equivalent of the original's kernel driver (CommMonitor
// sub_a874f0..sub_a893e0 chain): instead of an IRP-level filter, it patches the
// process's import-address table (IAT) for kernel32!CreateFileW / ReadFile /
// WriteFile / CloseHandle, keeps a handle -> COM port map, and streams every
// RX/TX of serial handles to the monitor over the named pipe \\.\pipe\monitor_capture.
//
// Safety rules: the hook never changes the data flow — the original function is
// always called first, captured bytes are copied out after the call, and our own
// module's imports are never patched (so our pipe writes can't recurse into the
// hooks). Failed pipe writes simply drop records; the client reconnects.

#![allow(non_snake_case)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

const PIPE_NAME: &str = "\\.\pipe\monitor_capture";

// Record tags (must match inject.rs).
const TAG_ATTACH: u32 = 1;
const TAG_OPEN: u32 = 2;
const TAG_CLOSE: u32 = 3;
const TAG_RX: u32 = 4;
const TAG_TX: u32 = 5;

const GENERIC_WRITE: u32 = 0x4000_0000;
const OPEN_EXISTING: u32 = 3;
const INVALID_HANDLE: isize = -1;
const ERROR_PIPE_BUSY: u32 = 231;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const TH32CS_SNAPMODULE: u32 = 0x8;
const FILE_NAME_INFO_CLASS: u32 = 2;

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
    pid_sent: bool,
}

impl PipeState {
    const fn dead() -> Self {
        PipeState { h: INVALID_HANDLE, pid_sent: false }
    }
}

static HANDLES: Mutex<HashMap<usize, String>> = Mutex::new(HashMap::new());
static PIPE: Mutex<PipeState> = Mutex::new(PipeState::dead());
static SELF_BASE: AtomicUsize = AtomicUsize::new(0);
static ORIG_CREATEFILEW: AtomicUsize = AtomicUsize::new(0);
static ORIG_READFILE: AtomicUsize = AtomicUsize::new(0);
static ORIG_WRITEFILE: AtomicUsize = AtomicUsize::new(0);
static ORIG_CLOSEHANDLE: AtomicUsize = AtomicUsize::new(0);

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_to_string(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut chars = Vec::new();
    let mut i = 0;
    unsafe {
        loop {
            let c = *p.add(i);
            if c == 0 {
                break;
            }
            chars.push(c);
            i += 1;
            if i > 32_768 {
                break;
            }
        }
    }
    String::from_utf16_lossy(&chars)
}

/// "COM6", "\\.\COM6", "COM6:" → Some("COM6"); anything else → None.
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

/// Look up (and register) the port label for a handle. Handles opened before we
/// were injected are classified once via GetFileInformationByHandleEx(FileNameInfo);
/// serial device paths look like \\Device\\Serial0 / \\Device\\vcp0 (com0com).
unsafe fn com_label(h: *mut std::ffi::c_void) -> Option<String> {
    let key = h as usize;
    if let Some(p) = HANDLES.lock().unwrap().get(&key) {
        return Some(p.clone());
    }
    let mut buf = [0u8; 1024];
    if GetFileInformationByHandleEx(h, FILE_NAME_INFO_CLASS, buf.as_mut_ptr() as _, 1024) == 0 {
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
    if !(path.contains("serial") || path.contains("vcp") || path.contains("vser")) {
        return None;
    }
    let label = path.rsplit('\\').next().unwrap_or("COM?").to_uppercase();
    HANDLES.lock().unwrap().insert(key, label.clone());
    send_open(key, &label);
    Some(label)
}

fn pipe_write(payload: &[u8]) -> bool {
    let mut st = PIPE.lock().unwrap();
    if st.h == INVALID_HANDLE {
        return false;
    }
    let mut written = 0u32;
    let ok = unsafe {
        WriteFile(
            st.h as *mut std::ffi::c_void,
            payload.as_ptr(),
            payload.len() as u32,
            &mut written,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 || written as usize != payload.len() {
        st.h = INVALID_HANDLE;
        st.pid_sent = false;
        return false;
    }
    true
}

fn send_record(tag: u32, payload: &[u8]) {
    let mut msg = Vec::with_capacity(8 + payload.len());
    msg.extend_from_slice(&tag.to_le_bytes());
    msg.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    msg.extend_from_slice(payload);
    pipe_write(&msg);
}

fn send_attach(exe: &str) {
    let pid = unsafe { GetCurrentProcessId() };
    let mut p = pid.to_le_bytes().to_vec();
    p.extend_from_slice(exe.as_bytes());
    send_record(TAG_ATTACH, &p);
}

fn send_open(handle: usize, port: &str) {
    let pid = unsafe { GetCurrentProcessId() };
    let mut p = pid.to_le_bytes().to_vec();
    p.extend_from_slice(&(handle as u64).to_le_bytes());
    p.extend_from_slice(port.as_bytes());
    send_record(TAG_OPEN, &p);
}

fn send_close(handle: usize) {
    let pid = unsafe { GetCurrentProcessId() };
    let mut p = pid.to_le_bytes().to_vec();
    p.extend_from_slice(&(handle as u64).to_le_bytes());
    send_record(TAG_CLOSE, &p);
}

fn send_io(tag: u32, handle: usize, data: &[u8]) {
    let pid = unsafe { GetCurrentProcessId() };
    let mut p = pid.to_le_bytes().to_vec();
    p.extend_from_slice(&(handle as u64).to_le_bytes());
    p.extend_from_slice(data);
    send_record(tag, &p);
}

// ---------------- hooks ----------------

type CreateFileWFn = unsafe extern "system" fn(
    *const u16,
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

unsafe extern "system" fn hook_CreateFileW(
    name: *const u16,
    access: u32,
    share: u32,
    sa: *mut std::ffi::c_void,
    disp: u32,
    flags: u32,
    tmpl: *mut std::ffi::c_void,
) -> *mut std::ffi::c_void {
    let f: CreateFileWFn = std::mem::transmute(ORIG_CREATEFILEW.load(Ordering::Relaxed));
    let h = f(name, access, share, sa, disp, flags, tmpl);
    if h as isize != INVALID_HANDLE {
        let s = wide_to_string(name);
        if let Some(port) = com_port_name(&s) {
            HANDLES.lock().unwrap().insert(h as usize, port.clone());
            send_open(h as usize, &port);
        }
    }
    h
}

unsafe extern "system" fn hook_ReadFile(
    h: *mut std::ffi::c_void,
    buf: *mut u8,
    len: u32,
    read: *mut u32,
    ov: *mut std::ffi::c_void,
) -> i32 {
    let f: ReadFileFn = std::mem::transmute(ORIG_READFILE.load(Ordering::Relaxed));
    let ok = f(h, buf, len, read, ov);
    if ok != 0 {
        let n = if read.is_null() { len } else { *read };
        if n > 0 {
            if let Some(_) = com_label(h) {
                let data = std::slice::from_raw_parts(buf, n as usize).to_vec();
                send_io(TAG_RX, h as usize, &data);
            }
        }
    }
    ok
}

unsafe extern "system" fn hook_WriteFile(
    h: *mut std::ffi::c_void,
    buf: *const u8,
    len: u32,
    written: *mut u32,
    ov: *mut std::ffi::c_void,
) -> i32 {
    let f: WriteFileFn = std::mem::transmute(ORIG_WRITEFILE.load(Ordering::Relaxed));
    let ok = f(h, buf, len, written, ov);
    if ok != 0 {
        let n = if written.is_null() { len } else { *written };
        if n > 0 {
            if let Some(_) = com_label(h) {
                let data = std::slice::from_raw_parts(buf, n as usize).to_vec();
                send_io(TAG_TX, h as usize, &data);
            }
        }
    }
    ok
}

unsafe extern "system" fn hook_CloseHandle(h: *mut std::ffi::c_void) -> i32 {
    let had = HANDLES.lock().unwrap().remove(&(h as usize)).is_some();
    if had {
        send_close(h as usize);
    }
    let f: CloseHandleFn = std::mem::transmute(ORIG_CLOSEHANDLE.load(Ordering::Relaxed));
    f(h)
}

// ---------------- IAT patching ----------------

unsafe fn resolve_kernel32(name: &[u8]) -> usize {
    let k32 = wide("kernel32.dll");
    let h = GetModuleHandleW(k32.as_ptr());
    let mut cname = name.to_vec();
    cname.push(0);
    GetProcAddress(h, cname.as_ptr()) as usize
}

unsafe fn patch_iat(base: *mut u8, targets: &[(usize, usize)]) {
    if base.is_null() {
        return;
    }
    if base as usize == SELF_BASE.load(Ordering::Relaxed) {
        return; // never hook our own imports (pipe writes must not recurse)
    }
    let e_lfanew = *(base.offset(0x3C) as *const u32) as isize;
    let opt = base.offset(e_lfanew).offset(0x18);
    if *(opt as *const u16) != 0x20B {
        return; // PE32+ (x64) only
    }
    let imp_rva = *(opt.offset(112 + 8) as *const u32) as isize; // data dir [1] = imports
    if imp_rva == 0 {
        return;
    }
    let mut desc = base.offset(imp_rva) as *const ImportDesc;
    while (*desc).original_first_thunk != 0 {
        let mut iat = base.offset((*desc).first_thunk as isize) as *mut usize;
        while *iat != 0 {
            for (orig, hook) in targets {
                if *iat == *orig {
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

unsafe fn patch_all() {
    let targets = [
        (ORIG_CREATEFILEW.load(Ordering::Relaxed), hook_CreateFileW as usize),
        (ORIG_READFILE.load(Ordering::Relaxed), hook_ReadFile as usize),
        (ORIG_WRITEFILE.load(Ordering::Relaxed), hook_WriteFile as usize),
        (ORIG_CLOSEHANDLE.load(Ordering::Relaxed), hook_CloseHandle as usize),
    ];
    if targets.iter().any(|t| t.0 == 0) {
        return;
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

unsafe fn pipe_connect_loop() {
    let name = wide(PIPE_NAME);
    // initial attach message: exe path of this process
    let exe = {
        let mut buf = [0u16; 1024];
        let n = get_module_file_name(buf.as_mut_ptr(), 1024) as usize;
        String::from_utf16_lossy(&buf[..n])
    };
    loop {
        let h = CreateFileW(
            name.as_ptr(),
            GENERIC_WRITE,
            0,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        );
        if h as isize != INVALID_HANDLE {
            {
                let mut st = PIPE.lock().unwrap();
                st.h = h as isize;
            }
            send_attach(&exe);
            // keep the connection healthy; reconnect if the monitor restarts
            loop {
                std::thread::sleep(std::time::Duration::from_millis(2000));
                let dead = { PIPE.lock().unwrap().h == INVALID_HANDLE };
                if !dead {
                    continue;
                }
                break;
            }
            continue;
        }
        if GetLastError() == ERROR_PIPE_BUSY {
            WaitNamedPipeW(name.as_ptr(), 2000);
        }
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }
}

unsafe fn get_module_file_name(buf: *mut u16, len: u32) -> u32 {
    // GetModuleFileNameW — declared separately to avoid name clashes in the extern block
    unsafe extern "system" {
        fn GetModuleFileNameW(h: *mut std::ffi::c_void, buf: *mut u16, len: u32) -> u32;
    }
    GetModuleFileNameW(std::ptr::null_mut(), buf, len)
}

unsafe fn worker(dll_base: *mut std::ffi::c_void) {
    SELF_BASE.store(dll_base as usize, Ordering::Relaxed);
    ORIG_CREATEFILEW.store(resolve_kernel32(b"CreateFileW"), Ordering::Relaxed);
    ORIG_READFILE.store(resolve_kernel32(b"ReadFile"), Ordering::Relaxed);
    ORIG_WRITEFILE.store(resolve_kernel32(b"WriteFile"), Ordering::Relaxed);
    ORIG_CLOSEHANDLE.store(resolve_kernel32(b"CloseHandle"), Ordering::Relaxed);
    patch_all();
    std::thread::spawn(|| loop {
        unsafe { patch_all() };
        std::thread::sleep(std::time::Duration::from_millis(3000));
    });
    pipe_connect_loop();
}

#[no_mangle]
extern "system" fn DllMain(
    dll_base: *mut std::ffi::c_void,
    reason: u32,
    _reserved: *mut std::ffi::c_void,
) -> i32 {
    if reason == 1 {
        // DLL_PROCESS_ATTACH — do nothing under the loader lock; the worker
        // thread does all the work (patching + pipe connection).
        std::thread::spawn(move || unsafe { worker(dll_base) });
    }
    1
}
