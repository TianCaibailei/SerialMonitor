// inject.rs — user-space interception front end.
//
// This is the zero-privilege capture path: instead of a kernel driver, it injects a hook
// DLL into the process that owns the serial port. See docs/技术手册.md for the design.
//
// Two halves:
//  1. Capture server: 4 instances of the named pipe \\.\pipe\monitor_capture in
//     byte mode. Injected hook DLLs connect (tag 1 ATTACH) and stream records
//     [tag u32][len u32][pid u32][payload] — tags match hook/src/lib.rs.
//  2. Injector: OpenProcess → VirtualAllocEx → WriteProcessMemory (dll path,
//     UTF-16) → CreateRemoteThread(LoadLibraryW). 64-bit targets only.
//
// The hook never modifies the target's data: original kernel32 functions run
// first, captured bytes are copied out after the call (see hook/src/lib.rs).

use std::sync::mpsc::{channel, Receiver};
use std::sync::Mutex;

pub const PIPE_NAME: &str = "\\\\.\\pipe\\monitor_capture";

// Record tags (must match hook/src/lib.rs).
const TAG_ATTACH: u32 = 1;
const TAG_OPEN: u32 = 2;
const TAG_CLOSE: u32 = 3;
const TAG_RX: u32 = 4;
const TAG_TX: u32 = 5;

pub enum CapMsg {
    Attach {
        pid: u32,
        exe: String,
    },
    Open {
        pid: u32,
        handle: u64,
        port: String,
    },
    Close {
        pid: u32,
        handle: u64,
    },
    Rx {
        pid: u32,
        handle: u64,
        data: Vec<u8>,
    },
    Tx {
        pid: u32,
        handle: u64,
        data: Vec<u8>,
    },
}

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const OPEN_EXISTING: u32 = 3;
const PIPE_ACCESS_DUPLEX: u32 = 3;
const PIPE_TYPE_BYTE: u32 = 0x0;
const PIPE_READMODE_BYTE: u32 = 0x0;
const PIPE_WAIT: u32 = 0x0;
const INVALID_HANDLE: isize = -1;
const ERROR_PIPE_CONNECTED: u32 = 539;
const PROCESS_CREATE_THREAD: u32 = 0x0002;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const PROCESS_VM_OPERATION: u32 = 0x0008;
const PROCESS_VM_WRITE: u32 = 0x0020;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;
const PAGE_READWRITE: u32 = 0x04;
const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT: u32 = 0x102;
const TH32CS_SNAPPROCESS: u32 = 0x2;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

extern "system" {
    fn CreateNamedPipeW(
        name: *const u16,
        open_mode: u32,
        pipe_mode: u32,
        instances: u32,
        out_buf: u32,
        in_buf: u32,
        timeout_ms: u32,
        sa: *mut std::ffi::c_void,
    ) -> *mut std::ffi::c_void;
    fn ConnectNamedPipe(h: *mut std::ffi::c_void, ov: *mut std::ffi::c_void) -> i32;
    fn DisconnectNamedPipe(h: *mut std::ffi::c_void) -> i32;
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
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut std::ffi::c_void;
    fn VirtualAllocEx(
        proc: *mut std::ffi::c_void,
        addr: *mut std::ffi::c_void,
        size: usize,
        ty: u32,
        prot: u32,
    ) -> *mut std::ffi::c_void;
    fn WriteProcessMemory(
        proc: *mut std::ffi::c_void,
        addr: *mut std::ffi::c_void,
        buf: *const u8,
        size: usize,
        written: *mut usize,
    ) -> i32;
    fn CreateRemoteThread(
        proc: *mut std::ffi::c_void,
        sa: *mut std::ffi::c_void,
        stack: usize,
        start: *mut std::ffi::c_void,
        param: *mut std::ffi::c_void,
        flags: u32,
        tid: *mut u32,
    ) -> *mut std::ffi::c_void;
    fn WaitForSingleObject(h: *mut std::ffi::c_void, ms: u32) -> u32;
    fn GetExitCodeThread(h: *mut std::ffi::c_void, code: *mut u32) -> i32;
    fn VirtualFreeEx(
        proc: *mut std::ffi::c_void,
        addr: *mut std::ffi::c_void,
        size: usize,
        ty: u32,
    ) -> i32;
    fn IsWow64Process(h: *mut std::ffi::c_void, wow64: *mut i32) -> i32;
    fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> *mut std::ffi::c_void;
    fn Process32FirstW(snap: *mut std::ffi::c_void, pe: *mut ProcessEntry32W) -> i32;
    fn Process32NextW(snap: *mut std::ffi::c_void, pe: *mut ProcessEntry32W) -> i32;
    fn GetCurrentProcessId() -> u32;
}

/// PROCESSENTRY32W as Windows actually lays it out on x64.
///
/// Measured against a live snapshot: the executable name begins at **offset 44**, not
/// at 36. The nine DWORD fields (dwSize..dwFlags) occupy bytes 0..36, but the wide
/// character array is 8-byte aligned, so Windows leaves 8 bytes of padding before it.
/// Modelling that padding explicitly is what makes the process names come out instead
/// of an empty string, and `dwSize` must be the full 568.
// Field names intentionally mirror the Win32 PROCESSENTRY32W definition: this is a
// #[repr(C)] ABI mirror, and renaming them to snake_case would obscure the mapping for
// anyone checking the layout against the SDK header.
#[allow(non_snake_case)]
#[repr(C)]
struct ProcessEntry32W {
    dwSize: u32,
    cntUsage: u32,
    th32ProcessID: u32,
    th32DefaultHeap: u32,
    th32ModuleID: u32,
    cntThreads: u32,
    th32ParentProcessID: u32,
    pcPriClassBase: u32,
    dwFlags: u32,
    /// Pads the DWORD block out to byte 44, where szExeFile actually begins on x64
    /// (measured from a live snapshot: "[System Process]" starts at offset 0x2C).
    _align: [u32; 2],
    szExeFile: [u16; 260],
    /// Trailing slack so the struct is exactly the 568 bytes Windows expects.
    _pad: [u8; 4],
}

const _: () = {
    assert!(std::mem::size_of::<ProcessEntry32W>() == 568);
};

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// UTF-16 NUL-terminated copy (shared with the port scanner and diagnostics).
pub fn wide_str(s: &str) -> Vec<u16> {
    wide(s)
}

/// True when a lower-cased NT device path names a serial port device.
pub fn is_serial_device_path(path: &str) -> bool {
    const MARKERS: &[&str] = &[
        "\\device\\serial",
        "\\device\\usbser",
        "\\device\\prolific",
        "\\device\\silabser",
        "\\device\\vcp",
        "\\device\\vserial",
        "\\device\\ftdi",
        "\\device\\comport",
        "\\device\\bthmodem",
        "\\device\\vser",
        "\\device\\ttys",
        "\\device\\bthfcom",
        "\\device\\cdc",
        "\\device\\aries",
        "\\device\\ch341",
        "\\device\\mct_u232",
    ];
    MARKERS.iter().any(|m| path.contains(m))
}

/// True for OS-critical processes we must never inject into.
pub fn is_critical_pid(pid: u32) -> bool {
    const CRITICAL_PIDS: &[u32] = &[0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40];
    if CRITICAL_PIDS.contains(&pid) {
        return true;
    }
    let h = unsafe { OpenProcess(0x1000, 0, pid) };
    if h.is_null() {
        return false;
    }
    let mut buf = [0u16; 512];
    let mut size = buf.len() as u32;
    extern "system" {
        fn QueryFullProcessImageNameW(
            h: *mut std::ffi::c_void,
            flags: u32,
            name: *mut u16,
            size: *mut u32,
        ) -> i32;
    }
    let ok = unsafe { QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut size) };
    unsafe { CloseHandle(h) };
    if ok == 0 {
        return false;
    }
    let s = String::from_utf16_lossy(&buf[..size as usize]);
    let name = s.rsplit('\\').next().unwrap_or(&s).to_lowercase();
    if name.is_empty() {
        return false;
    }
    let bare = name.strip_suffix(".exe").unwrap_or(&name);
    BLACKLIST.iter().any(|b| bare == *b || name == *b)
}

fn dbg(msg: &str) {
    if std::env::var("UM_DEBUG_PIPE").is_ok() {
        println!("pipe-srv: {}", msg);
    }
}

// one named-pipe instance: accept one hook DLL connection and parse its records
fn pipe_instance(tx: std::sync::mpsc::Sender<CapMsg>) {
    let name = wide(PIPE_NAME);
    loop {
        let h = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX, // server side reads; mode keeps clients happy
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                255, // max instances: one connection per injected process, and the
                // auto-attach hook lives in many processes at once. With the old
                // value of 4, every process beyond the fourth got
                // ERROR_PIPE_BUSY (231) and silently streamed nothing — which is
                // exactly why a monitored program could look completely idle.
                4096,
                4096,
                0,
                std::ptr::null_mut(),
            )
        };
        if h as isize == INVALID_HANDLE {
            dbg(&format!("create failed err={}", get_last_error()));
            std::thread::sleep(std::time::Duration::from_millis(1000));
            continue;
        }
        dbg("instance created, waiting connect");
        let connected = unsafe { ConnectNamedPipe(h, std::ptr::null_mut()) };
        dbg(&format!(
            "connect ret={} err={}",
            connected,
            get_last_error()
        ));
        if connected == 0 {
            let err = get_last_error();
            if err != ERROR_PIPE_CONNECTED {
                unsafe { CloseHandle(h) };
                std::thread::sleep(std::time::Duration::from_millis(200));
                continue;
            }
        }
        // a hook DLL attached — accumulate bytes and split records
        // [tag u32][len u32][pid u32][payload]; over-read bytes are kept for the
        // next record (a single ReadFile may span records or split one).
        let mut acc: Vec<u8> = Vec::with_capacity(4096);
        let mut buf = [0u8; 65536];
        'conn: loop {
            let mut n = 0u32;
            let ok = unsafe {
                ReadFile(
                    h,
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    &mut n,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 || n == 0 {
                break;
            }
            acc.extend_from_slice(&buf[..n as usize]);
            loop {
                if acc.len() < 12 {
                    break;
                }
                let tag = u32::from_le_bytes([acc[0], acc[1], acc[2], acc[3]]);
                let len = u32::from_le_bytes([acc[4], acc[5], acc[6], acc[7]]) as usize;
                let pid = u32::from_le_bytes([acc[8], acc[9], acc[10], acc[11]]);
                if len > 8 * 1024 * 1024 {
                    break 'conn; // absurd record — drop the connection
                }
                if acc.len() < 12 + len {
                    break; // partial record — wait for more bytes
                }
                let payload: Vec<u8> = acc[12..12 + len].to_vec();
                acc.drain(..12 + len);
                dbg(&format!("record tag={} len={} pid={}", tag, len, pid));
                if let Some(m) = decode(tag, pid, &payload) {
                    if tx.send(m).is_err() {
                        break 'conn; // monitor gone
                    }
                }
            }
        }
        unsafe {
            DisconnectNamedPipe(h);
            CloseHandle(h);
        }
    }
}

// simple win32 GetLastError via a probe that sets it reliably
/// Public: Win32 last-error for diagnostics in other modules.
pub fn last_error() -> u32 {
    get_last_error()
}

fn get_last_error() -> u32 {
    extern "system" {
        fn GetLastError() -> u32;
    }
    unsafe { GetLastError() }
}

// payload layouts: ATTACH exe utf8; OPEN handle u64 + port utf8; CLOSE handle u64;
// RX/TX handle u64 + bytes. pid rides in the record header.
fn decode(tag: u32, pid: u32, p: &[u8]) -> Option<CapMsg> {
    match tag {
        TAG_ATTACH => Some(CapMsg::Attach {
            pid,
            exe: String::from_utf8_lossy(p).into_owned(),
        }),
        TAG_OPEN if p.len() >= 8 => Some(CapMsg::Open {
            pid,
            handle: u64::from_le_bytes(p[0..8].try_into().ok()?),
            port: String::from_utf8_lossy(&p[8..]).into_owned(),
        }),
        TAG_CLOSE if p.len() >= 8 => Some(CapMsg::Close {
            pid,
            handle: u64::from_le_bytes(p[0..8].try_into().ok()?),
        }),
        TAG_RX if p.len() >= 8 => Some(CapMsg::Rx {
            pid,
            handle: u64::from_le_bytes(p[0..8].try_into().ok()?),
            data: p[8..].to_vec(),
        }),
        TAG_TX if p.len() >= 8 => Some(CapMsg::Tx {
            pid,
            handle: u64::from_le_bytes(p[0..8].try_into().ok()?),
            data: p[8..].to_vec(),
        }),
        _ => None,
    }
}

/// Start the capture server. Returns the receiver of captured records.
pub fn start_capture_server() -> Receiver<CapMsg> {
    let (tx, rx) = channel();
    let tx = Mutex::new(tx);
    // One server thread per possible hook connection. Each instance accepts exactly
    // one client at a time and then loops, so this covers every injected process
    // without any of them being turned away with ERROR_PIPE_BUSY.
    for _ in 0..12 {
        let tx = tx.lock().unwrap().clone();
        std::thread::spawn(move || pipe_instance(tx));
    }
    rx
}

// ---------------- process listing ----------------

const BLACKLIST: &[&str] = &[
    "system",
    "csrss.exe",
    "smss.exe",
    "wininit.exe",
    "winlogon.exe",
    "lsass.exe",
    "services.exe",
    "svchost.exe",
    "dwm.exe",
    "fontdrvhost.exe",
    "winidle0.exe",
    "securityhealthservice.exe",
    "memory compression",
    "registry",
];

/// (pid, exe name) of injectable processes — OS-critical ones excluded.
pub fn list_processes() -> Vec<(u32, String)> {
    let mut out = Vec::new();
    let me = unsafe { GetCurrentProcessId() };
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap as isize == INVALID_HANDLE {
        return out;
    }
    let mut pe = ProcessEntry32W {
        dwSize: std::mem::size_of::<ProcessEntry32W>() as u32,
        cntUsage: 0,
        th32ProcessID: 0,
        th32DefaultHeap: 0,
        th32ModuleID: 0,
        cntThreads: 0,
        th32ParentProcessID: 0,
        pcPriClassBase: 0,
        dwFlags: 0,
        _align: [0; 2],
        szExeFile: [0; 260],
        _pad: [0; 4],
    };
    unsafe {
        if Process32FirstW(snap, &mut pe) != 0 {
            loop {
                if pe.th32ProcessID != me {
                    let name = {
                        let end = pe.szExeFile.iter().position(|&c| c == 0).unwrap_or(260);
                        String::from_utf16_lossy(&pe.szExeFile[..end])
                    };
                    let lower = name.to_lowercase();
                    let critical = BLACKLIST
                        .iter()
                        .any(|b| lower == *b || lower == format!("{}.exe", *b));
                    let critical = critical || lower == "system" || lower == "system idle process";
                    if !critical {
                        out.push((pe.th32ProcessID, name));
                    }
                }
                if Process32NextW(snap, &mut pe) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
    // Sort case-insensitively for the process picker: `sort_by_key` would have to
    // allocate a lowercased String per element anyway, and clippy's suggestion applies
    // here because the key is computed on the fly.
    out.sort_by_key(|a| a.1.to_lowercase());
    out
}

// ---------------- injection ----------------

/// Run the bundled 32-bit injector to load `dll` into a WOW64 process.
///
/// The helper lives next to the monitor as `universal_injector_x86.exe`. It performs the
/// whole injection natively in the 32-bit world; this function only spawns it and
/// translates its exit status.
fn inject_via_x86_helper(pid: u32, dll: &str) -> Result<(), String> {
    let helper = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("universal_injector_x86.exe")));
    let Some(helper) = helper else {
        return Err("找不到 32 位注入器路径".into());
    };
    if !helper.exists() {
        return Err(format!(
            "缺少 32 位注入器 {}（请构建：\
             cargo build --release --bin universal_injector_x86 --target i686-pc-windows-msvc）",
            helper.display()
        ));
    }
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new(&helper)
        .arg(pid.to_string())
        .arg(dll)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("无法启动 32 位注入器: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let msg = String::from_utf8_lossy(&out.stderr);
    let msg = msg.trim();
    Err(if msg.is_empty() {
        format!("32 位注入器失败（退出码 {:?}）", out.status.code())
    } else {
        format!("32 位注入器失败: {msg}")
    })
}

/// Path of the hook DLL that matches a target's bitness.
///
/// Two binaries ship beside the monitor:
///   monitor_hook.dll       — x64, injected into 64-bit targets
///   monitor_hook_x86.dll   — x86, injected into 32-bit (WOW64) targets
///
/// A 64-bit process cannot load an x86 DLL and vice versa, so the right one has to be
/// picked from the target's bitness rather than from the monitor's own.
pub fn dll_path_for(wow64_target: bool) -> Option<std::path::PathBuf> {
    let dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    let name = if wow64_target {
        "monitor_hook_x86.dll"
    } else {
        "monitor_hook.dll"
    };
    let p = dir.join(name);
    if p.exists() {
        Some(p)
    } else {
        // Fall back to the 64-bit name so old layouts keep working (a 64-bit target).
        let alt = dir.join("monitor_hook.dll");
        if alt.exists() {
            Some(alt)
        } else {
            Some(p)
        }
    }
}

/// Path of the monitor's own (64-bit) hook DLL.
pub fn dll_path() -> Option<std::path::PathBuf> {
    dll_path_for(false)
}

/// Is this process 32-bit running under WOW64?
pub fn is_wow64(pid: u32) -> Option<bool> {
    let proc = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if proc.is_null() {
        return None;
    }
    let mut wow64 = 0i32;
    let ok = unsafe { IsWow64Process(proc, &mut wow64) };
    unsafe { CloseHandle(proc) };
    if ok == 0 {
        None
    } else {
        Some(wow64 != 0)
    }
}

/// Inject the hook DLL into `pid`, choosing the 64-bit or 32-bit DLL from the target's
/// own bitness. `dll` is the 64-bit path; the 32-bit sibling is derived from it.
pub fn inject(pid: u32, dll: &str) -> Result<(), String> {
    // No PROCESS_VM_READ here: requesting it alongside the write rights made
    // VirtualAllocEx fail with ERROR_ACCESS_DENIED on ordinary processes. Read access is
    // only needed for optional diagnostics, so it is requested separately (and the code
    // that uses it tolerates its absence).
    let proc = unsafe {
        OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_LIMITED_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE,
            0,
            pid,
        )
    };
    if proc.is_null() {
        return Err(format!("OpenProcess 失败 (pid {})", pid));
    }
    // Pick the DLL that matches the target's architecture.
    let mut wow64 = 0i32;
    let ok = unsafe { IsWow64Process(proc, &mut wow64) };
    if ok == 0 {
        unsafe { CloseHandle(proc) };
        return Err("IsWow64Process 失败".into());
    }
    let dll = if wow64 != 0 {
        // 32-bit target: use the x86 build of the hook.
        let p = std::path::Path::new(dll);
        let x86 = p.with_file_name("monitor_hook_x86.dll");
        if !x86.exists() {
            unsafe { CloseHandle(proc) };
            return Err(format!(
                "目标是 32 位进程，但缺少 {}（请用 i686 目标编译 hook：\
                 cargo build --release -p monitor_hook --target i686-pc-windows-msvc）",
                x86.display()
            ));
        }
        // Hand the whole job to the 32-bit helper: a 64-bit caller cannot reliably start
        // a remote LoadLibrary inside a WOW64 process (measured: entry address and path
        // were both correct, yet LoadLibrary returned -1 while the very same DLL loaded
        // fine in a native 32-bit host). The helper runs in the native 32-bit world, so
        // every address it computes is valid there.
        unsafe { CloseHandle(proc) };
        return inject_via_x86_helper(pid, &x86.to_string_lossy());
    } else {
        dll.to_string()
    };
    let dll = dll.as_str();
    let kernel32 = wide("kernel32.dll");
    let hmod = unsafe {
        extern "system" {
            fn GetModuleHandleW(name: *const u16) -> *mut std::ffi::c_void;
            fn GetProcAddress(h: *mut std::ffi::c_void, name: *const u8) -> *mut std::ffi::c_void;
        }
        let h = GetModuleHandleW(kernel32.as_ptr());
        let n = b"LoadLibraryW\0".to_vec();
        GetProcAddress(h, n.as_ptr() as *const u8)
    };
    if hmod.is_null() {
        unsafe { CloseHandle(proc) };
        return Err("GetProcAddress(LoadLibraryW) 失败".into());
    }
    // 32-bit targets get an ANSI path + LoadLibraryA. The DLL loads correctly when a
    // 32-bit host (rundll32) opens it, so the failure is specific to running
    // LoadLibraryW remotely from a 64-bit injector; the ANSI entry point with a byte
    // path avoids the wide-string type question entirely.
    let (path_bytes, is_wide) = if wow64 != 0 {
        let mut v = dll.as_bytes().to_vec();
        v.push(0);
        (v, false)
    } else {
        (
            wide(dll).iter().flat_map(|u| u.to_le_bytes()).collect(),
            true,
        )
    };
    let bytes = path_bytes.len();
    let _ = is_wide;
    // For a 32-bit (WOW64) target the allocation must land in the low 4 GB.
    let alloc_flags = if wow64 != 0 {
        MEM_COMMIT | MEM_RESERVE | 0x0010_0000 // MEM_TOP_DOWN
    } else {
        MEM_COMMIT | MEM_RESERVE
    };
    let remote = unsafe {
        VirtualAllocEx(
            proc,
            std::ptr::null_mut(),
            bytes,
            alloc_flags,
            PAGE_READWRITE,
        )
    };
    if remote.is_null() {
        unsafe { CloseHandle(proc) };
        return Err(format!("VirtualAllocEx 失败 (err={})", get_last_error()));
    }
    // A 32-bit target can only address the low 4 GB: the buffer holding the DLL path
    // must live there, otherwise the remote LoadLibraryW receives a truncated pointer
    // and returns NULL.
    if wow64 != 0 && remote as usize > 0xFFFF_FFFF {
        unsafe {
            VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
            CloseHandle(proc);
        }
        return Err(format!("32 位目标的分配地址超出 4GB 范围 ({:p})", remote));
    }
    let mut written = 0usize;
    let ok = unsafe {
        WriteProcessMemory(
            proc,
            remote,
            path_bytes.as_ptr() as *const u8,
            bytes,
            &mut written,
        )
    };
    // Verify the path only when the target grants read access. Some processes deny
    // PROCESS_VM_READ (VirtualAllocEx then fails with ERROR_ACCESS_DENIED), and a failed
    // *verification* must not abort an injection that is otherwise fine.
    {
        let mut check = vec![0u8; bytes];
        let mut got = 0usize;
        let read_ok = unsafe {
            ReadProcessMemory(
                proc,
                remote as *const std::ffi::c_void,
                check.as_mut_ptr() as *mut std::ffi::c_void,
                bytes,
                &mut got,
            )
        } != 0;
        if read_ok && check != path_bytes {
            eprintln!("inject: 路径回读不一致，中止注入");
            unsafe {
                VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
                CloseHandle(proc);
            }
            return Err("写入目标进程的 DLL 路径无法正确回读".into());
        }
    }
    if ok == 0 || written != bytes {
        unsafe {
            VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
            CloseHandle(proc);
        }
        return Err(format!(
            "WriteProcessMemory 失败 (err={})",
            get_last_error()
        ));
    }
    let entry = hmod;
    let th = unsafe {
        CreateRemoteThread(
            proc,
            std::ptr::null_mut(),
            0,
            entry,
            remote,
            0,
            std::ptr::null_mut(),
        )
    };
    if th.is_null() {
        unsafe {
            VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
            CloseHandle(proc);
        }
        return Err("CreateRemoteThread 失败".into());
    }
    let waited = unsafe { WaitForSingleObject(th, 10_000) };
    let mut code = 0u32;
    unsafe { GetExitCodeThread(th, &mut code) };
    unsafe { CloseHandle(th) };
    unsafe { VirtualFreeEx(proc, remote, 0, MEM_RELEASE) };
    unsafe { CloseHandle(proc) };
    // STILL_ACTIVE (259) means the remote thread never finished: the wait timed out, so
    // `code` is not a module handle and must not be treated as success.
    const STILL_ACTIVE: u32 = 259;
    const WAIT_TIMEOUT: u32 = 0x102;
    if waited == WAIT_TIMEOUT || code == STILL_ACTIVE {
        return Err(format!(
            "远程线程未在 10 秒内完成（可能被注入到正在关闭的进程，或 LoadLibrary 卡住）"
        ));
    }
    if code == 0 {
        return Err(format!(
            "LoadLibrary 返回 NULL — 无法在目标进程加载 {dll}。\
             常见原因：DLL 架构不匹配、缺少 VC 运行时、或路径不可访问。"
        ));
    }
    // The thread exit code is a machine word. In a WOW64 target the WOW64 layer may
    // sign-extend or truncate the returned HMODULE, so a non-zero value here is only
    // weak evidence. For 32-bit targets, confirm the DLL really is loaded by
    // enumerating the target's modules (architecture-aware) and looking for it by name.
    if wow64 != 0 {
        let leaf = std::path::Path::new(dll)
            .file_name()
            .map(|s| s.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        let verify_proc =
            unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | 0x0010, 0, pid) };
        let loaded = if verify_proc.is_null() {
            false
        } else {
            let mods = wow64_module_bases(verify_proc);
            let hit = mods.iter().any(|(_, p)| p.to_lowercase().ends_with(&leaf));
            unsafe { CloseHandle(verify_proc) };
            hit
        };
        if !loaded {
            return Err(format!(
                "目标进程里没有加载 {leaf}（远程线程返回 {code:#x}，但模块列表中没有它）"
            ));
        }
    }
    Ok(())
}

/// Resolve `LoadLibraryW` inside a 32-bit (WOW64) target process.
///
/// Our own process is 64-bit, so our kernel32 address is meaningless in the target.
/// The reliable route is to ask the target for its own kernel32 base through a tiny
/// remote call: `GetModuleHandleW(L"kernel32.dll")` then `GetProcAddress(_, "LoadLibraryW")`.
/// Both of those functions exist at WOW64-mapped addresses that the kernel translates,
/// so calling the *target's* GetModuleHandleW is what makes this work.
///
/// Implementation: put the wide string in the target, start a remote thread on the
/// target's `GetModuleHandleW`, read the returned HMODULE, then a second remote thread
/// on the target's `GetProcAddress` with that module — reading the result each time.

/// Resolve `LoadLibraryW` inside a 32-bit (WOW64) target process.
///
/// A 64-bit injector cannot use its own kernel32 address in a 32-bit target, so the
/// address is derived from the target itself:
///
///   1. `NtQueryInformationProcess` → 64-bit PEB of the target
///   2. WOW64 keeps a pointer to the 32-bit PEB at the start of the 64-bit PEB
///   3. walk the 32-bit PEB's `Ldr.InMemoryOrderModuleList` to find kernel32's base
///   4. parse that module's export directory (read through `ReadProcessMemory`)
///      and return the RVA of `LoadLibraryW` plus the base
///
/// Every step is read-only against the target, so a failure can never harm it.
fn resolve_loadlibrary_in_32bit_target(
    proc: *mut std::ffi::c_void,
) -> Result<*mut std::ffi::c_void, String> {
    // kernel32 is large and always maps kernelbase; LoadLibraryW is exported by
    // kernel32 itself on every supported Windows version.
    if let Ok(a) = wow64_export_address(proc, "kernel32.dll", "LoadLibraryW") {
        return Ok(a);
    }
    // kernelbase also exports it on Windows 10/11; fall back there.
    wow64_export_address(proc, "kernelbase.dll", "LoadLibraryW")
}

/// `LoadLibraryA` inside a WOW64 target, used when the wide version fails.
///
/// The DLL was verified to load correctly when a 32-bit process (rundll32) is pointed
/// at it, so the failure is specific to the remote call. Some 32-bit targets refuse a
/// wchar_t* path written by a 64-bit writer; the ANSI entry point with a plain byte
/// path avoids the type question entirely.
fn resolve_loadlibrarya_in_32bit_target(
    proc: *mut std::ffi::c_void,
) -> Result<*mut std::ffi::c_void, String> {
    if let Ok(a) = wow64_export_address(proc, "kernel32.dll", "LoadLibraryA") {
        return Ok(a);
    }
    wow64_export_address(proc, "kernelbase.dll", "LoadLibraryA")
}

extern "system" {
    fn NtQueryInformationProcess(
        handle: *mut std::ffi::c_void,
        class: u32,
        info: *mut std::ffi::c_void,
        len: u32,
        ret: *mut u32,
    ) -> i32;
    fn ReadProcessMemory(
        proc: *mut std::ffi::c_void,
        addr: *const std::ffi::c_void,
        buf: *mut std::ffi::c_void,
        size: usize,
        read: *mut usize,
    ) -> i32;
}

fn read_remote(proc: *mut std::ffi::c_void, addr: u64, buf: &mut [u8]) -> bool {
    if addr == 0 {
        return false;
    }
    let mut read = 0usize;
    unsafe {
        ReadProcessMemory(
            proc,
            addr as *const std::ffi::c_void,
            buf.as_mut_ptr() as *mut std::ffi::c_void,
            buf.len(),
            &mut read,
        ) != 0
            && read == buf.len()
    }
}

fn read_remote_u32(proc: *mut std::ffi::c_void, addr: u64) -> Option<u32> {
    let mut b = [0u8; 4];
    if read_remote(proc, addr, &mut b) {
        Some(u32::from_le_bytes(b))
    } else {
        None
    }
}

extern "system" {
    fn EnumProcessModulesEx(
        process: *mut std::ffi::c_void,
        modules: *mut *mut std::ffi::c_void,
        size: u32,
        needed: *mut u32,
        filter: u32,
    ) -> i32;
    fn GetModuleFileNameExW(
        process: *mut std::ffi::c_void,
        module: *mut std::ffi::c_void,
        name: *mut u16,
        size: u32,
    ) -> u32;
}

/// Is a module whose file name starts with `prefix` loaded in `pid`?
///
/// Uses EnumProcessModulesEx with the architecture filter that matches the target, so it
/// works for both 64-bit and WOW64 processes. (A Toolhelp-based version reported "not
/// loaded" even for successful injections because it guessed the struct offset wrong.)
pub fn is_dll_loaded(pid: u32, prefix: &str) -> bool {
    let proc = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | 0x0010, 0, pid) };
    if proc.is_null() {
        return false;
    }
    let wow = unsafe {
        let mut w = 0i32;
        IsWow64Process(proc, &mut w) != 0 && w != 0
    };
    let mods = if wow {
        wow64_module_bases(proc)
    } else {
        native_module_bases(proc)
    };
    unsafe { CloseHandle(proc) };
    let needle = prefix.to_lowercase();
    mods.iter().any(|(_, p)| {
        p.rsplit(['\\', '/'])
            .next()
            .unwrap_or(p)
            .to_lowercase()
            .starts_with(&needle)
    })
}

/// Module list of a 64-bit process.
fn native_module_bases(proc: *mut std::ffi::c_void) -> Vec<(*mut std::ffi::c_void, String)> {
    extern "system" {
        fn EnumProcessModulesEx(
            process: *mut std::ffi::c_void,
            modules: *mut *mut std::ffi::c_void,
            size: u32,
            needed: *mut u32,
            filter: u32,
        ) -> i32;
        fn GetModuleFileNameExW(
            process: *mut std::ffi::c_void,
            module: *mut std::ffi::c_void,
            name: *mut u16,
            size: u32,
        ) -> u32;
    }
    const LIST_MODULES_ALL: u32 = 0x03;
    let mut out = Vec::new();
    let mut needed: u32 = 0;
    unsafe { EnumProcessModulesEx(proc, std::ptr::null_mut(), 0, &mut needed, LIST_MODULES_ALL) };
    if needed == 0 {
        return out;
    }
    let count = needed as usize / std::mem::size_of::<*mut std::ffi::c_void>();
    if count == 0 || count > 8192 {
        return out;
    }
    let mut mods: Vec<*mut std::ffi::c_void> = vec![std::ptr::null_mut(); count];
    let mut needed2: u32 = 0;
    let ok = unsafe {
        EnumProcessModulesEx(
            proc,
            mods.as_mut_ptr(),
            (count * std::mem::size_of::<*mut std::ffi::c_void>()) as u32,
            &mut needed2,
            LIST_MODULES_ALL,
        )
    };
    if ok == 0 {
        return out;
    }
    for m in mods {
        if m.is_null() {
            continue;
        }
        let mut buf = [0u16; 512];
        let n = unsafe { GetModuleFileNameExW(proc, m, buf.as_mut_ptr(), buf.len() as u32) };
        if n == 0 {
            continue;
        }
        out.push((m, String::from_utf16_lossy(&buf[..n as usize])));
    }
    out
}

/// Module bases of a 32-bit (WOW64) process, via EnumProcessModulesEx.
///
/// This is far more robust than walking the target's PEB loader list from a 64-bit
/// process: the API performs the WOW64 translation itself, so it returns the *32-bit*
/// module handles even though the caller is 64-bit. The previous PEB walk intermittently
/// read an unreadable list entry and stopped after a handful of modules, which is why
/// kernel32 was often never reached.
fn wow64_module_bases(proc: *mut std::ffi::c_void) -> Vec<(*mut std::ffi::c_void, String)> {
    const LIST_MODULES_32BIT: u32 = 0x01;
    let mut out = Vec::new();
    let mut needed: u32 = 0;
    // First call sizes the array.
    unsafe {
        EnumProcessModulesEx(
            proc,
            std::ptr::null_mut(),
            0,
            &mut needed,
            LIST_MODULES_32BIT,
        )
    };
    if needed == 0 {
        return out;
    }
    let count = needed as usize / std::mem::size_of::<*mut std::ffi::c_void>();
    if count == 0 || count > 4096 {
        return out;
    }
    let mut mods: Vec<*mut std::ffi::c_void> = vec![std::ptr::null_mut(); count];
    let mut needed2: u32 = 0;
    let ok = unsafe {
        EnumProcessModulesEx(
            proc,
            mods.as_mut_ptr(),
            (count * std::mem::size_of::<*mut std::ffi::c_void>()) as u32,
            &mut needed2,
            LIST_MODULES_32BIT,
        )
    };
    if ok == 0 {
        return out;
    }
    for m in mods {
        if m.is_null() {
            continue;
        }
        let mut buf = [0u16; 512];
        let n = unsafe { GetModuleFileNameExW(proc, m, buf.as_mut_ptr(), buf.len() as u32) };
        if n == 0 {
            continue;
        }
        let full = String::from_utf16_lossy(&buf[..n as usize]);
        out.push((m, full));
    }
    out
}

/// Address of an export in a WOW64 target: pick the module by name from the
/// architecture-aware module list, then parse that image's export directory.
fn wow64_export_address(
    proc: *mut std::ffi::c_void,
    module: &str,
    symbol: &str,
) -> Result<*mut std::ffi::c_void, String> {
    let mods = wow64_module_bases(proc);
    if mods.is_empty() {
        return Err("无法枚举 32 位目标的模块".into());
    }
    let want = module.to_lowercase();
    let mut hit_base: u64 = 0;
    for (base, path) in &mods {
        let leaf = path
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(path)
            .to_lowercase();
        if leaf == want {
            hit_base = *base as u64;
            break;
        }
    }
    if hit_base == 0 {
        let names: Vec<String> = mods
            .iter()
            .filter_map(|(_, p)| p.rsplit(['\\', '/']).next().map(|s| s.to_string()))
            .take(8)
            .collect();
        return Err(format!(
            "32 位目标中未找到 {module}（可见模块: {}）",
            names.join(", ")
        ));
    }
    eprintln!("inject: {module} 基址 = {hit_base:#x}");
    let addr = export_rva_of(proc, hit_base, symbol)?;
    eprintln!(
        "inject: {symbol} RVA = {addr:#x} → 绝对地址 {:#x}",
        hit_base + addr as u64
    );
    Ok((hit_base + addr as u64) as *mut std::ffi::c_void)
}

/// Base address of a module loaded in a WOW64 target, found through the 32-bit PEB.
fn peb32_module_base(proc: *mut std::ffi::c_void, want: &str) -> Result<u64, String> {
    #[repr(C)]
    struct Pbi64 {
        exit_status: usize,
        peb: usize,
        affinity: usize,
        base_priority: isize,
        unique_pid: usize,
        parent_pid: usize,
    }
    let mut pbi = Pbi64 {
        exit_status: 0,
        peb: 0,
        affinity: 0,
        base_priority: 0,
        unique_pid: 0,
        parent_pid: 0,
    };
    let st = unsafe {
        NtQueryInformationProcess(
            proc,
            0, // ProcessBasicInformation
            &mut pbi as *mut Pbi64 as *mut std::ffi::c_void,
            std::mem::size_of::<Pbi64>() as u32,
            std::ptr::null_mut(),
        )
    };
    if st != 0 || pbi.peb == 0 {
        return Err(format!(
            "NtQueryInformationProcess 失败 (0x{:08X})",
            st as u32
        ));
    }
    // The 64-bit PEB of a WOW64 process does NOT begin with a pointer to the 32-bit
    // PEB (that is a common misconception; the pointer lives further in). The reliable
    // source is the thread environment block of the target's main thread, which holds
    // the 32-bit TEB at offset 0x2000 in a WOW64 process. Rather than guess layouts,
    // try the documented WOW64 PEB location: In the 64-bit PEB, `Ldr` is followed by
    // process fields, and the 32-bit PEB base is exposed through
    // NtQueryInformationProcess(ProcessWow64Information) — which returns exactly that
    // pointer and needs no layout assumptions.
    let mut wow_peb: usize = 0;
    let st2 = unsafe {
        NtQueryInformationProcess(
            proc,
            26, // ProcessWow64Information
            &mut wow_peb as *mut usize as *mut std::ffi::c_void,
            std::mem::size_of::<usize>() as u32,
            std::ptr::null_mut(),
        )
    };
    if st2 != 0 || wow_peb == 0 {
        return Err(format!(
            "ProcessWow64Information 失败 (0x{:08X})，目标可能不是 WOW64",
            st2 as u32
        ));
    }
    let peb32 = wow_peb as u64;
    // PEB32 layout check: the first DWORD holds InheritedAddressSpace/ReadImageFile/
    // BeingDebugged as single bytes, then a pointer to the process image base follows.
    // Validate the candidate PEB by reading ImageBaseAddress (+0x08), which must be a
    // plausible module address; if it is not, ProcessWow64Information returned the
    // 64-bit PEB's address space view and the 32-bit PEB has to be read differently.
    let image_base = read_remote_u32(proc, peb32 + 0x08).unwrap_or(0);
    if image_base == 0 || image_base < 0x1000 {
        return Err(format!(
            "32 位 PEB 校验失败 (PEB32={peb32:#x}, ImageBase={image_base:#x})"
        ));
    }
    // PEB32.Ldr at +0x0C.
    let ldr = read_remote_u32(proc, peb32 + 0x0C).unwrap_or(0) as u64;
    if ldr == 0 {
        return Err(format!("Ldr 为空 (PEB32={peb32:#x})"));
    }
    // Sanity: Ldr must live in the low 4 GB and must not equal a kernel32/ntdll export
    // address pattern that would indicate a misread.
    if ldr > 0xFFFF_FFFF {
        return Err(format!("Ldr 地址越界: {ldr:#x}"));
    }
    // PEB_LDR_DATA32: InMemoryOrderModuleList (LIST_ENTRY) at +0x14.
    let list_head = ldr + 0x14;
    let mut link = read_remote_u32(proc, list_head).unwrap_or(0) as u64;
    let needle = want.to_lowercase();
    let mut seen = 0;
    for _ in 0..256 {
        if link == 0 || link == list_head {
            break;
        }
        seen += 1;
        // LDR_DATA_TABLE_ENTRY32, addressed by its InMemoryOrderLinks member:
        //   +0x00 Flink            +0x04 Blink          (InMemoryOrderLinks)
        //   +0x08 DllBase          +0x0C EntryPoint
        //   +0x10 SizeOfImage      +0x14 FullDllName    (UNICODE_STRING)
        //   +0x1C BaseDllName      (UNICODE_STRING)
        //
        // Verified against a live WOW64 target: the name at +0x1C is the FULL path
        // ("c:\windows\system32\kernel32.dll"), so matching is by file name suffix
        // rather than equality. DllBase is read at +0x08; the earlier value that looked
        // like a heap pointer was being taken from the FullDllName buffer instead.
        let base = read_remote_u32(proc, link + 0x08).unwrap_or(0) as u64;
        let name_len = read_remote_u32(proc, link + 0x1C).unwrap_or(0) as u16 as usize;
        let name_buf_ptr = read_remote_u32(proc, link + 0x20).unwrap_or(0) as u64;
        let chars = name_len / 2;
        if chars > 0 && chars < 260 && name_buf_ptr != 0 {
            let mut raw = vec![0u8; chars * 2];
            if read_remote(proc, name_buf_ptr, &mut raw) {
                let units: Vec<u16> = raw
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                let full = String::from_utf16_lossy(&units);
                let leaf = full
                    .rsplit(['\\', '/'])
                    .next()
                    .unwrap_or(&full)
                    .to_lowercase();
                if leaf == needle && base != 0 {
                    // Verify this really is the module image base: a PE header must be
                    // there. Reading the wrong field is the classic failure mode here,
                    // and a bogus base makes the export walk fail with "not a PE".
                    let mut mz = [0u8; 2];
                    if read_remote(proc, base, &mut mz) && &mz == b"MZ" {
                        return Ok(base);
                    }
                    // Probe the neighbouring slots for a valid PE image header.
                    for delta in [0x0Cu64, 0x10, 0x14, 0x18, 0x04] {
                        let cand = read_remote_u32(proc, link + delta).unwrap_or(0) as u64;
                        let mut m = [0u8; 2];
                        if cand != 0 && read_remote(proc, cand, &mut m) && &m == b"MZ" {
                            return Ok(cand);
                        }
                    }
                    return Err(format!("{needle} 的 PE 基址无效 (读到 {base:#x})"));
                }
            }
        }
        link = match read_remote_u32(proc, link) {
            Some(next) => next as u64,
            None => break, // unreadable entry: stop rather than spin
        };
    }
    eprintln!("inject: 模块链遍历 {seen} 个条目仍未匹配 {want}");
    Err(format!("32 位目标中未找到 {want}"))
}

/// RVA of an exported symbol in a module loaded in the target (PE32 export walk).
fn export_rva_of(proc: *mut std::ffi::c_void, base: u64, symbol: &str) -> Result<u32, String> {
    let mut dos = [0u8; 64];
    if !read_remote(proc, base, &mut dos) {
        return Err("读取 PE 头失败".into());
    }
    if &dos[0..2] != b"MZ" {
        return Err("不是有效的 PE 模块".into());
    }
    let e_lfanew = u32::from_le_bytes([dos[0x3C], dos[0x3D], dos[0x3E], dos[0x3F]]) as u64;
    let mut nt = [0u8; 264];
    if !read_remote(proc, base + e_lfanew, &mut nt) {
        return Err("读取 NT 头失败".into());
    }
    if &nt[0..4] != b"PE\0\0" {
        return Err("PE 签名错误".into());
    }
    // Optional header: DataDirectory[0] = export table, at optional header + 96 (PE32).
    let opt = 24usize; // after signature(4) + file header(20)
    let export_rva =
        u32::from_le_bytes([nt[opt + 96], nt[opt + 97], nt[opt + 98], nt[opt + 99]]) as u64;
    let export_size =
        u32::from_le_bytes([nt[opt + 100], nt[opt + 101], nt[opt + 102], nt[opt + 103]]);
    if export_rva == 0 {
        return Err("模块没有导出表".into());
    }
    let dir = base + export_rva;
    // IMAGE_EXPORT_DIRECTORY, 40 bytes.
    let mut ed = [0u8; 40];
    if !read_remote(proc, dir, &mut ed) {
        return Err("读取导出目录失败".into());
    }
    let _ = export_size;
    let num_names = u32::from_le_bytes([ed[24], ed[25], ed[26], ed[27]]) as usize;
    let addr_of_names = u32::from_le_bytes([ed[32], ed[33], ed[34], ed[35]]) as u64;
    let addr_of_funcs = u32::from_le_bytes([ed[28], ed[29], ed[30], ed[31]]) as u64;
    let addr_of_ords = u32::from_le_bytes([ed[36], ed[37], ed[38], ed[39]]) as u64;
    let want = symbol.as_bytes();
    for i in 0..num_names.min(8192) {
        let name_rva =
            read_remote_u32(proc, base + addr_of_names + i as u64 * 4).unwrap_or(0) as u64;
        if name_rva == 0 {
            continue;
        }
        let mut name_buf = [0u8; 128];
        if !read_remote(proc, base + name_rva, &mut name_buf) {
            continue;
        }
        let end = name_buf
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(name_buf.len());
        if &name_buf[..end] == want {
            let ord = u16::from_le_bytes([
                read_remote_u32(proc, base + addr_of_ords + i as u64 * 2)
                    .map(|v| v as u8)
                    .unwrap_or(0),
                0,
            ]) as usize;
            let func_rva =
                read_remote_u32(proc, base + addr_of_funcs + ord as u64 * 4).unwrap_or(0);
            if func_rva != 0 {
                return Ok(func_rva);
            }
        }
    }
    Err(format!("未找到导出符号 {symbol}"))
}

/// Hidden CLI: --inject-smoke. Spawns ping.exe (64-bit, harmless, opens no COM),
/// injects the hook, waits ≤5 s for the ATTACH record over the pipe, kills it.
/// Prints one line and returns 0 (attach seen) or 1.
pub fn smoke_inject() -> i32 {
    let dll = match dll_path() {
        Some(p) => p,
        None => {
            println!("smoke: FAIL no dll path");
            return 1;
        }
    };
    if !dll.exists() {
        println!("smoke: FAIL missing dll {}", dll.display());
        return 1;
    }
    use std::os::windows::process::CommandExt;
    let child = std::process::Command::new("C:\\Windows\\System32\\ping.exe")
        .args(["-n", "25", "127.0.0.1"])
        .creation_flags(CREATE_NO_WINDOW)
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            println!("smoke: FAIL spawn ping: {}", e);
            return 1;
        }
    };
    let pid = child.id();
    let _ = std::fs::write(std::env::temp_dir().join("um_hook_debug"), b"1");
    let _ = std::fs::remove_file(std::env::temp_dir().join(format!("um_hook_{}.log", pid)));
    let rx = start_capture_server();
    if let Err(e) = inject(pid, &dll.to_string_lossy()) {
        println!("smoke: FAIL inject: {}", e);
        let _ = child.kill();
        let _ = child.wait();
        return 1;
    }
    // diagnostic: is monitor_hook.dll resident in the child?
    if let Ok(out) = std::process::Command::new("tasklist")
        .args(["/m", "monitor_hook.dll", "/fo", "csv", "/nh"])
        .output()
    {
        let s = String::from_utf8_lossy(&out.stdout).to_lowercase();
        println!("smoke: dll-resident={}", s.contains("ping.exe"));
    }
    let mut result = 1i32;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match rx.recv_timeout(std::time::Duration::from_millis(300)) {
            Ok(CapMsg::Attach { pid: p, exe }) if p == pid => {
                println!("smoke: OK pid {} exe {}", p, exe);
                result = 0;
                break;
            }
            Ok(m) => {
                let _ = m; // unexpected record — keep waiting
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if std::time::Instant::now() >= deadline {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    if result != 0 {
        println!("smoke: FAIL no attach within 5s");
        if let Ok(log) =
            std::fs::read_to_string(std::env::temp_dir().join(format!("um_hook_{}.log", pid)))
        {
            println!("smoke: hook log: {:?}", log);
        } else {
            println!("smoke: hook log: (none)");
        }
    }
    let _ = std::fs::remove_file(std::env::temp_dir().join("um_hook_debug"));
    result
}

/// Hidden CLI: --inject-comtest COMx COMy. Live end-to-end check of the whole
/// capture chain on a FREE loopback pair (e.g. the machine's idle COM1->COM2
/// Eltima pair; never the user's active ports). Spawns a monitored powershell
/// (64-bit .NET P/Invoke — a runtime API binder) that opens COMx, writes PING123
/// and polls ReadExisting for 5 s; a second, unmonitored powershell opens COMy
/// ~1.5 s later and writes ECHO123 so the monitored one must RECEIVE. Requires
/// ATTACH + OPEN + TX + RX records within 10 s. 0 on success, 1 on failure.
pub fn comtest_inject(com: &str, peer: &str) -> i32 {
    let dll = match dll_path() {
        Some(p) => p,
        None => {
            println!("comtest: FAIL no dll path");
            return 1;
        }
    };
    if !dll.exists() {
        println!("comtest: FAIL missing dll {}", dll.display());
        return 1;
    }
    // The child must be launched with the debug marker already absent so no noise;
    // script: open port, write, poll reads (so an incoming echo is captured), close.
    let script = format!(
        "$ErrorActionPreference='Stop'; \
         try {{ $p = New-Object System.IO.Ports.SerialPort('{}',9600); $p.Open(); \
         $p.Write('PING123'); $acc=''; \
         foreach ($i in 1..20) {{ $acc += $p.ReadExisting(); Start-Sleep -Milliseconds 250 }}; \
         Write-Output ('READ='+$acc); $p.Close() }} \
         catch {{ Write-Output ('ERR='+$_.Exception.Message); exit 3 }}; \
         Start-Sleep -Seconds 1",
        com
    );
    let writer_script = format!(
        "$ErrorActionPreference='Stop'; \
         Start-Sleep -Milliseconds 1500; \
         try {{ $q = New-Object System.IO.Ports.SerialPort('{}',9600); $q.Open(); \
         $q.Write('ECHO123'); Start-Sleep -Milliseconds 800; $q.Close() }} \
         catch {{ exit 4 }}",
        peer
    );
    use std::os::windows::process::CommandExt;
    let child = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(std::process::Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            println!("comtest: FAIL spawn powershell: {}", e);
            return 1;
        }
    };
    let pid = child.id();
    // opt-in hook diagnostics for this run (child inherits %TEMP%)
    let _ = std::fs::write(std::env::temp_dir().join("um_hook_debug"), b"1");
    let _ = std::fs::remove_file(std::env::temp_dir().join(format!("um_hook_{}.log", pid)));
    let rx = start_capture_server();
    // give the CLR a moment so injection lands while it is starting, but before
    // SerialPort.Open (which follows the -Command parse)
    std::thread::sleep(std::time::Duration::from_millis(300));
    if let Err(e) = inject(pid, &dll.to_string_lossy()) {
        println!("comtest: FAIL inject: {}", e);
        let _ = child.kill();
        let _ = child.wait();
        return 1;
    }
    // the echo writer: NOT injected, opens the peer end ~1.5 s from now
    let writer = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &writer_script])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(std::process::Stdio::null())
        .spawn();
    let mut attach = false;
    let mut open = false;
    let mut tx = 0usize;
    let mut rxc = 0usize;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match rx.recv_timeout(std::time::Duration::from_millis(300)) {
            Ok(CapMsg::Attach { pid: p, exe }) if p == pid => {
                attach = true;
                println!("comtest: attach {} {}", p, exe);
            }
            Ok(CapMsg::Open {
                pid: p, port: name, ..
            }) if p == pid => {
                open = true;
                println!("comtest: open {} handle port {}", p, name);
            }
            Ok(CapMsg::Tx { pid: p, data, .. }) if p == pid => {
                tx += data.len();
                println!("comtest: tx {} bytes {:?}", data.len(), data);
            }
            Ok(CapMsg::Rx { pid: p, data, .. }) if p == pid => {
                rxc += data.len();
                println!("comtest: rx {} bytes {:?}", data.len(), data);
            }
            Ok(_) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if std::time::Instant::now() >= deadline {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    if let Ok(mut w) = writer {
        let _ = w.kill();
        let _ = w.wait();
    }
    if let Some(mut s) = child.stdout.take() {
        use std::io::Read;
        let mut b = Vec::new();
        let _ = s.read_to_end(&mut b);
        println!("comtest: child: {}", String::from_utf8_lossy(&b).trim());
    }
    let ok = attach && open && tx > 0 && rxc > 0;
    if let Ok(log) =
        std::fs::read_to_string(std::env::temp_dir().join(format!("um_hook_{}.log", pid)))
    {
        for line in log.lines().take(60) {
            println!("comtest: hook| {}", line);
        }
    }
    let _ = std::fs::remove_file(std::env::temp_dir().join("um_hook_debug"));
    println!(
        "comtest: {} attach={} open={} tx_bytes={} rx_bytes={}",
        if ok { "OK" } else { "FAIL" },
        attach,
        open,
        tx,
        rxc
    );
    if ok {
        0
    } else {
        1
    }
}
