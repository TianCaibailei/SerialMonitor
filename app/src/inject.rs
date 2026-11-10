// inject.rs — user-space interception front end (substitutes the original's
// kernel driver ComDrv12x/ParDrv3x: sub_a874f0 service mgr, sub_a8b020 deployer,
// sub_a89f70 device open, sub_a89d60 ioctl pump chain, all in app/MECHANICS.md).
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
    Attach { pid: u32, exe: String },
    Open { pid: u32, handle: u64, port: String },
    Close { pid: u32, handle: u64 },
    Rx { pid: u32, handle: u64, data: Vec<u8> },
    Tx { pid: u32, handle: u64, data: Vec<u8> },
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
        dbg(&format!("connect ret={} err={}", connected, get_last_error()));
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
            let ok = unsafe { ReadFile(h, buf.as_mut_ptr(), buf.len() as u32, &mut n, std::ptr::null_mut()) };
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
        TAG_ATTACH => Some(CapMsg::Attach { pid, exe: String::from_utf8_lossy(p).into_owned() }),
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
    "system", "csrss.exe", "smss.exe", "wininit.exe", "winlogon.exe", "lsass.exe",
    "services.exe", "svchost.exe", "dwm.exe", "fontdrvhost.exe", "winidle0.exe",
    "securityhealthservice.exe", "memory compression", "registry",
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
                    let critical = BLACKLIST.iter().any(|b| lower == *b || lower == format!("{}.exe", *b));
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
    out.sort_by(|a, b| a.1.to_lowercase().cmp(&b.1.to_lowercase()));
    out
}

// ---------------- injection ----------------

/// Path of monitor_hook.dll beside our own exe.
pub fn dll_path() -> Option<std::path::PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("monitor_hook.dll")))
}

/// Inject the hook DLL into `pid`. 64-bit targets only.
pub fn inject(pid: u32, dll: &str) -> Result<(), String> {
    let proc = unsafe { OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, 0, pid) };
    if proc.is_null() {
        return Err(format!("OpenProcess 失败 (pid {})", pid));
    }
    // 64-bit only
    let mut wow64 = 0i32;
    let ok = unsafe { IsWow64Process(proc, &mut wow64) };
    if ok == 0 || wow64 != 0 {
        unsafe { CloseHandle(proc) };
        return Err("32 位进程，本版本只支持注入 64 位进程".into());
    }
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
    let path = wide(dll);
    let bytes = path.len() * 2;
    let remote = unsafe {
        VirtualAllocEx(proc, std::ptr::null_mut(), bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    };
    if remote.is_null() {
        unsafe { CloseHandle(proc) };
        return Err("VirtualAllocEx 失败".into());
    }
    let mut written = 0usize;
    let ok = unsafe { WriteProcessMemory(proc, remote, path.as_ptr() as *const u8, bytes, &mut written) };
    if ok == 0 || written != bytes {
        unsafe {
            VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
            CloseHandle(proc);
        }
        return Err("WriteProcessMemory 失败".into());
    }
    let th = unsafe {
        CreateRemoteThread(
            proc,
            std::ptr::null_mut(),
            0,
            hmod,
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
    unsafe { WaitForSingleObject(th, 10_000) };
    let mut code = 0u32;
    unsafe { GetExitCodeThread(th, &mut code) };
    unsafe { CloseHandle(th) };
    unsafe { VirtualFreeEx(proc, remote, 0, MEM_RELEASE) };
    unsafe { CloseHandle(proc) };
    if code == 0 {
        // LoadLibraryW returned NULL — DLL missing or DllMain failed
        return Err(format!("LoadLibraryW 返回 NULL — 检查 {} 是否存在", dll));
    }
    Ok(())
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
        if let Ok(log) = std::fs::read_to_string(std::env::temp_dir().join(format!("um_hook_{}.log", pid))) {
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
            Ok(CapMsg::Open { pid: p, port: name, .. }) if p == pid => {
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
    if let Ok(log) = std::fs::read_to_string(std::env::temp_dir().join(format!("um_hook_{}.log", pid))) {
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
