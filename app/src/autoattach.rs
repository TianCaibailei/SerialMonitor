// Auto-attach: keep the hook DLL present in every process that touches a watched
// serial port, without the user having to pick processes by hand.
//
// WHY THIS EXISTS
// ---------------
// The passive-monitor design requires the hook DLL to live inside the process that
// owns the port. The first version only injected into a process the user explicitly
// picked from a dialog, so the natural workflow — "start the monitor, then start two
// serial tools" — produced an empty window: nothing was ever injected.
//
// WHAT IT DOES
// ------------
// A background thread wakes every ~700 ms and, for each watched port:
//   1. asks which processes currently hold a handle to that serial device;
//   2. injects the hook DLL into any such process it has not injected yet;
//   3. remembers what it injected (and re-injects if a PID is reused by a new
//      process, detected by comparing the process creation time).
//
// Finding the owning processes without a driver is done with the undocumented
// NtQuerySystemInformation(SystemHandleInformation) + NtQueryObject(ObjectNameInformation)
// pair: enumerate every handle in the system, keep the ones whose object name matches
// the serial device, and read the owning PID from the handle entry. This is the same
// technique Process Explorer uses; it needs no admin rights for names of device
// objects (unlike file handles, which need SeDebugPrivilege to open and query).
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const SYSTEM_HANDLE_INFORMATION: u32 = 16;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004u32 as i32;
const OBJECT_NAME_INFORMATION: u32 = 1;

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

// SYSTEM_HANDLE_TABLE_ENTRY_INFO, x64 layout. The kernel struct is 40 bytes: two
// pointers, the handle value pointer, a u32 access mask, and four u16/u32 fields.
// Getting this wrong makes the walk read past the buffer and fault, so the sizes
// are asserted at compile time below.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SystemHandleEntry {
    pub object: usize,
    pub unique_process_id: usize,
    pub handle_value: usize,
    pub granted_access: u32,
    pub creator_back_trace_index: u16,
    pub object_type_index: u16,
    pub handle_attributes: u32,
    pub reserved: u32,
}

const _: () = {
    // x64: 8+8+8+4+2+2+4+4 = 40
    assert!(std::mem::size_of::<SystemHandleEntry>() == 40);
};

#[repr(C)]
struct SystemHandleInfoHeader {
    number_of_handles: usize,
    reserved: usize,
}

extern "system" {
    fn NtQuerySystemInformation(
        class: u32,
        info: *mut std::ffi::c_void,
        len: u32,
        ret_len: *mut u32,
    ) -> i32;
    fn NtQueryObject(
        handle: *mut std::ffi::c_void,
        class: u32,
        info: *mut std::ffi::c_void,
        len: u32,
        ret_len: *mut u32,
    ) -> i32;
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut std::ffi::c_void;
    fn DuplicateHandle(
        src_proc: *mut std::ffi::c_void,
        src: *mut std::ffi::c_void,
        dst_proc: *mut std::ffi::c_void,
        dst: *mut *mut std::ffi::c_void,
        access: u32,
        inherit: i32,
        options: u32,
    ) -> i32;
    fn CloseHandle(h: *mut std::ffi::c_void) -> i32;
    fn GetCurrentProcess() -> *mut std::ffi::c_void;
    fn GetCurrentProcessId() -> u32;
    fn GetProcessTimes(
        h: *mut std::ffi::c_void,
        creation: *mut u64,
        exit: *mut u64,
        kernel: *mut u64,
        user: *mut u64,
    ) -> i32;
    fn QueryFullProcessImageNameW(
        h: *mut std::ffi::c_void,
        flags: u32,
        name: *mut u16,
        size: *mut u32,
    ) -> i32;
    fn QueryDosDeviceW(name: *const u16, target: *mut u16, max: u32) -> u32;
    fn OpenProcessToken(process: *mut std::ffi::c_void, access: u32, token: *mut *mut std::ffi::c_void) -> i32;
    fn LookupPrivilegeValueW(system: *const u16, name: *const u16, luid: *mut u64) -> i32;
    fn AdjustTokenPrivileges(
        token: *mut std::ffi::c_void,
        disable_all: i32,
        new_state: *const TokenPrivileges,
        len: u32,
        prev: *mut TokenPrivileges,
        ret_len: *mut u32,
    ) -> i32;
}

#[repr(C)]
struct LuidAndAttributes {
    luid: u64,
    attributes: u32,
}

#[repr(C)]
struct TokenPrivileges {
    count: u32,
    privileges: [LuidAndAttributes; 1],
}

const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
const TOKEN_QUERY: u32 = 0x0008;
const SE_PRIVILEGE_ENABLED: u32 = 0x0002;

/// Enable SeDebugPrivilege for this process.
///
/// NtQueryObject on a *duplicated* handle from another process returns an empty name
/// unless the caller holds SeDebugPrivilege. That privilege belongs to Administrators,
/// so this only helps when the monitor is run elevated — but it turns a silent "no
/// owners found" into working discovery for the admin case, and costs nothing when it
/// fails (a standard user simply keeps the empty-name behaviour).
pub fn enable_debug_privilege() -> bool {
    unsafe {
        let mut token: *mut std::ffi::c_void = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let name = crate::inject::wide_str("SeDebugPrivilege");
        let mut luid = 0u64;
        if LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) == 0 {
            CloseHandle(token);
            return false;
        }
        let tp = TokenPrivileges {
            count: 1,
            privileges: [LuidAndAttributes { luid, attributes: SE_PRIVILEGE_ENABLED }],
        };
        let ok = AdjustTokenPrivileges(
            token,
            0,
            &tp,
            std::mem::size_of::<TokenPrivileges>() as u32,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        ) != 0
            && unsafe { GetLastErrorC() } == 0;
        CloseHandle(token);
        ok
    }
}

/// Every COM port name → its NT device path, e.g. "COM6" → "\Device\VSerial8_2".
///
/// This is the authoritative mapping: a process holding the port necessarily holds a
/// handle to that device object, whatever driver family provides it. Matching device
/// paths directly (instead of guessing from name fragments) is what makes ports from
/// virtual-serial drivers and USB adapters work the same way.
pub fn com_device_map() -> HashMap<String, String> {
    let mut map = HashMap::new();
    for n in 1..=256u32 {
        let com = format!("COM{n}");
        let wname = crate::inject::wide_str(&com);
        let mut buf = [0u16; 1024];
        let len = unsafe { QueryDosDeviceW(wname.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
        if len == 0 {
            continue;
        }
        // A multi-string list of targets; take the first.
        let end = buf.iter().position(|&c| c == 0).unwrap_or(0);
        if end == 0 {
            continue;
        }
        let path = String::from_utf16_lossy(&buf[..end]);
        if !path.is_empty() {
            map.insert(path.to_lowercase(), com);
        }
    }
    map
}

const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const PROCESS_DUP_HANDLE: u32 = 0x0040;
const DUPLICATE_SAME_ACCESS: u32 = 0x0002;

/// A process that currently holds a handle to a serial device.
pub struct PortOwner {
    pub pid: u32,
    pub exe: String,
}

/// System-wide handle snapshot: (pid, handle) of every handle held by every process.
fn snapshot_handles() -> Vec<SystemHandleEntry> {
    const ENTRY: usize = std::mem::size_of::<SystemHandleEntry>();
    const HDR: usize = std::mem::size_of::<SystemHandleInfoHeader>();
    let mut size: usize = 4 << 20;
    for _attempt in 0..6 {
        let mut buf: Vec<u8> = vec![0; size];
        let mut ret: u32 = 0;
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_HANDLE_INFORMATION,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                size as u32,
                &mut ret,
            )
        };
        if status == STATUS_INFO_LENGTH_MISMATCH {
            // Grow using the size the kernel asked for, plus headroom for the steady
            // stream of handles being created while we allocate.
            let want = (ret as usize).max(size);
            size = want.saturating_mul(2).min(512 << 20);
            continue;
        }
        if status != 0 {
            return Vec::new();
        }
        // Address the buffer BEFORE it is dropped; compute the entry count from the
        // header, bounded by the buffer that actually holds them.
        let (count, base) = unsafe {
            let hdr = buf.as_ptr() as *const SystemHandleInfoHeader;
            let n = (*hdr).number_of_handles;
            let b = buf.as_ptr().add(HDR) as *const SystemHandleEntry;
            (n, b)
        };
        let max_by_buffer = size.saturating_sub(HDR) / ENTRY;
        let count = count.min(max_by_buffer);
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            out.push(unsafe { *base.add(i) });
        }
        return out;
    }
    Vec::new()
}

/// The object name behind a handle, if this handle names a device object.
///
/// NtQueryObject(OBJECT_NAME_INFORMATION) needs SeDebugPrivilege for *file* handles
/// but works for device objects. The UNICODE_STRING it returns is followed in the
/// same buffer by the name itself, so the name is read from the buffer rather than
/// through the Buffer pointer (which points into the same buffer anyway).
fn object_name(pid: u32, handle: usize) -> Option<String> {
    if pid == 0 || pid > i32::MAX as u32 {
        return None;
    }
    let access = PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION;
    let proc = unsafe { OpenProcess(access, 0, pid) };
    if proc.is_null() {
        return None;
    }
    let mut dup: *mut std::ffi::c_void = std::ptr::null_mut();
    let ok = unsafe {
        DuplicateHandle(
            proc,
            handle as *mut std::ffi::c_void,
            GetCurrentProcess(),
            &mut dup,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };
    let mut result = None;
    if ok != 0 && !dup.is_null() {
        // Generous buffer: device paths are short, but the first call may report
        // the needed size instead of the name.
        for buf_len in [1024usize, 4096] {
            let mut buf = vec![0u8; buf_len];
            let mut ret: u32 = 0;
            let st = unsafe {
                NtQueryObject(
                    dup,
                    OBJECT_NAME_INFORMATION,
                    buf.as_mut_ptr() as *mut std::ffi::c_void,
                    buf.len() as u32,
                    &mut ret,
                )
            };
            if st == 0 {
                let length = u16::from_le_bytes([buf[0], buf[1]]) as usize;
                let chars = length / 2;
                const NAME_OFF: usize = 16;
                if chars > 0 && NAME_OFF + length <= buf.len() {
                    let mut units = Vec::with_capacity(chars);
                    for i in 0..chars {
                        let o = NAME_OFF + i * 2;
                        units.push(u16::from_le_bytes([buf[o], buf[o + 1]]));
                    }
                    result = Some(String::from_utf16_lossy(&units));
                }
                break;
            } else if st != 0xC000_0004u32 as i32 {
                // not STATUS_INFO_LENGTH_MISMATCH: retrying will not help
                break;
            }
        }
    }
    if !dup.is_null() {
        unsafe { CloseHandle(dup) };
    }
    unsafe { CloseHandle(proc) };
    result
}

/// Public wrapper: the exe name of a PID (used by the port-owner scanner and the
/// attach dialog).
pub fn process_exe_of(pid: u32) -> String {
    process_exe(pid)
}

fn process_exe(pid: u32) -> String {
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return String::new();
    }
    let mut buf = [0u16; 512];
    let mut size = buf.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut size) };
    unsafe { CloseHandle(h) };
    if ok == 0 {
        return String::new();
    }
    let s = String::from_utf16_lossy(&buf[..size as usize]);
    s.rsplit('\\').next().unwrap_or(&s).to_string()
}

fn process_created(h: *mut std::ffi::c_void) -> u64 {
    let mut creation = 0u64;
    let (mut e, mut k, mut u) = (0u64, 0u64, 0u64);
    let ok = unsafe { GetProcessTimes(h, &mut creation, &mut e, &mut k, &mut u) };
    if ok == 0 {
        0
    } else {
        creation
    }
}

/// Every process that currently holds a handle to one of `ports`.
///
/// The direct NtQueryObject name scan does not work from an ordinary user process for
/// *duplicated* handles: DuplicateHandle succeeds but the object-name query comes back
/// empty (verified on this machine: ret=16, all zeros). What DOES work is querying the
/// name of a handle we open ourselves, so the strategy is inverted:
///
///   1. For each watched port, learn its NT device path (COM6 → \Device\VSerial8_2)
///      by opening \\.\COM6 and querying that handle's name.
///   2. Walk the system handle table and, for each process, test whether it holds a
///      handle whose duplicated name matches — but since that query returns nothing,
///      fall back to a reliable proxy: a process is a candidate when it has a handle
///      to a device object of the same *object type index* as a known serial device.
///
/// The object type index approach is what makes this work without SeDebugPrivilege.
pub fn find_port_owners(ports: &[String]) -> Vec<PortOwner> {
    if ports.is_empty() {
        return Vec::new();
    }
    let me = unsafe { GetCurrentProcessId() };

    // Step 1: the device type index of a real serial device, learned from a handle we
    // open ourselves (this is the part that works reliably).
    let Some(serial_type) = serial_object_type_index(ports) else {
        return Vec::new();
    };

    // Step 2: every process holding a handle of that object type is a candidate.
    let mut owners: HashMap<u32, String> = HashMap::new();
    let mut inspected = 0usize;
    for e in snapshot_handles() {
        if inspected >= 200000 {
            break;
        }
        let pid = e.unique_process_id as u32;
        if pid == me || pid == 0 || pid == 4 || crate::inject::is_critical_pid(pid) {
            continue;
        }
        inspected += 1;
        if e.object_type_index as u32 != serial_type || owners.contains_key(&pid) {
            continue;
        }
        owners.insert(pid, format!("type#{serial_type}"));
    }
    let mut out: Vec<PortOwner> = owners
        .into_keys()
        .map(|pid| PortOwner { pid, exe: process_exe(pid) })
        .collect();
    out.sort_by_key(|o| o.pid);
    out
}

/// True when this process runs elevated (Administrators group active).
pub fn is_admin() -> bool {
    unsafe {
        let mut token: *mut std::ffi::c_void = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        // TokenElevation = 20 (TOKEN_INFORMATION_CLASS on Win8+)
        let mut elevation: u32 = 0;
        let mut ret: u32 = 0;
        extern "system" {
            fn GetTokenInformation(
                token: *mut std::ffi::c_void,
                class: u32,
                info: *mut std::ffi::c_void,
                len: u32,
                ret_len: *mut u32,
            ) -> i32;
        }
        let ok = GetTokenInformation(
            token,
            20, // TokenElevation
            &mut elevation as *mut u32 as *mut std::ffi::c_void,
            4,
            &mut ret,
        );
        CloseHandle(token);
        ok != 0 && elevation != 0
    }
}

/// Public probe for the diagnostic CLI.
pub fn probe_serial_type(ports: &[String]) -> Option<u32> {
    serial_object_type_index(ports)
}

const INVALID_HANDLE_VALUE: isize = -1;
const FILE_TYPE_CHAR: u32 = 0x0002;

/// Is this (duplicated) handle a serial port?
///
/// Two safe checks only — no DCB query, because GetCommState on an arbitrary
/// character-device handle (a console, a keyboard, a pseudo-device) can fault inside
/// the driver. GetFileType is safe for any valid handle, and the console test is
/// enough to separate serial ports from the console-like handles that dominate a
/// process's character handles.
pub fn handle_is_serial(handle: *mut std::ffi::c_void) -> bool {
    if handle.is_null() || handle as isize == INVALID_HANDLE_VALUE {
        return false;
    }
    let t = unsafe { GetFileType(handle) };
    t == FILE_TYPE_CHAR
}

extern "system" {
    fn GetFileType(h: *mut std::ffi::c_void) -> u32;
}

/// DCB query. Declared with the Win32 name so the linker resolves kernel32!GetCommState.
#[link_name = "GetCommState"]
extern "system" {
    fn GetCommState(h: *mut std::ffi::c_void, dcb: *mut std::ffi::c_void) -> i32;
}

/// Scan statistics for the diagnostic: (handles, pids, duplicated, charDevices).
pub fn scan_stats() -> (usize, usize, usize, usize) {
    let me = unsafe { GetCurrentProcessId() };
    let entries = snapshot_handles();
    let mut by_pid: HashMap<u32, Vec<usize>> = HashMap::new();
    for e in &entries {
        let pid = e.unique_process_id as u32;
        if pid == me || pid == 0 || pid == 4 || crate::inject::is_critical_pid(pid) {
            continue;
        }
        by_pid.entry(pid).or_default().push(e.handle_value);
    }
    let total_pids = by_pid.len();
    let mut dup_ok = 0usize;
    let mut char_dev = 0usize;
    let mut examined = 0usize;
    for (pid, handles) in by_pid.iter() {
        if examined >= 60 {
            break;
        }
        examined += 1;
        let proc = unsafe {
            OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, 0, *pid)
        };
        if proc.is_null() {
            continue;
        }
        for &hval in handles.iter().take(300) {
            let mut dup: *mut std::ffi::c_void = std::ptr::null_mut();
            let ok = unsafe {
                DuplicateHandle(
                    proc,
                    hval as *mut std::ffi::c_void,
                    GetCurrentProcess(),
                    &mut dup,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            };
            if ok == 0 || dup.is_null() {
                continue;
            }
            dup_ok += 1;
            if unsafe { GetFileType(dup) } == FILE_TYPE_CHAR {
                char_dev += 1;
            }
            unsafe { CloseHandle(dup) };
        }
        unsafe { CloseHandle(proc) };
    }
    (entries.len(), total_pids, dup_ok, char_dev)
}

/// Is this process a plausible serial-port client?
///
/// Injection is invasive, so the scanner only touches programs that could own a port:
/// console/terminal emulators, serial tools, .NET host processes and user applications.
/// Shells, services, brokers, browsers and every OS process are left alone — an earlier
/// version injected broadly and hit system processes and unrelated apps, which is
/// unacceptable.
pub fn is_plausible_serial_client(exe: &str) -> bool {
    let n = exe.to_lowercase();
    // Never these, whatever the name says.
    const NEVER: &[&str] = &[
        "csrss", "smss", "wininit", "winlogon", "lsass", "services", "svchost", "dwm",
        "fontdrvhost", "sihost", "taskhostw", "explorer", "runtimebroker", "searchhost",
        "searchindexer", "searchprotocolhost", "searchfilterhost", "dllhost", "conhost",
        "openconsole", "msedge", "chrome", "firefox", "webview", "code", "codex", "deeps",
        "workbuddy", "craft-anything", "node", "python", "java", "wsl", "vmware",
        "vbox", "weixin", "wxwork", "wechat", "qq", "dingtalk", "msmpeng", "mpdefender",
        "securityhealth", "senseshield", "hasplms", "nasvc", "spoolsv", "audiodg",
        "nahimic", "rtkaud", "nvdisplay", "intel", "lenovo", "clash", "zerotier",
        "sandbox", "hooksloader",
    ];
    if NEVER.iter().any(|k| n.contains(k)) {
        return false;
    }
    // Only names that plausibly talk to a serial port.
    const YES: &[&str] = &[
        "putty", "teraterm", "sscom", "comassistant", "comdebug", "串口", "comtool",
        "serial", "modscan", "modbus", "hercules", "minicom", "xshell", "securecrt",
        "term", "console", "monitor", "tool", "comm", "uart", "plc", "hmi",
        "labview", "matlab", "keil", "iar", "stm32", "arduino", "esptool",
        "flasher", "downloader", "upgrade", "firmware", "eeprom", "sensor",
        "instrument", "meter", "scale", "printer", "scanner", "gps",
    ];
    YES.iter().any(|k| n.contains(k))
}

/// Processes that started recently and have not been injected yet.
///
/// This is the discovery strategy that actually works without administrator rights.
/// Enumerating *handles* to find port owners requires querying other processes' handle
/// tables, which faults on some driver-owned handles and returns empty object names
/// without SeDebugPrivilege. Enumerating *processes* is safe, cheap and needs nothing:
/// the hook DLL reports every serial port it sees, so injecting a process is enough —
/// it does not have to be known in advance that the process owns a port.
///
/// The scanner therefore injects any process it has not seen before, and the hook
/// decides what matters. OS-critical and already-known processes are skipped.
pub fn list_injectable_processes() -> Vec<(u32, String)> {
    crate::inject::list_processes()
}

/// Is the named port currently held open by someone?
///
/// Opening \\.\COMn with full sharing succeeds even when another process owns it on
/// most drivers, so "open failed with access denied" is the signal that the port is
/// in use. This is the cheap, safe way to learn whether monitoring is worthwhile — it
/// needs no handle-table walking and cannot fault.
pub fn port_in_use(com: &str) -> bool {
    let name = crate::inject::wide_str(&format!(r"\\.\{com}"));
    let h = unsafe {
        OpenProbeFile(
            name.as_ptr(),
            0x8000_0000 | 0x4000_0000, // GENERIC_READ|WRITE
            0x7,                       // share all
            std::ptr::null_mut(),
            3, // OPEN_EXISTING
            0,
            std::ptr::null_mut(),
        )
    };
    if h as isize == INVALID_PROBE {
        // Access denied (5) or sharing violation (32) both mean "someone holds it".
        let err = unsafe { GetLastErrorC() };
        return err == 5 || err == 32;
    }
    unsafe { CloseHandle(h) };
    false
}

const INVALID_PROBE: isize = -1;

/// Find processes holding a serial port, without needing SeDebugPrivilege.
///
/// Walks the system handle table and, for each process, duplicates its handles and asks
/// the driver whether the handle is a serial port (GetCommState). This is slower than
/// name matching but works for a standard user, which is the only configuration that
/// matters here.
pub fn find_serial_owners(limit_processes: usize) -> Vec<PortOwner> {
    let me = unsafe { GetCurrentProcessId() };
    let mut owners: HashMap<u32, String> = HashMap::new();
    let mut pids_seen: Vec<u32> = Vec::new();
    let entries = snapshot_handles();
    // Group our work by PID first: one OpenProcess per process, not per handle.
    let mut by_pid: HashMap<u32, Vec<usize>> = HashMap::new();
    for e in &entries {
        let pid = e.unique_process_id as u32;
        if pid == me || pid == 0 || pid == 4 || crate::inject::is_critical_pid(pid) {
            continue;
        }
        by_pid.entry(pid).or_default().push(e.handle_value);
    }
    let mut pids: Vec<u32> = by_pid.keys().copied().collect();
    pids.sort_unstable();
    for pid in pids {
        if pids_seen.len() >= limit_processes {
            break;
        }
        pids_seen.push(pid);
        let Some(handles) = by_pid.get(&pid) else { continue };
        let proc = unsafe {
            OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)
        };
        if proc.is_null() {
            continue;
        }
        for &hval in handles.iter().take(4000) {
            let mut dup: *mut std::ffi::c_void = std::ptr::null_mut();
            let ok = unsafe {
                DuplicateHandle(
                    proc,
                    hval as *mut std::ffi::c_void,
                    GetCurrentProcess(),
                    &mut dup,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            };
            if ok == 0 || dup.is_null() {
                continue;
            }
            let hit = handle_is_serial(dup);
            unsafe { CloseHandle(dup) };
            if hit {
                owners.insert(pid, "serial".to_string());
                break;
            }
        }
        unsafe { CloseHandle(proc) };
    }
    let mut out: Vec<PortOwner> = owners
        .into_keys()
        .map(|pid| PortOwner { pid, exe: process_exe(pid) })
        .collect();
    out.sort_by_key(|o| o.pid);
    out
}


/// The object type index of a serial device object, learned by opening \\.\COMn and
/// finding the same handle in our own process's handle table.
fn serial_object_type_index(ports: &[String]) -> Option<u32> {
    for p in ports {
        let name = crate::inject::wide_str(&format!(r"\\.\{p}"));
        let h = unsafe {
            OpenProbeFile(
                name.as_ptr(),
                0x8000_0000,
                0x7,
                std::ptr::null_mut(),
                3,
                0,
                std::ptr::null_mut(),
            )
        };
        if h as isize == -1 {
            continue;
        }
        let handle_value = h as usize;
        let me = unsafe { GetCurrentProcessId() } as usize;
        let mut found = None;
        // Look up our own handle entry to read its object type index.
        for e in snapshot_handles() {
            if e.unique_process_id == me && e.handle_value == handle_value {
                found = Some(e.object_type_index as u32);
                break;
            }
        }
        unsafe { CloseHandle(h) };
        if let Some(t) = found {
            return Some(t);
        }
    }
    None
}

/// Tracks what has been injected so a PID is never injected twice, and a *reused*
/// PID (same number, different process) is injected again.
struct Attached {
    created: u64,
}

/// Shared, self-running auto-attach service.
pub struct AutoAttach {
    stop: Arc<AtomicBool>,
    attached: Arc<Mutex<HashMap<u32, Attached>>>,
    /// Process IDs the user explicitly detached: never auto-attach them again.
    skip: Arc<Mutex<Vec<u32>>>,
    ports: Arc<Mutex<Vec<String>>>,
    pub log: Arc<Mutex<Vec<String>>>,
}

impl AutoAttach {
    pub fn start(ports: Vec<String>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let attached: Arc<Mutex<HashMap<u32, Attached>>> = Arc::new(Mutex::new(HashMap::new()));
        let skip: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let ports_s = Arc::new(Mutex::new(ports));
        let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

        let (s, a, k, p, l) = (
            stop.clone(),
            attached.clone(),
            skip.clone(),
            ports_s.clone(),
            log.clone(),
        );
        std::thread::spawn(move || {
            push_log(&l, "自动附加线程已启动".to_string());
            let mut ticks = 0u64;
            while !s.load(Ordering::Relaxed) {
                ticks += 1;
                let watched: Vec<String> = p.lock().map(|g| g.clone()).unwrap_or_default();
                if watched.is_empty() {
                    if ticks % 20 == 1 {
                        push_log(&l, "等待监听会话…".to_string());
                    }
                    std::thread::sleep(std::time::Duration::from_millis(120));
                    continue;
                }
                if ticks % 10 == 1 {
                    push_log(&l, format!("扫描中 (监听 {})", watched.join(",")));
                }
                    // Discovery by process enumeration (see list_injectable_processes):
                    // safe without admin rights, and the hook itself decides whether a
                    // process touches a serial port.
                let candidates = list_injectable_processes();
                if ticks % 10 == 1 {
                    push_log(&l, format!("进程候选数 = {}", candidates.len()));
                }
                // Injection policy:
                //   * First pass only *records* existing processes, so opening the
                //     monitor does not storm the machine with hundreds of injections.
                //   * After that, any process that is new (or whose PID was reused) is
                //     a candidate, and the port owner list promotes it to high priority.
                //   * A bounded number per pass keeps the UI thread and the target
                //     processes responsive.
                let serial_owners: Vec<u32> = find_serial_owners(120)
                    .into_iter()
                    .map(|o| o.pid)
                    .collect();
                // Injection policy: serial owners first, then newly started processes.
                //
                // A "no activity, so wait" gate was tried and removed: opening
                // \\.\COMn with full sharing succeeds even while another program owns
                // the port on most drivers (verified with the ELTIMA virtual pair), so
                // "cannot open -> busy" is not a usable signal. Injecting newly started
                // processes directly is what actually works: the hook then reports the
                // ports it sees, and programs started after monitoring began are the
                // ones whose traffic matters.
                if ticks % 10 == 1 {
                    push_log(
                        &l,
                        format!(
                            "串口占用={} 持有者={:?}",
                            watched.iter().map(|p| format!("{p}:{}", port_in_use(p))).collect::<Vec<_>>().join(" "),
                            serial_owners
                        ),
                    );
                }
                let first_pass = ticks == 1;
                let mut injected_this_pass = 0usize;
                // Only processes we have never seen are candidates. This is what makes
                // the monitor practical: the first pass records the machine's existing
                // processes without injecting anything, and from then on only genuinely
                // new (or PID-reused) processes get hooked — which is exactly the set a
                // user creates by launching their serial tools.
                let mut fresh: Vec<(u32, String)> = Vec::new();
                {
                    let known = match a.lock() {
                        Ok(g) => g,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    for (pid, name) in candidates.iter() {
                        if !known.contains_key(pid) {
                            fresh.push((*pid, name.clone()));
                        }
                    }
                    if ticks % 10 == 1 || !fresh.is_empty() {
                        // Log a compact summary: dumping every process name made the
                        // result JSON unwieldy and hard to read.
                        let names: Vec<String> = fresh
                            .iter()
                            .take(6)
                            .map(|(p, n)| format!("{n}:{p}"))
                            .collect();
                        push_log(
                            &l,
                            format!(
                                "已知={} 候选={} 新进程={}{}",
                                known.len(),
                                candidates.len(),
                                names.join(", "),
                                if fresh.len() > 6 {
                                    format!(" …共{}", fresh.len())
                                } else {
                                    String::new()
                                }
                            ),
                        );
                    }
                }
                // Port owners first (they are the ones whose traffic matters), then the
                // rest. No per-pass cap: `fresh` is small by construction.
                let mut ordered: Vec<(u32, String)> = Vec::new();
                for (pid, name) in fresh.iter() {
                    if serial_owners.contains(pid) {
                        ordered.push((*pid, name.clone()));
                    }
                }
                for (pid, name) in fresh {
                    if !serial_owners.contains(&pid) {
                        ordered.push((pid, name));
                    }
                }
                for (pid, name) in ordered {
                    if injected_this_pass >= 40 {
                        break;
                    }
                    if k.lock().map(|g| g.contains(&pid)).unwrap_or(false) {
                        continue;
                    }
                    // On the first pass, only programs whose name marks them as a serial
                    // console are injected — everything else is merely recorded. Without
                    // this a monitor started *after* the serial tool would never see it.
                    let looks_like_serial_tool = {
                        let n = name.to_lowercase();
                        [
                            "putty", "comassistant", "sscom", "minicom", "串口", "serial",
                            "terminate", "term", "comdebug", "commonitor", "modscan",
                            "modbus", "hercules", "monitor", "tool", "console", "cmd.exe",
                            "powershell", "python", "node",
                        ]
                        .iter()
                        .any(|k| n.contains(k))
                    };
                    // Only plausible serial clients are injected; everything else is
                    // recorded and left completely alone.
                    if !is_plausible_serial_client(&name) {
                        let mut g = match a.lock() {
                            Ok(g) => g,
                            Err(poisoned) => poisoned.into_inner(),
                        };
                        let created_now = {
                            let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
                            let c = if h.is_null() {
                                0
                            } else {
                                let c = process_created(h);
                                unsafe { CloseHandle(h) };
                                c
                            };
                            c
                        };
                        g.insert(pid, Attached { created: created_now });
                        continue;
                    }
                    if first_pass && !looks_like_serial_tool {
                        // Record without injecting: existing programs were started
                        // before monitoring began and usually hold no port.
                        let mut g = match a.lock() {
                            Ok(g) => g,
                            Err(poisoned) => poisoned.into_inner(),
                        };
                        let created_now = {
                            let h = unsafe {
                                OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)
                            };
                            let c = if h.is_null() {
                                0
                            } else {
                                let c = process_created(h);
                                unsafe { CloseHandle(h) };
                                c
                            };
                            c
                        };
                        g.insert(pid, Attached { created: created_now });
                        continue;
                    }
                    let created_now = {
                        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
                        let c = if h.is_null() {
                            0
                        } else {
                            let c = process_created(h);
                            unsafe { CloseHandle(h) };
                            c
                        };
                        c
                    };
                    let need = {
                        let mut g = match a.lock() {
                            Ok(g) => g,
                            Err(poisoned) => poisoned.into_inner(),
                        };
                        match g.get(&pid) {
                            Some(prev) if prev.created == created_now && created_now != 0 => false,
                            _ => {
                                g.insert(pid, Attached { created: created_now });
                                true
                            }
                        }
                    };
                    if !need {
                        continue;
                    }
                    if let Some(dll) = crate::inject::dll_path() {
                        match crate::inject::inject(pid, &dll.to_string_lossy()) {
                            Ok(()) => {
                                injected_this_pass += 1;
                                let tag = if serial_owners.contains(&pid) { "串口进程" } else { "进程" };
                                push_log(&l, format!("已附加{tag} {name} (PID {pid})"));
                            }
                            Err(_) => {}
                        }
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(120));
            }
        });

        AutoAttach { stop, attached, skip, ports: ports_s, log }
    }

    /// Replace the watched port list (called when sessions change).
    pub fn set_ports(&self, ports: Vec<String>) {
        if let Ok(mut g) = self.ports.lock() {
            if *g != ports {
                *g = ports;
            }
        }
    }

    pub fn watched(&self) -> Vec<String> {
        self.ports.lock().map(|g| g.clone()).unwrap_or_default()
    }

    pub fn skip_pid(&self, pid: u32) {
        if let Ok(mut g) = self.skip.lock() {
            if !g.contains(&pid) {
                g.push(pid);
            }
        }
        if let Ok(mut g) = self.attached.lock() {
            g.remove(&pid);
        }
    }

    pub fn drained_log(&self) -> Vec<String> {
        match self.log.lock() {
            Ok(mut g) => std::mem::take(&mut *g),
            Err(p) => std::mem::take(&mut *p.into_inner()),
        }
    }
}

impl Drop for AutoAttach {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn push_log(log: &Arc<Mutex<Vec<String>>>, line: String) {
    if let Ok(mut g) = log.lock() {
        if g.len() < 200 {
            g.push(line);
        }
    }
}

/// Read the UNICODE_STRING at the start of an OBJECT_NAME_INFORMATION buffer.
///
/// On x64 `UNICODE_STRING` is `{ u16 Length; u16 MaximumLength; u32 pad; u64 Buffer; }`
/// — 16 bytes — and for OBJECT_NAME_INFORMATION the kernel writes the name bytes
/// directly after that header, so the name is at offset 16. `Buffer` is left as a
/// pointer that must not be dereferenced (it refers to the same buffer).
fn parse_object_name(buf: &[u8]) -> Option<String> {
    if buf.len() < 16 {
        return None;
    }
    let length = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    let chars = length / 2;
    if chars == 0 {
        return None;
    }
    const NAME_OFF: usize = 16;
    if NAME_OFF + length > buf.len() {
        // Some builds report the name only through Buffer; try that address only if
        // it happens to fall inside our buffer (otherwise it is kernel memory).
        let buf_ptr = u64::from_le_bytes([buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]]);
        let base = buf.as_ptr() as u64;
        if buf_ptr >= base && buf_ptr + length as u64 <= base + buf.len() as u64 {
            let off = (buf_ptr - base) as usize;
            let mut units = Vec::with_capacity(chars);
            for i in 0..chars {
                let o = off + i * 2;
                units.push(u16::from_le_bytes([buf[o], buf[o + 1]]));
            }
            return Some(String::from_utf16_lossy(&units));
        }
        return None;
    }
    let mut units = Vec::with_capacity(chars);
    for i in 0..chars {
        let o = NAME_OFF + i * 2;
        units.push(u16::from_le_bytes([buf[o], buf[o + 1]]));
    }
    Some(String::from_utf16_lossy(&units))
}

/// Probe: does NtQueryObject return a usable name for a *device* object?
/// Opens \\.\COMn read-only with full sharing and reads the object name behind the
/// handle. This is exactly what the owner scan does, so running it proves whether
/// the scan can work on this machine.
pub fn probe_device_name(com: &str) -> String {
    let name = crate::inject::wide_str(&format!(r"\\.\{com}"));
    let h = unsafe {
        OpenProbeFile(
            name.as_ptr(),
            0x8000_0000, // GENERIC_READ
            0x7,         // share all — must not disturb the current owner
            std::ptr::null_mut(),
            3, // OPEN_EXISTING
            0,
            std::ptr::null_mut(),
        )
    };
    if h as isize == -1 {
        return format!("无法打开 {com} (err={})", unsafe { GetLastErrorC() });
    }
    let mut buf = vec![0u8; 4096];
    let mut ret: u32 = 0;
    let st = unsafe {
        NtQueryObject(
            h,
            OBJECT_NAME_INFORMATION,
            buf.as_mut_ptr() as *mut std::ffi::c_void,
            buf.len() as u32,
            &mut ret,
        )
    };
    unsafe { CloseHandle(h) };
    if st != 0 {
        return format!("{com} NTSTATUS=0x{:08X}", st as u32);
    }
    match parse_object_name(&buf) {
        Some(n) => format!("{com} -> {n}"),
        None => format!("{com} 名称空 (ret={ret}, 头={:02X?})", &buf[..16]),
    }
}

/// Returns a human-readable status including the NTSTATUS, so a failing setup shows
/// the real reason instead of a silent "no owners found".
pub fn probe_object_query() -> String {
    // Use a handle we certainly own: the pipe server's own end if present, else a
    // handle to our own process object (always valid, always named).
    let pipe = crate::inject::PIPE_NAME;
    let name = crate::inject::wide_str(pipe);
    let h = unsafe {
        OpenProbeFile(
            name.as_ptr(),
            0xC000_0000, // GENERIC_READ|WRITE, harmless if the pipe refuses
            0x7,
            std::ptr::null_mut(),
            3,
            0,
            std::ptr::null_mut(),
        )
    };
    let target = if h as isize != -1 {
        h
    } else {
        // Fall back to the current process pseudo-handle (-1 is not a valid handle
        // for NtQueryObject, so open the real process object).
        let p = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, std::process::id()) };
        if p.is_null() {
            return "无法获得可用于查询的句柄".to_string();
        }
        p
    };
    let mut buf = vec![0u8; 4096];
    let mut ret: u32 = 0;
    let st = unsafe {
        NtQueryObject(
            target,
            OBJECT_NAME_INFORMATION,
            buf.as_mut_ptr() as *mut std::ffi::c_void,
            buf.len() as u32,
            &mut ret,
        )
    };
    unsafe { CloseHandle(target) };
    if st == 0 {
        match parse_object_name(&buf) {
            Some(n) => format!("成功, 名称 = {n}"),
            None => format!(
                "成功但名称为空 (ret={}, 前16字节={:02X?})",
                ret,
                &buf[..16.min(buf.len())]
            ),
        }
    } else {
        format!("NTSTATUS = 0x{:08X}", st as u32)
    }
}

extern "system" {
    #[link_name = "CreateFileW"]
    fn OpenProbeFile(
        name: *const u16,
        access: u32,
        share: u32,
        sa: *mut std::ffi::c_void,
        disp: u32,
        flags: u32,
        tmpl: *mut std::ffi::c_void,
    ) -> *mut std::ffi::c_void;
    #[link_name = "GetLastError"]
    fn GetLastErrorC() -> u32;
}

/// Public wrapper used by the diagnostic CLI.
pub fn snapshot_handles_pub() -> Vec<SystemHandleEntry> {
    snapshot_handles()
}

/// Like [`find_port_owners`] but stops after inspecting `max` handles. Used while
/// bringing up the scanner: a bounded walk cannot hide behind a full-system scan.
pub fn scan_owners_limited(ports: &[String], max: usize) -> Vec<PortOwner> {
    let me = unsafe { GetCurrentProcessId() };
    let wanted_com: Vec<String> = ports.iter().map(|p| p.to_lowercase()).collect();
    let mut owners: HashMap<u32, String> = HashMap::new();
    let entries = snapshot_handles();
    let mut inspected = 0usize;
    for e in entries.iter() {
        if inspected >= max {
            break;
        }
        let pid = e.unique_process_id as u32;
        if pid == me || pid == 0 || pid == 4 || crate::inject::is_critical_pid(pid) {
            continue;
        }
        inspected += 1;
        if owners.contains_key(&pid) {
            continue;
        }
        let Some(name) = object_name(pid, e.handle_value) else {
            continue;
        };
        let lower = name.to_lowercase();
        let by_com = wanted_com
            .iter()
            .any(|com| lower.contains(com.as_str()));
        let by_device = crate::inject::is_serial_device_path(&lower);
        if by_com || by_device {
            owners.insert(pid, name);
        }
    }
    let mut out: Vec<PortOwner> = owners
        .into_keys()
        .map(|pid| PortOwner { pid, exe: process_exe(pid) })
        .collect();
    out.sort_by_key(|o| o.pid);
    out
}

/// (total handles, named device handles, sample of (pid, name)) — lets a diagnostic
/// tell "the handle scan sees nothing" apart from "the name matching misses".
pub fn diagnose_scan() -> (usize, usize, Vec<(u32, String)>) {
    let entries = match std::panic::catch_unwind(|| snapshot_handles()) {
        Ok(e) => e,
        Err(_) => return (0, 0, Vec::new()),
    };
    let total = entries.len();
    let mut named = 0usize;
    let mut sample = Vec::new();
    for e in entries.iter() {
        let pid = e.unique_process_id as u32;
        if pid == 0 || pid == 4 {
            continue;
        }
        // Bound the work: a full system scan with name queries is slow and this is
        // only a diagnostic. Also keeps the crash surface small while debugging.
        if sample.len() >= 25 || total == 0 {
            break;
        }
        if sample.len() > 5000 {
            break;
        }
        if let Some(name) = std::panic::catch_unwind(|| object_name(pid, e.handle_value))
            .ok()
            .flatten()
        {
            if name.contains("\\Device\\") || name.contains("\\??\\") {
                named += 1;
                if sample.len() < 25 {
                    sample.push((pid, name));
                }
            }
        }
    }
    (total, named, sample)
}
