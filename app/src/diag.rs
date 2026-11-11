// Diagnostic for the auto-attach discovery step.
//
// --find-owners <COMx>  prints every process that currently holds a handle to that
// port, as the auto-attach thread sees it. Run it while a serial tool has the port
// open: an empty list means the handle-scan or the name matching is wrong, and that
// (not the hook) is why nothing is captured.

/// --list-procs: print what the process enumerator sees. A zero-length list while the
/// monitor runs headless means CreateToolhelp32Snapshot or the entry struct is wrong.
pub fn list_procs() -> i32 {
    // Raw probe first: is the snapshot call itself failing?
    extern "system" {
        fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> *mut std::ffi::c_void;
        fn GetLastError() -> u32;
        fn CloseHandle(h: *mut std::ffi::c_void) -> i32;
    }
    let snap = unsafe { CreateToolhelp32Snapshot(0x2, 0) };
    let snap_err = unsafe { GetLastError() };
    let invalid = snap as isize == -1;
    println!("list-procs: 快照句柄={:?} 无效={} err={}", snap, invalid, snap_err);
    if !invalid {
        unsafe { CloseHandle(snap) };
    }

    let procs = crate::inject::list_processes();
    println!("list-procs: 可注入进程数 = {}", procs.len());
    for (pid, name) in procs.iter().take(20) {
        println!("list-procs:   {pid} {name}");
    }
    if procs.is_empty() {
        1
    } else {
        0
    }
}

/// --handles-self: verify the handle snapshot really contains our own handles.
/// Prints how many entries belong to this PID and whether a freshly opened handle
/// appears in them — the exact check that made port-owner detection silently fail.
pub fn handles_self() -> i32 {
    extern "system" {
        #[link_name = "CreateFileW"]
        fn OpenFile(
            name: *const u16,
            access: u32,
            share: u32,
            sa: *mut std::ffi::c_void,
            disp: u32,
            flags: u32,
            tmpl: *mut std::ffi::c_void,
        ) -> *mut std::ffi::c_void;
        #[link_name = "CloseHandle"]
        fn CloseHandle(h: *mut std::ffi::c_void) -> i32;
        #[link_name = "GetCurrentProcessId"]
        fn GetCurrentProcessId() -> u32;
    }
    let me = unsafe { GetCurrentProcessId() };
    let snap = crate::autoattach::snapshot_handles_pub();
    let mine = snap.iter().filter(|e| e.unique_process_id as u32 == me).count();
    println!("handles-self: 快照总数={} 本进程={} PID={}", snap.len(), mine, me);

    // Open a real file handle we can look for.
    let path = std::env::temp_dir().join("um_handle_probe.txt");
    let wide: Vec<u16> = path.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();
    let h = unsafe {
        OpenFile(
            wide.as_ptr(),
            0x4000_0000,
            0x7,
            std::ptr::null_mut(),
            4, // OPEN_ALWAYS
            0x80,
            std::ptr::null_mut(),
        )
    };
    if h as isize == -1 {
        println!("handles-self: 无法创建探针文件");
        return 1;
    }
    let hv = h as usize;
    // Take the snapshot a few times: the kernel's handle table is updated lazily and
    // a handle created microseconds ago may not be visible in the very first snapshot.
    let mut found = false;
    let mut found_mine = false;
    for attempt in 0..5 {
        let snap2 = crate::autoattach::snapshot_handles_pub();
        found = snap2.iter().any(|e| e.handle_value == hv);
        found_mine = snap2
            .iter()
            .any(|e| e.handle_value == hv && e.unique_process_id as u32 == me);
        if found_mine {
            println!("handles-self: 第 {} 次快照找到（PID 匹配）", attempt + 1);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(30));
    }
    println!("handles-self: 探针句柄={hv:#x} 快照中出现={found} 且PID匹配={found_mine}");
    unsafe { CloseHandle(h) };
    if found_mine {
        0
    } else {
        1
    }
}

/// --inject-test <pid> — inject the right hook DLL (x64 or x86) into a process and
/// report whether it loaded. Verifies the 32-bit path without needing the UI.
pub fn inject_test(pid: u32) -> i32 {
    let wow = crate::inject::is_wow64(pid);
    println!("inject-test: PID {pid} 32位(WOW64) = {wow:?}");
    let dll = match wow {
        Some(true) => crate::inject::dll_path_for(true),
        _ => crate::inject::dll_path_for(false),
    };
    let Some(dll) = dll else {
        println!("inject-test: 找不到 hook DLL");
        return 1;
    };
    println!("inject-test: 使用 DLL = {}", dll.display());
    if !dll.exists() {
        println!("inject-test: DLL 不存在");
        return 1;
    }
    match crate::inject::inject(pid, &dll.to_string_lossy()) {
        Ok(()) => {
            println!("inject-test: 注入成功");
            std::thread::sleep(std::time::Duration::from_millis(800));
            // Verify through the API that also works for WOW64 targets: the previous
            // Toolhelp-based check reported "not loaded" even for a successful 64-bit
            // injection, so it was measuring its own offset bug, not the injection.
            let loaded = crate::inject::is_dll_loaded(pid, "monitor_hook");
            println!("inject-test: 模块已加载 = {loaded}");
            if loaded {
                0
            } else {
                1
            }
        }
        Err(e) => {
            println!("inject-test: 注入失败: {e}");
            1
        }
    }
}

/// Is a module whose name starts with `prefix` loaded in `pid`?
///
/// Uses MODULEENTRY32W with the same 44-byte header padding as PROCESSENTRY32W
/// (measured empirically: szModule begins at offset 44 on x64).
fn is_module_loaded(pid: u32, prefix: &str) -> bool {
    extern "system" {
        fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> *mut std::ffi::c_void;
        fn Module32FirstW(snap: *mut std::ffi::c_void, me: *mut u8) -> i32;
        fn Module32NextW(snap: *mut std::ffi::c_void, me: *mut u8) -> i32;
        fn CloseHandle(h: *mut std::ffi::c_void) -> i32;
    }
    // MODULEENTRY32W is 1088 bytes on x64; szModule starts at offset 44.
    const MODULE_OFF: usize = 44;
    let mut buf = [0u8; 1088];
    buf[0..4].copy_from_slice(&1088u32.to_le_bytes());
    let snap = unsafe { CreateToolhelp32Snapshot(0x8, pid) };
    if snap as isize == -1 {
        return false;
    }
    let needle = prefix.to_lowercase();
    let mut found = false;
    if unsafe { Module32FirstW(snap, buf.as_mut_ptr()) } != 0 {
        loop {
            // Read szModule as UTF-16 from the known offset.
            let mut units = Vec::new();
            for i in 0..256usize {
                let o = MODULE_OFF + i * 2;
                if o + 1 >= buf.len() {
                    break;
                }
                let u = u16::from_le_bytes([buf[o], buf[o + 1]]);
                if u == 0 {
                    break;
                }
                units.push(u);
            }
            let name = String::from_utf16_lossy(&units);
            if name.to_lowercase().contains(&needle) {
                found = true;
                break;
            }
            // Zero the name area before the next entry so stale text cannot match.
            for b in buf[MODULE_OFF..].iter_mut() {
                *b = 0;
            }
            if unsafe { Module32NextW(snap, buf.as_mut_ptr()) } == 0 {
                break;
            }
        }
    }
    unsafe { CloseHandle(snap) };
    found
}

/// --driver-test [seconds] — check the kernel driver: open it, attach ports, print what
/// it reports, then collect records for a while. Quickest way to see whether the filter
/// is loaded and whether it found any serial devices.
pub fn driver_test(seconds: u64) -> i32 {
    let Some(h) = crate::driver::DriverHandle::open() else {
        println!("driver-test: 无法打开 \\\\.\\UmSerialFilter");
        println!("driver-test: 驱动未加载。请以管理员身份执行:");
        println!("driver-test:   sc create UmSerialFilter type= kernel binPath= <驱动路径>");
        println!("driver-test:   sc start UmSerialFilter");
        return 1;
    };
    println!("driver-test: 已连接驱动");

    let attached = h.attach_ports();
    println!("driver-test: 附加到 {attached} 个串口设备");
    let ports = h.port_names(attached);
    for p in &ports {
        println!("driver-test:   [{}] {}", p.index, p.device);
    }
    if ports.is_empty() {
        println!("driver-test: 未找到任何串口设备（驱动附加失败或系统无串口）");
    }
    h.set_target(0);

    println!("driver-test: 收集 {seconds} 秒…");
    let start = std::time::Instant::now();
    let mut n = 0usize;
    let mut rx = 0usize;
    let mut tx = 0usize;
    while start.elapsed().as_secs() < seconds {
        match h.next_record() {
            Some(rec) => {
                n += 1;
                if rec.kind == crate::driver::RecordKind::Tx {
                    tx += rec.data.len();
                } else {
                    rx += rec.data.len();
                }
                let preview: String = rec
                    .data
                    .iter()
                    .take(40)
                    .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
                    .collect();
                println!(
                    "driver-test: [{}] pid={} port={} {} 字节: {preview}",
                    if rec.kind == crate::driver::RecordKind::Tx { "TX" } else { "RX" },
                    rec.pid,
                    rec.port_index,
                    rec.data.len()
                );
            }
            None => std::thread::sleep(std::time::Duration::from_millis(20)),
        }
    }
    println!("driver-test: 记录 {n} 条, RX {rx} 字节, TX {tx} 字节");
    if n > 0 {
        println!("driver-test: PASS 驱动捕获到数据");
        0
    } else {
        println!("driver-test: FAIL 未捕获到数据（收集期间请用串口工具收发）");
        1
    }
}

/// --holders <COMx>... — which processes hold these serial ports.
pub fn holders(ports: &[String]) -> i32 {
    let (list, note) = crate::portowners::find_port_holders(ports);
    println!("holders: {note}");
    for (pid, exe) in &list {
        println!("holders:   PID {pid}  {exe}");
    }
    if list.is_empty() {
        1
    } else {
        0
    }
}

pub fn find_owners(port: &str) -> i32 {
    println!("find-owners: 端口 = {port}");
    let elevated = crate::autoattach::enable_debug_privilege();
    println!("find-owners: [0] SeDebugPrivilege 启用: {elevated}");
    println!(
        "find-owners: [0b] 管理员: {}",
        crate::autoattach::is_admin()
    );
    // 1. The authoritative COM -> device map, which needs no handle scanning.
    let map = crate::autoattach::com_device_map();
    println!("find-owners: [1] 发现的串口设备映射:");
    for (dev, com) in &map {
        println!("find-owners:    {com} -> {dev}");
    }
    // 2. Can we query object names at all? Report the NTSTATUS on a known handle.
    let probe = crate::autoattach::probe_object_query();
    println!("find-owners: [2] NtQueryObject 探针: {probe}");
    println!("find-owners: [2b] 设备句柄探针: {}", crate::autoattach::probe_device_name(port));
    println!("find-owners: [2c] 串口对象类型索引: {:?}", crate::autoattach::probe_serial_type(&[port.to_string()]));

    // 3. Owner scan (GetFileType-based, no admin needed).
    println!("find-owners: [3] 扫描持有者（GetFileType 方案）...");
    let owners = crate::autoattach::find_serial_owners(400);
    if owners.is_empty() {
        println!("find-owners: 没有找到持有串口的进程");
    } else {
        for o in &owners {
            println!("find-owners: 串口持有者 PID {} {}", o.pid, o.exe);
        }
    }
    println!("find-owners: [4] 扫描统计: {:?}", crate::autoattach::scan_stats());
    if owners.is_empty() {
        1
    } else {
        0
    }
}
