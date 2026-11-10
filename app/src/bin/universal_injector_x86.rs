// 32-bit injector helper.
//
// WHY THIS EXISTS
// ---------------
// Injecting a DLL into a WOW64 process from a 64-bit process is unreliable: the
// address of LoadLibraryA/A inside the 32-bit target can be located correctly (verified:
// kernel32 base + export RVA are right), the path can be written and read back
// byte-for-byte, and the remote thread still returns -1 — because the caller's
// CreateRemoteThread call and the target's 32-bit loader disagree about the thread
// entry's calling environment.
//
// The robust fix is architectural separation: this small program is built for i686, so
// it runs *inside* the WOW64 world and every address it computes is a native 32-bit
// address. The 64-bit monitor spawns it with a PID and a DLL path and reads its exit
// code.
//
// Usage:  universal_injector_x86.exe <pid> <dll-path>
// Exit:   0 = DLL loaded, 1 = failed (message on stderr)
use std::ffi::c_void;

extern "system" {
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
    fn VirtualAllocEx(h: *mut c_void, addr: *mut c_void, size: usize, ty: u32, prot: u32) -> *mut c_void;
    fn WriteProcessMemory(
        h: *mut c_void,
        addr: *mut c_void,
        buf: *const u8,
        size: usize,
        written: *mut usize,
    ) -> i32;
    fn CreateRemoteThread(
        h: *mut c_void,
        sa: *mut c_void,
        stack: usize,
        start: *mut c_void,
        param: *mut c_void,
        flags: u32,
        tid: *mut u32,
    ) -> *mut c_void;
    fn WaitForSingleObject(h: *mut c_void, ms: u32) -> u32;
    fn GetExitCodeThread(h: *mut c_void, code: *mut u32) -> i32;
    fn CloseHandle(h: *mut c_void) -> i32;
    fn GetModuleHandleW(name: *const u16) -> *mut c_void;
    fn GetProcAddress(h: *mut c_void, name: *const u8) -> *mut c_void;
    fn GetLastError() -> u32;
}

const PROCESS_ALL: u32 = 0x1F0FFF;
const MEM_COMMIT_RESERVE: u32 = 0x3000;
const PAGE_READWRITE: u32 = 0x04;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("用法: universal_injector_x86 <pid> <dll-path>");
        std::process::exit(2);
    }
    let pid: u32 = match args[1].parse() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("PID 无效: {}", args[1]);
            std::process::exit(2);
        }
    };
    let dll = &args[2];

    unsafe {
        let proc = OpenProcess(PROCESS_ALL, 0, pid);
        if proc.is_null() {
            eprintln!("OpenProcess 失败");
            std::process::exit(1);
        }
        // Being a 32-bit process ourselves, GetProcAddress returns a native 32-bit
        // address — exactly what the target's loader expects.
        let k32 = GetModuleHandleW(wide("kernel32.dll").as_ptr());
        let mut ll_name = b"LoadLibraryW\0".to_vec();
        let load_library = GetProcAddress(k32, ll_name.as_mut_ptr());
        if load_library.is_null() {
            eprintln!("找不到 LoadLibraryW");
            CloseHandle(proc);
            std::process::exit(1);
        }
        let path = wide(dll);
        let bytes = path.len() * 2;
        let remote = VirtualAllocEx(
            proc,
            std::ptr::null_mut(),
            bytes,
            MEM_COMMIT_RESERVE,
            PAGE_READWRITE,
        );
        if remote.is_null() {
            eprintln!("VirtualAllocEx 失败");
            CloseHandle(proc);
            std::process::exit(1);
        }
        let mut written = 0usize;
        if WriteProcessMemory(
            proc,
            remote,
            path.as_ptr() as *const u8,
            bytes,
            &mut written,
        ) == 0
            || written != bytes
        {
            eprintln!("WriteProcessMemory 失败");
            CloseHandle(proc);
            std::process::exit(1);
        }
        let th = CreateRemoteThread(
            proc,
            std::ptr::null_mut(),
            0,
            load_library,
            remote,
            0,
            std::ptr::null_mut(),
        );
        if th.is_null() {
            eprintln!("CreateRemoteThread 失败 (err=0x{:X})", GetLastError());
            CloseHandle(proc);
            std::process::exit(1);
        }
        let waited = WaitForSingleObject(th, 15_000);
        let mut code = 0u32;
        GetExitCodeThread(th, &mut code);
        CloseHandle(th);
        CloseHandle(proc);
        // Diagnostics: the addresses are the whole story for a remote LoadLibrary.
        eprintln!(
            "诊断: LoadLibraryW={:p} 路径缓冲区={:p} 等待={waited} 线程退出码=0x{code:X}",
            load_library, remote
        );
        const STILL_ACTIVE: u32 = 259;
        if waited == 0x102 || code == STILL_ACTIVE {
            eprintln!("远程线程未完成（可能目标进程已退出或 LoadLibrary 卡住）");
            std::process::exit(1);
        }
        if code == 0 {
            eprintln!("LoadLibraryW 返回 NULL (GetLastError=0x{:X})", GetLastError());
            std::process::exit(1);
        }
        println!("注入成功, HMODULE = 0x{code:X}");
    }
}
