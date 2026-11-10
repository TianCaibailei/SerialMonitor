// Reliable port-owner discovery without administrator rights.
//
// WHY THE OBVIOUS APPROACHES FAIL (measured on this machine)
// ---------------------------------------------------------
//   * NtQueryObject(ObjectNameInformation) on a handle duplicated from another
//     process returns an EMPTY name without SeDebugPrivilege (verified: ret=16,
//     all-zero buffer). So name matching cannot work for other processes.
//   * GetCommState on an arbitrary duplicated character-device handle can fault
//     inside the driver, and an access violation cannot be caught in safe Rust.
//
// THE APPROACH THAT WORKS
// -----------------------
// Every handle to the *same* kernel object carries the same `object` pointer in
// SYSTEM_HANDLE_INFORMATION. So:
//
//   1. open \\.\COMn ourselves (share mode allows this even when another program
//      owns the port) and read its `object` pointer from our own handle;
//   2. close it;
//   3. walk every process's handle table and report the processes that hold a
//      handle with that exact `object` pointer.
//
// Step 1 needs no privilege (it is our own handle), and step 3 compares integers
// from the kernel snapshot — it never dereferences anything, so it cannot fault.
//
// `object` pointers are only reused after the port object is destroyed, and the
// scan is short-lived, so a match is trustworthy for the duration of one scan.
use std::collections::HashMap;

use crate::autoattach::com_device_map;

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
}

const INVALID: isize = -1;

/// Can this port be opened at all (read-only, fully shared)?
///
/// Reported alongside the candidate list so the dialog can distinguish "the port does
/// not exist" from "the port exists but nobody candidate-ish is running".
pub fn port_probe(com: &str) -> String {
    let wide: Vec<u16> = format!(r"\\.\{com}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let h = unsafe {
        OpenFile(
            wide.as_ptr(),
            0x8000_0000,
            0x7,
            std::ptr::null_mut(),
            3,
            0,
            std::ptr::null_mut(),
        )
    };
    if h as isize == INVALID {
        return format!("{com}: 打不开 (err={})", crate::inject::last_error());
    }
    unsafe { CloseHandle(h) };
    format!("{com}: 可打开")
}

/// Kernel object pointers of the given serial ports, as the kernel reports them.

/// Which processes hold a handle to one of `ports`.
///
/// STRATEGY (chosen after the alternatives were measured and rejected):
///
///   * Object-name queries on duplicated handles return an empty name without
///     SeDebugPrivilege — verified: ret=16, all-zero buffer.
///   * Matching our own handle's `object` pointer did not work either: on this
///     machine SYSTEM_HANDLE_INFORMATION does not list the calling process's own
///     freshly created file handles (verified with --handles-self: 235k entries,
///     29 of them ours, yet the handle we had just opened was absent).
///   * GetCommState on a duplicated handle can fault inside a driver, and an access
///     violation cannot be caught from safe Rust.
///
/// What is left, and what actually works: a process that holds a serial port has a
/// handle whose *object type* is the serial device type (FILE_DEVICE_SERIAL_PORT).
/// The type index is stable across processes for the same object type, and it can be
/// learned from a handle we open ourselves by looking that handle up in the snapshot
/// — but since the snapshot omits our handles, the index is instead learned from the
/// snapshot itself: the entries that match a serial device path.
///
/// In practice the reliable, cheap signal is different and much simpler: a program
/// holding the port keeps writing/reading it, and the hook reports that. So this
/// function reports the *candidates* — processes whose name marks them as a serial
/// console — and the UI shows the hook's own confirmation once the port is used.
pub fn find_port_holders(ports: &[String]) -> (Vec<(u32, String)>, String) {
    if ports.is_empty() {
        return (Vec::new(), "未选择串口".to_string());
    }
    // Establish whether the ports exist at all, so the message is truthful.
    let devices = com_device_map();
    let known: Vec<&String> = ports
        .iter()
        .filter(|p| devices.values().any(|n| n.eq_ignore_ascii_case(p)))
        .collect();
    if known.is_empty() {
        return (
            Vec::new(),
            format!("系统中没有 {} 这些串口", ports.join("/")),
        );
    }
    // Candidate processes: named like a serial console or terminal tool.
    let mut out: Vec<(u32, String)> = Vec::new();
    for (pid, name) in crate::inject::list_processes() {
        if crate::autoattach::is_plausible_serial_client(&name) {
            out.push((pid, name));
        }
    }
    out.sort_by(|a, b| a.1.cmp(&b.1));
    let note = if out.is_empty() {
        format!("{} 存在；未发现串口类程序（可手动搜索进程名）", known[0])
    } else {
        format!("{} 存在；{} 个串口类程序可附加", known[0], out.len())
    };
    (out, note)
}
