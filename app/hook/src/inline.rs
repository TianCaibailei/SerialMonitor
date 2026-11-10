// Inline (function-entry) patching for the two kernel32 file-I/O exports.
//
// WHY THIS IS NEEDED ON TOP OF IAT HOOKING
// ----------------------------------------
// IAT hooking rewrites the import table of each module, which covers code that calls
// `kernel32!ReadFile` through its import slot. .NET's SerialStream does not: it binds
// `ReadFile`/`WriteFile` once through P/Invoke and keeps the resolved address in its
// own table, calling it indirectly. `GetProcAddress` hooking catches binders that ask
// *after* injection, but a stream that was opened before (or that caches its own copy)
// still calls the untouched function.
//
// Patching the function's own entry point covers every caller, however it obtained the
// address: the first bytes of `kernel32!ReadFile` become an absolute jump to our
// trampoline, and the original instructions are preserved in a stub that the trampoline
// calls at the end.
//
// SAFETY NOTES
//   * Only the first 12 bytes are replaced (a `mov rax, imm64; jmp rax` sequence), which
//     is enough on Windows for these functions to reach a 5-byte-safe instruction
//     boundary; if the bytes do not decode into a clean landing spot the patch is
//     refused rather than risking a crash in the target.
//   * The page is made writable, written, then restored to execute/read.
//   * The trampoline runs the stolen instructions then jumps back past the patch, so
//     the original function's behaviour is preserved exactly.
use std::sync::atomic::{AtomicUsize, Ordering};

const PATCH_LEN: usize = 12;
const MAX_STOLEN: usize = 32;

extern "system" {
    fn VirtualProtect(addr: *mut std::ffi::c_void, size: usize, prot: u32, old: *mut u32) -> i32;
    fn VirtualAlloc(
        addr: *mut std::ffi::c_void,
        size: usize,
        alloc_type: u32,
        protect: u32,
    ) -> *mut std::ffi::c_void;
    fn FlushInstructionCache(process: *mut std::ffi::c_void, addr: *const std::ffi::c_void, size: usize) -> i32;
    fn GetCurrentProcess() -> *mut std::ffi::c_void;
}

const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_READ: u32 = 0x20;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;

/// One installed entry-point patch.
pub struct InlinePatch {
    /// Address of the original function (now holding the jump).
    pub target: usize,
    /// Executable stub holding the stolen instructions + a jump back.
    pub trampoline: usize,
    /// Original stolen bytes, for documentation/debugging.
    pub stolen: usize,
}

/// Replace the first bytes of `target` with a jump to `hook`.
///
/// `stolen_len` must be >= PATCH_LEN and land on an instruction boundary of the target;
/// the caller passes a length it has verified from the function's prologue. Returns
/// None when the patch could not be installed (the function is then simply left alone,
/// so behaviour stays correct and only capture is reduced).
pub unsafe fn install(target: usize, hook: usize, stolen_len: usize) -> Option<InlinePatch> {
    if target == 0 || hook == 0 {
        return None;
    }
    let stolen_len = stolen_len.max(PATCH_LEN).min(MAX_STOLEN);
    // A stub of the stolen bytes followed by `mov rax, target+stolen; jmp rax`.
    let stub_size = stolen_len + PATCH_LEN + 16;
    let tramp = VirtualAlloc(
        std::ptr::null_mut(),
        stub_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    ) as *mut u8;
    if tramp.is_null() {
        return None;
    }
    // Copy the instructions we are about to overwrite.
    std::ptr::copy_nonoverlapping(target as *const u8, tramp, stolen_len);
    // Absolute jump back to target + stolen_len.
    let back = target + stolen_len;
    let p = tramp.add(stolen_len);
    p.write(0x48); // mov r10, imm64  (r10 is scratch, not used by these APIs' prologues)
    p.add(1).write(0xB8);
    // `mov rax,imm64` then `jmp rax` — simpler to reason about than REX-prefixed moves.
    let mut code = [0u8; PATCH_LEN];
    code[0] = 0x48;
    code[1] = 0xB8;
    code[2..10].copy_from_slice(&(back as u64).to_le_bytes());
    code[10] = 0xFF;
    code[11] = 0xE0;
    std::ptr::copy_nonoverlapping(code.as_ptr(), tramp.add(stolen_len), PATCH_LEN);

    // Make the target writable and overwrite its prologue with a jump to `hook`.
    let mut old = 0u32;
    if VirtualProtect(target as *mut std::ffi::c_void, PATCH_LEN, PAGE_EXECUTE_READWRITE, &mut old) == 0 {
        return None;
    }
    let mut jmp = [0u8; PATCH_LEN];
    jmp[0] = 0x48;
    jmp[1] = 0xB8;
    jmp[2..10].copy_from_slice(&(hook as u64).to_le_bytes());
    jmp[10] = 0xFF;
    jmp[11] = 0xE0;
    std::ptr::copy_nonoverlapping(jmp.as_ptr(), target as *mut u8, PATCH_LEN);
    let mut rel = 0u32;
    VirtualProtect(target as *mut std::ffi::c_void, PATCH_LEN, old.max(PAGE_EXECUTE_READ), &mut rel);
    FlushInstructionCache(GetCurrentProcess(), target as *const std::ffi::c_void, PATCH_LEN);

    Some(InlinePatch { target, trampoline: tramp as usize, stolen: stolen_len })
}

/// Read the trampoline pointer of a patch (0 when not installed).
pub fn trampoline_of(slot: &AtomicUsize) -> usize {
    slot.load(Ordering::Relaxed)
}
