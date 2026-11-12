//! Native GDI window capture + minimal PNG writer (no dependencies).
//!
//! `PrintWindow` grabs our own window's pixels even when other windows cover it,
//! so the `--screenshot` verification never photographs the user's desktop.
//! No PowerShell: PS child processes hang on this machine when spawned from the
//! GUI app (observed 2026-11-10; script never reached its first statement).

#[repr(C)]
#[derive(Default)]
struct Rect {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}

#[repr(C)]
struct BitmapInfoHeader {
    size: u32,
    width: i32,
    height: i32,
    planes: u16,
    bit_count: u16,
    compression: u32,
    size_image: u32,
    x_ppm: i32,
    y_ppm: i32,
    clr_used: u32,
    clr_important: u32,
}

#[repr(C)]
struct BitmapInfo {
    header: BitmapInfoHeader,
    color: [u32; 3],
}

#[allow(non_snake_case)]
extern "system" {
    fn GetClientRect(hwnd: isize, r: *mut Rect) -> i32;
    fn EnumWindows(cb: Option<unsafe extern "system" fn(isize, isize) -> i32>, lp: isize) -> i32;
    fn IsWindowVisible(hwnd: isize) -> i32;
    fn GetWindowThreadProcessId(hwnd: isize, pid: *mut u32) -> u32;
    fn GetDC(hwnd: isize) -> isize;
    fn ReleaseDC(hwnd: isize, hdc: isize) -> i32;
    fn CreateCompatibleDC(hdc: isize) -> isize;
    fn DeleteDC(hdc: isize) -> i32;
    fn DeleteObject(obj: isize) -> i32;
    fn SelectObject(hdc: isize, obj: isize) -> isize;
    fn CreateDIBSection(
        hdc: isize,
        bi: *mut BitmapInfo,
        usage: u32,
        bits: *mut *mut u8,
        section: isize,
        offset: u32,
    ) -> isize;
    fn PrintWindow(hwnd: isize, hdc: isize, flags: u32) -> i32;
    fn BitBlt(
        dst: isize,
        dx: i32,
        dy: i32,
        w: i32,
        h: i32,
        src: isize,
        sx: i32,
        sy: i32,
        rop: u32,
    ) -> i32;
}

static FOUND_HWND: std::sync::atomic::AtomicIsize = std::sync::atomic::AtomicIsize::new(0);

unsafe extern "system" fn enum_cb(hwnd: isize, _lp: isize) -> i32 {
    unsafe {
        let mut owner = 0u32;
        GetWindowThreadProcessId(hwnd, &mut owner);
        if owner == std::process::id() && IsWindowVisible(hwnd) != 0 {
            FOUND_HWND.store(hwnd, std::sync::atomic::Ordering::SeqCst);
            return 0;
        }
    }
    1
}

/// Grab the app's own window (by pid) to a PNG; falls back to a screen-region
/// blit (only correct when nothing covers the window). RGBA rows bottom-up.
pub fn capture_window(out: &str, pid: u32, x: i32, y: i32, w: i32, h: i32) -> std::io::Result<()> {
    const PW_CLIENTONLY: u32 = 1;
    const PW_RENDERFULLCONTENT: u32 = 2;
    const SRCCOPY: u32 = 0x00CC_0020;
    const DIB_RGB_COLORS: u32 = 0;
    let _ = pid; // enum_cb matches our own process id

    unsafe {
        FOUND_HWND.store(0, std::sync::atomic::Ordering::SeqCst);
        EnumWindows(Some(enum_cb), 0);
        let hwnd = FOUND_HWND.load(std::sync::atomic::Ordering::SeqCst);

        let mut cw = w;
        let mut ch = h;
        let mut pixels: Vec<u8> = Vec::new();

        let bi = |cw: i32, ch: i32| BitmapInfo {
            header: BitmapInfoHeader {
                size: std::mem::size_of::<BitmapInfoHeader>() as u32,
                width: cw,
                height: ch, // positive => bottom-up rows
                planes: 1,
                bit_count: 32,
                compression: 0, // BI_RGB
                size_image: 0,
                x_ppm: 0,
                y_ppm: 0,
                clr_used: 0,
                clr_important: 0,
            },
            color: [0; 3],
        };

        if hwnd != 0 {
            let mut r = Rect::default();
            if GetClientRect(hwnd, &mut r) != 0 {
                cw = r.right - r.left;
                ch = r.bottom - r.top;
            }
            if cw > 0 && ch > 0 {
                let mut info = bi(cw, ch);
                let mut bits: *mut u8 = std::ptr::null_mut();
                let mem_dc = CreateCompatibleDC(0);
                let dib = CreateDIBSection(mem_dc, &mut info, DIB_RGB_COLORS, &mut bits, 0, 0);
                if dib != 0 && !bits.is_null() {
                    let old = SelectObject(mem_dc, dib);
                    let ok = PrintWindow(hwnd, mem_dc, PW_CLIENTONLY | PW_RENDERFULLCONTENT);
                    SelectObject(mem_dc, old);
                    if ok != 0 {
                        copy_pixels(bits, cw, ch, &mut pixels);
                    }
                }
                if dib != 0 {
                    DeleteObject(dib);
                }
                if mem_dc != 0 {
                    DeleteDC(mem_dc);
                }
            }
        }

        if pixels.is_empty() {
            // Screen-region fallback.
            cw = w;
            ch = h;
            let screen = GetDC(0);
            let mem_dc = CreateCompatibleDC(screen);
            let mut info = bi(cw, ch);
            let mut bits: *mut u8 = std::ptr::null_mut();
            let dib = CreateDIBSection(mem_dc, &mut info, DIB_RGB_COLORS, &mut bits, 0, 0);
            if dib != 0 && !bits.is_null() {
                let old = SelectObject(mem_dc, dib);
                BitBlt(mem_dc, 0, 0, cw, ch, screen, x, y, SRCCOPY);
                SelectObject(mem_dc, old);
                copy_pixels(bits, cw, ch, &mut pixels);
                DeleteObject(dib);
            }
            DeleteDC(mem_dc);
            ReleaseDC(0, screen);
        }

        if pixels.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "capture produced no pixels",
            ));
        }
        write_png(out, cw as u32, ch as u32, &pixels)
    }
}

/// Read one DIB's pixels: bottom-up BGRA rows -> top-down RGBA rows.
unsafe fn copy_pixels(bits: *mut u8, cw: i32, ch: i32, pixels: &mut Vec<u8>) {
    let stride = cw as usize * 4;
    for yy in (0..ch as usize).rev() {
        let src = unsafe { bits.add(yy * stride) };
        for px in 0..cw as usize {
            let b = unsafe { *src.add(px * 4) };
            let g = unsafe { *src.add(px * 4 + 1) };
            let r = unsafe { *src.add(px * 4 + 2) };
            pixels.extend_from_slice(&[r, g, b, 255]);
        }
    }
}

fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (n, t) in table.iter_mut().enumerate() {
        let mut c = n as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
        }
        *t = c;
    }
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc = table[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &byte in data {
        a = (a + byte as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

fn png_chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    let mut crc_input = Vec::with_capacity(4 + data.len());
    crc_input.extend_from_slice(kind);
    crc_input.extend_from_slice(data);
    out.extend_from_slice(&crc32(&crc_input).to_be_bytes());
}

fn write_png(path: &str, width: u32, height: u32, rgba: &[u8]) -> std::io::Result<()> {
    // Raw scanlines with filter byte 0; zlib wrapper with stored deflate blocks.
    let stride = width as usize * 4;
    let mut raw = Vec::with_capacity((stride + 1) * height as usize);
    for y in 0..height as usize {
        raw.push(0u8);
        raw.extend_from_slice(&rgba[y * stride..(y + 1) * stride]);
    }
    let mut idat = Vec::with_capacity(raw.len() + raw.len() / 65535 * 5 + 16);
    idat.extend_from_slice(&[0x78, 0x01]);
    let mut off = 0usize;
    while off < raw.len() {
        let take = (raw.len() - off).min(65535);
        let last = off + take >= raw.len();
        idat.push(u8::from(last));
        idat.extend_from_slice(&(take as u16).to_le_bytes());
        idat.extend_from_slice(&(!(take as u16)).to_le_bytes());
        idat.extend_from_slice(&raw[off..off + take]);
        off += take;
    }
    idat.extend_from_slice(&adler32(&raw).to_be_bytes());

    let mut png = Vec::with_capacity(idat.len() + 128);
    png.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]); // 8-bit RGBA, no interlace
    png_chunk(&mut png, b"IHDR", &ihdr);
    png_chunk(&mut png, b"IDAT", &idat);
    png_chunk(&mut png, b"IEND", &[]);
    std::fs::write(path, png)
}
