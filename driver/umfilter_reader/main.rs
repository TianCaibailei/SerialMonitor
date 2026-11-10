// User-mode side of the UmSerialFilter driver: open the control device, ask the driver
// to attach to every serial port, then drain captured records and print them.
//
// This is the tool used to prove the kernel filter actually captures traffic; the real
// monitor will consume the same IOCTL interface.
//
// Usage: umfilter_reader [seconds]
use std::ffi::c_void;

extern "system" {
    fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        sa: *mut c_void,
        disp: u32,
        flags: u32,
        tmpl: *mut c_void,
    ) -> *mut c_void;
    fn DeviceIoControl(
        h: *mut c_void,
        code: u32,
        inBuf: *mut c_void,
        inLen: u32,
        outBuf: *mut c_void,
        outLen: u32,
        returned: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
    fn CloseHandle(h: *mut c_void) -> i32;
    fn GetLastError() -> u32;
}

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const OPEN_EXISTING: u32 = 3;
const INVALID: isize = -1;

// device type 0x8000; function 0x800 + index; METHOD_BUFFERED = 0
const fn ctl_code(func: u32, access: u32) -> u32 {
    (0x8000u32 << 16) | (access << 14) | (func << 2) | 0
}
const FILE_READ_DATA: u32 = 0x0001;
const FILE_WRITE_DATA: u32 = 0x0002;

const IOCTL_GET_RECORD: u32 = ctl_code(0x800, FILE_READ_DATA);
const IOCTL_SET_TARGET: u32 = ctl_code(0x801, FILE_WRITE_DATA);
const IOCTL_GET_STATS: u32 = ctl_code(0x802, FILE_READ_DATA);
const IOCTL_ATTACH_PORTS: u32 = ctl_code(0x803, FILE_WRITE_DATA);

const RECORD_HEADER: usize = 32;
const MAX_PAYLOAD: usize = 4096;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let seconds: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(15);

    let path = wide(r"\\.\UmSerialFilter");
    let h = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            0 as *mut c_void,
            OPEN_EXISTING,
            0,
            0 as *mut c_void,
        )
    };
    if h as isize == INVALID {
        eprintln!("无法打开 \\\\.\\UmSerialFilter (err={})", unsafe { GetLastError() });
        eprintln!("请先加载驱动: sc create UmSerialFilter type= kernel binPath= <path>");
        std::process::exit(1);
    }
    println!("已连接过滤驱动");

    // Attach to every serial device the driver knows about.
    let mut attached = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            h,
            IOCTL_ATTACH_PORTS,
            0 as *mut c_void,
            0,
            &mut attached as *mut u32 as *mut c_void,
            4,
            &mut attached,
            0 as *mut c_void,
        )
    };
    if ok == 0 {
        eprintln!("附加串口失败 (err={})", unsafe { GetLastError() });
    } else {
        println!("驱动已附加到 {attached} 个串口设备");
    }

    // Enable capture for all processes.
    let mut target: u32 = 0;
    unsafe {
        DeviceIoControl(
            h,
            IOCTL_SET_TARGET,
            &mut target as *mut u32 as *mut c_void,
            4,
            0 as *mut c_void,
            0,
            &mut target,
            0 as *mut c_void,
        );
    }

    println!("开始收集 {seconds} 秒…");
    let start = std::time::Instant::now();
    let mut buf = vec![0u8; RECORD_HEADER + MAX_PAYLOAD];
    let mut total_rx = 0usize;
    let mut total_tx = 0usize;
    let mut count = 0usize;

    while start.elapsed().as_secs() < seconds {
        let mut returned = 0u32;
        let ok = unsafe {
            DeviceIoControl(
                h,
                IOCTL_GET_RECORD,
                0 as *mut c_void,
                0,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                &mut returned,
                0 as *mut c_void,
            )
        };
        if ok == 0 || returned < RECORD_HEADER as u32 {
            std::thread::sleep(std::time::Duration::from_millis(20));
            continue;
        }
        let size = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let dir = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let pid = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let data = &buf[RECORD_HEADER..RECORD_HEADER + size.min(MAX_PAYLOAD)];
        count += 1;
        if dir == 0 {
            total_rx += size;
        } else {
            total_tx += size;
        }
        let preview: String = data
            .iter()
            .take(48)
            .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
            .collect();
        println!(
            "[{}] pid={pid} {} 字节: {preview}",
            if dir == 0 { "RX" } else { "TX" },
            size
        );
    }

    println!();
    println!("=== 统计 ===");
    println!("记录数: {count}");
    println!("RX 字节: {total_rx}");
    println!("TX 字节: {total_tx}");
    unsafe { CloseHandle(h) };
    if count > 0 {
        println!("PASS: 驱动捕获到串口数据");
        std::process::exit(0);
    }
    println!("FAIL: 未捕获到数据");
    std::process::exit(1);
}
