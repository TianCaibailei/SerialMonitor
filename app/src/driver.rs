// User-mode client for the UmSerialFilter kernel driver.
//
// The driver exposes one control device (\\.\UmSerialFilter) with a small IOCTL set:
//   IOCTL_UM_ATTACH_PORTS  — attach the filter to every serial device
//   IOCTL_UM_GET_PORT_NAME — friendly (NT) name of one attached device
//   IOCTL_UM_SET_TARGET    — enable capture, optionally limited to one PID
//   IOCTL_UM_GET_RECORD    — pop one captured chunk (blocks until one is queued)
//   IOCTL_UM_GET_STATS     — counters
//
// The monitor polls this interface from a background thread and turns each record into
// the same ChannelCfg/Session rows the user-mode hook produces, so the UI needs no
// driver-specific code path.
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
        in_buf: *mut c_void,
        in_len: u32,
        out_buf: *mut c_void,
        out_len: u32,
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

const DEVICE_TYPE: u32 = 0x8000;
const FILE_READ_DATA: u32 = 0x0001;
const FILE_WRITE_DATA: u32 = 0x0002;

const fn ctl(func: u32, access: u32) -> u32 {
    (DEVICE_TYPE << 16) | (access << 14) | (func << 2)
}

pub const IOCTL_GET_RECORD: u32 = ctl(0x800, FILE_READ_DATA);
pub const IOCTL_SET_TARGET: u32 = ctl(0x801, FILE_WRITE_DATA);
pub const IOCTL_GET_STATS: u32 = ctl(0x802, FILE_READ_DATA);
pub const IOCTL_ATTACH_PORTS: u32 = ctl(0x803, FILE_WRITE_DATA);
pub const IOCTL_GET_PORT_NAME: u32 = ctl(0x804, FILE_READ_DATA);

pub const RECORD_HEADER: usize = 32;
pub const MAX_PAYLOAD: usize = 4096;
pub const CHANNEL_NAME: &str = "\\\\.\\UmSerialFilter";

/// One captured chunk, decoded from the driver's wire format.
#[derive(Clone, Debug)]
pub struct Record {
    pub dir_tx: bool,
    pub pid: u32,
    pub port_index: u32,
    pub handle: u64,
    pub timestamp: u64,
    pub data: Vec<u8>,
}

/// An attached port the driver knows about.
#[derive(Clone, Debug)]
pub struct DriverPort {
    pub index: u32,
    /// NT device path, e.g. "\Device\VSerial8_2".
    pub device: String,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Handle to the driver's control device.
pub struct DriverHandle {
    h: *mut c_void,
}

// The handle is only used from the capture thread; sending it across threads is safe
// because the kernel device object serialises IOCTLs internally.
unsafe impl Send for DriverHandle {}

impl DriverHandle {
    /// Open the control device. Returns None when the driver is not loaded.
    pub fn open() -> Option<Self> {
        let path = wide(CHANNEL_NAME);
        let h = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        if h as isize == INVALID {
            None
        } else {
            Some(DriverHandle { h })
        }
    }

    /// Is the driver present and usable?
    pub fn is_available() -> bool {
        Self::open().is_some()
    }

    fn ioctl(&self, code: u32, in_buf: Option<&[u8]>, out_len: usize) -> Option<(Vec<u8>, u32)> {
        let mut out = vec![0u8; out_len.max(1)];
        let mut returned = 0u32;
        let (in_ptr, in_len) = match in_buf {
            Some(b) => (b.as_ptr() as *mut c_void, b.len() as u32),
            None => (std::ptr::null_mut(), 0),
        };
        let ok = unsafe {
            DeviceIoControl(
                self.h,
                code,
                in_ptr,
                in_len,
                out.as_mut_ptr() as *mut c_void,
                out.len() as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            None
        } else {
            out.truncate(returned as usize);
            Some((out, returned))
        }
    }

    /// Ask the driver to attach to every serial device it can find.
    pub fn attach_ports(&self) -> u32 {
        match self.ioctl(IOCTL_ATTACH_PORTS, None, 4) {
            Some((out, _)) if out.len() >= 4 => {
                u32::from_le_bytes([out[0], out[1], out[2], out[3]])
            }
            _ => 0,
        }
    }

    /// Names of the attached ports, in index order.
    pub fn port_names(&self, count: u32) -> Vec<DriverPort> {
        let mut out = Vec::new();
        for index in 0..count {
            let inb = index.to_le_bytes();
            if let Some((buf, n)) = self.ioctl(IOCTL_GET_PORT_NAME, Some(&inb), 512) {
                if n >= 8 {
                    let chars = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
                    let need = 8 + chars * 2;
                    if buf.len() >= need && chars > 0 {
                        let mut units = Vec::with_capacity(chars);
                        for i in 0..chars {
                            let o = 8 + i * 2;
                            units.push(u16::from_le_bytes([buf[o], buf[o + 1]]));
                        }
                        out.push(DriverPort {
                            index,
                            device: String::from_utf16_lossy(&units),
                        });
                    }
                }
            }
        }
        out
    }

    /// Enable capture (pid 0 = every process).
    pub fn set_target(&self, pid: u32) {
        let b = pid.to_le_bytes();
        let _ = self.ioctl(IOCTL_SET_TARGET, Some(&b), 0);
    }

    /// Pop one record; None when the queue is empty.
    pub fn next_record(&self) -> Option<Record> {
        let (buf, n) = self.ioctl(IOCTL_GET_RECORD, None, RECORD_HEADER + MAX_PAYLOAD)?;
        if n < RECORD_HEADER as u32 {
            return None;
        }
        let size = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let dir = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let pid = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let port_index = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let mut handle = [0u8; 8];
        handle.copy_from_slice(&buf[16..24]);
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&buf[24..32]);
        let handle = u64::from_le_bytes(handle);
        let timestamp = u64::from_le_bytes(ts);
        let take = size.min(MAX_PAYLOAD).min(buf.len().saturating_sub(RECORD_HEADER));
        Some(Record {
            dir_tx: dir == 1,
            pid,
            port_index,
            handle,
            timestamp,
            data: buf[RECORD_HEADER..RECORD_HEADER + take].to_vec(),
        })
    }
}

impl Drop for DriverHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.h) };
    }
}
