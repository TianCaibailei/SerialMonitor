// Session engine: channels (serial / TCP client / TCP server / UDP), frame reassembly,
// row storage, filters, rate history, auto-save logging.

use crate::protocol::{self, FrameKind, ModbusParsed};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const FRAME_GAP_MS: u32 = 30;

#[derive(Clone, PartialEq)]
pub enum ChanKind {
    Serial,
    TcpClient,
    TcpServer,
    Udp,
    /// Intercepted serial handle inside another process (hook DLL reports RX/TX).
    HookSerial,
}

impl ChanKind {
    pub fn label(&self) -> &'static str {
        match self {
            ChanKind::Serial => "串口",
            ChanKind::TcpClient => "TCP客户端",
            ChanKind::TcpServer => "TCP服务端",
            ChanKind::Udp => "UDP",
            ChanKind::HookSerial => "拦截串口",
        }
    }
}

#[derive(Clone)]
pub struct ChannelCfg {
    pub kind: ChanKind,
    pub name: String,
    pub baud: u32,
    pub data_bits: u8,
    pub parity: u8, // 0 none 1 even 2 odd
    pub stop_bits: u8,
}

#[derive(Clone)]
pub struct ViewToggles {
    pub table: bool,
    pub terminal: bool,
    pub dump: bool,
    pub line: bool,
    pub modbus: bool,
}

impl Default for ViewToggles {
    fn default() -> Self {
        ViewToggles { table: true, terminal: true, dump: true, line: true, modbus: false }
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum ProtoType {
    None,
    Rtu,
    Ascii,
    Tcp,
}

impl ProtoType {
    pub fn label(&self) -> &'static str {
        match self {
            ProtoType::None => "无(原始数据)",
            ProtoType::Rtu => "Modbus RTU",
            ProtoType::Ascii => "Modbus ASCII",
            ProtoType::Tcp => "Modbus TCP(MBAP)",
        }
    }
}

#[derive(Clone, Debug)]
pub enum Ev {
    Rx { idx: usize, data: Vec<u8>, secs: u64, millis: u32 },
    Peer { idx: usize, label: String },
    Closed { idx: usize, why: String },
}

pub struct Row {
    pub seq: u64,
    pub idx: usize,
    pub dir_tx: bool,
    pub secs: u64,
    pub millis: u32,
    pub data: Vec<u8>,
    pub parsed: Option<ModbusParsed>,
    pub kind: FrameKind,
    pub merged: bool,
}

#[derive(Clone)]
pub struct Filters {
    pub dir: usize, // 0 全部 1 读 2 写
    pub fcs: Vec<u8>,
    pub text: String,
    pub text_on: bool,
}

impl Default for Filters {
    fn default() -> Self {
        Filters { dir: 0, fcs: Vec::new(), text: String::new(), text_on: false }
    }
}

impl Filters {
    pub fn pass(&self, r: &Row) -> bool {
        if self.dir == 1 && r.dir_tx {
            return false;
        }
        if self.dir == 2 && !r.dir_tx {
            return false;
        }
        if !self.fcs.is_empty() {
            match &r.parsed {
                Some(p) => {
                    if !self.fcs.contains(&p.function) {
                        return false;
                    }
                }
                None => return false,
            }
        }
        if self.text_on && !self.text.is_empty() {
            let t = self.text.to_lowercase();
            let hex = bytes_hex(&r.data).to_lowercase();
            let txt = String::from_utf8_lossy(&r.data).to_lowercase();
            if !hex.contains(&t) && !txt.contains(&t) {
                return false;
            }
        }
        true
    }
}

#[derive(Clone)]
pub struct Autosave {
    pub on: bool,
    pub path: String,
    pub split: usize, // 0 单个文件不分割 1 按时间范围分割 2 强制文件大小
    pub time_min: u64,
    pub size_mb: u64,
    pub encoding: usize, // 0 UTF-8 1 ANSI(GBK) 2 Unicode(UTF-16LE)
    pub written: u64,
    pub started_at: u64,
    pub cur_file: String,
}

pub struct Session {
    pub name: String,
    pub channels: Vec<ChannelCfg>,
    pub proto: ProtoType,
    pub views: ViewToggles,
    pub rows: Vec<Row>,
    pub ev_rx: Receiver<Ev>,
    pub stop: Arc<AtomicBool>,
    pub running: bool,
    pub bytes_rx: u64,
    pub bytes_tx: u64,
    pub rate: Vec<(u64, u64, u64)>,
    pub bufs: HashMap<usize, (Vec<u8>, u64, u32, bool)>,
    pub filters: Filters,
    pub autosave: Option<Autosave>,
    pub merge_ms: u64,
    pub string_len: usize,
    pub values_dec: bool,
    pub ascii_escape: bool,
    pub selected: Option<usize>,
    pub find_pos: usize,
    pub seq: u64,
    pub notices: Vec<String>,
    pub tcp_writes: Arc<Mutex<HashMap<usize, Vec<(String, TcpStream)>>>>,
    pub serial_writes: Vec<Option<Box<dyn serialport::SerialPort>>>,
    pub udp_sends: Vec<Option<Arc<UdpSocket>>>,
    pub send_hex: bool,
    pub send_text: String,
    pub send_chan: usize,
    pub preset_req: bool,
    pub preset_sel: usize,
    pub auto_scroll: bool,
    /// PID of the intercepted process (capture sessions only).
    pub cap_pid: Option<u32>,
    /// hook handle (u64 from the pipe) -> channel index.
    pub cap_map: HashMap<u64, usize>,
}

pub fn now_wall() -> (u64, u32) {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    (d.as_secs(), d.subsec_millis())
}

pub fn bytes_hex(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 3);
    for (i, b) in data.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{:02X}", b));
    }
    s
}

pub fn fmt_time(secs: u64, millis: u32) -> String {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60,
        millis
    )
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (y + i64::from(m <= 2), m, d)
}

pub fn escape_text(data: &[u8], escape: bool) -> String {
    let mut s = String::new();
    for &b in data {
        if b == b'\r' {
            s.push_str("\\r");
        } else if b == b'\n' {
            s.push_str("\\n");
        } else if b == b'\t' {
            s.push_str("\\t");
        } else if (0x20..0x7F).contains(&b) {
            s.push(b as char);
        } else if escape {
            s.push_str(&format!("\\x{:02X}", b));
        } else {
            s.push('?');
        }
    }
    s
}

impl Session {
    pub fn new(name: String, channels: Vec<ChannelCfg>, proto: ProtoType, views: ViewToggles) -> Self {
        let (tx, rx) = std::sync::mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let n = channels.len();
        let mut sess = Session {
            name,
            channels,
            proto,
            views,
            rows: Vec::new(),
            ev_rx: rx,
            stop: stop.clone(),
            running: false,
            bytes_rx: 0,
            bytes_tx: 0,
            rate: Vec::new(),
            bufs: HashMap::new(),
            filters: Filters::default(),
            autosave: None,
            merge_ms: 250, // edt_se_DumpMerge TRzSpinEdit default Value=250 ms (Min 5/Max 1000/Increment 5, DFM @0xcc9c36); btnApplyClick sub_ab15a0 stores to TDumpViewSetting+0x1c fDumpMergeTime, chk_DumpMerge ON → +0x19
            string_len: 16, // cbb_OutPutCharLen DFM default (items 2/4/8/10/12/16/32)
            values_dec: false,
            ascii_escape: true,
            selected: None,
            find_pos: 0,
            seq: 0,
            notices: Vec::new(),
            tcp_writes: Arc::new(Mutex::new(HashMap::new())),
            serial_writes: Vec::with_capacity(n),
            udp_sends: Vec::with_capacity(n),
            send_hex: true,
            send_text: String::new(),
            send_chan: 0,
            preset_req: true,
            preset_sel: 0,
            auto_scroll: true,
            cap_pid: None,
            cap_map: HashMap::new(),
        };
        for (idx, ch) in sess.channels.clone().iter().enumerate() {
            match ch.kind {
                ChanKind::Serial => sess.open_serial(idx, ch.clone(), tx.clone(), stop.clone()),
                ChanKind::TcpClient => sess.open_tcp_client(idx, ch.clone(), tx.clone(), stop.clone()),
                ChanKind::TcpServer => sess.open_tcp_server(idx, ch.clone(), tx.clone(), stop.clone()),
                ChanKind::Udp => sess.open_udp(idx, ch.clone(), tx.clone(), stop.clone()),
                ChanKind::HookSerial => {}
            }
        }
        sess
    }

    /// Capture session: rows arrive via ingest() from the hook-DLL pipe, not from
    /// channels we own. `add_capture_channel` registers each intercepted handle.
    pub fn new_capture(pid: u32, exe: &str) -> Self {
        let mut s = Session::new(
            format!("PID {} {}", pid, exe),
            Vec::new(),
            ProtoType::None,
            ViewToggles { table: true, terminal: true, dump: true, line: true, modbus: true },
        );
        s.running = true;
        s.cap_pid = Some(pid);
        s
    }

    /// Register an intercepted handle as a channel; returns its index.
    pub fn add_capture_channel(&mut self, port: &str) -> usize {
        let idx = self.channels.len();
        self.channels.push(ChannelCfg {
            kind: ChanKind::HookSerial,
            name: port.to_string(),
            baud: 0,
            data_bits: 8,
            parity: 0,
            stop_bits: 1,
        });
        self.serial_writes.push(None);
        self.udp_sends.push(None);
        idx
    }

    fn open_serial(&mut self, idx: usize, ch: ChannelCfg, tx: Sender<Ev>, stop: Arc<AtomicBool>) {
        self.serial_writes.push(None);
        let builder = serialport::new(&ch.name, ch.baud)
            .data_bits(if ch.data_bits == 7 {
                serialport::DataBits::Seven
            } else {
                serialport::DataBits::Eight
            })
            .parity(match ch.parity {
                1 => serialport::Parity::Even,
                2 => serialport::Parity::Odd,
                _ => serialport::Parity::None,
            })
            .stop_bits(if ch.stop_bits == 2 {
                serialport::StopBits::Two
            } else {
                serialport::StopBits::One
            })
            .timeout(Duration::from_millis(50));
        match builder.open() {
            Ok(port) => {
                let read_half = port.try_clone().ok();
                self.serial_writes[idx] = Some(port);
                if let Some(mut rh) = read_half {
                    let tx = tx.clone();
                    std::thread::spawn(move || {
                        let mut buf = [0u8; 4096];
                        loop {
                            if stop.load(Ordering::Relaxed) {
                                break;
                            }
                            match rh.read(&mut buf) {
                                Ok(0) => {}
                                Ok(n) => {
                                    let (s, ms) = now_wall();
                                    if tx.send(Ev::Rx { idx, data: buf[..n].to_vec(), secs: s, millis: ms }).is_err() {
                                        break;
                                    }
                                }
                                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                                Err(e) => {
                                    let _ = tx.send(Ev::Closed { idx, why: e.to_string() });
                                    break;
                                }
                            }
                        }
                    });
                }
            }
            Err(e) => self.notices.push(format!("打开 {} 失败: {}", ch.name, e)),
        }
    }

    fn open_tcp_client(&mut self, idx: usize, ch: ChannelCfg, tx: Sender<Ev>, stop: Arc<AtomicBool>) {
        let addr = match ch.name.to_socket_addrs() {
            Ok(mut it) => it.next(),
            Err(e) => {
                self.notices.push(format!("地址无效 {}: {}", ch.name, e));
                return;
            }
        };
        let sa = match addr {
            Some(a) => a,
            None => {
                self.notices.push(format!("地址无效 {}", ch.name));
                return;
            }
        };
        match TcpStream::connect_timeout(&sa, Duration::from_secs(3)) {
            Ok(stream) => {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
                let mut rh = match stream.try_clone() {
                    Ok(s) => s,
                    Err(e) => {
                        self.notices.push(format!("克隆连接失败: {}", e));
                        return;
                    }
                };
                self.tcp_writes.lock().unwrap().insert(idx, vec![(ch.name.clone(), stream)]);
                std::thread::spawn(move || {
                    let mut buf = [0u8; 8192];
                    loop {
                        if stop.load(Ordering::Relaxed) {
                            break;
                        }
                        match rh.read(&mut buf) {
                            Ok(0) => {
                                let _ = tx.send(Ev::Closed { idx, why: "连接已关闭".into() });
                                break;
                            }
                            Ok(n) => {
                                let (s, ms) = now_wall();
                                if tx.send(Ev::Rx { idx, data: buf[..n].to_vec(), secs: s, millis: ms }).is_err() {
                                    break;
                                }
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                            Err(e) => {
                                let _ = tx.send(Ev::Closed { idx, why: e.to_string() });
                                break;
                            }
                        }
                    }
                });
            }
            Err(e) => self.notices.push(format!("连接 {} 失败: {}", ch.name, e)),
        }
    }

    fn open_tcp_server(&mut self, idx: usize, ch: ChannelCfg, tx: Sender<Ev>, stop: Arc<AtomicBool>) {
        let addr = match ch.name.to_socket_addrs() {
            Ok(mut it) => it.next(),
            Err(e) => {
                self.notices.push(format!("地址无效 {}: {}", ch.name, e));
                return;
            }
        };
        let sa = match addr {
            Some(a) => a,
            None => {
                self.notices.push(format!("地址无效 {}", ch.name));
                return;
            }
        };
        match TcpListener::bind(sa) {
            Ok(listener) => {
                let _ = listener.set_nonblocking(true);
                self.notices.push(format!("TCP服务端监听 {}", ch.name));
                let writes = self.tcp_writes.clone();
                std::thread::spawn(move || {
                    loop {
                        if stop.load(Ordering::Relaxed) {
                            break;
                        }
                        match listener.accept() {
                            Ok((stream, peer)) => {
                                let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
                                let label = peer.to_string();
                                let _ = tx.send(Ev::Peer { idx, label: label.clone() });
                                if let Ok(w) = stream.try_clone() {
                                    writes.lock().unwrap().entry(idx).or_default().push((label, w));
                                }
                                let tx2 = tx.clone();
                                let stop2 = stop.clone();
                                let mut rh = stream;
                                std::thread::spawn(move || {
                                    let mut buf = [0u8; 8192];
                                    loop {
                                        if stop2.load(Ordering::Relaxed) {
                                            break;
                                        }
                                        match rh.read(&mut buf) {
                                            Ok(0) => break,
                                            Ok(n) => {
                                                let (s, ms) = now_wall();
                                                if tx2.send(Ev::Rx { idx, data: buf[..n].to_vec(), secs: s, millis: ms }).is_err() {
                                                    break;
                                                }
                                            }
                                            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                                            Err(_) => break,
                                        }
                                    }
                                });
                            }
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                std::thread::sleep(Duration::from_millis(100));
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
            Err(e) => self.notices.push(format!("监听 {} 失败: {}", ch.name, e)),
        }
    }

    fn open_udp(&mut self, idx: usize, _ch: ChannelCfg, tx: Sender<Ev>, stop: Arc<AtomicBool>) {
        match UdpSocket::bind("0.0.0.0:0") {
            Ok(sock) => {
                let _ = sock.set_read_timeout(Some(Duration::from_millis(50)));
                self.udp_sends.push(Some(Arc::new(sock)));
                let sock = self.udp_sends[idx].clone().unwrap();
                std::thread::spawn(move || {
                    let rh = match sock.try_clone() {
                        Ok(s) => s,
                        Err(_) => return,
                    };
                    let mut buf = [0u8; 8192];
                    loop {
                        if stop.load(Ordering::Relaxed) {
                            break;
                        }
                        match rh.recv_from(&mut buf) {
                            Ok((n, _peer)) => {
                                let (s, ms) = now_wall();
                                if tx.send(Ev::Rx { idx, data: buf[..n].to_vec(), secs: s, millis: ms }).is_err() {
                                    break;
                                }
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                            Err(_) => break,
                        }
                    }
                });
            }
            Err(e) => self.notices.push(format!("UDP绑定失败: {}", e)),
        }
    }

    pub fn poll(&mut self) {
        if !self.running {
            // still drain so paused sessions don't explode the channel
            while let Ok(ev) = self.ev_rx.try_recv() {
                if let Ev::Rx { idx, data, .. } = ev {
                    self.bytes_rx += data.len() as u64;
                    let _ = idx;
                }
            }
            return;
        }
        let mut n = 0;
        while let Ok(ev) = self.ev_rx.try_recv() {
            match ev {
                Ev::Rx { idx, data, secs, millis } => self.ingest(idx, data, secs, millis, false),
                Ev::Peer { idx, label } => {
                    self.notices.push(format!("通道{} 新连接 {}", idx, label));
                }
                Ev::Closed { idx, why } => {
                    self.notices.push(format!("通道{} 关闭: {}", idx, why));
                }
            }
            n += 1;
            if n >= 2000 {
                break;
            }
        }
        // flush idle RTU buffers
        let now = now_wall();
        let idxs: Vec<usize> = self.bufs.keys().copied().collect();
        for idx in idxs {
            let idle = {
                let e = self.bufs.get(&idx).unwrap();
                (now.0 > e.1) || (now.1 >= e.2 + 60)
            };
            if idle && !self.bufs.get(&idx).unwrap().0.is_empty() {
                let e = self.bufs.remove(&idx).unwrap();
                self.flush_rtu(idx, e.0, e.3, e.1, e.2);
            }
        }
    }

    pub fn ingest(&mut self, idx: usize, data: Vec<u8>, secs: u64, millis: u32, dir_tx: bool) {
        if dir_tx {
            self.bytes_tx += data.len() as u64;
        } else {
            self.bytes_rx += data.len() as u64;
        }
        match self.proto {
            ProtoType::None => self.push_row(data, idx, dir_tx, secs, millis, None),
            ProtoType::Tcp => {
                {
                    let e = self.bufs.entry(idx).or_default();
                    e.0.extend_from_slice(&data);
                    e.1 = secs;
                    e.2 = millis;
                    e.3 = dir_tx;
                }
                loop {
                    let parsed = {
                        let e = self.bufs.get_mut(&idx).unwrap();
                        protocol::parse_mbap(&e.0, e.3)
                    };
                    match parsed {
                        Some((p, used)) => {
                            let buf_len = self.bufs.get(&idx).map(|b| b.0.len()).unwrap_or(0);
                            let used = used.min(buf_len);
                            let e = self.bufs.get_mut(&idx).unwrap();
                            let frame = e.0[..used].to_vec();
                            let rest = e.0.split_off(used);
                            let dir = e.3;
                            let (ts, tms) = (e.1, e.2);
                            self.bufs.insert(idx, (rest, ts, tms, dir));
                            self.push_row(frame, idx, dir, ts, tms, Some(p));
                        }
                        None => break,
                    }
                }
            }
            ProtoType::Ascii => {
                {
                    let e = self.bufs.entry(idx).or_default();
                    e.0.extend_from_slice(&data);
                    e.1 = secs;
                    e.2 = millis;
                    e.3 = dir_tx;
                }
                loop {
                    let nl = self.bufs.get(&idx).unwrap().0.iter().position(|&b| b == b'\n');
                    match nl {
                        Some(pos) => {
                            let e = self.bufs.get_mut(&idx).unwrap();
                            let line: Vec<u8> = e.0.drain(..=pos).collect();
                            let dir = e.3;
                            let (s, ms) = (e.1, e.2);
                            let txt: Vec<u8> = line
                                .iter()
                                .copied()
                                .filter(|b| !b.is_ascii_whitespace())
                                .skip_while(|&b| b == b':')
                                .collect();
                            let parsed = protocol::parse_ascii_text(&txt, dir);
                            self.push_row(line, idx, dir, s, ms, parsed);
                        }
                        None => break,
                    }
                }
            }
            ProtoType::Rtu => {
                {
                    let e = self.bufs.entry(idx).or_default();
                    if !e.0.is_empty() && ((secs > e.1) || (e.2 + FRAME_GAP_MS <= millis && secs == e.1)) {
                        let old = std::mem::take(&mut e.0);
                        let (os, oms, odir) = (e.1, e.2, e.3);
                        self.flush_rtu(idx, old, odir, os, oms);
                        let e = self.bufs.get_mut(&idx).unwrap();
                        e.1 = secs;
                        e.2 = millis;
                        e.3 = dir_tx;
                    }
                    let e = self.bufs.get_mut(&idx).unwrap();
                    e.0.extend_from_slice(&data);
                    if e.1 == 0 && e.2 == 0 {
                        e.1 = secs;
                        e.2 = millis;
                        e.3 = dir_tx;
                    }
                    if e.0.len() >= 600 {
                        let old = std::mem::take(&mut e.0);
                        let (os, oms, odir) = (e.1, e.2, e.3);
                        self.flush_rtu(idx, old, odir, os, oms);
                    }
                }
            }
        }
    }

    fn flush_rtu(&mut self, idx: usize, buf: Vec<u8>, dir_tx: bool, secs: u64, millis: u32) {
        if buf.is_empty() {
            return;
        }
        let parsed = protocol::parse_rtu(&buf, dir_tx);
        self.push_row(buf, idx, dir_tx, secs, millis, parsed);
    }

    fn push_row(&mut self, data: Vec<u8>, idx: usize, dir_tx: bool, secs: u64, millis: u32, parsed: Option<ModbusParsed>) {
        // merge within merge_ms for raw mode (以指定时间区间合并"读"和"写"的数据):
        // - opposite direction: pair a read with its write (original semantics, once per row)
        // - same direction: reassemble reads the OS delivered in fragments (first byte
        //   split from the rest), chaining until the stream pauses past the window
        if self.merge_ms > 0 && parsed.is_none() {
            if let Some(last) = self.rows.last_mut() {
                if last.idx == idx && !last.merged {
                    let gap = if secs >= last.secs {
                        (secs - last.secs) * 1000 + millis as u64 - last.millis as u64
                    } else {
                        u64::MAX
                    };
                    if gap <= self.merge_ms {
                        if last.dir_tx != dir_tx {
                            last.data.extend_from_slice(&data);
                            last.merged = true;
                            return;
                        } else if last.data.len() < 65536 {
                            last.data.extend_from_slice(&data);
                            return; // keep chaining; merged stays false
                        }
                    }
                }
            }
        }
        self.seq += 1;
        let kind = parsed.as_ref().map(|p| p.kind).unwrap_or(if dir_tx { FrameKind::Req } else { FrameKind::Resp });
        let row = Row {
            seq: self.seq,
            idx,
            dir_tx,
            secs,
            millis,
            data,
            parsed,
            kind,
            merged: false,
        };
        let chan = self
            .channels
            .get(idx)
            .map(|c| c.name.clone())
            .unwrap_or_else(|| "?".into());
        if let Some(a) = &mut self.autosave {
            if a.on {
                autosave_line(&chan, &row, a);
            }
        }
        // rate bucket
        let sec = secs;
        match self.rate.last_mut() {
            Some(e) if e.0 == sec => {
                if dir_tx {
                    e.2 += 1;
                } else {
                    e.1 += 1;
                }
            }
            _ => {
                self.rate.push((sec, if dir_tx { 0 } else { 1 }, if dir_tx { 1 } else { 0 }));
                if self.rate.len() > 180 {
                    self.rate.remove(0);
                }
            }
        }
        self.rows.push(row);
        // grp_CaptureMax default: rbMaxLimit checked, cbb_CaptrueMax ItemIndex=2 of
        // 100000/500000/1000000/2000000/5000000 → 1,000,000 records (original DFM).
        if self.rows.len() > 1_000_000 {
            let drop = self.rows.len() - 900_000;
            self.rows.drain(..drop);
            self.selected = None;
            self.find_pos = 0;
        }
    }

    pub fn visible_count(&self) -> usize {
        self.rows.iter().filter(|r| self.filters.pass(r)).count()
    }

    pub fn send_bytes(&mut self, idx: usize, data: &[u8]) -> Result<(), String> {
        if self.channels.is_empty() {
            return Err("该会话没有通道".into());
        }
        let ch = &self.channels[idx.min(self.channels.len() - 1)];
        let res: Result<(), String> = match ch.kind {
            ChanKind::Serial => match self.serial_writes.get_mut(idx) {
                Some(Some(w)) => w.write_all(data).map_err(|e| e.to_string()),
                _ => Err("串口未打开".into()),
            },
            ChanKind::TcpClient | ChanKind::TcpServer => {
                let mut map = self.tcp_writes.lock().unwrap();
                match map.get_mut(&idx) {
                    Some(conns) => {
                        let mut err = None;
                        for (_, s) in conns.iter_mut() {
                            if let Err(e) = s.write_all(data) {
                                err = Some(e.to_string());
                            }
                        }
                        match err {
                            Some(e) => Err(e),
                            None => Ok(()),
                        }
                    }
                    None => Err("没有连接".into()),
                }
            }
            ChanKind::Udp => match self.udp_sends.get(idx) {
                Some(Some(s)) => s.send_to(data, &ch.name).map(|_| ()).map_err(|e| e.to_string()),
                _ => Err("UDP未打开".into()),
            },
            ChanKind::HookSerial => Err("拦截通道只读：串口句柄由被监控进程持有".into()),
        };
        if res.is_ok() {
            let (s, ms) = now_wall();
            self.ingest(idx, data.to_vec(), s, ms, true);
        }
        res
    }

    pub fn stop_all(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    pub fn clear(&mut self) {
        self.rows.clear();
        self.selected = None;
        self.find_pos = 0;
    }

    pub fn save_log(&self, path: &str, enc: usize) -> std::io::Result<()> {
        let mut out = String::from("# 万能监控日志 v1\n");
        for r in &self.rows {
            let chan = self
                .channels
                .get(r.idx)
                .map(|c| c.name.clone())
                .unwrap_or_else(|| "?".into());
            out.push_str(&format!(
                "{}\t{}\t{}\t{}\n",
                fmt_time(r.secs, r.millis),
                chan,
                if r.dir_tx { "写" } else { "读" },
                bytes_hex(&r.data)
            ));
        }
        let bytes: Vec<u8> = match enc {
            1 => {
                let (b, _, _) = encoding_rs::GBK.encode(&out);
                b.to_vec()
            }
            2 => {
                let (b, _, _) = encoding_rs::UTF_16LE.encode(&out);
                b.to_vec()
            }
            _ => out.into_bytes(),
        };
        std::fs::write(path, bytes)
    }
}

fn autosave_line(chan: &str, row: &Row, a: &mut Autosave) {
    // rotation
    let now = now_wall();
    let need_new = a.cur_file.is_empty()
        || match a.split {
            1 => now.0 >= a.started_at + a.time_min * 60,
            2 => a.written >= a.size_mb * 1024 * 1024,
            _ => false,
        };
    if need_new {
        let base = if a.path.is_empty() { "autosave".to_string() } else { a.path.clone() };
        let p = std::path::Path::new(&base);
        let stem = p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "autosave".into());
        let ext = p.extension().map(|s| format!(".{}", s.to_string_lossy())).unwrap_or_else(|| ".log".into());
        let n = now.0 % 100000;
        a.cur_file = format!("{}_{}{}", stem, n, ext);
        a.started_at = now.0;
        a.written = 0;
    }
    let line = format!(
        "{}\t{}\t{}\t{}\n",
        fmt_time(row.secs, row.millis),
        chan,
        if row.dir_tx { "写" } else { "读" },
        bytes_hex(&row.data)
    );
    let bytes: Vec<u8> = match a.encoding {
        1 => {
            let (b, _, _) = encoding_rs::GBK.encode(&line);
            b.to_vec()
        }
        2 => {
            let (b, _, _) = encoding_rs::UTF_16LE.encode(&line);
            b.to_vec()
        }
        _ => line.into_bytes(),
    };
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&a.cur_file) {
        let _ = f.write_all(&bytes);
        a.written += bytes.len() as u64;
    }
}

/// Synthetic frames for screenshot/demo mode (populated UI without hardware).
pub fn seed_demo(sess: &mut Session) {
    let pairs: &[(&str, &str)] = &[
        ("01 03 00 6B 00 03", "01 03 06 02 2B 00 00 00 64"),
        ("01 01 00 13 00 13", "01 01 03 CD 6B 05"),
        ("01 04 00 08 00 01", "01 04 02 00 0A"),
        ("01 06 00 01 00 03", "01 06 00 01 00 03"),
        ("01 10 00 01 00 02 04 00 0A 01 02", "01 10 00 01 00 02"),
        ("01 02 00 C4 00 16", "01 02 03 AC DB 35"),
    ];
    let now = now_wall();
    let mut t = now.0 - 30;
    let mut ms = now.1;
    for (req, resp) in pairs {
        let rq = protocol::parse_hex(req).unwrap_or_default();
        let rs = protocol::parse_hex(resp).unwrap_or_default();
        t += 1;
        sess.ingest(0, rq, t, ms, true);
        ms = (ms + 12) % 1000;
        sess.ingest(0, rs, t, ms, false);
        ms = (ms + 30) % 1000;
    }
    let text = b"Device READY, FW=2.1\r\n";
    sess.proto = ProtoType::None;
    sess.ingest(0, text.to_vec(), t + 1, 5, false);
    sess.proto = ProtoType::Rtu;
    let now2 = now_wall();
    for i in 0..40u64 {
        let rx = 40 + ((i * 37) % 90);
        sess.rate.push((now2.0 - 60 + i, rx, (i * 13) % 20));
    }
    sess.running = true;
}
