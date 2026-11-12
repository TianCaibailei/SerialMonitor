// Session engine: channels (serial / TCP client / TCP server / UDP), frame reassembly,
// row storage, filters, rate history, auto-save logging.

use crate::protocol::{self, FrameKind, ModbusParsed};
use crate::text_codec::{self, DisplayEncoding};
use std::collections::{HashMap, HashSet};
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
        ViewToggles {
            table: true,
            terminal: true,
            dump: true,
            line: true,
            modbus: false,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
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
    Rx {
        idx: usize,
        data: Vec<u8>,
        secs: u64,
        millis: u32,
    },
    Peer {
        idx: usize,
        label: String,
    },
    Closed {
        idx: usize,
        why: String,
    },
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
    /// Where the row came from. Driver rows are raw serial bytes captured by the kernel
    /// filter, not Modbus frames, so the UI must not present a parsed function code for
    /// them (the parser happily reports 00/"Unknown" for arbitrary bytes).
    pub origin: RowOrigin,
    /// Serial parameter change, when this row is a control record.
    pub control: Option<crate::driver::ControlInfo>,
}

/// Which capture path produced a row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum RowOrigin {
    /// Injected hook or a real serial/protocol channel.
    #[default]
    Channel,
    /// Kernel filter driver capture.
    Driver,
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
        Filters {
            dir: 0,
            fcs: Vec::new(),
            text: String::new(),
            text_on: false,
        }
    }
}

impl Filters {
    /// `enc` is the session's display encoding: text matching must see the same
    /// decoded characters the user sees in the views. GBK / UTF-16 content used to be
    /// unsearchable because this function went through `String::from_utf8_lossy`.
    pub fn pass(&self, r: &Row, enc: DisplayEncoding) -> bool {
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
            let txt = text_codec::decoded_text(&r.data, enc).to_lowercase();
            if !hex.contains(&t) && !txt.contains(&t) {
                return false;
            }
        }
        true
    }
}

/// 端口白名单的共用判定。
///
/// 未启用（`on == false`）= 不限制，这正是与 `drv_watch` 对齐的那半语义：
/// 默认状态、config.ini 里缺这一项、以及"全选"都是这个状态。
///
/// 一旦启用就严格按白名单走 —— 空集合表示"一个端口都不放行"，而不是"放行全部"。
/// 只有这样才能让「取消选择」按钮有意义；否则它和「全选」会变成同一个动作。
/// 做成自由函数是因为「过滤设置」对话框的草稿和 `Session` 上真正生效的状态
/// 必须用同一套规则，否则用户会看到"勾了却没生效"这种自相矛盾的界面。
pub fn pw_allowed(sel: &HashSet<String>, on: bool, name: &str) -> bool {
    if !on {
        return true;
    }
    sel.contains(name)
}

/// 全选 = 回到"不限制"。
pub fn pw_select_all(sel: &mut HashSet<String>, on: &mut bool) {
    sel.clear();
    *on = false;
}

/// 取消选择 = 有意的"一个都不看"（空集合 + 已启用）。这正是需要 `on` 标志的原因。
pub fn pw_select_none(sel: &mut HashSet<String>, on: &mut bool) {
    sel.clear();
    *on = true;
}

/// 反选：以当前生效的勾选状态为基准取补集；补集覆盖全部端口时回到"不限制"。
pub fn pw_invert(sel: &mut HashSet<String>, on: &mut bool, all: &[String]) {
    if all.is_empty() {
        return;
    }
    let next: HashSet<String> = all
        .iter()
        .filter(|n| !pw_allowed(sel, *on, n))
        .cloned()
        .collect();
    if next.len() >= all.len() {
        pw_select_all(sel, on);
    } else {
        *sel = next;
        *on = true;
    }
}

/// 勾选/取消勾选单个端口，交互对齐「驱动捕获设置」里的 drv_watch：
/// 第一次收窄时先把当前全部端口塞进白名单再移除；全部选回则清空集合恢复"不限制"。
pub fn pw_toggle(
    sel: &mut HashSet<String>,
    on: &mut bool,
    all: &[String],
    name: &str,
    checked: bool,
) {
    // 第一次收窄：从"全部勾选"出发，把现有端口都算进去。
    if !*on {
        *sel = all.iter().cloned().collect();
        *on = true;
    }
    if checked {
        sel.insert(name.to_string());
    } else {
        sel.remove(name);
    }
    // 全部选回 -> 回到"不限制"。用"覆盖了当前所有端口"判断而不是比 len：
    // 白名单里可能还留着已经不存在的旧端口名。
    if !all.is_empty() && all.iter().all(|n| sel.contains(n)) {
        pw_select_all(sel, on);
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
    /// Encoding used to turn captured bytes into readable text in every view, in
    /// search/filter, in copy and in export. This is deliberately separate from the
    /// old `save_enc`/`r_enc` fields (which only ever chose the export file bytes).
    pub display_encoding: DisplayEncoding,
    pub selected: Option<usize>,
    pub find_pos: usize,
    pub seq: u64,
    pub notices: Vec<String>,
    /// Keeps TCP client sockets alive for the lifetime of the session.
    ///
    /// The read loop owns a clone for reading; the original must stay somewhere or the
    /// connection would be closed as soon as `open_tcp_client` returns. This is a
    /// keep-alive holder only — the monitor never writes to it.
    pub tcp_conns: Arc<Mutex<HashMap<usize, Vec<TcpStream>>>>,
    pub serial_ports: Vec<Option<Box<dyn serialport::SerialPort>>>,
    pub udp_socks: Vec<Option<Arc<UdpSocket>>>,

    pub auto_scroll: bool,
    /// PID of the intercepted process (capture sessions only).
    pub cap_pid: Option<u32>,
    /// hook handle (u64 from the pipe) -> channel index.
    pub cap_map: HashMap<u64, usize>,
    /// 会话级端口白名单：只有**勾选**的端口名（通道名，如 "COM6"）才进入本会话。
    ///
    /// 语义对齐驱动路径上的 `drv_watch`（ui.rs）：**没启用 / 空 = 不限制**。
    /// 额外多一个 `port_watch_on` 开关，是因为「取消选择」必须能表达
    /// 「一个端口都不监视」—— 那在集合上也是空的，只有靠这个开关和"不限制"区分。
    pub port_watch: HashSet<String>,
    /// 端口过滤是否已启用。`false` → 不限制（新会话的默认状态，等价于"全部勾选"）。
    pub port_watch_on: bool,
}

pub fn now_wall() -> (u64, u32) {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    (d.as_secs(), d.subsec_millis())
}

fn b01(v: bool) -> char {
    if v {
        '1'
    } else {
        '0'
    }
}

/// Escape a field for the tab-separated archive format. Only the separator and the
/// escape character need handling, which keeps archives human-readable.
fn esc_field(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
    out
}

fn unesc_field(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('t') => out.push('\t'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('\\') => out.push('\\'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
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

/// Decode-then-escape. Kept under the old name so all existing call sites keep the
/// same shape; the extra `enc` argument forces every consumer to state which encoding
/// it renders with (there is no longer a hidden "bytes are ASCII" assumption).
pub fn escape_text(data: &[u8], escape: bool, enc: DisplayEncoding) -> String {
    text_codec::escape_text(data, escape, enc)
}

impl Session {
    pub fn new(
        name: String,
        channels: Vec<ChannelCfg>,
        proto: ProtoType,
        views: ViewToggles,
    ) -> Self {
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
            display_encoding: DisplayEncoding::Utf8,
            selected: None,
            find_pos: 0,
            seq: 0,
            notices: Vec::new(),
            tcp_conns: Arc::new(Mutex::new(HashMap::new())),
            serial_ports: Vec::with_capacity(n),
            udp_socks: Vec::with_capacity(n),

            auto_scroll: true,
            cap_pid: None,
            cap_map: HashMap::new(),
            port_watch: HashSet::new(),
            port_watch_on: false,
        };
        for (idx, ch) in sess.channels.clone().iter().enumerate() {
            match ch.kind {
                ChanKind::Serial => sess.open_serial(idx, ch.clone(), tx.clone(), stop.clone()),
                ChanKind::TcpClient => {
                    sess.open_tcp_client(idx, ch.clone(), tx.clone(), stop.clone())
                }
                ChanKind::TcpServer => {
                    sess.open_tcp_server(idx, ch.clone(), tx.clone(), stop.clone())
                }
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
            ViewToggles {
                table: true,
                terminal: true,
                dump: true,
                line: true,
                modbus: true,
            },
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
        self.serial_ports.push(None);
        self.udp_socks.push(None);
        idx
    }

    /// 会话级端口白名单：这个端口名目前是否允许进入本会话。
    ///
    /// 未启用 = 不限制（对齐 ui.rs 里 `drv_watch` 的"空/缺省 = 全部"语义）；
    /// 启用之后严格按白名单走，不在集合里的端口一律丢弃。
    pub fn port_allowed(&self, name: &str) -> bool {
        pw_allowed(&self.port_watch, self.port_watch_on, name)
    }

    /// 会话里可以出现在「监视端口」列表中的端口名（HookSerial 通道名，如 COM6）。
    ///
    /// 去重并保持通道顺序：驱动路径按端口建通道，同一端口不会重复，
    /// 但手工新建 + 自动附加有可能撞名，重复的 checkbox 会让人以为可以分别勾选。
    pub fn port_choices(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for c in &self.channels {
            if c.kind == ChanKind::HookSerial && !out.iter().any(|n| n == &c.name) {
                out.push(c.name.clone());
            }
        }
        out
    }

    fn open_serial(&mut self, idx: usize, ch: ChannelCfg, tx: Sender<Ev>, stop: Arc<AtomicBool>) {
        self.serial_ports.push(None);
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
                self.serial_ports[idx] = Some(port);
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
                                    if tx
                                        .send(Ev::Rx {
                                            idx,
                                            data: buf[..n].to_vec(),
                                            secs: s,
                                            millis: ms,
                                        })
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                                Err(e) => {
                                    let _ = tx.send(Ev::Closed {
                                        idx,
                                        why: e.to_string(),
                                    });
                                    break;
                                }
                            }
                        }
                    });
                }
            }
            Err(e) => {
                // A busy port is the single most common surprise here: another
                // program already owns it. serialport reports this as a
                // communication error whose text carries the OS message, so match
                // on the text and point at the mode built for exactly this case.
                let text = e.to_string();
                let busy = text.contains("denied")
                    || text.contains("拒绝")
                    || text.contains("occupied")
                    || text.contains("busy")
                    || text.contains("正在使用")
                    || text.contains("Access is denied");
                let msg = if busy {
                    format!(
                        "打开 {} 失败: 端口已被其他程序占用。\
                         若只想观察该程序的通信，请改用「串口监听(不占用)」通道并附加到该进程。",
                        ch.name
                    )
                } else {
                    format!("打开 {} 失败: {}", ch.name, text)
                };
                self.notices.push(msg);
            }
        }
    }

    fn open_tcp_client(
        &mut self,
        idx: usize,
        ch: ChannelCfg,
        tx: Sender<Ev>,
        stop: Arc<AtomicBool>,
    ) {
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
                self.tcp_conns.lock().unwrap().insert(idx, vec![stream]);
                std::thread::spawn(move || {
                    let mut buf = [0u8; 8192];
                    loop {
                        if stop.load(Ordering::Relaxed) {
                            break;
                        }
                        match rh.read(&mut buf) {
                            Ok(0) => {
                                let _ = tx.send(Ev::Closed {
                                    idx,
                                    why: "连接已关闭".into(),
                                });
                                break;
                            }
                            Ok(n) => {
                                let (s, ms) = now_wall();
                                if tx
                                    .send(Ev::Rx {
                                        idx,
                                        data: buf[..n].to_vec(),
                                        secs: s,
                                        millis: ms,
                                    })
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                            Err(e) => {
                                let _ = tx.send(Ev::Closed {
                                    idx,
                                    why: e.to_string(),
                                });
                                break;
                            }
                        }
                    }
                });
            }
            Err(e) => self.notices.push(format!("连接 {} 失败: {}", ch.name, e)),
        }
    }

    fn open_tcp_server(
        &mut self,
        idx: usize,
        ch: ChannelCfg,
        tx: Sender<Ev>,
        stop: Arc<AtomicBool>,
    ) {
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
                std::thread::spawn(move || loop {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    match listener.accept() {
                        Ok((stream, peer)) => {
                            let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
                            let label = peer.to_string();
                            let _ = tx.send(Ev::Peer { idx, label });
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
                                            if tx2
                                                .send(Ev::Rx {
                                                    idx,
                                                    data: buf[..n].to_vec(),
                                                    secs: s,
                                                    millis: ms,
                                                })
                                                .is_err()
                                            {
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
                });
            }
            Err(e) => self.notices.push(format!("监听 {} 失败: {}", ch.name, e)),
        }
    }

    fn open_udp(&mut self, idx: usize, _ch: ChannelCfg, tx: Sender<Ev>, stop: Arc<AtomicBool>) {
        match UdpSocket::bind("0.0.0.0:0") {
            Ok(sock) => {
                let _ = sock.set_read_timeout(Some(Duration::from_millis(50)));
                self.udp_socks.push(Some(Arc::new(sock)));
                let sock = self.udp_socks[idx].clone().unwrap();
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
                                if tx
                                    .send(Ev::Rx {
                                        idx,
                                        data: buf[..n].to_vec(),
                                        secs: s,
                                        millis: ms,
                                    })
                                    .is_err()
                                {
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
            // Still drain the channel so a paused session cannot grow it without bound,
            // but do NOT count what we drop: "暂停中" used to keep incrementing Bytes
            // (and counted every dropped RX chunk as received), which directly
            // contradicted the "已暂停" label in the status bar.
            while let Ok(ev) = self.ev_rx.try_recv() {
                if let Ev::Closed { idx, why } = ev {
                    self.notices.push(format!("通道{} 关闭: {}", idx, why));
                }
            }
            // Drop half-assembled protocol buffers too: replaying them after 恢复 would
            // emit frames whose pieces were received while paused.
            self.bufs.clear();
            return;
        }
        let mut n = 0;
        while let Ok(ev) = self.ev_rx.try_recv() {
            match ev {
                Ev::Rx {
                    idx,
                    data,
                    secs,
                    millis,
                } => self.ingest(idx, data, secs, millis, false),
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

    /// Feed one record captured by the kernel filter driver.
    ///
    /// Separate from `ingest` because driver rows are raw serial bytes, not protocol
    /// frames: no MBAP/ASCII parsing, no row merging, and the row is tagged with its
    /// origin so the UI shows "串口读/串口写" instead of a meaningless Modbus function
    /// code (the parser reports 00/"Unknown" for arbitrary bytes).
    pub fn ingest_driver(
        &mut self,
        idx: usize,
        data: Vec<u8>,
        secs: u64,
        millis: u32,
        dir_tx: bool,
        control: Option<crate::driver::ControlInfo>,
    ) {
        if dir_tx {
            self.bytes_tx += data.len() as u64;
        } else if control.is_none() {
            self.bytes_rx += data.len() as u64;
        }

        self.seq += 1;
        let kind = if dir_tx {
            FrameKind::Req
        } else {
            FrameKind::Resp
        };
        let row = Row {
            seq: self.seq,
            idx,
            dir_tx,
            secs,
            millis,
            data,
            parsed: None,
            kind,
            merged: false,
            origin: RowOrigin::Driver,
            control,
        };
        let chan = self
            .channels
            .get(idx)
            .map(|c| c.name.clone())
            .unwrap_or_else(|| "?".into());
        if let Some(a) = &mut self.autosave {
            if a.on {
                autosave_line(&chan, &row, a, self.display_encoding);
            }
        }
        self.bump_rate(secs, dir_tx, row.data.len() as u64);
        self.rows.push(row);
        if self.rows.len() > 1_000_000 {
            let drop = self.rows.len() - 1_000_000;
            self.rows.drain(0..drop);
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
                    let nl = self
                        .bufs
                        .get(&idx)
                        .unwrap()
                        .0
                        .iter()
                        .position(|&b| b == b'\n');
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
                let e = self.bufs.entry(idx).or_default();
                if !e.0.is_empty()
                    && ((secs > e.1) || (e.2 + FRAME_GAP_MS <= millis && secs == e.1))
                {
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

    fn flush_rtu(&mut self, idx: usize, buf: Vec<u8>, dir_tx: bool, secs: u64, millis: u32) {
        if buf.is_empty() {
            return;
        }
        let parsed = protocol::parse_rtu(&buf, dir_tx);
        self.push_row(buf, idx, dir_tx, secs, millis, parsed);
    }

    fn push_row(
        &mut self,
        data: Vec<u8>,
        idx: usize,
        dir_tx: bool,
        secs: u64,
        millis: u32,
        parsed: Option<ModbusParsed>,
    ) {
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
        let kind = parsed.as_ref().map(|p| p.kind).unwrap_or(if dir_tx {
            FrameKind::Req
        } else {
            FrameKind::Resp
        });
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
            origin: RowOrigin::Channel,
            control: None,
        };
        let chan = self
            .channels
            .get(idx)
            .map(|c| c.name.clone())
            .unwrap_or_else(|| "?".into());
        if let Some(a) = &mut self.autosave {
            if a.on {
                autosave_line(&chan, &row, a, self.display_encoding);
            }
        }
        self.bump_rate(secs, dir_tx, row.data.len() as u64);
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

    /// Record bytes into the per-second rate buckets.
    ///
    /// This used to add `1` per row, which made the Line view — labelled "B/s" — plot a
    /// frame count, and left the status bar with no throughput figure at all. Now each
    /// bucket carries real bytes so the curve and the status bar agree.
    fn bump_rate(&mut self, secs: u64, dir_tx: bool, bytes: u64) {
        match self.rate.last_mut() {
            Some(e) if e.0 == secs => {
                if dir_tx {
                    e.2 += bytes;
                } else {
                    e.1 += bytes;
                }
            }
            _ => {
                self.rate.push((
                    secs,
                    if dir_tx { 0 } else { bytes },
                    if dir_tx { bytes } else { 0 },
                ));
                // Keep ~10 minutes of per-second history.
                if self.rate.len() > 600 {
                    let drop = self.rate.len() - 600;
                    self.rate.drain(..drop);
                }
            }
        }
    }

    /// Bytes per second over the most recent completed second bucket (RX, TX).
    ///
    /// The newest bucket is still filling, so it is reported separately as "current";
    /// using it directly would make the number flicker to 0 at every second boundary.
    pub fn current_rate(&self) -> (u64, u64) {
        self.rate.last().map(|e| (e.1, e.2)).unwrap_or((0, 0))
    }

    /// Peak per-second rate over the retained window (RX, TX).
    pub fn peak_rate(&self) -> (u64, u64) {
        self.rate
            .iter()
            .fold((0u64, 0u64), |(prx, ptx), e| (prx.max(e.1), ptx.max(e.2)))
    }

    /// Total bytes for the two directions, regardless of capture path.
    pub fn totals(&self) -> (u64, u64) {
        (self.bytes_rx, self.bytes_tx)
    }

    pub fn visible_count(&self) -> usize {
        let enc = self.display_encoding;
        self.rows
            .iter()
            .filter(|r| self.filters.pass(r, enc))
            .count()
    }

    pub fn stop_all(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Serialise the session to a reopenable archive (`.umses`).
    ///
    /// Format (UTF-8 text, tab separated, versioned by the header line):
    ///
    /// ```text
    /// UMSEX 1
    /// name      <session name, escaped>
    /// proto     <none|rtu|ascii|tcp>
    /// encoding  <0|1|2>
    /// views     <table,terminal,dump,line,modbus>  (0/1 each)
    /// chan      <kind> <name, escaped> <baud> <data> <parity> <stop>
    /// row       <seq> <idx> <dir 0/1> <secs> <millis> <hex>
    /// ```
    ///
    /// Rows keep their raw bytes only: `parsed` is derived, so recomputing it on load is
    /// both cheaper and guaranteed consistent with the current parser.
    pub fn save_archive(&self, path: &str) -> std::io::Result<()> {
        let mut out = String::new();
        out.push_str("UMSEX 1\n");
        out.push_str(&format!("name\t{}\n", esc_field(&self.name)));
        out.push_str(&format!(
            "proto\t{}\n",
            match self.proto {
                ProtoType::None => "none",
                ProtoType::Rtu => "rtu",
                ProtoType::Ascii => "ascii",
                ProtoType::Tcp => "tcp",
            }
        ));
        out.push_str(&format!("encoding\t{}\n", self.display_encoding.as_index()));
        out.push_str(&format!(
            "views\t{}{}{}{}{}\n",
            b01(self.views.table),
            b01(self.views.terminal),
            b01(self.views.dump),
            b01(self.views.line),
            b01(self.views.modbus)
        ));
        for c in &self.channels {
            let kind = match c.kind {
                ChanKind::Serial => "serial",
                ChanKind::TcpClient => "tcpclient",
                ChanKind::TcpServer => "tcpserver",
                ChanKind::Udp => "udp",
                ChanKind::HookSerial => "hook",
            };
            out.push_str(&format!(
                "chan\t{}\t{}\t{}\t{}\t{}\t{}\n",
                kind,
                esc_field(&c.name),
                c.baud,
                c.data_bits,
                c.parity,
                c.stop_bits
            ));
        }
        for r in &self.rows {
            out.push_str(&format!(
                "row\t{}\t{}\t{}\t{}\t{}\t{}\n",
                r.seq,
                r.idx,
                if r.dir_tx { 1 } else { 0 },
                r.secs,
                r.millis,
                bytes_hex(&r.data).replace(' ', "")
            ));
        }
        std::fs::write(path, out)
    }

    /// Load a session written by `save_archive`. Returns a paused session (nothing is
    /// re-opened) so the user can browse history exactly as it was captured.
    pub fn load_archive(path: &str) -> Result<Session, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("读取失败: {e}"))?;
        let mut lines = text.lines();
        let header = lines.next().unwrap_or("");
        let mut it = header.split_whitespace();
        if it.next() != Some("UMSEX") {
            return Err("不是本程序的会话文件（缺少 UMSEX 头）".into());
        }
        let version: u32 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        if version != 1 {
            return Err(format!("不支持的会话文件版本 {version}（本程序支持 1）"));
        }
        let mut name = String::from("导入的会话");
        let mut proto = ProtoType::None;
        let mut encoding = DisplayEncoding::Utf8;
        let mut views = ViewToggles::default();
        let mut channels: Vec<ChannelCfg> = Vec::new();
        let mut rows_raw: Vec<(u64, usize, bool, u64, u32, Vec<u8>)> = Vec::new();

        for line in lines {
            if line.is_empty() {
                continue;
            }
            let f: Vec<&str> = line.split('\t').collect();
            match f.first().copied() {
                Some("name") if f.len() >= 2 => name = unesc_field(f[1]),
                Some("proto") if f.len() >= 2 => {
                    proto = match f[1] {
                        "rtu" => ProtoType::Rtu,
                        "ascii" => ProtoType::Ascii,
                        "tcp" => ProtoType::Tcp,
                        _ => ProtoType::None,
                    }
                }
                Some("encoding") if f.len() >= 2 => {
                    encoding = DisplayEncoding::from_index(f[1].parse().unwrap_or(0))
                }
                Some("views") if f.len() >= 2 => {
                    let v: Vec<char> = f[1].chars().collect();
                    views = ViewToggles {
                        table: v.first() != Some(&'0'),
                        terminal: v.get(1) != Some(&'0'),
                        dump: v.get(2) != Some(&'0'),
                        line: v.get(3) != Some(&'0'),
                        modbus: v.get(4) == Some(&'1'),
                    }
                }
                Some("chan") if f.len() >= 7 => {
                    let kind = match f[1] {
                        "serial" => ChanKind::Serial,
                        "tcpclient" => ChanKind::TcpClient,
                        "tcpserver" => ChanKind::TcpServer,
                        "udp" => ChanKind::Udp,
                        _ => ChanKind::HookSerial,
                    };
                    channels.push(ChannelCfg {
                        kind,
                        name: unesc_field(f[2]),
                        baud: f[3].parse().unwrap_or(9600),
                        data_bits: f[4].parse().unwrap_or(8),
                        parity: f[5].parse().unwrap_or(0),
                        stop_bits: f[6].parse().unwrap_or(1),
                    });
                }
                Some("row") if f.len() >= 7 => {
                    let seq: u64 = f[1].parse().unwrap_or(0);
                    let idx: usize = f[2].parse().unwrap_or(0);
                    let dir_tx = f[3] == "1";
                    let secs: u64 = f[4].parse().unwrap_or(0);
                    let millis: u32 = f[5].parse().unwrap_or(0);
                    let data = protocol::parse_hex(f[6]).unwrap_or_default();
                    rows_raw.push((seq, idx, dir_tx, secs, millis, data));
                }
                // Unknown keys are ignored on purpose: forward compatibility.
                _ => {}
            }
        }

        let mut s = Session::new(name, channels, proto, views);
        s.display_encoding = encoding;
        s.running = false; // imported sessions are for browsing only
        for (seq, idx, dir_tx, secs, millis, data) in rows_raw {
            // Re-derive the parse from the bytes so the archive needs no parser version.
            s.push_row_import(seq, idx, dir_tx, secs, millis, data);
        }
        Ok(s)
    }

    /// Insert a row read from an archive, preserving its original sequence number and
    /// timestamp. Kept separate from `push_row` so importing never re-merges rows that
    /// were already merged when captured, and never re-bumps live counters.
    fn push_row_import(
        &mut self,
        seq: u64,
        idx: usize,
        dir_tx: bool,
        secs: u64,
        millis: u32,
        data: Vec<u8>,
    ) {
        let parsed = match self.proto {
            ProtoType::None => None,
            ProtoType::Rtu => protocol::parse_rtu(&data, dir_tx),
            ProtoType::Ascii => protocol::parse_ascii_text(&data, dir_tx),
            ProtoType::Tcp => protocol::parse_mbap(&data, dir_tx).map(|(p, _)| p),
        };
        let kind = parsed.as_ref().map(|p| p.kind).unwrap_or(if dir_tx {
            FrameKind::Req
        } else {
            FrameKind::Resp
        });
        self.rows.push(Row {
            seq,
            idx,
            dir_tx,
            secs,
            millis,
            data,
            parsed,
            kind,
            merged: true,
            origin: RowOrigin::Channel,
            control: None,
        });
        self.seq = self.seq.max(seq);
    }

    pub fn clear(&mut self) {
        self.rows.clear();
        self.selected = None;
        self.find_pos = 0;
    }

    /// `enc` selects the **file** encoding; the text column always uses the session's
    /// display encoding so exported Chinese is readable (the old version exported only
    /// HEX, so switching encoding had no effect on the captured content at all).
    pub fn save_log(&self, path: &str, enc: DisplayEncoding) -> std::io::Result<()> {
        let dec = self.display_encoding;
        let mut out = String::from("# 万能监控日志 v2\n");
        out.push_str("# 列: 时间\t通道\t方向\tHEX\t文本(按显示编码解码)\n");
        for r in &self.rows {
            let chan = self
                .channels
                .get(r.idx)
                .map(|c| c.name.clone())
                .unwrap_or_else(|| "?".into());
            let text = text_codec::decoded_text(&r.data, dec).replace(['\r', '\n', '\t'], " ");
            out.push_str(&format!(
                "{}\t{}\t{}\t{}\t{}\n",
                fmt_time(r.secs, r.millis),
                chan,
                if r.dir_tx { "写" } else { "读" },
                bytes_hex(&r.data),
                text
            ));
        }
        std::fs::write(path, text_codec::encode(&out, enc))
    }
}

fn autosave_line(chan: &str, row: &Row, a: &mut Autosave, dec: DisplayEncoding) {
    // rotation
    let now = now_wall();
    let need_new = a.cur_file.is_empty()
        || match a.split {
            1 => now.0 >= a.started_at + a.time_min * 60,
            2 => a.written >= a.size_mb * 1024 * 1024,
            _ => false,
        };
    let enc = DisplayEncoding::from_index(a.encoding);
    if need_new {
        let base = if a.path.is_empty() {
            "autosave".to_string()
        } else {
            a.path.clone()
        };
        let p = std::path::Path::new(&base);
        let stem = p
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "autosave".into());
        let ext = p
            .extension()
            .map(|s| format!(".{}", s.to_string_lossy()))
            .unwrap_or_else(|| ".log".into());
        let n = now.0 % 100000;
        a.cur_file = format!("{}_{}{}", stem, n, ext);
        a.started_at = now.0;
        a.written = 0;
        // A BOM belongs at the very beginning of a new file only — appending it on
        // every rotation would inject it in the middle of a UTF-16 stream.
        let bom = text_codec::bom(enc);
        if !bom.is_empty() {
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&a.cur_file)
            {
                let _ = f.write_all(bom);
                a.written += bom.len() as u64;
            }
        }
    }
    let text = text_codec::decoded_text(&row.data, dec).replace(['\r', '\n', '\t'], " ");
    let line = format!(
        "{}\t{}\t{}\t{}\t{}\n",
        fmt_time(row.secs, row.millis),
        chan,
        if row.dir_tx { "写" } else { "读" },
        bytes_hex(&row.data),
        text
    );
    // encode() prepends a BOM; for append chunks we strip it so it is written once only.
    let full = text_codec::encode(&line, enc);
    let bom_len = text_codec::bom(enc).len();
    let bytes = &full[bom_len..];
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&a.cur_file)
    {
        let _ = f.write_all(bytes);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "umses_test_{tag}_{}_{}.umses",
            std::process::id(),
            now_wall().0
        ));
        p
    }

    fn sample_session() -> Session {
        let views = ViewToggles {
            table: true,
            terminal: true,
            dump: true,
            line: true,
            modbus: true,
        };
        let mut s = Session::new(
            "测试 会话\twith tab".into(),
            vec![
                ChannelCfg {
                    kind: ChanKind::HookSerial,
                    name: "COM6".into(),
                    baud: 0,
                    data_bits: 8,
                    parity: 0,
                    stop_bits: 1,
                },
                ChannelCfg {
                    kind: ChanKind::TcpClient,
                    name: "127.0.0.1:502".into(),
                    baud: 9600,
                    data_bits: 8,
                    parity: 1,
                    stop_bits: 2,
                },
            ],
            ProtoType::Rtu,
            views,
        );
        s.display_encoding = DisplayEncoding::Gbk;
        s.ingest(
            0,
            protocol::append_crc(&[0x01, 0x03, 0x00, 0x6B, 0x00, 0x03]),
            1_700_000_000,
            5,
            true,
        );
        s.ingest(
            0,
            protocol::append_crc(&[0x01, 0x03, 0x06, 0x02, 0x2B, 0x00, 0x00, 0x00, 0x64]),
            1_700_000_001,
            7,
            false,
        );
        // GBK "中文" as a raw payload, to prove bytes survive the roundtrip.
        s.ingest(1, vec![0xD6, 0xD0, 0xCE, 0xC4], 1_700_000_002, 9, false);
        s
    }

    #[test]
    fn archive_roundtrip_preserves_rows_and_settings() {
        let s = sample_session();
        let path = temp_path("roundtrip");
        s.save_archive(path.to_str().unwrap()).expect("save");

        let l = Session::load_archive(path.to_str().unwrap()).expect("load");
        assert_eq!(l.name, s.name);
        assert_eq!(l.proto, s.proto);
        assert_eq!(l.display_encoding, s.display_encoding);
        assert_eq!(l.channels.len(), s.channels.len());
        assert_eq!(l.channels[1].name, "127.0.0.1:502");
        assert_eq!(l.channels[1].parity, 1);
        assert_eq!(l.rows.len(), s.rows.len());
        for (a, b) in l.rows.iter().zip(s.rows.iter()) {
            assert_eq!(a.data, b.data, "payload must survive as bytes");
            assert_eq!(a.seq, b.seq);
            assert_eq!(a.secs, b.secs);
            assert_eq!(a.millis, b.millis);
            assert_eq!(a.dir_tx, b.dir_tx);
            assert_eq!(a.idx, b.idx);
        }
        // Loaded sessions are for browsing: never running, never re-merged.
        assert!(!l.running);
        // Parsed frames are re-derived from bytes, so they must still be present.
        assert!(l.rows.iter().any(|r| r.parsed.is_some()));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn archive_rejects_foreign_or_future_files() {
        let p1 = temp_path("foreign");
        std::fs::write(&p1, "hello\nworld\n").unwrap();
        assert!(Session::load_archive(p1.to_str().unwrap()).is_err());
        let _ = std::fs::remove_file(&p1);

        let p2 = temp_path("future");
        std::fs::write(&p2, "UMSEX 99\nname\tx\n").unwrap();
        assert!(Session::load_archive(p2.to_str().unwrap()).is_err());
        let _ = std::fs::remove_file(&p2);
    }

    #[test]
    fn archive_roundtrip_tolerates_tabs_and_backslashes_in_names() {
        let mut s = sample_session();
        s.name = "a\\b\tc".into();
        s.channels[0].name = "CO\\M\t6".into();
        let path = temp_path("escaping");
        s.save_archive(path.to_str().unwrap()).expect("save");
        let l = Session::load_archive(path.to_str().unwrap()).expect("load");
        assert_eq!(l.name, "a\\b\tc");
        assert_eq!(l.channels[0].name, "CO\\M\t6");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn pause_semantics_are_honoured_by_rate_buckets() {
        // bump_rate now stores bytes, not frame counts (the Line view is labelled B/s).
        let mut s = sample_session();
        let before = s.current_rate();
        s.ingest(0, vec![0u8; 10], 1_700_000_100, 0, false);
        let after = s.current_rate();
        assert!(
            after.0 >= before.0 + 10,
            "RX bucket must grow by the payload size (was {} -> {})",
            before.0,
            after.0
        );
        let (peak_rx, _) = s.peak_rate();
        assert!(peak_rx >= 10);
    }

    #[test]
    fn filters_search_decoded_text() {
        // Build the session with the raw (None) protocol so the payload lands as one
        // row: under Modbus RTU the reassembler would hold a non-frame payload back.
        let mut s = Session::new(
            "filter test".into(),
            vec![ChannelCfg {
                kind: ChanKind::Serial,
                name: "COM9".into(),
                baud: 9600,
                data_bits: 8,
                parity: 0,
                stop_bits: 1,
            }],
            ProtoType::None,
            ViewToggles::default(),
        );
        s.merge_ms = 0;
        s.display_encoding = DisplayEncoding::Gbk;
        s.ingest(0, vec![0xD6, 0xD0, 0xCE, 0xC4], 100, 0, false); // GBK "中文"
        assert_eq!(s.rows.len(), 1);

        s.filters.text = "中文".into();
        s.filters.text_on = true;
        assert_eq!(s.visible_count(), 1, "GBK payload must be findable as 中文");

        s.display_encoding = DisplayEncoding::Utf8;
        assert_eq!(s.visible_count(), 0, "same bytes are not 中文 under UTF-8");
    }

    // ---- frame reassembly -------------------------------------------------------------
    //
    // `ingest` decides where one protocol frame ends and the next begins. This is where a
    // monitor silently loses or merges data if it is wrong, and it had no tests at all.

    fn plain_session(proto: ProtoType) -> Session {
        let mut s = Session::new(
            "reassembly".into(),
            vec![ChannelCfg {
                kind: ChanKind::Serial,
                name: "COM1".into(),
                baud: 9600,
                data_bits: 8,
                parity: 0,
                stop_bits: 1,
            }],
            proto,
            ViewToggles::default(),
        );
        // Merging is a display preference for raw streams; frame-level tests must not be
        // perturbed by it.
        s.merge_ms = 0;
        s
    }

    #[test]
    fn rtu_splits_two_frames_arriving_in_one_read() {
        let mut s = plain_session(ProtoType::Rtu);
        let mut buf = protocol::append_crc(&[0x01, 0x03, 0x00, 0x6B, 0x00, 0x03]);
        buf.extend_from_slice(&protocol::append_crc(&[
            0x01, 0x03, 0x06, 0x02, 0x2B, 0x00, 0x00, 0x00, 0x64,
        ]));
        s.ingest(0, buf, 1000, 0, false);
        // RTU relies on the inter-frame gap, so both frames are still buffered as one.
        assert!(
            s.rows.is_empty(),
            "no frame may be emitted without a gap/idle signal"
        );

        // A second read after the gap flushes the buffered bytes as one frame, then the
        // newly arrived bytes start a fresh buffer.
        s.ingest(0, vec![0x01, 0x03], 1001, 0, false);
        assert_eq!(s.rows.len(), 1, "the first buffered frame must be flushed");
        assert!(s.rows[0].parsed.is_some(), "flushed frame must be parsed");
    }

    #[test]
    fn rtu_frame_is_flushed_once_the_buffer_exceeds_the_guard_size() {
        let mut s = plain_session(ProtoType::Rtu);
        // 600+ bytes forces a flush even without an idle gap (see ingest's `>= 600` guard).
        let payload: Vec<u8> = (0..700u32).map(|i| (i % 251) as u8).collect();
        s.ingest(0, payload, 1000, 0, false);
        assert_eq!(
            s.rows.len(),
            1,
            "oversized buffer must be flushed, not held forever"
        );
    }

    #[test]
    fn modbus_ascii_splits_on_newline() {
        let mut s = plain_session(ProtoType::Ascii);
        let pdu = [0x01u8, 0x03, 0x00, 0x6B, 0x00, 0x03];
        let mut hex = String::new();
        for b in pdu {
            hex.push_str(&format!("{b:02X}"));
        }
        let line = format!(":{hex}{:02X}\r\n", protocol::lrc(&pdu));
        s.ingest(0, line.clone().into_bytes(), 1000, 0, false);
        assert_eq!(s.rows.len(), 1);

        // Two frames in a single chunk must produce two rows.
        let two = format!("{line}{line}");
        s.ingest(0, two.into_bytes(), 1001, 0, false);
        assert_eq!(
            s.rows.len(),
            3,
            "each newline-terminated frame is its own row"
        );
    }

    #[test]
    fn modbus_tcp_splits_on_mbap_length() {
        let mut s = plain_session(ProtoType::Tcp);
        let f1 = protocol::wrap_mbap(&[0x01, 0x03, 0x00, 0x6B, 0x00, 0x03], 1);
        let f2 = protocol::wrap_mbap(&[0x01, 0x04, 0x00, 0x08, 0x00, 0x01], 2);
        // Frames coalesced in one TCP read must be split by their MBAP length field.
        let mut both = f1.clone();
        both.extend_from_slice(&f2);
        s.ingest(0, both, 1000, 0, false);
        assert_eq!(s.rows.len(), 2);
        assert!(s.rows.iter().all(|r| r.parsed.is_some()));

        // A partial frame must be buffered, not emitted half-formed.
        let f3 = protocol::wrap_mbap(&[0x01, 0x03, 0x00, 0x00, 0x00, 0x02], 3);
        s.ingest(0, f3[..4].to_vec(), 1001, 0, false);
        assert_eq!(s.rows.len(), 2, "incomplete MBAP frame stays buffered");
        s.ingest(0, f3[4..].to_vec(), 1001, 10, false);
        assert_eq!(
            s.rows.len(),
            3,
            "completing the frame emits exactly one row"
        );
    }

    #[test]
    fn raw_mode_emits_one_row_per_read() {
        let mut s = plain_session(ProtoType::None);
        s.ingest(0, b"hello".to_vec(), 1000, 0, false);
        s.ingest(0, b"world".to_vec(), 1000, 50, false);
        assert_eq!(s.rows.len(), 2);
        assert_eq!(s.rows[0].data, b"hello");
        assert_eq!(s.rows[1].data, b"world");
    }

    #[test]
    fn pause_drops_samples_instead_of_counting_them() {
        let mut s = plain_session(ProtoType::None);
        s.running = false;
        // Route data the way the live paths do: through poll(), which must discard it.
        let (tx, rx) = std::sync::mpsc::channel();
        s.ev_rx = rx;
        tx.send(Ev::Rx {
            idx: 0,
            data: vec![1, 2, 3, 4],
            secs: 1,
            millis: 0,
        })
        .unwrap();
        s.poll();
        assert!(s.rows.is_empty(), "paused sessions must not record rows");
        assert_eq!(
            s.bytes_rx, 0,
            "dropped bytes must not be counted as received"
        );
    }
}
