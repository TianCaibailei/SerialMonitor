// Main window: menus, session tabs, five views, dialogs, send pane, status bar.

use crate::inject::{self, CapMsg};
use crate::protocol::{self, REQUEST_PRESETS, RESPONSE_PRESETS};
use crate::session::{
    bytes_hex, escape_text, fmt_time, now_wall, pw_allowed, pw_invert, pw_select_all,
    pw_select_none, pw_toggle, seed_demo, Autosave, ChanKind, ChannelCfg, Filters, RowOrigin,
    ProtoType, Session, ViewToggles,
};
use crate::text_codec::{self, DisplayEncoding};
use egui::{
    Color32, ComboBox, Context, DragValue, RichText, ScrollArea, SelectableLabel, TextEdit, Ui,
    ViewportCommand, Window,
};
use egui_extras::{Column, TableBuilder};
use egui_plot::{Legend, Line, Plot, PlotPoints};
use std::collections::{HashMap, HashSet};
use std::sync::mpsc::Receiver;

const C_REQ: Color32 = Color32::from_rgb(0x1F, 0x6F, 0xEB);
const C_RESP: Color32 = Color32::from_rgb(0x23, 0xA5, 0x59);
const C_EXC: Color32 = Color32::from_rgb(0xE0, 0x80, 0x00);
const C_FAIL: Color32 = Color32::from_rgb(0xD6, 0x45, 0x45);
const C_TX: Color32 = Color32::from_rgb(0x35, 0x72, 0xD9);
const C_RX: Color32 = Color32::from_rgb(0x2D, 0x8A, 0x4B);

/// 发给驱动捕获线程的命令。
///
/// 控制设备是独占打开的（CreateFileW 的 share=0），界面手里没有句柄：一旦开始捕获，
/// 再想 set_target / attach_ports 就会拿到共享冲突错误。所以这些都交给已经持有句柄
/// 的那个线程去执行，而不是在 UI 线程里另开一个句柄。
pub enum DrvCmd {
    SetTarget(u32),
    /// 重新附加端口，并把新的端口表回传。
    Rescan,
    Stop,
}

/// 捕获线程回传的非数据事件。
pub enum DrvEvt {
    /// 端口表：序号 + 设备路径。
    Ports(Vec<(u32, String)>),
    /// set_target 已生效。
    Target(u32),
}

/// 设备路径转短名：`\Device\VSerial8_2` → `VSerial8_2`。
fn short_dev(path: &str) -> String {
    path.rsplit('\\').next().unwrap_or(path).to_string()
}


/// Channel display name. Unresolved ids render as `UNKNOWN(<id>)`, matching the
/// original's port-name fallback (CommMonitor sub_841a50; fmt "UNKNOWN(%d)" @0x841b74).
fn chan_label(s: &Session, idx: usize) -> String {
    match s.channels.get(idx) {
        Some(c) => c.name.clone(),
        None => format!("UNKNOWN({idx})"),
    }
}

const BAUDS: [u32; 12] = [1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400, 460800, 576000, 921600];
const FCS: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 0x0B, 0x0C, 0x0F, 0x10, 0x11, 0x14, 0x16, 0x2B];
const VIEW_NAMES: [&str; 5] = ["Table视图", "终端视图", "Dump视图", "Line曲线图", "Modbus视图"];
const ENCS: [&str; 3] = ["UTF-8", "ANSI(GBK)", "Unicode(UTF-16LE)"];
const SPLITS: [&str; 3] = ["单个文件不分割", "按时间范围分割", "强制文件大小，超过将覆盖"];
// Order matters: index 0 is the DEFAULT when the New Monitor dialog opens.
//
// A serial monitor exists to watch OTHER software's traffic, so the passive
// (hook) mode is the default and owning the port is the explicit exception. The
// original CommMonitor behaves the same way: its driver never opens the device.
const CHAN_KINDS: [&str; 5] = [
    "串口监听(不占用)",
    "TCP客户端",
    "TCP服务端",
    "UDP",
    "串口独占用(本软件占用)",
];

pub struct MonitorApp {
    pub sessions: Vec<Session>,
    pub active: usize,
    pub view_sel: usize,
    /// 显示编码的全局默认值（新建会话时继承）。菜单「设置→编码方式」同时改它和
    /// 当前活动会话，使切换立刻对所有视图生效；落盘到 config.ini。
    pub display_enc: DisplayEncoding,
    /// 导出文件编码；与显示编码分离，仍由「自动保存日志设置」里的编码选择管理。
    pub save_enc: usize,
    pub frame_count: u64,
    pub toast_msg: String,
    pub toast_until: u64,
    pub capture_done: bool,
    pub screenshot: Option<String>,

    // dialogs
    pub dlg_new: bool,
    pub dlg_filter: bool,
    pub dlg_redir: bool,
    pub dlg_prefs: bool,
    pub dlg_find: bool,
    pub dlg_about: bool,
    pub dlg_attach: bool,

    // cross-process interception (hook DLL over named pipe)
    pub cap_rx: Option<Receiver<CapMsg>>,
    pub procs: Vec<(u32, String)>,
    pub attach_sel: Option<usize>,
    /// Filter text for the attach dialog: matches exe name or PID.
    pub attach_filter: String,
    /// Hide obvious non-candidates (services, brokers, browsers) by default.
    pub attach_only_apps: bool,
    /// PIDs currently known to hold one of the watched ports, refreshed by the dialog.
    pub port_holders: Vec<u32>,
    /// Human-readable result of the last holder scan (shown in the dialog).
    pub holder_note: String,
    /// Frame on which the holder list was last refreshed.
    pub holders_at: u64,
    /// (pid, hook handle) → port name, from Open records; lets Rx/Tx route into
    /// hook-watch sessions by port even when the Open predates session creation.
    pub hook_ports: HashMap<(u32, u64), String>,
    /// Background service that injects the hook DLL into whatever program holds a
    /// watched port, so the user only opens a session and never picks processes.
    pub auto: Option<crate::autoattach::AutoAttach>,
    /// Kernel driver capture (when UmSerialFilter is loaded). Records arrive on a
    /// background thread; per-port channels are created on demand.
    pub drv: Option<crate::driver::DriverHandle>,
    pub drv_pid: Option<u32>,
    pub drv_rx: Option<Receiver<crate::driver::Record>>,
    /// Driver port index → session channel index, per session.
    pub drv_ports: HashMap<(usize, u32), usize>,
    pub drv_checked: bool,
    pub drv_note: String,
    /// 端口序号 → 设备路径。start_driver_capture / 重新扫描时一次性取全，
    /// drain_driver 只查表（见 drain_driver 里的说明）。
    pub drv_names: HashMap<u32, String>,
    // ---- 端口过滤：统一由「过滤设置 → 监视端口」控制 ----
    //
    // 两套捕获路径（注入 / 驱动）看到的世界不一样，过滤必须收敛到一处，否则用户
    // 要在两个地方各勾一遍，而且两个地方用的是**不同的名字**（驱动用设备短名
    // `VSerial8_2`，注入用 COM 号 `COM6`），对不上就会静默失效。
    //
    // 统一后的规则：
    //   * 唯一生效状态是 `Session::port_watch` / `port_watch_on`，按 **COM 号** 匹配；
    //   * 注入路径在 route_hook_data 里用它筛；
    //   * 驱动路径在 drain_driver 里用它筛；
    //   * 「驱动捕获设置」不再持有自己的端口白名单（原来的 drv_watch 已删除）。
    //
    // 这样用户只需要在一个地方表达「我关心 COM6」，两条路径同时遵守；
    // 而且驱动即使挂接了全部端口，也只有关注的端口会变成数据行。
    /// 端口白名单的默认/落盘状态：是否启用端口过滤。
    pub fport_on: bool,
    /// 端口白名单的默认/落盘状态：勾选的端口名（空集合 = 不限制）。
    pub fport_sel: HashSet<String>,
    /// 对话框草稿是从哪个会话同步来的（`self.active` 的下标）。
    ///
    /// 记下标而不是记 bool，是为了处理"对话框开着的时候切了会话标签页"：
    /// 那样草稿必须重新同步，否则点「应用」会把 A 会话的端口表写进 B 会话。
    /// `None` 表示草稿还没同步过（对话框是关着的）。
    pub fport_draft_sess: Option<usize>,
    /// 对话框草稿：是否启用端口过滤。
    pub fport_draft_on: bool,
    /// 对话框草稿：勾选的端口名。
    pub fport_draft_sel: HashSet<String>,
    /// Device path -> "COM6". Read once when capture starts so the UI can show the number
    /// the user recognises next to the device name.
    pub drv_com: HashMap<String, String>,
    /// 最近一次可用性检测的结果与错误码（错误码用于给签名/权限问题分类）。
    pub drv_avail: bool,
    pub drv_err: u32,
    /// 上次探测驱动的时间；探测是 CreateFile，不能每帧都做。
    pub drv_probe_at: Option<std::time::Instant>,
    /// 捕获线程的三件套：停止标志、线程句柄、命令通道。
    ///
    /// 驱动控制设备不支持被同一进程同时打开两次，所以端口重扫和 PID 切换必须交给
    /// 已经持有句柄的捕获线程执行，而不是在界面上另开一个句柄。
    pub drv_stop: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    pub drv_thread: Option<std::thread::JoinHandle<()>>,
    pub drv_cmd: Option<std::sync::mpsc::Sender<DrvCmd>>,
    pub drv_evt: Option<Receiver<DrvEvt>>,
    /// 驱动捕获设置对话框。
    pub dlg_drv: bool,
    pub drv_pid_text: String,

    // new-monitor dialog state (defaults, persisted to config.ini)
    pub chan_kind: usize,
    pub ports: Vec<String>,
    pub port_sel: Vec<bool>,
    pub baud_i: usize,
    pub data_i: usize,
    pub parity_i: usize,
    pub stop_i: usize,
    pub addr: String,
    pub proto_sel: usize,
    pub views_new: ViewToggles,
    pub auto_mon: bool,

    // filter defaults
    pub fdir: usize,
    pub fcs_sel: Vec<bool>,
    pub ftext: String,
    pub ftext_on: bool,

    // redirect defaults
    pub r_on: bool,
    pub r_path: String,
    pub r_split: usize,
    pub r_time: u64,
    pub r_size: u64,
    pub r_enc: usize,

    // display defaults
    pub p_merge: u64,
    pub p_strlen: usize,
    pub p_dec: bool,
    pub p_esc: bool,
    pub p_scroll: bool,
    /// 显示设置对话框：是否应用到全部会话（仅对话框内使用）。
    pub p_apply_all: bool,

    pub find_text: String,
    /// Row index the views should scroll to on the next frame (set by 查找 / 查找下一个).
    /// Cleared as soon as a view consumed it, so it is a one-shot request.
    pub scroll_to_row: Option<usize>,
    /// Last search result feedback, e.g. "3/128 匹配". Shown in the find dialog.
    pub find_note: String,
    /// Recently saved / opened `.umses` archives, newest first (persisted to config.ini).
    pub recent_archives: Vec<String>,
    /// Snapshot taken when 显示设置 opened, restored on 取消.
    pub prefs_backup: Option<(u64, usize, bool, bool, bool)>,
    /// Snapshot taken when 自动保存日志设置 opened, restored on 取消.
    pub redir_backup: Option<(bool, String, usize, u64, u64, usize)>,
    /// 「退出」在有会话时先确认，避免未保存的采集数据被直接丢弃。
    pub dlg_confirm_exit: bool,
}

fn b(v: bool) -> &'static str {
    if v { "1" } else { "0" }
}

/// 端口白名单在 config.ini 里的编码：逗号分隔（`COM6,COM7`）。
///
/// 之所以不用空格：config.ini 的解析是按空白切分的 `k=v`，值里带空格会被拆成
/// 两个 token。空字符串表示空集合。
fn fmt_port_list(sel: &HashSet<String>) -> String {
    let mut names: Vec<&String> = sel.iter().collect();
    names.sort(); // 稳定输出，避免每次保存都改文件内容
    names.iter().map(|s| s.as_str()).collect::<Vec<&str>>().join(",")
}

fn parse_port_list(v: &str) -> HashSet<String> {
    v.split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// Rough "is this a user application rather than a service/broker" test, used to keep
/// the attach list short by default. It only filters the *display* — any process is
/// still reachable by typing its name or PID in the search box.
fn looks_like_app(name: &str) -> bool {
    let n = name.to_lowercase();
    const NOISE: &[&str] = &[
        "svchost", "dllhost", "conhost", "runtimebroker", "searchhost", "searchindexer",
        "searchprotocolhost", "searchfilterhost", "taskhostw", "sihost", "fontdrvhost",
        "dwm", "csrss", "smss", "wininit", "winlogon", "lsass", "services", "spoolsv",
        "audiodg", "msmpeng", "mpdefender", "securityhealth", "smartscreen", "wudfhost",
        "wmiprvse", "dashost", "unsecapp", "lockapp", "textinputhost",
        "startmenuexperiencehost", "shellexperiencehost", "applicationframehost",
        "aggregatorhost", "backgroundtaskhost", "msedgewebview2", "crashpad_handler",
        "widgetboard", "widgetservice", "useroobebroker", "openconsole", "systemsettings",
    ];
    !NOISE.iter().any(|k| n.contains(k))
}

impl MonitorApp {
    pub fn new(screenshot: Option<String>) -> Self {
        let ports: Vec<String> = serialport::available_ports()
            .unwrap_or_default()
            .into_iter()
            .map(|p| p.port_name)
            .collect();
        let port_sel = vec![false; ports.len()];
        let mut app = MonitorApp {
            sessions: Vec::new(),
            active: 0,
            view_sel: 0,
            display_enc: DisplayEncoding::Utf8,
            save_enc: 0,
            frame_count: 0,
            toast_msg: String::new(),
            toast_until: 0,
            capture_done: false,
            screenshot: screenshot.clone(),
            dlg_new: false,
            dlg_filter: false,
            dlg_redir: false,
            dlg_prefs: false,
            dlg_find: false,
            dlg_about: false,
            dlg_attach: false,
            cap_rx: Some(inject::start_capture_server()),
            procs: Vec::new(),
            attach_sel: None,
            attach_filter: String::new(),
            attach_only_apps: true,
            port_holders: Vec::new(),
            holder_note: String::new(),
            holders_at: 0,
            hook_ports: HashMap::new(),
            auto: None,
            drv: None,
            drv_pid: None,
            drv_rx: None,
            drv_ports: HashMap::new(),
            drv_checked: false,
            drv_note: String::new(),
            drv_names: HashMap::new(),
            fport_on: false,
            fport_sel: HashSet::new(),
            fport_draft_sess: None,
            fport_draft_on: false,
            fport_draft_sel: HashSet::new(),
            drv_com: HashMap::new(),
            drv_avail: false,
            drv_err: 0,
            drv_probe_at: None,
            drv_stop: None,
            drv_thread: None,
            drv_cmd: None,
            drv_evt: None,
            dlg_drv: false,
            drv_pid_text: "0".into(),
            chan_kind: 0,
            ports,
            port_sel,
            baud_i: 3,
            data_i: 1,
            parity_i: 0,
            stop_i: 0,
            addr: "127.0.0.1:502".into(),
            proto_sel: 1,
            views_new: ViewToggles::default(),
            auto_mon: false,
            fdir: 0,
            fcs_sel: vec![false; FCS.len()],
            ftext: String::new(),
            ftext_on: false,
            r_on: false,
            r_path: "monitor.log".into(),
            r_split: 0,
            r_time: 10,
            r_size: 10,
            r_enc: 0,
            p_merge: 250,
            p_strlen: 16,
            p_dec: false,
            p_esc: true,
            p_scroll: true,
            p_apply_all: false,
            find_text: String::new(),
            scroll_to_row: None,
            find_note: String::new(),
            recent_archives: Vec::new(),
            prefs_backup: None,
            redir_backup: None,
            dlg_confirm_exit: false,
        };
        app.load_cfg();
        if screenshot.is_some() {
            let views = ViewToggles { table: true, terminal: true, dump: true, line: true, modbus: true };
            let mut s = Session::new("COM3 演示会话".into(), Vec::new(), ProtoType::Rtu, views);
            s.channels.push(ChannelCfg {
                kind: ChanKind::Serial,
                name: "COM3".into(),
                baud: 9600,
                data_bits: 8,
                parity: 0,
                stop_bits: 1,
            });
            seed_demo(&mut s);
            app.sessions.push(s);
            app.active = 0;
            // A screenshot run can ask for the attach dialog instead of the main
            // window, which is how the dialog's layout gets verified.
            if std::env::var("UM_SHOW_ATTACH").is_ok() {
                app.dlg_attach = true;
                app.procs = inject::list_processes();
                app.attach_filter = String::new();
            }
            // 同理，UM_SHOW_DRIVER 让截图跑的是「驱动捕获设置」对话框，
            // 否则这个对话框的排版没人验证得了（它平时要先点菜单才会出来）。
            if std::env::var("UM_SHOW_DRIVER").is_ok() {
                app.dlg_drv = true;
                app.probe_driver_availability(true);
                if !app.drv_avail {
                    app.drv_note = crate::driver::open_failure_hint(app.drv_err);
                }
            }
            // 同理，UM_SHOW_FILTER 让截图直接打开「过滤设置」，用于验证端口过滤区
            // 的排版（这是现在唯一的端口过滤入口，两条捕获路径共用）。
            if std::env::var("UM_SHOW_FILTER").is_ok() {
                app.dlg_filter = true;
            }
        }
        app
    }

    fn toast(&mut self, msg: impl Into<String>) {
        self.toast_msg = msg.into();
        self.toast_until = self.frame_count + 600;
    }

    /// Apply a display encoding: to the global default (new sessions inherit it), to
    /// every open session (so switching takes effect immediately), and to config.ini.
    /// This is the single entry point the menu uses — previously the menu only changed
    /// `save_enc`, which nothing in the rendering path ever read.
    fn set_display_encoding(&mut self, enc: DisplayEncoding) {
        self.display_enc = enc;
        for s in &mut self.sessions {
            s.display_encoding = enc;
        }
        self.save_cfg();
        self.toast(format!("显示编码已切换为 {}（全部视图即时生效）", enc.label()));
    }

    fn load_cfg(&mut self) {
        if let Ok(txt) = std::fs::read_to_string("config.ini") {
            for line in txt.lines().skip_while(|l| !l.trim().eq_ignore_ascii_case("[NewMon]")) {
                if line.trim().eq_ignore_ascii_case("[NewMon]") {
                    continue;
                }
                for kv in line.split_whitespace() {
                    if let Some((k, v)) = kv.split_once('=') {
                        let on = v == "1";
                        match k {
                            "tableView" => self.views_new.table = on,
                            "terminalView" => self.views_new.terminal = on,
                            "dumpView" => self.views_new.dump = on,
                            "modbusView" => self.views_new.modbus = on,
                            "lineView" => self.views_new.line = on,
                            "autoMon" => self.auto_mon = on,
                            "modbusType" => self.proto_sel = v.parse().unwrap_or(1),
                            // 端口白名单：两个键各管一件事，互不覆盖。
                            // 缺省（历史配置里没有这两项）= 不限制。
                            "portFilter" => self.fport_on = on,
                            "portWatch" => self.fport_sel = parse_port_list(v),
                            "displayEnc" => self.display_enc = DisplayEncoding::from_index(v.parse().unwrap_or(0)),
                            "exportEnc" => self.save_enc = v.parse().unwrap_or(0).min(2),
                            "recentArchive" => {
                                // Paths are tokenised by whitespace in this ini format, so
                                // spaces travel as %20 (see the writer).
                                let p = v.replace("%20", " ");
                                if !p.is_empty() && !self.recent_archives.iter().any(|q| q == &p) {
                                    self.recent_archives.push(p);
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    fn save_cfg(&self) {
        let t = format!(
            "[NewMon]\ntableView={} terminalView={} dumpView={} modbusView={} lineView={} autoMon={} modbusType={} portFilter={} portWatch={} displayEnc={} exportEnc={}\n",
            b(self.views_new.table),
            b(self.views_new.terminal),
            b(self.views_new.dump),
            b(self.views_new.modbus),
            b(self.views_new.line),
            b(self.auto_mon),
            self.proto_sel,
            b(self.fport_on),
            fmt_port_list(&self.fport_sel),
            self.display_enc.as_index(),
            self.save_enc
        );
        let mut t = t;
        for p in self.recent_archives.iter().take(8) {
            // Whitespace-delimited ini: encode spaces so a path with spaces survives.
            t.push_str(&format!("recentArchive={}\n", p.replace(' ', "%20")));
        }
        let _ = std::fs::write("config.ini", t);
    }

    fn sel_fcs(&self) -> Vec<u8> {
        FCS.iter()
            .zip(self.fcs_sel.iter())
            .filter(|(_, on)| **on)
            .map(|(fc, _)| *fc)
            .collect()
    }

    fn new_session(&mut self) {
        let mut chans: Vec<ChannelCfg> = Vec::new();
        let kind = match self.chan_kind {
            // 0 = 串口监听(不占用) — the default and the only mode that never
            // opens the device. 4 = 串口独占 (the monitor itself owns the port).
            1 => ChanKind::TcpClient,
            2 => ChanKind::TcpServer,
            3 => ChanKind::Udp,
            4 => ChanKind::Serial,
            _ => ChanKind::HookSerial,
        };
        if kind == ChanKind::Serial || kind == ChanKind::HookSerial {
            for (i, on) in self.port_sel.iter().enumerate() {
                if *on {
                    // HookSerial: passively watch the named port via injected hooks;
                    // we never open it, so other software can use it freely.
                    chans.push(ChannelCfg {
                        kind: kind.clone(),
                        name: self.ports[i].clone(),
                        baud: BAUDS[self.baud_i],
                        data_bits: if self.data_i == 0 { 7 } else { 8 },
                        parity: self.parity_i as u8,
                        stop_bits: if self.stop_i == 0 { 1 } else { 2 },
                    });
                }
            }
            if kind == ChanKind::HookSerial {
                for c in &mut chans {
                    c.baud = 0;
                }
            }
        } else {
            if self.addr.trim().is_empty() {
                self.toast("请填写地址，如 127.0.0.1:502");
                return;
            }
            chans.push(ChannelCfg {
                kind,
                name: self.addr.trim().to_string(),
                baud: BAUDS[self.baud_i],
                data_bits: 8,
                parity: 0,
                stop_bits: 1,
            });
        }
        if chans.is_empty() {
            self.toast("请至少选择一个通道");
            return;
        }
        let proto = match self.proto_sel {
            1 => ProtoType::Rtu,
            2 => ProtoType::Ascii,
            3 => ProtoType::Tcp,
            _ => ProtoType::None,
        };
        let name = format!("会话{}", self.sessions.len() + 1);
        let views = self.views_new.clone();
        let mut s = Session::new(name, chans, proto, views);
        s.merge_ms = self.p_merge;
        s.string_len = self.p_strlen;
        s.values_dec = self.p_dec;
        s.ascii_escape = self.p_esc;
        s.auto_scroll = self.p_scroll;
        s.display_encoding = self.display_enc;
        s.filters = Filters {
            dir: self.fdir,
            fcs: self.sel_fcs(),
            text: self.ftext.clone(),
            text_on: self.ftext_on,
        };
        // 端口白名单沿用「过滤设置」里上一次应用的选择（持久化在 config.ini）：
        // 用户连续开几个会话时，不必每次都重新勾一遍端口。
        //
        // 但只在**新会话确实包含这些端口**时才继承：否则一个只勾了 COM6 的旧白名单
        // 会让新建的 COM3 会话一条数据都显示不出来，而用户看到的只是一个空窗口。
        // （"取消选择 + 应用"会留下启用但空的白名单，那种配置同样不继承。）
        let inherited_any = s.channels.iter().any(|c| self.fport_sel.contains(&c.name));
        if self.fport_on && inherited_any {
            s.port_watch = self.fport_sel.clone();
            s.port_watch_on = true;
        }
        if self.auto_mon {
            s.running = true;
        }
        if self.r_on {
            let (now, _) = crate::session::now_wall();
            s.autosave = Some(Autosave {
                on: true,
                path: self.r_path.clone(),
                split: self.r_split,
                time_min: self.r_time.max(1),
                size_mb: self.r_size.max(1),
                encoding: self.r_enc,
                written: 0,
                started_at: now,
                cur_file: String::new(),
            });
        }
        if s.channels.iter().any(|c| c.kind == ChanKind::HookSerial) {
            s.notices
                .push("钩子监听会话：本软件不占用串口。请通过 菜单→监控→附加到进程(拦截)… 注入使用该串口的程序，其读写将被拦截显示。".into());
        }
        self.sessions.push(s);
        self.active = self.sessions.len() - 1;
        self.view_sel = 0;
        self.dlg_new = false;
        self.save_cfg();
        self.sync_auto_attach();
        self.toast("会话已创建");
    }

    /// Start capturing through the kernel filter driver, if it is loaded.
    ///
    /// The driver is the reliable capture path: it sits on the device stack, so it sees
    /// every process's traffic from the moment it attaches — no injection race.
    pub fn start_driver_capture(&mut self) -> bool {
        self.stop_driver_capture();
        let Some(h) = crate::driver::DriverHandle::open() else {
            // 失败原因决定用户要做什么：没装 → sc create；577 → testsigning；
            // 5 → 提权。只回一句「未检测到驱动」等于没给答案。
            let err = crate::driver::last_error();
            self.drv_avail = false;
            self.drv_err = err;
            self.drv_checked = true;
            self.drv_probe_at = Some(std::time::Instant::now());
            self.drv_note = crate::driver::open_failure_hint(err);
            return false;
        };
        self.drv_avail = true;
        self.drv_err = 0;
        self.drv_checked = true;
        self.drv_probe_at = Some(std::time::Instant::now());

        let attached = h.attach_ports();
        // 端口名只在这里取一次：设备路径是静态的，没必要每条新记录都回驱动问一遍。
        let ports: Vec<(u32, String)> = h
            .port_names(attached)
            .into_iter()
            .map(|p| (p.index, p.device))
            .collect();
        let target = self.drv_pid.unwrap_or(0);
        h.set_target(target);
        self.drv_names = ports.iter().cloned().collect();
        // Device path -> COM number, so the port list can show both.
        self.drv_com = crate::driver::com_names();
        // 端口过滤的统一规则见 MonitorApp 里 fport_* 字段上的说明：唯一白名单是
        // 「过滤设置 → 监视端口」，按 COM 号匹配，驱动与注入两条路径共用。
        self.set_driver_note_for_ports(attached, &ports);

        // Move the handle into a capture thread and stream records back over a channel.
        // The handle lives in the thread; the UI only keeps the receiving end. (An Arc
        // would require Sync, and DriverHandle is deliberately only Send — the kernel
        // device object serialises its own IOCTLs.)
        let (tx, rx) = std::sync::mpsc::channel();
        let (ctx, crx) = std::sync::mpsc::channel::<DrvCmd>();
        let (etx, erx) = std::sync::mpsc::channel::<DrvEvt>();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop2 = stop.clone();
        self.drv_thread = Some(std::thread::spawn(move || {
            loop {
                // 命令先于取记录处理：set_target 之后紧接着到来的记录才对得上新过滤条件。
                loop {
                    match crx.try_recv() {
                        Ok(DrvCmd::SetTarget(pid)) => {
                            h.set_target(pid);
                            let _ = etx.send(DrvEvt::Target(pid));
                        }
                        Ok(DrvCmd::Rescan) => {
                            let n = h.attach_ports();
                            let names = h
                                .port_names(n)
                                .into_iter()
                                .map(|p| (p.index, p.device))
                                .collect();
                            let _ = etx.send(DrvEvt::Ports(names));
                        }
                        Ok(DrvCmd::Stop) | Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                            return;
                        }
                        Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    }
                }
                if stop2.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                match h.next_record() {
                    Some(rec) => {
                        if tx.send(rec).is_err() {
                            return; // UI dropped the receiver — nobody wants the data
                        }
                    }
                    None => std::thread::sleep(std::time::Duration::from_millis(15)),
                }
            }
        }));
        self.drv = None; // the handle lives in the thread now
        self.drv_rx = Some(rx);
        self.drv_cmd = Some(ctx);
        self.drv_evt = Some(erx);
        self.drv_stop = Some(stop);
        true
    }

    /// Stop the capture thread and forget everything tied to that connection.
    pub fn stop_driver_capture(&mut self) {
        if let Some(tx) = self.drv_cmd.take() {
            let _ = tx.send(DrvCmd::Stop);
        }
        if let Some(stop) = self.drv_stop.take() {
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        // Never join on the UI thread.
        //
        // A join waits for the capture thread to leave next_record(), and that IOCTL can
        // be stuck inside a faulty driver. Joining would then freeze the whole window on
        // a bad driver — precisely the "not responding, cannot even be killed" state seen
        // with the first driver build. Reaping on a helper thread keeps the UI alive no
        // matter what the driver does.
        if let Some(t) = self.drv_thread.take() {
            std::thread::spawn(move || {
                let _ = t.join();
            });
        }
        self.drv_rx = None;
        self.drv_evt = None;
        self.drv_ports.clear();
    }

    /// 驱动端口序号 → 会话通道名（也是「监视端口」白名单里用来比对的那个名字）。
    ///
    /// 优先用 COM 号：用户勾选时看到的是 `COM6`，而驱动报的是 `\Device\VSerial8_2`。
    /// 拿不到 COM 映射时退回设备短名。**建通道和做过滤必须都走这里**，
    /// 否则两边的名字对不上，白名单会静默失效（要么什么都过滤不掉，要么全丢）。
    fn channel_port_name(&self, port_index: u32) -> String {
        let Some(path) = self.drv_names.get(&port_index) else {
            return format!("端口{}", port_index);
        };
        self.drv_com
            .get(path)
            .cloned()
            .unwrap_or_else(|| short_dev(path))
    }

    /// Format the "attached N ports" note shared by start and rescan.
    fn set_driver_note_for_ports(&mut self, attached: u32, ports: &[(u32, String)]) {
        self.drv_note = if attached == 0 || ports.is_empty() {
            "驱动已连接，但没有找到串口设备（检查设备管理器里是否存在 COM 端口）".to_string()
        } else {
            let names: Vec<String> = ports.iter().map(|(_, d)| short_dev(d)).collect();
            format!("驱动已附加 {attached} 个串口: {}", names.join(", "))
        };
    }

    /// 重新扫描端口。捕获中必须走线程命令（设备已被线程独占打开）。
    fn rescan_driver_ports(&mut self) {
        if let Some(tx) = &self.drv_cmd {
            let _ = tx.send(DrvCmd::Rescan);
            return;
        }
        // 未在捕获：可以自己打开设备问一次，问到就关掉。
        if let Some(h) = crate::driver::DriverHandle::open() {
            let n = h.attach_ports();
            let ports: Vec<(u32, String)> = h
                .port_names(n)
                .into_iter()
                .map(|p| (p.index, p.device))
                .collect();
            self.drv_avail = true;
            self.drv_err = 0;
            self.drv_checked = true;
            self.drv_names = ports.iter().cloned().collect();
        // Device path -> COM number, so the port list can show both.
        self.drv_com = crate::driver::com_names();
            self.set_driver_note_for_ports(n, &ports);
            self.toast(self.drv_note.clone());
        } else {
            let err = crate::driver::last_error();
            self.drv_avail = false;
            self.drv_err = err;
            self.drv_checked = true;
            self.drv_note = crate::driver::open_failure_hint(err);
            self.toast("驱动不可用，无法扫描端口");
        }
    }

    /// 探测驱动是否可用。
    ///
    /// CreateFileW 对控制设备来说不算便宜（驱动不响应时要等 SCM 超时），所以结果缓存
    /// 一段时间；`force` 用于用户主动点击「重新检测」的场景。
    fn probe_driver_availability(&mut self, force: bool) {
        const TTL: std::time::Duration = std::time::Duration::from_secs(3);
        if !force {
            if let Some(at) = self.drv_probe_at {
                if at.elapsed() < TTL {
                    return;
                }
            }
        }
        self.drv_probe_at = Some(std::time::Instant::now());
        // 已经在捕获时不要另开句柄——设备被线程独占，这里必然失败，
        // 复用已知状态即可。
        if self.drv_rx.is_some() {
            self.drv_avail = true;
            self.drv_checked = true;
            return;
        }
        self.drv_avail = crate::driver::DriverHandle::is_available();
        self.drv_err = if self.drv_avail { 0 } else { crate::driver::last_error() };
        self.drv_checked = true;
    }

    /// Drain driver records into the active session, creating a channel per port.
    fn drain_driver(&mut self) {
        // 先把捕获线程的事件收掉（端口表 / 目标 PID），它们决定了下面查表的内容。
        // 事件先收集到 Vec 里再处理：Receiver 借用了 self，直接在处理时改 self 会冲突。
        let mut evts: Vec<DrvEvt> = Vec::new();
        if let Some(evt) = &self.drv_evt {
            while let Ok(e) = evt.try_recv() {
                evts.push(e);
            }
        }
        for e in evts {
            match e {
                DrvEvt::Ports(list) => {
                    let n = list.len() as u32;
                    self.drv_names = list.iter().cloned().collect();
                    // 端口表变了，设备路径 → COM 号的映射必须一起刷新。
                    //
                    // 不刷新的话，捕获中新插入的端口在 drv_com 里查不到，channel_port_name
                    // 会退回设备短名（VSerial8_3 而不是 COM7）：通道建起来的名字和白名单里
                    // 用户勾的 COM7 对不上，port_allowed 静默返回 false，那个端口一个字都
                    // 不会显示，而「监视端口」列表里还多出一个没人认得的 VSerial8_3。
                    self.drv_com = crate::driver::com_names();
                    self.set_driver_note_for_ports(n, &list);
                    self.toast(self.drv_note.clone());
                }
                DrvEvt::Target(pid) => {
                    self.drv_pid = if pid == 0 { None } else { Some(pid) };
                    self.toast(if pid == 0 {
                        "驱动捕获目标: 所有进程".to_string()
                    } else {
                        format!("驱动捕获目标: PID {pid}")
                    });
                }
            }
        }
        let Some(rx) = &self.drv_rx else { return };
        let mut batch: Vec<crate::driver::Record> = Vec::new();
        while let Ok(rec) = rx.try_recv() {
            batch.push(rec);
            if batch.len() >= 256 {
                break; // keep the UI responsive under heavy traffic
            }
        }
        if batch.is_empty() {
            return;
        }
        // Which session receives driver data? The active passive-monitor session, or a
        // dedicated one created on first record.
        if self.sessions.is_empty() {
            // A session created purely by driver capture is raw serial traffic, not a
            // Modbus/TCP conversation — leaving the protocol at its default made the parser
            // label arbitrary bytes with a meaningless function code.
            let s = Session::new(
                "驱动捕获".into(),
                Vec::new(),
                ProtoType::None,
                ViewToggles { table: true, terminal: true, dump: true, line: true, modbus: false },
            );
            self.sessions.push(s);
            self.active = 0;
        }
        let sess_idx = self.active.min(self.sessions.len() - 1);
        for rec in batch {
            // 端口过滤：唯一来源是「过滤设置 → 监视端口」（`Session::port_watch`）。
            //
            // 驱动按设计挂接全部串口并上报一切（与参考产品一致，也让用户不必重新挂接
            // 就能切端口），所以"只看我关心的端口"必须由这一侧完成。注入路径在
            // route_hook_data 里用同一份白名单筛选，两条路径行为一致。
            //
            // 名字必须取自 channel_port_name：它和建通道用的是同一个函数，都优先返回
            // COM 号（用户认得的那个）。两处名字不一致会让白名单静默失效。
            let chan_port = self.channel_port_name(rec.port_index);
            // 白名单判断放在**建通道之后**（下面 ingest 之前）：被过滤的端口仍然会建
            // 通道，因此它还留在「监视端口」列表里，用户随时能勾回来 —— 否则就是单向门。
            let key = (sess_idx, rec.port_index);
            let chan = match self.drv_ports.get(&key) {
                Some(&c) => c,
                None => {
                    // 名字来自 start_driver_capture 一次性取好的表。以前这里每遇到一个
                    // 新端口就要重新查询整张端口表（O(N) 次 IOCTL），在 8 口以上、
                    // 每帧都有新端口时会把 UI 线程拖住；而端口名在驱动的生命周期内
                    // 不会变，查一次就够。
                    let name = chan_port.clone();
                    let s = &mut self.sessions[sess_idx];
                    // 会话里可能已经有同名的「串口监听」通道（新建会话时勾的端口）。
                    // 复用它而不是再建一条：否则同一个 COM6 会出现两个通道，
                    // 用户看到的通道列和「监视端口」列表都会变得难以对应。
                    let idx = match s
                        .channels
                        .iter()
                        .position(|c| c.kind == ChanKind::HookSerial && c.name == name)
                    {
                        Some(i) => i,
                        None => {
                            let i = s.channels.len();
                            s.channels.push(ChannelCfg {
                                kind: ChanKind::HookSerial,
                                name: name.clone(),
                                baud: 0,
                                data_bits: 8,
                                parity: 0,
                                stop_bits: 1,
                            });
                            s.notices.push(format!("驱动捕获端口: {name}"));
                            i
                        }
                    };
                    self.drv_ports.insert(key, idx);
                    // 驱动自己在记录里带有句柄，但通道是按端口聚合的：同一端口上不同
                    // 进程的读写都进这一路，和「串口监听」会话的行为保持一致。
                    let _ = rec.handle;
                    idx
                }
            };
            // 白名单在这里生效：通道已经建好（所以端口会出现在「监视端口」列表里，
            // 用户可以随时勾回来），但不在白名单上的端口，字节根本不进 rows。
            if !self.sessions[sess_idx].port_allowed(&chan_port) {
                continue;
            }
            // 暂停门禁：驱动链路同样必须尊重 `running`，否则「暂停监控」只对界面
            // 生效、数据继续入库并推高 Bytes（见 route_hook_data 的同类说明）。
            if !self.sessions[sess_idx].running {
                continue;
            }
            // The driver now reports Unix milliseconds, which is exactly what fmt_time
            // expects. (An earlier build passed raw FILETIME through here and every row
            // showed 1970-01-01.)
            let secs = rec.timestamp / 1000;
            let millis = (rec.timestamp % 1000) as u32;
            // Read the direction before moving `data` out of `rec`.
            let dir_tx = rec.kind == crate::driver::RecordKind::Tx;
            let control = rec.control;
            self.sessions[sess_idx].ingest_driver(
                chan,
                rec.data,
                secs,
                millis,
                dir_tx,
                control,
            );
        }
    }

    /// Point the auto-attach service at the ports of every passive (串口监听)
    /// channel. Called whenever sessions change.
    fn sync_auto_attach(&mut self) {
        let ports: Vec<String> = self
            .sessions
            .iter()
            .flat_map(|s| s.channels.iter())
            .filter(|c| c.kind == ChanKind::HookSerial)
            .map(|c| c.name.clone())
            .collect();
        match &self.auto {
            Some(a) => a.set_ports(ports),
            None => {
                if !ports.is_empty() {
                    self.auto = Some(crate::autoattach::AutoAttach::start(ports));
                }
            }
        }
    }

    fn close_active(&mut self) {
        let closed_name = self.sessions.get(self.active).map(|s| s.name.clone());
        let had_hook = self.sessions.get(self.active).map_or(false, |s| {
            s.cap_pid.is_some() || s.channels.iter().any(|c| c.kind == ChanKind::HookSerial)
        });
        if let Some(s) = self.sessions.get(self.active) {
            s.stop_all();
        }
        if self.active < self.sessions.len() {
            self.sessions.remove(self.active);
        }
        if self.active >= self.sessions.len() {
            self.active = self.sessions.len().saturating_sub(1);
        }
        self.view_sel = 0;
        // Closing a session never stopped the application-level capture paths. Say so
        // instead of leaving the user to wonder why data keeps arriving (and why a
        // driver session can reappear on its own).
        if had_hook {
            self.toast(format!(
                "已关闭{}。注意：{}仍在后台运行，新数据可能自动建会话；需要完全停止请用「监控→停止驱动捕获」",
                closed_name.unwrap_or_else(|| "会话".into()),
                if self.drv_rx.is_some() { "驱动捕获" } else { "进程拦截" }
            ));
        }
    }

    /// Export the active session's rows.
    ///
    /// File encoding = the user's export choice; text column = the session's display
    /// encoding, so exported Chinese is readable. Auto-named to avoid silently
    /// overwriting an earlier export (the old fixed `session_N.log` did).
    fn save_active(&mut self) {
        let Some(s) = self.sessions.get(self.active) else { return };
        let enc = DisplayEncoding::from_index(self.save_enc);
        let (secs, _) = now_wall();
        let safe_name = s
            .name
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect::<String>();
        let path = format!("session_{}_{secs}.log", safe_name);
        match s.save_log(&path, enc) {
            Ok(()) => self.toast(format!(
                "已导出 {}（文件编码 {}，文本按 {} 解码）",
                path,
                enc.label(),
                s.display_encoding.label()
            )),
            Err(e) => self.toast(format!("保存失败: {}", e)),
        }
    }

    /// Load the active session's display/auto-save settings into the dialog drafts.
    ///
    /// The dialogs used to open showing `MonitorApp`'s global defaults instead of the
    /// values actually in effect, so editing one field silently reset the others to the
    /// defaults. Cancelling also left the edits in place. Both are fixed by these two
    /// sync functions plus the `*_backup` restore on 取消.
    fn sync_prefs_from_session(&mut self) {
        if let Some(s) = self.sessions.get(self.active) {
            self.p_merge = s.merge_ms;
            self.p_strlen = s.string_len;
            self.p_dec = s.values_dec;
            self.p_esc = s.ascii_escape;
            self.p_scroll = s.auto_scroll;
        }
        self.prefs_backup = Some((self.p_merge, self.p_strlen, self.p_dec, self.p_esc, self.p_scroll));
    }

    fn sync_redir_from_session(&mut self) {
        if let Some(s) = self.sessions.get(self.active) {
            if let Some(a) = &s.autosave {
                self.r_on = a.on;
                self.r_path = a.path.clone();
                self.r_split = a.split;
                self.r_time = a.time_min;
                self.r_size = a.size_mb;
                self.r_enc = a.encoding;
            }
        }
        self.redir_backup = Some((
            self.r_on,
            self.r_path.clone(),
            self.r_split,
            self.r_time,
            self.r_size,
            self.r_enc,
        ));
    }

    fn restore_prefs(&mut self) {
        if let Some((m, l, d, e, s)) = self.prefs_backup.take() {
            self.p_merge = m;
            self.p_strlen = l;
            self.p_dec = d;
            self.p_esc = e;
            self.p_scroll = s;
        }
    }

    fn restore_redir(&mut self) {
        if let Some((on, path, split, t, sz, enc)) = self.redir_backup.take() {
            self.r_on = on;
            self.r_path = path;
            self.r_split = split;
            self.r_time = t;
            self.r_size = sz;
            self.r_enc = enc;
        }
    }

    /// Save the active session as a reopenable archive.
    fn save_archive_active(&mut self) {
        let Some(s) = self.sessions.get(self.active) else { return };
        let (secs, _) = now_wall();
        let safe: String = s
            .name
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect();
        let path = format!("session_{safe}_{secs}.umses");
        match s.save_archive(&path) {
            Ok(()) => {
                self.push_recent_archive(&path);
                self.toast(format!("会话已保存：{path}（可用「打开会话」回看）"));
            }
            Err(e) => self.toast(format!("保存会话失败: {e}")),
        }
    }

    fn push_recent_archive(&mut self, path: &str) {
        self.recent_archives.retain(|p| p != path);
        self.recent_archives.insert(0, path.to_string());
        self.recent_archives.truncate(8);
    }

    /// Open an archive. Without a native file dialog in the dependency set, the most
    /// recently saved/opened files are offered directly — which is also the fastest path
    /// for the common "save, then look at it again" workflow.
    fn open_archive_recent(&mut self) {
        if self.recent_archives.is_empty() {
            self.toast("还没有可打开的会话文件：请先「保存会话」");
            return;
        }
        let path = self.recent_archives[0].clone();
        match Session::load_archive(&path) {
            Ok(s) => {
                self.sessions.push(s);
                self.active = self.sessions.len() - 1;
                self.view_sel = 0;
                self.push_recent_archive(&path);
                self.toast(format!("已打开 {path}（只读回看，未占用任何端口）"));
            }
            Err(e) => {
                self.recent_archives.retain(|p| p != &path);
                self.toast(format!("打开失败: {e}"));
            }
        }
    }

    /// Restart a search from the first row (the 「查找」 button).
    fn find_reset(&mut self) {
        if let Some(s) = self.sessions.get_mut(self.active) {
            s.find_pos = 0;
        }
        self.find_note.clear();
    }

    fn find_next(&mut self) {
        let t = self.find_text.trim().to_lowercase();
        if t.is_empty() {
            self.find_note = "请输入查找内容".into();
            return;
        }
        let Some(s) = self.sessions.get_mut(self.active) else { return };
        let enc = s.display_encoding;
        let n = s.rows.len();
        let mut hit = None;
        for k in 0..=n {
            let i = (s.find_pos + k) % (n + 1);
            if i >= n {
                continue;
            }
            let r = &s.rows[i];
            let hex = bytes_hex(&r.data).to_lowercase();
            // Search the *decoded* text, so a query typed as Chinese matches GBK/UTF-16
            // payloads exactly as they are displayed.
            let txt = text_codec::decoded_text(&r.data, enc).to_lowercase();
            if hex.contains(&t) || txt.contains(&t) {
                hit = Some(i);
                break;
            }
        }
        let total = s
            .rows
            .iter()
            .filter(|r| {
                bytes_hex(&r.data).to_lowercase().contains(&t)
                    || text_codec::decoded_text(&r.data, enc).to_lowercase().contains(&t)
            })
            .count();
        match hit {
            Some(i) => {
                s.selected = Some(i);
                s.find_pos = i + 1;
                let ordinal = s.rows[..=i.min(s.rows.len().saturating_sub(1))]
                    .iter()
                    .filter(|r| {
                        bytes_hex(&r.data).to_lowercase().contains(&t)
                            || text_codec::decoded_text(&r.data, enc).to_lowercase().contains(&t)
                    })
                    .count();
                self.scroll_to_row = Some(i);
                self.find_note = format!("命中 {ordinal}/{total}（行 #{i}）");
            }
            None => {
                self.find_note = format!("未找到（共 {total} 处匹配，已到末尾）");
            }
        }
    }

    fn copy_selected(&mut self, ctx: &Context) {
        let Some(s) = self.sessions.get(self.active) else { return };
        let Some(si) = s.selected else { return };
        let Some(r) = s.rows.get(si) else { return };
        let mut line = format!(
            "#{}\t{}\t{}\t{}",
            r.seq,
            fmt_time(r.secs, r.millis),
            &chan_label(s, r.idx),
            if r.dir_tx { "写" } else { "读" }
        );
        if let Some(p) = &r.parsed {
            line += &format!(
                "\tID={} FC=0x{:02X} ADDR={} QTY={}",
                p.id,
                p.function,
                p.address.map(|a| a.to_string()).unwrap_or_else(|| "-".into()),
                p.quantity.map(|a| a.to_string()).unwrap_or_else(|| "-".into())
            );
        }
        line += &format!("\t{}", bytes_hex(&r.data));
        // Include the decoded text so copying a GBK / UTF-16 frame yields something the
        // user can paste into a document, not just hex.
        let txt = text_codec::decoded_text(&r.data, s.display_encoding);
        if !txt.is_empty() {
            line += &format!("\t{}", txt.replace(['\r', '\n', '\t'], " "));
        }
        ctx.copy_text(line);
        self.toast("已复制（含解码文本）");
    }

    fn top_panel(&mut self, ctx: &Context) {
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let has = !self.sessions.is_empty();
                ui.menu_button("文件", |ui| {
                    if ui.button("新建监控会话…").clicked() {
                        self.dlg_new = true;
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.add_enabled(has, egui::Button::new("保存会话（.umses，可重新打开）")).clicked() {
                        self.save_archive_active();
                        ui.close_menu();
                    }
                    if ui.button("打开会话（.umses）…").clicked() {
                        self.open_archive_recent();
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.add_enabled(has, egui::Button::new("导出日志（文本/HEX）")).clicked() {
                        self.save_active();
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("退出").clicked() {
                        ui.close_menu();
                        // 有正在采集的会话时提醒一次：退出不会自动保存，数据会丢。
                        if has {
                            self.dlg_confirm_exit = true;
                        } else {
                            std::process::exit(0);
                        }
                    }
                });
                ui.menu_button("监控", |ui| {
                    if ui.add_enabled(has, egui::Button::new("开启监控")).clicked() {
                        if let Some(s) = self.sessions.get_mut(self.active) {
                            s.running = true;
                        }
                        ui.close_menu();
                    }
                    if ui.add_enabled(has, egui::Button::new("暂停监控")).clicked() {
                        if let Some(s) = self.sessions.get_mut(self.active) {
                            s.running = false;
                        }
                        ui.close_menu();
                    }
                    if ui.add_enabled(has, egui::Button::new("关闭会话")).clicked() {
                        self.close_active();
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("过滤设置…").clicked() {
                        self.dlg_filter = true;
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("附加到进程(拦截)…").clicked() {
                        self.procs = inject::list_processes();
                        self.attach_sel = None;
                        self.dlg_attach = true;
                        ui.close_menu();
                    }
                    ui.separator();
                    // Kernel-driver capture: the reliable path — no injection race, and
                    // it sees every process from the moment it attaches.
                    if self.drv_rx.is_some() {
                        if ui.button("停止驱动捕获").clicked() {
                            self.stop_driver_capture();
                            self.drv_note = "驱动捕获已停止".into();
                            self.toast("已停止驱动捕获");
                        ui.close_menu();
                        }
                        ui.label("  驱动捕获运行中");
                    } else if ui.button("启用驱动捕获(推荐)").clicked() {
                        if self.start_driver_capture() {
                            self.toast("驱动捕获已启动");
                        } else {
                            // 失败时把完整指引塞进对话框，状态栏只放一句摘要。
                            self.dlg_drv = true;
                            self.toast("驱动不可用，已打开设置对话框查看原因");
                        ui.close_menu();
                        }
                    }
                    if ui.button("驱动捕获设置…").clicked() {
                        self.dlg_drv = true;
                        self.probe_driver_availability(true);
                        ui.close_menu();
                    }
                });
                ui.menu_button("编辑", |ui| {
                    if ui.add_enabled(has, egui::Button::new("复制")).clicked() {
                        self.copy_selected(ctx);
                        ui.close_menu();
                    }
                    if ui.button("查找…").clicked() {
                        self.dlg_find = true;
                        ui.close_menu();
                    }
                    if ui.add_enabled(has, egui::Button::new("查找下一个")).clicked() {
                        self.find_next();
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.add_enabled(has, egui::Button::new("清空数据")).clicked() {
                        if let Some(s) = self.sessions.get_mut(self.active) {
                            s.clear();
                        }
                        ui.close_menu();
                    }
                });
                ui.menu_button("设置", |ui| {
                    if ui.button("自动保存日志设置…").clicked() {
                        self.sync_redir_from_session();
                        self.dlg_redir = true;
                        ui.close_menu();
                    }
                    if ui.button("显示设置…").clicked() {
                        self.sync_prefs_from_session();
                        self.dlg_prefs = true;
                        ui.close_menu();
                    }
                    ui.separator();
                    ui.menu_button("显示编码（决定监控内容如何解码）", |ui| {
                        ui.label(RichText::new("作用于全部视图 / 查找 / 过滤 / 复制 / 导出文本").weak().small());
                        for e in DisplayEncoding::ALL {
                            let r = ui.radio(self.display_enc == e, e.label());
                            if r.clicked() {
                                self.set_display_encoding(e);
                                ui.close_menu();
                            }
                            r.on_hover_text(e.hint());
                        }
                        ui.separator();
                        ui.menu_button("导出文件编码（仅决定日志文件的字节格式）", |ui| {
                            for (i, name) in ENCS.iter().enumerate() {
                                if ui.radio(self.save_enc == i, *name).clicked() {
                                    self.save_enc = i;
                                    self.save_cfg();
                                    ui.close_menu();
                                }
                            }
                        });
                    });
                });
                ui.menu_button("视图", |ui| {
                    if !has {
                        ui.label(RichText::new("先新建一个会话").weak());
                    } else {
                        // View visibility used to be settable only at creation time, so a
                        // session created without the Modbus view could never show it.
                        ui.label(RichText::new("显示/隐藏视图（对当前会话即时生效）").weak().small());
                        let s = &mut self.sessions[self.active];
                        let mut changed = false;
                        changed |= ui.checkbox(&mut s.views.table, "Table 视图").changed();
                        changed |= ui.checkbox(&mut s.views.terminal, "终端视图").changed();
                        changed |= ui.checkbox(&mut s.views.dump, "Dump 视图").changed();
                        changed |= ui.checkbox(&mut s.views.line, "Line 曲线图").changed();
                        changed |= ui.checkbox(&mut s.views.modbus, "Modbus 视图").changed();
                        if changed {
                            // Keep the tab selection valid after a view disappears.
                            let enabled = self.enabled_views();
                            if !enabled.contains(&self.view_sel) {
                                self.view_sel = *enabled.first().unwrap_or(&0);
                            }
                        }
                        ui.separator();
                        if ui.button("全部显示").clicked() {
                            if let Some(s) = self.sessions.get_mut(self.active) {
                                s.views = ViewToggles {
                                    table: true,
                                    terminal: true,
                                    dump: true,
                                    line: true,
                                    modbus: true,
                                };
                            }
                        }
                    }
                });
                ui.menu_button("帮助", |ui| {
                    if ui.button("关于…").clicked() {
                        self.dlg_about = true;
                        ui.close_menu();
                    }
                });
                // session tabs
                ui.separator();
                let mut click_close = None;
                let mut click_tab = None;
                for (i, s) in self.sessions.iter().enumerate() {
                    let label = if i == self.active {
                        RichText::new(s.name.clone()).strong()
                    } else {
                        RichText::new(s.name.clone())
                    };
                    if ui.add(SelectableLabel::new(i == self.active, label)).clicked() {
                        click_tab = Some(i);
                    }
                    if ui.small_button("×").clicked() {
                        click_close = Some(i);
                    }
                    ui.separator();
                }
                if ui.button("＋ 新建").clicked() {
                    self.dlg_new = true;
                        ui.close_menu();
                }
                if let Some(i) = click_tab {
                    self.active = i;
                }
                if let Some(i) = click_close {
                    self.active = i;
                    self.close_active();
                }
            });
        });
    }

    fn status_bar(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.label(format!("会话 {}", self.sessions.len()));
            ui.separator();
            if let Some(s) = self.sessions.get(self.active) {
                ui.label(format!("通道 {}", s.channels.len()));
                ui.separator();
                let (tot_rx, tot_tx) = s.totals();
                ui.label(format!("Bytes: ↑{} ↓{}", tot_tx, tot_rx));
                ui.separator();
                // Live throughput: the Line view was the only place claiming "B/s" and it
                // plotted a frame count, so the status bar had no rate at all.
                let (cur_rx, cur_tx) = s.current_rate();
                let (pk_rx, pk_tx) = s.peak_rate();
                ui.label(
                    RichText::new(format!("速率 ↑{cur_tx}B/s ↓{cur_rx}B/s"))
                        .color(C_TX)
                        .strong(),
                )
                .on_hover_text(format!("峰值 ↑{pk_tx}B/s ↓{pk_rx}B/s（最近 10 分钟）"));
                ui.separator();
                ui.label(format!("行数 {}", s.visible_count()));
                ui.separator();
                let st = if s.running {
                    RichText::new("监控中").color(C_RX).strong()
                } else {
                    RichText::new("已暂停").color(Color32::GRAY)
                };
                ui.label(st);
                ui.separator();
                ui.label(format!("协议 {}", s.proto.label()));
                ui.separator();
                // Always show which encoding the payloads are rendered with: the old UI
                // had no indication at all, which is why switching 编码方式 looked broken.
                ui.label(RichText::new(format!("编码 {}", s.display_encoding.label())).weak())
                    .on_hover_text(s.display_encoding.hint());
                if let Some(n) = s.notices.last() {
                    ui.separator();
                    ui.label(RichText::new(n).small().color(Color32::GRAY));
                }
            } else {
                ui.label("无活动会话");
            }
            if self.frame_count < self.toast_until && !self.toast_msg.is_empty() {
                ui.separator();
                ui.label(RichText::new(&self.toast_msg).color(C_REQ));
            }
            // Driver state decides whether capture works without attaching to anything,
            // so it belongs in the always-visible status bar.
            ui.separator();
            if self.drv_rx.is_some() {
                // 端口数用已建立的通道数而不是端口表长度：用户关心的是「能看到几个端口的
                // 数据」，表里可能包含还没有任何流量的端口。
                let n = self.drv_ports.len().max(self.drv_names.len());
                ui.label(
                    RichText::new(format!("驱动：捕获中（{n} 个端口）"))
                        .color(C_RX)
                        .strong(),
                );
            } else if !self.drv_checked {
                ui.label(RichText::new("驱动：未启用").color(Color32::GRAY));
            } else if self.drv_avail {
                ui.label(RichText::new("驱动：未启用").color(C_REQ));
            } else {
                // 红色 + 明确指路：驱动没加载时，菜单里的「启用驱动捕获」是唯一的下一步。
                ui.label(RichText::new("驱动：未安装").color(C_FAIL).strong());
                ui.label(
                    RichText::new("（菜单 监控 → 启用驱动捕获，或看「驱动捕获设置…」）")
                        .small()
                        .color(Color32::GRAY),
                );
            }
        });
    }

    fn kind_color(kind: crate::protocol::FrameKind) -> Color32 {
        match kind {
            crate::protocol::FrameKind::Req => C_REQ,
            crate::protocol::FrameKind::Resp => C_RESP,
            crate::protocol::FrameKind::Except => C_EXC,
            crate::protocol::FrameKind::Failed => C_FAIL,
            crate::protocol::FrameKind::Raw => Color32::LIGHT_GRAY,
        }
    }

    fn enabled_views(&self) -> Vec<usize> {
        let Some(s) = self.sessions.get(self.active) else { return vec![0] };
        let v = &s.views;
        (0..5)
            .filter(|i| match i {
                0 => v.table,
                1 => v.terminal,
                2 => v.dump,
                3 => v.line,
                _ => v.modbus,
            })
            .collect()
    }

    fn main_area(&mut self, ui: &mut Ui) {
        if self.sessions.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(ui.available_height() / 3.0);
                ui.heading("万能串口监控");
                ui.label("串口 / TCP / UDP / Modbus 通信监控 · 协议解析 · 预设库");
                ui.add_space(12.0);
                if ui.button(RichText::new("新建监控会话…").size(18.0)).clicked() {
                    self.dlg_new = true;
                        ui.close_menu();
                }
            });
            return;
        }
        // view tab strip
        let enabled = self.enabled_views();
        if !enabled.contains(&self.view_sel) {
            self.view_sel = *enabled.first().unwrap_or(&0);
        }
        ui.horizontal(|ui| {
            for i in &enabled {
                let label = if self.view_sel == *i {
                    RichText::new(VIEW_NAMES[*i]).strong()
                } else {
                    RichText::new(VIEW_NAMES[*i])
                };
                if ui.add(SelectableLabel::new(self.view_sel == *i, label)).clicked() {
                    self.view_sel = *i;
                }
                ui.separator();
            }
            if let Some(s) = self.sessions.get(self.active) {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new(&s.name).weak());
                    ui.label(if s.running { "●" } else { "○" });
                });
            }
        });
        ui.separator();
        match self.view_sel {
            0 => self.view_table(ui),
            1 => self.view_terminal(ui),
            2 => self.view_dump(ui),
            3 => self.view_line(ui),
            _ => self.view_modbus(ui),
        }
    }

    fn view_table(&mut self, ui: &mut Ui) {
        let Some(s) = self.sessions.get_mut(self.active) else { return };
        let enc = s.display_encoding;
        let vis: Vec<usize> = s
            .rows
            .iter()
            .enumerate()
            .filter(|(_, r)| s.filters.pass(r, enc))
            .map(|(i, _)| i)
            .collect();
        let start = vis.len().saturating_sub(20000);
        let mut clicked: Option<usize> = None;
        // Scroll to a search hit. The row index is a `rows` index, so translate it into
        // a position within the visible window; hits outside the window cannot be shown
        // (the table intentionally renders only the tail), so widen by reporting it.
        let scroll_idx = self.scroll_to_row.take().and_then(|ri| {
            vis.iter()
                .enumerate()
                .skip(start)
                .find(|(_, &v)| v == ri)
                .map(|(pos, _)| pos)
        });
        let mut tb = TableBuilder::new(ui)
            .striped(true)
            .vscroll(true)
            .stick_to_bottom(s.auto_scroll && scroll_idx.is_none());
        if let Some(pos) = scroll_idx {
            tb = tb.scroll_to_row(pos, Some(egui::Align::Center));
        }
        tb.column(Column::initial(52.0).at_least(36.0))
            .column(Column::initial(150.0).at_least(110.0))
            .column(Column::initial(72.0).at_least(52.0))
            .column(Column::initial(44.0).at_least(36.0))
            .column(Column::initial(150.0).at_least(110.0))
            .column(Column::initial(44.0).at_least(36.0))
            .column(Column::initial(380.0).at_least(120.0))
            .column(Column::remainder().at_least(80.0))
            .header(20.0, |mut h| {
                for t in ["序号", "时间", "通道", "方向", "功能", "长度", "Hex数据", "数据"] {
                    h.col(|ui| {
                        ui.strong(t);
                    });
                }
            })
            .body(|mut body| {
                for &ri in &vis[start..] {
                    let r = &s.rows[ri];
                    body.row(20.0, |mut row| {
                        row.col(|ui| {
                            let label = RichText::new(format!("{}", r.seq));
                            if ui
                                .add(SelectableLabel::new(s.selected == Some(ri), label))
                                .clicked()
                            {
                                clicked = Some(ri);
                            }
                        });
                        row.col(|ui| {
                            ui.monospace(fmt_time(r.secs, r.millis));
                        });
                        row.col(|ui| {
                            ui.label(chan_label(s, r.idx));
                        });
                        row.col(|ui| {
                            let (t, c) = if r.dir_tx { ("写", C_TX) } else { ("读", C_RX) };
                            ui.colored_label(c, t);
                        });
                        row.col(|ui| {
                            // For driver-captured serial traffic the "function" column is
                            // not a Modbus function code: the session protocol may still be
                            // set to Modbus RTU, in which case the parser reports function
                            // 00/"Unknown" for what is really just bytes. Show the actual
                            // meaning — direction and, for control records, the operation.
                            if let Some(ci) = &r.control {
                                ui.label(ci.summary());
                            } else if let Some(p) = &r.parsed {
                                ui.label(format!(
                                    "{:02X} {}",
                                    p.function,
                                    protocol::fc_name(p.function)
                                ));
                            } else if r.origin == RowOrigin::Driver {
                                ui.label(if r.dir_tx { "串口写" } else { "串口读" });
                            } else {
                                ui.label(r.kind.name());
                            }
                        });
                        row.col(|ui| {
                            ui.label(format!("{}", r.data.len()));
                        });
                        row.col(|ui| {
                            // sub_a893e0 long-payload rule: past 0x400 bytes the original
                            // switches decode paths — mirror that as the hex-column cap.
                            const HEX_CAP: usize = 0x400;
                            let shown: String = if r.data.len() > HEX_CAP {
                                format!(
                                    "{} …(+{}B)",
                                    bytes_hex(&r.data[..HEX_CAP]),
                                    r.data.len() - HEX_CAP
                                )
                            } else {
                                bytes_hex(&r.data)
                            };
                            // Colour the payload by direction so reads and writes are
                            // distinguishable at a glance, matching the 读/写 column.
                            // Control records get their own colour instead.
                            let color = if r.control.is_some() {
                                C_REQ
                            } else if r.dir_tx {
                                C_TX
                            } else {
                                C_RX
                            };
                            ui.monospace(RichText::new(shown).color(color));
                        });
                        row.col(|ui| {
                            // Do NOT truncate by a fixed character count. `string_len` is a
                            // display preference from the original UI (16 by default) and
                            // clipping here silently cut most payloads in half —
                            // "Welcome to UartAssist 23" became "Welcome to UartA".
                            // The column scrolls/clips visually if it is too narrow, which
                            // is the right behaviour: the data is still there.
                            let t = escape_text(&r.data, s.ascii_escape, enc);
                            // Same direction colouring as the hex column.
                            let color = if r.control.is_some() {
                                C_REQ
                            } else if r.dir_tx {
                                C_TX
                            } else {
                                C_RX
                            };
                            ui.colored_label(color, t);
                        });
                    });
                }
            });
        if let Some(i) = clicked {
            s.selected = Some(i);
        }
    }

    fn view_terminal(&mut self, ui: &mut Ui) {
        let Some(s) = self.sessions.get_mut(self.active) else { return };
        let enc = s.display_encoding;
        let vis: Vec<usize> = s
            .rows
            .iter()
            .enumerate()
            .filter(|(_, r)| s.filters.pass(r, enc))
            .map(|(i, _)| i)
            .collect();
        let start = vis.len().saturating_sub(3000);
        let esc = s.ascii_escape;
        let auto = s.auto_scroll;
        let mut clicked: Option<usize> = None;
        ScrollArea::vertical().stick_to_bottom(auto).show(ui, |ui| {
            for &ri in &vis[start..] {
                let r = &s.rows[ri];
                let chan = chan_label(s, r.idx);
                let (tag, c) = if r.dir_tx { ("[TX]", C_TX) } else { ("[RX]", C_RX) };
                let line = escape_text(&r.data, esc, enc);
                let resp = ui.horizontal(|ui| {
                    ui.monospace(RichText::new(fmt_time(r.secs, r.millis)).weak().small());
                    ui.monospace(RichText::new(chan.as_str()).weak().small());
                    ui.monospace(RichText::new(tag).color(c).small());
                    ui.monospace(line);
                });
                if resp.response.clicked() {
                    clicked = Some(ri);
                }
            }
        });
        if let Some(i) = clicked {
            s.selected = Some(i);
        }
    }

    fn view_dump(&mut self, ui: &mut Ui) {
        let Some(s) = self.sessions.get_mut(self.active) else { return };
        let enc = s.display_encoding;
        let vis: Vec<usize> = s
            .rows
            .iter()
            .enumerate()
            .filter(|(_, r)| s.filters.pass(r, enc))
            .map(|(i, _)| i)
            .collect();
        let start = vis.len().saturating_sub(1200);
        let mut clicked: Option<usize> = None;
        ScrollArea::vertical().stick_to_bottom(s.auto_scroll).show(ui, |ui| {
            for &ri in &vis[start..] {
                let r = &s.rows[ri];
                let chan = chan_label(s, r.idx);
                let (tag, c) = if r.dir_tx { ("TX", C_TX) } else { ("RX", C_RX) };
                let head = format!(
                    "#{} {} {} {} {}B",
                    r.seq,
                    fmt_time(r.secs, r.millis),
                    chan,
                    tag,
                    r.data.len()
                );
                let hr = ui.horizontal(|ui| {
                    ui.colored_label(c, RichText::new(head).strong().small());
                });
                if hr.response.clicked() {
                    clicked = Some(ri);
                }
                for (off, chunk) in r.data.chunks(16).enumerate() {
                    let mut hex = String::new();
                    let mut asc = String::new();
                    for (j, &b) in chunk.iter().enumerate() {
                        hex += &format!("{:02X} ", b);
                        if j == 7 {
                            hex.push(' ');
                        }
                        asc.push(if (0x20..0x7F).contains(&b) { b as char } else { '.' });
                    }
                    let hr = ui.horizontal(|ui| {
                        ui.monospace(RichText::new(format!("{:04X}  ", off * 16)).weak());
                        ui.monospace(RichText::new(format!("{:<50}", hex.trim_end())).color(c));
                        ui.monospace(asc);
                    });
                    if hr.response.clicked() {
                        clicked = Some(ri);
                    }
                }
                // Hex dump stays byte-for-byte (that is what a dump *is*), but a decoded
                // preview is what makes GBK/UTF-16 payloads readable — the dump view used
                // to be the one place where even the ASCII column was byte-wise.
                let preview = text_codec::decoded_text(&r.data, enc)
                    .replace(['\r', '\n', '\t'], " ");
                if !preview.is_empty() {
                    let shown: String = if preview.chars().count() > 160 {
                        let mut t: String = preview.chars().take(160).collect();
                        t.push('…');
                        t
                    } else {
                        preview
                    };
                    let hr = ui.horizontal(|ui| {
                        ui.monospace(RichText::new("文本  ").weak());
                        ui.monospace(RichText::new(shown).color(c));
                    });
                    if hr.response.clicked() {
                        clicked = Some(ri);
                    }
                }
                ui.separator();
            }
        });
        if let Some(i) = clicked {
            s.selected = Some(i);
        }
    }

    fn view_line(&mut self, ui: &mut Ui) {
        let Some(s) = self.sessions.get(self.active) else { return };
        // Build a continuous per-second series ending at "now": gaps (seconds with no
        // traffic) must show as zero rather than being compressed away, which is what
        // made the old enumerate()-based x axis misleading.
        let now = now_wall().0;
        let window: u64 = 180;
        let first = now.saturating_sub(window);
        let mut rx: Vec<[f64; 2]> = Vec::with_capacity(window as usize + 1);
        let mut tx: Vec<[f64; 2]> = Vec::with_capacity(window as usize + 1);
        let buckets: std::collections::HashMap<u64, (u64, u64)> =
            s.rate.iter().map(|e| (e.0, (e.1, e.2))).collect();
        for sec in first..=now {
            let (r, t) = buckets.get(&sec).copied().unwrap_or((0, 0));
            // x = seconds before now, so the curve scrolls leftwards.
            let x = (sec as f64) - (now as f64);
            rx.push([x, r as f64]);
            tx.push([x, t as f64]);
        }
        let (_, cur_tx) = s.current_rate();
        let (_, pk_tx) = s.peak_rate();
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("当前 ↑{cur_tx} B/s")).color(C_TX).strong());
            ui.label(RichText::new(format!("峰值 ↑{pk_tx} B/s")).weak());
            ui.separator();
            ui.label(RichText::new("每点 = 1 秒内实际字节数，空闲秒补 0").weak().small());
        });
        Plot::new("line_plot")
            .legend(Legend::default())
            .y_axis_label("B/s")
            .x_axis_label("秒(最近 180s，0 = 现在)")
            .include_x(-(window as f64))
            .include_x(0.0)
            .show(ui, |plot| {
                plot.line(Line::new(PlotPoints::from(rx)).name("接收 B/s").color(C_RX));
                plot.line(Line::new(PlotPoints::from(tx)).name("发送 B/s").color(C_TX));
            });
    }

    fn view_modbus(&mut self, ui: &mut Ui) {
        let Some(s) = self.sessions.get_mut(self.active) else { return };
        let enc = s.display_encoding;
        let vis: Vec<usize> = s
            .rows
            .iter()
            .enumerate()
            .filter(|(_, r)| r.parsed.is_some() && s.filters.pass(r, enc))
            .map(|(i, _)| i)
            .collect();
        let dec = s.values_dec;
        let mut clicked: Option<usize> = None;
        // The Modbus table only ever shows parsed frames, so with "无(原始数据)" or a
        // driver-captured session it used to be a permanently blank panel with no
        // explanation. Say why instead of showing an empty grid.
        if vis.is_empty() {
            ui.add_space(24.0);
            ui.vertical_centered(|ui| {
                ui.label(RichText::new("没有可解析的 Modbus 帧").strong());
                ui.add_space(6.0);
                ui.label(
                    RichText::new(
                        "本视图只显示能被解析的 Modbus 帧。若会话协议是「无(原始数据)」，\
                         或数据来自驱动/串口原始抓包，请把协议改为 Modbus RTU / ASCII / TCP。",
                    )
                    .weak()
                    .small(),
                );
            });
            return;
        }
        TableBuilder::new(ui)
            .striped(true)
            .vscroll(true)
            .stick_to_bottom(s.auto_scroll)
            .column(Column::initial(52.0).at_least(36.0))
            .column(Column::initial(36.0).at_least(30.0))
            .column(Column::initial(44.0).at_least(36.0))
            .column(Column::initial(64.0).at_least(46.0))
            .column(Column::initial(64.0).at_least(46.0))
            .column(Column::remainder().at_least(100.0))
            .column(Column::initial(56.0).at_least(46.0))
            .column(Column::initial(56.0).at_least(40.0))
            .column(Column::initial(150.0).at_least(110.0))
            .column(Column::initial(170.0).at_least(90.0))
            .header(20.0, |mut h| {
                for t in ["序号", "ID", "Function", "Address", "Quantity", "Values", "CheckSum", "COM", "Time", "Remark"] {
                    h.col(|ui| {
                        ui.strong(t);
                    });
                }
            })
            .body(|mut body| {
                for &ri in &vis {
                    let r = &s.rows[ri];
                    let Some(p) = &r.parsed else { continue };
                    let col = Self::kind_color(p.kind);
                    body.row(20.0, |mut row| {
                        row.col(|ui| {
                            let label = RichText::new(format!("{}", r.seq)).color(col);
                            if ui.add(SelectableLabel::new(s.selected == Some(ri), label)).clicked() {
                                clicked = Some(ri);
                            }
                        });
                        row.col(|ui| {
                            ui.monospace(RichText::new(format!("{:02X}", p.id)).color(col));
                        });
                        row.col(|ui| {
                            ui.monospace(RichText::new(format!("{:02X}", p.function)).color(col));
                        });
                        row.col(|ui| {
                            ui.monospace(
                                p.address.map(|a| a.to_string()).unwrap_or_else(|| "-".into()),
                            );
                        });
                        row.col(|ui| {
                            ui.monospace(
                                p.quantity.map(|a| a.to_string()).unwrap_or_else(|| "-".into()),
                            );
                        });
                        row.col(|ui| {
                            let v = match &p.values {
                                None => "-".to_string(),
                                Some(vs) if vs.is_empty() => "-".to_string(),
                                Some(vs) => {
                                    if dec {
                                        vs.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(" ")
                                    } else {
                                        vs.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")
                                    }
                                }
                            };
                            let mut shown = v;
                            if shown.chars().count() > s.string_len.max(8) * 3 {
                                shown = shown.chars().take(s.string_len.max(8) * 3).collect::<String>() + "…";
                            }
                            ui.monospace(shown);
                        });
                        row.col(|ui| {
                            let mark = match p.checksum_ok {
                                Some(true) => RichText::new(format!("{} ✓", p.checksum)).color(C_RESP),
                                Some(false) => RichText::new(format!("{} ✗", p.checksum)).color(C_FAIL),
                                None => RichText::new(p.checksum.clone()).weak(),
                            };
                            ui.monospace(mark);
                        });
                        row.col(|ui| {
                            ui.label(chan_label(s, r.idx));
                        });
                        row.col(|ui| {
                            ui.monospace(fmt_time(r.secs, r.millis));
                        });
                        row.col(|ui| {
                            ui.label(RichText::new(&p.remark).color(col));
                        });
                    });
                }
            });
        if let Some(i) = clicked {
            s.selected = Some(i);
        }
    }

    fn send_pane(&mut self, ui: &mut Ui) {
        let Some(s) = self.sessions.get_mut(self.active) else {
            ui.label("无会话");
            return;
        };
        // detail of selected row
        if let Some(si) = s.selected {
            if let Some(r) = s.rows.get(si) {
                let chan = chan_label(s, r.idx);
                ui.horizontal_wrapped(|ui| {
                    ui.monospace(RichText::new(format!("#{} ", r.seq)).strong());
                    ui.monospace(fmt_time(r.secs, r.millis));
                    ui.label(chan);
                    let (t, c) = if r.dir_tx { ("写 TX", C_TX) } else { ("读 RX", C_RX) };
                    ui.colored_label(c, t);
                    if let Some(p) = &r.parsed {
                        ui.colored_label(
                            Self::kind_color(p.kind),
                            format!(
                                "{} · {} · Addr={} Qty={} CRC={} {}",
                                p.kind.name(),
                                protocol::fc_name(p.function),
                                p.address.map(|a| a.to_string()).unwrap_or_else(|| "-".into()),
                                p.quantity.map(|a| a.to_string()).unwrap_or_else(|| "-".into()),
                                p.checksum,
                                match p.checksum_ok {
                                    Some(true) => "✓",
                                    Some(false) => "✗",
                                    None => "-",
                                }
                            ),
                        );
                    }
                });
                ui.monospace(RichText::new(bytes_hex(&r.data)).color(Self::kind_color(r.kind)));
                ui.monospace(escape_text(&r.data, s.ascii_escape, s.display_encoding));
            }
        } else {
            ui.label(RichText::new("点击上方任一行查看详情").weak());
        }
        ui.separator();
        // ---- send controls ----
        //
        // 发送能力取决于通道类型：被动监听（拦截串口）的句柄由被监控进程持有，本软件
        // 根本没有可写句柄。以前按钮始终可用、点了必然失败，错误只塞进 notices，
        // 用户看到的就是「点了没反应」。现在按可用性禁用并在原位说明原因。
        let sel_kind = s.channels.get(s.send_chan).map(|c| c.kind.clone());
        let can_send = matches!(
            sel_kind,
            Some(ChanKind::Serial) | Some(ChanKind::TcpClient) | Some(ChanKind::TcpServer) | Some(ChanKind::Udp)
        );
        let reason = match (&sel_kind, can_send) {
            (None, _) => "该会话没有通道",
            (Some(ChanKind::HookSerial), _) => {
                "监听模式只读：串口句柄由被监控进程持有，本软件无法写入。需要主动收发请新建「串口独占用」会话。"
            }
            (_, true) => "",
            _ => "当前通道不可发送",
        };
        if !reason.is_empty() {
            ui.horizontal(|ui| {
                ui.label(RichText::new("ⓘ").color(C_REQ));
                ui.label(RichText::new(reason).color(C_REQ).small());
            });
        }
        // `s` holds a mutable borrow of self.sessions for the whole block, so collect the
        // user-visible feedback here and emit it after the closure ends.
        let mut feedback: Option<String> = None;
        ui.horizontal(|ui| {
            ComboBox::from_id_source("send_chan")
                .selected_text(s.channels.get(s.send_chan).map(|c| c.name.as_str()).unwrap_or("-"))
                .width(160.0)
                .show_ui(ui, |ui| {
                    for (i, c) in s.channels.iter().enumerate() {
                        ui.selectable_value(&mut s.send_chan, i, &c.name);
                    }
                })
                .response
                .on_disabled_hover_text("没有通道");
            ui.checkbox(&mut s.send_hex, "HEX");
            let resp = ui.add(
                TextEdit::singleline(&mut s.send_text)
                    .hint_text(if s.send_hex { "01 03 00 6B 00 03" } else { "hello" })
                    .desired_width(300.0),
            );
            let _ = resp;
            if ui
                .add_enabled(can_send, egui::Button::new("发送"))
                .on_disabled_hover_text(reason)
                .clicked()
            {
                let bytes = if s.send_hex {
                    protocol::parse_hex(&s.send_text)
                } else {
                    Some(s.send_text.bytes().collect())
                };
                feedback = Some(match bytes {
                    Some(data) if !data.is_empty() => match s.send_bytes(s.send_chan, &data) {
                        Ok(()) => format!("已发送 {} 字节", data.len()),
                        Err(e) => format!("发送失败: {e}"),
                    },
                    Some(_) => "没有可发送的内容".to_string(),
                    None => "HEX 格式错误：需要偶数个十六进制字符".to_string(),
                });
            }
            ui.separator();
            if ui.button("请求预设").clicked() {
                s.preset_req = true;
            }
            if ui.button("响应预设").clicked() {
                s.preset_req = false;
            }
            let list = if s.preset_req { REQUEST_PRESETS } else { RESPONSE_PRESETS };
            if s.preset_sel >= list.len() {
                s.preset_sel = 0;
            }
            ComboBox::from_id_source("preset_cb")
                .selected_text(list[s.preset_sel].name)
                .width(320.0)
                .show_ui(ui, |ui| {
                    for (i, p) in list.iter().enumerate() {
                        ui.selectable_value(&mut s.preset_sel, i, p.name);
                    }
                });
            if ui
                .add_enabled(can_send, egui::Button::new("发送预设"))
                .on_disabled_hover_text(reason)
                .clicked()
            {
                let pdu = protocol::parse_hex(list[s.preset_sel].data).unwrap_or_default();
                // One shared frame builder: the ASCII branch used to append the LRC
                // twice here, so every Modbus-ASCII preset was sent as a corrupt frame.
                let frame = protocol::build_frame(&pdu, s.proto, s.seq as u16);
                feedback = Some(match s.send_bytes(s.send_chan, &frame) {
                    Ok(()) => format!("已发送预设（{}，{} 字节）", s.proto.label(), frame.len()),
                    Err(e) => format!("发送失败: {e}"),
                });
            }
            ui.separator();
            if ui.button("清空数据").clicked() {
                s.clear();
            }
            ui.checkbox(&mut s.auto_scroll, "滚屏显示");
        });
        if let Some(msg) = feedback {
            self.toast(msg);
        }
    }

    fn dialogs(&mut self, ctx: &Context) {
        if self.dlg_new {
            Window::new("新建监控会话")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    self.dlg_new_ui(ui);
                });
        }
        if self.dlg_filter {
            Window::new("过滤设置").collapsible(false).show(ctx, |ui| {
                self.dlg_filter_ui(ui);
            });
        }
        if self.dlg_redir {
            Window::new("自动保存视图日志设置")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    self.dlg_redir_ui(ui);
                });
        }
        if self.dlg_prefs {
            Window::new("显示设置").collapsible(false).show(ctx, |ui| {
                self.dlg_prefs_ui(ui);
            });
        }
        if self.dlg_find {
            Window::new("查找")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.label("查找内容");
                        ui.add(TextEdit::singleline(&mut self.find_text).desired_width(220.0));
                    });
                    ui.label(
                        RichText::new("匹配 HEX，以及按当前显示编码解码后的文本（含中文）")
                            .weak()
                            .small(),
                    );
                    ui.horizontal(|ui| {
                        // 查找 restarts from the top; 查找下一个 continues from the last hit.
                        // Both used to call the same function, so 查找 felt like a no-op
                        // whenever the previous hit was already near the end.
                        if ui.button("查找").clicked() {
                            self.find_reset();
                            self.find_next();
                        }
                        if ui.button("查找下一个").clicked() {
                            self.find_next();
                        }
                        if ui.button("关闭").clicked() {
                            self.dlg_find = false;
                        }
                    });
                    if !self.find_note.is_empty() {
                        ui.label(RichText::new(&self.find_note).color(C_REQ).small());
                    }
                });
        }
        if self.dlg_confirm_exit {
            Window::new("确认退出")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label("当前还有监控会话。退出前建议先「保存会话」，否则本次采集的数据会丢失。");
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("保存会话并退出").clicked() {
                            self.save_archive_active();
                            std::process::exit(0);
                        }
                        if ui.button("直接退出").clicked() {
                            std::process::exit(0);
                        }
                        if ui.button("取消").clicked() {
                            self.dlg_confirm_exit = false;
                        }
                    });
                });
        }
        if self.dlg_about {
            Window::new("关于").collapsible(false).resizable(false).show(ctx, |ui| {
                ui.heading("万能串口监控 v1.0");
                ui.separator();
                ui.label("串口 / TCP / UDP / Modbus 通信监控");
                ui.label("五视图: Table / 终端 / Dump / Line曲线 / Modbus");
                ui.label("内置 23 请求 + 43 响应 Modbus 预设");
                ui.label("原创实现，不含任何第三方程序的品牌资源");
            });
        }
        if self.dlg_attach {
            Window::new("附加到进程(串口拦截)")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    self.dlg_attach_ui(ui);
                });
        }
        if self.dlg_drv {
            Window::new("驱动捕获设置")
                .collapsible(false)
                .resizable(true)
                .default_width(560.0)
                // Without an explicit position egui can place the window partly off-screen
                // on the first frame, which clipped the left edge of every label. Anchoring
                // it near the top-left keeps the whole dialog visible at any window size.
                .default_pos(egui::pos2(60.0, 80.0))
                .show(ctx, |ui| {
                    self.dlg_driver_ui(ui);
                });
        }
    }

    /// 驱动捕获设置对话框。
    ///
    /// 为什么要有这个对话框：驱动捕获的失败模式（没装、签名被拒、无端口、PID 填错）
    /// 各不相同，而菜单里的一键启用只能给出「成功/失败」。这里把驱动状态、端口表、
    /// PID 过滤和启停放在同一处，用户不用去翻文档就知道下一步该做什么。
    fn dlg_driver_ui(&mut self, ui: &mut Ui) {
        // 首帧或用户手动刷新后重新探测；对话框打开时探测失败不会影响已开始的捕获。
        if !self.drv_checked {
            self.probe_driver_availability(true);
        }
        let capturing = self.drv_rx.is_some();

        ui.horizontal(|ui| {
            ui.label(RichText::new("驱动状态:").strong());
            if capturing {
                ui.label(RichText::new("捕获已启动").color(C_RX).strong());
            } else if self.drv_avail {
                ui.label(RichText::new("可用（未启动捕获）").color(C_REQ).strong());
            } else {
                ui.label(RichText::new("不可用").color(C_FAIL).strong());
            }
            if ui.button("重新检测").clicked() {
                self.probe_driver_availability(true);
                        ui.close_menu();
            }
        });
        ui.label(
            RichText::new(format!("控制设备: {}", crate::driver::CHANNEL_NAME))
                .small()
                .color(Color32::GRAY),
        );
        // 捕获中驱动句柄在后台线程，UI 侧问不到 stats；未捕获时顺手读一次，
        // 让用户看清驱动自己认为附加了几个端口（可用于和上面的端口表对照）。
        if !capturing && self.drv_avail {
            if let Some(h) = crate::driver::DriverHandle::open() {
                if let Some(st) = h.stats() {
                    ui.label(RichText::new(st.summary()).small().color(Color32::GRAY));
                    // When a scan attaches nothing, say why instead of leaving the user
                    // with a bare "0". The counters come from the driver's discovery gate.
                    if st.attached == 0 && (st.rejected_type > 0 || st.rejected_name > 0) {
                        ui.label(
                            RichText::new(format!(
                                "扫描结果：类型不符 {} 个，名称不符 {} 个。\
                                 名称不符说明串口设备名不在 Serial/VSerial 命名空间内。",
                                st.rejected_type, st.rejected_name
                            ))
                            .small()
                            .color(C_FAIL),
                        );
                    }
                }
            }
        }

        // --- 端口过滤：统一入口在「过滤设置」，这里只做引导 ---
        //
        // 这里曾经有一套自己的端口勾选（按设备短名 VSerial8_2 匹配），而
        // 「过滤设置」里还有一套（按 COM 号匹配）。两份白名单、两种名字，
        // 用户在 A 处勾了 B 处不生效，而且驱动路径和注入路径各认一套 ——
        // 这就是"过滤不可预测"的根源。现在只有「过滤设置 → 监视端口」一处，
        // 两条捕获路径共用，这里只显示当前生效的选择并给出入口。
        ui.separator();
        ui.horizontal(|ui| {
            ui.label(RichText::new("监视端口").strong());
            ui.label(
                RichText::new("（与注入模式共用同一份设置）")
                    .small()
                    .color(Color32::GRAY),
            );
            if ui.button("去设置…").clicked() {
                self.dlg_drv = false;
                self.dlg_filter = true;
            }
        });
        if self.drv_names.is_empty() {
            ui.label(RichText::new("尚未扫描到端口").small().color(Color32::GRAY));
        } else {
            // 按 COM 号排序，读起来和用户的心智模型一致。
            let mut rows: Vec<(String, String)> = self
                .drv_names
                .values()
                .map(|path| {
                    let short = short_dev(path);
                    let com = self.drv_com.get(path).cloned().unwrap_or_else(|| short.clone());
                    (com, short)
                })
                .collect();
            rows.sort();
            rows.dedup();

            // 当前生效的白名单状态（只读展示，改要进「过滤设置」）。
            let (on, sel) = match self.sessions.get(self.active) {
                Some(s) => (s.port_watch_on, s.port_watch.clone()),
                None => (self.fport_on, self.fport_sel.clone()),
            };
            for (com, short) in rows {
                let watched = crate::session::pw_allowed(&sel, on, &com);
                let label = if com == short {
                    com.clone()
                } else {
                    format!("{com}  ({short})")
                };
                let mut on_box = watched;
                ui.horizontal(|ui| {
                    // 只读：勾选状态反映真实过滤结果，避免这里改了和实际不一致。
                    ui.add_enabled(false, egui::Checkbox::new(&mut on_box, label));
                    if !watched {
                        ui.label(RichText::new("已过滤").small().color(C_FAIL));
                    }
                });
            }
            if !on {
                ui.label(
                    RichText::new("当前：监视全部端口")
                        .small()
                        .color(Color32::GRAY),
                );
            } else {
                ui.label(
                    RichText::new(format!("当前：仅监视 {} 个端口", sel.len()))
                        .small()
                        .color(Color32::GRAY),
                );
            }
        }

        // --- 不可用时的可操作指引 ---
        if !self.drv_avail && !capturing {
            let err = self.drv_err;
            let hint = crate::driver::open_failure_hint(err);
            ui.separator();
            ui.label(RichText::new("如何让它可用：").strong());
            ScrollArea::vertical().id_source("drv_hint").max_height(170.0).show(ui, |ui| {
                // 文案里带命令，用等宽字体才对得上复制粘贴时的空格。
                ui.monospace(hint);
            });
            if ui.button("复制安装命令").clicked() {
                let cmd = "sc create UmSerialFilter type= kernel binPath= <umserialfilter.sys 完整路径>\r\nsc start UmSerialFilter\r\nsc query UmSerialFilter";
                ui.output_mut(|o| o.copied_text = cmd.to_string());
                        ui.close_menu();
            }
            ui.add_space(4.0);
            ui.label(
                RichText::new(
                    "提示：加载内核驱动必须管理员权限；本软件不需要自己提权，\
                     只需以管理员身份启动本程序或手动执行上面的命令。",
                )
                .small()
                .weak(),
            );
        }

        // --- 端口表 ---
        ui.separator();
        ui.horizontal(|ui| {
            ui.label(RichText::new("已附加端口:").strong());
            ui.label(
                RichText::new(format!("{} 个", self.drv_names.len()))
                    .small()
                    .color(Color32::GRAY),
            );
            if ui.button("重新扫描端口").clicked() {
                self.rescan_driver_ports();
                        ui.close_menu();
            }
        });
        if self.drv_names.is_empty() {
            // 两种「空」含义不同：驱动没起来时端口表本来就取不到，不能说成「已加载」。
            let msg = if self.drv_avail {
                "(没有端口) 驱动已加载但没有找到串口设备，插拔一次串口设备后再扫描"
            } else {
                "(没有端口) 驱动未就绪，先按上面的指引加载驱动"
            };
            ui.label(RichText::new(msg).weak());
        } else {
            let mut rows: Vec<(u32, String)> = self
                .drv_names
                .iter()
                .map(|(i, d)| (*i, d.clone()))
                .collect();
            rows.sort_by_key(|(i, _)| *i);
            ScrollArea::vertical().id_source("drv_ports").max_height(130.0).show(ui, |ui| {
                egui::Grid::new("drv_port_grid").striped(true).show(ui, |ui| {
                    ui.strong("序号");
                    ui.strong("设备路径");
                    ui.strong("短名");
                    ui.strong("会话通道");
                    ui.end_row();
                    for (idx, dev) in rows {
                        ui.monospace(idx.to_string());
                        ui.monospace(&dev);
                        ui.label(short_dev(&dev));
                        let linked = self.drv_ports.iter().any(|((_, pi), _)| *pi == idx);
                        if linked {
                            ui.label(RichText::new("已接入").color(C_RX));
                        } else {
                            ui.label(RichText::new("等待数据").weak());
                        }
                        ui.end_row();
                    }
                });
            });
        }

        // --- PID 过滤 ---
        ui.separator();
        ui.horizontal(|ui| {
            ui.label("PID 过滤:");
            ui.add(
                TextEdit::singleline(&mut self.drv_pid_text)
                    .hint_text("0 = 捕获所有进程")
                    .desired_width(120.0),
            );
            if ui.button("应用").clicked() {
                let pid: u32 = self.drv_pid_text.trim().parse().unwrap_or(0);
                self.apply_driver_pid(pid);
                        ui.close_menu();
            }
            if ui.button("所有进程").clicked() {
                self.drv_pid_text = "0".into();
                self.apply_driver_pid(0);
                        ui.close_menu();
            }
            let cur = self.drv_pid.unwrap_or(0);
            ui.label(
                RichText::new(if cur == 0 {
                    "当前: 所有进程".to_string()
                } else {
                    format!("当前: PID {cur}")
                })
                .small()
                .color(Color32::GRAY),
            );
        });
        ui.label(
            RichText::new("PID 过滤只影响驱动捕获；改成某个 PID 后，其它进程的串口流量不再入库。")
                .small()
                .weak(),
        );

        // --- 启停 ---
        ui.separator();
        ui.horizontal(|ui| {
            if capturing {
                if ui.button("停止捕获").clicked() {
                    self.stop_driver_capture();
                    self.drv_note = "驱动捕获已停止".into();
                    self.toast("已停止驱动捕获");
                        ui.close_menu();
                }
            } else if ui
                .add_enabled(self.drv_avail, egui::Button::new("开始捕获"))
                .clicked()
            {
                // 失败时 start_driver_capture 已经把 drv_avail/drv_err/drv_note 更新成
                // 真实原因，这里不要再覆盖成一句泛泛的提示。
                if self.start_driver_capture() {
                    self.toast("驱动捕获已启动");
                } else {
                    self.toast("驱动不可用，原因见下方说明");
                }
            }
            if ui.button("关闭").clicked() {
                self.dlg_drv = false;
                        ui.close_menu();
            }
        });
        // 驱动不可用时上面已经完整显示过 open_failure_hint，底部不再重复一遍；
        // 这里只负责「已可用」或「捕获中」的操作结果回显。
        if !self.drv_note.is_empty() && (capturing || self.drv_avail) {
            ui.add_space(4.0);
            ScrollArea::vertical().id_source("drv_note").max_height(90.0).show(ui, |ui| {
                ui.label(RichText::new(&self.drv_note).small());
            });
        }
        ui.separator();
        if ui.button("关闭").clicked() {
            self.dlg_drv = false;
                        ui.close_menu();
        }
    }

    /// 应用 PID 过滤。捕获中走线程命令（设备被线程独占，UI 侧没有句柄）。
    fn apply_driver_pid(&mut self, pid: u32) {
        self.drv_pid = if pid == 0 { None } else { Some(pid) };
        if let Some(tx) = &self.drv_cmd {
            let _ = tx.send(DrvCmd::SetTarget(pid));
            self.drv_note = if pid == 0 {
                "已切换为捕获所有进程".into()
            } else {
                format!("已把驱动捕获目标设为 PID {pid}")
            };
            self.toast(self.drv_note.clone());
            return;
        }
        // 未捕获：直接设一次，让下一次 start 之前驱动就按新条件工作。
        match crate::driver::DriverHandle::open() {
            Some(h) => {
                h.set_target(pid);
                self.drv_avail = true;
                self.drv_err = 0;
                self.drv_note = if pid == 0 {
                    "已设置：捕获所有进程".into()
                } else {
                    format!("已设置：仅捕获 PID {pid}")
                };
                self.toast(self.drv_note.clone());
            }
            None => {
                let err = crate::driver::last_error();
                self.drv_avail = false;
                self.drv_err = err;
                self.drv_checked = true;
                self.drv_note = crate::driver::open_failure_hint(err);
                self.toast("驱动不可用，PID 设置未生效");
            }
        }
    }

    fn dlg_attach_ui(&mut self, ui: &mut Ui) {
        // Refresh the process list when the dialog is first shown.
        if self.procs.is_empty() {
            self.procs = inject::list_processes();
        }
        // Refresh the port-holder list at most every ~1.5 s (the scan walks the whole
        // system handle table, so doing it every frame would burn CPU).
        if self.frame_count.saturating_sub(self.holders_at) > 90 || self.holders_at == 0 {
            self.holders_at = self.frame_count;
            let ports: Vec<String> = self
                .sessions
                .iter()
                .flat_map(|s| s.channels.iter())
                .filter(|c| c.kind == ChanKind::HookSerial)
                .map(|c| c.name.clone())
                .collect();
            if ports.is_empty() {
                self.port_holders.clear();
                self.holder_note = "尚未创建「串口监听」会话，无法判断谁在占用端口".into();
            } else {
                let (list, note) = crate::portowners::find_port_holders(&ports);
                self.port_holders = list.into_iter().map(|(p, _)| p).collect();
                self.holder_note = note;
            }
        }

        ui.label(
            egui::RichText::new("附加到进程（被动拦截，不占用串口）").strong(),
        );
        ui.add_space(4.0);

        // --- filter row ---
        ui.horizontal(|ui| {
            ui.label("搜索:");
            let resp = ui.add(
                egui::TextEdit::singleline(&mut self.attach_filter)
                    .hint_text("进程名或 PID")
                    .desired_width(180.0),
            );
            if resp.changed() {
                self.attach_sel = None;
            }
            if ui.button("清空").clicked() {
                self.attach_filter.clear();
                        ui.close_menu();
            }
            ui.checkbox(&mut self.attach_only_apps, "只看应用进程");
            if ui.button("刷新").clicked() {
                self.procs = inject::list_processes();
                self.holders_at = 0;
                self.attach_sel = None;
                        ui.close_menu();
            }
        });

        // --- holder status ---
        // Two sources of truth, the second being authoritative:
        //   * a name-based candidate scan (helps before anything is injected), and
        //   * the hook's own OPEN reports — a PID that reported opening a watched
        //     port definitely holds it, and is marked accordingly.
        let confirmed: Vec<u32> = self
            .hook_ports
            .keys()
            .map(|(pid, _)| *pid)
            .collect();
        let holder_txt = format!("{} 个进程；{}", self.procs.len(), self.holder_note);
        if confirmed.is_empty() && self.port_holders.is_empty() {
            ui.label(egui::RichText::new(holder_txt).weak());
        } else {
            let extra = if confirmed.is_empty() {
                String::new()
            } else {
                format!("；已确认占用串口的进程 {} 个", confirmed.len())
            };
            ui.colored_label(
                egui::Color32::from_rgb(0x2e, 0x7d, 0x32),
                format!("{holder_txt}{extra}"),
            );
        }

        // --- filtered candidate list ---
        let needle = self.attach_filter.trim().to_lowercase();
        let mut shown: Vec<(usize, String, bool)> = Vec::new();
        for (i, (pid, name)) in self.procs.iter().enumerate() {
            let is_holder = confirmed.contains(pid) || self.port_holders.contains(pid);
            if self.attach_only_apps && !is_holder && !looks_like_app(name) {
                continue;
            }
            if !needle.is_empty()
                && !name.to_lowercase().contains(&needle)
                && !pid.to_string().contains(&needle)
            {
                continue;
            }
            let label = if confirmed.contains(pid) {
                format!("● {name}  (PID {pid})  ← 已确认占用串口")
            } else if is_holder {
                format!("○ {name}  (PID {pid})  ← 可能占用串口")
            } else {
                format!("  {name}  (PID {pid})")
            };
            shown.push((i, label, is_holder));
        }
        // Port holders first, then alphabetical — the useful rows are always on top.
        shown.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.1.cmp(&b.1)));

        ScrollArea::vertical().max_height(280.0).show(ui, |ui| {
            if shown.is_empty() {
                ui.label("(没有匹配的进程)");
            }
            for (i, label, _) in shown.iter() {
                let selected = self.attach_sel == Some(*i);
                let resp = ui.add(SelectableLabel::new(selected, label));
                if resp.clicked() {
                    self.attach_sel = Some(*i);
                }
                if resp.double_clicked() {
                    self.attach_sel = Some(*i);
                    self.attach_selected();
                }
            }
        });

        ui.separator();
        ui.horizontal(|ui| {
            let can = self.attach_sel.is_some();
            if ui
                .add_enabled(can, egui::Button::new("注入并监控"))
                .clicked()
            {
                self.attach_selected();
            }
            if ui
                .add_enabled(
                    self.attach_sel.is_some(),
                    egui::Button::new("复制 PID"),
                )
                .clicked()
            {
                if let Some(i) = self.attach_sel {
                    let (pid, _) = self.procs[i].clone();
                    ui.output_mut(|o| o.copied_text = pid.to_string());
                }
            }
            if ui.button("关闭").clicked() {
                self.dlg_attach = false;
                        ui.close_menu();
            }
        });
        ui.add_space(2.0);
        ui.label(
            egui::RichText::new(
                "提示：带 ● 的进程正在占用被监听的串口，优先附加它们。\
                 重要：请在目标程序「打开串口之前」附加，否则它已缓存的 API 指针会绕过拦截。\
                 若程序已在运行，请先附加再让它重新打开串口。",
            )
            .weak()
            .small(),
        );
        ui.separator();
        if ui.button("关闭").clicked() {
            self.dlg_attach = false;
                        ui.close_menu();
        }
    }

    /// Inject the hook into the selected process and report the outcome.
    fn attach_selected(&mut self) {
        let Some(i) = self.attach_sel else { return };
        let Some((pid, name)) = self.procs.get(i).cloned() else {
            return;
        };
        let dll = inject::dll_path()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        match inject::inject(pid, &dll) {
            Ok(()) => {
                self.toast(format!("已注入 {name} (PID {pid})，其串口读写将被拦截"));
                if let Some(s) = self.sessions.get_mut(self.active) {
                    s.notices
                        .push(format!("已附加 {name} (PID {pid})"));
                }
                self.dlg_attach = false;
            }
            Err(e) => self.toast(format!("注入失败: {e}")),
        }
    }

    /// Drain records streamed by injected hook DLLs and route them into sessions.
    fn drain_capture(&mut self) {
        if self.cap_rx.is_none() {
            return;
        }
        let mut msgs = Vec::new();
        if let Some(rx) = &self.cap_rx {
            while let Ok(m) = rx.try_recv() {
                msgs.push(m);
            }
        }
        for m in msgs {
            self.on_capture(m);
        }
    }

    fn on_capture(&mut self, m: CapMsg) {
        match m {
            CapMsg::Attach { pid, exe } => {
                if self.sessions.iter().any(|s| s.cap_pid == Some(pid)) {
                    return; // hook reconnected — session already exists
                }
                let short = exe
                    .rsplit(['\\', '/'])
                    .next()
                    .unwrap_or("")
                    .to_string();
                // With a passive (串口监听) session open, data must flow into THAT
                // session — auto-attach must not spawn a new window per process.
                let has_passive = self
                    .sessions
                    .iter()
                    .any(|s| s.channels.iter().any(|c| c.kind == ChanKind::HookSerial));
                if !has_passive {
                    self.sessions.push(Session::new_capture(pid, &short));
                    self.active = self.sessions.len() - 1;
                }
                self.toast(format!("已附加进程 {} (PID {})", short, pid));
            }
            CapMsg::Open { pid, handle, port } => {
                self.hook_ports.insert((pid, handle), port.clone());
                if let Some(s) = self.sessions.iter_mut().find(|s| s.cap_pid == Some(pid)) {
                    let idx = s.add_capture_channel(&port);
                    s.cap_map.insert(handle, idx);
                    s.notices
                        .push(format!("通道{} 拦截 {} (句柄 0x{:X})", idx, port, handle));
                }
                // hook-watch sessions match by port name; they never own the port
                for s in self.sessions.iter_mut() {
                    if s.cap_pid.is_some() {
                        continue;
                    }
                    if let Some(idx) = s
                        .channels
                        .iter()
                        .position(|c| c.kind == ChanKind::HookSerial && c.name == port)
                    {
                        s.cap_map.insert(handle, idx);
                        s.notices
                            .push(format!("拦截到 {} 的读写 (PID {})", port, pid));
                    }
                }
            }
            CapMsg::Close { pid, handle } => {
                let port = self.hook_ports.remove(&(pid, handle));
                if let Some(s) = self.sessions.iter_mut().find(|s| s.cap_pid == Some(pid)) {
                    if s.cap_map.remove(&handle).is_some() {
                        s.notices.push("被拦截的串口句柄已关闭".into());
                    }
                }
                if let Some(port) = port {
                    for s in self.sessions.iter_mut() {
                        if s.cap_pid.is_some() {
                            continue;
                        }
                        if s.cap_map.remove(&handle).is_some() {
                            s.notices.push(format!("{} 已被对方关闭", port));
                        }
                    }
                }
            }
            CapMsg::Rx { pid, handle, data } => {
                self.route_hook_data(pid, handle, data, false);
            }
            CapMsg::Tx { pid, handle, data } => {
                self.route_hook_data(pid, handle, data, true);
            }
        }
    }

    /// Deliver hook-captured bytes to the PID capture session and to every
    /// hook-watch session whose channel names that port. Name routing works even
    /// when the port was opened before the watch session was created.
    ///
    /// 端口白名单（`Session::port_watch`，见「过滤设置」→「监视端口」）在这里生效：
    /// 每个会话在把字节喂进 `ingest` 之前先问一句 `port_allowed(端口名)`，被取消
    /// 勾选的端口连行都不会产生 —— 不只是界面上看不见，数据根本没进 `rows`。
    fn route_hook_data(&mut self, pid: u32, handle: u64, data: Vec<u8>, tx: bool) {
        let (secs, ms) = now_wall();
        // 端口名先取出来：PID 会话走 handle 映射，但过滤条件只认端口名，
        // 这样两条路由分支用的是同一份白名单判断。
        let port = self.hook_ports.get(&(pid, handle)).cloned();
        if let Some(s) = self.sessions.iter_mut().find(|s| s.cap_pid == Some(pid)) {
            // 暂停门禁：主链路也必须尊重 `running`，否则「暂停监控」对默认的被动监听
            // 路径完全没有作用（数据照进、Bytes 照涨，而状态栏写着「已暂停」）。
            if s.running {
                if let Some(&idx) = s.cap_map.get(&handle) {
                    // 端口名取不到时只能放行：没有名字就无从判断，宁可多显示也不要静默丢数据。
                    let allowed = match &port {
                        Some(p) => s.port_allowed(p),
                        None => true,
                    };
                    if allowed {
                        s.ingest(idx, data.clone(), secs, ms, tx);
                    }
                }
            }
        }
        if let Some(port) = port {
            for s in self.sessions.iter_mut() {
                if s.cap_pid.is_some() || !s.running {
                    continue;
                }
                if !s.port_allowed(&port) {
                    continue;
                }
                if let Some(idx) = s
                    .channels
                    .iter()
                    .position(|c| c.kind == ChanKind::HookSerial && c.name == port)
                {
                    s.ingest(idx, data.clone(), secs, ms, tx);
                }
            }
        }
    }

    fn dlg_new_ui(&mut self, ui: &mut Ui) {
        ComboBox::from_label("通道类型")
            .selected_text(CHAN_KINDS[self.chan_kind])
            .show_ui(ui, |ui| {
                for (i, k) in CHAN_KINDS.iter().enumerate() {
                    ui.selectable_value(&mut self.chan_kind, i, *k);
                }
            });
        if self.chan_kind == 0 || self.chan_kind == 4 {
            if self.chan_kind == 0 {
                ui.colored_label(
                    egui::Color32::from_rgb(0x2e, 0x7d, 0x32),
                    "被动监听：本软件不会打开串口，只读取被监控程序收到的数据。",
                );
                ui.label("下一步：菜单 → 监控 → 附加到进程(拦截)…，把钩子注入到使用该串口的程序。");
            } else {
                ui.colored_label(
                    egui::Color32::from_rgb(0xc6, 0x28, 0x28),
                    "独占模式：本软件会打开串口，其他程序将无法再使用它（仅在需要主动收发时使用）。",
                );
            }
            ui.label("串口 (可多选):");
            ScrollArea::vertical().max_height(120.0).show(ui, |ui| {
                for (i, p) in self.ports.iter().enumerate() {
                    while self.port_sel.len() <= i {
                        self.port_sel.push(false);
                    }
                    let mut on = self.port_sel[i];
                    if ui.checkbox(&mut on, p).changed() {
                        self.port_sel[i] = on;
                    }
                }
                if self.ports.is_empty() {
                    ui.label("(未发现串口)");
                }
            });
            if self.chan_kind == 0 {
                // Passive listening: baud/line settings belong to the program that
                // owns the port, not to us — nothing to configure here.
            } else {
            ComboBox::from_label("波特率")
                .selected_text(format!("{}", BAUDS[self.baud_i]))
                .show_ui(ui, |ui| {
                    for (i, b) in BAUDS.iter().enumerate() {
                        ui.selectable_value(&mut self.baud_i, i, format!("{}", b));
                    }
                });
            ui.horizontal(|ui| {
                ComboBox::from_label("数据位")
                    .selected_text(if self.data_i == 0 { "7" } else { "8" })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.data_i, 0, "7");
                        ui.selectable_value(&mut self.data_i, 1, "8");
                    });
                ComboBox::from_label("校验")
                    .selected_text(["无", "偶", "奇"][self.parity_i])
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.parity_i, 0, "无");
                        ui.selectable_value(&mut self.parity_i, 1, "偶");
                        ui.selectable_value(&mut self.parity_i, 2, "奇");
                    });
                ComboBox::from_label("停止位")
                    .selected_text(if self.stop_i == 0 { "1" } else { "2" })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.stop_i, 0, "1");
                        ui.selectable_value(&mut self.stop_i, 1, "2");
                    });
            });
            }
        } else {
            ui.horizontal(|ui| {
                ui.label("地址 (host:port)");
                ui.add(TextEdit::singleline(&mut self.addr).desired_width(200.0));
            });
        }
        ui.separator();
        ComboBox::from_label("协议类型")
            .selected_text(
                match self.proto_sel {
                    1 => ProtoType::Rtu,
                    2 => ProtoType::Ascii,
                    3 => ProtoType::Tcp,
                    _ => ProtoType::None,
                }
                .label(),
            )
            .show_ui(ui, |ui| {
                let vals = [(0, ProtoType::None), (1, ProtoType::Rtu), (2, ProtoType::Ascii), (3, ProtoType::Tcp)];
                for (i, p) in vals {
                    ui.selectable_value(&mut self.proto_sel, i, p.label());
                }
            });
        ui.label("视图:");
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.views_new.table, "Table视图");
            ui.checkbox(&mut self.views_new.terminal, "终端视图");
            ui.checkbox(&mut self.views_new.dump, "Dump视图");
            ui.checkbox(&mut self.views_new.line, "Line曲线图");
            ui.checkbox(&mut self.views_new.modbus, "Modbus视图");
        });
        ui.checkbox(&mut self.auto_mon, "创建后自动开始监控");
        ui.separator();
        ui.horizontal(|ui| {
            if ui.button("确定").clicked() {
                self.new_session();
                        ui.close_menu();
            }
            if ui.button("取消").clicked() {
                self.dlg_new = false;
                        ui.close_menu();
            }
        });
        ui.separator();
        if ui.button("关闭").clicked() {
            self.dlg_new = false;
                        ui.close_menu();
        }
    }

    /// 「过滤设置」对话框。
    ///
    /// 除了 方向 / Modbus 功能码 / 内容查找，这里还有「监视端口」—— 会话级端口白名单。
    /// 编辑走草稿（`fport_draft_*`），点「应用」才写回会话和 config.ini，和功能码同一套模型；
    /// 草稿在对话框打开时从当前会话同步一次（`fport_draft_sess`），所以每次打开看到的都是
    /// 真正生效的状态，而不是上一次遗留的默认值。
    fn dlg_filter_ui(&mut self, ui: &mut Ui) {
        // 打开对话框的第一帧（或切换了会话标签页）把草稿拉到当前会话的真实状态。
        if self.fport_draft_sess != Some(self.active) {
            match self.sessions.get(self.active) {
                Some(s) => {
                    self.fport_draft_on = s.port_watch_on;
                    self.fport_draft_sel = s.port_watch.clone();
                }
                None => {
                    self.fport_draft_on = self.fport_on;
                    self.fport_draft_sel = self.fport_sel.clone();
                }
            }
            self.fport_draft_sess = Some(self.active);
        }
        // 端口候选 = 会话已有通道 + 驱动已发现但还没有任何流量的端口。
        //
        // 只用会话通道会漏掉一种真实情况：驱动挂接了全部端口，但某个端口还没收到
        // 数据，因此还没建通道 —— 用户想在它出数据之前就把其他端口过滤掉，就找不到
        // 这个端口可勾。把驱动端口表并进来，候选集才是"机器上存在的串口"。
        let mut port_all: Vec<String> = match self.sessions.get(self.active) {
            Some(s) => s.port_choices(),
            None => Vec::new(),
        };
        for idx in self.drv_names.keys() {
            let n = self.channel_port_name(*idx);
            if !n.is_empty() && !port_all.iter().any(|x| x == &n) {
                port_all.push(n);
            }
        }
        // 按 COM 号排序；非 COM 名（设备短名）排在后面，保持稳定。
        port_all.sort_by_key(|n| {
            n.strip_prefix("COM")
                .and_then(|d| d.parse::<u32>().ok())
                .map(|d| (0u8, d, String::new()))
                .unwrap_or((1u8, 0, n.clone()))
        });

        ui.label("数据方向:");
        ui.horizontal(|ui| {
            for (i, t) in ["全部", "读", "写"].iter().enumerate() {
                if ui.radio(self.fdir == i, *t).clicked() {
                    self.fdir = i;
                }
            }
        });
        ui.separator();
        ui.label("Modbus 功能码过滤 (不勾选 = 全部):");
        ScrollArea::vertical().max_height(140.0).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                for (i, fc) in FCS.iter().enumerate() {
                    let mut on = self.fcs_sel[i];
                    if ui.checkbox(&mut on, format!("0x{:02X}", fc)).changed() {
                        self.fcs_sel[i] = on;
                    }
                }
            });
        });
        ui.horizontal(|ui| {
            if ui.button("全选").clicked() {
                self.fcs_sel.iter_mut().for_each(|v| *v = true);
                        ui.close_menu();
            }
            if ui.button("反选").clicked() {
                self.fcs_sel.iter_mut().for_each(|v| *v = !*v);
                        ui.close_menu();
            }
            if ui.button("取消选择").clicked() {
                self.fcs_sel.iter_mut().for_each(|v| *v = false);
                        ui.close_menu();
            }
            if ui.button("默认设置").clicked() {
                self.fcs_sel.iter_mut().for_each(|v| *v = false);
                self.fdir = 0;
                        ui.close_menu();
            }
        });
        ui.separator();
        // --- 监视端口：会话级端口白名单 ---
        ui.horizontal(|ui| {
            ui.label(RichText::new("监视端口:").strong());
            ui.label(
                RichText::new("（取消勾选即过滤该端口，两条捕获路径都生效；默认监视全部）")
                    .small()
                    .color(Color32::GRAY),
            );
        });
        if port_all.is_empty() {
            ui.label(
                RichText::new(
                    "该会话还没有端口通道。串口监听/驱动捕获的通道建立后，这里会列出端口名。",
                )
                .small()
                .color(Color32::GRAY),
            );
            // 没有端口可勾时仍要留一条出路：白名单可能是从 config.ini 继承来的
            // （启用 + 空集合 = 全部丢弃），否则这个会话会一直空白而用户无从恢复。
            if ui.button("清除端口过滤").clicked() {
                pw_select_all(&mut self.fport_draft_sel, &mut self.fport_draft_on);
                ui.close_menu();
            }
        } else {
            ScrollArea::vertical().id_source("filter_ports").max_height(120.0).show(ui, |ui| {
                for name in &port_all {
                    let mut on = pw_allowed(&self.fport_draft_sel, self.fport_draft_on, name);
                    if ui.checkbox(&mut on, name).changed() {
                        pw_toggle(
                            &mut self.fport_draft_sel,
                            &mut self.fport_draft_on,
                            &port_all,
                            name,
                            on,
                        );
                    }
                }
            });
            ui.horizontal(|ui| {
                if ui.button("全选").clicked() {
                    pw_select_all(&mut self.fport_draft_sel, &mut self.fport_draft_on);
                    ui.close_menu();
                }
                if ui.button("反选").clicked() {
                    pw_invert(&mut self.fport_draft_sel, &mut self.fport_draft_on, &port_all);
                    ui.close_menu();
                }
                if ui.button("取消选择").clicked() {
                    pw_select_none(&mut self.fport_draft_sel, &mut self.fport_draft_on);
                    ui.close_menu();
                }
            });
            if self.fport_draft_on && self.fport_draft_sel.is_empty() {
                ui.label(
                    RichText::new("已取消全部端口：该会话将不显示任何端口数据。")
                        .small()
                        .color(C_FAIL),
                );
            }
        }
        ui.separator();
        ui.horizontal(|ui| {
            ui.label("内容查找:");
            ui.add(TextEdit::singleline(&mut self.ftext).desired_width(180.0));
            ui.checkbox(&mut self.ftext_on, "启用");
        });
        ui.horizontal(|ui| {
            if ui.button("应用").clicked() {
                let fcs = self.sel_fcs();
                if let Some(s) = self.sessions.get_mut(self.active) {
                    s.filters = Filters {
                        dir: self.fdir,
                        fcs,
                        text: self.ftext.clone(),
                        text_on: self.ftext_on,
                    };
                    // 端口白名单写进会话 —— 这一步才让两条数据路径真正按端口过滤。
                    s.port_watch = self.fport_draft_sel.clone();
                    s.port_watch_on = self.fport_draft_on;
                }
                // 同时作为"默认设置"和 config.ini 的落盘值。
                self.fport_sel = self.fport_draft_sel.clone();
                self.fport_on = self.fport_draft_on;
                self.save_cfg();
                self.dlg_filter = false;
                self.fport_draft_sess = None;
                        ui.close_menu();
            }
            if ui.button("关闭").clicked() {
                self.dlg_filter = false;
                self.fport_draft_sess = None;
                ui.close_menu();
            }
        });
    }

    fn dlg_redir_ui(&mut self, ui: &mut Ui) {
        ui.checkbox(&mut self.r_on, "启用自动保存");
        ui.horizontal(|ui| {
            ui.label("输出文件");
            ui.add(TextEdit::singleline(&mut self.r_path).desired_width(260.0));
        });
        ComboBox::from_label("分割方式")
            .selected_text(SPLITS[self.r_split])
            .show_ui(ui, |ui| {
                for (i, s) in SPLITS.iter().enumerate() {
                    ui.selectable_value(&mut self.r_split, i, *s);
                }
            });
        ui.horizontal(|ui| {
            if self.r_split == 1 {
                ui.label("时间(分钟)");
                ui.add(DragValue::new(&mut self.r_time).speed(1.0).range(1..=100000));
            }
            if self.r_split == 2 {
                ui.label("大小(MB)");
                ui.add(DragValue::new(&mut self.r_size).speed(1.0).range(1..=10000));
            }
        });
        ui.label(
            RichText::new("日志文件编码（只影响写出的文件字节；界面显示编码在「设置→显示编码」）")
                .weak()
                .small(),
        );
        ComboBox::from_label("文件编码")
            .selected_text(ENCS[self.r_enc])
            .show_ui(ui, |ui| {
                for (i, e) in ENCS.iter().enumerate() {
                    ui.selectable_value(&mut self.r_enc, i, *e);
                }
            });
        if self.sessions.is_empty() {
            ui.label(RichText::new("当前没有会话：此设置会作为新建会话的默认值").color(C_REQ).small());
        }
        ui.separator();
        ui.horizontal(|ui| {
            if ui.button("保存").clicked() {
                let applied = self.sessions.get_mut(self.active).is_some();
                if let Some(s) = self.sessions.get_mut(self.active) {
                    if self.r_on {
                        let (now, _) = crate::session::now_wall();
                        s.autosave = Some(Autosave {
                            on: true,
                            path: self.r_path.clone(),
                            split: self.r_split,
                            time_min: self.r_time.max(1),
                            size_mb: self.r_size.max(1),
                            encoding: self.r_enc,
                            written: 0,
                            started_at: now,
                            cur_file: String::new(),
                        });
                    } else if let Some(a) = s.autosave.as_mut() {
                        a.on = false;
                    }
                }
                self.redir_backup = None;
                self.dlg_redir = false;
                self.toast(if applied {
                    "自动保存设置已应用到当前会话"
                } else {
                    "已保存为新建会话的默认值（当前没有会话）"
                });
            }
            if ui.button("取消").clicked() {
                self.restore_redir();
                self.dlg_redir = false;
                        ui.close_menu();
            }
        });
        ui.separator();
        if ui.button("关闭").clicked() {
            self.dlg_redir = false;
                        ui.close_menu();
        }
    }

    fn dlg_prefs_ui(&mut self, ui: &mut Ui) {
        if self.sessions.is_empty() {
            ui.label(RichText::new("当前没有会话：此设置会作为新建会话的默认值").color(C_REQ).small());
        }
        ui.horizontal(|ui| {
            ui.label("Modbus Values 列长度");
            ui.add(DragValue::new(&mut self.p_strlen).speed(1.0).range(8..=4096));
        });
        ui.label(
            RichText::new("仅作用于 Modbus 视图的 Values 列；Table/终端/Dump 的数据列不截断")
                .weak()
                .small(),
        );
        ui.horizontal(|ui| {
            ui.label("合并相邻读/写数据的时间窗口(ms)：");
            ui.add(DragValue::new(&mut self.p_merge).speed(1.0).range(5..=1000));
            for v in [5u64, 10, 20, 50, 100, 200, 500] {
                if ui.small_button(format!("{}", v)).clicked() {
                    self.p_merge = v;
                }
            }
        });
        ui.label(
            RichText::new("作用于原始字节流；已按 Modbus 解析成帧的会话不受影响")
                .weak()
                .small(),
        );
        ui.horizontal(|ui| {
            ui.label("Values 显示:");
            if ui.radio(!self.p_dec, "16进制").clicked() {
                self.p_dec = false;
            }
            if ui.radio(self.p_dec, "10进制").clicked() {
                self.p_dec = true;
            }
        });
        ui.checkbox(&mut self.p_esc, "非可视控制符显示为 \\xNN（否则显示 ?）");
        ui.checkbox(&mut self.p_scroll, "滚屏显示（自动跟随最新数据）");
        ui.checkbox(&mut self.p_apply_all, "应用到全部会话");
        ui.separator();
        ui.horizontal(|ui| {
            if ui.button("保存").clicked() {
                let apply_all = self.p_apply_all;
                let active = self.active;
                let mut n = 0usize;
                for (i, s) in self.sessions.iter_mut().enumerate() {
                    // Only the active session unless 应用到全部会话 is ticked.
                    if !apply_all && i != active {
                        continue;
                    }
                    s.merge_ms = self.p_merge;
                    s.string_len = self.p_strlen;
                    s.values_dec = self.p_dec;
                    s.ascii_escape = self.p_esc;
                    s.auto_scroll = self.p_scroll;
                    n += 1;
                }
                // The dialog drafts double as the defaults for new sessions.
                self.save_cfg();
                self.prefs_backup = None;
                self.dlg_prefs = false;
                self.toast(if n == 0 {
                    "已保存为新建会话的默认值（当前没有会话）".to_string()
                } else if apply_all {
                    format!("显示设置已应用到全部 {n} 个会话")
                } else {
                    "显示设置已应用到当前会话".to_string()
                });
            }
            if ui.button("取消").clicked() {
                self.restore_prefs();
                self.dlg_prefs = false;
            }
            if ui.button("关闭").clicked() {
                self.dlg_prefs = false;
            }
        });
    }
    /// True while any session is actively collecting. A passive (串口监听) channel
    /// counts as live even when idle, because a row can arrive at any moment.
    fn monitoring_live(&self) -> bool {
        self.drv_rx.is_some()
            || self.sessions.iter().any(|s| {
                s.running
                    || s.channels.iter().any(|c| c.kind == ChanKind::HookSerial)
                    || s.cap_pid.is_some()
            })
    }

    /// Show auto-attach events (which programs got hooked) without a dialog.
    ///
    /// The status bar already renders the session's most recent notice, and the toast
    /// area renders transient messages. Feeding the same line to both printed it twice
    /// — once small and grey from `notices`, once larger and blue from the toast — which
    /// is what the duplicated `串口占用=COM6:false 持有者=[]` in the status bar was.
    ///
    /// Only the session notice is kept: it is the durable, always-visible one, and it
    /// survives a repaint. Reserve the toast for one-off confirmations (injected / failed)
    /// so the two mechanisms never describe the same event.
    fn drain_auto_attach(&mut self) {
        let lines = match &self.auto {
            Some(a) => a.drained_log(),
            None => return,
        };
        if lines.is_empty() {
            return;
        }
        if let Some(s) = self.sessions.get_mut(self.active) {
            for line in lines {
                s.notices.push(line);
            }
            // `notices` is only ever displayed per session and never trimmed; an
            // auto-attach service that runs for hours would grow it without bound.
            let excess = s.notices.len().saturating_sub(64);
            if excess > 0 {
                s.notices.drain(..excess);
            }
        } else {
            // No session yet (nothing to attach the line to): the toast is the only
            // place it can be seen, so use it rather than dropping the information.
            if let Some(last) = lines.last() {
                self.toast(last.clone());
            }
        }
    }
}

impl eframe::App for MonitorApp {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        self.frame_count += 1;
        if let Some(out) = self.screenshot.clone() {
            if self.frame_count == 100 {
                // Lift above screen-share overlays before the grab.
                ctx.send_viewport_cmd(ViewportCommand::WindowLevel(egui::WindowLevel::AlwaysOnTop));
                ctx.send_viewport_cmd(ViewportCommand::Focus);
            }
            if !self.capture_done && self.frame_count >= 110 {
                self.capture_done = true;
                // Client-area rect in physical pixels, so the capture script stays pure .NET.
                let (mut x, mut y, mut w, mut h) = (0i32, 0i32, 1280i32, 800i32);
                let vp = ctx.input(|i| i.viewport().clone());
                if let Some(r) = vp.inner_rect {
                    x = r.left().round() as i32;
                    y = r.top().round() as i32;
                    w = r.width().round() as i32;
                    h = r.height().round() as i32;
                }
                if let Err(e) = crate::capture::capture_window(&out, std::process::id(), x, y, w, h) {
                    eprintln!("capture failed: {e}");
                }
                std::process::exit(0);
            }
        }
        self.drain_capture();
        self.drain_driver();
        self.drain_auto_attach();
        // 状态栏要区分「未启用」和「未安装」，而驱动可能在本程序启动之后才装上
        // （用户照着提示执行 sc create），所以低频重探一次，而不是只在启动时判一次。
        if self.frame_count % 60 == 0 {
            self.probe_driver_availability(false);
        }
        for s in self.sessions.iter_mut() {
            s.poll();
        }
        if self.active >= self.sessions.len() {
            self.active = self.sessions.len().saturating_sub(1);
        }
        self.top_panel(ctx);
        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| self.status_bar(ui));
        egui::TopBottomPanel::bottom("send_pane")
            .resizable(true)
            .default_height(190.0)
            .show(ctx, |ui| self.send_pane(ui));
        egui::CentralPanel::default().show(ctx, |ui| self.main_area(ui));
        self.dialogs(ctx);
        // Live monitoring must repaint continuously: rows arrive from background threads
        // and the window has to show them without a mouse move.
        //
        // 16 ms (~60 fps) rather than 60 ms. At 60 ms a row could sit in the channel for a
        // whole frame boundary, which read as "the monitor is always one message behind":
        // sending a second message is what made the first one appear.
        if self.frame_count < 200 || self.monitoring_live() {
            ctx.request_repaint_after(std::time::Duration::from_millis(16));
        }
    }
}
