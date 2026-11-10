// Main window: menus, session tabs, five views, dialogs, send pane, status bar.

use crate::inject::{self, CapMsg};
use crate::protocol::{self, REQUEST_PRESETS, RESPONSE_PRESETS};
use crate::session::{
    bytes_hex, escape_text, fmt_time, now_wall, seed_demo, Autosave, ChanKind, ChannelCfg, Filters,
    ProtoType, Session, ViewToggles,
};
use egui::{
    Color32, ComboBox, Context, DragValue, RichText, ScrollArea, SelectableLabel, TextEdit, Ui,
    ViewportCommand, Window,
};
use egui_extras::{Column, TableBuilder};
use egui_plot::{Legend, Line, Plot, PlotPoints};
use std::collections::HashMap;
use std::sync::mpsc::Receiver;

const C_REQ: Color32 = Color32::from_rgb(0x1F, 0x6F, 0xEB);
const C_RESP: Color32 = Color32::from_rgb(0x23, 0xA5, 0x59);
const C_EXC: Color32 = Color32::from_rgb(0xE0, 0x80, 0x00);
const C_FAIL: Color32 = Color32::from_rgb(0xD6, 0x45, 0x45);
const C_TX: Color32 = Color32::from_rgb(0x35, 0x72, 0xD9);
const C_RX: Color32 = Color32::from_rgb(0x2D, 0x8A, 0x4B);

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

    pub find_text: String,
}

fn b(v: bool) -> &'static str {
    if v { "1" } else { "0" }
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
            find_text: String::new(),
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
        }
        app
    }

    fn toast(&mut self, msg: impl Into<String>) {
        self.toast_msg = msg.into();
        self.toast_until = self.frame_count + 600;
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
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    fn save_cfg(&self) {
        let t = format!(
            "[NewMon]\ntableView={} terminalView={} dumpView={} modbusView={} lineView={} autoMon={} modbusType={}\n",
            b(self.views_new.table),
            b(self.views_new.terminal),
            b(self.views_new.dump),
            b(self.views_new.modbus),
            b(self.views_new.line),
            b(self.auto_mon),
            self.proto_sel
        );
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
        s.filters = Filters {
            dir: self.fdir,
            fcs: self.sel_fcs(),
            text: self.ftext.clone(),
            text_on: self.ftext_on,
        };
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
    }

    fn save_active(&mut self) {
        let Some(s) = self.sessions.get(self.active) else { return };
        let path = format!("session_{}.log", self.active + 1);
        match s.save_log(&path, self.save_enc) {
            Ok(()) => self.toast(format!("已保存 {}", path)),
            Err(e) => self.toast(format!("保存失败: {}", e)),
        }
    }

    fn find_next(&mut self) {
        let t = self.find_text.trim().to_lowercase();
        if t.is_empty() {
            return;
        }
        let Some(s) = self.sessions.get_mut(self.active) else { return };
        let n = s.rows.len();
        let mut hit = None;
        for k in 0..=n {
            let i = (s.find_pos + k) % (n + 1);
            if i >= n {
                continue;
            }
            let r = &s.rows[i];
            let hex = bytes_hex(&r.data).to_lowercase();
            let txt = String::from_utf8_lossy(&r.data).to_lowercase();
            if hex.contains(&t) || txt.contains(&t) {
                hit = Some(i);
                break;
            }
        }
        match hit {
            Some(i) => {
                s.selected = Some(i);
                s.find_pos = i + 1;
            }
            None => self.toast("未找到"),
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
        ctx.copy_text(line);
        self.toast("已复制");
    }

    fn top_panel(&mut self, ctx: &Context) {
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.menu_button("文件", |ui| {
                    if ui.button("新建监控会话…").clicked() {
                        self.dlg_new = true;
                    }
                    if ui.button("保存当前会话").clicked() {
                        self.save_active();
                    }
                    ui.separator();
                    if ui.button("退出").clicked() {
                        std::process::exit(0);
                    }
                });
                let has = !self.sessions.is_empty();
                ui.menu_button("监控", |ui| {
                    if ui.add_enabled(has, egui::Button::new("开启监控")).clicked() {
                        if let Some(s) = self.sessions.get_mut(self.active) {
                            s.running = true;
                        }
                    }
                    if ui.add_enabled(has, egui::Button::new("暂停监控")).clicked() {
                        if let Some(s) = self.sessions.get_mut(self.active) {
                            s.running = false;
                        }
                    }
                    if ui.add_enabled(has, egui::Button::new("关闭会话")).clicked() {
                        self.close_active();
                    }
                    ui.separator();
                    if ui.button("过滤设置…").clicked() {
                        self.dlg_filter = true;
                    }
                    ui.separator();
                    if ui.button("附加到进程(拦截)…").clicked() {
                        self.procs = inject::list_processes();
                        self.attach_sel = None;
                        self.dlg_attach = true;
                    }
                });
                ui.menu_button("编辑", |ui| {
                    if ui.add_enabled(has, egui::Button::new("复制")).clicked() {
                        self.copy_selected(ctx);
                    }
                    if ui.button("查找…").clicked() {
                        self.dlg_find = true;
                    }
                    if ui.add_enabled(has, egui::Button::new("查找下一个")).clicked() {
                        self.find_next();
                    }
                    ui.separator();
                    if ui.add_enabled(has, egui::Button::new("清空数据")).clicked() {
                        if let Some(s) = self.sessions.get_mut(self.active) {
                            s.clear();
                        }
                    }
                });
                ui.menu_button("设置", |ui| {
                    if ui.button("自动保存日志设置…").clicked() {
                        self.dlg_redir = true;
                    }
                    if ui.button("显示设置…").clicked() {
                        self.dlg_prefs = true;
                    }
                    ui.separator();
                    ui.menu_button("编码方式", |ui| {
                        for (i, name) in ENCS.iter().enumerate() {
                            if ui.radio(self.save_enc == i, *name).clicked() {
                                self.save_enc = i;
                            }
                        }
                    });
                });
                ui.menu_button("帮助", |ui| {
                    if ui.button("关于…").clicked() {
                        self.dlg_about = true;
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
                ui.label(format!("Bytes: ↑{} ↓{}", s.bytes_tx, s.bytes_rx));
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
        let vis: Vec<usize> = s
            .rows
            .iter()
            .enumerate()
            .filter(|(_, r)| s.filters.pass(r))
            .map(|(i, _)| i)
            .collect();
        let start = vis.len().saturating_sub(20000);
        let mut clicked: Option<usize> = None;
        TableBuilder::new(ui)
            .striped(true)
            .vscroll(true)
            .stick_to_bottom(s.auto_scroll)
            .column(Column::initial(52.0).at_least(36.0))
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
                            if let Some(p) = &r.parsed {
                                ui.label(format!("{:02X} {}", p.function, protocol::fc_name(p.function)));
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
                            ui.monospace(RichText::new(shown).color(Self::kind_color(r.kind)));
                        });
                        row.col(|ui| {
                            let mut t = escape_text(&r.data, s.ascii_escape);
                            t.truncate(s.string_len.max(4));
                            ui.label(t);
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
        let vis: Vec<usize> = s
            .rows
            .iter()
            .enumerate()
            .filter(|(_, r)| s.filters.pass(r))
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
                let line = escape_text(&r.data, esc);
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
        let vis: Vec<usize> = s
            .rows
            .iter()
            .enumerate()
            .filter(|(_, r)| s.filters.pass(r))
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
                ui.separator();
            }
        });
        if let Some(i) = clicked {
            s.selected = Some(i);
        }
    }

    fn view_line(&mut self, ui: &mut Ui) {
        let Some(s) = self.sessions.get(self.active) else { return };
        let rx: Vec<[f64; 2]> = s.rate.iter().enumerate().map(|(i, e)| [i as f64, e.1 as f64]).collect();
        let tx: Vec<[f64; 2]> = s.rate.iter().enumerate().map(|(i, e)| [i as f64, e.2 as f64]).collect();
        Plot::new("line_plot")
            .legend(Legend::default())
            .y_axis_label("B/s")
            .x_axis_label("秒(最近180s)")
            .show(ui, |plot| {
                plot.line(Line::new(PlotPoints::from(rx)).name("接收 B/s").color(C_RX));
                plot.line(Line::new(PlotPoints::from(tx)).name("发送 B/s").color(C_TX));
            });
    }

    fn view_modbus(&mut self, ui: &mut Ui) {
        let Some(s) = self.sessions.get_mut(self.active) else { return };
        let vis: Vec<usize> = s
            .rows
            .iter()
            .enumerate()
            .filter(|(_, r)| r.parsed.is_some() && s.filters.pass(r))
            .map(|(i, _)| i)
            .collect();
        let dec = s.values_dec;
        let mut clicked: Option<usize> = None;
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
                ui.monospace(escape_text(&r.data, s.ascii_escape));
            }
        } else {
            ui.label(RichText::new("点击上方任一行查看详情").weak());
        }
        ui.separator();
        // send controls
        ui.horizontal(|ui| {
            let n = s.channels.len();
            ComboBox::from_id_source("send_chan")
                .selected_text(s.channels.get(s.send_chan).map(|c| c.name.as_str()).unwrap_or("-"))
                .width(160.0)
                .show_ui(ui, |ui| {
                    for (i, c) in s.channels.iter().enumerate() {
                        ui.selectable_value(&mut s.send_chan, i, &c.name);
                    }
                })
                .response.on_disabled_hover_text("没有通道");
            let _ = n;
            ui.checkbox(&mut s.send_hex, "HEX");
            let resp = ui.add(
                TextEdit::singleline(&mut s.send_text)
                    .hint_text(if s.send_hex { "01 03 00 6B 00 03" } else { "hello" })
                    .desired_width(320.0),
            );
            if ui.button("发送").clicked() {
                let bytes = if s.send_hex {
                    protocol::parse_hex(&s.send_text)
                } else {
                    Some(s.send_text.bytes().collect())
                };
                match bytes {
                    Some(data) => match s.send_bytes(s.send_chan, &data) {
                        Ok(()) => {}
                        Err(e) => s.notices.push(format!("发送失败: {}", e)),
                    },
                    None => s.notices.push("HEX格式错误".into()),
                }
                let _ = resp;
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
                .width(340.0)
                .show_ui(ui, |ui| {
                    for (i, p) in list.iter().enumerate() {
                        ui.selectable_value(&mut s.preset_sel, i, p.name);
                    }
                });
            if ui.button("发送预设").clicked() {
                let pdu = protocol::parse_hex(list[s.preset_sel].data).unwrap_or_default();
                let frame = match s.proto {
                    ProtoType::Rtu => protocol::append_crc(&pdu),
                    ProtoType::Ascii => {
                        let mut v = vec![b':'];
                        v.extend(pdu.iter().flat_map(|b| format!("{:02X}", b).into_bytes()));
                        v.extend(protocol::lrc(&pdu).to_string().bytes());
                        let lrc = protocol::lrc(&pdu);
                        v.extend(format!("{:02X}", lrc).into_bytes());
                        v.extend_from_slice(b"\r\n");
                        v
                    }
                    ProtoType::Tcp => protocol::wrap_mbap(&pdu, s.seq as u16),
                    ProtoType::None => pdu,
                };
                match s.send_bytes(s.send_chan, &frame) {
                    Ok(()) => {}
                    Err(e) => s.notices.push(format!("发送失败: {}", e)),
                }
            }
            ui.separator();
            if ui.button("清空数据").clicked() {
                s.clear();
            }
            ui.checkbox(&mut s.auto_scroll, "滚屏显示");
        });
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
                    ui.horizontal(|ui| {
                        if ui.button("查找").clicked() {
                            self.find_next();
                        }
                        if ui.button("查找下一个").clicked() {
                            self.find_next();
                        }
                        if ui.button("关闭").clicked() {
                            self.dlg_find = false;
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
            }
            ui.checkbox(&mut self.attach_only_apps, "只看应用进程");
            if ui.button("刷新").clicked() {
                self.procs = inject::list_processes();
                self.holders_at = 0;
                self.attach_sel = None;
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
            }
        });
        ui.add_space(2.0);
        ui.label(
            egui::RichText::new(
                "提示：带 ● 的进程正在占用被监听的串口，优先附加它们。\
                 注入后新打开的串口会立即命名；注入前已打开的串口在下次读写时识别。",
            )
            .weak()
            .small(),
        );
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
    fn route_hook_data(&mut self, pid: u32, handle: u64, data: Vec<u8>, tx: bool) {
        let (secs, ms) = now_wall();
        if let Some(s) = self.sessions.iter_mut().find(|s| s.cap_pid == Some(pid)) {
            if let Some(&idx) = s.cap_map.get(&handle) {
                s.ingest(idx, data.clone(), secs, ms, tx);
            }
        }
        if let Some(port) = self.hook_ports.get(&(pid, handle)).cloned() {
            for s in self.sessions.iter_mut() {
                if s.cap_pid.is_some() {
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
            }
            if ui.button("取消").clicked() {
                self.dlg_new = false;
            }
        });
    }

    fn dlg_filter_ui(&mut self, ui: &mut Ui) {
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
            }
            if ui.button("反选").clicked() {
                self.fcs_sel.iter_mut().for_each(|v| *v = !*v);
            }
            if ui.button("取消选择").clicked() {
                self.fcs_sel.iter_mut().for_each(|v| *v = false);
            }
            if ui.button("默认设置").clicked() {
                self.fcs_sel.iter_mut().for_each(|v| *v = false);
                self.fdir = 0;
            }
        });
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
                }
                self.dlg_filter = false;
            }
            if ui.button("关闭").clicked() {
                self.dlg_filter = false;
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
        ComboBox::from_label("编码方式")
            .selected_text(ENCS[self.r_enc])
            .show_ui(ui, |ui| {
                for (i, e) in ENCS.iter().enumerate() {
                    ui.selectable_value(&mut self.r_enc, i, *e);
                }
            });
        ui.separator();
        ui.horizontal(|ui| {
            if ui.button("保存").clicked() {
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
                self.dlg_redir = false;
            }
            if ui.button("取消").clicked() {
                self.dlg_redir = false;
            }
        });
    }

    fn dlg_prefs_ui(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.label("字符串输出长度");
            ui.add(DragValue::new(&mut self.p_strlen).speed(1.0).range(8..=4096));
        });
        ui.horizontal(|ui| {
            ui.label("以指定时间区间合并\"读\"和\"写\"的数据(ms)：");
            ui.add(DragValue::new(&mut self.p_merge).speed(1.0).range(5..=1000));
            for v in [5u64, 10, 20, 50, 100, 200, 500] {
                if ui.small_button(format!("{}", v)).clicked() {
                    self.p_merge = v;
                }
            }
        });
        ui.horizontal(|ui| {
            ui.label("Values 显示:");
            if ui.radio(!self.p_dec, "16进制").clicked() {
                self.p_dec = false;
            }
            if ui.radio(self.p_dec, "10进制").clicked() {
                self.p_dec = true;
            }
        });
        ui.checkbox(&mut self.p_esc, "非可视ASCII转义符显示\\x(否则?)");
        ui.checkbox(&mut self.p_scroll, "滚屏显示");
        ui.separator();
        ui.horizontal(|ui| {
            if ui.button("保存").clicked() {
                if let Some(s) = self.sessions.get_mut(self.active) {
                    s.merge_ms = self.p_merge;
                    s.string_len = self.p_strlen;
                    s.values_dec = self.p_dec;
                    s.ascii_escape = self.p_esc;
                    s.auto_scroll = self.p_scroll;
                }
                self.dlg_prefs = false;
            }
            if ui.button("取消").clicked() {
                self.dlg_prefs = false;
            }
        });
    }
    /// True while any session is actively collecting. A passive (串口监听) channel
    /// counts as live even when idle, because a row can arrive at any moment.
    fn monitoring_live(&self) -> bool {
        self.sessions.iter().any(|s| {
            s.running
                || s.channels.iter().any(|c| c.kind == ChanKind::HookSerial)
                || s.cap_pid.is_some()
        })
    }

    /// Show auto-attach events (which programs got hooked) without a dialog.
    fn drain_auto_attach(&mut self) {
        let lines = match &self.auto {
            Some(a) => a.drained_log(),
            None => return,
        };
        for line in lines {
            self.toast(line.clone());
            if let Some(s) = self.sessions.get_mut(self.active) {
                s.notices.push(line);
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
        self.drain_auto_attach();
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
        // Live monitoring must repaint continuously: rows arrive from background
        // threads and the window has to show them without a mouse move.
        if self.frame_count < 200 || self.monitoring_live() {
            ctx.request_repaint_after(std::time::Duration::from_millis(60));
        }
    }
}
