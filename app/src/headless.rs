// Headless watch mode: runs the SAME session + auto-attach path the UI uses, but
// without a window, and writes a JSON result file. It exists to make the user's
// real scenario testable end to end:
//
//   monitor starts (passive listen on COM6)
//   -> two serial tools start and open COM6 / COM7
//   -> the monitor must capture their traffic WITHOUT any manual attach step
//
// Any divergence between this and the UI would defeat the purpose, so it builds the
// session with Session::new exactly like ui.rs::new_session does and lets the same
// AutoAttach service find and hook the owning processes.

use crate::autoattach::AutoAttach;
use crate::inject::{self, CapMsg};
use crate::session::{ChanKind, ChannelCfg, ProtoType, Session, ViewToggles};
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub fn headless_watch(port: &str, result_path: &str) -> i32 {
    // Same construction as the UI's passive session.
    let chans = vec![ChannelCfg {
        kind: ChanKind::HookSerial,
        name: port.to_string(),
        baud: 0,
        data_bits: 8,
        parity: 0,
        stop_bits: 1,
    }];
    let mut session = Session::new(
        format!("监听 {port}"),
        chans,
        ProtoType::None,
        ViewToggles { table: true, terminal: true, dump: true, line: true, modbus: true },
    );
    session.running = true;

    let rx = inject::start_capture_server();
    let auto = AutoAttach::start(vec![port.to_string()]);
    println!("headless-watch: 自动附加已启动，监听 {port}");

    let mut hook_ports: HashMap<(u32, u64), String> = HashMap::new();
    let mut tx = 0usize;
    let mut rxc = 0usize;
    let mut attached: Vec<String> = Vec::new();
    let mut notices: Vec<String> = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(20);

    while Instant::now() < deadline {
        // Capture records (same routing as ui.rs::route_hook_data)
        while let Ok(msg) = rx.try_recv() {
            match msg {
                CapMsg::Attach { pid, exe } => {
                    let short = exe.rsplit(['\\', '/']).next().unwrap_or("").to_string();
                    attached.push(format!("{short} (PID {pid})"));
                }
                CapMsg::Open { pid, handle, port: p } => {
                    hook_ports.insert((pid, handle), p);
                }
                CapMsg::Close { pid, handle } => {
                    hook_ports.remove(&(pid, handle));
                }
                CapMsg::Rx { pid, handle, data } => {
                    if let Some(p) = hook_ports.get(&(pid, handle)).cloned() {
                        if let Some(idx) = session
                            .channels
                            .iter()
                            .position(|c| c.kind == ChanKind::HookSerial && c.name == p)
                        {
                            let (s, ms) = crate::session::now_wall();
                            session.ingest(idx, data.clone(), s, ms, false);
                            rxc += data.len();
                        }
                    }
                }
                CapMsg::Tx { pid, handle, data } => {
                    if let Some(p) = hook_ports.get(&(pid, handle)).cloned() {
                        if let Some(idx) = session
                            .channels
                            .iter()
                            .position(|c| c.kind == ChanKind::HookSerial && c.name == p)
                        {
                            let (s, ms) = crate::session::now_wall();
                            session.ingest(idx, data.clone(), s, ms, true);
                            tx += data.len();
                        }
                    }
                }
            }
        }
        for line in auto.drained_log() {
            println!("headless-watch: [auto] {line}");
            notices.push(line);
        }
        session.poll();
        // Stop early once both directions of real traffic were seen.
        if tx > 0 && rxc > 0 && !attached.is_empty() {
            // keep collecting a moment for a stable row count
            std::thread::sleep(Duration::from_millis(500));
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    CapMsg::Open { pid, handle, port: p } => {
                        hook_ports.insert((pid, handle), p);
                    }
                    CapMsg::Rx { pid, handle, data } => {
                        if let Some(p) = hook_ports.get(&(pid, handle)).cloned() {
                            if let Some(idx) = session
                                .channels
                                .iter()
                                .position(|c| c.kind == ChanKind::HookSerial && c.name == p)
                            {
                                let (s, ms) = crate::session::now_wall();
                                session.ingest(idx, data.clone(), s, ms, false);
                                rxc += data.len();
                            }
                        }
                    }
                    CapMsg::Tx { pid, handle, data } => {
                        if let Some(p) = hook_ports.get(&(pid, handle)).cloned() {
                            if let Some(idx) = session
                                .channels
                                .iter()
                                .position(|c| c.kind == ChanKind::HookSerial && c.name == p)
                            {
                                let (s, ms) = crate::session::now_wall();
                                session.ingest(idx, data.clone(), s, ms, true);
                                tx += data.len();
                            }
                        }
                    }
                    _ => {}
                }
            }
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let rows = session.rows.len();
    // Every string field goes through the same escaper: process exe names can contain
    // characters that break JSON (and a naive format! produced invalid output before).
    let json = format!(
        "{{\"sessions\":1,\"rows\":{rows},\"tx\":{tx},\"rx\":{rxc},\"attached\":{},\"notices\":{}}}",
        serde_like(&[attached.join(", ")]),
        serde_like(&notices)
    );
    if let Err(e) = std::fs::write(result_path, json) {
        eprintln!("写结果失败: {e}");
        return 1;
    }
    println!("headless-watch: rows={rows} tx={tx} rx={rxc} attached=[{}]", attached.join(", "));
    if rows > 0 {
        0
    } else {
        1
    }
}

/// Tiny JSON array of strings — avoids a serde dependency for one field.
fn serde_like(items: &[String]) -> String {
    let mut s = String::from("[");
    for (i, it) in items.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push('"');
        for c in it.chars() {
            match c {
                '"' => s.push_str("\\\""),
                '\\' => s.push_str("\\\\"),
                '\n' => s.push_str("\\n"),
                '\r' => {}
                c => s.push(c),
            }
        }
        s.push('"');
    }
    s.push(']');
    s
}
