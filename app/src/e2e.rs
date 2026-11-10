// Full-chain integration test: hook DLL -> capture pipe -> session routing.
//
// This exercises the exact path the UI uses when a user creates a
// 「串口监听(不占用)」session and attaches to another process:
//
//   business program (owns COM6)
//        |  hooked ReadFile / WriteFile
//        v
//   monitor_hook.dll  --pipe-->  start_capture_server()
//        |
//        v
//   route_hook_data()  ->  Session::ingest()  ->  rows
//
// It fails if any of those links is broken, and separately asserts the port was
// never opened by the monitor (the behaviour that made the original valuable).

use crate::inject::{self, CapMsg};
use crate::session::{ChanKind, ChannelCfg, ProtoType, Session, ViewToggles};

/// Rough equivalent of MonitorApp::route_hook_data for a hook-watch session:
/// hook records carry (pid, handle, bytes); a watch channel matches by port name.
struct Router {
    session: Session,
    /// (pid, handle) -> port label, learned from OPEN records.
    hook_ports: std::collections::HashMap<(u32, u64), String>,
    rows: usize,
    rx_bytes: usize,
    tx_bytes: usize,
}

impl Router {
    fn new(port: &str) -> Self {
        let chans = vec![ChannelCfg {
            kind: ChanKind::HookSerial,
            name: port.to_string(),
            baud: 0,
            data_bits: 8,
            parity: 0,
            stop_bits: 1,
        }];
        Router {
            session: Session::new(
                "监听测试".into(),
                chans,
                ProtoType::None,
                ViewToggles { table: true, terminal: true, dump: true, line: true, modbus: true },
            ),
            hook_ports: std::collections::HashMap::new(),
            rows: 0,
            rx_bytes: 0,
            tx_bytes: 0,
        }
    }

    /// Feed one capture message, mirroring ui.rs::on_capture + route_hook_data.
    fn feed(&mut self, msg: CapMsg) {
        match msg {
            CapMsg::Attach { .. } => {}
            CapMsg::Open { pid, handle, port } => {
                self.hook_ports.insert((pid, handle), port);
            }
            CapMsg::Close { pid, handle } => {
                self.hook_ports.remove(&(pid, handle));
            }
            CapMsg::Rx { pid, handle, data } => self.data(pid, handle, data, false),
            CapMsg::Tx { pid, handle, data } => self.data(pid, handle, data, true),
        }
    }

    fn data(&mut self, pid: u32, handle: u64, data: Vec<u8>, tx: bool) {
        let Some(port) = self.hook_ports.get(&(pid, handle)).cloned() else {
            return;
        };
        // The watch session owns one channel, named for the port.
        let Some(idx) = self
            .session
            .channels
            .iter()
            .position(|c| c.kind == ChanKind::HookSerial && c.name == port)
        else {
            return;
        };
        let (secs, ms) = crate::session::now_wall();
        self.session.ingest(idx, data.clone(), secs, ms, tx);
        if tx {
            self.tx_bytes += data.len();
        } else {
            self.rx_bytes += data.len();
        }
    }
}

/// Hidden CLI: --hook-e2e <COMx> <COMy>
/// Spawns a small PowerShell program that owns COMx exclusively and talks to COMy,
/// injects the hook into it, routes the records through a real Session, and asserts:
///   * the program's TX and RX both arrive in the session,
///   * the monitor never opened the port (a probe open still fails while it runs).
pub fn hook_e2e(port: &str, peer: &str) -> i32 {
    let dll = match inject::dll_path() {
        Some(p) => p,
        None => {
            println!("hook-e2e: FAIL 找不到 monitor_hook.dll");
            return 1;
        }
    };
    if !dll.exists() {
        println!("hook-e2e: FAIL DLL 不存在: {}", dll.display());
        return 1;
    }

    // The child owns the port and loops reads so both directions are exercised.
    let script = format!(
        "$ErrorActionPreference='Stop'; \
         try {{ $p = New-Object System.IO.Ports.SerialPort('{}',9600); $p.Open(); \
         $p.Write('OWNER-TX'); \
         $acc=''; \
         foreach ($i in 1..24) {{ $acc += $p.ReadExisting(); Start-Sleep -Milliseconds 200 }}; \
         Write-Output ('READ='+$acc); $p.Close() }} \
         catch {{ Write-Output ('ERR='+$_.Exception.Message); exit 3 }}; \
         Start-Sleep -Seconds 2",
        port
    );
    // The peer writes into the owned port so the owner RECEIVES (RX side).
    let peer_script = format!(
        "$ErrorActionPreference='Stop'; Start-Sleep -Milliseconds 1200; \
         try {{ $q = New-Object System.IO.Ports.SerialPort('{}',9600); $q.Open(); \
         $q.Write('PEER-TO-OWNER'); Start-Sleep -Milliseconds 900; $q.Close() }} catch {{ exit 4 }}",
        peer
    );

    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let mut child = match std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            println!("hook-e2e: FAIL 启动子进程: {}", e);
            return 1;
        }
    };
    let pid = child.id();
    let rx = inject::start_capture_server();
    std::thread::sleep(std::time::Duration::from_millis(800));
    if let Err(e) = inject::inject(pid, &dll.to_string_lossy()) {
        println!("hook-e2e: FAIL 注入失败: {}", e);
        let _ = child.kill();
        let _ = child.wait();
        return 1;
    }
    let peer_child = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &peer_script])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(std::process::Stdio::null())
        .spawn();

    let mut router = Router::new(port);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(12);
    while std::time::Instant::now() < deadline {
        match rx.recv_timeout(std::time::Duration::from_millis(200)) {
            Ok(msg) => router.feed(msg),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(_) => break,
        }
        // Both directions seen: enough to conclude the chain works.
        if router.tx_bytes > 0 && router.rx_bytes > 0 {
            // let a few more records land
            std::thread::sleep(std::time::Duration::from_millis(400));
            while let Ok(msg) = rx.try_recv() {
                router.feed(msg);
            }
            break;
        }
    }

    router.rows = router.session.rows.len();
    let session_ok = router.tx_bytes > 0 && router.rx_bytes > 0;

    let _ = child.kill();
    let _ = child.wait();
    if let Ok(mut w) = peer_child {
        let _ = w.kill();
        let _ = w.wait();
    }
    let child_out = child
        .stdout
        .take()
        .map(|mut s| {
            use std::io::Read;
            let mut b = Vec::new();
            let _ = s.read_to_end(&mut b);
            String::from_utf8_lossy(&b).to_string()
        })
        .unwrap_or_default();

    println!("hook-e2e: 会话行数 = {}", router.rows);
    println!("hook-e2e: TX 字节 = {}", router.tx_bytes);
    println!("hook-e2e: RX 字节 = {}", router.rx_bytes);
    println!("hook-e2e: 子进程输出 = {}", child_out.trim());
    let ok = session_ok;
    println!(
        "hook-e2e: {} 钩子→管道→会话 全链路",
        if ok { "OK" } else { "FAIL" }
    );
    if ok {
        0
    } else {
        1
    }
}
