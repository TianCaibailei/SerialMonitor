// 万能串口监控 — serial / TCP / UDP / Modbus communication monitor.
// CLI: --screenshot <file.png>  render ~110 frames, save a PNG, exit 0.

mod autoattach;
mod capture;
mod diag;
mod e2e;
mod headless;
mod inject;
mod layout_probe;
mod native_serial;
mod portowners;
mod protocol;
mod session;
mod ui;

fn parse_args() -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--inject-smoke" {
            std::process::exit(inject::smoke_inject());
        }
        // --inject-comtest <COMx> <COMy> — live end-to-end interception check
        // against a free loopback pair (never the user's active ports).
        if args[i] == "--inject-comtest" {
            let port = args.get(i + 1).cloned().unwrap_or_else(|| "COM1".into());
            let peer = args.get(i + 2).cloned().unwrap_or_else(|| "COM2".into());
            std::process::exit(inject::comtest_inject(&port, &peer));
        }
        // --hook-e2e <COMx> <COMy> — full chain: hook DLL -> pipe -> session rows
        if args[i] == "--hook-e2e" {
            let port = args.get(i + 1).cloned().unwrap_or_else(|| "COM6".into());
            let peer = args.get(i + 2).cloned().unwrap_or_else(|| "COM7".into());
            std::process::exit(e2e::hook_e2e(&port, &peer));
        }
        // --headless-watch <COMx> --result <file.json>
        // Runs the passive-session + auto-attach path without a window and writes
        // what it captured. Used by the end-to-end scenario test.
        if args[i] == "--headless-watch" {
            let port = args.get(i + 1).cloned().unwrap_or_else(|| "COM6".into());
            let mut result = String::from("watch-result.json");
            if let Some(pos) = args.iter().position(|a| a == "--result") {
                if let Some(p) = args.get(pos + 1) {
                    result = p.clone();
                }
            }
            std::process::exit(headless::headless_watch(&port, &result));
        }
        // --inject-test <pid> — inject the architecture-correct hook DLL and verify
        if args[i] == "--inject-test" {
            let pid: u32 = args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(0);
            std::process::exit(diag::inject_test(pid));
        }
        // --handles-self — verify the handle snapshot contains our own handles
        if args[i] == "--handles-self" {
            std::process::exit(diag::handles_self());
        }
        // --holders <COMx>... — which processes hold these serial ports
        if args[i] == "--holders" {
            let ports: Vec<String> = args[i + 1..].to_vec();
            std::process::exit(diag::holders(&ports));
        }
        // --list-procs — what the process enumerator sees (auto-attach diagnostic)
        if args[i] == "--list-procs" {
            std::process::exit(diag::list_procs());
        }
        // --probe-layout — dump the raw PROCESSENTRY32W bytes to verify field offsets
        if args[i] == "--probe-layout" {
            std::process::exit(layout_probe::probe_layout());
        }
        // --native-serial <COMx> <ms> — a native (non-.NET) serial tool, used to test
        // whether the hook works for programs that call the Win32 API directly.
        if args[i] == "--native-serial" {
            let com = args.get(i + 1).cloned().unwrap_or_else(|| "COM6".into());
            let ms: u64 = args.get(i + 2).and_then(|s| s.parse().ok()).unwrap_or(8000);
            std::process::exit(native_serial::run(&com, ms));
        }
        // --find-owners <COMx> — who holds this port right now (auto-attach diagnostic)
        if args[i] == "--find-owners" {
            let port = args.get(i + 1).cloned().unwrap_or_else(|| "COM6".into());
            std::process::exit(diag::find_owners(&port));
        }
        if args[i] == "--screenshot" {
            return args.get(i + 1).cloned();
        }
        i += 1;
    }
    None
}

fn load_cjk_fonts() -> egui::FontDefinitions {
    let mut fonts = egui::FontDefinitions::default();
    for p in [
        "C:\\Windows\\Fonts\\simhei.ttf",
        "C:\\Windows\\Fonts\\msyh.ttc",
        "C:\\Windows\\Fonts\\DENG.TTF",
        "C:\\Windows\\Fonts\\simsun.ttc",
    ] {
        if let Ok(data) = std::fs::read(p) {
            fonts.font_data.insert("cjk".into(), egui::FontData::from_owned(data).into());
            fonts
                .families
                .get_mut(&egui::FontFamily::Proportional)
                .unwrap()
                .insert(0, "cjk".into());
            fonts
                .families
                .get_mut(&egui::FontFamily::Monospace)
                .unwrap()
                .insert(0, "cjk".into());
            break;
        }
    }
    fonts
}

fn main() {
    let screenshot = parse_args();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("万能串口监控")
            .with_inner_size([1280.0, 800.0]),
        ..Default::default()
    };
    let fonts = load_cjk_fonts();
    let _ = eframe::run_native(
        "万能串口监控",
        options,
        Box::new(move |cc| {
            cc.egui_ctx.set_fonts(fonts);
            Ok(Box::new(ui::MonitorApp::new(screenshot)))
        }),
    );
}
