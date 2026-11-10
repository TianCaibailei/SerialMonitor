// 万能串口监控 — serial / TCP / UDP / Modbus communication monitor.
// CLI: --screenshot <file.png>  render ~110 frames, save a PNG, exit 0.

mod capture;
mod e2e;
mod inject;
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
