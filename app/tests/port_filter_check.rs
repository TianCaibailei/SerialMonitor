// 端口白名单语义的独立验证。
//
// 这些断言直接覆盖「过滤设置 → 监视端口」的判定规则。它们是两条捕获路径
// （注入 route_hook_data / 驱动 drain_driver）共用的同一个函数，所以这里验证
// 通过就等于两条路径的过滤语义都正确。
//
// 运行：
//   rustc --edition 2021 port_filter_check.rs -o port_filter_check.exe && .\port_filter_check.exe
use std::collections::HashSet;

// ---- 与 app/src/session.rs 中的实现逐字一致 ----
fn pw_allowed(sel: &HashSet<String>, on: bool, name: &str) -> bool {
    if !on {
        return true;
    }
    sel.contains(name)
}

fn pw_select_all(sel: &mut HashSet<String>, on: &mut bool) {
    sel.clear();
    *on = false;
}

fn pw_select_none(sel: &mut HashSet<String>, on: &mut bool) {
    sel.clear();
    *on = true;
}

fn pw_invert(sel: &mut HashSet<String>, on: &mut bool, all: &[String]) {
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

fn pw_toggle(sel: &mut HashSet<String>, on: &mut bool, all: &[String], name: &str, checked: bool) {
    if !*on {
        *sel = all.iter().cloned().collect();
        *on = true;
    }
    if checked {
        sel.insert(name.to_string());
    } else {
        sel.remove(name);
    }
    if !all.is_empty() && all.iter().all(|n| sel.contains(n)) {
        pw_select_all(sel, on);
    }
}

fn main() {
    let all: Vec<String> = ["COM1", "COM2", "COM6", "COM7"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let mut fails = 0;
    macro_rules! check {
        ($cond:expr, $msg:expr) => {
            if $cond {
                println!("  ok   {}", $msg);
            } else {
                println!("  FAIL {}", $msg);
                fails += 1;
            }
        };
    }

    println!("1. 默认状态：不限制，全部放行");
    let mut sel = HashSet::new();
    let mut on = false;
    for p in &all {
        check!(pw_allowed(&sel, on, p), format!("{p} 放行"));
    }

    println!("2. 取消勾选 COM7：COM6 放行、COM7 丢弃（用户验收场景）");
    pw_toggle(&mut sel, &mut on, &all, "COM7", false);
    check!(on, "过滤已启用");
    check!(pw_allowed(&sel, on, "COM6"), "COM6 放行");
    check!(!pw_allowed(&sel, on, "COM7"), "COM7 丢弃");
    check!(pw_allowed(&sel, on, "COM1"), "COM1 仍放行");

    println!("3. 勾回 COM7：回到不限制");
    pw_toggle(&mut sel, &mut on, &all, "COM7", true);
    check!(!on, "回到不限制状态");
    for p in &all {
        check!(pw_allowed(&sel, on, p), format!("{p} 放行"));
    }

    println!("4. 取消选择：一个都不看（on=true + 空集合）");
    let mut sel = HashSet::new();
    let mut on = false;
    pw_select_none(&mut sel, &mut on);
    check!(on && sel.is_empty(), "状态 = 启用且空集合");
    for p in &all {
        check!(!pw_allowed(&sel, on, p), format!("{p} 丢弃"));
    }

    println!("5. 全选：恢复不限制（与「取消选择」必须不同）");
    let mut sel = HashSet::new();
    let mut on = false;
    pw_select_none(&mut sel, &mut on);
    pw_select_all(&mut sel, &mut on);
    check!(!on, "过滤关闭");
    for p in &all {
        check!(pw_allowed(&sel, on, p), format!("{p} 放行"));
    }

    println!("6. 反选两次回到原状态");
    let mut sel = HashSet::new();
    let mut on = false;
    pw_toggle(&mut sel, &mut on, &all, "COM1", false); // 剩 COM2/COM6/COM7
    let before: HashSet<String> = sel.clone();
    pw_invert(&mut sel, &mut on, &all);
    let after1: HashSet<String> = sel.clone();
    pw_invert(&mut sel, &mut on, &all);
    let after2: HashSet<String> = sel.clone();
    check!(before != after1, "第一次反选改变了集合");
    check!(before == after2, "第二次反选回到原集合");

    println!("7. 只留一个端口");
    let mut sel = HashSet::new();
    let mut on = false;
    for p in &["COM2", "COM6", "COM7"] {
        pw_toggle(&mut sel, &mut on, &all, p, false);
    }
    check!(on, "已启用");
    check!(pw_allowed(&sel, on, "COM1"), "COM1 放行");
    for p in &["COM2", "COM6", "COM7"] {
        check!(!pw_allowed(&sel, on, p), format!("{p} 丢弃"));
    }

    println!("8. 白名单里有已不存在的端口名（过时配置）不应崩溃");
    let mut sel: HashSet<String> = ["COM99"].iter().map(|s| s.to_string()).collect();
    let on = true;
    check!(!pw_allowed(&sel, on, "COM1"), "COM1 不在白名单 → 丢弃");
    check!(pw_allowed(&sel, on, "COM99"), "COM99 在白名单 → 放行");
    sel.clear();

    println!();
    if fails == 0 {
        println!("PASS: 端口白名单语义全部通过");
    } else {
        println!("FAIL: {fails} 项未通过");
        std::process::exit(1);
    }
}
