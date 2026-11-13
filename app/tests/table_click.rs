// Headless UI test for Table row selection.
//
// Two regressions motivate this file:
//   1. Row selection once worked only via a `SelectableLabel` in the first column.
//   2. Making the *row* the click target via `TableRow::response()` broke it completely,
//      because `response()` is the union of the cells' responses and a plain `ui.label`
//      only senses hover — so `clicked()` was always false.
//
// The contract these tests pin: every cell must be a `SelectableLabel` so a click on any
// column selects the row, and the row response alone must NOT be relied on.

use egui_extras::{Column, TableBuilder};

const ROWS: usize = 3;

/// Build a table shaped like the monitor's, recording which row (if any) was clicked.
/// `clickable_cells` toggles between the fixed and the broken implementation.
fn run_table(
    ctx: &egui::Context,
    clickable_cells: bool,
    row_rects: &mut Vec<egui::Rect>,
    hit: &mut Option<usize>,
) {
    egui::CentralPanel::default().show(ctx, |ui| {
        TableBuilder::new(ui)
            .striped(true)
            .vscroll(true)
            .column(Column::initial(60.0))
            .column(Column::initial(120.0))
            .column(Column::remainder())
            .header(20.0, |mut h| {
                h.col(|ui| {
                    ui.label("seq");
                });
                h.col(|ui| {
                    ui.label("time");
                });
                h.col(|ui| {
                    ui.label("data");
                });
            })
            .body(|mut body| {
                for i in 0..ROWS {
                    body.row(20.0, |mut row| {
                        let mut clicked_here = false;
                        row.col(|ui| {
                            if clickable_cells {
                                clicked_here |= ui
                                    .add(egui::SelectableLabel::new(false, format!("{i}")))
                                    .clicked();
                            } else {
                                ui.label(format!("{i}"));
                            }
                        });
                        row.col(|ui| {
                            if clickable_cells {
                                clicked_here |= ui
                                    .add(egui::SelectableLabel::new(false, "12:00:00"))
                                    .clicked();
                            } else {
                                ui.label("12:00:00");
                            }
                        });
                        row.col(|ui| {
                            if clickable_cells {
                                clicked_here |= ui
                                    .add(egui::SelectableLabel::new(false, "payload"))
                                    .clicked();
                            } else {
                                ui.label("payload");
                            }
                        });
                        if !clickable_cells && row.response().clicked() {
                            // The broken implementation relied on this instead.
                            clicked_here = true;
                        }
                        if row_rects.len() <= i {
                            row_rects.push(row.response().rect);
                        }
                        if clicked_here {
                            *hit = Some(i);
                        }
                    });
                }
            });
    });
}

fn input(events: Vec<egui::Event>) -> egui::RawInput {
    let mut i = egui::RawInput::default();
    i.screen_rect = Some(egui::Rect::from_min_size(
        egui::Pos2::ZERO,
        egui::vec2(400.0, 200.0),
    ));
    i.events = events;
    i
}

/// Click at `target` and return which row (if any) reported the click.
fn click_at(clickable_cells: bool, target: impl Fn(egui::Rect) -> egui::Pos2) -> Option<usize> {
    let ctx = egui::Context::default();
    let mut rects: Vec<egui::Rect> = Vec::new();
    let mut hit = None;

    // Layout pass: learn where the rows are instead of guessing panel paddings.
    let _ = ctx.run(input(vec![]), |c| {
        run_table(c, clickable_cells, &mut rects, &mut hit)
    });
    assert_eq!(
        rects.len(),
        ROWS,
        "expected {ROWS} body rows, got {:?}",
        rects
    );
    let pos = target(rects[1]);

    for events in [
        vec![egui::Event::PointerMoved(pos)],
        vec![
            egui::Event::PointerMoved(pos),
            egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: Default::default(),
            },
        ],
        vec![egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed: false,
            modifiers: Default::default(),
        }],
    ] {
        hit = None;
        let _ = ctx.run(input(events), |c| {
            run_table(c, clickable_cells, &mut rects, &mut hit)
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

#[test]
fn clicking_any_column_selects_the_row() {
    // Second column (时间) — previously not clickable at all.
    assert_eq!(
        click_at(true, |r| egui::pos2(r.min.x + 90.0, r.center().y)),
        Some(1)
    );
    // Third column (数据).
    assert_eq!(
        click_at(true, |r| egui::pos2(r.min.x + 250.0, r.center().y)),
        Some(1)
    );
    // First column (序号) — the one that always worked.
    assert_eq!(
        click_at(true, |r| egui::pos2(r.min.x + 20.0, r.center().y)),
        Some(1)
    );
}

/// The exact regression: relying on the row's own response never reports a click, because
/// plain labels only sense hover.
#[test]
fn row_response_alone_does_not_select_anything() {
    assert_eq!(
        click_at(false, |r| egui::pos2(r.min.x + 90.0, r.center().y)),
        None,
        "TableRow::response() must not be relied on for row selection"
    );
}
