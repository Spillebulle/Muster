//! The update dialog.
//!
//! [`crate::update::flow`] is the model — which screen, which stage, how many
//! seconds are left — and this file draws it and nothing else. Everything the
//! dialog decides is decided over there, where a test can reach it without a
//! window, and that is the same division `installwin.rs` keeps against
//! `installer.rs`.
//!
//! Three rules from the design language shape what is drawn, and each of them
//! is a way this dialog would otherwise lie:
//!
//! * **The bar never animates over an unknown.** [`Stage::progress`] returns
//!   `None` while Windows Installer works, and that draws an empty track. A
//!   creeping bar there would be an invention about somebody's installation.
//! * **Nothing says "verified".** Muster does not sign its releases. The words
//!   on screen are the address, HTTPS and a length, because that is the whole
//!   of the guarantee, and `crates/muster-desktop/tests/release.rs` fails the
//!   build if the word appears in a stage label.
//! * **One primary button per screen**, accent-filled, and it is whichever
//!   action the screen exists for.
//!
//! The first-run notice is here too, and it comes before any request goes out:
//! `CLAUDE.md` allows exactly one outbound request on Muster's own behalf and
//! requires that the user has been asked first.

use crate::theme::{Palette, metrics, text};
use crate::update::flow::Phase;
use crate::update::{Status, Updates};
use egui::{Align, Layout, RichText, Sense, Stroke, vec2};
use std::time::Instant;

/// The dialog's width. Wide enough for a release note to read as prose and
/// narrow enough that it is plainly a dialog rather than a second window.
const WIDTH: f32 = 460.0;

/// How tall the release notes may grow before they scroll.
const NOTES_HEIGHT: f32 = 160.0;

/// Draw whatever the update machinery currently has to say.
///
/// Called once a frame from [`crate::app::App::update`]. Draws nothing at all
/// in the ordinary case, which is the common one: no notice outstanding and no
/// dialog open.
pub fn show(ctx: &egui::Context, p: Palette, updates: &mut Updates) {
    if !updates.notice_seen {
        notice(ctx, p, updates);
        return;
    }
    if updates.flow().is_some() {
        dialog(ctx, p, updates);
    }
}

/// The first-run notice: what the check does, before it has been done.
///
/// Not a dialog about a feature. It is the consent `CLAUDE.md` requires, so it
/// says what leaves the machine, and both answers are real: Yes switches the
/// check on, No switches it off and neither leaves it ambiguous.
fn notice(ctx: &egui::Context, p: Palette, updates: &mut Updates) {
    modal(ctx, p, "update-notice", |ui| {
        heading(ui, p, "Checking for new versions");
        ui.add_space(metrics::S2);
        ui.label(
            RichText::new(
                "Muster can ask GitHub whether a newer version has been released, once, \
                 when it starts. That is the only request Muster makes on its own behalf: \
                 nothing about your network, the devices on it or this machine is sent \
                 anywhere, ever.",
            )
            .size(text::BODY)
            .color(p.text),
        );
        ui.add_space(metrics::S2);
        ui.label(
            RichText::new("You can change this later in About.")
                .size(text::SMALL)
                .color(p.text_muted),
        );
        ui.add_space(metrics::S4);

        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if button(ui, p, "Check for updates", true).clicked() {
                updates.notice_seen = true;
                updates.check_on_startup = true;
                persist(updates);
            }
            if button(ui, p, "Do not check", false).clicked() {
                updates.notice_seen = true;
                updates.check_on_startup = false;
                persist(updates);
            }
        });
    });
}

/// The dialog proper, on whichever screen the flow is on.
fn dialog(ctx: &egui::Context, p: Palette, updates: &mut Updates) {
    let now = Instant::now();
    // Read before anything is drawn: the phase and the release are borrowed
    // from `updates`, and the buttons below need it mutably.
    let Some(flow) = updates.flow() else { return };
    let phase = flow.phase().clone();
    let version = flow.release.version.to_string();
    let notes = flow.release.notes.clone();
    let page = flow.release.page.clone();
    let actions = updates.actions(&updates.flow().expect("checked above").release.clone());
    let holds_work = updates.busy();

    modal(ctx, p, "update", |ui| match &phase {
        Phase::Offer => {
            heading(ui, p, &format!("Muster {version} is available"));
            ui.add_space(metrics::S2);
            release_notes(ui, p, &notes);

            if let Some(obstacle) = &actions.obstacle {
                ui.add_space(metrics::S2);
                ui.label(RichText::new(obstacle).size(text::SMALL).color(p.caution));
            } else if actions.no_build {
                ui.add_space(metrics::S2);
                ui.label(
                    RichText::new(
                        "That release carries no build for this machine. The releases page \
                         has everything it does carry.",
                    )
                    .size(text::SMALL)
                    .color(p.caution),
                );
            }

            ui.add_space(metrics::S4);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if actions.update_now && button(ui, p, "Update now", true).clicked() {
                    updates.install_offered();
                }
                if actions.open_page && button(ui, p, "Open the releases page", true).clicked() {
                    crate::update::open_in_browser(&page);
                }
                if button(ui, p, "Not now", false).clicked() {
                    updates.dismiss();
                }
                if button(ui, p, "Never ask again", false).clicked() {
                    updates.never_ask_again();
                    persist(updates);
                }
            });
        }

        Phase::Working(stage) | Phase::Stopping(stage) => {
            heading(ui, p, &format!("Updating to {version}"));
            ui.add_space(metrics::S3);
            progress(ui, p, stage.progress());
            ui.add_space(metrics::S2);
            let label = match phase {
                Phase::Stopping(_) => "Stopping...".to_string(),
                _ => stage.label(),
            };
            ui.label(RichText::new(label).size(text::BODY).color(p.text));
            ui.add_space(metrics::S4);

            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                // Only while stopping would still leave the installation
                // untouched. Past that the button is taken off the screen
                // rather than offered and refused.
                if matches!(phase, Phase::Working(_))
                    && stage.can_stop()
                    && button(ui, p, "Cancel", false).clicked()
                {
                    updates.stop_update();
                }
            });
            ui.ctx().request_repaint();
        }

        Phase::Stopped => {
            heading(ui, p, "The update was stopped");
            ui.add_space(metrics::S2);
            ui.label(
                RichText::new("Nothing was written. Muster is the version you had.")
                    .size(text::BODY)
                    .color(p.text),
            );
            ui.add_space(metrics::S4);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if button(ui, p, "Try again", true).clicked() {
                    updates.retry();
                }
                if button(ui, p, "Close", false).clicked() {
                    updates.dismiss();
                }
            });
        }

        Phase::Done { outcome, countdown } => {
            heading(ui, p, &format!("Muster {version} is ready"));
            ui.add_space(metrics::S2);
            let what = match outcome {
                crate::update::Applied::Restart => {
                    "Muster will close and start again on the new version."
                }
                crate::update::Applied::Installer => {
                    "Windows will finish the installation once Muster closes."
                }
            };
            ui.label(RichText::new(what).size(text::BODY).color(p.text));

            if let Some(left) = countdown.seconds_left(now) {
                ui.add_space(metrics::S1);
                ui.label(
                    RichText::new(format!("Closing in {left} s"))
                        .size(text::TINY)
                        .color(p.text_dim)
                        .monospace(),
                );
                ui.ctx()
                    .request_repaint_after(std::time::Duration::from_millis(200));
            }

            ui.add_space(metrics::S4);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if countdown.running() && button(ui, p, "Wait", false).clicked() {
                    updates.cancel_countdown();
                }
            });
        }

        Phase::Failed(why) => {
            heading(ui, p, "The update did not finish");
            ui.add_space(metrics::S2);
            ui.label(RichText::new(why).size(text::BODY).color(p.text));
            ui.add_space(metrics::S2);
            ui.label(
                RichText::new("Muster is still the version you had.")
                    .size(text::SMALL)
                    .color(p.text_muted),
            );
            ui.add_space(metrics::S4);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if button(ui, p, "Try again", true).clicked() {
                    updates.retry();
                }
                if button(ui, p, "Open the releases page", false).clicked() {
                    crate::update::open_in_browser(&page);
                }
                if button(ui, p, "Close", false).clicked() {
                    updates.dismiss();
                }
            });
        }
    });

    // Escape closes the dialog, except while something is in flight: a modal
    // that vanished mid-download would leave a worker with nothing on screen to
    // say so.
    if !holds_work && ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
        updates.dismiss();
    }
}

/// What the status line in About says, so a check the user asked for reports
/// where they asked it rather than throwing a modal at them.
pub fn status_line(status: &Status) -> String {
    match status {
        Status::Idle => "Not checked this run.".to_string(),
        Status::Checking => "Checking...".to_string(),
        Status::UpToDate => "This is the newest release.".to_string(),
        Status::Available(release) => format!("Muster {} is available.", release.version),
        Status::Failed(why) => why.clone(),
    }
}

// ---------------------------------------------------------------------------
// Drawing
// ---------------------------------------------------------------------------

/// A modal: the scrim, the popover fill, a hairline, and a shadow.
///
/// §5 allows a shadow only under something that floats, and a dialog is the
/// case it means.
fn modal(ctx: &egui::Context, p: Palette, id: &str, contents: impl FnOnce(&mut egui::Ui)) {
    egui::Modal::new(egui::Id::new(id))
        .frame(
            egui::Frame::NONE
                .fill(p.popover)
                .stroke(Stroke::new(metrics::HAIRLINE, p.line_popover))
                .corner_radius(metrics::RADIUS_MODAL)
                .inner_margin(egui::Margin::same(metrics::S4 as i8))
                .shadow(egui::epaint::Shadow {
                    offset: [0, 4],
                    blur: 16,
                    spread: 0,
                    color: egui::Color32::from_black_alpha(90),
                }),
        )
        .show(ctx, |ui| {
            ui.set_width(WIDTH);
            contents(ui);
        });
}

fn heading(ui: &mut egui::Ui, p: Palette, text: &str) {
    ui.label(
        RichText::new(text)
            .size(crate::theme::text::HEADING)
            .color(p.text_strong),
    );
}

/// The release's own notes, scrolling where they are long.
///
/// Shown rather than summarised: they are what the release says about itself,
/// and `CHANGELOG.md` is written to be read by the person this dialog is in
/// front of.
fn release_notes(ui: &mut egui::Ui, p: Palette, notes: &str) {
    if notes.trim().is_empty() {
        ui.label(
            RichText::new("That release published no notes.")
                .size(text::SMALL)
                .color(p.text_muted),
        );
        return;
    }
    egui::Frame::NONE
        .fill(p.field)
        .stroke(Stroke::new(metrics::HAIRLINE, p.line))
        .corner_radius(metrics::RADIUS)
        .inner_margin(egui::Margin::same(metrics::S2 as i8))
        .show(ui, |ui| {
            egui::ScrollArea::vertical()
                .max_height(NOTES_HEIGHT)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    ui.label(RichText::new(notes.trim()).size(text::SMALL).color(p.text));
                });
        });
}

/// A bar that draws empty when it does not know. See the module comment.
fn progress(ui: &mut egui::Ui, p: Palette, fraction: Option<f32>) {
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 4.0), Sense::hover());
    ui.painter().rect_filled(rect, 2.0, p.control);
    if let Some(f) = fraction {
        let filled = egui::Rect::from_min_size(
            rect.left_top(),
            vec2(rect.width() * f.clamp(0.0, 1.0), rect.height()),
        );
        ui.painter().rect_filled(filled, 2.0, p.accent);
    }
}

/// A button, drawn rather than egui's, and `primary` is the accent-filled one.
fn button(ui: &mut egui::Ui, p: Palette, label: &str, primary: bool) -> egui::Response {
    let ink = if primary { p.accent_ink } else { p.text };
    let galley = ui.painter().layout_no_wrap(
        label.to_string(),
        egui::FontId::proportional(text::CONTROL),
        ink,
    );
    let size = vec2(galley.size().x + metrics::S4 * 2.0, metrics::BUTTON);
    let (rect, response) = ui.allocate_exact_size(size, Sense::click());

    let fill = match (primary, response.hovered()) {
        (true, _) => p.accent,
        (false, true) => p.control_hover,
        (false, false) => p.control,
    };
    ui.painter().rect_filled(rect, metrics::RADIUS, fill);
    if !primary {
        ui.painter().rect_stroke(
            rect,
            metrics::RADIUS,
            Stroke::new(metrics::HAIRLINE, p.line),
            egui::StrokeKind::Inside,
        );
    }
    let at = egui::pos2(
        rect.center().x - galley.size().x / 2.0,
        rect.center().y - galley.size().y / 2.0,
    );
    ui.painter().galley(at, galley, ink);
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Write the two settings out. Called wherever an answer changes one of them.
fn persist(updates: &Updates) {
    crate::prefs::save(crate::prefs::Prefs {
        check_on_startup: updates.check_on_startup,
        notice_seen: updates.notice_seen,
    });
}
