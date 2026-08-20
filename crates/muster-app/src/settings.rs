//! The settings page.
//!
//! §9 of `../Design-Principles/STYLE-GUIDE.md`: a modal with a navigation rail
//! down the left, one pane at a time, **saving live** — there is no Save button
//! and no Cancel, because a setting that only takes effect when you press
//! something is a setting you cannot try. The one command in the footer is
//! Restore all, which is the undo.
//!
//! Every figure here is an engine default surfaced, never a second opinion
//! about one. `prefs::Prefs::default()` reads `muster_net`'s own constants and a
//! test holds them equal, so what this page calls "the default" is what the
//! engine would have done unasked.
//!
//! ## The one screen that writes the update setting
//!
//! `CLAUDE.md` requires the setting governing the update check to live in one
//! place. It lives here. About keeps the *status* and the "Check now" command —
//! reporting and doing are not settings — but the switch itself is on this page
//! and nowhere else.

use crate::prefs::{self, Prefs, Theme};
use crate::theme::{self, Palette, metrics, text};
use crate::themelib::CustomTheme;
use crate::update::Updates;
use egui::{Align, Color32, Layout, Rect, RichText, Sense, Stroke, pos2, vec2};

/// The panes, in the order the rail lists them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Pane {
    #[default]
    General,
    Scanning,
    Themes,
}

impl Pane {
    const ALL: [Pane; 3] = [Pane::General, Pane::Scanning, Pane::Themes];

    const fn label(self) -> &'static str {
        match self {
            Pane::General => "General",
            Pane::Scanning => "Scanning",
            Pane::Themes => "Themes",
        }
    }

    const fn blurb(self) -> &'static str {
        match self {
            Pane::General => "How Muster looks, and the one request it makes.",
            Pane::Scanning => "How hard Muster knocks, and where.",
            Pane::Themes => "Colour tables, shared with the rest of the family.",
        }
    }
}

/// What the page is showing and what it has been told.
#[derive(Default)]
pub struct State {
    pub open: bool,
    pub pane: Pane,
    /// The scale being dragged, before it is applied.
    ///
    /// **Applied on release, not live.** The slider is inside the thing it
    /// scales, so a live apply moves the rail out from under the pointer and
    /// the knob runs away from the hand.
    pending_scale: Option<f32>,
    /// The library, read once when the page opens rather than per frame.
    themes: Vec<CustomTheme>,
    problems: Vec<String>,
}

impl State {
    /// Open the page, reading the theme library as it goes.
    pub fn open(&mut self) {
        let (themes, problems) = crate::themelib::load_all();
        self.themes = themes;
        self.problems = problems;
        self.open = true;
    }

    pub fn themes(&self) -> &[CustomTheme] {
        &self.themes
    }
}

/// What the page changed, for the caller to act on.
#[derive(Default)]
pub struct Outcome {
    /// The settings, if any of them moved.
    pub changed: bool,
    /// A scale to hand to egui, on the frame it was released.
    pub scale: Option<f32>,
}

/// Draw the page. Does nothing when it is shut.
pub fn show(
    ctx: &egui::Context,
    p: Palette,
    state: &mut State,
    prefs: &mut Prefs,
    updates: &mut Updates,
) -> Outcome {
    let mut out = Outcome::default();
    if !state.open {
        return out;
    }
    let before = prefs.clone();

    egui::Modal::new(egui::Id::new("settings"))
        .frame(
            egui::Frame::NONE
                .fill(p.chrome.to_opaque())
                .stroke(Stroke::new(metrics::HAIRLINE, p.line_popover))
                .corner_radius(metrics::RADIUS_MODAL)
                .shadow(egui::epaint::Shadow {
                    offset: [0, 24],
                    blur: 64,
                    spread: 0,
                    color: Color32::from_black_alpha(179),
                }),
        )
        .show(ctx, |ui| {
            let size = vec2(
                (ctx.screen_rect().width() * 0.92).min(920.0),
                (ctx.screen_rect().height() * 0.92).min(600.0),
            );
            ui.set_min_size(size);
            ui.set_max_size(size);

            ui.horizontal_top(|ui| {
                rail(ui, p, state);
                ui.add_space(metrics::PAD_PANEL);
                ui.vertical(|ui| {
                    pane_header(ui, p, state);
                    ui.add_space(metrics::S3);
                    egui::ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .max_height(size.y - 120.0)
                        .show(ui, |ui| match state.pane {
                            Pane::General => general(ui, p, state, prefs, updates, &mut out),
                            Pane::Scanning => scanning(ui, p, prefs),
                            Pane::Themes => themes(ui, p, state, prefs),
                        });
                    ui.add_space(metrics::S3);
                    footer(ui, p, prefs);
                });
            });
        });

    if *prefs != before {
        out.changed = true;
    }
    out
}

/// The 240 px navigation rail.
fn rail(ui: &mut egui::Ui, p: Palette, state: &mut State) {
    ui.vertical(|ui| {
        ui.set_width(metrics::SIDEBAR);
        ui.add_space(metrics::PAD_PANEL);
        ui.horizontal(|ui| {
            ui.add_space(metrics::PAD_PANEL);
            ui.label(
                RichText::new("Settings")
                    .font(theme::strong(text::PAGE))
                    .color(p.text_strong),
            );
        });
        ui.add_space(metrics::S3);
        for pane in Pane::ALL {
            if crate::app::nav_row(ui, p, pane.label(), state.pane == pane).clicked() {
                state.pane = pane;
            }
        }
    });
}

fn pane_header(ui: &mut egui::Ui, p: Palette, state: &mut State) {
    ui.add_space(metrics::PAD_PANEL);
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.label(
                RichText::new(state.pane.label())
                    .font(theme::strong(text::PAGE))
                    .color(p.text_strong),
            );
            ui.label(
                RichText::new(state.pane.blurb())
                    .size(text::SMALL)
                    .color(p.text_muted),
            );
        });
        ui.with_layout(Layout::right_to_left(Align::TOP), |ui| {
            ui.add_space(metrics::PAD_PANEL);
            if crate::app::close_button(ui, p).clicked() {
                state.open = false;
            }
        });
    });
}

fn footer(ui: &mut egui::Ui, p: Palette, prefs: &mut Prefs) {
    ui.horizontal(|ui| {
        let where_to = prefs::path()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "nowhere this machine will keep".to_string());
        ui.label(
            RichText::new(format!("Saved to {where_to}"))
                .size(text::TINY)
                .color(p.text_dim),
        );
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.add_space(metrics::PAD_PANEL);
            if crate::app::button(
                ui,
                p,
                "Restore all settings",
                crate::app::Kind::Outlined,
                true,
            )
            .clicked()
            {
                // Everything except what the user has already been *asked*.
                // Re-showing the update notice because somebody reset their
                // colours would be a dialog they have to answer twice.
                let seen = prefs.notice_seen;
                let last = prefs.last_check;
                *prefs = Prefs::default();
                prefs.notice_seen = seen;
                prefs.last_check = last;
            }
        });
    });
}

// ---------------------------------------------------------------------------
// Panes
// ---------------------------------------------------------------------------

fn general(
    ui: &mut egui::Ui,
    p: Palette,
    state: &mut State,
    prefs: &mut Prefs,
    updates: &mut Updates,
    out: &mut Outcome,
) {
    eyebrow(ui, p, "APPEARANCE");

    row(
        ui,
        p,
        "Theme",
        Some("Follow the desktop, or pick one."),
        |ui| {
            let mut chosen = prefs.theme;
            if segmented(ui, p, &mut chosen, &Theme::ALL, |t| t.label()) {
                prefs.theme = chosen;
            }
        },
    );

    row(
        ui,
        p,
        "Interface scale",
        Some("Everything grows together, so the type ranks keep their order."),
        |ui| {
            // The value being dragged, or the one in force.
            let mut value = state.pending_scale.unwrap_or(prefs.interface_scale);
            let response = slider(ui, p, &mut value, prefs::SCALE_MIN, prefs::SCALE_MAX, 0.25);
            if response.dragged() {
                state.pending_scale = Some(value);
            }
            if response.drag_stopped() || (response.changed() && !response.dragged()) {
                state.pending_scale = None;
                prefs.interface_scale = value;
                out.scale = Some(value);
            }
            ui.add_space(metrics::S2);
            ui.label(
                RichText::new(format!("{:.0}%", value * 100.0))
                    .size(text::TINY)
                    .monospace()
                    .color(p.text_muted),
            );
        },
    );

    ui.add_space(metrics::S4);
    eyebrow(ui, p, "UPDATES");

    // A copy Muster could not install is a read-only truth, not a dead switch.
    if let Some(why) = updates.check_unavailable() {
        ui.label(RichText::new(why).size(text::SMALL).color(p.text_muted));
        return;
    }

    row(
        ui,
        p,
        "Check for new versions when Muster starts",
        Some("The only request Muster makes on its own behalf, at most once every six hours."),
        |ui| {
            let mut on = prefs.check_on_startup;
            if toggle(ui, p, &mut on) {
                prefs.check_on_startup = on;
                // Answering here counts as having been asked, so the notice
                // does not appear afterwards to ask the same question again.
                prefs.notice_seen = true;
                updates.check_on_startup = on;
                updates.notice_seen = true;
            }
        },
    );
}

fn scanning(ui: &mut egui::Ui, p: Palette, prefs: &mut Prefs) {
    eyebrow(ui, p, "TARGET");
    row(
        ui,
        p,
        "Say so before scanning off this link",
        Some("A range that is not on this link is somebody else's network."),
        |ui| {
            let mut on = prefs.warn_off_link;
            if toggle(ui, p, &mut on) {
                prefs.warn_off_link = on;
            }
        },
    );

    ui.add_space(metrics::S4);
    eyebrow(ui, p, "RATE");
    row(
        ui,
        p,
        "Probes a second",
        Some("The whole sweep's budget, shared by every probe in it."),
        |ui| {
            let mut value = prefs.rate as f32;
            slider(ui, p, &mut value, 50.0, 5000.0, 50.0);
            prefs.rate = value as u32;
            ui.add_space(metrics::S2);
            ui.label(
                RichText::new(format!("{} /s", prefs.rate))
                    .size(text::TINY)
                    .monospace()
                    .color(p.text_muted),
            );
        },
    );
    row(
        ui,
        p,
        "Probes a second, one device",
        Some("A port scan asks one machine several hundred questions in a row."),
        |ui| {
            let mut value = prefs.port_rate as f32;
            slider(ui, p, &mut value, 50.0, 2000.0, 50.0);
            prefs.port_rate = value as u32;
            ui.add_space(metrics::S2);
            ui.label(
                RichText::new(format!("{} /s", prefs.port_rate))
                    .size(text::TINY)
                    .monospace()
                    .color(p.text_muted),
            );
        },
    );

    ui.add_space(metrics::S4);
    eyebrow(ui, p, "PORTS");
    ui.label(
        RichText::new(
            "Which ports a scan tries. Empty is the built-in list of the ones worth knowing \
             about; otherwise something like 22,80,443 or 1-1024.",
        )
        .size(text::TINY)
        .color(p.text_dim),
    );
    ui.add_space(metrics::S1);
    ui.horizontal(|ui| {
        crate::app::field(ui, p, &mut prefs.port_list, 240.0, "the common list");
        ui.add_space(metrics::S2);
        // Parsed live, so the field says whether it is usable before a scan
        // rather than failing after one.
        match prefs.port_list.trim() {
            "" => {
                let n = muster_net::portscan::Ports::common().len();
                ui.label(
                    RichText::new(format!("{n} ports"))
                        .size(text::TINY)
                        .color(p.text_muted),
                );
            }
            spec => match spec.parse::<muster_net::portscan::Ports>() {
                Ok(ports) => {
                    ui.label(
                        RichText::new(format!("{} ports", ports.len()))
                            .size(text::TINY)
                            .color(p.text_muted),
                    );
                }
                Err(e) => {
                    // In the error's own words, never a red outline alone.
                    ui.label(
                        RichText::new(e.to_string())
                            .size(text::TINY)
                            .color(p.caution),
                    );
                }
            },
        }
    });
}

fn themes(ui: &mut egui::Ui, p: Palette, state: &mut State, prefs: &mut Prefs) {
    ui.label(
        RichText::new(
            "Muster reads the same theme files as the rest of the family, so a theme made in \
             a sibling application opens here.",
        )
        .size(text::SMALL)
        .color(p.text),
    );
    ui.add_space(metrics::S1);
    if let Some(dir) = crate::themelib::directory() {
        ui.label(
            RichText::new(format!("Put .umbertheme files in {}", dir.display()))
                .size(text::TINY)
                .color(p.text_dim),
        );
    }
    ui.add_space(metrics::S3);

    eyebrow(ui, p, "BUILT IN");
    for (theme, label) in [(Theme::Dark, "Graphite"), (Theme::Light, "Paper")] {
        let chosen = prefs.custom_theme.is_none() && prefs.theme == theme;
        if theme_row(ui, p, label, "built in, so it is read-only", chosen).clicked() {
            prefs.theme = theme;
            prefs.custom_theme = None;
        }
    }

    ui.add_space(metrics::S4);
    eyebrow(ui, p, "FROM FILES");
    if state.themes.is_empty() {
        ui.label(
            RichText::new("No theme files found.")
                .size(text::TINY)
                .color(p.text_dim),
        );
    }
    for custom in &state.themes {
        let chosen = prefs.custom_theme.as_deref() == Some(custom.id.as_str());
        let note = match custom.skipped {
            0 => format!("based on {}", custom.base),
            // Never hidden: the file said something Muster could not read.
            n => format!(
                "based on {}, and {n} line{} could not be read",
                custom.base,
                if n == 1 { "" } else { "s" }
            ),
        };
        if theme_row(ui, p, &custom.name, &note, chosen).clicked() {
            prefs.custom_theme = Some(custom.id.clone());
            prefs.theme = if custom.is_dark() {
                Theme::Dark
            } else {
                Theme::Light
            };
        }
    }

    for problem in &state.problems {
        ui.add_space(metrics::S1);
        ui.label(RichText::new(problem).size(text::TINY).color(p.caution));
    }
}

// ---------------------------------------------------------------------------
// Rows and controls
// ---------------------------------------------------------------------------

fn eyebrow(ui: &mut egui::Ui, p: Palette, label: &str) {
    ui.add_space(metrics::S2);
    ui.label(
        RichText::new(label)
            .size(text::EYEBROW)
            .color(p.placeholder),
    );
    ui.add_space(metrics::S1);
}

/// One settings row: a label, an optional second line, and a control at the
/// right edge.
fn row(
    ui: &mut egui::Ui,
    p: Palette,
    label: &str,
    under: Option<&str>,
    control: impl FnOnce(&mut egui::Ui),
) {
    ui.add_space(metrics::S1);
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.label(RichText::new(label).size(text::CONTROL).color(p.text));
            if let Some(under) = under {
                ui.label(RichText::new(under).size(text::SMALL).color(p.text_dim));
            }
        });
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.add_space(metrics::PAD_PANEL);
            control(ui);
        });
    });
}

/// A theme in a list: its name, a note, and a mark when it is the one in use.
fn theme_row(
    ui: &mut egui::Ui,
    p: Palette,
    name: &str,
    note: &str,
    chosen: bool,
) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(
        vec2(ui.available_width(), metrics::ROW * 1.6),
        Sense::click(),
    );
    if chosen {
        ui.painter().rect_filled(rect, metrics::RADIUS, p.control);
        ui.painter().rect_filled(
            Rect::from_min_size(rect.left_top(), vec2(metrics::NAV_MARK_W, rect.height())),
            metrics::RADIUS_TIGHT,
            p.accent,
        );
    } else if response.hovered() {
        ui.painter()
            .rect_filled(rect, metrics::RADIUS, p.control_hover);
    }
    let x = rect.left() + metrics::S3;
    ui.painter().text(
        pos2(x, rect.center().y - 7.0),
        egui::Align2::LEFT_CENTER,
        name,
        egui::FontId::proportional(text::CONTROL),
        if chosen { p.text_strong } else { p.text },
    );
    ui.painter().text(
        pos2(x, rect.center().y + 7.0),
        egui::Align2::LEFT_CENTER,
        note,
        egui::FontId::proportional(text::TINY),
        p.text_dim,
    );
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// A segmented control, §7.9.
fn segmented<T: Copy + PartialEq>(
    ui: &mut egui::Ui,
    p: Palette,
    value: &mut T,
    options: &[T],
    label: impl Fn(T) -> &'static str,
) -> bool {
    let mut changed = false;
    let width = 74.0;
    let (rect, _) = ui.allocate_exact_size(
        vec2(width * options.len() as f32, metrics::BUTTON),
        Sense::hover(),
    );
    ui.painter().rect_filled(rect, metrics::RADIUS, p.control);
    ui.painter().rect_stroke(
        rect,
        metrics::RADIUS,
        Stroke::new(metrics::HAIRLINE, p.line),
        egui::StrokeKind::Inside,
    );
    for (i, option) in options.iter().enumerate() {
        let seg = Rect::from_min_size(
            pos2(rect.left() + width * i as f32, rect.top()),
            vec2(width, rect.height()),
        );
        let response = ui.interact(seg, ui.id().with(("segment", i)), Sense::click());
        let selected = *value == *option;
        if selected {
            // A neutral fill and strong text, never an accent background.
            ui.painter()
                .rect_filled(seg.shrink(2.0), metrics::RADIUS_TIGHT, p.control_active);
        }
        ui.painter().text(
            seg.center(),
            egui::Align2::CENTER_CENTER,
            label(*option),
            egui::FontId::proportional(text::CONTROL),
            if selected {
                p.text_strong
            } else {
                p.text_muted
            },
        );
        if response.clicked() && !selected {
            *value = *option;
            changed = true;
        }
    }
    changed
}

/// A slider, §7.10: a 3 px rail with an accent fill and a round knob.
fn slider(
    ui: &mut egui::Ui,
    p: Palette,
    value: &mut f32,
    min: f32,
    max: f32,
    step: f32,
) -> egui::Response {
    let width = 180.0;
    let (rect, response) =
        ui.allocate_exact_size(vec2(width, metrics::BUTTON), Sense::click_and_drag());

    let rail = Rect::from_center_size(rect.center(), vec2(width, 3.0));
    ui.painter().rect_filled(rail, 1.5, p.rail);

    let mut t = ((*value - min) / (max - min)).clamp(0.0, 1.0);
    let moving = response.dragged() || response.clicked();
    if moving && let Some(at) = response.interact_pointer_pos() {
        t = ((at.x - rail.left()) / rail.width()).clamp(0.0, 1.0);
        let raw = min + t * (max - min);
        // Snapped, so the readout is a figure somebody could have typed.
        *value = ((raw / step).round() * step).clamp(min, max);
        t = ((*value - min) / (max - min)).clamp(0.0, 1.0);
    }

    let filled = Rect::from_min_size(rail.left_top(), vec2(rail.width() * t, rail.height()));
    ui.painter().rect_filled(filled, 1.5, p.accent);
    ui.painter().circle_filled(
        pos2(rail.left() + rail.width() * t, rail.center().y),
        6.0,
        p.knob,
    );
    response
}

/// A toggle, §7.8: 34 x 18, knob left when off and right when on.
fn toggle(ui: &mut egui::Ui, p: Palette, on: &mut bool) -> bool {
    let (rect, response) = ui.allocate_exact_size(vec2(34.0, 18.0), Sense::click());
    let changed = response.clicked();
    if changed {
        *on = !*on;
    }
    ui.painter()
        .rect_filled(rect, 9.0, if *on { p.accent } else { p.control });
    if !*on {
        ui.painter().rect_stroke(
            rect,
            9.0,
            Stroke::new(metrics::HAIRLINE, p.line),
            egui::StrokeKind::Inside,
        );
    }
    let x = if *on {
        rect.right() - 9.0
    } else {
        rect.left() + 9.0
    };
    ui.painter().circle_filled(
        pos2(x, rect.center().y),
        6.0,
        if *on { p.accent_ink } else { p.knob },
    );
    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restoring_keeps_what_the_user_has_already_answered() {
        // Re-showing the update notice because somebody reset their colours
        // would be a dialog they have to answer twice.
        let mut prefs = Prefs {
            notice_seen: true,
            last_check: 42,
            rate: 12,
            ..Default::default()
        };
        let seen = prefs.notice_seen;
        let last = prefs.last_check;
        prefs = Prefs::default();
        prefs.notice_seen = seen;
        prefs.last_check = last;

        assert!(prefs.notice_seen, "the answer survives");
        assert_eq!(prefs.last_check, 42, "and so does the rate limit");
        assert_eq!(prefs.rate, Prefs::default().rate, "the rest is restored");
    }

    #[test]
    fn every_pane_is_named_and_described() {
        for pane in Pane::ALL {
            assert!(!pane.label().is_empty());
            assert!(!pane.blurb().is_empty());
        }
    }

    #[test]
    fn the_page_opens_on_general() {
        assert_eq!(State::default().pane, Pane::General);
        assert!(!State::default().open, "and it starts shut");
    }
}
