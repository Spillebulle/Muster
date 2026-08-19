//! The window.
//!
//! The shell is §16 of `../Design-Principles/STYLE-GUIDE.md`: a 34 px top bar
//! carrying the accent mark, a 240 px sidebar of navigation rows, a 26 px status
//! bar, hairlines everywhere and shadows only under things that float. The
//! device list is the app, so it is a dense table of figures in the monospaced
//! face with its columns aligned.
//!
//! The rule that shapes most of what follows: **selection is a neutral fill plus
//! strong text plus a small accent mark, and never an accent background.** It is
//! the defect the whole design language exists to avoid, so it is drawn in one
//! place ([`nav_row`]) rather than at each call site.

use crate::scan::State;
use crate::theme::{Mode, Palette, metrics, text};
use crate::update::{Exit, Updates};
use crate::{prefs, updatedlg};
use egui::{Align, Color32, FontId, Layout, Rect, RichText, Sense, Stroke, Vec2, pos2, vec2};
use muster_net::identify::Identity;
use muster_net::{Prefix, Survey};

/// Which screen the sidebar has selected.
///
/// Public so `examples/docs-images.rs` can ask for a particular one. Nothing
/// else outside this module names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum View {
    Devices,
    Network,
    About,
}

impl View {
    pub const ALL: [Self; 3] = [Self::Devices, Self::Network, Self::About];

    fn label(self) -> &'static str {
        match self {
            Self::Devices => "Devices",
            Self::Network => "This network",
            Self::About => "About",
        }
    }
}

pub struct App {
    survey: Survey,
    scan: State,
    view: View,
    mode: Mode,
    /// The prefix the next scan will take. Derived from the survey, and the
    /// default target is the local prefix — never a range somebody typed.
    target: Option<Prefix>,
    /// The update check and the dialog it raises.
    ///
    /// Its two settings are loaded from [`prefs`] at start-up and written back
    /// wherever an answer changes one, which is what `CLAUDE.md` means by the
    /// setting living in one place.
    updates: Updates,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        install_fonts(&cc.egui_ctx);

        let survey = muster_net::survey();
        let target = survey.default_targets().first().copied();
        let mode = match cc.egui_ctx.style().visuals.dark_mode {
            true => Mode::Dark,
            false => Mode::Light,
        };

        let saved = prefs::load();
        let mut updates = Updates::default();
        updates.check_on_startup = saved.check_on_startup;
        updates.notice_seen = saved.notice_seen;
        // The check runs on a thread and reports through a channel, which is not
        // an event: without a waker the answer would sit there until the mouse
        // moved. eframe's context is the waker.
        let ctx = cc.egui_ctx.clone();
        updates.set_waker(std::sync::Arc::new(move || ctx.request_repaint()));

        let app = Self {
            survey,
            scan: State::Idle,
            view: View::Devices,
            mode,
            target,
            updates,
        };
        apply(&cc.egui_ctx, Palette::of(app.mode));
        app
    }

    /// An app holding a scan it was handed, rather than one it took.
    ///
    /// The seam `examples/docs-images.rs` uses to photograph the interface with
    /// a network that is not whoever is building it. `CLAUDE.md`'s rule for the
    /// engine is that every reading is injected; this is the same rule one layer
    /// up, and it is why the README's pictures are of the real interface rather
    /// than a mock-up of it.
    ///
    /// The update notice is marked seen: a picture of the device table with a
    /// consent dialog over it is a picture of the dialog.
    pub fn seeded(
        cc: &eframe::CreationContext<'_>,
        survey: Survey,
        scan: State,
        view: View,
        mode: Mode,
    ) -> Self {
        install_fonts(&cc.egui_ctx);
        apply(&cc.egui_ctx, Palette::of(mode));

        let target = survey.default_targets().first().copied();
        let mut updates = Updates::default();
        updates.notice_seen = true;
        updates.check_on_startup = false;

        Self {
            survey,
            scan,
            view,
            mode,
            target,
            updates,
        }
    }

    fn palette(&self) -> Palette {
        Palette::of(self.mode)
    }

    fn start_scan(&mut self) {
        let Some(prefix) = self.target else { return };
        let on_link = self
            .survey
            .interfaces
            .iter()
            .filter(|i| i.is_scannable())
            .flat_map(|i| i.v4_prefixes())
            .any(|l| l.contains(prefix.network()));
        self.scan = State::start(&self.survey, prefix, on_link);
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // A running scan reports through a channel, which is not an event: the
        // frame has to be asked for or the progress sits there until the mouse
        // moves. Umber's update check has the same problem and the same answer.
        if self.scan.poll() || self.scan.is_running() {
            ctx.request_repaint_after(std::time::Duration::from_millis(60));
        }

        // The startup check, once, and only once the notice has been answered.
        self.updates.start_if_due();
        self.updates.poll(std::time::Instant::now());

        // An update that has landed asks the window to close, and the two ways
        // it ends are genuinely different: a swapped binary can be started
        // again from here, where the Windows installer needs Muster *gone* and
        // starts the new version itself.
        if let Some(exit) = self.updates.take_exit_request() {
            if exit == Exit::Restart
                && let Err(why) = crate::update::relaunch()
            {
                self.updates.restart_failed(why);
            } else {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }

        let p = self.palette();
        top_bar(ctx, p, self);
        status_bar(ctx, p, self);
        sidebar(ctx, p, self);

        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(p.window))
            .show(ctx, |ui| match self.view {
                View::Devices => devices_view(ui, p, self),
                View::Network => network_view(ui, p, &self.survey),
                View::About => about_view(ui, p, &mut self.updates),
            });

        // Last, so it draws over everything: the first-run notice, or the
        // update dialog when there is one.
        updatedlg::show(ctx, p, &mut self.updates);
    }
}

/// The 34 px bar: the accent mark, the name, and the scan control at the right.
fn top_bar(ctx: &egui::Context, p: Palette, app: &mut App) {
    egui::TopBottomPanel::top("top")
        .exact_height(metrics::MENU_BAR)
        .frame(
            egui::Frame::NONE
                .fill(p.chrome)
                .inner_margin(egui::Margin::symmetric(metrics::PAD_STRIP as i8, 0)),
        )
        .show_separator_line(false)
        .show(ctx, |ui| {
            hairline_bottom(ui, p);
            ui.horizontal_centered(|ui| {
                // The mark: a rounded square in the accent with no glyph in it.
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(metrics::MARK), Sense::hover());
                ui.painter()
                    .rect_filled(rect, metrics::RADIUS_TIGHT, p.accent);

                ui.add_space(metrics::S2);
                ui.label(
                    RichText::new("Muster")
                        .size(text::HEADING)
                        .color(p.text_strong),
                );

                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    scan_control(ui, p, app);
                });
            });
        });
}

/// Start, or stop. Cancelling is available throughout a scan and takes effect
/// at the next probe, so the control never has to be disabled mid-run.
fn scan_control(ui: &mut egui::Ui, p: Palette, app: &mut App) {
    if app.scan.is_running() {
        if button(ui, p, "Stop", false).clicked() {
            app.scan.cancel();
        }
        return;
    }

    let can = app.target.is_some();
    let label = match app.scan {
        State::Finished(_) => "Scan again",
        _ => "Scan",
    };
    let response = button(ui, p, label, can);
    if !can {
        // A control that cannot act says why rather than being mysteriously
        // dead. `CLAUDE.md`: nothing claims what the app cannot do.
        response.clone().on_hover_text(
            "No local network small enough to sweep. Run `muster survey` to see what \
             this machine knows.",
        );
    }
    if response.clicked() && can {
        app.start_scan();
    }
}

/// A painted button. Not egui's, because the design's controls are drawn to §7
/// and a stock control is the one thing the style guide refuses outright.
fn button(ui: &mut egui::Ui, p: Palette, label: &str, enabled: bool) -> egui::Response {
    let galley = ui.painter().layout_no_wrap(
        label.to_string(),
        FontId::proportional(text::CONTROL),
        if enabled { p.text } else { p.text_dim },
    );
    let size = vec2(galley.size().x + metrics::S3 * 2.0, metrics::BUTTON);
    let (rect, response) = ui.allocate_exact_size(size, Sense::click());

    let fill = if !enabled {
        p.control
    } else if response.hovered() {
        p.control_hover
    } else {
        p.control
    };
    ui.painter().rect_filled(rect, metrics::RADIUS, fill);
    ui.painter().rect_stroke(
        rect,
        metrics::RADIUS,
        Stroke::new(metrics::HAIRLINE, p.line),
        egui::StrokeKind::Inside,
    );
    let at = pos2(
        rect.center().x - galley.size().x / 2.0,
        rect.center().y - galley.size().y / 2.0,
    );
    ui.painter().galley(at, galley, p.text);
    if enabled {
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        response
    }
}

fn sidebar(ctx: &egui::Context, p: Palette, app: &mut App) {
    egui::SidePanel::left("nav")
        .exact_width(metrics::SIDEBAR)
        .resizable(false)
        .frame(egui::Frame::NONE.fill(p.dock))
        .show_separator_line(false)
        .show(ctx, |ui| {
            hairline_right(ui, p);
            ui.add_space(metrics::S2);
            for view in View::ALL {
                if nav_row(ui, p, view.label(), app.view == view).clicked() {
                    app.view = view;
                }
            }
        });
}

/// One navigation row.
///
/// The selected state is the design language's, and getting it wrong here would
/// be getting it wrong everywhere: a **neutral** fill (`control`), **strong**
/// text, and a small accent bar at the leading edge. An accent *background* is
/// the thing §2.4 forbids.
fn nav_row(ui: &mut egui::Ui, p: Palette, label: &str, selected: bool) -> egui::Response {
    let size = vec2(ui.available_width(), metrics::NAV_ROW);
    let (rect, response) = ui.allocate_exact_size(size, Sense::click());

    if selected {
        ui.painter().rect_filled(rect, metrics::RADIUS, p.control);
        let mark = Rect::from_min_size(
            rect.left_top() + vec2(0.0, metrics::S1),
            vec2(metrics::NAV_MARK_W, rect.height() - metrics::S2),
        );
        ui.painter()
            .rect_filled(mark, metrics::RADIUS_TIGHT, p.accent);
    } else if response.hovered() {
        ui.painter()
            .rect_filled(rect, metrics::RADIUS, p.control_hover);
    }

    ui.painter().text(
        rect.left_center() + vec2(metrics::PAD_PANEL, 0.0),
        egui::Align2::LEFT_CENTER,
        label,
        FontId::proportional(text::CONTROL),
        if selected {
            p.text_strong
        } else {
            p.text_muted
        },
    );
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

fn status_bar(ctx: &egui::Context, p: Palette, app: &App) {
    egui::TopBottomPanel::bottom("status")
        .exact_height(metrics::STATUS_BAR)
        .frame(
            egui::Frame::NONE
                .fill(p.chrome)
                .inner_margin(egui::Margin::symmetric(metrics::PAD_STRIP as i8, 0)),
        )
        .show_separator_line(false)
        .show(ctx, |ui| {
            hairline_top(ui, p);
            ui.horizontal_centered(|ui| {
                let message = match &app.scan {
                    State::Idle => match app.target {
                        Some(t) => format!("Ready — {t} ({} addresses)", t.host_count()),
                        None => "No local network to sweep".into(),
                    },
                    State::Running { phase, found, .. } => {
                        format!("{} — {found} found", phase.label())
                    }
                    State::Finished(o) => {
                        let mut s = format!(
                            "{} device{} on {}",
                            o.sweep.found.len(),
                            if o.sweep.found.len() == 1 { "" } else { "s" },
                            o.prefix
                        );
                        // A partial sweep never presents its count as the
                        // answer, in the one place the count is shown.
                        if o.sweep.cancelled {
                            s.push_str(" — stopped early, not the whole network");
                        }
                        for missed in &o.sweep.not_done {
                            s.push_str(&format!(" — {missed}"));
                        }
                        s
                    }
                };
                ui.label(RichText::new(message).size(text::TINY).color(p.text_dim));

                if let State::Running { phase, .. } = &app.scan {
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        progress(ui, p, phase.fraction());
                    });
                }
            });
        });
}

/// A progress bar that draws empty when it does not know.
///
/// `CLAUDE.md` refuses an animated bar over an unknown total everywhere, so the
/// [`Option`] is honoured rather than defaulted: `None` paints the track and
/// nothing in it.
fn progress(ui: &mut egui::Ui, p: Palette, fraction: Option<f32>) {
    let (rect, _) = ui.allocate_exact_size(vec2(120.0, 4.0), Sense::hover());
    ui.painter().rect_filled(rect, 2.0, p.control);
    if let Some(f) = fraction {
        let filled = Rect::from_min_size(
            rect.left_top(),
            vec2(rect.width() * f.clamp(0.0, 1.0), rect.height()),
        );
        ui.painter().rect_filled(filled, 2.0, p.accent);
    }
}

/// The device list. This is the app, so it is the densest thing in it.
fn devices_view(ui: &mut egui::Ui, p: Palette, app: &App) {
    let devices = app.scan.devices();
    let names = app.scan.names();

    if devices.is_empty() {
        let note = match &app.scan {
            State::Running { .. } => "Scanning…",
            State::Finished(_) => "Nothing answered on this network.",
            State::Idle => "No scan yet. Press Scan.",
        };
        empty_state(ui, p, note);
        return;
    }

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.add_space(metrics::S2);
            table_header(ui, p);
            for (i, host) in devices.iter().enumerate() {
                device_row(ui, p, host, names.get(i));
            }
            ui.add_space(metrics::S2);
        });
}

const COL_ADDRESS: f32 = 130.0;
const COL_NAME: f32 = 190.0;
const COL_MAC: f32 = 150.0;
const COL_TIME: f32 = 64.0;

fn table_header(ui: &mut egui::Ui, p: Palette) {
    let (rect, _) = ui.allocate_exact_size(
        vec2(ui.available_width(), metrics::ROW_PLAIN),
        Sense::hover(),
    );
    let mut x = rect.left() + metrics::PAD_PANEL;
    for (label, width) in [
        ("Address", COL_ADDRESS),
        ("Name", COL_NAME),
        ("Hardware", COL_MAC),
        ("Time", COL_TIME),
        ("Made by", 0.0),
    ] {
        ui.painter().text(
            pos2(x, rect.center().y),
            egui::Align2::LEFT_CENTER,
            label,
            FontId::proportional(text::TINY),
            p.placeholder,
        );
        x += width;
    }
    hairline_across(ui, p, rect.bottom());
}

/// One device.
///
/// Every figure — the address, the hardware address, the time — is in the
/// monospaced face so the columns line up down the page, which is the whole
/// reason `CLAUDE.md` calls this a table of figures.
fn device_row(
    ui: &mut egui::Ui,
    p: Palette,
    host: &muster_net::discover::Found,
    named: Option<&Identity>,
) {
    let (rect, response) =
        ui.allocate_exact_size(vec2(ui.available_width(), metrics::ROW), Sense::hover());
    if response.hovered() {
        ui.painter().rect_filled(rect, 0.0, p.control_hover);
    }

    let figure = FontId::monospace(text::TINY);
    let mut x = rect.left() + metrics::PAD_PANEL;
    let y = rect.center().y;

    ui.painter().text(
        pos2(x, y),
        egui::Align2::LEFT_CENTER,
        host.address.to_string(),
        figure.clone(),
        p.text_strong,
    );
    x += COL_ADDRESS;

    let name = named
        .and_then(Identity::best)
        .map(|n| n.value.clone())
        .unwrap_or_default();
    ui.painter().text(
        pos2(x, y),
        egui::Align2::LEFT_CENTER,
        &name,
        FontId::proportional(text::CONTROL),
        p.text,
    );
    x += COL_NAME;

    let mac = host.mac.map(|m| m.to_string()).unwrap_or_default();
    ui.painter().text(
        pos2(x, y),
        egui::Align2::LEFT_CENTER,
        &mac,
        figure.clone(),
        p.text_muted,
    );
    x += COL_MAC;

    let rtt = match host.rtt {
        Some(t) if t.as_millis() > 0 => format!("{} ms", t.as_millis()),
        Some(_) => "<1 ms".into(),
        None => String::new(),
    };
    ui.painter().text(
        pos2(x + COL_TIME - metrics::S2, y),
        egui::Align2::RIGHT_CENTER,
        &rtt,
        figure,
        p.text_dim,
    );
    x += COL_TIME;

    // The vendor, and the one thing that is *not* a vendor: a randomised
    // address is reported as randomised rather than as an unknown maker, which
    // `Origin` keeps separable all the way to here.
    let origin = host.mac.map(muster_net::vendor::lookup);
    let (vendor, colour) = match origin {
        Some(muster_net::vendor::Origin::Randomised) => {
            ("randomised address".to_string(), p.text_dim)
        }
        Some(o) => (o.label().to_string(), p.text_muted),
        None => (String::new(), p.text_muted),
    };
    ui.painter().text(
        pos2(x, y),
        egui::Align2::LEFT_CENTER,
        &vendor,
        FontId::proportional(text::SMALL),
        colour,
    );

    hairline_across(ui, p, rect.bottom());

    if response.hovered() {
        let why: Vec<String> = host.evidence.iter().map(|e| e.reason()).collect();
        let mut tip = why.join(", ");
        if let Some(best) = named.and_then(Identity::best) {
            tip.push_str(&format!("\nNamed by {}", best.source.label()));
        }
        if named.is_some_and(Identity::disputed) {
            let others = named.map(Identity::other_names).unwrap_or_default();
            tip.push_str(&format!("\nAlso called {}", others.join(", ")));
        }
        response.on_hover_text(tip);
    }
}

/// What the machine knows without sending anything.
fn network_view(ui: &mut egui::Ui, p: Palette, s: &Survey) {
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.add_space(metrics::S3);
            for iface in s.interfaces.iter().filter(|i| i.is_scannable()) {
                section(ui, p, &iface.friendly);
                for addr in &iface.addresses {
                    fact(
                        ui,
                        p,
                        "Address",
                        &format!("{} in {}", addr.address, addr.prefix),
                    );
                }
                if let Some(mac) = iface.mac {
                    fact(ui, p, "Hardware", &mac.to_string());
                }
            }

            section(ui, p, "Gateway");
            if !s.has(muster_net::survey::Reading::Routes) {
                // The rule that matters most in this whole view: a reading that
                // failed is said to have failed, never drawn as an absence.
                fact(ui, p, "", "could not be read");
            } else if s.gateways.is_empty() {
                fact(ui, p, "", "none — no default route");
            } else {
                for g in &s.gateways {
                    fact(ui, p, "", &g.address.to_string());
                }
            }

            section(ui, p, "DNS");
            if s.resolvers.is_empty() {
                fact(ui, p, "", "none configured");
            }
            for r in &s.resolvers {
                fact(ui, p, "", &r.to_string());
            }

            section(ui, p, "DHCP");
            if s.dhcp_servers.is_empty() {
                fact(ui, p, "", "no lease recorded");
            }
            for d in &s.dhcp_servers {
                fact(ui, p, "", &d.to_string());
            }

            if !s.gaps.is_empty() {
                section(ui, p, "Could not read");
                for gap in &s.gaps {
                    fact(ui, p, &gap.reading.to_string(), &gap.because);
                }
            }
            ui.add_space(metrics::S4);
        });
}

fn about_view(ui: &mut egui::Ui, p: Palette, updates: &mut Updates) {
    ui.add_space(metrics::S4);
    ui.horizontal(|ui| {
        ui.add_space(metrics::PAD_PANEL);
        ui.vertical(|ui| {
            ui.label(
                RichText::new("Muster")
                    .size(text::HEADING)
                    .color(p.text_strong),
            );
            ui.label(
                RichText::new(format!("Version {}", env!("CARGO_PKG_VERSION")))
                    .size(text::SMALL)
                    .color(p.text_muted),
            );
            ui.add_space(metrics::S3);
            for line in [
                "A scanner for the network this machine is on.",
                "",
                "Everything here runs without administrator rights. The port",
                "scan uses connect(); the faster SYN scan needs Npcap on",
                "Windows and CAP_NET_RAW on Linux, and is not built yet.",
                "",
                "Nothing about your network leaves this machine. There is no",
                "telemetry, and no address or name is ever looked up against a",
                "remote service. The one request Muster makes on its own behalf",
                "is the update check below, and it asks first.",
            ] {
                ui.label(RichText::new(line).size(text::BODY).color(p.text));
            }

            ui.add_space(metrics::S4);
            updates_section(ui, p, updates);
        });
    });
}

/// The update check, and the one switch that governs it.
///
/// `CLAUDE.md` puts the setting in one place, and this is it: there is no
/// second copy of it in a settings page, because there is no settings page.
fn updates_section(ui: &mut egui::Ui, p: Palette, updates: &mut Updates) {
    ui.label(
        RichText::new("UPDATES")
            .size(text::TINY)
            .color(p.placeholder),
    );
    ui.add_space(metrics::S1);

    // What this build cannot do, said before the button that would not work.
    // A check offered by a copy a package manager owns would be a button that
    // finds an update Muster is not allowed to install.
    if let Some(why) = updates.check_unavailable() {
        ui.label(RichText::new(why).size(text::SMALL).color(p.text_muted));
        return;
    }

    ui.label(
        RichText::new(updatedlg::status_line(updates.status()))
            .size(text::BODY)
            .color(p.text),
    );
    ui.add_space(metrics::S2);

    ui.horizontal(|ui| {
        let busy = matches!(updates.status(), crate::update::Status::Checking);
        if button(ui, p, "Check now", !busy).clicked() && !busy {
            updates.check();
        }
        // A result the user asked for is shown where they asked for it, so the
        // offer opens from here rather than being thrown up as a modal.
        if matches!(updates.status(), crate::update::Status::Available(_))
            && button(ui, p, "What is in it", true).clicked()
        {
            updates.open_offer();
        }
    });

    ui.add_space(metrics::S2);
    let mut on = updates.check_on_startup;
    if checkbox(ui, p, &mut on, "Check when Muster starts") {
        updates.check_on_startup = on;
        prefs::save(prefs::Prefs {
            check_on_startup: updates.check_on_startup,
            notice_seen: updates.notice_seen,
        });
    }
}

/// A tick box, drawn to §7.12. Returns whether it was just changed.
fn checkbox(ui: &mut egui::Ui, p: Palette, on: &mut bool, label: &str) -> bool {
    let galley = ui.painter().layout_no_wrap(
        label.to_string(),
        FontId::proportional(text::CONTROL),
        p.text,
    );
    let box_side = 14.0;
    let size = vec2(
        box_side + metrics::S2 + galley.size().x,
        metrics::ROW_PLAIN.max(box_side),
    );
    let (rect, response) = ui.allocate_exact_size(size, Sense::click());
    if response.clicked() {
        *on = !*on;
    }

    let square = Rect::from_min_size(
        pos2(rect.left(), rect.center().y - box_side / 2.0),
        Vec2::splat(box_side),
    );
    ui.painter().rect_filled(
        square,
        metrics::RADIUS_TIGHT,
        if *on { p.accent } else { p.field },
    );
    if !*on {
        ui.painter().rect_stroke(
            square,
            metrics::RADIUS_TIGHT,
            Stroke::new(metrics::HAIRLINE, p.line),
            egui::StrokeKind::Inside,
        );
    } else {
        // The tick, drawn rather than set in a glyph: two strokes in the ink
        // that belongs on an accent fill.
        let c = square.center();
        let s = box_side * 0.24;
        ui.painter().line_segment(
            [pos2(c.x - s, c.y), pos2(c.x - s * 0.2, c.y + s * 0.8)],
            Stroke::new(1.6_f32, p.accent_ink),
        );
        ui.painter().line_segment(
            [
                pos2(c.x - s * 0.2, c.y + s * 0.8),
                pos2(c.x + s, c.y - s * 0.7),
            ],
            Stroke::new(1.6_f32, p.accent_ink),
        );
    }
    ui.painter().galley(
        pos2(
            square.right() + metrics::S2,
            rect.center().y - galley.size().y / 2.0,
        ),
        galley,
        p.text,
    );
    response.clicked()
}

fn section(ui: &mut egui::Ui, p: Palette, title: &str) {
    ui.add_space(metrics::S3);
    ui.horizontal(|ui| {
        ui.add_space(metrics::PAD_PANEL);
        ui.label(
            RichText::new(title.to_uppercase())
                .size(text::TINY)
                .color(p.placeholder),
        );
    });
    ui.add_space(metrics::S1);
}

fn fact(ui: &mut egui::Ui, p: Palette, key: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.add_space(metrics::PAD_PANEL);
        if !key.is_empty() {
            ui.label(RichText::new(key).size(text::SMALL).color(p.text_dim));
        }
        ui.label(
            RichText::new(value)
                .size(text::SMALL)
                .color(p.text)
                .monospace(),
        );
    });
}

fn empty_state(ui: &mut egui::Ui, p: Palette, note: &str) {
    ui.centered_and_justified(|ui| {
        ui.label(RichText::new(note).size(text::BODY).color(p.text_dim));
    });
}

// ── hairlines ───────────────────────────────────────────────────────────────
//
// Every strip and panel edge is one, and they are painted rather than left to
// egui's separators so that the colour is the token and the width is exactly
// one pixel.

fn hairline_across(ui: &egui::Ui, p: Palette, y: f32) {
    let rect = ui.max_rect();
    ui.painter().hline(
        rect.left()..=rect.right(),
        y,
        Stroke::new(metrics::HAIRLINE, p.line_soft),
    );
}

fn hairline_bottom(ui: &egui::Ui, p: Palette) {
    let rect = ui.max_rect();
    ui.painter().hline(
        rect.left()..=rect.right(),
        rect.bottom(),
        Stroke::new(metrics::HAIRLINE, p.line),
    );
}

fn hairline_top(ui: &egui::Ui, p: Palette) {
    let rect = ui.max_rect();
    ui.painter().hline(
        rect.left()..=rect.right(),
        rect.top(),
        Stroke::new(metrics::HAIRLINE, p.line),
    );
}

fn hairline_right(ui: &egui::Ui, p: Palette) {
    let rect = ui.max_rect();
    ui.painter().vline(
        rect.right(),
        rect.top()..=rect.bottom(),
        Stroke::new(metrics::HAIRLINE, p.line),
    );
}

/// Archivo, bundled rather than fetched.
///
/// The house typeface, and it travels in the binary for the same reason
/// everything else does. egui's own monospace stays for figures.
pub(crate) fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "archivo".into(),
        std::sync::Arc::new(egui::FontData::from_static(include_bytes!(
            "../assets/Archivo.ttf"
        ))),
    );
    fonts
        .families
        .entry(egui::FontFamily::Proportional)
        .or_default()
        .insert(0, "archivo".into());
    ctx.set_fonts(fonts);
}

/// Pushes the palette into egui's own visuals, for the few things it draws
/// itself: scroll bars, tooltips, the window ground.
pub(crate) fn apply(ctx: &egui::Context, p: Palette) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = p.window;
    visuals.window_fill = p.popover;
    visuals.extreme_bg_color = p.field;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(metrics::HAIRLINE, p.line);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(metrics::HAIRLINE, p.text);
    visuals.window_stroke = Stroke::new(metrics::HAIRLINE, p.line_popover);
    // Shadows only under things that float; a panel is not one.
    visuals.window_shadow = egui::epaint::Shadow {
        offset: [0, 8],
        blur: 32,
        spread: 0,
        color: Color32::from_black_alpha(153),
    };
    visuals.popup_shadow = visuals.window_shadow;
    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = vec2(metrics::S2, metrics::S1);
    style.spacing.scroll.bar_width = 6.0;
    ctx.set_style(style);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_view_has_a_label() {
        for view in View::ALL {
            assert!(!view.label().is_empty());
        }
        assert_eq!(View::Devices.label(), "Devices");
    }

    /// The columns are laid out by adding widths along a row, so they only line
    /// up if the header and the row walk the same numbers. Pinning the sum is
    /// what catches a column added to one and not the other.
    #[test]
    fn the_table_columns_are_one_set_of_numbers() {
        assert_eq!(COL_ADDRESS + COL_NAME + COL_MAC + COL_TIME, 534.0);
    }
}
