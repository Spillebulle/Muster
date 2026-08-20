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
use crate::{deviceicon, dhcpcheck, ports, prefs, settings, updatedlg};
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
    /// The device whose detail panel is open, by address.
    ///
    /// By address rather than by row index: a second scan reorders the table,
    /// and an index would quietly select whatever moved into that position.
    selected: Option<std::net::IpAddr>,
    /// The port scan, which is per device and only ever one at a time.
    ports: ports::State,
    /// Who offers addresses on this link, and whether more than one does.
    dhcp: dhcpcheck::State,
    /// What was last written to the settings file, so a check that moved the
    /// clock is persisted once rather than on every frame.
    saved_last_check: u64,
    /// The app mark, uploaded once, with the theme it was drawn for.
    mark: Option<(Mode, egui::TextureHandle)>,
    /// What the user typed in the range field. Empty means the local prefix.
    ///
    /// Kept as text rather than as a `Prefix` so a half-typed address stays a
    /// half-typed address instead of a parse failure on every keystroke.
    target_text: String,
    /// The filter over the device table.
    search: String,
    /// The settings page, and everything it remembers.
    settings: settings::State,
    /// The settings themselves, as loaded and as edited.
    prefs: prefs::Prefs,
    /// What the desktop asked for, so `Theme::System` has something to follow.
    system_mode: Mode,
    /// A re-probe in flight: which device, and where its answer will arrive.
    ping: Option<(
        std::net::IpAddr,
        std::sync::mpsc::Receiver<Option<std::time::Duration>>,
    )>,
    /// What the last re-probe said, and about which device. `None` inside the
    /// tuple means nothing came back, which is **not** the same as gone.
    pinged: Option<(std::net::IpAddr, Option<std::time::Duration>)>,
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
        // What the desktop asked for. `Theme::System` follows it; the other
        // two override it.
        let system_mode = match cc.egui_ctx.style().visuals.dark_mode {
            true => Mode::Dark,
            false => Mode::Light,
        };

        let saved = prefs::load();
        let mode = saved.theme.resolve(system_mode);
        // The scale is egui's to hold: setting it marks the font atlas dirty,
        // so it is set once here and then only when it actually moves.
        cc.egui_ctx.set_zoom_factor(saved.interface_scale);
        let mut updates = Updates::default();
        updates.check_on_startup = saved.check_on_startup;
        updates.notice_seen = saved.notice_seen;
        updates.last_check = saved.last_check;
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
            selected: None,
            ports: ports::State::Idle,
            dhcp: dhcpcheck::State::Idle,
            saved_last_check: saved.last_check,
            mark: None,
            target_text: String::new(),
            search: String::new(),
            settings: settings::State::default(),
            prefs: saved.clone(),
            system_mode,
            ping: None,
            pinged: None,
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
            selected: None,
            ports: ports::State::Idle,
            dhcp: dhcpcheck::State::Idle,
            saved_last_check: 0,
            mark: None,
            target_text: String::new(),
            search: String::new(),
            settings: settings::State::default(),
            prefs: prefs::Prefs::default(),
            system_mode: mode,
            ping: None,
            pinged: None,
            updates,
        }
    }

    /// Is `prefix` one this machine is actually on?
    ///
    /// What separates the default from a range somebody typed, and what the
    /// toolbar says out loud before a scan leaves the link.
    fn on_link(&self, prefix: Prefix) -> bool {
        self.survey
            .interfaces
            .iter()
            .filter(|i| i.is_scannable())
            .flat_map(|i| i.v4_prefixes())
            .any(|local| local.contains(prefix.network()))
    }

    /// Ask one device again, on a thread.
    fn start_ping(&mut self, address: std::net::IpAddr) {
        let (tx, rx) = std::sync::mpsc::channel();
        let on_link = self.target.is_some_and(|p| self.on_link(p));
        std::thread::spawn(move || {
            let opts = if on_link {
                muster_net::discover::Options::on_link()
            } else {
                muster_net::discover::Options::default()
            };
            let found = muster_net::discover::probe(
                address,
                &muster_net::platform::Host,
                &muster_net::rate::Bucket::polite(),
                opts,
            );
            // `None` for "nothing came back" collapses with "found but no round
            // trip measured", and that is deliberate: neither is a time to
            // show, and the screen distinguishes them by whether a device is
            // still in the table at all.
            let _ = tx.send(found.and_then(|f| f.rtt));
        });
        self.ping = Some((address, rx));
    }

    /// Take a ping's answer if it has arrived. True when something changed.
    fn poll_ping(&mut self) -> bool {
        let Some((address, rx)) = &self.ping else {
            return false;
        };
        match rx.try_recv() {
            Ok(rtt) => {
                self.pinged = Some((*address, rtt));
                self.ping = None;
                true
            }
            // The worker ended without answering, which can only be a panic in
            // it. Stop waiting rather than leaving "asking…" on screen.
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                self.pinged = Some((*address, None));
                self.ping = None;
                true
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => false,
        }
    }

    /// Open the settings page, for `examples/docs-images.rs`.
    pub fn open_settings(&mut self) {
        self.settings.open();
    }

    /// Open the detail window on one device.
    ///
    /// The seam `examples/docs-images.rs` uses to photograph it. Nothing else
    /// outside this module sets the selection.
    pub fn select(&mut self, address: std::net::IpAddr) {
        self.selected = Some(address);
    }

    /// The theme in force: the chosen file, or the chosen mode, or the
    /// desktop's.
    fn theme_mode(&self) -> Mode {
        self.prefs.theme.resolve(self.system_mode)
    }

    /// The palette in force, which is a custom theme's table where one is
    /// chosen and a built-in ladder otherwise.
    fn palette(&self) -> Palette {
        if let Some(id) = &self.prefs.custom_theme
            && let Some(custom) = self.settings.themes().iter().find(|t| &t.id == id)
        {
            return custom.palette;
        }
        Palette::of(self.mode)
    }

    /// The app mark as a texture, drawn once per theme.
    ///
    /// Uploaded lazily because there is no context to upload with until the
    /// first frame, and re-made when the theme changes: the mark is a function
    /// of the palette, so a stale one would be the wrong accent.
    fn mark_texture(&mut self, ctx: &egui::Context) -> egui::TextureHandle {
        let mode = self.mode;
        if let Some((made_for, handle)) = &self.mark
            && *made_for == mode
        {
            return handle.clone();
        }
        let image = crate::art::mark(MARK_TEXTURE, Palette::of(mode));
        let handle = ctx.load_texture(
            "muster-mark",
            egui::ColorImage::from_rgba_unmultiplied(
                [MARK_TEXTURE as usize, MARK_TEXTURE as usize],
                &image.pixels,
            ),
            egui::TextureOptions::LINEAR,
        );
        self.mark = Some((mode, handle.clone()));
        handle
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
        if self.ports.poll() || self.ports.is_running() {
            ctx.request_repaint_after(std::time::Duration::from_millis(60));
            // A finished port scan is evidence about the device, so it goes
            // back into the device rather than staying in the panel. This is
            // what makes `kind`'s port table reachable at all: the sweep's own
            // knock only ever tries four ports, and the kind table excludes
            // exactly those four.
            if let Some(address) = self.ports.address()
                && let Some(scan) = self.ports.result_for(address)
            {
                let open: Vec<u16> = scan
                    .hosts
                    .first()
                    .map(|h| h.open().collect())
                    .unwrap_or_default();
                self.scan.record_open_ports(address, &open);
            }
        }
        if self.dhcp.poll() || self.dhcp.is_running() {
            ctx.request_repaint_after(std::time::Duration::from_millis(120));
        }
        if self.poll_ping() || self.ping.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(60));
        }

        // The startup check, once, and only once the notice has been answered.
        self.updates.start_if_due();
        self.updates.poll(std::time::Instant::now());

        // A check moves `last_check`, and it has to survive the process or the
        // throttle is per run and the rate limit is spent by the next launch.
        // Written here rather than in `update::check` so that module goes on
        // knowing nothing about where settings live.
        if self.updates.last_check != self.saved_last_check {
            self.saved_last_check = self.updates.last_check;
            self.prefs.check_on_startup = self.updates.check_on_startup;
            self.prefs.notice_seen = self.updates.notice_seen;
            self.prefs.last_check = self.updates.last_check;
            prefs::save(&self.prefs);
        }

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

        let view = self.view;
        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(p.window))
            .show(ctx, |ui| match view {
                View::Devices => devices_view(ui, p, self),
                View::Network => network_view(ui, p, self),
                View::About => about_view(ui, p, &mut self.updates),
            });

        // Over the table, but under the update dialog: a device's detail is
        // not modal and must not sit on top of something that is.
        if view == View::Devices {
            detail_window(ctx, p, self);
        }

        // The settings page, over the window and under the update dialog.
        let outcome = settings::show(
            ctx,
            p,
            &mut self.settings,
            &mut self.prefs,
            &mut self.updates,
        );
        if let Some(scale) = outcome.scale {
            // Only when it actually differs: `set_zoom_factor` marks the font
            // atlas dirty, and calling it every frame rebuilds every glyph.
            if (ctx.zoom_factor() - scale).abs() > f32::EPSILON {
                ctx.set_zoom_factor(scale);
            }
        }
        if outcome.changed {
            // The theme is resolved here rather than stored twice: the page
            // records a *choice*, and what that choice means depends on what
            // the desktop is doing.
            self.mode = self.theme_mode();
            apply(ctx, self.palette());
            self.updates.check_on_startup = self.prefs.check_on_startup;
            self.updates.notice_seen = self.prefs.notice_seen;
            prefs::save(&self.prefs);
        }

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
                // The mark, and the real one: the same `art::mark` the icon
                // files and the installer are drawn from, uploaded once and
                // scaled down here.
                //
                // Rasterised at `MARK_TEXTURE` rather than at 15 points, which
                // is the whole reason it can carry the glyph at this size at
                // all. `art`'s optical sizing drops the glyph below 24 *pixels*
                // because four discs cannot be drawn with gaps in fewer; a
                // texture built large and minified has no such limit, and it
                // stays sharp on a high-density display where 15 points is 30
                // pixels or more.
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(metrics::MARK), Sense::hover());
                let mark = app.mark_texture(ui.ctx());
                ui.painter().image(
                    mark.id(),
                    rect,
                    Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)),
                    Color32::WHITE,
                );

                ui.add_space(metrics::S2);
                ui.label(
                    RichText::new("Muster")
                        .size(text::HEADING)
                        .color(p.text_strong),
                );

                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    // §6.1 puts a settings gear at the right of the 34 px bar.
                    if gear_button(ui, p).clicked() {
                        app.settings.open();
                    }
                    ui.add_space(metrics::S2);
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
pub(crate) fn button(ui: &mut egui::Ui, p: Palette, label: &str, enabled: bool) -> egui::Response {
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
pub(crate) fn nav_row(
    ui: &mut egui::Ui,
    p: Palette,
    label: &str,
    selected: bool,
) -> egui::Response {
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
fn devices_view(ui: &mut egui::Ui, p: Palette, app: &mut App) {
    // Cloned out of the scan so the loop below can hold `app` mutably to set
    // the selection. A device list is a few dozen rows of small structs; the
    // alternative is threading a "what was clicked" value out through two
    // closures to satisfy the borrow checker, which is more code and no faster.
    let devices: Vec<muster_net::discover::Found> = app.scan.devices().to_vec();
    let names: Vec<Identity> = app.scan.names().to_vec();
    // Read once for the whole table rather than per row: the routing table
    // cannot change while a frame is being drawn, and `kind::identify` only
    // wants the answer to "is this the way out".
    let gateways: Vec<std::net::IpAddr> = app.survey.gateways.iter().map(|g| g.address).collect();

    // Above the empty state as well as above the table: a scan that found
    // nothing is exactly when somebody wants to change the range.
    devices_toolbar(ui, p, app);

    if devices.is_empty() {
        let note = match &app.scan {
            State::Running { .. } => "Sweeping. Devices appear here as they answer.",
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
            let mode = app.mode;
            let empty = Identity::default();
            let mut shown = 0usize;
            for (i, host) in devices.iter().enumerate() {
                let named = names.get(i);
                let is_gateway = gateways.contains(&host.address);
                let kind = muster_net::kind::kind_of(host, named.unwrap_or(&empty), is_gateway);
                if !matches(&app.search, host, named, kind) {
                    continue;
                }
                shown += 1;
                let selected = app.selected == Some(host.address);
                let response = device_row(ui, p, mode, host, named, is_gateway, selected);
                if response.clicked() {
                    // Clicking the open row shuts the window, which is the way
                    // back to the table without reaching for a close button.
                    app.selected = if selected { None } else { Some(host.address) };
                }
            }
            if shown == 0 {
                ui.add_space(metrics::S4);
                empty_state(ui, p, "Nothing here matches that.");
            }
            ui.add_space(metrics::S2);
        });
}

/// The device-kind icon's column. Narrow: it carries a picture and no text,
/// and the kind's name is in the row's tooltip rather than in a column of its
/// own, because a word per row would cost more width than the icon saves.
const COL_KIND: f32 = 26.0;

/// The size the app mark is rasterised at before being scaled into the top bar.
///
/// Four times the 15-point mark, so it is still oversampled on a display at
/// twice the density and minifies cleanly rather than being drawn at a size
/// where `art`'s optical sizing would drop the glyph.
const MARK_TEXTURE: u32 = 64;

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
        // The icon column's heading is deliberately empty: "Kind" over a column
        // of pictures labels the obvious and adds a word to the densest screen
        // in the application.
        ("", COL_KIND),
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
    mode: Mode,
    host: &muster_net::discover::Found,
    named: Option<&Identity>,
    is_gateway: bool,
    selected: bool,
) -> egui::Response {
    let (rect, response) =
        ui.allocate_exact_size(vec2(ui.available_width(), metrics::ROW), Sense::click());
    // Selection is a **neutral** fill plus strong text plus a small accent
    // mark, and never an accent background. The rule the whole design language
    // exists to protect, drawn the same way `nav_row` draws it.
    if selected {
        ui.painter().rect_filled(rect, 0.0, p.control);
        ui.painter().rect_filled(
            Rect::from_min_size(rect.left_top(), vec2(metrics::NAV_MARK_W, rect.height())),
            0.0,
            p.accent,
        );
    } else if response.hovered() {
        ui.painter().rect_filled(rect, 0.0, p.control_hover);
    }

    let figure = FontId::monospace(text::TINY);
    let mut x = rect.left() + metrics::PAD_PANEL;
    let y = rect.center().y;

    // What this device appears to be, and why. The guess is `muster-net`'s;
    // this file only decides how big to draw it.
    let empty = Identity::default();
    let guess = muster_net::kind::identify(host, named.unwrap_or(&empty), is_gateway);
    let kind = guess.map_or(muster_net::Kind::Unknown, |g| g.kind);
    let icon = Rect::from_center_size(pos2(x + metrics::ICON / 2.0, y), Vec2::splat(metrics::ICON));
    // The cut-outs are filled with whatever the row is sitting on, so a hovered
    // row shows its own fill through them rather than a stale window colour.
    let ground = if selected {
        p.control
    } else if response.hovered() {
        p.control_hover
    } else {
        p.window
    };
    deviceicon::draw(
        ui.painter(),
        icon,
        kind,
        deviceicon::colour(kind, mode, p.text_dim),
        ground,
    );
    x += COL_KIND;

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
        let mut tip = String::new();
        // The claim first, with its reason attached. `CLAUDE.md`: every claim
        // about a device is shown beside the reason for it, and an icon with no
        // way to ask "why do you think that" is a guess wearing a confident
        // face.
        if let Some(guess) = guess {
            tip.push_str(&format!(
                "{} — {}\n",
                guess.kind.label(),
                guess.clue.reason()
            ));
        }
        tip.push_str(&why.join(", "));
        if let Some(best) = named.and_then(Identity::best) {
            tip.push_str(&format!("\nNamed by {}", best.source.label()));
        }
        if named.is_some_and(Identity::disputed) {
            let others = named.map(Identity::other_names).unwrap_or_default();
            tip.push_str(&format!("\nAlso called {}", others.join(", ")));
        }
        response.clone().on_hover_text(tip);
    }
    response
}

/// What the machine knows without sending anything.
fn network_view(ui: &mut egui::Ui, p: Palette, app: &mut App) {
    let s = &app.survey.clone();
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
            dhcp_check(ui, p, app);

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

    // **No switch here.** `CLAUDE.md` requires the setting that governs the
    // check to live in one place, and once the settings page existed, About
    // having its own copy broke that rule from the inside. What stays is the
    // status and the command — reporting and doing are not settings.
    ui.add_space(metrics::S2);
    ui.label(
        RichText::new("Settings, General has the switch for the startup check.")
            .size(text::TINY)
            .color(p.text_dim),
    );
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

/// How wide the device window is.
const DETAIL_WIDTH: f32 = 320.0;

/// The window for the selected device: what it is, why, and what it offers.
///
/// A floating window rather than a docked panel, which is a change from how
/// this started. The panel took 264 px off the table permanently and put the
/// device's detail as far from the row as it is possible to get on a wide
/// screen; a window opens next to the work, moves if it is in the way, and
/// gives the width back when it closes. §7.17's rules apply: popover fill, a
/// hairline, and a shadow, because it floats.
fn detail_window(ctx: &egui::Context, p: Palette, app: &mut App) {
    let Some(address) = app.selected else { return };
    let Some(index) = app.scan.devices().iter().position(|d| d.address == address) else {
        // The device is gone, which means a later scan did not find it. Drop
        // the selection rather than showing a window about nothing.
        app.selected = None;
        return;
    };

    let host = app.scan.devices()[index].clone();
    let named = app.scan.names().get(index).cloned().unwrap_or_default();
    let is_gateway = app.survey.gateways.iter().any(|g| g.address == address);
    let guess = muster_net::kind::identify(&host, &named, is_gateway);
    let kind = guess.map_or(muster_net::Kind::Unknown, |g| g.kind);
    let mode = app.mode;

    let mut open = true;
    let title = named
        .best()
        .map(|n| n.value.clone())
        .unwrap_or_else(|| address.to_string());

    // **No stock chrome.** `title_bar(false)` and our own header: egui's title
    // bar is another toolkit's control, drawn in another toolkit's colours, and
    // §16 refuses those outright. It also arrived translucent, so the device
    // table read straight through the panel.
    egui::Window::new("device")
        .id(egui::Id::new("device-detail"))
        .title_bar(false)
        .collapsible(false)
        .resizable(false)
        .default_width(DETAIL_WIDTH)
        .frame(
            egui::Frame::NONE
                // Opaque, and stated: a floating thing over a dense table has
                // to be readable, and `popover` is the surface §5 puts menus
                // and floating panels on.
                .fill(p.popover.to_opaque())
                .stroke(Stroke::new(metrics::HAIRLINE, p.line_popover))
                .corner_radius(metrics::RADIUS_MODAL)
                .inner_margin(egui::Margin::same(metrics::PAD_PANEL as i8))
                .shadow(egui::epaint::Shadow {
                    offset: [0, 16],
                    blur: 48,
                    spread: 0,
                    color: Color32::from_black_alpha(178),
                }),
        )
        .show(ctx, |ui| {
            ui.set_width(DETAIL_WIDTH);

            // Our own header: the name, and a close mark that is an icon
            // button rather than a letter.
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(&title)
                        .size(text::HEADING)
                        .color(p.text_strong),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if close_button(ui, p).clicked() {
                        open = false;
                    }
                });
            });
            ui.add_space(metrics::S1);
            hairline_across(ui, p, ui.min_rect().bottom());
            ui.add_space(metrics::S2);

            ui.horizontal(|ui| {
                let (icon, _) = ui.allocate_exact_size(Vec2::splat(metrics::ROW), Sense::hover());
                deviceicon::draw(
                    ui.painter(),
                    Rect::from_center_size(icon.center(), Vec2::splat(metrics::ROW - 4.0)),
                    kind,
                    deviceicon::colour(kind, mode, p.text_dim),
                    p.popover,
                );
                ui.add_space(metrics::S1);
                // The claim and its reason, together. An icon with no way to
                // ask why is a guess wearing a confident face.
                match guess {
                    Some(g) => {
                        ui.vertical(|ui| {
                            ui.label(
                                RichText::new(g.kind.label())
                                    .size(text::CONTROL)
                                    .color(deviceicon::colour(kind, mode, p.text_muted)),
                            );
                            ui.label(
                                RichText::new(g.clue.reason())
                                    .size(text::TINY)
                                    .color(p.text_dim),
                            );
                        });
                    }
                    None => {
                        ui.label(
                            RichText::new("Nothing it said identifies what it is")
                                .size(text::TINY)
                                .color(p.text_dim),
                        );
                    }
                }
            });

            ui.add_space(metrics::S2);
            fact_row(ui, p, "Address", &address.to_string());
            if let Some(mac) = host.mac {
                fact_row(ui, p, "Hardware", &mac.to_string());
                let vendor = match muster_net::vendor::lookup(mac) {
                    muster_net::vendor::Origin::Randomised => "randomised address".to_string(),
                    other => other.label().to_string(),
                };
                fact_row(ui, p, "Made by", &vendor);
            }
            if let Some(workgroup) = &named.workgroup {
                fact_row(ui, p, "Workgroup", workgroup);
            }
            for name in &named.names {
                fact_row(ui, p, name.source.label(), &name.value);
            }
            if !named.services.is_empty() {
                fact_row(ui, p, "Advertises", &named.services.join(", "));
            }
            fact_row(
                ui,
                p,
                "Answered",
                &host
                    .evidence
                    .iter()
                    .map(muster_net::discover::Evidence::reason)
                    .collect::<Vec<_>>()
                    .join(", "),
            );

            ui.add_space(metrics::S3);
            ping_section(ui, p, app, address, host.rtt);

            ui.add_space(metrics::S3);
            ports_section(ui, p, app, address);
        });

    if !open {
        app.selected = None;
    }
}

/// Ask this one device again, now.
///
/// The same three probes the sweep uses, through `discover::probe`, so a
/// re-check and the sweep cannot disagree about what counts as an answer. It is
/// the question somebody actually has in front of a device list: *is it still
/// there?*
fn ping_section(
    ui: &mut egui::Ui,
    p: Palette,
    app: &mut App,
    address: std::net::IpAddr,
    swept_rtt: Option<std::time::Duration>,
) {
    ui.horizontal(|ui| {
        let waiting = app.ping.as_ref().is_some_and(|(a, _)| *a == address);
        if button(ui, p, "Ping", !waiting).clicked() && !waiting {
            app.start_ping(address);
        }
        ui.add_space(metrics::S2);

        let line = if waiting {
            "asking…".to_string()
        } else {
            match app.pinged {
                Some((a, Some(rtt))) if a == address => {
                    format!("answered in {} ms", rtt.as_millis())
                }
                // **Not "it is gone".** Silence is a device that is off, a
                // device that drops, or a probe that was rate limited into the
                // next second. The sweep's own rule, kept here.
                Some((a, None)) if a == address => "nothing came back this time".to_string(),
                _ => match swept_rtt {
                    Some(rtt) => format!("{} ms when it was swept", rtt.as_millis()),
                    None => String::new(),
                },
            }
        };
        ui.label(RichText::new(line).size(text::TINY).color(p.text_dim));
    });
}

/// One `label  value` line with a control that copies the value.
///
/// Every field is copyable because every field is something somebody is about
/// to paste somewhere: a hardware address into a DHCP reservation, an address
/// into a browser, a vendor into a search.
fn fact_row(ui: &mut egui::Ui, p: Palette, label: &str, value: &str) {
    if value.is_empty() {
        return;
    }
    ui.add_space(metrics::S1);
    ui.horizontal(|ui| {
        ui.label(RichText::new(label).size(text::TINY).color(p.text_dim));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            copy_button(ui, p, value);
        });
    });
    ui.label(
        RichText::new(value)
            .size(text::SMALL)
            .monospace()
            .color(p.text),
    );
}

/// A small copy control: two offset rectangles, drawn rather than lettered.
///
/// Icon-only, so it carries a tooltip — §11's rule, and the only thing that
/// makes an unlabelled control honest.
fn copy_button(ui: &mut egui::Ui, p: Palette, value: &str) -> egui::Response {
    let side = metrics::ICON;
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(side), Sense::click());
    let ink = if response.hovered() {
        p.text_strong
    } else {
        p.text_dim
    };

    // The back sheet, then the front one over it, so the two read as a stack
    // rather than as a cross.
    let back = Rect::from_min_size(
        pos2(rect.left() + side * 0.10, rect.top() + side * 0.10),
        Vec2::splat(side * 0.58),
    );
    let front = Rect::from_min_size(
        pos2(rect.left() + side * 0.32, rect.top() + side * 0.32),
        Vec2::splat(side * 0.58),
    );
    ui.painter().rect_stroke(
        back,
        2.0,
        Stroke::new(1.2_f32, ink),
        egui::StrokeKind::Inside,
    );
    ui.painter().rect_filled(front, 2.0, p.popover);
    ui.painter().rect_stroke(
        front,
        2.0,
        Stroke::new(1.2_f32, ink),
        egui::StrokeKind::Inside,
    );

    if response.clicked() {
        ui.ctx().copy_text(value.to_string());
    }
    response
        .clone()
        .on_hover_text(format!("Copy {value}"))
        .on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// The port scan, and what it is allowed to claim.
fn ports_section(ui: &mut egui::Ui, p: Palette, app: &mut App, address: std::net::IpAddr) {
    ui.label(RichText::new("PORTS").size(text::TINY).color(p.placeholder));
    ui.add_space(metrics::S1);

    if app.ports.is_running() {
        // Somebody's scan is running. If it is this device's, show it; if it is
        // another's, say so rather than offering a button that would silently
        // do nothing. One at a time is the rate limiter's rule, not a shortage
        // of threads.
        if app.ports.address() != Some(address) {
            ui.label(
                RichText::new("Another device is being scanned.")
                    .size(text::TINY)
                    .color(p.text_dim),
            );
            return;
        }
        progress(ui, p, app.ports.fraction());
        ui.add_space(metrics::S1);
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("Scanning…")
                    .size(text::TINY)
                    .color(p.text_dim),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if button(ui, p, "Stop", true).clicked() {
                    app.ports.cancel();
                }
            });
        });
        return;
    }

    let finished = app.ports.result_for(address).cloned();
    match finished {
        Some(scan) => {
            ui.label(
                RichText::new(ports::summary(&scan))
                    .size(text::SMALL)
                    .color(p.text),
            );
            ui.add_space(metrics::S1);

            if let Some(found) = scan.hosts.first() {
                for (port, state) in &found.answered {
                    if *state != muster_net::portscan::PortState::Open {
                        continue;
                    }
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(format!("{port}"))
                                .size(text::TINY)
                                .monospace()
                                .color(p.text_strong),
                        );
                        // A convention, not a banner: Muster did not ask the
                        // service what it was.
                        if let Some(hint) = ports::service_hint(*port) {
                            ui.label(RichText::new(hint).size(text::TINY).color(p.text_muted));
                        }
                    });
                }
            }

            // Whatever the engine wants said about its own answer: today, that
            // `connect()` is slower and louder than the SYN scan it will be,
            // and that silence is not a closed port.
            //
            // **Drawn as notes, in a neutral.** They were `caution` amber
            // first, which made every successful scan look like it had gone
            // wrong; these are facts about the method, not warnings about the
            // result. §2.5: semantic colour marks state, and "this is how it
            // was measured" is not a state.
            let notes = ports::caveats(&scan);
            if !notes.is_empty() {
                ui.add_space(metrics::S2);
                ui.label(
                    RichText::new("ABOUT THIS SCAN")
                        .size(text::TINY)
                        .color(p.placeholder),
                );
                for note in notes {
                    ui.add_space(metrics::S1);
                    ui.label(RichText::new(note).size(text::TINY).color(p.text_dim));
                }
            }

            ui.add_space(metrics::S2);
            if button(ui, p, "Scan again", true).clicked() {
                app.ports = ports::State::start(address, muster_net::portscan::Ports::common());
            }
        }
        None => {
            ui.label(
                RichText::new("The ports worth knowing about, on this one device.")
                    .size(text::TINY)
                    .color(p.text_dim),
            );
            ui.add_space(metrics::S2);
            if button(ui, p, "Scan ports", true).clicked() {
                app.ports = ports::State::start(address, muster_net::portscan::Ports::common());
            }
        }
    }
}

/// Who offers addresses on this link, and whether more than one does.
///
/// A button rather than part of a scan: a DISCOVER asks every server on the
/// link to reserve an address, and `CLAUDE.md`'s conduct rules make anything
/// beyond looking a deliberate act. Nothing takes the offer.
fn dhcp_check(ui: &mut egui::Ui, p: Palette, app: &mut App) {
    // The hardware address of the interface a scan would use. A DISCOVER is
    // answered to whoever sent it, so an address nothing on this link owns
    // would collect nothing.
    let mac = app
        .survey
        .interfaces
        .iter()
        .find(|i| i.is_scannable())
        .and_then(|i| i.mac);

    ui.add_space(metrics::S2);
    ui.horizontal(|ui| {
        ui.add_space(metrics::PAD_PANEL);
        if app.dhcp.is_running() {
            ui.label(
                RichText::new("Listening for offers…")
                    .size(text::SMALL)
                    .color(p.text_dim),
            );
            return;
        }
        let can = mac.is_some();
        let label = match app.dhcp.result() {
            Some(_) => "Check again",
            None => "Check for another DHCP server",
        };
        let response = button(ui, p, label, can);
        if !can {
            response.clone().on_hover_text(
                "No interface with a hardware address to ask from. Run \
                 `muster survey` to see what this machine knows.",
            );
        }
        if response.clicked()
            && let Some(mac) = mac
        {
            app.dhcp = dhcpcheck::State::start(mac);
        }
    });

    let Some(probe) = app.dhcp.result() else {
        return;
    };

    // Two servers is the fault this exists to find, so it is the one thing here
    // that is allowed a semantic colour. One server, or none, is a statement of
    // fact and stays neutral.
    let colour = if probe.is_contested() {
        p.caution
    } else {
        p.text
    };
    ui.add_space(metrics::S1);
    ui.horizontal(|ui| {
        ui.add_space(metrics::PAD_PANEL);
        ui.label(
            RichText::new(probe.verdict())
                .size(text::SMALL)
                .color(colour),
        );
    });

    for offer in &probe.offers {
        let mut detail = format!("offered {}", offer.offered);
        if let Some(router) = offer.router {
            detail.push_str(&format!(", gateway {router}"));
        }
        if let Some(lease) = offer.lease {
            detail.push_str(&format!(", {} h lease", lease.as_secs() / 3600));
        }
        fact(ui, p, &offer.server.to_string(), &detail);
    }
}

/// The strip above the device table: what to scan, and what to show.
///
/// §7.2's options strip. It carries the two things a scan needs from the user
/// and nothing else: the range to sweep, and a filter over what came back.
fn devices_toolbar(ui: &mut egui::Ui, p: Palette, app: &mut App) {
    ui.horizontal(|ui| {
        ui.add_space(metrics::PAD_PANEL);

        ui.label(RichText::new("Range").size(text::TINY).color(p.text_dim));
        let target = field(ui, p, &mut app.target_text, 150.0, "192.168.1.0/24");

        // Parsed on every keystroke so the field can say whether it is usable
        // before the button is pressed, rather than failing after it.
        //
        // **The default is still the local prefix.** Typing here is how
        // `CLAUDE.md`'s "scanning outside the local prefix is a deliberate act"
        // is expressed: an empty field means this machine's own network, and
        // anything else is something somebody chose to write.
        let typed: Option<Prefix> = match app.target_text.trim() {
            "" => app.survey.default_targets().first().copied(),
            text => text.parse().ok(),
        };
        let unparsed = !app.target_text.trim().is_empty() && typed.is_none();
        if unparsed {
            target.on_hover_text(
                "Not an address and prefix length. Try something like 192.168.1.0/24.",
            );
        }
        app.target = typed;

        // Off the link is worth saying once, plainly, without moralising.
        if let Some(prefix) = typed
            && !app.on_link(prefix)
        {
            ui.label(
                RichText::new("not this machine's network")
                    .size(text::TINY)
                    .color(p.caution),
            )
            .on_hover_text(
                "Muster will sweep it if you ask. Scanning a network you are \
                 not responsible for is your decision.",
            );
        }

        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.add_space(metrics::PAD_PANEL);
            if !app.search.is_empty() && button(ui, p, "Clear", false).clicked() {
                app.search.clear();
            }
            field(ui, p, &mut app.search, 200.0, "Search");
            ui.label(RichText::new("Filter").size(text::TINY).color(p.text_dim));
        });
    });
    ui.add_space(metrics::S1);
}

/// A text field, drawn to §7.11 rather than egui's own.
pub(crate) fn field(
    ui: &mut egui::Ui,
    p: Palette,
    text_of: &mut String,
    width: f32,
    placeholder: &str,
) -> egui::Response {
    let (rect, _) = ui.allocate_exact_size(vec2(width, metrics::FIELD), Sense::hover());
    ui.painter().rect_filled(rect, metrics::RADIUS, p.field);
    ui.painter().rect_stroke(
        rect,
        metrics::RADIUS,
        Stroke::new(metrics::HAIRLINE, p.line),
        egui::StrokeKind::Inside,
    );

    let inner = rect.shrink2(vec2(metrics::S2, 0.0));
    let mut child = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(inner)
            .layout(Layout::left_to_right(Align::Center)),
    );
    child.add(
        egui::TextEdit::singleline(text_of)
            .desired_width(inner.width())
            .frame(false)
            .hint_text(RichText::new(placeholder).color(p.placeholder))
            .font(FontId::proportional(text::CONTROL))
            .text_color(p.text),
    )
}

/// Does `text` match this device?
///
/// Matched across everything the row shows — address, name, hardware address,
/// vendor and kind — because somebody searching a device list is as likely to
/// be looking for "epson" or "printer" as for an address. Case-insensitive,
/// substring, and no syntax: a filter box that needs a query language is a
/// filter box nobody uses.
fn matches(
    needle: &str,
    host: &muster_net::discover::Found,
    named: Option<&Identity>,
    kind: muster_net::Kind,
) -> bool {
    let needle = needle.trim().to_ascii_lowercase();
    if needle.is_empty() {
        return true;
    }
    let mut hay = host.address.to_string();
    if let Some(mac) = host.mac {
        hay.push(' ');
        hay.push_str(&mac.to_string());
        hay.push(' ');
        hay.push_str(muster_net::vendor::lookup(mac).label());
    }
    if let Some(identity) = named {
        for name in &identity.names {
            hay.push(' ');
            hay.push_str(&name.value);
        }
        for service in &identity.services {
            hay.push(' ');
            hay.push_str(service);
        }
        if let Some(workgroup) = &identity.workgroup {
            hay.push(' ');
            hay.push_str(workgroup);
        }
    }
    hay.push(' ');
    hay.push_str(kind.label());
    hay.to_ascii_lowercase().contains(&needle)
}

/// A close mark: two strokes, drawn rather than lettered.
///
/// §7.5's header ends in one of these, and §11 requires a tooltip on any
/// icon-only control.
pub(crate) fn close_button(ui: &mut egui::Ui, p: Palette) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(metrics::ICON), Sense::click());
    let ink = if response.hovered() {
        p.text_strong
    } else {
        p.text_dim
    };
    let arm = rect.shrink(metrics::ICON * 0.28);
    ui.painter().line_segment(
        [arm.left_top(), arm.right_bottom()],
        Stroke::new(1.4_f32, ink),
    );
    ui.painter().line_segment(
        [arm.right_top(), arm.left_bottom()],
        Stroke::new(1.4_f32, ink),
    );
    response
        .clone()
        .on_hover_text("Close")
        .on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// The settings gear: a ring with teeth, drawn rather than lettered.
///
/// Icon-only, so §11 requires the tooltip.
fn gear_button(ui: &mut egui::Ui, p: Palette) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(metrics::ICON), Sense::click());
    let ink = if response.hovered() {
        p.text_strong
    } else {
        p.text_muted
    };
    let c = rect.center();
    let r = metrics::ICON * 0.30;
    ui.painter().circle_stroke(c, r, Stroke::new(1.6_f32, ink));
    // Six teeth, which reads as a gear at 16 px where eight reads as a blur.
    for k in 0..6 {
        let a = std::f32::consts::TAU * k as f32 / 6.0;
        let (sin, cos) = a.sin_cos();
        ui.painter().line_segment(
            [
                pos2(c.x + cos * r, c.y + sin * r),
                pos2(c.x + cos * (r + 3.0), c.y + sin * (r + 3.0)),
            ],
            Stroke::new(1.6_f32, ink),
        );
    }
    response
        .clone()
        .on_hover_text("Settings")
        .on_hover_cursor(egui::CursorIcon::PointingHand)
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
