//! The window.
//!
//! The shell is §16 of `../Design-Principles/STYLE-GUIDE.md`: a 34 px top bar
//! carrying the accent mark, a 240 px sidebar of navigation rows, a 26 px status
//! bar, hairlines everywhere and shadows only under things that float. The
//! device list is the app, so it is a dense table of figures in the monospaced
//! face with its columns aligned.
//!
//! Every navigation row carries an icon from [`crate::icons`], and the sidebar
//! is in two groups: the places to work at the top, and Settings and About at
//! the foot. That is the family's arrangement rather than this application's
//! invention — see [`sidebar`], which says where it comes from.
//!
//! The rule that shapes most of what follows: **selection is a neutral fill plus
//! strong text plus a small accent mark, and never an accent background.** It is
//! the defect the whole design language exists to avoid, so it is drawn in one
//! place ([`nav_row`]) rather than at each call site.

use crate::icons::{self, Icon};
use crate::scan::{self, State};
use crate::theme::{self, Mode, Palette, metrics, text};
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

    /// The views that are *destinations*, in the order the sidebar lists them.
    ///
    /// About is not one. It is where the version, the licence and the update
    /// check live, and the family puts those at the foot of the sidebar rather
    /// than at the top with the places a person actually goes: Tally's sidebar
    /// keeps Settings and the version strip below the navigation, and
    /// HomeLab's keeps the account and the version there. So About is still a
    /// view, and still selects like one, but it is grouped with Settings at
    /// the bottom instead of sitting above This network as a third place to
    /// work.
    pub const DESTINATIONS: [Self; 2] = [Self::Devices, Self::Network];

    fn label(self) -> &'static str {
        match self {
            Self::Devices => "Devices",
            Self::Network => "This network",
            Self::About => "About",
        }
    }

    fn icon(self) -> Icon {
        match self {
            Self::Devices => Icon::Devices,
            Self::Network => Icon::Network,
            Self::About => Icon::Info,
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
    /// Which column the table is ordered by, and which way.
    ///
    /// Not persisted, and that is a choice: a sort is a question somebody is
    /// asking of the scan in front of them — "which of these are printers",
    /// "which answered slowest" — and it should not still be asked of a
    /// different network tomorrow morning.
    sort: Sort,
    /// The settings page, and everything it remembers.
    settings: settings::State,
    /// The settings themselves, as loaded and as edited.
    prefs: prefs::Prefs,
    /// What the desktop asked for, so `Theme::System` has something to follow.
    system_mode: Mode,
    /// A re-probe in flight: which device, and where its answer will arrive.
    ping: Option<(
        std::net::IpAddr,
        std::sync::mpsc::Receiver<muster_net::discover::Recheck>,
    )>,
    /// What the last re-probe said, and about which device.
    ///
    /// The whole [`muster_net::discover::Recheck`] rather than the round trip
    /// alone, because the round trip cannot tell "it did not answer" from "the
    /// question was never asked". A machine that cannot open a ping socket
    /// sends no echo at all, and reporting that as silence from the device is
    /// the failure `CLAUDE.md` calls the worst this application can produce.
    pinged: Option<(std::net::IpAddr, muster_net::discover::Recheck)>,
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
            sort: Sort::default(),
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
        apply_for(&cc.egui_ctx, Palette::of(app.mode), app.mode);
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
        apply_for(&cc.egui_ctx, Palette::of(mode), mode);

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
            sort: Sort::default(),
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
            let found = muster_net::discover::recheck(
                address,
                &muster_net::platform::Host,
                &muster_net::rate::Bucket::polite(),
                opts,
            );
            let _ = tx.send(found);
        });
        self.ping = Some((address, rx));
    }

    /// Take a ping's answer if it has arrived. True when something changed.
    fn poll_ping(&mut self) -> bool {
        let Some((address, rx)) = &self.ping else {
            return false;
        };
        match rx.try_recv() {
            Ok(answer) => {
                self.pinged = Some((*address, answer));
                self.ping = None;
                true
            }
            // The worker ended without answering, which can only be a panic in
            // it. Stop waiting rather than leaving "asking…" on screen, and say
            // that the probe itself failed rather than blaming the device.
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                self.pinged = Some((
                    *address,
                    muster_net::discover::Recheck {
                        found: None,
                        not_done: vec!["the probe did not finish".into()],
                    },
                ));
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
        self.scan = State::start(&self.survey, prefix, on_link, self.scan_options());
        // A scan that asked about DHCP has the answer the DHCP view wants, so
        // the view shows it rather than making somebody ask the same question
        // twice from two screens.
        if self.prefs.scan_dhcp {
            self.dhcp = dhcpcheck::State::Idle;
        }
    }

    /// What a scan is asked to do, out of the settings.
    fn scan_options(&self) -> scan::Options {
        scan::Options {
            rate: self.prefs.rate,
            identify: self.prefs.identify,
            dns: self.prefs.scan_dns,
            dhcp: self.prefs.scan_dhcp,
        }
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
            apply_for(ctx, self.palette(), self.mode);
            self.updates.check_on_startup = self.prefs.check_on_startup;
            self.updates.notice_seen = self.prefs.notice_seen;
            prefs::save(&self.prefs);
        }

        // Last, so it draws over everything: the first-run notice, or the
        // update dialog when there is one.
        updatedlg::show(ctx, p, self.mode, &mut self.updates);
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
                        .font(theme::strong(text::HEADING))
                        .color(p.text_strong),
                );

                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    // §6.2 keeps navigation out of the top bar, and a gear is
                    // navigation: it went to the settings page from the one
                    // corner of the window furthest from every other way of
                    // getting somewhere. It is a row at the foot of the
                    // sidebar now, beside About, which is where the rest of
                    // the family keeps both. See [`sidebar`].
                    //
                    // The scan control used to sit here too, and it belongs in
                    // the options strip with the range it acts on — a control
                    // in one strip acting on a field in another is how a
                    // reader loses the connection between them.
                    //
                    // What a scan *does*, as against where it goes. The range
                    // is a field in the strip above the table because it
                    // changes with every scan; these change once and are then
                    // remembered, so they live behind a menu rather than
                    // spending width on the densest screen in the application.
                    scan_menu(ui, p, app);
                });
            });
        });
}

/// The scan menu: what a scan asks, and how hard.
///
/// A §7.17 popover hung off the top bar. Everything in it writes
/// [`crate::prefs::Prefs`] and is saved as it changes, so this and the settings
/// page's Scanning pane are two views of one set of values rather than two sets
/// that can drift apart.
///
/// **A running scan does not read these again.** [`scan::Options`] is taken
/// once at the start, so moving a control here changes the *next* scan and
/// never the one on screen. The note at the foot says so rather than leaving
/// somebody to wonder why nothing happened.
fn scan_menu(ui: &mut egui::Ui, p: Palette, app: &mut App) {
    let response = menu_button(ui, p, "Scan");
    let mut changed = false;
    let mode = app.mode;
    egui::Popup::menu(&response)
        .gap(metrics::S1)
        .frame(
            egui::Frame::NONE
                .fill(p.popover.to_opaque())
                .stroke(Stroke::new(metrics::HAIRLINE, p.line_popover))
                .corner_radius(metrics::RADIUS_MODAL)
                .inner_margin(egui::Margin::same(metrics::PAD_PANEL as i8))
                .shadow(theme::shadow::menu(mode)),
        )
        .show(|ui| {
            ui.set_width(SCAN_MENU_WIDTH);
            ui.label(
                RichText::new("WHAT A SCAN ASKS")
                    .size(text::EYEBROW)
                    .color(p.placeholder),
            );
            ui.add_space(metrics::S2);

            for (label, explain, value) in [
                (
                    "Identify devices",
                    "mDNS, SSDP and NetBIOS, and the model a device names for itself.",
                    &mut app.prefs.identify,
                ),
                (
                    "Find name servers",
                    "One DNS query per device that answered.",
                    &mut app.prefs.scan_dns,
                ),
                (
                    "Find DHCP servers",
                    "Broadcasts a DISCOVER and keeps every offer. Nothing is accepted.",
                    &mut app.prefs.scan_dhcp,
                ),
            ] {
                changed |= menu_toggle(ui, p, label, explain, value);
            }

            ui.add_space(metrics::S2);
            ui.label(
                RichText::new("RATE")
                    .size(text::EYEBROW)
                    .color(p.placeholder),
            );
            ui.add_space(metrics::S2);
            ui.horizontal(|ui| {
                let mut value = app.prefs.rate as f32;
                crate::settings::slider(ui, p, &mut value, 50.0, 5000.0, 50.0);
                if value as u32 != app.prefs.rate {
                    app.prefs.rate = value as u32;
                    changed = true;
                }
                ui.add_space(metrics::S2);
                ui.label(
                    RichText::new(format!("{} /s", app.prefs.rate))
                        .size(text::TINY)
                        .monospace()
                        .color(p.text_muted),
                );
            });

            if app.scan.is_running() {
                ui.add_space(metrics::S2);
                ui.label(
                    RichText::new("The scan running now keeps the settings it started with.")
                        .size(text::TINY)
                        .color(p.text_dim),
                );
            }
        });

    if changed {
        prefs::save(&app.prefs);
    }
}

/// How wide the scan menu is: enough for its longest sentence on one line.
const SCAN_MENU_WIDTH: f32 = 320.0;

/// The width a toggle occupies at the right of a menu row, from `settings`.
const TOGGLE_W: f32 = 34.0;

/// One switched line in a menu: a label, a sentence under it, a toggle.
fn menu_toggle(
    ui: &mut egui::Ui,
    p: Palette,
    label: &str,
    explain: &str,
    value: &mut bool,
) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.set_width(SCAN_MENU_WIDTH - TOGGLE_W - metrics::S3);
            ui.label(
                RichText::new(label)
                    .size(text::CONTROL)
                    .color(p.text_strong),
            );
            ui.label(RichText::new(explain).size(text::TINY).color(p.text_dim));
        });
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            changed = crate::settings::toggle(ui, p, value);
        });
    });
    ui.add_space(metrics::S2);
    changed
}

/// A button that opens a menu: §7.6's secondary with a chevron after the label.
///
/// Icon-only controls need a tooltip and this one is not icon-only, but the
/// chevron is the only thing saying it opens rather than acts, so it carries
/// the cursor change that says the same.
fn menu_button(ui: &mut egui::Ui, p: Palette, label: &str) -> egui::Response {
    let font = FontId::proportional(text::CONTROL);
    let galley = ui
        .painter()
        .layout_no_wrap(label.to_string(), font.clone(), p.text);
    let width = galley.size().x + metrics::S3 * 2.0 + CHEVRON;
    let (rect, response) = ui.allocate_exact_size(vec2(width, metrics::BUTTON), Sense::click());
    let fill = if response.hovered() {
        p.control_hover
    } else {
        p.control
    };
    ui.painter().rect_filled(rect, metrics::RADIUS, fill);
    ui.painter().text(
        pos2(rect.left() + metrics::S3, rect.center().y),
        egui::Align2::LEFT_CENTER,
        label,
        font,
        p.text,
    );

    // Two strokes, from the same set as the close mark and the gear, rather
    // than a letter pretending to be an icon.
    let c = pos2(rect.right() - metrics::S3 - CHEVRON / 2.0, rect.center().y);
    let (w, h) = (CHEVRON * 0.34, CHEVRON * 0.18);
    let ink = if response.hovered() {
        p.text_strong
    } else {
        p.text_muted
    };
    for arm in [-w, w] {
        ui.painter().line_segment(
            [pos2(c.x + arm, c.y - h), pos2(c.x, c.y + h)],
            Stroke::new(1.4_f32, ink),
        );
    }
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// The chevron's box on a menu button.
const CHEVRON: f32 = 12.0;

/// Start, or stop. Cancelling is available throughout a scan and takes effect
/// at the next probe, so the control never has to be disabled mid-run.
fn scan_control(ui: &mut egui::Ui, p: Palette, app: &mut App) {
    if app.scan.is_running() {
        if button(ui, p, "Stop", Kind::Secondary, true).clicked() {
            app.scan.cancel();
        }
        return;
    }

    let can = app.target.is_some();
    let label = match app.scan {
        State::Finished(_) => "Scan again",
        _ => "Scan",
    };
    let response = button(ui, p, label, Kind::Primary, can);
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

/// Which of §7.6's kinds a button is.
///
/// One table, one drawing. There were three `button` functions in this crate
/// with two different signatures and two different paddings, and neither could
/// express what the other did: the window's could not draw a primary, and the
/// dialogs' could not draw a disabled one. A button that cannot say "no" and a
/// button that cannot say "this is the one" are the same defect from opposite
/// ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// The one thing to do on this view. At most one visible.
    Primary,
    /// Everything else. A fill and **no border**.
    Secondary,
    /// On `dock`, or inside a well, where a filled button would vanish.
    Outlined,
    /// Cancel and tertiary. No fill, no border.
    Ghost,
}

/// A button, drawn to §7.6.
///
/// 26 px tall, radius 5, 11.5 px text, 12 px of padding either side. Disabled
/// is 45 % opacity across the whole control rather than dim text on a
/// full-strength fill, and the caller is expected to say why in a tooltip.
pub(crate) fn button(
    ui: &mut egui::Ui,
    p: Palette,
    label: &str,
    kind: Kind,
    enabled: bool,
) -> egui::Response {
    let font = match kind {
        // The primary is the one place §4 puts weight on a control.
        Kind::Primary => theme::strong(text::CONTROL),
        _ => FontId::proportional(text::CONTROL),
    };
    let galley = ui
        .painter()
        .layout_no_wrap(label.to_string(), font, Color32::PLACEHOLDER);
    let size = vec2(galley.size().x + metrics::PAD_PANEL * 2.0, metrics::BUTTON);
    let (rect, response) = ui.allocate_exact_size(
        size,
        if enabled {
            Sense::click()
        } else {
            Sense::hover()
        },
    );

    let hovered = enabled && response.hovered();
    let (fill, border, ink) = match kind {
        Kind::Primary => (Some(p.accent), None, p.accent_ink),
        Kind::Secondary => (
            Some(if hovered { p.control_hover } else { p.control }),
            None,
            p.text,
        ),
        Kind::Outlined => (
            None,
            Some(if hovered { p.line_dashed } else { p.line }),
            p.text,
        ),
        Kind::Ghost => (
            None,
            None,
            if hovered { p.text_strong } else { p.text_muted },
        ),
    };

    // 45 % opacity on the *whole* control, which is what makes a disabled
    // button read as unavailable rather than as merely quiet.
    let dim = |c: Color32| {
        if enabled { c } else { c.gamma_multiply(0.45) }
    };

    if let Some(fill) = fill {
        ui.painter().rect_filled(rect, metrics::RADIUS, dim(fill));
    }
    if let Some(border) = border {
        ui.painter().rect_stroke(
            rect,
            metrics::RADIUS,
            Stroke::new(metrics::HAIRLINE, dim(border)),
            egui::StrokeKind::Inside,
        );
    }
    ui.painter().galley(
        pos2(
            rect.center().x - galley.size().x / 2.0,
            rect.center().y - galley.size().y / 2.0,
        ),
        galley,
        dim(ink),
    );

    if enabled {
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        response
    }
}

/// The 240 px navigation column: where to go at the top, the two chrome rows
/// at the foot.
///
/// The split is the family's. Tally's sidebar carries its destinations in a
/// scrolling column and hangs Settings and the version strip off the bottom of
/// it, and HomeLab's does the same with the account; §6.2 keeps page
/// navigation out of the top bar entirely, which is where Muster's gear used
/// to be. So the foot is where the two rows that are not places to work live,
/// separated by a hairline and read in the order they are wanted: Settings
/// first, and under it About, which is the version and the licence and is
/// therefore the last thing on the column in every application in the house.
fn sidebar(ctx: &egui::Context, p: Palette, app: &mut App) {
    egui::SidePanel::left("nav")
        .exact_width(metrics::SIDEBAR)
        .resizable(false)
        .frame(egui::Frame::NONE.fill(p.dock))
        .show_separator_line(false)
        .show(ctx, |ui| {
            hairline_right(ui, p);

            // Bottom up, so the foot is pinned to the bottom of the column
            // however tall the window is, and the destinations fill what is
            // left above it. Read this block from the last line back: the
            // hairline, Settings, About, and the padding under the panel edge.
            ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
                ui.add_space(metrics::S2);
                if nav_row(
                    ui,
                    p,
                    View::About.icon(),
                    View::About.label(),
                    app.view == View::About,
                )
                .clicked()
                {
                    app.view = View::About;
                }
                // Settings is a modal rather than a view, so its row is never
                // the selected one: it opens something over the window and the
                // window keeps whichever destination it was on.
                if nav_row(ui, p, Icon::Gear, "Settings", false).clicked() {
                    app.settings.open();
                }
                ui.add_space(metrics::S2);
                // `min_rect` is what this layout has actually placed, so its
                // top is the top of the foot however many rows it holds.
                hairline_across(ui, p, ui.min_rect().top());

                // And the destinations, top down, in the space above.
                ui.with_layout(Layout::top_down(Align::Min), |ui| {
                    ui.add_space(metrics::S2);
                    for view in View::DESTINATIONS {
                        if nav_row(ui, p, view.icon(), view.label(), app.view == view).clicked() {
                            app.view = view;
                        }
                    }
                });
            });
        });
}

/// The space between a navigation row's icon and its label.
const NAV_GAP: f32 = 10.0;

/// One navigation row: an icon, a label, and the selected state.
///
/// The selected state is the design language's, and getting it wrong here would
/// be getting it wrong everywhere: a **neutral** fill (`control`), **strong**
/// text, and a small accent bar at the leading edge. An accent *background* is
/// the thing §2.4 forbids.
pub(crate) fn nav_row(
    ui: &mut egui::Ui,
    p: Palette,
    icon: Icon,
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

    // The icon takes the row's own colour, so it is muted at rest and strong
    // when the row is selected without being told twice.
    let ink = if selected {
        p.text_strong
    } else {
        p.text_muted
    };
    let glyph = Rect::from_center_size(
        rect.left_center() + vec2(metrics::PAD_PANEL + metrics::ICON / 2.0, 0.0),
        Vec2::splat(metrics::ICON),
    );
    icons::draw(ui.painter(), glyph, icon, ink);

    ui.painter().text(
        pos2(glyph.right() + NAV_GAP, rect.center().y),
        egui::Align2::LEFT_CENTER,
        label,
        FontId::proportional(text::CONTROL),
        ink,
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
                        Some(t) => format!("Ready · {t} · {} addresses", t.host_count()),
                        None => "No local network to sweep".into(),
                    },
                    State::Running { phase, found, .. } => {
                        format!("{} · {found} found", phase.label())
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
                            s.push_str(" · stopped early, not the whole network");
                        }
                        for missed in &o.sweep.not_done {
                            s.push_str(&format!(" · {missed}"));
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
    // §7.10 and §7.18: a 3 px rail in `rail`, filled in `accent`. It was 4 px
    // on `control`, which is the button's surface rather than the rail's.
    let (rect, _) = ui.allocate_exact_size(vec2(120.0, metrics::RAIL), Sense::hover());
    ui.painter().rect_filled(rect, metrics::RAIL / 2.0, p.rail);
    if let Some(f) = fraction {
        let filled = Rect::from_min_size(
            rect.left_top(),
            vec2(rect.width() * f.clamp(0.0, 1.0), rect.height()),
        );
        ui.painter()
            .rect_filled(filled, metrics::RAIL / 2.0, p.accent);
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
    let survey = app.survey.clone();

    // Above the empty state as well as above the table: a scan that found
    // nothing is exactly when somebody wants to change the range.
    devices_toolbar(ui, p, app);

    if devices.is_empty() {
        let (message, action) = match &app.scan {
            State::Running { .. } => ("Sweeping. Devices appear here as they answer.", None),
            State::Finished(_) => ("Nothing answered on this network.", Some("Scan again")),
            State::Idle => ("Nothing scanned yet.", Some("Scan")),
        };
        if empty_state(ui, p, message, action) {
            app.start_scan();
        }
        return;
    }

    // The order to draw in, as a list of indices into the two parallel
    // vectors. Sorting the devices themselves would break that pairing, and
    // sorting pairs would copy an identity per row per frame.
    let empty = Identity::default();
    let mut order: Vec<usize> = (0..devices.len()).collect();
    let sort = app.sort;
    order.sort_by(|a, b| {
        let key = |i: usize| {
            let host = &devices[i];
            let named = names.get(i);
            let vantage = survey.vantage(host.address);
            let kind = muster_net::kind::kind_of(host, named.unwrap_or(&empty), vantage);
            sort_key(sort.column, host, named, kind)
        };
        let (left, right) = (key(*a), key(*b));
        // The emptiness flag is the first element of the key and is compared
        // ascending whichever way the column points, so blank cells stay at
        // the bottom. See `sort_key`.
        left.0.cmp(&right.0).then_with(|| {
            let rest = (left.1, left.2).cmp(&(right.1, right.2));
            if sort.ascending { rest } else { rest.reverse() }
        })
    });

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.add_space(metrics::S2);
            table_header(ui, p, &mut app.sort);
            let mode = app.mode;
            let mut shown = 0usize;
            for i in order {
                let host = &devices[i];
                let named = names.get(i);
                let vantage = survey.vantage(host.address);
                let kind = muster_net::kind::kind_of(host, named.unwrap_or(&empty), vantage);
                if !matches(&app.search, host, named, kind) {
                    continue;
                }
                shown += 1;
                let selected = app.selected == Some(host.address);
                let response = device_row(ui, p, mode, host, named, vantage, selected);
                if response.clicked() {
                    // Clicking the open row shuts the window, which is the way
                    // back to the table without reaching for a close button.
                    app.selected = if selected { None } else { Some(host.address) };
                }
            }
            if shown == 0 {
                empty_state(ui, p, "Nothing here matches that.", None);
            }
            ui.add_space(metrics::S2);
        });
}

/// The device-kind icon's column. Narrow: it carries a picture and no text,
/// and the kind's name is in the row's tooltip rather than in a column of its
/// own, because a word per row would cost more width than the icon saves.
const COL_KIND: f32 = 26.0;

/// The corner radius of a selected table row.
///
/// **Square, where `nav_row`'s is rounded, and that is deliberate rather than
/// an oversight.** A sidebar holds a handful of separated items and a rounded
/// fill reads as one of them; a table row is one of forty touching its
/// neighbours top and bottom, and rounding each one leaves pale notches down
/// both edges of the column. Named so the two call sites disagree on purpose.
const TABLE_SELECTION_RADIUS: f32 = 0.0;

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
/// The badges: what a device serves the network. Two fit side by side.
const COL_SERVES: f32 = 84.0;

/// Which column the table is ordered by.
///
/// **Every column, including the ones that are pictures.** Sorting by kind is
/// how a list of forty becomes "the three printers"; sorting by what a device
/// serves is how the network's own infrastructure comes to the top. The
/// variants are in the order the columns are drawn, so the header can pair them
/// off without a second list to keep in step.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Column {
    Kind,
    /// The default, and it is the sweep's own order: an address is the one
    /// column with a total order everybody already agrees on.
    #[default]
    Address,
    Name,
    Mac,
    Time,
    Serves,
    Vendor,
}

/// A column, and which way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sort {
    pub column: Column,
    pub ascending: bool,
}

impl Default for Sort {
    fn default() -> Self {
        Self {
            column: Column::Address,
            ascending: true,
        }
    }
}

impl Sort {
    /// Click a heading: the same column reverses, a different one starts
    /// ascending.
    ///
    /// Starting a new column *descending* would be the other reasonable choice
    /// for time and for the badges, where the interesting end is the big one.
    /// It is not taken, because a table whose direction depends on which
    /// heading was clicked cannot be predicted from the heading.
    fn clicked(&mut self, column: Column) {
        if self.column == column {
            self.ascending = !self.ascending;
        } else {
            *self = Self {
                column,
                ascending: true,
            };
        }
    }
}

/// The key one row sorts on, as text or as a number.
///
/// Text is compared case-insensitively and **an empty cell always sorts last**,
/// whichever way the column is pointing. That is the one asymmetry here and it
/// is deliberate: a device with no name is not "before A", it is a row with
/// nothing in that column, and burying forty of them at the top of an ascending
/// sort would hide everything the sort was for.
fn sort_key(
    column: Column,
    host: &muster_net::discover::Found,
    named: Option<&Identity>,
    kind: muster_net::Kind,
) -> (bool, String, u128) {
    let text = |value: String| (value.is_empty(), value.to_ascii_lowercase(), 0u128);
    match column {
        Column::Kind => (
            kind == muster_net::Kind::Unknown,
            kind.label().to_ascii_lowercase(),
            0,
        ),
        // Ordered as a number, not as the text of one: `192.168.0.9` before
        // `192.168.0.10`, which sorting the strings gets backwards.
        Column::Address => (false, String::new(), address_key(host.address)),
        Column::Name => text(
            named
                .and_then(Identity::best)
                .map(|n| n.value.clone())
                .unwrap_or_default(),
        ),
        Column::Mac => text(host.mac.map(|m| m.to_string()).unwrap_or_default()),
        // A device that never gave a time has none, rather than a time of zero.
        Column::Time => (
            host.rtt.is_none(),
            String::new(),
            host.rtt.map_or(0, |t| t.as_micros()),
        ),
        // Most-serving first when descending, and the badge names break the
        // ties so two routers do not swap places between scans.
        Column::Serves => {
            let roles = named.map(Identity::roles).unwrap_or_default();
            (
                roles.is_empty(),
                roles
                    .iter()
                    .map(|r| r.label())
                    .collect::<Vec<_>>()
                    .join(" ")
                    .to_ascii_lowercase(),
                roles.len() as u128,
            )
        }
        Column::Vendor => text(match host.mac.map(muster_net::vendor::lookup) {
            Some(muster_net::vendor::Origin::Randomised) => "randomised address".to_string(),
            Some(other) => other.label().to_string(),
            None => String::new(),
        }),
    }
}

/// An address as one number, so both families order sensibly and v4 sorts
/// before v6.
fn address_key(address: std::net::IpAddr) -> u128 {
    match address {
        std::net::IpAddr::V4(v4) => u128::from(u32::from(v4)),
        std::net::IpAddr::V6(v6) => u128::from(v6) | 1 << 127,
    }
}

/// The table's headings, which are also its sort controls.
///
/// Every heading is a click target, including the icon column's, whose label is
/// deliberately empty: "Kind" over a column of pictures labels the obvious and
/// adds a word to the densest screen in the application. It still sorts, and
/// the caret is what says so.
fn table_header(ui: &mut egui::Ui, p: Palette, sort: &mut Sort) {
    // §7.16: a table header is a 26 px row in `text_dim`. It was 20 px in
    // `placeholder`, which is the eyebrow's colour and a different rank.
    let (rect, _) =
        ui.allocate_exact_size(vec2(ui.available_width(), metrics::ROW), Sense::hover());
    let mut x = rect.left() + metrics::PAD_PANEL;
    let last = rect.right() - metrics::PAD_PANEL;
    for (label, width, column) in [
        ("", COL_KIND, Column::Kind),
        ("Address", COL_ADDRESS, Column::Address),
        ("Name", COL_NAME, Column::Name),
        ("Hardware", COL_MAC, Column::Mac),
        ("Time", COL_TIME, Column::Time),
        ("Serves", COL_SERVES, Column::Serves),
        ("Made by", 0.0, Column::Vendor),
    ] {
        let span = if width > 0.0 { width } else { last - x };
        let cell = Rect::from_min_max(pos2(x, rect.top()), pos2(x + span, rect.bottom()));
        let response = ui.interact(
            cell,
            ui.id().with(("sort", label, column as usize)),
            Sense::click(),
        );
        if response.clicked() {
            sort.clicked(column);
        }
        let active = sort.column == column;
        let ink = if active {
            p.text_strong
        } else if response.hovered() {
            p.text_muted
        } else {
            p.text_dim
        };
        ui.painter().text(
            pos2(x, rect.center().y),
            egui::Align2::LEFT_CENTER,
            label,
            FontId::proportional(text::TINY),
            ink,
        );
        if active {
            // The caret sits after the label rather than at the column's right
            // edge, so it stays attached to the word it qualifies in a column
            // whose content is right-aligned.
            let after = ui
                .painter()
                .layout_no_wrap(label.to_string(), FontId::proportional(text::TINY), ink)
                .size()
                .x;
            caret(
                ui,
                pos2(x + after + metrics::S1 + CARET / 2.0, rect.center().y),
                sort.ascending,
                p.accent,
            );
        }
        if response.hovered() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        }
        x += span;
    }
    // `line`, not `line_soft`: this is the edge of a strip, and `line_soft`
    // belongs between rows inside a list.
    hairline_strip(ui, p, rect.bottom());
}

/// The sort caret's box.
const CARET: f32 = 8.0;

/// Which way a column is pointing: two strokes, from the same set as the
/// chevron on a menu button.
fn caret(ui: &mut egui::Ui, centre: egui::Pos2, up: bool, ink: Color32) {
    let (w, h) = (CARET * 0.34, CARET * 0.20);
    let tip = if up { -h } else { h };
    for arm in [-w, w] {
        ui.painter().line_segment(
            [
                pos2(centre.x + arm, centre.y - tip),
                pos2(centre.x, centre.y + tip),
            ],
            Stroke::new(1.3_f32, ink),
        );
    }
}

/// The badges: what a device serves the network.
///
/// §2.5 reserves colour for state and a badge is not a state, so these are a
/// neutral fill with strong text — the same recipe a selected row uses, which
/// is what keeps them from reading as warnings. The kind icon beside them is
/// the one coloured thing in the row and it stays that way.
fn badges(ui: &egui::Ui, p: Palette, rect: Rect, roles: &[muster_net::identify::Role]) {
    let font = FontId::proportional(text::TINY);
    let mut x = rect.left();
    for role in roles {
        let galley =
            ui.painter()
                .layout_no_wrap(role.label().to_string(), font.clone(), p.text_strong);
        let width = galley.size().x + metrics::S1 * 2.0;
        if x + width > rect.right() {
            return;
        }
        let pill =
            Rect::from_center_size(pos2(x + width / 2.0, rect.center().y), vec2(width, BADGE_H));
        ui.painter()
            .rect_filled(pill, metrics::RADIUS_TIGHT, p.control);
        ui.painter().text(
            pill.center(),
            egui::Align2::CENTER_CENTER,
            role.label(),
            font.clone(),
            p.text_strong,
        );
        x += width + metrics::S1;
    }
}

/// A badge's height. Short enough to sit inside a 20 px row with air above and
/// below it.
const BADGE_H: f32 = 14.0;

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
    vantage: muster_net::kind::Vantage,
    selected: bool,
) -> egui::Response {
    let (rect, response) =
        ui.allocate_exact_size(vec2(ui.available_width(), metrics::ROW), Sense::click());
    // Selection is a **neutral** fill plus strong text plus a small accent
    // mark, and never an accent background. The rule the whole design language
    // exists to protect, drawn the same way `nav_row` draws it.
    if selected {
        ui.painter()
            .rect_filled(rect, TABLE_SELECTION_RADIUS, p.control);
        ui.painter().rect_filled(
            Rect::from_min_size(rect.left_top(), vec2(metrics::NAV_MARK_W, rect.height())),
            TABLE_SELECTION_RADIUS,
            p.accent,
        );
    } else if response.hovered() {
        ui.painter()
            .rect_filled(rect, TABLE_SELECTION_RADIUS, p.control_hover);
    }

    let figure = FontId::monospace(text::TINY);
    let mut x = rect.left() + metrics::PAD_PANEL;
    let y = rect.center().y;

    // What this device appears to be, and why. The guess is `muster-net`'s;
    // this file only decides how big to draw it.
    let empty = Identity::default();
    let guess = muster_net::kind::identify(host, named.unwrap_or(&empty), vantage);
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

    // What this device serves the network, as against what it is. The icon
    // says the one and these say the other; a router that is also the name
    // server shows both, which no single label could.
    let roles = named.map(Identity::roles).unwrap_or_default();
    badges(
        ui,
        p,
        Rect::from_min_max(pos2(x, rect.top()), pos2(x + COL_SERVES, rect.bottom())),
        &roles,
    );
    x += COL_SERVES;

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
        for role in &roles {
            tip.push_str(&format!("{}: {}\n", role.label(), role.reason()));
        }
        // The claim first, with its reason attached. `CLAUDE.md`: every claim
        // about a device is shown beside the reason for it, and an icon with no
        // way to ask "why do you think that" is a guess wearing a confident
        // face.
        if let Some(guess) = guess {
            tip.push_str(&format!(
                "{}, because {}\n",
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
                note(ui, p, "", "could not be read");
            } else if s.gateways.is_empty() {
                note(ui, p, "", "none, there is no default route");
            } else {
                for g in &s.gateways {
                    fact(ui, p, "", &g.address.to_string());
                }
            }

            section(ui, p, "DNS");
            if s.resolvers.is_empty() {
                note(ui, p, "", "none configured");
            }
            for r in &s.resolvers {
                fact(ui, p, "", &r.to_string());
            }

            section(ui, p, "DHCP");
            if s.dhcp_servers.is_empty() {
                note(ui, p, "", "no lease recorded");
            }
            for d in &s.dhcp_servers {
                fact(ui, p, "", &d.to_string());
            }
            dhcp_check(ui, p, app);

            if !s.gaps.is_empty() {
                section(ui, p, "Could not read");
                for gap in &s.gaps {
                    note(ui, p, &gap.reading.to_string(), &gap.because);
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
                    .font(theme::strong(text::HEADING))
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

/// The update check, and what it reports.
///
/// The switch that governs it is not here. `CLAUDE.md` puts it in one place
/// and that place is Settings, General; this screen says where, and offers the
/// check a person asks for, which is never held back by the throttle.
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
        if button(ui, p, "Check now", Kind::Secondary, !busy).clicked() && !busy {
            updates.check();
        }
        // A result the user asked for is shown where they asked for it, so the
        // offer opens from here rather than being thrown up as a modal.
        if matches!(updates.status(), crate::update::Status::Available(_))
            && button(ui, p, "What is in it", Kind::Secondary, true).clicked()
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

/// One `key  value` line, where the value is a **figure**.
///
/// §4: figures are monospaced and tabular so columns line up and a value does
/// not jitter as it changes. Addresses, hardware addresses and counts are
/// figures.
fn fact(ui: &mut egui::Ui, p: Palette, key: &str, value: &str) {
    fact_of(ui, p, key, value, true)
}

/// One `key  value` line, where the value is a **sentence**.
///
/// The other half of the same rule, and the half that was missing: every value
/// went through `monospace()`, so "could not be read" and "none configured"
/// came out set as though they were numbers.
fn note(ui: &mut egui::Ui, p: Palette, key: &str, value: &str) {
    fact_of(ui, p, key, value, false)
}

fn fact_of(ui: &mut egui::Ui, p: Palette, key: &str, value: &str, figure: bool) {
    ui.horizontal(|ui| {
        ui.add_space(metrics::PAD_PANEL);
        if !key.is_empty() {
            ui.label(RichText::new(key).size(text::SMALL).color(p.text_dim));
        }
        let body = RichText::new(value).size(text::SMALL).color(p.text);
        ui.label(if figure { body.monospace() } else { body });
    });
}

/// §7.19's empty state: what is not here, and the way out of it.
///
/// `action` is drawn as a secondary button under the sentence and returns true
/// when it was pressed. An empty state that only describes the emptiness makes
/// the reader hunt for the control in another strip.
fn empty_state(ui: &mut egui::Ui, p: Palette, message: &str, action: Option<&str>) -> bool {
    let mut pressed = false;
    ui.vertical_centered(|ui| {
        ui.add_space(metrics::S4 * 2.0);
        ui.label(RichText::new(message).size(text::BODY).color(p.text_dim));
        if let Some(action) = action {
            ui.add_space(metrics::S3);
            pressed = button(ui, p, action, Kind::Secondary, true).clicked();
        }
    });
    pressed
}

// ── hairlines ───────────────────────────────────────────────────────────────
//
// Every strip and panel edge is one, and they are painted rather than left to
// egui's separators so that the colour is the token and the width is exactly
// one pixel.

/// The edge of a strip: `line`, one step stronger than a row's.
///
/// §5 keeps three weights of edge apart and they are not interchangeable:
/// `line` bounds a strip or a panel, `line_soft` separates rows inside a list,
/// and `line_popover` edges a thing that floats.
fn hairline_strip(ui: &mut egui::Ui, p: Palette, y: f32) {
    let rect = ui.max_rect();
    ui.painter().rect_filled(
        Rect::from_min_size(
            pos2(rect.left(), y - metrics::HAIRLINE),
            vec2(rect.width(), metrics::HAIRLINE),
        ),
        0.0,
        p.line,
    );
}

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

    // **Two static instances, not the variable font.** `Archivo.ttf` is
    // variable and its default instance is SemiBold; `ab_glyph`, which egui
    // rasterises with, does not apply variation axes, so registering it drew
    // the entire interface at 600. These two are cut from it at 400 and 600 by
    // `tools/make-fonts.py`, which is the only reason §4's "two weights only"
    // is expressible here at all.
    for (name, bytes) in [
        (
            "archivo",
            include_bytes!("../assets/Archivo-Regular.ttf").as_slice(),
        ),
        (
            theme::STRONG,
            include_bytes!("../assets/Archivo-SemiBold.ttf").as_slice(),
        ),
    ] {
        fonts.font_data.insert(
            name.into(),
            std::sync::Arc::new(egui::FontData::from_static(bytes)),
        );
    }

    fonts
        .families
        .entry(egui::FontFamily::Proportional)
        .or_default()
        .insert(0, "archivo".into());
    // A family of its own rather than a fallback, so asking for weight is
    // asking by name and nothing gets it by accident.
    fonts.families.insert(
        egui::FontFamily::Name(theme::STRONG.into()),
        vec![theme::STRONG.to_string()],
    );
    ctx.set_fonts(fonts);
}

/// Pushes the palette into egui's own visuals, for the few things it draws
/// itself: scroll bars, tooltips, the window ground.
/// Apply `p`, told which ladder it is so egui's own defaults start from the
/// right side.
///
/// **`Visuals::dark()` was used for both themes**, so in Paper every scroll
/// bar, tooltip, text selection and modal dim was still derived from the dark
/// defaults. §3.1: a theme is a table, never a code path.
pub(crate) fn apply_for(ctx: &egui::Context, p: Palette, mode: Mode) {
    let mut visuals = match mode {
        Mode::Dark => egui::Visuals::dark(),
        Mode::Light => egui::Visuals::light(),
    };
    visuals.panel_fill = p.window;
    visuals.window_fill = p.popover;
    visuals.extreme_bg_color = p.field;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(metrics::HAIRLINE, p.line);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(metrics::HAIRLINE, p.text);
    visuals.window_stroke = Stroke::new(metrics::HAIRLINE, p.line_popover);
    // Shadows only under things that float; a panel is not one. The geometry
    // is §5's table, and it differs per kind: a menu is not a dialog.
    visuals.window_shadow = theme::shadow::floating(mode);
    visuals.popup_shadow = theme::shadow::menu(mode);
    visuals.selection.bg_fill = p.accent_ring;
    visuals.selection.stroke = Stroke::new(metrics::HAIRLINE, p.text_strong);
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
    let guess = muster_net::kind::identify(&host, &named, app.survey.vantage(address));
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
                // §5's floating panel: `chrome`, radius 10, and the middle of
                // the three shadows. It was `popover`, which is the surface a
                // *menu* sits on — near enough to look right and wrong by the
                // table that decides it.
                .fill(p.chrome.to_opaque())
                .stroke(Stroke::new(metrics::HAIRLINE, p.line_popover))
                .corner_radius(metrics::RADIUS_MODAL)
                .inner_margin(egui::Margin::same(metrics::PAD_PANEL as i8))
                .shadow(theme::shadow::floating(mode)),
        )
        .show(ctx, |ui| {
            ui.set_width(DETAIL_WIDTH);

            // Our own header: the name, and a close mark that is an icon
            // button rather than a letter.
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(&title)
                        .font(theme::strong(text::HEADING))
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
                    p.chrome,
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

            // What it serves the network, under the claim about what it is:
            // the two are independent, and a router that is also the name
            // server has to be able to say both.
            let roles = named.roles();
            if !roles.is_empty() {
                ui.add_space(metrics::S2);
                ui.horizontal(|ui| {
                    let (rect, _) = ui.allocate_exact_size(
                        vec2(DETAIL_WIDTH, metrics::ROW_PLAIN),
                        Sense::hover(),
                    );
                    badges(ui, p, rect, &roles);
                });
                for role in &roles {
                    ui.label(
                        RichText::new(role.reason())
                            .size(text::TINY)
                            .color(p.text_dim),
                    );
                }
            }

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
            // The model the device named for itself, above the names other
            // people gave it: it is the most specific thing on the row and it
            // is what the guess above was usually made from.
            if let Some(model) = &named.model {
                fact_row(ui, p, "Model", model);
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
            // The UPnP half, kept in its own row rather than folded in with the
            // mDNS services: they are two vocabularies, and one list holding
            // `_ipp._tcp` beside `urn:schemas-upnp-org:device:Printer:1` reads
            // as neither.
            if !named.upnp.is_empty() {
                fact_row(ui, p, "UPnP", &named.upnp.join(", "));
            }
            if let Some(product) = &named.product {
                fact_row(ui, p, "Announces", product);
            }
            if let Some(resolver) = &named.resolver {
                // What the server said about itself, and what it will do for a
                // client. A server that would not say has answered the
                // question all the same, and the row says which.
                let what = match (&resolver.version, resolver.recursive) {
                    (Some(version), true) => format!("{version}, resolves for clients"),
                    (Some(version), false) => format!("{version}, its own zones only"),
                    (None, true) => "would not name itself, resolves for clients".to_string(),
                    (None, false) => "would not name itself".to_string(),
                };
                fact_row(ui, p, "Name server", &what);
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
/// The same three probes the sweep uses, through `discover::recheck`, so a
/// re-check and the sweep cannot disagree about what counts as an answer. It is
/// the question somebody actually has in front of a device list: *is it still
/// there?*
///
/// **And it answers a second question the first one hides.** A probe that could
/// not run is not a device that did not answer, so what this reports is which
/// of the two happened: a machine with ping sockets closed — a Linux where
/// `net.ipv4.ping_group_range` excludes the user — sends no echo at all, and
/// saying "nothing came back this time" there is the application blaming a
/// device for its own missing permission.
fn ping_section(
    ui: &mut egui::Ui,
    p: Palette,
    app: &mut App,
    address: std::net::IpAddr,
    swept_rtt: Option<std::time::Duration>,
) {
    ui.horizontal(|ui| {
        let waiting = app.ping.as_ref().is_some_and(|(a, _)| *a == address);
        if button(ui, p, "Ping", Kind::Secondary, !waiting).clicked() && !waiting {
            app.start_ping(address);
        }
        ui.add_space(metrics::S2);

        let answer = app.pinged.as_ref().filter(|(a, _)| *a == address);
        let line = if waiting {
            "asking…".to_string()
        } else {
            match answer {
                Some((_, r)) => match r.found.as_ref().and_then(|f| f.rtt) {
                    Some(rtt) => format!("answered in {} ms", rtt.as_millis()),
                    // A gap first, and it is the whole point of the change: a
                    // probe that never ran has nothing to say about the
                    // device, so it says something about this machine
                    // instead.
                    None if !r.not_done.is_empty() => {
                        format!("no time to report: {}", r.not_done.join("; "))
                    }
                    // It answered something, just not an echo, so the line
                    // names what did answer. "Nothing came back" about a
                    // device that answered ARP a moment ago is the same lie in
                    // a smaller way.
                    None if r.found.is_some() => {
                        let how: Vec<String> = r
                            .found
                            .iter()
                            .flat_map(|f| f.evidence.iter())
                            .map(muster_net::discover::Evidence::reason)
                            .collect();
                        format!("still there ({}), but no ICMP reply", how.join(", "))
                    }
                    // **Not "it is gone".** Silence is a device that is off, a
                    // device that drops, or a probe that was rate limited into
                    // the next second. The sweep's own rule, kept here.
                    None => "nothing came back this time".to_string(),
                },
                None => match swept_rtt {
                    Some(rtt) => format!("{} ms when it was swept", rtt.as_millis()),
                    None => String::new(),
                },
            }
        };
        // Amber where the machine could not ask, because that is a state the
        // reader has to act on rather than a reading of the network.
        let ink = match answer {
            Some((_, r))
                if !r.not_done.is_empty() && r.found.as_ref().is_none_or(|f| f.rtt.is_none()) =>
            {
                p.caution
            }
            _ => p.text_dim,
        };
        ui.label(RichText::new(line).size(text::TINY).color(ink));
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
    ui.painter().rect_filled(front, 2.0, p.chrome);
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
                if button(ui, p, "Stop", Kind::Secondary, true).clicked() {
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
            if button(ui, p, "Scan again", Kind::Secondary, true).clicked() {
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
            if button(ui, p, "Scan ports", Kind::Primary, true).clicked() {
                app.ports = ports::State::start(address, muster_net::portscan::Ports::common());
            }
        }
    }
}

/// Who offers addresses on this link, and whether more than one does.
///
/// A button, and — when the scan menu says so — a part of every scan. Both send
/// the same DISCOVER through the same engine, and this screen shows whichever
/// answer is newer, so nobody has to ask the same question twice from two
/// places. Nothing ever takes an offer.
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
        let response = button(ui, p, label, Kind::Secondary, can);
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

    // The last scan's answer, where it asked. A check made from this button is
    // newer by construction — it cannot have run before a scan that is already
    // finished — so it wins.
    let from_scan = match &app.scan {
        State::Finished(outcome) => outcome.dhcp.as_deref(),
        _ => None,
    };
    let Some(probe) = app.dhcp.result().or(from_scan) else {
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

    for offer in probe.distinct_offers() {
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
    // §7.2: an options strip is `chrome`, 36 px, with a hairline under it. It
    // was drawn straight onto the window with no ground of its own, so the
    // fields floated in the table's own surface.
    let strip = Rect::from_min_size(
        ui.max_rect().left_top(),
        vec2(ui.available_width(), metrics::OPTIONS_STRIP),
    );
    ui.painter().rect_filled(strip, 0.0, p.chrome);
    ui.painter().rect_filled(
        Rect::from_min_size(
            pos2(strip.left(), strip.bottom() - metrics::HAIRLINE),
            vec2(strip.width(), metrics::HAIRLINE),
        ),
        0.0,
        p.line,
    );

    ui.scope_builder(egui::UiBuilder::new().max_rect(strip), |ui| {
        ui.horizontal_centered(|ui| {
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

            ui.add_space(metrics::S3);
            // The one thing to do on this view, beside the range it acts on.
            scan_control(ui, p, app);

            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.add_space(metrics::PAD_PANEL);
                if !app.search.is_empty() && button(ui, p, "Clear", Kind::Ghost, true).clicked() {
                    app.search.clear();
                }
                field(ui, p, &mut app.search, 200.0, "Search");
                ui.label(RichText::new("Filter").size(text::TINY).color(p.text_dim));
            });
        });
    });
    ui.add_space(metrics::S2);
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
    // §7.11: radius 6, which is the tool radius rather than the button's 5.
    ui.painter()
        .rect_filled(rect, metrics::RADIUS_TOOL, p.field);

    let inner = rect.shrink2(vec2(metrics::S2, 0.0));
    let mut child = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(inner)
            .layout(Layout::left_to_right(Align::Center)),
    );
    let response = child.add(
        egui::TextEdit::singleline(text_of)
            .desired_width(inner.width())
            .frame(false)
            .hint_text(RichText::new(placeholder).color(p.placeholder))
            .font(FontId::proportional(text::CONTROL))
            .text_color(p.text),
    );
    // The edge last, so the focus ring sits over the fill rather than under
    // the text. Two pixels of `accent_ring` when it has the keyboard, a
    // hairline otherwise: §7.11, and the one focus indication in the
    // application.
    let (edge, width) = if response.has_focus() {
        (p.accent_ring, 2.0)
    } else {
        (p.line, metrics::HAIRLINE)
    };
    ui.painter().rect_stroke(
        rect,
        metrics::RADIUS_TOOL,
        Stroke::new(width, edge),
        egui::StrokeKind::Inside,
    );
    response
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

#[cfg(test)]
mod tests {
    use super::*;
    use muster_net::discover::{Evidence, Found};
    use muster_net::identify::{Resolver, Role};
    use muster_net::mac::MacAddr;
    use std::net::{IpAddr, Ipv4Addr};

    fn at(address: &str) -> Found {
        Found {
            address: address.parse().unwrap(),
            mac: None,
            evidence: vec![Evidence::Arp(MacAddr::new([0, 0, 0, 0, 0, 1]))],
            rtt: None,
        }
    }

    /// `192.168.0.9` comes before `192.168.0.10`, which sorting the text of an
    /// address gets backwards — and gets backwards on exactly the networks
    /// people scan.
    #[test]
    fn addresses_sort_as_numbers_and_not_as_text() {
        let mut rows = ["192.168.0.10", "192.168.0.9", "192.168.0.100"].map(at);
        rows.sort_by_key(|host| address_key(host.address));
        let order: Vec<String> = rows.iter().map(|h| h.address.to_string()).collect();
        assert_eq!(order, ["192.168.0.9", "192.168.0.10", "192.168.0.100"]);
    }

    /// And both families order, with v4 first, so a dual-stack table does not
    /// interleave them at random.
    #[test]
    fn the_two_address_families_do_not_interleave() {
        let v4 = address_key(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)));
        let v6 = address_key("::1".parse().unwrap());
        assert!(v4 < v6, "every v4 address sorts before every v6 one");
    }

    /// An empty cell sorts last whichever way the column points. See
    /// `sort_key`: burying the unnamed rows at the top of an ascending sort
    /// would hide everything the sort was for.
    #[test]
    fn a_blank_cell_sorts_last_in_both_directions() {
        let named = Identity {
            names: vec![muster_net::identify::Name {
                value: "printer".into(),
                source: muster_net::identify::Source::Mdns,
            }],
            ..Default::default()
        };
        let with = sort_key(
            Column::Name,
            &at("192.0.2.1"),
            Some(&named),
            muster_net::Kind::Unknown,
        );
        let without = sort_key(
            Column::Name,
            &at("192.0.2.2"),
            None,
            muster_net::Kind::Unknown,
        );
        assert!(!with.0 && without.0, "emptiness is the first key");
    }

    /// Clicking the heading that is already sorted reverses it; clicking
    /// another starts that one ascending.
    #[test]
    fn a_second_click_reverses_and_a_different_column_starts_over() {
        let mut sort = Sort::default();
        assert_eq!(sort.column, Column::Address);
        assert!(sort.ascending);

        sort.clicked(Column::Address);
        assert!(!sort.ascending, "the same column turns around");

        sort.clicked(Column::Time);
        assert_eq!(sort.column, Column::Time);
        assert!(sort.ascending, "a new column always starts ascending");
    }

    /// The badges sort by how many a device has, so the network's own
    /// infrastructure comes to one end of the table.
    #[test]
    fn serving_more_sorts_above_serving_less() {
        let router = Identity {
            resolver: Some(Resolver::default()),
            dhcp: true,
            ..Default::default()
        };
        let resolver = Identity {
            resolver: Some(Resolver::default()),
            ..Default::default()
        };
        assert_eq!(router.roles(), vec![Role::Dhcp, Role::Dns]);
        let both = sort_key(
            Column::Serves,
            &at("192.0.2.1"),
            Some(&router),
            muster_net::Kind::Router,
        );
        let one = sort_key(
            Column::Serves,
            &at("192.0.2.2"),
            Some(&resolver),
            muster_net::Kind::Server,
        );
        let none = sort_key(
            Column::Serves,
            &at("192.0.2.3"),
            None,
            muster_net::Kind::Unknown,
        );
        assert!(both.2 > one.2);
        assert!(!one.0 && none.0, "and a device serving nothing is blank");
    }

    #[test]
    fn every_view_has_a_label() {
        for view in View::ALL {
            assert!(!view.label().is_empty());
        }
        assert_eq!(View::Devices.label(), "Devices");
    }

    /// Every view needs a row somewhere, and the sidebar draws its two groups
    /// from two lists: a view added to [`View::ALL`] and to neither group is a
    /// screen with no way in, and one in both is a screen with two.
    #[test]
    fn every_view_has_exactly_one_row_in_the_sidebar() {
        for view in View::ALL {
            let destination = View::DESTINATIONS.contains(&view);
            let foot = view == View::About;
            assert!(
                destination != foot,
                "{view:?} has {} rows",
                destination as u8 + foot as u8
            );
        }
    }

    /// The columns are laid out by adding widths along a row, so they only line
    /// up if the header and the row walk the same numbers. Pinning the sum is
    /// what catches a column added to one and not the other.
    #[test]
    fn the_table_columns_are_one_set_of_numbers() {
        assert_eq!(COL_ADDRESS + COL_NAME + COL_MAC + COL_TIME, 534.0);
    }
}
