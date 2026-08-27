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
use crate::{deviceicon, dhcpcheck, ping, ports, prefs, settings, updatedlg};
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
    /// Re-checks: the last answer about each device, and any run in flight.
    ///
    /// A map rather than "the last one", because a run can be about twenty
    /// devices and because a loop keeps answering. See [`crate::ping`], which
    /// also holds the reason the whole `Recheck` is kept rather than the round
    /// trip: a round trip cannot tell "it did not answer" from "the question
    /// was never asked".
    ping: ping::State,
    /// The device window is showing its ping history beside the facts.
    ///
    /// Session state rather than a setting: it is a way of looking at the
    /// device in front of you, and it stays on while you click from one device
    /// to the next because that is the point of having opened it.
    history_open: bool,
    /// The devices the user has marked, by address.
    ///
    /// By address for the same reason [`Self::selected`] is: a second scan
    /// reorders the table, and an index would carry a mark to whatever moved
    /// into that row. A device that is no longer in the table keeps its mark
    /// and is simply not shown, which is what makes a mark survive a rescan of
    /// the same network.
    marked: std::collections::BTreeSet<std::net::IpAddr>,
    /// What was last copied, and when, for the pill at the foot of the window.
    copied: Option<(String, std::time::Instant)>,
    /// Devices waiting for a port scan, in order.
    ///
    /// **A queue rather than a set of threads**, because the rate limiter is
    /// global: two scans at once would each get half the budget and both would
    /// report a machine as more filtered than it is. `ports::State` owns that
    /// rule and this is what lets an action over twenty devices honour it.
    port_queue: std::collections::VecDeque<std::net::IpAddr>,
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
            ping: ping::State::default(),
            history_open: false,
            marked: std::collections::BTreeSet::new(),
            copied: None,
            port_queue: std::collections::VecDeque::new(),
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
            ping: ping::State::default(),
            history_open: false,
            marked: std::collections::BTreeSet::new(),
            copied: None,
            port_queue: std::collections::VecDeque::new(),
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

    /// Ask one device again, on a thread. The panel's own Ping button.
    fn start_ping(&mut self, address: std::net::IpAddr) {
        self.start_pings(vec![address], false);
    }

    /// Ask several devices again, once or until stopped.
    ///
    /// One entry point for the panel's button and the table's action menu, so
    /// there is one place that decides what a re-check is and the two cannot
    /// ask differently.
    fn start_pings(&mut self, targets: Vec<std::net::IpAddr>, looping: bool) {
        let on_link = self.target.is_some_and(|p| self.on_link(p));
        let every = std::time::Duration::from_millis(self.prefs.ping_every.into());
        self.ping.start_every(targets, looping, on_link, every);
    }

    /// Open the settings page, for `examples/docs-images.rs`.
    pub fn open_settings(&mut self) {
        self.settings.open();
    }

    /// Open the settings page on its Scanning pane, for
    /// `examples/docs-images.rs`.
    pub fn open_scanning(&mut self) {
        self.settings.open();
        self.settings.pane = settings::Pane::Scanning;
    }

    /// Open the detail window on one device.
    ///
    /// The seam `examples/docs-images.rs` uses to photograph it. Nothing else
    /// outside this module sets the selection.
    pub fn select(&mut self, address: std::net::IpAddr) {
        self.selected = Some(address);
    }

    /// Open the device window's history column, for `examples/docs-images.rs`.
    pub fn show_history(&mut self, samples: &[(u64, bool)]) {
        self.history_open = true;
        if let Some(address) = self.selected {
            self.ping.seed(address, samples);
        }
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

    /// Take the next device off the port-scan queue, if nothing is running.
    ///
    /// Called where a scan could have finished as well as where one is asked
    /// for, so a queue drains without anything having to watch it.
    fn start_next_port_scan(&mut self) {
        if self.ports.is_running() {
            return;
        }
        if let Some(address) = self.port_queue.pop_front() {
            self.ports = ports::State::start(address, muster_net::portscan::Ports::common());
        }
    }

    /// What a scan is asked to do, out of the settings.
    fn scan_options(&self) -> scan::Options {
        scan::Options {
            rate: self.prefs.rate,
            identify: self.prefs.identify,
            dns: self.prefs.scan_dns,
            dhcp: self.prefs.scan_dhcp,
            smb: self.prefs.scan_smb,
            nfs: self.prefs.scan_nfs,
            ssh: self.prefs.scan_ssh,
            reverse: self.prefs.scan_reverse,
            listen: self.prefs.scan_listen,
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
        // A finished scan has been folded into its device above, so the next
        // one may start. Outside the `if` on purpose: the queue has to drain on
        // the frame after a scan ends, and that frame has nothing new to poll.
        self.start_next_port_scan();
        if !self.port_queue.is_empty() {
            ctx.request_repaint_after(std::time::Duration::from_millis(120));
        }
        if self.dhcp.poll() || self.dhcp.is_running() {
            ctx.request_repaint_after(std::time::Duration::from_millis(120));
        }
        if self.ping.poll() || self.ping.is_running() {
            ctx.request_repaint_after(std::time::Duration::from_millis(60));
        }
        // The pill at the foot fades on a clock rather than on an event, so
        // the frame that takes it away has to be asked for.
        if self.copied.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(200));
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
        // Over everything, in the corner §7.17 gives a toast, and after the
        // status bar so it sits above it rather than under it.
        copied_pill(ctx, p, self);
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

                // **Nothing else lives up here, and that is the whole of §6.2.**
                // The gear was in this corner once, which put navigation in the
                // one place furthest from every other way of getting somewhere;
                // it is a row at the foot of the sidebar now, beside About.
                //
                // The scan control was here too, and then what a scan *asks*
                // was here as a menu of its own after the control had moved
                // down to the options strip — which left a menu in one strip
                // governing a button in another. Both are in the strip above
                // the table now, and they are one control: see
                // [`scan_control`], where the arrow at the button's right end
                // opens exactly what that menu carried.
            });
        });
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

/// Start or stop, and beside it what the next scan will ask.
///
/// **A split control**, which is new to §7.6 and is here for a reason the
/// alternatives could not meet. What a scan asks used to be a menu of its own
/// in the top bar, and the button that acts on those settings was down here
/// beside the range it sweeps: a control in one strip governing a menu in
/// another is how a reader loses the connection between them. Folding the menu
/// into the button's own right-hand end puts the question and the answer in one
/// place, and leaves the top bar to the mark, which is §6.2's whole argument.
///
/// Cancelling is available throughout a scan and takes effect at the next
/// probe, so the acting half never has to be disabled mid-run. The arrow is
/// never disabled at all: a scan that is running is exactly when somebody wants
/// to set up the next one.
fn scan_control(ui: &mut egui::Ui, p: Palette, app: &mut App) {
    let running = app.scan.is_running();
    let can = running || app.target.is_some();
    let label = match (running, &app.scan) {
        (true, _) => "Stop",
        (_, State::Finished(_)) => "Scan again",
        _ => "Scan",
    };
    let kind = if running {
        Kind::Secondary
    } else {
        Kind::Primary
    };

    let split = split_button(ui, p, label, kind, can);
    if !can {
        // A control that cannot act says why rather than being mysteriously
        // dead. `CLAUDE.md`: nothing claims what the app cannot do.
        split.act.clone().on_hover_text(
            "No local network small enough to sweep. Run `muster survey` to see what \
             this machine knows.",
        );
    }
    if split.act.clicked() && can {
        if running {
            app.scan.cancel();
        } else {
            app.start_scan();
        }
    }

    scan_options(ui, p, app, &split);
}

/// The two halves of a split button, and the whole it was drawn in.
struct Split {
    /// The label's half: the thing the button does.
    act: egui::Response,
    /// The arrow's half: the thing it opens.
    more: egui::Response,
    /// Both together, which is what a popover hangs off. Anchoring to the arrow
    /// alone would hang a 320 px panel off a 26 px control and leave it looking
    /// like it belonged to nothing.
    whole: Rect,
}

/// §7.6's button with an arrow fenced off at its right end.
///
/// One fill, one radius and one hairline between the halves, so it reads as one
/// control that can be pressed in two places rather than as two controls that
/// happen to touch. The hovered half is the one that lights up, which is the
/// only thing that tells somebody which of the two they are about to press.
fn split_button(ui: &mut egui::Ui, p: Palette, label: &str, kind: Kind, enabled: bool) -> Split {
    let font = match kind {
        Kind::Primary => theme::strong(text::CONTROL),
        _ => FontId::proportional(text::CONTROL),
    };
    let galley = ui
        .painter()
        .layout_no_wrap(label.to_string(), font, Color32::PLACEHOLDER);
    let width = galley.size().x + metrics::PAD_PANEL * 2.0 + ARROW_HALF;
    let (whole, _) = ui.allocate_exact_size(vec2(width, metrics::BUTTON), Sense::hover());
    let (left, right) = whole.split_left_right_at_x(whole.right() - ARROW_HALF);

    let id = ui.id().with("split");
    let act = ui.interact(
        left,
        id.with("act"),
        if enabled {
            Sense::click()
        } else {
            Sense::hover()
        },
    );
    // Never disabled: see [`scan_control`].
    let more = ui.interact(right, id.with("more"), Sense::click());

    let hovered = enabled && (act.hovered() || more.hovered());
    // **The fill is taken unhovered on purpose**, and the border and the ink
    // are not. A filled kind lights up half of itself below, so a base fill
    // that had already lit the whole control would make the half that is
    // actually under the pointer indistinguishable from the half that is not.
    // A border and an ink belong to the control as a whole and follow it.
    let (fill, _, _) = skin(p, kind, false);
    let (_, border, ink) = skin(p, kind, hovered);
    let dim = |c: Color32| {
        if enabled { c } else { c.gamma_multiply(0.45) }
    };

    if let Some(fill) = fill {
        ui.painter().rect_filled(whole, metrics::RADIUS, dim(fill));
    }
    if let Some(border) = border {
        ui.painter().rect_stroke(
            whole,
            metrics::RADIUS,
            Stroke::new(metrics::HAIRLINE, dim(border)),
            egui::StrokeKind::Inside,
        );
    }

    // The half under the pointer, rounded on its own outer side only, so the
    // highlight stops at the fence rather than at a corner of its own. The
    // primary keeps its accent under the pointer, exactly as [`button`] does.
    if enabled && fill.is_some() && kind != Kind::Primary {
        let r = metrics::RADIUS as u8;
        let ends = |outer_left: bool| {
            if outer_left {
                egui::CornerRadius {
                    nw: r,
                    sw: r,
                    ne: 0,
                    se: 0,
                }
            } else {
                egui::CornerRadius {
                    nw: 0,
                    sw: 0,
                    ne: r,
                    se: r,
                }
            }
        };
        if act.hovered() {
            ui.painter().rect_filled(left, ends(true), p.control_hover);
        } else if more.hovered() {
            ui.painter()
                .rect_filled(right, ends(false), p.control_hover);
        }
    }

    ui.painter().galley(
        pos2(
            left.center().x - galley.size().x / 2.0,
            left.center().y - galley.size().y / 2.0,
        ),
        galley,
        dim(ink),
    );

    // The fence. Drawn in the ink the label is drawn in, at a fraction of it,
    // so it belongs to the control in both themes: there is no line token that
    // reads as a border on an accent fill.
    let inset = metrics::S1;
    ui.painter().line_segment(
        [
            pos2(right.left(), whole.top() + inset),
            pos2(right.left(), whole.bottom() - inset),
        ],
        Stroke::new(metrics::HAIRLINE, dim(ink.gamma_multiply(0.35))),
    );

    // Two strokes, from the same set as the close mark and the gear, rather
    // than a letter pretending to be an icon.
    let c = right.center();
    let (w, h) = (CHEVRON * 0.34, CHEVRON * 0.18);
    let point = if more.hovered() {
        ink
    } else {
        ink.gamma_multiply(0.8)
    };
    for arm in [-w, w] {
        ui.painter().line_segment(
            [pos2(c.x + arm, c.y - h), pos2(c.x, c.y + h)],
            Stroke::new(1.4_f32, dim(point)),
        );
    }

    let act = if enabled {
        act.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        act
    };
    // §11: an icon-only control carries a tooltip. This one is a chevron and
    // nothing else, so it says what it opens.
    let more = more
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .on_hover_text("What the next scan asks");
    Split { act, more, whole }
}

/// The arrow's half of a split button. Its own target, and no wider than it
/// needs to be: the width belongs to the label.
const ARROW_HALF: f32 = 26.0;

/// The chevron's box.
const CHEVRON: f32 = 12.0;

/// How wide the chevron's *ink* is, as against the box it is drawn in.
///
/// The arms reach `CHEVRON * 0.34` either side of the centre, so the mark is
/// barely two thirds of its box. Laying a menu button out against the box
/// rather than against this is what put the chevron on top of the label: the
/// width reserved twelve pixels after the word and the glyph floated in the
/// middle of them, leaving under two pixels of daylight where the eye reads a
/// gap. Everything in [`menu_button`] measures the ink, so the padding either
/// side of it is the padding it looks like.
const CHEVRON_INK: f32 = CHEVRON * 0.68;

/// The gap between a menu button's label and its chevron.
///
/// One step of the spacing scale, and smaller than the [`metrics::S3`] either
/// end of the button: a chevron is part of the label's claim about what the
/// control does, so it has to sit nearer the word than the word sits to the
/// button's edge. Equal gaps would read as two things side by side.
const MENU_GAP: f32 = metrics::S2;

/// What a scan asks, hung off the arrow.
///
/// A §7.17 popover. Everything in it writes [`crate::prefs::Prefs`] and is saved
/// as it changes, so this and the settings page's Scanning pane are two views of
/// one set of values rather than two sets that can drift apart.
///
/// **It stays open until it is dismissed.** A menu closes on the first click,
/// which is right for a menu and wrong for a panel of switches: somebody
/// turning two things on had to reopen it between them. So the ways out are a
/// click outside it, escape, and the Scan button at its foot, which is the same
/// set a dialog has.
///
/// **A running scan does not read these again.** [`scan::Options`] is taken once
/// at the start, so moving a control here changes the *next* scan and never the
/// one on screen. The note at the foot says so rather than leaving somebody to
/// wonder why nothing happened.
fn scan_options(ui: &mut egui::Ui, p: Palette, app: &mut App, split: &Split) {
    let mut changed = false;
    let mut go = false;
    let mode = app.mode;
    let id = egui::Popup::default_response_id(&split.more);

    egui::Popup::from_toggle_button_response(&split.more)
        .anchor(split.whole)
        .kind(egui::PopupKind::Menu)
        .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)
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
                    "The link as a whole over mDNS, SSDP, WS-Discovery and NetBIOS, and each device about itself.",
                    &mut app.prefs.identify,
                ),
                (
                    "Listen for devices",
                    "Sends nothing. Hears the questions other devices ask, which is how the quiet ones are found.",
                    &mut app.prefs.scan_listen,
                ),
                (
                    "Ask this network for names",
                    "One reverse lookup per address, to your own router. It names devices that are asleep.",
                    &mut app.prefs.scan_reverse,
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
                (
                    "Find file shares",
                    "The negotiate an SMB client sends first, on port 445. Nothing is opened.",
                    &mut app.prefs.scan_smb,
                ),
                (
                    "Find NFS exports",
                    "The null call the protocol defines for it, on port 2049. Nothing is read.",
                    &mut app.prefs.scan_nfs,
                ),
                (
                    "Read SSH greetings",
                    "Listens to what a server says on port 22. Nothing is sent to it.",
                    &mut app.prefs.scan_ssh,
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

            ui.add_space(metrics::S3);
            let (line, _) =
                ui.allocate_exact_size(vec2(SCAN_MENU_WIDTH, metrics::HAIRLINE), Sense::hover());
            ui.painter().rect_filled(line, 0.0, p.line_popover);
            ui.add_space(metrics::S2);

            if app.scan.is_running() {
                ui.label(
                    RichText::new("The scan running now keeps the settings it started with.")
                        .size(text::TINY)
                        .color(p.text_dim),
                );
            } else {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("These take effect on the next scan.")
                            .size(text::TINY)
                            .color(p.text_dim),
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let can = app.target.is_some();
                        if button(ui, p, "Scan", Kind::Primary, can).clicked() && can {
                            go = true;
                        }
                    });
                });
            }
        });

    if changed {
        prefs::save(&app.prefs);
    }
    // The one way out that also acts. Closed by hand rather than by the popover
    // itself: the click landed inside it, which is exactly the click this
    // popover is configured to ignore.
    if go {
        app.start_scan();
        egui::Popup::close_id(ui.ctx(), id);
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

/// What each of §7.6's kinds is made of: a fill, a border, and the ink on it.
///
/// One table, read by both [`button`] and [`split_button`]. It was inside
/// `button` while `button` was the only thing that drew one, and the split
/// control is what made a second reader of it: two copies of this table would
/// be two buttons that stopped matching the first time a token moved.
fn skin(p: Palette, kind: Kind, hovered: bool) -> (Option<Color32>, Option<Color32>, Color32) {
    match kind {
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
    }
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

    let (fill, border, ink) = skin(p, kind, enabled && response.hovered());

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

                // A ping that keeps going has to be visible from outside the
                // table it is filling: the Ping column says "asking" on the
                // rows in front of the reader, and this says how many rows
                // there are and which time round it is. A loop nothing on
                // screen mentions is a loop somebody leaves running.
                if let Some((done, total, pass)) = app.ping.progress() {
                    let mut line = format!(" · pinging {done} of {total}");
                    if pass > 1 {
                        line.push_str(&format!(", round {pass}"));
                    }
                    ui.label(RichText::new(line).size(text::TINY).color(p.text_dim));
                }
                if !app.port_queue.is_empty() {
                    ui.label(
                        RichText::new(format!(" · {} more to port scan", app.port_queue.len()))
                            .size(text::TINY)
                            .color(p.text_dim),
                    );
                }

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
    // nothing is exactly when somebody wants to change the range. It is drawn
    // after the rows have been decided rather than before, because the two
    // menus in it act on exactly the rows the filter is showing.
    let shown = shown_rows(app, &devices, &names, &survey);
    devices_toolbar(
        ui,
        p,
        app,
        Table {
            devices: &devices,
            names: &names,
            survey: &survey,
            shown: &shown,
        },
    );

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

    let marked_here = shown
        .iter()
        .filter(|i| app.marked.contains(&devices[**i].address))
        .count();

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.add_space(metrics::S2);
            let before = app.prefs.columns;
            if let Some(mark_all) = table_header(
                ui,
                p,
                &mut app.sort,
                Marks::of(marked_here, shown.len()),
                &mut app.prefs.columns,
            ) {
                for i in &shown {
                    let address = devices[*i].address;
                    if mark_all {
                        app.marked.insert(address);
                    } else {
                        app.marked.remove(&address);
                    }
                }
            }
            // A dragged column is a setting like any other, and it is written
            // the moment it stops changing rather than on every frame of a
            // drag: the file would otherwise be rewritten sixty times a second
            // for as long as somebody held the edge.
            if app.prefs.columns != before && !ui.ctx().input(|i| i.pointer.any_down()) {
                crate::prefs::save(&app.prefs);
            }
            let widths = app.prefs.columns;
            let mode = app.mode;
            for i in &shown {
                let host = &devices[*i];
                let named = names.get(*i);
                let vantage = survey.vantage(host.address);
                let selected = app.selected == Some(host.address);
                let marked = app.marked.contains(&host.address);
                let ping = if app.ping.waiting_for(host.address) {
                    PingCell::Waiting
                } else {
                    match app.ping.answer_for(host.address) {
                        Some(answer) => PingCell::Answer(answer),
                        None => PingCell::Never,
                    }
                };
                let row = device_row(
                    ui,
                    p,
                    host,
                    RowInput {
                        mode,
                        named,
                        vantage,
                        selected,
                        marked,
                        ping,
                        widths,
                    },
                );
                if row.marked {
                    if marked {
                        app.marked.remove(&host.address);
                    } else {
                        app.marked.insert(host.address);
                    }
                }
                if row.clicked {
                    // Clicking the open row shuts the window, which is the way
                    // back to the table without reaching for a close button.
                    app.selected = if selected { None } else { Some(host.address) };
                }
            }
            if shown.is_empty() {
                empty_state(ui, p, "Nothing here matches that.", None);
            }
            ui.add_space(metrics::S2);
        });
}

/// The rows to draw, sorted and filtered, as indices into the scan's own
/// vectors.
///
/// Indices rather than devices: the devices and the names are two parallel
/// vectors and sorting either one would break the pairing, while sorting pairs
/// would copy an identity per row per frame.
fn shown_rows(
    app: &App,
    devices: &[muster_net::discover::Found],
    names: &[Identity],
    survey: &Survey,
) -> Vec<usize> {
    let empty = Identity::default();
    let mut order: Vec<usize> = (0..devices.len()).collect();
    let sort = app.sort;
    order.sort_by(|a, b| {
        let key = |i: usize| {
            let host = &devices[i];
            let named = names.get(i);
            let vantage = survey.vantage(host.address);
            let kind = muster_net::kind::kind_of(host, named.unwrap_or(&empty), vantage);
            sort_key(
                sort.column,
                host,
                named,
                kind,
                app.ping.rtt_for(host.address),
            )
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
    // Which rows the filter leaves. The header's box and both menus act on
    // exactly these: "everything" means everything in front of the reader,
    // never forty devices a search has hidden.
    order
        .into_iter()
        .filter(|i| {
            let host = &devices[*i];
            let named = names.get(*i);
            let vantage = survey.vantage(host.address);
            let kind = muster_net::kind::kind_of(host, named.unwrap_or(&empty), vantage);
            matches(&app.search, host, named, kind)
        })
        .collect()
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

/// The mark's column: §7.12's 16 px box in an 18 px hit area, plus the air
/// that keeps it off the window's edge. Fixed, so every box in the table lines
/// up under the one in the header.
const COL_MARK: f32 = 24.0;

/// How wide the columns a reader can drag are.
///
/// **The mark and the icon are not in here, and "Made by" is not either.** The
/// first two are boxes rather than columns — a 16 px checkbox in an 18 px hit
/// area, and an icon drawn at [`metrics::ICON`] — so a width for them would be
/// a width for nothing to fill. The last is the elastic one that takes whatever
/// is left, which is what stops a resize leaving a strip of empty table down the
/// right-hand side.
///
/// Widths are in points before the interface scale, the same as every other
/// figure in this file, so a table dragged into shape at one scale is the same
/// table at another.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Widths {
    pub address: f32,
    pub name: f32,
    pub mac: f32,
    pub time: f32,
    pub ping: f32,
    pub serves: f32,
    pub ports: f32,
}

impl Default for Widths {
    fn default() -> Self {
        Self {
            address: COL_ADDRESS,
            name: COL_NAME,
            mac: COL_MAC,
            time: COL_TIME,
            ping: COL_PING,
            serves: COL_SERVES,
            ports: COL_PORTS,
        }
    }
}

impl Widths {
    /// The narrowest a column may be dragged.
    ///
    /// Not zero, and not "as narrow as you like": a column dragged shut is a
    /// column whose heading cannot be read, and the reader has no way back to
    /// it except by finding an edge that is no longer visibly there. Wide
    /// enough for the shortest heading in the table and its sort caret.
    pub const NARROWEST: f32 = 46.0;

    /// The widest. Generous, and there only so that a dragged edge cannot be
    /// thrown far enough to push every other column off the window.
    pub const WIDEST: f32 = 520.0;

    /// What "Made by" is never squeezed below. It is the elastic column, so
    /// every other column's ceiling is whatever leaves this much.
    pub const VENDOR_LEAST: f32 = 90.0;

    /// The width this column is drawn at, for the ones that have one.
    fn of(self, column: Column) -> f32 {
        match column {
            Column::Address => self.address,
            Column::Name => self.name,
            Column::Mac => self.mac,
            Column::Time => self.time,
            Column::Ping => self.ping,
            Column::Serves => self.serves,
            Column::Ports => self.ports,
            // Not draggable: see the note on the type.
            Column::Kind => COL_KIND,
            Column::Vendor => 0.0,
        }
    }

    /// The field a drag on this column's edge moves, where there is one.
    fn slot(&mut self, column: Column) -> Option<&mut f32> {
        Some(match column {
            Column::Address => &mut self.address,
            Column::Name => &mut self.name,
            Column::Mac => &mut self.mac,
            Column::Time => &mut self.time,
            Column::Ping => &mut self.ping,
            Column::Serves => &mut self.serves,
            Column::Ports => &mut self.ports,
            Column::Kind | Column::Vendor => return None,
        })
    }

    /// Every draggable column added up.
    fn total(self) -> f32 {
        self.address + self.name + self.mac + self.time + self.ping + self.serves + self.ports
    }

    /// Reads the settings file's form: seven figures, comma separated.
    ///
    /// **Anything wrong gives the defaults rather than a refusal**, which is
    /// this file's rule everywhere. A table is a thing somebody can put back by
    /// dragging it; a settings file that will not load is not.
    pub fn parse(text: &str) -> Self {
        let figures: Vec<f32> = text
            .split(',')
            .filter_map(|f| f.trim().parse::<f32>().ok())
            .collect();
        let [address, name, mac, time, ping, serves, ports] = figures[..] else {
            return Self::default();
        };
        Self {
            address,
            name,
            mac,
            time,
            ping,
            serves,
            ports,
        }
        .sane()
    }

    /// The same seven figures, for writing back.
    pub fn render(self) -> String {
        [
            self.address,
            self.name,
            self.mac,
            self.time,
            self.ping,
            self.serves,
            self.ports,
        ]
        .map(|w| format!("{}", w.round()))
        .join(",")
    }

    /// Every width inside its bounds.
    ///
    /// Applied on the way in as well as on the way out, so a hand-edited file
    /// or one written by a later version cannot produce a table with a column
    /// nobody can find.
    pub fn sane(mut self) -> Self {
        for column in Column::ALL {
            if let Some(width) = self.slot(column)
                && !width.is_finite()
            {
                *width = Widths::default().of(column);
            }
        }
        for column in Column::ALL {
            if let Some(width) = self.slot(column) {
                *width = width.clamp(Self::NARROWEST, Self::WIDEST);
            }
        }
        self
    }
}

/// One line of text in a cell, cut with an ellipsis where it will not fit.
///
/// **A column the reader can drag has no promise that its contents fit**, and
/// the two ways of breaking that promise are not equally honest. Text painted
/// unclipped runs on under the next column's figures and makes both unreadable.
/// Text merely clipped stops mid-letter, which reads as a name that happens to
/// end oddly rather than as a name that has been cut. The ellipsis is the same
/// rule the ports and the badges follow with their `+n`: what does not fit is
/// *said* not to fit, never quietly dropped.
///
/// The whole value is still in the row's tooltip, which is where somebody goes
/// when the cut one is not enough.
fn cell_text(
    painter: &egui::Painter,
    at: egui::Pos2,
    align: egui::Align2,
    text: &str,
    font: FontId,
    ink: Color32,
    room: f32,
) {
    if text.is_empty() || room <= 0.0 {
        return;
    }
    let mut job =
        egui::text::LayoutJob::single_section(text.to_owned(), egui::TextFormat::simple(font, ink));
    job.wrap = egui::text::TextWrapping {
        max_width: room,
        max_rows: 1,
        // Break inside a word rather than dropping the word: an address and a
        // hardware address have no spaces in them at all, so a break only at
        // word boundaries would leave those two columns empty rather than cut.
        break_anywhere: true,
        overflow_character: Some('…'),
    };
    let galley = painter.layout_job(job);
    let anchored = align.anchor_size(at, galley.size());
    painter.galley(anchored.min, galley, ink);
}

/// How wide the band is that a reader grabs to resize a column.
///
/// Straddles the boundary, so half of it is the last pixels of one column and
/// half the first of the next. Wider than the hairline it sits on, because a
/// one-pixel target is a target nobody hits: §7 asks for a hit area rather than
/// an ink area everywhere else, and an edge is no different.
const GRIP: f32 = 8.0;

const COL_ADDRESS: f32 = 116.0;
const COL_NAME: f32 = 174.0;
const COL_MAC: f32 = 124.0;
/// The sweep's round trip: what the scan measured when it found the device.
const COL_TIME: f32 = 58.0;
/// The last re-check's round trip, which is a different fact from the sweep's
/// and is why it is a column of its own rather than a number that overwrites
/// one taken ten minutes ago.
const COL_PING: f32 = 62.0;
/// The open ports known about this device: what the sweep's knock found, and
/// whatever a port scan of it has added since. Wide enough for four, and what
/// does not fit is counted. See [`ports_cell`].
const COL_PORTS: f32 = 120.0;
/// The badges: what a device serves the network.
///
/// Wide enough for four of the five, which is every combination a real device
/// has turned up with: a router is DHCP and DNS, a NAS is SMB, NFS and SSH.
/// What does not fit is counted rather than dropped. See [`badges`].
const COL_SERVES: f32 = 132.0;

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
    /// The last re-check. Blank until one has been asked for, which is what
    /// makes it different from [`Column::Time`] rather than a second copy of
    /// it.
    Ping,
    Serves,
    /// What answered a connection: the sweep's own knock, and a port scan
    /// where one has been run.
    Ports,
    Vendor,
}

impl Column {
    /// Every column, in the order the header and the row both walk them.
    ///
    /// **One list, used by both**, because the two must agree: a header that
    /// walks its columns in one order and a row that walks them in another
    /// draws a table whose headings sit above the wrong figures, and nothing
    /// about it looks wrong until you read it.
    pub const ALL: [Column; 9] = [
        Column::Kind,
        Column::Address,
        Column::Name,
        Column::Mac,
        Column::Time,
        Column::Ping,
        Column::Serves,
        Column::Ports,
        Column::Vendor,
    ];

    /// The heading over it. Empty for the icon, which is a picture with no room
    /// for a word and whose meaning is in each row's tooltip.
    pub const fn heading(self) -> &'static str {
        match self {
            Self::Kind => "",
            Self::Address => "Address",
            Self::Name => "Name",
            Self::Mac => "Hardware",
            Self::Time => "Time",
            Self::Ping => "Ping",
            Self::Serves => "Serves",
            Self::Ports => "Ports",
            Self::Vendor => "Made by",
        }
    }
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
    ping: Option<std::time::Duration>,
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
        // The same shape as the sweep's time, over the other reading. A
        // device that has never been pinged has no time here rather than a
        // time of zero, so the whole unpinged half of the table stays at the
        // bottom whichever way the column points.
        Column::Ping => (
            ping.is_none(),
            String::new(),
            ping.map_or(0, |t| t.as_micros()),
        ),
        // Most open ports first when descending, and the port numbers break
        // the ties. A device nothing was found open on sorts as blank, which
        // includes every device no port scan has reached: "none found" and
        // "not looked for" are the same cell here, and the tooltip is where
        // the difference is said.
        Column::Ports => {
            let open = open_ports(host);
            (
                open.is_empty(),
                open.iter()
                    .map(|port| format!("{port:05}"))
                    .collect::<Vec<_>>()
                    .join(" "),
                open.len() as u128,
            )
        }
        Column::Vendor => text(match host.mac.map(muster_net::vendor::lookup) {
            Some(muster_net::vendor::Origin::Randomised) => "randomised address".to_string(),
            Some(other) => other.label().to_string(),
            None => String::new(),
        }),
    }
}

/// The ports known open on one device, ascending and without duplicates.
///
/// Read out of the device's own evidence rather than out of the port scanner,
/// and that is what makes the column outlive a scan of one device: the sweep's
/// knock records what it found, `scan::State::record_open_ports` folds a port
/// scan's result back in, and both arrive here as the same fact about the same
/// device. A refused port is deliberately not among them — it proves the host
/// is there and it proves the port is shut.
fn open_ports(host: &muster_net::discover::Found) -> Vec<u16> {
    let mut open: Vec<u16> = host
        .evidence
        .iter()
        .filter_map(|e| match e {
            muster_net::discover::Evidence::TcpOpen(port) => Some(*port),
            _ => None,
        })
        .collect();
    open.sort_unstable();
    open.dedup();
    open
}

/// An address as one number, so both families order sensibly and v4 sorts
/// before v6.
fn address_key(address: std::net::IpAddr) -> u128 {
    match address {
        std::net::IpAddr::V4(v4) => u128::from(u32::from(v4)),
        std::net::IpAddr::V6(v6) => u128::from(v6) | 1 << 127,
    }
}

/// The table's headings, which are also its sort controls, and the box that
/// marks every row at once.
///
/// Every heading is a click target, including the icon column's, whose label is
/// deliberately empty: "Kind" over a column of pictures labels the obvious and
/// adds a word to the densest screen in the application. It still sorts, and
/// the caret is what says so.
///
/// **The box at the left is not a sort control**, and it is the one thing in
/// this row that is not. It sits in the column the row boxes sit in, which is
/// §7.12's rule and the reason it reads as "one of these" rather than as a
/// heading with a decoration.
///
/// **Every boundary between two columns is a handle.** Dragging one moves that
/// column's right edge and nothing else: the columns to its right slide along
/// and "Made by" takes up or gives back the difference, so the table is never
/// left with a strip of nothing down its side. A boundary cannot be dragged
/// past the point where "Made by" would stop being worth having, and
/// double-clicking one puts that column back to the width it shipped with.
///
/// The grip band is taken out of the heading's own click target rather than
/// laid over it, so the edge resizes and the middle sorts, and neither has to
/// win a fight with the other.
///
/// Returns what the box was asked to do, where it was pressed: [`Some(true)`]
/// to mark everything shown and [`Some(false)`] to clear it. The caller owns
/// the marks and knows which rows the filter is showing; this only draws the
/// three states and reports the press.
fn table_header(
    ui: &mut egui::Ui,
    p: Palette,
    sort: &mut Sort,
    marks: Marks,
    widths: &mut Widths,
) -> Option<bool> {
    // §7.16: a table header is a 26 px row in `text_dim`. It was 20 px in
    // `placeholder`, which is the eyebrow's colour and a different rank.
    let (rect, _) =
        ui.allocate_exact_size(vec2(ui.available_width(), metrics::ROW), Sense::hover());
    let mut x = rect.left() + metrics::PAD_PANEL;

    // Mark everything, or nothing. The dash is the state that says "some", and
    // pressing it from there takes the rest rather than clearing what is
    // already marked: the reading of a half-filled box is "not finished".
    let box_rect = Rect::from_center_size(
        pos2(x + CHECK / 2.0, rect.center().y),
        Vec2::splat(CHECK_HIT),
    );
    let response = ui.interact(box_rect, ui.id().with("mark-all"), Sense::click());
    checkbox(ui, p, box_rect, marks, response.hovered());
    let pressed = response.clicked().then_some(marks != Marks::All);
    response
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .on_hover_text(match marks {
            Marks::All => "Clear every mark",
            _ => "Mark every device shown",
        });
    x += COL_MARK;

    let last = rect.right() - metrics::PAD_PANEL;
    // What a single column may grow to before "Made by" stops being worth
    // having. Measured once, against the widths as they are now, so a drag is
    // bounded by the window rather than by a figure guessed in advance.
    let room = last - x - COL_KIND - Widths::VENDOR_LEAST;
    for column in Column::ALL {
        let label = column.heading();
        let span = match column {
            Column::Vendor => last - x,
            other => widths.of(other),
        };
        // The grip band belongs to the edge, so it is taken out of the
        // heading's click target rather than laid over it. Only where there is
        // an edge to drag: the icon's width is fixed and the last column has no
        // right-hand edge of its own.
        let draggable = widths.slot(column).is_some();
        let grip = if draggable { GRIP / 2.0 } else { 0.0 };
        let cell = Rect::from_min_max(
            pos2(x, rect.top()),
            pos2((x + span - grip).max(x), rect.bottom()),
        );
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
            FontId::proportional(HEADING_SIZE),
            ink,
        );
        if active {
            // The caret sits after the label rather than at the column's right
            // edge, so it stays attached to the word it qualifies in a column
            // whose content is right-aligned.
            let after = ui
                .painter()
                .layout_no_wrap(label.to_string(), FontId::proportional(HEADING_SIZE), ink)
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

        if draggable {
            let edge = x + span;
            let band = Rect::from_min_max(
                pos2(edge - GRIP / 2.0, rect.top()),
                pos2(edge + GRIP / 2.0, rect.bottom()),
            );
            let handle = ui.interact(
                band,
                ui.id().with(("grip", column as usize)),
                Sense::click_and_drag(),
            );
            if handle.hovered() || handle.dragged() {
                ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeHorizontal);
            }
            // The edge shows itself while it is being used, and only then: a
            // table with a line down every boundary is a spreadsheet, and §7.16
            // does not want one.
            if handle.hovered() || handle.dragged() {
                ui.painter().rect_filled(
                    Rect::from_min_max(
                        pos2(edge - metrics::HAIRLINE, rect.top() + metrics::S1),
                        pos2(edge, rect.bottom() - metrics::S1),
                    ),
                    0.0,
                    p.accent,
                );
            }
            // Everything below moves one field, so the borrow is taken once and
            // the ceiling worked out before it.
            let others = widths.total() - widths.of(column);
            let ceiling = (room - others).clamp(Widths::NARROWEST, Widths::WIDEST);
            if let Some(width) = widths.slot(column) {
                if handle.double_clicked() {
                    // Back to what it shipped with, which is the way out of a
                    // column dragged somewhere unhelpful.
                    *width = Widths::default().of(column);
                } else if handle.dragged() {
                    *width += handle.drag_delta().x;
                }
                *width = width.clamp(Widths::NARROWEST, ceiling);
            }
            if handle.hovered() && !handle.dragged() {
                handle.on_hover_text("Drag to resize. Double click to put it back.");
            }
        }
        x += span;
    }
    // `line`, not `line_soft`: this is the edge of a strip, and `line_soft`
    // belongs between rows inside a list.
    hairline_strip(ui, p, rect.bottom());
    pressed
}

/// The heading's size: §4's `CONTROL`, one rank above the figures under it.
///
/// It was `TINY`, the same size as the addresses in the column, which left the
/// heading reading as another row of the table rather than as its label. One
/// rank is the whole change: §4 has four of them and a heading that reached for
/// `BODY` would outweigh the data it names.
const HEADING_SIZE: f32 = text::CONTROL;

/// How much of a table is marked. §7.12's three states, named rather than left
/// as a pair of booleans the header would have to reason about twice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Marks {
    None,
    Some,
    All,
}

impl Marks {
    /// The state of a box over `shown` rows of which `marked` are marked.
    ///
    /// An empty table is [`Marks::None`] rather than "all of nothing", which is
    /// the reading that would draw a ticked box over no rows.
    fn of(marked: usize, shown: usize) -> Self {
        match marked {
            0 => Self::None,
            n if n >= shown && shown > 0 => Self::All,
            _ => Self::Some,
        }
    }
}

/// §7.12's box: 16 px, radius 3, a `line` edge on `field`; ticked it is an
/// accent fill with an `accent_ink` tick, and half-filled it is the same fill
/// with a dash.
///
/// Drawn rather than lettered, for the reason every other mark in this
/// application is: a glyph would be the font's idea of a tick and would change
/// with the font.
fn checkbox(ui: &egui::Ui, p: Palette, hit: Rect, state: Marks, hovered: bool) {
    let rect = Rect::from_center_size(hit.center(), Vec2::splat(CHECK));
    match state {
        Marks::None => {
            ui.painter()
                .rect_filled(rect, metrics::RADIUS_TIGHT, p.field);
            ui.painter().rect_stroke(
                rect,
                metrics::RADIUS_TIGHT,
                Stroke::new(
                    metrics::HAIRLINE,
                    if hovered { p.line_dashed } else { p.line },
                ),
                egui::StrokeKind::Inside,
            );
        }
        Marks::Some | Marks::All => {
            ui.painter()
                .rect_filled(rect, metrics::RADIUS_TIGHT, p.accent);
            let ink = p.accent_ink;
            if state == Marks::All {
                // A tick, in two strokes: down to the low corner, then up.
                let a = pos2(rect.left() + rect.width() * 0.24, rect.center().y);
                let b = pos2(
                    rect.center().x - rect.width() * 0.04,
                    rect.bottom() - rect.height() * 0.28,
                );
                let c = pos2(
                    rect.right() - rect.width() * 0.20,
                    rect.top() + rect.height() * 0.30,
                );
                ui.painter().line_segment([a, b], Stroke::new(1.6_f32, ink));
                ui.painter().line_segment([b, c], Stroke::new(1.6_f32, ink));
            } else {
                let y = rect.center().y;
                ui.painter().line_segment(
                    [
                        pos2(rect.left() + rect.width() * 0.24, y),
                        pos2(rect.right() - rect.width() * 0.24, y),
                    ],
                    Stroke::new(2.0_f32, ink),
                );
            }
        }
    }
}

/// §7.12's box, and the 18 px hit area a box inside a row gets.
const CHECK: f32 = 16.0;
const CHECK_HIT: f32 = 18.0;

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
    let mut x = rect.left();
    let mut last = 0.0;
    for (i, role) in roles.iter().enumerate() {
        let width = pill_width(ui, role.label());
        if x + width > rect.right() {
            // **What did not fit is counted, never dropped.** A column that
            // quietly loses a badge shows a device serving less than it does,
            // which is the one thing a badge must not be able to do. The count
            // takes the place of the badge before it where it has to, because
            // "+2" says more than a third label that is not the last one, and
            // the row's tooltip names every role in full either way.
            let mut left = roles.len() - i;
            let mut at = x;
            if at + pill_width(ui, &format!("+{left}")) > rect.right() && last > 0.0 {
                at -= last;
                left += 1;
            }
            let more = format!("+{left}");
            if at + pill_width(ui, &more) <= rect.right() {
                pill(ui, p, rect, at, &more);
            }
            return;
        }
        pill(ui, p, rect, x, role.label());
        last = width + metrics::S1;
        x += last;
    }
}

/// The face of one badge: a neutral fill, strong text, tight radius.
fn pill(ui: &egui::Ui, p: Palette, row: Rect, x: f32, label: &str) {
    let width = pill_width(ui, label);
    let rect = Rect::from_center_size(pos2(x + width / 2.0, row.center().y), vec2(width, BADGE_H));
    ui.painter()
        .rect_filled(rect, metrics::RADIUS_TIGHT, p.control);
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        label,
        FontId::proportional(text::TINY),
        p.text_strong,
    );
}

/// How much room a badge for `label` wants, measured rather than guessed: the
/// labels are three and four letters and the difference decides how many fit.
fn pill_width(ui: &egui::Ui, label: &str) -> f32 {
    ui.painter()
        .layout_no_wrap(
            label.to_string(),
            FontId::proportional(text::TINY),
            Color32::PLACEHOLDER,
        )
        .size()
        .x
        + metrics::S1 * 2.0
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
    host: &muster_net::discover::Found,
    row: RowInput<'_>,
) -> Row {
    let RowInput {
        mode,
        named,
        vantage,
        selected,
        marked,
        ping,
        widths,
    } = row;
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

    // The mark, in the column the header's box sits in. Interacted *after* the
    // row, so it is the box that takes a click landing on it rather than the
    // row underneath opening the panel: the later widget is the one on top.
    let box_rect = Rect::from_center_size(pos2(x + CHECK / 2.0, y), Vec2::splat(CHECK_HIT));
    let mark = ui.interact(box_rect, response.id.with("mark"), Sense::click());
    checkbox(
        ui,
        p,
        box_rect,
        if marked { Marks::All } else { Marks::None },
        mark.hovered(),
    );
    if mark.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    x += COL_MARK;

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

    // Every text cell from here down is cut to its column with an ellipsis
    // rather than painted and hoped for: see [`cell_text`]. The two that are
    // not text — the badges and the ports — take a rectangle and count what
    // they cannot fit, which is the same rule by another means.
    let cell = |x: f32, width: f32| {
        Rect::from_min_max(pos2(x, rect.top()), pos2(x + width, rect.bottom()))
    };

    cell_text(
        ui.painter(),
        pos2(x, y),
        egui::Align2::LEFT_CENTER,
        &host.address.to_string(),
        figure.clone(),
        p.text_strong,
        widths.address - metrics::S2,
    );
    x += widths.address;

    let name = named
        .and_then(Identity::best)
        .map(|n| n.value.clone())
        .unwrap_or_default();
    cell_text(
        ui.painter(),
        pos2(x, y),
        egui::Align2::LEFT_CENTER,
        &name,
        FontId::proportional(text::CONTROL),
        p.text,
        widths.name - metrics::S2,
    );
    x += widths.name;

    let mac = host.mac.map(|m| m.to_string()).unwrap_or_default();
    cell_text(
        ui.painter(),
        pos2(x, y),
        egui::Align2::LEFT_CENTER,
        &mac,
        figure.clone(),
        p.text_muted,
        widths.mac - metrics::S2,
    );
    x += widths.mac;

    let rtt = match host.rtt {
        Some(t) if t.as_millis() > 0 => format!("{} ms", t.as_millis()),
        Some(_) => "<1 ms".into(),
        None => String::new(),
    };
    cell_text(
        ui.painter(),
        pos2(x + widths.time - metrics::S2, y),
        egui::Align2::RIGHT_CENTER,
        &rtt,
        figure,
        p.text_dim,
        widths.time - metrics::S2,
    );
    x += widths.time;

    // The last re-check, which is blank until one has been asked for. Amber
    // where the probe could not be sent, because that is a fact about this
    // machine and not a reading of the device: `CLAUDE.md`'s rule that a
    // question never asked is never reported as silence reaches into the table
    // and not only into the panel.
    let (ping_text, ping_ink) = match ping {
        PingCell::Waiting => ("asking…".to_string(), p.text_dim),
        PingCell::Answer(r) if unasked(r) => ("not asked".to_string(), p.caution),
        PingCell::Answer(r) => match r.found.as_ref().and_then(|f| f.rtt) {
            Some(t) if t.as_millis() > 0 => (format!("{} ms", t.as_millis()), p.text),
            Some(_) => ("<1 ms".to_string(), p.text),
            None => ("no reply".to_string(), p.text_dim),
        },
        PingCell::Never => (String::new(), p.text_dim),
    };
    cell_text(
        ui.painter(),
        pos2(x + widths.ping - metrics::S2, y),
        egui::Align2::RIGHT_CENTER,
        &ping_text,
        FontId::monospace(text::TINY),
        ping_ink,
        widths.ping - metrics::S2,
    );
    x += widths.ping;

    // What this device serves the network, as against what it is. The icon
    // says the one and these say the other; a router that is also the name
    // server shows both, which no single label could.
    let roles = named.map(Identity::roles).unwrap_or_default();
    let open = open_ports(host);
    badges(ui, p, cell(x, widths.serves), &roles);
    x += widths.serves;

    ports_cell(ui, p, cell(x, widths.ports), &open);
    x += widths.ports;

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
    cell_text(
        ui.painter(),
        pos2(x, y),
        egui::Align2::LEFT_CENTER,
        &vendor,
        FontId::proportional(text::SMALL),
        colour,
        rect.right() - metrics::PAD_PANEL - x,
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
        // What the ports cell cannot say in its width, and the one thing it
        // must not be read as saying: a blank cell is "nothing has looked",
        // not "nothing is open".
        if open.is_empty() {
            tip.push_str("\nNo open port found yet. Scan its ports to look.");
        } else {
            tip.push_str(&format!(
                "\nOpen: {}",
                open.iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if let PingCell::Answer(r) = ping {
            tip.push_str(&format!("\nLast ping: {}", ping_line(r)));
        }
        response.clone().on_hover_text(tip);
    }
    Row {
        clicked: response.clicked() && !mark.clicked(),
        marked: mark.clicked(),
    }
}

/// What a row needs that it cannot read off the device itself.
///
/// A struct rather than six more parameters: the row already takes the device
/// and the palette, and a drawing function with nine arguments is one whose
/// call site nobody can read.
struct RowInput<'a> {
    mode: Mode,
    named: Option<&'a Identity>,
    vantage: muster_net::kind::Vantage,
    /// Its panel is open.
    selected: bool,
    /// It is marked for the toolbar's menus.
    marked: bool,
    ping: PingCell<'a>,
    /// The columns as the reader has dragged them. The header owns these and
    /// the row is told, so the two cannot lay the table out differently.
    widths: Widths,
}

/// What a device row was asked to do.
///
/// Two presses rather than one response, because the mark and the row mean
/// different things and a caller that had to tell them apart by position would
/// be doing the hit test twice.
struct Row {
    /// The row itself: open or close this device's panel.
    clicked: bool,
    /// The box at its left: mark or unmark this device.
    marked: bool,
}

/// What the Ping column has to show about one device.
///
/// Three states and not two, which is the whole reason this is an enum: a
/// device that has never been asked, a device being asked now, and an answer —
/// and an answer is itself allowed to say "the question could not be sent".
#[derive(Clone, Copy)]
enum PingCell<'a> {
    Never,
    Waiting,
    Answer(&'a muster_net::discover::Recheck),
}

/// The open ports, as many as the column can hold and a count of the rest.
///
/// The same rule the badges follow: **what does not fit is counted, never
/// dropped.** A cell that quietly stopped at three would show a device with
/// fewer open ports than it has, and the row's tooltip lists them all.
fn ports_cell(ui: &egui::Ui, p: Palette, rect: Rect, open: &[u16]) {
    if open.is_empty() {
        return;
    }
    let font = FontId::monospace(text::TINY);
    let mut x = rect.left();
    let width = |ui: &egui::Ui, text: &str| {
        ui.painter()
            .layout_no_wrap(text.to_string(), font.clone(), Color32::PLACEHOLDER)
            .size()
            .x
    };
    for (i, port) in open.iter().enumerate() {
        let label = port.to_string();
        let w = width(ui, &label);
        let left = open.len() - i;
        if x + w > rect.right() {
            let more = format!("+{left}");
            if x + width(ui, &more) <= rect.right() {
                ui.painter().text(
                    pos2(x, rect.center().y),
                    egui::Align2::LEFT_CENTER,
                    &more,
                    font,
                    p.text_dim,
                );
            }
            return;
        }
        ui.painter().text(
            pos2(x, rect.center().y),
            egui::Align2::LEFT_CENTER,
            &label,
            font.clone(),
            p.text_muted,
        );
        x += w + metrics::S2;
    }
}

/// What the machine knows without sending anything.
///
/// **One card per network, and every card answers the same four questions.**
/// It was one long column of eyebrows — every address, then every gateway, then
/// every resolver, then every lease — which is the shape the survey happens to
/// be in rather than the shape the question is in. On a machine with a VPN up,
/// or a laptop on wifi and Ethernet at once, that column could not say which
/// gateway belonged to which link, and that is exactly what somebody opening
/// this page wants to know.
///
/// So the interface an address is configured on is the heading, and the
/// gateway, the resolvers and the DHCP server are read *for that interface*
/// where the platform records them per interface, which Windows does. Where it
/// does not — Unix keeps one resolver list for the machine — the card says the
/// list is the machine's rather than pretending it is the link's.
fn network_view(ui: &mut egui::Ui, p: Palette, app: &mut App) {
    let s = &app.survey.clone();
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.add_space(metrics::S3);

            let live: Vec<&muster_net::sysinfo::Interface> =
                s.interfaces.iter().filter(|i| i.is_scannable()).collect();
            if live.is_empty() {
                // A machine with no usable interface is a real state, and it is
                // the one that makes every other card on this page empty. Say
                // it once rather than drawing four blank cards.
                card(ui, p, "No network", None, |ui| {
                    card_note(
                        ui,
                        p,
                        "",
                        "No interface is up with an address on it, so there is nothing to scan.",
                    );
                });
            }
            for iface in live {
                network_card(ui, p, s, iface);
            }

            card(
                ui,
                p,
                "Who hands out addresses",
                Some("Asked, not read"),
                |ui| {
                    card_note(
                        ui,
                        p,
                        "",
                        "The servers above come from this machine's own lease. This asks the \
                     link itself, and keeps every offer: two servers answering is a fault \
                     worth finding.",
                    );
                    ui.add_space(metrics::S2);
                    dhcp_check(ui, p, app);
                },
            );

            if !s.gaps.is_empty() {
                // The rule that matters most in this whole view: a reading that
                // failed is said to have failed, never drawn as an absence.
                card(ui, p, "Could not read", None, |ui| {
                    for gap in &s.gaps {
                        card_note(ui, p, &gap.reading.to_string(), &gap.because);
                    }
                });
            }
            ui.add_space(metrics::S4);
        });
}

/// One interface, and the four things a network is.
fn network_card(
    ui: &mut egui::Ui,
    p: Palette,
    survey: &Survey,
    iface: &muster_net::sysinfo::Interface,
) {
    // The subtitle is what the card is *of*, in the words the rest of the
    // world uses: the link kind, and the kernel's own name for it where that
    // is not already the title.
    let mut subtitle = vec![link_kind(iface.kind).to_string()];
    if iface.name != iface.friendly && iface.name.len() <= NAME_IS_A_NAME {
        subtitle.push(iface.name.clone());
    }
    if iface.flags.point_to_point {
        subtitle.push("point to point".into());
    }

    card(ui, p, &iface.friendly, Some(&subtitle.join(" · ")), |ui| {
        card_facts(
            ui,
            p,
            "Address",
            &iface
                .addresses
                .iter()
                .map(|a| format!("{} in {}", a.address, a.prefix))
                .collect::<Vec<_>>(),
        );

        // The gateway *for this link*, which is what the interface index on
        // a default route is for. A card that showed the machine's gateway
        // list would say the same thing on every card and answer nothing.
        let gateways: Vec<String> = survey
            .gateways
            .iter()
            .filter(|g| g.interface_index == iface.index)
            .map(|g| g.address.to_string())
            .collect();
        if !survey.has(muster_net::survey::Reading::Routes) {
            card_note(ui, p, "Gateway", "could not be read");
        } else if gateways.is_empty() {
            card_note(ui, p, "Gateway", "none, nothing routes out of here");
        } else {
            card_facts(ui, p, "Gateway", &gateways);
        }

        // Windows reports resolvers per adapter, which is the truthful
        // answer on a machine with a VPN up. Unix has one list for the
        // machine, and the card says so rather than claiming the link's.
        if iface.dns.is_empty() {
            if survey.resolvers.is_empty() {
                card_note(ui, p, "DNS", "none configured");
            } else {
                card_facts(
                    ui,
                    p,
                    "DNS",
                    &survey
                        .resolvers
                        .iter()
                        .map(|r| format!("{r}  (this machine's list)"))
                        .collect::<Vec<_>>(),
                );
            }
        } else {
            card_facts(
                ui,
                p,
                "DNS",
                &iface.dns.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
            );
        }

        match iface.dhcp_server {
            Some(server) => card_facts(ui, p, "DHCP", &[server.to_string()]),
            None => card_note(ui, p, "DHCP", "no lease recorded on this interface"),
        }

        if let Some(mac) = iface.mac {
            card_facts(ui, p, "Hardware", &[mac.to_string()]);
        }
    });
}

/// How long an interface name can be and still be a name.
///
/// Windows calls an adapter by its GUID in `Interface::name`, which is 38
/// characters of nothing anybody wants under a heading; `eth0` and `wlp3s0`
/// are worth having. The length is the only thing that tells them apart
/// without matching a shape, and it is a caption either way.
const NAME_IS_A_NAME: usize = 16;

/// What kind of link, in a word.
const fn link_kind(kind: muster_net::sysinfo::LinkKind) -> &'static str {
    use muster_net::sysinfo::LinkKind;
    match kind {
        LinkKind::Ethernet => "Ethernet",
        LinkKind::Wireless => "Wireless",
        LinkKind::Loopback => "Loopback",
        LinkKind::Tunnel => "Tunnel",
        LinkKind::Unknown => "Link",
    }
}

/// §7.14's card: a `chrome` surface with a `line` edge, a title, and rows.
///
/// The one container this application draws. A page that is a list of groups
/// wants the groups to *look* like groups, and an eyebrow over a run of rows
/// only says where a group starts — never where it ends, which is what leaves
/// a reader attaching the last row to the wrong heading.
fn card<R>(
    ui: &mut egui::Ui,
    p: Palette,
    title: &str,
    subtitle: Option<&str>,
    content: impl FnOnce(&mut egui::Ui) -> R,
) {
    ui.horizontal(|ui| {
        ui.add_space(metrics::PAD_PANEL);
        let width = (ui.available_width() - metrics::PAD_PANEL).min(CARD_WIDTH);
        // **Top down, said out loud.** The card is placed inside a horizontal
        // layout to indent it, and a child inherits its parent's direction: the
        // first draft laid every row of every card out along one line, which is
        // a thing that looks like a bug in the card and is a bug in the
        // arrangement around it.
        ui.allocate_ui_with_layout(vec2(width, 0.0), Layout::top_down(Align::Min), |ui| {
            egui::Frame::NONE
                .fill(p.chrome)
                .stroke(Stroke::new(metrics::HAIRLINE, p.line))
                .corner_radius(metrics::RADIUS_CARD)
                .inner_margin(egui::Margin::same(metrics::PAD_PANEL as i8))
                .show(ui, |ui| {
                    ui.set_width(width - metrics::PAD_PANEL * 2.0);
                    ui.label(
                        RichText::new(title)
                            .font(theme::strong(text::HEADING))
                            .color(p.text_strong),
                    );
                    if let Some(subtitle) = subtitle.filter(|s| !s.is_empty()) {
                        ui.label(RichText::new(subtitle).size(text::TINY).color(p.text_dim));
                    }
                    ui.add_space(metrics::S2);
                    content(ui);
                });
        });
    });
    ui.add_space(metrics::S3);
}

/// How wide a card grows. Wide enough for an IPv6 address and its prefix on one
/// line, and no wider: a card the width of a maximised window is a stripe.
const CARD_WIDTH: f32 = 520.0;

/// The key column inside a card, so every value in it starts at the same x.
const CARD_KEY: f32 = 84.0;

/// One key and its values, as **figures**: §4's monospaced, tabular face, so a
/// column of addresses lines up under itself.
///
/// The key is drawn once however many values there are, because "Address" three
/// times over three addresses is the same word asked three times.
fn card_facts(ui: &mut egui::Ui, p: Palette, key: &str, values: &[String]) {
    for (i, value) in values.iter().enumerate() {
        card_line(ui, p, if i == 0 { key } else { "" }, value, true);
    }
}

/// One key and a **sentence**, which is the other half of the same rule: "none
/// configured" set in the figure face reads as though it were a number.
fn card_note(ui: &mut egui::Ui, p: Palette, key: &str, value: &str) {
    card_line(ui, p, key, value, false);
}

fn card_line(ui: &mut egui::Ui, p: Palette, key: &str, value: &str, figure: bool) {
    // Top aligned, because a sentence long enough to wrap must not drag its own
    // key down the card with it.
    ui.horizontal_top(|ui| {
        if !key.is_empty() || figure {
            let (rect, _) =
                ui.allocate_exact_size(vec2(CARD_KEY, metrics::ROW_PLAIN), Sense::hover());
            if !key.is_empty() {
                // Aligned to the *top* of the row and not its middle, so the
                // key sits on the first line of its value rather than three
                // pixels below it. The two are set at the same size, so their
                // tops are the one thing that lines up whatever the value is.
                ui.painter().text(
                    pos2(rect.left(), rect.top()),
                    egui::Align2::LEFT_TOP,
                    key,
                    FontId::proportional(text::SMALL),
                    p.text_dim,
                );
            }
        }
        let body = RichText::new(value).size(text::SMALL).color(p.text);
        let body = if figure { body.monospace() } else { body };
        // **Wrapped.** A note is a sentence, and a sentence that does not wrap
        // pushes the card out past the window rather than taking a second
        // line. A figure is short by construction and wraps for free.
        ui.add(egui::Label::new(body).wrap());
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

            ui.add_space(metrics::S3);
            link_row(
                ui,
                p,
                icons::Icon::Github,
                "The source, the releases and the issues",
                REPOSITORY,
            );

            ui.add_space(metrics::S4);
            updates_section(ui, p, updates);
        });
    });
}

/// Where Muster lives. The one address in the application that is not a device.
const REPOSITORY: &str = "https://github.com/Spillebulle/muster";

/// An icon and a label that open something in the browser.
///
/// **The only thing in Muster that reaches the internet on purpose besides the
/// update check**, and unlike that one it is not Muster making a request: it
/// hands the address to the desktop and the desktop opens it, so nothing about
/// this network is sent anywhere and nothing happens until somebody clicks.
/// The address is shown under the label rather than hidden behind it, because a
/// link whose destination you cannot read before following it is a link asking
/// to be trusted.
fn link_row(ui: &mut egui::Ui, p: Palette, icon: icons::Icon, label: &str, url: &str) {
    let height = metrics::ROW;
    let (rect, response) = ui.allocate_exact_size(
        vec2(ui.available_width().min(LINK_WIDTH), height),
        Sense::click(),
    );
    let ink = if response.hovered() {
        p.accent
    } else {
        p.text_muted
    };
    let mark = Rect::from_center_size(
        pos2(rect.left() + metrics::ICON / 2.0, rect.center().y),
        Vec2::splat(metrics::ICON),
    );
    icons::draw(ui.painter(), mark, icon, ink);
    ui.painter().text(
        pos2(mark.right() + metrics::S2, rect.center().y),
        egui::Align2::LEFT_CENTER,
        label,
        FontId::proportional(text::BODY),
        ink,
    );
    if response.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    if response.clicked() {
        ui.ctx().open_url(egui::OpenUrl::new_tab(url));
    }
    response.on_hover_text(url);
    ui.label(
        RichText::new(url)
            .size(text::TINY)
            .monospace()
            .color(p.text_dim),
    );
}

/// How wide a link row's hit area is: the label and no more, so the whole page
/// is not a click target.
const LINK_WIDTH: f32 = 320.0;

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

/// How much wider it gets when the ping history is open.
///
/// The history is a *second column* rather than something the facts scroll
/// past: a device's identity and its round trips are two different readings and
/// putting one below the other would push the buttons off the bottom of a panel
/// that is already tall. So the window grows sideways and the history fills
/// what it grew by, which is also what makes closing it put everything back
/// exactly where it was.
const HISTORY_WIDTH: f32 = 260.0;

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
    // Open, the history is a second column and the window grows by exactly what
    // the column needs, so closing it puts everything back where it was.
    let showing = app.history_open;
    let panel = if showing {
        DETAIL_WIDTH + metrics::S3 + HISTORY_WIDTH
    } else {
        DETAIL_WIDTH
    };
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
        .default_width(panel)
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
            ui.set_width(panel);

            // Our own header: the name, and a close mark that is an icon
            // button rather than a letter. Across the whole window, so the
            // close mark stays in its corner when the history opens.
            ui.horizontal(|ui| {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if close_button(ui, p).clicked() {
                        open = false;
                    }
                    ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                        ui.label(
                            RichText::new(&title)
                                .font(theme::strong(text::HEADING))
                                .color(p.text_strong),
                        );
                    });
                });
            });
            ui.add_space(metrics::S1);
            hairline_across(ui, p, ui.min_rect().bottom());
            ui.add_space(metrics::S2);

            ui.horizontal_top(|ui| {
                ui.vertical(|ui| {
                    ui.set_width(DETAIL_WIDTH);

                    ui.horizontal(|ui| {
                        let (icon, _) =
                            ui.allocate_exact_size(Vec2::splat(metrics::ROW), Sense::hover());
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
                            muster_net::vendor::Origin::Randomised => {
                                "randomised address".to_string()
                            }
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
                            (None, true) => {
                                "would not name itself, resolves for clients".to_string()
                            }
                            (None, false) => "would not name itself".to_string(),
                        };
                        fact_row(ui, p, "Name server", &what);
                    }
                    // The greeting, which is the software in the device's own words and
                    // is worth a row of its own for the same reason the resolver's
                    // version is. SMB and NFS get no row here: both answered a question
                    // and neither volunteered anything to print, so the badge and its
                    // reason are the whole of what is known, and inventing a line for
                    // them would be padding a panel with what a badge already said.
                    if let Some(greeting) = &named.serves.ssh {
                        fact_row(ui, p, "SSH", greeting);
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

                if showing {
                    ui.add_space(metrics::S2);
                    // The line between the two columns, which is what makes them
                    // read as one panel divided rather than two panels touching.
                    let (edge, _) = ui.allocate_exact_size(
                        vec2(metrics::HAIRLINE, ui.available_height()),
                        Sense::hover(),
                    );
                    ui.painter().rect_filled(edge, 0.0, p.line);
                    ui.add_space(metrics::S2);
                    ui.vertical(|ui| {
                        ui.set_width(HISTORY_WIDTH);
                        history_column(ui, p, app, address);
                    });
                }
            });
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
    let looping_here = app.ping.loops_for(address);

    ui.horizontal(|ui| {
        let waiting = app.ping.waiting_for(address);
        if button(ui, p, "Ping", Kind::Secondary, !waiting).clicked() && !waiting {
            app.start_ping(address);
        }
        ui.add_space(metrics::S1);

        // **The loop, where the table's Actions menu already had one and the
        // panel did not.** In front of one device is exactly where somebody
        // wants to watch a round trip settle, so the control belongs here too.
        // It is one button that changes what it says, rather than two of which
        // one is always wrong: a loop that is running has nothing to offer but
        // stopping.
        if looping_here {
            if button(ui, p, "Stop", Kind::Secondary, true)
                .on_hover_text("Stops the ping that is running")
                .clicked()
            {
                app.ping.cancel();
            }
        } else if button(ui, p, "Keep pinging", Kind::Secondary, true)
            .on_hover_text(format!(
                "Once every {:.1} s until you stop it. Settings has the interval.",
                app.prefs.ping_every as f32 / 1000.0
            ))
            .clicked()
        {
            app.start_pings(vec![address], true);
        }
        ui.add_space(metrics::S1);

        // The history is a way of looking at the same readings, so its control
        // sits with the buttons that produce them rather than in a corner.
        let kept = app.ping.history_for(address).len();
        let label = if app.history_open {
            "Hide history"
        } else {
            "History"
        };
        if button(ui, p, label, Kind::Ghost, true)
            .on_hover_text(match kept {
                0 => "Nothing kept yet: ping it and the results are remembered".to_string(),
                1 => "1 result kept".to_string(),
                n => format!("{n} results kept"),
            })
            .clicked()
        {
            app.history_open = !app.history_open;
        }
    });

    ui.horizontal(|ui| {
        let waiting = app.ping.waiting_for(address);
        let answer = app.ping.answer_for(address);
        let line = if waiting {
            "asking…".to_string()
        } else {
            match answer {
                Some(r) => ping_line(r),
                None => match swept_rtt {
                    Some(rtt) => format!("{} ms when it was swept", rtt.as_millis()),
                    None => String::new(),
                },
            }
        };
        // Amber where the machine could not ask, because that is a state the
        // reader has to act on rather than a reading of the network.
        let ink = match answer {
            Some(r) if unasked(r) => p.caution,
            _ => p.text_dim,
        };
        ui.label(RichText::new(line).size(text::TINY).color(ink));
    });
}

/// The ping history, as the second column of the device window.
///
/// **Two readings of the same thing, because they answer different questions.**
/// The bars say what the last minute *looked like* — steady, climbing, gappy —
/// which is the shape somebody is watching for and which no list of figures
/// shows at a glance. The list underneath says what each individual probe
/// actually returned, which is what gets quoted into a ticket.
///
/// A probe that could not be sent is drawn in `caution` and never as a lost
/// packet: `CLAUDE.md`'s rule that a question never asked is not a silence
/// reaches into the chart as much as into the column.
fn history_column(ui: &mut egui::Ui, p: Palette, app: &mut App, address: std::net::IpAddr) {
    ui.horizontal(|ui| {
        ui.label(
            RichText::new("PING HISTORY")
                .size(text::EYEBROW)
                .color(p.placeholder),
        );
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            let kept = app.ping.history_for(address).len();
            if button(ui, p, "Clear", Kind::Ghost, kept > 0).clicked() {
                app.ping.forget(address);
            }
        });
    });
    ui.add_space(metrics::S2);

    let samples = app.ping.history_for(address);
    if samples.is_empty() {
        ui.label(
            RichText::new("Nothing yet. Ping it, or keep pinging, and every result is kept here.")
                .size(text::TINY)
                .color(p.text_dim),
        );
        return;
    }

    // The slowest answer in what is shown, which is what the bars are drawn
    // against. Scaled to the data rather than to a fixed ceiling: a link where
    // everything answers in a millisecond would otherwise draw a flat line at
    // the bottom of the chart and say nothing.
    let shown: Vec<&crate::ping::Sample> = samples.iter().rev().take(HISTORY_BARS).rev().collect();
    let worst = shown
        .iter()
        .filter_map(|s| s.rtt)
        .max()
        .unwrap_or_default()
        .as_secs_f32()
        .max(0.001);

    let (chart, _) = ui.allocate_exact_size(vec2(HISTORY_WIDTH, HISTORY_CHART), Sense::hover());
    ui.painter()
        .rect_filled(chart, metrics::RADIUS_TIGHT, p.field);
    // **Newest at the right, and the bars fill the chart.** A fixed slot width
    // left a short history huddled in the left third of an empty box, which
    // reads as a chart that has gone wrong rather than as one with little in
    // it. The floor stops three results becoming three fat slabs.
    let slots = shown.len().clamp(HISTORY_LEAST, HISTORY_BARS);
    let step = chart.width() / slots as f32;
    for (i, sample) in shown.iter().enumerate() {
        let left = chart.right() - (shown.len() - i) as f32 * step;
        let (height, ink) = match (sample.rtt, sample.asked) {
            // An answer: as tall a share of the chart as it is of the slowest.
            (Some(rtt), _) => (
                (rtt.as_secs_f32() / worst * (chart.height() - 4.0)).max(1.5),
                p.accent,
            ),
            // Asked and nothing came back. Full height in the colour that means
            // "look at this", because a gap is the thing being watched for.
            (None, true) => (chart.height() - 4.0, p.critical),
            // Never asked. Not the device's failing and not drawn as one.
            (None, false) => (chart.height() - 4.0, p.caution),
        };
        ui.painter().rect_filled(
            Rect::from_min_max(
                pos2(left + 0.5, chart.bottom() - 2.0 - height),
                pos2(left + step - 0.5, chart.bottom() - 2.0),
            ),
            0.0,
            ink,
        );
    }

    ui.add_space(metrics::S1);
    ui.label(
        RichText::new(format!(
            "{} kept, worst {} ms",
            samples.len(),
            (worst * 1000.0).round() as u64
        ))
        .size(text::TINY)
        .color(p.text_dim),
    );
    ui.add_space(metrics::S2);

    // Newest first, because the reason somebody opened this is the one that
    // just happened.
    egui::ScrollArea::vertical()
        .max_height(HISTORY_LIST)
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let first = samples.first().map(|s| s.at);
            for sample in samples.iter().rev() {
                let since = first
                    .map(|f| sample.at.saturating_duration_since(f))
                    .unwrap_or_default();
                let (what, ink) = match (sample.rtt, sample.asked) {
                    (Some(rtt), _) => (format!("{} ms", rtt.as_millis()), p.text),
                    (None, true) => ("no reply".to_string(), p.text_dim),
                    (None, false) => ("not asked".to_string(), p.caution),
                };
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!("{:>6.1}s", since.as_secs_f32()))
                            .size(text::TINY)
                            .monospace()
                            .color(p.text_dim),
                    );
                    ui.label(RichText::new(what).size(text::TINY).monospace().color(ink));
                });
            }
        });
}

/// How many results the chart shows at once.
///
/// The chart is a shape rather than a record — the list under it is the record
/// — so it holds what fits at a readable bar width and lets the rest scroll
/// past underneath.
const HISTORY_BARS: usize = 60;

/// The fewest slots the chart is divided into, however little is in it.
const HISTORY_LEAST: usize = 16;

/// How tall the chart is, and how much of the column the list may take.
const HISTORY_CHART: f32 = 64.0;
const HISTORY_LIST: f32 = 260.0;

/// What one re-check says, in a sentence.
///
/// Pulled out of the panel because the table's Ping column asks the same
/// question of the same answer, and two readings of one `Recheck` would be two
/// chances to say "nothing came back" about a probe that was never sent.
fn ping_line(r: &muster_net::discover::Recheck) -> String {
    match r.found.as_ref().and_then(|f| f.rtt) {
        Some(rtt) => format!("answered in {} ms", rtt.as_millis()),
        // No round trip, so the line is made of the two things that are true
        // independently: what did answer, and what was never asked. A probe
        // that could not run has nothing to say about the device, and a device
        // that answered ARP a second ago is not gone — reporting either one
        // alone was how "nothing came back this time" came to be printed about
        // a machine sitting there answering.
        None => {
            let how: Vec<String> = r
                .found
                .iter()
                .flat_map(|f| f.evidence.iter())
                .map(muster_net::discover::Evidence::reason)
                .collect();
            let there = (!how.is_empty()).then(|| format!("still there ({})", how.join(", ")));
            let gaps = (!r.not_done.is_empty()).then(|| r.not_done.join("; "));
            match (there, gaps) {
                (Some(there), Some(gaps)) => format!("{there}, and {gaps}"),
                (Some(there), None) => format!("{there}, but no ICMP reply"),
                (None, Some(gaps)) => format!("no time to report: {gaps}"),
                // **Not "it is gone".** Silence is a device that is off, a
                // device that drops, or a probe that was rate limited into the
                // next second. The sweep's own rule, kept here.
                (None, None) => "nothing came back this time".to_string(),
            }
        }
    }
}

/// Did this answer come from a probe that could not be sent?
///
/// The one state the interface colours amber, because it is a fact about this
/// machine rather than a reading of the network, and the reader can act on it.
fn unasked(r: &muster_net::discover::Recheck) -> bool {
    !r.not_done.is_empty() && r.found.as_ref().is_none_or(|f| f.rtt.is_none())
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

    ui.horizontal(|ui| {
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
    ui.add_space(metrics::S2);
    ui.label(
        RichText::new(probe.verdict())
            .size(text::SMALL)
            .color(colour),
    );

    for offer in probe.distinct_offers() {
        let mut detail = format!("offered {}", offer.offered);
        if let Some(router) = offer.router {
            detail.push_str(&format!(", gateway {router}"));
        }
        if let Some(lease) = offer.lease {
            detail.push_str(&format!(", {} h lease", lease.as_secs() / 3600));
        }
        card_note(ui, p, &offer.server.to_string(), &detail);
        // RFC 8910's option 114, and it gets a line of its own rather than a
        // clause on the end of the one above: it is a statement about the
        // network rather than about the address being offered, and a URL is
        // long enough to push the lease off the end of a card.
        if let Some(portal) = offer.captive_portal() {
            card_note(ui, p, "Captive portal", portal);
        }
    }
}

/// The strip above the device table: what to scan, and what to show.
///
/// §7.2's options strip. It carries the two things a scan needs from the user
/// and nothing else: the range to sweep, and a filter over what came back.
fn devices_toolbar(ui: &mut egui::Ui, p: Palette, app: &mut App, table: Table<'_>) {
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

            // And what to do with what came back. Both act on the marked
            // devices, or on everything the filter is showing when nothing is
            // marked; [`Targets`] decides that once so the two menus cannot
            // disagree about what "these" means.
            let targets = Targets::of(app, &table);
            ui.add_space(metrics::S2);
            copy_menu(ui, p, app, &table, &targets);
            ui.add_space(metrics::S1);
            actions_menu(ui, p, app, &targets);

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

/// The rows the table is showing, and everything needed to read a value out of
/// one.
///
/// Handed to the toolbar rather than rebuilt there: the filter and the sort
/// have already been applied in [`devices_view`], and a menu that worked out
/// "which devices" for itself would be a second answer to a question that has
/// one.
pub(crate) struct Table<'a> {
    devices: &'a [muster_net::discover::Found],
    names: &'a [Identity],
    survey: &'a Survey,
    /// Indices into `devices`, in the order the rows are drawn.
    shown: &'a [usize],
}

/// Which devices an action or a copy is about, and what to call them.
struct Targets {
    addresses: Vec<std::net::IpAddr>,
    /// The marks decided this, rather than the filter.
    from_marks: bool,
    /// Devices are marked, and the filter is hiding every one of them.
    ///
    /// Its own state because it is the one case where doing the obvious thing
    /// would be a trap: falling back to "everything shown" there would act on
    /// rows the reader had deliberately marked *around*.
    marked_but_hidden: bool,
}

impl Targets {
    fn of(app: &App, table: &Table<'_>) -> Self {
        let shown: Vec<std::net::IpAddr> = table
            .shown
            .iter()
            .map(|i| table.devices[*i].address)
            .collect();
        let marked: Vec<std::net::IpAddr> = shown
            .iter()
            .copied()
            .filter(|a| app.marked.contains(a))
            .collect();
        if !marked.is_empty() {
            return Self {
                addresses: marked,
                from_marks: true,
                marked_but_hidden: false,
            };
        }
        if !app.marked.is_empty() {
            return Self {
                addresses: Vec::new(),
                from_marks: true,
                marked_but_hidden: true,
            };
        }
        Self {
            addresses: shown,
            from_marks: false,
            marked_but_hidden: false,
        }
    }

    fn len(&self) -> usize {
        self.addresses.len()
    }

    fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    /// What the menu says it is about, before anything is chosen.
    fn describe(&self) -> String {
        if self.marked_but_hidden {
            return "Nothing marked is on screen".to_string();
        }
        let n = self.len();
        let noun = if n == 1 { "device" } else { "devices" };
        if self.from_marks {
            format!("{n} marked {noun}")
        } else {
            format!("{n} {noun} shown")
        }
    }
}

/// A column somebody is about to paste somewhere.
///
/// Every field on this list is one already on screen. §11's rule for the
/// device panel — every field is copyable, because every field is something
/// about to be pasted — applied to the table, where the thing wanted is
/// usually the *column* rather than the cell: the addresses for a firewall
/// rule, the hardware addresses for a set of DHCP reservations.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Field {
    Address,
    Name,
    Mac,
    Vendor,
    Kind,
    Serves,
    Ping,
    Ports,
    /// Every column above, tab separated, one device per line. What a
    /// spreadsheet and a ticket both take.
    Row,
}

impl Field {
    const ALL: [Field; 9] = [
        Field::Address,
        Field::Name,
        Field::Mac,
        Field::Vendor,
        Field::Kind,
        Field::Serves,
        Field::Ping,
        Field::Ports,
        Field::Row,
    ];

    /// The menu's word for it, which is the table heading it copies.
    const fn label(self) -> &'static str {
        match self {
            Self::Address => "Address",
            Self::Name => "Name",
            Self::Mac => "Hardware address",
            Self::Vendor => "Made by",
            Self::Kind => "What it is",
            Self::Serves => "What it serves",
            Self::Ping => "Ping",
            Self::Ports => "Open ports",
            Self::Row => "The whole row",
        }
    }

    /// What the pill calls what was copied. Singular where one was.
    fn noun(self, n: usize) -> &'static str {
        let one = n == 1;
        match self {
            Self::Address => {
                if one {
                    "address"
                } else {
                    "addresses"
                }
            }
            Self::Name => {
                if one {
                    "name"
                } else {
                    "names"
                }
            }
            Self::Mac => {
                if one {
                    "hardware address"
                } else {
                    "hardware addresses"
                }
            }
            Self::Vendor => {
                if one {
                    "vendor"
                } else {
                    "vendors"
                }
            }
            Self::Kind => {
                if one {
                    "kind"
                } else {
                    "kinds"
                }
            }
            Self::Serves => {
                if one {
                    "role list"
                } else {
                    "role lists"
                }
            }
            Self::Ping => {
                if one {
                    "ping"
                } else {
                    "pings"
                }
            }
            Self::Ports => {
                if one {
                    "port list"
                } else {
                    "port lists"
                }
            }
            Self::Row => {
                if one {
                    "row"
                } else {
                    "rows"
                }
            }
        }
    }
}

/// One field of one device, as text.
///
/// Empty where the device has nothing in that column, and the caller drops
/// those rather than pasting a run of blank lines: a count that includes
/// twelve devices with no name would be a count of nothing.
fn field_value(
    field: Field,
    host: &muster_net::discover::Found,
    named: Option<&Identity>,
    kind: muster_net::Kind,
    ping: Option<&muster_net::discover::Recheck>,
) -> String {
    match field {
        Field::Address => host.address.to_string(),
        Field::Name => named
            .and_then(Identity::best)
            .map(|n| n.value.clone())
            .unwrap_or_default(),
        Field::Mac => host.mac.map(|m| m.to_string()).unwrap_or_default(),
        Field::Vendor => match host.mac.map(muster_net::vendor::lookup) {
            // The one thing that is not a vendor stays not a vendor here too.
            Some(muster_net::vendor::Origin::Randomised) => "randomised address".to_string(),
            Some(other) => other.label().to_string(),
            None => String::new(),
        },
        Field::Kind => match kind {
            muster_net::Kind::Unknown => String::new(),
            known => known.label().to_string(),
        },
        Field::Serves => named
            .map(Identity::roles)
            .unwrap_or_default()
            .iter()
            .map(|r| r.label())
            .collect::<Vec<_>>()
            .join(" "),
        // The measurement, not the sentence about it: a column of "12 ms" is
        // what somebody is pasting, and "still there (answered ARP)" is not.
        Field::Ping => match ping.and_then(|r| r.found.as_ref()?.rtt) {
            Some(t) => format!("{} ms", t.as_millis()),
            None => String::new(),
        },
        Field::Ports => open_ports(host)
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(" "),
        Field::Row => {
            let mut line = Vec::new();
            for one in Field::ALL {
                if one == Field::Row {
                    continue;
                }
                line.push(field_value(one, host, named, kind, ping));
            }
            // Tabs, and every column kept even where it is empty, because a
            // row pasted into a spreadsheet has to keep its shape.
            line.join("\t")
        }
    }
}

/// Copy a column of the table, and say what was copied.
fn copy_menu(ui: &mut egui::Ui, p: Palette, app: &mut App, table: &Table<'_>, targets: &Targets) {
    let response = menu_button(ui, p, "Copy", !targets.is_empty());
    let mode = app.mode;
    let mut chosen = None;
    popover(&response, p, mode, MENU_WIDTH, |ui| {
        ui.label(
            RichText::new(targets.describe().to_uppercase())
                .size(text::EYEBROW)
                .color(p.placeholder),
        );
        ui.add_space(metrics::S1);
        for field in Field::ALL {
            if field == Field::Row {
                menu_separator(ui, p);
            }
            if menu_row(ui, p, field.label(), None, true) {
                chosen = Some(field);
            }
        }
    });

    let Some(field) = chosen else {
        return;
    };
    let empty = Identity::default();
    let mut lines = Vec::new();
    for address in &targets.addresses {
        let Some(i) = table
            .shown
            .iter()
            .find(|i| table.devices[**i].address == *address)
        else {
            continue;
        };
        let host = &table.devices[*i];
        let named = table.names.get(*i);
        let kind = muster_net::kind::kind_of(
            host,
            named.unwrap_or(&empty),
            table.survey.vantage(host.address),
        );
        let value = field_value(field, host, named, kind, app.ping.answer_for(host.address));
        // A blank line is not a value. The count has to be what was actually
        // put on the clipboard or the pill is claiming more than it did.
        if !value.trim().is_empty() {
            lines.push(value);
        }
    }
    let count = lines.len();
    ui.ctx().copy_text(lines.join("\n"));
    app.copied = Some((
        format!("Copied {count} {}", field.noun(count)),
        std::time::Instant::now(),
    ));
}

/// What to do to the marked devices.
fn actions_menu(ui: &mut egui::Ui, p: Palette, app: &mut App, targets: &Targets) {
    let response = menu_button(ui, p, "Actions", !targets.is_empty());
    let mode = app.mode;
    let looping = app.ping.is_looping();
    let scanning = app.ports.is_running() || !app.port_queue.is_empty();
    let mut act = None;
    popover(&response, p, mode, MENU_WIDTH, |ui| {
        ui.label(
            RichText::new(targets.describe().to_uppercase())
                .size(text::EYEBROW)
                .color(p.placeholder),
        );
        ui.add_space(metrics::S1);
        if menu_row(ui, p, "Ping", Some("Once, and fill the Ping column."), true) {
            act = Some(Action::Ping);
        }
        if looping {
            if menu_row(ui, p, "Stop pinging", Some("The loop is running."), true) {
                act = Some(Action::StopPing);
            }
        } else if menu_row(
            ui,
            p,
            "Ping until stopped",
            Some("Round and round, at the polite rate."),
            true,
        ) {
            act = Some(Action::LoopPing);
        }
        menu_separator(ui, p);
        if scanning {
            if menu_row(ui, p, "Stop scanning ports", None, true) {
                act = Some(Action::StopPorts);
            }
        } else if menu_row(
            ui,
            p,
            "Scan ports",
            Some("One device at a time, the common list."),
            true,
        ) {
            act = Some(Action::ScanPorts);
        }
    });

    match act {
        Some(Action::Ping) => app.start_pings(targets.addresses.clone(), false),
        Some(Action::LoopPing) => app.start_pings(targets.addresses.clone(), true),
        Some(Action::StopPing) => app.ping.cancel(),
        // **A queue, because the rate limiter is global.** Two port scans at
        // once would each get half the budget and both would look broken, so
        // the devices are lined up and taken one at a time; see
        // `ports::State`, which is the module that owns that rule.
        Some(Action::ScanPorts) => {
            app.port_queue = targets.addresses.iter().copied().collect();
            app.start_next_port_scan();
        }
        Some(Action::StopPorts) => {
            app.port_queue.clear();
            app.ports.cancel();
        }
        None => {}
    }
}

/// What the actions menu was asked for. Read once, after the popover has been
/// drawn, because acting inside it would borrow the app twice.
enum Action {
    Ping,
    LoopPing,
    StopPing,
    ScanPorts,
    StopPorts,
}

/// How wide the two table menus are: enough for their longest sentence.
const MENU_WIDTH: f32 = 240.0;

/// A §7.17 popover hung off a menu button, drawn in the family's frame.
///
/// The frame is the one [`scan_options`] uses, and it is here so the three
/// menus in this window cannot drift into three shapes. Unlike that one this
/// **is** a menu — every row is a choice that acts — so a click closes it,
/// which is §7.7's behaviour and what a reader expects of a list of verbs.
fn popover<R>(
    response: &egui::Response,
    p: Palette,
    mode: Mode,
    width: f32,
    content: impl FnOnce(&mut egui::Ui) -> R,
) {
    egui::Popup::menu(response)
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
            ui.set_width(width);
            content(ui);
        });
}

/// One choice in a menu: a label, an optional sentence under it, a hover fill.
fn menu_row(ui: &mut egui::Ui, p: Palette, label: &str, note: Option<&str>, enabled: bool) -> bool {
    let height = if note.is_some() {
        metrics::ROW + metrics::S3
    } else {
        metrics::ROW
    };
    let (rect, response) = ui.allocate_exact_size(
        vec2(ui.available_width(), height),
        if enabled {
            Sense::click()
        } else {
            Sense::hover()
        },
    );
    if enabled && response.hovered() {
        ui.painter().rect_filled(
            rect.expand2(vec2(metrics::S1, 0.0)),
            metrics::RADIUS,
            p.control_hover,
        );
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    let ink = if enabled { p.text } else { p.text_dim };
    let top = match note {
        Some(_) => rect.top() + metrics::ROW / 2.0 - 1.0,
        None => rect.center().y,
    };
    ui.painter().text(
        pos2(rect.left(), top),
        egui::Align2::LEFT_CENTER,
        label,
        FontId::proportional(text::CONTROL),
        ink,
    );
    if let Some(note) = note {
        ui.painter().text(
            pos2(rect.left(), rect.bottom() - metrics::S3 / 2.0 - 1.0),
            egui::Align2::LEFT_CENTER,
            note,
            FontId::proportional(text::TINY),
            p.text_dim,
        );
    }
    enabled && response.clicked()
}

/// The hairline between two groups of menu rows.
fn menu_separator(ui: &mut egui::Ui, p: Palette) {
    ui.add_space(metrics::S1);
    let (rect, _) = ui.allocate_exact_size(
        vec2(ui.available_width(), metrics::HAIRLINE),
        Sense::hover(),
    );
    ui.painter().rect_filled(rect, 0.0, p.line_popover);
    ui.add_space(metrics::S1);
}

/// A button that opens a menu: §7.6's secondary with a chevron after the label.
///
/// The chevron is the only thing saying it opens rather than acts, so it also
/// carries the cursor that says the same. Disabled where there is nothing for
/// the menu to be about, with a tooltip saying so rather than a list of verbs
/// that would all do nothing.
fn menu_button(ui: &mut egui::Ui, p: Palette, label: &str, enabled: bool) -> egui::Response {
    let font = FontId::proportional(text::CONTROL);
    let galley = ui
        .painter()
        .layout_no_wrap(label.to_string(), font.clone(), p.text);
    let width = galley.size().x + metrics::S3 * 2.0 + MENU_GAP + CHEVRON_INK;
    let (rect, response) = ui.allocate_exact_size(
        vec2(width, metrics::BUTTON),
        if enabled {
            Sense::click()
        } else {
            Sense::hover()
        },
    );
    let dim = |c: Color32| {
        if enabled { c } else { c.gamma_multiply(0.45) }
    };
    let fill = if enabled && response.hovered() {
        p.control_hover
    } else {
        p.control
    };
    ui.painter().rect_filled(rect, metrics::RADIUS, dim(fill));
    ui.painter().text(
        pos2(rect.left() + metrics::S3, rect.center().y),
        egui::Align2::LEFT_CENTER,
        label,
        font,
        dim(p.text),
    );

    let c = pos2(
        rect.right() - metrics::S3 - CHEVRON_INK / 2.0,
        rect.center().y,
    );
    let (w, h) = (CHEVRON * 0.34, CHEVRON * 0.18);
    let ink = if enabled && response.hovered() {
        p.text_strong
    } else {
        p.text_muted
    };
    for arm in [-w, w] {
        ui.painter().line_segment(
            [pos2(c.x + arm, c.y - h), pos2(c.x, c.y + h)],
            Stroke::new(1.4_f32, dim(ink)),
        );
    }
    if !enabled {
        return response.on_hover_text("Nothing to act on: mark some devices, or scan.");
    }
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// The pill at the foot of the window: what was just copied.
///
/// §7.17's toast, in the corner it names and above the status bar rather than
/// over it. One sentence, no action, and gone in six seconds — a confirmation
/// that has to be dismissed is a confirmation that interrupted.
fn copied_pill(ctx: &egui::Context, p: Palette, app: &mut App) {
    let Some((message, at)) = &app.copied else {
        return;
    };
    let age = at.elapsed();
    if age > TOAST_LIFE {
        app.copied = None;
        return;
    }
    // The last half second is a fade rather than a disappearance, which is the
    // one thing that keeps it from reading as a glitch at the edge of vision.
    let fade = ((TOAST_LIFE.as_secs_f32() - age.as_secs_f32()) / 0.5).clamp(0.0, 1.0);
    let message = message.clone();
    egui::Area::new(egui::Id::new("copied-pill"))
        .order(egui::Order::Foreground)
        .anchor(
            egui::Align2::RIGHT_BOTTOM,
            vec2(-metrics::PAD_STRIP, -(metrics::STATUS_BAR + metrics::S3)),
        )
        .interactable(false)
        .show(ctx, |ui| {
            egui::Frame::NONE
                .fill(p.popover.to_opaque().gamma_multiply(fade))
                .stroke(Stroke::new(
                    metrics::HAIRLINE,
                    p.line_popover.gamma_multiply(fade),
                ))
                .corner_radius(metrics::RADIUS_MODAL)
                .inner_margin(egui::Margin::symmetric(
                    metrics::PAD_PANEL as i8,
                    metrics::S2 as i8,
                ))
                .shadow(theme::shadow::menu(app.mode))
                .show(ui, |ui| {
                    ui.label(
                        RichText::new(message)
                            .size(text::SMALL)
                            .color(p.text.gamma_multiply(fade)),
                    );
                });
        });
}

/// How long the pill stays. §7.17's six seconds.
const TOAST_LIFE: std::time::Duration = std::time::Duration::from_secs(6);

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
            None,
        );
        let without = sort_key(
            Column::Name,
            &at("192.0.2.2"),
            None,
            muster_net::Kind::Unknown,
            None,
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
            None,
        );
        let one = sort_key(
            Column::Serves,
            &at("192.0.2.2"),
            Some(&resolver),
            muster_net::Kind::Server,
            None,
        );
        let none = sort_key(
            Column::Serves,
            &at("192.0.2.3"),
            None,
            muster_net::Kind::Unknown,
            None,
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
        assert_eq!(FIXED_COLUMNS, 836.0);
    }

    /// And they have to fit the window Muster opens at, beside the sidebar,
    /// with room left for the vendor column that takes what is left.
    ///
    /// This is the assertion that has teeth. A column added without widening
    /// the window pushes "Made by" off the right edge, where nothing scrolls
    /// sideways to reach it — and the person who finds out is on a laptop.
    #[test]
    fn the_columns_fit_the_window_with_room_for_the_last_one() {
        let taken = FIXED_COLUMNS + metrics::PAD_PANEL * 2.0 + metrics::SIDEBAR;
        assert!(
            taken + VENDOR_ROOM <= crate::WINDOW[0],
            "the table wants {taken} px and the window has {}",
            crate::WINDOW[0]
        );
    }

    /// Every column with a fixed width, in the order the header and the row
    /// both walk them. "Made by" is the flexible one and is deliberately not
    /// here.
    const FIXED_COLUMNS: f32 = COL_MARK
        + COL_KIND
        + COL_ADDRESS
        + COL_NAME
        + COL_MAC
        + COL_TIME
        + COL_PING
        + COL_SERVES
        + COL_PORTS;

    /// What "Made by" needs to be worth having: enough for the longest vendor
    /// name a real network has turned up, which is about twenty characters.
    const VENDOR_ROOM: f32 = 160.0;

    /// The two lists the header and the row walk have to hold the same columns
    /// in the same order, or the headings sit above the wrong figures and
    /// nothing looks wrong until somebody reads it.
    #[test]
    fn every_column_is_walked_once() {
        let mut seen = Column::ALL.to_vec();
        seen.sort_by_key(|c| *c as usize);
        seen.dedup();
        assert_eq!(seen.len(), Column::ALL.len(), "a column appears twice");
        assert_eq!(*Column::ALL.last().expect("not empty"), Column::Vendor);
    }

    /// Only the columns with something to size are draggable. The mark and the
    /// icon are boxes, and "Made by" takes whatever is left.
    #[test]
    fn the_fixed_columns_have_no_handle() {
        let mut widths = Widths::default();
        assert!(widths.slot(Column::Kind).is_none());
        assert!(widths.slot(Column::Vendor).is_none());
        for column in [Column::Address, Column::Name, Column::Mac] {
            assert!(widths.slot(column).is_some(), "{column:?}");
        }
    }

    /// A width out of bounds is brought back rather than refused, which is the
    /// settings file's rule for every other figure.
    #[test]
    fn a_width_is_clamped_rather_than_rejected() {
        let wild = Widths {
            address: 4.0,
            name: 9_000.0,
            mac: f32::NAN,
            ..Default::default()
        }
        .sane();
        assert_eq!(wild.address, Widths::NARROWEST);
        assert_eq!(wild.name, Widths::WIDEST);
        assert_eq!(
            wild.mac, COL_MAC,
            "a figure that is not one gives the default"
        );
    }

    /// The settings file's form, both ways.
    #[test]
    fn widths_survive_a_round_trip() {
        let dragged = Widths {
            address: 140.0,
            ports: 200.0,
            ..Default::default()
        };
        assert_eq!(Widths::parse(&dragged.render()), dragged);
    }

    /// Anything the file cannot offer gives the table it shipped with. A
    /// settings file that will not load is worse than a table somebody has to
    /// drag again.
    #[test]
    fn a_broken_columns_line_gives_the_default_table() {
        for line in [
            "",
            "116,174",
            "one,two,three,four,five,six,seven",
            "1,2,3,4,5,6,7,8",
        ] {
            assert_eq!(Widths::parse(line), Widths::default(), "{line:?}");
        }
    }

    /// The whole table still fits the narrowest window the application opens
    /// at, with room for the elastic column.
    #[test]
    fn the_default_table_fits_the_smallest_window() {
        let fixed = COL_MARK + COL_KIND + Widths::default().total();
        assert!(
            fixed + Widths::VENDOR_LEAST <= crate::WINDOW[0],
            "the columns want {fixed} and the window is {}",
            crate::WINDOW[0]
        );
    }
}
