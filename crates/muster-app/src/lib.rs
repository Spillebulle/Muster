//! Muster's window.
//!
//! The interface and nothing else: no probing lives here, and every fact on the
//! screen came out of `muster-net` through the same API the text mode uses.
//! That boundary is what keeps the engine testable, and it is why this crate
//! has so little logic in it — the parts worth reasoning about are one layer
//! down, where a test can reach them without a window.
//!
//! `CLAUDE.md`'s interface rules are followed in [`app`], and the token table in
//! [`theme`] is `../Design-Principles/tokens.css` transcribed rather than
//! reinvented.

pub mod app;
pub mod art;
pub mod deviceicon;
pub mod dhcpcheck;
pub mod icons;
pub mod lucide;
pub mod ping;
pub mod ports;
pub mod prefs;
pub mod scan;
pub mod settings;
pub mod theme;
pub mod themelib;
/// Checking for, fetching and installing a new release.
///
/// Public because `examples/make-setup.rs` builds the setup executable with
/// `update::payload::append` — the same function the running binary reads a
/// payload back with, so the writer and the reader cannot drift.
pub mod update;
pub mod updatedlg;

/// The application id, which is also the name of the desktop entry.
///
/// One string, because on Wayland it is the *only* thing that gives the running
/// window an icon. A Wayland client cannot hand the compositor a picture the way
/// X11's `_NET_WM_ICON` lets it, so `with_icon` below reaches the title bar on
/// Windows and X11 and is discarded on Wayland; the taskbar there looks up
/// `<app_id>.desktop` and takes the icon out of that. Set nothing and winit
/// sends no app id at all, which is how the launcher — reading the same desktop
/// entry by name — could show the mark while the taskbar showed a blank square.
///
/// So this must stay character for character `packaging/io.github.spillebulle.muster.desktop`'s
/// name, and `packaging/check.sh` fails when the two drift apart. It is also
/// what `eframe` names the preferences directory, so it is not a string to
/// change lightly.
pub const APP_ID: &str = "io.github.spillebulle.muster";

/// The size the window opens at.
///
/// **Wide enough for the device table's fixed columns, the sidebar and a
/// readable vendor column**, with nothing scrolled sideways. It is a constant
/// rather than a literal because `app`'s own test measures the columns against
/// it: a column added without room for it is a column that silently pushes
/// "Made by" off the edge, and that is the sort of thing nobody notices until
/// they are on a laptop. Tall enough for a /24's worth of rows to be worth
/// scrolling through.
pub const WINDOW: [f32; 2] = [1280.0, 760.0];

/// Opens the window.
///
/// The one entry point the binary uses. Returns the framework's error rather
/// than exiting, so a machine with no usable graphics adapter reports that
/// rather than vanishing.
pub fn run() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size(WINDOW)
            .with_min_inner_size([760.0, 420.0])
            .with_title("Muster")
            // The mark, rasterised from the palette rather than loaded
            // from a file, so the taskbar cannot show a stale accent.
            .with_icon(art::window_icon())
            // And on Wayland, where that picture is dropped, the name of the
            // desktop entry the compositor reads one out of. See [`APP_ID`].
            .with_app_id(APP_ID),
        ..Default::default()
    };
    eframe::run_native(
        APP_ID,
        options,
        Box::new(|cc| Ok(Box::new(app::App::new(cc)))),
    )
}
