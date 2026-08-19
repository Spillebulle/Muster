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
pub mod prefs;
pub mod scan;
pub mod theme;
/// Checking for, fetching and installing a new release.
///
/// Public because `examples/make-setup.rs` builds the setup executable with
/// `update::payload::append` — the same function the running binary reads a
/// payload back with, so the writer and the reader cannot drift.
pub mod update;
pub mod updatedlg;

/// Opens the window.
///
/// The one entry point the binary uses. Returns the framework's error rather
/// than exiting, so a machine with no usable graphics adapter reports that
/// rather than vanishing.
pub fn run() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            // Wide enough for the device table's columns without a horizontal
            // scroll, and tall enough for a /24's worth of rows to be worth
            // scrolling through.
            .with_inner_size([1100.0, 720.0])
            .with_min_inner_size([760.0, 420.0])
            .with_title("Muster")
            // The mark, rasterised from the palette rather than loaded
            // from a file, so the taskbar cannot show a stale accent.
            .with_icon(art::window_icon()),
        ..Default::default()
    };
    eframe::run_native(
        "io.github.spillebulle.muster",
        options,
        Box::new(|cc| Ok(Box::new(app::App::new(cc)))),
    )
}
