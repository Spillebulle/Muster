//! The settings that outlive a run.
//!
//! `key = value`, one per line, with a `version` on the first. That was two
//! booleans once, and this file said it would become a real format at the third
//! setting; it is now a dozen and the format is still `key = value` — because a
//! settings file is a compatibility promise, and the promise this shape makes
//! is the easy one to keep.
//!
//! **An unknown key is ignored and a figure out of range is clamped, never
//! rejected.** A downgrade must not wipe what a later version wrote, and a
//! hand-edited file must not lose every setting because one line is wrong.
//!
//! `CLAUDE.md` requires that the setting governing the update check live in one
//! place. It lives here, and the settings page is the one screen that writes it.
//!
//! An unreadable or missing file is a first run, and the answer to both is the
//! defaults — which are the cautious ones, so "cannot read settings" comes out
//! as "asks before it checks", never as "checks anyway".

use crate::theme::Mode;
use std::path::PathBuf;

/// The format's version. Written first, and read but not yet branched on: it is
/// here so that a later change has something to branch on.
const VERSION: u32 = 1;

/// Which theme the interface wears.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Theme {
    Dark,
    Light,
    /// Follow the desktop. §3.1's third state and the default: an application
    /// that ignores the system preference is wrong half of every day.
    #[default]
    System,
}

impl Theme {
    pub const ALL: [Theme; 3] = [Theme::Dark, Theme::Light, Theme::System];

    pub const fn label(self) -> &'static str {
        match self {
            Theme::Dark => "Dark",
            Theme::Light => "Light",
            Theme::System => "System",
        }
    }

    const fn id(self) -> &'static str {
        match self {
            Theme::Dark => "dark",
            Theme::Light => "light",
            Theme::System => "system",
        }
    }

    fn from_id(id: &str) -> Option<Theme> {
        Theme::ALL.into_iter().find(|t| t.id() == id)
    }

    /// The palette this choice resolves to, given what the desktop asked for.
    pub fn resolve(self, system: Mode) -> Mode {
        match self {
            Theme::Dark => Mode::Dark,
            Theme::Light => Mode::Light,
            Theme::System => system,
        }
    }
}

/// How far the interface scale may be moved.
///
/// Below 0.75 the 11 px type stops being readable; above 2.0 the device table's
/// columns will not fit a small screen. Clamped on read rather than refused,
/// which is the rule for every figure in this file.
pub const SCALE_MIN: f32 = 0.75;
pub const SCALE_MAX: f32 = 2.0;

/// What is remembered between runs.
#[derive(Clone, Debug, PartialEq)]
pub struct Prefs {
    pub theme: Theme,
    /// The chosen custom theme's id, when one is chosen.
    pub custom_theme: Option<String>,
    /// egui's zoom factor. **Not the source of truth while running** — the
    /// context is. This is only what was last written.
    pub interface_scale: f32,

    /// Whether Muster asks GitHub for the release list when it starts.
    pub check_on_startup: bool,
    /// Whether the user has been shown what that check does. While this is
    /// false, no check runs at all.
    pub notice_seen: bool,
    /// When the last check went out, in seconds since the epoch. A rate limit
    /// rather than a cache: see `update::MIN_BETWEEN_CHECKS`.
    pub last_check: u64,

    /// Probes a second for a sweep, shared by every probe in it.
    pub rate: u32,
    /// Probes a second for a port scan of one device.
    pub port_rate: u32,
    /// Say so before sweeping a range this machine is not on.
    pub warn_off_link: bool,
    /// The port list. Empty means the built-in common list.
    pub port_list: String,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            theme: Theme::System,
            custom_theme: None,
            interface_scale: 1.0,
            // On, but gated behind `notice_seen`: the request does not go out
            // until somebody has been told it would.
            check_on_startup: true,
            notice_seen: false,
            last_check: 0,
            rate: muster_net::rate::DEFAULT_RATE,
            port_rate: 400,
            warn_off_link: true,
            port_list: String::new(),
        }
    }
}

/// Where the file lives, or `None` on a machine with no home to put it in.
pub fn path() -> Option<PathBuf> {
    directories::ProjectDirs::from("io.github", "spillebulle", "muster")
        .map(|dirs| dirs.config_dir().join("settings"))
}

/// Read the settings, falling back to the defaults for anything absent.
pub fn load() -> Prefs {
    let Some(path) = path() else {
        return Prefs::default();
    };
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Prefs::default();
    };
    parse(&text)
}

/// The parser, over text rather than over a file.
///
/// Separate so the tests exercise the half that can be wrong; `load` differs
/// only in where the string came from.
pub fn parse(text: &str) -> Prefs {
    let mut prefs = Prefs::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        let flag = value == "true";
        match key {
            "version" => {}
            "theme" => {
                if let Some(t) = Theme::from_id(&value.to_ascii_lowercase()) {
                    prefs.theme = t;
                }
            }
            // Absent and empty mean the same thing, and the file never carries
            // an empty one: a theme id is a file name.
            "custom_theme" => {
                prefs.custom_theme = (!value.is_empty()).then(|| value.to_string());
            }
            "interface_scale" => {
                if let Ok(v) = value.parse::<f32>() {
                    prefs.interface_scale = v.clamp(SCALE_MIN, SCALE_MAX);
                }
            }
            "check_on_startup" => prefs.check_on_startup = flag,
            "notice_seen" => prefs.notice_seen = flag,
            "last_check" => prefs.last_check = value.parse().unwrap_or(0),
            "rate" => {
                if let Ok(v) = value.parse::<u32>() {
                    prefs.rate = v.clamp(1, 100_000);
                }
            }
            "port_rate" => {
                if let Ok(v) = value.parse::<u32>() {
                    prefs.port_rate = v.clamp(1, 100_000);
                }
            }
            "warn_off_link" => prefs.warn_off_link = flag,
            "port_list" => prefs.port_list = value.to_string(),
            // A file written by a newer Muster. Ignored rather than refused:
            // the alternative is a downgrade wiping settings it did not
            // understand.
            _ => {}
        }
    }
    prefs
}

/// The file's text, for writing or for showing.
pub fn render(prefs: &Prefs) -> String {
    let mut out = String::new();
    out.push_str(&format!("version = {VERSION}\n"));
    out.push_str(&format!("theme = {}\n", prefs.theme.id()));
    if let Some(id) = &prefs.custom_theme {
        out.push_str(&format!("custom_theme = {id}\n"));
    }
    out.push_str(&format!("interface_scale = {:.3}\n", prefs.interface_scale));
    out.push_str(&format!("check_on_startup = {}\n", prefs.check_on_startup));
    out.push_str(&format!("notice_seen = {}\n", prefs.notice_seen));
    out.push_str(&format!("last_check = {}\n", prefs.last_check));
    out.push_str(&format!("rate = {}\n", prefs.rate));
    out.push_str(&format!("port_rate = {}\n", prefs.port_rate));
    out.push_str(&format!("warn_off_link = {}\n", prefs.warn_off_link));
    if !prefs.port_list.is_empty() {
        out.push_str(&format!("port_list = {}\n", prefs.port_list));
    }
    out
}

/// Write the settings.
///
/// A failure is logged and no more. Nothing on screen depends on this having
/// worked, and a dialog about a settings file is a worse interruption than a
/// preference that does not stick.
pub fn save(prefs: &Prefs) {
    let Some(path) = path() else {
        log::warn!("no configuration directory on this machine; settings not saved");
        return;
    };
    if let Some(dir) = path.parent()
        && let Err(e) = std::fs::create_dir_all(dir)
    {
        log::warn!("could not create {}: {e}", dir.display());
        return;
    }
    if let Err(e) = std::fs::write(&path, render(prefs)) {
        log::warn!("could not write {}: {e}", path.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_machine_has_not_been_asked_yet() {
        assert!(
            !Prefs::default().notice_seen,
            "no check may run before the notice"
        );
    }

    #[test]
    fn everything_survives_a_round_trip() {
        let prefs = Prefs {
            theme: Theme::Light,
            custom_theme: Some("midnight".into()),
            interface_scale: 1.25,
            check_on_startup: false,
            notice_seen: true,
            last_check: 1_760_000_000,
            rate: 500,
            port_rate: 200,
            warn_off_link: false,
            port_list: "22,80,443".into(),
        };
        assert_eq!(parse(&render(&prefs)), prefs);
    }

    #[test]
    fn an_unknown_key_is_ignored_rather_than_refused() {
        // A file written by a later Muster. Losing the settings it did share is
        // the failure this guards.
        let prefs = parse("version = 9\nnotice_seen = true\ngizmo = 12\nrate = 250\n");
        assert!(prefs.notice_seen);
        assert_eq!(prefs.rate, 250);
    }

    #[test]
    fn a_figure_out_of_range_is_clamped_rather_than_dropped() {
        // Rejecting the line would throw away every other setting in the file
        // with it.
        assert_eq!(parse("interface_scale = 9.0\n").interface_scale, SCALE_MAX);
        assert_eq!(parse("interface_scale = 0.1\n").interface_scale, SCALE_MIN);
        assert_eq!(
            parse("interface_scale = huge\n").interface_scale,
            Prefs::default().interface_scale,
            "and something that is not a number leaves the default"
        );
    }

    #[test]
    fn a_damaged_file_falls_back_to_the_cautious_defaults() {
        let prefs = parse("this is not a settings file\n\n#\n");
        assert_eq!(prefs, Prefs::default());
        assert!(!prefs.notice_seen);
    }

    #[test]
    fn the_scan_defaults_are_the_engine_s_own() {
        // Two statements of one number is how they drift, and the settings page
        // shows these as the defaults — so they have to *be* the defaults.
        assert_eq!(Prefs::default().rate, muster_net::rate::DEFAULT_RATE);
    }

    #[test]
    fn system_is_the_default_theme() {
        // §3.1: nothing is stamped unless somebody chose it.
        assert_eq!(Prefs::default().theme, Theme::System);
        assert_eq!(Theme::System.resolve(Mode::Light), Mode::Light);
        assert_eq!(Theme::Dark.resolve(Mode::Light), Mode::Dark);
    }

    #[test]
    fn an_empty_custom_theme_is_no_custom_theme() {
        assert_eq!(parse("custom_theme = \n").custom_theme, None);
        assert_eq!(
            parse("custom_theme = midnight\n").custom_theme.as_deref(),
            Some("midnight")
        );
    }
}
