//! The settings that outlive a run.
//!
//! There are two of them and they are both about the same thing: whether Muster
//! may ask GitHub what the newest release is. `CLAUDE.md` puts it plainly —
//! nothing leaves the machine, the update check is the one exception, it is off
//! until the user has been asked, and **the setting that controls it is in one
//! place.** This module is that place.
//!
//! The format is `key = value`, one per line, and that is a deliberate refusal
//! rather than an oversight. A settings file is a compatibility promise: the
//! next version has to read what this one wrote. Two booleans do not need a
//! serialisation format to make that promise, and choosing one now would fix a
//! shape before there is anything to shape. When there is a third setting worth
//! keeping this can become a real format, and reading the old file is six
//! lines.
//!
//! An unreadable or missing file is not an error. It is a first run, or a
//! machine where the configuration directory cannot be written, and the answer
//! to both is the defaults — which are the cautious ones, so the failure mode
//! of "cannot read settings" is "asks before it checks", not "checks anyway".

use std::path::PathBuf;

/// What is remembered between runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefs {
    /// Whether Muster asks GitHub for the release list when it starts.
    pub check_on_startup: bool,
    /// Whether the user has been shown what that check does.
    ///
    /// False on a fresh install, and while it is false **no check runs at
    /// all**. This is what makes `check_on_startup`'s default defensible: the
    /// request does not go out until somebody has been told it would.
    pub notice_seen: bool,
    /// When the last check went out, in seconds since the epoch.
    ///
    /// **This is a rate limit, not a cache.** GitHub allows sixty
    /// unauthenticated requests an hour from one address, and Muster is a tool
    /// people open, look at, and close — a check on every launch spends that
    /// budget in an afternoon of ordinary use, and the sixty-first launch is
    /// told it has been blocked. Remembering the last one is what keeps the
    /// automatic check to a few a day. A check the user asks for is never
    /// throttled: they can see the answer, so they can see the failure.
    ///
    /// Zero means never, which is what a fresh install and an unreadable file
    /// both come to.
    pub last_check: u64,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            // On, but gated behind `notice_seen`. See that field, and
            // `update::Updates::check_on_startup`, which carries the argument.
            check_on_startup: true,
            notice_seen: false,
            last_check: 0,
        }
    }
}

/// Where the file lives, or `None` on a machine with no home to put it in.
///
/// `directories` rather than a hand-rolled `%APPDATA%` / `$XDG_CONFIG_HOME`
/// pair, because the two platforms disagree about more than the variable name
/// and the crate already encodes which is which.
pub fn path() -> Option<PathBuf> {
    directories::ProjectDirs::from("io.github", "spillebulle", "muster")
        .map(|dirs| dirs.config_dir().join("settings"))
}

/// Read the settings, falling back to the defaults for anything absent.
pub fn load() -> Prefs {
    let mut prefs = Prefs::default();
    let Some(path) = path() else { return prefs };
    let Ok(text) = std::fs::read_to_string(&path) else {
        return prefs;
    };
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let raw = value;
        let value = value.trim() == "true";
        match key.trim() {
            "check_on_startup" => prefs.check_on_startup = value,
            "notice_seen" => prefs.notice_seen = value,
            // The one setting that is not a boolean, so it is read from the
            // raw text rather than from `value`. Anything unparseable is
            // "never", which costs one extra check and never skips one.
            "last_check" => prefs.last_check = raw.trim().parse().unwrap_or(0),
            // An unknown key is a file written by a newer Muster. Ignored
            // rather than refused: the alternative is a downgrade wiping
            // settings it did not understand.
            _ => {}
        }
    }
    prefs
}

/// Write the settings.
///
/// A failure is logged and no more. Nothing on screen depends on this having
/// worked, and a dialog about a settings file is a worse interruption than a
/// preference that does not stick.
pub fn save(prefs: Prefs) {
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
    let text = format!(
        "check_on_startup = {}\nnotice_seen = {}\nlast_check = {}\n",
        prefs.check_on_startup, prefs.notice_seen, prefs.last_check
    );
    if let Err(e) = std::fs::write(&path, text) {
        log::warn!("could not write {}: {e}", path.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The parser, over text rather than over a file, which is the half worth
    /// testing: `load` differs from this only in where the string came from.
    fn parse(text: &str) -> Prefs {
        let mut prefs = Prefs::default();
        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let raw = value;
            let value = value.trim() == "true";
            match key.trim() {
                "check_on_startup" => prefs.check_on_startup = value,
                "notice_seen" => prefs.notice_seen = value,
                "last_check" => prefs.last_check = raw.trim().parse().unwrap_or(0),
                _ => {}
            }
        }
        prefs
    }

    #[test]
    fn a_fresh_machine_has_not_been_asked_yet() {
        let prefs = Prefs::default();
        assert!(!prefs.notice_seen, "no check may run before the notice");
    }

    #[test]
    fn a_written_file_reads_back_the_same() {
        let prefs = Prefs {
            check_on_startup: false,
            notice_seen: true,
            last_check: 1_760_000_000,
        };
        let text = format!(
            "check_on_startup = {}\nnotice_seen = {}\nlast_check = {}\n",
            prefs.check_on_startup, prefs.notice_seen, prefs.last_check
        );
        assert_eq!(parse(&text), prefs);
    }

    #[test]
    fn an_unknown_key_is_ignored_rather_than_refused() {
        // A file written by a later Muster. Losing the settings it did share is
        // the failure this guards.
        let prefs = parse("notice_seen = true\naccent = 200\ncheck_on_startup = false\n");
        assert!(prefs.notice_seen);
        assert!(!prefs.check_on_startup);
    }

    #[test]
    fn a_last_check_that_will_not_parse_means_never() {
        // Costs one extra check, which is the harmless direction. Reading it as
        // "just now" would silently switch the startup check off.
        assert_eq!(parse("last_check = tomorrow\n").last_check, 0);
        assert_eq!(parse("last_check = 42\n").last_check, 42);
    }

    #[test]
    fn a_damaged_file_falls_back_to_the_cautious_defaults() {
        let prefs = parse("this is not a settings file\n\n#\n");
        assert_eq!(prefs, Prefs::default());
        assert!(!prefs.notice_seen);
    }
}
