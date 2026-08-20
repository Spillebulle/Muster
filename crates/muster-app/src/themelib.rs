//! Reading and writing `.umbertheme` files.
//!
//! The format is §3.2 of `../Design-Principles/STYLE-GUIDE.md`, and the
//! reference implementation is Umber's `themelib.rs`. **A theme made in a
//! sibling application opens in this one**, which is the whole point of the
//! family sharing a format, so everything here matches Umber deliberately —
//! including the header line, which says `Umber theme` in every application.
//! That reads oddly in Muster and is correct: it is the *format's* name, not
//! the application's, and changing it would fork the family.
//!
//! ## The shape
//!
//! ```text
//! Umber theme
//! # comments are skipped
//! name = Something
//! base = graphite
//! backdrop = #0D0E10
//! ...
//! ```
//!
//! Twenty-seven colour keys, always written, even where one equals the base's
//! value. A file is read in **two passes**: the first finds `base` so the
//! palette starts from a known ladder, the second applies the colours over it.
//! That ordering is what makes a partial theme legal — a file naming six
//! colours gets the other twenty-one from the theme it says it is based on.
//!
//! ## What is not in the file, and must not be
//!
//! `line_soft`, `line_dashed`, `field`, `placeholder`, `accent_ink`, `good` and
//! `critical` are all in [`Palette`] and none of them is a key. They are
//! **derived**, because a theme is a table of decisions and these are
//! consequences of decisions already made. Storing them would let a file
//! disagree with itself.
//!
//! ## Failure is per line, never per file
//!
//! A line that will not parse costs that one colour and nothing else; the base
//! theme's value stands and the count of skipped lines is reported. The one
//! thing that fails the whole file is a missing header, because a file that is
//! not a theme must not be read as a theme of default colours.

use crate::theme::{Mode, Palette};
use egui::Color32;

/// The first line of every theme file, in every application in the family.
const HEADER: &str = "Umber theme";

/// The extension, matched case-insensitively when listing a directory.
pub const EXTENSION: &str = "umbertheme";

/// Longest display name, in characters rather than bytes.
const MAX_NAME: usize = 64;

/// Most themes read from the library directory in one pass.
const MAX_THEMES: usize = 128;

const UNTITLED: &str = "Untitled theme";

/// The twenty-seven keys, in the order they are written.
///
/// The order is §2.1's: surfaces, lines, controls, type, accent, warnings,
/// links. It is also the order a theme editor would draw them in, which is why
/// it is stated once here rather than in two places.
///
/// **The file key is the stored word and may never change**, even where it
/// disagrees with the token's name in `tokens.css`: `border` is `--line`,
/// `popover_border` is `--line-popover`, `warning*` is `--caution*`, and
/// `link_1..6` are `--series-1..6`. Renaming any of them would silently drop
/// that colour from every file already written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Token {
    Backdrop,
    Window,
    Dock,
    Chrome,
    Popover,
    Border,
    PopoverBorder,
    Control,
    ControlHover,
    ControlActive,
    Rail,
    Knob,
    TextStrong,
    Text,
    TextMuted,
    TextDim,
    Accent,
    AccentDim,
    Warning,
    WarningBg,
    WarningBorder,
    Link1,
    Link2,
    Link3,
    Link4,
    Link5,
    Link6,
}

impl Token {
    pub const ALL: [Token; 27] = [
        Token::Backdrop,
        Token::Window,
        Token::Dock,
        Token::Chrome,
        Token::Popover,
        Token::Border,
        Token::PopoverBorder,
        Token::Control,
        Token::ControlHover,
        Token::ControlActive,
        Token::Rail,
        Token::Knob,
        Token::TextStrong,
        Token::Text,
        Token::TextMuted,
        Token::TextDim,
        Token::Accent,
        Token::AccentDim,
        Token::Warning,
        Token::WarningBg,
        Token::WarningBorder,
        Token::Link1,
        Token::Link2,
        Token::Link3,
        Token::Link4,
        Token::Link5,
        Token::Link6,
    ];

    /// The word this token is written as.
    pub const fn id(self) -> &'static str {
        match self {
            Token::Backdrop => "backdrop",
            Token::Window => "window",
            Token::Dock => "dock",
            Token::Chrome => "chrome",
            Token::Popover => "popover",
            Token::Border => "border",
            Token::PopoverBorder => "popover_border",
            Token::Control => "control",
            Token::ControlHover => "control_hover",
            Token::ControlActive => "control_active",
            Token::Rail => "rail",
            Token::Knob => "knob",
            Token::TextStrong => "text_strong",
            Token::Text => "text",
            Token::TextMuted => "text_muted",
            Token::TextDim => "text_dim",
            Token::Accent => "accent",
            Token::AccentDim => "accent_dim",
            Token::Warning => "warning",
            Token::WarningBg => "warning_bg",
            Token::WarningBorder => "warning_border",
            Token::Link1 => "link_1",
            Token::Link2 => "link_2",
            Token::Link3 => "link_3",
            Token::Link4 => "link_4",
            Token::Link5 => "link_5",
            Token::Link6 => "link_6",
        }
    }

    pub fn from_id(id: &str) -> Option<Token> {
        Token::ALL.into_iter().find(|t| t.id() == id)
    }

    /// Read this token out of a palette.
    pub fn get(self, p: &Palette) -> Color32 {
        match self {
            Token::Backdrop => p.backdrop,
            Token::Window => p.window,
            Token::Dock => p.dock,
            Token::Chrome => p.chrome,
            Token::Popover => p.popover,
            Token::Border => p.line,
            Token::PopoverBorder => p.line_popover,
            Token::Control => p.control,
            Token::ControlHover => p.control_hover,
            Token::ControlActive => p.control_active,
            Token::Rail => p.rail,
            Token::Knob => p.knob,
            Token::TextStrong => p.text_strong,
            Token::Text => p.text,
            Token::TextMuted => p.text_muted,
            Token::TextDim => p.text_dim,
            Token::Accent => p.accent,
            Token::AccentDim => p.accent_dim,
            Token::Warning => p.caution,
            Token::WarningBg => p.caution_bg,
            Token::WarningBorder => p.caution_line,
            Token::Link1 => p.series[0],
            Token::Link2 => p.series[1],
            Token::Link3 => p.series[2],
            Token::Link4 => p.series[3],
            Token::Link5 => p.series[4],
            Token::Link6 => p.series[5],
        }
    }

    /// Write this token into a palette.
    pub fn set(self, p: &mut Palette, c: Color32) {
        match self {
            Token::Backdrop => p.backdrop = c,
            Token::Window => p.window = c,
            Token::Dock => p.dock = c,
            Token::Chrome => p.chrome = c,
            Token::Popover => p.popover = c,
            Token::Border => p.line = c,
            Token::PopoverBorder => p.line_popover = c,
            Token::Control => p.control = c,
            Token::ControlHover => p.control_hover = c,
            Token::ControlActive => p.control_active = c,
            Token::Rail => p.rail = c,
            Token::Knob => p.knob = c,
            Token::TextStrong => p.text_strong = c,
            Token::Text => p.text = c,
            Token::TextMuted => p.text_muted = c,
            Token::TextDim => p.text_dim = c,
            Token::Accent => p.accent = c,
            Token::AccentDim => p.accent_dim = c,
            Token::Warning => p.caution = c,
            Token::WarningBg => p.caution_bg = c,
            Token::WarningBorder => p.caution_line = c,
            Token::Link1 => p.series[0] = c,
            Token::Link2 => p.series[1] = c,
            Token::Link3 => p.series[2] = c,
            Token::Link4 => p.series[3] = c,
            Token::Link5 => p.series[4] = c,
            Token::Link6 => p.series[5] = c,
        }
    }
}

/// A theme read from a file.
#[derive(Clone, Debug)]
pub struct CustomTheme {
    /// The file's stem, and the identity that survives a rename.
    pub id: String,
    pub name: String,
    /// The word the file gave for `base`, kept verbatim.
    ///
    /// **Kept rather than normalised**, which is a deliberate difference from
    /// Umber. Umber knows bases Muster does not, and would rewrite a
    /// `base = krita` it did not recognise as `base = graphite` — silently
    /// changing somebody's file on a round trip. Storing the raw word costs
    /// nothing, is invisible to Umber, and means Muster never damages a theme
    /// it merely opened.
    pub base: String,
    pub palette: Palette,
    /// How many lines could not be read. Shown, never hidden.
    pub skipped: usize,
}

impl CustomTheme {
    /// Is this a dark theme?
    ///
    /// **Decided by the base it names, never measured off its colours.** A
    /// theme is dark because it says it is; guessing from lightness would make
    /// a deliberately pale dark theme flip category.
    pub fn is_dark(&self) -> bool {
        !self.base.eq_ignore_ascii_case("paper")
    }
}

/// The palette a base word starts from.
fn base_palette(base: &str) -> Palette {
    match base.to_ascii_lowercase().as_str() {
        "paper" => Palette::of(Mode::Light),
        // Anything else, including a base only a sibling application knows,
        // fills from Graphite. The unknown word is still kept on the theme.
        _ => Palette::of(Mode::Dark),
    }
}

/// Read a theme file.
///
/// `stem` is the file name without its extension, used as the id and as the
/// fallback display name.
pub fn read(text: &str, stem: &str) -> Result<CustomTheme, String> {
    let mut lines = text.lines();
    let first = lines.next().unwrap_or_default();
    // The byte-order mark is stripped from this line only: a file saved by a
    // Windows editor starts with one and is otherwise perfectly good.
    let first = first.trim_start_matches('\u{feff}').trim();
    if !first.eq_ignore_ascii_case(HEADER) {
        return Err(format!(
            "That file does not start with \"{HEADER}\", so it is not a theme."
        ));
    }

    let body: Vec<(String, String)> = lines
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            Some((key.trim().to_ascii_lowercase(), value.trim().to_string()))
        })
        .collect();

    // Pass one: the base, so the palette starts from a known ladder.
    let base = body
        .iter()
        .rev()
        .find(|(k, _)| k == "base")
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| "graphite".to_string());
    let mut palette = base_palette(&base);

    // Pass two: the name and the colours over it.
    let mut name = String::new();
    let mut skipped = 0usize;
    for (key, value) in &body {
        if key == "base" {
            continue;
        }
        if key == "name" {
            name = clean_name(value);
            continue;
        }
        match (Token::from_id(key), parse_hex(value)) {
            (Some(token), Some(colour)) => token.set(&mut palette, colour),
            // Either an unknown key or a colour that will not parse. The base's
            // value stands; black is never taken for a misread line.
            _ => skipped += 1,
        }
    }

    if name.is_empty() {
        name = clean_name(stem);
    }
    if name.is_empty() {
        name = UNTITLED.to_string();
    }

    Ok(CustomTheme {
        id: slug(stem),
        name,
        base,
        palette,
        skipped,
    })
}

/// Write a theme file.
pub fn write(theme: &CustomTheme) -> String {
    let mut out = String::with_capacity(1024);
    out.push_str(HEADER);
    out.push('\n');
    out.push_str(
        "# A theme is a table of colours. Every line is a token and a\n\
         # six-digit sRGB hex; a line that does not parse costs that one\n\
         # colour and nothing else, and a token left out takes the base\n\
         # theme's value.\n",
    );
    out.push_str(&format!("name = {}\n", theme.name));
    out.push_str(&format!("base = {}\n", theme.base));
    for token in Token::ALL {
        out.push_str(&format!(
            "{} = {}\n",
            token.id(),
            to_hex(token.get(&theme.palette))
        ));
    }
    out
}

/// `#RGB` or `#RRGGBB`, in any case. No alpha, ever.
fn parse_hex(value: &str) -> Option<Color32> {
    let v = value.trim().trim_start_matches('#');
    if !v.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let digits: Vec<u32> = v.chars().filter_map(|c| c.to_digit(16)).collect();
    match digits.len() {
        // Short form: each digit doubled, so `#0AF` is `#00AAFF`.
        3 => Some(Color32::from_rgb(
            (digits[0] * 17) as u8,
            (digits[1] * 17) as u8,
            (digits[2] * 17) as u8,
        )),
        6 => Some(Color32::from_rgb(
            (digits[0] * 16 + digits[1]) as u8,
            (digits[2] * 16 + digits[3]) as u8,
            (digits[4] * 16 + digits[5]) as u8,
        )),
        _ => None,
    }
}

fn to_hex(c: Color32) -> String {
    format!("#{:02X}{:02X}{:02X}", c.r(), c.g(), c.b())
}

/// Control characters to spaces, cut to 64 characters, then trimmed.
///
/// The cut happens **before** the trim, which is Umber's order and matters: a
/// name whose sixty-fourth character is a space comes out without it.
fn clean_name(raw: &str) -> String {
    raw.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_NAME)
        .collect::<String>()
        .trim()
        .to_string()
}

/// A file-name stem from a display name.
///
/// ASCII alphanumerics lower-cased, every other run collapsed to a single `-`,
/// trimmed of `-`, cut at 48 characters, and `theme` if nothing survives.
pub fn slug(name: &str) -> String {
    let mut out = String::new();
    let mut pending_dash = false;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            if pending_dash && !out.is_empty() {
                out.push('-');
            }
            pending_dash = false;
            out.push(c.to_ascii_lowercase());
        } else {
            pending_dash = true;
        }
        if out.len() >= 48 {
            break;
        }
    }
    let out = out.trim_matches('-').to_string();
    if out.is_empty() {
        "theme".to_string()
    } else {
        out
    }
}

/// Where themes live: the **data** directory, not the configuration one.
///
/// A theme is content somebody made, not a setting; the split is the
/// platform's own and putting a library in the settings directory is how it
/// ends up being wiped by something tidying preferences.
pub fn directory() -> Option<std::path::PathBuf> {
    directories::ProjectDirs::from("io.github", "spillebulle", "muster")
        .map(|dirs| dirs.data_dir().join("themes"))
}

/// Every theme in the library, and a note for any file that could not be read.
///
/// A file that fails is reported rather than skipped in silence: somebody put
/// it there on purpose.
pub fn load_all() -> (Vec<CustomTheme>, Vec<String>) {
    let mut themes = Vec::new();
    let mut problems = Vec::new();
    let Some(dir) = directory() else {
        return (themes, problems);
    };
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return (themes, problems);
    };

    let mut paths: Vec<std::path::PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .is_some_and(|e| e.to_string_lossy().eq_ignore_ascii_case(EXTENSION))
        })
        .collect();
    paths.sort();

    for path in paths.into_iter().take(MAX_THEMES) {
        let stem = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        match std::fs::read_to_string(&path) {
            Ok(text) => match read(&text, &stem) {
                Ok(theme) => themes.push(theme),
                Err(why) => problems.push(format!("{}: {why}", path.display())),
            },
            Err(e) => problems.push(format!("{}: {e}", path.display())),
        }
    }
    (themes, problems)
}

/// Write a theme into the library, atomically.
///
/// Through a temporary file and a rename, so a failure part-way leaves the
/// previous theme intact rather than a half-written one.
pub fn save(theme: &CustomTheme) -> Result<std::path::PathBuf, String> {
    let dir = directory().ok_or("No data directory on this machine.")?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let path = dir.join(format!("{}.{EXTENSION}", theme.id));
    let temp = path.with_extension(format!("{EXTENSION}.saving"));
    std::fs::write(&temp, write(theme)).map_err(|e| format!("{}: {e}", temp.display()))?;
    if let Err(e) = std::fs::rename(&temp, &path) {
        let _ = std::fs::remove_file(&temp);
        return Err(format!("{}: {e}", path.display()));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_token_has_a_distinct_key_and_there_are_twenty_seven() {
        let mut ids: Vec<&str> = Token::ALL.iter().map(|t| t.id()).collect();
        assert_eq!(ids.len(), 27, "the format is twenty-seven keys");
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 27, "two tokens share a key");
    }

    #[test]
    fn a_theme_survives_a_round_trip() {
        let mut palette = Palette::of(Mode::Dark);
        palette.accent = Color32::from_rgb(0x12, 0x34, 0x56);
        let theme = CustomTheme {
            id: "test".into(),
            name: "Test".into(),
            base: "graphite".into(),
            palette,
            skipped: 0,
        };
        let text = write(&theme);
        let back = read(&text, "test").expect("it reads");
        assert_eq!(back.name, "Test");
        assert_eq!(back.base, "graphite");
        assert_eq!(back.palette.accent, Color32::from_rgb(0x12, 0x34, 0x56));
        assert_eq!(back.skipped, 0);
    }

    #[test]
    fn a_file_that_is_not_a_theme_is_refused_whole() {
        // Never read as a theme of default colours: that would be a made-up
        // theme presented as somebody's.
        assert!(read("name = Nice\naccent = #FF0000\n", "x").is_err());
        assert!(read("", "x").is_err());
    }

    #[test]
    fn a_byte_order_mark_does_not_stop_a_good_file_being_read() {
        let text = format!("\u{feff}{HEADER}\nname = Marked\n");
        assert_eq!(read(&text, "x").expect("reads").name, "Marked");
    }

    #[test]
    fn a_line_that_will_not_parse_costs_one_colour_and_is_counted() {
        let text = format!("{HEADER}\nbase = graphite\naccent = not-a-colour\nwindow = #010203\n");
        let theme = read(&text, "x").expect("reads");
        assert_eq!(theme.skipped, 1);
        assert_eq!(
            theme.palette.accent,
            Palette::of(Mode::Dark).accent,
            "the base's value stands"
        );
        assert_eq!(theme.palette.window, Color32::from_rgb(1, 2, 3));
    }

    #[test]
    fn an_absent_token_takes_the_base_theme_s_value() {
        let text = format!("{HEADER}\nbase = paper\naccent = #000000\n");
        let theme = read(&text, "x").expect("reads");
        assert_eq!(theme.palette.window, Palette::of(Mode::Light).window);
        assert!(!theme.is_dark(), "it said paper, so it is light");
    }

    #[test]
    fn a_base_only_a_sibling_knows_is_kept_rather_than_rewritten() {
        // Umber would normalise this to `graphite` and change somebody's file
        // on a round trip through Muster. Keeping the word costs nothing.
        let text = format!("{HEADER}\nbase = krita\n");
        let theme = read(&text, "x").expect("reads");
        assert_eq!(theme.base, "krita");
        assert!(write(&theme).contains("base = krita"));
        assert_eq!(
            theme.palette.window,
            Palette::of(Mode::Dark).window,
            "and it fills from graphite"
        );
    }

    #[test]
    fn colours_are_read_in_both_lengths_and_written_in_one() {
        assert_eq!(parse_hex("#0AF"), Some(Color32::from_rgb(0, 0xAA, 0xFF)));
        assert_eq!(parse_hex("00aaff"), Some(Color32::from_rgb(0, 0xAA, 0xFF)));
        assert_eq!(parse_hex("#12345"), None, "five digits is not a colour");
        assert_eq!(parse_hex("#gggggg"), None);
        assert_eq!(to_hex(Color32::from_rgb(0, 0xAA, 0xFF)), "#00AAFF");
    }

    #[test]
    fn a_name_is_cut_before_it_is_trimmed() {
        // Umber's order, and it is visible: a name whose sixty-fourth
        // character is a space comes out without it.
        let long = format!("{}{}", "a".repeat(63), "  tail");
        assert_eq!(clean_name(&long).len(), 63);
        assert_eq!(clean_name("  spaced  "), "spaced");
        assert_eq!(clean_name("with\u{7}control"), "with control");
    }

    #[test]
    fn a_slug_is_a_file_name_and_never_empty() {
        assert_eq!(slug("Midnight Blue"), "midnight-blue");
        assert_eq!(slug("  ...  "), "theme");
        assert_eq!(slug("Ünïcodé"), "n-cod");
        assert!(slug(&"x".repeat(200)).len() <= 48);
    }

    #[test]
    fn every_key_is_written_even_when_it_equals_the_base() {
        let theme = CustomTheme {
            id: "t".into(),
            name: "T".into(),
            base: "graphite".into(),
            palette: Palette::of(Mode::Dark),
            skipped: 0,
        };
        let text = write(&theme);
        for token in Token::ALL {
            assert!(
                text.contains(&format!("{} = ", token.id())),
                "{} is missing",
                token.id()
            );
        }
    }
}
