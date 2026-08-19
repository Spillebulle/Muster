//! The token table, ported from `../Design-Principles/tokens.css`.
//!
//! `CLAUDE.md`: port it rather than re-deriving it, and keep the size table
//! identical — the point of the numbers is that they are the same in every app
//! in the family. So the sizes below are `tokens.css`'s values transcribed, and
//! a change to one of them is a change to the house style rather than to Muster.
//!
//! ## The accent is derived, not picked
//!
//! `--accent-h` is the one number an app sets, and everything accent-coloured
//! comes out of it: `oklch(0.674 0.101 h)` for the accent and
//! `oklch(0.447 0.061 h)` for its muted twin, in both themes. Muster's hue is
//! **200**, signal cyan. Writing the resulting sRGB values in as constants would
//! work and would be wrong — it breaks the property that the hue is a single
//! knob, and the next app in the family copies the constants instead of the
//! recipe. [`oklch`] is therefore a real conversion, forty lines, and the tests
//! check it against the hexes `tokens.css` records in its own comments.
//!
//! The **neutrals** are the family's and are not derived from anything: they are
//! a hand-picked ladder at hue 264 (dark) and 82 (light), and `tokens.css`
//! states them in OKLCH so they read as a recipe. They go through the same
//! conversion for the same reason.

use egui::Color32;

/// Muster's hue. Umber is 60, HomeLab 160, Tally 255.
pub const ACCENT_H: f32 = 200.0;

/// Chrome sizes. Every one of these is `tokens.css`'s, and none of them is
/// Muster's to change.
pub mod metrics {
    /// The top bar, with the accent mark at its left.
    pub const MENU_BAR: f32 = 34.0;
    pub const STATUS_BAR: f32 = 26.0;
    /// The navigation column.
    pub const SIDEBAR: f32 = 240.0;
    /// A docked panel column, where Muster grows one.
    pub const PANEL: f32 = 264.0;
    /// A navigation row in the sidebar.
    pub const NAV_ROW: f32 = 30.0;
    /// A list row that is only text, which is what a device row is.
    pub const ROW_PLAIN: f32 = 20.0;
    /// A list row carrying a picture or a control.
    pub const ROW: f32 = 26.0;
    pub const BUTTON: f32 = 26.0;
    pub const FIELD: f32 = 26.0;
    /// Horizontal padding inside every strip.
    pub const PAD_STRIP: f32 = 12.0;
    pub const PAD_PANEL: f32 = 12.0;

    pub const RADIUS_TIGHT: f32 = 3.0;
    pub const RADIUS: f32 = 5.0;
    pub const RADIUS_TOOL: f32 = 6.0;
    pub const RADIUS_CARD: f32 = 8.0;
    pub const RADIUS_MODAL: f32 = 10.0;

    /// The app mark: a rounded square in the accent, no glyph in it.
    pub const MARK: f32 = 15.0;
    pub const ICON: f32 = 16.0;
    pub const HAIRLINE: f32 = 1.0;

    /// The accent bar down the left of a selected navigation row.
    pub const NAV_MARK_W: f32 = 3.0;

    pub const DASH: f32 = 5.0;
    pub const DASH_GAP: f32 = 4.0;

    /// Spacing scale.
    pub const S1: f32 = 4.0;
    pub const S2: f32 = 8.0;
    pub const S3: f32 = 12.0;
    pub const S4: f32 = 16.0;
}

/// The type scale. Four ranks plus the figure size, and never a fifth.
pub mod text {
    pub const HEADING: f32 = 13.0;
    pub const BODY: f32 = 12.0;
    pub const CONTROL: f32 = 11.5;
    pub const SMALL: f32 = 11.0;
    /// Figures, the status bar, chips. Monospaced and tabular wherever it is a
    /// number that lines up under another number.
    pub const TINY: f32 = 10.5;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Dark,
    Light,
}

/// Every colour the interface may draw with.
///
/// A component never names a colour that is not here; `CLAUDE.md` and the style
/// guide both make that the rule, and the reason is that a hex in a widget is a
/// colour the theme cannot move.
#[derive(Clone, Copy, Debug)]
pub struct Palette {
    pub backdrop: Color32,
    pub window: Color32,
    pub dock: Color32,
    pub chrome: Color32,
    pub popover: Color32,

    pub line_soft: Color32,
    pub line: Color32,
    pub line_popover: Color32,
    pub line_dashed: Color32,

    pub control: Color32,
    pub control_hover: Color32,
    /// The one accent-tinted neutral in the family, and it must stay the only
    /// one: selection is a neutral fill plus strong text plus a small accent
    /// mark, never an accent background.
    pub control_active: Color32,
    pub field: Color32,

    pub text_strong: Color32,
    pub text: Color32,
    pub text_muted: Color32,
    pub text_dim: Color32,
    pub placeholder: Color32,

    pub accent: Color32,
    pub accent_dim: Color32,
    /// Text drawn **on** the accent, and the only place that is allowed: the
    /// one primary button in a view. §2.4's list of where the accent may go is
    /// short and a fill behind body copy is not on it.
    pub accent_ink: Color32,

    /// State, never decoration.
    pub caution: Color32,
    pub good: Color32,
    pub critical: Color32,
}

impl Palette {
    pub fn of(mode: Mode) -> Self {
        match mode {
            Mode::Dark => Self::dark(),
            Mode::Light => Self::light(),
        }
    }

    /// Graphite. Cool grey, hue 264, chroma at most 0.008.
    pub fn dark() -> Self {
        Self {
            backdrop: oklch(0.164, 0.005, 264.0),
            window: oklch(0.182, 0.004, 264.0),
            dock: oklch(0.195, 0.004, 264.0),
            chrome: oklch(0.209, 0.004, 264.0),
            popover: oklch(0.227, 0.006, 271.0),

            line_soft: oklch(0.243, 0.006, 258.0),
            line: oklch(0.276, 0.006, 258.0),
            line_popover: oklch(0.301, 0.008, 264.0),
            line_dashed: oklch(0.359, 0.010, 261.0),

            control: oklch(0.244, 0.006, 271.0),
            control_hover: oklch(0.276, 0.006, 258.0),
            control_active: oklch(0.29, 0.012, ACCENT_H),
            field: oklch(0.195, 0.004, 264.0),

            text_strong: oklch(0.928, 0.003, 265.0),
            text: oklch(0.841, 0.005, 258.0),
            text_muted: oklch(0.695, 0.008, 261.0),
            text_dim: oklch(0.622, 0.008, 261.0),
            placeholder: oklch(0.481, 0.009, 261.0),

            accent: oklch(0.674, 0.101, ACCENT_H),
            accent_dim: oklch(0.447, 0.061, ACCENT_H),
            // `window` in the dark theme, per §2.3: near-black on a light
            // accent, rather than a black that belongs to no theme.
            accent_ink: oklch(0.182, 0.004, 264.0),

            caution: oklch(0.693, 0.096, 38.0),
            good: oklch(0.70, 0.10, 145.0),
            critical: oklch(0.66, 0.13, 22.0),
        }
    }

    /// Paper. Warm greys, hue 82, the same ladder and the same ranks.
    pub fn light() -> Self {
        Self {
            backdrop: oklch(0.908, 0.010, 82.0),
            window: oklch(0.944, 0.007, 81.0),
            dock: oklch(0.953, 0.007, 81.0),
            chrome: oklch(0.971, 0.006, 85.0),
            popover: Color32::WHITE,

            line_soft: oklch(0.915, 0.008, 82.0),
            line: oklch(0.890, 0.010, 82.0),
            line_popover: oklch(0.890, 0.010, 82.0),
            line_dashed: oklch(0.80, 0.012, 82.0),

            control: oklch(0.929, 0.009, 85.0),
            control_hover: oklch(0.896, 0.010, 82.0),
            control_active: oklch(0.909, 0.020, ACCENT_H),
            field: Color32::WHITE,

            text_strong: oklch(0.342, 0.004, 68.0),
            text: oklch(0.342, 0.004, 68.0),
            text_muted: oklch(0.526, 0.007, 75.0),
            text_dim: oklch(0.634, 0.008, 81.0),
            placeholder: oklch(0.72, 0.008, 81.0),

            // The accent is darkened for a light ground so it still reads
            // against it; the hue and the recipe are the same.
            accent: oklch(0.55, 0.11, ACCENT_H),
            accent_dim: oklch(0.70, 0.06, ACCENT_H),
            accent_ink: Color32::WHITE,

            caution: oklch(0.55, 0.11, 38.0),
            good: oklch(0.55, 0.11, 145.0),
            critical: oklch(0.52, 0.15, 22.0),
        }
    }
}

/// OKLCH to sRGB.
///
/// `L` is 0..1, `C` is chroma, `h` is degrees. The matrices are the standard
/// ones from Björn Ottosson's definition; the only thing worth watching is the
/// clamp at the end, which is what happens to a colour outside the sRGB gamut —
/// and every colour in the table above is inside it, so the clamp never fires
/// for the family's own tokens.
pub fn oklch(l: f32, c: f32, h_deg: f32) -> Color32 {
    let h = h_deg.to_radians();
    let (a, b) = (c * h.cos(), c * h.sin());

    let l_ = l + 0.396_337_78 * a + 0.215_803_76 * b;
    let m_ = l - 0.105_561_346 * a - 0.063_854_17 * b;
    let s_ = l - 0.089_484_18 * a - 1.291_485_5 * b;

    let (lc, mc, sc) = (l_ * l_ * l_, m_ * m_ * m_, s_ * s_ * s_);

    let r = 4.076_741_7 * lc - 3.307_711_6 * mc + 0.230_969_94 * sc;
    let g = -1.268_438 * lc + 2.609_757_4 * mc - 0.341_319_38 * sc;
    let bl = -0.004_196_086_3 * lc - 0.703_418_6 * mc + 1.707_614_7 * sc;

    Color32::from_rgb(to_srgb(r), to_srgb(g), to_srgb(bl))
}

/// Linear light to an sRGB byte, with the standard transfer curve.
fn to_srgb(v: f32) -> u8 {
    let v = v.clamp(0.0, 1.0);
    let encoded = if v <= 0.003_130_8 {
        12.92 * v
    } else {
        1.055 * v.powf(1.0 / 2.4) - 0.055
    };
    (encoded * 255.0).round().clamp(0.0, 255.0) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    fn near(got: Color32, want: (u8, u8, u8), tolerance: i32, what: &str) {
        let (r, g, b) = (got.r() as i32, got.g() as i32, got.b() as i32);
        let (wr, wg, wb) = (want.0 as i32, want.1 as i32, want.2 as i32);
        let off = (r - wr).abs().max((g - wg).abs()).max((b - wb).abs());
        assert!(
            off <= tolerance,
            "{what}: got #{r:02X}{g:02X}{b:02X}, wanted #{wr:02X}{wg:02X}{wb:02X} (off by {off})"
        );
    }

    /// `tokens.css` records the sRGB value of each neutral in a comment beside
    /// its OKLCH recipe. Those comments are the check on this conversion: if
    /// the maths here is wrong, Muster's greys are quietly a different family's
    /// greys and nothing else would ever say so.
    #[test]
    fn the_dark_ladder_matches_the_hexes_tokens_css_records() {
        let p = Palette::dark();
        near(p.backdrop, (0x0D, 0x0E, 0x10), 2, "--backdrop");
        near(p.window, (0x11, 0x12, 0x14), 2, "--window");
        near(p.dock, (0x14, 0x15, 0x17), 2, "--dock");
        near(p.chrome, (0x17, 0x18, 0x1A), 2, "--chrome");
        near(p.popover, (0x1B, 0x1C, 0x1F), 2, "--popover");
        near(p.line, (0x26, 0x28, 0x2B), 2, "--line");
        near(p.line_popover, (0x2C, 0x2E, 0x32), 2, "--line-popover");
        near(p.line_dashed, (0x3A, 0x3D, 0x42), 2, "--line-dashed");
        near(p.control, (0x1F, 0x20, 0x23), 2, "--control");
        near(p.text_strong, (0xE6, 0xE7, 0xE9), 2, "--text-strong");
        near(p.text, (0xC9, 0xCB, 0xCE), 2, "--text");
        near(p.text_muted, (0x9A, 0x9D, 0xA2), 2, "--text-muted");
        near(p.text_dim, (0x84, 0x87, 0x8C), 2, "--text-dim");
        near(p.placeholder, (0x5B, 0x5E, 0x63), 2, "--placeholder");
    }

    #[test]
    fn the_light_ladder_matches_too() {
        let p = Palette::light();
        near(p.backdrop, (0xE4, 0xE0, 0xD9), 2, "--backdrop");
        near(p.line, (0xDE, 0xDA, 0xD3), 2, "--line");
        near(p.control, (0xEA, 0xE7, 0xE1), 2, "--control");
        near(p.text_strong, (0x3A, 0x38, 0x36), 2, "--text-strong");
        near(p.text_muted, (0x6D, 0x6A, 0x66), 2, "--text-muted");
    }

    /// The recipe is the thing, not the value: at Umber's hue the same formula
    /// must give Umber's ochre. That is what proves the accent is derived
    /// rather than transcribed, and that Muster could not have quietly picked a
    /// colour of its own.
    #[test]
    fn the_accent_recipe_reproduces_umbers_ochre_at_umbers_hue() {
        near(
            oklch(0.674, 0.101, 68.0),
            (0xC0, 0x8A, 0x4E),
            3,
            "Umber accent",
        );
        near(
            oklch(0.447, 0.061, 68.0),
            (0x6B, 0x4E, 0x2E),
            3,
            "Umber accent-dim",
        );
    }

    /// And Muster's own is a cyan: blue and green high, red low.
    #[test]
    fn musters_accent_is_a_signal_cyan() {
        let a = Palette::dark().accent;
        assert!(a.b() > a.r() && a.g() > a.r(), "not cyan: {a:?}");
        assert!(a.r() < 120, "too warm to be cyan: {a:?}");
    }

    /// Every app in the family shares these numbers, so a change here is a
    /// change to the house style. Pinning them is what makes that deliberate.
    #[test]
    fn the_size_table_is_the_familys() {
        assert_eq!(metrics::MENU_BAR, 34.0);
        assert_eq!(metrics::STATUS_BAR, 26.0);
        assert_eq!(metrics::SIDEBAR, 240.0);
        assert_eq!(metrics::PANEL, 264.0);
        assert_eq!(metrics::RADIUS, 5.0);
        assert_eq!(metrics::RADIUS_CARD, 8.0);
        assert_eq!(metrics::MARK, 15.0);
        assert_eq!(text::HEADING, 13.0);
        assert_eq!(text::TINY, 10.5);
    }

    /// A colour outside the gamut is clamped rather than wrapping into a
    /// different hue, which is the failure that would be hardest to see: a
    /// wrapped channel turns a too-saturated cyan into an orange, and nothing
    /// downstream would question it.
    #[test]
    fn an_out_of_gamut_colour_clamps_instead_of_wrapping() {
        // Chroma 0.4 at this lightness is well outside sRGB.
        let wild = oklch(0.9, 0.4, 200.0);
        assert!(
            wild.b() > wild.r() && wild.g() > wild.r(),
            "clamping turned a cyan into something else: {wild:?}"
        );
        // Clamping means at least one channel has hit a rail.
        assert!(
            [wild.r(), wild.g(), wild.b()]
                .iter()
                .any(|&c| c == 0 || c == 255),
            "expected a channel at the gamut boundary: {wild:?}"
        );

        let black = oklch(0.0, 0.0, 0.0);
        assert_eq!((black.r(), black.g(), black.b()), (0, 0, 0));
        let white = oklch(1.0, 0.0, 0.0);
        assert_eq!((white.r(), white.g(), white.b()), (255, 255, 255));
    }
}
