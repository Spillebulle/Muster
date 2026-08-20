//! The mark, drawn rather than stored.
//!
//! The family's identity is one shape in one colour: a rounded square, radius
//! 30 % of its side, filled with the app's accent and carrying **no glyph**.
//! `../Design-Principles/STYLE-GUIDE.md` §17.4 is explicit that the accent *is*
//! the identity and the wordmark carries the name, which is what makes a dock
//! full of these readable at a glance.
//!
//! So the mark is a function of [`crate::theme::Palette`] and not a picture
//! somebody drew. That matters twice over:
//!
//! * The window icon is rasterised here at startup, so it cannot drift from the
//!   accent the interface is painted with. There is no PNG to forget to update
//!   when a hue moves.
//! * `examples/make-art.rs` writes `assets/icons/` and the README banners from
//!   this same code, so the committed files are a render of the token table
//!   rather than a second opinion about it.
//!
//! The font and the PNG encoder live in that example rather than here, as
//! development dependencies: the wordmark is only ever drawn into a file, and a
//! variable-font rasteriser compiled into the shipped binary to draw a picture
//! nobody sees at run time would be a quarter of a megabyte of dead weight.

use crate::theme::Palette;
use egui::Color32;

/// A straight RGBA8 buffer, top-left origin, no stride.
///
/// Small enough to be worth having rather than reaching for an image crate: the
/// largest thing drawn through it is a 1354 x 461 banner, and the only
/// operations are "fill" and "blend one pixel".
pub struct Image {
    pub width: u32,
    pub height: u32,
    /// `width * height * 4` bytes, RGBA, **not** premultiplied.
    pub pixels: Vec<u8>,
}

impl Image {
    /// A transparent image.
    pub fn new(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            pixels: vec![0; (width as usize) * (height as usize) * 4],
        }
    }

    /// An image filled with one opaque colour.
    pub fn filled(width: u32, height: u32, colour: Color32) -> Self {
        let mut image = Self::new(width, height);
        for px in image.pixels.chunks_exact_mut(4) {
            px.copy_from_slice(&[colour.r(), colour.g(), colour.b(), 255]);
        }
        image
    }

    /// Blends `colour` over the pixel at `(x, y)` with `coverage` in 0..=1.
    ///
    /// Source-over on straight (non-premultiplied) alpha, which is the awkward
    /// case: the destination's colour has to be weighted by its own alpha
    /// before the two are mixed, or drawing onto a transparent ground darkens
    /// the edge towards black. The icons are drawn onto exactly that, so the
    /// wrong version of this is visible as a grey fringe at 16 px.
    pub fn blend(&mut self, x: i32, y: i32, colour: Color32, coverage: f32) {
        if coverage <= 0.0 || x < 0 || y < 0 || x >= self.width as i32 || y >= self.height as i32 {
            return;
        }
        let alpha = coverage.clamp(0.0, 1.0) * (colour.a() as f32 / 255.0);
        if alpha <= 0.0 {
            return;
        }
        let i = ((y as usize) * (self.width as usize) + x as usize) * 4;
        let dst_a = self.pixels[i + 3] as f32 / 255.0;
        let out_a = alpha + dst_a * (1.0 - alpha);
        let src = [colour.r(), colour.g(), colour.b()];
        for (channel, s) in self.pixels[i..i + 3].iter_mut().zip(src) {
            let s = s as f32 / 255.0;
            let d = *channel as f32 / 255.0;
            let out = (s * alpha + d * dst_a * (1.0 - alpha)) / out_a;
            *channel = (out * 255.0).round().clamp(0.0, 255.0) as u8;
        }
        self.pixels[i + 3] = (out_a * 255.0).round().clamp(0.0, 255.0) as u8;
    }
}

/// How round the mark is: 30 % of its side, per §17.4.
const RADIUS_FRACTION: f32 = 0.30;

/// Samples per axis when working out how much of a pixel the shape covers.
///
/// Four means sixteen samples a pixel, which is enough that the curve reads as
/// smooth at 16 px, the size where a coarse edge is most obvious. An analytic
/// coverage would be exact and is not worth the arithmetic for a shape drawn
/// six times at build time and once at startup.
const SAMPLES: i32 = 4;

/// Draws the mark: a rounded square of `side` pixels with its top-left at
/// `(x, y)`, filled with `colour`.
pub fn rounded_square(image: &mut Image, x: f32, y: f32, side: f32, colour: Color32) {
    let radius = side * RADIUS_FRACTION;
    let x0 = x.floor() as i32;
    let y0 = y.floor() as i32;
    let x1 = (x + side).ceil() as i32;
    let y1 = (y + side).ceil() as i32;

    for py in y0..y1 {
        for px in x0..x1 {
            let mut hits = 0;
            for sy in 0..SAMPLES {
                for sx in 0..SAMPLES {
                    let fx = px as f32 + (sx as f32 + 0.5) / SAMPLES as f32;
                    let fy = py as f32 + (sy as f32 + 0.5) / SAMPLES as f32;
                    if inside(fx - x, fy - y, side, radius) {
                        hits += 1;
                    }
                }
            }
            if hits > 0 {
                let coverage = hits as f32 / (SAMPLES * SAMPLES) as f32;
                image.blend(px, py, colour, coverage);
            }
        }
    }
}

/// Is `(x, y)`, relative to the square's own top-left, inside it?
///
/// The four corners are quarter-circles of `radius`; everywhere else is the
/// square. Written as "fold the point into the nearest corner" rather than as
/// four cases, which is the same test and one branch.
fn inside(x: f32, y: f32, side: f32, radius: f32) -> bool {
    if x < 0.0 || y < 0.0 || x > side || y > side {
        return false;
    }
    let dx = (radius - x).max(x - (side - radius)).max(0.0);
    let dy = (radius - y).max(y - (side - radius)).max(0.0);
    dx * dx + dy * dy <= radius * radius
}

// ---------------------------------------------------------------------------
// The glyph
// ---------------------------------------------------------------------------

/// Where the full glyph gives way to the compact one.
///
/// The arms are the first thing to go. At 32 px an arm is two pixels wide with
/// a pixel of accent either side of it, which is not a line joining two things,
/// it is a smudge between them.
const COMPACT_BELOW: u32 = 40;

/// Where the glyph is dropped altogether and the mark is the bare square.
///
/// **This is the honest limit, not a shortcut.** Below it there are not enough
/// pixels to draw four separate discs with gaps between them: at 16 px the hub
/// would be under two pixels across and the gaps under one, and the result is a
/// dark blob in a cyan square, which says less than the square alone does. So
/// the 16 px icon and the 15 px mark in the top bar carry no glyph. That is
/// what optical sizing means, and every icon set that survives a taskbar does
/// it; drawing the same geometry at every size and calling it consistent is how
/// an icon ends up illegible exactly where it is seen most.
const PLAIN_BELOW: u32 = 24;

/// The satellites' distance from the centre, as a fraction of the side.
const ORBIT: f32 = 0.275;

/// Draws the network glyph into a mark of `side` pixels, in `ink`.
///
/// A hub with three satellites joined to it: devices on a network, which is the
/// most direct thing this application does. Three rather than four because
/// three is the fewest that reads as a network rather than as a pair, and it
/// leaves the most air between them at the sizes where air is scarce.
fn glyph(image: &mut Image, side: u32, ink: Color32) {
    if side < PLAIN_BELOW {
        return;
    }
    let compact = side < COMPACT_BELOW;

    let s = side as f32;
    let c = s / 2.0;
    // The compact form is heavier everywhere and drops the arms: fewer, fatter
    // shapes are what survive when a pixel is a large fraction of the drawing.
    // The compact form's numbers are not the full form's scaled up. They are
    // chosen so that the gap between the hub and a satellite is about 0.06 of
    // the side: the first attempt kept the orbit near the full form's and made
    // the discs fatter, which left a **0.6 px** gap at 32 px, so the four
    // shapes fused into the blob the arms were removed to avoid. Discs that
    // touch are one disc.
    let hub = s * if compact { 0.135 } else { 0.115 };
    let node = s * if compact { 0.105 } else { 0.090 };
    let arm = s * if compact { 0.0 } else { 0.062 };
    let orbit = s * if compact { 0.300 } else { ORBIT };

    // Twelve, four and eight o'clock.
    let satellites: [(f32, f32); 3] = std::array::from_fn(|k| {
        let a = -std::f32::consts::FRAC_PI_2 + k as f32 * std::f32::consts::TAU / 3.0;
        (orbit * a.cos(), orbit * a.sin())
    });

    // **Optically centred, not geometrically centred.** A three-pointed group
    // with one satellite up and two down is taller above the hub than below it:
    // the top one reaches `orbit + node`, while the lower pair sit at
    // `orbit·sin(30°)`, which is half as far. Drawing it about the true centre
    // therefore leaves it sitting high in the square, which is what it looked
    // like. Half that difference is `orbit / 4`, and shifting down by it puts
    // the *ink* in the middle rather than the coordinate system.
    let drop = orbit / 4.0;

    for py in 0..side as i32 {
        for px in 0..side as i32 {
            let mut hits = 0;
            for sy in 0..SAMPLES {
                for sx in 0..SAMPLES {
                    let x = px as f32 + (sx as f32 + 0.5) / SAMPLES as f32 - c;
                    let y = py as f32 + (sy as f32 + 0.5) / SAMPLES as f32 - c - drop;
                    if in_glyph(x, y, hub, node, arm, &satellites) {
                        hits += 1;
                    }
                }
            }
            if hits > 0 {
                image.blend(px, py, ink, hits as f32 / (SAMPLES * SAMPLES) as f32);
            }
        }
    }
}

/// Is `(x, y)`, measured from the mark's centre, inside the glyph?
fn in_glyph(x: f32, y: f32, hub: f32, node: f32, arm: f32, satellites: &[(f32, f32); 3]) -> bool {
    if disc(x, y, hub) {
        return true;
    }
    satellites
        .iter()
        .any(|&(nx, ny)| disc(x - nx, y - ny, node) || (arm > 0.0 && segment(x, y, nx, ny, arm)))
}

fn disc(x: f32, y: f32, r: f32) -> bool {
    x * x + y * y <= r * r
}

/// Within `w` of the segment from the centre to `(x1, y1)`.
fn segment(x: f32, y: f32, x1: f32, y1: f32, w: f32) -> bool {
    let len2 = x1 * x1 + y1 * y1;
    let t = if len2 <= 0.0 {
        0.0
    } else {
        ((x * x1 + y * y1) / len2).clamp(0.0, 1.0)
    };
    let (ex, ey) = (x - t * x1, y - t * y1);
    ex * ex + ey * ey <= (w / 2.0) * (w / 2.0)
}

/// The mark alone, on transparent, at `side` pixels square.
///
/// This is the app icon at every size and the favicon. The glyph is knocked out
/// of the square in the ink that belongs on an accent fill, so the mark stays
/// one solid shape rather than becoming a cut-out with the background showing
/// through it.
pub fn mark(side: u32, palette: Palette) -> Image {
    let mut image = Image::new(side, side);
    rounded_square(&mut image, 0.0, 0.0, side as f32, palette.accent);
    glyph(&mut image, side, palette.accent_ink);
    image
}

/// The window icon, for the viewport builder.
///
/// Drawn at 64 px, which is the largest size a taskbar or a title bar asks for
/// on either platform; the compositor scales down from it rather than up.
pub fn window_icon() -> egui::IconData {
    const SIDE: u32 = 64;
    let image = mark(SIDE, Palette::dark());
    egui::IconData {
        rgba: image.pixels,
        width: SIDE,
        height: SIDE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alpha_at(image: &Image, x: u32, y: u32) -> u8 {
        image.pixels[((y * image.width + x) * 4 + 3) as usize]
    }

    #[test]
    fn the_mark_is_solid_in_the_middle_and_clipped_at_the_corner() {
        let image = mark(64, Palette::dark());
        assert_eq!(alpha_at(&image, 32, 32), 255, "the centre is filled");
        assert_eq!(alpha_at(&image, 0, 0), 0, "the corner is rounded away");
        assert_eq!(alpha_at(&image, 63, 0), 0);
        assert_eq!(alpha_at(&image, 0, 63), 0);
        assert_eq!(alpha_at(&image, 63, 63), 0);
        // The middle of each edge is the flat part of the square, so it is on.
        assert_eq!(alpha_at(&image, 32, 0), 255);
        assert_eq!(alpha_at(&image, 0, 32), 255);
    }

    fn rgb_at(image: &Image, x: u32, y: u32) -> [u8; 3] {
        let i = ((y * image.width + x) * 4) as usize;
        [image.pixels[i], image.pixels[i + 1], image.pixels[i + 2]]
    }

    #[test]
    fn the_mark_carries_the_accent_and_no_other_colour() {
        let p = Palette::dark();
        let image = mark(256, p);
        // Low centre, which is inside the square and clear of the glyph.
        assert_eq!(
            rgb_at(&image, 128, 230),
            [p.accent.r(), p.accent.g(), p.accent.b()],
            "the mark is the accent, not a stored hex"
        );
    }

    #[test]
    fn the_glyph_is_knocked_out_in_the_ink_for_an_accent_fill() {
        let p = Palette::dark();
        let image = mark(256, p);
        // The hub sits on the centre.
        assert_eq!(
            rgb_at(&image, 128, 128),
            [p.accent_ink.r(), p.accent_ink.g(), p.accent_ink.b()],
            "the glyph is drawn in accent_ink, never in a colour of its own"
        );
    }

    #[test]
    fn a_small_mark_drops_the_glyph_rather_than_smudging_it() {
        // Optical sizing, and the rule the thresholds exist for: below 24 px
        // there is no room to draw four discs with gaps between them, so the
        // mark is the bare square. A glyph drawn there is a dark blob that says
        // less than the square alone.
        let p = Palette::dark();
        let ink = [p.accent_ink.r(), p.accent_ink.g(), p.accent_ink.b()];
        let has_ink = |side: u32| {
            let image = mark(side, p);
            image
                .pixels
                .chunks_exact(4)
                .any(|px| px[3] > 200 && [px[0], px[1], px[2]] == ink)
        };
        assert!(!has_ink(16), "16 px must carry no glyph");
        assert!(!has_ink(PLAIN_BELOW - 1), "below the threshold, no glyph");
        assert!(has_ink(PLAIN_BELOW), "at the threshold, the glyph appears");
        assert!(has_ink(256), "and it is there at every size above");
    }

    #[test]
    fn the_compact_form_drops_the_arms_and_keeps_the_discs_apart() {
        let p = Palette::dark();
        let accent = [p.accent.r(), p.accent.g(), p.accent.b()];

        // Two thirds of the way from the centre to the satellite at twelve
        // o'clock: on the arm in the full form, and between two discs in the
        // compact one.
        let probe = |side: u32| {
            let image = mark(side, p);
            let s = side as f32;
            // Mirrors `glyph`: the compact form orbits wider, and the whole
            // group is dropped by a quarter of the orbit to sit optically
            // centred. Measuring from the square's centre instead of the
            // glyph's is what made this test fail when the drop was added.
            let (hub, node, orbit) = if side < COMPACT_BELOW {
                (0.135, 0.105, 0.300)
            } else {
                (0.115, 0.090, ORBIT)
            };
            let centre = s / 2.0 + orbit * s / 4.0;
            // The middle of the gap between the hub and the satellite, so the
            // probe lands on flat colour rather than on an antialiased edge.
            let midpoint = (hub + orbit - node) / 2.0;
            let y = (centre - midpoint * s).round() as u32;
            rgb_at(&image, side / 2, y)
        };

        assert_eq!(
            probe(32),
            accent,
            "the compact form has no arms, so this point is still the fill"
        );
        assert_ne!(
            probe(64),
            accent,
            "the full form joins the hub to its satellites"
        );
    }

    #[test]
    fn the_edge_is_antialiased_rather_than_stepped() {
        // Somewhere along a corner's arc there has to be a partly covered
        // pixel; a purely binary edge is the defect this guards.
        let image = mark(64, Palette::dark());
        let partial = image
            .pixels
            .chunks_exact(4)
            .filter(|px| px[3] > 0 && px[3] < 255)
            .count();
        assert!(partial > 20, "expected a soft edge, found {partial} pixels");
    }

    #[test]
    fn blending_onto_transparent_keeps_the_colour() {
        // The straight-alpha trap: a naive source-over leaves a dark fringe
        // where a half-covered pixel meets nothing at all.
        let mut image = Image::new(1, 1);
        let red = Color32::from_rgb(255, 0, 0);
        image.blend(0, 0, red, 0.5);
        assert_eq!(&image.pixels[0..3], &[255, 0, 0]);
        assert_eq!(image.pixels[3], 128);
    }

    /// The glyph sits in the middle of the square by eye, not by coordinate.
    ///
    /// Measured from the drawn pixels, because the whole defect was that the
    /// arithmetic was centred and the picture was not.
    #[test]
    fn the_glyph_is_optically_centred() {
        let p = Palette::dark();
        let ink = [p.accent_ink.r(), p.accent_ink.g(), p.accent_ink.b()];
        for side in [64u32, 128, 256] {
            let image = mark(side, p);
            let is_ink = |x: u32, y: u32| {
                let i = ((y * side + x) * 4) as usize;
                image.pixels[i + 3] > 200
                    && [image.pixels[i], image.pixels[i + 1], image.pixels[i + 2]] == ink
            };
            let rows: Vec<u32> = (0..side)
                .filter(|y| (0..side).any(|x| is_ink(x, *y)))
                .collect();
            let top = *rows.first().expect("the glyph is drawn");
            let bottom = side - 1 - *rows.last().expect("the glyph is drawn");
            let slack = top.abs_diff(bottom);
            assert!(
                slack <= side / 32 + 1,
                "at {side} px the glyph sits {top} from the top and {bottom} from the bottom, which reads as off-centre"
            );
        }
    }

    #[test]
    fn the_window_icon_is_the_mark() {
        let icon = window_icon();
        assert_eq!(icon.width, 64);
        assert_eq!(icon.rgba.len(), 64 * 64 * 4);
    }
}
