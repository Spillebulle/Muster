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

/// The mark alone, on transparent, at `side` pixels square.
///
/// This is the app icon at every size and the favicon: §17.4 again, the icon
/// set is the mark and nothing else.
pub fn mark(side: u32, palette: Palette) -> Image {
    let mut image = Image::new(side, side);
    rounded_square(&mut image, 0.0, 0.0, side as f32, palette.accent);
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

    #[test]
    fn the_mark_carries_the_accent_and_no_other_colour() {
        let accent = Palette::dark().accent;
        let image = mark(32, Palette::dark());
        let i = ((16 * 32 + 16) * 4) as usize;
        assert_eq!(
            &image.pixels[i..i + 3],
            &[accent.r(), accent.g(), accent.b()],
            "the mark is the accent, not a stored hex"
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

    #[test]
    fn the_window_icon_is_the_mark() {
        let icon = window_icon();
        assert_eq!(icon.width, 64);
        assert_eq!(icon.rgba.len(), 64 * 64 * 4);
    }
}
