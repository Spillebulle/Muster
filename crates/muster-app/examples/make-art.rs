//! Writes `assets/icons/` and the README's banners.
//!
//! ```sh
//! cargo run -p muster-app --example make-art
//! ```
//!
//! Run by hand, and the files it writes are committed. Nothing in `cargo test`
//! calls it, because it writes into the working tree.
//!
//! **Nothing here invents a colour or a shape.** The mark comes out of
//! [`muster_app::art`], which draws it from [`muster_app::theme::Palette`], and
//! the grounds are that same palette's `backdrop` in each theme. What this file
//! adds is the wordmark and the file formats, and it adds them here rather than
//! in the library so that `skrifa` and `png` stay development dependencies: the
//! shipped binary draws the mark at startup for its window icon and never needs
//! either.
//!
//! Two things about the wordmark are worth knowing before changing it.
//!
//! * **The weight really is 900.** Archivo is a variable font, and `ab_glyph` —
//!   what egui rasterises with — does not apply variation axes, so asking it for
//!   a bold gets the Regular master back without complaint. `skrifa` applies
//!   them, which is why it is here for one string. This is the same reason
//!   Umber's splash carries it.
//! * **The wordmark is sized by its cap height, not by the em.** §17.4 puts
//!   the mark beside the wordmark, and the two read as one object only if the
//!   letters are set against the square's own measure. Setting the point size
//!   and hoping gets it wrong by the font's ascender, which is about a third of
//!   the height too much. The mark then takes [`MARK_PER_CAP`] of that cap and
//!   the two are centred on one line.

use ab_glyph_rasterizer::{Point, Rasterizer, point};
use muster_app::art::{Image, mark};
use muster_app::theme::Palette;
use skrifa::instance::{Location, Size};
use skrifa::outline::{DrawSettings, OutlinePen};
use skrifa::{FontRef, MetadataProvider};
use std::fs::{self, File};
use std::io::BufWriter;
use std::path::Path;

/// Archivo, the family's typeface, under the SIL Open Font License.
///
/// The same file the interface loads, included from the same place, so a font
/// update cannot leave the banner drawn in the old one.
const ARCHIVO: &[u8] = include_bytes!("../assets/Archivo.ttf");

/// The name, uppercase. §17.4: the wordmark carries the name and the mark
/// carries no glyph.
const WORDMARK: &str = "MUSTER";

/// The banner's size, Umber's, so every repository in the family shows the same
/// shape at the same width.
const BANNER: (u32, u32) = (1354, 461);

/// GitHub's social preview. §17.2 wants the banner on the dark ground here,
/// mark and wordmark centred, and nothing else in it.
const SOCIAL: (u32, u32) = (1280, 640);

/// The icon sizes §17.4 lists, which are also the sizes the `.ico` carries.
const ICON_SIZES: [u32; 6] = [16, 32, 48, 64, 128, 256];

/// The banner across the top of the installer's progress page.
///
/// 493x58 is WiX's figure for `WixUIBannerBmp`: the control is 370x44 dialog
/// units and MSI's units come out at four thirds of a pixel here.
const INSTALLER_BANNER: (u32, u32) = (493, 58);

/// The field behind the welcome and exit pages, `WixUIDialogBmp`. 370x234
/// dialog units by the same conversion.
const INSTALLER_DIALOG: (u32, u32) = (493, 312);

/// Where the installer's banner stops being light.
///
/// The banner belongs to `ProgressDlg`, whose transparent title is a control
/// 330 dialog units wide starting at 20 — nearly the whole strip. It is left
/// aligned and holds "Installing Muster", so the glyphs stop well short of a
/// third of it, and 300 is where the picture may safely go dark. A judgement
/// rather than a measurement, and the failure if a title ever did run that far
/// is text over the mark, which is ugly where the sidebar's figure below would
/// be unreadable.
const BANNER_SPLIT: u32 = 300;

/// Where the welcome and exit field stops being dark.
///
/// **This is the load-bearing number.** `WelcomeEulaDlg`, the whole of
/// `WixUI_Minimal`'s first page, draws its transparent title at dialog x 130,
/// which is 173 px, and its licence and accept box start at the same column;
/// `ExitDialog` and `FatalError` use 135, or 180 px. 168 clears the tighter of
/// the two by five pixels. Umber's was 176 first, taken off the exit dialog
/// alone, which put the first page's title three pixels into a near-black
/// ground — the one place a heading is drawn largest.
const DIALOG_SIDEBAR: u32 = 168;

/// Margin around the brand group inside the banner's dark block.
const BLOCK_MARGIN: f32 = 12.0;

/// Margin either side of the wordmark in the sidebar, which is twice the
/// banner's: the banner lays the group out across 193 px of a 58 px strip and
/// 12 px is all the air there is, where the sidebar's constraint is width alone
/// and a wordmark set edge to edge under an 88 px mark stops reading as one
/// stack.
const SIDEBAR_MARGIN: f32 = 24.0;

/// The mark's side in the sidebar, and the gap under it before the wordmark.
///
/// The banner lays the mark and the wordmark out as a row, and that row does
/// not fit a 168 px column at any size worth reading. So the sidebar stacks
/// them. It is the only second arrangement of the brand group in Muster, and it
/// is stated here, once, beside the only thing that draws it.
const SIDEBAR_MARK: f32 = 88.0;
const SIDEBAR_GAP: f32 = 22.0;

/// Tracking, in pixels, at a 64 px em. Negative: the wordmark is set tight.
const TRACKING_AT_64: f32 = -2.0;

/// The mark's side, as a multiple of the wordmark's cap height.
///
/// Not one. A square exactly as tall as the caps reads as *smaller* than them,
/// because the letters carry overshoot on their round tops and the eye measures
/// a solid block against a row of strokes. Umber's banner sets the mark a sixth
/// again over the caps and every repository in the family follows it, so the
/// number is here rather than in the two places that lay the row out.
const MARK_PER_CAP: f32 = 1.2;

/// The space between the mark and the first letter, as a fraction of the cap
/// height. Of the cap rather than of the mark, so that making the mark taller
/// moves the mark alone and not the air beside it.
const GAP_FRACTION: f32 = 0.46;

/// How much of the banner's width the mark and wordmark together may occupy.
/// The rest is the margin §17.4 calls generous.
const CONTENT_FRACTION: f32 = 0.68;

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the workspace root is two levels above this crate");

    let icons = root.join("assets/icons");
    let images = root.join("docs/images");
    fs::create_dir_all(&icons).expect("create assets/icons");
    fs::create_dir_all(&images).expect("create docs/images");

    // The icon set: the mark alone, on transparent, at every size.
    let mut sized = Vec::new();
    for side in ICON_SIZES {
        let image = mark(side, Palette::dark());
        write_png(&icons.join(format!("muster-{side}.png")), &image);
        sized.push(image);
    }
    write_ico(&icons.join("muster.ico"), &sized);

    // The banners, one per theme, and the social preview on the dark ground.
    let (w, h) = BANNER;
    write_png(&images.join("banner.png"), &banner(w, h, Palette::dark()));
    write_png(
        &images.join("banner-paper.png"),
        &banner(w, h, Palette::light()),
    );
    let (w, h) = SOCIAL;
    write_png(
        &images.join("social-preview.png"),
        &banner(w, h, Palette::dark()),
    );

    // The Windows installer's artwork. Two BMPs, because that is what WiX
    // reads, and generated from the same palette as everything else so a hue
    // change cannot leave the installer wearing the old one.
    let windows = root.join("packaging/windows");
    fs::create_dir_all(&windows).expect("create packaging/windows");
    write_bmp(&windows.join("banner.bmp"), &installer_banner());
    write_bmp(&windows.join("dialog.bmp"), &installer_dialog());

    println!("wrote {} and {}", icons.display(), images.display());
}

/// The banner: the mark beside the wordmark, centred on the theme's backdrop.
fn banner(width: u32, height: u32, palette: Palette) -> Image {
    let mut image = Image::filled(width, height, palette.backdrop);

    // §17.4 asks for the pair centred with generous margin, and the height
    // alone cannot deliver that: "MUSTER" is six wide letters, so a mark sized
    // off the height fills the frame edge to edge and the margin disappears.
    // The width is therefore the other constraint, and the smaller of the two
    // wins. Measuring at a probe size and scaling is what makes it one
    // calculation rather than a guess per banner size.
    const PROBE: f32 = 100.0;
    let probe = Font::new(PROBE).expect("Archivo is a variable font with a wght axis");
    let probe_total = PROBE * MARK_PER_CAP + PROBE * GAP_FRACTION + probe.width(WORDMARK);

    // A third of the height is the mark's share, so the height constrains the
    // mark and the width constrains the pair.
    let cap = (height as f32 * 0.34 / MARK_PER_CAP)
        .min(PROBE * (width as f32 * CONTENT_FRACTION) / probe_total)
        .round();
    let side = (cap * MARK_PER_CAP).round();
    let gap = cap * GAP_FRACTION;

    let font = Font::new(cap).expect("Archivo is a variable font with a wght axis");
    let text = font.width(WORDMARK);
    let total = side + gap + text;

    let x = ((width as f32 - total) / 2.0).round();
    let y = ((height as f32 - side) / 2.0).round();

    stamp(&mut image, x, y, side, palette);
    // The mark stands taller than the caps, so the two share a centre line
    // rather than a top edge: the cap band is centred on the same middle the
    // square is, which is the baseline one half cap below it.
    let baseline = (height as f32 / 2.0 + cap / 2.0).round();
    font.draw(WORDMARK, x + side + gap, baseline, |px, py, coverage| {
        image.blend(px, py, palette.text_strong, coverage)
    });

    image
}

/// The installer's banner: light where MSI writes, dark where the mark goes.
///
/// Two themes in one picture, and that is not indecision. MSI draws its own
/// title over the left of this strip in near-black, so that part has to be the
/// Paper ground it expects; the block on the right is the app's, and the mark
/// only reads on the Graphite backdrop it was drawn for.
fn installer_banner() -> Image {
    let (w, h) = INSTALLER_BANNER;
    let ink = Palette::dark();
    let mut image = Image::filled(w, h, Palette::light().chrome);

    // The dark block.
    for y in 0..h {
        for x in BANNER_SPLIT..w {
            image.blend(x as i32, y as i32, ink.backdrop, 1.0);
        }
    }

    // The brand group, laid out as a row at whatever scale fits the block.
    //
    // **Width is the binding constraint here, not height**, and assuming the
    // other way round is how this first came out with the last two letters over
    // the edge: the block is 193 px across and 58 tall, and a mark sized off the
    // height alone puts a wordmark six times its own width beside it. So the
    // fit is measured, the same way the README banner's is.
    let block_w = (w - BANNER_SPLIT) as f32;
    let available = block_w - BLOCK_MARGIN * 2.0;

    const PROBE: f32 = 100.0;
    let probe = Font::new(PROBE).expect("Archivo");
    let probe_total = PROBE * MARK_PER_CAP + PROBE * GAP_FRACTION + probe.width(WORDMARK);

    let cap = ((h as f32 - BLOCK_MARGIN * 2.0) / MARK_PER_CAP).min(PROBE * available / probe_total);
    let side = cap * MARK_PER_CAP;
    let gap = cap * GAP_FRACTION;
    let font = Font::new(cap).expect("Archivo");
    let total = side + gap + font.width(WORDMARK);
    let x = BANNER_SPLIT as f32 + (block_w - total) / 2.0;
    let y = (h as f32 - side) / 2.0;

    stamp(&mut image, x, y, side, ink);
    let baseline = h as f32 / 2.0 + cap / 2.0;
    font.draw(WORDMARK, x + side + gap, baseline, |px, py, coverage| {
        image.blend(px, py, ink.text_strong, coverage)
    });

    image
}

/// The welcome and exit field: a dark sidebar with the group stacked in it.
fn installer_dialog() -> Image {
    let (w, h) = INSTALLER_DIALOG;
    let ink = Palette::dark();
    let mut image = Image::filled(w, h, Palette::light().chrome);

    for y in 0..h {
        for x in 0..DIALOG_SIDEBAR {
            image.blend(x as i32, y as i32, ink.backdrop, 1.0);
        }
    }

    let column = DIALOG_SIDEBAR as f32;
    let font = Font::fitted(column - SIDEBAR_MARGIN * 2.0, WORDMARK).expect("Archivo");
    let word_h = font.cap_height();
    let group_h = SIDEBAR_MARK + SIDEBAR_GAP + word_h;
    let top = (h as f32 - group_h) / 2.0;

    stamp(
        &mut image,
        (column - SIDEBAR_MARK) / 2.0,
        top,
        SIDEBAR_MARK,
        ink,
    );

    let baseline = top + SIDEBAR_MARK + SIDEBAR_GAP + word_h;
    let x = (column - font.width(WORDMARK)) / 2.0;
    font.draw(WORDMARK, x, baseline, |px, py, coverage| {
        image.blend(px, py, ink.text_strong, coverage)
    });

    image
}

/// Stamps the mark, glyph and all, at `(x, y)`.
///
/// Through [`mark`] rather than by drawing a square here, so the banner and the
/// installer carry exactly the icon set's artwork. The first version of this
/// file drew a bare rounded square, which was right when the mark had no glyph
/// in it and became a second, plainer logo the moment it did.
fn stamp(image: &mut Image, x: f32, y: f32, side: f32, palette: Palette) {
    let m = mark(side.round() as u32, palette);
    let (ox, oy) = (x.round() as i32, y.round() as i32);
    for py in 0..m.height as i32 {
        for px in 0..m.width as i32 {
            let i = ((py as usize) * (m.width as usize) + px as usize) * 4;
            let p = &m.pixels[i..i + 4];
            let colour = egui::Color32::from_rgb(p[0], p[1], p[2]);
            image.blend(ox + px, oy + py, colour, p[3] as f32 / 255.0);
        }
    }
}

/// Archivo instanced at one size and weight.
struct Font {
    face: FontRef<'static>,
    location: Location,
    size: Size,
    tracking: f32,
}

impl Font {
    /// Instanced so that a capital letter is exactly `cap` pixels tall.
    ///
    /// Two passes: measure the cap height at a nominal size, then scale. The
    /// ratio is a property of the face at this weight, so one probe is enough.
    fn new(cap: f32) -> Option<Self> {
        let face = FontRef::new(ARCHIVO).ok()?;
        let location = face.axes().location([("wght", 900.0)]);

        const PROBE: f32 = 100.0;
        let ratio = face
            .metrics(Size::new(PROBE), &location)
            .cap_height
            .filter(|h| *h > 0.0)
            .map_or(0.72, |h| h / PROBE);
        let ppem = cap / ratio;

        Some(Self {
            face,
            location,
            size: Size::new(ppem),
            tracking: TRACKING_AT_64 * ppem / 64.0,
        })
    }

    /// The largest instance whose `text` fits `width`.
    ///
    /// Two constructions rather than a table of sizes: how wide "MUSTER" is at
    /// weight 900 is Archivo's to decide, and a number written down here would
    /// be wrong the day the font is updated.
    fn fitted(width: f32, text: &str) -> Option<Self> {
        const PROBE: f32 = 40.0;
        let probe = Self::new(PROBE)?;
        let measured = probe.width(text);
        if measured <= 0.0 {
            return Some(probe);
        }
        Self::new(PROBE * (width / measured))
    }

    fn ppem(&self) -> f32 {
        self.size.ppem().unwrap_or(0.0)
    }

    /// The cap height this instance was built around.
    fn cap_height(&self) -> f32 {
        self.face
            .metrics(self.size, &self.location)
            .cap_height
            .unwrap_or_else(|| self.ppem() * 0.72)
    }

    /// The run's total advance, in pixels.
    fn width(&self, text: &str) -> f32 {
        let metrics = self.face.glyph_metrics(self.size, &self.location);
        let charmap = self.face.charmap();
        let mut w = 0.0;
        for ch in text.chars() {
            let Some(gid) = charmap.map(ch) else { continue };
            w += metrics.advance_width(gid).unwrap_or(0.0) + self.tracking;
        }
        // The last letter's tracking is space after the run, which would push a
        // centred string left by half of it.
        (w - self.tracking).max(0.0)
    }

    /// Rasterises `text` with its left edge at `x` and its baseline at `y`,
    /// calling `plot(x, y, coverage)` for each pixel the glyphs touch.
    fn draw(&self, text: &str, x: f32, y: f32, mut plot: impl FnMut(i32, i32, f32)) {
        let metrics = self.face.glyph_metrics(self.size, &self.location);
        let charmap = self.face.charmap();
        let outlines = self.face.outline_glyphs();
        let ppem = self.ppem();

        // One rasteriser for the whole run rather than one per glyph: the
        // tracking is negative, so glyphs can overlap, and separate buffers
        // would leave a seam where they do. The box is padded by an em on every
        // side because outlines reach past the advance width.
        let pad = ppem;
        let width = (self.width(text) + pad * 2.0).ceil().max(1.0) as usize;
        let height = (ppem * 2.5).ceil().max(1.0) as usize;
        let baseline = ppem * 1.8;

        let mut raster = Rasterizer::new(width, height);
        let mut cursor = pad;
        for ch in text.chars() {
            let Some(gid) = charmap.map(ch) else { continue };
            if let Some(glyph) = outlines.get(gid) {
                let settings = DrawSettings::unhinted(self.size, &self.location);
                let mut pen = Pen::new(&mut raster, cursor, baseline);
                // A glyph that will not draw is skipped rather than aborting
                // the run: a banner missing one letter beats one missing all.
                let _ = glyph.draw(settings, &mut pen);
            }
            cursor += metrics.advance_width(gid).unwrap_or(0.0) + self.tracking;
        }

        let ox = (x - pad).round() as i32;
        let oy = (y - baseline).round() as i32;
        raster.for_each_pixel_2d(|px, py, coverage| {
            plot(ox + px as i32, oy + py as i32, coverage);
        });
    }
}

/// Feeds a glyph's outline to the rasteriser, flipping y as it goes.
///
/// Font outlines have y increasing upwards from the baseline; the rasteriser's
/// buffer has y increasing downwards from the top.
struct Pen<'a> {
    raster: &'a mut Rasterizer,
    x: f32,
    baseline: f32,
    last: Point,
    start: Point,
}

impl<'a> Pen<'a> {
    fn new(raster: &'a mut Rasterizer, x: f32, baseline: f32) -> Self {
        Self {
            raster,
            x,
            baseline,
            last: point(0.0, 0.0),
            start: point(0.0, 0.0),
        }
    }

    fn at(&self, x: f32, y: f32) -> Point {
        point(self.x + x, self.baseline - y)
    }
}

impl OutlinePen for Pen<'_> {
    fn move_to(&mut self, x: f32, y: f32) {
        self.last = self.at(x, y);
        self.start = self.last;
    }

    fn line_to(&mut self, x: f32, y: f32) {
        let to = self.at(x, y);
        self.raster.draw_line(self.last, to);
        self.last = to;
    }

    fn quad_to(&mut self, cx0: f32, cy0: f32, x: f32, y: f32) {
        let control = self.at(cx0, cy0);
        let to = self.at(x, y);
        self.raster.draw_quad(self.last, control, to);
        self.last = to;
    }

    fn curve_to(&mut self, cx0: f32, cy0: f32, cx1: f32, cy1: f32, x: f32, y: f32) {
        let c0 = self.at(cx0, cy0);
        let c1 = self.at(cx1, cy1);
        let to = self.at(x, y);
        self.raster.draw_cubic(self.last, c0, c1, to);
        self.last = to;
    }

    fn close(&mut self) {
        self.raster.draw_line(self.last, self.start);
        self.last = self.start;
    }
}

/// Writes a 24-bit BMP, which is what WiX reads for its two pictures.
///
/// Bottom-up rows and each row padded to a multiple of four bytes, both of
/// which are the format's and neither of which is optional: a top-down BMP is
/// legal and WiX renders it upside down, and an unpadded row shears the picture
/// by a pixel per scanline.
///
/// The alpha channel is dropped rather than composited, because both pictures
/// are built on an opaque fill and nothing in them is transparent by the time
/// it arrives here.
fn write_bmp(path: &Path, image: &Image) {
    let w = image.width as usize;
    let h = image.height as usize;
    let row = w * 3;
    let padded = row.div_ceil(4) * 4;
    let pixels = padded * h;

    let mut out = Vec::with_capacity(54 + pixels);
    out.extend_from_slice(b"BM");
    out.extend_from_slice(&((54 + pixels) as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved
    out.extend_from_slice(&54u32.to_le_bytes()); // offset to the pixels
    out.extend_from_slice(&40u32.to_le_bytes()); // BITMAPINFOHEADER
    out.extend_from_slice(&(image.width as i32).to_le_bytes());
    out.extend_from_slice(&(image.height as i32).to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes()); // planes
    out.extend_from_slice(&24u16.to_le_bytes()); // bits per pixel
    out.extend_from_slice(&0u32.to_le_bytes()); // BI_RGB, uncompressed
    out.extend_from_slice(&(pixels as u32).to_le_bytes());
    for _ in 0..4 {
        out.extend_from_slice(&0u32.to_le_bytes()); // resolution, palette
    }

    for y in (0..h).rev() {
        for x in 0..w {
            let i = (y * w + x) * 4;
            // BGR, which is the order the format stores.
            out.push(image.pixels[i + 2]);
            out.push(image.pixels[i + 1]);
            out.push(image.pixels[i]);
        }
        out.resize(out.len() + (padded - row), 0);
    }

    fs::write(path, out).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    println!("  {}", path.display());
}

fn write_png(path: &Path, image: &Image) {
    let file = File::create(path).unwrap_or_else(|e| panic!("create {}: {e}", path.display()));
    let mut encoder = png::Encoder::new(BufWriter::new(file), image.width, image.height);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    encoder
        .write_header()
        .and_then(|mut w| w.write_image_data(&image.pixels))
        .unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    println!("  {}", path.display());
}

/// Writes a Windows `.ico` carrying every size as a PNG.
///
/// PNG-compressed entries rather than the older BMP ones, which every Windows
/// this ships to has read since Vista and which keeps the 256 px entry from
/// being a quarter of a megabyte on its own. The container is a six-byte
/// directory header, then sixteen bytes per entry, then the images.
fn write_ico(path: &Path, images: &[Image]) {
    let encoded: Vec<Vec<u8>> = images
        .iter()
        .map(|image| {
            let mut buffer = Vec::new();
            let mut encoder = png::Encoder::new(&mut buffer, image.width, image.height);
            encoder.set_color(png::ColorType::Rgba);
            encoder.set_depth(png::BitDepth::Eight);
            encoder
                .write_header()
                .and_then(|mut w| w.write_image_data(&image.pixels))
                .expect("encode an icon");
            buffer
        })
        .collect();

    let mut out = Vec::new();
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved
    out.extend_from_slice(&1u16.to_le_bytes()); // 1 = icon
    out.extend_from_slice(&(encoded.len() as u16).to_le_bytes());

    // Offsets are absolute, so the directory has to be sized before any of it
    // is written: header plus one entry each.
    let mut offset = 6 + 16 * encoded.len() as u32;
    for (image, bytes) in images.iter().zip(&encoded) {
        // 256 is written as 0: the field is one byte and 256 does not fit.
        out.push(if image.width >= 256 {
            0
        } else {
            image.width as u8
        });
        out.push(if image.height >= 256 {
            0
        } else {
            image.height as u8
        });
        out.push(0); // palette size, 0 for truecolour
        out.push(0); // reserved
        out.extend_from_slice(&1u16.to_le_bytes()); // colour planes
        out.extend_from_slice(&32u16.to_le_bytes()); // bits per pixel
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
        offset += bytes.len() as u32;
    }
    for bytes in &encoded {
        out.extend_from_slice(bytes);
    }

    fs::write(path, out).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    println!("  {}", path.display());
}
