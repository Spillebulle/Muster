//! The chrome's icons, drawn rather than typed.
//!
//! A symbol like a gear is carried by no face this application bundles, so a
//! Unicode glyph is a blank box on one machine and a differently weighted
//! stranger on the next. Drawn from primitives, the set shares the stroke
//! weight of everything else on screen and looks the same on both platforms.
//!
//! **The shapes are Lucide's, and they were not always.** The set was drawn by
//! hand here first, and a hand-drawn icon is only as good as the hour it got:
//! the gear was a hub with six spokes coming off it at the hub's own radius,
//! which is not a gear but a sun, and it was on the one control in the
//! application everybody has to find. Lucide is the set the family already uses
//! — Tally's interface is built on `lucide-react` — so taking the geometry
//! rather than redrawing it makes the settings icon here and the settings icon
//! there the same mark. The path data is copied from the package verbatim; see
//! [`crate::lucide`], which also carries the licence and the reason the data is
//! flattened rather than rasterised.
//!
//! **This is the one stroke set §11 asks for, and it is monochrome.** The
//! filled, colourful marks in [`crate::deviceicon`] are the departure
//! `CLAUDE.md` states and argues for: those name what a device *is*, in a
//! column that exists so the printer can be found without reading. These name
//! where a click goes, beside a word that already says it.
//!
//! Icons are authored against a 24x24 box and scaled into whatever rect they
//! are given, so the 16 px instance in a navigation row and a larger one
//! elsewhere are the same shape.

use crate::lucide::{Node, Outline};
use egui::{Color32, Painter, Rect, Shape, Stroke, Vec2, pos2};
use std::sync::LazyLock;

/// The side of the box every icon below is drawn against.
const BOX: f32 = 24.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Icon {
    /// Lucide `monitor-smartphone`: a screen with a phone beside it, which is
    /// the list this row opens. Two devices rather than one, because a single
    /// screen reads as "this computer" — the one device the list is least
    /// about.
    Devices,
    /// Lucide `network`: a node above two others, joined. The shape of a link,
    /// not a globe; a globe would say the internet, and this view is
    /// emphatically about the network on this side of the gateway.
    Network,
    /// Lucide `settings`: the cog.
    Gear,
    /// Lucide `info`: a disc with an i in it.
    Info,
    /// Lucide `sliders-horizontal`: the pane of general settings.
    Sliders,
    /// Lucide `radar`. A magnifier would have done, but it is the mark for
    /// zoom everywhere else in the family.
    Radar,
    /// Lucide `contrast`: a disc dark down one side, which is the light and
    /// dark of a theme.
    Contrast,
}

impl Icon {
    /// Every icon, which is what the tests walk.
    pub const ALL: [Self; 7] = [
        Self::Devices,
        Self::Network,
        Self::Gear,
        Self::Info,
        Self::Sliders,
        Self::Radar,
        Self::Contrast,
    ];

    /// The icon's elements, copied from `lucide-react` v1.31.0 unchanged.
    ///
    /// Updating one is a paste over one line. Adding one is a paste of a new
    /// arm, and the name in the doc comment above it is the name to search
    /// lucide.dev for.
    fn nodes(self) -> &'static [Node] {
        match self {
            Self::Devices => &[
                Node::Path("M18 8V6a2 2 0 0 0-2-2H4a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h8"),
                Node::Path("M10 19v-3.96 3.15"),
                Node::Path("M7 19h5"),
                Node::Rect {
                    x: 16.0,
                    y: 12.0,
                    w: 6.0,
                    h: 10.0,
                    r: 2.0,
                },
            ],
            Self::Network => &[
                Node::Rect {
                    x: 16.0,
                    y: 16.0,
                    w: 6.0,
                    h: 6.0,
                    r: 1.0,
                },
                Node::Rect {
                    x: 2.0,
                    y: 16.0,
                    w: 6.0,
                    h: 6.0,
                    r: 1.0,
                },
                Node::Rect {
                    x: 9.0,
                    y: 2.0,
                    w: 6.0,
                    h: 6.0,
                    r: 1.0,
                },
                Node::Path("M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3"),
                Node::Path("M12 12V8"),
            ],
            Self::Gear => &[
                Node::Path(
                    "M9.671 4.136a2.34 2.34 0 0 1 4.659 0 2.34 2.34 0 0 0 3.319 1.915 2.34 2.34 0 0 1 2.33 4.033 2.34 2.34 0 0 0 0 3.831 2.34 2.34 0 0 1-2.33 4.033 2.34 2.34 0 0 0-3.319 1.915 2.34 2.34 0 0 1-4.659 0 2.34 2.34 0 0 0-3.32-1.915 2.34 2.34 0 0 1-2.33-4.033 2.34 2.34 0 0 0 0-3.831A2.34 2.34 0 0 1 6.35 6.051a2.34 2.34 0 0 0 3.319-1.915",
                ),
                Node::Circle {
                    cx: 12.0,
                    cy: 12.0,
                    r: 3.0,
                },
            ],
            Self::Info => &[
                Node::Circle {
                    cx: 12.0,
                    cy: 12.0,
                    r: 10.0,
                },
                Node::Path("M12 16v-4"),
                Node::Path("M12 8h.01"),
            ],
            Self::Sliders => &[
                Node::Path("M10 5H3"),
                Node::Path("M12 19H3"),
                Node::Path("M14 3v4"),
                Node::Path("M16 17v4"),
                Node::Path("M21 12h-9"),
                Node::Path("M21 19h-5"),
                Node::Path("M21 5h-7"),
                Node::Path("M8 10v4"),
                Node::Path("M8 12H3"),
            ],
            Self::Radar => &[
                Node::Path("M19.07 4.93A10 10 0 0 0 6.99 3.34"),
                Node::Path("M4 6h.01"),
                Node::Path("M2.29 9.62A10 10 0 1 0 21.31 8.35"),
                Node::Path("M16.24 7.76A6 6 0 1 0 8.23 16.67"),
                Node::Path("M12 18h.01"),
                Node::Path("M17.99 11.66A6 6 0 0 1 15.77 16.67"),
                Node::Circle {
                    cx: 12.0,
                    cy: 12.0,
                    r: 2.0,
                },
                Node::Path("m13.41 10.59 5.66-5.66"),
            ],
            Self::Contrast => &[
                Node::Circle {
                    cx: 12.0,
                    cy: 12.0,
                    r: 10.0,
                },
                Node::Path("M12 18a6 6 0 0 0 0-12v12z"),
            ],
        }
    }
}

/// Every icon, flattened once for the life of the process.
///
/// The parse and the arcs are cheap, but they are the same answer every frame
/// for every row of the sidebar, and an icon set is drawn some dozens of times
/// a frame. Held in the 24x24 box and scaled at the point of drawing, so one
/// copy serves every size.
static GEOMETRY: LazyLock<Vec<Vec<Outline>>> = LazyLock::new(|| {
    Icon::ALL
        .iter()
        .map(|i| crate::lucide::flatten(i.nodes()))
        .collect()
});

fn geometry(icon: Icon) -> &'static [Outline] {
    let at = Icon::ALL
        .iter()
        .position(|i| *i == icon)
        .expect("every icon is in ALL");
    &GEOMETRY[at]
}

/// Draw `icon` centred in `rect`, in `colour`.
///
/// The stroke scales with the box, so a small icon stays legible and a large
/// one does not turn spindly.
pub fn draw(painter: &Painter, rect: Rect, icon: Icon, colour: Color32) {
    let size = rect.width().min(rect.height());
    if size <= 1.0 {
        return;
    }
    let scale = size / BOX;
    let origin = rect.center() - Vec2::splat(size * 0.5);
    let width = (2.0 * scale).max(1.0);
    let stroke = Stroke::new(width, colour);

    for outline in geometry(icon) {
        let points: Vec<_> = outline
            .points
            .iter()
            .map(|p| pos2(origin.x + p.x * scale, origin.y + p.y * scale))
            .collect();
        // A dot is a stroke that goes nowhere, and egui would draw nothing at
        // all. Half the stroke's width is the radius SVG's round cap would have
        // given it.
        if outline.is_dot() {
            painter.circle_filled(points[0], width / 2.0, colour);
        } else if outline.closed {
            painter.add(Shape::closed_line(points, stroke));
        } else {
            painter.add(Shape::line(points, stroke));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every icon flattens to something, and to something the size of the box
    /// it was authored in.
    ///
    /// The parser answers a command it does not know by stopping, which would
    /// leave half an icon rather than a panic — this is what would catch it,
    /// along with a path whose numbers failed to parse and collapsed everything
    /// to the origin.
    #[test]
    fn every_icon_fills_its_box() {
        for icon in Icon::ALL {
            let outlines = crate::lucide::flatten(icon.nodes());
            assert!(!outlines.is_empty(), "{icon:?} flattened to nothing");

            let points: Vec<_> = outlines.iter().flat_map(|o| o.points.iter()).collect();
            let left = points.iter().map(|p| p.x).fold(f32::MAX, f32::min);
            let right = points.iter().map(|p| p.x).fold(f32::MIN, f32::max);
            let top = points.iter().map(|p| p.y).fold(f32::MAX, f32::min);
            let bottom = points.iter().map(|p| p.y).fold(f32::MIN, f32::max);

            assert!(
                left >= -0.5 && top >= -0.5 && right <= BOX + 0.5 && bottom <= BOX + 0.5,
                "{icon:?} runs outside the 24x24 box: {left}..{right}, {top}..{bottom}"
            );
            // Lucide leaves a unit or two of margin, so an icon that fills less
            // than half the box in either direction has lost a subpath.
            assert!(
                right - left > BOX / 2.0 || bottom - top > BOX / 2.0,
                "{icon:?} is too small to have all of its parts: {left}..{right}, {top}..{bottom}"
            );
        }
    }

    /// No icon uses a command the parser would stop at.
    ///
    /// Quadratics and the smooth forms are not implemented, and the day a
    /// pasted-in icon uses one this says so by name rather than by a shape
    /// somebody notices later.
    #[test]
    fn every_command_is_one_the_parser_knows() {
        const KNOWN: [char; 12] = ['M', 'm', 'L', 'l', 'H', 'h', 'V', 'v', 'C', 'c', 'A', 'a'];
        for icon in Icon::ALL {
            for node in icon.nodes() {
                let Node::Path(d) = node else {
                    continue;
                };
                for c in d.chars().filter(|c| c.is_ascii_alphabetic()) {
                    // `e` is an exponent rather than a command; no icon here
                    // uses one, and the check would be wrong if one did.
                    assert!(
                        KNOWN.contains(&c) || c == 'Z' || c == 'z',
                        "{icon:?} uses the SVG command {c}, which the parser does not know"
                    );
                }
            }
        }
    }
}
