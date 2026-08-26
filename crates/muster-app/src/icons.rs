//! The chrome's icons, drawn rather than typed.
//!
//! Umber's `icons.rs` in miniature, and it is here for that module's reason: a
//! symbol like a gear is carried by no face this application bundles, so a
//! Unicode glyph is a blank box on one machine and a differently weighted
//! stranger on the next. Drawn from primitives, the set shares the stroke
//! weight of everything else on screen and looks the same on both platforms.
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

use egui::{Color32, Painter, Pos2, Rect, Shape, Stroke, Vec2, vec2};

/// The side of the box every icon below is drawn against.
const BOX: f32 = 24.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Icon {
    /// A monitor with a phone beside it: the things on the network, which is
    /// the list this row opens. Two rectangles of different proportions rather
    /// than one, because a single screen reads as "this computer" — the one
    /// device the list is least about.
    Devices,
    /// A node above two others, joined: the shape of a link, not a globe. A
    /// globe would say the internet, and this view is emphatically about the
    /// network on this side of the gateway.
    Network,
    /// Six teeth, which reads as a gear at 16 px where eight reads as a blur.
    Gear,
    /// A disc with an i in it.
    Info,
    /// Two rails with a knob on each: the pane of general settings.
    Sliders,
    /// Rings with a sweep across them. A magnifier would have done, but it is
    /// the mark for zoom everywhere else in the family.
    Radar,
    /// A disc filled down one side: the light and dark of a theme.
    Contrast,
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
    let at = |x: f32, y: f32| origin + vec2(x * scale, y * scale);
    let stroke = Stroke::new((2.0 * scale).max(1.0), colour);
    let line = |a: Pos2, b: Pos2| painter.line_segment([a, b], stroke);
    let path = |pts: Vec<Pos2>| {
        painter.add(Shape::line(pts, stroke));
    };
    let boxed = |x0: f32, y0: f32, x1: f32, y1: f32| {
        path(vec![
            at(x0, y0),
            at(x1, y0),
            at(x1, y1),
            at(x0, y1),
            at(x0, y0),
        ]);
    };

    match icon {
        Icon::Devices => {
            // The screen, its stand, and the phone at the right.
            boxed(2.5, 5.0, 14.5, 13.5);
            line(at(8.5, 13.5), at(8.5, 16.5));
            line(at(5.5, 16.5), at(11.5, 16.5));
            boxed(16.5, 9.0, 21.5, 19.5);
        }

        Icon::Network => {
            painter.circle_stroke(at(12.0, 4.6), 2.4 * scale, stroke);
            line(at(12.0, 7.0), at(12.0, 10.6));
            line(at(5.0, 10.6), at(19.0, 10.6));
            line(at(5.0, 10.6), at(5.0, 14.6));
            line(at(19.0, 10.6), at(19.0, 14.6));
            painter.circle_stroke(at(5.0, 17.0), 2.4 * scale, stroke);
            painter.circle_stroke(at(19.0, 17.0), 2.4 * scale, stroke);
        }

        Icon::Gear => {
            // The ring is small and the teeth carry the reading, so both are
            // sized against the discs beside them in the rail rather than
            // against the box: a gear drawn to the same radius as the info
            // circle reads as the larger mark of the two.
            const HUB: f32 = 5.0;
            const TIP: f32 = 8.8;
            painter.circle_stroke(at(12.0, 12.0), HUB * scale, stroke);
            for k in 0..6 {
                let a = std::f32::consts::TAU * k as f32 / 6.0;
                let (sin, cos) = a.sin_cos();
                line(
                    at(12.0 + cos * HUB, 12.0 + sin * HUB),
                    at(12.0 + cos * TIP, 12.0 + sin * TIP),
                );
            }
        }

        Icon::Info => {
            painter.circle_stroke(at(12.0, 12.0), 8.6 * scale, stroke);
            painter.circle_filled(at(12.0, 7.8), 1.15 * scale, colour);
            line(at(12.0, 10.9), at(12.0, 16.6));
        }

        Icon::Sliders => {
            line(at(4.0, 9.0), at(20.0, 9.0));
            painter.circle_filled(at(9.0, 9.0), 2.3 * scale, colour);
            line(at(4.0, 15.0), at(20.0, 15.0));
            painter.circle_filled(at(15.0, 15.0), 2.3 * scale, colour);
        }

        Icon::Radar => {
            painter.circle_stroke(at(12.0, 12.0), 8.6 * scale, stroke);
            painter.circle_stroke(at(12.0, 12.0), 4.2 * scale, stroke);
            line(at(12.0, 12.0), at(18.1, 5.9));
        }

        Icon::Contrast => {
            const R: f32 = 8.6;
            painter.circle_stroke(at(12.0, 12.0), R * scale, stroke);
            // The right half, filled: an arc from the top round to the bottom,
            // and the diameter closes it.
            let mut half = Vec::with_capacity(19);
            for k in 0..=16 {
                let a = -std::f32::consts::FRAC_PI_2 + std::f32::consts::PI * k as f32 / 16.0;
                let (sin, cos) = a.sin_cos();
                half.push(at(12.0 + cos * R, 12.0 + sin * R));
            }
            painter.add(Shape::convex_polygon(half, colour, Stroke::NONE));
        }
    }
}
