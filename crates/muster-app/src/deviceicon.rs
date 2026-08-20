//! An icon per device kind, drawn rather than loaded.
//!
//! ## These are colourful on purpose, and that is a departure
//!
//! §11 of `../Design-Principles/STYLE-GUIDE.md` asks for icons from one stroke
//! set, and §2.5 reserves colour for state. These are neither: they are filled,
//! rounded and a different hue per kind. The departure is deliberate and worth
//! stating, because the alternative was tried first and is worse — twelve
//! monochrome outlines in `text-muted` are twelve things you have to *read*,
//! and the whole point of an icon column in a table of forty devices is to find
//! the printer without reading anything.
//!
//! What keeps it inside the family is that no icon names a colour. Every one of
//! them is [`theme::hued`], which is the accent's own lightness and chroma with
//! the hue moved, so they all carry the same weight as the interface around
//! them and both themes come out of the same recipe. There is no palette of
//! device colours to drift.
//!
//! ## They are shapes, not a font
//!
//! Each icon is a handful of rounded rectangles and circles laid out in a unit
//! square and scaled to whatever size the caller wants, so a 16 px row and a
//! 32 px detail view draw the same picture rather than two pictures. Details
//! are knocked out in the **row's own background** rather than drawn in a second
//! colour, which is the same trick the app mark uses: it keeps every icon a
//! single flat shape and means a selected row's fill shows through the cut-outs
//! without anything having to know about selection.

use crate::theme::{Mode, hued};
use egui::{Color32, Painter, Pos2, Rect, Stroke, pos2, vec2};
use muster_net::Kind;

/// The hue for each kind.
///
/// Spread around the wheel so that neighbouring rows never carry two colours a
/// reader has to compare to tell apart, and kept clear of the semantic tokens:
/// `caution` is hue 38 and `critical` 22, so nothing here sits between 20 and
/// 40 where a device would start to look like a warning.
const fn hue(kind: Kind) -> Option<f32> {
    Some(match kind {
        Kind::Camera => 0.0,
        Kind::Television => 45.0,
        Kind::Speaker => 80.0,
        Kind::SmartHome => 130.0,
        Kind::Server => 165.0,
        // The accent itself. The router is the one device every other device on
        // the list is reached through, and it is the only one that gets the
        // application's own colour.
        Kind::Router => 200.0,
        Kind::NetworkGear => 225.0,
        Kind::Computer => 255.0,
        Kind::Printer => 285.0,
        Kind::GameConsole => 310.0,
        Kind::Phone => 340.0,
        // No hue: nothing was learned, and a colour would be a claim.
        Kind::Unknown => return None,
    })
}

/// The colour an icon of this kind is drawn in.
///
/// `Unknown` is drawn in a neutral, which is the honest answer: colour here
/// means "this is a printer", and there is nothing to say.
pub fn colour(kind: Kind, mode: Mode, neutral: Color32) -> Color32 {
    hue(kind).map_or(neutral, |h| hued(h, mode))
}

/// Draw `kind` filling `rect`, with cut-outs in `ground`.
///
/// `ground` should be whatever the icon is being drawn on top of, so the
/// details read as holes in the shape rather than as a second colour.
pub fn draw(painter: &Painter, rect: Rect, kind: Kind, ink: Color32, ground: Color32) {
    // Everything below is in a unit square, so one drawing serves every size.
    let at = |x: f32, y: f32| -> Pos2 {
        pos2(
            rect.left() + x * rect.width(),
            rect.top() + y * rect.height(),
        )
    };
    let box_of = |x: f32, y: f32, w: f32, h: f32| -> Rect {
        Rect::from_min_size(at(x, y), vec2(w * rect.width(), h * rect.height()))
    };
    let s = rect.width();
    let fill = |r: Rect, radius: f32, c: Color32| painter.rect_filled(r, radius * s, c);
    let dot = |x: f32, y: f32, r: f32, c: Color32| painter.circle_filled(at(x, y), r * s, c);

    match kind {
        // A box with two antennae. The aerials are what stop it reading as a
        // plain rectangle beside the other boxes on this list.
        Kind::Router => {
            painter.line_segment([at(0.30, 0.44), at(0.18, 0.16)], Stroke::new(0.09 * s, ink));
            painter.line_segment([at(0.70, 0.44), at(0.82, 0.16)], Stroke::new(0.09 * s, ink));
            fill(box_of(0.10, 0.44, 0.80, 0.40), 0.14, ink);
            dot(0.30, 0.64, 0.07, ground);
            dot(0.52, 0.64, 0.07, ground);
        }

        // A switch: one box, a row of ports along it.
        Kind::NetworkGear => {
            fill(box_of(0.08, 0.30, 0.84, 0.40), 0.12, ink);
            for i in 0..4 {
                fill(
                    box_of(0.17 + i as f32 * 0.18, 0.42, 0.10, 0.16),
                    0.04,
                    ground,
                );
            }
        }

        // A monitor on a stand.
        Kind::Computer => {
            fill(box_of(0.10, 0.18, 0.80, 0.52), 0.12, ink);
            fill(box_of(0.20, 0.28, 0.60, 0.32), 0.06, ground);
            fill(box_of(0.42, 0.70, 0.16, 0.12), 0.03, ink);
            fill(box_of(0.26, 0.82, 0.48, 0.10), 0.05, ink);
        }

        // Two rack units, each with its light.
        Kind::Server => {
            fill(box_of(0.12, 0.16, 0.76, 0.30), 0.10, ink);
            fill(box_of(0.12, 0.54, 0.76, 0.30), 0.10, ink);
            dot(0.26, 0.31, 0.06, ground);
            dot(0.26, 0.69, 0.06, ground);
        }

        // Paper going in at the top, a sheet coming out at the front.
        Kind::Printer => {
            fill(box_of(0.26, 0.10, 0.48, 0.22), 0.05, ink);
            fill(box_of(0.08, 0.32, 0.84, 0.36), 0.12, ink);
            fill(box_of(0.24, 0.66, 0.52, 0.26), 0.05, ink);
            fill(box_of(0.32, 0.72, 0.36, 0.14), 0.03, ground);
            dot(0.78, 0.44, 0.05, ground);
        }

        // A handset: tall, rounded, with an earpiece.
        Kind::Phone => {
            fill(box_of(0.28, 0.06, 0.44, 0.88), 0.14, ink);
            fill(box_of(0.42, 0.13, 0.16, 0.04), 0.02, ground);
            fill(box_of(0.34, 0.22, 0.32, 0.56), 0.05, ground);
        }

        // A wide screen on a foot.
        Kind::Television => {
            fill(box_of(0.06, 0.16, 0.88, 0.56), 0.12, ink);
            fill(box_of(0.15, 0.25, 0.70, 0.38), 0.06, ground);
            fill(box_of(0.30, 0.80, 0.40, 0.09), 0.04, ink);
            painter.line_segment([at(0.50, 0.72), at(0.50, 0.82)], Stroke::new(0.08 * s, ink));
        }

        // A cabinet with a woofer and a tweeter.
        Kind::Speaker => {
            fill(box_of(0.22, 0.06, 0.56, 0.88), 0.14, ink);
            dot(0.50, 0.30, 0.09, ground);
            dot(0.50, 0.64, 0.15, ground);
            dot(0.50, 0.64, 0.06, ink);
        }

        // A body and a lens, pointed slightly.
        Kind::Camera => {
            fill(box_of(0.08, 0.28, 0.62, 0.44), 0.14, ink);
            dot(0.39, 0.50, 0.13, ground);
            dot(0.39, 0.50, 0.06, ink);
            painter.add(egui::Shape::convex_polygon(
                vec![
                    at(0.70, 0.36),
                    at(0.92, 0.24),
                    at(0.92, 0.76),
                    at(0.70, 0.64),
                ],
                ink,
                Stroke::NONE,
            ));
        }

        // A gamepad: a rounded body with two grips, a stick and a button.
        Kind::GameConsole => {
            fill(box_of(0.06, 0.30, 0.88, 0.40), 0.20, ink);
            fill(box_of(0.06, 0.52, 0.24, 0.26), 0.12, ink);
            fill(box_of(0.70, 0.52, 0.24, 0.26), 0.12, ink);
            dot(0.30, 0.48, 0.08, ground);
            dot(0.68, 0.48, 0.08, ground);
        }

        // A house, because the category is the room rather than the device.
        Kind::SmartHome => {
            painter.add(egui::Shape::convex_polygon(
                vec![at(0.50, 0.08), at(0.94, 0.46), at(0.06, 0.46)],
                ink,
                Stroke::NONE,
            ));
            fill(box_of(0.18, 0.44, 0.64, 0.48), 0.10, ink);
            fill(box_of(0.40, 0.60, 0.20, 0.32), 0.04, ground);
        }

        // A ring and nothing in it. Deliberately the emptiest icon on the list:
        // it is what "nothing said anything" looks like, and it must not read as
        // a device of its own.
        Kind::Unknown => {
            painter.circle_stroke(rect.center(), 0.30 * s, Stroke::new(0.10 * s, ink));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Kind; 12] = [
        Kind::Router,
        Kind::NetworkGear,
        Kind::Computer,
        Kind::Server,
        Kind::Printer,
        Kind::Phone,
        Kind::Television,
        Kind::Speaker,
        Kind::Camera,
        Kind::GameConsole,
        Kind::SmartHome,
        Kind::Unknown,
    ];

    #[test]
    fn nothing_learned_is_drawn_in_a_neutral() {
        let neutral = Color32::from_rgb(1, 2, 3);
        assert_eq!(
            colour(Kind::Unknown, Mode::Dark, neutral),
            neutral,
            "a colour on an unknown device would be a claim about it"
        );
    }

    #[test]
    fn the_router_wears_the_accent() {
        // §2.4 lets the accent mark the one thing everything else is reached
        // through, and on this screen that is the gateway.
        assert_eq!(
            colour(Kind::Router, Mode::Dark, Color32::BLACK),
            crate::theme::Palette::dark().accent
        );
    }

    #[test]
    fn every_kind_that_claims_something_has_a_colour_of_its_own() {
        let mut seen: Vec<(Kind, Color32)> = Vec::new();
        for kind in ALL {
            if kind == Kind::Unknown {
                continue;
            }
            let c = colour(kind, Mode::Dark, Color32::BLACK);
            if let Some((other, _)) = seen.iter().find(|(_, been)| *been == c) {
                panic!("{kind:?} and {other:?} are the same colour");
            }
            seen.push((kind, c));
        }
        assert_eq!(seen.len(), ALL.len() - 1);
    }

    #[test]
    fn no_icon_sits_in_the_warning_hues() {
        // `caution` is hue 38 and `critical` 22. A device drawn between them
        // would read as a state rather than as a thing.
        for kind in ALL {
            if let Some(h) = hue(kind) {
                assert!(
                    !(20.0..=40.0).contains(&h),
                    "{kind:?} at hue {h} would look like a warning"
                );
            }
        }
    }

    #[test]
    fn both_themes_answer_for_every_kind() {
        for kind in ALL {
            for mode in [Mode::Dark, Mode::Light] {
                let c = colour(kind, mode, Color32::GRAY);
                assert!(c.a() == 255, "{kind:?} in {mode:?} must be opaque");
            }
        }
    }
}
