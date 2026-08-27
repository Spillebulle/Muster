//! Lucide's geometry, read at the size it is drawn.
//!
//! The icons in [`crate::icons`] are Lucide's, and this module is what turns
//! one of them into something egui can stroke. The data there is copied from
//! the package verbatim — the same `d` attributes, the same numbers, in the
//! same order — so an icon can be compared against lucide.dev character by
//! character and updated by pasting a new line over an old one. Nothing here
//! interprets or improves them.
//!
//! What it parses is SVG's path grammar rather than anything Lucide's own, so
//! the one mark in that set which is not Lucide's — GitHub's, from Simple
//! Icons — comes through the same door.
//!
//! ## Why the geometry rather than the file
//!
//! Muster draws its chrome rather than typing it, for the reason
//! [`crate::icons`] gives: a symbol carried by a font is a blank box on one
//! machine and a differently weighted stranger on the next. An SVG *file* has
//! the opposite problem — a rasteriser, a cache keyed on size and on theme, and
//! a megabyte of dependency to draw a 16 px cog. The path data is the part
//! worth having, and flattening it into polylines costs the parser below and
//! nothing else. The icons then take the interface's own stroke weight and its
//! ink, and they are the same shape on both platforms.
//!
//! ## Lucide's terms
//!
//! ISC, Copyright (c) Lucide Icons and Contributors, which the README credits.
//! ISC is permissive and sits inside GPL-3.0-or-later without friction; what it
//! does require is that the notice travels with the work, which is why it is
//! written here as well as there.
//!
//! ## The box
//!
//! Every Lucide icon is authored against a 24x24 box with a stroke two units
//! wide and round caps. That is the box [`crate::icons`] already drew against,
//! which is why nothing above this module had to change.

use egui::{Pos2, pos2};

/// One element of a Lucide icon, as the package writes it.
///
/// Lucide describes an icon as a list of SVG elements rather than as one path,
/// so this list is the same list: a `["path", { d }]` becomes [`Node::Path`], a
/// `["circle", …]` becomes [`Node::Circle`], a `["rect", …]` becomes
/// [`Node::Rect`]. Keeping the shape of the source is what keeps the two
/// comparable by eye.
#[derive(Clone, Copy, Debug)]
pub enum Node {
    Path(&'static str),
    Circle {
        cx: f32,
        cy: f32,
        r: f32,
    },
    Rect {
        x: f32,
        y: f32,
        w: f32,
        h: f32,
        r: f32,
    },
}

/// A run of points in the 24x24 box, ready to be scaled and stroked.
///
/// `closed` is the difference between a rectangle and a line that happens to
/// end where it began: egui joins the last point to the first for the one and
/// leaves the join open on the other, and at two units wide that shows.
#[derive(Clone, Debug)]
pub struct Outline {
    pub points: Vec<Pos2>,
    pub closed: bool,
}

impl Outline {
    /// Is this outline a single point?
    ///
    /// Lucide draws a dot as a line going nowhere — `h.01` — because SVG gives
    /// that a round cap, and a round cap on a zero-length line is a circle.
    /// egui strokes a polyline with flat ends, so it would draw nothing at all
    /// and the pip of the `i` and the middle of the radar would simply be
    /// missing. [`crate::icons`] paints these as filled circles instead.
    pub fn is_dot(&self) -> bool {
        let Some(first) = self.points.first() else {
            return false;
        };
        self.points
            .iter()
            .all(|p| (p.x - first.x).abs() < 0.05 && (p.y - first.y).abs() < 0.05)
    }
}

/// How finely a curve is sampled: one segment per fifteen degrees.
///
/// An icon is drawn between 14 and 22 px across, where a quarter circle is some
/// five pixels of travel, so six segments across it are already finer than the
/// display. Being generous costs a handful of points held once per icon for the
/// life of the process.
const ARC_STEP: f32 = std::f32::consts::PI / 12.0;

/// Segments per cubic curve. Fixed rather than adaptive, for the same reason.
const CURVE_STEPS: usize = 12;

/// Turn an icon's nodes into outlines in the 24x24 box.
pub fn flatten(nodes: &[Node]) -> Vec<Outline> {
    let mut out = Vec::new();
    for node in nodes {
        match *node {
            Node::Path(d) => path(d, &mut out),
            Node::Circle { cx, cy, r } => out.push(ellipse(cx, cy, r)),
            Node::Rect { x, y, w, h, r } => out.push(rounded_rect(x, y, w, h, r)),
        }
    }
    out
}

/// A circle as a closed polyline.
fn ellipse(cx: f32, cy: f32, r: f32) -> Outline {
    const STEPS: usize = 48;
    let points = (0..STEPS)
        .map(|k| {
            let t = std::f32::consts::TAU * k as f32 / STEPS as f32;
            pos2(cx + r * t.cos(), cy + r * t.sin())
        })
        .collect();
    Outline {
        points,
        closed: true,
    }
}

/// A rectangle with corners of radius `r`, as a closed polyline.
fn rounded_rect(x: f32, y: f32, w: f32, h: f32, r: f32) -> Outline {
    let r = r.min(w / 2.0).min(h / 2.0);
    let mut points = Vec::new();
    // The four corner centres, from the top left and clockwise, each with the
    // angle its quarter turn starts at.
    let corners = [
        (x + r, y + r, std::f32::consts::PI),
        (x + w - r, y + r, -std::f32::consts::FRAC_PI_2),
        (x + w - r, y + h - r, 0.0),
        (x + r, y + h - r, std::f32::consts::FRAC_PI_2),
    ];
    for (cx, cy, from) in corners {
        const STEPS: usize = 6;
        for k in 0..=STEPS {
            let t = from + std::f32::consts::FRAC_PI_2 * k as f32 / STEPS as f32;
            points.push(pos2(cx + r * t.cos(), cy + r * t.sin()));
        }
    }
    Outline {
        points,
        closed: true,
    }
}

/// Walk one `d` attribute, appending an outline per subpath.
///
/// The subset of SVG's path grammar Lucide uses: moves, lines in all four
/// spellings, cubic curves, elliptical arcs and closes, absolute and relative,
/// with the implicit repeat that lets `m13.41 10.59 5.66-5.66` mean a move and
/// then a line. Quadratics and the smooth forms are not implemented, because no
/// icon here uses one — and a path that did would draw a straight line where a
/// curve belongs, which is why [`crate::icons`] has a test that walks every
/// icon and fails on a command this does not know.
fn path(d: &str, out: &mut Vec<Outline>) {
    let mut lexer = Lexer::new(d);
    let mut points: Vec<Pos2> = Vec::new();
    let mut closed = false;
    let mut cursor = pos2(0.0, 0.0);
    let mut start = cursor;
    let mut command = ' ';

    loop {
        // A command letter, or a number, which repeats the last command. `M`
        // repeats as `L`, the one exception the grammar makes.
        match lexer.command() {
            Some(letter) => {
                command = letter;
                if letter.eq_ignore_ascii_case(&'M') {
                    flush(&mut points, &mut closed, out);
                }
            }
            None if lexer.at_number() => {
                command = match command {
                    'M' => 'L',
                    'm' => 'l',
                    other => other,
                };
            }
            None => break,
        }

        let relative = command.is_ascii_lowercase();
        let here = cursor;
        match command.to_ascii_uppercase() {
            'M' => {
                cursor = place(here, lexer.number(), lexer.number(), relative);
                start = cursor;
                points.push(cursor);
            }
            'L' => {
                cursor = place(here, lexer.number(), lexer.number(), relative);
                points.push(cursor);
            }
            'H' => {
                let x = lexer.number();
                cursor.x = if relative { here.x + x } else { x };
                points.push(cursor);
            }
            'V' => {
                let y = lexer.number();
                cursor.y = if relative { here.y + y } else { y };
                points.push(cursor);
            }
            'C' => {
                let one = place(here, lexer.number(), lexer.number(), relative);
                let two = place(here, lexer.number(), lexer.number(), relative);
                let to = place(here, lexer.number(), lexer.number(), relative);
                curve(here, one, two, to, &mut points);
                cursor = to;
            }
            'A' => {
                let rx = lexer.number();
                let ry = lexer.number();
                let turn = lexer.number();
                let large = lexer.number() != 0.0;
                let sweep = lexer.number() != 0.0;
                let to = place(here, lexer.number(), lexer.number(), relative);
                arc(here, Radii { rx, ry, turn }, large, sweep, to, &mut points);
                cursor = to;
            }
            'Z' => {
                closed = true;
                cursor = start;
                flush(&mut points, &mut closed, out);
            }
            // A command this parser does not know. Stopping is the honest
            // answer: half an icon is visibly wrong, where a straight line
            // through where a curve belonged is not.
            _ => break,
        }
    }
    flush(&mut points, &mut closed, out);
}

/// Finish the subpath being collected, if there is one.
///
/// **A path that ends where it began is closed whether or not it says so.**
/// Lucide's cog is one long run of arcs whose last one lands back on the first
/// point and never writes a `z`; stroked as an open line it carries two flat
/// ends meeting at an angle, which at 16 px is a nick out of the rim.
fn flush(points: &mut Vec<Pos2>, closed: &mut bool, out: &mut Vec<Outline>) {
    if !points.is_empty() {
        if !*closed && points.len() > 2 {
            let first = points[0];
            let last = points[points.len() - 1];
            if (first.x - last.x).abs() < 0.05 && (first.y - last.y).abs() < 0.05 {
                points.pop();
                *closed = true;
            }
        }
        out.push(Outline {
            points: std::mem::take(points),
            closed: *closed,
        });
    }
    *closed = false;
}

/// A coordinate pair, absolute or relative to where the pen is.
fn place(from: Pos2, x: f32, y: f32, relative: bool) -> Pos2 {
    if relative {
        pos2(from.x + x, from.y + y)
    } else {
        pos2(x, y)
    }
}

/// A cubic curve, sampled.
fn curve(from: Pos2, one: Pos2, two: Pos2, to: Pos2, out: &mut Vec<Pos2>) {
    for k in 1..=CURVE_STEPS {
        let t = k as f32 / CURVE_STEPS as f32;
        let u = 1.0 - t;
        let (a, b, c, d) = (u * u * u, 3.0 * u * u * t, 3.0 * u * t * t, t * t * t);
        out.push(pos2(
            a * from.x + b * one.x + c * two.x + d * to.x,
            a * from.y + b * one.y + c * two.y + d * to.y,
        ));
    }
}

/// An arc's two radii and the rotation of its ellipse, in degrees.
#[derive(Clone, Copy, Debug)]
struct Radii {
    rx: f32,
    ry: f32,
    turn: f32,
}

/// An elliptical arc, from SVG's endpoint parametrisation to points along it.
///
/// The conversion is the one in the specification's implementation notes
/// (F.6.5): two endpoints, two radii and two flags name exactly one centre and
/// one sweep, and it is that centre this recovers before walking the angle.
/// Lucide's arcs are all circular and unrotated, but the rotation is carried
/// through anyway, because leaving it out would be a silent wrong answer the
/// day an icon uses one.
fn arc(from: Pos2, radii: Radii, large: bool, sweep: bool, to: Pos2, out: &mut Vec<Pos2>) {
    if (from.x - to.x).abs() < f32::EPSILON && (from.y - to.y).abs() < f32::EPSILON {
        return;
    }
    // A zero radius is a straight line, which the specification says in as many
    // words.
    if radii.rx.abs() < f32::EPSILON || radii.ry.abs() < f32::EPSILON {
        out.push(to);
        return;
    }
    let (mut rx, mut ry) = (radii.rx.abs(), radii.ry.abs());
    let (sin_turn, cos_turn) = radii.turn.to_radians().sin_cos();

    let dx = (from.x - to.x) / 2.0;
    let dy = (from.y - to.y) / 2.0;
    let x1 = cos_turn * dx + sin_turn * dy;
    let y1 = -sin_turn * dx + cos_turn * dy;

    // Radii too small to reach from one end to the other are grown until they
    // just do, rather than the arc being abandoned.
    let over = (x1 * x1) / (rx * rx) + (y1 * y1) / (ry * ry);
    if over > 1.0 {
        let grow = over.sqrt();
        rx *= grow;
        ry *= grow;
    }

    let top = (rx * rx * ry * ry - rx * rx * y1 * y1 - ry * ry * x1 * x1).max(0.0);
    let bottom = rx * rx * y1 * y1 + ry * ry * x1 * x1;
    let mut coefficient = (top / bottom).sqrt();
    if large == sweep {
        coefficient = -coefficient;
    }
    let cx1 = coefficient * rx * y1 / ry;
    let cy1 = -coefficient * ry * x1 / rx;

    let cx = cos_turn * cx1 - sin_turn * cy1 + (from.x + to.x) / 2.0;
    let cy = sin_turn * cx1 + cos_turn * cy1 + (from.y + to.y) / 2.0;

    let start = ((y1 - cy1) / ry).atan2((x1 - cx1) / rx);
    let end = ((-y1 - cy1) / ry).atan2((-x1 - cx1) / rx);
    let mut span = end - start;
    if sweep && span < 0.0 {
        span += std::f32::consts::TAU;
    } else if !sweep && span > 0.0 {
        span -= std::f32::consts::TAU;
    }

    let steps = ((span.abs() / ARC_STEP).ceil() as usize).max(2);
    for k in 1..=steps {
        let t = start + span * k as f32 / steps as f32;
        let (sin_t, cos_t) = t.sin_cos();
        out.push(pos2(
            cx + rx * cos_t * cos_turn - ry * sin_t * sin_turn,
            cy + rx * cos_t * sin_turn + ry * sin_t * cos_turn,
        ));
    }
}

/// The one place a `d` attribute is taken apart.
///
/// Deliberately small, and not a split on whitespace: SVG's number grammar lets
/// a sign end one number and begin the next, which is why `5.66-5.66` is two
/// numbers and `h.01` is a command and one.
struct Lexer<'a> {
    rest: &'a str,
}

impl<'a> Lexer<'a> {
    fn new(text: &'a str) -> Self {
        Self { rest: text }
    }

    fn skip(&mut self) {
        self.rest = self.rest.trim_start_matches([' ', ',', '\t', '\n', '\r']);
    }

    /// The next command letter, if the next thing is one.
    fn command(&mut self) -> Option<char> {
        self.skip();
        let letter = self.rest.chars().next()?;
        if letter.is_ascii_alphabetic() {
            self.rest = &self.rest[letter.len_utf8()..];
            Some(letter)
        } else {
            None
        }
    }

    /// Is a number next? What tells an implicit repeat from the end of the
    /// path.
    fn at_number(&mut self) -> bool {
        self.skip();
        self.rest
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit() || c == '-' || c == '+' || c == '.')
    }

    /// The next number, or zero where there is none. A malformed path is
    /// caught by the test in [`crate::icons`] rather than by a panic in front
    /// of somebody.
    ///
    /// **A second decimal point ends the number before it**, which is the other
    /// half of the rule the sign follows: `-5.5.08` is two numbers, and the
    /// separator is the point that could not belong to the first. Read
    /// greedily it is one token, `-5.5.08` parses as nothing, and the zero that
    /// stands in for it lands a curve's control point on the origin — which is
    /// exactly what the GitHub mark used to draw, an arm flung out of the box,
    /// while every icon whose numbers happened to be spelled with a leading
    /// digit came out perfect.
    fn number(&mut self) -> f32 {
        self.skip();
        let mut end = 0;
        let mut point = false;
        let mut exponent = false;
        for (index, c) in self.rest.char_indices() {
            let leading_sign = (c == '-' || c == '+') && index == 0;
            let exponent_sign = (c == '-' || c == '+') && self.rest[..index].ends_with(['e', 'E']);
            let takes = match c {
                '0'..='9' => true,
                // An exponent has no fraction, so a point after one ends the
                // number the same way a second point does.
                '.' => !point && !exponent,
                'e' | 'E' => !exponent && index > 0,
                _ => leading_sign || exponent_sign,
            };
            if !takes {
                break;
            }
            point |= c == '.';
            exponent |= c == 'e' || c == 'E';
            end = index + c.len_utf8();
        }
        let (number, rest) = self.rest.split_at(end);
        self.rest = rest;
        number.parse().unwrap_or(0.0)
    }
}

/// Every number the scan takes out of a `d` attribute, exactly as it took it.
///
/// **The one thing [`Lexer::number`] throws away.** It answers a token it
/// cannot read with zero, which is a legal coordinate inside a legal box, so a
/// path scanned wrongly draws a wrong icon and nothing anywhere says so. This
/// hands the tokens back unparsed for [`crate::icons`] to ask the question the
/// `unwrap_or` answers away.
#[cfg(test)]
pub fn number_tokens(d: &str) -> Vec<String> {
    let mut lexer = Lexer::new(d);
    let mut out = Vec::new();
    loop {
        if lexer.command().is_some() {
            continue;
        }
        if !lexer.at_number() {
            break;
        }
        let before = lexer.rest;
        lexer.number();
        let taken = before.len() - lexer.rest.len();
        // A number the scan takes nothing for would loop for ever. It cannot
        // happen after `at_number`, and this is cheaper than trusting that.
        if taken == 0 {
            break;
        }
        out.push(before[..taken].to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A number list where the signs do the separating.
    #[test]
    fn a_sign_ends_the_number_before_it() {
        let mut lexer = Lexer::new("5.66-5.66 1e2");
        assert!((lexer.number() - 5.66).abs() < 0.001);
        assert!((lexer.number() + 5.66).abs() < 0.001);
        assert!((lexer.number() - 100.0).abs() < 0.001);
    }

    /// A number list where a second point does the separating.
    ///
    /// Simple Icons writes the GitHub mark this way throughout, and read
    /// greedily every one of these is a token that parses as nothing.
    #[test]
    fn a_second_point_ends_the_number_before_it() {
        let mut lexer = Lexer::new("6-5.5.08-1.25 .5.5");
        for want in [6.0, -5.5, 0.08, -1.25, 0.5, 0.5] {
            let got = lexer.number();
            assert!((got - want).abs() < 0.001, "wanted {want}, got {got}");
        }
    }

    /// The same rule with nothing before the point either side of it.
    #[test]
    fn a_number_may_begin_with_its_point() {
        let mut lexer = Lexer::new(".4.4 3.4-3.4");
        for want in [0.4, 0.4, 3.4, -3.4] {
            let got = lexer.number();
            assert!((got - want).abs() < 0.001, "wanted {want}, got {got}");
        }
    }

    /// An exponent still parses, and still ends where it should.
    #[test]
    fn an_exponent_survives_the_second_point_rule() {
        let mut lexer = Lexer::new("1e2.5");
        assert!((lexer.number() - 100.0).abs() < 0.001);
        assert!((lexer.number() - 0.5).abs() < 0.001);
    }

    /// `M` followed by more pairs draws lines, and `z` closes what it started.
    #[test]
    fn a_move_repeats_as_a_line() {
        let mut out = Vec::new();
        path("M0 0 4 0 4 4z", &mut out);
        let [only] = out.as_slice() else {
            panic!("one subpath, got {}", out.len());
        };
        assert_eq!(only.points.len(), 3);
        assert!(only.closed, "z closes the outline");
    }

    /// A half circle by arc: the far side of a radius 6 circle centred at
    /// (12, 12), which is where `contrast` gets its shape.
    #[test]
    fn an_arc_bulges_the_way_the_sweep_flag_says() {
        let mut out = Vec::new();
        path("M12 18a6 6 0 0 0 0-12", &mut out);
        let [only] = out.as_slice() else {
            panic!("one subpath, got {}", out.len());
        };
        let east = only.points.iter().map(|p| p.x).fold(f32::MIN, f32::max);
        assert!(
            east > 17.0,
            "a sweep of 0 leaves the bottom by the east, so the half this \
             draws is the right one and its widest point is x = 18; got {east}"
        );
        let last = only.points.last().expect("an end");
        assert!((last.x - 12.0).abs() < 0.01 && (last.y - 6.0).abs() < 0.01);
    }

    /// The dot Lucide draws as a line going nowhere.
    #[test]
    fn a_zero_length_line_is_a_dot() {
        let mut out = Vec::new();
        path("M12 8h.01", &mut out);
        let [only] = out.as_slice() else {
            panic!("one subpath, got {}", out.len());
        };
        assert!(only.is_dot());
    }
}
