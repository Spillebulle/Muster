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
//! **The exception is a brand mark**, and there is one: [`Icon::Github`] is
//! GitHub's own silhouette, filled, from Simple Icons. A symbol can be drawn
//! in whatever hand the application writes in, because what it means comes
//! from its shape; a logo means one company and only the shape people already
//! know says so. Tally and HomeLab draw this same mark beside their own source
//! links, which is the other half of the argument. Filling it is why
//! [`triangulate`] is here.
//!
//! Icons are authored against a 24x24 box and scaled into whatever rect they
//! are given, so the 16 px instance in a navigation row and a larger one
//! elsewhere are the same shape.

use crate::lucide::{Node, Outline};
use egui::{Color32, Mesh, Painter, Pos2, Rect, Shape, Stroke, Vec2, pos2};
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
    /// GitHub's mark, filled, from Simple Icons.
    ///
    /// **The one icon here that is not Lucide's and not a stroke**, and the
    /// reason is that it is a brand mark rather than a symbol: it names one
    /// company's website, so the shape people already know is the shape that
    /// says so, and every other application in the family — Tally, HomeLab —
    /// draws this same silhouette beside its own source link. An outline
    /// version of a filled logo is a drawing of a logo.
    ///
    /// Simple Icons is CC0, so the path data travels without conditions; the
    /// README names it anyway, next to Lucide's.
    Github,
}

impl Icon {
    /// Every icon, which is what the tests walk.
    pub const ALL: [Self; 8] = [
        Self::Devices,
        Self::Network,
        Self::Gear,
        Self::Info,
        Self::Sliders,
        Self::Radar,
        Self::Contrast,
        Self::Github,
    ];

    /// Is this mark filled rather than stroked?
    ///
    /// One is, and [`Icon::Github`] says why. Everything else here is Lucide's,
    /// which means an outline at the interface's own stroke weight.
    fn is_filled(self) -> bool {
        matches!(self, Self::Github)
    }

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
            // Simple Icons `github`, copied verbatim the way the Lucide paths
            // above are. It is one closed subpath and it is filled, not
            // stroked; see [`Icon::is_filled`].
            Self::Github => &[Node::Path(
                "M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12",
            )],
        }
    }
}

/// One icon, ready to draw: its outlines, and for a filled mark the triangles
/// that cover them.
///
/// The triangles are indices into the outline's own points, so they survive
/// being scaled into any rect and are worked out exactly once.
struct Drawn {
    outlines: Vec<Outline>,
    /// One triangle list per outline, or nothing at all for a stroked icon.
    fill: Vec<Vec<[u32; 3]>>,
}

/// Every icon, flattened once for the life of the process.
///
/// The parse and the arcs are cheap, but they are the same answer every frame
/// for every row of the sidebar, and an icon set is drawn some dozens of times
/// a frame. Held in the 24x24 box and scaled at the point of drawing, so one
/// copy serves every size. Ear clipping the one filled mark is the expensive
/// part and is paid here, once, for the same reason.
static GEOMETRY: LazyLock<Vec<Drawn>> = LazyLock::new(|| {
    Icon::ALL
        .iter()
        .map(|i| {
            let outlines = crate::lucide::flatten(i.nodes());
            let fill = if i.is_filled() {
                outlines.iter().map(|o| triangulate(&o.points)).collect()
            } else {
                Vec::new()
            };
            Drawn { outlines, fill }
        })
        .collect()
});

fn geometry(icon: Icon) -> &'static Drawn {
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
    let drawn = geometry(icon);
    let place = |p: &Pos2| pos2(origin.x + p.x * scale, origin.y + p.y * scale);

    if !drawn.fill.is_empty() {
        for (outline, triangles) in drawn.outlines.iter().zip(&drawn.fill) {
            let points: Vec<_> = outline.points.iter().map(place).collect();
            let mut mesh = Mesh::default();
            for point in &points {
                mesh.colored_vertex(*point, colour);
            }
            for [a, b, c] in triangles {
                mesh.add_triangle(*a, *b, *c);
            }
            painter.add(Shape::mesh(mesh));
            // **A mesh has hard edges.** egui feathers what it tessellates
            // itself and takes triangles as given, so at 16 px the silhouette
            // would be a staircase. A hairline of the same ink along the same
            // outline is drawn the way every other stroke here is, and its
            // antialiasing is what smooths the edge of the fill under it.
            painter.add(Shape::closed_line(points, Stroke::new(1.0_f32, colour)));
        }
        return;
    }

    for outline in &drawn.outlines {
        let points: Vec<_> = outline.points.iter().map(place).collect();
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

/// Twice the area a run of points encloses, signed by which way it winds.
///
/// The sign is the whole point: it says which turn is a corner and which is a
/// notch, and in a y-down box that is the opposite of what a mathematician
/// would write down. Nothing here cares which way round it is, only that one
/// answer is used throughout.
fn winding(points: &[Pos2]) -> f32 {
    let mut sum = 0.0;
    for (index, a) in points.iter().enumerate() {
        let b = points[(index + 1) % points.len()];
        sum += a.x * b.y - b.x * a.y;
    }
    sum
}

/// Which side of the line `a`→`b` the point `c` falls.
fn turn(a: Pos2, b: Pos2, c: Pos2) -> f32 {
    (b.x - a.x) * (c.y - a.y) - (b.y - a.y) * (c.x - a.x)
}

/// Is `p` inside the triangle `a`, `b`, `c`, which winds positively?
fn inside(a: Pos2, b: Pos2, c: Pos2, p: Pos2) -> bool {
    turn(a, b, p) > 0.0 && turn(b, c, p) > 0.0 && turn(c, a, p) > 0.0
}

/// Cover a closed outline with triangles, by ear clipping.
///
/// **egui cannot fill this shape and does not say so.** Its tessellator covers
/// a closed path with a fan from the first point, which is right for the convex
/// shapes the widgets are made of and quietly wrong for anything with a notch
/// in it — the GitHub mark filled that way is a solid blob with its own arms
/// painted across the gaps. So the one filled mark is handed to the painter as
/// a mesh, and this is what works the mesh out: take the corner that no other
/// point of the outline sits inside, cut it off, and go round again.
///
/// Quadratic in the number of points and run once for the life of the process,
/// on one icon of some hundreds of points. The answer is indices into `points`,
/// so it holds for every size that icon is ever drawn at.
fn triangulate(points: &[Pos2]) -> Vec<[u32; 3]> {
    /// Below this an ear is a sliver rather than a triangle. The box is 24
    /// units across, so this is a millionth of it.
    const SLIVER: f32 = 1e-5;

    if points.len() < 3 {
        return Vec::new();
    }
    let mut left: Vec<u32> = (0..points.len() as u32).collect();
    // Ears are cut from a positively wound outline, so an outline that winds
    // the other way is walked backwards instead of being copied.
    if winding(points) < 0.0 {
        left.reverse();
    }

    let mut out = Vec::with_capacity(points.len() - 2);
    let at = |index: u32| points[index as usize];
    while left.len() > 3 {
        let before = left.len();
        let mut i = 0;
        while i < left.len() && left.len() > 3 {
            let n = left.len();
            let (a, b, c) = (left[(i + n - 1) % n], left[i], left[(i + 1) % n]);
            let corner = turn(at(a), at(b), at(c));
            // A corner flat enough to have no area is cut without asking what
            // is inside it: removing a point that lies on the line between its
            // neighbours cannot change the shape, and leaving it is how a walk
            // finds no ear at all and stalls.
            let ear = if corner.abs() < SLIVER {
                true
            } else {
                corner > 0.0
                    && !left.iter().any(|&other| {
                        other != a
                            && other != b
                            && other != c
                            && inside(at(a), at(b), at(c), at(other))
                    })
            };
            if ear {
                if corner.abs() >= SLIVER {
                    out.push([a, b, c]);
                }
                left.remove(i);
            } else {
                i += 1;
            }
        }
        // A whole pass without an ear means the outline crosses itself, which
        // no icon here does. Fanning what is left keeps the mark on screen
        // rather than dropping it, and the test below is what would catch it.
        if left.len() == before {
            break;
        }
    }
    for k in 1..left.len().saturating_sub(1) {
        out.push([left[0], left[k], left[k + 1]]);
    }
    out
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

    /// The sum of the triangles' areas, as a check that they cover the outline
    /// and do not overlap.
    fn covered(points: &[Pos2], triangles: &[[u32; 3]]) -> f32 {
        triangles
            .iter()
            .map(|&[a, b, c]| {
                let (a, b, c) = (points[a as usize], points[b as usize], points[c as usize]);
                turn(a, b, c).abs() / 2.0
            })
            .sum()
    }

    /// A notched shape is covered, and covered exactly once.
    ///
    /// This is the case a fan gets wrong: fanned from the origin, the L below
    /// paints over the bite taken out of it, and the total comes out larger
    /// than the shape.
    #[test]
    fn an_l_is_covered_by_its_triangles() {
        let l = [
            pos2(0.0, 0.0),
            pos2(6.0, 0.0),
            pos2(6.0, 2.0),
            pos2(2.0, 2.0),
            pos2(2.0, 6.0),
            pos2(0.0, 6.0),
        ];
        let triangles = triangulate(&l);
        assert_eq!(triangles.len(), l.len() - 2, "an ear per point but two");
        let area = winding(&l).abs() / 2.0;
        assert!((area - 20.0).abs() < 0.001, "the L is 20 units, got {area}");
        let covered = covered(&l, &triangles);
        assert!(
            (covered - area).abs() < 0.001,
            "the triangles cover {covered} of a shape that is {area}"
        );
    }

    /// The same, walked the other way round.
    #[test]
    fn winding_does_not_change_the_answer() {
        let mut l = vec![
            pos2(0.0, 0.0),
            pos2(6.0, 0.0),
            pos2(6.0, 2.0),
            pos2(2.0, 2.0),
            pos2(2.0, 6.0),
            pos2(0.0, 6.0),
        ];
        l.reverse();
        let covered = covered(&l, &triangulate(&l));
        assert!((covered - 20.0).abs() < 0.001, "got {covered}");
    }

    /// Every filled mark has a mesh, and the mesh is the mark.
    ///
    /// An ear clipper that gives up part way through still returns something,
    /// so the test that matters is not that it returned triangles but that
    /// they add up to the outline's own area. GitHub's mark is a few hundred
    /// points with the tail and the ears folding back on themselves, which is
    /// the shape a fan cannot do.
    #[test]
    fn a_filled_mark_is_covered_by_its_triangles() {
        for icon in Icon::ALL.into_iter().filter(|i| i.is_filled()) {
            for outline in crate::lucide::flatten(icon.nodes()) {
                let triangles = triangulate(&outline.points);
                assert!(!triangles.is_empty(), "{icon:?} covered by nothing");
                let area = winding(&outline.points).abs() / 2.0;
                let covered = covered(&outline.points, &triangles);
                assert!(
                    (covered - area).abs() < area * 0.001,
                    "{icon:?}: {covered} covered of an outline enclosing {area}"
                );
            }
        }
    }

    /// A stroked icon is not handed triangles it would not use.
    #[test]
    fn only_the_filled_marks_carry_a_mesh() {
        for icon in Icon::ALL {
            assert_eq!(
                !geometry(icon).fill.is_empty(),
                icon.is_filled(),
                "{icon:?} carries a mesh it should not, or lacks one it should"
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
