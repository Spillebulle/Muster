//! The pictures in `docs/images/`, taken by the interface that they are
//! pictures of.
//!
//! ```sh
//! cargo run -p muster-app --example docs-images
//! ```
//!
//! Run by hand, and the files it writes are committed. Nothing in `cargo test`
//! calls it: it wants a graphics adapter and a display, and it writes into the
//! working tree.
//!
//! **Nothing here draws an interface.** It builds the real [`muster_app::app::App`]
//! through [`App::seeded`], hands it a scan, and asks egui to photograph its own
//! window. A picture of the interface that something else drew goes stale in
//! silence, and a README is exactly where nobody looks for the drift.
//!
//! ## The network in the pictures is invented, and that is the point
//!
//! §17.3 of the style guide asks for real content and never lorem, and for a
//! network scanner those two rules pull against each other: the honest picture
//! of a real scan is a photograph of somebody's house. So the devices below are
//! made up, and they are made up *carefully* — the addresses are in a range
//! reserved for documentation, the hardware addresses carry real IEEE
//! assignments so the vendor column shows what it would really show, and one of
//! them is randomised so the picture includes the case most scanners get wrong.
//! Nothing here is a machine that exists.
//!
//! ## Frames are run until egui stops asking for another
//!
//! egui measures a layout against the previous frame's, so the first pass lays
//! the table out against a window it has not seen. Photographing that gets a
//! half-built screen. [`Shot::ready`] waits instead.

use muster_app::app::{App, View};
use muster_app::scan::{Outcome, State};
use muster_app::theme::Mode;
use muster_net::discover::{Evidence, Found, Sweep};
use muster_net::identify::{Identity, Name, Source};
use muster_net::sysinfo::{
    IfAddr, IfFlags, Interface, LinkKind, Neighbour, NeighbourState, Recorded, Route,
};
use muster_net::{MacAddr, Prefix, Survey};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Every picture the README asks for: the view, and the window it is taken at.
///
/// §17.3 wants the whole-thing picture 1400 to 1600 px wide, and detail
/// pictures cropped to the module at natural size. Muster's shell has nothing
/// to crop *to* — the module is the window — so the detail shots are taken at a
/// narrow window instead. That is a real size the interface has to work at, so
/// the picture is of the application rather than of a cut-out of it, and it is
/// the width §17.3 asks a right-aligned picture to sit at.
const SHOTS: [(&str, View, [f32; 2], Option<u8>); 5] = [
    ("settings.png", View::Devices, [1400.0, 700.0], Some(0)),
    ("window.png", View::Devices, [1400.0, 620.0], None),
    // The detail window, opened on the printer: the device with the most to
    // say about itself, so the picture shows the panel doing its job.
    ("device.png", View::Devices, [1400.0, 520.0], Some(27)),
    ("network.png", View::Network, [720.0, 380.0], None),
    ("about.png", View::About, [720.0, 480.0], None),
];

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the workspace root is two levels above this crate");
    let out = root.join("docs/images");
    std::fs::create_dir_all(&out).expect("create docs/images");

    for (name, view, window, select) in SHOTS {
        shoot(out.join(name), view, window, select);
        println!("  {}", out.join(name).display());
    }
}

/// Open the window on one view, photograph it, write the file and close.
fn shoot(path: PathBuf, view: View, window: [f32; 2], select: Option<u8>) {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size(window)
            // No decorations: §17.3 wants the OS window chrome cropped away,
            // and not drawing it is cheaper and exact where cropping is neither.
            .with_decorations(false)
            .with_title("Muster"),
        ..Default::default()
    };
    eframe::run_native(
        "io.github.spillebulle.muster.docs",
        options,
        Box::new(move |cc| {
            // One point per pixel. The scale the machine happens to run at is
            // not the scale the picture is specified at.
            cc.egui_ctx.set_pixels_per_point(1.0);
            let mut app = App::seeded(
                cc,
                survey(),
                State::Finished(Box::new(scan())),
                view,
                Mode::Dark,
            );
            match select {
                // Zero is not a host: it means "open the settings page", which
                // is the one picture that is not about a device.
                Some(0) => app.open_settings(),
                Some(host) => app.select(v4(192, 0, 2, host)),
                None => {}
            }
            Ok(Box::new(Shot {
                app,
                path,
                settled: 0,
                asked: false,
            }))
        }),
    )
    .expect("open a window");
}

/// The real app, plus the few frames of patience a photograph needs.
struct Shot {
    app: App,
    path: PathBuf,
    /// Frames drawn since the last one that asked to be drawn again.
    settled: u32,
    asked: bool,
}

impl Shot {
    /// How many frames to draw before photographing.
    ///
    /// egui measures a layout against the previous frame's, so the first pass
    /// lays the table out against a window it has not seen; a picture taken
    /// then is of a half-built screen. A handful of frames is all it takes to
    /// settle, and this interface has nothing that animates, so waiting for
    /// quiet would only be waiting for this example's own repaint request.
    const READY: u32 = 8;

    /// When to conclude no picture is coming. See the caller.
    const GIVE_UP: u32 = 600;
}

impl eframe::App for Shot {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        self.app.update(ctx, frame);

        // The picture arrives as an event on the frame after it was asked for.
        let shot = ctx.input(|i| {
            i.events.iter().find_map(|e| match e {
                egui::Event::Screenshot { image, .. } => Some(image.clone()),
                _ => None,
            })
        });
        if let Some(image) = shot {
            write_png(&self.path, &image);
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }

        self.settled += 1;
        if !self.asked && self.settled >= Shot::READY {
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::default()));
            self.asked = true;
        }
        // A window that never produced a picture must not sit there for ever:
        // this runs unattended from a shell, and a hang looks exactly like a
        // slow machine until somebody notices the build never finished.
        if self.settled > Shot::GIVE_UP {
            eprintln!(
                "docs-images: no picture arrived for {} after {} frames",
                self.path.display(),
                self.settled
            );
            std::process::exit(1);
        }
        // Frames do not arrive on their own: nothing in a settled interface
        // asks to be drawn again, and this example needs the next one.
        ctx.request_repaint();
    }
}

fn write_png(path: &Path, image: &egui::ColorImage) {
    let file = std::fs::File::create(path).expect("create the picture");
    let mut encoder = png::Encoder::new(
        std::io::BufWriter::new(file),
        image.width() as u32,
        image.height() as u32,
    );
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let bytes: Vec<u8> = image
        .pixels
        .iter()
        .flat_map(|p| [p.r(), p.g(), p.b(), p.a()])
        .collect();
    encoder
        .write_header()
        .and_then(|mut w| w.write_image_data(&bytes))
        .expect("write the picture");
}

// ---------------------------------------------------------------------------
// The invented network
// ---------------------------------------------------------------------------

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

/// `192.0.2.0/24`, which RFC 5737 reserves for documentation. Using a range
/// somebody's router might actually hand out would make these pictures look
/// like a photograph of a real house.
fn prefix() -> Prefix {
    Prefix::new(v4(192, 0, 2, 0), 24).expect("a /24 is a valid prefix")
}

/// What the machine taking the picture would have read from the system.
fn survey() -> Survey {
    let recorded = Recorded {
        interfaces: vec![Interface {
            name: "wlan0".into(),
            friendly: "Wi-Fi".into(),
            index: 4,
            mac: Some(MacAddr::new([0x3c, 0x22, 0xfb, 0x1a, 0x0c, 0x4e])),
            addresses: vec![IfAddr {
                address: v4(192, 0, 2, 34),
                prefix: prefix(),
            }],
            kind: LinkKind::Wireless,
            flags: IfFlags {
                up: true,
                loopback: false,
                point_to_point: false,
            },
            mtu: 1500,
            dns: vec![v4(192, 0, 2, 1)],
            dhcp_server: Some(v4(192, 0, 2, 1)),
        }],
        routes: vec![Route {
            destination: Prefix::new(v4(0, 0, 0, 0), 0).expect("the default route"),
            gateway: Some(v4(192, 0, 2, 1)),
            interface_index: 4,
            metric: 35,
        }],
        neighbours: vec![Neighbour {
            address: v4(192, 0, 2, 1),
            mac: MacAddr::new([0x44, 0xd9, 0xe7, 0x2b, 0x81, 0x0a]),
            interface_index: 4,
            state: NeighbourState::Reachable,
        }],
        resolvers: vec![v4(192, 0, 2, 1)],
        ..Recorded::default()
    };
    Survey::take(recorded)
}

/// A finished scan of that network.
///
/// Fourteen devices, which is an ordinary house, chosen so the table shows what
/// the table is for: things that name themselves over mDNS, a Windows machine
/// only NetBIOS answers for, devices that prove they are there by refusing a
/// connection rather than accepting one, two with no name at all, and a phone
/// with a randomised hardware address.
fn scan() -> Outcome {
    let devices: Vec<(u8, [u8; 6], Vec<Evidence>, u64)> = vec![
        (
            1,
            [0x44, 0xd9, 0xe7, 0x2b, 0x81, 0x0a],
            vec![
                Evidence::Arp(MacAddr::new([0x44, 0xd9, 0xe7, 0x2b, 0x81, 0x0a])),
                Evidence::TcpOpen(80),
                Evidence::TcpOpen(443),
            ],
            1_200,
        ),
        (
            18,
            [0xb8, 0x27, 0xeb, 0x4f, 0x2c, 0x91],
            vec![Evidence::Ping, Evidence::TcpOpen(22)],
            2_400,
        ),
        (
            27,
            [0x00, 0x1b, 0xa9, 0x60, 0x14, 0x3d],
            vec![
                Evidence::Ping,
                Evidence::TcpOpen(631),
                Evidence::TcpOpen(9100),
            ],
            6_800,
        ),
        (
            41,
            [0x2c, 0xf0, 0x5d, 0x77, 0x0e, 0xb2],
            vec![Evidence::TcpRefused(445)],
            9_100,
        ),
        (
            56,
            [0xd4, 0x9a, 0x20, 0x33, 0xa7, 0x18],
            vec![Evidence::Ping, Evidence::TcpOpen(8009)],
            14_300,
        ),
        // Locally administered: bit 1 of the first octet is set, so this is a
        // randomised address and the table has to say so rather than reporting
        // an unknown vendor.
        (
            73,
            [0x7a, 0x41, 0x9c, 0x0d, 0x52, 0xe6],
            vec![Evidence::Ping],
            37_500,
        ),
        (
            88,
            [0x00, 0x17, 0x88, 0x2a, 0x6b, 0xc4],
            vec![Evidence::TcpRefused(80)],
            21_900,
        ),
        (
            104,
            [0xdc, 0xa6, 0x32, 0x18, 0x7b, 0x50],
            vec![Evidence::Ping, Evidence::TcpOpen(8123)],
            3_100,
        ),
        (
            117,
            [0xf0, 0x18, 0x98, 0x64, 0x2d, 0x0f],
            vec![Evidence::TcpRefused(62078)],
            28_400,
        ),
        (
            132,
            [0x00, 0x11, 0x32, 0x1c, 0x33, 0xa8],
            vec![Evidence::Ping],
            11_700,
        ),
        (
            201,
            [0x8e, 0x35, 0xd2, 0x71, 0x06, 0x9b],
            vec![Evidence::Ping],
            44_200,
        ),
        // An Epson that says nothing about itself. Its vendor is the whole of
        // the evidence, which is the case the vendor table exists for: Seiko
        // Epson's networked products are printers, so the address alone is
        // enough.
        (
            36,
            [0x00, 0x26, 0xab, 0x51, 0x0d, 0x72],
            vec![Evidence::Ping],
            8_600,
        ),
        // A speaker, likewise identified by a vendor that makes one thing.
        (
            64,
            [0x00, 0x0e, 0x58, 0x3c, 0x91, 0x0a],
            vec![Evidence::Ping, Evidence::TcpOpen(1400)],
            5_400,
        ),
        // And a handset from a maker that only makes handsets, which is a
        // whole category the vendor table could not reach before.
        (
            149,
            [0x00, 0xca, 0xe0, 0x2d, 0x77, 0xb1],
            vec![Evidence::Ping],
            33_800,
        ),
    ];

    let found: Vec<Found> = devices
        .iter()
        .map(|(host, mac, evidence, rtt)| Found {
            address: v4(192, 0, 2, *host),
            mac: Some(MacAddr::new(*mac)),
            evidence: evidence.clone(),
            rtt: Some(Duration::from_micros(*rtt)),
        })
        .collect();

    let names = vec![
        named(&[("router.lan", Source::ReverseDns)], None, &[]),
        named(
            &[("pi-hole.local", Source::Mdns)],
            None,
            &["_ssh._tcp", "_http._tcp"],
        ),
        named(
            &[("BRW001BA960143D.local", Source::Mdns)],
            None,
            &["_ipp._tcp", "_pdl-datastream._tcp"],
        ),
        named(&[("STUDY-PC", Source::NetBios)], Some("WORKGROUP"), &[]),
        named(
            &[("living-room-tv.local", Source::Mdns)],
            None,
            &["_googlecast._tcp"],
        ),
        // Two sources that disagree, which the interface keeps rather than
        // resolving away.
        named(
            &[
                ("pixel-8.local", Source::Mdns),
                ("android-4f2c.lan", Source::ReverseDns),
            ],
            None,
            &[],
        ),
        Identity::default(),
        named(
            &[("homeassistant.local", Source::Mdns)],
            None,
            &["_home-assistant._tcp"],
        ),
        named(&[("iphone-kitchen.local", Source::Mdns)], None, &[]),
        named(&[("NAS-01", Source::NetBios)], Some("WORKGROUP"), &[]),
        Identity::default(),
        // The Epson, the Sonos and the phone each volunteer nothing: their
        // hardware vendor is the only thing that names them.
        Identity::default(),
        Identity::default(),
        Identity::default(),
    ];

    // Sorted by address, because the real sweep returns them that way and a
    // picture in a different order from the application is a picture of
    // something else. Paired first so a device and its name cannot come apart.
    let mut paired: Vec<(Found, Identity)> = found.into_iter().zip(names).collect();
    paired.sort_by_key(|(device, _)| device.address);
    let (found, names): (Vec<Found>, Vec<Identity>) = paired.into_iter().unzip();

    Outcome {
        sweep: Sweep {
            found,
            probed: 254,
            total: 254,
            // The honest note this build has to carry: an unprivileged sweep
            // could not ARP, and the interface says so rather than presenting
            // its count as the whole answer.
            not_done: vec![
                "ARP sweep: needs raw packet access, which this build does not have".into(),
            ],
            cancelled: false,
        },
        names,
        prefix: prefix(),
    }
}

fn named(names: &[(&str, Source)], workgroup: Option<&str>, services: &[&str]) -> Identity {
    Identity {
        names: names
            .iter()
            .map(|(value, source)| Name {
                value: (*value).to_string(),
                source: *source,
            })
            .collect(),
        workgroup: workgroup.map(str::to_string),
        mac: None,
        services: services.iter().map(|s| (*s).to_string()).collect(),
    }
}
