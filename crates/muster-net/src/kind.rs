//! What kind of thing a device is.
//!
//! Part of phase four, and the part that turns a table of addresses into a
//! picture of a network: an address with a vendor is a fact, and "the printer"
//! is what somebody was actually looking for.
//!
//! ## Every guess carries its reason
//!
//! `CLAUDE.md` is explicit that a claim about a device is stored beside the
//! reason for it and shown. So [`Kind`] never travels alone: [`Guess`] pairs it
//! with the [`Clue`] that produced it, the interface can say *why* it thinks a
//! thing is a printer, and "probably an iPhone" with nothing behind it is not
//! representable here.
//!
//! ## The clues are ranked, and the ranking is the design
//!
//! [`Clue`] is ordered from strongest to weakest, and [`identify`] takes the
//! best clue that fires rather than the first one it happens to check. That
//! matters because the signals genuinely disagree:
//!
//! * A **service the device advertises** is the device describing itself. A box
//!   answering `_ipp._tcp` is telling you it is a printer.
//! * The **route** is not an opinion at all: the gateway is the gateway.
//! * An **open port** is strong but not conclusive. Port 9100 is a print
//!   server, and it is also whatever somebody happened to put on 9100.
//! * A **vendor** is the weakest of the four and the most tempting. Apple makes
//!   phones, laptops, televisions, watches and speakers, so an Apple address
//!   says almost nothing on its own; Sonos makes speakers and nothing else, so
//!   it says a great deal. The table below carries only the vendors whose range
//!   is narrow enough for the inference to hold.
//!
//! A hostname is deliberately **not** a clue. `HP-Printer` is usually right and
//! `daves-old-printer-pc` is a desktop; a name is written by whoever set the
//! device up and is evidence about them, not about the hardware.
//!
//! Nothing here opens a socket. Everything it reads was already collected by
//! [`crate::discover`] and [`crate::identify`], so the whole module is a pure
//! function over a scan and the tests are a table.

use crate::discover::Found;
use crate::identify::Identity;
use crate::vendor::{self, Origin};

/// What a device appears to be.
///
/// Deliberately coarse. These are the categories somebody scans a home or
/// office network to see, and a longer list would be a longer list of things to
/// be wrong about: there is no `Laptop` because nothing on the wire
/// distinguishes one from a desktop, and no `Tablet` for the same reason.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// The way off this network.
    Router,
    /// An access point or switch that is not the gateway.
    NetworkGear,
    /// A general purpose machine: desktop, laptop, workstation.
    Computer,
    /// Something that exists to serve: a NAS, a home server, a hypervisor.
    Server,
    Printer,
    Phone,
    /// A television, a set-top box, or a streaming stick.
    Television,
    Speaker,
    Camera,
    GameConsole,
    /// A light, a plug, a thermostat, a sensor. Small, fixed function.
    SmartHome,
    /// Nothing said anything. **Not a failure**: most devices on most networks
    /// answer a ping and volunteer nothing else, and saying so is honest where
    /// guessing is not.
    #[default]
    Unknown,
}

impl Kind {
    /// A short label for the interface.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Router => "Router",
            Self::NetworkGear => "Network",
            Self::Computer => "Computer",
            Self::Server => "Server",
            Self::Printer => "Printer",
            Self::Phone => "Phone",
            Self::Television => "TV",
            Self::Speaker => "Speaker",
            Self::Camera => "Camera",
            Self::GameConsole => "Console",
            Self::SmartHome => "Smart home",
            Self::Unknown => "Unknown",
        }
    }
}

/// Why a device was taken for what it was taken for.
///
/// Ordered strongest first, and [`Ord`] is what [`identify`] sorts on, so
/// adding a variant in the wrong place changes the answers. That is deliberate:
/// the order *is* the priority, stated once, rather than an `if` chain whose
/// precedence is an accident of how it was written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Clue {
    /// It is the default gateway. Not an inference.
    Gateway,
    /// It advertised a service that says what it is.
    Service,
    /// A port that only one kind of thing listens on.
    Port,
    /// Its hardware vendor makes one kind of thing.
    Vendor,
    /// It answered NetBIOS with a workgroup.
    ///
    /// **Ranked last, below the vendor, and that placement is the point.** It
    /// is a self-report, which would put it with the services, but what it
    /// reports is only "speaks SMB" — true of every Windows machine and of
    /// every NAS. Ranked with the services it made a Synology box read as a
    /// desktop, because the workgroup beat a vendor that makes nothing but
    /// storage.
    Workgroup,
}

impl Clue {
    /// How the interface explains the guess.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Gateway => "it is this network's gateway",
            Self::Service => "it advertises a service only this kind offers",
            Self::Port => "a port only this kind listens on is open",
            Self::Vendor => "its hardware vendor makes only this kind",
            Self::Workgroup => "it answers NetBIOS with a workgroup, as Windows machines do",
        }
    }
}

/// A kind and the reason for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Guess {
    pub kind: Kind,
    pub clue: Clue,
}

/// Services that name a kind outright.
///
/// Matched as a prefix of the advertised type, so `_ipp._tcp.local` and
/// `_ipp._tcp` both hit. Only services whose presence is conclusive are here: a
/// `_http._tcp` is on half the devices ever made and names nothing.
const SERVICES: &[(&str, Kind)] = &[
    ("_ipp.", Kind::Printer),
    ("_ipps.", Kind::Printer),
    ("_printer.", Kind::Printer),
    ("_pdl-datastream.", Kind::Printer),
    ("_scanner.", Kind::Printer),
    ("_uscan.", Kind::Printer),
    ("_googlecast.", Kind::Television),
    ("_androidtvremote.", Kind::Television),
    ("_airplay.", Kind::Television),
    ("_roku.", Kind::Television),
    ("_raop.", Kind::Speaker),
    ("_spotify-connect.", Kind::Speaker),
    ("_sonos.", Kind::Speaker),
    ("_hap.", Kind::SmartHome),
    ("_homekit.", Kind::SmartHome),
    ("_hue.", Kind::SmartHome),
    ("_matter.", Kind::SmartHome),
    ("_home-assistant.", Kind::Server),
    ("_plexmediasvr.", Kind::Server),
    ("_smb.", Kind::Server),
    ("_afpovertcp.", Kind::Server),
    ("_nfs.", Kind::Server),
    ("_rfb.", Kind::Computer),
    ("_ssh.", Kind::Computer),
    ("_sftp-ssh.", Kind::Computer),
    // Avahi advertises this for the machine itself, so it is a Linux or BSD
    // host saying it is a host.
    ("_workstation.", Kind::Computer),
    ("_companion-link.", Kind::Computer),
    // iOS device pairing, and specific to a handset rather than to Apple.
    ("_apple-mobdev2.", Kind::Phone),
    ("_amzn-wplay.", Kind::Television),
    ("_device-info.", Kind::Unknown),
];

/// Ports that only one kind of thing listens on.
///
/// Short on purpose. 80, 443, 22 and 445 are on everything and are not here;
/// what is here is the handful where the service is the device.
const PORTS: &[(u16, Kind)] = &[
    (631, Kind::Printer),     // IPP
    (515, Kind::Printer),     // LPD
    (9100, Kind::Printer),    // JetDirect
    (8009, Kind::Television), // Chromecast
    (32400, Kind::Server),    // Plex
    (5000, Kind::Server),     // Synology DSM
    (548, Kind::Server),      // AFP
    (2049, Kind::Server),     // NFS
    (554, Kind::Camera),      // RTSP
    (37777, Kind::Camera),    // Dahua
    (1935, Kind::Camera),     // RTMP
    (8123, Kind::Server),     // Home Assistant
    (3389, Kind::Computer),   // RDP
    (5900, Kind::Computer),   // VNC
];

/// Vendors that make one kind of thing, and only one.
///
/// **This table earns its place by what is missing from it.** Apple, Samsung,
/// Google, Amazon, LG and Xiaomi all make four or five of the kinds above, so a
/// match on any of them would be a coin toss wearing a confident face. Every
/// name here makes essentially one product category, and the match is a
/// case-insensitive substring of the registry's own organisation name.
const VENDORS: &[(&str, Kind)] = &[
    ("sonos", Kind::Speaker),
    ("bose", Kind::Speaker),
    ("sonance", Kind::Speaker),
    ("brother", Kind::Printer),
    ("lexmark", Kind::Printer),
    ("zebra tech", Kind::Printer),
    ("kyocera", Kind::Printer),
    ("axis communications", Kind::Camera),
    ("hikvision", Kind::Camera),
    ("dahua", Kind::Camera),
    ("reolink", Kind::Camera),
    ("ubiquiti", Kind::NetworkGear),
    ("mikrotik", Kind::NetworkGear),
    ("aruba", Kind::NetworkGear),
    ("cisco systems", Kind::NetworkGear),
    ("netgear", Kind::NetworkGear),
    ("tp-link", Kind::NetworkGear),
    ("synology", Kind::Server),
    ("qnap", Kind::Server),
    ("nintendo", Kind::GameConsole),
    ("sony interactive", Kind::GameConsole),
    ("signify", Kind::SmartHome), // Philips Hue
    ("philips lighting", Kind::SmartHome),
    ("tuya", Kind::SmartHome),
    ("shelly", Kind::SmartHome),
    ("espressif", Kind::SmartHome),
    ("nest labs", Kind::SmartHome),
    ("ecobee", Kind::SmartHome),
    // Single-board computers, and nothing else.
    ("raspberry pi", Kind::Computer),
];

/// What this device appears to be, and why.
///
/// `is_gateway` is the caller's, because only the survey knows the routing
/// table; everything else is read from the scan.
pub fn identify(found: &Found, identity: &Identity, is_gateway: bool) -> Option<Guess> {
    let mut best: Option<Guess> = None;
    let mut consider = |kind: Kind, clue: Clue| {
        if kind == Kind::Unknown {
            return;
        }
        // Strongest clue wins, and the first of an equal pair keeps its place:
        // the tables are written most-specific first.
        if best.is_none_or(|found: Guess| clue < found.clue) {
            best = Some(Guess { kind, clue });
        }
    };

    if is_gateway {
        consider(Kind::Router, Clue::Gateway);
    }

    // A NetBIOS node status reply carrying a workgroup is a machine saying it
    // is a Windows machine, or a Samba host pretending to be one convincingly
    // enough that the distinction does not matter to somebody reading a device
    // list. It is a self-report, so it ranks with the services.
    if identity.workgroup.is_some() {
        consider(Kind::Computer, Clue::Workgroup);
    }

    for service in &identity.services {
        let service = service.to_ascii_lowercase();
        if let Some((_, kind)) = SERVICES.iter().find(|(name, _)| service.starts_with(name)) {
            consider(*kind, Clue::Service);
        }
    }

    for port in found.open_ports() {
        if let Some((_, kind)) = PORTS.iter().find(|(number, _)| *number == port) {
            consider(*kind, Clue::Port);
        }
    }

    if let Some(mac) = found.mac
        && let Origin::Registered { name, .. } = vendor::lookup(mac)
    {
        let name = name.to_ascii_lowercase();
        if let Some((_, kind)) = VENDORS.iter().find(|(needle, _)| name.contains(needle)) {
            consider(*kind, Clue::Vendor);
        }
    }

    best
}

/// The kind alone, with [`Kind::Unknown`] where nothing was learned.
pub fn kind_of(found: &Found, identity: &Identity, is_gateway: bool) -> Kind {
    identify(found, identity, is_gateway).map_or(Kind::Unknown, |guess| guess.kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discover::Evidence;
    use crate::identify::{Name, Source};
    use crate::mac::MacAddr;
    use std::net::{IpAddr, Ipv4Addr};

    fn host(ports: &[u16], mac: Option<[u8; 6]>) -> Found {
        Found {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)),
            mac: mac.map(MacAddr::new),
            evidence: ports.iter().map(|p| Evidence::TcpOpen(*p)).collect(),
            rtt: None,
        }
    }

    fn advertising(services: &[&str]) -> Identity {
        Identity {
            names: Vec::new(),
            workgroup: None,
            mac: None,
            services: services.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    #[test]
    fn the_gateway_is_not_a_guess() {
        let guess = identify(&host(&[], None), &Identity::default(), true).expect("a guess");
        assert_eq!(guess.kind, Kind::Router);
        assert_eq!(guess.clue, Clue::Gateway);
    }

    #[test]
    fn a_device_that_says_what_it_is_is_believed_over_its_ports() {
        // A printer with a web interface on 5000 would be read as a NAS by the
        // port table alone. What it advertises about itself wins.
        let guess = identify(
            &host(&[80, 5000], None),
            &advertising(&["_ipp._tcp.local"]),
            false,
        )
        .expect("a guess");
        assert_eq!(guess.kind, Kind::Printer);
        assert_eq!(guess.clue, Clue::Service);
    }

    #[test]
    fn a_port_beats_a_vendor() {
        // Ubiquiti make network gear, but this one is answering RTSP: a camera
        // they also make. The narrower signal is the open port.
        let ubiquiti = [0x44, 0xd9, 0xe7, 0x00, 0x00, 0x01];
        let guess =
            identify(&host(&[554], Some(ubiquiti)), &Identity::default(), false).expect("a guess");
        assert_eq!(guess.kind, Kind::Camera);
        assert_eq!(guess.clue, Clue::Port);
    }

    #[test]
    fn a_vendor_that_makes_one_thing_is_enough_on_its_own() {
        // Sonos make speakers and nothing else, which is the whole test for
        // whether a vendor belongs in the table.
        let sonos = [0x00, 0x0e, 0x58, 0x00, 0x00, 0x01];
        let guess =
            identify(&host(&[], Some(sonos)), &Identity::default(), false).expect("a guess");
        assert_eq!(guess.kind, Kind::Speaker);
        assert_eq!(guess.clue, Clue::Vendor);
    }

    #[test]
    fn nothing_learned_is_reported_as_nothing_learned() {
        // The common case on a real network, and the one a scanner is most
        // tempted to fill in with a guess.
        assert_eq!(
            identify(&host(&[], None), &Identity::default(), false),
            None
        );
        assert_eq!(
            kind_of(&host(&[], None), &Identity::default(), false),
            Kind::Unknown
        );
    }

    #[test]
    fn a_randomised_address_yields_no_vendor_guess() {
        // Bit 1 of the first octet set: the device made this address up, so
        // there is no manufacturer behind it to reason from.
        let randomised = [0x7a, 0x0e, 0x58, 0x00, 0x00, 0x01];
        assert_eq!(
            identify(&host(&[], Some(randomised)), &Identity::default(), false),
            None,
            "a made-up address must not be read as its accidental OUI"
        );
    }

    #[test]
    fn a_service_that_names_nothing_names_nothing() {
        // `_device-info` is on almost every Apple device and says only that it
        // is an Apple device. It is in the table mapped to `Unknown` so that
        // nobody adds it again believing it means something.
        assert_eq!(
            identify(
                &host(&[], None),
                &advertising(&["_device-info._tcp.local"]),
                false
            ),
            None
        );
    }

    #[test]
    fn a_workgroup_makes_it_a_computer() {
        // The commonest device on an office network, and one that often answers
        // nothing else: Windows blocks ping on the public profile and answers
        // NetBIOS anyway.
        let identity = Identity {
            workgroup: Some("WORKGROUP".to_string()),
            ..Identity::default()
        };
        let guess = identify(&host(&[], None), &identity, false).expect("a guess");
        assert_eq!(guess.kind, Kind::Computer);
        assert_eq!(guess.clue, Clue::Workgroup);
    }

    #[test]
    fn a_nas_that_speaks_smb_is_still_a_nas() {
        // The case that moved `Workgroup` below `Vendor`: a Synology box
        // answers NetBIOS like any file server, and reading that as "desktop"
        // threw away the one vendor that says exactly what the thing is.
        let synology = [0x00, 0x11, 0x32, 0x00, 0x00, 0x01];
        let identity = Identity {
            workgroup: Some("WORKGROUP".to_string()),
            ..Identity::default()
        };
        let guess = identify(&host(&[], Some(synology)), &identity, false).expect("a guess");
        assert_eq!(guess.kind, Kind::Server);
        assert_eq!(guess.clue, Clue::Vendor);
    }

    #[test]
    fn advertising_ssh_makes_it_a_computer() {
        let guess =
            identify(&host(&[], None), &advertising(&["_ssh._tcp.local"]), false).expect("a guess");
        assert_eq!(guess.kind, Kind::Computer);
    }

    #[test]
    fn a_hostname_is_never_a_clue() {
        // `HP-Printer` on a desktop is somebody's naming, not a printer.
        let identity = Identity {
            names: vec![Name {
                value: "HP-Printer".to_string(),
                source: Source::Mdns,
            }],
            ..Identity::default()
        };
        assert_eq!(identify(&host(&[], None), &identity, false), None);
    }

    #[test]
    fn the_clue_order_is_the_priority_order() {
        // The ranking is load-bearing: `identify` sorts on it, so a variant
        // inserted in the wrong place silently changes every answer.
        assert!(Clue::Gateway < Clue::Service);
        assert!(Clue::Service < Clue::Port);
        assert!(Clue::Port < Clue::Vendor);
        assert!(Clue::Vendor < Clue::Workgroup);
    }

    #[test]
    fn every_kind_has_a_label() {
        for kind in [
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
        ] {
            assert!(!kind.label().is_empty());
        }
    }
}
