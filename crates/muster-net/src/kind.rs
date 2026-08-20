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
use crate::mac::MacAddr;
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
///
/// ## The trailing dot is part of the needle, and it is load-bearing
///
/// `_uscan.` must not match `_uscans._tcp` and `_matter.` must not match
/// `_matterc._udp`, because those are separate service types that happen to
/// share a stem: eSCL's plain and TLS halves, and Matter's operational,
/// commissionable and commissioner discovery. The separator is what keeps them
/// apart. The price is that every sibling has to be written out, and for a
/// long time three of them were not — `_uscans.`, `_matterc.`/`_matterd.` and
/// `_androidtvremote2.` — so a driverless scanner, a Matter device waiting to
/// be commissioned and every Android TV made since 2021 all fell through this
/// table without matching anything. Adding a service here means asking what
/// its neighbours are called.
///
/// ## The order of this table is the tie-break
///
/// Every row produces the same [`Clue::Service`], so a device advertising two
/// of them is decided by rank alone. [`identify`] walks *this table* in its
/// outer loop and the device's advertised list in the inner one, which is the
/// difference between a documented order and the order the records happened to
/// sit in one packet: an Apple TV offers `_airplay._tcp` and `_raop._tcp`
/// together, and which of television and speaker it came out as used to depend
/// on the packet's layout.
///
/// So the specific comes before the general. Two consequences are worth
/// stating rather than discovering:
///
/// * `_airplay.` against `_raop.` stays genuinely ambiguous. A HomePod
///   advertises both, exactly as an Apple TV does, and reads here as a
///   television. That is one known wrong answer rather than a coin toss on
///   every device, and `_mediaremotetv.` above it catches the Apple TV on a
///   signal that is actually its own.
/// * A box offering file shares is being a server even when it is also
///   somebody's desktop, so `_smb.` outranks `_ssh.`. That is the same call
///   [`Clue::Workgroup`] documents, and it is what stops a NAS reading as a
///   laptop.
const SERVICES: &[(&str, Kind)] = &[
    // Printing and scanning. Nothing else on a network offers these.
    ("_ipp.", Kind::Printer),
    ("_ipps.", Kind::Printer),
    ("_ipp-tls.", Kind::Printer),
    ("_printer.", Kind::Printer),
    ("_pdl-datastream.", Kind::Printer),
    ("_fax-ipp.", Kind::Printer),
    ("_scanner.", Kind::Printer),
    ("_sane-port.", Kind::Printer),
    // eSCL, driverless scanning. The `s` is the TLS variant, and it is a
    // separate type rather than a suffix of the first.
    ("_uscan.", Kind::Printer),
    ("_uscans.", Kind::Printer),
    ("_axis-video.", Kind::Camera),
    // Media receivers that name their own brand, and so name the device.
    ("_sonos.", Kind::Speaker),
    ("_roku.", Kind::Television),
    ("_amzn-wplay.", Kind::Television),
    ("_androidtvremote2.", Kind::Television),
    // The Apple TV's own remote protocol: the one signal that tells it apart
    // from every other AirPlay receiver in the house.
    ("_mediaremotetv.", Kind::Television),
    ("_googlecast.", Kind::Television),
    // AirPlay video, then AirPlay audio. See the note above about HomePods.
    ("_airplay.", Kind::Television),
    ("_raop.", Kind::Speaker),
    ("_spotify-connect.", Kind::Speaker),
    // Home automation.
    ("_hap.", Kind::SmartHome),
    ("_homekit.", Kind::SmartHome),
    ("_hue.", Kind::SmartHome),
    ("_matter.", Kind::SmartHome),
    ("_matterc.", Kind::SmartHome),
    ("_matterd.", Kind::SmartHome),
    ("_esphomelib.", Kind::SmartHome),
    // Things that exist to serve.
    ("_home-assistant.", Kind::Server),
    ("_plexmediasvr.", Kind::Server),
    ("_smb.", Kind::Server),
    ("_afpovertcp.", Kind::Server),
    ("_nfs.", Kind::Server),
    // Time Machine offers a backup disc, DAAP offers a music library. Both are
    // a machine handing out storage rather than using it.
    ("_adisk.", Kind::Server),
    ("_daap.", Kind::Server),
    ("_rfb.", Kind::Computer),
    ("_ssh.", Kind::Computer),
    ("_sftp-ssh.", Kind::Computer),
    // Avahi advertises this for the machine itself, so it is a Linux or BSD
    // host saying it is a host.
    ("_workstation.", Kind::Computer),
    // GameStream's host half runs on a desktop with a graphics card in it.
    ("_nvstream.", Kind::Computer),
    // iOS device pairing, and specific to a handset rather than to Apple.
    ("_apple-mobdev2.", Kind::Phone),
    // Says "an Apple device" and nothing further: macOS, iOS, iPadOS and tvOS
    // all advertise it. It was mapped to `Computer`, which made every iPhone
    // and Apple TV in range a desktop, so it sits with `_device-info` now —
    // in the table, mapped to nothing, so that nobody adds it back believing
    // it says more than it does.
    ("_companion-link.", Kind::Unknown),
    ("_device-info.", Kind::Unknown),
];

/// Ports that only one kind of thing listens on.
///
/// Short on purpose. 80, 443, 22 and 445 are on everything and are not here;
/// what is here is the handful where the service is the device.
///
/// **Every port here must also be in [`crate::portscan::Ports::common`]**,
/// because that is the list a scan uses when nobody said otherwise, and a clue
/// that only fires on a hand-written port range is a clue that never fires.
/// 554, 8009, 8060 and 1400 were in this table and not in that list, which
/// left the camera and television port clues unreachable on a default scan.
/// `every_port_the_kind_table_names_is_in_the_default_scan` keeps the two in
/// step.
const PORTS: &[(u16, Kind)] = &[
    (631, Kind::Printer),     // IPP
    (515, Kind::Printer),     // LPD
    (9100, Kind::Printer),    // JetDirect
    (8008, Kind::Television), // Chromecast, the HTTP half
    (8009, Kind::Television), // Chromecast, the control channel
    (8060, Kind::Television), // Roku's external control protocol
    (1400, Kind::Speaker),    // Sonos
    (32400, Kind::Server),    // Plex
    (32469, Kind::Server),    // Plex, its DLNA half
    (5000, Kind::Server),     // Synology DSM
    // Also iperf's default, which is a thing somebody runs for a minute rather
    // than a thing that sits listening on a home network.
    (5001, Kind::Server),      // Synology DSM over TLS
    (8006, Kind::Server),      // Proxmox
    (548, Kind::Server),       // AFP
    (2049, Kind::Server),      // NFS
    (8123, Kind::Server),      // Home Assistant
    (554, Kind::Camera),       // RTSP
    (37777, Kind::Camera),     // Dahua
    (1935, Kind::Camera),      // RTMP
    (8291, Kind::NetworkGear), // MikroTik Winbox
    (8728, Kind::NetworkGear), // MikroTik API
    (8729, Kind::NetworkGear), // MikroTik API over TLS
    // lockdownd, which is on an iPhone or an iPad and on nothing else at all.
    (62078, Kind::Phone),
    (3389, Kind::Computer),  // RDP
    (5900, Kind::Computer),  // VNC
    (27036, Kind::Computer), // Steam remote play
];

/// How a vendor needle is compared with the registry's organisation name.
///
/// **The mode is part of the data because the wrong mode is a false claim.**
/// Every row here was once a case-insensitive substring, and the registry
/// punished it: `sonos` also matches SonoSite, SonoSound, sonoscape and Schunk
/// Sonosystems; `bose` matches BOSER TECHNOLOGY; `brother` matches McKay
/// Brothers and Brother, Brother and Sons; `sonance` matches Consonance and
/// Raven Resonance. Ultrasound scanners and a cable-splice manufacturer
/// reading as speakers is not a near miss. It is the table saying something
/// untrue with a reason printed beside it, which is worse than saying nothing.
///
/// So a short name now states how far it is allowed to reach, and only the
/// long ones keep [`Match::Contains`]: `guangdong oppo mobile` cannot be
/// anything else, and a substring is the only thing that finds a company which
/// is not at the front of its own registry name, as Tenda is in
/// `SHEN ZHEN TENDA TECHNOLOGY`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Match {
    /// Anywhere in the name.
    Contains,
    /// At the start of the name. The usual choice for a short brand.
    Prefix,
    /// The whole name and nothing else. The strongest, and the most brittle:
    /// the IEEE rewrites organisation names, so an `Exact` row can go dead in
    /// a registry refresh. That is survivable only because
    /// `every_vendor_needle_matches_the_registry` fails the build when it does.
    Exact,
}

impl Match {
    /// `name` must already be lower case, which is how the needles are written.
    fn matches(self, needle: &str, name: &str) -> bool {
        match self {
            Self::Contains => name.contains(needle),
            Self::Prefix => name.starts_with(needle),
            Self::Exact => name == needle,
        }
    }
}

/// Vendors that make one kind of thing, and only one.
///
/// **This table earns its place by what is missing from it.** Apple, Samsung,
/// Google, Amazon, LG and Xiaomi all make four or five of the kinds above, so a
/// match on any of them would be a coin toss wearing a confident face. Three
/// groups are kept out on purpose, and they are the tempting ones:
///
/// * **The component makers.** Intel, Realtek, Broadcom, Qualcomm, MediaTek,
///   Hon Hai, AzureWave, Murata, Liteon, Quanta, Pegatron and Compal between
///   them hold a large share of the registry, and every one of those blocks
///   names the radio rather than the thing it is soldered into.
/// * **The conglomerates.** Sony, Panasonic, Sharp, Bosch, Honeywell, Yamaha,
///   Harman, Nokia, ZTE and Huawei each make several of the kinds above.
///   `sony interactive` is in the table and `sony corporation` is not, which is
///   the whole distinction: the subsidiary makes consoles, the parent makes
///   everything.
/// * **The unqualified brand names.** `tcl`, `hisense` on its own and
///   `skyworth` name a company that ships televisions and the router that goes
///   under them, so a match would be right about half the time and confident
///   every time. `hisense visual` and `hisense electric` are the two qualified
///   names, and those are televisions.
///
/// Where a brand does span a television and a router — Sky, Humax and Buffalo
/// all do — the router half is nearly always the gateway, and [`Clue::Gateway`]
/// has already answered before this table is consulted. That is why those
/// three are here and TCL is not.
///
/// The needles are lower case and each carries its [`Match`] mode; see there
/// for why the mode is data rather than a fixed "substring".
const VENDORS: &[(Match, &str, Kind)] = &[
    // ---- Speakers ------------------------------------------------------
    // Two spellings of one company, and neither may be shortened to `sonos`:
    // that also catches SonoSite's ultrasound scanners.
    (Match::Prefix, "sonos, inc", Kind::Speaker),
    (Match::Prefix, "sonos inc", Kind::Speaker),
    (Match::Prefix, "bose corporation", Kind::Speaker),
    (Match::Exact, "sonance", Kind::Speaker),
    (Match::Prefix, "d&m holdings", Kind::Speaker), // Denon, Marantz
    (Match::Prefix, "sound united", Kind::Speaker),
    (Match::Prefix, "onkyo", Kind::Speaker),
    (Match::Prefix, "klipsch", Kind::Speaker),
    (Match::Prefix, "libratone", Kind::Speaker),
    (Match::Exact, "devialet", Kind::Speaker),
    (Match::Prefix, "bang & olufsen", Kind::Speaker),
    (Match::Prefix, "linn products", Kind::Speaker),
    (Match::Prefix, "lenbrook", Kind::Speaker), // NAD, Bluesound
    // ---- Printers ------------------------------------------------------
    (Match::Prefix, "brother industries", Kind::Printer),
    (Match::Prefix, "lexmark", Kind::Printer),
    (Match::Prefix, "zebra tech", Kind::Printer),
    // Kyocera also holds blocks for its handset, display and component arms,
    // so the two printer names are spelled out rather than matched on the
    // group name.
    (Match::Prefix, "kyocera corporation", Kind::Printer),
    (Match::Prefix, "kyocera document", Kind::Printer),
    (Match::Prefix, "seiko epson", Kind::Printer),
    (Match::Prefix, "canon inc", Kind::Printer),
    (Match::Prefix, "ricoh", Kind::Printer),
    (Match::Prefix, "konica minolta", Kind::Printer),
    (Match::Prefix, "oki electric", Kind::Printer),
    (Match::Prefix, "toshiba tec", Kind::Printer),
    // Xerox holds `00:00:00` to `00:00:09`, which is also what a zeroed or
    // hand-typed address looks like; see [`is_placeholder`].
    (Match::Prefix, "xerox corp", Kind::Printer),
    (Match::Contains, "pantum", Kind::Printer),
    (Match::Prefix, "star micronics", Kind::Printer),
    // ---- Cameras -------------------------------------------------------
    (Match::Prefix, "axis communications", Kind::Camera),
    (Match::Contains, "hikvision", Kind::Camera),
    // Substring, because the registry name begins with the province. It also
    // reaches one scale factory in Shanghai, which is the price of that.
    (Match::Contains, "dahua", Kind::Camera),
    (Match::Prefix, "reolink", Kind::Camera),
    (Match::Prefix, "amcrest", Kind::Camera),
    (Match::Contains, "uniview", Kind::Camera),
    (Match::Prefix, "vivotek", Kind::Camera),
    (Match::Prefix, "mobotix", Kind::Camera),
    (Match::Prefix, "arlo technology", Kind::Camera),
    (Match::Prefix, "wyze labs", Kind::Camera),
    (Match::Prefix, "swann communications", Kind::Camera),
    (Match::Prefix, "lorex technology", Kind::Camera),
    // Amazon owns both of these, and both make cameras and nothing else, which
    // is why they are here while `amazon technologies` is not.
    (Match::Prefix, "blink by amazon", Kind::Camera),
    (Match::Prefix, "ring llc", Kind::Camera),
    // ---- Network gear --------------------------------------------------
    (Match::Prefix, "ubiquiti", Kind::NetworkGear),
    // MikroTik registers every block as Routerboard.com. `mikrotik` sat in
    // this table for a long time and matched nothing whatsoever, which is the
    // defect `every_vendor_needle_matches_the_registry` exists to catch.
    (Match::Prefix, "routerboard", Kind::NetworkGear),
    (Match::Prefix, "cisco systems", Kind::NetworkGear),
    (Match::Prefix, "cisco meraki", Kind::NetworkGear),
    (Match::Exact, "netgear", Kind::NetworkGear),
    (Match::Prefix, "tp-link", Kind::NetworkGear),
    (Match::Prefix, "juniper networks", Kind::NetworkGear),
    (Match::Prefix, "extreme networks", Kind::NetworkGear),
    (Match::Prefix, "ruckus", Kind::NetworkGear),
    (Match::Prefix, "eero inc", Kind::NetworkGear),
    (Match::Prefix, "d-link", Kind::NetworkGear),
    (Match::Prefix, "zyxel", Kind::NetworkGear),
    (Match::Prefix, "fortinet", Kind::NetworkGear),
    (Match::Prefix, "brocade", Kind::NetworkGear),
    (Match::Contains, "h3c technologies", Kind::NetworkGear),
    // Substring: the blocks are held as Cisco-Linksys and The Linksys Group as
    // well as by Linksys itself.
    (Match::Contains, "linksys", Kind::NetworkGear),
    (Match::Prefix, "avm gmbh", Kind::NetworkGear), // Fritz!Box
    (Match::Prefix, "sonicwall", Kind::NetworkGear),
    (Match::Prefix, "arista net", Kind::NetworkGear),
    (Match::Prefix, "draytek", Kind::NetworkGear),
    (Match::Prefix, "engenius", Kind::NetworkGear),
    (Match::Prefix, "cradlepoint", Kind::NetworkGear),
    (Match::Contains, "tenda technology", Kind::NetworkGear),
    (Match::Prefix, "humax networks", Kind::NetworkGear),
    // ---- Servers and storage -------------------------------------------
    (Match::Prefix, "synology", Kind::Server),
    (Match::Prefix, "qnap", Kind::Server),
    (Match::Prefix, "asustor", Kind::Server),
    (Match::Prefix, "buffalo.inc", Kind::Server),
    (Match::Exact, "netapp", Kind::Server),
    (Match::Prefix, "seagate technology", Kind::Server),
    (Match::Contains, "western digital", Kind::Server),
    (Match::Exact, "nutanix", Kind::Server),
    (Match::Prefix, "proxmox", Kind::Server),
    // ---- Televisions ---------------------------------------------------
    (Match::Prefix, "roku, inc", Kind::Television),
    (Match::Prefix, "vizio, inc", Kind::Television),
    (Match::Prefix, "hisense visual", Kind::Television),
    (Match::Prefix, "hisense electric", Kind::Television),
    (Match::Prefix, "tp vision", Kind::Television), // Philips televisions
    (Match::Prefix, "vestel", Kind::Television),
    (Match::Prefix, "humax co", Kind::Television),
    (Match::Prefix, "sky uk", Kind::Television),
    // ---- Phones --------------------------------------------------------
    // The table had no phone vendor at all, which left the commonest device on
    // a home network as the one it could say least about. These ten are
    // pure-play handset makers and between them hold some seven hundred and
    // fifty blocks.
    (Match::Prefix, "guangdong oppo mobile", Kind::Phone),
    (Match::Prefix, "vivo mobile communication", Kind::Phone),
    (Match::Prefix, "motorola mobility", Kind::Phone),
    (Match::Prefix, "itel mobile", Kind::Phone),
    (Match::Prefix, "honor device", Kind::Phone),
    (Match::Prefix, "realme chongqing", Kind::Phone),
    (Match::Prefix, "tecno mobile", Kind::Phone),
    (Match::Prefix, "oneplus", Kind::Phone),
    (Match::Prefix, "fairphone", Kind::Phone),
    (Match::Prefix, "nothing technology", Kind::Phone),
    // ---- Consoles ------------------------------------------------------
    (Match::Prefix, "nintendo", Kind::GameConsole),
    (Match::Prefix, "sony interactive", Kind::GameConsole),
    // ---- Smart home ----------------------------------------------------
    (Match::Prefix, "signify", Kind::SmartHome), // Philips Hue
    (Match::Prefix, "philips lighting", Kind::SmartHome),
    (Match::Prefix, "tuya smart", Kind::SmartHome),
    (Match::Prefix, "shelly", Kind::SmartHome),
    (Match::Prefix, "espressif", Kind::SmartHome),
    (Match::Prefix, "nest labs", Kind::SmartHome),
    (Match::Prefix, "ecobee", Kind::SmartHome),
    (Match::Prefix, "lumi united", Kind::SmartHome), // Aqara
    (Match::Prefix, "ikea of sweden", Kind::SmartHome),
    (Match::Exact, "nanoleaf", Kind::SmartHome),
    (Match::Exact, "resideo", Kind::SmartHome),
    (Match::Exact, "netatmo", Kind::SmartHome),
    (Match::Prefix, "tado gmbh", Kind::SmartHome),
    (Match::Exact, "simplisafe", Kind::SmartHome),
    (Match::Contains, "chamberlain group", Kind::SmartHome),
    (Match::Prefix, "irobot", Kind::SmartHome),
    (Match::Contains, "roborock", Kind::SmartHome),
    (Match::Prefix, "dyson limited", Kind::SmartHome),
    (Match::Contains, "lifi labs", Kind::SmartHome), // LIFX
    // ---- Computers -----------------------------------------------------
    // Single-board computers, and nothing else.
    (Match::Prefix, "raspberry pi", Kind::Computer),
    // Dell also ships servers and a switch line, so this is the weakest row in
    // the table. It stays because a Dell address on a local network is a
    // desktop or a laptop far more often than it is anything else, and because
    // a PowerEdge answers on ports and services that outrank a vendor anyway.
    (Match::Prefix, "dell inc", Kind::Computer),
    (Match::Prefix, "micro-star", Kind::Computer),
    (Match::Prefix, "framework computer", Kind::Computer),
];

/// Is this address one of the ten blocks that cannot be told from a
/// placeholder?
///
/// `00:00:00` through `00:00:09` belong to XEROX CORPORATION, and they are
/// also what a half-initialised driver, a zeroed DHCP lease and a hand-typed
/// address look like. There are far more of those on a network built this
/// century than there are 1980s Xerox workstations, so an address in that
/// range yields no vendor clue at all. The registry's answer is correct; the
/// inference from it is what would be wrong, and "Printer, because its
/// hardware vendor makes only this kind" printed against `00:00:00:00:00:00`
/// is exactly the confident nonsense this module exists to avoid.
fn is_placeholder(mac: MacAddr) -> bool {
    mac.oui() <= 0x00_0009
}

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

    // The table is the outer loop and the device's own list is the inner one,
    // so that two services of equal rank are settled by `SERVICES`'s order
    // rather than by the order the records were laid out in one packet.
    let advertised: Vec<String> = identity
        .services
        .iter()
        .map(|service| service.to_ascii_lowercase())
        .collect();
    for (name, kind) in SERVICES {
        if advertised.iter().any(|service| service.starts_with(name)) {
            consider(*kind, Clue::Service);
        }
    }

    for port in found.open_ports() {
        if let Some((_, kind)) = PORTS.iter().find(|(number, _)| *number == port) {
            consider(*kind, Clue::Port);
        }
    }

    if let Some(mac) = found.mac
        && !is_placeholder(mac)
        && let Origin::Registered { name, .. } = vendor::lookup(mac)
    {
        let name = name.to_ascii_lowercase();
        if let Some((_, _, kind)) = VENDORS
            .iter()
            .find(|(mode, needle, _)| mode.matches(needle, &name))
        {
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

    /// The registry as `build.rs` reads it, so a needle can be checked against
    /// the same text the binary's table was compiled from.
    ///
    /// Read at run time rather than `include_str!`ed: it is 1.8 MB and nothing
    /// but this one test wants it.
    fn registry_organisations() -> Vec<String> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/data/oui.tsv");
        let text =
            std::fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
        text.lines()
            .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
            .filter_map(|line| line.split('\t').nth(2))
            .map(str::to_ascii_lowercase)
            .collect()
    }

    /// **The test that would have caught the two dead rows.**
    ///
    /// `mikrotik` and `aruba` sat in [`VENDORS`] matching nothing at all:
    /// MikroTik registers every block as Routerboard.com, and Aruba's
    /// assignments are held under Hewlett Packard Enterprise. Both looked like
    /// working entries and neither had ever fired. A needle that matches no
    /// organisation is not a harmless spare; it is a claim the table appears to
    /// make and cannot.
    ///
    /// It also has to keep catching it. The registry is refreshed with a
    /// release, the IEEE rewrites organisation names when it does, and an
    /// [`Match::Exact`] row is one rename away from going quietly dead.
    #[test]
    fn every_vendor_needle_matches_the_registry() {
        let names = registry_organisations();
        let mut dead = Vec::new();
        for (mode, needle, kind) in VENDORS {
            let hits = names
                .iter()
                .filter(|name| mode.matches(needle, name))
                .count();
            if hits == 0 {
                dead.push(format!("{mode:?}({needle:?}) -> {kind:?}"));
            }
        }
        assert!(
            dead.is_empty(),
            "these needles match no organisation in data/oui.tsv, so they can \
             never produce a guess: {dead:#?}"
        );
    }

    /// The mode is written down per row precisely so that a short name cannot
    /// reach into a longer company, and these are the four that it did.
    #[test]
    fn a_short_vendor_name_does_not_reach_into_a_longer_company() {
        for (mac, was, company) in [
            (
                [0x00, 0x08, 0xfb, 0x00, 0x00, 0x01],
                "a speaker",
                "SonoSite",
            ),
            (
                [0x00, 0x50, 0xb7, 0x00, 0x00, 0x01],
                "a speaker",
                "BOSER TECHNOLOGY",
            ),
            (
                [0x00, 0x17, 0x87, 0x00, 0x00, 0x01],
                "a printer",
                "Brother, Brother & Sons",
            ),
            (
                [0x70, 0xb3, 0xd5, 0xa4, 0xb0, 0x01],
                "a printer",
                "McKay Brothers",
            ),
            (
                [0x8c, 0x1f, 0x64, 0xf9, 0x10, 0x01],
                "a speaker",
                "Consonance",
            ),
            (
                [0xb4, 0xdf, 0x43, 0xc0, 0x00, 0x01],
                "a speaker",
                "Raven Resonance",
            ),
        ] {
            assert_eq!(
                identify(&host(&[], Some(mac)), &Identity::default(), false),
                None,
                "{company} was read as {was}"
            );
        }
    }

    /// And the companies the needles are actually for still answer.
    #[test]
    fn the_vendors_those_needles_are_for_still_match() {
        for (mac, expected) in [
            ([0x00, 0x0e, 0x58, 0x00, 0x00, 0x01], Kind::Speaker), // Sonos, Inc.
            ([0x60, 0xf6, 0x20, 0x00, 0x00, 0x01], Kind::Speaker), // Sonos Inc.
            ([0x40, 0x11, 0xdc, 0x00, 0x00, 0x01], Kind::Speaker), // Sonance
            ([0x00, 0x1b, 0xa9, 0x00, 0x00, 0x01], Kind::Printer), // Brother Industries
        ] {
            let guess = identify(&host(&[], Some(mac)), &Identity::default(), false);
            assert_eq!(guess.map(|g| g.kind), Some(expected), "{mac:02x?}");
        }
    }

    /// MikroTik's own name is nowhere in the IEEE registry, which is why the
    /// entry that used it never fired.
    #[test]
    fn mikrotik_is_found_under_the_name_it_actually_registered() {
        let routerboard = [0x00, 0x0c, 0x42, 0x00, 0x00, 0x01];
        let guess =
            identify(&host(&[], Some(routerboard)), &Identity::default(), false).expect("a guess");
        assert_eq!(guess.kind, Kind::NetworkGear);
        assert_eq!(guess.clue, Clue::Vendor);
    }

    /// The table had no phone vendor at all, so the commonest device on a home
    /// network was the one it could say least about.
    #[test]
    fn a_handset_maker_makes_it_a_phone() {
        let oppo = [0x00, 0xca, 0xe0, 0x00, 0x00, 0x01];
        let guess = identify(&host(&[], Some(oppo)), &Identity::default(), false).expect("a guess");
        assert_eq!(guess.kind, Kind::Phone);
        assert_eq!(guess.clue, Clue::Vendor);
    }

    /// XEROX CORPORATION holds `00:00:00` to `00:00:09`, so a zeroed or
    /// half-written address looks up as a printer manufacturer. It must not
    /// come out as a printer.
    #[test]
    fn a_placeholder_address_is_not_a_xerox_printer() {
        for mac in [
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x11, 0x22, 0x33],
            [0x00, 0x00, 0x09, 0x11, 0x22, 0x33],
        ] {
            assert_eq!(
                identify(&host(&[], Some(mac)), &Identity::default(), false),
                None,
                "{mac:02x?} was read as a vendor"
            );
        }
        // And a Xerox block from this century still is one.
        let xerox = [0x9c, 0x93, 0x4e, 0x00, 0x00, 0x01];
        let guess =
            identify(&host(&[], Some(xerox)), &Identity::default(), false).expect("a guess");
        assert_eq!(guess.kind, Kind::Printer);
    }

    /// Equal-rank clues used to be settled by whichever record the device
    /// happened to put first in its reply, which is a property of a packet
    /// rather than of a device.
    #[test]
    fn two_services_of_equal_rank_are_settled_by_the_table_not_the_packet() {
        let forwards = advertising(&["_airplay._tcp", "_raop._tcp"]);
        let backwards = advertising(&["_raop._tcp", "_airplay._tcp"]);
        assert_eq!(
            identify(&host(&[], None), &forwards, false),
            identify(&host(&[], None), &backwards, false),
            "the answer changed with the order of the advertised list"
        );
        assert_eq!(
            kind_of(&host(&[], None), &forwards, false),
            Kind::Television
        );
    }

    /// And an Apple TV is caught on a signal that is its own rather than on
    /// the ambiguous pair above.
    #[test]
    fn an_apple_tv_is_named_by_its_own_remote_protocol() {
        let apple_tv = advertising(&[
            "_raop._tcp",
            "_mediaremotetv._tcp",
            "_airplay._tcp",
            "_companion-link._tcp",
        ]);
        assert_eq!(
            kind_of(&host(&[], None), &apple_tv, false),
            Kind::Television
        );
    }

    /// `_companion-link._tcp` is on macOS, iOS, iPadOS and tvOS alike. It said
    /// "computer" for all four, which made every iPhone in range a desktop.
    #[test]
    fn companion_link_says_apple_and_nothing_more() {
        assert_eq!(
            identify(
                &host(&[], None),
                &advertising(&["_companion-link._tcp.local"]),
                false
            ),
            None
        );
    }

    /// Three service types were written without their siblings and so matched
    /// nothing that exists: eSCL over TLS, Matter's two discovery types, and
    /// every Android TV made since the remote protocol went to version two.
    #[test]
    fn the_service_siblings_that_were_missing_are_recognised() {
        for (service, expected) in [
            ("_uscans._tcp", Kind::Printer),
            ("_matterc._udp", Kind::SmartHome),
            ("_matterd._udp", Kind::SmartHome),
            ("_androidtvremote2._tcp", Kind::Television),
        ] {
            let guess =
                identify(&host(&[], None), &advertising(&[service]), false).expect("a guess");
            assert_eq!(guess.kind, expected, "{service}");
            assert_eq!(guess.clue, Clue::Service);
        }
    }

    /// The separator is what keeps `_uscan.` from swallowing `_uscans._tcp`,
    /// so a needle without it would silently conflate two service types.
    #[test]
    fn every_service_needle_ends_at_a_label_boundary() {
        for (name, _) in SERVICES {
            assert!(name.starts_with('_'), "{name} is not a service type");
            assert!(
                name.ends_with('.'),
                "{name} has no trailing dot, so it would also match any longer \
                 type beginning with those characters"
            );
        }
    }

    /// A port clue that names a kind is worthless if the default scan never
    /// probes that port, and for four of them it did not.
    #[test]
    fn every_port_the_kind_table_names_is_in_the_default_scan() {
        let common = crate::portscan::Ports::common();
        for (port, kind) in PORTS {
            assert!(
                common.as_slice().contains(port),
                "{port} names a {kind:?} here but is not in Ports::common, so \
                 the clue can never fire on a scan nobody configured"
            );
        }
    }

    #[test]
    fn the_ports_added_for_the_media_devices_produce_their_kinds() {
        for (port, expected) in [
            (8060u16, Kind::Television),
            (1400, Kind::Speaker),
            (8291, Kind::NetworkGear),
            (62078, Kind::Phone),
            (8006, Kind::Server),
        ] {
            let guess =
                identify(&host(&[port], None), &Identity::default(), false).expect("a guess");
            assert_eq!(guess.kind, expected, "port {port}");
            assert_eq!(guess.clue, Clue::Port);
        }
    }

    #[test]
    fn the_match_mode_says_how_far_a_needle_reaches() {
        assert!(Match::Contains.matches("tenda technology", "shen zhen tenda technology co.,ltd"));
        assert!(!Match::Prefix.matches("tenda technology", "shen zhen tenda technology co.,ltd"));
        assert!(Match::Prefix.matches("sonos, inc", "sonos, inc."));
        assert!(!Match::Prefix.matches("sonos, inc", "sonosite, inc."));
        assert!(Match::Exact.matches("netgear", "netgear"));
        assert!(!Match::Exact.matches("netgear", "netgear, inc."));
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
