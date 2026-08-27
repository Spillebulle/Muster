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
//! * The **silicon** is a separate and narrower claim: an Intel Corporate block
//!   is a network card, and a network card of that kind is in a computer. See
//!   [`CHIPSETS`], which exists because the vendor rule above had ruled out the
//!   one thing that could be said about most of the laptops on an office LAN.
//!
//! A hostname is deliberately **not** a clue. `HP-Printer` is usually right and
//! `daves-old-printer-pc` is a desktop; a name is written by whoever set the
//! device up and is evidence about them, not about the hardware.
//!
//! **This was tried the other way and taken out again**, so it is worth saying
//! what the trade actually is rather than leaving somebody to rediscover it. A
//! name table reaches a lot of devices that nothing else here can touch: a
//! printer answering only ARP called `HPLaserJet`, a television called
//! `LGwebOSTV-4`, a laptop with a randomised address called
//! `Janickes-MacBook-Pro`, card terminals called `VFI-347-262-554`. Ranked
//! last it also loses to every other clue, so the desktop above stays a
//! desktop. What it cannot do is be *certain*: a name is the one piece of
//! evidence a person can type, and this project would rather leave a row blank
//! than fill it with something that is usually true. `Unknown` is an answer
//! here, and the honest one.
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
    /// A card terminal: the thing a customer taps or a shop keeps by the till.
    ///
    /// Added because a real shop network came back as a column of blank rows.
    /// It earns a kind of its own rather than folding into [`Self::Computer`]
    /// because it is a fleet: on the networks that have one of these there are
    /// usually eight, they are the devices somebody is actually looking for,
    /// and nothing else on the list is that.
    ///
    /// **The hardware address is no help at all**, which is what makes this
    /// kind hard. A terminal is built around somebody else's radio module, so
    /// the four observed so far carried Huaqin, Zhong Ge, Murata and Quectel
    /// addresses — an ODM, a components house, a components house and a
    /// cellular module maker, none of which say anything about the finished
    /// product. The terminals that do own their blocks are in [`VENDORS`]; the
    /// rest are not found at all: their name is the only thing that says what
    /// they are, and a name is not evidence this module will act on. See the
    /// note at the top about what that costs.
    PaymentTerminal,
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
            Self::PaymentTerminal => "Payment terminal",
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
    /// It is the machine the scan is running on. Not an inference either.
    ///
    /// **The one device on the list that answers none of the questions.** A
    /// machine's own mDNS, NetBIOS and SSDP responders do not reply to
    /// datagrams the same machine sent out of its own interface, so the row for
    /// the computer somebody is sitting at came back with a hardware address, a
    /// motherboard vendor and nothing else — a blank icon in the middle of the
    /// list, and the one device whose identity was never in any doubt.
    ThisMachine,
    /// It advertised a service that says what it is.
    Service,
    /// It named its own model, over UPnP or in an mDNS `TXT` record.
    ///
    /// **Below [`Self::Service`], and it was written the other way round
    /// first.** A model string is more *specific* than a service type, which
    /// is the argument for ranking it above: `_airplay._tcp` cannot tell an
    /// Apple TV from a HomePod and `model=AudioAccessory5,1` can. What settles
    /// it the other way is that a service type is a protocol a device has to
    /// actually implement, and a model string is free text it can put anything
    /// in — and one very common kind of device puts something else in on
    /// purpose.
    ///
    /// Samba's `fruit:model` makes a file server advertise
    /// `model=MacPro7,1`, so that macOS draws a Mac in the sidebar instead of
    /// a generic box. TrueNAS, Synology, unRAID and OpenMediaVault all ship
    /// with it set. Ranked above the services, that one decoration turned
    /// every network-attached storage box on a real network into a desktop,
    /// beating the `_smb._tcp` the same device was honestly advertising.
    ///
    /// So the HomePod stays the known wrong answer `SERVICES` already
    /// documents, and a device that advertises no service at all — which is
    /// most televisions, and the case this clue was added for — is still named
    /// by its product string.
    Product,
    /// A port that only one kind of thing listens on.
    Port,
    /// Its hardware vendor makes one kind of thing.
    Vendor,
    /// The silicon inside it only ever goes into one kind of thing.
    ///
    /// A separate clue from [`Self::Vendor`] because it is a separate claim,
    /// and printing the vendor's reason against it would be a false one: Intel
    /// does not "make only computers", it makes the wireless card in one. What
    /// is true is the other direction — an Intel Corporate block ends up in a
    /// laptop, a desktop or a NUC and in nothing else — and that is a real
    /// clue about a device that answers nothing, which on an office network is
    /// most of the machines people sit in front of. [`CHIPSETS`] is kept to
    /// the blocks where that holds; the ones where it does not are named in
    /// [`VENDORS`]'s note about component makers, and Murata is in that note
    /// because a payment terminal was found wearing one.
    Chipset,
    /// It answered NetBIOS with a workgroup.
    ///
    /// **Ranked last, below the vendor, and that placement is the point.** It
    /// is a self-report, which would put it with the services, but what it
    /// reports is only "speaks SMB" — true of every Windows machine and of
    /// every NAS. Ranked with the services it made a Synology box read as a
    /// desktop, because the workgroup beat a vendor that makes nothing but
    /// storage.
    Workgroup,
    /// It answered LLMNR.
    ///
    /// Ranked below even the workgroup, and it is the weakest thing here that
    /// is still worth saying. LLMNR is spoken by Windows and by
    /// `systemd-resolved` and by nothing else that turns up on a home network,
    /// so a responder on 5355 is a general-purpose computer — but it is a
    /// *protocol* answering, not a device describing itself, and anything that
    /// knows better should beat it. It exists because a Windows desktop with
    /// its firewall on the public profile answers nothing else at all: no
    /// NetBIOS, no SSDP, no open port, and an mDNS name with no services
    /// behind it. That device was the commonest blank row on a real network.
    Llmnr,
}

impl Clue {
    /// How the interface explains the guess.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Gateway => "it is this network's gateway",
            Self::ThisMachine => "it is the machine running the scan",
            Self::Service => "it advertises a service only this kind offers",
            Self::Product => "it names a model only this kind has",
            Self::Port => "a port only this kind listens on is open",
            Self::Vendor => "its hardware vendor makes only this kind",
            Self::Chipset => "the silicon in it only goes into this kind",
            Self::Workgroup => "it answers NetBIOS with a workgroup, as Windows machines do",
            Self::Llmnr => "it answers LLMNR, which only computers do",
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
    // D-Link's own camera service. The camera it was taken from advertises
    // `_workstation._tcp` as well, and read as a desktop because of it.
    // `_dhnap._tcp` is on the same box and is deliberately not here: that is
    // D-Link's administration protocol and their routers speak it too.
    ("_dcamera.", Kind::Camera),
    // Thread's commissioning service, which a border router offers and nothing
    // else does.
    ("_meshcop.", Kind::SmartHome),
    // Media receivers that name their own brand, and so name the device.
    ("_sonos.", Kind::Speaker),
    ("_roku.", Kind::Television),
    ("_amzn-wplay.", Kind::Television),
    ("_androidtvremote2.", Kind::Television),
    ("_viziocast.", Kind::Television),
    // The Apple TV's pairing service, which no other Apple device offers.
    ("_appletv-v2.", Kind::Television),
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
    // Windows' own two: Delivery Optimization's peer cache and the remote
    // assistance service. Both are a Windows machine and neither is anything
    // else.
    ("_dosvc.", Kind::Computer),
    ("_teamviewer.", Kind::Computer),
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
    // ---- Payment terminals ----------------------------------------------
    // The makers whose own name is on the block, which is the minority: most
    // terminals are built on somebody else's radio module and are found by
    // by their name alone, which is not a clue here. See
    // [`Kind::PaymentTerminal`].
    (Match::Contains, "verifone", Kind::PaymentTerminal),
    (Match::Prefix, "ingenico", Kind::PaymentTerminal),
    (Match::Prefix, "pax computer", Kind::PaymentTerminal),
    (Match::Prefix, "castles technology", Kind::PaymentTerminal),
    (Match::Contains, "sunmi", Kind::PaymentTerminal),
    (Match::Prefix, "shenzhen xinguodu", Kind::PaymentTerminal), // NEXGO
    (
        Match::Prefix,
        "fujian newland payment",
        Kind::PaymentTerminal,
    ),
    (Match::Prefix, "fujian landi", Kind::PaymentTerminal),
    (Match::Prefix, "spire payments", Kind::PaymentTerminal),
    (Match::Prefix, "equinox payments", Kind::PaymentTerminal),
    (Match::Prefix, "ccv deutschland", Kind::PaymentTerminal),
    (Match::Prefix, "miura systems", Kind::PaymentTerminal),
    (Match::Prefix, "vanstone electronic", Kind::PaymentTerminal),
    (Match::Prefix, "beijing wiseasy", Kind::PaymentTerminal),
    // ---- Added after a real network came back blank ---------------------
    // Each of these was checked against the registry rather than guessed at,
    // which `every_vendor_needle_matches_the_registry` then keeps true.
    (Match::Prefix, "hmd global", Kind::Phone), // Nokia handsets, and only those
    (Match::Prefix, "hangzhou ezviz", Kind::Camera),
    (Match::Prefix, "cambium networks", Kind::NetworkGear),
    (Match::Contains, "meross", Kind::SmartHome),
];

/// Silicon and assembly houses whose blocks only ever end up in a computer.
///
/// [`VENDORS`] excludes the component makers on purpose and gives the reason:
/// a block held by a radio maker names the radio and not the thing it is
/// soldered into. That is right about most of them — a Murata address turned
/// out to be a card terminal, and a Realtek one is as likely to be a
/// television — and it is **wrong about the laptop trade**, where the part and
/// the product go together. An Intel Corporate block is a wireless card or an
/// Ethernet controller, and those go into laptops, desktops and NUCs and into
/// nothing else on a network; the ODMs below build the machines themselves
/// under other people's brands.
///
/// This was the commonest blank row on an office network by a distance. Intel
/// alone holds some six hundred and sixty blocks, and every laptop wearing one
/// came back as "nothing said anything" because the one thing that could be
/// said about it was ruled out by a rule aimed at somebody else.
///
/// The claim is narrower than a vendor's, so it makes a different one:
/// [`Clue::Chipset`] rather than [`Clue::Vendor`], ranked below it and worded
/// for what is actually true. The bar for a row here is that **every** product
/// the block turns up in is the same kind, which is why Hon Hai, Realtek,
/// AzureWave, Liteon and Murata are not on it: those are in phones,
/// televisions, set-top boxes, printers and card terminals as well.
const CHIPSETS: &[(Match, &str, Kind)] = &[
    (Match::Prefix, "intel corporate", Kind::Computer),
    (Match::Prefix, "intel corporation", Kind::Computer),
    // The notebook builders. Between them they assemble most of the laptops
    // that carry somebody else's badge.
    (Match::Prefix, "compal information", Kind::Computer),
    (Match::Prefix, "quanta computer", Kind::Computer),
    (Match::Prefix, "wistron", Kind::Computer),
    (Match::Prefix, "pegatron", Kind::Computer),
    (Match::Prefix, "clevo", Kind::Computer),
];

/// UPnP device and service types that name a kind.
///
/// Matched as a substring of the lower-cased URN, because the version suffix
/// changes (`:1`, `:2`) and some vendors prefix their own namespace.
///
/// **The general types are deliberately absent.** `upnp:rootdevice` says only
/// that a UPnP stack is running; `device:Basic` is the type for anything that
/// did not fit; and `device:MediaRenderer` is a television, a soundbar, an AV
/// receiver or a speaker, which is four kinds and therefore no clue. What is
/// here is the handful where the type is the device.
const UPNP: &[(&str, Kind)] = &[
    // DIAL: the second-screen launch protocol. Televisions, streaming sticks
    // and the boxes that behave like them, and nothing else at all.
    ("dial-multiscreen-org", Kind::Television),
    ("device:tvdevice", Kind::Television),
    // LG uses two namespaces of its own, and one real television answered with
    // both: `urn:lge:device:tv:1` and `urn:lge-com:service:webos-second-screen`.
    ("lge:device:tv", Kind::Television),
    ("lge-com", Kind::Television),
    ("roku:ecp", Kind::Television),
    ("samsung.com:device:remotecontrolreceiver", Kind::Television),
    ("schemas-sony-com:service:scalarweb", Kind::Television),
    ("device:zoneplayer", Kind::Speaker), // Sonos
    ("schemas-denon-com", Kind::Speaker),
    ("device:printer", Kind::Printer),
    ("service:printbasic", Kind::Printer),
    ("device:mediaserver", Kind::Server),
    // The router half of UPnP: port mapping, and the TR-064 configuration
    // service a modem or a Fritz!Box offers.
    ("device:internetgatewaydevice", Kind::NetworkGear),
    ("device:wandevice", Kind::NetworkGear),
    ("device:wanconnectiondevice", Kind::NetworkGear),
    ("dslforum-org", Kind::NetworkGear),
];

/// WS-Discovery `Types`, as a device claims them about itself.
///
/// The same class of self-report as an mDNS service or a UPnP device type, and
/// ranked with them as [`Clue::Service`]: a `Types` value is a protocol the
/// device implements and publishes, not free text it filled in.
///
/// **Matched with the namespace prefix on**, and that is what makes it safe.
/// `Computer` on its own is a word; `pub:Computer` is Microsoft's publication
/// namespace saying the thing is a PC. Every needle here is the prefix the
/// namespace's own specification defines and every implementation in the field
/// uses, and the prefix is matched as a substring so a responder that writes
/// `wsdp:` where another writes `d:` still lands on the same row.
///
/// `wsdp:device` is deliberately absent. Every WS-Discovery responder claims
/// it, so it says only "this is a device that answers WS-Discovery" — which the
/// reply itself already said, and which names no kind at all.
const WSD: &[(&str, Kind)] = &[
    // Microsoft's publication namespace. This is the one that matters: it is
    // what a Windows machine answers with, and on an office network it is the
    // only thing that names the machines people sit in front of.
    ("pub:computer", Kind::Computer),
    // WSD-Print, which every network printer of the last fifteen years speaks
    // and which Windows uses to find them.
    ("printdevicetype", Kind::Printer),
    // WSD-Scan. A scanner on a network is part of a multi-function printer
    // often enough that the two share a kind, and [`Kind`] has no `Scanner`
    // for the same reason it has no `Laptop`.
    ("scandevicetype", Kind::Printer),
    // ONVIF. `NetworkVideoTransmitter` is the profile every IP camera
    // implements, and `NetworkVideoDisplay`, `NetworkVideoStorage` and
    // `NetworkVideoAnalytics` are the rest of the family — a recorder is
    // camera equipment, and there is nothing else it could be.
    ("networkvideotransmitter", Kind::Camera),
    ("networkvideodisplay", Kind::Camera),
    ("networkvideostorage", Kind::Camera),
    ("networkvideoanalytics", Kind::Camera),
];

/// HomeKit accessory categories, by the number an accessory publishes.
///
/// HAP §6.4 has an accessory state its category in the `ci` key of its `_hap`
/// `TXT` record, out of a fixed list Apple defines. It is the same class of
/// claim as a service type - a number inside a protocol the device had to
/// implement to answer at all, not free text - so it produces
/// [`Clue::Service`], and [`identify`] consults it **before** the service table
/// so that it beats the `_hap.` row there when both fire. That row can only
/// ever say `SmartHome`, which for a doorbell camera or a television is the
/// wrong half of the answer.
///
/// The numbers are Apple's, checked against the published list rather than
/// guessed at, and the gaps in this table are the point:
///
/// * **1 (Other) and 2 (Bridge) are absent.** `Other` is the category an
///   accessory picks when none of the rest fit, and a bridge is a thing that
///   speaks for other things - a Hue hub is one and so is a Raspberry Pi
///   running Homebridge, which is a computer. Neither names a kind.
/// * **32 (Target controller) is absent** for the same reason: it is a remote
///   control, and [`Kind`] has nothing it belongs to.
/// * The rest of the smart-home rows collapse a dozen categories into one
///   kind, which is what [`Kind::SmartHome`] is for. A `Kind` per HomeKit
///   category would be a longer list of things to be wrong about, and the
///   exact category is still on the row as a fact.
const HAP_CATEGORIES: &[(u16, Kind)] = &[
    (3, Kind::SmartHome),  // Fan
    (4, Kind::SmartHome),  // Garage door opener
    (5, Kind::SmartHome),  // Lightbulb
    (6, Kind::SmartHome),  // Door lock
    (7, Kind::SmartHome),  // Outlet
    (8, Kind::SmartHome),  // Switch
    (9, Kind::SmartHome),  // Thermostat
    (10, Kind::SmartHome), // Sensor
    (11, Kind::SmartHome), // Security system
    (12, Kind::SmartHome), // Door
    (13, Kind::SmartHome), // Window
    (14, Kind::SmartHome), // Window covering
    (15, Kind::SmartHome), // Programmable switch
    // A range extender, an AirPort and a router are all somebody's networking
    // equipment. Where one of them is also the way off the network,
    // [`Clue::Gateway`] has already answered.
    (16, Kind::NetworkGear), // Range extender
    // The two this table was worth writing for. A HomeKit camera and a video
    // doorbell both advertise `_hap._tcp` and nothing else that names them, so
    // both were smart-home icons in a column of smart-home icons.
    (17, Kind::Camera),      // IP camera
    (18, Kind::Camera),      // Video doorbell
    (19, Kind::SmartHome),   // Air purifier
    (20, Kind::SmartHome),   // Heater
    (21, Kind::SmartHome),   // Air conditioner
    (22, Kind::SmartHome),   // Humidifier
    (23, Kind::SmartHome),   // Dehumidifier
    (24, Kind::Television),  // Apple TV
    (25, Kind::Speaker),     // HomePod
    (26, Kind::Speaker),     // Speaker
    (27, Kind::NetworkGear), // AirPort
    (28, Kind::SmartHome),   // Sprinkler
    (29, Kind::SmartHome),   // Faucet
    (30, Kind::SmartHome),   // Shower head
    (31, Kind::Television),  // Television
    (33, Kind::NetworkGear), // Router
    (34, Kind::Speaker),     // Audio receiver
    (35, Kind::Television),  // Television set-top box
    (36, Kind::Television),  // Television streaming stick
];

/// Product names, as a device writes them about itself.
///
/// Two sources, one table, because they are the same kind of statement: the
/// `SERVER` header of an SSDP reply (`Linux/4.19 UPnP/1.0 LG WebOS TV/1.0`) and
/// the model in an mDNS `TXT` record (`model=AudioAccessory5,1` from
/// `_device-info._tcp`, `md=SHIELD Android TV` from `_googlecast._tcp`).
///
/// Matched as a substring of the lower-cased string, and the needles have to be
/// chosen for that: a `SERVER` header is mostly boilerplate — `Linux/3.4`,
/// `UPnP/1.0`, `MiniUPnPd/1.9` — and every one of those boilerplate tokens
/// appears on routers, televisions and network-attached storage alike, so none
/// of them is here. The needle has to be the part a vendor wrote.
const PRODUCTS: &[(Match, &str, Kind)] = &[
    // Apple's model identifiers, which are the most precise self-report on any
    // network: `iPhone14,2`, `Mac14,2`, `AppleTV11,1`, `AudioAccessory5,1`.
    // Every one is a [`Match::Prefix`], because an identifier is the whole of
    // what the device said and a substring would go looking for it inside
    // other people's product names.
    (Match::Prefix, "appletv", Kind::Television),
    (Match::Prefix, "audioaccessory", Kind::Speaker),
    (Match::Prefix, "homepod", Kind::Speaker),
    (Match::Prefix, "iphone", Kind::Phone),
    // No `Tablet` kind, and an iPad is a general purpose machine, so it lands
    // where a laptop does.
    (Match::Prefix, "ipad", Kind::Computer),
    (Match::Prefix, "imac", Kind::Computer),
    // Every Mac since 2022 reports `Mac<n>,<n>` and the older ones report
    // `MacBookPro`, `Macmini` and `MacPro`, so one prefix covers the family.
    // As a substring it would also match Sagemcom, which makes routers.
    (Match::Prefix, "mac", Kind::Computer),
    (Match::Prefix, "airport", Kind::NetworkGear), // Express, Extreme, Time Capsule
    // Streaming and casting, by the name on the box. These arrive inside a
    // `SERVER` header as often as alone, so they reach.
    (Match::Contains, "shield android tv", Kind::Television),
    (Match::Contains, "chromecast", Kind::Television),
    (Match::Contains, "android tv", Kind::Television),
    (Match::Contains, "fire tv", Kind::Television),
    (Match::Contains, "webos", Kind::Television),
    (Match::Contains, "tizen", Kind::Television),
    (Match::Contains, "bravia", Kind::Television),
    (Match::Contains, "roku", Kind::Television),
    (Match::Contains, "nest hub", Kind::Speaker),
    (Match::Contains, "google home", Kind::Speaker),
    (Match::Contains, "nest audio", Kind::Speaker),
    (Match::Contains, "nest mini", Kind::Speaker),
    (Match::Contains, "sonos", Kind::Speaker),
    (Match::Contains, "soundtouch", Kind::Speaker),
    (Match::Contains, "heos", Kind::Speaker),
    (Match::Contains, "xbox", Kind::GameConsole),
    (Match::Contains, "playstation", Kind::GameConsole),
    // Storage and the things that serve from it. `plex` is a prefix and not a
    // substring, because it is also the back half of "duplexer".
    (Match::Contains, "synology", Kind::Server),
    (Match::Contains, "qnap", Kind::Server),
    (Match::Contains, "asustor", Kind::Server),
    (Match::Contains, "truenas", Kind::Server),
    (Match::Prefix, "plex", Kind::Server),
    // Printers, by the series name in an `_ipp` record's `ty=`.
    (Match::Contains, "laserjet", Kind::Printer),
    (Match::Contains, "officejet", Kind::Printer),
    (Match::Contains, "deskjet", Kind::Printer),
    (Match::Contains, "pixma", Kind::Printer),
    (Match::Contains, "ecotank", Kind::Printer),
    (Match::Contains, "workforce", Kind::Printer),
    // HP's embedded server, which is on their printers and on nothing else.
    (Match::Contains, "hp-chaisoe", Kind::Printer),
    (Match::Contains, "hikvision", Kind::Camera),
    (Match::Contains, "dahua", Kind::Camera),
    (Match::Contains, "reolink", Kind::Camera),
    (Match::Contains, "ipbridge", Kind::SmartHome), // the Philips Hue bridge
    (Match::Contains, "shelly", Kind::SmartHome),
    // Router firmware, named by the people who wrote it.
    (Match::Contains, "mikrotik", Kind::NetworkGear),
    (Match::Contains, "asuswrt", Kind::NetworkGear),
    (Match::Contains, "openwrt", Kind::NetworkGear),
    (Match::Contains, "dd-wrt", Kind::NetworkGear),
    (Match::Contains, "fritz", Kind::NetworkGear),
    (Match::Contains, "unifi", Kind::NetworkGear),
    // **Last, and that placement is the table's only tie-break that matters.**
    // A Windows machine running Plex answers with both, and the box is a
    // computer that happens to serve rather than a server; every other needle
    // above names a purpose-built device, so anything matching one of those as
    // well as this is that device.
    (Match::Contains, "microsoft-windows", Kind::Computer),
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

/// What the scan knows about a device without having asked it anything.
///
/// Two facts, both of them the caller's, because they come from where the scan
/// is standing rather than from the device: only the survey knows the routing
/// table and the machine's own addresses. They are grouped rather than passed
/// as a pair of booleans so that a third one — a switch port from LLDP, when
/// the privileged engine lands — has somewhere to go.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Vantage {
    /// This device is a default gateway.
    pub gateway: bool,
    /// This device is the machine the scan is running on.
    pub this_machine: bool,
}

impl Vantage {
    /// The gateway, and nothing else known.
    pub const fn gateway(gateway: bool) -> Self {
        Self {
            gateway,
            this_machine: false,
        }
    }
}

/// What this device appears to be, and why.
pub fn identify(found: &Found, identity: &Identity, vantage: Vantage) -> Option<Guess> {
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

    if vantage.gateway {
        consider(Kind::Router, Clue::Gateway);
    }

    // Ranked below the gateway, because a machine that is both is more useful
    // described as the way off the network than as somebody's desktop.
    if vantage.this_machine {
        consider(Kind::Computer, Clue::ThisMachine);
    }

    // A NetBIOS node status reply carrying a workgroup is a machine saying it
    // is a Windows machine, or a Samba host pretending to be one convincingly
    // enough that the distinction does not matter to somebody reading a device
    // list. It is a self-report, so it ranks with the services.
    if identity.workgroup.is_some() {
        consider(Kind::Computer, Clue::Workgroup);
    }

    // Weaker than the workgroup and, on the machines this was added for, the
    // only thing there is. See [`Clue::Llmnr`].
    if identity.llmnr {
        consider(Kind::Computer, Clue::Llmnr);
    }

    // What the device says it *is*, before what it says it *does*. Both the
    // SSDP `SERVER` header and an mDNS model string are searched against one
    // table, so a device that names itself in either place is read the same
    // way; the table is the outer loop for the same reason it is below.
    let named: Vec<String> = identity
        .product
        .iter()
        .chain(identity.model.iter())
        .map(|product| product.to_ascii_lowercase())
        .collect();
    for (mode, needle, kind) in PRODUCTS {
        if named.iter().any(|product| mode.matches(needle, product)) {
            consider(*kind, Clue::Product);
        }
    }

    // **Before the service table, and that is the whole of what this clue
    // buys.** Both produce `Clue::Service` and `consider` keeps the first of an
    // equal pair, so the order here is the tie-break: `SERVICES` can only say
    // that `_hap._tcp` is something in a house, and the category says which
    // thing. Asked in the other order, every HomeKit camera and doorbell on the
    // network would stay a smart-home icon.
    if let Some(category) = identity.hap
        && let Some((_, kind)) = HAP_CATEGORIES.iter().find(|(id, _)| *id == category)
    {
        consider(*kind, Clue::Service);
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

    // UPnP device types, which are the same class of self-report as an mDNS
    // service and are ranked with them. `identity.upnp` is already lower cased
    // by [`crate::ssdp::Announcement::types`].
    for (needle, kind) in UPNP {
        if identity.upnp.iter().any(|urn| urn.contains(needle)) {
            consider(*kind, Clue::Service);
        }
    }

    // And WS-Discovery's, which is a third vocabulary for the same kind of
    // claim. `identity.wsd` is already lower cased by [`crate::wsd::parse`].
    for (needle, kind) in WSD {
        if identity.wsd.iter().any(|claim| claim.contains(needle)) {
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
        // Below the vendor, and only where the vendor said nothing: the same
        // registry name, read for what the part goes into rather than for what
        // the company sells. See [`CHIPSETS`].
        if let Some((_, _, kind)) = CHIPSETS
            .iter()
            .find(|(mode, needle, _)| mode.matches(needle, &name))
        {
            consider(*kind, Clue::Chipset);
        }
    }

    best
}

/// The kind alone, with [`Kind::Unknown`] where nothing was learned.
pub fn kind_of(found: &Found, identity: &Identity, vantage: Vantage) -> Kind {
    identify(found, identity, vantage).map_or(Kind::Unknown, |guess| guess.kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discover::{Evidence, Protocol};
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
            services: services.iter().map(|s| (*s).to_string()).collect(),
            ..Default::default()
        }
    }

    /// A device that answered SSDP with these types and this `SERVER`.
    fn announcing(types: &[&str], server: Option<&str>) -> Identity {
        Identity {
            upnp: types.iter().map(|t| t.to_ascii_lowercase()).collect(),
            product: server.map(str::to_string),
            ..Default::default()
        }
    }

    /// A device that named its own model over mDNS.
    fn modelled(model: &str) -> Identity {
        Identity {
            model: Some(model.to_string()),
            ..Default::default()
        }
    }

    /// The case that started this: a device answering NetBIOS with a workgroup
    /// and nothing else was read as a Windows desktop, and it is a television.
    ///
    /// Nothing about the workgroup rule was wrong. What was missing is that
    /// nobody had asked the device what it offers, so the service that names it
    /// never reached this function.
    #[test]
    fn a_shield_that_answers_netbios_is_still_a_television() {
        let mut identity = advertising(&["_androidtvremote2._tcp", "_googlecast._tcp"]);
        identity.workgroup = Some("WORKGROUP".into());
        let guess = identify(&host(&[], None), &identity, Vantage::default()).expect("a guess");
        assert_eq!(guess.kind, Kind::Television);
        assert_eq!(guess.clue, Clue::Service);
    }

    /// The whole of what the HomeKit category buys: `_hap._tcp` says "something
    /// in a house" and the category says which thing.
    #[test]
    fn a_homekit_doorbell_is_a_camera_and_not_a_smart_plug() {
        let mut identity = advertising(&["_hap._tcp"]);
        // Without the category, the service table can only say `SmartHome`,
        // which is the answer every HomeKit accessory used to get.
        let guess = identify(&host(&[], None), &identity, Vantage::default()).expect("a guess");
        assert_eq!(guess.kind, Kind::SmartHome);

        identity.hap = Some(18);
        let guess = identify(&host(&[], None), &identity, Vantage::default()).expect("a guess");
        assert_eq!(guess.kind, Kind::Camera, "18 is a video doorbell");
        assert_eq!(guess.clue, Clue::Service, "a number in a protocol, not free text");
    }

    /// A category nobody has heard of is not a kind. HomeKit's list grows, and
    /// an accessory in a category added after this table was written must come
    /// out as whatever the rest of the evidence says rather than as a guess.
    #[test]
    fn a_category_this_table_does_not_know_names_nothing() {
        let mut identity = advertising(&["_hap._tcp"]);
        identity.hap = Some(99);
        let guess = identify(&host(&[], None), &identity, Vantage::default()).expect("a guess");
        assert_eq!(guess.kind, Kind::SmartHome, "the service is still a service");
    }

    /// The table is Apple's list, and the rows that are missing from it are as
    /// deliberate as the ones in it.
    #[test]
    fn the_homekit_table_is_apples_list_and_says_nothing_it_should_not() {
        let mut seen: Vec<u16> = HAP_CATEGORIES.iter().map(|(id, _)| *id).collect();
        let count = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), count, "a category cannot name two kinds");
        for (id, kind) in HAP_CATEGORIES {
            assert!((3..=36).contains(id), "{id} is not a category Apple defines");
            assert_ne!(*kind, Kind::Unknown, "a row that names nothing is not a row");
        }
        // `Other`, `Bridge` and `Target controller` name no kind, and a bridge
        // is a Hue hub as readily as it is a computer running Homebridge.
        for absent in [1u16, 2, 32] {
            assert!(
                !seen.contains(&absent),
                "{absent} names no kind and must not be in the table"
            );
        }
    }

    /// The `Scopes` of a WS-Discovery reply name the hardware, and they were
    /// parsed and dropped. A model ranks below a service, which is the second
    /// half of this test.
    ///
    /// The device identifier is **constructed from Microsoft's WS-Print
    /// documentation rather than captured**; the spelling is the one that
    /// documentation gives.
    #[test]
    fn a_printer_named_only_by_its_scopes_is_still_a_printer() {
        let mut identity = Identity::default();
        identity.probed(&crate::wsd::Match {
            scopes: vec!["MFG:HP;MDL:HP LaserJet MFP M428fdw".into()],
            ..Default::default()
        });
        let guess = identify(&host(&[], None), &identity, Vantage::default()).expect("a guess");
        assert_eq!(guess.kind, Kind::Printer);
        assert_eq!(guess.clue, Clue::Product, "a model is what a scope carries");

        // And where the same reply also claims a type, the type wins: a model
        // is free text and a `Types` value is a protocol the device has to
        // implement. `CLAUDE.md`, and the reason `Clue::Product` sits below
        // `Clue::Service`.
        identity.wsd.push("wprt:printdevicetype".into());
        let guess = identify(&host(&[], None), &identity, Vantage::default()).expect("a guess");
        assert_eq!(guess.clue, Clue::Service);
    }

    /// A UPnP device type is the same class of statement as an mDNS service and
    /// is ranked with it. DIAL is on televisions and streaming boxes only.
    #[test]
    fn a_upnp_type_names_a_kind() {
        let guess = identify(
            &host(&[], None),
            &announcing(&["urn:dial-multiscreen-org:device:dial:1"], None),
            Vantage::default(),
        )
        .expect("a guess");
        assert_eq!(guess.kind, Kind::Television);
        assert_eq!(guess.clue, Clue::Service);
    }

    /// The LG television from a real scan: two addresses, one MAC, a vendor
    /// that makes five of the kinds, no open ports and no mDNS at all. The
    /// `SERVER` header is the only thing on the wire that says what it is.
    #[test]
    fn a_server_header_names_a_product_where_the_vendor_cannot() {
        let guess = identify(
            &host(&[], None),
            &announcing(&[], Some("Linux/4.19 UPnP/1.0 LG WebOS TV/1.0")),
            Vantage::default(),
        )
        .expect("a guess");
        assert_eq!(guess.kind, Kind::Television);
        assert_eq!(guess.clue, Clue::Product);
    }

    /// Found on a real network within a minute of the model clue existing: a
    /// TrueNAS box advertising `_smb._tcp` and `model=MacPro7,1`, which is
    /// Samba's `fruit:model` asking macOS to draw it a Mac.
    ///
    /// The service is what the device does and the model is what it would like
    /// to be taken for, so the service wins. See [`Clue::Product`].
    #[test]
    fn a_file_server_pretending_to_be_a_mac_is_still_a_server() {
        let mut identity = advertising(&["_smb._tcp", "_device-info._tcp"]);
        identity.model = Some("MacPro7,1".into());
        let guess = identify(&host(&[], None), &identity, Vantage::default()).expect("a guess");
        assert_eq!(guess.kind, Kind::Server);
        assert_eq!(guess.clue, Clue::Service);
    }

    /// And with nothing else to go on the model is still taken, which is the
    /// whole point of having it.
    #[test]
    fn a_model_names_a_device_that_advertises_nothing() {
        let guess = identify(&host(&[], None), &modelled("MacPro7,1"), Vantage::default())
            .expect("a guess");
        assert_eq!(guess.kind, Kind::Computer);
        assert_eq!(guess.clue, Clue::Product);
    }

    #[test]
    fn a_cast_model_is_read_as_the_name_on_the_box() {
        for (model, kind) in [
            ("SHIELD Android TV", Kind::Television),
            ("Chromecast Ultra", Kind::Television),
            ("Google Nest Mini", Kind::Speaker),
            ("iPhone14,2", Kind::Phone),
            ("Mac14,2", Kind::Computer),
            ("MacBookPro18,3", Kind::Computer),
            ("HP OfficeJet 6950", Kind::Printer),
        ] {
            let guess = identify(&host(&[], None), &modelled(model), Vantage::default())
                .unwrap_or_else(|| panic!("{model} names nothing"));
            assert_eq!(guess.kind, kind, "{model}");
            assert_eq!(guess.clue, Clue::Product, "{model}");
        }
    }

    /// `Mac14,2` is a computer and `Mac` is not a needle that may match
    /// anything else, so the table spells the families out.
    #[test]
    fn a_product_needle_does_not_reach_past_its_own_product() {
        // "roku" must not be found inside an unrelated word, and "plex" must
        // not match "Plexus" — the substring rule is what makes both possible,
        // so both are asserted rather than assumed.
        assert!(
            identify(
                &host(&[], None),
                &modelled("Duplexer 3000"),
                Vantage::default()
            )
            .is_none()
        );
        assert!(
            identify(
                &host(&[], None),
                &modelled("Kodak Verite"),
                Vantage::default()
            )
            .is_none()
        );
    }

    /// The Windows desktop behind its own firewall: no NetBIOS, no services,
    /// no open ports, a motherboard vendor that makes five kinds of thing.
    #[test]
    fn llmnr_is_the_last_thing_that_still_says_computer() {
        let identity = Identity {
            llmnr: true,
            ..Default::default()
        };
        let guess = identify(&host(&[], None), &identity, Vantage::default()).expect("a guess");
        assert_eq!(guess.kind, Kind::Computer);
        assert_eq!(guess.clue, Clue::Llmnr);
    }

    /// And it is beaten by everything, including the weakest clue above it.
    #[test]
    fn anything_at_all_beats_llmnr() {
        let identity = Identity {
            llmnr: true,
            ..advertising(&["_ipp._tcp"])
        };
        assert_eq!(
            identify(&host(&[], None), &identity, Vantage::default())
                .unwrap()
                .kind,
            Kind::Printer
        );
        // A vendor is the weakest clue above it, and it still wins.
        let identity = Identity {
            llmnr: true,
            ..Default::default()
        };
        let sonos = identify(&host(&[], None), &identity, Vantage::default());
        assert_eq!(
            sonos.unwrap().clue,
            Clue::Llmnr,
            "with no vendor to beat it"
        );
        let with_vendor = identify(
            &host(&[], Some([0x00, 0x0e, 0x58, 1, 2, 3])),
            &identity,
            Vantage::default(),
        )
        .expect("a guess");
        assert_eq!(with_vendor.kind, Kind::Speaker, "the Sonos block");
        assert_eq!(with_vendor.clue, Clue::Vendor);
    }

    /// The blank row in the middle of every scan: the machine somebody is
    /// sitting at. Its own responders do not answer its own datagrams, so it
    /// arrives here with a hardware address and nothing else.
    #[test]
    fn the_machine_running_the_scan_is_known_without_asking_it() {
        let vantage = Vantage {
            gateway: false,
            this_machine: true,
        };
        let guess = identify(&host(&[], None), &Identity::default(), vantage).expect("a guess");
        assert_eq!(guess.kind, Kind::Computer);
        assert_eq!(guess.clue, Clue::ThisMachine);
    }

    /// And a machine that routes for the network is described as the way off
    /// it, which is the more useful of two true things.
    #[test]
    fn a_machine_that_is_also_the_gateway_is_the_gateway() {
        let vantage = Vantage {
            gateway: true,
            this_machine: true,
        };
        let guess = identify(&host(&[], None), &Identity::default(), vantage).expect("a guess");
        assert_eq!(guess.kind, Kind::Router);
    }

    #[test]
    fn the_gateway_is_not_a_guess() {
        let guess = identify(
            &host(&[], None),
            &Identity::default(),
            Vantage::gateway(true),
        )
        .expect("a guess");
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
            Vantage::default(),
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
        let guess = identify(
            &host(&[554], Some(ubiquiti)),
            &Identity::default(),
            Vantage::default(),
        )
        .expect("a guess");
        assert_eq!(guess.kind, Kind::Camera);
        assert_eq!(guess.clue, Clue::Port);
    }

    #[test]
    fn a_vendor_that_makes_one_thing_is_enough_on_its_own() {
        // Sonos make speakers and nothing else, which is the whole test for
        // whether a vendor belongs in the table.
        let sonos = [0x00, 0x0e, 0x58, 0x00, 0x00, 0x01];
        let guess = identify(
            &host(&[], Some(sonos)),
            &Identity::default(),
            Vantage::default(),
        )
        .expect("a guess");
        assert_eq!(guess.kind, Kind::Speaker);
        assert_eq!(guess.clue, Clue::Vendor);
    }

    #[test]
    fn nothing_learned_is_reported_as_nothing_learned() {
        // The common case on a real network, and the one a scanner is most
        // tempted to fill in with a guess.
        assert_eq!(
            identify(&host(&[], None), &Identity::default(), Vantage::default()),
            None
        );
        assert_eq!(
            kind_of(&host(&[], None), &Identity::default(), Vantage::default()),
            Kind::Unknown
        );
    }

    #[test]
    fn a_randomised_address_yields_no_vendor_guess() {
        // Bit 1 of the first octet set: the device made this address up, so
        // there is no manufacturer behind it to reason from.
        let randomised = [0x7a, 0x0e, 0x58, 0x00, 0x00, 0x01];
        assert_eq!(
            identify(
                &host(&[], Some(randomised)),
                &Identity::default(),
                Vantage::default()
            ),
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
                Vantage::default()
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
        let guess = identify(&host(&[], None), &identity, Vantage::default()).expect("a guess");
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
        let guess =
            identify(&host(&[], Some(synology)), &identity, Vantage::default()).expect("a guess");
        assert_eq!(guess.kind, Kind::Server);
        assert_eq!(guess.clue, Clue::Vendor);
    }

    #[test]
    fn advertising_ssh_makes_it_a_computer() {
        let guess = identify(
            &host(&[], None),
            &advertising(&["_ssh._tcp.local"]),
            Vantage::default(),
        )
        .expect("a guess");
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
        assert_eq!(
            identify(&host(&[], None), &identity, Vantage::default()),
            None
        );
    }

    /// Eight devices a real shop network could not name, kept as a record of
    /// what the rule above costs and of what would answer each of them.
    ///
    /// These are recorded observations rather than inventions, which is what
    /// `CLAUDE.md` asks a fingerprint table to be driven from. Every one of
    /// them has a name that says exactly what it is, and every one of them is
    /// [`Kind::Unknown`] here, because a name is not evidence this module acts
    /// on. **That is the intended answer, not a defect**, and this test exists
    /// so that a change which starts reading names has to come here and say so
    /// out loud rather than quietly turning eight rows into guesses.
    ///
    /// What would name them honestly is written against each: for most, a port
    /// scan or an SSDP reply the sweep did not have.
    #[test]
    fn the_devices_a_real_shop_network_could_not_name() {
        for (name, mac, would_answer_it) in [
            // HP make laptops as well as printers, so the block says nothing.
            // Port 9100 or 631 would settle it, and neither was scanned.
            (
                "HPLaserJet.local",
                [0x28, 0xc5, 0xc8, 0x1c, 0x72, 0xd9],
                "an open 9100 or 631, or the _ipp record it did not send",
            ),
            // Four card terminals on four component makers' blocks: an ODM, a
            // components house, another, and a cellular module maker. See
            // [`Kind::PaymentTerminal`].
            (
                "S1F4Pro-000195254265067",
                [0xc4, 0x60, 0x0a, 0x78, 0x6f, 0xf5],
                "nothing on the wire; the block is Huaqin's, an ODM",
            ),
            (
                "S1F2-000158223788345",
                [0xc4, 0x6e, 0x33, 0x7c, 0x76, 0xfd],
                "nothing on the wire; the block is a components house's",
            ),
            (
                "VFI-347-262-554",
                [0x58, 0xd5, 0x0a, 0xab, 0x6a, 0x6f],
                "nothing on the wire; the block is Murata's, a radio maker",
            ),
            (
                "P630-452345389",
                [0xec, 0x1d, 0x9e, 0xdb, 0x79, 0xed],
                "nothing on the wire; the block is Quectel's, a module maker",
            ),
            // LG Innotek make camera modules and lighting as well as the
            // radios in televisions. A multicast SSDP M-SEARCH would have had
            // this one: an LG television answers `urn:lge:device:tv:1`, which
            // `UPNP` already reads.
            (
                "LGwebOSTV-4.local",
                [0x60, 0xab, 0x14, 0x68, 0x2b, 0x44],
                "the SSDP reply an LG television gives to a multicast M-SEARCH",
            ),
            // A MacBook with a randomised address: no vendor, no services, and
            // the name is all there is. Nothing would answer this one without
            // asking the machine something it did not answer.
            (
                "Janickes-MacBook-Pro.local",
                [0xae, 0xcc, 0x66, 0x8e, 0xda, 0xd8],
                "an _rfb, _ssh or _companion-link record, or an open 5900",
            ),
        ] {
            let identity = Identity {
                names: vec![Name {
                    value: name.to_string(),
                    source: Source::Mdns,
                }],
                ..Identity::default()
            };
            let guess = identify(&host(&[], Some(mac)), &identity, Vantage::default());
            assert_eq!(
                guess, None,
                "{name} is deliberately blank; what would name it is {would_answer_it}"
            );
        }
    }

    /// The eighth of them, and the one that is answered: a laptop whose name is
    /// a fleet number and whose wireless card is the evidence.
    #[test]
    fn the_card_in_a_laptop_names_it_where_the_name_could_not() {
        let identity = Identity {
            names: vec![Name {
                value: "LT-00036".to_string(),
                source: Source::ReverseDns,
            }],
            ..Identity::default()
        };
        let guess = identify(
            &host(&[], Some([0x30, 0xf6, 0xef, 0x7c, 0x07, 0xea])),
            &identity,
            Vantage::default(),
        )
        .expect("an Intel block is a network card, and that card is in a computer");
        assert_eq!(guess.kind, Kind::Computer);
        assert_eq!(guess.clue, Clue::Chipset);
    }

    /// Both halves of the registry read the same way, so the same casing rule
    /// applies to the second table as to the first.
    #[test]
    fn the_chipset_needles_are_lower_case() {
        for (_, needle, _) in CHIPSETS {
            assert_eq!(*needle, needle.to_ascii_lowercase(), "{needle}");
        }
    }

    #[test]
    fn every_chipset_needle_matches_the_registry() {
        let names = registry_organisations();
        let dead: Vec<_> = CHIPSETS
            .iter()
            .filter(|(mode, needle, _)| !names.iter().any(|name| mode.matches(needle, name)))
            .map(|(mode, needle, kind)| format!("{mode:?}({needle:?}) -> {kind:?}"))
            .collect();
        assert!(
            dead.is_empty(),
            "these match no organisation in data/oui.tsv: {dead:#?}"
        );
    }

    #[test]
    fn the_clue_order_is_the_priority_order() {
        // The ranking is load-bearing: `identify` sorts on it, so a variant
        // inserted in the wrong place silently changes every answer.
        assert!(Clue::Gateway < Clue::ThisMachine);
        assert!(Clue::ThisMachine < Clue::Service);
        assert!(Clue::Service < Clue::Product);
        assert!(Clue::Product < Clue::Port);
        assert!(Clue::Port < Clue::Vendor);
        assert!(Clue::Vendor < Clue::Chipset);
        assert!(Clue::Chipset < Clue::Workgroup);
        assert!(Clue::Workgroup < Clue::Llmnr);
    }

    /// Every needle is compared against a lower-cased string, so a needle with
    /// a capital in it can never match. Cheap to write and impossible to see
    /// by reading the table.
    #[test]
    fn no_needle_can_be_ruled_out_by_its_own_casing() {
        for (_, needle, _) in PRODUCTS {
            assert_eq!(*needle, needle.to_ascii_lowercase(), "{needle}");
        }
        for (needle, _) in UPNP {
            assert_eq!(*needle, needle.to_ascii_lowercase(), "{needle}");
        }
        for (needle, _) in SERVICES {
            assert_eq!(*needle, needle.to_ascii_lowercase(), "{needle}");
            assert!(needle.starts_with('_'), "a service type begins with _");
            assert!(needle.ends_with('.'), "{needle} must end at a label break");
        }
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
                identify(
                    &host(&[], Some(mac)),
                    &Identity::default(),
                    Vantage::default()
                ),
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
            let guess = identify(
                &host(&[], Some(mac)),
                &Identity::default(),
                Vantage::default(),
            );
            assert_eq!(guess.map(|g| g.kind), Some(expected), "{mac:02x?}");
        }
    }

    /// MikroTik's own name is nowhere in the IEEE registry, which is why the
    /// entry that used it never fired.
    #[test]
    fn mikrotik_is_found_under_the_name_it_actually_registered() {
        let routerboard = [0x00, 0x0c, 0x42, 0x00, 0x00, 0x01];
        let guess = identify(
            &host(&[], Some(routerboard)),
            &Identity::default(),
            Vantage::default(),
        )
        .expect("a guess");
        assert_eq!(guess.kind, Kind::NetworkGear);
        assert_eq!(guess.clue, Clue::Vendor);
    }

    /// The table had no phone vendor at all, so the commonest device on a home
    /// network was the one it could say least about.
    #[test]
    fn a_handset_maker_makes_it_a_phone() {
        let oppo = [0x00, 0xca, 0xe0, 0x00, 0x00, 0x01];
        let guess = identify(
            &host(&[], Some(oppo)),
            &Identity::default(),
            Vantage::default(),
        )
        .expect("a guess");
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
                identify(
                    &host(&[], Some(mac)),
                    &Identity::default(),
                    Vantage::default()
                ),
                None,
                "{mac:02x?} was read as a vendor"
            );
        }
        // And a Xerox block from this century still is one.
        let xerox = [0x9c, 0x93, 0x4e, 0x00, 0x00, 0x01];
        let guess = identify(
            &host(&[], Some(xerox)),
            &Identity::default(),
            Vantage::default(),
        )
        .expect("a guess");
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
            identify(&host(&[], None), &forwards, Vantage::default()),
            identify(&host(&[], None), &backwards, Vantage::default()),
            "the answer changed with the order of the advertised list"
        );
        assert_eq!(
            kind_of(&host(&[], None), &forwards, Vantage::default()),
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
            kind_of(&host(&[], None), &apple_tv, Vantage::default()),
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
                Vantage::default()
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
            let guess = identify(
                &host(&[], None),
                &advertising(&[service]),
                Vantage::default(),
            )
            .expect("a guess");
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
            let guess = identify(
                &host(&[port], None),
                &Identity::default(),
                Vantage::default(),
            )
            .expect("a guess");
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
    /// The claim that finds Windows. A machine that answered WS-Discovery and
    /// nothing else is still named, which is the whole reason the protocol was
    /// added.
    #[test]
    fn a_windows_machine_is_named_by_what_it_told_ws_discovery() {
        let identity = Identity {
            wsd: vec!["wsdp:device".into(), "pub:computer".into()],
            ..Default::default()
        };
        let guess = identify(&bare("192.168.1.42"), &identity, Vantage::default());
        assert_eq!(
            guess,
            Some(Guess {
                kind: Kind::Computer,
                clue: Clue::Service
            })
        );
    }

    /// A printer and a camera answer the same probe in their own namespaces.
    #[test]
    fn ws_discovery_names_printers_and_cameras() {
        for (claim, expected) in [
            ("wprt:printdevicetype", Kind::Printer),
            ("wscn:scandevicetype", Kind::Printer),
            ("dn:networkvideotransmitter", Kind::Camera),
        ] {
            let identity = Identity {
                wsd: vec![claim.into()],
                ..Default::default()
            };
            let guess = identify(&bare("192.168.1.9"), &identity, Vantage::default());
            assert_eq!(guess.map(|g| g.kind), Some(expected), "{claim}");
        }
    }

    /// Every responder claims `wsdp:Device`, so it names nothing and must not
    /// be allowed to.
    #[test]
    fn a_bare_wsd_device_names_no_kind() {
        let identity = Identity {
            wsd: vec!["wsdp:device".into()],
            ..Default::default()
        };
        assert_eq!(
            identify(&bare("192.168.1.9"), &identity, Vantage::default()),
            None
        );
    }

    /// A device found only by the link is a device the sweep never probed, and
    /// it still gets a kind: the guess is made from what it said, not from
    /// whether a packet reached it.
    #[test]
    fn a_device_that_was_never_probed_is_still_identified() {
        let host = Found::announced("192.168.1.42".parse().unwrap(), Protocol::WsDiscovery);
        assert!(!host.was_probed());
        let identity = Identity {
            wsd: vec!["pub:computer".into()],
            ..Default::default()
        };
        assert_eq!(
            identify(&host, &identity, Vantage::default()).map(|g| g.kind),
            Some(Kind::Computer)
        );
    }

    /// A bare host with nothing but an address, for the tests above.
    fn bare(address: &str) -> Found {
        Found {
            address: address.parse().unwrap(),
            mac: None,
            evidence: vec![Evidence::Ping],
            rtt: None,
        }
    }
}
