//! Phase two: finding the hosts.
//!
//! The transport is behind [`Transport`] for the same reason the OS readings
//! are behind `SystemProbe`: so the sweep — the ordering, the rate limiting,
//! the cancellation, and what counts as evidence — is a pure function that
//! tests can drive without a network. Every test in this module runs against
//! [`Fake`].
//!
//! ## What counts as a host
//!
//! The rule worth stating, because it is the one most scanners get wrong: **a
//! refused connection proves a host.** A TCP RST is a machine declining a
//! connection, which means a machine was there to decline it. Treating only
//! open ports as evidence loses every device with a firewall that refuses
//! rather than drops, which on a home network is most of them.
//!
//! Its mirror is [`Outcome::NoAnswer`], which proves nothing whatsoever. Silence
//! is a host that is off, a host that drops, a switch that dropped it, or a
//! probe that was rate limited into the next second. It is never "closed" and
//! it is never "absent", and the sweep records how it looked rather than what
//! it might mean.
//!
//! ## What the sweep could not do
//!
//! A transport says what it can do through [`Capabilities`], and anything the
//! sweep therefore skipped is named in [`Sweep::not_done`]. This is the sharp
//! end of `CLAUDE.md`'s rule against silent degradation: an unprivileged sweep
//! that could not send an ARP request finds fewer devices, and the difference
//! between "there are eleven devices" and "there are eleven devices that
//! answered a ping, and I could not ARP" is the difference between a result and
//! a lie.

use crate::mac::MacAddr;
use crate::prefix::Prefix;
use crate::rate::Bucket;
use std::collections::BTreeSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

/// Ports worth knocking on when nothing else answered.
///
/// Not a port scan — that is phase three. These are the ports a device that
/// ignores ICMP is most likely to answer or refuse on, and the list is short
/// deliberately: it is four probes per silent host, not a service inventory.
/// 80 and 443 catch anything with a web interface, 22 catches Linux and most
/// appliances, 445 catches Windows, which ignores ping by default on a public
/// profile and is otherwise invisible.
pub const KNOCK_PORTS: &[u16] = &[80, 443, 22, 445];

/// The four tried next, and only for an address that answered none of the
/// above.
///
/// **The first four prove almost anything that refuses; these are for the
/// devices that drop.** Once a refusal is visible — see [`TCP_TIMEOUT`] — the
/// choice of port barely matters for a host that sends a RST, because it sends
/// one on every port. It matters entirely for the minority that drop
/// everything, and there the only question that gets an answer is a port the
/// device is actually *listening* on. So these are chosen for what they are
/// open on rather than for what they are closed on:
///
/// * **7000** is AirPlay, and on the network this was measured against it was
///   the only open port on either television. Nothing else in the sweep found
///   them.
/// * **62078** is `lockdownd`, which starts at boot on every iPhone and iPad
///   and listens for the life of the device. There is nothing else it can be.
/// * **8009** is the Chromecast control channel, which every Cast device and
///   Cast-capable television holds open.
/// * **9100** is JetDirect, on printers and on the storage boxes that offer
///   printing.
///
/// Four more connections, paid only on an address that has already produced
/// nothing, which on an ordinary network is a handful of addresses rather than
/// two hundred.
pub const KNOCK_HARDER: &[u16] = &[7000, 62078, 8009, 9100];

/// What a transport is able to send.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Capabilities {
    /// Can resolve a hardware address for an on-link IPv4 address. The best
    /// evidence there is: it is answered by the device's network stack below
    /// any firewall, so it finds hosts that ignore everything else.
    pub arp: bool,
    /// Can send an ICMP echo and hear the reply.
    pub icmp: bool,
    /// Can open TCP connections. True everywhere; listed so a transport can say
    /// no in a test.
    pub tcp: bool,
}

impl Capabilities {
    /// Everything an unprivileged engine has on a good day.
    pub const UNPRIVILEGED: Self = Self {
        arp: true,
        icmp: true,
        tcp: true,
    };
}

/// How a TCP probe ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The connection was accepted. There is a host and the port is open.
    Open,
    /// The connection was refused: a RST. **There is a host.**
    Refused,
    /// Nothing came back before the timeout. This proves nothing at all.
    NoAnswer,
}

/// What an echo reply carried.
///
/// **A round trip used to be the whole of it and the rest was thrown away.**
/// Every reply arrives with a TTL in front of it and both platforms already had
/// that byte in hand: Windows fills the field in on the reply structure it
/// hands back, and a raw socket on Linux is given the IP header itself. Rounded
/// up, it is a coarse class of network stack for every device that answered a
/// ping — see [`Stack`] — which makes it the cheapest identification in this
/// crate, because the probe it comes out of was paid for already.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Echo {
    /// How long the reply took.
    pub rtt: Duration,
    /// The TTL the reply arrived with, where the transport could read one.
    ///
    /// [`None`] is not zero and is not a default: it is a transport that did
    /// not surface the field. A stack inferred from a TTL nobody read would be
    /// exactly the invention the rest of this module refuses to make.
    pub ttl: Option<u8>,
}

impl Echo {
    /// A reply timed but not read: the round trip, and no claim about a stack.
    pub const fn timed(rtt: Duration) -> Self {
        Self { rtt, ttl: None }
    }
}

/// The class of network stack a reply's TTL points at.
///
/// A stack starts every packet at one of a few round numbers and each router on
/// the way takes one off, so what arrives here is that initial value minus the
/// hop count: a device on this wire answers with the number it started from,
/// and the same device behind a router answers with one less. Rounding **up**
/// to the nearest of 64, 128 and 255 is what recovers the number it started
/// from, and that number is a property of the operating system rather than of
/// the product. Linux, the BSDs, macOS, Android and iOS start at 64, Windows at
/// 128, and the stacks in switches, printer controllers and Solaris at 255.
///
/// **It is a claim about a stack and never about a product.** "The reply's TTL
/// suggests a Unix-like stack" is what a hop count supports; "this is a Linux
/// machine" is not, and neither is anything at all about what the device is
/// for. Half the phones, televisions, cameras and smart plugs on a network
/// answer with 64, so the band says what they have in common and nothing more.
/// That is also why only one of the three bands names a kind at all; see
/// [`crate::kind::Clue::Stack`].
///
/// **A value that fits no band is left blank**, which is the other half of the
/// same rule and the reason [`of`](Self::of) returns an [`Option`]. Rounding up
/// on its own never fails, because every number from 1 to 255 is below one of
/// the three, so a rule that only rounded would answer "Windows stack" for an
/// observed 100 and "Unix-like" for an observed 33 — claims about a device
/// thirty routers away rather than one on the wire being scanned. Only a value
/// within [`MOST_HOPS`] of a band is read, and everything else is a blank. A
/// blank is an answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Stack {
    /// Started at 64: Linux, the BSDs, macOS, Android and iOS, and the great
    /// many embedded devices built on Linux.
    Unix,
    /// Started at 128, which on any network worth scanning means Windows.
    Windows,
    /// Started at 255: the stacks in switches, routers, printer controllers and
    /// Solaris.
    Embedded,
}

/// How far a reply may have travelled and still be read.
///
/// The rounding is only sound while the hop count is small, and on the networks
/// Muster scans it is: the default target is this machine's own link, where the
/// count is nought, and a range somebody types is a network a couple of routers
/// away. Sixteen is far more than that and still comfortably less than the
/// distance between the bands, so a reply from anything this scanner can reach
/// lands inside a window, and a value outside every window is a packet whose
/// initial value cannot be recovered rather than one to guess at.
pub const MOST_HOPS: u8 = 16;

impl Stack {
    /// The stack a TTL observed on a reply points at, if it points at one.
    pub const fn of(observed: u8) -> Option<Self> {
        if observed >= 255 - MOST_HOPS {
            Some(Self::Embedded)
        } else if observed <= 128 && observed >= 128 - MOST_HOPS {
            Some(Self::Windows)
        } else if observed <= 64 && observed >= 64 - MOST_HOPS {
            Some(Self::Unix)
        } else {
            None
        }
    }

    /// The number a packet from this stack starts at.
    pub const fn initial(self) -> u8 {
        match self {
            Self::Unix => 64,
            Self::Windows => 128,
            Self::Embedded => 255,
        }
    }

    /// What the interface calls it, in the words the evidence supports.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Unix => "Unix-like stack",
            Self::Windows => "Windows stack",
            Self::Embedded => "embedded stack",
        }
    }

    /// The sentence shown beside the claim, which says what was measured as
    /// well as what it is taken to mean.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Unix => {
                "the TTL of its reply rounds up to 64, where Linux, the BSDs, macOS, Android and iOS all start"
            }
            Self::Windows => "the TTL of its reply rounds up to 128, where Windows starts",
            Self::Embedded => {
                "the TTL of its reply rounds up to 255, where the stacks in switches, printers and other embedded gear start"
            }
        }
    }
}

/// A protocol a device spoke to the link as a whole.
///
/// **This is the other half of finding a device, and for a long time it was
/// thrown away.** The sweep asks each address a question; these are the
/// questions asked once of everybody, and the answers arrive from whoever felt
/// like answering — including addresses the sweep never got a word out of. A
/// television that ignores ARP, drops ping and refuses nothing is silent to
/// phase two and shouts its model number at `239.255.255.250` every few
/// minutes, and until this existed it was not on the list.
///
/// The variants are ordered by how much a reply narrows down what the device
/// is, which is also roughly how much work each costs. Nothing depends on the
/// order; it is a reading order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Protocol {
    /// Multicast DNS, the question every Apple device, printer and Avahi host
    /// answers.
    Mdns,
    /// SSDP, which is how nearly everything that is not Apple announces itself:
    /// televisions, set-top boxes, media players, routers and cameras.
    Ssdp,
    /// WS-Discovery, which Windows machines, network printers and ONVIF
    /// cameras answer and the two above do not.
    WsDiscovery,
    /// The NetBIOS name service, asked of the broadcast address rather than of
    /// one machine.
    NetBios,
    /// **Not the device speaking.** This network's own resolver had a `PTR`
    /// record for the address, which is what the router was told once and is
    /// second-hand by definition: the device may be asleep, or may have given
    /// the address up a month ago. Last in this order for that reason, and it
    /// is deliberately never enough on its own to put a row on the device
    /// list — see [`crate::link::Voice::spoke`].
    Dns,
}

impl Protocol {
    /// The protocol's name, as the interface writes it.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Mdns => "mDNS",
            Self::Ssdp => "SSDP",
            Self::WsDiscovery => "WS-Discovery",
            Self::NetBios => "NetBIOS",
            Self::Dns => "reverse DNS",
        }
    }
}

/// Why Muster believes a host is there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Evidence {
    /// It answered an ARP request, with this hardware address.
    Arp(MacAddr),
    /// It answered a ping.
    Ping,
    /// It accepted a connection on this port.
    TcpOpen(u16),
    /// It refused a connection on this port, which proves it is there.
    TcpRefused(u16),
    /// It answered a question put to the whole link, in this protocol.
    ///
    /// As good as any other evidence and better than most: a device that sent
    /// a datagram is a device that exists, and unlike a TCP refusal it has
    /// also just said what it is. What it is *not* is a measurement — nothing
    /// here has a round trip time, and the interface must not draw one.
    Announced(Protocol),
    /// This machine's own neighbour table already had it, with a hardware
    /// address, from before the scan began.
    ///
    /// The one piece of evidence that costs no packet at all. It is what the
    /// operating system learned the last time anything on this machine talked
    /// to the device, so it is weaker than an answer given just now — a device
    /// can have left — and it is the only way an IPv6 neighbour reaches the
    /// list at all, because the sweep walks IPv4 addresses.
    Neighbour,
}

impl Evidence {
    /// A short phrase for the interface, which shows why rather than only what.
    pub fn reason(&self) -> String {
        match self {
            Self::Arp(_) => "answered ARP".into(),
            Self::Ping => "answered ping".into(),
            Self::TcpOpen(p) => format!("port {p} open"),
            Self::TcpRefused(p) => format!("port {p} refused"),
            Self::Announced(p) => format!("announced itself over {}", p.label()),
            Self::Neighbour => "already in this machine's neighbour table".into(),
        }
    }

    /// Did a probe of this address produce this, or did it arrive on its own?
    ///
    /// The sweep counts what it probed, and a device that was never probed
    /// must not be counted as one that was. See [`Sweep::heard`].
    pub const fn is_probe(&self) -> bool {
        matches!(
            self,
            Self::Arp(_) | Self::Ping | Self::TcpOpen(_) | Self::TcpRefused(_)
        )
    }
}

/// A host that answered something.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
    pub address: IpAddr,
    pub mac: Option<MacAddr>,
    /// Where [`Self::mac`] came from, when the device *said* it rather than
    /// its own stack answering for it.
    ///
    /// [`None`] means an ARP reply or this machine's neighbour table produced
    /// the address, which is a claim of a different order: those are written
    /// below the level anything on the device has an opinion about, and every
    /// route here is the device writing its address into a payload it
    /// composed. `CLAUDE.md` asks that a claim carry its reason, and this is
    /// that reason for the hardware column. See [`crate::claim`].
    pub mac_said: Option<crate::claim::Route>,
    /// Every reason, in the order they were obtained. Never empty: a `Found`
    /// with no evidence is a host nothing attests to, and this module does not
    /// build one.
    pub evidence: Vec<Evidence>,
    /// Round trip time, where something measured one.
    pub rtt: Option<Duration>,
    /// The TTL an echo reply arrived with, where one was read.
    ///
    /// The observation rather than the conclusion, because the observation is
    /// the fact: see [`Stack`] for what is and is not inferable from it, and
    /// [`Found::stack`] for the inference.
    pub ttl: Option<u8>,
}

impl Found {
    /// A host that answered a question put to the whole link.
    ///
    /// No round trip, because none was measured: the datagram was sent to a
    /// group and a reply arrived from somewhere, which proves the somewhere
    /// and times nothing. The hardware address is filled in later where the
    /// neighbour table or an ARP reply knows one.
    pub fn announced(address: IpAddr, protocol: Protocol) -> Self {
        Self {
            address,
            mac: None,
            mac_said: None,
            evidence: vec![Evidence::Announced(protocol)],
            rtt: None,
            ttl: None,
        }
    }

    /// A host this machine had already talked to, out of the neighbour table.
    pub fn neighbour(address: IpAddr, mac: MacAddr) -> Self {
        Self {
            address,
            mac: Some(mac),
            mac_said: None,
            evidence: vec![Evidence::Neighbour],
            rtt: None,
            ttl: None,
        }
    }

    /// Did anything Muster sent to *this address* come back?
    ///
    /// False for a device that only ever answered a group question or that
    /// came out of the neighbour table. The interface asks before it presents
    /// a silence as a fact about the device: a row that was never probed has
    /// nothing to say about ping, and saying "nothing came back" about a
    /// question that was never put is the mistake `discover::recheck` exists
    /// to stop.
    pub fn was_probed(&self) -> bool {
        self.evidence.iter().any(Evidence::is_probe)
    }

    /// Folds one more reason in, without repeating one already there.
    ///
    /// Order is preserved because it is meaningful: the evidence list reads as
    /// the order things were learned, and the interface prints it that way.
    pub fn attest(&mut self, evidence: Evidence) {
        if !self.evidence.contains(&evidence) {
            self.evidence.push(evidence);
        }
    }

    /// The class of stack this device's echo reply points at, if any.
    ///
    /// Blank for a device that was never pinged, for one whose reply carried no
    /// TTL, and for one whose TTL fits no band. All three read the same way to
    /// somebody looking at the row — nothing is known — and none of the three
    /// is a reason to guess.
    pub fn stack(&self) -> Option<Stack> {
        self.ttl.and_then(Stack::of)
    }

    /// The open ports the sweep happened to notice while knocking. Not a port
    /// scan's answer.
    pub fn open_ports(&self) -> Vec<u16> {
        self.evidence
            .iter()
            .filter_map(|e| match e {
                Evidence::TcpOpen(p) => Some(*p),
                _ => None,
            })
            .collect()
    }
}

/// The packet transport a sweep sends through.
///
/// Implementations live in `platform`. Every method takes its own timeout
/// rather than reading a shared setting, because the sweep varies them: an ARP
/// request on the local wire is answered in under a millisecond and a TCP
/// connection across a slow link is not.
pub trait Transport: Sync {
    fn capabilities(&self) -> Capabilities;

    /// Resolves a hardware address for an on-link IPv4 address.
    ///
    /// [`None`] means no answer. An error means the mechanism failed, which is
    /// a different thing and is counted separately.
    fn arp(&self, addr: Ipv4Addr, timeout: Duration) -> io::Result<Option<MacAddr>>;

    /// Sends one ICMP echo. [`None`] means no reply.
    ///
    /// An [`Echo`] rather than a bare round trip, because the reply carries a
    /// TTL as well and discarding it threw away the one piece of
    /// fingerprinting this engine gets without a raw socket. A transport that
    /// cannot read the TTL says so with [`Echo::timed`] rather than filling the
    /// field in with something.
    fn ping(&self, addr: IpAddr, timeout: Duration) -> io::Result<Option<Echo>>;

    /// Opens a TCP connection far enough to learn how it is answered, then
    /// drops it.
    fn tcp(&self, addr: IpAddr, port: u16, timeout: Duration) -> Outcome;
}

/// How hard to look.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// How long to wait for an ARP reply on the local wire.
    pub arp_timeout: Duration,
    pub ping_timeout: Duration,
    pub tcp_timeout: Duration,
    /// Probes in flight at once. The rate limiter decides the pace; this
    /// decides how much waiting happens in parallel, and on this sweep almost
    /// all of the elapsed time is waiting.
    ///
    /// It is high because the probes are *blocking* and mostly idle. The worst
    /// case is an address with nothing at it: the platform's ARP call spends a
    /// second or two on its own retries — a timeout Muster asks for and does
    /// not get — and a mostly empty /24 is two hundred of those. Sequentially
    /// that is the whole cost of the sweep; in parallel it is one wait.
    pub workers: usize,
    /// Knock on [`KNOCK_PORTS`] for addresses that answered nothing else.
    /// This is what finds a Windows machine on a public network profile.
    pub knock: bool,
    /// **The prefix is on this machine's own link**, which the caller knows
    /// and the sweep does not. It decides two things, and they are one flag
    /// because they are the same fact.
    ///
    /// *Whether ARP is asked at all.* Off-link it is not, and this is a
    /// correctness rule rather than a saving. `SendARP` on Windows resolves
    /// through the routing table, so for a destination one hop away the stack
    /// answers with the **next hop's** hardware address: an off-link sweep
    /// that asked would report all 254 addresses present, every one of them
    /// wearing the gateway's MAC. Linux's provoke-and-read-the-cache cannot
    /// invent that, so asking off-link also made the two platforms answer the
    /// same scan differently.
    ///
    /// *Whether silence from ARP settles an address.* On-link it does, and
    /// that is not an optimisation but the more correct answer: ARP is
    /// answered by a device's network stack below any firewall it has, and a
    /// host that did not answer could not use the network at all. Everything
    /// after it — a ping and four connections — is then spent proving
    /// something already known, at four seconds an empty address, which on a
    /// mostly empty /24 is the entire cost of the sweep.
    ///
    /// Off the link it must be false: an address one hop away is *supposed* to
    /// have no ARP reply, and taking that as absence finds nothing anywhere.
    ///
    /// The one thing the shortcut gives up is a host whose stack answers
    /// nothing at all yet still has open ports. That configuration cannot
    /// reach its own gateway, so it is a lab curiosity rather than a device on
    /// somebody's network — but a *link* that filters ARP between its clients
    /// is not, and [`Sweep::not_done`] says so when a whole prefix comes back
    /// silent. See [`ARP_SILENCE_SHARE`].
    pub arp_authoritative: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            // The local wire answers in microseconds. A second here is not
            // patience, it is 254 seconds of sweep.
            arp_timeout: Duration::from_millis(300),
            ping_timeout: Duration::from_millis(500),
            tcp_timeout: TCP_TIMEOUT,
            workers: 256,
            knock: true,
            // Off by default because it is only true on-link, and a default
            // that is wrong off-link finds nothing at all there.
            arp_authoritative: false,
        }
    }
}

impl Options {
    /// The options for sweeping a network this machine is on.
    pub fn on_link() -> Self {
        Self {
            arp_authoritative: true,
            ..Self::default()
        }
    }
}

/// How long to wait on a TCP knock, **which is a different number on each
/// platform because the platforms report a refusal differently.**
///
/// On Linux a RST arrives as `ECONNREFUSED` on the first one, in about as long
/// as the round trip: 600 ms is generous.
///
/// **On Windows it takes two seconds, and for a long time this was 400 ms
/// there too — which quietly made [`Outcome::Refused`] unreachable.** Windows
/// does not hand a RST straight to `connect()`; it treats the reset as possibly
/// transient, retransmits the SYN, and only fails the call when its own retry
/// schedule runs out. Measured on loopback and on the wire, against a closed
/// port, the refusal surfaces at 2.0 to 2.6 seconds and not before — so every
/// refused connection became [`Outcome::NoAnswer`], which is exactly the lie
/// this module's doc comment opens by refusing to tell. On a real network of
/// eighteen devices, seventeen of which refuse rather than drop, the same knock
/// proved eleven hosts at 400 ms and eighteen at 3000 ms.
///
/// `TCP_MAXRT` looks like the cure and is the opposite of one: it shortens the
/// call and turns the refusal into `WSAETIMEDOUT`, throwing away the very
/// evidence being waited for. Waiting is the only way to hear a RST on Windows.
///
/// The cost is paid in concurrency rather than in elapsed time — the knock only
/// runs for addresses that answered nothing else, and 256 of them are in flight
/// at once.
#[cfg(windows)]
const TCP_TIMEOUT: Duration = Duration::from_millis(3000);
#[cfg(not(windows))]
const TCP_TIMEOUT: Duration = Duration::from_millis(600);

/// The share of a prefix that has to be settled by ARP silence alone, with
/// nothing found anywhere, before the sweep stops believing the shortcut.
///
/// Nine in ten rather than all of them, because a link that filters ARP
/// between clients still lets the *gateway* answer sometimes, and one lucky
/// reply must not turn the caveat off for the other 253.
const ARP_SILENCE_SHARE: (u64, u64) = (9, 10);

/// One found host, in the high half of the packed tally.
const FOUND_STEP: u64 = 1 << 32;
/// The low half, which holds the addresses probed.
const PROBED_MASK: u64 = u32::MAX as u64;

/// What the workers have to tell the sweep that a [`Found`] cannot carry.
///
/// Shared by every worker, so it is behind its own locks rather than folded
/// into the result: a mechanism fails at an address, and the sweep reports it
/// once for the prefix.
#[derive(Default)]
struct Notes {
    /// One line per distinct reason, not per address. A broken ARP fails 254
    /// times over and the user has to be told once.
    gaps: Mutex<BTreeSet<String>>,
    /// Addresses settled by ARP silence and nothing else.
    arp_silent: AtomicU64,
}

impl Notes {
    fn gap(&self, line: String) {
        self.gaps.lock().expect("sweep notes poisoned").insert(line);
    }

    /// Everything recorded, in the order a `BTreeSet` keeps it: stable, so two
    /// runs of the same scan report the same lines in the same order.
    fn drain(&self) -> Vec<String> {
        self.gaps
            .lock()
            .expect("sweep notes poisoned")
            .iter()
            .cloned()
            .collect()
    }
}

/// Progress, reported as the sweep runs.
///
/// Carried beside the device the probe found, where it found one: see
/// [`sweep`]'s `progress` argument. It stays `Copy` for that reason — a `Found`
/// holds a `Vec` of evidence, and folding it in here would make every progress
/// report an allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    pub probed: u64,
    pub total: u64,
    pub found: u64,
}

/// The result of a sweep.
#[derive(Clone, Debug, Default)]
pub struct Sweep {
    pub found: Vec<Found>,
    /// Addresses actually probed. Less than the prefix's host count when the
    /// sweep was cancelled.
    pub probed: u64,
    pub total: u64,
    /// Techniques that were not available, in words fit to show. Empty means
    /// the sweep did everything it knows how to do.
    pub not_done: Vec<String>,
    /// True when the sweep stopped early because it was asked to.
    pub cancelled: bool,
}

impl Sweep {
    /// Admits a host that attested to itself rather than answering a probe.
    ///
    /// **The sweep walks addresses and this is how everything else gets in.**
    /// A device that answered a multicast question, or that was already in the
    /// neighbour table, is a device — but it was found by a different route
    /// and the list has to say so rather than quietly presenting it as a probe
    /// that succeeded. So the evidence comes in with it, and where the address
    /// is already on the list the two attestations are merged rather than one
    /// of them winning: a television that answered both ARP and SSDP has two
    /// reasons, and both are worth printing.
    ///
    /// Answers whether this was a device the sweep did not already have.
    ///
    /// The list stays sorted by address, which is the order [`sweep`] leaves it
    /// in and the order the table reads in. Inserting in place rather than
    /// re-sorting afterwards is what lets a caller admit hosts one at a time as
    /// they are heard.
    pub fn admit(&mut self, host: Found) -> bool {
        match self
            .found
            .binary_search_by_key(&host.address, |f| f.address)
        {
            Ok(at) => {
                let existing = &mut self.found[at];
                for evidence in host.evidence {
                    existing.attest(evidence);
                }
                // A hardware address from anywhere beats not having one, and a
                // probe's answer beats a table's memory of one, so an address
                // already known is never overwritten.
                if existing.mac.is_none() {
                    existing.mac = host.mac;
                    existing.mac_said = host.mac_said;
                }
                if existing.rtt.is_none() {
                    existing.rtt = host.rtt;
                }
                if existing.ttl.is_none() {
                    existing.ttl = host.ttl;
                }
                false
            }
            Err(at) => {
                self.found.insert(at, host);
                true
            }
        }
    }

    /// Admits what the operating system already knew, **without saying so
    /// about a device that answered for itself.**
    ///
    /// The neighbour table holds an entry for every device the sweep just
    /// found, because the sweep is what put most of them there. Recording that
    /// as evidence would print "already in this machine's neighbour table"
    /// against nearly every row, where it adds nothing to "answered ARP" and
    /// crowds out the reasons that do say something. The table earns its place
    /// on the two rows where it is the *only* thing that knows.
    ///
    /// The hardware address is taken either way, and that is the other half of
    /// why this is not simply skipped: a device found only by a multicast
    /// answer has no MAC, and the table very often has one.
    ///
    /// Answers whether this was a device the sweep did not already have.
    pub fn admit_neighbour(&mut self, address: IpAddr, mac: MacAddr) -> bool {
        match self.found.binary_search_by_key(&address, |f| f.address) {
            Ok(at) => {
                let existing = &mut self.found[at];
                // An address the device *said* yields to one a stack answered.
                // The table is what the kernel wrote down after a frame came
                // back; a stated address is the device's own account of
                // itself, and the two are not the same claim. Nothing is lost
                // by preferring this one — the account is kept whole in
                // [`crate::identify::Identity::said`].
                if existing.mac.is_none() || existing.mac_said.is_some() {
                    existing.mac = Some(mac);
                    existing.mac_said = None;
                }
                false
            }
            Err(at) => {
                self.found.insert(at, Found::neighbour(address, mac));
                true
            }
        }
    }

    /// Devices that never answered anything sent to their own address.
    ///
    /// The count the result line needs to stay honest: "fourteen devices" from
    /// a sweep that probed 254 addresses and got eleven answers is a claim
    /// about three devices that were heard rather than found, and the
    /// difference is one the reader is entitled to.
    pub fn heard(&self) -> usize {
        self.found.iter().filter(|f| !f.was_probed()).count()
    }

    /// Did this sweep look as hard as Muster knows how?
    ///
    /// The interface asks before presenting a count, because "no devices" from
    /// a partial sweep is the answer `CLAUDE.md` refuses to give.
    pub fn is_complete(&self) -> bool {
        self.not_done.is_empty() && !self.cancelled
    }
}

/// Sweeps a prefix.
///
/// Runs until every address has been probed or `cancel` is set. The prefix must
/// be enumerable; a caller handing over a /8 or an IPv6 prefix gets an empty
/// sweep with the reason in [`Sweep::not_done`], which is the same shape as any
/// other thing the sweep could not do.
pub fn sweep<T: Transport>(
    prefix: Prefix,
    transport: &T,
    rate: &Bucket,
    opts: Options,
    cancel: &AtomicBool,
    progress: &(dyn Fn(Progress, Option<&Found>) + Sync),
) -> Sweep {
    let caps = transport.capabilities();
    let mut result = Sweep {
        total: prefix.host_count(),
        ..Default::default()
    };

    let Some(hosts) = prefix.hosts() else {
        result.not_done.push(format!(
            "{prefix} is too large to sweep address by address; \
             discovery there is multicast and the neighbour table"
        ));
        return result;
    };

    let addresses: Vec<IpAddr> = hosts.collect();
    result.total = addresses.len() as u64;

    // Only claimed as a gap where the sweep would have used it. Off-link ARP
    // is not asked for at all, see `Options::arp_authoritative`, so calling it
    // missing there would be a caveat about a technique that could not have
    // helped, which is its own kind of dishonesty.
    if !caps.arp && opts.arp_authoritative {
        result.not_done.push(
            "could not send ARP requests, so devices that ignore ping and \
             refuse nothing were missed"
                .into(),
        );
    }
    if !caps.icmp {
        result.not_done.push(no_icmp());
    }

    let next = AtomicU64::new(0);
    // `probed` in the low half of a word and `found` in the high half. Two
    // counters read separately let a worker report a pair that never existed,
    // and let a slow worker deliver a lower count after a fast one, so both the
    // bar and the device count could tick backwards on screen.
    let tally = AtomicU64::new(0);
    // The highest pair anyone has reported, and the lock that makes reporting
    // it monotone. Packing the two counters into one word stops a caller ever
    // seeing a pair that did not exist; on its own it does not stop two workers
    // taking 10 and 11 and then reaching the callback in the other order, which
    // is the tick backwards a user actually sees. Only holding something across
    // the compare *and* the call fixes that, and the call is a line of text or
    // a channel send: 254 probes contending on it over several seconds is
    // nothing beside the packet each of them just waited for.
    let shown = Mutex::new(0u64);
    let notes = Notes::default();
    let workers = opts.workers.clamp(1, 512).min(addresses.len().max(1));
    let mut found: Vec<Found> = Vec::new();

    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            let (next, tally, shown, notes) = (&next, &tally, &shown, &notes);
            let addresses = &addresses;
            handles.push(scope.spawn(move || {
                let mut mine = Vec::new();
                loop {
                    if cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    let i = next.fetch_add(1, Ordering::Relaxed) as usize;
                    let Some(&address) = addresses.get(i) else {
                        break;
                    };

                    let hit = probe_one(address, transport, rate, &caps, opts, cancel, notes);
                    let step = if hit.is_some() { 1 + FOUND_STEP } else { 1 };
                    let ours = tally.fetch_add(step, Ordering::Relaxed) + step;
                    {
                        let mut pair = shown.lock().unwrap_or_else(|e| e.into_inner());
                        *pair = (*pair).max(ours);
                        // Reported **before** it is kept, so a caller can put
                        // the device on screen the moment it answers rather
                        // than when the whole prefix has been walked. A /24
                        // takes seconds and a /16 takes a great deal longer;
                        // either way, a table that fills as it goes is the
                        // difference between watching a scan and waiting for
                        // one.
                        progress(
                            Progress {
                                probed: *pair & PROBED_MASK,
                                total: addresses.len() as u64,
                                found: *pair >> 32,
                            },
                            hit.as_ref(),
                        );
                    }
                    if let Some(f) = hit {
                        mine.push(f);
                    }
                }
                mine
            }));
        }
        for handle in handles {
            found.extend(handle.join().unwrap_or_default());
        }
    });

    found.sort_by_key(|f| f.address);
    result.found = found;
    result.probed = tally.load(Ordering::Relaxed) & PROBED_MASK;
    result.cancelled = cancel.load(Ordering::Relaxed);
    result.not_done.extend(
        notes
            .gaps
            .lock()
            .expect("sweep notes poisoned")
            .iter()
            .cloned(),
    );

    // The shortcut's blind spot, and the reason it is checked rather than
    // trusted: `arp_authoritative` assumes a host that did not answer ARP could
    // not use the network. That holds for a *host* and not for a *link*. Guest
    // Wi-Fi and any access point with client isolation filter ARP between
    // clients, and there every address is settled by silence, the ping and the
    // knock are skipped, and the sweep hands back an empty network as a
    // finished answer. That is the failure `CLAUDE.md` calls the worst this
    // application can produce, because it looks like a result.
    //
    // Re-probing the whole prefix without the shortcut was the other option and
    // was not taken: it doubles the length of a sweep that has already found
    // nothing, with nothing on screen to say why it is still going, and it
    // still could not tell an isolated link from an empty one. Saying what was
    // assumed is the answer a user can act on.
    let arp_silent = notes.arp_silent.load(Ordering::Relaxed);
    if opts.arp_authoritative
        && result.found.is_empty()
        && result.probed > 0
        // A sweep stopped after three addresses says so already, and a second
        // caveat drawn from three data points would be a guess wearing the
        // same face as a finding.
        && !result.cancelled
        && arp_silent * ARP_SILENCE_SHARE.1 >= result.probed * ARP_SILENCE_SHARE.0
    {
        result.not_done.push(
            "nothing answered ARP anywhere in this network, and every address \
             was settled by that silence alone; on a link that filters ARP \
             between its clients, as guest Wi-Fi and client isolation do, \
             finding nothing is not the same as there being nothing"
                .into(),
        );
    }
    result
}

/// The one sentence for "no echo was sent", with the platform's remedy in it.
///
/// Written once and used by both the sweep and a re-check, because the two must
/// not describe the same machine differently: a scan that says the echoes were
/// skipped and a Ping button that says the device is silent is a contradiction
/// the reader has to resolve, and only one of the two is true.
fn no_icmp() -> String {
    format!("could not send ICMP echoes: {}", crate::platform::ICMP_HINT)
}

/// Probe one address, once.
///
/// The single-host form of the sweep, with everything available tried cheapest
/// and most conclusive first. ARP leads *on-link*, because there it is the
/// strongest evidence there is — answered below any firewall — and because it
/// yields the hardware address the whole device list is keyed on; off-link it
/// is not asked at all. The knock is last and only for silence, so a host that
/// answered already costs four fewer probes.
///
/// This is what a re-check of a device already on screen calls. It runs the
/// same probes in the same order and returns the same [`Found`], so what a
/// re-check says and what the sweep said cannot disagree about what counts as
/// an answer.
pub fn probe<T: Transport>(
    address: IpAddr,
    transport: &T,
    rate: &Bucket,
    opts: Options,
) -> Option<Found> {
    recheck(address, transport, rate, opts).found
}

/// One address asked again, **and what could not be asked**.
///
/// [`probe`] answers "did it reply", and for a long time that was the whole of
/// what a re-check could say. It is not enough, and the reason is the rule
/// `CLAUDE.md` states most sharply: *never degrade silently*. A machine where
/// ping sockets are closed skips the echo entirely — [`Capabilities::icmp`] is
/// false, so nothing is sent and nothing fails — and the device came back with
/// no round trip measured, which the interface then reported as **"nothing
/// came back this time"**. That is the application saying a device did not
/// answer a question it never asked, about a device that is very often sitting
/// there answering ARP in the same second.
///
/// So a re-check carries the same [`Sweep::not_done`] list a sweep does, built
/// the same way from the same two sources: the capabilities the transport does
/// not have, and any mechanism that failed while it ran.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Recheck {
    /// The device, where anything answered at all.
    pub found: Option<Found>,
    /// What was not asked, and why. Empty when every probe ran.
    pub not_done: Vec<String>,
}

/// Ask one address again, reporting the gaps as well as the answer.
pub fn recheck<T: Transport>(
    address: IpAddr,
    transport: &T,
    rate: &Bucket,
    opts: Options,
) -> Recheck {
    let caps = transport.capabilities();
    let notes = Notes::default();

    // The same two gaps [`sweep`] opens with, in the same words, so a re-check
    // and the scan that found the device cannot describe the machine
    // differently. Only claimed where the probe would have used it: off-link
    // ARP is not asked for at all.
    let mut not_done = Vec::new();
    if !caps.arp && opts.arp_authoritative && address.is_ipv4() {
        not_done.push(
            "could not send ARP requests, so a device that ignores ping and \
             refuses nothing may answer nothing here"
                .into(),
        );
    }
    if !caps.icmp {
        not_done.push(no_icmp());
    }

    // One address asked once is never cancelled.
    let found = probe_one(
        address,
        transport,
        rate,
        &caps,
        opts,
        &AtomicBool::new(false),
        &notes,
    );

    not_done.extend(notes.drain());
    Recheck { found, not_done }
}

/// The probes for one address.
///
/// `cancel` is read before **every** probe rather than once per address, which
/// is `CLAUDE.md`'s rule that cancelling takes effect at the next packet. One
/// check per address is one check per six probes and up to two and a half
/// seconds of waiting, and with 254 workers that was a thousand more packets
/// on the wire after the user pressed Stop.
#[allow(clippy::too_many_arguments)]
fn probe_one<T: Transport>(
    address: IpAddr,
    transport: &T,
    rate: &Bucket,
    caps: &Capabilities,
    opts: Options,
    cancel: &AtomicBool,
    notes: &Notes,
) -> Option<Found> {
    let mut evidence = Vec::new();
    let mut mac = None;
    let mut rtt = None;
    let mut ttl = None;

    // A labelled block rather than early returns, so that giving up part way
    // through still hands back whatever has already answered. A device found by
    // ARP and then cancelled before its ping is still a device.
    'probes: {
        // ARP is asked only on-link. Off the link the answer is the gateway's
        // hardware address rather than the destination's, which is a device
        // invented at every address. See `Options::arp_authoritative`.
        if caps.arp
            && opts.arp_authoritative
            && let IpAddr::V4(v4) = address
        {
            if !rate.wait_unless(cancel) {
                break 'probes;
            }
            match transport.arp(v4, opts.arp_timeout) {
                // An all-zero reply is the API's way of saying nothing
                // answered, and it is not a device.
                Ok(Some(hw)) if !hw.is_zero() => {
                    mac = Some(hw);
                    evidence.push(Evidence::Arp(hw));
                }
                // On-link silence settles it. See `Options::arp_authoritative`,
                // and note that the sweep counts how often this happens: a
                // whole prefix settled this way is a filtered link as readily
                // as an empty one.
                Ok(_) => {
                    notes.arp_silent.fetch_add(1, Ordering::Relaxed);
                    return None;
                }
                // An *error* is the mechanism failing, not the address
                // answering, so it never settles anything: fall through, probe
                // properly, and make sure the sweep says it happened.
                Err(e) => notes.gap(format!(
                    "hardware address lookups failed ({e}), so devices that \
                     ignore ping and refuse nothing may have been missed"
                )),
            }
        }

        if caps.icmp {
            if !rate.wait_unless(cancel) {
                break 'probes;
            }
            match transport.ping(address, opts.ping_timeout) {
                Ok(Some(echo)) => {
                    evidence.push(Evidence::Ping);
                    rtt = Some(echo.rtt);
                    // Kept whether or not it fits a band, because it is the
                    // reading and the band is the reading's interpretation.
                    ttl = echo.ttl;
                }
                // Silence, which proves nothing and needs no note.
                Ok(None) => {}
                // The transport could not send at all. This is where an IPv6
                // sweep lands today, because neither platform has written the
                // v6 echo: `Capabilities` has no family axis, so nothing above
                // knows the difference between "pinged and heard nothing" and
                // "never pinged". Recording it is what stops a /112 of silent
                // hosts reading as a network with nothing on it.
                Err(e) => notes.gap(format!("could not send an ICMP echo ({e})")),
            }
        }

        if evidence.is_empty() && opts.knock && caps.tcp {
            // Two rounds, and the second is only reached by an address that
            // answered nothing in the first: see [`KNOCK_HARDER`].
            for &port in KNOCK_PORTS.iter().chain(KNOCK_HARDER) {
                if !rate.wait_unless(cancel) {
                    break 'probes;
                }
                match transport.tcp(address, port, opts.tcp_timeout) {
                    Outcome::Open => evidence.push(Evidence::TcpOpen(port)),
                    // A refusal proves the host. Knocking further would only
                    // find more ports, which is phase three's job.
                    Outcome::Refused => {
                        evidence.push(Evidence::TcpRefused(port));
                        break;
                    }
                    Outcome::NoAnswer => {}
                }
                // An open port proves the host too, and the first four are on
                // everything. The second four are each a claim about what the
                // device *is*, so they are all worth asking even after one has
                // answered — a printer that opens 9100 is a printer, and a
                // television that opens 7000 is a television.
                if !evidence.is_empty() && port == *KNOCK_PORTS.last().expect("not empty") {
                    break;
                }
            }
        }
    }

    (!evidence.is_empty()).then_some(Found {
        address,
        mac,
        // The sweep only ever learns an address from an ARP reply or the
        // neighbour table, and neither is the device speaking.
        mac_said: None,
        evidence,
        rtt,
        ttl,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::Instant;

    /// A network held in a map. Every test in this module runs against it, and
    /// no test in this crate opens a socket.
    #[derive(Default)]
    struct Fake {
        caps: Capabilities,
        arp: BTreeMap<Ipv4Addr, MacAddr>,
        pings: Vec<IpAddr>,
        /// The TTL a recorded reply came back with, for the addresses where
        /// one was captured. An address in `pings` and not in here answered
        /// without one, which is a real transport as well: a ping socket on a
        /// kernel that will not hand the field over.
        ttls: BTreeMap<IpAddr, u8>,
        /// address → port → outcome
        tcp: BTreeMap<IpAddr, BTreeMap<u16, Outcome>>,
        sent: Mutex<Vec<String>>,
    }

    impl Fake {
        fn new() -> Self {
            Self {
                caps: Capabilities::UNPRIVILEGED,
                ..Default::default()
            }
        }
        fn note(&self, what: String) {
            self.sent.lock().unwrap().push(what);
        }
        fn count(&self, needle: &str) -> usize {
            self.sent
                .lock()
                .unwrap()
                .iter()
                .filter(|s| s.starts_with(needle))
                .count()
        }
    }

    impl Transport for Fake {
        fn capabilities(&self) -> Capabilities {
            self.caps
        }
        fn arp(&self, addr: Ipv4Addr, _: Duration) -> io::Result<Option<MacAddr>> {
            self.note(format!("arp {addr}"));
            Ok(self.arp.get(&addr).copied())
        }
        fn ping(&self, addr: IpAddr, _: Duration) -> io::Result<Option<Echo>> {
            self.note(format!("ping {addr}"));
            // Both real platforms answer a v6 address this way, so the fake
            // does too: a fake that is kinder than the transport it stands in
            // for is a test that passes for the wrong reason.
            if addr.is_ipv6() {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "IPv6 echo is not implemented",
                ));
            }
            Ok(self.pings.contains(&addr).then(|| Echo {
                rtt: Duration::from_millis(3),
                ttl: self.ttls.get(&addr).copied(),
            }))
        }
        fn tcp(&self, addr: IpAddr, port: u16, _: Duration) -> Outcome {
            self.note(format!("tcp {addr}:{port}"));
            self.tcp
                .get(&addr)
                .and_then(|p| p.get(&port))
                .copied()
                .unwrap_or(Outcome::NoAnswer)
        }
    }

    fn run(prefix: &str, fake: &Fake, opts: Options) -> Sweep {
        sweep(
            prefix.parse().unwrap(),
            fake,
            &Bucket::new(1_000_000),
            opts,
            &AtomicBool::new(false),
            &|_, _| {},
        )
    }

    fn v4(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn finds_a_host_by_arp_and_keeps_its_hardware_address() {
        let mut fake = Fake::new();
        fake.arp
            .insert(v4("192.168.1.1"), "3c:22:fb:aa:bb:cc".parse().unwrap());

        let s = run("192.168.1.0/24", &fake, Options::on_link());
        assert_eq!(s.found.len(), 1);
        assert_eq!(s.found[0].address, ip("192.168.1.1"));
        assert_eq!(s.found[0].mac, Some("3c:22:fb:aa:bb:cc".parse().unwrap()));
        assert_eq!(s.found[0].evidence[0].reason(), "answered ARP");
        assert_eq!(s.probed, 254);
        assert!(s.is_complete());
    }

    /// The bands, against TTLs recorded on real replies.
    ///
    /// 64, 128 and 255 are the three devices answering from this wire; 63,
    /// 127 and 254 are the same three answering from behind one router, which
    /// is the case the rounding exists for and the one a rule written as
    /// equality would get wrong on every network with a second subnet.
    #[test]
    fn a_reply_from_this_wire_and_one_from_behind_a_router_read_the_same() {
        for observed in [64, 63, 60, 48] {
            assert_eq!(Stack::of(observed), Some(Stack::Unix), "{observed}");
        }
        for observed in [128, 127, 120, 112] {
            assert_eq!(Stack::of(observed), Some(Stack::Windows), "{observed}");
        }
        for observed in [255, 254, 250, 239] {
            assert_eq!(Stack::of(observed), Some(Stack::Embedded), "{observed}");
        }
        assert_eq!(Stack::Unix.initial(), 64);
        assert_eq!(Stack::Windows.initial(), 128);
        assert_eq!(Stack::Embedded.initial(), 255);
    }

    /// And the half that keeps the claim honest: rounding up always succeeds,
    /// so a rule that only rounded would answer for every byte from 1 to 255.
    /// A value too far below a band is a packet whose initial value cannot be
    /// recovered, and a blank is the answer.
    #[test]
    fn a_ttl_that_fits_no_band_is_a_blank_rather_than_the_nearest_guess() {
        // 100 would be a Windows stack twenty-eight routers away, 33 a
        // Unix-like one thirty-one away, and 200 something fifty-five away.
        // Nothing a scan of a local network reaches is any of those.
        for observed in [1, 33, 47, 65, 100, 111, 129, 200, 238] {
            assert_eq!(Stack::of(observed), None, "{observed}");
        }
        // 32 is the one that matters most: it is also where a handful of old
        // stacks start, so reading it as a distant 64 would be picking one of
        // two answers with nothing to choose between them.
        assert_eq!(Stack::of(32), None);
    }

    /// The point of the change: a ping already sends and already waits, and
    /// what came back with it now reaches the device list.
    #[test]
    fn a_ping_carries_the_stack_it_answered_with() {
        let mut fake = Fake::new();
        fake.pings.push(ip("192.168.1.5"));
        fake.ttls.insert(ip("192.168.1.5"), 128);
        fake.pings.push(ip("192.168.1.6"));
        fake.ttls.insert(ip("192.168.1.6"), 64);
        // Answered, and the reply carried no TTL: a ping socket on a kernel
        // that would not hand the field over.
        fake.pings.push(ip("192.168.1.7"));

        let s = run("192.168.1.0/28", &fake, Options::default());
        let by = |a: &str| {
            s.found
                .iter()
                .find(|f| f.address == ip(a))
                .expect("it answered")
        };
        assert_eq!(by("192.168.1.5").ttl, Some(128));
        assert_eq!(by("192.168.1.5").stack(), Some(Stack::Windows));
        assert_eq!(by("192.168.1.6").stack(), Some(Stack::Unix));
        assert_eq!(
            by("192.168.1.7").stack(),
            None,
            "a reply with no TTL on it claims no stack"
        );
    }

    /// A device found some other way has no stack, and must not borrow one.
    /// The row is blank because nothing measured it, which is what
    /// [`Found::was_probed`] already says about the round trip beside it.
    #[test]
    fn a_device_that_was_never_pinged_claims_no_stack() {
        let mut fake = Fake::new();
        fake.tcp
            .insert(ip("192.168.1.3"), BTreeMap::from([(80, Outcome::Open)]));

        let s = run("192.168.1.0/29", &fake, Options::default());
        assert_eq!(s.found[0].ttl, None);
        assert_eq!(s.found[0].stack(), None);
        assert_eq!(
            Found::announced(ip("192.168.1.9"), Protocol::Ssdp).stack(),
            None
        );
    }

    /// The rule this module exists for. A device that refuses is a device.
    #[test]
    fn a_refused_connection_proves_a_host() {
        let mut fake = Fake::new();
        fake.tcp.insert(
            ip("192.168.1.7"),
            BTreeMap::from([(80, Outcome::NoAnswer), (443, Outcome::Refused)]),
        );

        let s = run("192.168.1.0/24", &fake, Options::default());
        assert_eq!(s.found.len(), 1);
        assert_eq!(s.found[0].address, ip("192.168.1.7"));
        assert_eq!(s.found[0].evidence, vec![Evidence::TcpRefused(443)]);
        assert_eq!(s.found[0].evidence[0].reason(), "port 443 refused");
    }

    /// The second round of the knock is for the devices that drop everything,
    /// and it is only paid by an address that answered none of the first four.
    #[test]
    fn the_harder_knock_is_only_for_an_address_that_answered_nothing() {
        let mut fake = Fake::new();
        // One that refuses on the first port, one that opens the last of the
        // first four, and one that says nothing at all.
        fake.tcp
            .insert(ip("192.168.1.1"), BTreeMap::from([(80, Outcome::Refused)]));
        fake.tcp
            .insert(ip("192.168.1.2"), BTreeMap::from([(445, Outcome::Open)]));

        run("192.168.1.0/29", &fake, Options::default());

        assert_eq!(fake.count("tcp 192.168.1.1:"), 1, "stopped at the refusal");
        assert_eq!(
            fake.count("tcp 192.168.1.2:"),
            KNOCK_PORTS.len(),
            "an open port in the first round ends the knock there"
        );
        assert_eq!(
            fake.count("tcp 192.168.1.3:"),
            KNOCK_PORTS.len() + KNOCK_HARDER.len(),
            "and an address that answered nothing gets the second round"
        );
    }

    /// A television that opens only 7000 is a device, and it was not one
    /// before: the first four ports find nothing on it at all.
    #[test]
    fn a_device_that_only_opens_an_airplay_port_is_found() {
        let mut fake = Fake::new();
        fake.tcp
            .insert(ip("192.168.1.9"), BTreeMap::from([(7000, Outcome::Open)]));

        let s = run("192.168.1.0/28", &fake, Options::default());
        assert_eq!(s.found.len(), 1);
        assert_eq!(s.found[0].address, ip("192.168.1.9"));
        assert_eq!(s.found[0].evidence, vec![Evidence::TcpOpen(7000)]);
    }

    /// A device the link answered for joins the list, in address order, and
    /// says how it got there.
    #[test]
    fn a_host_that_only_announced_itself_is_admitted() {
        let mut sweep = Sweep::default();
        assert!(sweep.admit(Found::announced(ip("192.168.1.9"), Protocol::Ssdp)));
        assert!(sweep.admit(Found::announced(ip("192.168.1.3"), Protocol::WsDiscovery)));

        assert_eq!(
            sweep.found.iter().map(|f| f.address).collect::<Vec<_>>(),
            vec![ip("192.168.1.3"), ip("192.168.1.9")],
            "the list stays in address order"
        );
        assert_eq!(
            sweep.found[0].evidence[0].reason(),
            "announced itself over WS-Discovery"
        );
        assert!(!sweep.found[0].was_probed());
        assert_eq!(sweep.heard(), 2);
    }

    /// A device that answered both a probe and the link keeps both reasons,
    /// and is one row.
    #[test]
    fn an_address_admitted_twice_gains_a_reason_rather_than_a_row() {
        let mut sweep = Sweep::default();
        sweep.found.push(Found {
            address: ip("192.168.1.9"),
            mac: None,
            mac_said: None,
            evidence: vec![Evidence::Ping],
            rtt: Some(Duration::from_millis(3)),
            ttl: Some(64),
        });

        assert!(!sweep.admit(Found::announced(ip("192.168.1.9"), Protocol::Mdns)));
        assert_eq!(sweep.found.len(), 1);
        assert_eq!(
            sweep.found[0].evidence,
            vec![Evidence::Ping, Evidence::Announced(Protocol::Mdns)]
        );
        // It answered a probe, so it is not one of the heard.
        assert!(sweep.found[0].was_probed());
        assert_eq!(sweep.heard(), 0);
        // And the measurements it already had are not thrown away by an
        // announcement, which measures nothing.
        assert_eq!(sweep.found[0].rtt, Some(Duration::from_millis(3)));
        assert_eq!(sweep.found[0].stack(), Some(Stack::Unix));
    }

    /// The neighbour table finds a device that answered nothing, and stays
    /// quiet about one that answered for itself — where it would only repeat
    /// what ARP already said.
    #[test]
    fn the_neighbour_table_speaks_only_when_it_is_the_one_that_knows() {
        let mac = MacAddr::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        let mut sweep = Sweep::default();
        sweep.found.push(Found {
            address: ip("192.168.1.9"),
            mac: Some(mac),
            mac_said: None,
            evidence: vec![Evidence::Arp(mac)],
            rtt: None,
            ttl: None,
        });

        assert!(!sweep.admit_neighbour(ip("192.168.1.9"), mac));
        assert_eq!(
            sweep.found[0].evidence,
            vec![Evidence::Arp(mac)],
            "it adds no reason to a device that answered for itself"
        );

        assert!(sweep.admit_neighbour(ip("192.168.1.4"), mac));
        assert_eq!(sweep.found[0].address, ip("192.168.1.4"));
        assert_eq!(sweep.found[0].evidence, vec![Evidence::Neighbour]);
    }

    /// A device found by a multicast answer has no hardware address, and the
    /// neighbour table very often has one. That is the other half of why the
    /// table is read even when it says nothing new about presence.
    #[test]
    fn the_neighbour_table_lends_a_hardware_address_without_taking_credit() {
        let mac = MacAddr::new([0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]);
        let mut sweep = Sweep::default();
        sweep.admit(Found::announced(ip("192.168.1.9"), Protocol::Ssdp));
        assert_eq!(sweep.found[0].mac, None);

        assert!(!sweep.admit_neighbour(ip("192.168.1.9"), mac));
        assert_eq!(sweep.found[0].mac, Some(mac));
        assert_eq!(
            sweep.found[0].evidence,
            vec![Evidence::Announced(Protocol::Ssdp)]
        );
    }

    /// And its mirror: silence is not a host.
    #[test]
    fn silence_finds_nothing() {
        let fake = Fake::new();
        let s = run("192.168.1.0/24", &fake, Options::default());
        assert!(s.found.is_empty());
        assert_eq!(s.probed, 254);
        assert!(
            s.is_complete(),
            "a sweep that found nothing still did its job"
        );
    }

    /// Once something has answered, the knock is wasted probes. Off-link,
    /// where the ping is the only thing that can answer first.
    #[test]
    fn a_host_that_answered_is_not_knocked_on() {
        let mut fake = Fake::new();
        fake.pings.push(ip("192.168.1.5"));

        run("192.168.1.0/28", &fake, Options::default());
        assert_eq!(fake.count("tcp 192.168.1.5:"), 0, "it already answered");
        assert!(
            fake.count("tcp 192.168.1.6:") > 0,
            "the silent one is knocked on"
        );
    }

    /// A refusal ends the knock; an open port does not, because a second open
    /// port is worth knowing and costs nothing extra to notice.
    #[test]
    fn the_knock_stops_at_a_refusal() {
        let mut fake = Fake::new();
        fake.tcp
            .insert(ip("192.168.1.3"), BTreeMap::from([(80, Outcome::Refused)]));
        fake.tcp.insert(
            ip("192.168.1.4"),
            BTreeMap::from([(80, Outcome::Open), (443, Outcome::Open)]),
        );

        run("192.168.1.0/29", &fake, Options::default());
        assert_eq!(fake.count("tcp 192.168.1.3:"), 1, "stopped at the RST");
        assert_eq!(fake.count("tcp 192.168.1.4:"), KNOCK_PORTS.len());

        let s = run("192.168.1.0/29", &fake, Options::default());
        let open = s
            .found
            .iter()
            .find(|f| f.address == ip("192.168.1.4"))
            .unwrap();
        assert_eq!(open.open_ports(), vec![80, 443]);
    }

    /// On a local wire an unanswered ARP settles the address, and the ping and
    /// four knocks after it are four seconds spent proving it twice.
    #[test]
    fn on_link_silence_from_arp_ends_the_probe() {
        let mut fake = Fake::new();
        fake.arp
            .insert(v4("192.168.1.1"), "3c:22:fb:aa:bb:cc".parse().unwrap());

        let s = run("192.168.1.0/29", &fake, Options::on_link());
        assert_eq!(s.found.len(), 1);
        assert_eq!(fake.count("arp"), 6, "every address is still asked");
        assert_eq!(
            fake.count("tcp"),
            0,
            "and none of the silent ones is knocked on"
        );
        assert_eq!(
            fake.count("ping"),
            1,
            "only the host that answered is pinged"
        );
    }

    /// Off the link an address is *supposed* to have no ARP reply, so taking
    /// that as absence would find nothing anywhere.
    #[test]
    fn off_link_silence_from_arp_settles_nothing() {
        let mut fake = Fake::new();
        fake.tcp
            .insert(ip("192.168.1.3"), BTreeMap::from([(80, Outcome::Open)]));

        let s = run("192.168.1.0/29", &fake, Options::default());
        assert_eq!(s.found.len(), 1, "found through the knock alone");
        assert_eq!(s.found[0].evidence, vec![Evidence::TcpOpen(80)]);
        assert!(fake.count("tcp") > 0);
    }

    /// And off the link it is not *asked*, which is the stronger rule.
    ///
    /// `SendARP` resolves through the routing table, so one hop away the stack
    /// answers with the gateway's hardware address rather than the
    /// destination's. A sweep that took that would report every address in the
    /// prefix as a device, all of them wearing the same MAC, and it would do so
    /// only on Windows: Linux reads the cache and cannot invent it. The two
    /// platforms have to answer the same scan the same way.
    #[test]
    fn arp_is_not_asked_off_link_at_all() {
        let mut fake = Fake::new();
        fake.arp
            .insert(v4("192.168.1.3"), "3c:22:fb:aa:bb:cc".parse().unwrap());

        let s = run("192.168.1.0/29", &fake, Options::default());
        assert_eq!(fake.count("arp"), 0, "not one request went out");
        assert!(
            s.found.is_empty(),
            "and no hardware address was invented: {:?}",
            s.found
        );
        assert!(
            s.not_done.is_empty(),
            "nor is a technique that does not apply reported as missing: {:?}",
            s.not_done
        );
    }

    /// The mechanism failing is not the address answering. A broken ARP must
    /// fall through to the other probes rather than concluding an empty
    /// network — the same rule as everywhere else in this crate.
    #[test]
    fn a_broken_arp_does_not_settle_an_address_even_on_link() {
        struct Broken;
        impl Transport for Broken {
            fn capabilities(&self) -> Capabilities {
                Capabilities::UNPRIVILEGED
            }
            fn arp(&self, _: Ipv4Addr, _: Duration) -> io::Result<Option<MacAddr>> {
                Err(io::Error::other("the ARP mechanism is broken"))
            }
            fn ping(&self, addr: IpAddr, _: Duration) -> io::Result<Option<Echo>> {
                Ok((addr == ip("192.168.1.2")).then_some(Echo::timed(Duration::from_millis(1))))
            }
            fn tcp(&self, _: IpAddr, _: u16, _: Duration) -> Outcome {
                Outcome::NoAnswer
            }
        }

        let s = sweep(
            "192.168.1.0/29".parse().unwrap(),
            &Broken,
            &Bucket::new(1_000_000),
            Options::on_link(),
            &AtomicBool::new(false),
            &|_, _| {},
        );
        assert_eq!(s.found.len(), 1, "the pinging host survives a broken ARP");
        assert_eq!(s.found[0].address, ip("192.168.1.2"));

        // And it is *said*. Falling through quietly still leaves a sweep that
        // found one device on a wire where it could not look for hardware
        // addresses at all, and presents that as the answer.
        assert!(
            !s.is_complete(),
            "a broken mechanism is an incomplete sweep"
        );
        assert_eq!(s.not_done.len(), 1, "{:?}", s.not_done);
        assert!(
            s.not_done[0].contains("hardware address lookups failed"),
            "{:?}",
            s.not_done
        );
    }

    /// The Ping button's defect, in the smallest form it takes: a machine that
    /// cannot open a ping socket sends no echo, and the device still answers
    /// ARP, so the re-check used to hand back a device with no round trip and
    /// the interface reported **"nothing came back this time"** about a
    /// question nobody asked.
    #[test]
    fn a_recheck_says_when_the_echo_was_never_sent() {
        let mut fake = Fake::new();
        fake.caps.icmp = false;
        fake.arp.insert(
            "192.168.1.7".parse().unwrap(),
            MacAddr::new([0x02, 0, 0, 0, 0, 7]),
        );

        let r = recheck(
            ip("192.168.1.7"),
            &fake,
            &Bucket::new(1_000_000),
            Options::on_link(),
        );

        let found = r.found.expect("ARP answered, so the device is there");
        assert_eq!(found.rtt, None, "no echo was sent, so there is no time");
        assert_eq!(
            fake.count("ping"),
            0,
            "and the transport was never asked to send one"
        );
        assert!(
            r.not_done.iter().any(|line| line.contains("ICMP")),
            "so the re-check has to say so: {:?}",
            r.not_done
        );
    }

    /// A re-check and the sweep that found the device must describe the same
    /// machine in the same words. Two screens disagreeing about whether the
    /// echoes went out is a contradiction the reader has to resolve, and only
    /// one of the two can be right.
    #[test]
    fn a_recheck_and_a_sweep_report_the_same_gap() {
        let mut fake = Fake::new();
        fake.caps.icmp = false;

        let swept = run("192.168.1.0/30", &fake, Options::on_link());
        let r = recheck(
            ip("192.168.1.1"),
            &fake,
            &Bucket::new(1_000_000),
            Options::on_link(),
        );

        let gap = swept
            .not_done
            .iter()
            .find(|line| line.contains("ICMP"))
            .expect("the sweep says it");
        assert!(r.not_done.contains(gap), "{:?}", r.not_done);
    }

    /// And where nothing is missing, nothing is said. A re-check that could run
    /// every probe must not decorate a plain answer with caveats.
    #[test]
    fn a_recheck_with_nothing_missing_says_nothing() {
        let mut fake = Fake::new();
        fake.pings.push(ip("192.168.1.5"));

        let r = recheck(
            ip("192.168.1.5"),
            &fake,
            &Bucket::new(1_000_000),
            Options::default(),
        );

        assert!(r.found.is_some());
        assert!(r.not_done.is_empty(), "{:?}", r.not_done);
    }

    /// The same rule one layer along: a transport that cannot ping the family
    /// being swept says so rather than letting every address read as silent.
    ///
    /// This is where an IPv6 sweep lands today. `Prefix::hosts` gates on the
    /// *size* of a prefix and not on its family, so a /126 is enumerated
    /// happily, and neither platform has written the v6 echo. `Capabilities`
    /// has no family axis to express that, so the error itself is what reaches
    /// the result.
    #[test]
    fn a_family_the_transport_cannot_ping_is_a_stated_gap() {
        let fake = Fake::new();
        let s = run("2001:db8::/126", &fake, Options::default());

        assert!(s.found.is_empty());
        assert_eq!(s.probed, 4, "the addresses were walked");
        assert_eq!(fake.count("arp"), 0, "there is no ARP for IPv6");
        assert!(
            !s.is_complete(),
            "so this is not a network with nothing on it"
        );
        assert_eq!(s.not_done.len(), 1, "{:?}", s.not_done);
        assert!(
            s.not_done[0].contains("could not send an ICMP echo"),
            "{:?}",
            s.not_done
        );
        assert!(
            s.not_done[0].contains("IPv6 echo is not implemented"),
            "and it carries the transport's own reason: {:?}",
            s.not_done
        );
    }

    /// The shortcut assumes a host that ignored ARP could not use the network.
    /// True of a host, false of a *link*: guest Wi-Fi and client isolation
    /// filter ARP between clients, and there the sweep settles all 254
    /// addresses on silence, skips everything else and hands back an empty
    /// network as a finished answer.
    #[test]
    fn a_link_that_filters_arp_is_not_reported_as_an_empty_network() {
        let fake = Fake::new();
        let s = run("192.168.1.0/24", &fake, Options::on_link());

        assert!(s.found.is_empty());
        assert_eq!(s.probed, 254);
        assert_eq!(fake.count("ping"), 0, "the shortcut did take effect");
        assert!(
            !s.is_complete(),
            "but nothing found by ARP alone is not an answer"
        );
        assert!(
            s.not_done.iter().any(|l| l.contains("filters ARP")),
            "{:?}",
            s.not_done
        );
    }

    /// And the caveat is not a permanent fixture: one device answering means
    /// ARP crosses this link, and the shortcut is then exactly what it claims.
    #[test]
    fn one_answer_is_enough_to_trust_the_shortcut() {
        let mut fake = Fake::new();
        fake.arp
            .insert(v4("192.168.1.1"), "3c:22:fb:aa:bb:cc".parse().unwrap());

        let s = run("192.168.1.0/24", &fake, Options::on_link());
        assert_eq!(s.found.len(), 1);
        assert!(s.is_complete(), "{:?}", s.not_done);
    }

    /// `CLAUDE.md`: never degrade silently. A sweep without ARP finds less and
    /// has to say so.
    #[test]
    fn a_sweep_that_could_not_arp_says_what_it_missed() {
        let mut fake = Fake::new();
        fake.caps = Capabilities {
            arp: false,
            icmp: true,
            tcp: true,
        };
        fake.pings.push(ip("192.168.1.9"));

        // On-link, where ARP is the technique the sweep would otherwise lead
        // with. Off-link it is not asked for at all and is not a gap.
        let s = run("192.168.1.0/24", &fake, Options::on_link());
        assert_eq!(s.found.len(), 1, "the pinging host is still found");
        assert!(!s.is_complete(), "but the sweep is not complete");
        assert_eq!(s.not_done.len(), 1);
        assert!(s.not_done[0].contains("ARP"), "{:?}", s.not_done);
        assert_eq!(fake.count("arp"), 0, "and it did not pretend to try");
    }

    /// An IPv6 prefix is not swept address by address, and the sweep says why
    /// rather than reporting an empty network.
    #[test]
    fn an_unenumerable_prefix_is_a_stated_gap() {
        let fake = Fake::new();
        let s = run("fe80::/64", &fake, Options::default());
        assert!(s.found.is_empty());
        assert!(!s.is_complete());
        assert_eq!(s.not_done.len(), 1);
        assert!(s.not_done[0].contains("too large"), "{:?}", s.not_done);
        assert_eq!(fake.count("ping"), 0);
    }

    #[test]
    fn cancelling_stops_early_and_the_result_admits_it() {
        let mut fake = Fake::new();
        for i in 1..=250 {
            fake.arp.insert(
                v4(&format!("192.168.1.{i}")),
                "02:00:00:00:00:01".parse().unwrap(),
            );
        }
        let cancel = AtomicBool::new(false);
        let seen = AtomicU64::new(0);

        let s = sweep(
            "192.168.1.0/24".parse().unwrap(),
            &fake,
            &Bucket::new(1_000_000),
            Options {
                workers: 1,
                ..Options::on_link()
            },
            &cancel,
            &|_, _| {
                if seen.fetch_add(1, Ordering::SeqCst) >= 9 {
                    cancel.store(true, Ordering::SeqCst);
                }
            },
        );

        assert!(s.cancelled);
        assert!(!s.is_complete());
        assert!(s.probed < 254, "stopped early, probed {}", s.probed);
        assert!(s.probed >= 10, "but kept what it had, probed {}", s.probed);
        assert_eq!(s.found.len() as u64, s.probed, "and reports those findings");
    }

    #[test]
    fn progress_counts_up_to_the_total_and_no_further() {
        let fake = Fake::new();
        let last = Mutex::new(Progress {
            probed: 0,
            total: 0,
            found: 0,
        });
        let s = sweep(
            "192.168.1.0/28".parse().unwrap(),
            &fake,
            &Bucket::new(1_000_000),
            Options::default(),
            &AtomicBool::new(false),
            &|p, _| {
                let mut last = last.lock().unwrap();
                assert!(p.probed <= p.total, "{p:?} overshot");
                *last = p;
            },
        );
        assert_eq!(s.total, 14);
        assert_eq!(last.lock().unwrap().probed, 14);
    }

    /// Every probe passes the limiter, which is the rule that keeps a sweep
    /// from looking like an attack.
    ///
    /// Asserted against the **bucket**, not against the transport. The earlier
    /// version of this test counted the fake's calls, which is a count of
    /// probes sent and says nothing at all about whether any of them was
    /// charged: deleting every `rate.wait()` in `probe_one` left it green. The
    /// bucket's clock is asked exactly once per charge, so counting the reads
    /// of the clock counts the charges.
    #[test]
    fn every_probe_is_charged_to_the_rate_limiter() {
        #[derive(Clone)]
        struct Counting {
            base: Instant,
            reads: Arc<AtomicU64>,
        }
        impl crate::rate::Clock for Counting {
            fn now(&self) -> Instant {
                self.reads.fetch_add(1, Ordering::SeqCst);
                self.base
            }
        }

        let reads = Arc::new(AtomicU64::new(0));
        let clock = Counting {
            base: Instant::now(),
            reads: Arc::clone(&reads),
        };
        // A burst wide enough that a stopped clock never makes a probe wait,
        // so the test finishes instantly and still charges for every one.
        let rate = Bucket::with_clock(1_000, 64, Box::new(clock));
        let built = reads.swap(0, Ordering::SeqCst);
        assert_eq!(built, 1, "the bucket reads the clock once to start");

        let fake = Fake::new();
        sweep(
            "192.168.1.0/30".parse().unwrap(),
            &fake,
            &rate,
            Options {
                workers: 1,
                ..Default::default()
            },
            &AtomicBool::new(false),
            &|_, _| {},
        );

        // Two addresses, each one ping and then both rounds of the knock,
        // because neither answered anything. No ARP: this prefix is not
        // on-link.
        let knocks = (KNOCK_PORTS.len() + KNOCK_HARDER.len()) as u64;
        assert_eq!(fake.count("arp"), 0);
        assert_eq!(fake.count("ping"), 2);
        assert_eq!(fake.count("tcp") as u64, 2 * knocks);
        assert_eq!(
            reads.load(Ordering::SeqCst),
            2 + 2 * knocks,
            "every probe that went out was charged for"
        );
    }

    /// `CLAUDE.md`: cancelling takes effect at the next packet, not at the end
    /// of a phase. One check per address is one check per six probes, and with
    /// 254 workers that was a thousand more packets after the user pressed
    /// Stop.
    #[test]
    fn cancelling_takes_effect_at_the_next_probe_and_not_the_next_address() {
        struct StopsDuringTheFirstPing<'a> {
            cancel: &'a AtomicBool,
            probes: AtomicU64,
        }
        impl Transport for StopsDuringTheFirstPing<'_> {
            fn capabilities(&self) -> Capabilities {
                Capabilities::UNPRIVILEGED
            }
            fn arp(&self, _: Ipv4Addr, _: Duration) -> io::Result<Option<MacAddr>> {
                self.probes.fetch_add(1, Ordering::SeqCst);
                Ok(None)
            }
            fn ping(&self, _: IpAddr, _: Duration) -> io::Result<Option<Echo>> {
                self.probes.fetch_add(1, Ordering::SeqCst);
                // The user presses Stop while this one probe is in flight.
                self.cancel.store(true, Ordering::SeqCst);
                Ok(None)
            }
            fn tcp(&self, _: IpAddr, _: u16, _: Duration) -> Outcome {
                self.probes.fetch_add(1, Ordering::SeqCst);
                Outcome::NoAnswer
            }
        }

        let cancel = AtomicBool::new(false);
        let transport = StopsDuringTheFirstPing {
            cancel: &cancel,
            probes: AtomicU64::new(0),
        };
        let s = sweep(
            "192.168.1.0/29".parse().unwrap(),
            &transport,
            &Bucket::new(1_000_000),
            Options {
                workers: 1,
                ..Default::default()
            },
            &cancel,
            &|_, _| {},
        );

        assert_eq!(
            transport.probes.load(Ordering::SeqCst),
            1,
            "the four knocks behind the cancelled ping must not go out"
        );
        assert!(s.cancelled);
        assert!(!s.is_complete());
    }

    /// A counter read out of two atomics can hand a caller a pair that never
    /// existed, and a slow worker can deliver a lower count after a fast one.
    /// Either way the bar ticks backwards, which reads as the scan losing its
    /// place.
    #[test]
    fn progress_never_goes_backwards() {
        let mut fake = Fake::new();
        for i in 1..=120 {
            fake.pings.push(ip(&format!("192.168.1.{i}")));
        }
        let worst = Mutex::new((0u64, 0u64));
        sweep(
            "192.168.1.0/24".parse().unwrap(),
            &fake,
            &Bucket::new(1_000_000),
            Options {
                workers: 64,
                ..Default::default()
            },
            &AtomicBool::new(false),
            &|p, _| {
                let mut worst = worst.lock().unwrap();
                assert!(
                    p.probed >= worst.0,
                    "probed went {} then {}",
                    worst.0,
                    p.probed
                );
                assert!(
                    p.found >= worst.1,
                    "found went {} then {}",
                    worst.1,
                    p.found
                );
                assert!(p.found <= p.probed, "{p:?} found more than it probed");
                *worst = (p.probed, p.found);
            },
        );
        let (probed, found) = *worst.lock().unwrap();
        assert_eq!(probed, 254);
        assert_eq!(found, 120);
    }

    #[test]
    fn results_come_back_in_address_order_whatever_the_threads_did() {
        let mut fake = Fake::new();
        for i in [200, 3, 47, 1, 99] {
            fake.pings.push(ip(&format!("192.168.1.{i}")));
        }
        let s = run(
            "192.168.1.0/24",
            &fake,
            Options {
                workers: 32,
                ..Default::default()
            },
        );
        let order: Vec<_> = s.found.iter().map(|f| f.address.to_string()).collect();
        assert_eq!(
            order,
            [
                "192.168.1.1",
                "192.168.1.3",
                "192.168.1.47",
                "192.168.1.99",
                "192.168.1.200"
            ]
        );
    }
}
