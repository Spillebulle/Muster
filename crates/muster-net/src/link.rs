//! The questions put to the whole link at once, and everything that answers.
//!
//! ## Why this is a phase and not a step of identification
//!
//! It used to be two lines inside [`crate::identify::many`]: an SSDP search and
//! an mDNS service enumeration, sent before the per-device work and folded into
//! the devices the sweep had already found. That threw away the more valuable
//! half of what came back. `identify::many` is handed a list of addresses, so
//! an answer from an address that was not on it had nowhere to go and was
//! dropped — and the answers from addresses the sweep missed are exactly the
//! devices somebody is scanning to find.
//!
//! **A device that sends a datagram is a device.** That is evidence as good as
//! an ARP reply and better than a TCP refusal, because the datagram also says
//! what the thing is. So the link phase runs on its own and produces two things
//! at once: proof that a host exists, and an identity for it. The sweep's list
//! and this one are unioned, and [`crate::discover::Evidence::Announced`]
//! records which route each device arrived by.
//!
//! ## It runs beside the sweep, so it is free
//!
//! Every question here is one datagram out and then a wait on a socket. The
//! wait is the whole cost, and it overlaps the sweep perfectly — the pattern
//! the DHCP probe has used since it was written. So [`ask`] is started when the
//! scan starts and collected when the sweep ends, the questions run in parallel
//! with each other as well, and a link phase that listens for four seconds adds
//! nothing to a scan that was going to take longer than that anyway.
//!
//! That is what makes a long window affordable, and a long window is what these
//! protocols need: an SSDP responder is entitled to spread its replies across
//! `MX` seconds, a television sends seventeen of them, and on the television it
//! was the twelfth that named it.
//!
//! ## What is asked, and why each one
//!
//! Six questions, each answered by devices the others miss. That is the whole
//! argument for asking all of them rather than picking the best:
//!
//! | Question | Reaches |
//! |---|---|
//! | mDNS service enumeration | Apple devices, printers, anything running Avahi |
//! | mDNS by **named** service type | everything the enumeration misses — see below |
//! | SSDP `M-SEARCH` | televisions, set-top boxes, media players, routers |
//! | WS-Discovery `Probe` | **Windows machines**, network printers, ONVIF cameras |
//! | NetBIOS node status, broadcast | Windows and Samba hosts, with their workgroup |
//! | Reverse `PTR`, to this network's own resolver | anything that took a DHCP lease and then went quiet |
//!
//! **The named service types are not redundant with the enumeration**, and this
//! is the least obvious thing in the module. `_services._dns-sd._udp.local` is
//! the meta-query that asks a responder to list what it offers, and RFC 6763
//! §9 requires a responder to register itself in that list — which a great many
//! embedded responders simply do not do. `esp-idf`'s mDNS component is the
//! commonest: every ESPHome node, every Shelly and every hobbyist ESP32 on the
//! network ignores the enumeration and answers a direct question about its own
//! service type immediately. Asking by name is one more datagram and reaches a
//! whole class of device that answers nothing else at all.
//!
//! As everywhere else in this crate, nothing here opens a socket: the datagrams
//! go through [`Ask`], and every test runs against a recorded one.

use crate::discover::{Evidence, Found, Protocol, Sweep};
use crate::identify::{Ask, DNS_PORT, Identity, MDNS, NBNS_PORT, Source};
use crate::rate::Bucket;
use crate::{dns, netbios, ssdp, wsd};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// How many datagrams one question will read before it stops listening.
///
/// A link with a television, a router and a media server on it produces some
/// forty SSDP replies; the cap bounds what a hostile responder can make this
/// allocate, and is not a target.
const MOST: usize = 512;

/// Service types worth asking about by name, in the three groups they are sent
/// in.
///
/// **Three datagrams rather than one**, because a responder that answers only
/// the first question in a message is a real thing and splitting the list
/// bounds what that costs. Each group leads with the types most likely to be
/// the only thing a device answers.
///
/// Every entry here is a service whose presence says something. `_http._tcp` is
/// deliberately absent: half the devices ever made offer one and it names
/// nothing, which is the same reason it is not in [`crate::kind`]'s table.
const NAMED_SERVICES: &[&[&str]] = &[
    &[
        // Avahi publishes this by default on every Debian, Ubuntu and Pop!_OS
        // machine, and the instance name it publishes is `hostname [mac]` —
        // a name *and* a hardware address, from a device that may have
        // answered nothing else.
        "_workstation._tcp.local",
        // Apple's own model record. Asked here as well as by name in
        // `identify::one`, because that one needs a name to build the question
        // from and this one does not.
        "_device-info._tcp.local",
        "_googlecast._tcp.local",
        "_airplay._tcp.local",
        "_raop._tcp.local",
        "_companion-link._tcp.local",
        "_homekit._tcp.local",
        // HomeKit accessories, whose `TXT` carries an accessory category.
        "_hap._tcp.local",
        "_hap._udp.local",
        "_matter._tcp.local",
    ],
    &[
        "_ipp._tcp.local",
        "_ipps._tcp.local",
        "_printer._tcp.local",
        "_pdl-datastream._tcp.local",
        "_uscan._tcp.local",
        "_scanner._tcp.local",
        "_smb._tcp.local",
        "_afpovertcp._tcp.local",
        "_nfs._tcp.local",
        "_sftp-ssh._tcp.local",
    ],
    &[
        // The ESP-based smart home, which is the class the meta-query misses
        // most completely.
        "_esphomelib._tcp.local",
        "_shelly._tcp.local",
        "_tasmota._tcp.local",
        // Windows' own Delivery Optimization, which a Windows machine
        // advertises when nothing else about it is visible.
        "_dosvc._tcp.local",
        "_spotify-connect._tcp.local",
        "_sonos._tcp.local",
        "_plexmediasvr._tcp.local",
        "_androidtvremote2._tcp.local",
        "_amzn-wplay._tcp.local",
        "_ssh._tcp.local",
    ],
];

/// The extra `ST` values worth searching for beside `ssdp:all`.
///
/// A minority of responders answer a search for their own device type and
/// ignore `ssdp:all` entirely — Hue bridges and some Roku and Sonos firmware
/// are the ones observed. Three more datagrams, and each is aimed at a device
/// that would otherwise be a blank row.
const SEARCH_TARGETS: &[&str] = &[
    "upnp:rootdevice",
    "roku:ecp",
    "urn:schemas-upnp-org:device:ZonePlayer:1",
];

/// What to ask the link.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// Enumerate services over mDNS, and ask about the named types.
    pub mdns: bool,
    /// Search for UPnP devices over SSDP.
    pub ssdp: bool,
    /// Probe for WS-Discovery devices, which is how Windows answers.
    pub wsd: bool,
    /// Ask the broadcast address for a NetBIOS node status.
    pub netbios: bool,
    /// Ask this network's own resolver for a name for every address in it.
    pub reverse: bool,
    /// How long to listen after each question. The questions wait at the same
    /// time as each other, so this is very nearly the phase's whole duration.
    pub window: Duration,
    /// The link's broadcast address, where the caller knows one.
    ///
    /// [`None`] skips the questions that are broadcast rather than multicast
    /// rather than guessing at an address: a datagram sent to the wrong
    /// broadcast address is a datagram sent to somebody else's network.
    pub broadcast: Option<Ipv4Addr>,
    /// The resolver to ask for `PTR` records, **and only where it is on this
    /// machine's own link**. See [`reverse_names`] for why that is a condition
    /// rather than a preference.
    pub resolver: Option<IpAddr>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            mdns: true,
            ssdp: true,
            wsd: true,
            netbios: true,
            reverse: true,
            // Long, and it costs nothing: see the module note. The old value
            // was 2500 ms and was chosen when this ran in series with the rest
            // of identification rather than beside the sweep.
            window: Duration::from_millis(4000),
            broadcast: None,
            resolver: None,
        }
    }
}

/// How many addresses the reverse question will ask about.
///
/// One datagram per address to one server, so it is bounded like any other
/// burst: a /24 is inside this and a /16 is not.
pub const REVERSE_MOST: usize = 1024;

/// What one address said when the link was asked.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Voice {
    /// Which of the link-wide questions it answered. Never empty.
    pub protocols: BTreeSet<Protocol>,
    /// What it said about itself, merged across every question it answered.
    pub identity: Identity,
}

impl Voice {
    /// Did anything the *device itself* said get us here?
    ///
    /// False when the only protocol against its name is [`Protocol::Dns`],
    /// which is not the device speaking at all — it is the router repeating
    /// what the device told it once, possibly a long time ago and possibly
    /// about a different device that has since given the address up. The
    /// distinction decides whether the address is a device or only a record,
    /// and [`ask`] keeps both rather than resolving it away.
    pub fn spoke(&self) -> bool {
        self.protocols.iter().any(|p| *p != Protocol::Dns)
    }
}

/// Everything the link said.
#[derive(Clone, Debug, Default)]
pub struct Heard {
    /// One entry per address that answered anything.
    pub by: BTreeMap<IpAddr, Voice>,
    /// Questions that could not be asked, in words fit to show.
    ///
    /// The same contract [`crate::discover::Sweep::not_done`] has, and for the
    /// same reason: a link phase that could not send a WS-Discovery probe finds
    /// no Windows machines, and reporting that as "there are no Windows
    /// machines" is the failure this application refuses to produce.
    pub not_done: Vec<String>,
}

impl Heard {
    /// The addresses that answered in their own voice, in order.
    ///
    /// Not every address in [`Self::by`]: a resolver's `PTR` record names an
    /// address without proving anything is at it, and admitting those to the
    /// device list as though they had answered would be inventing devices out
    /// of a router's memory. They are still carried, so a device the sweep
    /// found by another route gets its name.
    pub fn speakers(&self) -> impl Iterator<Item = (IpAddr, &Voice)> + '_ {
        self.by
            .iter()
            .filter_map(|(address, voice)| voice.spoke().then_some((*address, voice)))
    }

    /// Which protocol to credit a device with, where it answered more than one.
    ///
    /// The first in [`Protocol`]'s own order, which is the order of how much a
    /// reply narrows down what the device is.
    pub fn credit(&self, address: IpAddr) -> Option<Protocol> {
        self.by
            .get(&address)
            .and_then(|v| v.protocols.iter().find(|p| **p != Protocol::Dns).copied())
    }

    /// Folds one address's answer in, merging with anything already there.
    fn record(&mut self, address: IpAddr, protocol: Protocol, identity: Identity) {
        let voice = self.by.entry(address).or_default();
        voice.protocols.insert(protocol);
        voice.identity.merge(&identity);
    }
}

/// Folds what the link said into a device list and the identities beside it.
///
/// **The two lists are parallel by index and must stay that way**, which is the
/// whole reason this is a function rather than four lines at each call site: a
/// device admitted to `found` without an identity inserted at the same position
/// silently shifts every later row onto its neighbour's name. Both front ends
/// do this, and doing it twice by hand is how they would come to disagree.
///
/// A device the sweep already found gains a reason and whatever the link said
/// about it. A device it did not becomes a new row, credited to the protocol
/// that answered for it. Addresses that were only ever *named* — a resolver's
/// `PTR` record, which proves nothing is there — annotate an existing row and
/// never create one; see [`Voice::spoke`].
///
/// Answers with the addresses that were not on the list before.
pub fn fold(heard: &Heard, sweep: &mut Sweep, names: &mut Vec<Identity>) -> Vec<IpAddr> {
    let mut added = Vec::new();
    for (address, voice) in &heard.by {
        match sweep.found.binary_search_by_key(address, |f| f.address) {
            Ok(at) => {
                if let Some(protocol) = heard.credit(*address) {
                    sweep.found[at].attest(Evidence::Announced(protocol));
                }
                if let Some(identity) = names.get_mut(at) {
                    identity.merge(&voice.identity);
                }
                if sweep.found[at].mac.is_none() {
                    sweep.found[at].mac = voice.identity.mac;
                    sweep.found[at].mac_said = voice.identity.mac_route();
                }
            }
            Err(at) => {
                // Only what spoke becomes a row. A name is not a device.
                let Some(protocol) = heard.credit(*address) else {
                    continue;
                };
                let mut row = Found::announced(*address, protocol);
                // **The address the device stated, on the row that has no
                // other.** A device the sweep never probed has no ARP reply
                // and no neighbour entry behind it, so this is the only
                // hardware address its row will ever carry — and without it
                // the vendor column is blank for exactly the devices this
                // phase exists to find. The route is carried beside it,
                // because a device saying its own address is a weaker claim
                // than a stack answering for it and the interface has to be
                // able to say which happened.
                row.mac = voice.identity.mac;
                row.mac_said = voice.identity.mac_route();
                sweep.found.insert(at, row);
                if at <= names.len() {
                    names.insert(at, voice.identity.clone());
                }
                added.push(*address);
            }
        }
    }
    added
}

/// One question's answer: what it heard, and what it could not do.
type Answer = (Vec<(IpAddr, Protocol, Identity)>, Option<String>);

/// Asks the link everything, and returns what answered.
///
/// The questions run at the same time as each other, one thread and one socket
/// apiece, because each is a single datagram followed by the same wait: in
/// series they would cost the sum of the windows and in parallel they cost one.
///
/// **Never fails.** A question that could not be sent is a line in
/// [`Heard::not_done`], not an error: the caller has devices to report either
/// way, and the one thing it must not do is present a short list as a complete
/// one.
pub fn ask<A: Ask + ?Sized>(
    ask: &A,
    opts: Options,
    addresses: &[IpAddr],
    rate: &Bucket,
    cancel: &AtomicBool,
) -> Heard {
    let mut heard = Heard::default();
    if cancel.load(Ordering::Relaxed) {
        return heard;
    }

    let questions: Vec<Box<dyn Fn() -> Answer + Send + Sync + '_>> = {
        let mut out: Vec<Box<dyn Fn() -> Answer + Send + Sync + '_>> = Vec::new();
        if opts.mdns {
            out.push(Box::new(move || mdns_services(ask, opts)));
            out.push(Box::new(move || mdns_named(ask, opts, cancel)));
        }
        if opts.ssdp {
            out.push(Box::new(move || upnp(ask, opts, cancel)));
        }
        if opts.wsd {
            out.push(Box::new(move || windows(ask, opts)));
        }
        if opts.netbios {
            out.push(Box::new(move || nbns(ask, opts)));
        }
        if opts.reverse {
            out.push(Box::new(move || {
                reverse_names(ask, opts, addresses, rate, cancel)
            }));
        }
        out
    };

    let answers: Vec<Answer> = std::thread::scope(|scope| {
        let handles: Vec<_> = questions
            .iter()
            .map(|question| scope.spawn(question))
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or_default())
            .collect()
    });

    for (found, gap) in answers {
        for (address, protocol, identity) in found {
            heard.record(address, protocol, identity);
        }
        if let Some(gap) = gap {
            heard.not_done.push(gap);
        }
    }
    heard
}

/// The mDNS service enumeration: "list the service types you offer".
fn mdns_services<A: Ask + ?Sized>(ask: &A, opts: Options) -> Answer {
    let found = crate::identify::sweep_services(ask, opts.window);
    let out = found
        .into_iter()
        .map(|(address, identity)| (address, Protocol::Mdns, identity))
        .collect();
    (out, None)
}

/// mDNS again, asking about service types by name.
///
/// See the module note for why this is not the same question as the
/// enumeration. The groups go out one after another and the replies to all of
/// them are read together, because they are answered on the same socket.
fn mdns_named<A: Ask + ?Sized>(ask: &A, opts: Options, cancel: &AtomicBool) -> Answer {
    let mut by: BTreeMap<IpAddr, Identity> = BTreeMap::new();
    let each = opts.window / NAMED_SERVICES.len() as u32;

    for (group, names) in NAMED_SERVICES.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let questions: Vec<(&str, u16)> = names.iter().map(|n| (*n, dns::TYPE_PTR)).collect();
        // The group's index as the transaction id, so a reply to one group is
        // recognisable rather than merely unlikely to be confused with another.
        let query = dns::multicast_query(group as u16, &questions);
        let Ok(replies) = ask.ask_all(MDNS, &query, each, MOST) else {
            continue;
        };
        for (from, reply) in replies {
            let Some(message) = dns::parse(&reply) else {
                continue;
            };
            // Attributed by the address in the reply's own records where there
            // is one, and by the sender otherwise. See [`crate::identify`]:
            // a Bonjour sleep proxy answers on behalf of a machine that is
            // asleep, and crediting the proxy with the sleeping machine's
            // services is how one device becomes two wrong ones.
            let about = crate::identify::subject(&message, from);
            let entry = by.entry(about).or_default();
            let mut models = Vec::new();
            crate::identify::harvest(&message, entry, &mut models);
            models.sort_by_key(|(rank, _)| *rank);
            if entry.model.is_none() {
                entry.model = models.into_iter().next().map(|(_, value)| value);
            }
        }
    }

    let out = by
        .into_iter()
        .filter(|(_, identity)| !identity.is_empty())
        .map(|(address, identity)| (address, Protocol::Mdns, identity))
        .collect();
    (out, None)
}

/// The SSDP search, for everything and then for three device types that some
/// responders answer and `ssdp:all` does not reach.
fn upnp<A: Ask + ?Sized>(ask: &A, opts: Options, cancel: &AtomicBool) -> Answer {
    let mut by: BTreeMap<IpAddr, Identity> = BTreeMap::new();
    let mut fold = |announced: BTreeMap<IpAddr, Vec<ssdp::Announcement>>| {
        for (address, announcements) in announced {
            let identity = by.entry(address).or_default();
            for announcement in &announcements {
                identity.announced(announcement);
            }
        }
    };

    // Most of the window on the search that reaches most devices, and the rest
    // shared between the three that top it up.
    fold(ssdp::discover(ask, opts.window / 2));
    let each = opts.window / 2 / SEARCH_TARGETS.len() as u32;
    for target in SEARCH_TARGETS {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        fold(ssdp::search_for(ask, target, each));
    }

    let out = by
        .into_iter()
        .map(|(address, identity)| (address, Protocol::Ssdp, identity))
        .collect();
    (out, None)
}

/// The WS-Discovery probe.
///
/// **This is the question that finds Windows.** The identity it produces is
/// deliberately thin — WS-Discovery carries no hostname, so there is no name to
/// take — and what it does carry is the device's type list, which
/// [`crate::kind`] reads. Most of the value is in the reply having arrived at
/// all: an address that answered here is a device, and on a network of Windows
/// machines behind their own firewalls that is a row that did not exist before.
fn windows<A: Ask + ?Sized>(ask: &A, opts: Options) -> Answer {
    // A fresh `MessageID` per scan, from the clock: a responder that has
    // already answered an id is entitled to ignore it, so a constant here would
    // make every scan after the first find fewer devices than the first.
    let id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0x4d75_7374_4d75_7374, |d| d.as_nanos());

    let Ok(replies) = ask.ask_all(wsd::GROUP, &wsd::probe(id), opts.window, MOST) else {
        return (Vec::new(), None);
    };

    let mut by: BTreeMap<IpAddr, Identity> = BTreeMap::new();
    for (from, reply) in replies {
        let Some(matched) = wsd::parse(&reply) else {
            continue;
        };
        by.entry(from).or_default().probed(&matched);
    }
    let out = by
        .into_iter()
        .map(|(address, identity)| (address, Protocol::WsDiscovery, identity))
        .collect();
    (out, None)
}

/// The NetBIOS node status, asked of the broadcast address rather than of one
/// machine.
///
/// **The same lesson mDNS and SSDP both taught.** A node status query sent to
/// one machine is answered by that machine; one sent to the broadcast address
/// is answered by every machine on the link that still speaks NetBIOS,
/// including ones the sweep never reached. It costs one datagram where the
/// per-device question costs one each, it is the only question here that yields
/// a *workgroup*, and its reply carries the machine's **hardware address** —
/// which is worth a great deal to an engine that cannot send an ARP request.
fn nbns<A: Ask + ?Sized>(ask: &A, opts: Options) -> Answer {
    let Some(broadcast) = opts.broadcast else {
        return (
            Vec::new(),
            Some(
                "could not work out this network's broadcast address, so the NetBIOS \
                 question was not put to the link and Windows machines that answer \
                 only that were missed"
                    .into(),
            ),
        );
    };

    let to = SocketAddr::new(IpAddr::V4(broadcast), NBNS_PORT);
    let question = netbios::node_status_query(0);
    let Ok(replies) = ask.ask_all(to, &question, opts.window, MOST) else {
        return (Vec::new(), None);
    };

    let mut by: BTreeMap<IpAddr, Identity> = BTreeMap::new();
    for (from, reply) in replies {
        let Some(status) = netbios::parse_node_status(&reply) else {
            continue;
        };
        let identity = by.entry(from).or_default();
        if let Some(name) = status.hostname() {
            identity.add(name.to_string(), Source::NetBios);
        }
        if identity.workgroup.is_none() {
            identity.workgroup = status.workgroup().map(str::to_string);
        }
        if identity.mac.is_none() {
            identity.mac = status.mac;
        }
        if let Some(mac) = status.mac {
            identity.says(crate::claim::Claim::new(mac, crate::claim::Route::NetBios));
        }
    }
    let out = by
        .into_iter()
        .filter(|(_, identity)| !identity.is_empty())
        .map(|(address, identity)| (address, Protocol::NetBios, identity))
        .collect();
    (out, None)
}

/// Asks this network's own resolver for a name for every address in it.
///
/// **This is the question that names the devices that are asleep.** On nearly
/// every home network the resolver is the gateway, the gateway is running
/// `dnsmasq` or something like it, and it answers a `PTR` out of its own DHCP
/// lease table. A phone that took a lease, told the router its name, and then
/// went to sleep behind a firewall that drops rather than refuses is named
/// here and by nothing else Muster can do without privileges.
///
/// ## It is asked only of a resolver on this machine's own link
///
/// `CLAUDE.md`'s rule is that a question put to somebody else's resolver
/// carries nothing about this network, and this question carries a great deal:
/// two hundred and fifty addresses from the user's own LAN, and which of them
/// have devices at them. Asked of the gateway, that is a fact the gateway
/// already wrote down, and the datagram never leaves the wire. Asked of
/// `1.1.1.1`, or of a resolver reached down a VPN, it is a map of the user's
/// network handed to a stranger — and `in-addr.arpa` for a private range does
/// not reliably stop at the resolver either: RFC 6303 tells a resolver to
/// answer those locally, most do, and the ones that do not send the query to
/// the public internet where AS112 exists precisely because so many of them
/// escape.
///
/// So an off-link resolver is not asked, and the interface is told why rather
/// than being handed a shorter list of devices with no explanation. Nothing but
/// addresses already in this machine's own routing table is ever sent, and a
/// device's own name is never sent anywhere.
///
/// ## And it stops early when there is nothing to find
///
/// A router that does not keep reverse records answers `NXDOMAIN` to all 254,
/// which is 254 pointless datagrams. So the gateway's own address is asked
/// first: it is the one address on the network certain to have a record if any
/// address does. Nothing there means the whole sweep is skipped.
fn reverse_names<A: Ask + ?Sized>(
    ask: &A,
    opts: Options,
    addresses: &[IpAddr],
    rate: &Bucket,
    cancel: &AtomicBool,
) -> Answer {
    let Some(resolver) = opts.resolver else {
        // Not a gap worth a sentence: the caller passes `None` both when the
        // resolver could not be read and when it is deliberately not being
        // asked, and neither is a fact about a device.
        return (Vec::new(), None);
    };

    let asking: Vec<Ipv4Addr> = addresses
        .iter()
        .filter_map(|a| match a {
            IpAddr::V4(v4) => Some(*v4),
            IpAddr::V6(_) => None,
        })
        .take(REVERSE_MOST)
        .collect();
    if asking.is_empty() {
        return (Vec::new(), None);
    }
    if addresses.len() > REVERSE_MOST {
        return (
            Vec::new(),
            Some(format!(
                "this network has more than {REVERSE_MOST} addresses in it, so its \
                 resolver was not asked for a name for each of them and devices \
                 that are only named there were missed"
            )),
        );
    }

    let to = SocketAddr::new(resolver, DNS_PORT);
    let mut by: BTreeMap<IpAddr, Identity> = BTreeMap::new();
    // One exchange, and its answer decides whether the rest are worth sending.
    // The resolver's own address is the one certain to be named if anything is.
    let mut answered_any = false;

    for (i, address) in asking.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        // After the first handful, give up on a resolver that has answered
        // nothing: it does not keep reverse records for this network and the
        // remaining two hundred questions would all be `NXDOMAIN`.
        if i == PATIENCE && !answered_any {
            break;
        }
        if !rate.wait_unless(cancel) {
            break;
        }
        let question = dns::query(i as u16, &dns::reverse_name(*address), dns::TYPE_PTR, false);
        let Ok(reply) = ask.ask(to, &question, REVERSE_WAIT) else {
            continue;
        };
        let Some(message) = dns::parse(&reply) else {
            continue;
        };
        answered_any = true;
        let Some(name) = message.first_ptr() else {
            continue;
        };
        by.entry(IpAddr::V4(*address))
            .or_default()
            .add(name.to_string(), Source::ReverseDns);
    }

    let out = by
        .into_iter()
        .map(|(address, identity)| (address, Protocol::Dns, identity))
        .collect();
    (out, None)
}

/// How many addresses to ask about before concluding that a resolver keeps no
/// reverse records for this network.
///
/// The first addresses in a prefix are the ones most likely to be a gateway or
/// a server with a name, so a resolver that keeps records at all is very likely
/// to have answered inside this many. Getting it wrong costs a name; getting
/// the other side of it wrong costs 250 datagrams to a server that has nothing
/// to say.
const PATIENCE: usize = 12;

/// How long one reverse question waits.
///
/// The resolver is on the same wire, so a reply is a millisecond away or is not
/// coming. This is paid once per address that answers nothing.
const REVERSE_WAIT: Duration = Duration::from_millis(300);

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::Mutex;

    /// A link that answers recorded datagrams, keyed by where the question
    /// went.
    #[derive(Default)]
    struct Link {
        /// Replies to a group question, by destination.
        group: BTreeMap<SocketAddr, Vec<(IpAddr, Vec<u8>)>>,
        /// Replies to a private question, by destination.
        private: BTreeMap<SocketAddr, Vec<u8>>,
        asked: Mutex<Vec<SocketAddr>>,
    }

    impl Ask for Link {
        fn ask(&self, to: SocketAddr, _p: &[u8], _t: Duration) -> io::Result<Vec<u8>> {
            self.asked.lock().unwrap().push(to);
            match self.private.get(&to) {
                Some(reply) => Ok(reply.clone()),
                None => Err(io::Error::new(io::ErrorKind::TimedOut, "nothing answered")),
            }
        }

        fn ask_all(
            &self,
            to: SocketAddr,
            _p: &[u8],
            _w: Duration,
            _m: usize,
        ) -> io::Result<Vec<(IpAddr, Vec<u8>)>> {
            self.asked.lock().unwrap().push(to);
            match self.group.get(&to) {
                Some(replies) => Ok(replies.clone()),
                None => Err(io::Error::new(io::ErrorKind::TimedOut, "nothing answered")),
            }
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn mac(s: &str) -> crate::MacAddr {
        s.parse().unwrap()
    }

    use crate::claim::Route;

    /// Every question off, so a test switches on the one it is about.
    fn quiet() -> Options {
        Options {
            mdns: false,
            ssdp: false,
            wsd: false,
            netbios: false,
            reverse: false,
            broadcast: Some(Ipv4Addr::new(192, 168, 1, 255)),
            resolver: None,
            window: Duration::from_millis(10),
        }
    }

    fn run(link: &Link, opts: Options, addresses: &[IpAddr]) -> Heard {
        ask(
            link,
            opts,
            addresses,
            &Bucket::new(1_000_000),
            &AtomicBool::new(false),
        )
    }

    fn windows_reply() -> Vec<u8> {
        br#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
 xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
 xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
 <s:Header><a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</a:Action></s:Header>
 <s:Body><d:ProbeMatches><d:ProbeMatch>
  <a:EndpointReference><a:Address>urn:uuid:abcd</a:Address></a:EndpointReference>
  <d:Types>wsdp:Device pub:Computer</d:Types>
  <d:XAddrs>http://192.168.1.42:5357/abcd/</d:XAddrs>
 </d:ProbeMatch></d:ProbeMatches></s:Body></s:Envelope>"#
            .to_vec()
    }

    /// The whole point of the module: a Windows machine that answers
    /// WS-Discovery and nothing else is a device.
    #[test]
    fn a_windows_machine_that_answers_only_wsd_is_found() {
        let mut link = Link::default();
        link.group
            .insert(wsd::GROUP, vec![(ip("192.168.1.42"), windows_reply())]);

        let heard = run(
            &link,
            Options {
                wsd: true,
                ..quiet()
            },
            &[],
        );

        let voice = heard.by.get(&ip("192.168.1.42")).expect("a device");
        assert!(voice.protocols.contains(&Protocol::WsDiscovery));
        assert!(voice.identity.wsd.contains(&"pub:computer".to_string()));
        assert!(voice.spoke());
        assert_eq!(
            heard.speakers().map(|(a, _)| a).collect::<Vec<_>>(),
            vec![ip("192.168.1.42")]
        );
    }

    /// A question that could not be asked is a line the interface prints, not
    /// an empty answer.
    #[test]
    fn no_broadcast_address_is_said_out_loud() {
        let heard = run(
            &Link::default(),
            Options {
                netbios: true,
                broadcast: None,
                ..quiet()
            },
            &[],
        );
        assert!(heard.by.is_empty());
        assert_eq!(heard.not_done.len(), 1);
        assert!(heard.not_done[0].contains("NetBIOS"));
    }

    /// The NetBIOS question goes to the broadcast address, not to a device.
    #[test]
    fn netbios_is_asked_of_the_whole_link() {
        let link = Link::default();
        let _ = run(
            &link,
            Options {
                netbios: true,
                ..quiet()
            },
            &[],
        );
        assert_eq!(
            *link.asked.lock().unwrap(),
            vec![SocketAddr::new(ip("192.168.1.255"), NBNS_PORT)]
        );
    }

    /// Two questions answered by one address are one device with two protocols
    /// against its name, not two rows.
    #[test]
    fn one_address_answering_twice_is_one_device() {
        let mut link = Link::default();
        link.group
            .insert(wsd::GROUP, vec![(ip("192.168.1.42"), windows_reply())]);
        link.group.insert(
            ssdp::GROUP,
            vec![(
                ip("192.168.1.42"),
                b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nSERVER: Linux/5.0 UPnP/1.0 Thing/1.0\r\n\r\n"
                    .to_vec(),
            )],
        );

        let heard = run(
            &link,
            Options {
                wsd: true,
                ssdp: true,
                ..quiet()
            },
            &[],
        );

        assert_eq!(heard.by.len(), 1);
        let voice = &heard.by[&ip("192.168.1.42")];
        assert_eq!(
            voice.protocols.iter().copied().collect::<Vec<_>>(),
            vec![Protocol::Ssdp, Protocol::WsDiscovery]
        );
        assert_eq!(
            voice.identity.product.as_deref(),
            Some("Linux/5.0 UPnP/1.0 Thing/1.0")
        );
        // The strongest protocol is the one the row is credited to.
        assert_eq!(heard.credit(ip("192.168.1.42")), Some(Protocol::Ssdp));
    }

    /// An off-link resolver is never asked, which the caller enforces by
    /// passing [`None`]. Nothing is sent and nothing is claimed.
    #[test]
    fn no_resolver_means_no_reverse_question() {
        let link = Link::default();
        let heard = run(
            &link,
            Options {
                reverse: true,
                resolver: None,
                ..quiet()
            },
            &[ip("192.168.1.5")],
        );
        assert!(heard.by.is_empty());
        assert!(heard.not_done.is_empty());
        assert!(link.asked.lock().unwrap().is_empty());
    }

    /// A resolver that keeps reverse records names the addresses that have
    /// them, and that name is marked as second-hand.
    #[test]
    fn the_resolver_names_what_it_knows() {
        let mut link = Link::default();
        link.private.insert(
            SocketAddr::new(ip("192.168.1.1"), DNS_PORT),
            ptr_reply("5.1.168.192.in-addr.arpa", "kitchen-pi.lan"),
        );

        let heard = run(
            &link,
            Options {
                reverse: true,
                resolver: Some(ip("192.168.1.1")),
                ..quiet()
            },
            &[ip("192.168.1.5")],
        );

        let voice = &heard.by[&ip("192.168.1.5")];
        assert_eq!(
            voice.identity.best().map(|n| n.value.as_str()),
            Some("kitchen-pi.lan")
        );
        assert_eq!(
            voice.identity.best().map(|n| n.source),
            Some(Source::ReverseDns)
        );
        // A record is not a device. It names one the sweep may have found; it
        // does not put a row on the list by itself.
        assert!(!voice.spoke());
        assert_eq!(heard.speakers().count(), 0);
    }

    /// A resolver with nothing to say is given up on rather than asked two
    /// hundred and fifty times.
    #[test]
    fn a_resolver_that_keeps_no_records_is_not_flogged() {
        let link = Link::default();
        let addresses: Vec<IpAddr> = (1..200)
            .map(|i| IpAddr::V4(Ipv4Addr::new(192, 168, 1, i)))
            .collect();

        let heard = run(
            &link,
            Options {
                reverse: true,
                resolver: Some(ip("192.168.1.1")),
                ..quiet()
            },
            &addresses,
        );

        assert!(heard.by.is_empty());
        assert_eq!(link.asked.lock().unwrap().len(), PATIENCE);
    }

    /// A prefix too large to ask about address by address is said out loud
    /// rather than quietly skipped.
    #[test]
    fn too_many_addresses_to_ask_about_is_said_out_loud() {
        let addresses: Vec<IpAddr> = (0..=REVERSE_MOST)
            .map(|i| IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8)))
            .collect();

        let heard = run(
            &Link::default(),
            Options {
                reverse: true,
                resolver: Some(ip("10.0.0.1")),
                ..quiet()
            },
            &addresses,
        );
        assert_eq!(heard.not_done.len(), 1);
        assert!(heard.not_done[0].contains("name for each"));
    }

    /// Cancelling before the phase starts asks nothing at all.
    #[test]
    fn a_cancelled_scan_asks_nothing() {
        let link = Link::default();
        let heard = ask(
            &link,
            Options::default(),
            &[],
            &Bucket::new(1_000_000),
            &AtomicBool::new(true),
        );
        assert!(heard.by.is_empty());
        assert!(link.asked.lock().unwrap().is_empty());
    }

    /// The television that started all of this.
    ///
    /// It answers the group and ignores every question addressed to it, and
    /// under the old shape it could only ever annotate a row the sweep had
    /// already found. Here it *is* the row. Both halves of the attribution
    /// matter: the reply's own source address is the only thing tying it to a
    /// device, and getting that wrong would put a television's name on its
    /// neighbour.
    #[test]
    fn a_device_that_only_ever_answers_the_group_is_still_a_device() {
        let television = ip("192.168.0.107");
        let router = ip("192.168.0.1");
        let mut link = Link::default();
        link.group.insert(
            ssdp::GROUP,
            vec![
                // The first reply from the television names nothing, which is
                // the usual case and the reason the whole window is read.
                (
                    television,
                    b"HTTP/1.1 200 OK
ST: upnp:rootdevice
SERVER: WebOS/4.0.0 UPnP/1.0

"
                    .to_vec(),
                ),
                (
                    television,
                    b"HTTP/1.1 200 OK
ST: urn:lge:device:tv:1
SERVER: WebOS/4.0.0 UPnP/1.0

"
                    .to_vec(),
                ),
                (
                    router,
                    b"HTTP/1.1 200 OK
ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1
SERVER: TP-LINK/TP-LINK UPnP/1.1 MiniUPnPd/2.2.2

"
                    .to_vec(),
                ),
            ],
        );

        let heard = run(
            &link,
            Options {
                ssdp: true,
                ..quiet()
            },
            &[],
        );

        assert_eq!(heard.speakers().count(), 2);
        let tv = &heard.by[&television];
        assert!(
            tv.identity
                .upnp
                .contains(&"urn:lge:device:tv:1".to_string())
        );
        assert_eq!(tv.identity.product.as_deref(), Some("WebOS/4.0.0 UPnP/1.0"));
        // And the router keeps its own answer rather than the television's.
        let gateway = &heard.by[&router];
        assert!(
            gateway
                .identity
                .upnp
                .iter()
                .any(|u| u.contains("internetgatewaydevice"))
        );
        assert!(
            !gateway
                .identity
                .upnp
                .contains(&"urn:lge:device:tv:1".to_string())
        );
    }

    /// The same for mDNS: a responder that only reads its group socket.
    #[test]
    fn the_link_wide_mdns_question_finds_what_answers_nothing_privately() {
        let television = ip("192.168.0.107");
        let mut link = Link::default();
        link.group.insert(
            MDNS,
            vec![(
                television,
                ptr_reply(
                    "_services._dns-sd._udp.local",
                    "_androidtvremote2._tcp.local",
                ),
            )],
        );

        let heard = run(
            &link,
            Options {
                mdns: true,
                ..quiet()
            },
            &[],
        );

        let voice = &heard.by[&television];
        assert_eq!(voice.identity.services, vec!["_androidtvremote2._tcp"]);
        assert!(voice.spoke());
        assert_eq!(heard.speakers().count(), 1);
    }

    /// A Bonjour sleep proxy answers on behalf of a machine that is asleep, so
    /// the reply's own address record is what says which device it is about.
    ///
    /// Attributing it to the sender would put the sleeping laptop's services on
    /// the Apple TV's row and leave the laptop off the list — one device
    /// becoming two wrong ones. Getting it right also *finds* the laptop, which
    /// answered nothing and was never swept.
    #[test]
    fn a_proxied_answer_belongs_to_the_device_it_is_about() {
        let proxy = ip("192.168.0.50");
        let asleep = ip("192.168.0.77");
        let mut link = Link::default();
        link.group.insert(
            MDNS,
            vec![(proxy, proxied_reply("_smb._tcp.local", "quiet-mac", asleep))],
        );

        let heard = run(
            &link,
            Options {
                mdns: true,
                ..quiet()
            },
            &[],
        );

        assert!(
            heard.by.contains_key(&asleep),
            "the sleeping machine is the device the reply is about"
        );
        assert!(
            !heard.by.contains_key(&proxy),
            "and the proxy is not credited with its services"
        );
        assert_eq!(heard.by[&asleep].identity.services, vec!["_smb._tcp"]);
    }

    /// A `PTR` naming a service, with the `A` record a proxy attaches saying
    /// which machine it is really about.
    fn proxied_reply(service: &str, host: &str, address: IpAddr) -> Vec<u8> {
        let IpAddr::V4(v4) = address else {
            unreachable!("the fixture is v4")
        };
        let mut m = Vec::new();
        m.extend_from_slice(&0u16.to_be_bytes());
        m.extend_from_slice(&0x8400u16.to_be_bytes());
        m.extend_from_slice(&0u16.to_be_bytes()); // no questions
        m.extend_from_slice(&1u16.to_be_bytes()); // one answer
        m.extend_from_slice(&0u16.to_be_bytes()); // no authority
        m.extend_from_slice(&1u16.to_be_bytes()); // one additional

        write_name(&mut m, service);
        m.extend_from_slice(&dns::TYPE_PTR.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&120u32.to_be_bytes());
        let mut data = Vec::new();
        write_name(&mut data, &format!("{host}.{service}"));
        m.extend_from_slice(&(data.len() as u16).to_be_bytes());
        m.extend_from_slice(&data);

        write_name(&mut m, &format!("{host}.local"));
        m.extend_from_slice(&dns::TYPE_A.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&120u32.to_be_bytes());
        m.extend_from_slice(&4u16.to_be_bytes());
        m.extend_from_slice(&v4.octets());
        m
    }

    /// The two lists are parallel by index, and a device inserted into one
    /// without the other puts every later row's name on its neighbour.
    #[test]
    fn folding_keeps_the_names_beside_the_devices() {
        let mut sweep = Sweep::default();
        for address in ["192.168.1.2", "192.168.1.9"] {
            sweep.found.push(Found {
                address: ip(address),
                mac: None,
                mac_said: None,
                evidence: vec![Evidence::Ping],
                rtt: None,
                ttl: None,
            });
        }
        let mut names = vec![Identity::default(), Identity::default()];
        names[1].add("nine".into(), Source::Mdns);

        // One that lands between them, and one that lands at the end.
        let mut heard = Heard::default();
        for (address, name) in [("192.168.1.5", "five"), ("192.168.1.40", "forty")] {
            let voice = heard.by.entry(ip(address)).or_default();
            voice.protocols.insert(Protocol::Ssdp);
            voice.identity.add(name.into(), Source::Mdns);
        }

        let added = fold(&heard, &mut sweep, &mut names);

        assert_eq!(added, vec![ip("192.168.1.5"), ip("192.168.1.40")]);
        assert_eq!(
            sweep.found.iter().map(|f| f.address).collect::<Vec<_>>(),
            vec![
                ip("192.168.1.2"),
                ip("192.168.1.5"),
                ip("192.168.1.9"),
                ip("192.168.1.40")
            ]
        );
        assert_eq!(names.len(), sweep.found.len());
        assert_eq!(names[1].best().map(|n| n.value.as_str()), Some("five"));
        assert_eq!(
            names[2].best().map(|n| n.value.as_str()),
            Some("nine"),
            "the row that was already there keeps its own name"
        );
        assert_eq!(names[3].best().map(|n| n.value.as_str()), Some("forty"));
    }

    /// **The gap this whole route exists to close.** A device that only ever
    /// answered a multicast question has no ARP reply and no neighbour entry
    /// behind it, so its row used to carry a blank hardware column and a blank
    /// vendor beside a perfectly good name — and the reply that put it on the
    /// list had its address in it all along. The row now takes what the device
    /// stated, and carries the route beside it, because a stated address is a
    /// weaker claim than an answered one and the interface has to be able to
    /// say which it is showing.
    #[test]
    fn an_announced_row_takes_the_address_the_device_stated() {
        let mut sweep = Sweep::default();
        let mut names: Vec<Identity> = Vec::new();

        let mut heard = Heard::default();
        let voice = heard.by.entry(ip("192.168.1.62")).or_default();
        voice.protocols.insert(Protocol::Mdns);
        voice.identity.says(crate::claim::Claim::new(
            mac("f4:cf:a2:f7:5c:84"),
            Route::EspHome,
        ));

        assert_eq!(
            fold(&heard, &mut sweep, &mut names),
            vec![ip("192.168.1.62")]
        );
        assert_eq!(sweep.found[0].mac, Some(mac("f4:cf:a2:f7:5c:84")));
        assert_eq!(sweep.found[0].mac_said, Some(Route::EspHome));
        assert!(!sweep.found[0].was_probed(), "nothing was ever sent to it");
        assert_eq!(
            crate::vendor::lookup(sweep.found[0].mac.unwrap()).name(),
            Some("Espressif Inc."),
            "which is the whole point: the vendor column is no longer blank"
        );
    }

    /// A device the sweep *did* reach keeps the address its stack answered
    /// with, and the row says nothing about a stated one. The two claims are
    /// not the same rank, and the stated one is still kept whole beside the
    /// name.
    #[test]
    fn an_answered_address_is_not_overwritten_by_a_stated_one() {
        let answered = mac("3c:22:fb:11:22:33");
        let mut sweep = Sweep::default();
        sweep.found.push(Found {
            address: ip("192.168.1.62"),
            mac: Some(answered),
            mac_said: None,
            evidence: vec![Evidence::Arp(answered)],
            rtt: None,
            ttl: None,
        });
        let mut names = vec![Identity::default()];

        let mut heard = Heard::default();
        let voice = heard.by.entry(ip("192.168.1.62")).or_default();
        voice.protocols.insert(Protocol::Mdns);
        voice.identity.says(crate::claim::Claim::new(
            mac("f4:cf:a2:f7:5c:84"),
            Route::EspHome,
        ));

        fold(&heard, &mut sweep, &mut names);
        assert_eq!(sweep.found[0].mac, Some(answered));
        assert_eq!(sweep.found[0].mac_said, None, "a stack answered this one");
        assert_eq!(names[0].said.len(), 1, "and the device's account is kept");
    }

    /// A resolver's record names a device the sweep found and never invents
    /// one the sweep did not.
    #[test]
    fn a_name_alone_never_becomes_a_row() {
        let mut sweep = Sweep::default();
        let mut names = Vec::new();

        let mut heard = Heard::default();
        let voice = heard.by.entry(ip("192.168.1.5")).or_default();
        voice.protocols.insert(Protocol::Dns);
        voice.identity.add("ghost.lan".into(), Source::ReverseDns);

        assert!(fold(&heard, &mut sweep, &mut names).is_empty());
        assert!(sweep.found.is_empty());
        assert!(names.is_empty());
    }

    /// One `PTR` answer, as a resolver sends it.
    fn ptr_reply(question: &str, answer: &str) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&0u16.to_be_bytes());
        m.extend_from_slice(&0x8180u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&[0, 0, 0, 0]);
        write_name(&mut m, question);
        m.extend_from_slice(&dns::TYPE_PTR.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        write_name(&mut m, question);
        m.extend_from_slice(&dns::TYPE_PTR.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&60u32.to_be_bytes());
        let mut data = Vec::new();
        write_name(&mut data, answer);
        m.extend_from_slice(&(data.len() as u16).to_be_bytes());
        m.extend_from_slice(&data);
        m
    }

    fn write_name(out: &mut Vec<u8>, name: &str) {
        for label in name.split('.').filter(|l| !l.is_empty()) {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
    }
}
