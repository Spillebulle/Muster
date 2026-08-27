//! Phase four: asking a device what it is.
//!
//! Only for hosts that answered the sweep, and it is a different shape from the
//! sweep: a handful of short exchanges per device rather than one probe per
//! address. All of it is ordinary UDP, so all of it works with no privileges on
//! both platforms.
//!
//! ## Asked privately, and asked of the link
//!
//! Per device, in [`one`]:
//!
//! * **Reverse DNS** to the machine's own resolver. On a home network that
//!   resolver is usually the router, and the router knows the hostname every
//!   device gave it with its DHCP request. It is the cheapest name there is.
//! * **mDNS**, twice: the reverse question, which a responder answers with its
//!   own `.local` name, and `_services._dns-sd._udp.local`, which it answers
//!   with the list of what it offers. The second is what turns a name into a
//!   kind, and for a long time it was not asked: devices came back named and
//!   silent about themselves, and the service half of [`crate::kind`] could
//!   not fire.
//! * **`_device-info._tcp`**, by the name the device just gave, which is where
//!   an Apple device writes its exact model.
//! * **NetBIOS** to port 137, which is how a Windows machine says its name —
//!   including the ones that ignore ping.
//! * **LLMNR** to port 5355, which is how the Windows machines that have
//!   switched NetBIOS off still say it.
//!
//! Once per scan, in [`many`]:
//!
//! * **An SSDP search** of the whole link. See [`crate::ssdp`].
//! * **The same `_services._dns-sd._udp.local` question**, sent to the mDNS
//!   group rather than to a device.
//!
//! **The link-wide pair is not redundant with the private pair, and finding
//! that out is what these two are here for.** A great many responders — two
//! televisions on the network this was written against, and a camera — process
//! only what arrives on their multicast socket and ignore the identical
//! question addressed to them alone. Asking each device privately found four
//! devices out of twenty-one; asking the link as well found fourteen.
//!
//! Every question is a datagram out and one or more back, so the whole platform
//! surface is [`Ask`], with two methods. The tests drive it with recorded
//! replies and no test opens a socket.
//!
//! ## Sources are merged with a priority, never raced
//!
//! `CLAUDE.md`: identity is a merge of independent sources with a priority, and
//! where sources disagree both are kept. A device answering as two things is
//! information — often that it is a router, or a host running virtual machines.
//! So [`Identity`] holds every name learned with the source that gave it, and
//! [`Identity::best`] applies the order rather than the arrival time. A race
//! would make the answer depend on which reply happened to come back first,
//! which is not a property of the device at all.
//!
//! The order is **self-reported first**: mDNS, NetBIOS and LLMNR are the device
//! speaking about itself, while reverse DNS is what the router was told once,
//! possibly by a previous occupant of the address.

use crate::claim::{Claim, Route};
use crate::dns;
use crate::mac::MacAddr;
use crate::netbios;
use crate::rate::Bucket;
use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

/// Where a name came from. The order of the variants is the priority order, so
/// `derive(PartialOrd)` is the comparison and there is no second list to keep
/// in step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    /// The device answered mDNS about itself.
    Mdns,
    /// The device answered NetBIOS about itself.
    NetBios,
    /// The device answered LLMNR about itself.
    Llmnr,
    /// The resolver had a `PTR` record. Second-hand, and sometimes stale.
    ReverseDns,
}

impl Source {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Mdns => "mDNS",
            Self::NetBios => "NetBIOS",
            Self::Llmnr => "LLMNR",
            Self::ReverseDns => "reverse DNS",
        }
    }
}

/// Something a device does *for* the rest of the network.
///
/// Distinct from [`crate::Kind`], and the distinction is the point: a kind is
/// what a device **is** and a role is what it **serves**. The two are
/// independent — a router serves both of these, a NAS often serves neither, and
/// a Raspberry Pi running Pi-hole serves both while being a computer. So the
/// interface shows the kind as an icon and the roles as badges beside it,
/// rather than trying to fold "it is a DNS server" into a single label.
///
/// **Every role here is a service that answered.** Not a port that was open,
/// not a vendor that usually runs one: the device was asked a question in the
/// protocol and replied in it.
///
/// The order is the badge order, and it is the network's own infrastructure
/// first: what hands out addresses, what resolves names, then what serves
/// files, then what accepts a shell. Two devices with the same roles therefore
/// show the same badges in the same sequence, and a row does not reshuffle
/// itself between scans.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    /// It offered an address in reply to a DHCP DISCOVER.
    Dhcp,
    /// It answered a DNS query.
    Dns,
    /// It answered an SMB negotiate: a Windows share, a NAS, or Samba.
    Smb,
    /// It answered an NFS null call.
    Nfs,
    /// It greeted an SSH connection.
    Ssh,
}

impl Role {
    /// The badge's text.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Dhcp => "DHCP",
            Self::Dns => "DNS",
            Self::Smb => "SMB",
            Self::Nfs => "NFS",
            Self::Ssh => "SSH",
        }
    }

    /// What the badge means, for the tooltip. §11 wants one on anything that
    /// is not a sentence.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Dhcp => "it offered this network an address",
            Self::Dns => "it answered a DNS query",
            Self::Smb => "it answered an SMB negotiate, so it serves files",
            Self::Nfs => "it answered an NFS null call, so it exports a file system",
            Self::Ssh => "it greeted an SSH connection",
        }
    }
}

/// What a device that answers on port 53 said about itself.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Resolver {
    /// Its answer to `version.bind`, where it gave one.
    ///
    /// `dnsmasq-2.90`, `9.18.28-1~deb12u2-Debian`, `Pi-hole-FTL 6.0`. Servers
    /// are free to withhold it and hardened ones do, so this is [`None`] as
    /// often as not and the role does not depend on it.
    pub version: Option<String>,
    /// It set `RA`, so it will resolve on a client's behalf.
    ///
    /// The difference between the resolver a network's devices point at and a
    /// server that is only authoritative for its own zone — and, on a home
    /// network, the difference between the router and a NAS running a private
    /// zone for its containers.
    pub recursive: bool,
}

/// A name, and who said so.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Name {
    pub value: String,
    pub source: Source,
}

/// What was learned about one device.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Identity {
    /// Every name learned, best source first. Disagreement is preserved rather
    /// than resolved away.
    pub names: Vec<Name>,
    /// The Windows workgroup or domain, where one answered.
    pub workgroup: Option<String>,
    /// A hardware address reported by NetBIOS, which is worth keeping beside
    /// the one ARP found: when they disagree, something is answering for
    /// another machine.
    ///
    /// The best of [`Self::said`] by that list's own priority, and never an
    /// address an ARP reply or the neighbour table produced: everything here
    /// is a device's statement about itself.
    pub mac: Option<MacAddr>,
    /// Every hardware address the device *stated*, with the route that carried
    /// it, best route first.
    ///
    /// **A different kind of claim from one a stack answered**, which is why
    /// it is a list of [`Claim`] rather than one more `Option<MacAddr>`: an
    /// ARP reply is written below the level anything on the device has an
    /// opinion about, and every one of these is the device writing its own
    /// address into a payload. See [`crate::claim`].
    ///
    /// Kept whole rather than resolved down to one, because two routes
    /// disagreeing is information — usually a device answering for a second
    /// interface, or a proxy answering for somebody else. [`Self::disputed_mac`]
    /// is the question the interface asks.
    pub said: Vec<Claim>,
    /// The device's own persistent identifier, where it published one: a UPnP
    /// `UDN`, or a WS-Discovery endpoint reference where no UPnP one was
    /// heard.
    ///
    /// UPnP Device Architecture requires a `UDN` to be fixed over time and to
    /// survive a reboot, which makes it the most stable thing the televisions
    /// and set-top boxes ARP is worst at ever say about themselves. It used to
    /// be split off the `USN` and thrown away. Opaque: nothing reads meaning
    /// into it, and nothing here builds label persistence or scan comparison
    /// on top of it — those are their own piece of work.
    pub udn: Option<String>,
    /// mDNS service types seen, such as `_ipp._tcp` for a printer.
    pub services: Vec<String>,
    /// UPnP device and service types announced over SSDP, lower cased, such as
    /// `urn:dial-multiscreen-org:device:dial:1` for a television.
    ///
    /// A separate list from [`Self::services`] rather than the same one,
    /// because the two are different vocabularies and showing a URN under
    /// "advertises" beside `_ipp._tcp` reads as one list of nonsense.
    pub upnp: Vec<String>,
    /// The `Types` a device claimed over WS-Discovery, lower cased and with
    /// their namespace prefixes left on: `pub:computer`,
    /// `wprt:printdevicetype`, `dn:networkvideotransmitter`.
    ///
    /// A third vocabulary beside [`Self::services`] and [`Self::upnp`], and
    /// separate for the same reason those two are separate from each other:
    /// they are different languages and showing them in one list reads as
    /// nonsense. The prefix is kept because it is half the meaning — `pub:` is
    /// Microsoft's publication namespace and is what makes `Computer` a claim
    /// about a Windows machine rather than a word.
    pub wsd: Vec<String>,
    /// The `SERVER` header of an SSDP reply: the product, in the device's own
    /// words. `Linux/4.19 UPnP/1.0 LG WebOS TV/1.0`.
    pub product: Option<String>,
    /// The model the device named for itself in an mDNS `TXT` record:
    /// `model=AudioAccessory5,1`, `md=SHIELD Android TV`, `ty=HP OfficeJet
    /// 6950`.
    ///
    /// The most precise thing a device ever volunteers, and worth a field of
    /// its own rather than a line in [`Self::services`]: a service type says
    /// what a device does and this says what it is.
    pub model: Option<String>,
    /// It answered on port 53, and what it said.
    pub resolver: Option<Resolver>,
    /// It answered a DHCP DISCOVER with an offer.
    ///
    /// Filled in by the caller rather than by [`one`]: a DISCOVER is one
    /// broadcast for the whole link, so the answer arrives as a list of servers
    /// and is attributed here afterwards. See [`Identity::offers_addresses`].
    pub dhcp: bool,
    /// The device answered LLMNR, which on a home network means Windows or a
    /// Linux machine running `systemd-resolved`.
    ///
    /// Kept as a flag rather than inferred from a name's source, because the
    /// fact worth having is that it *responded*: a responder that answered
    /// with a name Muster already had is still a machine saying it speaks a
    /// protocol only general-purpose computers speak.
    pub llmnr: bool,
    /// What it answered over a connection: SMB, NFS, the SSH greeting.
    ///
    /// Filled in by the caller from [`crate::service`] rather than by [`one`],
    /// for the same reason [`Self::dhcp`] is: those questions are asked over
    /// TCP and this phase is a UDP phase. See [`Self::serves`].
    pub serves: crate::service::Serves,
}

impl Identity {
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
            && self.workgroup.is_none()
            && self.services.is_empty()
            && self.upnp.is_empty()
            && self.wsd.is_empty()
            && self.said.is_empty()
            && self.udn.is_none()
            && self.product.is_none()
            && self.model.is_none()
            && self.resolver.is_none()
            && !self.dhcp
            && !self.llmnr
            && self.serves.is_empty()
    }

    /// The name to show. The highest-priority source wins; ties keep the first.
    pub fn best(&self) -> Option<&Name> {
        self.names.iter().min_by_key(|n| n.source)
    }

    /// Do the sources disagree about what this device is called?
    ///
    /// Worth surfacing rather than hiding: it is usually a router with two
    /// identities, or an address that changed hands since the resolver last
    /// heard about it.
    pub fn disputed(&self) -> bool {
        let mut seen: Vec<String> = self.names.iter().map(|n| canonical(&n.value)).collect();
        seen.sort_unstable();
        seen.dedup();
        seen.len() > 1
    }

    /// The names other than the best one, for saying what else it is called.
    /// Empty unless the sources genuinely disagree.
    pub fn other_names(&self) -> Vec<&str> {
        let Some(best) = self.best() else {
            return Vec::new();
        };
        let best_key = canonical(&best.value);
        let mut out = Vec::new();
        for name in &self.names {
            if canonical(&name.value) != best_key && !out.contains(&name.value.as_str()) {
                out.push(name.value.as_str());
            }
        }
        out
    }

    /// What this device serves the network, for the badges.
    ///
    /// Ordered by [`Role`]'s own order rather than by when each was learned, so
    /// two devices with the same roles show the same badges in the same
    /// sequence and a row does not reshuffle itself between scans.
    pub fn roles(&self) -> Vec<Role> {
        let mut out = Vec::new();
        if self.dhcp {
            out.push(Role::Dhcp);
        }
        if self.resolver.is_some() {
            out.push(Role::Dns);
        }
        if self.serves.smb {
            out.push(Role::Smb);
        }
        if self.serves.nfs {
            out.push(Role::Nfs);
        }
        if self.serves.ssh.is_some() {
            out.push(Role::Ssh);
        }
        out
    }

    /// Records that this device answered a DHCP DISCOVER.
    pub fn offers_addresses(&mut self) {
        self.dhcp = true;
    }

    /// Records what this device answered over a connection.
    ///
    /// A merge rather than an assignment: a scan that asked only about SMB must
    /// not wipe what an earlier answer said about the rest.
    pub fn serves(&mut self, serves: &crate::service::Serves) {
        self.serves.smb |= serves.smb;
        self.serves.nfs |= serves.nfs;
        if self.serves.ssh.is_none() {
            self.serves.ssh.clone_from(&serves.ssh);
        }
    }

    /// Folds in what another question learned about this same device.
    ///
    /// The device asked privately and the device that answered the group are
    /// one device, so this is a union rather than a choice: a name is added
    /// with its source and the deduplication in [`Self::add`] settles the rest,
    /// and anything already known is kept because the answer that arrived first
    /// is the more specific of the two — [`crate::link`] merges the link's four
    /// protocols into one identity in the order they are asked, and
    /// [`many`] then merges that into what the private questions found.
    ///
    /// **Every field is unioned, and it was not always.** This merged names,
    /// services and the model, and dropped the other nine — which was invisible
    /// while the only thing it merged was an mDNS answer that could not carry
    /// them. The moment a link-wide phase started producing SSDP product
    /// strings, WS-Discovery types and NetBIOS workgroups, a partial merge
    /// would have thrown away the identification for every device that answered
    /// the link and not the private question, which is precisely the set of
    /// devices the link phase exists to find.
    pub fn merge(&mut self, other: &Self) {
        for name in &other.names {
            self.add(name.value.clone(), name.source);
        }
        for service in &other.services {
            if !self.services.contains(service) {
                self.services.push(service.clone());
            }
        }
        for kind in &other.upnp {
            if !self.upnp.contains(kind) {
                self.upnp.push(kind.clone());
            }
        }
        for kind in &other.wsd {
            if !self.wsd.contains(kind) {
                self.wsd.push(kind.clone());
            }
        }
        if self.workgroup.is_none() {
            self.workgroup.clone_from(&other.workgroup);
        }
        if self.mac.is_none() {
            self.mac = other.mac;
        }
        for claim in &other.said {
            self.says(*claim);
        }
        if self.udn.is_none() {
            self.udn.clone_from(&other.udn);
        }
        if self.product.is_none() {
            self.product.clone_from(&other.product);
        }
        if self.model.is_none() {
            self.model.clone_from(&other.model);
        }
        if self.resolver.is_none() {
            self.resolver.clone_from(&other.resolver);
        }
        self.dhcp |= other.dhcp;
        self.llmnr |= other.llmnr;
        self.serves(&other.serves);
    }

    /// Folds one SSDP reply in.
    ///
    /// The first `SERVER` wins. They are the same in every reply from one
    /// device, and a device that contradicts itself between datagrams is not
    /// saying anything worth preferring the later half of.
    pub fn announced(&mut self, announcement: &crate::ssdp::Announcement) {
        for kind in announcement.types() {
            if !self.upnp.contains(&kind) {
                self.upnp.push(kind);
            }
        }
        if self.product.is_none() {
            self.product.clone_from(&announcement.server);
        }
        // The half of `USN` that used to be dropped on the floor: the device's
        // own identifier, and — where it was built the way UPnP recommends —
        // the hardware address inside it. See [`crate::claim`].
        if self.udn.is_none() {
            self.udn = announcement.udn();
        }
        if let Some(claim) = announcement.hardware() {
            self.says(claim);
        }
    }

    /// Records a hardware address the device stated about itself.
    ///
    /// Ordered by [`Route`]'s own priority rather than by arrival, for the
    /// reason every other merge here is: the answer must not depend on which
    /// datagram came back first. [`Self::mac`] follows the best of them, and
    /// only where nothing has set it — a NetBIOS statistics block that was
    /// read before the claims existed keeps its place.
    pub fn says(&mut self, claim: Claim) {
        if !self.said.contains(&claim) {
            self.said.push(claim);
            self.said.sort_unstable();
        }
        if self.mac.is_none() {
            self.mac = self.said.first().map(|c| c.mac);
        }
    }

    /// The best-supported route for the address on [`Self::mac`], where the
    /// device stated it.
    ///
    /// [`None`] where nothing stated one, which is the ordinary case for a
    /// device whose address came out of an ARP reply or the neighbour table.
    pub fn mac_route(&self) -> Option<Route> {
        let mac = self.mac?;
        self.said.iter().find(|c| c.mac == mac).map(|c| c.route)
    }

    /// Do the routes disagree about this device's hardware address?
    ///
    /// Worth surfacing rather than resolving away, the same as
    /// [`Self::disputed`] is for names: a device stating two addresses is
    /// usually stating both of its interfaces, and occasionally it is
    /// something answering on another machine's behalf.
    pub fn disputed_mac(&self) -> bool {
        let mut seen: Vec<MacAddr> = self.said.iter().map(|c| c.mac).collect();
        seen.sort_unstable();
        seen.dedup();
        seen.len() > 1
    }

    pub fn add(&mut self, value: String, source: Source) {
        let value = value.trim_end_matches('.').to_string();
        if value.is_empty() {
            return;
        }
        // The same name from the same source twice is one name.
        if self
            .names
            .iter()
            .any(|n| n.value == value && n.source == source)
        {
            return;
        }
        self.names.push(Name { value, source });
        self.names.sort_by_key(|n| n.source);
    }
}

/// The form two names are compared in, so that one device is not reported as
/// disagreeing with itself.
///
/// Two things have to be normalised away, and both were found by running this
/// against a real network:
///
/// * **The local suffix.** `printer.local`, `printer.lan` and `printer` are one
///   name wearing different clothes, because the resolver, the mDNS responder
///   and NetBIOS each append their own.
/// * **Case.** NetBIOS names are conventionally upper case and mDNS names are
///   not, so a NAS answering both is `TRUENAS` and `truenas.local` — which
///   compared literally is a dispute on nearly every machine that runs Samba.
fn canonical(name: &str) -> String {
    name.trim_end_matches('.')
        .trim_end_matches(".local")
        .trim_end_matches(".lan")
        .trim_end_matches(".home")
        .to_ascii_lowercase()
}

/// One datagram out, one back. The whole platform surface of this phase.
pub trait Ask: Sync {
    /// Sends `payload` to `to` and waits for a single reply.
    ///
    /// Returns the reply, or an error on timeout. Implementations must bind a
    /// fresh ephemeral port per call: two identifications running at once on
    /// one socket would each receive the other's answers.
    fn ask(&self, to: SocketAddr, payload: &[u8], timeout: Duration) -> io::Result<Vec<u8>>;

    /// Sends `payload` to `to` and collects every reply that arrives inside
    /// `window`, up to `most`, each with the address it came from.
    ///
    /// **SSDP is why this exists**, and both halves of the signature are its
    /// doing. A device answering `ST: ssdp:all` sends one datagram per device
    /// and service it hosts, and the one that names what it is is rarely the
    /// first to arrive — so the whole window is read. And the search goes to a
    /// multicast group rather than to a device, so the sender's address is the
    /// only thing that says which device an answer is about.
    ///
    /// The default answers with the single reply [`Ask::ask`] gives, attributed
    /// to the address it was sent to, so a transport that only knows how to do
    /// one exchange stays usable and every recorded test fake keeps working.
    fn ask_all(
        &self,
        to: SocketAddr,
        payload: &[u8],
        window: Duration,
        most: usize,
    ) -> io::Result<Vec<(IpAddr, Vec<u8>)>> {
        let _ = most;
        self.ask(to, payload, window)
            .map(|reply| vec![(to.ip(), reply)])
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub timeout: Duration,
    pub workers: usize,
    /// The resolver to ask for `PTR` records. [`None`] skips reverse DNS, which
    /// is the honest state on a machine whose resolver could not be read.
    pub resolver: Option<IpAddr>,
    pub mdns: bool,
    pub netbios: bool,
    /// Ask the device for its UPnP announcements. See [`crate::ssdp`].
    pub ssdp: bool,
    /// Ask the device over LLMNR, which is how a Windows machine with NetBIOS
    /// switched off still says its name.
    pub llmnr: bool,
    /// Ask the device whether it is a name server.
    pub dns: bool,
    /// How long to listen after each of the two link-wide questions.
    ///
    /// Much longer than [`Self::timeout`], and paid twice for a whole scan
    /// rather than once per device. An SSDP responder is entitled to spread its
    /// answers across `MX` seconds and a television sends seventeen of them, so
    /// a window shorter than this loses the later ones — and on the television
    /// it was the twelfth that named it.
    pub link_window: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            // These are all local exchanges. A device that has not answered in
            // half a second is not going to.
            timeout: Duration::from_millis(600),
            workers: 32,
            resolver: None,
            mdns: true,
            netbios: true,
            ssdp: true,
            llmnr: true,
            dns: true,
            link_window: Duration::from_millis(2500),
        }
    }
}

/// The mDNS group and port. Fixed by the standard.
pub const MDNS: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)), 5353);
/// NetBIOS name service.
pub const NBNS_PORT: u16 = 137;
/// Link-local multicast name resolution, RFC 4795.
pub const LLMNR_PORT: u16 = 5355;
/// Where a name server listens.
pub const DNS_PORT: u16 = 53;

/// The pseudo-record a name server answers with what it is, in the CHAOS class
/// that exists on a modern network for this and nothing else.
///
/// **Asked first, because it is the question that cannot leave the network.** A
/// name server answers `version.bind` out of itself — with the string, or with
/// a refusal from a server that has been told not to say — and a forwarder has
/// nowhere to forward a CHAOS query to. Either reply proves a name server is
/// listening, and the string is a banner: the server volunteers it or it does
/// not, and reading what is offered is the whole of the interaction
/// `CLAUDE.md`'s conduct rules allow.
const VERSION_BIND: &str = "version.bind";

/// The fallback question, for a server that ignores CHAOS entirely.
///
/// `localhost`, and the choice of name is the point. Asking a stranger's
/// resolver for anything at all may make it go out to the internet — this one
/// does, on a router observed while this was written, despite RFC 6761 §6.3
/// telling it to answer `localhost` itself. So the name asked for has to be one
/// that says nothing about the network being scanned and nothing about who is
/// asking, and `localhost` is the most-resolved name there is. What Muster must
/// never do is put a device's own name or address into a question for somebody
/// else's server, and it does not.
const RESOLVER_PROBE: &str = "localhost";

/// DNS-SD's enumeration query: "list the service types you offer".
const SERVICE_ENUMERATION: &str = "_services._dns-sd._udp.local";

/// How many datagrams a link-wide question will read before it stops listening.
const MOST: usize = 512;

/// Asks the whole link what it offers, and returns the answers by address.
///
/// **The same lesson SSDP taught, and it applies here too.** Two televisions on
/// a real network ignored a unicast mDNS question entirely and answered this
/// one within milliseconds: a responder that only processes what arrives on the
/// group socket is common, and asking each device privately misses every one of
/// them. The per-device questions stay — they are what gets a name out of the
/// devices that do answer them — and this is asked once beside them.
///
/// The query goes out from an ephemeral port, which under RFC 6762 §6.7 makes
/// it a *legacy* query: a responder answers one of those with a unicast
/// datagram to the port that asked, rather than by multicasting to the group.
/// That is what makes one socket able to collect the link's answers and tell
/// them apart, and it is why nothing here has to join a multicast group.
pub fn sweep_services<A: Ask + ?Sized>(ask: &A, window: Duration) -> BTreeMap<IpAddr, Identity> {
    let question = dns::query(0, SERVICE_ENUMERATION, dns::TYPE_PTR, false);
    let Ok(replies) = ask.ask_all(MDNS, &question, window, MOST) else {
        return BTreeMap::new();
    };

    let mut found: BTreeMap<IpAddr, (Identity, Vec<(usize, String)>)> = BTreeMap::new();
    for (from, reply) in replies {
        if let Some(message) = dns::parse(&reply) {
            // The device the reply is *about*, which is the sender unless a
            // sleep proxy answered for somebody else. See [`subject`].
            let (identity, models) = found.entry(subject(&message, from)).or_default();
            harvest(&message, identity, models);
        }
    }
    found
        .into_iter()
        .map(|(address, (mut identity, mut models))| {
            models.sort_by_key(|(rank, _)| *rank);
            identity.model = models.into_iter().next().map(|(_, value)| value);
            (address, identity)
        })
        .collect()
}

/// mDNS `TXT` keys that name a model, best first.
///
/// `model` is Apple's, in `_device-info._tcp`, and it is an exact hardware
/// identifier. `md` is Google Cast's and is the name on the box. `ty` and
/// `usb_MDL` are the printing world's, and both are the model as the printer's
/// own driver knows it. Where a device fills in more than one they agree, and
/// the order is what settles it when they do not.
const MODEL_KEYS: &[&str] = &["model", "md", "ty", "usb_mdl"];

/// The service a device's own model lives in, and Apple's alone fills it in.
const DEVICE_INFO: &str = "_device-info._tcp.local";

/// Identifies one device.
///
/// Never fails: a device that answers nothing has an empty [`Identity`], which
/// is a real answer and different from an error.
pub fn one<A: Ask>(address: IpAddr, ask: &A, rate: &Bucket, opts: Options, id: u16) -> Identity {
    let mut found = Identity::default();
    // Every model string any record offered, with its key's rank. Collected
    // rather than assigned, so that the answer does not depend on which of the
    // three mDNS questions a device happened to answer first.
    let mut models: Vec<(usize, String)> = Vec::new();

    if let (Some(resolver), IpAddr::V4(v4)) = (opts.resolver, address) {
        rate.wait();
        let q = dns::query(id, &dns::reverse_name(v4), dns::TYPE_PTR, false);
        if let Ok(reply) = ask.ask(SocketAddr::new(resolver, 53), &q, opts.timeout)
            && let Some(msg) = dns::parse(&reply)
            && let Some(name) = msg.first_ptr()
        {
            found.add(name.to_string(), Source::ReverseDns);
        }
    }

    if opts.mdns
        && let IpAddr::V4(v4) = address
    {
        rate.wait();
        // The same reverse question, asked of the device itself. A responder
        // owning the address answers with its own `.local` name.
        let q = dns::query(0, &dns::reverse_name(v4), dns::TYPE_PTR, true);
        // Sent to the device rather than to the group: unicast mDNS is answered
        // by every responder worth having, and it keeps one device's answer from
        // arriving while another device is being identified.
        if let Ok(reply) = ask.ask(SocketAddr::new(address, 5353), &q, opts.timeout)
            && let Some(msg) = dns::parse(&reply)
        {
            if let Some(name) = msg.first_ptr() {
                found.add(name.to_string(), Source::Mdns);
            }
            harvest(&msg, &mut found, &mut models);
        }

        // **The question that asks what the device *does*.** The reverse lookup
        // above gets a name and, if the responder is generous with its
        // additional section, a service or two by luck. Most are not generous,
        // which is why a network full of Chromecasts, Android televisions and
        // printers came back as a list of names with nothing behind them: the
        // service half of `kind`'s table could not fire because nothing had
        // ever asked for a service.
        //
        // `_services._dns-sd._udp.local` is DNS-SD's own enumeration query, and
        // its answers are one `PTR` per service type the responder offers. One
        // datagram, and it is the difference between "SHIELDANDROIDTV, a
        // Windows machine, because it answered NetBIOS" and "a television,
        // because it advertises `_androidtvremote2._tcp`".
        rate.wait();
        let q = dns::query(0, SERVICE_ENUMERATION, dns::TYPE_PTR, true);
        if let Ok(reply) = ask.ask(SocketAddr::new(address, 5353), &q, opts.timeout)
            && let Some(msg) = dns::parse(&reply)
        {
            harvest(&msg, &mut found, &mut models);
        }

        // And the question that asks what the device *is*. `_device-info._tcp`
        // is not enumerated by the query above — Apple's responder does not
        // list it as a service, because it is not one — so it has to be asked
        // for by name, and its name is built from the name the device just
        // gave. `Ulriks-iPhone._device-info._tcp.local` answers with
        // `model=iPhone14,2`, which is the difference between "an Apple
        // device" and "a phone".
        if let Some(stem) = found
            .names
            .iter()
            .find(|name| name.source == Source::Mdns)
            .map(|name| name.value.trim_end_matches(".local").to_string())
        {
            rate.wait();
            let q = dns::query(0, &format!("{stem}.{DEVICE_INFO}"), dns::TYPE_TXT, true);
            if let Ok(reply) = ask.ask(SocketAddr::new(address, 5353), &q, opts.timeout)
                && let Some(msg) = dns::parse(&reply)
            {
                harvest(&msg, &mut found, &mut models);
            }
        }
    }

    if opts.netbios {
        rate.wait();
        let q = netbios::node_status_query(id);
        if let Ok(reply) = ask.ask(SocketAddr::new(address, NBNS_PORT), &q, opts.timeout)
            && let Some(status) = netbios::parse_node_status(&reply)
        {
            if let Some(name) = status.hostname() {
                found.add(name.to_string(), Source::NetBios);
            }
            found.workgroup = status.workgroup().map(str::to_string);
            found.mac = status.mac;
            if let Some(mac) = status.mac {
                found.says(Claim::new(mac, Route::NetBios));
            }
        }
    }

    // LLMNR, and it is asked *because* NetBIOS often is not answered any more.
    // A machine with NetBIOS over TCP/IP switched off — which is the default on
    // a network Windows has classified as public, and increasingly the default
    // full stop — answers nothing on 137 and still answers here.
    //
    // The flag is worth as much as the name. LLMNR is implemented by Windows
    // and by `systemd-resolved`, and by nothing else on a home network: no
    // television, printer, camera or light bulb has ever answered on 5355. It
    // is a weak clue and it is ranked as one, but it is the only clue at all
    // for the commonest silent device there is, a Windows desktop behind its
    // own firewall.
    if opts.llmnr
        && let IpAddr::V4(v4) = address
    {
        rate.wait();
        let q = dns::query(id, &dns::reverse_name(v4), dns::TYPE_PTR, false);
        if let Ok(reply) = ask.ask(SocketAddr::new(address, LLMNR_PORT), &q, opts.timeout)
            && let Some(msg) = dns::parse(&reply)
        {
            found.llmnr = true;
            if let Some(name) = msg.first_ptr() {
                found.add(name.to_string(), Source::Llmnr);
            }
        }
    }

    // Is this a name server?
    //
    // **Any well-formed reply is the answer.** A server that refuses the query,
    // or does not have the name, or will not recurse for a stranger, has still
    // spoken DNS on port 53 — and "there is a name server here" is what the
    // badge claims. Requiring a successful resolution would miss every resolver
    // configured to serve its own subnet only, which is most of the ones worth
    // finding on a managed network.
    //
    // The second question is asked only when the first went unanswered, so the
    // ordinary case is one datagram that never left the link.
    if opts.dns {
        rate.wait();
        let question = dns::query_in_class(id, VERSION_BIND, dns::TYPE_TXT, dns::CLASS_CH);
        if let Ok(reply) = ask.ask(SocketAddr::new(address, DNS_PORT), &question, opts.timeout)
            && let Some(message) = dns::parse(&reply)
            && message.is_response()
            && message.id == id
        {
            found.resolver = Some(Resolver {
                version: message.first_txt().filter(|v| !v.trim().is_empty()),
                recursive: message.recursion_available(),
            });
        }

        if found.resolver.is_none() {
            rate.wait();
            let question = dns::query(id, RESOLVER_PROBE, dns::TYPE_A, false);
            if let Ok(reply) = ask.ask(SocketAddr::new(address, DNS_PORT), &question, opts.timeout)
                && let Some(message) = dns::parse(&reply)
                && message.is_response()
                && message.id == id
            {
                found.resolver = Some(Resolver {
                    version: None,
                    recursive: message.recursion_available(),
                });
            }
        }
    }

    models.sort_by_key(|(rank, _)| *rank);
    found.model = models.into_iter().next().map(|(_, value)| value);
    found
}

/// Which device an mDNS reply is *about*, given who sent it.
///
/// **Not always the sender, and getting this wrong merges two devices into
/// one.** A Bonjour sleep proxy — which is what an Apple TV or a HomePod
/// quietly becomes — registers the services of machines that have gone to sleep
/// and answers mDNS on their behalf. So a reply arriving from the Apple TV's
/// address can be describing somebody's sleeping laptop, and attributing it by
/// sender puts the laptop's name, services and model on the television's row
/// while leaving the laptop off the list entirely.
///
/// The address records in the reply are what settle it: a responder attaches
/// the `A` or `AAAA` for the name it is answering about.
///
/// **The sender wins whenever it is named in the reply**, which is the ordinary
/// case of a device answering for itself, and that rule is what stops the other
/// two failures:
///
/// * A dual-stacked device answers with both its `A` and its `AAAA`. Taking the
///   first record would key half its answers under its link-local IPv6 address
///   and split one device into two rows.
/// * A reply describing several hosts at once names them all, and the one it is
///   *from* is the one it is about.
///
/// Only when the sender is nowhere in the reply is it somebody else's record,
/// and then an address of the sender's own family is preferred — a proxy on
/// IPv4 is speaking for a machine's IPv4 address.
///
/// **This also finds devices.** The address in a proxied record is very often
/// one that answered nothing at all: a sleeping machine no sweep would find.
pub fn subject(msg: &dns::Message, from: IpAddr) -> IpAddr {
    let mut named = msg.records().filter_map(|r| match r.data {
        dns::RData::A(v4) => Some(IpAddr::V4(v4)),
        dns::RData::Aaaa(v6) => Some(IpAddr::V6(v6)),
        _ => None,
    });

    let mut first_alike = None;
    let mut first_any = None;
    for address in &mut named {
        if address == from {
            return from;
        }
        if first_any.is_none() {
            first_any = Some(address);
        }
        if first_alike.is_none() && address.is_ipv4() == from.is_ipv4() {
            first_alike = Some(address);
        }
    }
    first_alike.or(first_any).unwrap_or(from)
}

/// Takes everything worth having out of an mDNS reply.
///
/// Both mDNS questions read the same things, and they read them from every
/// section: a responder answering a `PTR` commonly attaches the `SRV`, `TXT`
/// and `A` records for the same service without being asked, and those carry
/// the service type as their own name.
pub fn harvest(msg: &dns::Message, found: &mut Identity, models: &mut Vec<(usize, String)>) {
    // The hardware addresses the reply states about itself, which are a
    // whitelist of fields rather than anything in it that looks like one. See
    // [`crate::claim`], and the HomeKit identifier it refuses.
    for claim in crate::claim::from_mdns(msg) {
        found.says(claim);
    }
    let offered = |service: Option<String>, found: &mut Identity| {
        if let Some(service) = service
            && !found.services.contains(&service)
        {
            found.services.push(service);
        }
    };
    for record in msg.records() {
        match &record.data {
            dns::RData::Srv { target, .. } => found.add(target.clone(), Source::Mdns),
            // A `PTR` answering the enumeration query has the service type as
            // its *data*, not as its name, which is the whole point of asking
            // it. `_services._dns-sd._udp.local PTR _googlecast._tcp.local`.
            dns::RData::Name(target) => offered(service_type(target), found),
            dns::RData::Txt(strings) => {
                for entry in strings {
                    if let Some((rank, value)) = model_of(entry)
                        && !models.iter().any(|(_, seen)| seen == &value)
                    {
                        models.push((rank, value));
                    }
                }
            }
            _ => {}
        }
        offered(service_type(&record.name), found);
    }
}

/// The model out of one `TXT` entry, and how good a source its key is.
///
/// `TXT` entries are `key=value` with the key case-insensitive, and everything
/// that is not one of [`MODEL_KEYS`] is somebody's protocol detail: a printer's
/// `_ipp` record carries a dozen entries and only two of them name the printer.
fn model_of(entry: &str) -> Option<(usize, String)> {
    let (key, value) = entry.split_once('=')?;
    // Avahi's `model` carries an appearance hint after an `@`, which a real
    // network hands over as `MacPro7,1@ECOLOR=226,226,224`. It is the colour
    // Finder should tint the icon, it is not part of the model, and it would
    // be shown to somebody as though it were.
    let value = value.split('@').next().unwrap_or(value).trim();
    if value.is_empty() {
        return None;
    }
    let key = key.trim().to_ascii_lowercase();
    let rank = MODEL_KEYS.iter().position(|known| *known == key)?;
    Some((rank, value.to_string()))
}

/// The `_ipp._tcp` out of an mDNS name, where there is one.
///
/// Three shapes have to come out the same, because all three arrive:
///
/// * `printer._ipp._tcp.local` — an instance, from a record's name.
/// * `_ipp._tcp.local` — a bare type, which is what the enumeration query is
///   answered with. This one used to return [`None`]: the old reader took
///   everything after the first `._` and got `_tcp` alone, so **every answer to
///   the question that lists a device's services was thrown away**. It was
///   invisible because nothing asked that question yet.
/// * `_universal._sub._ipp._tcp.local` — a subtype, which AirPrint uses. The
///   type is what matters and the subtype is dropped.
///
/// So the scan is for a label beginning with `_` that is followed by `_tcp` or
/// `_udp`, taking the last such pair rather than the first.
fn service_type(name: &str) -> Option<String> {
    let trimmed = name.trim_end_matches('.').trim_end_matches(".local");
    // `_services._dns-sd._udp` is the meta-query used to *enumerate* service
    // types. It is not a service anything offers, and reporting it would put
    // "_dns-sd._udp" in the list of what a device does.
    if trimmed.starts_with("_services.") {
        return None;
    }
    let labels: Vec<&str> = trimmed.split('.').collect();
    labels.windows(2).find_map(|pair| {
        let (name, protocol) = (pair[0], pair[1]);
        (name.starts_with('_') && (protocol == "_tcp" || protocol == "_udp"))
            .then(|| format!("{name}.{protocol}"))
    })
}

/// Identifies many devices, in parallel, cancellably.
///
/// Returns an identity per input address, in the same order, so the caller can
/// zip it against what the sweep found.
///
/// **The link-wide questions are not asked here, and used to be.** An SSDP
/// search and an mDNS enumeration ran at the top of this function and their
/// answers were folded into the addresses the caller had passed in — which
/// meant an answer from an address the sweep had missed had nowhere to go and
/// was dropped. Those are the devices worth finding, so the link is now asked
/// by [`crate::link`], as a phase of its own that runs beside the sweep and
/// can *add* to the device list rather than only annotate it. What is left here
/// is what it says: questions put to one device, about itself.
pub fn many<A: Ask>(
    addresses: &[IpAddr],
    ask: &A,
    rate: &Bucket,
    opts: Options,
    cancel: &AtomicBool,
    progress: &(dyn Fn(usize, usize) + Sync),
) -> Vec<Identity> {
    let next = AtomicU64::new(0);
    let done = AtomicU64::new(0);
    let mut out: Vec<Identity> = vec![Identity::default(); addresses.len()];
    let workers = opts.workers.clamp(1, 256).min(addresses.len().max(1));

    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            let (next, done) = (&next, &done);
            handles.push(scope.spawn(move || {
                let mut mine: Vec<(usize, Identity)> = Vec::new();
                loop {
                    if cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    let i = next.fetch_add(1, Ordering::Relaxed) as usize;
                    let Some(&address) = addresses.get(i) else {
                        break;
                    };
                    // The transaction id is the index, which makes a reply
                    // meant for another device recognisable rather than merely
                    // unlikely.
                    let found = one(address, ask, rate, opts, i as u16);
                    mine.push((i, found));
                    progress(
                        done.fetch_add(1, Ordering::Relaxed) as usize + 1,
                        addresses.len(),
                    );
                }
                mine
            }));
        }
        for handle in handles {
            for (i, found) in handle.join().unwrap_or_default() {
                out[i] = found;
            }
        }
    });

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// Recorded replies, keyed by where the question went.
    ///
    /// `asked` keys by the question as well, because identification now sends
    /// three different mDNS questions to one port and a fake that could only
    /// tell them apart by address would answer all three with the same
    /// datagram — which is the one thing a recorded transport must not do.
    #[derive(Default)]
    struct Fake {
        replies: BTreeMap<SocketAddr, Vec<u8>>,
        asked_about: BTreeMap<(SocketAddr, String), Vec<u8>>,
        asked: Mutex<Vec<SocketAddr>>,
    }

    impl Fake {
        /// Answers `question` asked of `to`, and nothing else.
        fn about(&mut self, to: SocketAddr, question: &str, reply: Vec<u8>) {
            self.asked_about
                .insert((to, question.to_ascii_lowercase()), reply);
        }
    }

    impl Ask for Fake {
        fn ask(&self, to: SocketAddr, payload: &[u8], _t: Duration) -> io::Result<Vec<u8>> {
            self.asked.lock().unwrap().push(to);
            let question = dns::parse(payload).and_then(|m| {
                m.questions
                    .first()
                    .map(|(name, _)| name.to_ascii_lowercase())
            });
            if let Some(question) = question
                && let Some(reply) = self.asked_about.get(&(to, question))
            {
                return Ok(reply.clone());
            }
            match self.replies.get(&to) {
                Some(r) => Ok(r.clone()),
                None => Err(io::Error::new(io::ErrorKind::TimedOut, "nothing answered")),
            }
        }
    }

    /// A `REFUSED` reply with recursion available and no records, which is
    /// what a hardened or a small name server sends.
    fn refusal(id: u16) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&id.to_be_bytes());
        // Response, recursion desired, recursion available, rcode 5.
        m.extend_from_slice(&0x8185u16.to_be_bytes());
        m.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
        m
    }

    /// One `TXT` record, as an mDNS responder would send it.
    fn txt_reply(name: &str, entries: &[&str]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&0u16.to_be_bytes());
        m.extend_from_slice(&0x8400u16.to_be_bytes());
        m.extend_from_slice(&0u16.to_be_bytes()); // no question echoed
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&[0, 0, 0, 0]);
        for label in name.trim_end_matches('.').split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&dns::TYPE_TXT.to_be_bytes());
        m.extend_from_slice(&dns::CLASS_IN.to_be_bytes());
        m.extend_from_slice(&60u32.to_be_bytes());
        let mut body = Vec::new();
        for entry in entries {
            body.push(entry.len() as u8);
            body.extend_from_slice(entry.as_bytes());
        }
        m.extend_from_slice(&(body.len() as u16).to_be_bytes());
        m.extend_from_slice(&body);
        m
    }

    fn ptr_reply(question: &str, answer: &str) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&0u16.to_be_bytes());
        m.extend_from_slice(&0x8180u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&[0, 0, 0, 0]);
        let q = dns::query(0, question, dns::TYPE_PTR, false);
        m.extend_from_slice(&q[12..]); // the question, name and type and class
        m.extend_from_slice(&[0xc0, 12]); // answer name points at it
        m.extend_from_slice(&dns::TYPE_PTR.to_be_bytes());
        m.extend_from_slice(&dns::CLASS_IN.to_be_bytes());
        m.extend_from_slice(&60u32.to_be_bytes());
        let mut target = Vec::new();
        for label in answer.split('.') {
            target.push(label.len() as u8);
            target.extend_from_slice(label.as_bytes());
        }
        target.push(0);
        m.extend_from_slice(&(target.len() as u16).to_be_bytes());
        m.extend_from_slice(&target);
        m
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn opts_all(resolver: &str) -> Options {
        Options {
            resolver: Some(ip(resolver)),
            ..Default::default()
        }
    }

    #[test]
    fn reverse_dns_finds_a_name_through_the_resolver() {
        let mut fake = Fake::default();
        fake.replies.insert(
            SocketAddr::new(ip("192.168.0.1"), 53),
            ptr_reply("9.0.168.192.in-addr.arpa", "kitchen-pi.lan"),
        );

        let found = one(
            ip("192.168.0.9"),
            &fake,
            &Bucket::new(1_000_000),
            opts_all("192.168.0.1"),
            1,
        );
        assert_eq!(found.best().unwrap().value, "kitchen-pi.lan");
        assert_eq!(found.best().unwrap().source, Source::ReverseDns);
    }

    /// The rule: self-reported beats second-hand, and the order is the
    /// priority, not the arrival.
    #[test]
    fn a_device_speaking_for_itself_outranks_the_resolver() {
        let mut fake = Fake::default();
        fake.replies.insert(
            SocketAddr::new(ip("192.168.0.1"), 53),
            ptr_reply("9.0.168.192.in-addr.arpa", "old-name.lan"),
        );
        fake.replies.insert(
            SocketAddr::new(ip("192.168.0.9"), 5353),
            ptr_reply("9.0.168.192.in-addr.arpa", "living-room.local"),
        );

        let found = one(
            ip("192.168.0.9"),
            &fake,
            &Bucket::new(1_000_000),
            opts_all("192.168.0.1"),
            1,
        );
        assert_eq!(found.best().unwrap().source, Source::Mdns);
        assert_eq!(found.best().unwrap().value, "living-room.local");

        // And the disagreement is kept rather than resolved away.
        assert_eq!(found.names.len(), 2);
        assert!(found.disputed(), "two genuinely different names");
    }

    /// The case found on a real network: a NAS running Samba answers NetBIOS
    /// as `TRUENAS` and mDNS as `truenas.local`. Compared literally that is a
    /// dispute, and it would be one on every machine running Samba.
    #[test]
    fn a_netbios_name_does_not_dispute_its_own_mdns_name() {
        let mut found = Identity::default();
        found.add("truenas.local".into(), Source::Mdns);
        found.add("TRUENAS".into(), Source::NetBios);
        assert!(!found.disputed(), "{:?}", found.names);
        assert_eq!(found.other_names(), Vec::<&str>::new());
        assert_eq!(found.best().unwrap().value, "truenas.local");
    }

    /// And the real thing still reads as a dispute, with the other name named.
    #[test]
    fn genuinely_different_names_are_reported_with_both() {
        let mut found = Identity::default();
        found.add("living-room.local".into(), Source::Mdns);
        found.add("old-tenant.lan".into(), Source::ReverseDns);
        assert!(found.disputed());
        assert_eq!(found.other_names(), vec!["old-tenant.lan"]);
    }

    /// `printer.local` and `printer` are one name, and marking that as a
    /// dispute would flag half a network.
    #[test]
    fn the_same_name_with_and_without_a_suffix_is_not_a_dispute() {
        let mut fake = Fake::default();
        fake.replies.insert(
            SocketAddr::new(ip("192.168.0.1"), 53),
            ptr_reply("9.0.168.192.in-addr.arpa", "printer.lan"),
        );
        fake.replies.insert(
            SocketAddr::new(ip("192.168.0.9"), 5353),
            ptr_reply("9.0.168.192.in-addr.arpa", "printer.local"),
        );
        let found = one(
            ip("192.168.0.9"),
            &fake,
            &Bucket::new(1_000_000),
            opts_all("192.168.0.1"),
            1,
        );
        assert_eq!(found.names.len(), 2);
        assert!(!found.disputed());
    }

    #[test]
    fn netbios_gives_a_windows_machine_its_name_and_workgroup() {
        // Reuse the netbios module's own reply builder shape.
        let mut m = Vec::new();
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&0x8400u16.to_be_bytes());
        m.extend_from_slice(&0u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&[0, 0, 0, 0]);
        let q = netbios::node_status_query(1);
        m.extend_from_slice(&q[12..46]); // the encoded name and terminator
        m.extend_from_slice(&[0x00, 0x21, 0x00, 0x01]);
        m.extend_from_slice(&0u32.to_be_bytes());
        let mut body = vec![2u8];
        for (name, suffix, group) in [("DESKTOP-7F3A", 0x00u8, false), ("WORKGROUP", 0x00, true)] {
            let mut padded = format!("{name:<15}").into_bytes();
            padded.truncate(15);
            body.extend_from_slice(&padded);
            body.push(suffix);
            body.extend_from_slice(&(if group { 0x8000u16 } else { 0x0400 }).to_be_bytes());
        }
        body.extend_from_slice(&[0x4c, 0xed, 0xfb, 0xb8, 0x1f, 0x75]);
        body.extend_from_slice(&[0u8; 40]);
        m.extend_from_slice(&(body.len() as u16).to_be_bytes());
        m.extend_from_slice(&body);

        let mut fake = Fake::default();
        fake.replies
            .insert(SocketAddr::new(ip("192.168.0.20"), 137), m);

        let found = one(
            ip("192.168.0.20"),
            &fake,
            &Bucket::new(1_000_000),
            Options::default(),
            1,
        );
        assert_eq!(found.best().unwrap().value, "DESKTOP-7F3A");
        assert_eq!(found.best().unwrap().source, Source::NetBios);
        assert_eq!(found.workgroup.as_deref(), Some("WORKGROUP"));
        assert_eq!(found.mac, Some("4c:ed:fb:b8:1f:75".parse().unwrap()));
    }

    #[test]
    fn a_device_that_answers_nothing_gets_an_empty_identity_not_an_error() {
        let fake = Fake::default();
        let found = one(
            ip("192.168.0.9"),
            &fake,
            &Bucket::new(1_000_000),
            opts_all("192.168.0.1"),
            1,
        );
        assert!(found.is_empty());
        assert_eq!(found.best(), None);
        assert!(!found.disputed());
    }

    /// A machine whose resolver could not be read must not be asked at a
    /// guessed address.
    #[test]
    fn no_resolver_means_no_reverse_lookup_rather_than_a_guess() {
        let fake = Fake::default();
        let opts = Options {
            resolver: None,
            ..Default::default()
        };
        one(ip("192.168.0.9"), &fake, &Bucket::new(1_000_000), opts, 1);
        let asked = fake.asked.lock().unwrap();
        // Port 53 is asked of the *device*, to find out whether it is itself a
        // name server. What must not happen is a question to a resolver, and
        // with no resolver configured there is no address to send one to.
        assert!(
            asked
                .iter()
                .all(|a| a.port() != 53 || a.ip() == ip("192.168.0.9")),
            "asked something that is not the device: {asked:?}"
        );
        assert!(asked.iter().any(|a| a.port() == 5353));
        assert!(asked.iter().any(|a| a.port() == 137));
    }

    /// The defect this was all written for: a device that answers mDNS with a
    /// name and is never asked what it offers.
    ///
    /// The enumeration query's answers carry the service type as the `PTR`
    /// **data**, not as the record's name, which is why it needed a reader of
    /// its own. Before this the device came back with a name and an empty
    /// service list, and `kind` had nothing to work with.
    #[test]
    fn asking_what_a_device_offers_is_what_fills_the_service_list() {
        let device = SocketAddr::new(ip("192.168.0.101"), 5353);
        let mut fake = Fake::default();
        fake.about(
            device,
            "101.0.168.192.in-addr.arpa",
            ptr_reply("101.0.168.192.in-addr.arpa", "SHIELDANDROIDTV.local"),
        );
        fake.about(
            device,
            SERVICE_ENUMERATION,
            ptr_reply(SERVICE_ENUMERATION, "_androidtvremote2._tcp.local"),
        );

        let found = one(
            ip("192.168.0.101"),
            &fake,
            &Bucket::new(1_000_000),
            Options::default(),
            1,
        );
        assert_eq!(found.best().unwrap().value, "SHIELDANDROIDTV.local");
        assert_eq!(found.services, vec!["_androidtvremote2._tcp"]);
        // And the enumeration's answer is a service, not a second name for the
        // device.
        assert_eq!(found.names.len(), 1, "{:?}", found.names);
    }

    /// `_device-info` is asked for by name, built from the name the device just
    /// gave, because the enumeration query does not list it.
    #[test]
    fn the_model_is_asked_for_under_the_name_the_device_gave() {
        let device = SocketAddr::new(ip("192.168.0.30"), 5353);
        let mut fake = Fake::default();
        fake.about(
            device,
            "30.0.168.192.in-addr.arpa",
            ptr_reply("30.0.168.192.in-addr.arpa", "Kitchen.local"),
        );
        fake.about(
            device,
            &format!("Kitchen.{DEVICE_INFO}"),
            txt_reply(
                &format!("Kitchen.{DEVICE_INFO}"),
                &["model=AudioAccessory5,1", "osxvers=21"],
            ),
        );

        let found = one(
            ip("192.168.0.30"),
            &fake,
            &Bucket::new(1_000_000),
            Options::default(),
            1,
        );
        assert_eq!(found.model.as_deref(), Some("AudioAccessory5,1"));
    }

    /// Where two keys both name a model, the better key wins whichever record
    /// happened to arrive first.
    #[test]
    fn the_best_model_key_wins_and_not_the_first_reply() {
        assert_eq!(
            model_of("md=Chromecast Ultra"),
            Some((1, "Chromecast Ultra".into()))
        );
        assert_eq!(
            model_of("ty=HP OfficeJet 6950"),
            Some((2, "HP OfficeJet 6950".into()))
        );
        assert_eq!(model_of("rp=printers/hp"), None, "not a model key");
        assert_eq!(model_of("model="), None, "an empty value names nothing");
        assert_eq!(model_of("MODEL=iPhone14,2"), Some((0, "iPhone14,2".into())));
        // As a TrueNAS box on a real network sends it.
        assert_eq!(
            model_of("model=MacPro7,1@ECOLOR=226,226,224"),
            Some((0, "MacPro7,1".into())),
            "the colour hint is not part of the model"
        );
    }

    /// A name server is anything that answers in the protocol, including a
    /// server that answers by refusing.
    ///
    /// The router this was tested against replies `REFUSED` to `version.bind`
    /// and carries no version string, and it is unmistakably a name server. A
    /// probe that only counted successful answers would have missed it, and
    /// with it most of the resolvers on managed networks.
    #[test]
    fn a_refusal_on_port_53_is_still_a_name_server() {
        let mut fake = Fake::default();
        fake.replies.insert(
            SocketAddr::new(ip("192.168.0.1"), DNS_PORT),
            // A reply to transaction 7: response, recursion available, REFUSED,
            // and no records at all.
            refusal(7),
        );
        let found = one(
            ip("192.168.0.1"),
            &fake,
            &Bucket::new(1_000_000),
            Options::default(),
            7,
        );
        assert_eq!(found.roles(), vec![Role::Dns]);
        let resolver = found.resolver.expect("a name server");
        assert_eq!(resolver.version, None, "it refused to say");
        assert!(resolver.recursive, "and it resolves for clients");
    }

    /// The version string, where a server gives one.
    #[test]
    fn a_server_that_names_itself_is_recorded_with_its_version() {
        let mut fake = Fake::default();
        fake.about(
            SocketAddr::new(ip("192.168.0.1"), DNS_PORT),
            VERSION_BIND,
            txt_reply(VERSION_BIND, &["dnsmasq-2.90"]),
        );
        let found = one(
            ip("192.168.0.1"),
            &fake,
            &Bucket::new(1_000_000),
            Options::default(),
            0,
        );
        let resolver = found.resolver.expect("a name server");
        assert_eq!(resolver.version.as_deref(), Some("dnsmasq-2.90"));
    }

    /// A device that says nothing on 53 gets no badge, which is the whole
    /// point: the badge is a service that answered.
    #[test]
    fn silence_on_port_53_is_not_a_name_server() {
        let found = one(
            ip("192.168.0.9"),
            &Fake::default(),
            &Bucket::new(1_000_000),
            Options::default(),
            1,
        );
        assert_eq!(found.resolver, None);
        assert!(found.roles().is_empty());
    }

    /// The badges come out in a stated order, so a row does not reshuffle
    /// itself between two scans that learned the same things.
    #[test]
    fn the_roles_are_ordered_by_the_enum_and_not_by_arrival() {
        let mut identity = Identity {
            resolver: Some(Resolver::default()),
            ..Default::default()
        };
        identity.offers_addresses();
        assert_eq!(identity.roles(), vec![Role::Dhcp, Role::Dns]);
    }

    /// The connected half of the same rule: what a device serves over TCP is
    /// folded in, and it comes out in the enum's order beside the rest.
    #[test]
    fn what_a_device_serves_over_a_connection_is_badged_too() {
        let mut identity = Identity::default();
        identity.serves(&crate::service::Serves {
            nfs: true,
            ssh: Some("SSH-2.0-OpenSSH_9.6".into()),
            ..Default::default()
        });
        // A second pass that learned only about SMB adds to what is known
        // rather than replacing it.
        identity.serves(&crate::service::Serves {
            smb: true,
            ..Default::default()
        });
        assert_eq!(identity.roles(), vec![Role::Smb, Role::Nfs, Role::Ssh]);
        assert!(
            !identity.is_empty(),
            "a service answered, so it is not empty"
        );
    }

    /// A responder on 5355 is the flag, whether or not it gave a new name.
    #[test]
    fn an_llmnr_answer_is_recorded_even_when_the_name_is_already_known() {
        let mut fake = Fake::default();
        fake.replies.insert(
            SocketAddr::new(ip("192.168.0.150"), LLMNR_PORT),
            ptr_reply("150.0.168.192.in-addr.arpa", "HOME-GAMING"),
        );
        let found = one(
            ip("192.168.0.150"),
            &fake,
            &Bucket::new(1_000_000),
            Options::default(),
            1,
        );
        assert!(found.llmnr);
        assert_eq!(found.best().unwrap().source, Source::Llmnr);
    }

    #[test]
    fn service_types_are_read_out_of_mdns_names() {
        let read = |name: &str| service_type(name).unwrap_or_default();
        assert_eq!(read("brother._ipp._tcp.local"), "_ipp._tcp");
        assert_eq!(
            read("Living Room._googlecast._tcp.local."),
            "_googlecast._tcp"
        );
        // A bare type, which is what the enumeration query is answered with.
        assert_eq!(
            read("_androidtvremote2._tcp.local"),
            "_androidtvremote2._tcp"
        );
        assert_eq!(read("_spotify-connect._tcp"), "_spotify-connect._tcp");
        // A subtype names its type, not itself.
        assert_eq!(read("_universal._sub._ipp._tcp.local"), "_ipp._tcp");
        assert_eq!(service_type("host.local"), None);
        assert_eq!(service_type("_services._dns-sd._udp.local"), None);
    }

    #[test]
    fn many_keeps_results_in_the_order_it_was_given() {
        let mut fake = Fake::default();
        for (i, last) in [3u8, 9, 21].iter().enumerate() {
            fake.replies.insert(
                SocketAddr::new(ip(&format!("192.168.0.{last}")), 5353),
                ptr_reply(
                    &format!("{last}.0.168.192.in-addr.arpa"),
                    &format!("host{i}.local"),
                ),
            );
        }
        let addresses: Vec<IpAddr> = (1..=30).map(|n| ip(&format!("192.168.0.{n}"))).collect();
        let found = many(
            &addresses,
            &fake,
            &Bucket::new(1_000_000),
            Options::default(),
            &AtomicBool::new(false),
            &|_, _| {},
        );
        assert_eq!(found.len(), 30);
        assert_eq!(found[2].best().unwrap().value, "host0.local"); // .3
        assert_eq!(found[8].best().unwrap().value, "host1.local"); // .9
        assert_eq!(found[20].best().unwrap().value, "host2.local"); // .21
        assert!(found[0].is_empty());
    }

    #[test]
    fn cancelling_stops_the_run() {
        let fake = Fake::default();
        let addresses: Vec<IpAddr> = (1..=200).map(|n| ip(&format!("10.0.0.{n}"))).collect();
        let cancel = AtomicBool::new(false);
        let seen = AtomicU64::new(0);
        let found = many(
            &addresses,
            &fake,
            &Bucket::new(1_000_000),
            Options {
                workers: 1,
                ..Default::default()
            },
            &cancel,
            &|_, _| {
                if seen.fetch_add(1, Ordering::SeqCst) >= 4 {
                    cancel.store(true, Ordering::SeqCst);
                }
            },
        );
        assert_eq!(found.len(), 200, "every address still has a slot");
        assert!(found.iter().all(Identity::is_empty));
        assert!(seen.load(Ordering::SeqCst) < 200);
    }
}
