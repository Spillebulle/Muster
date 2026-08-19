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
use std::io;
use std::net::{IpAddr, Ipv4Addr};
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
}

impl Evidence {
    /// A short phrase for the interface, which shows why rather than only what.
    pub fn reason(&self) -> String {
        match self {
            Self::Arp(_) => "answered ARP".into(),
            Self::Ping => "answered ping".into(),
            Self::TcpOpen(p) => format!("port {p} open"),
            Self::TcpRefused(p) => format!("port {p} refused"),
        }
    }
}

/// A host that answered something.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
    pub address: IpAddr,
    pub mac: Option<MacAddr>,
    /// Every reason, in the order they were obtained. Never empty: a `Found`
    /// with no evidence is a host nothing attests to, and this module does not
    /// build one.
    pub evidence: Vec<Evidence>,
    /// Round trip time, where something measured one.
    pub rtt: Option<Duration>,
}

impl Found {
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
    fn ping(&self, addr: IpAddr, timeout: Duration) -> io::Result<Option<Duration>>;

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
    /// Treat silence from ARP as proof that nothing is at the address, and stop
    /// probing it.
    ///
    /// **Only true when the prefix is on the machine's own link**, which the
    /// caller knows and the sweep does not. There it is not an optimisation but
    /// the more correct answer: ARP is answered by a device's network stack
    /// below any firewall it has, and a host that did not answer could not use
    /// the network at all. Everything after it — a ping and four connections —
    /// is then spent proving something already known, at four seconds an empty
    /// address, which on a mostly empty /24 is the entire cost of the sweep.
    ///
    /// Off the link it must be false: an address one hop away is *supposed* to
    /// have no ARP reply, and taking that as absence finds nothing anywhere.
    ///
    /// The one thing this gives up is a host whose stack answers nothing at all
    /// yet still has open ports. That configuration cannot reach its own
    /// gateway, so it is a lab curiosity rather than a device on somebody's
    /// network.
    pub arp_authoritative: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            // The local wire answers in microseconds. A second here is not
            // patience, it is 254 seconds of sweep.
            arp_timeout: Duration::from_millis(300),
            ping_timeout: Duration::from_millis(500),
            tcp_timeout: Duration::from_millis(400),
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

/// Progress, reported as the sweep runs.
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
    progress: &(dyn Fn(Progress) + Sync),
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

    if !caps.arp {
        result.not_done.push(
            "could not send ARP requests, so devices that ignore ping and \
             refuse nothing were missed"
                .into(),
        );
    }
    if !caps.icmp {
        result.not_done.push("could not send ICMP echoes".into());
    }

    let next = AtomicU64::new(0);
    let probed = AtomicU64::new(0);
    let found_count = AtomicU64::new(0);
    let workers = opts.workers.clamp(1, 512).min(addresses.len().max(1));
    let mut found: Vec<Found> = Vec::new();

    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            let (next, probed, found_count) = (&next, &probed, &found_count);
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

                    let hit = probe_one(address, transport, rate, &caps, opts);
                    let done = probed.fetch_add(1, Ordering::Relaxed) + 1;
                    let hits = match hit {
                        Some(f) => {
                            mine.push(f);
                            found_count.fetch_add(1, Ordering::Relaxed) + 1
                        }
                        None => found_count.load(Ordering::Relaxed),
                    };
                    progress(Progress {
                        probed: done,
                        total: addresses.len() as u64,
                        found: hits,
                    });
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
    result.probed = probed.load(Ordering::Relaxed);
    result.cancelled = cancel.load(Ordering::Relaxed);
    result
}

/// Probes one address with everything available, cheapest and most conclusive
/// first.
///
/// ARP leads because it is the strongest evidence on a local wire — answered
/// below any firewall — and because it yields the hardware address, which is
/// what the whole device list is keyed on. The knock is last and only for
/// silence, so a host that answered already costs four fewer probes.
fn probe_one<T: Transport>(
    address: IpAddr,
    transport: &T,
    rate: &Bucket,
    caps: &Capabilities,
    opts: Options,
) -> Option<Found> {
    let mut evidence = Vec::new();
    let mut mac = None;
    let mut rtt = None;

    if caps.arp
        && let IpAddr::V4(v4) = address
    {
        rate.wait();
        let answered = transport.arp(v4, opts.arp_timeout);
        match answered {
            // An all-zero reply is the API's way of saying nothing answered,
            // and it is not a device.
            Ok(Some(hw)) if !hw.is_zero() => {
                mac = Some(hw);
                evidence.push(Evidence::Arp(hw));
            }
            // On-link silence settles it. See `Options::arp_authoritative`.
            Ok(_) if opts.arp_authoritative => return None,
            // An *error* is the mechanism failing, not the address answering,
            // so it never settles anything: fall through and probe properly.
            _ => {}
        }
    }

    if caps.icmp {
        rate.wait();
        if let Ok(Some(t)) = transport.ping(address, opts.ping_timeout) {
            evidence.push(Evidence::Ping);
            rtt = Some(t);
        }
    }

    if evidence.is_empty() && opts.knock && caps.tcp {
        for &port in KNOCK_PORTS {
            rate.wait();
            match transport.tcp(address, port, opts.tcp_timeout) {
                Outcome::Open => evidence.push(Evidence::TcpOpen(port)),
                // A refusal proves the host. Knocking further would only find
                // more ports, which is phase three's job.
                Outcome::Refused => {
                    evidence.push(Evidence::TcpRefused(port));
                    break;
                }
                Outcome::NoAnswer => {}
            }
        }
    }

    (!evidence.is_empty()).then_some(Found {
        address,
        mac,
        evidence,
        rtt,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// A network held in a map. Every test in this module runs against it, and
    /// no test in this crate opens a socket.
    #[derive(Default)]
    struct Fake {
        caps: Capabilities,
        arp: BTreeMap<Ipv4Addr, MacAddr>,
        pings: Vec<IpAddr>,
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
        fn ping(&self, addr: IpAddr, _: Duration) -> io::Result<Option<Duration>> {
            self.note(format!("ping {addr}"));
            Ok(self
                .pings
                .contains(&addr)
                .then_some(Duration::from_millis(3)))
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
            &|_| {},
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

        let s = run("192.168.1.0/24", &fake, Options::default());
        assert_eq!(s.found.len(), 1);
        assert_eq!(s.found[0].address, ip("192.168.1.1"));
        assert_eq!(s.found[0].mac, Some("3c:22:fb:aa:bb:cc".parse().unwrap()));
        assert_eq!(s.found[0].evidence[0].reason(), "answered ARP");
        assert_eq!(s.probed, 254);
        assert!(s.is_complete());
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

    /// Once something has answered, the knock is wasted probes.
    #[test]
    fn a_host_that_answered_is_not_knocked_on() {
        let mut fake = Fake::new();
        fake.arp
            .insert(v4("192.168.1.5"), "3c:22:fb:aa:bb:cc".parse().unwrap());

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
            fn ping(&self, addr: IpAddr, _: Duration) -> io::Result<Option<Duration>> {
                Ok((addr == ip("192.168.1.2")).then_some(Duration::from_millis(1)))
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
            &|_| {},
        );
        assert_eq!(s.found.len(), 1, "the pinging host survives a broken ARP");
        assert_eq!(s.found[0].address, ip("192.168.1.2"));
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

        let s = run("192.168.1.0/24", &fake, Options::default());
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
                ..Default::default()
            },
            &cancel,
            &|_| {
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
            &|p| {
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
    #[test]
    fn every_probe_is_charged_to_the_rate_limiter() {
        let fake = Fake::new();
        let rate = Bucket::new(1_000_000);
        let opts = Options {
            workers: 1,
            ..Default::default()
        };
        sweep(
            "192.168.1.0/30".parse().unwrap(),
            &fake,
            &rate,
            opts,
            &AtomicBool::new(false),
            &|_| {},
        );
        // Two addresses, each: one ARP, one ping, then four knocks.
        assert_eq!(fake.count("arp"), 2);
        assert_eq!(fake.count("ping"), 2);
        assert_eq!(fake.count("tcp"), 8);
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
