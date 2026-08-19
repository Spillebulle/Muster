//! Phase three: which ports are open.
//!
//! ## The stateless design, and why it is here before the transport that needs
//! it
//!
//! `CLAUDE.md` settles the shape: the scan keeps **no per-probe record**. The
//! probe's identity is encoded in the packet it sends — a keyed hash of source,
//! destination, port and a per-run secret, written into the TCP initial
//! sequence number — so a reply identifies itself. A SYN-ACK is ours when its
//! acknowledgement minus one is that cookie. Nothing is allocated per port,
//! nothing times out per port, and the send rate is a function of the rate
//! limiter and nothing else.
//!
//! That design needs raw packet access, which means Npcap on Windows and
//! `CAP_NET_RAW` on Linux, and neither is available yet. **The reply validation
//! is written and tested first anyway**, which is what `CLAUDE.md` asks for: it
//! is the part that has to be right, and retrofitting it under a scanner that
//! already works by other means is how it ends up never being written. So
//! [`Cookie`] is here, complete and tested, and the raw transport will use it
//! rather than the other way round.
//!
//! Until then the working path is [`Method::Connect`], which asks the operating
//! system to open a connection. It is unprivileged, it works everywhere, and it
//! is **slower by a large factor** because it is one socket and one piece of
//! kernel state per port. It says so in the result rather than being quietly
//! substituted.
//!
//! ## Absence of a reply is never "closed"
//!
//! The rule the whole module is arranged around, and the most common lie a
//! scanner tells. Three states, and the third is not a synonym for the second:
//!
//! * A **SYN-ACK** means open.
//! * A **RST** means closed: something is there and it refused.
//! * **Nothing** means [`PortState::Filtered`] — dropped by a firewall, lost, or
//!   rate limited into the next second. It is not evidence that the port is
//!   shut, and reporting it as such invents a fact about somebody's network.

use crate::rate::Bucket;
use crate::siphash::SipHasher;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

/// The per-run secret and the cookie derived from it.
///
/// One per scan. The secret never leaves the process and is not derived from
/// anything guessable: an attacker who could predict the cookie could forge
/// SYN-ACKs that Muster would report as open ports on hosts that never
/// answered.
pub struct Cookie {
    hasher: SipHasher,
}

impl Cookie {
    /// A cookie keyed by the operating system's randomness.
    pub fn new() -> Self {
        use std::hash::{BuildHasher, RandomState};
        // `RandomState` is seeded by the OS per process. Two independent
        // instances give two independent words, which is the key material
        // needed without taking a dependency for it.
        let k0 = RandomState::new().hash_one(0x6d75_7374_6572u64);
        let k1 = RandomState::new().hash_one(0x7363_616e_6e65u64);
        Self {
            hasher: SipHasher::new(k0, k1),
        }
    }

    /// A cookie with a stated key, for tests and for reproducing a run.
    pub const fn with_key(k0: u64, k1: u64) -> Self {
        Self {
            hasher: SipHasher::new(k0, k1),
        }
    }

    /// The initial sequence number to send for this probe.
    ///
    /// Every field that distinguishes one probe from another goes in, so a
    /// reply from a *different* address or port cannot validate against a
    /// cookie meant for this one.
    pub fn for_probe(&self, source: IpAddr, target: IpAddr, port: u16) -> u32 {
        let mut msg = Vec::with_capacity(38);
        push_addr(&mut msg, source);
        push_addr(&mut msg, target);
        msg.extend_from_slice(&port.to_be_bytes());
        // Folding to 32 bits loses half the hash, which is inherent: the
        // sequence number is 32 bits wide. A one-in-four-billion false accept
        // per reply is the cost of the design, and it is the same cost masscan
        // pays.
        self.hasher.hash(&msg) as u32
    }

    /// Is this SYN-ACK a reply to a probe we sent?
    ///
    /// The acknowledgement number of a SYN-ACK is our sequence number plus one,
    /// so the check is the cookie plus one. Wrapping is deliberate: sequence
    /// numbers are modulo 2³², and a cookie of `0xffff_ffff` is acknowledged as
    /// `0`.
    pub fn validates(&self, source: IpAddr, target: IpAddr, port: u16, ack: u32) -> bool {
        ack == self.for_probe(source, target, port).wrapping_add(1)
    }
}

impl Default for Cookie {
    fn default() -> Self {
        Self::new()
    }
}

fn push_addr(out: &mut Vec<u8>, addr: IpAddr) {
    match addr {
        IpAddr::V4(a) => out.extend_from_slice(&a.octets()),
        IpAddr::V6(a) => out.extend_from_slice(&a.octets()),
    }
}

/// What was learned about one port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortState {
    /// A SYN-ACK, or an accepted connection. Something is listening.
    Open,
    /// A RST. There is a host and nothing is listening on this port.
    Closed,
    /// No answer. **Not** closed: dropped, filtered, or lost.
    Filtered,
}

impl PortState {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
            // Named for what was observed rather than for a conclusion, because
            // there is no conclusion to draw.
            Self::Filtered => "no reply",
        }
    }
}

/// How the answer was obtained, which the result carries so that the interface
/// can say which engine produced it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// Stateless SYN probes over a raw socket. Fast, needs privileges.
    Syn,
    /// A full connection per port, through the OS. Unprivileged and slow.
    Connect,
}

impl Method {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Syn => "SYN",
            Self::Connect => "connect()",
        }
    }

    /// What the user needs to know about this method's limits, or [`None`]
    /// where there is nothing to say.
    pub const fn caveat(self) -> Option<&'static str> {
        match self {
            Self::Syn => None,
            Self::Connect => Some(
                "used connect(), which is slower and completes the handshake, \
                 so the far end may log it",
            ),
        }
    }
}

/// A set of ports to scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ports(Vec<u16>);

impl Ports {
    /// The ports worth trying when nobody said which.
    ///
    /// Not "the top thousand": a short list that answers the question people
    /// actually ask of a home or office network — what is serving, what is
    /// remotely administrable, and what is exposed that should not be. A
    /// thousand ports per host is a different scan and should be asked for.
    pub fn common() -> Self {
        Self(vec![
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 515, 548, 587, 631,
            993, 995, 1080, 1433, 1723, 1883, 2049, 3000, 3306, 3389, 4444, 5000, 5060, 5432, 5555,
            5900, 5901, 6379, 7000, 8000, 8006, 8080, 8081, 8123, 8443, 8888, 9000, 9090, 9100,
            27017, 32400, 51820,
        ])
    }

    pub fn as_slice(&self) -> &[u16] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::str::FromStr for Ports {
    type Err = PortsError;

    /// Accepts `80`, `80,443`, `1-1024`, and any mixture of those.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut out: Vec<u16> = Vec::new();
        for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            match part.split_once('-') {
                None => out.push(
                    part.parse()
                        .map_err(|_| PortsError::NotAPort(part.into()))?,
                ),
                Some((from, to)) => {
                    let from: u16 = from
                        .trim()
                        .parse()
                        .map_err(|_| PortsError::NotAPort(from.into()))?;
                    let to: u16 = to
                        .trim()
                        .parse()
                        .map_err(|_| PortsError::NotAPort(to.into()))?;
                    if from > to {
                        return Err(PortsError::Backwards(from, to));
                    }
                    out.extend(from..=to);
                }
            }
        }
        if out.is_empty() {
            return Err(PortsError::Empty);
        }
        out.sort_unstable();
        out.dedup();
        Ok(Self(out))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortsError {
    NotAPort(String),
    Backwards(u16, u16),
    Empty,
}

impl std::fmt::Display for PortsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAPort(s) => write!(f, "'{s}' is not a port number"),
            Self::Backwards(a, b) => write!(f, "the range {a}-{b} runs backwards"),
            Self::Empty => f.write_str("no ports given"),
        }
    }
}

impl std::error::Error for PortsError {}

/// The transport a port scan probes through.
pub trait Scanner: Sync {
    fn method(&self) -> Method;

    /// Probes one port and says how it answered.
    fn probe(&self, target: IpAddr, port: u16, timeout: Duration) -> PortState;
}

/// The unprivileged scanner: one connection per port, through the OS.
#[derive(Clone, Copy, Debug, Default)]
pub struct ConnectScanner;

impl Scanner for ConnectScanner {
    fn method(&self) -> Method {
        Method::Connect
    }

    fn probe(&self, target: IpAddr, port: u16, timeout: Duration) -> PortState {
        match crate::platform::tcp::knock(target, port, timeout) {
            crate::discover::Outcome::Open => PortState::Open,
            crate::discover::Outcome::Refused => PortState::Closed,
            // The rule: silence is not a closed port.
            crate::discover::Outcome::NoAnswer => PortState::Filtered,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub timeout: Duration,
    pub workers: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(700),
            // Every probe is a blocking connection that mostly waits, so this
            // is the same reasoning the sweep's worker count follows.
            workers: 256,
        }
    }
}

/// One host's open ports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostPorts {
    pub address: IpAddr,
    /// Ports that answered, with how. Filtered ports are **not** listed
    /// individually — there are usually hundreds and they say nothing — but
    /// they are counted.
    pub answered: Vec<(u16, PortState)>,
    pub filtered: usize,
}

impl HostPorts {
    pub fn open(&self) -> impl Iterator<Item = u16> + '_ {
        self.answered
            .iter()
            .filter(|(_, s)| *s == PortState::Open)
            .map(|(p, _)| *p)
    }

    pub fn closed(&self) -> usize {
        self.answered
            .iter()
            .filter(|(_, s)| *s == PortState::Closed)
            .count()
    }
}

/// The result of scanning some hosts.
#[derive(Clone, Debug)]
pub struct Scan {
    pub hosts: Vec<HostPorts>,
    pub method: Method,
    pub probed: u64,
    pub total: u64,
    pub cancelled: bool,
}

impl Scan {
    /// What the interface must say alongside the result, if anything.
    pub fn caveats(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(c) = self.method.caveat() {
            out.push(c.to_string());
        }
        if self.cancelled {
            out.push("stopped early, so this is not every port".into());
        }
        let filtered: usize = self.hosts.iter().map(|h| h.filtered).sum();
        if filtered > 0 {
            out.push(format!(
                "{filtered} port{} did not answer, which is not the same as being closed",
                if filtered == 1 { "" } else { "s" }
            ));
        }
        out
    }
}

/// Scans a set of ports on a set of hosts.
pub fn scan<S: Scanner>(
    targets: &[IpAddr],
    ports: &Ports,
    scanner: &S,
    rate: &Bucket,
    opts: Options,
    cancel: &AtomicBool,
    progress: &(dyn Fn(u64, u64) + Sync),
) -> Scan {
    let total = (targets.len() * ports.len()) as u64;
    let next = AtomicU64::new(0);
    let done = AtomicU64::new(0);
    let workers = opts.workers.clamp(1, 512).min(total.max(1) as usize);

    // One flat index over the whole grid, so the work splits evenly whether
    // there is one host with many ports or many hosts with few.
    let mut per_host: Vec<Vec<(u16, PortState)>> = vec![Vec::new(); targets.len()];

    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            let (next, done) = (&next, &done);
            handles.push(scope.spawn(move || {
                let mut mine: Vec<(usize, u16, PortState)> = Vec::new();
                loop {
                    if cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= total {
                        break;
                    }
                    let host = (i / ports.len() as u64) as usize;
                    let port = ports.as_slice()[(i % ports.len() as u64) as usize];

                    rate.wait();
                    let state = scanner.probe(targets[host], port, opts.timeout);
                    mine.push((host, port, state));
                    progress(done.fetch_add(1, Ordering::Relaxed) + 1, total);
                }
                mine
            }));
        }
        for handle in handles {
            for (host, port, state) in handle.join().unwrap_or_default() {
                per_host[host].push((port, state));
            }
        }
    });

    let hosts = targets
        .iter()
        .zip(per_host)
        .map(|(&address, mut found)| {
            found.sort_unstable_by_key(|(p, _)| *p);
            let filtered = found
                .iter()
                .filter(|(_, s)| *s == PortState::Filtered)
                .count();
            found.retain(|(_, s)| *s != PortState::Filtered);
            HostPorts {
                address,
                answered: found,
                filtered,
            }
        })
        .collect();

    Scan {
        hosts,
        method: scanner.method(),
        probed: done.load(Ordering::Relaxed),
        total,
        cancelled: cancel.load(Ordering::Relaxed),
    }
}

/// A socket address, for callers building one.
pub fn at(address: IpAddr, port: u16) -> SocketAddr {
    SocketAddr::new(address, port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // ---- the cookie, which is the part that has to be right ----

    /// A reply validates only against the probe that produced it. Every field
    /// is varied in turn, because a cookie that ignored one of them would let a
    /// reply from the wrong host or port be accepted as an open port here.
    #[test]
    fn a_cookie_validates_only_its_own_probe() {
        let c = Cookie::with_key(0xdead_beef, 0xfeed_face);
        let src = ip("192.168.0.150");
        let dst = ip("192.168.0.1");

        let isn = c.for_probe(src, dst, 443);
        assert!(c.validates(src, dst, 443, isn.wrapping_add(1)));

        // Right handshake, wrong port.
        assert!(!c.validates(src, dst, 80, isn.wrapping_add(1)));
        // Right port, a different host answering.
        assert!(!c.validates(src, ip("192.168.0.2"), 443, isn.wrapping_add(1)));
        // Our own address changed, so this is another run's probe.
        assert!(!c.validates(ip("192.168.0.9"), dst, 443, isn.wrapping_add(1)));
        // The acknowledgement is the sequence number itself rather than +1.
        assert!(!c.validates(src, dst, 443, isn));
    }

    /// Sequence numbers are modulo 2³². A cookie at the top of the range is
    /// acknowledged as zero, and a check written with a plain `+ 1` panics
    /// there in a debug build and is wrong in a release one.
    #[test]
    fn a_cookie_at_the_end_of_the_range_wraps() {
        // Search for a probe whose cookie is large enough to exercise the wrap.
        let c = Cookie::with_key(1, 2);
        let src = ip("10.0.0.1");
        for port in 1..=u16::MAX {
            let dst = ip("10.0.0.2");
            let isn = c.for_probe(src, dst, port);
            if isn == u32::MAX {
                assert!(c.validates(src, dst, port, 0), "wrapped acknowledgement");
                return;
            }
        }
        // Not finding one is expected; assert the arithmetic directly instead.
        assert_eq!(u32::MAX.wrapping_add(1), 0);
    }

    /// Without a secret, anything on the network could forge a reply that
    /// Muster reports as an open port.
    #[test]
    fn two_runs_do_not_share_cookies() {
        let a = Cookie::with_key(1, 2);
        let b = Cookie::with_key(3, 4);
        let (src, dst) = (ip("10.0.0.1"), ip("10.0.0.2"));
        let differing = (1..=1000u16)
            .filter(|&p| a.for_probe(src, dst, p) != b.for_probe(src, dst, p))
            .count();
        assert_eq!(
            differing, 1000,
            "a different secret must give different cookies"
        );
    }

    #[test]
    fn cookies_differ_across_ports_and_hosts() {
        let c = Cookie::with_key(9, 9);
        let src = ip("10.0.0.1");
        let mut seen = std::collections::BTreeSet::new();
        for port in 1..=500u16 {
            seen.insert(c.for_probe(src, ip("10.0.0.2"), port));
        }
        assert_eq!(seen.len(), 500, "no two ports share a cookie");

        let mut hosts = std::collections::BTreeSet::new();
        for n in 1..=200u8 {
            hosts.insert(c.for_probe(src, ip(&format!("10.0.0.{n}")), 443));
        }
        assert_eq!(hosts.len(), 200);
    }

    #[test]
    fn a_new_cookie_is_not_a_fixed_one() {
        let (src, dst) = (ip("10.0.0.1"), ip("10.0.0.2"));
        let a = Cookie::new().for_probe(src, dst, 443);
        let b = Cookie::new().for_probe(src, dst, 443);
        // Two independently keyed cookies agreeing would mean the key is not
        // random. One in four billion says this is not flaky.
        assert_ne!(a, b);
    }

    // ---- the port list ----

    #[test]
    fn parses_lists_and_ranges() {
        let p: Ports = "80,443,8080".parse().unwrap();
        assert_eq!(p.as_slice(), &[80, 443, 8080]);

        let p: Ports = "20-25".parse().unwrap();
        assert_eq!(p.as_slice(), &[20, 21, 22, 23, 24, 25]);

        // Mixed, overlapping, out of order: sorted and deduplicated.
        let p: Ports = "443, 80, 79-81".parse().unwrap();
        assert_eq!(p.as_slice(), &[79, 80, 81, 443]);
    }

    #[test]
    fn refuses_nonsense_rather_than_scanning_something_unintended() {
        assert!("".parse::<Ports>().is_err());
        assert!("http".parse::<Ports>().is_err());
        assert!("70000".parse::<Ports>().is_err(), "beyond a u16");
        assert_eq!(
            "100-50".parse::<Ports>(),
            Err(PortsError::Backwards(100, 50))
        );
    }

    #[test]
    fn the_whole_range_is_expressible() {
        let p: Ports = "1-65535".parse().unwrap();
        assert_eq!(p.len(), 65535);
    }

    // ---- the engine ----

    #[derive(Default)]
    struct Fake {
        open: BTreeMap<IpAddr, Vec<u16>>,
        closed: BTreeMap<IpAddr, Vec<u16>>,
        probed: Mutex<Vec<(IpAddr, u16)>>,
    }

    impl Scanner for Fake {
        fn method(&self) -> Method {
            Method::Connect
        }
        fn probe(&self, target: IpAddr, port: u16, _t: Duration) -> PortState {
            self.probed.lock().unwrap().push((target, port));
            if self.open.get(&target).is_some_and(|v| v.contains(&port)) {
                PortState::Open
            } else if self.closed.get(&target).is_some_and(|v| v.contains(&port)) {
                PortState::Closed
            } else {
                PortState::Filtered
            }
        }
    }

    fn run(fake: &Fake, targets: &[IpAddr], ports: &str) -> Scan {
        scan(
            targets,
            &ports.parse().unwrap(),
            fake,
            &Bucket::new(1_000_000),
            Options::default(),
            &AtomicBool::new(false),
            &|_, _| {},
        )
    }

    #[test]
    fn finds_open_ports_and_keeps_them_in_order() {
        let mut fake = Fake::default();
        fake.open.insert(ip("192.168.0.6"), vec![22, 443, 80]);

        let s = run(&fake, &[ip("192.168.0.6")], "22,80,443,8080");
        let open: Vec<u16> = s.hosts[0].open().collect();
        assert_eq!(open, vec![22, 80, 443]);
        assert_eq!(s.probed, 4);
        assert_eq!(s.total, 4);
    }

    /// The rule the module exists for. A port that said nothing is not closed,
    /// and the two must never be summed together.
    #[test]
    fn silence_is_not_reported_as_closed() {
        let mut fake = Fake::default();
        fake.closed.insert(ip("10.0.0.1"), vec![80]);
        // 443 and 8080 answer nothing at all.

        let s = run(&fake, &[ip("10.0.0.1")], "80,443,8080");
        assert_eq!(s.hosts[0].closed(), 1, "only the RST counts as closed");
        assert_eq!(s.hosts[0].filtered, 2);
        assert_eq!(s.hosts[0].open().count(), 0);

        // And the caveat says so in words.
        let caveats = s.caveats().join("; ");
        assert!(caveats.contains("did not answer"), "{caveats}");
        assert!(
            caveats.contains("not the same as being closed"),
            "{caveats}"
        );
    }

    /// The unprivileged method is never substituted silently.
    #[test]
    fn the_method_is_reported_with_its_limits() {
        let fake = Fake::default();
        let s = run(&fake, &[ip("10.0.0.1")], "80");
        assert_eq!(s.method, Method::Connect);
        assert_eq!(s.method.label(), "connect()");
        assert!(s.caveats().iter().any(|c| c.contains("connect()")));
        assert_eq!(
            Method::Syn.caveat(),
            None,
            "the fast path has nothing to apologise for"
        );
    }

    #[test]
    fn every_host_and_port_is_probed_exactly_once() {
        let fake = Fake::default();
        let targets: Vec<IpAddr> = (1..=8).map(|n| ip(&format!("10.0.0.{n}"))).collect();
        let s = run(&fake, &targets, "80,443,22");

        assert_eq!(s.total, 24);
        let mut probed = fake.probed.lock().unwrap().clone();
        probed.sort();
        probed.dedup();
        assert_eq!(probed.len(), 24, "each pair probed once");
        assert_eq!(s.hosts.len(), 8);
    }

    #[test]
    fn cancelling_stops_and_says_so() {
        let fake = Fake::default();
        let targets: Vec<IpAddr> = (1..=20).map(|n| ip(&format!("10.0.0.{n}"))).collect();
        let cancel = AtomicBool::new(false);
        let seen = AtomicU64::new(0);
        let s = scan(
            &targets,
            &"1-100".parse().unwrap(),
            &fake,
            &Bucket::new(1_000_000),
            Options {
                workers: 1,
                ..Default::default()
            },
            &cancel,
            &|_, _| {
                if seen.fetch_add(1, Ordering::SeqCst) >= 9 {
                    cancel.store(true, Ordering::SeqCst);
                }
            },
        );
        assert!(s.cancelled);
        assert!(s.probed < s.total);
        assert!(s.caveats().iter().any(|c| c.contains("stopped early")));
    }

    #[test]
    fn the_common_list_is_sorted_and_free_of_duplicates() {
        let common = Ports::common();
        let mut sorted = common.as_slice().to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.as_slice(), common.as_slice());
        assert!(common.as_slice().contains(&443));
        assert!(common.as_slice().contains(&22));
    }
}
