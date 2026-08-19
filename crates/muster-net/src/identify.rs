//! Phase four: asking a device what it is.
//!
//! Only for hosts that answered the sweep, and it is a different shape from the
//! sweep: a handful of short exchanges per device rather than one probe per
//! address. All of it is ordinary UDP, so all of it works with no privileges on
//! both platforms.
//!
//! Three questions, in one seam:
//!
//! * **Reverse DNS** to the machine's own resolver. On a home network that
//!   resolver is usually the router, and the router knows the hostname every
//!   device gave it with its DHCP request. It is the cheapest name there is.
//! * **mDNS** to `224.0.0.251:5353`, which Apple devices, printers,
//!   Chromecasts and anything running Avahi answer for themselves.
//! * **NetBIOS** to port 137, which is how a Windows machine says its name —
//!   including the ones that ignore ping.
//!
//! Every one of them is a datagram out and a datagram back, so the whole
//! platform surface is [`Ask`], with one method. The tests drive it with
//! recorded replies and no test opens a socket.
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
//! The order is **self-reported first**: mDNS and NetBIOS are the device
//! speaking about itself, while reverse DNS is what the router was told once,
//! possibly by a previous occupant of the address.

use crate::dns;
use crate::mac::MacAddr;
use crate::netbios;
use crate::rate::Bucket;
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
    /// The resolver had a `PTR` record. Second-hand, and sometimes stale.
    ReverseDns,
}

impl Source {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Mdns => "mDNS",
            Self::NetBios => "NetBIOS",
            Self::ReverseDns => "reverse DNS",
        }
    }
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
    pub mac: Option<MacAddr>,
    /// mDNS service types seen, such as `_ipp._tcp` for a printer.
    pub services: Vec<String>,
}

impl Identity {
    pub fn is_empty(&self) -> bool {
        self.names.is_empty() && self.workgroup.is_none() && self.services.is_empty()
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

    fn add(&mut self, value: String, source: Source) {
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
        }
    }
}

/// The mDNS group and port. Fixed by the standard.
pub const MDNS: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)), 5353);
/// NetBIOS name service.
pub const NBNS_PORT: u16 = 137;

/// Identifies one device.
///
/// Never fails: a device that answers nothing has an empty [`Identity`], which
/// is a real answer and different from an error.
pub fn one<A: Ask>(address: IpAddr, ask: &A, rate: &Bucket, opts: Options, id: u16) -> Identity {
    let mut found = Identity::default();

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
            for record in msg.records() {
                if let dns::RData::Srv { target, .. } = &record.data {
                    found.add(target.clone(), Source::Mdns);
                }
                if let Some(service) = service_type(&record.name)
                    && !found.services.iter().any(|s| s == service)
                {
                    found.services.push(service.to_string());
                }
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
        }
    }

    found
}

/// The `_ipp._tcp` out of `printer._ipp._tcp.local`, where there is one.
fn service_type(name: &str) -> Option<&str> {
    let trimmed = name.trim_end_matches('.').trim_end_matches(".local");
    // `_services._dns-sd._udp` is the meta-query used to *enumerate* service
    // types. It is not a service anything offers, and reporting it would put
    // "_dns-sd._udp" in the list of what a device does.
    if trimmed.starts_with("_services.") {
        return None;
    }
    let at = trimmed.find("._")?;
    let service = &trimmed[at + 1..];
    // Two labels, `_ipp._tcp`, and nothing else.
    let mut parts = service.split('.');
    let (Some(a), Some(b), None) = (parts.next(), parts.next(), parts.next()) else {
        return None;
    };
    (a.starts_with('_') && (b == "_tcp" || b == "_udp")).then_some(service)
}

/// Identifies many devices, in parallel, cancellably.
///
/// Returns an identity per input address, in the same order, so the caller can
/// zip it against what the sweep found.
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
    #[derive(Default)]
    struct Fake {
        replies: BTreeMap<SocketAddr, Vec<u8>>,
        asked: Mutex<Vec<SocketAddr>>,
    }

    impl Ask for Fake {
        fn ask(&self, to: SocketAddr, _payload: &[u8], _t: Duration) -> io::Result<Vec<u8>> {
            self.asked.lock().unwrap().push(to);
            match self.replies.get(&to) {
                Some(r) => Ok(r.clone()),
                None => Err(io::Error::new(io::ErrorKind::TimedOut, "nothing answered")),
            }
        }
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
        assert!(
            !asked.iter().any(|a| a.port() == 53),
            "asked something: {asked:?}"
        );
        assert!(asked.iter().any(|a| a.port() == 5353));
        assert!(asked.iter().any(|a| a.port() == 137));
    }

    #[test]
    fn service_types_are_read_out_of_mdns_names() {
        assert_eq!(service_type("brother._ipp._tcp.local"), Some("_ipp._tcp"));
        assert_eq!(
            service_type("Living Room._googlecast._tcp.local."),
            Some("_googlecast._tcp")
        );
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
