//! Reading a scan's own results across rows.
//!
//! Every other phase looks at one device at a time, and there are things about
//! a network that no single row can say: two devices answering to one name, one
//! hardware address on two rows, a device that never got a lease, a datagram
//! from an address that belongs to some other network. Each of those is already
//! written down somewhere in a finished scan, and until this module existed
//! nothing ever compared two rows with each other.
//!
//! ## It is arithmetic, not a phase
//!
//! Nothing here opens a socket, asks for a privilege or takes a reading. It is
//! a pure function of a [`Sweep`], the identities beside it and the [`Survey`],
//! which is what makes every test below a table of constructed values and what
//! lets the interface call it on a finished scan as often as it likes.
//!
//! ## Every finding carries the reading that produced it
//!
//! `CLAUDE.md`'s rule for identification applies here word for word: a claim
//! about a device is stored beside the reason for it and shown. So a [`Finding`]
//! is an [`Anomaly`], the addresses it is about, and the evidence in words. What
//! is deliberately absent is a *score*: nothing here is rated, ranked by danger
//! or given a severity, because a number would be an opinion wearing the
//! clothes of a measurement.
//!
//! ## What is not built, and why
//!
//! **"Two hardware addresses claim one IP" is not here, and it must not be
//! added on the unprivileged path.** It reads as the strongest check of the
//! lot, and it cannot be taken honestly with the readings this engine has:
//! `SendARP` and the neighbour table each return exactly *one* answer for an
//! address, so an unprivileged version has to compare two reads taken seconds
//! apart and call the difference a conflict. A MAC that changed between two
//! reads is far more often a phone rotating a randomised address, a lease that
//! moved, or a cache entry that expired, than it is a second device claiming
//! the address. That is a false-positive generator wearing an alarming label,
//! and shipping one would cost more trust than the true positives buy.
//!
//! The real check needs to *see the answers* rather than ask for one: two ARP
//! replies for one address in the same window, which is the raw transport, so
//! it waits for the privileged engine along with the SYN scan and the passive
//! fingerprinting. The comparison this module does make, [`Anomaly::SharedMac`],
//! is the honest cousin: it compares rows *within one sweep*, where both
//! readings were taken at the same time by the same mechanism.
//!
//! DHCP pool bounds are not here either, and for a simpler reason: an offer
//! reveals the one address a server was willing to give this machine and says
//! nothing whatsoever about the range it came from. There is no honest version
//! of that check to write.

use crate::discover::{Evidence, Found, Sweep};
use crate::identify::{self, Identity, Source};
use crate::mac::MacAddr;
use crate::prefix::Prefix;
use crate::survey::{Reading, Survey};
use std::collections::BTreeMap;
use std::net::IpAddr;

/// How many addresses a sweep has to have probed before silence from all of
/// them says anything.
///
/// "Only the gateway answered" is an ordinary quiet moment on a /29 with three
/// devices on it, two of them asleep. On a prefix of any size it is a pattern.
/// Sixteen is the smallest sample this will draw a conclusion from, and the
/// conclusion is still worded as a likelihood.
const ENOUGH_PROBED: u64 = 16;

/// Something a scan's own results say when they are read across rows.
///
/// The order is the reading order and the order findings come back in: what is
/// about a pair of devices first, then what is about one device, then what is
/// about the link as a whole.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Anomaly {
    /// Two devices answer to one name.
    SharedName,
    /// One hardware address, two addresses on the list.
    SharedMac,
    /// The gateway's hardware address is on an ordinary host as well.
    GatewayMac,
    /// A device gave itself an address because nothing offered it one.
    NoLease,
    /// A device was heard from an address in none of this machine's prefixes.
    OffPrefix,
    /// The gateway answered and nothing else did.
    Isolated,
}

impl Anomaly {
    /// The heading, as the interface writes it.
    pub const fn label(self) -> &'static str {
        match self {
            Self::SharedName => "One name, two devices",
            Self::SharedMac => "One hardware address, two devices",
            Self::GatewayMac => "The gateway's hardware address is elsewhere too",
            Self::NoLease => "No address from DHCP",
            Self::OffPrefix => "Heard from outside this network",
            Self::Isolated => "This link probably isolates its clients",
        }
    }

    /// What it means, which is a sentence rather than a verdict.
    ///
    /// Each says the ordinary explanation as well as the interesting one,
    /// because on most networks the ordinary one is what is happening and a
    /// reader who is told only the alarming half learns to distrust the whole
    /// panel.
    pub const fn meaning(self) -> &'static str {
        match self {
            Self::SharedName => {
                "Two devices answer to the same name, so anything that reaches \
                 one of them by name reaches whichever answers first. It is \
                 usually a device that was replaced without the old one being \
                 taken off the network."
            }
            Self::SharedMac => {
                "One hardware address is on two rows. That is one device \
                 holding two addresses, which is ordinary on a router or a \
                 server, and it is also what one device answering in another's \
                 place looks like."
            }
            Self::GatewayMac => {
                "The gateway's hardware address answers for another address on \
                 this link as well. On most networks that is the router \
                 holding a second address; it is also the shape of a machine \
                 answering in the gateway's place."
            }
            Self::NoLease => {
                "A device that asks for an address and gets none gives itself \
                 one in 169.254.0.0/16. It is on the wire and it can reach \
                 nothing that is routed, so either no DHCP server answered it \
                 or it was refused one."
            }
            Self::OffPrefix => {
                "A datagram arrived from an address in none of this machine's \
                 own prefixes. It is usually a device still configured for the \
                 network it was on last, and it is what two networks sharing \
                 one link look like."
            }
            Self::Isolated => {
                "The gateway answered and nothing else on the link did. Guest, \
                 hotel and office networks are built this way deliberately, \
                 and it is good news: the devices on this link cannot reach \
                 each other, so neither can anything that gets onto it. It is \
                 stated as a likelihood because a link where every other \
                 device happens to be asleep looks the same from here."
            }
        }
    }
}

/// One thing the results say, and what said it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub about: Anomaly,
    /// The devices this is about, in address order. Never empty.
    pub addresses: Vec<IpAddr>,
    /// The readings behind it, in words fit to show. This is the half that
    /// keeps a finding from being an assertion.
    pub evidence: String,
}

/// Reads a finished scan across its own rows.
///
/// `names` is parallel to `sweep.found` by index, which is the invariant
/// [`crate::link::fold`] exists to hold, and it is taken here rather than
/// rebuilt because the duplicate-name check has to run **after** that merge:
/// [`crate::identify::subject`] attributes an mDNS reply to the device it is
/// *about* rather than to whichever address sent it, which is what stops a
/// dual-stacked device from being two rows and therefore from disputing its own
/// name. Run this against unmerged identities and the commonest finding on the
/// list would be one device arguing with itself.
///
/// Never fails, and says nothing where it cannot say anything: a survey that
/// could not read the interface list has no prefixes to compare an address
/// against, and a sweep that could not finish proves nothing by its silence.
pub fn find(sweep: &Sweep, names: &[Identity], survey: &Survey) -> Vec<Finding> {
    let mut out = Vec::new();
    shared_names(sweep, names, survey, &mut out);
    hardware_addresses(sweep, survey, &mut out);
    without_a_lease(sweep, &mut out);
    off_prefix(sweep, survey, &mut out);
    isolation(sweep, survey, &mut out);
    out.sort_by(|a, b| {
        a.about
            .cmp(&b.about)
            .then_with(|| a.addresses.cmp(&b.addresses))
    });
    out
}

/// The IPv4 prefixes this machine is actually on.
fn local_prefixes(survey: &Survey) -> Vec<Prefix> {
    let mut out = Vec::new();
    for prefix in survey
        .interfaces
        .iter()
        .filter(|i| i.is_scannable())
        .flat_map(crate::sysinfo::Interface::v4_prefixes)
    {
        if !out.contains(&prefix) {
            out.push(prefix);
        }
    }
    out
}

/// The hardware address on a row, where the scan learned one.
fn mac_of(sweep: &Sweep, address: IpAddr) -> Option<MacAddr> {
    sweep
        .found
        .iter()
        .find(|f| f.address == address)
        .and_then(|f| f.mac)
}

/// Why this device is on the list at all, in the words the row already uses.
fn how_it_got_here(found: &Found) -> String {
    found
        .evidence
        .first()
        .map_or_else(|| "is on the list".to_string(), Evidence::reason)
}

/// A list of things, joined the way a sentence joins them.
fn and_list(parts: &[String]) -> String {
    match parts {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// One name, and everybody claiming it.
struct Claim {
    /// The name as the device wrote it, for showing. The key it is filed under
    /// is [`identify::canonical`] of this.
    shown: String,
    by: Vec<(IpAddr, Source)>,
}

/// Two devices answering to one name.
///
/// **Only the names a device said about itself count**, which is why
/// [`Source::ReverseDns`] is not here: a `PTR` record proves that a resolver
/// wrote something down once, so two addresses carrying one `PTR` is a router's
/// stale memory rather than two devices in a dispute. That is the same reason
/// `link::Voice::spoke` keeps a reverse lookup from putting a row on the device
/// list at all.
fn shared_names(sweep: &Sweep, names: &[Identity], survey: &Survey, out: &mut Vec<Finding>) {
    let mut claims: BTreeMap<String, Claim> = BTreeMap::new();
    for (found, identity) in sweep.found.iter().zip(names) {
        // This machine's own addresses are all one device, and it is the one
        // device whose multi-homing is a fact rather than an inference: a
        // laptop on wifi and Ethernet at once answers to one name on both.
        if survey.owns(found.address) {
            continue;
        }
        for name in &identity.names {
            if !matches!(name.source, Source::Mdns | Source::NetBios) {
                continue;
            }
            let key = identify::canonical(&name.value);
            if key.is_empty() {
                continue;
            }
            let claim = claims.entry(key).or_insert_with(|| Claim {
                shown: name.value.clone(),
                by: Vec::new(),
            });
            if !claim.by.iter().any(|(a, _)| *a == found.address) {
                claim.by.push((found.address, name.source));
            }
        }
    }

    for claim in claims.values() {
        // Only the addresses that can be told apart from each other. See
        // `different_devices`.
        let mut real: Vec<(IpAddr, Source)> = Vec::new();
        for (i, one) in claim.by.iter().enumerate() {
            let disputed = claim
                .by
                .iter()
                .enumerate()
                .any(|(j, other)| i != j && different_devices(sweep, one.0, other.0));
            if disputed {
                real.push(*one);
            }
        }
        if real.len() < 2 {
            continue;
        }
        real.sort_by_key(|(address, _)| *address);
        let said: Vec<String> = real
            .iter()
            .map(|(address, source)| format!("{address} over {}", source.label()))
            .collect();
        out.push(Finding {
            about: Anomaly::SharedName,
            addresses: real.iter().map(|(address, _)| *address).collect(),
            evidence: format!("{} is claimed by {}", claim.shown, and_list(&said)),
        });
    }
}

/// Are these two rows provably two devices?
///
/// **The dual-stack test, and the reason this check has one at all.** One
/// device with an IPv4 address and an IPv6 one answers to the same name on
/// both, and reporting that as two devices in a name dispute would put a
/// finding against half the machines on a modern network.
///
/// So there are two ways to be sure, and silence otherwise:
///
/// * Two hardware addresses that differ. Two devices, whatever else is true.
/// * The same family. A device holding two addresses of one family is possible
///   and is worth reporting either way, because one of the two rows is then
///   answering for something.
///
/// Where the families differ and the hardware addresses are unknown, nothing is
/// claimed: this cannot be told from one device wearing both, and a blank is an
/// answer.
fn different_devices(sweep: &Sweep, one: IpAddr, other: IpAddr) -> bool {
    match (mac_of(sweep, one), mac_of(sweep, other)) {
        (Some(a), Some(b)) => a != b,
        _ => one.is_ipv4() == other.is_ipv4(),
    }
}

/// One hardware address on two rows, and the gateway's on somebody else's.
///
/// **IPv4 only, and that is the same dual-stack guard [`different_devices`]
/// applies.** A device with an address in each family has one hardware address
/// and two rows, which is one device and not a collision, and comparing across
/// families would report every dual-stacked machine on the network.
fn hardware_addresses(sweep: &Sweep, survey: &Survey, out: &mut Vec<Finding>) {
    let gateways: Vec<(IpAddr, MacAddr)> = survey
        .gateways
        .iter()
        .filter_map(|g| {
            let mac = mac_of(sweep, g.address).or_else(|| {
                survey
                    .known_devices()
                    .find(|n| n.address == g.address)
                    .map(|n| n.mac)
            })?;
            Some((g.address, mac))
        })
        .collect();

    let mut by_mac: BTreeMap<MacAddr, Vec<IpAddr>> = BTreeMap::new();
    for found in &sweep.found {
        let Some(mac) = found.mac else {
            continue;
        };
        // A group address is not a device, an all-zero one is an unresolved
        // entry, and this machine's own addresses are this machine's.
        if mac.is_zero() || mac.is_multicast() || survey.owns(found.address) {
            continue;
        }
        if !found.address.is_ipv4() {
            continue;
        }
        by_mac.entry(mac).or_default().push(found.address);
    }

    for (mac, addresses) in by_mac {
        match gateways.iter().find(|(_, m)| *m == mac) {
            Some((gateway, _)) => {
                let others: Vec<String> = addresses
                    .iter()
                    .filter(|a| *a != gateway)
                    .map(IpAddr::to_string)
                    .collect();
                if others.is_empty() {
                    continue;
                }
                let mut all = addresses.clone();
                if !all.contains(gateway) {
                    all.push(*gateway);
                }
                all.sort_unstable();
                out.push(Finding {
                    about: Anomaly::GatewayMac,
                    addresses: all,
                    evidence: format!(
                        "the gateway {gateway} answers with {mac}, and so does {}",
                        and_list(&others)
                    ),
                });
            }
            None => {
                if addresses.len() < 2 {
                    continue;
                }
                let shown: Vec<String> = addresses.iter().map(IpAddr::to_string).collect();
                out.push(Finding {
                    about: Anomaly::SharedMac,
                    addresses,
                    evidence: format!("{mac} answered for {}", and_list(&shown)),
                });
            }
        }
    }
}

/// A device that gave itself an address.
///
/// **IPv4 only, and the family is the whole of the check.** 169.254.0.0/16 is
/// what a client falls back to when no DHCP server answered it, so the address
/// is the evidence. IPv6's `fe80::/10` is nothing of the sort: a link-local
/// address is normal, permanent and present on every IPv6 interface ever
/// configured, and treating one as a failed lease would put this finding on
/// every device on the network.
fn without_a_lease(sweep: &Sweep, out: &mut Vec<Finding>) {
    for found in &sweep.found {
        let IpAddr::V4(v4) = found.address else {
            continue;
        };
        if !v4.is_link_local() {
            continue;
        }
        out.push(Finding {
            about: Anomaly::NoLease,
            addresses: vec![found.address],
            evidence: format!(
                "{v4} is in 169.254.0.0/16, and it {}",
                how_it_got_here(found)
            ),
        });
    }
}

/// A datagram from an address that belongs to another network.
///
/// This is the honest form of what gets loosely called a VLAN leak: something
/// spoke on this link wearing an address from a network this machine is not on.
/// Two conditions keep it from being noise.
///
/// * **It has to have been heard rather than probed.** The sweep only walks
///   addresses inside the prefix it was given, so an address outside every
///   prefix can only have arrived from the link phase or the listen, which is
///   the reading this finding is about.
/// * **There have to be prefixes to compare it against.** A survey that could
///   not read the interface list knows of no prefixes at all, and "outside
///   every prefix" would then be true of everything.
///
/// IPv6 is skipped rather than guessed at: a device holding a global address
/// from a prefix this machine did not configure is an ordinary state of a
/// dual-stacked link, and the check would fire on it.
fn off_prefix(sweep: &Sweep, survey: &Survey, out: &mut Vec<Finding>) {
    if !survey.has(Reading::Interfaces) {
        return;
    }
    let local = local_prefixes(survey);
    if local.is_empty() {
        return;
    }

    for found in &sweep.found {
        let IpAddr::V4(v4) = found.address else {
            continue;
        };
        // A device with no lease is its own finding, and it is outside every
        // prefix by definition. Saying it twice in different words would be
        // one reading wearing two hats.
        if v4.is_link_local() || survey.owns(found.address) {
            continue;
        }
        if !found
            .evidence
            .iter()
            .any(|e| matches!(e, Evidence::Announced(_)))
        {
            continue;
        }
        if local.iter().any(|p| p.contains(found.address)) {
            continue;
        }
        let prefixes: Vec<String> = local.iter().map(Prefix::to_string).collect();
        out.push(Finding {
            about: Anomaly::OffPrefix,
            addresses: vec![found.address],
            evidence: format!(
                "{v4} {}, and it is in none of this machine's prefixes: {}",
                how_it_got_here(found),
                and_list(&prefixes)
            ),
        });
    }
}

/// The gateway answered and nothing else did.
///
/// **The whole of this function is the guard, and the claim is three lines at
/// the end of it.** `CLAUDE.md`'s worst failure is an empty list presented as
/// an answer, and naming client isolation is the good version of that: it turns
/// "nothing found" into "nothing found, and here is the likely reason". It is
/// also the finding that would be most damaging to get wrong, because an engine
/// that could not send an ARP request finds exactly this and the honest answer
/// there is that Muster could not look.
///
/// So the sweep has to have finished, and it has to have finished *completely*:
/// [`Sweep::is_complete`] is false when it was cancelled and false when any
/// technique was missing, and both front ends fold the link phase's and the
/// listen's own gaps into the same list, so one question covers every phase
/// that could have gone quiet without saying so.
fn isolation(sweep: &Sweep, survey: &Survey, out: &mut Vec<Finding>) {
    // The engine could not look, or was told to stop looking. Either way its
    // silence is about Muster and not about the link.
    if !sweep.is_complete() {
        return;
    }
    // Nothing knows which address the gateway is, so nothing can say that it
    // was the only one that answered.
    if !survey.has(Reading::Routes) {
        return;
    }
    if sweep.probed < sweep.total || sweep.total < ENOUGH_PROBED {
        return;
    }

    let Some(gateway) = survey.gateways.iter().map(|g| g.address).find(|address| {
        sweep
            .found
            .iter()
            .any(|f| f.address == *address && f.was_probed())
    }) else {
        // A link where even the gateway said nothing is not an isolated link,
        // it is a link where the questions are not getting through.
        return;
    };

    let mut this_machine = false;
    for found in &sweep.found {
        if found.address == gateway {
            continue;
        }
        if survey.owns(found.address) {
            this_machine = true;
            continue;
        }
        // Anything else at all: a device that answered, a device that
        // announced itself, or one the neighbour table remembers. Any of the
        // three is a device this link let us reach, so it is not isolating.
        return;
    }

    let evidence = if this_machine {
        format!(
            "{} addresses were probed, and nothing answered but the gateway {gateway} and this machine",
            sweep.probed
        )
    } else {
        format!(
            "{} addresses were probed, and the gateway {gateway} was the only one that answered",
            sweep.probed
        )
    };
    out.push(Finding {
        about: Anomaly::Isolated,
        addresses: vec![gateway],
        evidence,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discover::Protocol;
    use crate::identify::Name;
    use crate::survey::Gateway;
    use crate::sysinfo::{IfAddr, IfFlags, Interface, LinkKind, Neighbour, NeighbourState};

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn prefix(text: &str) -> Prefix {
        text.parse().unwrap()
    }

    fn mac(text: &str) -> MacAddr {
        text.parse().unwrap()
    }

    /// A machine on `192.168.1.0/24` at `.42`, with the gateway at `.1`.
    fn here() -> Survey {
        let mut survey = Survey {
            interfaces: vec![Interface {
                name: "eth0".into(),
                friendly: "Ethernet".into(),
                index: 2,
                mac: Some(mac("3c:22:fb:00:11:22")),
                addresses: vec![IfAddr {
                    address: ip("192.168.1.42"),
                    prefix: prefix("192.168.1.0/24"),
                }],
                kind: LinkKind::Ethernet,
                flags: IfFlags {
                    up: true,
                    loopback: false,
                    point_to_point: false,
                },
                mtu: 1500,
                dns: Vec::new(),
                dhcp_server: None,
            }],
            ..Default::default()
        };
        survey.gateways.push(Gateway {
            address: ip("192.168.1.1"),
            interface_index: 2,
            metric: 10,
        });
        survey
    }

    /// A row that answered a probe, with a hardware address where one is given.
    fn probed(address: &str, hw: Option<&str>) -> Found {
        Found {
            address: ip(address),
            mac: hw.map(mac),
            mac_said: None,
            evidence: vec![Evidence::Ping],
            rtt: None,
            ttl: None,
        }
    }

    /// A row that arrived because something was overheard from it.
    fn announced(address: &str) -> Found {
        Found::announced(ip(address), Protocol::Mdns)
    }

    fn named(value: &str, source: Source) -> Identity {
        Identity {
            names: vec![Name {
                value: value.into(),
                source,
            }],
            ..Default::default()
        }
    }

    /// A finished sweep of a /24 holding these rows and these identities.
    fn swept(rows: Vec<(Found, Identity)>) -> (Sweep, Vec<Identity>) {
        let mut sweep = Sweep {
            probed: 254,
            total: 254,
            ..Default::default()
        };
        let mut names = Vec::new();
        for (found, identity) in rows {
            sweep.found.push(found);
            names.push(identity);
        }
        sweep.found.sort_by_key(|f| f.address);
        (sweep, names)
    }

    fn about(findings: &[Finding], what: Anomaly) -> Vec<&Finding> {
        findings.iter().filter(|f| f.about == what).collect()
    }

    /// Two devices, two hardware addresses, one name. The plain positive.
    #[test]
    fn two_devices_answering_to_one_name_are_reported() {
        let (sweep, names) = swept(vec![
            (
                probed("192.168.1.5", Some("3c:22:fb:aa:bb:cc")),
                named("nas.local", Source::Mdns),
            ),
            (
                probed("192.168.1.9", Some("3c:22:fb:dd:ee:ff")),
                named("NAS", Source::NetBios),
            ),
        ]);
        let found = find(&sweep, &names, &here());
        let shared = about(&found, Anomaly::SharedName);
        assert_eq!(shared.len(), 1, "one name, reported once");
        assert_eq!(
            shared[0].addresses,
            vec![ip("192.168.1.5"), ip("192.168.1.9")]
        );
        assert!(
            shared[0].evidence.contains("over mDNS") && shared[0].evidence.contains("over NetBIOS"),
            "and it says who said what: {}",
            shared[0].evidence
        );
    }

    /// **The false positive this check is most likely to produce.** One device
    /// with an address in each family answers to one name on both. It has one
    /// hardware address, and it is one device.
    #[test]
    fn a_dual_stacked_device_does_not_dispute_its_own_name() {
        let (sweep, names) = swept(vec![
            (
                probed("192.168.1.5", Some("3c:22:fb:aa:bb:cc")),
                named("nas.local", Source::Mdns),
            ),
            (
                probed("fe80::1", Some("3c:22:fb:aa:bb:cc")),
                named("nas.local", Source::Mdns),
            ),
        ]);
        let found = find(&sweep, &names, &here());
        assert!(
            about(&found, Anomaly::SharedName).is_empty(),
            "one hardware address is one device: {found:?}"
        );
        assert!(
            about(&found, Anomaly::SharedMac).is_empty(),
            "and the same reading is not a collision either"
        );
    }

    /// The same device across two families with no hardware address known.
    /// Nothing can tell this from two devices, so nothing is claimed.
    #[test]
    fn two_families_with_no_hardware_address_say_nothing() {
        let (sweep, names) = swept(vec![
            (
                probed("192.168.1.5", None),
                named("nas.local", Source::Mdns),
            ),
            (probed("fe80::1", None), named("nas.local", Source::Mdns)),
        ]);
        let found = find(&sweep, &names, &here());
        assert!(about(&found, Anomaly::SharedName).is_empty(), "{found:?}");
    }

    /// A `PTR` proves that a router wrote something down, not that a device
    /// said anything. Two addresses under one stale record are not a dispute.
    #[test]
    fn a_name_out_of_the_resolver_is_never_a_dispute() {
        let (sweep, names) = swept(vec![
            (
                probed("192.168.1.5", Some("3c:22:fb:aa:bb:cc")),
                named("old-host", Source::ReverseDns),
            ),
            (
                probed("192.168.1.9", Some("3c:22:fb:dd:ee:ff")),
                named("old-host", Source::ReverseDns),
            ),
        ]);
        let found = find(&sweep, &names, &here());
        assert!(about(&found, Anomaly::SharedName).is_empty(), "{found:?}");
    }

    /// The suffixes are normalised the way one row's own name comparison
    /// normalises them, so `TRUENAS` and `truenas.local` are one name here as
    /// well as there.
    #[test]
    fn the_local_suffix_and_the_case_are_not_two_names() {
        let (sweep, names) = swept(vec![
            (
                probed("192.168.1.5", Some("3c:22:fb:aa:bb:cc")),
                named("truenas.local", Source::Mdns),
            ),
            (
                probed("192.168.1.9", Some("3c:22:fb:dd:ee:ff")),
                named("TRUENAS", Source::NetBios),
            ),
        ]);
        let found = find(&sweep, &names, &here());
        assert_eq!(about(&found, Anomaly::SharedName).len(), 1);
    }

    /// One hardware address on two IPv4 rows.
    #[test]
    fn one_hardware_address_on_two_rows_is_reported() {
        let (sweep, names) = swept(vec![
            (
                probed("192.168.1.5", Some("3c:22:fb:aa:bb:cc")),
                Identity::default(),
            ),
            (
                probed("192.168.1.77", Some("3c:22:fb:aa:bb:cc")),
                Identity::default(),
            ),
        ]);
        let found = find(&sweep, &names, &here());
        let shared = about(&found, Anomaly::SharedMac);
        assert_eq!(shared.len(), 1);
        assert_eq!(
            shared[0].addresses,
            vec![ip("192.168.1.5"), ip("192.168.1.77")]
        );
        assert!(shared[0].evidence.contains("3c:22:fb:aa:bb:cc"));
    }

    /// The gateway's hardware address on an ordinary host is its own finding,
    /// and it is not also reported as a plain collision.
    #[test]
    fn the_gateways_hardware_address_elsewhere_is_its_own_finding() {
        let (sweep, names) = swept(vec![
            (
                probed("192.168.1.1", Some("3c:22:fb:11:11:11")),
                Identity::default(),
            ),
            (
                probed("192.168.1.77", Some("3c:22:fb:11:11:11")),
                Identity::default(),
            ),
        ]);
        let found = find(&sweep, &names, &here());
        assert!(about(&found, Anomaly::SharedMac).is_empty(), "not twice");
        let gateway = about(&found, Anomaly::GatewayMac);
        assert_eq!(gateway.len(), 1);
        assert_eq!(
            gateway[0].addresses,
            vec![ip("192.168.1.1"), ip("192.168.1.77")]
        );
        assert!(gateway[0].evidence.contains("192.168.1.77"));
    }

    /// The gateway's hardware address is read from the neighbour table where
    /// the sweep has no row for it, which is the ordinary case on a link the
    /// gateway does not answer probes on.
    #[test]
    fn the_gateways_hardware_address_can_come_from_the_neighbour_table() {
        let mut survey = here();
        survey.neighbours.push(Neighbour {
            address: ip("192.168.1.1"),
            mac: mac("3c:22:fb:11:11:11"),
            interface_index: 2,
            state: NeighbourState::Reachable,
        });
        let (sweep, names) = swept(vec![(
            probed("192.168.1.77", Some("3c:22:fb:11:11:11")),
            Identity::default(),
        )]);
        let found = find(&sweep, &names, &survey);
        assert_eq!(about(&found, Anomaly::GatewayMac).len(), 1, "{found:?}");
    }

    /// A device that gave itself an address, and the IPv6 link-local address
    /// beside it that is nothing of the kind.
    #[test]
    fn a_link_local_address_is_a_lease_that_never_arrived() {
        let (sweep, names) = swept(vec![
            (announced("169.254.10.4"), Identity::default()),
            (
                probed("fe80::abcd", Some("3c:22:fb:aa:bb:cc")),
                Identity::default(),
            ),
        ]);
        let found = find(&sweep, &names, &here());
        let lease = about(&found, Anomaly::NoLease);
        assert_eq!(lease.len(), 1, "the IPv6 one is normal: {found:?}");
        assert_eq!(lease[0].addresses, vec![ip("169.254.10.4")]);
        assert!(
            lease[0].evidence.contains("announced itself over mDNS"),
            "and it carries the reading that put it on the list: {}",
            lease[0].evidence
        );
    }

    /// Heard from an address on another network. The row has to have been
    /// heard rather than probed, and 169.254 is left to its own finding.
    #[test]
    fn an_address_from_another_network_is_reported_once() {
        let (sweep, names) = swept(vec![
            (announced("10.9.0.7"), Identity::default()),
            (announced("169.254.10.4"), Identity::default()),
            (probed("192.168.1.5", None), Identity::default()),
        ]);
        let found = find(&sweep, &names, &here());
        let off = about(&found, Anomaly::OffPrefix);
        assert_eq!(off.len(), 1, "{found:?}");
        assert_eq!(off[0].addresses, vec![ip("10.9.0.7")]);
        assert!(
            off[0].evidence.contains("192.168.1.0/24"),
            "and it names what it is outside of: {}",
            off[0].evidence
        );
    }

    /// A survey that could not read the interfaces knows of no prefixes, and
    /// "outside every prefix" would then be true of every address there is.
    #[test]
    fn nothing_is_outside_a_prefix_list_that_was_never_read() {
        let (sweep, names) = swept(vec![(announced("10.9.0.7"), Identity::default())]);
        let blind = Survey::default();
        let found = find(&sweep, &names, &blind);
        assert!(about(&found, Anomaly::OffPrefix).is_empty(), "{found:?}");
    }

    /// The gateway answered, this machine is on its own list, and nothing else
    /// said anything. The good news, worded as a likelihood.
    #[test]
    fn a_link_where_only_the_gateway_answers_is_named() {
        let (sweep, names) = swept(vec![
            (
                probed("192.168.1.1", Some("3c:22:fb:11:11:11")),
                Identity::default(),
            ),
            (
                probed("192.168.1.42", Some("3c:22:fb:00:11:22")),
                Identity::default(),
            ),
        ]);
        let found = find(&sweep, &names, &here());
        let isolated = about(&found, Anomaly::Isolated);
        assert_eq!(isolated.len(), 1, "{found:?}");
        assert_eq!(isolated[0].addresses, vec![ip("192.168.1.1")]);
        assert!(
            isolated[0].evidence.contains("this machine"),
            "and it says what did answer: {}",
            isolated[0].evidence
        );
        assert!(
            isolated[0].about.meaning().contains("likelihood"),
            "and it is stated as one"
        );
    }

    /// **The failure this check must never produce.** A sweep that could not
    /// send an ARP request finds the same short list, and the honest answer
    /// there is that Muster could not look.
    #[test]
    fn a_sweep_that_could_not_look_never_concludes_isolation() {
        let (mut sweep, names) = swept(vec![(
            probed("192.168.1.1", Some("3c:22:fb:11:11:11")),
            Identity::default(),
        )]);
        sweep.not_done.push("could not send ARP requests".into());
        assert!(
            about(&find(&sweep, &names, &here()), Anomaly::Isolated).is_empty(),
            "a gap in the sweep is not a fact about the link"
        );

        let (mut sweep, names) = swept(vec![(
            probed("192.168.1.1", Some("3c:22:fb:11:11:11")),
            Identity::default(),
        )]);
        sweep.cancelled = true;
        assert!(
            about(&find(&sweep, &names, &here()), Anomaly::Isolated).is_empty(),
            "and neither is being stopped halfway"
        );
    }

    /// One other device on the list is the whole of the counter-evidence,
    /// including one that only announced itself.
    #[test]
    fn one_other_device_is_enough_to_say_nothing() {
        for other in [
            probed("192.168.1.5", None),
            announced("192.168.1.5"),
            Found::neighbour(ip("192.168.1.5"), mac("3c:22:fb:aa:bb:cc")),
        ] {
            let (sweep, names) = swept(vec![
                (
                    probed("192.168.1.1", Some("3c:22:fb:11:11:11")),
                    Identity::default(),
                ),
                (other.clone(), Identity::default()),
            ]);
            let found = find(&sweep, &names, &here());
            assert!(
                about(&found, Anomaly::Isolated).is_empty(),
                "{:?} is a device this link let us reach",
                other.address
            );
        }
    }

    /// A gateway that answered nothing is a link nothing is getting through,
    /// which is a different thing from a link that isolates its clients.
    #[test]
    fn a_silent_gateway_is_not_an_isolated_link() {
        let (sweep, names) = swept(Vec::new());
        assert!(about(&find(&sweep, &names, &here()), Anomaly::Isolated).is_empty());
    }

    /// Silence from a handful of addresses is an ordinary quiet moment.
    #[test]
    fn a_tiny_prefix_proves_nothing() {
        let (mut sweep, names) = swept(vec![(
            probed("192.168.1.1", Some("3c:22:fb:11:11:11")),
            Identity::default(),
        )]);
        sweep.probed = 6;
        sweep.total = 6;
        assert!(about(&find(&sweep, &names, &here()), Anomaly::Isolated).is_empty());
    }

    /// A clean scan of an ordinary network says nothing at all, which is the
    /// state this module is in on most networks and has to be quiet in.
    #[test]
    fn an_ordinary_network_produces_no_findings() {
        let (sweep, names) = swept(vec![
            (
                probed("192.168.1.1", Some("3c:22:fb:11:11:11")),
                named("router.local", Source::Mdns),
            ),
            (
                probed("192.168.1.5", Some("3c:22:fb:aa:bb:cc")),
                named("nas.local", Source::Mdns),
            ),
            (
                probed("192.168.1.42", Some("3c:22:fb:00:11:22")),
                named("desk", Source::NetBios),
            ),
        ]);
        assert_eq!(find(&sweep, &names, &here()), Vec::new());
    }

    /// Findings come back in a stated order, so a panel does not reshuffle
    /// itself between two readings of the same scan.
    #[test]
    fn findings_come_back_in_the_reading_order() {
        let (sweep, names) = swept(vec![
            (announced("169.254.10.4"), Identity::default()),
            (
                probed("192.168.1.5", Some("3c:22:fb:aa:bb:cc")),
                named("nas.local", Source::Mdns),
            ),
            (
                probed("192.168.1.9", Some("3c:22:fb:dd:ee:ff")),
                named("nas.local", Source::Mdns),
            ),
        ]);
        let found = find(&sweep, &names, &here());
        let order: Vec<Anomaly> = found.iter().map(|f| f.about).collect();
        assert_eq!(order, vec![Anomaly::SharedName, Anomaly::NoLease]);
        assert!(found.iter().all(|f| !f.evidence.is_empty()));
        assert!(found.iter().all(|f| !f.addresses.is_empty()));
    }
}
