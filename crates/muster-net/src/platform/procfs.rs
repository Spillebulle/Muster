//! Parsing the text Linux publishes about its network, as pure functions.
//!
//! **This module is compiled on every platform, deliberately.** The functions
//! take `&str` and return values; nothing here opens a file. That is what lets
//! the Linux answers be tested on a Windows machine, which `CLAUDE.md` names as
//! the only way they get tested at all — the alternative is a `cfg(unix)` block
//! whose tests never run for whoever is doing the work.
//!
//! The formats are older than most of the tooling that reads them and each has
//! a trap:
//!
//! * **`/proc/net/route` is little-endian hex**, so `0101A8C0` is `192.168.1.1`
//!   and reading it big-endian gives a plausible, wrong address on the same
//!   network. The mask is a mask rather than a length.
//! * **`/proc/net/arp` reports incomplete entries** with an all-zero hardware
//!   address and flags `0x0`. Those are probes nothing answered, and counting
//!   them is how a sweep invents hosts.
//! * **`/proc/net/ipv6_route` has no header line** and its addresses are
//!   unpunctuated hex, in network order — the opposite convention to the v4
//!   file in the same directory.

use crate::mac::MacAddr;
use crate::prefix::Prefix;
use crate::sysinfo::{Neighbour, NeighbourState, Route};
use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// `RTF_UP`, and the flag that says an entry carries a gateway.
const RTF_UP: u32 = 0x0001;
const RTF_GATEWAY: u32 = 0x0002;

/// Parses `/proc/net/route`, returning routes and the interface *name* each
/// belongs to.
///
/// The name rather than the index because this file names interfaces and the
/// index has to be looked up separately; resolving it here would mean this
/// function knowing how to read `/sys`, which is exactly the dependency the
/// module is written to avoid.
pub fn routes_v4(text: &str) -> Vec<(String, Route)> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 11 {
            continue;
        }
        let (Ok(dest), Ok(gw), Ok(flags), Ok(metric), Ok(mask)) = (
            u32::from_str_radix(f[1], 16),
            u32::from_str_radix(f[2], 16),
            u32::from_str_radix(f[3], 16),
            f[6].parse::<u32>(),
            u32::from_str_radix(f[7], 16),
        ) else {
            continue;
        };
        if flags & RTF_UP == 0 {
            continue;
        }

        // Little-endian: the low byte of the word is the first octet.
        let destination = Ipv4Addr::from(dest.to_le_bytes());
        let Ok(prefix) = Prefix::new(IpAddr::V4(destination), mask_len_v4(mask)) else {
            continue;
        };
        let gateway = (flags & RTF_GATEWAY != 0 && gw != 0)
            .then(|| IpAddr::V4(Ipv4Addr::from(gw.to_le_bytes())));

        out.push((
            f[0].to_string(),
            Route {
                destination: prefix,
                gateway,
                interface_index: 0,
                metric,
            },
        ));
    }
    out
}

/// A contiguous netmask as a prefix length. A mask with holes in it is not a
/// thing the kernel emits, and `count_ones` is the reading that survives one if
/// it ever does.
fn mask_len_v4(mask: u32) -> u8 {
    u32::from_le(mask.to_be()).count_ones() as u8
}

/// Parses `/proc/net/ipv6_route`. No header line, and every address is 32 hex
/// digits in network order.
pub fn routes_v6(text: &str) -> Vec<(String, Route)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let (Some(destination), Ok(len), Some(next_hop), Ok(metric)) = (
            hex_v6(f[0]),
            u8::from_str_radix(f[1], 16),
            hex_v6(f[4]),
            u32::from_str_radix(f[5], 16),
        ) else {
            continue;
        };
        let Ok(prefix) = Prefix::new(IpAddr::V6(destination), len) else {
            continue;
        };
        let gateway = (!next_hop.is_unspecified()).then_some(IpAddr::V6(next_hop));
        out.push((
            f[9].to_string(),
            Route {
                destination: prefix,
                gateway,
                interface_index: 0,
                metric,
            },
        ));
    }
    out
}

fn hex_v6(s: &str) -> Option<Ipv6Addr> {
    if s.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(Ipv6Addr::from(bytes))
}

/// `/proc/net/arp`. IPv4 only — the kernel publishes no v6 equivalent, and the
/// neighbour table for that family comes through netlink.
pub fn neighbours_v4(text: &str) -> Vec<(String, Neighbour)> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 6 {
            continue;
        }
        let (Ok(address), Ok(flags), Ok(mac)) = (
            f[0].parse::<Ipv4Addr>(),
            u32::from_str_radix(f[2].trim_start_matches("0x"), 16),
            f[3].parse::<MacAddr>(),
        ) else {
            continue;
        };

        // ATF_COM (0x02) is a completed entry; ATF_PERM (0x04) is a static one.
        // Flags of zero with an all-zero address is a probe that went
        // unanswered, and it is not a device.
        let state = if flags & 0x04 != 0 {
            NeighbourState::Static
        } else if flags & 0x02 != 0 {
            NeighbourState::Reachable
        } else {
            NeighbourState::Incomplete
        };

        out.push((
            f[5].to_string(),
            Neighbour {
                address: IpAddr::V4(address),
                mac,
                interface_index: 0,
                state,
            },
        ));
    }
    out
}

/// How long a snapshot of the neighbour table is worth reusing.
///
/// The sweep polls for a provoked entry every five milliseconds, so a snapshot
/// that lasts that long is one read per poll for the whole prefix instead of
/// one per address.
pub const ARP_SNAPSHOT_TTL: Duration = Duration::from_millis(5);

/// One shared, short-lived reading of the kernel's neighbour table.
///
/// **This exists because the obvious implementation is quadratic.** The
/// unprivileged Linux ARP provokes the kernel into resolving an address and
/// then waits for the answer to appear in `/proc/net/arp`; written per address
/// that is a whole-file read and a whole-table parse every five milliseconds,
/// per address, per worker. With 256 workers and a 300 ms budget a mostly empty
/// /24 issued on the order of fifteen thousand reads of the same file, some
/// fifty thousand a second, and the cost grew with the square of the address
/// count. All 256 workers want the identical file at the identical moment, so
/// they take one copy of it.
///
/// The clock and the reader are both arguments, which is what lets this be
/// tested on a machine with no `/proc` at all — the same rule the rest of this
/// module follows.
#[derive(Debug)]
pub struct ArpSnapshot {
    ttl: Duration,
    held: RwLock<Held>,
}

#[derive(Debug, Default)]
struct Held {
    /// When the text was read. `None` before the first read.
    taken: Option<Instant>,
    /// Only the entries that are evidence: an incomplete entry is the record
    /// of a question nobody answered, and a zero address is not a device.
    entries: BTreeMap<Ipv4Addr, MacAddr>,
}

impl ArpSnapshot {
    pub const fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            held: RwLock::new(Held {
                taken: None,
                entries: BTreeMap::new(),
            }),
        }
    }

    /// Looks one address up, re-reading the table first where the snapshot has
    /// expired.
    ///
    /// `read` is called at most once per TTL however many callers arrive: the
    /// refresh happens under the write lock, and a caller that waited for it
    /// re-checks the age rather than reading again. Serialising the workers on
    /// one read is the point, not a cost.
    pub fn lookup<R>(&self, addr: Ipv4Addr, now: Instant, read: R) -> io::Result<Option<MacAddr>>
    where
        R: FnOnce() -> io::Result<String>,
    {
        {
            let held = self.held.read().unwrap_or_else(|e| e.into_inner());
            if held.fresh_at(now, self.ttl) {
                return Ok(held.entries.get(&addr).copied());
            }
        }

        let mut held = self.held.write().unwrap_or_else(|e| e.into_inner());
        // Another worker may have refreshed it while this one waited for the
        // lock, which is the ordinary case with 256 of them.
        if held.fresh_at(now, self.ttl) {
            return Ok(held.entries.get(&addr).copied());
        }

        let text = read()?;
        held.entries = neighbours_v4(&text)
            .into_iter()
            .filter_map(|(_, n)| match n.address {
                IpAddr::V4(a) if n.state != NeighbourState::Incomplete && !n.mac.is_zero() => {
                    Some((a, n.mac))
                }
                _ => None,
            })
            .collect();
        held.taken = Some(now);
        Ok(held.entries.get(&addr).copied())
    }
}

impl Held {
    fn fresh_at(&self, now: Instant, ttl: Duration) -> bool {
        self.taken
            .is_some_and(|taken| now.saturating_duration_since(taken) < ttl)
    }
}

/// `/etc/resolv.conf`, or what `resolvectl` writes into it.
///
/// `127.0.0.53` is kept rather than filtered: it is `systemd-resolved`, it is
/// genuinely the resolver the machine uses, and hiding it would make the DNS
/// row disagree with what the rest of the system reports.
pub fn resolvers(text: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let Some(rest) = line.strip_prefix("nameserver") else {
            continue;
        };
        // The scope suffix on a link-local resolver is not part of the address.
        let word = rest.split_whitespace().next().unwrap_or("");
        let word = word.split('%').next().unwrap_or(word);
        if let Ok(addr) = word.parse::<IpAddr>()
            && !out.contains(&addr)
        {
            out.push(addr);
        }
    }
    out
}

/// The DHCP server from a `systemd-networkd` lease file
/// (`/run/systemd/netif/leases/<ifindex>`), which is a plain `KEY=value` list
/// readable without privileges.
pub fn lease_server(text: &str) -> Option<IpAddr> {
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("SERVER_ADDRESS="))
        .find_map(|v| v.trim().parse().ok())
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// The table as the kernel writes it: one answered entry, one entry that is
    /// only the record of an unanswered question.
    const ARP_TABLE: &str = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         3c:22:fb:aa:bb:cc     *        wlan0
192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        wlan0
";

    fn at(base: Instant, millis: u64) -> Instant {
        base + Duration::from_millis(millis)
    }

    /// The reading itself, unchanged by the caching: an answered entry is a
    /// hardware address and an incomplete one is not a device.
    #[test]
    fn the_snapshot_answers_exactly_what_a_fresh_read_would() {
        let snap = ArpSnapshot::new(ARP_SNAPSHOT_TTL);
        let now = Instant::now();
        let read = || Ok(ARP_TABLE.to_string());

        assert_eq!(
            snap.lookup("192.168.1.1".parse().unwrap(), now, read)
                .unwrap(),
            Some("3c:22:fb:aa:bb:cc".parse().unwrap())
        );
        assert_eq!(
            snap.lookup("192.168.1.9".parse().unwrap(), now, read)
                .unwrap(),
            None,
            "an entry nothing answered is not a device"
        );
        assert_eq!(
            snap.lookup("192.168.1.55".parse().unwrap(), now, read)
                .unwrap(),
            None
        );
    }

    /// The defect this type exists for. Every address in a /24 asking at the
    /// same moment reads the file once, not 254 times.
    #[test]
    fn a_whole_prefix_asking_at_once_reads_the_table_once() {
        let snap = ArpSnapshot::new(ARP_SNAPSHOT_TTL);
        let reads = AtomicU64::new(0);
        let now = Instant::now();

        for i in 1..=254u8 {
            let addr = Ipv4Addr::new(192, 168, 1, i);
            snap.lookup(addr, now, || {
                reads.fetch_add(1, Ordering::SeqCst);
                Ok(ARP_TABLE.to_string())
            })
            .unwrap();
        }
        assert_eq!(reads.load(Ordering::SeqCst), 1);
    }

    /// And it is still a *snapshot*: past the TTL the next caller re-reads, so
    /// an address that has only just answered is found.
    #[test]
    fn an_expired_snapshot_is_read_again() {
        let snap = ArpSnapshot::new(Duration::from_millis(5));
        let base = Instant::now();
        let addr: Ipv4Addr = "192.168.1.1".parse().unwrap();

        assert_eq!(snap.lookup(addr, base, || Ok(String::new())).unwrap(), None);
        // Inside the window the empty reading stands, whatever the file says.
        assert_eq!(
            snap.lookup(addr, at(base, 4), || Ok(ARP_TABLE.to_string()))
                .unwrap(),
            None
        );
        // Past it, the answer arrives.
        assert_eq!(
            snap.lookup(addr, at(base, 5), || Ok(ARP_TABLE.to_string()))
                .unwrap(),
            Some("3c:22:fb:aa:bb:cc".parse().unwrap())
        );
    }

    /// A read that failed is an error rather than an empty table. Caching the
    /// failure would turn one unreadable moment into a prefix of addresses that
    /// look settled, which is the rule `CLAUDE.md` is built on.
    #[test]
    fn a_failed_read_is_not_cached_as_an_empty_table() {
        let snap = ArpSnapshot::new(ARP_SNAPSHOT_TTL);
        let now = Instant::now();
        let addr: Ipv4Addr = "192.168.1.1".parse().unwrap();

        let e = snap
            .lookup(addr, now, || Err(io::Error::other("no /proc here")))
            .expect_err("the failure is reported");
        assert_eq!(e.to_string(), "no /proc here");

        assert_eq!(
            snap.lookup(addr, now, || Ok(ARP_TABLE.to_string()))
                .unwrap(),
            Some("3c:22:fb:aa:bb:cc".parse().unwrap()),
            "and the next caller reads for itself"
        );
    }

    /// Every worker in a sweep shares one snapshot, so the concurrent case is
    /// the normal case.
    #[test]
    fn workers_sharing_a_snapshot_still_get_the_right_answer() {
        let snap = ArpSnapshot::new(Duration::from_secs(3600));
        let reads = AtomicU64::new(0);
        let now = Instant::now();

        std::thread::scope(|scope| {
            for _ in 0..16 {
                scope.spawn(|| {
                    for i in 1..=64u8 {
                        let got = snap
                            .lookup(Ipv4Addr::new(192, 168, 1, i), now, || {
                                reads.fetch_add(1, Ordering::SeqCst);
                                Ok(ARP_TABLE.to_string())
                            })
                            .unwrap();
                        assert_eq!(got.is_some(), i == 1);
                    }
                });
            }
        });
        assert_eq!(reads.load(Ordering::SeqCst), 1, "one read, sixteen threads");
    }

    /// The reader is called at most once per window even when the caller keeps
    /// asking, which is what the sweep's five millisecond poll relies on.
    #[test]
    fn the_reader_runs_once_per_window_however_often_it_is_asked() {
        let snap = ArpSnapshot::new(Duration::from_millis(5));
        let base = Instant::now();
        let reads = Cell::new(0u32);
        let addr: Ipv4Addr = "192.168.1.1".parse().unwrap();

        for step in 0..20u64 {
            let _ = snap.lookup(addr, at(base, step), || {
                reads.set(reads.get() + 1);
                Ok(ARP_TABLE.to_string())
            });
        }
        assert_eq!(reads.get(), 4, "twenty milliseconds is four windows");
    }

    use super::*;

    /// A laptop on a home network, wired and with a VPN up. Real output shape,
    /// tabs and all.
    const ROUTE: &str = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
tun0\t00000000\t0100080A\t0003\t0\t0\t50\t00000000\t0\t0\t0
eth0\t0000FEA9\t00000000\t0001\t0\t0\t1000\t0000FFFF\t0\t0\t0
";

    /// The trap: little-endian hex. `0101A8C0` is 192.168.1.1, and read the
    /// other way round it is 192.168.1.1's neighbour — plausible and wrong.
    #[test]
    fn route_addresses_are_little_endian() {
        let routes = routes_v4(ROUTE);
        let (iface, default) = &routes[0];
        assert_eq!(iface, "eth0");
        assert!(default.is_default());
        assert_eq!(
            default.gateway,
            Some("192.168.1.1".parse::<IpAddr>().unwrap())
        );
        assert_eq!(default.metric, 100);
    }

    #[test]
    fn masks_become_prefix_lengths() {
        let routes = routes_v4(ROUTE);
        assert_eq!(routes[1].1.destination.to_string(), "192.168.1.0/24");
        assert_eq!(routes[1].1.gateway, None, "an on-link route has no gateway");
        assert_eq!(routes[3].1.destination.to_string(), "169.254.0.0/16");
    }

    #[test]
    fn both_default_routes_survive_for_the_survey_to_choose_between() {
        let routes = routes_v4(ROUTE);
        let defaults: Vec<_> = routes.iter().filter(|(_, r)| r.is_default()).collect();
        assert_eq!(defaults.len(), 2);
        assert_eq!(defaults[1].0, "tun0");
        assert_eq!(
            defaults[1].1.metric, 50,
            "the VPN's better metric is preserved"
        );
    }

    #[test]
    fn a_route_that_is_not_up_is_skipped() {
        let down =
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth0\t0001A8C0\t00000000\t0000\t0\t0\t100\t00FFFFFF\t0\t0\t0
";
        assert!(routes_v4(down).is_empty());
    }

    #[test]
    fn rubbish_lines_are_skipped_rather_than_panicking() {
        assert!(routes_v4("Iface Destination\nnonsense\n\n").is_empty());
        assert!(routes_v6("nonsense\n").is_empty());
        assert!(neighbours_v4("IP address\ngarbage here\n").is_empty());
    }

    const IPV6_ROUTE: &str = "\
fe800000000000000000000000000000 40 00000000000000000000000000000000 00 \
00000000000000000000000000000000 00000100 00000000 00000000 00000001 eth0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 \
fe800000000000000000000000000001 00000400 00000000 00000000 00000003 eth0
";

    #[test]
    fn ipv6_routes_read_the_unpunctuated_form() {
        let routes = routes_v6(IPV6_ROUTE);
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].1.destination.to_string(), "fe80::/64");
        assert_eq!(routes[0].1.gateway, None);

        assert!(routes[1].1.is_default());
        assert_eq!(
            routes[1].1.gateway,
            Some("fe80::1".parse::<IpAddr>().unwrap())
        );
        assert_eq!(routes[1].1.metric, 0x400);
    }

    const ARP: &str = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         3c:22:fb:aa:bb:cc     *        eth0
192.168.1.50     0x1         0x0         00:00:00:00:00:00     *        eth0
192.168.1.60     0x1         0x6         aa:bb:cc:dd:ee:ff     *        eth0
";

    /// The rule: flags of zero is a probe nothing answered.
    #[test]
    fn incomplete_arp_entries_are_not_devices() {
        let found = neighbours_v4(ARP);
        assert_eq!(found.len(), 3, "all three are parsed");

        let evidence: Vec<_> = found
            .iter()
            .filter(|(_, n)| n.state.is_evidence())
            .map(|(_, n)| n.address.to_string())
            .collect();
        assert_eq!(evidence, ["192.168.1.1", "192.168.1.60"]);

        assert_eq!(found[1].1.state, NeighbourState::Incomplete);
        assert!(found[1].1.mac.is_zero());
        assert_eq!(found[2].1.state, NeighbourState::Static, "ATF_PERM");
        assert_eq!(found[0].0, "eth0");
    }

    #[test]
    fn resolvers_ignore_comments_options_and_scopes() {
        let text = "\
# Generated by NetworkManager
nameserver 192.168.1.1
nameserver 1.1.1.1  # the fallback
options edns0 trust-ad
search lan
nameserver fe80::1%eth0
nameserver 192.168.1.1
nameserver not-an-address
";
        assert_eq!(
            resolvers(text),
            vec![
                "192.168.1.1".parse::<IpAddr>().unwrap(),
                "1.1.1.1".parse().unwrap(),
                "fe80::1".parse().unwrap(),
            ]
        );
    }

    /// `systemd-resolved` is the machine's resolver and is reported as such.
    #[test]
    fn the_stub_resolver_is_reported_rather_than_hidden() {
        assert_eq!(
            resolvers("nameserver 127.0.0.53\n"),
            vec!["127.0.0.53".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn a_lease_file_gives_the_dhcp_server() {
        let lease = "\
# This is private data. Do not parse.
ADDRESS=192.168.1.42
NETMASK=255.255.255.0
ROUTER=192.168.1.1
SERVER_ADDRESS=192.168.1.1
NEXT_SERVER=192.168.1.1
";
        assert_eq!(lease_server(lease), Some("192.168.1.1".parse().unwrap()));
        assert_eq!(lease_server("ADDRESS=1.2.3.4\n"), None);
    }
}
