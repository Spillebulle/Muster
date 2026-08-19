//! Phase one: what the machine already knows about the network it is on.
//!
//! No packets are sent here. Every answer comes from a [`SystemProbe`], which
//! means this whole phase runs with no privileges, instantly, and on a machine
//! with Npcap missing and `CAP_NET_RAW` unavailable. It is also the phase that
//! answers most of what people actually want — the gateway, the DNS servers,
//! the DHCP server, the interface and its prefix — so it is usable on its own
//! and is not a preamble to the sweep.
//!
//! The whole module is a pure function of the readings. That is what makes the
//! Linux answers testable on Windows and the Windows answers testable on Linux,
//! which is the only way either gets tested at all.
//!
//! ## Gaps are results
//!
//! A reading that failed is recorded in [`Survey::gaps`] and never flattened
//! into an empty vector. `CLAUDE.md`'s rule is that "no devices found" from an
//! engine that could not look is the worst failure this application can
//! produce, because it looks like an answer. A survey that could not read the
//! routing table therefore reports that it has no gateway *because it could not
//! look*, and the interface above has what it needs to say so.

use crate::prefix::Prefix;
use crate::sysinfo::{Interface, Neighbour, Route, SystemProbe};
use std::fmt;
use std::net::IpAddr;

/// A reading that could not be taken, and what is consequently unknown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gap {
    pub reading: Reading,
    pub because: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reading {
    Interfaces,
    Routes,
    Neighbours,
    Resolvers,
}

impl fmt::Display for Reading {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Interfaces => "the interface list",
            Self::Routes => "the routing table",
            Self::Neighbours => "the neighbour table",
            Self::Resolvers => "the resolver configuration",
        })
    }
}

/// A router this machine sends through, per family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gateway {
    pub address: IpAddr,
    pub interface_index: u32,
    pub metric: u32,
}

/// The picture phase one builds.
#[derive(Clone, Debug, Default)]
pub struct Survey {
    pub interfaces: Vec<Interface>,
    pub routes: Vec<Route>,
    pub neighbours: Vec<Neighbour>,
    /// The machine-wide resolver list, unioned with the per-interface ones so
    /// there is one list to show and it is complete.
    pub resolvers: Vec<IpAddr>,
    /// Default-route gateways, best (lowest metric) first, at most one per
    /// family. A dual-stack machine has two and both are worth showing.
    pub gateways: Vec<Gateway>,
    /// DHCP servers as recorded in the current leases. Unprivileged, and not
    /// the same question as "which servers would answer a DISCOVER" — that one
    /// needs packets, and is how a rogue server is found.
    pub dhcp_servers: Vec<IpAddr>,
    pub gaps: Vec<Gap>,
}

impl Survey {
    /// Takes the survey. Never fails: a probe that cannot answer produces gaps,
    /// because there is always something worth showing and refusing to report
    /// anything is the one outcome that helps nobody.
    pub fn take<P: SystemProbe>(probe: P) -> Self {
        let mut survey = Self::default();

        match probe.interfaces() {
            Ok(v) => survey.interfaces = v,
            Err(e) => survey.gap(Reading::Interfaces, e),
        }
        match probe.routes() {
            Ok(v) => survey.routes = v,
            Err(e) => survey.gap(Reading::Routes, e),
        }
        match probe.neighbours() {
            Ok(v) => survey.neighbours = v,
            Err(e) => survey.gap(Reading::Neighbours, e),
        }
        match probe.resolvers() {
            Ok(v) => survey.resolvers = v,
            Err(e) => survey.gap(Reading::Resolvers, e),
        }

        survey.derive();
        survey
    }

    fn gap(&mut self, reading: Reading, e: std::io::Error) {
        self.gaps.push(Gap {
            reading,
            because: e.to_string(),
        });
    }

    /// Works out the gateways, the resolver union and the DHCP servers from
    /// the raw readings. Split out so the derivation is one place and a
    /// hand-built `Survey` in a test behaves like a probed one.
    fn derive(&mut self) {
        // Best default route per family. Sorting by metric and keeping the
        // first of each family is how a machine with a VPN up reports the
        // route traffic is actually taking rather than both.
        let mut defaults: Vec<&Route> = self.routes.iter().filter(|r| r.is_default()).collect();
        defaults.sort_by_key(|r| r.metric);
        let mut seen_v4 = false;
        let mut seen_v6 = false;
        for route in defaults {
            let Some(address) = route.gateway else {
                continue;
            };
            let is_v4 = address.is_ipv4();
            if (is_v4 && seen_v4) || (!is_v4 && seen_v6) {
                continue;
            }
            if is_v4 {
                seen_v4 = true
            } else {
                seen_v6 = true
            }
            self.gateways.push(Gateway {
                address,
                interface_index: route.interface_index,
                metric: route.metric,
            });
        }

        // Windows reports resolvers per adapter and Unix reports them once.
        // Unioning both, in order, gives one list that is right on both and
        // that keeps the machine-wide list first where there is one.
        for iface in &self.interfaces {
            for &dns in &iface.dns {
                if !self.resolvers.contains(&dns) {
                    self.resolvers.push(dns);
                }
            }
        }

        for iface in &self.interfaces {
            if let Some(server) = iface.dhcp_server
                && !self.dhcp_servers.contains(&server)
            {
                self.dhcp_servers.push(server);
            }
        }
    }

    /// The interface a scan should run on by default: the one carrying the best
    /// default route, if it is scannable.
    ///
    /// Falls back to the first scannable interface with an IPv4 prefix, which
    /// is the right answer on a machine with no default route at all — an
    /// isolated lab network being exactly the sort of place this tool is used.
    pub fn primary(&self) -> Option<&Interface> {
        let by_gateway = self
            .gateways
            .iter()
            .find_map(|g| self.interface(g.interface_index))
            .filter(|i| i.is_scannable());
        by_gateway.or_else(|| {
            self.interfaces
                .iter()
                .find(|i| i.is_scannable() && i.v4_prefixes().next().is_some())
        })
    }

    pub fn interface(&self, index: u32) -> Option<&Interface> {
        self.interfaces.iter().find(|i| i.index == index)
    }

    /// The prefixes a default scan would sweep: the directly attached IPv4
    /// networks of the primary interface, excluding anything too large to walk.
    ///
    /// `CLAUDE.md`: the default target is the local prefix derived from the
    /// interface, never a range somebody typed and never beyond the link.
    pub fn default_targets(&self) -> Vec<Prefix> {
        let Some(iface) = self.primary() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for prefix in iface.v4_prefixes() {
            // A /32 on an interface is a host route, not a network to sweep;
            // it is what a VPN client and a point-to-point link both look like.
            if prefix.len() == 32 || prefix.hosts().is_none() {
                continue;
            }
            if !out.contains(&prefix) {
                out.push(prefix);
            }
        }
        out
    }

    /// Neighbour entries that attest to a device rather than to a failed probe.
    pub fn known_devices(&self) -> impl Iterator<Item = &Neighbour> {
        self.neighbours
            .iter()
            .filter(|n| n.state.is_evidence() && !n.mac.is_zero() && !n.mac.is_multicast())
    }

    /// Was this reading taken at all? The interface asks before saying that
    /// something is absent, so it can say "could not look" instead.
    pub fn has(&self, reading: Reading) -> bool {
        !self.gaps.iter().any(|g| g.reading == reading)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mac::MacAddr;
    use crate::sysinfo::{IfAddr, IfFlags, LinkKind, NeighbourState, Recorded};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn prefix(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    /// A wired interface on a home network, plus loopback. The shape most of
    /// these tests need.
    fn wired(index: u32, addr: &str, net: &str) -> Interface {
        Interface {
            name: format!("eth{index}"),
            friendly: format!("Ethernet {index}"),
            index,
            mac: Some("3c:22:fb:00:11:22".parse().unwrap()),
            addresses: vec![IfAddr {
                address: ip(addr),
                prefix: prefix(net),
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
        }
    }

    fn loopback() -> Interface {
        Interface {
            name: "lo".into(),
            friendly: "Loopback".into(),
            index: 1,
            mac: None,
            addresses: vec![IfAddr {
                address: ip("127.0.0.1"),
                prefix: prefix("127.0.0.0/8"),
            }],
            kind: LinkKind::Loopback,
            flags: IfFlags {
                up: true,
                loopback: true,
                point_to_point: false,
            },
            mtu: 65536,
            dns: Vec::new(),
            dhcp_server: None,
        }
    }

    fn default_route(gateway: &str, index: u32, metric: u32) -> Route {
        Route {
            destination: prefix("0.0.0.0/0"),
            gateway: Some(ip(gateway)),
            interface_index: index,
            metric,
        }
    }

    fn home() -> Recorded {
        let mut eth = wired(2, "192.168.1.42", "192.168.1.0/24");
        eth.dns = vec![ip("192.168.1.1")];
        eth.dhcp_server = Some(ip("192.168.1.1"));
        Recorded {
            interfaces: vec![loopback(), eth],
            routes: vec![
                default_route("192.168.1.1", 2, 10),
                Route {
                    destination: prefix("192.168.1.0/24"),
                    gateway: None,
                    interface_index: 2,
                    metric: 10,
                },
            ],
            neighbours: vec![Neighbour {
                address: ip("192.168.1.1"),
                mac: "3c:22:fb:aa:bb:cc".parse().unwrap(),
                interface_index: 2,
                state: NeighbourState::Reachable,
            }],
            resolvers: vec![ip("192.168.1.1")],
            broken: false,
        }
    }

    #[test]
    fn finds_the_gateway_the_interface_and_the_prefix() {
        let s = Survey::take(home());
        assert_eq!(s.gateways.len(), 1);
        assert_eq!(s.gateways[0].address, ip("192.168.1.1"));
        assert_eq!(s.primary().unwrap().name, "eth2");
        assert_eq!(s.default_targets(), vec![prefix("192.168.1.0/24")]);
        assert_eq!(s.dhcp_servers, vec![ip("192.168.1.1")]);
        assert!(s.gaps.is_empty());
    }

    /// Loopback is up and has an address, and is never the interface to scan.
    #[test]
    fn loopback_is_never_the_primary_interface() {
        let mut r = home();
        r.routes.clear();
        let s = Survey::take(r);
        assert_eq!(s.primary().unwrap().name, "eth2");
        assert!(!loopback().is_scannable());
    }

    /// A VPN raises a second default route with a better metric. The gateway
    /// reported must be the one traffic takes, and only one per family.
    #[test]
    fn the_best_default_route_wins_and_only_one_per_family() {
        let mut r = home();
        r.interfaces.push(wired(3, "10.8.0.2", "10.8.0.0/24"));
        r.routes.push(default_route("10.8.0.1", 3, 1));
        r.routes.push(Route {
            destination: prefix("::/0"),
            gateway: Some(ip("fe80::1")),
            interface_index: 2,
            metric: 20,
        });

        let s = Survey::take(r);
        let v4: Vec<_> = s.gateways.iter().filter(|g| g.address.is_ipv4()).collect();
        assert_eq!(v4.len(), 1, "one v4 gateway, the best one");
        assert_eq!(v4[0].address, ip("10.8.0.1"));
        assert_eq!(s.gateways.len(), 2, "and the v6 one beside it");
        assert_eq!(s.primary().unwrap().name, "eth3");
    }

    /// The rule this module exists for. A probe that cannot read the routing
    /// table must not report a machine with no gateway.
    #[test]
    fn a_failed_reading_is_a_gap_and_not_an_empty_answer() {
        let s = Survey::take(Recorded {
            broken: true,
            ..home()
        });
        assert!(s.gateways.is_empty());
        assert!(!s.has(Reading::Routes));
        assert!(!s.has(Reading::Interfaces));
        assert_eq!(
            s.gaps.len(),
            4,
            "every reading failed and every one is named"
        );
        assert!(s.gaps.iter().all(|g| !g.because.is_empty()));
    }

    #[test]
    fn a_good_survey_claims_every_reading() {
        let s = Survey::take(home());
        for reading in [
            Reading::Interfaces,
            Reading::Routes,
            Reading::Neighbours,
            Reading::Resolvers,
        ] {
            assert!(s.has(reading), "{reading} should have been read");
        }
    }

    /// Windows reports resolvers per adapter, Unix reports them once. The
    /// union has to hold both without repeating either.
    #[test]
    fn resolvers_are_unioned_without_duplicates() {
        let mut r = home();
        r.resolvers = vec![ip("1.1.1.1")];
        r.interfaces[1].dns = vec![ip("1.1.1.1"), ip("192.168.1.1")];
        let s = Survey::take(r);
        assert_eq!(s.resolvers, vec![ip("1.1.1.1"), ip("192.168.1.1")]);
    }

    /// A /32 on the interface is a VPN or a point-to-point link. Sweeping it
    /// is one probe at the machine's own address.
    #[test]
    fn host_routes_are_not_swept() {
        let mut r = home();
        r.interfaces[1].addresses.push(IfAddr {
            address: ip("10.8.0.2"),
            prefix: prefix("10.8.0.2/32"),
        });
        let s = Survey::take(r);
        assert_eq!(s.default_targets(), vec![prefix("192.168.1.0/24")]);
    }

    /// An interface holding a /8 is a target the user has to ask for, not one
    /// a default scan walks into.
    #[test]
    fn an_over_broad_prefix_is_not_a_default_target() {
        let mut r = home();
        r.interfaces[1].addresses = vec![IfAddr {
            address: ip("10.1.2.3"),
            prefix: prefix("10.0.0.0/8"),
        }];
        r.routes = vec![default_route("10.0.0.1", 2, 10)];
        let s = Survey::take(r);
        assert!(s.primary().is_some());
        assert!(
            s.default_targets().is_empty(),
            "a /8 needs asking, not defaulting"
        );
    }

    /// An incomplete ARP entry is a probe that failed. Counting it as a device
    /// is how an unprivileged sweep invents hosts.
    #[test]
    fn incomplete_neighbours_are_not_devices() {
        let mut r = home();
        r.neighbours.push(Neighbour {
            address: ip("192.168.1.99"),
            mac: MacAddr::ZERO,
            interface_index: 2,
            state: NeighbourState::Incomplete,
        });
        r.neighbours.push(Neighbour {
            address: ip("224.0.0.251"),
            mac: "01:00:5e:00:00:fb".parse().unwrap(),
            interface_index: 2,
            state: NeighbourState::Static,
        });
        let s = Survey::take(r);
        let found: Vec<_> = s.known_devices().map(|n| n.address).collect();
        assert_eq!(found, vec![ip("192.168.1.1")]);
    }

    /// A machine on an isolated network has no default route and is exactly
    /// the sort of place this tool gets used.
    #[test]
    fn a_network_with_no_gateway_still_has_a_target() {
        let r = Recorded {
            interfaces: vec![loopback(), wired(2, "172.16.5.9", "172.16.5.0/24")],
            routes: Vec::new(),
            ..Default::default()
        };
        let s = Survey::take(r);
        assert!(s.gateways.is_empty());
        assert_eq!(s.default_targets(), vec![prefix("172.16.5.0/24")]);
    }
}
