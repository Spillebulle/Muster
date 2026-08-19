//! What the operating system already knows, and the seam it comes through.
//!
//! This is the boundary `CLAUDE.md` calls the one that matters most: every
//! reading the engine takes from the platform arrives through [`SystemProbe`],
//! and nothing above this module calls an OS function. The point is not
//! tidiness. It is that a scanner whose tests need a network interface has no
//! tests at all, because CI runners have no LAN worth scanning and no two
//! developer machines see the same one.
//!
//! So there are two implementations. [`platform::Host`](crate::platform::Host)
//! is the real one, and it is the only place in the crate that talks to the IP
//! Helper API or to netlink. [`Recorded`] is a set of readings held in memory,
//! which is what every test in the crate runs against — including the tests for
//! the *other* platform's answers, which is the only way those get exercised on
//! a developer's machine at all.
//!
//! Every method returns [`io::Result`] and none of them is expected to be
//! infallible: a probe that cannot read the routing table is a real state, and
//! the survey above reports it as a gap rather than as an empty network.

use crate::mac::MacAddr;
use crate::prefix::Prefix;
use std::io;
use std::net::IpAddr;

/// A network interface as the OS describes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    /// The kernel's name for it: `eth0`, `wlan0`, or on Windows the adapter
    /// GUID. Stable, unfriendly, and what other tools print.
    pub name: String,
    /// What the user would recognise. On Windows this is the adapter's
    /// description ("Intel(R) Wi-Fi 6 AX201"); elsewhere it is `name` again,
    /// because there is nothing better and an empty string is worse.
    pub friendly: String,
    /// The interface index, which is how routes and neighbours refer to it.
    pub index: u32,
    /// The hardware address. [`None`] for interfaces that have none, such as
    /// loopback and most tunnels — which is different from an all-zero one.
    pub mac: Option<MacAddr>,
    /// Every address configured on the interface, with the prefix it sits in.
    pub addresses: Vec<IfAddr>,
    pub kind: LinkKind,
    pub flags: IfFlags,
    /// Bytes, or `0` where the platform did not say.
    pub mtu: u32,
    /// Resolvers configured for this interface specifically. Windows reports
    /// them per adapter, which is more truthful than a single global list on a
    /// machine with a VPN up; Unix has only the global list and leaves this
    /// empty.
    pub dns: Vec<IpAddr>,
    /// The DHCP server the current lease came from, where the platform records
    /// it. This is the *unprivileged* answer to "what is my DHCP server", and
    /// it is why the first phase of a scan needs no packets at all.
    pub dhcp_server: Option<IpAddr>,
}

impl Interface {
    /// Is this an interface a scan should consider? Up, not loopback, and
    /// carrying at least one address.
    pub fn is_scannable(&self) -> bool {
        self.flags.up && !self.flags.loopback && !self.addresses.is_empty()
    }

    /// The IPv4 prefixes configured here, which are what can be swept.
    pub fn v4_prefixes(&self) -> impl Iterator<Item = Prefix> + '_ {
        self.addresses
            .iter()
            .filter(|a| a.address.is_ipv4())
            .map(|a| a.prefix)
    }
}

/// One address on an interface, and the network it implies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IfAddr {
    pub address: IpAddr,
    pub prefix: Prefix,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IfFlags {
    pub up: bool,
    pub loopback: bool,
    /// No broadcast domain, so no ARP sweep: a VPN or a PPP link.
    pub point_to_point: bool,
}

/// What kind of link this is, as far as the platform will say.
///
/// It is worth knowing beyond labelling: a wireless interface cannot be put in
/// promiscuous mode usefully on most drivers, and a tunnel has no neighbours to
/// ARP for. `Unknown` is honest and common.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LinkKind {
    Ethernet,
    Wireless,
    Loopback,
    Tunnel,
    #[default]
    Unknown,
}

/// A routing table entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    pub destination: Prefix,
    /// [`None`] for a route onto a directly attached link, which is exactly how
    /// the engine tells "this network is on my wire" from "this network is
    /// somewhere behind a router".
    pub gateway: Option<IpAddr>,
    pub interface_index: u32,
    pub metric: u32,
}

impl Route {
    /// A default route: `0.0.0.0/0` or `::/0`. The gateway of the best one is
    /// the machine's gateway.
    pub fn is_default(&self) -> bool {
        self.destination.len() == 0
    }
}

/// A neighbour (ARP or NDP) table entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Neighbour {
    pub address: IpAddr,
    pub mac: MacAddr,
    pub interface_index: u32,
    pub state: NeighbourState,
}

/// How much the entry is worth believing.
///
/// The platforms disagree on the details, so these are the states worth acting
/// on rather than a union of both tables. The distinction that matters is
/// [`NeighbourState::Incomplete`]: an entry exists because something asked, and
/// nothing answered. That is a probe that failed, not a device — and reading it
/// as one is how an unprivileged sweep invents hosts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NeighbourState {
    /// Confirmed recently. A device is there.
    Reachable,
    /// Was confirmed, may have gone. Still evidence of a device.
    Stale,
    /// Asked, nothing answered. Not evidence of anything.
    Incomplete,
    /// Configured by hand, never verified.
    Static,
}

impl NeighbourState {
    /// Does this entry attest to a device being present?
    pub fn is_evidence(self) -> bool {
        matches!(self, Self::Reachable | Self::Stale | Self::Static)
    }
}

/// Everything the engine reads from the operating system.
///
/// Implementors do no interpretation: they hand over what the platform said,
/// and the survey above decides what it means. That split is what lets the
/// Windows answers be reasoned about on Linux and the other way round.
pub trait SystemProbe {
    fn interfaces(&self) -> io::Result<Vec<Interface>>;
    fn routes(&self) -> io::Result<Vec<Route>>;
    fn neighbours(&self) -> io::Result<Vec<Neighbour>>;

    /// The machine-wide resolver list. On Unix this is `/etc/resolv.conf` or
    /// what `systemd-resolved` reports; on Windows the per-interface lists in
    /// [`Interface::dns`] are better, and this is their union.
    fn resolvers(&self) -> io::Result<Vec<IpAddr>>;
}

/// Readings held in memory, for tests and for the rehearsal menu.
///
/// This is the whole test double. It is deliberately a plain struct of public
/// vectors rather than a builder: a test that has to learn an API before it can
/// state "there is one interface with this address" will be written as an
/// integration test against the real machine instead, which is the thing this
/// module exists to prevent.
#[derive(Clone, Debug, Default)]
pub struct Recorded {
    pub interfaces: Vec<Interface>,
    pub routes: Vec<Route>,
    pub neighbours: Vec<Neighbour>,
    pub resolvers: Vec<IpAddr>,
    /// Set to make every reading fail, which is the state a survey has to
    /// report as a gap rather than as an empty network.
    pub broken: bool,
}

impl Recorded {
    fn check(&self) -> io::Result<()> {
        if self.broken {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "recorded probe is broken",
            ))
        } else {
            Ok(())
        }
    }
}

impl SystemProbe for Recorded {
    fn interfaces(&self) -> io::Result<Vec<Interface>> {
        self.check()?;
        Ok(self.interfaces.clone())
    }

    fn routes(&self) -> io::Result<Vec<Route>> {
        self.check()?;
        Ok(self.routes.clone())
    }

    fn neighbours(&self) -> io::Result<Vec<Neighbour>> {
        self.check()?;
        Ok(self.neighbours.clone())
    }

    fn resolvers(&self) -> io::Result<Vec<IpAddr>> {
        self.check()?;
        Ok(self.resolvers.clone())
    }
}

/// Borrowed probes are probes, so a survey can be taken through a reference
/// without the caller cloning readings it already has.
impl<T: SystemProbe + ?Sized> SystemProbe for &T {
    fn interfaces(&self) -> io::Result<Vec<Interface>> {
        (**self).interfaces()
    }
    fn routes(&self) -> io::Result<Vec<Route>> {
        (**self).routes()
    }
    fn neighbours(&self) -> io::Result<Vec<Neighbour>> {
        (**self).neighbours()
    }
    fn resolvers(&self) -> io::Result<Vec<IpAddr>> {
        (**self).resolvers()
    }
}
