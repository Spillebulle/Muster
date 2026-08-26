//! The one place in the crate that talks to an operating system.
//!
//! Everything above this module works through
//! [`SystemProbe`](crate::sysinfo::SystemProbe), so this is the only code that
//! has to be reasoned about per platform, and the only code a test cannot run.
//!
//! An unsupported platform gets [`Unsupported`], which fails every reading
//! rather than answering emptily. That is not a courtesy: a survey of failures
//! reports gaps, and gaps are what the interface shows instead of "no devices
//! found". Compiling on a platform Muster does not support should look like a
//! platform Muster does not support.

use std::io;

pub mod listen;
pub mod procfs;
pub mod tcp;
pub mod udp;

/// What to do about it, when this machine will not let Muster send an ICMP
/// echo.
///
/// A gap the user can close is worth a sentence saying how, and this is the one
/// gap on Linux that a person hits with no way to guess the cure: ping sockets
/// are gated on `net.ipv4.ping_group_range`, a distribution either opens it for
/// everybody or leaves it shut, and nothing on screen ever mentioned it. Debian,
/// Ubuntu and Pop!_OS leave it shut. The string lives here because the remedy is
/// the platform's.
///
/// **Both routes are named because both were tried.** A shut sysctl is not the
/// end of it: `linux::Echo` asks for a raw socket next, so this sentence is only
/// ever shown by a process that has neither.
///
/// **The cure named is the whole capability set, not the missing half.**
/// `setcap` replaces what a binary has rather than adding to it, so a user told
/// to grant `cap_net_raw` alone would silently take away the port 68 the DHCP
/// check was granted. The two messages therefore print the same command.
#[cfg(target_os = "linux")]
pub const ICMP_HINT: &str = "ping sockets are closed to this user and this build has no raw socket, so no echo was sent. The packaged builds are granted one on install; for this one it is sudo setcap cap_net_bind_service,cap_net_raw=+ep on the muster binary, or run Muster with sudo";

/// Windows answers echoes through `IcmpSendEcho2`, which needs nothing, so a
/// failure here is the API refusing rather than a setting to change.
#[cfg(windows)]
pub const ICMP_HINT: &str = "the system's own ICMP helper would not answer";

#[cfg(not(any(windows, target_os = "linux")))]
pub const ICMP_HINT: &str = "Muster sends no ICMP echoes on this platform";

/// What to do about it, when this machine will not let Muster bind port 68.
///
/// The same rule as [`ICMP_HINT`]: a gap somebody can close is worth the
/// sentence that says how. **And it has to be the right sentence**, which is
/// why this is a function of the error rather than one string appended to
/// whatever the operating system said. There are two entirely different ways to
/// fail to get port 68 and they have opposite cures:
///
/// * `EACCES` — the port is below 1024 and this process may not bind one. Cured
///   by `CAP_NET_BIND_SERVICE`, which the packaged builds grant on install.
/// * `EADDRINUSE` — the bind got *past* that check, and the machine's own DHCP
///   client is holding the port. A capability is not the cure, and this build
///   evidently already has one; the socket asked to share the port and that
///   client would not.
///
/// Shipping the first sentence for the second error is the application
/// misreading its own error and telling somebody to grant a privilege they can
/// see they already have. It was doing exactly that on Pop!_OS.
#[cfg(target_os = "linux")]
pub fn dhcp_hint(error: &io::Error) -> &'static str {
    match error.kind() {
        io::ErrorKind::AddrInUse => {
            "another DHCP client on this machine already holds port 68 and would not share it. Muster asks for the port with SO_REUSEADDR, which most system clients allow; stopping that client, or running Muster as root, is what is left"
        }
        _ => {
            "port 68 is below 1024, so binding it needs a capability this build does not have. Granting it once is sudo setcap cap_net_bind_service,cap_net_raw=+ep on the muster binary, and the packaged builds do that on install"
        }
    }
}

/// On Windows the port belongs to the DHCP Client service, and Muster will not
/// take it from the service this machine's own address depends on.
///
/// `SO_REUSEADDR` would let it: on Windows that option means *hijack*, and the
/// datagrams the service is waiting for would start arriving here instead. A
/// rogue-server check is not worth a machine's own lease renewal going missing,
/// so this stays a sentence rather than becoming a socket option. Stopping the
/// service is the honest way in, and it is the user's to decide.
#[cfg(windows)]
pub fn dhcp_hint(_error: &io::Error) -> &'static str {
    "the DHCP Client service holds port 68 already. Muster will not take the port from the service this machine's own address depends on, so the check needs that service stopped"
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn dhcp_hint(_error: &io::Error) -> &'static str {
    "port 68 could not be bound on this platform"
}

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::Host;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::Host;

#[cfg(not(any(windows, target_os = "linux")))]
pub use unsupported::Host;

#[cfg(not(any(windows, target_os = "linux")))]
mod unsupported {
    use crate::discover::{Capabilities, Outcome, Transport};
    use crate::mac::MacAddr;
    use crate::sysinfo::{Interface, Neighbour, Route, SystemProbe};
    use std::io;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    #[derive(Clone, Copy, Debug, Default)]
    pub struct Host;

    fn no(reading: &str) -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            format!("Muster does not read {reading} on this platform"),
        )
    }

    impl SystemProbe for Host {
        fn interfaces(&self) -> io::Result<Vec<Interface>> {
            Err(no("the interface list"))
        }
        fn routes(&self) -> io::Result<Vec<Route>> {
            Err(no("the routing table"))
        }
        fn neighbours(&self) -> io::Result<Vec<Neighbour>> {
            Err(no("the neighbour table"))
        }
        fn resolvers(&self) -> io::Result<Vec<IpAddr>> {
            Err(no("the resolver configuration"))
        }
    }

    /// TCP is `std` and works anywhere, so it is offered even here. ARP and
    /// ICMP are not, and saying so is what turns an unsupported platform into
    /// a sweep that reports what it could not do.
    impl Transport for Host {
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                arp: false,
                icmp: false,
                tcp: true,
            }
        }
        fn arp(&self, _: Ipv4Addr, _: Duration) -> io::Result<Option<MacAddr>> {
            Err(no("hardware addresses"))
        }
        fn ping(&self, _: IpAddr, _: Duration) -> io::Result<Option<Duration>> {
            Err(no("ICMP echoes"))
        }
        fn tcp(&self, addr: IpAddr, port: u16, timeout: Duration) -> Outcome {
            super::tcp::knock(addr, port, timeout)
        }
    }
}
