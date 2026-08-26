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

pub mod procfs;
pub mod tcp;
pub mod udp;

/// What to do about it, when this machine will not let Muster send an ICMP
/// echo.
///
/// A gap the user can close is worth a sentence saying how, and this is the one
/// gap on Linux that a person hits with no way to guess the cure: ping sockets
/// are gated on `net.ipv4.ping_group_range`, a distribution either opens it for
/// everybody or leaves it shut, and nothing on screen ever mentioned it. The
/// string lives here because the remedy is the platform's, and it is the only
/// per-platform sentence in the crate for that reason.
#[cfg(target_os = "linux")]
pub const ICMP_HINT: &str = "ping sockets are closed to this user, so no echo was sent. Opening them is sysctl -w net.ipv4.ping_group_range=\"0 2147483647\", or run Muster with more privilege";

/// Windows answers echoes through `IcmpSendEcho2`, which needs nothing, so a
/// failure here is the API refusing rather than a setting to change.
#[cfg(windows)]
pub const ICMP_HINT: &str = "the system's own ICMP helper would not answer";

#[cfg(not(any(windows, target_os = "linux")))]
pub const ICMP_HINT: &str = "Muster sends no ICMP echoes on this platform";

/// What to do about it, when this machine will not let Muster bind port 68.
///
/// The same rule as [`ICMP_HINT`]: a gap somebody can close is worth the
/// sentence that says how. On Linux the cure is one capability — not
/// `CAP_NET_RAW`, just the right to bind a port below 1024 — and the packaged
/// builds grant it in their install scriptlet, so this sentence is for the
/// tarball, the AppImage and a development tree.
#[cfg(target_os = "linux")]
pub const DHCP_HINT: &str = "port 68 is below 1024, so binding it needs a capability this build does not have. Granting it once is sudo setcap cap_net_bind_service=+ep on the muster binary, and the packaged builds do that on install";

#[cfg(windows)]
pub const DHCP_HINT: &str =
    "the DHCP Client service usually holds port 68 already, and Muster cannot share it yet";

#[cfg(not(any(windows, target_os = "linux")))]
pub const DHCP_HINT: &str = "port 68 could not be bound on this platform";

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
