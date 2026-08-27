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

/// The TTL an IPv4 datagram arrived with, out of the header in front of it.
///
/// The reading a raw socket needs, because a raw socket is handed the whole
/// datagram rather than the payload; a ping socket is handed the payload and
/// has to be told to send the TTL along beside it. See `linux::echo`.
///
/// **Here rather than in the Linux module**, which is where its only caller
/// is, because it is a pure reading of a recorded packet and this file compiles
/// on every platform. That means the test for it runs on the machine Muster is
/// developed on as well as on the ones that use it, which for a byte offset
/// into a header is the difference between a checked reading and a hopeful one.
///
/// The offset is fixed and the header's *length* is not, which is why this
/// reads the version rather than the length: byte 8 is the TTL in every IPv4
/// header, options or no options, and anything that is not IPv4 is not read at
/// all.
pub fn datagram_ttl(datagram: &[u8]) -> Option<u8> {
    if datagram.first()? >> 4 != 4 {
        return None;
    }
    datagram.get(8).copied()
}

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
    use crate::discover::{Capabilities, Echo, Outcome, Transport};
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
        fn ping(&self, _: IpAddr, _: Duration) -> io::Result<Option<Echo>> {
            Err(no("ICMP echoes"))
        }
        fn tcp(&self, addr: IpAddr, port: u16, timeout: Duration) -> Outcome {
            super::tcp::knock(addr, port, timeout)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::datagram_ttl;
    use crate::discover::Stack;

    /// A recorded echo reply as a raw socket hands it over: the IPv4 header,
    /// then the ICMP message. Only the header is written out, because the TTL
    /// is in it and nothing below byte 20 is read here.
    ///
    /// `ttl` goes in at byte 8 and `ihl` is the header length in 32-bit words,
    /// which is 5 with no options and more with them.
    fn recorded(ihl: u8, ttl: u8) -> Vec<u8> {
        let mut ip = vec![0u8; usize::from(ihl) * 4];
        let total = ip.len() as u16 + 8;
        ip[0] = 0x40 | ihl;
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        ip[8] = ttl;
        ip[9] = 1; // IPPROTO_ICMP.
        ip[12..16].copy_from_slice(&[192, 168, 1, 1]);
        ip[16..20].copy_from_slice(&[192, 168, 1, 42]);
        // The echo reply itself: type 0, code 0, and the rest of the header.
        ip.extend_from_slice(&[0, 0, 0, 0, 0x1e, 0x2f, 0, 1]);
        ip
    }

    /// Three recorded replies, read through the whole chain: the byte out of
    /// the header, and the band it rounds up to.
    #[test]
    fn the_ttl_comes_out_of_a_recorded_reply_and_names_a_stack() {
        assert_eq!(datagram_ttl(&recorded(5, 64)), Some(64));
        assert_eq!(
            datagram_ttl(&recorded(5, 64)).and_then(Stack::of),
            Some(Stack::Unix)
        );
        assert_eq!(
            datagram_ttl(&recorded(5, 128)).and_then(Stack::of),
            Some(Stack::Windows)
        );
        // A router two hops off, which is what the rounding is for.
        assert_eq!(
            datagram_ttl(&recorded(5, 253)).and_then(Stack::of),
            Some(Stack::Embedded)
        );
    }

    /// The header's length varies and the TTL's offset does not, so a reply
    /// carrying IP options must read the same. A reader that skipped `ihl * 4`
    /// bytes and then looked would find a byte of the payload.
    #[test]
    fn a_header_carrying_options_is_read_at_the_same_offset() {
        assert_eq!(datagram_ttl(&recorded(9, 64)), Some(64));
    }

    /// And what is not read: anything that is not IPv4, and anything too short
    /// to hold the field. Neither is a TTL of zero.
    #[test]
    fn a_datagram_that_is_not_ipv4_or_is_too_short_reads_nothing() {
        let mut six = recorded(5, 64);
        six[0] = 0x60;
        assert_eq!(datagram_ttl(&six), None);
        assert_eq!(datagram_ttl(&[]), None);
        assert_eq!(datagram_ttl(&recorded(5, 64)[..8]), None);
    }
}
