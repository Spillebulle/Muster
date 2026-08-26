//! Sitting on a discovery port without taking it from anybody.
//!
//! The engine's side of this is [`crate::listen`], which explains why the phase
//! exists. This file is the three awkward mechanics it needs, none of which
//! `std::net::UdpSocket` can do on its own:
//!
//! 1. **`SO_REUSEADDR` before the bind.** Port 5353 belongs to the machine's
//!    own mDNS responder and 1900 to its SSDP service. The option is what lets
//!    a second socket sit beside the first and have each datagram delivered to
//!    both; without it the bind fails with "address in use" and the whole phase
//!    is dead on any machine that has a responder running, which is all of
//!    them. `UdpSocket::bind` binds before a caller can set anything, which is
//!    why `socket2` is a dependency.
//! 2. **Joining the group on each interface.** A machine with a VPN up has more
//!    than one, and joining on the wrong one hears the wrong link.
//! 3. **The pinhole.** See [`crate::listen`]: on Windows a listener that sends
//!    nothing hears nothing, and the failure is silent.
//!
//! **Nothing here ever answers.** Datagrams are read and the socket never
//! writes except to send the pinhole, so the responders that own these ports go
//! on answering for the machine exactly as they did before.

use crate::listen::{Ear, POKE_EVERY, Watch};
use socket2::{Domain, Protocol as SockProtocol, Socket, Type};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// How long a receive waits before the loop looks at the clock again.
///
/// Short enough that cancelling is felt at once and the pinhole is re-opened on
/// time, long enough that a quiet link is not a spin loop.
const TICK: Duration = Duration::from_millis(250);

/// One whole datagram. The same size and the same reason as
/// [`crate::platform::udp`]'s: Windows fails an oversized receive where Linux
/// truncates, so a buffer as wide as UDP can carry is what makes the two
/// platforms agree.
const RECV_BUFFER: usize = 65_536;

/// The real ear.
#[derive(Clone, Copy, Debug, Default)]
pub struct Link;

impl Ear for Link {
    fn overhear(
        &self,
        watch: &Watch,
        on: &[Ipv4Addr],
        poke: &[u8],
        window: Duration,
        cancel: &AtomicBool,
    ) -> io::Result<Vec<(IpAddr, Vec<u8>)>> {
        let socket = share(watch.port)?;
        socket.set_read_timeout(Some(TICK))?;

        // Where the pinhole datagram goes: the group for a protocol that has
        // one, and the all-ones broadcast for the two that do not.
        let to = match watch.group {
            Some(group) => {
                for address in on {
                    // A failure to join one interface is not a failure to
                    // listen: a machine with a down VPN adapter has an address
                    // that cannot carry a group, and the interface that matters
                    // usually joins fine. What could not be joined is silent
                    // here and visible in what is *not* heard.
                    let _ = socket.join_multicast_v4(&group, address);
                }
                // Link only. A discovery datagram has no business past the
                // first router, and the default of 1 is not something to leave
                // to chance.
                let _ = socket.set_multicast_ttl_v4(1);
                // The machine is on its own device list, so it should hear
                // itself.
                let _ = socket.set_multicast_loop_v4(true);
                SocketAddr::V4(SocketAddrV4::new(group, watch.port))
            }
            None => {
                socket.set_broadcast(true)?;
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::BROADCAST, watch.port))
            }
        };

        let deadline = Instant::now() + window;
        let mut next_poke = Instant::now();
        let mut heard = Vec::new();
        let mut buffer = vec![0u8; RECV_BUFFER];

        while Instant::now() < deadline {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            // Sent before the first receive and then on a timer. **This is the
            // line that makes the phase work on Windows at all**; see
            // [`crate::listen`] for the measurement.
            if Instant::now() >= next_poke {
                let _ = socket.send_to(poke, to);
                next_poke = Instant::now() + POKE_EVERY;
            }
            match socket.recv_from(&mut buffer) {
                Ok((n, from)) => {
                    // The machine's own datagrams are its own row's evidence,
                    // and it is on the list like anything else.
                    heard.push((from.ip(), buffer[..n].to_vec()));
                    // A hostile responder cannot make this allocate without
                    // bound. Well past what a busy link produces in a scan.
                    if heard.len() >= MOST {
                        break;
                    }
                }
                // The tick expired with nothing on the socket, which is the
                // ordinary case for most of the window.
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(heard)
    }
}

/// How many datagrams one watch will keep.
const MOST: usize = 4096;

/// A UDP socket on `port`, shared with whatever already has it.
///
/// `SO_REUSEADDR` on both platforms, and `SO_REUSEPORT` as well where it
/// exists: Linux wants both for a multicast listener to sit beside Avahi, and
/// Windows has only the first. On Windows the option succeeds unless the
/// incumbent asked for `SO_EXCLUSIVEADDRUSE`, and none of the system's own
/// discovery services do.
///
/// **Bound to `0.0.0.0` rather than to the group.** Binding the group address
/// is the documented Unix idiom and is not portable: Windows rejects it, and a
/// socket bound to the wildcard receives the group's datagrams on both
/// platforms once the membership is joined.
fn share(port: u16) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(SockProtocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
    socket.set_reuse_port(true)?;
    socket.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)).into())?;
    Ok(socket.into())
}
