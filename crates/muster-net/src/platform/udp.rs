//! The one datagram exchange identification is built on.
//!
//! `std` and nothing else, so it is the same code on every platform and needs
//! no privileges anywhere: every port it talks to is a destination, and the
//! source is an ephemeral port the OS picks.
//!
//! **A fresh socket per exchange, deliberately.** Reusing one would be cheaper
//! and wrong: thirty-two identifications run at once, and a shared socket would
//! hand one device's reply to whichever thread happened to call `recv` first.
//! Binding per call costs a syscall and makes the answer belong to the question.

use crate::identify::Ask;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// The receive buffer, which is one whole datagram's worth.
///
/// It was 4 KiB, on the reasoning that a longer reply is a service list nothing
/// is going to display and that a truncated datagram parses as far as it goes.
/// That reasoning holds on Linux, where the kernel truncates and reports the
/// bytes it copied. **It does not hold on Windows**, where an oversized
/// datagram fails the receive with `WSAEMSGSIZE` instead — so a device with a
/// long mDNS service list was identified on one platform and not on the other,
/// and the difference was invisible because the error looked like any other
/// timeout. A buffer as large as UDP can carry is what makes the two platforms
/// agree; [`WSAEMSGSIZE`] below is the belt to its braces.
const RECV_BUFFER: usize = 65_536;

/// `WSAEMSGSIZE`. Named by number because it has no `io::ErrorKind` of its own
/// and is a no-op on every other platform.
const WSAEMSGSIZE: i32 = 10040;

/// The exchange. Held by `Host` so callers have one type to pass around.
#[derive(Clone, Copy, Debug, Default)]
pub struct Udp;

impl Ask for Udp {
    fn ask(&self, to: SocketAddr, payload: &[u8], timeout: Duration) -> io::Result<Vec<u8>> {
        // Bind to the family being asked, or a v4 socket cannot reach a v6
        // address and the error arrives as a confusing "invalid argument".
        let bind: SocketAddr = if to.is_ipv4() {
            "0.0.0.0:0".parse().expect("literal")
        } else {
            "[::]:0".parse().expect("literal")
        };
        let socket = UdpSocket::bind(bind)?;
        socket.set_read_timeout(Some(timeout))?;
        socket.send_to(payload, to)?;

        let mut buf = vec![0u8; RECV_BUFFER];
        let deadline = Instant::now() + timeout;
        loop {
            let (n, from) = match socket.recv_from(&mut buf) {
                Ok(got) => got,
                // A datagram longer than the buffer. Windows reports this as a
                // failure *after* filling the buffer, and the sender it filled
                // in is thrown away with the return value, so the reply cannot
                // be attributed. That is why the buffer is a whole datagram
                // wide: nothing a device can put on a UDP socket reaches here,
                // and the arm exists so that if something ever does it is a
                // partial parse rather than a device that identifies as
                // nothing. What arrived is what was asked for as far as
                // anything can tell, and the alternative is discarding it.
                Err(e) if e.raw_os_error() == Some(WSAEMSGSIZE) => (buf.len(), to),
                Err(e) => return Err(e),
            };
            // The socket is unconnected, so anything on the network can send to
            // it. Only the address that was asked gets to answer: otherwise a
            // device could name its neighbour.
            if from.ip() == to.ip() {
                buf.truncate(n);
                return Ok(buf);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "no reply from the address asked",
                ));
            }
            socket.set_read_timeout(Some(left))?;
        }
    }
}

/// The DHCP exchange: one broadcast out, everything that answers collected.
///
/// **Port 68 is the whole difficulty.** A DHCP server replies to the client
/// port, so a client has to be listening on 68 to hear an offer at all, and 68
/// is not a port a program simply gets:
///
/// * On **Linux** it is below 1024, so binding it needs `CAP_NET_BIND_SERVICE`
///   or root.
/// * On **Windows** the port is usually already held by the DHCP Client
///   service, which is the thing that got this machine its own address.
///
/// So this fails often, and failing is fine as long as it says so: `dhcp::probe`
/// turns the error into a sentence and the interface shows it, rather than
/// reporting "no rogue server found" for a question that was never asked.
///
/// Sharing the port with the system's own client is possible with
/// `SO_REUSEADDR` before the bind, which `std` cannot express — it is the next
/// step for this feature and needs a socket built through `libc` and
/// `windows-sys` by hand.
#[derive(Clone, Copy, Debug, Default)]
pub struct Dhcp;

/// Where a DHCP server listens, and where a client does.
const SERVER_PORT: u16 = 67;
const CLIENT_PORT: u16 = 68;

/// How long to wait on the socket between checks of the deadline.
///
/// Short enough that the window is honoured to within a tick, long enough that
/// a quiet link is not a spin loop.
const TICK: Duration = Duration::from_millis(200);

impl crate::dhcp::Broadcaster for Dhcp {
    fn broadcast(&self, payload: &[u8], window: Duration) -> io::Result<Vec<Vec<u8>>> {
        let socket = UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, CLIENT_PORT))?;
        socket.set_broadcast(true)?;
        socket.set_read_timeout(Some(TICK))?;
        socket.send_to(payload, (std::net::Ipv4Addr::BROADCAST, SERVER_PORT))?;

        // Every reply within the window, not the first. That is the feature:
        // one offer is a working network and two is a fault, and a loop that
        // stopped at the first would never be able to tell them apart.
        let deadline = Instant::now() + window;
        let mut replies = Vec::new();
        let mut buffer = [0u8; 1500];
        while Instant::now() < deadline {
            match socket.recv_from(&mut buffer) {
                Ok((n, _)) => replies.push(buffer[..n].to_vec()),
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
        Ok(replies)
    }
}
