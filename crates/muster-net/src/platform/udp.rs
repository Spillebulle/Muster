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

        // 4 KiB holds any reply worth reading here. A device sending more is
        // sending a service list longer than anything is going to display, and
        // a truncated datagram parses as far as it goes.
        let mut buf = vec![0u8; 4096];
        let deadline = Instant::now() + timeout;
        loop {
            let (n, from) = socket.recv_from(&mut buf)?;
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
