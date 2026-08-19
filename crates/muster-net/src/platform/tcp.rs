//! The TCP knock, which is the same on every platform.
//!
//! It is `std` and nothing else, needs no privileges anywhere, and is the
//! bottom of the fallback ladder: whatever else a machine cannot do, it can
//! open a socket.
//!
//! The distinction this file exists to preserve is between a refusal and
//! silence. `connect` fails both ways and the difference is only in the error
//! kind, so flattening them into `Err` — which is the obvious way to write this
//! — loses the fact that a RST proves a host. That is the mistake
//! [`crate::discover`] is written to avoid, and this is where it would be made.

use crate::discover::Outcome;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

/// Connects far enough to learn how the address answers, then drops it.
///
/// The stream is closed immediately rather than shut down politely: this is a
/// liveness probe, nothing is going to be sent, and a FIN and a RST cost the
/// far end the same.
pub fn knock(address: IpAddr, port: u16, timeout: Duration) -> Outcome {
    match TcpStream::connect_timeout(&SocketAddr::new(address, port), timeout) {
        Ok(_) => Outcome::Open,
        Err(e) => match e.kind() {
            // A RST. Something is there and it said no.
            ErrorKind::ConnectionRefused => Outcome::Refused,

            // The host or the network said the address is unreachable. That is
            // a *router* speaking, not the host, so it is not evidence of a
            // host — but it is not silence either, and treating it as a refusal
            // would invent a device at every unused address behind a router
            // that answers ICMP unreachable. Silence is the honest reading.
            ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable => Outcome::NoAnswer,

            _ => Outcome::NoAnswer,
        },
    }
}
