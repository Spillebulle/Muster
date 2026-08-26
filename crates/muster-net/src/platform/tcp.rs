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
use std::io::{self, ErrorKind};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

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

/// The connection [`crate::service`] asks its questions on.
///
/// `std` and nothing else again, so it is the same code on both platforms and
/// needs no privileges: a connection out to somebody else's port is the one
/// thing every operating system lets an ordinary process do.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stream;

impl crate::service::Speak for Stream {
    fn speak(
        &self,
        to: SocketAddr,
        opening: &[u8],
        timeout: Duration,
        most: usize,
    ) -> io::Result<Vec<u8>> {
        use std::io::{Read, Write};

        let stream = TcpStream::connect_timeout(&to, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        // Nagle would hold a short opening back waiting for a second one that
        // is never coming. There is exactly one write per connection here.
        let _ = stream.set_nodelay(true);

        let mut stream = stream;
        if !opening.is_empty() {
            stream.write_all(opening)?;
        }

        // **One read, and a second only when the first was too short to read at
        // all.** Every answer this phase understands arrives in one segment: an
        // SSH greeting is a line, an RPC reply is forty bytes, and an SMB
        // header comes with its NetBIOS framing. Reading until the far end
        // closes would instead spend the whole timeout on every SSH server on
        // the network, because an SSH server does not close after greeting.
        let mut buf = vec![0u8; most];
        let mut got = 0;
        let deadline = Instant::now() + timeout;
        while got < ENOUGH {
            match stream.read(&mut buf[got..]) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => {
                    if got == 0 {
                        return Err(e);
                    }
                    break;
                }
            }
            if Instant::now() >= deadline {
                break;
            }
        }

        buf.truncate(got);
        if buf.is_empty() {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "the connection opened and nothing was said on it",
            ));
        }
        Ok(buf)
    }
}

/// How much of an answer is enough to stop reading.
///
/// The shortest thing any of the readers needs is an SMB header at eight bytes;
/// this is a little more, so a server that splits its framing from its header
/// is still read whole, and so short that no real answer needs a second pass.
const ENOUGH: usize = 32;
