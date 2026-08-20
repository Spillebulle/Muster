//! Asking who hands out addresses, as the window sees it.
//!
//! [`muster_net::dhcp`] is the model and the wire format; this is the little
//! state machine that keeps the question off the interface thread. The probe
//! spends its whole life waiting on a socket for a fixed window, so running it
//! inline would freeze the window for as long as it listens.
//!
//! It is **not** run as part of a scan, and that is deliberate. A DISCOVER asks
//! every server on the link to reserve an address; it is cheap and harmless and
//! nothing takes the offer, but it is still a broadcast that makes servers do
//! work, and `CLAUDE.md`'s conduct rules make anything beyond looking a
//! deliberate act. So it has its own button.

use muster_net::dhcp::{self, Probe};
use muster_net::mac::MacAddr;
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

/// How long to listen for offers.
///
/// A server on a healthy link answers in milliseconds. The window is this long
/// because the *second* server is the one being looked for, and a rogue is
/// often a slow one: a small router doing NAT on a busy uplink, or a virtual
/// machine that has to be woken.
const WINDOW: Duration = Duration::from_secs(3);

pub enum State {
    Idle,
    Running(Receiver<Probe>),
    Done(Box<Probe>),
}

impl State {
    /// Send a DISCOVER and start listening.
    ///
    /// `mac` is this machine's, so the offers come back addressed to us rather
    /// than to a hardware address nothing on the link has.
    pub fn start(mac: MacAddr) -> Self {
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            // A fresh transaction id per probe, so a reply cannot be confused
            // with another client's negotiation happening at the same time. It
            // comes from the clock rather than from a counter: a predictable id
            // on a real network would collect somebody else's exchange.
            let xid = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0x4d75_7374, |d| d.subsec_nanos() ^ d.as_secs() as u32);
            let _ = tx.send(dhcp::probe(
                &muster_net::platform::udp::Dhcp,
                mac,
                xid,
                WINDOW,
            ));
        });
        Self::Running(rx)
    }

    /// Take the answer if it has arrived. True when something changed.
    pub fn poll(&mut self) -> bool {
        let Self::Running(rx) = self else {
            return false;
        };
        match rx.try_recv() {
            Ok(probe) => {
                *self = Self::Done(Box::new(probe));
                true
            }
            // The worker ended without answering, which can only be a panic in
            // it. Back to idle rather than a spinner that never stops.
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                *self = Self::Idle;
                true
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => false,
        }
    }

    pub fn is_running(&self) -> bool {
        matches!(self, Self::Running(_))
    }

    pub fn result(&self) -> Option<&Probe> {
        match self {
            Self::Done(probe) => Some(probe),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_idle_check_has_nothing_to_say() {
        let mut state = State::Idle;
        assert!(!state.poll());
        assert!(!state.is_running());
        assert!(state.result().is_none());
    }

    #[test]
    fn a_worker_that_vanished_does_not_leave_a_spinner_running() {
        // The channel is dropped without a probe being sent, which is what a
        // panicked worker looks like from here.
        let (tx, rx) = channel::<Probe>();
        drop(tx);
        let mut state = State::Running(rx);
        assert!(state.poll(), "the change is reported");
        assert!(!state.is_running(), "and it stops running");
    }

    #[test]
    fn the_window_is_long_enough_for_a_slow_second_server() {
        // The whole point is the *second* answer, which is often the slow one.
        assert!(WINDOW >= Duration::from_secs(2));
    }
}
