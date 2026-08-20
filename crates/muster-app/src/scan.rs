//! The scan, as the window sees it.
//!
//! A scan runs on its own thread and reports through a channel; the window
//! polls that channel each frame. This module holds the state machine so that
//! what the interface *says* about a scan is decided in one place and can be
//! reasoned about without a window — the same division `CLAUDE.md` describes
//! for Umber's update dialog, where the model is one file and the drawing is
//! another.
//!
//! Two rules from `CLAUDE.md` live here rather than in the painting:
//!
//! * **A scan in progress is a normal state, not a modal.** So [`State`] is a
//!   field of the app rather than something that blocks it, results arrive
//!   incrementally, and cancelling is available throughout.
//! * **Progress over a known total is reported; anything else leaves the bar
//!   empty.** [`Phase::fraction`] returns an [`Option`], and the sweep is the
//!   only phase that can fill it in — the survey is instant and identification
//!   is counted but so short that a bar for it would be a flicker.

use muster_net::discover::{self, Found};
use muster_net::identify::{self, Identity};
use muster_net::rate::Bucket;
use muster_net::{Prefix, Survey};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};

/// What the scan thread reports.
pub enum Update {
    Swept {
        probed: u64,
        total: u64,
        found: u64,
        /// The device this probe found, where it found one.
        ///
        /// Carried so the table can fill as the sweep runs. `CLAUDE.md` asks
        /// for results to arrive incrementally, and this is what makes that
        /// true of the devices themselves rather than only of the counter.
        hit: Option<Box<Found>>,
    },
    Identifying {
        done: usize,
        total: usize,
    },
    /// The whole result. Sent once, at the end, cancelled or not.
    Done(Box<Outcome>),
}

/// A finished scan.
pub struct Outcome {
    pub sweep: discover::Sweep,
    pub names: Vec<Identity>,
    pub prefix: Prefix,
}

/// Which part of a scan is running.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Sweeping { probed: u64, total: u64 },
    Identifying { done: usize, total: usize },
}

impl Phase {
    /// How far along, where that is knowable.
    ///
    /// Always knowable here, because both phases count over a total decided
    /// before they start. The [`Option`] is kept because the moment a phase
    /// arrives that cannot count — a passive listen, a continuous monitor — the
    /// bar must draw empty rather than animate, and a function returning `f32`
    /// would have nowhere to say so.
    pub fn fraction(self) -> Option<f32> {
        match self {
            Self::Sweeping { probed, total } if total > 0 => Some(probed as f32 / total as f32),
            Self::Identifying { done, total } if total > 0 => Some(done as f32 / total as f32),
            _ => None,
        }
    }

    pub fn label(self) -> String {
        match self {
            Self::Sweeping { probed, total } => format!("Sweeping {probed} of {total}"),
            Self::Identifying { done, total } => format!("Identifying {done} of {total}"),
        }
    }
}

/// The scan as the window holds it.
pub enum State {
    Idle,
    Running {
        phase: Phase,
        found: u64,
        /// Devices found so far, in the order they answered.
        ///
        /// **Kept here rather than waited for.** The table reads this while the
        /// sweep runs, so a device appears the moment it answers instead of
        /// when the last address in the prefix has been probed. On a /24 that
        /// is a few seconds; on anything larger it is the difference between a
        /// tool that is working and a tool that has hung.
        devices: Vec<Found>,
        cancel: Arc<AtomicBool>,
        rx: Receiver<Update>,
    },
    Finished(Box<Outcome>),
}

impl State {
    pub fn is_running(&self) -> bool {
        matches!(self, Self::Running { .. })
    }

    /// Starts a scan of one prefix.
    pub fn start(survey: &Survey, prefix: Prefix, on_link: bool) -> Self {
        let (tx, rx) = channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let resolver = survey.resolvers.iter().copied().find(|a| a.is_ipv4());

        {
            let cancel = Arc::clone(&cancel);
            std::thread::spawn(move || run(prefix, on_link, resolver, cancel, tx));
        }

        Self::Running {
            phase: Phase::Sweeping {
                probed: 0,
                total: prefix.host_count(),
            },
            found: 0,
            devices: Vec::new(),
            cancel,
            rx,
        }
    }

    /// Drains whatever the thread has said. Returns true when something moved,
    /// which is what tells the window to ask for another frame.
    pub fn poll(&mut self) -> bool {
        let mut moved = false;
        let mut finished = None;

        if let Self::Running {
            phase,
            found,
            devices,
            rx,
            ..
        } = self
        {
            loop {
                match rx.try_recv() {
                    Ok(Update::Swept {
                        probed,
                        total,
                        found: f,
                        hit,
                    }) => {
                        *phase = Phase::Sweeping { probed, total };
                        *found = f;
                        if let Some(device) = hit {
                            devices.push(*device);
                        }
                        moved = true;
                    }
                    Ok(Update::Identifying { done, total }) => {
                        *phase = Phase::Identifying { done, total };
                        moved = true;
                    }
                    Ok(Update::Done(outcome)) => {
                        finished = Some(outcome);
                        moved = true;
                        break;
                    }
                    // Disconnected without a result means the thread died,
                    // which can only be a panic in it.
                    //
                    // **This must return to idle, and for a while it said so
                    // and did not.** The comment here described the behaviour
                    // and the code only broke out of the loop, leaving `self`
                    // in `Running`: the bar sat at "Sweeping n of m" for ever,
                    // Stop did nothing anybody could see, the Scan button stayed
                    // unreachable because `scan_control` returns early while a
                    // scan is running, and the window asked for a repaint every
                    // 60 ms for the rest of the session. `ports.rs` and
                    // `dhcpcheck.rs` both handle this correctly, which is what
                    // makes the omission plainly accidental rather than a
                    // decision.
                    //
                    // No outcome is invented: idle is "no scan", which is what
                    // is true, where an empty `Finished` would claim the network
                    // was swept and found nothing.
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        *self = Self::Idle;
                        return true;
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                }
            }
        }

        if let Some(outcome) = finished {
            *self = Self::Finished(outcome);
        }
        moved
    }

    /// Asks the scan to stop. It stops at the next probe rather than at the end
    /// of a phase, which is `CLAUDE.md`'s rule.
    pub fn cancel(&self) {
        if let Self::Running { cancel, .. } = self {
            cancel.store(true, Ordering::SeqCst);
        }
    }

    /// The devices to show: the finished ones, or nothing yet.
    /// Every device known so far, finished or not.
    ///
    /// While a sweep runs this is what has answered up to now; once it ends it
    /// is the sweep's own list. Both are "what Muster has found", which is the
    /// only thing the table ever wants.
    pub fn devices(&self) -> &[Found] {
        match self {
            Self::Finished(o) => &o.sweep.found,
            Self::Running { devices, .. } => devices,
            Self::Idle => &[],
        }
    }

    /// Record what a port scan found, so identification can use it.
    ///
    /// **Without this the port half of `kind::identify` is dead code.** The
    /// only producer of `Evidence::TcpOpen` in the engine is the sweep's knock,
    /// which tries 80, 443, 22 and 445 — and `kind`'s port table deliberately
    /// excludes exactly those four, because they are on everything and name
    /// nothing. So the ports that *do* name a kind (9100 a printer, 32400 a
    /// Plex server, 554 a camera) were never in the evidence a guess was made
    /// from, and a device stayed `Unknown` even after the user had run a port
    /// scan and could see 9100 open in the panel.
    ///
    /// Folding the result back into the device's own evidence is what closes
    /// that, and it keeps the existing rule intact: the guess is still made
    /// from evidence attached to the device, and the row's tooltip still names
    /// the clue.
    pub fn record_open_ports(&mut self, address: IpAddr, open: &[u16]) {
        let devices = match self {
            Self::Finished(outcome) => &mut outcome.sweep.found,
            Self::Running { devices, .. } => devices,
            Self::Idle => return,
        };
        let Some(device) = devices.iter_mut().find(|d| d.address == address) else {
            return;
        };
        for port in open {
            let evidence = muster_net::discover::Evidence::TcpOpen(*port);
            if !device.evidence.contains(&evidence) {
                device.evidence.push(evidence);
            }
        }
    }

    /// The names learned, parallel to [`Self::devices`].
    ///
    /// Empty while a sweep is running: identification is phase four and has not
    /// started yet, so a device on screen mid-scan has an address and no name.
    /// That is honest — the alternative is holding the whole table back until
    /// every name is in.
    pub fn names(&self) -> &[Identity] {
        match self {
            Self::Finished(o) => &o.names,
            _ => &[],
        }
    }
}

fn run(
    prefix: Prefix,
    on_link: bool,
    resolver: Option<std::net::IpAddr>,
    cancel: Arc<AtomicBool>,
    tx: Sender<Update>,
) {
    let transport = muster_net::platform::Host;
    let rate = Bucket::polite();
    let opts = if on_link {
        discover::Options::on_link()
    } else {
        discover::Options::default()
    };

    let sweep = discover::sweep(prefix, &transport, &rate, opts, &cancel, &|p, hit| {
        let _ = tx.send(Update::Swept {
            probed: p.probed,
            total: p.total,
            found: p.found,
            hit: hit.cloned().map(Box::new),
        });
    });

    let addresses: Vec<_> = sweep.found.iter().map(|f| f.address).collect();
    let names = identify::many(
        &addresses,
        &muster_net::platform::udp::Udp,
        &rate,
        identify::Options {
            resolver,
            ..Default::default()
        },
        &cancel,
        &|done, total| {
            let _ = tx.send(Update::Identifying { done, total });
        },
    );

    let _ = tx.send(Update::Done(Box::new(Outcome {
        sweep,
        names,
        prefix,
    })));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rule: a bar over an unknown total draws empty rather than animating.
    /// Both phases can count today, so the guard is what keeps the next one
    /// honest.
    #[test]
    fn progress_over_nothing_is_not_a_fraction() {
        assert_eq!(
            Phase::Sweeping {
                probed: 0,
                total: 0
            }
            .fraction(),
            None
        );
        assert_eq!(Phase::Identifying { done: 3, total: 0 }.fraction(), None);
    }

    #[test]
    fn progress_over_a_known_total_is_reported() {
        assert_eq!(
            Phase::Sweeping {
                probed: 127,
                total: 254
            }
            .fraction(),
            Some(0.5)
        );
        assert_eq!(
            Phase::Identifying { done: 1, total: 4 }.fraction(),
            Some(0.25)
        );
    }

    #[test]
    fn a_phase_says_what_it_is_doing() {
        assert_eq!(
            Phase::Sweeping {
                probed: 10,
                total: 254
            }
            .label(),
            "Sweeping 10 of 254"
        );
        assert_eq!(
            Phase::Identifying { done: 2, total: 9 }.label(),
            "Identifying 2 of 9"
        );
    }

    /// An idle or running scan shows no devices rather than a stale list from
    /// the run before, which would be the wrong network entirely after the
    /// target changed.
    #[test]
    fn only_a_finished_scan_has_devices() {
        assert!(State::Idle.devices().is_empty());
        assert!(State::Idle.names().is_empty());
        assert!(!State::Idle.is_running());
    }

    /// Cancelling an idle scan is a no-op rather than a panic: the button is
    /// drawn from the same state that decides whether it does anything.
    #[test]
    fn cancelling_nothing_is_harmless() {
        State::Idle.cancel();
    }
}
