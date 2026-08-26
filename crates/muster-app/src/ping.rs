//! Re-checking devices, one or many, once or until told to stop.
//!
//! The same division `scan.rs` and `ports.rs` keep: the state machine is here,
//! so what the interface *says* about a ping is decided in one place and can be
//! reasoned about without a window.
//!
//! Two rules from `CLAUDE.md` are the whole reason this is not a round trip in
//! a box.
//!
//! * **A probe that could not run says so, and never blames the device.** What
//!   is kept per device is the whole [`Recheck`] — the answer *and* the list of
//!   questions this machine could not ask. "Nothing came back this time" was
//!   printed once about a machine that was sitting there answering, because the
//!   ping socket was shut and nothing said so.
//! * **A result belongs to the device it is about.** Answers are kept in a map
//!   keyed by address rather than as "the last one", so pinging twenty devices
//!   fills twenty rows instead of overwriting one.
//!
//! A loop is the same run with a flag: the worker walks its targets, and where
//! it was asked to keep going it walks them again until it is cancelled. That
//! is what makes "ping until I stop it" one state rather than a second one to
//! keep in step with this.

use muster_net::discover::{self, Recheck};
use muster_net::rate::Bucket;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, channel};

/// How many devices are asked at once inside one run.
///
/// A re-check is a blocking wait on a socket that mostly sleeps, so this is the
/// sweep's reasoning rather than the processor's. It is small because the rate
/// limiter is the real budget and a wider pool would only queue against it.
const WORKERS: usize = 8;

/// A run in flight.
struct Run {
    /// Every device this run is about, so a row can say it is waiting.
    targets: Vec<IpAddr>,
    /// Keep going round until cancelled.
    looping: bool,
    cancel: Arc<AtomicBool>,
    rx: Receiver<(IpAddr, Recheck)>,
    /// Answers in this pass, for the progress line. Reset each time round.
    answered: usize,
    /// How many times round it has been. One is a single pass.
    passes: usize,
}

/// What the window holds: the last answer per device, and any run in flight.
#[derive(Default)]
pub struct State {
    /// The last answer about each device, by address.
    ///
    /// **Never cleared when a new run starts.** A device that answered a minute
    /// ago and is being asked again still has a last answer, and blanking the
    /// column at the start of every pass would make a loop flicker rather than
    /// update.
    answers: BTreeMap<IpAddr, Recheck>,
    run: Option<Run>,
}

impl State {
    /// Ask about these devices. `looping` keeps going until [`Self::cancel`].
    ///
    /// Starting a run replaces whatever was running, which is what makes the
    /// menu's "Ping" usable while a loop is going: the newer question is the
    /// one that was asked.
    pub fn start(&mut self, targets: Vec<IpAddr>, looping: bool, on_link: bool) {
        if targets.is_empty() {
            return;
        }
        self.cancel();

        let cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = channel();
        let worker_cancel = Arc::clone(&cancel);
        let list = targets.clone();

        std::thread::spawn(move || {
            let opts = if on_link {
                discover::Options::on_link()
            } else {
                discover::Options::default()
            };
            // One budget for the whole run, shared by every worker in it: a
            // loop over twenty devices must not send twenty times what one
            // device's re-check sends.
            let rate = Bucket::polite();
            let transport = muster_net::platform::Host;

            loop {
                let next = AtomicUsize::new(0);
                std::thread::scope(|scope| {
                    for _ in 0..WORKERS.min(list.len()) {
                        let (next, tx, rate, transport) = (&next, tx.clone(), &rate, &transport);
                        let cancel = &worker_cancel;
                        let list = &list;
                        scope.spawn(move || {
                            loop {
                                if cancel.load(Ordering::Relaxed) {
                                    break;
                                }
                                let i = next.fetch_add(1, Ordering::Relaxed);
                                let Some(&address) = list.get(i) else {
                                    break;
                                };
                                let answer = discover::recheck(address, transport, rate, opts);
                                // A closed channel is the window having gone
                                // away, which is the one reason to stop early.
                                if tx.send((address, answer)).is_err() {
                                    break;
                                }
                            }
                        });
                    }
                });
                if !looping || worker_cancel.load(Ordering::Relaxed) {
                    break;
                }
            }
        });

        self.run = Some(Run {
            targets,
            looping,
            cancel,
            rx,
            answered: 0,
            passes: 1,
        });
    }

    /// Stop at the next answer rather than at the end of a pass.
    pub fn cancel(&mut self) {
        if let Some(run) = &self.run {
            run.cancel.store(true, Ordering::SeqCst);
        }
        self.run = None;
    }

    /// Take whatever the worker has said. True when something moved, which is
    /// what tells the window to ask for another frame.
    pub fn poll(&mut self) -> bool {
        let Some(run) = &mut self.run else {
            return false;
        };
        let mut moved = false;
        let mut ended = false;
        loop {
            match run.rx.try_recv() {
                Ok((address, answer)) => {
                    self.answers.insert(address, answer);
                    run.answered += 1;
                    if run.answered >= run.targets.len() {
                        // Round again, or done. A single pass ends here; a loop
                        // starts counting the next one.
                        if run.looping {
                            run.answered = 0;
                            run.passes += 1;
                        } else {
                            ended = true;
                        }
                    }
                    moved = true;
                }
                // The worker ended without saying so, which can only be a panic
                // in it. Stop waiting rather than leaving a row saying "asking"
                // for the rest of the session, and blame the probe rather than
                // the device.
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    for address in &run.targets {
                        self.answers.entry(*address).or_insert_with(|| Recheck {
                            found: None,
                            not_done: vec!["the probe did not finish".into()],
                        });
                    }
                    ended = true;
                    moved = true;
                    break;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
            }
        }
        if ended {
            self.run = None;
        }
        moved
    }

    pub fn is_running(&self) -> bool {
        self.run.is_some()
    }

    /// Is a run going that will keep going?
    pub fn is_looping(&self) -> bool {
        self.run.as_ref().is_some_and(|r| r.looping)
    }

    /// How many devices this run is about, and how many have answered in the
    /// pass it is on. [`None`] when nothing is running.
    pub fn progress(&self) -> Option<(usize, usize, usize)> {
        let run = self.run.as_ref()?;
        Some((run.answered, run.targets.len(), run.passes))
    }

    /// Is this device one the run is waiting on?
    pub fn waiting_for(&self, address: IpAddr) -> bool {
        self.run
            .as_ref()
            .is_some_and(|r| r.targets.contains(&address))
    }

    /// The last answer about one device.
    pub fn answer_for(&self, address: IpAddr) -> Option<&Recheck> {
        self.answers.get(&address)
    }

    /// The round trip to show in a table cell: the last ping's, where the last
    /// ping got one.
    ///
    /// [`None`] covers both "never asked" and "asked and nothing came back",
    /// which the cell tells apart by asking [`Self::answer_for`] as well. A
    /// function returning a duration alone would have nowhere to say which.
    pub fn rtt_for(&self, address: IpAddr) -> Option<std::time::Duration> {
        self.answers.get(&address)?.found.as_ref()?.rtt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    /// Nothing is asked about nobody. The menu can offer "Ping" with no device
    /// marked, and this is what keeps that from spawning a thread with no work
    /// and a state that never ends.
    #[test]
    fn a_run_over_no_devices_is_not_a_run() {
        let mut state = State::default();
        state.start(Vec::new(), false, true);
        assert!(!state.is_running());
        assert!(!state.poll());
    }

    /// An idle state answers about nothing, rather than about the last device
    /// somebody happened to ask about.
    #[test]
    fn an_idle_state_has_no_answers() {
        let state = State::default();
        assert!(state.answer_for(ip("192.168.0.1")).is_none());
        assert!(state.rtt_for(ip("192.168.0.1")).is_none());
        assert!(!state.waiting_for(ip("192.168.0.1")));
        assert_eq!(state.progress(), None);
    }

    /// Cancelling nothing is harmless: the control is drawn from the same state
    /// that decides whether it does anything.
    #[test]
    fn cancelling_nothing_is_harmless() {
        State::default().cancel();
    }

    /// The distinction the whole module exists for: a device that did not
    /// answer is not the same as a probe that was never sent, and the round
    /// trip alone cannot tell them apart.
    #[test]
    fn silence_and_a_question_never_asked_are_different_answers() {
        let mut state = State::default();
        let quiet = ip("192.168.0.2");
        state.answers.insert(
            quiet,
            Recheck {
                found: None,
                not_done: Vec::new(),
            },
        );
        let unasked = ip("192.168.0.3");
        state.answers.insert(
            unasked,
            Recheck {
                found: None,
                not_done: vec!["no echo was sent".into()],
            },
        );

        assert_eq!(state.rtt_for(quiet), None);
        assert_eq!(state.rtt_for(unasked), None);
        assert!(
            state
                .answer_for(quiet)
                .is_some_and(|r| r.not_done.is_empty())
        );
        assert!(
            state
                .answer_for(unasked)
                .is_some_and(|r| !r.not_done.is_empty()),
            "and the one that could not be asked still says so"
        );
    }
}
