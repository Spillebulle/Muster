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
use std::time::{Duration, Instant};

/// How long a loop waits between passes, unless told otherwise.
///
/// **A loop used to have no interval at all**, which is not a detail: the rate
/// limiter was the only thing pacing it, so one device on a fast link was
/// re-probed as quickly as the bucket would refill — over a hundred times a
/// second. That is a scan of one address at flood rate, it looks exactly like
/// the thing `CLAUDE.md` says a scanner must never be mistaken for, and it
/// tells the reader nothing a probe every half second does not.
///
/// Half a second is the interval between passes rather than between probes, so
/// a loop over twenty devices that takes longer than this to get round simply
/// goes again at once: the rule is "no faster than this", not "exactly this".
pub const EVERY: Duration = Duration::from_millis(500);

/// The shortest and longest a loop may be paced at.
///
/// The floor is not zero and never should be: this is the setting that used to
/// be absent, and an interval of nothing is the defect it was added to fix.
pub const FASTEST: Duration = Duration::from_millis(200);
pub const SLOWEST: Duration = Duration::from_secs(10);

/// How many results are kept per device.
///
/// Enough to fill the panel's history column several times over, so scrolling
/// back through a loop that has been running a few minutes reaches something.
/// Bounded because a loop left running overnight would otherwise be a leak.
pub const REMEMBERED: usize = 512;

/// One re-check, kept for the history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sample {
    /// When it was taken, as the window's own clock reads.
    pub at: Instant,
    /// The round trip, where one was measured. [`None`] is a device that did
    /// not answer *or* a probe that could not be sent, and the two are told
    /// apart by [`Self::asked`].
    pub rtt: Option<Duration>,
    /// The probe actually went out. False is this machine's failing rather than
    /// the device's, and the history must not draw it as a lost packet.
    pub asked: bool,
}

/// What a history says, taken together.
///
/// **Three counts, not two, and that is the whole design of this struct.** A
/// history holds probes that were answered, probes that were sent and came back
/// with nothing, and probes this machine could not send at all, and the third is
/// not a lost packet. `CLAUDE.md`'s rule about `discover::recheck` is that a
/// question never asked must never be reported as a device's silence, and loss
/// is where that rule turns into arithmetic: **the readings that could not be
/// asked are outside the denominator**, so a machine with its ping sockets shut
/// reports that nothing was sent rather than "100% lost", which would be Muster
/// blaming a device for a question it never put to it.
///
/// Everything here is a fact about the readings kept. Nothing is scored, and
/// there is no threshold at which a figure becomes a verdict.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Probes that actually went out.
    pub sent: usize,
    /// Probes that came back with a round trip.
    pub answered: usize,
    /// Probes this machine could not send. See [`Sample::asked`].
    pub unasked: usize,
    /// The shortest round trip measured.
    pub best: Option<Duration>,
    /// The mean of the round trips measured.
    ///
    /// Over the answers alone: a silence has no duration, and counting it as
    /// zero would flatter exactly the links that drop packets.
    pub mean: Option<Duration>,
    pub worst: Option<Duration>,
    /// How far a round trip sits from the mean, on average.
    ///
    /// The **mean absolute deviation**, which is deliberately not the figure
    /// `iputils` prints in its `mdev` column: that one is a standard deviation
    /// wearing a similar name. Both describe the same spread and they are not
    /// the same number, so this says which it is rather than leaving somebody
    /// to compare the two and conclude that one of the tools is broken.
    pub jitter: Option<Duration>,
}

impl Stats {
    /// Folds a history down. Arithmetic over readings already taken, so it
    /// sends nothing and can be called every frame.
    pub fn of(samples: &[Sample]) -> Self {
        let mut stats = Self::default();
        let mut trips: Vec<f64> = Vec::with_capacity(samples.len());
        for sample in samples {
            // The one branch this whole struct is about: a probe that never
            // went out is counted on its own and is not a probe.
            if !sample.asked {
                stats.unasked += 1;
                continue;
            }
            stats.sent += 1;
            if let Some(rtt) = sample.rtt {
                stats.answered += 1;
                trips.push(rtt.as_secs_f64());
            }
        }

        if trips.is_empty() {
            return stats;
        }
        let mean = trips.iter().sum::<f64>() / trips.len() as f64;
        let spread = trips.iter().map(|t| (t - mean).abs()).sum::<f64>() / trips.len() as f64;
        stats.best = trips.iter().copied().reduce(f64::min).map(seconds);
        stats.worst = trips.iter().copied().reduce(f64::max).map(seconds);
        stats.mean = Some(seconds(mean));
        stats.jitter = Some(seconds(spread));
        stats
    }

    /// Everything kept, asked or not.
    pub fn kept(self) -> usize {
        self.sent + self.unasked
    }

    /// Probes that went out and were not answered.
    pub fn lost(self) -> usize {
        self.sent - self.answered
    }

    /// Loss as a percentage **of the probes that were actually sent**.
    ///
    /// [`None`] when none were, which is the case this returns an option for: a
    /// percentage over no probes is not zero, it is nothing at all, and a panel
    /// showing "0% lost" about a machine that could not send a single echo is
    /// the lie the amber reading exists to prevent.
    pub fn loss(self) -> Option<f32> {
        (self.sent > 0).then(|| self.lost() as f32 / self.sent as f32 * 100.0)
    }

    /// The counts, said out loud, in the order somebody reads them.
    ///
    /// The probes that could not be asked are named rather than folded in, and
    /// the percentage is absent rather than zero where nothing was sent.
    pub fn counts(self) -> String {
        if self.kept() == 0 {
            return "nothing kept yet".to_string();
        }
        let mut line = format!("{} sent, {} answered", self.sent, self.answered);
        if let Some(loss) = self.loss() {
            line = format!("{line}, {}% lost", loss.round() as u32);
        }
        if self.unasked > 0 {
            line = format!("{line}, {} this machine could not ask", self.unasked);
        }
        line
    }

    /// The round trips, where any were measured.
    ///
    /// [`None`] is a history with no answer in it, and the caller says nothing
    /// rather than drawing a row of zeroes.
    pub fn round_trips(self) -> Option<String> {
        let (best, mean, worst, jitter) = (self.best?, self.mean?, self.worst?, self.jitter?);
        Some(format!(
            "best {} ms, mean {} ms, worst {} ms, jitter {} ms",
            millis(best),
            millis(mean),
            millis(worst),
            millis(jitter)
        ))
    }
}

/// Seconds back into a duration, saturating rather than panicking on the
/// nonsense a negative would be.
fn seconds(value: f64) -> Duration {
    Duration::try_from_secs_f64(value.max(0.0)).unwrap_or_default()
}

/// Milliseconds to one decimal, because a wired link answers in less than one
/// and whole milliseconds would round every device on it to the same figure.
fn millis(value: Duration) -> String {
    format!("{:.1}", value.as_secs_f64() * 1000.0)
}

/// How long a paced loop sleeps between looks at the cancel flag.
const TICK: Duration = Duration::from_millis(25);

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
    /// Devices this run has heard from at all, so a row that has answered once
    /// stops saying it is waiting. See [`State::waiting_for`].
    heard: std::collections::BTreeSet<IpAddr>,
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
    /// Every result kept, per device, oldest first and capped at
    /// [`REMEMBERED`].
    ///
    /// Kept beside `answers` rather than derived from it because the two answer
    /// different questions: the table wants the latest reading and the panel
    /// wants the shape of the last few minutes. A loop that has been running is
    /// the only way to get the second, and throwing it away when the loop stops
    /// would make the history useless exactly when somebody wants to read it.
    history: BTreeMap<IpAddr, Vec<Sample>>,
    run: Option<Run>,
}

impl State {
    /// Ask about these devices. `looping` keeps going until [`Self::cancel`].
    ///
    /// Starting a run replaces whatever was running, which is what makes the
    /// menu's "Ping" usable while a loop is going: the newer question is the
    /// one that was asked.
    pub fn start(&mut self, targets: Vec<IpAddr>, looping: bool, on_link: bool) {
        self.start_every(targets, looping, on_link, EVERY);
    }

    /// The same, paced at a stated interval. See [`EVERY`].
    pub fn start_every(
        &mut self,
        targets: Vec<IpAddr>,
        looping: bool,
        on_link: bool,
        every: Duration,
    ) {
        if targets.is_empty() {
            return;
        }
        self.cancel();
        let every = every.clamp(FASTEST, SLOWEST);

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
                let began = Instant::now();
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
                // **The pause that makes this a loop rather than a flood.**
                // Measured from the start of the pass, so the interval is the
                // period and not an extra delay on top of however long the
                // probes took: a pass that already took longer than `every`
                // goes again at once. Slept in slices, because a loop that
                // ignores the cancel flag for half a second is a Stop button
                // that does not feel like one.
                while began.elapsed() < every {
                    if worker_cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    std::thread::sleep(TICK.min(every - began.elapsed()));
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
            heard: Default::default(),
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
                    // Kept before it is moved into `answers`, so the history is
                    // the same reading the table shows and cannot drift from
                    // it.
                    let sample = Sample {
                        at: Instant::now(),
                        rtt: answer.found.as_ref().and_then(|f| f.rtt),
                        asked: answer.not_done.is_empty(),
                    };
                    let kept = self.history.entry(address).or_default();
                    kept.push(sample);
                    if kept.len() > REMEMBERED {
                        // The oldest go first. A `Vec` rather than a deque
                        // because the panel reads it as a slice and this
                        // happens once every few hundred probes.
                        kept.drain(..kept.len() - REMEMBERED);
                    }
                    self.answers.insert(address, answer);
                    run.heard.insert(address);
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

    /// Is this device one the run has yet to hear from at all?
    ///
    /// **Only until its first answer, and that is the whole of the fix.** This
    /// used to be true for every target for as long as the run lasted, so a
    /// loop over twenty devices showed twenty rows saying "asking…" from the
    /// first probe to the last — the answers were arriving and being written
    /// down, and the column was covering them up. Two complaints came out of
    /// one line: results that seemed to wait for the whole group, and a column
    /// that never showed anything but "asking" once a loop was going.
    ///
    /// So a device is "waiting" only before it has said anything in this run.
    /// After that its last reading stands, including "no reply", until the next
    /// one replaces it. A row never goes backwards to a blank.
    pub fn waiting_for(&self, address: IpAddr) -> bool {
        self.run
            .as_ref()
            .is_some_and(|r| r.targets.contains(&address) && !r.heard.contains(&address))
    }

    /// Is a loop running that includes this device?
    ///
    /// What the panel's button asks before deciding whether it offers to start
    /// one or to stop one. A loop the table's menu started over twenty devices
    /// counts: the reader is looking at one of the twenty, the button they can
    /// see is stopping the thing that is happening, and a panel that offered to
    /// "keep pinging" a device already being pinged would be lying about the
    /// state of the machine.
    pub fn loops_for(&self, address: IpAddr) -> bool {
        self.run
            .as_ref()
            .is_some_and(|r| r.looping && r.targets.contains(&address))
    }

    /// Everything kept about one device, oldest first.
    pub fn history_for(&self, address: IpAddr) -> &[Sample] {
        self.history.get(&address).map_or(&[], Vec::as_slice)
    }

    /// What that history adds up to. See [`Stats`], and in particular what is
    /// and is not in the loss denominator.
    pub fn stats_for(&self, address: IpAddr) -> Stats {
        Stats::of(self.history_for(address))
    }

    /// Puts a made-up history in, for `examples/docs-images.rs`.
    ///
    /// The pictures in the README are taken by the real interface — see that
    /// example's note — and a history is the one thing on the device window
    /// that cannot be seeded by handing the app a finished scan, because it is
    /// made by probing. Each entry is a round trip in milliseconds and whether
    /// the probe went out at all; a zero round trip that *was* asked is a
    /// device that did not answer.
    pub fn seed(&mut self, address: IpAddr, samples: &[(u64, bool)]) {
        let now = Instant::now();
        let kept: Vec<Sample> = samples
            .iter()
            .enumerate()
            .map(|(i, &(ms, asked))| Sample {
                at: now + Duration::from_millis(i as u64 * 500),
                rtt: (ms > 0).then(|| Duration::from_millis(ms)),
                asked,
            })
            .collect();
        self.history.insert(address, kept);
    }

    /// Forgets one device's history, for the panel's own control.
    pub fn forget(&mut self, address: IpAddr) {
        self.history.remove(&address);
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

    /// A state with a run in flight, without starting a thread.
    ///
    /// The tests below are about what the *window* is told while a run is on,
    /// which is a question about this file's bookkeeping and not about probing.
    /// Building the run directly is what keeps them from needing a network.
    fn running(targets: &[IpAddr], looping: bool) -> State {
        State {
            run: Some(Run {
                targets: targets.to_vec(),
                looping,
                cancel: Arc::new(AtomicBool::new(false)),
                rx: channel().1,
                answered: 0,
                passes: 1,
                heard: Default::default(),
            }),
            ..Default::default()
        }
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

    /// **The defect that made a loop unreadable.** Every target used to be
    /// "waiting" for as long as the run lasted, so the answers arrived, were
    /// written down, and were covered up by a column saying "asking…". A device
    /// is waiting only until it has said something.
    #[test]
    fn a_device_stops_waiting_once_it_has_answered() {
        let one = ip("192.168.0.2");
        let two = ip("192.168.0.3");
        let mut state = running(&[one, two], true);

        assert!(state.waiting_for(one));
        assert!(state.waiting_for(two));

        if let Some(run) = &mut state.run {
            run.heard.insert(one);
        }
        assert!(
            !state.waiting_for(one),
            "it has answered, so it is not waiting"
        );
        assert!(state.waiting_for(two), "and its neighbour still is");
    }

    /// A device nothing is asking about is not waiting for anything.
    #[test]
    fn a_device_no_run_is_about_is_never_waiting() {
        let state = running(&[ip("192.168.0.2")], false);
        assert!(!state.waiting_for(ip("192.168.0.9")));
        assert!(
            !state.loops_for(ip("192.168.0.2")),
            "this run is not a loop"
        );
    }

    /// An interval of nothing is what the flood was. The floor is not
    /// negotiable, and neither is the ceiling.
    #[test]
    fn a_loop_is_never_paced_faster_than_the_floor() {
        for asked in [Duration::ZERO, Duration::from_millis(1), FASTEST] {
            assert_eq!(asked.clamp(FASTEST, SLOWEST), FASTEST, "{asked:?}");
        }
        assert_eq!(Duration::from_secs(600).clamp(FASTEST, SLOWEST), SLOWEST);
        assert_eq!(
            EVERY.clamp(FASTEST, SLOWEST),
            EVERY,
            "the default is inside"
        );
    }

    /// History is kept per device, oldest first, and bounded.
    #[test]
    fn history_is_kept_per_device_and_bounded() {
        let mut state = State::default();
        let one = ip("192.168.0.2");
        let two = ip("192.168.0.3");
        state.seed(one, &[(1, true), (0, true), (3, false)]);
        state.seed(two, &[(7, true)]);

        let kept = state.history_for(one);
        assert_eq!(kept.len(), 3);
        assert_eq!(kept[0].rtt, Some(Duration::from_millis(1)));
        assert_eq!(kept[1].rtt, None, "a zero round trip is no reply");
        assert!(kept[1].asked, "and it was asked");
        assert!(!kept[2].asked, "where this one was not");
        assert_eq!(state.history_for(two).len(), 1);
        assert!(state.history_for(ip("192.168.0.9")).is_empty());

        state.forget(one);
        assert!(state.history_for(one).is_empty());
        assert_eq!(state.history_for(two).len(), 1, "and only that one");
    }

    /// Cancelling nothing is harmless: the control is drawn from the same state
    /// that decides whether it does anything.
    #[test]
    fn cancelling_nothing_is_harmless() {
        State::default().cancel();
    }

    /// **The rule the statistics exist to keep.** Three of these probes went
    /// out and one of them was never sent, so the loss is one in three and not
    /// one in four: a probe this machine could not send is not a probe the
    /// device failed to answer.
    #[test]
    fn a_probe_that_was_never_sent_is_outside_the_loss() {
        let mut state = State::default();
        let one = ip("192.168.0.2");
        state.seed(one, &[(10, true), (0, true), (20, true), (0, false)]);

        let stats = state.stats_for(one);
        assert_eq!(stats.kept(), 4, "four readings are kept");
        assert_eq!(stats.sent, 3, "three of them were sent");
        assert_eq!(stats.answered, 2);
        assert_eq!(stats.unasked, 1);
        assert_eq!(stats.lost(), 1);
        let loss = stats.loss().expect("something was sent");
        assert!(
            (loss - 100.0 / 3.0).abs() < 0.01,
            "one lost in three sent, not one in four kept: {loss}"
        );
        assert!(
            stats.counts().contains("this machine could not ask"),
            "and the count that is outside the denominator is named: {}",
            stats.counts()
        );
    }

    /// A machine whose ping sockets are shut has lost nothing, because it sent
    /// nothing. A percentage here would be the application blaming the device.
    #[test]
    fn nothing_sent_is_not_a_hundred_percent_lost() {
        let mut state = State::default();
        let quiet = ip("192.168.0.3");
        state.seed(quiet, &[(0, false), (0, false)]);

        let stats = state.stats_for(quiet);
        assert_eq!(stats.sent, 0);
        assert_eq!(stats.unasked, 2);
        assert_eq!(stats.loss(), None, "no denominator, so no percentage");
        assert!(
            !stats.counts().contains('%'),
            "and none is printed either: {}",
            stats.counts()
        );
        assert_eq!(stats.round_trips(), None, "and nothing was measured");
    }

    /// An empty history says so rather than reporting a perfect link.
    #[test]
    fn an_empty_history_reports_nothing_rather_than_zero() {
        let stats = State::default().stats_for(ip("192.168.0.4"));
        assert_eq!(stats, Stats::default());
        assert_eq!(stats.loss(), None);
        assert_eq!(stats.counts(), "nothing kept yet");
    }

    /// The spread is over the answers alone. A silence has no duration, and
    /// folding it in as zero would make a dropping link look steadier than a
    /// clean one.
    #[test]
    fn the_round_trips_are_the_answers_and_only_the_answers() {
        let mut state = State::default();
        let one = ip("192.168.0.5");
        // 10 ms, 20 ms and 30 ms answered, one silence, one never asked.
        state.seed(
            one,
            &[(10, true), (0, true), (20, true), (30, true), (0, false)],
        );

        let stats = state.stats_for(one);
        assert_eq!(stats.best, Some(Duration::from_millis(10)));
        assert_eq!(stats.worst, Some(Duration::from_millis(30)));
        assert_eq!(stats.mean, Some(Duration::from_millis(20)));
        // Mean absolute deviation of 10, 20, 30 about 20 is (10 + 0 + 10) / 3.
        let jitter = stats.jitter.expect("three answers have a spread");
        assert!(
            (jitter.as_secs_f64() - 0.020 / 3.0).abs() < 1e-9,
            "{jitter:?}"
        );
        let line = stats.round_trips().expect("something answered");
        assert!(line.contains("best 10.0 ms"), "{line}");
        assert!(line.contains("worst 30.0 ms"), "{line}");
    }

    /// One answer has no spread, and the figure is zero rather than absent:
    /// there was something to measure and it did not vary.
    #[test]
    fn a_single_answer_has_no_spread() {
        let mut state = State::default();
        let one = ip("192.168.0.6");
        state.seed(one, &[(7, true)]);
        let stats = state.stats_for(one);
        assert_eq!(stats.jitter, Some(Duration::ZERO));
        assert_eq!(stats.loss(), Some(0.0), "it was asked, and it answered");
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
