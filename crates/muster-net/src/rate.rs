//! The rate limiter every probe passes through.
//!
//! `CLAUDE.md` makes this a rule rather than a setting: a scanner that sends as
//! fast as it can is indistinguishable from an attack, is dropped by any switch
//! with storm control, and produces false negatives that look like an empty
//! network. So there is one token bucket, every sender takes from it, and the
//! default is well below what the link would carry.
//!
//! It is a bucket rather than a sleep between packets because a scan is bursty
//! by nature — a sweep of 254 addresses wants to go out in one breath and then
//! wait for replies — and a fixed delay turns that into 254 sequential waits.
//! The burst is capped so "bursty" cannot become "all of it at once".
//!
//! ## The clock is injected
//!
//! [`Bucket::with_clock`] takes the time source, so the tests advance time by
//! hand and finish instantly. A rate limiter tested with real sleeps is a test
//! suite that takes minutes and a limiter nobody re-tests after changing.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Probes per second the default scan is willing to send.
///
/// 1 000 is roughly 40 kB/s of ARP or bare SYNs: invisible on any modern
/// switch, and it sweeps a /24 in a quarter of a second. It is not the fastest
/// this can go and is not meant to be — the fast path is a decision the user
/// makes about a network they own.
pub const DEFAULT_RATE: u32 = 1_000;

/// The most probes that may leave back to back before the bucket has to refill.
///
/// One breath's worth of a /24. Larger and a sweep arrives as a single burst
/// that looks exactly like the thing storm control exists to stop.
pub const DEFAULT_BURST: u32 = 256;

/// The longest a cancellable wait sleeps without looking at the flag.
///
/// Short enough that Stop is felt as immediate and long enough that a slow
/// rate is not a spin loop: a one-per-second bucket wakes fifty times over a
/// wait instead of once, which is nothing beside the packet it is not sending.
const CANCEL_TICK: Duration = Duration::from_millis(20);

/// Where the current time comes from. Real time in the application, a counter
/// in the tests.
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

/// The system clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// A token bucket, shared by every thread that sends.
pub struct Bucket {
    rate: f64,
    burst: f64,
    state: Mutex<State>,
    clock: Box<dyn Clock>,
}

struct State {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    /// A bucket at the given rate, with the default burst.
    pub fn new(per_second: u32) -> Self {
        Self::with_clock(per_second, DEFAULT_BURST, Box::new(SystemClock))
    }

    /// The default scan's limiter.
    pub fn polite() -> Self {
        Self::new(DEFAULT_RATE)
    }

    pub fn with_clock(per_second: u32, burst: u32, clock: Box<dyn Clock>) -> Self {
        // A rate of zero would divide by zero in `take` and means "send
        // nothing", which is not a scan. One per second is the slowest that is
        // still a scan, and it is what a caller asking for zero gets.
        let rate = per_second.max(1) as f64;
        let burst = burst.max(1) as f64;
        let now = clock.now();
        Self {
            rate,
            burst,
            state: Mutex::new(State {
                tokens: burst,
                last: now,
            }),
            clock,
        }
    }

    /// How long the caller must wait before sending one probe, and charges for
    /// it. [`Duration::ZERO`] means send now.
    ///
    /// The charge happens whether or not the caller waits, which is what keeps
    /// the rate right across threads: two callers asking at once get two
    /// different answers rather than the same one.
    pub fn take(&self) -> Duration {
        let now = self.clock.now();
        let mut state = self.state.lock().expect("rate bucket poisoned");

        let elapsed = now.saturating_duration_since(state.last).as_secs_f64();
        state.tokens = (state.tokens + elapsed * self.rate).min(self.burst);
        state.last = now;

        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            return Duration::ZERO;
        }

        // Going into debt rather than refusing: the caller is told to wait for
        // the token it has already been charged for, so a queue of senders
        // spreads out instead of spinning on an empty bucket.
        let short_by = 1.0 - state.tokens;
        state.tokens -= 1.0;
        Duration::from_secs_f64(short_by / self.rate)
    }

    /// Takes a probe's worth of budget and sleeps for it if there is one.
    pub fn wait(&self) {
        let delay = self.take();
        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
    }

    /// The same wait, given up on when `cancel` is set. Answers **false** when
    /// the caller must not send.
    ///
    /// `CLAUDE.md` asks that cancelling take effect at the next packet rather
    /// than at the end of a phase, and an uninterruptible sleep is how that
    /// rule gets broken without anybody writing it down: at a slow rate one
    /// wait is seconds long, and a sweep with hundreds of workers in it can go
    /// on sending for as long again after the user has pressed Stop. So the
    /// sleep is in slices and the flag is read between them, and it is read
    /// once *before* the budget is taken so that a cancelled scan sends
    /// nothing more at all.
    ///
    /// The budget is still charged when the answer is false, exactly as
    /// [`Bucket::take`] documents: a charge that is not spent costs the next
    /// scan one token and keeps the rate honest across threads, which is the
    /// side to err on.
    pub fn wait_unless(&self, cancel: &AtomicBool) -> bool {
        if cancel.load(Ordering::Relaxed) {
            return false;
        }
        let mut left = self.take();
        while !left.is_zero() {
            let slice = left.min(CANCEL_TICK);
            std::thread::sleep(slice);
            left -= slice;
            if cancel.load(Ordering::Relaxed) {
                return false;
            }
        }
        true
    }

    pub fn rate(&self) -> u32 {
        self.rate as u32
    }
}

impl std::fmt::Debug for Bucket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bucket")
            .field("rate", &self.rate)
            .field("burst", &self.burst)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A clock the test drives. Microseconds since an arbitrary start.
    #[derive(Clone, Default)]
    struct Fake {
        base: Option<Instant>,
        micros: Arc<AtomicU64>,
    }

    impl Fake {
        fn new() -> Self {
            Self {
                base: Some(Instant::now()),
                micros: Arc::new(AtomicU64::new(0)),
            }
        }
        fn advance(&self, by: Duration) {
            self.micros
                .fetch_add(by.as_micros() as u64, Ordering::SeqCst);
        }
    }

    impl Clock for Fake {
        fn now(&self) -> Instant {
            self.base.unwrap() + Duration::from_micros(self.micros.load(Ordering::SeqCst))
        }
    }

    #[test]
    fn the_first_burst_goes_out_without_waiting() {
        let clock = Fake::new();
        let b = Bucket::with_clock(1_000, 256, Box::new(clock.clone()));
        for i in 0..256 {
            assert_eq!(b.take(), Duration::ZERO, "probe {i} should not wait");
        }
    }

    #[test]
    fn the_burst_is_capped_and_the_next_probe_waits() {
        let clock = Fake::new();
        let b = Bucket::with_clock(1_000, 256, Box::new(clock.clone()));
        for _ in 0..256 {
            b.take();
        }
        let wait = b.take();
        assert!(wait > Duration::ZERO, "the 257th probe must wait");
        // One token at a thousand a second is a millisecond.
        assert!(wait <= Duration::from_millis(2), "waited {wait:?}");
    }

    #[test]
    fn tokens_come_back_at_the_configured_rate() {
        let clock = Fake::new();
        let b = Bucket::with_clock(1_000, 10, Box::new(clock.clone()));
        for _ in 0..10 {
            b.take();
        }
        assert!(b.take() > Duration::ZERO);

        // Ten milliseconds at a thousand a second is ten tokens, but the
        // eleventh probe above already borrowed one.
        clock.advance(Duration::from_millis(10));
        let free = (0..9).filter(|_| b.take().is_zero()).count();
        assert_eq!(free, 9, "nine tokens back, one having been borrowed");
    }

    /// An idle scanner must not bank an hour of budget and then empty it in one
    /// burst, which is precisely the shape storm control drops.
    #[test]
    fn idling_does_not_bank_unlimited_budget() {
        let clock = Fake::new();
        let b = Bucket::with_clock(1_000, 256, Box::new(clock.clone()));
        clock.advance(Duration::from_secs(3600));

        let free = (0..1_000).filter(|_| b.take().is_zero()).count();
        assert_eq!(free, 256, "an hour idle still buys exactly one burst");
    }

    /// A rate of zero is not a scan; it is a division by zero waiting to
    /// happen. The floor is what the caller gets instead of a panic.
    #[test]
    fn a_rate_of_zero_becomes_the_slowest_real_rate() {
        let b = Bucket::with_clock(0, 0, Box::new(Fake::new()));
        assert_eq!(b.rate(), 1);
        assert_eq!(b.take(), Duration::ZERO, "the one burst token");
        assert!(
            b.take() >= Duration::from_millis(900),
            "then a second a probe"
        );
    }

    /// The rule cancelling depends on: a wait that cannot be interrupted is a
    /// scan that keeps sending after Stop.
    #[test]
    fn a_cancelled_wait_gives_up_long_before_the_delay_is_over() {
        // A real clock and a real sleep, because the thing under test *is* the
        // sleep. One per second with a burst of one, so the second probe is
        // told to wait a whole second.
        let b = Bucket::with_clock(1, 1, Box::new(SystemClock));
        assert!(b.wait_unless(&AtomicBool::new(false)), "the burst token");

        let cancel = AtomicBool::new(false);
        let started = Instant::now();
        std::thread::scope(|s| {
            s.spawn(|| {
                std::thread::sleep(Duration::from_millis(30));
                cancel.store(true, Ordering::SeqCst);
            });
            assert!(!b.wait_unless(&cancel), "cancelled, so do not send");
        });
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "waited {:?} of a one second delay",
            started.elapsed()
        );
    }

    /// And the flag is read before the budget is spent, so a scan already
    /// stopped sends nothing more at all.
    #[test]
    fn an_already_cancelled_wait_sends_nothing_and_returns_at_once() {
        let b = Bucket::new(1_000);
        let cancel = AtomicBool::new(true);
        let started = Instant::now();
        assert!(!b.wait_unless(&cancel));
        assert!(started.elapsed() < Duration::from_millis(50));
    }

    #[test]
    fn an_uncancelled_wait_still_hands_out_the_burst() {
        let clock = Fake::new();
        let b = Bucket::with_clock(1_000, 4, Box::new(clock.clone()));
        let go = AtomicBool::new(false);
        for i in 0..4 {
            assert!(b.wait_unless(&go), "probe {i} is inside the burst");
        }
    }

    /// Two threads asking at the same moment must be charged twice.
    #[test]
    fn concurrent_takes_are_charged_separately() {
        let clock = Fake::new();
        let b = Arc::new(Bucket::with_clock(1_000, 100, Box::new(clock.clone())));
        let free = Arc::new(AtomicU64::new(0));

        std::thread::scope(|s| {
            for _ in 0..8 {
                let b = Arc::clone(&b);
                let free = Arc::clone(&free);
                s.spawn(move || {
                    for _ in 0..50 {
                        if b.take().is_zero() {
                            free.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                });
            }
        });

        assert_eq!(
            free.load(Ordering::SeqCst),
            100,
            "400 probes against a 100 burst on a stopped clock"
        );
    }
}
