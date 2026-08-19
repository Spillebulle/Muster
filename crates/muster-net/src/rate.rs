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
