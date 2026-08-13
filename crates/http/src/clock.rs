// SPDX-License-Identifier: Apache-2.0
//! Explicit clock capabilities used by HTTP timeout and cache policy.

use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// A paired wall and monotonic reading supplied by an injected clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockReading {
    /// Unix epoch milliseconds used for expiry metadata.
    pub wall_millis: i64,
    /// Monotonic duration from the fixture origin used for deadlines.
    pub monotonic: Duration,
}

impl ClockReading {
    /// Creates a reading from explicit values.
    #[must_use]
    pub const fn new(wall_millis: i64, monotonic: Duration) -> Self {
        Self {
            wall_millis,
            monotonic,
        }
    }

    /// Adds a non-negative duration to both components without saturating.
    ///
    /// Wall time is retained at millisecond precision, so sub-millisecond
    /// advances still move the monotonic component while leaving the wall
    /// component unchanged.  No component is updated when either addition
    /// cannot be represented.
    #[must_use]
    pub fn checked_add(self, amount: Duration) -> Option<Self> {
        let monotonic = self.monotonic.checked_add(amount)?;
        let wall_millis = i64::try_from(amount.as_millis()).ok()?;
        let wall_millis = self.wall_millis.checked_add(wall_millis)?;
        Some(Self::new(wall_millis, monotonic))
    }

    /// Returns elapsed monotonic time from `earlier` or a typed reversal
    /// error when the supplied reading moved backwards.
    pub fn checked_duration_since(self, earlier: Self) -> Result<Duration, ClockError> {
        self.monotonic
            .checked_sub(earlier.monotonic)
            .ok_or(ClockError::MovedBackward {
                previous: earlier.monotonic,
                current: self.monotonic,
            })
    }

    /// Validates monotonic progress between two samples.
    ///
    /// Equality is accepted for an intentionally quiescent fixture.  A
    /// runnable operation must observe a strictly later sample; equality in
    /// that mode is a provider-declared stall, not an invitation to extend a
    /// deadline.
    pub fn validate_progress(
        previous: Self,
        current: Self,
        runnable: bool,
    ) -> Result<(), ClockError> {
        if current.monotonic < previous.monotonic {
            return Err(ClockError::MovedBackward {
                previous: previous.monotonic,
                current: current.monotonic,
            });
        }
        if runnable && current.monotonic == previous.monotonic {
            return Err(ClockError::Stalled);
        }
        Ok(())
    }
}

/// Supplies controlled time to the HTTP semantic core.
pub trait Clock: Send + Sync {
    /// Returns one consistent wall/monotonic reading.
    fn now(&self) -> ClockReading;

    /// Returns whether this clock can make progress during an operation.
    ///
    /// A fixed fixture clock is useful for isolated state tests, but it is
    /// not a valid default for a bounded network operation: a read deadline
    /// would never become observable.  Such clocks are accepted only when a
    /// caller explicitly asks for them through a test-oriented constructor.
    fn can_progress(&self) -> bool {
        true
    }

    /// Samples the clock and validates progress from a previous reading.
    ///
    /// This helper is intentionally explicit: callers decide whether the
    /// operation is still runnable, while the clock seam distinguishes a
    /// reversed source from a source that stopped making progress.  It never
    /// sleeps or polls to diagnose a stall.
    fn observe(&self, previous: ClockReading, runnable: bool) -> Result<ClockReading, ClockError> {
        if runnable && !self.can_progress() {
            return Err(ClockError::Stalled);
        }
        let current = self.now();
        ClockReading::validate_progress(previous, current, runnable)?;
        Ok(current)
    }
}

/// A clock fixed at epoch zero, useful only for deterministic state tests.
///
/// [`HttpClient`](crate::HttpClient) does not use this clock as its default;
/// callers that pass it to a client constructor receive a typed unavailable
/// clock error instead of a client whose deadlines can never expire.
#[derive(Clone, Copy, Debug, Default)]
pub struct EpochClock;

impl Clock for EpochClock {
    fn now(&self) -> ClockReading {
        ClockReading::new(0, Duration::ZERO)
    }

    fn can_progress(&self) -> bool {
        false
    }
}

/// A monotonic clock used by the convenience client constructor.
///
/// The semantic core still accepts an injected [`Clock`] for deterministic
/// tests and controlled execution.  This adapter exists only so the public
/// `HttpClient::new` convenience API does not silently use a fixed-zero
/// deadline clock.
#[derive(Clone, Debug)]
pub struct SystemClock {
    origin: Instant,
    wall_origin_millis: i64,
}

impl Default for SystemClock {
    fn default() -> Self {
        let wall_origin_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| i64::try_from(duration.as_millis()).ok())
            .unwrap_or(i64::MAX);
        Self {
            origin: Instant::now(),
            wall_origin_millis,
        }
    }
}

impl Clock for SystemClock {
    fn now(&self) -> ClockReading {
        let monotonic = self.origin.elapsed();
        let elapsed_millis = i64::try_from(monotonic.as_millis()).unwrap_or(i64::MAX);
        let wall_millis = self
            .wall_origin_millis
            .checked_add(elapsed_millis)
            .unwrap_or(i64::MAX);
        ClockReading::new(wall_millis, monotonic)
    }
}

#[derive(Debug)]
struct ManualClockState {
    reading: ClockReading,
}

/// A deterministic clock whose time advances only when requested.
#[derive(Clone, Debug)]
pub struct ManualClock {
    state: Arc<Mutex<ManualClockState>>,
}

impl ManualClock {
    /// Creates a clock at an explicit wall and monotonic origin.
    #[must_use]
    pub fn new(wall_millis: i64, monotonic: Duration) -> Self {
        Self {
            state: Arc::new(Mutex::new(ManualClockState {
                reading: ClockReading::new(wall_millis, monotonic),
            })),
        }
    }

    /// Creates a clock at epoch zero.
    #[must_use]
    pub fn epoch() -> Self {
        Self::new(0, Duration::ZERO)
    }

    /// Advances both clock components by a non-negative duration.
    pub fn advance(&self, amount: Duration) -> Result<(), ClockError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.reading = state
            .reading
            .checked_add(amount)
            .ok_or(ClockError::Overflow)?;
        Ok(())
    }

    /// Advances to a monotonic target while preserving the paired wall
    /// reading.  A target before the current instant is a reversal and leaves
    /// the clock unchanged.
    pub fn advance_to(&self, target: Duration) -> Result<(), ClockError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let amount =
            target
                .checked_sub(state.reading.monotonic)
                .ok_or(ClockError::MovedBackward {
                    previous: state.reading.monotonic,
                    current: target,
                })?;
        state.reading = state
            .reading
            .checked_add(amount)
            .ok_or(ClockError::Overflow)?;
        Ok(())
    }

    /// Sets both components to an explicit reading without validating
    /// monotonic order.
    ///
    /// This is intentionally an unchecked fixture operation: tests can model
    /// a faulty provider and then assert that [`Clock::observe`] rejects the
    /// reversal.  Production clock adapters should never move backwards.
    pub fn set(&self, reading: ClockReading) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.reading = reading;
    }
}

impl Clock for ManualClock {
    fn now(&self) -> ClockReading {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .reading
    }
}

/// Failure to advance a manual clock without wrapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockError {
    /// The requested advance would overflow wall or monotonic time.
    Overflow,
    /// A clock sample moved backwards relative to the prior sample.
    MovedBackward {
        /// The earlier monotonic sample.
        previous: Duration,
        /// The later sample that was rejected.
        current: Duration,
    },
    /// A runnable operation observed no monotonic progress.
    Stalled,
}

impl ClockError {
    /// Returns the stable HTTP budget code for this failure.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Overflow => "http.arithmetic.overflow",
            Self::MovedBackward { .. } => "http.budget.clock-invalid",
            Self::Stalled => "http.budget.clock-stalled",
        }
    }
}

impl std::fmt::Display for ClockError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Overflow => formatter.write_str("clock advance overflowed"),
            Self::MovedBackward { previous, current } => write!(
                formatter,
                "clock moved backwards from {previous:?} to {current:?}"
            ),
            Self::Stalled => formatter.write_str("clock stopped progressing"),
        }
    }
}

impl std::error::Error for ClockError {}

/// A monotonic deadline passed to a transport operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Deadline {
    /// Absolute monotonic deadline.
    pub at: Duration,
}

impl Deadline {
    /// Creates a deadline at an absolute monotonic instant.
    #[must_use]
    pub const fn at(at: Duration) -> Self {
        Self { at }
    }

    /// Creates a deadline from the current reading and a timeout.
    ///
    /// A zero timeout is valid and produces an already-expired deadline.  An
    /// unrepresentable sum is rejected instead of saturating and extending
    /// the operation.
    #[must_use]
    pub fn after(now: ClockReading, timeout: Duration) -> Option<Self> {
        now.monotonic.checked_add(timeout).map(Self::at)
    }

    /// Returns whether the deadline has elapsed.
    #[must_use]
    pub fn expired(self, now: ClockReading) -> bool {
        now.monotonic >= self.at
    }

    /// Returns the remaining duration, if any.
    #[must_use]
    pub fn remaining(self, now: ClockReading) -> Option<Duration> {
        self.at.checked_sub(now.monotonic)
    }

    /// Returns remaining time, using zero for an expired deadline.
    ///
    /// This is the representation used by a one-budget operation: zero is
    /// exhausted and never means "no timeout".
    #[must_use]
    pub fn remaining_or_zero(self, now: ClockReading) -> Duration {
        self.at.saturating_sub(now.monotonic)
    }

    /// Returns the earlier of two absolute deadlines.
    #[must_use]
    pub fn min(self, other: Self) -> Self {
        Self {
            at: self.at.min(other.at),
        }
    }

    /// Applies a phase cap without extending an already-expired budget.
    ///
    /// The resulting absolute deadline is `now + min(remaining, cap)` when
    /// the budget is still active.  Checked addition distinguishes an
    /// unrepresentable deadline from an expired one.
    pub fn capped(self, now: ClockReading, cap: Duration) -> Option<Self> {
        if self.expired(now) {
            return Some(self);
        }
        let phase = now
            .monotonic
            .checked_add(self.remaining_or_zero(now).min(cap))?;
        Some(Self::at(phase).min(self))
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "tests use expect at assertion boundaries for fixed in-process fixtures"
    )]

    use super::*;

    #[test]
    fn manual_clock_shares_atomic_readings_and_keeps_submillisecond_monotonicity() {
        let clock = ManualClock::new(1_000, Duration::from_millis(4));
        let clone = clock.clone();

        clock.advance(Duration::from_nanos(1_500)).expect("advance");

        assert_eq!(
            clone.now(),
            ClockReading::new(
                1_000,
                Duration::from_millis(4) + Duration::from_nanos(1_500)
            )
        );
    }

    #[test]
    fn manual_clock_overflow_is_atomic_and_advance_to_rejects_reversal() {
        let clock = ManualClock::new(i64::MAX, Duration::ZERO);
        let before = clock.now();
        assert_eq!(
            clock.advance(Duration::from_millis(1)),
            Err(ClockError::Overflow)
        );
        assert_eq!(clock.now(), before);

        let clock = ManualClock::epoch();
        clock.advance(Duration::from_secs(2)).expect("advance");
        let before = clock.now();
        assert_eq!(
            clock.advance_to(Duration::from_secs(1)),
            Err(ClockError::MovedBackward {
                previous: Duration::from_secs(2),
                current: Duration::from_secs(1),
            })
        );
        assert_eq!(clock.now(), before);
    }

    #[test]
    fn clock_observe_distinguishes_reversal_stall_and_fixture_quiescence() {
        let clock = ManualClock::epoch();
        let first = clock.now();
        assert_eq!(clock.observe(first, true), Err(ClockError::Stalled));
        assert_eq!(ClockError::Stalled.code(), "http.budget.clock-stalled");
        assert_eq!(clock.observe(first, false), Ok(first));

        let elapsed = ClockReading::new(0, Duration::from_secs(3))
            .checked_duration_since(first)
            .expect("forward duration");
        assert_eq!(elapsed, Duration::from_secs(3));

        clock.set(ClockReading::new(0, Duration::from_secs(2)));
        let later = clock.now();
        clock.set(ClockReading::new(0, Duration::from_secs(1)));
        assert_eq!(
            clock.observe(later, true),
            Err(ClockError::MovedBackward {
                previous: Duration::from_secs(2),
                current: Duration::from_secs(1),
            })
        );
        assert_eq!(
            ClockError::MovedBackward {
                previous: Duration::from_secs(2),
                current: Duration::from_secs(1),
            }
            .code(),
            "http.budget.clock-invalid"
        );
    }

    #[test]
    fn deadline_zero_remaining_and_phase_cap_never_extend_the_budget() {
        let start = ClockReading::new(0, Duration::from_secs(10));
        let deadline = Deadline::after(start, Duration::from_secs(5)).expect("deadline");

        assert!(
            Deadline::after(start, Duration::ZERO)
                .expect("zero deadline")
                .expired(start)
        );
        assert_eq!(
            deadline.remaining_or_zero(ClockReading::new(0, Duration::from_secs(15))),
            Duration::ZERO
        );
        assert_eq!(
            deadline
                .capped(
                    ClockReading::new(0, Duration::from_secs(12)),
                    Duration::from_secs(10),
                )
                .expect("phase deadline"),
            Deadline::at(Duration::from_secs(15))
        );
        assert_eq!(
            deadline
                .capped(
                    ClockReading::new(0, Duration::from_secs(16)),
                    Duration::from_secs(1),
                )
                .expect("expired deadline"),
            deadline
        );
    }

    #[test]
    fn deadline_creation_and_capping_fail_closed_on_overflow() {
        let near_max = ClockReading::new(0, Duration::MAX);
        assert_eq!(Deadline::after(near_max, Duration::from_nanos(1)), None);

        let deadline = Deadline::at(Duration::MAX);
        assert_eq!(
            deadline.capped(
                ClockReading::new(0, Duration::MAX - Duration::from_nanos(1)),
                Duration::from_secs(1),
            ),
            Some(deadline)
        );
    }

    #[test]
    fn cancellation_is_independent_from_clock_progress() {
        let clock = ManualClock::epoch();
        let cancellation = crate::CancellationToken::default();
        let deadline = Deadline::after(clock.now(), Duration::from_secs(1)).expect("deadline");

        assert!(!cancellation.is_cancelled());
        assert!(!deadline.expired(clock.now()));
        cancellation.cancel();
        assert!(cancellation.is_cancelled());
        assert!(!deadline.expired(clock.now()));
    }
}
