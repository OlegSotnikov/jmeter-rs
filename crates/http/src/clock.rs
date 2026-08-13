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
        let monotonic = state
            .reading
            .monotonic
            .checked_add(amount)
            .ok_or(ClockError::Overflow)?;
        let millis = i64::try_from(amount.as_millis()).map_err(|_| ClockError::Overflow)?;
        let wall_millis = state
            .reading
            .wall_millis
            .checked_add(millis)
            .ok_or(ClockError::Overflow)?;
        state.reading = ClockReading::new(wall_millis, monotonic);
        Ok(())
    }

    /// Sets both components to an explicit reading.
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
}

impl std::fmt::Display for ClockError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Overflow => formatter.write_str("clock advance overflowed"),
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
    /// Creates a deadline from the current reading and a timeout.
    #[must_use]
    pub fn after(now: ClockReading, timeout: Duration) -> Option<Self> {
        now.monotonic.checked_add(timeout).map(|at| Self { at })
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
}
