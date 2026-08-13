// SPDX-License-Identifier: Apache-2.0
//! Wall-clock and duration values for sample results.

use crate::{InputField, ResultError, ResultField, TimingViolation};

/// A signed wall-clock timestamp in milliseconds since the Unix epoch.
///
/// Wall time is intentionally separate from all monotonic sample durations.
/// Negative values are allowed for pre-epoch timestamps; arithmetic still uses
/// checked operations.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WallTimestamp(i64);

impl WallTimestamp {
    /// Creates a timestamp from epoch milliseconds.
    pub const fn new(value: i64) -> Self {
        Self::from_millis(value)
    }

    /// Creates a timestamp from epoch milliseconds.
    pub const fn from_millis(value: i64) -> Self {
        Self(value)
    }

    /// Returns epoch milliseconds.
    pub const fn as_millis(self) -> i64 {
        self.0
    }

    /// Adds signed milliseconds, returning an overflow error instead of
    /// wrapping.
    pub fn checked_add_millis(self, value: i64) -> crate::Result<Self> {
        self.0
            .checked_add(value)
            .map(Self)
            .ok_or(ResultError::Overflow {
                field: ResultField::Timestamp,
            })
    }

    /// Returns the non-negative millisecond span to a later timestamp.
    pub fn checked_span_to(self, later: Self) -> crate::Result<u64> {
        if later.0 < self.0 {
            return Err(ResultError::InvalidTiming {
                violation: TimingViolation::EndBeforeStart,
            });
        }
        let span = i128::from(later.0) - i128::from(self.0);
        u64::try_from(span).map_err(|_| ResultError::Overflow {
            field: ResultField::Elapsed,
        })
    }
}

impl From<i64> for WallTimestamp {
    fn from(value: i64) -> Self {
        Self::from_millis(value)
    }
}

/// Compatibility alias for a wall timestamp.
pub type Timestamp = WallTimestamp;
/// Explicitly named millisecond timestamp alias.
pub type TimestampMillis = WallTimestamp;

macro_rules! duration_type {
    ($(#[$meta:meta])* $name:ident, $field:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(u64);

        impl $name {
            /// Creates a non-negative duration from milliseconds.
            pub const fn new(value: u64) -> Self {
                Self::from_millis(value)
            }

            /// Creates a non-negative duration from milliseconds.
            pub const fn from_millis(value: u64) -> Self {
                Self(value)
            }

            /// Returns the duration in milliseconds.
            pub const fn as_millis(self) -> u64 {
                self.0
            }

            /// Adds two durations without wrapping.
            pub fn checked_add(self, other: Self) -> crate::Result<Self> {
                self.0.checked_add(other.0).map(Self).ok_or(ResultError::Overflow {
                    field: ResultField::$field,
                })
            }

            /// Converts a signed wire value, rejecting negative durations.
            pub fn try_from_i64(value: i64) -> crate::Result<Self> {
                u64::try_from(value).map(Self).map_err(|_| ResultError::InvalidInput {
                    field: InputField::NegativeNumber(ResultField::$field),
                })
            }
        }

        impl TryFrom<i64> for $name {
            type Error = ResultError;

            fn try_from(value: i64) -> Result<Self, Self::Error> {
                Self::try_from_i64(value)
            }
        }

        impl From<u64> for $name {
            fn from(value: u64) -> Self {
                Self::from_millis(value)
            }
        }
    };
}

duration_type!(
    /// Elapsed sample duration.
    ElapsedTime,
    Elapsed
);
duration_type!(
    /// Time from sample start until the first response byte.
    Latency,
    Latency
);
duration_type!(
    /// Time spent establishing a connection.
    ConnectTime,
    Connect
);
duration_type!(
    /// Time attributed to idle periods inside a sample.
    IdleTime,
    Idle
);

/// The distinct timing fields carried by a sample result.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SampleTiming {
    timestamp: Option<WallTimestamp>,
    start: Option<WallTimestamp>,
    end: Option<WallTimestamp>,
    elapsed: Option<ElapsedTime>,
    latency: Option<Latency>,
    connect: Option<ConnectTime>,
    idle: Option<IdleTime>,
}

impl SampleTiming {
    /// Builds and validates a complete timing value. This is an alias for
    /// [`SampleTiming::from_parts`].
    pub fn new(
        timestamp: Option<WallTimestamp>,
        start: Option<WallTimestamp>,
        end: Option<WallTimestamp>,
        elapsed: Option<ElapsedTime>,
        latency: Option<Latency>,
        connect: Option<ConnectTime>,
        idle: Option<IdleTime>,
    ) -> crate::Result<Self> {
        Self::from_parts(timestamp, start, end, elapsed, latency, connect, idle)
    }

    /// Builds and validates a complete timing value. Every field remains
    /// optional to preserve absent JTL attributes.
    pub fn from_parts(
        timestamp: Option<WallTimestamp>,
        start: Option<WallTimestamp>,
        end: Option<WallTimestamp>,
        elapsed: Option<ElapsedTime>,
        latency: Option<Latency>,
        connect: Option<ConnectTime>,
        idle: Option<IdleTime>,
    ) -> crate::Result<Self> {
        let timing = Self {
            timestamp,
            start,
            end,
            elapsed,
            latency,
            connect,
            idle,
        };
        timing.validate()?;
        Ok(timing)
    }

    /// Builds timing values exactly as supplied by a result wire format.
    ///
    /// Wire formats may contain independently serialized latency, connect,
    /// and idle values that do not satisfy execution-time inequalities.  This
    /// constructor intentionally performs no relational validation; callers
    /// constructing runtime samples should use [`SampleTiming::from_parts`].
    pub const fn from_wire_parts(
        timestamp: Option<WallTimestamp>,
        start: Option<WallTimestamp>,
        end: Option<WallTimestamp>,
        elapsed: Option<ElapsedTime>,
        latency: Option<Latency>,
        connect: Option<ConnectTime>,
        idle: Option<IdleTime>,
    ) -> Self {
        Self {
            timestamp,
            start,
            end,
            elapsed,
            latency,
            connect,
            idle,
        }
    }

    /// Returns the optional serialized wall timestamp.
    pub const fn timestamp(&self) -> Option<WallTimestamp> {
        self.timestamp
    }

    /// Returns the optional sample start timestamp.
    pub const fn start(&self) -> Option<WallTimestamp> {
        self.start
    }

    /// Returns the optional sample end timestamp.
    pub const fn end(&self) -> Option<WallTimestamp> {
        self.end
    }

    /// Returns elapsed time.
    pub const fn elapsed(&self) -> Option<ElapsedTime> {
        self.elapsed
    }

    /// Returns latency.
    pub const fn latency(&self) -> Option<Latency> {
        self.latency
    }

    /// Returns connect time.
    pub const fn connect(&self) -> Option<ConnectTime> {
        self.connect
    }

    /// Returns idle time.
    pub const fn idle(&self) -> Option<IdleTime> {
        self.idle
    }

    /// Sets the serialized wall timestamp.
    pub fn set_timestamp(&mut self, value: Option<WallTimestamp>) {
        self.timestamp = value;
    }

    /// Sets the sample start timestamp and validates all timing relations.
    pub fn set_start(&mut self, value: Option<WallTimestamp>) -> crate::Result<()> {
        self.replace_checked(|timing| timing.start = value)
    }

    /// Sets the sample end timestamp and validates all timing relations.
    pub fn set_end(&mut self, value: Option<WallTimestamp>) -> crate::Result<()> {
        self.replace_checked(|timing| timing.end = value)
    }

    /// Sets elapsed time and validates all timing relations.
    pub fn set_elapsed(&mut self, value: Option<ElapsedTime>) -> crate::Result<()> {
        self.replace_checked(|timing| timing.elapsed = value)
    }

    /// Sets latency and validates all timing relations.
    pub fn set_latency(&mut self, value: Option<Latency>) -> crate::Result<()> {
        self.replace_checked(|timing| timing.latency = value)
    }

    /// Sets connect time and validates all timing relations.
    pub fn set_connect(&mut self, value: Option<ConnectTime>) -> crate::Result<()> {
        self.replace_checked(|timing| timing.connect = value)
    }

    /// Sets idle time and validates all timing relations.
    pub fn set_idle(&mut self, value: Option<IdleTime>) -> crate::Result<()> {
        self.replace_checked(|timing| timing.idle = value)
    }

    /// Validates timestamp ordering and duration bounds.
    pub fn validate(&self) -> crate::Result<()> {
        if let (Some(start), Some(end)) = (self.start, self.end) {
            let span = start.checked_span_to(end)?;
            if let Some(elapsed) = self.elapsed
                && elapsed.as_millis() > span
            {
                return Err(ResultError::InvalidTiming {
                    violation: TimingViolation::ElapsedExceedsWallSpan,
                });
            }
        }

        if let (Some(elapsed), Some(latency)) = (self.elapsed, self.latency)
            && latency.as_millis() > elapsed.as_millis()
        {
            return Err(ResultError::InvalidTiming {
                violation: TimingViolation::LatencyExceedsElapsed,
            });
        }
        if let (Some(elapsed), Some(connect)) = (self.elapsed, self.connect)
            && connect.as_millis() > elapsed.as_millis()
        {
            return Err(ResultError::InvalidTiming {
                violation: TimingViolation::ConnectExceedsElapsed,
            });
        }
        if let (Some(elapsed), Some(idle)) = (self.elapsed, self.idle)
            && idle.as_millis() > elapsed.as_millis()
        {
            return Err(ResultError::InvalidTiming {
                violation: TimingViolation::IdleExceedsElapsed,
            });
        }
        Ok(())
    }

    /// Aggregates the child's end timestamp into this timing value. JMeter's
    /// parent duration is a wall span, not a sum of child durations; latency,
    /// connect, and idle measurements remain the parent's own measurements.
    pub(crate) fn aggregate_child(&mut self, child: &Self) -> crate::Result<()> {
        let mut candidate = self.clone();
        if let Some(child_end) = child.end {
            candidate.end = Some(match candidate.end {
                Some(parent_end) if parent_end > child_end => parent_end,
                _ => child_end,
            });
        }
        if candidate.elapsed.is_none() {
            candidate.elapsed = child.elapsed;
        }
        if let (Some(start), Some(end)) = (candidate.start, candidate.end) {
            let span = start.checked_span_to(end)?;
            candidate.elapsed = Some(ElapsedTime::from_millis(span));
        }
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    fn replace_checked<F>(&mut self, update: F) -> crate::Result<()>
    where
        F: FnOnce(&mut Self),
    {
        let previous = self.clone();
        update(self);
        if let Err(error) = self.validate() {
            *self = previous;
            return Err(error);
        }
        Ok(())
    }
}
