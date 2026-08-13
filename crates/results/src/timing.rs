// SPDX-License-Identifier: Apache-2.0
//! Wall-clock and duration values for sample results.

use std::time::Duration;

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

    /// Returns the non-negative span to a later timestamp as a standard
    /// duration.
    pub fn checked_duration_to(self, later: Self) -> crate::Result<Duration> {
        self.checked_span_to(later).map(Duration::from_millis)
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

            /// Converts this millisecond value to a standard duration.
            pub const fn as_duration(self) -> Duration {
                Duration::from_millis(self.0)
            }

            /// Converts a standard duration to this millisecond value.
            ///
            /// JTL timing fields have millisecond precision.  Sub-
            /// millisecond precision is therefore deliberately truncated,
            /// matching the integer wire representation; the conversion
            /// still rejects a duration whose millisecond count cannot fit in
            /// the domain's `u64` representation.
            pub fn try_from_duration(value: Duration) -> crate::Result<Self> {
                u64::try_from(value.as_millis())
                    .map(Self)
                    .map_err(|_| ResultError::Overflow {
                        field: ResultField::$field,
                    })
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

/// Selects which wall-clock endpoint is projected to the JTL `timeStamp`/`ts`
/// field.
///
/// JMeter's `sampleresult.timestamp.start` setting controls this choice.  It
/// is represented as an enum at this domain boundary so callers cannot
/// accidentally invert a bare boolean at a serialization site.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum TimestampSource {
    /// Use the sample start timestamp.
    #[default]
    Start,
    /// Use the sample end timestamp.
    End,
}

impl TimestampSource {
    /// Selects an endpoint from a pair of wall timestamps.
    pub const fn select(self, start: WallTimestamp, end: WallTimestamp) -> WallTimestamp {
        match self {
            Self::Start => start,
            Self::End => end,
        }
    }
}

/// One atomic wall/monotonic clock reading used to project a sample result.
///
/// The two axes intentionally remain separate: wall time is serialized while
/// monotonic time supplies elapsed duration.  This type is a value-only seam
/// for controlled clocks and has no dependency on a runtime clock provider.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TimingReading {
    wall: WallTimestamp,
    monotonic: Duration,
}

impl TimingReading {
    /// Creates a reading from a wall timestamp and a monotonic instant.
    pub const fn new(wall: WallTimestamp, monotonic: Duration) -> Self {
        Self { wall, monotonic }
    }

    /// Returns the wall timestamp.
    pub const fn wall(self) -> WallTimestamp {
        self.wall
    }

    /// Returns the monotonic instant.
    pub const fn monotonic(self) -> Duration {
        self.monotonic
    }

    /// Returns the elapsed duration to a later monotonic reading.
    pub fn checked_elapsed_to(self, later: Self) -> crate::Result<ElapsedTime> {
        let duration =
            later
                .monotonic
                .checked_sub(self.monotonic)
                .ok_or(ResultError::InvalidTiming {
                    violation: TimingViolation::EndBeforeStart,
                })?;
        ElapsedTime::try_from_duration(duration)
    }
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
    /// Wall timestamp at which a currently paused sample was suspended.
    /// This is execution state, not a serialized duration; `idle` carries
    /// the accumulated paused time.
    pause_start: Option<WallTimestamp>,
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
            pause_start: None,
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
            pause_start: None,
            elapsed,
            latency,
            connect,
            idle,
        }
    }

    /// Projects a sample timing value from two controlled clock readings.
    ///
    /// The elapsed field is derived from the monotonic axis, while start,
    /// end, and the serialized timestamp are copied from the wall axis. The
    /// resulting value is passed through normal runtime validation, so a
    /// backwards clock or an inconsistent component returns a typed error.
    pub fn from_clock_readings(
        start: TimingReading,
        end: TimingReading,
        timestamp_source: TimestampSource,
        latency: Option<Latency>,
        connect: Option<ConnectTime>,
        idle: Option<IdleTime>,
    ) -> crate::Result<Self> {
        let elapsed = start.checked_elapsed_to(end)?;
        let idle_millis = idle.map_or(0, IdleTime::as_millis);
        let elapsed_millis =
            elapsed
                .as_millis()
                .checked_sub(idle_millis)
                .ok_or(ResultError::InvalidTiming {
                    violation: TimingViolation::IdleExceedsElapsed,
                })?;
        let timestamp = timestamp_source.select(start.wall(), end.wall());
        Self::from_parts(
            Some(timestamp),
            Some(start.wall()),
            Some(end.wall()),
            Some(ElapsedTime::from_millis(elapsed_millis)),
            latency,
            connect,
            idle,
        )
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

    /// Returns the active pause start, if this sample is currently paused.
    pub const fn pause_start(&self) -> Option<WallTimestamp> {
        self.pause_start
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

    /// Returns the wall-clock span between start and end when both endpoints
    /// are present.
    pub fn checked_wall_span(&self) -> crate::Result<Option<ElapsedTime>> {
        match (self.start, self.end) {
            (Some(start), Some(end)) => start
                .checked_span_to(end)
                .map(ElapsedTime::from_millis)
                .map(Some),
            _ => Ok(None),
        }
    }

    /// Returns the timestamp selected for the configured JTL wire mode.
    ///
    /// If the selected endpoint is absent, the explicit serialized timestamp
    /// is used as a compatibility fallback. This preserves partially loaded
    /// legacy JTL values while preferring the start/end pair for runtime
    /// samples.
    pub const fn timestamp_for(&self, source: TimestampSource) -> Option<WallTimestamp> {
        match source {
            TimestampSource::Start => match self.start {
                Some(value) => Some(value),
                None => self.timestamp,
            },
            TimestampSource::End => match self.end {
                Some(value) => Some(value),
                None => self.timestamp,
            },
        }
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

    /// Records the start of a pause at a caller-supplied wall timestamp.
    /// Duplicate pauses are rejected instead of silently replacing state.
    pub fn sample_pause_at(&mut self, at: WallTimestamp) -> crate::Result<()> {
        if self.pause_start.is_some() {
            return Err(ResultError::InvalidInput {
                field: InputField::Value(ResultField::Timestamp),
            });
        }
        self.pause_start = Some(at);
        Ok(())
    }

    /// Ends the active pause and adds its checked duration to idle time.
    /// The mutation is atomic when the endpoint is before the pause or the
    /// idle accumulator would overflow.
    pub fn sample_resume_at(&mut self, at: WallTimestamp) -> crate::Result<IdleTime> {
        let Some(start) = self.pause_start else {
            return Err(ResultError::InvalidInput {
                field: InputField::Value(ResultField::Timestamp),
            });
        };
        let duration = IdleTime::from_millis(start.checked_span_to(at)?);
        let current = self.idle.unwrap_or_default();
        let idle = current.checked_add(duration)?;
        let mut candidate = self.clone();
        candidate.pause_start = None;
        candidate.idle = Some(idle);
        if let (Some(sample_start), Some(end)) = (candidate.start, candidate.end) {
            let span = sample_start.checked_span_to(end)?;
            let elapsed = span
                .checked_sub(idle.as_millis())
                .ok_or(ResultError::InvalidTiming {
                    violation: TimingViolation::IdleExceedsElapsed,
                })?;
            candidate.elapsed = Some(ElapsedTime::from_millis(elapsed));
        }
        candidate.validate_components()?;
        *self = candidate;
        Ok(duration)
    }

    /// Records a sample start exactly once.  This is the value-only
    /// counterpart of JMeter's `sampleStart`; no ambient clock is consulted.
    pub fn sample_start_at(&mut self, at: WallTimestamp) -> crate::Result<()> {
        if self.start.is_some() {
            return Err(ResultError::InvalidInput {
                field: InputField::Value(ResultField::Timestamp),
            });
        }
        self.start = Some(at);
        Ok(())
    }

    /// Records a sample start and projects the serialized timestamp using an
    /// explicit save-service timestamp mode.  The mode is required at this
    /// boundary because the pure result model must not guess whether `ts`
    /// means the start or end endpoint.
    pub fn sample_start_at_with_source(
        &mut self,
        at: WallTimestamp,
        source: TimestampSource,
    ) -> crate::Result<()> {
        self.sample_start_at(at)?;
        if matches!(source, TimestampSource::Start) {
            self.timestamp = Some(at);
        }
        Ok(())
    }

    /// Records a sample end exactly once and derives elapsed time from the
    /// start/end span minus accumulated idle time when a start exists.
    pub fn sample_end_at(&mut self, at: WallTimestamp) -> crate::Result<()> {
        if self.end.is_some() {
            return Err(ResultError::InvalidInput {
                field: InputField::Value(ResultField::Timestamp),
            });
        }
        let mut candidate = self.clone();
        candidate.end = Some(at);
        if let Some(start) = candidate.start {
            let span = start.checked_span_to(at)?;
            let idle = candidate.idle.unwrap_or_default().as_millis();
            let elapsed = span.checked_sub(idle).ok_or(ResultError::InvalidTiming {
                violation: TimingViolation::IdleExceedsElapsed,
            })?;
            candidate.elapsed = Some(ElapsedTime::from_millis(elapsed));
        }
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    /// Records a sample end and projects the serialized timestamp using an
    /// explicit save-service timestamp mode.  The update is atomic when the
    /// endpoint ordering or derived elapsed value is invalid.
    pub fn sample_end_at_with_source(
        &mut self,
        at: WallTimestamp,
        source: TimestampSource,
    ) -> crate::Result<()> {
        let previous = self.clone();
        self.sample_end_at(at)?;
        self.timestamp = match source {
            TimestampSource::Start => self.start,
            TimestampSource::End => self.end,
        };
        if let Err(error) = self.validate() {
            *self = previous;
            return Err(error);
        }
        Ok(())
    }

    /// Records the first-response marker and derives latency from a supplied
    /// wall timestamp.  Idle time already accumulated before the marker is
    /// excluded, matching JMeter's `latencyEnd` calculation.
    pub fn latency_end_at(&mut self, at: WallTimestamp) -> crate::Result<Latency> {
        let value = Latency::from_millis(self.elapsed_since_start(at)?);
        self.replace_checked(|timing| timing.latency = Some(value))?;
        Ok(value)
    }

    /// Records the connection-complete marker and derives connect time from a
    /// supplied wall timestamp.  Idle time already accumulated before the
    /// marker is excluded, matching JMeter's `connectEnd` calculation.
    pub fn connect_end_at(&mut self, at: WallTimestamp) -> crate::Result<ConnectTime> {
        let value = ConnectTime::from_millis(self.elapsed_since_start(at)?);
        self.replace_checked(|timing| timing.connect = Some(value))?;
        Ok(value)
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
        if let Some(span) = self.checked_wall_span()?
            && let Some(elapsed) = self.elapsed
            && elapsed.as_millis() > span.as_millis()
        {
            return Err(ResultError::InvalidTiming {
                violation: TimingViolation::ElapsedExceedsWallSpan,
            });
        }

        self.validate_components()
    }

    /// Validates the independent elapsed/latency/connect/idle component
    /// inequalities without comparing elapsed to wall-clock span.
    ///
    /// A caller projecting from a monotonic clock can use this method when a
    /// wall clock is known to be independently adjustable. The regular
    /// [`SampleTiming::validate`] method additionally checks start/end wall
    /// ordering and the elapsed-to-wall-span relation.
    pub fn validate_components(&self) -> crate::Result<()> {
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
            let idle = candidate.idle.map_or(0, IdleTime::as_millis);
            let elapsed = span.checked_sub(idle).ok_or(ResultError::InvalidTiming {
                violation: TimingViolation::IdleExceedsElapsed,
            })?;
            candidate.elapsed = Some(ElapsedTime::from_millis(elapsed));
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

    fn elapsed_since_start(&self, at: WallTimestamp) -> crate::Result<u64> {
        let start = self.start.ok_or(ResultError::InvalidInput {
            field: InputField::Value(ResultField::Timestamp),
        })?;
        let span = start.checked_span_to(at)?;
        span.checked_sub(self.idle.map_or(0, IdleTime::as_millis))
            .ok_or(ResultError::InvalidTiming {
                violation: TimingViolation::IdleExceedsElapsed,
            })
    }
}

// Test fixtures use `expect` at setup/assertion boundaries so failures retain
// the operation name; production timing paths remain explicitly fallible.
#[allow(clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;

    fn invalid<T>(violation: TimingViolation) -> crate::Result<T> {
        Err(ResultError::InvalidTiming { violation })
    }

    #[test]
    fn wall_span_handles_pre_epoch_values_and_full_signed_range() {
        assert_eq!(
            WallTimestamp::from_millis(-1)
                .checked_duration_to(WallTimestamp::from_millis(1))
                .expect("span"),
            Duration::from_millis(2)
        );
        assert_eq!(
            WallTimestamp::from_millis(i64::MIN)
                .checked_span_to(WallTimestamp::from_millis(i64::MAX))
                .expect("full signed range span"),
            u64::MAX
        );
        assert_eq!(
            WallTimestamp::from_millis(1).checked_span_to(WallTimestamp::from_millis(-1)),
            invalid(TimingViolation::EndBeforeStart)
        );
    }

    #[test]
    fn checked_timestamp_and_duration_arithmetic_reports_overflow() {
        assert_eq!(
            WallTimestamp::from_millis(i64::MAX).checked_add_millis(1),
            Err(ResultError::Overflow {
                field: ResultField::Timestamp
            })
        );
        assert_eq!(
            WallTimestamp::from_millis(i64::MIN).checked_add_millis(-1),
            Err(ResultError::Overflow {
                field: ResultField::Timestamp
            })
        );
        assert_eq!(
            ElapsedTime::from_millis(u64::MAX).checked_add(ElapsedTime::from_millis(1)),
            Err(ResultError::Overflow {
                field: ResultField::Elapsed
            })
        );
        assert_eq!(
            ElapsedTime::try_from_duration(Duration::from_secs(u64::MAX)),
            Err(ResultError::Overflow {
                field: ResultField::Elapsed
            })
        );
    }

    #[test]
    fn controlled_readings_project_wall_and_monotonic_axes_separately() {
        let start = TimingReading::new(
            WallTimestamp::from_millis(1_700_000_000_000),
            Duration::from_millis(50),
        );
        let end = TimingReading::new(
            WallTimestamp::from_millis(1_700_000_000_123),
            Duration::from_millis(173),
        );
        let timing = SampleTiming::from_clock_readings(
            start,
            end,
            TimestampSource::Start,
            Some(Latency::from_millis(20)),
            Some(ConnectTime::from_millis(10)),
            Some(IdleTime::from_millis(3)),
        )
        .expect("controlled timing");
        assert_eq!(
            timing.timestamp_for(TimestampSource::Start),
            Some(start.wall())
        );
        assert_eq!(timing.timestamp_for(TimestampSource::End), Some(end.wall()));
        assert_eq!(timing.elapsed(), Some(ElapsedTime::from_millis(120)));
        assert_eq!(
            timing.checked_wall_span().expect("wall span"),
            Some(ElapsedTime::from_millis(123))
        );
        assert_eq!(timing.latency(), Some(Latency::from_millis(20)));
        assert_eq!(timing.connect(), Some(ConnectTime::from_millis(10)));
        assert_eq!(timing.idle(), Some(IdleTime::from_millis(3)));
    }

    #[test]
    fn controlled_readings_reject_backwards_monotonic_or_wall_time() {
        let wall_start =
            TimingReading::new(WallTimestamp::from_millis(10), Duration::from_millis(10));
        let monotonic_backwards =
            TimingReading::new(WallTimestamp::from_millis(11), Duration::from_millis(9));
        assert_eq!(
            SampleTiming::from_clock_readings(
                wall_start,
                monotonic_backwards,
                TimestampSource::Start,
                None,
                None,
                None,
            ),
            invalid(TimingViolation::EndBeforeStart)
        );

        let wall_backwards =
            TimingReading::new(WallTimestamp::from_millis(9), Duration::from_millis(11));
        assert_eq!(
            SampleTiming::from_clock_readings(
                wall_start,
                wall_backwards,
                TimestampSource::End,
                None,
                None,
                None,
            ),
            invalid(TimingViolation::EndBeforeStart)
        );

        assert_eq!(
            SampleTiming::from_clock_readings(
                wall_start,
                TimingReading::new(WallTimestamp::from_millis(12), Duration::from_millis(11),),
                TimestampSource::Start,
                None,
                None,
                Some(IdleTime::from_millis(2)),
            ),
            invalid(TimingViolation::IdleExceedsElapsed)
        );
    }

    #[test]
    fn timestamp_selection_falls_back_to_explicit_wire_timestamp() {
        let explicit = WallTimestamp::from_millis(42);
        let timing = SampleTiming::from_wire_parts(
            Some(explicit),
            None,
            None,
            Some(ElapsedTime::from_millis(1)),
            None,
            None,
            None,
        );
        assert_eq!(timing.timestamp_for(TimestampSource::Start), Some(explicit));
        assert_eq!(timing.timestamp_for(TimestampSource::End), Some(explicit));

        let with_start = SampleTiming::from_wire_parts(
            Some(explicit),
            Some(WallTimestamp::from_millis(40)),
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(
            with_start.timestamp_for(TimestampSource::Start),
            Some(WallTimestamp::from_millis(40))
        );
        assert_eq!(
            with_start.timestamp_for(TimestampSource::End),
            Some(explicit)
        );
    }

    #[test]
    fn component_invariants_are_checked_independently_and_at_boundaries() {
        let valid = SampleTiming::from_parts(
            None,
            None,
            None,
            Some(ElapsedTime::from_millis(5)),
            Some(Latency::from_millis(5)),
            Some(ConnectTime::from_millis(5)),
            Some(IdleTime::from_millis(5)),
        )
        .expect("equal components are valid");
        assert!(valid.validate_components().is_ok());

        assert_eq!(
            SampleTiming::from_parts(
                None,
                None,
                None,
                Some(ElapsedTime::from_millis(5)),
                Some(Latency::from_millis(6)),
                None,
                None,
            ),
            invalid(TimingViolation::LatencyExceedsElapsed)
        );
        assert_eq!(
            SampleTiming::from_parts(
                None,
                None,
                None,
                Some(ElapsedTime::from_millis(5)),
                None,
                Some(ConnectTime::from_millis(6)),
                None,
            ),
            invalid(TimingViolation::ConnectExceedsElapsed)
        );
        assert_eq!(
            SampleTiming::from_parts(
                None,
                None,
                None,
                Some(ElapsedTime::from_millis(5)),
                None,
                None,
                Some(IdleTime::from_millis(6)),
            ),
            invalid(TimingViolation::IdleExceedsElapsed)
        );
    }

    #[test]
    fn runtime_validation_rejects_elapsed_longer_than_wall_span() {
        assert_eq!(
            SampleTiming::from_parts(
                None,
                Some(WallTimestamp::from_millis(100)),
                Some(WallTimestamp::from_millis(110)),
                Some(ElapsedTime::from_millis(11)),
                None,
                None,
                None,
            ),
            invalid(TimingViolation::ElapsedExceedsWallSpan)
        );
    }

    #[test]
    fn sample_lifecycle_derives_idle_and_rejects_duplicate_calls() {
        let mut timing = SampleTiming::default();
        timing
            .sample_start_at(WallTimestamp::from_millis(10))
            .expect("first start");
        assert_eq!(
            timing.sample_start_at(WallTimestamp::from_millis(11)),
            Err(ResultError::InvalidInput {
                field: InputField::Value(ResultField::Timestamp),
            })
        );
        timing
            .sample_pause_at(WallTimestamp::from_millis(20))
            .expect("pause");
        assert_eq!(timing.pause_start(), Some(WallTimestamp::from_millis(20)));
        assert_eq!(
            timing.sample_pause_at(WallTimestamp::from_millis(21)),
            Err(ResultError::InvalidInput {
                field: InputField::Value(ResultField::Timestamp),
            })
        );
        assert_eq!(
            timing
                .sample_resume_at(WallTimestamp::from_millis(25))
                .expect("resume"),
            IdleTime::from_millis(5)
        );
        assert_eq!(timing.idle(), Some(IdleTime::from_millis(5)));
        assert_eq!(timing.pause_start(), None);
        timing
            .sample_end_at(WallTimestamp::from_millis(40))
            .expect("end");
        assert_eq!(timing.elapsed(), Some(ElapsedTime::from_millis(25)));
        assert_eq!(
            timing.sample_end_at(WallTimestamp::from_millis(41)),
            Err(ResultError::InvalidInput {
                field: InputField::Value(ResultField::Timestamp),
            })
        );
    }

    #[test]
    fn lifecycle_timestamp_mode_and_marker_durations_are_explicit() {
        let mut timing = SampleTiming::default();
        timing
            .sample_start_at_with_source(WallTimestamp::from_millis(100), TimestampSource::End)
            .expect("start with end timestamp mode");
        assert_eq!(timing.timestamp(), None);
        assert_eq!(
            timing
                .connect_end_at(WallTimestamp::from_millis(104))
                .expect("connect marker"),
            ConnectTime::from_millis(4)
        );
        timing
            .sample_pause_at(WallTimestamp::from_millis(105))
            .expect("pause");
        timing
            .sample_resume_at(WallTimestamp::from_millis(107))
            .expect("resume");
        assert_eq!(
            timing
                .latency_end_at(WallTimestamp::from_millis(110))
                .expect("latency marker"),
            Latency::from_millis(8)
        );
        timing
            .sample_end_at_with_source(WallTimestamp::from_millis(120), TimestampSource::End)
            .expect("end with end timestamp mode");
        assert_eq!(timing.timestamp(), Some(WallTimestamp::from_millis(120)));
        assert_eq!(timing.elapsed(), Some(ElapsedTime::from_millis(18)));
    }

    #[test]
    fn marker_without_start_is_rejected_without_mutation() {
        let mut timing = SampleTiming::default();
        assert_eq!(
            timing.latency_end_at(WallTimestamp::from_millis(1)),
            Err(ResultError::InvalidInput {
                field: InputField::Value(ResultField::Timestamp),
            })
        );
        assert_eq!(timing.latency(), None);
        assert_eq!(
            timing.connect_end_at(WallTimestamp::from_millis(1)),
            Err(ResultError::InvalidInput {
                field: InputField::Value(ResultField::Timestamp),
            })
        );
        assert_eq!(timing.connect(), None);
    }

    #[test]
    fn sample_end_before_start_is_rejected_without_mutation() {
        let mut timing = SampleTiming::default();
        timing
            .sample_start_at(WallTimestamp::from_millis(10))
            .expect("start");
        assert_eq!(
            timing.sample_end_at(WallTimestamp::from_millis(9)),
            Err(ResultError::InvalidTiming {
                violation: TimingViolation::EndBeforeStart,
            })
        );
        assert_eq!(timing.end(), None);
        assert_eq!(timing.elapsed(), None);
    }

    #[test]
    fn sample_resume_before_pause_is_rejected_without_mutation() {
        let mut timing = SampleTiming::default();
        assert!(
            timing
                .sample_pause_at(WallTimestamp::from_millis(20))
                .is_ok()
        );
        assert_eq!(
            timing.sample_resume_at(WallTimestamp::from_millis(19)),
            Err(ResultError::InvalidTiming {
                violation: TimingViolation::EndBeforeStart,
            })
        );
        assert_eq!(timing.pause_start(), Some(WallTimestamp::from_millis(20)));
        assert_eq!(timing.idle(), None);
    }
}
