// SPDX-License-Identifier: Apache-2.0
//! Bounded logical event traces and deterministic replay cursors.

use crate::error::{ErrorCode, StableError};
use std::fmt;
use std::sync::{Arc, Mutex};

/// Bounds applied to both recording and replay input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraceLimits {
    /// Maximum number of retained events.
    pub max_events: usize,
    /// Maximum bytes in one event's kind plus payload.
    pub max_event_bytes: usize,
    /// Maximum bytes retained by the whole trace.
    pub max_total_bytes: usize,
    /// Maximum bytes in an event kind.
    pub max_kind_bytes: usize,
}

impl TraceLimits {
    /// Creates explicit bounded limits.  Zero is valid and models a closed
    /// trace that rejects every event without allocating storage.
    #[must_use]
    pub const fn new(max_events: usize, max_event_bytes: usize, max_total_bytes: usize) -> Self {
        Self {
            max_events,
            max_event_bytes,
            max_total_bytes,
            max_kind_bytes: max_event_bytes,
        }
    }

    /// Sets an independent bound for event-kind bytes.
    #[must_use]
    pub const fn with_kind_limit(mut self, max_kind_bytes: usize) -> Self {
        self.max_kind_bytes = max_kind_bytes;
        self
    }

    /// A useful finite default for unit and integration traces.
    #[must_use]
    pub const fn default_bounded() -> Self {
        Self::new(4_096, 16 * 1024, 4 * 1024 * 1024)
    }
}

impl Default for TraceLimits {
    fn default() -> Self {
        Self::default_bounded()
    }
}

/// Event data independent of its recording sequence number.
#[derive(Clone, PartialEq, Eq)]
pub struct TraceEventData {
    /// A bounded logical event kind, such as `timer.register`.
    pub kind: String,
    /// A deterministic opaque payload owned by the trace.
    pub payload: Vec<u8>,
}

/// A redacted trace-event-data projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceEventDataDiagnostic {
    /// Number of UTF-8 bytes in the event kind.
    pub kind_bytes: usize,
    /// Number of opaque payload bytes.
    pub payload_bytes: usize,
}

impl TraceEventData {
    /// Creates event data.  Bounds are checked when the data enters a trace or
    /// replay log.
    #[must_use]
    pub fn new(kind: impl Into<String>, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            kind: kind.into(),
            payload: payload.into(),
        }
    }

    fn byte_len(&self) -> Option<usize> {
        self.kind.len().checked_add(self.payload.len())
    }

    /// Returns an explicit redacted diagnostic projection.
    #[must_use]
    pub fn redacted(&self) -> TraceEventDataDiagnostic {
        TraceEventDataDiagnostic {
            kind_bytes: self.kind.len(),
            payload_bytes: self.payload.len(),
        }
    }
}

impl fmt::Debug for TraceEventData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.redacted().fmt(formatter)
    }
}

/// One retained event, with a stable sequence assigned by its recorder.
#[derive(Clone, PartialEq, Eq)]
pub struct TraceEvent {
    /// Zero-based monotonically increasing sequence number.
    pub sequence: u64,
    /// Kind and payload of the event.
    pub data: TraceEventData,
}

/// A redacted trace-event projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceEventDiagnostic {
    /// Event sequence number.
    pub sequence: u64,
    /// Redacted event data.
    pub data: TraceEventDataDiagnostic,
}

impl TraceEvent {
    /// Creates an event value for replay input or assertions.
    #[must_use]
    pub fn new(sequence: u64, kind: impl Into<String>, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            sequence,
            data: TraceEventData::new(kind, payload),
        }
    }

    /// Returns the event kind.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.data.kind
    }

    /// Returns the event payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.data.payload
    }

    /// Returns event data without the sequence number.
    #[must_use]
    pub fn data(&self) -> TraceEventData {
        self.data.clone()
    }

    /// Returns an explicit redacted diagnostic projection.
    #[must_use]
    pub fn redacted(&self) -> TraceEventDiagnostic {
        TraceEventDiagnostic {
            sequence: self.sequence,
            data: self.data.redacted(),
        }
    }
}

impl fmt::Debug for TraceEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.redacted().fmt(formatter)
    }
}

/// Errors returned while recording a bounded trace or loading replay input.
#[derive(Clone, PartialEq, Eq)]
pub enum TraceError {
    /// An event kind exceeds the configured kind limit.
    KindTooLarge {
        /// Actual kind bytes.
        actual: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// An event exceeds the configured per-event byte limit.
    EventTooLarge {
        /// Actual event bytes.
        actual: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// The event count or retained bytes exceed a configured bound.
    CapacityExceeded {
        /// Number of events after the attempted insertion.
        event_count: usize,
        /// Bytes after the attempted insertion.
        total_bytes: usize,
    },
    /// A sequence number cannot be incremented.
    SequenceOverflow,
    /// Replay input contains a duplicate or decreasing sequence number.
    NonMonotonicSequence {
        /// Zero-based event position.
        position: usize,
        /// Prior sequence number.
        previous: u64,
        /// Rejected sequence number.
        actual: u64,
    },
    /// A size calculation overflowed before a limit comparison.
    InvalidLimit,
}

impl fmt::Debug for TraceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("TraceError");
        match self {
            Self::KindTooLarge { actual, limit } => debug
                .field("kind", &"KindTooLarge")
                .field("actual", actual)
                .field("limit", limit),
            Self::EventTooLarge { actual, limit } => debug
                .field("kind", &"EventTooLarge")
                .field("actual", actual)
                .field("limit", limit),
            Self::CapacityExceeded {
                event_count,
                total_bytes,
            } => debug
                .field("kind", &"CapacityExceeded")
                .field("event_count", event_count)
                .field("total_bytes", total_bytes),
            Self::SequenceOverflow => debug.field("kind", &"SequenceOverflow"),
            Self::NonMonotonicSequence {
                position,
                previous,
                actual,
            } => debug
                .field("kind", &"NonMonotonicSequence")
                .field("position", position)
                .field("previous", previous)
                .field("actual", actual),
            Self::InvalidLimit => debug.field("kind", &"InvalidLimit"),
        };
        debug.finish()
    }
}

impl TraceError {
    /// Returns the stable error code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::KindTooLarge { .. } => ErrorCode::TraceKindTooLarge,
            Self::EventTooLarge { .. } => ErrorCode::TraceEventTooLarge,
            Self::CapacityExceeded { .. } => ErrorCode::TraceCapacity,
            Self::SequenceOverflow => ErrorCode::TraceSequenceOverflow,
            Self::NonMonotonicSequence { .. } => ErrorCode::TraceSequenceInvalid,
            Self::InvalidLimit => ErrorCode::TraceInvalidLimit,
        }
    }
}

impl fmt::Display for TraceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KindTooLarge { actual, limit } => {
                write!(
                    formatter,
                    "{}: kind bytes {actual} exceed {limit}",
                    self.code()
                )
            }
            Self::EventTooLarge { actual, limit } => {
                write!(
                    formatter,
                    "{}: event bytes {actual} exceed {limit}",
                    self.code()
                )
            }
            Self::CapacityExceeded {
                event_count,
                total_bytes,
            } => write!(
                formatter,
                "{}: event count {event_count} or total bytes {total_bytes} exceed the trace bound",
                self.code()
            ),
            Self::SequenceOverflow => write!(formatter, "{}: trace sequence overflow", self.code()),
            Self::NonMonotonicSequence {
                position,
                previous,
                actual,
            } => write!(
                formatter,
                "{}: sequence {actual} at position {position} is not greater than {previous}",
                self.code()
            ),
            Self::InvalidLimit => write!(
                formatter,
                "{}: trace size calculation overflow",
                self.code()
            ),
        }
    }
}

impl std::error::Error for TraceError {}
impl StableError for TraceError {
    fn code(&self) -> ErrorCode {
        self.code()
    }
}

#[derive(Debug)]
struct TraceState {
    limits: TraceLimits,
    next_sequence: u64,
    total_bytes: usize,
    events: Vec<TraceEvent>,
}

/// A cloneable bounded recorder of logical events.
///
/// Clones share the retained event list, sequence, and limits.  Recording is
/// explicit and never blocks or sleeps.  A failed insertion leaves both the
/// event list and sequence unchanged.
#[derive(Clone)]
pub struct EventTrace {
    state: Arc<Mutex<TraceState>>,
}

impl fmt::Debug for EventTrace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = recover_lock(&self.state);
        formatter
            .debug_struct("EventTrace")
            .field("limits", &state.limits)
            .field("event_count", &state.events.len())
            .field("total_bytes", &state.total_bytes)
            .field("next_sequence", &state.next_sequence)
            .finish()
    }
}

impl EventTrace {
    /// Creates an empty trace with finite limits.
    #[must_use]
    pub fn new(limits: TraceLimits) -> Self {
        Self {
            state: Arc::new(Mutex::new(TraceState {
                limits,
                next_sequence: 0,
                total_bytes: 0,
                events: Vec::new(),
            })),
        }
    }

    /// Returns a clone sharing the trace state.
    #[must_use]
    pub fn shared(&self) -> Self {
        self.clone()
    }

    /// Returns the active bounds.
    #[must_use]
    pub fn limits(&self) -> TraceLimits {
        recover_lock(&self.state).limits
    }

    /// Returns the number of retained events.
    #[must_use]
    pub fn len(&self) -> usize {
        recover_lock(&self.state).events.len()
    }

    /// Returns whether no events are retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the retained byte count.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        recover_lock(&self.state).total_bytes
    }

    /// Records one event and returns the assigned event.
    pub fn record(&self, kind: &str, payload: &[u8]) -> Result<TraceEvent, TraceError> {
        let limits = self.limits();
        let event_bytes = kind
            .len()
            .checked_add(payload.len())
            .ok_or(TraceError::InvalidLimit)?;
        validate_lengths(&limits, kind.len(), event_bytes)?;
        self.record_data(TraceEventData::new(kind, payload.to_vec()))
    }

    /// Alias for [`EventTrace::record`] at call sites that prefer event
    /// terminology.
    pub fn record_event(&self, kind: &str, payload: &[u8]) -> Result<TraceEvent, TraceError> {
        self.record(kind, payload)
    }

    /// Records owned event data without an additional payload clone.
    pub fn record_data(&self, data: TraceEventData) -> Result<TraceEvent, TraceError> {
        let event_bytes = data.byte_len().ok_or(TraceError::InvalidLimit)?;
        let mut state = recover_lock(&self.state);
        validate_data(&state.limits, event_bytes, &data)?;
        let event_count = state
            .events
            .len()
            .checked_add(1)
            .ok_or(TraceError::InvalidLimit)?;
        let total_bytes = state
            .total_bytes
            .checked_add(event_bytes)
            .ok_or(TraceError::InvalidLimit)?;
        if event_count > state.limits.max_events || total_bytes > state.limits.max_total_bytes {
            return Err(TraceError::CapacityExceeded {
                event_count,
                total_bytes,
            });
        }
        let sequence = state
            .next_sequence
            .checked_add(1)
            .ok_or(TraceError::SequenceOverflow)?;
        let event = TraceEvent {
            sequence: state.next_sequence,
            data,
        };
        state.next_sequence = sequence;
        state.total_bytes = total_bytes;
        state.events.push(event.clone());
        Ok(event)
    }

    /// Returns a bounded snapshot suitable for serialization or replay.
    #[must_use]
    pub fn snapshot(&self) -> Vec<TraceEvent> {
        recover_lock(&self.state).events.clone()
    }

    /// Creates a replay cursor over the current snapshot.
    #[must_use]
    pub fn replay(&self) -> ReplayCursor {
        let state = recover_lock(&self.state);
        ReplayCursor::from_log(ReplayLog {
            limits: state.limits,
            events: state.events.clone(),
            total_bytes: state.total_bytes,
        })
    }

    /// Clears retained events while preserving the next sequence number.
    pub fn clear(&self) {
        let mut state = recover_lock(&self.state);
        state.events.clear();
        state.total_bytes = 0;
    }
}

/// An owned, validated event stream used to construct replay cursors.
#[derive(Clone, PartialEq, Eq)]
pub struct ReplayLog {
    limits: TraceLimits,
    events: Vec<TraceEvent>,
    total_bytes: usize,
}

impl fmt::Debug for ReplayLog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayLog")
            .field("limits", &self.limits)
            .field("event_count", &self.events.len())
            .field("total_bytes", &self.total_bytes)
            .finish()
    }
}

impl ReplayLog {
    /// Validates and owns replay events under explicit bounds.
    pub fn new(events: Vec<TraceEvent>, limits: TraceLimits) -> Result<Self, TraceError> {
        let mut total_bytes = 0_usize;
        let mut previous_sequence = None;
        for (position, event) in events.iter().enumerate() {
            if let Some(previous) = previous_sequence
                && event.sequence <= previous
            {
                return Err(TraceError::NonMonotonicSequence {
                    position,
                    previous,
                    actual: event.sequence,
                });
            }
            previous_sequence = Some(event.sequence);
            let bytes = event.data.byte_len().ok_or(TraceError::InvalidLimit)?;
            validate_data(&limits, bytes, &event.data)?;
            total_bytes = total_bytes
                .checked_add(bytes)
                .ok_or(TraceError::InvalidLimit)?;
        }
        if events.len() > limits.max_events || total_bytes > limits.max_total_bytes {
            return Err(TraceError::CapacityExceeded {
                event_count: events.len(),
                total_bytes,
            });
        }
        Ok(Self {
            limits,
            events,
            total_bytes,
        })
    }

    /// Returns bounded default replay limits for a supplied event vector.
    pub fn from_events(events: Vec<TraceEvent>) -> Result<Self, TraceError> {
        Self::new(events, TraceLimits::default())
    }

    /// Returns the configured replay limits.
    #[must_use]
    pub const fn limits(&self) -> TraceLimits {
        self.limits
    }

    /// Returns the number of expected events.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Returns whether no events are expected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Returns the retained byte count.
    #[must_use]
    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Returns the expected events as an immutable slice.
    #[must_use]
    pub fn events(&self) -> &[TraceEvent] {
        &self.events
    }

    /// Starts replay at the first event.
    #[must_use]
    pub fn replay(&self) -> ReplayCursor {
        ReplayCursor::from_log(self.clone())
    }
}

/// Errors returned by replay consumption.
#[derive(Clone, PartialEq, Eq)]
pub enum ReplayError {
    /// The caller emitted an event after the expected stream ended.
    Exhausted {
        /// Zero-based event position at which the extra event occurred.
        position: usize,
        /// The extra event, when one was supplied and it satisfied input
        /// bounds.  [`ReplayCursor::next_expected`] has no actual event and
        /// therefore reports `None`.
        actual: Option<TraceEventData>,
    },
    /// The actual event differs from the expected event at this position.
    Mismatch {
        /// Zero-based event position.
        position: usize,
        /// Expected event data.
        expected: TraceEventData,
        /// Actual event data.
        actual: TraceEventData,
    },
    /// The event payload matches but its sequence number differs.
    SequenceMismatch {
        /// Zero-based event position.
        position: usize,
        /// Expected sequence number.
        expected: u64,
        /// Actual sequence number.
        actual: u64,
    },
    /// Replay finished before all expected events were consumed.
    TrailingEvents {
        /// Position at which `finish` was called.
        position: usize,
        /// Number of events still expected.
        remaining: usize,
    },
    /// Actual replay input violated trace limits.
    InvalidInput(TraceError),
}

impl fmt::Debug for ReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("ReplayError");
        match self {
            Self::Exhausted { position, actual } => debug
                .field("kind", &"Exhausted")
                .field("position", position)
                .field("actual", &actual.as_ref().map(TraceEventData::redacted)),
            Self::Mismatch {
                position,
                expected,
                actual,
            } => debug
                .field("kind", &"Mismatch")
                .field("position", position)
                .field("expected", &expected.redacted())
                .field("actual", &actual.redacted()),
            Self::SequenceMismatch {
                position,
                expected,
                actual,
            } => debug
                .field("kind", &"SequenceMismatch")
                .field("position", position)
                .field("expected", expected)
                .field("actual", actual),
            Self::TrailingEvents {
                position,
                remaining,
            } => debug
                .field("kind", &"TrailingEvents")
                .field("position", position)
                .field("remaining", remaining),
            Self::InvalidInput(error) => debug.field("kind", &"InvalidInput").field("error", error),
        };
        debug.finish()
    }
}

impl ReplayError {
    /// Returns the stable error code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Exhausted { .. } => ErrorCode::ReplayExhausted,
            Self::Mismatch { .. } => ErrorCode::ReplayMismatch,
            Self::SequenceMismatch { .. } => ErrorCode::ReplaySequenceMismatch,
            Self::TrailingEvents { .. } => ErrorCode::ReplayTrailingEvents,
            Self::InvalidInput(error) => error.code(),
        }
    }

    /// Returns the replay position associated with this error.
    #[must_use]
    pub const fn position(&self) -> usize {
        match self {
            Self::Exhausted { position, .. }
            | Self::Mismatch { position, .. }
            | Self::SequenceMismatch { position, .. }
            | Self::TrailingEvents { position, .. } => *position,
            Self::InvalidInput(_) => 0,
        }
    }
}

impl fmt::Display for ReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exhausted { position, .. } => {
                write!(
                    formatter,
                    "{}: extra event at position {position}",
                    self.code()
                )
            }
            Self::Mismatch { position, .. } => {
                write!(
                    formatter,
                    "{}: event mismatch at position {position}",
                    self.code()
                )
            }
            Self::SequenceMismatch {
                position,
                expected,
                actual,
            } => write!(
                formatter,
                "{}: sequence mismatch at position {position}: expected {expected}, got {actual}",
                self.code()
            ),
            Self::TrailingEvents {
                position,
                remaining,
            } => write!(
                formatter,
                "{}: {remaining} event(s) remain at position {position}",
                self.code()
            ),
            Self::InvalidInput(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ReplayError {}
impl StableError for ReplayError {
    fn code(&self) -> ErrorCode {
        self.code()
    }
}

/// A cursor that compares actual logical events with a bounded replay log.
#[derive(Clone)]
pub struct ReplayCursor {
    log: ReplayLog,
    position: usize,
}

impl fmt::Debug for ReplayCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayCursor")
            .field("position", &self.position)
            .field("remaining", &self.remaining())
            .field("log", &self.log)
            .finish()
    }
}

impl ReplayCursor {
    fn from_log(log: ReplayLog) -> Self {
        Self { log, position: 0 }
    }

    /// Returns the current zero-based position.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.position
    }

    /// Returns the number of expected events not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.log.len().saturating_sub(self.position)
    }

    /// Consumes the next expected event without comparing it.
    pub fn next_expected(&mut self) -> Result<TraceEvent, ReplayError> {
        let event = self
            .log
            .events
            .get(self.position)
            .cloned()
            .ok_or(ReplayError::Exhausted {
                position: self.position,
                actual: None,
            })?;
        self.position += 1;
        Ok(event)
    }

    /// Compares and consumes one event by kind and payload.
    pub fn expect(&mut self, kind: &str, payload: &[u8]) -> Result<TraceEvent, ReplayError> {
        let data = TraceEventData::new(kind, payload.to_vec());
        self.validate_actual(&data)?;
        let Some(expected) = self.log.events.get(self.position) else {
            return Err(ReplayError::Exhausted {
                position: self.position,
                actual: Some(data),
            });
        };
        if expected.data != data {
            return Err(ReplayError::Mismatch {
                position: self.position,
                expected: expected.data.clone(),
                actual: data,
            });
        }
        self.position += 1;
        Ok(expected.clone())
    }

    /// Alias for [`ReplayCursor::expect`].
    pub fn assert_next(&mut self, kind: &str, payload: &[u8]) -> Result<TraceEvent, ReplayError> {
        self.expect(kind, payload)
    }

    /// Compares and consumes a complete event, including its sequence number.
    pub fn expect_event(&mut self, actual: &TraceEvent) -> Result<TraceEvent, ReplayError> {
        self.validate_actual(&actual.data)?;
        let Some(expected) = self.log.events.get(self.position) else {
            return Err(ReplayError::Exhausted {
                position: self.position,
                actual: Some(actual.data.clone()),
            });
        };
        if expected.sequence != actual.sequence {
            return Err(ReplayError::SequenceMismatch {
                position: self.position,
                expected: expected.sequence,
                actual: actual.sequence,
            });
        }
        if expected != actual {
            return Err(ReplayError::Mismatch {
                position: self.position,
                expected: expected.data.clone(),
                actual: actual.data.clone(),
            });
        }
        self.position += 1;
        Ok(expected.clone())
    }

    /// Asserts that the complete expected stream has been consumed.
    pub fn finish(&self) -> Result<(), ReplayError> {
        let remaining = self.remaining();
        if remaining == 0 {
            Ok(())
        } else {
            Err(ReplayError::TrailingEvents {
                position: self.position,
                remaining,
            })
        }
    }

    fn validate_actual(&self, data: &TraceEventData) -> Result<(), ReplayError> {
        let bytes = data
            .byte_len()
            .ok_or(ReplayError::InvalidInput(TraceError::InvalidLimit))?;
        validate_data(&self.log.limits, bytes, data).map_err(ReplayError::InvalidInput)
    }
}

fn validate_data(
    limits: &TraceLimits,
    event_bytes: usize,
    data: &TraceEventData,
) -> Result<(), TraceError> {
    validate_lengths(limits, data.kind.len(), event_bytes)
}

fn validate_lengths(
    limits: &TraceLimits,
    kind_bytes: usize,
    event_bytes: usize,
) -> Result<(), TraceError> {
    if kind_bytes > limits.max_kind_bytes {
        return Err(TraceError::KindTooLarge {
            actual: kind_bytes,
            limit: limits.max_kind_bytes,
        });
    }
    if event_bytes > limits.max_event_bytes {
        return Err(TraceError::EventTooLarge {
            actual: event_bytes,
            limit: limits.max_event_bytes,
        });
    }
    Ok(())
}

fn recover_lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    // Test fixtures use unwrap to keep the assertion setup concise; every
    // value is deliberately within the bounds being tested.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn limits() -> TraceLimits {
        TraceLimits::new(4, 16, 32).with_kind_limit(8)
    }

    #[test]
    fn records_stable_sequences_and_replays() {
        let trace = EventTrace::new(limits());
        let first = trace.record("wake", &[1]).unwrap();
        let second = trace.record("cancel", &[2, 3]).unwrap();
        assert_eq!(first.sequence, 0);
        assert_eq!(second.sequence, 1);
        let mut replay = trace.replay();
        assert_eq!(replay.expect("wake", &[1]).unwrap(), first);
        assert_eq!(replay.expect("cancel", &[2, 3]).unwrap(), second);
        replay.finish().unwrap();
    }

    #[test]
    fn mismatch_exhaustion_and_trailing_are_typed() {
        let trace = EventTrace::new(limits());
        trace.record("one", &[]).unwrap();
        let mut replay = trace.replay();
        let error = replay.expect("two", &[]).unwrap_err();
        assert_eq!(error.code(), ErrorCode::ReplayMismatch);
        assert_eq!(error.position(), 0);

        replay.expect("one", &[]).unwrap();
        let error = replay.expect("three", &[]).unwrap_err();
        assert_eq!(error.code(), ErrorCode::ReplayExhausted);

        let replay = trace.replay();
        let error = replay.finish().unwrap_err();
        assert_eq!(error.code(), ErrorCode::ReplayTrailingEvents);
    }

    #[test]
    fn event_and_total_limits_never_partially_record() {
        let trace = EventTrace::new(TraceLimits::new(1, 4, 4));
        trace.record("a", &[1, 2, 3]).unwrap();
        let error = trace.record("b", &[]).unwrap_err();
        assert_eq!(error.code(), ErrorCode::TraceCapacity);
        assert_eq!(trace.len(), 1);
        assert_eq!(trace.snapshot()[0].sequence, 0);

        let trace = EventTrace::new(TraceLimits::new(4, 4, 10));
        let error = trace.record("long", &[1]).unwrap_err();
        assert_eq!(error.code(), ErrorCode::TraceEventTooLarge);
    }

    #[test]
    fn kind_limit_and_replay_input_limit_are_enforced() {
        let trace = EventTrace::new(limits());
        let error = trace.record("too-long-kind", &[]).unwrap_err();
        assert_eq!(error.code(), ErrorCode::TraceKindTooLarge);

        let log = ReplayLog::new(
            vec![TraceEvent::new(0, "too-long-kind", Vec::<u8>::new())],
            limits(),
        )
        .unwrap_err();
        assert_eq!(log.code(), ErrorCode::TraceKindTooLarge);
    }

    #[test]
    fn replay_log_rejects_duplicate_and_decreasing_sequences() {
        let duplicate = ReplayLog::new(
            vec![
                TraceEvent::new(4, "one", Vec::<u8>::new()),
                TraceEvent::new(4, "two", Vec::<u8>::new()),
            ],
            limits(),
        )
        .unwrap_err();
        assert_eq!(duplicate.code(), ErrorCode::TraceSequenceInvalid);

        let decreasing = ReplayLog::new(
            vec![
                TraceEvent::new(5, "one", Vec::<u8>::new()),
                TraceEvent::new(3, "two", Vec::<u8>::new()),
            ],
            limits(),
        )
        .unwrap_err();
        assert_eq!(decreasing.code(), ErrorCode::TraceSequenceInvalid);
    }

    #[test]
    fn full_event_replay_reports_sequence_mismatch() {
        let trace = EventTrace::new(limits());
        let expected = trace.record("event", &[1]).unwrap();
        let mut replay = trace.replay();
        let actual = TraceEvent::new(expected.sequence + 1, "event", [1]);
        let error = replay.expect_event(&actual).unwrap_err();
        assert_eq!(error.code(), ErrorCode::ReplaySequenceMismatch);
        assert_eq!(replay.position(), 0);
    }

    #[test]
    fn trace_sequence_overflow_does_not_partially_record() {
        let trace = EventTrace::new(limits());
        {
            let mut state = recover_lock(&trace.state);
            state.next_sequence = u64::MAX;
        }
        let error = trace.record("overflow", &[]).unwrap_err();
        assert_eq!(error.code(), ErrorCode::TraceSequenceOverflow);
        assert!(trace.is_empty());
    }

    #[test]
    fn cloned_trace_shares_sequence_and_clear_is_bounded() {
        let trace = EventTrace::new(limits());
        let clone = trace.clone();
        clone.record("a", &[]).unwrap();
        assert_eq!(trace.len(), 1);
        trace.clear();
        let event = clone.record("b", &[]).unwrap();
        assert_eq!(event.sequence, 1);
        assert_eq!(trace.len(), 1);
    }

    #[test]
    fn trace_and_replay_debug_omit_kind_and_payload_contents() {
        let trace = EventTrace::new(TraceLimits::new(4, 32, 64).with_kind_limit(32));
        trace.record("secret-kind", b"secret-payload").unwrap();
        let debug = format!("{trace:?}{:?}", trace.snapshot());
        assert!(!debug.contains("secret-kind"));
        assert!(!debug.contains("secret-payload"));

        let mut replay = trace.replay();
        let error = replay.expect("other", b"secret-payload").unwrap_err();
        let error_debug = format!("{error:?}");
        assert!(!error_debug.contains("secret-kind"));
        assert!(!error_debug.contains("secret-payload"));
    }
}
