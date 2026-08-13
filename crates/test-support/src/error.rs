// SPDX-License-Identifier: Apache-2.0
//! Stable error codes shared by deterministic test capabilities.

use std::fmt;

/// Machine-readable error identifiers for this crate.
///
/// The string returned by [`ErrorCode::as_str`] is the compatibility key.  It
/// is intentionally independent of localized display text and should be used
/// by differential tests and fixture manifests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// A clock operation would overflow its wall or monotonic representation.
    ClockOverflow,
    /// A requested monotonic deadline is earlier than the current time.
    ClockMovedBackward,
    /// A timer capacity limit was reached.
    TimerCapacity,
    /// A timer deadline calculation overflowed.
    TimerDeadlineOverflow,
    /// A timer sequence or identifier cannot be incremented.
    TimerSequenceOverflow,
    /// A timer handle no longer refers to an active registration.
    TimerUnknown,
    /// A timer/sleeper owner still has registrations when leak checking ran.
    TimerLeak,
    /// A timer lifecycle trace could not retain another bounded event.
    TimerTraceCapacity,
    /// A random range has no values.
    RandomEmptyRange,
    /// A random scope would exceed the configured nesting depth.
    RandomScopeDepth,
    /// A random scope path would exceed the configured byte bound.
    RandomScopeBytes,
    /// A trace configuration or input limit is invalid.
    TraceInvalidLimit,
    /// A trace has reached its event or total-byte bound.
    TraceCapacity,
    /// A trace event exceeds its per-event bound.
    TraceEventTooLarge,
    /// A trace kind exceeds its kind-length bound.
    TraceKindTooLarge,
    /// A trace sequence number cannot be incremented.
    TraceSequenceOverflow,
    /// Replay input contains a duplicate or decreasing sequence number.
    TraceSequenceInvalid,
    /// Replay was asked for an event after the expected stream ended.
    ReplayExhausted,
    /// A replay event differs from the expected event.
    ReplayMismatch,
    /// A replay event has the right data but the wrong sequence number.
    ReplaySequenceMismatch,
    /// Replay ended while expected events remained.
    ReplayTrailingEvents,
    /// A deterministic scheduler has reached its active-task bound.
    SchedulerCapacity,
    /// A deterministic scheduler's event log has reached its bound.
    SchedulerEventCapacity,
    /// A scheduler deadline calculation overflowed.
    SchedulerDeadlineOverflow,
    /// A scheduler task or sequence identifier cannot be incremented.
    SchedulerSequenceOverflow,
    /// A scheduler handle does not refer to an active task.
    SchedulerUnknownTask,
    /// A scheduler owner still has registrations when leak checking ran.
    SchedulerLeak,
    /// The deterministic scheduler watchdog found no progress with work left.
    SchedulerDeadlock,
    /// The deterministic scheduler watchdog found a ready task not being served.
    SchedulerStarvation,
    /// The deterministic scheduler exceeded its task-creation budget.
    SchedulerRunaway,
    /// The deterministic scheduler watchdog exceeded its observation budget.
    SchedulerWatchdogLimit,
    /// A transport script has no response left for a request.
    TransportScriptExhausted,
    /// A transport request did not match the next scripted expectation.
    TransportRequestMismatch,
    /// A fake transport body exceeded a configured bound.
    TransportBodyTooLarge,
    /// A fake transport header exceeded a configured bound.
    TransportHeaderTooLarge,
    /// A fake transport request or response exceeded its header-count bound.
    TransportHeaderCountTooLarge,
    /// A fake transport method exceeded its configured bound.
    TransportMethodTooLarge,
    /// A fake transport target exceeded its configured bound.
    TransportTargetTooLarge,
    /// The complete scripted transport exceeded its byte bound.
    TransportScriptTooLarge,
    /// A retained transport event exceeded its byte bound.
    TransportEventTooLarge,
    /// A fake transport step or event log exceeded a configured bound.
    TransportCapacity,
    /// A fake transport returned a logical delay to the caller.
    TransportDelayPending,
    /// One logical transport delay exceeded the per-step bound.
    TransportDelayTooLarge,
    /// Aggregate logical transport delay exceeded its bound.
    TransportDelayAggregateTooLarge,
    /// A fake transport size calculation overflowed.
    TransportInvalidSize,
    /// A scripted response omitted its terminal end marker.
    TransportMissingEnd,
    /// A scripted response contains data after its first terminal end marker.
    TransportUnexpectedEnd,
    /// A transport exchange ended before a terminal response step was consumed.
    TransportIncomplete,
    /// A transport request/event sequence number cannot be incremented.
    TransportSequenceOverflow,
    /// A scripted transport reset the exchange.
    TransportReset,
    /// A transport exchange was cancelled before its terminal step.
    TransportCancelled,
    /// A transport owner still has active exchanges when leak checking ran.
    TransportLeak,
    /// A scripted transport contained a step after its terminal reset.
    TransportUnexpectedAfterReset,
    /// A fixture identifier or metadata value is invalid.
    FixtureInvalidMetadata,
    /// A fixture contains a duplicate artifact name.
    FixtureDuplicateArtifact,
    /// A fixture artifact exceeds its configured bound.
    FixtureArtifactTooLarge,
    /// A fixture artifact name exceeds its configured byte bound.
    FixtureArtifactNameTooLarge,
    /// A fixture exceeds its configured artifact or byte-count bound.
    FixtureCapacity,
    /// A canonical record or stream exceeds its configured bound.
    CanonicalCapacity,
    /// Canonical text input or output exceeds its configured byte bound.
    CanonicalTextTooLarge,
    /// A canonical field exceeds its configured byte bound.
    CanonicalFieldTooLarge,
    /// A canonical event stream exceeds its configured event bound.
    CanonicalEventCapacity,
    /// A canonical event exceeds its configured byte bound.
    CanonicalEventTooLarge,
    /// A canonical event stream exceeds its aggregate byte bound.
    CanonicalEventBytesCapacity,
}

impl ErrorCode {
    /// Returns the stable machine-readable spelling of this code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClockOverflow => "TEST_SUPPORT_CLOCK_OVERFLOW",
            Self::ClockMovedBackward => "TEST_SUPPORT_CLOCK_MOVED_BACKWARD",
            Self::TimerCapacity => "TEST_SUPPORT_TIMER_CAPACITY",
            Self::TimerDeadlineOverflow => "TEST_SUPPORT_TIMER_DEADLINE_OVERFLOW",
            Self::TimerSequenceOverflow => "TEST_SUPPORT_TIMER_SEQUENCE_OVERFLOW",
            Self::TimerUnknown => "TEST_SUPPORT_TIMER_UNKNOWN",
            Self::TimerLeak => "TEST_SUPPORT_TIMER_LEAK",
            Self::TimerTraceCapacity => "TEST_SUPPORT_TIMER_TRACE_CAPACITY",
            Self::RandomEmptyRange => "TEST_SUPPORT_RANDOM_EMPTY_RANGE",
            Self::RandomScopeDepth => "TEST_SUPPORT_RANDOM_SCOPE_DEPTH",
            Self::RandomScopeBytes => "TEST_SUPPORT_RANDOM_SCOPE_BYTES",
            Self::TraceInvalidLimit => "TEST_SUPPORT_TRACE_INVALID_LIMIT",
            Self::TraceCapacity => "TEST_SUPPORT_TRACE_CAPACITY",
            Self::TraceEventTooLarge => "TEST_SUPPORT_TRACE_EVENT_TOO_LARGE",
            Self::TraceKindTooLarge => "TEST_SUPPORT_TRACE_KIND_TOO_LARGE",
            Self::TraceSequenceOverflow => "TEST_SUPPORT_TRACE_SEQUENCE_OVERFLOW",
            Self::TraceSequenceInvalid => "TEST_SUPPORT_TRACE_SEQUENCE_INVALID",
            Self::ReplayExhausted => "TEST_SUPPORT_REPLAY_EXHAUSTED",
            Self::ReplayMismatch => "TEST_SUPPORT_REPLAY_MISMATCH",
            Self::ReplaySequenceMismatch => "TEST_SUPPORT_REPLAY_SEQUENCE_MISMATCH",
            Self::ReplayTrailingEvents => "TEST_SUPPORT_REPLAY_TRAILING_EVENTS",
            Self::SchedulerCapacity => "TEST_SUPPORT_SCHEDULER_CAPACITY",
            Self::SchedulerEventCapacity => "TEST_SUPPORT_SCHEDULER_EVENT_CAPACITY",
            Self::SchedulerDeadlineOverflow => "TEST_SUPPORT_SCHEDULER_DEADLINE_OVERFLOW",
            Self::SchedulerSequenceOverflow => "TEST_SUPPORT_SCHEDULER_SEQUENCE_OVERFLOW",
            Self::SchedulerUnknownTask => "TEST_SUPPORT_SCHEDULER_UNKNOWN_TASK",
            Self::SchedulerLeak => "TEST_SUPPORT_SCHEDULER_LEAK",
            Self::SchedulerDeadlock => "TEST_SUPPORT_SCHEDULER_DEADLOCK",
            Self::SchedulerStarvation => "TEST_SUPPORT_SCHEDULER_STARVATION",
            Self::SchedulerRunaway => "TEST_SUPPORT_SCHEDULER_RUNAWAY",
            Self::SchedulerWatchdogLimit => "TEST_SUPPORT_SCHEDULER_WATCHDOG_LIMIT",
            Self::TransportScriptExhausted => "TEST_SUPPORT_TRANSPORT_SCRIPT_EXHAUSTED",
            Self::TransportRequestMismatch => "TEST_SUPPORT_TRANSPORT_REQUEST_MISMATCH",
            Self::TransportBodyTooLarge => "TEST_SUPPORT_TRANSPORT_BODY_TOO_LARGE",
            Self::TransportHeaderTooLarge => "TEST_SUPPORT_TRANSPORT_HEADER_TOO_LARGE",
            Self::TransportHeaderCountTooLarge => "TEST_SUPPORT_TRANSPORT_HEADER_COUNT_TOO_LARGE",
            Self::TransportMethodTooLarge => "TEST_SUPPORT_TRANSPORT_METHOD_TOO_LARGE",
            Self::TransportTargetTooLarge => "TEST_SUPPORT_TRANSPORT_TARGET_TOO_LARGE",
            Self::TransportScriptTooLarge => "TEST_SUPPORT_TRANSPORT_SCRIPT_TOO_LARGE",
            Self::TransportEventTooLarge => "TEST_SUPPORT_TRANSPORT_EVENT_TOO_LARGE",
            Self::TransportCapacity => "TEST_SUPPORT_TRANSPORT_CAPACITY",
            Self::TransportDelayPending => "TEST_SUPPORT_TRANSPORT_DELAY_PENDING",
            Self::TransportDelayTooLarge => "TEST_SUPPORT_TRANSPORT_DELAY_TOO_LARGE",
            Self::TransportDelayAggregateTooLarge => {
                "TEST_SUPPORT_TRANSPORT_DELAY_AGGREGATE_TOO_LARGE"
            }
            Self::TransportInvalidSize => "TEST_SUPPORT_TRANSPORT_INVALID_SIZE",
            Self::TransportMissingEnd => "TEST_SUPPORT_TRANSPORT_MISSING_END",
            Self::TransportUnexpectedEnd => "TEST_SUPPORT_TRANSPORT_UNEXPECTED_END",
            Self::TransportIncomplete => "TEST_SUPPORT_TRANSPORT_INCOMPLETE",
            Self::TransportSequenceOverflow => "TEST_SUPPORT_TRANSPORT_SEQUENCE_OVERFLOW",
            Self::TransportReset => "TEST_SUPPORT_TRANSPORT_RESET",
            Self::TransportCancelled => "TEST_SUPPORT_TRANSPORT_CANCELLED",
            Self::TransportLeak => "TEST_SUPPORT_TRANSPORT_LEAK",
            Self::TransportUnexpectedAfterReset => "TEST_SUPPORT_TRANSPORT_UNEXPECTED_AFTER_RESET",
            Self::FixtureInvalidMetadata => "TEST_SUPPORT_FIXTURE_INVALID_METADATA",
            Self::FixtureDuplicateArtifact => "TEST_SUPPORT_FIXTURE_DUPLICATE_ARTIFACT",
            Self::FixtureArtifactTooLarge => "TEST_SUPPORT_FIXTURE_ARTIFACT_TOO_LARGE",
            Self::FixtureArtifactNameTooLarge => "TEST_SUPPORT_FIXTURE_ARTIFACT_NAME_TOO_LARGE",
            Self::FixtureCapacity => "TEST_SUPPORT_FIXTURE_CAPACITY",
            Self::CanonicalCapacity => "TEST_SUPPORT_CANONICAL_CAPACITY",
            Self::CanonicalTextTooLarge => "TEST_SUPPORT_CANONICAL_TEXT_TOO_LARGE",
            Self::CanonicalFieldTooLarge => "TEST_SUPPORT_CANONICAL_FIELD_TOO_LARGE",
            Self::CanonicalEventCapacity => "TEST_SUPPORT_CANONICAL_EVENT_CAPACITY",
            Self::CanonicalEventTooLarge => "TEST_SUPPORT_CANONICAL_EVENT_TOO_LARGE",
            Self::CanonicalEventBytesCapacity => "TEST_SUPPORT_CANONICAL_EVENT_BYTES_CAPACITY",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A common interface implemented by every capability error.
pub trait StableError: std::error::Error {
    /// Returns the stable machine-readable code for this error.
    fn code(&self) -> ErrorCode;
}
