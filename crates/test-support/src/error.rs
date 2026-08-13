// SPDX-License-Identifier: Apache-2.0
//! Stable error codes shared by deterministic test capabilities.

use std::fmt;

/// Default upper bound for diagnostic context retained by the test harness.
///
/// Error displays are for a human at a local assertion boundary and are not a
/// safe wire or artifact format.  Anything that crosses a harness boundary
/// should use [`ErrorDiagnostic`] (or [`BoundedDiagnostic`]) so a malformed
/// fixture cannot turn an error into an unbounded allocation or an evidence
/// artifact containing arbitrary input.
pub const MAX_DIAGNOSTIC_BYTES: usize = 1024;

/// Placeholder used for context that is intentionally not retained.
pub const REDACTED_VALUE: &str = "<redacted>";

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

    /// Alias for [`ErrorCode::as_str`] at serialization boundaries.
    #[must_use]
    pub const fn stable_code(self) -> &'static str {
        self.as_str()
    }

    /// Every code in this crate, in stable declaration order.
    ///
    /// Keeping the registry next to [`ErrorCode::as_str`] makes the closed
    /// vocabulary auditable and lets harnesses validate manifests without
    /// matching on every individual variant.  The slice is immutable and has
    /// no runtime allocation.
    pub const ALL: &[Self] = &[
        Self::ClockOverflow,
        Self::ClockMovedBackward,
        Self::TimerCapacity,
        Self::TimerDeadlineOverflow,
        Self::TimerSequenceOverflow,
        Self::TimerUnknown,
        Self::TimerLeak,
        Self::TimerTraceCapacity,
        Self::RandomEmptyRange,
        Self::RandomScopeDepth,
        Self::RandomScopeBytes,
        Self::TraceInvalidLimit,
        Self::TraceCapacity,
        Self::TraceEventTooLarge,
        Self::TraceKindTooLarge,
        Self::TraceSequenceOverflow,
        Self::TraceSequenceInvalid,
        Self::ReplayExhausted,
        Self::ReplayMismatch,
        Self::ReplaySequenceMismatch,
        Self::ReplayTrailingEvents,
        Self::SchedulerCapacity,
        Self::SchedulerEventCapacity,
        Self::SchedulerDeadlineOverflow,
        Self::SchedulerSequenceOverflow,
        Self::SchedulerUnknownTask,
        Self::SchedulerLeak,
        Self::SchedulerDeadlock,
        Self::SchedulerStarvation,
        Self::SchedulerRunaway,
        Self::SchedulerWatchdogLimit,
        Self::TransportScriptExhausted,
        Self::TransportRequestMismatch,
        Self::TransportBodyTooLarge,
        Self::TransportHeaderTooLarge,
        Self::TransportHeaderCountTooLarge,
        Self::TransportMethodTooLarge,
        Self::TransportTargetTooLarge,
        Self::TransportScriptTooLarge,
        Self::TransportEventTooLarge,
        Self::TransportCapacity,
        Self::TransportDelayPending,
        Self::TransportDelayTooLarge,
        Self::TransportDelayAggregateTooLarge,
        Self::TransportInvalidSize,
        Self::TransportMissingEnd,
        Self::TransportUnexpectedEnd,
        Self::TransportIncomplete,
        Self::TransportSequenceOverflow,
        Self::TransportReset,
        Self::TransportCancelled,
        Self::TransportLeak,
        Self::TransportUnexpectedAfterReset,
        Self::FixtureInvalidMetadata,
        Self::FixtureDuplicateArtifact,
        Self::FixtureArtifactTooLarge,
        Self::FixtureArtifactNameTooLarge,
        Self::FixtureCapacity,
        Self::CanonicalCapacity,
        Self::CanonicalTextTooLarge,
        Self::CanonicalFieldTooLarge,
        Self::CanonicalEventCapacity,
        Self::CanonicalEventTooLarge,
        Self::CanonicalEventBytesCapacity,
    ];

    /// Parses a stable code spelling without accepting localized text.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|code| code.as_str() == value)
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A UTF-8 diagnostic that is bounded before it is retained or emitted.
///
/// The `Debug` representation deliberately reports only byte length and
/// truncation state.  Callers that need the text for a local assertion can
/// use [`BoundedDiagnostic::as_str`] or `Display`; generic logs should prefer
/// `Debug` so fixture values do not escape into telemetry.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BoundedDiagnostic {
    text: String,
    truncated: bool,
    redacted: bool,
}

impl BoundedDiagnostic {
    /// Retains at most `max_bytes` UTF-8 bytes of `value`.
    #[must_use]
    pub fn new(value: impl AsRef<str>, max_bytes: usize) -> Self {
        let value = value.as_ref();
        let max_bytes = max_bytes.min(MAX_DIAGNOSTIC_BYTES);
        if value.len() <= max_bytes {
            return Self {
                text: value.to_owned(),
                truncated: false,
                redacted: false,
            };
        }

        let mut text = String::new();
        if max_bytes >= '…'.len_utf8() {
            let prefix_bytes = max_bytes - '…'.len_utf8();
            // `value.get(..prefix_bytes)` can end in a UTF-8 continuation byte
            // even when `value.get(..max_bytes)` was not available.  Walking
            // char boundaries avoids a panic and keeps the bound exact.
            let mut safe_prefix = 0;
            for (index, character) in value.char_indices() {
                let next = index + character.len_utf8();
                if next > prefix_bytes {
                    break;
                }
                safe_prefix = next;
            }
            text.push_str(&value[..safe_prefix]);
            text.push('…');
        } else {
            let mut safe_prefix = 0;
            for (index, character) in value.char_indices() {
                let next = index + character.len_utf8();
                if next > max_bytes {
                    break;
                }
                safe_prefix = next;
            }
            text.push_str(&value[..safe_prefix]);
        }
        Self {
            text,
            truncated: true,
            redacted: false,
        }
    }

    /// Retains a fixed redaction marker under the requested byte bound.
    #[must_use]
    pub fn redacted(max_bytes: usize) -> Self {
        let mut diagnostic = Self::new(REDACTED_VALUE, max_bytes);
        diagnostic.redacted = true;
        diagnostic
    }

    /// Returns the bounded text for an explicitly local diagnostic.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns the retained UTF-8 byte length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.text.len()
    }

    /// Returns whether input was shortened to satisfy the bound.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Returns whether the value is an explicit redaction marker.
    #[must_use]
    pub const fn is_redacted(&self) -> bool {
        self.redacted
    }

    /// Returns whether no diagnostic text was retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }
}

impl fmt::Debug for BoundedDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedDiagnostic")
            .field("bytes", &self.text.len())
            .field("truncated", &self.truncated)
            .field("redacted", &self.redacted)
            .finish()
    }
}

impl fmt::Display for BoundedDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// Stable, redaction-safe projection of a capability error.
#[derive(Clone, PartialEq, Eq)]
pub struct ErrorDiagnostic {
    code: ErrorCode,
    context: BoundedDiagnostic,
}

impl ErrorDiagnostic {
    /// Creates a diagnostic with bounded context supplied by the caller.
    ///
    /// The context is assumed to be safe for local diagnostics.  Its `Debug`
    /// representation remains redacted; use `Display` only at an explicit
    /// assertion boundary.
    #[must_use]
    pub fn with_context(code: ErrorCode, context: impl AsRef<str>) -> Self {
        Self {
            code,
            context: BoundedDiagnostic::new(context, MAX_DIAGNOSTIC_BYTES),
        }
    }

    /// Creates a diagnostic containing no caller-controlled context.
    #[must_use]
    pub fn redacted(code: ErrorCode) -> Self {
        Self {
            code,
            context: BoundedDiagnostic::redacted(MAX_DIAGNOSTIC_BYTES),
        }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    /// Returns bounded context for an explicit local assertion boundary.
    #[must_use]
    pub fn context(&self) -> &str {
        self.context.as_str()
    }

    /// Returns the bounded context projection.
    #[must_use]
    pub const fn context_value(&self) -> &BoundedDiagnostic {
        &self.context
    }
}

impl fmt::Debug for ErrorDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ErrorDiagnostic")
            .field("code", &self.code)
            .field("context", &self.context)
            .finish()
    }
}

impl fmt::Display for ErrorDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.context)
    }
}

/// A common interface implemented by every capability error.
pub trait StableError: std::error::Error {
    /// Returns the stable machine-readable code for this error.
    fn code(&self) -> ErrorCode;

    /// Returns a redaction-safe diagnostic projection.
    ///
    /// Implementations may still expose their richer `Display` text at a
    /// local assertion boundary, but generic harnesses should use this method
    /// so malformed fixture input cannot become an unbounded or secret-bearing
    /// artifact.
    fn diagnostic(&self) -> ErrorDiagnostic {
        ErrorDiagnostic::redacted(self.code())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_code_registry_is_closed_ascii_unique_and_round_trips() {
        assert!(!ErrorCode::ALL.is_empty());
        for (index, code) in ErrorCode::ALL.iter().enumerate() {
            let spelling = code.as_str();
            assert!(spelling.is_ascii());
            assert!(spelling.starts_with("TEST_SUPPORT_"));
            assert_eq!(code.stable_code(), spelling);
            assert_eq!(ErrorCode::parse(spelling), Some(*code));
            assert_eq!(code.to_string(), spelling);
            assert!(
                ErrorCode::ALL[..index]
                    .iter()
                    .all(|previous| previous.as_str() != spelling)
            );
        }
        assert_eq!(ErrorCode::parse("TEST_SUPPORT_UNKNOWN"), None);
        assert_eq!(ErrorCode::parse("fixture capacity"), None);
    }

    #[test]
    fn bounded_diagnostic_is_utf8_safe_and_does_not_leak_in_debug() {
        let secret = "fixture-secret-雪-credential";
        let diagnostic = BoundedDiagnostic::new(secret, 10);
        assert!(diagnostic.len() <= 10);
        assert!(diagnostic.is_truncated());
        assert!(!diagnostic.as_str().contains(secret));
        assert!(!format!("{diagnostic:?}").contains("fixture-secret"));

        let oversized = "x".repeat(MAX_DIAGNOSTIC_BYTES + 1);
        let hard_bound = BoundedDiagnostic::new(oversized, usize::MAX);
        assert!(hard_bound.len() <= MAX_DIAGNOSTIC_BYTES);
        assert!(hard_bound.is_truncated());

        let redacted = BoundedDiagnostic::redacted(4);
        assert!(redacted.len() <= 4);
        assert!(redacted.is_redacted());
        assert!(!format!("{redacted:?}").contains(REDACTED_VALUE));
    }

    #[test]
    fn stable_error_default_diagnostic_contains_only_code_and_redaction() {
        #[derive(Debug)]
        struct FixtureFailure;

        impl fmt::Display for FixtureFailure {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("credential=fixture-secret")
            }
        }

        impl std::error::Error for FixtureFailure {}

        impl StableError for FixtureFailure {
            fn code(&self) -> ErrorCode {
                ErrorCode::FixtureInvalidMetadata
            }
        }

        let error = FixtureFailure;
        let diagnostic = error.diagnostic();
        assert_eq!(diagnostic.code(), ErrorCode::FixtureInvalidMetadata);
        assert_eq!(diagnostic.context(), REDACTED_VALUE);
        assert!(!format!("{diagnostic:?}").contains("fixture-secret"));
    }

    #[test]
    fn error_diagnostic_bounds_context_but_keeps_code_stable() {
        let context = "fixture-secret".repeat(MAX_DIAGNOSTIC_BYTES);
        let diagnostic = ErrorDiagnostic::with_context(ErrorCode::TransportReset, context);
        assert_eq!(diagnostic.code(), ErrorCode::TransportReset);
        assert!(diagnostic.context_value().len() <= MAX_DIAGNOSTIC_BYTES);
        assert!(diagnostic.context_value().is_truncated());
        assert!(!format!("{diagnostic:?}").contains("fixture-secret"));
        assert!(
            diagnostic
                .to_string()
                .starts_with("TEST_SUPPORT_TRANSPORT_RESET: ")
        );
    }
}
