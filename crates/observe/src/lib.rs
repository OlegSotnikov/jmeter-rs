// SPDX-License-Identifier: Apache-2.0
//! Runtime-neutral structured diagnostics.
//!
//! This crate deliberately has no runtime, exporter, logger, HTTP, or result
//! model dependency.  It owns the small diagnostic contract used at those
//! boundaries: bounded correlation identifiers, redacted key/value fields,
//! bounded metric counters/gauges/histograms, event and span records, and
//! explicit sink contracts.  A record is safe to clone and retain after it has
//! been built; untrusted input is never retained beyond the configured limits.

#![forbid(unsafe_code)]

mod router_adapter;
mod standalone_telemetry;

pub use router_adapter::{
    MAX_ROUTER_IDENTITY_BYTES, RouterAdmissionDiagnosticInput, RouterAdmissionOutcome,
    RouterConservationCounts, RouterConservationDiagnosticInput, RouterDiagnosticAdapter,
    RouterDiagnosticError, RouterFinalizationDiagnosticInput, RouterFinalizationStage,
};
pub use standalone_telemetry::{
    Decision0009CapabilityRejectionKind, Decision0009Disposition, Decision0009DispositionInput,
    Decision0009Mode, Decision0009PathCount, Decision0009PathInput, Decision0009PathKind,
    Decision0009PreflightInput, Decision0009Telemetry, Decision0009TelemetryError,
    MAX_DECISION0009_PATHS, MAX_DECISION0009_TEXT_BYTES,
};

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Text inserted whenever a value is known to contain a secret.
///
/// This is a reserved sentinel, not an input-preservation guarantee. A
/// configured secret may overlap these bytes; byte-substring scanners must
/// recognize and ignore the complete sentinel rather than treating a marker
/// substring as evidence that the original secret escaped.
pub const REDACTED: &str = "[REDACTED]";

/// Maximum bytes retained by an identifier created by this crate.
pub const MAX_IDENTIFIER_BYTES: usize = 128;

/// Maximum bytes accepted by [`Secret::try_new`].
pub const MAX_SECRET_BYTES: usize = 4096;

/// Maximum configured exact secrets retained by one redaction policy.
pub const MAX_CONFIGURED_SECRETS: usize = 128;

/// Default maximum number of fields in one event or span.
pub const DEFAULT_MAX_FIELDS: usize = 32;

/// Default maximum bytes retained by one field key.
pub const DEFAULT_MAX_KEY_BYTES: usize = 64;

/// Default maximum bytes retained by one field value.
pub const DEFAULT_MAX_VALUE_BYTES: usize = 1024;

/// Absolute safety ceiling for one configured key bound.
pub const HARD_MAX_KEY_BYTES: usize = 16 * 1024;

/// Absolute safety ceiling for one configured value bound.
pub const HARD_MAX_VALUE_BYTES: usize = 1024 * 1024;

/// Absolute safety ceiling for one configured field-count bound.
pub const HARD_MAX_FIELDS: usize = 4096;

/// Maximum bytes scanned for one untrusted diagnostic value before policy
/// classification.  Values beyond this bound are rejected as a whole so a
/// secret after the retained prefix cannot bypass inspection.
pub const HARD_MAX_SCAN_BYTES: usize = HARD_MAX_VALUE_BYTES;

/// Maximum recursive structural redaction depth for nested URL, query,
/// header, and JSON-like values.  Values beyond this depth fail closed.
pub const MAX_REDACTION_DEPTH: usize = 8;

/// Default maximum records retained by [`InMemorySink`].
pub const DEFAULT_MAX_RECORDS: usize = 4096;

/// Default maximum bytes retained by [`InMemorySink`].
pub const DEFAULT_MAX_SINK_BYTES: usize = 4 * 1024 * 1024;

/// A caller-assigned, monotonically ordered identity for an observation
/// record.  Zero is reserved as the unassigned value and is rejected by
/// sinks; the observe crate never allocates a process-global sequence.
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SequenceId(u64);

impl SequenceId {
    /// Creates a sequence identity.  `0` is intentionally reserved for an
    /// unassigned record and is rejected when it enters a sink.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the raw sequence value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns whether this is an assigned, sink-valid identity.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.0 != 0
    }
}

impl fmt::Debug for SequenceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

impl fmt::Display for SequenceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A deterministic pair of monotonic and wall-clock readings.
///
/// The values are supplied by a caller-owned [`Clock`].  No system clock is
/// consulted by this crate, which keeps event ordering and span durations
/// reproducible in tests and in adapters.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Timestamp {
    monotonic_nanos: u64,
    wall_time_millis: i64,
}

impl Timestamp {
    /// Creates a timestamp from explicit monotonic nanoseconds and wall-clock
    /// milliseconds since the Unix epoch.
    #[must_use]
    pub const fn new(monotonic_nanos: u64, wall_time_millis: i64) -> Self {
        Self {
            monotonic_nanos,
            wall_time_millis,
        }
    }

    /// Alias for [`Self::new`] at wire/adaptor boundaries.
    #[must_use]
    pub const fn from_parts(monotonic_nanos: u64, wall_time_millis: i64) -> Self {
        Self::new(monotonic_nanos, wall_time_millis)
    }

    /// Returns the monotonic reading used for duration calculations.
    #[must_use]
    pub const fn monotonic_nanos(self) -> u64 {
        self.monotonic_nanos
    }

    /// Returns the caller-supplied wall-clock reading in milliseconds.
    #[must_use]
    pub const fn wall_time_millis(self) -> i64 {
        self.wall_time_millis
    }

    /// Computes a non-negative duration from a start reading.
    #[must_use]
    pub const fn duration_since(self, start: Self) -> Duration {
        Duration::from_nanos(self.monotonic_nanos.saturating_sub(start.monotonic_nanos))
    }

    /// Returns whether this reading is not before the supplied start reading
    /// on the monotonic axis.
    #[must_use]
    pub const fn is_monotonic_after(self, start: Self) -> bool {
        self.monotonic_nanos >= start.monotonic_nanos
    }
}

/// Explicit clock capability used by diagnostic constructors and span ends.
pub trait Clock: Send + Sync {
    /// Returns the next caller-defined monotonic/wall-clock reading.
    fn now(&self) -> Timestamp;
}

/// Explicit sequence capability used by diagnostic constructors and sinks.
pub trait Sequencer: Send + Sync {
    /// Returns the next non-zero sequence identity, or zero after exhaustion.
    fn next(&self) -> SequenceId;
}

/// A deterministic clock useful for adapters and unit tests.
#[derive(Debug)]
pub struct DeterministicClock {
    value: Mutex<Timestamp>,
}

impl DeterministicClock {
    /// Creates a clock at an explicit initial reading.
    #[must_use]
    pub fn new(value: Timestamp) -> Self {
        Self {
            value: Mutex::new(value),
        }
    }

    /// Replaces the current reading.
    pub fn set(&self, value: Timestamp) {
        *lock_timestamp(&self.value) = value;
    }

    /// Advances both readings by explicit deltas without sleeping.
    pub fn advance(&self, monotonic_nanos: u64, wall_time_millis: i64) {
        let mut value = lock_timestamp(&self.value);
        value.monotonic_nanos = value.monotonic_nanos.saturating_add(monotonic_nanos);
        value.wall_time_millis = value.wall_time_millis.saturating_add(wall_time_millis);
    }
}

impl Clock for DeterministicClock {
    fn now(&self) -> Timestamp {
        *lock_timestamp(&self.value)
    }
}

/// A caller-owned deterministic sequence source.  It has no process-global
/// state and can therefore be seeded independently for each run or test.
#[derive(Debug)]
pub struct DeterministicSequencer {
    next: AtomicU64,
}

/// Alias used by adapters that prefer the conventional manual-clock name.
pub type ManualClock = DeterministicClock;

/// Alias used by adapters that prefer an atomic sequence-source name.
pub type AtomicSequencer = DeterministicSequencer;

impl DeterministicSequencer {
    /// Creates a source whose first returned identity is `first`.
    #[must_use]
    pub const fn new(first: u64) -> Self {
        Self {
            next: AtomicU64::new(if first == 0 { 1 } else { first }),
        }
    }
}

impl Sequencer for DeterministicSequencer {
    fn next(&self) -> SequenceId {
        let result = self
            .next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            });
        match result {
            Ok(value) => SequenceId::new(value),
            Err(_) => SequenceId::default(),
        }
    }
}

fn lock_timestamp(state: &Mutex<Timestamp>) -> std::sync::MutexGuard<'_, Timestamp> {
    match state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Truncate UTF-8 text at a byte bound without splitting a code point.
fn truncate_text(value: &str, maximum: usize) -> (String, bool) {
    if value.len() <= maximum {
        return (value.to_owned(), false);
    }
    if maximum == 0 {
        return (String::new(), true);
    }
    let mut end = maximum.min(value.len());
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    (value[..end].to_owned(), true)
}

/// Append a text fragment up to a byte bound, preserving UTF-8 boundaries.
fn append_bounded(output: &mut String, fragment: &str, maximum: usize) -> bool {
    if output.len() >= maximum {
        return fragment.is_empty();
    }
    let remaining = maximum - output.len();
    if fragment.len() <= remaining {
        output.push_str(fragment);
        return true;
    }
    let (prefix, _) = truncate_text(fragment, remaining);
    output.push_str(&prefix);
    false
}

fn contains_control(value: &str) -> bool {
    contains_control_with_limit(value, HARD_MAX_SCAN_BYTES)
}

fn contains_control_with_limit(value: &str, maximum: usize) -> bool {
    if value.len() > maximum {
        return true;
    }
    value.chars().any(char::is_control)
}

fn contains_percent_encoded_control(value: &str, maximum: usize) -> bool {
    if value.len() > maximum {
        return true;
    }
    if !value.as_bytes().contains(&b'%') {
        return false;
    }
    let mut decoded = value.to_owned();
    for depth in 0..=MAX_REDACTION_DEPTH {
        if percent_decode(&decoded, maximum)
            .chars()
            .any(char::is_control)
        {
            return true;
        }
        if !decoded.as_bytes().contains(&b'%') {
            return false;
        }
        if depth == MAX_REDACTION_DEPTH {
            // The remaining encoded structure cannot be classified within
            // the bounded decode budget. Fail closed instead of allowing a
            // deeply escaped control sequence to reach an exporter.
            return true;
        }
        let next = percent_decode(&decoded, maximum);
        if next == decoded {
            return false;
        }
        decoded = next;
    }
    true
}

/// A deterministic, allocation-bounded digest used when an identity is too
/// long to retain losslessly.  The prefix keeps diagnostics recognizable while
/// the digest prevents two long values with the same prefix from collapsing to
/// one correlation ID.
fn bounded_identity(value: &str, maximum: usize) -> (String, bool) {
    if value.len() <= maximum {
        return (value.to_owned(), false);
    }
    let suffix = format!("~{:016x}", stable_digest(value.as_bytes()));
    let prefix_limit = maximum.saturating_sub(suffix.len());
    let (prefix, _) = truncate_text(value, prefix_limit);
    let mut output = String::with_capacity(maximum);
    output.push_str(&prefix);
    output.push_str(&suffix);
    (output, true)
}

/// Stable non-cryptographic digest for bounded identity/cardinality handling.
fn stable_digest(value: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in value {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3_u64);
    }
    hash
}

/// A bounded text value used for metadata which must not grow without limit.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct BoundedText(String);

impl BoundedText {
    fn new(value: impl AsRef<str>, maximum: usize) -> Self {
        Self(truncate_text(value.as_ref(), maximum).0)
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for BoundedText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

impl fmt::Display for BoundedText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Error returned when a value that must remain an identity or secret is too
/// large or empty.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InputError {
    /// The supplied identifier or metadata is empty.
    Empty,
    /// The supplied value exceeded its hard bound.
    TooLong {
        /// Actual input length in bytes.
        actual: usize,
        /// Maximum accepted length in bytes.
        maximum: usize,
    },
}

impl InputError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Empty => "observe.input.empty",
            Self::TooLong { .. } => "observe.input.too-long",
        }
    }
}

impl fmt::Display for InputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("observe.input.empty"),
            Self::TooLong { actual, maximum } => {
                write!(
                    formatter,
                    "observe.input.too-long ({actual} > {maximum} bytes)"
                )
            }
        }
    }
}

impl std::error::Error for InputError {}

macro_rules! identifier_type {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name {
            value: String,
            truncated: bool,
        }

        impl $name {
            /// Creates a bounded identifier.
            ///
            /// An overlong identity retains a recognizable prefix plus a
            /// deterministic digest suffix rather than a collision-prone raw
            /// prefix.  Callers which need to reject an overlong identity can
            /// use [`Self::try_new`].
            #[must_use]
            pub fn new(value: impl AsRef<str>) -> Self {
                let (value, truncated) = bounded_identity(value.as_ref(), MAX_IDENTIFIER_BYTES);
                Self { value, truncated }
            }

            /// Creates an identifier only when it is non-empty and within the
            /// hard identifier bound.
            pub fn try_new(value: impl AsRef<str>) -> Result<Self, InputError> {
                let value = value.as_ref();
                if value.is_empty() {
                    return Err(InputError::Empty);
                }
                if value.len() > MAX_IDENTIFIER_BYTES {
                    return Err(InputError::TooLong {
                        actual: value.len(),
                        maximum: MAX_IDENTIFIER_BYTES,
                    });
                }
                Ok(Self {
                    value: value.to_owned(),
                    truncated: false,
                })
            }

            /// Creates an identifier from a numeric logical identity.
            #[must_use]
            pub fn from_u64(value: u64) -> Self {
                Self::new(value.to_string())
            }

            /// Returns the bounded identifier text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.value
            }

            /// Consumes the identifier and returns its bounded text.
            #[must_use]
            pub fn into_string(self) -> String {
                self.value
            }

            /// Returns whether [`Self::new`] had to bound its input.
            #[must_use]
            pub fn was_truncated(&self, original: impl AsRef<str>) -> bool {
                original.as_ref().len() > self.value.len()
            }

            fn was_bounded(&self) -> bool {
                self.truncated
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&REDACTED)
                    .finish()
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self::new(value)
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self::new(value)
            }
        }

        impl From<u64> for $name {
            fn from(value: u64) -> Self {
                Self::from_u64(value)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.value)
            }
        }
    };
}

identifier_type!(
    RunId,
    "A bounded identity for one engine run.  It is correlation metadata, not a secret."
);
identifier_type!(
    UserId,
    "A bounded identity for one logical virtual user.  It is correlation metadata, not a label exporter."
);
identifier_type!(
    SampleId,
    "A bounded identity for one sample or diagnostic operation."
);
identifier_type!(PlanId, "A bounded identity for one plan or plan revision.");
identifier_type!(
    PlanHash,
    "A bounded content identity for one plan revision."
);
identifier_type!(ProfileId, "A bounded compatibility profile identity.");
identifier_type!(
    ThreadGroupId,
    "A bounded identity for one thread group in a run."
);
identifier_type!(
    ControllerPath,
    "A bounded ordered path identifying a controller or plan location."
);
identifier_type!(PluginId, "A bounded identity for one plugin capability.");
identifier_type!(
    ConnectionId,
    "A bounded identity for one transport connection."
);

/// A span identity allocated by the caller or a deterministic sink.
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SpanId(u64);

impl SpanId {
    /// Creates a span identity from its raw value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the raw span identity.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for SpanId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("SpanId").field(&REDACTED).finish()
    }
}

impl fmt::Display for SpanId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Correlation values propagated from a run into users, samples, events, and
/// child spans.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorrelationContext {
    policy: RedactionPolicy,
    run_id: Option<RunId>,
    plan_id: Option<PlanId>,
    plan_hash: Option<PlanHash>,
    profile_id: Option<ProfileId>,
    thread_group_id: Option<ThreadGroupId>,
    user_id: Option<UserId>,
    sample_id: Option<SampleId>,
    parent_sample_id: Option<SampleId>,
    controller_path: Option<ControllerPath>,
    plugin_id: Option<PluginId>,
    connection_id: Option<ConnectionId>,
    iteration: Option<u64>,
}

impl CorrelationContext {
    /// Creates an empty correlation context.
    #[must_use]
    pub fn new() -> Self {
        Self {
            policy: RedactionPolicy::new(),
            run_id: None,
            plan_id: None,
            plan_hash: None,
            profile_id: None,
            thread_group_id: None,
            user_id: None,
            sample_id: None,
            parent_sample_id: None,
            controller_path: None,
            plugin_id: None,
            connection_id: None,
            iteration: None,
        }
    }

    /// Creates an empty context retaining the caller's redaction policy.
    #[must_use]
    pub fn with_policy(policy: RedactionPolicy) -> Self {
        Self {
            policy,
            ..Self::new()
        }
    }

    /// Returns the retained policy without exposing configured secret values.
    #[must_use]
    pub fn redaction_policy(&self) -> &RedactionPolicy {
        &self.policy
    }

    /// Attaches a run identity.
    #[must_use]
    pub fn with_run_id(mut self, value: impl Into<RunId>) -> Self {
        let value = value.into();
        let redacted = redact_identifier_text(&self.policy, value.as_str(), value.was_bounded());
        self.run_id = Some(RunId::new(redacted));
        self
    }

    /// Attaches a plan identity.
    #[must_use]
    pub fn with_plan_id(mut self, value: impl Into<PlanId>) -> Self {
        let value = value.into();
        let redacted = redact_identifier_text(&self.policy, value.as_str(), value.was_bounded());
        self.plan_id = Some(PlanId::new(redacted));
        self
    }

    /// Attaches a content hash for the plan revision.
    #[must_use]
    pub fn with_plan_hash(mut self, value: impl Into<PlanHash>) -> Self {
        let value = value.into();
        let redacted = redact_identifier_text(&self.policy, value.as_str(), value.was_bounded());
        self.plan_hash = Some(PlanHash::new(redacted));
        self
    }

    /// Attaches the active compatibility profile identity.
    #[must_use]
    pub fn with_profile_id(mut self, value: impl Into<ProfileId>) -> Self {
        let value = value.into();
        let redacted = redact_identifier_text(&self.policy, value.as_str(), value.was_bounded());
        self.profile_id = Some(ProfileId::new(redacted));
        self
    }

    /// Attaches a thread-group identity.
    #[must_use]
    pub fn with_thread_group_id(mut self, value: impl Into<ThreadGroupId>) -> Self {
        let value = value.into();
        let redacted = redact_identifier_text(&self.policy, value.as_str(), value.was_bounded());
        self.thread_group_id = Some(ThreadGroupId::new(redacted));
        self
    }

    /// Attaches a virtual-user identity.
    #[must_use]
    pub fn with_user_id(mut self, value: impl Into<UserId>) -> Self {
        let value = value.into();
        let redacted = redact_identifier_text(&self.policy, value.as_str(), value.was_bounded());
        self.user_id = Some(UserId::new(redacted));
        self
    }

    /// Attaches a sample identity.
    #[must_use]
    pub fn with_sample_id(mut self, value: impl Into<SampleId>) -> Self {
        let value = value.into();
        let redacted = redact_identifier_text(&self.policy, value.as_str(), value.was_bounded());
        self.sample_id = Some(SampleId::new(redacted));
        self
    }

    /// Attaches the parent sample identity.
    #[must_use]
    pub fn with_parent_sample_id(mut self, value: impl Into<SampleId>) -> Self {
        let value = value.into();
        let redacted = redact_identifier_text(&self.policy, value.as_str(), value.was_bounded());
        self.parent_sample_id = Some(SampleId::new(redacted));
        self
    }

    /// Attaches an ordered controller path.
    #[must_use]
    pub fn with_controller_path(mut self, value: impl Into<ControllerPath>) -> Self {
        let value = value.into();
        let redacted = redact_identifier_text(&self.policy, value.as_str(), value.was_bounded());
        self.controller_path = Some(ControllerPath::new(redacted));
        self
    }

    /// Attaches a plugin capability identity.
    #[must_use]
    pub fn with_plugin_id(mut self, value: impl Into<PluginId>) -> Self {
        let value = value.into();
        let redacted = redact_identifier_text(&self.policy, value.as_str(), value.was_bounded());
        self.plugin_id = Some(PluginId::new(redacted));
        self
    }

    /// Attaches a transport connection identity.
    #[must_use]
    pub fn with_connection_id(mut self, value: impl Into<ConnectionId>) -> Self {
        let value = value.into();
        let redacted = redact_identifier_text(&self.policy, value.as_str(), value.was_bounded());
        self.connection_id = Some(ConnectionId::new(redacted));
        self
    }

    /// Attaches the logical iteration number.
    #[must_use]
    pub const fn with_iteration(mut self, value: u64) -> Self {
        self.iteration = Some(value);
        self
    }

    /// Returns the run identity, when present.
    #[must_use]
    pub fn run_id(&self) -> Option<&RunId> {
        self.run_id.as_ref()
    }

    /// Returns the plan identity, when present.
    #[must_use]
    pub fn plan_id(&self) -> Option<&PlanId> {
        self.plan_id.as_ref()
    }

    /// Returns the plan content hash, when present.
    #[must_use]
    pub fn plan_hash(&self) -> Option<&PlanHash> {
        self.plan_hash.as_ref()
    }

    /// Returns the compatibility profile identity, when present.
    #[must_use]
    pub fn profile_id(&self) -> Option<&ProfileId> {
        self.profile_id.as_ref()
    }

    /// Returns the thread-group identity, when present.
    #[must_use]
    pub fn thread_group_id(&self) -> Option<&ThreadGroupId> {
        self.thread_group_id.as_ref()
    }

    /// Returns the virtual-user identity, when present.
    #[must_use]
    pub fn user_id(&self) -> Option<&UserId> {
        self.user_id.as_ref()
    }

    /// Returns the sample identity, when present.
    #[must_use]
    pub fn sample_id(&self) -> Option<&SampleId> {
        self.sample_id.as_ref()
    }

    /// Returns the parent sample identity, when present.
    #[must_use]
    pub fn parent_sample_id(&self) -> Option<&SampleId> {
        self.parent_sample_id.as_ref()
    }

    /// Returns the controller path, when present.
    #[must_use]
    pub fn controller_path(&self) -> Option<&ControllerPath> {
        self.controller_path.as_ref()
    }

    /// Returns the plugin identity, when present.
    #[must_use]
    pub fn plugin_id(&self) -> Option<&PluginId> {
        self.plugin_id.as_ref()
    }

    /// Returns the transport connection identity, when present.
    #[must_use]
    pub fn connection_id(&self) -> Option<&ConnectionId> {
        self.connection_id.as_ref()
    }

    /// Returns the logical iteration number, when present.
    #[must_use]
    pub const fn iteration(&self) -> Option<u64> {
        self.iteration
    }

    /// Creates a child context that inherits all current correlation values.
    #[must_use]
    pub fn child(&self) -> Self {
        self.clone()
    }

    /// Returns a child context re-sanitized with a caller-supplied policy.
    #[must_use]
    pub fn child_with_policy(&self, policy: RedactionPolicy) -> Self {
        self.redact(&policy)
    }

    fn redact(&self, policy: &RedactionPolicy) -> Self {
        Self {
            policy: policy.clone(),
            run_id: self.run_id.as_ref().map(|value| {
                RunId::new(redact_identifier_text(
                    policy,
                    value.as_str(),
                    value.was_bounded(),
                ))
            }),
            plan_id: self.plan_id.as_ref().map(|value| {
                PlanId::new(redact_identifier_text(
                    policy,
                    value.as_str(),
                    value.was_bounded(),
                ))
            }),
            plan_hash: self.plan_hash.as_ref().map(|value| {
                PlanHash::new(redact_identifier_text(
                    policy,
                    value.as_str(),
                    value.was_bounded(),
                ))
            }),
            profile_id: self.profile_id.as_ref().map(|value| {
                ProfileId::new(redact_identifier_text(
                    policy,
                    value.as_str(),
                    value.was_bounded(),
                ))
            }),
            thread_group_id: self.thread_group_id.as_ref().map(|value| {
                ThreadGroupId::new(redact_identifier_text(
                    policy,
                    value.as_str(),
                    value.was_bounded(),
                ))
            }),
            user_id: self.user_id.as_ref().map(|value| {
                UserId::new(redact_identifier_text(
                    policy,
                    value.as_str(),
                    value.was_bounded(),
                ))
            }),
            sample_id: self.sample_id.as_ref().map(|value| {
                SampleId::new(redact_identifier_text(
                    policy,
                    value.as_str(),
                    value.was_bounded(),
                ))
            }),
            parent_sample_id: self.parent_sample_id.as_ref().map(|value| {
                SampleId::new(redact_identifier_text(
                    policy,
                    value.as_str(),
                    value.was_bounded(),
                ))
            }),
            controller_path: self.controller_path.as_ref().map(|value| {
                ControllerPath::new(redact_identifier_text(
                    policy,
                    value.as_str(),
                    value.was_bounded(),
                ))
            }),
            plugin_id: self.plugin_id.as_ref().map(|value| {
                PluginId::new(redact_identifier_text(
                    policy,
                    value.as_str(),
                    value.was_bounded(),
                ))
            }),
            connection_id: self.connection_id.as_ref().map(|value| {
                ConnectionId::new(redact_identifier_text(
                    policy,
                    value.as_str(),
                    value.was_bounded(),
                ))
            }),
            iteration: self.iteration,
        }
    }
}

impl Default for CorrelationContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Alias emphasizing that a context is a set of correlation IDs.
pub type CorrelationIds = CorrelationContext;

/// Event and span severity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Severity {
    /// Extremely detailed diagnostic information.
    Trace,
    /// Developer-focused diagnostic information.
    Debug,
    /// Normal lifecycle information.
    Info,
    /// A recoverable anomaly.
    Warn,
    /// An operation failed or needs attention.
    Error,
    /// The run or diagnostic pipeline cannot continue.
    Fatal,
}

impl Severity {
    /// Returns the stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
            Self::Fatal => "fatal",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Whether a failed operation may be retried by its owning boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Retryability {
    /// The operation's retry policy is not known at this diagnostic layer.
    Unknown,
    /// The same operation may be attempted again.
    Retryable,
    /// Retrying the operation is not allowed or cannot make progress.
    Terminal,
}

impl Retryability {
    /// Returns the stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Retryable => "retryable",
            Self::Terminal => "terminal",
        }
    }
}

impl fmt::Display for Retryability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Stable diagnostic categories used by library boundaries.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DiagnosticCategory {
    /// Configuration or operator input.
    Config,
    /// Malformed plan syntax.
    PlanSyntax,
    /// Invalid plan semantics.
    PlanSemantics,
    /// A recognized operation is not supported by this capability set.
    Unsupported,
    /// Scheduling, deadline, or cancellation behavior.
    Schedule,
    /// Transport, protocol, TLS, or proxy behavior.
    Transport,
    /// Sampler-specific behavior.
    Sampler,
    /// Assertion behavior.
    Assertion,
    /// Script or expression execution.
    Script,
    /// Plugin or JVM bridge behavior.
    Plugin,
    /// Result persistence or diagnostic sink behavior.
    Persistence,
    /// Security-policy or redaction behavior.
    Security,
    /// Internal invariant failure.
    Internal,
    /// Observability pipeline behavior.
    Observation,
    /// A bounded extension category.
    Custom(CustomCategory),
}

/// A caller-defined category retained within the category-name bound.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CustomCategory(BoundedText);

impl CustomCategory {
    /// Creates a bounded custom category name.
    #[must_use]
    pub fn new(value: impl AsRef<str>) -> Self {
        Self(BoundedText::new(default_name(value), DEFAULT_MAX_KEY_BYTES))
    }

    /// Creates a category name through an explicit redaction policy.
    #[must_use]
    pub fn new_with_policy(policy: &RedactionPolicy, value: impl AsRef<str>) -> Self {
        Self(BoundedText::new(
            redact_metadata(policy, value.as_ref(), DEFAULT_MAX_KEY_BYTES),
            DEFAULT_MAX_KEY_BYTES,
        ))
    }

    /// Returns the bounded custom category spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for CustomCategory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

impl DiagnosticCategory {
    /// Creates a category from a case-insensitive stable spelling.
    #[must_use]
    pub fn new(value: impl AsRef<str>) -> Self {
        let value = value.as_ref();
        if value.eq_ignore_ascii_case("config") || value.eq_ignore_ascii_case("configuration") {
            Self::Config
        } else if value.eq_ignore_ascii_case("plan-syntax")
            || value.eq_ignore_ascii_case("plansyntax")
        {
            Self::PlanSyntax
        } else if value.eq_ignore_ascii_case("plan-semantics")
            || value.eq_ignore_ascii_case("plansemantics")
        {
            Self::PlanSemantics
        } else if value.eq_ignore_ascii_case("unsupported")
            || value.eq_ignore_ascii_case("unsupported-capability")
        {
            Self::Unsupported
        } else if value.eq_ignore_ascii_case("schedule") {
            Self::Schedule
        } else if value.eq_ignore_ascii_case("transport") {
            Self::Transport
        } else if value.eq_ignore_ascii_case("sampler") {
            Self::Sampler
        } else if value.eq_ignore_ascii_case("assertion") {
            Self::Assertion
        } else if value.eq_ignore_ascii_case("script") {
            Self::Script
        } else if value.eq_ignore_ascii_case("plugin")
            || value.eq_ignore_ascii_case("plugin-bridge")
        {
            Self::Plugin
        } else if value.eq_ignore_ascii_case("persistence") {
            Self::Persistence
        } else if value.eq_ignore_ascii_case("security") {
            Self::Security
        } else if value.eq_ignore_ascii_case("internal") {
            Self::Internal
        } else if value.eq_ignore_ascii_case("observation")
            || value.eq_ignore_ascii_case("observability")
        {
            Self::Observation
        } else {
            Self::Custom(CustomCategory::new(value))
        }
    }

    /// Creates a category while applying an explicit redaction policy to
    /// caller-defined category names.
    #[must_use]
    pub fn new_with_policy(policy: &RedactionPolicy, value: impl AsRef<str>) -> Self {
        let value = value.as_ref();
        if value.eq_ignore_ascii_case("config") || value.eq_ignore_ascii_case("configuration") {
            Self::Config
        } else if value.eq_ignore_ascii_case("plan-syntax")
            || value.eq_ignore_ascii_case("plansyntax")
        {
            Self::PlanSyntax
        } else if value.eq_ignore_ascii_case("plan-semantics")
            || value.eq_ignore_ascii_case("plansemantics")
        {
            Self::PlanSemantics
        } else if value.eq_ignore_ascii_case("unsupported")
            || value.eq_ignore_ascii_case("unsupported-capability")
        {
            Self::Unsupported
        } else if value.eq_ignore_ascii_case("schedule") {
            Self::Schedule
        } else if value.eq_ignore_ascii_case("transport") {
            Self::Transport
        } else if value.eq_ignore_ascii_case("sampler") {
            Self::Sampler
        } else if value.eq_ignore_ascii_case("assertion") {
            Self::Assertion
        } else if value.eq_ignore_ascii_case("script") {
            Self::Script
        } else if value.eq_ignore_ascii_case("plugin")
            || value.eq_ignore_ascii_case("plugin-bridge")
        {
            Self::Plugin
        } else if value.eq_ignore_ascii_case("persistence") {
            Self::Persistence
        } else if value.eq_ignore_ascii_case("security") {
            Self::Security
        } else if value.eq_ignore_ascii_case("internal") {
            Self::Internal
        } else if value.eq_ignore_ascii_case("observation")
            || value.eq_ignore_ascii_case("observability")
        {
            Self::Observation
        } else {
            Self::Custom(CustomCategory::new_with_policy(policy, value))
        }
    }

    /// Returns the stable lowercase category spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Config => "config",
            Self::PlanSyntax => "plan_syntax",
            Self::PlanSemantics => "plan_semantics",
            Self::Unsupported => "unsupported",
            Self::Schedule => "schedule",
            Self::Transport => "transport",
            Self::Sampler => "sampler",
            Self::Assertion => "assertion",
            Self::Script => "script",
            Self::Plugin => "plugin",
            Self::Persistence => "persistence",
            Self::Security => "security",
            Self::Internal => "internal",
            Self::Observation => "observation",
            Self::Custom(value) => value.as_str(),
        }
    }
}

impl From<&str> for DiagnosticCategory {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for DiagnosticCategory {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl fmt::Display for DiagnosticCategory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Custom(_) => formatter.write_str(REDACTED),
            builtin => formatter.write_str(builtin.as_str()),
        }
    }
}

/// A bounded stable machine-readable error code.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StableErrorCode(BoundedText);

impl StableErrorCode {
    /// Creates a bounded code, truncating only at a UTF-8 boundary.
    #[must_use]
    pub fn new(value: impl AsRef<str>) -> Self {
        Self(BoundedText::new(default_name(value), DEFAULT_MAX_KEY_BYTES))
    }

    /// Creates a code while applying an explicit redaction policy.
    #[must_use]
    pub fn new_with_policy(policy: &RedactionPolicy, value: impl AsRef<str>) -> Self {
        Self(BoundedText::new(
            redact_metadata(policy, value.as_ref(), DEFAULT_MAX_KEY_BYTES),
            DEFAULT_MAX_KEY_BYTES,
        ))
    }

    /// Returns the code spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl From<&str> for StableErrorCode {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for StableErrorCode {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl fmt::Display for StableErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

/// Alias for callers that prefer the shorter error-code name.
pub type ErrorCode = StableErrorCode;

/// Bounds applied before diagnostic data is retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RedactionLimits {
    /// Maximum number of fields in one event or span.
    pub max_fields: usize,
    /// Maximum key length in bytes.
    pub max_key_bytes: usize,
    /// Maximum value length in bytes.
    pub max_value_bytes: usize,
}

impl RedactionLimits {
    /// Creates explicit field bounds. Zero is valid and rejects all fields.
    #[must_use]
    pub const fn new(max_fields: usize, max_key_bytes: usize, max_value_bytes: usize) -> Self {
        Self {
            max_fields: if max_fields > HARD_MAX_FIELDS {
                HARD_MAX_FIELDS
            } else {
                max_fields
            },
            max_key_bytes: if max_key_bytes > HARD_MAX_KEY_BYTES {
                HARD_MAX_KEY_BYTES
            } else {
                max_key_bytes
            },
            max_value_bytes: if max_value_bytes > HARD_MAX_VALUE_BYTES {
                HARD_MAX_VALUE_BYTES
            } else {
                max_value_bytes
            },
        }
    }
}

impl Default for RedactionLimits {
    fn default() -> Self {
        Self {
            max_fields: DEFAULT_MAX_FIELDS,
            max_key_bytes: DEFAULT_MAX_KEY_BYTES,
            max_value_bytes: DEFAULT_MAX_VALUE_BYTES,
        }
    }
}

/// Explicit limits for an in-memory diagnostic sink.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SinkLimits {
    /// Maximum number of records retained.
    pub max_records: usize,
    /// Maximum aggregate record bytes retained.
    pub max_bytes: usize,
}

impl SinkLimits {
    /// Creates explicit sink bounds. Zero is valid and models an always-full
    /// sink until it is closed.
    #[must_use]
    pub const fn new(max_records: usize, max_bytes: usize) -> Self {
        Self {
            max_records: if max_records > HARD_MAX_FIELDS.saturating_mul(1024) {
                HARD_MAX_FIELDS.saturating_mul(1024)
            } else {
                max_records
            },
            max_bytes: if max_bytes > HARD_MAX_VALUE_BYTES.saturating_mul(256) {
                HARD_MAX_VALUE_BYTES.saturating_mul(256)
            } else {
                max_bytes
            },
        }
    }
}

impl Default for SinkLimits {
    fn default() -> Self {
        Self {
            max_records: DEFAULT_MAX_RECORDS,
            max_bytes: DEFAULT_MAX_SINK_BYTES,
        }
    }
}

impl From<usize> for SinkLimits {
    fn from(max_records: usize) -> Self {
        Self::new(max_records, DEFAULT_MAX_SINK_BYTES)
    }
}

/// A secret value whose ordinary formatting never reveals the secret.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Secret {
    value: String,
    truncated: bool,
}

impl Secret {
    /// Creates a bounded secret. Empty values are retained as an inert secret;
    /// use [`Self::try_new`] when configuration errors should be reported.
    #[must_use]
    pub fn new(value: impl AsRef<str>) -> Self {
        let (value, truncated) = truncate_text(value.as_ref(), MAX_SECRET_BYTES);
        Self { value, truncated }
    }

    /// Creates a non-empty secret within the hard bound.
    pub fn try_new(value: impl AsRef<str>) -> Result<Self, InputError> {
        let value = value.as_ref();
        if value.is_empty() {
            return Err(InputError::Empty);
        }
        if value.len() > MAX_SECRET_BYTES {
            return Err(InputError::TooLong {
                actual: value.len(),
                maximum: MAX_SECRET_BYTES,
            });
        }
        Ok(Self {
            value: value.to_owned(),
            truncated: false,
        })
    }

    /// Returns the secret for the redaction implementation.
    ///
    /// This is intentionally crate-private.  A caller can configure a
    /// [`RedactionPolicy`] with a [`Secret`], but there is no public getter
    /// which can turn the secret back into loggable raw text.
    #[must_use]
    fn as_str(&self) -> &str {
        &self.value
    }

    /// Returns whether the secret is inert because it is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    /// Returns whether [`Self::new`] had to truncate the input.
    ///
    /// A truncated secret is not safe to use as an exact configured secret:
    /// retaining only a prefix would make the redaction policy claim to
    /// protect a value that it can no longer match completely.  Builder-style
    /// policy methods therefore ignore such a value; callers that need an
    /// explicit configuration error should use [`Self::try_new`] or
    /// [`RedactionPolicy::try_add_secret`].
    #[must_use]
    pub const fn was_truncated(&self) -> bool {
        self.truncated
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

/// Alias commonly used by configuration callers.
pub type SecretString = Secret;

/// Errors returned while adding a configured secret.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RedactionError {
    /// The configured secret is empty.
    EmptySecret,
    /// The configured secret exceeds the hard bound.
    SecretTooLong {
        /// Actual secret length in bytes.
        actual: usize,
        /// Maximum accepted length in bytes.
        maximum: usize,
    },
    /// The policy has reached its configured-secret bound.
    SecretLimitExceeded {
        /// Maximum number of configured secrets.
        maximum: usize,
    },
}

impl RedactionError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::EmptySecret => "observe.redaction.empty-secret",
            Self::SecretTooLong { .. } => "observe.redaction.secret-too-long",
            Self::SecretLimitExceeded { .. } => "observe.redaction.secret-limit",
        }
    }
}

impl fmt::Display for RedactionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySecret => formatter.write_str("observe.redaction.empty-secret"),
            Self::SecretTooLong { actual, maximum } => write!(
                formatter,
                "observe.redaction.secret-too-long ({actual} > {maximum} bytes)"
            ),
            Self::SecretLimitExceeded { maximum } => {
                write!(formatter, "observe.redaction.secret-limit ({maximum})")
            }
        }
    }
}

impl std::error::Error for RedactionError {}

/// A central policy for recognizing and redacting sensitive diagnostic data.
///
/// The policy matches field-name tokens, not arbitrary substrings, so a field
/// such as `notauthorization` does not become secret merely because it has a
/// sensitive spelling inside it. Password-like camel-case and separator forms
/// (for example `dbPassword` and `db_password`) are recognized. Configured
/// secrets are replaced literally anywhere in a value, including URLs.
///
/// [`REDACTED`] is a reserved output sentinel. Configuration accepts a secret
/// that overlaps the sentinel for compatibility; consumers that scan bytes
/// must compare complete marker tokens instead of asserting that a secret's
/// individual bytes never occur in output.
#[derive(Clone, Eq, PartialEq)]
pub struct RedactionPolicy {
    limits: RedactionLimits,
    secrets: Vec<Secret>,
}

impl fmt::Debug for RedactionPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedactionPolicy")
            .field("limits", &self.limits)
            .field("secret_count", &self.secrets.len())
            .finish()
    }
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl RedactionPolicy {
    /// Creates the default central policy with finite field limits.
    #[must_use]
    pub fn new() -> Self {
        Self {
            limits: RedactionLimits::default(),
            secrets: Vec::new(),
        }
    }

    /// Creates a policy with explicit field bounds.
    #[must_use]
    pub fn with_limits(limits: RedactionLimits) -> Self {
        Self {
            limits: RedactionLimits::new(
                limits.max_fields,
                limits.max_key_bytes,
                limits.max_value_bytes,
            ),
            secrets: Vec::new(),
        }
    }

    /// Returns the active field limits.
    #[must_use]
    pub const fn limits(&self) -> RedactionLimits {
        self.limits
    }

    /// Returns the number of configured secrets without exposing them.
    #[must_use]
    pub fn secret_count(&self) -> usize {
        self.secrets.len()
    }

    /// Returns a bounded estimate of the retained policy state.
    ///
    /// This is deliberately an accounting value, not a serialization size.
    /// It includes the policy's configured limits and secret bytes once so a
    /// bounded sink or registry can account for retained security state
    /// without cloning a complete policy into every field.
    #[must_use]
    pub fn retained_bytes(&self) -> usize {
        self.secrets
            .iter()
            .fold(3 * core::mem::size_of::<usize>(), |total, secret| {
                total.saturating_add(secret.as_str().len())
            })
    }

    /// Adds a bounded secret using a builder-style API. Duplicate and
    /// over-capacity values are ignored; use [`Self::try_add_secret`] when
    /// configuration errors must be surfaced. A secret overlapping the
    /// [`REDACTED`] sentinel is accepted for compatibility and retains the
    /// sentinel semantics documented on [`REDACTED`].
    #[must_use]
    pub fn with_secret(mut self, secret: impl Into<Secret>) -> Self {
        let secret = secret.into();
        if !secret.was_truncated()
            && self.secrets.len() < MAX_CONFIGURED_SECRETS
            && !secret.is_empty()
            && !self.secrets.iter().any(|item| item == &secret)
        {
            self.secrets.push(secret);
        }
        self
    }

    /// Adds an exact secret and reports invalid configuration rather than
    /// silently accepting it. A secret overlapping [`REDACTED`] is valid
    /// configuration; output markers are reserved sentinels, so byte-based
    /// consumers must match complete markers rather than use substring
    /// absence as their invariant.
    pub fn try_add_secret(&mut self, value: impl AsRef<str>) -> Result<(), RedactionError> {
        let value = value.as_ref();
        if value.is_empty() {
            return Err(RedactionError::EmptySecret);
        }
        if value.len() > MAX_SECRET_BYTES {
            return Err(RedactionError::SecretTooLong {
                actual: value.len(),
                maximum: MAX_SECRET_BYTES,
            });
        }
        if self.secrets.len() >= MAX_CONFIGURED_SECRETS {
            return Err(RedactionError::SecretLimitExceeded {
                maximum: MAX_CONFIGURED_SECRETS,
            });
        }
        let secret = Secret::new(value);
        if !self.secrets.iter().any(|item| item == &secret) {
            self.secrets.push(secret);
        }
        Ok(())
    }

    /// Returns whether a field name is sensitive under this policy.
    #[must_use]
    pub fn is_sensitive_key(&self, key: &str) -> bool {
        sensitive_key(key)
    }

    fn contains_configured_secret(&self, value: &str) -> bool {
        if value.len() > HARD_MAX_SCAN_BYTES {
            return !self.secrets.is_empty();
        }
        self.secrets
            .iter()
            .any(|secret| !secret.is_empty() && value.contains(secret.as_str()))
    }

    fn contains_percent_encoded_secret(&self, value: &str) -> bool {
        self.contains_percent_encoded_secret_with_limit(value, HARD_MAX_VALUE_BYTES)
    }

    fn contains_percent_encoded_secret_with_limit(
        &self,
        value: &str,
        decoded_limit: usize,
    ) -> bool {
        if self.secrets.is_empty()
            || !value.as_bytes().contains(&b'%')
            || self.contains_configured_secret(value)
        {
            return false;
        }
        // Include one maximum-sized configured secret beyond the normal
        // decoded scan bound.  This catches a secret which begins just before
        // the retained bound and otherwise would be lost when percent
        // decoding stops at that boundary.
        let scan_limit = decoded_limit.saturating_add(MAX_SECRET_BYTES);
        let mut decoded = percent_decode(value, scan_limit);
        let mut decode_steps = 0;
        loop {
            if self.contains_configured_secret(&decoded) {
                return true;
            }
            if !decoded.as_bytes().contains(&b'%') {
                return false;
            }
            if decode_steps >= MAX_REDACTION_DEPTH {
                // A value which still has encoded structure after the shared
                // recursion budget cannot be proven secret-free. Fail closed
                // instead of retaining an opaque deeply encoded payload.
                return true;
            }
            let next = percent_decode(&decoded, scan_limit);
            if next == decoded {
                return false;
            }
            decoded = next;
            decode_steps = decode_steps.saturating_add(1);
        }
    }

    /// Redacts a field value and applies the value bound.
    #[must_use]
    pub fn redact(&self, key: &str, value: &str) -> String {
        self.redact_value_for_key(key, value).0
    }

    /// Redacts a value without a field name, still applying configured exact
    /// secrets and the value bound.
    #[must_use]
    pub fn redact_value(&self, value: &str) -> String {
        self.redact_value_for_key("", value).0
    }

    /// Creates one sanitized key/value field.
    #[must_use]
    pub fn field(&self, key: &str, value: &str) -> DiagnosticField {
        let (value, value_truncated) = self.redact_value_for_key(key, value);
        // Keys are diagnostic data too.  A caller-controlled label or header
        // name can contain a configured secret, and retaining the raw key
        // would bypass value-only redaction.  Sensitivity of the value is
        // still decided from the original key before this sanitized copy is
        // stored.
        let (redacted_key, key_redaction_truncated) = self.redact_key(key);
        let (key, key_truncated) = truncate_text(&redacted_key, self.limits.max_key_bytes);
        DiagnosticField {
            key,
            value,
            truncated: key_redaction_truncated || key_truncated || value_truncated,
        }
    }

    /// Alias for [`Self::field`] at call sites that name the operation
    /// explicitly.
    #[must_use]
    pub fn redact_field(&self, key: &str, value: &str) -> DiagnosticField {
        self.field(key, value)
    }

    fn redact_value_for_key(&self, key: &str, value: &str) -> (String, bool) {
        self.redact_value_for_key_with_maximum(key, value, self.limits.max_value_bytes)
    }

    fn redact_key(&self, key: &str) -> (String, bool) {
        let (bounded, oversized) = truncate_text(key, HARD_MAX_KEY_BYTES);
        if oversized || unsafe_key_structure(&bounded) {
            return (truncate_text(REDACTED, self.limits.max_key_bytes).0, true);
        }
        self.redact_value_for_key_with_maximum_and_encoded_limit(
            "",
            &bounded,
            self.limits.max_key_bytes,
            HARD_MAX_KEY_BYTES,
        )
    }

    fn redact_value_for_key_with_maximum(
        &self,
        key: &str,
        value: &str,
        maximum: usize,
    ) -> (String, bool) {
        self.redact_value_for_key_with_maximum_and_encoded_limit(
            key,
            value,
            maximum,
            HARD_MAX_VALUE_BYTES,
        )
    }

    fn redact_value_for_key_with_maximum_and_encoded_limit(
        &self,
        key: &str,
        value: &str,
        maximum: usize,
        encoded_limit: usize,
    ) -> (String, bool) {
        if maximum == 0 {
            return (String::new(), !value.is_empty());
        }
        if value.len() > HARD_MAX_SCAN_BYTES {
            // Do not inspect a prefix and then retain it.  A secret beyond
            // the scan budget must make the complete value fail closed.
            let (marker, _) = truncate_text(REDACTED, maximum);
            return (marker, true);
        }
        if sensitive_key(key) {
            return truncate_text(REDACTED, maximum);
        }
        if has_json_escape_layer(value, HARD_MAX_SCAN_BYTES) {
            match decode_text_layers(value, HARD_MAX_SCAN_BYTES) {
                Some(decoded)
                    if decoded.chars().any(char::is_control)
                        || self.contains_configured_secret(&decoded) =>
                {
                    // A URL or header branch may otherwise preserve JSON-style
                    // escape bytes as opaque text.  Inspect the decoded
                    // spelling before structural dispatch so escaped controls
                    // and configured secrets cannot bypass the branch-specific
                    // sanitizer.
                    return truncate_text(REDACTED, maximum);
                }
                None => {
                    // An invalid or too-deep mixed encoding cannot be
                    // classified within the bounded inspection budget.
                    return truncate_text(REDACTED, maximum);
                }
                Some(_) => {}
            }
        }

        if contains_control_with_limit(key, HARD_MAX_KEY_BYTES)
            || contains_percent_encoded_control(key, HARD_MAX_KEY_BYTES)
        {
            return truncate_text(REDACTED, maximum);
        }

        let header_like = header_key(key);
        // Header framing takes precedence over URI heuristics. A header value
        // may itself contain `?` or `#`, but it must still be parsed as a
        // header block rather than being routed through URL handling.
        let url_like = !header_like
            && (url_key(key) || looks_like_url(value) || looks_like_relative_uri(value));
        if url_like
            && (contains_control(value)
                || contains_percent_encoded_control(value, HARD_MAX_SCAN_BYTES))
        {
            return truncate_text(REDACTED, maximum);
        }
        if header_like && contains_percent_encoded_control(value, HARD_MAX_SCAN_BYTES) {
            return truncate_text(REDACTED, maximum);
        }
        if !url_like && !header_like && contains_control(value) {
            return truncate_text(REDACTED, maximum);
        }
        if !url_like && self.contains_percent_encoded_secret_with_limit(value, encoded_limit) {
            return truncate_text(REDACTED, maximum);
        }
        // Structural parsing must see the original spelling.  Replacing a
        // literal secret first can erase delimiters (`?`, `&`, `:`) and leave
        // a nested encoded secret outside the parser's view.  Every branch
        // performs literal replacement after structural redaction below.
        // Give structural parsing the full bounded scan budget.  Applying the
        // output bound before literal replacement could retain a safe-looking
        // prefix while the configured secret begins just beyond that prefix.
        let structural_maximum = HARD_MAX_SCAN_BYTES.max(maximum);
        let (mut structured, mut structured_truncated) = if url_like {
            redact_url_structure(value, self, structural_maximum)
        } else if header_like {
            redact_header_text(value, self, structural_maximum)
        } else {
            redact_generic_text(value, self, structural_maximum, 0)
        };

        // Run literal replacement after structural redaction as well. This
        // makes the no-secret invariant hold even when a configured secret is
        // in a URL userinfo/query component or a header value.
        let (replaced, replacement_truncated) =
            replace_configured_secrets(&structured, &self.secrets, maximum, true);
        structured = replaced;
        structured_truncated |= replacement_truncated;
        // A structural pass may have consumed the bound before a configured
        // replacement. A final bounded copy keeps the invariant explicit.
        let (structured, final_truncated) = truncate_text(&structured, maximum);
        structured_truncated |= final_truncated;
        (structured, structured_truncated)
    }
}

const SENSITIVE_EXACT_KEYS: &[&str] = &[
    "authorization",
    "auth",
    "authtoken",
    "proxyauthorization",
    "proxyauth",
    "proxyuser",
    "proxyusername",
    "proxypass",
    "proxypassword",
    "proxycredential",
    "proxycredentials",
    "cookie",
    "cookies",
    "setcookie",
    "cookie2",
    "apikey",
    "xapikey",
    "xauthtoken",
    "xapitoken",
    "api_token",
    "apitoken",
    "token",
    "accesstoken",
    "refreshtoken",
    "idtoken",
    "bearertoken",
    "session",
    "sessionid",
    "jwt",
    "signature",
    "sig",
    "nonce",
    "accesskey",
    "oauth_token",
    "oauthtoken",
    "clientsecret",
    "clientcredential",
    "clientcredentials",
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "secret",
    "credential",
    "credentials",
    "privatekey",
    "signingkey",
    "requestbody",
    "responsebody",
    "rawbody",
    "body",
    "payload",
    "requestpayload",
    "responsepayload",
    "requestdata",
    "responsedata",
];

fn unsafe_key_structure(value: &str) -> bool {
    if value
        .chars()
        .any(|character| !character.is_ascii() || character.is_control())
    {
        return true;
    }
    if !value.as_bytes().contains(&b'%') {
        return false;
    }
    if has_invalid_percent_escape(value) {
        return true;
    }
    percent_decode(value, HARD_MAX_KEY_BYTES)
        .chars()
        .any(|character| !character.is_ascii() || character.is_control())
}

fn has_invalid_percent_escape(value: &str) -> bool {
    let bytes = value.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'%'
            && (index + 2 >= bytes.len()
                || hex_value(bytes[index + 1]).is_none()
                || hex_value(bytes[index + 2]).is_none())
        {
            return true;
        }
    }
    false
}

fn canonical_key(value: &str) -> String {
    let bounded = truncate_text(value, HARD_MAX_KEY_BYTES).0;
    let mut canonical = String::with_capacity(bounded.len().min(DEFAULT_MAX_KEY_BYTES));
    for character in bounded.chars() {
        if character.is_ascii_alphanumeric() {
            canonical.push(character.to_ascii_lowercase());
        }
    }
    canonical
}

fn key_tokens(value: &str) -> Vec<String> {
    let bounded = truncate_text(value, HARD_MAX_KEY_BYTES).0;
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut previous_upper = false;
    let mut previous_lower = false;
    let mut previous_digit = false;
    for (index, character) in bounded.char_indices() {
        let separator = !character.is_ascii_alphanumeric();
        let upper = character.is_ascii_uppercase();
        let lower = character.is_ascii_lowercase();
        let digit = character.is_ascii_digit();
        let next = bounded[index + character.len_utf8()..].chars().next();
        let acronym_boundary =
            upper && previous_upper && next.is_some_and(|next| next.is_ascii_lowercase());
        if separator {
            if !token.is_empty() {
                tokens.push(core::mem::take(&mut token));
            }
        } else if upper
            && !token.is_empty()
            && (previous_lower || previous_digit || acronym_boundary)
        {
            tokens.push(core::mem::take(&mut token));
            token.push(character.to_ascii_lowercase());
        } else {
            token.push(character.to_ascii_lowercase());
        }
        previous_upper = upper;
        previous_lower = lower;
        previous_digit = digit;
    }
    if !token.is_empty() {
        tokens.push(token);
    }
    tokens
}

fn sensitive_key(key: &str) -> bool {
    // Header/query/property names are wire-facing security selectors.  A
    // non-ASCII or control character can be used to make a visually similar
    // sensitive name evade a downstream parser, so fail closed rather than
    // guessing that such a key is harmless.
    let (bounded, oversized) = {
        let (bounded, truncated) = truncate_text(key, HARD_MAX_KEY_BYTES);
        (bounded, truncated)
    };
    if oversized || unsafe_key_structure(&bounded) {
        return true;
    }
    if sensitive_key_spelling(&bounded) {
        return true;
    }
    if bounded.as_bytes().contains(&b'%') || bounded.as_bytes().contains(&b'\\') {
        let mut decoded = bounded.clone();
        for depth in 0..=MAX_REDACTION_DEPTH {
            if decoded
                .chars()
                .any(|character| !character.is_ascii() || character.is_control())
                || sensitive_key_spelling(&decoded)
            {
                return true;
            }

            // Apply both decoders in each bounded step.  This catches mixed
            // spellings such as `%5Cu0074oken`, where percent decoding first
            // exposes a JSON escape which must then be classified as `token`.
            let mut next = decoded.clone();
            let mut changed = false;
            if next.as_bytes().contains(&b'%') {
                let percent_decoded = percent_decode(&next, HARD_MAX_KEY_BYTES);
                if percent_decoded != next {
                    next = percent_decoded;
                    changed = true;
                }
            }
            if next.as_bytes().contains(&b'\\') {
                match decode_json_escaped_text(&next) {
                    Some(json_decoded) if json_decoded != next => {
                        next = json_decoded;
                        changed = true;
                    }
                    Some(_) => {}
                    None => {
                        // Invalid JSON-style escapes cannot be classified as
                        // harmless without risking an escaped sensitive name.
                        return true;
                    }
                }
            }
            if !changed {
                if next.as_bytes().contains(&b'%') || next.as_bytes().contains(&b'\\') {
                    return true;
                }
                return false;
            }
            if next
                .chars()
                .any(|character| !character.is_ascii() || character.is_control())
                || sensitive_key_spelling(&next)
            {
                return true;
            }
            if depth == MAX_REDACTION_DEPTH {
                // Deeply encoded names cannot be classified safely within
                // the bounded decode budget. Treat them as sensitive rather
                // than allowing a repeated-escape spelling to bypass field
                // name redaction.
                return next.as_bytes().contains(&b'%') || next.as_bytes().contains(&b'\\');
            }
            decoded = next;
        }
        return true;
    }
    false
}

fn sensitive_key_spelling(key: &str) -> bool {
    let canonical = canonical_key(key);
    if SENSITIVE_EXACT_KEYS.contains(&canonical.as_str()) {
        return true;
    }
    let tokens = key_tokens(key);
    if tokens.iter().any(|token| sensitive_token(token)) {
        return true;
    }
    if tokens.windows(2).any(|pair| {
        matches!(
            pair,
            [first, second]
                if matches!(
                    (first.as_str(), second.as_str()),
                    ("api", "key")
                        | ("encryption", "key")
                        | ("private", "key")
                        | ("signing", "key")
                        | ("secret", "key")
                )
        )
    }) {
        return true;
    }
    // A compact camel-case spelling such as `dbPassword` is tokenized above;
    // this suffix check covers common all-lower-case forms without treating a
    // random substring such as `notpasswordish` as a secret field.
    [
        "password",
        "passwd",
        "passphrase",
        "credential",
        "credentials",
        "token",
        "accesstoken",
        "refreshtoken",
        "idtoken",
        "bearertoken",
        "oauthtoken",
        "apikey",
        "session",
        "sessionid",
        "jwt",
        "signature",
        "sig",
        "nonce",
        "accesskey",
        "body",
    ]
    .iter()
    .any(|suffix| {
        let numeric_suffix = canonical.strip_prefix(suffix).is_some_and(|rest| {
            !rest.is_empty() && rest.chars().all(|character| character.is_ascii_digit())
        });
        let compact_suffix = matches!(
            *suffix,
            "password" | "passwd" | "passphrase" | "credential" | "credentials"
        ) && canonical.ends_with(suffix)
            && canonical.len() > suffix.len();
        numeric_suffix || compact_suffix
    })
}

fn sensitive_token(token: &str) -> bool {
    const BASES: &[&str] = &[
        "authorization",
        "auth",
        "proxyauthorization",
        "proxyauth",
        "cookie",
        "cookies",
        "apikey",
        "token",
        "password",
        "passwd",
        "pwd",
        "passphrase",
        "secret",
        "credential",
        "credentials",
        "accesstoken",
        "refreshtoken",
        "idtoken",
        "bearertoken",
        "oauthtoken",
        "session",
        "sessionid",
        "jwt",
        "signature",
        "sig",
        "nonce",
        "accesskey",
        "body",
    ];
    BASES.iter().any(|base| {
        token == *base
            || token.strip_prefix(base).is_some_and(|suffix| {
                !suffix.is_empty() && suffix.chars().all(|character| character.is_ascii_digit())
            })
    })
}

fn url_key(key: &str) -> bool {
    is_url_key_canonical(&canonical_key(key))
        || (key.as_bytes().contains(&b'%')
            && is_url_key_canonical(&canonical_key(&percent_decode(key, HARD_MAX_KEY_BYTES))))
}

fn header_key(key: &str) -> bool {
    is_header_key_canonical(&canonical_key(key))
        || (key.as_bytes().contains(&b'%')
            && is_header_key_canonical(&canonical_key(&percent_decode(key, HARD_MAX_KEY_BYTES))))
}

fn is_url_key_canonical(canonical: &str) -> bool {
    matches!(
        canonical,
        "url" | "uri" | "endpoint" | "requesturl" | "responseurl" | "targeturl" | "location"
    )
}

fn is_header_key_canonical(canonical: &str) -> bool {
    canonical == "header"
        || canonical == "headers"
        || canonical.ends_with("header")
        || canonical.ends_with("headers")
}

fn looks_like_url(value: &str) -> bool {
    if value.starts_with("//") {
        return true;
    }
    let Some(separator) = value.find("://") else {
        return false;
    };
    separator > 0
        && value[..separator].chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
        })
}

/// Returns whether a bounded value needs relative-URI component handling.
///
/// Relative URI references do not have a scheme or authority, so an alias
/// such as `url`/`uri` cannot be the only signal for structural redaction.
/// A raw query or fragment delimiter is sufficient to classify the value;
/// conservative over-redaction is safer than retaining a sensitive query from
/// a relative URI under a caller-defined field name. The caller also enforces
/// the hard scan bound before invoking URL processing.
fn looks_like_relative_uri(value: &str) -> bool {
    value.len() <= HARD_MAX_SCAN_BYTES
        && value
            .as_bytes()
            .iter()
            .any(|byte| matches!(*byte, b'?' | b'#'))
}

fn authority_bounds(value: &str) -> Option<(usize, usize)> {
    let start = if value.starts_with("//") {
        2
    } else {
        value.find("://")?.saturating_add(3)
    };
    let end = value[start..]
        .find(['/', '?', '#'])
        .map_or(value.len(), |offset| start + offset);
    Some((start, end))
}

fn query_bounds(value: &str) -> Option<(usize, usize)> {
    let start = value.find('?')?.saturating_add(1);
    let end = value[start..]
        .find('#')
        .map_or(value.len(), |offset| start + offset);
    Some((start, end))
}

fn fragment_bounds(value: &str) -> Option<(usize, usize)> {
    let start = value.find('#')?.saturating_add(1);
    Some((start, value.len()))
}

fn redact_url_structure(value: &str, policy: &RedactionPolicy, maximum: usize) -> (String, bool) {
    redact_url_structure_at_depth(value, policy, maximum, 0)
}

fn redact_url_structure_at_depth(
    value: &str,
    policy: &RedactionPolicy,
    maximum: usize,
    depth: usize,
) -> (String, bool) {
    if maximum == 0 {
        return (String::new(), !value.is_empty());
    }
    if depth > MAX_REDACTION_DEPTH || value.len() > HARD_MAX_SCAN_BYTES {
        let (marker, _) = truncate_text(REDACTED, maximum);
        return (marker, true);
    }
    let mut output = String::with_capacity(value.len().min(maximum));
    let mut truncated = false;
    let mut cursor = 0;
    if let Some((authority_start, authority_end)) = authority_bounds(value) {
        let authority = &value[authority_start..authority_end];
        let userinfo_end = authority.rfind('@');
        let encoded_userinfo = userinfo_end.is_none()
            && authority.as_bytes().contains(&b'%')
            && percent_decode(authority, HARD_MAX_VALUE_BYTES).contains('@');
        if encoded_userinfo {
            // An encoded `@` is still a URL userinfo delimiter after URL
            // decoding.  Mapping the decoded offset back to the raw spelling
            // is unnecessary and error-prone; fail closed for the whole
            // authority rather than retaining an encoded credential prefix.
            truncated |= !append_bounded(&mut output, &value[..authority_start], maximum);
            truncated |= !append_bounded(&mut output, REDACTED, maximum);
        } else if let Some(relative_end) = userinfo_end {
            let at = authority_start + relative_end;
            let host_has_encoded_secret = policy.contains_percent_encoded_secret_with_limit(
                &value[at + 1..authority_end],
                HARD_MAX_VALUE_BYTES,
            );
            truncated |= !append_bounded(&mut output, &value[..authority_start], maximum);
            truncated |= !append_bounded(&mut output, REDACTED, maximum);
            truncated |= !append_bounded(&mut output, "@", maximum);
            if host_has_encoded_secret {
                truncated |= !append_bounded(&mut output, REDACTED, maximum);
            } else {
                truncated |= !append_bounded(&mut output, &value[at + 1..authority_end], maximum);
            }
        } else {
            if policy.contains_percent_encoded_secret_with_limit(
                &value[authority_start..authority_end],
                HARD_MAX_VALUE_BYTES,
            ) {
                truncated |= !append_bounded(&mut output, &value[..authority_start], maximum);
                truncated |= !append_bounded(&mut output, REDACTED, maximum);
            } else {
                truncated |= !append_bounded(&mut output, &value[..authority_end], maximum);
            }
        }
        cursor = authority_end;
    }

    if output.len() >= maximum {
        return (output, truncated || cursor < value.len());
    }

    // Keep the authority and path shape, but do not retain an encoded
    // configured secret from a path component.  Query handling below can
    // redact only the affected value, while an opaque path is safest as one
    // bounded placeholder.
    let path_end = value[cursor..]
        .find(['?', '#'])
        .map_or(value.len(), |offset| cursor + offset);
    if path_end > cursor && policy.contains_percent_encoded_secret(&value[cursor..path_end]) {
        // Do not retain the first path segment as a supposedly safe prefix:
        // the encoded secret may be in that segment itself (for example,
        // `/p%C3%A4ss/rest`).  Preserve only the structural leading slash;
        // the complete path payload is otherwise replaced as one unit.
        let leading_slash = value[cursor..path_end].starts_with('/');
        if leading_slash {
            truncated |= !append_bounded(&mut output, "/", maximum);
        }
        truncated |= !append_bounded(&mut output, REDACTED, maximum);
        cursor = path_end;
    }

    if let Some((query_start, query_end)) = query_bounds(value)
        && query_start >= cursor
    {
        let query_marker = query_start.saturating_sub(1);
        truncated |= !append_bounded(&mut output, &value[cursor..query_marker], maximum);
        truncated |= !append_bounded(&mut output, "?", maximum);
        truncated |= redact_query_at_depth(
            &mut output,
            &value[query_start..query_end],
            policy,
            maximum,
            depth,
        );
        cursor = query_end;
    }

    if output.len() >= maximum {
        return (output, truncated || cursor < value.len());
    }

    // URL fragments are not sent to an HTTP origin, but they frequently carry
    // bearer-like state in browser and recorder diagnostics.  Treat a
    // fragment containing key/value pairs like a query component so a secret
    // is not moved from `?token=...` to `#token=...` to bypass redaction.
    if let Some((fragment_start, fragment_end)) = fragment_bounds(value)
        && fragment_start >= cursor
    {
        let fragment_marker = fragment_start.saturating_sub(1);
        truncated |= !append_bounded(&mut output, &value[cursor..fragment_marker], maximum);
        truncated |= !append_bounded(&mut output, "#", maximum);
        truncated |= redact_fragment_at_depth(
            &mut output,
            &value[fragment_start..fragment_end],
            policy,
            maximum,
            depth,
        );
        cursor = fragment_end;
    }
    truncated |= !append_bounded(&mut output, &value[cursor..], maximum);
    (output, truncated)
}

fn redact_fragment_at_depth(
    output: &mut String,
    fragment: &str,
    policy: &RedactionPolicy,
    maximum: usize,
    depth: usize,
) -> bool {
    if output.len() >= maximum {
        return !fragment.is_empty();
    }
    if depth > MAX_REDACTION_DEPTH {
        return !append_bounded(output, REDACTED, maximum);
    }
    let mut truncated = false;
    // Preserve an opaque fragment prefix while still handling the common
    // `#state?access_token=...` form as structured data.
    if let Some(query) = fragment.find('?') {
        if policy.contains_percent_encoded_secret(&fragment[..query]) {
            truncated |= !append_bounded(output, REDACTED, maximum);
        } else {
            truncated |= !append_bounded(output, &fragment[..query], maximum);
        }
        truncated |= !append_bounded(output, "?", maximum);
        truncated |= redact_query_at_depth(output, &fragment[query + 1..], policy, maximum, depth);
    } else if policy.contains_percent_encoded_secret(fragment) {
        truncated |= !append_bounded(output, REDACTED, maximum);
    } else {
        truncated |= redact_query_at_depth(output, fragment, policy, maximum, depth);
    }
    truncated
}

fn redact_query_at_depth(
    output: &mut String,
    query: &str,
    policy: &RedactionPolicy,
    maximum: usize,
    depth: usize,
) -> bool {
    if maximum == 0 {
        return !query.is_empty();
    }
    if depth > MAX_REDACTION_DEPTH || query.len() > HARD_MAX_SCAN_BYTES {
        return !append_bounded(output, REDACTED, maximum);
    }
    let mut truncated = false;
    let mut consumed = false;
    let mut segment_start = 0;
    while segment_start <= query.len() && output.len() < maximum {
        let segment_end = query[segment_start..]
            .find(['&', ';'])
            .map_or(query.len(), |offset| segment_start + offset);
        let segment = &query[segment_start..segment_end];
        if let Some(equal) = segment.find('=') {
            let key = &segment[..equal];
            let value = &segment[equal + 1..];
            let decoded_key = percent_decode(key, HARD_MAX_KEY_BYTES);
            let key_oversized = key.len() > HARD_MAX_KEY_BYTES;
            let key_has_secret = key_oversized
                || contains_control(&decoded_key)
                || unsafe_key_structure(key)
                || policy.contains_configured_secret(key)
                || policy.contains_percent_encoded_secret_with_limit(key, HARD_MAX_KEY_BYTES);
            if key_has_secret {
                truncated |= !append_bounded(output, REDACTED, maximum);
            } else {
                truncated |= !append_bounded(output, key, maximum);
            }
            truncated |= !append_bounded(output, "=", maximum);
            if key.len() > HARD_MAX_KEY_BYTES
                || contains_control(&decoded_key)
                || unsafe_key_structure(key)
                || policy.is_sensitive_key(&decoded_key)
                || policy.contains_configured_secret(value)
                || policy.contains_percent_encoded_secret(value)
            {
                truncated |= !append_bounded(output, REDACTED, maximum);
            } else {
                let remaining = maximum.saturating_sub(output.len());
                let (safe_value, value_truncated) =
                    redact_nested_value(value, policy, remaining, depth.saturating_add(1));
                truncated |= !append_bounded(output, &safe_value, maximum);
                truncated |= value_truncated;
            }
        } else {
            let decoded_segment = percent_decode(segment, HARD_MAX_KEY_BYTES);
            let sensitive_segment = segment.len() > HARD_MAX_KEY_BYTES
                || policy.is_sensitive_key(&decoded_segment)
                || query_segment_has_sensitive_key(&decoded_segment, policy)
                || policy.contains_configured_secret(segment)
                || policy.contains_percent_encoded_secret(segment);
            if sensitive_segment {
                truncated |= !append_bounded(output, REDACTED, maximum);
            } else {
                truncated |= !append_bounded(output, segment, maximum);
            }
        }
        if segment_end == query.len() {
            consumed = true;
            break;
        }
        let separator = &query[segment_end..segment_end + 1];
        truncated |= !append_bounded(output, separator, maximum);
        segment_start = segment_end + 1;
    }
    truncated || !consumed
}

fn query_segment_has_sensitive_key(segment: &str, policy: &RedactionPolicy) -> bool {
    segment
        .find(['=', ':'])
        .is_some_and(|separator| policy.is_sensitive_key(segment[..separator].trim()))
}

fn percent_decode(value: &str, maximum: usize) -> String {
    if maximum == 0 {
        return String::new();
    }

    // Decode into bytes first.  Decoding one `%XX` byte at a time through
    // `from_utf8_lossy` turns a multi-byte UTF-8 secret into replacement
    // characters and prevents configured-secret matching.  The byte vector is
    // capped before allocation and the final string is bounded again below.
    let mut decoded = Vec::with_capacity(value.len().min(maximum));
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() && decoded.len() < maximum {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let high = hex_value(bytes[index + 1]);
            let low = hex_value(bytes[index + 2]);
            if let (Some(high), Some(low)) = (high, low) {
                decoded.push(high << 4 | low);
                index += 3;
                continue;
            }
        }
        let character = value[index..].chars().next();
        let Some(character) = character else {
            break;
        };
        let mut buffer = [0_u8; 4];
        let text = character.encode_utf8(&mut buffer).as_bytes();
        let remaining = maximum - decoded.len();
        if text.len() > remaining {
            break;
        }
        decoded.extend_from_slice(text);
        index += character.len_utf8();
    }
    truncate_text(&String::from_utf8_lossy(&decoded), maximum).0
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn redact_header_text(value: &str, policy: &RedactionPolicy, maximum: usize) -> (String, bool) {
    redact_header_text_at_depth(value, policy, maximum, 0)
}

fn redact_header_text_at_depth(
    value: &str,
    policy: &RedactionPolicy,
    maximum: usize,
    depth: usize,
) -> (String, bool) {
    if maximum == 0 {
        return (String::new(), !value.is_empty());
    }
    if depth > MAX_REDACTION_DEPTH || value.len() > HARD_MAX_SCAN_BYTES {
        let (marker, _) = truncate_text(REDACTED, maximum);
        return (marker, true);
    }
    let mut output = String::with_capacity(value.len().min(maximum));
    let mut truncated = false;
    let mut line_start = 0;
    let mut sensitive_continuation = false;
    while line_start < value.len() && output.len() < maximum {
        let line_end = value[line_start..]
            .find('\n')
            .map_or(value.len(), |offset| line_start + offset);
        let raw_line = &value[line_start..line_end];
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        let body_start = line
            .char_indices()
            .find(|(_, character)| *character != ' ' && *character != '\t')
            .map_or(line.len(), |(index, _)| index);
        if line[body_start..].chars().any(char::is_control) {
            truncated |= !append_bounded(&mut output, REDACTED, maximum);
            sensitive_continuation = true;
            if line_end == value.len() {
                line_start = value.len();
                break;
            }
            truncated |= !append_bounded(&mut output, "\n", maximum);
            line_start = line_end + 1;
            continue;
        }
        if sensitive_continuation
            && line
                .chars()
                .next()
                .is_some_and(|character| character == ' ' || character == '\t')
        {
            // RFC-style folded continuation lines belong to the preceding
            // header even when their payload contains a colon.  Classifying
            // the continuation as a fresh header first would let
            // `\tname: secret` evade a sensitive preceding header.
            let prefix_len = line
                .char_indices()
                .find(|(_, character)| *character != ' ' && *character != '\t')
                .map_or(line.len(), |(index, _)| index);
            truncated |= !append_header_prefix(&mut output, &line[..prefix_len], maximum);
            truncated |= !append_bounded(&mut output, REDACTED, maximum);
        } else if let Some(colon) = line.find(':') {
            let raw_name = &line[body_start..colon];
            let name = raw_name.trim();
            let valid_name = raw_name == name && valid_header_name(name);
            let name_unsafe = name.len() > HARD_MAX_KEY_BYTES || unsafe_key_structure(name);
            let name_has_configured_secret = policy.contains_configured_secret(name)
                || policy.contains_percent_encoded_secret_with_limit(name, HARD_MAX_KEY_BYTES);
            let prefix_ok = append_header_prefix(&mut output, &line[..body_start], maximum);
            truncated |= !prefix_ok;
            if !valid_name || name_unsafe || name_has_configured_secret {
                // Do not retain an invalid header name either: a confusable
                // or malformed name can itself carry an unrecognized secret.
                truncated |= !append_bounded(&mut output, REDACTED, maximum);
                sensitive_continuation = true;
            } else if policy.is_sensitive_key(name) {
                truncated |= !append_bounded(&mut output, &line[body_start..colon + 1], maximum);
                truncated |= !append_bounded(&mut output, REDACTED, maximum);
                sensitive_continuation = true;
            } else {
                truncated |= !append_bounded(&mut output, &line[body_start..colon + 1], maximum);
                let header_value = &line[colon + 1..];
                // Header names such as `X-Redirect` and `X-Request-Target`
                // are not sensitive themselves, but their values can carry
                // a URL or relative query (`/?token=...`).  Parse that
                // nested structure before retaining the otherwise harmless
                // header value so query secrets cannot bypass the central
                // policy merely by moving into a non-sensitive header.
                let remaining = maximum.saturating_sub(output.len());
                let (safe_value, value_truncated) = redact_nested_header_value_at_depth(
                    header_value,
                    policy,
                    remaining,
                    depth.saturating_add(1),
                );
                truncated |= !append_bounded(&mut output, &safe_value, maximum);
                truncated |= value_truncated;
                sensitive_continuation = false;
            }
        } else if policy.is_sensitive_key(line.trim())
            || line
                .split_ascii_whitespace()
                .next()
                .is_some_and(|name| policy.is_sensitive_key(name))
        {
            // Malformed header lines are not allowed to become a redaction
            // escape hatch.  A token-only sensitive line is retained only as
            // a bounded marker and keeps subsequent folded lines sensitive.
            truncated |= !append_bounded(&mut output, REDACTED, maximum);
            sensitive_continuation = true;
        } else {
            // A line without a colon is not a valid header field.  Retaining
            // it would make strings such as `Authorization=...` an easy way
            // to bypass the field-name policy, so malformed lines fail closed.
            truncated |= !append_bounded(&mut output, REDACTED, maximum);
            sensitive_continuation = true;
        }
        if line_end == value.len() {
            // The final line was fully consumed.  Mark the input exhausted so
            // an exact-boundary copy is not reported as a truncation merely
            // because `line_start` still names the line's original offset.
            line_start = value.len();
            break;
        }
        truncated |= !append_bounded(&mut output, "\n", maximum);
        line_start = line_end + 1;
    }
    (output, truncated || line_start < value.len())
}

fn redact_nested_header_value_at_depth(
    value: &str,
    policy: &RedactionPolicy,
    maximum: usize,
    depth: usize,
) -> (String, bool) {
    if maximum == 0 {
        return (String::new(), !value.is_empty());
    }
    redact_nested_value(value, policy, maximum, depth)
}

/// Redacts nested values which are carried in otherwise generic prose or
/// JSON-like text.  This deliberately uses a small bounded scanner rather
/// than a permissive JSON parser: diagnostics are allowed to contain prose,
/// while the security rule still needs to recognize `token=...`, quoted JSON
/// members, and nested objects without allocating an unbounded syntax tree.
fn redact_nested_value(
    value: &str,
    policy: &RedactionPolicy,
    maximum: usize,
    depth: usize,
) -> (String, bool) {
    if maximum == 0 {
        return (String::new(), !value.is_empty());
    }
    if depth > MAX_REDACTION_DEPTH || value.len() > HARD_MAX_SCAN_BYTES {
        let (marker, _) = truncate_text(REDACTED, maximum);
        return (marker, true);
    }

    // A configured secret can be represented entirely through JSON escapes
    // (`"\\u0074oken"`) and therefore be absent from the raw byte spelling.
    // Decode one bounded copy before structural scanning so opaque nested JSON
    // cannot bypass literal-secret replacement.
    if value.as_bytes().contains(&b'\\')
        && let Some(decoded) = decode_json_escaped_text(value)
        && policy.contains_configured_secret(&decoded)
    {
        let (marker, _) = truncate_text(REDACTED, maximum);
        return (marker, true);
    }

    // A nested value does not need to look like a URL or assignment to carry
    // a percent-encoded configured secret.  Check the bounded decode chain
    // before structural classification so an opaque header payload cannot
    // preserve an encoded secret merely because it has no delimiter.
    if policy.contains_percent_encoded_secret_with_limit(value, HARD_MAX_VALUE_BYTES) {
        let (marker, _) = truncate_text(REDACTED, maximum);
        return (marker, true);
    }

    // Decode only for structural inspection.  If the decoded spelling is a
    // URL, query, or JSON-like object, retaining the original percent escapes
    // would leave nested keys opaque to the redaction pass.  Some adapters
    // encode an already-encoded value more than once, so repeat this bounded
    // inspection until a structure is found or the shared recursion budget is
    // exhausted.  Exhaustion fails closed instead of retaining an opaque
    // possibly-sensitive payload.
    let mut decoded = value.to_owned();
    let mut structural = false;
    let mut decode_steps = 0;
    while decoded.as_bytes().contains(&b'%') {
        if depth.saturating_add(decode_steps) >= MAX_REDACTION_DEPTH {
            let (marker, _) = truncate_text(REDACTED, maximum);
            return (marker, true);
        }
        let next = percent_decode(&decoded, HARD_MAX_SCAN_BYTES);
        if next == decoded {
            break;
        }
        decoded = next;
        decode_steps = decode_steps.saturating_add(1);
        if looks_like_nested_structure(&decoded) {
            structural = true;
            break;
        }
    }
    let source = if structural { decoded.as_str() } else { value };
    let url_structural =
        looks_like_url(source) || (looks_like_relative_uri(source) && !looks_like_jsonish(source));
    let (mut safe, mut truncated) = if url_structural {
        redact_url_structure_at_depth(source, policy, maximum, depth.saturating_add(1))
    } else {
        redact_generic_text(source, policy, maximum, depth.saturating_add(1))
    };

    if truncated {
        // The scanner did not consume the complete nested value.  Returning
        // its visible prefix could retain the beginning of a configured
        // secret which crosses the output bound, so fail closed for the whole
        // nested payload.
        let (marker, _) = truncate_text(REDACTED, maximum);
        return (marker, true);
    }

    // A generic pass is followed by a literal pass so configured secrets are
    // removed even when they occur in ordinary prose, a URL userinfo value,
    // or an encoded value which was decoded only for inspection.
    let (replaced, replacement_truncated) =
        replace_configured_secrets(&safe, &policy.secrets, maximum, true);
    safe = replaced;
    truncated |= replacement_truncated;
    let (safe, final_truncated) = truncate_text(&safe, maximum);
    truncated |= final_truncated;
    (safe, truncated)
}

/// Decode JSON string escapes for bounded secret and key checks.
fn decode_json_escaped_text(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut output = String::with_capacity(value.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'\\' {
            let character = value[index..].chars().next()?;
            output.push(character);
            index += character.len_utf8();
            continue;
        }
        index = index.saturating_add(1);
        let escape = *bytes.get(index)?;
        index = index.saturating_add(1);
        match escape {
            b'"' => output.push('"'),
            b'\\' => output.push('\\'),
            b'/' => output.push('/'),
            b'b' => output.push('\u{0008}'),
            b'f' => output.push('\u{000c}'),
            b'n' => output.push('\n'),
            b'r' => output.push('\r'),
            b't' => output.push('\t'),
            b'u' => {
                let high = parse_json_escape_code_unit(bytes, &mut index)?;
                if (0xD800..=0xDBFF).contains(&high) {
                    if bytes.get(index..index.saturating_add(2)) != Some(b"\\u") {
                        return None;
                    }
                    index = index.saturating_add(2);
                    let low = parse_json_escape_code_unit(bytes, &mut index)?;
                    if !(0xDC00..=0xDFFF).contains(&low) {
                        return None;
                    }
                    let code_point =
                        0x1_0000 + ((u32::from(high) - 0xD800) << 10) + (u32::from(low) - 0xDC00);
                    output.push(char::from_u32(code_point)?);
                } else if (0xDC00..=0xDFFF).contains(&high) {
                    return None;
                } else {
                    output.push(char::from_u32(u32::from(high))?);
                }
            }
            _ => return None,
        }
    }
    Some(output)
}

fn parse_json_escape_code_unit(bytes: &[u8], index: &mut usize) -> Option<u16> {
    let end = index.checked_add(4)?;
    let digits = bytes.get(*index..end)?;
    let mut value = 0_u16;
    for digit in digits {
        value = value
            .checked_mul(16)?
            .checked_add(u16::from(hex_value(*digit)?))?;
    }
    *index = end;
    Some(value)
}

fn has_json_escape_layer(value: &str, maximum: usize) -> bool {
    if value.as_bytes().contains(&b'\\') {
        return true;
    }
    if !value.as_bytes().contains(&b'%') {
        return false;
    }
    let mut decoded = value.to_owned();
    for _ in 0..=MAX_REDACTION_DEPTH {
        if !decoded.as_bytes().contains(&b'%') {
            return false;
        }
        let next = percent_decode(&decoded, maximum);
        if next == decoded {
            return false;
        }
        if next.as_bytes().contains(&b'\\') {
            return true;
        }
        decoded = next;
    }
    false
}

/// Decode bounded percent and JSON escape layers for hazard inspection.
///
/// The two encodings may be mixed (`%5Cu0074oken`), so applying either
/// decoder only once is insufficient.  This helper is for classification,
/// not output reconstruction; callers fail closed when the bounded layer
/// budget or escape validity prevents a complete classification.
fn decode_text_layers(value: &str, maximum: usize) -> Option<String> {
    if value.len() > maximum {
        return None;
    }
    let mut decoded = value.to_owned();
    for depth in 0..=MAX_REDACTION_DEPTH {
        let mut next = decoded.clone();
        let mut changed = false;
        if next.as_bytes().contains(&b'%') {
            let percent_decoded = percent_decode(&next, maximum);
            if percent_decoded != next {
                next = percent_decoded;
                changed = true;
            }
        }
        if next.as_bytes().contains(&b'\\') {
            match decode_json_escaped_text(&next) {
                Some(json_decoded) if json_decoded != next => {
                    next = json_decoded;
                    changed = true;
                }
                Some(_) => {}
                None => return None,
            }
        }
        if !changed {
            return Some(next);
        }
        if depth == MAX_REDACTION_DEPTH {
            return None;
        }
        decoded = next;
    }
    None
}

fn generic_assignment_key_is_sensitive(policy: &RedactionPolicy, key: &str) -> bool {
    if policy.is_sensitive_key(key) {
        return true;
    }
    if !key.as_bytes().contains(&b'\\') {
        return false;
    }
    decode_json_escaped_text(key).is_none_or(|decoded| policy.is_sensitive_key(&decoded))
}

fn generic_assignment_key_contains_secret(policy: &RedactionPolicy, key: &str) -> bool {
    if policy.contains_configured_secret(key) {
        return true;
    }
    key.as_bytes().contains(&b'\\')
        && decode_json_escaped_text(key)
            .is_some_and(|decoded| policy.contains_configured_secret(&decoded))
}

fn looks_like_jsonish(value: &str) -> bool {
    let bytes = value.as_bytes();
    (bytes.first() == Some(&b'{') && bytes.last() == Some(&b'}'))
        || (bytes.first() == Some(&b'[') && bytes.last() == Some(&b']'))
        || value.contains("\":")
        || value.contains("':")
}

fn looks_like_nested_structure(value: &str) -> bool {
    looks_like_url(value)
        || looks_like_relative_uri(value)
        || looks_like_jsonish(value)
        || generic_assignment_at(value, 0).is_some()
}

/// Bounded generic text sanitizer.  It recognizes sensitive assignments at
/// every nesting level and also routes embedded URL-like tokens through the
/// structural parser.  Non-sensitive text is copied one Unicode scalar at a
/// time so malformed boundaries cannot panic or bypass the output bound.
fn redact_generic_text(
    value: &str,
    policy: &RedactionPolicy,
    maximum: usize,
    depth: usize,
) -> (String, bool) {
    if maximum == 0 {
        return (String::new(), !value.is_empty());
    }
    if depth > MAX_REDACTION_DEPTH || value.len() > HARD_MAX_SCAN_BYTES {
        let (marker, _) = truncate_text(REDACTED, maximum);
        return (marker, true);
    }

    // JSON escapes can also occur in prose fragments rather than a complete
    // object.  If the decoded bounded spelling contains a configured secret,
    // reject the whole value before retaining any raw escaped prefix.
    if value.as_bytes().contains(&b'\\')
        && let Some(decoded) = decode_json_escaped_text(value)
        && policy.contains_configured_secret(&decoded)
    {
        let (marker, _) = truncate_text(REDACTED, maximum);
        return (marker, true);
    }

    // Decode JSON escapes before scanning a JSON-like generic value.  Without
    // this pass, a quoted key/value such as `"raw\\u002dsecret"` is copied
    // character-by-character and never reaches the nested assignment logic.
    // The decoded spelling is bounded by the already bounded input and is
    // used only when it is recognizably JSON-like.
    if value.as_bytes().contains(&b'\\')
        && let Some(decoded) = decode_json_escaped_text(value)
        && decoded != value
        && looks_like_jsonish(&decoded)
    {
        if decoded.chars().any(char::is_control) {
            let (marker, _) = truncate_text(REDACTED, maximum);
            return (marker, true);
        }
        return redact_generic_text(&decoded, policy, maximum, depth.saturating_add(1));
    }

    let mut output = String::with_capacity(value.len().min(maximum));
    let mut cursor = 0;
    let mut truncated = false;
    while cursor < value.len() && output.len() < maximum {
        if let Some(assignment) = generic_assignment_at(value, cursor)
            && generic_assignment_key_is_sensitive(policy, assignment.key)
        {
            // A configured secret in a quoted key may only exist after JSON
            // escape decoding.  Retaining that key while replacing just its
            // value would still leak the configured secret, so fail closed for
            // this bounded value.
            if generic_assignment_key_contains_secret(policy, assignment.key) {
                let (marker, _) = truncate_text(REDACTED, maximum);
                return (marker, true);
            }
            let quoted_value = value
                .as_bytes()
                .get(assignment.value_start)
                .is_some_and(|byte| matches!(*byte, b'"' | b'\''));
            let prefix_end = if quoted_value {
                assignment.value_start.saturating_add(1)
            } else {
                assignment.value_start
            };
            let assignment_end = if quoted_value
                || value
                    .as_bytes()
                    .get(assignment.value_start)
                    .is_some_and(|byte| matches!(*byte, b'{' | b'['))
            {
                assignment.end
            } else {
                generic_sensitive_value_end(value, assignment.value_start, assignment.end)
            };
            truncated |= !append_bounded(&mut output, &value[cursor..prefix_end], maximum);
            truncated |= !append_bounded(&mut output, REDACTED, maximum);
            cursor = assignment_end;
            continue;
        }

        if generic_url_start(value, cursor) {
            let end = generic_token_end(value, cursor);
            if end > cursor {
                let (safe, value_truncated) = redact_nested_value(
                    &value[cursor..end],
                    policy,
                    maximum.saturating_sub(output.len()),
                    depth.saturating_add(1),
                );
                truncated |= !append_bounded(&mut output, &safe, maximum);
                truncated |= value_truncated;
                cursor = end;
                continue;
            }
        }

        let Some(character) = value[cursor..].chars().next() else {
            break;
        };
        let mut buffer = [0_u8; 4];
        let text = character.encode_utf8(&mut buffer);
        truncated |= !append_bounded(&mut output, text, maximum);
        cursor += character.len_utf8();
    }

    truncated |= cursor < value.len();
    if truncated {
        // The output bound was reached before the input was fully inspected.
        // Do not retain a prefix whose final bytes could be the start of a
        // configured secret or sensitive assignment.
        let (marker, _) = truncate_text(REDACTED, maximum);
        return (marker, true);
    }
    let (replaced, replacement_truncated) =
        replace_configured_secrets(&output, &policy.secrets, maximum, true);
    truncated |= replacement_truncated;
    let (replaced, final_truncated) = truncate_text(&replaced, maximum);
    truncated |= final_truncated;
    (replaced, truncated)
}

fn generic_sensitive_value_end(value: &str, start: usize, initial_end: usize) -> usize {
    let bytes = value.as_bytes();
    let mut index = initial_end.max(start);
    while index < bytes.len() {
        if matches!(
            bytes[index],
            b',' | b';' | b'&' | b'\n' | b'\r' | b'}' | b']'
        ) {
            break;
        }
        if bytes[index].is_ascii_whitespace() {
            let mut next = index;
            while next < bytes.len() && bytes[next].is_ascii_whitespace() {
                next += 1;
            }
            if next < bytes.len() && generic_assignment_at(value, next).is_some() {
                break;
            }
        }
        let Some(character) = value[index..].chars().next() else {
            break;
        };
        index += character.len_utf8();
    }
    index
}

#[derive(Clone, Copy)]
struct GenericAssignment<'a> {
    key: &'a str,
    value_start: usize,
    end: usize,
}

fn generic_assignment_at<'a>(value: &'a str, cursor: usize) -> Option<GenericAssignment<'a>> {
    if cursor >= value.len() {
        return None;
    }
    let bytes = value.as_bytes();
    let first = bytes[cursor];
    let (key_start, key_end, after_key) = if first == b'"' || first == b'\'' {
        let quote = first;
        let mut index = cursor + 1;
        while index < bytes.len() {
            if bytes[index] == b'\\' {
                index = index.saturating_add(2);
                continue;
            }
            if bytes[index] == quote {
                return generic_assignment_after_key(value, cursor + 1, index, index + 1);
            }
            index += 1;
        }
        return None;
    } else if first.is_ascii_alphanumeric() || matches!(first, b'_' | b'-' | b'.' | b'%') {
        if cursor > 0
            && value[..cursor]
                .chars()
                .next_back()
                .is_some_and(|previous| previous.is_ascii_alphanumeric() || previous == '_')
        {
            return None;
        }
        let mut index = cursor;
        while index < bytes.len()
            && (bytes[index].is_ascii_alphanumeric()
                || matches!(bytes[index], b'_' | b'-' | b'.' | b'%'))
        {
            index += 1;
        }
        (cursor, index, index)
    } else {
        return None;
    };
    generic_assignment_after_key(value, key_start, key_end, after_key)
}

fn generic_assignment_after_key<'a>(
    value: &'a str,
    key_start: usize,
    key_end: usize,
    after_key: usize,
) -> Option<GenericAssignment<'a>> {
    let bytes = value.as_bytes();
    let mut index = after_key;
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    if index >= bytes.len() || !matches!(bytes[index], b':' | b'=') {
        return None;
    }
    index += 1;
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    let value_start = index;
    let (_, end) = generic_value_span(value, value_start);
    Some(GenericAssignment {
        key: &value[key_start..key_end],
        value_start,
        end,
    })
}

fn generic_value_span(value: &str, start: usize) -> (usize, usize) {
    if start >= value.len() {
        return (start, start);
    }
    let bytes = value.as_bytes();
    if bytes[start] == b'"' || bytes[start] == b'\'' {
        let quote = bytes[start];
        let mut index = start + 1;
        while index < bytes.len() {
            if bytes[index] == b'\\' {
                index = index.saturating_add(2);
                continue;
            }
            if bytes[index] == quote {
                return (start + 1, index);
            }
            index += 1;
        }
        return (start + 1, bytes.len());
    }
    if matches!(bytes[start], b'{' | b'[')
        && let Some(end) = balanced_value_end(value, start)
    {
        return (start, end);
    }
    let mut index = start;
    while index < bytes.len()
        && !matches!(
            bytes[index],
            b',' | b';' | b'&' | b'\n' | b'\r' | b'}' | b']'
        )
        && !bytes[index].is_ascii_whitespace()
    {
        index += 1;
    }
    (start, index)
}

fn balanced_value_end(value: &str, start: usize) -> Option<usize> {
    let bytes = value.as_bytes();
    let mut stack = Vec::new();
    let mut index = start;
    while index < bytes.len() && stack.len() <= MAX_REDACTION_DEPTH {
        match bytes[index] {
            b'"' | b'\'' => {
                let quote = bytes[index];
                index += 1;
                while index < bytes.len() {
                    if bytes[index] == b'\\' {
                        index = index.saturating_add(2);
                    } else if bytes[index] == quote {
                        index += 1;
                        break;
                    } else {
                        index += 1;
                    }
                }
                continue;
            }
            b'{' => stack.push(b'}'),
            b'[' => stack.push(b']'),
            b'}' | b']' => {
                if stack.pop() != Some(bytes[index]) {
                    return None;
                }
                if stack.is_empty() {
                    return Some(index + 1);
                }
            }
            _ => {}
        }
        index += 1;
    }
    None
}

fn generic_url_start(value: &str, cursor: usize) -> bool {
    if !generic_token_boundary(value, cursor) {
        return false;
    }
    let tail = &value[cursor..];
    looks_like_url_prefix(tail)
        || tail.starts_with("//")
        || ((tail.starts_with('/') || tail.starts_with('?') || tail.starts_with('#'))
            && (tail.contains('?') || tail.contains('#')))
        || (tail.starts_with('%') && {
            let mut decoded = percent_decode(tail, 512);
            let mut steps = 0;
            while steps < MAX_REDACTION_DEPTH && !looks_like_nested_structure(&decoded) {
                if !decoded.as_bytes().contains(&b'%') {
                    break;
                }
                let next = percent_decode(&decoded, 512);
                if next == decoded {
                    break;
                }
                decoded = next;
                steps += 1;
            }
            looks_like_nested_structure(&decoded)
        })
}

fn generic_token_boundary(value: &str, cursor: usize) -> bool {
    if cursor == 0 {
        return true;
    }
    value[..cursor].chars().next_back().is_some_and(|previous| {
        !previous.is_ascii_alphanumeric() && !matches!(previous, '_' | '/' | '%')
    })
}

fn looks_like_url_prefix(value: &str) -> bool {
    const MAX_SCHEME_BYTES: usize = 64;
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() && index < MAX_SCHEME_BYTES {
        if bytes[index] == b':' {
            return index > 0
                && bytes.get(index + 1..index + 3) == Some(b"//")
                && value[..index].bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
                });
        }
        if !(bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'+' | b'-' | b'.')) {
            return false;
        }
        index += 1;
    }
    false
}

fn generic_token_end(value: &str, start: usize) -> usize {
    value[start..]
        .char_indices()
        .find(|(_, character)| {
            character.is_ascii_whitespace()
                || matches!(character, ',' | ';' | '}' | ']' | '"' | '\'')
        })
        .map_or(value.len(), |(index, _)| start + index)
}

fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii()
                && !byte.is_ascii_control()
                && !byte.is_ascii_whitespace()
                && byte != b':'
        })
}

fn append_header_prefix(output: &mut String, prefix: &str, maximum: usize) -> bool {
    let mut truncated = false;
    let mut segment_start = 0;
    for (index, character) in prefix.char_indices() {
        if character == '\t' {
            truncated |= !append_bounded(output, &prefix[segment_start..index], maximum);
            truncated |= !append_bounded(output, " ", maximum);
            segment_start = index + character.len_utf8();
        }
    }
    truncated |= !append_bounded(output, &prefix[segment_start..], maximum);
    !truncated
}

fn replace_configured_secrets(
    value: &str,
    secrets: &[Secret],
    maximum: usize,
    skip_markers: bool,
) -> (String, bool) {
    if secrets.is_empty() || maximum == 0 {
        return truncate_text(value, maximum);
    }
    let mut output = String::with_capacity(value.len().min(maximum));
    let mut index = 0;
    let mut truncated = false;
    while index < value.len() && output.len() < maximum {
        // Structural redaction already emitted this marker.  Do not treat
        // marker text as fresh user input when an operator happens to choose
        // a configured secret that is itself contained in the marker.
        if skip_markers && value[index..].starts_with(REDACTED) {
            truncated |= !append_bounded(&mut output, REDACTED, maximum);
            index += REDACTED.len();
            while index < value.len() && value[index..].starts_with(REDACTED) {
                index += REDACTED.len();
            }
            continue;
        }
        let mut match_length = 0;
        for secret in secrets {
            if secret.is_empty() {
                continue;
            }
            let candidate = secret.as_str().as_bytes();
            if candidate.len() > match_length
                && index.saturating_add(candidate.len()) <= value.len()
                && value.as_bytes()[index..index + candidate.len()] == *candidate
            {
                match_length = candidate.len();
            }
        }
        if match_length > 0 {
            truncated |= !append_bounded(&mut output, REDACTED, maximum);
            index += match_length;
        } else if let Some(character) = value[index..].chars().next() {
            let mut buffer = [0_u8; 4];
            let text = character.encode_utf8(&mut buffer);
            truncated |= !append_bounded(&mut output, text, maximum);
            index += character.len_utf8();
        } else {
            break;
        }
    }
    let input_exhausted = index < value.len();
    if input_exhausted {
        // Once the output bound prevents us from proving that the remainder
        // is secret-free, fail closed rather than retaining an inspectable
        // prefix which could precede a configured secret.
        let (marker, _) = truncate_text(REDACTED, maximum);
        return (marker, true);
    }
    (output, truncated)
}

/// A sanitized, bounded diagnostic key/value field.
#[derive(Clone)]
pub struct DiagnosticField {
    key: String,
    value: String,
    truncated: bool,
}

impl PartialEq for DiagnosticField {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key && self.value == other.value && self.truncated == other.truncated
    }
}

impl Eq for DiagnosticField {}

impl DiagnosticField {
    /// Creates a field through the default redaction policy.
    #[must_use]
    pub fn new(key: impl AsRef<str>, value: impl AsRef<str>) -> Self {
        RedactionPolicy::new().field(key.as_ref(), value.as_ref())
    }

    /// Creates a field through the caller's retained central policy.
    #[must_use]
    pub fn with_policy(
        policy: &RedactionPolicy,
        key: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Self {
        policy.field(key.as_ref(), value.as_ref())
    }

    /// Returns the bounded field key.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Returns the already-redacted bounded value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Returns whether key or value truncation occurred.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Consumes the field and returns its sanitized parts.
    #[must_use]
    pub fn into_parts(self) -> (String, String) {
        (self.key, self.value)
    }
}

impl fmt::Debug for DiagnosticField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiagnosticField")
            .field("key", &REDACTED)
            .field("value", &REDACTED)
            .field("truncated", &self.truncated)
            .finish()
    }
}

impl fmt::Display for DiagnosticField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

/// Short aliases for a diagnostic field.
pub type KeyValue = DiagnosticField;
/// Short aliases for a diagnostic field.
pub type Field = DiagnosticField;

/// Alias for [`DiagnosticEvent`].
pub type Event = DiagnosticEvent;
/// Alias for [`DiagnosticSpan`].
pub type Span = DiagnosticSpan;
/// Alias for [`DiagnosticRecord`].
pub type Record = DiagnosticRecord;

/// Errors returned while adding bounded fields to a record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObserveError {
    /// The record already has its maximum number of fields.
    FieldLimitExceeded {
        /// Maximum field count.
        maximum: usize,
    },
    /// A span end was requested without an explicit span-start timestamp.
    MissingTimestamp,
    /// The supplied end reading precedes the span start on the monotonic
    /// clock axis.
    NonMonotonicTimestamp,
}

impl ObserveError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::FieldLimitExceeded { .. } => "observe.fields.limit",
            Self::MissingTimestamp => "observe.timestamp.missing",
            Self::NonMonotonicTimestamp => "observe.timestamp.non-monotonic",
        }
    }
}

impl fmt::Display for ObserveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FieldLimitExceeded { maximum } => {
                write!(formatter, "observe.fields.limit (maximum {maximum})")
            }
            Self::MissingTimestamp => formatter.write_str("observe.timestamp.missing"),
            Self::NonMonotonicTimestamp => formatter.write_str("observe.timestamp.non-monotonic"),
        }
    }
}

impl std::error::Error for ObserveError {}

fn default_name(value: impl AsRef<str>) -> String {
    let policy = RedactionPolicy::new();
    let (name, truncated) =
        policy.redact_value_for_key_with_maximum("", value.as_ref(), DEFAULT_MAX_KEY_BYTES);
    if truncated {
        // Constructors without a caller-supplied policy must not retain a
        // prefix which could contain the beginning of a later-configured
        // secret.  A builder applies its policy after construction, so an
        // opaque marker is the safe intermediate representation.
        REDACTED.to_owned()
    } else {
        name
    }
}

/// One immutable structured diagnostic event.
#[derive(Clone, Eq, PartialEq)]
pub struct DiagnosticEvent {
    policy: RedactionPolicy,
    name: String,
    severity: Severity,
    category: DiagnosticCategory,
    error_code: Option<StableErrorCode>,
    retryability: Option<Retryability>,
    correlation: CorrelationContext,
    fields: Vec<DiagnosticField>,
    timestamp: Option<Timestamp>,
    sequence: SequenceId,
}

impl fmt::Debug for DiagnosticEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiagnosticEvent")
            .field("name", &REDACTED)
            .field("severity", &self.severity)
            .field("category", &self.category)
            .field("error_code", &self.error_code)
            .field("retryability", &self.retryability)
            .field("correlation", &self.correlation)
            .field("fields", &self.fields)
            .finish()
    }
}

impl fmt::Display for DiagnosticEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

impl DiagnosticEvent {
    /// Creates an event with a default redaction policy and no error code.
    #[must_use]
    pub fn new(
        name: impl AsRef<str>,
        severity: Severity,
        category: impl Into<DiagnosticCategory>,
    ) -> Self {
        Self {
            policy: RedactionPolicy::new(),
            name: default_name(name),
            severity,
            category: category.into(),
            error_code: None,
            retryability: None,
            correlation: CorrelationContext::new(),
            fields: Vec::new(),
            timestamp: None,
            sequence: SequenceId::default(),
        }
    }

    /// Creates an event while retaining and applying an explicit policy.
    #[must_use]
    pub fn new_with_policy(
        policy: RedactionPolicy,
        name: impl AsRef<str>,
        severity: Severity,
        category: impl Into<DiagnosticCategory>,
    ) -> Self {
        let mut event = Self::new(name, severity, category);
        event.policy = policy.clone();
        event.correlation = CorrelationContext::with_policy(policy.clone());
        redact_event_in_place(&mut event, &policy);
        event
    }

    /// Returns a builder that applies a custom redaction policy.
    #[must_use]
    pub fn builder(
        name: impl AsRef<str>,
        severity: Severity,
        category: impl Into<DiagnosticCategory>,
    ) -> DiagnosticEventBuilder {
        DiagnosticEventBuilder::new(name, severity, category)
    }

    /// Returns a builder initialized with an explicit policy.
    #[must_use]
    pub fn builder_with_policy(
        policy: RedactionPolicy,
        name: impl AsRef<str>,
        severity: Severity,
        category: impl Into<DiagnosticCategory>,
    ) -> DiagnosticEventBuilder {
        DiagnosticEventBuilder::new_with_policy(policy, name, severity, category)
    }

    /// Replaces the retained policy and re-sanitizes all existing metadata.
    #[must_use]
    pub fn with_policy(mut self, policy: RedactionPolicy) -> Self {
        self.policy = policy.clone();
        redact_event_in_place(&mut self, &policy);
        self
    }

    /// Rebinds the policy while enforcing the destination field bound.
    pub fn try_with_policy(mut self, policy: RedactionPolicy) -> Result<Self, ObserveError> {
        if self.fields.len() > policy.limits.max_fields {
            return Err(ObserveError::FieldLimitExceeded {
                maximum: policy.limits.max_fields,
            });
        }
        self.policy = policy.clone();
        redact_event_in_place(&mut self, &policy);
        Ok(self)
    }

    /// Rebinds an existing event in place with an atomic field-bound check.
    pub fn rebind_policy(&mut self, policy: RedactionPolicy) -> Result<(), ObserveError> {
        if self.fields.len() > policy.limits.max_fields {
            return Err(ObserveError::FieldLimitExceeded {
                maximum: policy.limits.max_fields,
            });
        }
        self.policy = policy.clone();
        redact_event_in_place(self, &policy);
        Ok(())
    }

    /// Creates an event with explicit start timing and sequence capabilities.
    #[must_use]
    pub fn new_timed(
        policy: RedactionPolicy,
        name: impl AsRef<str>,
        severity: Severity,
        category: impl Into<DiagnosticCategory>,
        timestamp: Timestamp,
        sequence: SequenceId,
    ) -> Self {
        Self::new_with_policy(policy, name, severity, category)
            .with_timestamp(timestamp)
            .with_sequence(sequence)
    }

    /// Creates an event using caller-owned deterministic timing capabilities.
    #[must_use]
    pub fn new_with_capabilities(
        policy: RedactionPolicy,
        name: impl AsRef<str>,
        severity: Severity,
        category: impl Into<DiagnosticCategory>,
        clock: &dyn Clock,
        sequencer: &dyn Sequencer,
    ) -> Self {
        Self::new_timed(
            policy,
            name,
            severity,
            category,
            clock.now(),
            sequencer.next(),
        )
    }

    /// Attaches a stable error code.
    #[must_use]
    pub fn with_error_code(mut self, code: impl Into<StableErrorCode>) -> Self {
        self.error_code = Some(redact_code(&self.policy, code.into()));
        self
    }

    /// Attaches retryability classification for a failed operation.
    #[must_use]
    pub const fn with_retryability(mut self, retryability: Retryability) -> Self {
        self.retryability = Some(retryability);
        self
    }

    /// Attaches correlation values.
    #[must_use]
    pub fn with_correlation(mut self, correlation: CorrelationContext) -> Self {
        self.correlation = correlation.redact(&self.policy);
        self
    }

    /// Adds an explicit caller-supplied timestamp.
    #[must_use]
    pub const fn with_timestamp(mut self, timestamp: Timestamp) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    /// Obtains and retains a timestamp from an explicit clock capability.
    #[must_use]
    pub fn with_clock(self, clock: &dyn Clock) -> Self {
        self.with_timestamp(clock.now())
    }

    /// Adds an explicit stable sequence identity.
    #[must_use]
    pub const fn with_sequence(mut self, sequence: SequenceId) -> Self {
        self.sequence = sequence;
        self
    }

    /// Obtains and retains a sequence identity from an explicit capability.
    #[must_use]
    pub fn with_sequencer(self, sequencer: &dyn Sequencer) -> Self {
        self.with_sequence(sequencer.next())
    }

    /// Applies both explicit timing capabilities in one deterministic step.
    #[must_use]
    pub fn with_capabilities(self, clock: &dyn Clock, sequencer: &dyn Sequencer) -> Self {
        self.with_clock(clock).with_sequencer(sequencer)
    }

    /// Adds one field through the default policy.
    pub fn add_field(
        &mut self,
        key: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Result<(), ObserveError> {
        if self.fields.len() >= self.policy.limits.max_fields {
            return Err(ObserveError::FieldLimitExceeded {
                maximum: self.policy.limits.max_fields,
            });
        }
        self.fields
            .push(self.policy.field(key.as_ref(), value.as_ref()));
        Ok(())
    }

    /// Adds one field with an explicit central policy.
    pub fn add_field_with_policy(
        &mut self,
        policy: &RedactionPolicy,
        key: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Result<(), ObserveError> {
        self.policy = policy.clone();
        redact_event_in_place(self, policy);
        if self.fields.len() >= policy.limits.max_fields {
            return Err(ObserveError::FieldLimitExceeded {
                maximum: policy.limits.max_fields,
            });
        }
        self.fields.push(policy.field(key.as_ref(), value.as_ref()));
        Ok(())
    }

    /// Returns the bounded event name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns event severity.
    #[must_use]
    pub const fn severity(&self) -> Severity {
        self.severity
    }

    /// Returns event category.
    #[must_use]
    pub fn category(&self) -> &DiagnosticCategory {
        &self.category
    }

    /// Returns the stable error code, when present.
    #[must_use]
    pub fn error_code(&self) -> Option<&StableErrorCode> {
        self.error_code.as_ref()
    }

    /// Returns retryability classification, when present.
    #[must_use]
    pub const fn retryability(&self) -> Option<Retryability> {
        self.retryability
    }

    /// Returns propagated correlation values.
    #[must_use]
    pub fn correlation(&self) -> &CorrelationContext {
        &self.correlation
    }

    /// Returns sanitized fields in insertion order.
    #[must_use]
    pub fn fields(&self) -> &[DiagnosticField] {
        &self.fields
    }

    /// Returns the explicit timestamp, when one was attached.
    #[must_use]
    pub const fn timestamp(&self) -> Option<Timestamp> {
        self.timestamp
    }

    /// Returns the stable sequence identity (zero means unassigned).
    #[must_use]
    pub const fn sequence(&self) -> SequenceId {
        self.sequence
    }

    /// Alias for [`Self::sequence`] at wire/adaptor boundaries.
    #[must_use]
    pub const fn sequence_id(&self) -> SequenceId {
        self.sequence
    }

    /// Returns the retained policy without exposing configured secret values.
    #[must_use]
    pub fn redaction_policy(&self) -> &RedactionPolicy {
        &self.policy
    }
}

/// Builder for a sanitized diagnostic event.
pub struct DiagnosticEventBuilder {
    event: DiagnosticEvent,
    policy: RedactionPolicy,
    error: Option<ObserveError>,
}

impl fmt::Debug for DiagnosticEventBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiagnosticEventBuilder")
            .field("event", &REDACTED)
            .field("policy", &self.policy)
            .field("error", &self.error)
            .finish()
    }
}

impl fmt::Display for DiagnosticEventBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

impl DiagnosticEventBuilder {
    /// Creates an event builder with default field limits.
    #[must_use]
    pub fn new(
        name: impl AsRef<str>,
        severity: Severity,
        category: impl Into<DiagnosticCategory>,
    ) -> Self {
        Self {
            event: DiagnosticEvent::new(name, severity, category),
            policy: RedactionPolicy::new(),
            error: None,
        }
    }

    /// Creates a builder retaining an explicit redaction policy from the
    /// beginning of construction.
    #[must_use]
    pub fn new_with_policy(
        policy: RedactionPolicy,
        name: impl AsRef<str>,
        severity: Severity,
        category: impl Into<DiagnosticCategory>,
    ) -> Self {
        Self {
            event: DiagnosticEvent::new_with_policy(policy.clone(), name, severity, category),
            policy,
            error: None,
        }
    }

    /// Replaces the builder's central redaction policy.
    #[must_use]
    pub fn with_policy(mut self, policy: RedactionPolicy) -> Self {
        self.policy = policy;
        self.event = self.event.with_policy(self.policy.clone());
        self
    }

    /// Attaches a stable error code.
    #[must_use]
    pub fn with_error_code(mut self, code: impl Into<StableErrorCode>) -> Self {
        self.event = self.event.with_error_code(code);
        self
    }

    /// Attaches retryability classification for a failed operation.
    #[must_use]
    pub const fn with_retryability(mut self, retryability: Retryability) -> Self {
        self.event.retryability = Some(retryability);
        self
    }

    /// Attaches correlation values.
    #[must_use]
    pub fn with_correlation(mut self, correlation: CorrelationContext) -> Self {
        self.event = self.event.with_correlation(correlation);
        self
    }

    /// Attaches an explicit timestamp to the event under construction.
    #[must_use]
    pub fn with_timestamp(mut self, timestamp: Timestamp) -> Self {
        self.event.timestamp = Some(timestamp);
        self
    }

    /// Attaches a timestamp read from an explicit clock capability.
    #[must_use]
    pub fn with_clock(self, clock: &dyn Clock) -> Self {
        self.with_timestamp(clock.now())
    }

    /// Attaches an explicit sequence identity to the event.
    #[must_use]
    pub const fn with_sequence(mut self, sequence: SequenceId) -> Self {
        self.event.sequence = sequence;
        self
    }

    /// Attaches a sequence identity read from an explicit capability.
    #[must_use]
    pub fn with_sequencer(self, sequencer: &dyn Sequencer) -> Self {
        self.with_sequence(sequencer.next())
    }

    /// Applies both explicit timing capabilities in one deterministic step.
    #[must_use]
    pub fn with_capabilities(self, clock: &dyn Clock, sequencer: &dyn Sequencer) -> Self {
        self.with_clock(clock).with_sequencer(sequencer)
    }

    /// Adds a field, retaining any limit error until [`Self::build`].
    #[must_use]
    pub fn field(mut self, key: impl AsRef<str>, value: impl AsRef<str>) -> Self {
        if self.error.is_none() {
            let key = key.as_ref();
            let value = value.as_ref();
            if self.event.fields.len() >= self.policy.limits.max_fields {
                self.error = Some(ObserveError::FieldLimitExceeded {
                    maximum: self.policy.limits.max_fields,
                });
            } else {
                self.event.fields.push(self.policy.field(key, value));
            }
        }
        self
    }

    /// Adds a field and reports a field-limit error immediately.
    pub fn try_field(
        mut self,
        key: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Result<Self, ObserveError> {
        if self.event.fields.len() >= self.policy.limits.max_fields {
            return Err(ObserveError::FieldLimitExceeded {
                maximum: self.policy.limits.max_fields,
            });
        }
        self.event
            .fields
            .push(self.policy.field(key.as_ref(), value.as_ref()));
        Ok(self)
    }

    /// Finishes the event, returning any deferred field-limit error.
    pub fn build(self) -> Result<DiagnosticEvent, ObserveError> {
        match self.error {
            Some(error) => Err(error),
            None => {
                let mut event = self.event;
                redact_event_in_place(&mut event, &self.policy);
                Ok(event)
            }
        }
    }
}

/// The terminal state recorded for a span.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SpanOutcome {
    /// Span completed normally.
    Complete,
    /// Span completed with an error.
    Error,
    /// Span was cancelled before normal completion.
    Canceled,
}

impl SpanOutcome {
    /// Returns the stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Error => "error",
            Self::Canceled => "canceled",
        }
    }
}

/// One immutable structured span-start record.
#[derive(Clone, Eq, PartialEq)]
pub struct DiagnosticSpan {
    policy: RedactionPolicy,
    id: SpanId,
    parent_id: Option<SpanId>,
    name: String,
    severity: Severity,
    category: DiagnosticCategory,
    error_code: Option<StableErrorCode>,
    retryability: Option<Retryability>,
    correlation: CorrelationContext,
    fields: Vec<DiagnosticField>,
    started_at: Option<Timestamp>,
    sequence: SequenceId,
}

impl fmt::Debug for DiagnosticSpan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiagnosticSpan")
            .field("id", &self.id)
            .field("parent_id", &self.parent_id)
            .field("name", &REDACTED)
            .field("severity", &self.severity)
            .field("category", &self.category)
            .field("error_code", &self.error_code)
            .field("retryability", &self.retryability)
            .field("correlation", &self.correlation)
            .field("fields", &self.fields)
            .finish()
    }
}

impl fmt::Display for DiagnosticSpan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

impl DiagnosticSpan {
    /// Creates a span with no assigned ID, parent, or error code.
    #[must_use]
    pub fn new(
        name: impl AsRef<str>,
        severity: Severity,
        category: impl Into<DiagnosticCategory>,
    ) -> Self {
        Self {
            policy: RedactionPolicy::new(),
            id: SpanId::default(),
            parent_id: None,
            name: default_name(name),
            severity,
            category: category.into(),
            error_code: None,
            retryability: None,
            correlation: CorrelationContext::new(),
            fields: Vec::new(),
            started_at: None,
            sequence: SequenceId::default(),
        }
    }

    /// Creates a span while retaining and applying an explicit policy.
    #[must_use]
    pub fn new_with_policy(
        policy: RedactionPolicy,
        name: impl AsRef<str>,
        severity: Severity,
        category: impl Into<DiagnosticCategory>,
    ) -> Self {
        let mut span = Self::new(name, severity, category);
        span.policy = policy.clone();
        span.correlation = CorrelationContext::with_policy(policy.clone());
        redact_span_in_place(&mut span, &policy);
        span
    }

    /// Returns a span builder with default redaction policy.
    #[must_use]
    pub fn builder(
        name: impl AsRef<str>,
        severity: Severity,
        category: impl Into<DiagnosticCategory>,
    ) -> DiagnosticSpanBuilder {
        DiagnosticSpanBuilder::new(name, severity, category)
    }

    /// Returns a span builder initialized with an explicit policy.
    #[must_use]
    pub fn builder_with_policy(
        policy: RedactionPolicy,
        name: impl AsRef<str>,
        severity: Severity,
        category: impl Into<DiagnosticCategory>,
    ) -> DiagnosticSpanBuilder {
        DiagnosticSpanBuilder::new_with_policy(policy, name, severity, category)
    }

    /// Replaces the retained policy and re-sanitizes existing metadata.
    #[must_use]
    pub fn with_policy(mut self, policy: RedactionPolicy) -> Self {
        self.policy = policy.clone();
        redact_span_in_place(&mut self, &policy);
        self
    }

    /// Rebinds the policy while enforcing the destination field bound.
    pub fn try_with_policy(mut self, policy: RedactionPolicy) -> Result<Self, ObserveError> {
        if self.fields.len() > policy.limits.max_fields {
            return Err(ObserveError::FieldLimitExceeded {
                maximum: policy.limits.max_fields,
            });
        }
        self.policy = policy.clone();
        redact_span_in_place(&mut self, &policy);
        Ok(self)
    }

    /// Rebinds an existing span in place with an atomic field-bound check.
    pub fn rebind_policy(&mut self, policy: RedactionPolicy) -> Result<(), ObserveError> {
        if self.fields.len() > policy.limits.max_fields {
            return Err(ObserveError::FieldLimitExceeded {
                maximum: policy.limits.max_fields,
            });
        }
        self.policy = policy.clone();
        redact_span_in_place(self, &policy);
        Ok(())
    }

    /// Creates a span with explicit start timing and sequence capabilities.
    #[must_use]
    pub fn new_timed(
        policy: RedactionPolicy,
        name: impl AsRef<str>,
        severity: Severity,
        category: impl Into<DiagnosticCategory>,
        timestamp: Timestamp,
        sequence: SequenceId,
    ) -> Self {
        Self::new_with_policy(policy, name, severity, category)
            .with_timestamp(timestamp)
            .with_sequence(sequence)
    }

    /// Creates a span using caller-owned deterministic timing capabilities.
    #[must_use]
    pub fn new_with_capabilities(
        policy: RedactionPolicy,
        name: impl AsRef<str>,
        severity: Severity,
        category: impl Into<DiagnosticCategory>,
        clock: &dyn Clock,
        sequencer: &dyn Sequencer,
    ) -> Self {
        Self::new_timed(
            policy,
            name,
            severity,
            category,
            clock.now(),
            sequencer.next(),
        )
    }

    /// Assigns a span identity.
    #[must_use]
    pub const fn with_id(mut self, id: SpanId) -> Self {
        self.id = id;
        self
    }

    /// Assigns a parent span identity.
    #[must_use]
    pub const fn with_parent_id(mut self, id: SpanId) -> Self {
        self.parent_id = Some(id);
        self
    }

    /// Attaches a stable error code.
    #[must_use]
    pub fn with_error_code(mut self, code: impl Into<StableErrorCode>) -> Self {
        self.error_code = Some(redact_code(&self.policy, code.into()));
        self
    }

    /// Attaches retryability classification for a failed span.
    #[must_use]
    pub const fn with_retryability(mut self, retryability: Retryability) -> Self {
        self.retryability = Some(retryability);
        self
    }

    /// Attaches correlation values.
    #[must_use]
    pub fn with_correlation(mut self, correlation: CorrelationContext) -> Self {
        self.correlation = correlation.redact(&self.policy);
        self
    }

    /// Assigns an explicit monotonic/wall-clock start reading.
    #[must_use]
    pub const fn with_timestamp(mut self, timestamp: Timestamp) -> Self {
        self.started_at = Some(timestamp);
        self
    }

    /// Assigns a start reading from an explicit clock capability.
    #[must_use]
    pub fn with_clock(self, clock: &dyn Clock) -> Self {
        self.with_timestamp(clock.now())
    }

    /// Assigns an explicit stable sequence identity.
    #[must_use]
    pub const fn with_sequence(mut self, sequence: SequenceId) -> Self {
        self.sequence = sequence;
        self
    }

    /// Assigns a sequence identity from an explicit capability.
    #[must_use]
    pub fn with_sequencer(self, sequencer: &dyn Sequencer) -> Self {
        self.with_sequence(sequencer.next())
    }

    /// Applies both explicit timing capabilities in one deterministic step.
    #[must_use]
    pub fn with_capabilities(self, clock: &dyn Clock, sequencer: &dyn Sequencer) -> Self {
        self.with_clock(clock).with_sequencer(sequencer)
    }

    /// Returns the span identity.
    #[must_use]
    pub const fn id(&self) -> SpanId {
        self.id
    }

    /// Returns the optional parent span identity.
    #[must_use]
    pub const fn parent_id(&self) -> Option<SpanId> {
        self.parent_id
    }

    /// Returns the bounded span name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns span severity.
    #[must_use]
    pub const fn severity(&self) -> Severity {
        self.severity
    }

    /// Returns span category.
    #[must_use]
    pub fn category(&self) -> &DiagnosticCategory {
        &self.category
    }

    /// Returns the stable error code, when present.
    #[must_use]
    pub fn error_code(&self) -> Option<&StableErrorCode> {
        self.error_code.as_ref()
    }

    /// Returns retryability classification, when present.
    #[must_use]
    pub const fn retryability(&self) -> Option<Retryability> {
        self.retryability
    }

    /// Returns propagated correlation values.
    #[must_use]
    pub fn correlation(&self) -> &CorrelationContext {
        &self.correlation
    }

    /// Returns sanitized fields in insertion order.
    #[must_use]
    pub fn fields(&self) -> &[DiagnosticField] {
        &self.fields
    }

    /// Returns the explicit start timestamp, when one was attached.
    #[must_use]
    pub const fn started_at(&self) -> Option<Timestamp> {
        self.started_at
    }

    /// Alias for [`Self::started_at`] used by timestamp-oriented adapters.
    #[must_use]
    pub const fn timestamp(&self) -> Option<Timestamp> {
        self.started_at
    }

    /// Returns the stable sequence identity (zero means unassigned).
    #[must_use]
    pub const fn sequence(&self) -> SequenceId {
        self.sequence
    }

    /// Alias for [`Self::sequence`] at wire/adaptor boundaries.
    #[must_use]
    pub const fn sequence_id(&self) -> SequenceId {
        self.sequence
    }

    /// Returns the retained policy without exposing configured secret values.
    #[must_use]
    pub fn redaction_policy(&self) -> &RedactionPolicy {
        &self.policy
    }

    /// Adds a sanitized field under the default policy.
    pub fn add_field(
        &mut self,
        key: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Result<(), ObserveError> {
        if self.fields.len() >= self.policy.limits.max_fields {
            return Err(ObserveError::FieldLimitExceeded {
                maximum: self.policy.limits.max_fields,
            });
        }
        self.fields
            .push(self.policy.field(key.as_ref(), value.as_ref()));
        Ok(())
    }

    /// Adds a sanitized field under an explicit policy.
    pub fn add_field_with_policy(
        &mut self,
        policy: &RedactionPolicy,
        key: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Result<(), ObserveError> {
        self.policy = policy.clone();
        redact_span_in_place(self, policy);
        if self.fields.len() >= policy.limits.max_fields {
            return Err(ObserveError::FieldLimitExceeded {
                maximum: policy.limits.max_fields,
            });
        }
        self.fields.push(policy.field(key.as_ref(), value.as_ref()));
        Ok(())
    }

    /// Creates a child span inheriting this span's context and correlation.
    #[must_use]
    pub fn child(
        &self,
        name: impl AsRef<str>,
        severity: Severity,
        category: impl Into<DiagnosticCategory>,
    ) -> DiagnosticSpanBuilder {
        DiagnosticSpanBuilder::new_with_policy(self.policy.clone(), name, severity, category)
            .with_parent_id(self.id)
            .with_correlation(self.correlation.clone())
    }

    /// Creates an event builder inheriting this span's correlation context.
    #[must_use]
    pub fn event(
        &self,
        name: impl AsRef<str>,
        severity: Severity,
        category: impl Into<DiagnosticCategory>,
    ) -> DiagnosticEventBuilder {
        DiagnosticEventBuilder::new_with_policy(self.policy.clone(), name, severity, category)
            .with_correlation(self.correlation.clone())
    }

    /// Creates the explicit terminal record for this span.
    #[must_use]
    pub fn end(&self, outcome: SpanOutcome) -> SpanEnd {
        SpanEnd {
            policy: self.policy.clone(),
            id: self.id,
            outcome,
            error_code: self.error_code.clone(),
            retryability: self.retryability,
            started_at: self.started_at,
            ended_at: None,
            duration: Duration::ZERO,
            sequence: SequenceId::default(),
        }
    }

    /// Ends this span at an explicit timestamp and sequence identity.
    pub fn end_at(
        &self,
        outcome: SpanOutcome,
        ended_at: Timestamp,
        sequence: SequenceId,
    ) -> Result<SpanEnd, ObserveError> {
        let Some(started_at) = self.started_at else {
            return Err(ObserveError::MissingTimestamp);
        };
        if !ended_at.is_monotonic_after(started_at) {
            return Err(ObserveError::NonMonotonicTimestamp);
        }
        Ok(SpanEnd {
            policy: self.policy.clone(),
            id: self.id,
            outcome,
            error_code: self.error_code.clone(),
            retryability: self.retryability,
            started_at: Some(started_at),
            ended_at: Some(ended_at),
            duration: ended_at.duration_since(started_at),
            sequence,
        })
    }

    /// Ends this span using explicit caller-owned clock and sequence
    /// capabilities.
    pub fn end_with_capabilities(
        &self,
        outcome: SpanOutcome,
        clock: &dyn Clock,
        sequencer: &dyn Sequencer,
    ) -> Result<SpanEnd, ObserveError> {
        self.end_at(outcome, clock.now(), sequencer.next())
    }
}

/// Builder for a sanitized diagnostic span.
pub struct DiagnosticSpanBuilder {
    span: DiagnosticSpan,
    policy: RedactionPolicy,
    error: Option<ObserveError>,
}

impl fmt::Debug for DiagnosticSpanBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiagnosticSpanBuilder")
            .field("span", &REDACTED)
            .field("policy", &self.policy)
            .field("error", &self.error)
            .finish()
    }
}

impl fmt::Display for DiagnosticSpanBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

impl DiagnosticSpanBuilder {
    /// Creates a span builder with default field limits.
    #[must_use]
    pub fn new(
        name: impl AsRef<str>,
        severity: Severity,
        category: impl Into<DiagnosticCategory>,
    ) -> Self {
        Self {
            span: DiagnosticSpan::new(name, severity, category),
            policy: RedactionPolicy::new(),
            error: None,
        }
    }

    /// Creates a span builder retaining an explicit redaction policy.
    #[must_use]
    pub fn new_with_policy(
        policy: RedactionPolicy,
        name: impl AsRef<str>,
        severity: Severity,
        category: impl Into<DiagnosticCategory>,
    ) -> Self {
        Self {
            span: DiagnosticSpan::new_with_policy(policy.clone(), name, severity, category),
            policy,
            error: None,
        }
    }

    /// Replaces the builder's central redaction policy.
    #[must_use]
    pub fn with_policy(mut self, policy: RedactionPolicy) -> Self {
        self.policy = policy;
        self.span = self.span.with_policy(self.policy.clone());
        self
    }

    /// Assigns a span identity.
    #[must_use]
    pub const fn with_id(mut self, id: SpanId) -> Self {
        self.span.id = id;
        self
    }

    /// Assigns a parent span identity.
    #[must_use]
    pub const fn with_parent_id(mut self, id: SpanId) -> Self {
        self.span.parent_id = Some(id);
        self
    }

    /// Attaches an error code.
    #[must_use]
    pub fn with_error_code(mut self, code: impl Into<StableErrorCode>) -> Self {
        self.span = self.span.with_error_code(code);
        self
    }

    /// Attaches retryability classification for a failed span.
    #[must_use]
    pub const fn with_retryability(mut self, retryability: Retryability) -> Self {
        self.span.retryability = Some(retryability);
        self
    }

    /// Attaches correlation values.
    #[must_use]
    pub fn with_correlation(mut self, correlation: CorrelationContext) -> Self {
        self.span = self.span.with_correlation(correlation);
        self
    }

    /// Attaches an explicit span-start timestamp.
    #[must_use]
    pub fn with_timestamp(mut self, timestamp: Timestamp) -> Self {
        self.span.started_at = Some(timestamp);
        self
    }

    /// Attaches a timestamp from an explicit clock capability.
    #[must_use]
    pub fn with_clock(self, clock: &dyn Clock) -> Self {
        self.with_timestamp(clock.now())
    }

    /// Attaches an explicit sequence identity.
    #[must_use]
    pub const fn with_sequence(mut self, sequence: SequenceId) -> Self {
        self.span.sequence = sequence;
        self
    }

    /// Attaches a sequence identity from an explicit capability.
    #[must_use]
    pub fn with_sequencer(self, sequencer: &dyn Sequencer) -> Self {
        self.with_sequence(sequencer.next())
    }

    /// Applies both explicit timing capabilities in one deterministic step.
    #[must_use]
    pub fn with_capabilities(self, clock: &dyn Clock, sequencer: &dyn Sequencer) -> Self {
        self.with_clock(clock).with_sequencer(sequencer)
    }

    /// Adds a field, retaining any limit error until [`Self::build`].
    #[must_use]
    pub fn field(mut self, key: impl AsRef<str>, value: impl AsRef<str>) -> Self {
        if self.error.is_none() {
            if self.span.fields.len() >= self.policy.limits.max_fields {
                self.error = Some(ObserveError::FieldLimitExceeded {
                    maximum: self.policy.limits.max_fields,
                });
            } else {
                self.span
                    .fields
                    .push(self.policy.field(key.as_ref(), value.as_ref()));
            }
        }
        self
    }

    /// Adds a field and reports a field-limit error immediately.
    pub fn try_field(
        mut self,
        key: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Result<Self, ObserveError> {
        if self.span.fields.len() >= self.policy.limits.max_fields {
            return Err(ObserveError::FieldLimitExceeded {
                maximum: self.policy.limits.max_fields,
            });
        }
        self.span
            .fields
            .push(self.policy.field(key.as_ref(), value.as_ref()));
        Ok(self)
    }

    /// Finishes the span, returning any deferred field-limit error.
    pub fn build(self) -> Result<DiagnosticSpan, ObserveError> {
        match self.error {
            Some(error) => Err(error),
            None => {
                let mut span = self.span;
                redact_span_in_place(&mut span, &self.policy);
                Ok(span)
            }
        }
    }
}

/// Explicit terminal information for one span.
#[derive(Clone, Eq, PartialEq)]
pub struct SpanEnd {
    policy: RedactionPolicy,
    id: SpanId,
    outcome: SpanOutcome,
    error_code: Option<StableErrorCode>,
    retryability: Option<Retryability>,
    started_at: Option<Timestamp>,
    ended_at: Option<Timestamp>,
    duration: Duration,
    sequence: SequenceId,
}

impl fmt::Debug for SpanEnd {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SpanEnd")
            .field("id", &self.id)
            .field("outcome", &self.outcome)
            .field("error_code", &self.error_code)
            .field("retryability", &self.retryability)
            .finish()
    }
}

impl fmt::Display for SpanEnd {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

impl SpanEnd {
    /// Creates a terminal record without an error code.
    #[must_use]
    pub fn new(id: SpanId, outcome: SpanOutcome) -> Self {
        Self {
            policy: RedactionPolicy::new(),
            id,
            outcome,
            error_code: None,
            retryability: None,
            started_at: None,
            ended_at: None,
            duration: Duration::ZERO,
            sequence: SequenceId::default(),
        }
    }

    /// Creates a terminal record retaining an explicit redaction policy.
    #[must_use]
    pub fn new_with_policy(policy: RedactionPolicy, id: SpanId, outcome: SpanOutcome) -> Self {
        let mut end = Self::new(id, outcome);
        end.policy = policy;
        end
    }

    /// Creates a terminal record with explicit start/end readings and a
    /// caller-assigned stable sequence identity.
    pub fn new_timed(
        policy: RedactionPolicy,
        id: SpanId,
        outcome: SpanOutcome,
        started_at: Timestamp,
        ended_at: Timestamp,
        sequence: SequenceId,
    ) -> Result<Self, ObserveError> {
        Self::new_with_policy(policy, id, outcome)
            .try_with_timing(started_at, ended_at)
            .map(|end| end.with_sequence(sequence))
    }

    /// Attaches a stable error code to the terminal record.
    #[must_use]
    pub fn with_error_code(mut self, code: impl Into<StableErrorCode>) -> Self {
        self.error_code = Some(redact_code(&self.policy, code.into()));
        self
    }

    /// Attaches retryability classification to the terminal record.
    #[must_use]
    pub const fn with_retryability(mut self, retryability: Retryability) -> Self {
        self.retryability = Some(retryability);
        self
    }

    /// Replaces the retained policy and re-sanitizes terminal metadata.
    #[must_use]
    pub fn with_policy(mut self, policy: RedactionPolicy) -> Self {
        self.policy = policy.clone();
        self.error_code = self
            .error_code
            .take()
            .map(|code| redact_code(&policy, code));
        self
    }

    /// Attaches explicit span timing and computes its monotonic duration.
    #[must_use]
    pub fn with_timing(mut self, started_at: Timestamp, ended_at: Timestamp) -> Self {
        self.started_at = Some(started_at);
        self.ended_at = Some(ended_at);
        self.duration = ended_at.duration_since(started_at);
        self
    }

    /// Attaches explicit timing while rejecting a backwards monotonic
    /// reading.
    pub fn try_with_timing(
        self,
        started_at: Timestamp,
        ended_at: Timestamp,
    ) -> Result<Self, ObserveError> {
        if !ended_at.is_monotonic_after(started_at) {
            return Err(ObserveError::NonMonotonicTimestamp);
        }
        Ok(self.with_timing(started_at, ended_at))
    }

    /// Attaches the terminal timestamp from an explicit clock capability.
    #[must_use]
    pub fn with_clock(mut self, clock: &dyn Clock) -> Self {
        let ended_at = clock.now();
        if let Some(started_at) = self.started_at {
            self.ended_at = Some(ended_at);
            self.duration = ended_at.duration_since(started_at);
        } else {
            self.ended_at = Some(ended_at);
        }
        self
    }

    /// Attaches a terminal reading from an explicit clock while enforcing
    /// that the span has a start and the monotonic axis does not go backwards.
    pub fn try_with_clock(self, clock: &dyn Clock) -> Result<Self, ObserveError> {
        let Some(started_at) = self.started_at else {
            return Err(ObserveError::MissingTimestamp);
        };
        self.try_with_timing(started_at, clock.now())
    }

    /// Completes terminal timing and sequence assignment through explicit
    /// caller-owned capabilities.
    pub fn with_capabilities(
        self,
        clock: &dyn Clock,
        sequencer: &dyn Sequencer,
    ) -> Result<Self, ObserveError> {
        self.try_with_clock(clock)
            .map(|end| end.with_sequence(sequencer.next()))
    }

    /// Attaches the stable terminal sequence identity.
    #[must_use]
    pub const fn with_sequence(mut self, sequence: SequenceId) -> Self {
        self.sequence = sequence;
        self
    }

    /// Attaches a terminal sequence from an explicit capability.
    #[must_use]
    pub fn with_sequencer(self, sequencer: &dyn Sequencer) -> Self {
        self.with_sequence(sequencer.next())
    }

    /// Returns the ended span identity.
    #[must_use]
    pub const fn id(&self) -> SpanId {
        self.id
    }

    /// Returns the terminal outcome.
    #[must_use]
    pub const fn outcome(&self) -> SpanOutcome {
        self.outcome
    }

    /// Returns the terminal error code, when present.
    #[must_use]
    pub fn error_code(&self) -> Option<&StableErrorCode> {
        self.error_code.as_ref()
    }

    /// Returns retryability classification, when present.
    #[must_use]
    pub const fn retryability(&self) -> Option<Retryability> {
        self.retryability
    }

    /// Returns the span-start timestamp, when present.
    #[must_use]
    pub const fn started_at(&self) -> Option<Timestamp> {
        self.started_at
    }

    /// Returns the span-end timestamp, when present.
    #[must_use]
    pub const fn ended_at(&self) -> Option<Timestamp> {
        self.ended_at
    }

    /// Returns the monotonic duration between start and end.
    #[must_use]
    pub const fn duration(&self) -> Duration {
        self.duration
    }

    /// Returns the stable terminal sequence identity.
    #[must_use]
    pub const fn sequence(&self) -> SequenceId {
        self.sequence
    }

    /// Alias for [`Self::sequence`] at wire/adaptor boundaries.
    #[must_use]
    pub const fn sequence_id(&self) -> SequenceId {
        self.sequence
    }

    /// Returns the retained policy without exposing configured secret values.
    #[must_use]
    pub fn redaction_policy(&self) -> &RedactionPolicy {
        &self.policy
    }
}

fn redact_identifier_text(policy: &RedactionPolicy, value: &str, was_bounded: bool) -> String {
    if was_bounded {
        // `Identifier::new` keeps a recognizable prefix plus a digest.  The
        // prefix may contain only the beginning of a configured secret, so it
        // cannot be safely policy-scanned after construction.  Keep the
        // digest for identity distinction and discard the entire raw prefix.
        let Some((_, suffix)) = value.rsplit_once('~') else {
            return REDACTED.to_owned();
        };
        if suffix.len() != 16 || !suffix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return REDACTED.to_owned();
        }
        return format!("{REDACTED}~{suffix}");
    }
    let (redacted, redaction_truncated) =
        policy.redact_value_for_key_with_maximum("", value, HARD_MAX_VALUE_BYTES);
    if !redaction_truncated && value.len() <= MAX_IDENTIFIER_BYTES {
        return redacted;
    }

    // Keep the visible prefix safe while deriving uniqueness from the raw
    // identity only through a one-way bounded digest.  Hashing the raw input
    // here prevents two different long identities from collapsing after a
    // redaction or output-bound truncation, while the custom Debug
    // implementations keep the identity out of debug logs.
    let suffix = format!("~{:016x}", stable_digest(value.as_bytes()));
    let prefix_limit = MAX_IDENTIFIER_BYTES.saturating_sub(suffix.len());
    let (prefix, _) = truncate_text(&redacted, prefix_limit);
    let mut bounded = String::with_capacity(MAX_IDENTIFIER_BYTES);
    bounded.push_str(&prefix);
    bounded.push_str(&suffix);
    bounded
}

fn redact_metadata(policy: &RedactionPolicy, value: &str, maximum: usize) -> String {
    let maximum = maximum.min(policy.limits.max_key_bytes);
    policy
        .redact_value_for_key_with_maximum_and_encoded_limit(
            "",
            value,
            maximum,
            maximum.saturating_add(MAX_SECRET_BYTES),
        )
        .0
}

fn redact_category(policy: &RedactionPolicy, category: DiagnosticCategory) -> DiagnosticCategory {
    match category {
        DiagnosticCategory::Custom(value) => {
            DiagnosticCategory::Custom(CustomCategory(BoundedText::new(
                redact_metadata(policy, value.as_str(), DEFAULT_MAX_KEY_BYTES),
                DEFAULT_MAX_KEY_BYTES,
            )))
        }
        builtin => builtin,
    }
}

fn redact_code(policy: &RedactionPolicy, code: StableErrorCode) -> StableErrorCode {
    StableErrorCode(BoundedText::new(
        redact_metadata(policy, code.as_str(), DEFAULT_MAX_KEY_BYTES),
        DEFAULT_MAX_KEY_BYTES,
    ))
}

fn redact_event_in_place(event: &mut DiagnosticEvent, policy: &RedactionPolicy) {
    event.policy = policy.clone();
    event.name = redact_metadata(policy, &event.name, DEFAULT_MAX_KEY_BYTES);
    event.category = redact_category(policy, event.category.clone());
    event.error_code = event
        .error_code
        .take()
        .map(|code| redact_code(policy, code));
    event.correlation = event.correlation.redact(policy);
    event.fields = event
        .fields
        .iter()
        .map(|field| {
            let mut redacted = policy.field(&field.key, &field.value);
            redacted.truncated |= field.truncated;
            redacted
        })
        .collect();
}

fn redact_span_in_place(span: &mut DiagnosticSpan, policy: &RedactionPolicy) {
    span.policy = policy.clone();
    span.name = redact_metadata(policy, &span.name, DEFAULT_MAX_KEY_BYTES);
    span.category = redact_category(policy, span.category.clone());
    span.error_code = span.error_code.take().map(|code| redact_code(policy, code));
    span.correlation = span.correlation.redact(policy);
    span.fields = span
        .fields
        .iter()
        .map(|field| {
            let mut redacted = policy.field(&field.key, &field.value);
            redacted.truncated |= field.truncated;
            redacted
        })
        .collect();
}

/// One record accepted by a diagnostic sink.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiagnosticRecord {
    /// One structured event.
    Event(DiagnosticEvent),
    /// A span start.
    SpanStart(DiagnosticSpan),
    /// A span terminal record.
    SpanEnd(SpanEnd),
}

impl From<DiagnosticEvent> for DiagnosticRecord {
    fn from(value: DiagnosticEvent) -> Self {
        Self::Event(value)
    }
}

impl From<DiagnosticSpan> for DiagnosticRecord {
    fn from(value: DiagnosticSpan) -> Self {
        Self::SpanStart(value)
    }
}

impl From<SpanEnd> for DiagnosticRecord {
    fn from(value: SpanEnd) -> Self {
        Self::SpanEnd(value)
    }
}

impl fmt::Display for DiagnosticRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

impl DiagnosticRecord {
    fn byte_len(&self) -> usize {
        match self {
            Self::Event(event) => event_byte_len(event),
            Self::SpanStart(span) => span_byte_len(span),
            Self::SpanEnd(end) => {
                16 + end
                    .error_code
                    .as_ref()
                    .map_or(0, |code| code.as_str().len())
                    + end
                        .retryability
                        .map_or(0, |retryability| retryability.as_str().len())
                    + end.outcome.as_str().len()
                    + 8
                    + end.policy.retained_bytes()
            }
        }
    }

    /// Returns this record's stable sequence identity.
    #[must_use]
    pub const fn sequence(&self) -> SequenceId {
        match self {
            Self::Event(event) => event.sequence,
            Self::SpanStart(span) => span.sequence,
            Self::SpanEnd(end) => end.sequence,
        }
    }

    fn redact(self, policy: &RedactionPolicy) -> Result<Self, SinkError> {
        match self {
            Self::Event(mut event) => {
                if event.fields.len() > policy.limits.max_fields {
                    return Err(SinkError::RecordFieldLimitExceeded {
                        maximum: policy.limits.max_fields,
                    });
                }
                redact_event_in_place(&mut event, policy);
                Ok(Self::Event(event))
            }
            Self::SpanStart(mut span) => {
                if span.fields.len() > policy.limits.max_fields {
                    return Err(SinkError::RecordFieldLimitExceeded {
                        maximum: policy.limits.max_fields,
                    });
                }
                redact_span_in_place(&mut span, policy);
                Ok(Self::SpanStart(span))
            }
            Self::SpanEnd(mut end) => {
                end.error_code = end.error_code.map(|code| redact_code(policy, code));
                end.policy = policy.clone();
                Ok(Self::SpanEnd(end))
            }
        }
    }
}

fn fields_byte_len(fields: &[DiagnosticField]) -> usize {
    fields.iter().fold(0, |total, field| {
        total
            .saturating_add(field.key.len())
            .saturating_add(field.value.len())
    })
}

fn correlation_byte_len(correlation: &CorrelationContext) -> usize {
    correlation
        .run_id
        .as_ref()
        .map_or(0, |value| value.as_str().len())
        .saturating_add(
            correlation
                .plan_id
                .as_ref()
                .map_or(0, |value| value.as_str().len()),
        )
        .saturating_add(
            correlation
                .plan_hash
                .as_ref()
                .map_or(0, |value| value.as_str().len()),
        )
        .saturating_add(
            correlation
                .profile_id
                .as_ref()
                .map_or(0, |value| value.as_str().len()),
        )
        .saturating_add(
            correlation
                .thread_group_id
                .as_ref()
                .map_or(0, |value| value.as_str().len()),
        )
        .saturating_add(
            correlation
                .user_id
                .as_ref()
                .map_or(0, |value| value.as_str().len()),
        )
        .saturating_add(
            correlation
                .sample_id
                .as_ref()
                .map_or(0, |value| value.as_str().len()),
        )
        .saturating_add(
            correlation
                .parent_sample_id
                .as_ref()
                .map_or(0, |value| value.as_str().len()),
        )
        .saturating_add(
            correlation
                .controller_path
                .as_ref()
                .map_or(0, |value| value.as_str().len()),
        )
        .saturating_add(
            correlation
                .plugin_id
                .as_ref()
                .map_or(0, |value| value.as_str().len()),
        )
        .saturating_add(
            correlation
                .connection_id
                .as_ref()
                .map_or(0, |value| value.as_str().len()),
        )
        .saturating_add(8)
        .saturating_add(correlation.policy.retained_bytes())
}

fn event_byte_len(event: &DiagnosticEvent) -> usize {
    event
        .name
        .len()
        .saturating_add(event.category.as_str().len())
        .saturating_add(
            event
                .error_code
                .as_ref()
                .map_or(0, |code| code.as_str().len()),
        )
        .saturating_add(
            event
                .retryability
                .map_or(0, |retryability| retryability.as_str().len()),
        )
        .saturating_add(correlation_byte_len(&event.correlation))
        .saturating_add(fields_byte_len(&event.fields))
        .saturating_add(event.policy.retained_bytes())
}

fn span_byte_len(span: &DiagnosticSpan) -> usize {
    span.name
        .len()
        .saturating_add(8)
        .saturating_add(if span.parent_id.is_some() { 8 } else { 0 })
        .saturating_add(span.category.as_str().len())
        .saturating_add(
            span.error_code
                .as_ref()
                .map_or(0, |code| code.as_str().len()),
        )
        .saturating_add(
            span.retryability
                .map_or(0, |retryability| retryability.as_str().len()),
        )
        .saturating_add(correlation_byte_len(&span.correlation))
        .saturating_add(fields_byte_len(&span.fields))
        .saturating_add(span.policy.retained_bytes())
}

/// Errors returned by a bounded sink.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SinkError {
    /// The sink has reached its record or byte capacity. The record was not
    /// accepted. A record submitted through [`DiagnosticSink::record_ref`]
    /// remains owned by the caller and can be retried against another sink.
    Full {
        /// Configured record capacity.
        max_records: usize,
        /// Configured byte capacity.
        max_bytes: usize,
    },
    /// The record contains more fields than this sink's redaction policy can
    /// retain.  The record was rejected rather than silently dropping fields.
    RecordFieldLimitExceeded {
        /// Configured maximum fields per record.
        maximum: usize,
    },
    /// The sink was explicitly closed. The record was not accepted.
    Closed,
    /// Cancellation closed the sink; retained records remain drainable.
    Canceled,
    /// The record did not carry an explicit sequence identity.
    MissingSequence,
    /// A sequence identity was already accepted by this sink.
    DuplicateSequence {
        /// Reused sequence identity.
        sequence: SequenceId,
    },
    /// A span identity was zero, which is reserved as unassigned.
    InvalidSpanId,
    /// A span identity was already started or completed.
    DuplicateSpan {
        /// Reused span identity.
        id: SpanId,
    },
    /// A span parent was not live when the child started.
    InvalidParent {
        /// Child span identity.
        id: SpanId,
        /// Missing parent identity.
        parent: SpanId,
    },
    /// A span end referenced a span which is not currently active.
    SpanNotActive {
        /// Referenced span identity.
        id: SpanId,
    },
    /// A lifecycle record omitted its explicit timestamp.
    MissingTimestamp,
    /// A span end precedes its start on the monotonic clock axis.
    NonMonotonicTimestamp,
    /// Closing with live spans would violate exactly-once lifecycle
    /// accounting.
    OpenSpans {
        /// Number of spans still requiring an end record.
        count: usize,
    },
    /// A parent span cannot end while one of its direct children is live.
    ActiveChildren {
        /// Parent span identity.
        id: SpanId,
        /// Number of live direct children.
        count: usize,
    },
    /// The bounded identity history is full.  The sink rejects new records
    /// rather than evicting identities and weakening duplicate detection.
    LifecycleLimitExceeded {
        /// Maximum sequence identities retained for lifecycle validation.
        maximum: usize,
    },
}

impl SinkError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Full { .. } => "observe.sink.full",
            Self::RecordFieldLimitExceeded { .. } => "observe.sink.fields-limit",
            Self::Closed => "observe.sink.closed",
            Self::Canceled => "observe.sink.canceled",
            Self::MissingSequence => "observe.sink.sequence-missing",
            Self::DuplicateSequence { .. } => "observe.sink.sequence-duplicate",
            Self::InvalidSpanId => "observe.sink.span-id-invalid",
            Self::DuplicateSpan { .. } => "observe.sink.span-duplicate",
            Self::InvalidParent { .. } => "observe.sink.parent-invalid",
            Self::SpanNotActive { .. } => "observe.sink.span-not-active",
            Self::MissingTimestamp => "observe.sink.timestamp-missing",
            Self::NonMonotonicTimestamp => "observe.sink.timestamp-non-monotonic",
            Self::OpenSpans { .. } => "observe.sink.open-spans",
            Self::ActiveChildren { .. } => "observe.sink.active-children",
            Self::LifecycleLimitExceeded { .. } => "observe.sink.lifecycle-limit",
        }
    }
}

impl fmt::Display for SinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full {
                max_records,
                max_bytes,
            } => write!(
                formatter,
                "observe.sink.full (maximum {max_records} records/{max_bytes} bytes)"
            ),
            Self::RecordFieldLimitExceeded { maximum } => {
                write!(formatter, "observe.sink.fields-limit (maximum {maximum})")
            }
            Self::Closed => formatter.write_str("observe.sink.closed"),
            Self::Canceled => formatter.write_str("observe.sink.canceled"),
            Self::MissingSequence => formatter.write_str("observe.sink.sequence-missing"),
            Self::DuplicateSequence { sequence } => {
                write!(formatter, "observe.sink.sequence-duplicate ({sequence})")
            }
            Self::InvalidSpanId => formatter.write_str("observe.sink.span-id-invalid"),
            Self::DuplicateSpan { id } => {
                write!(formatter, "observe.sink.span-duplicate ({id})")
            }
            Self::InvalidParent { id, parent } => {
                write!(formatter, "observe.sink.parent-invalid ({id} -> {parent})")
            }
            Self::SpanNotActive { id } => {
                write!(formatter, "observe.sink.span-not-active ({id})")
            }
            Self::MissingTimestamp => formatter.write_str("observe.sink.timestamp-missing"),
            Self::NonMonotonicTimestamp => {
                formatter.write_str("observe.sink.timestamp-non-monotonic")
            }
            Self::OpenSpans { count } => write!(formatter, "observe.sink.open-spans ({count})"),
            Self::ActiveChildren { id, count } => {
                write!(formatter, "observe.sink.active-children ({id}, {count})")
            }
            Self::LifecycleLimitExceeded { maximum } => {
                write!(
                    formatter,
                    "observe.sink.lifecycle-limit (maximum {maximum})"
                )
            }
        }
    }
}

impl std::error::Error for SinkError {}

/// The bounded backpressure behavior of a diagnostic sink.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BackpressurePolicy {
    /// Reject a record when capacity is full; the caller retains ownership and
    /// chooses whether to retry or fail the operation.
    Reject,
}

/// Executor-neutral diagnostic sink contract.
///
/// Runtime/results adapters must assign a non-zero unique [`SequenceId`] and
/// explicit [`Timestamp`] to every event, span start, and span end.  They must
/// submit a span start before its end, keep parent spans live until children
/// finish, end every active span exactly once (using `Canceled` when needed),
/// and handle [`SinkError::Full`] according to [`BackpressurePolicy::Reject`].
/// `flush`, `drain`, `close`, and `cancel` are synchronous and executor-neutral;
/// an adapter that owns an asynchronous queue must drive that queue outside
/// this trait while preserving these no-drop/error semantics.
pub trait DiagnosticSink: Send + Sync {
    /// Records one diagnostic record, consuming the owned value. Callers that
    /// must retain ownership across rejection should use
    /// [`DiagnosticSink::record_ref`], whose borrowed retry contract is
    /// explicit.
    fn record(&self, record: DiagnosticRecord) -> Result<(), SinkError>;

    /// Admits a borrowed record without consuming caller ownership.  A
    /// [`SinkError`] therefore has an explicit retry contract: callers may
    /// retry the same record after [`SinkError::Full`] or route it to another
    /// sink.  Implementations with an asynchronous queue must copy or retain
    /// the bounded record before returning `Ok`.
    fn record_ref(&self, record: &DiagnosticRecord) -> Result<(), SinkError> {
        self.record(record.clone())
    }

    /// Alias for [`DiagnosticSink::record`] useful for queue-like callers.
    fn submit(&self, record: DiagnosticRecord) -> Result<(), SinkError> {
        self.record(record)
    }

    /// Borrowed retry-safe alias for [`DiagnosticSink::record_ref`].
    fn submit_ref(&self, record: &DiagnosticRecord) -> Result<(), SinkError> {
        self.record_ref(record)
    }

    /// Alias for [`DiagnosticSink::record`] useful for exporter-like callers.
    fn emit(&self, record: DiagnosticRecord) -> Result<(), SinkError> {
        self.record(record)
    }

    /// Borrowed retry-safe alias for [`DiagnosticSink::record_ref`].
    fn emit_ref(&self, record: &DiagnosticRecord) -> Result<(), SinkError> {
        self.record_ref(record)
    }

    /// Records an event through the same bounded path.
    fn event(&self, event: DiagnosticEvent) -> Result<(), SinkError> {
        self.record(DiagnosticRecord::Event(event))
    }

    /// Records a span start through the same bounded path.
    fn span_start(&self, span: DiagnosticSpan) -> Result<(), SinkError> {
        self.record(DiagnosticRecord::SpanStart(span))
    }

    /// Records a span end through the same bounded path.
    fn span_end(&self, end: SpanEnd) -> Result<(), SinkError> {
        self.record(DiagnosticRecord::SpanEnd(end))
    }

    /// Returns the explicit bounded backpressure policy.
    fn backpressure_policy(&self) -> BackpressurePolicy;

    /// Flushes records accepted by the sink.
    fn flush(&self) -> Result<(), SinkError>;

    /// Drains records in deterministic sequence order.
    fn drain(&self) -> Result<Vec<DiagnosticRecord>, SinkError>;

    /// Closes the sink after all live spans have ended.
    fn close(&self) -> Result<(), SinkError>;

    /// Cancels future submissions without silently dropping retained records.
    fn cancel(&self) -> Result<(), SinkError>;
}

/// Shared deterministic in-memory sink with explicit full and closed states.
#[derive(Clone, Debug)]
pub struct InMemorySink {
    state: Arc<Mutex<InMemoryState>>,
    limits: SinkLimits,
    policy: RedactionPolicy,
}

/// Alias for the deterministic bounded in-memory sink.
pub type MemorySink = InMemorySink;

#[derive(Debug)]
struct InMemoryState {
    records: Vec<DiagnosticRecord>,
    total_bytes: usize,
    closed: bool,
    canceled: bool,
    sequences: BTreeSet<SequenceId>,
    active_spans: BTreeMap<SpanId, Timestamp>,
    active_children: BTreeMap<SpanId, BTreeSet<SpanId>>,
    span_parents: BTreeMap<SpanId, Option<SpanId>>,
    completed_spans: BTreeSet<SpanId>,
}

impl InMemorySink {
    /// Creates a sink with explicit limits or a record-count shorthand.
    #[must_use]
    pub fn new(limits: impl Into<SinkLimits>) -> Self {
        Self::with_limits_and_policy(limits.into(), RedactionPolicy::new())
    }

    /// Creates a sink with explicit bounds and policy.
    #[must_use]
    pub fn new_with_policy(limits: impl Into<SinkLimits>, policy: RedactionPolicy) -> Self {
        Self::with_limits_and_policy(limits.into(), policy)
    }

    /// Creates a sink with explicit limits and a central redaction policy.
    #[must_use]
    pub fn with_limits_and_policy(limits: SinkLimits, policy: RedactionPolicy) -> Self {
        let limits = SinkLimits::new(limits.max_records, limits.max_bytes);
        Self {
            state: Arc::new(Mutex::new(InMemoryState {
                records: Vec::new(),
                // A policy larger than the configured budget leaves the
                // sink effectively full. Keep accounting within the bound;
                // admission still rejects every record whose full retained
                // representation cannot fit.
                total_bytes: policy.retained_bytes().min(limits.max_bytes),
                closed: false,
                canceled: false,
                sequences: BTreeSet::new(),
                active_spans: BTreeMap::new(),
                active_children: BTreeMap::new(),
                span_parents: BTreeMap::new(),
                completed_spans: BTreeSet::new(),
            })),
            limits,
            policy,
        }
    }

    /// Creates a sink with default capacity and a custom policy.
    #[must_use]
    pub fn with_policy(policy: RedactionPolicy) -> Self {
        Self::with_limits_and_policy(SinkLimits::default(), policy)
    }

    /// Returns the retained policy without exposing configured secret values.
    #[must_use]
    pub fn redaction_policy(&self) -> &RedactionPolicy {
        &self.policy
    }

    /// Returns the configured sink limits.
    #[must_use]
    pub const fn limits(&self) -> SinkLimits {
        self.limits
    }

    /// Returns the number of retained records.
    #[must_use]
    pub fn len(&self) -> usize {
        lock_state(&self.state).records.len()
    }

    /// Returns whether no records are retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns retained aggregate record bytes.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        lock_state(&self.state).total_bytes
    }

    /// Returns whether the sink has been closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        let state = lock_state(&self.state);
        state.closed || state.canceled
    }

    /// Closes the sink. Closing is terminal and idempotent.
    pub fn close(&self) -> Result<(), SinkError> {
        let mut state = lock_state(&self.state);
        if state.canceled {
            return Err(SinkError::Canceled);
        }
        if !state.active_spans.is_empty() {
            return Err(SinkError::OpenSpans {
                count: state.active_spans.len(),
            });
        }
        state.closed = true;
        Ok(())
    }

    /// Cancels future submissions while retaining accepted records.
    pub fn cancel(&self) -> Result<(), SinkError> {
        let mut state = lock_state(&self.state);
        if state.closed {
            return Err(SinkError::Closed);
        }
        if !state.active_spans.is_empty() {
            return Err(SinkError::OpenSpans {
                count: state.active_spans.len(),
            });
        }
        state.canceled = true;
        Ok(())
    }

    /// Flushes an in-memory sink; no deferred work exists.
    pub fn flush(&self) -> Result<(), SinkError> {
        let state = lock_state(&self.state);
        if state.canceled {
            return Err(SinkError::Canceled);
        }
        if state.closed {
            return Err(SinkError::Closed);
        }
        Ok(())
    }

    /// Removes and returns all retained records in sequence order.  Draining
    /// while a span is live is rejected so bounded lifecycle state cannot be
    /// detached from its start record.
    pub fn drain(&self) -> Result<Vec<DiagnosticRecord>, SinkError> {
        let mut state = lock_state(&self.state);
        if !state.active_spans.is_empty() {
            return Err(SinkError::OpenSpans {
                count: state.active_spans.len(),
            });
        }
        let mut records = core::mem::take(&mut state.records);
        state.total_bytes = self.policy.retained_bytes().min(self.limits.max_bytes);
        records.sort_by_key(DiagnosticRecord::sequence);
        Ok(records)
    }

    /// Returns a deterministic snapshot of retained records ordered by their
    /// explicit sequence identity.
    #[must_use]
    pub fn records(&self) -> Vec<DiagnosticRecord> {
        let mut records = lock_state(&self.state).records.clone();
        records.sort_by_key(DiagnosticRecord::sequence);
        records
    }

    /// Returns only retained event records in sequence order.
    #[must_use]
    pub fn events(&self) -> Vec<DiagnosticEvent> {
        self.records()
            .into_iter()
            .filter_map(|record| match record {
                DiagnosticRecord::Event(event) => Some(event),
                DiagnosticRecord::SpanStart(_) | DiagnosticRecord::SpanEnd(_) => None,
            })
            .collect()
    }

    /// Returns only retained span-start records in sequence order.
    #[must_use]
    pub fn spans(&self) -> Vec<DiagnosticSpan> {
        self.records()
            .into_iter()
            .filter_map(|record| match record {
                DiagnosticRecord::SpanStart(span) => Some(span),
                DiagnosticRecord::Event(_) | DiagnosticRecord::SpanEnd(_) => None,
            })
            .collect()
    }
}

impl Default for InMemorySink {
    fn default() -> Self {
        Self::new(SinkLimits::default())
    }
}

fn lock_state(state: &Mutex<InMemoryState>) -> std::sync::MutexGuard<'_, InMemoryState> {
    match state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

impl InMemorySink {
    fn admit_record(&self, input: &DiagnosticRecord) -> Result<(), SinkError> {
        let mut state = lock_state(&self.state);
        if state.canceled {
            return Err(SinkError::Canceled);
        }
        if state.closed {
            return Err(SinkError::Closed);
        }
        let record = input.clone().redact(&self.policy)?;
        let sequence = record.sequence();
        if !sequence.is_valid() {
            return Err(SinkError::MissingSequence);
        }
        if state.sequences.contains(&sequence) {
            return Err(SinkError::DuplicateSequence { sequence });
        }
        match &record {
            DiagnosticRecord::Event(event) => {
                if event.timestamp.is_none() {
                    return Err(SinkError::MissingTimestamp);
                }
            }
            DiagnosticRecord::SpanStart(span) => {
                if span.id.get() == 0 {
                    return Err(SinkError::InvalidSpanId);
                }
                let Some(started_at) = span.started_at else {
                    return Err(SinkError::MissingTimestamp);
                };
                if state.active_spans.contains_key(&span.id)
                    || state.completed_spans.contains(&span.id)
                {
                    return Err(SinkError::DuplicateSpan { id: span.id });
                }
                if let Some(parent) = span.parent_id
                    && (parent.get() == 0 || !state.active_spans.contains_key(&parent))
                {
                    return Err(SinkError::InvalidParent {
                        id: span.id,
                        parent,
                    });
                }
                // The local binding keeps this check explicit before the
                // capacity branch below; no state is mutated until accepted.
                let _ = started_at;
            }
            DiagnosticRecord::SpanEnd(end) => {
                if end.id.get() == 0 {
                    return Err(SinkError::InvalidSpanId);
                }
                let Some(ended_at) = end.ended_at else {
                    return Err(SinkError::MissingTimestamp);
                };
                let Some(started_at) = end.started_at else {
                    return Err(SinkError::MissingTimestamp);
                };
                let Some(active_started_at) = state.active_spans.get(&end.id) else {
                    return Err(SinkError::SpanNotActive { id: end.id });
                };
                if *active_started_at != started_at {
                    return Err(SinkError::MissingTimestamp);
                }
                if !ended_at.is_monotonic_after(started_at) {
                    return Err(SinkError::NonMonotonicTimestamp);
                }
                if end.duration != ended_at.duration_since(started_at) {
                    return Err(SinkError::MissingTimestamp);
                }
                if let Some(children) = state.active_children.get(&end.id)
                    && !children.is_empty()
                {
                    return Err(SinkError::ActiveChildren {
                        id: end.id,
                        count: children.len(),
                    });
                }
            }
        }
        let record_bytes = record.byte_len();
        let exceeds_records = state.records.len() >= self.limits.max_records;
        let exceeds_bytes = state.total_bytes.saturating_add(record_bytes) > self.limits.max_bytes;
        if exceeds_records || exceeds_bytes {
            return Err(SinkError::Full {
                max_records: self.limits.max_records,
                max_bytes: self.limits.max_bytes,
            });
        }
        if state.sequences.len() >= self.limits.max_records {
            return Err(SinkError::LifecycleLimitExceeded {
                maximum: self.limits.max_records,
            });
        }
        state.total_bytes = state.total_bytes.saturating_add(record_bytes);
        state.sequences.insert(sequence);
        match &record {
            DiagnosticRecord::SpanStart(span) => {
                if let Some(started_at) = span.started_at {
                    state.active_spans.insert(span.id, started_at);
                    state.active_children.insert(span.id, BTreeSet::new());
                    state.span_parents.insert(span.id, span.parent_id);
                    if let Some(parent) = span.parent_id {
                        state
                            .active_children
                            .entry(parent)
                            .or_default()
                            .insert(span.id);
                    }
                }
            }
            DiagnosticRecord::SpanEnd(end) => {
                state.active_spans.remove(&end.id);
                if let Some(parent) = state.span_parents.remove(&end.id).flatten()
                    && let Some(children) = state.active_children.get_mut(&parent)
                {
                    children.remove(&end.id);
                }
                state.active_children.remove(&end.id);
                state.completed_spans.insert(end.id);
            }
            DiagnosticRecord::Event(_) => {}
        }
        state.records.push(record);
        Ok(())
    }
}

impl DiagnosticSink for InMemorySink {
    fn record(&self, record: DiagnosticRecord) -> Result<(), SinkError> {
        self.admit_record(&record)
    }

    fn record_ref(&self, record: &DiagnosticRecord) -> Result<(), SinkError> {
        self.admit_record(record)
    }

    fn backpressure_policy(&self) -> BackpressurePolicy {
        BackpressurePolicy::Reject
    }

    fn flush(&self) -> Result<(), SinkError> {
        InMemorySink::flush(self)
    }

    fn drain(&self) -> Result<Vec<DiagnosticRecord>, SinkError> {
        InMemorySink::drain(self)
    }

    fn close(&self) -> Result<(), SinkError> {
        InMemorySink::close(self)
    }

    fn cancel(&self) -> Result<(), SinkError> {
        InMemorySink::cancel(self)
    }
}

/// Default maximum number of distinct metric identities retained by one
/// registry.
pub const DEFAULT_MAX_METRICS: usize = 1_024;

/// Default maximum number of labels on one metric identity.
pub const DEFAULT_MAX_METRIC_LABELS: usize = 8;

/// Default maximum metric-name length in bytes.
pub const DEFAULT_MAX_METRIC_NAME_BYTES: usize = 128;

/// Default maximum metric-label key length in bytes.
pub const DEFAULT_MAX_METRIC_LABEL_KEY_BYTES: usize = 64;

/// Default maximum metric-label value length in bytes.
pub const DEFAULT_MAX_METRIC_LABEL_VALUE_BYTES: usize = 128;

/// Default maximum number of explicit histogram buckets.
pub const DEFAULT_MAX_HISTOGRAM_BUCKETS: usize = 32;

/// Default aggregate bytes retained by one metric registry.
pub const DEFAULT_MAX_METRIC_BYTES: usize = 4 * 1024 * 1024;

/// Absolute safety ceiling for distinct metric identities.
pub const HARD_MAX_METRICS: usize = 65_536;

/// Absolute safety ceiling for labels on one metric identity.
pub const HARD_MAX_METRIC_LABELS: usize = 64;

/// Absolute safety ceiling for a metric name.
pub const HARD_MAX_METRIC_NAME_BYTES: usize = 4 * 1024;

/// Absolute safety ceiling for a metric-label key.
pub const HARD_MAX_METRIC_LABEL_KEY_BYTES: usize = 4 * 1024;

/// Absolute safety ceiling for a metric-label value.
pub const HARD_MAX_METRIC_LABEL_VALUE_BYTES: usize = 16 * 1024;

/// Absolute safety ceiling for explicit histogram buckets.
pub const HARD_MAX_HISTOGRAM_BUCKETS: usize = 256;

/// Absolute safety ceiling for aggregate metric state.
pub const HARD_MAX_METRIC_BYTES: usize = 64 * 1024 * 1024;

/// Resource bounds for the in-process metric registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetricLimits {
    /// Maximum number of distinct metric name/label combinations.
    pub max_metrics: usize,
    /// Maximum number of labels on one metric.
    pub max_labels: usize,
    /// Maximum metric-name length in bytes.
    pub max_name_bytes: usize,
    /// Maximum label-key length in bytes.
    pub max_label_key_bytes: usize,
    /// Maximum label-value length in bytes.
    pub max_label_value_bytes: usize,
    /// Maximum explicit histogram buckets.
    pub max_histogram_buckets: usize,
    /// Maximum aggregate bytes retained by the registry.
    pub max_bytes: usize,
}

impl MetricLimits {
    /// Creates metric bounds, clamping each value to a finite safety ceiling.
    #[must_use]
    pub const fn new(
        max_metrics: usize,
        max_labels: usize,
        max_name_bytes: usize,
        max_label_key_bytes: usize,
        max_label_value_bytes: usize,
        max_histogram_buckets: usize,
    ) -> Self {
        Self {
            max_metrics: if max_metrics > HARD_MAX_METRICS {
                HARD_MAX_METRICS
            } else {
                max_metrics
            },
            max_labels: if max_labels > HARD_MAX_METRIC_LABELS {
                HARD_MAX_METRIC_LABELS
            } else {
                max_labels
            },
            max_name_bytes: if max_name_bytes > HARD_MAX_METRIC_NAME_BYTES {
                HARD_MAX_METRIC_NAME_BYTES
            } else {
                max_name_bytes
            },
            max_label_key_bytes: if max_label_key_bytes > HARD_MAX_METRIC_LABEL_KEY_BYTES {
                HARD_MAX_METRIC_LABEL_KEY_BYTES
            } else {
                max_label_key_bytes
            },
            max_label_value_bytes: if max_label_value_bytes > HARD_MAX_METRIC_LABEL_VALUE_BYTES {
                HARD_MAX_METRIC_LABEL_VALUE_BYTES
            } else {
                max_label_value_bytes
            },
            max_histogram_buckets: if max_histogram_buckets > HARD_MAX_HISTOGRAM_BUCKETS {
                HARD_MAX_HISTOGRAM_BUCKETS
            } else {
                max_histogram_buckets
            },
            max_bytes: DEFAULT_MAX_METRIC_BYTES,
        }
    }

    /// Creates metric bounds with an explicit aggregate byte limit.
    #[must_use]
    pub const fn new_with_max_bytes(
        max_metrics: usize,
        max_labels: usize,
        max_name_bytes: usize,
        max_label_key_bytes: usize,
        max_label_value_bytes: usize,
        max_histogram_buckets: usize,
        max_bytes: usize,
    ) -> Self {
        Self::new(
            max_metrics,
            max_labels,
            max_name_bytes,
            max_label_key_bytes,
            max_label_value_bytes,
            max_histogram_buckets,
        )
        .with_max_bytes(max_bytes)
    }

    /// Rebinds only the aggregate byte bound, retaining all other limits.
    #[must_use]
    pub const fn with_max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = if max_bytes > HARD_MAX_METRIC_BYTES {
            HARD_MAX_METRIC_BYTES
        } else {
            max_bytes
        };
        self
    }
}

impl Default for MetricLimits {
    fn default() -> Self {
        Self {
            max_metrics: DEFAULT_MAX_METRICS,
            max_labels: DEFAULT_MAX_METRIC_LABELS,
            max_name_bytes: DEFAULT_MAX_METRIC_NAME_BYTES,
            max_label_key_bytes: DEFAULT_MAX_METRIC_LABEL_KEY_BYTES,
            max_label_value_bytes: DEFAULT_MAX_METRIC_LABEL_VALUE_BYTES,
            max_histogram_buckets: DEFAULT_MAX_HISTOGRAM_BUCKETS,
            max_bytes: DEFAULT_MAX_METRIC_BYTES,
        }
    }
}

/// Errors returned by the bounded in-process metric registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetricError {
    /// A metric name was empty.
    EmptyName,
    /// A metric name contained a control, non-ASCII, or unsupported character.
    InvalidName,
    /// A metric name exceeded its configured bound.
    NameTooLong {
        /// Input byte length.
        actual: usize,
        /// Configured maximum byte length.
        maximum: usize,
    },
    /// A metric label key was empty.
    EmptyLabelKey,
    /// A metric label key contained non-ASCII or control input.
    InvalidLabelKey,
    /// A metric label key exceeded its configured bound.
    LabelKeyTooLong {
        /// Input byte length.
        actual: usize,
        /// Configured maximum byte length.
        maximum: usize,
    },
    /// A metric label value exceeded its configured bound.
    LabelValueTooLong {
        /// Input byte length.
        actual: usize,
        /// Configured maximum byte length.
        maximum: usize,
    },
    /// A low-cardinality label value contained an unsafe character.
    InvalidLabelValue,
    /// A metric contains more labels than configured.
    LabelLimitExceeded {
        /// Configured maximum label count.
        maximum: usize,
    },
    /// Two labels on one metric used the same key.
    DuplicateLabel,
    /// The registry reached its distinct-metric bound.
    MetricLimitExceeded {
        /// Configured maximum distinct metric count.
        maximum: usize,
    },
    /// A metric identity was previously registered with another kind.
    TypeConflict,
    /// Histogram boundaries were not strictly increasing.
    InvalidHistogramBounds,
    /// A histogram has more buckets than configured.
    HistogramBucketLimitExceeded {
        /// Configured maximum bucket count.
        maximum: usize,
    },
    /// A counter or histogram accumulator would overflow.
    ValueOverflow,
    /// The registry was explicitly closed.
    Closed,
    /// A policy rebind would mutate metric state shared by another registry
    /// handle. Rebinding is rejected rather than leaving clones with
    /// divergent redaction policies over one shared state.
    SharedPolicy,
    /// Aggregate retained metric state exceeded its byte bound.
    ByteLimitExceeded {
        /// Configured aggregate byte limit.
        maximum: usize,
    },
}

impl MetricError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::EmptyName => "observe.metric.empty-name",
            Self::InvalidName => "observe.metric.invalid-name",
            Self::NameTooLong { .. } => "observe.metric.name-too-long",
            Self::EmptyLabelKey => "observe.metric.empty-label-key",
            Self::InvalidLabelKey => "observe.metric.invalid-label-key",
            Self::LabelKeyTooLong { .. } => "observe.metric.label-key-too-long",
            Self::LabelValueTooLong { .. } => "observe.metric.label-value-too-long",
            Self::InvalidLabelValue => "observe.metric.invalid-label-value",
            Self::LabelLimitExceeded { .. } => "observe.metric.label-limit",
            Self::DuplicateLabel => "observe.metric.duplicate-label",
            Self::MetricLimitExceeded { .. } => "observe.metric.limit",
            Self::TypeConflict => "observe.metric.type-conflict",
            Self::InvalidHistogramBounds => "observe.metric.invalid-buckets",
            Self::HistogramBucketLimitExceeded { .. } => "observe.metric.bucket-limit",
            Self::ValueOverflow => "observe.metric.overflow",
            Self::Closed => "observe.metric.closed",
            Self::SharedPolicy => "observe.metric.shared-policy",
            Self::ByteLimitExceeded { .. } => "observe.metric.bytes-limit",
        }
    }
}

impl fmt::Display for MetricError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyName => formatter.write_str("observe.metric.empty-name"),
            Self::InvalidName => formatter.write_str("observe.metric.invalid-name"),
            Self::NameTooLong { actual, maximum } => {
                write!(
                    formatter,
                    "observe.metric.name-too-long ({actual} > {maximum} bytes)"
                )
            }
            Self::EmptyLabelKey => formatter.write_str("observe.metric.empty-label-key"),
            Self::InvalidLabelKey => formatter.write_str("observe.metric.invalid-label-key"),
            Self::LabelKeyTooLong { actual, maximum } => write!(
                formatter,
                "observe.metric.label-key-too-long ({actual} > {maximum} bytes)"
            ),
            Self::LabelValueTooLong { actual, maximum } => write!(
                formatter,
                "observe.metric.label-value-too-long ({actual} > {maximum} bytes)"
            ),
            Self::InvalidLabelValue => formatter.write_str("observe.metric.invalid-label-value"),
            Self::LabelLimitExceeded { maximum } => {
                write!(formatter, "observe.metric.label-limit (maximum {maximum})")
            }
            Self::DuplicateLabel => formatter.write_str("observe.metric.duplicate-label"),
            Self::MetricLimitExceeded { maximum } => {
                write!(formatter, "observe.metric.limit (maximum {maximum})")
            }
            Self::TypeConflict => formatter.write_str("observe.metric.type-conflict"),
            Self::InvalidHistogramBounds => formatter.write_str("observe.metric.invalid-buckets"),
            Self::HistogramBucketLimitExceeded { maximum } => {
                write!(formatter, "observe.metric.bucket-limit (maximum {maximum})")
            }
            Self::ValueOverflow => formatter.write_str("observe.metric.overflow"),
            Self::Closed => formatter.write_str("observe.metric.closed"),
            Self::SharedPolicy => formatter.write_str("observe.metric.shared-policy"),
            Self::ByteLimitExceeded { maximum } => {
                write!(formatter, "observe.metric.bytes-limit (maximum {maximum})")
            }
        }
    }
}

impl std::error::Error for MetricError {}

/// One sanitized metric label.  Labels are intentionally separate from
/// diagnostic fields so metric identity does not expose event-only metadata.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MetricLabel {
    key: String,
    value: String,
}

impl fmt::Debug for MetricLabel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MetricLabel")
            .field("key", &REDACTED)
            .field("value", &REDACTED)
            .finish()
    }
}

impl MetricLabel {
    /// Creates a label using the default metric and redaction bounds.
    pub fn new(key: impl AsRef<str>, value: impl AsRef<str>) -> Result<Self, MetricError> {
        let limits = MetricLimits::default();
        Self::with_policy(
            &RedactionPolicy::new(),
            limits,
            key.as_ref(),
            value.as_ref(),
        )
    }

    /// Creates a label with an explicit central redaction policy.
    pub fn new_with_policy(
        policy: &RedactionPolicy,
        key: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Result<Self, MetricError> {
        Self::with_policy(
            policy,
            MetricLimits::default(),
            key.as_ref(),
            value.as_ref(),
        )
    }

    fn with_policy(
        policy: &RedactionPolicy,
        limits: MetricLimits,
        key: &str,
        value: &str,
    ) -> Result<Self, MetricError> {
        if key.is_empty() {
            return Err(MetricError::EmptyLabelKey);
        }
        let key_maximum = limits.max_label_key_bytes.min(policy.limits.max_key_bytes);
        if key.len() > key_maximum {
            return Err(MetricError::LabelKeyTooLong {
                actual: key.len(),
                maximum: key_maximum,
            });
        }
        if key
            .chars()
            .any(|character| !character.is_ascii() || character.is_control())
        {
            return Err(MetricError::InvalidLabelKey);
        }
        if !valid_metric_label_key(key) {
            return Err(MetricError::InvalidLabelKey);
        }
        if value.len() > limits.max_label_value_bytes {
            return Err(MetricError::LabelValueTooLong {
                actual: value.len(),
                maximum: limits.max_label_value_bytes,
            });
        }
        let low_cardinality = is_low_cardinality_metric_key(key);
        if low_cardinality && value.len() > policy.limits.max_value_bytes {
            return Err(MetricError::LabelValueTooLong {
                actual: value.len(),
                maximum: policy.limits.max_value_bytes,
            });
        }
        if low_cardinality && !valid_low_cardinality_value(value) {
            return Err(MetricError::InvalidLabelValue);
        }
        let original_value = value;
        let field = policy.field(key, original_value);
        let field_truncated = field.is_truncated();
        let (key, value) = field.into_parts();
        if key.is_empty() {
            return Err(MetricError::EmptyLabelKey);
        }
        if key.len() > key_maximum {
            return Err(MetricError::LabelKeyTooLong {
                actual: key.len(),
                maximum: key_maximum,
            });
        }
        if !valid_metric_label_key(&key) {
            // A configured secret may occur in a label key.  The central
            // policy replaces it with a marker containing punctuation, which
            // is not a valid metric identity.  Reject rather than retaining a
            // malformed or partially redacted key.
            return Err(MetricError::InvalidLabelKey);
        }
        if value.len() > limits.max_label_value_bytes {
            return Err(MetricError::LabelValueTooLong {
                actual: value.len(),
                maximum: limits.max_label_value_bytes,
            });
        }
        if low_cardinality && value != REDACTED && !valid_low_cardinality_value(&value) {
            return Err(MetricError::InvalidLabelValue);
        }
        let value =
            if value == REDACTED || (low_cardinality && metric_value_allowlisted(&key, &value)) {
                value
            } else if is_hashed_metric_value(&value) {
                // Re-sanitizing an already safe metric identity must be
                // idempotent.  Hashing an existing digest again on every
                // policy rebind would silently change the metric series.
                value
            } else if field_truncated
                && !policy.contains_configured_secret(original_value)
                && !policy.contains_percent_encoded_secret(original_value)
            {
                // Never derive a cardinality identity from a policy-truncated
                // prefix: two long values sharing that prefix would collapse to
                // the same metric series.  The raw input is already bounded by
                // `MetricLimits`; retain only its digest.
                hashed_metric_value(original_value, limits.max_label_value_bytes)?
            } else {
                hashed_metric_value(value.as_str(), limits.max_label_value_bytes)?
            };
        Ok(Self { key, value })
    }

    /// Returns the sanitized label key.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Returns the sanitized label value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

fn hashed_metric_value(value: &str, maximum: usize) -> Result<String, MetricError> {
    const HASHED_VALUE_BYTES: usize = 16;
    if maximum < HASHED_VALUE_BYTES {
        return Err(MetricError::LabelValueTooLong {
            actual: HASHED_VALUE_BYTES,
            maximum,
        });
    }
    Ok(format!(
        "h:{:014x}",
        stable_digest(value.as_bytes()) & 0x00ff_ffff_ffff_ffff
    ))
}

fn is_hashed_metric_value(value: &str) -> bool {
    let Some(digest) = value.strip_prefix("h:") else {
        return false;
    };
    digest.len() == 14 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_low_cardinality_metric_key(key: &str) -> bool {
    matches!(
        canonical_key(key).as_str(),
        "category"
            | "code"
            | "component"
            | "direction"
            | "kind"
            | "method"
            | "operation"
            | "outcome"
            | "phase"
            | "protocol"
            | "reason"
            | "result"
            | "state"
            | "status"
            | "type"
    )
}

fn valid_metric_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn valid_metric_label_key(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn valid_low_cardinality_value(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'_' | b'.' | b'-' | b':' | b'/' | b'+' | b'=')
        })
}

fn metric_value_allowlisted(_key: &str, value: &str) -> bool {
    if !valid_low_cardinality_value(value) {
        return false;
    }
    // Numeric status/error codes are bounded to their conventional three
    // byte representation.  Retaining arbitrary-length digit strings would
    // turn a low-cardinality label into an unbounded identity dimension.
    if value.len() <= 3 && value.bytes().all(|byte| byte.is_ascii_digit()) {
        return true;
    }
    const ALLOWED: &[&str] = &[
        "sample",
        "transaction",
        "counter",
        "gauge",
        "histogram",
        "start",
        "end",
        "complete",
        "error",
        "cancel",
        "canceled",
        "cancelled",
        "success",
        "failure",
        "unknown",
        "retryable",
        "terminal",
        "request",
        "response",
        "read",
        "write",
        "http",
        "https",
        "tcp",
        "udp",
        "get",
        "post",
        "put",
        "delete",
        "head",
        "patch",
        "options",
        "setup",
        "main",
        "teardown",
        "normal",
        "warning",
        "info",
        "debug",
        "trace",
        "fatal",
        "client",
        "server",
        "in",
        "out",
        "true",
        "false",
    ];
    // Metric label keys are already bounded and ASCII; keep the allowlist
    // explicit so an arbitrary low-cardinality-looking value is hashed
    // instead of becoming an unreviewed metric dimension.
    ALLOWED.contains(&value) || matches!(value, "1xx" | "2xx" | "3xx" | "4xx" | "5xx")
}

/// An insertion-order-independent collection of sanitized metric labels.
#[derive(Clone, Debug)]
pub struct MetricLabels {
    labels: Vec<MetricLabel>,
    limits: MetricLimits,
    policy: RedactionPolicy,
}

impl MetricLabels {
    /// Creates an empty label set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            labels: Vec::new(),
            limits: MetricLimits {
                max_metrics: DEFAULT_MAX_METRICS,
                max_labels: DEFAULT_MAX_METRIC_LABELS,
                max_name_bytes: DEFAULT_MAX_METRIC_NAME_BYTES,
                max_label_key_bytes: DEFAULT_MAX_METRIC_LABEL_KEY_BYTES,
                max_label_value_bytes: DEFAULT_MAX_METRIC_LABEL_VALUE_BYTES,
                max_histogram_buckets: DEFAULT_MAX_HISTOGRAM_BUCKETS,
                max_bytes: DEFAULT_MAX_METRIC_BYTES,
            },
            policy: RedactionPolicy::new(),
        }
    }

    /// Creates an empty label set with explicit resource bounds.
    #[must_use]
    pub fn with_limits(limits: MetricLimits) -> Self {
        Self {
            labels: Vec::new(),
            limits: MetricLimits::new(
                limits.max_metrics,
                limits.max_labels,
                limits.max_name_bytes,
                limits.max_label_key_bytes,
                limits.max_label_value_bytes,
                limits.max_histogram_buckets,
            )
            .with_max_bytes(limits.max_bytes),
            policy: RedactionPolicy::new(),
        }
    }

    /// Creates an empty label set with explicit bounds and redaction policy.
    #[must_use]
    pub fn with_limits_and_policy(limits: MetricLimits, policy: RedactionPolicy) -> Self {
        Self {
            labels: Vec::new(),
            limits: MetricLimits::new(
                limits.max_metrics,
                limits.max_labels,
                limits.max_name_bytes,
                limits.max_label_key_bytes,
                limits.max_label_value_bytes,
                limits.max_histogram_buckets,
            )
            .with_max_bytes(limits.max_bytes),
            policy,
        }
    }

    /// Creates an empty label set with default bounds and explicit policy.
    #[must_use]
    pub fn with_policy(policy: RedactionPolicy) -> Self {
        Self::with_limits_and_policy(MetricLimits::default(), policy)
    }

    /// Returns the retained policy without exposing configured secret values.
    #[must_use]
    pub fn redaction_policy(&self) -> &RedactionPolicy {
        &self.policy
    }

    /// Adds a label using default redaction and metric bounds.
    pub fn push(
        &mut self,
        key: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Result<(), MetricError> {
        let policy = self.policy.clone();
        self.push_with_policy(&policy, self.limits, key.as_ref(), value.as_ref())
    }

    /// Adds a label after applying an explicit central policy and bounds.
    pub fn push_with_policy(
        &mut self,
        policy: &RedactionPolicy,
        limits: MetricLimits,
        key: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Result<(), MetricError> {
        let limits = MetricLimits::new(
            limits.max_metrics,
            self.limits.max_labels.min(limits.max_labels),
            self.limits.max_name_bytes.min(limits.max_name_bytes),
            self.limits
                .max_label_key_bytes
                .min(limits.max_label_key_bytes),
            self.limits
                .max_label_value_bytes
                .min(limits.max_label_value_bytes),
            self.limits
                .max_histogram_buckets
                .min(limits.max_histogram_buckets),
        )
        .with_max_bytes(self.limits.max_bytes.min(limits.max_bytes));
        if self.labels.len() >= limits.max_labels {
            return Err(MetricError::LabelLimitExceeded {
                maximum: limits.max_labels,
            });
        }
        // Rebind every retained label before adding the new one.  A policy
        // change must not leave values sanitized under an earlier policy;
        // rebuilding first also makes the operation atomic on error.
        let mut rebound = Vec::with_capacity(self.labels.len().saturating_add(1));
        for existing in &self.labels {
            let label = MetricLabel::with_policy(policy, limits, &existing.key, &existing.value)?;
            if rebound
                .iter()
                .any(|item: &MetricLabel| item.key == label.key)
            {
                return Err(MetricError::DuplicateLabel);
            }
            rebound.push(label);
        }
        let label = MetricLabel::with_policy(policy, limits, key.as_ref(), value.as_ref())?;
        if rebound.iter().any(|item| item.key == label.key) {
            return Err(MetricError::DuplicateLabel);
        }
        rebound.push(label);
        self.labels = rebound;
        self.labels.sort();
        self.limits = limits;
        self.policy = policy.clone();
        Ok(())
    }

    /// Re-sanitizes all retained labels under a new policy without adding a
    /// label.  The operation is atomic and preserves the current bounds.
    pub fn rebind_policy(&mut self, policy: RedactionPolicy) -> Result<(), MetricError> {
        let limits = self.limits;
        let mut rebound = Vec::with_capacity(self.labels.len());
        for existing in &self.labels {
            let label = MetricLabel::with_policy(&policy, limits, &existing.key, &existing.value)?;
            if rebound
                .iter()
                .any(|item: &MetricLabel| item.key == label.key)
            {
                return Err(MetricError::DuplicateLabel);
            }
            rebound.push(label);
        }
        rebound.sort();
        self.labels = rebound;
        self.policy = policy;
        Ok(())
    }

    /// Returns the number of labels.
    #[must_use]
    pub fn len(&self) -> usize {
        self.labels.len()
    }

    /// Returns whether this set has no labels.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }

    /// Returns labels in deterministic key/value order.
    #[must_use]
    pub fn as_slice(&self) -> &[MetricLabel] {
        &self.labels
    }

    /// Returns a label value by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.labels
            .binary_search_by(|label| label.key.as_str().cmp(key))
            .ok()
            .map(|index| self.labels[index].value.as_str())
    }
}

impl Default for MetricLabels {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for MetricLabels {
    fn eq(&self, other: &Self) -> bool {
        self.labels == other.labels
    }
}

impl Eq for MetricLabels {}

impl std::hash::Hash for MetricLabels {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.labels.hash(state);
    }
}

impl Ord for MetricLabels {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.labels.cmp(&other.labels)
    }
}

impl PartialOrd for MetricLabels {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// The kind of an in-process metric.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MetricKind {
    /// A monotonically increasing count.
    Counter,
    /// A point-in-time signed value.
    Gauge,
    /// A non-negative observation distribution.
    Histogram,
}

/// One explicit histogram bucket and its cumulative count.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HistogramBucket {
    upper_bound: u64,
    count: u64,
}

impl HistogramBucket {
    /// Returns the inclusive upper bound for this bucket.
    #[must_use]
    pub const fn upper_bound(self) -> u64 {
        self.upper_bound
    }

    /// Returns observations at or below [`Self::upper_bound`].
    #[must_use]
    pub const fn count(self) -> u64 {
        self.count
    }
}

/// Bounded aggregate state for one histogram metric.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HistogramSnapshot {
    count: u64,
    sum: u128,
    minimum: Option<u64>,
    maximum: Option<u64>,
    buckets: Vec<HistogramBucket>,
    overflow_count: u64,
}

impl HistogramSnapshot {
    /// Returns the number of observations.
    #[must_use]
    pub const fn count(&self) -> u64 {
        self.count
    }

    /// Returns the exact integer sum until it reaches `u128::MAX`.
    #[must_use]
    pub const fn sum(&self) -> u128 {
        self.sum
    }

    /// Returns the smallest observation, when one exists.
    #[must_use]
    pub const fn minimum(&self) -> Option<u64> {
        self.minimum
    }

    /// Returns the largest observation, when one exists.
    #[must_use]
    pub const fn maximum(&self) -> Option<u64> {
        self.maximum
    }

    /// Returns configured cumulative buckets in ascending-bound order.
    #[must_use]
    pub fn buckets(&self) -> &[HistogramBucket] {
        &self.buckets
    }

    /// Returns observations above the final configured bucket.
    #[must_use]
    pub const fn overflow_count(&self) -> u64 {
        self.overflow_count
    }
}

/// One deterministic metric snapshot.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MetricSnapshot {
    /// A counter value.
    Counter {
        /// Metric name.
        name: String,
        /// Sanitized identity labels.
        labels: MetricLabels,
        /// Current count.
        value: u64,
    },
    /// A gauge value.
    Gauge {
        /// Metric name.
        name: String,
        /// Sanitized identity labels.
        labels: MetricLabels,
        /// Current signed value.
        value: i64,
    },
    /// A histogram aggregate.
    Histogram {
        /// Metric name.
        name: String,
        /// Sanitized identity labels.
        labels: MetricLabels,
        /// Bounded aggregate state.
        snapshot: HistogramSnapshot,
    },
}

impl fmt::Debug for MetricSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MetricSnapshot")
            .field("kind", &self.kind())
            .field("name", &REDACTED)
            .field("labels", self.labels())
            .finish()
    }
}

impl MetricSnapshot {
    /// Returns the metric kind.
    #[must_use]
    pub const fn kind(&self) -> MetricKind {
        match self {
            Self::Counter { .. } => MetricKind::Counter,
            Self::Gauge { .. } => MetricKind::Gauge,
            Self::Histogram { .. } => MetricKind::Histogram,
        }
    }

    /// Returns the metric name.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Counter { name, .. }
            | Self::Gauge { name, .. }
            | Self::Histogram { name, .. } => name,
        }
    }

    /// Returns metric identity labels.
    #[must_use]
    pub fn labels(&self) -> &MetricLabels {
        match self {
            Self::Counter { labels, .. }
            | Self::Gauge { labels, .. }
            | Self::Histogram { labels, .. } => labels,
        }
    }
}

#[derive(Clone, Debug)]
enum MetricStateValue {
    Counter(u64),
    Gauge(i64),
    Histogram {
        buckets: Vec<HistogramBucket>,
        count: u64,
        sum: u128,
        minimum: Option<u64>,
        maximum: Option<u64>,
        overflow_count: u64,
    },
}

#[derive(Clone, Debug)]
struct MetricEntry {
    name: String,
    labels: MetricLabels,
    value: MetricStateValue,
}

#[derive(Debug)]
struct MetricsState {
    entries: Vec<MetricEntry>,
    total_bytes: usize,
    closed: bool,
}

/// Shared, bounded, executor-neutral metric registry.
#[derive(Clone)]
pub struct MetricsRegistry {
    state: Arc<Mutex<MetricsState>>,
    limits: MetricLimits,
    policy: RedactionPolicy,
}

impl fmt::Debug for MetricsRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MetricsRegistry")
            .field("limits", &self.limits)
            .field("metric_count", &self.len())
            .field("closed", &self.is_closed())
            .finish()
    }
}

/// Alias emphasizing that the registry is an in-process metrics sink.
pub type Metrics = MetricsRegistry;

impl MetricsRegistry {
    /// Creates a registry with explicit bounds and central redaction policy.
    #[must_use]
    pub fn with_limits_and_policy(limits: MetricLimits, policy: RedactionPolicy) -> Self {
        let limits = MetricLimits::new(
            limits.max_metrics,
            limits.max_labels,
            limits.max_name_bytes,
            limits.max_label_key_bytes,
            limits.max_label_value_bytes,
            limits.max_histogram_buckets,
        )
        .with_max_bytes(limits.max_bytes);
        Self {
            state: Arc::new(Mutex::new(MetricsState {
                entries: Vec::new(),
                // A policy which cannot fit in the configured aggregate
                // budget makes the registry effectively full. Keep the
                // externally reported accounting within the declared bound;
                // entry admission still fails its byte preflight.
                total_bytes: policy.retained_bytes().min(limits.max_bytes),
                closed: false,
            })),
            limits,
            policy,
        }
    }

    /// Creates a registry with explicit bounds and default redaction.
    #[must_use]
    pub fn new(limits: MetricLimits) -> Self {
        Self::with_limits_and_policy(limits, RedactionPolicy::new())
    }

    /// Creates a registry with explicit bounds and an explicit policy.
    #[must_use]
    pub fn new_with_policy(limits: MetricLimits, policy: RedactionPolicy) -> Self {
        Self::with_limits_and_policy(limits, policy)
    }

    /// Creates a registry with default metric bounds and custom redaction.
    #[must_use]
    pub fn with_policy(policy: RedactionPolicy) -> Self {
        Self::with_limits_and_policy(MetricLimits::default(), policy)
    }

    /// Returns the retained policy without exposing configured secret values.
    #[must_use]
    pub fn redaction_policy(&self) -> &RedactionPolicy {
        &self.policy
    }

    /// Re-sanitizes retained metric identities under a new policy.
    ///
    /// The rebuild is atomic: a field, identity collision, or aggregate byte
    /// limit error leaves both the old policy and the old metric state intact.
    pub fn rebind_policy(&mut self, policy: RedactionPolicy) -> Result<(), MetricError> {
        let mut state = lock_metrics_state(&self.state);
        if state.closed {
            return Err(MetricError::Closed);
        }
        if policy == self.policy {
            return Ok(());
        }
        if Arc::strong_count(&self.state) > 1 {
            // Clones share the metric entries but carry their policy by value.
            // Updating one handle would let another handle admit identities
            // under stale redaction rules, so fail closed before rebuilding.
            return Err(MetricError::SharedPolicy);
        }
        let old_entries = state.entries.clone();

        let mut entries = Vec::with_capacity(old_entries.len());
        let mut total_bytes = policy.retained_bytes();
        for old in old_entries {
            let name = metric_name_with_policy(&policy, self.limits, &old.name)?;
            let mut labels = MetricLabels::with_limits_and_policy(self.limits, policy.clone());
            for label in &old.labels.labels {
                labels.push_with_policy(&policy, self.limits, &label.key, &label.value)?;
            }
            if entries
                .iter()
                .any(|entry: &MetricEntry| entry.name == name && entry.labels == labels)
            {
                return Err(MetricError::TypeConflict);
            }
            let entry = MetricEntry {
                name,
                labels,
                value: old.value,
            };
            total_bytes = total_bytes.saturating_add(metric_entry_byte_len(
                &entry.name,
                &entry.labels,
                &entry.value,
            ));
            entries.push(entry);
        }
        if total_bytes > self.limits.max_bytes {
            return Err(MetricError::ByteLimitExceeded {
                maximum: self.limits.max_bytes,
            });
        }
        state.entries = entries;
        state.total_bytes = total_bytes;
        self.policy = policy;
        Ok(())
    }

    /// Creates a registry with default bounds and policy.
    #[must_use]
    pub fn default_registry() -> Self {
        Self::new(MetricLimits::default())
    }

    /// Returns configured metric bounds.
    #[must_use]
    pub const fn limits(&self) -> MetricLimits {
        self.limits
    }

    /// Returns the number of distinct metric identities.
    #[must_use]
    pub fn len(&self) -> usize {
        lock_metrics_state(&self.state).entries.len()
    }

    /// Returns whether no metrics have been registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns whether the registry has been closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        lock_metrics_state(&self.state).closed
    }

    /// Returns aggregate bytes retained by metric state and its policy.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        lock_metrics_state(&self.state).total_bytes
    }

    /// Closes the registry.  Closing is terminal and idempotent.
    pub fn close(&self) {
        lock_metrics_state(&self.state).closed = true;
    }

    /// Increments a counter by one.
    pub fn increment(
        &self,
        name: impl AsRef<str>,
        labels: &MetricLabels,
    ) -> Result<(), MetricError> {
        self.add_counter(name, labels, 1)
    }

    /// Adds a checked amount to a counter.
    pub fn add_counter(
        &self,
        name: impl AsRef<str>,
        labels: &MetricLabels,
        amount: u64,
    ) -> Result<(), MetricError> {
        let name = self.metric_name(name.as_ref())?;
        let labels = self.metric_labels(labels)?;
        let mut state = lock_metrics_state(&self.state);
        if state.closed {
            return Err(MetricError::Closed);
        }
        let entry = self.entry_or_insert(&mut state, name, labels, MetricStateValue::Counter(0))?;
        match &mut entry.value {
            MetricStateValue::Counter(value) => {
                *value = value
                    .checked_add(amount)
                    .ok_or(MetricError::ValueOverflow)?;
                Ok(())
            }
            _ => Err(MetricError::TypeConflict),
        }
    }

    /// Sets a signed gauge value.
    pub fn set_gauge(
        &self,
        name: impl AsRef<str>,
        labels: &MetricLabels,
        value: i64,
    ) -> Result<(), MetricError> {
        let name = self.metric_name(name.as_ref())?;
        let labels = self.metric_labels(labels)?;
        let mut state = lock_metrics_state(&self.state);
        if state.closed {
            return Err(MetricError::Closed);
        }
        let entry =
            self.entry_or_insert(&mut state, name, labels, MetricStateValue::Gauge(value))?;
        match &mut entry.value {
            MetricStateValue::Gauge(current) => {
                *current = value;
                Ok(())
            }
            _ => Err(MetricError::TypeConflict),
        }
    }

    /// Adds a signed delta to a gauge without overflowing.
    pub fn add_gauge(
        &self,
        name: impl AsRef<str>,
        labels: &MetricLabels,
        delta: i64,
    ) -> Result<(), MetricError> {
        let name = self.metric_name(name.as_ref())?;
        let labels = self.metric_labels(labels)?;
        let mut state = lock_metrics_state(&self.state);
        if state.closed {
            return Err(MetricError::Closed);
        }
        let entry = self.entry_or_insert(&mut state, name, labels, MetricStateValue::Gauge(0))?;
        match &mut entry.value {
            MetricStateValue::Gauge(value) => {
                *value = value.checked_add(delta).ok_or(MetricError::ValueOverflow)?;
                Ok(())
            }
            _ => Err(MetricError::TypeConflict),
        }
    }

    /// Records one non-negative histogram observation.
    ///
    /// The first observation registers the explicit bucket boundaries. Later
    /// observations must provide the same boundaries, which prevents a
    /// metric identity from silently changing its meaning.
    pub fn observe(
        &self,
        name: impl AsRef<str>,
        labels: &MetricLabels,
        value: u64,
        buckets: &[u64],
    ) -> Result<(), MetricError> {
        self.validate_buckets(buckets)?;
        let name = self.metric_name(name.as_ref())?;
        let labels = self.metric_labels(labels)?;
        let mut state = lock_metrics_state(&self.state);
        if state.closed {
            return Err(MetricError::Closed);
        }
        let initial_buckets = buckets
            .iter()
            .copied()
            .map(|upper_bound| HistogramBucket {
                upper_bound,
                count: 0,
            })
            .collect();
        let entry = self.entry_or_insert(
            &mut state,
            name,
            labels,
            MetricStateValue::Histogram {
                buckets: initial_buckets,
                count: 0,
                sum: 0,
                minimum: None,
                maximum: None,
                overflow_count: 0,
            },
        )?;
        let MetricStateValue::Histogram {
            buckets: current_buckets,
            count,
            sum,
            minimum,
            maximum,
            overflow_count,
        } = &mut entry.value
        else {
            return Err(MetricError::TypeConflict);
        };
        if current_buckets
            .iter()
            .map(|bucket| bucket.upper_bound)
            .ne(buckets.iter().copied())
        {
            return Err(MetricError::TypeConflict);
        }
        // Preflight every fallible accumulator before mutating any of them;
        // an overflow must not leave a partially updated histogram.
        let next_count = (*count).checked_add(1).ok_or(MetricError::ValueOverflow)?;
        let next_sum = (*sum)
            .checked_add(u128::from(value))
            .ok_or(MetricError::ValueOverflow)?;
        let bucket_index = current_buckets
            .iter()
            .position(|bucket| value <= bucket.upper_bound);
        let next_bucket_count = if let Some(index) = bucket_index {
            Some((
                index,
                current_buckets[index]
                    .count
                    .checked_add(1)
                    .ok_or(MetricError::ValueOverflow)?,
            ))
        } else {
            None
        };
        let next_overflow_count = if bucket_index.is_none() {
            Some(
                (*overflow_count)
                    .checked_add(1)
                    .ok_or(MetricError::ValueOverflow)?,
            )
        } else {
            None
        };
        *count = next_count;
        *sum = next_sum;
        *minimum = Some(minimum.map_or(value, |current| current.min(value)));
        *maximum = Some(maximum.map_or(value, |current| current.max(value)));
        if let Some((index, next_bucket_count)) = next_bucket_count {
            current_buckets[index].count = next_bucket_count;
        } else if let Some(next_overflow_count) = next_overflow_count {
            *overflow_count = next_overflow_count;
        }
        Ok(())
    }

    /// Returns all metrics in deterministic name/label/kind order.
    #[must_use]
    pub fn snapshot(&self) -> Vec<MetricSnapshot> {
        let state = lock_metrics_state(&self.state);
        let mut snapshots = state
            .entries
            .iter()
            .map(metric_snapshot)
            .collect::<Vec<_>>();
        snapshots.sort_by(|left, right| {
            left.name()
                .cmp(right.name())
                .then_with(|| left.labels().cmp(right.labels()))
                .then_with(|| left.kind().cmp(&right.kind()))
        });
        snapshots
    }

    fn metric_name(&self, name: &str) -> Result<String, MetricError> {
        metric_name_with_policy(&self.policy, self.limits, name)
    }

    fn metric_labels(&self, labels: &MetricLabels) -> Result<MetricLabels, MetricError> {
        if labels.len() > self.limits.max_labels {
            return Err(MetricError::LabelLimitExceeded {
                maximum: self.limits.max_labels,
            });
        }
        let mut sanitized = MetricLabels::with_limits_and_policy(self.limits, self.policy.clone());
        for label in &labels.labels {
            sanitized.push_with_policy(&self.policy, self.limits, &label.key, &label.value)?;
        }
        Ok(sanitized)
    }

    fn validate_buckets(&self, buckets: &[u64]) -> Result<(), MetricError> {
        if buckets.len() > self.limits.max_histogram_buckets {
            return Err(MetricError::HistogramBucketLimitExceeded {
                maximum: self.limits.max_histogram_buckets,
            });
        }
        if buckets.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(MetricError::InvalidHistogramBounds);
        }
        Ok(())
    }

    fn entry_or_insert<'a>(
        &self,
        state: &'a mut MetricsState,
        name: String,
        labels: MetricLabels,
        initial: MetricStateValue,
    ) -> Result<&'a mut MetricEntry, MetricError> {
        if let Some(index) = state
            .entries
            .iter()
            .position(|entry| entry.name == name && entry.labels == labels)
        {
            return Ok(&mut state.entries[index]);
        }
        if state.entries.len() >= self.limits.max_metrics {
            return Err(MetricError::MetricLimitExceeded {
                maximum: self.limits.max_metrics,
            });
        }
        let entry_bytes = metric_entry_byte_len(&name, &labels, &initial);
        if state.total_bytes.saturating_add(entry_bytes) > self.limits.max_bytes {
            return Err(MetricError::ByteLimitExceeded {
                maximum: self.limits.max_bytes,
            });
        }
        state.entries.push(MetricEntry {
            name,
            labels,
            value: initial,
        });
        state.total_bytes = state.total_bytes.saturating_add(entry_bytes);
        let index = state.entries.len().saturating_sub(1);
        Ok(&mut state.entries[index])
    }
}

fn metric_name_with_policy(
    policy: &RedactionPolicy,
    limits: MetricLimits,
    name: &str,
) -> Result<String, MetricError> {
    if name.is_empty() {
        return Err(MetricError::EmptyName);
    }
    let maximum = limits.max_name_bytes.min(policy.limits.max_key_bytes);
    if name.len() > maximum {
        return Err(MetricError::NameTooLong {
            actual: name.len(),
            maximum,
        });
    }
    if !valid_metric_name(name) {
        return Err(MetricError::InvalidName);
    }
    let name = policy
        .redact_value_for_key_with_maximum("", name, maximum)
        .0;
    if !valid_metric_name(&name) {
        return Err(MetricError::InvalidName);
    }
    Ok(truncate_text(&name, maximum).0)
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::default_registry()
    }
}

fn lock_metrics_state(state: &Mutex<MetricsState>) -> std::sync::MutexGuard<'_, MetricsState> {
    match state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn metric_entry_byte_len(name: &str, labels: &MetricLabels, value: &MetricStateValue) -> usize {
    let value_bytes = match value {
        MetricStateValue::Counter(_) => core::mem::size_of::<u64>(),
        MetricStateValue::Gauge(_) => core::mem::size_of::<i64>(),
        MetricStateValue::Histogram { buckets, .. } => buckets
            .len()
            .saturating_mul(core::mem::size_of::<HistogramBucket>())
            .saturating_add(5 * core::mem::size_of::<u64>())
            .saturating_add(core::mem::size_of::<u128>()),
    };
    name.len()
        .saturating_add(metric_labels_byte_len(labels))
        .saturating_add(value_bytes)
}

fn metric_labels_byte_len(labels: &MetricLabels) -> usize {
    labels
        .labels
        .iter()
        .fold(0_usize, |total, label| {
            total
                .saturating_add(label.key.len())
                .saturating_add(label.value.len())
        })
        .saturating_add(labels.policy.retained_bytes())
}

fn metric_snapshot(entry: &MetricEntry) -> MetricSnapshot {
    match &entry.value {
        MetricStateValue::Counter(value) => MetricSnapshot::Counter {
            name: entry.name.clone(),
            labels: entry.labels.clone(),
            value: *value,
        },
        MetricStateValue::Gauge(value) => MetricSnapshot::Gauge {
            name: entry.name.clone(),
            labels: entry.labels.clone(),
            value: *value,
        },
        MetricStateValue::Histogram {
            buckets,
            count,
            sum,
            minimum,
            maximum,
            overflow_count,
        } => MetricSnapshot::Histogram {
            name: entry.name.clone(),
            labels: entry.labels.clone(),
            snapshot: HistogramSnapshot {
                count: *count,
                sum: *sum,
                minimum: *minimum,
                maximum: *maximum,
                buckets: buckets.clone(),
                overflow_count: *overflow_count,
            },
        },
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "deterministic observability tests use assertions for setup"
)]
mod tests {
    use super::*;

    fn event(policy: RedactionPolicy, key: &str, value: &str) -> DiagnosticEvent {
        let identity = format!("{key}\0{value}");
        let sequence = SequenceId::new(stable_digest(identity.as_bytes()).max(1));
        let timestamp = Timestamp::new(sequence.get(), sequence.get() as i64);
        DiagnosticEvent::builder("sample", Severity::Info, DiagnosticCategory::Sampler)
            .with_policy(policy)
            .with_timestamp(timestamp)
            .with_sequence(sequence)
            .field(key, value)
            .build()
            .expect("event should build")
    }

    #[test]
    fn secret_debug_and_display_never_reveal_value() {
        let secret = Secret::new("top-secret-value");
        assert_eq!(secret.to_string(), REDACTED);
        assert_eq!(format!("{secret:?}"), REDACTED);
        assert_eq!(
            RedactionError::EmptySecret.code(),
            "observe.redaction.empty-secret"
        );
        assert_eq!(
            RedactionError::SecretTooLong {
                actual: 2,
                maximum: 1
            }
            .code(),
            "observe.redaction.secret-too-long"
        );
        let policy = RedactionPolicy::new().with_secret(secret.clone());
        assert_eq!(policy.secret_count(), 1);
        assert!(!format!("{policy:?}").contains("top-secret-value"));
    }

    #[test]
    fn redaction_marker_overlap_has_explicit_sentinel_semantics() {
        let mut policy = RedactionPolicy::new();
        policy
            .try_add_secret("REDACTED")
            .expect("marker-overlapping secret is documented compatibility behavior");
        let policy = policy.with_secret(REDACTED);
        assert_eq!(policy.secret_count(), 2);
        assert_eq!(
            policy.redact("message", "prefix REDACTED suffix"),
            "prefix [REDACTED] suffix"
        );
        assert_eq!(policy.redact("password", "value"), REDACTED);
    }

    #[test]
    fn all_sensitive_key_spellings_and_case_are_redacted() {
        let policy = RedactionPolicy::new();
        let keys = [
            "Authorization",
            "authorization",
            "PROXY-AUTHORIZATION",
            "proxy_authorization",
            "ProxyPassword",
            "proxy_password",
            "Cookie",
            "set-cookie",
            "cookies",
            "X-API-Key",
            "api_key",
            "X-Auth-Token",
            "ApiToken",
            "access-token",
            "refresh_token",
            "password",
            "PASSWORD",
            "dbPassword",
            "db_password",
            "passphrase",
            "client_secret",
            "request_body",
            "request_body_text",
            "response_body_bytes",
            "raw_body_hex",
            "response-body",
            "body",
            "body2",
            "payload",
        ];
        for key in keys {
            let field = policy.field(key, "value-secret");
            assert_eq!(field.value(), REDACTED, "{key} was not redacted");
        }
        for key in ["HTTPAuthorization", "X-Goog-Api-Key", "X-Encryption-Key"] {
            assert_eq!(policy.field(key, "value-secret").value(), REDACTED, "{key}");
        }
    }

    #[test]
    fn sensitive_matching_uses_field_tokens_not_arbitrary_substrings() {
        let policy = RedactionPolicy::new();
        assert_eq!(policy.redact("notauthorization", "ordinary"), "ordinary");
        assert_eq!(policy.redact("tokenizer", "ordinary"), "ordinary");
        assert_eq!(policy.redact("safe_passwordish", "ordinary"), "ordinary");
        assert_eq!(policy.redact("authorization", "ordinary"), REDACTED);
    }

    #[test]
    fn url_userinfo_and_sensitive_query_values_are_redacted() {
        let policy = RedactionPolicy::new();
        let field = policy.field(
            "url",
            "https://alice:pw@example.test/path?password=query-pw&safe=visible&api_key=abc#frag",
        );
        assert!(!field.value().contains("alice:pw"));
        assert!(!field.value().contains("query-pw"));
        assert!(!field.value().contains("abc"));
        assert!(field.value().contains("safe=visible"));
        assert!(field.value().contains("[REDACTED]"));
    }

    #[test]
    fn relative_uri_values_are_structurally_redacted_without_aliases() {
        let policy = RedactionPolicy::new();
        for (key, value) in [
            (
                "request_uri",
                "/path?token=hidden&safe=visible#state?password=hidden",
            ),
            ("message", "relative/path?token=hidden"),
        ] {
            let field = policy.field(key, value);
            assert!(!field.value().contains("hidden"), "{key}");
            assert!(field.value().contains("[REDACTED]"), "{key}");
        }
        let oversized = format!(
            "{}?token=hidden",
            "x".repeat(HARD_MAX_SCAN_BYTES.saturating_add(1))
        );
        assert_eq!(policy.field("message", &oversized).value(), REDACTED);
    }

    #[test]
    fn percent_encoded_query_keys_and_header_values_are_redacted() {
        let policy = RedactionPolicy::new();
        let url = policy.field(
            "request_url",
            "https://example.test/?%70%61%73%73%77%6f%72%64=hidden",
        );
        assert!(!url.value().contains("hidden"));
        let headers = policy.field(
            "request_headers",
            "Authorization: Bearer hidden\nX-Trace: visible",
        );
        assert!(!headers.value().contains("Bearer hidden"));
        assert!(headers.value().contains("X-Trace: visible"));

        let encoded_url_key = policy.field("%75%72%6c", "/path?password=hidden");
        assert!(!encoded_url_key.value().contains("hidden"));
        let encoded_header_key = policy.field(
            "%72%65%71%75%65%73%74%5f%68%65%61%64%65%72%73",
            "Authorization: hidden",
        );
        assert!(!encoded_header_key.value().contains("hidden"));
    }

    #[test]
    fn folded_sensitive_header_continuations_are_redacted() {
        let policy = RedactionPolicy::new();
        let headers = policy.field(
            "request_headers",
            "Authorization: Bearer hidden\n\tcontinued: hidden\nX-Trace: visible",
        );
        assert!(!headers.value().contains("hidden"));
        assert!(headers.value().contains("X-Trace: visible"));

        let malformed = policy.field("request_headers", "Authorization Bearer hidden");
        assert!(!malformed.value().contains("hidden"));
        let malformed_separator = policy.field("request_headers", "Authorization=hidden");
        assert!(!malformed_separator.value().contains("hidden"));
        let empty_name = policy.field("request_headers", ": hidden");
        assert!(!empty_name.value().contains("hidden"));
        let folded = policy.field("request_headers", "X-Trace: visible\n\tcontinued: safe");
        assert!(!folded.value().contains('\t'));
    }

    #[test]
    fn unicode_and_control_keys_fail_closed() {
        let policy = RedactionPolicy::new();
        for key in ["passаword", "authorization\u{0}", "safe\r\nInjected"] {
            let field = policy.field(key, "hidden");
            assert_eq!(field.value(), REDACTED);
            assert_eq!(field.key(), REDACTED);
        }
        let encoded_unicode = policy.field("pass%C3%A4word", "hidden");
        assert_eq!(encoded_unicode.key(), REDACTED);
        assert_eq!(encoded_unicode.value(), REDACTED);
        let encoded_control = policy.field("safe%0AInjected", "hidden");
        assert_eq!(encoded_control.key(), REDACTED);
        assert_eq!(encoded_control.value(), REDACTED);
        assert_eq!(policy.field("%61uthorization", "hidden").value(), REDACTED);
    }

    #[test]
    fn prebuild_and_record_formatters_never_reveal_raw_metadata() {
        let secret = "formatter-secret";
        let category = DiagnosticCategory::Custom(CustomCategory::new(secret));
        let code = StableErrorCode::new(format!("code-{secret}"));
        let builder =
            DiagnosticEvent::builder(format!("event-{secret}"), Severity::Error, category.clone())
                .with_error_code(code.clone())
                .field("message", secret);
        assert!(!format!("{builder:?}").contains(secret));
        assert!(!builder.to_string().contains(secret));
        let event = builder.build().expect("event should build");
        assert!(!format!("{event:?}").contains(secret));
        assert!(!event.to_string().contains(secret));
        assert!(!format!("{category:?}").contains(secret));
        assert!(!category.to_string().contains(secret));
        assert!(!CustomCategory::new(secret).to_string().contains(secret));
        assert!(!format!("{code:?}").contains(secret));
        assert!(!code.to_string().contains(secret));

        let span_builder = DiagnosticSpan::builder(
            format!("span-{secret}"),
            Severity::Error,
            DiagnosticCategory::Observation,
        )
        .with_error_code(code)
        .with_id(SpanId::new(7));
        assert!(!format!("{span_builder:?}").contains(secret));
        assert!(!span_builder.to_string().contains(secret));
        let span = span_builder.build().expect("span should build");
        let end = span.end(SpanOutcome::Error);
        assert!(!format!("{span:?}").contains(secret));
        assert!(!span.to_string().contains(secret));
        assert!(!format!("{end:?}").contains(secret));
        assert!(!end.to_string().contains(secret));
        assert!(!DiagnosticRecord::from(end).to_string().contains(secret));
    }

    #[test]
    fn controls_are_normalized_or_redacted_in_header_and_url_structure() {
        let policy = RedactionPolicy::new();
        let headers = policy.field(
            "request_headers",
            "X-Trace: visible\r\nAuthorization: hidden\r\nX-End: ok",
        );
        assert!(!headers.value().contains('\r'));
        assert!(headers.value().contains("X-Trace: visible"));
        assert!(!headers.value().contains("hidden"));
        assert_eq!(
            policy.field("request_headers", "X: bad\u{0}").value(),
            REDACTED
        );
        assert_eq!(
            policy
                .field("url", "https://example.test/a\r\nX: bad")
                .value(),
            REDACTED
        );
        assert_eq!(
            policy.field("url", "https://example.test/a%0AX").value(),
            REDACTED
        );
    }

    #[test]
    fn configured_secrets_are_replaced_in_plain_values_and_urls() {
        let policy = RedactionPolicy::new().with_secret("configured-secret");
        for (key, value) in [
            ("message", "prefix configured-secret suffix"),
            (
                "url",
                "https://configured-secret@example.test/?q=configured-secret",
            ),
            ("request_headers", "X-Key: configured-secret"),
        ] {
            let field = policy.field(key, value);
            assert!(!field.value().contains("configured-secret"));
        }
        let encoded = policy.field("url", "https://example.test/?value=configured%2Dsecret");
        assert!(!encoded.value().contains("configured-secret"));
        let double_encoded = policy.field("message", "prefix=configured%252Dsecret");
        assert!(!double_encoded.value().contains("configured-secret"));
    }

    #[test]
    fn truncation_is_bounded_after_redaction_and_secret_is_not_reintroduced() {
        let limits = RedactionLimits::new(4, 8, 8);
        let policy = RedactionPolicy::with_limits(limits).with_secret("very-long-secret");
        let sensitive = policy.field("password", "very-long-secret-with-tail");
        assert!(sensitive.value().len() <= 8);
        assert!(!sensitive.value().contains("very-long-secret"));
        assert!(sensitive.is_truncated());
        let ordinary = policy.field("message", "prefix very-long-secret suffix");
        assert!(ordinary.value().len() <= 8);
        assert!(!ordinary.value().contains("very-long-secret"));
    }

    #[test]
    fn structural_redaction_reports_truncation_after_early_bound() {
        let policy = RedactionPolicy::with_limits(RedactionLimits::new(4, 32, 12));
        let field = policy.field("request_headers", "X-Long: 1234567890\nY: tail");
        assert!(field.is_truncated());

        let exact = RedactionPolicy::with_limits(RedactionLimits::new(4, 32, 9))
            .field("request_headers", "X: value");
        assert!(!exact.is_truncated());
    }

    #[test]
    fn url_redaction_preserves_single_query_and_fragment_delimiters() {
        let policy = RedactionPolicy::new();
        let field = policy.field(
            "url",
            "https://example.test/path?password=hidden&safe=visible#state?token=hidden",
        );
        assert!(!field.value().contains("??"));
        assert!(!field.value().contains("##"));
        assert!(field.value().contains("?password="));
        assert!(field.value().contains("#state?token="));
    }

    #[test]
    fn configured_secrets_are_detected_in_encoded_url_components_and_beyond_value_bound() {
        let policy =
            RedactionPolicy::with_limits(RedactionLimits::new(4, 64, 64)).with_secret("päss");
        let path = policy.field("url", "https://example.test/path/p%C3%A4ss?safe=visible");
        assert!(!path.value().contains("p%C3%A4ss"));
        assert!(path.value().contains("safe=visible"));

        let first_segment = policy.field("url", "https://example.test/p%C3%A4ss/rest");
        assert!(!first_segment.value().contains("p%C3%A4ss"));
        assert!(!first_segment.value().contains("päss"));

        let fragment = policy.field("url", "https://example.test/#state/p%C3%A4ss");
        assert!(!fragment.value().contains("p%C3%A4ss"));

        let authority = policy.field("url", "https://example.%70%C3%A4ss.test/path");
        assert!(!authority.value().contains("%70%C3%A4ss"));

        let encoded_userinfo = policy.field("url", "https://alice%3Asecret%40example.test/path");
        assert!(!encoded_userinfo.value().contains("%40"));

        let key = policy.field("url", "https://example.test/?p%C3%A4ss=safe");
        assert!(!key.value().contains("p%C3%A4ss"));

        let long_value = format!("https://example.test/?value={}p%C3%A4ss", "x".repeat(2_000));
        let bounded = policy.field("url", &long_value);
        assert!(!bounded.value().contains("p%C3%A4ss"));
        assert!(bounded.value().len() <= 64);
    }

    #[test]
    fn configured_secrets_in_opaque_query_segments_are_redacted() {
        let policy = RedactionPolicy::new().with_secret("päss");
        let field = policy.field("url", "https://example.test/?state/p%C3%A4ss");
        assert!(!field.value().contains("%C3%A4ss"));

        let malformed_sensitive = policy.field("url", "https://example.test/?authorization:hidden");
        assert!(!malformed_sensitive.value().contains("hidden"));
    }

    #[test]
    fn configured_secrets_are_replaced_before_a_value_bound() {
        let policy = RedactionPolicy::with_limits(RedactionLimits::new(4, 64, 14))
            .with_secret("secret-value");
        let plain = policy.field("message", "prefixsecret-value-tail");
        assert!(!plain.value().contains("secret-value"));
        assert!(!plain.value().contains("secret"));

        let url = policy.field(
            "url",
            "https://example.test/prefixsecret-value-tail?safe=visible",
        );
        assert!(!url.value().contains("secret-value"));
        assert!(!url.value().contains("secret"));
    }

    #[test]
    fn oversized_query_keys_fail_closed_and_decode_scan_catches_boundary_secrets() {
        let policy = RedactionPolicy::new().with_secret("päss");
        let oversized_key = format!("{}token", "x".repeat(HARD_MAX_KEY_BYTES));
        let url = policy.field(
            "url",
            &format!("https://example.test/?{oversized_key}=visible"),
        );
        assert!(!url.value().contains("token"));
        assert!(policy.contains_percent_encoded_secret_with_limit("p%C3%A4ss", 2));
    }

    #[test]
    fn field_count_limit_is_explicit() {
        let policy = RedactionPolicy::with_limits(RedactionLimits::new(1, 32, 32));
        let result =
            DiagnosticEvent::builder("event", Severity::Info, DiagnosticCategory::Observation)
                .with_policy(policy)
                .try_field("one", "1")
                .expect("first field")
                .try_field("two", "2");
        assert!(matches!(
            result,
            Err(ObserveError::FieldLimitExceeded { maximum: 1 })
        ));
    }

    #[test]
    fn arbitrary_strings_are_bounded_without_panics() {
        let policy = RedactionPolicy::new();
        let values = [
            "",
            "?&&;=",
            "https:///%%@?#",
            "\u{0}\u{1f600}\n",
            "Authorization: \u{0}\nnot-a-header",
            &"x".repeat(100_000),
        ];
        for value in values {
            let field = policy.field("url", value);
            assert!(field.key().len() <= DEFAULT_MAX_KEY_BYTES);
            assert!(field.value().len() <= DEFAULT_MAX_VALUE_BYTES);
        }
    }

    #[test]
    fn deterministic_adversarial_corpus_preserves_redaction_invariants() {
        let policy = RedactionPolicy::with_limits(RedactionLimits::new(8, 48, 96))
            .with_secret("corpus-secret");
        let fragments = [
            "safe",
            "%",
            "%41",
            "?token=corpus-secret",
            "#state=corpus-secret",
            "Authorization: corpus-secret",
            "\r",
            "\n",
            "\t",
            "\u{0}",
            "päss",
            "&;=",
        ];
        for seed in 0_u64..128 {
            let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15);
            let mut value = String::new();
            let count = (seed as usize % 48).saturating_add(1);
            for _ in 0..count {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                value.push_str(fragments[(state as usize) % fragments.len()]);
            }
            let key = if seed % 2 == 0 {
                "request_url"
            } else {
                "request_headers"
            };
            let field = policy.field(key, &value);
            assert!(field.key().len() <= 48);
            assert!(field.value().len() <= 96);
            assert!(!field.value().contains("corpus-secret"));
            assert_eq!(field.value(), policy.redact(key, &value));
        }
    }

    #[test]
    fn adversarial_boundaries_are_fail_closed_and_deterministic() {
        let policy = RedactionPolicy::with_limits(RedactionLimits::new(8, 32, 32))
            .with_secret("needle-secret");
        for length in [0, 1, 31, 32, 33, 1_024, HARD_MAX_SCAN_BYTES + 1] {
            let mut value = "x".repeat(length);
            if length > 16 {
                value.replace_range(length - 13.., "needle-secret");
            }
            let field = policy.field("request_url", &value);
            assert!(field.value().len() <= 32);
            assert!(!field.value().contains("needle-secret"));
            if length > HARD_MAX_SCAN_BYTES {
                assert!(field.is_truncated());
            }
            assert_eq!(field.value(), policy.redact("request_url", &value));
        }
        let giant_key = format!("safe-{}-needle-secret", "k".repeat(HARD_MAX_KEY_BYTES));
        let field = policy.field(&giant_key, "value");
        assert_eq!(field.key(), REDACTED);
        assert_eq!(field.value(), REDACTED);
    }

    #[test]
    fn hostile_key_scanning_is_bounded() {
        let policy = RedactionPolicy::new();
        let key = "x".repeat(2 * HARD_MAX_KEY_BYTES);
        let field = policy.field(&key, "value");
        assert!(field.key().len() <= DEFAULT_MAX_KEY_BYTES);
        assert!(field.value().len() <= DEFAULT_MAX_VALUE_BYTES);

        let encoded_key = format!("%{}", "41".repeat(HARD_MAX_KEY_BYTES));
        let field = policy.field(&encoded_key, "value");
        assert_eq!(field.key(), REDACTED);
        assert_eq!(field.value(), REDACTED);
    }

    #[test]
    fn configured_limits_have_absolute_safety_ceilings() {
        let policy =
            RedactionPolicy::with_limits(RedactionLimits::new(usize::MAX, usize::MAX, usize::MAX));
        assert_eq!(policy.limits().max_fields, HARD_MAX_FIELDS);
        assert_eq!(policy.limits().max_key_bytes, HARD_MAX_KEY_BYTES);
        assert_eq!(policy.limits().max_value_bytes, HARD_MAX_VALUE_BYTES);
        let sink = InMemorySink::new(SinkLimits::new(usize::MAX, usize::MAX));
        assert!(sink.limits().max_records < usize::MAX);
        assert!(sink.limits().max_bytes < usize::MAX);
        let tiny_sink = InMemorySink::with_limits_and_policy(
            SinkLimits::new(1, 1),
            RedactionPolicy::new().with_secret("policy-bytes"),
        );
        assert!(tiny_sink.total_bytes() <= tiny_sink.limits().max_bytes);
    }

    #[test]
    fn correlation_propagates_from_span_to_child_and_event() {
        let context = CorrelationContext::new()
            .with_run_id("run-1")
            .with_plan_id("plan-1")
            .with_plan_hash("sha256:plan-1")
            .with_profile_id("jmeter-5.6.3")
            .with_thread_group_id("group-1")
            .with_user_id("user-1")
            .with_sample_id("sample-1")
            .with_parent_sample_id("parent-1")
            .with_controller_path("0/1")
            .with_plugin_id("plugin-1")
            .with_connection_id("connection-1")
            .with_iteration(7);
        let span = DiagnosticSpan::builder("sampler", Severity::Info, DiagnosticCategory::Sampler)
            .with_id(SpanId::new(9))
            .with_correlation(context.clone())
            .build()
            .expect("span should build");
        let child = span
            .child("assertion", Severity::Debug, DiagnosticCategory::Assertion)
            .build()
            .expect("child should build");
        let event = span
            .event("sample.end", Severity::Info, DiagnosticCategory::Sampler)
            .build()
            .expect("event should build");
        assert_eq!(child.parent_id(), Some(SpanId::new(9)));
        assert_eq!(child.correlation(), &context);
        assert_eq!(event.correlation(), &context);
    }

    #[test]
    fn sink_full_and_closed_behavior_is_explicit_and_deterministic() {
        let sink = InMemorySink::with_limits_and_policy(
            SinkLimits::new(1, usize::MAX),
            RedactionPolicy::new(),
        );
        sink.event(event(RedactionPolicy::new(), "message", "one"))
            .expect("first event fits");
        assert!(matches!(
            sink.event(event(RedactionPolicy::new(), "message", "two")),
            Err(SinkError::Full { .. })
        ));
        assert_eq!(sink.len(), 1);
        sink.close().expect("sink should close");
        assert!(matches!(
            sink.event(event(RedactionPolicy::new(), "message", "three")),
            Err(SinkError::Closed)
        ));
    }

    #[test]
    fn sink_applies_its_policy_to_records_and_keeps_order() {
        let sink = InMemorySink::with_policy(RedactionPolicy::new().with_secret("sink-secret"));
        let first =
            DiagnosticEvent::builder("first", Severity::Info, DiagnosticCategory::Observation)
                .with_timestamp(Timestamp::new(1, 1))
                .with_sequence(SequenceId::new(1))
                .field("message", "sink-secret")
                .build()
                .expect("first event should build");
        let second =
            DiagnosticEvent::builder("second", Severity::Info, DiagnosticCategory::Observation)
                .with_timestamp(Timestamp::new(2, 2))
                .with_sequence(SequenceId::new(2))
                .field("message", "safe")
                .build()
                .expect("second event should build");
        sink.event(first).expect("first event fits");
        sink.event(second).expect("second event fits");
        let events = sink.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].fields()[0].value(), REDACTED);
        assert_eq!(events[1].fields()[0].value(), "safe");
    }

    #[test]
    fn span_start_and_end_are_sink_records() {
        let sink = InMemorySink::new(SinkLimits::new(3, usize::MAX));
        let span = DiagnosticSpan::new("run", Severity::Info, DiagnosticCategory::Observation)
            .with_id(SpanId::new(1))
            .with_timestamp(Timestamp::new(1, 1))
            .with_sequence(SequenceId::new(1));
        sink.span_start(span.clone()).expect("span start fits");
        sink.span_end(
            span.end_at(
                SpanOutcome::Complete,
                Timestamp::new(2, 2),
                SequenceId::new(2),
            )
            .expect("span end timing"),
        )
        .expect("span end fits");
        assert_eq!(sink.spans().len(), 1);
        assert_eq!(sink.records().len(), 2);
    }

    #[test]
    fn url_fragment_and_percent_encoded_utf8_secrets_are_redacted() {
        let policy = RedactionPolicy::new().with_secret("päss");
        let url = policy.field(
            "url",
            "https://example.test/#state?token=p%C3%A4ss&safe=visible",
        );
        assert!(!url.value().contains("p%C3%A4ss"));
        assert!(!url.value().contains("päss"));
        assert!(url.value().contains("safe=visible"));
    }

    #[test]
    fn truncated_secret_is_never_registered_by_builder_api() {
        let secret = Secret::new("s".repeat(MAX_SECRET_BYTES + 1));
        assert!(secret.was_truncated());
        let policy = RedactionPolicy::new().with_secret(secret);
        assert_eq!(policy.secret_count(), 0);
    }

    #[test]
    fn sink_redacts_secret_like_metadata_and_correlation() {
        let policy = RedactionPolicy::new().with_secret("run-secret");
        let correlation = CorrelationContext::new()
            .with_run_id("run-secret")
            .with_controller_path("controller-safe");
        let event = DiagnosticEvent::builder(
            "event-run-secret",
            Severity::Info,
            DiagnosticCategory::Custom(CustomCategory::new("category-run-secret")),
        )
        .with_correlation(correlation)
        .with_error_code("error-run-secret")
        .with_retryability(Retryability::Terminal)
        .with_timestamp(Timestamp::new(1, 1))
        .with_sequence(SequenceId::new(1))
        .build()
        .expect("event should build");
        let sink = InMemorySink::with_policy(policy);
        sink.event(event).expect("event should fit");
        let stored = &sink.events()[0];
        assert!(!stored.name().contains("run-secret"));
        assert!(!stored.category().as_str().contains("run-secret"));
        assert!(
            !stored
                .error_code()
                .expect("error code")
                .as_str()
                .contains("run-secret")
        );
        assert!(
            !stored
                .correlation()
                .run_id()
                .expect("run ID")
                .as_str()
                .contains("run-secret")
        );
        assert_eq!(stored.retryability(), Some(Retryability::Terminal));
    }

    #[test]
    fn builders_redact_metadata_and_correlation_before_returning_records() {
        let policy = RedactionPolicy::new().with_secret("builder-secret");
        let event = DiagnosticEvent::builder(
            "event-builder-secret",
            Severity::Info,
            DiagnosticCategory::Custom(CustomCategory::new("category-builder-secret")),
        )
        .with_policy(policy.clone())
        .with_error_code("error-builder-secret")
        .with_correlation(CorrelationContext::new().with_run_id("builder-secret"))
        .build()
        .expect("event should build");
        assert!(!event.name().contains("builder-secret"));
        assert!(!event.category().as_str().contains("builder-secret"));
        assert!(
            !event
                .error_code()
                .expect("error code")
                .as_str()
                .contains("builder-secret")
        );
        assert!(
            !event
                .correlation()
                .run_id()
                .expect("run ID")
                .as_str()
                .contains("builder-secret")
        );

        let span = DiagnosticSpan::builder(
            "span-builder-secret",
            Severity::Info,
            DiagnosticCategory::Observation,
        )
        .with_policy(policy)
        .with_correlation(CorrelationContext::new().with_run_id("builder-secret"))
        .build()
        .expect("span should build");
        assert!(!span.name().contains("builder-secret"));
        assert!(
            !span
                .correlation()
                .run_id()
                .expect("run ID")
                .as_str()
                .contains("builder-secret")
        );
    }

    #[test]
    fn metadata_constructor_does_not_retain_secret_prefix_at_bound() {
        let secret = "metadata-secret";
        let raw_name = format!("{}{}", "x".repeat(DEFAULT_MAX_KEY_BYTES - 4), secret);
        let policy = RedactionPolicy::new().with_secret(secret);
        let event = DiagnosticEvent::builder(
            raw_name.clone(),
            Severity::Info,
            DiagnosticCategory::Observation,
        )
        .with_policy(policy.clone())
        .with_error_code(raw_name.clone())
        .build()
        .expect("event should build");
        assert_eq!(event.name(), REDACTED);
        assert_eq!(event.error_code().expect("error code").as_str(), REDACTED);

        let span = DiagnosticSpan::builder(raw_name, Severity::Info, DiagnosticCategory::Sampler)
            .with_policy(policy)
            .build()
            .expect("span should build");
        assert_eq!(span.name(), REDACTED);
    }

    #[test]
    fn sink_rejects_records_over_its_field_bound_without_dropping_fields() {
        let policy = RedactionPolicy::with_limits(RedactionLimits::new(1, 32, 32));
        let event = DiagnosticEvent::new("event", Severity::Info, DiagnosticCategory::Observation)
            .with_error_code("observe.test");
        let mut event = event;
        event.add_field("one", "1").expect("first field");
        event.add_field("two", "2").expect("second field");
        let sink = InMemorySink::with_limits_and_policy(SinkLimits::default(), policy);
        assert_eq!(
            sink.event(event),
            Err(SinkError::RecordFieldLimitExceeded { maximum: 1 })
        );
        assert!(sink.is_empty());
    }

    #[test]
    fn metric_labels_are_sorted_redacted_and_duplicate_checked() {
        let mut labels = MetricLabels::new();
        labels.push("z", "last").expect("label fits");
        labels
            .push("authorization", "Bearer secret")
            .expect("label fits");
        assert_eq!(labels.as_slice()[0].key(), "authorization");
        assert_eq!(labels.get("authorization"), Some(REDACTED));
        assert_eq!(
            labels.push("z", "duplicate"),
            Err(MetricError::DuplicateLabel)
        );
    }

    #[test]
    fn metrics_are_bounded_typed_and_deterministic() {
        let limits = MetricLimits::new(4, 2, 32, 16, 16, 3);
        let registry = MetricsRegistry::new(limits);
        let mut labels = MetricLabels::with_limits(limits);
        labels.push("kind", "sample").expect("label fits");
        registry
            .increment("samples.started", &labels)
            .expect("counter fits");
        registry
            .add_gauge("users.active", &labels, 2)
            .expect("gauge fits");
        registry
            .observe("sample.elapsed", &labels, 5, &[10, 20])
            .expect("histogram fits");
        registry
            .observe("sample.elapsed", &labels, 25, &[10, 20])
            .expect("histogram fits");
        let snapshots = registry.snapshot();
        assert_eq!(snapshots.len(), 3);
        assert!(matches!(
            snapshots[0],
            MetricSnapshot::Histogram { .. }
                | MetricSnapshot::Counter { .. }
                | MetricSnapshot::Gauge { .. }
        ));
        let histogram = snapshots
            .iter()
            .find_map(|snapshot| match snapshot {
                MetricSnapshot::Histogram { snapshot, .. } => Some(snapshot),
                _ => None,
            })
            .expect("histogram snapshot");
        assert_eq!(histogram.count(), 2);
        assert_eq!(histogram.buckets()[0].count(), 1);
        assert_eq!(histogram.overflow_count(), 1);
        assert_eq!(registry.add_counter("samples.started", &labels, 1), Ok(()));
        assert_eq!(
            registry.observe("sample.bad", &labels, 1, &[2, 2]),
            Err(MetricError::InvalidHistogramBounds)
        );
        registry.close();
        assert_eq!(
            registry.increment("closed", &labels),
            Err(MetricError::Closed)
        );
    }

    #[test]
    fn metric_high_cardinality_labels_are_hashed() {
        let mut labels = MetricLabels::new();
        labels
            .push("user_id", "user-unique-value")
            .expect("label fits");
        let value = labels.get("user_id").expect("user label");
        assert!(value.starts_with("h:"));
        assert!(!value.contains("user-unique-value"));
    }

    #[test]
    fn metric_hashes_full_value_after_policy_bound_and_rejects_unsafe_keys() {
        let policy = RedactionPolicy::with_limits(RedactionLimits::new(4, 64, 4));
        let limits = MetricLimits::new(4, 8, 64, 64, 32, 4);
        let first = MetricLabel::with_policy(&policy, limits, "user_id", "prefix-one")
            .expect("first label");
        let second = MetricLabel::with_policy(&policy, limits, "user_id", "prefix-two")
            .expect("second label");
        assert_ne!(first.value(), second.value());
        assert!(matches!(
            MetricLabel::new("user\u{0}id", "value"),
            Err(MetricError::InvalidLabelKey)
        ));

        let mut labels = MetricLabels::new();
        labels
            .push("user_id", "already-hashed")
            .expect("hashed label");
        let hashed = labels.get("user_id").expect("hashed value").to_owned();
        let registry = MetricsRegistry::new(MetricLimits::default());
        registry
            .increment("idempotent", &labels)
            .expect("registry accepts sanitized label");
        let snapshots = registry.snapshot();
        let stored = snapshots[0].labels().get("user_id").expect("stored label");
        assert!(stored.starts_with("h:"));
        assert_ne!(stored, "already-hashed");
        assert!(hashed.starts_with("h:"));

        let secret_policy = RedactionPolicy::new().with_secret("metric-secret");
        let secret_label = MetricLabel::with_policy(
            &secret_policy,
            MetricLimits::default(),
            "request_id",
            "prefix-metric-secret-suffix",
        )
        .expect("secret label");
        assert!(!secret_label.value().contains("metric-secret"));
        assert!(secret_label.value().starts_with("h:") || secret_label.value() == REDACTED);

        let key_secret_policy = RedactionPolicy::new().with_secret("private");
        assert!(matches!(
            MetricLabel::with_policy(
                &key_secret_policy,
                MetricLimits::default(),
                "private_label",
                "safe"
            ),
            Err(MetricError::InvalidLabelKey)
        ));
    }

    #[test]
    fn metric_names_and_low_cardinality_values_are_validated() {
        let registry = MetricsRegistry::default_registry();
        let labels = MetricLabels::new();
        assert_eq!(
            registry.increment("bad name", &labels),
            Err(MetricError::InvalidName)
        );
        assert_eq!(
            registry.increment("bad\u{0}name", &labels),
            Err(MetricError::InvalidName)
        );
        let invalid_status = MetricLabel::new("status", "200 OK");
        assert!(matches!(
            invalid_status,
            Err(MetricError::InvalidLabelValue)
        ));
        let invalid_control = MetricLabel::new("status", "200\u{0}");
        assert!(matches!(
            invalid_control,
            Err(MetricError::InvalidLabelValue)
        ));
    }

    #[test]
    fn long_identifier_uses_digest_and_debug_never_reveals_raw_text() {
        let first = "prefix-".to_owned() + &"a".repeat(MAX_IDENTIFIER_BYTES);
        let second = "prefix-".to_owned() + &"b".repeat(MAX_IDENTIFIER_BYTES);
        let first_id = RunId::new(&first);
        let second_id = RunId::new(&second);
        assert_ne!(first_id, second_id);
        assert!(first_id.was_truncated(&first));
        assert!(!format!("{first_id:?}").contains('a'));
        assert!(!format!("{second_id:?}").contains('b'));
        assert!(!format!("{:?}", SpanId::new(42)).contains("42"));
    }

    #[test]
    fn registry_preserves_configured_label_capacity_above_default() {
        let limits = MetricLimits::new(1, 12, 32, 16, 16, 2);
        let registry = MetricsRegistry::new(limits);
        let mut labels = MetricLabels::with_limits(limits);
        for index in 0..12 {
            labels
                .push(format!("key-{index}"), "value")
                .expect("configured label capacity");
        }
        registry
            .increment("many.labels", &labels)
            .expect("registry accepts configured label capacity");
    }

    #[test]
    fn metrics_reject_type_conflicts_and_distinct_metric_overflow() {
        let limits = MetricLimits::new(1, 1, 32, 16, 16, 2);
        let registry = MetricsRegistry::new(limits);
        let labels = MetricLabels::new();
        registry.increment("same", &labels).expect("counter fits");
        assert_eq!(
            registry.set_gauge("same", &labels, 1),
            Err(MetricError::TypeConflict)
        );
        assert_eq!(
            registry.increment("another", &labels),
            Err(MetricError::MetricLimitExceeded { maximum: 1 })
        );
    }

    #[test]
    fn nested_query_data_in_non_sensitive_headers_is_redacted() {
        let policy = RedactionPolicy::new();
        for value in [
            "https://example.test/redirect?token=header-secret&safe=visible",
            "/redirect?password=header-secret&safe=visible",
            "state?access_token=header-secret&safe=visible",
        ] {
            let field = policy.field("x-trace", value);
            assert!(!field.value().contains("header-secret"), "{value}");
            assert!(field.value().contains("safe=visible"), "{value}");
        }
    }

    #[test]
    fn explicit_clock_and_sequencer_make_span_duration_reproducible() {
        let policy = RedactionPolicy::new().with_secret("timing-secret");
        let clock = DeterministicClock::new(Timestamp::new(10, 1_000));
        let sequencer = DeterministicSequencer::new(7);
        let span = DiagnosticSpan::builder_with_policy(
            policy,
            "sample",
            Severity::Info,
            DiagnosticCategory::Sampler,
        )
        .with_id(SpanId::new(9))
        .with_capabilities(&clock, &sequencer)
        .build()
        .expect("span should build");
        clock.advance(25, 4);
        let end = span
            .end_with_capabilities(SpanOutcome::Complete, &clock, &sequencer)
            .expect("span should end");
        assert_eq!(span.started_at(), Some(Timestamp::new(10, 1_000)));
        assert_eq!(end.ended_at(), Some(Timestamp::new(35, 1_004)));
        assert_eq!(end.duration(), Duration::from_nanos(25));
        assert_eq!(span.sequence(), SequenceId::new(7));
        assert_eq!(end.sequence(), SequenceId::new(8));
        assert_eq!(
            span.end_at(
                SpanOutcome::Complete,
                Timestamp::new(9, 1_001),
                SequenceId::new(9),
            ),
            Err(ObserveError::NonMonotonicTimestamp)
        );
    }

    #[test]
    fn sink_enforces_span_lifecycle_and_duplicate_end_errors() {
        let sink = InMemorySink::with_policy(RedactionPolicy::new());
        let span = DiagnosticSpan::new("parent", Severity::Info, DiagnosticCategory::Observation)
            .with_id(SpanId::new(11))
            .with_timestamp(Timestamp::new(100, 10))
            .with_sequence(SequenceId::new(1));
        sink.span_start(span.clone()).expect("start should fit");
        assert_eq!(sink.close(), Err(SinkError::OpenSpans { count: 1 }));
        let end = span
            .end_at(
                SpanOutcome::Complete,
                Timestamp::new(125, 11),
                SequenceId::new(2),
            )
            .expect("end timing");
        sink.span_end(end.clone()).expect("end should fit");
        assert_eq!(
            sink.span_end(end.with_sequence(SequenceId::new(3))),
            Err(SinkError::SpanNotActive {
                id: SpanId::new(11)
            })
        );
        let duplicate_start = span.with_sequence(SequenceId::new(4));
        assert_eq!(
            sink.span_start(duplicate_start),
            Err(SinkError::DuplicateSpan {
                id: SpanId::new(11)
            })
        );
        assert_eq!(sink.close(), Ok(()));
    }

    #[test]
    fn sink_trait_exposes_flush_drain_backpressure_and_cancellation() {
        let sink = InMemorySink::with_policy(RedactionPolicy::new());
        let trait_sink: &dyn DiagnosticSink = &sink;
        assert_eq!(trait_sink.backpressure_policy(), BackpressurePolicy::Reject);
        trait_sink.flush().expect("flush should be immediate");
        trait_sink
            .event(event(RedactionPolicy::new(), "message", "retained"))
            .expect("event should fit");
        let drained = trait_sink.drain().expect("drain should be explicit");
        assert_eq!(drained.len(), 1);
        assert!(sink.is_empty());
        trait_sink.cancel().expect("cancel should be idempotent");
        assert_eq!(
            trait_sink.event(event(RedactionPolicy::new(), "message", "late")),
            Err(SinkError::Canceled)
        );
        assert_eq!(trait_sink.flush(), Err(SinkError::Canceled));
        assert!(
            trait_sink
                .drain()
                .expect("canceled records remain drainable")
                .is_empty()
        );
    }

    #[test]
    fn sink_lifecycle_history_is_bounded_and_never_evicts_identity_state() {
        let sink = InMemorySink::with_limits_and_policy(
            SinkLimits::new(1, usize::MAX),
            RedactionPolicy::new(),
        );
        sink.event(
            DiagnosticEvent::builder("one", Severity::Info, DiagnosticCategory::Observation)
                .with_timestamp(Timestamp::new(1, 1))
                .with_sequence(SequenceId::new(1))
                .build()
                .expect("event should build"),
        )
        .expect("first event should fit");
        sink.drain().expect("closed lifecycle has no open spans");
        assert_eq!(
            sink.event(
                DiagnosticEvent::builder("two", Severity::Info, DiagnosticCategory::Observation)
                    .with_timestamp(Timestamp::new(2, 2))
                    .with_sequence(SequenceId::new(2))
                    .build()
                    .expect("event should build"),
            ),
            Err(SinkError::LifecycleLimitExceeded { maximum: 1 })
        );
    }

    #[test]
    fn concurrent_submissions_are_returned_in_sequence_order() {
        const COUNT: u64 = 16;
        let sink = Arc::new(InMemorySink::with_policy(RedactionPolicy::new()));
        std::thread::scope(|scope| {
            for sequence in 1..=COUNT {
                let sink = Arc::clone(&sink);
                scope.spawn(move || {
                    let record = DiagnosticEvent::builder(
                        format!("event-{sequence}"),
                        Severity::Info,
                        DiagnosticCategory::Observation,
                    )
                    .with_timestamp(Timestamp::new(sequence, sequence as i64))
                    .with_sequence(SequenceId::new(sequence))
                    .build()
                    .expect("event should build");
                    sink.event(record).expect("record should fit");
                });
            }
        });
        let sequences: Vec<_> = sink
            .records()
            .iter()
            .map(DiagnosticRecord::sequence)
            .collect();
        assert_eq!(
            sequences,
            (1..=COUNT).map(SequenceId::new).collect::<Vec<_>>()
        );
    }

    #[test]
    fn retained_policy_redacts_direct_mutators_children_and_terminal_metadata() {
        let policy = RedactionPolicy::new().with_secret("direct-secret");
        let mut event = DiagnosticEvent::new_with_policy(
            policy.clone(),
            "event-direct-secret",
            Severity::Error,
            DiagnosticCategory::Observation,
        )
        .with_error_code("code-direct-secret")
        .with_correlation(
            CorrelationContext::with_policy(policy.clone()).with_run_id("direct-secret"),
        );
        event
            .add_field("message", "direct-secret")
            .expect("field should fit");
        assert!(!event.name().contains("direct-secret"));
        assert!(!event.fields()[0].value().contains("direct-secret"));
        assert!(!format!("{event:?}").contains("direct-secret"));

        let span = DiagnosticSpan::new_with_policy(
            policy,
            "span",
            Severity::Info,
            DiagnosticCategory::Observation,
        )
        .with_id(SpanId::new(1));
        let child = span
            .child("child", Severity::Debug, DiagnosticCategory::Observation)
            .field("message", "direct-secret")
            .build()
            .expect("child should build");
        assert!(!child.fields()[0].value().contains("direct-secret"));
        let end = SpanEnd::new_with_policy(
            child.redaction_policy().clone(),
            child.id(),
            SpanOutcome::Error,
        )
        .with_error_code("end-direct-secret");
        assert!(
            !end.error_code()
                .expect("error code")
                .as_str()
                .contains("direct-secret")
        );
        assert!(!format!("{end:?}").contains("direct-secret"));
    }

    #[test]
    fn expanded_sensitive_classifier_covers_numeric_suffixes() {
        let policy = RedactionPolicy::new();
        for key in [
            "session",
            "session_id",
            "session_id_2",
            "jwt",
            "jwt7",
            "signature",
            "signature_11",
            "sig",
            "sig3",
            "nonce",
            "nonce_4",
            "access_key",
            "access_key9",
            "db_jwt7",
            "db_token2",
        ] {
            assert!(
                policy.is_sensitive_key(key),
                "key should be sensitive: {key}"
            );
            assert_eq!(policy.field(key, "secret-value").value(), REDACTED);
        }
        let multiply_encoded_key = policy.field("%252574oken", "hidden");
        assert_eq!(multiply_encoded_key.value(), REDACTED);
        assert!(!policy.is_sensitive_key("not-sessionish"));
    }

    #[test]
    fn generic_text_redacts_nested_json_prose_and_encoded_urls() {
        let policy = RedactionPolicy::new().with_secret("raw-secret");
        let json = policy.field(
            "message",
            r#"prose token=raw-secret nested={"session_id":"raw-secret","safe":"ok"}"#,
        );
        assert!(!json.value().contains("raw-secret"));
        assert!(json.value().contains("session_id"));
        assert!(json.value().contains("safe"));

        let headers = policy.field(
            "headers",
            "X-Redirect: {\"target\":\"https://example.test/?nonce=raw-secret\"}",
        );
        assert!(!headers.value().contains("raw-secret"));
        assert!(headers.value().contains("X-Redirect:"));
        assert!(headers.value().contains("target"));

        let encoded = policy.field(
            "headers",
            "X-Redirect: redirect=https%3A%2F%2Fexample.test%2F%3Fsession_id%3Draw-secret",
        );
        assert!(!encoded.value().contains("raw-secret"));
        assert!(!encoded.value().contains("raw-secret"));

        let encoded_json =
            RedactionPolicy::new().field("message", "payload=%7B%22token%22%3A%22hidden%22%7D");
        assert!(!encoded_json.value().contains("hidden"));

        let double_encoded_json = RedactionPolicy::new().field(
            "message",
            "payload=%257B%2522token%2522%253A%2522hidden%2522%257D",
        );
        assert!(!double_encoded_json.value().contains("hidden"));

        let encoded_assignment = RedactionPolicy::new().field("message", "payload=token%3Dhidden");
        assert!(!encoded_assignment.value().contains("hidden"));

        let encoded_opaque_header = RedactionPolicy::new()
            .with_secret("päss")
            .field("headers", "X-Trace: p%C3%A4ss");
        assert!(!encoded_opaque_header.value().contains("p%C3%A4ss"));

        let encoded_header_name = RedactionPolicy::new()
            .with_secret("päss")
            .field("headers", "X-%70%C3%A4ss: visible");
        assert!(!encoded_header_name.value().contains("p%C3%A4ss"));
    }

    #[test]
    fn generic_json_unicode_escapes_cannot_bypass_redaction() {
        let policy = RedactionPolicy::new().with_secret("raw-secret");
        let escaped_field_key = RedactionPolicy::new().field(r#"\u0074oken"#, "hidden");
        assert_eq!(escaped_field_key.value(), REDACTED);
        let malformed_field_key = RedactionPolicy::new().field(r#"\uD800"#, "hidden");
        assert_eq!(malformed_field_key.value(), REDACTED);

        let escaped_key = policy.field(
            "message",
            r#"{"\u0074\u006f\u006b\u0065\u006e":"hidden","safe":"ok"}"#,
        );
        assert!(!escaped_key.value().contains("hidden"));
        assert!(escaped_key.value().contains("safe"));

        let escaped_value = policy.field("message", r#"{"message":"raw\u002dsecret","safe":"ok"}"#);
        assert!(!escaped_value.value().contains("raw\\u002dsecret"));
        assert!(!escaped_value.value().contains("raw-secret"));

        let escaped_prose = policy.field("message", r#"prefix raw\u002dsecret suffix"#);
        assert!(!escaped_prose.value().contains("raw\\u002dsecret"));
        assert!(!escaped_prose.value().contains("raw-secret"));

        let escaped_url = policy.field("url", r#"https://example.test/?safe=raw\u002dsecret"#);
        assert_eq!(escaped_url.value(), REDACTED);

        let mixed_encoded_secret =
            policy.field("message", r#"prefix %5Cu0072aw%5Cu002dsecret suffix"#);
        assert_eq!(mixed_encoded_secret.value(), REDACTED);
        let mixed_encoded_key =
            RedactionPolicy::new().field("message", r#"{"%5Cu0074oken":"hidden","safe":"ok"}"#);
        assert!(!mixed_encoded_key.value().contains("hidden"));

        let malformed_escape = RedactionPolicy::new().field("message", r#"{"\uD800":"malformed"}"#);
        assert!(!malformed_escape.value().contains("malformed"));
        assert_eq!(
            RedactionPolicy::new()
                .field("message", r#"{"safe":"line\u000abreak"}"#)
                .value(),
            REDACTED
        );
        assert!(decode_json_escaped_text(r#"\uD83D\uDE00"#).is_some());
        assert!(decode_json_escaped_text(r#"\uD800"#).is_none());
    }

    #[test]
    fn nested_redaction_fails_closed_at_output_boundaries() {
        let policy =
            RedactionPolicy::with_limits(RedactionLimits::new(4, 32, 16)).with_secret("raw-secret");
        let field = policy.field("headers", "X-Trace: prefix raw-secret");
        assert!(field.is_truncated());
        assert!(!field.value().contains("raw-secret"));
        assert_eq!(field.value(), REDACTED);
    }

    #[test]
    fn deeply_percent_encoded_values_fail_closed_at_decode_budget() {
        let mut encoded_key = "%74%6f%6b%65%6e".to_owned();
        for _ in 0..MAX_REDACTION_DEPTH {
            encoded_key = encoded_key.replace('%', "%25");
        }
        let field = RedactionPolicy::new().field("message", &format!("{encoded_key}=hidden"));
        assert!(!field.value().contains("hidden"));
        assert!(field.value().contains(REDACTED));

        let mut encoded_secret = "raw-secret"
            .bytes()
            .map(|byte| format!("%{byte:02x}"))
            .collect::<String>();
        for _ in 0..MAX_REDACTION_DEPTH {
            encoded_secret = encoded_secret.replace('%', "%25");
        }
        let configured = RedactionPolicy::new().with_secret("raw-secret");
        let field = configured.field("message", &encoded_secret);
        assert_eq!(field.value(), REDACTED);

        let mut encoded_control = "%0a".to_owned();
        for _ in 0..MAX_REDACTION_DEPTH {
            encoded_control = encoded_control.replace('%', "%25");
        }
        assert_eq!(
            RedactionPolicy::new().field("url", &format!("/safe?x={encoded_control}")),
            RedactionPolicy::new().field("url", REDACTED)
        );
    }

    #[test]
    fn generic_text_scanner_keeps_large_plain_values_bounded() {
        let field = RedactionPolicy::new().field("message", &"x".repeat(64 * 1024));
        assert!(field.is_truncated());
        assert!(field.value().len() <= DEFAULT_MAX_VALUE_BYTES);
    }

    #[test]
    fn policy_rebind_enforces_destination_field_bounds_atomically() {
        let wide = RedactionPolicy::with_limits(RedactionLimits::new(4, 32, 32));
        let mut event = DiagnosticEvent::builder_with_policy(
            wide.clone(),
            "event",
            Severity::Info,
            DiagnosticCategory::Observation,
        )
        .field("one", "1")
        .field("two", "2")
        .build()
        .expect("wide event should build");
        let narrow = RedactionPolicy::with_limits(RedactionLimits::new(1, 32, 32));
        assert_eq!(
            event.rebind_policy(narrow.clone()),
            Err(ObserveError::FieldLimitExceeded { maximum: 1 })
        );
        assert_eq!(event.fields().len(), 2);
        assert_eq!(event.redaction_policy().limits().max_fields, 4);
        let rebound = event
            .clone()
            .try_with_policy(wide)
            .expect("equal bound rebind should fit");
        assert_eq!(rebound.fields().len(), 2);
    }

    #[test]
    fn metrics_hash_unknown_low_cardinality_values_and_bound_total_bytes() {
        let unknown = MetricLabel::new("status", "operator-private").expect("label fits");
        assert!(unknown.value().starts_with("h:"));
        let status_class_with_suffix =
            MetricLabel::new("status", "1xx-private-token").expect("label fits");
        assert!(status_class_with_suffix.value().starts_with("h:"));
        let long_numeric_status = MetricLabel::new("status", "123456789").expect("label fits");
        assert!(long_numeric_status.value().starts_with("h:"));
        let code = MetricLabel::new("code", "operator-private").expect("code fits");
        assert!(code.value().starts_with("h:"));
        let allowed = MetricLabel::new("kind", "sample").expect("allowlisted label fits");
        assert_eq!(allowed.value(), "sample");

        let limits = MetricLimits::new_with_max_bytes(8, 4, 64, 32, 32, 4, 100);
        let registry = MetricsRegistry::new(limits);
        let labels = MetricLabels::new();
        assert_eq!(
            registry.total_bytes(),
            RedactionPolicy::new().retained_bytes()
        );
        registry
            .increment("small", &labels)
            .expect("first metric fits");
        let before = registry.total_bytes();
        assert!(before <= limits.max_bytes);
        let result = registry.increment("a-metric-name-that-cannot-fit-again", &labels);
        assert!(matches!(result, Err(MetricError::ByteLimitExceeded { .. })));
        assert_eq!(registry.total_bytes(), before);

        let mut labels = MetricLabels::new();
        labels
            .push("status", "operator-private")
            .expect("label fits");
        let old = labels.get("status").expect("status label").to_owned();
        labels
            .rebind_policy(RedactionPolicy::new().with_secret("new-policy-secret"))
            .expect("safe digest remains safe under policy rebind");
        assert_eq!(labels.get("status"), Some(old.as_str()));

        let tiny_limits = MetricLimits::new_with_max_bytes(1, 1, 32, 16, 16, 1, 1);
        let oversized_policy = RedactionPolicy::new().with_secret("policy-bytes");
        let full_registry = MetricsRegistry::new_with_policy(tiny_limits, oversized_policy);
        assert!(full_registry.total_bytes() <= tiny_limits.max_bytes);
        assert!(matches!(
            full_registry.increment("blocked", &MetricLabels::new()),
            Err(MetricError::ByteLimitExceeded { .. })
        ));
    }

    #[test]
    fn metric_policy_rebind_rejects_shared_handles() {
        let mut registry = MetricsRegistry::default_registry();
        let shared = registry.clone();
        let policy = RedactionPolicy::new().with_secret("shared-policy-secret");
        assert_eq!(
            registry.rebind_policy(policy.clone()),
            Err(MetricError::SharedPolicy)
        );
        assert_eq!(registry.rebind_policy(RedactionPolicy::new()), Ok(()));
        drop(shared);
        assert_eq!(registry.rebind_policy(policy), Ok(()));
        registry.close();
        assert_eq!(
            registry.rebind_policy(RedactionPolicy::new()),
            Err(MetricError::Closed)
        );
    }

    #[test]
    fn sink_rejects_parent_end_until_children_end_and_borrowed_retry_is_safe() {
        let sink = InMemorySink::new(SinkLimits::new(8, usize::MAX));
        let parent = DiagnosticSpan::new_timed(
            RedactionPolicy::new(),
            "parent",
            Severity::Info,
            DiagnosticCategory::Observation,
            Timestamp::new(1, 1),
            SequenceId::new(1),
        )
        .with_id(SpanId::new(1));
        let child = parent
            .child("child", Severity::Info, DiagnosticCategory::Observation)
            .with_timestamp(Timestamp::new(2, 2))
            .with_sequence(SequenceId::new(2))
            .with_id(SpanId::new(2))
            .build()
            .expect("child should build");
        sink.span_start(parent.clone()).expect("parent starts");
        sink.span_start(child.clone()).expect("child starts");
        let parent_end = parent
            .end_at(
                SpanOutcome::Complete,
                Timestamp::new(4, 4),
                SequenceId::new(4),
            )
            .expect("parent timing");
        assert!(matches!(
            sink.span_end(parent_end.clone()),
            Err(SinkError::ActiveChildren { id, count: 1 }) if id == SpanId::new(1)
        ));
        let child_end = child
            .end_at(
                SpanOutcome::Complete,
                Timestamp::new(3, 3),
                SequenceId::new(3),
            )
            .expect("child timing");
        sink.span_end(child_end).expect("child ends");
        sink.span_end(parent_end).expect("parent ends after child");

        let full = InMemorySink::new(SinkLimits::new(1, usize::MAX));
        let first = DiagnosticEvent::new_timed(
            RedactionPolicy::new(),
            "first",
            Severity::Info,
            DiagnosticCategory::Observation,
            Timestamp::new(10, 10),
            SequenceId::new(10),
        );
        full.event(first).expect("first event fits");
        let retry = DiagnosticRecord::Event(DiagnosticEvent::new_timed(
            RedactionPolicy::new(),
            "retry",
            Severity::Info,
            DiagnosticCategory::Observation,
            Timestamp::new(11, 11),
            SequenceId::new(11),
        ));
        assert!(matches!(
            full.record_ref(&retry),
            Err(SinkError::Full { .. })
        ));
        let retry_sink = InMemorySink::new(SinkLimits::new(1, usize::MAX));
        retry_sink
            .record_ref(&retry)
            .expect("borrowed record can retry on another sink");
    }
}
