// SPDX-License-Identifier: Apache-2.0
//! Canonical diagnostics for the typed result-router boundary.
//!
//! The runtime crate currently keeps its typed result-router module private
//! and only re-exports the older router contract.  This module consequently
//! has no runtime dependency: it defines the small, canonical projection that
//! a future runtime bridge can populate once that contract is exported.  The
//! projection is deliberately owned by `observe`, so a bridge cannot create a
//! second redaction or identity vocabulary.
//!
//! Every mapping retains the caller's [`RedactionPolicy`] in the resulting
//! [`DiagnosticEvent`].  Router identities are retained when safe and replaced
//! by a deterministic digest when policy redaction would otherwise expose
//! input.  The digest preserves equality and correlation without retaining a
//! secret.  All diagnostic text is passed through the same bounded policy.

use super::{
    DiagnosticCategory, DiagnosticEvent, ObserveError, RedactionPolicy, SequenceId, Severity,
    Timestamp, stable_digest,
};
use core::fmt;

/// Maximum bytes accepted for one canonical router identity.
pub const MAX_ROUTER_IDENTITY_BYTES: usize = 128;

/// The outcome reported by a typed router admission attempt.
///
/// The variants mirror the bounded admission outcomes of the typed router;
/// they do not retain router-owned error strings or queue objects.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RouterAdmissionOutcome {
    /// The event was admitted.
    Accepted,
    /// The destination was full and the caller may apply its retry contract.
    Full,
    /// The destination has closed admission.
    Closed,
    /// Admission was canceled before ownership was transferred.
    Cancelled,
    /// The destination rejected admission with a typed failure.
    Failed,
    /// The router diagnosed a drop while retaining the event identity.
    DiagnosedDrop,
}

impl RouterAdmissionOutcome {
    const fn code(self) -> &'static str {
        match self {
            Self::Accepted => "router.admission.accepted",
            Self::Full => "router.admission.full",
            Self::Closed => "router.admission.closed",
            Self::Cancelled => "router.admission.cancelled",
            Self::Failed => "router.admission.failed",
            Self::DiagnosedDrop => "router.admission.diagnosed_drop",
        }
    }

    const fn severity(self) -> Severity {
        match self {
            Self::Accepted => Severity::Info,
            Self::Full | Self::Closed | Self::Cancelled | Self::DiagnosedDrop => Severity::Warn,
            Self::Failed => Severity::Error,
        }
    }
}

/// The finalization phase associated with a router diagnostic.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RouterFinalizationStage {
    /// Admission was stopped before draining.
    StopAdmission,
    /// Queued delivery was drained.
    Drain,
    /// The sink's flush boundary was reached.
    Flush,
    /// The sink was closed.
    Close,
    /// The final report was published.
    Publish,
}

impl RouterFinalizationStage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::StopAdmission => "stop_admission",
            Self::Drain => "drain",
            Self::Flush => "flush",
            Self::Close => "close",
            Self::Publish => "publish",
        }
    }
}

/// Counts used when mapping a conservation failure.
///
/// These are scalar ledger facts rather than diagnostic text.  They preserve
/// the router's stable accounting identities without retaining an unbounded
/// report or error chain.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RouterConservationCounts {
    /// Number of events selected for the router boundary.
    pub selected_events: u64,
    /// Number of events admitted to a sink.
    pub admitted_events: u64,
    /// Number of events durably acknowledged.
    pub durable_events: u64,
    /// Number of events diagnosed as dropped.
    pub diagnosed_drop_events: u64,
    /// Number of events rejected as failures.
    pub failed_events: u64,
    /// Number of bytes selected for the router boundary.
    pub selected_bytes: u64,
    /// Number of bytes admitted to a sink.
    pub admitted_bytes: u64,
    /// Number of bytes durably acknowledged.
    pub durable_bytes: u64,
}

/// Input projection for one typed router admission outcome.
///
/// The string references are borrowed only for the duration of mapping and
/// are redacted before the resulting event retains any data.  The identity
/// fields should use the runtime's canonical stable spellings (for example,
/// its run/generation/event/sink IDs).
pub struct RouterAdmissionDiagnosticInput<'a> {
    /// Admission result.
    pub outcome: RouterAdmissionOutcome,
    /// Stable run identity, when the outcome has one.
    pub run_id: Option<&'a str>,
    /// Stable run generation, when the outcome has one.
    pub run_generation: Option<u64>,
    /// Stable event identity, when the outcome has one.
    pub event_id: Option<&'a str>,
    /// Stable sink identity, when the outcome has one.
    pub sink_id: Option<&'a str>,
    /// Event size supplied by the router, when known.
    pub bytes: Option<usize>,
    /// Bounded router reason or diagnostic, when supplied.
    pub detail: Option<&'a str>,
}

impl fmt::Debug for RouterAdmissionDiagnosticInput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RouterAdmissionDiagnosticInput")
            .field("outcome", &self.outcome)
            .field("has_run_id", &self.run_id.is_some())
            .field("run_generation", &self.run_generation)
            .field("has_event_id", &self.event_id.is_some())
            .field("has_sink_id", &self.sink_id.is_some())
            .field("bytes", &self.bytes)
            .field("has_detail", &self.detail.is_some())
            .finish()
    }
}

/// Input projection for one typed router finalization failure.
pub struct RouterFinalizationDiagnosticInput<'a> {
    /// Finalization phase.
    pub stage: RouterFinalizationStage,
    /// Stable run identity, when the report has one.
    pub run_id: Option<&'a str>,
    /// Stable run generation, when the report has one.
    pub run_generation: Option<u64>,
    /// Stable sink identity, when the report has one.
    pub sink_id: Option<&'a str>,
    /// Primary typed finalization diagnostic.
    pub primary: &'a str,
    /// Secondary cleanup diagnostic, when cleanup also failed.
    pub secondary: Option<&'a str>,
}

impl fmt::Debug for RouterFinalizationDiagnosticInput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RouterFinalizationDiagnosticInput")
            .field("stage", &self.stage)
            .field("has_run_id", &self.run_id.is_some())
            .field("run_generation", &self.run_generation)
            .field("has_sink_id", &self.sink_id.is_some())
            .field("has_primary", &!self.primary.is_empty())
            .field(
                "has_secondary",
                &self.secondary.is_some_and(|value| !value.is_empty()),
            )
            .finish()
    }
}

/// Input projection for a typed router conservation failure.
pub struct RouterConservationDiagnosticInput<'a> {
    /// Stable run identity, when the report has one.
    pub run_id: Option<&'a str>,
    /// Stable run generation, when the report has one.
    pub run_generation: Option<u64>,
    /// Stable sink identity, when the report has one.
    pub sink_id: Option<&'a str>,
    /// Stable event identity, when the report can identify one.
    pub event_id: Option<&'a str>,
    /// Bounded ledger counters.
    pub counts: RouterConservationCounts,
    /// Typed conservation detail.
    pub detail: &'a str,
}

impl fmt::Debug for RouterConservationDiagnosticInput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RouterConservationDiagnosticInput")
            .field("has_run_id", &self.run_id.is_some())
            .field("run_generation", &self.run_generation)
            .field("has_sink_id", &self.sink_id.is_some())
            .field("has_event_id", &self.event_id.is_some())
            .field("counts", &self.counts)
            .field("has_detail", &!self.detail.is_empty())
            .finish()
    }
}

/// Errors found while constructing a canonical router diagnostic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouterDiagnosticError {
    /// A required stable identity was empty.
    EmptyIdentity {
        /// Canonical field which was empty.
        field: &'static str,
    },
    /// A stable identity exceeded the pre-allocation bound.
    IdentityTooLong {
        /// Canonical field which exceeded its bound.
        field: &'static str,
        /// Input byte length.
        actual: usize,
        /// Maximum accepted byte length.
        maximum: usize,
    },
    /// A required typed diagnostic was empty.
    EmptyDetail {
        /// Canonical field which was empty.
        field: &'static str,
    },
    /// A caller did not assign a valid sequence identity.
    InvalidSequence,
    /// The retained observe policy could not retain the mapped event.
    Observe(ObserveError),
}

impl RouterDiagnosticError {
    /// Returns a stable machine-readable code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::EmptyIdentity { .. } => "router.identity.empty",
            Self::IdentityTooLong { .. } => "router.identity.too_long",
            Self::EmptyDetail { .. } => "router.detail.empty",
            Self::InvalidSequence => "router.sequence.invalid",
            Self::Observe(error) => error.code(),
        }
    }
}

impl fmt::Display for RouterDiagnosticError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyIdentity { field } => write!(formatter, "router.identity.empty ({field})"),
            Self::IdentityTooLong {
                field,
                actual,
                maximum,
            } => write!(
                formatter,
                "router.identity.too_long ({field}, {actual} > {maximum})"
            ),
            Self::EmptyDetail { field } => write!(formatter, "router.detail.empty ({field})"),
            Self::InvalidSequence => formatter.write_str("router.sequence.invalid"),
            Self::Observe(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for RouterDiagnosticError {}

impl From<ObserveError> for RouterDiagnosticError {
    fn from(error: ObserveError) -> Self {
        Self::Observe(error)
    }
}

/// Pure adapter from typed router projections to bounded diagnostic events.
///
/// The policy is retained by every event produced by this adapter.  Timing
/// and sequence values are explicit arguments because the adapter never reads
/// an ambient clock or allocates a global identity.
#[derive(Clone, Debug)]
pub struct RouterDiagnosticAdapter {
    policy: RedactionPolicy,
}

impl RouterDiagnosticAdapter {
    /// Creates an adapter with the caller's retained redaction policy.
    #[must_use]
    pub fn new(policy: RedactionPolicy) -> Self {
        Self { policy }
    }

    /// Returns the retained policy without exposing configured secrets.
    #[must_use]
    pub fn redaction_policy(&self) -> &RedactionPolicy {
        &self.policy
    }

    /// Maps one typed router admission result.
    pub fn admission(
        &self,
        input: &RouterAdmissionDiagnosticInput<'_>,
        timestamp: Timestamp,
        sequence: SequenceId,
    ) -> Result<DiagnosticEvent, RouterDiagnosticError> {
        let mut event = self.base_event(
            "result.router.admission",
            input.outcome.severity(),
            input.outcome.code(),
            timestamp,
            sequence,
        )?;
        self.add_optional_identity(&mut event, "router.run_id", input.run_id)?;
        self.add_optional_number(&mut event, "router.run_generation", input.run_generation)?;
        self.add_optional_identity(&mut event, "router.event_id", input.event_id)?;
        self.add_optional_identity(&mut event, "router.sink_id", input.sink_id)?;
        self.add_optional_usize(&mut event, "router.bytes", input.bytes)?;
        if let Some(detail) = input.detail {
            self.add_detail(&mut event, "router.detail", detail)?;
        }
        Ok(event)
    }

    /// Maps a typed router finalization failure, retaining both error layers.
    pub fn finalization(
        &self,
        input: &RouterFinalizationDiagnosticInput<'_>,
        timestamp: Timestamp,
        sequence: SequenceId,
    ) -> Result<DiagnosticEvent, RouterDiagnosticError> {
        if input.primary.is_empty() {
            return Err(RouterDiagnosticError::EmptyDetail { field: "primary" });
        }
        if input.secondary.is_some_and(str::is_empty) {
            return Err(RouterDiagnosticError::EmptyDetail { field: "secondary" });
        }
        let mut event = self.base_event(
            "result.router.finalization",
            Severity::Error,
            "router.finalization.failed",
            timestamp,
            sequence,
        )?;
        self.add_optional_identity(&mut event, "router.run_id", input.run_id)?;
        self.add_optional_number(&mut event, "router.run_generation", input.run_generation)?;
        event.add_field("router.stage", input.stage.as_str())?;
        self.add_optional_identity(&mut event, "router.sink_id", input.sink_id)?;
        self.add_detail(&mut event, "router.primary", input.primary)?;
        if let Some(secondary) = input.secondary {
            self.add_detail(&mut event, "router.secondary", secondary)?;
        }
        Ok(event)
    }

    /// Maps a typed ledger conservation violation.
    pub fn conservation(
        &self,
        input: &RouterConservationDiagnosticInput<'_>,
        timestamp: Timestamp,
        sequence: SequenceId,
    ) -> Result<DiagnosticEvent, RouterDiagnosticError> {
        if input.detail.is_empty() {
            return Err(RouterDiagnosticError::EmptyDetail { field: "detail" });
        }
        let mut event = self.base_event(
            "result.router.conservation",
            Severity::Fatal,
            "router.conservation.violation",
            timestamp,
            sequence,
        )?;
        self.add_optional_identity(&mut event, "router.run_id", input.run_id)?;
        self.add_optional_number(&mut event, "router.run_generation", input.run_generation)?;
        self.add_optional_identity(&mut event, "router.sink_id", input.sink_id)?;
        self.add_optional_identity(&mut event, "router.event_id", input.event_id)?;
        self.add_number(
            &mut event,
            "router.selected_events",
            input.counts.selected_events,
        )?;
        self.add_number(
            &mut event,
            "router.admitted_events",
            input.counts.admitted_events,
        )?;
        self.add_number(
            &mut event,
            "router.durable_events",
            input.counts.durable_events,
        )?;
        self.add_number(
            &mut event,
            "router.diagnosed_drop_events",
            input.counts.diagnosed_drop_events,
        )?;
        self.add_number(
            &mut event,
            "router.failed_events",
            input.counts.failed_events,
        )?;
        self.add_number(
            &mut event,
            "router.selected_bytes",
            input.counts.selected_bytes,
        )?;
        self.add_number(
            &mut event,
            "router.admitted_bytes",
            input.counts.admitted_bytes,
        )?;
        self.add_number(
            &mut event,
            "router.durable_bytes",
            input.counts.durable_bytes,
        )?;
        self.add_detail(&mut event, "router.detail", input.detail)?;
        Ok(event)
    }

    fn base_event(
        &self,
        name: &'static str,
        severity: Severity,
        code: &'static str,
        timestamp: Timestamp,
        sequence: SequenceId,
    ) -> Result<DiagnosticEvent, RouterDiagnosticError> {
        if !sequence.is_valid() {
            return Err(RouterDiagnosticError::InvalidSequence);
        }
        Ok(DiagnosticEvent::new_timed(
            self.policy.clone(),
            name,
            severity,
            DiagnosticCategory::Persistence,
            timestamp,
            sequence,
        )
        .with_error_code(code))
    }

    fn add_optional_identity(
        &self,
        event: &mut DiagnosticEvent,
        key: &'static str,
        value: Option<&str>,
    ) -> Result<(), RouterDiagnosticError> {
        let Some(value) = value else {
            return Ok(());
        };
        if value.is_empty() {
            return Err(RouterDiagnosticError::EmptyIdentity { field: key });
        }
        if value.len() > MAX_ROUTER_IDENTITY_BYTES {
            return Err(RouterDiagnosticError::IdentityTooLong {
                field: key,
                actual: value.len(),
                maximum: MAX_ROUTER_IDENTITY_BYTES,
            });
        }
        let sanitized = self.policy.redact_value(value);
        let stable = if sanitized == value && sanitized.len() <= MAX_ROUTER_IDENTITY_BYTES {
            sanitized
        } else {
            format!("h:{:016x}", stable_digest(value.as_bytes()))
        };
        event.add_field(key, stable)?;
        Ok(())
    }

    fn add_optional_number(
        &self,
        event: &mut DiagnosticEvent,
        key: &'static str,
        value: Option<u64>,
    ) -> Result<(), RouterDiagnosticError> {
        if let Some(value) = value {
            self.add_number(event, key, value)?;
        }
        Ok(())
    }

    fn add_optional_usize(
        &self,
        event: &mut DiagnosticEvent,
        key: &'static str,
        value: Option<usize>,
    ) -> Result<(), RouterDiagnosticError> {
        if let Some(value) = value {
            event.add_field(key, value.to_string())?;
        }
        Ok(())
    }

    fn add_number(
        &self,
        event: &mut DiagnosticEvent,
        key: &'static str,
        value: u64,
    ) -> Result<(), RouterDiagnosticError> {
        event.add_field(key, value.to_string())?;
        Ok(())
    }

    fn add_detail(
        &self,
        event: &mut DiagnosticEvent,
        key: &'static str,
        value: &str,
    ) -> Result<(), RouterDiagnosticError> {
        event.add_field(key, value)?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "deterministic adapter tests use assertions for setup"
)]
mod tests {
    use super::*;
    use crate::{RedactionLimits, Secret};

    fn policy() -> RedactionPolicy {
        RedactionPolicy::with_limits(RedactionLimits::new(32, 64, 96))
            .with_secret(Secret::try_new("router-secret").expect("test secret"))
    }

    fn field<'a>(event: &'a DiagnosticEvent, key: &str) -> &'a str {
        event
            .fields()
            .iter()
            .find(|field| field.key() == key)
            .map(crate::DiagnosticField::value)
            .expect("field present")
    }

    #[test]
    fn admission_is_bounded_redacted_and_identity_stable() {
        let adapter = RouterDiagnosticAdapter::new(policy());
        let input = RouterAdmissionDiagnosticInput {
            outcome: RouterAdmissionOutcome::Failed,
            run_id: Some("run-7"),
            run_generation: Some(3),
            event_id: Some("event-19"),
            sink_id: Some("sink-2"),
            bytes: Some(17),
            detail: Some("authorization=router-secret nested query token=router-secret"),
        };
        let event = adapter
            .admission(&input, Timestamp::new(11, 22), SequenceId::new(9))
            .expect("admission mapping");

        assert_eq!(event.name(), "result.router.admission");
        assert_eq!(event.sequence(), SequenceId::new(9));
        assert_eq!(event.timestamp(), Some(Timestamp::new(11, 22)));
        assert_eq!(field(&event, "router.run_id"), "run-7");
        assert_eq!(field(&event, "router.event_id"), "event-19");
        assert_eq!(field(&event, "router.sink_id"), "sink-2");
        assert!(!field(&event, "router.detail").contains("router-secret"));
        assert_eq!(event.redaction_policy(), adapter.redaction_policy());
    }

    #[test]
    fn finalization_retains_both_diagnostics_without_leaking_secret() {
        let adapter = RouterDiagnosticAdapter::new(policy());
        let input = RouterFinalizationDiagnosticInput {
            stage: RouterFinalizationStage::Flush,
            run_id: Some("run-7"),
            run_generation: Some(3),
            sink_id: Some("sink-2"),
            primary: "flush failed for router-secret",
            secondary: Some("close failed for router-secret"),
        };
        let event = adapter
            .finalization(&input, Timestamp::new(12, 23), SequenceId::new(10))
            .expect("finalization mapping");

        assert_eq!(field(&event, "router.stage"), "flush");
        assert!(!field(&event, "router.primary").contains("router-secret"));
        assert!(!field(&event, "router.secondary").contains("router-secret"));
        assert_eq!(field(&event, "router.run_id"), "run-7");
    }

    #[test]
    fn conservation_keeps_identity_and_bounded_ledger_facts() {
        let adapter = RouterDiagnosticAdapter::new(policy());
        let input = RouterConservationDiagnosticInput {
            run_id: Some("run-7"),
            run_generation: Some(3),
            sink_id: Some("sink-2"),
            event_id: Some("event-19"),
            counts: RouterConservationCounts {
                selected_events: 4,
                admitted_events: 3,
                durable_events: 2,
                diagnosed_drop_events: 1,
                failed_events: 0,
                selected_bytes: 400,
                admitted_bytes: 300,
                durable_bytes: 200,
            },
            detail: "ledger mismatch for router-secret",
        };
        let event = adapter
            .conservation(&input, Timestamp::new(13, 24), SequenceId::new(11))
            .expect("conservation mapping");

        assert_eq!(event.severity(), Severity::Fatal);
        assert_eq!(field(&event, "router.selected_events"), "4");
        assert_eq!(field(&event, "router.durable_bytes"), "200");
        assert_eq!(field(&event, "router.event_id"), "event-19");
        assert!(!field(&event, "router.detail").contains("router-secret"));
    }

    #[test]
    fn secret_bearing_identity_becomes_a_stable_digest() {
        let adapter = RouterDiagnosticAdapter::new(policy());
        let input = RouterAdmissionDiagnosticInput {
            outcome: RouterAdmissionOutcome::DiagnosedDrop,
            run_id: Some("run-router-secret"),
            run_generation: None,
            event_id: Some("event-1"),
            sink_id: None,
            bytes: None,
            detail: None,
        };
        let first = adapter
            .admission(&input, Timestamp::new(1, 1), SequenceId::new(1))
            .expect("first mapping");
        let second = adapter
            .admission(&input, Timestamp::new(1, 1), SequenceId::new(1))
            .expect("second mapping");
        let first_id = field(&first, "router.run_id");
        assert!(first_id.starts_with("h:"));
        assert!(!first_id.contains("router-secret"));
        assert_eq!(first_id, field(&second, "router.run_id"));
    }

    #[test]
    fn projection_debug_does_not_retain_borrowed_secret_text() {
        let input = RouterFinalizationDiagnosticInput {
            stage: RouterFinalizationStage::Close,
            run_id: Some("run-router-secret"),
            run_generation: Some(1),
            sink_id: Some("sink-1"),
            primary: "close failed for router-secret",
            secondary: Some("cleanup failed for router-secret"),
        };
        let debug = format!("{input:?}");
        assert!(!debug.contains("router-secret"));
        assert!(debug.contains("has_primary: true"));
    }

    #[test]
    fn identity_bound_is_checked_before_retention_and_sequence_is_explicit() {
        let adapter = RouterDiagnosticAdapter::new(policy());
        let oversized = "x".repeat(MAX_ROUTER_IDENTITY_BYTES + 1);
        let input = RouterAdmissionDiagnosticInput {
            outcome: RouterAdmissionOutcome::Accepted,
            run_id: Some(&oversized),
            run_generation: None,
            event_id: None,
            sink_id: None,
            bytes: None,
            detail: None,
        };
        assert_eq!(
            adapter.admission(&input, Timestamp::new(1, 1), SequenceId::new(1)),
            Err(RouterDiagnosticError::IdentityTooLong {
                field: "router.run_id",
                actual: MAX_ROUTER_IDENTITY_BYTES + 1,
                maximum: MAX_ROUTER_IDENTITY_BYTES,
            })
        );

        let valid = RouterAdmissionDiagnosticInput {
            outcome: RouterAdmissionOutcome::Accepted,
            run_id: Some("run-1"),
            run_generation: None,
            event_id: None,
            sink_id: None,
            bytes: None,
            detail: None,
        };
        assert_eq!(
            adapter.admission(&valid, Timestamp::new(1, 1), SequenceId::default()),
            Err(RouterDiagnosticError::InvalidSequence)
        );
    }

    #[test]
    fn empty_finalization_and_conservation_details_are_typed_errors() {
        let adapter = RouterDiagnosticAdapter::new(policy());
        let finalization = RouterFinalizationDiagnosticInput {
            stage: RouterFinalizationStage::Close,
            run_id: None,
            run_generation: None,
            sink_id: None,
            primary: "",
            secondary: None,
        };
        assert_eq!(
            adapter.finalization(&finalization, Timestamp::new(1, 1), SequenceId::new(1)),
            Err(RouterDiagnosticError::EmptyDetail { field: "primary" })
        );
        let conservation = RouterConservationDiagnosticInput {
            run_id: None,
            run_generation: None,
            sink_id: None,
            event_id: None,
            counts: RouterConservationCounts::default(),
            detail: "",
        };
        assert_eq!(
            adapter.conservation(&conservation, Timestamp::new(1, 1), SequenceId::new(1)),
            Err(RouterDiagnosticError::EmptyDetail { field: "detail" })
        );
    }
}
