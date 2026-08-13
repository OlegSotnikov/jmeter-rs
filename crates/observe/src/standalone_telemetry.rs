// SPDX-License-Identifier: Apache-2.0
//! Bounded diagnostics for the Decision 0009 plan-admission boundary.
//!
//! Decision 0009 makes implementation-path selection an atomic property of a
//! complete executable plan.  This module is the deliberately small
//! projection used by adapters at that boundary.  It does not depend on the
//! runtime capability implementation: callers provide the already-classified
//! path family and bounded identity text, and this crate records only a
//! redacted, deterministic observation.
//!
//! The path slice is validated in full before an event is built.  In
//! particular, a native prefix is never reported as admitted when a later
//! path is Java-only or unavailable.  The event contains aggregate counts and
//! an order-sensitive manifest digest rather than one high-cardinality field
//! for every node; the count and digest account for every validated path.

use super::{
    DiagnosticCategory, DiagnosticEvent, ObserveError, RedactionPolicy, SequenceId, Severity,
    Timestamp, stable_digest,
};
use core::fmt;
use std::collections::BTreeSet;

/// Maximum number of path entries accepted by one Decision 0009 observation.
///
/// This is intentionally lower than an unbounded plan-manifest limit.  A
/// telemetry adapter must remain safe when a malformed or adversarial plan
/// supplies an enormous number of executable nodes.
pub const MAX_DECISION0009_PATHS: usize = 4_096;

/// Maximum bytes accepted for one Decision 0009 identity or detail string.
pub const MAX_DECISION0009_TEXT_BYTES: usize = 512;

/// Capability mode selected for the complete plan admission.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Decision0009Mode {
    /// The one-artifact Rust product with no Java compatibility pack.
    StandaloneNative,
    /// An explicitly selected and negotiated compatibility pack.
    CompatibilityPack,
}

impl Decision0009Mode {
    /// Returns the stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StandaloneNative => "standalone-native",
            Self::CompatibilityPack => "compatibility-pack",
        }
    }

    /// Returns whether the mode is the one-artifact native product.
    #[must_use]
    pub const fn is_standalone_native(self) -> bool {
        matches!(self, Self::StandaloneNative)
    }
}

impl fmt::Display for Decision0009Mode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One of the four closed implementation-path families from Decision 0009.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Decision0009PathKind {
    /// A versioned standalone Rust capability.
    Native,
    /// A versioned JVM compatibility-pack capability.
    CompatJvm,
    /// A versioned Java RMI compatibility-pack capability.
    CompatRmi,
    /// No executable implementation is available.
    Unavailable,
}

impl Decision0009PathKind {
    /// Returns the stable path-family spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::CompatJvm => "compat.jvm",
            Self::CompatRmi => "compat.rmi",
            Self::Unavailable => "unavailable",
        }
    }

    /// Returns whether this path requires the optional compatibility pack.
    #[must_use]
    pub const fn requires_compatibility_pack(self) -> bool {
        matches!(self, Self::CompatJvm | Self::CompatRmi)
    }

    /// Returns whether this path is explicitly unavailable.
    #[must_use]
    pub const fn is_unavailable(self) -> bool {
        matches!(self, Self::Unavailable)
    }
}

impl fmt::Display for Decision0009PathKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Stable reasons for rejecting a complete plan admission.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Decision0009CapabilityRejectionKind {
    /// A standalone run contains a JVM or RMI path.
    CompatibilityPackRequired,
    /// A path was explicitly classified as unavailable.
    Unavailable,
    /// A path was not in the negotiated capability set.
    CapabilityNotNegotiated,
    /// A path was bound to a different profile.
    ProfileMismatch,
    /// A path was compiled from a different executable-plan digest.
    PlanDigestMismatch,
    /// A path was negotiated against a different capability-set digest.
    CapabilitySetDigestMismatch,
    /// The path manifest was malformed.
    InvalidManifest,
    /// Two entries claimed the same source identity.
    DuplicateSource,
    /// The bounded path limit was exceeded.
    PathLimitExceeded,
}

impl Decision0009CapabilityRejectionKind {
    /// Returns the stable machine-readable rejection code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::CompatibilityPackRequired => "runtime.capability.compatibility-pack-required",
            Self::Unavailable => "runtime.capability.unavailable",
            Self::CapabilityNotNegotiated => "runtime.capability.not-negotiated",
            Self::ProfileMismatch => "runtime.capability.profile-mismatch",
            Self::PlanDigestMismatch => "runtime.capability.plan-mismatch",
            Self::CapabilitySetDigestMismatch => "runtime.capability.capability-set-mismatch",
            Self::InvalidManifest => "runtime.capability.invalid-manifest",
            Self::DuplicateSource => "runtime.capability.duplicate-source",
            Self::PathLimitExceeded => "runtime.capability.path-limit",
        }
    }

    /// Returns the stable short spelling used in event fields.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CompatibilityPackRequired => "compatibility-pack-required",
            Self::Unavailable => "unavailable",
            Self::CapabilityNotNegotiated => "not-negotiated",
            Self::ProfileMismatch => "profile-mismatch",
            Self::PlanDigestMismatch => "plan-mismatch",
            Self::CapabilitySetDigestMismatch => "capability-set-mismatch",
            Self::InvalidManifest => "invalid-manifest",
            Self::DuplicateSource => "duplicate-source",
            Self::PathLimitExceeded => "path-limit",
        }
    }
}

impl fmt::Display for Decision0009CapabilityRejectionKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Terminal disposition of a complete plan admission.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Decision0009Disposition {
    /// The complete path manifest was admitted.
    Accepted,
    /// The complete path manifest was rejected before side effects.
    Rejected,
}

impl Decision0009Disposition {
    /// Alias for callers that use Decision 0009's “admitted” terminology.
    #[allow(non_upper_case_globals)]
    pub const Admitted: Self = Self::Accepted;

    /// Returns the stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
        }
    }

    /// Returns whether this is the successful terminal disposition.
    #[must_use]
    pub const fn is_accepted(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

impl fmt::Display for Decision0009Disposition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Aggregate counts for the ordered path manifest.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Decision0009PathCount {
    /// Number of native paths.
    pub native: u64,
    /// Number of JVM compatibility-pack paths.
    pub compat_jvm: u64,
    /// Number of Java RMI compatibility-pack paths.
    pub compat_rmi: u64,
    /// Number of explicitly unavailable paths.
    pub unavailable: u64,
}

impl Decision0009PathCount {
    /// Creates counts from an ordered path slice after validating every path.
    pub fn from_paths(
        paths: &[Decision0009PathInput<'_>],
    ) -> Result<Self, Decision0009TelemetryError> {
        if paths.len() > MAX_DECISION0009_PATHS {
            return Err(Decision0009TelemetryError::PathLimitExceeded {
                maximum: MAX_DECISION0009_PATHS,
            });
        }
        let mut count = Self::default();
        for path in paths {
            path.validate()?;
            match path.kind {
                Decision0009PathKind::Native => count.native = count.native.saturating_add(1),
                Decision0009PathKind::CompatJvm => {
                    count.compat_jvm = count.compat_jvm.saturating_add(1)
                }
                Decision0009PathKind::CompatRmi => {
                    count.compat_rmi = count.compat_rmi.saturating_add(1)
                }
                Decision0009PathKind::Unavailable => {
                    count.unavailable = count.unavailable.saturating_add(1)
                }
            }
        }
        Ok(count)
    }

    /// Alias emphasizing that the caller is asking for a bounded operation.
    pub fn try_from_paths(
        paths: &[Decision0009PathInput<'_>],
    ) -> Result<Self, Decision0009TelemetryError> {
        Self::from_paths(paths)
    }

    /// Returns the total number of paths.
    #[must_use]
    pub const fn total(self) -> u64 {
        self.native
            .saturating_add(self.compat_jvm)
            .saturating_add(self.compat_rmi)
            .saturating_add(self.unavailable)
    }

    /// Returns whether every path is a native path.
    #[must_use]
    pub const fn all_native(self) -> bool {
        self.compat_jvm == 0 && self.compat_rmi == 0 && self.unavailable == 0
    }

    /// Returns whether at least one external or unavailable path is present.
    #[must_use]
    pub const fn has_non_native(self) -> bool {
        !self.all_native()
    }
}

/// Borrowed projection of one implementation-path identity.
///
/// `source` is normally a node or run-level identity.  The capability is the
/// versioned capability token (for example `http@1`); unavailable paths carry
/// their bounded reason in `detail` instead.  These fields borrow caller data
/// and are never retained by a telemetry input after event construction.
#[derive(Clone, Copy)]
pub struct Decision0009PathInput<'a> {
    /// Node or run-level source identity.
    pub source: &'a str,
    /// Closed implementation-path family.
    pub kind: Decision0009PathKind,
    /// Versioned capability token, when the path is executable.
    pub capability: Option<&'a str>,
    /// Bounded unavailable reason or optional path detail.
    pub detail: Option<&'a str>,
}

impl<'a> Decision0009PathInput<'a> {
    /// Creates a path projection with an optional capability and detail.
    #[must_use]
    pub const fn new(
        source: &'a str,
        kind: Decision0009PathKind,
        capability: Option<&'a str>,
        detail: Option<&'a str>,
    ) -> Self {
        Self {
            source,
            kind,
            capability,
            detail,
        }
    }

    /// Creates a native path projection.
    #[must_use]
    pub const fn native(source: &'a str, capability: &'a str) -> Self {
        Self::new(source, Decision0009PathKind::Native, Some(capability), None)
    }

    /// Creates a JVM compatibility-pack path projection.
    #[must_use]
    pub const fn compat_jvm(source: &'a str, capability: &'a str) -> Self {
        Self::new(
            source,
            Decision0009PathKind::CompatJvm,
            Some(capability),
            None,
        )
    }

    /// Creates a Java RMI compatibility-pack path projection.
    #[must_use]
    pub const fn compat_rmi(source: &'a str, capability: &'a str) -> Self {
        Self::new(
            source,
            Decision0009PathKind::CompatRmi,
            Some(capability),
            None,
        )
    }

    /// Creates an unavailable path projection with its stable reason detail.
    #[must_use]
    pub const fn unavailable(source: &'a str, detail: &'a str) -> Self {
        Self::new(
            source,
            Decision0009PathKind::Unavailable,
            None,
            Some(detail),
        )
    }

    fn validate(&self) -> Result<(), Decision0009TelemetryError> {
        validate_text(self.source, "source", true)?;
        match self.kind {
            Decision0009PathKind::Native
            | Decision0009PathKind::CompatJvm
            | Decision0009PathKind::CompatRmi => {
                let capability = self
                    .capability
                    .ok_or(Decision0009TelemetryError::MissingCapability)?;
                validate_text(capability, "capability", true)?;
            }
            Decision0009PathKind::Unavailable => {
                let detail = self
                    .detail
                    .ok_or(Decision0009TelemetryError::MissingDetail)?;
                validate_text(detail, "detail", true)?;
            }
        }
        if let Some(detail) = self.detail {
            validate_text(detail, "detail", false)?;
        }
        Ok(())
    }
}

impl fmt::Debug for Decision0009PathInput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Decision0009PathInput")
            .field("has_source", &(!self.source.is_empty()))
            .field("kind", &self.kind)
            .field("has_capability", &self.capability.is_some())
            .field("has_detail", &self.detail.is_some())
            .finish()
    }
}

/// Borrowed input for one complete plan-preflight observation.
pub struct Decision0009PreflightInput<'a> {
    /// Capability mode selected for the complete plan.
    pub mode: Decision0009Mode,
    /// Active compatibility profile identity.
    pub profile_id: &'a str,
    /// Digest of the complete executable plan.
    pub plan_digest: &'a str,
    /// Digest of the negotiated capability set.
    pub capability_set_digest: &'a str,
    /// Ordered, enabled executable-path manifest.
    pub paths: &'a [Decision0009PathInput<'a>],
}

impl<'a> Decision0009PreflightInput<'a> {
    /// Creates a preflight input from the complete ordered path manifest.
    #[must_use]
    pub const fn new(
        mode: Decision0009Mode,
        profile_id: &'a str,
        plan_digest: &'a str,
        capability_set_digest: &'a str,
        paths: &'a [Decision0009PathInput<'a>],
    ) -> Self {
        Self {
            mode,
            profile_id,
            plan_digest,
            capability_set_digest,
            paths,
        }
    }
}

impl fmt::Debug for Decision0009PreflightInput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Decision0009PreflightInput")
            .field("mode", &self.mode)
            .field("has_profile_id", &(!self.profile_id.is_empty()))
            .field("has_plan_digest", &(!self.plan_digest.is_empty()))
            .field(
                "has_capability_set_digest",
                &(!self.capability_set_digest.is_empty()),
            )
            .field("path_count", &self.paths.len())
            .finish()
    }
}

/// Borrowed input for the terminal disposition of a complete preflight.
pub struct Decision0009DispositionInput<'a> {
    /// Terminal admission disposition.
    pub disposition: Decision0009Disposition,
    /// Stable rejection reason when the disposition is rejected.
    pub rejection: Option<Decision0009CapabilityRejectionKind>,
    /// Source identity associated with the first rejecting path, when known.
    pub source: Option<&'a str>,
    /// Bounded diagnostic detail, when supplied by the classifier.
    pub detail: Option<&'a str>,
}

impl<'a> Decision0009DispositionInput<'a> {
    /// Creates an accepted disposition.
    #[must_use]
    pub const fn accepted() -> Self {
        Self {
            disposition: Decision0009Disposition::Accepted,
            rejection: None,
            source: None,
            detail: None,
        }
    }

    /// Creates a rejected disposition with a stable reason.
    #[must_use]
    pub const fn rejected(rejection: Decision0009CapabilityRejectionKind) -> Self {
        Self {
            disposition: Decision0009Disposition::Rejected,
            rejection: Some(rejection),
            source: None,
            detail: None,
        }
    }

    /// Adds the source identity associated with a rejection.
    #[must_use]
    pub const fn with_source(mut self, source: &'a str) -> Self {
        self.source = Some(source);
        self
    }

    /// Adds bounded classifier detail.
    #[must_use]
    pub const fn with_detail(mut self, detail: &'a str) -> Self {
        self.detail = Some(detail);
        self
    }
}

impl fmt::Debug for Decision0009DispositionInput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Decision0009DispositionInput")
            .field("disposition", &self.disposition)
            .field("rejection", &self.rejection)
            .field("has_source", &self.source.is_some())
            .field("has_detail", &self.detail.is_some())
            .finish()
    }
}

/// Errors returned while constructing a bounded Decision 0009 observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Decision0009TelemetryError {
    /// A required text field was empty.
    EmptyText {
        /// Canonical field name.
        field: &'static str,
    },
    /// A text field exceeds the module's pre-allocation bound.
    TextTooLong {
        /// Canonical field name.
        field: &'static str,
        /// Input length in bytes.
        actual: usize,
        /// Maximum accepted length.
        maximum: usize,
    },
    /// The path manifest exceeds the bounded telemetry limit.
    PathLimitExceeded {
        /// Maximum accepted path count.
        maximum: usize,
    },
    /// A source identity was repeated in the ordered manifest.
    DuplicateSource,
    /// An executable path omitted its capability token.
    MissingCapability,
    /// An unavailable path omitted its reason detail.
    MissingDetail,
    /// A rejected disposition omitted its stable rejection kind.
    MissingRejection,
    /// An accepted disposition carried a rejection kind.
    UnexpectedRejection,
    /// An event was supplied an unassigned sequence identity.
    InvalidSequence,
    /// The shared observe event rejected a field due to policy limits.
    Observe(ObserveError),
}

impl Decision0009TelemetryError {
    /// Returns a stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::EmptyText { .. } => "decision0009.input.empty",
            Self::TextTooLong { .. } => "decision0009.input.too-long",
            Self::PathLimitExceeded { .. } => "decision0009.paths.limit",
            Self::DuplicateSource => "decision0009.paths.duplicate-source",
            Self::MissingCapability => "decision0009.path.capability-missing",
            Self::MissingDetail => "decision0009.path.detail-missing",
            Self::MissingRejection => "decision0009.disposition.rejection-missing",
            Self::UnexpectedRejection => "decision0009.disposition.rejection-unexpected",
            Self::InvalidSequence => "decision0009.sequence.invalid",
            Self::Observe(error) => error.code(),
        }
    }
}

impl fmt::Display for Decision0009TelemetryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyText { field } => write!(formatter, "{} ({field})", self.code()),
            Self::TextTooLong {
                field,
                actual,
                maximum,
            } => write!(formatter, "{} ({field}: {actual} > {maximum})", self.code()),
            Self::PathLimitExceeded { maximum } => {
                write!(formatter, "{} ({maximum})", self.code())
            }
            Self::DuplicateSource
            | Self::MissingCapability
            | Self::MissingDetail
            | Self::MissingRejection
            | Self::UnexpectedRejection
            | Self::InvalidSequence => formatter.write_str(self.code()),
            Self::Observe(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for Decision0009TelemetryError {}

impl From<ObserveError> for Decision0009TelemetryError {
    fn from(error: ObserveError) -> Self {
        Self::Observe(error)
    }
}

/// Runtime-neutral adapter for Decision 0009 preflight and disposition data.
#[derive(Clone, Debug)]
pub struct Decision0009Telemetry {
    policy: RedactionPolicy,
}

impl Default for Decision0009Telemetry {
    fn default() -> Self {
        Self::new(RedactionPolicy::new())
    }
}

impl Decision0009Telemetry {
    /// Creates an adapter retaining the caller's central redaction policy.
    #[must_use]
    pub fn new(policy: RedactionPolicy) -> Self {
        Self { policy }
    }

    /// Returns the retained policy without exposing configured secrets.
    #[must_use]
    pub fn redaction_policy(&self) -> &RedactionPolicy {
        &self.policy
    }

    /// Maps a complete ordered plan preflight into one bounded event.
    pub fn preflight(
        &self,
        input: &Decision0009PreflightInput<'_>,
        timestamp: Timestamp,
        sequence: SequenceId,
    ) -> Result<DiagnosticEvent, Decision0009TelemetryError> {
        if !sequence.is_valid() {
            return Err(Decision0009TelemetryError::InvalidSequence);
        }
        validate_text(input.profile_id, "profile_id", true)?;
        validate_text(input.plan_digest, "plan_digest", true)?;
        validate_text(input.capability_set_digest, "capability_set_digest", true)?;
        let counts = Decision0009PathCount::from_paths(input.paths)?;
        ensure_unique_sources(input.paths)?;
        let mut event = DiagnosticEvent::new_timed(
            self.policy.clone(),
            "capability.plan.preflight",
            Severity::Info,
            DiagnosticCategory::Observation,
            timestamp,
            sequence,
        )
        .with_error_code("decision0009.preflight");
        add_field(&mut event, "decision.mode", input.mode.as_str())?;
        add_identity(
            &self.policy,
            &mut event,
            "decision.profile_id",
            input.profile_id,
        )?;
        add_identity(
            &self.policy,
            &mut event,
            "decision.plan_digest",
            input.plan_digest,
        )?;
        add_identity(
            &self.policy,
            &mut event,
            "decision.capability_set_digest",
            input.capability_set_digest,
        )?;
        add_count(&mut event, "decision.path_count", counts.total())?;
        add_count(&mut event, "decision.native_paths", counts.native)?;
        add_count(&mut event, "decision.compat_jvm_paths", counts.compat_jvm)?;
        add_count(&mut event, "decision.compat_rmi_paths", counts.compat_rmi)?;
        add_count(&mut event, "decision.unavailable_paths", counts.unavailable)?;
        add_field(
            &mut event,
            "decision.path_manifest_digest",
            &format!("h:{:016x}", manifest_digest(input.paths)),
        )?;
        Ok(event)
    }

    /// Alias for adapters which name the operation `plan_preflight`.
    pub fn plan_preflight(
        &self,
        input: &Decision0009PreflightInput<'_>,
        timestamp: Timestamp,
        sequence: SequenceId,
    ) -> Result<DiagnosticEvent, Decision0009TelemetryError> {
        self.preflight(input, timestamp, sequence)
    }

    /// Maps a terminal accepted/rejected disposition into one bounded event.
    pub fn disposition(
        &self,
        input: &Decision0009DispositionInput<'_>,
        timestamp: Timestamp,
        sequence: SequenceId,
    ) -> Result<DiagnosticEvent, Decision0009TelemetryError> {
        if !sequence.is_valid() {
            return Err(Decision0009TelemetryError::InvalidSequence);
        }
        match (input.disposition, input.rejection) {
            (Decision0009Disposition::Accepted, Some(_)) => {
                return Err(Decision0009TelemetryError::UnexpectedRejection);
            }
            (Decision0009Disposition::Rejected, None) => {
                return Err(Decision0009TelemetryError::MissingRejection);
            }
            _ => {}
        }
        if let Some(source) = input.source {
            validate_text(source, "source", true)?;
        }
        if let Some(detail) = input.detail {
            validate_text(detail, "detail", false)?;
        }
        let (severity, category, code) = match (input.disposition, input.rejection) {
            (Decision0009Disposition::Accepted, None) => (
                Severity::Info,
                DiagnosticCategory::Observation,
                "decision0009.admitted",
            ),
            (Decision0009Disposition::Accepted, Some(_)) => {
                return Err(Decision0009TelemetryError::UnexpectedRejection);
            }
            (Decision0009Disposition::Rejected, Some(rejection)) => (
                Severity::Error,
                DiagnosticCategory::Unsupported,
                rejection.code(),
            ),
            (Decision0009Disposition::Rejected, None) => {
                return Err(Decision0009TelemetryError::MissingRejection);
            }
        };
        let mut event = DiagnosticEvent::new_timed(
            self.policy.clone(),
            "capability.plan.disposition",
            severity,
            category,
            timestamp,
            sequence,
        )
        .with_error_code(code);
        add_field(
            &mut event,
            "decision.disposition",
            input.disposition.as_str(),
        )?;
        if let Some(rejection) = input.rejection {
            add_field(&mut event, "decision.rejection", rejection.as_str())?;
        }
        if let Some(source) = input.source {
            add_identity(&self.policy, &mut event, "decision.source", source)?;
        }
        if let Some(detail) = input.detail {
            add_field(&mut event, "decision.detail", detail)?;
        }
        Ok(event)
    }

    /// Alias for adapters which name the terminal operation `admission`.
    pub fn admission(
        &self,
        input: &Decision0009DispositionInput<'_>,
        timestamp: Timestamp,
        sequence: SequenceId,
    ) -> Result<DiagnosticEvent, Decision0009TelemetryError> {
        self.disposition(input, timestamp, sequence)
    }
}

fn validate_text(
    value: &str,
    field: &'static str,
    required: bool,
) -> Result<(), Decision0009TelemetryError> {
    if required && value.is_empty() {
        return Err(Decision0009TelemetryError::EmptyText { field });
    }
    if value.len() > MAX_DECISION0009_TEXT_BYTES {
        return Err(Decision0009TelemetryError::TextTooLong {
            field,
            actual: value.len(),
            maximum: MAX_DECISION0009_TEXT_BYTES,
        });
    }
    Ok(())
}

fn ensure_unique_sources(
    paths: &[Decision0009PathInput<'_>],
) -> Result<(), Decision0009TelemetryError> {
    let mut sources = BTreeSet::new();
    for path in paths {
        if !sources.insert(path.source) {
            return Err(Decision0009TelemetryError::DuplicateSource);
        }
    }
    Ok(())
}

fn manifest_digest(paths: &[Decision0009PathInput<'_>]) -> u64 {
    let mut digest = 0xcbf29ce484222325_u64;
    for path in paths {
        digest = digest_step(digest, path.kind.as_str().as_bytes());
        digest = digest_step(digest, path.source.as_bytes());
        if let Some(capability) = path.capability {
            digest = digest_step(digest, capability.as_bytes());
        }
        if let Some(detail) = path.detail {
            digest = digest_step(digest, detail.as_bytes());
        }
    }
    digest
}

fn digest_step(seed: u64, value: &[u8]) -> u64 {
    let mut digest = seed;
    for byte in value {
        digest ^= u64::from(*byte);
        digest = digest.wrapping_mul(0x100000001b3_u64);
    }
    // A separator makes adjacent fields unambiguous and keeps the digest
    // order-sensitive even when two values have the same byte set.
    digest ^= 0xff;
    digest.wrapping_mul(0x100000001b3_u64)
}

fn add_field(
    event: &mut DiagnosticEvent,
    key: &'static str,
    value: &str,
) -> Result<(), Decision0009TelemetryError> {
    event.add_field(key, value).map_err(Into::into)
}

fn add_count(
    event: &mut DiagnosticEvent,
    key: &'static str,
    value: u64,
) -> Result<(), Decision0009TelemetryError> {
    add_field(event, key, &value.to_string())
}

fn add_identity(
    policy: &RedactionPolicy,
    event: &mut DiagnosticEvent,
    key: &'static str,
    value: &str,
) -> Result<(), Decision0009TelemetryError> {
    let redacted = policy.redact_value(value);
    let stable = if redacted == value {
        redacted
    } else {
        format!("h:{:016x}", stable_digest(value.as_bytes()))
    };
    add_field(event, key, &stable)
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "deterministic telemetry fixtures use assertion-context setup"
)]
mod tests {
    use super::*;
    use crate::{RedactionLimits, Secret};

    fn policy() -> RedactionPolicy {
        RedactionPolicy::with_limits(RedactionLimits::new(32, 64, 128))
            .with_secret(Secret::try_new("telemetry-secret").expect("test secret"))
    }

    fn field<'a>(event: &'a DiagnosticEvent, key: &str) -> &'a str {
        event
            .fields()
            .iter()
            .find(|field| field.key() == key)
            .map(crate::DiagnosticField::value)
            .expect("field present")
    }

    fn native_paths() -> Vec<Decision0009PathInput<'static>> {
        vec![
            Decision0009PathInput::native("node/0", "http@1"),
            Decision0009PathInput::native("node/1", "controller@1"),
        ]
    }

    #[test]
    fn preflight_is_deterministic_and_accounts_for_each_path() {
        let paths = native_paths();
        let input = Decision0009PreflightInput::new(
            Decision0009Mode::StandaloneNative,
            "jmeter-5.6.3",
            "plan-digest",
            "capability-digest",
            &paths,
        );
        let adapter = Decision0009Telemetry::new(policy());
        let first = adapter
            .preflight(&input, Timestamp::new(3, 4), SequenceId::new(5))
            .expect("preflight");
        let second = adapter
            .preflight(&input, Timestamp::new(3, 4), SequenceId::new(5))
            .expect("preflight");
        assert_eq!(first, second);
        assert_eq!(field(&first, "decision.path_count"), "2");
        assert_eq!(field(&first, "decision.native_paths"), "2");
        assert_eq!(field(&first, "decision.compat_jvm_paths"), "0");
        assert_eq!(
            first.error_code().map(|code| code.as_str()),
            Some("decision0009.preflight")
        );
    }

    #[test]
    fn preflight_rejects_an_oversized_or_duplicate_manifest_before_mapping() {
        let too_many =
            vec![Decision0009PathInput::native("node", "http@1"); MAX_DECISION0009_PATHS + 1];
        assert_eq!(
            Decision0009PathCount::from_paths(&too_many),
            Err(Decision0009TelemetryError::PathLimitExceeded {
                maximum: MAX_DECISION0009_PATHS
            })
        );

        let paths = vec![
            Decision0009PathInput::native("same", "http@1"),
            Decision0009PathInput::native("same", "controller@1"),
        ];
        let input = Decision0009PreflightInput::new(
            Decision0009Mode::StandaloneNative,
            "profile",
            "plan",
            "capabilities",
            &paths,
        );
        let error = Decision0009Telemetry::new(policy())
            .preflight(&input, Timestamp::new(1, 1), SequenceId::new(1))
            .expect_err("duplicate source");
        assert_eq!(error, Decision0009TelemetryError::DuplicateSource);
    }

    #[test]
    fn rejected_disposition_has_stable_code_and_redacts_detail() {
        let input = Decision0009DispositionInput::rejected(
            Decision0009CapabilityRejectionKind::CompatibilityPackRequired,
        )
        .with_source("node/java")
        .with_detail("script uses telemetry-secret and must use the pinned pack");
        let event = Decision0009Telemetry::new(policy())
            .disposition(&input, Timestamp::new(7, 8), SequenceId::new(9))
            .expect("disposition");
        assert_eq!(event.severity(), Severity::Error);
        assert_eq!(
            event.error_code().map(|code| code.as_str()),
            Some("runtime.capability.compatibility-pack-required")
        );
        assert_eq!(
            field(&event, "decision.rejection"),
            "compatibility-pack-required"
        );
        assert!(!field(&event, "decision.detail").contains("telemetry-secret"));
    }

    #[test]
    fn accepted_and_rejected_dispositions_require_consistent_reason_data() {
        let accepted_with_reason = Decision0009DispositionInput {
            disposition: Decision0009Disposition::Accepted,
            rejection: Some(Decision0009CapabilityRejectionKind::Unavailable),
            source: None,
            detail: None,
        };
        assert_eq!(
            Decision0009Telemetry::default()
                .disposition(
                    &accepted_with_reason,
                    Timestamp::default(),
                    SequenceId::new(1)
                )
                .expect_err("accepted reason must be rejected"),
            Decision0009TelemetryError::UnexpectedRejection
        );
        let rejected_without_reason = Decision0009DispositionInput {
            disposition: Decision0009Disposition::Rejected,
            rejection: None,
            source: None,
            detail: None,
        };
        assert_eq!(
            Decision0009Telemetry::default()
                .disposition(
                    &rejected_without_reason,
                    Timestamp::default(),
                    SequenceId::new(1)
                )
                .expect_err("rejected disposition needs a reason"),
            Decision0009TelemetryError::MissingRejection
        );
    }

    #[test]
    fn zero_sequence_and_missing_path_identity_fail_closed() {
        let paths = [Decision0009PathInput::new(
            "node/0",
            Decision0009PathKind::Native,
            None,
            None,
        )];
        assert_eq!(
            Decision0009PathCount::from_paths(&paths),
            Err(Decision0009TelemetryError::MissingCapability)
        );
        let good = [Decision0009PathInput::native("node/0", "http@1")];
        let input = Decision0009PreflightInput::new(
            Decision0009Mode::StandaloneNative,
            "profile",
            "plan",
            "capabilities",
            &good,
        );
        assert_eq!(
            Decision0009Telemetry::default()
                .preflight(&input, Timestamp::default(), SequenceId::default())
                .expect_err("zero sequence"),
            Decision0009TelemetryError::InvalidSequence
        );
    }
}
