// SPDX-License-Identifier: Apache-2.0
//! Run-owned, executor-neutral result routing.
//!
//! A result collector is a run resource, not a component cloned into every
//! virtual user.  This module consequently only owns immutable event
//! envelopes and bounded delivery queues.  It deliberately knows nothing
//! about JTL codecs, report algorithms, files, or executors.  Applications and
//! the `results`/`report` crates provide [`ResultSink`] implementations at the
//! effectful edge.

#![allow(
    clippy::type_complexity,
    reason = "boxed standard-library futures are the executor-neutral sink contract"
)]
#![allow(
    dead_code,
    reason = "revision 3 contract is re-exported by the consolidation-owned runtime facade"
)]
#![allow(
    deprecated,
    reason = "legacy lifecycle adapters remain callable until consolidation adopts revision 3"
)]

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::future::{self, Future};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::Waker;

use jmeter_rs_model::NodeId;
use jmeter_rs_results::{
    AssertionOutcome, LogicalAction, RunIdentity, SampleEvent, SampleResult, ThreadIdentity,
    TransactionState, ValidationLimits,
};
use jmeter_rs_results::{
    ByteCount, ConnectTime, ElapsedTime, ErrorCount, IdleTime, Latency, SampleCount, ThreadCount,
    WallTimestamp,
};

const MAX_PLAN_PATH: usize = 4_096;
const MAX_SINKS: usize = 4_096;
const MAX_DIAGNOSTIC_BYTES: usize = 4_096;

fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// Revision 3 typed routing contract
// ---------------------------------------------------------------------------
//
// The original API above is retained temporarily for the runtime/lifecycle
// consolidation.  It is deliberately a compatibility adapter: its textual
// and document-local identities cannot satisfy the revision 3 contract.  New
// code should use the domain-qualified types below.  Keeping this boundary in
// the pure runtime crate lets the application, results, and report crates
// migrate without introducing a filesystem, Tokio, or executor dependency.

const MAX_TYPED_DIAGNOSTIC_BYTES: usize = 4_096;
const MAX_PLAN_DOMAIN_BYTES: usize = 1_048_576;
const MAX_TYPED_PLAN_PATH: usize = 4_096;
const MAX_LEDGER_TRANSITIONS: usize = 1_000_000;
const MAX_IDENTITY_TEXT_BYTES: usize = 4_096;
const MAX_PROFILE_CAPABILITIES: usize = 4_096;

/// Appends a length-delimited field tag.  Every canonical identity and
/// payload field uses this helper so adjacent values cannot be confused with
/// a different field layout.
fn append_canonical_tag(value: &mut Vec<u8>, tag: &[u8]) {
    value.extend_from_slice(&(tag.len() as u32).to_be_bytes());
    value.extend_from_slice(tag);
}

fn append_canonical_bytes(value: &mut Vec<u8>, tag: &[u8], bytes: &[u8]) {
    append_canonical_tag(value, tag);
    value.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    value.extend_from_slice(bytes);
}

fn append_canonical_text(value: &mut Vec<u8>, tag: &[u8], text: &str) {
    append_canonical_bytes(value, tag, text.as_bytes());
}

fn append_canonical_u64(value: &mut Vec<u8>, tag: &[u8], number: u64) {
    append_canonical_bytes(value, tag, &number.to_be_bytes());
}

fn append_canonical_i64(value: &mut Vec<u8>, tag: &[u8], number: i64) {
    append_canonical_bytes(value, tag, &number.to_be_bytes());
}

fn append_canonical_bool(value: &mut Vec<u8>, tag: &[u8], flag: bool) {
    append_canonical_bytes(value, tag, &[u8::from(flag)]);
}

fn append_optional_canonical_bytes(value: &mut Vec<u8>, tag: &[u8], bytes: Option<&[u8]>) {
    append_canonical_tag(value, tag);
    match bytes {
        Some(bytes) => {
            value.push(1);
            value.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            value.extend_from_slice(bytes);
        }
        None => value.push(0),
    }
}

fn append_optional_canonical_text(value: &mut Vec<u8>, tag: &[u8], text: Option<&str>) {
    append_optional_canonical_bytes(value, tag, text.map(str::as_bytes));
}

fn append_optional_canonical_u64(value: &mut Vec<u8>, tag: &[u8], number: Option<u64>) {
    append_canonical_tag(value, tag);
    match number {
        Some(number) => {
            value.push(1);
            value.extend_from_slice(&number.to_be_bytes());
        }
        None => value.push(0),
    }
}

fn append_optional_canonical_i64(value: &mut Vec<u8>, tag: &[u8], number: Option<i64>) {
    append_canonical_tag(value, tag);
    match number {
        Some(number) => {
            value.push(1);
            value.extend_from_slice(&number.to_be_bytes());
        }
        None => value.push(0),
    }
}

fn bounded_text_with_limit(mut value: String, limit: usize) -> String {
    if value.len() <= limit {
        return value;
    }
    let suffix = "...";
    let mut end = limit.saturating_sub(suffix.len());
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    value.push_str(suffix);
    value
}

/// A fixed-width SHA-256 digest used for plan, payload, and acknowledgement
/// binding.  The implementation is intentionally local so this pure crate
/// does not need a cryptography or executor dependency.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Digest32([u8; 32]);

impl Digest32 {
    /// Hashes one bounded in-memory value with SHA-256.
    #[must_use]
    pub fn sha256(value: &[u8]) -> Self {
        Self(sha256_bytes(value))
    }

    /// Hashes tagged parts without concatenating them first.
    #[must_use]
    pub fn sha256_parts(parts: &[&[u8]]) -> Self {
        let mut value = Vec::new();
        for part in parts {
            value.extend_from_slice(part);
        }
        Self::sha256(&value)
    }

    /// Restores a digest from its canonical fixed-width representation.
    pub const fn from_bytes(value: [u8; 32]) -> Self {
        Self(value)
    }

    /// Returns the canonical bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Returns whether this value is the reserved all-zero value.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        let mut index = 0;
        while index < self.0.len() {
            if self.0[index] != 0 {
                return false;
            }
            index += 1;
        }
        true
    }
}

impl fmt::Debug for Digest32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Digest32")
            .field(&hex_digest(self.0))
            .finish()
    }
}

impl fmt::Display for Digest32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex_digest(self.0))
    }
}

/// A stable identity-construction error.  It is intentionally independent of
/// sink errors so callers can distinguish malformed identity from I/O.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentityError {
    /// A required nonzero identity was constructed with zero.
    Zero { field: &'static str },
    /// A required byte or text identity was empty.
    Empty { field: &'static str },
    /// An identity exceeded its bounded representation.
    TooLong { field: &'static str, max: usize },
    /// An identity did not have its exact canonical width.
    WrongLength {
        field: &'static str,
        expected: usize,
    },
    /// A source reference belongs to a different plan domain.
    DomainMismatch,
    /// A bound identity was reused with different data.
    Collision,
    /// A canonical identity list was not sorted or contained a duplicate.
    NonCanonical { field: &'static str },
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero { field } => write!(formatter, "identity.{field}.zero"),
            Self::Empty { field } => write!(formatter, "identity.{field}.empty"),
            Self::TooLong { field, max } => write!(formatter, "identity.{field}.too-long({max})"),
            Self::WrongLength { field, expected } => {
                write!(formatter, "identity.{field}.wrong-length({expected})")
            }
            Self::DomainMismatch => formatter.write_str("identity.domain-mismatch"),
            Self::Collision => formatter.write_str("result.identity.collision"),
            Self::NonCanonical { field } => {
                write!(formatter, "identity.{field}.non-canonical")
            }
        }
    }
}

impl std::error::Error for IdentityError {}

/// The active compatibility profile identity bound into a plan domain.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProfileIdentity {
    id: String,
    version: String,
}

impl ProfileIdentity {
    /// Creates a bounded, non-empty profile identity.
    pub fn new(id: impl Into<String>, version: impl Into<String>) -> Result<Self, IdentityError> {
        let id = checked_identity_text(id.into(), "profile-id")?;
        let version = checked_identity_text(version.into(), "profile-version")?;
        Ok(Self { id, version })
    }

    /// Returns the profile identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the profile version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns canonical tagged bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        append_canonical_text(&mut bytes, b"profile-id", &self.id);
        append_canonical_text(&mut bytes, b"profile-version", &self.version);
        bytes
    }
}

/// One selected capability identity.  Capability versions are explicit so a
/// same-named capability with changed semantics cannot alias a prior domain.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CapabilityIdentity {
    id: String,
    version: String,
}

impl CapabilityIdentity {
    /// Creates a bounded, non-empty capability identity.
    pub fn new(id: impl Into<String>, version: impl Into<String>) -> Result<Self, IdentityError> {
        let id = checked_identity_text(id.into(), "capability-id")?;
        let version = checked_identity_text(version.into(), "capability-version")?;
        Ok(Self { id, version })
    }

    /// Returns the capability identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the capability version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns canonical tagged bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        append_canonical_text(&mut bytes, b"capability-id", &self.id);
        append_canonical_text(&mut bytes, b"capability-version", &self.version);
        bytes
    }
}

/// The profile plus the exact selected capability set used to compile a plan.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProfileCapabilityIdentity {
    profile: ProfileIdentity,
    capabilities: Arc<[CapabilityIdentity]>,
}

impl ProfileCapabilityIdentity {
    /// Creates a canonical identity. Capabilities must already be sorted and
    /// unique by `(id, version)`; callers can use [`Self::from_unsorted`] when
    /// collecting an unordered capability selection.
    pub fn new(
        profile: ProfileIdentity,
        capabilities: Vec<CapabilityIdentity>,
    ) -> Result<Self, IdentityError> {
        if capabilities.len() > MAX_PROFILE_CAPABILITIES {
            return Err(IdentityError::TooLong {
                field: "capabilities",
                max: MAX_PROFILE_CAPABILITIES,
            });
        }
        if capabilities.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(IdentityError::NonCanonical {
                field: "capabilities",
            });
        }
        Ok(Self {
            profile,
            capabilities: capabilities.into(),
        })
    }

    /// Creates a canonical identity from arbitrary input ordering.
    pub fn from_unsorted(
        profile: ProfileIdentity,
        mut capabilities: Vec<CapabilityIdentity>,
    ) -> Result<Self, IdentityError> {
        capabilities.sort();
        if capabilities.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(IdentityError::NonCanonical {
                field: "capabilities",
            });
        }
        Self::new(profile, capabilities)
    }

    /// Returns the active profile identity.
    #[must_use]
    pub fn profile(&self) -> &ProfileIdentity {
        &self.profile
    }

    /// Returns the selected capabilities in canonical order.
    #[must_use]
    pub fn capabilities(&self) -> &[CapabilityIdentity] {
        &self.capabilities
    }

    /// Returns the canonical profile/capability identity bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        append_canonical_bytes(&mut bytes, b"profile", &self.profile.canonical_bytes());
        append_canonical_u64(
            &mut bytes,
            b"capability-count",
            self.capabilities.len() as u64,
        );
        for capability in self.capabilities.iter() {
            append_canonical_bytes(&mut bytes, b"capability", &capability.canonical_bytes());
        }
        bytes
    }

    /// Returns the SHA-256 capability/profile-set digest.
    #[must_use]
    pub fn digest(&self) -> Digest32 {
        Digest32::sha256_parts(&[
            b"jmeter-rs.profile-capabilities.v4\0",
            &self.canonical_bytes(),
        ])
    }
}

fn checked_identity_text(value: String, field: &'static str) -> Result<String, IdentityError> {
    if value.is_empty() {
        return Err(IdentityError::Empty { field });
    }
    if value.len() > MAX_IDENTITY_TEXT_BYTES {
        return Err(IdentityError::TooLong {
            field,
            max: MAX_IDENTITY_TEXT_BYTES,
        });
    }
    if value.as_bytes().contains(&0)
        || value.trim() != value
        || !value.chars().all(|character| !character.is_control())
    {
        return Err(IdentityError::NonCanonical { field });
    }
    Ok(value)
}

/// The SHA-256 domain of one canonical executable plan and its import/module
/// namespace.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PlanDomain(Digest32);

impl PlanDomain {
    /// Hashes one canonical executable plan in the local import domain.
    #[deprecated(note = "use from_canonical_plan_and_identity with the active profile")]
    pub fn from_canonical_plan(plan: &[u8]) -> Result<Self, IdentityError> {
        Self::from_canonical_plan_and_import(plan, b"local")
    }

    /// Hashes a canonical executable plan together with its import/module
    /// domain and explicit active profile/capability identity. Length tags
    /// prevent concatenation ambiguity.
    pub fn from_canonical_plan_and_identity(
        plan: &[u8],
        import_domain: &[u8],
        profile_capabilities: &ProfileCapabilityIdentity,
    ) -> Result<Self, IdentityError> {
        if plan.is_empty() {
            return Err(IdentityError::Empty { field: "plan" });
        }
        if import_domain.is_empty() {
            return Err(IdentityError::Empty {
                field: "import-domain",
            });
        }
        if plan.len() > MAX_PLAN_DOMAIN_BYTES {
            return Err(IdentityError::TooLong {
                field: "plan",
                max: MAX_PLAN_DOMAIN_BYTES,
            });
        }
        if import_domain.len() > MAX_PLAN_DOMAIN_BYTES {
            return Err(IdentityError::TooLong {
                field: "import-domain",
                max: MAX_PLAN_DOMAIN_BYTES,
            });
        }
        let plan_len = (plan.len() as u64).to_be_bytes();
        let import_len = (import_domain.len() as u64).to_be_bytes();
        let profile_bytes = profile_capabilities.canonical_bytes();
        let profile_len = (profile_bytes.len() as u64).to_be_bytes();
        let digest = Digest32::sha256_parts(&[
            b"jmeter-rs.plan-domain.v4\0",
            &import_len,
            import_domain,
            &plan_len,
            plan,
            &profile_len,
            &profile_bytes,
        ]);
        Ok(Self(digest))
    }

    /// Convenience constructor for an explicit profile and selected
    /// capabilities.
    pub fn from_canonical_plan_and_profile(
        plan: &[u8],
        import_domain: &[u8],
        profile: ProfileIdentity,
        capabilities: Vec<CapabilityIdentity>,
    ) -> Result<Self, IdentityError> {
        let identity = ProfileCapabilityIdentity::from_unsorted(profile, capabilities)?;
        Self::from_canonical_plan_and_identity(plan, import_domain, &identity)
    }

    /// Hashes a canonical plan with explicit profile/capability text. This is
    /// useful at an adapter boundary where capability versions are absent from
    /// the upstream profile and therefore must be named as the supplied wire
    /// identity.
    pub fn from_canonical_plan_and_profile_text(
        plan: &[u8],
        import_domain: &[u8],
        profile_id: impl Into<String>,
        profile_version: impl Into<String>,
        capabilities: Vec<(String, String)>,
    ) -> Result<Self, IdentityError> {
        let profile = ProfileIdentity::new(profile_id, profile_version)?;
        let capabilities = capabilities
            .into_iter()
            .map(|(id, version)| CapabilityIdentity::new(id, version))
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_canonical_plan_and_profile(plan, import_domain, profile, capabilities)
    }

    /// Legacy profile-free constructor retained as an explicit compatibility
    /// adapter. Its generated identity is stable but does not claim an active
    /// compatibility profile.
    #[deprecated(note = "use from_canonical_plan_and_identity with the active profile")]
    pub fn from_canonical_plan_and_import(
        plan: &[u8],
        import_domain: &[u8],
    ) -> Result<Self, IdentityError> {
        let profile = ProfileIdentity::new("legacy-profile-free", "compat-v4")?;
        let identity = ProfileCapabilityIdentity::new(profile, Vec::new())?;
        Self::from_canonical_plan_and_identity(plan, import_domain, &identity)
    }

    /// Restores a nonzero plan domain digest.
    pub fn from_digest(digest: Digest32) -> Result<Self, IdentityError> {
        if digest.is_zero() {
            return Err(IdentityError::Zero {
                field: "plan-domain",
            });
        }
        Ok(Self(digest))
    }

    /// Returns the bound digest.
    #[must_use]
    pub const fn digest(self) -> Digest32 {
        self.0
    }
}

/// A document-local node reference qualified by its executable plan domain.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PlanNodeRef {
    plan_domain: PlanDomain,
    node_id: NodeId,
}

impl PlanNodeRef {
    /// Constructs a domain-qualified node reference.
    pub fn new(plan_domain: PlanDomain, node_id: NodeId) -> Result<Self, IdentityError> {
        if node_id.is_zero() {
            return Err(IdentityError::Zero { field: "node-id" });
        }
        Ok(Self {
            plan_domain,
            node_id,
        })
    }

    /// Constructs a reference from a raw nonzero node number.
    pub fn from_u64(plan_domain: PlanDomain, node_id: u64) -> Result<Self, IdentityError> {
        Self::new(plan_domain, NodeId::new(node_id))
    }

    /// Returns the plan domain.
    #[must_use]
    pub const fn plan_domain(self) -> PlanDomain {
        self.plan_domain
    }

    /// Returns the document-local node identity.
    #[must_use]
    pub const fn node_id(self) -> NodeId {
        self.node_id
    }

    /// Returns canonical big-endian bytes for this domain-qualified node.
    #[must_use]
    pub fn canonical_bytes(self) -> [u8; 40] {
        let mut bytes = [0u8; 40];
        bytes[..32].copy_from_slice(&self.plan_domain.digest().as_bytes());
        bytes[32..].copy_from_slice(&self.node_id.get().to_be_bytes());
        bytes
    }
}

/// A nonzero run identity represented in a fixed-width canonical form.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TypedRunId([u8; 16]);

impl TypedRunId {
    /// Derives the fixed-width run identity from the immutable result-event
    /// run identity.  Empty textual run identities are rejected rather than
    /// becoming an implicit sentinel.
    pub fn from_run_identity(value: &RunIdentity) -> Result<Self, IdentityError> {
        if value.as_str().is_empty() {
            return Err(IdentityError::Empty { field: "run-id" });
        }
        if value.as_str().len() > MAX_IDENTITY_TEXT_BYTES {
            return Err(IdentityError::TooLong {
                field: "run-id",
                max: MAX_IDENTITY_TEXT_BYTES,
            });
        }
        let digest = Digest32::sha256_parts(&[b"jmeter-rs.run-id.v3\0", value.as_str().as_bytes()]);
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest.as_bytes()[..16]);
        Self::from_bytes(bytes)
    }

    /// Creates a run identity from a nonzero integer.
    pub fn from_u128(value: u128) -> Result<Self, IdentityError> {
        if value == 0 {
            return Err(IdentityError::Zero { field: "run-id" });
        }
        Ok(Self(value.to_be_bytes()))
    }

    /// Restores a run identity from its exact wire width.
    pub fn from_bytes(value: [u8; 16]) -> Result<Self, IdentityError> {
        if value.iter().all(|byte| *byte == 0) {
            return Err(IdentityError::Zero { field: "run-id" });
        }
        Ok(Self(value))
    }

    /// Returns canonical bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }
}

/// Revision 3 spelling for the fixed-width run identity.
pub type RunId = TypedRunId;

/// A nonzero generation of a run identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RunGeneration(u64);

impl RunGeneration {
    /// Creates a generation; zero is reserved as absent.
    pub fn new(value: u64) -> Result<Self, IdentityError> {
        nonzero_u64(value, "run-generation").map(Self)
    }

    /// Returns the numeric generation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A nonzero worker identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WorkerId(u64);

impl WorkerId {
    /// Creates a worker identity.
    pub fn new(value: u64) -> Result<Self, IdentityError> {
        nonzero_u64(value, "worker-id").map(Self)
    }

    /// Returns the numeric worker identity.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A nonzero generation of a worker identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WorkerGeneration(u64);

impl WorkerGeneration {
    /// Creates a worker generation.
    pub fn new(value: u64) -> Result<Self, IdentityError> {
        nonzero_u64(value, "worker-generation").map(Self)
    }

    /// Returns the numeric generation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A nonzero sample/event sequence assigned monotonically by one run.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TypedRunSequence(u64);

impl TypedRunSequence {
    /// Creates a nonzero sequence.
    pub fn new(value: u64) -> Result<Self, IdentityError> {
        nonzero_u64(value, "run-sequence").map(Self)
    }

    /// Returns the numeric sequence.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A nonzero sample invocation identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TypedSampleId(u64);

impl TypedSampleId {
    /// Creates a sample identity; absence must use `Option`, never zero.
    pub fn new(value: u64) -> Result<Self, IdentityError> {
        nonzero_u64(value, "sample-id").map(Self)
    }

    /// Returns the numeric sample identity.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Revision 3 spelling for the payload digest.
pub type PayloadDigest = Digest32;
/// Revision 3 spelling for the typed sequence.
pub type EventSequence = TypedRunSequence;
/// Explicit versioned spelling for the typed run sequence.
pub type RunSequenceV3 = TypedRunSequence;
/// Revision 3 spelling for the typed sample identity.
pub type SampleId = TypedSampleId;
/// Explicit versioned spelling for the typed sample identity.
pub type SampleIdentityV3 = TypedSampleId;

/// A nonzero sink-plan generation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SinkPlanGeneration(u64);

impl SinkPlanGeneration {
    /// Creates a sink-plan generation.
    pub fn new(value: u64) -> Result<Self, IdentityError> {
        nonzero_u64(value, "sink-plan-generation").map(Self)
    }

    /// Returns the numeric generation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

fn nonzero_u64(value: u64, field: &'static str) -> Result<u64, IdentityError> {
    if value == 0 {
        Err(IdentityError::Zero { field })
    } else {
        Ok(value)
    }
}

/// A sink identity bound to one run, sink-plan generation, and collector
/// node.  It is intentionally distinct from the deprecated numeric
/// [`SinkId`] compatibility adapter below.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct QualifiedSinkId {
    run_id: TypedRunId,
    sink_plan_generation: SinkPlanGeneration,
    collector: PlanNodeRef,
}

impl QualifiedSinkId {
    /// Constructs a fully bound sink identity.
    #[must_use]
    pub const fn from_parts(
        run_id: TypedRunId,
        sink_plan_generation: SinkPlanGeneration,
        collector: PlanNodeRef,
    ) -> Self {
        Self {
            run_id,
            sink_plan_generation,
            collector,
        }
    }

    /// Returns the run identity.
    #[must_use]
    pub const fn run_id(self) -> TypedRunId {
        self.run_id
    }

    /// Returns the sink-plan generation.
    #[must_use]
    pub const fn sink_plan_generation(self) -> SinkPlanGeneration {
        self.sink_plan_generation
    }

    /// Returns the domain-qualified collector node.
    #[must_use]
    pub const fn collector(self) -> PlanNodeRef {
        self.collector
    }

    /// Returns canonical big-endian bytes binding run, sink generation, and
    /// qualified collector identity.
    #[must_use]
    pub fn canonical_bytes(self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..16].copy_from_slice(&self.run_id.as_bytes());
        bytes[16..24].copy_from_slice(&self.sink_plan_generation.get().to_be_bytes());
        bytes[24..64].copy_from_slice(&self.collector.canonical_bytes());
        bytes
    }
}

/// Compatibility aliases for callers that prefer the terminology used in the
/// decision record.
pub type TypedSinkId = QualifiedSinkId;
/// Compatibility alias for the revision 3 sink identity.
pub type DomainSinkId = QualifiedSinkId;

/// Explicit sampler-versus-transaction origin with domain-qualified
/// controller parentage.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TypedResultOrigin {
    /// A direct sampler notification.
    Sampler {
        /// Sampler node.
        sampler: PlanNodeRef,
        /// Innermost enclosing transaction, when present.
        parent: Option<PlanNodeRef>,
    },
    /// A synthetic transaction-controller notification.
    Transaction {
        /// Transaction controller node.
        controller: PlanNodeRef,
        /// Enclosing transaction, when nested.
        parent: Option<PlanNodeRef>,
    },
}

impl TypedResultOrigin {
    /// Returns the source node.
    #[must_use]
    pub const fn source(self) -> PlanNodeRef {
        match self {
            Self::Sampler { sampler, .. } => sampler,
            Self::Transaction { controller, .. } => controller,
        }
    }

    /// Returns the optional enclosing transaction.
    #[must_use]
    pub const fn parent(self) -> Option<PlanNodeRef> {
        match self {
            Self::Sampler { parent, .. } | Self::Transaction { parent, .. } => parent,
        }
    }

    /// Returns whether the origin is synthetic transaction output.
    #[must_use]
    pub const fn is_transaction(self) -> bool {
        matches!(self, Self::Transaction { .. })
    }
}

/// User identity carried by a typed event envelope.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TypedUserIdentity {
    lifecycle_id: u64,
    group: PlanNodeRef,
    thread_number: u64,
    iteration: u64,
}

impl TypedUserIdentity {
    /// Creates a virtual-user identity.  Lifecycle and thread numbers are
    /// nonzero; iteration zero is a valid first iteration.
    pub fn new(
        lifecycle_id: u64,
        group: PlanNodeRef,
        thread_number: u64,
        iteration: u64,
    ) -> Result<Self, IdentityError> {
        nonzero_u64(lifecycle_id, "lifecycle-id")?;
        nonzero_u64(thread_number, "thread-number")?;
        Ok(Self {
            lifecycle_id,
            group,
            thread_number,
            iteration,
        })
    }

    /// Returns the lifecycle identity.
    #[must_use]
    pub const fn lifecycle_id(self) -> u64 {
        self.lifecycle_id
    }

    /// Returns the qualified owning group.
    #[must_use]
    pub const fn group(self) -> PlanNodeRef {
        self.group
    }

    /// Returns the one-based thread number.
    #[must_use]
    pub const fn thread_number(self) -> u64 {
        self.thread_number
    }

    /// Returns the zero-based iteration.
    #[must_use]
    pub const fn iteration(self) -> u64 {
        self.iteration
    }
}

/// An event identity whose digest binds the original payload snapshot.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EventId {
    run_id: TypedRunId,
    run_generation: RunGeneration,
    worker_id: WorkerId,
    worker_generation: WorkerGeneration,
    sequence: TypedRunSequence,
    payload_digest: Digest32,
}

impl EventId {
    /// Creates an event identity and binds its immutable payload digest.
    pub fn new(
        run_id: TypedRunId,
        run_generation: RunGeneration,
        worker_id: WorkerId,
        worker_generation: WorkerGeneration,
        sequence: TypedRunSequence,
        payload_digest: Digest32,
    ) -> Result<Self, IdentityError> {
        if payload_digest.is_zero() {
            return Err(IdentityError::Zero {
                field: "payload-digest",
            });
        }
        Ok(Self {
            run_id,
            run_generation,
            worker_id,
            worker_generation,
            sequence,
            payload_digest,
        })
    }

    /// Returns the run identity.
    #[must_use]
    pub const fn run_id(self) -> TypedRunId {
        self.run_id
    }

    /// Returns the run generation.
    #[must_use]
    pub const fn run_generation(self) -> RunGeneration {
        self.run_generation
    }

    /// Returns the worker identity.
    #[must_use]
    pub const fn worker_id(self) -> WorkerId {
        self.worker_id
    }

    /// Returns the worker generation.
    #[must_use]
    pub const fn worker_generation(self) -> WorkerGeneration {
        self.worker_generation
    }

    /// Returns the run sequence.
    #[must_use]
    pub const fn sequence(self) -> TypedRunSequence {
        self.sequence
    }

    /// Returns the immutable payload digest.
    #[must_use]
    pub const fn payload_digest(self) -> Digest32 {
        self.payload_digest
    }

    /// Returns canonical bytes for the event identity binding.
    #[must_use]
    pub fn canonical_bytes(self) -> [u8; 80] {
        let mut bytes = [0u8; 80];
        bytes[..16].copy_from_slice(&self.run_id.as_bytes());
        bytes[16..24].copy_from_slice(&self.run_generation.get().to_be_bytes());
        bytes[24..32].copy_from_slice(&self.worker_id.get().to_be_bytes());
        bytes[32..40].copy_from_slice(&self.worker_generation.get().to_be_bytes());
        bytes[40..48].copy_from_slice(&self.sequence.get().to_be_bytes());
        bytes[48..80].copy_from_slice(&self.payload_digest.as_bytes());
        bytes
    }
}

/// An immutable revision 3 result envelope.  The same `Arc<SampleEvent>` is
/// presented to every sink; this type has no reconstruction or lossy adapter
/// path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedResultEnvelope {
    event_id: EventId,
    run_text: RunIdentity,
    source: PlanNodeRef,
    plan_path: Arc<[PlanNodeRef]>,
    run: TypedRunId,
    run_generation: RunGeneration,
    worker: WorkerId,
    worker_generation: WorkerGeneration,
    user: TypedUserIdentity,
    thread: ThreadIdentity,
    sample: TypedSampleId,
    origin: TypedResultOrigin,
    event: Arc<SampleEvent>,
    byte_size: usize,
}

impl TypedResultEnvelope {
    /// Builds a typed envelope from the complete listener snapshot.
    #[allow(
        clippy::too_many_arguments,
        reason = "the envelope boundary deliberately names every identity"
    )]
    pub fn new(
        sequence: TypedRunSequence,
        run: TypedRunId,
        run_generation: RunGeneration,
        worker: WorkerId,
        worker_generation: WorkerGeneration,
        source: PlanNodeRef,
        plan_path: Vec<PlanNodeRef>,
        user: TypedUserIdentity,
        thread: ThreadIdentity,
        sample: TypedSampleId,
        origin: TypedResultOrigin,
        event: SampleEvent,
    ) -> Result<Self, IdentityError> {
        if plan_path.is_empty() || plan_path.len() > MAX_TYPED_PLAN_PATH {
            return Err(if plan_path.is_empty() {
                IdentityError::Empty { field: "plan-path" }
            } else {
                IdentityError::TooLong {
                    field: "plan-path",
                    max: MAX_TYPED_PLAN_PATH,
                }
            });
        }
        let domain = source.plan_domain();
        if plan_path.last().copied() != Some(source)
            || plan_path.iter().any(|node| node.plan_domain() != domain)
        {
            return Err(IdentityError::DomainMismatch);
        }
        if origin.source() != source {
            return Err(IdentityError::DomainMismatch);
        }
        if user.group().plan_domain() != domain {
            return Err(IdentityError::DomainMismatch);
        }
        if let Some(parent) = origin.parent()
            && parent.plan_domain() != domain
        {
            return Err(IdentityError::DomainMismatch);
        }
        event
            .result()
            .validate_with_limits(ValidationLimits::default())
            .map_err(|_| IdentityError::Collision)?;
        if TypedRunId::from_run_identity(event.run())? != run {
            return Err(IdentityError::Collision);
        }
        if event.thread() != &thread {
            return Err(IdentityError::Collision);
        }
        let payload_digest = typed_payload_digest(&event, source, &plan_path, user, sample, origin);
        let event_id = EventId::new(
            run,
            run_generation,
            worker,
            worker_generation,
            sequence,
            payload_digest,
        )?;
        let byte_size = estimate_event_bytes(&event)
            .saturating_add(
                plan_path
                    .len()
                    .saturating_mul(std::mem::size_of::<PlanNodeRef>()),
            )
            .saturating_add(std::mem::size_of::<Self>())
            .max(1);
        Ok(Self {
            event_id,
            run_text: event.run().clone(),
            source,
            plan_path: plan_path.into(),
            run,
            run_generation,
            worker,
            worker_generation,
            user,
            thread,
            sample,
            origin,
            event: Arc::new(event),
            byte_size,
        })
    }

    /// Returns the event identity.
    #[must_use]
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }

    /// Returns the immutable canonical digest of the original snapshot.
    #[must_use]
    pub const fn payload_digest(&self) -> Digest32 {
        self.event_id.payload_digest()
    }

    /// Returns the original snapshot.
    #[must_use]
    pub fn event(&self) -> &SampleEvent {
        &self.event
    }

    /// Returns the run's source text retained for wire compatibility.
    #[must_use]
    pub fn run_text(&self) -> &RunIdentity {
        &self.run_text
    }

    /// Returns the qualified source node.
    #[must_use]
    pub const fn source(&self) -> PlanNodeRef {
        self.source
    }

    /// Returns the ordered qualified plan path.
    #[must_use]
    pub fn plan_path(&self) -> &[PlanNodeRef] {
        &self.plan_path
    }

    /// Returns the typed run identity.
    #[must_use]
    pub const fn run(&self) -> TypedRunId {
        self.run
    }

    /// Returns the run generation.
    #[must_use]
    pub const fn run_generation(&self) -> RunGeneration {
        self.run_generation
    }

    /// Returns the worker identity.
    #[must_use]
    pub const fn worker(&self) -> WorkerId {
        self.worker
    }

    /// Returns the worker generation.
    #[must_use]
    pub const fn worker_generation(&self) -> WorkerGeneration {
        self.worker_generation
    }

    /// Returns user identity.
    #[must_use]
    pub const fn user(&self) -> TypedUserIdentity {
        self.user
    }

    /// Returns thread identity.
    #[must_use]
    pub fn thread(&self) -> &ThreadIdentity {
        &self.thread
    }

    /// Returns sample identity.
    #[must_use]
    pub const fn sample(&self) -> TypedSampleId {
        self.sample
    }

    /// Returns origin and transaction parentage.
    #[must_use]
    pub const fn origin(&self) -> TypedResultOrigin {
        self.origin
    }

    /// Returns bounded accounting bytes.
    #[must_use]
    pub const fn byte_size(&self) -> usize {
        self.byte_size
    }
}

/// A short name for the typed envelope used by the decision record.
pub type ResultEnvelopeV3 = TypedResultEnvelope;
/// Explicitly named immutable revision 3 envelope alias.
pub type ImmutableResultEnvelope = TypedResultEnvelope;
/// Explicitly named revision 3 sink identity alias.
pub type SinkIdV3 = QualifiedSinkId;

fn hex_digest(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(64);
    for byte in bytes {
        value.push(char::from(HEX[(byte >> 4) as usize]));
        value.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    value
}

fn sha256_bytes(input: &[u8]) -> [u8; 32] {
    // FIPS 180-4, section 6.2.2.  This small implementation is suitable for
    // bounded event/configuration identities and keeps the router executor
    // and dependency neutral.
    const INITIAL: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    const ROUND: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];
    let bit_len = (input.len() as u64).saturating_mul(8);
    let padded_len = input
        .len()
        .saturating_add(1)
        .saturating_add(8)
        .saturating_add(63)
        & !63;
    let mut padded = Vec::with_capacity(padded_len);
    padded.extend_from_slice(input);
    padded.push(0x80);
    padded.resize(padded_len.saturating_sub(8), 0);
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut hash = INITIAL;
    for chunk in padded.chunks_exact(64) {
        let mut schedule = [0u32; 64];
        for (index, word) in schedule.iter_mut().take(16).enumerate() {
            let offset = index * 4;
            *word = u32::from_be_bytes([
                chunk[offset],
                chunk[offset + 1],
                chunk[offset + 2],
                chunk[offset + 3],
            ]);
        }
        for index in 16..64 {
            let first = schedule[index - 15];
            let second = schedule[index - 2];
            let sigma0 = first.rotate_right(7) ^ first.rotate_right(18) ^ (first >> 3);
            let sigma1 = second.rotate_right(17) ^ second.rotate_right(19) ^ (second >> 10);
            schedule[index] = schedule[index - 16]
                .wrapping_add(sigma0)
                .wrapping_add(schedule[index - 7])
                .wrapping_add(sigma1);
        }
        let mut state = hash;
        for index in 0..64 {
            let sigma1 =
                state[4].rotate_right(6) ^ state[4].rotate_right(11) ^ state[4].rotate_right(25);
            let choose = (state[4] & state[5]) ^ ((!state[4]) & state[6]);
            let temp1 = state[7]
                .wrapping_add(sigma1)
                .wrapping_add(choose)
                .wrapping_add(ROUND[index])
                .wrapping_add(schedule[index]);
            let sigma0 =
                state[0].rotate_right(2) ^ state[0].rotate_right(13) ^ state[0].rotate_right(22);
            let majority = (state[0] & state[1]) ^ (state[0] & state[2]) ^ (state[1] & state[2]);
            let temp2 = sigma0.wrapping_add(majority);
            state[7] = state[6];
            state[6] = state[5];
            state[5] = state[4];
            state[4] = state[3].wrapping_add(temp1);
            state[3] = state[2];
            state[2] = state[1];
            state[1] = state[0];
            state[0] = temp1.wrapping_add(temp2);
        }
        for index in 0..8 {
            hash[index] = hash[index].wrapping_add(state[index]);
        }
    }
    let mut output = [0u8; 32];
    for (index, word) in hash.into_iter().enumerate() {
        output[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    output
}

fn typed_payload_digest(
    event: &SampleEvent,
    source: PlanNodeRef,
    plan_path: &[PlanNodeRef],
    user: TypedUserIdentity,
    sample: TypedSampleId,
    origin: TypedResultOrigin,
) -> Digest32 {
    let mut value = Vec::new();
    append_canonical_tag(&mut value, b"sample-event");
    append_plan_node(&mut value, b"source", source);
    append_canonical_u64(&mut value, b"plan-path-count", plan_path.len() as u64);
    for (index, node) in plan_path.iter().copied().enumerate() {
        append_plan_node(&mut value, b"plan-path-node", node);
        append_canonical_u64(&mut value, b"plan-path-index", index as u64);
    }
    append_canonical_u64(&mut value, b"user-lifecycle", user.lifecycle_id());
    append_plan_node(&mut value, b"user-group", user.group());
    append_canonical_u64(&mut value, b"user-thread-number", user.thread_number());
    append_canonical_u64(&mut value, b"user-iteration", user.iteration());
    append_canonical_u64(&mut value, b"sample-id", sample.get());
    append_origin(&mut value, origin);

    append_canonical_text(&mut value, b"run", event.run().as_str());
    append_canonical_text(&mut value, b"host", event.host().as_str());
    append_thread_identity_v4(&mut value, event.thread());
    append_canonical_u64(
        &mut value,
        b"variable-count",
        event.variables().len() as u64,
    );
    for (name, variable) in event.variables().iter() {
        append_canonical_text(&mut value, b"variable-name", name);
        append_optional_canonical_text(&mut value, b"variable-value", variable.as_str());
    }
    append_transaction_state(&mut value, event.transaction_state());
    append_result_digest_v4(&mut value, event.result());
    Digest32::sha256_parts(&[b"jmeter-rs.result-payload.v4\0", &value])
}

fn append_plan_node(value: &mut Vec<u8>, tag: &[u8], node: PlanNodeRef) {
    let bytes = node.canonical_bytes();
    append_canonical_bytes(value, tag, &bytes);
}

fn append_optional_plan_node(value: &mut Vec<u8>, tag: &[u8], node: Option<PlanNodeRef>) {
    append_canonical_tag(value, tag);
    match node {
        Some(node) => {
            value.push(1);
            value.extend_from_slice(&node.canonical_bytes());
        }
        None => value.push(0),
    }
}

fn append_origin(value: &mut Vec<u8>, origin: TypedResultOrigin) {
    append_canonical_tag(value, b"origin");
    match origin {
        TypedResultOrigin::Sampler { sampler, parent } => {
            value.push(1);
            append_plan_node(value, b"origin-sampler", sampler);
            append_optional_plan_node(value, b"origin-parent", parent);
        }
        TypedResultOrigin::Transaction { controller, parent } => {
            value.push(2);
            append_plan_node(value, b"origin-controller", controller);
            append_optional_plan_node(value, b"origin-parent", parent);
        }
    }
}

fn append_thread_identity_v4(value: &mut Vec<u8>, thread: &ThreadIdentity) {
    append_canonical_text(value, b"thread-name", thread.name());
    append_optional_canonical_text(value, b"thread-group", thread.group());
    append_optional_canonical_u64(value, b"thread-number", thread.number());
}

fn append_transaction_state(value: &mut Vec<u8>, state: Option<TransactionState>) {
    append_canonical_tag(value, b"transaction-state");
    value.push(match state {
        None => 0,
        Some(TransactionState::Start) => 1,
        Some(TransactionState::End) => 2,
    });
}

fn append_result_digest_v4(value: &mut Vec<u8>, result: &SampleResult) {
    append_canonical_tag(value, b"result");
    append_optional_canonical_text(value, b"label", result.label_field());
    append_optional_canonical_bool(value, b"success", result.success());
    append_optional_canonical_i64(
        value,
        b"timestamp",
        result.timestamp().map(WallTimestamp::as_millis),
    );
    append_optional_canonical_i64(
        value,
        b"start-time",
        result.start_time().map(WallTimestamp::as_millis),
    );
    append_optional_canonical_i64(
        value,
        b"end-time",
        result.end_time().map(WallTimestamp::as_millis),
    );
    append_optional_canonical_u64(
        value,
        b"elapsed",
        result.elapsed().map(ElapsedTime::as_millis),
    );
    append_optional_canonical_u64(value, b"latency", result.latency().map(Latency::as_millis));
    append_optional_canonical_u64(
        value,
        b"connect-time",
        result.connect_time().map(ConnectTime::as_millis),
    );
    append_optional_canonical_u64(
        value,
        b"idle-time",
        result.idle_time().map(IdleTime::as_millis),
    );
    append_optional_canonical_text(value, b"response-code", result.response_code());
    append_optional_canonical_text(value, b"response-message", result.response_message());
    append_optional_canonical_text(value, b"failure-message", result.failure_message());
    append_optional_canonical_text(
        value,
        b"data-type",
        result.data_type().map(|data_type| data_type.as_wire()),
    );
    append_optional_canonical_text(
        value,
        b"data-encoding",
        result.data_encoding().map(|encoding| encoding.as_str()),
    );
    append_optional_canonical_bytes(
        value,
        b"request-data",
        result.request_data().map(|data| data.as_bytes()),
    );
    append_optional_canonical_bytes(
        value,
        b"response-data",
        result.response_data().map(|data| data.as_bytes()),
    );
    append_optional_canonical_text(
        value,
        b"request-headers",
        result.request_headers().map(|headers| headers.as_str()),
    );
    append_optional_canonical_text(
        value,
        b"response-headers",
        result.response_headers().map(|headers| headers.as_str()),
    );
    append_optional_canonical_text(value, b"sampler-data", result.sampler_data());
    append_optional_canonical_text(value, b"response-file", result.response_file());
    append_optional_canonical_text(value, b"url", result.url());
    append_optional_canonical_u64(
        value,
        b"received-bytes",
        result.received_bytes().map(ByteCount::as_u64),
    );
    append_optional_canonical_u64(
        value,
        b"sent-bytes",
        result.sent_bytes().map(ByteCount::as_u64),
    );
    append_optional_canonical_u64(
        value,
        b"group-threads",
        result.group_threads().map(ThreadCount::as_u64),
    );
    append_optional_canonical_u64(
        value,
        b"all-threads",
        result.all_threads().map(ThreadCount::as_u64),
    );
    append_optional_canonical_u64(
        value,
        b"sample-count",
        result.sample_count().map(SampleCount::as_u64),
    );
    append_optional_canonical_u64(
        value,
        b"error-count",
        result.error_count().map(ErrorCount::as_u64),
    );

    let flags = result.flags();
    append_canonical_bool(value, b"flag-stop-thread", flags.stop_thread());
    append_canonical_bool(value, b"flag-stop-test", flags.stop_test());
    append_canonical_bool(value, b"flag-stop-test-now", flags.stop_test_now());
    append_canonical_bool(value, b"flag-start-next-loop", flags.start_next_loop());
    append_canonical_bool(value, b"flag-ignored", flags.ignored());
    append_canonical_tag(value, b"flag-logical-action");
    value.push(match flags.logical_action() {
        None => 0,
        Some(LogicalAction::Continue) => 1,
        Some(LogicalAction::StartNextIteration) => 2,
        Some(LogicalAction::StopThread) => 3,
        Some(LogicalAction::StopTest) => 4,
        Some(LogicalAction::StopTestNow) => 5,
    });

    append_canonical_u64(value, b"assertion-count", result.assertions().len() as u64);
    for assertion in result.assertions() {
        append_canonical_text(value, b"assertion-name", assertion.name());
        append_canonical_bool(value, b"assertion-failure", assertion.is_failure());
        append_canonical_bool(value, b"assertion-error", assertion.is_error());
        append_canonical_tag(value, b"assertion-outcome");
        value.push(match assertion.outcome() {
            AssertionOutcome::Passed => 1,
            AssertionOutcome::Failure => 2,
            AssertionOutcome::Error => 3,
        });
        append_optional_canonical_text(
            value,
            b"assertion-failure-message",
            assertion.failure_message(),
        );
        append_optional_canonical_text(
            value,
            b"assertion-error-message",
            assertion.error_message(),
        );
    }
    append_canonical_u64(
        value,
        b"sub-result-count",
        result.sub_results().len() as u64,
    );
    for child in result.sub_results() {
        append_result_digest_v4(value, child);
    }
}

fn append_optional_canonical_bool(value: &mut Vec<u8>, tag: &[u8], flag: Option<bool>) {
    append_canonical_tag(value, tag);
    match flag {
        Some(flag) => {
            value.push(1);
            value.push(u8::from(flag));
        }
        None => value.push(0),
    }
}

/// A bounded diagnostic retained in the ledger and finalization report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedDiagnostic(String);

impl BoundedDiagnostic {
    /// Creates a bounded diagnostic; excess text is deterministically clipped.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(bounded_text_with_limit(
            value.into(),
            MAX_TYPED_DIAGNOSTIC_BYTES,
        ))
    }

    /// Returns the redacted/bounded diagnostic text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BoundedDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// An explicit full-queue policy.  `DiagnosedDrop` is not a compatibility
/// policy and must be selected deliberately by the caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FullPolicy {
    /// Retry admission using the run's one shared remaining budget.
    Backpressure {
        /// A sink-local upper bound; attempts still consume the router's one
        /// shared run budget and can never reset it.
        deadline: RetryBudget,
    },
    /// Fail the run when this sink is full.
    FailRun,
    /// Record a named drop for a non-compatibility output.
    DiagnosedDrop {
        /// Stable reason retained in the ledger.
        reason: BoundedDiagnostic,
    },
}

/// A finite operation budget shared by backpressure and finalization retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryBudget {
    remaining: u32,
}

impl RetryBudget {
    /// Creates a budget.  Zero means exhausted, not absent.
    #[must_use]
    pub const fn new(remaining: u32) -> Self {
        Self { remaining }
    }

    /// Returns remaining attempts.
    #[must_use]
    pub const fn remaining(self) -> u32 {
        self.remaining
    }

    /// Consumes one attempt, returning whether it was available.
    pub fn consume(&mut self) -> bool {
        if self.remaining == 0 {
            false
        } else {
            self.remaining -= 1;
            true
        }
    }
}

/// Executor-neutral failure from a finite run operation budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetError {
    /// The caller's cancellation signal was raised.
    Cancelled,
    /// The monotonic deadline has elapsed.
    Expired,
    /// No retry attempt remains in the shared budget.
    RetryBudgetExhausted,
    /// The requested duration could not be represented by the clock domain.
    DeadlineOverflow,
}

impl fmt::Display for BudgetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Cancelled => "result.budget.cancelled",
            Self::Expired => "result.budget.expired",
            Self::RetryBudgetExhausted => "result.budget.retry-exhausted",
            Self::DeadlineOverflow => "result.budget.deadline-overflow",
        })
    }
}

impl std::error::Error for BudgetError {}

/// A caller-owned monotonic tick source.  The unit is deliberately opaque to
/// the router; adapters may use a timer wheel, virtual clock, or test clock.
pub trait MonotonicClock {
    /// Returns a non-decreasing tick value.
    fn now_ticks(&self) -> u64;
}

/// A caller-owned cancellation source.  Registration is advisory: callers
/// must still call [`RunOperationBudget::check`] at every bounded boundary.
pub trait CancellationSignal {
    /// Returns whether cancellation has been requested.
    fn is_cancelled(&self) -> bool;

    /// Registers a waker for a future cancellation notification.
    fn register_waker(&self, waker: &Waker);
}

/// A finite operation budget shared by admission, sink delivery, and
/// finalization adapters.  It carries no executor or timer implementation.
pub struct RunOperationBudget<'a> {
    clock: &'a dyn MonotonicClock,
    cancellation: &'a dyn CancellationSignal,
    deadline_ticks: u64,
    phase_deadline_ticks: Option<u64>,
    retry_budget: RetryBudget,
}

impl<'a> RunOperationBudget<'a> {
    /// Creates a budget from the current monotonic tick and finite duration.
    pub fn new(
        clock: &'a dyn MonotonicClock,
        cancellation: &'a dyn CancellationSignal,
        duration_ticks: u64,
        retry_budget: RetryBudget,
    ) -> Result<Self, BudgetError> {
        let deadline_ticks = clock
            .now_ticks()
            .checked_add(duration_ticks)
            .ok_or(BudgetError::DeadlineOverflow)?;
        Ok(Self {
            clock,
            cancellation,
            deadline_ticks,
            phase_deadline_ticks: None,
            retry_budget,
        })
    }

    /// Narrows the budget for a phase. A phase can never extend the run-wide
    /// deadline or a previously installed narrower phase deadline.
    pub fn with_phase_deadline(&mut self, deadline_ticks: u64) {
        self.phase_deadline_ticks = Some(
            self.phase_deadline_ticks
                .map_or(deadline_ticks, |current| current.min(deadline_ticks)),
        );
    }

    /// Returns the remaining monotonic ticks, or zero when cancelled/expired.
    #[must_use]
    pub fn remaining_ticks(&self) -> u64 {
        if self.cancellation.is_cancelled() {
            return 0;
        }
        let deadline = self
            .phase_deadline_ticks
            .map_or(self.deadline_ticks, |phase| phase.min(self.deadline_ticks));
        deadline.saturating_sub(self.clock.now_ticks())
    }

    /// Returns the shared retry budget without resetting it.
    #[must_use]
    pub const fn retry_budget(&self) -> RetryBudget {
        self.retry_budget
    }

    /// Checks cancellation and finite time before an operation boundary.
    pub fn check(&self) -> Result<(), BudgetError> {
        if self.cancellation.is_cancelled() {
            return Err(BudgetError::Cancelled);
        }
        if self.remaining_ticks() == 0 {
            return Err(BudgetError::Expired);
        }
        Ok(())
    }

    /// Consumes one retry/finalization attempt from the shared finite budget.
    pub fn consume_attempt(&mut self) -> Result<(), BudgetError> {
        self.check()?;
        if self.retry_budget.consume() {
            Ok(())
        } else {
            Err(BudgetError::RetryBudgetExhausted)
        }
    }

    /// Registers a cancellation wakeup without coupling this type to an
    /// executor.
    pub fn register_waker(&self, waker: &Waker) {
        self.cancellation.register_waker(waker);
    }
}

/// A standard-library future shape that an adapter may use for one bounded
/// operation. The router itself never polls or schedules it.
pub type BudgetedFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, BudgetError>> + 'a>>;

/// Optional adapter seam for sink operations that borrow one run budget.
pub trait BudgetedOperation {
    /// Starts one bounded operation; the adapter owns polling and execution.
    fn run<'operation, 'budget>(
        &'operation self,
        budget: &'operation mut RunOperationBudget<'budget>,
    ) -> BudgetedFuture<'operation, ()>;
}

/// The boundary at which a sink's acknowledgement becomes durable.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DurabilityBoundary {
    /// The sink processed the event in memory only.
    MemoryProcessed,
    /// The format writer accepted the complete record.
    FormatWritten,
    /// The writer flushed its buffered representation.
    Flushed,
    /// The underlying durable store was synchronised.
    Synced,
    /// A remote sink acknowledged durable receipt.
    RemoteAcknowledged,
}

impl DurabilityBoundary {
    /// Returns a stable wire-independent discriminant for key binding.
    #[must_use]
    pub const fn canonical_tag(self) -> u8 {
        match self {
            Self::MemoryProcessed => 1,
            Self::FormatWritten => 2,
            Self::Flushed => 3,
            Self::Synced => 4,
            Self::RemoteAcknowledged => 5,
        }
    }
}

/// A nonzero delivery attempt ordinal.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AttemptOrdinal(u32);

impl AttemptOrdinal {
    /// Creates an attempt ordinal.
    pub fn new(value: u32) -> Result<Self, IdentityError> {
        if value == 0 {
            Err(IdentityError::Zero { field: "attempt" })
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the attempt number.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// A sink acknowledgement bound to the exact event, sink, payload, attempt,
/// idempotency key, and declared durability boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DurabilityAck {
    event_id: EventId,
    sink_id: QualifiedSinkId,
    payload_digest: Digest32,
    attempt: AttemptOrdinal,
    boundary: DurabilityBoundary,
    idempotency_key: Digest32,
}

impl DurabilityAck {
    /// Constructs a bound acknowledgement.
    pub fn new(
        event_id: EventId,
        sink_id: QualifiedSinkId,
        attempt: AttemptOrdinal,
        boundary: DurabilityBoundary,
        idempotency_key: Digest32,
    ) -> Result<Self, IdentityError> {
        if event_id.run_id() != sink_id.run_id() {
            return Err(IdentityError::DomainMismatch);
        }
        if idempotency_key.is_zero() {
            return Err(IdentityError::Zero {
                field: "idempotency-key",
            });
        }
        Ok(Self {
            event_id,
            sink_id,
            payload_digest: event_id.payload_digest(),
            attempt,
            boundary,
            idempotency_key,
        })
    }

    /// Returns event identity.
    #[must_use]
    pub const fn event_id(self) -> EventId {
        self.event_id
    }

    /// Returns sink identity.
    #[must_use]
    pub const fn sink_id(self) -> QualifiedSinkId {
        self.sink_id
    }

    /// Returns payload digest.
    #[must_use]
    pub const fn payload_digest(self) -> Digest32 {
        self.payload_digest
    }

    /// Returns attempt ordinal.
    #[must_use]
    pub const fn attempt(self) -> AttemptOrdinal {
        self.attempt
    }

    /// Returns durability boundary.
    #[must_use]
    pub const fn boundary(self) -> DurabilityBoundary {
        self.boundary
    }

    /// Returns the stable retry/idempotency key.
    #[must_use]
    pub const fn idempotency_key(self) -> Digest32 {
        self.idempotency_key
    }
}

/// A reason for an event not entering a sink queue.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NotAdmittedReason {
    /// A finite item/byte limit was reached.
    Full,
    /// Admission had already been stopped.
    Closed,
    /// The run was cancelled.
    Cancelled,
    /// A sink failed before this event could be admitted.
    FailedBeforeAdmission(BoundedDiagnostic),
}

/// A reason for a selected event's terminal sink failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FailureReason {
    /// The sink failed after queue admission and the outcome is retryable.
    Retryable(BoundedDiagnostic),
    /// The sink outcome is unknown; retrying is forbidden.
    UnknownOutcome(BoundedDiagnostic),
    /// The sink rejected the event permanently.
    Permanent(BoundedDiagnostic),
    /// Cancellation or finalization deadline released accepted work.
    Cancelled,
}

/// Public per-event/per-sink terminal or in-flight disposition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LedgerDisposition {
    /// Admission did not reserve this sink.
    NotAdmitted(NotAdmittedReason),
    /// Reserved and queued for this sink.
    Queued,
    /// Removed from the queue and currently owned by a sink attempt.
    Processing,
    /// The sink acknowledged its declared durability boundary.
    Durable,
    /// An explicitly non-compatibility diagnosed drop.
    DiagnosedDrop(BoundedDiagnostic),
    /// A terminal sink failure.
    Failed(FailureReason),
}

/// Internal transition state.  `Selected` is intentionally not exposed as a
/// final disposition: it exists only during transactional reservation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LedgerState {
    /// A reservation attempt selected this event/sink pair.
    Selected,
    /// A public ledger disposition.
    Disposition(LedgerDisposition),
}

/// A stable event/sink ledger key.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeliveryKey {
    /// Event identity.
    pub event_id: EventId,
    /// Sink identity.
    pub sink_id: QualifiedSinkId,
}

#[derive(Clone, Debug)]
struct LedgerEntry {
    bytes: usize,
    state: LedgerState,
    admitted: bool,
    attempts: AttemptOrdinal,
    idempotency_key: Digest32,
    boundary: DurabilityBoundary,
    last_budget: u32,
}

/// A transition retained for deterministic diagnostics and audit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerTransition {
    /// Monotonic transition ordinal.
    pub ordinal: u64,
    /// Event/sink pair.
    pub key: DeliveryKey,
    /// Previous state.
    pub from: LedgerState,
    /// New state.
    pub to: LedgerState,
    /// Bounded accounting bytes.
    pub bytes: usize,
    /// Shared budget remaining after this transition.
    pub remaining_budget: u32,
    /// Optional acknowledgement boundary.
    pub boundary: Option<DurabilityBoundary>,
    /// Optional bounded diagnostic.
    pub diagnostic: Option<BoundedDiagnostic>,
}

/// Errors raised by an invalid ledger transition or conservation check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LedgerError {
    /// Identity construction failed.
    Identity(IdentityError),
    /// The event/sink key was already selected.
    DuplicateSelection,
    /// The requested transition is not legal from the current state.
    InvalidTransition {
        /// Current state.
        state: LedgerState,
        /// Requested operation.
        operation: &'static str,
    },
    /// The acknowledgement did not match the active delivery attempt.
    AcknowledgementMismatch,
    /// A retry was requested after an unknown result.
    RetryAfterUnknownOutcome,
    /// No shared retry/finalization budget remained.
    RetryBudgetExhausted,
    /// Diagnosed drop was attempted without explicit non-compatibility policy.
    DiagnosedDropNotAllowed,
    /// The bounded transition ledger exhausted its configured capacity.
    TransitionLimit,
    /// Selected/accepted/terminal counts did not conserve every admission.
    ConservationViolation {
        /// Stable explanation.
        detail: String,
    },
}

impl From<IdentityError> for LedgerError {
    fn from(value: IdentityError) -> Self {
        Self::Identity(value)
    }
}

impl fmt::Display for LedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identity(error) => error.fmt(formatter),
            Self::DuplicateSelection => formatter.write_str("result.ledger.duplicate-selection"),
            Self::InvalidTransition { operation, .. } => {
                write!(formatter, "result.ledger.invalid-transition.{operation}")
            }
            Self::AcknowledgementMismatch => {
                formatter.write_str("result.ledger.acknowledgement-mismatch")
            }
            Self::RetryAfterUnknownOutcome => {
                formatter.write_str("result.ledger.retry-after-unknown-outcome")
            }
            Self::RetryBudgetExhausted => {
                formatter.write_str("result.ledger.retry-budget-exhausted")
            }
            Self::DiagnosedDropNotAllowed => {
                formatter.write_str("result.ledger.diagnosed-drop-not-allowed")
            }
            Self::TransitionLimit => formatter.write_str("result.ledger.transition-limit"),
            Self::ConservationViolation { detail } => {
                write!(formatter, "result.ledger.conservation: {detail}")
            }
        }
    }
}

impl std::error::Error for LedgerError {}

/// Counts used by the conservation equations.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LedgerSummary {
    /// Number of selected event/sink pairs.
    pub selected: usize,
    /// Number admitted into a sink queue or processing attempt.
    pub admitted: usize,
    /// Number admitted into a sink queue or processing attempt.
    pub accepted: usize,
    /// Number durably acknowledged.
    pub durable: usize,
    /// Number explicitly diagnosed as dropped.
    pub diagnosed_drop: usize,
    /// Number terminally failed after admission.
    pub failed: usize,
    /// Number terminally failed after admission (explicit rev4 spelling).
    pub failed_after_admission: usize,
    /// Number not admitted.
    pub not_admitted: usize,
    /// Number still queued or processing.
    pub incomplete: usize,
}

/// An immutable audit ledger for transactional all-sink reservation and
/// delivery lifecycle.
#[derive(Clone, Debug, Default)]
pub struct DeliveryLedger {
    entries: BTreeMap<DeliveryKey, LedgerEntry>,
    transitions: Vec<LedgerTransition>,
    next_ordinal: u64,
}

impl DeliveryLedger {
    /// Creates an empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Selects an event/sink pair before any worker can observe a reservation.
    pub fn select(
        &mut self,
        key: DeliveryKey,
        bytes: usize,
        remaining_budget: u32,
    ) -> Result<(), LedgerError> {
        self.select_with_boundary(key, bytes, remaining_budget, DurabilityBoundary::Flushed)
    }

    /// Selects an event/sink pair and binds its declared durability boundary.
    pub fn select_with_boundary(
        &mut self,
        key: DeliveryKey,
        bytes: usize,
        remaining_budget: u32,
        boundary: DurabilityBoundary,
    ) -> Result<(), LedgerError> {
        if self.transitions.len() >= MAX_LEDGER_TRANSITIONS {
            return Err(LedgerError::TransitionLimit);
        }
        if self.entries.contains_key(&key) {
            return Err(LedgerError::DuplicateSelection);
        }
        let idempotency_key = delivery_idempotency_key(key, boundary);
        self.entries.insert(
            key,
            LedgerEntry {
                bytes,
                state: LedgerState::Selected,
                admitted: false,
                attempts: AttemptOrdinal::new(1)?,
                idempotency_key,
                boundary,
                last_budget: remaining_budget,
            },
        );
        self.record(
            key,
            LedgerState::Selected,
            bytes,
            remaining_budget,
            None,
            None,
        )
    }

    /// Marks a selected pair as not admitted.
    pub fn not_admitted(
        &mut self,
        key: DeliveryKey,
        reason: NotAdmittedReason,
    ) -> Result<(), LedgerError> {
        self.transition(
            key,
            LedgerState::Disposition(LedgerDisposition::NotAdmitted(reason)),
            0,
            None,
            None,
        )
    }

    /// Marks a selected pair as queued.
    pub fn queued(&mut self, key: DeliveryKey, remaining_budget: u32) -> Result<(), LedgerError> {
        self.transition(
            key,
            LedgerState::Disposition(LedgerDisposition::Queued),
            remaining_budget,
            None,
            None,
        )
    }

    /// Marks a queued pair as processing and returns its attempt ordinal.
    pub fn processing(
        &mut self,
        key: DeliveryKey,
        remaining_budget: u32,
    ) -> Result<AttemptOrdinal, LedgerError> {
        let entry = self.entry(key)?;
        let attempt = entry.attempts;
        self.transition(
            key,
            LedgerState::Disposition(LedgerDisposition::Processing),
            remaining_budget,
            None,
            None,
        )?;
        Ok(attempt)
    }

    /// Marks a processing pair durable after validating the complete ack.
    pub fn durable(
        &mut self,
        ack: DurabilityAck,
        remaining_budget: u32,
    ) -> Result<(), LedgerError> {
        let key = DeliveryKey {
            event_id: ack.event_id(),
            sink_id: ack.sink_id(),
        };
        let entry = self.entry(key)?;
        if !matches!(
            entry.state,
            LedgerState::Disposition(LedgerDisposition::Processing)
        ) || entry.attempts != ack.attempt()
            || entry.idempotency_key != ack.idempotency_key()
            || entry.boundary != ack.boundary()
            || key.event_id.payload_digest() != ack.payload_digest()
        {
            return Err(LedgerError::AcknowledgementMismatch);
        }
        self.transition(
            key,
            LedgerState::Disposition(LedgerDisposition::Durable),
            remaining_budget,
            Some(ack.boundary()),
            None,
        )
    }

    /// Records a diagnosed drop.  The caller must pass explicit policy proof.
    pub fn diagnosed_drop(
        &mut self,
        key: DeliveryKey,
        reason: BoundedDiagnostic,
        non_compatibility_policy: bool,
    ) -> Result<(), LedgerError> {
        if !non_compatibility_policy {
            return Err(LedgerError::DiagnosedDropNotAllowed);
        }
        self.transition(
            key,
            LedgerState::Disposition(LedgerDisposition::DiagnosedDrop(reason.clone())),
            0,
            None,
            Some(reason),
        )
    }

    /// Records a terminal failure.  Before-admission failures remain
    /// `NotAdmitted`; all others count as accepted failures.
    pub fn failed(&mut self, key: DeliveryKey, reason: FailureReason) -> Result<(), LedgerError> {
        if matches!(&reason, FailureReason::Cancelled)
            && matches!(self.state(key)?, LedgerState::Selected)
        {
            return self.not_admitted(
                key,
                NotAdmittedReason::FailedBeforeAdmission(BoundedDiagnostic::new("cancelled")),
            );
        }
        let diagnostic = match &reason {
            FailureReason::Retryable(message)
            | FailureReason::UnknownOutcome(message)
            | FailureReason::Permanent(message) => Some(message.clone()),
            FailureReason::Cancelled => Some(BoundedDiagnostic::new("cancelled")),
        };
        self.transition(
            key,
            LedgerState::Disposition(LedgerDisposition::Failed(reason)),
            0,
            None,
            diagnostic,
        )
    }

    /// Requeues a retryable failure using the same event/sink key and budget.
    pub fn retry(&mut self, key: DeliveryKey, budget: &mut RetryBudget) -> Result<(), LedgerError> {
        let state = self.state(key)?;
        match &state {
            LedgerState::Disposition(LedgerDisposition::Failed(FailureReason::Retryable(_))) => {}
            LedgerState::Disposition(LedgerDisposition::Failed(FailureReason::UnknownOutcome(
                _,
            ))) => {
                return Err(LedgerError::RetryAfterUnknownOutcome);
            }
            state => {
                return Err(LedgerError::InvalidTransition {
                    state: state.clone(),
                    operation: "retry",
                });
            }
        }
        if !budget.consume() {
            return Err(LedgerError::RetryBudgetExhausted);
        }
        let next = self
            .entry(key)?
            .attempts
            .get()
            .checked_add(1)
            .ok_or(LedgerError::RetryBudgetExhausted)?;
        self.transition(
            key,
            LedgerState::Disposition(LedgerDisposition::Queued),
            budget.remaining(),
            None,
            None,
        )?;
        self.entry_mut(key)?.attempts = AttemptOrdinal::new(next)?;
        Ok(())
    }

    /// Returns the current state, or a typed transition error if absent.
    pub fn state(&self, key: DeliveryKey) -> Result<LedgerState, LedgerError> {
        Ok(self.entry(key)?.state.clone())
    }

    /// Returns the current public disposition, if one exists.
    #[must_use]
    pub fn disposition(&self, key: DeliveryKey) -> Option<LedgerDisposition> {
        self.entries.get(&key).and_then(|entry| match &entry.state {
            LedgerState::Selected => None,
            LedgerState::Disposition(disposition) => Some(disposition.clone()),
        })
    }

    /// Returns a stable delivery idempotency key.
    pub fn idempotency_key(&self, key: DeliveryKey) -> Result<Digest32, LedgerError> {
        Ok(self.entry(key)?.idempotency_key)
    }

    /// Returns all transition records in ordinal order.
    #[must_use]
    pub fn transitions(&self) -> &[LedgerTransition] {
        &self.transitions
    }

    /// Returns the current accounting summary.
    #[must_use]
    pub fn summary(&self) -> LedgerSummary {
        let mut summary = LedgerSummary::default();
        for entry in self.entries.values() {
            summary.selected += 1;
            match &entry.state {
                LedgerState::Selected => {}
                LedgerState::Disposition(LedgerDisposition::NotAdmitted(_)) => {
                    summary.not_admitted += 1;
                }
                LedgerState::Disposition(LedgerDisposition::Queued)
                | LedgerState::Disposition(LedgerDisposition::Processing) => {
                    if entry.admitted {
                        summary.admitted += 1;
                        summary.accepted += 1;
                    }
                    summary.incomplete += 1;
                }
                LedgerState::Disposition(LedgerDisposition::Durable) => {
                    if entry.admitted {
                        summary.admitted += 1;
                        summary.accepted += 1;
                    }
                    summary.durable += 1;
                }
                LedgerState::Disposition(LedgerDisposition::DiagnosedDrop(_)) => {
                    if entry.admitted {
                        summary.admitted += 1;
                        summary.accepted += 1;
                    }
                    summary.diagnosed_drop += 1;
                }
                LedgerState::Disposition(LedgerDisposition::Failed(_)) => {
                    if entry.admitted {
                        summary.admitted += 1;
                        summary.accepted += 1;
                        summary.failed_after_admission += 1;
                        summary.failed += 1;
                    } else {
                        summary.not_admitted += 1;
                    }
                }
            }
        }
        summary
    }

    /// Validates the revision 4 conservation equations and rejects incomplete
    /// work at a finalization boundary.
    pub fn validate_conservation(&self) -> Result<LedgerSummary, LedgerError> {
        let summary = self.summary();
        if summary.incomplete != 0
            || summary.selected
                != summary.not_admitted
                    + summary.durable
                    + summary.diagnosed_drop
                    + summary.failed_after_admission
            || summary.admitted
                != summary.durable + summary.diagnosed_drop + summary.failed_after_admission
            || summary.accepted != summary.admitted
            || summary.failed != summary.failed_after_admission
        {
            return Err(LedgerError::ConservationViolation {
                detail: format!(
                    "selected={}, admitted={}, accepted={}, durable={}, drop={}, failed-after-admission={}, not-admitted={}, incomplete={}",
                    summary.selected,
                    summary.admitted,
                    summary.accepted,
                    summary.durable,
                    summary.diagnosed_drop,
                    summary.failed_after_admission,
                    summary.not_admitted,
                    summary.incomplete,
                ),
            });
        }
        Ok(summary)
    }

    /// Builds a finalization report retaining every incomplete reference and
    /// the per-sink conservation counts.
    #[must_use]
    pub fn finalization_report(&self) -> FinalizationReport {
        FinalizationReport::from_ledger(self)
    }

    /// Builds a report that also includes configured sinks with no selected
    /// event yet.  This keeps zero-count sink isolation visible at run close.
    #[must_use]
    pub fn finalization_report_for(
        &self,
        sink_ids: impl IntoIterator<Item = QualifiedSinkId>,
    ) -> FinalizationReport {
        FinalizationReport::from_ledger_with_sinks(self, sink_ids)
    }

    fn entry(&self, key: DeliveryKey) -> Result<&LedgerEntry, LedgerError> {
        self.entries
            .get(&key)
            .ok_or(LedgerError::InvalidTransition {
                state: LedgerState::Selected,
                operation: "missing",
            })
    }

    fn entry_mut(&mut self, key: DeliveryKey) -> Result<&mut LedgerEntry, LedgerError> {
        self.entries
            .get_mut(&key)
            .ok_or(LedgerError::InvalidTransition {
                state: LedgerState::Selected,
                operation: "missing",
            })
    }

    fn transition(
        &mut self,
        key: DeliveryKey,
        to: LedgerState,
        remaining_budget: u32,
        boundary: Option<DurabilityBoundary>,
        diagnostic: Option<BoundedDiagnostic>,
    ) -> Result<(), LedgerError> {
        let entry = self.entry(key)?.clone();
        if !legal_transition(&entry.state, &to) {
            return Err(LedgerError::InvalidTransition {
                state: entry.state,
                operation: "transition",
            });
        }
        if self.transitions.len() >= MAX_LEDGER_TRANSITIONS {
            return Err(LedgerError::TransitionLimit);
        }
        let bytes = entry.bytes;
        let entry = self
            .entries
            .get_mut(&key)
            .ok_or(LedgerError::InvalidTransition {
                state: LedgerState::Selected,
                operation: "missing",
            })?;
        entry.state = to.clone();
        entry.last_budget = remaining_budget;
        if matches!(
            &to,
            LedgerState::Disposition(LedgerDisposition::Queued)
                | LedgerState::Disposition(LedgerDisposition::DiagnosedDrop(_))
        ) {
            entry.admitted = true;
        }
        self.record(key, to, bytes, remaining_budget, boundary, diagnostic)
    }

    fn record(
        &mut self,
        key: DeliveryKey,
        to: LedgerState,
        bytes: usize,
        remaining_budget: u32,
        boundary: Option<DurabilityBoundary>,
        diagnostic: Option<BoundedDiagnostic>,
    ) -> Result<(), LedgerError> {
        let from =
            if let Some(previous) = self.transitions.iter().rev().find(|item| item.key == key) {
                previous.to.clone()
            } else {
                LedgerState::Selected
            };
        self.next_ordinal = self
            .next_ordinal
            .checked_add(1)
            .ok_or(LedgerError::TransitionLimit)?;
        self.transitions.push(LedgerTransition {
            ordinal: self.next_ordinal,
            key,
            from,
            to,
            bytes,
            remaining_budget,
            boundary,
            diagnostic,
        });
        Ok(())
    }
}

fn legal_transition(from: &LedgerState, to: &LedgerState) -> bool {
    matches!(
        (from, to),
        (
            LedgerState::Selected,
            LedgerState::Disposition(LedgerDisposition::NotAdmitted(_))
        ) | (
            LedgerState::Selected,
            LedgerState::Disposition(LedgerDisposition::Queued)
        ) | (
            LedgerState::Disposition(LedgerDisposition::Queued),
            LedgerState::Disposition(LedgerDisposition::Processing),
        ) | (
            LedgerState::Disposition(LedgerDisposition::Queued),
            LedgerState::Disposition(LedgerDisposition::Failed(_)),
        ) | (
            LedgerState::Disposition(LedgerDisposition::Processing),
            LedgerState::Disposition(LedgerDisposition::Durable),
        ) | (
            LedgerState::Disposition(LedgerDisposition::Processing),
            LedgerState::Disposition(LedgerDisposition::DiagnosedDrop(_)),
        ) | (
            LedgerState::Disposition(LedgerDisposition::Processing),
            LedgerState::Disposition(LedgerDisposition::Failed(_)),
        ) | (
            LedgerState::Disposition(LedgerDisposition::Failed(FailureReason::Retryable(_))),
            LedgerState::Disposition(LedgerDisposition::Queued),
        )
    )
}

fn delivery_idempotency_key(key: DeliveryKey, boundary: DurabilityBoundary) -> Digest32 {
    let event_id = key.event_id.canonical_bytes();
    let sink_id = key.sink_id.canonical_bytes();
    let payload_digest = key.event_id.payload_digest().as_bytes();
    Digest32::sha256_parts(&[
        b"jmeter-rs.delivery-key.v4\0",
        &event_id,
        &sink_id,
        &payload_digest,
        &[boundary.canonical_tag()],
    ])
}

fn event_id_in_run_order(first: EventId, second: EventId) -> bool {
    first
        .sequence()
        .cmp(&second.sequence())
        .then_with(|| first.cmp(&second))
        .is_lt()
}

/// Lifecycle outcome retained in a finalization report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FinalizationOutcome {
    /// The operation did not run because finalization stopped earlier.
    NotAttempted,
    /// The operation completed.
    Succeeded,
    /// The operation failed with bounded diagnostic context.
    Failed(BoundedDiagnostic),
}

/// An event/sink reference that could not reach a terminal disposition before
/// finalization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncompleteDelivery {
    /// Event/sink key.
    pub key: DeliveryKey,
    /// Last known disposition.
    pub disposition: LedgerState,
}

/// Per-sink finalization accounting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SinkFinalizationReport {
    /// Sink identity.
    pub sink_id: QualifiedSinkId,
    /// Selected pairs for this sink.
    pub selected: usize,
    /// Admitted pairs for this sink.
    pub admitted: usize,
    /// Selected pairs that were not admitted.
    pub not_admitted: usize,
    /// Durable pair count.
    pub durable: usize,
    /// Diagnosed-drop count.
    pub diagnosed_drop: usize,
    /// Terminal failed pair count.
    pub failed: usize,
    /// Terminal failed pair count after admission.
    pub failed_after_admission: usize,
    /// First event in run order, if selected.
    pub first_event_id: Option<EventId>,
    /// Last event in run order, if selected.
    pub last_event_id: Option<EventId>,
    /// Sink flush outcome.
    pub flush: FinalizationOutcome,
    /// Sink close/finish outcome.
    pub close: FinalizationOutcome,
    /// Publication outcome (effectful application layer may replace this).
    pub publication: FinalizationOutcome,
    /// Incomplete event references.
    pub incomplete: Vec<IncompleteDelivery>,
    /// Redacted bounded errors.
    pub errors: Vec<BoundedDiagnostic>,
}

/// Complete run finalization accounting.  It is valid to publish only after
/// [`FinalizationReport::validate_conservation`] succeeds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizationReport {
    /// Per-sink reports in stable sink-id order.
    pub sinks: Vec<SinkFinalizationReport>,
    /// Aggregate counts.
    pub summary: LedgerSummary,
    /// Number of selected event/sink pairs.
    pub selected: usize,
    /// Number of selected pairs that never entered a sink queue.
    pub not_admitted: usize,
    /// Number admitted into a sink queue or processing attempt.
    pub admitted: usize,
    /// Number durably acknowledged.
    pub durable: usize,
    /// Number explicitly diagnosed after admission.
    pub diagnosed_drop: usize,
    /// Number terminally failed after admission.
    pub failed_after_admission: usize,
    /// Whether all ledger entries reached a terminal disposition.
    pub conservation_valid: bool,
}

impl FinalizationReport {
    fn from_ledger(ledger: &DeliveryLedger) -> Self {
        Self::from_ledger_with_sinks(ledger, std::iter::empty())
    }

    fn from_ledger_with_sinks(
        ledger: &DeliveryLedger,
        sink_ids: impl IntoIterator<Item = QualifiedSinkId>,
    ) -> Self {
        let mut by_sink: BTreeMap<QualifiedSinkId, SinkFinalizationReport> = BTreeMap::new();
        for sink_id in sink_ids {
            by_sink
                .entry(sink_id)
                .or_insert_with(|| SinkFinalizationReport {
                    sink_id,
                    selected: 0,
                    admitted: 0,
                    not_admitted: 0,
                    durable: 0,
                    diagnosed_drop: 0,
                    failed: 0,
                    failed_after_admission: 0,
                    first_event_id: None,
                    last_event_id: None,
                    flush: FinalizationOutcome::NotAttempted,
                    close: FinalizationOutcome::NotAttempted,
                    publication: FinalizationOutcome::NotAttempted,
                    incomplete: Vec::new(),
                    errors: Vec::new(),
                });
        }
        for (key, entry) in &ledger.entries {
            let report = by_sink
                .entry(key.sink_id)
                .or_insert_with(|| SinkFinalizationReport {
                    sink_id: key.sink_id,
                    selected: 0,
                    admitted: 0,
                    not_admitted: 0,
                    durable: 0,
                    diagnosed_drop: 0,
                    failed: 0,
                    failed_after_admission: 0,
                    first_event_id: None,
                    last_event_id: None,
                    flush: FinalizationOutcome::NotAttempted,
                    close: FinalizationOutcome::NotAttempted,
                    publication: FinalizationOutcome::NotAttempted,
                    incomplete: Vec::new(),
                    errors: Vec::new(),
                });
            report.selected += 1;
            if report
                .first_event_id
                .map_or(true, |first| event_id_in_run_order(key.event_id, first))
            {
                report.first_event_id = Some(key.event_id);
            }
            if report
                .last_event_id
                .map_or(true, |last| event_id_in_run_order(last, key.event_id))
            {
                report.last_event_id = Some(key.event_id);
            }
            match &entry.state {
                LedgerState::Selected => report.incomplete.push(IncompleteDelivery {
                    key: *key,
                    disposition: entry.state.clone(),
                }),
                LedgerState::Disposition(LedgerDisposition::NotAdmitted(_)) => {
                    report.not_admitted += 1;
                }
                LedgerState::Disposition(LedgerDisposition::Queued)
                | LedgerState::Disposition(LedgerDisposition::Processing) => {
                    report.admitted += 1;
                    report.incomplete.push(IncompleteDelivery {
                        key: *key,
                        disposition: entry.state.clone(),
                    });
                }
                LedgerState::Disposition(LedgerDisposition::Durable) => {
                    report.admitted += 1;
                    report.durable += 1;
                }
                LedgerState::Disposition(LedgerDisposition::DiagnosedDrop(_)) => {
                    report.admitted += 1;
                    report.diagnosed_drop += 1;
                }
                LedgerState::Disposition(LedgerDisposition::Failed(_)) => {
                    if entry.admitted {
                        report.admitted += 1;
                        report.failed_after_admission += 1;
                        report.failed += 1;
                    } else {
                        report.not_admitted += 1;
                    }
                }
            }
        }
        let summary = ledger.summary();
        Self {
            sinks: by_sink.into_values().collect(),
            conservation_valid: ledger.validate_conservation().is_ok(),
            selected: summary.selected,
            not_admitted: summary.not_admitted,
            admitted: summary.admitted,
            durable: summary.durable,
            diagnosed_drop: summary.diagnosed_drop,
            failed_after_admission: summary.failed_after_admission,
            summary,
        }
    }

    /// Validates per-sink and aggregate conservation equations.
    pub fn validate_conservation(&self) -> Result<(), LedgerError> {
        let summary = self.summary;
        if self.selected != summary.selected
            || self.not_admitted != summary.not_admitted
            || self.admitted != summary.admitted
            || self.durable != summary.durable
            || self.diagnosed_drop != summary.diagnosed_drop
            || self.failed_after_admission != summary.failed_after_admission
            || summary.incomplete != 0
            || summary.selected
                != summary.not_admitted
                    + summary.durable
                    + summary.diagnosed_drop
                    + summary.failed_after_admission
            || summary.admitted
                != summary.durable + summary.diagnosed_drop + summary.failed_after_admission
            || summary.accepted != summary.admitted
            || summary.failed != summary.failed_after_admission
        {
            return Err(LedgerError::ConservationViolation {
                detail: "aggregate finalization counts are not conserved".to_owned(),
            });
        }
        if !self.conservation_valid {
            return Err(LedgerError::ConservationViolation {
                detail: "finalization report contains incomplete or unbalanced entries".to_owned(),
            });
        }
        for sink in &self.sinks {
            if sink.selected
                != sink.not_admitted
                    + sink.durable
                    + sink.diagnosed_drop
                    + sink.failed_after_admission
                || sink.admitted != sink.durable + sink.diagnosed_drop + sink.failed_after_admission
                || sink.failed != sink.failed_after_admission
            {
                return Err(LedgerError::ConservationViolation {
                    detail: format!(
                        "sink {} has unbalanced counts",
                        sink.sink_id.collector().node_id()
                    ),
                });
            }
            if !sink.incomplete.is_empty() {
                return Err(LedgerError::ConservationViolation {
                    detail: format!(
                        "sink {} has incomplete entries",
                        sink.sink_id.collector().node_id()
                    ),
                });
            }
        }
        Ok(())
    }
}

/// A finite, domain-qualified sink plan for the pure deterministic router.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedSinkPlan {
    /// Bound sink identity.
    pub id: QualifiedSinkId,
    /// Item/byte queue limits.
    pub limits: SinkLimits,
    /// Explicit full policy.
    pub full_policy: FullPolicy,
    /// Boundary required before a sink acknowledgement is durable.
    pub durability_boundary: DurabilityBoundary,
}

impl TypedSinkPlan {
    /// Creates a typed sink plan.
    #[must_use]
    pub const fn new(id: QualifiedSinkId, limits: SinkLimits, full_policy: FullPolicy) -> Self {
        Self::with_boundary(id, limits, full_policy, DurabilityBoundary::Flushed)
    }

    /// Creates a sink plan with an explicit durability boundary.
    #[must_use]
    pub const fn with_boundary(
        id: QualifiedSinkId,
        limits: SinkLimits,
        full_policy: FullPolicy,
        durability_boundary: DurabilityBoundary,
    ) -> Self {
        Self {
            id,
            limits,
            full_policy,
            durability_boundary,
        }
    }
}

/// Explicit admission outcomes for the revision 4 pure router.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TypedAdmissionOutcome {
    /// Reserved in every sink queue.
    Accepted {
        /// Immutable event identity.
        event_id: EventId,
        /// Accounted payload bytes.
        bytes: usize,
    },
    /// A finite sink could not reserve the event; no sink queue was mutated.
    Full {
        /// First stable sink that was full.
        sink_id: QualifiedSinkId,
        /// Event identity that remains unadmitted.
        event_id: EventId,
        /// Accounted payload bytes.
        bytes: usize,
    },
    /// Admission was closed.
    Closed,
    /// Admission was cancelled.
    Cancelled,
    /// A sink failed before all-sink reservation completed.
    Failed {
        /// Failed sink, when one was identified.
        sink_id: Option<QualifiedSinkId>,
        /// Bounded diagnostic.
        error: BoundedDiagnostic,
    },
}

/// Typed router lifecycle phase.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TypedRouterPhase {
    /// Sinks are configured but have not started.
    New,
    /// Admission is open.
    Open,
    /// Admission is closed; queued work may drain.
    AdmissionStopped,
    /// Queued work is being leased to sinks.
    Draining,
    /// All accepted work is terminal and the pure flush boundary is reached.
    Flushed,
    /// Cancellation released or is releasing work.
    Cancelled,
    /// Finalization completed.
    Finished,
    /// A run-failing sink error occurred.
    Failed,
}

#[derive(Clone)]
struct TypedQueued {
    envelope: Arc<TypedResultEnvelope>,
    bytes: usize,
}

#[derive(Clone)]
struct TypedInFlight {
    envelope: Arc<TypedResultEnvelope>,
    attempt: AttemptOrdinal,
}

#[derive(Clone)]
struct TypedSinkState {
    plan: TypedSinkPlan,
    queue: VecDeque<TypedQueued>,
    queued_bytes: usize,
    in_flight: BTreeMap<EventId, TypedInFlight>,
    failed: Option<BoundedDiagnostic>,
}

/// A deterministic executor-neutral model of the revision 3 router.  Effectful
/// sinks consume [`DeliveryLease`] values and return [`DurabilityAck`] values;
/// no filesystem, Tokio, or network behavior is embedded here.
#[derive(Clone)]
pub struct TypedResultRouter {
    run_id: TypedRunId,
    run_generation: RunGeneration,
    phase: TypedRouterPhase,
    next_sequence: u64,
    arbiter_cursor: usize,
    shared_budget: RetryBudget,
    sinks: Vec<TypedSinkState>,
    ledger: DeliveryLedger,
}

/// Alias used by callers migrating directly from the decision record.
pub type PureResultRouter = TypedResultRouter;
/// Versioned alias for the typed router contract.
pub type ResultRouterV3 = TypedResultRouter;
/// Explicit compatibility name for the pre-revision-3 router.
pub type LegacyResultRouter = ResultRouter;
/// Explicit compatibility name for the pre-revision-3 envelope.
pub type LegacyResultEnvelope = ResultEnvelope;
/// Explicit compatibility name for the pre-revision-3 sink identifier.
pub type LegacySinkId = SinkId;

/// Errors raised by typed-router configuration and lifecycle operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TypedRouterError {
    /// Typed identity failure.
    Identity(IdentityError),
    /// The injected finite operation budget or cancellation source stopped
    /// the requested boundary.
    Budget(BudgetError),
    /// Ledger transition failure.
    Ledger(LedgerError),
    /// Duplicate or excessive sink configuration.
    InvalidConfiguration(BoundedDiagnostic),
    /// Operation is not legal in the current lifecycle phase.
    InvalidState {
        /// Current phase.
        phase: TypedRouterPhase,
        /// Requested operation.
        operation: &'static str,
    },
    /// Primary work and finalization both failed; neither diagnostic is lost.
    Combined {
        /// Primary failure.
        primary: Box<Self>,
        /// Finalization failure.
        secondary: Box<Self>,
    },
}

impl From<IdentityError> for TypedRouterError {
    fn from(value: IdentityError) -> Self {
        Self::Identity(value)
    }
}

impl From<BudgetError> for TypedRouterError {
    fn from(value: BudgetError) -> Self {
        Self::Budget(value)
    }
}

impl From<LedgerError> for TypedRouterError {
    fn from(value: LedgerError) -> Self {
        Self::Ledger(value)
    }
}

impl fmt::Display for TypedRouterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identity(error) => error.fmt(formatter),
            Self::Budget(error) => error.fmt(formatter),
            Self::Ledger(error) => error.fmt(formatter),
            Self::InvalidConfiguration(detail) => {
                write!(formatter, "result.router.configuration: {detail}")
            }
            Self::InvalidState { phase, operation } => {
                write!(formatter, "result.router.state.{operation}: {phase:?}")
            }
            Self::Combined { primary, secondary } => {
                write!(
                    formatter,
                    "result.router.combined: primary={primary}; secondary={secondary}"
                )
            }
        }
    }
}

impl std::error::Error for TypedRouterError {}

impl TypedResultRouter {
    /// Creates a deterministic router with stable sink-id ordering.
    pub fn new(
        run_id: TypedRunId,
        run_generation: RunGeneration,
        shared_budget: RetryBudget,
        plans: impl IntoIterator<Item = TypedSinkPlan>,
    ) -> Result<Self, TypedRouterError> {
        let mut plans = plans.into_iter().collect::<Vec<_>>();
        if plans.is_empty() || plans.len() > MAX_SINKS {
            return Err(TypedRouterError::InvalidConfiguration(
                BoundedDiagnostic::new("typed router requires a bounded non-empty sink plan"),
            ));
        }
        plans.sort_by_key(|plan| plan.id);
        if plans.windows(2).any(|window| window[0].id == window[1].id) {
            return Err(TypedRouterError::InvalidConfiguration(
                BoundedDiagnostic::new("duplicate qualified sink identity"),
            ));
        }
        if plans.iter().any(|plan| plan.id.run_id() != run_id) {
            return Err(TypedRouterError::InvalidConfiguration(
                BoundedDiagnostic::new("sink belongs to a different run"),
            ));
        }
        if plans
            .iter()
            .any(|plan| plan.limits.max_finalization_steps == 0)
        {
            return Err(TypedRouterError::InvalidConfiguration(
                BoundedDiagnostic::new("sink finalization limit must be non-zero"),
            ));
        }
        Ok(Self {
            run_id,
            run_generation,
            phase: TypedRouterPhase::New,
            next_sequence: 1,
            arbiter_cursor: 0,
            shared_budget,
            sinks: plans
                .into_iter()
                .map(|plan| TypedSinkState {
                    plan,
                    queue: VecDeque::new(),
                    queued_bytes: 0,
                    in_flight: BTreeMap::new(),
                    failed: None,
                })
                .collect(),
            ledger: DeliveryLedger::new(),
        })
    }

    /// Returns phase.
    #[must_use]
    pub const fn phase(&self) -> TypedRouterPhase {
        self.phase
    }

    /// Returns the shared remaining budget.
    #[must_use]
    pub const fn remaining_budget(&self) -> RetryBudget {
        self.shared_budget
    }

    /// Returns the immutable ledger.
    #[must_use]
    pub const fn ledger(&self) -> &DeliveryLedger {
        &self.ledger
    }

    /// Starts the pure run resource.  Admission cannot begin in `New`.
    pub fn start(&mut self) -> Result<(), TypedRouterError> {
        match self.phase {
            TypedRouterPhase::New => {
                self.phase = TypedRouterPhase::Open;
                Ok(())
            }
            TypedRouterPhase::Open => Ok(()),
            phase => Err(TypedRouterError::InvalidState {
                phase,
                operation: "start",
            }),
        }
    }

    /// Returns mutable ledger access for deterministic fake-sink harnesses.
    pub fn ledger_mut(&mut self) -> &mut DeliveryLedger {
        &mut self.ledger
    }

    /// Checks an injected finite budget before admitting an original event.
    /// The budget remains borrowed by the caller and is never reset here.
    pub fn admit_with_budget(
        &mut self,
        envelope: TypedResultEnvelope,
        budget: &RunOperationBudget<'_>,
    ) -> Result<TypedAdmissionOutcome, TypedRouterError> {
        budget.check().map_err(TypedRouterError::Budget)?;
        self.admit(envelope)
    }

    /// Admits one original event transactionally into every sink queue.
    pub fn admit(
        &mut self,
        envelope: TypedResultEnvelope,
    ) -> Result<TypedAdmissionOutcome, TypedRouterError> {
        match self.phase {
            TypedRouterPhase::Open => {}
            TypedRouterPhase::New | TypedRouterPhase::Draining | TypedRouterPhase::Flushed => {
                return Ok(TypedAdmissionOutcome::Closed);
            }
            TypedRouterPhase::Cancelled => return Ok(TypedAdmissionOutcome::Cancelled),
            TypedRouterPhase::AdmissionStopped
            | TypedRouterPhase::Finished
            | TypedRouterPhase::Failed => return Ok(TypedAdmissionOutcome::Closed),
        }
        if envelope.run() != self.run_id || envelope.run_generation() != self.run_generation {
            return Err(TypedRouterError::InvalidConfiguration(
                BoundedDiagnostic::new("event belongs to a different run or generation"),
            ));
        }
        let sequence = envelope.event_id().sequence().get();
        if sequence != self.next_sequence {
            return Err(TypedRouterError::InvalidConfiguration(
                BoundedDiagnostic::new("event sequence is not the next monotonic run sequence"),
            ));
        }
        let event_id = envelope.event_id();
        let bytes = envelope.byte_size();
        if let Some(sink) = self.sinks.iter().find(|sink| sink.failed.is_some()) {
            let error = sink
                .failed
                .clone()
                .unwrap_or_else(|| BoundedDiagnostic::new("sink failed"));
            for state in &self.sinks {
                let key = DeliveryKey {
                    event_id,
                    sink_id: state.plan.id,
                };
                self.ledger.select_with_boundary(
                    key,
                    bytes,
                    self.shared_budget.remaining(),
                    state.plan.durability_boundary,
                )?;
            }
            for state in &self.sinks {
                let key = DeliveryKey {
                    event_id,
                    sink_id: state.plan.id,
                };
                self.ledger
                    .not_admitted(key, NotAdmittedReason::FailedBeforeAdmission(error.clone()))?;
            }
            return Ok(TypedAdmissionOutcome::Failed {
                sink_id: Some(sink.plan.id),
                error,
            });
        }
        let full_sink = self.sinks.iter().find(|sink| {
            sink.queue.len() >= sink.plan.limits.max_items
                || sink.queued_bytes.saturating_add(bytes) > sink.plan.limits.max_bytes
        });
        if let Some(sink) = full_sink {
            if let FullPolicy::Backpressure { deadline } = &sink.plan.full_policy {
                if deadline.remaining() == 0 || self.shared_budget.remaining() == 0 {
                    self.phase = TypedRouterPhase::Failed;
                    return Ok(TypedAdmissionOutcome::Failed {
                        sink_id: Some(sink.plan.id),
                        error: BoundedDiagnostic::new("shared backpressure budget exhausted"),
                    });
                }
                // A backpressure result remains outside the ledger until the
                // caller successfully reserves it.  This is what permits the
                // same EventId/payload to be retried without manufacturing a
                // second semantic event or violating terminal ledger closure.
                return Ok(TypedAdmissionOutcome::Full {
                    sink_id: sink.plan.id,
                    event_id,
                    bytes,
                });
            }
            for state in &self.sinks {
                let key = DeliveryKey {
                    event_id,
                    sink_id: state.plan.id,
                };
                self.ledger.select_with_boundary(
                    key,
                    bytes,
                    self.shared_budget.remaining(),
                    state.plan.durability_boundary,
                )?;
            }
            let full_id = sink.plan.id;
            let reason = BoundedDiagnostic::new("finite sink queue is full");
            for state in &self.sinks {
                let key = DeliveryKey {
                    event_id,
                    sink_id: state.plan.id,
                };
                if state.plan.id == full_id {
                    // A full queue rejects admission. Diagnosed drops are
                    // reserved for work that was admitted and later released
                    // by an explicit post-admission outcome.
                    self.ledger.not_admitted(key, NotAdmittedReason::Full)?;
                } else {
                    self.ledger.not_admitted(key, NotAdmittedReason::Full)?;
                }
            }
            if matches!(&sink.plan.full_policy, FullPolicy::FailRun) {
                self.phase = TypedRouterPhase::Failed;
                return Ok(TypedAdmissionOutcome::Failed {
                    sink_id: Some(full_id),
                    error: reason,
                });
            }
            return Ok(TypedAdmissionOutcome::Full {
                sink_id: full_id,
                event_id,
                bytes,
            });
        }

        let envelope = Arc::new(envelope);
        let mut keys = Vec::with_capacity(self.sinks.len());
        for state in &self.sinks {
            let key = DeliveryKey {
                event_id,
                sink_id: state.plan.id,
            };
            self.ledger.select_with_boundary(
                key,
                bytes,
                self.shared_budget.remaining(),
                state.plan.durability_boundary,
            )?;
            keys.push(key);
        }
        for (state, key) in self.sinks.iter_mut().zip(keys) {
            self.ledger.queued(key, self.shared_budget.remaining())?;
            state.queued_bytes = state.queued_bytes.saturating_add(bytes);
            state.queue.push_back(TypedQueued {
                envelope: Arc::clone(&envelope),
                bytes,
            });
        }
        self.next_sequence = self.next_sequence.checked_add(1).ok_or_else(|| {
            TypedRouterError::InvalidConfiguration(BoundedDiagnostic::new("run sequence exhausted"))
        })?;
        Ok(TypedAdmissionOutcome::Accepted { event_id, bytes })
    }

    /// Retries a full admission using the one run-level budget.  The event's
    /// sequence, payload digest, and sink identities remain unchanged.
    pub fn retry_admission(
        &mut self,
        envelope: TypedResultEnvelope,
    ) -> Result<TypedAdmissionOutcome, TypedRouterError> {
        if !self.shared_budget.consume() {
            return Err(TypedRouterError::Ledger(LedgerError::RetryBudgetExhausted));
        }
        self.admit(envelope)
    }

    /// Stops new admission while retaining queued work for draining.
    pub fn stop_admission(&mut self) -> Result<(), TypedRouterError> {
        match self.phase {
            TypedRouterPhase::Open => {
                self.phase = TypedRouterPhase::AdmissionStopped;
                Ok(())
            }
            TypedRouterPhase::AdmissionStopped
            | TypedRouterPhase::Draining
            | TypedRouterPhase::Flushed
            | TypedRouterPhase::Finished => Ok(()),
            phase => Err(TypedRouterError::InvalidState {
                phase,
                operation: "stop-admission",
            }),
        }
    }

    /// Takes the next queued event using stable round-robin sink arbitration.
    pub fn next_delivery(&mut self) -> Result<Option<DeliveryLease>, TypedRouterError> {
        if matches!(
            self.phase,
            TypedRouterPhase::Cancelled | TypedRouterPhase::Finished
        ) {
            return Ok(None);
        }
        if self.phase == TypedRouterPhase::AdmissionStopped {
            self.phase = TypedRouterPhase::Draining;
        }
        if self.sinks.is_empty() {
            return Ok(None);
        }
        for offset in 0..self.sinks.len() {
            let index = (self.arbiter_cursor + offset) % self.sinks.len();
            if self.sinks[index].failed.is_some() {
                continue;
            }
            let Some(item) = self.sinks[index].queue.pop_front() else {
                continue;
            };
            self.sinks[index].queued_bytes =
                self.sinks[index].queued_bytes.saturating_sub(item.bytes);
            let key = DeliveryKey {
                event_id: item.envelope.event_id(),
                sink_id: self.sinks[index].plan.id,
            };
            let attempt = self
                .ledger
                .processing(key, self.shared_budget.remaining())?;
            self.sinks[index].in_flight.insert(
                key.event_id,
                TypedInFlight {
                    envelope: Arc::clone(&item.envelope),
                    attempt,
                },
            );
            self.arbiter_cursor = (index + 1) % self.sinks.len();
            return Ok(Some(DeliveryLease {
                key,
                envelope: item.envelope,
                attempt,
                idempotency_key: self.ledger.idempotency_key(key)?,
                durability_boundary: self.sinks[index].plan.durability_boundary,
            }));
        }
        Ok(None)
    }

    /// Marks the in-memory delivery boundary flushed after all work is
    /// terminal.  Actual format/remote flushing remains an effectful sink
    /// concern and must return a bound [`DurabilityAck`].
    pub fn flush(&mut self) -> Result<(), TypedRouterError> {
        if !matches!(
            self.phase,
            TypedRouterPhase::AdmissionStopped
                | TypedRouterPhase::Draining
                | TypedRouterPhase::Flushed
        ) {
            return Err(TypedRouterError::InvalidState {
                phase: self.phase,
                operation: "flush",
            });
        }
        if self.ledger.entries.values().any(|entry| {
            matches!(
                &entry.state,
                LedgerState::Selected
                    | LedgerState::Disposition(LedgerDisposition::Queued)
                    | LedgerState::Disposition(LedgerDisposition::Processing)
            )
        }) {
            return Err(TypedRouterError::Ledger(
                LedgerError::ConservationViolation {
                    detail: "flush reached with incomplete delivery entries".to_owned(),
                },
            ));
        }
        self.phase = TypedRouterPhase::Flushed;
        Ok(())
    }

    /// Completes a lease at its declared durability boundary.
    pub fn acknowledge(&mut self, ack: DurabilityAck) -> Result<(), TypedRouterError> {
        let key = DeliveryKey {
            event_id: ack.event_id(),
            sink_id: ack.sink_id(),
        };
        let index = self.sink_index(key.sink_id)?;
        self.ledger.durable(ack, self.shared_budget.remaining())?;
        self.sinks[index].in_flight.remove(&key.event_id);
        Ok(())
    }

    /// Records an explicit diagnosed drop for an already admitted processing
    /// lease. Queue-full rejection never reaches this path.
    pub fn diagnosed_drop(
        &mut self,
        key: DeliveryKey,
        reason: BoundedDiagnostic,
    ) -> Result<(), TypedRouterError> {
        let index = self.sink_index(key.sink_id)?;
        if !matches!(
            self.sinks[index].plan.full_policy,
            FullPolicy::DiagnosedDrop { .. }
        ) {
            return Err(TypedRouterError::Ledger(
                LedgerError::DiagnosedDropNotAllowed,
            ));
        }
        self.ledger.diagnosed_drop(key, reason, true)?;
        self.sinks[index].in_flight.remove(&key.event_id);
        Ok(())
    }

    /// Records a terminal sink failure.  Retryable failures retain their lease
    /// until [`Self::retry`] consumes the same shared budget.
    pub fn fail(
        &mut self,
        key: DeliveryKey,
        reason: FailureReason,
    ) -> Result<(), TypedRouterError> {
        let index = self.sink_index(key.sink_id)?;
        self.ledger.failed(key, reason.clone())?;
        if !matches!(&reason, FailureReason::Retryable(_)) {
            self.sinks[index].in_flight.remove(&key.event_id);
            let diagnostic = match &reason {
                FailureReason::Retryable(message)
                | FailureReason::UnknownOutcome(message)
                | FailureReason::Permanent(message) => message.clone(),
                FailureReason::Cancelled => BoundedDiagnostic::new("cancelled"),
            };
            self.sinks[index].failed = Some(diagnostic.clone());
            let pending = self
                .ledger
                .entries
                .iter()
                .filter_map(|(pending_key, entry)| {
                    (pending_key.sink_id == key.sink_id
                        && matches!(
                            &entry.state,
                            LedgerState::Disposition(LedgerDisposition::Queued)
                        ))
                    .then_some(*pending_key)
                })
                .collect::<Vec<_>>();
            for pending_key in pending {
                self.ledger
                    .failed(pending_key, FailureReason::Permanent(diagnostic.clone()))?;
            }
            self.sinks[index].queue.clear();
            self.sinks[index].queued_bytes = 0;
        }
        if matches!(&reason, FailureReason::UnknownOutcome(_)) {
            self.phase = TypedRouterPhase::Failed;
        }
        Ok(())
    }

    /// Requeues a retryable lease with the same event/sink idempotency key.
    pub fn retry(&mut self, key: DeliveryKey) -> Result<(), TypedRouterError> {
        let index = self.sink_index(key.sink_id)?;
        self.ledger.retry(key, &mut self.shared_budget)?;
        let in_flight = self.sinks[index]
            .in_flight
            .remove(&key.event_id)
            .ok_or(LedgerError::RetryAfterUnknownOutcome)?;
        let bytes = in_flight.envelope.byte_size();
        self.sinks[index].queued_bytes = self.sinks[index].queued_bytes.saturating_add(bytes);
        self.sinks[index].queue.push_back(TypedQueued {
            envelope: in_flight.envelope,
            bytes,
        });
        Ok(())
    }

    /// Cancels and explicitly accounts every queued/processing pair.
    pub fn cancel(&mut self) -> Result<(), TypedRouterError> {
        if self.phase == TypedRouterPhase::Finished {
            return Ok(());
        }
        self.phase = TypedRouterPhase::Cancelled;
        let keys = self.pending_keys();
        for key in keys {
            if matches!(
                self.ledger.state(key)?,
                LedgerState::Disposition(LedgerDisposition::Queued)
                    | LedgerState::Disposition(LedgerDisposition::Processing)
            ) {
                self.ledger.failed(key, FailureReason::Cancelled)?;
            }
        }
        for sink in &mut self.sinks {
            sink.queue.clear();
            sink.queued_bytes = 0;
            sink.in_flight.clear();
        }
        Ok(())
    }

    /// Stops admission, accounts pending work, and returns a report ready for
    /// effectful flush/close publication.
    pub fn finish(&mut self) -> Result<FinalizationReport, TypedRouterError> {
        if self.phase == TypedRouterPhase::Open {
            self.phase = TypedRouterPhase::AdmissionStopped;
        }
        if self.phase == TypedRouterPhase::Cancelled {
            return Err(TypedRouterError::InvalidState {
                phase: self.phase,
                operation: "finish",
            });
        }
        let keys = self.pending_keys();
        for key in keys {
            if matches!(
                self.ledger.state(key)?,
                LedgerState::Disposition(LedgerDisposition::Queued)
                    | LedgerState::Disposition(LedgerDisposition::Processing)
            ) {
                self.ledger.failed(key, FailureReason::Cancelled)?;
            }
        }
        for sink in &mut self.sinks {
            sink.queue.clear();
            sink.queued_bytes = 0;
            sink.in_flight.clear();
        }
        self.flush()?;
        self.phase = TypedRouterPhase::Finished;
        let report = self
            .ledger
            .finalization_report_for(self.sinks.iter().map(|sink| sink.plan.id));
        report.validate_conservation()?;
        Ok(report)
    }

    fn pending_keys(&self) -> Vec<DeliveryKey> {
        self.ledger
            .entries
            .iter()
            .filter_map(|(key, entry)| {
                matches!(
                    &entry.state,
                    LedgerState::Disposition(LedgerDisposition::Queued)
                        | LedgerState::Disposition(LedgerDisposition::Processing)
                )
                .then_some(*key)
            })
            .collect()
    }

    fn sink_index(&self, sink_id: QualifiedSinkId) -> Result<usize, TypedRouterError> {
        self.sinks
            .iter()
            .position(|sink| sink.plan.id == sink_id)
            .ok_or_else(|| {
                TypedRouterError::InvalidConfiguration(BoundedDiagnostic::new(
                    "unknown sink identity",
                ))
            })
    }
}

/// One owned processing lease.  The envelope and idempotency key remain bound
/// to the exact event/sink pair across retries.
#[derive(Clone, Debug)]
pub struct DeliveryLease {
    key: DeliveryKey,
    envelope: Arc<TypedResultEnvelope>,
    attempt: AttemptOrdinal,
    idempotency_key: Digest32,
    durability_boundary: DurabilityBoundary,
}

impl DeliveryLease {
    /// Returns event/sink key.
    #[must_use]
    pub const fn key(&self) -> DeliveryKey {
        self.key
    }

    /// Returns the immutable original envelope.
    #[must_use]
    pub fn envelope(&self) -> &TypedResultEnvelope {
        &self.envelope
    }

    /// Returns the attempt ordinal.
    #[must_use]
    pub const fn attempt(&self) -> AttemptOrdinal {
        self.attempt
    }

    /// Returns the stable idempotency key.
    #[must_use]
    pub const fn idempotency_key(&self) -> Digest32 {
        self.idempotency_key
    }

    /// Returns the boundary declared by the sink plan for this delivery.
    #[must_use]
    pub const fn durability_boundary(&self) -> DurabilityBoundary {
        self.durability_boundary
    }

    /// Constructs a durability acknowledgement for this lease.
    pub fn acknowledge(
        &self,
        boundary: DurabilityBoundary,
    ) -> Result<DurabilityAck, IdentityError> {
        if boundary != self.durability_boundary {
            return Err(IdentityError::Collision);
        }
        DurabilityAck::new(
            self.key.event_id,
            self.key.sink_id,
            self.attempt,
            boundary,
            self.idempotency_key,
        )
    }
}

fn bounded_text(value: impl Into<String>) -> String {
    let value = value.into();
    if value.len() <= MAX_DIAGNOSTIC_BYTES {
        return value;
    }
    let suffix = "...";
    let mut end = MAX_DIAGNOSTIC_BYTES.saturating_sub(suffix.len());
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    let mut value = value;
    value.truncate(end);
    value.push_str(suffix);
    value
}

/// A monotonic sequence assigned once to a result emitted by one run.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RunSequence(u64);

impl RunSequence {
    /// Creates a checked revision 3 sequence.  The infallible `new` method is
    /// retained only for the temporary legacy adapter.
    pub fn try_new(value: u64) -> Result<Self, IdentityError> {
        nonzero_u64(value, "run-sequence").map(Self)
    }

    /// Creates a sequence from its persisted representation.
    #[deprecated(note = "use TypedRunSequence::new; zero is invalid in revision 3")]
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the sequence value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns whether this identity has been assigned by a router.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.0 != 0
    }
}

impl From<u64> for RunSequence {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl From<RunSequence> for u64 {
    fn from(value: RunSequence) -> Self {
        value.get()
    }
}

impl fmt::Display for RunSequence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A monotonically assigned invocation identity within one run.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SampleIdentity(u64);

impl SampleIdentity {
    /// Creates a checked revision 3 sample identity.  The infallible `new`
    /// method is retained only for the temporary legacy adapter.
    pub fn try_new(value: u64) -> Result<Self, IdentityError> {
        nonzero_u64(value, "sample-id").map(Self)
    }

    /// Creates a sample identity from its persisted representation.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the identity value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns whether this identity has been assigned by a router.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.0 != 0
    }
}

impl From<u64> for SampleIdentity {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl From<SampleIdentity> for u64 {
    fn from(value: SampleIdentity) -> Self {
        value.get()
    }
}

/// The virtual-user identity captured by a result envelope.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UserIdentity {
    /// Run-local virtual-user lifecycle identity.
    pub lifecycle_id: u64,
    /// Owning thread-group node.
    pub group_id: NodeId,
    /// One-based thread number within the group.
    pub thread_number: u64,
    /// Zero-based root iteration at notification time.
    pub iteration: u64,
}

impl UserIdentity {
    /// Creates a virtual-user identity.
    #[must_use]
    pub const fn new(
        lifecycle_id: u64,
        group_id: NodeId,
        thread_number: u64,
        iteration: u64,
    ) -> Self {
        Self {
            lifecycle_id,
            group_id,
            thread_number,
            iteration,
        }
    }
}

/// Origin and explicit controller parentage for a result event.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ResultOrigin {
    /// A result produced directly by a sampler.
    Sampler {
        /// Sampler node identity.
        sampler_id: NodeId,
        /// Innermost transaction controller containing the sampler, if any.
        parent: Option<NodeId>,
    },
    /// A synthetic result produced by a transaction controller.
    Transaction {
        /// Transaction-controller node identity.
        controller_id: NodeId,
        /// Enclosing transaction controller, if nested.
        parent: Option<NodeId>,
    },
}

impl ResultOrigin {
    /// Returns the source node represented by this origin.
    #[must_use]
    pub const fn source_node(self) -> NodeId {
        match self {
            Self::Sampler { sampler_id, .. } => sampler_id,
            Self::Transaction { controller_id, .. } => controller_id,
        }
    }

    /// Returns the optional enclosing controller identity.
    #[must_use]
    pub const fn parent(self) -> Option<NodeId> {
        match self {
            Self::Sampler { parent, .. } | Self::Transaction { parent, .. } => parent,
        }
    }

    /// Returns whether this is a synthetic transaction result.
    #[must_use]
    pub const fn is_transaction(self) -> bool {
        matches!(self, Self::Transaction { .. })
    }
}

/// Metadata supplied by the runtime at listener-notification time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResultEventMetadata {
    /// Source sampler or transaction node.
    pub source_node: NodeId,
    /// Ordered root-to-source plan identity path.
    pub plan_path: Vec<NodeId>,
    /// Virtual-user identity.
    pub user: UserIdentity,
    /// Sample invocation identity.  The router does not infer this from a
    /// label or from result data.
    pub sample: SampleIdentity,
    /// Sampler-versus-transaction origin and parentage.
    pub origin: ResultOrigin,
}

impl ResultEventMetadata {
    /// Creates event metadata and validates the finite plan-path bound.
    pub fn new(
        source_node: NodeId,
        plan_path: Vec<NodeId>,
        user: UserIdentity,
        sample: SampleIdentity,
        origin: ResultOrigin,
    ) -> Result<Self, ResultRouterError> {
        if plan_path.len() > MAX_PLAN_PATH {
            return Err(ResultRouterError::InvalidConfiguration {
                detail: "result plan path exceeds runtime bound".to_owned(),
            });
        }
        if plan_path.last().copied() != Some(source_node) {
            return Err(ResultRouterError::InvalidConfiguration {
                detail: "result plan path must end at its source node".to_owned(),
            });
        }
        if origin.source_node() != source_node {
            return Err(ResultRouterError::InvalidConfiguration {
                detail: "result origin does not match its source node".to_owned(),
            });
        }
        Ok(Self {
            source_node,
            plan_path,
            user,
            sample,
            origin,
        })
    }
}

/// An immutable event plus all identity needed by a run-level sink.
///
/// The contained [`SampleEvent`] is the exact snapshot produced at the
/// listener phase.  Sinks receive this object directly; no sink or
/// application adapter may reconstruct a second event from a partial result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResultEnvelope {
    sequence: RunSequence,
    source_node: NodeId,
    plan_path: Arc<[NodeId]>,
    run: RunIdentity,
    user: UserIdentity,
    thread: ThreadIdentity,
    sample: SampleIdentity,
    origin: ResultOrigin,
    event: Arc<SampleEvent>,
    byte_size: usize,
}

impl ResultEnvelope {
    /// Creates an immutable envelope from the original event snapshot.
    #[allow(
        clippy::too_many_arguments,
        reason = "the envelope boundary keeps every compatibility identity explicit"
    )]
    #[deprecated(note = "use ResultEnvelopeV3::new with domain-qualified identities")]
    pub fn new(
        sequence: RunSequence,
        source_node: NodeId,
        plan_path: Vec<NodeId>,
        run: RunIdentity,
        user: UserIdentity,
        thread: ThreadIdentity,
        sample: SampleIdentity,
        origin: ResultOrigin,
        event: SampleEvent,
    ) -> Result<Self, ResultRouterError> {
        if !sequence.is_valid() || !sample.is_valid() {
            return Err(ResultRouterError::InvalidConfiguration {
                detail: "result envelope identities must be non-zero".to_owned(),
            });
        }
        if plan_path.len() > MAX_PLAN_PATH {
            return Err(ResultRouterError::InvalidConfiguration {
                detail: "result plan path exceeds runtime bound".to_owned(),
            });
        }
        if plan_path.last().copied() != Some(source_node) {
            return Err(ResultRouterError::InvalidConfiguration {
                detail: "result plan path must end at its source node".to_owned(),
            });
        }
        if origin.source_node() != source_node {
            return Err(ResultRouterError::InvalidConfiguration {
                detail: "result origin does not match its source node".to_owned(),
            });
        }
        event
            .result()
            .validate_with_limits(ValidationLimits::default())
            .map_err(|source| ResultRouterError::InvalidConfiguration {
                detail: format!("result event exceeds runtime hierarchy limits: {source}"),
            })?;
        if run != *event.run() {
            return Err(ResultRouterError::InvalidConfiguration {
                detail: "result envelope run identity differs from its event".to_owned(),
            });
        }
        if thread != *event.thread() {
            return Err(ResultRouterError::InvalidConfiguration {
                detail: "result envelope thread identity differs from its event".to_owned(),
            });
        }
        let byte_size = estimate_event_bytes(&event)
            .saturating_add(
                plan_path
                    .len()
                    .saturating_mul(std::mem::size_of::<NodeId>()),
            )
            .saturating_add(std::mem::size_of::<Self>());
        Ok(Self {
            sequence,
            source_node,
            plan_path: plan_path.into(),
            run,
            user,
            thread,
            sample,
            origin,
            event: Arc::new(event),
            byte_size: byte_size.max(1),
        })
    }

    /// Returns the assigned run sequence.
    #[must_use]
    pub const fn sequence(&self) -> RunSequence {
        self.sequence
    }

    /// Returns the source node identity.
    #[must_use]
    pub const fn source_node(&self) -> NodeId {
        self.source_node
    }

    /// Returns the ordered root-to-source plan path.
    #[must_use]
    pub fn plan_path(&self) -> &[NodeId] {
        &self.plan_path
    }

    /// Returns the run identity copied into the event.
    #[must_use]
    pub fn run(&self) -> &RunIdentity {
        &self.run
    }

    /// Returns the virtual-user identity.
    #[must_use]
    pub const fn user(&self) -> UserIdentity {
        self.user
    }

    /// Returns the thread identity copied into the event.
    #[must_use]
    pub fn thread(&self) -> &ThreadIdentity {
        &self.thread
    }

    /// Returns the sample invocation identity.
    #[must_use]
    pub const fn sample(&self) -> SampleIdentity {
        self.sample
    }

    /// Returns sampler-versus-transaction origin and parentage.
    #[must_use]
    pub const fn origin(&self) -> ResultOrigin {
        self.origin
    }

    /// Returns the original immutable event snapshot.
    #[must_use]
    pub fn event(&self) -> &SampleEvent {
        &self.event
    }

    /// Returns the deterministic bounded accounting size used by the router.
    #[must_use]
    pub const fn byte_size(&self) -> usize {
        self.byte_size
    }
}

fn estimate_event_bytes(event: &SampleEvent) -> usize {
    let mut bytes = event
        .run()
        .as_str()
        .len()
        .saturating_add(event.host().as_str().len())
        .saturating_add(event.thread().name().len())
        .saturating_add(event.thread().group().map_or(0, str::len))
        .saturating_add(
            event
                .variables()
                .iter()
                .fold(0usize, |total, (name, value)| {
                    total
                        .saturating_add(name.len())
                        .saturating_add(value.as_str().map_or(0, str::len))
                }),
        );
    let mut pending = vec![event.result()];
    while let Some(result) = pending.pop() {
        bytes = bytes.saturating_add(result_bytes(result));
        pending.extend(result.sub_results());
    }
    bytes
}

fn result_bytes(result: &SampleResult) -> usize {
    let string_bytes = [
        Some(result.label()),
        result.response_code(),
        result.response_message(),
        result.failure_message(),
        result.data_encoding().map(|value| value.as_str()),
        result.request_headers().map(|value| value.as_str()),
        result.response_headers().map(|value| value.as_str()),
        result.sampler_data(),
        result.response_file(),
        result.url(),
    ]
    .into_iter()
    .flatten()
    .fold(0usize, |total, value| total.saturating_add(value.len()));
    let data_bytes = result
        .request_data()
        .map_or(0, |value| value.len())
        .saturating_add(result.response_data().map_or(0, |value| value.len()));
    let assertion_bytes = result.assertions().iter().fold(0usize, |total, value| {
        total
            .saturating_add(value.name().len())
            .saturating_add(value.failure_message().map_or(0, str::len))
            .saturating_add(value.error_message().map_or(0, str::len))
    });
    string_bytes
        .saturating_add(data_bytes)
        .saturating_add(assertion_bytes)
        .saturating_add(std::mem::size_of::<SampleResult>())
}

/// Stable identity of one configured result sink.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SinkId(u64);

impl SinkId {
    /// Creates a sink identity.
    #[deprecated(note = "use QualifiedSinkId; numeric sink IDs are compatibility-only")]
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the identity value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl From<u64> for SinkId {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl From<SinkId> for u64 {
    fn from(value: SinkId) -> Self {
        value.get()
    }
}

impl fmt::Display for SinkId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Finite per-sink queue limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SinkLimits {
    /// Maximum number of admitted envelopes waiting for this sink.
    pub max_items: usize,
    /// Maximum estimated bytes waiting for this sink.
    pub max_bytes: usize,
    /// Maximum pure lifecycle/finalization operations for this sink.
    pub max_finalization_steps: usize,
}

impl SinkLimits {
    /// Creates finite queue limits.  Zero is permitted and makes admission
    /// explicitly full; no implicit unbounded/default capacity is selected.
    #[must_use]
    pub const fn new(max_items: usize, max_bytes: usize) -> Self {
        Self {
            max_items,
            max_bytes,
            // Compatibility callers historically supplied only queue limits;
            // retain a finite derived bound until consolidation supplies an
            // explicit profile value.
            max_finalization_steps: if max_items == 0 { 1 } else { max_items },
        }
    }

    /// Creates queue and finalization limits explicitly.
    #[must_use]
    pub const fn with_finalization(
        max_items: usize,
        max_bytes: usize,
        max_finalization_steps: usize,
    ) -> Self {
        Self {
            max_items,
            max_bytes,
            max_finalization_steps,
        }
    }
}

/// Errors returned by a concrete result sink.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SinkError {
    /// The sink rejected or could not persist an event.
    Failed(String),
    /// The sink does not implement this lifecycle operation.
    Unsupported(String),
    /// The sink was cancelled.
    Cancelled,
    /// The sink-specific finite limit was exceeded.
    ResourceLimit(String),
    /// Both a primary sink operation and its finalization failed.
    Combined {
        /// Primary sink error.
        primary: Box<Self>,
        /// Finalization or cleanup error.
        secondary: Box<Self>,
    },
}

impl SinkError {
    /// Creates a bounded sink failure.
    #[must_use]
    pub fn failed(message: impl Into<String>) -> Self {
        Self::Failed(bounded_text(message))
    }

    /// Creates a bounded unsupported-operation error.
    #[must_use]
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::Unsupported(bounded_text(message))
    }

    /// Creates a bounded resource-limit error.
    #[must_use]
    pub fn resource_limit(message: impl Into<String>) -> Self {
        Self::ResourceLimit(bounded_text(message))
    }

    /// Returns a stable machine-readable category.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Failed(_) => "runtime.result-sink.failed",
            Self::Unsupported(_) => "runtime.result-sink.unsupported",
            Self::Cancelled => "runtime.result-sink.cancelled",
            Self::ResourceLimit(_) => "runtime.result-sink.resource-limit",
            Self::Combined { .. } => "runtime.result-sink.combined",
        }
    }
}

impl fmt::Display for SinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Failed(message) | Self::Unsupported(message) | Self::ResourceLimit(message) => {
                write!(formatter, "{}: {message}", self.code())
            }
            Self::Cancelled => formatter.write_str(self.code()),
            Self::Combined { primary, secondary } => {
                write!(
                    formatter,
                    "{}: primary={primary}; secondary={secondary}",
                    self.code()
                )
            }
        }
    }
}

impl std::error::Error for SinkError {}

/// Executor-neutral future returned by a sink lifecycle operation.
pub type ResultSinkFuture<'a> = Pin<Box<dyn Future<Output = Result<(), SinkError>> + 'a>>;

/// A run-owned result destination.
pub trait ResultSink: Send + Sync {
    /// Starts the sink before sampling begins.
    fn start<'a>(&'a self) -> ResultSinkFuture<'a> {
        Box::pin(future::ready(Ok(())))
    }

    /// Consumes one original immutable envelope in run order.
    fn write<'a>(&'a self, envelope: &'a ResultEnvelope) -> ResultSinkFuture<'a>;

    /// Flushes accepted events already delivered to the sink.
    fn flush<'a>(&'a self) -> ResultSinkFuture<'a> {
        Box::pin(future::ready(Ok(())))
    }

    /// Finishes and closes the sink.  It must be idempotent.
    fn finish<'a>(&'a self) -> ResultSinkFuture<'a> {
        Box::pin(future::ready(Ok(())))
    }

    /// Synchronously cancels the sink when a router/future is dropped.
    /// Implementations must be bounded and idempotent.
    fn cancel(&self) -> Result<(), SinkError> {
        Ok(())
    }
}

/// One sink and its finite queue policy.
#[derive(Clone)]
pub struct ResultSinkSpec {
    /// Stable sink identity.
    pub id: SinkId,
    /// Bounded queue limits.
    pub limits: SinkLimits,
    /// Sink implementation owned once by the run.
    pub sink: Arc<dyn ResultSink>,
}

impl fmt::Debug for ResultSinkSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResultSinkSpec")
            .field("id", &self.id)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl ResultSinkSpec {
    /// Creates a sink specification.
    #[must_use]
    #[deprecated(note = "use TypedSinkPlan and an effectful typed sink adapter")]
    pub fn new(id: impl Into<SinkId>, limits: SinkLimits, sink: Arc<dyn ResultSink>) -> Self {
        Self {
            id: id.into(),
            limits,
            sink,
        }
    }
}

/// Run-level lifecycle phase.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RouterPhase {
    /// No sink has been started.
    New,
    /// All configured sinks have started and admission is open.
    Started,
    /// No new events are accepted; queued events may drain.
    AdmissionStopped,
    /// Queued events are being delivered.
    Draining,
    /// Queues are empty and sinks have been flushed.
    Flushed,
    /// All sinks have been finished.
    Finished,
    /// Admission and pending work were cancelled.
    Cancelled,
    /// A terminal routing/finalization error occurred.
    Failed,
}

/// The result of attempting to admit one event into every sink queue.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmissionOutcome {
    /// The event was admitted to every configured sink queue.
    Accepted {
        /// Sequence assigned exactly once to this event.
        sequence: RunSequence,
        /// Accounted bytes reserved in each queue.
        bytes: usize,
    },
    /// At least one sink could not reserve the event.  No sink queue was
    /// mutated, so an event is never partially admitted.
    Full {
        /// The first bounded sink which rejected admission.
        sink_id: SinkId,
        /// Event bytes that would have been reserved.
        bytes: usize,
    },
    /// Admission was closed after the run lifecycle moved past `Started`.
    Closed,
    /// Admission was cancelled by a drop or explicit cancellation.
    Cancelled,
    /// A sink had already failed.  Healthy sinks remain isolated and can be
    /// finalized, but this event is not reported as accepted.
    Failed {
        /// Failed sink identity.
        sink_id: SinkId,
        /// Retained sink diagnostic.
        error: SinkError,
    },
    /// A run-level failure occurred before any concrete sink could be named.
    /// This replaces the old zero-valued sink sentinel during migration.
    FailedWithoutSink {
        /// Retained bounded diagnostic.
        error: SinkError,
    },
}

/// Queue accounting for one sink.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SinkQueueStats {
    /// Sink identity.
    pub sink_id: SinkId,
    /// Number of queued envelopes.
    pub queued_items: usize,
    /// Queued estimated bytes.
    pub queued_bytes: usize,
    /// Item capacity.
    pub max_items: usize,
    /// Byte capacity.
    pub max_bytes: usize,
    /// Whether this sink has failed.
    pub failed: bool,
}

/// Router accounting snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouterStats {
    /// Current lifecycle phase.
    pub phase: RouterPhase,
    /// Next sequence which would be assigned.
    pub next_sequence: RunSequence,
    /// Per-sink queue accounting.
    pub sinks: Vec<SinkQueueStats>,
}

/// Errors raised by router lifecycle and configuration operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResultRouterError {
    /// Sink configuration is malformed or exceeds a finite bound.
    InvalidConfiguration {
        /// Bounded configuration detail.
        detail: String,
    },
    /// A requested lifecycle operation is not valid in the current phase.
    InvalidState {
        /// Current router phase.
        phase: RouterPhase,
        /// Requested operation.
        operation: &'static str,
    },
    /// One sink failed while starting, writing, flushing, or finishing.
    Sink {
        /// Sink identity.
        sink_id: SinkId,
        /// Lifecycle operation.
        operation: &'static str,
        /// Sink diagnostic.
        source: SinkError,
    },
    /// Admission could not be completed without dropping or partially
    /// delivering the original event.
    Admission {
        /// Explicit admission outcome.
        outcome: AdmissionOutcome,
    },
    /// Sequence allocation overflowed.
    SequenceExhausted,
    /// Cancellation released accepted work that was still queued.  The
    /// counts make that loss explicit to a caller that requested cancellation.
    Cancelled {
        /// Number of accepted envelopes released without delivery.
        pending_items: usize,
        /// Estimated bytes released without delivery.
        pending_bytes: usize,
    },
    /// Primary routing work and finalization both failed.
    Combined {
        /// Primary error.
        primary: Box<Self>,
        /// Finalization error.
        secondary: Box<Self>,
    },
}

impl ResultRouterError {
    /// Returns a stable machine-readable category.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidConfiguration { .. } => "runtime.result-router.configuration",
            Self::InvalidState { .. } => "runtime.result-router.state",
            Self::Sink { .. } => "runtime.result-router.sink",
            Self::Admission { .. } => "runtime.result-router.admission",
            Self::SequenceExhausted => "runtime.result-router.sequence-exhausted",
            Self::Cancelled { .. } => "runtime.result-router.cancelled",
            Self::Combined { .. } => "runtime.result-router.combined",
        }
    }
}

impl fmt::Display for ResultRouterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration { detail } => {
                write!(formatter, "{}: {detail}", self.code())
            }
            Self::InvalidState { phase, operation } => {
                write!(formatter, "{}: {operation} in phase {phase:?}", self.code())
            }
            Self::Sink {
                sink_id,
                operation,
                source,
            } => write!(
                formatter,
                "{} at sink {sink_id} during {operation}: {source}",
                self.code()
            ),
            Self::Admission { outcome } => write!(formatter, "{}: {outcome:?}", self.code()),
            Self::SequenceExhausted => formatter.write_str(self.code()),
            Self::Cancelled {
                pending_items,
                pending_bytes,
            } => write!(
                formatter,
                "{}: released {pending_items} queued items ({pending_bytes} bytes)",
                self.code()
            ),
            Self::Combined { primary, secondary } => {
                write!(
                    formatter,
                    "{}: primary={primary}; secondary={secondary}",
                    self.code()
                )
            }
        }
    }
}

impl std::error::Error for ResultRouterError {}

/// Executor-neutral future returned by router lifecycle methods.
pub type ResultRouterFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ResultRouterError>> + 'a>>;

struct QueuedEnvelope {
    envelope: Arc<ResultEnvelope>,
    bytes: usize,
}

struct SinkState {
    spec: ResultSinkSpec,
    started: bool,
    queue: VecDeque<QueuedEnvelope>,
    queued_bytes: usize,
    failed: Option<SinkError>,
}

struct RouterState {
    phase: RouterPhase,
    next_sequence: u64,
    next_sample: u64,
    sinks: Vec<SinkState>,
    startup_active: bool,
    delivery_active: bool,
    drop_error: Option<ResultRouterError>,
}

struct RouterInner {
    run: RunIdentity,
    state: Mutex<RouterState>,
}

/// A run-owned bounded fan-out router.
#[derive(Clone)]
pub struct ResultRouter {
    inner: Arc<RouterInner>,
}

impl fmt::Debug for ResultRouter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResultRouter")
            .field("run", &self.inner.run)
            .field("stats", &self.stats())
            .finish()
    }
}

impl ResultRouter {
    /// Creates a router with one finite queue per sink.
    #[deprecated(note = "use TypedResultRouter::new for the revision 3 contract")]
    pub fn new(
        run: impl Into<RunIdentity>,
        specs: impl IntoIterator<Item = ResultSinkSpec>,
    ) -> Result<Self, ResultRouterError> {
        let mut sinks = Vec::new();
        for spec in specs {
            if sinks.len() >= MAX_SINKS {
                return Err(ResultRouterError::InvalidConfiguration {
                    detail: "result sink count exceeds runtime bound".to_owned(),
                });
            }
            if sinks.iter().any(|item: &SinkState| item.spec.id == spec.id) {
                return Err(ResultRouterError::InvalidConfiguration {
                    detail: format!("duplicate result sink identity {}", spec.id),
                });
            }
            sinks.push(SinkState {
                spec,
                started: false,
                queue: VecDeque::new(),
                queued_bytes: 0,
                failed: None,
            });
        }
        if sinks.is_empty() {
            return Err(ResultRouterError::InvalidConfiguration {
                detail: "result router requires at least one sink".to_owned(),
            });
        }
        Ok(Self {
            inner: Arc::new(RouterInner {
                run: run.into(),
                state: Mutex::new(RouterState {
                    phase: RouterPhase::New,
                    next_sequence: 1,
                    next_sample: 1,
                    sinks,
                    startup_active: false,
                    delivery_active: false,
                    drop_error: None,
                }),
            }),
        })
    }

    /// Returns the run identity owned by this router.
    #[must_use]
    pub fn run(&self) -> &RunIdentity {
        &self.inner.run
    }

    /// Starts every sink transactionally. Sampling must not begin until this
    /// future succeeds.
    pub fn start(&self) -> ResultRouterFuture<'static, ()> {
        let router = self.clone();
        Box::pin(async move {
            let guard = RouterFutureDropGuard::new(router.clone());
            let sink_count = {
                let mut state = lock(&router.inner.state);
                if state.phase != RouterPhase::New || state.startup_active {
                    guard.disarm();
                    return Err(ResultRouterError::InvalidState {
                        phase: state.phase,
                        operation: "start",
                    });
                }
                state.startup_active = true;
                state.sinks.len()
            };
            for index in 0..sink_count {
                let (sink_id, sink) = {
                    let mut state = lock(&router.inner.state);
                    if state.phase != RouterPhase::New || !state.startup_active {
                        state.startup_active = false;
                        guard.disarm();
                        return Err(ResultRouterError::InvalidState {
                            phase: state.phase,
                            operation: "start",
                        });
                    }
                    let sink = &state.sinks[index];
                    (sink.spec.id, Arc::clone(&sink.spec.sink))
                };
                match sink.start().await {
                    Ok(()) => {
                        let mut state = lock(&router.inner.state);
                        if state.phase != RouterPhase::New || !state.startup_active {
                            let phase = state.phase;
                            state.startup_active = false;
                            drop(state);
                            let cancel =
                                sink.cancel().err().map(|source| ResultRouterError::Sink {
                                    sink_id,
                                    operation: "cancel-after-start-race",
                                    source,
                                });
                            guard.disarm();
                            return Err(combine_router_errors(
                                ResultRouterError::InvalidState {
                                    phase,
                                    operation: "start",
                                },
                                cancel,
                            ));
                        }
                        state.sinks[index].started = true;
                    }
                    Err(source) => {
                        let primary = ResultRouterError::Sink {
                            sink_id,
                            operation: "start",
                            source,
                        };
                        let rollback = finish_started_sinks(&router).await;
                        let mut state = lock(&router.inner.state);
                        if state.phase == RouterPhase::New {
                            state.phase = RouterPhase::Failed;
                        }
                        state.startup_active = false;
                        drop(state);
                        guard.disarm();
                        return Err(combine_router_errors(primary, rollback));
                    }
                }
            }
            let mut state = lock(&router.inner.state);
            state.startup_active = false;
            if state.phase != RouterPhase::New {
                let phase = state.phase;
                drop(state);
                guard.disarm();
                return Err(ResultRouterError::InvalidState {
                    phase,
                    operation: "start",
                });
            }
            state.phase = RouterPhase::Started;
            drop(state);
            guard.disarm();
            Ok(())
        })
    }

    /// Stops new event admission.  It is idempotent once the run has entered
    /// a finalization phase.
    pub fn stop_admission(&self) -> Result<(), ResultRouterError> {
        let mut state = lock(&self.inner.state);
        match state.phase {
            RouterPhase::Started => {
                state.phase = RouterPhase::AdmissionStopped;
                Ok(())
            }
            RouterPhase::AdmissionStopped
            | RouterPhase::Draining
            | RouterPhase::Flushed
            | RouterPhase::Finished
            | RouterPhase::Failed => Ok(()),
            RouterPhase::New | RouterPhase::Cancelled => Err(ResultRouterError::InvalidState {
                phase: state.phase,
                operation: "stop-admission",
            }),
        }
    }

    /// Admits an original event and assigns its run/sample identities exactly
    /// once.  Admission is transactional across sinks: a full or failed sink
    /// leaves every sink queue unchanged.
    pub fn admit(&self, event: SampleEvent, mut metadata: ResultEventMetadata) -> AdmissionOutcome {
        let mut state = lock(&self.inner.state);
        match state.phase {
            RouterPhase::Started => {}
            RouterPhase::Cancelled => return AdmissionOutcome::Cancelled,
            RouterPhase::Failed => {
                if let Some(sink) = state.sinks.iter().find(|sink| sink.failed.is_some()) {
                    return AdmissionOutcome::Failed {
                        sink_id: sink.spec.id,
                        error: sink.failed.clone().unwrap_or_else(|| {
                            SinkError::failed("result sink failed without a diagnostic")
                        }),
                    };
                }
                return AdmissionOutcome::Closed;
            }
            _ => return AdmissionOutcome::Closed,
        }
        if let Err(source) = event
            .result()
            .validate_with_limits(ValidationLimits::default())
        {
            return AdmissionOutcome::FailedWithoutSink {
                error: SinkError::failed(format!(
                    "result event exceeds runtime hierarchy limits: {source}"
                )),
            };
        }
        let bytes = estimate_event_bytes(&event)
            .saturating_add(
                metadata
                    .plan_path
                    .len()
                    .saturating_mul(std::mem::size_of::<NodeId>()),
            )
            .saturating_add(std::mem::size_of::<ResultEnvelope>())
            .max(1);
        for sink in &state.sinks {
            if let Some(error) = sink.failed.clone() {
                return AdmissionOutcome::Failed {
                    sink_id: sink.spec.id,
                    error,
                };
            }
            if sink.queue.len() >= sink.spec.limits.max_items
                || sink.queued_bytes.saturating_add(bytes) > sink.spec.limits.max_bytes
            {
                return AdmissionOutcome::Full {
                    sink_id: sink.spec.id,
                    bytes,
                };
            }
        }
        let next_sequence = match state.next_sequence.checked_add(1) {
            Some(next) => next,
            None => {
                return AdmissionOutcome::FailedWithoutSink {
                    error: SinkError::resource_limit("run sequence exhausted"),
                };
            }
        };
        let (sample, next_sample) = if metadata.sample.get() == 0 {
            match state.next_sample.checked_add(1) {
                Some(next) => (SampleIdentity::new(state.next_sample), next),
                None => {
                    return AdmissionOutcome::FailedWithoutSink {
                        error: SinkError::resource_limit("sample identity exhausted"),
                    };
                }
            }
        } else {
            (
                metadata.sample,
                state
                    .next_sample
                    .max(metadata.sample.get().saturating_add(1)),
            )
        };
        let sequence = RunSequence::new(state.next_sequence);
        metadata.sample = sample;
        let envelope = match ResultEnvelope::new(
            sequence,
            metadata.source_node,
            metadata.plan_path,
            self.inner.run.clone(),
            metadata.user,
            event.thread().clone(),
            metadata.sample,
            metadata.origin,
            event,
        ) {
            Ok(envelope) => Arc::new(envelope),
            Err(error) => {
                return AdmissionOutcome::FailedWithoutSink {
                    error: SinkError::failed(error.to_string()),
                };
            }
        };
        state.next_sequence = next_sequence;
        state.next_sample = next_sample;
        let bytes = envelope.byte_size();
        for sink in &mut state.sinks {
            sink.queued_bytes = sink.queued_bytes.saturating_add(bytes);
            sink.queue.push_back(QueuedEnvelope {
                envelope: Arc::clone(&envelope),
                bytes,
            });
        }
        AdmissionOutcome::Accepted { sequence, bytes }
    }

    /// Admits an already-built envelope.  This is useful to adapters which
    /// assign identities at a boundary outside the convenience `admit` call.
    pub fn admit_envelope(&self, envelope: ResultEnvelope) -> AdmissionOutcome {
        let mut state = lock(&self.inner.state);
        match state.phase {
            RouterPhase::Started => {}
            RouterPhase::Cancelled => return AdmissionOutcome::Cancelled,
            _ => return AdmissionOutcome::Closed,
        }
        if envelope.run() != &self.inner.run {
            return AdmissionOutcome::FailedWithoutSink {
                error: SinkError::failed("result envelope belongs to a different run"),
            };
        }
        if envelope.sequence.get() != state.next_sequence {
            return AdmissionOutcome::FailedWithoutSink {
                error: SinkError::failed("result envelope sequence is not the next run sequence"),
            };
        }
        let bytes = envelope.byte_size();
        for sink in &state.sinks {
            if let Some(error) = sink.failed.clone() {
                return AdmissionOutcome::Failed {
                    sink_id: sink.spec.id,
                    error,
                };
            }
            if sink.queue.len() >= sink.spec.limits.max_items
                || sink.queued_bytes.saturating_add(bytes) > sink.spec.limits.max_bytes
            {
                return AdmissionOutcome::Full {
                    sink_id: sink.spec.id,
                    bytes,
                };
            }
        }
        state.next_sequence = match state.next_sequence.checked_add(1) {
            Some(next) => next,
            None => {
                return AdmissionOutcome::FailedWithoutSink {
                    error: SinkError::resource_limit("run sequence exhausted"),
                };
            }
        };
        state.next_sample = state
            .next_sample
            .max(envelope.sample.get().saturating_add(1));
        let envelope = Arc::new(envelope);
        for sink in &mut state.sinks {
            sink.queued_bytes = sink.queued_bytes.saturating_add(bytes);
            sink.queue.push_back(QueuedEnvelope {
                envelope: Arc::clone(&envelope),
                bytes,
            });
        }
        AdmissionOutcome::Accepted {
            sequence: envelope.sequence(),
            bytes,
        }
    }

    /// Delivers all accepted events to all healthy sinks in run-sequence order.
    /// A failed sink is isolated while healthy sinks continue draining.
    pub fn drain(&self) -> ResultRouterFuture<'static, ()> {
        let router = self.clone();
        Box::pin(async move {
            let guard = RouterFutureDropGuard::new(router.clone());
            {
                let mut state = lock(&router.inner.state);
                match state.phase {
                    RouterPhase::AdmissionStopped | RouterPhase::Draining => {
                        if state.delivery_active {
                            guard.disarm();
                            return Err(ResultRouterError::InvalidState {
                                phase: state.phase,
                                operation: "drain",
                            });
                        }
                        state.phase = RouterPhase::Draining;
                        state.delivery_active = true;
                    }
                    RouterPhase::Started => {
                        if state.delivery_active {
                            guard.disarm();
                            return Err(ResultRouterError::InvalidState {
                                phase: state.phase,
                                operation: "drain",
                            });
                        }
                        state.phase = RouterPhase::Draining;
                        state.delivery_active = true;
                    }
                    RouterPhase::Cancelled => {
                        guard.disarm();
                        return Err(ResultRouterError::InvalidState {
                            phase: state.phase,
                            operation: "drain",
                        });
                    }
                    RouterPhase::Failed | RouterPhase::Flushed | RouterPhase::Finished => {
                        guard.disarm();
                        return Ok(());
                    }
                    RouterPhase::New => {
                        guard.disarm();
                        return Err(ResultRouterError::InvalidState {
                            phase: state.phase,
                            operation: "drain",
                        });
                    }
                }
            }
            let failure = deliver_queued(&router).await;
            let mut state = lock(&router.inner.state);
            let cancelled = state.phase == RouterPhase::Cancelled;
            state.delivery_active = false;
            if !cancelled && failure.is_none() {
                state.phase = RouterPhase::AdmissionStopped;
            }
            drop(state);
            guard.disarm();
            if cancelled {
                return Err(ResultRouterError::InvalidState {
                    phase: RouterPhase::Cancelled,
                    operation: "drain",
                });
            }
            match failure {
                Some(error) => Err(error),
                None => Ok(()),
            }
        })
    }

    /// Delivers accepted events while keeping admission open.  Runtime uses
    /// this bounded hand-off at listener notification points so a finite queue
    /// never becomes an unbounded post-run retention vector.  A sink failure
    /// remains isolated and is reported explicitly.
    pub fn deliver(&self) -> ResultRouterFuture<'static, ()> {
        let router = self.clone();
        Box::pin(async move {
            let guard = RouterFutureDropGuard::new(router.clone());
            {
                let mut state = lock(&router.inner.state);
                match state.phase {
                    RouterPhase::Started => {
                        if state.delivery_active {
                            // A concurrent caller shares the active delivery
                            // future's bounded work.  Its caller still waits
                            // for its own runtime task; returning here avoids
                            // duplicate sink writes or queue pops.
                            guard.disarm();
                            return Ok(());
                        }
                        state.delivery_active = true;
                    }
                    RouterPhase::Draining => {
                        guard.disarm();
                        return Err(ResultRouterError::InvalidState {
                            phase: state.phase,
                            operation: "deliver",
                        });
                    }
                    RouterPhase::Failed => {
                        guard.disarm();
                        return Err(ResultRouterError::InvalidState {
                            phase: state.phase,
                            operation: "deliver",
                        });
                    }
                    RouterPhase::Cancelled | RouterPhase::New => {
                        guard.disarm();
                        return Err(ResultRouterError::InvalidState {
                            phase: state.phase,
                            operation: "deliver",
                        });
                    }
                    RouterPhase::AdmissionStopped
                    | RouterPhase::Flushed
                    | RouterPhase::Finished => {
                        guard.disarm();
                        return Ok(());
                    }
                }
            }
            let failure = deliver_queued(&router).await;
            let mut state = lock(&router.inner.state);
            let cancelled = state.phase == RouterPhase::Cancelled;
            state.delivery_active = false;
            if !cancelled
                && failure.is_none()
                && !matches!(
                    state.phase,
                    RouterPhase::AdmissionStopped | RouterPhase::Draining
                )
            {
                state.phase = RouterPhase::Started;
            }
            drop(state);
            guard.disarm();
            if cancelled {
                return Err(ResultRouterError::InvalidState {
                    phase: RouterPhase::Cancelled,
                    operation: "deliver",
                });
            }
            match failure {
                Some(error) => Err(error),
                None => Ok(()),
            }
        })
    }

    /// Flushes all healthy started sinks after accepted events have drained.
    pub fn flush(&self) -> ResultRouterFuture<'static, ()> {
        let router = self.clone();
        Box::pin(async move {
            let guard = RouterFutureDropGuard::new(router.clone());
            let sink_count = {
                let state = lock(&router.inner.state);
                if !matches!(
                    state.phase,
                    RouterPhase::AdmissionStopped
                        | RouterPhase::Draining
                        | RouterPhase::Flushed
                        | RouterPhase::Failed
                        | RouterPhase::Finished
                ) {
                    guard.disarm();
                    return Err(ResultRouterError::InvalidState {
                        phase: state.phase,
                        operation: "flush",
                    });
                }
                if state.delivery_active {
                    guard.disarm();
                    return Err(ResultRouterError::InvalidState {
                        phase: state.phase,
                        operation: "flush",
                    });
                }
                state.sinks.len()
            };
            let mut failure = None;
            for index in 0..sink_count {
                let (sink_id, sink, failed, started) = {
                    let state = lock(&router.inner.state);
                    let item = &state.sinks[index];
                    (
                        item.spec.id,
                        Arc::clone(&item.spec.sink),
                        item.failed.is_some(),
                        item.started,
                    )
                };
                if failed || !started {
                    continue;
                }
                if let Err(source) = sink.flush().await {
                    let error = ResultRouterError::Sink {
                        sink_id,
                        operation: "flush",
                        source: source.clone(),
                    };
                    lock(&router.inner.state).sinks[index].failed = Some(source);
                    combine_router_error_slot(&mut failure, error);
                }
            }
            let mut state = lock(&router.inner.state);
            let cancelled = state.phase == RouterPhase::Cancelled;
            let finished = state.phase == RouterPhase::Finished;
            if cancelled {
                drop(state);
                guard.disarm();
                return Err(failure.unwrap_or(ResultRouterError::InvalidState {
                    phase: RouterPhase::Cancelled,
                    operation: "flush",
                }));
            }
            if failure.is_none() && !finished && state.phase != RouterPhase::Failed {
                state.phase = RouterPhase::Flushed;
            } else if failure.is_some() {
                state.phase = RouterPhase::Failed;
            }
            drop(state);
            guard.disarm();
            match failure {
                Some(error) => Err(error),
                None => Ok(()),
            }
        })
    }

    /// Drains, flushes, and finishes every started sink.  Finalization keeps
    /// running after one sink fails and combines all primary/finalization
    /// diagnostics rather than dropping a secondary error.
    pub fn finish(&self) -> ResultRouterFuture<'static, ()> {
        let router = self.clone();
        Box::pin(async move {
            let guard = RouterFutureDropGuard::new(router.clone());
            let mut failure = prior_sink_failures(&router);
            if let Err(error) = router.stop_admission() {
                combine_router_error_slot(&mut failure, error);
            }
            if let Err(error) = router.drain().await {
                combine_router_error_slot(&mut failure, error);
            }
            if let Err(error) = router.flush().await {
                combine_router_error_slot(&mut failure, error);
            }
            let sink_count = lock(&router.inner.state).sinks.len();
            for index in 0..sink_count {
                let (sink_id, sink, started) = {
                    let state = lock(&router.inner.state);
                    let item = &state.sinks[index];
                    (item.spec.id, Arc::clone(&item.spec.sink), item.started)
                };
                if !started {
                    continue;
                }
                if let Err(source) = sink.finish().await {
                    let error = ResultRouterError::Sink {
                        sink_id,
                        operation: "finish",
                        source: source.clone(),
                    };
                    lock(&router.inner.state).sinks[index].failed = Some(source);
                    combine_router_error_slot(&mut failure, error);
                }
            }
            let mut state = lock(&router.inner.state);
            let cancelled = state.phase == RouterPhase::Cancelled;
            if cancelled {
                drop(state);
                guard.disarm();
                return Err(failure.unwrap_or(ResultRouterError::InvalidState {
                    phase: RouterPhase::Cancelled,
                    operation: "finish",
                }));
            }
            if failure.is_none() && state.phase != RouterPhase::Failed {
                state.phase = RouterPhase::Finished;
            } else {
                state.phase = RouterPhase::Failed;
            }
            drop(state);
            guard.disarm();
            match failure {
                Some(error) => Err(error),
                None => Ok(()),
            }
        })
    }

    /// Cancels admission and synchronously releases every queued reservation.
    pub fn cancel(&self) -> Result<(), ResultRouterError> {
        cancel_inner(&self.inner)
    }

    /// Returns a deterministic accounting snapshot.
    #[must_use]
    pub fn stats(&self) -> RouterStats {
        let state = lock(&self.inner.state);
        RouterStats {
            phase: state.phase,
            next_sequence: RunSequence::new(state.next_sequence),
            sinks: state
                .sinks
                .iter()
                .map(|sink| SinkQueueStats {
                    sink_id: sink.spec.id,
                    queued_items: sink.queue.len(),
                    queued_bytes: sink.queued_bytes,
                    max_items: sink.spec.limits.max_items,
                    max_bytes: sink.spec.limits.max_bytes,
                    failed: sink.failed.is_some(),
                })
                .collect(),
        }
    }

    /// Returns whether no further lifecycle operation can admit events.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            lock(&self.inner.state).phase,
            RouterPhase::Finished | RouterPhase::Cancelled | RouterPhase::Failed
        )
    }
}

impl Drop for ResultRouter {
    fn drop(&mut self) {
        if Arc::strong_count(&self.inner) != 1 {
            return;
        }
        let _ = cancel_inner(&self.inner);
    }
}

fn combine_router_errors(
    primary: ResultRouterError,
    secondary: Option<ResultRouterError>,
) -> ResultRouterError {
    match secondary {
        Some(secondary) => ResultRouterError::Combined {
            primary: Box::new(primary),
            secondary: Box::new(secondary),
        },
        None => primary,
    }
}

fn combine_router_error_slot(slot: &mut Option<ResultRouterError>, error: ResultRouterError) {
    *slot = Some(match slot.take() {
        Some(primary) => ResultRouterError::Combined {
            primary: Box::new(primary),
            secondary: Box::new(error),
        },
        None => error,
    });
}

async fn deliver_queued(router: &ResultRouter) -> Option<ResultRouterError> {
    let mut failure = None;
    let sink_count = lock(&router.inner.state).sinks.len();
    for index in 0..sink_count {
        loop {
            let (sink_id, sink, envelope) = {
                let state = lock(&router.inner.state);
                let sink_state = &state.sinks[index];
                let Some(item) = sink_state.queue.front() else {
                    break;
                };
                if sink_state.failed.is_some() {
                    break;
                }
                (
                    sink_state.spec.id,
                    Arc::clone(&sink_state.spec.sink),
                    Arc::clone(&item.envelope),
                )
            };
            if let Err(source) = sink.write(&envelope).await {
                let error = ResultRouterError::Sink {
                    sink_id,
                    operation: "write",
                    source: source.clone(),
                };
                let mut state = lock(&router.inner.state);
                state.sinks[index].failed = Some(source);
                state.sinks[index].queue.clear();
                state.sinks[index].queued_bytes = 0;
                state.phase = RouterPhase::Failed;
                combine_router_error_slot(&mut failure, error);
                break;
            }
            let mut state = lock(&router.inner.state);
            if let Some(item) = state.sinks[index].queue.pop_front() {
                state.sinks[index].queued_bytes =
                    state.sinks[index].queued_bytes.saturating_sub(item.bytes);
            }
        }
    }
    failure
}

async fn finish_started_sinks(router: &ResultRouter) -> Option<ResultRouterError> {
    let sink_count = lock(&router.inner.state).sinks.len();
    let mut failure = None;
    for index in 0..sink_count {
        let (sink_id, sink, started) = {
            let state = lock(&router.inner.state);
            let item = &state.sinks[index];
            (item.spec.id, Arc::clone(&item.spec.sink), item.started)
        };
        if !started {
            continue;
        }
        if let Err(source) = sink.finish().await {
            combine_router_error_slot(
                &mut failure,
                ResultRouterError::Sink {
                    sink_id,
                    operation: "rollback-finish",
                    source,
                },
            );
        }
    }
    failure
}

fn prior_sink_failures(router: &ResultRouter) -> Option<ResultRouterError> {
    let state = lock(&router.inner.state);
    let mut failure = None;
    for sink in &state.sinks {
        if let Some(source) = sink.failed.clone() {
            combine_router_error_slot(
                &mut failure,
                ResultRouterError::Sink {
                    sink_id: sink.spec.id,
                    operation: "previous",
                    source,
                },
            );
        }
    }
    failure
}

fn cancel_inner(inner: &Arc<RouterInner>) -> Result<(), ResultRouterError> {
    let (sinks, pending_items, pending_bytes) = {
        let mut state = lock(&inner.state);
        if state.phase == RouterPhase::Finished || state.phase == RouterPhase::Cancelled {
            return Ok(());
        }
        let was_failed = state.phase == RouterPhase::Failed;
        state.phase = if was_failed {
            RouterPhase::Failed
        } else {
            RouterPhase::Cancelled
        };
        state.startup_active = false;
        state.delivery_active = false;
        let pending_items = state
            .sinks
            .iter()
            .map(|sink| sink.queue.len())
            .max()
            .unwrap_or(0);
        let pending_bytes = state
            .sinks
            .iter()
            .map(|sink| sink.queued_bytes)
            .max()
            .unwrap_or(0);
        for sink in &mut state.sinks {
            sink.queue.clear();
            sink.queued_bytes = 0;
        }
        let sinks = state
            .sinks
            .iter()
            .filter(|sink| sink.started)
            .map(|sink| (sink.spec.id, Arc::clone(&sink.spec.sink)))
            .collect::<Vec<_>>();
        (sinks, pending_items, pending_bytes)
    };
    let mut failure =
        (pending_items > 0 || pending_bytes > 0).then_some(ResultRouterError::Cancelled {
            pending_items,
            pending_bytes,
        });
    for (sink_id, sink) in sinks {
        if let Err(source) = sink.cancel() {
            combine_router_error_slot(
                &mut failure,
                ResultRouterError::Sink {
                    sink_id,
                    operation: "cancel",
                    source,
                },
            );
        }
    }
    if let Some(error) = failure {
        let mut state = lock(&inner.state);
        state.drop_error = Some(error.clone());
        if !matches!(error, ResultRouterError::Cancelled { .. }) {
            state.phase = RouterPhase::Failed;
        }
        Err(error)
    } else {
        Ok(())
    }
}

struct RouterFutureDropGuard {
    router: ResultRouter,
    armed: bool,
}

impl RouterFutureDropGuard {
    fn new(router: ResultRouter) -> Self {
        Self {
            router,
            armed: true,
        }
    }

    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for RouterFutureDropGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.router.cancel();
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "router tests assert deterministic setup before inspecting state"
)]
mod tests {
    use super::*;
    use std::task::{Context, Poll, Waker};

    fn block_on<F: Future>(future: F) -> F::Output {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = Box::pin(future);
        loop {
            match Pin::new(&mut future).poll(&mut context) {
                Poll::Ready(value) => return value,
                Poll::Pending => std::hint::spin_loop(),
            }
        }
    }

    #[derive(Default)]
    struct FakeState {
        started: usize,
        writes: Vec<(RunSequence, String, ResultOrigin)>,
        flushed: usize,
        finished: usize,
        cancelled: usize,
        fail_start: bool,
        fail_write: bool,
        fail_flush: bool,
        fail_finish: bool,
    }

    struct FakeSink {
        state: Arc<Mutex<FakeState>>,
    }

    struct PendingSink {
        state: Arc<Mutex<FakeState>>,
    }

    impl FakeSink {
        fn new(state: Arc<Mutex<FakeState>>) -> Self {
            Self { state }
        }
    }

    impl ResultSink for PendingSink {
        fn write<'a>(&'a self, _envelope: &'a ResultEnvelope) -> ResultSinkFuture<'a> {
            Box::pin(future::pending())
        }

        fn cancel(&self) -> Result<(), SinkError> {
            let mut state = lock(&self.state);
            state.cancelled = state.cancelled.saturating_add(1);
            Ok(())
        }
    }

    impl ResultSink for FakeSink {
        fn start<'a>(&'a self) -> ResultSinkFuture<'a> {
            let state = Arc::clone(&self.state);
            Box::pin(future::ready({
                let mut state = lock(&state);
                if state.fail_start {
                    Err(SinkError::failed("fake start"))
                } else {
                    state.started = state.started.saturating_add(1);
                    Ok(())
                }
            }))
        }

        fn write<'a>(&'a self, envelope: &'a ResultEnvelope) -> ResultSinkFuture<'a> {
            let state = Arc::clone(&self.state);
            Box::pin(future::ready({
                let mut state = lock(&state);
                if state.fail_write {
                    Err(SinkError::failed("fake write"))
                } else {
                    state.writes.push((
                        envelope.sequence(),
                        envelope.event().result().label().to_owned(),
                        envelope.origin(),
                    ));
                    Ok(())
                }
            }))
        }

        fn flush<'a>(&'a self) -> ResultSinkFuture<'a> {
            let state = Arc::clone(&self.state);
            Box::pin(future::ready({
                let mut state = lock(&state);
                if state.fail_flush {
                    Err(SinkError::failed("fake flush"))
                } else {
                    state.flushed = state.flushed.saturating_add(1);
                    Ok(())
                }
            }))
        }

        fn finish<'a>(&'a self) -> ResultSinkFuture<'a> {
            let state = Arc::clone(&self.state);
            Box::pin(future::ready({
                let mut state = lock(&state);
                if state.fail_finish {
                    Err(SinkError::failed("fake finish"))
                } else {
                    state.finished = state.finished.saturating_add(1);
                    Ok(())
                }
            }))
        }

        fn cancel(&self) -> Result<(), SinkError> {
            let mut state = lock(&self.state);
            state.cancelled = state.cancelled.saturating_add(1);
            Ok(())
        }
    }

    fn event(label: &str) -> SampleEvent {
        let mut result = SampleResult::new(label);
        result.set_successful(true);
        SampleEvent::new(
            result,
            "run",
            ThreadIdentity::with_group("thread-1", Some("group".to_owned()), Some(1)),
            "host",
            jmeter_rs_results::VariableSnapshot::new(),
        )
    }

    fn metadata(id: u64, origin: ResultOrigin) -> ResultEventMetadata {
        ResultEventMetadata::new(
            NodeId::new(id),
            vec![NodeId::new(10), NodeId::new(id)],
            UserIdentity::new(1, NodeId::new(10), 1, 0),
            SampleIdentity::new(0),
            origin,
        )
        .expect("valid metadata")
    }

    fn router(
        first: Arc<Mutex<FakeState>>,
        second: Option<Arc<Mutex<FakeState>>>,
        limits: SinkLimits,
    ) -> ResultRouter {
        let mut specs = vec![ResultSinkSpec::new(
            SinkId::new(1),
            limits,
            Arc::new(FakeSink::new(first)),
        )];
        if let Some(state) = second {
            specs.push(ResultSinkSpec::new(
                SinkId::new(2),
                limits,
                Arc::new(FakeSink::new(state)),
            ));
        }
        ResultRouter::new("run", specs).expect("router")
    }

    #[test]
    fn ordering_identity_origin_and_original_snapshot_are_preserved() {
        let first = Arc::new(Mutex::new(FakeState::default()));
        let router = router(Arc::clone(&first), None, SinkLimits::new(4, 100_000));
        block_on(router.start()).expect("start");
        assert!(matches!(
            router.admit(
                event("one"),
                metadata(
                    11,
                    ResultOrigin::Sampler {
                        sampler_id: NodeId::new(11),
                        parent: Some(NodeId::new(12)),
                    }
                )
            ),
            AdmissionOutcome::Accepted {
                sequence: RunSequence(1),
                ..
            }
        ));
        assert!(matches!(
            router.admit(
                event("two"),
                metadata(
                    12,
                    ResultOrigin::Transaction {
                        controller_id: NodeId::new(12),
                        parent: None,
                    }
                )
            ),
            AdmissionOutcome::Accepted {
                sequence: RunSequence(2),
                ..
            }
        ));
        block_on(router.finish()).expect("finish");
        let state = lock(&first);
        assert_eq!(
            state.writes,
            vec![
                (
                    RunSequence(1),
                    "one".to_owned(),
                    ResultOrigin::Sampler {
                        sampler_id: NodeId::new(11),
                        parent: Some(NodeId::new(12)),
                    }
                ),
                (
                    RunSequence(2),
                    "two".to_owned(),
                    ResultOrigin::Transaction {
                        controller_id: NodeId::new(12),
                        parent: None,
                    }
                )
            ]
        );
        assert_eq!(state.finished, 1);
    }

    #[test]
    fn full_admission_is_transactional_across_isolated_sinks() {
        let first = Arc::new(Mutex::new(FakeState::default()));
        let second = Arc::new(Mutex::new(FakeState::default()));
        let router = router(
            Arc::clone(&first),
            Some(Arc::clone(&second)),
            SinkLimits::new(1, 100_000),
        );
        block_on(router.start()).expect("start");
        let origin = ResultOrigin::Sampler {
            sampler_id: NodeId::new(11),
            parent: None,
        };
        assert!(matches!(
            router.admit(event("one"), metadata(11, origin)),
            AdmissionOutcome::Accepted { .. }
        ));
        assert!(matches!(
            router.admit(
                event("two"),
                metadata(
                    12,
                    ResultOrigin::Sampler {
                        sampler_id: NodeId::new(12),
                        parent: None,
                    },
                ),
            ),
            AdmissionOutcome::Full {
                sink_id: SinkId(1),
                ..
            }
        ));
        assert_eq!(router.stats().sinks[0].queued_items, 1);
        assert_eq!(router.stats().sinks[1].queued_items, 1);
        block_on(router.finish()).expect("finish");
        assert_eq!(lock(&first).writes.len(), 1);
        assert_eq!(lock(&second).writes.len(), 1);
    }

    #[test]
    fn byte_admission_is_bounded_without_partial_reservation() {
        let state = Arc::new(Mutex::new(FakeState::default()));
        let router = router(Arc::clone(&state), None, SinkLimits::new(8, 1));
        block_on(router.start()).expect("start");
        assert!(matches!(
            router.admit(
                event("byte-full"),
                metadata(
                    11,
                    ResultOrigin::Sampler {
                        sampler_id: NodeId::new(11),
                        parent: None,
                    }
                )
            ),
            AdmissionOutcome::Full {
                sink_id: SinkId(1),
                bytes: _
            }
        ));
        assert_eq!(router.stats().next_sequence, RunSequence::new(1));
        assert_eq!(router.stats().sinks[0].queued_items, 0);
        block_on(router.finish()).expect("finish");
    }

    #[test]
    fn failed_sink_does_not_corrupt_healthy_sink_and_finalization_is_explicit() {
        let healthy = Arc::new(Mutex::new(FakeState::default()));
        let failed = Arc::new(Mutex::new(FakeState {
            fail_write: true,
            ..FakeState::default()
        }));
        let router = router(
            Arc::clone(&healthy),
            Some(Arc::clone(&failed)),
            SinkLimits::new(2, 100_000),
        );
        block_on(router.start()).expect("start");
        let origin = ResultOrigin::Sampler {
            sampler_id: NodeId::new(11),
            parent: None,
        };
        assert!(matches!(
            router.admit(event("one"), metadata(11, origin)),
            AdmissionOutcome::Accepted { .. }
        ));
        let drain = block_on(router.drain());
        assert!(matches!(drain, Err(ResultRouterError::Sink { .. })));
        assert_eq!(lock(&healthy).writes.len(), 1);
        assert!(router.stats().sinks[1].failed);
        assert!(matches!(
            router.admit(
                event("two"),
                metadata(
                    12,
                    ResultOrigin::Sampler {
                        sampler_id: NodeId::new(12),
                        parent: None,
                    },
                ),
            ),
            AdmissionOutcome::Failed { .. }
        ));
        assert!(block_on(router.finish()).is_err());
        assert_eq!(router.stats().sinks[1].queued_items, 0);
    }

    #[test]
    fn startup_failure_rolls_back_started_sinks_before_admission() {
        let first = Arc::new(Mutex::new(FakeState::default()));
        let second = Arc::new(Mutex::new(FakeState {
            fail_start: true,
            ..FakeState::default()
        }));
        let router = ResultRouter::new(
            "run",
            [
                ResultSinkSpec::new(
                    SinkId::new(1),
                    SinkLimits::new(1, 100_000),
                    Arc::new(FakeSink::new(Arc::clone(&first))),
                ),
                ResultSinkSpec::new(
                    SinkId::new(2),
                    SinkLimits::new(1, 100_000),
                    Arc::new(FakeSink::new(Arc::clone(&second))),
                ),
            ],
        )
        .expect("router");
        assert!(matches!(
            block_on(router.start()),
            Err(ResultRouterError::Sink {
                sink_id: SinkId(2),
                operation: "start",
                ..
            })
        ));
        assert_eq!(lock(&first).finished, 1);
        assert_eq!(router.stats().phase, RouterPhase::Failed);
        assert!(matches!(
            router.admit(
                event("closed"),
                metadata(
                    11,
                    ResultOrigin::Sampler {
                        sampler_id: NodeId::new(11),
                        parent: None,
                    }
                )
            ),
            AdmissionOutcome::Closed
        ));
    }

    #[test]
    fn cancellation_releases_all_item_and_byte_permits() {
        let state = Arc::new(Mutex::new(FakeState::default()));
        let router = router(Arc::clone(&state), None, SinkLimits::new(2, 100_000));
        block_on(router.start()).expect("start");
        assert!(matches!(
            router.admit(
                event("one"),
                metadata(
                    11,
                    ResultOrigin::Sampler {
                        sampler_id: NodeId::new(11),
                        parent: None,
                    }
                )
            ),
            AdmissionOutcome::Accepted { .. }
        ));
        assert!(matches!(
            router.cancel(),
            Err(ResultRouterError::Cancelled {
                pending_items: 1,
                pending_bytes: _
            })
        ));
        let stats = router.stats();
        assert_eq!(stats.phase, RouterPhase::Cancelled);
        assert_eq!(stats.sinks[0].queued_items, 0);
        assert_eq!(stats.sinks[0].queued_bytes, 0);
        assert!(matches!(
            router.admit(
                event("two"),
                metadata(
                    12,
                    ResultOrigin::Sampler {
                        sampler_id: NodeId::new(12),
                        parent: None,
                    }
                )
            ),
            AdmissionOutcome::Cancelled
        ));
        assert_eq!(lock(&state).cancelled, 1);
    }

    #[test]
    fn dropped_pending_delivery_cancels_sink_and_releases_permits() {
        let state = Arc::new(Mutex::new(FakeState::default()));
        let router = ResultRouter::new(
            "run",
            [ResultSinkSpec::new(
                SinkId::new(1),
                SinkLimits::new(1, 100_000),
                Arc::new(PendingSink {
                    state: Arc::clone(&state),
                }),
            )],
        )
        .expect("router");
        block_on(router.start()).expect("start");
        assert!(matches!(
            router.admit(
                event("pending"),
                metadata(
                    11,
                    ResultOrigin::Sampler {
                        sampler_id: NodeId::new(11),
                        parent: None,
                    }
                )
            ),
            AdmissionOutcome::Accepted { .. }
        ));

        let mut delivery = Box::pin(router.drain());
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        assert!(matches!(
            Pin::new(&mut delivery).poll(&mut context),
            Poll::Pending
        ));
        drop(delivery);

        let stats = router.stats();
        assert_eq!(stats.phase, RouterPhase::Cancelled);
        assert_eq!(stats.sinks[0].queued_items, 0);
        assert_eq!(stats.sinks[0].queued_bytes, 0);
        assert_eq!(lock(&state).cancelled, 1);
    }
}

#[cfg(test)]
mod revision3_tests {
    use super::*;

    fn event(label: &str) -> SampleEvent {
        let mut result = SampleResult::new(label);
        result.set_successful(true);
        SampleEvent::new(
            result,
            "run-text",
            ThreadIdentity::with_group("thread-1", Some("group".to_owned()), Some(1)),
            "host",
            jmeter_rs_results::VariableSnapshot::new(),
        )
    }

    struct Fixture {
        run: TypedRunId,
        generation: RunGeneration,
        domain: PlanDomain,
        root: PlanNodeRef,
        source: PlanNodeRef,
        worker: WorkerId,
        worker_generation: WorkerGeneration,
    }

    fn fixture() -> Fixture {
        let run = TypedRunId::from_run_identity(&RunIdentity::new("run-text")).expect("run");
        let generation = RunGeneration::new(1).expect("generation");
        let domain = PlanDomain::from_canonical_plan(b"canonical-plan").expect("domain");
        let root = PlanNodeRef::from_u64(domain, 1).expect("root");
        let source = PlanNodeRef::from_u64(domain, 2).expect("source");
        Fixture {
            run,
            generation,
            domain,
            root,
            source,
            worker: WorkerId::new(3).expect("worker"),
            worker_generation: WorkerGeneration::new(1).expect("worker generation"),
        }
    }

    fn envelope(fixture: &Fixture, sequence: u64, label: &str) -> TypedResultEnvelope {
        let user = TypedUserIdentity::new(1, fixture.root, 1, 0).expect("user");
        TypedResultEnvelope::new(
            TypedRunSequence::new(sequence).expect("sequence"),
            fixture.run,
            fixture.generation,
            fixture.worker,
            fixture.worker_generation,
            fixture.source,
            vec![fixture.root, fixture.source],
            user,
            ThreadIdentity::with_group("thread-1", Some("group".to_owned()), Some(1)),
            TypedSampleId::new(sequence).expect("sample"),
            TypedResultOrigin::Sampler {
                sampler: fixture.source,
                parent: None,
            },
            event(label),
        )
        .expect("typed envelope")
    }

    fn sink(fixture: &Fixture, node: u64, limits: SinkLimits, policy: FullPolicy) -> TypedSinkPlan {
        let collector = PlanNodeRef::from_u64(fixture.domain, node).expect("collector");
        TypedSinkPlan::new(
            QualifiedSinkId::from_parts(
                fixture.run,
                SinkPlanGeneration::new(1).expect("sink generation"),
                collector,
            ),
            limits,
            policy,
        )
    }

    fn router(fixture: &Fixture, limits: SinkLimits) -> TypedResultRouter {
        let mut router = TypedResultRouter::new(
            fixture.run,
            fixture.generation,
            RetryBudget::new(3),
            [
                sink(fixture, 4, limits, FullPolicy::FailRun),
                sink(fixture, 3, limits, FullPolicy::FailRun),
            ],
        )
        .expect("router");
        router.start().expect("start");
        router
    }

    #[test]
    fn sha256_and_identity_constructors_reject_reserved_values() {
        assert_eq!(
            hex_digest(Digest32::sha256(b"abc").as_bytes()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(matches!(
            TypedRunId::from_u128(0),
            Err(IdentityError::Zero { .. })
        ));
        assert!(matches!(
            RunGeneration::new(0),
            Err(IdentityError::Zero { .. })
        ));
        assert!(matches!(WorkerId::new(0), Err(IdentityError::Zero { .. })));
        assert!(matches!(
            TypedRunSequence::new(0),
            Err(IdentityError::Zero { .. })
        ));
        assert!(matches!(
            PlanDomain::from_canonical_plan(b""),
            Err(IdentityError::Empty { .. })
        ));
    }

    #[test]
    fn typed_envelope_binds_origin_path_and_original_snapshot() {
        let fixture = fixture();
        let first = envelope(&fixture, 1, "one");
        let second = envelope(&fixture, 2, "two");
        assert_eq!(first.event().result().label(), "one");
        assert_ne!(first.event_id(), second.event_id());
        assert_ne!(
            first.event_id().payload_digest(),
            second.event_id().payload_digest()
        );
        assert!(!first.origin().is_transaction());
        assert_eq!(first.plan_path().last().copied(), Some(fixture.source));
        let transaction = TypedResultEnvelope::new(
            TypedRunSequence::new(3).expect("sequence"),
            fixture.run,
            fixture.generation,
            fixture.worker,
            fixture.worker_generation,
            fixture.root,
            vec![fixture.root],
            TypedUserIdentity::new(1, fixture.root, 1, 0).expect("user"),
            ThreadIdentity::with_group("thread-1", Some("group".to_owned()), Some(1)),
            TypedSampleId::new(3).expect("sample"),
            TypedResultOrigin::Transaction {
                controller: fixture.root,
                parent: None,
            },
            event("transaction"),
        )
        .expect("transaction envelope");
        assert!(transaction.origin().is_transaction());
    }

    #[test]
    fn reservation_is_transactional_and_delivery_order_is_stable() {
        let fixture = fixture();
        let mut router = router(&fixture, SinkLimits::new(4, 100_000));
        let envelope = envelope(&fixture, 1, "one");
        let event_id = envelope.event_id();
        assert!(matches!(
            router.admit(envelope),
            Ok(TypedAdmissionOutcome::Accepted { .. })
        ));
        let first = router.next_delivery().expect("delivery").expect("first");
        let second = router.next_delivery().expect("delivery").expect("second");
        assert!(
            first.key().sink_id.collector().node_id().get()
                < second.key().sink_id.collector().node_id().get()
        );
        assert_eq!(first.envelope().event_id(), event_id);
        assert!(std::ptr::eq(
            first.envelope().event(),
            second.envelope().event()
        ));
        router
            .acknowledge(first.acknowledge(first.durability_boundary()).expect("ack"))
            .expect("first durable");
        router
            .acknowledge(
                second
                    .acknowledge(second.durability_boundary())
                    .expect("ack"),
            )
            .expect("second durable");
        let summary = router
            .ledger()
            .validate_conservation()
            .expect("conservation");
        assert_eq!(summary.selected, 2);
        assert_eq!(summary.accepted, 2);
        assert_eq!(summary.durable, 2);
        assert_eq!(summary.incomplete, 0);
        assert!(
            router
                .ledger()
                .transitions()
                .windows(2)
                .all(|pair| pair[0].ordinal < pair[1].ordinal)
        );
    }

    #[test]
    fn full_reservation_leaves_every_sink_unadmitted() {
        let fixture = fixture();
        let mut router = router(&fixture, SinkLimits::new(0, 0));
        let envelope = envelope(&fixture, 1, "full");
        let event_id = envelope.event_id();
        let outcome = router.admit(envelope).expect("outcome");
        assert!(matches!(outcome, TypedAdmissionOutcome::Failed { .. }));
        assert_eq!(router.ledger().summary().selected, 2);
        assert_eq!(router.ledger().summary().not_admitted, 2);
        assert_eq!(router.ledger().summary().accepted, 0);
        assert!(router.next_delivery().expect("delivery").is_none());
        assert!(router.ledger().transitions().iter().any(|transition| {
            transition.key.event_id == event_id
                && matches!(
                    transition.to,
                    LedgerState::Disposition(LedgerDisposition::NotAdmitted(_))
                )
        }));
    }

    #[test]
    fn backpressure_retries_same_event_with_shared_budget() {
        let fixture = fixture();
        let plan = sink(
            &fixture,
            3,
            SinkLimits::new(1, 100_000),
            FullPolicy::Backpressure {
                deadline: RetryBudget::new(2),
            },
        );
        let mut router =
            TypedResultRouter::new(fixture.run, fixture.generation, RetryBudget::new(2), [plan])
                .expect("router");
        router.start().expect("start");
        let first = envelope(&fixture, 1, "first");
        router.admit(first).expect("first admission");
        let pending = envelope(&fixture, 2, "pending");
        let full = router.admit(pending.clone()).expect("full outcome");
        assert!(matches!(full, TypedAdmissionOutcome::Full { .. }));
        assert_eq!(router.ledger().summary().selected, 1);
        let lease = router.next_delivery().expect("delivery").expect("lease");
        router
            .acknowledge(lease.acknowledge(lease.durability_boundary()).expect("ack"))
            .expect("durable");
        let accepted = router.retry_admission(pending).expect("retry outcome");
        assert!(matches!(accepted, TypedAdmissionOutcome::Accepted { .. }));
        assert_eq!(router.remaining_budget().remaining(), 1);
    }

    #[test]
    fn diagnosed_drop_is_explicit_non_compatibility_terminal_accounting() {
        let fixture = fixture();
        let plan = sink(
            &fixture,
            3,
            SinkLimits::with_finalization(1, 100_000, 1),
            FullPolicy::DiagnosedDrop {
                reason: BoundedDiagnostic::new("sampled-out by policy"),
            },
        );
        let mut router =
            TypedResultRouter::new(fixture.run, fixture.generation, RetryBudget::new(1), [plan])
                .expect("router");
        router.start().expect("start");
        let outcome = router
            .admit(envelope(&fixture, 1, "drop"))
            .expect("outcome");
        assert!(matches!(outcome, TypedAdmissionOutcome::Accepted { .. }));
        assert!(matches!(
            router.admit(envelope(&fixture, 2, "drop-two")),
            Ok(TypedAdmissionOutcome::Full { .. })
        ));
        let lease = router.next_delivery().expect("delivery").expect("lease");
        router
            .diagnosed_drop(lease.key(), BoundedDiagnostic::new("sampled-out by policy"))
            .expect("diagnosed drop");
        assert_eq!(router.ledger().summary().diagnosed_drop, 1);
        assert_eq!(router.ledger().summary().admitted, 1);
        assert!(router.ledger().validate_conservation().is_ok());
        assert_eq!(router.ledger().summary().not_admitted, 1);
        let report = router.ledger().finalization_report();
        assert_eq!(report.selected, 2);
        assert_eq!(report.not_admitted, 1);
        assert_eq!(report.admitted, 1);
        assert_eq!(report.diagnosed_drop, 1);
        assert_eq!(report.failed_after_admission, 0);
        report.validate_conservation().expect("report conservation");
    }

    #[test]
    fn cancellation_accounts_accepted_work_instead_of_clearing_it() {
        let fixture = fixture();
        let mut router = router(&fixture, SinkLimits::new(2, 100_000));
        assert!(matches!(
            router.admit(envelope(&fixture, 1, "cancel")),
            Ok(TypedAdmissionOutcome::Accepted { .. })
        ));
        router.cancel().expect("cancel");
        let summary = router
            .ledger()
            .validate_conservation()
            .expect("conservation");
        assert_eq!(summary.selected, 2);
        assert_eq!(summary.accepted, 2);
        assert_eq!(summary.failed, 2);
        assert_eq!(summary.incomplete, 0);
        assert_eq!(router.phase(), TypedRouterPhase::Cancelled);
    }

    #[test]
    fn retry_keeps_event_sink_identity_and_forbids_unknown_outcome_retry() {
        let fixture = fixture();
        let mut router = TypedResultRouter::new(
            fixture.run,
            fixture.generation,
            RetryBudget::new(3),
            [sink(
                &fixture,
                3,
                SinkLimits::new(2, 100_000),
                FullPolicy::Backpressure {
                    deadline: RetryBudget::new(2),
                },
            )],
        )
        .expect("router");
        router.start().expect("start");
        router.admit(envelope(&fixture, 1, "retry")).expect("admit");
        let lease = router.next_delivery().expect("delivery").expect("lease");
        let key = lease.key();
        let idempotency_key = lease.idempotency_key();
        router
            .fail(
                key,
                FailureReason::Retryable(BoundedDiagnostic::new("temporary")),
            )
            .expect("retryable failure");
        router.retry(key).expect("retry");
        let retried = router.next_delivery().expect("delivery").expect("retried");
        assert_eq!(retried.key(), key);
        assert_eq!(retried.idempotency_key(), idempotency_key);
        assert_eq!(retried.attempt().get(), 2);
        router
            .acknowledge(
                retried
                    .acknowledge(retried.durability_boundary())
                    .expect("ack"),
            )
            .expect("durable");

        router
            .admit(envelope(&fixture, 2, "unknown"))
            .expect("admit");
        let unknown = router.next_delivery().expect("delivery").expect("lease");
        router
            .fail(
                unknown.key(),
                FailureReason::UnknownOutcome(BoundedDiagnostic::new("unknown")),
            )
            .expect("unknown failure");
        assert!(matches!(
            router.retry(unknown.key()),
            Err(TypedRouterError::Ledger(
                LedgerError::RetryAfterUnknownOutcome
            ))
        ));
    }

    #[test]
    fn sink_failure_isolation_leaves_other_sink_deliverable() {
        let fixture = fixture();
        let mut router = router(&fixture, SinkLimits::new(2, 100_000));
        router
            .admit(envelope(&fixture, 1, "isolated"))
            .expect("admit");
        let first = router.next_delivery().expect("delivery").expect("first");
        router
            .fail(
                first.key(),
                FailureReason::Permanent(BoundedDiagnostic::new("sink failed")),
            )
            .expect("failure");
        let second = router.next_delivery().expect("delivery").expect("second");
        assert_ne!(first.key().sink_id, second.key().sink_id);
        router
            .acknowledge(
                second
                    .acknowledge(second.durability_boundary())
                    .expect("ack"),
            )
            .expect("other sink durable");
        assert_eq!(router.ledger().summary().failed, 1);
        assert_eq!(router.ledger().summary().durable, 1);
    }

    #[test]
    fn failed_sink_accounts_its_remaining_queue_without_blocking_healthy_sink() {
        let fixture = fixture();
        let mut router = router(&fixture, SinkLimits::new(4, 100_000));
        router
            .admit(envelope(&fixture, 1, "one"))
            .expect("admit one");
        router
            .admit(envelope(&fixture, 2, "two"))
            .expect("admit two");
        let failed_lease = router.next_delivery().expect("delivery").expect("lease");
        let failed_sink = failed_lease.key().sink_id;
        router
            .fail(
                failed_lease.key(),
                FailureReason::Permanent(BoundedDiagnostic::new("isolated failure")),
            )
            .expect("fail sink");
        while let Some(lease) = router.next_delivery().expect("delivery") {
            if lease.key().sink_id != failed_sink {
                router
                    .acknowledge(lease.acknowledge(lease.durability_boundary()).expect("ack"))
                    .expect("healthy durable");
            }
        }
        let summary = router
            .ledger()
            .validate_conservation()
            .expect("conservation");
        assert_eq!(summary.selected, 4);
        assert_eq!(summary.failed, 2);
        assert_eq!(summary.durable, 2);
    }

    #[test]
    fn finalization_report_retains_incomplete_references() {
        let fixture = fixture();
        let mut router = router(&fixture, SinkLimits::new(2, 100_000));
        router
            .admit(envelope(&fixture, 1, "pending"))
            .expect("admit");
        let report = router.ledger().finalization_report();
        assert!(!report.conservation_valid);
        assert!(report.sinks.iter().all(|sink| !sink.incomplete.is_empty()));
        assert!(report.validate_conservation().is_err());
    }

    #[test]
    fn lifecycle_boundaries_and_closed_transition_matrix_are_deterministic() {
        let fixture = fixture();
        let mut router = router(&fixture, SinkLimits::new(2, 100_000));
        assert_eq!(router.phase(), TypedRouterPhase::Open);
        assert!(router.stop_admission().is_ok());
        assert!(router.admit(envelope(&fixture, 1, "closed")).is_ok());
        assert!(matches!(
            router.admit(envelope(&fixture, 1, "closed-again")),
            Ok(TypedAdmissionOutcome::Closed)
        ));
        assert!(router.flush().is_ok());
        assert_eq!(router.phase(), TypedRouterPhase::Flushed);
        assert!(router.finish().is_ok());
        assert_eq!(router.phase(), TypedRouterPhase::Finished);

        let mut ledger = DeliveryLedger::new();
        let event_id = envelope(&fixture, 1, "matrix").event_id();
        let sink_id = sink(
            &fixture,
            3,
            SinkLimits::new(2, 100_000),
            FullPolicy::FailRun,
        )
        .id;
        let key = DeliveryKey { event_id, sink_id };
        ledger.select(key, 1, 0).expect("select");
        ledger.queued(key, 0).expect("queue");
        ledger.processing(key, 0).expect("processing");
        assert!(matches!(
            ledger.not_admitted(key, NotAdmittedReason::Closed),
            Err(LedgerError::InvalidTransition { .. })
        ));
        let lease_key = key;
        let ack = DurabilityAck::new(
            event_id,
            sink_id,
            AttemptOrdinal::new(1).expect("attempt"),
            DurabilityBoundary::Flushed,
            ledger.idempotency_key(lease_key).expect("key"),
        )
        .expect("ack");
        ledger.durable(ack, 0).expect("durable");
        assert!(ledger.processing(key, 0).is_err());
        assert!(ledger.validate_conservation().is_ok());
    }

    #[test]
    fn profile_capability_identity_changes_plan_domain_deterministically() {
        let first_profile = ProfileIdentity::new("jmeter", "5.6.3").expect("profile");
        let second_profile = ProfileIdentity::new("jmeter", "5.6.4").expect("profile");
        let capability = CapabilityIdentity::new("result-router", "4").expect("capability");
        let first = PlanDomain::from_canonical_plan_and_profile(
            b"plan",
            b"module",
            first_profile.clone(),
            vec![capability.clone()],
        )
        .expect("domain");
        let reordered = PlanDomain::from_canonical_plan_and_profile(
            b"plan",
            b"module",
            first_profile,
            vec![capability.clone()],
        )
        .expect("domain");
        let changed_profile = PlanDomain::from_canonical_plan_and_profile(
            b"plan",
            b"module",
            second_profile,
            vec![capability],
        )
        .expect("domain");
        assert_eq!(first, reordered);
        assert_ne!(first, changed_profile);
        let unsorted = ProfileCapabilityIdentity::from_unsorted(
            ProfileIdentity::new("jmeter", "5.6.3").expect("profile"),
            vec![
                CapabilityIdentity::new("z", "1").expect("capability"),
                CapabilityIdentity::new("a", "1").expect("capability"),
            ],
        )
        .expect("canonical set");
        assert_eq!(unsorted.capabilities()[0].id(), "a");
    }

    #[test]
    fn payload_digest_binds_metadata_and_public_result_presence() {
        let fixture = fixture();
        let original = envelope(&fixture, 1, "digest");
        let mut changed_result = SampleResult::new("digest");
        changed_result.set_successful(true);
        changed_result.set_response_data_bytes(vec![1, 2, 3]);
        let changed = TypedResultEnvelope::new(
            TypedRunSequence::new(1).expect("sequence"),
            fixture.run,
            fixture.generation,
            fixture.worker,
            fixture.worker_generation,
            fixture.source,
            vec![fixture.root, fixture.source],
            TypedUserIdentity::new(1, fixture.root, 1, 0).expect("user"),
            ThreadIdentity::with_group("thread-1", Some("group".to_owned()), Some(1)),
            TypedSampleId::new(1).expect("sample"),
            TypedResultOrigin::Sampler {
                sampler: fixture.source,
                parent: None,
            },
            SampleEvent::new(
                changed_result,
                "run-text",
                ThreadIdentity::with_group("thread-1", Some("group".to_owned()), Some(1)),
                "host",
                jmeter_rs_results::VariableSnapshot::new(),
            ),
        )
        .expect("changed envelope");
        assert_ne!(original.payload_digest(), changed.payload_digest());

        let alternate_domain = PlanDomain::from_canonical_plan_and_profile_text(
            b"another-plan",
            b"module",
            "jmeter",
            "5.6.3",
            vec![("result-router".to_owned(), "4".to_owned())],
        )
        .expect("domain");
        let alternate_source = PlanNodeRef::from_u64(alternate_domain, 2).expect("source");
        let alternate_root = PlanNodeRef::from_u64(alternate_domain, 1).expect("root");
        let alternate = TypedResultEnvelope::new(
            TypedRunSequence::new(1).expect("sequence"),
            fixture.run,
            fixture.generation,
            fixture.worker,
            fixture.worker_generation,
            alternate_source,
            vec![alternate_root, alternate_source],
            TypedUserIdentity::new(1, alternate_root, 1, 0).expect("user"),
            ThreadIdentity::with_group("thread-1", Some("group".to_owned()), Some(1)),
            TypedSampleId::new(1).expect("sample"),
            TypedResultOrigin::Sampler {
                sampler: alternate_source,
                parent: None,
            },
            event("digest"),
        )
        .expect("alternate envelope");
        assert_ne!(original.payload_digest(), alternate.payload_digest());
    }

    #[test]
    fn idempotency_key_excludes_attempt_but_binds_boundary() {
        let fixture = fixture();
        let event_id = envelope(&fixture, 1, "key").event_id();
        let sink_id = sink(
            &fixture,
            3,
            SinkLimits::new(2, 100_000),
            FullPolicy::FailRun,
        )
        .id;
        let key = DeliveryKey { event_id, sink_id };
        let mut first = DeliveryLedger::new();
        first
            .select_with_boundary(key, 1, 0, DurabilityBoundary::Flushed)
            .expect("select");
        let stable = first.idempotency_key(key).expect("key");
        let mut second = DeliveryLedger::new();
        second
            .select_with_boundary(key, 1, 0, DurabilityBoundary::Synced)
            .expect("select");
        assert_ne!(stable, second.idempotency_key(key).expect("key"));
        assert_eq!(first.entry(key).expect("entry").attempts.get(), 1);
        assert_eq!(
            stable,
            delivery_idempotency_key(key, DurabilityBoundary::Flushed)
        );
        assert!(matches!(
            first.diagnosed_drop(key, BoundedDiagnostic::new("too early"), true),
            Err(LedgerError::InvalidTransition { .. })
        ));
    }

    struct TestClock(std::cell::Cell<u64>);

    impl MonotonicClock for TestClock {
        fn now_ticks(&self) -> u64 {
            self.0.get()
        }
    }

    struct TestCancellation(std::cell::Cell<bool>);

    impl CancellationSignal for TestCancellation {
        fn is_cancelled(&self) -> bool {
            self.0.get()
        }

        fn register_waker(&self, _waker: &Waker) {}
    }

    #[test]
    fn finite_budget_uses_monotonic_phase_deadline_and_cancellation() {
        let clock = TestClock(std::cell::Cell::new(10));
        let cancellation = TestCancellation(std::cell::Cell::new(false));
        let mut budget =
            RunOperationBudget::new(&clock, &cancellation, 5, RetryBudget::new(1)).expect("budget");
        assert_eq!(budget.remaining_ticks(), 5);
        budget.with_phase_deadline(13);
        assert_eq!(budget.remaining_ticks(), 3);
        budget.consume_attempt().expect("attempt");
        assert_eq!(budget.retry_budget().remaining(), 0);
        assert_eq!(budget.remaining_ticks(), 3);
        assert!(matches!(
            budget.consume_attempt(),
            Err(BudgetError::RetryBudgetExhausted)
        ));
        clock.0.set(13);
        assert!(matches!(budget.check(), Err(BudgetError::Expired)));
        cancellation.0.set(true);
        assert!(matches!(budget.check(), Err(BudgetError::Cancelled)));
    }
}
