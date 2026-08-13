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

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::future::{self, Future};
use std::num::NonZeroU64;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::Waker;
use std::time::Duration;

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

// A sink queue cannot require more transition records than the bounded
// ledger can retain.  Keeping this admission bound explicit also prevents a
// trusted but nonsensical `usize::MAX` queue setting from turning a run into
// an effectively unbounded resource reservation.
const MAX_TYPED_QUEUE_ITEMS: usize = MAX_LEDGER_TRANSITIONS / 2;

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

fn redact_diagnostic(mut value: String) -> String {
    // Sink and ledger diagnostics can originate at an effectful adapter.  Do
    // not retain the common credential-shaped fields even when an adapter
    // accidentally includes them in an error.  This deliberately stays
    // dependency-free and deterministic; it is not intended to parse a
    // general configuration language.
    const SECRET_KEYS: [&str; 9] = [
        "password",
        "passwd",
        "token",
        "secret",
        "authorization",
        "api_key",
        "apikey",
        "access_key",
        "client_secret",
    ];
    // Bound the scan before cloning so a misbehaving adapter cannot make the
    // redaction pass retain an unbounded second copy of its diagnostic.
    let scan_limit = MAX_DIAGNOSTIC_BYTES.saturating_add(256);
    if value.len() > scan_limit {
        let mut end = scan_limit;
        while end > 0 && !value.is_char_boundary(end) {
            end -= 1;
        }
        value.truncate(end);
    }
    let original = value.clone();
    let mut output = String::with_capacity(original.len());
    let mut cursor = 0;
    while cursor < original.len() {
        let Some(relative) = original[cursor..]
            .find(|character: char| character.is_ascii_alphabetic() || character == '_')
        else {
            output.push_str(&original[cursor..]);
            break;
        };
        let start = cursor + relative;
        output.push_str(&original[cursor..start]);
        let end = original[start..]
            .find(|character: char| {
                !(character.is_ascii_alphanumeric() || character == '_' || character == '-')
            })
            .map_or(original.len(), |offset| start + offset);
        let word = &original[start..end];
        let lower = word.to_ascii_lowercase();
        let is_boundary = start == 0
            || !original[..start]
                .chars()
                .next_back()
                .is_some_and(|character| character.is_ascii_alphanumeric() || character == '_');
        let key = SECRET_KEYS
            .iter()
            .find(|candidate| lower.eq_ignore_ascii_case(candidate));
        let after = &original[end..];
        let separator = after
            .chars()
            .next()
            .filter(|character| *character == '=' || *character == ':');
        if is_boundary && key.is_some() && separator.is_some() {
            output.push_str(word);
            output.push(after.chars().next().unwrap_or('='));
            output.push_str("<redacted>");
            let mut skip = end + 1;
            while skip < original.len()
                && !matches!(original.as_bytes()[skip], b' ' | b'\t' | b',' | b';' | b')')
            {
                skip += 1;
            }
            cursor = skip;
        } else {
            output.push_str(word);
            cursor = end;
        }
    }
    value.clear();
    value.push_str(&output);
    value
}

fn bounded_text_with_limit(mut value: String, limit: usize) -> String {
    value = redact_diagnostic(value);
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
    /// Checked accounting for an identity or immutable envelope overflowed.
    Overflow { field: &'static str },
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
            Self::Overflow { field } => write!(formatter, "identity.{field}.overflow"),
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
    /// The fallible monotonic clock could not produce a reading.
    Clock(ResultClockError),
    /// The operation window was zero and therefore could not own a pending
    /// operation.
    ZeroOperationWindow,
    /// The run-owned operation identity allocator exhausted its checked
    /// non-zero domain.
    OperationIdExhausted,
    /// A checked attempt ordinal could not be represented.
    AttemptOrdinalOverflow,
    /// The application wait registrar rejected this operation's exact wait.
    Wait(ResultWaitError),
    /// A sink is outside the authority's bound run or selected sink set.
    ScopeMismatch,
    /// Finalization was requested more than once with a different authority
    /// state.
    FinalizationAlreadyStarted,
}

impl fmt::Display for BudgetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clock(error) => error.fmt(formatter),
            Self::Cancelled => formatter.write_str("result.budget.cancelled"),
            Self::Expired => formatter.write_str("result.budget.expired"),
            Self::RetryBudgetExhausted => formatter.write_str("result.budget.retry-exhausted"),
            Self::DeadlineOverflow => formatter.write_str("result.budget.deadline-overflow"),
            Self::ZeroOperationWindow => formatter.write_str("result.budget.zero-operation-window"),
            Self::OperationIdExhausted => {
                formatter.write_str("result.budget.operation-id-exhausted")
            }
            Self::AttemptOrdinalOverflow => {
                formatter.write_str("result.budget.attempt-ordinal-overflow")
            }
            Self::Wait(error) => error.fmt(formatter),
            Self::ScopeMismatch => formatter.write_str("result.budget.scope-mismatch"),
            Self::FinalizationAlreadyStarted => {
                formatter.write_str("result.budget.finalization-already-started")
            }
        }
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
pub trait CancellationSignal: Send + Sync {
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
        match deadline.checked_sub(self.clock.now_ticks()) {
            Some(remaining) => remaining,
            None => 0,
        }
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

// ---------------------------------------------------------------------------
// Decision 0015: run-owned result-delivery liveness
// ---------------------------------------------------------------------------
//
// `RunOperationBudget` above is retained as a deprecated compatibility seam
// for older embedders.  It must not be used by the typed production router:
// its borrowed shape and one absolute deadline describe the superseded
// arbitrary run-start budget.  The types below make the authority explicit,
// share retry accounting through one allocation, and give every semantic
// operation one finite, non-refreshing lease.

/// A fallible error from the run's monotonic clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultClockError {
    /// The clock provider could not produce a reading.
    Unavailable,
    /// A provider returned a reading earlier than its previous reading.
    Reversed {
        /// The last accepted reading.
        previous: crate::MonotonicInstant,
        /// The invalid reading.
        current: crate::MonotonicInstant,
    },
    /// The provider returned a value that could not be represented in the
    /// shared monotonic domain.
    Overflow,
}

impl fmt::Display for ResultClockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("result.clock.unavailable"),
            Self::Reversed { .. } => formatter.write_str("result.clock.reversed"),
            Self::Overflow => formatter.write_str("result.clock.overflow"),
        }
    }
}

impl std::error::Error for ResultClockError {}

/// Supplies the one monotonic time domain used by all result operations.
///
/// The trait is intentionally fallible.  A sink must not turn a failed clock
/// read into a large deadline or otherwise continue with an invented time.
pub trait ResultMonotonicClock: Send + Sync {
    /// Reads the current absolute monotonic instant.
    fn now(&self) -> Result<crate::MonotonicInstant, ResultClockError>;
}

impl<F> ResultMonotonicClock for F
where
    F: Fn() -> Result<crate::MonotonicInstant, ResultClockError> + Send + Sync,
{
    fn now(&self) -> Result<crate::MonotonicInstant, ResultClockError> {
        self()
    }
}

/// Compatibility alias for callers that prefer the decision's terminology.
pub use ResultMonotonicClock as FallibleMonotonicClock;

/// The semantic operation whose liveness is bounded by one lease.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ResultOperationKind {
    /// Sink startup/readiness handshake.
    Start,
    /// Queue admission blocked by a full sink.
    AdmissionBackpressure,
    /// Processing one event for one sink, including retries.
    Process,
    /// Flushing accepted sink data.
    Flush,
    /// Finishing/closing one sink.
    Finish,
    /// Recovering one result transaction.
    Recovery,
}

/// The run and selected sink scope owned by a result-delivery authority.
///
/// A sink-set scope is used for run-wide admission and finalization work. A
/// sink scope is allocated for effectful work against one qualified sink. The
/// authority validates the sink binding before allocating the operation ID,
/// so a provider cannot accidentally wait under another sink's identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ResultOperationScope {
    /// The selected sink set for one run and plan generation.
    SinkSet {
        /// Run identity.
        run: TypedRunId,
        /// Selected sink-plan generation.
        sink_plan_generation: SinkPlanGeneration,
    },
    /// One sink in the selected set.
    Sink {
        /// Run identity.
        run: TypedRunId,
        /// Fully qualified sink identity.
        sink: QualifiedSinkId,
    },
}

impl ResultOperationScope {
    /// Creates the run-wide selected sink-set scope.
    #[must_use]
    pub const fn sink_set(run: TypedRunId, sink_plan_generation: SinkPlanGeneration) -> Self {
        Self::SinkSet {
            run,
            sink_plan_generation,
        }
    }

    /// Returns the run identity bound to this scope.
    #[must_use]
    pub const fn run(self) -> TypedRunId {
        match self {
            Self::SinkSet { run, .. } | Self::Sink { run, .. } => run,
        }
    }

    /// Returns whether this scope contains the qualified sink.
    #[must_use]
    pub fn contains(self, sink: QualifiedSinkId) -> bool {
        match self {
            Self::SinkSet {
                run,
                sink_plan_generation,
            } => sink.run_id() == run && sink.sink_plan_generation() == sink_plan_generation,
            Self::Sink {
                run,
                sink: selected,
            } => run == sink.run_id() && selected == sink,
        }
    }

    /// Narrows a selected sink-set scope to one sink.
    fn for_sink(self, sink: QualifiedSinkId) -> Option<Self> {
        if self.contains(sink) {
            Some(Self::Sink {
                run: self.run(),
                sink,
            })
        } else {
            None
        }
    }
}

impl ResultOperationKind {
    const fn name(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::AdmissionBackpressure => "admission-backpressure",
            Self::Process => "process",
            Self::Flush => "flush",
            Self::Finish => "finish",
            Self::Recovery => "recovery",
        }
    }
}

/// Explicit finite windows admitted for each result operation kind.
///
/// No `Default` implementation is provided deliberately: a production run
/// must select its operation policy explicitly and no value here limits the
/// duration of the load test itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResultOperationWindows {
    start: Duration,
    admission_backpressure: Duration,
    process: Duration,
    flush: Duration,
    finish: Duration,
    recovery: Duration,
    finalization: Duration,
}

impl ResultOperationWindows {
    /// Creates explicit windows for every semantic operation and the shared
    /// finalization cap.
    #[must_use]
    pub const fn new(
        start: Duration,
        admission_backpressure: Duration,
        process: Duration,
        flush: Duration,
        finish: Duration,
        recovery: Duration,
        finalization: Duration,
    ) -> Self {
        Self {
            start,
            admission_backpressure,
            process,
            flush,
            finish,
            recovery,
            finalization,
        }
    }

    /// Builds explicit uniform operation windows while keeping a separately
    /// selected finalization cap.
    #[must_use]
    pub const fn uniform(operation: Duration, finalization: Duration) -> Self {
        Self::new(
            operation,
            operation,
            operation,
            operation,
            operation,
            operation,
            finalization,
        )
    }

    fn window(self, kind: ResultOperationKind) -> Duration {
        match kind {
            ResultOperationKind::Start => self.start,
            ResultOperationKind::AdmissionBackpressure => self.admission_backpressure,
            ResultOperationKind::Process => self.process,
            ResultOperationKind::Flush => self.flush,
            ResultOperationKind::Finish => self.finish,
            ResultOperationKind::Recovery => self.recovery,
        }
    }

    fn validate(self) -> Result<(), BudgetError> {
        let windows = [
            (ResultOperationKind::Start, self.start),
            (
                ResultOperationKind::AdmissionBackpressure,
                self.admission_backpressure,
            ),
            (ResultOperationKind::Process, self.process),
            (ResultOperationKind::Flush, self.flush),
            (ResultOperationKind::Finish, self.finish),
            (ResultOperationKind::Recovery, self.recovery),
        ];
        if windows
            .iter()
            .any(|(_, duration)| *duration == Duration::ZERO)
            || self.finalization == Duration::ZERO
        {
            return Err(BudgetError::ZeroOperationWindow);
        }
        Ok(())
    }

    /// Returns the selected finalization cap.
    #[must_use]
    pub const fn finalization(self) -> Duration {
        self.finalization
    }
}

/// Configuration for one run-owned result-delivery authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResultDeliveryBudgetConfig {
    /// Run and selected sink-set identity bound to every allocated lease.
    pub scope: ResultOperationScope,
    /// Explicit operation windows.
    pub windows: ResultOperationWindows,
    /// Shared retry attempts across all operations and sinks.
    pub max_retry_attempts: u32,
    /// Optional invocation/profile-provided whole-run deadline. `None` is the
    /// normal value and does not impose a run-duration ceiling.
    pub whole_run_deadline: Option<crate::MonotonicInstant>,
}

impl ResultDeliveryBudgetConfig {
    /// Creates explicit result-delivery policy.
    #[must_use]
    pub const fn new(
        scope: ResultOperationScope,
        windows: ResultOperationWindows,
        max_retry_attempts: u32,
        whole_run_deadline: Option<crate::MonotonicInstant>,
    ) -> Self {
        Self {
            scope,
            windows,
            max_retry_attempts,
            whole_run_deadline,
        }
    }
}

/// A checked, non-zero operation identity allocated by one run authority.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResultOperationId(NonZeroU64);

impl ResultOperationId {
    /// Creates an operation identity, rejecting zero.
    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Returns its non-zero numeric representation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Stable error from the narrow result wait-registration capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultWaitError {
    /// The registrar rejected the bounded registration.
    Rejected,
    /// The registrar has already shut down.
    Shutdown,
    /// The exact registration was retired already.
    AlreadyRetired,
    /// The capability is not installed for this production path.
    Unavailable,
}

impl fmt::Display for ResultWaitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Rejected => "result.wait.rejected",
            Self::Shutdown => "result.wait.shutdown",
            Self::AlreadyRetired => "result.wait.already-retired",
            Self::Unavailable => "result.wait.unavailable",
        })
    }
}

impl std::error::Error for ResultWaitError {}

/// Bounded input to a result wait registrar.  The waker is an executor token,
/// not a run future or result payload.
#[derive(Debug)]
pub struct ResultWaitSpec {
    /// Operation that owns this wait.
    pub operation: ResultOperationId,
    /// Typed wait owner supplied by the runtime/application boundary.
    pub owner: crate::WaitOwnerClass,
    /// One absolute, already-established deadline.
    pub deadline: crate::MonotonicInstant,
    /// Exact executor wake token.
    pub waker: Waker,
}

/// A registrar supplied by the application time owner.
pub trait ResultWaitRegistrar: Send + Sync {
    /// Registers one finite provider/queue wait before a future returns
    /// `Pending`.
    fn register(
        &self,
        spec: ResultWaitSpec,
    ) -> Result<Box<dyn ResultWaitRegistrationHandle>, ResultWaitError>;
}

/// The owned handle returned by a result wait registrar.
pub trait ResultWaitRegistrationHandle: Send {
    /// Retires the exact registration.
    fn retire(&mut self) -> Result<(), ResultWaitError>;
}

/// RAII guard for one exact result wait registration.
pub struct ResultWaitRegistration {
    handle: Option<Box<dyn ResultWaitRegistrationHandle>>,
}

impl fmt::Debug for ResultWaitRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResultWaitRegistration")
            .field("active", &self.handle.is_some())
            .finish()
    }
}

impl ResultWaitRegistration {
    fn new(handle: Box<dyn ResultWaitRegistrationHandle>) -> Self {
        Self {
            handle: Some(handle),
        }
    }

    /// Retires this exact registration and consumes the guard.
    pub fn retire(mut self) -> Result<(), ResultWaitError> {
        if let Some(mut handle) = self.handle.take() {
            handle.retire()
        } else {
            Ok(())
        }
    }

    /// Returns whether the exact registration is still owned by this guard.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.handle.is_some()
    }
}

impl Drop for ResultWaitRegistration {
    fn drop(&mut self) {
        if let Some(mut handle) = self.handle.take() {
            let _ = handle.retire();
        }
    }
}

/// Operation lease shared by a sink future and its retry path.
///
/// The lease is intentionally not `Clone`.  A caller can borrow it for the
/// lifetime of one sink future, but no operation can mint a second deadline
/// by polling, waking, retrying, or changing phase.
pub struct ResultOperationLease {
    authority: Arc<ResultDeliveryBudgetState>,
    id: ResultOperationId,
    scope: ResultOperationScope,
    kind: ResultOperationKind,
    deadline: crate::MonotonicInstant,
    allow_cancelled: bool,
}

impl fmt::Debug for ResultOperationLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResultOperationLease")
            .field("id", &self.id)
            .field("scope", &self.scope)
            .field("kind", &self.kind)
            .field("deadline", &self.deadline)
            .finish()
    }
}

impl ResultOperationLease {
    /// Returns the immutable operation identity.
    #[must_use]
    pub const fn id(&self) -> ResultOperationId {
        self.id
    }

    /// Returns the run/sink scope bound to this lease.
    #[must_use]
    pub fn scope(&self) -> ResultOperationScope {
        self.scope
    }

    /// Returns the semantic operation kind.
    #[must_use]
    pub const fn kind(&self) -> ResultOperationKind {
        self.kind
    }

    /// Returns the one absolute, non-refreshing deadline.
    #[must_use]
    pub const fn deadline(&self) -> crate::MonotonicInstant {
        self.deadline
    }

    /// Checks clock health and this lease's fixed deadline. Normal work also
    /// checks cancellation; cleanup leases intentionally continue to the
    /// shared finalization cap so accepted work is accounted for after a
    /// primary failure or cancellation request.
    pub fn check(&self) -> Result<(), BudgetError> {
        if !self.allow_cancelled && self.authority.cancellation.is_cancelled() {
            return Err(BudgetError::Cancelled);
        }
        let now = self.authority.now()?;
        if now >= self.deadline {
            return Err(BudgetError::Expired);
        }
        Ok(())
    }

    /// Returns the finite remaining duration without rebuilding a deadline.
    pub fn remaining(&self) -> Result<Duration, BudgetError> {
        self.check()?;
        self.deadline
            .duration_since(self.authority.now()?)
            .ok_or(BudgetError::Expired)
    }

    /// Consumes one retry from the shared run attempt ledger. Polls and
    /// ordinary progress do not consume attempts.
    pub fn consume_retry(&self) -> Result<AttemptOrdinal, BudgetError> {
        self.check()?;
        self.authority.consume_attempt()
    }

    /// Returns shared attempts remaining for a ledger diagnostic.
    #[must_use]
    pub fn attempts_remaining(&self) -> u32 {
        self.authority.attempts_remaining()
    }

    /// Registers the exact provider/queue wait before a sink future returns
    /// `Pending`. Completion, cancellation, timeout, and drop must retire the
    /// returned guard.
    pub fn register_wait(
        &self,
        registrar: &dyn ResultWaitRegistrar,
        owner: crate::WaitOwnerClass,
        waker: &Waker,
    ) -> Result<ResultWaitRegistration, BudgetError> {
        self.check()?;
        let waker = waker.clone();
        registrar
            .register(ResultWaitSpec {
                operation: self.id,
                owner,
                deadline: self.deadline,
                waker,
            })
            .map(ResultWaitRegistration::new)
            .map_err(BudgetError::Wait)
    }

    /// Registers this run's cancellation wake source for a pending provider
    /// future. The lease supplies the exact shared authority; adapters do not
    /// mint or retain a second cancellation token.
    pub fn register_waker(&self, waker: &Waker) {
        self.authority.cancellation.register_waker(waker);
    }
}

struct SharedAttemptLedger {
    remaining: u32,
    next_ordinal: u32,
}

impl SharedAttemptLedger {
    fn consume(&mut self) -> Result<AttemptOrdinal, BudgetError> {
        if self.remaining == 0 {
            return Err(BudgetError::RetryBudgetExhausted);
        }
        let ordinal = AttemptOrdinal::new(self.next_ordinal)
            .map_err(|_| BudgetError::AttemptOrdinalOverflow)?;
        self.next_ordinal = self
            .next_ordinal
            .checked_add(1)
            .ok_or(BudgetError::AttemptOrdinalOverflow)?;
        self.remaining -= 1;
        Ok(ordinal)
    }
}

struct ResultDeliveryBudgetState {
    scope: ResultOperationScope,
    clock: Arc<dyn ResultMonotonicClock>,
    cancellation: Arc<dyn CancellationSignal>,
    windows: ResultOperationWindows,
    attempts: Mutex<SharedAttemptLedger>,
    last_now: Mutex<crate::MonotonicInstant>,
    next_operation: AtomicU64,
    whole_run_deadline: Option<crate::MonotonicInstant>,
    finalization_deadline: Mutex<Option<crate::MonotonicInstant>>,
}

impl ResultDeliveryBudgetState {
    fn now(&self) -> Result<crate::MonotonicInstant, BudgetError> {
        let current = self.clock.now().map_err(BudgetError::Clock)?;
        let mut last = lock(&self.last_now);
        if current < *last {
            return Err(BudgetError::Clock(ResultClockError::Reversed {
                previous: *last,
                current,
            }));
        }
        *last = current;
        Ok(current)
    }

    fn allocate_operation_id(&self) -> Result<ResultOperationId, BudgetError> {
        let mut current = self.next_operation.load(Ordering::Acquire);
        loop {
            let next = current
                .checked_add(1)
                .ok_or(BudgetError::OperationIdExhausted)?;
            match self.next_operation.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return ResultOperationId::new(current)
                        .ok_or(BudgetError::OperationIdExhausted);
                }
                Err(observed) => current = observed,
            }
        }
    }

    fn effective_deadline(
        &self,
        kind: ResultOperationKind,
        now: crate::MonotonicInstant,
    ) -> Result<crate::MonotonicInstant, BudgetError> {
        if let Some(deadline) = self.whole_run_deadline
            && deadline <= now
        {
            return Err(BudgetError::Expired);
        }
        let mut deadline = now
            .checked_add(self.windows.window(kind))
            .ok_or(BudgetError::DeadlineOverflow)?;
        if let Some(run_deadline) = self.whole_run_deadline {
            deadline = deadline.min(run_deadline);
        }
        if let Some(finalization_deadline) = *lock(&self.finalization_deadline) {
            deadline = deadline.min(finalization_deadline);
        }
        if deadline <= now {
            return Err(BudgetError::Expired);
        }
        Ok(deadline)
    }

    fn consume_attempt(&self) -> Result<AttemptOrdinal, BudgetError> {
        lock(&self.attempts).consume()
    }

    fn attempts_remaining(&self) -> u32 {
        lock(&self.attempts).remaining
    }
}

/// One run-owned result-delivery authority. Clones share cancellation, clock,
/// operation identity allocation, finalization narrowing, and attempt state.
#[derive(Clone)]
pub struct ResultDeliveryBudget {
    state: Arc<ResultDeliveryBudgetState>,
}

impl fmt::Debug for ResultDeliveryBudget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResultDeliveryBudget")
            .field("attempts_remaining", &self.attempts_remaining())
            .field("whole_run_deadline", &self.state.whole_run_deadline)
            .field(
                "finalization_deadline",
                &lock(&self.state.finalization_deadline),
            )
            .finish()
    }
}

impl ResultDeliveryBudget {
    /// Creates one explicit run-owned authority.
    pub fn new(
        clock: Arc<dyn ResultMonotonicClock>,
        cancellation: Arc<dyn CancellationSignal>,
        config: ResultDeliveryBudgetConfig,
    ) -> Result<Self, BudgetError> {
        if let ResultOperationScope::Sink { run, sink } = config.scope
            && run != sink.run_id()
        {
            return Err(BudgetError::ScopeMismatch);
        }
        config.windows.validate()?;
        // Read once at construction so an unavailable clock fails before any
        // sink starts, while `None` still leaves the run duration unbounded.
        let now = clock.now().map_err(BudgetError::Clock)?;
        if let Some(deadline) = config.whole_run_deadline
            && deadline <= now
        {
            return Err(BudgetError::Expired);
        }
        Ok(Self {
            state: Arc::new(ResultDeliveryBudgetState {
                scope: config.scope,
                clock,
                cancellation,
                windows: config.windows,
                attempts: Mutex::new(SharedAttemptLedger {
                    remaining: config.max_retry_attempts,
                    next_ordinal: 1,
                }),
                last_now: Mutex::new(now),
                next_operation: AtomicU64::new(1),
                whole_run_deadline: config.whole_run_deadline,
                finalization_deadline: Mutex::new(None),
            }),
        })
    }

    /// Convenience constructor retaining all policy as explicit arguments.
    pub fn from_parts(
        scope: ResultOperationScope,
        clock: Arc<dyn ResultMonotonicClock>,
        cancellation: Arc<dyn CancellationSignal>,
        windows: ResultOperationWindows,
        max_retry_attempts: u32,
        whole_run_deadline: Option<crate::MonotonicInstant>,
    ) -> Result<Self, BudgetError> {
        Self::new(
            clock,
            cancellation,
            ResultDeliveryBudgetConfig::new(scope, windows, max_retry_attempts, whole_run_deadline),
        )
    }

    /// Returns the run/sink-set scope selected for this authority.
    #[must_use]
    pub fn scope(&self) -> ResultOperationScope {
        self.state.scope
    }

    /// Starts one finite semantic operation lease. The deadline is fixed and
    /// automatically narrowed by whole-run/finalization deadlines.
    pub fn begin_operation(
        &self,
        kind: ResultOperationKind,
    ) -> Result<ResultOperationLease, BudgetError> {
        if self.state.cancellation.is_cancelled() {
            return Err(BudgetError::Cancelled);
        }
        self.begin_operation_in_scope(self.state.scope, kind, false)
    }

    fn begin_operation_in_scope(
        &self,
        scope: ResultOperationScope,
        kind: ResultOperationKind,
        allow_cancelled: bool,
    ) -> Result<ResultOperationLease, BudgetError> {
        if !allow_cancelled && self.state.cancellation.is_cancelled() {
            return Err(BudgetError::Cancelled);
        }
        let now = self.state.now()?;
        let deadline = self.state.effective_deadline(kind, now)?;
        let id = self.state.allocate_operation_id()?;
        Ok(ResultOperationLease {
            authority: Arc::clone(&self.state),
            id,
            scope,
            kind,
            deadline,
            allow_cancelled,
        })
    }

    /// Starts one normal effectful operation bound to one configured sink.
    /// The operation ID is still allocated by this shared run authority.
    pub fn begin_sink_operation(
        &self,
        sink: QualifiedSinkId,
        kind: ResultOperationKind,
    ) -> Result<ResultOperationLease, BudgetError> {
        let scope = self
            .state
            .scope
            .for_sink(sink)
            .ok_or(BudgetError::ScopeMismatch)?;
        self.begin_operation_in_scope(scope, kind, false)
    }

    /// Alias using the decision's admitted-operation wording.
    pub fn admit_operation(
        &self,
        kind: ResultOperationKind,
    ) -> Result<ResultOperationLease, BudgetError> {
        self.begin_operation(kind)
    }

    /// Establishes one shared finalization deadline. Repeated calls return a
    /// view of the same absolute cap rather than refreshing it.
    pub fn begin_finalization(&self) -> Result<ResultFinalizationLease, BudgetError> {
        if let Some(deadline) = *lock(&self.state.finalization_deadline) {
            return Ok(ResultFinalizationLease {
                budget: self.clone(),
                deadline,
            });
        }
        let now = self.state.now()?;
        if let Some(run_deadline) = self.state.whole_run_deadline
            && run_deadline <= now
        {
            return Err(BudgetError::Expired);
        }
        let mut deadline = now
            .checked_add(self.state.windows.finalization())
            .ok_or(BudgetError::DeadlineOverflow)?;
        if let Some(run_deadline) = self.state.whole_run_deadline {
            deadline = deadline.min(run_deadline);
        }
        if deadline <= now {
            return Err(BudgetError::Expired);
        }
        let mut finalization = lock(&self.state.finalization_deadline);
        if let Some(existing) = *finalization {
            deadline = existing;
        } else {
            *finalization = Some(deadline);
        }
        Ok(ResultFinalizationLease {
            budget: self.clone(),
            deadline,
        })
    }

    /// Returns the shared finalization cap, if finalization has started.
    #[must_use]
    pub fn finalization_deadline(&self) -> Option<crate::MonotonicInstant> {
        *lock(&self.state.finalization_deadline)
    }

    /// Returns shared retry attempts remaining without resetting them.
    #[must_use]
    pub fn attempts_remaining(&self) -> u32 {
        self.state.attempts_remaining()
    }
}

/// A view proving that one shared finalization cap has been established.
#[derive(Clone, Debug)]
pub struct ResultFinalizationLease {
    budget: ResultDeliveryBudget,
    deadline: crate::MonotonicInstant,
}

impl ResultFinalizationLease {
    /// Returns the one shared absolute finalization deadline.
    #[must_use]
    pub const fn deadline(&self) -> crate::MonotonicInstant {
        self.deadline
    }

    /// Starts a sink operation narrowed by the shared finalization cap.
    pub fn operation(
        &self,
        kind: ResultOperationKind,
    ) -> Result<ResultOperationLease, BudgetError> {
        self.budget
            .begin_operation_in_scope(self.budget.state.scope, kind, true)
    }

    /// Starts one cleanup operation narrowed to the selected sink and shared
    /// finalization cap. Cancellation does not invalidate this lease.
    pub fn sink_operation(
        &self,
        sink: QualifiedSinkId,
        kind: ResultOperationKind,
    ) -> Result<ResultOperationLease, BudgetError> {
        let scope = self
            .budget
            .state
            .scope
            .for_sink(sink)
            .ok_or(BudgetError::ScopeMismatch)?;
        self.budget.begin_operation_in_scope(scope, kind, true)
    }
}

/// A no-op registrar used only by the legacy constructor. Any pending sink
/// must use the explicit application registrar constructor instead.
#[derive(Debug, Default)]
pub struct UnavailableResultWaitRegistrar;

impl ResultWaitRegistrar for UnavailableResultWaitRegistrar {
    fn register(
        &self,
        _spec: ResultWaitSpec,
    ) -> Result<Box<dyn ResultWaitRegistrationHandle>, ResultWaitError> {
        Err(ResultWaitError::Unavailable)
    }
}

impl ResultWaitRegistrationHandle for crate::progress::WaitRegistration {
    fn retire(&mut self) -> Result<(), ResultWaitError> {
        crate::progress::WaitRegistration::retire(self).map_err(|error| match error {
            crate::progress::WaitRegistryError::AlreadyRetired { .. } => {
                ResultWaitError::AlreadyRetired
            }
            crate::progress::WaitRegistryError::Shutdown => ResultWaitError::Shutdown,
            _ => ResultWaitError::Rejected,
        })
    }
}

impl ResultWaitRegistrar for crate::progress::WaitRegistry {
    fn register(
        &self,
        spec: ResultWaitSpec,
    ) -> Result<Box<dyn ResultWaitRegistrationHandle>, ResultWaitError> {
        let identity = crate::progress::OpaqueWaitIdentity::from_u64(spec.operation.get());
        let wait_spec =
            crate::progress::WaitRegistrationSpec::new(spec.owner, identity, spec.deadline)
                .with_waker(&spec.waker)
                .map_err(|_| ResultWaitError::Rejected)?;
        self.register(wait_spec)
            .map(|registration| Box::new(registration) as Box<dyn ResultWaitRegistrationHandle>)
            .map_err(|error| match error {
                crate::progress::WaitRegistryError::Shutdown => ResultWaitError::Shutdown,
                _ => ResultWaitError::Rejected,
            })
    }
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
    /// Optional bounded acknowledgement/durability token digest.
    pub acknowledgement_digest: Option<Digest32>,
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
    /// A retry would exceed the sink's finite waiting queue.
    RetryQueueFull,
    /// A retry or acknowledgement did not have an active processing lease.
    LeaseMissing,
    /// Finalization would exceed a sink's explicit finite operation bound.
    FinalizationLimit,
    /// Diagnosed drop was attempted without explicit non-compatibility policy.
    DiagnosedDropNotAllowed,
    /// The bounded transition ledger exhausted its configured capacity.
    TransitionLimit,
    /// A bounded queue/accounting counter could not be represented without
    /// silently wrapping or clamping its value.
    ArithmeticOverflow {
        /// Stable counter name used in diagnostics.
        field: &'static str,
    },
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
            Self::RetryQueueFull => formatter.write_str("result.ledger.retry-queue-full"),
            Self::LeaseMissing => formatter.write_str("result.ledger.lease-missing"),
            Self::FinalizationLimit => formatter.write_str("result.ledger.finalization-limit"),
            Self::DiagnosedDropNotAllowed => {
                formatter.write_str("result.ledger.diagnosed-drop-not-allowed")
            }
            Self::TransitionLimit => formatter.write_str("result.ledger.transition-limit"),
            Self::ArithmeticOverflow { field } => {
                write!(formatter, "result.ledger.arithmetic-overflow.{field}")
            }
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
            Some(ack.idempotency_key()),
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
            None,
            diagnostic,
        )
    }

    /// Converts a retryable failure into a terminal failure during bounded
    /// cancellation/finalization.  A retryable failure remains incomplete
    /// until the caller either requeues it or explicitly closes it.
    pub fn terminalize_retryable(
        &mut self,
        key: DeliveryKey,
        reason: FailureReason,
    ) -> Result<(), LedgerError> {
        if matches!(&reason, FailureReason::Retryable(_)) {
            return Err(LedgerError::InvalidTransition {
                state: self.state(key)?,
                operation: "terminalize-retryable",
            });
        }
        let state = self.state(key)?;
        if !matches!(
            &state,
            LedgerState::Disposition(LedgerDisposition::Failed(FailureReason::Retryable(_)))
        ) {
            return Err(LedgerError::InvalidTransition {
                state,
                operation: "terminalize-retryable",
            });
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
        // Preflight fallible conditions before consuming the shared budget.
        // A failed retry must not spend an attempt while leaving no matching
        // queue item for the ledger state.
        if self.transitions.len() >= MAX_LEDGER_TRANSITIONS {
            return Err(LedgerError::TransitionLimit);
        }
        let next = self
            .entry(key)?
            .attempts
            .get()
            .checked_add(1)
            .ok_or(LedgerError::RetryBudgetExhausted)?;
        if !budget.consume() {
            return Err(LedgerError::RetryBudgetExhausted);
        }
        self.transition(
            key,
            LedgerState::Disposition(LedgerDisposition::Queued),
            budget.remaining(),
            None,
            None,
            None,
        )?;
        self.entry_mut(key)?.attempts = AttemptOrdinal::new(next)?;
        Ok(())
    }

    /// Requeues one retryable delivery using an attempt already charged by
    /// the run-owned `ResultDeliveryBudget`. This keeps the pure ledger's
    /// legacy retry counter available to old callers while the typed
    /// production adapter uses one shared authority for all sink attempts.
    pub fn retry_with_remaining(
        &mut self,
        key: DeliveryKey,
        remaining_budget: u32,
    ) -> Result<AttemptOrdinal, LedgerError> {
        let state = self.state(key)?;
        if !matches!(
            &state,
            LedgerState::Disposition(LedgerDisposition::Failed(FailureReason::Retryable(_)))
        ) {
            if matches!(
                &state,
                LedgerState::Disposition(LedgerDisposition::Failed(FailureReason::UnknownOutcome(
                    _
                )))
            ) {
                return Err(LedgerError::RetryAfterUnknownOutcome);
            }
            return Err(LedgerError::InvalidTransition {
                state,
                operation: "retry-with-remaining",
            });
        }
        if self.transitions.len() >= MAX_LEDGER_TRANSITIONS {
            return Err(LedgerError::TransitionLimit);
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
            remaining_budget,
            None,
            None,
            None,
        )?;
        let attempt = AttemptOrdinal::new(next)?;
        self.entry_mut(key)?.attempts = attempt;
        Ok(attempt)
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
                    if matches!(
                        &entry.state,
                        LedgerState::Disposition(LedgerDisposition::Failed(
                            FailureReason::Retryable(_)
                        ))
                    ) {
                        if entry.admitted {
                            summary.admitted += 1;
                            summary.accepted += 1;
                            summary.incomplete += 1;
                        } else {
                            summary.not_admitted += 1;
                        }
                    } else if entry.admitted {
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
        acknowledgement_digest: Option<Digest32>,
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
        self.record(
            key,
            to,
            bytes,
            remaining_budget,
            boundary,
            acknowledgement_digest,
            diagnostic,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the transition record keeps each bounded audit field explicit"
    )]
    fn record(
        &mut self,
        key: DeliveryKey,
        to: LedgerState,
        bytes: usize,
        remaining_budget: u32,
        boundary: Option<DurabilityBoundary>,
        acknowledgement_digest: Option<Digest32>,
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
            acknowledgement_digest,
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
        ) | (
            LedgerState::Disposition(LedgerDisposition::Failed(FailureReason::Retryable(_))),
            LedgerState::Disposition(LedgerDisposition::Failed(_)),
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
                .is_none_or(|first| event_id_in_run_order(key.event_id, first))
            {
                report.first_event_id = Some(key.event_id);
            }
            if report
                .last_event_id
                .is_none_or(|last| event_id_in_run_order(last, key.event_id))
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
                    if matches!(
                        &entry.state,
                        LedgerState::Disposition(LedgerDisposition::Failed(
                            FailureReason::Retryable(_)
                        ))
                    ) {
                        if entry.admitted {
                            report.admitted += 1;
                            report.incomplete.push(IncompleteDelivery {
                                key: *key,
                                disposition: entry.state.clone(),
                            });
                        } else {
                            report.not_admitted += 1;
                        }
                    } else if entry.admitted {
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

/// Explicit identity inputs required to bind one runtime worker to a typed
/// result router.  None of these values are inferred from labels, raw
/// document-local node numbers, or a legacy run string.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TypedRouterIdentity {
    plan_domain: PlanDomain,
    run: TypedRunId,
    run_generation: RunGeneration,
    worker: WorkerId,
    worker_generation: WorkerGeneration,
}

impl TypedRouterIdentity {
    /// Creates a complete run/worker identity binding.
    #[must_use]
    pub const fn new(
        plan_domain: PlanDomain,
        run: TypedRunId,
        run_generation: RunGeneration,
        worker: WorkerId,
        worker_generation: WorkerGeneration,
    ) -> Self {
        Self {
            plan_domain,
            run,
            run_generation,
            worker,
            worker_generation,
        }
    }

    /// Returns the executable-plan domain.
    #[must_use]
    pub const fn plan_domain(self) -> PlanDomain {
        self.plan_domain
    }

    /// Returns the typed run identity.
    #[must_use]
    pub const fn run(self) -> TypedRunId {
        self.run
    }

    /// Returns the run generation.
    #[must_use]
    pub const fn run_generation(self) -> RunGeneration {
        self.run_generation
    }

    /// Returns the worker identity.
    #[must_use]
    pub const fn worker(self) -> WorkerId {
        self.worker
    }

    /// Returns the worker generation.
    #[must_use]
    pub const fn worker_generation(self) -> WorkerGeneration {
        self.worker_generation
    }

    /// Qualifies one document-local node in this immutable plan domain.
    pub fn node(self, node: NodeId) -> Result<PlanNodeRef, IdentityError> {
        PlanNodeRef::new(self.plan_domain, node)
    }

    /// Qualifies an ordered document-local path without changing its order.
    pub fn path(self, path: &[NodeId]) -> Result<Vec<PlanNodeRef>, IdentityError> {
        if path.is_empty() {
            return Err(IdentityError::Empty { field: "plan-path" });
        }
        if path.len() > MAX_TYPED_PLAN_PATH {
            return Err(IdentityError::TooLong {
                field: "plan-path",
                max: MAX_TYPED_PLAN_PATH,
            });
        }
        path.iter().copied().map(|node| self.node(node)).collect()
    }
}

/// Explicit admission outcomes for the revision 4 pure router.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TypedAdmissionOutcome {
    /// The sample was explicitly marked ignored by the sampler result.  It
    /// never enters the ledger or a sink queue and does not advance sequence.
    Ignored,
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

#[derive(Clone, Copy)]
struct PendingAdmission {
    event_id: EventId,
    sink_id: QualifiedSinkId,
    bytes: usize,
    attempts: u32,
}

/// A deterministic executor-neutral model of the revision 4 router.  Effectful
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
    /// A full/backpressure admission remains bound to its original EventId
    /// until it either commits or the run is cancelled.  This prevents a
    /// caller from retrying the same sequence with a different payload.
    pending_admissions: BTreeMap<TypedRunSequence, PendingAdmission>,
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
    /// A typed sink returned a category-preserving effectful error.
    Sink(TypedSinkError),
    /// A sink future could not obtain or retire its exact wait registration.
    Wait(ResultWaitError),
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
    /// Admission could not reserve every selected sink without dropping the
    /// original immutable event.
    Admission(TypedAdmissionOutcome),
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
            Self::Sink(error) => error.fmt(formatter),
            Self::Wait(error) => error.fmt(formatter),
            Self::Ledger(error) => error.fmt(formatter),
            Self::InvalidConfiguration(detail) => {
                write!(formatter, "result.router.configuration: {detail}")
            }
            Self::InvalidState { phase, operation } => {
                write!(formatter, "result.router.state.{operation}: {phase:?}")
            }
            Self::Admission(outcome) => {
                write!(formatter, "result.router.admission: {outcome:?}")
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
        if plans
            .iter()
            .any(|plan| plan.limits.max_items > MAX_TYPED_QUEUE_ITEMS)
        {
            return Err(TypedRouterError::InvalidConfiguration(
                BoundedDiagnostic::new("sink queue item limit exceeds ledger bound"),
            ));
        }
        if plans
            .iter()
            .any(|plan| plan.limits.max_finalization_steps > MAX_LEDGER_TRANSITIONS)
        {
            return Err(TypedRouterError::InvalidConfiguration(
                BoundedDiagnostic::new("sink finalization limit exceeds ledger bound"),
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
            pending_admissions: BTreeMap::new(),
            ledger: DeliveryLedger::new(),
        })
    }

    /// Returns phase.
    #[must_use]
    pub const fn phase(&self) -> TypedRouterPhase {
        self.phase
    }

    /// Returns the run identity bound at construction.
    #[must_use]
    pub const fn run_id(&self) -> TypedRunId {
        self.run_id
    }

    /// Returns the run generation bound at construction.
    #[must_use]
    pub const fn run_generation(&self) -> RunGeneration {
        self.run_generation
    }

    /// Returns the next sequence that a caller must bind into an envelope.
    pub fn next_sequence(&self) -> Result<TypedRunSequence, TypedRouterError> {
        TypedRunSequence::new(self.next_sequence).map_err(TypedRouterError::Identity)
    }

    /// Returns all configured sink identities in stable admission order.
    #[must_use]
    pub fn sink_ids(&self) -> Vec<QualifiedSinkId> {
        self.sinks.iter().map(|sink| sink.plan.id).collect()
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

    fn ensure_ledger_capacity(&self, sink_steps: usize) -> Result<(), TypedRouterError> {
        let required = self
            .sinks
            .len()
            .checked_mul(sink_steps)
            .ok_or(TypedRouterError::Ledger(LedgerError::TransitionLimit))?;
        let available = self
            .ledger
            .transitions
            .len()
            .checked_add(required)
            .ok_or(TypedRouterError::Ledger(LedgerError::TransitionLimit))?;
        if available > MAX_LEDGER_TRANSITIONS {
            return Err(TypedRouterError::Ledger(LedgerError::TransitionLimit));
        }
        Ok(())
    }

    fn record_not_admitted(
        &mut self,
        event_id: EventId,
        bytes: usize,
        reason: NotAdmittedReason,
    ) -> Result<(), TypedRouterError> {
        let next_sequence = self.next_sequence.checked_add(1).ok_or_else(|| {
            TypedRouterError::InvalidConfiguration(BoundedDiagnostic::new("run sequence exhausted"))
        })?;
        self.ensure_ledger_capacity(2)?;
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
        for key in keys {
            self.ledger.not_admitted(key, reason.clone())?;
        }
        self.pending_admissions.remove(&event_id.sequence());
        self.next_sequence = next_sequence;
        Ok(())
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
        if let Some(pending) = self.pending_admissions.get(&envelope.event_id().sequence()) {
            if pending.event_id != event_id || pending.bytes != bytes {
                return Err(TypedRouterError::InvalidConfiguration(
                    BoundedDiagnostic::new("backpressure retry identity collision"),
                ));
            }
            // A pending admission may only be committed through
            // `retry_admission`, which is the sole path that consumes the
            // bounded backpressure budget.  Calling `admit` again cannot
            // bypass that budget even if the queue has since drained.
            return Ok(TypedAdmissionOutcome::Full {
                sink_id: pending.sink_id,
                event_id,
                bytes,
            });
        }
        if envelope.event().result().is_ignored() {
            return Ok(TypedAdmissionOutcome::Ignored);
        }
        if let Some(sink) = self.sinks.iter().find(|sink| sink.failed.is_some()) {
            let error = sink
                .failed
                .clone()
                .unwrap_or_else(|| BoundedDiagnostic::new("sink failed"));
            let sink_id = sink.plan.id;
            self.record_not_admitted(
                event_id,
                bytes,
                NotAdmittedReason::FailedBeforeAdmission(error.clone()),
            )?;
            return Ok(TypedAdmissionOutcome::Failed {
                sink_id: Some(sink_id),
                error,
            });
        }
        let mut full_index = None;
        for (index, sink) in self.sinks.iter().enumerate() {
            let queued_bytes =
                sink.queued_bytes
                    .checked_add(bytes)
                    .ok_or(TypedRouterError::Ledger(LedgerError::ArithmeticOverflow {
                        field: "queued-bytes",
                    }))?;
            if sink.queue.len() >= sink.plan.limits.max_items
                || queued_bytes > sink.plan.limits.max_bytes
            {
                full_index = Some(index);
                break;
            }
        }
        if let Some(full_index) = full_index {
            let full_id = self.sinks[full_index].plan.id;
            let full_policy = self.sinks[full_index].plan.full_policy.clone();
            if matches!(full_policy, FullPolicy::Backpressure { .. }) {
                let deadline_exhausted = matches!(
                    &full_policy,
                    FullPolicy::Backpressure { deadline } if deadline.remaining() == 0
                );
                if deadline_exhausted || self.shared_budget.remaining() == 0 {
                    self.record_not_admitted(
                        event_id,
                        bytes,
                        NotAdmittedReason::FailedBeforeAdmission(BoundedDiagnostic::new(
                            "backpressure budget exhausted",
                        )),
                    )?;
                    self.phase = TypedRouterPhase::Failed;
                    return Ok(TypedAdmissionOutcome::Failed {
                        sink_id: Some(full_id),
                        error: BoundedDiagnostic::new("shared backpressure budget exhausted"),
                    });
                }
                // A backpressure result remains outside the ledger until the
                // caller successfully reserves it.  This is what permits the
                // same EventId/payload to be retried without manufacturing a
                // second semantic event or violating terminal ledger closure.
                self.pending_admissions
                    .entry(envelope.event_id().sequence())
                    .or_insert(PendingAdmission {
                        event_id,
                        sink_id: full_id,
                        bytes,
                        attempts: 0,
                    });
                return Ok(TypedAdmissionOutcome::Full {
                    sink_id: full_id,
                    event_id,
                    bytes,
                });
            }
            self.record_not_admitted(event_id, bytes, NotAdmittedReason::Full)?;
            let reason = BoundedDiagnostic::new("finite sink queue is full");
            if matches!(full_policy, FullPolicy::FailRun) {
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

        let next_sequence = self.next_sequence.checked_add(1).ok_or_else(|| {
            TypedRouterError::InvalidConfiguration(BoundedDiagnostic::new("run sequence exhausted"))
        })?;
        self.ensure_ledger_capacity(2)?;
        // Check every sink before mutating the ledger so an accounting
        // overflow cannot leave a partially reserved all-sink admission.
        for state in &self.sinks {
            state
                .queued_bytes
                .checked_add(bytes)
                .ok_or(TypedRouterError::Ledger(LedgerError::ArithmeticOverflow {
                    field: "queued-bytes",
                }))?;
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
            state.queued_bytes =
                state
                    .queued_bytes
                    .checked_add(bytes)
                    .ok_or(TypedRouterError::Ledger(LedgerError::ArithmeticOverflow {
                        field: "queued-bytes",
                    }))?;
            state.queue.push_back(TypedQueued {
                envelope: Arc::clone(&envelope),
                bytes,
            });
        }
        self.pending_admissions.remove(&event_id.sequence());
        self.next_sequence = next_sequence;
        Ok(TypedAdmissionOutcome::Accepted { event_id, bytes })
    }

    /// Retries a full admission using the one run-level budget.  The event's
    /// sequence, payload digest, and sink identities remain unchanged.
    pub fn retry_admission(
        &mut self,
        envelope: TypedResultEnvelope,
    ) -> Result<TypedAdmissionOutcome, TypedRouterError> {
        match self.phase {
            TypedRouterPhase::Open => {}
            TypedRouterPhase::Cancelled => return Ok(TypedAdmissionOutcome::Cancelled),
            TypedRouterPhase::New
            | TypedRouterPhase::AdmissionStopped
            | TypedRouterPhase::Draining
            | TypedRouterPhase::Flushed
            | TypedRouterPhase::Finished
            | TypedRouterPhase::Failed => return Ok(TypedAdmissionOutcome::Closed),
        }
        let sequence = envelope.event_id().sequence();
        let pending = self
            .pending_admissions
            .get(&sequence)
            .copied()
            .ok_or_else(|| {
                TypedRouterError::InvalidConfiguration(BoundedDiagnostic::new(
                    "no pending backpressure admission",
                ))
            })?;
        if pending.event_id != envelope.event_id() || pending.bytes != envelope.byte_size() {
            return Err(TypedRouterError::InvalidConfiguration(
                BoundedDiagnostic::new("backpressure retry identity collision"),
            ));
        }
        let index = self.sink_index(pending.sink_id)?;
        let deadline_limit = match &self.sinks[index].plan.full_policy {
            FullPolicy::Backpressure { deadline } => deadline.remaining(),
            FullPolicy::FailRun | FullPolicy::DiagnosedDrop { .. } => 0,
        };
        if pending.attempts >= deadline_limit {
            self.record_not_admitted(
                pending.event_id,
                pending.bytes,
                NotAdmittedReason::FailedBeforeAdmission(BoundedDiagnostic::new(
                    "backpressure deadline exhausted",
                )),
            )?;
            self.phase = TypedRouterPhase::Failed;
            return Ok(TypedAdmissionOutcome::Failed {
                sink_id: Some(pending.sink_id),
                error: BoundedDiagnostic::new("backpressure deadline exhausted"),
            });
        }
        if self.shared_budget.remaining() == 0 {
            self.record_not_admitted(
                pending.event_id,
                pending.bytes,
                NotAdmittedReason::FailedBeforeAdmission(BoundedDiagnostic::new(
                    "shared backpressure budget exhausted",
                )),
            )?;
            self.phase = TypedRouterPhase::Failed;
            return Ok(TypedAdmissionOutcome::Failed {
                sink_id: Some(pending.sink_id),
                error: BoundedDiagnostic::new("shared backpressure budget exhausted"),
            });
        }
        let shared_before = self.shared_budget;
        self.pending_admissions.remove(&sequence);
        if !self.shared_budget.consume() {
            self.pending_admissions.insert(sequence, pending);
            return Err(TypedRouterError::Ledger(LedgerError::RetryBudgetExhausted));
        }
        let outcome = self.admit(envelope);
        if outcome.is_err() {
            self.shared_budget = shared_before;
            self.pending_admissions.insert(sequence, pending);
        } else if matches!(&outcome, Ok(TypedAdmissionOutcome::Full { .. })) {
            let mut next_pending = pending;
            next_pending.attempts =
                next_pending
                    .attempts
                    .checked_add(1)
                    .ok_or(TypedRouterError::Ledger(LedgerError::ArithmeticOverflow {
                        field: "backpressure-attempts",
                    }))?;
            self.pending_admissions.insert(sequence, next_pending);
        }
        outcome
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
            let Some(item) = self.sinks[index].queue.front().cloned() else {
                continue;
            };
            let key = DeliveryKey {
                event_id: item.envelope.event_id(),
                sink_id: self.sinks[index].plan.id,
            };
            let attempt = self
                .ledger
                .processing(key, self.shared_budget.remaining())?;
            let queued_bytes = self.sinks[index]
                .queued_bytes
                .checked_sub(item.bytes)
                .ok_or(TypedRouterError::Ledger(LedgerError::ArithmeticOverflow {
                    field: "queued-bytes-underflow",
                }))?;
            let _ = self.sinks[index].queue.pop_front();
            self.sinks[index].queued_bytes = queued_bytes;
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
                | TypedRouterPhase::Failed
        ) {
            return Err(TypedRouterError::InvalidState {
                phase: self.phase,
                operation: "flush",
            });
        }
        if !self.pending_admissions.is_empty() {
            return Err(TypedRouterError::Ledger(
                LedgerError::ConservationViolation {
                    detail: "flush reached with pending backpressure admissions".to_owned(),
                },
            ));
        }
        if self.ledger.entries.values().any(|entry| {
            matches!(
                &entry.state,
                LedgerState::Selected
                    | LedgerState::Disposition(LedgerDisposition::Queued)
                    | LedgerState::Disposition(LedgerDisposition::Processing)
                    | LedgerState::Disposition(LedgerDisposition::Failed(
                        FailureReason::Retryable(_)
                    ))
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
        let active = self.sinks[index]
            .in_flight
            .get(&key.event_id)
            .ok_or(TypedRouterError::Ledger(LedgerError::LeaseMissing))?;
        if active.attempt != ack.attempt() {
            return Err(TypedRouterError::Ledger(
                LedgerError::AcknowledgementMismatch,
            ));
        }
        self.ledger.durable(ack, self.shared_budget.remaining())?;
        self.sinks[index]
            .in_flight
            .remove(&key.event_id)
            .ok_or(TypedRouterError::Ledger(LedgerError::LeaseMissing))?;
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
        if !self.sinks[index].in_flight.contains_key(&key.event_id) {
            return Err(TypedRouterError::Ledger(LedgerError::LeaseMissing));
        }
        self.ledger.diagnosed_drop(key, reason, true)?;
        self.sinks[index]
            .in_flight
            .remove(&key.event_id)
            .ok_or(TypedRouterError::Ledger(LedgerError::LeaseMissing))?;
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
        if !self.sinks[index].in_flight.contains_key(&key.event_id) {
            return Err(TypedRouterError::Ledger(LedgerError::LeaseMissing));
        }
        if !matches!(&reason, FailureReason::Retryable(_)) {
            let queued = self
                .ledger
                .entries
                .iter()
                .filter(|(pending_key, entry)| {
                    pending_key.sink_id == key.sink_id
                        && matches!(
                            &entry.state,
                            LedgerState::Selected
                                | LedgerState::Disposition(LedgerDisposition::Queued)
                        )
                })
                .count();
            let other_in_flight = self.sinks[index].in_flight.len().checked_sub(1).ok_or(
                TypedRouterError::Ledger(LedgerError::ArithmeticOverflow {
                    field: "in-flight-count-underflow",
                }),
            )?;
            let required = 1usize
                .checked_add(queued)
                .and_then(|count| count.checked_add(other_in_flight))
                .ok_or(TypedRouterError::Ledger(LedgerError::TransitionLimit))?;
            let available = self
                .ledger
                .transitions
                .len()
                .checked_add(required)
                .ok_or(TypedRouterError::Ledger(LedgerError::TransitionLimit))?;
            if available > MAX_LEDGER_TRANSITIONS {
                return Err(TypedRouterError::Ledger(LedgerError::TransitionLimit));
            }
        }
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
            let in_flight = self.sinks[index]
                .in_flight
                .keys()
                .copied()
                .filter(|event_id| *event_id != key.event_id)
                .map(|event_id| DeliveryKey {
                    event_id,
                    sink_id: key.sink_id,
                })
                .collect::<Vec<_>>();
            for in_flight_key in in_flight {
                self.ledger.failed(
                    in_flight_key,
                    FailureReason::UnknownOutcome(diagnostic.clone()),
                )?;
            }
            self.phase = TypedRouterPhase::Failed;
            // The queued entries are now terminal in the ledger.  They may be
            // released from memory, but only after that accounting transition.
            self.sinks[index].in_flight.clear();
            self.sinks[index].queue.clear();
            self.sinks[index].queued_bytes = 0;
        }
        if matches!(&reason, FailureReason::UnknownOutcome(_)) {
            self.phase = TypedRouterPhase::Failed;
        }
        Ok(())
    }

    /// Converts a pending backpressure attempt into explicit non-admission
    /// ledger entries when a run is finalized without another retry.
    fn close_pending_admissions(
        &mut self,
        reason: NotAdmittedReason,
    ) -> Result<(), TypedRouterError> {
        let pending_count = self.pending_admissions.len();
        let required = pending_count
            .checked_mul(
                self.sinks
                    .len()
                    .checked_mul(2)
                    .ok_or(TypedRouterError::Ledger(LedgerError::ArithmeticOverflow {
                        field: "sink-finalization-count",
                    }))?,
            )
            .ok_or(TypedRouterError::Ledger(LedgerError::TransitionLimit))?;
        let available = self
            .ledger
            .transitions
            .len()
            .checked_add(required)
            .ok_or(TypedRouterError::Ledger(LedgerError::TransitionLimit))?;
        if available > MAX_LEDGER_TRANSITIONS {
            return Err(TypedRouterError::Ledger(LedgerError::TransitionLimit));
        }
        let pending = std::mem::take(&mut self.pending_admissions);
        for (_, pending) in pending {
            self.record_not_admitted(pending.event_id, pending.bytes, reason.clone())?;
        }
        Ok(())
    }

    fn ensure_finalization_capacity(&self) -> Result<(), TypedRouterError> {
        let pending_steps = self
            .pending_admissions
            .len()
            .checked_mul(2)
            .ok_or(TypedRouterError::Ledger(LedgerError::FinalizationLimit))?;
        for sink in &self.sinks {
            let queued_steps = self
                .ledger
                .entries
                .iter()
                .filter(|(key, entry)| {
                    key.sink_id == sink.plan.id
                        && matches!(
                            &entry.state,
                            LedgerState::Disposition(LedgerDisposition::Queued)
                                | LedgerState::Disposition(LedgerDisposition::Processing)
                                | LedgerState::Disposition(LedgerDisposition::Failed(
                                    FailureReason::Retryable(_)
                                ))
                        )
                })
                .count();
            let required = pending_steps
                .checked_add(queued_steps)
                .ok_or(TypedRouterError::Ledger(LedgerError::FinalizationLimit))?;
            if required > sink.plan.limits.max_finalization_steps {
                return Err(TypedRouterError::Ledger(LedgerError::FinalizationLimit));
            }
        }
        Ok(())
    }

    /// Requeues a retryable lease with the same event/sink idempotency key.
    pub fn retry(&mut self, key: DeliveryKey) -> Result<(), TypedRouterError> {
        let index = self.sink_index(key.sink_id)?;
        match self.ledger.state(key)? {
            LedgerState::Disposition(LedgerDisposition::Failed(FailureReason::Retryable(_))) => {}
            LedgerState::Disposition(LedgerDisposition::Failed(FailureReason::UnknownOutcome(
                _,
            ))) => {
                return Err(TypedRouterError::Ledger(
                    LedgerError::RetryAfterUnknownOutcome,
                ));
            }
            state => {
                return Err(TypedRouterError::Ledger(LedgerError::InvalidTransition {
                    state,
                    operation: "retry",
                }));
            }
        }
        let in_flight = self.sinks[index]
            .in_flight
            .get(&key.event_id)
            .cloned()
            .ok_or(TypedRouterError::Ledger(LedgerError::LeaseMissing))?;
        let queued_bytes = self.sinks[index]
            .queued_bytes
            .checked_add(in_flight.envelope.byte_size())
            .ok_or(TypedRouterError::Ledger(LedgerError::ArithmeticOverflow {
                field: "queued-bytes",
            }))?;
        if self.sinks[index].queue.len() >= self.sinks[index].plan.limits.max_items
            || queued_bytes > self.sinks[index].plan.limits.max_bytes
        {
            return Err(TypedRouterError::Ledger(LedgerError::RetryQueueFull));
        }
        self.ledger.retry(key, &mut self.shared_budget)?;
        let in_flight = self.sinks[index]
            .in_flight
            .remove(&key.event_id)
            .ok_or(LedgerError::LeaseMissing)?;
        let bytes = in_flight.envelope.byte_size();
        self.sinks[index].queued_bytes =
            self.sinks[index]
                .queued_bytes
                .checked_add(bytes)
                .ok_or(TypedRouterError::Ledger(LedgerError::ArithmeticOverflow {
                    field: "queued-bytes",
                }))?;
        self.sinks[index].queue.push_back(TypedQueued {
            envelope: in_flight.envelope,
            bytes,
        });
        Ok(())
    }

    /// Reuses one semantic process operation after a retryable sink outcome.
    /// The supplied remaining attempt count comes from the shared run-owned
    /// authority; no adapter-local retry budget is reset or consumed here.
    fn retry_for_operation(
        &mut self,
        key: DeliveryKey,
        reason: BoundedDiagnostic,
        remaining_attempts: u32,
    ) -> Result<DeliveryLease, TypedRouterError> {
        let index = self.sink_index(key.sink_id)?;
        let in_flight = self.sinks[index]
            .in_flight
            .get(&key.event_id)
            .cloned()
            .ok_or(TypedRouterError::Ledger(LedgerError::LeaseMissing))?;
        self.ledger.failed(key, FailureReason::Retryable(reason))?;
        let attempt = self.ledger.retry_with_remaining(key, remaining_attempts)?;
        self.ledger.processing(key, remaining_attempts)?;
        self.sinks[index]
            .in_flight
            .get_mut(&key.event_id)
            .ok_or(TypedRouterError::Ledger(LedgerError::LeaseMissing))?
            .attempt = attempt;
        Ok(DeliveryLease {
            key,
            envelope: in_flight.envelope,
            attempt,
            idempotency_key: self.ledger.idempotency_key(key)?,
            durability_boundary: self.sinks[index].plan.durability_boundary,
        })
    }

    /// Cancels and explicitly accounts every queued/processing pair.
    pub fn cancel(&mut self) -> Result<(), TypedRouterError> {
        if self.phase == TypedRouterPhase::Finished {
            return Ok(());
        }
        self.ensure_finalization_capacity()?;
        self.phase = TypedRouterPhase::Cancelled;
        self.close_pending_admissions(NotAdmittedReason::Cancelled)?;
        let keys = self.pending_keys();
        for key in keys {
            let state = self.ledger.state(key)?;
            if matches!(
                &state,
                LedgerState::Selected
                    | LedgerState::Disposition(LedgerDisposition::Queued)
                    | LedgerState::Disposition(LedgerDisposition::Processing)
            ) {
                self.ledger.failed(key, FailureReason::Cancelled)?;
            } else if matches!(
                &state,
                LedgerState::Disposition(LedgerDisposition::Failed(FailureReason::Retryable(_)))
            ) {
                self.ledger
                    .terminalize_retryable(key, FailureReason::Cancelled)?;
            }
        }
        for sink in &mut self.sinks {
            sink.queue.clear();
            sink.queued_bytes = 0;
            sink.in_flight.clear();
        }
        self.pending_admissions.clear();
        Ok(())
    }

    /// Stops admission, accounts pending work, and returns a report ready for
    /// effectful flush/close publication.
    pub fn finish(&mut self) -> Result<FinalizationReport, TypedRouterError> {
        if self.phase == TypedRouterPhase::Finished {
            let report = self
                .ledger
                .finalization_report_for(self.sinks.iter().map(|sink| sink.plan.id));
            report.validate_conservation()?;
            return Ok(report);
        }
        if matches!(self.phase, TypedRouterPhase::New | TypedRouterPhase::Open) {
            self.phase = TypedRouterPhase::AdmissionStopped;
        }
        if self.phase == TypedRouterPhase::Cancelled {
            return Err(TypedRouterError::InvalidState {
                phase: self.phase,
                operation: "finish",
            });
        }
        self.ensure_finalization_capacity()?;
        self.close_pending_admissions(NotAdmittedReason::Closed)?;
        let keys = self.pending_keys();
        for key in keys {
            let state = self.ledger.state(key)?;
            if matches!(
                &state,
                LedgerState::Selected
                    | LedgerState::Disposition(LedgerDisposition::Queued)
                    | LedgerState::Disposition(LedgerDisposition::Processing)
            ) {
                self.ledger.failed(key, FailureReason::Cancelled)?;
            } else if matches!(
                &state,
                LedgerState::Disposition(LedgerDisposition::Failed(FailureReason::Retryable(_)))
            ) {
                self.ledger
                    .terminalize_retryable(key, FailureReason::Cancelled)?;
            }
        }
        for sink in &mut self.sinks {
            sink.queue.clear();
            sink.queued_bytes = 0;
            sink.in_flight.clear();
        }
        self.pending_admissions.clear();
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
                    LedgerState::Selected
                        | LedgerState::Disposition(LedgerDisposition::Queued)
                        | LedgerState::Disposition(LedgerDisposition::Processing)
                        | LedgerState::Disposition(LedgerDisposition::Failed(
                            FailureReason::Retryable(_)
                        ))
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

/// Executor-neutral future returned by one typed sink adapter operation.
pub type TypedSinkFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, TypedSinkError>> + 'a>>;

/// Errors from an effectful typed sink adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TypedSinkError {
    /// The operation may be retried with the same lease/idempotency key.
    Retryable(BoundedDiagnostic),
    /// The adapter cannot establish whether the event was durable. It must
    /// never be retried implicitly.
    UnknownOutcome(BoundedDiagnostic),
    /// The event or lifecycle operation failed permanently.
    Permanent(BoundedDiagnostic),
    /// The operation observed run cancellation.
    Cancelled,
    /// The shared finite operation budget stopped the operation.
    Budget(BudgetError),
}

impl TypedSinkError {
    /// Creates a bounded retryable sink error.
    #[must_use]
    pub fn retryable(value: impl Into<String>) -> Self {
        Self::Retryable(BoundedDiagnostic::new(value))
    }

    /// Creates a bounded unknown-outcome sink error.
    #[must_use]
    pub fn unknown_outcome(value: impl Into<String>) -> Self {
        Self::UnknownOutcome(BoundedDiagnostic::new(value))
    }

    /// Creates a bounded permanent sink error.
    #[must_use]
    pub fn permanent(value: impl Into<String>) -> Self {
        Self::Permanent(BoundedDiagnostic::new(value))
    }

    /// Returns the stable machine-readable category.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Retryable(_) => "runtime.typed-sink.retryable",
            Self::UnknownOutcome(_) => "runtime.typed-sink.unknown-outcome",
            Self::Permanent(_) => "runtime.typed-sink.permanent",
            Self::Cancelled => "runtime.typed-sink.cancelled",
            Self::Budget(_) => "runtime.typed-sink.budget",
        }
    }
}

impl fmt::Display for TypedSinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Retryable(detail) | Self::UnknownOutcome(detail) | Self::Permanent(detail) => {
                write!(formatter, "{}: {detail}", self.code())
            }
            Self::Cancelled => formatter.write_str(self.code()),
            Self::Budget(error) => write!(formatter, "{}: {error}", self.code()),
        }
    }
}

impl std::error::Error for TypedSinkError {}

/// One run-owned, executor-neutral typed result destination.
///
/// A sink receives the original [`TypedResultEnvelope`] through a
/// [`DeliveryLease`]. It must return an acknowledgement made from that lease;
/// the router verifies the event, sink, attempt, payload digest, idempotency
/// key, and durability boundary before terminalizing the ledger entry.
pub trait TypedSinkAdapter: Send + Sync {
    /// Starts the sink before sampling begins.
    fn start<'a>(
        &'a self,
        operation: &'a ResultOperationLease,
        wait_registrar: &'a dyn ResultWaitRegistrar,
    ) -> TypedSinkFuture<'a, ()> {
        let _ = (operation, wait_registrar);
        Box::pin(future::ready(Ok(())))
    }

    /// Processes one leased original event and returns its bound durability
    /// acknowledgement.
    fn process<'a>(
        &'a self,
        lease: &'a DeliveryLease,
        operation: &'a ResultOperationLease,
        wait_registrar: &'a dyn ResultWaitRegistrar,
    ) -> TypedSinkFuture<'a, DurabilityAck>;

    /// Flushes all events already acknowledged by this sink.
    fn flush<'a>(
        &'a self,
        operation: &'a ResultOperationLease,
        wait_registrar: &'a dyn ResultWaitRegistrar,
    ) -> TypedSinkFuture<'a, ()> {
        let _ = (operation, wait_registrar);
        Box::pin(future::ready(Ok(())))
    }

    /// Finishes and closes the sink. Implementations must be idempotent.
    fn finish<'a>(
        &'a self,
        operation: &'a ResultOperationLease,
        wait_registrar: &'a dyn ResultWaitRegistrar,
    ) -> TypedSinkFuture<'a, ()> {
        let _ = (operation, wait_registrar);
        Box::pin(future::ready(Ok(())))
    }

    /// Requests bounded cancellation. This method must not block.
    fn cancel(&self) -> Result<(), TypedSinkError> {
        Ok(())
    }
}

/// A run-owned shared typed router and its effectful sink adapters.
///
/// `TypedResultRouter` is the deterministic ledger/queue model. This adapter
/// is the only production-facing bridge that lets a runtime engine start,
/// admit, lease, acknowledge, drain, flush, and finish those queues. The
/// router is shared across scheduler clones; it is never cloned per user.
#[derive(Clone)]
pub struct TypedResultRouterAdapter {
    router: Arc<Mutex<TypedResultRouter>>,
    identity: TypedRouterIdentity,
    sinks: Arc<BTreeMap<QualifiedSinkId, Arc<dyn TypedSinkAdapter>>>,
    started: Arc<Mutex<BTreeSet<QualifiedSinkId>>>,
    budget: ResultDeliveryBudget,
    wait_registrar: Arc<dyn ResultWaitRegistrar>,
}

impl fmt::Debug for TypedResultRouterAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TypedResultRouterAdapter")
            .field("identity", &self.identity)
            .field("phase", &lock(&self.router).phase())
            .field("sink_count", &self.sinks.len())
            .finish()
    }
}

impl TypedResultRouterAdapter {
    /// Creates one shared typed router/sink binding and validates every sink
    /// identity before any adapter is started.
    #[deprecated(
        note = "use new_with_liveness; typed production routing requires an explicit shared authority"
    )]
    pub fn new(
        router: TypedResultRouter,
        identity: TypedRouterIdentity,
        adapters: impl IntoIterator<Item = (QualifiedSinkId, Arc<dyn TypedSinkAdapter>)>,
    ) -> Result<Self, TypedRouterError> {
        let _ = (router, identity, adapters);
        Err(TypedRouterError::InvalidConfiguration(
            BoundedDiagnostic::new(
                "typed sink requires an explicit ResultDeliveryBudget and wait registrar",
            ),
        ))
    }

    /// Creates a typed router binding with the one run-owned liveness
    /// authority and application wait registrar.  No default operation
    /// duration or implicit run deadline is manufactured here.
    pub fn new_with_liveness(
        router: TypedResultRouter,
        identity: TypedRouterIdentity,
        adapters: impl IntoIterator<Item = (QualifiedSinkId, Arc<dyn TypedSinkAdapter>)>,
        budget: ResultDeliveryBudget,
        wait_registrar: Arc<dyn ResultWaitRegistrar>,
    ) -> Result<Self, TypedRouterError> {
        if router.run_id() != identity.run || router.run_generation() != identity.run_generation {
            return Err(TypedRouterError::InvalidConfiguration(
                BoundedDiagnostic::new("typed router identity does not match its run"),
            ));
        }
        let expected = router.sink_ids();
        let budget_scope = budget.scope();
        if budget_scope.run() != identity.run
            || expected
                .iter()
                .copied()
                .any(|sink_id| !budget_scope.contains(sink_id))
        {
            return Err(TypedRouterError::InvalidConfiguration(
                BoundedDiagnostic::new(
                    "result budget scope does not cover the router run and selected sinks",
                ),
            ));
        }
        let mut sinks = BTreeMap::new();
        for (sink_id, adapter) in adapters {
            if expected.binary_search(&sink_id).is_err() || sinks.insert(sink_id, adapter).is_some()
            {
                return Err(TypedRouterError::InvalidConfiguration(
                    BoundedDiagnostic::new("typed sink adapter identity is not unique/configured"),
                ));
            }
        }
        if sinks.len() != expected.len() {
            return Err(TypedRouterError::InvalidConfiguration(
                BoundedDiagnostic::new("typed router is missing a sink adapter"),
            ));
        }
        Ok(Self {
            router: Arc::new(Mutex::new(router)),
            identity,
            sinks: Arc::new(sinks),
            started: Arc::new(Mutex::new(BTreeSet::new())),
            budget,
            wait_registrar,
        })
    }

    /// Returns the shared run-owned liveness authority.
    #[must_use]
    pub fn budget(&self) -> ResultDeliveryBudget {
        self.budget.clone()
    }

    /// Returns the shared wait-registration capability.
    #[must_use]
    pub fn wait_registrar(&self) -> Arc<dyn ResultWaitRegistrar> {
        Arc::clone(&self.wait_registrar)
    }

    /// Returns the explicit plan/run/worker identity binding.
    #[must_use]
    pub const fn identity(&self) -> TypedRouterIdentity {
        self.identity
    }

    /// Returns the shared router phase.
    #[must_use]
    pub fn phase(&self) -> TypedRouterPhase {
        lock(&self.router).phase()
    }

    /// Returns the immutable ledger snapshot under the shared router lock.
    #[must_use]
    pub fn ledger_snapshot(&self) -> DeliveryLedger {
        lock(&self.router).ledger().clone()
    }

    /// Returns the next event sequence to bind to a new envelope.
    pub fn next_sequence(&self) -> Result<TypedRunSequence, TypedRouterError> {
        lock(&self.router).next_sequence()
    }

    /// Qualifies one source node using the explicit plan domain.
    pub fn node(&self, node: NodeId) -> Result<PlanNodeRef, IdentityError> {
        self.identity.node(node)
    }

    /// Qualifies an ordered source path using the explicit plan domain.
    pub fn path(&self, path: &[NodeId]) -> Result<Vec<PlanNodeRef>, IdentityError> {
        self.identity.path(path)
    }

    /// Starts all sink adapters in stable sink identity order. If one start
    /// fails, already-started adapters are synchronously cancelled and the
    /// router is cancelled before the error is returned.
    pub async fn start(&self) -> Result<(), TypedRouterError> {
        {
            let mut router = lock(&self.router);
            router.start()?;
        }
        for (sink_id, adapter) in self.sinks.iter() {
            let operation = match self
                .budget
                .begin_sink_operation(*sink_id, ResultOperationKind::Start)
            {
                Ok(operation) => operation,
                Err(error) => {
                    let mut aggregate = Some(TypedRouterError::Budget(error));
                    for secondary in self.cancel_started_errors() {
                        Self::append_error(&mut aggregate, secondary);
                    }
                    if let Err(secondary) = lock(&self.router).cancel() {
                        Self::append_error(&mut aggregate, secondary);
                    }
                    if let Some(error) = aggregate {
                        return Err(error);
                    }
                    return Ok(());
                }
            };
            if let Err(error) = adapter
                .start(&operation, self.wait_registrar.as_ref())
                .await
            {
                let mut aggregate = Some(Self::sink_error(error));
                for secondary in self.cancel_started_errors() {
                    Self::append_error(&mut aggregate, secondary);
                }
                if let Err(secondary) = lock(&self.router).cancel() {
                    Self::append_error(&mut aggregate, secondary);
                }
                if let Some(error) = aggregate {
                    return Err(error);
                }
                return Ok(());
            }
            lock(&self.started).insert(*sink_id);
        }
        Ok(())
    }

    /// Admits one immutable event transactionally into all selected sinks.
    pub fn admit(
        &self,
        envelope: TypedResultEnvelope,
    ) -> Result<TypedAdmissionOutcome, TypedRouterError> {
        lock(&self.router).admit(envelope)
    }

    /// Retries a previously full admission while preserving its exact event
    /// identity and payload digest.
    pub fn retry_admission(
        &self,
        envelope: TypedResultEnvelope,
    ) -> Result<TypedAdmissionOutcome, TypedRouterError> {
        lock(&self.router).retry_admission(envelope)
    }

    /// Processes every queued lease in deterministic bounded round-robin
    /// order. A sink acknowledgement is accepted only after exact validation.
    /// One process lease is reused for retryable outcomes, so polling and
    /// retries cannot refresh the operation deadline.
    pub async fn deliver(&self) -> Result<(), TypedRouterError> {
        self.deliver_inner(None).await
    }

    /// Drains accepted work under the one shared finalization cap. The
    /// cleanup lease deliberately remains usable after execution cancellation
    /// so accepted events receive a durable acknowledgement or an explicit
    /// terminal error.
    async fn deliver_finalization(
        &self,
        finalization: &ResultFinalizationLease,
    ) -> Result<(), TypedRouterError> {
        self.deliver_inner(Some(finalization)).await
    }

    async fn deliver_inner(
        &self,
        finalization: Option<&ResultFinalizationLease>,
    ) -> Result<(), TypedRouterError> {
        loop {
            let initial_lease = { lock(&self.router).next_delivery()? };
            let Some(mut lease) = initial_lease else {
                return Ok(());
            };
            let sink_id = lease.key().sink_id;
            let adapter = self.sinks.get(&sink_id).ok_or_else(|| {
                TypedRouterError::InvalidConfiguration(BoundedDiagnostic::new(
                    "lease references an unconfigured sink adapter",
                ))
            })?;
            let operation = match finalization {
                Some(finalization) => {
                    finalization.sink_operation(sink_id, ResultOperationKind::Process)
                }
                None => self
                    .budget
                    .begin_sink_operation(sink_id, ResultOperationKind::Process),
            }
            .map_err(TypedRouterError::Budget)?;
            loop {
                if let Err(error) = operation.check() {
                    return Err(self.fail_delivery(
                        lease.key(),
                        TypedRouterError::Budget(error),
                        FailureReason::Cancelled,
                    ));
                }
                let outcome = adapter
                    .process(&lease, &operation, self.wait_registrar.as_ref())
                    .await;
                match outcome {
                    Ok(ack) => {
                        lock(&self.router).acknowledge(ack)?;
                        break;
                    }
                    Err(TypedSinkError::Retryable(reason)) => {
                        let retry_primary =
                            TypedRouterError::Sink(TypedSinkError::Retryable(reason.clone()));
                        // The same operation lease is retained across this
                        // retry. The router only advances the delivery
                        // attempt ordinal and returns the next bound lease.
                        if let Err(error) = operation.check() {
                            return Err(self.fail_delivery(
                                lease.key(),
                                Self::combine_errors(
                                    retry_primary.clone(),
                                    TypedRouterError::Budget(error),
                                ),
                                FailureReason::Cancelled,
                            ));
                        }
                        if let Err(error) = operation.consume_retry() {
                            return Err(self.fail_delivery(
                                lease.key(),
                                Self::combine_errors(
                                    retry_primary.clone(),
                                    TypedRouterError::Budget(error),
                                ),
                                FailureReason::Cancelled,
                            ));
                        }
                        lease = match lock(&self.router).retry_for_operation(
                            lease.key(),
                            reason,
                            operation.attempts_remaining(),
                        ) {
                            Ok(lease) => lease,
                            Err(error) => {
                                return Err(Self::combine_errors(retry_primary, error));
                            }
                        };
                    }
                    Err(error) => {
                        let reason = match &error {
                            TypedSinkError::UnknownOutcome(detail) => {
                                FailureReason::UnknownOutcome(detail.clone())
                            }
                            TypedSinkError::Permanent(detail) => {
                                FailureReason::Permanent(detail.clone())
                            }
                            TypedSinkError::Cancelled => FailureReason::Cancelled,
                            TypedSinkError::Budget(_) => FailureReason::Cancelled,
                            TypedSinkError::Retryable(_) => {
                                return Err(TypedRouterError::Sink(error));
                            }
                        };
                        let primary = Self::sink_error(error);
                        return Err(self.fail_delivery(lease.key(), primary, reason));
                    }
                }
            }
        }
    }

    /// Stops admission, drains accepted work, flushes adapters, and closes
    /// the pure router. Primary and cleanup errors are retained together.
    pub async fn finish(&self) -> Result<FinalizationReport, TypedRouterError> {
        let mut primary = None;
        let finalization = match self.budget.begin_finalization() {
            Ok(finalization) => Some(finalization),
            Err(error) => {
                primary = Some(TypedRouterError::Budget(error));
                None
            }
        };
        if let Err(error) = lock(&self.router).stop_admission() {
            Self::append_error(&mut primary, error);
        }
        if let Some(finalization) = finalization.as_ref()
            && let Err(error) = self.deliver_finalization(finalization).await
        {
            Self::append_error(&mut primary, error);
        }
        if let Some(finalization) = finalization.as_ref() {
            for (sink_id, adapter) in self.sinks.iter() {
                if !lock(&self.started).contains(sink_id) {
                    continue;
                }
                let operation =
                    match finalization.sink_operation(*sink_id, ResultOperationKind::Flush) {
                        Ok(operation) => operation,
                        Err(error) => {
                            Self::append_error(&mut primary, TypedRouterError::Budget(error));
                            continue;
                        }
                    };
                if let Err(error) = adapter
                    .flush(&operation, self.wait_registrar.as_ref())
                    .await
                {
                    Self::append_error(&mut primary, Self::sink_error(error));
                }
            }
        }
        // Every started adapter gets one finish attempt, even after another
        // adapter's flush/finish failed. The pure router is not allowed to
        // enter Finished until this whole owner cleanup phase succeeds.
        if let Some(finalization) = finalization.as_ref() {
            for (sink_id, adapter) in self.sinks.iter() {
                if !lock(&self.started).contains(sink_id) {
                    continue;
                }
                let operation =
                    match finalization.sink_operation(*sink_id, ResultOperationKind::Finish) {
                        Ok(operation) => operation,
                        Err(error) => {
                            Self::append_error(&mut primary, TypedRouterError::Budget(error));
                            continue;
                        }
                    };
                if let Err(error) = adapter
                    .finish(&operation, self.wait_registrar.as_ref())
                    .await
                {
                    Self::append_error(&mut primary, Self::sink_error(error));
                }
            }
        }
        if let Some(error) = primary {
            let mut aggregate = Some(error);
            for secondary in self.cancel_started_errors() {
                Self::append_error(&mut aggregate, secondary);
            }
            if let Err(secondary) = lock(&self.router).cancel() {
                Self::append_error(&mut aggregate, secondary);
            }
            if let Some(error) = aggregate {
                return Err(error);
            }
        }
        match lock(&self.router).finish() {
            Ok(report) => Ok(report),
            Err(error) => Err(error),
        }
    }

    /// Cancels every started adapter and explicitly terminalizes every
    /// accepted/queued delivery. This path is synchronous and bounded so a
    /// dropped engine future cannot silently lose a reservation.
    pub fn cancel(&self) -> Result<(), TypedRouterError> {
        let mut primary = lock(&self.router).cancel().err();
        for error in self.cancel_started_errors() {
            if let Some(existing) = primary.take() {
                primary = Some(TypedRouterError::Combined {
                    primary: Box::new(existing),
                    secondary: Box::new(error),
                });
            } else {
                primary = Some(error);
            }
        }
        match primary {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn cancel_started(&self) -> Option<TypedRouterError> {
        let errors = self.cancel_started_errors();
        let mut aggregate = None;
        for error in errors {
            if let Some(existing) = aggregate.take() {
                aggregate = Some(TypedRouterError::Combined {
                    primary: Box::new(existing),
                    secondary: Box::new(error),
                });
            } else {
                aggregate = Some(error);
            }
        }
        aggregate
    }

    fn cancel_started_errors(&self) -> Vec<TypedRouterError> {
        let started = lock(&self.started).clone();
        started
            .into_iter()
            .filter_map(|_sink_id| {
                self.sinks
                    .get(&_sink_id)
                    .and_then(|adapter| adapter.cancel().err().map(Self::sink_error))
            })
            .collect()
    }

    fn sink_error(error: TypedSinkError) -> TypedRouterError {
        match error {
            TypedSinkError::Budget(error) => TypedRouterError::Budget(error),
            other => TypedRouterError::Sink(other),
        }
    }

    fn combine_errors(primary: TypedRouterError, secondary: TypedRouterError) -> TypedRouterError {
        TypedRouterError::Combined {
            primary: Box::new(primary),
            secondary: Box::new(secondary),
        }
    }

    fn fail_delivery(
        &self,
        key: DeliveryKey,
        primary: TypedRouterError,
        reason: FailureReason,
    ) -> TypedRouterError {
        match lock(&self.router).fail(key, reason) {
            Ok(()) => primary,
            Err(secondary) => Self::combine_errors(primary, secondary),
        }
    }

    fn append_error(target: &mut Option<TypedRouterError>, error: TypedRouterError) {
        if let Some(existing) = target.take() {
            *target = Some(TypedRouterError::Combined {
                primary: Box::new(existing),
                secondary: Box::new(error),
            });
        } else {
            *target = Some(error);
        }
    }
}

/// A cancellation view for the executor-neutral typed sink budget.
impl CancellationSignal for crate::CancellationToken {
    fn is_cancelled(&self) -> bool {
        self.is_cancelled()
    }

    fn register_waker(&self, waker: &Waker) {
        self.register_waker(waker);
    }
}

fn bounded_text(value: impl Into<String>) -> String {
    bounded_text_with_limit(value.into(), MAX_DIAGNOSTIC_BYTES)
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

/// Execution scope at which a listener receives a result.
///
/// JMeter notifies listeners at the end of the owning scope.  Keeping the
/// phase on the immutable event metadata lets a run-level collector preserve
/// setup/main/teardown routing without guessing from a label or plan node.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ListenerPhase {
    /// A result emitted by a setup thread group.
    Setup,
    /// A normal sampler or transaction result.
    #[default]
    Main,
    /// A result emitted by a teardown thread group.
    Teardown,
}

/// Result-success selection used by the JMeter ResultCollector flags.
///
/// `ErrorsOnly` and `SuccessesOnly` are separate flags in JMeter.  The
/// combination is intentionally represented as `Both` and rejected during
/// router configuration until the pinned oracle establishes the exact
/// four-row truth table for that combination.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ListenerFilterMode {
    /// Deliver every non-ignored root sample.
    #[default]
    All,
    /// Deliver only samples whose root result is unsuccessful.
    ErrorsOnly,
    /// Deliver only samples whose root result is successful.
    SuccessesOnly,
    /// Both source flags were set; this is not silently interpreted.
    Both,
}

/// The event shape exposed to a listener route.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ListenerSampleSelection {
    /// Preserve the complete root event, including its nested sub-results.
    #[default]
    CompleteEvent,
    /// UI-only child-sample projection, which is not an independent
    /// notification in the pure run-level router.
    ChildSamplesOnly,
}

/// Pure listener selection policy attached to one sink specification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListenerRoutePolicy {
    enabled: bool,
    order: Option<u64>,
    phase: Option<ListenerPhase>,
    filter: ListenerFilterMode,
    scope_prefix: Option<Arc<[NodeId]>>,
    sample_selection: ListenerSampleSelection,
}

impl Default for ListenerRoutePolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            order: None,
            phase: None,
            filter: ListenerFilterMode::All,
            scope_prefix: None,
            sample_selection: ListenerSampleSelection::CompleteEvent,
        }
    }
}

impl ListenerRoutePolicy {
    /// Creates the default enabled all-results route.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets whether this listener is enabled.  Disabled listeners remain in
    /// the plan for diagnostics and ordering but never start or receive data.
    #[must_use]
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Disables this listener without removing its configured identity.
    #[must_use]
    pub fn disabled(self) -> Self {
        self.enabled(false)
    }

    /// Assigns a stable listener order.  Equal orders retain input order.
    #[must_use]
    pub fn ordered(mut self, order: u64) -> Self {
        self.order = Some(order);
        self
    }

    /// Selects the setup, main, or teardown phase.
    #[must_use]
    pub fn phase(mut self, phase: ListenerPhase) -> Self {
        self.phase = Some(phase);
        self
    }

    /// Selects only unsuccessful root samples.
    #[must_use]
    pub fn errors_only(mut self) -> Self {
        self.filter = ListenerFilterMode::ErrorsOnly;
        self
    }

    /// Selects only successful root samples.
    #[must_use]
    pub fn successes_only(mut self) -> Self {
        self.filter = ListenerFilterMode::SuccessesOnly;
        self
    }

    /// Selects all non-ignored root samples.
    #[must_use]
    pub fn all_results(mut self) -> Self {
        self.filter = ListenerFilterMode::All;
        self
    }

    /// Applies the two source ResultCollector flags with an explicit
    /// unsupported result for the unverified both-enabled combination.
    pub fn with_result_flags(
        mut self,
        error_only: bool,
        success_only: bool,
    ) -> Result<Self, ResultRouterError> {
        self.filter = match (error_only, success_only) {
            (false, false) => ListenerFilterMode::All,
            (true, false) => ListenerFilterMode::ErrorsOnly,
            (false, true) => ListenerFilterMode::SuccessesOnly,
            (true, true) => {
                return Err(ResultRouterError::InvalidConfiguration {
                    detail: "result.filter.unverified: errors-only and successes-only together"
                        .to_owned(),
                });
            }
        };
        Ok(self)
    }

    /// Alias using the JMeter ResultCollector terminology.
    pub fn result_collector_flags(
        self,
        error_logging: bool,
        success_only: bool,
    ) -> Result<Self, ResultRouterError> {
        self.with_result_flags(error_logging, success_only)
    }

    /// Restricts the route to results whose source path starts with the
    /// supplied listener scope path.
    pub fn scoped_to(mut self, path: impl Into<Vec<NodeId>>) -> Result<Self, ResultRouterError> {
        let path = path.into();
        if path.len() > MAX_PLAN_PATH {
            return Err(ResultRouterError::InvalidConfiguration {
                detail: "result listener scope path exceeds runtime bound".to_owned(),
            });
        }
        self.scope_prefix = Some(path.into());
        Ok(self)
    }

    /// Retains the complete root event.  This is the only notification shape
    /// supported by the pure router; serialization decides which sub-result
    /// fields are written.
    #[must_use]
    pub fn complete_event(mut self) -> Self {
        self.sample_selection = ListenerSampleSelection::CompleteEvent;
        self
    }

    /// Rejects the UI-only child-sample projection explicitly.  Child
    /// samples remain inside the root envelope and are never silently
    /// flattened into independent listener events.
    pub fn child_samples_only(self) -> Result<Self, ResultRouterError> {
        Err(ResultRouterError::InvalidConfiguration {
            detail: "result.listener.child-samples-only-unsupported".to_owned(),
        })
    }

    /// JMeter's label-regex controls belong to individual visualizers, not
    /// the run-level ResultCollector.  Refuse them rather than accepting a
    /// UI-only option and silently dropping data.
    pub fn label_regex(self, _pattern: impl AsRef<str>) -> Result<Self, ResultRouterError> {
        Err(ResultRouterError::InvalidConfiguration {
            detail: "result.listener.label-regex-unsupported".to_owned(),
        })
    }

    /// There is no generic listener thread predicate in the pinned JMeter
    /// listener contract; reject one as an explicit capability error.
    pub fn thread_predicate(self, _predicate: impl AsRef<str>) -> Result<Self, ResultRouterError> {
        Err(ResultRouterError::InvalidConfiguration {
            detail: "result.listener.thread-predicate-unsupported".to_owned(),
        })
    }

    /// Returns whether this listener is enabled.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the configured stable order, if any.
    #[must_use]
    pub const fn order(&self) -> Option<u64> {
        self.order
    }

    /// Returns this policy's event-shape selection.
    #[must_use]
    pub const fn sample_selection(&self) -> ListenerSampleSelection {
        self.sample_selection
    }

    fn validate(&self) -> Result<(), ResultRouterError> {
        if self.filter == ListenerFilterMode::Both {
            return Err(ResultRouterError::InvalidConfiguration {
                detail: "result.filter.unverified: both result flags".to_owned(),
            });
        }
        if self.sample_selection == ListenerSampleSelection::ChildSamplesOnly {
            return Err(ResultRouterError::InvalidConfiguration {
                detail: "result.listener.child-samples-only-unsupported".to_owned(),
            });
        }
        if self
            .scope_prefix
            .as_ref()
            .is_some_and(|path| path.len() > MAX_PLAN_PATH)
        {
            return Err(ResultRouterError::InvalidConfiguration {
                detail: "result listener scope path exceeds runtime bound".to_owned(),
            });
        }
        Ok(())
    }

    fn matches_metadata(
        &self,
        event: &SampleEvent,
        metadata: &ResultEventMetadata,
    ) -> Result<bool, SinkError> {
        if !self.enabled {
            return Ok(false);
        }
        if self.phase.is_some_and(|phase| phase != metadata.phase) {
            return Ok(false);
        }
        if self
            .scope_prefix
            .as_ref()
            .is_some_and(|prefix| !metadata.plan_path.starts_with(prefix))
        {
            return Ok(false);
        }
        self.matches_result(event.result())
    }

    fn matches_envelope(&self, envelope: &ResultEnvelope) -> Result<bool, SinkError> {
        if !self.enabled {
            return Ok(false);
        }
        if self.phase.is_some_and(|phase| phase != envelope.phase) {
            return Ok(false);
        }
        if self
            .scope_prefix
            .as_ref()
            .is_some_and(|prefix| !envelope.plan_path.starts_with(prefix))
        {
            return Ok(false);
        }
        self.matches_result(envelope.event.result())
    }

    fn matches_result(&self, result: &SampleResult) -> Result<bool, SinkError> {
        match self.sample_selection {
            ListenerSampleSelection::CompleteEvent => {}
            ListenerSampleSelection::ChildSamplesOnly => {
                return Err(SinkError::unsupported(
                    "result.listener.child-samples-only-unsupported",
                ));
            }
        }
        let successful = result.is_successful();
        match self.filter {
            ListenerFilterMode::All => Ok(true),
            ListenerFilterMode::ErrorsOnly => Ok(!successful),
            ListenerFilterMode::SuccessesOnly => Ok(successful),
            ListenerFilterMode::Both => Err(SinkError::unsupported(
                "result.filter.unverified: both result flags",
            )),
        }
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
    /// Setup/main/teardown scope at which this event was emitted.
    pub phase: ListenerPhase,
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
            phase: ListenerPhase::Main,
        })
    }

    /// Sets the explicit setup/main/teardown scope for this notification.
    #[must_use]
    pub fn with_phase(mut self, phase: ListenerPhase) -> Self {
        self.phase = phase;
        self
    }

    /// Marks this notification as setup-scope without requiring callers to
    /// construct the phase enum directly.
    #[must_use]
    pub fn setup(self) -> Self {
        self.with_phase(ListenerPhase::Setup)
    }

    /// Marks this notification as main-scope.
    #[must_use]
    pub fn main(self) -> Self {
        self.with_phase(ListenerPhase::Main)
    }

    /// Marks this notification as teardown-scope without requiring callers
    /// to construct the phase enum directly.
    #[must_use]
    pub fn teardown(self) -> Self {
        self.with_phase(ListenerPhase::Teardown)
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
    phase: ListenerPhase,
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
        Self::new_with_phase(
            sequence,
            source_node,
            plan_path,
            run,
            user,
            thread,
            sample,
            origin,
            ListenerPhase::Main,
            event,
        )
    }

    /// Creates an immutable envelope while retaining the listener execution
    /// phase.  The legacy constructor defaults to [`ListenerPhase::Main`].
    #[allow(
        clippy::too_many_arguments,
        reason = "the envelope boundary keeps every compatibility identity explicit"
    )]
    pub fn new_with_phase(
        sequence: RunSequence,
        source_node: NodeId,
        plan_path: Vec<NodeId>,
        run: RunIdentity,
        user: UserIdentity,
        thread: ThreadIdentity,
        sample: SampleIdentity,
        origin: ResultOrigin,
        phase: ListenerPhase,
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
            phase,
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

    /// Returns the setup/main/teardown phase captured at notification time.
    #[must_use]
    pub const fn phase(&self) -> ListenerPhase {
        self.phase
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

fn checked_event_bytes(event: &SampleEvent, plan_path_len: usize) -> Option<usize> {
    let event_bytes = estimate_event_bytes(event);
    if event_bytes == usize::MAX {
        return None;
    }
    event_bytes
        .checked_add(plan_path_len.checked_mul(std::mem::size_of::<NodeId>())?)?
        .checked_add(std::mem::size_of::<ResultEnvelope>())
        .map(|bytes| bytes.max(1))
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
            // One pending backpressure admission may require a bounded
            // select-plus-not-admitted pair in addition to queued work.
            max_finalization_steps: max_items.saturating_add(2),
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
    /// Pure listener scope/filter policy.  The policy never changes the
    /// immutable event; it only controls which configured sink receives it.
    pub route: ListenerRoutePolicy,
}

impl fmt::Debug for ResultSinkSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResultSinkSpec")
            .field("id", &self.id)
            .field("limits", &self.limits)
            .field("route", &self.route)
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
            route: ListenerRoutePolicy::default(),
        }
    }

    /// Replaces the pure listener routing policy.
    #[must_use]
    pub fn with_route(mut self, route: ListenerRoutePolicy) -> Self {
        self.route = route;
        self
    }

    /// Disables this listener while retaining it in the configured plan.
    #[must_use]
    pub fn disabled(self) -> Self {
        let route = self.route.clone().disabled();
        self.with_route(route)
    }

    /// Assigns stable listener ordering; equal orders retain input order.
    #[must_use]
    pub fn ordered(self, order: u64) -> Self {
        let route = self.route.clone().ordered(order);
        self.with_route(route)
    }

    /// Selects only unsuccessful root samples.
    #[must_use]
    pub fn errors_only(self) -> Self {
        let route = self.route.clone().errors_only();
        self.with_route(route)
    }

    /// Selects only successful root samples.
    #[must_use]
    pub fn successes_only(self) -> Self {
        let route = self.route.clone().successes_only();
        self.with_route(route)
    }

    /// Selects all non-ignored root samples.
    #[must_use]
    pub fn all_results(self) -> Self {
        let route = self.route.clone().all_results();
        self.with_route(route)
    }

    /// Restricts this sink to setup results.
    #[must_use]
    pub fn setup_only(self) -> Self {
        let route = self.route.clone().phase(ListenerPhase::Setup);
        self.with_route(route)
    }

    /// Restricts this sink to main results.
    #[must_use]
    pub fn main_only(self) -> Self {
        let route = self.route.clone().phase(ListenerPhase::Main);
        self.with_route(route)
    }

    /// Restricts this sink to teardown results.
    #[must_use]
    pub fn teardown_only(self) -> Self {
        let route = self.route.clone().phase(ListenerPhase::Teardown);
        self.with_route(route)
    }

    /// Applies the source ResultCollector flags and reports the unverified
    /// both-enabled combination instead of guessing its truth table.
    pub fn with_result_flags(
        self,
        error_only: bool,
        success_only: bool,
    ) -> Result<Self, ResultRouterError> {
        let route = self
            .route
            .clone()
            .with_result_flags(error_only, success_only)?;
        Ok(self.with_route(route))
    }

    /// Alias using the JMeter ResultCollector property names.
    pub fn result_collector_flags(
        self,
        error_logging: bool,
        success_only: bool,
    ) -> Result<Self, ResultRouterError> {
        self.with_result_flags(error_logging, success_only)
    }

    /// Restricts this listener to an owning plan scope prefix.
    pub fn scoped_to(self, path: impl Into<Vec<NodeId>>) -> Result<Self, ResultRouterError> {
        let route = self.route.clone().scoped_to(path)?;
        Ok(self.with_route(route))
    }

    /// Rejects the UI-only child-sample projection explicitly.
    pub fn child_samples_only(self) -> Result<Self, ResultRouterError> {
        self.route
            .clone()
            .child_samples_only()
            .map(|route| self.with_route(route))
    }

    /// Rejects visualizer-only label regex filtering explicitly.
    pub fn label_regex(self, pattern: impl AsRef<str>) -> Result<Self, ResultRouterError> {
        self.route
            .clone()
            .label_regex(pattern)
            .map(|route| self.with_route(route))
    }

    /// Rejects a non-source-defined generic thread predicate explicitly.
    pub fn thread_predicate(self, predicate: impl AsRef<str>) -> Result<Self, ResultRouterError> {
        self.route
            .clone()
            .thread_predicate(predicate)
            .map(|route| self.with_route(route))
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
    /// The sample was explicitly marked ignored by the sampler result.  It
    /// never enters a sink queue or advances run/sample accounting.
    Ignored,
    /// The event was admitted to every selected listener queue.  Explicit
    /// listener filters may intentionally make `selected_sinks` smaller than
    /// the configured sink count.
    Accepted {
        /// Sequence assigned exactly once to this event.
        sequence: RunSequence,
        /// Accounted bytes reserved in each queue.
        bytes: usize,
        /// Number of enabled listener queues selected by this event.  A
        /// zero count is an intentional filter result, not a silent drop;
        /// the event still receives a run identity and is visible in stats.
        selected_sinks: usize,
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
    /// Number of non-ignored events assigned a run sequence.
    pub admitted_events: usize,
    /// Number of sink routes rejected by an explicit listener policy.
    pub filtered_routes: usize,
    /// Number of ignored events rejected before identity assignment.
    pub ignored_events: usize,
    /// Number of sink queue items successfully delivered.
    pub delivered_items: usize,
    /// Number of queued sink items terminally released after a diagnosed
    /// sink failure or cancellation.
    pub terminal_drops: usize,
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
    flush_called: bool,
    finish_called: bool,
    cancel_called: bool,
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
    admitted_events: usize,
    filtered_routes: usize,
    ignored_events: usize,
    delivered_items: usize,
    terminal_drops: usize,
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
            spec.route.validate()?;
            if spec.limits.max_items > MAX_TYPED_QUEUE_ITEMS {
                return Err(ResultRouterError::InvalidConfiguration {
                    detail: "result sink item limit exceeds runtime bound".to_owned(),
                });
            }
            if spec.limits.max_finalization_steps > MAX_LEDGER_TRANSITIONS {
                return Err(ResultRouterError::InvalidConfiguration {
                    detail: "result sink finalization limit exceeds runtime bound".to_owned(),
                });
            }
            sinks.push(SinkState {
                spec,
                started: false,
                flush_called: false,
                finish_called: false,
                cancel_called: false,
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
        // Compiler order is authoritative.  Explicit orders are sorted
        // stably; specs without an order retain their original order after
        // all explicitly ordered listeners.
        sinks.sort_by_key(|sink| sink.spec.route.order().unwrap_or(u64::MAX));
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
                    admitted_events: 0,
                    filtered_routes: 0,
                    ignored_events: 0,
                    delivered_items: 0,
                    terminal_drops: 0,
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
                    if !sink.spec.route.is_enabled() {
                        continue;
                    }
                    (sink.spec.id, Arc::clone(&sink.spec.sink))
                };
                match sink.start().await {
                    Ok(()) => {
                        let mut state = lock(&router.inner.state);
                        if state.phase != RouterPhase::New || !state.startup_active {
                            let phase = state.phase;
                            state.sinks[index].cancel_called = true;
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
        if event.result().is_ignored() {
            state.ignored_events = match state.ignored_events.checked_add(1) {
                Some(value) => value,
                None => {
                    return AdmissionOutcome::FailedWithoutSink {
                        error: SinkError::resource_limit("result ignored counter exhausted"),
                    };
                }
            };
            return AdmissionOutcome::Ignored;
        }
        let mut selected = Vec::new();
        let mut enabled_sinks = 0usize;
        for (index, sink) in state.sinks.iter().enumerate() {
            if !sink.spec.route.is_enabled() {
                continue;
            }
            enabled_sinks = match enabled_sinks.checked_add(1) {
                Some(value) => value,
                None => {
                    return AdmissionOutcome::FailedWithoutSink {
                        error: SinkError::resource_limit("result listener counter exhausted"),
                    };
                }
            };
            let matches = match sink.spec.route.matches_metadata(&event, &metadata) {
                Ok(matches) => matches,
                Err(error) => {
                    return AdmissionOutcome::FailedWithoutSink { error };
                }
            };
            if !matches {
                continue;
            }
            if let Some(error) = sink.failed.clone() {
                return AdmissionOutcome::Failed {
                    sink_id: sink.spec.id,
                    error,
                };
            }
            selected.push(index);
        }
        let bytes = match checked_event_bytes(&event, metadata.plan_path.len()) {
            Some(bytes) => bytes,
            None => {
                return AdmissionOutcome::FailedWithoutSink {
                    error: SinkError::resource_limit("result byte accounting overflow"),
                };
            }
        };
        let filtered_routes = enabled_sinks.saturating_sub(selected.len());
        let admitted_events = match state.admitted_events.checked_add(1) {
            Some(value) => value,
            None => {
                return AdmissionOutcome::FailedWithoutSink {
                    error: SinkError::resource_limit("result admission counter exhausted"),
                };
            }
        };
        let filtered_total = match state.filtered_routes.checked_add(filtered_routes) {
            Some(value) => value,
            None => {
                return AdmissionOutcome::FailedWithoutSink {
                    error: SinkError::resource_limit("result filter counter exhausted"),
                };
            }
        };
        for &index in &selected {
            let sink = &state.sinks[index];
            let queued_bytes = match sink.queued_bytes.checked_add(bytes) {
                Some(queued_bytes) => queued_bytes,
                None => {
                    return AdmissionOutcome::FailedWithoutSink {
                        error: SinkError::resource_limit("result queue byte accounting overflow"),
                    };
                }
            };
            if sink.queue.len() >= sink.spec.limits.max_items
                || queued_bytes > sink.spec.limits.max_bytes
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
            let next = match metadata.sample.get().checked_add(1) {
                Some(next) => next,
                None => {
                    return AdmissionOutcome::FailedWithoutSink {
                        error: SinkError::resource_limit("sample identity exhausted"),
                    };
                }
            };
            (metadata.sample, state.next_sample.max(next))
        };
        let sequence = RunSequence::new(state.next_sequence);
        metadata.sample = sample;
        let envelope = match ResultEnvelope::new_with_phase(
            sequence,
            metadata.source_node,
            metadata.plan_path,
            self.inner.run.clone(),
            metadata.user,
            event.thread().clone(),
            metadata.sample,
            metadata.origin,
            metadata.phase,
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
        state.admitted_events = admitted_events;
        state.filtered_routes = filtered_total;
        let selected_count = selected.len();
        for index in selected {
            let sink = &mut state.sinks[index];
            sink.queued_bytes = match sink.queued_bytes.checked_add(bytes) {
                Some(value) => value,
                None => {
                    return AdmissionOutcome::FailedWithoutSink {
                        error: SinkError::resource_limit("result queue byte accounting overflow"),
                    };
                }
            };
            sink.queue.push_back(QueuedEnvelope {
                envelope: Arc::clone(&envelope),
                bytes,
            });
        }
        AdmissionOutcome::Accepted {
            sequence,
            bytes,
            selected_sinks: selected_count,
        }
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
        if envelope.event().result().is_ignored() {
            state.ignored_events = match state.ignored_events.checked_add(1) {
                Some(value) => value,
                None => {
                    return AdmissionOutcome::FailedWithoutSink {
                        error: SinkError::resource_limit("result ignored counter exhausted"),
                    };
                }
            };
            return AdmissionOutcome::Ignored;
        }
        let bytes = envelope.byte_size();
        let mut selected = Vec::new();
        let mut enabled_sinks = 0usize;
        for (index, sink) in state.sinks.iter().enumerate() {
            if !sink.spec.route.is_enabled() {
                continue;
            }
            enabled_sinks = match enabled_sinks.checked_add(1) {
                Some(value) => value,
                None => {
                    return AdmissionOutcome::FailedWithoutSink {
                        error: SinkError::resource_limit("result listener counter exhausted"),
                    };
                }
            };
            let matches = match sink.spec.route.matches_envelope(&envelope) {
                Ok(matches) => matches,
                Err(error) => return AdmissionOutcome::FailedWithoutSink { error },
            };
            if !matches {
                continue;
            }
            if let Some(error) = sink.failed.clone() {
                return AdmissionOutcome::Failed {
                    sink_id: sink.spec.id,
                    error,
                };
            }
            selected.push(index);
        }
        for &index in &selected {
            let sink = &state.sinks[index];
            let queued_bytes = match sink.queued_bytes.checked_add(bytes) {
                Some(queued_bytes) => queued_bytes,
                None => {
                    return AdmissionOutcome::FailedWithoutSink {
                        error: SinkError::resource_limit("result queue byte accounting overflow"),
                    };
                }
            };
            if sink.queue.len() >= sink.spec.limits.max_items
                || queued_bytes > sink.spec.limits.max_bytes
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
        let sample_next = match envelope.sample.get().checked_add(1) {
            Some(next) => next,
            None => {
                return AdmissionOutcome::FailedWithoutSink {
                    error: SinkError::resource_limit("sample identity exhausted"),
                };
            }
        };
        let next_sample = state.next_sample.max(sample_next);
        let filtered_routes = enabled_sinks.saturating_sub(selected.len());
        let admitted_events = match state.admitted_events.checked_add(1) {
            Some(value) => value,
            None => {
                return AdmissionOutcome::FailedWithoutSink {
                    error: SinkError::resource_limit("result admission counter exhausted"),
                };
            }
        };
        let filtered_total = match state.filtered_routes.checked_add(filtered_routes) {
            Some(value) => value,
            None => {
                return AdmissionOutcome::FailedWithoutSink {
                    error: SinkError::resource_limit("result filter counter exhausted"),
                };
            }
        };
        state.next_sequence = next_sequence;
        state.next_sample = next_sample;
        state.admitted_events = admitted_events;
        state.filtered_routes = filtered_total;
        let selected_count = selected.len();
        let envelope = Arc::new(envelope);
        for index in selected {
            let sink = &mut state.sinks[index];
            sink.queued_bytes = match sink.queued_bytes.checked_add(bytes) {
                Some(value) => value,
                None => {
                    // The same condition was preflighted above; retaining a
                    // defensive error keeps accounting explicit if this code
                    // is changed to admit concurrently in the future.
                    return AdmissionOutcome::FailedWithoutSink {
                        error: SinkError::resource_limit("result queue byte accounting overflow"),
                    };
                }
            };
            sink.queue.push_back(QueuedEnvelope {
                envelope: Arc::clone(&envelope),
                bytes,
            });
        }
        AdmissionOutcome::Accepted {
            sequence: envelope.sequence(),
            bytes,
            selected_sinks: selected_count,
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
                if state.phase == RouterPhase::Finished {
                    guard.disarm();
                    return Ok(());
                }
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
                let (sink_id, sink, failed, started, flush_called) = {
                    let mut state = lock(&router.inner.state);
                    let item = &state.sinks[index];
                    let should_flush = item.started && !item.flush_called && item.failed.is_none();
                    let sink_id = item.spec.id;
                    let sink = Arc::clone(&item.spec.sink);
                    let failed = item.failed.is_some();
                    let started = item.started;
                    if should_flush {
                        state.sinks[index].flush_called = true;
                    }
                    (sink_id, sink, failed, started, should_flush)
                };
                if failed || !started || !flush_called {
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
            if lock(&router.inner.state).phase == RouterPhase::Finished {
                guard.disarm();
                return Ok(());
            }
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
                let (sink_id, sink, started, finish_called) = {
                    let mut state = lock(&router.inner.state);
                    let item = &state.sinks[index];
                    let sink_id = item.spec.id;
                    let sink = Arc::clone(&item.spec.sink);
                    let started = item.started;
                    let should_finish = started && !item.finish_called;
                    if should_finish {
                        state.sinks[index].finish_called = true;
                    }
                    (sink_id, sink, started, should_finish)
                };
                if !started || !finish_called {
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
            admitted_events: state.admitted_events,
            filtered_routes: state.filtered_routes,
            ignored_events: state.ignored_events,
            delivered_items: state.delivered_items,
            terminal_drops: state.terminal_drops,
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
    // Select the lowest queued run sequence globally before each write.  A
    // sink may have filtered a sequence that another sink retains, so this
    // interleaves notifications by event and then by configured listener
    // order instead of draining one listener's entire queue first.
    loop {
        let next_sequence = {
            let state = lock(&router.inner.state);
            state
                .sinks
                .iter()
                .filter(|sink| sink.spec.route.is_enabled() && sink.failed.is_none())
                .filter_map(|sink| sink.queue.front().map(|item| item.envelope.sequence()))
                .min()
        };
        let Some(next_sequence) = next_sequence else {
            break;
        };
        for index in 0..sink_count {
            let (sink_id, sink, envelope) = {
                let state = lock(&router.inner.state);
                let sink_state = &state.sinks[index];
                let Some(item) = sink_state.queue.front() else {
                    continue;
                };
                if !sink_state.spec.route.is_enabled()
                    || sink_state.failed.is_some()
                    || item.envelope.sequence() != next_sequence
                {
                    continue;
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
                let dropped_items = state.sinks[index].queue.len();
                if let Some(total) = state.terminal_drops.checked_add(dropped_items) {
                    state.terminal_drops = total;
                } else {
                    combine_router_error_slot(
                        &mut failure,
                        ResultRouterError::Sink {
                            sink_id,
                            operation: "write-accounting",
                            source: SinkError::resource_limit(
                                "result terminal-drop counter exhausted",
                            ),
                        },
                    );
                }
                state.sinks[index].queue.clear();
                state.sinks[index].queued_bytes = 0;
                state.phase = RouterPhase::Failed;
                combine_router_error_slot(&mut failure, error);
                continue;
            }
            let mut state = lock(&router.inner.state);
            if let Some(item) = state.sinks[index].queue.pop_front() {
                state.sinks[index].queued_bytes = state.sinks[index]
                    .queued_bytes
                    .checked_sub(item.bytes)
                    .map_or(0, |remaining| remaining);
                if let Some(total) = state.delivered_items.checked_add(1) {
                    state.delivered_items = total;
                } else {
                    state.phase = RouterPhase::Failed;
                    combine_router_error_slot(
                        &mut failure,
                        ResultRouterError::Sink {
                            sink_id: state.sinks[index].spec.id,
                            operation: "write-accounting",
                            source: SinkError::resource_limit(
                                "result delivered-item counter exhausted",
                            ),
                        },
                    );
                    break;
                }
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
            let mut state = lock(&router.inner.state);
            let item = &state.sinks[index];
            let sink_id = item.spec.id;
            let sink = Arc::clone(&item.spec.sink);
            let started = item.started && !item.finish_called;
            if started {
                state.sinks[index].finish_called = true;
            }
            (sink_id, sink, started)
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
    let (sinks, pending_items, pending_bytes, accounting_error) = {
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
        let released_routes = state
            .sinks
            .iter()
            .try_fold(0usize, |total, sink| total.checked_add(sink.queue.len()));
        let accounting_error =
            match released_routes.and_then(|released| state.terminal_drops.checked_add(released)) {
                Some(total) => {
                    state.terminal_drops = total;
                    None
                }
                None => Some(ResultRouterError::InvalidConfiguration {
                    detail: "result terminal-drop counter exhausted".to_owned(),
                }),
            };
        for sink in &mut state.sinks {
            sink.queue.clear();
            sink.queued_bytes = 0;
        }
        let sinks = state
            .sinks
            .iter()
            .filter(|sink| sink.started && !sink.cancel_called)
            .map(|sink| (sink.spec.id, Arc::clone(&sink.spec.sink)))
            .collect::<Vec<_>>();
        for sink in &mut state.sinks {
            if sink.started && !sink.cancel_called {
                sink.cancel_called = true;
            }
        }
        (sinks, pending_items, pending_bytes, accounting_error)
    };
    let mut failure = accounting_error.or_else(|| {
        (pending_items > 0 || pending_bytes > 0).then_some(ResultRouterError::Cancelled {
            pending_items,
            pending_bytes,
        })
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
        subresult_counts: Vec<usize>,
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
                    state
                        .subresult_counts
                        .push(envelope.event().result().sub_results().len());
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

    fn ignored_event(label: &str) -> SampleEvent {
        let mut result = SampleResult::new(label);
        result.set_successful(true);
        result.set_ignore(true);
        SampleEvent::new(
            result,
            "run",
            ThreadIdentity::with_group("thread-1", Some("group".to_owned()), Some(1)),
            "host",
            jmeter_rs_results::VariableSnapshot::new(),
        )
    }

    fn failed_event(label: &str) -> SampleEvent {
        let mut result = SampleResult::new(label);
        result.set_successful(false);
        SampleEvent::new(
            result,
            "run",
            ThreadIdentity::with_group("thread-1", Some("group".to_owned()), Some(1)),
            "host",
            jmeter_rs_results::VariableSnapshot::new(),
        )
    }

    fn event_with_failed_child(label: &str) -> SampleEvent {
        let mut parent = SampleResult::new(label);
        parent.set_successful(true);
        let mut child = SampleResult::new("child");
        child.set_successful(false);
        parent
            .try_add_sub_result_raw(child, ValidationLimits::default())
            .expect("valid child result");
        SampleEvent::new(
            parent,
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
    fn ignored_samples_are_filtered_before_sink_admission_and_accounting() {
        let first = Arc::new(Mutex::new(FakeState::default()));
        let router = router(Arc::clone(&first), None, SinkLimits::new(1, 100_000));
        block_on(router.start()).expect("start");
        assert!(matches!(
            router.admit(
                ignored_event("ignored"),
                metadata(
                    11,
                    ResultOrigin::Sampler {
                        sampler_id: NodeId::new(11),
                        parent: None,
                    },
                ),
            ),
            AdmissionOutcome::Ignored
        ));
        let stats = router.stats();
        assert_eq!(stats.next_sequence, RunSequence::new(1));
        assert_eq!(stats.sinks[0].queued_items, 0);
        block_on(router.finish()).expect("finish");
        assert!(lock(&first).writes.is_empty());
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

    #[test]
    fn result_collector_success_and_error_filters_select_root_samples_per_sink() {
        let successes = Arc::new(Mutex::new(FakeState::default()));
        let errors = Arc::new(Mutex::new(FakeState::default()));
        let router = ResultRouter::new(
            "run",
            [
                ResultSinkSpec::new(
                    SinkId::new(1),
                    SinkLimits::new(4, 100_000),
                    Arc::new(FakeSink::new(Arc::clone(&successes))),
                )
                .successes_only(),
                ResultSinkSpec::new(
                    SinkId::new(2),
                    SinkLimits::new(4, 100_000),
                    Arc::new(FakeSink::new(Arc::clone(&errors))),
                )
                .errors_only(),
            ],
        )
        .expect("router");
        block_on(router.start()).expect("start");
        let sampler = |id| ResultOrigin::Sampler {
            sampler_id: NodeId::new(id),
            parent: None,
        };
        assert!(matches!(
            router.admit(event("ok"), metadata(11, sampler(11))),
            AdmissionOutcome::Accepted {
                selected_sinks: 1,
                ..
            }
        ));
        assert!(matches!(
            router.admit(failed_event("bad"), metadata(12, sampler(12))),
            AdmissionOutcome::Accepted {
                selected_sinks: 1,
                ..
            }
        ));
        assert_eq!(router.stats().filtered_routes, 2);
        block_on(router.finish()).expect("finish");
        assert_eq!(lock(&successes).writes.len(), 1);
        assert_eq!(lock(&successes).writes[0].1, "ok");
        assert_eq!(lock(&errors).writes.len(), 1);
        assert_eq!(lock(&errors).writes[0].1, "bad");
    }

    #[test]
    fn enabled_listener_order_is_interleaved_per_event_sequence() {
        let shared = Arc::new(Mutex::new(FakeState::default()));
        let router = ResultRouter::new(
            "run",
            [
                ResultSinkSpec::new(
                    SinkId::new(1),
                    SinkLimits::new(4, 100_000),
                    Arc::new(FakeSink::new(Arc::clone(&shared))),
                ),
                ResultSinkSpec::new(
                    SinkId::new(2),
                    SinkLimits::new(4, 100_000),
                    Arc::new(FakeSink::new(Arc::clone(&shared))),
                ),
            ],
        )
        .expect("router");
        block_on(router.start()).expect("start");
        assert!(matches!(
            router.admit(
                event("one"),
                metadata(
                    11,
                    ResultOrigin::Sampler {
                        sampler_id: NodeId::new(11),
                        parent: None,
                    },
                ),
            ),
            AdmissionOutcome::Accepted {
                selected_sinks: 2,
                ..
            }
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
            AdmissionOutcome::Accepted {
                selected_sinks: 2,
                ..
            }
        ));
        block_on(router.finish()).expect("finish");
        let shared = lock(&shared);
        let labels = shared
            .writes
            .iter()
            .map(|write| write.1.as_str())
            .collect::<Vec<_>>();
        assert_eq!(labels, vec!["one", "one", "two", "two"]);
    }

    #[test]
    fn root_success_filter_does_not_flatten_or_reclassify_failed_subresults() {
        let state = Arc::new(Mutex::new(FakeState::default()));
        let router = ResultRouter::new(
            "run",
            [ResultSinkSpec::new(
                SinkId::new(1),
                SinkLimits::new(2, 100_000),
                Arc::new(FakeSink::new(Arc::clone(&state))),
            )
            .successes_only()],
        )
        .expect("router");
        block_on(router.start()).expect("start");
        let outcome = router.admit(
            event_with_failed_child("parent"),
            metadata(
                11,
                ResultOrigin::Sampler {
                    sampler_id: NodeId::new(11),
                    parent: None,
                },
            ),
        );
        assert!(
            matches!(
                &outcome,
                AdmissionOutcome::Accepted {
                    selected_sinks: 1,
                    ..
                }
            ),
            "unexpected outcome: {outcome:?}"
        );
        block_on(router.finish()).expect("finish");
        assert_eq!(lock(&state).writes.len(), 1);
        assert_eq!(lock(&state).subresult_counts, vec![1]);
        assert_eq!(router.stats().delivered_items, 1);
    }

    #[test]
    fn listener_phase_scope_and_order_are_explicit_and_disabled_sinks_do_not_start() {
        let setup = Arc::new(Mutex::new(FakeState::default()));
        let teardown = Arc::new(Mutex::new(FakeState::default()));
        let disabled = Arc::new(Mutex::new(FakeState::default()));
        let router = ResultRouter::new(
            "run",
            [
                ResultSinkSpec::new(
                    SinkId::new(2),
                    SinkLimits::new(2, 100_000),
                    Arc::new(FakeSink::new(Arc::clone(&teardown))),
                )
                .ordered(20)
                .teardown_only(),
                ResultSinkSpec::new(
                    SinkId::new(1),
                    SinkLimits::new(2, 100_000),
                    Arc::new(FakeSink::new(Arc::clone(&setup))),
                )
                .ordered(10)
                .setup_only(),
                ResultSinkSpec::new(
                    SinkId::new(3),
                    SinkLimits::new(2, 100_000),
                    Arc::new(FakeSink::new(Arc::clone(&disabled))),
                )
                .ordered(30)
                .disabled(),
            ],
        )
        .expect("router");
        assert_eq!(
            router
                .stats()
                .sinks
                .iter()
                .map(|sink| sink.sink_id)
                .collect::<Vec<_>>(),
            vec![SinkId::new(1), SinkId::new(2), SinkId::new(3)]
        );
        block_on(router.start()).expect("start");
        assert_eq!(lock(&setup).started, 1);
        assert_eq!(lock(&teardown).started, 1);
        assert_eq!(lock(&disabled).started, 0);
        let sampler = ResultOrigin::Sampler {
            sampler_id: NodeId::new(11),
            parent: None,
        };
        assert!(matches!(
            router.admit(
                event("setup"),
                metadata(11, sampler).with_phase(ListenerPhase::Setup),
            ),
            AdmissionOutcome::Accepted {
                selected_sinks: 1,
                ..
            }
        ));
        assert!(matches!(
            router.admit(
                event("teardown"),
                metadata(
                    11,
                    ResultOrigin::Sampler {
                        sampler_id: NodeId::new(11),
                        parent: None,
                    },
                )
                .with_phase(ListenerPhase::Teardown),
            ),
            AdmissionOutcome::Accepted {
                selected_sinks: 1,
                ..
            }
        ));
        block_on(router.finish()).expect("finish");
        assert_eq!(lock(&setup).writes.len(), 1);
        assert_eq!(lock(&teardown).writes.len(), 1);
        assert!(lock(&disabled).writes.is_empty());
    }

    #[test]
    fn unsupported_visualizer_filters_and_both_result_flags_are_explicit_errors() {
        let state = Arc::new(Mutex::new(FakeState::default()));
        let base = ResultSinkSpec::new(
            SinkId::new(1),
            SinkLimits::new(1, 100_000),
            Arc::new(FakeSink::new(state)),
        );
        let both = base.clone().with_result_flags(true, true);
        assert!(matches!(
            both,
            Err(ResultRouterError::InvalidConfiguration { detail })
                if detail.contains("result.filter.unverified")
        ));
        assert!(matches!(
            base.clone().label_regex(".*secret.*"),
            Err(ResultRouterError::InvalidConfiguration { detail })
                if detail == "result.listener.label-regex-unsupported"
        ));
        assert!(matches!(
            base.clone().thread_predicate("thread-1"),
            Err(ResultRouterError::InvalidConfiguration { detail })
                if detail == "result.listener.thread-predicate-unsupported"
        ));
        assert!(matches!(
            base.child_samples_only(),
            Err(ResultRouterError::InvalidConfiguration { detail })
                if detail == "result.listener.child-samples-only-unsupported"
        ));
    }

    #[test]
    fn terminal_finish_and_diagnostics_are_exact_once_and_redacted() {
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
                    },
                ),
            ),
            AdmissionOutcome::Accepted { .. }
        ));
        block_on(router.finish()).expect("finish");
        block_on(router.finish()).expect("idempotent finish");
        let state = lock(&state);
        assert_eq!(state.finished, 1);
        assert_eq!(state.flushed, 1);
        drop(state);

        let error = SinkError::failed("token=topsecret password:other-secret");
        assert_eq!(error.code(), "runtime.result-sink.failed");
        let rendered = error.to_string();
        assert!(!rendered.contains("topsecret"));
        assert!(!rendered.contains("other-secret"));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn oversized_legacy_queue_limits_are_rejected_instead_of_unbounded() {
        let state = Arc::new(Mutex::new(FakeState::default()));
        let result = ResultRouter::new(
            "run",
            [ResultSinkSpec::new(
                SinkId::new(1),
                SinkLimits::new(MAX_TYPED_QUEUE_ITEMS + 1, 100_000),
                Arc::new(FakeSink::new(state)),
            )],
        );
        assert!(matches!(
            result,
            Err(ResultRouterError::InvalidConfiguration { detail })
                if detail == "result sink item limit exceeds runtime bound"
        ));
    }

    #[test]
    fn all_disabled_listeners_are_preserved_without_starting_a_sink() {
        let state = Arc::new(Mutex::new(FakeState::default()));
        let router = ResultRouter::new(
            "run",
            [ResultSinkSpec::new(
                SinkId::new(1),
                SinkLimits::new(1, 100_000),
                Arc::new(FakeSink::new(Arc::clone(&state))),
            )
            .disabled()],
        )
        .expect("disabled listener plan");
        block_on(router.start()).expect("start");
        assert!(matches!(
            router.admit(
                event("disabled"),
                metadata(
                    11,
                    ResultOrigin::Sampler {
                        sampler_id: NodeId::new(11),
                        parent: None,
                    },
                ),
            ),
            AdmissionOutcome::Accepted {
                selected_sinks: 0,
                ..
            }
        ));
        block_on(router.finish()).expect("finish");
        let state = lock(&state);
        assert_eq!(state.started, 0);
        assert!(state.writes.is_empty());
    }
}

#[cfg(test)]
mod revision3_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::task::{Context, Poll};
    use std::time::Duration;

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

    #[derive(Clone)]
    struct LivenessClock {
        current: Arc<Mutex<Result<crate::MonotonicInstant, ResultClockError>>>,
    }

    impl LivenessClock {
        fn at(duration: Duration) -> Self {
            Self {
                current: Arc::new(Mutex::new(Ok(crate::MonotonicInstant::from_duration(
                    duration,
                )))),
            }
        }

        fn set(&self, duration: Duration) {
            *lock(&self.current) = Ok(crate::MonotonicInstant::from_duration(duration));
        }

        fn fail(&self, error: ResultClockError) {
            *lock(&self.current) = Err(error);
        }
    }

    impl ResultMonotonicClock for LivenessClock {
        fn now(&self) -> Result<crate::MonotonicInstant, ResultClockError> {
            lock(&self.current).clone()
        }
    }

    fn liveness_budget(
        clock: &LivenessClock,
        attempts: u32,
        operation: Duration,
        finalization: Duration,
    ) -> ResultDeliveryBudget {
        ResultDeliveryBudget::from_parts(
            ResultOperationScope::sink_set(
                TypedRunId::from_u128(1).expect("run"),
                SinkPlanGeneration::new(1).expect("sink generation"),
            ),
            Arc::new(clock.clone()),
            Arc::new(crate::CancellationToken::new()),
            ResultOperationWindows::uniform(operation, finalization),
            attempts,
            None,
        )
        .expect("liveness budget")
    }

    #[test]
    fn progressing_run_can_outlive_each_operation_window() {
        let clock = LivenessClock::at(Duration::ZERO);
        let budget = liveness_budget(&clock, 8, Duration::from_secs(5), Duration::from_secs(5));
        let first = budget
            .begin_operation(ResultOperationKind::Process)
            .expect("first lease");
        assert_eq!(
            first.deadline(),
            crate::MonotonicInstant::from_duration(Duration::from_secs(5))
        );
        clock.set(Duration::from_secs(4));
        first.check().expect("first lease remains live");
        let second = budget
            .begin_operation(ResultOperationKind::Process)
            .expect("second lease");
        assert_eq!(
            second.deadline(),
            crate::MonotonicInstant::from_duration(Duration::from_secs(9))
        );
        clock.set(Duration::from_secs(8));
        second.check().expect("run keeps progressing");
    }

    #[test]
    fn operation_deadline_is_absolute_and_not_refreshed_by_poll_or_retry() {
        let clock = LivenessClock::at(Duration::ZERO);
        let budget = liveness_budget(&clock, 3, Duration::from_secs(5), Duration::from_secs(10));
        let lease = budget
            .begin_operation(ResultOperationKind::Process)
            .expect("lease");
        let deadline = lease.deadline();
        clock.set(Duration::from_secs(4));
        lease.consume_retry().expect("first attempt");
        assert_eq!(lease.deadline(), deadline);
        clock.set(Duration::from_secs(6));
        assert!(matches!(lease.check(), Err(BudgetError::Expired)));
    }

    #[test]
    fn attempts_are_shared_across_cloned_authority_and_operations() {
        let clock = LivenessClock::at(Duration::ZERO);
        let budget = liveness_budget(&clock, 2, Duration::from_secs(10), Duration::from_secs(10));
        let clone = budget.clone();
        let first = budget
            .begin_operation(ResultOperationKind::Process)
            .expect("first");
        let second = clone
            .begin_operation(ResultOperationKind::Flush)
            .expect("second");
        first.consume_retry().expect("attempt one");
        second.consume_retry().expect("attempt two");
        assert_eq!(budget.attempts_remaining(), 0);
        assert!(matches!(
            second.consume_retry(),
            Err(BudgetError::RetryBudgetExhausted)
        ));
    }

    #[test]
    fn finalization_narrows_later_operation_leases_to_one_shared_cap() {
        let clock = LivenessClock::at(Duration::ZERO);
        let budget = liveness_budget(&clock, 8, Duration::from_secs(30), Duration::from_secs(7));
        let process = budget
            .begin_operation(ResultOperationKind::Process)
            .expect("process");
        let finalization = budget.begin_finalization().expect("finalization");
        let flush = finalization
            .operation(ResultOperationKind::Flush)
            .expect("flush");
        let finish = budget
            .begin_operation(ResultOperationKind::Finish)
            .expect("finish");
        assert_eq!(finalization.deadline(), flush.deadline());
        assert_eq!(flush.deadline(), finish.deadline());
        assert!(process.deadline() > flush.deadline());
        assert_eq!(budget.finalization_deadline(), Some(flush.deadline()));
    }

    #[test]
    fn clock_failures_are_typed_and_never_become_a_large_deadline() {
        let clock = LivenessClock::at(Duration::ZERO);
        clock.fail(ResultClockError::Unavailable);
        assert!(matches!(
            ResultDeliveryBudget::from_parts(
                ResultOperationScope::sink_set(
                    TypedRunId::from_u128(1).expect("run"),
                    SinkPlanGeneration::new(1).expect("sink generation"),
                ),
                Arc::new(clock),
                Arc::new(crate::CancellationToken::new()),
                ResultOperationWindows::uniform(Duration::from_secs(1), Duration::from_secs(1)),
                1,
                None,
            ),
            Err(BudgetError::Clock(ResultClockError::Unavailable))
        ));

        let clock = LivenessClock::at(Duration::from_secs(5));
        let budget = liveness_budget(&clock, 1, Duration::from_secs(5), Duration::from_secs(5));
        clock.set(Duration::from_secs(4));
        assert!(matches!(
            budget.begin_operation(ResultOperationKind::Process),
            Err(BudgetError::Clock(ResultClockError::Reversed { .. }))
        ));
    }

    #[derive(Default)]
    struct WakeCounter(AtomicUsize);

    impl std::task::Wake for WakeCounter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }

    struct CapturedWait {
        operation: ResultOperationId,
        owner: crate::WaitOwnerClass,
        deadline: crate::MonotonicInstant,
    }

    struct CapturingWaitRegistrar {
        captured: Mutex<Option<CapturedWait>>,
    }

    struct RetirableWaitHandle;

    impl ResultWaitRegistrationHandle for RetirableWaitHandle {
        fn retire(&mut self) -> Result<(), ResultWaitError> {
            Ok(())
        }
    }

    impl ResultWaitRegistrar for CapturingWaitRegistrar {
        fn register(
            &self,
            spec: ResultWaitSpec,
        ) -> Result<Box<dyn ResultWaitRegistrationHandle>, ResultWaitError> {
            *lock(&self.captured) = Some(CapturedWait {
                operation: spec.operation,
                owner: spec.owner,
                deadline: spec.deadline,
            });
            Ok(Box::new(RetirableWaitHandle))
        }
    }

    #[test]
    fn lease_owns_provider_identity_and_exact_cancellation_wake() {
        let clock = LivenessClock::at(Duration::ZERO);
        let cancellation = Arc::new(crate::CancellationToken::new());
        let run = TypedRunId::from_u128(7).expect("run");
        let generation = SinkPlanGeneration::new(3).expect("generation");
        let sink = QualifiedSinkId::from_parts(
            run,
            generation,
            PlanNodeRef::from_u64(PlanDomain::from_canonical_plan(b"wait").expect("domain"), 4)
                .expect("node"),
        );
        let budget = ResultDeliveryBudget::from_parts(
            ResultOperationScope::sink_set(run, generation),
            Arc::new(clock),
            Arc::clone(&cancellation) as Arc<dyn CancellationSignal>,
            ResultOperationWindows::uniform(Duration::from_secs(5), Duration::from_secs(5)),
            1,
            None,
        )
        .expect("budget");
        let lease = budget
            .begin_sink_operation(sink, ResultOperationKind::Process)
            .expect("sink lease");
        assert_eq!(lease.scope(), ResultOperationScope::Sink { run, sink });
        let registrar = CapturingWaitRegistrar {
            captured: Mutex::new(None),
        };
        let registration = lease
            .register_wait(
                &registrar,
                crate::WaitOwnerClass::Provider,
                &Waker::from(Arc::new(WakeCounter::default())),
            )
            .expect("wait");
        let captured = lock(&registrar.captured)
            .as_ref()
            .map(|value| (value.operation, value.owner, value.deadline))
            .expect("captured wait");
        assert_eq!(captured.0, lease.id());
        assert_eq!(captured.1, crate::WaitOwnerClass::Provider);
        assert_eq!(captured.2, lease.deadline());
        drop(registration);

        let wake = Arc::new(WakeCounter::default());
        lease.register_waker(&Waker::from(Arc::clone(&wake)));
        cancellation.cancel_immediate();
        assert!(wake.0.load(Ordering::Acquire) > 0);
        assert!(matches!(lease.check(), Err(BudgetError::Cancelled)));
    }

    #[test]
    fn operation_ids_are_shared_and_scope_rejects_foreign_sinks() {
        let clock = LivenessClock::at(Duration::ZERO);
        let run = TypedRunId::from_u128(9).expect("run");
        let foreign_run = TypedRunId::from_u128(10).expect("foreign run");
        let generation = SinkPlanGeneration::new(1).expect("generation");
        let sink = QualifiedSinkId::from_parts(
            run,
            generation,
            PlanNodeRef::from_u64(PlanDomain::from_canonical_plan(b"ids").expect("domain"), 1)
                .expect("node"),
        );
        let other = QualifiedSinkId::from_parts(
            run,
            SinkPlanGeneration::new(2).expect("foreign generation"),
            PlanNodeRef::from_u64(PlanDomain::from_canonical_plan(b"ids").expect("domain"), 2)
                .expect("node"),
        );
        let budget = ResultDeliveryBudget::from_parts(
            ResultOperationScope::sink_set(run, generation),
            Arc::new(clock),
            Arc::new(crate::CancellationToken::new()),
            ResultOperationWindows::uniform(Duration::from_secs(5), Duration::from_secs(5)),
            1,
            None,
        )
        .expect("budget");
        let first = budget
            .begin_sink_operation(sink, ResultOperationKind::Process)
            .expect("first");
        let second = budget
            .begin_sink_operation(sink, ResultOperationKind::Flush)
            .expect("second");
        assert_ne!(first.id(), second.id());
        assert!(matches!(
            budget.begin_sink_operation(other, ResultOperationKind::Process),
            Err(BudgetError::ScopeMismatch)
        ));

        let malformed_scope = ResultOperationScope::Sink {
            run: foreign_run,
            sink,
        };
        assert!(matches!(
            ResultDeliveryBudget::from_parts(
                malformed_scope,
                Arc::new(LivenessClock::at(Duration::ZERO)),
                Arc::new(crate::CancellationToken::new()),
                ResultOperationWindows::uniform(Duration::from_secs(5), Duration::from_secs(5)),
                1,
                None,
            ),
            Err(BudgetError::ScopeMismatch)
        ));
    }

    struct OrderedTypedAdapter {
        trace: Arc<Mutex<Vec<&'static str>>>,
        fail_flush: bool,
        fail_finish: bool,
        fail_cancel: bool,
    }

    impl TypedSinkAdapter for OrderedTypedAdapter {
        fn start<'a>(
            &'a self,
            _operation: &'a ResultOperationLease,
            _wait_registrar: &'a dyn ResultWaitRegistrar,
        ) -> TypedSinkFuture<'a, ()> {
            lock(&self.trace).push("start");
            Box::pin(future::ready(Ok(())))
        }

        fn process<'a>(
            &'a self,
            lease: &'a DeliveryLease,
            _operation: &'a ResultOperationLease,
            _wait_registrar: &'a dyn ResultWaitRegistrar,
        ) -> TypedSinkFuture<'a, DurabilityAck> {
            lock(&self.trace).push("process");
            Box::pin(future::ready(
                lease
                    .acknowledge(lease.durability_boundary())
                    .map_err(|error| TypedSinkError::permanent(error.to_string())),
            ))
        }

        fn flush<'a>(
            &'a self,
            _operation: &'a ResultOperationLease,
            _wait_registrar: &'a dyn ResultWaitRegistrar,
        ) -> TypedSinkFuture<'a, ()> {
            lock(&self.trace).push("flush");
            if self.fail_flush {
                Box::pin(future::ready(Err(TypedSinkError::permanent(
                    "flush failed",
                ))))
            } else {
                Box::pin(future::ready(Ok(())))
            }
        }

        fn finish<'a>(
            &'a self,
            _operation: &'a ResultOperationLease,
            _wait_registrar: &'a dyn ResultWaitRegistrar,
        ) -> TypedSinkFuture<'a, ()> {
            lock(&self.trace).push("finish");
            if self.fail_finish {
                Box::pin(future::ready(Err(TypedSinkError::permanent(
                    "finish failed",
                ))))
            } else {
                Box::pin(future::ready(Ok(())))
            }
        }

        fn cancel(&self) -> Result<(), TypedSinkError> {
            if self.fail_cancel {
                Err(TypedSinkError::unknown_outcome("cancel failed"))
            } else {
                Ok(())
            }
        }
    }

    fn typed_adapter(
        fixture: &Fixture,
        trace: Arc<Mutex<Vec<&'static str>>>,
        fail_finish: bool,
    ) -> TypedResultRouterAdapter {
        typed_adapter_with_options(fixture, trace, false, fail_finish, false, 8).0
    }

    fn typed_adapter_with_options(
        fixture: &Fixture,
        trace: Arc<Mutex<Vec<&'static str>>>,
        fail_flush: bool,
        fail_finish: bool,
        fail_cancel: bool,
        attempts: u32,
    ) -> (TypedResultRouterAdapter, Arc<crate::CancellationToken>) {
        let sink_id = sink(
            fixture,
            3,
            SinkLimits::with_finalization(4, 100_000, 16),
            FullPolicy::FailRun,
        )
        .id;
        let router = TypedResultRouter::new(
            fixture.run,
            fixture.generation,
            RetryBudget::new(8),
            [TypedSinkPlan::with_boundary(
                sink_id,
                SinkLimits::with_finalization(4, 100_000, 16),
                FullPolicy::FailRun,
                DurabilityBoundary::FormatWritten,
            )],
        )
        .expect("router");
        let clock = LivenessClock::at(Duration::ZERO);
        let cancellation = Arc::new(crate::CancellationToken::new());
        let budget = ResultDeliveryBudget::from_parts(
            ResultOperationScope::sink_set(fixture.run, sink_id.sink_plan_generation()),
            Arc::new(clock),
            Arc::clone(&cancellation) as Arc<dyn CancellationSignal>,
            ResultOperationWindows::uniform(Duration::from_secs(10), Duration::from_secs(10)),
            attempts,
            None,
        )
        .expect("liveness budget");
        let domain = fixture.domain;
        let adapter = TypedResultRouterAdapter::new_with_liveness(
            router,
            TypedRouterIdentity::new(
                domain,
                fixture.run,
                fixture.generation,
                fixture.worker,
                fixture.worker_generation,
            ),
            [(
                sink_id,
                Arc::new(OrderedTypedAdapter {
                    trace,
                    fail_flush,
                    fail_finish,
                    fail_cancel,
                }) as Arc<dyn TypedSinkAdapter>,
            )],
            budget,
            Arc::new(crate::WaitRegistry::default()),
        )
        .expect("typed adapter");
        (adapter, cancellation)
    }

    #[test]
    fn typed_adapter_finishes_sinks_before_pure_router_finished() {
        let fixture = fixture();
        let trace = Arc::new(Mutex::new(Vec::new()));
        let adapter = typed_adapter(&fixture, Arc::clone(&trace), false);
        block_on(adapter.start()).expect("start");
        adapter
            .admit(envelope(&fixture, 1, "ordered"))
            .expect("admit");
        block_on(adapter.deliver()).expect("deliver");
        block_on(adapter.finish()).expect("finish");
        assert_eq!(&*lock(&trace), &["start", "process", "flush", "finish"]);
        assert_eq!(adapter.phase(), TypedRouterPhase::Finished);
    }

    #[test]
    fn typed_adapter_preserves_finish_error_and_never_publishes_finished() {
        let fixture = fixture();
        let trace = Arc::new(Mutex::new(Vec::new()));
        let adapter = typed_adapter(&fixture, Arc::clone(&trace), true);
        block_on(adapter.start()).expect("start");
        adapter
            .admit(envelope(&fixture, 1, "finish-error"))
            .expect("admit");
        let error = block_on(adapter.finish()).expect_err("finish must fail");
        assert!(matches!(
            error,
            TypedRouterError::Sink(TypedSinkError::Permanent(_))
        ));
        assert_eq!(&*lock(&trace), &["start", "process", "flush", "finish"]);
        assert_ne!(adapter.phase(), TypedRouterPhase::Finished);
    }

    #[test]
    fn zero_retry_budget_still_permits_the_initial_delivery_attempt() {
        let fixture = fixture();
        let trace = Arc::new(Mutex::new(Vec::new()));
        let (adapter, _) =
            typed_adapter_with_options(&fixture, Arc::clone(&trace), false, false, false, 0);
        block_on(adapter.start()).expect("start");
        adapter
            .admit(envelope(&fixture, 1, "initial-attempt"))
            .expect("admit");
        block_on(adapter.deliver()).expect("initial attempt is free");
        assert_eq!(&*lock(&trace), &["start", "process"]);
    }

    #[test]
    fn cancellation_only_stops_normal_work_and_cleanup_uses_finalization_lease() {
        let fixture = fixture();
        let trace = Arc::new(Mutex::new(Vec::new()));
        let (adapter, cancellation) =
            typed_adapter_with_options(&fixture, Arc::clone(&trace), false, false, false, 0);
        block_on(adapter.start()).expect("start");
        adapter
            .admit(envelope(&fixture, 1, "cancelled-run"))
            .expect("admit");
        cancellation.cancel_immediate();
        block_on(adapter.finish()).expect("cleanup remains bounded and usable");
        assert_eq!(&*lock(&trace), &["start", "process", "flush", "finish"]);
        assert_eq!(adapter.phase(), TypedRouterPhase::Finished);
    }

    #[test]
    fn cleanup_errors_are_all_retained_and_cancel_category_is_typed() {
        let fixture = fixture();
        let trace = Arc::new(Mutex::new(Vec::new()));
        let (adapter, _) =
            typed_adapter_with_options(&fixture, Arc::clone(&trace), true, true, true, 0);
        block_on(adapter.start()).expect("start");
        adapter
            .admit(envelope(&fixture, 1, "cleanup-errors"))
            .expect("admit");
        let error = block_on(adapter.finish()).expect_err("cleanup errors");
        let rendered = error.to_string();
        assert!(rendered.contains("flush failed"));
        assert!(rendered.contains("finish failed"));
        assert!(rendered.contains("cancel failed"));
        assert!(rendered.contains("unknown-outcome"));
        assert_ne!(adapter.phase(), TypedRouterPhase::Finished);
        assert_eq!(&*lock(&trace), &["start", "process", "flush", "finish"]);
    }

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

    fn ignored_envelope(fixture: &Fixture, sequence: u64, label: &str) -> TypedResultEnvelope {
        let user = TypedUserIdentity::new(1, fixture.root, 1, 0).expect("user");
        let mut result = SampleResult::new(label);
        result.set_successful(true);
        result.set_ignore(true);
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
            SampleEvent::new(
                result,
                "run-text",
                ThreadIdentity::with_group("thread-1", Some("group".to_owned()), Some(1)),
                "host",
                jmeter_rs_results::VariableSnapshot::new(),
            ),
        )
        .expect("typed ignored envelope")
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
    fn typed_ignored_samples_do_not_enter_ledger_or_advance_sequence() {
        let fixture = fixture();
        let mut router = router(&fixture, SinkLimits::new(1, 100_000));
        assert!(matches!(
            router.admit(ignored_envelope(&fixture, 1, "ignored")),
            Ok(TypedAdmissionOutcome::Ignored)
        ));
        assert_eq!(router.ledger().summary().selected, 0);
        assert!(matches!(
            router.admit(envelope(&fixture, 1, "accepted")),
            Ok(TypedAdmissionOutcome::Accepted { .. })
        ));
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

    #[test]
    fn stale_ack_is_rejected_after_retry_and_after_terminal_ack() {
        let fixture = fixture();
        let mut router = TypedResultRouter::new(
            fixture.run,
            fixture.generation,
            RetryBudget::new(2),
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
        router
            .admit(envelope(&fixture, 1, "retry-ack"))
            .expect("admit");
        let lease = router.next_delivery().expect("delivery").expect("lease");
        let key = lease.key();
        let stale_ack = lease.acknowledge(lease.durability_boundary()).expect("ack");
        router
            .fail(
                key,
                FailureReason::Retryable(BoundedDiagnostic::new("temporary")),
            )
            .expect("retryable failure");
        router.retry(key).expect("retry");
        let retried = router
            .next_delivery()
            .expect("delivery")
            .expect("retry lease");
        assert!(matches!(
            router.acknowledge(stale_ack),
            Err(TypedRouterError::Ledger(
                LedgerError::AcknowledgementMismatch
            ))
        ));
        router
            .acknowledge(
                retried
                    .acknowledge(retried.durability_boundary())
                    .expect("retry ack"),
            )
            .expect("durable");
        assert!(matches!(
            router.acknowledge(
                retried
                    .acknowledge(retried.durability_boundary())
                    .expect("duplicate ack")
            ),
            Err(TypedRouterError::Ledger(LedgerError::LeaseMissing))
        ));
        assert_eq!(router.ledger().summary().durable, 1);
        assert!(router.ledger().validate_conservation().is_ok());
    }

    #[test]
    fn retry_queue_full_does_not_spend_budget_or_change_ledger_state() {
        let fixture = fixture();
        let mut router = TypedResultRouter::new(
            fixture.run,
            fixture.generation,
            RetryBudget::new(3),
            [sink(
                &fixture,
                3,
                SinkLimits::new(1, 100_000),
                FullPolicy::FailRun,
            )],
        )
        .expect("router");
        router.start().expect("start");
        router.admit(envelope(&fixture, 1, "first")).expect("first");
        let first = router
            .next_delivery()
            .expect("delivery")
            .expect("first lease");
        router
            .admit(envelope(&fixture, 2, "second"))
            .expect("second");
        router
            .fail(
                first.key(),
                FailureReason::Retryable(BoundedDiagnostic::new("temporary")),
            )
            .expect("retryable failure");
        let remaining = router.remaining_budget().remaining();
        assert!(matches!(
            router.retry(first.key()),
            Err(TypedRouterError::Ledger(LedgerError::RetryQueueFull))
        ));
        assert_eq!(router.remaining_budget().remaining(), remaining);
        assert!(matches!(
            router.ledger().disposition(first.key()),
            Some(LedgerDisposition::Failed(FailureReason::Retryable(_)))
        ));
        let second = router
            .next_delivery()
            .expect("delivery")
            .expect("second lease");
        router
            .acknowledge(
                second
                    .acknowledge(second.durability_boundary())
                    .expect("ack"),
            )
            .expect("second durable");
        router.retry(first.key()).expect("retry after capacity");
        let retried = router
            .next_delivery()
            .expect("delivery")
            .expect("retry lease");
        router
            .acknowledge(
                retried
                    .acknowledge(retried.durability_boundary())
                    .expect("ack"),
            )
            .expect("retry durable");
        assert!(router.ledger().validate_conservation().is_ok());
    }

    #[test]
    fn backpressure_retry_identity_collision_cannot_spend_budget() {
        let fixture = fixture();
        let mut router = TypedResultRouter::new(
            fixture.run,
            fixture.generation,
            RetryBudget::new(2),
            [sink(
                &fixture,
                3,
                SinkLimits::new(1, 100_000),
                FullPolicy::Backpressure {
                    deadline: RetryBudget::new(2),
                },
            )],
        )
        .expect("router");
        router.start().expect("start");
        router.admit(envelope(&fixture, 1, "full")).expect("first");
        let pending = envelope(&fixture, 2, "original");
        assert!(matches!(
            router.admit(pending.clone()),
            Ok(TypedAdmissionOutcome::Full { .. })
        ));
        let alternate = envelope(&fixture, 2, "different-payload");
        let remaining = router.remaining_budget().remaining();
        assert!(matches!(
            router.retry_admission(alternate),
            Err(TypedRouterError::InvalidConfiguration(_))
        ));
        assert_eq!(router.remaining_budget().remaining(), remaining);
        let lease = router.next_delivery().expect("delivery").expect("lease");
        router
            .acknowledge(lease.acknowledge(lease.durability_boundary()).expect("ack"))
            .expect("durable");
        let remaining = router.remaining_budget().remaining();
        assert!(matches!(
            router.admit(pending.clone()),
            Ok(TypedAdmissionOutcome::Full { .. })
        ));
        assert_eq!(router.remaining_budget().remaining(), remaining);
        assert!(matches!(
            router.retry_admission(pending),
            Ok(TypedAdmissionOutcome::Accepted { .. })
        ));
    }

    #[test]
    fn finish_closes_pending_backpressure_and_conserves_counts() {
        let fixture = fixture();
        let mut router = TypedResultRouter::new(
            fixture.run,
            fixture.generation,
            RetryBudget::new(2),
            [sink(
                &fixture,
                3,
                SinkLimits::with_finalization(1, 100_000, 3),
                FullPolicy::Backpressure {
                    deadline: RetryBudget::new(2),
                },
            )],
        )
        .expect("router");
        router.start().expect("start");
        router
            .admit(envelope(&fixture, 1, "accepted"))
            .expect("first");
        assert!(matches!(
            router.admit(envelope(&fixture, 2, "pending")),
            Ok(TypedAdmissionOutcome::Full { .. })
        ));
        let report = router.finish().expect("finish");
        assert_eq!(report.selected, 2);
        assert_eq!(report.not_admitted, 1);
        assert_eq!(report.failed_after_admission, 1);
        assert_eq!(report.summary.incomplete, 0);
        report.validate_conservation().expect("conservation");
        assert_eq!(router.phase(), TypedRouterPhase::Finished);
    }

    #[test]
    fn finalization_bound_rejects_unaccountable_pending_work() {
        let fixture = fixture();
        let mut router = TypedResultRouter::new(
            fixture.run,
            fixture.generation,
            RetryBudget::new(1),
            [sink(
                &fixture,
                3,
                SinkLimits::with_finalization(1, 100_000, 2),
                FullPolicy::Backpressure {
                    deadline: RetryBudget::new(1),
                },
            )],
        )
        .expect("router");
        router.start().expect("start");
        router
            .admit(envelope(&fixture, 1, "accepted"))
            .expect("first");
        assert!(matches!(
            router.admit(envelope(&fixture, 2, "pending")),
            Ok(TypedAdmissionOutcome::Full { .. })
        ));
        assert!(matches!(
            router.finish(),
            Err(TypedRouterError::Ledger(LedgerError::FinalizationLimit))
        ));
        assert_eq!(router.phase(), TypedRouterPhase::AdmissionStopped);
        assert_eq!(router.ledger().summary().incomplete, 1);
        let lease = router.next_delivery().expect("delivery").expect("lease");
        router
            .acknowledge(lease.acknowledge(lease.durability_boundary()).expect("ack"))
            .expect("durable");
        let report = router.finish().expect("finish after draining");
        report.validate_conservation().expect("conservation");
    }

    #[test]
    fn cancellation_terminalizes_retryable_failures() {
        let fixture = fixture();
        let mut router = TypedResultRouter::new(
            fixture.run,
            fixture.generation,
            RetryBudget::new(2),
            [sink(
                &fixture,
                3,
                SinkLimits::new(1, 100_000),
                FullPolicy::Backpressure {
                    deadline: RetryBudget::new(2),
                },
            )],
        )
        .expect("router");
        router.start().expect("start");
        router
            .admit(envelope(&fixture, 1, "cancel-retry"))
            .expect("admit");
        let lease = router.next_delivery().expect("delivery").expect("lease");
        router
            .fail(
                lease.key(),
                FailureReason::Retryable(BoundedDiagnostic::new("temporary")),
            )
            .expect("retryable failure");
        router.cancel().expect("cancel");
        let summary = router
            .ledger()
            .validate_conservation()
            .expect("conservation");
        assert_eq!(summary.failed_after_admission, 1);
        assert_eq!(summary.incomplete, 0);
    }

    #[test]
    fn typed_router_rejects_queue_limits_that_exceed_ledger_capacity() {
        let fixture = fixture();
        let oversized = SinkLimits::new(MAX_TYPED_QUEUE_ITEMS + 1, usize::MAX);
        assert!(matches!(
            TypedResultRouter::new(
                fixture.run,
                fixture.generation,
                RetryBudget::new(1),
                [sink(&fixture, 3, oversized, FullPolicy::FailRun)],
            ),
            Err(TypedRouterError::InvalidConfiguration(_))
        ));
        let oversized_finalization =
            SinkLimits::with_finalization(1, 100, MAX_LEDGER_TRANSITIONS + 1);
        assert!(matches!(
            TypedResultRouter::new(
                fixture.run,
                fixture.generation,
                RetryBudget::new(1),
                [sink(
                    &fixture,
                    3,
                    oversized_finalization,
                    FullPolicy::FailRun,
                )],
            ),
            Err(TypedRouterError::InvalidConfiguration(_))
        ));
    }

    struct TestClock(std::cell::Cell<u64>);

    impl MonotonicClock for TestClock {
        fn now_ticks(&self) -> u64 {
            self.0.get()
        }
    }

    struct TestCancellation(AtomicBool);

    impl CancellationSignal for TestCancellation {
        fn is_cancelled(&self) -> bool {
            self.0.load(Ordering::Acquire)
        }

        fn register_waker(&self, _waker: &Waker) {}
    }

    #[test]
    fn finite_budget_uses_monotonic_phase_deadline_and_cancellation() {
        let clock = TestClock(std::cell::Cell::new(10));
        let cancellation = TestCancellation(AtomicBool::new(false));
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
        cancellation.0.store(true, Ordering::Release);
        assert!(matches!(budget.check(), Err(BudgetError::Cancelled)));
    }
}
