// SPDX-License-Identifier: Apache-2.0
//! Pure implementation-path identity and whole-plan admission.
//!
//! Decision 0009 makes path selection an admission property of the complete
//! executable plan.  This module deliberately contains no filesystem,
//! process, network, JVM, clock, or executor access.  An application builds
//! one identity for every enabled executable node (and run-level callback),
//! then asks a [`RuntimeCapabilitySet`] to classify the complete collection
//! before setup or other observable work starts.

use std::collections::BTreeSet;
use std::fmt;

use jmeter_rs_model::NodeId;

const MAX_PROFILE_ID_BYTES: usize = 128;
const MAX_CAPABILITY_ID_BYTES: usize = 256;
const MAX_PROVIDER_ID_BYTES: usize = 256;
const MAX_PROVIDER_VERSION_BYTES: usize = 128;
const MAX_CALLBACK_ID_BYTES: usize = 256;
const MAX_REASON_BYTES: usize = 512;
const MAX_MANIFEST_ENTRIES: usize = 100_000;

/// A fixed-size digest carried by a runtime identity.
///
/// The runtime does not calculate this digest: the owning compiler or
/// application supplies the digest produced by its pinned manifest.  A
/// zero digest is rejected at identity validation so a caller cannot mistake
/// an absent digest for an authenticated plan or capability set.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Digest32([u8; 32]);

impl Digest32 {
    /// Creates a digest from its raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw digest bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Returns whether all digest bytes are zero.
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

impl From<[u8; 32]> for Digest32 {
    fn from(bytes: [u8; 32]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl fmt::Debug for Digest32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Digest32(")?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str(")")
    }
}

/// Stable categories for invalid capability identity input.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CapabilityIdentityErrorCode {
    /// A required text field was empty.
    Empty,
    /// A bounded text field exceeded its limit.
    TooLong,
    /// A text field contained a control character.
    ControlCharacter,
    /// A digest field was all zero.
    ZeroDigest,
    /// A version field was not positive.
    InvalidVersion,
    /// An identity token used unsupported syntax.
    InvalidToken,
}

/// A bounded, typed identity validation error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityIdentityError {
    /// Stable machine-readable category.
    pub code: CapabilityIdentityErrorCode,
    /// Field that failed validation.
    pub field: &'static str,
    /// Bounded diagnostic detail.
    pub detail: String,
}

impl CapabilityIdentityError {
    fn new(
        code: CapabilityIdentityErrorCode,
        field: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            code,
            field,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for CapabilityIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} in {}: {}", self.code, self.field, self.detail)
    }
}

impl std::error::Error for CapabilityIdentityError {}

impl fmt::Display for CapabilityIdentityErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Empty => "empty",
            Self::TooLong => "too-long",
            Self::ControlCharacter => "control-character",
            Self::ZeroDigest => "zero-digest",
            Self::InvalidVersion => "invalid-version",
            Self::InvalidToken => "invalid-token",
        };
        formatter.write_str(name)
    }
}

fn validate_text(
    value: &str,
    field: &'static str,
    max_bytes: usize,
    allow_empty: bool,
) -> Result<(), CapabilityIdentityError> {
    if !allow_empty && value.is_empty() {
        return Err(CapabilityIdentityError::new(
            CapabilityIdentityErrorCode::Empty,
            field,
            "value is required",
        ));
    }
    if value.len() > max_bytes {
        return Err(CapabilityIdentityError::new(
            CapabilityIdentityErrorCode::TooLong,
            field,
            format!("value exceeds {max_bytes} bytes"),
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(CapabilityIdentityError::new(
            CapabilityIdentityErrorCode::ControlCharacter,
            field,
            "control characters are not permitted",
        ));
    }
    Ok(())
}

fn validate_token(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), CapabilityIdentityError> {
    validate_text(value, field, max_bytes, false)?;
    if value.chars().any(char::is_whitespace) {
        return Err(CapabilityIdentityError::new(
            CapabilityIdentityErrorCode::InvalidToken,
            field,
            "whitespace is not permitted",
        ));
    }
    Ok(())
}

fn validate_digest(
    digest: Digest32,
    field: &'static str,
) -> Result<(), CapabilityIdentityError> {
    if digest.is_zero() {
        return Err(CapabilityIdentityError::new(
            CapabilityIdentityErrorCode::ZeroDigest,
            field,
            "digest must be present and non-zero",
        ));
    }
    Ok(())
}

/// The exact compatibility profile bound to an executable path.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProfileIdentity {
    /// Profile identifier, for example `jmeter-5.6.3`.
    pub id: String,
    /// Profile schema/content version.
    pub version: u32,
    /// Canonical digest of the profile manifest.
    pub digest: Digest32,
}

impl ProfileIdentity {
    /// Creates and validates a profile identity.
    pub fn new(
        id: impl Into<String>,
        version: u32,
        digest: Digest32,
    ) -> Result<Self, CapabilityIdentityError> {
        let identity = Self {
            id: id.into(),
            version,
            digest,
        };
        identity.validate()?;
        Ok(identity)
    }

    /// Validates the profile identity.
    pub fn validate(&self) -> Result<(), CapabilityIdentityError> {
        validate_token(&self.id, "profile.id", MAX_PROFILE_ID_BYTES)?;
        if self.version == 0 {
            return Err(CapabilityIdentityError::new(
                CapabilityIdentityErrorCode::InvalidVersion,
                "profile.version",
                "version must be positive",
            ));
        }
        validate_digest(self.digest, "profile.digest")
    }
}

/// Identity of a provider used by a selected implementation path.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderIdentity {
    /// Provider or built-in implementation identifier.
    pub id: String,
    /// Provider release/version identity.
    pub version: String,
    /// Optional artifact digest for an external provider.
    pub artifact_digest: Option<Digest32>,
}

impl ProviderIdentity {
    /// Creates a provider identity without an external artifact digest.
    pub fn new(
        id: impl Into<String>,
        version: impl Into<String>,
    ) -> Result<Self, CapabilityIdentityError> {
        let identity = Self {
            id: id.into(),
            version: version.into(),
            artifact_digest: None,
        };
        identity.validate()?;
        Ok(identity)
    }

    /// Adds and validates an external provider artifact digest.
    pub fn with_artifact_digest(
        mut self,
        digest: Digest32,
    ) -> Result<Self, CapabilityIdentityError> {
        validate_digest(digest, "provider.artifact_digest")?;
        self.artifact_digest = Some(digest);
        Ok(self)
    }

    /// Validates the provider identity.
    pub fn validate(&self) -> Result<(), CapabilityIdentityError> {
        validate_token(&self.id, "provider.id", MAX_PROVIDER_ID_BYTES)?;
        validate_token(
            &self.version,
            "provider.version",
            MAX_PROVIDER_VERSION_BYTES,
        )?;
        if let Some(digest) = self.artifact_digest {
            validate_digest(digest, "provider.artifact_digest")?;
        }
        Ok(())
    }
}

/// Source identity attached to an enabled executable node or run callback.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SourceIdentity {
    /// A document-local executable node.
    Node {
        /// Stable document-local node identity.
        node_id: NodeId,
    },
    /// A run-level callback with an explicit source order.
    RunLevel {
        /// Stable callback order within the run lifecycle.
        ordinal: u32,
        /// Bounded callback identity, such as `setup` or `teardown`.
        callback: String,
    },
}

impl SourceIdentity {
    /// Creates a node source identity.
    #[must_use]
    pub const fn node(node_id: NodeId) -> Self {
        Self::Node { node_id }
    }

    /// Creates and validates a run-level callback identity.
    pub fn run_level(
        ordinal: u32,
        callback: impl Into<String>,
    ) -> Result<Self, CapabilityIdentityError> {
        let source = Self::RunLevel {
            ordinal,
            callback: callback.into(),
        };
        source.validate()?;
        Ok(source)
    }

    /// Validates the source identity.
    pub fn validate(&self) -> Result<(), CapabilityIdentityError> {
        if let Self::RunLevel { callback, .. } = self {
            validate_token(callback, "source.callback", MAX_CALLBACK_ID_BYTES)?;
        }
        Ok(())
    }
}

/// A versioned capability name used by one implementation path.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VersionedCapability {
    /// Stable capability identifier without a path-family prefix.
    pub id: String,
    /// Positive capability schema/implementation version.
    pub version: u32,
}

impl VersionedCapability {
    /// Creates and validates a versioned capability.
    pub fn new(
        id: impl Into<String>,
        version: u32,
    ) -> Result<Self, CapabilityIdentityError> {
        let capability = Self {
            id: id.into(),
            version,
        };
        capability.validate()?;
        Ok(capability)
    }

    /// Validates this capability.
    pub fn validate(&self) -> Result<(), CapabilityIdentityError> {
        validate_token(&self.id, "capability.id", MAX_CAPABILITY_ID_BYTES)?;
        if self.version == 0 {
            return Err(CapabilityIdentityError::new(
                CapabilityIdentityErrorCode::InvalidVersion,
                "capability.version",
                "version must be positive",
            ));
        }
        Ok(())
    }

    /// Returns a stable human-readable capability token.
    #[must_use]
    pub fn canonical_name(&self) -> String {
        format!("{}@{}", self.id, self.version)
    }
}

/// Stable reason codes for an unavailable implementation path.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum UnavailableReasonCode {
    /// No implementation is declared for the source element.
    UnsupportedCapability,
    /// The optional compatibility pack is required.
    RequiresCompatibilityPack,
    /// A required negotiated capability is absent.
    MissingCapability,
    /// A required provider or driver is absent.
    MissingProvider,
    /// A required service is absent.
    MissingService,
    /// The target platform does not provide the path.
    PlatformUnavailable,
    /// The declared protocol is unavailable.
    ProtocolUnavailable,
    /// The source has invalid configuration for this path.
    InvalidConfiguration,
}

impl fmt::Display for UnavailableReasonCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::UnsupportedCapability => "unsupported-capability",
            Self::RequiresCompatibilityPack => "requires-compatibility-pack",
            Self::MissingCapability => "missing-capability",
            Self::MissingProvider => "missing-provider",
            Self::MissingService => "missing-service",
            Self::PlatformUnavailable => "platform-unavailable",
            Self::ProtocolUnavailable => "protocol-unavailable",
            Self::InvalidConfiguration => "invalid-configuration",
        };
        formatter.write_str(value)
    }
}

/// A bounded, stable unavailable-path reason.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UnavailableReason {
    /// Stable machine-readable reason code.
    pub code: UnavailableReasonCode,
    /// Bounded diagnostic detail; it is never used for routing.
    pub detail: String,
}

impl UnavailableReason {
    /// Creates and validates an unavailable-path reason.
    pub fn new(
        code: UnavailableReasonCode,
        detail: impl Into<String>,
    ) -> Result<Self, CapabilityIdentityError> {
        let reason = Self {
            code,
            detail: detail.into(),
        };
        reason.validate()?;
        Ok(reason)
    }

    /// Validates the bounded reason detail.
    pub fn validate(&self) -> Result<(), CapabilityIdentityError> {
        validate_text(&self.detail, "unavailable.detail", MAX_REASON_BYTES, true)
    }
}

/// Closed implementation-path family.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ImplementationPathFamily {
    /// A versioned standalone Rust implementation.
    Native,
    /// A versioned optional JVM compatibility-pack implementation.
    CompatJvm,
    /// A versioned optional Java RMI compatibility-pack implementation.
    CompatRmi,
    /// No executable implementation is available.
    Unavailable,
}

impl fmt::Display for ImplementationPathFamily {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Native => "native",
            Self::CompatJvm => "compat.jvm",
            Self::CompatRmi => "compat.rmi",
            Self::Unavailable => "unavailable",
        };
        formatter.write_str(value)
    }
}

/// The closed path choice for one executable source identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ImplementationPath {
    /// A standalone Rust capability.
    Native(VersionedCapability),
    /// A pinned JVM compatibility-pack capability.
    CompatJvm(VersionedCapability),
    /// A pinned Java RMI compatibility-pack capability.
    CompatRmi(VersionedCapability),
    /// A deliberately unavailable source capability.
    Unavailable(UnavailableReason),
}

impl ImplementationPath {
    /// Creates a native path from a versioned capability.
    #[must_use]
    pub fn native(capability: VersionedCapability) -> Self {
        Self::Native(capability)
    }

    /// Creates a JVM compatibility path from a versioned capability.
    #[must_use]
    pub fn compat_jvm(capability: VersionedCapability) -> Self {
        Self::CompatJvm(capability)
    }

    /// Creates an RMI compatibility path from a versioned capability.
    #[must_use]
    pub fn compat_rmi(capability: VersionedCapability) -> Self {
        Self::CompatRmi(capability)
    }

    /// Creates an unavailable path from a stable reason.
    #[must_use]
    pub fn unavailable(reason: UnavailableReason) -> Self {
        Self::Unavailable(reason)
    }

    /// Returns the closed path family.
    #[must_use]
    pub const fn family(&self) -> ImplementationPathFamily {
        match self {
            Self::Native(_) => ImplementationPathFamily::Native,
            Self::CompatJvm(_) => ImplementationPathFamily::CompatJvm,
            Self::CompatRmi(_) => ImplementationPathFamily::CompatRmi,
            Self::Unavailable(_) => ImplementationPathFamily::Unavailable,
        }
    }

    /// Returns the versioned capability for an executable path.
    #[must_use]
    pub fn capability(&self) -> Option<&VersionedCapability> {
        match self {
            Self::Native(capability)
            | Self::CompatJvm(capability)
            | Self::CompatRmi(capability) => Some(capability),
            Self::Unavailable(_) => None,
        }
    }

    /// Returns the unavailable reason, if this is an unavailable path.
    #[must_use]
    pub fn unavailable_reason(&self) -> Option<&UnavailableReason> {
        match self {
            Self::Unavailable(reason) => Some(reason),
            Self::Native(_) | Self::CompatJvm(_) | Self::CompatRmi(_) => None,
        }
    }

    /// Validates all path-owned fields.
    pub fn validate(&self) -> Result<(), CapabilityIdentityError> {
        match self {
            Self::Native(capability)
            | Self::CompatJvm(capability)
            | Self::CompatRmi(capability) => capability.validate(),
            Self::Unavailable(reason) => reason.validate(),
        }
    }

    /// Returns a stable path token such as `native.http@1`.
    #[must_use]
    pub fn canonical_name(&self) -> String {
        match self {
            Self::Native(capability)
            | Self::CompatJvm(capability)
            | Self::CompatRmi(capability) => {
                format!("{}.{}", self.family(), capability.canonical_name())
            }
            Self::Unavailable(reason) => format!("{}.{}", self.family(), reason.code),
        }
    }
}

/// Full identity bound to one implementation path.
///
/// The profile, executable-plan digest, source identity, provider identity,
/// and negotiated capability-set digest are all part of the identity.  A
/// path family or capability name alone is never sufficient for admission.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ImplementationPathIdentity {
    /// Selected closed path.
    pub path: ImplementationPath,
    /// Exact compatibility profile identity.
    pub profile: ProfileIdentity,
    /// Digest of the complete executable plan.
    pub plan_digest: Digest32,
    /// Node or run-level source identity.
    pub source: SourceIdentity,
    /// Provider/driver/built-in implementation identity.
    pub provider: ProviderIdentity,
    /// Digest of the negotiated runtime capability set.
    pub capability_set_digest: Digest32,
}

impl ImplementationPathIdentity {
    /// Creates and validates a complete implementation-path identity.
    pub fn new(
        profile: ProfileIdentity,
        plan_digest: Digest32,
        source: SourceIdentity,
        provider: ProviderIdentity,
        capability_set_digest: Digest32,
        path: ImplementationPath,
    ) -> Result<Self, CapabilityIdentityError> {
        let identity = Self {
            path,
            profile,
            plan_digest,
            source,
            provider,
            capability_set_digest,
        };
        identity.validate()?;
        Ok(identity)
    }

    /// Alias emphasizing that the fields are assembled from a pinned
    /// manifest rather than inferred from a class name.
    pub fn from_parts(
        profile: ProfileIdentity,
        plan_digest: Digest32,
        source: SourceIdentity,
        provider: ProviderIdentity,
        capability_set_digest: Digest32,
        path: ImplementationPath,
    ) -> Result<Self, CapabilityIdentityError> {
        Self::new(
            profile,
            plan_digest,
            source,
            provider,
            capability_set_digest,
            path,
        )
    }

    /// Validates every component of the identity.
    pub fn validate(&self) -> Result<(), CapabilityIdentityError> {
        self.profile.validate()?;
        validate_digest(self.plan_digest, "plan.digest")?;
        self.source.validate()?;
        self.provider.validate()?;
        validate_digest(self.capability_set_digest, "capability-set.digest")?;
        self.path.validate()
    }

    /// Returns the selected closed path family.
    #[must_use]
    pub const fn family(&self) -> ImplementationPathFamily {
        self.path.family()
    }
}

/// A capability negotiated for one path family.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NegotiatedCapability {
    /// Path family for which this capability is valid.
    pub family: ImplementationPathFamily,
    /// Exact versioned capability identity.
    pub capability: VersionedCapability,
}

impl NegotiatedCapability {
    /// Creates a negotiated capability and rejects the unavailable family.
    pub fn new(
        family: ImplementationPathFamily,
        capability: VersionedCapability,
    ) -> Result<Self, CapabilityIdentityError> {
        if family == ImplementationPathFamily::Unavailable {
            return Err(CapabilityIdentityError::new(
                CapabilityIdentityErrorCode::InvalidToken,
                "negotiated-capability.family",
                "unavailable is not a negotiable implementation family",
            ));
        }
        capability.validate()?;
        Ok(Self { family, capability })
    }

    /// Creates a native negotiated capability.
    pub fn native(capability: VersionedCapability) -> Result<Self, CapabilityIdentityError> {
        Self::new(ImplementationPathFamily::Native, capability)
    }

    /// Creates a JVM negotiated capability.
    pub fn compat_jvm(capability: VersionedCapability) -> Result<Self, CapabilityIdentityError> {
        Self::new(ImplementationPathFamily::CompatJvm, capability)
    }

    /// Creates an RMI negotiated capability.
    pub fn compat_rmi(capability: VersionedCapability) -> Result<Self, CapabilityIdentityError> {
        Self::new(ImplementationPathFamily::CompatRmi, capability)
    }
}

/// The mode under which a complete plan is admitted.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AdmissionMode {
    /// Only standalone native paths may be admitted.
    StandaloneNative,
    /// The explicitly provisioned compatibility pack may provide negotiated
    /// JVM/RMI paths in addition to native paths.
    CompatibilityPack,
}

/// A closed negotiated capability set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeCapabilitySet {
    /// Standalone mode and its exact native capabilities.
    StandaloneNative {
        /// Profile bound to the set.
        profile: ProfileIdentity,
        /// Executable-plan digest bound to the set.
        plan_digest: Digest32,
        /// Digest of this negotiated set.
        capability_set_digest: Digest32,
        /// Exact native capabilities available to the run.
        capabilities: BTreeSet<VersionedCapability>,
    },
    /// Explicit compatibility-pack mode and all negotiated path capabilities.
    CompatibilityPack {
        /// Profile bound to the set.
        profile: ProfileIdentity,
        /// Executable-plan digest bound to the set.
        plan_digest: Digest32,
        /// Digest of this negotiated set.
        capability_set_digest: Digest32,
        /// Exact path-family/capability pairs available to the run.
        capabilities: BTreeSet<NegotiatedCapability>,
    },
}

impl RuntimeCapabilitySet {
    /// Creates a standalone native capability set.
    pub fn standalone_native<I>(
        profile: ProfileIdentity,
        plan_digest: Digest32,
        capability_set_digest: Digest32,
        capabilities: I,
    ) -> Result<Self, CapabilityIdentityError>
    where
        I: IntoIterator<Item = VersionedCapability>,
    {
        let mut set = BTreeSet::new();
        for capability in capabilities {
            capability.validate()?;
            set.insert(capability);
        }
        let result = Self::StandaloneNative {
            profile,
            plan_digest,
            capability_set_digest,
            capabilities: set,
        };
        result.validate()?;
        Ok(result)
    }

    /// Creates an explicit compatibility-pack capability set.
    pub fn compatibility_pack<I>(
        profile: ProfileIdentity,
        plan_digest: Digest32,
        capability_set_digest: Digest32,
        capabilities: I,
    ) -> Result<Self, CapabilityIdentityError>
    where
        I: IntoIterator<Item = NegotiatedCapability>,
    {
        let mut set = BTreeSet::new();
        for capability in capabilities {
            capability.capability.validate()?;
            if capability.family == ImplementationPathFamily::Unavailable {
                return Err(CapabilityIdentityError::new(
                    CapabilityIdentityErrorCode::InvalidToken,
                    "negotiated-capability.family",
                    "unavailable is not negotiable",
                ));
            }
            set.insert(capability);
        }
        let result = Self::CompatibilityPack {
            profile,
            plan_digest,
            capability_set_digest,
            capabilities: set,
        };
        result.validate()?;
        Ok(result)
    }

    /// Returns the admission mode represented by this set.
    #[must_use]
    pub const fn mode(&self) -> AdmissionMode {
        match self {
            Self::StandaloneNative { .. } => AdmissionMode::StandaloneNative,
            Self::CompatibilityPack { .. } => AdmissionMode::CompatibilityPack,
        }
    }

    /// Returns the profile bound to this set.
    #[must_use]
    pub fn profile(&self) -> &ProfileIdentity {
        match self {
            Self::StandaloneNative { profile, .. } | Self::CompatibilityPack { profile, .. } => {
                profile
            }
        }
    }

    /// Returns the executable-plan digest bound to this set.
    #[must_use]
    pub const fn plan_digest(&self) -> Digest32 {
        match self {
            Self::StandaloneNative { plan_digest, .. }
            | Self::CompatibilityPack { plan_digest, .. } => *plan_digest,
        }
    }

    /// Returns the negotiated capability-set digest.
    #[must_use]
    pub const fn capability_set_digest(&self) -> Digest32 {
        match self {
            Self::StandaloneNative {
                capability_set_digest,
                ..
            }
            | Self::CompatibilityPack {
                capability_set_digest,
                ..
            } => *capability_set_digest,
        }
    }

    /// Validates a set whose fields may have been constructed through public
    /// struct fields rather than one of the checked constructors.
    pub fn validate(&self) -> Result<(), CapabilityIdentityError> {
        self.profile().validate()?;
        validate_digest(self.plan_digest(), "plan.digest")?;
        validate_digest(self.capability_set_digest(), "capability-set.digest")?;
        match self {
            Self::StandaloneNative { capabilities, .. } => {
                for capability in capabilities {
                    capability.validate()?;
                }
            }
            Self::CompatibilityPack { capabilities, .. } => {
                for capability in capabilities {
                    NegotiatedCapability::new(capability.family, capability.capability.clone())?;
                }
            }
        }
        Ok(())
    }

    /// Classifies a complete ordered collection of path identities.
    ///
    /// The collection is first validated, bounded, sorted by source identity,
    /// and checked for duplicate sources.  Only after every entry is known to
    /// be valid are admission rules evaluated.  Therefore this method returns
    /// either one complete [`PlanAdmission`] or one error; it never exposes a
    /// partially admitted native prefix when a later path needs Java or is
    /// unavailable.
    pub fn classify<I>(
        &self,
        identities: I,
    ) -> Result<PlanAdmission, PlanAdmissionError>
    where
        I: IntoIterator<Item = ImplementationPathIdentity>,
    {
        self.validate().map_err(PlanAdmissionError::SetIdentity)?;
        let manifest = ImplementationPathManifest::new(identities)
            .map_err(PlanAdmissionError::Manifest)?;

        for identity in manifest.entries() {
            if identity.profile != *self.profile() {
                return Err(PlanAdmissionError::ProfileMismatch {
                    source: identity.source.clone(),
                });
            }
            if identity.plan_digest != self.plan_digest() {
                return Err(PlanAdmissionError::PlanDigestMismatch {
                    source: identity.source.clone(),
                });
            }
            if identity.capability_set_digest != self.capability_set_digest() {
                return Err(PlanAdmissionError::CapabilitySetDigestMismatch {
                    source: identity.source.clone(),
                });
            }

            match &identity.path {
                ImplementationPath::Unavailable(reason) => {
                    return Err(PlanAdmissionError::Unavailable {
                        source: identity.source.clone(),
                        reason: reason.clone(),
                    });
                }
                ImplementationPath::Native(capability) => {
                    if !self.supports(ImplementationPathFamily::Native, capability) {
                        return Err(PlanAdmissionError::CapabilityNotNegotiated {
                            source: identity.source.clone(),
                            family: ImplementationPathFamily::Native,
                            capability: capability.clone(),
                        });
                    }
                }
                ImplementationPath::CompatJvm(capability) => {
                    if self.mode() == AdmissionMode::StandaloneNative {
                        return Err(PlanAdmissionError::RequiresCompatibilityPack {
                            source: identity.source.clone(),
                            family: ImplementationPathFamily::CompatJvm,
                            capability: capability.clone(),
                        });
                    }
                    if !self.supports(ImplementationPathFamily::CompatJvm, capability) {
                        return Err(PlanAdmissionError::CapabilityNotNegotiated {
                            source: identity.source.clone(),
                            family: ImplementationPathFamily::CompatJvm,
                            capability: capability.clone(),
                        });
                    }
                }
                ImplementationPath::CompatRmi(capability) => {
                    if self.mode() == AdmissionMode::StandaloneNative {
                        return Err(PlanAdmissionError::RequiresCompatibilityPack {
                            source: identity.source.clone(),
                            family: ImplementationPathFamily::CompatRmi,
                            capability: capability.clone(),
                        });
                    }
                    if !self.supports(ImplementationPathFamily::CompatRmi, capability) {
                        return Err(PlanAdmissionError::CapabilityNotNegotiated {
                            source: identity.source.clone(),
                            family: ImplementationPathFamily::CompatRmi,
                            capability: capability.clone(),
                        });
                    }
                }
            }
        }

        Ok(PlanAdmission {
            mode: self.mode(),
            profile: self.profile().clone(),
            plan_digest: self.plan_digest(),
            capability_set_digest: self.capability_set_digest(),
            manifest,
        })
    }

    /// Alias for callers that name the operation “admit”.
    pub fn admit<I>(&self, identities: I) -> Result<PlanAdmission, PlanAdmissionError>
    where
        I: IntoIterator<Item = ImplementationPathIdentity>,
    {
        self.classify(identities)
    }

    fn supports(&self, family: ImplementationPathFamily, capability: &VersionedCapability) -> bool {
        match self {
            Self::StandaloneNative { capabilities, .. } => {
                family == ImplementationPathFamily::Native && capabilities.contains(capability)
            }
            Self::CompatibilityPack { capabilities, .. } => capabilities.contains(
                &NegotiatedCapability {
                    family,
                    capability: capability.clone(),
                },
            ),
        }
    }
}

/// An ordered, duplicate-free executable-path manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImplementationPathManifest {
    entries: Vec<ImplementationPathIdentity>,
}

impl ImplementationPathManifest {
    /// Creates a bounded manifest sorted by source identity.
    pub fn new<I>(identities: I) -> Result<Self, ManifestError>
    where
        I: IntoIterator<Item = ImplementationPathIdentity>,
    {
        let mut entries = Vec::new();
        for identity in identities {
            if entries.len() >= MAX_MANIFEST_ENTRIES {
                return Err(ManifestError::Limit {
                    limit: MAX_MANIFEST_ENTRIES,
                });
            }
            identity.validate().map_err(ManifestError::Identity)?;
            entries.push(identity);
        }
        entries.sort_by(|left, right| left.source.cmp(&right.source));
        for pair in entries.windows(2) {
            if pair[0].source == pair[1].source {
                return Err(ManifestError::DuplicateSource {
                    source: pair[0].source.clone(),
                });
            }
        }
        Ok(Self { entries })
    }

    /// Returns entries in deterministic source order.
    #[must_use]
    pub fn entries(&self) -> &[ImplementationPathIdentity] {
        &self.entries
    }

    /// Returns the number of executable entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether no executable entries are present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterates entries in deterministic source order.
    pub fn iter(&self) -> impl Iterator<Item = &ImplementationPathIdentity> {
        self.entries.iter()
    }
}

/// Errors constructing the ordered path manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifestError {
    /// An identity failed validation.
    Identity(CapabilityIdentityError),
    /// The manifest exceeded its bounded entry count.
    Limit {
        /// Maximum accepted entries.
        limit: usize,
    },
    /// Two executable entries claimed one source identity.
    DuplicateSource {
        /// Repeated source identity.
        source: SourceIdentity,
    },
}

impl fmt::Display for ManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identity(error) => write!(formatter, "invalid path identity: {error}"),
            Self::Limit { limit } => write!(formatter, "path manifest exceeds {limit} entries"),
            Self::DuplicateSource { source } => {
                write!(formatter, "duplicate executable source identity: {source:?}")
            }
        }
    }
}

impl std::error::Error for ManifestError {}

/// Atomic whole-plan admission errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlanAdmissionError {
    /// The configured capability set itself is invalid.
    SetIdentity(CapabilityIdentityError),
    /// The candidate manifest is invalid or duplicated.
    Manifest(ManifestError),
    /// An entry was bound to another compatibility profile.
    ProfileMismatch {
        /// Rejected source identity.
        source: SourceIdentity,
    },
    /// An entry was compiled from another executable plan.
    PlanDigestMismatch {
        /// Rejected source identity.
        source: SourceIdentity,
    },
    /// An entry was negotiated against another capability set.
    CapabilitySetDigestMismatch {
        /// Rejected source identity.
        source: SourceIdentity,
    },
    /// An explicitly unavailable path was present.
    Unavailable {
        /// Rejected source identity.
        source: SourceIdentity,
        /// Stable unavailable reason.
        reason: UnavailableReason,
    },
    /// Standalone mode encountered a JVM/RMI path.
    RequiresCompatibilityPack {
        /// Rejected source identity.
        source: SourceIdentity,
        /// Rejected external path family.
        family: ImplementationPathFamily,
        /// Rejected capability.
        capability: VersionedCapability,
    },
    /// A path was not in the exact negotiated set.
    CapabilityNotNegotiated {
        /// Rejected source identity.
        source: SourceIdentity,
        /// Rejected path family.
        family: ImplementationPathFamily,
        /// Rejected capability.
        capability: VersionedCapability,
    },
}

impl PlanAdmissionError {
    /// Returns a stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::SetIdentity(_) => "runtime.capability.invalid-set",
            Self::Manifest(_) => "runtime.capability.invalid-manifest",
            Self::ProfileMismatch { .. } => "runtime.capability.profile-mismatch",
            Self::PlanDigestMismatch { .. } => "runtime.capability.plan-mismatch",
            Self::CapabilitySetDigestMismatch { .. } => {
                "runtime.capability.capability-set-mismatch"
            }
            Self::Unavailable { .. } => "runtime.capability.unavailable",
            Self::RequiresCompatibilityPack { .. } => {
                "runtime.capability.compatibility-pack-required"
            }
            Self::CapabilityNotNegotiated { .. } => "runtime.capability.not-negotiated",
        }
    }
}

impl fmt::Display for PlanAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SetIdentity(error) => write!(formatter, "{}: {error}", self.code()),
            Self::Manifest(error) => write!(formatter, "{}: {error}", self.code()),
            Self::ProfileMismatch { source } => {
                write!(formatter, "{} at {source:?}", self.code())
            }
            Self::PlanDigestMismatch { source } => {
                write!(formatter, "{} at {source:?}", self.code())
            }
            Self::CapabilitySetDigestMismatch { source } => {
                write!(formatter, "{} at {source:?}", self.code())
            }
            Self::Unavailable { source, reason } => {
                write!(formatter, "{} at {source:?}: {}", self.code(), reason.code)
            }
            Self::RequiresCompatibilityPack {
                source,
                family,
                capability,
            }
            | Self::CapabilityNotNegotiated {
                source,
                family,
                capability,
            } => write!(
                formatter,
                "{} at {source:?}: {family}.{}",
                self.code(),
                capability.canonical_name()
            ),
        }
    }
}

impl std::error::Error for PlanAdmissionError {}

/// The complete plan admission result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanAdmission {
    mode: AdmissionMode,
    profile: ProfileIdentity,
    plan_digest: Digest32,
    capability_set_digest: Digest32,
    manifest: ImplementationPathManifest,
}

impl PlanAdmission {
    /// Returns the mode that admitted this complete plan.
    #[must_use]
    pub const fn mode(&self) -> AdmissionMode {
        self.mode
    }

    /// Returns the immutable ordered path manifest.
    #[must_use]
    pub const fn manifest(&self) -> &ImplementationPathManifest {
        &self.manifest
    }

    /// Returns the profile bound to the admission.
    #[must_use]
    pub const fn profile(&self) -> &ProfileIdentity {
        &self.profile
    }

    /// Returns the executable-plan digest bound to the admission.
    #[must_use]
    pub const fn plan_digest(&self) -> Digest32 {
        self.plan_digest
    }

    /// Returns the negotiated capability-set digest bound to the admission.
    #[must_use]
    pub const fn capability_set_digest(&self) -> Digest32 {
        self.capability_set_digest
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "pure deterministic capability fixtures")]
mod tests {
    use super::*;

    fn digest(byte: u8) -> Digest32 {
        Digest32::from_bytes([byte; 32])
    }

    fn profile() -> ProfileIdentity {
        ProfileIdentity::new("jmeter-5.6.3", 2, digest(1)).expect("profile")
    }

    fn provider() -> ProviderIdentity {
        ProviderIdentity::new("standalone-native", "1").expect("provider")
    }

    fn capability(name: &str) -> VersionedCapability {
        VersionedCapability::new(name, 1).expect("capability")
    }

    fn identity(source: SourceIdentity, path: ImplementationPath) -> ImplementationPathIdentity {
        ImplementationPathIdentity::new(
            profile(),
            digest(2),
            source,
            provider(),
            digest(3),
            path,
        )
        .expect("identity")
    }

    fn native_set() -> RuntimeCapabilitySet {
        RuntimeCapabilitySet::standalone_native(
            profile(),
            digest(2),
            digest(3),
            [capability("http")],
        )
        .expect("native set")
    }

    #[test]
    fn zero_digest_is_not_an_identity() {
        assert!(matches!(
            ProfileIdentity::new("profile", 1, digest(0)),
            Err(CapabilityIdentityError {
                code: CapabilityIdentityErrorCode::ZeroDigest,
                field: "profile.digest",
                ..
            })
        ));
    }

    #[test]
    fn manifest_is_sorted_by_source_and_rejects_duplicates() {
        let later = identity(
            SourceIdentity::node(NodeId::new(20)),
            ImplementationPath::native(capability("later")),
        );
        let earlier = identity(
            SourceIdentity::node(NodeId::new(10)),
            ImplementationPath::native(capability("earlier")),
        );
        let manifest = ImplementationPathManifest::new([later.clone(), earlier.clone()])
            .expect("manifest");
        assert_eq!(manifest.entries()[0].source, earlier.source);
        assert_eq!(manifest.entries()[1].source, later.source);

        let duplicate = ImplementationPathManifest::new([earlier.clone(), earlier])
            .expect_err("duplicate source");
        assert!(matches!(duplicate, ManifestError::DuplicateSource { .. }));
    }

    #[test]
    fn standalone_admission_is_atomic_for_native_prefix_and_jvm_tail() {
        let native = identity(
            SourceIdentity::node(NodeId::new(1)),
            ImplementationPath::native(capability("http")),
        );
        let jvm = identity(
            SourceIdentity::node(NodeId::new(2)),
            ImplementationPath::compat_jvm(capability("java-sampler")),
        );
        let error = native_set()
            .classify([native, jvm])
            .expect_err("mixed standalone plan must fail");
        assert!(matches!(
            error,
            PlanAdmissionError::RequiresCompatibilityPack {
                source: SourceIdentity::Node {
                    node_id: NodeId(2)
                },
                family: ImplementationPathFamily::CompatJvm,
                ..
            }
        ));
    }

    #[test]
    fn standalone_admission_rejects_explicit_unavailable_paths() {
        let reason = UnavailableReason::new(
            UnavailableReasonCode::UnsupportedCapability,
            "no native implementation",
        )
        .expect("reason");
        let error = native_set()
            .classify([identity(
                SourceIdentity::node(NodeId::new(9)),
                ImplementationPath::unavailable(reason),
            )])
            .expect_err("unavailable path");
        assert_eq!(error.code(), "runtime.capability.unavailable");
    }

    #[test]
    fn compatibility_pack_admits_exact_mixed_native_and_jvm_paths() {
        let native_capability = capability("http");
        let jvm_capability = capability("java-sampler");
        let set = RuntimeCapabilitySet::compatibility_pack(
            profile(),
            digest(2),
            digest(3),
            [
                NegotiatedCapability::native(native_capability.clone()).expect("native"),
                NegotiatedCapability::compat_jvm(jvm_capability.clone()).expect("jvm"),
            ],
        )
        .expect("compatibility set");
        let admission = set
            .classify([
                identity(
                    SourceIdentity::node(NodeId::new(1)),
                    ImplementationPath::native(native_capability),
                ),
                identity(
                    SourceIdentity::node(NodeId::new(2)),
                    ImplementationPath::compat_jvm(jvm_capability),
                ),
            ])
            .expect("exactly negotiated mixed plan");
        assert_eq!(admission.mode(), AdmissionMode::CompatibilityPack);
        assert_eq!(admission.manifest().len(), 2);
    }

    #[test]
    fn compatibility_pack_does_not_implicitly_fallback_to_native() {
        let jvm_capability = capability("java-sampler");
        let set = RuntimeCapabilitySet::compatibility_pack(
            profile(),
            digest(2),
            digest(3),
            [NegotiatedCapability::native(capability("http")).expect("native")],
        )
        .expect("compatibility set");
        let error = set
            .classify([identity(
                SourceIdentity::node(NodeId::new(1)),
                ImplementationPath::compat_jvm(jvm_capability),
            )])
            .expect_err("missing JVM capability");
        assert!(matches!(
            error,
            PlanAdmissionError::CapabilityNotNegotiated {
                family: ImplementationPathFamily::CompatJvm,
                ..
            }
        ));
    }

    #[test]
    fn identity_context_mismatch_is_rejected_before_path_support_checks() {
        let mut wrong_plan = identity(
            SourceIdentity::node(NodeId::new(1)),
            ImplementationPath::native(capability("http")),
        );
        wrong_plan.plan_digest = digest(8);
        let error = native_set()
            .classify([wrong_plan])
            .expect_err("plan mismatch");
        assert!(matches!(error, PlanAdmissionError::PlanDigestMismatch { .. }));
    }

    #[test]
    fn run_level_sources_have_deterministic_order() {
        let first = identity(
            SourceIdentity::run_level(0, "setup").expect("setup"),
            ImplementationPath::native(capability("setup")),
        );
        let second = identity(
            SourceIdentity::run_level(1, "teardown").expect("teardown"),
            ImplementationPath::native(capability("teardown")),
        );
        let manifest = ImplementationPathManifest::new([second, first]).expect("manifest");
        assert!(manifest.entries()[0].source < manifest.entries()[1].source);
    }
}
