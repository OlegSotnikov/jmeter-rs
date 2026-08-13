// SPDX-License-Identifier: Apache-2.0
//! In-memory fixture manifests and bounded artifact builders.
//!
//! Fixtures built here are deliberately offline values.  The builder never
//! opens a path, reads an environment variable, consults the wall clock, or
//! acquires a Java/JMeter artifact.  Callers can pass the resulting bytes to a
//! test-specific parser or oracle adapter while keeping provenance and
//! deterministic metadata visible in the assertion.
//!
//! The metadata here is intentionally not the complete oracle manifest:
//! target/JVM, plugin/service hashes, normalization-policy references, and
//! process-run evidence remain owned by `tools/jmeter-oracle`.

use crate::error::{ErrorCode, StableError};
use crate::random::RandomSeed;
use std::fmt;

/// Bounds for one in-memory fixture case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixtureLimits {
    /// Maximum artifact count.
    pub max_artifacts: usize,
    /// Maximum UTF-8 bytes in one artifact name.
    pub max_artifact_name_bytes: usize,
    /// Maximum bytes in one artifact.
    pub max_artifact_bytes: usize,
    /// Maximum bytes across all artifact names and contents.
    pub max_total_bytes: usize,
    /// Maximum bytes across textual metadata fields.
    pub max_metadata_bytes: usize,
}

impl FixtureLimits {
    /// Creates explicit finite fixture bounds.
    #[must_use]
    pub const fn new(
        max_artifacts: usize,
        max_artifact_bytes: usize,
        max_total_bytes: usize,
        max_metadata_bytes: usize,
    ) -> Self {
        Self {
            max_artifacts,
            max_artifact_name_bytes: 256,
            max_artifact_bytes,
            max_total_bytes,
            max_metadata_bytes,
        }
    }

    /// A useful finite default for unit and oracle-adapter tests.
    #[must_use]
    pub const fn default_bounded() -> Self {
        Self::new(64, 4 * 1024 * 1024, 16 * 1024 * 1024, 4 * 1024)
    }

    /// Sets the maximum UTF-8 bytes in one artifact name.
    #[must_use]
    pub const fn with_artifact_name_limit(mut self, limit: usize) -> Self {
        self.max_artifact_name_bytes = limit;
        self
    }

    /// Alias emphasizing that the limit is measured in name bytes.
    #[must_use]
    pub const fn with_artifact_name_bytes_limit(self, limit: usize) -> Self {
        self.with_artifact_name_limit(limit)
    }
}

impl Default for FixtureLimits {
    fn default() -> Self {
        Self::default_bounded()
    }
}

/// How a fixture artifact was obtained.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FixtureOrigin {
    /// Authored for this repository rather than copied from upstream.
    Original,
    /// Produced by a named deterministic generator.
    Generated,
    /// Minimized from a recorded failing input.
    Minimized,
    /// Imported from an explicitly licensed external source.
    Imported,
}

impl FixtureOrigin {
    /// Returns the stable manifest spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Original => "original",
            Self::Generated => "generated",
            Self::Minimized => "minimized",
            Self::Imported => "imported",
        }
    }
}

/// Explicit, non-ambient provenance for a fixture case.
#[derive(Clone, PartialEq, Eq)]
pub struct FixtureProvenance {
    origin: FixtureOrigin,
    source: String,
    revision: String,
    author: String,
    license: String,
    retrieved_on: String,
    modification: String,
}

impl fmt::Debug for FixtureProvenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixtureProvenance")
            .field("origin", &self.origin)
            .field("source_bytes", &self.source.len())
            .field("revision_bytes", &self.revision.len())
            .field("author_bytes", &self.author.len())
            .field("license_bytes", &self.license.len())
            .field("retrieved_on_bytes", &self.retrieved_on.len())
            .field("modification_bytes", &self.modification.len())
            .finish()
    }
}

impl FixtureProvenance {
    /// Creates provenance from caller-supplied manifest values.
    #[must_use]
    pub fn new(
        origin: FixtureOrigin,
        source: impl Into<String>,
        revision: impl Into<String>,
        author: impl Into<String>,
        license: impl Into<String>,
        retrieved_on: impl Into<String>,
        modification: impl Into<String>,
    ) -> Self {
        Self {
            origin,
            source: source.into(),
            revision: revision.into(),
            author: author.into(),
            license: license.into(),
            retrieved_on: retrieved_on.into(),
            modification: modification.into(),
        }
    }

    /// Returns deterministic defaults for an original repository fixture.
    #[must_use]
    pub fn original() -> Self {
        Self::new(
            FixtureOrigin::Original,
            "repository",
            "workspace",
            "jmeter-rs",
            "Apache-2.0",
            "not-applicable",
            "original fixture",
        )
    }

    /// Returns the fixture origin.
    #[must_use]
    pub const fn origin(&self) -> FixtureOrigin {
        self.origin
    }

    /// Returns source URL/repository or explicit local source label.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Returns source revision, release, or generator version.
    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }

    /// Returns the declared author or generator.
    #[must_use]
    pub fn author(&self) -> &str {
        &self.author
    }

    /// Returns the declared license expression.
    #[must_use]
    pub fn license(&self) -> &str {
        &self.license
    }

    /// Returns the explicit retrieval date/marker from the manifest.
    #[must_use]
    pub fn retrieved_on(&self) -> &str {
        &self.retrieved_on
    }

    /// Returns the declared transformation/modification note.
    #[must_use]
    pub fn modification(&self) -> &str {
        &self.modification
    }
}

/// Explicit deterministic metadata attached to a fixture case.
#[derive(Clone, PartialEq, Eq)]
pub struct FixtureMetadata {
    profile_id: String,
    fixture_family_id: String,
    case_id: String,
    seed: RandomSeed,
    clock_mode: String,
    locale: String,
    timezone: String,
    charset: String,
    provenance: FixtureProvenance,
}

impl fmt::Debug for FixtureMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixtureMetadata")
            .field("profile_id_bytes", &self.profile_id.len())
            .field("fixture_family_id_bytes", &self.fixture_family_id.len())
            .field("case_id_bytes", &self.case_id.len())
            .field("seed", &self.seed)
            .field("clock_mode_bytes", &self.clock_mode.len())
            .field("locale_bytes", &self.locale.len())
            .field("timezone_bytes", &self.timezone.len())
            .field("charset_bytes", &self.charset.len())
            .field("provenance", &self.provenance)
            .finish()
    }
}

impl FixtureMetadata {
    /// Returns the compatibility profile identifier.
    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    /// Returns the profile fixture-family identifier.
    #[must_use]
    pub fn fixture_family_id(&self) -> &str {
        &self.fixture_family_id
    }

    /// Returns the case identifier.
    #[must_use]
    pub fn case_id(&self) -> &str {
        &self.case_id
    }

    /// Returns the recorded random seed.
    #[must_use]
    pub const fn seed(&self) -> RandomSeed {
        self.seed
    }

    /// Returns the explicit clock mode.
    #[must_use]
    pub fn clock_mode(&self) -> &str {
        &self.clock_mode
    }

    /// Returns the explicit locale.
    #[must_use]
    pub fn locale(&self) -> &str {
        &self.locale
    }

    /// Returns the explicit timezone.
    #[must_use]
    pub fn timezone(&self) -> &str {
        &self.timezone
    }

    /// Returns the explicit default charset.
    #[must_use]
    pub fn charset(&self) -> &str {
        &self.charset
    }

    /// Returns explicit source, license, and transformation provenance.
    #[must_use]
    pub const fn provenance(&self) -> &FixtureProvenance {
        &self.provenance
    }
}

/// One named, ordered fixture artifact.
#[derive(Clone, PartialEq, Eq)]
pub struct FixtureArtifact {
    name: String,
    bytes: Vec<u8>,
}

/// A bounded diagnostic view of a fixture artifact.
///
/// The bytes are intentionally represented only by their length.  Callers
/// that need fixture bytes must request [`FixtureArtifact::bytes`] explicitly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixtureArtifactDiagnostic {
    /// Artifact name retained for fixture correlation.
    pub name: String,
    /// Number of raw bytes in the artifact.
    pub byte_len: usize,
}

impl FixtureArtifact {
    /// Returns an explicit redacted diagnostic projection.
    #[must_use]
    pub fn redacted(&self) -> FixtureArtifactDiagnostic {
        FixtureArtifactDiagnostic {
            name: self.name.clone(),
            byte_len: self.bytes.len(),
        }
    }
}

impl fmt::Debug for FixtureArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.redacted().fmt(formatter)
    }
}

impl FixtureArtifact {
    /// Returns the stable artifact name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns artifact bytes without copying.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns artifact byte length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns UTF-8 bytes in the artifact name.
    #[must_use]
    pub fn name_len(&self) -> usize {
        self.name.len()
    }

    /// Returns whether the artifact has no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Errors returned by bounded fixture construction.
#[derive(Clone, PartialEq, Eq)]
pub enum FixtureError {
    /// A metadata or artifact identifier is empty or contains a NUL byte.
    InvalidMetadata {
        /// Field name that failed validation.
        field: &'static str,
    },
    /// Two artifacts used the same name.
    DuplicateArtifact {
        /// Duplicate artifact name.
        name: String,
    },
    /// One artifact exceeded its byte bound.
    ArtifactTooLarge {
        /// Artifact name.
        name: String,
        /// Actual bytes.
        actual: usize,
        /// Configured bound.
        limit: usize,
    },
    /// One artifact name exceeded its UTF-8 byte bound.
    ArtifactNameTooLarge {
        /// Artifact name.
        name: String,
        /// Actual name bytes.
        actual: usize,
        /// Configured name bound.
        limit: usize,
    },
    /// Artifact count or aggregate name/content byte bound was exceeded.
    CapacityExceeded {
        /// Actual artifact count.
        artifact_count: usize,
        /// Actual total bytes.
        total_bytes: usize,
        /// Configured artifact bound.
        artifact_limit: usize,
        /// Configured total-byte bound.
        total_limit: usize,
    },
    /// Textual metadata exceeded the configured aggregate bound.
    MetadataTooLarge {
        /// Actual metadata bytes.
        actual: usize,
        /// Configured bound.
        limit: usize,
    },
}

impl fmt::Debug for FixtureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("FixtureError");
        match self {
            Self::InvalidMetadata { field } => debug
                .field("kind", &"InvalidMetadata")
                .field("field", field),
            Self::DuplicateArtifact { name } => debug
                .field("kind", &"DuplicateArtifact")
                .field("name_bytes", &name.len()),
            Self::ArtifactTooLarge {
                name,
                actual,
                limit,
            } => debug
                .field("kind", &"ArtifactTooLarge")
                .field("name_bytes", &name.len())
                .field("actual", actual)
                .field("limit", limit),
            Self::ArtifactNameTooLarge {
                name,
                actual,
                limit,
            } => debug
                .field("kind", &"ArtifactNameTooLarge")
                .field("name_bytes", &name.len())
                .field("actual", actual)
                .field("limit", limit),
            Self::CapacityExceeded {
                artifact_count,
                total_bytes,
                artifact_limit,
                total_limit,
            } => debug
                .field("kind", &"CapacityExceeded")
                .field("artifact_count", artifact_count)
                .field("total_bytes", total_bytes)
                .field("artifact_limit", artifact_limit)
                .field("total_limit", total_limit),
            Self::MetadataTooLarge { actual, limit } => debug
                .field("kind", &"MetadataTooLarge")
                .field("actual", actual)
                .field("limit", limit),
        };
        debug.finish()
    }
}

impl FixtureError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::InvalidMetadata { .. } | Self::MetadataTooLarge { .. } => {
                ErrorCode::FixtureInvalidMetadata
            }
            Self::DuplicateArtifact { .. } => ErrorCode::FixtureDuplicateArtifact,
            Self::ArtifactTooLarge { .. } => ErrorCode::FixtureArtifactTooLarge,
            Self::ArtifactNameTooLarge { .. } => ErrorCode::FixtureArtifactNameTooLarge,
            Self::CapacityExceeded { .. } => ErrorCode::FixtureCapacity,
        }
    }
}

impl fmt::Display for FixtureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMetadata { field } => {
                write!(formatter, "{}: invalid metadata field {field}", self.code())
            }
            Self::DuplicateArtifact { name } => {
                write!(formatter, "{}: duplicate artifact {name:?}", self.code())
            }
            Self::ArtifactTooLarge {
                name,
                actual,
                limit,
            } => write!(
                formatter,
                "{}: artifact {name:?} is {actual} bytes, limit {limit}",
                self.code()
            ),
            Self::ArtifactNameTooLarge {
                name,
                actual,
                limit,
            } => write!(
                formatter,
                "{}: artifact name {name:?} is {actual} bytes, limit {limit}",
                self.code()
            ),
            Self::CapacityExceeded {
                artifact_count,
                total_bytes,
                artifact_limit,
                total_limit,
            } => write!(
                formatter,
                "{}: artifacts {artifact_count}/{artifact_limit}, bytes {total_bytes}/{total_limit}",
                self.code()
            ),
            Self::MetadataTooLarge { actual, limit } => write!(
                formatter,
                "{}: metadata bytes {actual} exceed {limit}",
                self.code()
            ),
        }
    }
}

impl std::error::Error for FixtureError {}

impl StableError for FixtureError {
    fn code(&self) -> ErrorCode {
        self.code()
    }
}

/// An immutable fixture case with ordered, bounded artifacts.
#[derive(Clone, PartialEq, Eq)]
pub struct FixtureCase {
    limits: FixtureLimits,
    metadata: FixtureMetadata,
    artifacts: Vec<FixtureArtifact>,
    total_bytes: usize,
}

/// A redacted, bounded diagnostic view of a fixture case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixtureCaseDiagnostic {
    /// Metadata diagnostic summary.
    pub metadata: FixtureMetadataDiagnostic,
    /// Number of ordered artifacts.
    pub artifact_count: usize,
    /// Aggregate raw artifact name/content bytes.
    pub total_bytes: usize,
    /// Redacted artifact summaries.
    pub artifacts: Vec<FixtureArtifactDiagnostic>,
}

/// A redacted diagnostic view of fixture metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixtureMetadataDiagnostic {
    /// Profile identifier byte length.
    pub profile_id_bytes: usize,
    /// Fixture-family identifier byte length.
    pub fixture_family_id_bytes: usize,
    /// Case identifier byte length.
    pub case_id_bytes: usize,
    /// Recorded deterministic seed.
    pub seed: RandomSeed,
}

impl FixtureCase {
    /// Returns an explicit redacted diagnostic projection.
    #[must_use]
    pub fn redacted(&self) -> FixtureCaseDiagnostic {
        FixtureCaseDiagnostic {
            metadata: FixtureMetadataDiagnostic {
                profile_id_bytes: self.metadata.profile_id.len(),
                fixture_family_id_bytes: self.metadata.fixture_family_id.len(),
                case_id_bytes: self.metadata.case_id.len(),
                seed: self.metadata.seed,
            },
            artifact_count: self.artifacts.len(),
            total_bytes: self.total_bytes,
            artifacts: self
                .artifacts
                .iter()
                .map(FixtureArtifact::redacted)
                .collect(),
        }
    }
}

impl fmt::Debug for FixtureCase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.redacted().fmt(formatter)
    }
}

impl FixtureCase {
    /// Returns the fixture limits used at construction.
    #[must_use]
    pub const fn limits(&self) -> FixtureLimits {
        self.limits
    }

    /// Returns deterministic metadata.
    #[must_use]
    pub const fn metadata(&self) -> &FixtureMetadata {
        &self.metadata
    }

    /// Returns ordered artifact entries.
    #[must_use]
    pub fn artifacts(&self) -> &[FixtureArtifact] {
        &self.artifacts
    }

    /// Returns total artifact name and content bytes.
    #[must_use]
    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Finds an artifact by exact name.
    #[must_use]
    pub fn artifact(&self, name: &str) -> Option<&[u8]> {
        self.artifacts
            .iter()
            .find(|artifact| artifact.name == name)
            .map(FixtureArtifact::bytes)
    }

    /// Returns a named artifact entry.
    #[must_use]
    pub fn artifact_entry(&self, name: &str) -> Option<&FixtureArtifact> {
        self.artifacts.iter().find(|artifact| artifact.name == name)
    }

    /// Returns a deterministic non-cryptographic fingerprint of metadata and
    /// ordered bytes.  Use a pinned digest outside this crate when integrity,
    /// rather than fixture identity, is required.
    #[must_use]
    pub fn fingerprint(&self) -> u64 {
        let mut hash = 0xcbf2_9ce4_8422_2325_u64;
        for field in [
            self.metadata.profile_id.as_bytes(),
            self.metadata.fixture_family_id.as_bytes(),
            self.metadata.case_id.as_bytes(),
            self.metadata.clock_mode.as_bytes(),
            self.metadata.locale.as_bytes(),
            self.metadata.timezone.as_bytes(),
            self.metadata.charset.as_bytes(),
            self.metadata.provenance.origin.as_str().as_bytes(),
            self.metadata.provenance.source.as_bytes(),
            self.metadata.provenance.revision.as_bytes(),
            self.metadata.provenance.author.as_bytes(),
            self.metadata.provenance.license.as_bytes(),
            self.metadata.provenance.retrieved_on.as_bytes(),
            self.metadata.provenance.modification.as_bytes(),
            &self.metadata.seed.value().to_le_bytes(),
        ] {
            hash_bytes(&mut hash, field);
        }
        for artifact in &self.artifacts {
            hash_bytes(&mut hash, artifact.name.as_bytes());
            hash_bytes(&mut hash, &artifact.bytes);
        }
        hash
    }
}

/// Builder for an offline, deterministic fixture case.
#[derive(Clone)]
pub struct FixtureCaseBuilder {
    limits: FixtureLimits,
    profile_id: String,
    fixture_family_id: String,
    case_id: String,
    seed: RandomSeed,
    clock_mode: String,
    locale: String,
    timezone: String,
    charset: String,
    provenance: FixtureProvenance,
    artifacts: Vec<FixtureArtifact>,
    total_bytes: usize,
    pending_error: Option<FixtureError>,
}

impl fmt::Debug for FixtureCaseBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixtureCaseBuilder")
            .field("profile_id_bytes", &self.profile_id.len())
            .field("fixture_family_id_bytes", &self.fixture_family_id.len())
            .field("case_id_bytes", &self.case_id.len())
            .field("artifact_count", &self.artifacts.len())
            .field("total_bytes", &self.total_bytes)
            .field("pending_error", &self.pending_error)
            .finish()
    }
}

impl FixtureCaseBuilder {
    /// Starts a fixture with explicit case identity and deterministic defaults.
    #[must_use]
    pub fn new(case_id: impl Into<String>) -> Self {
        Self {
            limits: FixtureLimits::default(),
            profile_id: "test".to_owned(),
            fixture_family_id: "local".to_owned(),
            case_id: case_id.into(),
            seed: RandomSeed::new(0),
            clock_mode: "virtual".to_owned(),
            locale: "en-US".to_owned(),
            timezone: "UTC".to_owned(),
            charset: "UTF-8".to_owned(),
            provenance: FixtureProvenance::original(),
            artifacts: Vec::new(),
            total_bytes: 0,
            pending_error: None,
        }
    }

    /// Starts a fixture with explicit identity and bounds.
    #[must_use]
    pub fn with_limits(case_id: impl Into<String>, limits: FixtureLimits) -> Self {
        let mut builder = Self::new(case_id);
        builder.limits = limits;
        builder
    }

    /// Sets the compatibility profile identifier.
    #[must_use]
    pub fn profile_id(mut self, profile_id: impl Into<String>) -> Self {
        self.profile_id = profile_id.into();
        self
    }

    /// Alias for [`Self::profile_id`].
    #[must_use]
    pub fn profile(self, profile_id: impl Into<String>) -> Self {
        self.profile_id(profile_id)
    }

    /// Sets the profile fixture-family identifier.
    #[must_use]
    pub fn fixture_family_id(mut self, fixture_family_id: impl Into<String>) -> Self {
        self.fixture_family_id = fixture_family_id.into();
        self
    }

    /// Alias for [`Self::fixture_family_id`].
    #[must_use]
    pub fn fixture_family(self, fixture_family_id: impl Into<String>) -> Self {
        self.fixture_family_id(fixture_family_id)
    }

    /// Replaces the case identifier.
    #[must_use]
    pub fn case_id(mut self, case_id: impl Into<String>) -> Self {
        self.case_id = case_id.into();
        self
    }

    /// Sets the recorded random seed.
    #[must_use]
    pub fn seed(mut self, seed: impl Into<RandomSeed>) -> Self {
        self.seed = seed.into();
        self
    }

    /// Sets the explicit clock mode.
    #[must_use]
    pub fn clock_mode(mut self, clock_mode: impl Into<String>) -> Self {
        self.clock_mode = clock_mode.into();
        self
    }

    /// Sets explicit source/license/transformation provenance.
    #[must_use]
    pub fn provenance(mut self, provenance: FixtureProvenance) -> Self {
        self.provenance = provenance;
        self
    }

    /// Sets locale, timezone, and charset together.
    #[must_use]
    pub fn environment(
        mut self,
        locale: impl Into<String>,
        timezone: impl Into<String>,
        charset: impl Into<String>,
    ) -> Self {
        self.locale = locale.into();
        self.timezone = timezone.into();
        self.charset = charset.into();
        self
    }

    /// Adds an artifact, recording an error for [`Self::build`] while keeping
    /// builder-style chains ergonomic.
    #[must_use]
    pub fn artifact(mut self, name: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Self {
        if self.pending_error.is_none()
            && let Err(error) = self.try_add_artifact(name.into(), bytes.into())
        {
            self.pending_error = Some(error);
        }
        self
    }

    /// Adds an artifact and returns setup errors immediately.
    pub fn try_artifact(
        self,
        name: impl Into<String>,
        bytes: impl Into<Vec<u8>>,
    ) -> Result<Self, FixtureError> {
        let mut builder = self;
        builder.try_add_artifact(name.into(), bytes.into())?;
        Ok(builder)
    }

    /// Alias for [`Self::try_artifact`].
    pub fn add_artifact(
        self,
        name: impl Into<String>,
        bytes: impl Into<Vec<u8>>,
    ) -> Result<Self, FixtureError> {
        self.try_artifact(name, bytes)
    }

    /// Alias emphasizing that an artifact is an expected output.
    #[must_use]
    pub fn expected(self, name: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Self {
        self.artifact(name, bytes)
    }

    /// Builds the immutable case after validating all metadata and bounds.
    pub fn build(self) -> Result<FixtureCase, FixtureError> {
        if let Some(error) = self.pending_error {
            return Err(error);
        }
        validate_identifier("profile_id", &self.profile_id)?;
        validate_identifier("fixture_family_id", &self.fixture_family_id)?;
        validate_identifier("case_id", &self.case_id)?;
        validate_identifier("clock_mode", &self.clock_mode)?;
        validate_identifier("locale", &self.locale)?;
        validate_identifier("timezone", &self.timezone)?;
        validate_identifier("charset", &self.charset)?;
        for (field, value) in [
            ("provenance_source", self.provenance.source.as_str()),
            ("provenance_revision", self.provenance.revision.as_str()),
            ("provenance_author", self.provenance.author.as_str()),
            ("provenance_license", self.provenance.license.as_str()),
            (
                "provenance_retrieved_on",
                self.provenance.retrieved_on.as_str(),
            ),
            (
                "provenance_modification",
                self.provenance.modification.as_str(),
            ),
        ] {
            validate_metadata_text(field, value)?;
        }
        let metadata_bytes = [
            self.profile_id.len(),
            self.fixture_family_id.len(),
            self.case_id.len(),
            self.clock_mode.len(),
            self.locale.len(),
            self.timezone.len(),
            self.charset.len(),
            self.provenance.source.len(),
            self.provenance.revision.len(),
            self.provenance.author.len(),
            self.provenance.license.len(),
            self.provenance.retrieved_on.len(),
            self.provenance.modification.len(),
        ]
        .into_iter()
        .try_fold(0_usize, usize::checked_add)
        .ok_or(FixtureError::MetadataTooLarge {
            actual: usize::MAX,
            limit: self.limits.max_metadata_bytes,
        })?;
        if metadata_bytes > self.limits.max_metadata_bytes {
            return Err(FixtureError::MetadataTooLarge {
                actual: metadata_bytes,
                limit: self.limits.max_metadata_bytes,
            });
        }
        Ok(FixtureCase {
            limits: self.limits,
            metadata: FixtureMetadata {
                profile_id: self.profile_id,
                fixture_family_id: self.fixture_family_id,
                case_id: self.case_id,
                seed: self.seed,
                clock_mode: self.clock_mode,
                locale: self.locale,
                timezone: self.timezone,
                charset: self.charset,
                provenance: self.provenance,
            },
            artifacts: self.artifacts,
            total_bytes: self.total_bytes,
        })
    }

    fn try_add_artifact(&mut self, name: String, bytes: Vec<u8>) -> Result<(), FixtureError> {
        validate_identifier("artifact_name", &name)?;
        if self.artifacts.iter().any(|artifact| artifact.name == name) {
            return Err(FixtureError::DuplicateArtifact { name });
        }
        let name_bytes = name.len();
        if name_bytes > self.limits.max_artifact_name_bytes {
            return Err(FixtureError::ArtifactNameTooLarge {
                name,
                actual: name_bytes,
                limit: self.limits.max_artifact_name_bytes,
            });
        }
        if bytes.len() > self.limits.max_artifact_bytes {
            return Err(FixtureError::ArtifactTooLarge {
                name,
                actual: bytes.len(),
                limit: self.limits.max_artifact_bytes,
            });
        }
        let artifact_count = self.artifacts.len().saturating_add(1);
        let artifact_bytes =
            name_bytes
                .checked_add(bytes.len())
                .ok_or(FixtureError::CapacityExceeded {
                    artifact_count,
                    total_bytes: usize::MAX,
                    artifact_limit: self.limits.max_artifacts,
                    total_limit: self.limits.max_total_bytes,
                })?;
        let total_bytes =
            self.total_bytes
                .checked_add(artifact_bytes)
                .ok_or(FixtureError::CapacityExceeded {
                    artifact_count,
                    total_bytes: usize::MAX,
                    artifact_limit: self.limits.max_artifacts,
                    total_limit: self.limits.max_total_bytes,
                })?;
        if artifact_count > self.limits.max_artifacts || total_bytes > self.limits.max_total_bytes {
            return Err(FixtureError::CapacityExceeded {
                artifact_count,
                total_bytes,
                artifact_limit: self.limits.max_artifacts,
                total_limit: self.limits.max_total_bytes,
            });
        }
        self.artifacts.push(FixtureArtifact { name, bytes });
        self.total_bytes = total_bytes;
        Ok(())
    }
}

/// Short alias for the fixture-case builder.
pub type FixtureBuilder = FixtureCaseBuilder;

fn validate_identifier(field: &'static str, value: &str) -> Result<(), FixtureError> {
    if value.is_empty()
        || value == "."
        || value.contains("..")
        || value.starts_with(['/', '\\'])
        || value
            .as_bytes()
            .windows(2)
            .any(|window| window == *b"/\\" || window == *b"\\/")
        || value.contains('/')
        || value.contains('\\')
        || value
            .chars()
            .any(|character| character.is_control() || matches!(character, '\u{2028}' | '\u{2029}'))
        || value.as_bytes().get(1) == Some(&b':')
            && value
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic)
    {
        Err(FixtureError::InvalidMetadata { field })
    } else {
        Ok(())
    }
}

fn validate_metadata_text(field: &'static str, value: &str) -> Result<(), FixtureError> {
    if value.is_empty()
        || value
            .chars()
            .any(|character| character.is_control() || matches!(character, '\u{2028}' | '\u{2029}'))
    {
        Err(FixtureError::InvalidMetadata { field })
    } else {
        Ok(())
    }
}

fn hash_bytes(hash: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *hash ^= u64::from(*byte);
        *hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    *hash ^= 0xff;
    *hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn builder_preserves_metadata_order_and_artifact_bytes() {
        let fixture = FixtureBuilder::new("case-0")
            .profile("jmeter-5.6.3")
            .fixture_family("FX-TEST")
            .seed(41_u64)
            .artifact("plan.jmx", b"<test/>".to_vec())
            .expected("expected.jtl", b"sample".to_vec())
            .build()
            .unwrap();
        assert_eq!(fixture.metadata().profile_id(), "jmeter-5.6.3");
        assert_eq!(fixture.metadata().fixture_family_id(), "FX-TEST");
        assert_eq!(fixture.metadata().seed().value(), 41);
        assert_eq!(fixture.artifact("plan.jmx"), Some(b"<test/>".as_slice()));
        assert_eq!(fixture.artifacts()[1].name(), "expected.jtl");
        assert_ne!(fixture.fingerprint(), 0);
    }

    #[test]
    fn duplicate_and_oversized_artifacts_are_rejected_without_partial_add() {
        let limits = FixtureLimits::new(2, 3, 12, 64);
        let builder = FixtureBuilder::with_limits("case", limits)
            .artifact("one", b"123".to_vec())
            .artifact("one", b"x".to_vec());
        assert_eq!(
            builder.build().unwrap_err().code(),
            ErrorCode::FixtureDuplicateArtifact
        );

        let error = FixtureBuilder::with_limits("case", limits)
            .try_artifact("large", b"1234".to_vec())
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::FixtureArtifactTooLarge);
    }

    #[test]
    fn total_and_metadata_bounds_are_checked() {
        let limits = FixtureLimits::new(2, 4, 4, 4);
        let builder = FixtureBuilder::with_limits("case", limits)
            .artifact("a", b"12".to_vec())
            .artifact("b", b"34".to_vec())
            .artifact("c", b"".to_vec());
        assert_eq!(
            builder.build().unwrap_err().code(),
            ErrorCode::FixtureCapacity
        );

        let error = FixtureBuilder::with_limits("case", FixtureLimits::new(1, 4, 4, 1))
            .build()
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::FixtureInvalidMetadata);
    }

    #[test]
    fn artifact_names_are_bounded_and_counted_in_total_bytes() {
        let limits = FixtureLimits::new(2, 8, 4, 128).with_artifact_name_limit(3);
        let fixture = FixtureBuilder::with_limits("case", limits)
            .artifact("abc", b"x".to_vec())
            .build()
            .unwrap();
        assert_eq!(fixture.total_bytes(), 4);
        assert_eq!(fixture.artifacts()[0].name_len(), 3);

        let error = FixtureBuilder::with_limits("case", limits)
            .try_artifact("abcd", b"".to_vec())
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::FixtureArtifactNameTooLarge);

        let error = FixtureBuilder::with_limits("case", limits)
            .try_artifact("abc", b"xy".to_vec())
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::FixtureCapacity);

        let count_limited = FixtureLimits::new(1, 8, 32, 128);
        let error = FixtureBuilder::with_limits("case", count_limited)
            .artifact("one", b"".to_vec())
            .try_artifact("two", b"".to_vec())
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::FixtureCapacity);
    }

    #[test]
    fn empty_and_nul_fixture_identifiers_are_rejected() {
        let cases = [
            ("case_id", FixtureBuilder::new("")),
            ("profile_id", FixtureBuilder::new("case").profile("")),
            (
                "fixture_family_id",
                FixtureBuilder::new("case").fixture_family(""),
            ),
            ("clock_mode", FixtureBuilder::new("case").clock_mode("")),
            (
                "locale",
                FixtureBuilder::new("case").environment("", "UTC", "UTF-8"),
            ),
            (
                "timezone",
                FixtureBuilder::new("case").environment("en-US", "", "UTF-8"),
            ),
            (
                "charset",
                FixtureBuilder::new("case").environment("en-US", "UTC", ""),
            ),
            ("case_id", FixtureBuilder::new("nul\0case")),
            (
                "profile_id",
                FixtureBuilder::new("case").profile("nul\0profile"),
            ),
            (
                "fixture_family_id",
                FixtureBuilder::new("case").fixture_family("nul\0family"),
            ),
            (
                "clock_mode",
                FixtureBuilder::new("case").clock_mode("nul\0clock"),
            ),
            (
                "locale",
                FixtureBuilder::new("case").environment("nul\0locale", "UTC", "UTF-8"),
            ),
        ];
        for (field, builder) in cases {
            let error = builder.build().unwrap_err();
            assert!(matches!(
                error,
                FixtureError::InvalidMetadata { field: actual } if actual == field
            ));
        }

        for name in ["", "nul\0artifact"] {
            let error = FixtureBuilder::new("case")
                .try_artifact(name, Vec::new())
                .unwrap_err();
            assert!(matches!(
                error,
                FixtureError::InvalidMetadata {
                    field: "artifact_name"
                }
            ));
        }
    }

    #[test]
    fn provenance_is_explicit_and_part_of_fixture_identity() {
        let original = FixtureBuilder::new("case")
            .artifact("fixture", b"bytes".to_vec())
            .build()
            .unwrap();
        assert_eq!(
            original.metadata().provenance().origin(),
            FixtureOrigin::Original
        );
        assert_eq!(
            original.metadata().provenance().retrieved_on(),
            "not-applicable"
        );

        let imported = FixtureBuilder::new("case")
            .provenance(FixtureProvenance::new(
                FixtureOrigin::Imported,
                "local-license-record",
                "revision-1",
                "fixture-author",
                "Apache-2.0",
                "2026-08-12",
                "normalized line endings",
            ))
            .artifact("fixture", b"bytes".to_vec())
            .build()
            .unwrap();
        assert_eq!(
            imported.metadata().provenance().origin(),
            FixtureOrigin::Imported
        );
        assert_ne!(original.fingerprint(), imported.fingerprint());
    }

    #[test]
    fn portable_identifiers_reject_paths_drives_dotdot_and_controls() {
        for value in [
            "/absolute",
            "\\\\server\\share",
            "nested/name",
            "nested\\name",
            "..",
            "C:relative",
            "line\nfeed",
            "line\u{2028}separator",
            "tab\tvalue",
            "nul\0value",
        ] {
            let error = FixtureBuilder::new(value).build().unwrap_err();
            assert!(matches!(
                error,
                FixtureError::InvalidMetadata { field: "case_id" }
            ));
        }
        for value in [
            "/absolute",
            "nested/name",
            "nested\\name",
            ".",
            "..",
            "C:foo",
        ] {
            let error = FixtureBuilder::new("case")
                .try_artifact(value, b"secret-body".to_vec())
                .unwrap_err();
            assert_eq!(error.code(), ErrorCode::FixtureInvalidMetadata);
        }
    }

    #[test]
    fn fixture_debug_is_redacted_but_raw_bytes_remain_explicit() {
        let fixture = FixtureBuilder::new("case")
            .artifact("artifact", b"fixture-secret".to_vec())
            .build()
            .unwrap();
        let output = format!("{fixture:?}");
        assert!(!output.contains("fixture-secret"));
        assert!(output.contains("byte_len"));
        assert_eq!(
            fixture.artifact("artifact"),
            Some(b"fixture-secret".as_slice())
        );
    }
}
