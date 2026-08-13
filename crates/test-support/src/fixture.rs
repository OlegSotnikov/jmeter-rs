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
use std::path::{Component, Path, PathBuf};

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

/// A SHA-256 digest used to identify fixture bytes without retaining their
/// contents in diagnostics.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FixtureDigest([u8; 32]);

impl FixtureDigest {
    /// The number of bytes in a SHA-256 digest.
    pub const BYTE_LEN: usize = 32;

    /// Computes SHA-256 over a bounded byte slice.
    #[must_use]
    pub fn sha256(bytes: &[u8]) -> Self {
        Self(sha256_bytes(bytes))
    }

    /// Constructs a digest from its raw 32-byte representation.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw digest bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Returns lowercase hexadecimal without consulting locale or process
    /// state.
    #[must_use]
    pub fn to_hex(self) -> String {
        let mut output = String::with_capacity(64);
        for byte in self.0 {
            output.push(HEX[(byte >> 4) as usize]);
            output.push(HEX[(byte & 0x0f) as usize]);
        }
        output
    }
}

impl fmt::Debug for FixtureDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("FixtureDigest")
            .field(&self.to_hex())
            .finish()
    }
}

impl fmt::Display for FixtureDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

const HEX: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

/// Errors reported by an injected fixture filesystem.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixtureFilesystemError {
    /// The requested path does not exist.
    NotFound,
    /// The adapter refused access.
    PermissionDenied,
    /// The adapter could not resolve the path.
    InvalidPath,
    /// The requested file exceeds the supplied read bound.
    TooLarge,
    /// The adapter is unavailable.
    Unavailable,
}

impl FixtureFilesystemError {
    /// Returns the stable adapter failure spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not-found",
            Self::PermissionDenied => "permission-denied",
            Self::InvalidPath => "invalid-path",
            Self::TooLarge => "too-large",
            Self::Unavailable => "unavailable",
        }
    }
}

impl fmt::Display for FixtureFilesystemError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotFound => "fixture file not found",
            Self::PermissionDenied => "fixture file access denied",
            Self::InvalidPath => "fixture path could not be resolved",
            Self::TooLarge => "fixture file exceeds the read bound",
            Self::Unavailable => "fixture filesystem unavailable",
        })
    }
}

impl std::error::Error for FixtureFilesystemError {}

/// Explicit filesystem capability used by local fixture loading.
pub trait FixtureFilesystem {
    /// Resolves symlinks/junctions using the adapter's explicit filesystem.
    fn canonicalize(&self, path: &Path) -> Result<PathBuf, FixtureFilesystemError>;

    /// Reads one file while enforcing the supplied byte bound.
    fn read_bounded(
        &self,
        path: &Path,
        max_bytes: usize,
    ) -> Result<Vec<u8>, FixtureFilesystemError>;
}

/// Validates and normalizes a relative fixture path without touching the
/// filesystem. Parent traversal, roots, drive prefixes, controls, and
/// non-UTF-8 names are rejected for cross-platform manifest stability.
pub fn validate_fixture_relative_path(path: &Path) -> Result<PathBuf, FixtureError> {
    if path.to_str().is_some_and(|value| {
        value.contains('\\')
            || (value.as_bytes().get(1) == Some(&b':')
                && value
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphabetic))
    }) {
        return Err(FixtureError::InvalidMetadata {
            field: "artifact_path",
        });
    }
    let mut normalized = PathBuf::new();
    let mut saw_component = false;
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                let text = part.to_str().ok_or(FixtureError::InvalidMetadata {
                    field: "artifact_path",
                })?;
                if text.is_empty()
                    || text.contains('\\')
                    || text.chars().any(|character| {
                        character.is_control() || matches!(character, '\u{2028}' | '\u{2029}')
                    })
                {
                    return Err(FixtureError::InvalidMetadata {
                        field: "artifact_path",
                    });
                }
                saw_component = true;
                normalized.push(part);
            }
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => {
                return Err(FixtureError::InvalidMetadata {
                    field: "artifact_path",
                });
            }
        }
    }
    saw_component
        .then_some(normalized)
        .ok_or(FixtureError::InvalidMetadata {
            field: "artifact_path",
        })
}

/// Resolves a relative fixture path beneath an explicit absolute root using
/// lexical checks only. Use the builder filesystem loader when symlink or
/// junction containment must also be checked.
pub fn resolve_fixture_path(root: &Path, relative: &Path) -> Result<PathBuf, FixtureError> {
    if !root.is_absolute() {
        return Err(FixtureError::InvalidMetadata {
            field: "fixture_root",
        });
    }
    Ok(root.join(validate_fixture_relative_path(relative)?))
}

fn is_strictly_contained(root: &Path, candidate: &Path) -> bool {
    candidate
        .strip_prefix(root)
        .ok()
        .is_some_and(|suffix| suffix.components().next().is_some())
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
    digest: FixtureDigest,
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
    /// SHA-256 of the raw artifact bytes.
    pub sha256: FixtureDigest,
}

impl FixtureArtifact {
    /// Returns an explicit redacted diagnostic projection.
    #[must_use]
    pub fn redacted(&self) -> FixtureArtifactDiagnostic {
        FixtureArtifactDiagnostic {
            name: self.name.clone(),
            byte_len: self.bytes.len(),
            sha256: self.digest,
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

    /// Returns the SHA-256 of the raw artifact bytes.
    #[must_use]
    pub const fn sha256(&self) -> FixtureDigest {
        self.digest
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
    /// The resolved artifact path was not contained by the canonical root.
    OutsideRoot,
    /// The injected filesystem rejected a bounded read or canonicalization.
    Filesystem {
        /// Stable adapter-level failure category.
        kind: FixtureFilesystemError,
    },
    /// Artifact bytes did not match the manifest's expected digest.
    DigestMismatch {
        /// Artifact name, retained only for local assertion context.
        name: String,
        /// Digest declared by the manifest.
        expected: FixtureDigest,
        /// Digest observed from the injected filesystem.
        actual: FixtureDigest,
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
            Self::OutsideRoot => debug.field("kind", &"OutsideRoot"),
            Self::Filesystem { kind } => debug
                .field("kind", &"Filesystem")
                .field("filesystem_kind", kind),
            Self::DigestMismatch {
                name,
                expected,
                actual,
            } => debug
                .field("kind", &"DigestMismatch")
                .field("name_bytes", &name.len())
                .field("expected", expected)
                .field("actual", actual),
        };
        debug.finish()
    }
}

impl FixtureError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::InvalidMetadata { .. }
            | Self::MetadataTooLarge { .. }
            | Self::OutsideRoot
            | Self::Filesystem { .. }
            | Self::DigestMismatch { .. } => ErrorCode::FixtureInvalidMetadata,
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
            Self::OutsideRoot => write!(
                formatter,
                "{}: fixture path is outside its root",
                self.code()
            ),
            Self::Filesystem { kind } => write!(formatter, "{}: {kind}", self.code()),
            Self::DigestMismatch {
                name,
                expected,
                actual,
            } => write!(
                formatter,
                "{}: artifact {name:?} digest {actual} does not match {expected}",
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

    /// Returns the SHA-256 identity of the complete bounded fixture manifest.
    ///
    /// Fields are length-prefixed in insertion order, so adjacent strings,
    /// artifact names, and artifact bytes cannot become ambiguous.  The
    /// digest is suitable for provenance references; it is not a substitute
    /// for a signed upstream artifact digest.
    #[must_use]
    pub fn manifest_digest(&self) -> FixtureDigest {
        let mut encoded = Vec::with_capacity(self.total_bytes.saturating_add(512));
        encoded.extend_from_slice(b"jmeter-rs/fixture-manifest/1\0");
        for limit in [
            self.limits.max_artifacts,
            self.limits.max_artifact_name_bytes,
            self.limits.max_artifact_bytes,
            self.limits.max_total_bytes,
            self.limits.max_metadata_bytes,
        ] {
            append_digest_field(&mut encoded, &limit.to_le_bytes());
        }
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
            append_digest_field(&mut encoded, field);
        }
        append_digest_field(&mut encoded, &(self.artifacts.len() as u64).to_le_bytes());
        for artifact in &self.artifacts {
            append_digest_field(&mut encoded, artifact.name.as_bytes());
            append_digest_field(&mut encoded, &artifact.bytes);
        }
        FixtureDigest::sha256(&encoded)
    }

    /// Alias for [`Self::manifest_digest`].
    #[must_use]
    pub fn sha256(&self) -> FixtureDigest {
        self.manifest_digest()
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

    /// Reads one artifact through an explicit, injected filesystem.
    ///
    /// The root must be absolute. Both root and candidate are canonicalized by
    /// the adapter before containment is checked, so symlinks/junctions that
    /// escape the declared root are rejected. The adapter receives the
    /// canonical candidate and the configured per-artifact byte limit.
    pub fn artifact_from_filesystem<F: FixtureFilesystem>(
        self,
        name: impl Into<String>,
        root: &Path,
        relative: &Path,
        filesystem: &F,
    ) -> Result<Self, FixtureError> {
        self.artifact_from_filesystem_checked(name, root, relative, filesystem, None)
    }

    /// Reads one artifact and checks its bytes against an expected SHA-256.
    pub fn artifact_from_filesystem_with_digest<F: FixtureFilesystem>(
        self,
        name: impl Into<String>,
        root: &Path,
        relative: &Path,
        filesystem: &F,
        expected: FixtureDigest,
    ) -> Result<Self, FixtureError> {
        self.artifact_from_filesystem_checked(name, root, relative, filesystem, Some(expected))
    }

    /// Alias for [`Self::artifact_from_filesystem`].
    pub fn artifact_from_path<F: FixtureFilesystem>(
        self,
        name: impl Into<String>,
        root: &Path,
        relative: &Path,
        filesystem: &F,
    ) -> Result<Self, FixtureError> {
        self.artifact_from_filesystem(name, root, relative, filesystem)
    }

    fn artifact_from_filesystem_checked<F: FixtureFilesystem>(
        self,
        name: impl Into<String>,
        root: &Path,
        relative: &Path,
        filesystem: &F,
        expected: Option<FixtureDigest>,
    ) -> Result<Self, FixtureError> {
        let name = name.into();
        validate_identifier("artifact_name", &name)?;
        if self.artifacts.iter().any(|artifact| artifact.name == name) {
            return Err(FixtureError::DuplicateArtifact { name });
        }
        if name.len() > self.limits.max_artifact_name_bytes {
            let actual = name.len();
            return Err(FixtureError::ArtifactNameTooLarge {
                name,
                actual,
                limit: self.limits.max_artifact_name_bytes,
            });
        }
        let candidate = resolve_fixture_path(root, relative)?;
        let canonical_root = filesystem
            .canonicalize(root)
            .map_err(|kind| FixtureError::Filesystem { kind })?;
        let canonical_candidate = filesystem
            .canonicalize(&candidate)
            .map_err(|kind| FixtureError::Filesystem { kind })?;
        if !canonical_root.is_absolute()
            || !canonical_candidate.is_absolute()
            || !is_strictly_contained(&canonical_root, &canonical_candidate)
        {
            return Err(FixtureError::OutsideRoot);
        }
        let bytes = filesystem
            .read_bounded(&canonical_candidate, self.limits.max_artifact_bytes)
            .map_err(|kind| FixtureError::Filesystem { kind })?;
        if bytes.len() > self.limits.max_artifact_bytes {
            return Err(FixtureError::ArtifactTooLarge {
                name,
                actual: bytes.len(),
                limit: self.limits.max_artifact_bytes,
            });
        }
        if let Some(expected) = expected {
            let actual = FixtureDigest::sha256(&bytes);
            if actual != expected {
                return Err(FixtureError::DigestMismatch {
                    name: name.clone(),
                    expected,
                    actual,
                });
            }
        }
        self.try_artifact(name, bytes)
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
        let digest = FixtureDigest::sha256(&bytes);
        self.artifacts.push(FixtureArtifact {
            name,
            bytes,
            digest,
        });
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

fn append_digest_field(encoded: &mut Vec<u8>, value: &[u8]) {
    encoded.extend_from_slice(&(value.len() as u64).to_le_bytes());
    encoded.extend_from_slice(value);
}

// SHA-256 is kept here instead of adding a dependency to the std-only
// test-support crate. The implementation follows FIPS 180-4's padded,
// big-endian 512-bit block schedule and is exercised against published test
// vectors below.
fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut state = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    let mut block = [0_u8; 64];
    let mut used = 0_usize;
    for byte in bytes {
        block[used] = *byte;
        used += 1;
        if used == block.len() {
            sha256_compress(&mut state, &block);
            used = 0;
        }
    }

    block[used] = 0x80;
    used += 1;
    if used > 56 {
        block[used..].fill(0);
        sha256_compress(&mut state, &block);
        block.fill(0);
    } else {
        block[used..56].fill(0);
    }
    let bit_len = (bytes.len() as u64).wrapping_mul(8);
    block[56..].copy_from_slice(&bit_len.to_be_bytes());
    sha256_compress(&mut state, &block);

    let mut digest = [0_u8; 32];
    for (index, word) in state.into_iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

fn sha256_compress(state: &mut [u32; 8], block: &[u8; 64]) {
    const ROUND_CONSTANTS: [u32; 64] = [
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
    let mut schedule = [0_u32; 64];
    for (index, word) in schedule.iter_mut().enumerate().take(16) {
        let offset = index * 4;
        *word = u32::from_be_bytes([
            block[offset],
            block[offset + 1],
            block[offset + 2],
            block[offset + 3],
        ]);
    }
    for index in 16..64 {
        let lower = schedule[index - 15];
        let upper = schedule[index - 2];
        let sigma0 = lower.rotate_right(7) ^ lower.rotate_right(18) ^ (lower >> 3);
        let sigma1 = upper.rotate_right(17) ^ upper.rotate_right(19) ^ (upper >> 10);
        schedule[index] = schedule[index - 16]
            .wrapping_add(sigma0)
            .wrapping_add(schedule[index - 7])
            .wrapping_add(sigma1);
    }

    let mut working = *state;
    for index in 0..64 {
        let [a, b, c, d, e, f, g, h] = working;
        let sigma1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let choose = (e & f) ^ ((!e) & g);
        let temporary1 = h
            .wrapping_add(sigma1)
            .wrapping_add(choose)
            .wrapping_add(ROUND_CONSTANTS[index])
            .wrapping_add(schedule[index]);
        let sigma0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let temporary2 = sigma0.wrapping_add(majority);
        working = [
            temporary1.wrapping_add(temporary2),
            a,
            b,
            c,
            d.wrapping_add(temporary1),
            e,
            f,
            g,
        ];
    }
    for (state_word, working_word) in state.iter_mut().zip(working) {
        *state_word = state_word.wrapping_add(working_word);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    struct MemoryFilesystem {
        root: PathBuf,
        files: Vec<(PathBuf, Vec<u8>)>,
        escaped: PathBuf,
    }

    impl FixtureFilesystem for MemoryFilesystem {
        fn canonicalize(&self, path: &Path) -> Result<PathBuf, FixtureFilesystemError> {
            if path == self.root {
                return Ok(self.root.clone());
            }
            if path == self.root.join("escape.jmx") {
                return Ok(self.escaped.clone());
            }
            if self.files.iter().any(|(file, _)| file == path) {
                return Ok(path.to_owned());
            }
            Err(FixtureFilesystemError::NotFound)
        }

        fn read_bounded(
            &self,
            path: &Path,
            max_bytes: usize,
        ) -> Result<Vec<u8>, FixtureFilesystemError> {
            let Some((_, bytes)) = self.files.iter().find(|(file, _)| file == path) else {
                return Err(FixtureFilesystemError::NotFound);
            };
            if bytes.len() > max_bytes {
                return Err(FixtureFilesystemError::TooLarge);
            }
            Ok(bytes.clone())
        }
    }

    fn memory_root() -> PathBuf {
        #[cfg(windows)]
        {
            PathBuf::from(r"C:\fixture-root")
        }
        #[cfg(not(windows))]
        {
            PathBuf::from("/fixture-root")
        }
    }

    fn memory_filesystem() -> MemoryFilesystem {
        let root = memory_root();
        MemoryFilesystem {
            files: vec![(root.join("plan.jmx"), b"<test/>".to_vec())],
            escaped: {
                #[cfg(windows)]
                {
                    PathBuf::from(r"C:\outside\secret.jmx")
                }
                #[cfg(not(windows))]
                {
                    PathBuf::from("/outside/secret.jmx")
                }
            },
            root,
        }
    }

    #[test]
    fn sha256_uses_published_vectors_and_fixed_hex() {
        assert_eq!(
            FixtureDigest::sha256(b"").to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            FixtureDigest::sha256(b"abc").to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            FixtureDigest::sha256(&vec![b'a'; 1_000]).to_hex(),
            "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"
        );
        assert_eq!(
            FixtureDigest::sha256(b"abc").as_bytes().len(),
            FixtureDigest::BYTE_LEN
        );
    }

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
        assert_eq!(
            fixture.artifact_entry("artifact").unwrap().sha256(),
            FixtureDigest::sha256(b"fixture-secret")
        );
        assert_eq!(
            fixture
                .artifact_entry("artifact")
                .unwrap()
                .redacted()
                .sha256,
            FixtureDigest::sha256(b"fixture-secret")
        );
    }

    #[test]
    fn manifest_digest_is_ordered_and_changes_on_provenance_or_bytes() {
        let first = FixtureBuilder::new("case")
            .artifact("one", b"1".to_vec())
            .artifact("two", b"2".to_vec())
            .build()
            .unwrap();
        let reordered = FixtureBuilder::new("case")
            .artifact("two", b"2".to_vec())
            .artifact("one", b"1".to_vec())
            .build()
            .unwrap();
        let changed = FixtureBuilder::new("case")
            .artifact("one", b"changed".to_vec())
            .artifact("two", b"2".to_vec())
            .build()
            .unwrap();
        assert_ne!(first.manifest_digest(), reordered.manifest_digest());
        assert_ne!(first.manifest_digest(), changed.manifest_digest());
        assert_eq!(first.manifest_digest(), first.sha256());
    }

    #[test]
    fn injected_filesystem_requires_absolute_root_and_canonical_containment() {
        let filesystem = memory_filesystem();
        let root = memory_root();
        let fixture = FixtureBuilder::new("case")
            .artifact_from_filesystem_with_digest(
                "plan",
                &root,
                Path::new("plan.jmx"),
                &filesystem,
                FixtureDigest::sha256(b"<test/>"),
            )
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(fixture.artifact("plan"), Some(b"<test/>".as_slice()));

        let outside = FixtureBuilder::new("case")
            .artifact_from_filesystem("escape", &root, Path::new("escape.jmx"), &filesystem)
            .unwrap_err();
        assert!(matches!(outside, FixtureError::OutsideRoot));

        let relative_root = FixtureBuilder::new("case")
            .artifact_from_filesystem(
                "plan",
                Path::new("fixture"),
                Path::new("plan.jmx"),
                &filesystem,
            )
            .unwrap_err();
        assert!(matches!(
            relative_root,
            FixtureError::InvalidMetadata {
                field: "fixture_root"
            }
        ));
    }

    #[test]
    fn relative_paths_reject_escape_and_platform_absolute_forms() {
        for value in [
            "../outside.txt",
            "nested/../../outside.txt",
            "/absolute.txt",
            r"..\outside.txt",
            r"C:\outside.txt",
            "C:relative.txt",
            r"\\server\share\outside.txt",
            ".",
            "",
        ] {
            assert!(matches!(
                validate_fixture_relative_path(Path::new(value)),
                Err(FixtureError::InvalidMetadata {
                    field: "artifact_path"
                })
            ));
        }
        assert_eq!(
            validate_fixture_relative_path(Path::new("nested/input.txt")).unwrap(),
            PathBuf::from("nested/input.txt")
        );
    }

    #[test]
    fn injected_filesystem_read_is_bounded_and_digest_mismatch_is_rejected() {
        let mut filesystem = memory_filesystem();
        filesystem.files[0].1 = b"too-large".to_vec();
        let limits = FixtureLimits::new(2, 3, 32, 128);
        let too_large = FixtureBuilder::with_limits("case", limits)
            .artifact_from_filesystem("plan", &memory_root(), Path::new("plan.jmx"), &filesystem)
            .unwrap_err();
        assert!(matches!(
            too_large,
            FixtureError::Filesystem {
                kind: FixtureFilesystemError::TooLarge
            }
        ));

        filesystem.files[0].1 = b"ok".to_vec();
        let mismatch = FixtureBuilder::new("case")
            .artifact_from_filesystem_with_digest(
                "plan",
                &memory_root(),
                Path::new("plan.jmx"),
                &filesystem,
                FixtureDigest::sha256(b"not-ok"),
            )
            .unwrap_err();
        assert!(matches!(mismatch, FixtureError::DigestMismatch { .. }));
    }
}
