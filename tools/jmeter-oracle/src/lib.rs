// SPDX-License-Identifier: Apache-2.0
//! Fail-closed Apache JMeter oracle manifest and process harness.
//!
//! This tool never downloads an artifact, invokes a shell, or turns an
//! unavailable oracle into compatibility evidence. Source JSON is retained as
//! a serde_json Value so extensions are not silently discarded.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use nix::sys::signal::{Signal, killpg};
#[cfg(unix)]
use nix::unistd::{Pid, getpgid};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256, Sha512};

/// The only compatibility profile accepted by this harness.
pub const SUPPORTED_PROFILE_ID: &str = "jmeter-5.6.3";
/// Profile manifest schema identifier.
pub const PROFILE_SCHEMA_ID: &str = "jmeter-rs.compatibility-profile";
/// Oracle case manifest schema identifier.
pub const CASE_SCHEMA_ID: &str = "jmeter-rs.oracle-case";
/// Schema version implemented by this harness.
pub const MANIFEST_SCHEMA_VERSION: u64 = 1;
/// Maximum profile/case input size.
pub const DEFAULT_MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum bytes retained from each child output pipe.
pub const DEFAULT_MAX_PROCESS_OUTPUT_BYTES: usize = 1024 * 1024;
/// Maximum size of an emitted result or log artifact.
pub const DEFAULT_MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
/// Default timeout for one child invocation.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);
/// Maximum number of bytes accepted in a recorded target triple.
pub const MAX_TARGET_TRIPLE_BYTES: usize = 80;

static WORKSPACE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Stable machine-readable error categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCode {
    /// Caller option or manifest field is invalid.
    Configuration,
    /// Manifest is not valid JSON.
    ManifestJson,
    /// Manifest JSON violates the supported schema.
    ManifestSchema,
    /// Profile and case do not describe the same run.
    ManifestMismatch,
    /// Required file is unavailable or unreadable.
    File,
    /// Digest does not match the declared value.
    DigestMismatch,
    /// Path violates an explicit containment policy.
    PathPolicy,
    /// Explicit executable is unavailable or not executable.
    Executable,
    /// Process cleanup cannot be made robust on this platform.
    UnsupportedPlatform,
    /// Child exceeded its deadline.
    Timeout,
    /// Child output or an artifact exceeded its bound.
    OutputLimit,
    /// Child failed or omitted a required artifact.
    Process,
    /// Process-tree ownership was lost or could not be proven.
    ContainmentLost,
    /// The bounded cleanup registry has no slot reserved for this child.
    ReaperCapacity,
    /// A JTL input could not be parsed safely.
    JtlParse,
    /// The requested JTL or projection format is unsupported.
    UnsupportedFormat,
    /// The compared artifacts differ in an observable field.
    ComparisonMismatch,
    /// A normalization request is not declared by the case/profile.
    Normalization,
    /// Internal synchronization or invariant failure.
    Internal,
}

impl ErrorCode {
    /// Return the stable CLI spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Configuration => "configuration",
            Self::ManifestJson => "manifest-json",
            Self::ManifestSchema => "manifest-schema",
            Self::ManifestMismatch => "manifest-mismatch",
            Self::File => "file",
            Self::DigestMismatch => "digest-mismatch",
            Self::PathPolicy => "path-policy",
            Self::Executable => "executable",
            Self::UnsupportedPlatform => "unsupported-platform",
            Self::Timeout => "timeout",
            Self::OutputLimit => "output-limit",
            Self::Process => "process",
            Self::ContainmentLost => "containment-lost",
            Self::ReaperCapacity => "reaper-capacity",
            Self::JtlParse => "jtl-parse",
            Self::UnsupportedFormat => "unsupported-format",
            Self::ComparisonMismatch => "comparison-mismatch",
            Self::Normalization => "normalization",
            Self::Internal => "internal",
        }
    }
}

/// Stable subtype for process-tree ownership failures.
///
/// `ErrorCode::ContainmentLost` is the category surfaced to callers.  The
/// subtype keeps the reason machine-readable without turning every platform
/// detail into a top-level error code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessErrorKind {
    /// The root exited before a process-tree cleanup operation could prove
    /// that its numeric group token was still owned.
    RootExitedBeforeTreeCleanup,
    /// The root's live process group did not match the token established at
    /// spawn time.
    ProcessGroupMismatch,
    /// The root's process group could not be looked up while it was live.
    ProcessGroupLookup,
    /// A process-group signal failed after ownership was established.
    ProcessGroupSignal,
    /// A bounded output reader could not prove that all pipe readers stopped.
    ReaderCancellation,
}

impl ProcessErrorKind {
    /// Return the stable machine-readable subtype spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RootExitedBeforeTreeCleanup => "root-exited-before-tree-cleanup",
            Self::ProcessGroupMismatch => "process-group-mismatch",
            Self::ProcessGroupLookup => "process-group-lookup",
            Self::ProcessGroupSignal => "process-group-signal",
            Self::ReaderCancellation => "reader-cancellation",
        }
    }
}

mod compare;
mod jmx;

pub use compare::{
    ArtifactSummary, CompareFormat, CompareLimits, CompareOptions, CompareReport, NeutralAssertion,
    NeutralDocument, NeutralEvent, NeutralRoot, StructuredDiff, compare_case_artifacts,
    compare_jtl_files, parse_jtl, parse_jtl_with_format,
};
pub use jmx::{JmxDocument, compare_jmx_files, parse_jmx_semantic};

impl Display for ErrorCode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Typed error from the oracle runner.
#[derive(Clone, Debug)]
pub struct OracleError {
    code: ErrorCode,
    message: String,
    kind: Option<ProcessErrorKind>,
    secondary: Option<Box<OracleError>>,
}

impl OracleError {
    fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            kind: None,
            secondary: None,
        }
    }

    fn with_kind(mut self, kind: ProcessErrorKind) -> Self {
        self.kind = Some(kind);
        self
    }

    fn with_secondary(mut self, secondary: OracleError) -> Self {
        self.secondary = Some(Box::new(secondary));
        self
    }

    /// Construct a CLI configuration/diagnostic error.
    pub fn new_for_cli(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::new(code, message)
    }

    /// Return the stable machine-readable category.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    /// Return the diagnostic message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Return the process-specific failure subtype, when one exists.
    #[must_use]
    pub const fn kind(&self) -> Option<ProcessErrorKind> {
        self.kind
    }

    /// Return a bounded secondary cleanup diagnostic, when one exists.
    #[must_use]
    pub fn secondary(&self) -> Option<&OracleError> {
        self.secondary.as_deref()
    }

    /// Return the bounded diagnostic including process subtype and secondary
    /// cleanup details.
    #[must_use]
    pub fn diagnostic(&self) -> String {
        self.to_string()
    }
}

impl Display for OracleError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)?;
        if let Some(kind) = self.kind {
            write!(formatter, " [{}]", kind.as_str())?;
        }
        if let Some(secondary) = &self.secondary {
            write!(formatter, "; secondary cleanup: {}", secondary)?;
        }
        Ok(())
    }
}

impl std::error::Error for OracleError {}

type Result<T> = std::result::Result<T, OracleError>;

fn schema_error(path: &Path, message: impl Into<String>) -> OracleError {
    OracleError::new(
        ErrorCode::ManifestSchema,
        format!("manifest '{}': {}", path.display(), message.into()),
    )
}

fn io_error(code: ErrorCode, operation: &str, path: &Path, error: io::Error) -> OracleError {
    OracleError::new(
        code,
        format!("{} '{}': {}", operation, path.display(), error),
    )
}

fn configuration_error(message: impl Into<String>) -> OracleError {
    OracleError::new(ErrorCode::Configuration, message)
}

fn path_error(message: impl Into<String>) -> OracleError {
    OracleError::new(ErrorCode::PathPolicy, message)
}

fn mismatch_error(message: impl Into<String>) -> OracleError {
    OracleError::new(ErrorCode::ManifestMismatch, message)
}

fn read_json(path: &Path) -> Result<Value> {
    let metadata =
        fs::metadata(path).map_err(|error| io_error(ErrorCode::File, "stat", path, error))?;
    if !metadata.is_file() {
        return Err(OracleError::new(
            ErrorCode::File,
            format!("expected regular file '{}'", path.display()),
        ));
    }
    if metadata.len() > DEFAULT_MAX_INPUT_BYTES {
        return Err(OracleError::new(
            ErrorCode::OutputLimit,
            format!(
                "manifest '{}' exceeds {} bytes",
                path.display(),
                DEFAULT_MAX_INPUT_BYTES
            ),
        ));
    }
    let mut file =
        File::open(path).map_err(|error| io_error(ErrorCode::File, "open", path, error))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| io_error(ErrorCode::File, "read", path, error))?;
    serde_json::from_slice(&bytes).map_err(|error| {
        OracleError::new(
            ErrorCode::ManifestJson,
            format!("parse manifest '{}': {}", path.display(), error),
        )
    })
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(path_error("path must not be empty"));
    }
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|directory| directory.join(path))
            .map_err(|error| {
                OracleError::new(
                    ErrorCode::PathPolicy,
                    format!("resolve current directory: {}", error),
                )
            })
    }
}

fn object<'a>(value: &'a Value, path: &Path) -> Result<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| schema_error(path, "root/value must be an object"))
}

fn required_string<'a>(map: &'a Map<String, Value>, key: &str, path: &Path) -> Result<&'a str> {
    map.get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| schema_error(path, format!("'{}' must be a non-empty string", key)))
}

fn required_object<'a>(
    map: &'a Map<String, Value>,
    key: &str,
    path: &Path,
) -> Result<&'a Map<String, Value>> {
    map.get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| schema_error(path, format!("'{}' must be an object", key)))
}

fn required_array<'a>(
    map: &'a Map<String, Value>,
    key: &str,
    path: &Path,
) -> Result<&'a Vec<Value>> {
    map.get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| schema_error(path, format!("'{}' must be an array", key)))
}

fn required_u64(map: &Map<String, Value>, key: &str, path: &Path) -> Result<u64> {
    map.get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| schema_error(path, format!("'{}' must be an unsigned integer", key)))
}

fn validate_schema(map: &Map<String, Value>, schema_id: &str, path: &Path) -> Result<()> {
    if required_string(map, "schema_id", path)? != schema_id {
        return Err(schema_error(
            path,
            format!("expected schema_id '{}'", schema_id),
        ));
    }
    let version = required_u64(map, "schema_version", path)?;
    if version != MANIFEST_SCHEMA_VERSION {
        return Err(schema_error(
            path,
            format!(
                "unsupported schema_version {}; expected {}",
                version, MANIFEST_SCHEMA_VERSION
            ),
        ));
    }
    Ok(())
}

fn string_array(map: &Map<String, Value>, key: &str, path: &Path) -> Result<Vec<String>> {
    let array = required_array(map, key, path)?;
    let mut values = Vec::with_capacity(array.len());
    for (index, value) in array.iter().enumerate() {
        values.push(
            value
                .as_str()
                .filter(|item| !item.is_empty())
                .ok_or_else(|| {
                    schema_error(
                        path,
                        format!("'{}[{}]' must be a non-empty string", key, index),
                    )
                })?
                .to_owned(),
        );
    }
    Ok(values)
}

fn unique(values: Vec<String>, label: &str, path: &Path) -> Result<Vec<String>> {
    let mut seen = BTreeSet::new();
    for value in &values {
        if !seen.insert(value) {
            return Err(schema_error(
                path,
                format!("duplicate {} '{}'", label, value),
            ));
        }
    }
    Ok(values)
}

fn is_hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_https(value: &str, field: &str, path: &Path) -> Result<()> {
    if !value.starts_with("https://") || value.chars().any(char::is_whitespace) {
        return Err(schema_error(
            path,
            format!("'{}' must be an HTTPS URL", field),
        ));
    }
    Ok(())
}

fn valid_env_key(value: &str) -> bool {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

fn parse_environment(map: &Map<String, Value>, path: &Path) -> Result<BTreeMap<String, String>> {
    let values = required_array(map, "environment_allowlist", path)?;
    let mut result = BTreeMap::new();
    for (index, value) in values.iter().enumerate() {
        let item = value.as_str().ok_or_else(|| {
            schema_error(
                path,
                format!("environment_allowlist[{}] must be a string", index),
            )
        })?;
        let (key, value) = item.split_once('=').ok_or_else(|| {
            schema_error(
                path,
                format!("environment_allowlist[{}] must be KEY=VALUE", index),
            )
        })?;
        if !valid_env_key(key) {
            return Err(schema_error(
                path,
                format!("invalid environment key '{}'", key),
            ));
        }
        if value.contains('\0') {
            return Err(schema_error(
                path,
                format!("environment_allowlist[{}] contains NUL", index),
            ));
        }
        if result.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(schema_error(
                path,
                format!("duplicate environment key '{}'", key),
            ));
        }
    }
    Ok(result)
}

/// Pinned upstream archive declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactSpec {
    filename: String,
    format: String,
    digest: String,
    url: String,
    digest_url: String,
    size_bytes: Option<u64>,
}

impl ArtifactSpec {
    /// Return the profile artifact filename.
    #[must_use]
    pub fn filename(&self) -> &str {
        &self.filename
    }

    /// Return the profile archive format.
    #[must_use]
    pub fn format(&self) -> &str {
        &self.format
    }

    /// Return the expected lowercase SHA-512.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Return the optional expected artifact size.
    #[must_use]
    pub const fn size_bytes(&self) -> Option<u64> {
        self.size_bytes
    }

    /// Return the pinned download URL; this runner never fetches it.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Return the pinned sidecar URL; this runner never fetches it.
    #[must_use]
    pub fn digest_url(&self) -> &str {
        &self.digest_url
    }
}

/// Parsed profile with its complete source JSON retained.
#[derive(Clone, Debug)]
pub struct ProfileManifest {
    source_path: PathBuf,
    profile_id: String,
    document: Value,
    artifact: ArtifactSpec,
    fixture_ids: BTreeSet<String>,
    feature_ids: BTreeSet<String>,
    policy_ids: BTreeSet<String>,
    environment: BTreeMap<String, String>,
    locale: String,
    timezone: String,
    default_charset: String,
}

impl ProfileManifest {
    /// Load and validate a profile JSON document.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let source_path = absolute_path(path.as_ref())?;
        let document = read_json(&source_path)?;
        let map = object(&document, &source_path)?;
        validate_schema(map, PROFILE_SCHEMA_ID, &source_path)?;
        let profile_id = required_string(map, "profile_id", &source_path)?.to_owned();
        if profile_id != SUPPORTED_PROFILE_ID {
            return Err(schema_error(
                &source_path,
                format!("unsupported profile_id '{}'", profile_id),
            ));
        }
        let upstream = required_object(map, "upstream", &source_path)?;
        if required_string(upstream, "project", &source_path)? != "Apache JMeter"
            || required_string(upstream, "version", &source_path)? != "5.6.3"
        {
            return Err(schema_error(
                &source_path,
                "profile must pin Apache JMeter 5.6.3",
            ));
        }
        let artifact_map = required_object(upstream, "artifact", &source_path)?;
        let filename = required_string(artifact_map, "filename", &source_path)?.to_owned();
        if filename.contains('/') || filename.contains('\\') {
            return Err(schema_error(
                &source_path,
                "artifact filename must be a plain filename",
            ));
        }
        let format = required_string(artifact_map, "format", &source_path)?.to_owned();
        if !format.eq_ignore_ascii_case("zip") {
            return Err(schema_error(&source_path, "artifact format must be zip"));
        }
        let algorithm = required_string(artifact_map, "digest_algorithm", &source_path)?;
        if !algorithm.eq_ignore_ascii_case("SHA-512") {
            return Err(schema_error(
                &source_path,
                format!("unsupported digest algorithm '{}'", algorithm),
            ));
        }
        let digest = required_string(artifact_map, "digest", &source_path)?.to_ascii_lowercase();
        if !is_hex(&digest, 128) {
            return Err(schema_error(
                &source_path,
                "artifact digest must be 128 hexadecimal characters",
            ));
        }
        let url = required_string(artifact_map, "url", &source_path)?.to_owned();
        validate_https(&url, "upstream.artifact.url", &source_path)?;
        let digest_url = required_string(artifact_map, "digest_url", &source_path)?.to_owned();
        validate_https(&digest_url, "upstream.artifact.digest_url", &source_path)?;
        let size_bytes = artifact_map
            .get("verification")
            .and_then(Value::as_object)
            .and_then(|verification| verification.get("artifact_size_bytes"))
            .and_then(Value::as_u64);
        let artifact = ArtifactSpec {
            filename,
            format,
            digest,
            url,
            digest_url,
            size_bytes,
        };
        let assumptions = required_object(map, "runtime_assumptions", &source_path)?;
        let determinism = required_object(assumptions, "determinism", &source_path)?;
        let locale = required_string(determinism, "locale", &source_path)?.to_owned();
        let timezone = required_string(determinism, "timezone", &source_path)?.to_owned();
        let default_charset =
            required_string(determinism, "default_charset", &source_path)?.to_owned();
        let environment = parse_environment(determinism, &source_path)?;
        let fixture_ids = catalog_ids(map, "oracle_fixture_catalog", &source_path)?;
        let policy_ids = catalog_ids(map, "normalization_policies", &source_path)?;
        let boundary_ids = catalog_ids(map, "external_runtime_boundaries", &source_path)?;
        let feature_ids = catalog_ids(map, "features", &source_path)?;
        validate_feature_refs(map, &source_path, &fixture_ids, &policy_ids, &boundary_ids)?;
        Ok(Self {
            source_path,
            profile_id,
            document,
            artifact,
            fixture_ids,
            feature_ids,
            policy_ids,
            environment,
            locale,
            timezone,
            default_charset,
        })
    }

    /// Return source path.
    #[must_use]
    pub fn source_path(&self) -> &Path {
        &self.source_path
    }

    /// Return profile ID.
    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    /// Return complete source JSON, including unknown fields.
    #[must_use]
    pub fn document(&self) -> &Value {
        &self.document
    }

    /// Return artifact declaration.
    #[must_use]
    pub fn artifact(&self) -> &ArtifactSpec {
        &self.artifact
    }

    /// Return explicit profile environment entries.
    #[must_use]
    pub fn environment_allowlist(&self) -> &BTreeMap<String, String> {
        &self.environment
    }

    /// Return profile locale.
    #[must_use]
    pub fn locale(&self) -> &str {
        &self.locale
    }

    /// Return profile timezone.
    #[must_use]
    pub fn timezone(&self) -> &str {
        &self.timezone
    }

    /// Return profile default charset.
    #[must_use]
    pub fn default_charset(&self) -> &str {
        &self.default_charset
    }

    fn has_fixture(&self, id: &str) -> bool {
        self.fixture_ids.contains(id)
    }

    fn has_feature(&self, id: &str) -> bool {
        self.feature_ids.contains(id)
    }

    fn has_policy(&self, id: &str) -> bool {
        self.policy_ids.contains(id)
    }
}

fn catalog_ids(map: &Map<String, Value>, key: &str, path: &Path) -> Result<BTreeSet<String>> {
    let values = required_array(map, key, path)?;
    let mut result = BTreeSet::new();
    for (index, value) in values.iter().enumerate() {
        let item = value
            .as_object()
            .ok_or_else(|| schema_error(path, format!("{}[{}] must be an object", key, index)))?;
        let id = required_string(item, "id", path)?;
        if !result.insert(id.to_owned()) {
            return Err(schema_error(path, format!("duplicate {} id '{}'", key, id)));
        }
    }
    Ok(result)
}

fn validate_feature_refs(
    map: &Map<String, Value>,
    path: &Path,
    fixture_ids: &BTreeSet<String>,
    policy_ids: &BTreeSet<String>,
    boundary_ids: &BTreeSet<String>,
) -> Result<()> {
    let values = required_array(map, "features", path)?;
    for (index, value) in values.iter().enumerate() {
        let item = value
            .as_object()
            .ok_or_else(|| schema_error(path, format!("features[{}] must be an object", index)))?;
        let feature = required_string(item, "id", path)?;
        for id in string_array(item, "required_oracle_fixture_ids", path)? {
            if !fixture_ids.contains(&id) {
                return Err(schema_error(
                    path,
                    format!("feature '{}' references unknown fixture '{}'", feature, id),
                ));
            }
        }
        for id in string_array(item, "normalization_policy_refs", path)? {
            if !policy_ids.contains(&id) {
                return Err(schema_error(
                    path,
                    format!("feature '{}' references unknown policy '{}'", feature, id),
                ));
            }
        }
        for id in string_array(item, "external_runtime_boundary_ids", path)? {
            if !boundary_ids.contains(&id) {
                return Err(schema_error(
                    path,
                    format!("feature '{}' references unknown boundary '{}'", feature, id),
                ));
            }
        }
    }
    Ok(())
}

/// A fixture file and its manifest-declared SHA-256 digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseFile {
    path: String,
    sha256: String,
    format: Option<String>,
}

impl CaseFile {
    /// Return the manifest-relative path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Return the lowercase expected SHA-256.
    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Return the optional format hint.
    #[must_use]
    pub fn format(&self) -> Option<&str> {
        self.format.as_deref()
    }
}

/// One raw command template. Source arguments are retained exactly; only
/// approved path placeholders are replaced at materialization time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandTemplate {
    arguments: Vec<String>,
    result_placeholder: String,
    log_placeholder: String,
    property_file: Option<String>,
}

impl CommandTemplate {
    /// Return original template arguments.
    #[must_use]
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    /// Return the result path placeholder.
    #[must_use]
    pub fn result_placeholder(&self) -> &str {
        &self.result_placeholder
    }

    /// Return the log path placeholder.
    #[must_use]
    pub fn log_placeholder(&self) -> &str {
        &self.log_placeholder
    }

    /// Return the manifest-relative property selected by the q option.
    #[must_use]
    pub fn property_file(&self) -> Option<&str> {
        self.property_file.as_deref()
    }
}

/// Parsed case manifest with its complete source JSON retained.
#[derive(Clone, Debug)]
pub struct CaseManifest {
    source_path: PathBuf,
    case_id: String,
    profile_id: String,
    fixture_family_id: String,
    conformance_ids: Vec<String>,
    normalization_policy_refs: Vec<String>,
    document: Value,
    plan: CaseFile,
    property_files: Vec<CaseFile>,
    command_templates: Vec<CommandTemplate>,
}

impl CaseManifest {
    /// Load and schema-validate a case JSON document.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let source_path = absolute_path(path.as_ref())?;
        let document = read_json(&source_path)?;
        let map = object(&document, &source_path)?;
        validate_schema(map, CASE_SCHEMA_ID, &source_path)?;
        let case_id = required_string(map, "case_id", &source_path)?.to_owned();
        let profile_id = required_string(map, "profile_id", &source_path)?.to_owned();
        if profile_id != SUPPORTED_PROFILE_ID {
            return Err(schema_error(
                &source_path,
                format!("unsupported case profile_id '{}'", profile_id),
            ));
        }
        let fixture_family_id = required_string(map, "fixture_family_id", &source_path)?.to_owned();
        let conformance_ids = unique(
            string_array(map, "conformance_ids", &source_path)?,
            "conformance id",
            &source_path,
        )?;
        let normalization_policy_refs = unique(
            string_array(map, "normalization_policy_refs", &source_path)?,
            "normalization policy",
            &source_path,
        )?;
        let plan = parse_case_file(map, "plan", &source_path, 0)?;
        let property_array = required_array(map, "property_files", &source_path)?;
        let mut property_files = Vec::with_capacity(property_array.len());
        for (index, value) in property_array.iter().enumerate() {
            let property_map = value.as_object().ok_or_else(|| {
                schema_error(
                    &source_path,
                    format!("property_files[{}] must be an object", index),
                )
            })?;
            property_files.push(parse_case_file_map(
                property_map,
                &source_path,
                "property_files",
                index,
            )?);
        }
        let command = required_object(map, "command", &source_path)?;
        let mode = required_string(command, "mode", &source_path)?;
        if !matches!(mode, "nongui" | "nongui-static-only") {
            return Err(schema_error(
                &source_path,
                "only non-GUI oracle mode is supported",
            ));
        }
        let command_templates = if mode == "nongui-static-only" {
            validate_static_only_command(command, &source_path)?;
            Vec::new()
        } else {
            parse_templates(command, &plan, &property_files, &source_path)?
        };
        Ok(Self {
            source_path,
            case_id,
            profile_id,
            fixture_family_id,
            conformance_ids,
            normalization_policy_refs,
            document,
            plan,
            property_files,
            command_templates,
        })
    }

    /// Return source path.
    #[must_use]
    pub fn source_path(&self) -> &Path {
        &self.source_path
    }

    /// Return case ID.
    #[must_use]
    pub fn case_id(&self) -> &str {
        &self.case_id
    }

    /// Return case profile ID.
    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    /// Return fixture family ID.
    #[must_use]
    pub fn fixture_family_id(&self) -> &str {
        &self.fixture_family_id
    }

    /// Return declared conformance IDs.
    #[must_use]
    pub fn conformance_ids(&self) -> &[String] {
        &self.conformance_ids
    }

    /// Return declared policy references.
    #[must_use]
    pub fn normalization_policy_refs(&self) -> &[String] {
        &self.normalization_policy_refs
    }

    /// Return complete source JSON, including unknown fields.
    #[must_use]
    pub fn document(&self) -> &Value {
        &self.document
    }

    /// Return the JMX plan declaration.
    #[must_use]
    pub fn plan(&self) -> &CaseFile {
        &self.plan
    }

    /// Return property files in manifest order.
    #[must_use]
    pub fn property_files(&self) -> &[CaseFile] {
        &self.property_files
    }

    /// Return command templates in manifest order.
    #[must_use]
    pub fn command_templates(&self) -> &[CommandTemplate] {
        &self.command_templates
    }
}

fn parse_case_file(
    map: &Map<String, Value>,
    key: &str,
    path: &Path,
    index: usize,
) -> Result<CaseFile> {
    let nested = required_object(map, key, path)?;
    parse_case_file_map(nested, path, key, index)
}

fn parse_case_file_map(
    map: &Map<String, Value>,
    path: &Path,
    field: &str,
    index: usize,
) -> Result<CaseFile> {
    let relative = required_string(map, "path", path)?.to_owned();
    validate_relative_path(&relative, path, &format!("{}[{}].path", field, index))?;
    let sha256 = required_string(map, "sha256", path)?.to_ascii_lowercase();
    if !is_hex(&sha256, 64) {
        return Err(schema_error(
            path,
            format!(
                "{}[{}].sha256 must be 64 hexadecimal characters",
                field, index
            ),
        ));
    }
    let format = map
        .get("format")
        .map(|value| {
            value
                .as_str()
                .filter(|item| !item.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| {
                    schema_error(
                        path,
                        format!("{}[{}].format must be a string", field, index),
                    )
                })
        })
        .transpose()?;
    Ok(CaseFile {
        path: relative,
        sha256,
        format,
    })
}

fn parse_templates(
    command: &Map<String, Value>,
    plan: &CaseFile,
    properties: &[CaseFile],
    path: &Path,
) -> Result<Vec<CommandTemplate>> {
    let one = command.contains_key("argv_template");
    let many = command.contains_key("argv_templates");
    if one == many {
        return Err(schema_error(
            path,
            "command must contain exactly one argv template field",
        ));
    }
    let mut templates = Vec::new();
    if one {
        let values = required_array(command, "argv_template", path)?;
        templates.push(parse_template(
            values,
            plan,
            properties,
            path,
            "argv_template",
        )?);
    } else {
        let values = required_array(command, "argv_templates", path)?;
        if values.is_empty() {
            return Err(schema_error(
                path,
                "command.argv_templates must not be empty",
            ));
        }
        for (index, value) in values.iter().enumerate() {
            let values = value.as_array().ok_or_else(|| {
                schema_error(
                    path,
                    format!("command.argv_templates[{}] must be an array", index),
                )
            })?;
            templates.push(parse_template(
                values,
                plan,
                properties,
                path,
                &format!("argv_templates[{}]", index),
            )?);
        }
    }
    Ok(templates)
}

fn validate_static_only_command(command: &Map<String, Value>, path: &Path) -> Result<()> {
    if command.contains_key("argv_templates") || !command.contains_key("argv_template") {
        return Err(schema_error(
            path,
            "nongui-static-only command must contain exactly one argv_template",
        ));
    }
    let values = required_array(command, "argv_template", path)?;
    if values.len() != 1 || values[0].as_str() != Some("<not-run: static-only>") {
        return Err(schema_error(
            path,
            "nongui-static-only command must use the exact <not-run: static-only> placeholder",
        ));
    }
    Ok(())
}

fn parse_template(
    values: &[Value],
    plan: &CaseFile,
    properties: &[CaseFile],
    path: &Path,
    field: &str,
) -> Result<CommandTemplate> {
    if values.is_empty() {
        return Err(schema_error(
            path,
            format!("command.{} must not be empty", field),
        ));
    }
    let mut arguments = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let argument = value.as_str().ok_or_else(|| {
            schema_error(
                path,
                format!("command.{}[{}] must be a string", field, index),
            )
        })?;
        if argument.is_empty() || argument.contains('\0') {
            return Err(schema_error(
                path,
                format!("command.{}[{}] is empty or contains NUL", field, index),
            ));
        }
        arguments.push(argument.to_owned());
    }
    if !jmeter_program_name(&arguments[0]) {
        return Err(schema_error(
            path,
            format!("command.{}[0] must identify jmeter", field),
        ));
    }
    if !arguments.iter().any(|value| value == "-n") {
        return Err(schema_error(
            path,
            format!("command.{} must include -n", field),
        ));
    }
    let plan_arg = option_argument(&arguments, "-t", path, field)?;
    if plan_arg != plan.path() {
        return Err(schema_error(
            path,
            format!("command.{} -t must reference '{}'", field, plan.path()),
        ));
    }
    let result = option_argument(&arguments, "-l", path, field)?.to_owned();
    validate_output_placeholder(&result, path, field, "-l")?;
    let log = option_argument(&arguments, "-j", path, field)?.to_owned();
    validate_output_placeholder(&log, path, field, "-j")?;
    if result == log {
        return Err(schema_error(
            path,
            format!("command.{} must use distinct result and log outputs", field),
        ));
    }
    let property = optional_option_argument(&arguments, "-q", path, field)?.map(str::to_owned);
    if let Some(property) = &property
        && !properties.iter().any(|item| item.path() == property)
    {
        return Err(schema_error(
            path,
            format!("command.{} -q references unknown '{}'", field, property),
        ));
    }
    validate_options(&arguments, path, field)?;
    Ok(CommandTemplate {
        arguments,
        result_placeholder: result,
        log_placeholder: log,
        property_file: property,
    })
}

fn option_argument<'a>(
    arguments: &'a [String],
    option: &str,
    path: &Path,
    field: &str,
) -> Result<&'a str> {
    let mut found = None;
    for (index, argument) in arguments.iter().enumerate() {
        if argument == option {
            if found.is_some() {
                return Err(schema_error(
                    path,
                    format!("command.{} repeats {}", field, option),
                ));
            }
            let value = arguments.get(index + 1).ok_or_else(|| {
                schema_error(
                    path,
                    format!("command.{} {} is missing its value", field, option),
                )
            })?;
            if value.starts_with('-') {
                return Err(schema_error(
                    path,
                    format!("command.{} {} has an option as value", field, option),
                ));
            }
            found = Some(value.as_str());
        }
    }
    found.ok_or_else(|| schema_error(path, format!("command.{} is missing {}", field, option)))
}

fn optional_option_argument<'a>(
    arguments: &'a [String],
    option: &str,
    path: &Path,
    field: &str,
) -> Result<Option<&'a str>> {
    let mut found = None;
    for (index, argument) in arguments.iter().enumerate() {
        if argument == option {
            if found.is_some() {
                return Err(schema_error(
                    path,
                    format!("command.{} repeats {}", field, option),
                ));
            }
            let value = arguments.get(index + 1).ok_or_else(|| {
                schema_error(
                    path,
                    format!("command.{} {} is missing its value", field, option),
                )
            })?;
            if value.starts_with('-') {
                return Err(schema_error(
                    path,
                    format!("command.{} {} has an option as value", field, option),
                ));
            }
            found = Some(value.as_str());
        }
    }
    Ok(found)
}

fn validate_options(arguments: &[String], path: &Path, field: &str) -> Result<()> {
    let with_values = ["-q", "-t", "-l", "-j"];
    let mut index = 1;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "-n" {
            index += 1;
        } else if with_values.contains(&argument.as_str()) {
            index += 2;
        } else if argument.starts_with("-J") && argument[2..].contains('=') {
            index += 1;
        } else {
            return Err(schema_error(
                path,
                format!("command.{} has unsupported argument '{}'", field, argument),
            ));
        }
    }
    Ok(())
}

fn jmeter_program_name(argument: &str) -> bool {
    let name = Path::new(argument)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(argument);
    matches!(name, "jmeter" | "jmeter.sh" | "jmeter.bat" | "jmeter.cmd")
}

fn validate_output_placeholder(value: &str, path: &Path, field: &str, option: &str) -> Result<()> {
    let suffix = value.strip_prefix("<ignored>/").ok_or_else(|| {
        schema_error(
            path,
            format!("command.{} {} must use <ignored>/ output", field, option),
        )
    })?;
    validate_relative_path(suffix, path, &format!("command.{} {}", field, option))
}

fn validate_relative_path(value: &str, path: &Path, field: &str) -> Result<()> {
    let candidate = Path::new(value);
    if value.is_empty() || candidate.is_absolute() {
        return Err(schema_error(
            path,
            format!("{} must be a non-empty relative path", field),
        ));
    }
    for component in candidate.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(schema_error(
                    path,
                    format!("{} must not escape its root", field),
                ));
            }
        }
    }
    Ok(())
}

/// Profile/case pair whose fixture files have been root-checked and hashed.
#[derive(Clone, Debug)]
pub struct ValidatedCase {
    profile: ProfileManifest,
    case: CaseManifest,
    fixture_dir: PathBuf,
    plan_path: PathBuf,
    property_paths: BTreeMap<String, PathBuf>,
    plan_sha256: String,
    property_sha256: BTreeMap<String, String>,
}

impl ValidatedCase {
    /// Validate a loaded profile/case pair and all referenced fixture files.
    pub fn new(
        profile: ProfileManifest,
        case: CaseManifest,
        fixture_dir: impl AsRef<Path>,
    ) -> Result<Self> {
        if profile.profile_id() != case.profile_id() {
            return Err(mismatch_error(format!(
                "profile '{}' does not match case profile '{}'",
                profile.profile_id(),
                case.profile_id()
            )));
        }
        if !profile.has_fixture(case.fixture_family_id()) {
            return Err(mismatch_error(format!(
                "case '{}' references unknown fixture family '{}'",
                case.case_id(),
                case.fixture_family_id()
            )));
        }
        for id in case.conformance_ids() {
            if !profile.has_feature(id) {
                return Err(mismatch_error(format!(
                    "case '{}' references unknown conformance id '{}'",
                    case.case_id(),
                    id
                )));
            }
        }
        for id in case.normalization_policy_refs() {
            if !profile.has_policy(id) {
                return Err(mismatch_error(format!(
                    "case '{}' references unknown normalization policy '{}'",
                    case.case_id(),
                    id
                )));
            }
        }
        let fixture_dir = canonical_directory(fixture_dir.as_ref())?;
        let plan_path = contained_existing_file(&fixture_dir, case.plan().path())?;
        let plan_sha256 = digest_file(&plan_path, DEFAULT_MAX_INPUT_BYTES, DigestKind::Sha256)?.hex;
        if plan_sha256 != case.plan().sha256() {
            return Err(OracleError::new(
                ErrorCode::DigestMismatch,
                format!(
                    "plan '{}' SHA-256 mismatch: expected {}, got {}",
                    case.plan().path(),
                    case.plan().sha256(),
                    plan_sha256
                ),
            ));
        }
        let mut property_paths = BTreeMap::new();
        let mut property_sha256 = BTreeMap::new();
        for property in case.property_files() {
            if property_paths.contains_key(property.path()) {
                return Err(mismatch_error(format!(
                    "case '{}' repeats property file '{}'",
                    case.case_id(),
                    property.path()
                )));
            }
            let property_path = contained_existing_file(&fixture_dir, property.path())?;
            let digest =
                digest_file(&property_path, DEFAULT_MAX_INPUT_BYTES, DigestKind::Sha256)?.hex;
            if digest != property.sha256() {
                return Err(OracleError::new(
                    ErrorCode::DigestMismatch,
                    format!(
                        "property '{}' SHA-256 mismatch: expected {}, got {}",
                        property.path(),
                        property.sha256(),
                        digest
                    ),
                ));
            }
            property_paths.insert(property.path().to_owned(), property_path);
            property_sha256.insert(property.path().to_owned(), digest);
        }
        Ok(Self {
            profile,
            case,
            fixture_dir,
            plan_path,
            property_paths,
            plan_sha256,
            property_sha256,
        })
    }

    /// Return validated profile.
    #[must_use]
    pub fn profile(&self) -> &ProfileManifest {
        &self.profile
    }

    /// Return validated case.
    #[must_use]
    pub fn case(&self) -> &CaseManifest {
        &self.case
    }

    /// Return canonical fixture root.
    #[must_use]
    pub fn fixture_dir(&self) -> &Path {
        &self.fixture_dir
    }

    /// Return canonical plan path.
    #[must_use]
    pub fn plan_path(&self) -> &Path {
        &self.plan_path
    }

    /// Return verified plan SHA-256.
    #[must_use]
    pub fn plan_sha256(&self) -> &str {
        &self.plan_sha256
    }

    /// Return verified property paths by manifest-relative name.
    #[must_use]
    pub fn property_paths(&self) -> &BTreeMap<String, PathBuf> {
        &self.property_paths
    }

    /// Return verified property SHA-256 values by manifest-relative name.
    #[must_use]
    pub fn property_sha256(&self) -> &BTreeMap<String, String> {
        &self.property_sha256
    }

    /// Materialize one sanitized process command into an explicit output
    /// directory. No shell interpolation occurs.
    pub fn materialize_command(
        &self,
        template_index: usize,
        jmeter_path: impl AsRef<Path>,
        output_dir: impl AsRef<Path>,
    ) -> Result<MaterializedCommand> {
        let template = self
            .case
            .command_templates()
            .get(template_index)
            .ok_or_else(|| {
                configuration_error(format!("template index {} is out of range", template_index))
            })?;
        let jmeter_path = explicit_executable(jmeter_path.as_ref(), "jmeter")?;
        let output_dir = canonical_directory(output_dir.as_ref())?;
        let mut arguments = Vec::with_capacity(template.arguments().len());
        for (index, argument) in template.arguments().iter().enumerate() {
            if index == 0 {
                continue;
            } else if argument == self.case.plan().path() {
                arguments.push(self.plan_path.to_string_lossy().into_owned());
            } else if let Some(property_path) = self.property_paths.get(argument) {
                arguments.push(property_path.to_string_lossy().into_owned());
            } else if let Some(suffix) = argument.strip_prefix("<ignored>/") {
                arguments.push(
                    contained_output_file(&output_dir, suffix)?
                        .to_string_lossy()
                        .into_owned(),
                );
            } else {
                arguments.push(argument.clone());
            }
        }
        let result_suffix = template
            .result_placeholder()
            .strip_prefix("<ignored>/")
            .ok_or_else(|| configuration_error("result placeholder was not validated"))?;
        let log_suffix = template
            .log_placeholder()
            .strip_prefix("<ignored>/")
            .ok_or_else(|| configuration_error("log placeholder was not validated"))?;
        let result_path = contained_output_file(&output_dir, result_suffix)?;
        let log_path = contained_output_file(&output_dir, log_suffix)?;
        Ok(MaterializedCommand {
            program: jmeter_path,
            arguments,
            result_path,
            log_path,
            output_dir,
        })
    }
}

/// A command ready for direct use with std::process::Command.
#[derive(Clone, Debug)]
pub struct MaterializedCommand {
    program: PathBuf,
    arguments: Vec<String>,
    result_path: PathBuf,
    log_path: PathBuf,
    output_dir: PathBuf,
}

impl MaterializedCommand {
    /// Return absolute launcher path.
    #[must_use]
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// Return arguments excluding the program path.
    #[must_use]
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    /// Return expected JTL path.
    #[must_use]
    pub fn result_path(&self) -> &Path {
        &self.result_path
    }

    /// Return expected JMeter log path.
    #[must_use]
    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    /// Return dedicated output directory.
    #[must_use]
    pub fn output_dir(&self) -> &Path {
        &self.output_dir
    }

    /// Return argv with JMeter property values redacted.
    #[must_use]
    pub fn redacted_argv(&self) -> Vec<String> {
        let mut result = Vec::with_capacity(self.arguments.len() + 1);
        result.push(self.program.to_string_lossy().into_owned());
        result.extend(
            self.arguments
                .iter()
                .map(|argument| redact_argument(argument)),
        );
        result
    }
}

fn canonical_directory(path: &Path) -> Result<PathBuf> {
    let absolute = absolute_path(path)?;
    fs::create_dir_all(&absolute)
        .map_err(|error| io_error(ErrorCode::File, "create directory", &absolute, error))?;
    let canonical = fs::canonicalize(&absolute)
        .map_err(|error| io_error(ErrorCode::File, "canonicalize directory", &absolute, error))?;
    if !canonical.is_dir() {
        return Err(OracleError::new(
            ErrorCode::File,
            format!("expected directory '{}'", canonical.display()),
        ));
    }
    Ok(canonical)
}

fn contained_existing_file(root: &Path, relative: &str) -> Result<PathBuf> {
    validate_relative_path(relative, root, "fixture path")?;
    let candidate = root.join(relative);
    let canonical = fs::canonicalize(&candidate).map_err(|error| {
        io_error(
            ErrorCode::File,
            "canonicalize fixture file",
            &candidate,
            error,
        )
    })?;
    if !canonical.starts_with(root) {
        return Err(path_error(format!(
            "fixture file '{}' escapes root '{}'",
            canonical.display(),
            root.display()
        )));
    }
    let metadata = fs::metadata(&canonical)
        .map_err(|error| io_error(ErrorCode::File, "stat fixture file", &canonical, error))?;
    if !metadata.is_file() {
        return Err(OracleError::new(
            ErrorCode::File,
            format!("expected regular fixture file '{}'", canonical.display()),
        ));
    }
    Ok(canonical)
}

fn contained_output_file(root: &Path, relative: &str) -> Result<PathBuf> {
    validate_relative_path(relative, root, "output path")?;
    let candidate = root.join(relative);
    if !candidate.starts_with(root) {
        return Err(path_error(format!(
            "output path '{}' escapes root",
            candidate.display()
        )));
    }
    Ok(candidate)
}

fn explicit_executable(path: &Path, label: &str) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(path_error(format!("{} executable must be absolute", label)));
    }
    let canonical = fs::canonicalize(path).map_err(|error| {
        io_error(
            ErrorCode::Executable,
            "canonicalize executable",
            path,
            error,
        )
    })?;
    let metadata = fs::metadata(&canonical)
        .map_err(|error| io_error(ErrorCode::Executable, "stat executable", &canonical, error))?;
    if !metadata.is_file() || !is_executable(&canonical) {
        return Err(OracleError::new(
            ErrorCode::Executable,
            format!(
                "{} executable is unavailable or not executable: '{}'",
                label,
                canonical.display()
            ),
        ));
    }
    Ok(canonical)
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path)
        .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "exe" | "cmd" | "bat"
            )
        })
        .unwrap_or(false)
}

enum DigestKind {
    Sha256,
    Sha512,
}

struct DigestResult {
    hex: String,
    size_bytes: u64,
}

fn digest_file(path: &Path, maximum: u64, kind: DigestKind) -> Result<DigestResult> {
    let metadata = fs::metadata(path)
        .map_err(|error| io_error(ErrorCode::File, "stat digest input", path, error))?;
    if !metadata.is_file() {
        return Err(OracleError::new(
            ErrorCode::File,
            format!("digest input is not a regular file '{}'", path.display()),
        ));
    }
    if metadata.len() > maximum {
        return Err(OracleError::new(
            ErrorCode::OutputLimit,
            format!("file '{}' exceeds {} bytes", path.display(), maximum),
        ));
    }
    let mut file = File::open(path)
        .map_err(|error| io_error(ErrorCode::File, "open digest input", path, error))?;
    let mut size = 0_u64;
    let mut buffer = [0_u8; 128 * 1024];
    let hex = match kind {
        DigestKind::Sha256 => {
            let mut hasher = Sha256::new();
            loop {
                let count = file
                    .read(&mut buffer)
                    .map_err(|error| io_error(ErrorCode::File, "read digest input", path, error))?;
                if count == 0 {
                    break;
                }
                size = size.saturating_add(count as u64);
                if size > maximum {
                    return Err(OracleError::new(
                        ErrorCode::OutputLimit,
                        format!("file '{}' exceeded size bound", path.display()),
                    ));
                }
                hasher.update(&buffer[..count]);
            }
            to_hex(&hasher.finalize())
        }
        DigestKind::Sha512 => {
            let mut hasher = Sha512::new();
            loop {
                let count = file
                    .read(&mut buffer)
                    .map_err(|error| io_error(ErrorCode::File, "read digest input", path, error))?;
                if count == 0 {
                    break;
                }
                size = size.saturating_add(count as u64);
                if size > maximum {
                    return Err(OracleError::new(
                        ErrorCode::OutputLimit,
                        format!("file '{}' exceeded size bound", path.display()),
                    ));
                }
                hasher.update(&buffer[..count]);
            }
            to_hex(&hasher.finalize())
        }
    };
    Ok(DigestResult {
        hex,
        size_bytes: size,
    })
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 15) as usize] as char);
    }
    result
}

/// Metadata for a verified caller-supplied JMeter archive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactMetadata {
    /// Absolute artifact path.
    pub path: String,
    /// Observed file name.
    pub filename: String,
    /// Bytes hashed.
    pub size_bytes: u64,
    /// SHA-512 digest.
    pub sha512: String,
}

impl Serialize for ArtifactMetadata {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ArtifactMetadata", 4)?;
        state.serialize_field("path", &self.path)?;
        state.serialize_field("filename", &self.filename)?;
        state.serialize_field("size_bytes", &self.size_bytes)?;
        state.serialize_field("sha512", &self.sha512)?;
        state.end()
    }
}

/// Verify a supplied ZIP against the active profile SHA-512.
pub fn verify_artifact(
    profile: &ProfileManifest,
    artifact_path: impl AsRef<Path>,
) -> Result<ArtifactMetadata> {
    let path = absolute_path(artifact_path.as_ref())?;
    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| extension.eq_ignore_ascii_case("zip"))
        != Some(true)
    {
        return Err(path_error(format!(
            "artifact must have .zip extension: '{}'",
            path.display()
        )));
    }
    let digest = digest_file(&path, 4 * 1024 * 1024 * 1024, DigestKind::Sha512)?;
    if digest.hex != profile.artifact().digest() {
        return Err(OracleError::new(
            ErrorCode::DigestMismatch,
            format!(
                "artifact SHA-512 mismatch: expected {}, got {}",
                profile.artifact().digest(),
                digest.hex
            ),
        ));
    }
    if let Some(expected) = profile.artifact().size_bytes()
        && digest.size_bytes != expected
    {
        return Err(OracleError::new(
            ErrorCode::DigestMismatch,
            format!(
                "artifact size mismatch: expected {}, got {}",
                expected, digest.size_bytes
            ),
        ));
    }
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            path_error(format!(
                "artifact path has no UTF-8 filename: '{}'",
                path.display()
            ))
        })?;
    Ok(ArtifactMetadata {
        path: path.to_string_lossy().into_owned(),
        filename: filename.to_owned(),
        size_bytes: digest.size_bytes,
        sha512: digest.hex,
    })
}

/// Resource limits for one child invocation.
#[derive(Clone, Debug)]
pub struct RunnerLimits {
    /// Maximum wall-clock duration.
    pub timeout: Duration,
    /// Maximum bytes retained from each output pipe.
    pub max_process_output_bytes: usize,
    /// Maximum bytes in each result/log artifact.
    pub max_artifact_bytes: u64,
}

impl Default for RunnerLimits {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            max_process_output_bytes: DEFAULT_MAX_PROCESS_OUTPUT_BYTES,
            max_artifact_bytes: DEFAULT_MAX_ARTIFACT_BYTES,
        }
    }
}

impl RunnerLimits {
    fn validate(&self) -> Result<()> {
        if self.timeout.is_zero() {
            return Err(configuration_error("timeout must be greater than zero"));
        }
        if self.max_process_output_bytes == 0 {
            return Err(configuration_error(
                "max process output bytes must be greater than zero",
            ));
        }
        if self.max_artifact_bytes == 0 {
            return Err(configuration_error(
                "max artifact bytes must be greater than zero",
            ));
        }
        Ok(())
    }
}

/// Explicit process/output settings for one case.
#[derive(Clone, Debug)]
pub struct RunRequest {
    /// Validated profile/case fixture bundle.
    pub fixture: ValidatedCase,
    /// Absolute JMeter launcher path.
    pub jmeter_path: PathBuf,
    /// Absolute Java path. Required for actual execution.
    pub java_path: Option<PathBuf>,
    /// Verified ZIP metadata. Required for actual execution.
    pub artifact: Option<ArtifactMetadata>,
    /// Output root; one unique child is created for each template.
    pub output_root: Option<PathBuf>,
    /// Resource bounds.
    pub limits: RunnerLimits,
    /// Optional zero-based template selection.
    pub template_index: Option<usize>,
}

impl RunRequest {
    fn validate_dry_run(&self) -> Result<()> {
        self.limits.validate()?;
        explicit_executable(&self.jmeter_path, "jmeter")?;
        if let Some(java) = &self.java_path {
            explicit_executable(java, "java")?;
        }
        if let Some(index) = self.template_index
            && index >= self.fixture.case().command_templates().len()
        {
            return Err(configuration_error(format!(
                "template index {} is out of range",
                index
            )));
        }
        Ok(())
    }

    fn validate_run(&self) -> Result<()> {
        self.validate_dry_run()?;
        if self.java_path.is_none() {
            return Err(configuration_error(
                "an explicit Java path is required for execution",
            ));
        }
        if self.artifact.is_none() {
            return Err(configuration_error(
                "a verified JMeter ZIP is required for execution",
            ));
        }
        Ok(())
    }
}

/// Bounded redacted child output summary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OutputMetadata {
    /// Total bytes observed.
    pub size_bytes: u64,
    /// SHA-256 of retained bytes.
    pub sha256: String,
    /// Redacted diagnostic preview.
    pub preview: String,
}

/// Metadata for one required emitted artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OutputArtifactMetadata {
    /// Absolute path.
    pub path: String,
    /// Artifact size.
    pub size_bytes: u64,
    /// Artifact SHA-256.
    pub sha256: String,
}

/// Bounded information returned by the Java version probe.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JavaMetadata {
    /// Explicit executable path.
    pub executable: String,
    /// SHA-256 of the selected Java executable.
    pub executable_sha256: String,
    /// Version-process exit code.
    pub exit_code: Option<i32>,
    /// Redacted version output.
    pub version_output: String,
}

/// A validated exact Rust compilation target triple.
//
// Rust exposes target components as compile-time `cfg` values rather than a
// single target-triple constant to ordinary crate code.  The runner therefore
// uses a closed mapping below that includes the vendor and ABI environment;
// it never reconstructs a triple from only the operating system and
// architecture.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TargetTriple(String);

impl TargetTriple {
    /// Validate and retain a target triple for metadata or a trusted input.
    pub fn parse(value: &str) -> Result<Self> {
        if !(3..=MAX_TARGET_TRIPLE_BYTES).contains(&value.len()) {
            return Err(configuration_error(format!(
                "target triple must contain 3..={} bytes",
                MAX_TARGET_TRIPLE_BYTES
            )));
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(configuration_error(
                "target triple contains a character outside [A-Za-z0-9._-]",
            ));
        }
        Ok(Self(value.to_owned()))
    }

    /// Return the validated target triple text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for TargetTriple {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(|error| serde::de::Error::custom(error.to_string()))
    }
}

/// Read-only target fields accepted when inspecting old oracle diagnostics.
///
/// New run metadata always emits [`RunMetadata::target_triple`].  The optional
/// field here is intentionally limited to diagnostic reads so older reports
/// without that field remain readable without allowing new reports to omit it.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct RunMetadataDiagnostic {
    /// Legacy operating-system identifier, when present.
    #[serde(default)]
    pub target_os: Option<String>,
    /// Legacy architecture identifier, when present.
    #[serde(default)]
    pub target_arch: Option<String>,
    /// Exact target triple, absent only in an older diagnostic.
    #[serde(default)]
    pub target_triple: Option<TargetTriple>,
}

/// Resolve the exact target triple selected at compile time.
const COMPILE_TARGET_TRIPLE: Option<&str> = {
    #[cfg(all(
        target_arch = "x86_64",
        target_os = "linux",
        target_vendor = "unknown",
        target_env = "gnu"
    ))]
    {
        Some("x86_64-unknown-linux-gnu")
    }
    #[cfg(all(
        target_arch = "aarch64",
        target_os = "linux",
        target_vendor = "unknown",
        target_env = "gnu"
    ))]
    {
        Some("aarch64-unknown-linux-gnu")
    }
    #[cfg(all(
        target_arch = "x86_64",
        target_os = "linux",
        target_vendor = "unknown",
        target_env = "musl"
    ))]
    {
        Some("x86_64-unknown-linux-musl")
    }
    #[cfg(all(
        target_arch = "aarch64",
        target_os = "linux",
        target_vendor = "unknown",
        target_env = "musl"
    ))]
    {
        Some("aarch64-unknown-linux-musl")
    }
    #[cfg(all(target_arch = "x86_64", target_os = "macos", target_vendor = "apple"))]
    {
        Some("x86_64-apple-darwin")
    }
    #[cfg(all(target_arch = "aarch64", target_os = "macos", target_vendor = "apple"))]
    {
        Some("aarch64-apple-darwin")
    }
    #[cfg(all(
        target_arch = "x86_64",
        target_os = "windows",
        target_vendor = "pc",
        target_env = "msvc"
    ))]
    {
        Some("x86_64-pc-windows-msvc")
    }
    #[cfg(all(
        target_arch = "aarch64",
        target_os = "windows",
        target_vendor = "pc",
        target_env = "msvc"
    ))]
    {
        Some("aarch64-pc-windows-msvc")
    }
    #[cfg(all(
        target_arch = "x86_64",
        target_os = "windows",
        target_vendor = "pc",
        target_env = "gnu"
    ))]
    {
        Some("x86_64-pc-windows-gnu")
    }
    #[cfg(all(
        target_arch = "aarch64",
        target_os = "windows",
        target_vendor = "pc",
        target_env = "gnu"
    ))]
    {
        Some("aarch64-pc-windows-gnu")
    }
    #[cfg(not(any(
        all(
            target_arch = "x86_64",
            target_os = "linux",
            target_vendor = "unknown",
            target_env = "gnu"
        ),
        all(
            target_arch = "aarch64",
            target_os = "linux",
            target_vendor = "unknown",
            target_env = "gnu"
        ),
        all(
            target_arch = "x86_64",
            target_os = "linux",
            target_vendor = "unknown",
            target_env = "musl"
        ),
        all(
            target_arch = "aarch64",
            target_os = "linux",
            target_vendor = "unknown",
            target_env = "musl"
        ),
        all(target_arch = "x86_64", target_os = "macos", target_vendor = "apple"),
        all(target_arch = "aarch64", target_os = "macos", target_vendor = "apple"),
        all(
            target_arch = "x86_64",
            target_os = "windows",
            target_vendor = "pc",
            target_env = "msvc"
        ),
        all(
            target_arch = "aarch64",
            target_os = "windows",
            target_vendor = "pc",
            target_env = "msvc"
        ),
        all(
            target_arch = "x86_64",
            target_os = "windows",
            target_vendor = "pc",
            target_env = "gnu"
        ),
        all(
            target_arch = "aarch64",
            target_os = "windows",
            target_vendor = "pc",
            target_env = "gnu"
        )
    )))]
    {
        None
    }
};

fn compile_target_triple() -> Result<TargetTriple> {
    let value = COMPILE_TARGET_TRIPLE.ok_or_else(|| {
        configuration_error("exact compile-time target triple is unsupported by the oracle")
    })?;
    TargetTriple::parse(value)
}

/// Metadata from one successful JMeter invocation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RunMetadata {
    /// Profile ID.
    pub profile_id: String,
    /// Case ID.
    pub case_id: String,
    /// Template index.
    pub template_index: usize,
    /// Redacted argv.
    pub argv: Vec<String>,
    /// Environment keys only; values are never persisted.
    pub environment_keys: Vec<String>,
    /// Dedicated process working directory.
    pub working_directory: String,
    /// Compile-time target operating-system identifier.
    pub target_os: String,
    /// Compile-time target architecture identifier.
    pub target_arch: String,
    /// Exact compile-time target triple.
    pub target_triple: TargetTriple,
    /// Profile locale.
    pub locale: String,
    /// Profile timezone.
    pub timezone: String,
    /// Profile default charset.
    pub default_charset: String,
    /// Verified archive metadata.
    pub artifact: ArtifactMetadata,
    /// SHA-256 of the selected JMeter launcher.
    pub jmeter_sha256: String,
    /// Java version metadata.
    pub java: JavaMetadata,
    /// JMeter process exit code.
    pub process_exit: Option<i32>,
    /// Child stdout summary.
    pub stdout: OutputMetadata,
    /// Child stderr summary.
    pub stderr: OutputMetadata,
    /// JTL/result metadata.
    pub result: OutputArtifactMetadata,
    /// JMeter log metadata.
    pub log: OutputArtifactMetadata,
}

/// Metadata from a dry-run command construction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DryRunMetadata {
    /// Profile ID.
    pub profile_id: String,
    /// Case ID.
    pub case_id: String,
    /// Template index.
    pub template_index: usize,
    /// Redacted argv.
    pub argv: Vec<String>,
    /// Environment keys only.
    pub environment_keys: Vec<String>,
    /// Dedicated output directory.
    pub working_directory: String,
    /// Profile locale.
    pub locale: String,
    /// Profile timezone.
    pub timezone: String,
    /// Profile default charset.
    pub default_charset: String,
    /// Optional verified archive metadata.
    pub artifact: Option<ArtifactMetadata>,
}

/// Process-supervising oracle runner.
#[derive(Debug, Default)]
pub struct OracleRunner;

impl OracleRunner {
    /// Load and validate a profile/case fixture bundle.
    pub fn validate(
        profile_path: impl AsRef<Path>,
        case_path: impl AsRef<Path>,
        fixture_dir: impl AsRef<Path>,
    ) -> Result<ValidatedCase> {
        let profile = ProfileManifest::load(profile_path)?;
        let case = CaseManifest::load(case_path)?;
        ValidatedCase::new(profile, case, fixture_dir)
    }

    /// Construct sanitized commands without launching a process. Missing
    /// archive metadata is allowed because dry-run makes no conformance claim.
    pub fn dry_run(&self, request: &RunRequest) -> Result<Vec<DryRunMetadata>> {
        request.validate_dry_run()?;
        let root = output_root(
            request.output_root.as_deref(),
            request.fixture.case().case_id(),
        )?;
        let environment = build_environment(&request.fixture, request.java_path.as_deref())?;
        let indices = template_indices(
            request.fixture.case().command_templates().len(),
            request.template_index,
        );
        let mut reports = Vec::with_capacity(indices.len());
        for index in indices {
            let output = create_output_dir(&root, request.fixture.case().case_id(), index)?;
            let command =
                request
                    .fixture
                    .materialize_command(index, &request.jmeter_path, &output)?;
            reports.push(DryRunMetadata {
                profile_id: request.fixture.profile().profile_id().to_owned(),
                case_id: request.fixture.case().case_id().to_owned(),
                template_index: index,
                argv: command.redacted_argv(),
                environment_keys: environment.keys().cloned().collect(),
                working_directory: output.to_string_lossy().into_owned(),
                locale: request.fixture.profile().locale().to_owned(),
                timezone: request.fixture.profile().timezone().to_owned(),
                default_charset: request.fixture.profile().default_charset().to_owned(),
                artifact: request.artifact.clone(),
            });
        }
        Ok(reports)
    }

    /// Execute all or one case command templates with verified archive and
    /// explicit Java/JMeter paths.
    pub fn run(&self, request: &RunRequest) -> Result<Vec<RunMetadata>> {
        let result = self.run_inner(request);
        finish_run_with_cleanup(result)
    }

    fn run_inner(&self, request: &RunRequest) -> Result<Vec<RunMetadata>> {
        request.validate_run()?;
        let target_triple = compile_target_triple()?;
        let root = output_root(
            request.output_root.as_deref(),
            request.fixture.case().case_id(),
        )?;
        let environment = build_environment(&request.fixture, request.java_path.as_deref())?;
        let java = request
            .java_path
            .as_deref()
            .ok_or_else(|| configuration_error("Java path missing after validation"))?;
        let java_metadata = probe_java(java, &root, &request.limits)?;
        let jmeter_digest = digest_file(
            &request.jmeter_path,
            4 * 1024 * 1024 * 1024,
            DigestKind::Sha256,
        )?
        .hex;
        let indices = template_indices(
            request.fixture.case().command_templates().len(),
            request.template_index,
        );
        let mut reports = Vec::with_capacity(indices.len());
        for index in indices {
            let output = create_output_dir(&root, request.fixture.case().case_id(), index)?;
            let command =
                request
                    .fixture
                    .materialize_command(index, &request.jmeter_path, &output)?;
            let capture = execute_jmeter(&command, &environment, &request.limits)?;
            let result = output_artifact(command.result_path(), request.limits.max_artifact_bytes)?;
            let log = output_artifact(command.log_path(), request.limits.max_artifact_bytes)?;
            reports.push(RunMetadata {
                profile_id: request.fixture.profile().profile_id().to_owned(),
                case_id: request.fixture.case().case_id().to_owned(),
                template_index: index,
                argv: command.redacted_argv(),
                environment_keys: environment.keys().cloned().collect(),
                working_directory: output.to_string_lossy().into_owned(),
                target_os: std::env::consts::OS.to_owned(),
                target_arch: std::env::consts::ARCH.to_owned(),
                target_triple: target_triple.clone(),
                locale: request.fixture.profile().locale().to_owned(),
                timezone: request.fixture.profile().timezone().to_owned(),
                default_charset: request.fixture.profile().default_charset().to_owned(),
                artifact: request
                    .artifact
                    .clone()
                    .ok_or_else(|| configuration_error("archive missing after validation"))?,
                java: java_metadata.clone(),
                jmeter_sha256: jmeter_digest.clone(),
                process_exit: capture.status.code(),
                stdout: capture.stdout,
                stderr: capture.stderr,
                result,
                log,
            });
        }
        Ok(reports)
    }
}

fn finish_run_with_cleanup<T>(result: Result<T>) -> Result<T> {
    let drain = service_retained_children();
    match (result, drain) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_value), Err(cleanup_error)) => Err(cleanup_error),
        (Err(error), Err(cleanup_error)) => Err(combine_cleanup_errors(error, Some(cleanup_error))),
    }
}

fn template_indices(length: usize, selected: Option<usize>) -> Vec<usize> {
    match selected {
        Some(index) => vec![index],
        None => (0..length).collect(),
    }
}

fn sanitize_component(value: &str) -> Result<String> {
    if value.is_empty() || value == "." || value == ".." {
        return Err(configuration_error("unsafe empty/dot case identifier"));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(configuration_error(format!(
            "unsafe case identifier '{}'",
            value
        )));
    }
    Ok(value.to_owned())
}

fn output_root(root: Option<&Path>, case_id: &str) -> Result<PathBuf> {
    let base = match root {
        Some(path) => canonical_directory(path)?,
        None => canonical_directory(&std::env::temp_dir().join("jmeter-oracle-runs"))?,
    };
    canonical_directory(&base.join(sanitize_component(case_id)?))
}

fn create_output_dir(root: &Path, case_id: &str, index: usize) -> Result<PathBuf> {
    let case_id = sanitize_component(case_id)?;
    for _ in 0..32 {
        let counter = WORKSPACE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = root.join(format!(
            "{}-run-{}-{}-{}",
            case_id,
            std::process::id(),
            index,
            counter
        ));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(io_error(
                    ErrorCode::File,
                    "create output directory",
                    &path,
                    error,
                ));
            }
        }
    }
    Err(OracleError::new(
        ErrorCode::File,
        format!("cannot allocate output below '{}'", root.display()),
    ))
}

fn build_environment(
    fixture: &ValidatedCase,
    java: Option<&Path>,
) -> Result<BTreeMap<String, String>> {
    let profile = fixture.profile();
    let mut environment = profile.environment_allowlist().clone();
    insert_environment(&mut environment, "LC_ALL", profile.locale())?;
    insert_environment(&mut environment, "LANG", profile.locale())?;
    insert_environment(&mut environment, "TZ", profile.timezone())?;
    if let Some(java) = java {
        let parent = java
            .parent()
            .ok_or_else(|| path_error("Java executable has no parent"))?;
        let home = parent.parent().unwrap_or(parent);
        insert_environment(&mut environment, "JAVACMD", &java.to_string_lossy())?;
        insert_environment(&mut environment, "JAVA_HOME", &home.to_string_lossy())?;
        insert_environment(
            &mut environment,
            "PATH",
            &format!("{}{}{}", parent.display(), path_separator(), system_path()),
        )?;
    } else {
        insert_environment(&mut environment, "PATH", system_path())?;
    }
    Ok(environment)
}

fn insert_environment(
    environment: &mut BTreeMap<String, String>,
    key: &str,
    value: &str,
) -> Result<()> {
    if let Some(existing) = environment.get(key) {
        if existing != value {
            return Err(configuration_error(format!(
                "profile allowlist conflicts with required {} value",
                key
            )));
        }
    } else {
        environment.insert(key.to_owned(), value.to_owned());
    }
    Ok(())
}

#[cfg(unix)]
const fn path_separator() -> &'static str {
    ":"
}

#[cfg(not(unix))]
const fn path_separator() -> &'static str {
    ";"
}

#[cfg(unix)]
const fn system_path() -> &'static str {
    "/usr/bin:/bin"
}

#[cfg(not(unix))]
const fn system_path() -> &'static str {
    ""
}

fn probe_java(path: &Path, root: &Path, limits: &RunnerLimits) -> Result<JavaMetadata> {
    let output = create_output_dir(root, "java-probe", 0)?;
    let mut command = Command::new(path);
    command.arg("-version");
    command.current_dir(&output);
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    let cleanup = configure_process_cleanup(&mut command, default_process_cleanup())?;
    let environment = BTreeMap::from([
        ("LC_ALL".to_owned(), "C".to_owned()),
        ("LANG".to_owned(), "C".to_owned()),
        ("TZ".to_owned(), "UTC".to_owned()),
        ("PATH".to_owned(), system_path().to_owned()),
    ]);
    let capture = execute_spawned(command, &environment, limits, &[], cleanup)?;
    if !capture.status.success() {
        return Err(OracleError::new(
            ErrorCode::Process,
            format!(
                "Java -version exited {}; stderr: {}",
                format_exit_status(capture.status),
                capture.stderr.preview
            ),
        ));
    }
    let executable_sha256 = digest_file(path, 4 * 1024 * 1024 * 1024, DigestKind::Sha256)?.hex;
    Ok(JavaMetadata {
        executable: path.to_string_lossy().into_owned(),
        executable_sha256,
        exit_code: capture.status.code(),
        version_output: merge_preview(&capture.stdout.preview, &capture.stderr.preview),
    })
}

fn merge_preview(stdout: &str, stderr: &str) -> String {
    match (stdout.is_empty(), stderr.is_empty()) {
        (true, true) => String::new(),
        (false, true) => stdout.to_owned(),
        (true, false) => stderr.to_owned(),
        (false, false) => format!("stdout: {}\nstderr: {}", stdout, stderr),
    }
}

#[derive(Debug)]
struct ProcessCapture {
    status: ExitStatus,
    stdout: OutputMetadata,
    stderr: OutputMetadata,
}

fn execute_jmeter(
    command: &MaterializedCommand,
    environment: &BTreeMap<String, String>,
    limits: &RunnerLimits,
) -> Result<ProcessCapture> {
    execute_jmeter_with_cleanup(command, environment, limits, default_process_cleanup())
}

#[cfg(unix)]
const fn default_process_cleanup() -> ChildCleanup {
    // The launcher is allowed to spawn Java and helper descendants.  The
    // command is placed in its own group before spawn so the group id is
    // proven from the still-live owned Child handle during cleanup.
    ChildCleanup::ProcessGroup
}

#[cfg(not(unix))]
const fn default_process_cleanup() -> ChildCleanup {
    // Windows and other non-Unix targets have no safe process-tree primitive
    // in this harness.  Requesting the normal process-tree policy therefore
    // fails explicitly instead of silently downgrading to direct-child mode.
    ChildCleanup::ProcessGroup
}

fn execute_jmeter_with_cleanup(
    command: &MaterializedCommand,
    environment: &BTreeMap<String, String>,
    limits: &RunnerLimits,
    requested_cleanup: ChildCleanup,
) -> Result<ProcessCapture> {
    let mut process = Command::new(command.program());
    process.args(command.arguments());
    process.current_dir(command.output_dir());
    process.stdin(Stdio::null());
    process.stdout(Stdio::piped());
    process.stderr(Stdio::piped());
    let cleanup = configure_process_cleanup(&mut process, requested_cleanup)?;
    let capture = execute_spawned(
        process,
        environment,
        limits,
        &[command.result_path(), command.log_path()],
        cleanup,
    )?;
    if !capture.status.success() {
        return Err(OracleError::new(
            ErrorCode::Process,
            format!(
                "JMeter exited {}; stdout: {}; stderr: {}",
                format_exit_status(capture.status),
                capture.stdout.preview,
                capture.stderr.preview
            ),
        ));
    }
    Ok(capture)
}

#[cfg_attr(
    not(unix),
    allow(
        unreachable_code,
        unused_variables,
        unused_mut,
        reason = "non-Unix capture fails closed before unsupported reader setup"
    )
)]
fn execute_spawned(
    mut command: Command,
    environment: &BTreeMap<String, String>,
    limits: &RunnerLimits,
    watched: &[&Path],
    cleanup: ChildCleanup,
) -> Result<ProcessCapture> {
    #[cfg(not(unix))]
    {
        return Err(OracleError::new(
            ErrorCode::UnsupportedPlatform,
            "oracle process capture requires bounded nonblocking readers on this platform",
        ));
    }
    // Service retained exact children before starting another process. The
    // final run-level drain below is independent of this pre-spawn pass.
    service_retained_children()?;
    // Reserve the fixed registry slot before `spawn`. Every post-spawn owner
    // therefore has a bounded destination if cleanup cannot finish.
    let permit = retained_children().reserve()?;
    command.env_clear();
    for (key, value) in environment {
        command.env(key, value);
    }
    let child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            drop(permit);
            return Err(OracleError::new(
                ErrorCode::Executable,
                format!("spawn oracle process: {}", error),
            ));
        }
    };
    // Arm the guard immediately after spawn. Every path after this point,
    // including pipe setup, reader startup, and wait failures, retains the
    // configured cleanup policy through `Drop`.
    let mut owned_child = OwnedChild::new(child, cleanup, permit);
    #[cfg(unix)]
    if cleanup == ChildCleanup::ProcessGroup {
        let group = match prove_live_process_group(owned_child.child_mut()?) {
            Ok(group) => group,
            Err(error) => {
                // If the liveness proof observed an exit, preserve that
                // reaped state so Drop cannot attempt a stale group signal.
                if let Ok(Some(status)) = owned_child.child_mut()?.try_wait() {
                    owned_child.mark_reaped(status);
                }
                return fail_after_spawn(&mut owned_child, error);
            }
        };
        owned_child.set_group(group);
    }
    let stdout = match owned_child.child_mut()?.stdout.take() {
        Some(stdout) => stdout,
        None => {
            return fail_after_spawn(
                &mut owned_child,
                OracleError::new(ErrorCode::Internal, "stdout pipe missing"),
            );
        }
    };
    let stderr = match owned_child.child_mut()?.stderr.take() {
        Some(stderr) => stderr,
        None => {
            return fail_after_spawn(
                &mut owned_child,
                OracleError::new(ErrorCode::Internal, "stderr pipe missing"),
            );
        }
    };
    let stdout_capture = StreamCapture::new(limits.max_process_output_bytes);
    let stderr_capture = StreamCapture::new(limits.max_process_output_bytes);
    let mut stdout_reader = match spawn_process_reader(stdout, "stdout") {
        Ok(reader) => reader,
        Err(error) => return fail_after_spawn(&mut owned_child, error),
    };
    let mut stderr_reader = match spawn_process_reader(stderr, "stderr") {
        Ok(reader) => reader,
        Err(error) => {
            stdout_reader.cancel();
            drop(stdout_reader);
            let cleanup_result = owned_child.cleanup();
            return Err(combine_cleanup_errors(error, cleanup_result.err()));
        }
    };
    let started = Instant::now();
    loop {
        stdout_reader.poll(&stdout_capture)?;
        stderr_reader.poll(&stderr_capture)?;
        if stdout_capture.exceeded() || stderr_capture.exceeded() {
            return cleanup_with_readers(
                &mut owned_child,
                stdout_reader,
                stderr_reader,
                OracleError::new(
                    ErrorCode::OutputLimit,
                    "oracle process output exceeded bound",
                ),
            );
        }
        if watched
            .iter()
            .any(|path| artifact_over_limit(path, limits.max_artifact_bytes))
        {
            return cleanup_with_readers(
                &mut owned_child,
                stdout_reader,
                stderr_reader,
                OracleError::new(ErrorCode::OutputLimit, "oracle artifact exceeded bound"),
            );
        }
        let wait = owned_child.child_mut()?.try_wait();
        match wait {
            Ok(Some(status)) => {
                // Do not disarm the guard until both readers are complete. A
                // descendant can retain a pipe after the root exits; only a
                // fully drained reader pair permits ordinary completion.
                owned_child.mark_reaped(status);
                let reader_result = stdout_reader.finish(&stdout_capture);
                let reader_result =
                    reader_result.and_then(|()| stderr_reader.finish(&stderr_capture));
                if let Err(reader_error) = reader_result {
                    let cause = if cleanup == ChildCleanup::ProcessGroup {
                        root_exited_before_tree_cleanup()
                    } else {
                        reader_error.clone()
                    };
                    let secondary = if cleanup == ChildCleanup::ProcessGroup {
                        Some(reader_error)
                    } else {
                        None
                    };
                    drop(stdout_reader);
                    drop(stderr_reader);
                    return Err(combine_cleanup_errors(cause, secondary));
                }
                drop(stdout_reader);
                drop(stderr_reader);
                owned_child.disarm_reaped();
                if stdout_capture.exceeded() || stderr_capture.exceeded() {
                    return Err(OracleError::new(
                        ErrorCode::OutputLimit,
                        "oracle process output exceeded bound",
                    ));
                }
                return Ok(ProcessCapture {
                    status,
                    stdout: stdout_capture.finish()?,
                    stderr: stderr_capture.finish()?,
                });
            }
            Ok(None) => {}
            Err(error) => {
                let wait_error = OracleError::new(
                    ErrorCode::Process,
                    format!("wait for oracle process: {}", error),
                );
                return cleanup_with_readers(
                    &mut owned_child,
                    stdout_reader,
                    stderr_reader,
                    wait_error,
                );
            }
        }
        if started.elapsed() >= limits.timeout {
            return cleanup_with_readers(
                &mut owned_child,
                stdout_reader,
                stderr_reader,
                OracleError::new(
                    ErrorCode::Timeout,
                    format!(
                        "oracle process exceeded {} seconds",
                        limits.timeout.as_secs()
                    ),
                ),
            );
        }
        thread::sleep(Duration::from_millis(5));
    }
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "direct-child cleanup is exercised by ordinary seams"
    )
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChildCleanup {
    /// Signal and reap only the exact owned child.  This is the normal mode.
    DirectChild,
    /// The command was explicitly configured in its own process group.
    /// This mode is reserved for namespace-isolated tests and callers that
    /// explicitly request process-tree cleanup.
    ProcessGroup,
}

enum DirectSignal {
    /// The owned child exited during the liveness check and was reaped.
    AlreadyExited(ExitStatus),
    /// A signal was sent to the still-live owned child.
    Signalled,
}

#[cfg(unix)]
type GroupToken = Option<ProcessGroupId>;

#[cfg(not(unix))]
type GroupToken = Option<()>;

const CLEANUP_POLL_TIMEOUT: Duration = Duration::from_millis(100);
const CLEANUP_POLL_INTERVAL: Duration = Duration::from_millis(2);
const READER_WAIT_TIMEOUT: Duration = Duration::from_millis(100);
const REAPER_RETRY_INTERVAL: Duration = Duration::from_millis(10);
const REAPER_MAX_RETRIES: usize = 16;
const REAPER_CAPACITY: usize = 16;

/// A child that could not be reaped in the first bounded cleanup attempt.
/// Keeping the exact handle in this entry prevents `Child::Drop` from
/// silently orphaning a still-live process.
struct RetainedCleanup<C> {
    child: C,
    cleanup: ChildCleanup,
    group: GroupToken,
    last_error: OracleError,
}

enum CleanupSlot<C> {
    /// A slot reserved before `Command::spawn`; no child exists yet.
    Reserved,
    /// A slot owning an exact child handle after a cleanup failure.
    Occupied(RetainedCleanup<C>),
}

/// A fixed-capacity reservation made before spawning a child.
///
/// The reservation is tied to one slot, so cleanup handoff cannot fail from
/// capacity exhaustion after the OS child has been created.
struct CleanupReservation<'a, C> {
    registry: &'a CleanupRegistry<C>,
    index: usize,
    active: bool,
}

impl<C> CleanupReservation<'_, C> {
    fn commit(mut self, entry: RetainedCleanup<C>) -> Result<()> {
        match self.registry.commit(self.index, entry) {
            Ok(()) => {
                self.active = false;
                Ok(())
            }
            Err((error, entry)) => {
                // The index came from this reservation and is therefore
                // valid. Force the exact entry back into that same fixed slot
                // before returning the invariant error; never drop ownership
                // merely because handoff reporting failed.
                self.registry.force_commit(self.index, entry);
                self.active = false;
                Err(error)
            }
        }
    }
}

impl<C> Drop for CleanupReservation<'_, C> {
    fn drop(&mut self) {
        if self.active {
            self.registry.release(self.index);
        }
    }
}

/// Fixed-capacity retry registry used when bounded cleanup cannot finish.
///
/// The boxed slot array is allocated once by the repository-owned capacity
/// constructor. It never grows, and a slot is reserved before each spawn.
/// There is no detached cleanup worker: the owner or an explicit final drain
/// retains and services the exact child synchronously.
struct CleanupRegistry<C> {
    slots: Mutex<Box<[Option<CleanupSlot<C>>]>>,
}

impl<C> CleanupRegistry<C> {
    #[cfg(test)]
    fn new() -> Self {
        Self::with_capacity(REAPER_CAPACITY)
    }

    fn with_capacity(capacity: usize) -> Self {
        let slots: Box<[Option<CleanupSlot<C>>]> =
            std::iter::repeat_with(|| None).take(capacity).collect();
        Self {
            slots: Mutex::new(slots),
        }
    }

    fn lock_slots(&self) -> std::sync::MutexGuard<'_, Box<[Option<CleanupSlot<C>>]>> {
        match self.slots.lock() {
            Ok(slots) => slots,
            Err(poisoned) => {
                // Recover the still-owned fixed slot array, but publish the
                // synchronization failure so it is never mistaken for a
                // clean handoff.
                report_reaper_failure(&OracleError::new(
                    ErrorCode::Internal,
                    "cleanup registry lock was poisoned; recovered owned slots",
                ));
                poisoned.into_inner()
            }
        }
    }

    fn reserve(&self) -> Result<CleanupReservation<'_, C>> {
        let mut slots = self.lock_slots();
        let Some((index, slot)) = slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.is_none())
        else {
            return Err(OracleError::new(
                ErrorCode::ReaperCapacity,
                "bounded cleanup registry is at capacity; refusing to spawn",
            ));
        };
        *slot = Some(CleanupSlot::Reserved);
        Ok(CleanupReservation {
            registry: self,
            index,
            active: true,
        })
    }

    fn commit(
        &self,
        index: usize,
        entry: RetainedCleanup<C>,
    ) -> std::result::Result<(), (OracleError, RetainedCleanup<C>)> {
        let mut slots = self.lock_slots();
        let Some(slot) = slots.get_mut(index) else {
            return Err((
                OracleError::new(
                    ErrorCode::Internal,
                    "cleanup reservation index is outside fixed registry",
                ),
                entry,
            ));
        };
        if !matches!(slot, Some(CleanupSlot::Reserved)) {
            return Err((
                OracleError::new(
                    ErrorCode::Internal,
                    "cleanup reservation was not in the reserved state",
                ),
                entry,
            ));
        }
        *slot = Some(CleanupSlot::Occupied(entry));
        Ok(())
    }

    fn force_commit(&self, index: usize, entry: RetainedCleanup<C>) {
        let mut slots = self.lock_slots();
        if let Some(slot) = slots.get_mut(index) {
            *slot = Some(CleanupSlot::Occupied(entry));
        } else {
            // A reservation can only carry an in-range index. This diagnostic
            // is still emitted if an internal invariant is corrupted.
            report_reaper_failure(&OracleError::new(
                ErrorCode::Internal,
                "cannot retain exact child after invalid reservation index",
            ));
        }
    }

    fn release(&self, index: usize) {
        let mut slots = self.lock_slots();
        if let Some(slot) = slots.get_mut(index) {
            *slot = None;
        }
    }

    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "registry retention is exercised by seams")
    )]
    fn retain(
        &self,
        child: C,
        cleanup: ChildCleanup,
        group: GroupToken,
        error: OracleError,
    ) -> Result<()> {
        let reservation = self.reserve()?;
        reservation.commit(RetainedCleanup {
            child,
            cleanup,
            group,
            last_error: error,
        })
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        let slots = self.lock_slots();
        slots
            .iter()
            .filter(|slot| matches!(slot, Some(CleanupSlot::Occupied(_))))
            .count()
    }

    fn service_with<F, S>(&self, attempts: usize, mut cleanup: F, mut sleeper: S) -> Result<()>
    where
        C: ChildOps,
        F: FnMut(&mut C, ChildCleanup, GroupToken) -> Result<ExitStatus>,
        S: FnMut(Duration),
    {
        let mut first_error = None;
        let capacity = {
            let slots = self.lock_slots();
            slots.len()
        };

        // Drain every slot on every explicit service pass. This pass is not
        // coupled to a future spawn, and one failed entry cannot hide a later
        // entry's result.
        for index in 0..capacity {
            let mut entry = {
                let mut slots = self.lock_slots();
                match slots.get_mut(index).and_then(Option::take) {
                    Some(CleanupSlot::Occupied(entry)) => Some(entry),
                    Some(CleanupSlot::Reserved) => {
                        // A reserved slot belongs to a still-live caller and
                        // must not be serviced or released by this drain.
                        slots[index] = Some(CleanupSlot::Reserved);
                        None
                    }
                    None => None,
                }
            };
            let Some(mut entry_value) = entry.take() else {
                continue;
            };
            let result = retry_cleanup_with(
                &mut entry_value.child,
                attempts,
                |child| cleanup(child, entry_value.cleanup, entry_value.group),
                &mut sleeper,
            );
            match result {
                Ok(_status) => {}
                Err(error) => {
                    let combined = combine_cleanup_errors(entry_value.last_error, Some(error));
                    if first_error.is_none() {
                        first_error = Some(combined.clone());
                    }
                    entry_value.last_error = combined;
                    // A containment error can race with root exit. Once the
                    // exact Child proves it is already reaped, retaining the
                    // stale group token would only invite a later unsafe
                    // rediscovery. Drop this entry after recording the
                    // diagnostic; never signal it again.
                    if entry_value.last_error.code() == ErrorCode::ContainmentLost
                        && matches!(entry_value.child.try_wait(), Ok(Some(_)))
                    {
                        continue;
                    }
                    let mut slots = self.lock_slots();
                    // The slot was taken above and cannot have been reserved
                    // by another owner while this entry remained owned here.
                    if let Some(slot) = slots.get_mut(index) {
                        *slot = Some(CleanupSlot::Occupied(entry_value));
                    }
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

static RETAINED_CHILDREN: OnceLock<CleanupRegistry<Child>> = OnceLock::new();

fn retained_children() -> &'static CleanupRegistry<Child> {
    RETAINED_CHILDREN.get_or_init(|| CleanupRegistry::with_capacity(REAPER_CAPACITY))
}

/// An owned child guard armed at the spawn boundary.  The guard deliberately
/// retains the configured cleanup policy through every failure and drop path.
struct OwnedChild<'a> {
    child: Option<Child>,
    cleanup: ChildCleanup,
    group: GroupToken,
    reaped: Option<ExitStatus>,
    permit: Option<CleanupReservation<'a, Child>>,
}

impl<'a> OwnedChild<'a> {
    fn new(child: Child, cleanup: ChildCleanup, permit: CleanupReservation<'a, Child>) -> Self {
        Self {
            child: Some(child),
            cleanup,
            group: None,
            reaped: None,
            permit: Some(permit),
        }
    }

    fn child_mut(&mut self) -> Result<&mut Child> {
        self.child.as_mut().ok_or_else(|| {
            OracleError::new(
                ErrorCode::Internal,
                "owned child guard was already disarmed",
            )
        })
    }

    #[cfg(unix)]
    fn set_group(&mut self, group: ProcessGroupId) {
        self.group = Some(group);
    }

    fn mark_reaped(&mut self, status: ExitStatus) {
        // Keep the exact Child and group token until all pipe readers have
        // finished. Drop must see this marker and never signal a stale PGID.
        self.reaped = Some(status);
    }

    fn disarm_reaped(&mut self) {
        // This is called only after all readers have completed. The root has
        // already been reaped by `try_wait`; dropping the handle is then safe.
        let _ = self.child.take();
        let _ = self.permit.take();
    }

    fn cleanup(&mut self) -> Result<ExitStatus> {
        if let Some(status) = self.reaped {
            if self.cleanup == ChildCleanup::ProcessGroup {
                return Err(root_exited_before_tree_cleanup());
            }
            self.disarm_reaped();
            return Ok(status);
        }
        #[cfg(unix)]
        if self.cleanup == ChildCleanup::ProcessGroup && self.group.is_none() {
            // Setup failed before a safe tree token was established. Reap
            // only the exact root; callers retain the setup/containment error
            // and never claim that descendants were cleaned.
            let result = match self.child.as_mut() {
                Some(child) => terminate_direct_and_reap(child),
                None => Err(OracleError::new(
                    ErrorCode::Internal,
                    "owned child guard was already disarmed",
                )),
            };
            if result.is_ok() {
                self.disarm_reaped();
            }
            return result;
        }
        let result = match self.child.as_mut() {
            Some(child) => cleanup_child_with_group(child, self.cleanup, self.group),
            None => Err(OracleError::new(
                ErrorCode::Internal,
                "owned child guard was already disarmed",
            )),
        };
        if result.is_ok() {
            self.disarm_reaped();
        }
        result
    }
}

impl Drop for OwnedChild<'_> {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            let _ = self.permit.take();
            return;
        };

        let Some(permit) = self.permit.take() else {
            // A missing reservation is an internal invariant failure. Keep
            // the exact root owned by the fixed registry only when the normal
            // reservation path supplied one; this branch cannot occur in a
            // correctly constructed guard.
            report_reaper_failure(&OracleError::new(
                ErrorCode::Internal,
                "owned child guard lost its cleanup reservation",
            ));
            return;
        };

        if self.reaped.is_some() {
            // The root was already reaped. The token remains held until this
            // guard is dropped after reader completion, but no numeric group
            // signal is ever attempted.
            drop(permit);
            return;
        }

        // Drop cannot report an error. It must nevertheless make the same
        // bounded configured-policy attempt as all explicit failure paths.
        // If an unusual OS error prevents a bounded reap, hand the exact
        // owned handle to the pre-reserved fixed registry without blocking
        // this drop path.
        let cleanup_result = cleanup_child_with_group(&mut child, self.cleanup, self.group);
        let error = match cleanup_result {
            Ok(_status) => {
                drop(permit);
                return;
            }
            Err(error) => error,
        };
        let entry = RetainedCleanup {
            child,
            cleanup: self.cleanup,
            group: self.group,
            last_error: error.clone(),
        };
        report_reaper_failure(&error);
        if let Err(commit_error) = permit.commit(entry) {
            // The slot was reserved before spawn. Reaching this branch means
            // an internal state corruption, but retain the original error as
            // the primary diagnostic rather than dropping a live child.
            report_reaper_failure(&combine_cleanup_errors(error, Some(commit_error)));
        }
    }
}

fn fail_after_spawn(child: &mut OwnedChild<'_>, cause: OracleError) -> Result<ProcessCapture> {
    let cleanup_result = child.cleanup();
    Err(combine_cleanup_errors(cause, cleanup_result.err()))
}

fn cleanup_with_readers(
    child: &mut OwnedChild<'_>,
    mut stdout_reader: ReaderHandle,
    mut stderr_reader: ReaderHandle,
    cause: OracleError,
) -> Result<ProcessCapture> {
    stdout_reader.cancel();
    stderr_reader.cancel();
    drop(stdout_reader);
    drop(stderr_reader);
    // The exact child remains owned until both reader handles have been
    // cancelled and dropped. This ordering prevents a direct-child reap from
    // disarming the root while pipe readers still own inherited descriptors.
    let cleanup_result = child.cleanup();
    let first_error = cleanup_result.err();
    Err(combine_cleanup_errors(cause, first_error))
}

fn combine_cleanup_errors(cause: OracleError, cleanup: Option<OracleError>) -> OracleError {
    match cleanup {
        Some(cleanup) => cause.with_secondary(cleanup),
        None => cause,
    }
}

trait ChildOps {
    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>>;
    fn kill(&mut self) -> io::Result<()>;
    #[cfg(unix)]
    fn validate_group(&mut self, expected: ProcessGroupId) -> Result<ProcessGroupId>;
}

impl ChildOps for Child {
    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        Child::try_wait(self)
    }

    fn kill(&mut self) -> io::Result<()> {
        Child::kill(self)
    }

    #[cfg(unix)]
    fn validate_group(&mut self, expected: ProcessGroupId) -> Result<ProcessGroupId> {
        prove_live_process_group_matches(self, expected)
    }
}

#[cfg_attr(
    not(test),
    allow(dead_code, reason = "direct-child cleanup is exercised by seams")
)]
fn cleanup_child(child: &mut Child, cleanup: ChildCleanup) -> Result<ExitStatus> {
    let group: GroupToken = {
        #[cfg(unix)]
        {
            if cleanup == ChildCleanup::ProcessGroup {
                Some(prove_live_process_group(child)?)
            } else {
                None
            }
        }
        #[cfg(not(unix))]
        {
            None
        }
    };
    cleanup_child_with_group(child, cleanup, group)
}

fn cleanup_child_with_group(
    child: &mut Child,
    cleanup: ChildCleanup,
    group: GroupToken,
) -> Result<ExitStatus> {
    cleanup_child_with_token(child, cleanup, group, kill_owned_process_group)
}

#[cfg_attr(
    not(unix),
    allow(unused_variables, reason = "non-Unix process-tree path is fail-closed")
)]
fn cleanup_child_with_token<C, G>(
    child: &mut C,
    cleanup: ChildCleanup,
    group: GroupToken,
    mut kill_group: G,
) -> Result<ExitStatus>
where
    C: ChildOps,
    G: FnMut(GroupToken) -> Result<()>,
{
    match child.try_wait() {
        Ok(Some(status)) => {
            if cleanup == ChildCleanup::ProcessGroup {
                return Err(root_exited_before_tree_cleanup());
            }
            return Ok(status);
        }
        Ok(None) => {}
        Err(error) => {
            return Err(OracleError::new(
                ErrorCode::Process,
                format!("check oracle process before cleanup: {}", error),
            ));
        }
    }

    match cleanup {
        ChildCleanup::DirectChild => terminate_direct_and_reap(child),
        ChildCleanup::ProcessGroup => {
            #[cfg(not(unix))]
            {
                let _ = &mut kill_group;
                let unsupported = OracleError::new(
                    ErrorCode::UnsupportedPlatform,
                    "process-group cleanup was requested but is unsupported on this platform",
                );
                return match terminate_direct_and_reap(child) {
                    Ok(_status) => Err(unsupported),
                    Err(cleanup_error) => {
                        Err(combine_cleanup_errors(unsupported, Some(cleanup_error)))
                    }
                };
            }

            #[cfg(unix)]
            {
                let group = group.ok_or_else(|| {
                    OracleError::new(
                        ErrorCode::Internal,
                        "process-group cleanup has no proven ownership token",
                    )
                })?;
                // The token is validated again immediately before every group
                // signal. A mismatch never falls back to signalling the stale
                // numeric value.
                let live_group = match child.validate_group(group) {
                    Ok(live_group) => live_group,
                    Err(containment) => {
                        let direct = terminate_direct_and_reap(child).err();
                        return Err(combine_cleanup_errors(containment, direct));
                    }
                };
                if let Err(group_error) = kill_group(Some(live_group)) {
                    let containment = OracleError::new(
                        ErrorCode::ContainmentLost,
                        format!("process-group cleanup failed: {}", group_error.message()),
                    )
                    .with_kind(ProcessErrorKind::ProcessGroupSignal);
                    let direct = terminate_direct_and_reap(child).err();
                    return Err(combine_cleanup_errors(containment, direct));
                }

                // A successful group signal still requires exact-root reap.
                // If it does not happen in the bounded interval, direct-child
                // escalation is allowed only after another liveness check.
                if let Some(status) = poll_child(child, CLEANUP_POLL_TIMEOUT)? {
                    return Ok(status);
                }
                match signal_direct_child(child)? {
                    DirectSignal::AlreadyExited(status) => Ok(status),
                    DirectSignal::Signalled => reap_after_signal(child, None),
                }
            }
        }
    }
}

fn root_exited_before_tree_cleanup() -> OracleError {
    OracleError::new(
        ErrorCode::ContainmentLost,
        "root exited before process-tree cleanup; descendants were not proven cleaned",
    )
    .with_kind(ProcessErrorKind::RootExitedBeforeTreeCleanup)
}

#[cfg_attr(
    not(test),
    allow(dead_code, reason = "injected cleanup seam is test-only")
)]
fn cleanup_child_with<C, G>(
    child: &mut C,
    cleanup: ChildCleanup,
    group: GroupToken,
    kill_group: G,
) -> Result<ExitStatus>
where
    C: ChildOps,
    G: FnMut(GroupToken) -> Result<()>,
{
    cleanup_child_with_token(child, cleanup, group, kill_group)
}

fn terminate_direct_and_reap<C: ChildOps>(child: &mut C) -> Result<ExitStatus> {
    match signal_direct_child(child)? {
        DirectSignal::AlreadyExited(status) => Ok(status),
        DirectSignal::Signalled => reap_after_signal(child, None),
    }
}

fn reap_after_signal<C: ChildOps>(
    child: &mut C,
    prior_error: Option<OracleError>,
) -> Result<ExitStatus> {
    match poll_child(child, CLEANUP_POLL_TIMEOUT)? {
        Some(status) => match prior_error {
            Some(error) => Err(error),
            None => Ok(status),
        },
        None => Err(OracleError::new(
            ErrorCode::Process,
            "oracle child did not exit before bounded cleanup deadline",
        )),
    }
}

fn poll_child<C: ChildOps>(child: &mut C, timeout: Duration) -> Result<Option<ExitStatus>> {
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(Some(status)),
            Ok(None) => {}
            Err(error) => {
                return Err(OracleError::new(
                    ErrorCode::Process,
                    format!("poll oracle process: {}", error),
                ));
            }
        }
        if started.elapsed() >= timeout {
            return Ok(None);
        }
        thread::sleep(CLEANUP_POLL_INTERVAL.min(timeout.saturating_sub(started.elapsed())));
    }
}

fn signal_direct_child<C: ChildOps>(child: &mut C) -> Result<DirectSignal> {
    // The liveness check is immediately before the signal.  An exited child
    // is already reaped and must never be signalled.
    match child.try_wait() {
        Ok(Some(status)) => return Ok(DirectSignal::AlreadyExited(status)),
        Ok(None) => {}
        Err(error) => {
            return Err(OracleError::new(
                ErrorCode::Process,
                format!("check oracle process before direct signal: {}", error),
            ));
        }
    }
    match child.kill() {
        Ok(()) => Ok(DirectSignal::Signalled),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(DirectSignal::Signalled),
        Err(error) => Err(OracleError::new(
            ErrorCode::Process,
            format!("terminate direct oracle child: {}", error),
        )),
    }
}

fn retry_cleanup_with<C, F, S>(
    child: &mut C,
    attempts: usize,
    mut cleanup: F,
    mut sleeper: S,
) -> Result<ExitStatus>
where
    C: ChildOps,
    F: FnMut(&mut C) -> Result<ExitStatus>,
    S: FnMut(Duration),
{
    if attempts == 0 {
        return Err(configuration_error(
            "child cleanup retry count must be greater than zero",
        ));
    }
    let mut last_error = None;
    for attempt in 0..attempts {
        match cleanup(child) {
            Ok(status) => return Ok(status),
            Err(error) => {
                // A tree cleanup failure is terminal for this token. Once
                // containment is lost, a later `try_wait` returning Some is
                // only proof that the root was reaped; it is not proof that
                // descendants were cleaned.
                if error.code() == ErrorCode::ContainmentLost {
                    return Err(error);
                }
                // A process-group cleanup may report the group error after
                // the exact child has already exited and been reaped. Never
                // retain that handle in the retry path.
                match child.try_wait() {
                    Ok(Some(status)) => return Ok(status),
                    Ok(None) => last_error = Some(error),
                    Err(wait_error) => {
                        let wait_error = OracleError::new(
                            ErrorCode::Process,
                            format!("check child after cleanup retry: {}", wait_error),
                        );
                        last_error = Some(combine_cleanup_errors(error, Some(wait_error)));
                    }
                }
            }
        }
        if attempt + 1 < attempts {
            sleeper(REAPER_RETRY_INTERVAL);
        }
    }
    match last_error {
        Some(error) => Err(error),
        None => Err(OracleError::new(
            ErrorCode::Process,
            "child cleanup retry ended without a diagnostic",
        )),
    }
}

#[cfg_attr(
    not(test),
    allow(dead_code, reason = "handoff failure seam is test-only")
)]
fn fallback_after_handoff_failure_with<C, F, S>(
    child: &mut C,
    handoff_error: OracleError,
    attempts: usize,
    cleanup: F,
    sleeper: S,
) -> Result<()>
where
    C: ChildOps,
    F: FnMut(&mut C) -> Result<ExitStatus>,
    S: FnMut(Duration),
{
    match retry_cleanup_with(child, attempts, cleanup, sleeper) {
        Ok(_status) => Ok(()),
        Err(cleanup_error) => Err(combine_cleanup_errors(handoff_error, Some(cleanup_error))),
    }
}

fn report_reaper_failure(error: &OracleError) {
    eprintln!(
        "jmeter-oracle error [{}]: {}; exact child handle retained in fixed cleanup registry",
        error.code(),
        error
    );
}

fn service_retained_children() -> Result<()> {
    retained_children().service_with(REAPER_MAX_RETRIES, cleanup_child_with_group, thread::sleep)
}

fn artifact_over_limit(path: &Path, maximum: u64) -> bool {
    fs::metadata(path)
        .map(|metadata| metadata.len() > maximum)
        .unwrap_or(false)
}

struct StreamCapture {
    retained: Mutex<Vec<u8>>,
    total: AtomicU64,
    exceeded: AtomicBool,
    maximum: usize,
}

impl StreamCapture {
    fn new(maximum: usize) -> Self {
        Self {
            retained: Mutex::new(Vec::with_capacity(maximum.min(8192))),
            total: AtomicU64::new(0),
            exceeded: AtomicBool::new(false),
            maximum,
        }
    }

    fn push(&self, bytes: &[u8]) {
        let total =
            self.total.fetch_add(bytes.len() as u64, Ordering::Relaxed) + bytes.len() as u64;
        if total > self.maximum as u64 {
            self.exceeded.store(true, Ordering::Release);
        }
        if let Ok(mut retained) = self.retained.lock() {
            let remaining = self.maximum.saturating_sub(retained.len());
            retained.extend_from_slice(&bytes[..bytes.len().min(remaining)]);
        }
    }

    fn exceeded(&self) -> bool {
        self.exceeded.load(Ordering::Acquire)
    }

    fn finish(&self) -> Result<OutputMetadata> {
        let retained = self
            .retained
            .lock()
            .map_err(|_| OracleError::new(ErrorCode::Internal, "output capture lock poisoned"))?;
        let mut hasher = Sha256::new();
        hasher.update(&*retained);
        Ok(OutputMetadata {
            size_bytes: self.total.load(Ordering::Acquire),
            sha256: to_hex(&hasher.finalize()),
            preview: redact_text(&String::from_utf8_lossy(&retained)),
        })
    }
}

struct ReaderHandle {
    // Readers are serviced by the owning supervisor thread. This keeps every
    // handle joined by construction: there is no detached reader or reaper
    // thread that can outlive the exact child ownership state.
    reader: Option<Box<dyn Read + Send>>,
    eof: bool,
}

impl ReaderHandle {
    fn poll(&mut self, capture: &StreamCapture) -> Result<bool> {
        if self.eof {
            return Ok(true);
        }
        let Some(reader) = self.reader.as_mut() else {
            self.eof = true;
            return Ok(true);
        };
        let mut buffer = [0_u8; 8192];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => {
                    self.eof = true;
                    return Ok(true);
                }
                Ok(count) => {
                    capture.push(&buffer[..count]);
                    if capture.exceeded() {
                        return Ok(false);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(false);
                }
                Err(error) => {
                    return Err(OracleError::new(
                        ErrorCode::Process,
                        format!("read oracle output: {}", error),
                    ));
                }
            }
        }
    }

    fn finish(&mut self, capture: &StreamCapture) -> Result<()> {
        let started = Instant::now();
        while !self.poll(capture)? {
            if started.elapsed() >= READER_WAIT_TIMEOUT {
                self.cancel();
                return Err(OracleError::new(
                    ErrorCode::Timeout,
                    "oracle output reader did not stop before bounded deadline",
                ));
            }
            thread::sleep(CLEANUP_POLL_INTERVAL);
        }
        Ok(())
    }

    fn cancel(&mut self) {
        // Dropping the read end is the cancellation operation. Unix pipes are
        // nonblocking, so this is bounded even when an escaped descendant
        // retains the write end.
        let _ = self.reader.take();
        self.eof = true;
    }
}

impl Drop for ReaderHandle {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[cfg(unix)]
fn spawn_process_reader<R: Read + Send + std::os::fd::AsFd + 'static>(
    reader: R,
    _stream_name: &str,
) -> Result<ReaderHandle> {
    // Unix pipes are made nonblocking so cancellation closes the reader loop
    // even when a descendant inherited the write end.
    set_reader_nonblocking(&reader)?;
    Ok(ReaderHandle {
        reader: Some(Box::new(reader)),
        eof: false,
    })
}

#[cfg(not(unix))]
fn spawn_process_reader<R: Read + Send + 'static>(
    _reader: R,
    _stream_name: &str,
) -> Result<ReaderHandle> {
    Err(OracleError::new(
        ErrorCode::UnsupportedPlatform,
        "bounded nonblocking child readers are unsupported on this platform",
    ))
}

#[cfg(unix)]
fn set_reader_nonblocking<R: std::os::fd::AsFd>(reader: &R) -> Result<()> {
    use nix::fcntl::{FcntlArg, OFlag, fcntl};

    let current = fcntl(reader, FcntlArg::F_GETFL).map_err(|error| {
        OracleError::new(
            ErrorCode::Process,
            format!("get oracle output pipe flags: {}", error),
        )
    })?;
    let flags = OFlag::from_bits_truncate(current) | OFlag::O_NONBLOCK;
    fcntl(reader, FcntlArg::F_SETFL(flags)).map_err(|error| {
        OracleError::new(
            ErrorCode::Process,
            format!("set oracle output pipe nonblocking: {}", error),
        )
    })?;
    Ok(())
}

#[cfg(not(unix))]
#[allow(dead_code, reason = "non-Unix capture fails closed before use")]
fn set_reader_nonblocking<R: Read>(_reader: &R) -> Result<()> {
    Ok(())
}

fn configure_process_cleanup(
    command: &mut Command,
    requested: ChildCleanup,
) -> Result<ChildCleanup> {
    match requested {
        ChildCleanup::DirectChild => Ok(ChildCleanup::DirectChild),
        ChildCleanup::ProcessGroup => configure_process_group(command),
    }
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) -> Result<ChildCleanup> {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
    Ok(ChildCleanup::ProcessGroup)
}

#[cfg(not(unix))]
fn configure_process_group(_command: &mut Command) -> Result<ChildCleanup> {
    Err(OracleError::new(
        ErrorCode::UnsupportedPlatform,
        "process-group cleanup was requested but is unsupported on this platform",
    ))
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessGroupId(i32);

#[cfg(unix)]
impl TryFrom<u32> for ProcessGroupId {
    type Error = OracleError;

    fn try_from(raw: u32) -> Result<Self> {
        let raw = i32::try_from(raw).map_err(|_| {
            OracleError::new(
                ErrorCode::Process,
                format!("child process-group id {} overflows pid_t", raw),
            )
        })?;
        if raw <= 1 {
            return Err(OracleError::new(
                ErrorCode::Process,
                format!("unsafe child process-group id {}; refusing signal", raw),
            ));
        }
        Ok(Self(raw))
    }
}

#[cfg(unix)]
impl ProcessGroupId {
    fn as_raw(self) -> i32 {
        self.0
    }
}

#[cfg(unix)]
fn process_group_from_pid(raw: i32) -> Result<ProcessGroupId> {
    if raw <= 1 {
        return Err(OracleError::new(
            ErrorCode::ContainmentLost,
            format!("unsafe process-group id {}; refusing ownership", raw),
        )
        .with_kind(ProcessErrorKind::ProcessGroupLookup));
    }
    Ok(ProcessGroupId(raw))
}

#[cfg(unix)]
fn prove_live_process_group(child: &mut Child) -> Result<ProcessGroupId> {
    match child.try_wait() {
        Ok(Some(_status)) => return Err(root_exited_before_tree_cleanup()),
        Ok(None) => {}
        Err(error) => {
            return Err(OracleError::new(
                ErrorCode::Process,
                format!("check root before process-group lookup: {}", error),
            ));
        }
    }
    let root_pid = ProcessGroupId::try_from(child.id()).map_err(|error| {
        OracleError::new(
            ErrorCode::ContainmentLost,
            format!(
                "root PID cannot be a process-group token: {}",
                error.message()
            ),
        )
        .with_kind(ProcessErrorKind::ProcessGroupLookup)
    })?;
    let observed = getpgid(Some(Pid::from_raw(root_pid.0))).map_err(|error| {
        OracleError::new(
            ErrorCode::ContainmentLost,
            format!("lookup root process group: {}", error),
        )
        .with_kind(ProcessErrorKind::ProcessGroupLookup)
    })?;
    let observed = process_group_from_pid(observed.as_raw())?;
    if observed != root_pid {
        return Err(OracleError::new(
            ErrorCode::ContainmentLost,
            format!(
                "root process group {} does not equal root PID {}",
                observed.as_raw(),
                root_pid.as_raw()
            ),
        )
        .with_kind(ProcessErrorKind::ProcessGroupMismatch));
    }
    Ok(observed)
}

#[cfg(unix)]
fn prove_live_process_group_matches(
    child: &mut Child,
    expected: ProcessGroupId,
) -> Result<ProcessGroupId> {
    let observed = prove_live_process_group(child)?;
    if observed != expected {
        return Err(OracleError::new(
            ErrorCode::ContainmentLost,
            format!(
                "root process group changed from {} to {}",
                expected.as_raw(),
                observed.as_raw()
            ),
        )
        .with_kind(ProcessErrorKind::ProcessGroupMismatch));
    }
    Ok(observed)
}

#[cfg(unix)]
fn kill_owned_process_group(group: GroupToken) -> Result<()> {
    let Some(group) = group else {
        return Err(OracleError::new(
            ErrorCode::Internal,
            "process-group signal missing proven ownership token",
        ));
    };
    killpg(Pid::from_raw(group.0), Signal::SIGKILL).map_err(|error| {
        OracleError::new(
            ErrorCode::ContainmentLost,
            format!("kill owned oracle process group: {}", error),
        )
        .with_kind(ProcessErrorKind::ProcessGroupSignal)
    })?;
    Ok(())
}

#[cfg(not(unix))]
fn kill_owned_process_group(_group: GroupToken) -> Result<()> {
    Err(OracleError::new(
        ErrorCode::UnsupportedPlatform,
        "process-group cleanup was requested but is unsupported on this platform",
    ))
}

fn format_exit_status(status: ExitStatus) -> String {
    status
        .code()
        .map(|code| format!("exit code {}", code))
        .unwrap_or_else(|| "terminated by signal".to_owned())
}

fn output_artifact(path: &Path, maximum: u64) -> Result<OutputArtifactMetadata> {
    let digest = digest_file(path, maximum, DigestKind::Sha256)?;
    Ok(OutputArtifactMetadata {
        path: path.to_string_lossy().into_owned(),
        size_bytes: digest.size_bytes,
        sha256: digest.hex,
    })
}

fn redact_argument(argument: &str) -> String {
    if let Some(rest) = argument.strip_prefix("-J")
        && let Some((key, _)) = rest.split_once('=')
    {
        return format!("-J{}=<redacted>", key);
    }
    argument.to_owned()
}

fn redact_text(value: &str) -> String {
    const LIMIT: usize = 4096;
    let mut result = String::new();
    for line in value.lines() {
        let lower = line.to_ascii_lowercase();
        if [
            "password",
            "passwd",
            "secret",
            "token",
            "authorization",
            "credential",
            "private_key",
        ]
        .iter()
        .any(|needle| lower.contains(needle))
        {
            result.push_str("<redacted sensitive output>");
        } else {
            result.push_str(line);
        }
        result.push('\n');
        if result.len() >= LIMIT {
            break;
        }
    }
    result.truncate(LIMIT);
    result
}

/// Serialize machine-readable metadata.
pub fn metadata_json<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string_pretty(value).map_err(|error| {
        OracleError::new(
            ErrorCode::Internal,
            format!("serialize metadata: {}", error),
        )
    })
}

/// Parse a positive unsigned CLI value.
pub fn parse_positive_u64(value: &str, option: &str) -> Result<u64> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| configuration_error(format!("{} must be an unsigned integer", option)))?;
    if parsed == 0 {
        return Err(configuration_error(format!(
            "{} must be greater than zero",
            option
        )));
    }
    Ok(parsed)
}

/// Return a validation report that explicitly makes no conformance claim.
pub fn validation_json(bundle: &ValidatedCase, artifact: Option<&ArtifactMetadata>) -> Value {
    json!({
        "status": "validated",
        "profile_id": bundle.profile().profile_id(),
        "case_id": bundle.case().case_id(),
        "fixture_dir": bundle.fixture_dir().to_string_lossy(),
        "plan_sha256": bundle.plan_sha256(),
        "property_sha256": bundle.property_sha256(),
        "command_template_count": bundle.case().command_templates().len(),
        "artifact": artifact,
        "conformance_claim": "none"
    })
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures use assertion-context panics only"
)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::fs;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let root = std::env::temp_dir();
            for index in 0..100_u32 {
                let path = root.join(format!(
                    "jmeter-oracle-test-{}-{}",
                    std::process::id(),
                    index
                ));
                if fs::create_dir(&path).is_ok() {
                    return Self { path };
                }
            }
            panic!("cannot allocate test directory");
        }

        fn write(&self, relative: &str, contents: &str) -> PathBuf {
            let path = self.path.join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("test parent");
            }
            fs::write(&path, contents).expect("test file");
            path
        }

        fn write_json(&self, relative: &str, value: &Value) -> PathBuf {
            self.write(
                relative,
                &serde_json::to_string_pretty(value).expect("json"),
            )
        }

        #[cfg(unix)]
        fn executable(&self, relative: &str, contents: &str) -> PathBuf {
            let path = self.write(relative, contents);
            let mut permissions = fs::metadata(&path).expect("metadata").permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&path, permissions).expect("permissions");
            path
        }

        #[cfg(not(unix))]
        fn executable(&self, relative: &str, contents: &str) -> PathBuf {
            self.write(relative, contents)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn sha256_text(value: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(value.as_bytes());
        to_hex(&hasher.finalize())
    }

    fn sha512_text(value: &str) -> String {
        let mut hasher = Sha512::new();
        hasher.update(value.as_bytes());
        to_hex(&hasher.finalize())
    }

    fn profile_document(artifact_digest: &str) -> Value {
        json!({
            "schema_id": PROFILE_SCHEMA_ID,
            "schema_version": 1,
            "profile_id": SUPPORTED_PROFILE_ID,
            "upstream": {
                "project": "Apache JMeter",
                "version": "5.6.3",
                "artifact": {
                    "filename": "oracle.zip",
                    "format": "zip",
                    "digest_algorithm": "SHA-512",
                    "digest": artifact_digest,
                    "url": "https://example.invalid/oracle.zip",
                    "digest_url": "https://example.invalid/oracle.zip.sha512"
                }
            },
            "runtime_assumptions": {
                "determinism": {
                    "locale": "C",
                    "timezone": "UTC",
                    "default_charset": "UTF-8",
                    "environment_allowlist": []
                }
            },
            "oracle_fixture_catalog": [{"id": "FX-TEST"}],
            "normalization_policies": [{"id": "NORM-TEST"}],
            "external_runtime_boundaries": [],
            "features": [{
                "id": "TEST-001",
                "required_oracle_fixture_ids": ["FX-TEST"],
                "normalization_policy_refs": ["NORM-TEST"],
                "external_runtime_boundary_ids": []
            }],
            "unknown_extension": {"preserve": [1, 2, 3]}
        })
    }

    fn case_document(plan_sha: &str, property_sha: &str) -> Value {
        json!({
            "schema_id": CASE_SCHEMA_ID,
            "schema_version": 1,
            "case_id": "ORACLE-TEST",
            "profile_id": SUPPORTED_PROFILE_ID,
            "fixture_family_id": "FX-TEST",
            "conformance_ids": ["TEST-001"],
            "normalization_policy_refs": ["NORM-TEST"],
            "plan": {"path": "plan.jmx", "sha256": plan_sha},
            "property_files": [{"path": "oracle.properties", "sha256": property_sha}],
            "command": {
                "mode": "nongui",
                "argv_template": [
                    "jmeter", "-n", "-q", "oracle.properties", "-t", "plan.jmx",
                    "-l", "<ignored>/oracle.jtl", "-j", "<ignored>/oracle.log",
                    "-Jsafe=value"
                ]
            },
            "unknown_extension": {"preserve": true}
        })
    }

    fn fixture() -> (TempDir, PathBuf, PathBuf, PathBuf) {
        let temp = TempDir::new();
        let plan_contents = "<jmeterTestPlan/>\n";
        let property_contents = "sample_variables=x\n";
        let _plan = temp.write("plan.jmx", plan_contents);
        temp.write("oracle.properties", property_contents);
        let artifact_contents = "not-a-real-archive-for-unit-test";
        let artifact = temp.write("oracle.zip", artifact_contents);
        let profile = temp.write_json(
            "profile.json",
            &profile_document(&sha512_text(artifact_contents)),
        );
        let case_file = temp.write_json(
            "case.json",
            &case_document(&sha256_text(plan_contents), &sha256_text(property_contents)),
        );
        (temp, profile, case_file, artifact)
    }

    #[test]
    fn active_profile_and_fixture_cases_validate_without_loss() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile_path = root.join("../../compat/profiles/jmeter-5.6.3.json");
        let profile = ProfileManifest::load(&profile_path).expect("active profile");
        assert_eq!(profile.profile_id(), SUPPORTED_PROFILE_ID);
        assert!(profile.document().get("claim_policy").is_some());
        for name in [
            "lifecycle-debug",
            "controllers",
            "assertion-failure",
            "jtl-fields",
            "jmx-topology/no-drop-boundaries",
        ] {
            let case_path = root.join(format!(
                "../../compat/fixtures/jmeter-5.6.3/{}/case.json",
                name
            ));
            let fixture_dir = case_path.parent().expect("case parent");
            let case = CaseManifest::load(&case_path).expect("active case");
            let bundle =
                ValidatedCase::new(profile.clone(), case, fixture_dir).expect("fixture hashes");
            assert!(!bundle.plan_sha256().is_empty());
        }
    }

    #[test]
    fn target_triple_validation_is_bounded_and_serializes_as_text() {
        let triple = TargetTriple::parse("x86_64-unknown-linux-gnu").expect("target triple");
        assert_eq!(triple.as_str(), "x86_64-unknown-linux-gnu");
        assert_eq!(
            serde_json::to_value(&triple).expect("serialized triple"),
            json!("x86_64-unknown-linux-gnu")
        );
        assert!(TargetTriple::parse("x").is_err());
        assert!(TargetTriple::parse(&"x".repeat(MAX_TARGET_TRIPLE_BYTES + 1)).is_err());
        assert!(TargetTriple::parse("x86 64-unknown-linux-gnu").is_err());
        assert!(TargetTriple::parse("x86_64-unknown-linux-😀").is_err());
    }

    #[test]
    fn compile_target_triple_is_an_exact_supported_identity() {
        let triple = compile_target_triple().expect("supported compile target");
        assert!(matches!(
            triple.as_str(),
            "x86_64-unknown-linux-gnu"
                | "aarch64-unknown-linux-gnu"
                | "x86_64-unknown-linux-musl"
                | "aarch64-unknown-linux-musl"
                | "x86_64-apple-darwin"
                | "aarch64-apple-darwin"
                | "x86_64-pc-windows-msvc"
                | "aarch64-pc-windows-msvc"
                | "x86_64-pc-windows-gnu"
                | "aarch64-pc-windows-gnu"
        ));
    }

    #[test]
    fn run_metadata_serializes_exact_target_triple_field() {
        let metadata = RunMetadata {
            profile_id: SUPPORTED_PROFILE_ID.to_owned(),
            case_id: "ORACLE-TEST".to_owned(),
            template_index: 0,
            argv: Vec::new(),
            environment_keys: Vec::new(),
            working_directory: "/tmp/oracle".to_owned(),
            target_os: "linux".to_owned(),
            target_arch: "x86_64".to_owned(),
            target_triple: TargetTriple::parse("x86_64-unknown-linux-gnu").expect("target triple"),
            locale: "C".to_owned(),
            timezone: "UTC".to_owned(),
            default_charset: "UTF-8".to_owned(),
            artifact: ArtifactMetadata {
                path: "/tmp/oracle.zip".to_owned(),
                filename: "oracle.zip".to_owned(),
                size_bytes: 0,
                sha512: "0".repeat(128),
            },
            jmeter_sha256: "0".repeat(64),
            java: JavaMetadata {
                executable: "/bin/java".to_owned(),
                executable_sha256: "0".repeat(64),
                exit_code: Some(0),
                version_output: String::new(),
            },
            process_exit: Some(0),
            stdout: OutputMetadata {
                size_bytes: 0,
                sha256: "0".repeat(64),
                preview: String::new(),
            },
            stderr: OutputMetadata {
                size_bytes: 0,
                sha256: "0".repeat(64),
                preview: String::new(),
            },
            result: OutputArtifactMetadata {
                path: "/tmp/oracle.jtl".to_owned(),
                size_bytes: 0,
                sha256: "0".repeat(64),
            },
            log: OutputArtifactMetadata {
                path: "/tmp/oracle.log".to_owned(),
                size_bytes: 0,
                sha256: "0".repeat(64),
            },
        };
        let encoded = serde_json::to_value(metadata).expect("run metadata");
        assert_eq!(encoded["target_triple"], json!("x86_64-unknown-linux-gnu"));
    }

    #[test]
    fn old_run_diagnostic_may_omit_target_triple() {
        let old: RunMetadataDiagnostic =
            serde_json::from_str(r#"{"target_os":"linux","target_arch":"x86_64","locale":"C"}"#)
                .expect("old diagnostic");
        assert_eq!(old.target_os.as_deref(), Some("linux"));
        assert_eq!(old.target_arch.as_deref(), Some("x86_64"));
        assert_eq!(old.target_triple, None);

        let current: RunMetadataDiagnostic =
            serde_json::from_str(r#"{"target_triple":"aarch64-apple-darwin","future_field":true}"#)
                .expect("current diagnostic");
        assert_eq!(
            current.target_triple.as_ref().map(TargetTriple::as_str),
            Some("aarch64-apple-darwin")
        );
        assert!(
            serde_json::from_str::<RunMetadataDiagnostic>(r#"{"target_triple":"not a triple"}"#)
                .is_err()
        );
    }

    #[test]
    fn unknown_manifest_fields_are_retained() {
        let (temp, profile_path, case_path, _artifact) = fixture();
        let profile = ProfileManifest::load(profile_path).expect("profile");
        let case = CaseManifest::load(case_path).expect("case");
        assert_eq!(profile.document()["unknown_extension"]["preserve"][1], 2);
        assert_eq!(case.document()["unknown_extension"]["preserve"], true);
        ValidatedCase::new(profile, case, temp.path.clone()).expect("fixture");
    }

    #[test]
    fn traversal_gui_and_unsupported_options_fail_closed() {
        let (temp, profile_path, case_path, _artifact) = fixture();
        let mut value: Value =
            serde_json::from_str(&fs::read_to_string(&case_path).expect("case")).expect("json");
        value["plan"]["path"] = Value::String("../plan.jmx".to_owned());
        temp.write_json("case-traversal.json", &value);
        let error =
            CaseManifest::load(temp.path.join("case-traversal.json")).expect_err("traversal");
        assert_eq!(error.code(), ErrorCode::ManifestSchema);

        value["plan"]["path"] = Value::String("plan.jmx".to_owned());
        value["command"]["mode"] = Value::String("gui".to_owned());
        temp.write_json("case-gui.json", &value);
        let error = CaseManifest::load(temp.path.join("case-gui.json")).expect_err("gui");
        assert_eq!(error.code(), ErrorCode::ManifestSchema);

        value["command"]["mode"] = Value::String("nongui".to_owned());
        value["command"]["argv_template"]
            .as_array_mut()
            .expect("args")
            .push(Value::String("-x".to_owned()));
        temp.write_json("case-option.json", &value);
        let error = CaseManifest::load(temp.path.join("case-option.json")).expect_err("option");
        assert_eq!(error.code(), ErrorCode::ManifestSchema);
        let _ = profile_path;
    }

    #[test]
    fn command_materialization_and_dry_run_redact_values() {
        let (temp, profile_path, case_path, artifact_path) = fixture();
        let bundle = OracleRunner::validate(&profile_path, &case_path, &temp.path).expect("bundle");
        let launcher = temp.executable("bin/jmeter", "#!/bin/sh\nexit 0\n");
        let artifact = verify_artifact(bundle.profile(), &artifact_path).expect("digest");
        let request = RunRequest {
            fixture: bundle,
            jmeter_path: launcher,
            java_path: None,
            artifact: Some(artifact),
            output_root: Some(temp.path.join("outputs")),
            limits: RunnerLimits::default(),
            template_index: None,
        };
        let reports = OracleRunner.dry_run(&request).expect("dry run");
        assert_eq!(reports.len(), 1);
        assert_eq!(
            reports[0].argv.last().map(String::as_str),
            Some("-Jsafe=<redacted>")
        );
        assert!(!reports[0].environment_keys.contains(&"HOME".to_owned()));
    }

    #[cfg(unix)]
    #[test]
    fn fake_java_and_jmeter_execute_with_bounded_metadata() {
        let (temp, profile_path, case_path, artifact_path) = fixture();
        let bundle = OracleRunner::validate(&profile_path, &case_path, &temp.path).expect("bundle");
        let java = temp.executable(
            "bin/java",
            "#!/bin/sh\necho 'openjdk version 17' >&2\ni=0\nwhile [ \"$i\" -lt 100000 ]; do i=$((i + 1)); done\nexit 0\n",
        );
        let jmeter = temp.executable(
            "bin/jmeter",
            "#!/bin/sh\nresult=''\nlog=''\nwhile [ \"$#\" -gt 0 ]; do\n  case \"$1\" in\n    -l) result=\"$2\"; shift 2;;\n    -j) log=\"$2\"; shift 2;;\n    *) shift;;\n  esac\ndone\nprintf 'sample\\n' > \"$result\"\nprintf 'log\\n' > \"$log\"\nprintf 'visible output\\n'\ni=0\nwhile [ \"$i\" -lt 100000 ]; do i=$((i + 1)); done\n",
        );
        let artifact = verify_artifact(bundle.profile(), &artifact_path).expect("digest");
        let request = RunRequest {
            fixture: bundle,
            jmeter_path: jmeter,
            java_path: Some(java),
            artifact: Some(artifact),
            output_root: Some(temp.path.join("outputs")),
            limits: RunnerLimits {
                timeout: Duration::from_secs(5),
                max_process_output_bytes: 4096,
                max_artifact_bytes: 4096,
            },
            template_index: Some(0),
        };
        let reports = OracleRunner.run(&request).expect("run");
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].process_exit, Some(0));
        assert_eq!(reports[0].result.size_bytes, 7);
        assert!(reports[0].java.version_output.contains("openjdk"));
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "run only through tests/pid_namespace.sh"]
    fn timeout_returns_error_after_process_group_cleanup() {
        let namespace = fs::read_link("/proc/self/ns/pid").expect("self PID namespace");
        let user_namespace = fs::read_link("/proc/self/ns/user").expect("self user namespace");
        let pid_one_user_namespace =
            fs::read_link("/proc/1/ns/user").expect("namespace PID 1 user identity");
        assert_eq!(user_namespace, pid_one_user_namespace);
        let pid_one_namespace = fs::read_link("/proc/1/ns/pid").expect("namespace PID 1 identity");
        assert_eq!(namespace, pid_one_namespace);
        let status = fs::read_to_string("/proc/self/status").expect("self status");
        let nspid_fields = status
            .lines()
            .find_map(|line| line.strip_prefix("NSpid:").map(str::split_whitespace))
            .map_or(0, Iterator::count);
        assert!(nspid_fields >= 2, "test must run in a nested PID namespace");
        let pid_one_status = fs::read_to_string("/proc/1/status").expect("PID 1 status");
        let pid_one_nspid = pid_one_status
            .lines()
            .find_map(|line| line.strip_prefix("NSpid:").map(str::split_whitespace))
            .and_then(|mut values| values.next_back())
            .and_then(|value| value.parse::<u32>().ok());
        assert_eq!(pid_one_nspid, Some(1));
        let mountinfo = fs::read_to_string("/proc/self/mountinfo").expect("mountinfo");
        assert!(
            mountinfo
                .lines()
                .any(|line| line.contains(" - proc /proc "))
        );
        let uid_map = fs::read_to_string("/proc/self/uid_map").expect("uid map");
        let uid_fields = uid_map.split_whitespace().collect::<Vec<_>>();
        assert!(uid_fields.len() >= 3 && uid_fields[0] == "0" && uid_fields[1] == "0");
        let gid_map = fs::read_to_string("/proc/self/gid_map").expect("gid map");
        let gid_fields = gid_map.split_whitespace().collect::<Vec<_>>();
        assert!(gid_fields.len() >= 3 && gid_fields[0] == "0" && gid_fields[1] == "0");
        let proof = std::env::var("JMT_PID_NAMESPACE_PROOF_TOKEN")
            .expect("run this test through the verified PID namespace wrapper");
        let prefix = format!("jmeter-rs-pidns-v1:{}:1:", namespace.display());
        let nonce = proof
            .strip_prefix(&prefix)
            .expect("namespace proof token is missing or bound to another namespace");
        assert_eq!(nonce.len(), 36, "namespace proof nonce is malformed");
        assert!(
            nonce
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b'-'),
            "namespace proof nonce is malformed",
        );
        let _namespace_proof_complete = proof;
        let (temp, profile_path, case_path, artifact_path) = fixture();
        let bundle = OracleRunner::validate(&profile_path, &case_path, &temp.path).expect("bundle");
        let java = temp.executable("bin/java", "#!/bin/sh\necho 'openjdk version 17' >&2\n");
        let jmeter = temp.executable("bin/jmeter", "#!/bin/sh\nwhile :; do :; done\n");
        let artifact = verify_artifact(bundle.profile(), &artifact_path).expect("digest");
        let output_root_path = temp.path.join("timeout-output");
        fs::create_dir_all(&output_root_path).expect("output root");
        let output =
            create_output_dir(&output_root_path, "ORACLE-TEST", 0).expect("output directory");
        let command = bundle
            .materialize_command(0, &jmeter, &output)
            .expect("command");
        let environment = build_environment(&bundle, Some(&java)).expect("environment");
        let limits = RunnerLimits {
            timeout: Duration::from_millis(50),
            max_process_output_bytes: 4096,
            max_artifact_bytes: 4096,
        };
        let error = execute_jmeter_with_cleanup(
            &command,
            &environment,
            &limits,
            ChildCleanup::ProcessGroup,
        )
        .expect_err("timeout");
        assert_eq!(error.code(), ErrorCode::Timeout);
        let _ = artifact;
    }

    #[cfg(unix)]
    #[test]
    fn child_output_bound_is_enforced_before_artifact_comparison() {
        let (temp, profile_path, case_path, artifact_path) = fixture();
        let bundle = OracleRunner::validate(&profile_path, &case_path, &temp.path).expect("bundle");
        let java = temp.executable("bin/java", "#!/bin/sh\necho 'openjdk version 17' >&2\n");
        let jmeter = temp.executable(
            "bin/jmeter",
            "#!/bin/sh\nprintf '0123456789abcdef0123456789abcdef\\n'\n",
        );
        let artifact = verify_artifact(bundle.profile(), &artifact_path).expect("digest");
        let output_root_path = temp.path.join("output-bound");
        fs::create_dir_all(&output_root_path).expect("output root");
        let output = create_output_dir(&output_root_path, "ORACLE-TEST", 0).expect("output");
        let command = bundle
            .materialize_command(0, &jmeter, &output)
            .expect("command");
        let environment = build_environment(&bundle, Some(&java)).expect("environment");
        // This ordinary output-limit regression deliberately uses direct
        // child cleanup.  Process-group signalling is covered only by the
        // ignored PID-namespace timeout test above.
        let error = execute_jmeter_with_cleanup(
            &command,
            &environment,
            &RunnerLimits {
                timeout: Duration::from_secs(5),
                max_process_output_bytes: 8,
                max_artifact_bytes: 4096,
            },
            ChildCleanup::DirectChild,
        )
        .expect_err("output bound");
        assert_eq!(error.code(), ErrorCode::OutputLimit);
        let _ = artifact;
    }

    #[test]
    fn limits_and_artifact_mismatch_fail_closed() {
        let (temp, profile_path, case_path, artifact_path) = fixture();
        let profile = ProfileManifest::load(&profile_path).expect("profile");
        let limits = RunnerLimits {
            timeout: Duration::ZERO,
            ..RunnerLimits::default()
        };
        assert_eq!(
            limits.validate().expect_err("zero timeout").code(),
            ErrorCode::Configuration
        );
        let wrong = temp.write("wrong.zip", "wrong");
        let error = verify_artifact(&profile, wrong).expect_err("wrong digest");
        assert_eq!(error.code(), ErrorCode::DigestMismatch);
        let _ = artifact_path;
        let _ = case_path;
    }

    #[cfg(unix)]
    #[test]
    fn exited_child_is_reaped_without_a_signal() {
        let mut child = Command::new("/bin/echo")
            .arg("exited")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn short-lived child");
        let mut output = String::new();
        child
            .stdout
            .take()
            .expect("echo stdout pipe")
            .read_to_string(&mut output)
            .expect("read exited child output");
        assert_eq!(output, "exited\n");
        cleanup_child(&mut child, ChildCleanup::DirectChild).expect("exited child cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn process_group_id_rejects_kernel_and_conversion_unsafe_values() {
        assert!(ProcessGroupId::try_from(0).is_err());
        assert!(ProcessGroupId::try_from(1).is_err());
        assert!(ProcessGroupId::try_from(i32::MAX as u32).is_ok());
        assert!(ProcessGroupId::try_from(i32::MAX as u32 + 1).is_err());
        assert!(ProcessGroupId::try_from(u32::MAX).is_err());
    }

    #[cfg(not(unix))]
    #[test]
    fn process_group_cleanup_is_explicitly_unsupported_on_non_unix() {
        let mut command = Command::new("jmeter");
        let error = configure_process_cleanup(&mut command, ChildCleanup::ProcessGroup)
            .expect_err("non-Unix process tree");
        assert_eq!(error.code(), ErrorCode::UnsupportedPlatform);
    }

    #[cfg(unix)]
    #[test]
    fn missing_stdout_pipe_is_cleaned_by_owned_direct_child_guard() {
        let mut command = Command::new("/bin/true");
        command.stdout(Stdio::null());
        command.stderr(Stdio::piped());
        let error = execute_spawned(
            command,
            &BTreeMap::new(),
            &RunnerLimits::default(),
            &[],
            ChildCleanup::DirectChild,
        )
        .expect_err("missing stdout pipe");
        assert_eq!(error.code(), ErrorCode::Internal);
    }

    #[cfg(unix)]
    #[test]
    fn missing_stderr_pipe_is_cleaned_by_owned_direct_child_guard() {
        let mut command = Command::new("/bin/true");
        command.stdout(Stdio::piped());
        command.stderr(Stdio::null());
        let error = execute_spawned(
            command,
            &BTreeMap::new(),
            &RunnerLimits::default(),
            &[],
            ChildCleanup::DirectChild,
        )
        .expect_err("missing stderr pipe");
        assert_eq!(error.code(), ErrorCode::Internal);
    }

    #[derive(Debug)]
    struct FakeChild {
        waits: VecDeque<io::Result<Option<ExitStatus>>>,
        kill_error: Option<io::ErrorKind>,
        kill_count: usize,
    }

    impl FakeChild {
        fn new(waits: impl IntoIterator<Item = io::Result<Option<ExitStatus>>>) -> Self {
            Self {
                waits: waits.into_iter().collect(),
                kill_error: None,
                kill_count: 0,
            }
        }
    }

    impl ChildOps for FakeChild {
        fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
            self.waits.pop_front().unwrap_or(Ok(None))
        }

        fn kill(&mut self) -> io::Result<()> {
            self.kill_count += 1;
            match self.kill_error {
                Some(kind) => Err(io::Error::new(kind, "injected direct cleanup failure")),
                None => Ok(()),
            }
        }

        #[cfg(unix)]
        fn validate_group(&mut self, expected: ProcessGroupId) -> Result<ProcessGroupId> {
            Ok(expected)
        }
    }

    #[test]
    fn cleanup_failure_seam_reports_direct_kill_error_without_group_signal() {
        let mut child = FakeChild::new([Ok(None), Ok(None)]);
        child.kill_error = Some(io::ErrorKind::PermissionDenied);
        let error = cleanup_child_with(&mut child, ChildCleanup::DirectChild, None, |_| {
            panic!("direct cleanup must not invoke group signal seam")
        })
        .expect_err("injected direct cleanup failure");
        assert_eq!(error.code(), ErrorCode::Process);
        assert_eq!(child.kill_count, 1);
    }

    #[test]
    fn cleanup_retry_seam_is_bounded_without_blocking_or_signalling() {
        let mut child = FakeChild::new([Ok(None), Ok(None), Ok(None)]);
        let mut attempts = 0;
        let error = retry_cleanup_with(
            &mut child,
            3,
            |_child| {
                attempts += 1;
                Err(OracleError::new(
                    ErrorCode::Process,
                    "injected retry failure",
                ))
            },
            |_delay| {},
        )
        .expect_err("bounded retry failure");
        assert_eq!(error.code(), ErrorCode::Process);
        assert_eq!(attempts, 3);
        assert_eq!(child.kill_count, 0);
    }

    #[test]
    fn zero_cleanup_retries_fail_as_configuration_without_touching_child() {
        let mut child = FakeChild::new([]);
        let error = retry_cleanup_with(&mut child, 0, |_child| unreachable!(), |_delay| {})
            .expect_err("zero retries");
        assert_eq!(error.code(), ErrorCode::Configuration);
        assert_eq!(child.kill_count, 0);
    }

    #[test]
    fn cleanup_registry_reserves_capacity_before_a_child_exists() {
        let registry: CleanupRegistry<FakeChild> = CleanupRegistry::with_capacity(1);
        let reservation = registry.reserve().expect("first reservation");
        let error = match registry.reserve() {
            Ok(_) => panic!("capacity must be bounded"),
            Err(error) => error,
        };
        assert_eq!(error.code(), ErrorCode::ReaperCapacity);
        drop(reservation);
        registry.reserve().expect("released reservation");
    }

    #[test]
    fn cleanup_diagnostics_preserve_primary_error_code_and_secondary_detail() {
        let primary = OracleError::new(ErrorCode::Timeout, "operation timed out");
        let cleanup = OracleError::new(
            ErrorCode::ContainmentLost,
            "root exited before tree cleanup",
        )
        .with_kind(ProcessErrorKind::RootExitedBeforeTreeCleanup);
        let combined = combine_cleanup_errors(primary, Some(cleanup));
        assert_eq!(combined.code(), ErrorCode::Timeout);
        assert_eq!(
            combined.secondary().and_then(OracleError::kind),
            Some(ProcessErrorKind::RootExitedBeforeTreeCleanup)
        );
    }

    #[cfg(unix)]
    #[test]
    fn exited_root_before_tree_cleanup_is_containment_loss_without_group_signal() {
        use std::os::unix::process::ExitStatusExt;

        let status = ExitStatus::from_raw(0);
        let mut child = FakeChild::new([Ok(Some(status))]);
        let mut signalled = false;
        let error = cleanup_child_with(
            &mut child,
            ChildCleanup::ProcessGroup,
            Some(ProcessGroupId(42)),
            |_group| {
                signalled = true;
                Ok(())
            },
        )
        .expect_err("exited root must not claim tree cleanup");
        assert_eq!(error.code(), ErrorCode::ContainmentLost);
        assert_eq!(
            error.kind(),
            Some(ProcessErrorKind::RootExitedBeforeTreeCleanup)
        );
        assert!(!signalled);
        assert_eq!(child.kill_count, 0);
    }

    #[cfg(unix)]
    #[test]
    fn injected_reaper_spawn_failure_has_bounded_fallback_and_typed_failure() {
        use std::os::unix::process::ExitStatusExt;

        let status = ExitStatus::from_raw(0);
        let mut eventually_reaped = FakeChild::new([Ok(None), Ok(Some(status))]);
        fallback_after_handoff_failure_with(
            &mut eventually_reaped,
            OracleError::new(ErrorCode::Internal, "injected reaper spawn failure"),
            2,
            |_child| {
                Err(OracleError::new(
                    ErrorCode::Process,
                    "injected cleanup failure",
                ))
            },
            |_delay| {},
        )
        .expect("bounded fallback observes eventual reap");
        assert_eq!(eventually_reaped.kill_count, 0);

        let mut still_live = FakeChild::new([Ok(None), Ok(None), Ok(None), Ok(None)]);
        let error = fallback_after_handoff_failure_with(
            &mut still_live,
            OracleError::new(ErrorCode::Internal, "injected reaper spawn failure"),
            2,
            |_child| {
                Err(OracleError::new(
                    ErrorCode::Process,
                    "injected cleanup failure",
                ))
            },
            |_delay| {},
        )
        .expect_err("bounded fallback failure");
        assert_eq!(error.code(), ErrorCode::Internal);
        assert!(error.message().contains("injected reaper spawn failure"));
    }

    #[cfg(unix)]
    #[test]
    fn retained_cleanup_registry_eventually_reaps_or_surfaces_typed_failure() {
        use std::os::unix::process::ExitStatusExt;

        let status = ExitStatus::from_raw(0);
        let registry = CleanupRegistry::new();
        registry
            .retain(
                FakeChild::new([Ok(None), Ok(Some(status))]),
                ChildCleanup::DirectChild,
                None,
                OracleError::new(ErrorCode::Process, "initial retained cleanup failure"),
            )
            .expect("reserve registry slot");
        registry
            .service_with(
                2,
                |_child, _cleanup, _group| {
                    Err(OracleError::new(
                        ErrorCode::Process,
                        "injected retained cleanup failure",
                    ))
                },
                |_delay| {},
            )
            .expect("registry retries until exact child is reaped");
        assert_eq!(registry.len(), 0);

        registry
            .retain(
                FakeChild::new([Ok(None), Ok(None), Ok(None), Ok(None)]),
                ChildCleanup::DirectChild,
                None,
                OracleError::new(ErrorCode::Process, "initial retained cleanup failure"),
            )
            .expect("reserve registry slot");
        let error = registry
            .service_with(
                2,
                |_child, _cleanup, _group| {
                    Err(OracleError::new(
                        ErrorCode::Process,
                        "injected retained cleanup failure",
                    ))
                },
                |_delay| {},
            )
            .expect_err("registry failure");
        assert_eq!(error.code(), ErrorCode::Process);
        assert_eq!(registry.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn process_group_failure_falls_back_to_exact_child_and_reap() {
        use std::os::unix::process::ExitStatusExt;

        let status = ExitStatus::from_raw(0);
        let mut child = FakeChild::new([Ok(None), Ok(None), Ok(Some(status))]);
        let mut group_id = None;
        let error = cleanup_child_with(
            &mut child,
            ChildCleanup::ProcessGroup,
            Some(ProcessGroupId(42)),
            |id| {
                group_id = Some(id);
                Err(OracleError::new(
                    ErrorCode::Process,
                    "injected group cleanup failure",
                ))
            },
        )
        .expect_err("group failure remains observable");
        assert_eq!(error.code(), ErrorCode::ContainmentLost);
        assert_eq!(child.kill_count, 1);
        assert!(group_id.is_some_and(|id| id.is_some_and(|id| id.as_raw() > 1)));
    }

    #[cfg(unix)]
    #[test]
    fn reader_cancellation_is_bounded_when_writer_remains_open() {
        use std::os::unix::net::UnixStream;

        let (reader, writer) = UnixStream::pair().expect("socket pair");
        let capture = StreamCapture::new(64);
        let mut handle = spawn_process_reader(reader, "bounded").expect("reader");
        handle.cancel();
        handle
            .finish(&capture)
            .expect("bounded reader cancellation");
        drop(writer);
    }
}
