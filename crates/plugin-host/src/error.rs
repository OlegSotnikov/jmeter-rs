// SPDX-License-Identifier: Apache-2.0

use std::{fmt, path::PathBuf};

/// Maximum UTF-8 bytes retained from one plugin diagnostic.
///
/// Error codes are the compatibility surface.  Detail is only bounded
/// diagnostic context and may contain untrusted worker, manifest, or OS text.
pub const MAX_ERROR_DETAIL_BYTES: usize = 4 * 1024;
/// Alias naming the plugin boundary explicitly for callers that expose
/// multiple error domains from one application.
pub const MAX_PLUGIN_ERROR_DETAIL_BYTES: usize = MAX_ERROR_DETAIL_BYTES;

/// Maximum UTF-8 bytes retained for a diagnostic filesystem path.
///
/// Paths are retained only for internal, source-location-aware diagnostics;
/// [`Debug`] and [`Display`] never expose them.
pub const MAX_ERROR_PATH_BYTES: usize = 4 * 1024;
/// Alias naming the plugin boundary explicitly.
pub const MAX_PLUGIN_ERROR_PATH_BYTES: usize = MAX_ERROR_PATH_BYTES;

/// Maximum number of secondary failures retained by one plugin error.
///
/// A failure storm must not turn cleanup/error reporting into an unbounded
/// allocation.  The omitted count remains observable through
/// [`PluginError::secondary_omitted_count`].
pub const MAX_SECONDARY_ERRORS: usize = 32;
/// Alias for the generic error-bound spelling.
pub const MAX_ERROR_SECONDARY_ERRORS: usize = MAX_SECONDARY_ERRORS;
/// Alias naming the plugin boundary explicitly.
pub const MAX_PLUGIN_ERROR_SECONDARY_ERRORS: usize = MAX_SECONDARY_ERRORS;

/// Closed retryability classification for a plugin operation or cleanup
/// attempt.
///
/// `Retryable` is a classification of a bounded operation whose state machine
/// has proved that trying again can make progress.  It is not a peer-provided
/// boolean and does not authorize replay after useful plugin work may have
/// started.  `Unknown` is deliberately conservative for worker timeouts,
/// crashes, and I/O failures whose execution boundary is uncertain.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Retryability {
    /// The operation's replay safety is not proven.
    Unknown,
    /// A bounded retry may make progress at the current state boundary.
    Retryable,
    /// Retrying is forbidden or cannot make progress.
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

    /// Returns whether this value classifies a retry as safe at the current
    /// operation boundary.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::Retryable)
    }
}

impl fmt::Display for Retryability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Retains a diagnostic string without allowing hostile input to grow an
/// error object without bound.  The ellipsis is included only when there is
/// room for it and truncation always occurs at a UTF-8 boundary.
fn bounded_text(value: &str, maximum: usize) -> String {
    if value.len() <= maximum {
        return value.to_owned();
    }

    let marker = "…";
    let content_maximum = maximum.saturating_sub(marker.len());
    let prefix = utf8_prefix(value, content_maximum);
    let mut bounded = String::with_capacity(prefix.len().saturating_add(marker.len()));
    bounded.push_str(prefix);
    if maximum >= marker.len() {
        bounded.push_str(marker);
    }
    bounded
}

/// Returns a prefix no longer than `maximum` bytes and ending at a UTF-8
/// boundary.  The returned slice borrows the caller's already-bounded input;
/// no allocation is proportional to an untrusted suffix.
fn utf8_prefix(value: &str, maximum: usize) -> &str {
    let mut end = maximum.min(value.len());
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

/// Stable machine-readable outcomes produced by the plugin boundary.
///
/// Display text is diagnostic only.  Callers that need to make a compatibility
/// decision must use [`PluginError::code`].  In particular, `plugin.unavailable`
/// and `jmx.invalid` are intentionally different outcomes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PluginErrorCode {
    /// The configured discovery directory is not an allowed directory.
    DiscoveryDirectory,
    /// A directory entry could not be inspected.
    DiscoveryIo,
    /// Discovery inspected more directory entries than its bounded budget.
    DiscoveryEntryLimit,
    /// Discovery admitted more total manifest bytes than its bounded budget.
    DiscoveryManifestBytesLimit,
    /// Discovery admitted more validated descriptors than its bounded budget.
    DiscoveryDescriptorLimit,
    /// Discovery admitted more capabilities than its bounded budget.
    DiscoveryCapabilityLimit,
    /// Discovery produced more diagnostics than its bounded budget.
    DiscoveryDiagnosticLimit,
    /// A discovered path exceeded the configured path-byte budget.
    DiscoveryPathLimit,
    /// A manifest exceeded the configured input bound.
    ManifestTooLarge,
    /// A manifest could not be read.
    ManifestIo,
    /// A manifest was not valid JSON or did not have the expected shape.
    ManifestParse,
    /// A manifest field violated a domain invariant.
    ManifestInvalid,
    /// A symlink was encountered where the policy forbids it.
    SymlinkNotAllowed,
    /// A resolved path leaves the configured allowlisted root.
    PathOutsideRoot,
    /// A declared executable does not exist.
    ExecutableMissing,
    /// A declared executable is not a regular file.
    ExecutableNotFile,
    /// A declared executable cannot be run by the host policy.
    ExecutableNotExecutable,
    /// A declared executable exceeds the deterministic identity-read byte budget.
    ExecutableTooLarge,
    /// Reading an executable exceeded the deterministic identity-read operation budget.
    ExecutableReadLimit,
    /// A validated executable changed before process creation.
    ExecutableChanged,
    /// Stable executable launch identity is unavailable on this platform.
    ExecutableLaunchUnsupported,
    /// Two manifests declare the same stable plugin ID.
    DuplicatePluginId,
    /// Two capabilities claim the same alias or canonical name.
    DuplicateCapabilityAlias,
    /// The host and plugin protocol ranges do not overlap.
    ProtocolMismatch,
    /// The requested compatibility profile is not declared by the plugin.
    ProfileMismatch,
    /// The requested element/function is not declared by the plugin.
    CapabilityMismatch,
    /// A declared plugin classpath root or artifact is unavailable.
    PluginClasspathUnavailable,
    /// More than one plugin declaration resolves the requested alias.
    PluginAliasAmbiguous,
    /// A requested plugin class is unavailable.
    PluginClassUnavailable,
    /// A requested plugin element is unavailable.
    PluginElementUnavailable,
    /// A requested plugin function is unavailable.
    PluginFunctionUnavailable,
    /// The plugin process could not be started or is otherwise unavailable.
    PluginUnavailable,
    /// The caller supplied malformed or incomplete JMX metadata.
    InvalidJmx,
    /// The caller requested an unsupported plugin capability.
    UnsupportedCapability,
    /// A plugin operation would exceed the configured concurrency bound.
    ConcurrencyLimit,
    /// The worker startup deadline elapsed.
    StartupTimeout,
    /// A worker operation deadline elapsed.
    WorkerTimeout,
    /// A caller cancelled a worker operation.
    WorkerCancelled,
    /// Worker output exceeded its byte quota.
    WorkerOutputLimit,
    /// A framed message exceeded the negotiated message quota.
    WorkerMessageLimit,
    /// A worker rejected a resource quota whose wire/output category is not
    /// available in the structured error code.
    WorkerResourceLimit,
    /// The worker sent malformed, incomplete, or unexpected protocol data.
    WorkerProtocol,
    /// A response did not correlate to the outstanding request.
    WorkerRequestMismatch,
    /// The worker's pipe could not be read or written.
    WorkerIo,
    /// A worker process could not be reaped or cleaned up within its bound.
    WorkerCleanup,
    /// The explicit worker argument vector exceeded its aggregate bound.
    ProcessArgumentLimit,
    /// The explicit worker environment exceeded its aggregate bound.
    ProcessEnvironmentLimit,
    /// The selected process-group cleanup policy is unavailable on this OS.
    ProcessGroupUnsupported,
    /// The worker exited before completing the operation.
    WorkerCrashed,
    /// The worker returned a structured error.
    WorkerRejected,
}

impl PluginErrorCode {
    /// Every closed error code defined by this plugin-host revision.
    pub const ALL: &[Self] = &[
        Self::DiscoveryDirectory,
        Self::DiscoveryIo,
        Self::DiscoveryEntryLimit,
        Self::DiscoveryManifestBytesLimit,
        Self::DiscoveryDescriptorLimit,
        Self::DiscoveryCapabilityLimit,
        Self::DiscoveryDiagnosticLimit,
        Self::DiscoveryPathLimit,
        Self::ManifestTooLarge,
        Self::ManifestIo,
        Self::ManifestParse,
        Self::ManifestInvalid,
        Self::SymlinkNotAllowed,
        Self::PathOutsideRoot,
        Self::ExecutableMissing,
        Self::ExecutableNotFile,
        Self::ExecutableNotExecutable,
        Self::ExecutableTooLarge,
        Self::ExecutableReadLimit,
        Self::ExecutableChanged,
        Self::ExecutableLaunchUnsupported,
        Self::DuplicatePluginId,
        Self::DuplicateCapabilityAlias,
        Self::ProtocolMismatch,
        Self::ProfileMismatch,
        Self::CapabilityMismatch,
        Self::PluginClasspathUnavailable,
        Self::PluginAliasAmbiguous,
        Self::PluginClassUnavailable,
        Self::PluginElementUnavailable,
        Self::PluginFunctionUnavailable,
        Self::PluginUnavailable,
        Self::InvalidJmx,
        Self::UnsupportedCapability,
        Self::ConcurrencyLimit,
        Self::StartupTimeout,
        Self::WorkerTimeout,
        Self::WorkerCancelled,
        Self::WorkerOutputLimit,
        Self::WorkerMessageLimit,
        Self::WorkerResourceLimit,
        Self::WorkerProtocol,
        Self::WorkerRequestMismatch,
        Self::WorkerIo,
        Self::WorkerCleanup,
        Self::ProcessArgumentLimit,
        Self::ProcessEnvironmentLimit,
        Self::ProcessGroupUnsupported,
        Self::WorkerCrashed,
        Self::WorkerRejected,
    ];

    /// Returns the stable machine code used in diagnostics and tests.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DiscoveryDirectory => "plugin.discovery.directory",
            Self::DiscoveryIo => "plugin.discovery.io",
            Self::DiscoveryEntryLimit => "plugin.discovery.entry-limit",
            Self::DiscoveryManifestBytesLimit => "plugin.discovery.manifest-byte-limit",
            Self::DiscoveryDescriptorLimit => "plugin.discovery.descriptor-limit",
            Self::DiscoveryCapabilityLimit => "plugin.discovery.capability-limit",
            Self::DiscoveryDiagnosticLimit => "plugin.discovery.diagnostic-limit",
            Self::DiscoveryPathLimit => "plugin.discovery.path-limit",
            Self::ManifestTooLarge => "plugin.manifest.too-large",
            Self::ManifestIo => "plugin.manifest.io",
            Self::ManifestParse => "plugin.manifest.parse",
            Self::ManifestInvalid => "plugin.manifest.invalid",
            Self::SymlinkNotAllowed => "plugin.discovery.symlink-not-allowed",
            Self::PathOutsideRoot => "plugin.discovery.path-outside-root",
            Self::ExecutableMissing => "plugin.executable.missing",
            Self::ExecutableNotFile => "plugin.executable.not-file",
            Self::ExecutableNotExecutable => "plugin.executable.not-executable",
            Self::ExecutableTooLarge => "plugin.executable.too-large",
            Self::ExecutableReadLimit => "plugin.executable.read-limit",
            Self::ExecutableChanged => "plugin.executable.changed",
            Self::ExecutableLaunchUnsupported => "plugin.executable.launch-unsupported",
            Self::DuplicatePluginId => "plugin.discovery.duplicate-id",
            Self::DuplicateCapabilityAlias => "plugin.discovery.duplicate-alias",
            Self::ProtocolMismatch => "plugin.negotiation.protocol",
            Self::ProfileMismatch => "plugin.negotiation.profile",
            Self::CapabilityMismatch => "plugin.negotiation.capability",
            Self::PluginClasspathUnavailable => "plugin.classpath.unavailable",
            Self::PluginAliasAmbiguous => "plugin.alias.ambiguous",
            Self::PluginClassUnavailable => "plugin.class.unavailable",
            Self::PluginElementUnavailable => "plugin.element.unavailable",
            Self::PluginFunctionUnavailable => "plugin.function.unavailable",
            Self::PluginUnavailable => "plugin.unavailable",
            Self::InvalidJmx => "jmx.invalid",
            Self::UnsupportedCapability => "plugin.capability.unsupported",
            Self::ConcurrencyLimit => "plugin.resource.concurrency",
            Self::StartupTimeout => "plugin.worker.startup-timeout",
            Self::WorkerTimeout => "plugin.worker.timeout",
            Self::WorkerCancelled => "plugin.worker.cancelled",
            Self::WorkerOutputLimit => "plugin.worker.output-limit",
            Self::WorkerMessageLimit => "plugin.worker.message-limit",
            Self::WorkerResourceLimit => "plugin.worker.resource-limit",
            Self::WorkerProtocol => "plugin.worker.protocol",
            Self::WorkerRequestMismatch => "plugin.worker.request-mismatch",
            Self::WorkerIo => "plugin.worker.io",
            Self::WorkerCleanup => "plugin.worker.cleanup",
            Self::ProcessArgumentLimit => "plugin.process.argument-limit",
            Self::ProcessEnvironmentLimit => "plugin.process.environment-limit",
            Self::ProcessGroupUnsupported => "plugin.worker.process-group-unsupported",
            Self::WorkerCrashed => "plugin.worker.crashed",
            Self::WorkerRejected => "plugin.worker.rejected",
        }
    }

    /// Alias emphasizing that [`Self::as_str`] is the stable compatibility
    /// key rather than human-facing diagnostic prose.
    #[must_use]
    pub const fn stable_code(self) -> &'static str {
        self.as_str()
    }

    /// Parses a stable code without accepting localized or peer-provided
    /// display text.
    #[must_use]
    pub fn from_stable_code(value: &str) -> Option<Self> {
        Self::from_str(value)
    }

    /// Parses a canonical stable code.  Unknown or peer-supplied prose is
    /// rejected instead of being promoted to a new compatibility category.
    #[must_use]
    #[allow(
        clippy::should_implement_trait,
        reason = "the inherent parser keeps PluginErrorCode usable without importing FromStr"
    )]
    pub fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "plugin.discovery.directory" => Self::DiscoveryDirectory,
            "plugin.discovery.io" => Self::DiscoveryIo,
            "plugin.discovery.entry-limit" => Self::DiscoveryEntryLimit,
            "plugin.discovery.manifest-byte-limit" => Self::DiscoveryManifestBytesLimit,
            "plugin.discovery.descriptor-limit" => Self::DiscoveryDescriptorLimit,
            "plugin.discovery.capability-limit" => Self::DiscoveryCapabilityLimit,
            "plugin.discovery.diagnostic-limit" => Self::DiscoveryDiagnosticLimit,
            "plugin.discovery.path-limit" => Self::DiscoveryPathLimit,
            "plugin.manifest.too-large" => Self::ManifestTooLarge,
            "plugin.manifest.io" => Self::ManifestIo,
            "plugin.manifest.parse" => Self::ManifestParse,
            "plugin.manifest.invalid" => Self::ManifestInvalid,
            "plugin.discovery.symlink-not-allowed" => Self::SymlinkNotAllowed,
            "plugin.discovery.path-outside-root" => Self::PathOutsideRoot,
            "plugin.executable.missing" => Self::ExecutableMissing,
            "plugin.executable.not-file" => Self::ExecutableNotFile,
            "plugin.executable.not-executable" => Self::ExecutableNotExecutable,
            "plugin.executable.too-large" => Self::ExecutableTooLarge,
            "plugin.executable.read-limit" => Self::ExecutableReadLimit,
            "plugin.executable.changed" => Self::ExecutableChanged,
            "plugin.executable.launch-unsupported" => Self::ExecutableLaunchUnsupported,
            "plugin.discovery.duplicate-id" => Self::DuplicatePluginId,
            "plugin.discovery.duplicate-alias" => Self::DuplicateCapabilityAlias,
            "plugin.negotiation.protocol" => Self::ProtocolMismatch,
            "plugin.negotiation.profile" => Self::ProfileMismatch,
            "plugin.negotiation.capability" => Self::CapabilityMismatch,
            "plugin.classpath.unavailable" => Self::PluginClasspathUnavailable,
            "plugin.alias.ambiguous" => Self::PluginAliasAmbiguous,
            "plugin.class.unavailable" => Self::PluginClassUnavailable,
            "plugin.element.unavailable" => Self::PluginElementUnavailable,
            "plugin.function.unavailable" => Self::PluginFunctionUnavailable,
            "plugin.unavailable" => Self::PluginUnavailable,
            "jmx.invalid" => Self::InvalidJmx,
            "plugin.capability.unsupported" => Self::UnsupportedCapability,
            "plugin.resource.concurrency" => Self::ConcurrencyLimit,
            "plugin.worker.startup-timeout" => Self::StartupTimeout,
            "plugin.worker.timeout" => Self::WorkerTimeout,
            "plugin.worker.cancelled" => Self::WorkerCancelled,
            "plugin.worker.output-limit" => Self::WorkerOutputLimit,
            "plugin.worker.message-limit" => Self::WorkerMessageLimit,
            "plugin.worker.resource-limit" => Self::WorkerResourceLimit,
            "plugin.worker.protocol" => Self::WorkerProtocol,
            "plugin.worker.request-mismatch" => Self::WorkerRequestMismatch,
            "plugin.worker.io" => Self::WorkerIo,
            "plugin.worker.cleanup" => Self::WorkerCleanup,
            "plugin.process.argument-limit" => Self::ProcessArgumentLimit,
            "plugin.process.environment-limit" => Self::ProcessEnvironmentLimit,
            "plugin.worker.process-group-unsupported" => Self::ProcessGroupUnsupported,
            "plugin.worker.crashed" => Self::WorkerCrashed,
            "plugin.worker.rejected" => Self::WorkerRejected,
            _ => return None,
        })
    }

    /// Returns whether this code denotes a finite resource boundary.
    #[must_use]
    pub const fn is_limit(self) -> bool {
        matches!(
            self,
            Self::DiscoveryEntryLimit
                | Self::DiscoveryManifestBytesLimit
                | Self::DiscoveryDescriptorLimit
                | Self::DiscoveryCapabilityLimit
                | Self::DiscoveryDiagnosticLimit
                | Self::DiscoveryPathLimit
                | Self::ManifestTooLarge
                | Self::ExecutableTooLarge
                | Self::ExecutableReadLimit
                | Self::ConcurrencyLimit
                | Self::WorkerOutputLimit
                | Self::WorkerMessageLimit
                | Self::WorkerResourceLimit
                | Self::ProcessArgumentLimit
                | Self::ProcessEnvironmentLimit
        )
    }

    /// Returns the conservative default retryability for this error family.
    ///
    /// Callers with a more precise operation state may use
    /// [`PluginError::with_retryability`] to attach a proof-backed
    /// classification.  Worker execution failures remain `Unknown` here:
    /// this enum cannot prove whether useful plugin work started.
    #[must_use]
    pub const fn retryability(self) -> Retryability {
        match self {
            Self::DiscoveryIo | Self::ManifestIo | Self::ConcurrencyLimit => {
                Retryability::Retryable
            }
            Self::WorkerCleanup => Retryability::Retryable,
            Self::DiscoveryDirectory
            | Self::DiscoveryEntryLimit
            | Self::DiscoveryManifestBytesLimit
            | Self::DiscoveryDescriptorLimit
            | Self::DiscoveryCapabilityLimit
            | Self::DiscoveryDiagnosticLimit
            | Self::DiscoveryPathLimit
            | Self::ManifestTooLarge
            | Self::ManifestParse
            | Self::ManifestInvalid
            | Self::SymlinkNotAllowed
            | Self::PathOutsideRoot
            | Self::ExecutableMissing
            | Self::ExecutableNotFile
            | Self::ExecutableNotExecutable
            | Self::ExecutableTooLarge
            | Self::ExecutableReadLimit
            | Self::ExecutableChanged
            | Self::ExecutableLaunchUnsupported
            | Self::DuplicatePluginId
            | Self::DuplicateCapabilityAlias
            | Self::InvalidJmx
            | Self::UnsupportedCapability
            | Self::ProtocolMismatch
            | Self::ProfileMismatch
            | Self::CapabilityMismatch
            | Self::PluginClasspathUnavailable
            | Self::PluginAliasAmbiguous
            | Self::PluginClassUnavailable
            | Self::PluginElementUnavailable
            | Self::PluginFunctionUnavailable
            | Self::WorkerCancelled
            | Self::WorkerOutputLimit
            | Self::WorkerMessageLimit
            | Self::WorkerResourceLimit
            | Self::WorkerRequestMismatch
            | Self::ProcessArgumentLimit
            | Self::ProcessEnvironmentLimit
            | Self::ProcessGroupUnsupported => Retryability::Terminal,
            _ => Retryability::Unknown,
        }
    }
}

impl std::str::FromStr for PluginErrorCode {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        PluginErrorCode::from_str(value).ok_or(())
    }
}

impl fmt::Display for PluginErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A typed error at the plugin discovery, negotiation, or process boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct PluginError {
    code: PluginErrorCode,
    detail: String,
    path: Option<PathBuf>,
    retryability: Retryability,
    secondary_code: Option<PluginErrorCode>,
    secondary: Vec<PluginError>,
    secondary_omitted: usize,
}

impl fmt::Debug for PluginError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginError")
            .field("code", &self.code)
            .field("retryability", &self.retryability)
            .field("detail", &"<redacted>")
            .field("path", &self.path.as_ref().map(|_| "<redacted>"))
            .field("secondary_count", &self.secondary.len())
            .field("secondary_omitted", &self.secondary_omitted)
            .finish()
    }
}

impl PluginError {
    /// Maximum bytes retained from one detail string.
    pub const MAX_DETAIL_BYTES: usize = MAX_ERROR_DETAIL_BYTES;

    /// Maximum bytes retained for one diagnostic path.
    pub const MAX_PATH_BYTES: usize = MAX_ERROR_PATH_BYTES;

    /// Maximum retained secondary failures.
    pub const MAX_SECONDARY_ERRORS: usize = MAX_SECONDARY_ERRORS;

    /// Creates an error without a filesystem location.
    pub fn new(code: PluginErrorCode, detail: impl Into<String>) -> Self {
        let detail = detail.into();
        Self {
            code,
            detail: bounded_text(&detail, MAX_ERROR_DETAIL_BYTES),
            path: None,
            retryability: code.retryability(),
            secondary_code: None,
            secondary: Vec::new(),
            secondary_omitted: 0,
        }
    }

    /// Attaches a bounded filesystem location for internal diagnostics.
    ///
    /// Overlong paths are discarded because truncating a path could change
    /// which source location it identifies.  The stable error code remains
    /// available and [`Self::path`] returns `None` for the discarded value.
    pub fn with_path(mut self, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        if path.as_os_str().to_string_lossy().len() <= MAX_ERROR_PATH_BYTES {
            self.path = Some(path);
        } else {
            self.path = None;
        }
        self
    }

    /// Overrides the conservative retryability classification with a
    /// state-machine proof known by the caller.
    #[must_use]
    pub const fn with_retryability(mut self, retryability: Retryability) -> Self {
        self.retryability = retryability;
        self
    }

    /// Attaches a machine-readable secondary failure without replacing the
    /// primary outcome.  Cleanup failures use this field so callers can
    /// distinguish an operation error from an ownership/reap error.
    pub fn with_secondary_code(mut self, code: PluginErrorCode) -> Self {
        if self.secondary_code.is_none() {
            self.secondary_code = Some(code);
        }
        self.push_secondary(PluginError::new(code, "secondary failure"));
        self
    }

    /// Attaches a complete secondary failure without discarding its detail or
    /// its own secondary failures.  This keeps cleanup/cancellation failures
    /// lossless while preserving the original operation as the primary error.
    pub fn with_secondary_error(mut self, error: PluginError) -> Self {
        if self.secondary_code.is_none() {
            self.secondary_code = Some(error.code);
        }
        self.push_secondary(error);
        self
    }

    fn push_secondary(&mut self, error: PluginError) {
        if self.secondary.len() < MAX_SECONDARY_ERRORS {
            self.secondary.push(error);
        } else {
            self.secondary_omitted = self.secondary_omitted.saturating_add(1);
        }
    }

    pub(crate) fn with_detail_suffix(mut self, suffix: impl AsRef<str>) -> Self {
        let suffix = suffix.as_ref();
        let separator = if self.detail.is_empty() { "" } else { "; " };
        let separator_bytes = separator.len();
        let Some(available) = MAX_ERROR_DETAIL_BYTES
            .checked_sub(self.detail.len())
            .and_then(|remaining| remaining.checked_sub(separator_bytes))
        else {
            return self;
        };
        if available == 0 {
            return self;
        }

        self.detail.push_str(separator);
        if suffix.len() <= available {
            self.detail.push_str(suffix);
            return self;
        }

        let marker = "…";
        let prefix_budget = available.saturating_sub(marker.len());
        self.detail.push_str(utf8_prefix(suffix, prefix_budget));
        if available >= marker.len() {
            self.detail.push_str(marker);
        }
        self
    }

    /// Returns the stable machine-readable code.
    pub const fn code(&self) -> PluginErrorCode {
        self.code
    }

    /// Returns a machine-readable secondary outcome, if one was observed.
    pub const fn secondary_code(&self) -> Option<PluginErrorCode> {
        self.secondary_code
    }

    /// Returns the conservative or proof-backed retryability classification.
    #[must_use]
    pub const fn retryability(&self) -> Retryability {
        self.retryability
    }

    /// Returns whether this error is classified as safely retryable at its
    /// current state boundary.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        self.retryability.is_retryable()
    }

    /// Alias for callers that use the shorter process-supervision spelling.
    #[must_use]
    pub const fn retryable(&self) -> bool {
        self.is_retryable()
    }

    /// Returns whether this error is terminal for the current operation.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self.retryability, Retryability::Terminal)
    }

    /// Returns the stable code directly from the error instance.
    #[must_use]
    pub const fn stable_code(&self) -> &'static str {
        self.code.as_str()
    }

    /// Returns whether the primary code denotes a finite resource boundary.
    #[must_use]
    pub const fn is_limit(&self) -> bool {
        self.code.is_limit()
    }

    /// Returns all structured secondary failures in observation order.
    pub fn secondary_errors(&self) -> &[PluginError] {
        &self.secondary
    }

    /// Returns how many secondary failures were omitted after the bounded
    /// secondary collection became full.
    #[must_use]
    pub const fn secondary_omitted_count(&self) -> usize {
        self.secondary_omitted
    }

    /// Returns the diagnostic detail.
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// Returns the retained diagnostic length in UTF-8 bytes.
    #[must_use]
    pub const fn detail_len(&self) -> usize {
        self.detail.len()
    }

    /// Returns whether retained detail is within the hard diagnostic bound.
    #[must_use]
    pub const fn detail_is_bounded(&self) -> bool {
        self.detail.len() <= MAX_ERROR_DETAIL_BYTES
    }

    /// Returns a safe placeholder for ordinary diagnostic consumers.
    #[must_use]
    pub const fn redacted_detail(&self) -> &'static str {
        "<redacted plugin diagnostic>"
    }

    /// Returns the associated path, if one is safe to report.
    pub fn path(&self) -> Option<&std::path::Path> {
        self.path.as_deref()
    }

    /// Returns `true` only for the explicit unavailable-capability outcome.
    pub const fn is_plugin_unavailable(&self) -> bool {
        matches!(
            self.code,
            PluginErrorCode::PluginUnavailable
                | PluginErrorCode::PluginClasspathUnavailable
                | PluginErrorCode::PluginClassUnavailable
                | PluginErrorCode::PluginElementUnavailable
                | PluginErrorCode::PluginFunctionUnavailable
        )
    }

    /// Returns `true` for malformed JMX metadata supplied to a plugin call.
    pub const fn is_invalid_jmx(&self) -> bool {
        matches!(self.code, PluginErrorCode::InvalidJmx)
    }
}

impl fmt::Display for PluginError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: <redacted>", self.code)
    }
}

impl std::error::Error for PluginError {}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "error tests assert explicit redaction behavior"
)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_worker_detail_but_keeps_stable_code() {
        let error = PluginError::new(
            PluginErrorCode::WorkerRejected,
            "worker secret and untrusted response text",
        );
        let debug = format!("{error:?}");
        assert!(debug.contains("WorkerRejected"));
        assert!(!debug.contains("worker secret"));
        assert!(!debug.contains("untrusted response text"));
    }

    #[test]
    fn display_redacts_detail_and_path_but_keeps_stable_code() {
        let error = PluginError::new(
            PluginErrorCode::ManifestParse,
            "manifest secret and untrusted input",
        )
        .with_path("/secret/plugin-manifest.json");
        let display = error.to_string();
        assert!(display.contains("plugin.manifest.parse"));
        assert!(!display.contains("manifest secret"));
        assert!(!display.contains("/secret/plugin-manifest.json"));
        let debug = format!("{error:?}");
        assert!(!debug.contains("/secret/plugin-manifest.json"));
    }

    #[test]
    fn secondary_errors_retain_multiple_structured_failures() {
        let error = PluginError::new(PluginErrorCode::WorkerProtocol, "primary")
            .with_secondary_error(PluginError::new(
                PluginErrorCode::WorkerCleanup,
                "first cleanup",
            ))
            .with_secondary_error(PluginError::new(
                PluginErrorCode::WorkerIo,
                "second cleanup",
            ));
        assert_eq!(error.secondary_errors().len(), 2);
        assert_eq!(
            error.secondary_errors()[0].code(),
            PluginErrorCode::WorkerCleanup
        );
        assert_eq!(
            error.secondary_errors()[1].code(),
            PluginErrorCode::WorkerIo
        );
        assert_eq!(error.secondary_code(), Some(PluginErrorCode::WorkerCleanup));
    }

    #[test]
    fn plugin_contract_codes_are_stable_and_round_trip() {
        let codes = [
            (
                PluginErrorCode::PluginClasspathUnavailable,
                "plugin.classpath.unavailable",
            ),
            (
                PluginErrorCode::PluginAliasAmbiguous,
                "plugin.alias.ambiguous",
            ),
            (
                PluginErrorCode::PluginClassUnavailable,
                "plugin.class.unavailable",
            ),
            (
                PluginErrorCode::PluginElementUnavailable,
                "plugin.element.unavailable",
            ),
            (
                PluginErrorCode::PluginFunctionUnavailable,
                "plugin.function.unavailable",
            ),
        ];
        for (code, stable) in codes {
            assert_eq!(code.as_str(), stable);
            assert_eq!(code.stable_code(), stable);
            assert_eq!(PluginErrorCode::from_str(stable), Some(code));
        }
        assert_eq!(
            PluginErrorCode::from_str("plugin.worker.not-a-real-code"),
            None
        );
    }

    #[test]
    fn every_error_code_has_one_stable_spelling() {
        for (index, code) in PluginErrorCode::ALL.iter().enumerate() {
            let spelling = code.as_str();
            assert!(!spelling.is_empty());
            assert_eq!(PluginErrorCode::from_stable_code(spelling), Some(*code));
            assert!(
                PluginErrorCode::ALL[..index]
                    .iter()
                    .all(|previous| previous.as_str() != spelling)
            );
        }
    }

    #[test]
    fn retryability_is_closed_and_conservative() {
        assert_eq!(
            PluginErrorCode::WorkerCleanup.retryability(),
            Retryability::Retryable
        );
        assert_eq!(
            PluginErrorCode::InvalidJmx.retryability(),
            Retryability::Terminal
        );
        assert_eq!(
            PluginErrorCode::WorkerTimeout.retryability(),
            Retryability::Unknown
        );
        assert_eq!(
            PluginErrorCode::WorkerMessageLimit.retryability(),
            Retryability::Terminal
        );
        assert_eq!(
            PluginErrorCode::ManifestInvalid.retryability(),
            Retryability::Terminal
        );

        let error = PluginError::new(PluginErrorCode::WorkerCleanup, "cleanup")
            .with_retryability(Retryability::Terminal);
        assert_eq!(error.retryability(), Retryability::Terminal);
        assert!(!error.is_retryable());
        assert!(!error.retryable());
        assert_eq!(Retryability::Retryable.as_str(), "retryable");
        assert!(Retryability::Retryable.is_retryable());
    }

    #[test]
    fn detail_and_path_are_bounded_without_invalid_utf8_truncation() {
        let detail = "é".repeat(PluginError::MAX_DETAIL_BYTES);
        let path = "p".repeat(PluginError::MAX_PATH_BYTES + 1);
        let error = PluginError::new(PluginErrorCode::ManifestParse, detail)
            .with_path(path)
            .with_detail_suffix("suffix");

        assert!(error.detail().len() <= PluginError::MAX_DETAIL_BYTES);
        assert!(error.detail().is_char_boundary(error.detail().len()));
        assert!(error.detail().ends_with('…'));
        assert!(error.path().is_none());
        let display = error.to_string();
        assert_eq!(display, "plugin.manifest.parse: <redacted>");
        assert!(!display.contains("suffix"));
    }

    #[test]
    fn secondary_failures_are_bounded_and_omissions_are_observable() {
        let mut error = PluginError::new(PluginErrorCode::WorkerProtocol, "primary");
        for _ in 0..PluginError::MAX_SECONDARY_ERRORS + 3 {
            error = error.with_secondary_code(PluginErrorCode::WorkerCleanup);
        }
        assert_eq!(
            error.secondary_errors().len(),
            PluginError::MAX_SECONDARY_ERRORS
        );
        assert_eq!(error.secondary_omitted_count(), 3);
        assert_eq!(error.secondary_code(), Some(PluginErrorCode::WorkerCleanup));
        let debug = format!("{error:?}");
        assert!(debug.contains("secondary_omitted: 3"));
    }

    #[test]
    fn unavailable_contract_errors_are_classified_as_plugin_unavailable() {
        for code in [
            PluginErrorCode::PluginUnavailable,
            PluginErrorCode::PluginClasspathUnavailable,
            PluginErrorCode::PluginClassUnavailable,
            PluginErrorCode::PluginElementUnavailable,
            PluginErrorCode::PluginFunctionUnavailable,
        ] {
            assert!(PluginError::new(code, "unavailable").is_plugin_unavailable());
        }
        assert!(
            !PluginError::new(PluginErrorCode::PluginAliasAmbiguous, "ambiguous")
                .is_plugin_unavailable()
        );
    }
}
