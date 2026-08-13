// SPDX-License-Identifier: Apache-2.0

use std::{fmt, path::PathBuf};

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
    secondary_code: Option<PluginErrorCode>,
    secondary: Vec<PluginError>,
}

impl fmt::Debug for PluginError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginError")
            .field("code", &self.code)
            .field("detail", &"<redacted>")
            .field("path", &self.path.as_ref().map(|_| "<redacted>"))
            .field("secondary_count", &self.secondary.len())
            .finish()
    }
}

impl PluginError {
    /// Creates an error without a filesystem location.
    pub fn new(code: PluginErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
            path: None,
            secondary_code: None,
            secondary: Vec::new(),
        }
    }

    /// Attaches a non-secret filesystem location for diagnostics.
    pub fn with_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Attaches a machine-readable secondary failure without replacing the
    /// primary outcome.  Cleanup failures use this field so callers can
    /// distinguish an operation error from an ownership/reap error.
    pub fn with_secondary_code(mut self, code: PluginErrorCode) -> Self {
        if self.secondary_code.is_none() {
            self.secondary_code = Some(code);
        }
        self.secondary
            .push(PluginError::new(code, "secondary failure"));
        self
    }

    /// Attaches a complete secondary failure without discarding its detail or
    /// its own secondary failures.  This keeps cleanup/cancellation failures
    /// lossless while preserving the original operation as the primary error.
    pub fn with_secondary_error(mut self, error: PluginError) -> Self {
        if self.secondary_code.is_none() {
            self.secondary_code = Some(error.code);
        }
        self.secondary.push(error);
        self
    }

    pub(crate) fn with_detail_suffix(mut self, suffix: impl AsRef<str>) -> Self {
        if !self.detail.is_empty() {
            self.detail.push_str("; ");
        }
        self.detail.push_str(suffix.as_ref());
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

    /// Returns all structured secondary failures in observation order.
    pub fn secondary_errors(&self) -> &[PluginError] {
        &self.secondary
    }

    /// Returns the diagnostic detail.
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// Returns the associated path, if one is safe to report.
    pub fn path(&self) -> Option<&std::path::Path> {
        self.path.as_deref()
    }

    /// Returns `true` only for the explicit unavailable-capability outcome.
    pub const fn is_plugin_unavailable(&self) -> bool {
        matches!(self.code, PluginErrorCode::PluginUnavailable)
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
}
