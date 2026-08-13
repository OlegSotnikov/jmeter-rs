// SPDX-License-Identifier: Apache-2.0
//! Plugin admission and the process-supervision migration boundary.
//!
//! Plugin execution is an optional compatibility-pack capability.  This
//! module owns manifest admission, bounded request accounting, and the
//! explicit unavailable result used until the caller is wired to the shared
//! process-supervision service.  It intentionally contains no OS child,
//! process-group, signal, or helper ownership.  Keeping those capabilities
//! out of this crate is important: a plugin must not regain a private cleanup
//! implementation through a convenience fallback.

use crate::{
    discovery::{ExecutableIdentity, PluginDescriptor, capture_executable_identity},
    error::{PluginError, PluginErrorCode},
    manifest::{PluginRequest, PluginResponse, ResourceLimits},
};
use jmeter_rs_bridge_protocol::{FrameCodec, FrameLimits, HEADER_LEN};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

/// Maximum explicit worker arguments accepted by one process policy.
pub const MAX_PROCESS_ARGUMENT_COUNT: usize = 1024;
/// Maximum aggregate argument bytes, including one terminating byte per item.
pub const MAX_PROCESS_ARGUMENT_BYTES: usize = 256 * 1024;
/// Maximum explicit environment entries accepted by one process policy.
pub const MAX_PROCESS_ENVIRONMENT_COUNT: usize = 1024;
/// Maximum aggregate environment bytes, including `=` and terminators.
pub const MAX_PROCESS_ENVIRONMENT_BYTES: usize = 256 * 1024;

/// Compatibility names retained for callers while ownership moves to the
/// shared supervisor.  The enum is metadata only; it never performs cleanup.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CleanupPolicy {
    /// Reviewed helper policy whose contract excludes descendants.
    ExactChild,
    /// Descendant-aware policy required by the plugin compatibility pack.
    #[default]
    ProcessGroup,
}

/// Backwards-compatible name for the containment policy type.
pub type ProcessGroupPolicy = CleanupPolicy;

impl CleanupPolicy {
    fn validate(self) -> Result<(), PluginError> {
        if self == Self::ProcessGroup {
            #[cfg(not(unix))]
            {
                return Err(PluginError::new(
                    PluginErrorCode::ProcessGroupUnsupported,
                    "descendant-aware plugin supervision is unavailable on this platform",
                ));
            }
        }
        Ok(())
    }
}

/// Explicit launch metadata.  The shared supervisor is the sole owner of
/// applying this policy to an operating-system launch.
#[derive(Clone, Eq, PartialEq)]
pub struct ProcessPolicy {
    /// Canonical working directory for the worker.
    pub working_root: PathBuf,
    /// Explicit argument vector, preserved without interpolation.
    pub arguments: Vec<String>,
    /// Explicit environment allowlist and values.
    pub environment: BTreeMap<String, String>,
    /// Requested containment policy, interpreted by the shared supervisor.
    pub cleanup_policy: CleanupPolicy,
}

impl std::fmt::Debug for ProcessPolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProcessPolicy")
            .field("working_root", &self.working_root)
            .field("argument_count", &self.arguments.len())
            .field("arguments", &"<redacted>")
            .field("environment_count", &self.environment.len())
            .field("environment", &"<redacted>")
            .field("cleanup_policy", &self.cleanup_policy)
            .finish()
    }
}

impl ProcessPolicy {
    /// Creates a policy with no arguments and an empty environment.
    pub fn new(working_root: impl Into<PathBuf>) -> Self {
        Self {
            working_root: working_root.into(),
            arguments: Vec::new(),
            environment: BTreeMap::new(),
            cleanup_policy: CleanupPolicy::default(),
        }
    }

    /// Adds one explicit argument.
    pub fn with_argument(mut self, argument: impl Into<String>) -> Self {
        self.arguments.push(argument.into());
        self
    }

    /// Adds or replaces one explicit environment value.
    pub fn with_environment(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.environment.insert(key.into(), value.into());
        self
    }

    /// Selects the metadata policy used by the eventual shared launch.
    pub fn with_cleanup_policy(mut self, policy: CleanupPolicy) -> Self {
        self.cleanup_policy = policy;
        self
    }

    /// Selects exact-child metadata explicitly.
    pub fn with_exact_child_cleanup(self) -> Self {
        self.with_cleanup_policy(CleanupPolicy::ExactChild)
    }

    /// Selects descendant-aware metadata explicitly.
    pub fn with_process_group_cleanup(self) -> Self {
        self.with_cleanup_policy(CleanupPolicy::ProcessGroup)
    }

    /// Returns the requested metadata policy.
    pub const fn cleanup_policy(&self) -> CleanupPolicy {
        self.cleanup_policy
    }

    fn validate(&self) -> Result<PathBuf, PluginError> {
        self.cleanup_policy.validate()?;
        if !self.working_root.is_absolute() {
            return Err(PluginError::new(
                PluginErrorCode::PathOutsideRoot,
                "worker working root must be absolute",
            ));
        }
        if self.arguments.len() > MAX_PROCESS_ARGUMENT_COUNT {
            return Err(PluginError::new(
                PluginErrorCode::ProcessArgumentLimit,
                format!(
                    "worker argument count exceeds the {MAX_PROCESS_ARGUMENT_COUNT}-entry bound"
                ),
            ));
        }
        let mut argument_bytes = 0usize;
        for argument in &self.arguments {
            if argument.contains('\0') {
                return Err(PluginError::new(
                    PluginErrorCode::ManifestInvalid,
                    "worker arguments must not contain NUL",
                ));
            }
            let argument_size = argument.len().checked_add(1).ok_or_else(|| {
                PluginError::new(
                    PluginErrorCode::ProcessArgumentLimit,
                    "worker argument byte accounting overflowed",
                )
            })?;
            argument_bytes = argument_bytes.checked_add(argument_size).ok_or_else(|| {
                PluginError::new(
                    PluginErrorCode::ProcessArgumentLimit,
                    "worker argument byte accounting overflowed",
                )
            })?;
            if argument_bytes > MAX_PROCESS_ARGUMENT_BYTES {
                return Err(PluginError::new(
                    PluginErrorCode::ProcessArgumentLimit,
                    format!(
                        "worker arguments exceed the {MAX_PROCESS_ARGUMENT_BYTES}-byte aggregate bound"
                    ),
                ));
            }
        }
        if self.environment.len() > MAX_PROCESS_ENVIRONMENT_COUNT {
            return Err(PluginError::new(
                PluginErrorCode::ProcessEnvironmentLimit,
                format!(
                    "worker environment entry count exceeds the {MAX_PROCESS_ENVIRONMENT_COUNT}-entry bound"
                ),
            ));
        }
        let mut environment_bytes = 0usize;
        for (key, value) in &self.environment {
            if key.is_empty() || key.contains('=') || key.contains('\0') || value.contains('\0') {
                return Err(PluginError::new(
                    PluginErrorCode::ManifestInvalid,
                    "worker environment keys must be non-empty, cannot contain '=', and all values must be NUL-free",
                ));
            }
            let entry_bytes = key
                .len()
                .checked_add(1)
                .and_then(|size| size.checked_add(value.len()))
                .and_then(|size| size.checked_add(1))
                .ok_or_else(|| {
                    PluginError::new(
                        PluginErrorCode::ProcessEnvironmentLimit,
                        "worker environment byte accounting overflowed",
                    )
                })?;
            environment_bytes = environment_bytes.checked_add(entry_bytes).ok_or_else(|| {
                PluginError::new(
                    PluginErrorCode::ProcessEnvironmentLimit,
                    "worker environment byte accounting overflowed",
                )
            })?;
            if environment_bytes > MAX_PROCESS_ENVIRONMENT_BYTES {
                return Err(PluginError::new(
                    PluginErrorCode::ProcessEnvironmentLimit,
                    format!(
                        "worker environment exceeds the {MAX_PROCESS_ENVIRONMENT_BYTES}-byte aggregate bound"
                    ),
                ));
            }
        }
        let root = std::fs::canonicalize(&self.working_root).map_err(|error| {
            PluginError::new(
                PluginErrorCode::PathOutsideRoot,
                format!("cannot canonicalize worker working root: {error}"),
            )
            .with_path(&self.working_root)
        })?;
        if !root.is_dir() {
            return Err(PluginError::new(
                PluginErrorCode::PathOutsideRoot,
                "worker working root is not a directory",
            )
            .with_path(root));
        }
        Ok(root)
    }
}

/// Supervisor options derived from a manifest and explicit launch metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisorConfig {
    /// Profile sent in request metadata by the eventual shared adapter.
    pub profile: String,
    /// Explicit launch metadata.
    pub process: ProcessPolicy,
}

impl SupervisorConfig {
    /// Uses the manifest directory as the worker root.
    pub fn for_descriptor(
        descriptor: &PluginDescriptor,
        profile: impl Into<String>,
    ) -> Result<Self, PluginError> {
        let parent = descriptor.manifest_path.parent().ok_or_else(|| {
            PluginError::new(PluginErrorCode::PathOutsideRoot, "manifest has no parent")
        })?;
        Ok(Self {
            profile: profile.into(),
            process: ProcessPolicy::new(parent),
        })
    }
}

/// A cancellation handle that can be shared with the caller's stop signal.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    /// Creates a non-cancelled token.
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cancellation.  The shared supervisor observes this token.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Returns whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// A plugin invoker whose execution capability is admitted only by the
/// shared process-supervision service.
pub struct PluginSupervisor {
    descriptor: PluginDescriptor,
    executable_identity: ExecutableIdentity,
    profile: String,
    process: ProcessPolicy,
    active: AtomicUsize,
}

impl std::fmt::Debug for PluginSupervisor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PluginSupervisor")
            .field("plugin_id", &self.descriptor.manifest.id)
            .field("profile", &self.profile)
            .field("process", &self.process)
            .finish_non_exhaustive()
    }
}

impl PluginSupervisor {
    /// Creates a supervisor after validating the explicit working root and
    /// profile.  No compatibility-pack capability is activated here.
    pub fn new(
        descriptor: PluginDescriptor,
        config: SupervisorConfig,
    ) -> Result<Self, PluginError> {
        descriptor.validate_integrity()?;
        if !descriptor.manifest.supports_profile(&config.profile) {
            return Err(PluginError::new(
                PluginErrorCode::ProfileMismatch,
                format!("plugin does not support profile {}", config.profile),
            ));
        }
        let root = config.process.validate()?;
        if !descriptor.executable_path.starts_with(&root) {
            return Err(PluginError::new(
                PluginErrorCode::PathOutsideRoot,
                "worker executable is outside its explicit working root",
            )
            .with_path(&descriptor.executable_path));
        }
        let executable_identity = capture_executable_identity(&descriptor.executable_path)?;
        Ok(Self {
            descriptor,
            executable_identity,
            profile: config.profile,
            process: ProcessPolicy {
                working_root: root,
                ..config.process
            },
            active: AtomicUsize::new(0),
        })
    }

    /// Returns the installed plugin descriptor.
    pub fn descriptor(&self) -> &PluginDescriptor {
        &self.descriptor
    }

    /// Invokes a request.  Execution remains unavailable until shared-service
    /// activation, so this path cannot create an implicit side effect.
    pub fn invoke(&self, request: &PluginRequest) -> Result<PluginResponse, PluginError> {
        let token = CancellationToken::new();
        self.invoke_with_cancellation(request, &token)
    }

    /// Invokes while observing an external cancellation token.
    pub fn invoke_with_cancellation(
        &self,
        request: &PluginRequest,
        cancellation: &CancellationToken,
    ) -> Result<PluginResponse, PluginError> {
        request.validate_for_message_limit(self.descriptor.manifest.limits.max_message_bytes)?;
        if cancellation.is_cancelled() {
            return Err(PluginError::new(
                PluginErrorCode::WorkerCancelled,
                "plugin operation was cancelled before shared-service activation",
            ));
        }
        if self
            .descriptor
            .manifest
            .find_capability(&request.capability)
            .is_none()
        {
            return Err(PluginError::new(
                PluginErrorCode::CapabilityMismatch,
                format!(
                    "plugin does not declare {} capability {}",
                    request.capability.kind.as_str(),
                    request.capability.name
                ),
            ));
        }
        let preservation = &self.descriptor.manifest.preservation;
        let jmx_preserved =
            !request.jmx.requires_preservation() || preservation.preserves_unknown_element();
        if !jmx_preserved {
            return Err(PluginError::new(
                PluginErrorCode::UnsupportedCapability,
                "plugin preservation contract does not accept unknown JMX data",
            ));
        }
        let _permit = ActivePermit::acquire(
            &self.active,
            self.descriptor.manifest.limits.max_concurrent_requests,
        )?;
        self.invoke_inner(request, cancellation)
    }

    fn invoke_inner(
        &self,
        request: &PluginRequest,
        cancellation: &CancellationToken,
    ) -> Result<PluginResponse, PluginError> {
        // Keep the identity and policy values borrowed so future migration
        // code must consume the validated descriptor rather than rediscover
        // ambient paths or launch metadata.
        let _ = (
            &self.process,
            &self.executable_identity,
            request,
            cancellation,
        );
        Err(PluginError::new(
            PluginErrorCode::PluginUnavailable,
            "plugin execution requires an activated shared process supervisor",
        ))
    }
}

struct ActivePermit<'a> {
    active: &'a AtomicUsize,
}

impl<'a> ActivePermit<'a> {
    fn acquire(active: &'a AtomicUsize, maximum: usize) -> Result<Self, PluginError> {
        loop {
            let current = active.load(Ordering::Acquire);
            if current >= maximum {
                return Err(PluginError::new(
                    PluginErrorCode::ConcurrencyLimit,
                    format!("plugin concurrency limit {maximum} is exhausted"),
                ));
            }
            if active
                .compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(Self { active });
            }
        }
    }
}

impl Drop for ActivePermit<'_> {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

fn codec_for_limits(limits: &ResourceLimits) -> Result<FrameCodec, PluginError> {
    let frame_limits = FrameLimits {
        max_payload_len: limits.max_message_bytes,
        ..FrameLimits::default()
    };
    let codec = FrameCodec::try_with_limits(frame_limits).map_err(|_| {
        PluginError::new(
            PluginErrorCode::WorkerMessageLimit,
            "configured plugin frame limits are invalid",
        )
    })?;
    let Some(max_frame_len) = codec.max_frame_len() else {
        return Err(PluginError::new(
            PluginErrorCode::WorkerMessageLimit,
            "configured plugin frame length cannot be represented",
        ));
    };
    if max_frame_len < HEADER_LEN {
        return Err(PluginError::new(
            PluginErrorCode::WorkerMessageLimit,
            "configured plugin frame length is below its header",
        ));
    }
    Ok(codec)
}

/// A bounded fake lifecycle used by pure tests while the real adapter is
/// migrated.  Its token is opaque and cannot address an operating-system
/// resource; failure injection therefore cannot affect unrelated processes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FakeState {
    Reserved,
    LaunchQueued,
    Active,
    CleanupRequested,
    Complete,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FakeToken(u32);

struct FakeLifecycle {
    state: FakeState,
    token: Option<FakeToken>,
    attempts: u8,
    fail_cleanup: bool,
}

impl FakeLifecycle {
    const MAX_ATTEMPTS: u8 = 3;

    fn reserve() -> Self {
        Self {
            state: FakeState::Reserved,
            token: None,
            attempts: 0,
            fail_cleanup: false,
        }
    }

    fn queue(&mut self) {
        if self.state == FakeState::Reserved {
            self.state = FakeState::LaunchQueued;
        }
    }

    fn activate(&mut self) {
        if self.state == FakeState::LaunchQueued {
            self.token = Some(FakeToken(1));
            self.state = FakeState::Active;
        }
    }

    fn fail_next_cleanup(&mut self) {
        self.fail_cleanup = true;
    }

    fn request_cleanup(&mut self) {
        if matches!(self.state, FakeState::Active | FakeState::CleanupRequested) {
            self.state = FakeState::CleanupRequested;
        }
    }

    fn cleanup_attempt(&mut self) {
        if self.state != FakeState::CleanupRequested {
            return;
        }
        self.attempts = self.attempts.saturating_add(1);
        if self.fail_cleanup && self.attempts < Self::MAX_ATTEMPTS {
            return;
        }
        if self.fail_cleanup {
            self.state = FakeState::Quarantined;
        } else {
            self.token = None;
            self.state = FakeState::Complete;
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "pure lifecycle seam tests have explicit fixture context"
)]
mod tests {
    use super::*;

    #[test]
    fn metadata_policy_defaults_to_descendant_aware_mode() {
        assert_eq!(CleanupPolicy::default(), CleanupPolicy::ProcessGroup);
        assert_eq!(
            ProcessPolicy::new("/tmp").cleanup_policy(),
            CleanupPolicy::ProcessGroup
        );
    }

    #[cfg(not(unix))]
    #[test]
    fn unsupported_targets_fail_closed_before_path_use() {
        let error = ProcessPolicy::new("relative")
            .validate()
            .expect_err("descendant guarantee must not silently degrade");
        assert_eq!(error.code(), PluginErrorCode::ProcessGroupUnsupported);
    }

    #[test]
    fn process_metadata_redacts_arguments_and_environment_values() {
        let policy = ProcessPolicy::new("/tmp/plugin")
            .with_argument("--token=argument-secret")
            .with_environment("PLUGIN_SECRET", "environment-secret");
        let debug = format!("{policy:?}");
        assert!(debug.contains("argument_count"));
        assert!(debug.contains("environment_count"));
        assert!(!debug.contains("argument-secret"));
        assert!(!debug.contains("environment-secret"));
    }

    #[test]
    fn process_metadata_bounds_argument_and_environment_aggregates() {
        let mut arguments = ProcessPolicy::new("/tmp").with_exact_child_cleanup();
        for _ in 0..=MAX_PROCESS_ARGUMENT_COUNT {
            arguments = arguments.with_argument("x");
        }
        assert_eq!(
            arguments
                .validate()
                .expect_err("argument count must be bounded")
                .code(),
            PluginErrorCode::ProcessArgumentLimit
        );

        let environment = ProcessPolicy::new("/tmp")
            .with_exact_child_cleanup()
            .with_environment("bounded", "x".repeat(MAX_PROCESS_ENVIRONMENT_BYTES));
        assert_eq!(
            environment
                .validate()
                .expect_err("environment aggregate bytes must be bounded")
                .code(),
            PluginErrorCode::ProcessEnvironmentLimit
        );
    }

    #[test]
    fn codec_rejects_payload_quota_beyond_bridge_frame_cap() {
        let mut limits = ResourceLimits::default();
        limits.max_message_bytes = crate::manifest::HARD_MAX_MESSAGE_BYTES + 1;
        let error = codec_for_limits(&limits).expect_err("invalid frame aggregate");
        assert_eq!(error.code(), PluginErrorCode::WorkerMessageLimit);
    }

    #[test]
    fn codec_accepts_exact_bridge_payload_bound() {
        let mut limits = ResourceLimits::default();
        limits.max_message_bytes = crate::manifest::HARD_MAX_MESSAGE_BYTES;
        let codec = codec_for_limits(&limits).expect("exact aggregate frame bound is valid");
        assert_eq!(
            codec.max_frame_len(),
            Some(jmeter_rs_bridge_protocol::MAX_FRAME_BYTES)
        );
    }

    #[test]
    fn fake_lifecycle_is_bounded_and_quarantines_after_three_failures() {
        let mut lifecycle = FakeLifecycle::reserve();
        assert_eq!(lifecycle.state, FakeState::Reserved);
        lifecycle.queue();
        lifecycle.activate();
        assert_eq!(lifecycle.token, Some(FakeToken(1)));
        lifecycle.fail_next_cleanup();
        lifecycle.request_cleanup();
        lifecycle.cleanup_attempt();
        lifecycle.cleanup_attempt();
        assert_eq!(lifecycle.state, FakeState::CleanupRequested);
        lifecycle.cleanup_attempt();
        assert_eq!(lifecycle.state, FakeState::Quarantined);
        assert_eq!(lifecycle.attempts, FakeLifecycle::MAX_ATTEMPTS);
        assert_eq!(lifecycle.token, Some(FakeToken(1)));
    }

    #[test]
    fn fake_lifecycle_releases_opaque_token_only_on_completion() {
        let mut lifecycle = FakeLifecycle::reserve();
        lifecycle.queue();
        lifecycle.activate();
        lifecycle.request_cleanup();
        lifecycle.cleanup_attempt();
        assert_eq!(lifecycle.state, FakeState::Complete);
        assert_eq!(lifecycle.token, None);
    }

    #[test]
    fn cancellation_is_monotonic() {
        let token = CancellationToken::new();
        assert!(!token.is_cancelled());
        token.cancel();
        token.cancel();
        assert!(token.is_cancelled());
    }
}
