// SPDX-License-Identifier: Apache-2.0

use crate::{
    discovery::{
        ExecutableIdentity, PluginDescriptor, capture_executable_identity,
        verify_executable_identity,
    },
    error::{PluginError, PluginErrorCode},
    manifest::{PluginRequest, PluginResponse, ResourceLimits},
    protocol,
};
use jmeter_rs_bridge_protocol::{Frame, FrameCodec, FrameLimits, HEADER_LEN, MessageKind};
#[cfg(unix)]
use nix::{
    fcntl::{FcntlArg, OFlag, fcntl},
    sys::signal::{Signal, killpg},
    unistd::{Pid, getpgid},
};
use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
    path::PathBuf,
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError},
    },
    thread,
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::fd::AsFd;
#[cfg(unix)]
use std::os::unix::process::CommandExt;

const POLL_INTERVAL: Duration = Duration::from_millis(10);
const READ_CHUNK_BYTES: usize = 16 * 1024;
const READER_QUEUE_CAPACITY: usize = 64;
const WRITER_QUEUE_CAPACITY: usize = 1;
const DROP_CLEANUP_TIMEOUT: Duration = Duration::from_millis(250);
/// Maximum explicit worker arguments accepted by one process policy.
pub const MAX_PROCESS_ARGUMENT_COUNT: usize = 1024;
/// Maximum aggregate argument bytes, including one terminating byte per item.
pub const MAX_PROCESS_ARGUMENT_BYTES: usize = 256 * 1024;
/// Maximum explicit environment entries accepted by one process policy.
pub const MAX_PROCESS_ENVIRONMENT_COUNT: usize = 1024;
/// Maximum aggregate environment bytes, including `=` and terminators.
pub const MAX_PROCESS_ENVIRONMENT_BYTES: usize = 256 * 1024;

/// Explicit process cleanup policy.
///
/// The default is [`CleanupPolicy::ProcessGroup`], which gives a worker and
/// its descendants an owned lifetime boundary on Unix.  It creates the group
/// with `CommandExt::process_group(0)` and validates the resulting group ID
/// before calling the safe `nix::killpg` wrapper.  [`CleanupPolicy::ExactChild`]
/// is retained as an explicit policy for tests and workers whose contract
/// deliberately excludes descendants.  No policy invokes a shell or an
/// external process utility.  On non-Unix targets the default remains the
/// descendant-safe policy and validation fails closed with
/// [`PluginErrorCode::ProcessGroupUnsupported`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CleanupPolicy {
    /// Signal and reap exactly the spawned child.
    ExactChild,
    /// Isolate the child in its own Unix process group and clean up the group.
    #[default]
    ProcessGroup,
}

/// Backwards-compatible name for the process-group policy type.
pub type ProcessGroupPolicy = CleanupPolicy;

impl CleanupPolicy {
    fn validate(self) -> Result<(), PluginError> {
        if self == Self::ProcessGroup {
            #[cfg(not(unix))]
            {
                return Err(PluginError::new(
                    PluginErrorCode::ProcessGroupUnsupported,
                    "process-group cleanup is unavailable on this platform",
                ));
            }
        }
        Ok(())
    }
}

/// Explicit process policy.  Environment inheritance is disabled; only keys
/// in this map reach the worker.
#[derive(Clone, Eq, PartialEq)]
pub struct ProcessPolicy {
    /// Canonical working directory for the worker.
    pub working_root: PathBuf,
    /// Explicit argument vector, passed without shell interpolation.
    pub arguments: Vec<String>,
    /// Explicit environment allowlist and values.
    pub environment: BTreeMap<String, String>,
    /// Cleanup behavior for the worker and its descendants.
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
    /// Creates a policy with no arguments, an empty environment, and the
    /// descendant-safe default cleanup policy.
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

    /// Selects the cleanup policy used for subsequently spawned workers.
    pub fn with_cleanup_policy(mut self, policy: CleanupPolicy) -> Self {
        self.cleanup_policy = policy;
        self
    }

    /// Selects exact-child cleanup explicitly.
    pub fn with_exact_child_cleanup(self) -> Self {
        self.with_cleanup_policy(CleanupPolicy::ExactChild)
    }

    /// Selects Unix process-group cleanup explicitly.
    pub fn with_process_group_cleanup(self) -> Self {
        self.with_cleanup_policy(CleanupPolicy::ProcessGroup)
    }

    /// Returns the configured cleanup policy.
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

/// Supervisor options derived from a manifest and explicit process policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisorConfig {
    /// Profile sent in request metadata and checked during handshake.
    pub profile: String,
    /// Explicit process policy.
    pub process: ProcessPolicy,
}

impl SupervisorConfig {
    /// Uses the manifest directory as the worker root with the descendant-safe
    /// default cleanup policy and no inherited state.
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

/// A cancellation handle that can be shared with a caller's stop signal.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    /// Creates a non-cancelled token.
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cancellation.  The operation observes it between bounded IPC
    /// reads/writes and terminates the worker if it does not stop immediately.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Returns whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// A fresh-process plugin invoker.  Each call owns one worker and always
/// cleans it up, which bounds crash impact and avoids stale protocol state.
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
    /// profile.  No process is started by this constructor.
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

    /// Invokes a request with a fresh cancellation token.
    pub fn invoke(&self, request: &PluginRequest) -> Result<PluginResponse, PluginError> {
        let token = CancellationToken::new();
        self.invoke_with_cancellation(request, &token)
    }

    /// Invokes a request while observing an external cancellation token.
    pub fn invoke_with_cancellation(
        &self,
        request: &PluginRequest,
        cancellation: &CancellationToken,
    ) -> Result<PluginResponse, PluginError> {
        request.validate_for_message_limit(self.descriptor.manifest.limits.max_message_bytes)?;
        if cancellation.is_cancelled() {
            return Err(PluginError::new(
                PluginErrorCode::WorkerCancelled,
                "plugin worker operation was cancelled before spawn",
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
        let limits = &self.descriptor.manifest.limits;
        let codec = codec_for_limits(limits)?;
        let mut runtime = WorkerRuntime::spawn(
            &self.descriptor,
            &self.process,
            limits,
            &self.executable_identity,
        )?;
        let operation = (|| {
            let startup_deadline = deadline_after(limits.startup_timeout());
            let handshake = protocol::encode_handshake(&codec, &self.descriptor.manifest)?;
            runtime.write_frame(
                &handshake,
                remaining(startup_deadline),
                cancellation,
                PluginErrorCode::StartupTimeout,
            )?;
            let handshake_frame = wait_for_frame(
                &mut runtime,
                &codec,
                0,
                remaining(startup_deadline),
                limits.cancel_grace_timeout(),
                cancellation,
                PluginErrorCode::StartupTimeout,
            )?;
            let worker = protocol::decode_handshake_frame(&handshake_frame)?;
            protocol::negotiate_worker(
                &self.descriptor.manifest,
                &worker,
                &self.profile,
                &request.capability,
            )?;

            let request_id = 1;
            let payload = protocol::encode_request(&codec, request)?;
            let frame = Frame::new(MessageKind::Request, request_id, payload)
                .with_profile(self.profile.clone())
                .with_capabilities(vec![request.capability.name.clone()]);
            let encoded = codec.encode(&frame).map_err(|error| {
                PluginError::new(
                    PluginErrorCode::WorkerMessageLimit,
                    format!("plugin request exceeds message limit: {error}"),
                )
            })?;
            let request_deadline = deadline_after(limits.request_timeout());
            runtime.write_frame(
                &encoded,
                remaining(request_deadline),
                cancellation,
                PluginErrorCode::WorkerTimeout,
            )?;
            let response_frame = wait_for_frame(
                &mut runtime,
                &codec,
                request_id,
                remaining(request_deadline),
                limits.cancel_grace_timeout(),
                cancellation,
                PluginErrorCode::WorkerTimeout,
            )?;
            protocol::decode_response(&codec, &response_frame, request_id)
        })();
        let cleanup = runtime.cleanup(limits.cancel_grace_timeout());
        combine_operation_and_cleanup(operation, cleanup)
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

fn deadline_after(timeout: Duration) -> Instant {
    Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now)
}

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

struct WorkerRuntime {
    guard: ChildGuard,
    readers: ReaderSet,
    writer: WriterHandle,
    cleaned: bool,
}

impl WorkerRuntime {
    fn spawn(
        descriptor: &PluginDescriptor,
        process: &ProcessPolicy,
        limits: &ResourceLimits,
        executable_identity: &ExecutableIdentity,
    ) -> Result<Self, PluginError> {
        let mut guard = spawn_worker(descriptor, process, executable_identity)?;
        let stdout = match guard.take_stdout() {
            Some(stdout) => stdout,
            None => {
                let error =
                    PluginError::new(PluginErrorCode::WorkerIo, "worker stdout was not piped");
                return Err(cleanup_setup_error(
                    error,
                    guard
                        .cleanup(DROP_CLEANUP_TIMEOUT)
                        .map_err(child_guard_error),
                ));
            }
        };
        let stderr = match guard.take_stderr() {
            Some(stderr) => stderr,
            None => {
                let error =
                    PluginError::new(PluginErrorCode::WorkerIo, "worker stderr was not piped");
                return Err(cleanup_setup_error(
                    error,
                    guard
                        .cleanup(DROP_CLEANUP_TIMEOUT)
                        .map_err(child_guard_error),
                ));
            }
        };
        let readers = match ReaderSet::spawn(stdout, stderr, limits) {
            Ok(readers) => readers,
            Err(error) => {
                return Err(cleanup_setup_error(
                    error,
                    guard
                        .cleanup(DROP_CLEANUP_TIMEOUT)
                        .map_err(child_guard_error),
                ));
            }
        };
        let stdin = match guard.take_stdin() {
            Some(stdin) => stdin,
            None => {
                let error =
                    PluginError::new(PluginErrorCode::WorkerIo, "worker stdin was not piped");
                let mut readers = readers;
                let reader_cleanup = readers.shutdown(DROP_CLEANUP_TIMEOUT);
                return Err(cleanup_setup_error(
                    error,
                    combine_cleanup_results(
                        guard
                            .cleanup(DROP_CLEANUP_TIMEOUT)
                            .map_err(child_guard_error),
                        reader_cleanup,
                    ),
                ));
            }
        };
        let writer = match WriterHandle::spawn(stdin) {
            Ok(writer) => writer,
            Err(error) => {
                let mut readers = readers;
                let reader_cleanup = readers.shutdown(DROP_CLEANUP_TIMEOUT);
                return Err(cleanup_setup_error(
                    error,
                    combine_cleanup_results(
                        guard
                            .cleanup(DROP_CLEANUP_TIMEOUT)
                            .map_err(child_guard_error),
                        reader_cleanup,
                    ),
                ));
            }
        };
        Ok(Self {
            guard,
            readers,
            writer,
            cleaned: false,
        })
    }

    fn write_frame(
        &mut self,
        frame: &[u8],
        timeout: Duration,
        cancellation: &CancellationToken,
        timeout_code: PluginErrorCode,
    ) -> Result<(), PluginError> {
        self.writer
            .write(frame, timeout, cancellation)
            .map_err(|error| error.into_plugin_error(timeout_code))
    }

    fn cleanup(&mut self, timeout: Duration) -> Result<(), PluginError> {
        if self.cleaned {
            return Ok(());
        }
        let timeout = timeout.max(POLL_INTERVAL);
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        let mut first_error = self
            .guard
            .cleanup_until(deadline)
            .err()
            .map(child_guard_error);
        if let Err(error) = self.writer.shutdown(deadline) {
            append_cleanup_error(&mut first_error, error);
        }
        if let Err(error) = self.readers.shutdown_until(deadline) {
            append_cleanup_error(&mut first_error, error);
        }
        if let Some(error) = self.readers.take_terminal_failure() {
            append_cleanup_error(&mut first_error, error);
        }
        match first_error {
            None => {
                self.cleaned = true;
                Ok(())
            }
            Some(error) => Err(error),
        }
    }
}

fn append_cleanup_error(slot: &mut Option<PluginError>, error: PluginError) {
    match slot.take() {
        Some(primary) => *slot = Some(primary.with_secondary_error(error)),
        None => *slot = Some(error),
    }
}

impl Drop for WorkerRuntime {
    fn drop(&mut self) {
        let _ = self.cleanup(DROP_CLEANUP_TIMEOUT);
    }
}

fn combine_operation_and_cleanup(
    operation: Result<PluginResponse, PluginError>,
    cleanup: Result<(), PluginError>,
) -> Result<PluginResponse, PluginError> {
    match (operation, cleanup) {
        (Ok(response), Ok(())) => Ok(response),
        (Ok(_), Err(cleanup)) => Err(cleanup),
        (Err(operation), Ok(())) => Err(operation),
        (Err(operation), Err(cleanup)) => Err(operation
            .clone()
            .with_secondary_error(cleanup.clone())
            .with_detail_suffix(format!("cleanup also failed: {}", cleanup.detail()))),
    }
}

fn cleanup_setup_error(operation: PluginError, cleanup: Result<(), PluginError>) -> PluginError {
    match cleanup {
        Ok(()) => operation,
        Err(cleanup) => operation
            .clone()
            .with_secondary_error(cleanup.clone())
            .with_detail_suffix(format!("cleanup also failed: {}", cleanup.detail())),
    }
}

fn combine_cleanup_results(
    first: Result<(), PluginError>,
    second: Result<(), PluginError>,
) -> Result<(), PluginError> {
    match (first, second) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(first), Ok(())) => Err(first),
        (Ok(()), Err(second)) => Err(second),
        (Err(first), Err(second)) => Err(first
            .clone()
            .with_secondary_error(second.clone())
            .with_detail_suffix(format!(
                "another cleanup path also failed: {}",
                second.detail()
            ))),
    }
}

fn spawn_worker(
    descriptor: &PluginDescriptor,
    process: &ProcessPolicy,
    executable_identity: &ExecutableIdentity,
) -> Result<ChildGuard, PluginError> {
    process.cleanup_policy.validate()?;
    verify_executable_identity(&descriptor.executable_path, executable_identity)?;
    let mut command = Command::new(&descriptor.executable_path);
    #[cfg(unix)]
    if process.cleanup_policy == CleanupPolicy::ProcessGroup {
        // `0` asks the child to become the leader of a fresh group whose ID is
        // then validated from the still-owned Child handle below.
        command.process_group(0);
    }
    command
        .args(&process.arguments)
        .current_dir(&process.working_root)
        .env_clear()
        .envs(&process.environment)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = command.spawn().map_err(|error| {
        PluginError::new(
            PluginErrorCode::PluginUnavailable,
            format!("cannot start plugin worker: {error}"),
        )
        .with_path(&descriptor.executable_path)
    })?;
    ChildGuard::new(child, process.cleanup_policy)
}

#[derive(Debug)]
enum ChildGuardError {
    TryWait(io::Error),
    Kill(io::Error),
    Wait(io::Error),
    WaitTimeout,
    /// The child was already reaped before the original process-group token
    /// was used.  Signalling the numeric PGID after that point could target a
    /// reused group, so cleanup fails closed and retains the token.
    #[cfg(unix)]
    GroupOwnershipLost,
}

impl std::fmt::Display for ChildGuardError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TryWait(error) => write!(formatter, "cannot inspect worker status: {error}"),
            Self::Kill(error) => write!(formatter, "cannot terminate worker: {error}"),
            Self::Wait(error) => write!(formatter, "cannot reap worker: {error}"),
            Self::WaitTimeout => formatter.write_str("worker reap deadline elapsed"),
            #[cfg(unix)]
            Self::GroupOwnershipLost => formatter
                .write_str("worker process-group ownership proof was lost before group cleanup"),
        }
    }
}

impl std::error::Error for ChildGuardError {}

fn child_guard_error(error: ChildGuardError) -> PluginError {
    PluginError::new(PluginErrorCode::WorkerCleanup, error.to_string())
}

struct ChildGuard {
    child: Option<Child>,
    cleanup_policy: CleanupPolicy,
    #[cfg(unix)]
    process_group: Option<ProcessGroupToken>,
    #[cfg(unix)]
    group_signal_delivered: bool,
    exit_status: Option<ExitStatus>,
}

impl ChildGuard {
    fn new(child: Child, cleanup_policy: CleanupPolicy) -> Result<Self, PluginError> {
        #[cfg(unix)]
        let process_group = if cleanup_policy == CleanupPolicy::ProcessGroup {
            match ProcessGroupToken::from_child(&child) {
                Ok(process_group) => Some(process_group),
                Err(error) => {
                    let mut fallback = Self {
                        child: Some(child),
                        cleanup_policy: CleanupPolicy::ExactChild,
                        process_group: None,
                        group_signal_delivered: false,
                        exit_status: None,
                    };
                    let invalid = PluginError::new(
                        PluginErrorCode::WorkerCleanup,
                        format!("invalid worker process-group ID: {error}"),
                    );
                    return Err(cleanup_setup_error(
                        invalid,
                        fallback
                            .cleanup(DROP_CLEANUP_TIMEOUT)
                            .map_err(child_guard_error),
                    ));
                }
            }
        } else {
            None
        };
        #[cfg(not(unix))]
        if cleanup_policy == CleanupPolicy::ProcessGroup {
            let mut fallback = Self {
                child: Some(child),
                cleanup_policy: CleanupPolicy::ExactChild,
                exit_status: None,
            };
            let unsupported = PluginError::new(
                PluginErrorCode::ProcessGroupUnsupported,
                "process-group cleanup is unavailable on this platform",
            );
            return Err(cleanup_setup_error(
                unsupported,
                fallback
                    .cleanup(DROP_CLEANUP_TIMEOUT)
                    .map_err(child_guard_error),
            ));
        }
        Ok(Self {
            child: Some(child),
            cleanup_policy,
            #[cfg(unix)]
            process_group,
            #[cfg(unix)]
            group_signal_delivered: false,
            exit_status: None,
        })
    }

    fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.child.as_mut()?.stdin.take()
    }

    fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.as_mut()?.stdout.take()
    }

    fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.child.as_mut()?.stderr.take()
    }

    /// Checks the exact owned child without sending a signal.
    fn try_wait(&mut self) -> Result<Option<ExitStatus>, ChildGuardError> {
        if let Some(status) = self.exit_status.as_ref() {
            return Ok(Some(*status));
        }
        let child = self.child.as_mut().ok_or_else(|| {
            ChildGuardError::TryWait(io::Error::other(
                "owned worker handle was unexpectedly moved",
            ))
        })?;
        match child.try_wait().map_err(ChildGuardError::TryWait)? {
            Some(status) => {
                self.exit_status = Some(status);
                Ok(Some(status))
            }
            None => Ok(None),
        }
    }

    /// Terminates only the exact child represented by the owned handle.
    /// Process-group cleanup is deliberately orchestrated by
    /// [`Self::cleanup_until`] so it can poll after `killpg` and perform the
    /// exact-child fallback without losing ownership proof.
    fn kill(&mut self) -> Result<(), ChildGuardError> {
        if self.try_wait()?.is_some() {
            return Ok(());
        }
        self.child
            .as_mut()
            .ok_or_else(|| {
                ChildGuardError::Kill(io::Error::other(
                    "owned worker handle was unexpectedly moved",
                ))
            })?
            .kill()
            .map_err(ChildGuardError::Kill)
    }

    #[cfg(unix)]
    fn kill_group(&mut self) -> Result<(), ChildGuardError> {
        if self.cleanup_policy != CleanupPolicy::ProcessGroup {
            return Ok(());
        }
        if self.group_signal_delivered {
            return Ok(());
        }
        // A Child handle that has not gone through try_wait still owns the
        // unreaped process.  That lifetime proof prevents PGID reuse while we
        // issue this one validated group signal, even if the child just
        // exited and is a zombie.
        if self.exit_status.is_some() {
            return Err(ChildGuardError::GroupOwnershipLost);
        }
        let Some(process_group) = self.process_group else {
            return Err(ChildGuardError::GroupOwnershipLost);
        };
        let observed = getpgid(Some(Pid::from_raw(process_group.leader as i32)))
            .map_err(|_| ChildGuardError::GroupOwnershipLost)?;
        if observed != Pid::from_raw(process_group.id.as_raw()) {
            return Err(ChildGuardError::GroupOwnershipLost);
        }
        match killpg(Pid::from_raw(process_group.id.as_raw()), Signal::SIGKILL) {
            Ok(()) => {
                self.group_signal_delivered = true;
                Ok(())
            }
            Err(error) if is_missing_signal(&error) => {
                // ESRCH means the owned group has already disappeared.  It is
                // safe to remember that no further group signal is required;
                // the unreaped child handle still prevents a reused PGID at
                // this point.
                self.group_signal_delivered = true;
                Ok(())
            }
            Err(error) => Err(ChildGuardError::Kill(io::Error::from(error))),
        }
    }

    /// Reaps the exact child by polling until the supplied deadline.
    fn wait(&mut self, deadline: Instant) -> Result<ExitStatus, ChildGuardError> {
        loop {
            match self.try_wait().map_err(|error| match error {
                ChildGuardError::TryWait(error) => ChildGuardError::Wait(error),
                other => other,
            })? {
                Some(status) => return Ok(status),
                None if Instant::now() >= deadline => return Err(ChildGuardError::WaitTimeout),
                None => {
                    thread::sleep(
                        POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
                    );
                }
            }
        }
    }

    fn cleanup(&mut self, timeout: Duration) -> Result<(), ChildGuardError> {
        let deadline = Instant::now()
            .checked_add(timeout.max(POLL_INTERVAL))
            .unwrap_or_else(Instant::now);
        self.cleanup_until(deadline)
    }

    fn cleanup_until(&mut self, deadline: Instant) -> Result<(), ChildGuardError> {
        #[cfg(unix)]
        let group_error = if self.cleanup_policy == CleanupPolicy::ProcessGroup {
            self.kill_group().err()
        } else {
            None
        };
        #[cfg(not(unix))]
        let group_error: Option<ChildGuardError> = None;

        let status = self.try_wait()?;
        if status.is_some() {
            return match group_error {
                Some(error) => Err(error),
                None => Ok(()),
            };
        }

        // A successful group signal gets a short bounded observation window;
        // if the exact child is still live, use the owned Child handle as the
        // safe fallback before waiting out the caller's full deadline.
        let mut probe_error = None;
        #[cfg(unix)]
        let group_signal_succeeded = self.group_signal_delivered;
        #[cfg(not(unix))]
        let group_signal_succeeded = false;
        if group_signal_succeeded {
            let probe_deadline = Instant::now()
                .checked_add(POLL_INTERVAL)
                .unwrap_or(deadline)
                .min(deadline);
            probe_error = self.wait(probe_deadline).err();
            if probe_error.is_none() {
                return match group_error {
                    Some(error) => Err(error),
                    None => Ok(()),
                };
            }
        }

        let kill_error = self.kill().err();
        let wait_error = self.wait(deadline).err();
        match (group_error, kill_error, wait_error, probe_error) {
            (_, _, Some(error), _) => Err(error),
            (Some(error), _, None, _) => Err(error),
            (None, Some(error), None, Some(_)) => Err(error),
            (None, Some(error), None, None) => Err(error),
            _ => Ok(()),
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.cleanup(DROP_CLEANUP_TIMEOUT).is_err()
            && let Some(child) = self.child.take()
        {
            // Do not drop a live Child handle after a bounded cleanup failure:
            // transfer it to an explicit retry owner.  Every retry remains
            // bounded; the owner persists the original group token instead
            // of pretending that cleanup completed.
            let retry = Self {
                child: Some(child),
                cleanup_policy: self.cleanup_policy,
                #[cfg(unix)]
                process_group: self.process_group,
                #[cfg(unix)]
                group_signal_delivered: self.group_signal_delivered,
                exit_status: self.exit_status,
            };
            retain_child_guard(retry);
        }
    }
}

static RETAINED_CHILD_GUARDS: OnceLock<Mutex<Vec<ChildGuard>>> = OnceLock::new();
static RETAINED_JOIN_HANDLES: OnceLock<Mutex<Vec<thread::JoinHandle<()>>>> = OnceLock::new();

fn retain_child_guard(guard: ChildGuard) {
    let owner = Arc::new(Mutex::new(Some(guard)));
    let thread_owner = Arc::clone(&owner);
    let spawn = thread::Builder::new()
        .name("jmeter-plugin-cleanup".to_owned())
        .spawn(move || {
            let mut guard = match thread_owner.lock() {
                Ok(mut owner) => owner.take(),
                Err(poisoned) => poisoned.into_inner().take(),
            };
            let Some(mut guard) = guard.take() else {
                return;
            };
            loop {
                match guard.cleanup(DROP_CLEANUP_TIMEOUT) {
                    Ok(()) => return,
                    #[cfg(unix)]
                    Err(ChildGuardError::GroupOwnershipLost) => {
                        retain_child_guard_token(guard);
                        return;
                    }
                    Err(_) => {}
                }
                thread::sleep(POLL_INTERVAL);
            }
        });
    if let Err(error) = spawn {
        // Thread creation failure is exceptional, but ownership must still be
        // retained rather than silently detached.  The process-local registry
        // keeps the Child handle and original group token available for a
        // future explicit retry/diagnostic hook.
        if let Ok(mut retained) = RETAINED_CHILD_GUARDS
            .get_or_init(|| Mutex::new(Vec::new()))
            .try_lock()
        {
            if let Ok(mut owner) = owner.try_lock() {
                if let Some(guard) = owner.take() {
                    retained.push(guard);
                }
            } else {
                std::mem::forget(owner);
            }
        } else {
            eprintln!("plugin cleanup owner could not start or retain retry thread: {error}");
            std::mem::forget(owner);
        }
    }
}

#[cfg(unix)]
fn retain_child_guard_token(guard: ChildGuard) {
    if let Ok(mut retained) = RETAINED_CHILD_GUARDS
        .get_or_init(|| Mutex::new(Vec::new()))
        .try_lock()
    {
        retained.push(guard);
    } else {
        // The token has no safe signal operation left; leaking the small
        // process-local token is safer than dropping it and implying that a
        // potentially reused numeric PGID is owned.
        std::mem::forget(guard);
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessGroupId(i32);

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessGroupToken {
    id: ProcessGroupId,
    leader: u32,
}

#[cfg(unix)]
impl ProcessGroupToken {
    fn from_child(child: &Child) -> Result<Self, ProcessGroupIdError> {
        let leader = child.id();
        let id = ProcessGroupId::try_from(leader)?;
        // The group leader must actually be in the group we intend to own.
        // The Child handle remains unreaped while this check runs, so the
        // identity/lifetime proof cannot be invalidated by PID reuse.
        let observed = getpgid(Some(Pid::from_raw(leader as i32)))
            .map_err(|_| ProcessGroupIdError::NotOwned)?;
        if observed != Pid::from_raw(id.as_raw()) {
            return Err(ProcessGroupIdError::NotOwned);
        }
        Ok(Self { id, leader })
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessGroupIdError {
    Reserved,
    OutOfRange,
    NotOwned,
}

#[cfg(unix)]
impl std::fmt::Display for ProcessGroupIdError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Reserved => formatter.write_str("process-group IDs one or below are reserved"),
            Self::OutOfRange => {
                formatter.write_str("process-group ID is outside the platform range")
            }
            Self::NotOwned => formatter.write_str("worker is not the owned process-group leader"),
        }
    }
}

#[cfg(unix)]
impl TryFrom<u32> for ProcessGroupId {
    type Error = ProcessGroupIdError;

    fn try_from(raw: u32) -> Result<Self, Self::Error> {
        let raw = i32::try_from(raw).map_err(|_| ProcessGroupIdError::OutOfRange)?;
        if raw <= 1 {
            return Err(ProcessGroupIdError::Reserved);
        }
        Ok(Self(raw))
    }
}

#[cfg(unix)]
impl ProcessGroupId {
    const fn as_raw(self) -> i32 {
        self.0
    }
}

#[cfg(unix)]
fn is_missing_signal(error: &nix::errno::Errno) -> bool {
    *error == nix::errno::Errno::ESRCH
}

struct ReaderSet {
    events: Receiver<IoEvent>,
    handles: Vec<thread::JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    queue_full: Arc<AtomicBool>,
    terminal_failures: Arc<Mutex<ReaderFailureState>>,
    cleanup_failed: bool,
}

#[derive(Default)]
struct ReaderFailureState {
    // There are exactly two reader threads and each records at most one
    // terminal delivery failure, so the structured secondary chain is
    // naturally bounded by the stdout/stderr reader count.
    error: Option<PluginError>,
}

impl ReaderFailureState {
    fn record(&mut self, error: PluginError) {
        self.error = Some(match self.error.take() {
            Some(primary) => primary.with_secondary_error(error),
            None => error,
        });
    }

    fn take(&mut self) -> Option<PluginError> {
        self.error.take()
    }
}

impl ReaderSet {
    fn spawn(
        stdout: ChildStdout,
        stderr: ChildStderr,
        limits: &ResourceLimits,
    ) -> Result<Self, PluginError> {
        set_nonblocking(&stdout)?;
        set_nonblocking(&stderr)?;
        let (sender, events) = mpsc::sync_channel(READER_QUEUE_CAPACITY);
        let stop = Arc::new(AtomicBool::new(false));
        let queue_full = Arc::new(AtomicBool::new(false));
        let terminal_failures = Arc::new(Mutex::new(ReaderFailureState::default()));
        let stdout_thread = spawn_reader(
            stdout,
            StreamKind::Stdout,
            limits.max_output_bytes,
            sender.clone(),
            Arc::clone(&stop),
            Arc::clone(&queue_full),
            Arc::clone(&terminal_failures),
        )?;
        let stderr_thread = match spawn_reader(
            stderr,
            StreamKind::Stderr,
            limits.max_stderr_bytes,
            sender,
            Arc::clone(&stop),
            Arc::clone(&queue_full),
            Arc::clone(&terminal_failures),
        ) {
            Ok(thread) => thread,
            Err(error) => {
                stop.store(true, Ordering::Release);
                match join_handle_bounded(stdout_thread, Instant::now() + DROP_CLEANUP_TIMEOUT) {
                    JoinOutcome::Joined => {}
                    JoinOutcome::Panicked => {
                        let error = PluginError::new(
                            PluginErrorCode::WorkerCleanup,
                            format!("{error}; stdout reader panicked during cleanup"),
                        );
                        return Err(with_reader_terminal_failure(error, &terminal_failures));
                    }
                    JoinOutcome::TimedOut(handle) => {
                        retain_join_handle(handle, "stdout");
                        let error = PluginError::new(
                            PluginErrorCode::WorkerCleanup,
                            format!("{error}; stdout reader retained for bounded cleanup retry"),
                        );
                        return Err(with_reader_terminal_failure(error, &terminal_failures));
                    }
                }
                return Err(with_reader_terminal_failure(error, &terminal_failures));
            }
        };
        Ok(Self {
            events,
            handles: vec![stdout_thread, stderr_thread],
            stop,
            queue_full,
            terminal_failures,
            cleanup_failed: false,
        })
    }

    fn recv_timeout(&self, timeout: Duration) -> Result<IoEvent, RecvTimeoutError> {
        self.events.recv_timeout(timeout)
    }

    fn is_queue_full(&self) -> bool {
        self.queue_full.load(Ordering::Acquire)
    }

    fn take_terminal_failure(&self) -> Option<PluginError> {
        take_reader_failure(&self.terminal_failures)
    }

    fn shutdown(&mut self, timeout: Duration) -> Result<(), PluginError> {
        self.shutdown_until(
            Instant::now()
                .checked_add(timeout.max(POLL_INTERVAL))
                .unwrap_or_else(Instant::now),
        )
    }

    fn shutdown_until(&mut self, deadline: Instant) -> Result<(), PluginError> {
        self.stop.store(true, Ordering::Release);
        if self.cleanup_failed {
            let mut error = PluginError::new(
                PluginErrorCode::WorkerCleanup,
                "worker output reader cleanup previously failed; ownership remains retryable",
            );
            if let Some(terminal) = self.take_terminal_failure() {
                error = error.with_secondary_error(terminal);
            }
            return Err(error);
        }
        let mut cleanup_failed = false;
        for handle in self.handles.drain(..) {
            match join_handle_bounded(handle, deadline) {
                JoinOutcome::Joined => {}
                JoinOutcome::Panicked => cleanup_failed = true,
                JoinOutcome::TimedOut(handle) => {
                    cleanup_failed = true;
                    retain_join_handle(handle, "reader");
                }
            }
        }
        let mut error = if cleanup_failed {
            self.cleanup_failed = true;
            Some(PluginError::new(
                PluginErrorCode::WorkerCleanup,
                "worker output reader cleanup failed; ownership retained for retry",
            ))
        } else {
            None
        };
        if let Some(terminal) = self.take_terminal_failure() {
            append_cleanup_error(&mut error, terminal);
        }
        match error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl Drop for ReaderSet {
    fn drop(&mut self) {
        let _ = self.shutdown(DROP_CLEANUP_TIMEOUT);
    }
}

#[derive(Clone, Copy, Debug)]
enum StreamKind {
    Stdout,
    Stderr,
}

enum IoEvent {
    Data(StreamKind, Vec<u8>),
    Eof(StreamKind),
    Error(StreamKind, String),
    Limit(StreamKind),
}

fn record_reader_failure(failures: &Arc<Mutex<ReaderFailureState>>, error: PluginError) {
    let mut state = match failures.lock() {
        Ok(state) => state,
        Err(poisoned) => poisoned.into_inner(),
    };
    state.record(error);
}

fn take_reader_failure(failures: &Arc<Mutex<ReaderFailureState>>) -> Option<PluginError> {
    let mut state = match failures.lock() {
        Ok(state) => state,
        Err(poisoned) => poisoned.into_inner(),
    };
    state.take()
}

fn with_reader_terminal_failure(
    error: PluginError,
    failures: &Arc<Mutex<ReaderFailureState>>,
) -> PluginError {
    match take_reader_failure(failures) {
        Some(terminal) => error.with_secondary_error(terminal),
        None => error,
    }
}

fn terminal_event_delivery_error(event: IoEvent, delivery: &'static str) -> PluginError {
    match event {
        IoEvent::Eof(kind) => PluginError::new(
            PluginErrorCode::WorkerIo,
            format!("plugin {kind:?} pipe EOF event could not be delivered ({delivery})"),
        ),
        IoEvent::Limit(kind) => PluginError::new(
            PluginErrorCode::WorkerOutputLimit,
            format!("plugin {kind:?} pipe output-limit event could not be delivered ({delivery})"),
        ),
        IoEvent::Error(kind, detail) => PluginError::new(
            PluginErrorCode::WorkerIo,
            format!(
                "plugin {kind:?} pipe failed: {detail}; terminal error event could not be delivered ({delivery})"
            ),
        ),
        IoEvent::Data(kind, _) => PluginError::new(
            PluginErrorCode::WorkerIo,
            format!(
                "plugin {kind:?} data event could not be delivered before reader termination ({delivery})"
            ),
        ),
    }
}

fn send_terminal_event(
    sender: &SyncSender<IoEvent>,
    failures: &Arc<Mutex<ReaderFailureState>>,
    event: IoEvent,
) {
    match sender.try_send(event) {
        Ok(()) => {}
        Err(TrySendError::Full(event)) => record_reader_failure(
            failures,
            terminal_event_delivery_error(event, "reader event queue full"),
        ),
        Err(TrySendError::Disconnected(event)) => record_reader_failure(
            failures,
            terminal_event_delivery_error(event, "reader event queue disconnected"),
        ),
    }
}

fn spawn_reader<R: Read + Send + 'static>(
    mut reader: R,
    kind: StreamKind,
    limit: usize,
    sender: SyncSender<IoEvent>,
    stop: Arc<AtomicBool>,
    queue_full: Arc<AtomicBool>,
    failures: Arc<Mutex<ReaderFailureState>>,
) -> Result<thread::JoinHandle<()>, PluginError> {
    thread::Builder::new()
        .name(format!("jmeter-plugin-{kind:?}"))
        .spawn(move || {
            let mut total = 0usize;
            let mut buffer = [0_u8; READ_CHUNK_BYTES];
            loop {
                if stop.load(Ordering::Acquire) {
                    return;
                }
                match reader.read(&mut buffer) {
                    Ok(0) => {
                        send_terminal_event(&sender, &failures, IoEvent::Eof(kind));
                        return;
                    }
                    Ok(length) => {
                        total = total.saturating_add(length);
                        if total > limit {
                            send_terminal_event(&sender, &failures, IoEvent::Limit(kind));
                            return;
                        }
                        match sender.try_send(IoEvent::Data(kind, buffer[..length].to_vec())) {
                            Ok(()) => {}
                            Err(TrySendError::Disconnected(_)) => return,
                            Err(TrySendError::Full(_)) => {
                                queue_full.store(true, Ordering::Release);
                                return;
                            }
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(POLL_INTERVAL);
                    }
                    Err(error) => {
                        send_terminal_event(
                            &sender,
                            &failures,
                            IoEvent::Error(kind, error.to_string()),
                        );
                        return;
                    }
                }
            }
        })
        .map_err(|error| {
            PluginError::new(
                PluginErrorCode::WorkerIo,
                format!("cannot start worker pipe reader: {error}"),
            )
        })
}

#[cfg(unix)]
fn set_nonblocking<T>(fd: &T) -> Result<(), PluginError>
where
    T: AsFd,
{
    let flags = fcntl(fd, FcntlArg::F_GETFL).map_err(|error| {
        PluginError::new(
            PluginErrorCode::WorkerIo,
            format!("cannot inspect worker pipe flags: {error}"),
        )
    })?;
    let mut flags = OFlag::from_bits_retain(flags);
    flags.insert(OFlag::O_NONBLOCK);
    fcntl(fd, FcntlArg::F_SETFL(flags)).map_err(|error| {
        PluginError::new(
            PluginErrorCode::WorkerIo,
            format!("cannot make worker pipe non-blocking: {error}"),
        )
    })?;
    Ok(())
}

#[cfg(not(unix))]
fn set_nonblocking<T>(_fd: &T) -> Result<(), PluginError> {
    Ok(())
}

enum JoinOutcome {
    Joined,
    TimedOut(thread::JoinHandle<()>),
    Panicked,
}

fn join_handle_bounded(handle: thread::JoinHandle<()>, deadline: Instant) -> JoinOutcome {
    while !handle.is_finished() {
        if Instant::now() >= deadline {
            // Return the handle to an explicit retry owner.  Dropping it here
            // would detach a potentially blocking pipe operation and lose the
            // only ownership needed to retry cleanup safely.
            return JoinOutcome::TimedOut(handle);
        }
        thread::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
    }
    match handle.join() {
        Ok(()) => JoinOutcome::Joined,
        Err(_) => JoinOutcome::Panicked,
    }
}

fn retain_join_handle(handle: thread::JoinHandle<()>, label: &'static str) {
    let owner = Arc::new(Mutex::new(Some(handle)));
    let thread_owner = Arc::clone(&owner);
    let spawn = thread::Builder::new()
        .name(format!("jmeter-plugin-{label}-cleanup"))
        .spawn(move || {
            let handle = match thread_owner.lock() {
                Ok(mut owner) => owner.take(),
                Err(poisoned) => poisoned.into_inner().take(),
            };
            if let Some(handle) = handle {
                let _ = handle.join();
            }
        });
    if let Err(error) = spawn {
        if let Ok(mut retained) = RETAINED_JOIN_HANDLES
            .get_or_init(|| Mutex::new(Vec::new()))
            .try_lock()
        {
            if let Ok(mut owner) = owner.try_lock()
                && let Some(handle) = owner.take()
            {
                retained.push(handle);
            } else {
                std::mem::forget(owner);
            }
        } else {
            eprintln!("plugin {label} cleanup owner could not be retained: {error}");
            std::mem::forget(owner);
        }
    }
}

enum WriterOutcome {
    Complete,
    Cancelled,
    Timeout,
    Error(String),
}

struct WriteCommand {
    bytes: Vec<u8>,
    deadline: Instant,
    cancellation: CancellationToken,
    completion: SyncSender<WriterOutcome>,
}

struct WriterHandle {
    sender: Option<SyncSender<WriteCommand>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
    cleanup_failed: bool,
}

impl WriterHandle {
    fn spawn(mut stdin: ChildStdin) -> Result<Self, PluginError> {
        set_nonblocking(&stdin)?;
        let (sender, receiver) = mpsc::sync_channel(WRITER_QUEUE_CAPACITY);
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let handle = thread::Builder::new()
            .name("jmeter-plugin-stdin".to_owned())
            .spawn(move || writer_loop(&mut stdin, receiver, thread_stop))
            .map_err(|error| {
                PluginError::new(
                    PluginErrorCode::WorkerIo,
                    format!("cannot start worker pipe writer: {error}"),
                )
            })?;
        Ok(Self {
            sender: Some(sender),
            stop,
            handle: Some(handle),
            cleanup_failed: false,
        })
    }

    fn write(
        &mut self,
        bytes: &[u8],
        timeout: Duration,
        cancellation: &CancellationToken,
    ) -> Result<(), WriterFailure> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        let (completion, result) = mpsc::sync_channel(1);
        let mut command = Some(WriteCommand {
            bytes: bytes.to_vec(),
            deadline,
            cancellation: cancellation.clone(),
            completion,
        });
        loop {
            if cancellation.is_cancelled() {
                return Err(WriterFailure::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(WriterFailure::Timeout);
            }
            let Some(sender) = self.sender.as_ref() else {
                return Err(WriterFailure::Error(
                    "worker stdin writer is closed".to_owned(),
                ));
            };
            let Some(next_command) = command.take() else {
                return Err(WriterFailure::Error(
                    "writer command was unexpectedly absent".to_owned(),
                ));
            };
            match sender.try_send(next_command) {
                Ok(()) => break,
                Err(TrySendError::Disconnected(_)) => {
                    return Err(WriterFailure::Error(
                        "worker stdin writer disconnected".to_owned(),
                    ));
                }
                Err(TrySendError::Full(returned)) => {
                    command = Some(returned);
                    thread::sleep(
                        POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
                    );
                }
            }
        }
        loop {
            let now = Instant::now();
            if cancellation.is_cancelled() {
                return Err(WriterFailure::Cancelled);
            }
            if now >= deadline {
                return Err(WriterFailure::Timeout);
            }
            match result.recv_timeout(POLL_INTERVAL.min(deadline.saturating_duration_since(now))) {
                Ok(WriterOutcome::Complete) => return Ok(()),
                Ok(WriterOutcome::Cancelled) => return Err(WriterFailure::Cancelled),
                Ok(WriterOutcome::Timeout) => return Err(WriterFailure::Timeout),
                Ok(WriterOutcome::Error(error)) => return Err(WriterFailure::Error(error)),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(WriterFailure::Error(
                        "worker stdin writer disconnected".to_owned(),
                    ));
                }
            }
        }
    }

    fn shutdown(&mut self, deadline: Instant) -> Result<(), PluginError> {
        self.stop.store(true, Ordering::Release);
        self.sender.take();
        if self.cleanup_failed {
            return Err(PluginError::new(
                PluginErrorCode::WorkerCleanup,
                "worker stdin writer cleanup previously failed; ownership remains retryable",
            ));
        }
        if let Some(handle) = self.handle.take() {
            match join_handle_bounded(handle, deadline) {
                JoinOutcome::Joined => {}
                JoinOutcome::Panicked => {
                    self.cleanup_failed = true;
                    return Err(PluginError::new(
                        PluginErrorCode::WorkerCleanup,
                        "worker stdin writer panicked during cleanup",
                    ));
                }
                JoinOutcome::TimedOut(handle) => {
                    retain_join_handle(handle, "stdin");
                    self.cleanup_failed = true;
                    return Err(PluginError::new(
                        PluginErrorCode::WorkerCleanup,
                        "worker stdin writer retained for bounded cleanup retry",
                    ));
                }
            }
        }
        Ok(())
    }
}

impl Drop for WriterHandle {
    fn drop(&mut self) {
        let deadline = Instant::now() + DROP_CLEANUP_TIMEOUT;
        let _ = self.shutdown(deadline);
    }
}

fn writer_loop(stdin: &mut ChildStdin, receiver: Receiver<WriteCommand>, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::Acquire) {
        let command = match receiver.recv_timeout(POLL_INTERVAL) {
            Ok(command) => command,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => return,
        };
        let outcome = write_bytes(stdin, &command, &stop);
        let _ = command.completion.try_send(outcome);
    }
}

fn write_bytes(stdin: &mut ChildStdin, command: &WriteCommand, stop: &AtomicBool) -> WriterOutcome {
    let mut offset = 0usize;
    while offset < command.bytes.len() {
        if stop.load(Ordering::Acquire) || command.cancellation.is_cancelled() {
            return WriterOutcome::Cancelled;
        }
        if Instant::now() >= command.deadline {
            return WriterOutcome::Timeout;
        }
        match stdin.write(&command.bytes[offset..]) {
            Ok(0) => return WriterOutcome::Error("worker stdin returned zero bytes".to_owned()),
            Ok(written) => offset = offset.saturating_add(written),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(POLL_INTERVAL);
            }
            Err(error) => return WriterOutcome::Error(error.to_string()),
        }
    }
    match stdin.flush() {
        Ok(()) => WriterOutcome::Complete,
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => WriterOutcome::Complete,
        Err(error) => WriterOutcome::Error(error.to_string()),
    }
}

enum WriterFailure {
    Cancelled,
    Timeout,
    Error(String),
}

impl WriterFailure {
    fn into_plugin_error(self, timeout_code: PluginErrorCode) -> PluginError {
        match self {
            Self::Cancelled => PluginError::new(
                PluginErrorCode::WorkerCancelled,
                "plugin worker operation was cancelled while writing",
            ),
            Self::Timeout => PluginError::new(timeout_code, "plugin worker write deadline elapsed"),
            Self::Error(error) => PluginError::new(
                PluginErrorCode::WorkerIo,
                format!("cannot write worker frame: {error}"),
            ),
        }
    }
}

fn wait_for_frame(
    runtime: &mut WorkerRuntime,
    codec: &FrameCodec,
    request_id: u64,
    timeout: Duration,
    cancel_grace: Duration,
    cancellation: &CancellationToken,
    timeout_code: PluginErrorCode,
) -> Result<Frame, PluginError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    let max_frame_bytes = codec.max_frame_len().ok_or_else(|| {
        PluginError::new(
            PluginErrorCode::WorkerMessageLimit,
            "configured plugin frame length cannot be represented",
        )
    })?;
    let mut output = Vec::new();
    let mut stdout_closed = false;
    loop {
        if let Some(error) = runtime.readers.take_terminal_failure() {
            return Err(error);
        }
        if runtime.readers.is_queue_full() {
            return Err(PluginError::new(
                PluginErrorCode::WorkerOutputLimit,
                "worker pipe event queue is full",
            ));
        }
        if cancellation.is_cancelled() {
            let cancellation_error = send_cancellation(runtime, codec, request_id, cancel_grace);
            return Err(with_cancellation_detail(
                PluginError::new(
                    PluginErrorCode::WorkerCancelled,
                    "plugin worker operation was cancelled",
                ),
                cancellation_error,
            ));
        }
        let now = Instant::now();
        if now >= deadline {
            let cancellation_error = send_cancellation(runtime, codec, request_id, cancel_grace);
            return Err(with_cancellation_detail(
                PluginError::new(timeout_code, "plugin worker deadline elapsed"),
                cancellation_error,
            ));
        }
        let wait = deadline.saturating_duration_since(now).min(POLL_INTERVAL);
        match runtime.readers.recv_timeout(wait) {
            Ok(IoEvent::Data(StreamKind::Stdout, bytes)) => {
                if output.len().saturating_add(bytes.len()) > max_frame_bytes {
                    return Err(PluginError::new(
                        PluginErrorCode::WorkerMessageLimit,
                        "worker framed output exceeds configured message limit",
                    ));
                }
                output.extend_from_slice(&bytes);
                if let Some(frame) = protocol::decode_next_frame(codec, &mut output)? {
                    return validate_frame(frame, request_id);
                }
            }
            Ok(IoEvent::Data(StreamKind::Stderr, _bytes)) => {}
            Ok(IoEvent::Eof(StreamKind::Stdout)) => stdout_closed = true,
            Ok(IoEvent::Eof(StreamKind::Stderr)) => {}
            Ok(IoEvent::Limit(_kind)) => {
                return Err(PluginError::new(
                    PluginErrorCode::WorkerOutputLimit,
                    "worker output exceeded output quota",
                ));
            }
            Ok(IoEvent::Error(kind, detail)) => {
                return Err(PluginError::new(
                    PluginErrorCode::WorkerIo,
                    format!("plugin {kind:?} pipe failed: {detail}"),
                ));
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                if let Some(error) = runtime.readers.take_terminal_failure() {
                    return Err(error);
                }
                return Err(PluginError::new(
                    PluginErrorCode::WorkerProtocol,
                    "plugin worker pipe readers disconnected",
                ));
            }
        }
        // A child may write its final frame and exit before the reader thread
        // has delivered the bytes.  Wait until stdout EOF establishes that
        // the reader drained the pipe before mapping the exact child status.
        if stdout_closed
            && let Some(status) = runtime.guard.try_wait().map_err(child_guard_error)?
        {
            if let Some(frame) = protocol::decode_next_frame(codec, &mut output)? {
                return validate_frame(frame, request_id);
            }
            return Err(PluginError::new(
                if status.success() {
                    PluginErrorCode::WorkerProtocol
                } else {
                    PluginErrorCode::WorkerCrashed
                },
                if status.success() {
                    "plugin worker exited before sending a complete response"
                } else {
                    "plugin worker exited unexpectedly"
                },
            ));
        }
    }
}

fn send_cancellation(
    runtime: &mut WorkerRuntime,
    codec: &FrameCodec,
    request_id: u64,
    cancel_grace: Duration,
) -> Result<(), PluginError> {
    let cancel = protocol::cancellation_frame(codec, request_id)?;
    let token = CancellationToken::new();
    runtime.write_frame(
        &cancel,
        cancel_grace.max(POLL_INTERVAL),
        &token,
        PluginErrorCode::WorkerTimeout,
    )
}

fn with_cancellation_detail(
    operation: PluginError,
    cancellation: Result<(), PluginError>,
) -> PluginError {
    match cancellation {
        Ok(()) => operation,
        Err(error) => operation
            .with_secondary_code(error.code())
            .with_detail_suffix(format!("cancellation write failed: {}", error.detail())),
    }
}

fn validate_frame(frame: Frame, request_id: u64) -> Result<Frame, PluginError> {
    if frame.request_id != request_id {
        return Err(PluginError::new(
            PluginErrorCode::WorkerRequestMismatch,
            format!("expected request {request_id}, got {}", frame.request_id),
        ));
    }
    if request_id == 0 && frame.kind != MessageKind::Handshake {
        return Err(PluginError::new(
            PluginErrorCode::WorkerProtocol,
            format!("expected handshake frame, got {}", frame.kind),
        ));
    }
    if request_id != 0 && !matches!(frame.kind, MessageKind::Response | MessageKind::Error) {
        return Err(PluginError::new(
            PluginErrorCode::WorkerProtocol,
            format!("unexpected worker frame kind {}", frame.kind),
        ));
    }
    Ok(frame)
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "lifecycle seam tests have explicit fixture context"
)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn process_group_id_rejects_reserved_and_out_of_range_values() {
        assert!(ProcessGroupId::try_from(0_u32).is_err());
        assert!(ProcessGroupId::try_from(1_u32).is_err());
        assert!(ProcessGroupId::try_from(u32::MAX).is_err());
        assert!(ProcessGroupId::try_from(2_u32).is_ok());
    }

    #[test]
    fn process_group_is_default_and_exact_child_is_explicit() {
        assert_eq!(CleanupPolicy::default(), CleanupPolicy::ProcessGroup);
        assert_eq!(
            ProcessPolicy::new("/tmp").cleanup_policy(),
            CleanupPolicy::ProcessGroup
        );
    }

    #[cfg(not(unix))]
    #[test]
    fn non_unix_default_fails_closed_before_path_use() {
        let error = ProcessPolicy::new("relative")
            .validate()
            .expect_err("descendant guarantee must not silently degrade");
        assert_eq!(error.code(), PluginErrorCode::ProcessGroupUnsupported);
    }

    #[test]
    fn cleanup_failures_are_preserved_as_typed_errors() {
        let operation = PluginError::new(PluginErrorCode::WorkerProtocol, "protocol failed");
        let merged = cleanup_setup_error(
            operation,
            Err(PluginError::new(
                PluginErrorCode::WorkerCleanup,
                "reap failed",
            )),
        );
        assert_eq!(merged.code(), PluginErrorCode::WorkerProtocol);
        assert_eq!(
            merged.secondary_code(),
            Some(PluginErrorCode::WorkerCleanup)
        );
        assert!(merged.detail().contains("protocol failed"));
        assert!(merged.detail().contains("reap failed"));
    }

    #[test]
    fn terminal_reader_delivery_failures_are_observable_and_structured() {
        let (sender, receiver) = mpsc::sync_channel(1);
        sender
            .try_send(IoEvent::Data(StreamKind::Stdout, vec![1]))
            .expect("fill the bounded event queue");
        let failures = Arc::new(Mutex::new(ReaderFailureState::default()));

        send_terminal_event(&sender, &failures, IoEvent::Eof(StreamKind::Stdout));
        drop(receiver);
        send_terminal_event(&sender, &failures, IoEvent::Limit(StreamKind::Stderr));
        send_terminal_event(
            &sender,
            &failures,
            IoEvent::Error(StreamKind::Stderr, "/secret/worker-pipe".to_owned()),
        );

        let error = match failures.lock() {
            Ok(mut failures) => failures.take().expect("terminal failure is retained"),
            Err(poisoned) => poisoned
                .into_inner()
                .take()
                .expect("terminal failure is retained after poisoning"),
        };
        assert_eq!(error.code(), PluginErrorCode::WorkerIo);
        assert_eq!(error.secondary_errors().len(), 2);
        assert_eq!(
            error.secondary_errors()[0].code(),
            PluginErrorCode::WorkerOutputLimit
        );
        assert_eq!(
            error.secondary_errors()[1].code(),
            PluginErrorCode::WorkerIo
        );
        assert!(
            error.secondary_errors()[1]
                .detail()
                .contains("/secret/worker-pipe")
        );
        let display = error.to_string();
        assert_eq!(display, "plugin.worker.io: <redacted>");
        assert!(!display.contains("/secret/worker-pipe"));
    }

    #[test]
    fn process_policy_debug_redacts_arguments_and_environment_values() {
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
    fn process_policy_bounds_argument_and_environment_aggregates() {
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
    fn codec_rejects_manifest_payload_quota_beyond_bridge_frame_cap() {
        let mut limits = ResourceLimits::default();
        limits.max_message_bytes = crate::manifest::HARD_MAX_MESSAGE_BYTES + 1;
        let error = codec_for_limits(&limits).expect_err("invalid frame aggregate");
        assert_eq!(error.code(), PluginErrorCode::WorkerMessageLimit);
    }

    #[test]
    fn codec_accepts_exact_bridge_payload_bound_and_reports_frame_length() {
        let mut limits = ResourceLimits::default();
        limits.max_message_bytes = crate::manifest::HARD_MAX_MESSAGE_BYTES;
        let codec = codec_for_limits(&limits).expect("exact aggregate frame bound is valid");
        assert_eq!(
            codec.max_frame_len(),
            Some(jmeter_rs_bridge_protocol::MAX_FRAME_BYTES)
        );
    }

    #[cfg(unix)]
    #[test]
    fn exited_child_is_reaped_without_a_signal() {
        let child = Command::new("/bin/true")
            .spawn()
            .expect("spawn short-lived child");
        let mut guard = ChildGuard::new(child, CleanupPolicy::ExactChild).expect("child guard");
        let status = guard
            .wait(Instant::now() + Duration::from_secs(2))
            .expect("reap exited child");
        assert!(status.success());
        assert!(guard.try_wait().expect("inspect reaped child").is_some());
        guard
            .cleanup(DROP_CLEANUP_TIMEOUT)
            .expect("cleanup remains idempotent after reap");
    }

    #[cfg(unix)]
    #[test]
    fn wait_reports_a_bounded_timeout_before_cleanup_reaps() {
        let child = Command::new("/bin/sleep")
            .arg("1")
            .spawn()
            .expect("spawn bounded wait fixture");
        let mut guard = ChildGuard::new(child, CleanupPolicy::ExactChild).expect("child guard");
        assert!(matches!(
            guard.wait(Instant::now()),
            Err(ChildGuardError::WaitTimeout)
        ));
        guard
            .cleanup(DROP_CLEANUP_TIMEOUT)
            .expect("cleanup reaps timeout fixture");
    }
}
