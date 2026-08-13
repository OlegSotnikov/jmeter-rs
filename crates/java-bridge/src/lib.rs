// SPDX-License-Identifier: Apache-2.0
//! Synchronous out-of-process supervision for delegated JVM capabilities.
//!
//! The crate deliberately does not implement Java semantics. A caller supplies
//! an absolute worker executable, classpath, compatibility profile, and
//! capability set. The worker speaks the bounded v1 framing protocol from
//! jmeter-rs-bridge-protocol over stdin/stdout. The API is blocking and is
//! intended to run on a dedicated blocking pool.
//!
//! The launch environment is cleared before the explicit allowlist is added:
//! ambient classpaths, Java option variables, proxy variables, credentials,
//! and PATH are never inherited. On Unix, the default policy creates an owned
//! process group with the standard-library process-group command extension and
//! uses a validated safe signal wrapper for cleanup. Other platforms return a
//! typed unsupported error unless ChildOnly is selected.

use jmeter_rs_bridge_protocol::{
    Cancellation, DecodeError, Frame, FrameCodec, FrameLimits, HEADER_LEN, MAX_CAPABILITIES,
    MAX_CAPABILITY_LEN, MAX_ERROR_MESSAGE_LEN, MAX_METADATA_LEN, MAX_PROFILE_LEN, MessageKind,
    PROTOCOL_VERSION, RemoteError, RemoteErrorCode, RequestId,
};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use nix::sys::signal::{Signal, killpg};
#[cfg(unix)]
use nix::unistd::Pid;
#[cfg(unix)]
use std::os::unix::process::CommandExt;

/// Reserved request ID used for capability/profile negotiation.
pub const HANDSHAKE_REQUEST_ID: RequestId = 0;
/// Default startup deadline.
pub const DEFAULT_STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
/// Default handshake deadline.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Default operation deadline.
pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// Default cancellation grace period.
pub const DEFAULT_CANCELLATION_TIMEOUT: Duration = Duration::from_millis(250);
/// Default aggregate stdin limit.
pub const DEFAULT_MAX_STDIN_BYTES: usize = 16 * 1024 * 1024;
/// Default aggregate stdout limit.
pub const DEFAULT_MAX_STDOUT_BYTES: usize = 16 * 1024 * 1024;
/// Default retained stderr limit.
pub const DEFAULT_MAX_STDERR_BYTES: usize = 64 * 1024;
/// Default encoded message limit.
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 1024 * 1024;

const MAX_ENV_VARS: usize = 64;
const MAX_ENV_KEY_BYTES: usize = 256;
const MAX_ENV_VALUE_BYTES: usize = 64 * 1024;
const MAX_ENV_TOTAL_BYTES: usize = 4 * 1024 * 1024;
const MAX_ARGUMENTS: usize = 256;
const MAX_ARGUMENT_BYTES: usize = 64 * 1024;
const MAX_ARGUMENT_TOTAL_BYTES: usize = 1024 * 1024;
const MAX_CLASSPATH_ENTRIES: usize = 256;
const MAX_CLASSPATH_ENTRY_BYTES: usize = 4096;
const MAX_CLASSPATH_TOTAL_BYTES: usize = 4 * 1024 * 1024;
const MAX_CAPABILITY_TOTAL_BYTES: usize = 256 * 1024;
const MAX_REDACTION_VALUES: usize = 256;
const MAX_REDACTION_TOTAL_BYTES: usize = 4 * 1024 * 1024;
const MAX_EXECUTABLE_PATH_BYTES: usize = 4096;
const MAX_CONFIGURED_STREAM_BYTES: usize = 64 * 1024 * 1024;
const MAX_CONFIGURED_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
const READER_CHUNK_BYTES: usize = 8192;
const MAX_EVENT_QUEUE: usize = 256;
const MAX_WRITER_QUEUE: usize = 1;
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(2);
const MAX_REQUEST_ID_PROBES: usize = 1024;
const MAX_REAPER_ATTEMPTS: usize = 512;

/// Process cleanup behavior.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ProcessGroupPolicy {
    /// Require Unix process-group isolation and cleanup.
    #[default]
    Required,
    /// Clean up only the direct child. Descendants are not guaranteed.
    ChildOnly,
}

/// Explicit bounded configuration for a worker process.
#[derive(Clone, Debug)]
pub struct WorkerConfig {
    /// Absolute executable path; no shell is invoked.
    pub executable: PathBuf,
    /// Literal executable arguments.
    pub args: Vec<OsString>,
    /// Absolute classpath entries, exported as an explicit CLASSPATH value.
    pub classpath: Vec<PathBuf>,
    /// Required compatibility profile.
    pub profile: String,
    /// Capabilities required during handshake.
    pub capabilities: Vec<String>,
    /// Environment allowlist. No other variables are inherited.
    pub environment: BTreeMap<OsString, OsString>,
    /// Absolute existing worker working directory.
    pub working_root: PathBuf,
    /// Process setup deadline.
    pub startup_timeout: Duration,
    /// Handshake response deadline.
    pub handshake_timeout: Duration,
    /// Default operation response deadline.
    pub call_timeout: Duration,
    /// Grace period after sending cancellation.
    pub cancellation_timeout: Duration,
    /// Aggregate bytes written to stdin.
    pub max_stdin_bytes: usize,
    /// Aggregate bytes read from stdout.
    pub max_stdout_bytes: usize,
    /// Bytes retained from stderr; stderr is always drained.
    pub max_stderr_bytes: usize,
    /// Maximum encoded size of one frame.
    pub max_message_bytes: usize,
    /// Process cleanup policy.
    pub process_group_policy: ProcessGroupPolicy,
    /// Additional UTF-8 values redacted from stderr diagnostics.
    pub redacted_values: Vec<String>,
}

impl WorkerConfig {
    /// Creates safe bounded defaults.
    pub fn new(
        executable: impl Into<PathBuf>,
        working_root: impl Into<PathBuf>,
        profile: impl Into<String>,
    ) -> Self {
        Self {
            executable: executable.into(),
            args: Vec::new(),
            classpath: Vec::new(),
            profile: profile.into(),
            capabilities: Vec::new(),
            environment: BTreeMap::new(),
            working_root: working_root.into(),
            startup_timeout: DEFAULT_STARTUP_TIMEOUT,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            call_timeout: DEFAULT_CALL_TIMEOUT,
            cancellation_timeout: DEFAULT_CANCELLATION_TIMEOUT,
            max_stdin_bytes: DEFAULT_MAX_STDIN_BYTES,
            max_stdout_bytes: DEFAULT_MAX_STDOUT_BYTES,
            max_stderr_bytes: DEFAULT_MAX_STDERR_BYTES,
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            process_group_policy: ProcessGroupPolicy::default(),
            redacted_values: Vec::new(),
        }
    }

    /// Returns an invalid empty configuration for incremental construction.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Replaces the absolute executable path.
    pub fn with_executable(mut self, executable: impl Into<PathBuf>) -> Self {
        self.executable = executable.into();
        self
    }

    /// Replaces the absolute working root.
    pub fn with_working_root(mut self, working_root: impl Into<PathBuf>) -> Self {
        self.working_root = working_root.into();
        self
    }

    /// Replaces the required compatibility profile.
    pub fn with_profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = profile.into();
        self
    }

    /// Replaces literal worker arguments.
    pub fn with_args<I, A>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = A>,
        A: Into<OsString>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    /// Replaces absolute classpath entries.
    pub fn with_classpath<I, P>(mut self, classpath: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        self.classpath = classpath.into_iter().map(Into::into).collect();
        self
    }

    /// Appends one absolute classpath entry.
    pub fn with_classpath_entry(mut self, entry: impl Into<PathBuf>) -> Self {
        self.classpath.push(entry.into());
        self
    }

    /// Replaces required capabilities.
    pub fn with_capabilities<I, C>(mut self, capabilities: I) -> Self
    where
        I: IntoIterator<Item = C>,
        C: Into<String>,
    {
        self.capabilities = capabilities.into_iter().map(Into::into).collect();
        self
    }

    /// Replaces the explicit environment allowlist.
    pub fn with_environment<I, K, V>(mut self, environment: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<OsString>,
        V: Into<OsString>,
    {
        self.environment = environment
            .into_iter()
            .map(|(key, value)| (key.into(), value.into()))
            .collect();
        self
    }

    /// Adds one explicit environment variable.
    pub fn with_env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.environment.insert(key.into(), value.into());
        self
    }

    /// Sets startup, handshake, call, and cancellation deadlines.
    pub fn with_timeouts(
        mut self,
        startup: Duration,
        handshake: Duration,
        call: Duration,
        cancellation: Duration,
    ) -> Self {
        self.startup_timeout = startup;
        self.handshake_timeout = handshake;
        self.call_timeout = call;
        self.cancellation_timeout = cancellation;
        self
    }

    /// Sets aggregate stream and frame limits.
    pub fn with_limits(
        mut self,
        max_stdin_bytes: usize,
        max_stdout_bytes: usize,
        max_stderr_bytes: usize,
        max_message_bytes: usize,
    ) -> Self {
        self.max_stdin_bytes = max_stdin_bytes;
        self.max_stdout_bytes = max_stdout_bytes;
        self.max_stderr_bytes = max_stderr_bytes;
        self.max_message_bytes = max_message_bytes;
        self
    }

    /// Sets process cleanup policy.
    pub fn with_process_group_policy(mut self, policy: ProcessGroupPolicy) -> Self {
        self.process_group_policy = policy;
        self
    }

    /// Adds a value to stderr redaction.
    pub fn with_redacted_value(mut self, value: impl Into<String>) -> Self {
        self.redacted_values.push(value.into());
        self
    }

    /// Validates all explicit paths, identifiers, limits, and policy.
    pub fn validate(&self) -> Result<(), BridgeError> {
        validate_file(&self.executable, "executable")?;
        validate_directory(&self.working_root, "working root")?;
        if self.profile.is_empty() {
            return Err(config_error("profile is empty"));
        }
        if self.profile.len() > MAX_PROFILE_LEN {
            return Err(config_error("profile exceeds protocol limit"));
        }
        if self.executable.to_string_lossy().len() > MAX_EXECUTABLE_PATH_BYTES {
            return Err(config_error("executable path exceeds configured bound"));
        }
        if self.capabilities.len() > MAX_CAPABILITIES {
            return Err(config_error("capability count exceeds protocol limit"));
        }
        let mut capability_bytes = 0usize;
        for (index, capability) in self.capabilities.iter().enumerate() {
            if capability.is_empty() || capability.len() > MAX_CAPABILITY_LEN {
                return Err(config_error(format!("invalid capability at index {index}")));
            }
            if self.capabilities[..index]
                .iter()
                .any(|item| item == capability)
            {
                return Err(config_error(format!(
                    "duplicate capability at index {index}"
                )));
            }
            capability_bytes = capability_bytes
                .checked_add(capability.len())
                .ok_or_else(|| config_error("capability bytes overflow"))?;
            if capability_bytes > MAX_CAPABILITY_TOTAL_BYTES {
                return Err(config_error("capability bytes exceed configured bound"));
            }
        }
        if self.args.len() > MAX_ARGUMENTS {
            return Err(config_error(
                "worker argument count exceeds configured bound",
            ));
        }
        let mut argument_bytes = 0usize;
        for (index, argument) in self.args.iter().enumerate() {
            if contains_nul(argument) {
                return Err(config_error("worker argument contains NUL"));
            }
            let length = argument.to_string_lossy().len();
            if length > MAX_ARGUMENT_BYTES {
                return Err(config_error(format!(
                    "worker argument {index} exceeds configured byte bound"
                )));
            }
            argument_bytes = argument_bytes
                .checked_add(length)
                .ok_or_else(|| config_error("worker argument bytes overflow"))?;
            if argument_bytes > MAX_ARGUMENT_TOTAL_BYTES {
                return Err(config_error(
                    "worker argument bytes exceed configured bound",
                ));
            }
        }
        if self.classpath.len() > MAX_CLASSPATH_ENTRIES {
            return Err(config_error(
                "classpath entry count exceeds configured bound",
            ));
        }
        let mut classpath_bytes = 0usize;
        for (index, entry) in self.classpath.iter().enumerate() {
            if !entry.is_absolute() || entry.as_os_str().is_empty() {
                return Err(config_error(format!(
                    "classpath entry {index} must be an absolute non-empty path"
                )));
            }
            let length = entry.to_string_lossy().len();
            if length > MAX_CLASSPATH_ENTRY_BYTES {
                return Err(config_error(format!(
                    "classpath entry {index} exceeds configured byte bound"
                )));
            }
            classpath_bytes = classpath_bytes
                .checked_add(length)
                .ok_or_else(|| config_error("classpath bytes overflow"))?;
            if classpath_bytes > MAX_CLASSPATH_TOTAL_BYTES {
                return Err(config_error("classpath bytes exceed configured bound"));
            }
        }
        if self.environment.len() > MAX_ENV_VARS {
            return Err(config_error("environment allowlist is too large"));
        }
        let mut environment_bytes = 0usize;
        for (key, value) in &self.environment {
            if key.is_empty() || contains_nul(key) || contains_nul(value) {
                return Err(config_error("environment key/value is invalid"));
            }
            if key.to_string_lossy().len() > MAX_ENV_KEY_BYTES {
                return Err(config_error("environment key is too large"));
            }
            if value.to_string_lossy().len() > MAX_ENV_VALUE_BYTES {
                return Err(config_error("environment value is too large"));
            }
            environment_bytes = environment_bytes
                .checked_add(key.to_string_lossy().len())
                .and_then(|size| size.checked_add(value.to_string_lossy().len()))
                .ok_or_else(|| config_error("environment bytes overflow"))?;
            if environment_bytes > MAX_ENV_TOTAL_BYTES {
                return Err(config_error("environment bytes exceed configured bound"));
            }
            if forbidden_environment_key(key) {
                return Err(config_error(format!(
                    "environment variable {} is reserved",
                    key.to_string_lossy()
                )));
            }
        }
        if self.redacted_values.len() > MAX_REDACTION_VALUES {
            return Err(config_error(
                "redaction value count exceeds configured bound",
            ));
        }
        let mut redaction_bytes = 0usize;
        for value in &self.redacted_values {
            redaction_bytes = redaction_bytes
                .checked_add(value.len())
                .ok_or_else(|| config_error("redaction bytes overflow"))?;
            if redaction_bytes > MAX_REDACTION_TOTAL_BYTES {
                return Err(config_error("redaction bytes exceed configured bound"));
            }
        }
        if self.startup_timeout.is_zero()
            || self.handshake_timeout.is_zero()
            || self.call_timeout.is_zero()
            || self.cancellation_timeout.is_zero()
        {
            return Err(config_error("worker deadlines must be non-zero"));
        }
        if self.max_stdin_bytes == 0 || self.max_stdout_bytes == 0 || self.max_stderr_bytes == 0 {
            return Err(config_error("worker stream limits must be non-zero"));
        }
        if self.max_stdin_bytes > MAX_CONFIGURED_STREAM_BYTES
            || self.max_stdout_bytes > MAX_CONFIGURED_STREAM_BYTES
            || self.max_stderr_bytes > MAX_CONFIGURED_STREAM_BYTES
        {
            return Err(config_error("worker stream limit exceeds configured bound"));
        }
        if self.max_message_bytes < HEADER_LEN
            || self.max_message_bytes > MAX_CONFIGURED_MESSAGE_BYTES
        {
            return Err(config_error(
                "maximum message size is outside protocol bounds",
            ));
        }
        check_process_group_policy(self.process_group_policy)
    }

    fn codec(&self) -> FrameCodec {
        let payload = self.max_message_bytes.saturating_sub(HEADER_LEN);
        let limits = FrameLimits {
            max_payload_len: payload,
            max_metadata_len: payload.min(MAX_METADATA_LEN),
            max_error_message_len: payload.saturating_sub(5).min(MAX_ERROR_MESSAGE_LEN),
            ..FrameLimits::default()
        };
        FrameCodec::with_limits(limits)
    }
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            executable: PathBuf::new(),
            args: Vec::new(),
            classpath: Vec::new(),
            profile: String::new(),
            capabilities: Vec::new(),
            environment: BTreeMap::new(),
            working_root: PathBuf::new(),
            startup_timeout: DEFAULT_STARTUP_TIMEOUT,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            call_timeout: DEFAULT_CALL_TIMEOUT,
            cancellation_timeout: DEFAULT_CANCELLATION_TIMEOUT,
            max_stdin_bytes: DEFAULT_MAX_STDIN_BYTES,
            max_stdout_bytes: DEFAULT_MAX_STDOUT_BYTES,
            max_stderr_bytes: DEFAULT_MAX_STDERR_BYTES,
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            process_group_policy: ProcessGroupPolicy::default(),
            redacted_values: Vec::new(),
        }
    }
}

/// Stable supervisor error category.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum BridgeErrorCode {
    /// Invalid or unsafe configuration.
    Configuration = 1,
    /// Process-group cleanup is not supported on this platform.
    ProcessGroupUnsupported = 2,
    /// Required process-group utility is unavailable.
    ProcessGroupUnavailable = 3,
    /// Process setup exceeded its deadline.
    StartupTimeout = 4,
    /// Handshake exceeded its deadline.
    HandshakeTimeout = 5,
    /// Operation exceeded its deadline.
    DeadlineExceeded = 6,
    /// Operation was cancelled.
    Cancelled = 7,
    /// Worker did not advertise a required capability.
    CapabilityUnavailable = 8,
    /// Worker profile differed from the requested profile.
    ProfileMismatch = 9,
    /// Framing or message protocol violation.
    ProtocolViolation = 10,
    /// Operating-system I/O failure.
    Io = 11,
    /// Worker pipes became unavailable.
    WorkerUnavailable = 12,
    /// Worker exited before completing an operation.
    WorkerCrashed = 13,
    /// Stream or frame resource limit was exceeded.
    ResourceLimit = 14,
    /// Structured error returned by the worker.
    RemoteError = 15,
    /// Cleanup failure.
    Shutdown = 16,
}

impl BridgeErrorCode {
    /// Returns the stable symbolic code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Configuration => "configuration",
            Self::ProcessGroupUnsupported => "process_group_unsupported",
            Self::ProcessGroupUnavailable => "process_group_unavailable",
            Self::StartupTimeout => "startup_timeout",
            Self::HandshakeTimeout => "handshake_timeout",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::Cancelled => "cancelled",
            Self::CapabilityUnavailable => "capability_unavailable",
            Self::ProfileMismatch => "profile_mismatch",
            Self::ProtocolViolation => "protocol_violation",
            Self::Io => "io",
            Self::WorkerUnavailable => "worker_unavailable",
            Self::WorkerCrashed => "worker_crashed",
            Self::ResourceLimit => "resource_limit",
            Self::RemoteError => "remote_error",
            Self::Shutdown => "shutdown",
        }
    }
}

impl fmt::Display for BridgeErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Bounded, redacted worker stderr.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StderrReport {
    text: String,
    bytes_seen: usize,
    truncated: bool,
    redacted: bool,
}

impl StderrReport {
    /// Returns redacted diagnostic text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Returns total observed bytes, including discarded bytes.
    pub const fn bytes_seen(&self) -> usize {
        self.bytes_seen
    }

    /// Returns whether the configured retention limit was exceeded.
    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    /// Returns whether a configured value was replaced.
    pub const fn redacted(&self) -> bool {
        self.redacted
    }
}

/// Structured supervisor error. Human text is diagnostic only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeError {
    code: BridgeErrorCode,
    retryable: bool,
    message: String,
    os_error: Option<i32>,
    request_id: Option<RequestId>,
    stderr: Option<Box<StderrReport>>,
    remote_error: Option<Box<RemoteError>>,
}

impl BridgeError {
    /// Creates a local structured error.
    pub fn new(code: BridgeErrorCode, retryable: bool, message: impl Into<String>) -> Self {
        Self {
            code,
            retryable,
            message: message.into(),
            os_error: None,
            request_id: None,
            stderr: None,
            remote_error: None,
        }
    }

    /// Returns the stable machine category.
    pub const fn code(&self) -> BridgeErrorCode {
        self.code
    }

    /// Returns whether retrying may succeed.
    pub const fn retryable(&self) -> bool {
        self.retryable
    }

    /// Returns the diagnostic message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the raw operating-system error associated with cleanup or I/O,
    /// when the platform supplied one.
    pub const fn os_error(&self) -> Option<i32> {
        self.os_error
    }

    /// Returns the correlated request ID.
    pub const fn request_id(&self) -> Option<RequestId> {
        self.request_id
    }

    /// Returns redacted worker stderr.
    pub fn stderr(&self) -> Option<&StderrReport> {
        self.stderr.as_deref()
    }

    /// Returns a worker-provided structured error.
    pub fn remote_error(&self) -> Option<&RemoteError> {
        self.remote_error.as_deref()
    }

    fn with_request_id(mut self, request_id: RequestId) -> Self {
        self.request_id = Some(request_id);
        self
    }

    fn with_stderr(mut self, stderr: StderrReport) -> Self {
        self.stderr = Some(Box::new(stderr));
        self
    }

    fn with_remote_error(mut self, error: RemoteError) -> Self {
        self.remote_error = Some(Box::new(error));
        self
    }

    fn with_cleanup_error(mut self, error: impl fmt::Display) -> Self {
        self.message = format!("{}; worker cleanup failed: {error}", self.message);
        self
    }

    fn with_cleanup_io_error(mut self, error: &io::Error) -> Self {
        if self.os_error.is_none() {
            self.os_error = cleanup_raw_os_error(error);
        }
        self.with_cleanup_error(cleanup_error_detail(error))
    }
}

impl fmt::Display for BridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)?;
        if let Some(id) = self.request_id {
            write!(formatter, " (request {id})")?;
        }
        if let Some(stderr) = &self.stderr {
            if !stderr.text.is_empty() {
                write!(formatter, "; stderr: {}", stderr.text)?;
            }
            if stderr.truncated {
                formatter.write_str(" [stderr truncated]")?;
            }
        }
        Ok(())
    }
}

impl std::error::Error for BridgeError {}

/// Worker metadata negotiated during startup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerInfo {
    /// Negotiated protocol version.
    pub protocol_version: u8,
    /// Worker-advertised profile.
    pub profile: String,
    /// Worker-advertised capabilities.
    pub capabilities: Vec<String>,
}

impl WorkerInfo {
    /// Tests whether one capability was advertised.
    pub fn supports(&self, capability: &str) -> bool {
        self.capabilities.iter().any(|item| item == capability)
    }
}

/// Cooperative cancellation source for a blocking call.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Creates a non-cancelled token.
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cancellation.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Returns whether cancellation was requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

/// Short compatibility alias.
pub type CancelToken = CancellationToken;

/// Per-call timeout and cancellation settings.
#[derive(Clone, Debug)]
pub struct CallOptions {
    /// Maximum response wait.
    pub timeout: Duration,
    /// Optional cooperative cancellation source.
    pub cancellation: Option<CancellationToken>,
}

impl Default for CallOptions {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_CALL_TIMEOUT,
            cancellation: None,
        }
    }
}

impl CallOptions {
    /// Creates options with a timeout.
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            timeout,
            ..Self::default()
        }
    }

    /// Attaches a cancellation token.
    pub fn with_cancellation(mut self, token: CancellationToken) -> Self {
        self.cancellation = Some(token);
        self
    }
}

/// Successful correlated worker response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerResponse {
    /// Echoed request ID.
    pub request_id: RequestId,
    /// Opaque response payload.
    pub payload: Vec<u8>,
}

/// Blocking framed worker transport.
pub struct Worker {
    inner: Arc<WorkerInner>,
    config: WorkerConfig,
    info: WorkerInfo,
}

impl fmt::Debug for Worker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Worker")
            .field("profile", &self.info.profile)
            .field("protocol_version", &self.info.protocol_version)
            .field("capabilities", &self.info.capabilities)
            .field("pid", &self.inner.lifecycle.control.pid)
            .finish()
    }
}

/// Stateless supervisor facade.
#[derive(Clone, Copy, Debug, Default)]
pub struct Supervisor;

impl Supervisor {
    /// Creates a supervisor.
    pub const fn new() -> Self {
        Self
    }

    /// Starts and negotiates one worker.
    pub fn start(&self, config: WorkerConfig) -> Result<Worker, BridgeError> {
        Worker::start(config)
    }

    /// Alias for start.
    pub fn spawn(&self, config: WorkerConfig) -> Result<Worker, BridgeError> {
        self.start(config)
    }
}

impl Worker {
    /// Starts and negotiates an explicitly configured worker.
    pub fn start(config: WorkerConfig) -> Result<Self, BridgeError> {
        config.validate()?;
        let started = Instant::now();
        let root = config
            .working_root
            .canonicalize()
            .map_err(|error| io_error("canonicalize working root", error))?;
        let mut command = build_command(&config, &root)?;
        let child = command
            .spawn()
            .map_err(|error| io_error("spawn worker", error))?;
        let mut control = Arc::new(ProcessControl::new(
            child,
            config.process_group_policy,
            config.cancellation_timeout,
        ));
        if started.elapsed() >= config.startup_timeout {
            let error = BridgeError::new(
                BridgeErrorCode::StartupTimeout,
                true,
                "worker launch exceeded startup deadline",
            );
            return Err(match control.terminate() {
                Ok(()) => error,
                Err(cleanup) => error.with_cleanup_io_error(&cleanup),
            });
        }

        let child_stdin = take_stdin(&mut control)?;
        let child_stdout = take_stdout(&mut control)?;
        let child_stderr = take_stderr(&mut control)?;
        let (events_tx, events_rx) = mpsc::sync_channel(MAX_EVENT_QUEUE);
        let stderr = Arc::new(StderrCollector::new(
            config.max_stderr_bytes,
            redaction_patterns(&config),
        ));
        let failures = Arc::new(FailureState::default());
        let codec = config.codec();
        let (stdin_sender, stdin_receiver) = mpsc::sync_channel(MAX_WRITER_QUEUE);
        let stdin = Arc::new(Mutex::new(Some(stdin_sender)));
        let threads = Arc::new(WorkerThreads::new());
        let lifecycle = Arc::new(WorkerLifecycle::new(
            Arc::clone(&stdin),
            Arc::clone(&failures),
            Arc::clone(&stderr),
            Arc::clone(&control),
            Arc::clone(&threads),
        ));

        match spawn_stdout_reader(
            child_stdout,
            codec,
            config.max_stdout_bytes,
            config.max_message_bytes,
            events_tx.clone(),
            Arc::clone(&lifecycle),
        ) {
            Ok(reader) => threads.set_stdout(reader),
            Err(error) => {
                return Err(startup_failure(error, &lifecycle));
            }
        };
        match spawn_stderr_reader(child_stderr, events_tx.clone(), Arc::clone(&lifecycle)) {
            Ok(reader) => threads.set_stderr(reader),
            Err(error) => {
                return Err(startup_failure(error, &lifecycle));
            }
        };
        match spawn_stdin_writer(
            child_stdin,
            stdin_receiver,
            events_tx,
            Arc::clone(&lifecycle),
        ) {
            Ok(writer) => threads.set_stdin(writer),
            Err(error) => {
                return Err(startup_failure(error, &lifecycle));
            }
        };
        let mut worker = Self {
            inner: Arc::new(WorkerInner {
                lifecycle,
                stdin_bytes: Mutex::new(0),
                events: Mutex::new(events_rx),
                pending: Mutex::new(HashMap::new()),
                outstanding: Mutex::new(HashSet::new()),
                codec,
                max_stdin_bytes: config.max_stdin_bytes,
                max_message_bytes: config.max_message_bytes,
                next_request_id: AtomicU64::new(1),
            }),
            config,
            info: WorkerInfo {
                protocol_version: PROTOCOL_VERSION,
                profile: String::new(),
                capabilities: Vec::new(),
            },
        };

        let startup_remaining = worker
            .config
            .startup_timeout
            .checked_sub(started.elapsed())
            .unwrap_or_default();
        let timeout = startup_remaining.min(worker.config.handshake_timeout);
        if timeout.is_zero() {
            return Err(worker.shutdown_error(BridgeError::new(
                BridgeErrorCode::StartupTimeout,
                true,
                "worker handshake could not start before startup deadline",
            )));
        }
        let handshake = Frame::handshake(
            HANDSHAKE_REQUEST_ID,
            worker.config.profile.clone(),
            worker.config.capabilities.clone(),
        );
        if let Err(error) = worker.send_frame_until(
            handshake,
            Instant::now()
                .checked_add(timeout)
                .unwrap_or_else(Instant::now),
            None,
        ) {
            return Err(
                worker.shutdown_error(error.with_stderr(worker.inner.lifecycle.stderr.report()))
            );
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        let response = match worker.wait_for_frame(HANDSHAKE_REQUEST_ID, deadline, None) {
            Ok(frame) => frame,
            Err(WaitFailure::Timeout) => {
                return Err(worker.shutdown_error(
                    BridgeError::new(
                        BridgeErrorCode::HandshakeTimeout,
                        true,
                        "worker handshake exceeded deadline",
                    )
                    .with_stderr(worker.inner.lifecycle.stderr.report()),
                ));
            }
            Err(WaitFailure::Cancelled) => {
                return Err(worker.shutdown_error(BridgeError::new(
                    BridgeErrorCode::Cancelled,
                    true,
                    "worker handshake was cancelled",
                )));
            }
            Err(WaitFailure::Error(error)) => {
                return Err(worker
                    .shutdown_error(error.with_stderr(worker.inner.lifecycle.stderr.report())));
            }
        };
        if let Err(error) = worker.negotiate_handshake(response) {
            return Err(
                worker.shutdown_error(error.with_stderr(worker.inner.lifecycle.stderr.report()))
            );
        }
        Ok(worker)
    }

    /// Alias for start.
    pub fn spawn(config: WorkerConfig) -> Result<Self, BridgeError> {
        Self::start(config)
    }

    /// Returns negotiated metadata.
    pub fn info(&self) -> &WorkerInfo {
        &self.info
    }

    /// Returns the launch configuration.
    pub fn config(&self) -> &WorkerConfig {
        &self.config
    }

    /// Returns current redacted stderr.
    pub fn stderr(&self) -> StderrReport {
        self.inner.lifecycle.stderr.report()
    }

    /// Returns whether cleanup has closed the transport.
    pub fn is_closed(&self) -> bool {
        self.inner.lifecycle.closed.load(Ordering::Acquire)
    }

    /// Sends one request using the configured call deadline.
    pub fn call<P>(&self, payload: P) -> Result<Vec<u8>, BridgeError>
    where
        P: AsRef<[u8]>,
    {
        self.call_with_options(payload, CallOptions::with_timeout(self.config.call_timeout))
    }

    /// Compatibility alias for the default call operation.
    pub fn invoke<P>(&self, payload: P) -> Result<Vec<u8>, BridgeError>
    where
        P: AsRef<[u8]>,
    {
        self.call(payload)
    }

    /// Sends one request with a fixed deadline.
    pub fn call_with_timeout<P>(
        &self,
        payload: P,
        timeout: Duration,
    ) -> Result<Vec<u8>, BridgeError>
    where
        P: AsRef<[u8]>,
    {
        self.call_with_options(payload, CallOptions::with_timeout(timeout))
    }

    /// Sends one request with explicit timeout and cancellation.
    pub fn call_with_options<P>(
        &self,
        payload: P,
        options: CallOptions,
    ) -> Result<Vec<u8>, BridgeError>
    where
        P: AsRef<[u8]>,
    {
        Ok(self.request_with_options(payload, options)?.payload)
    }

    /// Sends one request and returns its correlated response.
    pub fn request<P>(&self, payload: P) -> Result<WorkerResponse, BridgeError>
    where
        P: AsRef<[u8]>,
    {
        self.request_with_options(payload, CallOptions::with_timeout(self.config.call_timeout))
    }

    /// Sends one request and returns its correlated response.
    pub fn request_with_options<P>(
        &self,
        payload: P,
        options: CallOptions,
    ) -> Result<WorkerResponse, BridgeError>
    where
        P: AsRef<[u8]>,
    {
        if options.timeout.is_zero() {
            return Err(config_error("call timeout must be non-zero"));
        }
        if options
            .cancellation
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
        {
            return Err(BridgeError::new(
                BridgeErrorCode::Cancelled,
                true,
                "operation was cancelled before dispatch",
            ));
        }
        if let Some(error) = self.inner.failure() {
            return Err(error.with_stderr(self.inner.lifecycle.stderr.report()));
        }
        if self.inner.lifecycle.closed.load(Ordering::Acquire) {
            return Err(BridgeError::new(
                BridgeErrorCode::WorkerUnavailable,
                true,
                "worker transport is closed",
            ));
        }
        if payload.as_ref().len() > self.inner.max_message_bytes.saturating_sub(HEADER_LEN) {
            return Err(resource_error(
                "worker request payload exceeds configured message bound",
            ));
        }

        let id = allocate_request_id(&self.inner.next_request_id, &self.inner.outstanding)?;
        let deadline = Instant::now()
            .checked_add(options.timeout)
            .unwrap_or_else(Instant::now);
        let frame = Frame::new(MessageKind::Request, id, payload.as_ref().to_vec())
            .with_deadline(wire_deadline(options.timeout).unwrap_or_default());
        if let Err(error) = self.send_frame_until(frame, deadline, options.cancellation.as_ref()) {
            self.inner.release_request_id(id);
            let error = error
                .with_request_id(id)
                .with_stderr(self.inner.lifecycle.stderr.report());
            return Err(self.inner.cleanup_error(error));
        }
        let response = match self.wait_for_frame(id, deadline, options.cancellation.as_ref()) {
            Ok(frame) => frame,
            Err(WaitFailure::Timeout) => {
                let error = self.abort_request(
                    id,
                    BridgeErrorCode::DeadlineExceeded,
                    "worker operation exceeded its deadline",
                );
                self.inner.release_request_id(id);
                return Err(error);
            }
            Err(WaitFailure::Cancelled) => {
                let error = self.abort_request(
                    id,
                    BridgeErrorCode::Cancelled,
                    "worker operation was cancelled",
                );
                self.inner.release_request_id(id);
                return Err(error);
            }
            Err(WaitFailure::Error(error)) => {
                self.inner.release_request_id(id);
                return Err(error
                    .with_request_id(id)
                    .with_stderr(self.inner.lifecycle.stderr.report()));
            }
        };
        self.inner.release_request_id(id);
        self.decode_response(id, response)
    }

    /// Sends a cancellation notification for a request.
    pub fn cancel(&self, request_id: RequestId) -> Result<(), BridgeError> {
        let deadline = Instant::now()
            .checked_add(self.config.cancellation_timeout)
            .unwrap_or_else(Instant::now);
        self.send_frame_until(
            Frame::new(MessageKind::Cancel, request_id, Vec::new())
                .with_cancellation(Cancellation::Requested)
                .with_deadline(wire_deadline(self.config.cancellation_timeout).unwrap_or_default()),
            deadline,
            None,
        )
    }

    /// Terminates the worker and releases process resources.
    pub fn shutdown(&self) -> Result<(), BridgeError> {
        self.inner.shutdown(true)
    }

    fn send_frame_until(
        &self,
        frame: Frame,
        deadline: Instant,
        cancellation: Option<&CancellationToken>,
    ) -> Result<(), BridgeError> {
        let bytes = self
            .inner
            .codec
            .encode(&frame)
            .map_err(|error| resource_error(format!("encode worker frame: {error}")))?;
        if bytes.len() > self.inner.max_message_bytes {
            return Err(resource_error("encoded worker frame exceeds message limit"));
        }
        {
            let mut count = lock_unpoisoned(&self.inner.stdin_bytes);
            let next = (*count)
                .checked_add(bytes.len())
                .ok_or_else(|| resource_error("stdin byte counter overflow"))?;
            if next > self.inner.max_stdin_bytes {
                return Err(resource_error("worker stdin byte limit exceeded"));
            }
            // Reserve the bounded aggregate budget before enqueueing. A frame
            // that cannot be delivered before its deadline still consumes the
            // configured process budget; the transport is being closed on
            // that path and no later write is permitted.
            *count = next;
        }
        let mut pending = Some(bytes);
        loop {
            if let Some(error) = self.inner.failure() {
                return Err(error.with_stderr(self.inner.lifecycle.stderr.report()));
            }
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return Err(BridgeError::new(
                    BridgeErrorCode::Cancelled,
                    true,
                    "worker stdin writer was cancelled",
                ));
            }
            if self.inner.lifecycle.closed.load(Ordering::Acquire) {
                return Err(BridgeError::new(
                    BridgeErrorCode::WorkerUnavailable,
                    true,
                    "worker transport is closed",
                ));
            }
            if Instant::now() >= deadline {
                return Err(BridgeError::new(
                    BridgeErrorCode::DeadlineExceeded,
                    true,
                    "worker stdin writer exceeded deadline",
                ));
            }
            let sender = lock_unpoisoned(&self.inner.lifecycle.stdin)
                .as_ref()
                .cloned()
                .ok_or_else(|| {
                    BridgeError::new(
                        BridgeErrorCode::WorkerUnavailable,
                        true,
                        "worker stdin writer is closed",
                    )
                })?;
            let bytes = pending.take().ok_or_else(|| {
                BridgeError::new(
                    BridgeErrorCode::Io,
                    false,
                    "worker stdin writer lost a pending frame",
                )
            })?;
            match sender.try_send(bytes) {
                Ok(()) => return Ok(()),
                Err(TrySendError::Disconnected(_)) => {
                    return Err(BridgeError::new(
                        BridgeErrorCode::WorkerUnavailable,
                        true,
                        "worker stdin writer disconnected",
                    ));
                }
                Err(TrySendError::Full(bytes)) => {
                    pending = Some(bytes);
                }
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(BridgeError::new(
                    BridgeErrorCode::DeadlineExceeded,
                    true,
                    "worker stdin writer exceeded deadline",
                ));
            }
            thread::sleep(PROCESS_POLL_INTERVAL.min(deadline.saturating_duration_since(now)));
        }
    }

    fn wait_for_frame(
        &self,
        request_id: RequestId,
        deadline: Instant,
        cancellation: Option<&CancellationToken>,
    ) -> Result<Frame, WaitFailure> {
        loop {
            if let Some(error) = self.inner.failure() {
                return Err(WaitFailure::Error(error));
            }
            if let Some(frame) = self.take_pending(request_id) {
                return Ok(frame);
            }
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return Err(WaitFailure::Cancelled);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(WaitFailure::Timeout);
            }
            let mut wait = deadline.saturating_duration_since(now);
            if cancellation.is_some() {
                wait = wait.min(Duration::from_millis(20));
            }
            let event = {
                let receiver = lock_unpoisoned(&self.inner.events);
                receiver.recv_timeout(wait)
            };
            match event {
                Ok(ReaderEvent::Frame(frame)) if frame.request_id == request_id => {
                    return Ok(frame);
                }
                Ok(ReaderEvent::Frame(frame)) => {
                    let mut pending = lock_unpoisoned(&self.inner.pending);
                    let pending_count = pending.values().map(VecDeque::len).sum::<usize>();
                    if pending_count >= MAX_EVENT_QUEUE {
                        let error = self
                            .cleanup_error(resource_error("pending worker response queue is full"));
                        self.inner.set_failure(error.clone());
                        return Err(WaitFailure::Error(error));
                    }
                    pending
                        .entry(frame.request_id)
                        .or_default()
                        .push_back(frame);
                }
                Ok(ReaderEvent::Failure(error)) => {
                    self.inner.set_failure(error.clone());
                    return Err(WaitFailure::Error(error));
                }
                Ok(ReaderEvent::Eof) => {
                    let error = self.cleanup_error(BridgeError::new(
                        BridgeErrorCode::WorkerCrashed,
                        true,
                        "worker stdout closed before a response",
                    ));
                    self.inner.set_failure(error.clone());
                    return Err(WaitFailure::Error(error));
                }
                Err(RecvTimeoutError::Timeout)
                    if cancellation.is_some_and(CancellationToken::is_cancelled) =>
                {
                    return Err(WaitFailure::Cancelled);
                }
                Err(RecvTimeoutError::Timeout) if Instant::now() >= deadline => {
                    return Err(WaitFailure::Timeout);
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    let error = self.cleanup_error(BridgeError::new(
                        BridgeErrorCode::WorkerUnavailable,
                        true,
                        "worker event reader disconnected",
                    ));
                    self.inner.set_failure(error.clone());
                    return Err(WaitFailure::Error(error));
                }
            }
        }
    }

    fn cleanup_error(&self, error: BridgeError) -> BridgeError {
        self.inner.cleanup_error(error)
    }

    fn take_pending(&self, request_id: RequestId) -> Option<Frame> {
        let mut pending = lock_unpoisoned(&self.inner.pending);
        let queue = pending.get_mut(&request_id)?;
        let frame = queue.pop_front();
        if queue.is_empty() {
            pending.remove(&request_id);
        }
        frame
    }

    fn abort_request(
        &self,
        request_id: RequestId,
        code: BridgeErrorCode,
        message: &'static str,
    ) -> BridgeError {
        let cancel_error = self.cancel(request_id).err();
        let deadline = Instant::now()
            .checked_add(self.config.cancellation_timeout)
            .unwrap_or_else(Instant::now);
        let _ = self.wait_for_frame(request_id, deadline, None);
        let mut error = BridgeError::new(code, true, message)
            .with_request_id(request_id)
            .with_stderr(self.inner.lifecycle.stderr.report());
        if let Some(cancel_error) = cancel_error {
            error = combine_bridge_errors(error, cancel_error);
        }
        if let Err(cleanup) = self.inner.shutdown(true) {
            error = combine_bridge_errors(error, cleanup);
        }
        error
    }

    fn decode_response(
        &self,
        request_id: RequestId,
        frame: Frame,
    ) -> Result<WorkerResponse, BridgeError> {
        if frame.request_id != request_id {
            return Err(BridgeError::new(
                BridgeErrorCode::ProtocolViolation,
                false,
                "worker response request ID did not correlate",
            )
            .with_request_id(request_id)
            .with_stderr(self.inner.lifecycle.stderr.report()));
        }
        match frame.kind {
            MessageKind::Response => {
                if frame.cancellation == Cancellation::Cancelled {
                    return Err(BridgeError::new(
                        BridgeErrorCode::Cancelled,
                        true,
                        "worker acknowledged cancellation",
                    )
                    .with_request_id(request_id)
                    .with_stderr(self.inner.lifecycle.stderr.report()));
                }
                Ok(WorkerResponse {
                    request_id,
                    payload: frame.payload,
                })
            }
            MessageKind::Error => {
                let remote = self
                    .inner
                    .codec
                    .decode_remote_error(&frame)
                    .map_err(|error| {
                        BridgeError::new(
                            BridgeErrorCode::ProtocolViolation,
                            false,
                            format!("invalid structured worker error: {error}"),
                        )
                        .with_request_id(request_id)
                        .with_stderr(self.inner.lifecycle.stderr.report())
                    })?;
                Err(map_remote_error(
                    remote,
                    request_id,
                    self.inner.lifecycle.stderr.report(),
                ))
            }
            _ => Err(BridgeError::new(
                BridgeErrorCode::ProtocolViolation,
                false,
                format!("unexpected {} frame for operation response", frame.kind),
            )
            .with_request_id(request_id)
            .with_stderr(self.inner.lifecycle.stderr.report())),
        }
    }

    fn negotiate_handshake(&mut self, frame: Frame) -> Result<(), BridgeError> {
        if frame.request_id != HANDSHAKE_REQUEST_ID {
            return Err(BridgeError::new(
                BridgeErrorCode::ProtocolViolation,
                false,
                "worker handshake request ID did not match",
            ));
        }
        if frame.kind == MessageKind::Error {
            let remote = self
                .inner
                .codec
                .decode_remote_error(&frame)
                .map_err(|error| {
                    BridgeError::new(
                        BridgeErrorCode::ProtocolViolation,
                        false,
                        format!("invalid structured handshake error: {error}"),
                    )
                })?;
            return Err(map_remote_error(
                remote,
                HANDSHAKE_REQUEST_ID,
                self.inner.lifecycle.stderr.report(),
            ));
        }
        if frame.kind != MessageKind::Handshake {
            return Err(BridgeError::new(
                BridgeErrorCode::ProtocolViolation,
                false,
                format!("expected handshake response, got {}", frame.kind),
            ));
        }
        let profile = frame.profile.ok_or_else(|| {
            BridgeError::new(
                BridgeErrorCode::ProfileMismatch,
                false,
                "worker handshake omitted profile",
            )
        })?;
        if profile != self.config.profile {
            return Err(BridgeError::new(
                BridgeErrorCode::ProfileMismatch,
                false,
                "worker profile did not match requested profile",
            ));
        }
        for required in &self.config.capabilities {
            if !frame.capabilities.iter().any(|item| item == required) {
                return Err(BridgeError::new(
                    BridgeErrorCode::CapabilityUnavailable,
                    false,
                    format!("worker lacks required capability {required}"),
                ));
            }
        }
        self.info = WorkerInfo {
            protocol_version: PROTOCOL_VERSION,
            profile,
            capabilities: frame.capabilities,
        };
        Ok(())
    }

    fn shutdown_error(&self, error: BridgeError) -> BridgeError {
        match self.inner.shutdown(true) {
            Ok(()) => error,
            Err(cleanup) => combine_bridge_errors(error, cleanup),
        }
    }

    fn shutdown_best_effort(&self) {
        if let Err(error) = self.inner.shutdown(true) {
            self.inner.set_failure(error);
        }
        self.inner.lifecycle.control.reap_on_drop();
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.shutdown_best_effort();
    }
}

struct WorkerThreads {
    stdout: Mutex<Option<JoinHandle<()>>>,
    stderr: Mutex<Option<JoinHandle<()>>>,
    stdin: Mutex<Option<JoinHandle<()>>>,
}

impl WorkerThreads {
    fn new() -> Self {
        Self {
            stdout: Mutex::new(None),
            stderr: Mutex::new(None),
            stdin: Mutex::new(None),
        }
    }

    fn set_stdout(&self, thread: JoinHandle<()>) {
        *lock_unpoisoned(&self.stdout) = Some(thread);
    }

    fn set_stderr(&self, thread: JoinHandle<()>) {
        *lock_unpoisoned(&self.stderr) = Some(thread);
    }

    fn set_stdin(&self, thread: JoinHandle<()>) {
        *lock_unpoisoned(&self.stdin) = Some(thread);
    }
}

struct WorkerLifecycle {
    stdin: Arc<Mutex<Option<SyncSender<Vec<u8>>>>>,
    failures: Arc<FailureState>,
    stderr: Arc<StderrCollector>,
    control: Arc<ProcessControl>,
    closed: AtomicBool,
    threads: Arc<WorkerThreads>,
    shutdown: Mutex<ShutdownState>,
    shutdown_cv: Condvar,
    join: Mutex<JoinState>,
    join_cv: Condvar,
}

impl WorkerLifecycle {
    fn new(
        stdin: Arc<Mutex<Option<SyncSender<Vec<u8>>>>>,
        failures: Arc<FailureState>,
        stderr: Arc<StderrCollector>,
        control: Arc<ProcessControl>,
        threads: Arc<WorkerThreads>,
    ) -> Self {
        Self {
            stdin,
            failures,
            stderr,
            control,
            closed: AtomicBool::new(false),
            threads,
            shutdown: Mutex::new(ShutdownState::default()),
            shutdown_cv: Condvar::new(),
            join: Mutex::new(JoinState::default()),
            join_cv: Condvar::new(),
        }
    }

    fn shutdown(&self, join_threads: bool) -> Result<(), BridgeError> {
        {
            let mut state = lock_unpoisoned(&self.shutdown);
            if let Some(running) = state.running {
                while state.running == Some(running) {
                    state = match self.shutdown_cv.wait(state) {
                        Ok(state) => state,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                }
                let result = state
                    .completed
                    .as_ref()
                    .map(|completed| (*completed.result).clone())
                    .unwrap_or_else(|| {
                        Err(BridgeError::new(
                            BridgeErrorCode::Shutdown,
                            true,
                            "worker cleanup result was lost",
                        ))
                    });
                if !join_threads {
                    return result;
                }
                drop(state);
                return self.finish_join(result);
            }
            if let Some(completed) = state.completed.as_ref()
                && completed.terminal
            {
                let result = (*completed.result).clone();
                if !join_threads {
                    return result;
                }
                drop(state);
                return self.finish_join(result);
            }
            state.next_generation = state.next_generation.wrapping_add(1).max(1);
            state.running = Some(state.next_generation);
        }

        self.closed.store(true, Ordering::Release);
        // Dropping the sender closes the bounded queue before the exact
        // child is signalled. Fatal reader/writer paths and explicit
        // shutdown therefore share one terminal transport state.
        let stdin = lock_unpoisoned(&self.stdin).take();
        drop(stdin);
        let result = self
            .control
            .terminate()
            .map_err(|error| cleanup_bridge_error(&self.stderr, &error));
        let mut state = lock_unpoisoned(&self.shutdown);
        state.completed = Some(CompletedShutdown {
            result: Arc::new(result.clone()),
            terminal: self.control.cleanup_terminal(),
        });
        state.running = None;
        self.shutdown_cv.notify_all();
        if join_threads {
            self.finish_join(result)
        } else {
            result
        }
    }

    fn finish_join(&self, result: Result<(), BridgeError>) -> Result<(), BridgeError> {
        let should_join = {
            let mut state = lock_unpoisoned(&self.join);
            if let Some(completed) = state.completed.as_ref() {
                return combine_results(result, (**completed).clone());
            }
            if state.running {
                while state.running {
                    state = match self.join_cv.wait(state) {
                        Ok(state) => state,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                }
                let join_result = state
                    .completed
                    .as_ref()
                    .map(|completed| (**completed).clone())
                    .unwrap_or_else(|| {
                        Err(BridgeError::new(
                            BridgeErrorCode::Shutdown,
                            true,
                            "worker thread join result was lost",
                        ))
                    });
                return combine_results(result, join_result);
            }
            state.running = true;
            true
        };
        if should_join {
            let join_result = self.join_threads();
            let combined = combine_results(result, join_result.clone());
            let mut state = lock_unpoisoned(&self.join);
            state.completed = Some(Arc::new(join_result));
            state.running = false;
            self.join_cv.notify_all();
            return combined;
        }
        result
    }

    fn join_threads(&self) -> Result<(), BridgeError> {
        let join_deadline = Instant::now()
            .checked_add(self.control.cleanup_timeout())
            .unwrap_or_else(Instant::now);
        let mut result = Ok(());
        for (slot, name) in [
            (&self.threads.stdin, "stdin writer"),
            (&self.threads.stdout, "stdout reader"),
            (&self.threads.stderr, "stderr reader"),
        ] {
            if let Some(thread) = lock_unpoisoned(slot).take()
                && let Err(error) = join_thread_until(thread, join_deadline, name)
            {
                result = Err(match result {
                    Ok(()) => error,
                    Err(primary) => combine_bridge_errors(primary, error),
                });
            }
        }
        result
    }

    fn report_failure(&self, error: BridgeError, sender: &SyncSender<ReaderEvent>) {
        let mut error = error.with_stderr(self.stderr.report());
        if let Err(cleanup) = self.shutdown(false) {
            error = combine_bridge_errors(error, cleanup);
        }
        self.failures.set(error.clone());
        let _ = sender.try_send(ReaderEvent::Failure(error));
    }
}

struct WorkerInner {
    lifecycle: Arc<WorkerLifecycle>,
    stdin_bytes: Mutex<usize>,
    events: Mutex<Receiver<ReaderEvent>>,
    pending: Mutex<HashMap<RequestId, VecDeque<Frame>>>,
    outstanding: Mutex<HashSet<RequestId>>,
    codec: FrameCodec,
    max_stdin_bytes: usize,
    max_message_bytes: usize,
    next_request_id: AtomicU64,
}

#[derive(Default)]
struct ShutdownState {
    next_generation: u64,
    running: Option<u64>,
    completed: Option<CompletedShutdown>,
}

#[derive(Default)]
struct JoinState {
    running: bool,
    completed: Option<Arc<Result<(), BridgeError>>>,
}

struct CompletedShutdown {
    result: Arc<Result<(), BridgeError>>,
    terminal: bool,
}

impl WorkerInner {
    fn failure(&self) -> Option<BridgeError> {
        self.lifecycle.failures.get()
    }

    fn set_failure(&self, error: BridgeError) {
        self.lifecycle.failures.set(error);
    }

    fn release_request_id(&self, request_id: RequestId) {
        lock_unpoisoned(&self.outstanding).remove(&request_id);
    }

    fn shutdown(&self, join_threads: bool) -> Result<(), BridgeError> {
        self.lifecycle.shutdown(join_threads)
    }

    fn cleanup_error(&self, error: BridgeError) -> BridgeError {
        match self.lifecycle.shutdown(false) {
            Ok(()) => error,
            Err(cleanup) => combine_bridge_errors(error, cleanup),
        }
    }
}

#[derive(Default)]
struct FailureState {
    error: Mutex<Option<BridgeError>>,
}

impl FailureState {
    fn get(&self) -> Option<BridgeError> {
        lock_unpoisoned(&self.error).clone()
    }

    fn set(&self, error: BridgeError) {
        let mut current = lock_unpoisoned(&self.error);
        if current.is_none() {
            *current = Some(error);
        }
    }
}

/// A process-group identifier that is safe to pass to a group-signal API.
///
/// Values one or below have process-wide or implementation-defined meaning,
/// and values that cannot be represented by the platform PID type are never
/// accepted. The only production constructor from a worker process is derived
/// from the successfully spawned child's PID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessGroupId(i32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessGroupIdError {
    Reserved,
    OutOfRange,
}

impl TryFrom<i64> for ProcessGroupId {
    type Error = ProcessGroupIdError;

    fn try_from(raw: i64) -> Result<Self, Self::Error> {
        let raw = i32::try_from(raw).map_err(|_| ProcessGroupIdError::OutOfRange)?;
        if raw <= 1 {
            return Err(ProcessGroupIdError::Reserved);
        }
        Ok(Self(raw))
    }
}

impl TryFrom<u64> for ProcessGroupId {
    type Error = ProcessGroupIdError;

    fn try_from(raw: u64) -> Result<Self, Self::Error> {
        let raw = i32::try_from(raw).map_err(|_| ProcessGroupIdError::OutOfRange)?;
        if raw <= 1 {
            return Err(ProcessGroupIdError::Reserved);
        }
        Ok(Self(raw))
    }
}

impl TryFrom<u32> for ProcessGroupId {
    type Error = ProcessGroupIdError;

    fn try_from(raw: u32) -> Result<Self, Self::Error> {
        Self::try_from(u64::from(raw))
    }
}

impl ProcessGroupId {
    const fn as_raw(self) -> i32 {
        self.0
    }
}

struct ProcessControl {
    child: Mutex<Option<Child>>,
    policy: ProcessGroupPolicy,
    pid: u32,
    process_group_pid: u32,
    cleanup_timeout: Duration,
    signaler: Arc<dyn ProcessGroupSignaler>,
    direct_signaler: Arc<dyn DirectChildSignaler>,
    reaper_spawner: Arc<dyn ChildReaperSpawner>,
    cleanup: Mutex<ProcessState>,
    cleanup_cv: Condvar,
}

#[derive(Default)]
struct ProcessState {
    next_generation: u64,
    running: Option<u64>,
    completed: Option<CompletedCleanup>,
}

struct CompletedCleanup {
    generation: u64,
    result: Arc<io::Result<()>>,
    terminal: bool,
}

trait ProcessGroupSignaler: Send + Sync {
    fn signal(&self, process_group: ProcessGroupId) -> io::Result<()>;
}

trait DirectChildSignaler: Send + Sync {
    fn signal(&self, child: &mut Child) -> io::Result<()>;
}

trait ChildReaperSpawner: Send + Sync {
    fn spawn(&self, child: Child, timeout: Duration) -> ReaperSpawnResult;
}

enum ReaperSpawnResult {
    Spawned,
    Failed(Child),
}

struct OperatingSystemProcessGroupSignaler;

#[cfg(unix)]
impl ProcessGroupSignaler for OperatingSystemProcessGroupSignaler {
    fn signal(&self, process_group: ProcessGroupId) -> io::Result<()> {
        signal_process_group(process_group)
    }
}

#[cfg(not(unix))]
impl ProcessGroupSignaler for OperatingSystemProcessGroupSignaler {
    fn signal(&self, _process_group: ProcessGroupId) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "process-group signalling is unsupported on this platform",
        ))
    }
}

struct OperatingSystemDirectChildSignaler;

impl DirectChildSignaler for OperatingSystemDirectChildSignaler {
    fn signal(&self, child: &mut Child) -> io::Result<()> {
        signal_direct_child(child)
    }
}

struct OperatingSystemChildReaperSpawner;

impl ChildReaperSpawner for OperatingSystemChildReaperSpawner {
    fn spawn(&self, child: Child, timeout: Duration) -> ReaperSpawnResult {
        let holder = Arc::new(Mutex::new(Some(child)));
        let thread_holder = Arc::clone(&holder);
        match thread::Builder::new()
            .name("jmeter-java-bridge-reaper".to_owned())
            .spawn(move || {
                if let Some(child) = lock_unpoisoned(&thread_holder).take() {
                    reap_owned_child(child, timeout);
                }
            }) {
            Ok(_) => ReaperSpawnResult::Spawned,
            Err(_) => match lock_unpoisoned(&holder).take() {
                Some(child) => ReaperSpawnResult::Failed(child),
                None => ReaperSpawnResult::Spawned,
            },
        }
    }
}

impl ProcessControl {
    fn new(child: Child, policy: ProcessGroupPolicy, cleanup_timeout: Duration) -> Self {
        Self::with_signaler(
            child,
            policy,
            cleanup_timeout,
            Arc::new(OperatingSystemProcessGroupSignaler),
        )
    }

    fn with_signaler(
        child: Child,
        policy: ProcessGroupPolicy,
        cleanup_timeout: Duration,
        signaler: Arc<dyn ProcessGroupSignaler>,
    ) -> Self {
        let pid = child.id();
        Self::with_signals(
            child,
            policy,
            cleanup_timeout,
            pid,
            signaler,
            Arc::new(OperatingSystemDirectChildSignaler),
        )
    }

    fn with_signals(
        child: Child,
        policy: ProcessGroupPolicy,
        cleanup_timeout: Duration,
        process_group_pid: u32,
        signaler: Arc<dyn ProcessGroupSignaler>,
        direct_signaler: Arc<dyn DirectChildSignaler>,
    ) -> Self {
        Self::with_reaper_spawner(
            child,
            policy,
            cleanup_timeout,
            process_group_pid,
            signaler,
            direct_signaler,
            Arc::new(OperatingSystemChildReaperSpawner),
        )
    }

    fn with_reaper_spawner(
        child: Child,
        policy: ProcessGroupPolicy,
        cleanup_timeout: Duration,
        process_group_pid: u32,
        signaler: Arc<dyn ProcessGroupSignaler>,
        direct_signaler: Arc<dyn DirectChildSignaler>,
        reaper_spawner: Arc<dyn ChildReaperSpawner>,
    ) -> Self {
        let pid = child.id();
        Self {
            child: Mutex::new(Some(child)),
            policy,
            pid,
            process_group_pid,
            cleanup_timeout: if cleanup_timeout.is_zero() {
                DEFAULT_CANCELLATION_TIMEOUT
            } else {
                cleanup_timeout
            },
            signaler,
            direct_signaler,
            reaper_spawner,
            cleanup: Mutex::new(ProcessState::default()),
            cleanup_cv: Condvar::new(),
        }
    }

    fn cleanup_timeout(&self) -> Duration {
        self.cleanup_timeout
    }

    fn cleanup_terminal(&self) -> bool {
        lock_unpoisoned(&self.cleanup)
            .completed
            .as_ref()
            .is_some_and(|completed| completed.terminal)
    }

    fn take_stdin(&self) -> Option<ChildStdin> {
        lock_unpoisoned(&self.child)
            .as_mut()
            .and_then(|child| child.stdin.take())
    }

    fn take_stdout(&self) -> Option<std::process::ChildStdout> {
        lock_unpoisoned(&self.child)
            .as_mut()
            .and_then(|child| child.stdout.take())
    }

    fn take_stderr(&self) -> Option<std::process::ChildStderr> {
        lock_unpoisoned(&self.child)
            .as_mut()
            .and_then(|child| child.stderr.take())
    }

    fn terminate(&self) -> io::Result<()> {
        let generation = {
            let mut state = lock_unpoisoned(&self.cleanup);
            if let Some(running) = state.running {
                while state.running == Some(running) {
                    state = match self.cleanup_cv.wait(state) {
                        Ok(state) => state,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                }
                return state
                    .completed
                    .as_ref()
                    .filter(|completed| completed.generation == running)
                    .map(|completed| clone_io_result(completed.result.as_ref()))
                    .unwrap_or_else(|| Err(io::Error::other("process cleanup result was lost")));
            }
            if let Some(completed) = state.completed.as_ref()
                && completed.terminal
            {
                return clone_io_result(completed.result.as_ref());
            }
            state.next_generation = state.next_generation.wrapping_add(1).max(1);
            let generation = state.next_generation;
            state.running = Some(generation);
            generation
        };

        let attempt = self.terminate_once();
        let result = attempt.result;
        let shared = Arc::new(clone_io_result(&result));
        let mut state = lock_unpoisoned(&self.cleanup);
        state.completed = Some(CompletedCleanup {
            generation,
            result: shared,
            terminal: attempt.terminal,
        });
        state.running = None;
        self.cleanup_cv.notify_all();
        result
    }

    fn terminate_once(&self) -> CleanupAttempt {
        let mut child_slot = lock_unpoisoned(&self.child);
        let Some(child) = child_slot.as_mut() else {
            return CleanupAttempt::terminal(Ok(()));
        };

        // This is the ownership check immediately before any signal. An
        // exited child is reaped by `try_wait` and is never signalled.
        match child.try_wait() {
            Ok(Some(_status)) => {
                *child_slot = None;
                return CleanupAttempt::terminal(Ok(()));
            }
            Ok(None) => {}
            Err(error) if is_missing_process(&error) => {
                // An ESRCH/NotFound liveness error does not prove that this
                // exact handle was reaped. Keep the handle and expose the
                // raw OS error so a later cleanup attempt can retry safely.
                return CleanupAttempt::retryable(Err(error));
            }
            Err(error) => {
                return CleanupAttempt::retryable(Err(io_error_with_context(
                    "check worker process before cleanup",
                    error,
                )));
            }
        }

        let mut cleanup_error = None;
        if self.policy == ProcessGroupPolicy::Required {
            // Read and validate the group id only after the liveness proof
            // above. The id comes from this still-live, unreaped Child handle.
            match ProcessGroupId::try_from(self.process_group_pid) {
                Ok(process_group) => {
                    cleanup_error = self.signaler.signal(process_group).err();
                }
                Err(error) => {
                    // Required group cleanup must not silently downgrade to a
                    // direct-child-only policy. The exact child remains the
                    // safe fallback, but the policy failure is retained.
                    cleanup_error = Some(process_group_policy_error(self.process_group_pid, error));
                    if let Err(direct_error) = self.direct_signaler.signal(child) {
                        cleanup_error = Some(combine_cleanup_errors(cleanup_error, direct_error));
                    }
                    let attempt = finish_direct_cleanup(child, cleanup_error, self.cleanup_timeout);
                    if attempt.terminal {
                        *child_slot = None;
                    }
                    return attempt;
                }
            }
        }

        if let Some(signal_error) = cleanup_error.as_ref() {
            // A failed group signal, including ESRCH, immediately uses the
            // exact owned child fallback. The group error remains typed even
            // when direct fallback/reap proves cleanup completed.
            if let Err(direct_error) = self.direct_signaler.signal(child) {
                return CleanupAttempt::retryable(Err(combine_cleanup_errors(
                    cleanup_error,
                    direct_error,
                )));
            }
            let deadline = Instant::now()
                .checked_add(self.cleanup_timeout)
                .unwrap_or_else(Instant::now);
            let attempt = finish_reap_cleanup(child, Some(clone_io_error(signal_error)), deadline);
            if attempt.terminal {
                *child_slot = None;
            }
            return attempt;
        }

        let first_deadline = Instant::now()
            .checked_add(self.cleanup_timeout)
            .unwrap_or_else(Instant::now);
        match reap_until(child, first_deadline) {
            Ok(()) => {
                *child_slot = None;
                return CleanupAttempt::terminal(cleanup_error.map_or(Ok(()), Err));
            }
            Err(error) if error.kind() != io::ErrorKind::TimedOut => {
                return CleanupAttempt::retryable(Err(combine_cleanup_errors(
                    cleanup_error,
                    error,
                )));
            }
            Err(_) => {}
        }

        // A group signal can succeed while the direct child escaped the
        // group, and ESRCH can race with that escape. In either case the exact
        // owned Child handle is the only safe fallback.
        if let Err(error) = self.direct_signaler.signal(child) {
            return CleanupAttempt::retryable(Err(combine_cleanup_errors(cleanup_error, error)));
        }
        let second_deadline = Instant::now()
            .checked_add(self.cleanup_timeout)
            .unwrap_or_else(Instant::now);
        match reap_until(child, second_deadline) {
            Ok(()) => {
                *child_slot = None;
                CleanupAttempt::terminal(cleanup_error.map_or(Ok(()), Err))
            }
            Err(error) => {
                CleanupAttempt::retryable(Err(combine_cleanup_errors(cleanup_error, error)))
            }
        }
    }
}

struct CleanupAttempt {
    result: io::Result<()>,
    terminal: bool,
}

impl CleanupAttempt {
    fn terminal(result: io::Result<()>) -> Self {
        Self {
            result,
            terminal: true,
        }
    }

    fn retryable(result: io::Result<()>) -> Self {
        Self {
            result,
            terminal: false,
        }
    }
}

fn finish_direct_cleanup(
    child: &mut Child,
    cleanup_error: Option<io::Error>,
    timeout: Duration,
) -> CleanupAttempt {
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    finish_reap_cleanup(child, cleanup_error, deadline)
}

fn finish_reap_cleanup(
    child: &mut Child,
    cleanup_error: Option<io::Error>,
    deadline: Instant,
) -> CleanupAttempt {
    match reap_until(child, deadline) {
        Ok(()) => CleanupAttempt::terminal(cleanup_error.map_or(Ok(()), Err)),
        Err(error) => CleanupAttempt::retryable(Err(combine_cleanup_errors(cleanup_error, error))),
    }
}

fn clone_io_result(result: &io::Result<()>) -> io::Result<()> {
    result.as_ref().map(|_| ()).map_err(clone_io_error)
}

fn clone_io_error(error: &io::Error) -> io::Error {
    match error.get_ref().and_then(|source| {
        source
            .downcast_ref::<CleanupAggregate>()
            .map(|aggregate| (error.kind(), aggregate.clone()))
    }) {
        Some((kind, aggregate)) => io::Error::new(kind, aggregate),
        None => match error.raw_os_error() {
            Some(code) => io::Error::from_raw_os_error(code),
            None => io::Error::new(error.kind(), error.to_string()),
        },
    }
}

fn cleanup_raw_os_error(error: &io::Error) -> Option<i32> {
    error.raw_os_error().or_else(|| {
        error
            .get_ref()
            .and_then(|source| source.downcast_ref::<CleanupAggregate>())
            .and_then(|aggregate| aggregate.raw_os_error)
    })
}

#[derive(Clone, Debug)]
struct CleanupAggregate {
    message: String,
    raw_os_error: Option<i32>,
}

impl fmt::Display for CleanupAggregate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CleanupAggregate {}

fn cleanup_error_detail(error: &io::Error) -> String {
    match cleanup_raw_os_error(error) {
        Some(code) => format!("{error} (os error {code})"),
        None => error.to_string(),
    }
}

fn cleanup_bridge_error(stderr: &StderrCollector, error: &io::Error) -> BridgeError {
    let code = if error.kind() == io::ErrorKind::InvalidInput
        && error
            .to_string()
            .starts_with("required process-group policy rejected")
    {
        BridgeErrorCode::ProcessGroupUnavailable
    } else {
        BridgeErrorCode::Shutdown
    };
    let mut result = BridgeError::new(
        code,
        true,
        format!("worker cleanup failed: {}", cleanup_error_detail(error)),
    )
    .with_stderr(stderr.report());
    result.os_error = cleanup_raw_os_error(error);
    result
}

fn combine_bridge_errors(mut primary: BridgeError, secondary: BridgeError) -> BridgeError {
    primary.retryable |= secondary.retryable;
    primary.message = format!(
        "{}; additional cleanup failure: {}",
        primary.message, secondary
    );
    if primary.os_error.is_none() {
        primary.os_error = secondary.os_error;
    }
    if primary.stderr.is_none() {
        primary.stderr = secondary.stderr;
    }
    primary
}

fn combine_results(
    primary: Result<(), BridgeError>,
    secondary: Result<(), BridgeError>,
) -> Result<(), BridgeError> {
    match (primary, secondary) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(error)) | (Err(error), Ok(())) => Err(error),
        (Err(primary), Err(secondary)) => Err(combine_bridge_errors(primary, secondary)),
    }
}

fn startup_failure(error: BridgeError, lifecycle: &WorkerLifecycle) -> BridgeError {
    let cleanup = lifecycle.shutdown(false);
    let joins = lifecycle.finish_join(Ok(()));
    let mut result = error;
    if let Err(cleanup) = cleanup {
        result = combine_bridge_errors(result, cleanup);
    }
    if let Err(joins) = joins {
        result = combine_bridge_errors(result, joins);
    }
    lifecycle.control.reap_on_drop();
    result
}

fn combine_cleanup_errors(first: Option<io::Error>, second: io::Error) -> io::Error {
    match first {
        Some(first) => {
            let raw_os_error =
                cleanup_raw_os_error(&second).or_else(|| cleanup_raw_os_error(&first));
            let kind = if first.kind() == io::ErrorKind::InvalidInput {
                first.kind()
            } else {
                second.kind()
            };
            io::Error::new(
                kind,
                CleanupAggregate {
                    message: format!("{first}; {second}"),
                    raw_os_error,
                },
            )
        }
        None => second,
    }
}

fn reap_until(child: &mut Child, deadline: Instant) -> io::Result<()> {
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => return Ok(()),
            Ok(None) => {}
            Err(error) => {
                return Err(io_error_with_context("poll worker process cleanup", error));
            }
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "worker process did not exit before cleanup deadline",
            ));
        }
        thread::sleep(PROCESS_POLL_INTERVAL.min(deadline.saturating_duration_since(now)));
    }
}

fn signal_direct_child(child: &mut Child) -> io::Result<()> {
    // Keep the second liveness check adjacent to the direct signal. The Child
    // remains owned and unreaped throughout, so its PID cannot be reused for
    // an unrelated process.
    match child.try_wait() {
        Ok(Some(_status)) => Ok(()),
        Ok(None) => child
            .kill()
            .map_err(|error| io_error_with_context("terminate direct worker child", error)),
        Err(error) => Err(io_error_with_context(
            "check worker before direct termination",
            error,
        )),
    }
}

fn is_missing_process(error: &io::Error) -> bool {
    // ESRCH is only a liveness observation. It is benign after the owned
    // Child has independently reported exit and been reaped; on an otherwise
    // live/unreaped handle it remains a typed retryable cleanup failure.
    #[cfg(unix)]
    {
        error.kind() == io::ErrorKind::NotFound
            || cleanup_raw_os_error(error) == Some(nix::errno::Errno::ESRCH as i32)
    }
    #[cfg(not(unix))]
    {
        error.kind() == io::ErrorKind::NotFound
    }
}

fn io_error_with_context(context: &str, error: io::Error) -> io::Error {
    match cleanup_raw_os_error(&error) {
        Some(code) => io::Error::from_raw_os_error(code),
        None => io::Error::new(error.kind(), format!("{context}: {error}")),
    }
}

fn process_group_policy_error(raw: u32, error: ProcessGroupIdError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("required process-group policy rejected child id {raw}: {error:?}"),
    )
}

#[cfg(unix)]
fn signal_process_group(process_group: ProcessGroupId) -> io::Result<()> {
    killpg(Pid::from_raw(process_group.as_raw()), Signal::SIGKILL).map_err(io::Error::from)
}

impl Drop for ProcessControl {
    fn drop(&mut self) {
        // A retryable timeout is intentionally not terminal. Make the
        // bounded state-machine attempt once more, then hand the exact still-
        // owned Child to a bounded polling reaper rather than dropping it and
        // risking an orphan.
        let _ = self.terminate();
        self.reap_on_drop();
    }
}

impl ProcessControl {
    fn reap_on_drop(&self) {
        if let Some(child) = lock_unpoisoned(&self.child).take() {
            let timeout = self.cleanup_timeout;
            match self.reaper_spawner.spawn(child, timeout) {
                ReaperSpawnResult::Spawned => {}
                ReaperSpawnResult::Failed(mut child) => {
                    // A failed reaper spawn must not drop the exact owned
                    // handle. Make one bounded direct-child attempt, then
                    // retain the still-live handle in the exact-child
                    // registry for a later cleanup owner.
                    let _ = self.direct_signaler.signal(&mut child);
                    let deadline = Instant::now()
                        .checked_add(timeout)
                        .unwrap_or_else(Instant::now);
                    if reap_until(&mut child, deadline).is_err() {
                        retain_unreaped_child(child);
                    }
                }
            }
        }
    }
}

static UNREAPED_CHILDREN: OnceLock<Mutex<Vec<Child>>> = OnceLock::new();

fn retain_unreaped_child(child: Child) {
    let registry = UNREAPED_CHILDREN.get_or_init(|| Mutex::new(Vec::new()));
    lock_unpoisoned(registry).push(child);
}

fn reap_owned_child(mut child: Child, timeout: Duration) {
    for _ in 0..MAX_REAPER_ATTEMPTS {
        match child.try_wait() {
            Ok(Some(_status)) => return,
            Ok(None) => {
                let _ = child.kill();
            }
            Err(_) => {}
        }
        thread::sleep(PROCESS_POLL_INTERVAL.min(timeout));
    }
    // Keep the exact handle owned if a platform-specific failure prevents
    // bounded polling from proving exit. The registry is deliberately exact-
    // child only; it never discovers or signals by a stale PID.
    retain_unreaped_child(child);
}

fn join_thread_until(
    thread: JoinHandle<()>,
    deadline: Instant,
    name: &str,
) -> Result<(), BridgeError> {
    let mut thread = Some(thread);
    loop {
        let Some(handle) = thread.as_ref() else {
            return Ok(());
        };
        if handle.is_finished() {
            let handle = thread.take().ok_or_else(|| {
                BridgeError::new(
                    BridgeErrorCode::Shutdown,
                    true,
                    format!("{name} join handle was lost"),
                )
            })?;
            return handle.join().map_err(|_| {
                BridgeError::new(
                    BridgeErrorCode::Shutdown,
                    true,
                    format!("{name} thread panicked during cleanup"),
                )
            });
        }
        let now = Instant::now();
        if now >= deadline {
            // Dropping JoinHandle detaches the bounded cleanup thread. The
            // process and its pipes remain owned by the Arc<ProcessControl>
            // captured by that thread, so no broad process discovery occurs.
            return Err(BridgeError::new(
                BridgeErrorCode::Shutdown,
                true,
                format!("{name} did not stop before cleanup deadline"),
            ));
        }
        thread::sleep(PROCESS_POLL_INTERVAL.min(deadline.saturating_duration_since(now)));
    }
}

struct StderrCollector {
    limit: usize,
    patterns: Vec<Vec<u8>>,
    state: Mutex<StderrState>,
}

struct StderrState {
    bytes_seen: usize,
    bytes: Vec<u8>,
    exceeded: bool,
}

impl StderrCollector {
    fn new(limit: usize, patterns: Vec<Vec<u8>>) -> Self {
        Self {
            limit,
            patterns,
            state: Mutex::new(StderrState {
                bytes_seen: 0,
                bytes: Vec::new(),
                exceeded: false,
            }),
        }
    }

    fn append(&self, bytes: &[u8]) {
        let mut state = lock_unpoisoned(&self.state);
        state.bytes_seen = state.bytes_seen.saturating_add(bytes.len());
        let remaining = self.limit.saturating_sub(state.bytes.len());
        if remaining != 0 {
            state
                .bytes
                .extend_from_slice(&bytes[..bytes.len().min(remaining)]);
        }
        if state.bytes_seen > self.limit {
            state.exceeded = true;
        }
    }

    fn exceeded(&self) -> bool {
        lock_unpoisoned(&self.state).exceeded
    }

    fn report(&self) -> StderrReport {
        let state = lock_unpoisoned(&self.state);
        let raw = String::from_utf8_lossy(&state.bytes).into_owned();
        let mut text = raw;
        let mut redacted = false;
        for pattern in &self.patterns {
            if let Ok(pattern) = std::str::from_utf8(pattern)
                && !pattern.is_empty()
                && text.contains(pattern)
            {
                text = text.replace(pattern, "[REDACTED]");
                redacted = true;
            }
        }
        if state.exceeded {
            text.push_str(" ... [truncated]");
        }
        StderrReport {
            text,
            bytes_seen: state.bytes_seen,
            truncated: state.exceeded,
            redacted,
        }
    }
}

#[derive(Debug)]
enum ReaderEvent {
    Frame(Frame),
    Failure(BridgeError),
    Eof,
}

#[derive(Debug)]
enum WaitFailure {
    Timeout,
    Cancelled,
    Error(BridgeError),
}

fn spawn_stdin_writer(
    stdin: ChildStdin,
    receiver: Receiver<Vec<u8>>,
    sender: SyncSender<ReaderEvent>,
    lifecycle: Arc<WorkerLifecycle>,
) -> Result<JoinHandle<()>, BridgeError> {
    thread::Builder::new()
        .name("jmeter-java-bridge-stdin".to_owned())
        .spawn(move || stdin_writer(stdin, receiver, sender, lifecycle))
        .map_err(|error| io_error("start stdin writer", error))
}

fn stdin_writer(
    mut stdin: ChildStdin,
    receiver: Receiver<Vec<u8>>,
    sender: SyncSender<ReaderEvent>,
    lifecycle: Arc<WorkerLifecycle>,
) {
    while let Ok(bytes) = receiver.recv() {
        if let Err(error) = stdin.write_all(&bytes).and_then(|()| stdin.flush()) {
            lifecycle.report_failure(io_error("write worker frame", error), &sender);
            return;
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "reader wiring keeps each bounded dependency explicit"
)]
fn spawn_stdout_reader(
    stdout: std::process::ChildStdout,
    codec: FrameCodec,
    stdout_limit: usize,
    message_limit: usize,
    sender: SyncSender<ReaderEvent>,
    lifecycle: Arc<WorkerLifecycle>,
) -> Result<JoinHandle<()>, BridgeError> {
    thread::Builder::new()
        .name("jmeter-java-bridge-stdout".to_owned())
        .spawn(move || {
            stdout_reader(
                stdout,
                codec,
                stdout_limit,
                message_limit,
                sender,
                lifecycle,
            )
        })
        .map_err(|error| io_error("start stdout reader", error))
}

fn spawn_stderr_reader(
    stderr_input: std::process::ChildStderr,
    sender: SyncSender<ReaderEvent>,
    lifecycle: Arc<WorkerLifecycle>,
) -> Result<JoinHandle<()>, BridgeError> {
    thread::Builder::new()
        .name("jmeter-java-bridge-stderr".to_owned())
        .spawn(move || stderr_reader(stderr_input, sender, lifecycle))
        .map_err(|error| io_error("start stderr reader", error))
}

#[allow(
    clippy::too_many_arguments,
    reason = "reader wiring keeps each bounded dependency explicit"
)]
fn stdout_reader(
    mut stdout: std::process::ChildStdout,
    codec: FrameCodec,
    stdout_limit: usize,
    message_limit: usize,
    sender: SyncSender<ReaderEvent>,
    lifecycle: Arc<WorkerLifecycle>,
) {
    let mut buffer = Vec::new();
    let mut scratch = [0_u8; READER_CHUNK_BYTES];
    let mut bytes_seen = 0usize;
    loop {
        let read = match stdout.read(&mut scratch) {
            Ok(read) => read,
            Err(error) => {
                publish_failure(io_error("read worker stdout", error), &sender, &lifecycle);
                return;
            }
        };
        if read == 0 {
            let _ = sender.try_send(ReaderEvent::Eof);
            return;
        }
        bytes_seen = bytes_seen.saturating_add(read);
        if bytes_seen > stdout_limit {
            publish_failure(
                resource_error(format!("worker stdout exceeds {stdout_limit} bytes")),
                &sender,
                &lifecycle,
            );
            return;
        }
        buffer.extend_from_slice(&scratch[..read]);
        if buffer.len() >= HEADER_LEN {
            let metadata_len =
                u32::from_be_bytes([buffer[28], buffer[29], buffer[30], buffer[31]]) as usize;
            let payload_len =
                u32::from_be_bytes([buffer[32], buffer[33], buffer[34], buffer[35]]) as usize;
            let declared_len = HEADER_LEN
                .checked_add(metadata_len)
                .and_then(|length| length.checked_add(payload_len));
            if declared_len.is_none_or(|length| length > message_limit) {
                publish_failure(
                    resource_error("worker frame exceeds message limit"),
                    &sender,
                    &lifecycle,
                );
                return;
            }
        }
        let mut input = buffer.as_slice();
        let mut consumed = 0usize;
        loop {
            let input_before = input.len();
            match codec.decode_next(&mut input) {
                Ok(Some(frame)) => {
                    let frame_len = input_before - input.len();
                    consumed += frame_len;
                    if frame_len > message_limit {
                        publish_failure(
                            resource_error("worker frame exceeds message limit"),
                            &sender,
                            &lifecycle,
                        );
                        return;
                    }
                    if send_event(&sender, ReaderEvent::Frame(frame), &lifecycle).is_err() {
                        return;
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    publish_failure(protocol_error(error), &sender, &lifecycle);
                    return;
                }
            }
        }
        if consumed != 0 {
            buffer.drain(..consumed);
        }
    }
}

fn stderr_reader(
    mut input: std::process::ChildStderr,
    sender: SyncSender<ReaderEvent>,
    lifecycle: Arc<WorkerLifecycle>,
) {
    let mut scratch = [0_u8; READER_CHUNK_BYTES];
    loop {
        let read = match input.read(&mut scratch) {
            Ok(read) => read,
            Err(error) => {
                publish_failure(io_error("read worker stderr", error), &sender, &lifecycle);
                return;
            }
        };
        if read == 0 {
            return;
        }
        lifecycle.stderr.append(&scratch[..read]);
        if lifecycle.stderr.exceeded() {
            publish_failure(
                resource_error("worker stderr exceeds configured limit"),
                &sender,
                &lifecycle,
            );
            return;
        }
    }
}

fn publish_failure(
    error: BridgeError,
    sender: &SyncSender<ReaderEvent>,
    lifecycle: &WorkerLifecycle,
) {
    lifecycle.report_failure(error, sender);
}

fn send_event(
    sender: &SyncSender<ReaderEvent>,
    event: ReaderEvent,
    lifecycle: &WorkerLifecycle,
) -> Result<(), ()> {
    match sender.try_send(event) {
        Ok(()) => Ok(()),
        Err(TrySendError::Disconnected(_)) => Err(()),
        Err(TrySendError::Full(_)) => {
            lifecycle.report_failure(resource_error("worker event queue is full"), sender);
            Err(())
        }
    }
}

fn build_command(config: &WorkerConfig, root: &Path) -> Result<Command, BridgeError> {
    let mut command = Command::new(&config.executable);
    #[cfg(unix)]
    if config.process_group_policy == ProcessGroupPolicy::Required {
        command.process_group(0);
    }
    command.args(&config.args);
    command.current_dir(root);
    command.env_clear();
    for (key, value) in &config.environment {
        command.env(key, value);
    }
    if config.classpath.is_empty() {
        command.env_remove("CLASSPATH");
    } else {
        let classpath = std::env::join_paths(&config.classpath)
            .map_err(|error| config_error(format!("build classpath: {error}")))?;
        command.env("CLASSPATH", classpath);
    }
    command.stdin(Stdio::piped());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    Ok(command)
}

fn take_stdin(control: &mut Arc<ProcessControl>) -> Result<ChildStdin, BridgeError> {
    Arc::get_mut(control)
        .and_then(|control| control.take_stdin())
        .ok_or_else(|| pipe_unavailable(control, "worker stdin pipe was unavailable"))
}

fn take_stdout(
    control: &mut Arc<ProcessControl>,
) -> Result<std::process::ChildStdout, BridgeError> {
    Arc::get_mut(control)
        .and_then(|control| control.take_stdout())
        .ok_or_else(|| pipe_unavailable(control, "worker stdout pipe was unavailable"))
}

fn take_stderr(
    control: &mut Arc<ProcessControl>,
) -> Result<std::process::ChildStderr, BridgeError> {
    Arc::get_mut(control)
        .and_then(|control| control.take_stderr())
        .ok_or_else(|| pipe_unavailable(control, "worker stderr pipe was unavailable"))
}

fn pipe_unavailable(control: &Arc<ProcessControl>, message: &'static str) -> BridgeError {
    let error = BridgeError::new(BridgeErrorCode::WorkerUnavailable, true, message);
    match control.terminate() {
        Ok(()) => error,
        Err(cleanup) => error.with_cleanup_io_error(&cleanup),
    }
}

fn allocate_request_id(
    next: &AtomicU64,
    outstanding: &Mutex<HashSet<RequestId>>,
) -> Result<RequestId, BridgeError> {
    let mut outstanding = lock_unpoisoned(outstanding);
    for _ in 0..MAX_REQUEST_ID_PROBES {
        let id = next.fetch_add(1, Ordering::Relaxed);
        if id != HANDSHAKE_REQUEST_ID && outstanding.insert(id) {
            return Ok(id);
        }
    }
    Err(resource_error(
        "worker request ID space is exhausted while requests remain outstanding",
    ))
}

fn wire_deadline(timeout: Duration) -> Option<jmeter_rs_bridge_protocol::Deadline> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    let now = now.as_millis().min(u64::MAX as u128) as u64;
    let timeout = timeout.as_millis().min(u64::MAX as u128) as u64;
    let timestamp = now.saturating_add(timeout.max(1)).max(1);
    Some(jmeter_rs_bridge_protocol::Deadline::at_unix_millis(
        timestamp,
    ))
}

fn map_remote_error(
    error: RemoteError,
    request_id: RequestId,
    stderr: StderrReport,
) -> BridgeError {
    let code = match error.code {
        RemoteErrorCode::UnsupportedVersion => BridgeErrorCode::ProtocolViolation,
        RemoteErrorCode::ProfileMismatch => BridgeErrorCode::ProfileMismatch,
        RemoteErrorCode::CapabilityUnavailable => BridgeErrorCode::CapabilityUnavailable,
        RemoteErrorCode::WorkerUnavailable => BridgeErrorCode::WorkerUnavailable,
        RemoteErrorCode::WorkerCrashed => BridgeErrorCode::WorkerCrashed,
        RemoteErrorCode::WorkerLimitExceeded => BridgeErrorCode::ResourceLimit,
        RemoteErrorCode::DeadlineExceeded => BridgeErrorCode::DeadlineExceeded,
        RemoteErrorCode::Cancelled => BridgeErrorCode::Cancelled,
        RemoteErrorCode::ProtocolViolation
        | RemoteErrorCode::UnsupportedMessageKind
        | RemoteErrorCode::InvalidRequest
        | RemoteErrorCode::InvalidPayload => BridgeErrorCode::ProtocolViolation,
        RemoteErrorCode::Internal | RemoteErrorCode::Unknown(_) => BridgeErrorCode::RemoteError,
    };
    BridgeError::new(code, error.retryable, error.message.clone())
        .with_request_id(request_id)
        .with_stderr(stderr)
        .with_remote_error(error)
}

fn redaction_patterns(config: &WorkerConfig) -> Vec<Vec<u8>> {
    let mut values = config
        .redacted_values
        .iter()
        .filter(|value| !value.is_empty())
        .map(|value| value.as_bytes().to_vec())
        .collect::<Vec<_>>();
    for value in config.environment.values() {
        let value = value.to_string_lossy();
        if !value.is_empty() && !values.iter().any(|item| item == value.as_bytes()) {
            values.push(value.as_bytes().to_vec());
        }
    }
    values
}

fn config_error(message: impl Into<String>) -> BridgeError {
    BridgeError::new(BridgeErrorCode::Configuration, false, message)
}

fn io_error(operation: &str, error: io::Error) -> BridgeError {
    let mut result = BridgeError::new(
        BridgeErrorCode::Io,
        true,
        format!("{operation}: {}", cleanup_error_detail(&error)),
    );
    result.os_error = cleanup_raw_os_error(&error);
    result
}

fn resource_error(message: impl Into<String>) -> BridgeError {
    BridgeError::new(BridgeErrorCode::ResourceLimit, false, message)
}

fn protocol_error(error: DecodeError) -> BridgeError {
    BridgeError::new(
        BridgeErrorCode::ProtocolViolation,
        false,
        format!("decode worker frame: {error}"),
    )
}

fn validate_file(path: &Path, label: &str) -> Result<(), BridgeError> {
    if !path.is_absolute() {
        return Err(config_error(format!("{label} must be absolute")));
    }
    if !path.is_file() {
        return Err(config_error(format!("{label} is not an existing file")));
    }
    Ok(())
}

fn validate_directory(path: &Path, label: &str) -> Result<(), BridgeError> {
    if !path.is_absolute() {
        return Err(config_error(format!("{label} must be absolute")));
    }
    if !path.is_dir() {
        return Err(config_error(format!(
            "{label} is not an existing directory"
        )));
    }
    Ok(())
}

fn contains_nul(value: &OsStr) -> bool {
    value.to_string_lossy().contains('\0')
}

fn forbidden_environment_key(key: &OsStr) -> bool {
    matches!(
        key.to_string_lossy().to_ascii_uppercase().as_str(),
        "CLASSPATH"
            | "JAVA_TOOL_OPTIONS"
            | "_JAVA_OPTIONS"
            | "JDK_JAVA_OPTIONS"
            | "HTTP_PROXY"
            | "HTTPS_PROXY"
            | "ALL_PROXY"
            | "NO_PROXY"
    )
}

fn check_process_group_policy(policy: ProcessGroupPolicy) -> Result<(), BridgeError> {
    if policy != ProcessGroupPolicy::Required {
        return Ok(());
    }
    #[cfg(unix)]
    {
        Ok(())
    }
    #[cfg(not(unix))]
    {
        Err(BridgeError::new(
            BridgeErrorCode::ProcessGroupUnsupported,
            false,
            "process-group cleanup is unsupported on this platform",
        ))
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test setup failures have explicit assertion context"
)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn empty_configuration_fails_closed() {
        let error = WorkerConfig::empty()
            .validate()
            .expect_err("empty config must fail");
        assert_eq!(error.code(), BridgeErrorCode::Configuration);
    }

    #[test]
    fn reserved_ambient_environment_is_rejected() {
        let mut config = WorkerConfig::empty();
        config.environment.insert(
            OsString::from("HTTP_PROXY"),
            OsString::from("http://proxy.invalid"),
        );
        let error = config
            .validate()
            .expect_err("proxy variable must be rejected");
        assert_eq!(error.code(), BridgeErrorCode::Configuration);
    }

    #[cfg(unix)]
    #[test]
    fn configuration_preflight_bounds_are_fail_closed() {
        let base = || WorkerConfig::new("/bin/echo", "/tmp", "profile");

        let error = base()
            .with_args((0..=MAX_ARGUMENTS).map(|_| OsString::from("arg")))
            .validate()
            .expect_err("argument count must be bounded");
        assert_eq!(error.code(), BridgeErrorCode::Configuration);

        let error = base()
            .with_classpath((0..=MAX_CLASSPATH_ENTRIES).map(|_| PathBuf::from("/tmp/x")))
            .validate()
            .expect_err("classpath count must be bounded");
        assert_eq!(error.code(), BridgeErrorCode::Configuration);

        let mut environment = BTreeMap::new();
        for index in 0..MAX_ENV_VARS {
            environment.insert(
                OsString::from(format!("TEST_{index}")),
                OsString::from("x".repeat(MAX_ENV_VALUE_BYTES)),
            );
        }
        let error = base()
            .with_environment(environment)
            .validate()
            .expect_err("aggregate environment bytes must be bounded");
        assert_eq!(error.code(), BridgeErrorCode::Configuration);

        let mut config = base();
        config.max_message_bytes = MAX_CONFIGURED_MESSAGE_BYTES + 1;
        let error = config.validate().expect_err("message size must be bounded");
        assert_eq!(error.code(), BridgeErrorCode::Configuration);

        let mut config = base();
        config.max_stdout_bytes = MAX_CONFIGURED_STREAM_BYTES + 1;
        let error = config.validate().expect_err("stream size must be bounded");
        assert_eq!(error.code(), BridgeErrorCode::Configuration);
    }

    #[test]
    fn stderr_redaction_is_bounded() {
        let collector = StderrCollector::new(64, vec![b"secret".to_vec()]);
        collector.append(b"worker secret diagnostic");
        let report = collector.report();
        assert!(report.redacted());
        assert!(!report.text().contains("secret"));
    }

    #[test]
    fn process_group_id_rejects_reserved_and_overflow_values() {
        assert!(ProcessGroupId::try_from(-1_i64).is_err());
        assert!(ProcessGroupId::try_from(0_i64).is_err());
        assert!(ProcessGroupId::try_from(1_i64).is_err());
        assert!(ProcessGroupId::try_from(i64::MAX).is_err());
        assert!(ProcessGroupId::try_from(u32::MAX).is_err());
        assert!(ProcessGroupId::try_from(i64::from(i32::MAX)).is_ok());
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
        let control = ProcessControl::new(
            child,
            ProcessGroupPolicy::ChildOnly,
            DEFAULT_CANCELLATION_TIMEOUT,
        );
        control.terminate().expect("exited child cleanup");
        assert!(lock_unpoisoned(&control.child).is_none());
    }

    #[cfg(unix)]
    struct NoopSignaler;

    #[cfg(unix)]
    impl ProcessGroupSignaler for NoopSignaler {
        fn signal(&self, _process_group: ProcessGroupId) -> io::Result<()> {
            Ok(())
        }
    }

    #[cfg(unix)]
    struct ErrorSignaler {
        started: mpsc::Sender<()>,
        release: Arc<std::sync::Barrier>,
        error: i32,
    }

    #[cfg(unix)]
    impl ProcessGroupSignaler for ErrorSignaler {
        fn signal(&self, _process_group: ProcessGroupId) -> io::Result<()> {
            let _ = self.started.send(());
            self.release.wait();
            Err(io::Error::from_raw_os_error(self.error))
        }
    }

    #[cfg(unix)]
    struct SwitchingDirectSignaler {
        calls: AtomicUsize,
        kill_after: usize,
    }

    #[cfg(unix)]
    impl DirectChildSignaler for SwitchingDirectSignaler {
        fn signal(&self, child: &mut Child) -> io::Result<()> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if call >= self.kill_after {
                signal_direct_child(child)
            } else {
                Ok(())
            }
        }
    }

    #[cfg(unix)]
    struct FailedReaperSpawner {
        calls: AtomicUsize,
    }

    #[cfg(unix)]
    impl ChildReaperSpawner for FailedReaperSpawner {
        fn spawn(&self, child: Child, _timeout: Duration) -> ReaperSpawnResult {
            self.calls.fetch_add(1, Ordering::SeqCst);
            ReaperSpawnResult::Failed(child)
        }
    }

    #[cfg(unix)]
    fn live_test_child() -> Child {
        Command::new("/bin/sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn bounded cleanup child")
    }

    #[cfg(unix)]
    #[test]
    fn successful_group_signal_still_falls_back_after_bounded_poll() {
        let control = ProcessControl::with_signaler(
            live_test_child(),
            ProcessGroupPolicy::Required,
            Duration::from_millis(20),
            Arc::new(NoopSignaler),
        );
        let started = Instant::now();
        control
            .terminate()
            .expect("direct fallback must reap child");
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(lock_unpoisoned(&control.child).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn group_signal_failure_is_observable_after_direct_fallback() {
        let (started, _received) = mpsc::channel();
        let control = ProcessControl::with_signaler(
            live_test_child(),
            ProcessGroupPolicy::Required,
            Duration::from_millis(20),
            Arc::new(ErrorSignaler {
                started,
                release: Arc::new(std::sync::Barrier::new(1)),
                error: nix::errno::Errno::ESRCH as i32,
            }),
        );
        let error = control
            .terminate()
            .expect_err("group failure remains observable");
        assert_eq!(error.raw_os_error(), Some(nix::errno::Errno::ESRCH as i32));
        let typed = cleanup_bridge_error(&StderrCollector::new(64, Vec::new()), &error);
        assert_eq!(typed.os_error(), Some(nix::errno::Errno::ESRCH as i32));
        assert!(typed.message().contains("os error"));
        assert!(lock_unpoisoned(&control.child).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn required_invalid_group_id_is_typed_and_direct_fallback_reaps() {
        let control = ProcessControl::with_signals(
            live_test_child(),
            ProcessGroupPolicy::Required,
            Duration::from_millis(20),
            1,
            Arc::new(NoopSignaler),
            Arc::new(OperatingSystemDirectChildSignaler),
        );
        let error = control
            .terminate()
            .expect_err("invalid required group id must remain observable");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("required process-group policy"));
        let typed = cleanup_bridge_error(&StderrCollector::new(64, Vec::new()), &error);
        assert_eq!(typed.code(), BridgeErrorCode::ProcessGroupUnavailable);
        assert!(lock_unpoisoned(&control.child).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn retryable_timeout_is_not_cached_while_child_remains_live() {
        let direct = Arc::new(SwitchingDirectSignaler {
            calls: AtomicUsize::new(0),
            kill_after: 3,
        });
        let control = ProcessControl::with_signals(
            live_test_child(),
            ProcessGroupPolicy::Required,
            Duration::from_millis(5),
            2,
            Arc::new(NoopSignaler),
            Arc::clone(&direct) as Arc<dyn DirectChildSignaler>,
        );
        let first = control
            .terminate()
            .expect_err("first bounded timeout must be retryable");
        assert_eq!(first.kind(), io::ErrorKind::TimedOut);
        assert!(lock_unpoisoned(&control.child).is_some());
        let second = control
            .terminate()
            .expect_err("retryable cleanup must run again");
        assert_eq!(second.kind(), io::ErrorKind::TimedOut);
        assert!(lock_unpoisoned(&control.child).is_some());
        control
            .terminate()
            .expect("third attempt kills exact child");
        assert_eq!(direct.calls.load(Ordering::SeqCst), 3);
        assert!(lock_unpoisoned(&control.child).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn failed_reaper_spawn_retains_exact_child_for_bounded_fallback() {
        let direct = Arc::new(SwitchingDirectSignaler {
            calls: AtomicUsize::new(0),
            kill_after: 3,
        });
        let reaper = Arc::new(FailedReaperSpawner {
            calls: AtomicUsize::new(0),
        });
        let control = ProcessControl::with_reaper_spawner(
            live_test_child(),
            ProcessGroupPolicy::Required,
            Duration::from_millis(5),
            2,
            Arc::new(NoopSignaler),
            Arc::clone(&direct) as Arc<dyn DirectChildSignaler>,
            Arc::clone(&reaper) as Arc<dyn ChildReaperSpawner>,
        );
        control
            .terminate()
            .expect_err("seed a retryable cleanup before drop");
        drop(control);
        assert_eq!(reaper.calls.load(Ordering::SeqCst), 1);
        assert_eq!(direct.calls.load(Ordering::SeqCst), 3);
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_cleanup_receives_first_failure_result() {
        let (started_sender, started_receiver) = mpsc::channel();
        let release = Arc::new(std::sync::Barrier::new(2));
        let control = Arc::new(ProcessControl::with_signaler(
            live_test_child(),
            ProcessGroupPolicy::Required,
            Duration::from_millis(30),
            Arc::new(ErrorSignaler {
                started: started_sender,
                release: Arc::clone(&release),
                error: nix::errno::Errno::EPERM as i32,
            }),
        ));
        let first_control = Arc::clone(&control);
        let first = thread::spawn(move || first_control.terminate());
        started_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("first cleanup entered signal seam");
        let second_control = Arc::clone(&control);
        let second = thread::spawn(move || second_control.terminate());
        // The signal seam is the only gate in the first cleanup. Release it
        // after the second caller exists so the second caller must observe the
        // in-flight generation and cannot return a false success.
        release.wait();
        let first_result = first.join().expect("first cleanup thread");
        let second_result = second.join().expect("second cleanup thread");
        assert_eq!(
            second_result.as_ref().err().map(io::Error::kind),
            first_result.as_ref().err().map(io::Error::kind),
        );
        assert!(first_result.is_err());
    }

    #[test]
    fn request_id_exhaustion_is_bounded_and_typed() {
        let next = AtomicU64::new(1);
        let outstanding = Mutex::new((1..=MAX_REQUEST_ID_PROBES as u64).collect());
        let error = allocate_request_id(&next, &outstanding)
            .expect_err("occupied request IDs must not be reused");
        assert_eq!(error.code(), BridgeErrorCode::ResourceLimit);
    }
}
