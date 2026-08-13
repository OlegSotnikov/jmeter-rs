// SPDX-License-Identifier: Apache-2.0
//! Typed boundary for the optional JVM compatibility pack.
//!
//! The standalone product deliberately does not launch a JVM.  This crate
//! retains the bounded configuration, cancellation, and bridge error
//! vocabulary needed by the optional pack, but its worker entry point remains
//! fail-closed until the shared process-supervision launch capability is
//! exposed to callers.  In particular, this crate owns no process handle,
//! numeric process identity, process-group token, signal operation, or
//! cleanup registry.
//!
//! The protocol crate remains data-only.  A future worker adapter will attach
//! framed I/O only after it receives an activated capability from
//! `jmeter-rs-process-supervision`; it must not reintroduce a local process
//! owner here.

use jmeter_rs_bridge_protocol::{
    HEADER_LEN, MAX_CAPABILITIES, MAX_CAPABILITY_LEN, MAX_PROFILE_LEN, RemoteError, RequestId,
};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use jmeter_rs_process_supervision as process_supervision;

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

/// Legacy policy selector retained for source compatibility with callers
/// while the optional worker path is unavailable.
///
/// Neither variant authorizes local cleanup.  JVM workers will require the
/// shared supervisor's process-tree capability when the adapter is enabled;
/// `ChildOnly` is rejected during validation for that reason.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ProcessGroupPolicy {
    /// Require the shared process-tree capability.
    #[default]
    Required,
    /// Legacy direct-child policy, which is not valid for JVM workers.
    ChildOnly,
}

/// Explicit bounded configuration for a worker process.
#[derive(Clone, Debug)]
pub struct WorkerConfig {
    /// Absolute executable path accepted by the application allowlist.
    pub executable: PathBuf,
    /// Literal executable arguments.
    pub args: Vec<OsString>,
    /// Absolute classpath entries.
    pub classpath: Vec<PathBuf>,
    /// Required compatibility profile.
    pub profile: String,
    /// Capabilities required during handshake.
    pub capabilities: Vec<String>,
    /// Environment allowlist. No ambient values are accepted.
    pub environment: BTreeMap<OsString, OsString>,
    /// Absolute worker working directory.
    pub working_root: PathBuf,
    /// Process setup deadline.
    pub startup_timeout: Duration,
    /// Handshake response deadline.
    pub handshake_timeout: Duration,
    /// Default operation response deadline.
    pub call_timeout: Duration,
    /// Grace period for cancellation.
    pub cancellation_timeout: Duration,
    /// Aggregate bytes written to the worker stream.
    pub max_stdin_bytes: usize,
    /// Aggregate bytes read from the worker stream.
    pub max_stdout_bytes: usize,
    /// Retained worker diagnostic bytes.
    pub max_stderr_bytes: usize,
    /// Maximum encoded size of one frame.
    pub max_message_bytes: usize,
    /// Shared-supervisor containment requirement.
    pub process_group_policy: ProcessGroupPolicy,
    /// Additional UTF-8 values redacted from diagnostics.
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

    /// Selects the shared-supervisor containment policy.
    pub fn with_process_group_policy(mut self, policy: ProcessGroupPolicy) -> Self {
        self.process_group_policy = policy;
        self
    }

    /// Adds a value to diagnostic redaction.
    pub fn with_redacted_value(mut self, value: impl Into<String>) -> Self {
        self.redacted_values.push(value.into());
        self
    }

    /// Validates explicit paths, identifiers, limits, and containment policy.
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
        validate_supervisor_policy(self.process_group_policy)
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
    /// Shared process-tree containment is unsupported on this platform.
    ProcessGroupUnsupported = 2,
    /// Shared process-tree capability is unavailable.
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
    /// Worker transport became unavailable.
    WorkerUnavailable = 12,
    /// Worker exited before completing an operation.
    WorkerCrashed = 13,
    /// Stream or frame resource limit was exceeded.
    ResourceLimit = 14,
    /// Structured error returned by a worker.
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

/// Bounded, redacted worker diagnostic report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StderrReport {
    text: String,
    bytes_seen: usize,
    truncated: bool,
    redacted: bool,
}

impl StderrReport {
    fn empty() -> Self {
        Self {
            text: String::new(),
            bytes_seen: 0,
            truncated: false,
            redacted: false,
        }
    }

    /// Returns redacted diagnostic text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Returns total observed bytes.
    pub const fn bytes_seen(&self) -> usize {
        self.bytes_seen
    }

    /// Returns whether the retention limit was exceeded.
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

    /// Returns the raw operating-system error, when supplied by an edge.
    pub const fn os_error(&self) -> Option<i32> {
        self.os_error
    }

    /// Returns the correlated request ID.
    pub const fn request_id(&self) -> Option<RequestId> {
        self.request_id
    }

    /// Returns redacted worker diagnostics.
    pub fn stderr(&self) -> Option<&StderrReport> {
        self.stderr.as_deref()
    }

    /// Returns a worker-provided structured error.
    pub fn remote_error(&self) -> Option<&RemoteError> {
        self.remote_error.as_deref()
    }
}

impl fmt::Display for BridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)?;
        if let Some(id) = self.request_id {
            write!(formatter, " (request {id})")?;
        }
        if let Some(stderr) = &self.stderr
            && !stderr.text.is_empty()
        {
            write!(formatter, "; stderr: {}", stderr.text)?;
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

    /// Requests cancellation monotonically.
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

/// Fail-closed optional worker handle.
pub struct Worker {
    config: WorkerConfig,
    info: WorkerInfo,
    closed: Arc<AtomicBool>,
}

impl fmt::Debug for Worker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Worker")
            .field("profile", &self.info.profile)
            .field("protocol_version", &self.info.protocol_version)
            .field("capabilities", &self.info.capabilities)
            .field("closed", &self.is_closed())
            .finish()
    }
}

/// Stateless supervisor facade.
#[derive(Clone, Copy, Debug, Default)]
pub struct Supervisor;

impl Supervisor {
    /// Creates a supervisor facade.
    pub const fn new() -> Self {
        Self
    }

    /// Starts and negotiates one worker.
    pub fn start(&self, config: WorkerConfig) -> Result<Worker, BridgeError> {
        Worker::start(config)
    }

    /// Alias for [`Supervisor::start`].
    pub fn spawn(&self, config: WorkerConfig) -> Result<Worker, BridgeError> {
        self.start(config)
    }
}

impl Worker {
    /// Rejects worker launch until the shared supervisor capability is wired.
    pub fn start(config: WorkerConfig) -> Result<Self, BridgeError> {
        config.validate()?;
        Err(BridgeError::new(
            BridgeErrorCode::CapabilityUnavailable,
            false,
            "optional JVM worker is unavailable until shared process supervision is activated",
        ))
    }

    /// Alias for [`Worker::start`].
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

    /// Returns current redacted diagnostics.
    pub fn stderr(&self) -> StderrReport {
        StderrReport::empty()
    }

    /// Returns whether the transport is closed.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
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
        if payload.as_ref().len() > self.config.max_message_bytes.saturating_sub(HEADER_LEN) {
            return Err(BridgeError::new(
                BridgeErrorCode::ResourceLimit,
                false,
                "worker request payload exceeds configured message bound",
            ));
        }
        Err(self.unavailable_error())
    }

    /// Sends a cancellation notification for a request.
    pub fn cancel(&self, _request_id: RequestId) -> Result<(), BridgeError> {
        Err(self.unavailable_error())
    }

    /// Marks this inactive compatibility handle closed.
    pub fn shutdown(&self) -> Result<(), BridgeError> {
        self.closed.store(true, Ordering::Release);
        Ok(())
    }

    fn unavailable_error(&self) -> BridgeError {
        BridgeError::new(
            BridgeErrorCode::WorkerUnavailable,
            true,
            "optional JVM worker is unavailable until shared process supervision is activated",
        )
    }
}

fn validate_supervisor_policy(policy: ProcessGroupPolicy) -> Result<(), BridgeError> {
    if policy == ProcessGroupPolicy::ChildOnly {
        return Err(BridgeError::new(
            BridgeErrorCode::ProcessGroupUnavailable,
            false,
            "JVM workers require shared process-tree containment",
        ));
    }
    if !process_supervision::process_tree_supported() {
        return Err(BridgeError::new(
            BridgeErrorCode::ProcessGroupUnsupported,
            false,
            "shared process-tree containment is unavailable on this platform",
        ));
    }
    Ok(())
}

/// Validates a supervisor-owned group target without exposing or signalling it.
///
/// The shared crate owns the numeric-domain rule: zero and one are rejected,
/// and accepted values must fit the platform's signed target representation.
#[cfg(all(test, unix))]
fn validate_supervisor_group_target(raw: u32) -> Result<(), BridgeError> {
    process_supervision::validate_process_group_id(raw)
        .map(|_| ())
        .map_err(|error| {
            BridgeError::new(
                BridgeErrorCode::ProcessGroupUnavailable,
                false,
                format!(
                    "shared supervisor rejected group target: {}",
                    error.message()
                ),
            )
        })
}

fn config_error(message: impl Into<String>) -> BridgeError {
    BridgeError::new(BridgeErrorCode::Configuration, false, message)
}

fn validate_file(path: &Path, label: &str) -> Result<(), BridgeError> {
    if !path.is_absolute() {
        return Err(config_error(format!("{label} must be absolute")));
    }
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => Err(config_error(format!("{label} is not a regular file"))),
        Err(_) => Err(config_error(format!("{label} is unavailable"))),
    }
}

fn validate_directory(path: &Path, label: &str) -> Result<(), BridgeError> {
    if !path.is_absolute() {
        return Err(config_error(format!("{label} must be absolute")));
    }
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(config_error(format!("{label} is not a directory"))),
        Err(_) => Err(config_error(format!("{label} is unavailable"))),
    }
}

fn contains_nul(value: &OsStr) -> bool {
    value.to_string_lossy().contains('\0')
}

fn forbidden_environment_key(key: &OsStr) -> bool {
    matches!(
        key.to_string_lossy().as_ref(),
        "CLASSPATH"
            | "JAVA_HOME"
            | "JRE_HOME"
            | "JVM_ARGS"
            | "JAVA_TOOL_OPTIONS"
            | "_JAVA_OPTIONS"
            | "MAVEN_OPTS"
            | "GRADLE_OPTS"
            | "HTTP_PROXY"
            | "HTTPS_PROXY"
            | "ALL_PROXY"
            | "NO_PROXY"
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn empty_configuration_fails_closed() {
        let error = WorkerConfig::empty()
            .validate()
            .expect_err("empty configuration must be rejected");
        assert_eq!(error.code(), BridgeErrorCode::Configuration);
    }

    #[test]
    fn duplicate_capabilities_are_rejected_without_launching() {
        let config = WorkerConfig::new("relative-worker", "/tmp", "profile")
            .with_capabilities(["SCRIPT-001", "SCRIPT-001"]);
        let error = config
            .validate()
            .expect_err("invalid path is checked before capability duplication");
        assert_eq!(error.code(), BridgeErrorCode::Configuration);
    }

    #[test]
    fn cancellation_is_monotonic() {
        let token = CancellationToken::new();
        assert!(!token.is_cancelled());
        token.cancel();
        token.cancel();
        assert!(token.is_cancelled());
    }

    #[cfg(unix)]
    #[test]
    fn group_target_validation_rejects_reserved_values() {
        assert!(validate_supervisor_group_target(0).is_err());
        assert!(validate_supervisor_group_target(1).is_err());
        assert!(validate_supervisor_group_target(2).is_ok());
    }

    #[test]
    fn child_only_policy_fails_before_optional_worker_admission() {
        let config = WorkerConfig::new("relative-worker", "/tmp", "profile")
            .with_process_group_policy(ProcessGroupPolicy::ChildOnly);
        let error = validate_supervisor_policy(config.process_group_policy)
            .expect_err("JVM workers must not select direct-child cleanup");
        assert_eq!(error.code(), BridgeErrorCode::ProcessGroupUnavailable);
    }

    #[test]
    fn empty_diagnostics_are_bounded() {
        let report = StderrReport::empty();
        assert!(report.text().is_empty());
        assert_eq!(report.bytes_seen(), 0);
        assert!(!report.truncated());
        assert!(!report.redacted());
    }
}
