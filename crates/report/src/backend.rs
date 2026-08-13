// SPDX-License-Identifier: Apache-2.0
//! Pure REPORT-003 backend-listener contracts.
//!
//! This module deliberately owns no sockets, executor, clock, JVM, or
//! filesystem access.  It contains the bounded event/metric state machine and
//! the two wire encoders used by the Graphite plaintext and InfluxDB HTTP
//! adapters.  An application supplies [`BackendSender`], [`BackendClock`],
//! and [`BackendScheduler`] implementations at the effectful edge.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;

use jmeter_rs_results::{SampleEvent, SampleResult};

use crate::metrics::{CountMode, represented_counts};

/// JMeter's documented default BackendListener queue size.
pub const DEFAULT_BACKEND_QUEUE_CAPACITY: usize = 5_000;
/// Default maximum bytes retained by a backend queue.
pub const DEFAULT_BACKEND_QUEUE_BYTES: usize = 64 * 1024 * 1024;
/// Default number of events admitted to one backend send.
pub const DEFAULT_BACKEND_BATCH_CAPACITY: usize = 1_024;
/// Default maximum encoded payload size.
pub const DEFAULT_BACKEND_BATCH_BYTES: usize = 4 * 1024 * 1024;
/// Default Graphite send interval in milliseconds.
pub const DEFAULT_GRAPHITE_SEND_INTERVAL_MILLIS: u64 = 1_000;
/// Default InfluxDB send interval in milliseconds.
pub const DEFAULT_INFLUX_SEND_INTERVAL_MILLIS: u64 = 5_000;
/// Default bounded percentile window used by JMeter backend metrics.
pub const DEFAULT_BACKEND_WINDOW_SAMPLES: usize = 100;
/// Maximum number of distinct transaction contexts retained in one interval.
pub const DEFAULT_BACKEND_MAX_CONTEXTS: usize = 4_096;
/// Maximum number of annotation events retained in one interval.
pub const DEFAULT_BACKEND_MAX_ANNOTATIONS: usize = 4_096;
/// Maximum annotation text size.
pub const MAX_BACKEND_ANNOTATION_BYTES: usize = 16 * 1024;
/// Default shutdown bound in milliseconds.
pub const DEFAULT_BACKEND_SHUTDOWN_TIMEOUT_MILLIS: u64 = 30_000;
/// Default retry count.  A sender may apply a stricter transport policy.
pub const DEFAULT_BACKEND_MAX_RETRIES: usize = 0;
/// Maximum retries an effectful sender may apply for one accepted batch.
pub const MAX_BACKEND_RETRIES: usize = 16;
/// Maximum backend sampler-filter expression length.
pub const MAX_BACKEND_FILTER_BYTES: usize = 4 * 1024;
/// Maximum backend Java descriptor arguments.
pub const MAX_BACKEND_ARGUMENTS: usize = 256;
/// Maximum backend Java descriptor argument bytes.
pub const MAX_BACKEND_ARGUMENT_BYTES: usize = 64 * 1024;
/// Maximum number of regex matcher states explored for one label.
const MAX_REGEX_STATES: usize = 8_192;

/// Stable configuration fields used in backend errors.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BackendConfigField {
    /// Queue item capacity.
    QueueCapacity,
    /// Queue byte capacity.
    QueueBytes,
    /// Batch item capacity.
    BatchCapacity,
    /// Batch byte capacity.
    BatchBytes,
    /// Send interval.
    SendInterval,
    /// Shutdown timeout.
    ShutdownTimeout,
    /// Retry count.
    MaxRetries,
    /// Percentile list.
    Percentiles,
    /// Window configuration.
    Window,
    /// Graphite host.
    Host,
    /// Graphite port.
    Port,
    /// Graphite metric prefix.
    RootMetricsPrefix,
    /// InfluxDB URL.
    Url,
    /// InfluxDB measurement.
    Measurement,
    /// InfluxDB token.
    Token,
    /// Application tag.
    Application,
    /// Sampler filter.
    SamplerFilter,
    /// External sender class.
    Sender,
    /// Java listener class.
    ClassName,
    /// Java profile identifier.
    Profile,
    /// Java listener argument.
    Argument,
}

impl fmt::Display for BackendConfigField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::QueueCapacity => "queue_capacity",
            Self::QueueBytes => "queue_bytes",
            Self::BatchCapacity => "batch_capacity",
            Self::BatchBytes => "batch_bytes",
            Self::SendInterval => "send_interval",
            Self::ShutdownTimeout => "shutdown_timeout",
            Self::MaxRetries => "max_retries",
            Self::Percentiles => "percentiles",
            Self::Window => "window",
            Self::Host => "host",
            Self::Port => "port",
            Self::RootMetricsPrefix => "root_metrics_prefix",
            Self::Url => "url",
            Self::Measurement => "measurement",
            Self::Token => "token",
            Self::Application => "application",
            Self::SamplerFilter => "sampler_filter",
            Self::Sender => "sender",
            Self::ClassName => "class_name",
            Self::Profile => "profile",
            Self::Argument => "argument",
        };
        formatter.write_str(value)
    }
}

/// Bounded resources owned by a backend listener.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BackendResource {
    /// Number of queued events.
    QueueItems,
    /// Bytes retained by queued events.
    QueueBytes,
    /// Events in one send batch.
    BatchItems,
    /// Bytes in one encoded batch.
    BatchBytes,
    /// Distinct metric contexts.
    MetricContexts,
    /// Retained percentile observations.
    PercentileSamples,
    /// Influx tags.
    Tags,
    /// Influx fields.
    Fields,
    /// One Graphite line.
    LineBytes,
    /// One Influx body.
    BodyBytes,
    /// One event projection.
    EventBytes,
    /// Java descriptor arguments.
    Arguments,
    /// Java descriptor argument bytes.
    ArgumentBytes,
    /// Error descriptors.
    ErrorKeys,
    /// Regex matcher states.
    RegexStates,
}

impl fmt::Display for BackendResource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::QueueItems => "queue_items",
            Self::QueueBytes => "queue_bytes",
            Self::BatchItems => "batch_items",
            Self::BatchBytes => "batch_bytes",
            Self::MetricContexts => "metric_contexts",
            Self::PercentileSamples => "percentile_samples",
            Self::Tags => "tags",
            Self::Fields => "fields",
            Self::LineBytes => "line_bytes",
            Self::BodyBytes => "body_bytes",
            Self::EventBytes => "event_bytes",
            Self::Arguments => "arguments",
            Self::ArgumentBytes => "argument_bytes",
            Self::ErrorKeys => "error_keys",
            Self::RegexStates => "regex_states",
        };
        formatter.write_str(value)
    }
}

/// Operations named in stable timeout/shutdown errors.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BackendOperation {
    /// Sender setup.
    Setup,
    /// Queue admission.
    Enqueue,
    /// Periodic or final flush.
    Flush,
    /// External send.
    Send,
    /// Sender teardown.
    Teardown,
    /// Scheduler registration.
    Schedule,
    /// Finalization drain.
    Shutdown,
}

impl fmt::Display for BackendOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Setup => "setup",
            Self::Enqueue => "enqueue",
            Self::Flush => "flush",
            Self::Send => "send",
            Self::Teardown => "teardown",
            Self::Schedule => "schedule",
            Self::Shutdown => "shutdown",
        })
    }
}

/// Transport failure class supplied by an effectful sender adapter.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BackendTransportErrorKind {
    /// Name or route resolution failed.
    Resolve,
    /// Connection establishment failed.
    Connect,
    /// A write failed before the sender could establish delivery.
    Write,
    /// A response/read failed.
    Read,
    /// The remote protocol rejected the payload.
    Protocol,
    /// Cancellation interrupted the operation.
    Cancelled,
}

impl fmt::Display for BackendTransportErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Resolve => "resolve",
            Self::Connect => "connect",
            Self::Write => "write",
            Self::Read => "read",
            Self::Protocol => "protocol",
            Self::Cancelled => "cancelled",
        })
    }
}

/// Typed, redacted failures from the backend core and its adapters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BackendError {
    /// A configuration value is not representable.
    InvalidConfig {
        /// Invalid field.
        field: BackendConfigField,
    },
    /// A bounded resource was exceeded.
    LimitExceeded {
        /// Resource kind.
        resource: BackendResource,
        /// Attempted amount.
        actual: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// A requested protocol or sender is intentionally not implemented.
    Unsupported {
        /// Stable capability identifier.
        capability: String,
    },
    /// An external capability is unavailable.
    ExternalUnavailable {
        /// Stable capability identifier.
        capability: String,
    },
    /// The queue has no admission capacity.
    QueueFull {
        /// Configured item capacity.
        capacity: usize,
    },
    /// The queue was closed before admission.
    QueueClosed,
    /// Cancellation was requested.
    Cancelled,
    /// A bounded operation reached its deadline.
    Timeout {
        /// Operation that timed out.
        operation: BackendOperation,
    },
    /// An injected sender failed.
    Transport {
        /// Failure class.
        kind: BackendTransportErrorKind,
        /// Whether a retry may be safe before delivery is known.
        retryable: bool,
    },
    /// An HTTP sender returned a non-success status.
    HttpStatus {
        /// Status code only; response bodies are never retained here.
        status: u16,
        /// Whether the status may be retried by the edge adapter.
        retryable: bool,
    },
    /// A wire serializer rejected the protocol representation.
    Protocol,
    /// Checked arithmetic overflow.
    Overflow,
    /// Finalization could not account for all accepted events.
    Shutdown {
        /// Finalization stage.
        operation: BackendOperation,
    },
}

impl BackendError {
    /// Returns the stable machine-readable error code.
    pub fn stable_code(&self) -> &'static str {
        match self {
            Self::InvalidConfig { .. } => "report.backend.invalid_config",
            Self::LimitExceeded { .. } => "report.backend.limit_exceeded",
            Self::Unsupported { .. } => "report.backend.unsupported",
            Self::ExternalUnavailable { .. } => "report.backend.external_unavailable",
            Self::QueueFull { .. } => "report.backend.queue_full",
            Self::QueueClosed => "report.backend.closed",
            Self::Cancelled => "report.backend.cancelled",
            Self::Timeout { .. } => "report.backend.timeout",
            Self::Transport { kind, .. } => match kind {
                BackendTransportErrorKind::Resolve => "report.backend.resolve",
                BackendTransportErrorKind::Connect => "report.backend.connect",
                BackendTransportErrorKind::Write => "report.backend.write",
                BackendTransportErrorKind::Read => "report.backend.read",
                BackendTransportErrorKind::Protocol => "report.backend.protocol",
                BackendTransportErrorKind::Cancelled => "report.backend.cancelled",
            },
            Self::HttpStatus { .. } => "report.backend.http_status",
            Self::Protocol => "report.backend.protocol",
            Self::Overflow => "report.backend.overflow",
            Self::Shutdown { .. } => "report.backend.shutdown",
        }
    }

    /// Returns whether an edge sender may retry this error without violating
    /// the core's no-silent-loss rule.
    pub const fn retryable(&self) -> bool {
        match self {
            Self::Transport { retryable, .. } | Self::HttpStatus { retryable, .. } => *retryable,
            _ => false,
        }
    }
}

impl fmt::Display for BackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig { field } => write!(formatter, "{} ({field})", self.stable_code()),
            Self::LimitExceeded {
                resource,
                actual,
                maximum,
            } => write!(
                formatter,
                "{} ({resource}: {actual}>{maximum})",
                self.stable_code()
            ),
            Self::Unsupported { capability } | Self::ExternalUnavailable { capability } => {
                write!(formatter, "{} ({capability})", self.stable_code())
            }
            Self::QueueFull { capacity } => {
                write!(formatter, "{} (capacity {capacity})", self.stable_code())
            }
            Self::QueueClosed | Self::Cancelled | Self::Protocol | Self::Overflow => {
                formatter.write_str(self.stable_code())
            }
            Self::Timeout { operation } | Self::Shutdown { operation } => {
                write!(formatter, "{} ({operation})", self.stable_code())
            }
            Self::Transport { kind, retryable } => {
                write!(
                    formatter,
                    "{} ({kind}, retryable={retryable})",
                    self.stable_code()
                )
            }
            Self::HttpStatus { status, retryable } => {
                write!(
                    formatter,
                    "{} ({status}, retryable={retryable})",
                    self.stable_code()
                )
            }
        }
    }
}

impl std::error::Error for BackendError {}

/// Queue behavior when all configured permits are occupied.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum QueueFullPolicy {
    /// Return a stable queue-full error and retain the event for the caller.
    #[default]
    Fail,
    /// Account the loss explicitly and return a diagnostic outcome.
    DropWithDiagnostic,
}

/// Bounded event and payload limits shared by backend endpoints.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendQueueConfig {
    /// Maximum number of queued events.
    pub capacity: usize,
    /// Maximum estimated event bytes retained.
    pub max_bytes: usize,
    /// Maximum events in one send.
    pub batch_capacity: usize,
    /// Maximum encoded bytes in one send.
    pub batch_bytes: usize,
    /// Full queue behavior.
    pub full_policy: QueueFullPolicy,
}

impl BackendQueueConfig {
    /// Creates validated queue limits.
    pub fn new(
        capacity: usize,
        max_bytes: usize,
        batch_capacity: usize,
        batch_bytes: usize,
    ) -> Result<Self, BackendError> {
        let value = Self {
            capacity,
            max_bytes,
            batch_capacity,
            batch_bytes,
            full_policy: QueueFullPolicy::Fail,
        };
        value.validate()?;
        Ok(value)
    }

    /// Changes the explicit full-queue policy.
    #[must_use]
    pub const fn with_full_policy(mut self, policy: QueueFullPolicy) -> Self {
        self.full_policy = policy;
        self
    }

    /// Validates all queue bounds.
    pub fn validate(&self) -> Result<(), BackendError> {
        if self.capacity == 0 {
            return Err(BackendError::InvalidConfig {
                field: BackendConfigField::QueueCapacity,
            });
        }
        if self.max_bytes == 0 {
            return Err(BackendError::InvalidConfig {
                field: BackendConfigField::QueueBytes,
            });
        }
        if self.batch_capacity == 0 {
            return Err(BackendError::InvalidConfig {
                field: BackendConfigField::BatchCapacity,
            });
        }
        if self.batch_bytes == 0 {
            return Err(BackendError::InvalidConfig {
                field: BackendConfigField::BatchBytes,
            });
        }
        Ok(())
    }
}

impl Default for BackendQueueConfig {
    fn default() -> Self {
        Self {
            capacity: DEFAULT_BACKEND_QUEUE_CAPACITY,
            max_bytes: DEFAULT_BACKEND_QUEUE_BYTES,
            batch_capacity: DEFAULT_BACKEND_BATCH_CAPACITY,
            batch_bytes: DEFAULT_BACKEND_BATCH_BYTES,
            full_policy: QueueFullPolicy::Fail,
        }
    }
}

/// Backend metric window mode.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BackendWindowMode {
    /// Retain the newest fixed number of observations.
    Fixed,
    /// Retain observations from the newest duration, bounded by count.
    Timed,
}

/// Independent bounded state used by JMeter backend percentile metrics.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BackendWindowConfig {
    /// Window mode.
    pub mode: BackendWindowMode,
    /// Maximum retained observations.
    pub max_samples: usize,
    /// Timed-window duration in milliseconds. Ignored by [`BackendWindowMode::Fixed`].
    pub duration_millis: u64,
}

impl BackendWindowConfig {
    /// Creates a fixed-count window.
    pub fn fixed(max_samples: usize) -> Result<Self, BackendError> {
        let value = Self {
            mode: BackendWindowMode::Fixed,
            max_samples,
            duration_millis: 0,
        };
        value.validate()?;
        Ok(value)
    }

    /// Creates a timed window with a count bound.
    pub fn timed(duration_millis: u64, max_samples: usize) -> Result<Self, BackendError> {
        let value = Self {
            mode: BackendWindowMode::Timed,
            max_samples,
            duration_millis,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates the window.
    pub fn validate(&self) -> Result<(), BackendError> {
        if self.max_samples == 0
            || (self.mode == BackendWindowMode::Timed && self.duration_millis == 0)
        {
            return Err(BackendError::InvalidConfig {
                field: BackendConfigField::Window,
            });
        }
        Ok(())
    }
}

impl Default for BackendWindowConfig {
    fn default() -> Self {
        Self {
            mode: BackendWindowMode::Fixed,
            max_samples: DEFAULT_BACKEND_WINDOW_SAMPLES,
            duration_millis: 0,
        }
    }
}

/// A decimal percentile retained as integer basis points for deterministic
/// equality and wire spelling.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BackendPercentile(u16);

impl BackendPercentile {
    /// Creates a percentile from a finite percentage in `0..=100`.
    pub fn from_percent(value: f64) -> Result<Self, BackendError> {
        if !value.is_finite() || !(0.0..=100.0).contains(&value) {
            return Err(BackendError::InvalidConfig {
                field: BackendConfigField::Percentiles,
            });
        }
        let basis = (value * 100.0).round();
        if !(0.0..=10_000.0).contains(&basis) {
            return Err(BackendError::InvalidConfig {
                field: BackendConfigField::Percentiles,
            });
        }
        Ok(Self(basis as u16))
    }

    /// Returns the percentage value.
    pub fn as_percent(self) -> f64 {
        f64::from(self.0) / 100.0
    }

    /// Returns a JMeter-style decimal suffix without trailing zeroes.
    pub fn wire_suffix(self) -> String {
        let whole = self.0 / 100;
        let fraction = self.0 % 100;
        if fraction == 0 {
            return whole.to_string();
        }
        if fraction.is_multiple_of(10) {
            format!("{whole}.{}", fraction / 10)
        } else {
            format!("{whole}.{fraction:02}")
        }
    }

    fn influx_suffix(self) -> String {
        if self.0.is_multiple_of(100) {
            format!("{:.1}", self.as_percent())
        } else {
            self.wire_suffix()
        }
    }
}

impl TryFrom<f64> for BackendPercentile {
    type Error = BackendError;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        Self::from_percent(value)
    }
}

/// Compiled sampler-selection filter.
#[derive(Clone, Debug, Default, PartialEq)]
pub enum SamplerFilter {
    /// Select no detail contexts.
    #[default]
    None,
    /// Select exact labels.
    Exact(Vec<String>),
    /// Select labels using the bounded Java-compatible subset and a full
    /// match.  Unsupported syntax is rejected during construction.
    RegexFull(CompiledPattern),
    /// Select labels using the bounded Java-compatible subset and a search.
    RegexFind(CompiledPattern),
}

impl SamplerFilter {
    /// Creates an exact-label filter, preserving first-seen configuration
    /// order while matching duplicates only once.
    pub fn exact<I, S>(labels: I) -> Result<Self, BackendError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut values = Vec::new();
        for label in labels {
            let label = label.into();
            validate_filter_text(&label)?;
            if !values.iter().any(|item| item == &label) {
                values.push(label);
            }
        }
        Ok(Self::Exact(values))
    }

    /// Compiles a full-match filter for Graphite's sampler list.
    pub fn regex_full(pattern: impl Into<String>) -> Result<Self, BackendError> {
        Ok(Self::RegexFull(CompiledPattern::compile(pattern.into())?))
    }

    /// Compiles a search filter for InfluxDB's sampler regex.
    pub fn regex_find(pattern: impl Into<String>) -> Result<Self, BackendError> {
        Ok(Self::RegexFind(CompiledPattern::compile(pattern.into())?))
    }

    /// Returns whether a label is selected.
    pub fn matches(&self, label: &str) -> Result<bool, BackendError> {
        match self {
            Self::None => Ok(false),
            Self::Exact(labels) => Ok(labels.iter().any(|item| item == label)),
            Self::RegexFull(pattern) => pattern.is_match(label, false),
            Self::RegexFind(pattern) => pattern.is_match(label, true),
        }
    }
}

fn validate_filter_text(value: &str) -> Result<(), BackendError> {
    if value.is_empty() || value.len() > MAX_BACKEND_FILTER_BYTES || value.contains(['\n', '\r']) {
        return Err(BackendError::InvalidConfig {
            field: BackendConfigField::SamplerFilter,
        });
    }
    Ok(())
}

/// Graphite sender kind.  Pickle remains an explicit unsupported capability
/// in this native REPORT-003 core.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum GraphiteSenderKind {
    /// Graphite plaintext protocol.
    #[default]
    Text,
    /// JMeter's Pickle protocol, intentionally not guessed here.
    Pickle,
}

/// Shared backend scheduling and queue policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendRuntimeConfig {
    /// Bounded queue limits.
    pub queue: BackendQueueConfig,
    /// Periodic send interval in milliseconds.
    pub send_interval_millis: u64,
    /// Maximum graceful-finalization duration in milliseconds.
    pub shutdown_timeout_millis: u64,
    /// Sender retry budget; the sender decides whether an individual retry is
    /// safe after classifying delivery state.
    pub max_retries: usize,
    /// Independent backend metric window.
    pub window: BackendWindowConfig,
}

impl BackendRuntimeConfig {
    /// Creates validated runtime limits.
    pub fn new(send_interval_millis: u64) -> Result<Self, BackendError> {
        let value = Self {
            queue: BackendQueueConfig::default(),
            send_interval_millis,
            shutdown_timeout_millis: DEFAULT_BACKEND_SHUTDOWN_TIMEOUT_MILLIS,
            max_retries: DEFAULT_BACKEND_MAX_RETRIES,
            window: BackendWindowConfig::default(),
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates runtime limits.
    pub fn validate(&self) -> Result<(), BackendError> {
        self.queue.validate()?;
        if self.send_interval_millis == 0 {
            return Err(BackendError::InvalidConfig {
                field: BackendConfigField::SendInterval,
            });
        }
        if self.shutdown_timeout_millis == 0 {
            return Err(BackendError::InvalidConfig {
                field: BackendConfigField::ShutdownTimeout,
            });
        }
        if self.max_retries > MAX_BACKEND_RETRIES {
            return Err(BackendError::InvalidConfig {
                field: BackendConfigField::MaxRetries,
            });
        }
        self.window.validate()?;
        Ok(())
    }
}

/// Graphite plaintext endpoint configuration.
#[derive(Clone, Debug, PartialEq)]
pub struct GraphiteConfig {
    /// Shared runtime limits.
    pub runtime: BackendRuntimeConfig,
    /// Sender class/protocol.
    pub sender: GraphiteSenderKind,
    /// Graphite host as configured; no DNS is performed here.
    pub host: String,
    /// Graphite port.
    pub port: u16,
    /// Prefix concatenated directly with the context.
    pub root_metrics_prefix: String,
    /// Percentiles in configured order.
    pub percentiles: Vec<BackendPercentile>,
    /// Detail sampler filter.
    pub sampler_filter: SamplerFilter,
    /// Whether only the all-summary context is sent.
    pub summary_only: bool,
}

impl GraphiteConfig {
    /// Creates the documented plaintext defaults.
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self, BackendError> {
        let runtime = BackendRuntimeConfig::new(DEFAULT_GRAPHITE_SEND_INTERVAL_MILLIS)?;
        let percentiles = default_percentiles()?;
        let value = Self {
            runtime,
            sender: GraphiteSenderKind::Text,
            host: host.into(),
            port,
            root_metrics_prefix: "jmeter.".to_owned(),
            percentiles,
            sampler_filter: SamplerFilter::None,
            summary_only: true,
        };
        value.validate()?;
        Ok(value)
    }

    /// Changes the sender kind.  Pickle will fail validation explicitly.
    #[must_use]
    pub const fn with_sender(mut self, sender: GraphiteSenderKind) -> Self {
        self.sender = sender;
        self
    }

    /// Changes the root metric prefix.
    #[must_use]
    pub fn with_root_metrics_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.root_metrics_prefix = prefix.into();
        self
    }

    /// Changes the detail filter.
    #[must_use]
    pub fn with_sampler_filter(mut self, filter: SamplerFilter) -> Self {
        self.sampler_filter = filter;
        self
    }

    /// Changes summary-only mode.
    #[must_use]
    pub const fn with_summary_only(mut self, value: bool) -> Self {
        self.summary_only = value;
        self
    }

    /// Validates endpoint and serializer configuration.
    pub fn validate(&self) -> Result<(), BackendError> {
        self.runtime.validate()?;
        if self.sender == GraphiteSenderKind::Pickle {
            return Err(BackendError::Unsupported {
                capability: "graphite.pickle".to_owned(),
            });
        }
        if self.host.is_empty() || self.host.contains(['\n', '\r', ' ']) {
            return Err(BackendError::InvalidConfig {
                field: BackendConfigField::Host,
            });
        }
        if self.port == 0 {
            return Err(BackendError::InvalidConfig {
                field: BackendConfigField::Port,
            });
        }
        validate_metric_prefix(&self.root_metrics_prefix)?;
        validate_percentile_list(&self.percentiles)?;
        Ok(())
    }
}

impl Default for GraphiteConfig {
    fn default() -> Self {
        Self::new("127.0.0.1", 2_003).unwrap_or_else(|_| Self {
            runtime: BackendRuntimeConfig {
                queue: BackendQueueConfig::default(),
                send_interval_millis: DEFAULT_GRAPHITE_SEND_INTERVAL_MILLIS,
                shutdown_timeout_millis: DEFAULT_BACKEND_SHUTDOWN_TIMEOUT_MILLIS,
                max_retries: DEFAULT_BACKEND_MAX_RETRIES,
                window: BackendWindowConfig::default(),
            },
            sender: GraphiteSenderKind::Text,
            host: "127.0.0.1".to_owned(),
            port: 2_003,
            root_metrics_prefix: "jmeter.".to_owned(),
            percentiles: Vec::new(),
            sampler_filter: SamplerFilter::None,
            summary_only: true,
        })
    }
}

/// Millisecond timestamp precision supported by this pure Influx serializer.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum InfluxTimestampPrecision {
    /// Unix epoch milliseconds, matching the REPORT-003 fixture.
    #[default]
    Milliseconds,
    /// Other precisions are explicit unsupported capabilities.
    Unsupported,
}

/// Redacted secret wrapper for Influx authentication tokens.
#[derive(Clone, Eq, PartialEq)]
pub struct BackendSecret(String);

impl BackendSecret {
    /// Stores a token without exposing it in debug output.
    pub fn new(value: impl Into<String>) -> Result<Self, BackendError> {
        let value = value.into();
        if value.is_empty() || value.contains(['\n', '\r']) {
            return Err(BackendError::InvalidConfig {
                field: BackendConfigField::Token,
            });
        }
        Ok(Self(value))
    }

    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for BackendSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

/// InfluxDB HTTP endpoint configuration.
#[derive(Clone, PartialEq)]
pub struct InfluxConfig {
    /// Shared runtime limits.
    pub runtime: BackendRuntimeConfig,
    /// URL including its explicit v1/v2 query parameters.
    pub url: String,
    /// Optional v2 token.
    pub token: Option<BackendSecret>,
    /// Application tag.
    pub application: String,
    /// Measurement name.
    pub measurement: String,
    /// Whether only the all-summary context is sent.
    pub summary_only: bool,
    /// Detail sampler filter.
    pub sampler_filter: SamplerFilter,
    /// Percentiles in configured order.
    pub percentiles: Vec<BackendPercentile>,
    /// Annotation title.
    pub test_title: String,
    /// Optional annotation tag value.
    pub event_tags: Option<String>,
    /// Explicit custom `TAG_*` values.
    pub custom_tags: BTreeMap<String, String>,
    /// Timestamp precision.
    pub timestamp_precision: InfluxTimestampPrecision,
}

impl fmt::Debug for InfluxConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InfluxConfig")
            .field("runtime", &self.runtime)
            .field("url", &redact_url(&self.url))
            .field("token", &self.token)
            .field("application", &self.application)
            .field("measurement", &self.measurement)
            .field("summary_only", &self.summary_only)
            .field("sampler_filter", &self.sampler_filter)
            .field("percentiles", &self.percentiles)
            .field("test_title", &self.test_title)
            .field("event_tags", &self.event_tags)
            .field("custom_tags", &self.custom_tags)
            .field("timestamp_precision", &self.timestamp_precision)
            .finish()
    }
}

impl InfluxConfig {
    /// Creates the documented v1 HTTP defaults.
    pub fn new(
        url: impl Into<String>,
        application: impl Into<String>,
    ) -> Result<Self, BackendError> {
        let runtime = BackendRuntimeConfig::new(DEFAULT_INFLUX_SEND_INTERVAL_MILLIS)?;
        let value = Self {
            runtime,
            url: url.into(),
            token: None,
            application: application.into(),
            measurement: "jmeter".to_owned(),
            summary_only: true,
            sampler_filter: SamplerFilter::None,
            percentiles: default_percentiles()?,
            test_title: "Test name".to_owned(),
            event_tags: None,
            custom_tags: BTreeMap::new(),
            timestamp_precision: InfluxTimestampPrecision::Milliseconds,
        };
        value.validate()?;
        Ok(value)
    }

    /// Sets a token, retaining redaction in configuration/request diagnostics.
    pub fn with_token(mut self, token: impl Into<String>) -> Result<Self, BackendError> {
        self.token = Some(BackendSecret::new(token)?);
        Ok(self)
    }

    /// Changes the measurement.
    #[must_use]
    pub fn with_measurement(mut self, measurement: impl Into<String>) -> Self {
        self.measurement = measurement.into();
        self
    }

    /// Changes detail filtering.
    #[must_use]
    pub fn with_sampler_filter(mut self, filter: SamplerFilter) -> Self {
        self.sampler_filter = filter;
        self
    }

    /// Changes summary-only mode.
    #[must_use]
    pub const fn with_summary_only(mut self, value: bool) -> Self {
        self.summary_only = value;
        self
    }

    /// Adds one custom tag without the upstream `TAG_` prefix.
    pub fn with_custom_tag(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, BackendError> {
        let name = name.into();
        let value = value.into();
        validate_influx_text(&name, BackendResource::Tags)?;
        validate_influx_text(&value, BackendResource::Tags)?;
        self.custom_tags.insert(name, value);
        self.validate()?;
        Ok(self)
    }

    /// Returns a redacted URL suitable for diagnostics.
    pub fn redacted_url(&self) -> String {
        redact_url(&self.url)
    }

    /// Validates endpoint and serializer configuration.
    pub fn validate(&self) -> Result<(), BackendError> {
        self.runtime.validate()?;
        validate_influx_url(&self.url)?;
        validate_influx_text(&self.application, BackendResource::Tags)?;
        validate_influx_text(&self.measurement, BackendResource::Tags)?;
        validate_influx_text(&self.test_title, BackendResource::BodyBytes)?;
        if let Some(value) = &self.event_tags {
            validate_influx_text(value, BackendResource::Tags)?;
        }
        if self.timestamp_precision == InfluxTimestampPrecision::Unsupported {
            return Err(BackendError::Unsupported {
                capability: "influx.timestamp_precision".to_owned(),
            });
        }
        validate_percentile_list(&self.percentiles)?;
        if self.custom_tags.len() > 64 {
            return Err(BackendError::LimitExceeded {
                resource: BackendResource::Tags,
                actual: self.custom_tags.len(),
                maximum: 64,
            });
        }
        Ok(())
    }
}

impl Default for InfluxConfig {
    fn default() -> Self {
        Self::new("http://127.0.0.1:8086/write?db=jmeter", "application").unwrap_or_else(|_| Self {
            runtime: BackendRuntimeConfig {
                queue: BackendQueueConfig::default(),
                send_interval_millis: DEFAULT_INFLUX_SEND_INTERVAL_MILLIS,
                shutdown_timeout_millis: DEFAULT_BACKEND_SHUTDOWN_TIMEOUT_MILLIS,
                max_retries: DEFAULT_BACKEND_MAX_RETRIES,
                window: BackendWindowConfig::default(),
            },
            url: "http://127.0.0.1:8086/write?db=jmeter".to_owned(),
            token: None,
            application: "application".to_owned(),
            measurement: "jmeter".to_owned(),
            summary_only: true,
            sampler_filter: SamplerFilter::None,
            percentiles: Vec::new(),
            test_title: "Test name".to_owned(),
            event_tags: None,
            custom_tags: BTreeMap::new(),
            timestamp_precision: InfluxTimestampPrecision::Milliseconds,
        })
    }
}

/// Ordered custom Java BackendListener descriptor.  It is intentionally an
/// external capability marker; no class loading occurs in this crate.
#[derive(Clone, Eq, PartialEq)]
pub struct JavaBackendListenerDescriptor {
    /// Fully-qualified class name.
    pub class_name: String,
    /// Required compatibility profile identifier.
    pub profile: String,
    /// Ordered raw BackendListener arguments.
    pub arguments: Vec<(String, String)>,
}

impl fmt::Debug for JavaBackendListenerDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted = self
            .arguments
            .iter()
            .map(|(name, value)| (name.as_str(), redact_argument(name, value)))
            .collect::<Vec<_>>();
        formatter
            .debug_struct("JavaBackendListenerDescriptor")
            .field("class_name", &self.class_name)
            .field("profile", &self.profile)
            .field("arguments", &redacted)
            .finish()
    }
}

impl JavaBackendListenerDescriptor {
    /// Creates a bounded descriptor while retaining argument order and names.
    pub fn new(
        class_name: impl Into<String>,
        profile: impl Into<String>,
        arguments: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, BackendError> {
        let class_name = class_name.into();
        let profile = profile.into();
        if class_name.is_empty() || class_name.contains(['\n', '\r', ' ']) {
            return Err(BackendError::InvalidConfig {
                field: BackendConfigField::ClassName,
            });
        }
        if profile.is_empty() || profile.contains(['\n', '\r', ' ']) {
            return Err(BackendError::InvalidConfig {
                field: BackendConfigField::Profile,
            });
        }
        let mut values = Vec::new();
        let mut bytes = 0_usize;
        for (name, value) in arguments {
            if name.is_empty() || name.contains(['\n', '\r']) || value.contains(['\n', '\r']) {
                return Err(BackendError::InvalidConfig {
                    field: BackendConfigField::Argument,
                });
            }
            if values.len() == MAX_BACKEND_ARGUMENTS {
                return Err(BackendError::LimitExceeded {
                    resource: BackendResource::Arguments,
                    actual: values.len() + 1,
                    maximum: MAX_BACKEND_ARGUMENTS,
                });
            }
            let amount = name
                .len()
                .checked_add(value.len())
                .ok_or(BackendError::Overflow)?;
            bytes = bytes.checked_add(amount).ok_or(BackendError::Overflow)?;
            if amount > MAX_BACKEND_ARGUMENT_BYTES {
                return Err(BackendError::LimitExceeded {
                    resource: BackendResource::ArgumentBytes,
                    actual: amount,
                    maximum: MAX_BACKEND_ARGUMENT_BYTES,
                });
            }
            values.push((name, value));
        }
        if bytes > MAX_BACKEND_ARGUMENTS * MAX_BACKEND_ARGUMENT_BYTES {
            return Err(BackendError::LimitExceeded {
                resource: BackendResource::ArgumentBytes,
                actual: bytes,
                maximum: MAX_BACKEND_ARGUMENTS * MAX_BACKEND_ARGUMENT_BYTES,
            });
        }
        Ok(Self {
            class_name,
            profile,
            arguments: values,
        })
    }

    /// Returns the explicit unavailable-capability error for native execution.
    pub fn unsupported_error(&self) -> BackendError {
        BackendError::ExternalUnavailable {
            capability: "java.backend_listener".to_owned(),
        }
    }
}

/// Endpoint selected by a native backend listener.
#[derive(Clone, Debug, PartialEq)]
pub enum BackendEndpoint {
    /// Graphite plaintext.
    Graphite(GraphiteConfig),
    /// InfluxDB line protocol over HTTP.
    Influx(InfluxConfig),
    /// Explicit custom Java delegation descriptor.
    Java(JavaBackendListenerDescriptor),
}

impl BackendEndpoint {
    /// Validates the selected endpoint.
    pub fn validate(&self) -> Result<(), BackendError> {
        match self {
            Self::Graphite(value) => value.validate(),
            Self::Influx(value) => value.validate(),
            Self::Java(value) => Err(value.unsupported_error()),
        }
    }
}

fn default_percentiles() -> Result<Vec<BackendPercentile>, BackendError> {
    [90.0, 95.0, 99.0]
        .into_iter()
        .map(BackendPercentile::from_percent)
        .collect()
}

fn validate_percentile_list(values: &[BackendPercentile]) -> Result<(), BackendError> {
    if values.is_empty() || values.len() > 16 {
        return Err(BackendError::InvalidConfig {
            field: BackendConfigField::Percentiles,
        });
    }
    Ok(())
}

fn validate_metric_prefix(value: &str) -> Result<(), BackendError> {
    if value.is_empty() || value.len() > 16 * 1024 || value.contains(['\n', '\r', ' ']) {
        return Err(BackendError::InvalidConfig {
            field: BackendConfigField::RootMetricsPrefix,
        });
    }
    Ok(())
}

fn validate_influx_url(value: &str) -> Result<(), BackendError> {
    if value.is_empty()
        || value.len() > 16 * 1024
        || value.contains(['\n', '\r'])
        || !(value.starts_with("http://") || value.starts_with("https://"))
    {
        return Err(BackendError::InvalidConfig {
            field: BackendConfigField::Url,
        });
    }
    Ok(())
}

fn validate_influx_text(value: &str, resource: BackendResource) -> Result<(), BackendError> {
    if value.is_empty() || value.len() > 16 * 1024 || value.contains(['\n', '\r']) {
        return Err(BackendError::InvalidConfig {
            field: if resource == BackendResource::Tags {
                BackendConfigField::Application
            } else {
                BackendConfigField::Measurement
            },
        });
    }
    Ok(())
}

fn redact_argument(name: &str, value: &str) -> String {
    let lower = name.to_ascii_lowercase();
    if lower.contains("token")
        || lower.contains("password")
        || lower.contains("secret")
        || lower.contains("authorization")
        || lower.contains("credential")
    {
        "<redacted>".to_owned()
    } else {
        value.to_owned()
    }
}

fn redact_url(value: &str) -> String {
    let mut redacted = value.to_owned();
    if let Some(authority_start) = redacted.find("://") {
        let host_start = authority_start + 3;
        if let Some(path_start) = redacted[host_start..]
            .find(['/', '?', '#'])
            .map(|index| host_start + index)
        {
            let authority = &redacted[host_start..path_start];
            if let Some(at) = authority.rfind('@') {
                redacted.replace_range(host_start..host_start + at + 1, "<redacted>@");
            }
        }
    }
    for key in ["token", "password", "secret", "authorization", "credential"] {
        let mut cursor = 0;
        while let Some(relative) = redacted[cursor..].find(&format!("{key}=")) {
            let start = cursor + relative + key.len() + 1;
            let end = redacted[start..]
                .find('&')
                .map_or(redacted.len(), |offset| start + offset);
            redacted.replace_range(start..end, "<redacted>");
            cursor = start + "<redacted>".len();
            if cursor >= redacted.len() {
                break;
            }
        }
    }
    redacted
}

/// A single Graphite plaintext metric line before encoding.
#[derive(Clone, Debug, PartialEq)]
pub struct GraphiteMetricLine {
    /// Fully-qualified metric path.
    pub path: String,
    /// Numeric metric value.
    pub value: f64,
    /// Unix epoch seconds.
    pub timestamp_seconds: i64,
}

/// Encodes Graphite plaintext lines as UTF-8 bytes.
pub fn encode_graphite_plaintext(
    lines: &[GraphiteMetricLine],
    max_line_bytes: usize,
    max_body_bytes: usize,
) -> Result<Vec<u8>, BackendError> {
    if max_line_bytes == 0 || max_body_bytes == 0 {
        return Err(BackendError::InvalidConfig {
            field: BackendConfigField::BatchBytes,
        });
    }
    let mut output = Vec::new();
    for line in lines {
        if line.path.is_empty() || line.path.contains(['\n', '\r', ' ']) || !line.value.is_finite()
        {
            return Err(BackendError::Protocol);
        }
        let text = format!(
            "{} {} {}\n",
            line.path,
            format_metric_value(line.value),
            line.timestamp_seconds
        );
        let bytes = text.as_bytes();
        if bytes.len() > max_line_bytes {
            return Err(BackendError::LimitExceeded {
                resource: BackendResource::LineBytes,
                actual: bytes.len(),
                maximum: max_line_bytes,
            });
        }
        let next = output
            .len()
            .checked_add(bytes.len())
            .ok_or(BackendError::Overflow)?;
        if next > max_body_bytes {
            return Err(BackendError::LimitExceeded {
                resource: BackendResource::BodyBytes,
                actual: next,
                maximum: max_body_bytes,
            });
        }
        output.extend_from_slice(bytes);
    }
    Ok(output)
}

/// Replaces the path characters documented by JMeter's Graphite sender.
pub fn sanitize_graphite_context(value: &str) -> Result<String, BackendError> {
    if value.is_empty() || value.contains(['\n', '\r']) {
        return Err(BackendError::Protocol);
    }
    let mut result = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' | ' ' => result.push('-'),
            '.' => result.push('_'),
            character => result.push(character),
        }
    }
    Ok(result)
}

fn format_metric_value(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{value:.0}")
    } else {
        value.to_string()
    }
}

/// An Influx line-protocol tag in insertion order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InfluxTag {
    /// Tag key.
    pub key: String,
    /// Tag value.
    pub value: String,
}

/// An Influx line-protocol field value.
#[derive(Clone, Debug, PartialEq)]
pub enum InfluxFieldValue {
    /// Signed integer with the line-protocol integer suffix.
    Integer(i64),
    /// Unsigned integer with the line-protocol unsigned suffix.
    Unsigned(u64),
    /// Finite floating-point value.
    Float(f64),
    /// Boolean value.
    Boolean(bool),
    /// String value.
    String(String),
}

/// An Influx line-protocol point with deterministic insertion ordering.
#[derive(Clone, Debug, PartialEq)]
pub struct InfluxPoint {
    /// Measurement name.
    pub measurement: String,
    /// Ordered tags.
    pub tags: Vec<InfluxTag>,
    /// Ordered fields.
    pub fields: Vec<(String, InfluxFieldValue)>,
    /// Optional epoch-millisecond timestamp.
    pub timestamp_millis: Option<i64>,
}

impl InfluxPoint {
    /// Creates an empty point.
    pub fn new(measurement: impl Into<String>, timestamp_millis: Option<i64>) -> Self {
        Self {
            measurement: measurement.into(),
            tags: Vec::new(),
            fields: Vec::new(),
            timestamp_millis,
        }
    }

    /// Adds one tag, rejecting duplicate keys and invalid text.
    pub fn add_tag(
        &mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), BackendError> {
        let key = key.into();
        let value = value.into();
        validate_line_text(&key, BackendResource::Tags)?;
        validate_line_text(&value, BackendResource::Tags)?;
        if self.tags.iter().any(|tag| tag.key == key) {
            return Err(BackendError::Protocol);
        }
        self.tags.push(InfluxTag { key, value });
        Ok(())
    }

    /// Adds one field, rejecting duplicate keys and invalid text.
    pub fn add_field(
        &mut self,
        key: impl Into<String>,
        value: InfluxFieldValue,
    ) -> Result<(), BackendError> {
        let key = key.into();
        validate_line_text(&key, BackendResource::Fields)?;
        if self.fields.iter().any(|(field, _)| field == &key) {
            return Err(BackendError::Protocol);
        }
        if let InfluxFieldValue::Float(value) = value
            && !value.is_finite()
        {
            return Err(BackendError::Protocol);
        }
        self.fields.push((key, value));
        Ok(())
    }
}

/// Encodes Influx line protocol with explicit escaping and bounds.
pub fn encode_influx_line_protocol(
    points: &[InfluxPoint],
    max_line_bytes: usize,
    max_body_bytes: usize,
) -> Result<Vec<u8>, BackendError> {
    if max_line_bytes == 0 || max_body_bytes == 0 {
        return Err(BackendError::InvalidConfig {
            field: BackendConfigField::BatchBytes,
        });
    }
    let mut body = Vec::new();
    for point in points {
        validate_line_text(&point.measurement, BackendResource::Tags)?;
        if point.fields.is_empty() {
            return Err(BackendError::Protocol);
        }
        let mut line = String::new();
        line.push_str(&escape_measurement_or_key(&point.measurement));
        for tag in &point.tags {
            line.push(',');
            line.push_str(&escape_measurement_or_key(&tag.key));
            line.push('=');
            line.push_str(&escape_tag_value(&tag.value));
        }
        line.push(' ');
        for (index, (key, value)) in point.fields.iter().enumerate() {
            if index > 0 {
                line.push(',');
            }
            line.push_str(&escape_measurement_or_key(key));
            line.push('=');
            append_field_value(&mut line, value)?;
        }
        if let Some(timestamp) = point.timestamp_millis {
            line.push(' ');
            line.push_str(&timestamp.to_string());
        }
        line.push('\n');
        if line.len() > max_line_bytes {
            return Err(BackendError::LimitExceeded {
                resource: BackendResource::LineBytes,
                actual: line.len(),
                maximum: max_line_bytes,
            });
        }
        let next = body
            .len()
            .checked_add(line.len())
            .ok_or(BackendError::Overflow)?;
        if next > max_body_bytes {
            return Err(BackendError::LimitExceeded {
                resource: BackendResource::BodyBytes,
                actual: next,
                maximum: max_body_bytes,
            });
        }
        body.extend_from_slice(line.as_bytes());
    }
    Ok(body)
}

fn validate_line_text(value: &str, resource: BackendResource) -> Result<(), BackendError> {
    if value.is_empty() || value.len() > 16 * 1024 || value.contains(['\n', '\r']) {
        return Err(BackendError::LimitExceeded {
            resource,
            actual: value.len(),
            maximum: 16 * 1024,
        });
    }
    Ok(())
}

fn escape_measurement_or_key(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| match character {
            ',' | ' ' | '=' => ['\\', character].into_iter().collect::<Vec<_>>(),
            character => [character].into_iter().collect::<Vec<_>>(),
        })
        .collect()
}

fn escape_tag_value(value: &str) -> String {
    escape_measurement_or_key(value)
}

fn append_field_value(output: &mut String, value: &InfluxFieldValue) -> Result<(), BackendError> {
    match value {
        InfluxFieldValue::Integer(value) => output.push_str(&format!("{value}i")),
        InfluxFieldValue::Unsigned(value) => output.push_str(&format!("{value}u")),
        InfluxFieldValue::Float(value) => {
            if !value.is_finite() {
                return Err(BackendError::Protocol);
            }
            output.push_str(&value.to_string());
        }
        InfluxFieldValue::Boolean(value) => output.push_str(if *value { "true" } else { "false" }),
        InfluxFieldValue::String(value) => {
            output.push('"');
            for character in value.chars() {
                match character {
                    '\\' | '"' => {
                        output.push('\\');
                        output.push(character);
                    }
                    '\n' | '\r' => return Err(BackendError::Protocol),
                    character => output.push(character),
                }
            }
            output.push('"');
        }
    }
    Ok(())
}

/// Status-separated statistics for one transaction/context.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BackendStatusSnapshot {
    /// Number of represented samples.
    pub count: u64,
    /// Minimum elapsed value with an elapsed observation.
    pub min_millis: Option<u64>,
    /// Maximum elapsed value with an elapsed observation.
    pub max_millis: Option<u64>,
    /// Mean elapsed value with an elapsed observation.
    pub average_millis: Option<f64>,
    /// Configured percentile values.
    pub percentiles: BTreeMap<BackendPercentile, f64>,
}

/// Aggregated metrics for one Graphite/Influx transaction context.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BackendContextSnapshot {
    /// Successful response statistics.
    pub ok: BackendStatusSnapshot,
    /// Failed response statistics.
    pub ko: BackendStatusSnapshot,
    /// All response statistics.
    pub all: BackendStatusSnapshot,
    /// Server-hit count, including nested sub-results when represented.
    pub hit_count: u64,
    /// Sent-byte total.
    pub sent_bytes: u64,
    /// Received-byte total.
    pub received_bytes: u64,
    /// Failed represented sample count.
    pub error_count: u64,
}

/// Active-thread statistics supplied by explicit lifecycle notifications.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ActiveThreadSnapshot {
    /// Minimum observed active threads.
    pub min: Option<u64>,
    /// Maximum observed active threads.
    pub max: Option<u64>,
    /// Mean observed active threads.
    pub mean: Option<f64>,
    /// Explicit thread-start notifications.
    pub started: u64,
    /// Explicit thread-end notifications.
    pub ended: u64,
}

/// One Influx error descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendErrorSnapshot {
    /// Transaction/context label that produced the error.
    pub transaction: String,
    /// Response code, with empty/absent values mapped to `0`.
    pub response_code: String,
    /// Response message, with empty/absent values mapped to `none`.
    pub response_message: String,
    /// Count.
    pub count: u64,
}

/// An Influx annotation event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendAnnotation {
    /// Annotation text.
    pub text: String,
    /// Epoch-millisecond timestamp.
    pub timestamp_millis: i64,
}

/// Immutable snapshot used by both wire serializers.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BackendMetricsSnapshot {
    /// Contexts in lexical order.
    pub contexts: BTreeMap<String, BackendContextSnapshot>,
    /// Internal active-thread metrics.
    pub active_threads: ActiveThreadSnapshot,
    /// Error descriptors in first-seen order.
    pub errors: Vec<BackendErrorSnapshot>,
    /// Test-start/end annotation records.
    pub annotations: Vec<BackendAnnotation>,
}

/// Alias used by callers that treat a snapshot as one metric batch.
pub type BackendMetricBatch = BackendMetricsSnapshot;

/// Converts a snapshot to Graphite metric lines.
pub fn graphite_metric_lines(
    config: &GraphiteConfig,
    snapshot: &BackendMetricsSnapshot,
    timestamp_millis: i64,
) -> Result<Vec<GraphiteMetricLine>, BackendError> {
    config.validate()?;
    let timestamp_seconds = timestamp_millis.div_euclid(1_000);
    let mut lines = Vec::new();
    for (context, metrics) in &snapshot.contexts {
        let context = sanitize_graphite_context(context)?;
        let prefix = format!("{}{context}.", config.root_metrics_prefix);
        append_graphite_count(&mut lines, &prefix, "ok", &metrics.ok, timestamp_seconds);
        append_graphite_count(&mut lines, &prefix, "ko", &metrics.ko, timestamp_seconds);
        append_graphite_count(&mut lines, &prefix, "a", &metrics.all, timestamp_seconds);
        lines.push(graphite_line(
            &prefix,
            "h.count",
            metrics.hit_count,
            timestamp_seconds,
        ));
        lines.push(graphite_line(
            &prefix,
            "sb.bytes",
            metrics.sent_bytes,
            timestamp_seconds,
        ));
        lines.push(graphite_line(
            &prefix,
            "rb.bytes",
            metrics.received_bytes,
            timestamp_seconds,
        ));
        append_graphite_timings(
            &mut lines,
            &prefix,
            "ok",
            &metrics.ok,
            &config.percentiles,
            timestamp_seconds,
        );
        append_graphite_timings(
            &mut lines,
            &prefix,
            "ko",
            &metrics.ko,
            &config.percentiles,
            timestamp_seconds,
        );
        append_graphite_timings(
            &mut lines,
            &prefix,
            "a",
            &metrics.all,
            &config.percentiles,
            timestamp_seconds,
        );
    }
    if snapshot.active_threads.min.is_some()
        || snapshot.active_threads.max.is_some()
        || snapshot.active_threads.mean.is_some()
        || snapshot.active_threads.started > 0
        || snapshot.active_threads.ended > 0
    {
        let prefix = format!("{}test.", config.root_metrics_prefix);
        if let Some(value) = snapshot.active_threads.min {
            lines.push(graphite_line(&prefix, "minAT", value, timestamp_seconds));
        }
        if let Some(value) = snapshot.active_threads.max {
            lines.push(graphite_line(&prefix, "maxAT", value, timestamp_seconds));
        }
        if let Some(value) = snapshot.active_threads.mean {
            lines.push(GraphiteMetricLine {
                path: format!("{prefix}meanAT"),
                value,
                timestamp_seconds,
            });
        }
        lines.push(graphite_line(
            &prefix,
            "startedT",
            snapshot.active_threads.started,
            timestamp_seconds,
        ));
        lines.push(graphite_line(
            &prefix,
            "endedT",
            snapshot.active_threads.ended,
            timestamp_seconds,
        ));
    }
    Ok(lines)
}

fn graphite_line(
    prefix: &str,
    suffix: &str,
    value: u64,
    timestamp_seconds: i64,
) -> GraphiteMetricLine {
    GraphiteMetricLine {
        path: format!("{prefix}{suffix}"),
        value: value as f64,
        timestamp_seconds,
    }
}

fn append_graphite_count(
    lines: &mut Vec<GraphiteMetricLine>,
    prefix: &str,
    name: &str,
    status: &BackendStatusSnapshot,
    timestamp_seconds: i64,
) {
    lines.push(graphite_line(
        prefix,
        &format!("{name}.count"),
        status.count,
        timestamp_seconds,
    ));
}

fn append_graphite_timings(
    lines: &mut Vec<GraphiteMetricLine>,
    prefix: &str,
    name: &str,
    status: &BackendStatusSnapshot,
    percentiles: &[BackendPercentile],
    timestamp_seconds: i64,
) {
    if let Some(value) = status.min_millis {
        lines.push(graphite_line(
            prefix,
            &format!("{name}.min"),
            value,
            timestamp_seconds,
        ));
    }
    if let Some(value) = status.max_millis {
        lines.push(graphite_line(
            prefix,
            &format!("{name}.max"),
            value,
            timestamp_seconds,
        ));
    }
    if let Some(value) = status.average_millis {
        lines.push(GraphiteMetricLine {
            path: format!("{prefix}{name}.avg"),
            value,
            timestamp_seconds,
        });
    }
    for percentile in percentiles {
        if let Some(value) = status.percentiles.get(percentile) {
            lines.push(GraphiteMetricLine {
                path: format!("{prefix}{name}.pct{}", percentile.wire_suffix()),
                value: *value,
                timestamp_seconds,
            });
        }
    }
}

/// Converts a snapshot to Influx points using the configured schema.
pub fn influx_points(
    config: &InfluxConfig,
    snapshot: &BackendMetricsSnapshot,
    timestamp_millis: i64,
) -> Result<Vec<InfluxPoint>, BackendError> {
    config.validate()?;
    let mut points = Vec::new();
    for (transaction, metrics) in &snapshot.contexts {
        let mut all = InfluxPoint::new(&config.measurement, Some(timestamp_millis));
        add_common_tags(&mut all, config, transaction, "all")?;
        add_context_fields(&mut all, metrics, &config.percentiles)?;
        points.push(all);
        if !config.summary_only && config.sampler_filter.matches(transaction)? {
            append_influx_status_point(
                &mut points,
                config,
                InfluxStatusSpec {
                    transaction,
                    status: "ok",
                    metrics: &metrics.ok,
                    hit_count: metrics.hit_count,
                    sent_bytes: metrics.sent_bytes,
                    received_bytes: metrics.received_bytes,
                    percentiles: &config.percentiles,
                    timestamp_millis,
                },
            )?;
            append_influx_status_point(
                &mut points,
                config,
                InfluxStatusSpec {
                    transaction,
                    status: "ko",
                    metrics: &metrics.ko,
                    hit_count: metrics.hit_count,
                    sent_bytes: metrics.sent_bytes,
                    received_bytes: metrics.received_bytes,
                    percentiles: &config.percentiles,
                    timestamp_millis,
                },
            )?;
        }
        for error in snapshot
            .errors
            .iter()
            .filter(|error| error.transaction == *transaction)
        {
            append_influx_error_point(&mut points, config, error, timestamp_millis)?;
        }
    }
    if snapshot.active_threads.min.is_some()
        || snapshot.active_threads.max.is_some()
        || snapshot.active_threads.mean.is_some()
        || snapshot.active_threads.started > 0
        || snapshot.active_threads.ended > 0
    {
        let mut point = InfluxPoint::new("internal", Some(timestamp_millis));
        point.add_tag("application", &config.application)?;
        point.add_tag("transaction", "internal")?;
        if let Some(value) = snapshot.active_threads.min {
            point.add_field("minAT", InfluxFieldValue::Unsigned(value))?;
        }
        if let Some(value) = snapshot.active_threads.max {
            point.add_field("maxAT", InfluxFieldValue::Unsigned(value))?;
        }
        if let Some(value) = snapshot.active_threads.mean {
            point.add_field("meanAT", InfluxFieldValue::Float(value))?;
        }
        point.add_field(
            "startedT",
            InfluxFieldValue::Unsigned(snapshot.active_threads.started),
        )?;
        point.add_field(
            "endedT",
            InfluxFieldValue::Unsigned(snapshot.active_threads.ended),
        )?;
        points.push(point);
    }
    for annotation in &snapshot.annotations {
        let mut point = InfluxPoint::new("events", Some(annotation.timestamp_millis));
        point.add_tag("application", &config.application)?;
        point.add_tag("title", &config.test_title)?;
        if let Some(tags) = &config.event_tags {
            point.add_tag("tags", tags)?;
        }
        point.add_field("text", InfluxFieldValue::String(annotation.text.clone()))?;
        points.push(point);
    }
    Ok(points)
}

fn append_influx_error_point(
    points: &mut Vec<InfluxPoint>,
    config: &InfluxConfig,
    error: &BackendErrorSnapshot,
    timestamp_millis: i64,
) -> Result<(), BackendError> {
    let mut point = InfluxPoint::new(&config.measurement, Some(timestamp_millis));
    point.add_tag("application", &config.application)?;
    point.add_tag("transaction", &error.transaction)?;
    point.add_tag("responseCode", &error.response_code)?;
    point.add_tag("responseMessage", &error.response_message)?;
    point.add_field("count", InfluxFieldValue::Unsigned(error.count))?;
    points.push(point);
    Ok(())
}

fn add_common_tags(
    point: &mut InfluxPoint,
    config: &InfluxConfig,
    transaction: &str,
    status: &str,
) -> Result<(), BackendError> {
    point.add_tag("application", &config.application)?;
    point.add_tag("transaction", transaction)?;
    point.add_tag("statut", status)?;
    for (key, value) in &config.custom_tags {
        point.add_tag(key, value)?;
    }
    Ok(())
}

struct InfluxStatusSpec<'a> {
    transaction: &'a str,
    status: &'a str,
    metrics: &'a BackendStatusSnapshot,
    hit_count: u64,
    sent_bytes: u64,
    received_bytes: u64,
    percentiles: &'a [BackendPercentile],
    timestamp_millis: i64,
}

fn append_influx_status_point(
    points: &mut Vec<InfluxPoint>,
    config: &InfluxConfig,
    spec: InfluxStatusSpec<'_>,
) -> Result<(), BackendError> {
    if spec.metrics.count == 0 {
        return Ok(());
    }
    let mut point = InfluxPoint::new(&config.measurement, Some(spec.timestamp_millis));
    add_common_tags(&mut point, config, spec.transaction, spec.status)?;
    add_status_fields(
        &mut point,
        spec.metrics,
        spec.hit_count,
        spec.sent_bytes,
        spec.received_bytes,
        None,
        spec.percentiles,
    )?;
    points.push(point);
    Ok(())
}

fn add_context_fields(
    point: &mut InfluxPoint,
    context: &BackendContextSnapshot,
    percentiles: &[BackendPercentile],
) -> Result<(), BackendError> {
    add_status_fields(
        point,
        &context.all,
        context.hit_count,
        context.sent_bytes,
        context.received_bytes,
        Some(context.error_count),
        percentiles,
    )
}

fn add_status_fields(
    point: &mut InfluxPoint,
    metrics: &BackendStatusSnapshot,
    hit_count: u64,
    sent_bytes: u64,
    received_bytes: u64,
    error_count: Option<u64>,
    percentiles: &[BackendPercentile],
) -> Result<(), BackendError> {
    point.add_field("count", InfluxFieldValue::Unsigned(metrics.count))?;
    if let Some(value) = error_count {
        point.add_field("countError", InfluxFieldValue::Unsigned(value))?;
    }
    if let Some(value) = metrics.average_millis {
        point.add_field("avg", InfluxFieldValue::Float(value))?;
    }
    if let Some(value) = metrics.min_millis {
        point.add_field("min", InfluxFieldValue::Unsigned(value))?;
    }
    if let Some(value) = metrics.max_millis {
        point.add_field("max", InfluxFieldValue::Unsigned(value))?;
    }
    point.add_field("hit", InfluxFieldValue::Unsigned(hit_count))?;
    point.add_field("sb", InfluxFieldValue::Unsigned(sent_bytes))?;
    point.add_field("rb", InfluxFieldValue::Unsigned(received_bytes))?;
    for percentile in percentiles {
        if let Some(value) = metrics.percentiles.get(percentile) {
            point.add_field(
                format!("pct{}", percentile.influx_suffix()),
                InfluxFieldValue::Float(*value),
            )?;
        }
    }
    Ok(())
}

/// Influx HTTP request created by the pure serializer.
#[derive(Clone, Eq, PartialEq)]
pub struct InfluxHttpRequest {
    /// Redaction-aware target URL.
    pub url: String,
    /// Request headers.  Authorization is retained for the edge sender but
    /// omitted from [`Debug`] output.
    pub headers: Vec<(String, String)>,
    /// UTF-8 line-protocol body.
    pub body: Vec<u8>,
}

impl fmt::Debug for InfluxHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let headers = self
            .headers
            .iter()
            .map(|(name, value)| {
                if name.eq_ignore_ascii_case("authorization") {
                    (name.as_str(), "<redacted>".to_owned())
                } else {
                    (name.as_str(), value.clone())
                }
            })
            .collect::<Vec<_>>();
        formatter
            .debug_struct("InfluxHttpRequest")
            .field("url", &redact_url(&self.url))
            .field("headers", &headers)
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

/// Builds an Influx HTTP request from points.
pub fn build_influx_http_request(
    config: &InfluxConfig,
    points: &[InfluxPoint],
    max_line_bytes: usize,
    max_body_bytes: usize,
) -> Result<InfluxHttpRequest, BackendError> {
    config.validate()?;
    let body = encode_influx_line_protocol(points, max_line_bytes, max_body_bytes)?;
    let mut headers = vec![(
        "Content-Type".to_owned(),
        "text/plain; charset=utf-8".to_owned(),
    )];
    if let Some(token) = &config.token {
        headers.push((
            "Authorization".to_owned(),
            format!("Token {}", token.expose()),
        ));
    }
    Ok(InfluxHttpRequest {
        url: config.url.clone(),
        headers,
        body,
    })
}

/// A sender boundary implemented by the application/runtime edge.
pub trait BackendSender: Send {
    /// Performs endpoint setup without opening an implicit ambient service.
    fn setup(&mut self, endpoint: &BackendEndpoint) -> Result<(), BackendError>;
    /// Sends one already-encoded payload.  A failed send leaves the accepted
    /// events queued for explicit retry or finalization failure.
    fn send(&mut self, payload: &BackendPayload) -> Result<(), BackendError>;
    /// Performs bounded sender teardown.
    fn teardown(&mut self) -> Result<(), BackendError>;
}

/// Pure wire payload handed to a sender adapter.
#[derive(Clone, PartialEq)]
pub enum BackendPayload {
    /// Graphite plaintext bytes and target.
    Graphite {
        /// Host.
        host: String,
        /// Port.
        port: u16,
        /// UTF-8 lines.
        body: Vec<u8>,
    },
    /// Influx HTTP request.
    Influx(InfluxHttpRequest),
}

impl fmt::Debug for BackendPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Graphite { host, port, body } => formatter
                .debug_struct("Graphite")
                .field("host", host)
                .field("port", port)
                .field("body_bytes", &body.len())
                .finish(),
            Self::Influx(request) => request.fmt(formatter),
        }
    }
}

/// Wall clock capability used only to timestamp scheduled sends.
pub trait BackendClock: Send {
    /// Returns Unix epoch milliseconds.
    fn now_millis(&self) -> i64;
}

/// Scheduler capability used to arm/cancel periodic flush notifications.
pub trait BackendScheduler: Send {
    /// Arms a wakeup at an absolute epoch-millisecond value.
    fn schedule(&mut self, at_millis: i64) -> Result<(), BackendError>;
    /// Cancels a previously armed wakeup.
    fn cancel(&mut self) -> Result<(), BackendError>;
}

/// Lifecycle state of a backend listener.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BackendLifecycleState {
    /// Constructed but not started.
    Created,
    /// Accepting events.
    Running,
    /// No new events; accepted events are being finalized.
    Draining,
    /// Closed after teardown.
    Closed,
    /// Failed; accepted events remain accounted for but delivery is no longer
    /// considered successful.
    Failed,
}

/// Queue admission result; an explicit dropped outcome is never silent.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EnqueueOutcome {
    /// Event accepted.
    Accepted,
    /// Event intentionally not retained, with cumulative diagnostic count.
    DroppedWithDiagnostic {
        /// Number dropped by this listener.
        dropped_total: u64,
    },
}

/// Flush result.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FlushOutcome {
    /// Nothing was queued.
    Idle,
    /// Number of events delivered in this send.
    Sent {
        /// Delivered events.
        events: usize,
    },
}

#[derive(Clone)]
struct QueuedEvent {
    event: SampleEvent,
    estimated_bytes: usize,
}

/// Run-owned bounded backend listener state machine.
pub struct BackendListener {
    endpoint: BackendEndpoint,
    runtime_config: BackendRuntimeConfig,
    summary_only: bool,
    sampler_filter: SamplerFilter,
    percentiles_config: Vec<BackendPercentile>,
    sender: Box<dyn BackendSender>,
    clock: Box<dyn BackendClock>,
    scheduler: Box<dyn BackendScheduler>,
    state: BackendLifecycleState,
    queue: VecDeque<QueuedEvent>,
    queue_bytes: usize,
    dropped_events: u64,
    next_sequence: u64,
    next_flush_millis: Option<i64>,
    scheduler_armed: bool,
    sender_started: bool,
    metrics: MetricState,
    cancelled: bool,
}

impl fmt::Debug for BackendListener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackendListener")
            .field("endpoint", &self.endpoint)
            .field("state", &self.state)
            .field("queued_events", &self.queue.len())
            .field("queued_bytes", &self.queue_bytes)
            .field("dropped_events", &self.dropped_events)
            .finish()
    }
}

impl BackendListener {
    /// Creates a run-owned listener.  No sender or scheduler effect occurs
    /// until [`BackendListener::start`] is called.
    pub fn new(
        endpoint: BackendEndpoint,
        sender: Box<dyn BackendSender>,
        clock: Box<dyn BackendClock>,
        scheduler: Box<dyn BackendScheduler>,
    ) -> Result<Self, BackendError> {
        endpoint.validate()?;
        let (runtime_config, summary_only, sampler_filter, percentiles_config) = match &endpoint {
            BackendEndpoint::Graphite(config) => (
                config.runtime.clone(),
                config.summary_only,
                config.sampler_filter.clone(),
                config.percentiles.clone(),
            ),
            BackendEndpoint::Influx(config) => (
                config.runtime.clone(),
                config.summary_only,
                config.sampler_filter.clone(),
                config.percentiles.clone(),
            ),
            BackendEndpoint::Java(_) => {
                return Err(BackendError::ExternalUnavailable {
                    capability: "java.backend_listener".to_owned(),
                });
            }
        };
        let window = runtime_config.window;
        Ok(Self {
            endpoint,
            runtime_config,
            summary_only,
            sampler_filter,
            percentiles_config,
            sender,
            clock,
            scheduler,
            state: BackendLifecycleState::Created,
            queue: VecDeque::new(),
            queue_bytes: 0,
            dropped_events: 0,
            next_sequence: 0,
            next_flush_millis: None,
            scheduler_armed: false,
            sender_started: false,
            metrics: MetricState::new(window),
            cancelled: false,
        })
    }

    /// Starts sender setup and arms the first periodic flush.
    pub fn start(&mut self) -> Result<(), BackendError> {
        if self.state != BackendLifecycleState::Created {
            return Err(BackendError::InvalidConfig {
                field: BackendConfigField::Sender,
            });
        }
        if let Err(error) = self.sender.setup(&self.endpoint) {
            self.state = BackendLifecycleState::Failed;
            return Err(error);
        }
        self.sender_started = true;
        let due = match self.next_deadline() {
            Ok(due) => due,
            Err(error) => {
                let _ = self.sender.teardown();
                self.sender_started = false;
                self.state = BackendLifecycleState::Failed;
                return Err(error);
            }
        };
        if let Err(error) = self.scheduler.schedule(due) {
            let _ = self.sender.teardown();
            self.sender_started = false;
            self.state = BackendLifecycleState::Failed;
            return Err(error);
        }
        self.next_flush_millis = Some(due);
        self.scheduler_armed = true;
        self.state = BackendLifecycleState::Running;
        Ok(())
    }

    /// Returns the lifecycle state.
    pub const fn state(&self) -> BackendLifecycleState {
        self.state
    }

    /// Returns the number of accepted events awaiting delivery.
    pub fn queued_events(&self) -> usize {
        self.queue.len()
    }

    /// Returns estimated queued bytes.
    pub const fn queued_bytes(&self) -> usize {
        self.queue_bytes
    }

    /// Returns cumulative explicitly diagnosed drops.
    pub const fn dropped_events(&self) -> u64 {
        self.dropped_events
    }

    /// Returns the next sequence number that will be assigned.
    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// Enqueues an immutable event snapshot without performing I/O.
    pub fn enqueue(&mut self, event: SampleEvent) -> Result<EnqueueOutcome, BackendError> {
        if self.state != BackendLifecycleState::Running {
            return Err(if self.cancelled {
                BackendError::Cancelled
            } else {
                BackendError::QueueClosed
            });
        }
        let estimated_bytes = estimate_event_bytes(&event)?;
        let queue = &self.runtime_config.queue;
        if self.queue.len() >= queue.capacity
            || self
                .queue_bytes
                .checked_add(estimated_bytes)
                .is_none_or(|value| value > queue.max_bytes)
        {
            if queue.full_policy == QueueFullPolicy::DropWithDiagnostic {
                self.dropped_events = self.dropped_events.saturating_add(1);
                return Ok(EnqueueOutcome::DroppedWithDiagnostic {
                    dropped_total: self.dropped_events,
                });
            }
            return Err(BackendError::QueueFull {
                capacity: queue.capacity,
            });
        }
        self.queue_bytes = self
            .queue_bytes
            .checked_add(estimated_bytes)
            .ok_or(BackendError::Overflow)?;
        self.queue.push_back(QueuedEvent {
            event,
            estimated_bytes,
        });
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(BackendError::Overflow)?;
        Ok(EnqueueOutcome::Accepted)
    }

    /// Enqueues a borrowed event by taking the immutable listener snapshot.
    pub fn enqueue_ref(&mut self, event: &SampleEvent) -> Result<EnqueueOutcome, BackendError> {
        self.enqueue(event.clone())
    }

    /// Polls the injected clock and flushes when the scheduled deadline is due.
    pub fn poll(&mut self) -> Result<FlushOutcome, BackendError> {
        if self.state != BackendLifecycleState::Running {
            return Err(if self.cancelled {
                BackendError::Cancelled
            } else {
                BackendError::QueueClosed
            });
        }
        if self
            .next_flush_millis
            .is_some_and(|deadline| self.clock.now_millis() >= deadline)
        {
            self.flush()
        } else {
            Ok(FlushOutcome::Idle)
        }
    }

    /// Flushes one bounded batch.  Failed sends retain every accepted event.
    pub fn flush(&mut self) -> Result<FlushOutcome, BackendError> {
        if self.cancelled {
            return Err(BackendError::Cancelled);
        }
        if !matches!(
            self.state,
            BackendLifecycleState::Running | BackendLifecycleState::Draining
        ) {
            return Err(BackendError::QueueClosed);
        }
        self.flush_internal(true)
    }

    fn flush_internal(&mut self, reschedule: bool) -> Result<FlushOutcome, BackendError> {
        if self.queue.is_empty() && !self.metrics.has_pending() {
            if reschedule {
                self.arm_next_flush()?;
            }
            return Ok(FlushOutcome::Idle);
        }
        let queue_config = &self.runtime().queue;
        let take = self.queue.len().min(queue_config.batch_capacity);
        let mut candidate = self.metrics.clone();
        let now = self.clock.now_millis();
        let mut batch_bytes = 0_usize;
        for queued in self.queue.iter().take(take) {
            batch_bytes = batch_bytes
                .checked_add(queued.estimated_bytes)
                .ok_or(BackendError::Overflow)?;
            candidate.record(&queued.event, now, self.selection(), self.runtime().window)?;
        }
        if batch_bytes > queue_config.batch_bytes {
            return Err(BackendError::LimitExceeded {
                resource: BackendResource::BatchBytes,
                actual: batch_bytes,
                maximum: queue_config.batch_bytes,
            });
        }
        let snapshot = candidate.snapshot(now, self.percentiles())?;
        let payload = self.payload(&snapshot, now)?;
        self.sender.send(&payload)?;
        for _ in 0..take {
            if let Some(queued) = self.queue.pop_front() {
                self.queue_bytes = self
                    .queue_bytes
                    .checked_sub(queued.estimated_bytes)
                    .ok_or(BackendError::Overflow)?;
            }
        }
        candidate.reset_interval();
        self.metrics = candidate;
        if reschedule && self.state == BackendLifecycleState::Running {
            self.arm_next_flush()?;
        }
        Ok(FlushOutcome::Sent { events: take })
    }

    /// Records an explicit test-start annotation in the next Influx batch.
    pub fn test_started(&mut self, title: impl Into<String>) -> Result<(), BackendError> {
        self.record_annotation(format!("{} started", title.into()))
    }

    /// Records an explicit test-end annotation in the final Influx batch.
    pub fn test_ended(&mut self, title: impl Into<String>) -> Result<(), BackendError> {
        self.record_annotation(format!("{} ended", title.into()))
    }

    /// Records one active-thread observation.
    pub fn active_threads(&mut self, count: u64) -> Result<(), BackendError> {
        self.ensure_running()?;
        self.metrics.active.add(count)?;
        Ok(())
    }

    /// Records a thread-start lifecycle notification.
    pub fn thread_started(&mut self) {
        if self.state == BackendLifecycleState::Running {
            self.metrics.active.started = self.metrics.active.started.saturating_add(1);
        }
    }

    /// Records a thread-end lifecycle notification.
    pub fn thread_ended(&mut self) {
        if self.state == BackendLifecycleState::Running {
            self.metrics.active.ended = self.metrics.active.ended.saturating_add(1);
        }
    }

    fn ensure_running(&self) -> Result<(), BackendError> {
        if self.state == BackendLifecycleState::Running {
            Ok(())
        } else if self.cancelled {
            Err(BackendError::Cancelled)
        } else {
            Err(BackendError::QueueClosed)
        }
    }

    fn record_annotation(&mut self, text: String) -> Result<(), BackendError> {
        self.ensure_running()?;
        if self.metrics.annotations.len() >= DEFAULT_BACKEND_MAX_ANNOTATIONS {
            return Err(BackendError::LimitExceeded {
                resource: BackendResource::BodyBytes,
                actual: self.metrics.annotations.len() + 1,
                maximum: DEFAULT_BACKEND_MAX_ANNOTATIONS,
            });
        }
        if text.len() > MAX_BACKEND_ANNOTATION_BYTES || text.contains(['\n', '\r']) {
            return Err(BackendError::LimitExceeded {
                resource: BackendResource::BodyBytes,
                actual: text.len(),
                maximum: MAX_BACKEND_ANNOTATION_BYTES,
            });
        }
        self.metrics.annotations.push(BackendAnnotation {
            text,
            timestamp_millis: self.clock.now_millis(),
        });
        Ok(())
    }

    /// Requests cancellation.  Accepted events remain observable through the
    /// queue and finalization reports cancellation rather than dropping them.
    pub fn cancel(&mut self) -> Result<(), BackendError> {
        if matches!(
            self.state,
            BackendLifecycleState::Closed | BackendLifecycleState::Failed
        ) {
            return Ok(());
        }
        if self.state == BackendLifecycleState::Created {
            self.cancelled = true;
            self.state = BackendLifecycleState::Closed;
            return Ok(());
        }
        self.cancelled = true;
        self.state = BackendLifecycleState::Draining;
        if self.scheduler_armed {
            self.scheduler.cancel()?;
            self.scheduler_armed = false;
            self.next_flush_millis = None;
        }
        Ok(())
    }

    /// Drains accepted events in bounded batches and tears down the sender.
    pub fn finish(&mut self) -> Result<(), BackendError> {
        if matches!(
            self.state,
            BackendLifecycleState::Closed | BackendLifecycleState::Failed
        ) {
            return Ok(());
        }
        if self.state == BackendLifecycleState::Created {
            self.state = BackendLifecycleState::Closed;
            return Ok(());
        }
        if self.state == BackendLifecycleState::Running {
            self.state = BackendLifecycleState::Draining;
        }
        let mut first_error = None;
        if self.scheduler_armed {
            if let Err(error) = self.scheduler.cancel() {
                first_error = Some(error);
            } else {
                self.scheduler_armed = false;
                self.next_flush_millis = None;
            }
        }
        if self.cancelled && first_error.is_none() {
            first_error = Some(BackendError::Cancelled);
        } else if !self.cancelled && first_error.is_none() {
            let mut rounds = 0_usize;
            let max_rounds = self.queue.len().saturating_add(1);
            while !self.queue.is_empty() && rounds < max_rounds {
                rounds = rounds.saturating_add(1);
                match self.flush_internal(false) {
                    Ok(FlushOutcome::Sent { events }) if events > 0 => {}
                    Ok(_) => {
                        first_error = Some(BackendError::Shutdown {
                            operation: BackendOperation::Shutdown,
                        });
                        break;
                    }
                    Err(error) => {
                        first_error = Some(error);
                        break;
                    }
                }
            }
            if first_error.is_none() && !self.queue.is_empty() {
                first_error = Some(BackendError::Shutdown {
                    operation: BackendOperation::Shutdown,
                });
            }
            if first_error.is_none()
                && self.queue.is_empty()
                && self.metrics.has_pending()
                && let Err(error) = self.flush_internal(false)
            {
                first_error = Some(error);
            }
        }
        if self.sender_started {
            if let Err(error) = self.sender.teardown()
                && first_error.is_none()
            {
                first_error = Some(error);
            }
            self.sender_started = false;
        }
        self.state = if first_error.is_some() {
            BackendLifecycleState::Failed
        } else {
            BackendLifecycleState::Closed
        };
        first_error.map_or(Ok(()), Err)
    }

    /// Returns a snapshot of committed metrics, using the injected clock.
    pub fn snapshot(&self) -> Result<BackendMetricsSnapshot, BackendError> {
        self.metrics
            .snapshot(self.clock.now_millis(), self.percentiles())
    }

    fn runtime(&self) -> &BackendRuntimeConfig {
        &self.runtime_config
    }

    fn selection(&self) -> Selection<'_> {
        Selection {
            summary_only: self.summary_only,
            filter: &self.sampler_filter,
        }
    }

    fn percentiles(&self) -> &[BackendPercentile] {
        &self.percentiles_config
    }

    fn payload(
        &self,
        snapshot: &BackendMetricsSnapshot,
        now: i64,
    ) -> Result<BackendPayload, BackendError> {
        match &self.endpoint {
            BackendEndpoint::Graphite(config) => {
                let lines = graphite_metric_lines(config, snapshot, now)?;
                let body = encode_graphite_plaintext(
                    &lines,
                    self.runtime().queue.batch_bytes,
                    self.runtime().queue.batch_bytes,
                )?;
                Ok(BackendPayload::Graphite {
                    host: config.host.clone(),
                    port: config.port,
                    body,
                })
            }
            BackendEndpoint::Influx(config) => {
                let points = influx_points(config, snapshot, now)?;
                let request = build_influx_http_request(
                    config,
                    &points,
                    self.runtime().queue.batch_bytes,
                    self.runtime().queue.batch_bytes,
                )?;
                Ok(BackendPayload::Influx(request))
            }
            BackendEndpoint::Java(_) => Err(BackendError::ExternalUnavailable {
                capability: "java.backend_listener".to_owned(),
            }),
        }
    }

    fn arm_next_flush(&mut self) -> Result<(), BackendError> {
        let due = self.next_deadline()?;
        self.scheduler.schedule(due)?;
        self.next_flush_millis = Some(due);
        self.scheduler_armed = true;
        Ok(())
    }

    fn next_deadline(&self) -> Result<i64, BackendError> {
        let interval = i64::try_from(self.runtime().send_interval_millis)
            .map_err(|_| BackendError::Overflow)?;
        self.clock
            .now_millis()
            .checked_add(interval)
            .ok_or(BackendError::Overflow)
    }
}

fn estimate_event_bytes(event: &SampleEvent) -> Result<usize, BackendError> {
    fn result_bytes(result: &SampleResult, depth: usize) -> Result<usize, BackendError> {
        if depth > 128 {
            return Err(BackendError::LimitExceeded {
                resource: BackendResource::EventBytes,
                actual: depth,
                maximum: 128,
            });
        }
        let mut size = 64_usize;
        for amount in [
            result.label().len(),
            result.response_code().map_or(0, str::len),
            result.response_message().map_or(0, str::len),
            result.failure_message().map_or(0, str::len),
            result.sampler_data().map_or(0, str::len),
            result.response_file().map_or(0, str::len),
            result.url().map_or(0, str::len),
            result.request_data().map_or(0, |value| value.len()),
            result.response_data().map_or(0, |value| value.len()),
            result
                .request_headers()
                .map_or(0, |value| value.as_str().len()),
            result
                .response_headers()
                .map_or(0, |value| value.as_str().len()),
        ] {
            size = size.checked_add(amount).ok_or(BackendError::Overflow)?;
        }
        for assertion in result.assertions() {
            for amount in [
                assertion.name().len(),
                assertion.failure_message().map_or(0, str::len),
                assertion.error_message().map_or(0, str::len),
            ] {
                size = size.checked_add(amount).ok_or(BackendError::Overflow)?;
            }
        }
        for child in result.sub_results() {
            size = size
                .checked_add(result_bytes(child, depth + 1)?)
                .ok_or(BackendError::Overflow)?;
        }
        Ok(size)
    }
    let mut size = result_bytes(event.result(), 0)?;
    for amount in [
        event.run().as_str().len(),
        event.thread().name().len(),
        event.thread().group().map_or(0, str::len),
        event.host().as_str().len(),
    ] {
        size = size.checked_add(amount).ok_or(BackendError::Overflow)?;
    }
    for (name, value) in event.variables().iter() {
        size = size.checked_add(name.len()).ok_or(BackendError::Overflow)?;
        if let Some(value) = value.as_str() {
            size = size
                .checked_add(value.len())
                .ok_or(BackendError::Overflow)?;
        }
    }
    Ok(size)
}

#[derive(Clone, Copy)]
struct Selection<'a> {
    summary_only: bool,
    filter: &'a SamplerFilter,
}

#[derive(Clone)]
struct ObservationWindow {
    config: BackendWindowConfig,
    values: VecDeque<(i64, u64)>,
}

impl ObservationWindow {
    fn new(config: BackendWindowConfig) -> Self {
        Self {
            config,
            values: VecDeque::new(),
        }
    }

    fn add(&mut self, now: i64, value: u64) {
        if self.values.len() >= self.config.max_samples {
            self.values.pop_front();
        }
        self.values.push_back((now, value));
        self.prune(now);
    }

    fn prune(&mut self, now: i64) {
        if self.config.mode == BackendWindowMode::Timed {
            let floor = now.saturating_sub(self.config.duration_millis.min(i64::MAX as u64) as i64);
            while self
                .values
                .front()
                .is_some_and(|(timestamp, _)| *timestamp < floor)
            {
                self.values.pop_front();
            }
        }
    }

    fn values(&self, now: i64) -> Vec<u64> {
        let mut copy = self.clone();
        copy.prune(now);
        copy.values.iter().map(|(_, value)| *value).collect()
    }
}

#[derive(Clone)]
struct StatusState {
    count: u64,
    sum: u64,
    elapsed_count: u64,
    min: Option<u64>,
    max: Option<u64>,
    interval_values: ObservationWindow,
    window_values: ObservationWindow,
}

impl StatusState {
    fn new(window: BackendWindowConfig) -> Self {
        Self {
            count: 0,
            sum: 0,
            elapsed_count: 0,
            min: None,
            max: None,
            interval_values: ObservationWindow::new(window),
            window_values: ObservationWindow::new(window),
        }
    }

    fn add(&mut self, count: u64, elapsed: Option<u64>, now: i64) -> Result<(), BackendError> {
        self.count = self
            .count
            .checked_add(count)
            .ok_or(BackendError::Overflow)?;
        if count > 0
            && let Some(value) = elapsed
        {
            self.elapsed_count = self
                .elapsed_count
                .checked_add(count)
                .ok_or(BackendError::Overflow)?;
            let per_sample = if count > 1 { value / count } else { value };
            self.sum = self
                .sum
                .checked_add(
                    per_sample
                        .checked_mul(count)
                        .ok_or(BackendError::Overflow)?,
                )
                .ok_or(BackendError::Overflow)?;
            self.min = Some(self.min.map_or(per_sample, |old| old.min(per_sample)));
            self.max = Some(self.max.map_or(per_sample, |old| old.max(per_sample)));
            let repeats = usize::try_from(count).map_err(|_| BackendError::Overflow)?;
            let repeats = repeats.min(self.window_values.config.max_samples);
            for _ in 0..repeats {
                self.interval_values.add(now, per_sample);
                self.window_values.add(now, per_sample);
            }
        }
        Ok(())
    }

    fn snapshot(&self, now: i64, percentiles: &[BackendPercentile]) -> BackendStatusSnapshot {
        let values = self.window_values.values(now);
        let mut sorted = values;
        sorted.sort_unstable();
        let percentile_values = percentiles
            .iter()
            .filter_map(|percentile| {
                percentile_rank(&sorted, *percentile).map(|value| (*percentile, value))
            })
            .collect();
        BackendStatusSnapshot {
            count: self.count,
            min_millis: self.min,
            max_millis: self.max,
            average_millis: if self.sum == 0 && self.min.is_none() {
                None
            } else {
                Some(self.sum as f64 / self.elapsed_count as f64)
            },
            percentiles: percentile_values,
        }
    }

    fn reset_interval(&mut self) {
        self.count = 0;
        self.sum = 0;
        self.elapsed_count = 0;
        self.min = None;
        self.max = None;
        self.interval_values.values.clear();
    }
}

fn percentile_rank(values: &[u64], percentile: BackendPercentile) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let count = values.len() as f64;
    let rank = (count * percentile.as_percent() / 100.0).round() as usize;
    let index = rank.saturating_sub(1).min(values.len() - 1);
    Some(values[index] as f64)
}

#[derive(Clone)]
struct ContextState {
    ok: StatusState,
    ko: StatusState,
    all: StatusState,
    hit_count: u64,
    sent_bytes: u64,
    received_bytes: u64,
    error_count: u64,
}

impl ContextState {
    fn new(window: BackendWindowConfig) -> Self {
        Self {
            ok: StatusState::new(window),
            ko: StatusState::new(window),
            all: StatusState::new(window),
            hit_count: 0,
            sent_bytes: 0,
            received_bytes: 0,
            error_count: 0,
        }
    }

    fn add(&mut self, result: &SampleResult, now: i64) -> Result<(), BackendError> {
        let counts =
            represented_counts(result, CountMode::Weighted).map_err(|_| BackendError::Protocol)?;
        let count = counts.samples;
        if count == 0 {
            return Err(BackendError::Protocol);
        }
        let errors = counts.errors;
        if result.elapsed().is_some() && count > 1 && errors > 0 && errors < count {
            return Err(BackendError::Unsupported {
                capability: "backend.weighted_partial_status_timing".to_owned(),
            });
        }
        let successes = count.checked_sub(errors).ok_or(BackendError::Overflow)?;
        let elapsed = result.elapsed().map(|value| value.as_millis());
        self.ok.add(successes, elapsed, now)?;
        self.ko.add(errors, elapsed, now)?;
        self.all.add(count, elapsed, now)?;
        self.hit_count = self
            .hit_count
            .checked_add(hit_count(result)?)
            .ok_or(BackendError::Overflow)?;
        self.sent_bytes = self
            .sent_bytes
            .checked_add(result.sent_bytes().map_or(0, |value| value.as_u64()))
            .ok_or(BackendError::Overflow)?;
        self.received_bytes = self
            .received_bytes
            .checked_add(result.received_bytes().map_or(0, |value| value.as_u64()))
            .ok_or(BackendError::Overflow)?;
        self.error_count = self
            .error_count
            .checked_add(errors)
            .ok_or(BackendError::Overflow)?;
        Ok(())
    }

    fn snapshot(&self, now: i64, percentiles: &[BackendPercentile]) -> BackendContextSnapshot {
        BackendContextSnapshot {
            ok: self.ok.snapshot(now, percentiles),
            ko: self.ko.snapshot(now, percentiles),
            all: self.all.snapshot(now, percentiles),
            hit_count: self.hit_count,
            sent_bytes: self.sent_bytes,
            received_bytes: self.received_bytes,
            error_count: self.error_count,
        }
    }

    fn reset_interval(&mut self) {
        self.ok.reset_interval();
        self.ko.reset_interval();
        self.all.reset_interval();
        self.hit_count = 0;
        self.sent_bytes = 0;
        self.received_bytes = 0;
        self.error_count = 0;
    }
}

fn hit_count(result: &SampleResult) -> Result<u64, BackendError> {
    let mut count = result.sample_count().map_or(1, |value| value.as_u64());
    for child in result.sub_results() {
        count = count
            .checked_add(hit_count(child)?)
            .ok_or(BackendError::Overflow)?;
    }
    Ok(count)
}

#[derive(Clone, Default)]
struct ActiveThreadState {
    values: Vec<u64>,
    started: u64,
    ended: u64,
}

impl ActiveThreadState {
    fn add(&mut self, value: u64) -> Result<(), BackendError> {
        if self.values.len() >= DEFAULT_BACKEND_WINDOW_SAMPLES {
            self.values.remove(0);
        }
        self.values.push(value);
        Ok(())
    }

    fn snapshot(&self) -> ActiveThreadSnapshot {
        let min = self.values.iter().copied().min();
        let max = self.values.iter().copied().max();
        let mean = if self.values.is_empty() {
            None
        } else {
            Some(
                self.values.iter().map(|value| *value as f64).sum::<f64>()
                    / self.values.len() as f64,
            )
        };
        ActiveThreadSnapshot {
            min,
            max,
            mean,
            started: self.started,
            ended: self.ended,
        }
    }
}

#[derive(Clone)]
struct MetricState {
    window: BackendWindowConfig,
    contexts: BTreeMap<String, ContextState>,
    errors: Vec<BackendErrorSnapshot>,
    active: ActiveThreadState,
    annotations: Vec<BackendAnnotation>,
}

impl MetricState {
    fn new(window: BackendWindowConfig) -> Self {
        Self {
            window,
            contexts: BTreeMap::new(),
            errors: Vec::new(),
            active: ActiveThreadState::default(),
            annotations: Vec::new(),
        }
    }

    fn record(
        &mut self,
        event: &SampleEvent,
        now: i64,
        selection: Selection<'_>,
        _window: BackendWindowConfig,
    ) -> Result<(), BackendError> {
        let label = event.result().label().to_owned();
        let include_detail = !selection.summary_only && selection.filter.matches(&label)?;
        let mut labels = Vec::new();
        labels.push("all".to_owned());
        if include_detail && label != "all" {
            labels.push(label.clone());
        }
        for context in labels {
            if !self.contexts.contains_key(&context)
                && self.contexts.len() >= DEFAULT_BACKEND_MAX_CONTEXTS
            {
                return Err(BackendError::LimitExceeded {
                    resource: BackendResource::MetricContexts,
                    actual: self.contexts.len() + 1,
                    maximum: DEFAULT_BACKEND_MAX_CONTEXTS,
                });
            }
            let entry = self
                .contexts
                .entry(context)
                .or_insert_with(|| ContextState::new(self.window));
            entry.add(event.result(), now)?;
        }
        let result = event.result();
        let count = represented_counts(result, CountMode::Weighted)
            .map_err(|_| BackendError::Protocol)?
            .errors;
        if count > 0 {
            let response_code = result
                .response_code()
                .filter(|value| !value.is_empty())
                .unwrap_or("0")
                .to_owned();
            let response_message = result
                .response_message()
                .filter(|value| !value.is_empty())
                .unwrap_or("none")
                .to_owned();
            if let Some(existing) = self.errors.iter_mut().find(|value| {
                value.transaction == label
                    && value.response_code == response_code
                    && value.response_message == response_message
            }) {
                existing.count = existing
                    .count
                    .checked_add(count)
                    .ok_or(BackendError::Overflow)?;
            } else {
                if self.errors.len() >= 4_096 {
                    return Err(BackendError::LimitExceeded {
                        resource: BackendResource::ErrorKeys,
                        actual: self.errors.len() + 1,
                        maximum: 4_096,
                    });
                }
                self.errors.push(BackendErrorSnapshot {
                    transaction: label,
                    response_code,
                    response_message,
                    count,
                });
            }
        }
        Ok(())
    }

    fn snapshot(
        &self,
        now: i64,
        percentiles: &[BackendPercentile],
    ) -> Result<BackendMetricsSnapshot, BackendError> {
        Ok(BackendMetricsSnapshot {
            contexts: self
                .contexts
                .iter()
                .map(|(key, value)| (key.clone(), value.snapshot(now, percentiles)))
                .collect(),
            active_threads: self.active.snapshot(),
            errors: self.errors.clone(),
            annotations: self.annotations.clone(),
        })
    }

    fn reset_interval(&mut self) {
        for context in self.contexts.values_mut() {
            context.reset_interval();
        }
        self.errors.clear();
        self.active.values.clear();
        self.active.started = 0;
        self.active.ended = 0;
        self.annotations.clear();
    }

    fn has_pending(&self) -> bool {
        self.contexts.values().any(|context| {
            context.all.count > 0
                || context.ko.count > 0
                || context.ok.count > 0
                || context.hit_count > 0
                || context.sent_bytes > 0
                || context.received_bytes > 0
                || context.error_count > 0
        }) || !self.errors.is_empty()
            || !self.annotations.is_empty()
            || !self.active.values.is_empty()
            || self.active.started > 0
            || self.active.ended > 0
    }
}

// A deliberately bounded regular-expression subset.  It covers the patterns
// used by the REPORT-003 fixture (literals, groups, alternation, `.`, anchors,
// and `*+?`) without adding a third-party regex dependency to the pure crate.
/// A compiled bounded sampler-filter expression.
#[derive(Clone, Debug, PartialEq)]
pub struct CompiledPattern {
    root: PatternNode,
}

#[derive(Clone, Debug, PartialEq)]
enum PatternNode {
    Sequence(Vec<PatternNode>),
    Alternation(Vec<PatternNode>),
    Literal(char),
    Any,
    Start,
    End,
    Repeat(Box<PatternNode>, RepeatKind),
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum RepeatKind {
    ZeroOrMore,
    OneOrMore,
    ZeroOrOne,
}

impl CompiledPattern {
    /// Compiles the bounded subset.
    pub fn compile(pattern: String) -> Result<Self, BackendError> {
        validate_filter_text(&pattern)?;
        let chars = pattern.chars().collect::<Vec<_>>();
        let mut parser = PatternParser {
            chars: &chars,
            index: 0,
        };
        let root = parser.expression(false)?;
        if parser.index != chars.len() {
            return Err(BackendError::InvalidConfig {
                field: BackendConfigField::SamplerFilter,
            });
        }
        Ok(Self { root })
    }

    fn is_match(&self, value: &str, find: bool) -> Result<bool, BackendError> {
        let input = value.chars().collect::<Vec<_>>();
        let starts = if find { 0..=input.len() } else { 0..=0 };
        for start in starts {
            let mut states = 0;
            let positions = match_pattern(&self.root, &input, start, &mut states)?;
            if positions
                .iter()
                .any(|position| !find || *position <= input.len())
                && (find || positions.contains(&input.len()))
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

struct PatternParser<'a> {
    chars: &'a [char],
    index: usize,
}

impl PatternParser<'_> {
    fn expression(&mut self, in_group: bool) -> Result<PatternNode, BackendError> {
        let mut alternatives = Vec::new();
        alternatives.push(self.sequence(in_group)?);
        while self.peek() == Some('|') {
            self.index += 1;
            alternatives.push(self.sequence(in_group)?);
        }
        Ok(if alternatives.len() == 1 {
            alternatives.remove(0)
        } else {
            PatternNode::Alternation(alternatives)
        })
    }

    fn sequence(&mut self, in_group: bool) -> Result<PatternNode, BackendError> {
        let mut nodes = Vec::new();
        while let Some(value) = self.peek() {
            if value == '|' || (in_group && value == ')') {
                break;
            }
            let mut node = match value {
                '(' => {
                    self.index += 1;
                    let nested = self.expression(true)?;
                    if self.peek() != Some(')') {
                        return Err(BackendError::InvalidConfig {
                            field: BackendConfigField::SamplerFilter,
                        });
                    }
                    self.index += 1;
                    nested
                }
                ')' | '*' | '+' | '?' => {
                    return Err(BackendError::InvalidConfig {
                        field: BackendConfigField::SamplerFilter,
                    });
                }
                '.' => {
                    self.index += 1;
                    PatternNode::Any
                }
                '^' => {
                    self.index += 1;
                    PatternNode::Start
                }
                '$' => {
                    self.index += 1;
                    PatternNode::End
                }
                '\\' => {
                    self.index += 1;
                    let Some(literal) = self.take() else {
                        return Err(BackendError::InvalidConfig {
                            field: BackendConfigField::SamplerFilter,
                        });
                    };
                    PatternNode::Literal(literal)
                }
                '[' => {
                    return Err(BackendError::Unsupported {
                        capability: "backend.regex.character_class".to_owned(),
                    });
                }
                literal => {
                    self.index += 1;
                    PatternNode::Literal(literal)
                }
            };
            if let Some(quantifier) = self.peek() {
                let kind = match quantifier {
                    '*' => Some(RepeatKind::ZeroOrMore),
                    '+' => Some(RepeatKind::OneOrMore),
                    '?' => Some(RepeatKind::ZeroOrOne),
                    _ => None,
                };
                if let Some(kind) = kind {
                    self.index += 1;
                    node = PatternNode::Repeat(Box::new(node), kind);
                }
            }
            nodes.push(node);
        }
        Ok(PatternNode::Sequence(nodes))
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.index).copied()
    }

    fn take(&mut self) -> Option<char> {
        let value = self.peek()?;
        self.index += 1;
        Some(value)
    }
}

fn match_pattern(
    node: &PatternNode,
    input: &[char],
    position: usize,
    states: &mut usize,
) -> Result<Vec<usize>, BackendError> {
    *states = states.saturating_add(1);
    if *states > MAX_REGEX_STATES {
        return Err(BackendError::LimitExceeded {
            resource: BackendResource::RegexStates,
            actual: *states,
            maximum: MAX_REGEX_STATES,
        });
    }
    match node {
        PatternNode::Sequence(nodes) => {
            let mut positions = vec![position];
            for child in nodes {
                let mut next = Vec::new();
                for current in positions {
                    next.extend(match_pattern(child, input, current, states)?);
                }
                positions = next;
                if positions.is_empty() {
                    break;
                }
            }
            Ok(positions)
        }
        PatternNode::Alternation(nodes) => {
            let mut positions = Vec::new();
            for child in nodes {
                positions.extend(match_pattern(child, input, position, states)?);
            }
            positions.sort_unstable();
            positions.dedup();
            Ok(positions)
        }
        PatternNode::Literal(value) => Ok(input
            .get(position)
            .filter(|candidate| *candidate == value)
            .map_or_else(Vec::new, |_| vec![position + 1])),
        PatternNode::Any => Ok(input
            .get(position)
            .map_or_else(Vec::new, |_| vec![position + 1])),
        PatternNode::Start => Ok((position == 0).then_some(position).into_iter().collect()),
        PatternNode::End => Ok((position == input.len())
            .then_some(position)
            .into_iter()
            .collect()),
        PatternNode::Repeat(child, kind) => {
            let minimum = match kind {
                RepeatKind::ZeroOrMore | RepeatKind::ZeroOrOne => 0,
                RepeatKind::OneOrMore => 1,
            };
            let maximum = if *kind == RepeatKind::ZeroOrOne {
                Some(1)
            } else {
                None
            };
            let mut output = Vec::new();
            let mut context = RepeatContext {
                child,
                input,
                minimum,
                maximum,
                states,
                output: &mut output,
            };
            context.walk(position, 0)?;
            output.sort_unstable();
            output.dedup();
            Ok(output)
        }
    }
}

struct RepeatContext<'a> {
    child: &'a PatternNode,
    input: &'a [char],
    minimum: usize,
    maximum: Option<usize>,
    states: &'a mut usize,
    output: &'a mut Vec<usize>,
}

impl RepeatContext<'_> {
    fn walk(&mut self, position: usize, count: usize) -> Result<(), BackendError> {
        if count >= self.minimum {
            self.output.push(position);
        }
        if self.maximum.is_some_and(|limit| count >= limit) {
            return Ok(());
        }
        let next_positions = match_pattern(self.child, self.input, position, self.states)?;
        for next in next_positions {
            if next == position {
                continue;
            }
            self.walk(next, count + 1)?;
        }
        Ok(())
    }
}
