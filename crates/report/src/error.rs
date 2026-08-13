// SPDX-License-Identifier: Apache-2.0
//! Stable errors returned by report aggregation.

use core::fmt;

/// Fields whose checked arithmetic is performed by an aggregate.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReportField {
    /// Number of represented samples.
    SampleCount,
    /// Number of represented failed samples.
    ErrorCount,
    /// Number of samples with an elapsed value.
    ElapsedCount,
    /// Received-byte total.
    ReceivedBytes,
    /// Sent-byte total.
    SentBytes,
    /// Running variance accumulator.
    Variance,
    /// Interval duration used for rates.
    Interval,
    /// Number of distinct labels retained by an aggregate.
    Labels,
    /// Number of distinct error keys retained by an aggregate.
    ErrorKeys,
    /// Number of exact percentile observations retained by an aggregate.
    PercentileSamples,
    /// Wall-clock timestamp used to place a graph row in a bucket.
    Timestamp,
    /// Latency timing field used by the latency graph family.
    Latency,
    /// Connect timing field used by the connect-time graph family.
    Connect,
    /// Group-thread count used by the active-threads graph family.
    GroupThreads,
    /// All-thread count used by the active-threads graph family.
    AllThreads,
    /// Response-code field used by the response-code graph family.
    ResponseCode,
    /// Sample-label field used by the label/TPS graph family.
    Label,
}

impl fmt::Display for ReportField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::SampleCount => "sample_count",
            Self::ErrorCount => "error_count",
            Self::ElapsedCount => "elapsed_count",
            Self::ReceivedBytes => "received_bytes",
            Self::SentBytes => "sent_bytes",
            Self::Variance => "variance",
            Self::Interval => "interval",
            Self::Labels => "labels",
            Self::ErrorKeys => "error_keys",
            Self::PercentileSamples => "percentile_samples",
            Self::Timestamp => "timestamp",
            Self::Latency => "latency",
            Self::Connect => "connect",
            Self::GroupThreads => "group_threads",
            Self::AllThreads => "all_threads",
            Self::ResponseCode => "response_code",
            Self::Label => "label",
        };
        formatter.write_str(name)
    }
}

/// Bounded resources retained by a streaming aggregate.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReportLimit {
    /// Input rows supplied to a slice-based report projection.
    InputSamples,
    /// Distinct sample labels, excluding the total row.
    Labels,
    /// Distinct response-code/message pairs.
    ErrorKeys,
    /// Exact elapsed observations used for percentile queries.
    PercentileSamples,
    /// Time-series points retained by a graph aggregation.
    GraphPoints,
    /// UTF-8 bytes retained in one sample label.
    LabelBytes,
    /// UTF-8 bytes retained in one response-code/message error key.
    ErrorKeyBytes,
    /// Distinct keys retained by a graph section.
    GraphSeriesKeys,
    /// Scalar observations retained by a graph section.
    GraphSamples,
}

impl fmt::Display for ReportLimit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InputSamples => "input samples",
            Self::Labels => "labels",
            Self::ErrorKeys => "error keys",
            Self::PercentileSamples => "percentile samples",
            Self::GraphPoints => "graph points",
            Self::LabelBytes => "label bytes",
            Self::ErrorKeyBytes => "error-key bytes",
            Self::GraphSeriesKeys => "graph series keys",
            Self::GraphSamples => "graph samples",
        })
    }
}

/// Configuration values that can be rejected before aggregation begins.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ConfigField {
    /// Maximum input rows accepted by slice-based projections.
    MaxInputSamples,
    /// Maximum number of labels.
    MaxLabels,
    /// Maximum number of distinct error keys.
    MaxErrorKeys,
    /// Maximum number of retained exact percentile observations.
    MaxPercentileSamples,
    /// Maximum UTF-8 bytes in a sample label.
    MaxLabelBytes,
    /// Maximum UTF-8 bytes in one response-code/message key.
    MaxErrorKeyBytes,
    /// Maximum number of graph points requested by a graph projection.
    MaxGraphPoints,
    /// APDEX satisfied/tolerated thresholds.
    ApdexThresholds,
    /// Number of top errors requested in a report.
    TopErrorLimit,
    /// Configured percentile levels.
    Percentiles,
    /// Configured decimal percentile levels.
    PercentileLevels,
    /// Dashboard time-series bucket granularity.
    OverallGranularity,
    /// Dashboard percentile estimator.
    PercentileEstimator,
    /// Dashboard transaction-controller top-error policy.
    TransactionControllerErrors,
}

impl fmt::Display for ConfigField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::MaxInputSamples => "max_input_samples",
            Self::MaxLabels => "max_labels",
            Self::MaxErrorKeys => "max_error_keys",
            Self::MaxPercentileSamples => "max_percentile_samples",
            Self::MaxLabelBytes => "max_label_bytes",
            Self::MaxErrorKeyBytes => "max_error_key_bytes",
            Self::MaxGraphPoints => "max_graph_points",
            Self::ApdexThresholds => "apdex_thresholds",
            Self::TopErrorLimit => "top_error_limit",
            Self::Percentiles => "percentiles",
            Self::PercentileLevels => "percentile_levels",
            Self::OverallGranularity => "overall_granularity",
            Self::PercentileEstimator => "percentile_estimator",
            Self::TransactionControllerErrors => "transaction_controller_errors",
        };
        formatter.write_str(name)
    }
}

/// Sample fields that can make an aggregate input inconsistent.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SampleField {
    /// The represented sample count.
    SampleCount,
    /// The represented error count.
    ErrorCount,
}

impl fmt::Display for SampleField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SampleCount => "sample_count",
            Self::ErrorCount => "error_count",
        })
    }
}

/// Typed, stable failures from report configuration and aggregation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReportError {
    /// A configuration value is not representable by the report algorithm.
    InvalidConfig {
        /// The rejected configuration field.
        field: ConfigField,
    },
    /// The explicit interval is empty or runs backwards.
    InvalidInterval {
        /// Start epoch milliseconds.
        start: i64,
        /// End epoch milliseconds.
        end: i64,
    },
    /// A percentile is not finite or is outside the inclusive 0..=100 range.
    InvalidPercentile,
    /// A checked arithmetic operation exceeded its field representation.
    Overflow {
        /// The field that overflowed.
        field: ReportField,
    },
    /// An explicit resource bound was reached.
    LimitExceeded {
        /// The bounded resource.
        resource: ReportLimit,
        /// The attempted amount.
        actual: usize,
        /// The configured maximum.
        maximum: usize,
    },
    /// Two aggregates do not have the same algorithm/configuration.
    IncompatibleMerge,
    /// An input result contains contradictory represented counts.
    InvalidSample {
        /// The contradictory field.
        field: SampleField,
    },
    /// A metric cannot be represented by a deterministic JSON/HTML output.
    Serialization,
    /// The requested report graph requires a capability or input field that
    /// is not available.  This is deliberately distinct from an empty graph:
    /// callers must not turn an unavailable source into a false success.
    Unsupported {
        /// Stable graph capability identifier.
        capability: &'static str,
    },
    /// A graph row did not carry any usable timestamp.  Such a row cannot be
    /// assigned to a fixed bucket and is therefore never silently discarded.
    MissingTimestamp {
        /// Stable graph section identifier, or `graph` for the generic API.
        section: &'static str,
    },
}

impl ReportError {
    /// Returns a stable machine-readable error code.
    pub const fn stable_code(self) -> &'static str {
        match self {
            Self::InvalidConfig { .. } => "report.invalid_config",
            Self::InvalidInterval { .. } => "report.invalid_interval",
            Self::InvalidPercentile => "report.invalid_percentile",
            Self::Overflow { .. } => "report.overflow",
            Self::LimitExceeded { .. } => "report.limit_exceeded",
            Self::IncompatibleMerge => "report.incompatible_merge",
            Self::InvalidSample { .. } => "report.invalid_sample",
            Self::Serialization => "report.serialization",
            Self::Unsupported { .. } => "report.unsupported",
            Self::MissingTimestamp { .. } => "report.missing_timestamp",
        }
    }
}

impl fmt::Display for ReportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig { field } => write!(formatter, "{}: {field}", self.stable_code()),
            Self::InvalidInterval { start, end } => write!(
                formatter,
                "{}: start {start} must precede end {end}",
                self.stable_code()
            ),
            Self::InvalidPercentile => formatter.write_str(self.stable_code()),
            Self::Overflow { field } => write!(formatter, "{}: {field}", self.stable_code()),
            Self::LimitExceeded {
                resource,
                actual,
                maximum,
            } => write!(
                formatter,
                "{}: {resource} {actual} exceeds {maximum}",
                self.stable_code()
            ),
            Self::IncompatibleMerge => formatter.write_str(self.stable_code()),
            Self::InvalidSample { field } => write!(formatter, "{}: {field}", self.stable_code()),
            Self::Serialization => formatter.write_str(self.stable_code()),
            Self::Unsupported { capability } => {
                write!(formatter, "{}: {capability}", self.stable_code())
            }
            Self::MissingTimestamp { section } => {
                write!(formatter, "{}: {section}", self.stable_code())
            }
        }
    }
}

impl std::error::Error for ReportError {}
