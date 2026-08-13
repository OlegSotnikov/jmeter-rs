// SPDX-License-Identifier: Apache-2.0
//! Explicit time, resource, and algorithm configuration for reports.

use core::cmp::Ordering;
use core::hash::{Hash, Hasher};

use jmeter_rs_results::WallTimestamp;

use crate::error::{ConfigField, ReportError, ReportLimit};

const DEFAULT_REPORT_PERCENTILES: [u8; 3] = [90, 95, 99];
const DEFAULT_MAX_LABEL_BYTES: usize = 16 * 1024;
const DEFAULT_MAX_ERROR_KEY_BYTES: usize = 16 * 1024;
/// Default bound for one caller-supplied graph/result input slice.
///
/// Streaming report ingestion does not materialize the complete stream, but
/// graph projection APIs accept slices for convenience. Keep those APIs
/// bounded as well so a caller cannot turn a pure-core helper into an
/// unbounded allocation by passing an arbitrarily large collection.
pub(crate) const DEFAULT_MAX_INPUT_SAMPLES: usize = 100_000;

pub(crate) fn validate_input_sample_count(
    actual: usize,
    maximum: usize,
) -> Result<(), ReportError> {
    if actual > maximum {
        return Err(ReportError::LimitExceeded {
            resource: ReportLimit::InputSamples,
            actual,
            maximum,
        });
    }
    Ok(())
}
const DEFAULT_REPORT_PERCENTILE_LEVELS: [PercentileLevel; 3] = [
    PercentileLevel::from_basis_points(9_000),
    PercentileLevel::from_basis_points(9_500),
    PercentileLevel::from_basis_points(9_900),
];

fn validate_percentiles(percentiles: [u8; 3]) -> Result<(), ReportError> {
    if percentiles.iter().all(|value| *value <= 100) {
        Ok(())
    } else {
        Err(ReportError::InvalidConfig {
            field: ConfigField::Percentiles,
        })
    }
}

/// A finite percentile percentage retained without decimal truncation.
///
/// JMeter's report properties are commonly integer percentages, but the
/// dashboard API accepts decimal levels as well.  Bit-stable storage keeps
/// configuration equality and merge compatibility deterministic without
/// relying on approximate comparisons.
#[derive(Clone, Copy, Debug)]
pub struct PercentileLevel(f64);

impl PercentileLevel {
    /// Creates a level from hundredths of a percent (`0..=10_000`).
    pub(crate) const fn from_basis_points(value: u16) -> Self {
        Self(value as f64 / 100.0)
    }

    /// Creates a level from any finite percentage in the inclusive range.
    pub fn from_percent(value: f64) -> Result<Self, ReportError> {
        if !value.is_finite() || !(0.0..=100.0).contains(&value) {
            return Err(ReportError::InvalidConfig {
                field: ConfigField::PercentileLevels,
            });
        }
        Ok(Self(if value == 0.0 { 0.0 } else { value }))
    }

    /// Returns the retained percentage value.
    pub fn as_percent(self) -> f64 {
        self.0
    }

    /// Returns hundredths of a percent.
    pub const fn basis_points(self) -> u16 {
        (self.0 * 100.0).round() as u16
    }
}

impl PartialEq for PercentileLevel {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bits() == other.0.to_bits()
    }
}

impl Eq for PercentileLevel {}

impl Hash for PercentileLevel {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_bits().hash(state);
    }
}

impl PartialOrd for PercentileLevel {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PercentileLevel {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.total_cmp(&other.0)
    }
}

/// Accepted decimal or integer percentile configuration input.
pub trait PercentileConfiguration {
    /// Converts the input into compatibility integer levels and exact levels.
    fn into_parts(self) -> Result<([u8; 3], [PercentileLevel; 3]), ReportError>;
}

impl PercentileConfiguration for [u8; 3] {
    fn into_parts(self) -> Result<([u8; 3], [PercentileLevel; 3]), ReportError> {
        validate_percentiles(self)?;
        Ok((
            self,
            [
                PercentileLevel::from_basis_points(u16::from(self[0]) * 100),
                PercentileLevel::from_basis_points(u16::from(self[1]) * 100),
                PercentileLevel::from_basis_points(u16::from(self[2]) * 100),
            ],
        ))
    }
}

impl PercentileConfiguration for [f64; 3] {
    fn into_parts(self) -> Result<([u8; 3], [PercentileLevel; 3]), ReportError> {
        let levels = [
            PercentileLevel::from_percent(self[0])?,
            PercentileLevel::from_percent(self[1])?,
            PercentileLevel::from_percent(self[2])?,
        ];
        Ok((
            [
                self[0].round() as u8,
                self[1].round() as u8,
                self[2].round() as u8,
            ],
            levels,
        ))
    }
}

/// Estimator used by dashboard percentile queries.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum DashboardPercentileEstimator {
    /// Apache Commons Math's legacy `p * (n + 1)` interpolation.
    #[default]
    Legacy,
    /// R-3 / nearest-rank-compatible rounded `n * p` selection.
    R3,
}

/// Whether event labels are kept raw or qualified with their thread group.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum LabelGrouping {
    /// Use the sampler label exactly as serialized.
    #[default]
    Raw,
    /// Prefix a label with the event thread-group name when present.
    ThreadGroup,
}

/// A non-empty, explicit wall-clock interval used by rate metrics.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ReportInterval {
    start: WallTimestamp,
    end: WallTimestamp,
    duration_millis: u64,
}

impl ReportInterval {
    /// Creates an interval from explicit Unix epoch millisecond timestamps.
    ///
    /// A zero-length interval is rejected because no finite throughput can be
    /// defined for it.  This also prevents an accidental report from using a
    /// process or wall-clock duration as an implicit denominator.
    pub fn new(start: WallTimestamp, end: WallTimestamp) -> Result<Self, ReportError> {
        let duration_millis =
            start
                .checked_span_to(end)
                .map_err(|_| ReportError::InvalidInterval {
                    start: start.as_millis(),
                    end: end.as_millis(),
                })?;
        if duration_millis == 0 {
            return Err(ReportError::InvalidInterval {
                start: start.as_millis(),
                end: end.as_millis(),
            });
        }
        Ok(Self {
            start,
            end,
            duration_millis,
        })
    }

    /// Creates an interval from explicit epoch milliseconds.
    pub fn from_millis(start: i64, end: i64) -> Result<Self, ReportError> {
        Self::new(
            WallTimestamp::from_millis(start),
            WallTimestamp::from_millis(end),
        )
    }

    /// Returns the inclusive interval start marker.
    pub const fn start(self) -> WallTimestamp {
        self.start
    }

    /// Returns the interval end marker.
    pub const fn end(self) -> WallTimestamp {
        self.end
    }

    /// Returns the positive interval duration in milliseconds.
    pub const fn duration_millis(self) -> u64 {
        self.duration_millis
    }

    /// Returns the interval duration in seconds.
    pub fn duration_seconds(self) -> f64 {
        self.duration_millis as f64 / 1_000.0
    }
}

/// Resource bounds applied independently to each total or label summary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AggregateLimits {
    pub(crate) max_labels: usize,
    pub(crate) max_error_keys: usize,
    pub(crate) max_percentile_samples: usize,
    pub(crate) max_input_samples: usize,
    pub(crate) max_label_bytes: usize,
    pub(crate) max_error_key_bytes: usize,
}

impl AggregateLimits {
    /// Creates finite non-zero aggregate bounds.
    pub fn new(
        max_labels: usize,
        max_error_keys: usize,
        max_percentile_samples: usize,
    ) -> Result<Self, ReportError> {
        if max_labels == 0 {
            return Err(ReportError::InvalidConfig {
                field: ConfigField::MaxLabels,
            });
        }
        if max_error_keys == 0 {
            return Err(ReportError::InvalidConfig {
                field: ConfigField::MaxErrorKeys,
            });
        }
        if max_percentile_samples == 0 {
            return Err(ReportError::InvalidConfig {
                field: ConfigField::MaxPercentileSamples,
            });
        }
        Ok(Self {
            max_labels,
            max_error_keys,
            max_percentile_samples,
            max_input_samples: DEFAULT_MAX_INPUT_SAMPLES,
            max_label_bytes: DEFAULT_MAX_LABEL_BYTES,
            max_error_key_bytes: DEFAULT_MAX_ERROR_KEY_BYTES,
        })
    }

    /// Replaces the maximum number of rows accepted by a slice-based report
    /// projection. The configured value cannot exceed the crate-wide slice
    /// bound used by the standalone graph aggregators. Streaming `add_result`
    /// APIs remain bounded by their aggregate maps and percentile/window
    /// limits.
    pub fn with_max_input_samples(mut self, maximum: usize) -> Result<Self, ReportError> {
        if maximum == 0 || maximum > DEFAULT_MAX_INPUT_SAMPLES {
            return Err(ReportError::InvalidConfig {
                field: ConfigField::MaxInputSamples,
            });
        }
        self.max_input_samples = maximum;
        Ok(self)
    }

    /// Replaces the maximum UTF-8 byte lengths retained for labels and error
    /// keys. Values are checked before insertion into an aggregate map and
    /// cannot exceed the crate-wide bounds used by standalone graph APIs.
    pub fn with_string_limits(
        mut self,
        max_label_bytes: usize,
        max_error_key_bytes: usize,
    ) -> Result<Self, ReportError> {
        if max_label_bytes == 0 || max_label_bytes > DEFAULT_MAX_LABEL_BYTES {
            return Err(ReportError::InvalidConfig {
                field: ConfigField::MaxLabelBytes,
            });
        }
        if max_error_key_bytes == 0 || max_error_key_bytes > DEFAULT_MAX_ERROR_KEY_BYTES {
            return Err(ReportError::InvalidConfig {
                field: ConfigField::MaxErrorKeyBytes,
            });
        }
        self.max_label_bytes = max_label_bytes;
        self.max_error_key_bytes = max_error_key_bytes;
        Ok(self)
    }

    /// Returns the maximum number of distinct labels (not counting total).
    pub const fn max_labels(self) -> usize {
        self.max_labels
    }

    /// Returns the maximum number of distinct error keys in one summary.
    pub const fn max_error_keys(self) -> usize {
        self.max_error_keys
    }

    /// Returns the maximum number of retained exact percentile observations.
    pub const fn max_percentile_samples(self) -> usize {
        self.max_percentile_samples
    }

    /// Returns the maximum number of rows accepted by a slice-based report
    /// projection.
    pub const fn max_input_samples(self) -> usize {
        self.max_input_samples
    }

    /// Returns the maximum UTF-8 bytes in one sample label.
    pub const fn max_label_bytes(self) -> usize {
        self.max_label_bytes
    }

    /// Returns the maximum UTF-8 bytes in one response-code/message key.
    pub const fn max_error_key_bytes(self) -> usize {
        self.max_error_key_bytes
    }
}

impl Default for AggregateLimits {
    fn default() -> Self {
        // The listener's exact percentile store is deliberately bounded.  A
        // dashboard can opt into its smaller statistical window separately.
        Self {
            max_labels: 4_096,
            max_error_keys: 4_096,
            max_percentile_samples: 100_000,
            max_input_samples: DEFAULT_MAX_INPUT_SAMPLES,
            max_label_bytes: DEFAULT_MAX_LABEL_BYTES,
            max_error_key_bytes: DEFAULT_MAX_ERROR_KEY_BYTES,
        }
    }
}

/// APDEX satisfied and tolerated thresholds in milliseconds.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ApdexThresholds {
    pub(crate) satisfied_millis: u64,
    pub(crate) tolerated_millis: u64,
}

impl ApdexThresholds {
    /// Creates thresholds, requiring satisfied to be no greater than
    /// tolerated.
    pub fn new(satisfied_millis: u64, tolerated_millis: u64) -> Result<Self, ReportError> {
        if satisfied_millis > tolerated_millis {
            return Err(ReportError::InvalidConfig {
                field: ConfigField::ApdexThresholds,
            });
        }
        Ok(Self {
            satisfied_millis,
            tolerated_millis,
        })
    }

    /// Returns the satisfied threshold.
    pub const fn satisfied_millis(self) -> u64 {
        self.satisfied_millis
    }

    /// Returns the tolerated threshold.
    pub const fn tolerated_millis(self) -> u64 {
        self.tolerated_millis
    }
}

impl Default for ApdexThresholds {
    fn default() -> Self {
        Self {
            satisfied_millis: 500,
            tolerated_millis: 1_500,
        }
    }
}

/// Configuration for the listener Aggregate/Summary family.
///
/// Listener percentiles use every retained observation and JMeter's weighted
/// `Math.round` rank.  This configuration is intentionally a separate type from
/// [`DashboardConfig`], whose bounded window and interpolation rule are
/// different algorithms.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ListenerConfig {
    interval: ReportInterval,
    limits: AggregateLimits,
    apdex: ApdexThresholds,
    top_error_limit: usize,
    percentiles: [u8; 3],
    percentile_levels: [PercentileLevel; 3],
    label_grouping: LabelGrouping,
}

impl ListenerConfig {
    /// Creates listener configuration with documented JMeter-like defaults.
    pub const fn new(interval: ReportInterval) -> Self {
        Self {
            interval,
            limits: AggregateLimits {
                max_labels: 4_096,
                max_error_keys: 4_096,
                max_percentile_samples: 100_000,
                max_input_samples: DEFAULT_MAX_INPUT_SAMPLES,
                max_label_bytes: DEFAULT_MAX_LABEL_BYTES,
                max_error_key_bytes: DEFAULT_MAX_ERROR_KEY_BYTES,
            },
            apdex: ApdexThresholds {
                satisfied_millis: 500,
                tolerated_millis: 1_500,
            },
            top_error_limit: 5,
            percentiles: DEFAULT_REPORT_PERCENTILES,
            percentile_levels: DEFAULT_REPORT_PERCENTILE_LEVELS,
            label_grouping: LabelGrouping::Raw,
        }
    }

    /// Replaces resource bounds.
    pub const fn with_limits(mut self, limits: AggregateLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Replaces APDEX thresholds.
    pub const fn with_apdex(mut self, apdex: ApdexThresholds) -> Self {
        self.apdex = apdex;
        self
    }

    /// Sets the number of error keys emitted by the top-errors view.
    pub fn with_top_error_limit(mut self, limit: usize) -> Result<Self, ReportError> {
        if limit > self.limits.max_error_keys() {
            return Err(ReportError::InvalidConfig {
                field: ConfigField::TopErrorLimit,
            });
        }
        self.top_error_limit = limit;
        Ok(self)
    }

    /// Sets the three configured Aggregate/Summary percentile levels.
    ///
    /// The default is JMeter's 90th, 95th, and 99th percentiles.  The values
    /// are percentages in the inclusive `0..=100` range.
    pub fn with_percentiles<P: PercentileConfiguration>(
        mut self,
        percentiles: P,
    ) -> Result<Self, ReportError> {
        let (integer_levels, exact_levels) = percentiles.into_parts()?;
        self.percentiles = integer_levels;
        self.percentile_levels = exact_levels;
        Ok(self)
    }

    /// Sets decimal Aggregate/Summary percentile levels.
    pub fn with_decimal_percentiles(self, percentiles: [f64; 3]) -> Result<Self, ReportError> {
        self.with_percentiles(percentiles)
    }

    /// Sets event-label grouping for event-based ingestion.
    pub const fn with_label_grouping(mut self, grouping: LabelGrouping) -> Self {
        self.label_grouping = grouping;
        self
    }

    /// Returns the explicit interval.
    pub const fn interval(self) -> ReportInterval {
        self.interval
    }

    /// Returns resource bounds.
    pub const fn limits(self) -> AggregateLimits {
        self.limits
    }

    /// Returns APDEX thresholds.
    pub const fn apdex(self) -> ApdexThresholds {
        self.apdex
    }

    /// Returns the requested top-error count.
    pub const fn top_error_limit(self) -> usize {
        self.top_error_limit
    }

    /// Returns the configured percentile levels.
    pub const fn percentiles(self) -> [u8; 3] {
        self.percentiles
    }

    /// Returns configured percentile levels without losing decimal precision.
    pub const fn percentile_levels(self) -> [PercentileLevel; 3] {
        self.percentile_levels
    }

    /// Returns configured percentile percentages, preserving decimals.
    pub fn percentile_values(self) -> [f64; 3] {
        [
            self.percentile_levels[0].as_percent(),
            self.percentile_levels[1].as_percent(),
            self.percentile_levels[2].as_percent(),
        ]
    }

    /// Returns event-label grouping policy.
    pub const fn label_grouping(self) -> LabelGrouping {
        self.label_grouping
    }
}

/// Configuration for dashboard data metrics.
///
/// Dashboard percentile queries use a deterministic FIFO window (the newest
/// `percentile_window` observations) and the JMeter/Commons-Math legacy
/// interpolation estimator.  Means, standard deviations, counts, byte totals,
/// and APDEX still cover the full stream. Dashboard input rows are unweighted
/// even when a JTL result carries an aggregate `sample_count`; the listener
/// Aggregate mode is the weighted GUI surface. Thus dashboard percentiles are
/// deliberately not claimed equal to listener percentiles.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DashboardConfig {
    interval: ReportInterval,
    limits: AggregateLimits,
    percentile_window: usize,
    apdex: ApdexThresholds,
    top_error_limit: usize,
    percentiles: [u8; 3],
    percentile_levels: [PercentileLevel; 3],
    estimator: DashboardPercentileEstimator,
    overall_granularity_millis: u64,
    exclude_transaction_controllers_from_top5: bool,
    label_grouping: LabelGrouping,
}

impl DashboardConfig {
    /// Creates dashboard configuration with JMeter's documented 20,000
    /// observation statistical-window default.
    pub fn new(interval: ReportInterval) -> Result<Self, ReportError> {
        let limits = AggregateLimits::default();
        if limits.max_percentile_samples() < 20_000 {
            return Err(ReportError::InvalidConfig {
                field: ConfigField::MaxPercentileSamples,
            });
        }
        Ok(Self {
            interval,
            limits,
            percentile_window: 20_000,
            apdex: ApdexThresholds::default(),
            top_error_limit: 5,
            percentiles: DEFAULT_REPORT_PERCENTILES,
            percentile_levels: DEFAULT_REPORT_PERCENTILE_LEVELS,
            estimator: DashboardPercentileEstimator::Legacy,
            overall_granularity_millis: 60_000,
            exclude_transaction_controllers_from_top5: true,
            label_grouping: LabelGrouping::Raw,
        })
    }

    /// Replaces resource bounds, including the dashboard window ceiling.
    pub fn with_limits(mut self, limits: AggregateLimits) -> Result<Self, ReportError> {
        if self.percentile_window > limits.max_percentile_samples() {
            return Err(ReportError::InvalidConfig {
                field: ConfigField::MaxPercentileSamples,
            });
        }
        if self.top_error_limit > limits.max_error_keys() {
            return Err(ReportError::InvalidConfig {
                field: ConfigField::TopErrorLimit,
            });
        }
        self.limits = limits;
        Ok(self)
    }

    /// Sets the dashboard FIFO percentile window.
    pub fn with_percentile_window(mut self, window: usize) -> Result<Self, ReportError> {
        if window == 0 || window > self.limits.max_percentile_samples() {
            return Err(ReportError::InvalidConfig {
                field: ConfigField::MaxPercentileSamples,
            });
        }
        self.percentile_window = window;
        Ok(self)
    }

    /// Replaces APDEX thresholds.
    pub const fn with_apdex(mut self, apdex: ApdexThresholds) -> Self {
        self.apdex = apdex;
        self
    }

    /// Sets the number of error keys emitted by the top-errors view.
    pub fn with_top_error_limit(mut self, limit: usize) -> Result<Self, ReportError> {
        if limit > self.limits.max_error_keys() {
            return Err(ReportError::InvalidConfig {
                field: ConfigField::TopErrorLimit,
            });
        }
        self.top_error_limit = limit;
        Ok(self)
    }

    /// Sets the three configured dashboard statistics percentile levels.
    ///
    /// The default is JMeter's 90th, 95th, and 99th percentiles.  The values
    /// are percentages in the inclusive `0..=100` range.
    pub fn with_percentiles<P: PercentileConfiguration>(
        mut self,
        percentiles: P,
    ) -> Result<Self, ReportError> {
        let (integer_levels, exact_levels) = percentiles.into_parts()?;
        self.percentiles = integer_levels;
        self.percentile_levels = exact_levels;
        Ok(self)
    }

    /// Sets decimal dashboard percentile levels.
    pub fn with_decimal_percentiles(self, percentiles: [f64; 3]) -> Result<Self, ReportError> {
        self.with_percentiles(percentiles)
    }

    /// Selects the dashboard percentile estimator.
    pub const fn with_percentile_estimator(
        mut self,
        estimator: DashboardPercentileEstimator,
    ) -> Self {
        self.estimator = estimator;
        self
    }

    /// Alias for [`DashboardConfig::with_percentile_estimator`].
    pub const fn with_estimator(self, estimator: DashboardPercentileEstimator) -> Self {
        self.with_percentile_estimator(estimator)
    }

    /// Sets the dashboard time-series granularity in milliseconds. JMeter
    /// requires a value strictly greater than one second.
    pub fn with_overall_granularity_millis(
        mut self,
        granularity_millis: u64,
    ) -> Result<Self, ReportError> {
        if granularity_millis <= 1_000 {
            return Err(ReportError::InvalidConfig {
                field: ConfigField::OverallGranularity,
            });
        }
        self.overall_granularity_millis = granularity_millis;
        Ok(self)
    }

    /// Sets whether transaction-controller rows are omitted from per-label
    /// sampler top-five errors (JMeter's report-generator default). The
    /// overall Top5 consumer always omits controllers.
    pub const fn with_exclude_transaction_controllers_from_top5(mut self, exclude: bool) -> Self {
        self.exclude_transaction_controllers_from_top5 = exclude;
        self
    }

    /// Sets event-label grouping for event-based ingestion.
    pub const fn with_label_grouping(mut self, grouping: LabelGrouping) -> Self {
        self.label_grouping = grouping;
        self
    }

    /// Alias matching JMeter's `statistic_window` property terminology.
    pub fn with_statistic_window(self, window: usize) -> Result<Self, ReportError> {
        self.with_percentile_window(window)
    }

    /// Returns the explicit interval.
    pub const fn interval(self) -> ReportInterval {
        self.interval
    }

    /// Returns resource bounds.
    pub const fn limits(self) -> AggregateLimits {
        self.limits
    }

    /// Returns the FIFO percentile window size.
    pub const fn percentile_window(self) -> usize {
        self.percentile_window
    }

    /// Returns APDEX thresholds.
    pub const fn apdex(self) -> ApdexThresholds {
        self.apdex
    }

    /// Returns the requested top-error count.
    pub const fn top_error_limit(self) -> usize {
        self.top_error_limit
    }

    /// Returns the configured percentile levels.
    pub const fn percentiles(self) -> [u8; 3] {
        self.percentiles
    }

    /// Returns configured percentile levels without losing decimal precision.
    pub const fn percentile_levels(self) -> [PercentileLevel; 3] {
        self.percentile_levels
    }

    /// Returns configured percentile percentages, preserving decimals.
    pub fn percentile_values(self) -> [f64; 3] {
        [
            self.percentile_levels[0].as_percent(),
            self.percentile_levels[1].as_percent(),
            self.percentile_levels[2].as_percent(),
        ]
    }

    /// Returns the configured dashboard percentile estimator.
    pub const fn percentile_estimator(self) -> DashboardPercentileEstimator {
        self.estimator
    }

    /// Returns dashboard time-series granularity in milliseconds.
    pub const fn overall_granularity_millis(self) -> u64 {
        self.overall_granularity_millis
    }

    /// Returns the per-label transaction-controller top-five filtering policy.
    pub const fn exclude_transaction_controllers_from_top5(self) -> bool {
        self.exclude_transaction_controllers_from_top5
    }

    /// Returns event-label grouping policy.
    pub const fn label_grouping(self) -> LabelGrouping {
        self.label_grouping
    }

    /// Returns the FIFO statistical-window size under JMeter's property name.
    pub const fn statistic_window(self) -> usize {
        self.percentile_window
    }
}
