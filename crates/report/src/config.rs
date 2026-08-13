// SPDX-License-Identifier: Apache-2.0
//! Explicit time, resource, and algorithm configuration for reports.

use core::cmp::Ordering;
use core::hash::{Hash, Hasher};
use std::collections::BTreeMap;

use jmeter_rs_results::WallTimestamp;

use crate::error::{ConfigField, ReportError, ReportLimit};

/// Default percentile levels used by JMeter's Aggregate/Summary listeners.
pub const DEFAULT_REPORT_PERCENTILES: [u8; 3] = [90, 95, 99];
const DEFAULT_MAX_LABEL_BYTES: usize = 16 * 1024;
const DEFAULT_MAX_ERROR_KEY_BYTES: usize = 16 * 1024;
/// Default bound for one caller-supplied graph/result input slice.
///
/// Streaming report ingestion does not materialize the complete stream, but
/// graph projection APIs accept slices for convenience. Keep those APIs
/// bounded as well so a caller cannot turn a pure-core helper into an
/// unbounded allocation by passing an arbitrarily large collection.
pub(crate) const DEFAULT_MAX_INPUT_SAMPLES: usize = 100_000;

/// Default `jmeter.reportgenerator.overall_granularity` value, in
/// milliseconds.
pub const DEFAULT_REPORT_OVERALL_GRANULARITY_MILLIS: u64 = 60_000;
/// Default `jmeter.reportgenerator.statistic_window` size.
pub const DEFAULT_REPORT_STATISTIC_WINDOW: usize = 20_000;
/// Default response-time distribution bucket width, in milliseconds.
pub const DEFAULT_RESPONSE_TIME_DISTRIBUTION_GRANULARITY_MILLIS: u64 = 100;
/// The report generator rejects overall buckets at or below one second.
pub const MIN_REPORT_OVERALL_GRANULARITY_MILLIS: u64 = 1_001;
/// Maximum retained report-generator property key/value bytes.  Property
/// loading is pure, but it must remain bounded when fed untrusted input.
pub const MAX_REPORT_PROPERTY_BYTES: usize = 64 * 1024;
/// Maximum unknown report-generator properties retained by one projection.
pub const MAX_REPORT_PROPERTIES: usize = 256;

/// Exact JMeter property names consumed by report configuration.
pub const AGGREGATE_RPT_PCT1: &str = "aggregate_rpt_pct1";
/// Exact JMeter property name for the second Aggregate/Summary percentile.
pub const AGGREGATE_RPT_PCT2: &str = "aggregate_rpt_pct2";
/// Exact JMeter property name for the third Aggregate/Summary percentile.
pub const AGGREGATE_RPT_PCT3: &str = "aggregate_rpt_pct3";
/// Exact JMeter report-generator APDEX satisfied-threshold property.
pub const REPORTGENERATOR_APDEX_SATISFIED_THRESHOLD: &str =
    "jmeter.reportgenerator.apdex_satisfied_threshold";
/// Exact JMeter report-generator APDEX tolerated-threshold property.
pub const REPORTGENERATOR_APDEX_TOLERATED_THRESHOLD: &str =
    "jmeter.reportgenerator.apdex_tolerated_threshold";
/// Exact JMeter report-generator overall-granularity property.
pub const REPORTGENERATOR_OVERALL_GRANULARITY: &str = "jmeter.reportgenerator.overall_granularity";
/// Exact JMeter report-generator statistical-window property.
pub const REPORTGENERATOR_STATISTIC_WINDOW: &str = "jmeter.reportgenerator.statistic_window";
/// Exact JMeter report-generator transaction-controller filtering property.
pub const REPORTGENERATOR_EXCLUDE_TC_FROM_TOP5_ERRORS_BY_SAMPLER: &str =
    "jmeter.reportgenerator.exclude_tc_from_top5_errors_by_sampler";
/// Exact JMeter response-time distribution granularity property.
pub const REPORTGENERATOR_RESPONSE_TIME_DISTRIBUTION_GRANULARITY: &str =
    "jmeter.reportgenerator.graph.responseTimeDistribution.property.set_granularity";
/// Exact JMeter report-generator sample-filter property.
pub const REPORTGENERATOR_SAMPLE_FILTER: &str = "jmeter.reportgenerator.sample_filter";
/// Exact JMeter report title property.
pub const REPORTGENERATOR_REPORT_TITLE: &str = "jmeter.reportgenerator.report_title";
/// Exact JMeter report date-format property.
pub const REPORTGENERATOR_DATE_FORMAT: &str = "jmeter.reportgenerator.date_format";
/// Exact JMeter report range-start property.
pub const REPORTGENERATOR_START_DATE: &str = "jmeter.reportgenerator.start_date";
/// Exact JMeter report range-end property.
pub const REPORTGENERATOR_END_DATE: &str = "jmeter.reportgenerator.end_date";

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

/// Known report configuration properties and their exact JMeter spellings.
///
/// Keeping this mapping in the pure report crate prevents Rust-facing field
/// names from becoming an accidental wire contract.  Unknown properties are
/// retained by [`ReportGeneratorProperties`] rather than being silently
/// discarded.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ReportProperty {
    /// Aggregate/Summary first percentile.
    AggregatePercentile1,
    /// Aggregate/Summary second percentile.
    AggregatePercentile2,
    /// Aggregate/Summary third percentile.
    AggregatePercentile3,
    /// Dashboard APDEX satisfied threshold.
    DashboardApdexSatisfiedThreshold,
    /// Dashboard APDEX tolerated threshold.
    DashboardApdexToleratedThreshold,
    /// Dashboard overall time-series granularity.
    DashboardOverallGranularity,
    /// Dashboard statistical-window size.
    DashboardStatisticWindow,
    /// Dashboard transaction-controller top-five filtering.
    DashboardExcludeTransactionControllersFromTop5,
    /// Response-time distribution granularity.
    ResponseTimeDistributionGranularity,
    /// Dashboard sample filter expression.
    DashboardSampleFilter,
    /// Dashboard title.
    DashboardReportTitle,
    /// Dashboard date format.
    DashboardDateFormat,
    /// Dashboard range start.
    DashboardStartDate,
    /// Dashboard range end.
    DashboardEndDate,
}

impl ReportProperty {
    /// Returns the exact upstream property spelling.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::AggregatePercentile1 => AGGREGATE_RPT_PCT1,
            Self::AggregatePercentile2 => AGGREGATE_RPT_PCT2,
            Self::AggregatePercentile3 => AGGREGATE_RPT_PCT3,
            Self::DashboardApdexSatisfiedThreshold => REPORTGENERATOR_APDEX_SATISFIED_THRESHOLD,
            Self::DashboardApdexToleratedThreshold => REPORTGENERATOR_APDEX_TOLERATED_THRESHOLD,
            Self::DashboardOverallGranularity => REPORTGENERATOR_OVERALL_GRANULARITY,
            Self::DashboardStatisticWindow => REPORTGENERATOR_STATISTIC_WINDOW,
            Self::DashboardExcludeTransactionControllersFromTop5 => {
                REPORTGENERATOR_EXCLUDE_TC_FROM_TOP5_ERRORS_BY_SAMPLER
            }
            Self::ResponseTimeDistributionGranularity => {
                REPORTGENERATOR_RESPONSE_TIME_DISTRIBUTION_GRANULARITY
            }
            Self::DashboardSampleFilter => REPORTGENERATOR_SAMPLE_FILTER,
            Self::DashboardReportTitle => REPORTGENERATOR_REPORT_TITLE,
            Self::DashboardDateFormat => REPORTGENERATOR_DATE_FORMAT,
            Self::DashboardStartDate => REPORTGENERATOR_START_DATE,
            Self::DashboardEndDate => REPORTGENERATOR_END_DATE,
        }
    }

    /// Resolves an exact upstream property spelling to a known property.
    pub fn from_wire_name(name: &str) -> Option<Self> {
        Some(match name {
            AGGREGATE_RPT_PCT1 => Self::AggregatePercentile1,
            AGGREGATE_RPT_PCT2 => Self::AggregatePercentile2,
            AGGREGATE_RPT_PCT3 => Self::AggregatePercentile3,
            REPORTGENERATOR_APDEX_SATISFIED_THRESHOLD => Self::DashboardApdexSatisfiedThreshold,
            REPORTGENERATOR_APDEX_TOLERATED_THRESHOLD => Self::DashboardApdexToleratedThreshold,
            REPORTGENERATOR_OVERALL_GRANULARITY => Self::DashboardOverallGranularity,
            REPORTGENERATOR_STATISTIC_WINDOW => Self::DashboardStatisticWindow,
            REPORTGENERATOR_EXCLUDE_TC_FROM_TOP5_ERRORS_BY_SAMPLER => {
                Self::DashboardExcludeTransactionControllersFromTop5
            }
            REPORTGENERATOR_RESPONSE_TIME_DISTRIBUTION_GRANULARITY => {
                Self::ResponseTimeDistributionGranularity
            }
            REPORTGENERATOR_SAMPLE_FILTER => Self::DashboardSampleFilter,
            REPORTGENERATOR_REPORT_TITLE => Self::DashboardReportTitle,
            REPORTGENERATOR_DATE_FORMAT => Self::DashboardDateFormat,
            REPORTGENERATOR_START_DATE => Self::DashboardStartDate,
            REPORTGENERATOR_END_DATE => Self::DashboardEndDate,
            _ => return None,
        })
    }
}

/// A presence-aware, pure projection of report-generator properties.
///
/// `Option<String>` intentionally distinguishes an absent property (`None`)
/// from an explicitly present empty value (`Some(String::new())`). Numeric and
/// boolean properties reject empty values because JMeter cannot interpret
/// them as those types. Properties outside the known report surface are
/// retained in source order-independent form so plugin/custom graph data is
/// not silently lost.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ReportGeneratorProperties {
    aggregate_percentiles: [Option<f64>; 3],
    apdex_satisfied_millis: Option<u64>,
    apdex_tolerated_millis: Option<u64>,
    overall_granularity_millis: Option<u64>,
    statistic_window: Option<usize>,
    exclude_transaction_controllers_from_top5: Option<bool>,
    response_time_distribution_granularity_millis: Option<u64>,
    sample_filter: Option<String>,
    report_title: Option<String>,
    date_format: Option<String>,
    start_date: Option<String>,
    end_date: Option<String>,
    unknown: Vec<(String, String)>,
}

impl ReportGeneratorProperties {
    /// Builds a projection from ordered JMeter properties. Repeated keys use
    /// the last value, matching Java `Properties` merge behavior.
    pub fn from_properties<I, K, V>(properties: I) -> Result<Self, ReportError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let mut projection = Self::default();
        for (key, value) in properties {
            projection.apply_property(key.as_ref(), value.as_ref())?;
        }
        Ok(projection)
    }

    /// Builds a projection from a property map.
    pub fn from_property_map(properties: &BTreeMap<String, String>) -> Result<Self, ReportError> {
        Self::from_properties(properties.iter())
    }

    /// Applies one property, retaining unknown report-generator keys.
    pub fn apply_property(&mut self, key: &str, value: &str) -> Result<(), ReportError> {
        if key.len() > MAX_REPORT_PROPERTY_BYTES || value.len() > MAX_REPORT_PROPERTY_BYTES {
            return Err(ReportError::Unsupported {
                capability: "report.property_bounds",
            });
        }
        let known = ReportProperty::from_wire_name(key);
        match known {
            Some(ReportProperty::AggregatePercentile1)
            | Some(ReportProperty::AggregatePercentile2)
            | Some(ReportProperty::AggregatePercentile3) => {
                let percentile = parse_percentile(value)?;
                let index = if key == AGGREGATE_RPT_PCT1 {
                    0
                } else if key == AGGREGATE_RPT_PCT2 {
                    1
                } else {
                    2
                };
                self.aggregate_percentiles[index] = Some(percentile);
            }
            Some(ReportProperty::DashboardApdexSatisfiedThreshold) => {
                self.apdex_satisfied_millis = Some(parse_u64(value, ConfigField::ApdexThresholds)?);
            }
            Some(ReportProperty::DashboardApdexToleratedThreshold) => {
                self.apdex_tolerated_millis = Some(parse_u64(value, ConfigField::ApdexThresholds)?);
            }
            Some(ReportProperty::DashboardOverallGranularity) => {
                self.overall_granularity_millis =
                    Some(parse_u64(value, ConfigField::OverallGranularity)?);
            }
            Some(ReportProperty::DashboardStatisticWindow) => {
                self.statistic_window =
                    Some(parse_usize(value, ConfigField::MaxPercentileSamples)?);
            }
            Some(ReportProperty::DashboardExcludeTransactionControllersFromTop5) => {
                self.exclude_transaction_controllers_from_top5 =
                    Some(parse_bool(value, ConfigField::TransactionControllerErrors)?);
            }
            Some(ReportProperty::ResponseTimeDistributionGranularity) => {
                self.response_time_distribution_granularity_millis =
                    Some(parse_u64(value, ConfigField::OverallGranularity)?);
            }
            Some(ReportProperty::DashboardSampleFilter) => {
                self.sample_filter = Some(value.to_owned());
            }
            Some(ReportProperty::DashboardReportTitle) => {
                self.report_title = Some(value.to_owned());
            }
            Some(ReportProperty::DashboardDateFormat) => {
                self.date_format = Some(value.to_owned());
            }
            Some(ReportProperty::DashboardStartDate) => {
                self.start_date = Some(value.to_owned());
            }
            Some(ReportProperty::DashboardEndDate) => {
                self.end_date = Some(value.to_owned());
            }
            None if key.starts_with("jmeter.reportgenerator.") => {
                if let Some((_, existing)) = self.unknown.iter_mut().find(|(name, _)| name == key) {
                    *existing = value.to_owned();
                } else {
                    if self.unknown.len() >= MAX_REPORT_PROPERTIES {
                        return Err(ReportError::Unsupported {
                            capability: "report.property_bounds",
                        });
                    }
                    self.unknown.push((key.to_owned(), value.to_owned()));
                }
            }
            None => {}
        }
        Ok(())
    }

    /// Returns whether the exact property was present in the input.
    pub fn contains(&self, property: ReportProperty) -> bool {
        match property {
            ReportProperty::AggregatePercentile1 => self.aggregate_percentiles[0].is_some(),
            ReportProperty::AggregatePercentile2 => self.aggregate_percentiles[1].is_some(),
            ReportProperty::AggregatePercentile3 => self.aggregate_percentiles[2].is_some(),
            ReportProperty::DashboardApdexSatisfiedThreshold => {
                self.apdex_satisfied_millis.is_some()
            }
            ReportProperty::DashboardApdexToleratedThreshold => {
                self.apdex_tolerated_millis.is_some()
            }
            ReportProperty::DashboardOverallGranularity => {
                self.overall_granularity_millis.is_some()
            }
            ReportProperty::DashboardStatisticWindow => self.statistic_window.is_some(),
            ReportProperty::DashboardExcludeTransactionControllersFromTop5 => {
                self.exclude_transaction_controllers_from_top5.is_some()
            }
            ReportProperty::ResponseTimeDistributionGranularity => {
                self.response_time_distribution_granularity_millis.is_some()
            }
            ReportProperty::DashboardSampleFilter => self.sample_filter.is_some(),
            ReportProperty::DashboardReportTitle => self.report_title.is_some(),
            ReportProperty::DashboardDateFormat => self.date_format.is_some(),
            ReportProperty::DashboardStartDate => self.start_date.is_some(),
            ReportProperty::DashboardEndDate => self.end_date.is_some(),
        }
    }

    /// Returns the configured aggregate percentile, if explicitly present.
    pub fn aggregate_percentile(&self, index: usize) -> Option<f64> {
        self.aggregate_percentiles.get(index).copied().flatten()
    }

    /// Returns explicit aggregate levels, filling absent levels with JMeter's
    /// 90/95/99 defaults.
    pub fn aggregate_percentiles(&self) -> [f64; 3] {
        [0, 1, 2].map(|index| {
            self.aggregate_percentile(index)
                .unwrap_or(f64::from(DEFAULT_REPORT_PERCENTILES[index]))
        })
    }

    /// Returns the explicit APDEX thresholds, if supplied.
    pub const fn apdex_satisfied_millis(&self) -> Option<u64> {
        self.apdex_satisfied_millis
    }

    /// Returns the explicit APDEX tolerance threshold, if supplied.
    pub const fn apdex_tolerated_millis(&self) -> Option<u64> {
        self.apdex_tolerated_millis
    }

    /// Returns the explicit overall granularity, if supplied.
    pub const fn overall_granularity_millis(&self) -> Option<u64> {
        self.overall_granularity_millis
    }

    /// Returns the explicit statistical window, if supplied.
    pub const fn statistic_window(&self) -> Option<usize> {
        self.statistic_window
    }

    /// Returns the explicit transaction-controller filtering flag, if supplied.
    pub const fn exclude_transaction_controllers_from_top5(&self) -> Option<bool> {
        self.exclude_transaction_controllers_from_top5
    }

    /// Returns the explicit response-time distribution granularity, if supplied.
    pub const fn response_time_distribution_granularity_millis(&self) -> Option<u64> {
        self.response_time_distribution_granularity_millis
    }

    /// Returns the optional sample filter, preserving an explicit empty value.
    pub fn sample_filter(&self) -> Option<&str> {
        self.sample_filter.as_deref()
    }

    /// Returns the optional report title, preserving an explicit empty value.
    pub fn report_title(&self) -> Option<&str> {
        self.report_title.as_deref()
    }

    /// Returns the optional Java date format, preserving an explicit empty value.
    pub fn date_format(&self) -> Option<&str> {
        self.date_format.as_deref()
    }

    /// Returns the optional date-range start, preserving an explicit empty value.
    pub fn start_date(&self) -> Option<&str> {
        self.start_date.as_deref()
    }

    /// Returns the optional date-range end, preserving an explicit empty value.
    pub fn end_date(&self) -> Option<&str> {
        self.end_date.as_deref()
    }

    /// Returns retained unknown report-generator properties.
    pub fn unknown_properties(&self) -> &[(String, String)] {
        &self.unknown
    }

    /// Returns one retained unknown property by its exact wire name.
    pub fn unknown_property(&self, name: &str) -> Option<&str> {
        self.unknown
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

fn parse_u64(value: &str, field: ConfigField) -> Result<u64, ReportError> {
    // JMeter's report-generator long properties are parsed with
    // Long.parseLong after trimming. Keep the Rust-facing value non-negative
    // while rejecting values that Java cannot represent.
    value
        .trim()
        .parse::<i64>()
        .ok()
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(ReportError::InvalidConfig { field })
}

fn parse_usize(value: &str, field: ConfigField) -> Result<usize, ReportError> {
    let value = value
        .trim()
        .parse::<i64>()
        .map_err(|_| ReportError::InvalidConfig { field })?;
    // JMeter reads statistic_window through its int-valued property helper;
    // keep that wire bound independent of the host usize width.
    if !(0..=i64::from(i32::MAX)).contains(&value) {
        return Err(ReportError::InvalidConfig { field });
    }
    Ok(value as usize)
}

fn parse_bool(value: &str, field: ConfigField) -> Result<bool, ReportError> {
    if value.eq_ignore_ascii_case("true") {
        Ok(true)
    } else if value.eq_ignore_ascii_case("false") {
        Ok(false)
    } else {
        Err(ReportError::InvalidConfig { field })
    }
}

fn parse_percentile(value: &str) -> Result<f64, ReportError> {
    let value = value
        .trim()
        .parse::<f64>()
        .map_err(|_| ReportError::InvalidConfig {
            field: ConfigField::PercentileLevels,
        })?;
    if value.is_finite() && (0.0..=100.0).contains(&value) {
        Ok(value)
    } else {
        Err(ReportError::InvalidConfig {
            field: ConfigField::PercentileLevels,
        })
    }
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

    /// Builds listener configuration from JMeter's Aggregate/Summary
    /// percentile properties and an explicit reporting interval.
    pub fn from_properties<I, K, V>(
        interval: ReportInterval,
        properties: I,
    ) -> Result<Self, ReportError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let properties = ReportGeneratorProperties::from_properties(properties)?;
        Self::from_report_generator_properties(interval, &properties)
    }

    /// Builds listener configuration from a parsed property projection.
    pub fn from_report_generator_properties(
        interval: ReportInterval,
        properties: &ReportGeneratorProperties,
    ) -> Result<Self, ReportError> {
        Self::new(interval).with_decimal_percentiles(properties.aggregate_percentiles())
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
    response_time_distribution_granularity_millis: u64,
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
            percentile_window: DEFAULT_REPORT_STATISTIC_WINDOW,
            apdex: ApdexThresholds::default(),
            top_error_limit: 5,
            percentiles: DEFAULT_REPORT_PERCENTILES,
            percentile_levels: DEFAULT_REPORT_PERCENTILE_LEVELS,
            estimator: DashboardPercentileEstimator::Legacy,
            overall_granularity_millis: DEFAULT_REPORT_OVERALL_GRANULARITY_MILLIS,
            response_time_distribution_granularity_millis:
                DEFAULT_RESPONSE_TIME_DISTRIBUTION_GRANULARITY_MILLIS,
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
        if granularity_millis < MIN_REPORT_OVERALL_GRANULARITY_MILLIS
            || granularity_millis > i64::MAX as u64
        {
            return Err(ReportError::InvalidConfig {
                field: ConfigField::OverallGranularity,
            });
        }
        self.overall_granularity_millis = granularity_millis;
        Ok(self)
    }

    /// Sets the response-time distribution bucket width in milliseconds.
    ///
    /// JMeter's built-in report-generator default is 100 ms. Unlike the
    /// overall time-series width, this consumer accepts sub-second values;
    /// zero is still rejected because it cannot define a bucket.
    pub fn with_response_time_distribution_granularity_millis(
        mut self,
        granularity_millis: u64,
    ) -> Result<Self, ReportError> {
        if granularity_millis == 0 || granularity_millis > i64::MAX as u64 {
            return Err(ReportError::InvalidConfig {
                field: ConfigField::OverallGranularity,
            });
        }
        self.response_time_distribution_granularity_millis = granularity_millis;
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

    /// Builds dashboard configuration from JMeter report-generator
    /// properties and an explicit reporting interval.
    pub fn from_properties<I, K, V>(
        interval: ReportInterval,
        properties: I,
    ) -> Result<Self, ReportError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let properties = ReportGeneratorProperties::from_properties(properties)?;
        Self::from_report_generator_properties(interval, &properties)
    }

    /// Builds dashboard configuration from a parsed property projection.
    pub fn from_report_generator_properties(
        interval: ReportInterval,
        properties: &ReportGeneratorProperties,
    ) -> Result<Self, ReportError> {
        let mut config = Self::new(interval)?;
        // JMeter's dashboard statistics and response-time-percentile graph
        // consumers read the Aggregate/Summary percentile properties
        // (`aggregate_rpt_pct1/2/3`).  Keep their decimal values intact for
        // the dashboard's configured percentile levels.
        config = config.with_decimal_percentiles(properties.aggregate_percentiles())?;
        if let Some(window) = properties.statistic_window() {
            config = config.with_percentile_window(window)?;
        }
        if let Some(granularity) = properties.overall_granularity_millis() {
            config = config.with_overall_granularity_millis(granularity)?;
        }
        if let Some(granularity) = properties.response_time_distribution_granularity_millis() {
            config = config.with_response_time_distribution_granularity_millis(granularity)?;
        }
        let apdex = ApdexThresholds::new(
            properties
                .apdex_satisfied_millis()
                .unwrap_or_else(|| ApdexThresholds::default().satisfied_millis()),
            properties
                .apdex_tolerated_millis()
                .unwrap_or_else(|| ApdexThresholds::default().tolerated_millis()),
        )?;
        config = config.with_apdex(apdex);
        if let Some(exclude) = properties.exclude_transaction_controllers_from_top5() {
            config = config.with_exclude_transaction_controllers_from_top5(exclude);
        }
        Ok(config)
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

    /// Returns response-time distribution bucket width in milliseconds.
    pub const fn response_time_distribution_granularity_millis(self) -> u64 {
        self.response_time_distribution_granularity_millis
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

#[cfg(test)]
// Fixed fixture constructors panic only when a fixed test value no longer
// satisfies the validated report configuration contract.
#[allow(clippy::panic)]
mod tests {
    use super::*;

    fn interval() -> ReportInterval {
        match ReportInterval::from_millis(0, 10_000) {
            Ok(interval) => interval,
            Err(error) => panic!("non-empty test interval: {error:?}"),
        }
    }

    #[test]
    fn report_property_wire_names_are_exact_and_round_trip() {
        let properties = [
            ReportProperty::AggregatePercentile1,
            ReportProperty::AggregatePercentile2,
            ReportProperty::AggregatePercentile3,
            ReportProperty::DashboardApdexSatisfiedThreshold,
            ReportProperty::DashboardApdexToleratedThreshold,
            ReportProperty::DashboardOverallGranularity,
            ReportProperty::DashboardStatisticWindow,
            ReportProperty::DashboardExcludeTransactionControllersFromTop5,
            ReportProperty::ResponseTimeDistributionGranularity,
            ReportProperty::DashboardSampleFilter,
            ReportProperty::DashboardReportTitle,
            ReportProperty::DashboardDateFormat,
            ReportProperty::DashboardStartDate,
            ReportProperty::DashboardEndDate,
        ];
        for property in properties {
            assert_eq!(
                ReportProperty::from_wire_name(property.wire_name()),
                Some(property)
            );
        }
        assert_eq!(AGGREGATE_RPT_PCT1, "aggregate_rpt_pct1");
        assert_eq!(
            REPORTGENERATOR_STATISTIC_WINDOW,
            "jmeter.reportgenerator.statistic_window"
        );
        assert_eq!(
            REPORTGENERATOR_EXCLUDE_TC_FROM_TOP5_ERRORS_BY_SAMPLER,
            "jmeter.reportgenerator.exclude_tc_from_top5_errors_by_sampler"
        );
    }

    #[test]
    fn property_projection_preserves_presence_empty_and_unknown_values() {
        let properties = match ReportGeneratorProperties::from_properties([
            (AGGREGATE_RPT_PCT1, "90.5"),
            (REPORTGENERATOR_SAMPLE_FILTER, ""),
            (
                "jmeter.reportgenerator.graph.custom.classname",
                "plugin.Graph",
            ),
            (REPORTGENERATOR_STATISTIC_WINDOW, "7"),
            (REPORTGENERATOR_STATISTIC_WINDOW, "5"),
        ]) {
            Ok(properties) => properties,
            Err(error) => panic!("valid report properties: {error:?}"),
        };
        assert!(properties.contains(ReportProperty::AggregatePercentile1));
        assert_eq!(properties.aggregate_percentile(0), Some(90.5));
        assert!(properties.contains(ReportProperty::DashboardSampleFilter));
        assert_eq!(properties.sample_filter(), Some(""));
        assert_eq!(properties.statistic_window(), Some(5));
        assert_eq!(
            properties.unknown_property("jmeter.reportgenerator.graph.custom.classname"),
            Some("plugin.Graph")
        );

        let absent = ReportGeneratorProperties::default();
        assert!(!absent.contains(ReportProperty::DashboardSampleFilter));
        assert_eq!(absent.sample_filter(), None);
    }

    #[test]
    fn property_projection_applies_documented_defaults_and_rejects_bounds() {
        let properties = match ReportGeneratorProperties::from_properties([
            (AGGREGATE_RPT_PCT1, "90.125"),
            (AGGREGATE_RPT_PCT2, "95.25"),
            (AGGREGATE_RPT_PCT3, "99.875"),
            (REPORTGENERATOR_OVERALL_GRANULARITY, "10000"),
            (REPORTGENERATOR_STATISTIC_WINDOW, "5"),
            (REPORTGENERATOR_APDEX_SATISFIED_THRESHOLD, "500"),
            (REPORTGENERATOR_APDEX_TOLERATED_THRESHOLD, "1500"),
            (REPORTGENERATOR_RESPONSE_TIME_DISTRIBUTION_GRANULARITY, "25"),
            (
                REPORTGENERATOR_EXCLUDE_TC_FROM_TOP5_ERRORS_BY_SAMPLER,
                "false",
            ),
        ]) {
            Ok(properties) => properties,
            Err(error) => panic!("valid report properties: {error:?}"),
        };
        let dashboard =
            match DashboardConfig::from_report_generator_properties(interval(), &properties) {
                Ok(dashboard) => dashboard,
                Err(error) => panic!("valid dashboard config: {error:?}"),
            };
        assert_eq!(dashboard.percentile_values(), [90.125, 95.25, 99.875]);
        assert_eq!(dashboard.overall_granularity_millis(), 10_000);
        assert_eq!(dashboard.statistic_window(), 5);
        let apdex = match ApdexThresholds::new(500, 1_500) {
            Ok(apdex) => apdex,
            Err(error) => panic!("apdex: {error:?}"),
        };
        assert_eq!(dashboard.apdex(), apdex);
        assert_eq!(
            dashboard.response_time_distribution_granularity_millis(),
            25
        );
        assert!(!dashboard.exclude_transaction_controllers_from_top5());

        let defaults = match DashboardConfig::new(interval()) {
            Ok(defaults) => defaults,
            Err(error) => panic!("default dashboard config: {error:?}"),
        };
        assert_eq!(defaults.overall_granularity_millis(), 60_000);
        assert_eq!(defaults.statistic_window(), 20_000);
        assert_eq!(
            defaults.response_time_distribution_granularity_millis(),
            DEFAULT_RESPONSE_TIME_DISTRIBUTION_GRANULARITY_MILLIS
        );

        assert_eq!(
            DashboardConfig::from_properties(
                interval(),
                [(REPORTGENERATOR_OVERALL_GRANULARITY, "1000")]
            ),
            Err(ReportError::InvalidConfig {
                field: ConfigField::OverallGranularity
            })
        );
        assert_eq!(
            DashboardConfig::from_properties(interval(), [(REPORTGENERATOR_STATISTIC_WINDOW, "0")]),
            Err(ReportError::InvalidConfig {
                field: ConfigField::MaxPercentileSamples
            })
        );
        assert_eq!(
            ReportGeneratorProperties::from_properties([(
                REPORTGENERATOR_EXCLUDE_TC_FROM_TOP5_ERRORS_BY_SAMPLER,
                "yes"
            )]),
            Err(ReportError::InvalidConfig {
                field: ConfigField::TransactionControllerErrors
            })
        );
    }

    #[test]
    fn dashboard_properties_apply_each_supported_override() {
        let defaults = match DashboardConfig::new(interval()) {
            Ok(config) => config,
            Err(error) => panic!("default dashboard config: {error:?}"),
        };
        assert_eq!(defaults.percentile_values(), [90.0, 95.0, 99.0]);

        let first =
            match DashboardConfig::from_properties(interval(), [(AGGREGATE_RPT_PCT1, "12.345")]) {
                Ok(config) => config,
                Err(error) => panic!("first percentile override: {error:?}"),
            };
        assert_eq!(first.percentile_values(), [12.345, 95.0, 99.0]);

        let second =
            match DashboardConfig::from_properties(interval(), [(AGGREGATE_RPT_PCT2, "50.5")]) {
                Ok(config) => config,
                Err(error) => panic!("second percentile override: {error:?}"),
            };
        assert_eq!(second.percentile_values(), [90.0, 50.5, 99.0]);

        let third =
            match DashboardConfig::from_properties(interval(), [(AGGREGATE_RPT_PCT3, "99.875")]) {
                Ok(config) => config,
                Err(error) => panic!("third percentile override: {error:?}"),
            };
        assert_eq!(third.percentile_values(), [90.0, 95.0, 99.875]);

        let satisfied = match DashboardConfig::from_properties(
            interval(),
            [(REPORTGENERATOR_APDEX_SATISFIED_THRESHOLD, "250")],
        ) {
            Ok(config) => config,
            Err(error) => panic!("satisfied APDEX override: {error:?}"),
        };
        assert_eq!(satisfied.apdex().satisfied_millis(), 250);
        assert_eq!(satisfied.apdex().tolerated_millis(), 1_500);

        let tolerated = match DashboardConfig::from_properties(
            interval(),
            [(REPORTGENERATOR_APDEX_TOLERATED_THRESHOLD, "2500")],
        ) {
            Ok(config) => config,
            Err(error) => panic!("tolerated APDEX override: {error:?}"),
        };
        assert_eq!(tolerated.apdex().satisfied_millis(), 500);
        assert_eq!(tolerated.apdex().tolerated_millis(), 2_500);

        let window = match DashboardConfig::from_properties(
            interval(),
            [(REPORTGENERATOR_STATISTIC_WINDOW, "1")],
        ) {
            Ok(config) => config,
            Err(error) => panic!("statistic window override: {error:?}"),
        };
        assert_eq!(window.statistic_window(), 1);

        let overall = match DashboardConfig::from_properties(
            interval(),
            [(REPORTGENERATOR_OVERALL_GRANULARITY, "1001")],
        ) {
            Ok(config) => config,
            Err(error) => panic!("overall granularity override: {error:?}"),
        };
        assert_eq!(overall.overall_granularity_millis(), 1_001);

        let distribution = match DashboardConfig::from_properties(
            interval(),
            [(REPORTGENERATOR_RESPONSE_TIME_DISTRIBUTION_GRANULARITY, "1")],
        ) {
            Ok(config) => config,
            Err(error) => panic!("response distribution override: {error:?}"),
        };
        assert_eq!(
            distribution.response_time_distribution_granularity_millis(),
            1
        );

        let include_controllers = match DashboardConfig::from_properties(
            interval(),
            [(
                REPORTGENERATOR_EXCLUDE_TC_FROM_TOP5_ERRORS_BY_SAMPLER,
                "false",
            )],
        ) {
            Ok(config) => config,
            Err(error) => panic!("controller filtering override: {error:?}"),
        };
        assert!(!include_controllers.exclude_transaction_controllers_from_top5());
    }

    #[test]
    fn dashboard_properties_reject_invalid_values_and_honor_boundaries() {
        for value in ["", "-0.1", "100.1", "NaN", "inf"] {
            assert_eq!(
                ReportGeneratorProperties::from_properties([(AGGREGATE_RPT_PCT1, value)]),
                Err(ReportError::InvalidConfig {
                    field: ConfigField::PercentileLevels
                })
            );
        }

        let boundaries = match DashboardConfig::from_properties(
            interval(),
            [
                (AGGREGATE_RPT_PCT1, "0"),
                (AGGREGATE_RPT_PCT2, "100"),
                (AGGREGATE_RPT_PCT3, "50.125"),
                (REPORTGENERATOR_APDEX_SATISFIED_THRESHOLD, "0"),
                (REPORTGENERATOR_APDEX_TOLERATED_THRESHOLD, "0"),
                (REPORTGENERATOR_STATISTIC_WINDOW, "1"),
                (REPORTGENERATOR_OVERALL_GRANULARITY, "1001"),
                (REPORTGENERATOR_RESPONSE_TIME_DISTRIBUTION_GRANULARITY, "1"),
                (
                    REPORTGENERATOR_EXCLUDE_TC_FROM_TOP5_ERRORS_BY_SAMPLER,
                    "true",
                ),
            ],
        ) {
            Ok(config) => config,
            Err(error) => panic!("boundary dashboard config: {error:?}"),
        };
        assert_eq!(boundaries.percentile_values(), [0.0, 100.0, 50.125]);
        let zero_apdex = match ApdexThresholds::new(0, 0) {
            Ok(apdex) => apdex,
            Err(error) => panic!("zero APDEX thresholds: {error:?}"),
        };
        assert_eq!(boundaries.apdex(), zero_apdex);

        let max_window = AggregateLimits::default().max_percentile_samples();
        let max_window_value = max_window.to_string();
        let max_window_config = match DashboardConfig::from_properties(
            interval(),
            [(REPORTGENERATOR_STATISTIC_WINDOW, max_window_value.as_str())],
        ) {
            Ok(config) => config,
            Err(error) => panic!("maximum statistic window: {error:?}"),
        };
        assert_eq!(max_window_config.statistic_window(), max_window);

        let too_large_window = (i64::from(i32::MAX) + 1).to_string();
        assert_eq!(
            ReportGeneratorProperties::from_properties([(
                REPORTGENERATOR_STATISTIC_WINDOW,
                too_large_window.as_str(),
            )]),
            Err(ReportError::InvalidConfig {
                field: ConfigField::MaxPercentileSamples
            })
        );

        let max_long = i64::MAX.to_string();
        let max_long_config = match DashboardConfig::from_properties(
            interval(),
            [
                (REPORTGENERATOR_APDEX_SATISFIED_THRESHOLD, max_long.as_str()),
                (REPORTGENERATOR_APDEX_TOLERATED_THRESHOLD, max_long.as_str()),
                (REPORTGENERATOR_OVERALL_GRANULARITY, max_long.as_str()),
                (
                    REPORTGENERATOR_RESPONSE_TIME_DISTRIBUTION_GRANULARITY,
                    max_long.as_str(),
                ),
            ],
        ) {
            Ok(config) => config,
            Err(error) => panic!("maximum Java long properties: {error:?}"),
        };
        let maximum_apdex = match ApdexThresholds::new(i64::MAX as u64, i64::MAX as u64) {
            Ok(apdex) => apdex,
            Err(error) => panic!("maximum APDEX thresholds: {error:?}"),
        };
        assert_eq!(max_long_config.apdex(), maximum_apdex);
        assert_eq!(
            max_long_config.overall_granularity_millis(),
            i64::MAX as u64
        );
        assert_eq!(
            max_long_config.response_time_distribution_granularity_millis(),
            i64::MAX as u64
        );

        assert_eq!(
            DashboardConfig::from_properties(
                interval(),
                [(REPORTGENERATOR_APDEX_SATISFIED_THRESHOLD, "not-a-number")]
            ),
            Err(ReportError::InvalidConfig {
                field: ConfigField::ApdexThresholds
            })
        );
        assert_eq!(
            DashboardConfig::from_properties(interval(), [(REPORTGENERATOR_STATISTIC_WINDOW, "0")]),
            Err(ReportError::InvalidConfig {
                field: ConfigField::MaxPercentileSamples
            })
        );
        assert_eq!(
            DashboardConfig::from_properties(
                interval(),
                [(REPORTGENERATOR_OVERALL_GRANULARITY, "1000")]
            ),
            Err(ReportError::InvalidConfig {
                field: ConfigField::OverallGranularity
            })
        );
        assert_eq!(
            DashboardConfig::from_properties(
                interval(),
                [(REPORTGENERATOR_RESPONSE_TIME_DISTRIBUTION_GRANULARITY, "0")]
            ),
            Err(ReportError::InvalidConfig {
                field: ConfigField::OverallGranularity
            })
        );
        assert_eq!(
            DashboardConfig::from_properties(
                interval(),
                [(
                    REPORTGENERATOR_EXCLUDE_TC_FROM_TOP5_ERRORS_BY_SAMPLER,
                    "maybe",
                )]
            ),
            Err(ReportError::InvalidConfig {
                field: ConfigField::TransactionControllerErrors
            })
        );

        let too_large = (i64::MAX as u128 + 1).to_string();
        assert_eq!(
            ReportGeneratorProperties::from_properties([(
                REPORTGENERATOR_APDEX_SATISFIED_THRESHOLD,
                too_large.as_str(),
            )]),
            Err(ReportError::InvalidConfig {
                field: ConfigField::ApdexThresholds
            })
        );

        let text_only = match DashboardConfig::from_properties(
            interval(),
            [
                (REPORTGENERATOR_SAMPLE_FILTER, "sample.*"),
                (REPORTGENERATOR_REPORT_TITLE, "Custom title"),
                (REPORTGENERATOR_DATE_FORMAT, "yyyy"),
                (REPORTGENERATOR_START_DATE, "20240101000000"),
                (REPORTGENERATOR_END_DATE, "20240102000000"),
            ],
        ) {
            Ok(config) => config,
            Err(error) => panic!("unsupported dashboard text properties: {error:?}"),
        };
        let defaults = match DashboardConfig::new(interval()) {
            Ok(config) => config,
            Err(error) => panic!("default dashboard config: {error:?}"),
        };
        assert_eq!(text_only, defaults);
    }

    #[test]
    fn listener_properties_retain_decimal_percentiles() {
        let listener = match ListenerConfig::from_properties(
            interval(),
            [
                (AGGREGATE_RPT_PCT1, "50.5"),
                (AGGREGATE_RPT_PCT2, "90"),
                (AGGREGATE_RPT_PCT3, "99.25"),
            ],
        ) {
            Ok(listener) => listener,
            Err(error) => panic!("valid listener properties: {error:?}"),
        };
        assert_eq!(listener.percentile_values(), [50.5, 90.0, 99.25]);
        assert_eq!(listener.percentiles(), [51, 90, 99]);
        assert_eq!(
            ListenerConfig::from_properties(interval(), [(AGGREGATE_RPT_PCT1, "101")]),
            Err(ReportError::InvalidConfig {
                field: ConfigField::PercentileLevels
            })
        );
    }
}
