// SPDX-License-Identifier: Apache-2.0
//! Bounded dashboard report metrics.
//!
//! Dashboard percentile estimates intentionally differ from listener
//! percentiles.  The report generator keeps a FIFO statistical window and
//! interpolates between sorted values; counters and APDEX continue to cover
//! the complete input stream.

use std::collections::{BTreeMap, VecDeque};

use jmeter_rs_results::{SampleEvent, SampleResult};

use crate::config::{
    DashboardConfig, DashboardPercentileEstimator, LabelGrouping, PercentileLevel,
    validate_input_sample_count,
};
use crate::error::{ReportError, ReportLimit};
use crate::graph::{
    GraphAggregationOptions, GraphPoint, GraphSample, GraphTimestampPolicy,
    aggregate_graph_samples, aggregate_graph_samples_with_options,
    validate_graph_input_with_limits, write_graph_points_json,
};
use crate::graphs::{
    ActiveThreadsGraphPoint, BytesGraphPoint, ConnectGraphPoint, GraphBucket, HitsPerSecondPoint,
    LatencyGraphPoint, LatencyRequestPoint, ResponseCodeGraphPoint, ResponseTimeDistributionPoint,
    ResponseTimeGraphPoint, ResponseTimePercentileGraphPoint, ResponseTimeRequestPoint,
    SyntheticResponseTimePoint, TimeVsThreadsGraphPoint, TotalTpsPoint, TransactionTpsPoint,
    aggregate_active_threads_graph_samples, aggregate_bytes_graph_samples,
    aggregate_connect_graph_samples, aggregate_hits_per_second_graph_samples,
    aggregate_latency_graph_samples, aggregate_latency_vs_request_graph_samples,
    aggregate_response_code_graph_samples, aggregate_response_time_distribution_graph_samples,
    aggregate_response_time_graph_samples,
    aggregate_response_time_percentile_graph_samples_with_estimator,
    aggregate_response_time_vs_request_graph_samples,
    aggregate_synthetic_response_time_graph_samples, aggregate_time_vs_threads_graph_samples,
    aggregate_total_tps_graph_samples, aggregate_transactions_per_second_graph_samples,
};
use crate::metrics::{
    CountMode, ErrorKey, SampleMetadata, SummaryMetrics, TopError, append_window_observation,
    represented_counts, validate_label, validate_percentile,
};

/// Dashboard metrics for one sample label or the total row.
#[derive(Clone, Debug, PartialEq)]
pub struct DashboardMetrics {
    summary: SummaryMetrics,
    error_summary: DashboardErrorSummary,
    percentile_window: VecDeque<u64>,
    interval: crate::ReportInterval,
    percentile_window_limit: usize,
    top_error_limit: usize,
    percentiles: [u8; 3],
    percentile_levels: [PercentileLevel; 3],
    estimator: DashboardPercentileEstimator,
}

/// Error consumer state is separate from statistics state. JMeter's dashboard
/// wires `ErrorsSummaryConsumer` beneath the shared reverse controller filter,
/// so its overall and per-label keys see sampler rows only. APDEX is wired
/// before that filter and is handled independently by [`SummaryMetrics`].
#[derive(Clone, Debug, Default, PartialEq)]
struct DashboardErrorSummary {
    total_rows: u64,
    counts: BTreeMap<ErrorKey, u64>,
}

impl DashboardErrorSummary {
    fn add_result(
        &mut self,
        result: &SampleResult,
        limits: crate::AggregateLimits,
    ) -> Result<(), ReportError> {
        let counts = represented_counts(result, CountMode::Unweighted)?;
        self.total_rows = self
            .total_rows
            .checked_add(1)
            .ok_or(ReportError::Overflow {
                field: crate::ReportField::SampleCount,
            })?;
        if counts.errors == 0 {
            return Ok(());
        }
        let key = ErrorKey::from_result(result);
        let key_bytes = key.code().len().saturating_add(key.message().len());
        if key_bytes > limits.max_error_key_bytes() {
            return Err(ReportError::LimitExceeded {
                resource: ReportLimit::ErrorKeyBytes,
                actual: key_bytes,
                maximum: limits.max_error_key_bytes(),
            });
        }
        if !self.counts.contains_key(&key) && self.counts.len() >= limits.max_error_keys() {
            return Err(ReportError::LimitExceeded {
                resource: ReportLimit::ErrorKeys,
                actual: self.counts.len().saturating_add(1),
                maximum: limits.max_error_keys(),
            });
        }
        let current = self.counts.get(&key).copied().unwrap_or(0);
        let updated = current
            .checked_add(counts.errors)
            .ok_or(ReportError::Overflow {
                field: crate::ReportField::ErrorCount,
            })?;
        self.counts.insert(key, updated);
        Ok(())
    }

    fn merge(&mut self, other: &Self, limits: crate::AggregateLimits) -> Result<(), ReportError> {
        self.total_rows =
            self.total_rows
                .checked_add(other.total_rows)
                .ok_or(ReportError::Overflow {
                    field: crate::ReportField::SampleCount,
                })?;
        for (key, count) in &other.counts {
            if !self.counts.contains_key(key) && self.counts.len() >= limits.max_error_keys() {
                return Err(ReportError::LimitExceeded {
                    resource: ReportLimit::ErrorKeys,
                    actual: self.counts.len().saturating_add(1),
                    maximum: limits.max_error_keys(),
                });
            }
            let current = self.counts.get(key).copied().unwrap_or(0);
            let updated = current.checked_add(*count).ok_or(ReportError::Overflow {
                field: crate::ReportField::ErrorCount,
            })?;
            self.counts.insert(key.clone(), updated);
        }
        Ok(())
    }

    fn error_counts(&self) -> Vec<TopError> {
        self.counts
            .iter()
            .map(|(key, count)| TopError::from_parts(key.clone(), *count))
            .collect()
    }
}

/// One graph section declared by JMeter 5.6.3's report-generator inventory.
/// The generic graph projection can materialize the sections whose source
/// fields are represented by [`GraphPoint`]; specialized sections remain
/// explicitly unrequested until their source fields are supplied.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DashboardGraphDefinition {
    /// Stable report-generator graph identifier.
    pub id: &'static str,
    /// Human-readable graph title from reportgenerator.properties.
    pub title: &'static str,
    /// Whether this graph's pinned consumer excludes controller rows.
    pub exclude_transaction_controllers: bool,
}

/// Declared graph inventory for the pinned JMeter 5.6.3 dashboard profile.
pub const DASHBOARD_GRAPH_INVENTORY: [DashboardGraphDefinition; 16] = [
    DashboardGraphDefinition {
        id: "responseTimePercentiles",
        title: "Response Time Percentiles",
        exclude_transaction_controllers: false,
    },
    DashboardGraphDefinition {
        id: "responseTimeDistribution",
        title: "Response Time Distribution",
        exclude_transaction_controllers: false,
    },
    DashboardGraphDefinition {
        id: "activeThreadsOverTime",
        title: "Active Threads Over Time",
        exclude_transaction_controllers: false,
    },
    DashboardGraphDefinition {
        id: "timeVsThreads",
        title: "Time VS Threads",
        exclude_transaction_controllers: false,
    },
    DashboardGraphDefinition {
        id: "bytesThroughputOverTime",
        title: "Bytes Throughput Over Time",
        exclude_transaction_controllers: true,
    },
    DashboardGraphDefinition {
        id: "responseTimesOverTime",
        title: "Response Time Over Time",
        exclude_transaction_controllers: false,
    },
    DashboardGraphDefinition {
        id: "responseTimePercentilesOverTime",
        title: "Response Time Percentiles Over Time (successful requests only)",
        exclude_transaction_controllers: false,
    },
    DashboardGraphDefinition {
        id: "syntheticResponseTimeDistribution",
        title: "Synthetic Response Times Distribution",
        exclude_transaction_controllers: true,
    },
    DashboardGraphDefinition {
        id: "latenciesOverTime",
        title: "Latencies Over Time",
        exclude_transaction_controllers: false,
    },
    DashboardGraphDefinition {
        id: "connectTimeOverTime",
        title: "Connect Time Over Time",
        exclude_transaction_controllers: false,
    },
    DashboardGraphDefinition {
        id: "responseTimeVsRequest",
        title: "Response Time Vs Request",
        exclude_transaction_controllers: true,
    },
    DashboardGraphDefinition {
        id: "latencyVsRequest",
        title: "Latencies Vs Request",
        exclude_transaction_controllers: true,
    },
    DashboardGraphDefinition {
        id: "hitsPerSecond",
        title: "Hits Per Second",
        exclude_transaction_controllers: true,
    },
    DashboardGraphDefinition {
        id: "codesPerSecond",
        title: "Codes Per Second",
        exclude_transaction_controllers: true,
    },
    DashboardGraphDefinition {
        id: "totalTPS",
        title: "Total Transactions Per Second",
        exclude_transaction_controllers: false,
    },
    DashboardGraphDefinition {
        id: "transactionsPerSecond",
        title: "Transactions Per Second",
        exclude_transaction_controllers: false,
    },
];

/// Distinct payload for each named dashboard graph consumer.  A payload is
/// intentionally not a `Vec<GraphPoint>` alias: the source field vocabulary
/// and output shape remain visible at the API and serialization boundaries.
#[derive(Clone, Debug, PartialEq)]
pub enum DashboardGraphPayload {
    /// Response-time percentile buckets.
    ResponseTimePercentiles(Vec<ResponseTimePercentileGraphPoint>),
    /// Exact response-time distribution values.
    ResponseTimeDistribution(Vec<ResponseTimeDistributionPoint>),
    /// Group/all active-thread series.
    ActiveThreads(Vec<ActiveThreadsGraphPoint>),
    /// All-thread scatter series.
    TimeVsThreads(Vec<TimeVsThreadsGraphPoint>),
    /// Request/sent and response/received byte rates.
    BytesThroughput(Vec<BytesGraphPoint>),
    /// Elapsed response-time buckets.
    ResponseTimes(Vec<ResponseTimeGraphPoint>),
    /// Successful response-time percentile buckets.
    SuccessfulResponseTimePercentiles(Vec<ResponseTimePercentileGraphPoint>),
    /// Synthetic APDEX distribution.
    SyntheticResponseTimeDistribution(Vec<SyntheticResponseTimePoint>),
    /// Latency buckets.
    Latencies(Vec<LatencyGraphPoint>),
    /// Connect-time buckets.
    ConnectTimes(Vec<ConnectGraphPoint>),
    /// Response-time-versus-request scatter values.
    ResponseTimeVsRequest(Vec<ResponseTimeRequestPoint>),
    /// Latency-versus-request scatter values.
    LatencyVsRequest(Vec<LatencyRequestPoint>),
    /// Hits per second buckets.
    HitsPerSecond(Vec<HitsPerSecondPoint>),
    /// Response-code rate buckets.
    CodesPerSecond(Vec<ResponseCodeGraphPoint>),
    /// Total TPS buckets.
    TotalTps(Vec<TotalTpsPoint>),
    /// Label-specific TPS buckets.
    TransactionsPerSecond(Vec<TransactionTpsPoint>),
}

impl DashboardGraphPayload {
    /// Returns the inventory identifier corresponding to this payload.
    pub const fn id(&self) -> &'static str {
        match self {
            Self::ResponseTimePercentiles(_) => "responseTimePercentiles",
            Self::ResponseTimeDistribution(_) => "responseTimeDistribution",
            Self::ActiveThreads(_) => "activeThreadsOverTime",
            Self::TimeVsThreads(_) => "timeVsThreads",
            Self::BytesThroughput(_) => "bytesThroughputOverTime",
            Self::ResponseTimes(_) => "responseTimesOverTime",
            Self::SuccessfulResponseTimePercentiles(_) => "responseTimePercentilesOverTime",
            Self::SyntheticResponseTimeDistribution(_) => "syntheticResponseTimeDistribution",
            Self::Latencies(_) => "latenciesOverTime",
            Self::ConnectTimes(_) => "connectTimeOverTime",
            Self::ResponseTimeVsRequest(_) => "responseTimeVsRequest",
            Self::LatencyVsRequest(_) => "latencyVsRequest",
            Self::HitsPerSecond(_) => "hitsPerSecond",
            Self::CodesPerSecond(_) => "codesPerSecond",
            Self::TotalTps(_) => "totalTPS",
            Self::TransactionsPerSecond(_) => "transactionsPerSecond",
        }
    }
}

/// Status retained for one dashboard graph section.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DashboardGraphStatus {
    /// A field-specific payload was successfully materialized.
    Materialized,
    /// The section is declared but no exact payload was supplied.
    NotMaterialized,
    /// An exact source field/capability was unavailable.
    Unsupported,
}

/// One named section's status and optional distinct payload.
#[derive(Clone, Debug, PartialEq)]
pub struct DashboardGraphSection {
    id: &'static str,
    status: DashboardGraphStatus,
    error: Option<ReportError>,
    payload: Option<DashboardGraphPayload>,
}

impl DashboardGraphSection {
    /// Returns the stable section identifier.
    pub const fn id(&self) -> &'static str {
        self.id
    }
    /// Returns the section status.
    pub const fn status(&self) -> DashboardGraphStatus {
        self.status
    }
    /// Returns the typed materialization error, if any.
    pub const fn error(&self) -> Option<ReportError> {
        self.error
    }
    /// Returns the distinct payload when materialized.
    pub fn payload(&self) -> Option<&DashboardGraphPayload> {
        self.payload.as_ref()
    }
}

/// Complete 5.6.3 dashboard graph inventory with truthful per-section
/// materialization status.  `new` starts with all sections explicitly not
/// materialized; callers must provide field-specific inputs to change that.
#[derive(Clone, Debug, PartialEq)]
pub struct DashboardGraphSections {
    sections: BTreeMap<&'static str, DashboardGraphSection>,
}

impl DashboardGraphSections {
    /// Creates the declared inventory with no fabricated graph points.
    pub fn new() -> Self {
        let sections = DASHBOARD_GRAPH_INVENTORY
            .iter()
            .map(|definition| {
                (
                    definition.id,
                    DashboardGraphSection {
                        id: definition.id,
                        status: DashboardGraphStatus::NotMaterialized,
                        error: None,
                        payload: None,
                    },
                )
            })
            .collect();
        Self { sections }
    }

    /// Returns one section in inventory order by stable identifier.
    pub fn section(&self, id: &str) -> Option<&DashboardGraphSection> {
        self.sections.get(id)
    }

    /// Iterates all sections in the pinned inventory order.
    pub fn sections(&self) -> impl Iterator<Item = &DashboardGraphSection> {
        DASHBOARD_GRAPH_INVENTORY
            .iter()
            .filter_map(|definition| self.sections.get(definition.id))
    }

    /// Marks a section as materialized with a matching field-specific payload.
    pub fn set_payload(&mut self, payload: DashboardGraphPayload) -> Result<(), ReportError> {
        let id = payload.id();
        let section = self
            .sections
            .get_mut(id)
            .ok_or(ReportError::Unsupported { capability: id })?;
        section.status = DashboardGraphStatus::Materialized;
        section.error = None;
        section.payload = Some(payload);
        Ok(())
    }

    /// Marks a declared section unavailable while retaining its typed cause.
    pub fn mark_unsupported(&mut self, id: &str, error: ReportError) -> Result<(), ReportError> {
        let section = self.sections.get_mut(id).ok_or(ReportError::Unsupported {
            capability: "graph.section",
        })?;
        section.status = DashboardGraphStatus::Unsupported;
        section.error = Some(error);
        section.payload = None;
        Ok(())
    }
}

impl Default for DashboardGraphSections {
    fn default() -> Self {
        Self::new()
    }
}

/// Stable top-level dashboard sections exposed by the pinned report
/// generator. Specialized graph consumers remain explicit in the inventory
/// below until their source fields are supplied.
pub const DASHBOARD_SECTIONS: [&str; 7] = [
    "apdex",
    "request_summary",
    "statistics",
    "errors",
    "top_errors",
    "time_series",
    "response_time_distribution",
];

const GRAPH_FIELDS_NONE: &[&str] = &[];
const GRAPH_FIELDS_ELAPSED: &[&str] = &["elapsed"];
const GRAPH_FIELDS_THREADS: &[&str] = &["grpThreads", "allThreads"];
const GRAPH_FIELDS_TIME_THREADS: &[&str] = &["timeStamp", "allThreads"];
const GRAPH_FIELDS_BYTES: &[&str] = &["bytes", "sentBytes"];
const GRAPH_FIELDS_ELAPSED_SUCCESS: &[&str] = &["elapsed", "success"];
const GRAPH_FIELDS_SYNTHETIC: &[&str] = &[
    "elapsed",
    "apdex_satisfied_threshold",
    "apdex_tolerated_threshold",
];
const GRAPH_FIELDS_LATENCY: &[&str] = &["Latency"];
const GRAPH_FIELDS_CONNECT: &[&str] = &["Connect"];
const GRAPH_FIELDS_RESPONSE_REQUEST: &[&str] = &["elapsed", "timeStamp"];
const GRAPH_FIELDS_LATENCY_REQUEST: &[&str] = &["Latency", "timeStamp"];
const GRAPH_FIELDS_HITS: &[&str] = &["SampleCount", "timeStamp"];
const GRAPH_FIELDS_CODES: &[&str] = &["responseCode", "timeStamp"];
const GRAPH_FIELDS_TRANSACTION: &[&str] = &["label", "SampleCount", "timeStamp"];

fn graph_source_fields(id: &str) -> &'static [&'static str] {
    match id {
        "responseTimePercentiles" | "responseTimeDistribution" | "responseTimesOverTime" => {
            GRAPH_FIELDS_ELAPSED
        }
        "activeThreadsOverTime" => GRAPH_FIELDS_THREADS,
        "timeVsThreads" => GRAPH_FIELDS_TIME_THREADS,
        "bytesThroughputOverTime" => GRAPH_FIELDS_BYTES,
        "responseTimePercentilesOverTime" => GRAPH_FIELDS_ELAPSED_SUCCESS,
        "syntheticResponseTimeDistribution" => GRAPH_FIELDS_SYNTHETIC,
        "latenciesOverTime" => GRAPH_FIELDS_LATENCY,
        "connectTimeOverTime" => GRAPH_FIELDS_CONNECT,
        "responseTimeVsRequest" => GRAPH_FIELDS_RESPONSE_REQUEST,
        "latencyVsRequest" => GRAPH_FIELDS_LATENCY_REQUEST,
        "hitsPerSecond" | "totalTPS" => GRAPH_FIELDS_HITS,
        "codesPerSecond" => GRAPH_FIELDS_CODES,
        "transactionsPerSecond" => GRAPH_FIELDS_TRANSACTION,
        _ => GRAPH_FIELDS_NONE,
    }
}

impl DashboardMetrics {
    fn empty(config: DashboardConfig) -> Self {
        Self {
            summary: SummaryMetrics::new(),
            error_summary: DashboardErrorSummary::default(),
            // Do not eagerly allocate an operator-supplied maximum.  The
            // window grows only as observations arrive and is always capped
            // by `percentile_window_limit`.
            percentile_window: VecDeque::new(),
            interval: config.interval(),
            percentile_window_limit: config.percentile_window(),
            top_error_limit: config.top_error_limit(),
            percentiles: config.percentiles(),
            percentile_levels: config.percentile_levels(),
            estimator: config.percentile_estimator(),
        }
    }

    /// Returns complete-stream count/timing/byte/APDEX/error metrics.
    pub const fn summary(&self) -> &SummaryMetrics {
        &self.summary
    }

    /// Alias for [`DashboardMetrics::summary`].
    pub const fn metrics(&self) -> &SummaryMetrics {
        self.summary()
    }

    /// Returns the explicit interval used for rates.
    pub const fn interval(&self) -> crate::ReportInterval {
        self.interval
    }

    /// Returns represented sample count from the complete input stream.
    pub const fn sample_count(&self) -> u64 {
        self.summary.sample_count()
    }

    /// Returns represented failed-sample count from the complete input stream.
    pub const fn error_count(&self) -> u64 {
        self.summary.error_count()
    }

    /// Returns the number of rows seen by the dashboard ErrorsSummary
    /// consumer, after its reverse transaction-controller filter.
    pub const fn error_summary_sample_count(&self) -> u64 {
        self.error_summary.total_rows
    }

    /// Returns failed rows seen by ErrorsSummary, independent of the
    /// statistics/APDEX controller policies.
    pub fn error_summary_error_count(&self) -> u64 {
        self.error_summary
            .counts
            .values()
            .copied()
            .fold(0, u64::saturating_add)
    }

    /// Returns represented successful-sample count.
    pub const fn success_count(&self) -> u64 {
        self.summary.success_count()
    }

    /// Returns the number of rows with elapsed values.
    pub const fn elapsed_count(&self) -> u64 {
        self.summary.elapsed_count()
    }

    /// Returns elapsed mean across the complete input stream.
    pub const fn elapsed_mean(&self) -> Option<f64> {
        self.summary.elapsed_mean()
    }

    /// Returns elapsed population standard deviation across the complete
    /// input stream.
    pub fn elapsed_stddev(&self) -> Option<f64> {
        self.summary.elapsed_stddev()
    }

    /// Returns population elapsed variance across the complete stream.
    pub fn elapsed_variance(&self) -> Option<f64> {
        self.summary.elapsed_variance()
    }

    /// Returns the minimum elapsed value in milliseconds.
    pub const fn elapsed_min(&self) -> Option<u64> {
        self.summary.elapsed_min()
    }

    /// Returns the maximum elapsed value in milliseconds.
    pub const fn elapsed_max(&self) -> Option<u64> {
        self.summary.elapsed_max()
    }

    /// Returns total received bytes.
    pub const fn received_bytes(&self) -> u64 {
        self.summary.received_bytes()
    }

    /// Returns total sent bytes.
    pub const fn sent_bytes(&self) -> u64 {
        self.summary.sent_bytes()
    }

    /// Returns the average received-byte size per represented sample.
    pub fn average_received_bytes(&self) -> Option<f64> {
        self.summary.average_received_bytes()
    }

    /// Returns the average sent-byte size per represented sample.
    pub fn average_sent_bytes(&self) -> Option<f64> {
        self.summary.average_sent_bytes()
    }

    /// Returns complete-stream samples per second.
    pub fn throughput_per_second(&self) -> f64 {
        self.summary.throughput_per_second(self.interval)
    }

    /// Alias for [`DashboardMetrics::throughput_per_second`].
    pub fn throughput(&self) -> f64 {
        self.throughput_per_second()
    }

    /// Returns the complete-stream failed-sample percentage.
    pub fn error_percentage(&self) -> f64 {
        self.summary.error_percentage()
    }

    /// Returns the percentage of represented rows that succeeded.
    pub fn success_percentage(&self) -> f64 {
        self.summary.success_percentage()
    }

    /// Returns failed rows per second over the observed span or explicit
    /// fallback interval.
    pub fn error_throughput_per_second(&self) -> f64 {
        self.summary.error_throughput_per_second(self.interval)
    }

    /// Returns received bytes per second over this report's interval.
    pub fn received_bytes_per_second(&self) -> f64 {
        self.summary.received_bytes_per_second(self.interval)
    }

    /// Returns sent bytes per second over this report's interval.
    pub fn sent_bytes_per_second(&self) -> f64 {
        self.summary.sent_bytes_per_second(self.interval)
    }

    /// Returns APDEX counts from the complete stream.
    pub const fn apdex(&self) -> crate::ApdexCounts {
        self.summary.apdex()
    }

    /// Returns all error keys in deterministic key order.
    pub fn error_counts(&self) -> Vec<TopError> {
        self.error_summary.error_counts()
    }

    /// Returns the configured number of highest-count errors.
    pub fn top_errors(&self) -> Vec<TopError> {
        self.summary.top_errors(self.top_error_limit)
    }

    /// Returns the highest-count errors up to an explicit limit.
    pub fn top_errors_up_to(&self, limit: usize) -> Vec<TopError> {
        self.summary.top_errors(limit)
    }

    /// Returns the configured percentile levels (90, 95, and 99 by default).
    pub const fn configured_percentiles(&self) -> [u8; 3] {
        self.percentiles
    }

    /// Evaluates all configured percentile levels in deterministic order.
    pub fn percentiles(&self) -> Result<[Option<f64>; 3], ReportError> {
        Ok([
            self.percentile(self.percentile_levels[0].as_percent())?,
            self.percentile(self.percentile_levels[1].as_percent())?,
            self.percentile(self.percentile_levels[2].as_percent())?,
        ])
    }

    /// Returns the number of observations currently retained by the FIFO
    /// percentile window.
    pub fn percentile_sample_count(&self) -> usize {
        self.percentile_window.len()
    }

    /// Returns the retained FIFO observations in insertion order.
    ///
    /// The vector is bounded by the configured percentile window and is
    /// intended for deterministic report serialization and diagnostics.
    pub fn percentile_window_observations(&self) -> Vec<u64> {
        self.percentile_window.iter().copied().collect()
    }

    /// Returns the configured FIFO window capacity.
    pub const fn percentile_window_limit(&self) -> usize {
        self.percentile_window_limit
    }

    /// Returns the selected dashboard percentile estimator.
    pub const fn percentile_estimator(&self) -> DashboardPercentileEstimator {
        self.estimator
    }

    /// Returns configured percentile levels, including decimal values.
    pub const fn configured_percentile_levels(&self) -> [PercentileLevel; 3] {
        self.percentile_levels
    }

    /// Returns configured percentile percentages, preserving decimals.
    pub fn configured_percentile_values(&self) -> [f64; 3] {
        [
            self.percentile_levels[0].as_percent(),
            self.percentile_levels[1].as_percent(),
            self.percentile_levels[2].as_percent(),
        ]
    }

    /// Returns the sorted/interpolated dashboard percentile in milliseconds.
    ///
    /// The legacy position is `p * (n + 1)` for `p` in `[0, 1]`, clamped to the
    /// observed minimum/maximum, with adjacent values linearly interpolated.
    /// Only the newest configured window contributes.
    pub fn percentile(&self, percentile: f64) -> Result<Option<f64>, ReportError> {
        validate_percentile(percentile)?;
        if self.percentile_window.is_empty() {
            return Ok(None);
        }
        let mut values: Vec<u64> = self.percentile_window.iter().copied().collect();
        values.sort_unstable();
        if values.len() == 1 {
            return Ok(Some(values[0] as f64));
        }
        let position = match self.estimator {
            DashboardPercentileEstimator::Legacy => percentile / 100.0 * (values.len() + 1) as f64,
            DashboardPercentileEstimator::R3 => {
                let rank = nearest_even_rank(percentile / 100.0 * values.len() as f64).max(1);
                return Ok(Some(values[(rank - 1).min(values.len() - 1)] as f64));
            }
        };
        if position <= 1.0 {
            return Ok(Some(values[0] as f64));
        }
        if position >= values.len() as f64 {
            return Ok(Some(values[values.len() - 1] as f64));
        }
        let lower = position.floor() as usize - 1;
        let upper = lower + 1;
        let weight = position.fract();
        Ok(Some(
            values[lower] as f64 + (values[upper] as f64 - values[lower] as f64) * weight,
        ))
    }

    /// Returns the interpolated percentile rounded to the nearest integer
    /// millisecond.
    pub fn percentile_millis(&self, percentile: f64) -> Result<Option<u64>, ReportError> {
        Ok(self
            .percentile(percentile)?
            .map(|value| value.round() as u64))
    }

    /// Returns the median (50th percentile) in milliseconds.
    pub fn median(&self) -> Result<Option<f64>, ReportError> {
        self.percentile(50.0)
    }

    pub(crate) fn add_result_with_metadata(
        &mut self,
        result: &SampleResult,
        config: DashboardConfig,
        metadata: SampleMetadata,
    ) -> Result<(), ReportError> {
        let thresholds = metadata.apdex_thresholds().unwrap_or(config.apdex());
        let observation = self.summary.add_result_unweighted(
            result,
            thresholds,
            config.limits(),
            !metadata.is_transaction_controller()
                || !config.exclude_transaction_controllers_from_top5(),
        )?;
        if !metadata.is_transaction_controller() {
            self.error_summary.add_result(result, config.limits())?;
        }
        append_window_observation(
            &mut self.percentile_window,
            observation,
            config.percentile_window(),
        )?;
        Ok(())
    }

    pub(crate) fn add_apdex_only_with_metadata(
        &mut self,
        result: &SampleResult,
        config: DashboardConfig,
        metadata: SampleMetadata,
    ) -> Result<(), ReportError> {
        let thresholds = metadata.apdex_thresholds().unwrap_or(config.apdex());
        self.summary
            .add_apdex_only(result, thresholds, crate::metrics::CountMode::Unweighted)?;
        Ok(())
    }

    fn merge(&mut self, other: &Self, config: DashboardConfig) -> Result<(), ReportError> {
        let mut updated = self.clone();
        updated.summary.merge(&other.summary, config.limits())?;
        updated
            .error_summary
            .merge(&other.error_summary, config.limits())?;
        for value in &other.percentile_window {
            if updated.percentile_window.len() == config.percentile_window() {
                updated.percentile_window.pop_front();
            }
            updated.percentile_window.push_back(*value);
        }
        *self = updated;
        Ok(())
    }
}

/// Deterministic dashboard data model with complete-stream totals and
/// bounded FIFO per-label metrics.
#[derive(Clone, Debug, PartialEq)]
pub struct DashboardReport {
    config: DashboardConfig,
    total: DashboardMetrics,
    labels: BTreeMap<String, DashboardMetrics>,
}

impl DashboardReport {
    /// Creates an empty dashboard report.
    pub fn new(config: DashboardConfig) -> Self {
        Self {
            config,
            total: DashboardMetrics::empty(config),
            labels: BTreeMap::new(),
        }
    }

    /// Returns dashboard algorithm/resource configuration.
    pub const fn config(&self) -> DashboardConfig {
        self.config
    }

    /// Returns the complete-stream total row.
    pub const fn total(&self) -> &DashboardMetrics {
        &self.total
    }

    /// Alias for [`DashboardReport::total`].
    pub const fn summary(&self) -> &DashboardMetrics {
        self.total()
    }

    /// Returns a row for one exact sample label.
    pub fn label(&self, label: &str) -> Option<&DashboardMetrics> {
        self.labels.get(label)
    }

    /// Returns rows in deterministic lexicographic label order.
    pub fn labels(&self) -> impl Iterator<Item = (&str, &DashboardMetrics)> {
        self.labels
            .iter()
            .map(|(label, metrics)| (label.as_str(), metrics))
    }

    /// Returns the number of retained distinct labels.
    pub fn label_count(&self) -> usize {
        self.labels.len()
    }

    /// Adds a result to complete-stream and per-label metrics atomically.
    pub fn add_result(&mut self, result: &SampleResult) -> Result<(), ReportError> {
        let label = result.label().to_owned();
        self.add_labeled_result(result, &label, SampleMetadata::sampler())
    }

    /// Adds a result with explicit transaction-controller metadata.
    pub fn add_result_with_metadata(
        &mut self,
        result: &SampleResult,
        metadata: SampleMetadata,
    ) -> Result<(), ReportError> {
        let label = result.label().to_owned();
        self.add_labeled_result(result, &label, metadata)
    }

    fn add_labeled_result(
        &mut self,
        result: &SampleResult,
        label: &str,
        metadata: SampleMetadata,
    ) -> Result<(), ReportError> {
        validate_label(label, self.config.limits())?;
        if !self.labels.contains_key(label)
            && self.labels.len() >= self.config.limits().max_labels()
        {
            return Err(ReportError::LimitExceeded {
                resource: ReportLimit::Labels,
                actual: self.labels.len().saturating_add(1),
                maximum: self.config.limits().max_labels(),
            });
        }

        // Clone only the total and changed label row.  This preserves the
        // atomic-on-error contract without copying every retained label for
        // each incoming sample.
        let mut next_total = self.total.clone();
        // JMeter's overall StatisticsSummary, RequestsSummary,
        // ErrorsSummary, and (by default) Top5ErrorsBySampler consumers omit
        // transaction-controller rows. ApdexSummary is the deliberate
        // exception: it sees every non-empty controller sample. Keep that
        // contribution separate so a controller cannot leak into overall
        // rates, statistics, error tables, or the FIFO percentile window.
        if metadata.is_transaction_controller() {
            next_total.add_apdex_only_with_metadata(result, self.config, metadata)?;
        } else {
            next_total.add_result_with_metadata(result, self.config, metadata)?;
        }
        let mut next_row = self
            .labels
            .get(label)
            .cloned()
            .unwrap_or_else(|| DashboardMetrics::empty(self.config));
        next_row.add_result_with_metadata(result, self.config, metadata)?;
        self.total = next_total;
        self.labels.insert(label.to_owned(), next_row);
        Ok(())
    }

    /// Alias for [`DashboardReport::add_result`].
    pub fn add_sample(&mut self, result: &SampleResult) -> Result<(), ReportError> {
        self.add_result(result)
    }

    /// Adds the result carried by a listener event.
    pub fn add_event(&mut self, event: &SampleEvent) -> Result<(), ReportError> {
        let label = grouped_label(
            self.config.label_grouping(),
            event.thread().group(),
            event.result().label(),
        );
        self.add_labeled_result(event.result(), &label, SampleMetadata::sampler())
    }

    /// Adds an event with explicit transaction-controller metadata.
    pub fn add_event_with_metadata(
        &mut self,
        event: &SampleEvent,
        metadata: SampleMetadata,
    ) -> Result<(), ReportError> {
        let label = grouped_label(
            self.config.label_grouping(),
            event.thread().group(),
            event.result().label(),
        );
        self.add_labeled_result(event.result(), &label, metadata)
    }

    /// Merges dashboard reports with identical configuration.
    ///
    /// FIFO windows are concatenated in merge-call order and truncated from
    /// the front.  Callers should merge reports in source-stream order when
    /// exact newest-window semantics matter.
    pub fn merge(&mut self, other: &Self) -> Result<(), ReportError> {
        if self.config != other.config {
            return Err(ReportError::IncompatibleMerge);
        }

        let new_labels = other
            .labels
            .keys()
            .filter(|label| !self.labels.contains_key(*label))
            .count();
        let resulting_labels =
            self.labels
                .len()
                .checked_add(new_labels)
                .ok_or(ReportError::LimitExceeded {
                    resource: ReportLimit::Labels,
                    actual: usize::MAX,
                    maximum: self.config.limits().max_labels(),
                })?;
        if resulting_labels > self.config.limits().max_labels() {
            return Err(ReportError::LimitExceeded {
                resource: ReportLimit::Labels,
                actual: resulting_labels,
                maximum: self.config.limits().max_labels(),
            });
        }
        let mut next_total = self.total.clone();
        next_total.merge(&other.total, self.config)?;
        let mut next_rows = Vec::with_capacity(other.labels.len());
        for (label, other_row) in &other.labels {
            let mut next_row = self
                .labels
                .get(label)
                .cloned()
                .unwrap_or_else(|| DashboardMetrics::empty(self.config));
            next_row.merge(other_row, self.config)?;
            next_rows.push((label.clone(), next_row));
        }
        self.total = next_total;
        for (label, row) in next_rows {
            self.labels.insert(label, row);
        }
        Ok(())
    }

    /// Removes all observations while retaining configuration.
    pub fn clear(&mut self) {
        self.total = DashboardMetrics::empty(self.config);
        self.labels.clear();
    }

    /// Aggregates caller-retained timestamps using the configured dashboard
    /// overall granularity.
    pub fn graph_series(
        &self,
        samples: &[GraphSample],
        max_points: usize,
    ) -> Result<Vec<GraphPoint>, ReportError> {
        validate_graph_input_with_limits(samples, self.config.limits())?;
        aggregate_graph_samples(
            samples,
            self.config.interval(),
            self.config.overall_granularity_millis(),
            max_points,
        )
    }

    /// Aggregates a graph using an explicit controller policy. This is the
    /// adapter used by named inventory sections whose JMeter properties set
    /// `exclude_controllers=true`.
    pub fn graph_series_with_options(
        &self,
        samples: &[GraphSample],
        max_points: usize,
        options: GraphAggregationOptions,
    ) -> Result<Vec<GraphPoint>, ReportError> {
        validate_graph_input_with_limits(samples, self.config.limits())?;
        aggregate_graph_samples_with_options(
            samples,
            self.config.interval(),
            self.config.overall_granularity_millis(),
            max_points,
            options,
        )
    }

    /// Aggregates a graph using one declared JMeter graph section's policy.
    pub fn graph_series_for_definition(
        &self,
        definition: DashboardGraphDefinition,
        samples: &[GraphSample],
        max_points: usize,
    ) -> Result<Vec<GraphPoint>, ReportError> {
        self.graph_series_with_options(
            samples,
            max_points,
            if definition.exclude_transaction_controllers {
                GraphAggregationOptions::exclude_controllers()
            } else {
                GraphAggregationOptions::include_controllers()
            },
        )
    }

    /// Materializes one named dashboard graph using its field-specific
    /// consumer.  The generic [`GraphPoint`] projection is intentionally not
    /// used here: each named section keeps its own source fields and output
    /// shape.  Missing source fields are returned as a typed unsupported
    /// error so callers can retain a not-materialized section state.
    pub fn materialize_graph_section(
        &self,
        id: &str,
        samples: &[GraphSample],
        max_points: usize,
    ) -> Result<DashboardGraphPayload, ReportError> {
        validate_graph_input_with_limits(samples, self.config.limits())?;
        let definition = DASHBOARD_GRAPH_INVENTORY
            .iter()
            .find(|definition| definition.id == id)
            .copied()
            .ok_or(ReportError::Unsupported {
                capability: "graph.section",
            })?;
        let options = if definition.exclude_transaction_controllers {
            GraphAggregationOptions::exclude_controllers()
        } else {
            GraphAggregationOptions::include_controllers()
        };
        let interval = self.config.interval();
        let granularity = self.config.overall_granularity_millis();
        let percentile_values = self.config.percentile_values();
        let max_samples = self.config.limits().max_percentile_samples();
        match id {
            "responseTimePercentiles" => Ok(DashboardGraphPayload::ResponseTimePercentiles(
                aggregate_response_time_percentile_graph_samples_with_estimator(
                    samples,
                    interval,
                    granularity,
                    &percentile_values,
                    max_points,
                    max_samples,
                    options,
                    self.config.percentile_estimator(),
                )?,
            )),
            "responseTimeDistribution" => Ok(DashboardGraphPayload::ResponseTimeDistribution(
                aggregate_response_time_distribution_graph_samples(
                    samples,
                    interval,
                    max_points,
                    max_samples,
                    options,
                )?,
            )),
            "activeThreadsOverTime" => Ok(DashboardGraphPayload::ActiveThreads(
                aggregate_active_threads_graph_samples(
                    samples,
                    interval,
                    granularity,
                    max_points,
                    options,
                )?,
            )),
            "timeVsThreads" => Ok(DashboardGraphPayload::TimeVsThreads(
                aggregate_time_vs_threads_graph_samples(samples, interval, max_points, options)?,
            )),
            "bytesThroughputOverTime" => Ok(DashboardGraphPayload::BytesThroughput(
                aggregate_bytes_graph_samples(samples, interval, granularity, max_points, options)?,
            )),
            "responseTimesOverTime" => Ok(DashboardGraphPayload::ResponseTimes(
                aggregate_response_time_graph_samples(
                    samples,
                    interval,
                    granularity,
                    max_points,
                    options,
                )?,
            )),
            "responseTimePercentilesOverTime" => {
                let successful = successful_graph_samples(samples, interval, options)?;
                Ok(DashboardGraphPayload::SuccessfulResponseTimePercentiles(
                    aggregate_response_time_percentile_graph_samples_with_estimator(
                        &successful,
                        interval,
                        granularity,
                        &percentile_values,
                        max_points,
                        max_samples,
                        options,
                        self.config.percentile_estimator(),
                    )?,
                ))
            }
            "syntheticResponseTimeDistribution" => {
                let apdex = self.config.apdex();
                Ok(DashboardGraphPayload::SyntheticResponseTimeDistribution(
                    aggregate_synthetic_response_time_graph_samples(
                        samples,
                        interval,
                        apdex.satisfied_millis(),
                        apdex.tolerated_millis(),
                        max_points,
                        options,
                    )?,
                ))
            }
            "latenciesOverTime" => Ok(DashboardGraphPayload::Latencies(
                aggregate_latency_graph_samples(
                    samples,
                    interval,
                    granularity,
                    max_points,
                    options,
                )?,
            )),
            "connectTimeOverTime" => Ok(DashboardGraphPayload::ConnectTimes(
                aggregate_connect_graph_samples(
                    samples,
                    interval,
                    granularity,
                    max_points,
                    options,
                )?,
            )),
            "responseTimeVsRequest" => Ok(DashboardGraphPayload::ResponseTimeVsRequest(
                aggregate_response_time_vs_request_graph_samples(
                    samples, interval, max_points, options,
                )?,
            )),
            "latencyVsRequest" => Ok(DashboardGraphPayload::LatencyVsRequest(
                aggregate_latency_vs_request_graph_samples(samples, interval, max_points, options)?,
            )),
            "hitsPerSecond" => Ok(DashboardGraphPayload::HitsPerSecond(
                aggregate_hits_per_second_graph_samples(
                    samples,
                    interval,
                    granularity,
                    max_points,
                    options,
                )?,
            )),
            "codesPerSecond" => Ok(DashboardGraphPayload::CodesPerSecond(
                aggregate_response_code_graph_samples(
                    samples,
                    interval,
                    granularity,
                    max_points,
                    options,
                )?,
            )),
            "totalTPS" => Ok(DashboardGraphPayload::TotalTps(
                aggregate_total_tps_graph_samples(
                    samples,
                    interval,
                    granularity,
                    max_points,
                    options,
                )?,
            )),
            "transactionsPerSecond" => Ok(DashboardGraphPayload::TransactionsPerSecond(
                aggregate_transactions_per_second_graph_samples(
                    samples,
                    interval,
                    granularity,
                    max_points,
                    options,
                )?,
            )),
            _ => Err(ReportError::Unsupported {
                capability: "graph.section",
            }),
        }
    }

    /// Materializes the complete dashboard inventory atomically per section.
    /// An empty input remains explicitly not materialized.  If a section has
    /// rows but lacks its source field, the section is marked unsupported with
    /// the exact typed cause while other sections continue independently.
    pub fn materialize_graph_sections(
        &self,
        samples: &[GraphSample],
        max_points: usize,
    ) -> DashboardGraphSections {
        let mut sections = DashboardGraphSections::new();
        if samples.is_empty() {
            return sections;
        }
        if let Err(error) = validate_graph_input_with_limits(samples, self.config.limits()) {
            for definition in DASHBOARD_GRAPH_INVENTORY {
                let _ = sections.mark_unsupported(definition.id, error);
            }
            return sections;
        }
        for definition in DASHBOARD_GRAPH_INVENTORY {
            match self.materialize_graph_section(definition.id, samples, max_points) {
                Ok(payload) => {
                    // This payload's id was resolved from the same inventory,
                    // so a failure here would indicate an internal mismatch.
                    if let Err(error) = sections.set_payload(payload) {
                        let _ = sections.mark_unsupported(definition.id, error);
                    }
                }
                Err(error) => {
                    let _ = sections.mark_unsupported(definition.id, error);
                }
            }
        }
        sections
    }

    /// Projects result snapshots with the timestamp policy declared by the
    /// named consumer, then materializes that field-specific section.
    pub fn materialize_graph_section_from_results(
        &self,
        id: &str,
        results: &[SampleResult],
        max_points: usize,
    ) -> Result<DashboardGraphPayload, ReportError> {
        validate_input_sample_count(results.len(), self.config.limits().max_input_samples())?;
        let policy = if matches!(id, "hitsPerSecond" | "codesPerSecond") {
            GraphTimestampPolicy::Start
        } else {
            GraphTimestampPolicy::End
        };
        let samples = results
            .iter()
            .map(|result| {
                GraphSample::try_from_result_with_timestamp(result, policy)?
                    .ok_or(ReportError::Serialization)
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.materialize_graph_section(id, &samples, max_points)
    }

    /// Projects event rows into graph samples while retaining the explicit
    /// transaction-controller metadata supplied by the caller.  Results and
    /// events do not encode that identity themselves, so no label heuristic is
    /// applied here.
    pub fn graph_samples_from_events_with_metadata(
        &self,
        events: &[(&SampleEvent, SampleMetadata)],
        policy: GraphTimestampPolicy,
    ) -> Result<Vec<GraphSample>, ReportError> {
        validate_input_sample_count(events.len(), self.config.limits().max_input_samples())?;
        let mut samples = Vec::with_capacity(events.len());
        for (event, metadata) in events {
            let sample = GraphSample::try_from_result_with_metadata_and_timestamp(
                event.result(),
                *metadata,
                policy,
            )?
            .ok_or(ReportError::Serialization)?;
            samples.push(sample);
        }
        validate_graph_input_with_limits(&samples, self.config.limits())?;
        Ok(samples)
    }

    /// Projects result snapshots into weighted graph rows and aggregates them
    /// using the configured dashboard granularity.
    pub fn graph_series_from_results(
        &self,
        results: &[SampleResult],
        max_points: usize,
    ) -> Result<Vec<GraphPoint>, ReportError> {
        self.graph_series_from_results_with_policy(results, max_points, GraphTimestampPolicy::End)
    }

    /// Projects result snapshots with an explicit timestamp policy before
    /// applying the dashboard's fixed-width aggregation.
    pub fn graph_series_from_results_with_policy(
        &self,
        results: &[SampleResult],
        max_points: usize,
        policy: GraphTimestampPolicy,
    ) -> Result<Vec<GraphPoint>, ReportError> {
        validate_input_sample_count(results.len(), self.config.limits().max_input_samples())?;
        let mut samples = Vec::with_capacity(results.len());
        for result in results {
            let sample = GraphSample::try_from_result_with_timestamp(result, policy)?
                .ok_or(ReportError::Serialization)?;
            samples.push(sample);
        }
        self.graph_series(&samples, max_points)
    }

    /// Projects result snapshots for one declared graph section. JMeter's
    /// `hitsPerSecond` and `codesPerSecond` sections select sample start time;
    /// the other named time-series sections use sample end time.
    pub fn graph_series_from_results_for_definition(
        &self,
        definition: DashboardGraphDefinition,
        results: &[SampleResult],
        max_points: usize,
    ) -> Result<Vec<GraphPoint>, ReportError> {
        validate_input_sample_count(results.len(), self.config.limits().max_input_samples())?;
        let policy = if matches!(definition.id, "hitsPerSecond" | "codesPerSecond") {
            GraphTimestampPolicy::Start
        } else {
            GraphTimestampPolicy::End
        };
        let samples = results
            .iter()
            .map(|result| {
                GraphSample::try_from_result_with_timestamp(result, policy)?
                    .ok_or(ReportError::Serialization)
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.graph_series_for_definition(definition, &samples, max_points)
    }

    /// Returns the deterministic JSON dashboard data contract.
    pub fn to_json(&self) -> Result<String, ReportError> {
        self.to_json_with_graph(&[])
    }

    /// Returns dashboard JSON with an explicitly supplied graph projection.
    pub fn to_json_with_graph(&self, graph: &[GraphPoint]) -> Result<String, ReportError> {
        self.to_json_with_graph_and_sections(graph, &DashboardGraphSections::new())
    }

    /// Returns dashboard JSON with both the legacy generic graph projection
    /// and explicitly materialized named graph sections.  Named sections are
    /// serialized from their field-specific payloads; the generic projection
    /// never changes a section's status.
    pub fn to_json_with_graph_and_sections(
        &self,
        graph: &[GraphPoint],
        sections: &DashboardGraphSections,
    ) -> Result<String, ReportError> {
        let mut output = String::new();
        output.push_str("{\"config\":{");
        output.push_str("\"percentile_estimator\":");
        push_json_string(
            &mut output,
            match self.config.percentile_estimator() {
                DashboardPercentileEstimator::Legacy => "LEGACY",
                DashboardPercentileEstimator::R3 => "R_3",
            },
        );
        output.push_str(",\"percentile_window\":");
        output.push_str(&self.config.percentile_window().to_string());
        output.push_str(",\"overall_granularity_millis\":");
        output.push_str(&self.config.overall_granularity_millis().to_string());
        output.push_str("},\"total\":");
        write_metrics_json(&mut output, self.total())?;
        output.push_str(",\"labels\":[");
        for (index, (label, metrics)) in self.labels().enumerate() {
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            output.push_str("\"label\":");
            push_json_string(&mut output, label);
            output.push_str(",\"metrics\":");
            write_metrics_json(&mut output, metrics)?;
            output.push('}');
        }
        output.push_str("],\"graph\":");
        write_graph_points_json(&mut output, graph)?;
        output.push_str(",\"dashboard_sections\":[");
        for (index, section) in DASHBOARD_SECTIONS.iter().enumerate() {
            if index != 0 {
                output.push(',');
            }
            push_json_string(&mut output, section);
        }
        output.push(']');
        output.push_str(",\"planned_graph_inventory\":");
        write_dashboard_graph_sections_json(&mut output, sections)?;
        output.push('}');
        Ok(output)
    }

    /// Alias for [`DashboardReport::to_json`].
    pub fn json(&self) -> Result<String, ReportError> {
        self.to_json()
    }

    /// Returns a deterministic, escaped HTML table for dashboard consumers.
    pub fn to_html(&self) -> Result<String, ReportError> {
        self.to_html_with_graph_sections(&DashboardGraphSections::new())
    }

    /// Returns HTML with truthful named graph-section statuses and payload
    /// identities.  A generic graph slice is not used to claim a named graph
    /// was materialized.
    pub fn to_html_with_graph_sections(
        &self,
        sections: &DashboardGraphSections,
    ) -> Result<String, ReportError> {
        validate_dashboard_metrics_finite(self.total())?;
        for (_, metrics) in self.labels() {
            validate_dashboard_metrics_finite(metrics)?;
        }
        let mut output = String::from(
            "<!doctype html><meta charset=\"utf-8\"><table><thead><tr><th>Label</th><th>Samples</th><th>Successes</th><th>Errors</th><th>Average (ms)</th><th>Min (ms)</th><th>Max (ms)</th><th>Error %</th><th>Error throughput</th><th>Received bytes</th><th>Sent bytes</th></tr></thead><tbody>",
        );
        push_html_row(&mut output, "Total", self.total())?;
        for (label, metrics) in self.labels() {
            push_html_row(&mut output, label, metrics)?;
        }
        output.push_str("</tbody></table>");
        push_dashboard_details_html(&mut output, self.total(), sections)?;
        Ok(output)
    }

    /// Alias for [`DashboardReport::to_html`].
    pub fn html(&self) -> Result<String, ReportError> {
        self.to_html()
    }
}

/// Compatibility name for dashboard data.
pub type Dashboard = DashboardReport;

fn grouped_label(grouping: LabelGrouping, group: Option<&str>, label: &str) -> String {
    match (grouping, group) {
        (LabelGrouping::ThreadGroup, Some(group)) if !group.is_empty() => {
            format!("{group}:{label}")
        }
        _ => label.to_owned(),
    }
}

fn successful_graph_samples(
    samples: &[GraphSample],
    interval: crate::ReportInterval,
    options: GraphAggregationOptions,
) -> Result<Vec<GraphSample>, ReportError> {
    let mut successful = Vec::new();
    for sample in samples {
        let timestamp = sample.timestamp().as_millis();
        if timestamp < interval.start().as_millis()
            || timestamp >= interval.end().as_millis()
            || (options.excludes_transaction_controllers() && sample.is_transaction_controller())
        {
            continue;
        }
        match sample.successful() {
            Some(true) => successful.push(sample.clone()),
            Some(false) => {}
            None => {
                return Err(ReportError::Unsupported {
                    capability: "graph.response_time_percentiles.missing_success",
                });
            }
        }
    }
    Ok(successful)
}

/// Commons Math R_3 uses nearest-rank selection with ties rounded to the
/// nearest even integer. The explicit tie rule avoids inheriting Rust's
/// estimator-independent `f64::round` behavior at half ranks.
fn nearest_even_rank(value: f64) -> usize {
    let lower = value.floor();
    let fraction = value - lower;
    let rounded = if fraction < 0.5 {
        lower
    } else if fraction > 0.5 {
        lower + 1.0
    } else if (lower as u64).is_multiple_of(2) {
        lower
    } else {
        lower + 1.0
    };
    rounded.max(1.0) as usize
}

fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\u{0c}' => output.push_str("\\f"),
            character if character <= '\u{1f}' => {
                use core::fmt::Write;
                let _ = write!(output, "\\u{:04X}", character as u32);
            }
            character => output.push(character),
        }
    }
    output.push('"');
}

fn write_optional_json_number(output: &mut String, value: Option<f64>) -> Result<(), ReportError> {
    match value {
        Some(value) if value.is_finite() => output.push_str(&format!("{value}")),
        Some(_) => return Err(ReportError::Serialization),
        None => output.push_str("null"),
    }
    Ok(())
}

fn format_dashboard_html_number(value: Option<f64>) -> Result<String, ReportError> {
    match value {
        Some(value) if value.is_finite() => Ok(value.to_string()),
        Some(_) => Err(ReportError::Serialization),
        None => Ok(String::new()),
    }
}

fn validate_dashboard_metrics_finite(metrics: &DashboardMetrics) -> Result<(), ReportError> {
    for value in [
        metrics.elapsed_mean(),
        metrics.elapsed_stddev(),
        metrics.elapsed_variance(),
        Some(metrics.error_percentage()),
        Some(metrics.success_percentage()),
        Some(metrics.throughput_per_second()),
        Some(metrics.error_throughput_per_second()),
        Some(metrics.received_bytes_per_second()),
        Some(metrics.sent_bytes_per_second()),
        metrics.apdex().score(),
    ] {
        let _ = format_dashboard_html_number(value)?;
    }
    for percentile in DASHBOARD_SERIALIZED_PERCENTILES {
        let _ = format_dashboard_html_number(metrics.percentile(percentile)?)?;
    }
    Ok(())
}

fn write_metrics_json(output: &mut String, metrics: &DashboardMetrics) -> Result<(), ReportError> {
    validate_dashboard_metrics_finite(metrics)?;
    output.push('{');
    output.push_str("\"sample_count\":");
    output.push_str(&metrics.sample_count().to_string());
    output.push_str(",\"success_count\":");
    output.push_str(&metrics.success_count().to_string());
    output.push_str(",\"error_count\":");
    output.push_str(&metrics.error_count().to_string());
    output.push_str(",\"error_summary_sample_count\":");
    output.push_str(&metrics.error_summary_sample_count().to_string());
    output.push_str(",\"error_summary_error_count\":");
    output.push_str(&metrics.error_summary_error_count().to_string());
    output.push_str(",\"elapsed_count\":");
    output.push_str(&metrics.elapsed_count().to_string());
    output.push_str(",\"average_millis\":");
    write_optional_json_number(output, metrics.elapsed_mean())?;
    output.push_str(",\"min_millis\":");
    match metrics.elapsed_min() {
        Some(value) => output.push_str(&value.to_string()),
        None => output.push_str("null"),
    }
    output.push_str(",\"max_millis\":");
    match metrics.elapsed_max() {
        Some(value) => output.push_str(&value.to_string()),
        None => output.push_str("null"),
    }
    output.push_str(",\"stddev_millis\":");
    write_optional_json_number(output, metrics.elapsed_stddev())?;
    output.push_str(",\"elapsed_variance_population_millis2\":");
    write_optional_json_number(output, metrics.summary().elapsed_variance())?;
    output.push_str(",\"error_percentage\":");
    write_optional_json_number(output, Some(metrics.error_percentage()))?;
    output.push_str(",\"throughput_per_second\":");
    write_optional_json_number(output, Some(metrics.throughput_per_second()))?;
    output.push_str(",\"error_throughput_per_second\":");
    write_optional_json_number(output, Some(metrics.error_throughput_per_second()))?;
    output.push_str(",\"received_bytes\":");
    output.push_str(&metrics.received_bytes().to_string());
    output.push_str(",\"sent_bytes\":");
    output.push_str(&metrics.sent_bytes().to_string());
    output.push_str(",\"received_bytes_per_second\":");
    write_optional_json_number(output, Some(metrics.received_bytes_per_second()))?;
    output.push_str(",\"sent_bytes_per_second\":");
    write_optional_json_number(output, Some(metrics.sent_bytes_per_second()))?;
    output.push_str(",\"success_percentage\":");
    write_optional_json_number(output, Some(metrics.success_percentage()))?;
    output.push_str(",\"apdex\":{");
    output.push_str("\"satisfied\":");
    output.push_str(&metrics.apdex().satisfied().to_string());
    output.push_str(",\"tolerated\":");
    output.push_str(&metrics.apdex().tolerated().to_string());
    output.push_str(",\"frustrated\":");
    output.push_str(&metrics.apdex().frustrated().to_string());
    output.push_str(",\"score\":");
    write_optional_json_number(output, metrics.apdex().score())?;
    output.push_str("},\"percentile_sample_count\":");
    output.push_str(&metrics.percentile_sample_count().to_string());
    output.push_str(",\"window_observations\":[");
    for (index, value) in metrics.percentile_window_observations().iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str(&value.to_string());
    }
    output.push_str("],\"percentiles\":[");
    let values = metrics.percentiles()?;
    for (index, value) in values.into_iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        write_optional_json_number(output, value)?;
    }
    output.push_str("],\"percentiles_millis\":{");
    write_dashboard_percentile_map(output, metrics, false)?;
    output.push_str("},\"percentiles_millis_rounded\":{");
    write_dashboard_percentile_map(output, metrics, true)?;
    output.push_str("},\"error_counts\":[");
    write_error_list_json(output, &metrics.error_counts());
    output.push_str("],\"errors\":[");
    write_error_list_json(output, &metrics.error_counts());
    output.push_str("],\"top_errors\":[");
    write_error_list_json(output, &metrics.top_errors());
    output.push(']');
    output.push('}');
    Ok(())
}

const DASHBOARD_SERIALIZED_PERCENTILES: [f64; 8] = [0.0, 25.0, 50.0, 75.0, 90.0, 95.0, 99.0, 100.0];

fn write_dashboard_percentile_map(
    output: &mut String,
    metrics: &DashboardMetrics,
    rounded: bool,
) -> Result<(), ReportError> {
    for (index, percentile) in DASHBOARD_SERIALIZED_PERCENTILES.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        push_json_string(output, &format_percentile_key(*percentile));
        output.push(':');
        let value = if rounded {
            metrics
                .percentile_millis(*percentile)?
                .map(|value| value as f64)
        } else {
            metrics.percentile(*percentile)?
        };
        write_optional_json_number(output, value)?;
    }
    Ok(())
}

fn format_percentile_key(percentile: f64) -> String {
    if percentile.fract() == 0.0 {
        format!("{percentile:.0}")
    } else {
        percentile.to_string()
    }
}

fn write_dashboard_graph_sections_json(
    output: &mut String,
    sections: &DashboardGraphSections,
) -> Result<(), ReportError> {
    output.push('[');
    for (index, definition) in DASHBOARD_GRAPH_INVENTORY.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push('{');
        output.push_str("\"id\":");
        push_json_string(output, definition.id);
        output.push_str(",\"title\":");
        push_json_string(output, definition.title);
        output.push_str(",\"exclude_transaction_controllers\":");
        output.push_str(if definition.exclude_transaction_controllers {
            "true"
        } else {
            "false"
        });
        output.push_str(",\"source_fields\":[");
        for (field_index, field) in graph_source_fields(definition.id).iter().enumerate() {
            if field_index != 0 {
                output.push(',');
            }
            push_json_string(output, field);
        }
        output.push(']');
        output.push_str(",\"status\":");
        let section = sections
            .section(definition.id)
            .ok_or(ReportError::Serialization)?;
        push_json_string(output, dashboard_graph_status_name(section.status()));
        if let Some(error) = section.error() {
            output.push_str(",\"error_code\":");
            push_json_string(output, error.stable_code());
            output.push_str(",\"error\":");
            push_json_string(output, &error.to_string());
        }
        output.push_str(",\"payload\":");
        if let Some(payload) = section.payload() {
            write_dashboard_graph_payload_json(output, payload)?;
        } else {
            output.push_str("null");
        }
        // Keep the old field present for consumers that only inspect the
        // inventory envelope.  The actual named data is always in `payload`.
        output.push_str(",\"points\":[]");
        output.push('}');
    }
    output.push(']');
    Ok(())
}

fn dashboard_graph_status_name(status: DashboardGraphStatus) -> &'static str {
    match status {
        DashboardGraphStatus::Materialized => "materialized",
        DashboardGraphStatus::NotMaterialized => "planned_not_materialized",
        DashboardGraphStatus::Unsupported => "unsupported",
    }
}

fn write_graph_bucket_json(output: &mut String, bucket: GraphBucket) {
    output.push_str("\"start_ms\":");
    output.push_str(&bucket.start().as_millis().to_string());
    output.push_str(",\"end_ms_exclusive\":");
    output.push_str(&bucket.end().as_millis().to_string());
}

fn write_dashboard_graph_payload_json(
    output: &mut String,
    payload: &DashboardGraphPayload,
) -> Result<(), ReportError> {
    let target = output;
    let mut encoded = String::new();
    let output = &mut encoded;
    output.push('{');
    output.push_str("\"kind\":");
    push_json_string(output, payload.id());
    output.push_str(",\"points\":[");
    match payload {
        DashboardGraphPayload::ResponseTimePercentiles(points)
        | DashboardGraphPayload::SuccessfulResponseTimePercentiles(points) => {
            for (index, point) in points.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push('{');
                write_graph_bucket_json(output, point.bucket());
                output.push_str(",\"sample_count\":");
                output.push_str(&point.sample_count().to_string());
                output.push_str(",\"percentiles\":[");
                for (percentile_index, (percentile, value)) in
                    point.percentiles().iter().enumerate()
                {
                    if percentile_index != 0 {
                        output.push(',');
                    }
                    output.push('{');
                    output.push_str("\"percentile\":");
                    write_optional_json_number(output, Some(*percentile))?;
                    output.push_str(",\"value_millis\":");
                    write_optional_json_number(output, *value)?;
                    output.push('}');
                }
                output.push_str("]}");
            }
        }
        DashboardGraphPayload::ResponseTimeDistribution(points) => {
            for (index, point) in points.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push('{');
                output.push_str("\"elapsed_millis\":");
                output.push_str(&point.elapsed_millis().to_string());
                output.push_str(",\"sample_count\":");
                output.push_str(&point.sample_count().to_string());
                output.push('}');
            }
        }
        DashboardGraphPayload::ActiveThreads(points) => {
            for (index, point) in points.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push('{');
                write_graph_bucket_json(output, point.bucket());
                output.push_str(",\"sample_count\":");
                output.push_str(&point.sample_count().to_string());
                output.push_str(",\"group_threads\":");
                write_optional_json_u64(output, point.group_threads());
                output.push_str(",\"all_threads\":");
                write_optional_json_u64(output, point.all_threads());
                output.push('}');
            }
        }
        DashboardGraphPayload::TimeVsThreads(points) => {
            for (index, point) in points.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push('{');
                output.push_str("\"timestamp_ms\":");
                output.push_str(&point.timestamp().as_millis().to_string());
                output.push_str(",\"all_threads\":");
                output.push_str(&point.all_threads().to_string());
                output.push('}');
            }
        }
        DashboardGraphPayload::BytesThroughput(points) => {
            for (index, point) in points.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push('{');
                write_graph_bucket_json(output, point.bucket());
                output.push_str(",\"sample_count\":");
                output.push_str(&point.sample_count().to_string());
                output.push_str(",\"received_bytes\":");
                output.push_str(&point.received_bytes().to_string());
                output.push_str(",\"sent_bytes\":");
                output.push_str(&point.sent_bytes().to_string());
                output.push_str(",\"received_bytes_per_second\":");
                write_optional_json_number(output, Some(point.received_bytes_per_second()))?;
                output.push_str(",\"sent_bytes_per_second\":");
                write_optional_json_number(output, Some(point.sent_bytes_per_second()))?;
                output.push('}');
            }
        }
        DashboardGraphPayload::ResponseTimes(points) => {
            for (index, point) in points.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push('{');
                write_graph_bucket_json(output, point.bucket());
                output.push_str(",\"sample_count\":");
                output.push_str(&point.sample_count().to_string());
                output.push_str(",\"elapsed_count\":");
                output.push_str(&point.elapsed_count().to_string());
                output.push_str(",\"elapsed_sum_millis\":");
                write_optional_json_number(output, Some(point.elapsed_sum_millis()))?;
                output.push_str(",\"elapsed_mean_millis\":");
                write_optional_json_number(output, point.elapsed_mean_millis())?;
                output.push_str(",\"elapsed_variance_population_millis2\":");
                write_optional_json_number(output, point.elapsed_variance_millis2())?;
                output.push_str(",\"elapsed_stddev_millis\":");
                write_optional_json_number(output, point.elapsed_stddev_millis())?;
                output.push('}');
            }
        }
        DashboardGraphPayload::SyntheticResponseTimeDistribution(points) => {
            for (index, point) in points.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push('{');
                output.push_str("\"elapsed_millis\":");
                output.push_str(&point.elapsed_millis().to_string());
                output.push_str(",\"satisfied\":");
                output.push_str(&point.satisfied().to_string());
                output.push_str(",\"tolerated\":");
                output.push_str(&point.tolerated().to_string());
                output.push_str(",\"frustrated\":");
                output.push_str(&point.frustrated().to_string());
                output.push('}');
            }
        }
        DashboardGraphPayload::Latencies(points) => {
            for (index, point) in points.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push('{');
                write_graph_bucket_json(output, point.bucket());
                output.push_str(",\"sample_count\":");
                output.push_str(&point.sample_count().to_string());
                output.push_str(",\"latency_count\":");
                output.push_str(&point.latency_count().to_string());
                output.push_str(",\"latency_sum_millis\":");
                write_optional_json_number(output, Some(point.latency_sum_millis()))?;
                output.push_str(",\"latency_mean_millis\":");
                write_optional_json_number(output, point.latency_mean_millis())?;
                output.push_str(",\"latency_variance_population_millis2\":");
                write_optional_json_number(output, point.latency_variance_millis2())?;
                output.push_str(",\"latency_stddev_millis\":");
                write_optional_json_number(output, point.latency_stddev_millis())?;
                output.push_str(",\"latency_min_millis\":");
                write_optional_json_u64(output, point.latency_min_millis());
                output.push_str(",\"latency_max_millis\":");
                write_optional_json_u64(output, point.latency_max_millis());
                output.push('}');
            }
        }
        DashboardGraphPayload::ConnectTimes(points) => {
            for (index, point) in points.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push('{');
                write_graph_bucket_json(output, point.bucket());
                output.push_str(",\"sample_count\":");
                output.push_str(&point.sample_count().to_string());
                output.push_str(",\"connect_count\":");
                output.push_str(&point.connect_count().to_string());
                output.push_str(",\"connect_sum_millis\":");
                write_optional_json_number(output, Some(point.connect_sum_millis()))?;
                output.push_str(",\"connect_mean_millis\":");
                write_optional_json_number(output, point.connect_mean_millis())?;
                output.push_str(",\"connect_variance_population_millis2\":");
                write_optional_json_number(output, point.connect_variance_millis2())?;
                output.push_str(",\"connect_stddev_millis\":");
                write_optional_json_number(output, point.connect_stddev_millis())?;
                output.push_str(",\"connect_min_millis\":");
                write_optional_json_u64(output, point.connect_min_millis());
                output.push_str(",\"connect_max_millis\":");
                write_optional_json_u64(output, point.connect_max_millis());
                output.push('}');
            }
        }
        DashboardGraphPayload::ResponseTimeVsRequest(points) => {
            for (index, point) in points.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push('{');
                output.push_str("\"timestamp_ms\":");
                output.push_str(&point.timestamp().as_millis().to_string());
                output.push_str(",\"elapsed_millis\":");
                output.push_str(&point.elapsed_millis().to_string());
                output.push_str(",\"successful\":");
                match point.successful() {
                    Some(value) => output.push_str(if value { "true" } else { "false" }),
                    None => output.push_str("null"),
                }
                output.push('}');
            }
        }
        DashboardGraphPayload::LatencyVsRequest(points) => {
            for (index, point) in points.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push('{');
                output.push_str("\"timestamp_ms\":");
                output.push_str(&point.timestamp().as_millis().to_string());
                output.push_str(",\"latency_millis\":");
                output.push_str(&point.latency_millis().to_string());
                output.push('}');
            }
        }
        DashboardGraphPayload::HitsPerSecond(points) => {
            for (index, point) in points.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push('{');
                write_graph_bucket_json(output, point.bucket());
                output.push_str(",\"sample_count\":");
                output.push_str(&point.sample_count().to_string());
                output.push_str(",\"per_second\":");
                write_optional_json_number(output, Some(point.per_second()))?;
                output.push('}');
            }
        }
        DashboardGraphPayload::CodesPerSecond(points) => {
            for (index, point) in points.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push('{');
                write_graph_bucket_json(output, point.bucket());
                output.push_str(",\"response_code\":");
                push_json_string(output, point.response_code());
                output.push_str(",\"response_message\":");
                push_json_string(output, point.response_message());
                output.push_str(",\"sample_count\":");
                output.push_str(&point.sample_count().to_string());
                output.push_str(",\"error_count\":");
                output.push_str(&point.error_count().to_string());
                output.push_str(",\"per_second\":");
                write_optional_json_number(output, Some(point.per_second()))?;
                output.push('}');
            }
        }
        DashboardGraphPayload::TotalTps(points) => {
            for (index, point) in points.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push('{');
                write_graph_bucket_json(output, point.bucket());
                output.push_str(",\"transaction_count\":");
                output.push_str(&point.transaction_count().to_string());
                output.push_str(",\"per_second\":");
                write_optional_json_number(output, Some(point.per_second()))?;
                output.push('}');
            }
        }
        DashboardGraphPayload::TransactionsPerSecond(points) => {
            for (index, point) in points.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push('{');
                write_graph_bucket_json(output, point.bucket());
                output.push_str(",\"label\":");
                push_json_string(output, point.label());
                output.push_str(",\"transaction_count\":");
                output.push_str(&point.transaction_count().to_string());
                output.push_str(",\"per_second\":");
                write_optional_json_number(output, Some(point.per_second()))?;
                output.push('}');
            }
        }
    }
    output.push_str("]}");
    // The local buffer above ensures a nonfinite field cannot leave a partial
    // graph payload in the caller's output.
    target.push_str(&encoded);
    Ok(())
}

fn write_optional_json_u64(output: &mut String, value: Option<u64>) {
    match value {
        Some(value) => output.push_str(&value.to_string()),
        None => output.push_str("null"),
    }
}

fn write_error_list_json(output: &mut String, values: &[TopError]) {
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push('{');
        output.push_str("\"key\":");
        push_json_string(output, &value.key().jmeter_key());
        output.push(',');
        output.push_str("\"response_code\":");
        push_json_string(output, value.key().code());
        output.push_str(",\"message\":");
        push_json_string(output, value.key().message());
        output.push_str(",\"count\":");
        output.push_str(&value.count().to_string());
        output.push('}');
    }
}

fn push_html_escaped(output: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            character if character.is_control() => {
                use core::fmt::Write;
                let _ = write!(output, "&#x{:x};", character as u32);
            }
            character => output.push(character),
        }
    }
}

fn push_html_row(
    output: &mut String,
    label: &str,
    metrics: &DashboardMetrics,
) -> Result<(), ReportError> {
    let values = [
        metrics.sample_count().to_string(),
        metrics.success_count().to_string(),
        metrics.error_count().to_string(),
        format_dashboard_html_number(metrics.elapsed_mean())?,
        metrics
            .elapsed_min()
            .map_or_else(String::new, |value| value.to_string()),
        metrics
            .elapsed_max()
            .map_or_else(String::new, |value| value.to_string()),
        format_dashboard_html_number(Some(metrics.error_percentage()))?,
        format_dashboard_html_number(Some(metrics.error_throughput_per_second()))?,
        metrics.received_bytes().to_string(),
        metrics.sent_bytes().to_string(),
    ];
    output.push_str("<tr><td>");
    push_html_escaped(output, label);
    for value in values {
        output.push_str("</td><td>");
        output.push_str(&value);
    }
    output.push_str("</td></tr>");
    Ok(())
}

fn push_dashboard_details_html(
    output: &mut String,
    metrics: &DashboardMetrics,
    sections: &DashboardGraphSections,
) -> Result<(), ReportError> {
    let score = format_dashboard_html_number(metrics.apdex().score())?;
    let percentiles = DASHBOARD_SERIALIZED_PERCENTILES
        .into_iter()
        .map(|percentile| {
            metrics
                .percentile(percentile)
                .and_then(format_dashboard_html_number)
                .map(|value| (percentile, value))
        })
        .collect::<Result<Vec<_>, _>>()?;
    output.push_str("<section id=\"apdex\"><h2>APDEX</h2><p>Satisfied: ");
    output.push_str(&metrics.apdex().satisfied().to_string());
    output.push_str("; Tolerated: ");
    output.push_str(&metrics.apdex().tolerated().to_string());
    output.push_str("; Frustrated: ");
    output.push_str(&metrics.apdex().frustrated().to_string());
    output.push_str("; Score: ");
    output.push_str(&score);
    output.push_str("</p></section><section id=\"percentiles\"><h2>Percentiles</h2><ul>");
    for (percentile, value) in percentiles {
        output.push_str("<li>p");
        output.push_str(&format_percentile_key(percentile));
        output.push_str(": ");
        output.push_str(&value);
        output.push_str(" ms</li>");
    }
    output.push_str("</ul></section><section id=\"errors\"><h2>Errors</h2><ul>");
    for error in metrics.error_counts() {
        output.push_str("<li>");
        push_dashboard_error_html(output, error.key());
        output.push_str(": ");
        output.push_str(&error.count().to_string());
        output.push_str("</li>");
    }
    output.push_str("</ul></section><section id=\"top-errors\"><h2>Top errors</h2><ul>");
    for error in metrics.top_errors() {
        output.push_str("<li>");
        push_dashboard_error_html(output, error.key());
        output.push_str(": ");
        output.push_str(&error.count().to_string());
        output.push_str("</li>");
    }
    output.push_str("</ul></section><section id=\"graphs\"><h2>Graphs</h2><ul>");
    for definition in DASHBOARD_GRAPH_INVENTORY {
        let section = sections
            .section(definition.id)
            .ok_or(ReportError::Serialization)?;
        output.push_str("<li data-graph-id=\"");
        push_html_escaped(output, definition.id);
        output.push_str("\" data-status=\"");
        push_html_escaped(output, dashboard_graph_status_name(section.status()));
        if let Some(payload) = section.payload() {
            output.push_str("\" data-payload-kind=\"");
            push_html_escaped(output, payload.id());
        }
        output.push_str("\">");
        push_html_escaped(output, definition.title);
        output.push_str(" (status: ");
        push_html_escaped(output, dashboard_graph_status_name(section.status()));
        if let Some(error) = section.error() {
            output.push_str("; error: ");
            push_html_escaped(output, error.stable_code());
        }
        output.push_str(")</li>");
    }
    output.push_str("</ul></section>");
    Ok(())
}

fn push_dashboard_error_html(output: &mut String, key: &crate::ErrorKey) {
    if key.code() == "Assertion failed" {
        if key.message().is_empty() {
            output.push_str(key.code());
        } else {
            output.push_str(key.message());
        }
        return;
    }
    push_html_escaped(output, key.code());
    if !key.message().is_empty() {
        output.push('/');
        output.push_str(key.message());
    }
}

#[cfg(test)]
// The fixture constructors use unwrap only after asserting that their fixed
// constants are valid; this keeps the cases readable and deterministic.
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{
        AggregateLimits, DashboardPercentileEstimator, PercentileLevel, SampleMetadata,
        SummaryConfig, SummaryReport,
    };
    use jmeter_rs_results::{ElapsedTime, ErrorCount, SampleCount};

    fn config() -> DashboardConfig {
        let interval = crate::ReportInterval::from_millis(0, 1_000).unwrap();
        DashboardConfig::new(interval)
            .unwrap()
            .with_percentile_window(3)
            .unwrap()
    }

    fn sample(label: &str, elapsed: u64, success: bool, code: &str, message: &str) -> SampleResult {
        let mut result = SampleResult::new(label);
        assert!(
            result
                .set_elapsed(Some(ElapsedTime::from_millis(elapsed)))
                .is_ok()
        );
        result.set_successful(success);
        result.set_response_code_text(code);
        result.set_response_message_text(message);
        result.set_sample_count(Some(SampleCount::ONE));
        result.set_error_count(Some(if success {
            ErrorCount::ZERO
        } else {
            ErrorCount::from_u64(1)
        }));
        result
    }

    fn report_fixture_results() -> Vec<SampleResult> {
        let mut search_batch = sample("api/search", 600, false, "503", "overload");
        search_batch.set_sample_count(Some(SampleCount::from_u64(2)));
        search_batch.set_error_count(Some(ErrorCount::from_u64(1)));
        let mut health = SampleResult::new("api/health");
        health.set_successful(true);
        health.set_response_code_text("204");
        health.set_response_message_text("No Content");
        health.set_error_count(Some(ErrorCount::ZERO));
        vec![
            sample("api/login", 100, true, "200", "OK"),
            sample("api/search", 500, true, "200", "OK"),
            search_batch,
            sample("api/write", 1500, true, "200", "OK"),
            sample("api/write", 1501, false, "409", "conflict"),
            health,
            sample("api/cache", 2500, true, "200", "OK"),
        ]
    }

    fn assert_json_structure(document: &str) {
        let mut stack = Vec::new();
        let mut in_string = false;
        let mut escaped = false;
        for character in document.chars() {
            if in_string {
                if escaped {
                    escaped = false;
                } else if character == '\\' {
                    escaped = true;
                } else if character == '"' {
                    in_string = false;
                }
                continue;
            }
            match character {
                '"' => in_string = true,
                '{' | '[' => stack.push(character),
                '}' => assert_eq!(stack.pop(), Some('{'), "unbalanced JSON object"),
                ']' => assert_eq!(stack.pop(), Some('['), "unbalanced JSON array"),
                _ => {}
            }
        }
        assert!(!in_string && !escaped, "unterminated JSON string");
        assert!(stack.is_empty(), "unbalanced JSON delimiters");
    }

    #[test]
    fn dashboard_uses_fifo_window_and_interpolation() {
        let mut report = DashboardReport::new(config());
        for result in [
            sample("alpha", 100, true, "200", "ok"),
            sample("alpha", 600, true, "200", "ok"),
            sample("beta", 200, false, "500", "bad"),
            sample("beta", 600, false, "500", "bad"),
        ] {
            assert!(report.add_result(&result).is_ok());
        }
        let total = report.total();
        assert_eq!(total.sample_count(), 4);
        assert_eq!(total.percentile_sample_count(), 3);
        assert_eq!(total.percentile_millis(50.0), Ok(Some(600)));
        assert_eq!(total.percentile(25.0), Ok(Some(200.0)));
        assert_eq!(total.percentile_millis(25.0), Ok(Some(200)));
        assert_eq!(total.elapsed_mean(), Some(375.0));
        assert_eq!(total.apdex().frustrated(), 2);
    }

    #[test]
    fn dashboard_limits_labels_and_merges_complete_stream() {
        let interval = crate::ReportInterval::from_millis(0, 1_000).unwrap();
        let limits = AggregateLimits::new(1, 5, 3).unwrap();
        let config = DashboardConfig::new(interval)
            .unwrap()
            .with_percentile_window(2)
            .unwrap()
            .with_limits(limits)
            .unwrap();
        let mut left = DashboardReport::new(config);
        let mut right = DashboardReport::new(config);
        assert!(
            left.add_result(&sample("same", 100, true, "200", "ok"))
                .is_ok()
        );
        assert!(
            right
                .add_result(&sample("same", 300, true, "200", "ok"))
                .is_ok()
        );
        assert!(left.merge(&right).is_ok());
        assert_eq!(left.total().sample_count(), 2);
        assert_eq!(left.total().percentile_sample_count(), 2);
        assert_eq!(left.total().percentile_millis(50.0), Ok(Some(200)));
        let before = left.clone();
        assert!(matches!(
            left.add_result(&sample("new", 400, true, "200", "ok")),
            Err(ReportError::LimitExceeded {
                resource: ReportLimit::Labels,
                ..
            })
        ));
        assert_eq!(left, before);
    }

    #[test]
    fn dashboard_rows_are_unweighted_and_estimator_is_configurable() {
        let interval = crate::ReportInterval::from_millis(0, 1_000).unwrap();
        let config = DashboardConfig::new(interval)
            .unwrap()
            .with_percentile_window(8)
            .unwrap()
            .with_percentile_estimator(DashboardPercentileEstimator::R3)
            .with_decimal_percentiles([12.5, 50.5, 99.5])
            .unwrap();
        assert_eq!(
            config.percentile_levels()[0],
            PercentileLevel::from_percent(12.5).unwrap()
        );
        let mut result = sample("batch", 100, true, "200", "ok");
        result.set_sample_count(Some(SampleCount::from_u64(8)));
        result.set_error_count(Some(ErrorCount::ZERO));
        let mut report = DashboardReport::new(config);
        assert!(report.add_result(&result).is_ok());
        assert_eq!(report.total().sample_count(), 1);
        assert_eq!(report.total().percentile_sample_count(), 1);
        assert_eq!(
            report.total().percentile_estimator(),
            DashboardPercentileEstimator::R3
        );
        assert_eq!(
            report.total().percentiles(),
            Ok([Some(100.0), Some(100.0), Some(100.0)])
        );

        let mut values = DashboardReport::new(
            DashboardConfig::new(interval)
                .unwrap()
                .with_percentile_window(8)
                .unwrap()
                .with_percentile_estimator(DashboardPercentileEstimator::R3),
        );
        for (label, elapsed) in [("one", 10), ("two", 20), ("three", 30)] {
            assert!(
                values
                    .add_result(&sample(label, elapsed, true, "200", "ok"))
                    .is_ok()
            );
        }
        assert_eq!(values.total().percentile_millis(34.0), Ok(Some(10)));
    }

    #[test]
    fn dashboard_controller_stats_and_error_consumer_exclude_but_apdex_keeps_overall_row() {
        let mut report = DashboardReport::new(config());
        let controller = sample("controller", 100, false, "500", "controller");
        assert!(
            report
                .add_result_with_metadata(&controller, SampleMetadata::transaction_controller())
                .is_ok()
        );
        assert_eq!(report.total().error_count(), 0);
        assert_eq!(report.total().sample_count(), 0);
        assert_eq!(report.total().apdex().satisfied(), 0);
        assert_eq!(report.total().apdex().tolerated(), 0);
        assert_eq!(report.total().apdex().frustrated(), 1);
        assert_eq!(report.total().error_summary_sample_count(), 0);
        assert_eq!(report.total().error_summary_error_count(), 0);
        assert_eq!(
            report.label("controller").map(|row| row.error_count()),
            Some(1)
        );
        assert!(report.total().error_counts().is_empty());
        assert!(report.total().top_errors().is_empty());

        let mut include_top5 =
            DashboardReport::new(config().with_exclude_transaction_controllers_from_top5(false));
        assert!(
            include_top5
                .add_result_with_metadata(&controller, SampleMetadata::transaction_controller())
                .is_ok()
        );
        assert_eq!(include_top5.total().sample_count(), 0);
        // JMeter's Top5ErrorsBySamplerConsumer always omits controllers from
        // its overall result. The configuration flag only controls the
        // per-label consumer, which is retained on the label row above.
        assert!(include_top5.total().top_errors().is_empty());
        assert_eq!(
            include_top5
                .label("controller")
                .map(|row| row.top_errors()[0].count()),
            Some(1)
        );
    }

    #[test]
    fn dashboard_named_graph_policy_excludes_only_declared_controllers() {
        let report = DashboardReport::new(
            config()
                .with_overall_granularity_millis(2_000)
                .unwrap_or_else(|_| panic!("valid granularity")),
        );
        let controller = GraphSample::new(
            jmeter_rs_results::WallTimestamp::from_millis(100),
            Some(10),
            false,
            1,
            1,
        )
        .with_transaction_controller(true);
        let ordinary = GraphSample::new(
            jmeter_rs_results::WallTimestamp::from_millis(100),
            Some(20),
            false,
            2,
            2,
        );
        let definition = DASHBOARD_GRAPH_INVENTORY
            .iter()
            .find(|definition| definition.id == "bytesThroughputOverTime")
            .copied()
            .unwrap_or_else(|| panic!("declared graph"));
        let points = report
            .graph_series_for_definition(definition, &[controller.clone(), ordinary.clone()], 4)
            .unwrap_or_else(|_| panic!("valid graph"));
        assert_eq!(points[0].sample_count(), 1);
        let definition = DASHBOARD_GRAPH_INVENTORY[0];
        let points = report
            .graph_series_for_definition(definition, &[controller, ordinary], 4)
            .unwrap_or_else(|_| panic!("valid graph"));
        assert_eq!(points[0].sample_count(), 2);
    }

    #[test]
    fn dashboard_output_is_deterministic_and_escaped() {
        let mut report = DashboardReport::new(config());
        assert!(
            report
                .add_result(&sample("a<\"b", 10, true, "200", "ok"))
                .is_ok()
        );
        let json = report.to_json().unwrap_or_else(|_| panic!("valid JSON"));
        assert!(json.contains("\"label\":\"a<\\\"b\""));
        assert_eq!(json, report.json().unwrap_or_else(|_| panic!("valid JSON")));
        let html = report.to_html().unwrap_or_else(|_| panic!("valid HTML"));
        assert!(html.contains("a&lt;&quot;b"));
        assert_eq!(html, report.html().unwrap_or_else(|_| panic!("valid HTML")));
    }

    #[test]
    fn dashboard_config_rejects_zero_granularity() {
        let interval = crate::ReportInterval::from_millis(0, 1_000).unwrap();
        assert_eq!(
            DashboardConfig::new(interval)
                .unwrap()
                .with_overall_granularity_millis(0),
            Err(ReportError::InvalidConfig {
                field: crate::ConfigField::OverallGranularity,
            })
        );
        assert_eq!(
            DashboardConfig::new(interval)
                .unwrap()
                .with_overall_granularity_millis(1_000),
            Err(ReportError::InvalidConfig {
                field: crate::ConfigField::OverallGranularity,
            })
        );
    }

    #[test]
    fn dashboard_fixture_is_row_based_with_zero_elapsed_and_legacy_window() {
        let interval = crate::ReportInterval::from_millis(1_704_067_200_000, 1_704_067_210_000)
            .unwrap_or_else(|_| panic!("valid fixture interval"));
        let config = DashboardConfig::new(interval)
            .unwrap_or_else(|_| panic!("valid config"))
            .with_percentile_window(5)
            .unwrap_or_else(|_| panic!("valid window"))
            .with_overall_granularity_millis(10_000)
            .unwrap_or_else(|_| panic!("valid granularity"));
        let mut report = DashboardReport::new(config);
        for result in report_fixture_results() {
            assert!(report.add_result(&result).is_ok());
        }
        let total = report.total();
        assert_eq!(total.sample_count(), 7);
        assert_eq!(total.success_count(), 5);
        assert_eq!(total.error_count(), 2);
        assert_eq!(total.elapsed_count(), 7);
        assert_eq!(total.elapsed_min(), Some(0));
        assert_eq!(total.elapsed_max(), Some(2500));
        assert_eq!(total.elapsed_mean(), Some(957.2857142857143));
        assert_eq!(total.elapsed_variance(), Some(708318.4897959183));
        assert!((total.elapsed_stddev().unwrap_or_default() - 841.6165931087138).abs() < 1e-9);
        assert_eq!(total.apdex().satisfied(), 3);
        assert_eq!(total.apdex().tolerated(), 1);
        assert_eq!(total.apdex().frustrated(), 3);
        assert_eq!(total.percentile_sample_count(), 5);
        assert_eq!(total.percentile_millis(50.0), Ok(Some(1500)));
        assert_eq!(total.percentile(75.0), Ok(Some(2000.5)));
        assert_eq!(total.percentile_millis(90.0), Ok(Some(2500)));
        let search = report
            .label("api/search")
            .unwrap_or_else(|| panic!("fixture search row"));
        assert_eq!(search.sample_count(), 2);
        assert_eq!(search.elapsed_mean(), Some(550.0));
        assert_eq!(search.percentile_millis(50.0), Ok(Some(550)));
    }

    #[test]
    fn dashboard_r3_uses_nearest_even_half_ranks() {
        let interval = crate::ReportInterval::from_millis(0, 1_000).unwrap();
        let config = DashboardConfig::new(interval)
            .unwrap()
            .with_percentile_window(8)
            .unwrap()
            .with_percentile_estimator(DashboardPercentileEstimator::R3);
        let mut report = DashboardReport::new(config);
        for (label, elapsed) in [("one", 10), ("two", 20), ("three", 30)] {
            assert!(
                report
                    .add_result(&sample(label, elapsed, true, "200", "ok"))
                    .is_ok()
            );
        }
        assert_eq!(report.total().percentile_millis(50.0), Ok(Some(20)));
        assert_eq!(
            report.total().percentile_millis(16.666666666666668),
            Ok(Some(10))
        );

        let mut five = DashboardReport::new(
            DashboardConfig::new(interval)
                .unwrap()
                .with_percentile_window(8)
                .unwrap()
                .with_percentile_estimator(DashboardPercentileEstimator::R3),
        );
        for (label, elapsed) in [("a", 10), ("b", 20), ("c", 30), ("d", 40), ("e", 50)] {
            assert!(
                five.add_result(&sample(label, elapsed, true, "200", "ok"))
                    .is_ok()
            );
        }
        // n=5, p=.5 gives rank 2.5; nearest-even chooses rank 2, not rank 3.
        assert_eq!(five.total().percentile_millis(50.0), Ok(Some(20)));
        // n=5, p=.9 gives rank 4.5; nearest-even chooses rank 4.
        assert_eq!(five.total().percentile_millis(90.0), Ok(Some(40)));

        let mut decimal = DashboardReport::new(
            DashboardConfig::new(interval)
                .unwrap()
                .with_percentile_window(8)
                .unwrap()
                .with_percentile_estimator(DashboardPercentileEstimator::R3),
        );
        for (label, elapsed) in [("a", 10), ("b", 20), ("c", 30), ("d", 40)] {
            assert!(
                decimal
                    .add_result(&sample(label, elapsed, true, "200", "ok"))
                    .is_ok()
            );
        }
        // Decimal p=.375 gives rank 1.5; lower rank 1 is odd, so rank 2 wins.
        assert_eq!(decimal.total().percentile_millis(37.5), Ok(Some(20)));
    }

    #[test]
    fn dashboard_serialization_is_complete_and_typed() {
        let mut report = DashboardReport::new(config());
        assert!(
            report
                .add_result(&sample("row", 10, true, "200", "ok"))
                .is_ok()
        );
        let json = report.to_json().unwrap_or_else(|_| panic!("valid JSON"));
        for field in [
            "\"success_count\":1",
            "\"elapsed_count\":1",
            "\"received_bytes\":0",
            "\"error_throughput_per_second\":0",
            "\"graph\":[]",
            "\"dashboard_sections\":[\"apdex\",\"request_summary\",\"statistics\",\"errors\",\"top_errors\",\"time_series\",\"response_time_distribution\"]",
            "\"planned_graph_inventory\":[",
            "\"status\":\"planned_not_materialized\"",
        ] {
            assert!(json.contains(field), "missing {field}");
        }
        assert!(report.to_html().is_ok());
    }

    #[test]
    fn dashboard_html_fails_closed_on_nonfinite_variance() {
        let mut report = DashboardReport::new(config());
        for elapsed in [1_000_000_000_000_u64, 1_000_000_000_001_u64] {
            assert!(
                report
                    .add_result(&sample("unstable", elapsed, true, "200", "ok"))
                    .is_ok()
            );
        }
        assert_eq!(report.to_html(), Err(ReportError::Serialization));
    }

    #[test]
    fn dashboard_named_graph_materialization_is_distinct_and_truthful() {
        let interval = crate::ReportInterval::from_millis(0, 5_000).unwrap();
        let config = DashboardConfig::new(interval)
            .unwrap()
            .with_percentile_window(8)
            .unwrap()
            .with_overall_granularity_millis(2_000)
            .unwrap();
        let report = DashboardReport::new(config);
        let sample = GraphSample::new(
            jmeter_rs_results::WallTimestamp::from_millis(100),
            Some(100),
            false,
            400,
            40,
        )
        .with_latency(Some(50))
        .with_connect(Some(25))
        .with_group_threads(Some(3))
        .with_all_threads(Some(8))
        .with_label("GET /items")
        .with_response_code("200")
        .with_response_message("OK")
        .with_success(Some(true));

        let payload = report
            .materialize_graph_section("latenciesOverTime", std::slice::from_ref(&sample), 8)
            .unwrap_or_else(|_| panic!("latency payload"));
        assert!(matches!(payload, DashboardGraphPayload::Latencies(_)));
        let sections = report.materialize_graph_sections(&[sample], 8);
        assert_eq!(
            sections
                .section("latenciesOverTime")
                .unwrap_or_else(|| panic!("latency section"))
                .status(),
            DashboardGraphStatus::Materialized
        );
        let json = report
            .to_json_with_graph_and_sections(&[], &sections)
            .unwrap_or_else(|_| panic!("valid dashboard JSON"));
        assert_json_structure(&json);
        assert!(json.contains("\"kind\":\"latenciesOverTime\""));
        assert!(json.contains("\"latency_sum_millis\":50"));
        assert!(json.contains("\"kind\":\"responseTimesOverTime\""));
        assert!(json.contains("\"elapsed_sum_millis\":100"));
        let html = report
            .to_html_with_graph_sections(&sections)
            .unwrap_or_else(|_| panic!("valid dashboard HTML"));
        assert!(html.contains("data-graph-id=\"latenciesOverTime\" data-status=\"materialized\""));
        assert!(html.contains("data-payload-kind=\"latenciesOverTime\""));
    }

    #[test]
    fn dashboard_graph_metadata_adapter_preserves_controller_identity() {
        let report = DashboardReport::new(config());
        let mut result = sample("controller", 100, true, "200", "OK");
        result.set_timestamp(Some(jmeter_rs_results::WallTimestamp::from_millis(100)));
        let event = jmeter_rs_results::SampleEvent::new(
            result,
            "run",
            jmeter_rs_results::ThreadIdentity::new("thread"),
            "host",
            jmeter_rs_results::VariableSnapshot::new(),
        );
        let samples = report
            .graph_samples_from_events_with_metadata(
                &[(&event, SampleMetadata::transaction_controller())],
                GraphTimestampPolicy::End,
            )
            .unwrap_or_else(|_| panic!("valid graph event"));
        assert!(samples[0].is_transaction_controller());
    }

    #[test]
    fn dashboard_calculator_variance_keeps_large_offset_rounding() {
        let interval = crate::ReportInterval::from_millis(0, 1_000).unwrap();
        let mut report = DashboardReport::new(
            DashboardConfig::new(interval)
                .unwrap()
                .with_percentile_window(8)
                .unwrap(),
        );
        for elapsed in [1_000_000_000_000_u64, 1_000_000_000_001_u64] {
            assert!(
                report
                    .add_result(&sample("large", elapsed, true, "200", "OK"))
                    .is_ok()
            );
        }
        assert_eq!(report.total().elapsed_variance(), Some(-134_217_728.0));
    }

    #[test]
    fn summary_conversion_is_not_dashboard_or_listener() {
        let interval = crate::ReportInterval::from_millis(0, 1_000).unwrap();
        let mut summary = SummaryReport::new(SummaryConfig::new(interval));
        assert!(
            summary
                .add_result(&sample("one", 10, true, "200", "ok"))
                .is_ok()
        );
        assert_eq!(summary.total().sample_count(), 1);
        let json = summary.to_json().unwrap_or_else(|_| panic!("valid JSON"));
        assert!(json.contains("\"sample_count\":1"));
        assert!(json.contains("\"graph\":[]"));
        assert!(summary.to_html().is_ok());
    }
}
