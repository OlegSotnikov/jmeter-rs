// SPDX-License-Identifier: Apache-2.0
//! Field-specific dashboard graph aggregators.
//!
//! The JMeter report generator has separate consumers for elapsed time,
//! latency, connect time, bytes, active threads, response codes, labels, and
//! distributions.  Keeping those payloads as separate Rust types prevents a
//! caller from accidentally presenting an elapsed/bytes series as a latency
//! or response-code graph.  Every aggregator is bounded and builds its result
//! in local state before returning it, so an input error cannot leave a partial
//! materialization behind.

use std::collections::{BTreeMap, BTreeSet};

use jmeter_rs_results::WallTimestamp;

use crate::ReportInterval;
use crate::config::DashboardPercentileEstimator;
use crate::error::{ReportError, ReportField, ReportLimit, SampleField};
use crate::graph::{GraphAggregationOptions, GraphSample, validate_graph_input};
use crate::metrics::validate_percentile;

const MISSING_LATENCY: &str = "graph.latencies.missing_latency";
const MISSING_CONNECT: &str = "graph.connect_time.missing_connect";
const MISSING_GROUP_THREADS: &str = "graph.active_threads.missing_group_threads";
const MISSING_ALL_THREADS: &str = "graph.active_threads.missing_all_threads";
const MISSING_BYTES: &str = "graph.bytes.missing_request_or_response_bytes";
const MISSING_RESPONSE_CODE: &str = "graph.response_codes.missing_response_code";
const MISSING_LABEL: &str = "graph.labels.missing_label";
const MISSING_ELAPSED: &str = "graph.distribution.missing_elapsed";
const MISSING_SUCCESS: &str = "graph.response_time.missing_success";

// The report-generator.properties entry for ResponseTimeDistribution uses a
// separate 100 ms elapsed-time granularity.  It is intentionally not the
// overall time-series granularity (normally 60 seconds).
const RESPONSE_TIME_DISTRIBUTION_GRANULARITY_MILLIS: u64 = 100;

// The versus-request consumers use AbstractVersusRequestsGraphConsumer's
// fixed one-second request-count window.  This is independent of the
// dashboard's overall over-time granularity.
const VERSUS_REQUEST_GRANULARITY_MILLIS: i64 = 1_000;

/// Common fixed-width bucket identity exposed by field-specific graph points.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct GraphBucket {
    start: WallTimestamp,
    end: WallTimestamp,
}

impl GraphBucket {
    /// Returns the absolute bucket start.
    pub const fn start(self) -> WallTimestamp {
        self.start
    }

    /// Returns the absolute, end-exclusive bucket end.
    pub const fn end(self) -> WallTimestamp {
        self.end
    }
}

/// A latency-over-time bucket.  This type cannot be used for connect-time or
/// elapsed-time payloads by construction.
#[derive(Clone, Debug, PartialEq)]
pub struct LatencyGraphPoint {
    bucket: GraphBucket,
    sample_count: u64,
    latency_count: u64,
    latency_sum_millis: f64,
    latency_mean_millis: Option<f64>,
    latency_variance_millis2: Option<f64>,
    latency_stddev_millis: Option<f64>,
    latency_min_millis: Option<u64>,
    latency_max_millis: Option<u64>,
}

impl LatencyGraphPoint {
    /// Returns the bucket identity.
    pub const fn bucket(&self) -> GraphBucket {
        self.bucket
    }
    /// Returns represented rows.
    pub const fn sample_count(&self) -> u64 {
        self.sample_count
    }
    /// Returns rows carrying latency.
    pub const fn latency_count(&self) -> u64 {
        self.latency_count
    }
    /// Returns the wire-compatible latency sum.
    pub const fn latency_sum_millis(&self) -> f64 {
        self.latency_sum_millis
    }
    /// Returns the latency mean.
    pub const fn latency_mean_millis(&self) -> Option<f64> {
        self.latency_mean_millis
    }
    /// Returns the Calculator population variance.
    pub const fn latency_variance_millis2(&self) -> Option<f64> {
        self.latency_variance_millis2
    }
    /// Returns the Calculator population standard deviation.
    pub const fn latency_stddev_millis(&self) -> Option<f64> {
        self.latency_stddev_millis
    }
    /// Returns the effective minimum.
    pub const fn latency_min_millis(&self) -> Option<u64> {
        self.latency_min_millis
    }
    /// Returns the effective maximum.
    pub const fn latency_max_millis(&self) -> Option<u64> {
        self.latency_max_millis
    }
}

/// A connect-time-over-time bucket, deliberately distinct from latency.
#[derive(Clone, Debug, PartialEq)]
pub struct ConnectGraphPoint {
    bucket: GraphBucket,
    sample_count: u64,
    connect_count: u64,
    connect_sum_millis: f64,
    connect_mean_millis: Option<f64>,
    connect_variance_millis2: Option<f64>,
    connect_stddev_millis: Option<f64>,
    connect_min_millis: Option<u64>,
    connect_max_millis: Option<u64>,
}

impl ConnectGraphPoint {
    /// Returns the bucket identity.
    pub const fn bucket(&self) -> GraphBucket {
        self.bucket
    }
    /// Returns represented rows.
    pub const fn sample_count(&self) -> u64 {
        self.sample_count
    }
    /// Returns rows carrying connect time.
    pub const fn connect_count(&self) -> u64 {
        self.connect_count
    }
    /// Returns the wire-compatible connect sum.
    pub const fn connect_sum_millis(&self) -> f64 {
        self.connect_sum_millis
    }
    /// Returns the connect mean.
    pub const fn connect_mean_millis(&self) -> Option<f64> {
        self.connect_mean_millis
    }
    /// Returns the Calculator population variance.
    pub const fn connect_variance_millis2(&self) -> Option<f64> {
        self.connect_variance_millis2
    }
    /// Returns the Calculator population standard deviation.
    pub const fn connect_stddev_millis(&self) -> Option<f64> {
        self.connect_stddev_millis
    }
    /// Returns the effective minimum.
    pub const fn connect_min_millis(&self) -> Option<u64> {
        self.connect_min_millis
    }
    /// Returns the effective maximum.
    pub const fn connect_max_millis(&self) -> Option<u64> {
        self.connect_max_millis
    }
}

/// Active thread counts over one fixed bucket. Group and all-thread values are
/// retained independently; no all-thread fallback is used for group threads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveThreadsGraphPoint {
    bucket: GraphBucket,
    sample_count: u64,
    group_threads: Option<u64>,
    all_threads: Option<u64>,
}

impl ActiveThreadsGraphPoint {
    /// Returns the bucket identity.
    pub const fn bucket(self) -> GraphBucket {
        self.bucket
    }
    /// Returns represented rows.
    pub const fn sample_count(self) -> u64 {
        self.sample_count
    }
    /// Returns the maximum group-thread count in the bucket.
    pub const fn group_threads(self) -> Option<u64> {
        self.group_threads
    }
    /// Returns the maximum all-thread count in the bucket.
    pub const fn all_threads(self) -> Option<u64> {
        self.all_threads
    }
}

/// Time-vs-threads payload, separated from the two-series active-thread graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimeVsThreadsGraphPoint {
    timestamp: WallTimestamp,
    all_threads: u64,
}

impl TimeVsThreadsGraphPoint {
    /// Returns the source timestamp.
    pub const fn timestamp(self) -> WallTimestamp {
        self.timestamp
    }
    /// Returns the all-thread value.
    pub const fn all_threads(self) -> u64 {
        self.all_threads
    }
}

/// Bytes-throughput payload retaining request/sent and response/received
/// counters as independent values.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BytesGraphPoint {
    bucket: GraphBucket,
    sample_count: u64,
    received_bytes: u64,
    sent_bytes: u64,
    received_bytes_per_second: f64,
    sent_bytes_per_second: f64,
}

impl BytesGraphPoint {
    /// Returns the bucket identity.
    pub const fn bucket(self) -> GraphBucket {
        self.bucket
    }
    /// Returns represented rows.
    pub const fn sample_count(self) -> u64 {
        self.sample_count
    }
    /// Returns response/received bytes.
    pub const fn received_bytes(self) -> u64 {
        self.received_bytes
    }
    /// Returns request/sent bytes.
    pub const fn sent_bytes(self) -> u64 {
        self.sent_bytes
    }
    /// Returns response bytes per second.
    pub const fn received_bytes_per_second(self) -> f64 {
        self.received_bytes_per_second
    }
    /// Returns request bytes per second.
    pub const fn sent_bytes_per_second(self) -> f64 {
        self.sent_bytes_per_second
    }
}

/// Response-code count in one bucket.  Code and message are retained so
/// equal numeric codes with distinct wire messages remain distinguishable.
#[derive(Clone, Debug, PartialEq)]
pub struct ResponseCodeGraphPoint {
    bucket: GraphBucket,
    response_code: String,
    response_message: String,
    sample_count: u64,
    error_count: u64,
    per_second: f64,
}

impl ResponseCodeGraphPoint {
    /// Returns the bucket identity.
    pub const fn bucket(&self) -> GraphBucket {
        self.bucket
    }
    /// Returns response code.
    pub fn response_code(&self) -> &str {
        &self.response_code
    }
    /// Returns response message.
    pub fn response_message(&self) -> &str {
        &self.response_message
    }
    /// Returns represented rows for this code.
    pub const fn sample_count(&self) -> u64 {
        self.sample_count
    }
    /// Returns failed rows for this code.
    pub const fn error_count(&self) -> u64 {
        self.error_count
    }
    /// Returns this code's rate.
    pub const fn per_second(&self) -> f64 {
        self.per_second
    }
}

/// Label count/rate in one bucket.
#[derive(Clone, Debug, PartialEq)]
pub struct LabelGraphPoint {
    bucket: GraphBucket,
    label: String,
    sample_count: u64,
    error_count: u64,
    per_second: f64,
}

impl LabelGraphPoint {
    /// Returns the bucket identity.
    pub const fn bucket(&self) -> GraphBucket {
        self.bucket
    }
    /// Returns the exact wire label.
    pub fn label(&self) -> &str {
        &self.label
    }
    /// Returns represented rows for this label.
    pub const fn sample_count(&self) -> u64 {
        self.sample_count
    }
    /// Returns failed rows for this label.
    pub const fn error_count(&self) -> u64 {
        self.error_count
    }
    /// Returns this label's rate.
    pub const fn per_second(&self) -> f64 {
        self.per_second
    }
}

/// Elapsed response-time bucket used by the named response-time graph.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ResponseTimeGraphPoint {
    bucket: GraphBucket,
    sample_count: u64,
    elapsed_count: u64,
    elapsed_sum_millis: f64,
    elapsed_mean_millis: Option<f64>,
    elapsed_variance_millis2: Option<f64>,
    elapsed_stddev_millis: Option<f64>,
    elapsed_min_millis: Option<u64>,
    elapsed_max_millis: Option<u64>,
}

impl ResponseTimeGraphPoint {
    /// Returns the bucket identity.
    pub const fn bucket(self) -> GraphBucket {
        self.bucket
    }
    /// Returns represented rows.
    pub const fn sample_count(self) -> u64 {
        self.sample_count
    }
    /// Returns elapsed observations.
    pub const fn elapsed_count(self) -> u64 {
        self.elapsed_count
    }
    /// Returns elapsed sum.
    pub const fn elapsed_sum_millis(self) -> f64 {
        self.elapsed_sum_millis
    }
    /// Returns elapsed mean.
    pub const fn elapsed_mean_millis(self) -> Option<f64> {
        self.elapsed_mean_millis
    }
    /// Returns Calculator variance.
    pub const fn elapsed_variance_millis2(self) -> Option<f64> {
        self.elapsed_variance_millis2
    }
    /// Returns Calculator standard deviation.
    pub const fn elapsed_stddev_millis(self) -> Option<f64> {
        self.elapsed_stddev_millis
    }
    /// Returns the effective minimum elapsed value.
    pub const fn elapsed_min_millis(self) -> Option<u64> {
        self.elapsed_min_millis
    }
    /// Returns the effective maximum elapsed value.
    pub const fn elapsed_max_millis(self) -> Option<u64> {
        self.elapsed_max_millis
    }
}

/// A response-time percentile point for a bucket.
#[derive(Clone, Debug, PartialEq)]
pub struct ResponseTimePercentileGraphPoint {
    bucket: GraphBucket,
    sample_count: u64,
    percentiles: Vec<(f64, Option<f64>)>,
}

impl ResponseTimePercentileGraphPoint {
    /// Returns the bucket identity.
    pub const fn bucket(&self) -> GraphBucket {
        self.bucket
    }
    /// Returns represented rows.
    pub const fn sample_count(&self) -> u64 {
        self.sample_count
    }
    /// Returns percentile/value pairs in requested order.
    pub fn percentiles(&self) -> &[(f64, Option<f64>)] {
        &self.percentiles
    }
}

/// One exact response-time distribution observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponseTimeDistributionPoint {
    elapsed_millis: u64,
    sample_count: u64,
}

impl ResponseTimeDistributionPoint {
    /// Returns elapsed value.
    pub const fn elapsed_millis(self) -> u64 {
        self.elapsed_millis
    }
    /// Returns represented count.
    pub const fn sample_count(self) -> u64 {
        self.sample_count
    }
}

/// One synthetic response-time distribution category.
///
/// JMeter's consumer uses four fixed x-axis keys (0 = satisfied, 1 =
/// tolerated, 2 = untolerated, 3 = failed) and status-specific series. The
/// category key is retained in `elapsed_millis` for wire-shape continuity;
/// [`Self::category`] is the clearer accessor for new callers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyntheticResponseTimePoint {
    elapsed_millis: u64,
    satisfied: u64,
    tolerated: u64,
    frustrated: u64,
}

impl SyntheticResponseTimePoint {
    /// Returns the synthetic category key (0..=3).
    pub const fn elapsed_millis(self) -> u64 {
        self.elapsed_millis
    }
    /// Returns the synthetic category key (0 = satisfied, 1 = tolerated,
    /// 2 = untolerated, 3 = failed).
    pub const fn category(self) -> u8 {
        self.elapsed_millis as u8
    }
    /// Returns satisfied count.
    pub const fn satisfied(self) -> u64 {
        self.satisfied
    }
    /// Returns tolerated count.
    pub const fn tolerated(self) -> u64 {
        self.tolerated
    }
    /// Returns frustrated count.
    pub const fn frustrated(self) -> u64 {
        self.frustrated
    }
}

/// A response-time-versus-request scatter point.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ResponseTimeRequestPoint {
    timestamp: WallTimestamp,
    requests_per_second: u64,
    elapsed_millis: f64,
    successful: Option<bool>,
}

impl ResponseTimeRequestPoint {
    /// Returns request timestamp.
    pub const fn timestamp(self) -> WallTimestamp {
        self.timestamp
    }
    /// Returns the request-rate x-axis value used by JMeter's versus-request
    /// consumer for this one-second window.
    pub const fn requests_per_second(self) -> u64 {
        self.requests_per_second
    }
    /// Returns elapsed response time.
    pub const fn elapsed_millis(self) -> f64 {
        self.elapsed_millis
    }
    /// Returns the wire success flag.
    pub const fn successful(self) -> Option<bool> {
        self.successful
    }
}

/// A latency-versus-request scatter point.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LatencyRequestPoint {
    timestamp: WallTimestamp,
    requests_per_second: u64,
    latency_millis: f64,
    successful: Option<bool>,
}

impl LatencyRequestPoint {
    /// Returns request timestamp.
    pub const fn timestamp(self) -> WallTimestamp {
        self.timestamp
    }
    /// Returns the request-rate x-axis value used by JMeter's versus-request
    /// consumer for this one-second window.
    pub const fn requests_per_second(self) -> u64 {
        self.requests_per_second
    }
    /// Returns latency.
    pub const fn latency_millis(self) -> f64 {
        self.latency_millis
    }

    /// Returns the wire success flag used to keep successful and failed
    /// request series separate.
    pub const fn successful(self) -> Option<bool> {
        self.successful
    }
}

/// Hits-per-second point based on represented sample count.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HitsPerSecondPoint {
    bucket: GraphBucket,
    sample_count: u64,
    per_second: f64,
}

impl HitsPerSecondPoint {
    /// Returns bucket identity.
    pub const fn bucket(self) -> GraphBucket {
        self.bucket
    }
    /// Returns represented rows.
    pub const fn sample_count(self) -> u64 {
        self.sample_count
    }
    /// Returns hits per second.
    pub const fn per_second(self) -> f64 {
        self.per_second
    }
}

/// Total-transactions-per-second point.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TotalTpsPoint {
    bucket: GraphBucket,
    successful: bool,
    transaction_count: u64,
    per_second: f64,
}

impl TotalTpsPoint {
    /// Returns bucket identity.
    pub const fn bucket(self) -> GraphBucket {
        self.bucket
    }
    /// Returns transaction count.
    pub const fn transaction_count(self) -> u64 {
        self.transaction_count
    }
    /// Returns whether this series represents successful transactions.
    pub const fn successful(self) -> bool {
        self.successful
    }
    /// Returns TPS.
    pub const fn per_second(self) -> f64 {
        self.per_second
    }
}

/// Label-specific transaction rate point.
#[derive(Clone, Debug, PartialEq)]
pub struct TransactionTpsPoint {
    bucket: GraphBucket,
    label: String,
    transaction_count: u64,
    per_second: f64,
}

impl TransactionTpsPoint {
    /// Returns bucket identity.
    pub const fn bucket(&self) -> GraphBucket {
        self.bucket
    }
    /// Returns label.
    pub fn label(&self) -> &str {
        &self.label
    }
    /// Returns transaction count.
    pub const fn transaction_count(&self) -> u64 {
        self.transaction_count
    }
    /// Returns TPS.
    pub const fn per_second(&self) -> f64 {
        self.per_second
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct CalculatorStats {
    count: u64,
    sum: f64,
    sum_of_squares: f64,
    min: Option<u64>,
    max: Option<u64>,
}

impl CalculatorStats {
    /// Adds a value that is already normalized to one represented
    /// observation. StatisticalSampleResult elapsed values are normalized by
    /// [`GraphSample`] before they reach the response-time graph. Latency and
    /// connect-time fields are row values, so their effective value is also
    /// the value carried by the graph row. Dividing either field again would
    /// make its min/max disagree with the weighted sum and mean.
    fn add_effective(&mut self, value: u64, weight: u64) -> Result<(), ReportError> {
        self.add_with_effective(value, weight, value)
    }

    fn add_with_effective(
        &mut self,
        value: u64,
        weight: u64,
        effective: u64,
    ) -> Result<(), ReportError> {
        if weight == 0 {
            return Ok(());
        }
        let count = self
            .count
            .checked_add(weight)
            .ok_or(ReportError::Overflow {
                field: ReportField::ElapsedCount,
            })?;
        let value_f = value as f64;
        let weight_f = weight as f64;
        // Keep the existing weighted Calculator sum behavior; `effective`
        // separately identifies the per-observation value for min/max.
        let sum = self.sum + value_f * weight_f;
        let sum_of_squares = self.sum_of_squares + value_f * value_f * weight_f;
        if !sum.is_finite() || !sum_of_squares.is_finite() {
            return Err(ReportError::Overflow {
                field: ReportField::Variance,
            });
        }
        self.count = count;
        self.sum = sum;
        self.sum_of_squares = sum_of_squares;
        self.min = Some(self.min.map_or(effective, |current| current.min(effective)));
        self.max = Some(self.max.map_or(effective, |current| current.max(effective)));
        Ok(())
    }

    /// Adds a statistical row whose elapsed value is a total for `weight`
    /// represented observations. JTL aggregate rows retain the total elapsed
    /// time, so reconstructing it from an integer-divided value would lose a
    /// remainder (for example, 5 ms over 2 samples).
    fn add_total_with_effective(
        &mut self,
        total: u128,
        weight: u64,
        effective: u64,
    ) -> Result<(), ReportError> {
        if weight == 0 {
            return Ok(());
        }
        let count = self
            .count
            .checked_add(weight)
            .ok_or(ReportError::Overflow {
                field: ReportField::ElapsedCount,
            })?;
        let total_f = total as f64;
        let weight_f = weight as f64;
        let sum = self.sum + total_f;
        let sum_of_squares = self.sum_of_squares + total_f * total_f / weight_f;
        if !sum.is_finite() || !sum_of_squares.is_finite() {
            return Err(ReportError::Overflow {
                field: ReportField::Variance,
            });
        }
        self.count = count;
        self.sum = sum;
        self.sum_of_squares = sum_of_squares;
        self.min = Some(self.min.map_or(effective, |current| current.min(effective)));
        self.max = Some(self.max.map_or(effective, |current| current.max(effective)));
        Ok(())
    }

    fn mean(&self) -> Option<f64> {
        (self.count > 0).then_some(self.sum / self.count as f64)
    }

    fn variance(&self) -> Option<f64> {
        if self.count == 0 {
            return None;
        }
        // This is the Apache JMeter 5.6.3 Calculator formula.  In
        // particular, do not replace it with Welford's centered accumulator:
        // report compatibility includes the source algorithm's large-offset
        // floating-point behavior.
        Some((self.sum_of_squares - self.sum * self.sum / self.count as f64) / self.count as f64)
    }

    fn stddev(&self) -> Option<f64> {
        self.variance().map(f64::sqrt)
    }
}

fn validate_width(granularity_millis: u64) -> Result<i64, ReportError> {
    if granularity_millis <= 1_000 {
        return Err(ReportError::InvalidConfig {
            field: crate::ConfigField::OverallGranularity,
        });
    }
    i64::try_from(granularity_millis).map_err(|_| ReportError::Overflow {
        field: ReportField::Interval,
    })
}

fn bucket_for(timestamp: WallTimestamp, width: i64) -> Result<GraphBucket, ReportError> {
    let quotient = timestamp.as_millis().div_euclid(width);
    let start = quotient.checked_mul(width).ok_or(ReportError::Overflow {
        field: ReportField::Timestamp,
    })?;
    let end = start.checked_add(width).ok_or(ReportError::Overflow {
        field: ReportField::Timestamp,
    })?;
    Ok(GraphBucket {
        start: WallTimestamp::from_millis(start),
        end: WallTimestamp::from_millis(end),
    })
}

fn in_interval(sample: &GraphSample, interval: ReportInterval) -> bool {
    let timestamp = sample.timestamp().as_millis();
    timestamp >= interval.start().as_millis() && timestamp < interval.end().as_millis()
}

fn excluded(sample: &GraphSample, options: GraphAggregationOptions) -> bool {
    options.excludes_transaction_controllers() && sample.is_transaction_controller()
}

fn validate_sample_counts(sample: &GraphSample) -> Result<(), ReportError> {
    if sample.error_count() > sample.sample_count() {
        Err(ReportError::InvalidSample {
            field: SampleField::ErrorCount,
        })
    } else {
        Ok(())
    }
}

fn check_new_bucket<K: Ord>(
    map: &BTreeMap<K, impl Sized>,
    max_points: usize,
) -> Result<(), ReportError> {
    if max_points == 0 {
        return Err(ReportError::InvalidConfig {
            field: crate::ConfigField::MaxGraphPoints,
        });
    }
    if map.len() >= max_points {
        return Err(ReportError::LimitExceeded {
            resource: ReportLimit::GraphPoints,
            actual: map.len().saturating_add(1),
            maximum: max_points,
        });
    }
    Ok(())
}

fn validate_max_points(max_points: usize) -> Result<(), ReportError> {
    if max_points == 0 {
        Err(ReportError::InvalidConfig {
            field: crate::ConfigField::MaxGraphPoints,
        })
    } else {
        Ok(())
    }
}

type CalculatorStatsSummary = (
    u64,
    f64,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<u64>,
    Option<u64>,
);

fn finish_stats(stats: CalculatorStats) -> CalculatorStatsSummary {
    (
        stats.count,
        stats.sum,
        stats.mean(),
        stats.variance(),
        stats.stddev(),
        stats.min,
        stats.max,
    )
}

/// Aggregates the distinct latency field into bounded buckets.
pub fn aggregate_latency_graph_samples(
    samples: &[GraphSample],
    interval: ReportInterval,
    granularity_millis: u64,
    max_points: usize,
    options: GraphAggregationOptions,
) -> Result<Vec<LatencyGraphPoint>, ReportError> {
    validate_graph_input(samples)?;
    validate_max_points(max_points)?;
    let width = validate_width(granularity_millis)?;
    let mut buckets = BTreeMap::<i64, (GraphBucket, u64, CalculatorStats)>::new();
    for sample in samples {
        if !in_interval(sample, interval) || excluded(sample, options) {
            continue;
        }
        validate_sample_counts(sample)?;
        let latency = sample.latency_millis().ok_or(ReportError::Unsupported {
            capability: MISSING_LATENCY,
        })?;
        let bucket = bucket_for(sample.timestamp(), width)?;
        let key = bucket.start().as_millis();
        if !buckets.contains_key(&key) {
            check_new_bucket(&buckets, max_points)?;
            buckets.insert(key, (bucket, 0, CalculatorStats::default()));
        }
        let (_, sample_count, stats) = buckets.get_mut(&key).ok_or(ReportError::Serialization)?;
        *sample_count =
            sample_count
                .checked_add(sample.sample_count())
                .ok_or(ReportError::Overflow {
                    field: ReportField::SampleCount,
                })?;
        stats.add_effective(latency, sample.sample_count())?;
    }
    Ok(buckets
        .into_values()
        .map(|(bucket, sample_count, stats)| {
            let (count, sum, mean, variance, stddev, min, max) = finish_stats(stats);
            LatencyGraphPoint {
                bucket,
                sample_count,
                latency_count: count,
                latency_sum_millis: sum,
                latency_mean_millis: mean,
                latency_variance_millis2: variance,
                latency_stddev_millis: stddev,
                latency_min_millis: min,
                latency_max_millis: max,
            }
        })
        .collect())
}

/// Aggregates the distinct connect-time field into bounded buckets.
pub fn aggregate_connect_graph_samples(
    samples: &[GraphSample],
    interval: ReportInterval,
    granularity_millis: u64,
    max_points: usize,
    options: GraphAggregationOptions,
) -> Result<Vec<ConnectGraphPoint>, ReportError> {
    validate_graph_input(samples)?;
    validate_max_points(max_points)?;
    let width = validate_width(granularity_millis)?;
    let mut buckets = BTreeMap::<i64, (GraphBucket, u64, CalculatorStats)>::new();
    for sample in samples {
        if !in_interval(sample, interval) || excluded(sample, options) {
            continue;
        }
        validate_sample_counts(sample)?;
        let connect = sample.connect_millis().ok_or(ReportError::Unsupported {
            capability: MISSING_CONNECT,
        })?;
        let bucket = bucket_for(sample.timestamp(), width)?;
        let key = bucket.start().as_millis();
        if !buckets.contains_key(&key) {
            check_new_bucket(&buckets, max_points)?;
            buckets.insert(key, (bucket, 0, CalculatorStats::default()));
        }
        let (_, sample_count, stats) = buckets.get_mut(&key).ok_or(ReportError::Serialization)?;
        *sample_count =
            sample_count
                .checked_add(sample.sample_count())
                .ok_or(ReportError::Overflow {
                    field: ReportField::SampleCount,
                })?;
        stats.add_effective(connect, sample.sample_count())?;
    }
    Ok(buckets
        .into_values()
        .map(|(bucket, sample_count, stats)| {
            let (count, sum, mean, variance, stddev, min, max) = finish_stats(stats);
            ConnectGraphPoint {
                bucket,
                sample_count,
                connect_count: count,
                connect_sum_millis: sum,
                connect_mean_millis: mean,
                connect_variance_millis2: variance,
                connect_stddev_millis: stddev,
                connect_min_millis: min,
                connect_max_millis: max,
            }
        })
        .collect())
}

/// Aggregates independent group/all active-thread fields.
pub fn aggregate_active_threads_graph_samples(
    samples: &[GraphSample],
    interval: ReportInterval,
    granularity_millis: u64,
    max_points: usize,
    options: GraphAggregationOptions,
) -> Result<Vec<ActiveThreadsGraphPoint>, ReportError> {
    validate_graph_input(samples)?;
    validate_max_points(max_points)?;
    let width = validate_width(granularity_millis)?;
    let mut buckets = BTreeMap::<i64, (GraphBucket, u64, Option<u64>, Option<u64>)>::new();
    for sample in samples {
        if !in_interval(sample, interval) || excluded(sample, options) {
            continue;
        }
        validate_sample_counts(sample)?;
        let group_threads = sample.group_threads().ok_or(ReportError::Unsupported {
            capability: MISSING_GROUP_THREADS,
        })?;
        let all_threads = sample.all_threads().ok_or(ReportError::Unsupported {
            capability: MISSING_ALL_THREADS,
        })?;
        let bucket = bucket_for(sample.timestamp(), width)?;
        let key = bucket.start().as_millis();
        if !buckets.contains_key(&key) {
            check_new_bucket(&buckets, max_points)?;
            buckets.insert(key, (bucket, 0, None, None));
        }
        let (_, count, group, all) = buckets.get_mut(&key).ok_or(ReportError::Serialization)?;
        *count = count
            .checked_add(sample.sample_count())
            .ok_or(ReportError::Overflow {
                field: ReportField::SampleCount,
            })?;
        *group = Some(group.map_or(group_threads, |value| value.max(group_threads)));
        *all = Some(all.map_or(all_threads, |value| value.max(all_threads)));
    }
    Ok(buckets
        .into_values()
        .map(
            |(bucket, sample_count, group_threads, all_threads)| ActiveThreadsGraphPoint {
                bucket,
                sample_count,
                group_threads,
                all_threads,
            },
        )
        .collect())
}

/// Aggregates the all-thread field for the distinct time-vs-threads scatter
/// section. It intentionally does not return the group-thread series.
pub fn aggregate_time_vs_threads_graph_samples(
    samples: &[GraphSample],
    interval: ReportInterval,
    max_points: usize,
    options: GraphAggregationOptions,
) -> Result<Vec<TimeVsThreadsGraphPoint>, ReportError> {
    validate_graph_input(samples)?;
    validate_max_points(max_points)?;
    let mut output = Vec::new();
    for sample in samples {
        if !in_interval(sample, interval) || excluded(sample, options) {
            continue;
        }
        validate_sample_counts(sample)?;
        let all_threads = sample.all_threads().ok_or(ReportError::Unsupported {
            capability: MISSING_ALL_THREADS,
        })?;
        if output.len() >= max_points {
            return Err(ReportError::LimitExceeded {
                resource: ReportLimit::GraphSamples,
                actual: output.len().saturating_add(1),
                maximum: max_points,
            });
        }
        output.push(TimeVsThreadsGraphPoint {
            timestamp: sample.timestamp(),
            all_threads,
        });
    }
    Ok(output)
}

/// Aggregates sent/request and received/response bytes independently.
pub fn aggregate_bytes_graph_samples(
    samples: &[GraphSample],
    interval: ReportInterval,
    granularity_millis: u64,
    max_points: usize,
    options: GraphAggregationOptions,
) -> Result<Vec<BytesGraphPoint>, ReportError> {
    validate_graph_input(samples)?;
    validate_max_points(max_points)?;
    let width = validate_width(granularity_millis)?;
    let mut buckets = BTreeMap::<i64, (GraphBucket, u64, u64, u64)>::new();
    for sample in samples {
        if !in_interval(sample, interval) || excluded(sample, options) {
            continue;
        }
        validate_sample_counts(sample)?;
        let received = sample
            .received_bytes_field()
            .ok_or(ReportError::Unsupported {
                capability: MISSING_BYTES,
            })?;
        let sent = sample.sent_bytes_field().ok_or(ReportError::Unsupported {
            capability: MISSING_BYTES,
        })?;
        let bucket = bucket_for(sample.timestamp(), width)?;
        let key = bucket.start().as_millis();
        if !buckets.contains_key(&key) {
            check_new_bucket(&buckets, max_points)?;
            buckets.insert(key, (bucket, 0, 0, 0));
        }
        let (_, count, received_total, sent_total) =
            buckets.get_mut(&key).ok_or(ReportError::Serialization)?;
        *count = count
            .checked_add(sample.sample_count())
            .ok_or(ReportError::Overflow {
                field: ReportField::SampleCount,
            })?;
        *received_total = received_total
            .checked_add(received)
            .ok_or(ReportError::Overflow {
                field: ReportField::ReceivedBytes,
            })?;
        *sent_total = sent_total.checked_add(sent).ok_or(ReportError::Overflow {
            field: ReportField::SentBytes,
        })?;
    }
    let seconds = granularity_millis as f64 / 1_000.0;
    Ok(buckets
        .into_values()
        .map(
            |(bucket, sample_count, received_bytes, sent_bytes)| BytesGraphPoint {
                bucket,
                sample_count,
                received_bytes,
                sent_bytes,
                received_bytes_per_second: received_bytes as f64 / seconds,
                sent_bytes_per_second: sent_bytes as f64 / seconds,
            },
        )
        .collect())
}

/// Aggregates response codes per bucket.  This is a keyed series and is not a
/// byte/elapsed graph alias.
pub fn aggregate_response_code_graph_samples(
    samples: &[GraphSample],
    interval: ReportInterval,
    granularity_millis: u64,
    max_points: usize,
    options: GraphAggregationOptions,
) -> Result<Vec<ResponseCodeGraphPoint>, ReportError> {
    validate_graph_input(samples)?;
    validate_max_points(max_points)?;
    let width = validate_width(granularity_millis)?;
    // CodesPerSecondGraphConsumer uses CodeSeriesSelector, whose key is the
    // response code alone.  Response messages are not a series dimension;
    // retain the first wire message only as diagnostic metadata on the typed
    // point.
    let mut buckets = BTreeMap::<(i64, String), (GraphBucket, String, u64, u64)>::new();
    for sample in samples {
        if !in_interval(sample, interval) || excluded(sample, options) {
            continue;
        }
        validate_sample_counts(sample)?;
        let code = sample.response_code().ok_or(ReportError::Unsupported {
            capability: MISSING_RESPONSE_CODE,
        })?;
        let message = sample.response_message().unwrap_or_default();
        let bucket = bucket_for(sample.timestamp(), width)?;
        let key = (bucket.start().as_millis(), code.to_owned());
        if !buckets.contains_key(&key) {
            check_new_bucket(&buckets, max_points)?;
            buckets.insert(key.clone(), (bucket, message.to_owned(), 0, 0));
        }
        let (_, response_message_slot, count, errors) =
            buckets.get_mut(&key).ok_or(ReportError::Serialization)?;
        // Response messages are not a CodeSeriesSelector dimension. Keep a
        // deterministic diagnostic representative rather than making the
        // payload depend on source-row arrival order.
        if message < response_message_slot.as_str() {
            *response_message_slot = message.to_owned();
        }
        *count = count
            .checked_add(sample.sample_count())
            .ok_or(ReportError::Overflow {
                field: ReportField::SampleCount,
            })?;
        *errors = errors
            .checked_add(sample.error_count())
            .ok_or(ReportError::Overflow {
                field: ReportField::ErrorCount,
            })?;
        if *errors > *count {
            return Err(ReportError::InvalidSample {
                field: SampleField::ErrorCount,
            });
        }
    }
    let seconds = granularity_millis as f64 / 1_000.0;
    Ok(buckets
        .into_iter()
        .map(
            |((_, response_code), (bucket, response_message, sample_count, error_count))| {
                ResponseCodeGraphPoint {
                    bucket,
                    response_code,
                    response_message,
                    sample_count,
                    error_count,
                    per_second: sample_count as f64 / seconds,
                }
            },
        )
        .collect())
}

/// Aggregates labels per bucket.  The label is a required wire field rather
/// than a synthesized fallback.
pub fn aggregate_label_graph_samples(
    samples: &[GraphSample],
    interval: ReportInterval,
    granularity_millis: u64,
    max_points: usize,
    options: GraphAggregationOptions,
) -> Result<Vec<LabelGraphPoint>, ReportError> {
    validate_graph_input(samples)?;
    validate_max_points(max_points)?;
    let width = validate_width(granularity_millis)?;
    let mut buckets = BTreeMap::<(i64, String), (GraphBucket, u64, u64)>::new();
    for sample in samples {
        if !in_interval(sample, interval) || excluded(sample, options) {
            continue;
        }
        validate_sample_counts(sample)?;
        let label = sample.label().ok_or(ReportError::Unsupported {
            capability: MISSING_LABEL,
        })?;
        let bucket = bucket_for(sample.timestamp(), width)?;
        let key = (bucket.start().as_millis(), label.to_owned());
        if !buckets.contains_key(&key) {
            check_new_bucket(&buckets, max_points)?;
            buckets.insert(key.clone(), (bucket, 0, 0));
        }
        let (_, count, errors) = buckets.get_mut(&key).ok_or(ReportError::Serialization)?;
        *count = count
            .checked_add(sample.sample_count())
            .ok_or(ReportError::Overflow {
                field: ReportField::SampleCount,
            })?;
        *errors = errors
            .checked_add(sample.error_count())
            .ok_or(ReportError::Overflow {
                field: ReportField::ErrorCount,
            })?;
        if *errors > *count {
            return Err(ReportError::InvalidSample {
                field: SampleField::ErrorCount,
            });
        }
    }
    let seconds = granularity_millis as f64 / 1_000.0;
    Ok(buckets
        .into_iter()
        .map(
            |((_, label), (bucket, sample_count, error_count))| LabelGraphPoint {
                bucket,
                label,
                sample_count,
                error_count,
                per_second: sample_count as f64 / seconds,
            },
        )
        .collect())
}

/// Aggregates elapsed response-time statistics in distinct buckets.
pub fn aggregate_response_time_graph_samples(
    samples: &[GraphSample],
    interval: ReportInterval,
    granularity_millis: u64,
    max_points: usize,
    options: GraphAggregationOptions,
) -> Result<Vec<ResponseTimeGraphPoint>, ReportError> {
    validate_graph_input(samples)?;
    validate_max_points(max_points)?;
    let width = validate_width(granularity_millis)?;
    let mut buckets = BTreeMap::<i64, (GraphBucket, u64, CalculatorStats)>::new();
    for sample in samples {
        if !in_interval(sample, interval) || excluded(sample, options) {
            continue;
        }
        validate_sample_counts(sample)?;
        let elapsed = sample
            .elapsed_wire_millis()
            .ok_or(ReportError::Unsupported {
                capability: MISSING_ELAPSED,
            })?;
        let bucket = bucket_for(sample.timestamp(), width)?;
        let key = bucket.start().as_millis();
        if !buckets.contains_key(&key) {
            check_new_bucket(&buckets, max_points)?;
            buckets.insert(key, (bucket, 0, CalculatorStats::default()));
        }
        let (_, count, stats) = buckets.get_mut(&key).ok_or(ReportError::Serialization)?;
        *count = count
            .checked_add(sample.sample_count())
            .ok_or(ReportError::Overflow {
                field: ReportField::SampleCount,
            })?;
        if let Some(total) = sample.elapsed_total_millis() {
            stats.add_total_with_effective(total, sample.sample_count(), elapsed)?;
        } else {
            stats.add_effective(elapsed, sample.sample_count())?;
        }
    }
    Ok(buckets
        .into_values()
        .map(|(bucket, sample_count, stats)| ResponseTimeGraphPoint {
            bucket,
            sample_count,
            elapsed_count: stats.count,
            elapsed_sum_millis: stats.sum,
            elapsed_mean_millis: stats.mean(),
            elapsed_variance_millis2: stats.variance(),
            elapsed_stddev_millis: stats.stddev(),
            elapsed_min_millis: stats.min,
            elapsed_max_millis: stats.max,
        })
        .collect())
}

fn add_elapsed_values(
    values: &mut BTreeMap<u64, u64>,
    sample: &GraphSample,
    max_samples: usize,
) -> Result<(), ReportError> {
    let elapsed = sample
        .elapsed_wire_millis()
        .ok_or(ReportError::Unsupported {
            capability: MISSING_ELAPSED,
        })?;
    let elapsed = elapsed - elapsed % RESPONSE_TIME_DISTRIBUTION_GRANULARITY_MILLIS;
    let current = values.get(&elapsed).copied().unwrap_or(0);
    let updated = current
        .checked_add(sample.sample_count())
        .ok_or(ReportError::Overflow {
            field: ReportField::ElapsedCount,
        })?;
    let represented = values.values().try_fold(0_usize, |total, value| {
        usize::try_from(*value)
            .ok()
            .and_then(|value| total.checked_add(value))
    });
    let represented = represented.ok_or(ReportError::Overflow {
        field: ReportField::PercentileSamples,
    })?;
    let additional = usize::try_from(sample.sample_count()).map_err(|_| ReportError::Overflow {
        field: ReportField::PercentileSamples,
    })?;
    if represented
        .checked_add(additional)
        .ok_or(ReportError::Overflow {
            field: ReportField::PercentileSamples,
        })?
        > max_samples
    {
        return Err(ReportError::LimitExceeded {
            resource: ReportLimit::GraphSamples,
            actual: represented.saturating_add(additional),
            maximum: max_samples,
        });
    }
    values.insert(elapsed, updated);
    Ok(())
}

/// Aggregates the response-time distribution using JMeter's dedicated 100 ms
/// elapsed-time buckets, retaining sorted bucket starts and represented
/// counts. This elapsed-value granularity is distinct from the overall
/// over-time granularity.
pub fn aggregate_response_time_distribution_graph_samples(
    samples: &[GraphSample],
    interval: ReportInterval,
    max_points: usize,
    max_samples: usize,
    options: GraphAggregationOptions,
) -> Result<Vec<ResponseTimeDistributionPoint>, ReportError> {
    validate_graph_input(samples)?;
    if max_samples == 0 {
        return Err(ReportError::InvalidConfig {
            field: crate::ConfigField::MaxPercentileSamples,
        });
    }
    validate_max_points(max_points)?;
    let mut values = BTreeMap::new();
    for sample in samples {
        if !in_interval(sample, interval) || excluded(sample, options) {
            continue;
        }
        validate_sample_counts(sample)?;
        add_elapsed_values(&mut values, sample, max_samples)?;
        if values.len() > max_points {
            return Err(ReportError::LimitExceeded {
                resource: ReportLimit::GraphPoints,
                actual: values.len(),
                maximum: max_points,
            });
        }
    }
    Ok(values
        .into_iter()
        .map(
            |(elapsed_millis, sample_count)| ResponseTimeDistributionPoint {
                elapsed_millis,
                sample_count,
            },
        )
        .collect())
}

/// Aggregates synthetic APDEX response-time categories using JMeter's four
/// fixed category keys rather than one point per elapsed value.
pub fn aggregate_synthetic_response_time_graph_samples(
    samples: &[GraphSample],
    interval: ReportInterval,
    satisfied_millis: u64,
    tolerated_millis: u64,
    max_points: usize,
    options: GraphAggregationOptions,
) -> Result<Vec<SyntheticResponseTimePoint>, ReportError> {
    validate_graph_input(samples)?;
    if satisfied_millis > tolerated_millis {
        return Err(ReportError::InvalidConfig {
            field: crate::ConfigField::ApdexThresholds,
        });
    }
    validate_max_points(max_points)?;
    let mut values = BTreeMap::<u64, u64>::new();
    for sample in samples {
        if !in_interval(sample, interval) || excluded(sample, options) {
            continue;
        }
        validate_sample_counts(sample)?;
        let elapsed = sample
            .elapsed_wire_millis()
            .ok_or(ReportError::Unsupported {
                capability: MISSING_ELAPSED,
            })?;
        let successful = sample.successful().ok_or(ReportError::Unsupported {
            capability: MISSING_SUCCESS,
        })?;
        let category = if !successful {
            3
        } else if elapsed <= satisfied_millis {
            0
        } else if elapsed <= tolerated_millis {
            1
        } else {
            2
        };
        if !values.contains_key(&category) {
            if values.len() >= max_points {
                return Err(ReportError::LimitExceeded {
                    resource: ReportLimit::GraphPoints,
                    actual: values.len().saturating_add(1),
                    maximum: max_points,
                });
            }
            values.insert(category, 0);
        }
        let count = values
            .get_mut(&category)
            .ok_or(ReportError::Serialization)?;
        *count = count
            .checked_add(sample.sample_count())
            .ok_or(ReportError::Overflow {
                field: if category == 3 {
                    ReportField::ErrorCount
                } else {
                    ReportField::SampleCount
                },
            })?;
    }
    Ok(values
        .into_iter()
        .map(|(elapsed_millis, count)| {
            let (satisfied, tolerated, frustrated) = match elapsed_millis {
                0 => (count, 0, 0),
                1 => (0, count, 0),
                2 | 3 => (0, 0, count),
                _ => (0, 0, 0),
            };
            SyntheticResponseTimePoint {
                elapsed_millis,
                satisfied,
                tolerated,
                frustrated,
            }
        })
        .collect())
}

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

fn percentile_value(
    values: &[u64],
    percentile: f64,
    estimator: DashboardPercentileEstimator,
) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    if values.len() == 1 {
        return Some(values[0] as f64);
    }
    match estimator {
        DashboardPercentileEstimator::Legacy => {
            let position = percentile / 100.0 * (values.len() + 1) as f64;
            if position <= 1.0 {
                return Some(values[0] as f64);
            }
            if position >= values.len() as f64 {
                return Some(values[values.len() - 1] as f64);
            }
            let lower = position.floor() as usize - 1;
            let upper = lower + 1;
            let weight = position.fract();
            Some(values[lower] as f64 + (values[upper] as f64 - values[lower] as f64) * weight)
        }
        DashboardPercentileEstimator::R3 => {
            let rank = nearest_even_rank(percentile / 100.0 * values.len() as f64);
            Some(values[(rank - 1).min(values.len() - 1)] as f64)
        }
    }
}

/// Aggregates elapsed percentiles per bucket using the dashboard's LEGACY
/// estimator by default. This is separate from listener weighted percentiles.
pub fn aggregate_response_time_percentile_graph_samples(
    samples: &[GraphSample],
    interval: ReportInterval,
    granularity_millis: u64,
    percentiles: &[f64],
    max_points: usize,
    max_samples: usize,
    options: GraphAggregationOptions,
) -> Result<Vec<ResponseTimePercentileGraphPoint>, ReportError> {
    validate_graph_input(samples)?;
    aggregate_response_time_percentile_graph_samples_with_estimator(
        samples,
        interval,
        granularity_millis,
        percentiles,
        max_points,
        max_samples,
        options,
        DashboardPercentileEstimator::Legacy,
    )
}

/// Aggregates elapsed percentiles per bucket with the requested dashboard
/// estimator. Each bucket retains its own bounded exact observations.
// The explicit arguments mirror the pinned graph consumer contract; grouping
// them into an opaque options object would hide source fields at this boundary.
#[allow(clippy::too_many_arguments)]
pub fn aggregate_response_time_percentile_graph_samples_with_estimator(
    samples: &[GraphSample],
    interval: ReportInterval,
    granularity_millis: u64,
    percentiles: &[f64],
    max_points: usize,
    max_samples: usize,
    options: GraphAggregationOptions,
    estimator: DashboardPercentileEstimator,
) -> Result<Vec<ResponseTimePercentileGraphPoint>, ReportError> {
    validate_graph_input(samples)?;
    validate_max_points(max_points)?;
    if max_samples == 0 {
        return Err(ReportError::InvalidConfig {
            field: crate::ConfigField::MaxPercentileSamples,
        });
    }
    let width = validate_width(granularity_millis)?;
    for percentile in percentiles {
        validate_percentile(*percentile)?;
    }
    let mut buckets = BTreeMap::<i64, (GraphBucket, u64, BTreeMap<u64, u64>)>::new();
    for sample in samples {
        if !in_interval(sample, interval) || excluded(sample, options) {
            continue;
        }
        validate_sample_counts(sample)?;
        let bucket = bucket_for(sample.timestamp(), width)?;
        let key = bucket.start().as_millis();
        if !buckets.contains_key(&key) {
            check_new_bucket(&buckets, max_points)?;
            buckets.insert(key, (bucket, 0, BTreeMap::new()));
        }
        let (_, count, values) = buckets.get_mut(&key).ok_or(ReportError::Serialization)?;
        *count = count
            .checked_add(sample.sample_count())
            .ok_or(ReportError::Overflow {
                field: ReportField::SampleCount,
            })?;
        add_elapsed_values(values, sample, max_samples)?;
    }
    Ok(buckets
        .into_values()
        .map(|(bucket, sample_count, values)| {
            let mut expanded = Vec::new();
            for (value, count) in values {
                for _ in 0..count {
                    expanded.push(value);
                }
            }
            expanded.sort_unstable();
            let percentile_values = percentiles
                .iter()
                .map(|percentile| {
                    (
                        *percentile,
                        percentile_value(&expanded, *percentile, estimator),
                    )
                })
                .collect();
            ResponseTimePercentileGraphPoint {
                bucket,
                sample_count,
                percentiles: percentile_values,
            }
        })
        .collect())
}

/// Materializes response-time-versus-request scatter points.
pub fn aggregate_response_time_vs_request_graph_samples(
    samples: &[GraphSample],
    interval: ReportInterval,
    max_points: usize,
    options: GraphAggregationOptions,
) -> Result<Vec<ResponseTimeRequestPoint>, ReportError> {
    validate_graph_input(samples)?;
    aggregate_scatter_response_time(samples, interval, max_points, options)
}

fn aggregate_scatter_response_time(
    samples: &[GraphSample],
    interval: ReportInterval,
    max_points: usize,
    options: GraphAggregationOptions,
) -> Result<Vec<ResponseTimeRequestPoint>, ReportError> {
    validate_max_points(max_points)?;
    // AbstractVersusRequestsGraphConsumer first tags rows with the number of
    // requests in a one-second end-time bucket, then MedianAggregatorFactory
    // computes one point per success-status series and bucket.
    let mut rows = Vec::<(i64, bool, u64)>::new();
    let mut request_counts = BTreeMap::<i64, u64>::new();
    for sample in samples {
        if !in_interval(sample, interval) || excluded(sample, options) {
            continue;
        }
        validate_sample_counts(sample)?;
        let elapsed = sample
            .elapsed_wire_millis()
            .ok_or(ReportError::Unsupported {
                capability: MISSING_ELAPSED,
            })?;
        let successful = sample.successful().ok_or(ReportError::Unsupported {
            capability: MISSING_SUCCESS,
        })?;
        let bucket_start = sample
            .timestamp()
            .as_millis()
            .div_euclid(VERSUS_REQUEST_GRANULARITY_MILLIS)
            .checked_mul(VERSUS_REQUEST_GRANULARITY_MILLIS)
            .ok_or(ReportError::Overflow {
                field: ReportField::Timestamp,
            })?;
        let request_count = request_counts.entry(bucket_start).or_insert(0);
        *request_count =
            request_count
                .checked_add(sample.sample_count())
                .ok_or(ReportError::Overflow {
                    field: ReportField::SampleCount,
                })?;
        rows.push((bucket_start, successful, elapsed));
    }
    let mut values_by_rate = BTreeMap::<(u64, bool), Vec<u64>>::new();
    for (bucket_start, successful, elapsed) in rows {
        let request_rate = request_counts.get(&bucket_start).copied().unwrap_or(0);
        let key = (request_rate, successful);
        if !values_by_rate.contains_key(&key) {
            if values_by_rate.len() >= max_points {
                return Err(ReportError::LimitExceeded {
                    resource: ReportLimit::GraphSamples,
                    actual: values_by_rate.len().saturating_add(1),
                    maximum: max_points,
                });
            }
            values_by_rate.insert(key, Vec::new());
        }
        values_by_rate
            .get_mut(&key)
            .ok_or(ReportError::Serialization)?
            .push(elapsed);
    }
    values_by_rate
        .into_iter()
        .map(|((request_rate, successful), mut values)| -> Result<
            ResponseTimeRequestPoint,
            ReportError,
        > {
            values.sort_unstable();
            Ok(ResponseTimeRequestPoint {
                // JMeter's x-axis is request rate, not wall time. Keep a
                // deterministic projection for legacy timestamp callers;
                // `requests_per_second` is the compatibility field.
                timestamp: WallTimestamp::from_millis(i64::try_from(request_rate).map_err(
                    |_| ReportError::Overflow {
                        field: ReportField::Interval,
                    },
                )?),
                requests_per_second: request_rate,
                elapsed_millis: percentile_value(
                    &values,
                    50.0,
                    DashboardPercentileEstimator::Legacy,
                )
                .unwrap_or(0.0),
                successful: Some(successful),
            })
        })
        .collect::<Result<Vec<_>, _>>()
}

/// Materializes latency-versus-request scatter points.
pub fn aggregate_latency_vs_request_graph_samples(
    samples: &[GraphSample],
    interval: ReportInterval,
    max_points: usize,
    options: GraphAggregationOptions,
) -> Result<Vec<LatencyRequestPoint>, ReportError> {
    validate_graph_input(samples)?;
    validate_max_points(max_points)?;
    let mut rows = Vec::<(i64, bool, u64)>::new();
    let mut request_counts = BTreeMap::<i64, u64>::new();
    for sample in samples {
        if !in_interval(sample, interval) || excluded(sample, options) {
            continue;
        }
        validate_sample_counts(sample)?;
        let latency = sample.latency_millis().ok_or(ReportError::Unsupported {
            capability: MISSING_LATENCY,
        })?;
        let successful = sample.successful().ok_or(ReportError::Unsupported {
            capability: MISSING_SUCCESS,
        })?;
        let bucket_start = sample
            .timestamp()
            .as_millis()
            .div_euclid(VERSUS_REQUEST_GRANULARITY_MILLIS)
            .checked_mul(VERSUS_REQUEST_GRANULARITY_MILLIS)
            .ok_or(ReportError::Overflow {
                field: ReportField::Timestamp,
            })?;
        let request_count = request_counts.entry(bucket_start).or_insert(0);
        *request_count =
            request_count
                .checked_add(sample.sample_count())
                .ok_or(ReportError::Overflow {
                    field: ReportField::SampleCount,
                })?;
        rows.push((bucket_start, successful, latency));
    }
    let mut values_by_rate = BTreeMap::<(u64, bool), Vec<u64>>::new();
    for (bucket_start, successful, latency) in rows {
        let request_rate = request_counts.get(&bucket_start).copied().unwrap_or(0);
        let key = (request_rate, successful);
        if !values_by_rate.contains_key(&key) {
            if values_by_rate.len() >= max_points {
                return Err(ReportError::LimitExceeded {
                    resource: ReportLimit::GraphSamples,
                    actual: values_by_rate.len().saturating_add(1),
                    maximum: max_points,
                });
            }
            values_by_rate.insert(key, Vec::new());
        }
        values_by_rate
            .get_mut(&key)
            .ok_or(ReportError::Serialization)?
            .push(latency);
    }
    values_by_rate
        .into_iter()
        .map(
            |((request_rate, successful), mut values)| -> Result<LatencyRequestPoint, ReportError> {
                values.sort_unstable();
                Ok(LatencyRequestPoint {
                    timestamp: WallTimestamp::from_millis(i64::try_from(request_rate).map_err(
                        |_| ReportError::Overflow {
                            field: ReportField::Interval,
                        },
                    )?),
                    requests_per_second: request_rate,
                    latency_millis: percentile_value(
                        &values,
                        50.0,
                        DashboardPercentileEstimator::Legacy,
                    )
                    .unwrap_or(0.0),
                    successful: Some(successful),
                })
            },
        )
        .collect::<Result<Vec<_>, _>>()
}

/// Materializes hits per second using represented sample counts.
pub fn aggregate_hits_per_second_graph_samples(
    samples: &[GraphSample],
    interval: ReportInterval,
    granularity_millis: u64,
    max_points: usize,
    options: GraphAggregationOptions,
) -> Result<Vec<HitsPerSecondPoint>, ReportError> {
    validate_graph_input(samples)?;
    validate_max_points(max_points)?;
    let width = validate_width(granularity_millis)?;
    let mut buckets = BTreeMap::<i64, (GraphBucket, u64)>::new();
    for sample in samples {
        if !in_interval(sample, interval) || excluded(sample, options) {
            continue;
        }
        validate_sample_counts(sample)?;
        let bucket = bucket_for(sample.timestamp(), width)?;
        let key = bucket.start().as_millis();
        if !buckets.contains_key(&key) {
            check_new_bucket(&buckets, max_points)?;
            buckets.insert(key, (bucket, 0));
        }
        let (_, count) = buckets.get_mut(&key).ok_or(ReportError::Serialization)?;
        *count = count
            .checked_add(sample.sample_count())
            .ok_or(ReportError::Overflow {
                field: ReportField::SampleCount,
            })?;
    }
    let seconds = granularity_millis as f64 / 1_000.0;
    Ok(buckets
        .into_values()
        .map(|(bucket, sample_count)| HitsPerSecondPoint {
            bucket,
            sample_count,
            per_second: sample_count as f64 / seconds,
        })
        .collect())
}

/// Materializes total transactions per second. It is separate from hits/sec
/// so the JSON/HTML section names cannot accidentally collapse.
pub fn aggregate_total_tps_graph_samples(
    samples: &[GraphSample],
    interval: ReportInterval,
    granularity_millis: u64,
    max_points: usize,
    options: GraphAggregationOptions,
) -> Result<Vec<TotalTpsPoint>, ReportError> {
    validate_graph_input(samples)?;
    validate_max_points(max_points)?;
    let width = validate_width(granularity_millis)?;
    // TotalTPS is a status-split consumer and includes controller results.
    // It therefore cannot be an alias for Hits Per Second.
    let mut buckets = BTreeMap::<(i64, bool), (GraphBucket, u64)>::new();
    for sample in samples {
        if !in_interval(sample, interval) || excluded(sample, options) {
            continue;
        }
        validate_sample_counts(sample)?;
        let successful = sample.successful().ok_or(ReportError::Unsupported {
            capability: MISSING_SUCCESS,
        })?;
        let bucket = bucket_for(sample.timestamp(), width)?;
        let key = (bucket.start().as_millis(), successful);
        if !buckets.contains_key(&key) {
            check_new_bucket(&buckets, max_points)?;
            buckets.insert(key, (bucket, 0));
        }
        let (_, count) = buckets.get_mut(&key).ok_or(ReportError::Serialization)?;
        *count = count
            .checked_add(sample.sample_count())
            .ok_or(ReportError::Overflow {
                field: ReportField::SampleCount,
            })?;
    }
    let seconds = granularity_millis as f64 / 1_000.0;
    Ok(buckets
        .into_iter()
        .map(
            |((_, successful), (bucket, transaction_count))| TotalTpsPoint {
                successful,
                bucket,
                transaction_count,
                per_second: transaction_count as f64 / seconds,
            },
        )
        .collect())
}

/// Materializes label-specific transaction rates.
pub fn aggregate_transactions_per_second_graph_samples(
    samples: &[GraphSample],
    interval: ReportInterval,
    granularity_millis: u64,
    max_points: usize,
    options: GraphAggregationOptions,
) -> Result<Vec<TransactionTpsPoint>, ReportError> {
    validate_graph_input(samples)?;
    validate_max_points(max_points)?;
    let width = validate_width(granularity_millis)?;
    // TransactionsPerSecondGraphConsumer uses one series per sampler label
    // and success status (`<label>-success` / `<label>-failure`). It is not a
    // rename of the label-count graph: merging status rows would change the
    // dashboard series topology.
    let mut buckets = BTreeMap::<(i64, String, bool), (GraphBucket, u64)>::new();
    for sample in samples {
        if !in_interval(sample, interval) || excluded(sample, options) {
            continue;
        }
        validate_sample_counts(sample)?;
        let label = sample.label().ok_or(ReportError::Unsupported {
            capability: MISSING_LABEL,
        })?;
        let successful = sample.successful().ok_or(ReportError::Unsupported {
            capability: MISSING_SUCCESS,
        })?;
        let bucket = bucket_for(sample.timestamp(), width)?;
        let key = (bucket.start().as_millis(), label.to_owned(), successful);
        if !buckets.contains_key(&key) {
            check_new_bucket(&buckets, max_points)?;
            buckets.insert(key.clone(), (bucket, 0));
        }
        let (_, count) = buckets.get_mut(&key).ok_or(ReportError::Serialization)?;
        *count = count
            .checked_add(sample.sample_count())
            .ok_or(ReportError::Overflow {
                field: ReportField::SampleCount,
            })?;
    }
    let seconds = granularity_millis as f64 / 1_000.0;
    Ok(buckets
        .into_iter()
        .map(
            |((_, label, successful), (bucket, transaction_count))| TransactionTpsPoint {
                bucket,
                label: format!(
                    "{}-{}",
                    label,
                    if successful { "success" } else { "failure" }
                ),
                transaction_count,
                per_second: transaction_count as f64 / seconds,
            },
        )
        .collect())
}

/// Returns the set of source labels in deterministic order.  This helper is
/// used by dashboard serializers to report cardinality without fabricating a
/// graph series.
pub fn graph_labels(
    samples: &[GraphSample],
    interval: ReportInterval,
    max_labels: usize,
    options: GraphAggregationOptions,
) -> Result<Vec<String>, ReportError> {
    validate_graph_input(samples)?;
    validate_max_points(max_labels)?;
    let mut labels = BTreeSet::new();
    for sample in samples {
        if !in_interval(sample, interval) || excluded(sample, options) {
            continue;
        }
        validate_sample_counts(sample)?;
        let label = sample.label().ok_or(ReportError::Unsupported {
            capability: MISSING_LABEL,
        })?;
        if labels.insert(label.to_owned()) && labels.len() > max_labels {
            return Err(ReportError::LimitExceeded {
                resource: ReportLimit::GraphSeriesKeys,
                actual: labels.len(),
                maximum: max_labels,
            });
        }
    }
    Ok(labels.into_iter().collect())
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use jmeter_rs_results::{ElapsedTime, ErrorCount, SampleCount, SampleResult};

    use super::*;

    fn interval() -> ReportInterval {
        ReportInterval::from_millis(0, 10_000).unwrap()
    }

    fn complete_sample(timestamp: i64, elapsed: u64) -> GraphSample {
        GraphSample::new(
            WallTimestamp::from_millis(timestamp),
            Some(elapsed),
            false,
            400,
            40,
        )
        .with_latency(Some(elapsed / 2))
        .with_connect(Some(elapsed / 4))
        .with_group_threads(Some(3))
        .with_all_threads(Some(8))
        .with_label("GET /items")
        .with_response_code("200")
        .with_response_message("OK")
        .with_success(Some(true))
    }

    #[test]
    fn named_consumers_keep_source_fields_and_payloads_distinct() {
        let samples = [complete_sample(100, 100), complete_sample(1_100, 300)];
        let options = GraphAggregationOptions::include_controllers();
        let latency =
            aggregate_latency_graph_samples(&samples, interval(), 2_000, 8, options).unwrap();
        let connect =
            aggregate_connect_graph_samples(&samples, interval(), 2_000, 8, options).unwrap();
        let bytes = aggregate_bytes_graph_samples(&samples, interval(), 2_000, 8, options).unwrap();
        let active =
            aggregate_active_threads_graph_samples(&samples, interval(), 2_000, 8, options)
                .unwrap();
        let response_codes =
            aggregate_response_code_graph_samples(&samples, interval(), 2_000, 8, options).unwrap();
        let labels =
            aggregate_label_graph_samples(&samples, interval(), 2_000, 8, options).unwrap();
        let response_time =
            aggregate_response_time_graph_samples(&samples, interval(), 2_000, 8, options).unwrap();
        assert_eq!(latency[0].latency_sum_millis(), 200.0);
        assert_eq!(connect[0].connect_sum_millis(), 100.0);
        assert_eq!(bytes[0].received_bytes(), 800);
        assert_eq!(bytes[0].sent_bytes(), 80);
        assert_eq!(active[0].group_threads(), Some(3));
        assert_eq!(active[0].all_threads(), Some(8));
        assert_eq!(response_codes[0].response_code(), "200");
        assert_eq!(response_codes[0].response_message(), "OK");
        assert_eq!(labels[0].label(), "GET /items");
        assert_eq!(response_time[0].elapsed_sum_millis(), 400.0);
        assert_ne!(
            latency[0].latency_sum_millis(),
            response_time[0].elapsed_sum_millis()
        );

        let distribution =
            aggregate_response_time_distribution_graph_samples(&samples, interval(), 8, 8, options)
                .unwrap();
        assert_eq!(distribution.len(), 2);
        let synthetic = aggregate_synthetic_response_time_graph_samples(
            &samples,
            interval(),
            500,
            1_500,
            8,
            options,
        )
        .unwrap();
        assert_eq!(synthetic.len(), 1);
        assert_eq!(synthetic[0].category(), 0);
        assert_eq!(synthetic[0].satisfied(), 2);
        let percentiles = aggregate_response_time_percentile_graph_samples(
            &samples,
            interval(),
            2_000,
            &[50.0, 90.0],
            8,
            8,
            options,
        )
        .unwrap();
        assert_eq!(percentiles[0].percentiles()[0], (50.0, Some(200.0)));
        assert_eq!(percentiles[0].percentiles()[1], (90.0, Some(300.0)));
    }

    #[test]
    fn weighted_latency_and_connect_stats_keep_effective_values_coherent() {
        let sample = complete_sample(100, 600)
            .with_latency(Some(40))
            .with_connect(Some(20))
            .with_counts(2, 1);
        let options = GraphAggregationOptions::include_controllers();
        let latency = aggregate_latency_graph_samples(
            std::slice::from_ref(&sample),
            interval(),
            2_000,
            8,
            options,
        )
        .unwrap();
        let connect = aggregate_connect_graph_samples(
            std::slice::from_ref(&sample),
            interval(),
            2_000,
            8,
            options,
        )
        .unwrap();

        assert_eq!(latency[0].sample_count(), 2);
        assert_eq!(latency[0].latency_count(), 2);
        assert_eq!(latency[0].latency_sum_millis(), 80.0);
        assert_eq!(latency[0].latency_mean_millis(), Some(40.0));
        assert_eq!(latency[0].latency_min_millis(), Some(40));
        assert_eq!(latency[0].latency_max_millis(), Some(40));
        assert_eq!(connect[0].sample_count(), 2);
        assert_eq!(connect[0].connect_count(), 2);
        assert_eq!(connect[0].connect_sum_millis(), 40.0);
        assert_eq!(connect[0].connect_mean_millis(), Some(20.0));
        assert_eq!(connect[0].connect_min_millis(), Some(20));
        assert_eq!(connect[0].connect_max_millis(), Some(20));
    }

    #[test]
    fn unavailable_specialized_fields_are_typed_errors() {
        let missing_elapsed = GraphSample::new(WallTimestamp::from_millis(100), None, false, 0, 0);
        let missing_latency =
            GraphSample::new(WallTimestamp::from_millis(100), Some(1), false, 0, 0);
        let options = GraphAggregationOptions::include_controllers();
        assert_eq!(
            aggregate_response_time_graph_samples(
                std::slice::from_ref(&missing_elapsed),
                interval(),
                2_000,
                8,
                options,
            ),
            Err(ReportError::Unsupported {
                capability: MISSING_ELAPSED
            })
        );
        assert_eq!(
            aggregate_latency_graph_samples(
                std::slice::from_ref(&missing_latency),
                interval(),
                2_000,
                8,
                options,
            ),
            Err(ReportError::Unsupported {
                capability: MISSING_LATENCY
            })
        );
    }

    #[test]
    fn graph_bucket_arithmetic_rejects_i64_minimum_overflow() {
        let interval = ReportInterval::from_millis(i64::MIN, i64::MIN + 5_000).unwrap();
        let sample = GraphSample::new(WallTimestamp::from_millis(i64::MIN), Some(1), false, 0, 0);
        assert_eq!(
            aggregate_response_time_graph_samples(
                std::slice::from_ref(&sample),
                interval,
                2_000,
                8,
                GraphAggregationOptions::include_controllers(),
            ),
            Err(ReportError::Overflow {
                field: ReportField::Timestamp
            })
        );
        assert_eq!(
            aggregate_graph_samples_for_test(&[sample], interval, 2_000),
            Err(ReportError::Overflow {
                field: ReportField::Timestamp
            })
        );
    }

    fn aggregate_graph_samples_for_test(
        samples: &[GraphSample],
        interval: ReportInterval,
        granularity: u64,
    ) -> Result<Vec<crate::GraphPoint>, ReportError> {
        crate::aggregate_graph_samples(samples, interval, granularity, 8)
    }

    #[test]
    fn calculator_variance_retains_large_offset_rounding() {
        let base = 1_000_000_000_000_u64;
        let samples = [
            GraphSample::new(WallTimestamp::from_millis(100), Some(base), false, 0, 0),
            GraphSample::new(WallTimestamp::from_millis(100), Some(base + 1), false, 0, 0),
        ];
        let points = aggregate_response_time_graph_samples(
            &samples,
            interval(),
            2_000,
            8,
            GraphAggregationOptions::include_controllers(),
        )
        .unwrap();
        // This negative result is the pinned raw Calculator subtraction. A
        // centered/Welford replacement or arbitrary max(0) clamp would hide
        // the compatibility-visible large-offset rounding behavior.
        assert_eq!(points[0].elapsed_variance_millis2(), Some(-134_217_728.0));
    }

    #[test]
    fn weighted_response_time_uses_effective_elapsed_for_min_and_max() {
        let mut result = SampleResult::new("weighted");
        result.set_timestamp(Some(WallTimestamp::from_millis(100)));
        assert!(
            result
                .set_elapsed(Some(ElapsedTime::from_millis(600)))
                .is_ok()
        );
        result.set_successful(true);
        result.set_sample_count(Some(SampleCount::from_u64(2)));
        result.set_error_count(Some(ErrorCount::ZERO));
        let sample = GraphSample::try_from_result(&result)
            .unwrap_or_else(|_| panic!("valid weighted result"))
            .unwrap_or_else(|| panic!("timestamp present"));
        assert_eq!(sample.elapsed_millis(), Some(300));
        let points = aggregate_response_time_graph_samples(
            std::slice::from_ref(&sample),
            interval(),
            2_000,
            8,
            GraphAggregationOptions::include_controllers(),
        )
        .unwrap();
        assert_eq!(points[0].elapsed_mean_millis(), Some(300.0));
        assert_eq!(points[0].elapsed_min_millis(), Some(300));
        assert_eq!(points[0].elapsed_max_millis(), Some(300));
    }

    #[test]
    fn response_code_series_merge_messages_but_retain_first_message_metadata() {
        let first = complete_sample(100, 100).with_response_message("first");
        let second = complete_sample(200, 100).with_response_message("second");
        let points = aggregate_response_code_graph_samples(
            &[first, second],
            interval(),
            2_000,
            8,
            GraphAggregationOptions::include_controllers(),
        )
        .unwrap();
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].response_code(), "200");
        assert_eq!(points[0].response_message(), "first");
        assert_eq!(points[0].sample_count(), 2);
    }

    #[test]
    fn response_time_distribution_uses_100_millisecond_elapsed_buckets() {
        let samples = [
            complete_sample(100, 105),
            complete_sample(200, 199),
            complete_sample(300, 201),
        ];
        let points = aggregate_response_time_distribution_graph_samples(
            &samples,
            interval(),
            8,
            8,
            GraphAggregationOptions::include_controllers(),
        )
        .unwrap();
        assert_eq!(
            points
                .iter()
                .map(|point| (point.elapsed_millis(), point.sample_count()))
                .collect::<Vec<_>>(),
            vec![(100, 2), (200, 1)]
        );
    }

    #[test]
    fn versus_request_graphs_emit_one_status_specific_median_per_second() {
        let samples = [
            complete_sample(100, 100).with_latency(Some(10)),
            complete_sample(900, 300).with_latency(Some(30)),
            complete_sample(1_100, 500).with_latency(Some(50)),
            complete_sample(2_100, 700).with_latency(Some(70)),
        ];
        let response = aggregate_response_time_vs_request_graph_samples(
            &samples,
            interval(),
            8,
            GraphAggregationOptions::include_controllers(),
        )
        .unwrap();
        assert_eq!(response.len(), 2);
        assert_eq!(response[0].requests_per_second(), 1);
        assert_eq!(response[0].timestamp().as_millis(), 1);
        assert_eq!(response[0].elapsed_millis(), 600.0);
        assert_eq!(response[1].requests_per_second(), 2);
        assert_eq!(response[1].timestamp().as_millis(), 2);
        // JMeter's MedianAggregatorFactory averages the two values in this
        // request-rate series (100 and 300), so the median is 200 ms.
        assert_eq!(response[1].elapsed_millis(), 200.0);

        let latency = aggregate_latency_vs_request_graph_samples(
            &samples,
            interval(),
            8,
            GraphAggregationOptions::include_controllers(),
        )
        .unwrap();
        assert_eq!(latency.len(), 2);
        assert_eq!(latency[0].requests_per_second(), 1);
        assert_eq!(latency[0].latency_millis(), 60.0);
        assert_eq!(latency[1].requests_per_second(), 2);
        assert_eq!(latency[1].latency_millis(), 20.0);
        assert_eq!(latency[0].successful(), Some(true));
    }

    #[test]
    fn versus_request_medians_keep_success_and_failure_series_separate() {
        let samples = [
            complete_sample(400, 700)
                .with_success(Some(false))
                .with_counts(1, 1),
            complete_sample(100, 100),
            complete_sample(300, 500)
                .with_success(Some(false))
                .with_counts(1, 1),
            complete_sample(200, 300),
        ];
        let points = aggregate_response_time_vs_request_graph_samples(
            &samples,
            interval(),
            8,
            GraphAggregationOptions::include_controllers(),
        )
        .unwrap();

        assert_eq!(points.len(), 2);
        let successful = match points.iter().find(|point| point.successful() == Some(true)) {
            Some(point) => point,
            None => panic!("successful versus-request series"),
        };
        assert_eq!(successful.requests_per_second(), 4);
        assert_eq!(successful.elapsed_millis(), 200.0);
        let failed = match points
            .iter()
            .find(|point| point.successful() == Some(false))
        {
            Some(point) => point,
            None => panic!("failed versus-request series"),
        };
        assert_eq!(failed.requests_per_second(), 4);
        assert_eq!(failed.elapsed_millis(), 600.0);
    }

    #[test]
    fn tps_consumers_keep_success_and_failure_series_separate() {
        let success = complete_sample(100, 100).with_label("GET");
        let failure = complete_sample(200, 100)
            .with_label("GET")
            .with_success(Some(false))
            .with_counts(1, 1);
        let total = aggregate_total_tps_graph_samples(
            &[success.clone(), failure.clone()],
            interval(),
            2_000,
            8,
            GraphAggregationOptions::include_controllers(),
        )
        .unwrap();
        assert_eq!(total.len(), 2);
        assert!(!total[0].successful());
        assert_eq!(total[0].transaction_count(), 1);
        assert!(total[1].successful());
        assert_eq!(total[1].transaction_count(), 1);

        let transactions = aggregate_transactions_per_second_graph_samples(
            &[success, failure],
            interval(),
            2_000,
            8,
            GraphAggregationOptions::include_controllers(),
        )
        .unwrap();
        assert_eq!(transactions.len(), 2);
        assert_eq!(transactions[0].label(), "GET-failure");
        assert_eq!(transactions[1].label(), "GET-success");
    }

    #[test]
    fn synthetic_distribution_uses_four_fixed_categories() {
        let samples = [
            complete_sample(100, 100),
            complete_sample(200, 600),
            complete_sample(300, 1_600),
            complete_sample(400, 1_600).with_success(Some(false)),
        ];
        let points = aggregate_synthetic_response_time_graph_samples(
            &samples,
            interval(),
            500,
            1_500,
            8,
            GraphAggregationOptions::include_controllers(),
        )
        .unwrap();
        assert_eq!(
            points
                .iter()
                .map(|point| (
                    point.category(),
                    point.satisfied(),
                    point.tolerated(),
                    point.frustrated()
                ))
                .collect::<Vec<_>>(),
            vec![(0, 1, 0, 0), (1, 0, 1, 0), (2, 0, 0, 1), (3, 0, 0, 1)]
        );
    }
}
