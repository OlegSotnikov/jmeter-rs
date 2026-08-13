// SPDX-License-Identifier: Apache-2.0
//! Deterministic, bounded graph/time-series aggregation.

use std::collections::BTreeMap;

use jmeter_rs_results::{SampleResult, WallTimestamp};

use crate::ReportInterval;
use crate::config::{AggregateLimits, validate_input_sample_count};
use crate::error::{ReportError, ReportField, ReportLimit, SampleField};
use crate::metrics::{SampleMetadata, represented_counts, validate_label};

/// One graph observation. The bytes and active-thread values are row values,
/// while `sample_count`/`error_count` and elapsed statistics can represent a
/// StatisticalSampleResult aggregate.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct GraphSample {
    timestamp: WallTimestamp,
    elapsed_millis: Option<u64>,
    /// Exact elapsed total represented by this row.  `elapsed_millis` is the
    /// effective per-row value exposed to legacy graph callers, while this
    /// value keeps a statistical row's wire total lossless when it is added
    /// to a weighted bucket (for example, 5 ms over 2 samples).
    elapsed_total_millis: Option<u128>,
    elapsed_present: bool,
    latency_millis: Option<u64>,
    connect_millis: Option<u64>,
    sample_count: u64,
    error_count: u64,
    received_bytes: Option<u64>,
    sent_bytes: Option<u64>,
    group_threads: Option<u64>,
    all_threads: Option<u64>,
    label: Option<String>,
    response_code: Option<String>,
    response_message: Option<String>,
    successful: Option<bool>,
    transaction_controller: bool,
}

/// Timestamp selected by a JMeter graph consumer when placing a result in a
/// time-series bucket. Most 5.6.3 over-time consumers use the sample end;
/// `hitsPerSecond` is the declared exception and uses the sample start.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum GraphTimestampPolicy {
    /// Use the sample start timestamp, falling back to the serialized value
    /// and then the end timestamp when a source omitted a field.
    Start,
    /// Use the sample end timestamp, falling back to the serialized value and
    /// then the start timestamp when a source omitted a field.
    #[default]
    End,
}

/// Count semantics selected when projecting a result into a graph row.
///
/// Listener aggregates use represented (weighted) counts for statistical
/// samples, while dashboard graph consumers operate on source rows.  Keeping
/// this choice explicit prevents a dashboard row from silently becoming a
/// weighted listener observation.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum GraphSampleCountMode {
    /// Preserve `SampleCount`/`ErrorCount` as represented weights.
    #[default]
    Weighted,
    /// Treat one serialized result row as one graph observation.
    Row,
}

impl GraphSample {
    /// Creates a graph observation.  A missing elapsed value contributes to
    /// counts/rates but not response-time statistics.
    pub const fn new(
        timestamp: WallTimestamp,
        elapsed_millis: Option<u64>,
        failed: bool,
        received_bytes: u64,
        sent_bytes: u64,
    ) -> Self {
        Self {
            timestamp,
            elapsed_millis,
            elapsed_total_millis: match elapsed_millis {
                Some(value) => Some(value as u128),
                None => None,
            },
            elapsed_present: elapsed_millis.is_some(),
            latency_millis: None,
            connect_millis: None,
            sample_count: 1,
            error_count: if failed { 1 } else { 0 },
            received_bytes: Some(received_bytes),
            sent_bytes: Some(sent_bytes),
            group_threads: None,
            all_threads: None,
            label: None,
            response_code: None,
            response_message: None,
            successful: Some(!failed),
            transaction_controller: false,
        }
    }

    /// Sets an optional all-thread count carried by this observation.
    pub const fn with_active_threads(mut self, active_threads: Option<u64>) -> Self {
        self.all_threads = active_threads;
        self
    }

    /// Sets the group-thread count carried by this observation.
    pub const fn with_group_threads(mut self, group_threads: Option<u64>) -> Self {
        self.group_threads = group_threads;
        self
    }

    /// Sets the all-thread count carried by this observation.
    pub const fn with_all_threads(mut self, all_threads: Option<u64>) -> Self {
        self.all_threads = all_threads;
        self
    }

    /// Sets the distinct latency timing field.
    pub const fn with_latency(mut self, latency_millis: Option<u64>) -> Self {
        self.latency_millis = latency_millis;
        self
    }

    /// Sets the distinct connect timing field.
    pub const fn with_connect(mut self, connect_millis: Option<u64>) -> Self {
        self.connect_millis = connect_millis;
        self
    }

    /// Sets the wire label used by label and transaction-rate consumers.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Sets the wire response code used by the response-code consumer.
    pub fn with_response_code(mut self, response_code: impl Into<String>) -> Self {
        self.response_code = Some(response_code.into());
        self
    }

    /// Sets the wire response message used to keep response-code ties stable.
    pub fn with_response_message(mut self, response_message: impl Into<String>) -> Self {
        self.response_message = Some(response_message.into());
        self
    }

    /// Sets the label and validates all graph strings against explicit report
    /// bounds before returning the row.
    pub fn try_with_label(
        self,
        label: impl Into<String>,
        limits: AggregateLimits,
    ) -> Result<Self, ReportError> {
        let sample = self.with_label(label);
        sample.validate_strings(limits)?;
        Ok(sample)
    }

    /// Sets the response code and validates all graph strings against
    /// explicit report bounds before returning the row.
    pub fn try_with_response_code(
        self,
        response_code: impl Into<String>,
        limits: AggregateLimits,
    ) -> Result<Self, ReportError> {
        let sample = self.with_response_code(response_code);
        sample.validate_strings(limits)?;
        Ok(sample)
    }

    /// Sets the response message and validates all graph strings against
    /// explicit report bounds before returning the row.
    pub fn try_with_response_message(
        self,
        response_message: impl Into<String>,
        limits: AggregateLimits,
    ) -> Result<Self, ReportError> {
        let sample = self.with_response_message(response_message);
        sample.validate_strings(limits)?;
        Ok(sample)
    }

    /// Validates the optional graph label and response-code/message strings
    /// without truncating or otherwise changing their wire values.
    pub fn validate_strings(&self, limits: AggregateLimits) -> Result<(), ReportError> {
        if let Some(label) = self.label() {
            validate_label(label, limits)?;
        }
        let error_key_bytes = self
            .response_code()
            .map_or(0, str::len)
            .saturating_add(self.response_message().map_or(0, str::len));
        if error_key_bytes > limits.max_error_key_bytes() {
            return Err(ReportError::LimitExceeded {
                resource: ReportLimit::ErrorKeyBytes,
                actual: error_key_bytes,
                maximum: limits.max_error_key_bytes(),
            });
        }
        Ok(())
    }

    /// Sets the optional wire success field.
    pub const fn with_success(mut self, successful: Option<bool>) -> Self {
        self.successful = successful;
        self
    }

    /// Sets whether the serialized elapsed field was present.  The elapsed
    /// value itself remains the reader's deterministic zero fallback when the
    /// field was absent, but specialized graph consumers can still report the
    /// distinction instead of treating missing input as measured latency.
    pub const fn with_elapsed_presence(mut self, present: bool) -> Self {
        self.elapsed_present = present;
        self
    }

    /// Replaces represented/error counts for an aggregate graph row.
    pub const fn with_counts(mut self, sample_count: u64, error_count: u64) -> Self {
        self.sample_count = sample_count;
        self.error_count = error_count;
        self.elapsed_total_millis = match self.elapsed_millis {
            Some(elapsed) => Some((elapsed as u128) * (sample_count as u128)),
            None => None,
        };
        self
    }

    /// Marks this row as a transaction-controller result for graph consumers
    /// whose pinned JMeter configuration excludes controllers.
    pub const fn with_transaction_controller(mut self, value: bool) -> Self {
        self.transaction_controller = value;
        self
    }

    /// Projects a result into one graph row using JMeter's default end-time
    /// graph policy. `hitsPerSecond` callers should use
    /// [`Self::try_from_result_with_timestamp`] with [`GraphTimestampPolicy::Start`].
    pub fn from_result(result: &SampleResult) -> Result<Option<Self>, ReportError> {
        Self::try_from_result(result)
    }

    /// Projects one result into a weighted graph row, returning malformed
    /// represented-count input as a typed report error.
    pub fn try_from_result(result: &SampleResult) -> Result<Option<Self>, ReportError> {
        Self::try_from_result_with_timestamp(result, GraphTimestampPolicy::End)
    }

    /// Projects one serialized result row without applying statistical sample
    /// weights.  This is the mode used by dashboard graph consumers; listener
    /// totals should continue to use [`Self::try_from_result`].
    pub fn try_from_result_as_row(result: &SampleResult) -> Result<Option<Self>, ReportError> {
        Self::try_from_result_with_count_mode(
            result,
            GraphSampleCountMode::Row,
            GraphTimestampPolicy::End,
        )
    }

    /// Projects one result using explicit event metadata.  Result and event
    /// wire models do not carry transaction-controller identity, so callers
    /// that have that runtime fact must use this adapter rather than infer it
    /// from a sampler label.
    pub fn try_from_result_with_metadata(
        result: &SampleResult,
        metadata: SampleMetadata,
    ) -> Result<Option<Self>, ReportError> {
        Self::try_from_result_with_metadata_and_timestamp(
            result,
            metadata,
            GraphTimestampPolicy::End,
        )
    }

    /// Projects one result using an explicit JMeter graph timestamp policy.
    /// This keeps end-time and start-time consumers distinct while preserving
    /// one weighted elapsed/count adapter.
    pub fn try_from_result_with_timestamp(
        result: &SampleResult,
        policy: GraphTimestampPolicy,
    ) -> Result<Option<Self>, ReportError> {
        Self::try_from_result_with_metadata_and_timestamp(result, SampleMetadata::sampler(), policy)
    }

    /// Projects one result with explicit count semantics and timestamp policy.
    pub fn try_from_result_with_count_mode(
        result: &SampleResult,
        mode: GraphSampleCountMode,
        policy: GraphTimestampPolicy,
    ) -> Result<Option<Self>, ReportError> {
        Self::try_from_result_with_metadata_and_timestamp_and_count_mode(
            result,
            SampleMetadata::sampler(),
            policy,
            mode,
        )
    }

    /// Projects one result using both explicit event metadata and a timestamp
    /// policy.  A missing timestamp is a typed error; it is never silently
    /// omitted from a graph stream.
    pub fn try_from_result_with_metadata_and_timestamp(
        result: &SampleResult,
        metadata: SampleMetadata,
        policy: GraphTimestampPolicy,
    ) -> Result<Option<Self>, ReportError> {
        Self::try_from_result_with_metadata_and_timestamp_and_count_mode(
            result,
            metadata,
            policy,
            GraphSampleCountMode::Weighted,
        )
    }

    /// Projects one result with explicit event metadata, timestamp policy, and
    /// count semantics.  The result/event wire models do not carry controller
    /// identity, so metadata remains an independent input.
    pub fn try_from_result_with_metadata_and_timestamp_and_count_mode(
        result: &SampleResult,
        metadata: SampleMetadata,
        policy: GraphTimestampPolicy,
        mode: GraphSampleCountMode,
    ) -> Result<Option<Self>, ReportError> {
        let counts = represented_counts(
            result,
            match mode {
                GraphSampleCountMode::Weighted => crate::metrics::CountMode::Weighted,
                GraphSampleCountMode::Row => crate::metrics::CountMode::Unweighted,
            },
        )?;
        let timestamp = match policy {
            GraphTimestampPolicy::Start => result
                .start_time()
                .or_else(|| result.timestamp())
                .or_else(|| result.end_time()),
            GraphTimestampPolicy::End => result
                .end_time()
                .or_else(|| result.timestamp())
                .or_else(|| result.start_time()),
        };
        let Some(timestamp) = timestamp else {
            return Err(ReportError::MissingTimestamp { section: "graph" });
        };
        let elapsed_present = result.elapsed().is_some();
        let elapsed_total = result.elapsed().map(|value| value.as_millis()).unwrap_or(0);
        // A zero represented count is retained as an empty graph row. The
        // explicit zero fallback is the pinned absent/empty elapsed value;
        // nonzero counts use the weighted per-sample division.
        let elapsed_millis = elapsed_total.checked_div(counts.samples).unwrap_or(0);
        let sample = Self {
            timestamp,
            elapsed_millis: Some(elapsed_millis),
            elapsed_total_millis: result.elapsed().map(|value| u128::from(value.as_millis())),
            elapsed_present,
            latency_millis: result.latency().map(|value| value.as_millis()),
            connect_millis: result.connect_time().map(|value| value.as_millis()),
            sample_count: counts.samples,
            error_count: counts.errors,
            received_bytes: result.received_bytes().map(|value| value.as_u64()),
            sent_bytes: result.sent_bytes().map(|value| value.as_u64()),
            group_threads: result.group_threads().map(|value| value.as_u64()),
            all_threads: result.all_threads().map(|value| value.as_u64()),
            label: result.label_field().map(ToOwned::to_owned),
            response_code: result.response_code().map(ToOwned::to_owned),
            response_message: result.response_message().map(ToOwned::to_owned),
            successful: result.success(),
            transaction_controller: metadata.is_transaction_controller(),
        };
        sample.validate_strings(AggregateLimits::default())?;
        Ok(Some(sample))
    }

    /// Returns the represented row count.
    pub const fn sample_count(&self) -> u64 {
        self.sample_count
    }

    /// Returns the represented failed-row count.
    pub const fn error_count(&self) -> u64 {
        self.error_count
    }

    /// Returns whether at least one represented row failed.
    pub const fn failed(&self) -> bool {
        self.error_count > 0
    }

    /// Returns the observation timestamp.
    pub const fn timestamp(&self) -> WallTimestamp {
        self.timestamp
    }

    /// Returns optional elapsed milliseconds.
    pub const fn elapsed_millis(&self) -> Option<u64> {
        self.elapsed_millis
    }

    /// Returns the exact elapsed total represented by this observation.
    ///
    /// A normal row has a total equal to its elapsed value.  A weighted row
    /// retains the original wire total instead of reconstructing it from an
    /// integer-divided per-row value.  The wider integer type makes the
    /// representation lossless for every pair of `u64` elapsed/count fields.
    pub const fn elapsed_total_millis(&self) -> Option<u128> {
        self.elapsed_total_millis
    }

    /// Returns the elapsed value only when the source row carried an elapsed
    /// wire field.  The legacy [`Self::elapsed_millis`] accessor intentionally
    /// retains its zero fallback for generic listener-style graph counters;
    /// field-specific response-time consumers use this accessor so an absent
    /// measurement cannot become a fabricated zero-latency observation.
    pub const fn elapsed_wire_millis(&self) -> Option<u64> {
        if self.elapsed_present {
            self.elapsed_millis
        } else {
            None
        }
    }

    /// Returns whether the serialized elapsed field was present.
    pub const fn elapsed_was_present(&self) -> bool {
        self.elapsed_present
    }

    /// Returns the distinct latency field.
    pub const fn latency_millis(&self) -> Option<u64> {
        self.latency_millis
    }

    /// Returns the distinct connect-time field.
    pub const fn connect_millis(&self) -> Option<u64> {
        self.connect_millis
    }

    /// Returns received bytes.
    pub const fn received_bytes(&self) -> u64 {
        match self.received_bytes {
            Some(value) => value,
            None => 0,
        }
    }

    /// Returns the received-byte wire field without inventing a zero.
    pub const fn received_bytes_field(&self) -> Option<u64> {
        self.received_bytes
    }

    /// Returns sent bytes.
    pub const fn sent_bytes(&self) -> u64 {
        match self.sent_bytes {
            Some(value) => value,
            None => 0,
        }
    }

    /// Returns the sent-byte wire field without inventing a zero.
    pub const fn sent_bytes_field(&self) -> Option<u64> {
        self.sent_bytes
    }

    /// Returns the optional active-thread count.
    pub const fn active_threads(&self) -> Option<u64> {
        self.all_threads
    }

    /// Returns the optional group-thread count.
    pub const fn group_threads(&self) -> Option<u64> {
        self.group_threads
    }

    /// Returns the optional all-thread count.
    pub const fn all_threads(&self) -> Option<u64> {
        self.all_threads
    }

    /// Returns the optional wire label.
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// Returns the optional response code.
    pub fn response_code(&self) -> Option<&str> {
        self.response_code.as_deref()
    }

    /// Returns the optional response message.
    pub fn response_message(&self) -> Option<&str> {
        self.response_message.as_deref()
    }

    /// Returns the optional wire success field.
    pub const fn successful(&self) -> Option<bool> {
        self.successful
    }

    /// Returns whether this row is marked as a transaction controller.
    pub const fn is_transaction_controller(&self) -> bool {
        self.transaction_controller
    }
}

/// Per-consumer graph filtering policy. JMeter's report generator declares
/// controller exclusion independently for each graph rather than globally.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct GraphAggregationOptions {
    exclude_transaction_controllers: bool,
}

impl GraphAggregationOptions {
    /// Includes controller rows (the default for graphs without an explicit
    /// `exclude_controllers=true` property).
    pub const fn include_controllers() -> Self {
        Self {
            exclude_transaction_controllers: false,
        }
    }

    /// Excludes rows marked as transaction controllers.
    pub const fn exclude_controllers() -> Self {
        Self {
            exclude_transaction_controllers: true,
        }
    }

    /// Returns the configured controller policy.
    pub const fn excludes_transaction_controllers(self) -> bool {
        self.exclude_transaction_controllers
    }
}

/// One fixed-width graph bucket.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GraphPoint {
    start: WallTimestamp,
    end: WallTimestamp,
    sample_count: u64,
    error_count: u64,
    elapsed_count: u64,
    elapsed_mean: Option<f64>,
    elapsed_stddev: Option<f64>,
    elapsed_sum_millis: Option<f64>,
    received_bytes: u64,
    sent_bytes: u64,
    throughput_per_second: f64,
    error_throughput_per_second: f64,
    active_threads: Option<u64>,
}

impl GraphPoint {
    /// Returns bucket start.
    pub const fn start(self) -> WallTimestamp {
        self.start
    }

    /// Returns bucket end.
    pub const fn end(self) -> WallTimestamp {
        self.end
    }

    /// Returns represented graph rows.
    pub const fn sample_count(self) -> u64 {
        self.sample_count
    }

    /// Returns failed graph rows.
    pub const fn error_count(self) -> u64 {
        self.error_count
    }

    /// Returns rows with elapsed values.
    pub const fn elapsed_count(self) -> u64 {
        self.elapsed_count
    }

    /// Returns elapsed mean.
    pub const fn elapsed_mean(self) -> Option<f64> {
        self.elapsed_mean
    }

    /// Returns population elapsed standard deviation.
    pub const fn elapsed_stddev(self) -> Option<f64> {
        self.elapsed_stddev
    }

    /// Returns the elapsed sum represented by this bucket.
    pub const fn elapsed_sum_millis(self) -> Option<f64> {
        self.elapsed_sum_millis
    }

    /// Returns received bytes.
    pub const fn received_bytes(self) -> u64 {
        self.received_bytes
    }

    /// Returns sent bytes.
    pub const fn sent_bytes(self) -> u64 {
        self.sent_bytes
    }

    /// Returns samples per second using this bucket's fixed granularity.
    pub const fn throughput_per_second(self) -> f64 {
        self.throughput_per_second
    }

    /// Returns failed samples per second in this bucket.
    pub const fn error_throughput_per_second(self) -> f64 {
        self.error_throughput_per_second
    }

    /// Returns the largest active-thread count observed in this bucket.
    pub const fn active_threads(self) -> Option<u64> {
        self.active_threads
    }
}

/// Aggregates graph observations into deterministic fixed-width buckets.
/// Granularity must be greater than one second, matching JMeter's throughput
/// graph contract.
///
/// Samples outside the explicit end-exclusive interval are ignored. Empty
/// buckets are omitted, matching JMeter's sparse graph data contract.
/// `max_points` bounds retained output and is checked before any result is
/// returned.
pub fn aggregate_graph_samples(
    samples: &[GraphSample],
    interval: ReportInterval,
    granularity_millis: u64,
    max_points: usize,
) -> Result<Vec<GraphPoint>, ReportError> {
    aggregate_graph_samples_with_options(
        samples,
        interval,
        granularity_millis,
        max_points,
        GraphAggregationOptions::include_controllers(),
    )
}

/// Aggregates graph observations using an explicit per-consumer policy.
///
/// Bucket keys are absolute epoch floors (`timestamp - timestamp % width`),
/// exactly as JMeter's `TimeStampKeysSelector` computes them. The report
/// interval is an end-exclusive source selection window: rows before the
/// start or at/after the end are ignored, while a retained bucket may begin
/// before an unaligned interval start because its key is absolute.
pub fn aggregate_graph_samples_with_options(
    samples: &[GraphSample],
    interval: ReportInterval,
    granularity_millis: u64,
    max_points: usize,
    options: GraphAggregationOptions,
) -> Result<Vec<GraphPoint>, ReportError> {
    validate_graph_input(samples)?;
    if granularity_millis <= 1_000 {
        return Err(ReportError::InvalidConfig {
            field: crate::ConfigField::OverallGranularity,
        });
    }
    if max_points == 0 {
        return Err(ReportError::InvalidConfig {
            field: crate::ConfigField::MaxGraphPoints,
        });
    }

    let width = i64::try_from(granularity_millis).map_err(|_| ReportError::Overflow {
        field: ReportField::Interval,
    })?;
    let start_bound = interval.start().as_millis();
    let end_bound = interval.end().as_millis();
    let mut buckets = BTreeMap::<i64, Bucket>::new();
    for sample in samples {
        let timestamp = sample.timestamp().as_millis();
        if timestamp < start_bound
            || timestamp >= end_bound
            || (options.excludes_transaction_controllers() && sample.is_transaction_controller())
        {
            continue;
        }
        let quotient = timestamp.div_euclid(width);
        let bucket_start = quotient.checked_mul(width).ok_or(ReportError::Overflow {
            field: ReportField::Timestamp,
        })?;
        if !buckets.contains_key(&bucket_start) && buckets.len() >= max_points {
            return Err(ReportError::LimitExceeded {
                resource: ReportLimit::GraphPoints,
                actual: buckets.len().saturating_add(1),
                maximum: max_points,
            });
        }
        let bucket = buckets.entry(bucket_start).or_default();
        bucket.add(sample.clone())?;
    }

    let mut points = Vec::with_capacity(buckets.len());
    for (bucket_start, bucket) in buckets {
        let start = WallTimestamp::from_millis(bucket_start);
        let end = start
            .checked_add_millis(width)
            .map_err(|_| ReportError::Overflow {
                field: ReportField::Interval,
            })?;
        points.push(bucket.finish(start, end, granularity_millis));
    }
    Ok(points)
}

pub(crate) fn validate_graph_input(samples: &[GraphSample]) -> Result<(), ReportError> {
    validate_graph_input_with_limits(samples, AggregateLimits::default())
}

pub(crate) fn validate_graph_input_with_limits(
    samples: &[GraphSample],
    limits: AggregateLimits,
) -> Result<(), ReportError> {
    validate_input_sample_count(samples.len(), limits.max_input_samples())?;
    for sample in samples {
        sample.validate_strings(limits)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default)]
struct Bucket {
    sample_count: u64,
    error_count: u64,
    elapsed_count: u64,
    mean: f64,
    m2: f64,
    sum: f64,
    sum_of_squares: f64,
    received_bytes: u64,
    sent_bytes: u64,
    active_threads: Option<u64>,
}

impl Bucket {
    fn add(&mut self, sample: GraphSample) -> Result<(), ReportError> {
        if sample.error_count() > sample.sample_count() {
            return Err(ReportError::InvalidSample {
                field: SampleField::ErrorCount,
            });
        }
        self.sample_count =
            self.sample_count
                .checked_add(sample.sample_count())
                .ok_or(ReportError::Overflow {
                    field: ReportField::SampleCount,
                })?;
        self.error_count =
            self.error_count
                .checked_add(sample.error_count())
                .ok_or(ReportError::Overflow {
                    field: ReportField::ErrorCount,
                })?;
        self.received_bytes = self
            .received_bytes
            .checked_add(sample.received_bytes())
            .ok_or(ReportError::Overflow {
                field: ReportField::ReceivedBytes,
            })?;
        self.sent_bytes =
            self.sent_bytes
                .checked_add(sample.sent_bytes())
                .ok_or(ReportError::Overflow {
                    field: ReportField::SentBytes,
                })?;
        if let Some(active_threads) = sample.active_threads() {
            self.active_threads = Some(
                self.active_threads
                    .map_or(active_threads, |current| current.max(active_threads)),
            );
        }
        if sample.sample_count() == 0 {
            return Ok(());
        }
        // The generic listener graph keeps the historical zero fallback for a
        // serialized row whose elapsed field is absent, while specialized
        // response-time consumers use `elapsed_wire_millis` and reject that
        // row.  Rows built directly with `None` have no fallback and remain
        // absent from elapsed statistics.
        let elapsed_total = if sample.elapsed_was_present() {
            sample.elapsed_total_millis()
        } else {
            sample.elapsed_millis().map(u128::from)
        };
        let Some(elapsed_total) = elapsed_total else {
            return Ok(());
        };
        let new_count = self
            .elapsed_count
            .checked_add(sample.sample_count())
            .ok_or(ReportError::Overflow {
                field: ReportField::ElapsedCount,
            })?;
        let weight = sample.sample_count() as f64;
        let elapsed = elapsed_total as f64;
        let sum = self.sum + elapsed;
        let sum_of_squares = self.sum_of_squares + elapsed * elapsed / weight;
        let mean = sum / new_count as f64;
        let variance_numerator = sum_of_squares - sum * sum / new_count as f64;
        if !sum.is_finite()
            || !sum_of_squares.is_finite()
            || !mean.is_finite()
            || !variance_numerator.is_finite()
        {
            return Err(ReportError::Overflow {
                field: ReportField::Variance,
            });
        }
        self.sum = sum;
        self.sum_of_squares = sum_of_squares;
        self.mean = mean;
        self.m2 = variance_numerator;
        self.elapsed_count = new_count;
        Ok(())
    }

    fn finish(self, start: WallTimestamp, end: WallTimestamp, width: u64) -> GraphPoint {
        GraphPoint {
            start,
            end,
            sample_count: self.sample_count,
            error_count: self.error_count,
            elapsed_count: self.elapsed_count,
            elapsed_mean: (self.elapsed_count > 0).then_some(self.mean),
            elapsed_stddev: (self.elapsed_count > 0)
                .then_some((self.m2 / self.elapsed_count as f64).sqrt()),
            elapsed_sum_millis: (self.elapsed_count > 0).then_some(self.sum),
            received_bytes: self.received_bytes,
            sent_bytes: self.sent_bytes,
            throughput_per_second: self.sample_count as f64 / (width as f64 / 1_000.0),
            error_throughput_per_second: self.error_count as f64 / (width as f64 / 1_000.0),
            active_threads: self.active_threads,
        }
    }
}

/// Writes graph points as a deterministic JSON array for report serializers.
pub(crate) fn write_graph_points_json(
    output: &mut String,
    points: &[GraphPoint],
) -> Result<(), ReportError> {
    const MAX_SERIALIZED_GRAPH_POINTS: usize = 100_000;
    if points.len() > MAX_SERIALIZED_GRAPH_POINTS {
        return Err(ReportError::LimitExceeded {
            resource: ReportLimit::GraphPoints,
            actual: points.len(),
            maximum: MAX_SERIALIZED_GRAPH_POINTS,
        });
    }
    for point in points {
        validate_graph_number(point.elapsed_sum_millis())?;
        validate_graph_number(point.elapsed_mean())?;
        validate_graph_number(point.elapsed_stddev())?;
        validate_graph_number(Some(point.throughput_per_second()))?;
        validate_graph_number(Some(point.error_throughput_per_second()))?;
    }
    output.push('[');
    for (index, point) in points.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push('{');
        output.push_str("\"start_ms\":");
        output.push_str(&point.start().as_millis().to_string());
        output.push_str(",\"end_ms_exclusive\":");
        output.push_str(&point.end().as_millis().to_string());
        output.push_str(",\"sample_count\":");
        output.push_str(&point.sample_count().to_string());
        output.push_str(",\"error_count\":");
        output.push_str(&point.error_count().to_string());
        output.push_str(",\"elapsed_count\":");
        output.push_str(&point.elapsed_count().to_string());
        output.push_str(",\"elapsed_sum_millis\":");
        write_graph_optional_number(output, point.elapsed_sum_millis())?;
        output.push_str(",\"elapsed_mean_millis\":");
        write_graph_optional_number(output, point.elapsed_mean())?;
        output.push_str(",\"elapsed_stddev_millis\":");
        write_graph_optional_number(output, point.elapsed_stddev())?;
        output.push_str(",\"received_bytes\":");
        output.push_str(&point.received_bytes().to_string());
        output.push_str(",\"sent_bytes\":");
        output.push_str(&point.sent_bytes().to_string());
        output.push_str(",\"throughput_per_second\":");
        output.push_str(&point.throughput_per_second().to_string());
        output.push_str(",\"error_throughput_per_second\":");
        output.push_str(&point.error_throughput_per_second().to_string());
        if let Some(active_threads) = point.active_threads() {
            output.push_str(",\"active_threads\":");
            output.push_str(&active_threads.to_string());
        }
        output.push('}');
    }
    output.push(']');
    Ok(())
}

fn validate_graph_number(value: Option<f64>) -> Result<(), ReportError> {
    if value.is_some_and(|value| !value.is_finite()) {
        Err(ReportError::Serialization)
    } else {
        Ok(())
    }
}

fn write_graph_optional_number(output: &mut String, value: Option<f64>) -> Result<(), ReportError> {
    match value {
        Some(value) if value.is_finite() => output.push_str(&value.to_string()),
        Some(_) => return Err(ReportError::Serialization),
        None => output.push_str("null"),
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use jmeter_rs_results::{ElapsedTime, ErrorCount, SampleCount};

    #[test]
    fn graph_buckets_are_sparse_sorted_and_bounded() {
        let interval = ReportInterval::from_millis(1_000, 5_000).unwrap();
        let samples = [
            GraphSample::new(WallTimestamp::from_millis(1_100), Some(10), false, 4, 2)
                .with_active_threads(Some(2)),
            GraphSample::new(WallTimestamp::from_millis(1_900), Some(30), true, 6, 3)
                .with_active_threads(Some(4)),
            GraphSample::new(WallTimestamp::from_millis(3_100), Some(50), false, 8, 4),
        ];
        let points = aggregate_graph_samples(&samples, interval, 2_000, 4).unwrap();
        assert_eq!(points.len(), 2);
        assert_eq!(points[0].start().as_millis(), 0);
        assert_eq!(points[0].sample_count(), 2);
        assert_eq!(points[0].error_count(), 1);
        assert_eq!(points[0].elapsed_mean(), Some(20.0));
        assert_eq!(points[0].active_threads(), Some(4));
        assert_eq!(points[1].start().as_millis(), 2_000);
        assert_eq!(points[1].throughput_per_second(), 0.5);
    }

    #[test]
    fn graph_bucket_order_uses_absolute_euclidean_floors() {
        let interval = ReportInterval::from_millis(-500, 2_001)
            .unwrap_or_else(|_| panic!("valid test interval"));
        let samples = [
            GraphSample::new(WallTimestamp::from_millis(1), Some(20), false, 0, 0),
            GraphSample::new(WallTimestamp::from_millis(-1), Some(10), false, 0, 0),
        ];
        let points = aggregate_graph_samples(&samples, interval, 2_000, 4)
            .unwrap_or_else(|_| panic!("valid graph samples"));
        assert_eq!(points.len(), 2);
        assert_eq!(points[0].start().as_millis(), -2_000);
        assert_eq!(points[0].end().as_millis(), 0);
        assert_eq!(points[0].sample_count(), 1);
        assert_eq!(points[1].start().as_millis(), 0);
        assert_eq!(points[1].sample_count(), 1);
    }

    #[test]
    fn graph_point_bound_failure_is_typed() {
        let interval = ReportInterval::from_millis(0, 5_000).unwrap();
        let samples = [
            GraphSample::new(WallTimestamp::from_millis(0), None, false, 0, 0),
            GraphSample::new(WallTimestamp::from_millis(4_000), None, false, 0, 0),
        ];
        assert_eq!(
            aggregate_graph_samples(&samples, interval, 2_000, 1),
            Err(ReportError::LimitExceeded {
                resource: ReportLimit::GraphPoints,
                actual: 2,
                maximum: 1,
            })
        );
    }

    #[test]
    fn weighted_result_projection_divides_elapsed_and_maps_absent_to_zero() {
        let timestamp = WallTimestamp::from_millis(1_704_067_202_000);
        let mut batch = SampleResult::new("api/search");
        batch.set_timestamp(Some(timestamp));
        assert!(
            batch
                .set_elapsed(Some(ElapsedTime::from_millis(600)))
                .is_ok()
        );
        batch.set_successful(false);
        batch.set_sample_count(Some(SampleCount::from_u64(2)));
        batch.set_error_count(Some(ErrorCount::from_u64(1)));
        let projected = GraphSample::try_from_result(&batch)
            .unwrap_or_else(|_| panic!("valid result"))
            .unwrap_or_else(|| panic!("timestamp present"));
        assert_eq!(projected.sample_count(), 2);
        assert_eq!(projected.error_count(), 1);
        assert_eq!(projected.elapsed_millis(), Some(300));

        let mut absent = SampleResult::new("api/health");
        absent.set_timestamp(Some(WallTimestamp::from_millis(1_704_067_205_000)));
        absent.set_successful(true);
        absent.set_sample_count(Some(SampleCount::ONE));
        absent.set_error_count(Some(ErrorCount::ZERO));
        let absent = GraphSample::try_from_result(&absent)
            .unwrap_or_else(|_| panic!("valid result"))
            .unwrap_or_else(|| panic!("timestamp present"));
        assert_eq!(absent.elapsed_millis(), Some(0));

        let interval = ReportInterval::from_millis(1_704_067_204_000, 1_704_067_206_000)
            .unwrap_or_else(|_| panic!("valid test interval"));
        let points = aggregate_graph_samples(&[absent], interval, 2_000, 1)
            .unwrap_or_else(|_| panic!("valid graph samples"));
        assert_eq!(points[0].sample_count(), 1);
        assert_eq!(points[0].elapsed_count(), 1);
        assert_eq!(points[0].elapsed_sum_millis(), Some(0.0));
    }

    #[test]
    fn weighted_projection_retains_non_divisible_elapsed_total() {
        let mut result = SampleResult::new("fractional");
        result.set_timestamp(Some(WallTimestamp::from_millis(1_000)));
        assert!(
            result
                .set_elapsed(Some(ElapsedTime::from_millis(5)))
                .is_ok()
        );
        result.set_successful(true);
        result.set_sample_count(Some(SampleCount::from_u64(2)));
        result.set_error_count(Some(ErrorCount::ZERO));

        let sample = GraphSample::try_from_result(&result)
            .unwrap_or_else(|_| panic!("valid weighted result"))
            .unwrap_or_else(|| panic!("timestamp present"));
        assert_eq!(sample.elapsed_millis(), Some(2));
        assert_eq!(sample.elapsed_total_millis(), Some(5));

        let interval =
            ReportInterval::from_millis(0, 2_000).unwrap_or_else(|_| panic!("valid test interval"));
        let points = aggregate_graph_samples(&[sample], interval, 2_000, 1)
            .unwrap_or_else(|_| panic!("valid graph samples"));
        assert_eq!(points[0].elapsed_count(), 2);
        assert_eq!(points[0].elapsed_sum_millis(), Some(5.0));
        assert_eq!(points[0].elapsed_mean(), Some(2.5));
    }

    #[test]
    fn row_projection_keeps_dashboard_row_identity() {
        let mut result = SampleResult::new("dashboard-row");
        result.set_timestamp(Some(WallTimestamp::from_millis(1_000)));
        assert!(
            result
                .set_elapsed(Some(ElapsedTime::from_millis(600)))
                .is_ok()
        );
        result.set_successful(false);
        result.set_sample_count(Some(SampleCount::from_u64(2)));
        result.set_error_count(Some(ErrorCount::from_u64(1)));

        let weighted = GraphSample::try_from_result(&result)
            .unwrap_or_else(|_| panic!("valid weighted result"))
            .unwrap_or_else(|| panic!("timestamp present"));
        let row = GraphSample::try_from_result_as_row(&result)
            .unwrap_or_else(|_| panic!("valid row result"))
            .unwrap_or_else(|| panic!("timestamp present"));
        assert_eq!(weighted.sample_count(), 2);
        assert_eq!(weighted.error_count(), 1);
        assert_eq!(weighted.elapsed_millis(), Some(300));
        assert_eq!(row.sample_count(), 1);
        assert_eq!(row.error_count(), 1);
        assert_eq!(row.elapsed_millis(), Some(600));
        assert_eq!(row.elapsed_total_millis(), Some(600));
    }

    #[test]
    fn graph_json_rejects_nonfinite_values_before_writing() {
        let base = 1_000_000_000_000_u64;
        let samples = [
            GraphSample::new(WallTimestamp::from_millis(100), Some(base), false, 0, 0),
            GraphSample::new(WallTimestamp::from_millis(100), Some(base + 1), false, 0, 0),
        ];
        let interval = ReportInterval::from_millis(0, 10_000)
            .unwrap_or_else(|_| panic!("valid test interval"));
        let points = aggregate_graph_samples(&samples, interval, 2_000, 8)
            .unwrap_or_else(|_| panic!("valid graph samples"));
        assert!(
            points[0]
                .elapsed_stddev()
                .is_some_and(|value| !value.is_finite())
        );
        let mut output = String::from("prefix");
        assert_eq!(
            write_graph_points_json(&mut output, &points),
            Err(ReportError::Serialization)
        );
        assert_eq!(output, "prefix");
    }

    #[test]
    fn graph_result_projection_selects_end_by_default_and_start_when_requested() {
        let mut result = SampleResult::new("timed");
        result.set_successful(true);
        result.set_sample_count(Some(SampleCount::ONE));
        result.set_error_count(Some(ErrorCount::ZERO));
        assert!(
            result
                .set_start_time(Some(WallTimestamp::from_millis(1_100)))
                .is_ok()
        );
        assert!(
            result
                .set_end_time(Some(WallTimestamp::from_millis(2_100)))
                .is_ok()
        );
        assert_eq!(
            GraphSample::try_from_result(&result)
                .unwrap_or_else(|_| panic!("valid result"))
                .map(|sample| sample.timestamp().as_millis()),
            Some(2_100)
        );
        assert_eq!(
            GraphSample::try_from_result_with_timestamp(&result, GraphTimestampPolicy::Start)
                .unwrap_or_else(|_| panic!("valid result"))
                .map(|sample| sample.timestamp().as_millis()),
            Some(1_100)
        );
    }

    #[test]
    fn timestamp_less_result_is_not_silently_dropped() {
        let mut result = SampleResult::new("untimed");
        result.set_successful(true);
        result.set_sample_count(Some(SampleCount::ONE));
        result.set_error_count(Some(ErrorCount::ZERO));
        assert_eq!(
            GraphSample::try_from_result(&result),
            Err(ReportError::MissingTimestamp { section: "graph" })
        );
    }

    #[test]
    fn graph_controller_policy_and_end_bound_are_explicit() {
        let interval = ReportInterval::from_millis(1_000, 5_000).unwrap();
        let controller =
            GraphSample::new(WallTimestamp::from_millis(2_100), Some(100), false, 10, 1)
                .with_transaction_controller(true);
        let ordinary = GraphSample::new(WallTimestamp::from_millis(2_100), Some(300), false, 20, 2);
        let at_end = GraphSample::new(WallTimestamp::from_millis(5_000), Some(500), false, 30, 3);
        let points = aggregate_graph_samples_with_options(
            &[controller, ordinary, at_end],
            interval,
            2_000,
            4,
            GraphAggregationOptions::exclude_controllers(),
        )
        .unwrap();
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].start().as_millis(), 2_000);
        assert_eq!(points[0].sample_count(), 1);
        assert_eq!(points[0].received_bytes(), 20);
    }

    #[test]
    fn zero_count_rows_still_preserve_active_thread_observations() {
        let interval =
            ReportInterval::from_millis(0, 2_000).unwrap_or_else(|_| panic!("valid test interval"));
        let sample = GraphSample::new(WallTimestamp::from_millis(1_000), None, false, 0, 0)
            .with_counts(0, 0)
            .with_active_threads(Some(7));
        let points = aggregate_graph_samples(&[sample], interval, 2_000, 1)
            .unwrap_or_else(|_| panic!("valid graph samples"));
        assert_eq!(points[0].sample_count(), 0);
        assert_eq!(points[0].elapsed_count(), 0);
        assert_eq!(points[0].active_threads(), Some(7));
    }

    #[test]
    fn graph_string_builders_and_validation_are_bounded() {
        let limits = AggregateLimits::new(4, 4, 4)
            .unwrap()
            .with_string_limits(3, 5)
            .unwrap();
        let sample = GraphSample::new(WallTimestamp::from_millis(2_100), Some(1), false, 0, 0);
        assert_eq!(
            sample.clone().try_with_label("abcd", limits),
            Err(ReportError::LimitExceeded {
                resource: ReportLimit::LabelBytes,
                actual: 4,
                maximum: 3,
            })
        );
        assert_eq!(
            sample
                .with_response_code("200")
                .try_with_response_message("error!", limits),
            Err(ReportError::LimitExceeded {
                resource: ReportLimit::ErrorKeyBytes,
                actual: 9,
                maximum: 5,
            })
        );
    }

    #[test]
    fn from_result_propagates_invalid_counts_instead_of_dropping_rows() {
        let mut result = SampleResult::new("invalid");
        result.set_timestamp(Some(WallTimestamp::from_millis(2_000)));
        result.set_sample_count(Some(SampleCount::from_u64(1)));
        result.set_error_count(Some(ErrorCount::from_u64(2)));
        result.set_successful(false);
        assert_eq!(
            GraphSample::from_result(&result),
            Err(ReportError::InvalidSample {
                field: SampleField::ErrorCount
            })
        );

        result.set_timestamp(None);
        assert_eq!(
            GraphSample::from_result(&result),
            Err(ReportError::InvalidSample {
                field: SampleField::ErrorCount
            })
        );
    }

    #[test]
    fn weighted_fixture_graph_counts_bytes_and_effective_elapsed() {
        let start = WallTimestamp::from_millis(1_704_067_200_000);
        let interval = ReportInterval::from_millis(1_704_067_200_000, 1_704_067_210_000)
            .unwrap_or_else(|_| panic!("valid fixture interval"));
        let samples = [
            GraphSample::new(start, Some(100), false, 1_000, 120),
            GraphSample::new(start, Some(500), false, 2_000, 180),
            GraphSample::new(start, Some(300), true, 2_200, 240).with_counts(2, 1),
            GraphSample::new(start, Some(1500), false, 3_000, 300),
            GraphSample::new(start, Some(1501), true, 400, 80),
            GraphSample::new(start, Some(0), false, 0, 0),
            GraphSample::new(start, Some(2500), false, 500, 50),
        ];
        let points = aggregate_graph_samples(&samples, interval, 10_000, 1)
            .unwrap_or_else(|_| panic!("valid graph"));
        assert_eq!(points.len(), 1);
        let point = points[0];
        assert_eq!(point.sample_count(), 8);
        assert_eq!(point.error_count(), 2);
        assert_eq!(point.elapsed_count(), 8);
        assert_eq!(point.elapsed_sum_millis(), Some(6701.0));
        assert_eq!(point.elapsed_mean(), Some(837.625));
        assert_eq!(point.received_bytes(), 9_100);
        assert_eq!(point.sent_bytes(), 970);
        assert_eq!(point.throughput_per_second(), 0.8);
        assert_eq!(point.error_throughput_per_second(), 0.2);
    }
}
