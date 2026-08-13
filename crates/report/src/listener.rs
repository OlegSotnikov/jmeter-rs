// SPDX-License-Identifier: Apache-2.0
//! Listener-side Aggregate/Summary/graph metrics.
//!
//! Listener percentiles intentionally use an exact, bounded observation set
//! and weighted Math.round rank selection.  This is not the dashboard estimator: JMeter's
//! GUI aggregate views and report generator use different percentile paths.

use std::collections::BTreeMap;

use jmeter_rs_results::{SampleEvent, SampleResult};

use crate::config::{
    DEFAULT_MAX_INPUT_SAMPLES, LabelGrouping, ListenerConfig, PercentileLevel,
    validate_input_sample_count,
};
use crate::error::{ReportError, ReportLimit};
use crate::graph::{
    GraphPoint, GraphSample, GraphTimestampPolicy, aggregate_graph_samples,
    validate_graph_input_with_limits, write_graph_points_json,
};
use crate::metrics::{
    SampleMetadata, SummaryMetrics, TopError, append_exact_observation, validate_label,
    validate_percentile,
};

/// Exact listener metrics for one sample label or the total row.
#[derive(Clone, Debug, PartialEq)]
pub struct ListenerMetrics {
    summary: SummaryMetrics,
    percentile_values: Vec<u64>,
    interval: crate::ReportInterval,
    top_error_limit: usize,
    percentiles: [u8; 3],
    percentile_levels: [PercentileLevel; 3],
}

impl ListenerMetrics {
    fn empty(config: ListenerConfig) -> Self {
        Self {
            summary: SummaryMetrics::new(),
            percentile_values: Vec::new(),
            interval: config.interval(),
            top_error_limit: config.top_error_limit(),
            percentiles: config.percentiles(),
            percentile_levels: config.percentile_levels(),
        }
    }

    /// Returns the shared count/timing/byte/APDEX/error summary.
    pub const fn summary(&self) -> &SummaryMetrics {
        &self.summary
    }

    /// Alias for [`ListenerMetrics::summary`].
    pub const fn metrics(&self) -> &SummaryMetrics {
        self.summary()
    }

    /// Returns the explicit interval used for rates.
    pub const fn interval(&self) -> crate::ReportInterval {
        self.interval
    }

    /// Returns represented sample count.
    pub const fn sample_count(&self) -> u64 {
        self.summary.sample_count()
    }

    /// Returns represented failed-sample count.
    pub const fn error_count(&self) -> u64 {
        self.summary.error_count()
    }

    /// Returns represented successful-sample count.
    pub const fn success_count(&self) -> u64 {
        self.summary.success_count()
    }

    /// Returns the number of samples with elapsed values.
    pub const fn elapsed_count(&self) -> u64 {
        self.summary.elapsed_count()
    }

    /// Returns the smallest elapsed value in milliseconds.
    pub const fn elapsed_min(&self) -> Option<u64> {
        self.summary.elapsed_min()
    }

    /// Returns the largest elapsed value in milliseconds.
    pub const fn elapsed_max(&self) -> Option<u64> {
        self.summary.elapsed_max()
    }

    /// Returns the elapsed mean in milliseconds.
    pub const fn elapsed_mean(&self) -> Option<f64> {
        self.summary.elapsed_mean()
    }

    /// Returns population standard deviation in milliseconds.
    pub fn elapsed_stddev(&self) -> Option<f64> {
        self.summary.elapsed_stddev()
    }

    /// Returns received-byte total.
    pub const fn received_bytes(&self) -> u64 {
        self.summary.received_bytes()
    }

    /// Returns sent-byte total.
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

    /// Returns samples per second over this report's explicit interval.
    pub fn throughput_per_second(&self) -> f64 {
        self.summary.throughput_per_second(self.interval)
    }

    /// Alias for [`ListenerMetrics::throughput_per_second`].
    pub fn throughput(&self) -> f64 {
        self.throughput_per_second()
    }

    /// Returns the failed-sample rate per second.
    pub fn error_throughput_per_second(&self) -> f64 {
        self.summary.error_throughput_per_second(self.interval)
    }

    /// Returns the percentage of represented samples that failed.
    pub fn error_percentage(&self) -> f64 {
        self.summary.error_percentage()
    }

    /// Returns the percentage of represented samples that succeeded.
    pub fn success_percentage(&self) -> f64 {
        self.summary.success_percentage()
    }

    /// Returns received bytes per second over this report's interval.
    pub fn received_bytes_per_second(&self) -> f64 {
        self.summary.received_bytes_per_second(self.interval)
    }

    /// Returns sent bytes per second over this report's interval.
    pub fn sent_bytes_per_second(&self) -> f64 {
        self.summary.sent_bytes_per_second(self.interval)
    }

    /// Returns APDEX category counts and score inputs.
    pub const fn apdex(&self) -> crate::ApdexCounts {
        self.summary.apdex()
    }

    /// Returns all error keys in deterministic key order.
    pub fn error_counts(&self) -> Vec<TopError> {
        self.summary.error_counts()
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

    /// Returns configured percentile levels, retaining decimal precision.
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

    /// Evaluates all configured percentile levels in deterministic order.
    pub fn percentiles(&self) -> Result<[Option<f64>; 3], ReportError> {
        Ok([
            self.percentile(self.percentile_levels[0].as_percent())?,
            self.percentile(self.percentile_levels[1].as_percent())?,
            self.percentile(self.percentile_levels[2].as_percent())?,
        ])
    }

    /// Returns the number of retained exact percentile observations.
    pub fn percentile_sample_count(&self) -> usize {
        self.percentile_values.len()
    }

    /// Returns JMeter's weighted percentile rank in milliseconds.
    ///
    /// Percentile zero selects the minimum and percentile 100 selects the
    /// maximum.  A summary with no elapsed observations returns `None`.
    pub fn percentile(&self, percentile: f64) -> Result<Option<f64>, ReportError> {
        validate_percentile(percentile)?;
        if self.percentile_values.is_empty() {
            return Ok(None);
        }
        let mut values = self.percentile_values.clone();
        values.sort_unstable();
        // JMeter's listener calculator uses Math.round(p * N) over the
        // weighted observation count.  Clamp the resulting one-based rank so
        // p=0 and sparse low percentiles still select the minimum.
        let rank = ((percentile / 100.0) * values.len() as f64).round();
        let index = rank.max(1.0) as usize - 1;
        Ok(Some(values[index.min(values.len() - 1)] as f64))
    }

    /// Returns the nearest-rank percentile as an integer number of
    /// milliseconds.
    pub fn percentile_millis(&self, percentile: f64) -> Result<Option<u64>, ReportError> {
        Ok(self.percentile(percentile)?.map(|value| value as u64))
    }

    /// Returns the median (50th percentile) in milliseconds.
    pub fn median(&self) -> Result<Option<f64>, ReportError> {
        self.percentile(50.0)
    }

    /// Adds one result to this already-created metric row.
    pub(crate) fn add_result_with_metadata(
        &mut self,
        result: &SampleResult,
        config: ListenerConfig,
        metadata: SampleMetadata,
    ) -> Result<(), ReportError> {
        let thresholds = metadata.apdex_thresholds().unwrap_or(config.apdex());
        let observation = self
            .summary
            .add_result(result, thresholds, config.limits())?;
        append_exact_observation(
            &mut self.percentile_values,
            observation,
            config.limits().max_percentile_samples(),
        )?;
        Ok(())
    }

    fn merge(&mut self, other: &Self, config: ListenerConfig) -> Result<(), ReportError> {
        let mut updated = self.clone();
        updated.summary.merge(&other.summary, config.limits())?;
        let new_len = updated
            .percentile_values
            .len()
            .checked_add(other.percentile_values.len())
            .ok_or(ReportError::LimitExceeded {
                resource: ReportLimit::PercentileSamples,
                actual: usize::MAX,
                maximum: config.limits().max_percentile_samples(),
            })?;
        if new_len > config.limits().max_percentile_samples() {
            return Err(ReportError::LimitExceeded {
                resource: ReportLimit::PercentileSamples,
                actual: new_len,
                maximum: config.limits().max_percentile_samples(),
            });
        }
        updated
            .percentile_values
            .extend_from_slice(&other.percentile_values);
        *self = updated;
        Ok(())
    }
}

/// Deterministic listener Aggregate/Summary report with a total row and
/// bounded per-label rows.
#[derive(Clone, Debug, PartialEq)]
pub struct ListenerReport {
    config: ListenerConfig,
    total: ListenerMetrics,
    labels: BTreeMap<String, ListenerMetrics>,
}

impl ListenerReport {
    /// Creates an empty listener report.
    pub fn new(config: ListenerConfig) -> Self {
        Self {
            config,
            total: ListenerMetrics::empty(config),
            labels: BTreeMap::new(),
        }
    }

    /// Returns the algorithm/resource configuration.
    pub const fn config(&self) -> ListenerConfig {
        self.config
    }

    /// Returns the total row.
    pub const fn total(&self) -> &ListenerMetrics {
        &self.total
    }

    /// Alias for [`ListenerReport::total`].
    pub const fn summary(&self) -> &ListenerMetrics {
        self.total()
    }

    /// Returns a row for one exact label, if it was observed.
    pub fn label(&self, label: &str) -> Option<&ListenerMetrics> {
        self.labels.get(label)
    }

    /// Returns rows in deterministic lexicographic label order.
    pub fn labels(&self) -> impl Iterator<Item = (&str, &ListenerMetrics)> {
        self.labels
            .iter()
            .map(|(label, metrics)| (label.as_str(), metrics))
    }

    /// Returns the number of distinct labels retained.
    pub fn label_count(&self) -> usize {
        self.labels.len()
    }

    /// Adds a result snapshot to the total and its label row.
    ///
    /// The operation is atomic.  On a limit, invalid-input, or overflow
    /// error, neither the total nor any label row is changed.
    pub fn add_result(&mut self, result: &SampleResult) -> Result<(), ReportError> {
        self.add_labeled_result(result, result.label(), SampleMetadata::sampler())
    }

    /// Adds a result with explicit controller metadata.  Listener top-error
    /// views include controller rows; metadata is retained for callers that
    /// also feed the same event into dashboard reports.
    pub fn add_result_with_metadata(
        &mut self,
        result: &SampleResult,
        metadata: SampleMetadata,
    ) -> Result<(), ReportError> {
        self.add_labeled_result(result, result.label(), metadata)
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
        next_total.add_result_with_metadata(result, self.config, metadata)?;
        let mut next_row = self
            .labels
            .get(label)
            .cloned()
            .unwrap_or_else(|| ListenerMetrics::empty(self.config));
        next_row.add_result_with_metadata(result, self.config, metadata)?;
        self.total = next_total;
        self.labels.insert(label.to_owned(), next_row);
        Ok(())
    }

    /// Alias for [`ListenerReport::add_result`].
    pub fn add_sample(&mut self, result: &SampleResult) -> Result<(), ReportError> {
        self.add_result(result)
    }

    /// Adds the result carried by a listener event.
    pub fn add_event(&mut self, event: &SampleEvent) -> Result<(), ReportError> {
        let label = grouped_label(
            self.config.label_grouping(),
            event.thread().group(),
            event.result().label(),
            self.config.limits(),
        )?;
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
            self.config.limits(),
        )?;
        self.add_labeled_result(event.result(), &label, metadata)
    }

    /// Merges another report with identical listener configuration.
    ///
    /// Listener percentile observations are exact, so merging concatenates
    /// the retained observations and remains independent of arrival order.
    /// The operation is atomic on all errors.
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
                .unwrap_or_else(|| ListenerMetrics::empty(self.config));
            next_row.merge(other_row, self.config)?;
            next_rows.push((label.clone(), next_row));
        }
        self.total = next_total;
        for (label, row) in next_rows {
            self.labels.insert(label, row);
        }
        Ok(())
    }

    /// Removes all observations while retaining this report's configuration.
    pub fn clear(&mut self) {
        self.total = ListenerMetrics::empty(self.config);
        self.labels.clear();
    }

    /// Aggregates caller-retained graph observations with an explicit bucket
    /// width. Listener configuration does not silently choose a graph scale.
    pub fn graph_series(
        &self,
        samples: &[GraphSample],
        granularity_millis: u64,
        max_points: usize,
    ) -> Result<Vec<GraphPoint>, ReportError> {
        validate_graph_input_with_limits(samples, self.config.limits())?;
        aggregate_graph_samples(
            samples,
            self.config.interval(),
            granularity_millis,
            max_points,
        )
    }

    /// Projects result snapshots into weighted graph rows and aggregates them
    /// with the supplied fixed bucket width.
    pub fn graph_series_from_results(
        &self,
        results: &[SampleResult],
        granularity_millis: u64,
        max_points: usize,
    ) -> Result<Vec<GraphPoint>, ReportError> {
        self.graph_series_from_results_with_policy(
            results,
            granularity_millis,
            max_points,
            GraphTimestampPolicy::End,
        )
    }

    /// Projects result snapshots with an explicit graph timestamp policy and
    /// aggregates them using the supplied fixed bucket width.
    pub fn graph_series_from_results_with_policy(
        &self,
        results: &[SampleResult],
        granularity_millis: u64,
        max_points: usize,
        policy: GraphTimestampPolicy,
    ) -> Result<Vec<GraphPoint>, ReportError> {
        validate_input_sample_count(results.len(), self.config.limits().max_input_samples())?;
        let mut samples = Vec::with_capacity(results.len());
        for result in results {
            if let Some(sample) = GraphSample::try_from_result_with_timestamp(result, policy)? {
                samples.push(sample);
            }
        }
        self.graph_series(&samples, granularity_millis, max_points)
    }

    /// Returns a deterministic JSON representation of Aggregate listener
    /// rows, including configured percentiles and error tables.
    pub fn to_json(&self) -> Result<String, ReportError> {
        self.to_json_with_graph(&[])
    }

    /// Returns listener JSON with an explicitly supplied graph projection.
    pub fn to_json_with_graph(&self, graph: &[GraphPoint]) -> Result<String, ReportError> {
        let mut output = String::new();
        output.push_str("{\"total\":");
        write_listener_metrics_json(&mut output, self.total())?;
        output.push_str(",\"labels\":[");
        for (index, (label, metrics)) in self.labels().enumerate() {
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            output.push_str("\"label\":");
            push_json_string(&mut output, label);
            output.push_str(",\"metrics\":");
            write_listener_metrics_json(&mut output, metrics)?;
            output.push('}');
        }
        output.push_str("],\"graph\":");
        write_graph_points_json(&mut output, graph)?;
        output.push('}');
        Ok(output)
    }

    /// Returns a deterministic escaped HTML table for Aggregate listener
    /// consumers.
    pub fn to_html(&self) -> Result<String, ReportError> {
        validate_listener_metrics_finite(self.total())?;
        for (_, metrics) in self.labels() {
            validate_listener_metrics_finite(metrics)?;
        }
        let mut output = String::from(
            "<!doctype html><meta charset=\"utf-8\"><table><thead><tr><th>Label</th><th>Samples</th><th>Successes</th><th>Errors</th><th>Average (ms)</th><th>Min (ms)</th><th>Max (ms)</th><th>Stddev (ms)</th><th>Median (ms)</th><th>Error %</th><th>Throughput</th><th>Error throughput</th><th>Received bytes</th><th>Sent bytes</th></tr></thead><tbody>",
        );
        push_listener_html_row(&mut output, "Total", self.total())?;
        for (label, metrics) in self.labels() {
            push_listener_html_row(&mut output, label, metrics)?;
        }
        output.push_str("</tbody></table>");
        push_listener_details_html(&mut output, self.total())?;
        Ok(output)
    }

    /// Alias for [`ListenerReport::to_json`].
    pub fn json(&self) -> Result<String, ReportError> {
        self.to_json()
    }

    /// Alias for [`ListenerReport::to_html`].
    pub fn html(&self) -> Result<String, ReportError> {
        self.to_html()
    }
}

/// Configuration for the low-memory Summary Report surface.
///
/// Unlike [`ListenerConfig`], this mode deliberately stores no percentile
/// observations while retaining weighted represented sample counts. It is
/// therefore a distinct memory/algorithm surface even when both reports
/// receive the same stream.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SummaryConfig {
    interval: crate::ReportInterval,
    limits: crate::AggregateLimits,
    apdex: crate::ApdexThresholds,
    top_error_limit: usize,
    label_grouping: LabelGrouping,
}

impl SummaryConfig {
    /// Creates Summary configuration from an explicit report interval.
    pub const fn new(interval: crate::ReportInterval) -> Self {
        Self {
            interval,
            limits: crate::AggregateLimits {
                max_labels: 4_096,
                max_error_keys: 4_096,
                max_percentile_samples: 1,
                max_input_samples: DEFAULT_MAX_INPUT_SAMPLES,
                max_label_bytes: 16 * 1024,
                max_error_key_bytes: 16 * 1024,
            },
            apdex: crate::ApdexThresholds {
                satisfied_millis: 500,
                tolerated_millis: 1_500,
            },
            top_error_limit: 5,
            label_grouping: LabelGrouping::Raw,
        }
    }

    /// Reuses bounds from listener configuration.
    pub const fn with_limits(mut self, limits: crate::AggregateLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Replaces APDEX thresholds.
    pub const fn with_apdex(mut self, apdex: crate::ApdexThresholds) -> Self {
        self.apdex = apdex;
        self
    }

    /// Sets the top-error limit.
    pub fn with_top_error_limit(mut self, limit: usize) -> Result<Self, ReportError> {
        if limit > self.limits.max_error_keys() {
            return Err(crate::ReportError::InvalidConfig {
                field: crate::ConfigField::TopErrorLimit,
            });
        }
        self.top_error_limit = limit;
        Ok(self)
    }

    /// Sets event-label grouping.
    pub const fn with_label_grouping(mut self, grouping: LabelGrouping) -> Self {
        self.label_grouping = grouping;
        self
    }

    /// Returns the explicit interval.
    pub const fn interval(self) -> crate::ReportInterval {
        self.interval
    }

    /// Returns resource bounds.
    pub const fn limits(self) -> crate::AggregateLimits {
        self.limits
    }

    /// Returns APDEX thresholds.
    pub const fn apdex(self) -> crate::ApdexThresholds {
        self.apdex
    }

    /// Returns top-error limit.
    pub const fn top_error_limit(self) -> usize {
        self.top_error_limit
    }

    /// Returns event-label grouping.
    pub const fn label_grouping(self) -> LabelGrouping {
        self.label_grouping
    }
}

impl From<ListenerConfig> for SummaryConfig {
    fn from(config: ListenerConfig) -> Self {
        let mut summary = Self::new(config.interval())
            .with_limits(config.limits())
            .with_apdex(config.apdex())
            .with_label_grouping(config.label_grouping());
        // Keep the configured listener limit across the infallible adapter.
        // Calling the fallible builder here would silently discard the value
        // on an otherwise representable ListenerConfig whose custom error-key
        // bound is smaller than the default limit.
        summary.top_error_limit = config.top_error_limit();
        summary
    }
}

/// Low-memory JMeter Summary Report with represented-count weighting and no
/// exact percentile observation store.
#[derive(Clone, Debug, PartialEq)]
pub struct SummaryReport {
    config: SummaryConfig,
    total: SummaryMetrics,
    labels: BTreeMap<String, SummaryMetrics>,
}

impl SummaryReport {
    /// Creates an empty Summary Report.
    pub fn new(config: impl Into<SummaryConfig>) -> Self {
        let config = config.into();
        Self {
            config,
            total: SummaryMetrics::new(),
            labels: BTreeMap::new(),
        }
    }

    /// Returns Summary configuration.
    pub const fn config(&self) -> SummaryConfig {
        self.config
    }

    /// Returns the complete-stream total row.
    pub const fn total(&self) -> &SummaryMetrics {
        &self.total
    }

    /// Alias for [`SummaryReport::total`].
    pub const fn summary(&self) -> &SummaryMetrics {
        self.total()
    }

    /// Returns one exact label row.
    pub fn label(&self, label: &str) -> Option<&SummaryMetrics> {
        self.labels.get(label)
    }

    /// Returns rows in deterministic lexicographic order.
    pub fn labels(&self) -> impl Iterator<Item = (&str, &SummaryMetrics)> {
        self.labels
            .iter()
            .map(|(label, metrics)| (label.as_str(), metrics))
    }

    /// Returns the retained label count.
    pub fn label_count(&self) -> usize {
        self.labels.len()
    }

    /// Adds one result row using GUI Summary's represented-count semantics.
    pub fn add_result(&mut self, result: &SampleResult) -> Result<(), ReportError> {
        self.add_labeled_result(result, result.label(), SampleMetadata::sampler())
    }

    /// Alias for [`SummaryReport::add_result`].
    pub fn add_sample(&mut self, result: &SampleResult) -> Result<(), ReportError> {
        self.add_result(result)
    }

    /// Adds one result row with explicit metadata.
    pub fn add_result_with_metadata(
        &mut self,
        result: &SampleResult,
        metadata: SampleMetadata,
    ) -> Result<(), ReportError> {
        self.add_labeled_result(result, result.label(), metadata)
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
        let mut next_total = self.total.clone();
        let thresholds = metadata.apdex_thresholds().unwrap_or(self.config.apdex());
        next_total.add_result(result, thresholds, self.config.limits())?;
        let mut next_row = self.labels.get(label).cloned().unwrap_or_default();
        next_row.add_result(result, thresholds, self.config.limits())?;
        self.total = next_total;
        self.labels.insert(label.to_owned(), next_row);
        Ok(())
    }

    /// Adds the result carried by an event, applying optional thread-group
    /// label qualification.
    pub fn add_event(&mut self, event: &SampleEvent) -> Result<(), ReportError> {
        let label = grouped_label(
            self.config.label_grouping(),
            event.thread().group(),
            event.result().label(),
            self.config.limits(),
        )?;
        self.add_labeled_result(event.result(), &label, SampleMetadata::sampler())
    }

    /// Adds an event with explicit metadata.
    pub fn add_event_with_metadata(
        &mut self,
        event: &SampleEvent,
        metadata: SampleMetadata,
    ) -> Result<(), ReportError> {
        let label = grouped_label(
            self.config.label_grouping(),
            event.thread().group(),
            event.result().label(),
            self.config.limits(),
        )?;
        self.add_labeled_result(event.result(), &label, metadata)
    }

    /// Merges another Summary Report with identical configuration.
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
        next_total.merge(&other.total, self.config.limits())?;
        let mut next_rows = Vec::with_capacity(other.labels.len());
        for (label, row) in &other.labels {
            let mut next_row = self.labels.get(label).cloned().unwrap_or_default();
            next_row.merge(row, self.config.limits())?;
            next_rows.push((label.clone(), next_row));
        }
        self.total = next_total;
        for (label, row) in next_rows {
            self.labels.insert(label, row);
        }
        Ok(())
    }

    /// Removes all rows while retaining configuration.
    pub fn clear(&mut self) {
        self.total = SummaryMetrics::new();
        self.labels.clear();
    }

    /// Aggregates caller-retained graph observations for the Summary stream.
    pub fn graph_series(
        &self,
        samples: &[GraphSample],
        granularity_millis: u64,
        max_points: usize,
    ) -> Result<Vec<GraphPoint>, ReportError> {
        validate_graph_input_with_limits(samples, self.config.limits())?;
        aggregate_graph_samples(
            samples,
            self.config.interval(),
            granularity_millis,
            max_points,
        )
    }

    /// Projects result snapshots into weighted graph rows and aggregates them
    /// for the Summary stream.
    pub fn graph_series_from_results(
        &self,
        results: &[SampleResult],
        granularity_millis: u64,
        max_points: usize,
    ) -> Result<Vec<GraphPoint>, ReportError> {
        self.graph_series_from_results_with_policy(
            results,
            granularity_millis,
            max_points,
            GraphTimestampPolicy::End,
        )
    }

    /// Projects result snapshots with an explicit graph timestamp policy and
    /// aggregates them for the Summary stream.
    pub fn graph_series_from_results_with_policy(
        &self,
        results: &[SampleResult],
        granularity_millis: u64,
        max_points: usize,
        policy: GraphTimestampPolicy,
    ) -> Result<Vec<GraphPoint>, ReportError> {
        validate_input_sample_count(results.len(), self.config.limits().max_input_samples())?;
        let mut samples = Vec::with_capacity(results.len());
        for result in results {
            if let Some(sample) = GraphSample::try_from_result_with_timestamp(result, policy)? {
                samples.push(sample);
            }
        }
        self.graph_series(&samples, granularity_millis, max_points)
    }

    /// Returns a deterministic JSON Summary projection.
    pub fn to_json(&self) -> Result<String, ReportError> {
        self.to_json_with_graph(&[])
    }

    /// Returns Summary JSON with an explicitly supplied graph projection.
    pub fn to_json_with_graph(&self, graph: &[GraphPoint]) -> Result<String, ReportError> {
        let mut output = String::new();
        output.push_str("{\"total\":");
        write_summary_metrics_json(
            &mut output,
            &self.total,
            self.config.interval(),
            self.config.top_error_limit(),
        )?;
        output.push_str(",\"labels\":[");
        for (index, (label, metrics)) in self.labels().enumerate() {
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            output.push_str("\"label\":");
            push_json_string(&mut output, label);
            output.push_str(",\"metrics\":");
            write_summary_metrics_json(
                &mut output,
                metrics,
                self.config.interval(),
                self.config.top_error_limit(),
            )?;
            output.push('}');
        }
        output.push_str("],\"graph\":");
        write_graph_points_json(&mut output, graph)?;
        output.push('}');
        Ok(output)
    }

    /// Returns a deterministic escaped HTML Summary table.
    pub fn to_html(&self) -> Result<String, ReportError> {
        validate_summary_metrics_finite(&self.total, self.config.interval())?;
        for (_, metrics) in self.labels() {
            validate_summary_metrics_finite(metrics, self.config.interval())?;
        }
        let mut output = String::from(
            "<!doctype html><meta charset=\"utf-8\"><table><thead><tr><th>Label</th><th>Samples</th><th>Successes</th><th>Errors</th><th>Average (ms)</th><th>Min (ms)</th><th>Max (ms)</th><th>Stddev (ms)</th><th>Error %</th><th>Throughput</th><th>Received bytes</th><th>Sent bytes</th></tr></thead><tbody>",
        );
        push_summary_html_row(&mut output, "Total", &self.total, self.config.interval())?;
        for (label, metrics) in self.labels() {
            push_summary_html_row(&mut output, label, metrics, self.config.interval())?;
        }
        output.push_str("</tbody></table>");
        push_summary_details_html(
            &mut output,
            &self.total,
            self.config.interval(),
            self.config.top_error_limit(),
        )?;
        Ok(output)
    }

    /// Alias for [`SummaryReport::to_json`].
    pub fn json(&self) -> Result<String, ReportError> {
        self.to_json()
    }

    /// Alias for [`SummaryReport::to_html`].
    pub fn html(&self) -> Result<String, ReportError> {
        self.to_html()
    }
}

/// Compatibility name for the listener Aggregate Report surface.
pub type AggregateReport = ListenerReport;

/// Compatibility name for listener-side aggregate state.
pub type ListenerAggregate = ListenerReport;

fn grouped_label(
    grouping: LabelGrouping,
    group: Option<&str>,
    label: &str,
    limits: crate::AggregateLimits,
) -> Result<String, ReportError> {
    // Validate before concatenating. Events created by a caller without the
    // results crate's snapshot constructor are still untrusted at this
    // boundary, and a giant thread-group name must not force an unbounded
    // temporary allocation merely to produce a limit error.
    validate_label(label, limits)?;
    match (grouping, group) {
        (LabelGrouping::ThreadGroup, Some(group)) if !group.is_empty() => {
            let actual = group
                .len()
                .checked_add(1)
                .and_then(|value| value.checked_add(label.len()))
                .unwrap_or(usize::MAX);
            if actual > limits.max_label_bytes() {
                return Err(ReportError::LimitExceeded {
                    resource: ReportLimit::LabelBytes,
                    actual,
                    maximum: limits.max_label_bytes(),
                });
            }
            let mut qualified = String::with_capacity(actual);
            qualified.push_str(group);
            qualified.push(':');
            qualified.push_str(label);
            Ok(qualified)
        }
        _ => Ok(label.to_owned()),
    }
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

fn write_listener_number(output: &mut String, value: Option<f64>) -> Result<(), ReportError> {
    match value {
        Some(value) if value.is_finite() => output.push_str(&value.to_string()),
        Some(_) => return Err(ReportError::Serialization),
        None => output.push_str("null"),
    }
    Ok(())
}

fn format_listener_html_number(value: Option<f64>) -> Result<String, ReportError> {
    match value {
        Some(value) if value.is_finite() => Ok(value.to_string()),
        Some(_) => Err(ReportError::Serialization),
        None => Ok(String::new()),
    }
}

fn validate_listener_metrics_finite(metrics: &ListenerMetrics) -> Result<(), ReportError> {
    for value in [
        metrics.elapsed_mean(),
        metrics.elapsed_stddev(),
        metrics.summary().elapsed_variance(),
        Some(metrics.error_percentage()),
        Some(metrics.success_percentage()),
        Some(metrics.throughput_per_second()),
        Some(metrics.error_throughput_per_second()),
        Some(metrics.received_bytes_per_second()),
        Some(metrics.sent_bytes_per_second()),
        metrics.apdex().score(),
    ] {
        let _ = format_listener_html_number(value)?;
    }
    for percentile in SERIALIZED_PERCENTILES {
        let _ = format_listener_html_number(metrics.percentile(percentile)?)?;
    }
    Ok(())
}

fn validate_summary_metrics_finite(
    metrics: &SummaryMetrics,
    interval: crate::ReportInterval,
) -> Result<(), ReportError> {
    for value in [
        metrics.elapsed_mean(),
        metrics.elapsed_stddev(),
        metrics.elapsed_variance(),
        Some(metrics.error_percentage()),
        Some(metrics.success_percentage()),
        Some(metrics.throughput_per_second(interval)),
        Some(metrics.error_throughput_per_second(interval)),
        Some(metrics.received_bytes_per_second(interval)),
        Some(metrics.sent_bytes_per_second(interval)),
        metrics.apdex().score(),
    ] {
        let _ = format_listener_html_number(value)?;
    }
    Ok(())
}

fn write_listener_errors(output: &mut String, values: &[TopError]) {
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

fn write_listener_metrics_json(
    output: &mut String,
    metrics: &ListenerMetrics,
) -> Result<(), ReportError> {
    validate_listener_metrics_finite(metrics)?;
    output.push('{');
    output.push_str("\"sample_count\":");
    output.push_str(&metrics.sample_count().to_string());
    output.push_str(",\"success_count\":");
    output.push_str(&metrics.success_count().to_string());
    output.push_str(",\"error_count\":");
    output.push_str(&metrics.error_count().to_string());
    output.push_str(",\"elapsed_count\":");
    output.push_str(&metrics.elapsed_count().to_string());
    output.push_str(",\"average_millis\":");
    write_listener_number(output, metrics.elapsed_mean())?;
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
    write_listener_number(output, metrics.elapsed_stddev())?;
    output.push_str(",\"elapsed_variance_population_millis2\":");
    write_listener_number(output, metrics.summary().elapsed_variance())?;
    output.push_str(",\"error_percentage\":");
    write_listener_number(output, Some(metrics.error_percentage()))?;
    output.push_str(",\"throughput_per_second\":");
    write_listener_number(output, Some(metrics.throughput_per_second()))?;
    output.push_str(",\"error_throughput_per_second\":");
    write_listener_number(output, Some(metrics.error_throughput_per_second()))?;
    output.push_str(",\"received_bytes\":");
    output.push_str(&metrics.received_bytes().to_string());
    output.push_str(",\"sent_bytes\":");
    output.push_str(&metrics.sent_bytes().to_string());
    output.push_str(",\"received_bytes_per_second\":");
    write_listener_number(output, Some(metrics.received_bytes_per_second()))?;
    output.push_str(",\"sent_bytes_per_second\":");
    write_listener_number(output, Some(metrics.sent_bytes_per_second()))?;
    output.push_str(",\"success_percentage\":");
    write_listener_number(output, Some(metrics.success_percentage()))?;
    output.push_str(",\"apdex\":{");
    output.push_str("\"satisfied\":");
    output.push_str(&metrics.apdex().satisfied().to_string());
    output.push_str(",\"tolerated\":");
    output.push_str(&metrics.apdex().tolerated().to_string());
    output.push_str(",\"frustrated\":");
    output.push_str(&metrics.apdex().frustrated().to_string());
    output.push_str(",\"score\":");
    write_listener_number(output, metrics.apdex().score())?;
    output.push('}');
    output.push_str(",\"percentiles\":[");
    let values = metrics.percentiles()?;
    for (index, value) in values.into_iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        write_listener_number(output, value)?;
    }
    output.push_str("],\"errors\":[");
    write_listener_errors(output, &metrics.error_counts());
    output.push_str("],\"error_counts\":[");
    write_listener_errors(output, &metrics.error_counts());
    output.push_str("],\"top_errors\":[");
    write_listener_errors(output, &metrics.top_errors());
    output.push_str("],\"percentile_sample_count\":");
    output.push_str(&metrics.percentile_sample_count().to_string());
    output.push_str(",\"percentiles_millis\":{");
    write_listener_percentile_map(output, metrics, false)?;
    output.push_str("},\"percentiles_millis_rounded\":{");
    write_listener_percentile_map(output, metrics, true)?;
    output.push_str("}}");
    Ok(())
}

const SERIALIZED_PERCENTILES: [f64; 8] = [0.0, 25.0, 50.0, 75.0, 90.0, 95.0, 99.0, 100.0];

fn write_listener_percentile_map(
    output: &mut String,
    metrics: &ListenerMetrics,
    rounded: bool,
) -> Result<(), ReportError> {
    for (index, percentile) in SERIALIZED_PERCENTILES.iter().enumerate() {
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
        write_listener_number(output, value)?;
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

fn push_listener_html_escaped(output: &mut String, value: &str) {
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

fn push_listener_html_row(
    output: &mut String,
    label: &str,
    metrics: &ListenerMetrics,
) -> Result<(), ReportError> {
    let values = [
        metrics.sample_count().to_string(),
        metrics.success_count().to_string(),
        metrics.error_count().to_string(),
        format_listener_html_number(metrics.elapsed_mean())?,
        metrics
            .elapsed_min()
            .map_or_else(String::new, |value| value.to_string()),
        metrics
            .elapsed_max()
            .map_or_else(String::new, |value| value.to_string()),
        format_listener_html_number(metrics.elapsed_stddev())?,
        format_listener_html_number(metrics.median()?)?,
        format_listener_html_number(Some(metrics.error_percentage()))?,
        format_listener_html_number(Some(metrics.throughput_per_second()))?,
        format_listener_html_number(Some(metrics.error_throughput_per_second()))?,
        metrics.received_bytes().to_string(),
        metrics.sent_bytes().to_string(),
    ];
    output.push_str("<tr><td>");
    push_listener_html_escaped(output, label);
    for value in values {
        output.push_str("</td><td>");
        output.push_str(&value);
    }
    output.push_str("</td></tr>");
    Ok(())
}

fn write_summary_metrics_json(
    output: &mut String,
    metrics: &SummaryMetrics,
    interval: crate::ReportInterval,
    top_error_limit: usize,
) -> Result<(), ReportError> {
    validate_summary_metrics_finite(metrics, interval)?;
    output.push('{');
    output.push_str("\"sample_count\":");
    output.push_str(&metrics.sample_count().to_string());
    output.push_str(",\"success_count\":");
    output.push_str(&metrics.success_count().to_string());
    output.push_str(",\"error_count\":");
    output.push_str(&metrics.error_count().to_string());
    output.push_str(",\"elapsed_count\":");
    output.push_str(&metrics.elapsed_count().to_string());
    output.push_str(",\"average_millis\":");
    write_listener_number(output, metrics.elapsed_mean())?;
    output.push_str(",\"min_millis\":");
    write_listener_number(output, metrics.elapsed_min().map(|value| value as f64))?;
    output.push_str(",\"max_millis\":");
    write_listener_number(output, metrics.elapsed_max().map(|value| value as f64))?;
    output.push_str(",\"stddev_millis\":");
    write_listener_number(output, metrics.elapsed_stddev())?;
    output.push_str(",\"elapsed_variance_population_millis2\":");
    write_listener_number(output, metrics.elapsed_variance())?;
    output.push_str(",\"error_percentage\":");
    write_listener_number(output, Some(metrics.error_percentage()))?;
    output.push_str(",\"success_percentage\":");
    write_listener_number(output, Some(metrics.success_percentage()))?;
    output.push_str(",\"throughput_per_second\":");
    write_listener_number(output, Some(metrics.throughput_per_second(interval)))?;
    output.push_str(",\"error_throughput_per_second\":");
    write_listener_number(output, Some(metrics.error_throughput_per_second(interval)))?;
    output.push_str(",\"received_bytes\":");
    output.push_str(&metrics.received_bytes().to_string());
    output.push_str(",\"sent_bytes\":");
    output.push_str(&metrics.sent_bytes().to_string());
    output.push_str(",\"received_bytes_per_second\":");
    write_listener_number(output, Some(metrics.received_bytes_per_second(interval)))?;
    output.push_str(",\"sent_bytes_per_second\":");
    write_listener_number(output, Some(metrics.sent_bytes_per_second(interval)))?;
    output.push_str(",\"apdex\":{");
    output.push_str("\"satisfied\":");
    output.push_str(&metrics.apdex().satisfied().to_string());
    output.push_str(",\"tolerated\":");
    output.push_str(&metrics.apdex().tolerated().to_string());
    output.push_str(",\"frustrated\":");
    output.push_str(&metrics.apdex().frustrated().to_string());
    output.push_str(",\"score\":");
    write_listener_number(output, metrics.apdex().score())?;
    output.push_str("},\"error_counts\":[");
    write_listener_errors(output, &metrics.error_counts());
    output.push_str("],\"errors\":[");
    write_listener_errors(output, &metrics.error_counts());
    output.push_str("],\"top_errors\":[");
    write_listener_errors(output, &metrics.top_errors(top_error_limit));
    output.push_str(
        "],\"percentile_sample_count\":0,\"percentiles\":null,\"percentiles_millis\":null,\"percentiles_millis_rounded\":null}",
    );
    Ok(())
}

fn push_summary_html_row(
    output: &mut String,
    label: &str,
    metrics: &SummaryMetrics,
    interval: crate::ReportInterval,
) -> Result<(), ReportError> {
    let values = [
        metrics.sample_count().to_string(),
        metrics.success_count().to_string(),
        metrics.error_count().to_string(),
        format_listener_html_number(metrics.elapsed_mean())?,
        metrics
            .elapsed_min()
            .map_or_else(String::new, |value| value.to_string()),
        metrics
            .elapsed_max()
            .map_or_else(String::new, |value| value.to_string()),
        format_listener_html_number(metrics.elapsed_stddev())?,
        format_listener_html_number(Some(metrics.error_percentage()))?,
        format_listener_html_number(Some(metrics.throughput_per_second(interval)))?,
        metrics.received_bytes().to_string(),
        metrics.sent_bytes().to_string(),
    ];
    output.push_str("<tr><td>");
    push_listener_html_escaped(output, label);
    for value in values {
        output.push_str("</td><td>");
        output.push_str(&value);
    }
    output.push_str("</td></tr>");
    Ok(())
}

fn push_listener_details_html(
    output: &mut String,
    metrics: &ListenerMetrics,
) -> Result<(), ReportError> {
    let score = format_listener_html_number(metrics.apdex().score())?;
    let percentiles = SERIALIZED_PERCENTILES
        .into_iter()
        .map(|percentile| {
            metrics
                .percentile(percentile)
                .and_then(format_listener_html_number)
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
        push_listener_error_html(output, error.key());
        output.push_str(": ");
        output.push_str(&error.count().to_string());
        output.push_str("</li>");
    }
    output.push_str("</ul></section><section id=\"top-errors\"><h2>Top errors</h2><ul>");
    for error in metrics.top_errors() {
        output.push_str("<li>");
        push_listener_error_html(output, error.key());
        output.push_str(": ");
        output.push_str(&error.count().to_string());
        output.push_str("</li>");
    }
    output.push_str("</ul></section>");
    Ok(())
}

fn push_summary_details_html(
    output: &mut String,
    metrics: &SummaryMetrics,
    interval: crate::ReportInterval,
    top_error_limit: usize,
) -> Result<(), ReportError> {
    let score = format_listener_html_number(metrics.apdex().score())?;
    let throughput = format_listener_html_number(Some(metrics.throughput_per_second(interval)))?;
    output.push_str("<section id=\"apdex\"><h2>APDEX</h2><p>Satisfied: ");
    output.push_str(&metrics.apdex().satisfied().to_string());
    output.push_str("; Tolerated: ");
    output.push_str(&metrics.apdex().tolerated().to_string());
    output.push_str("; Frustrated: ");
    output.push_str(&metrics.apdex().frustrated().to_string());
    output.push_str("; Score: ");
    output.push_str(&score);
    output.push_str("</p><p>Percentiles: not retained by Summary (bounded low-memory surface).</p></section><section id=\"errors\"><h2>Errors</h2><ul>");
    for error in metrics.error_counts() {
        output.push_str("<li>");
        push_listener_error_html(output, error.key());
        output.push_str(": ");
        output.push_str(&error.count().to_string());
        output.push_str("</li>");
    }
    output.push_str("</ul></section><section id=\"top-errors\"><h2>Top errors</h2><ul>");
    for error in metrics.top_errors(top_error_limit) {
        output.push_str("<li>");
        push_listener_error_html(output, error.key());
        output.push_str(": ");
        output.push_str(&error.count().to_string());
        output.push_str("</li>");
    }
    output.push_str("</ul><p>Throughput: ");
    output.push_str(&throughput);
    output.push_str("</p></section>");
    Ok(())
}

fn push_listener_error_html(output: &mut String, key: &crate::ErrorKey) {
    if key.code() == "Assertion failed" {
        if key.message().is_empty() {
            output.push_str(key.code());
        } else {
            output.push_str(key.message());
        }
        return;
    }
    push_listener_html_escaped(output, key.code());
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
    use jmeter_rs_results::{
        AssertionResult, ByteCount, ElapsedTime, ErrorCount, SampleCount, ThreadIdentity,
        VariableSnapshot, WallTimestamp,
    };

    fn config() -> ListenerConfig {
        ListenerConfig::new(
            crate::ReportInterval::from_millis(0, 1_000)
                .unwrap_or_else(|_| panic!("test interval must be valid")),
        )
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
        result.set_received_bytes(Some(ByteCount::new(100)));
        result.set_sent_bytes(Some(ByteCount::new(10)));
        result.set_sample_count(Some(SampleCount::ONE));
        result.set_error_count(Some(if success {
            ErrorCount::ZERO
        } else {
            ErrorCount::from_u64(1)
        }));
        result
    }

    fn report_fixture_results() -> Vec<SampleResult> {
        fn bytes(mut result: SampleResult, received: u64, sent: u64) -> SampleResult {
            result.set_received_bytes(Some(ByteCount::new(received)));
            result.set_sent_bytes(Some(ByteCount::new(sent)));
            result
        }
        let mut search_batch = sample("api/search", 600, false, "503", "overload");
        search_batch.set_received_bytes(Some(ByteCount::new(2_200)));
        search_batch.set_sent_bytes(Some(ByteCount::new(240)));
        search_batch.set_sample_count(Some(SampleCount::from_u64(2)));
        search_batch.set_error_count(Some(ErrorCount::from_u64(1)));
        let mut health = SampleResult::new("api/health");
        health.set_successful(true);
        health.set_response_code_text("204");
        health.set_response_message_text("No Content");
        health.set_error_count(Some(ErrorCount::ZERO));
        vec![
            bytes(sample("api/login", 100, true, "200", "OK"), 1_000, 120),
            bytes(sample("api/search", 500, true, "200", "OK"), 2_000, 180),
            search_batch,
            bytes(sample("api/write", 1500, true, "200", "OK"), 3_000, 300),
            bytes(sample("api/write", 1501, false, "409", "conflict"), 400, 80),
            health,
            bytes(sample("api/cache", 2500, true, "200", "OK"), 500, 50),
        ]
    }

    #[test]
    fn listener_golden_metrics_are_deterministic() {
        let mut report = ListenerReport::new(config());
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
        assert_eq!(total.error_count(), 2);
        assert_eq!(total.elapsed_min(), Some(100));
        assert_eq!(total.elapsed_max(), Some(600));
        assert_eq!(total.elapsed_mean(), Some(375.0));
        assert!((total.elapsed_stddev().unwrap_or_default() - 227.76084).abs() < 0.001);
        assert_eq!(total.received_bytes(), 400);
        assert_eq!(total.sent_bytes(), 40);
        assert_eq!(total.average_received_bytes(), Some(100.0));
        assert_eq!(total.throughput(), 4.0);
        assert_eq!(total.received_bytes_per_second(), 400.0);
        assert_eq!(total.error_percentage(), 50.0);
        assert_eq!(total.percentile_millis(50.0), Ok(Some(200)));
        assert_eq!(total.percentile_millis(75.0), Ok(Some(600)));
        assert_eq!(total.apdex().satisfied(), 1);
        assert_eq!(total.apdex().tolerated(), 1);
        assert_eq!(total.apdex().frustrated(), 2);
        assert_eq!(total.top_errors()[0].key().code(), "500");
        assert_eq!(total.top_errors()[0].count(), 2);
        assert_eq!(
            report.labels().map(|(label, _)| label).collect::<Vec<_>>(),
            ["alpha", "beta"]
        );
        assert_eq!(
            total.percentile(f64::NAN),
            Err(ReportError::InvalidPercentile)
        );
    }

    #[test]
    fn listener_limit_errors_are_atomic() {
        let limits =
            crate::AggregateLimits::new(1, 1, 2).unwrap_or_else(|_| panic!("valid limits"));
        let config = config().with_limits(limits);
        let mut report = ListenerReport::new(config);
        assert!(
            report
                .add_result(&sample("one", 1, true, "200", "ok"))
                .is_ok()
        );
        let before = report.clone();
        assert!(matches!(
            report.add_result(&sample("two", 2, true, "200", "ok")),
            Err(ReportError::LimitExceeded {
                resource: ReportLimit::Labels,
                ..
            })
        ));
        assert_eq!(report, before);
        assert!(matches!(
            report.add_result(&sample("one", 3, false, "500", "first")),
            Ok(())
        ));
        let before = report.clone();
        assert!(matches!(
            report.add_result(&sample("one", 4, false, "501", "second")),
            Err(ReportError::LimitExceeded {
                resource: ReportLimit::ErrorKeys,
                ..
            })
        ));
        assert_eq!(report, before);
        assert!(matches!(
            report.add_result(&sample("one", 5, true, "200", "ok")),
            Err(ReportError::LimitExceeded {
                resource: ReportLimit::PercentileSamples,
                ..
            })
        ));
        assert_eq!(report, before);
    }

    #[test]
    fn listener_merge_is_associative_for_exact_observations() {
        let mut left = ListenerReport::new(config());
        let mut right = ListenerReport::new(config());
        assert!(
            left.add_result(&sample("a", 100, true, "200", "ok"))
                .is_ok()
        );
        assert!(
            right
                .add_result(&sample("a", 300, true, "200", "ok"))
                .is_ok()
        );
        assert!(left.merge(&right).is_ok());
        assert_eq!(left.total().sample_count(), 2);
        assert_eq!(left.total().percentile_millis(50.0), Ok(Some(100)));
        assert!(matches!(
            left.merge(&ListenerReport::new(ListenerConfig::new(
                crate::ReportInterval::from_millis(0, 2_000).unwrap_or_else(|_| panic!("valid")),
            ))),
            Err(ReportError::IncompatibleMerge)
        ));
    }

    #[test]
    fn listener_merge_checks_combined_label_limit_before_mutation() {
        let limits = crate::AggregateLimits::new(2, 4, 16).unwrap();
        let config = config().with_limits(limits);
        let mut left = ListenerReport::new(config);
        let mut right = ListenerReport::new(config);
        assert!(
            left.add_result(&sample("left", 1, true, "200", "ok"))
                .is_ok()
        );
        assert!(
            right
                .add_result(&sample("one", 1, true, "200", "ok"))
                .is_ok()
        );
        assert!(
            right
                .add_result(&sample("two", 1, true, "200", "ok"))
                .is_ok()
        );
        let before = left.clone();
        assert!(matches!(
            left.merge(&right),
            Err(ReportError::LimitExceeded {
                resource: ReportLimit::Labels,
                actual: 3,
                maximum: 2,
            })
        ));
        assert_eq!(left, before);
    }

    #[test]
    fn listener_counter_overflow_is_atomic() {
        let mut report = ListenerReport::new(config());
        let mut huge = SampleResult::new("huge");
        huge.set_sample_count(Some(SampleCount::from_u64(u64::MAX)));
        huge.set_error_count(Some(ErrorCount::ZERO));
        huge.set_successful(true);
        assert!(matches!(
            report.add_result(&huge),
            Err(ReportError::LimitExceeded {
                resource: ReportLimit::PercentileSamples,
                ..
            })
        ));
        assert_eq!(report.total().sample_count(), 0);
    }

    #[test]
    fn listener_percentile_uses_jmeter_round_rank() {
        let mut report = ListenerReport::new(config());
        for (label, elapsed) in [("one", 10), ("two", 20), ("three", 30)] {
            assert!(
                report
                    .add_result(&sample(label, elapsed, true, "200", "ok"))
                    .is_ok()
            );
        }
        // ceil(34% * 3) would select 20; JMeter's Math.round selects rank 1.
        assert_eq!(report.total().percentile_millis(34.0), Ok(Some(10)));
    }

    #[test]
    fn listener_rates_use_observed_label_span() {
        let mut report = ListenerReport::new(config());
        let mut result = sample("timed", 2_000, true, "200", "ok");
        assert!(
            result
                .set_start_time(Some(WallTimestamp::from_millis(1_000)))
                .is_ok()
        );
        assert!(
            result
                .set_end_time(Some(WallTimestamp::from_millis(3_000)))
                .is_ok()
        );
        assert!(report.add_result(&result).is_ok());
        assert_eq!(report.total().throughput(), 0.5);
        assert_eq!(
            report.label("timed").map(ListenerMetrics::throughput),
            Some(0.5)
        );
    }

    #[test]
    fn failed_result_without_error_count_is_frustrated_and_uses_assertion_key() {
        let mut report = ListenerReport::new(config());
        let mut result = sample("failed", 100, false, "500", "");
        result.set_error_count(Some(ErrorCount::ZERO));
        assert!(
            result
                .add_assertion(AssertionResult::failed(
                    "assert",
                    Some("line\nfailed".to_owned()),
                ))
                .is_ok()
        );
        assert!(report.add_result(&result).is_ok());
        assert_eq!(report.total().error_count(), 1);
        assert_eq!(report.total().apdex().frustrated(), 1);
        let errors = report.total().error_counts();
        assert_eq!(errors.len(), 1);
        // A non-success HTTP response keeps the response-code/message key;
        // assertion fallback is only selected for 2xx/3xx (or an empty code
        // with a non-blank failure message), matching ErrorsSummaryConsumer.
        assert_eq!(errors[0].key().code(), "500");
        assert_eq!(errors[0].key().message(), "");
        assert_eq!(errors[0].key().jmeter_key(), "500");
    }

    #[test]
    fn assertion_failure_is_an_error_when_wire_success_and_counts_are_absent() {
        let mut report = ListenerReport::new(config());
        let mut result = SampleResult::new("assert-only");
        assert!(
            result
                .set_elapsed(Some(ElapsedTime::from_millis(20)))
                .is_ok()
        );
        assert!(
            result
                .add_assertion(AssertionResult::errored(
                    "assert",
                    Some("assertion error".to_owned()),
                ))
                .is_ok()
        );
        assert!(report.add_result(&result).is_ok());
        assert_eq!(report.total().error_count(), 1);
        assert_eq!(report.total().apdex().frustrated(), 1);
    }

    #[test]
    fn error_key_uses_assertion_fallback_and_html4_escaping() {
        let mut report = ListenerReport::new(config());
        let mut result = sample("assert", 20, false, "200", "ignored");
        result.set_error_count(Some(ErrorCount::ZERO));
        result.set_failure_message(Some("Test failed: <title> & \\\"x\\\"".to_owned()));
        assert!(report.add_result(&result).is_ok());
        let error = &report.total().error_counts()[0];
        assert_eq!(error.key().code(), "Assertion failed");
        assert_eq!(
            error.key().message(),
            "Test failed: &lt;title&gt; &amp; \\\\&quot;x\\\\&quot;"
        );
        assert_eq!(
            error.key().jmeter_key(),
            "Test failed: &lt;title&gt; &amp; \\\\&quot;x\\\\&quot;"
        );
        let html = report.to_html().unwrap_or_else(|_| panic!("valid HTML"));
        assert!(html.contains("Test failed: &lt;title&gt;"));
        assert!(!html.contains("&amp;lt;title&amp;gt;"));

        let mut escaped = sample("escaped", 20, false, "500", "it's bad\u{0001}");
        escaped.set_error_count(Some(ErrorCount::from_u64(1)));
        let mut raw_report = ListenerReport::new(config());
        assert!(raw_report.add_result(&escaped).is_ok());
        let raw_key = &raw_report.total().error_counts()[0];
        assert_eq!(raw_key.key().code(), "500");
        assert_eq!(raw_key.key().message(), "it&apos;s bad\\u0001");
        assert_eq!(raw_key.key().jmeter_key(), "500/it&apos;s bad\\u0001");

        let mut direct_assertion = sample("direct-assert", 20, false, "200", "ignored");
        direct_assertion.set_error_count(Some(ErrorCount::ZERO));
        assert!(
            direct_assertion
                .add_assertion(AssertionResult::failed(
                    "assert",
                    Some("from assertion".to_owned()),
                ))
                .is_ok()
        );
        let mut direct_report = ListenerReport::new(config());
        assert!(direct_report.add_result(&direct_assertion).is_ok());
        assert_eq!(
            direct_report.total().error_counts()[0].key().jmeter_key(),
            "from assertion"
        );
    }

    #[test]
    fn successful_result_does_not_create_an_error_from_stale_error_count() {
        let mut report = ListenerReport::new(config());
        let mut result = sample("success", 20, true, "200", "ok");
        result.set_error_count(Some(ErrorCount::from_u64(1)));
        assert!(report.add_result(&result).is_ok());
        assert_eq!(report.total().error_count(), 0);
        assert!(report.total().error_counts().is_empty());
    }

    #[test]
    fn failed_batch_is_all_frustrated_even_with_partial_wire_error_count() {
        let mut report = ListenerReport::new(config());
        let mut result = sample("batch-failed", 100, false, "500", "bad");
        result.set_sample_count(Some(SampleCount::from_u64(4)));
        result.set_error_count(Some(ErrorCount::from_u64(1)));
        assert!(report.add_result(&result).is_ok());
        assert_eq!(report.total().sample_count(), 4);
        assert_eq!(report.total().error_count(), 1);
        assert_eq!(report.total().apdex().frustrated(), 1);
        assert_eq!(report.total().apdex().satisfied(), 3);
    }

    #[test]
    fn summary_is_distinct_and_weighted_without_percentiles() {
        let mut result = sample("batch", 100, true, "200", "ok");
        result.set_sample_count(Some(SampleCount::from_u64(4)));
        result.set_error_count(Some(ErrorCount::ZERO));
        let mut summary = SummaryReport::new(SummaryConfig::new(
            crate::ReportInterval::from_millis(0, 1_000).unwrap(),
        ));
        assert!(summary.add_result(&result).is_ok());
        assert_eq!(summary.total().sample_count(), 4);
        assert_eq!(summary.total().elapsed_count(), 4);
        assert_eq!(summary.total().top_errors(5).len(), 0);
    }

    #[test]
    fn summary_merge_preserves_weighted_statistics_and_limits() {
        let summary_config =
            SummaryConfig::new(crate::ReportInterval::from_millis(0, 1_000).unwrap());
        let mut left = SummaryReport::new(summary_config);
        let mut right = SummaryReport::new(summary_config);
        assert!(
            left.add_result(&sample("row", 10, true, "200", "ok"))
                .is_ok()
        );
        assert!(
            right
                .add_result(&sample("row", 30, true, "200", "ok"))
                .is_ok()
        );
        assert!(left.merge(&right).is_ok());
        assert_eq!(left.total().sample_count(), 2);
        assert_eq!(left.total().elapsed_count(), 2);
        assert_eq!(left.total().elapsed_mean(), Some(20.0));
    }

    #[test]
    fn per_transaction_apdex_threshold_override_is_applied_atomically() {
        let mut report = ListenerReport::new(config());
        let result = sample("strict", 1, true, "200", "ok");
        let strict = crate::ApdexThresholds::new(0, 0).unwrap();
        assert!(
            report
                .add_result_with_metadata(&result, SampleMetadata::sampler_with_apdex(strict))
                .is_ok()
        );
        assert_eq!(report.total().apdex().satisfied(), 0);
        assert_eq!(report.total().apdex().frustrated(), 1);
    }

    #[test]
    fn event_grouping_is_explicit_and_deterministic() {
        let listener_config = config().with_label_grouping(LabelGrouping::ThreadGroup);
        let mut report = ListenerReport::new(listener_config);
        let result = sample("request", 10, true, "200", "ok");
        let event = SampleEvent::new(
            result,
            "run",
            ThreadIdentity::with_group("thread", Some("group".to_owned()), None),
            "host",
            VariableSnapshot::new(),
        );
        assert!(report.add_event(&event).is_ok());
        assert!(report.label("group:request").is_some());
    }

    #[test]
    fn listener_aggregates_only_the_immutable_event_snapshot() {
        let mut result = sample("before", 10, true, "200", "ok");
        let mut variables = VariableSnapshot::new();
        variables.insert("phase", "before");
        let event = SampleEvent::snapshot(
            &result,
            "run-1",
            ThreadIdentity::with_group("thread-1", Some("group-a".to_owned()), Some(1)),
            "host-1",
            variables,
        )
        .unwrap_or_else(|_| panic!("fixed event snapshot must validate"));

        // Mutating the producer-owned values after notification must not
        // change the event delivered to a run-owned listener.
        result.set_label("after");
        let mut report = ListenerReport::new(config());
        report
            .add_event(&event)
            .unwrap_or_else(|_| panic!("snapshot event must aggregate"));
        assert_eq!(report.label_count(), 1);
        assert!(report.label("before").is_some());
        assert!(report.label("after").is_none());
        assert_eq!(event.result().label(), "before");
        assert_eq!(event.thread().group(), Some("group-a"));
        assert_eq!(
            event
                .variables()
                .get("phase")
                .and_then(|value| value.as_str()),
            Some("before")
        );
    }

    #[test]
    fn listener_filtering_is_an_upstream_boundary_and_does_not_reinterpret_rows() {
        // ResultCollector's error_logging/success_only policy is applied by
        // the routing layer before a report sink.  The report algorithm must
        // count exactly the stream it receives, including ignored and
        // transaction-controller rows, rather than deriving policy from a
        // label or a mutable result flag.
        let mut success = sample("success", 10, true, "200", "ok");
        let mut ignored = sample("ignored", 20, true, "200", "ok");
        ignored.set_ignored(true);
        let controller = sample("transaction", 30, false, "500", "failed");
        let events = [
            SampleEvent::new(
                success.clone(),
                "run",
                ThreadIdentity::new("t"),
                "host",
                VariableSnapshot::new(),
            ),
            SampleEvent::new(
                ignored,
                "run",
                ThreadIdentity::new("t"),
                "host",
                VariableSnapshot::new(),
            ),
            SampleEvent::new(
                controller,
                "run",
                ThreadIdentity::new("t"),
                "host",
                VariableSnapshot::new(),
            ),
        ];
        let mut report = ListenerReport::new(config());
        for event in &events {
            report
                .add_event(event)
                .unwrap_or_else(|_| panic!("fixed event must aggregate"));
        }
        assert_eq!(report.total().sample_count(), 3);
        assert_eq!(report.total().error_count(), 1);

        // A caller can construct a filtered stream explicitly.  This keeps
        // the four truth-table combinations observable without silently
        // making the report layer guess which collector flags were selected.
        success.set_successful(false);
        let filtered = SampleEvent::new(
            success,
            "run",
            ThreadIdentity::new("t"),
            "host",
            VariableSnapshot::new(),
        );
        let mut filtered_report = ListenerReport::new(config());
        filtered_report
            .add_event(&filtered)
            .unwrap_or_else(|_| panic!("filtered event must aggregate"));
        assert_eq!(filtered_report.total().sample_count(), 1);
        assert_eq!(filtered_report.total().error_count(), 1);
    }

    #[test]
    fn listener_grouping_keeps_same_label_rows_distinct_by_thread_group() {
        let listener_config = config().with_label_grouping(LabelGrouping::ThreadGroup);
        let mut report = ListenerReport::new(listener_config);
        for group in ["group-b", "group-a", "group-b"] {
            let event = SampleEvent::new(
                sample("request", 10, true, "200", "ok"),
                "run",
                ThreadIdentity::with_group("thread", Some(group.to_owned()), None),
                "host",
                VariableSnapshot::new(),
            );
            report
                .add_event(&event)
                .unwrap_or_else(|_| panic!("grouped event must aggregate"));
        }
        assert_eq!(report.total().sample_count(), 3);
        assert_eq!(
            report
                .label("group-a:request")
                .map(ListenerMetrics::sample_count),
            Some(1)
        );
        assert_eq!(
            report
                .label("group-b:request")
                .map(ListenerMetrics::sample_count),
            Some(2)
        );
        assert_eq!(
            report.labels().map(|(label, _)| label).collect::<Vec<_>>(),
            ["group-a:request", "group-b:request"]
        );
    }

    #[test]
    fn listener_grouping_rejects_oversized_qualified_labels_before_allocation() {
        let limits = crate::AggregateLimits::new(4, 4, 4)
            .unwrap_or_else(|_| panic!("fixed limits must validate"))
            .with_string_limits(8, 8)
            .unwrap_or_else(|_| panic!("fixed string limits must validate"));
        let mut report = ListenerReport::new(
            config()
                .with_limits(limits)
                .with_label_grouping(LabelGrouping::ThreadGroup),
        );
        let event = SampleEvent::new(
            sample("request", 10, true, "200", "ok"),
            "run",
            ThreadIdentity::with_group("thread", Some("group".to_owned()), None),
            "host",
            VariableSnapshot::new(),
        );
        assert_eq!(
            report.add_event(&event),
            Err(ReportError::LimitExceeded {
                resource: ReportLimit::LabelBytes,
                actual: 13,
                maximum: 8,
            })
        );
        assert_eq!(report.total().sample_count(), 0);
        assert_eq!(report.label_count(), 0);
    }

    #[test]
    fn listener_partitioned_workers_merge_deterministically() {
        let partitions = vec![
            vec![
                sample("b", 300, true, "200", "ok"),
                sample("a", 100, true, "200", "ok"),
            ],
            vec![
                sample("b", 500, false, "500", "bad"),
                sample("c", 200, true, "200", "ok"),
            ],
        ];
        let worker_reports = std::thread::scope(|scope| {
            let handles = partitions.iter().map(|partition| {
                scope.spawn(move || {
                    let mut report = ListenerReport::new(config());
                    for result in partition {
                        report
                            .add_result(result)
                            .unwrap_or_else(|_| panic!("fixed worker result must aggregate"));
                    }
                    report
                })
            });
            handles
                .map(|handle| {
                    handle
                        .join()
                        .unwrap_or_else(|_| panic!("worker report must not panic"))
                })
                .collect::<Vec<_>>()
        });

        let mut merged = ListenerReport::new(config());
        for report in &worker_reports {
            merged
                .merge(report)
                .unwrap_or_else(|_| panic!("same-config worker reports must merge"));
        }
        let mut sequential = ListenerReport::new(config());
        for partition in &partitions {
            for result in partition {
                sequential
                    .add_result(result)
                    .unwrap_or_else(|_| panic!("fixed sequential result must aggregate"));
            }
        }
        assert_eq!(merged, sequential);
        assert_eq!(merged.total().sample_count(), 4);
        assert_eq!(merged.total().error_count(), 1);
    }

    #[test]
    fn listener_received_byte_overflow_is_atomic() {
        let mut report = ListenerReport::new(config());
        let mut first = sample("bytes", 1, true, "200", "ok");
        first.set_received_bytes(Some(ByteCount::new(u64::MAX)));
        report
            .add_result(&first)
            .unwrap_or_else(|_| panic!("maximum byte count must fit once"));
        let before = report.clone();

        let mut second = sample("bytes", 1, true, "200", "ok");
        second.set_received_bytes(Some(ByteCount::new(1)));
        assert_eq!(
            report.add_result(&second),
            Err(ReportError::Overflow {
                field: crate::ReportField::ReceivedBytes,
            })
        );
        assert_eq!(report, before);
    }

    #[test]
    fn listener_capacity_rejection_is_atomic_before_any_row_is_published() {
        let limits = crate::AggregateLimits::new(1, 1, 1)
            .unwrap_or_else(|_| panic!("fixed limits must validate"));
        let mut report = ListenerReport::new(config().with_limits(limits));
        report
            .add_result(&sample("one", 1, true, "200", "ok"))
            .unwrap_or_else(|_| panic!("first bounded result must fit"));
        let before = report.clone();
        assert!(matches!(
            report.add_result(&sample("one", 2, true, "200", "ok")),
            Err(ReportError::LimitExceeded {
                resource: ReportLimit::PercentileSamples,
                actual: 2,
                maximum: 1,
            })
        ));
        assert_eq!(report, before);
    }

    #[test]
    fn listener_output_is_deterministic_and_escaped() {
        let mut report = ListenerReport::new(config());
        assert!(
            report
                .add_result(&sample("a<\"b", 10, true, "200", "ok"))
                .is_ok()
        );
        let json = report.to_json().unwrap_or_else(|_| panic!("valid JSON"));
        assert!(json.contains("\"label\":\"a<\\\"b\""));
        let html = report.to_html().unwrap_or_else(|_| panic!("valid HTML"));
        assert!(html.contains("a&lt;&quot;b"));
    }

    #[test]
    fn report_fixture_weighted_elapsed_apdex_and_rates_match_contract() {
        let interval = crate::ReportInterval::from_millis(1_704_067_200_000, 1_704_067_210_000)
            .unwrap_or_else(|_| panic!("valid fixture interval"));
        let mut report = ListenerReport::new(ListenerConfig::new(interval));
        for result in report_fixture_results() {
            assert!(report.add_result(&result).is_ok());
        }
        let total = report.total();
        assert_eq!(total.sample_count(), 8);
        assert_eq!(total.success_count(), 6);
        assert_eq!(total.error_count(), 2);
        assert_eq!(total.elapsed_count(), 8);
        assert_eq!(total.elapsed_min(), Some(0));
        assert_eq!(total.elapsed_max(), Some(2500));
        assert_eq!(total.elapsed_mean(), Some(837.625));
        assert!((total.elapsed_stddev().unwrap_or_default() - 835.1703325519891).abs() < 1e-9);
        assert_eq!(total.received_bytes(), 9_100);
        assert_eq!(total.sent_bytes(), 970);
        assert_eq!(total.throughput(), 0.8);
        assert_eq!(total.error_throughput_per_second(), 0.2);
        assert_eq!(total.apdex().satisfied(), 4);
        assert_eq!(total.apdex().tolerated(), 1);
        assert_eq!(total.apdex().frustrated(), 3);
        assert_eq!(total.percentile_millis(50.0), Ok(Some(300)));
        assert_eq!(total.percentile_millis(90.0), Ok(Some(1501)));
        let search = report
            .label("api/search")
            .unwrap_or_else(|| panic!("fixture search row"));
        assert_eq!(search.sample_count(), 3);
        assert_eq!(search.elapsed_min(), Some(300));
        assert_eq!(search.elapsed_max(), Some(500));
        assert_eq!(search.elapsed_mean(), Some(366.6666666666667));
        assert_eq!(search.percentile_millis(50.0), Ok(Some(300)));
        let health = report
            .label("api/health")
            .unwrap_or_else(|| panic!("fixture health row"));
        assert_eq!(health.elapsed_count(), 1);
        assert_eq!(health.elapsed_mean(), Some(0.0));
    }

    #[test]
    fn report_fixture_serializers_include_complete_metrics() {
        let interval = crate::ReportInterval::from_millis(0, 10_000).unwrap();
        let mut report = ListenerReport::new(ListenerConfig::new(interval));
        for result in report_fixture_results() {
            assert!(report.add_result(&result).is_ok());
        }
        let json = report.to_json().unwrap_or_else(|_| panic!("valid JSON"));
        for field in [
            "\"success_count\":6",
            "\"elapsed_count\":8",
            "\"received_bytes\":9100",
            "\"error_throughput_per_second\":0.2",
            "\"response_code\":\"409\"",
            "\"graph\":[]",
        ] {
            assert!(json.contains(field), "missing {field} in {json}");
        }
        let html = report.to_html().unwrap_or_else(|_| panic!("valid HTML"));
        assert!(html.contains("Successes"));
        assert!(html.contains("Received bytes"));
    }

    #[test]
    fn listener_and_summary_html_fail_closed_on_nonfinite_variance() {
        let base = 1_000_000_000_000_u64;
        let mut listener = ListenerReport::new(config());
        let mut summary = SummaryReport::new(SummaryConfig::new(config().interval()));
        for elapsed in [base, base + 1] {
            let result = sample("unstable", elapsed, true, "200", "ok");
            assert!(listener.add_result(&result).is_ok());
            assert!(summary.add_result(&result).is_ok());
        }
        assert_eq!(listener.to_html(), Err(ReportError::Serialization));
        assert_eq!(summary.to_html(), Err(ReportError::Serialization));
    }

    #[test]
    fn report_string_limits_reject_untrusted_keys_atomically() {
        let interval = crate::ReportInterval::from_millis(0, 1_000).unwrap();
        let limits = crate::AggregateLimits::new(4, 4, 16)
            .unwrap()
            .with_string_limits(3, 5)
            .unwrap();
        let config = ListenerConfig::new(interval).with_limits(limits);
        let mut report = ListenerReport::new(config);
        assert!(matches!(
            report.add_result(&sample("long", 1, true, "200", "ok")),
            Err(ReportError::LimitExceeded {
                resource: ReportLimit::LabelBytes,
                ..
            })
        ));
        let mut failed = sample("ok", 1, false, "500", "long-message");
        assert!(matches!(
            report.add_result(&failed),
            Err(ReportError::LimitExceeded {
                resource: ReportLimit::ErrorKeyBytes,
                ..
            })
        ));
        failed.set_response_message_text("x");
        assert!(report.add_result(&failed).is_ok());
    }
}
