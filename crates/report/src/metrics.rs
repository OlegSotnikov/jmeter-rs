// SPDX-License-Identifier: Apache-2.0
//! Shared bounded counters and numerically stable summary metrics.

use std::collections::BTreeMap;

use jmeter_rs_results::{SampleResult, WallTimestamp};

use crate::config::{AggregateLimits, ApdexThresholds, ReportInterval};
use crate::error::{ReportError, ReportField, ReportLimit, SampleField};

/// A response-code/message pair used by the top-errors view.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ErrorKey {
    code: String,
    message: String,
}

impl ErrorKey {
    /// Creates an error key, retaining Unicode and empty wire values.
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    /// Builds the JMeter-style response-code/error-message key for a failed
    /// result.
    ///
    /// JMeter's `ErrorsSummaryConsumer` first builds a response-code/message
    /// key and then replaces it with the assertion marker for a 2xx/3xx
    /// response (or an empty response code with a non-blank failure message).
    /// The report surface keeps that marker in the response-code field so the
    /// two fields remain lossless while preserving the upstream key fallback.
    /// Error text is HTML4 escaped before JSON/control escaping, matching the
    /// pinned consumer's `escapeJson` helper.
    pub fn from_result(result: &SampleResult) -> Self {
        let response_code = result.response_code().unwrap_or_default();
        let response_message = result.response_message().unwrap_or_default();
        let failure_message = result
            .assertions()
            .iter()
            .find_map(|assertion| assertion.failure_message().or(assertion.error_message()))
            .or_else(|| result.failure_message())
            .unwrap_or_default();
        let assertion_key = is_jmeter_success_code(response_code)
            || (response_code.is_empty() && !failure_message.trim().is_empty());
        if assertion_key {
            let message = if failure_message.trim().is_empty() {
                String::new()
            } else {
                escape_error_component(failure_message)
            };
            return Self::new("Assertion failed", message);
        }
        // JMeter leaves the response code itself untouched; only the message
        // component passes through `escapeJson`.
        Self::new(
            response_code.to_owned(),
            escape_error_component(response_message),
        )
    }

    /// Returns the response code.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Returns the response/failure message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the single key string emitted by JMeter's ErrorsSummary
    /// consumer. The split fields remain available for the listener/dashboard
    /// table shape, while this accessor makes assertion fallback and escaping
    /// unambiguous at the serialization boundary.
    pub fn jmeter_key(&self) -> String {
        if self.code == "Assertion failed" {
            if self.message.is_empty() {
                self.code.clone()
            } else {
                self.message.clone()
            }
        } else if self.message.is_empty() {
            self.code.clone()
        } else {
            format!("{}/{}", self.code, self.message)
        }
    }
}

fn escape_error_component(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            '\\' => escaped.push_str("\\\\"),
            '\u{08}' => escaped.push_str("\\b"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\u{0c}' => escaped.push_str("\\f"),
            character if character <= '\u{1f}' => {
                use core::fmt::Write;
                let _ = write!(escaped, "\\u{:04X}", character as u32);
            }
            character => escaped.push(character),
        }
    }
    escaped
}

fn is_jmeter_success_code(value: &str) -> bool {
    // `MetricUtils.isSuccessCode(String)` first accepts Java numeric
    // characters and then parses an int. Keep the explicit checked fold so a
    // very long/unrepresentable response code is not silently treated as a
    // successful assertion key.
    let mut code = 0_i32;
    if value.is_empty() {
        return false;
    }
    for character in value.chars() {
        let Some(digit) = character.to_digit(10) else {
            return false;
        };
        let Ok(digit) = i32::try_from(digit) else {
            return false;
        };
        code = match code
            .checked_mul(10)
            .and_then(|value| value.checked_add(digit))
        {
            Some(value) => value,
            None => return false,
        };
    }
    (200..=399).contains(&code)
}

/// Metadata supplied when a result is ingested through an event/report
/// adapter.  Result rows do not encode transaction-controller identity, so it
/// is kept explicit instead of guessing from a sampler label.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct SampleMetadata {
    transaction_controller: bool,
    apdex_thresholds: Option<ApdexThresholds>,
}

impl SampleMetadata {
    /// Creates metadata for an ordinary sampler row.
    pub const fn sampler() -> Self {
        Self {
            transaction_controller: false,
            apdex_thresholds: None,
        }
    }

    /// Creates metadata for a transaction-controller row.
    pub const fn transaction_controller() -> Self {
        Self {
            transaction_controller: true,
            apdex_thresholds: None,
        }
    }

    /// Creates ordinary sampler metadata with a transaction-specific APDEX
    /// threshold pair.
    pub const fn sampler_with_apdex(thresholds: ApdexThresholds) -> Self {
        Self {
            transaction_controller: false,
            apdex_thresholds: Some(thresholds),
        }
    }

    /// Creates transaction-controller metadata with a transaction-specific
    /// APDEX threshold pair.
    pub const fn transaction_controller_with_apdex(thresholds: ApdexThresholds) -> Self {
        Self {
            transaction_controller: true,
            apdex_thresholds: Some(thresholds),
        }
    }

    /// Returns whether this row is a transaction controller.
    pub const fn is_transaction_controller(self) -> bool {
        self.transaction_controller
    }

    /// Returns an optional threshold override for this transaction.
    pub const fn apdex_thresholds(self) -> Option<ApdexThresholds> {
        self.apdex_thresholds
    }
}

/// One deterministically ordered top-error entry.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TopError {
    key: ErrorKey,
    count: u64,
}

impl TopError {
    /// Creates an entry from an error key and checked count source.
    pub(crate) const fn from_parts(key: ErrorKey, count: u64) -> Self {
        Self { key, count }
    }

    /// Returns the response-code/message key.
    pub fn key(&self) -> &ErrorKey {
        &self.key
    }

    /// Returns the number of represented failed samples.
    pub const fn count(&self) -> u64 {
        self.count
    }
}

/// APDEX category counts and score.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ApdexCounts {
    satisfied: u64,
    tolerated: u64,
    frustrated: u64,
}

impl ApdexCounts {
    /// Creates empty APDEX counts.
    pub const fn empty() -> Self {
        Self {
            satisfied: 0,
            tolerated: 0,
            frustrated: 0,
        }
    }

    /// Returns satisfied samples.
    pub const fn satisfied(self) -> u64 {
        self.satisfied
    }

    /// Returns tolerated samples.
    pub const fn tolerated(self) -> u64 {
        self.tolerated
    }

    /// Returns frustrated samples, including failed samples.
    pub const fn frustrated(self) -> u64 {
        self.frustrated
    }

    /// Returns the total APDEX denominator.
    pub fn total(self) -> u64 {
        self.satisfied
            .saturating_add(self.tolerated)
            .saturating_add(self.frustrated)
    }

    /// Returns the total APDEX denominator using checked arithmetic.
    pub fn checked_total(self) -> Result<u64, ReportError> {
        self.satisfied
            .checked_add(self.tolerated)
            .and_then(|value| value.checked_add(self.frustrated))
            .ok_or(ReportError::Overflow {
                field: ReportField::SampleCount,
            })
    }

    /// Returns the APDEX score `(satisfied + tolerated / 2) / total`.
    pub fn score(self) -> Option<f64> {
        let total = self.total();
        if total == 0 {
            None
        } else {
            Some((self.satisfied as f64 + self.tolerated as f64 / 2.0) / total as f64)
        }
    }

    pub(crate) fn add(
        &mut self,
        samples: u64,
        errors: u64,
        elapsed: Option<u64>,
        thresholds: ApdexThresholds,
    ) -> Result<(), ReportError> {
        let successful = samples
            .checked_sub(errors)
            .ok_or(ReportError::InvalidSample {
                field: SampleField::ErrorCount,
            })?;
        self.frustrated = self
            .frustrated
            .checked_add(errors)
            .ok_or(ReportError::Overflow {
                field: ReportField::ErrorCount,
            })?;

        let Some(elapsed) = elapsed else {
            self.frustrated =
                self.frustrated
                    .checked_add(successful)
                    .ok_or(ReportError::Overflow {
                        field: ReportField::SampleCount,
                    })?;
            return Ok(());
        };
        let target = if elapsed <= thresholds.satisfied_millis() {
            &mut self.satisfied
        } else if elapsed <= thresholds.tolerated_millis() {
            &mut self.tolerated
        } else {
            &mut self.frustrated
        };
        *target = target
            .checked_add(successful)
            .ok_or(ReportError::Overflow {
                field: ReportField::SampleCount,
            })?;
        Ok(())
    }

    pub(crate) fn merge(&mut self, other: Self) -> Result<(), ReportError> {
        self.satisfied =
            self.satisfied
                .checked_add(other.satisfied)
                .ok_or(ReportError::Overflow {
                    field: ReportField::SampleCount,
                })?;
        self.tolerated =
            self.tolerated
                .checked_add(other.tolerated)
                .ok_or(ReportError::Overflow {
                    field: ReportField::SampleCount,
                })?;
        self.frustrated =
            self.frustrated
                .checked_add(other.frustrated)
                .ok_or(ReportError::Overflow {
                    field: ReportField::SampleCount,
                })?;
        Ok(())
    }
}

impl Default for ApdexCounts {
    fn default() -> Self {
        Self::empty()
    }
}

/// Public count, timing, byte, APDEX, and error metrics shared by report
/// surfaces. Percentile algorithms remain on their respective report types.
#[derive(Clone, Debug, PartialEq)]
pub struct SummaryMetrics {
    sample_count: u64,
    error_count: u64,
    elapsed: RunningStats,
    received_bytes: u64,
    sent_bytes: u64,
    apdex: ApdexCounts,
    errors: BTreeMap<ErrorKey, u64>,
    top_errors: BTreeMap<ErrorKey, u64>,
    observed_start: Option<WallTimestamp>,
    observed_end: Option<WallTimestamp>,
}

impl SummaryMetrics {
    /// Creates an empty summary.
    pub fn new() -> Self {
        Self::empty()
    }

    /// Returns whether this summary has no represented samples.
    pub const fn is_empty(&self) -> bool {
        self.sample_count == 0
    }

    /// Returns represented sample count.
    pub const fn sample_count(&self) -> u64 {
        self.sample_count
    }

    /// Returns represented failed-sample count.
    pub const fn error_count(&self) -> u64 {
        self.error_count
    }

    /// Returns represented successful-sample count.
    pub const fn success_count(&self) -> u64 {
        // `add_result` and `merge` both preserve error_count <= sample_count.
        // Saturating subtraction keeps this read-only accessor total even if a
        // future internal representation is extended.
        self.sample_count.saturating_sub(self.error_count)
    }

    /// Returns the percentage of represented samples that failed.
    pub fn error_percentage(&self) -> f64 {
        if self.sample_count == 0 {
            0.0
        } else {
            self.error_count as f64 * 100.0 / self.sample_count as f64
        }
    }

    /// Returns the percentage of represented samples that succeeded.
    pub fn success_percentage(&self) -> f64 {
        if self.sample_count == 0 {
            0.0
        } else {
            self.success_count() as f64 * 100.0 / self.sample_count as f64
        }
    }

    /// Returns the number of represented samples with elapsed values.
    pub const fn elapsed_count(&self) -> u64 {
        self.elapsed.count
    }

    /// Returns the smallest observed elapsed value.
    pub const fn elapsed_min(&self) -> Option<u64> {
        self.elapsed.min
    }

    /// Returns the largest observed elapsed value.
    pub const fn elapsed_max(&self) -> Option<u64> {
        self.elapsed.max
    }

    /// Returns the running elapsed mean retained by the Calculator
    /// accumulator.
    pub const fn elapsed_mean(&self) -> Option<f64> {
        self.elapsed.mean()
    }

    /// Returns population standard deviation from the Calculator accumulator.
    pub fn elapsed_stddev(&self) -> Option<f64> {
        self.elapsed.stddev()
    }

    /// Returns population variance using JMeter Calculator's arithmetic.
    /// Keeping this as a derived read avoids exposing the mutable accumulator
    /// while preserving the exact report field.
    pub fn elapsed_variance(&self) -> Option<f64> {
        self.elapsed.variance()
    }

    /// Returns total received bytes, treating an absent wire field as zero.
    pub const fn received_bytes(&self) -> u64 {
        self.received_bytes
    }

    /// Returns total sent bytes, treating an absent wire field as zero.
    pub const fn sent_bytes(&self) -> u64 {
        self.sent_bytes
    }

    /// Returns the average received-byte size per represented sample.
    pub fn average_received_bytes(&self) -> Option<f64> {
        if self.sample_count == 0 {
            None
        } else {
            Some(self.received_bytes as f64 / self.sample_count as f64)
        }
    }

    /// Returns the average sent-byte size per represented sample.
    pub fn average_sent_bytes(&self) -> Option<f64> {
        if self.sample_count == 0 {
            None
        } else {
            Some(self.sent_bytes as f64 / self.sample_count as f64)
        }
    }

    /// Returns represented samples per second over the observed report span.
    /// When no valid start/end pair was retained, the caller's explicit
    /// interval is used as a deterministic fallback.
    pub fn throughput_per_second(&self, interval: ReportInterval) -> f64 {
        self.sample_count as f64 / self.effective_interval(interval).duration_seconds()
    }

    /// Alias for [`SummaryMetrics::throughput_per_second`].
    pub fn throughput(&self, interval: ReportInterval) -> f64 {
        self.throughput_per_second(interval)
    }

    /// Returns represented failed samples per second over an explicit report
    /// interval.
    pub fn error_throughput_per_second(&self, interval: ReportInterval) -> f64 {
        self.error_count as f64 / self.effective_interval(interval).duration_seconds()
    }

    /// Returns received bytes per second over an explicit report interval.
    pub fn received_bytes_per_second(&self, interval: ReportInterval) -> f64 {
        self.received_bytes as f64 / self.effective_interval(interval).duration_seconds()
    }

    /// Returns sent bytes per second over an explicit report interval.
    pub fn sent_bytes_per_second(&self, interval: ReportInterval) -> f64 {
        self.sent_bytes as f64 / self.effective_interval(interval).duration_seconds()
    }

    /// Returns APDEX category counts.
    pub const fn apdex(&self) -> ApdexCounts {
        self.apdex
    }

    /// Returns all error keys in deterministic key order, with counts.
    pub fn error_counts(&self) -> Vec<TopError> {
        self.errors
            .iter()
            .map(|(key, count)| TopError::from_parts(key.clone(), *count))
            .collect()
    }

    /// Returns the highest-count errors, breaking ties by code then message.
    pub fn top_errors(&self, limit: usize) -> Vec<TopError> {
        let mut values: Vec<TopError> = self
            .top_errors
            .iter()
            .map(|(key, count)| TopError::from_parts(key.clone(), *count))
            .collect();
        values.sort_by(|left, right| {
            right
                .count
                .cmp(&left.count)
                .then_with(|| left.key.cmp(&right.key))
        });
        values.truncate(limit);
        values
    }

    pub(crate) fn empty() -> Self {
        Self {
            sample_count: 0,
            error_count: 0,
            elapsed: RunningStats::default(),
            received_bytes: 0,
            sent_bytes: 0,
            apdex: ApdexCounts::empty(),
            errors: BTreeMap::new(),
            top_errors: BTreeMap::new(),
            observed_start: None,
            observed_end: None,
        }
    }

    /// Returns the earliest retained sample start timestamp, if any.
    pub const fn observed_start(&self) -> Option<WallTimestamp> {
        self.observed_start
    }

    /// Returns the latest retained sample end timestamp, if any.
    pub const fn observed_end(&self) -> Option<WallTimestamp> {
        self.observed_end
    }

    fn effective_interval(&self, fallback: ReportInterval) -> ReportInterval {
        match (self.observed_start, self.observed_end) {
            (Some(start), Some(end)) => ReportInterval::new(start, end).unwrap_or(fallback),
            _ => fallback,
        }
    }

    pub(crate) fn add_result(
        &mut self,
        result: &SampleResult,
        thresholds: ApdexThresholds,
        limits: AggregateLimits,
    ) -> Result<PreparedObservation, ReportError> {
        self.add_result_with_mode(result, thresholds, limits, CountMode::Weighted, true)
    }

    pub(crate) fn add_result_unweighted(
        &mut self,
        result: &SampleResult,
        thresholds: ApdexThresholds,
        limits: AggregateLimits,
        include_top_errors: bool,
    ) -> Result<PreparedObservation, ReportError> {
        self.add_result_with_mode(
            result,
            thresholds,
            limits,
            CountMode::Unweighted,
            include_top_errors,
        )
    }

    /// Adds only the APDEX contribution for one unweighted dashboard row.
    ///
    /// Report-generator consumers intentionally have different controller
    /// policies: statistics/request-summary/error/top-five consumers omit an
    /// overall transaction-controller row, while `ApdexSummaryConsumer`
    /// retains it. This method lets the dashboard apply that split without
    /// leaking controller rows into the other counters or FIFO percentiles.
    pub(crate) fn add_apdex_only(
        &mut self,
        result: &SampleResult,
        thresholds: ApdexThresholds,
        mode: CountMode,
    ) -> Result<(), ReportError> {
        let counts = represented_counts(result, mode)?;
        let elapsed_total = result.elapsed().map(|value| value.as_millis());
        let elapsed = (counts.samples > 0).then(|| {
            elapsed_total
                .unwrap_or(0)
                .checked_div(counts.samples)
                .unwrap_or(0)
        });
        self.apdex
            .add(counts.samples, counts.apdex_errors, elapsed, thresholds)
    }

    fn add_result_with_mode(
        &mut self,
        result: &SampleResult,
        thresholds: ApdexThresholds,
        limits: AggregateLimits,
        mode: CountMode,
        include_top_errors: bool,
    ) -> Result<PreparedObservation, ReportError> {
        // Validate and build the complete next state before replacing `self`.
        // A caller can then safely retry after a resource-limit or arithmetic
        // error without observing a partially counted sample.
        let mut updated = self.clone();
        let observation =
            updated.add_result_mut(result, thresholds, limits, mode, include_top_errors)?;
        *self = updated;
        Ok(observation)
    }

    fn add_result_mut(
        &mut self,
        result: &SampleResult,
        thresholds: ApdexThresholds,
        limits: AggregateLimits,
        mode: CountMode,
        include_top_errors: bool,
    ) -> Result<PreparedObservation, ReportError> {
        let counts = represented_counts(result, mode)?;
        // JMeter's report readers expose an absent elapsed attribute as zero.
        // StatisticalSampleResult rows carry the total elapsed time for all
        // represented samples; percentile/APDEX observations therefore use
        // the integer per-sample value while running means retain the wire
        // total exactly (matching Calculator.addValue).
        let elapsed_total = result.elapsed().map(|value| value.as_millis());
        let elapsed = (counts.samples > 0).then(|| {
            elapsed_total
                .unwrap_or(0)
                .checked_div(counts.samples)
                .unwrap_or(0)
        });

        self.observe_timestamps(result);

        self.sample_count =
            self.sample_count
                .checked_add(counts.samples)
                .ok_or(ReportError::Overflow {
                    field: ReportField::SampleCount,
                })?;
        self.error_count =
            self.error_count
                .checked_add(counts.errors)
                .ok_or(ReportError::Overflow {
                    field: ReportField::ErrorCount,
                })?;
        if counts.samples > 0 {
            self.elapsed
                .update(elapsed_total.unwrap_or(0), counts.samples)?;
        }
        self.received_bytes = self
            .received_bytes
            .checked_add(result.received_bytes().map_or(0, |value| value.as_u64()))
            .ok_or(ReportError::Overflow {
                field: ReportField::ReceivedBytes,
            })?;
        self.sent_bytes = self
            .sent_bytes
            .checked_add(result.sent_bytes().map_or(0, |value| value.as_u64()))
            .ok_or(ReportError::Overflow {
                field: ReportField::SentBytes,
            })?;
        self.apdex
            .add(counts.samples, counts.apdex_errors, elapsed, thresholds)?;

        if counts.errors > 0 {
            let key = ErrorKey::from_result(result);
            let key_bytes = key.code().len().saturating_add(key.message().len());
            if key_bytes > limits.max_error_key_bytes() {
                return Err(ReportError::LimitExceeded {
                    resource: ReportLimit::ErrorKeyBytes,
                    actual: key_bytes,
                    maximum: limits.max_error_key_bytes(),
                });
            }
            let count = self.errors.get(&key).copied().unwrap_or(0);
            if !self.errors.contains_key(&key) && self.errors.len() >= limits.max_error_keys() {
                return Err(ReportError::LimitExceeded {
                    resource: ReportLimit::ErrorKeys,
                    actual: self.errors.len().saturating_add(1),
                    maximum: limits.max_error_keys(),
                });
            }
            let updated = count
                .checked_add(counts.errors)
                .ok_or(ReportError::Overflow {
                    field: ReportField::ErrorCount,
                })?;
            self.errors.insert(key, updated);
            if include_top_errors {
                let key = ErrorKey::from_result(result);
                let count = self.top_errors.get(&key).copied().unwrap_or(0);
                let updated = count
                    .checked_add(counts.errors)
                    .ok_or(ReportError::Overflow {
                        field: ReportField::ErrorCount,
                    })?;
                self.top_errors.insert(key, updated);
            }
        }

        Ok(PreparedObservation {
            elapsed,
            sample_count: counts.samples,
        })
    }

    pub(crate) fn merge(
        &mut self,
        other: &Self,
        limits: AggregateLimits,
    ) -> Result<(), ReportError> {
        let mut updated = self.clone();
        updated.merge_mut(other, limits)?;
        *self = updated;
        Ok(())
    }

    fn merge_mut(&mut self, other: &Self, limits: AggregateLimits) -> Result<(), ReportError> {
        self.sample_count =
            self.sample_count
                .checked_add(other.sample_count)
                .ok_or(ReportError::Overflow {
                    field: ReportField::SampleCount,
                })?;
        self.error_count =
            self.error_count
                .checked_add(other.error_count)
                .ok_or(ReportError::Overflow {
                    field: ReportField::ErrorCount,
                })?;
        self.elapsed.merge(&other.elapsed)?;
        self.received_bytes = self
            .received_bytes
            .checked_add(other.received_bytes)
            .ok_or(ReportError::Overflow {
                field: ReportField::ReceivedBytes,
            })?;
        self.sent_bytes =
            self.sent_bytes
                .checked_add(other.sent_bytes)
                .ok_or(ReportError::Overflow {
                    field: ReportField::SentBytes,
                })?;
        self.apdex.merge(other.apdex)?;
        self.observed_start = match (self.observed_start, other.observed_start) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (None, value) | (value, None) => value,
        };
        self.observed_end = match (self.observed_end, other.observed_end) {
            (Some(left), Some(right)) => Some(left.max(right)),
            (None, value) | (value, None) => value,
        };
        for (key, count) in &other.errors {
            let current = self.errors.get(key).copied().unwrap_or(0);
            if !self.errors.contains_key(key) && self.errors.len() >= limits.max_error_keys() {
                return Err(ReportError::LimitExceeded {
                    resource: ReportLimit::ErrorKeys,
                    actual: self.errors.len().saturating_add(1),
                    maximum: limits.max_error_keys(),
                });
            }
            let updated = current.checked_add(*count).ok_or(ReportError::Overflow {
                field: ReportField::ErrorCount,
            })?;
            self.errors.insert(key.clone(), updated);
        }
        for (key, count) in &other.top_errors {
            let current = self.top_errors.get(key).copied().unwrap_or(0);
            let updated = current.checked_add(*count).ok_or(ReportError::Overflow {
                field: ReportField::ErrorCount,
            })?;
            self.top_errors.insert(key.clone(), updated);
        }
        Ok(())
    }

    fn observe_timestamps(&mut self, result: &SampleResult) {
        if let Some(start) = result.start_time() {
            self.observed_start = Some(
                self.observed_start
                    .map_or(start, |current| current.min(start)),
            );
        }
        if let Some(end) = result.end_time() {
            self.observed_end = Some(self.observed_end.map_or(end, |current| current.max(end)));
        }
    }
}

impl Default for SummaryMetrics {
    fn default() -> Self {
        Self::empty()
    }
}

/// One event's checked represented counts and elapsed value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreparedObservation {
    /// Effective integer per-sample elapsed duration. Report readers map an
    /// absent elapsed field to zero before this value is prepared.
    pub(crate) elapsed: Option<u64>,
    /// Number of represented samples, used as a weight.
    pub(crate) sample_count: u64,
}

/// Checks a caller-supplied label before it is copied into a report map.
pub(crate) fn validate_label(label: &str, limits: AggregateLimits) -> Result<(), ReportError> {
    let actual = label.len();
    if actual > limits.max_label_bytes() {
        return Err(ReportError::LimitExceeded {
            resource: ReportLimit::LabelBytes,
            actual,
            maximum: limits.max_label_bytes(),
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RepresentedCounts {
    pub(crate) samples: u64,
    pub(crate) errors: u64,
    pub(crate) apdex_errors: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CountMode {
    Weighted,
    Unweighted,
}

pub(crate) fn represented_counts(
    result: &SampleResult,
    mode: CountMode,
) -> Result<RepresentedCounts, ReportError> {
    // JMeter's ordinary SampleResult starts with one represented sample and
    // StatisticalSampleResult only becomes observable after its first add.
    // A serialized `sc=0` row therefore cannot contribute coherent count,
    // error, APDEX, or byte-rate metrics.  Reject it instead of counting its
    // bytes while silently leaving the denominator at zero.
    if result
        .sample_count()
        .is_some_and(|value| value.as_u64() == 0)
    {
        return Err(ReportError::InvalidSample {
            field: SampleField::SampleCount,
        });
    }
    let samples = match mode {
        CountMode::Weighted => result.sample_count().map_or(1, |value| value.as_u64()),
        CountMode::Unweighted => 1,
    };
    let assertion_failed = result
        .assertions()
        .iter()
        .any(|assertion| assertion.is_failure() || assertion.is_error());
    let explicit_failed = result.success() == Some(false) || assertion_failed;
    let errors = match mode {
        // A failed JMeter result is always frustrated.  An explicit batch
        // error count is retained when present, while an absent/zero count on
        // a failed batch means every represented sample failed.
        CountMode::Weighted if explicit_failed => result
            .error_count()
            .filter(|value| value.as_u64() > 0)
            .map_or(samples, |value| value.as_u64()),
        CountMode::Weighted => match result.error_count() {
            Some(value) if result.success().is_none() => value.as_u64(),
            _ => 0,
        },
        CountMode::Unweighted if explicit_failed => 1,
        CountMode::Unweighted => match result.error_count() {
            Some(value) if result.success().is_none() && value.as_u64() > 0 => 1,
            _ => 0,
        },
    };
    if errors > samples {
        return Err(ReportError::InvalidSample {
            field: SampleField::ErrorCount,
        });
    }
    let apdex_errors = errors;
    Ok(RepresentedCounts {
        samples,
        errors,
        apdex_errors,
    })
}

/// Running statistics with JMeter's aggregate-sample semantics.
///
/// JMeter's `Calculator` adds the wire elapsed total to the sum, divides it
/// by `SampleCount` for min/max, and adds `total² / SampleCount` to the sum of
/// squares. Keeping both sums lets a statistical sample retain its fractional
/// mean while exposing the same integer effective observations to percentiles.
///
/// The variance expression is deliberately kept in the same operation order
/// as JMeter 5.6.3 (`sum_of_squares / count - mean²`).  Rewriting that as
/// `(sum_of_squares - sum² / count) / count` is algebraically equivalent but
/// not bit-equivalent for large or nearly equal values, and can turn a
/// source-compatible standard deviation into a different report value.
#[derive(Clone, Copy, Debug, PartialEq)]
struct RunningStats {
    count: u64,
    sum: f64,
    sum_of_squares: f64,
    mean: f64,
    variance: f64,
    min: Option<u64>,
    max: Option<u64>,
}

impl RunningStats {
    fn update(&mut self, value: u64, weight: u64) -> Result<(), ReportError> {
        if weight == 0 {
            return Ok(());
        }
        let new_count = self
            .count
            .checked_add(weight)
            .ok_or(ReportError::Overflow {
                field: ReportField::ElapsedCount,
            })?;
        let total = value as f64;
        let weight_f = weight as f64;
        let sum = self.sum + total;
        let sum_of_squares = self.sum_of_squares + total * total / weight_f;
        let mean = sum / new_count as f64;
        // This is the arithmetic used by Apache JMeter 5.6.3's Calculator:
        // sumOfSquares / count - mean * mean.  It is intentionally not
        // replaced by a centered/Welford accumulator; its floating-point
        // behavior is part of the report compatibility surface.
        let variance = sum_of_squares / new_count as f64 - mean * mean;
        let effective = value / weight;
        if !sum.is_finite()
            || !sum_of_squares.is_finite()
            || !mean.is_finite()
            || !variance.is_finite()
        {
            return Err(ReportError::Overflow {
                field: ReportField::Variance,
            });
        }
        self.sum = sum;
        self.sum_of_squares = sum_of_squares;
        self.mean = mean;
        self.variance = variance;
        if !self.mean.is_finite() || !self.variance.is_finite() {
            return Err(ReportError::Overflow {
                field: ReportField::Variance,
            });
        }
        self.count = new_count;
        self.min = Some(self.min.map_or(effective, |current| current.min(effective)));
        self.max = Some(self.max.map_or(effective, |current| current.max(effective)));
        Ok(())
    }

    fn merge(&mut self, other: &Self) -> Result<(), ReportError> {
        if other.count == 0 {
            return Ok(());
        }
        if self.count == 0 {
            *self = *other;
            return Ok(());
        }
        let total = self
            .count
            .checked_add(other.count)
            .ok_or(ReportError::Overflow {
                field: ReportField::ElapsedCount,
            })?;
        let sum = self.sum + other.sum;
        let sum_of_squares = self.sum_of_squares + other.sum_of_squares;
        let mean = sum / total as f64;
        let variance = sum_of_squares / total as f64 - mean * mean;
        if !sum.is_finite()
            || !sum_of_squares.is_finite()
            || !mean.is_finite()
            || !variance.is_finite()
        {
            return Err(ReportError::Overflow {
                field: ReportField::Variance,
            });
        }
        self.sum = sum;
        self.sum_of_squares = sum_of_squares;
        self.mean = mean;
        self.variance = variance;
        self.count = total;
        self.min = Some(match (self.min, other.min) {
            (Some(left), Some(right)) => left.min(right),
            (Some(value), None) | (None, Some(value)) => value,
            (None, None) => {
                return Err(ReportError::Overflow {
                    field: ReportField::ElapsedCount,
                });
            }
        });
        self.max = Some(match (self.max, other.max) {
            (Some(left), Some(right)) => left.max(right),
            (Some(value), None) | (None, Some(value)) => value,
            (None, None) => {
                return Err(ReportError::Overflow {
                    field: ReportField::ElapsedCount,
                });
            }
        });
        Ok(())
    }

    const fn mean(&self) -> Option<f64> {
        if self.count == 0 {
            None
        } else {
            Some(self.mean)
        }
    }

    fn variance(&self) -> Option<f64> {
        if self.count == 0 {
            None
        } else {
            Some(self.variance)
        }
    }

    fn stddev(&self) -> Option<f64> {
        if self.count == 0 {
            None
        } else {
            Some(self.variance.sqrt())
        }
    }
}

impl Default for RunningStats {
    fn default() -> Self {
        Self {
            count: 0,
            sum: 0.0,
            sum_of_squares: 0.0,
            mean: 0.0,
            variance: 0.0,
            min: None,
            max: None,
        }
    }
}

/// Validates a caller-supplied percentile percentage.
pub(crate) fn validate_percentile(percentile: f64) -> Result<(), ReportError> {
    if percentile.is_finite() && (0.0..=100.0).contains(&percentile) {
        Ok(())
    } else {
        Err(ReportError::InvalidPercentile)
    }
}

/// Adds an exact weighted observation to a bounded vector.
pub(crate) fn append_exact_observation(
    values: &mut Vec<u64>,
    observation: PreparedObservation,
    maximum: usize,
) -> Result<(), ReportError> {
    let Some(elapsed) = observation.elapsed else {
        return Ok(());
    };
    let amount = usize::try_from(observation.sample_count).map_err(|_| ReportError::Overflow {
        field: ReportField::PercentileSamples,
    })?;
    let new_len = values
        .len()
        .checked_add(amount)
        .ok_or(ReportError::Overflow {
            field: ReportField::PercentileSamples,
        })?;
    if new_len > maximum {
        return Err(ReportError::LimitExceeded {
            resource: ReportLimit::PercentileSamples,
            actual: new_len,
            maximum,
        });
    }
    values.resize(new_len, elapsed);
    Ok(())
}

/// Appends a weighted observation to a bounded FIFO window.
pub(crate) fn append_window_observation(
    values: &mut std::collections::VecDeque<u64>,
    observation: PreparedObservation,
    maximum: usize,
) -> Result<(), ReportError> {
    let Some(elapsed) = observation.elapsed else {
        return Ok(());
    };
    // A window intentionally retains only the newest observations. Avoid a
    // potentially enormous loop when a StatisticalSampleResult represents a
    // large batch by retaining at most `maximum` copies. Dashboard rows are
    // unweighted, so the conversion is guaranteed by represented_counts.
    let amount = usize::try_from(observation.sample_count).map_err(|_| ReportError::Overflow {
        field: ReportField::PercentileSamples,
    })?;
    let amount = amount.min(maximum);
    for _ in 0..amount {
        if values.len() == maximum {
            values.pop_front();
        }
        values.push_back(elapsed);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use jmeter_rs_results::{ElapsedTime, SampleCount};

    fn thresholds() -> ApdexThresholds {
        ApdexThresholds::new(500, 1_500).unwrap_or_else(|_| panic!("fixed thresholds"))
    }

    #[test]
    fn running_stats_match_jmeter_operation_order_for_weighted_rows() {
        let mut stats = RunningStats::default();
        stats.update(100, 1).unwrap_or_else(|_| panic!("first row"));
        stats
            .update(1_000_000_000_001, 2)
            .unwrap_or_else(|_| panic!("weighted row"));

        let sum = 100.0 + 1_000_000_000_001.0;
        let sum_of_squares = 100.0 * 100.0 + (1_000_000_000_001.0 * 1_000_000_000_001.0) / 2.0;
        let mean = sum / 3.0;
        // This order is the one used by org.apache.jmeter.util.Calculator.
        let variance = sum_of_squares / 3.0 - mean * mean;

        assert_eq!(stats.count, 3);
        assert_eq!(stats.sum, sum);
        assert_eq!(stats.sum_of_squares, sum_of_squares);
        assert_eq!(stats.mean, mean);
        assert_eq!(stats.variance, variance);
        assert_eq!(stats.min, Some(100));
        assert_eq!(stats.max, Some(500_000_000_000));
        assert_eq!(stats.stddev(), Some(variance.sqrt()));
    }

    #[test]
    fn represented_counts_reject_an_explicit_zero_sample_row() {
        let mut result = SampleResult::new("zero");
        result.set_sample_count(Some(SampleCount::from_u64(0)));
        assert!(
            result
                .set_elapsed(Some(ElapsedTime::from_millis(10)))
                .is_ok()
        );

        for mode in [CountMode::Weighted, CountMode::Unweighted] {
            assert_eq!(
                represented_counts(&result, mode),
                Err(ReportError::InvalidSample {
                    field: SampleField::SampleCount,
                })
            );
        }
    }

    #[test]
    fn apdex_uses_inclusive_thresholds_and_failed_rows_are_frustrated() {
        let mut counts = ApdexCounts::empty();
        counts
            .add(1, 0, Some(500), thresholds())
            .unwrap_or_else(|_| panic!("satisfied boundary"));
        counts
            .add(1, 0, Some(1_500), thresholds())
            .unwrap_or_else(|_| panic!("tolerated boundary"));
        counts
            .add(1, 1, Some(1), thresholds())
            .unwrap_or_else(|_| panic!("failed row"));

        assert_eq!(counts.satisfied(), 1);
        assert_eq!(counts.tolerated(), 1);
        assert_eq!(counts.frustrated(), 1);
        assert_eq!(counts.total(), 3);
        assert_eq!(counts.score(), Some(0.5));
    }

    #[test]
    fn exact_observation_append_is_bounded_and_atomic() {
        let mut values = vec![7, 8];
        let before = values.clone();
        let result = append_exact_observation(
            &mut values,
            PreparedObservation {
                elapsed: Some(9),
                sample_count: 2,
            },
            3,
        );
        assert_eq!(
            result,
            Err(ReportError::LimitExceeded {
                resource: ReportLimit::PercentileSamples,
                actual: 4,
                maximum: 3,
            })
        );
        assert_eq!(values, before);
    }

    #[test]
    fn running_stats_count_overflow_is_checked_before_mutation() {
        let mut stats = RunningStats {
            count: u64::MAX,
            sum: 4.0,
            sum_of_squares: 16.0,
            mean: 4.0,
            variance: 0.0,
            min: Some(4),
            max: Some(4),
        };
        let before = stats;
        assert_eq!(
            stats.update(4, 1),
            Err(ReportError::Overflow {
                field: ReportField::ElapsedCount,
            })
        );
        assert_eq!(stats, before);
    }

    #[test]
    fn summary_sample_count_overflow_is_checked_before_mutation() {
        let mut summary = SummaryMetrics::empty();
        summary.sample_count = u64::MAX;
        let before = summary.clone();
        let mut result = SampleResult::new("overflow");
        result.set_successful(true);

        assert_eq!(
            summary.add_result(&result, thresholds(), AggregateLimits::default()),
            Err(ReportError::Overflow {
                field: ReportField::SampleCount,
            })
        );
        assert_eq!(summary, before);
    }

    #[test]
    fn apdex_count_overflow_is_checked_before_mutation() {
        let mut counts = ApdexCounts {
            satisfied: u64::MAX,
            tolerated: 0,
            frustrated: 0,
        };
        let before = counts;
        assert_eq!(
            counts.add(1, 0, Some(0), thresholds()),
            Err(ReportError::Overflow {
                field: ReportField::SampleCount,
            })
        );
        assert_eq!(counts, before);
    }
}
