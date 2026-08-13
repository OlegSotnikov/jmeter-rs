// SPDX-License-Identifier: Apache-2.0
//! Pure admission of the effective local JMeter report-generator properties.
//!
//! This module is deliberately separate from the report writer and the
//! filesystem-facing runner.  It consumes an already-resolved
//! [`PropertyMap`], rejects every report property that the currently wired
//! dashboard path cannot apply, and only then constructs the pure report
//! configuration.  There is no path, filesystem, environment, clock, or I/O
//! access here.

use std::collections::BTreeMap;
use std::fmt;

use jmeter_rs_report::{
    ConfigField, DashboardConfig, MAX_REPORT_PROPERTY_BYTES, MIN_REPORT_OVERALL_GRANULARITY_MILLIS,
    REPORTGENERATOR_APDEX_SATISFIED_THRESHOLD,
    REPORTGENERATOR_EXCLUDE_TC_FROM_TOP5_ERRORS_BY_SAMPLER, REPORTGENERATOR_OVERALL_GRANULARITY,
    REPORTGENERATOR_RESPONSE_TIME_DISTRIBUTION_GRANULARITY, REPORTGENERATOR_STATISTIC_WINDOW,
    ReportError, ReportGeneratorProperties, ReportInterval, ReportProperty,
};

use crate::config::{PropertyMap, PropertyProvenance, ResolvedConfig, ResolvedProperty};

/// The maximum diagnostic key bytes retained by this adapter.
///
/// Effective configuration already has a smaller key bound, but keeping an
/// explicit local bound makes this module safe when a caller constructs a
/// [`PropertyMap`] through a future adapter with a different limit.
const MAX_REPORT_POLICY_DIAGNOSTIC_KEY_BYTES: usize = 512;

/// A report-generator property that is known by the report crate but is not
/// applied by the current dashboard construction path.
const UNSUPPORTED_KNOWN_PROPERTIES: [ReportProperty; 5] = [
    ReportProperty::DashboardSampleFilter,
    ReportProperty::DashboardReportTitle,
    ReportProperty::DashboardDateFormat,
    ReportProperty::DashboardStartDate,
    ReportProperty::DashboardEndDate,
];

/// A property whose downstream behavior is implemented by the current
/// dashboard core.
const SUPPORTED_PROPERTIES: [ReportProperty; 9] = [
    ReportProperty::AggregatePercentile1,
    ReportProperty::AggregatePercentile2,
    ReportProperty::AggregatePercentile3,
    ReportProperty::DashboardApdexSatisfiedThreshold,
    ReportProperty::DashboardApdexToleratedThreshold,
    ReportProperty::DashboardOverallGranularity,
    ReportProperty::DashboardStatisticWindow,
    ReportProperty::DashboardExcludeTransactionControllersFromTop5,
    ReportProperty::ResponseTimeDistributionGranularity,
];

/// The reason an explicit report-generator key cannot be admitted.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum UnsupportedReportProperty {
    /// A known JMeter property is exposed by the report crate but is not
    /// consumed by `DashboardConfig::from_report_generator_properties` or by
    /// the current dashboard/HTML path.
    KnownButNotApplied(ReportProperty),
    /// The key is in the report-generator namespace but is not part of the
    /// pinned, implemented property inventory.
    UnknownReportGeneratorProperty,
}

impl UnsupportedReportProperty {
    /// Returns a stable reason label for diagnostics and tests.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KnownButNotApplied(_) => "known-but-not-applied",
            Self::UnknownReportGeneratorProperty => "unknown-reportgenerator-property",
        }
    }
}

impl fmt::Display for UnsupportedReportProperty {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The part of a report property whose byte bound was exceeded.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReportPropertyBound {
    /// The exact property key was too large.
    Key,
    /// The property value was too large.  The value is never retained in the
    /// error or rendered in its diagnostic.
    Value,
}

impl ReportPropertyBound {
    /// Returns a stable bound label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Key => "key",
            Self::Value => "value",
        }
    }
}

impl fmt::Display for ReportPropertyBound {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Stable, pure report-policy admission failures.
///
/// No variant stores a property value.  The exact public key is retained so
/// an operator can identify the rejected setting while secret-like or merely
/// large values remain absent from `Debug` and `Display` diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReportPolicyError {
    /// A known or report-generator-namespace property cannot be applied by
    /// the current dashboard path.
    UnsupportedProperty {
        /// Exact effective public key.
        key: String,
        /// Typed reason for rejection.
        reason: UnsupportedReportProperty,
    },
    /// A supported property could not be parsed or violated a report-core
    /// configuration bound.
    InvalidProperty {
        /// Exact effective public key.
        key: String,
        /// Underlying pure report configuration failure.
        error: ReportError,
    },
    /// A report property key or value exceeded the report-core byte bound.
    PropertyBound {
        /// Exact effective public key (possibly the bounded diagnostic form
        /// when the key itself is oversized).
        key: String,
        /// Whether the key or value exceeded the bound.
        bound: ReportPropertyBound,
        /// Observed UTF-8 byte length.
        observed: usize,
        /// Maximum accepted UTF-8 byte length.
        maximum: usize,
    },
    /// An unexpected pure report construction failure.  This remains typed so
    /// callers cannot mistake it for a successfully admitted policy.
    Construction(ReportError),
}

impl ReportPolicyError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedProperty { .. } => "report.policy.unsupported-property",
            Self::InvalidProperty { .. } => "report.policy.invalid-property",
            Self::PropertyBound { .. } => "report.policy.property-bound",
            Self::Construction(error) => error.stable_code(),
        }
    }

    /// Returns the exact public property key involved in this failure, when
    /// one exists.
    #[must_use]
    pub fn key(&self) -> Option<&str> {
        match self {
            Self::UnsupportedProperty { key, .. }
            | Self::InvalidProperty { key, .. }
            | Self::PropertyBound { key, .. } => Some(key),
            Self::Construction(_) => None,
        }
    }

    /// Returns whether this failure can be retried without changing input.
    #[must_use]
    pub const fn retryable(&self) -> bool {
        false
    }

    /// Returns a bounded diagnostic.  Property values and configuration
    /// provenance are intentionally not included.
    #[must_use]
    pub fn redacted_message(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for ReportPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedProperty { key, reason } => {
                write!(
                    formatter,
                    "{}: {}: {reason}",
                    self.code(),
                    diagnostic_key(key)
                )
            }
            Self::InvalidProperty { key, error } => {
                write!(
                    formatter,
                    "{}: {}: {}",
                    self.code(),
                    diagnostic_key(key),
                    error.stable_code()
                )
            }
            Self::PropertyBound {
                key,
                bound,
                observed,
                maximum,
            } => write!(
                formatter,
                "{}: {}: {bound} is {observed} bytes; maximum is {maximum}",
                self.code(),
                diagnostic_key(key)
            ),
            Self::Construction(error) => {
                write!(formatter, "{}: {}", self.code(), error.stable_code())
            }
        }
    }
}

impl std::error::Error for ReportPolicyError {}

/// An atomically admitted dashboard policy.
///
/// The policy retains the exact effective report-generator projection, the
/// dashboard configuration built from one explicit interval, and winning
/// provenance for every admitted property.  Unsupported or invalid input is
/// rejected before this value can be constructed.
#[derive(Clone, Debug, PartialEq)]
pub struct AdmittedReportPolicy {
    report_generator: ReportGeneratorProperties,
    dashboard: DashboardConfig,
    provenance: BTreeMap<String, PropertyProvenance>,
}

impl AdmittedReportPolicy {
    /// Returns the report-generator projection after admission.
    #[must_use]
    pub const fn report_generator(&self) -> &ReportGeneratorProperties {
        &self.report_generator
    }

    /// Returns the dashboard configuration built for the explicit interval.
    #[must_use]
    pub const fn dashboard(&self) -> DashboardConfig {
        self.dashboard
    }
    /// Returns the winning provenance for an admitted exact public key.
    #[must_use]
    pub fn provenance(&self, key: &str) -> Option<&PropertyProvenance> {
        self.provenance.get(key)
    }

    /// Returns all admitted key/provenance pairs in deterministic key order.
    #[must_use]
    pub fn provenances(&self) -> &BTreeMap<String, PropertyProvenance> {
        &self.provenance
    }
}

/// Admits report configuration from the effective local JMeter namespace.
///
/// System and global properties are intentionally ignored: this function
/// consumes only `ResolvedConfig::jmeter_properties()`, matching the local
/// report-generator property space and avoiding an ambient namespace merge.
pub(crate) fn admit_report_policy(
    resolved: &ResolvedConfig,
    interval: ReportInterval,
) -> Result<AdmittedReportPolicy, ReportPolicyError> {
    admit_report_policy_from_properties(resolved.jmeter_properties(), interval)
}

/// Admits report configuration from one already-effective property map.
///
/// The map must contain final values, not a sequence of source assignments;
/// precedence has already been resolved by
/// [`crate::config::ConfigLoader`].  This function
/// never reads files, paths, environment variables, or the process clock.
pub(crate) fn admit_report_policy_from_properties(
    properties: &PropertyMap,
    interval: ReportInterval,
) -> Result<AdmittedReportPolicy, ReportPolicyError> {
    let mut projection = ReportGeneratorProperties::default();
    let mut provenance = BTreeMap::new();
    // `iter_java` preserves exact Java keys and avoids the lossy projection
    // collision that `PropertyMap::entries` must retain for legacy callers.
    for (_, property) in properties.iter_java() {
        let key = exact_key(property);
        let Some(disposition) = disposition(&key) else {
            continue;
        };

        match disposition {
            PropertyDisposition::Supported(report_property) => {
                let key_bytes = key.len();
                if key_bytes > MAX_REPORT_PROPERTY_BYTES {
                    return Err(ReportPolicyError::PropertyBound {
                        key,
                        bound: ReportPropertyBound::Key,
                        observed: key_bytes,
                        maximum: MAX_REPORT_PROPERTY_BYTES,
                    });
                }
                if property.value.as_str().len() > MAX_REPORT_PROPERTY_BYTES {
                    return Err(ReportPolicyError::PropertyBound {
                        key,
                        bound: ReportPropertyBound::Value,
                        observed: property.value.as_str().len(),
                        maximum: MAX_REPORT_PROPERTY_BYTES,
                    });
                }
                projection
                    .apply_property(&key, property.value.as_str())
                    .map_err(|error| ReportPolicyError::InvalidProperty {
                        key: key.clone(),
                        error,
                    })?;
                provenance.insert(key, property.provenance.clone());
                debug_assert!(SUPPORTED_PROPERTIES.contains(&report_property));
            }
            PropertyDisposition::Unsupported(reason) => {
                return Err(ReportPolicyError::UnsupportedProperty { key, reason });
            }
            PropertyDisposition::Unknown => {
                return Err(ReportPolicyError::UnsupportedProperty {
                    key,
                    reason: UnsupportedReportProperty::UnknownReportGeneratorProperty,
                });
            }
        }
    }

    let dashboard = DashboardConfig::from_report_generator_properties(interval, &projection)
        .map_err(|error| map_dashboard_error(error, &projection))?;

    Ok(AdmittedReportPolicy {
        report_generator: projection,
        dashboard,
        provenance,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PropertyDisposition {
    Supported(ReportProperty),
    Unsupported(UnsupportedReportProperty),
    Unknown,
}

fn disposition(key: &str) -> Option<PropertyDisposition> {
    if let Some(property) = ReportProperty::from_wire_name(key) {
        if SUPPORTED_PROPERTIES.contains(&property) {
            return Some(PropertyDisposition::Supported(property));
        }
        debug_assert!(UNSUPPORTED_KNOWN_PROPERTIES.contains(&property));
        return Some(PropertyDisposition::Unsupported(
            UnsupportedReportProperty::KnownButNotApplied(property),
        ));
    }
    if key.starts_with("jmeter.reportgenerator.") {
        Some(PropertyDisposition::Unknown)
    } else {
        None
    }
}

fn exact_key(property: &ResolvedProperty) -> String {
    property
        .java_key()
        .to_utf8()
        .unwrap_or_else(|| property.java_key().escaped())
}

fn diagnostic_key(key: &str) -> String {
    if key.len() <= MAX_REPORT_POLICY_DIAGNOSTIC_KEY_BYTES {
        return key.to_owned();
    }
    let mut end = MAX_REPORT_POLICY_DIAGNOSTIC_KEY_BYTES.saturating_sub(3);
    while end > 0 && !key.is_char_boundary(end) {
        end -= 1;
    }
    let mut bounded = key[..end].to_owned();
    bounded.push('…');
    bounded
}

fn map_dashboard_error(
    error: ReportError,
    properties: &ReportGeneratorProperties,
) -> ReportPolicyError {
    let key = match error {
        ReportError::InvalidConfig {
            field: ConfigField::ApdexThresholds,
        } => Some(REPORTGENERATOR_APDEX_SATISFIED_THRESHOLD),
        ReportError::InvalidConfig {
            field: ConfigField::MaxPercentileSamples,
        } => Some(REPORTGENERATOR_STATISTIC_WINDOW),
        ReportError::InvalidConfig {
            field: ConfigField::TransactionControllerErrors,
        } => Some(REPORTGENERATOR_EXCLUDE_TC_FROM_TOP5_ERRORS_BY_SAMPLER),
        ReportError::InvalidConfig {
            field: ConfigField::PercentileLevels,
        } => {
            if properties.aggregate_percentile(0).is_some() {
                Some(jmeter_rs_report::AGGREGATE_RPT_PCT1)
            } else if properties.aggregate_percentile(1).is_some() {
                Some(jmeter_rs_report::AGGREGATE_RPT_PCT2)
            } else if properties.aggregate_percentile(2).is_some() {
                Some(jmeter_rs_report::AGGREGATE_RPT_PCT3)
            } else {
                None
            }
        }
        ReportError::InvalidConfig {
            field: ConfigField::OverallGranularity,
        } => {
            if properties
                .overall_granularity_millis()
                .is_some_and(|value| value < MIN_REPORT_OVERALL_GRANULARITY_MILLIS)
            {
                Some(REPORTGENERATOR_OVERALL_GRANULARITY)
            } else if properties
                .response_time_distribution_granularity_millis()
                .is_some_and(|value| value == 0)
            {
                Some(REPORTGENERATOR_RESPONSE_TIME_DISTRIBUTION_GRANULARITY)
            } else {
                Some(REPORTGENERATOR_OVERALL_GRANULARITY)
            }
        }
        _ => None,
    };
    match key {
        Some(key) => ReportPolicyError::InvalidProperty {
            key: key.to_owned(),
            error,
        },
        None => ReportPolicyError::Construction(error),
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::config::{ConfigLoader, ConfigNamespace, ConfigPlan};
    use jmeter_rs_report::{
        AGGREGATE_RPT_PCT1, AGGREGATE_RPT_PCT2, AGGREGATE_RPT_PCT3,
        DEFAULT_REPORT_STATISTIC_WINDOW, REPORTGENERATOR_APDEX_TOLERATED_THRESHOLD,
        REPORTGENERATOR_DATE_FORMAT, REPORTGENERATOR_END_DATE, REPORTGENERATOR_REPORT_TITLE,
        REPORTGENERATOR_SAMPLE_FILTER, REPORTGENERATOR_START_DATE,
    };

    fn interval() -> ReportInterval {
        ReportInterval::from_millis(0, 10_000).expect("non-empty fixture interval")
    }

    fn resolved(entries: &[(&str, &str)]) -> ResolvedConfig {
        let mut plan = ConfigPlan::new();
        for (occurrence, (key, value)) in entries.iter().enumerate() {
            plan.push_assignment(
                ConfigNamespace::Jmeter,
                (*key).to_owned(),
                (*value).to_owned(),
                occurrence,
            );
        }
        ConfigLoader::new()
            .resolve(&plan)
            .expect("inline report property fixture resolves")
    }

    fn policy(entries: &[(&str, &str)]) -> Result<AdmittedReportPolicy, ReportPolicyError> {
        admit_report_policy(&resolved(entries), interval())
    }

    #[test]
    fn empty_effective_map_uses_dashboard_defaults_and_explicit_interval() {
        let admitted = policy(&[]).expect("defaults admit");
        let dashboard = admitted.dashboard();
        assert_eq!(dashboard.interval(), interval());
        assert_eq!(dashboard.apdex().satisfied_millis(), 500);
        assert_eq!(dashboard.apdex().tolerated_millis(), 1_500);
        assert_eq!(dashboard.overall_granularity_millis(), 60_000);
        assert_eq!(
            dashboard.statistic_window(),
            DEFAULT_REPORT_STATISTIC_WINDOW
        );
        assert_eq!(
            dashboard.response_time_distribution_granularity_millis(),
            100
        );
        assert_eq!(dashboard.percentile_values(), [90.0, 95.0, 99.0]);
        assert!(dashboard.exclude_transaction_controllers_from_top5());
        assert!(admitted.provenances().is_empty());
    }

    #[test]
    fn each_supported_override_is_applied_and_provenance_is_retained() {
        let admitted = policy(&[
            (REPORTGENERATOR_APDEX_SATISFIED_THRESHOLD, "700"),
            (REPORTGENERATOR_APDEX_TOLERATED_THRESHOLD, "1700"),
            (REPORTGENERATOR_OVERALL_GRANULARITY, "2000"),
            (REPORTGENERATOR_STATISTIC_WINDOW, "5"),
            (
                REPORTGENERATOR_EXCLUDE_TC_FROM_TOP5_ERRORS_BY_SAMPLER,
                "false",
            ),
            (REPORTGENERATOR_RESPONSE_TIME_DISTRIBUTION_GRANULARITY, "25"),
            (AGGREGATE_RPT_PCT1, "90.5"),
            (AGGREGATE_RPT_PCT2, "95"),
            (AGGREGATE_RPT_PCT3, "99.25"),
        ])
        .expect("supported overrides admit");
        let dashboard = admitted.dashboard();
        assert_eq!(dashboard.apdex().satisfied_millis(), 700);
        assert_eq!(dashboard.apdex().tolerated_millis(), 1_700);
        assert_eq!(dashboard.overall_granularity_millis(), 2_000);
        assert_eq!(dashboard.statistic_window(), 5);
        assert!(!dashboard.exclude_transaction_controllers_from_top5());
        assert_eq!(
            dashboard.response_time_distribution_granularity_millis(),
            25
        );
        assert_eq!(dashboard.percentile_values(), [90.5, 95.0, 99.25]);
        assert_eq!(
            admitted.report_generator().aggregate_percentiles(),
            [90.5, 95.0, 99.25]
        );
        assert_eq!(admitted.report_generator().statistic_window(), Some(5));
        assert_eq!(admitted.provenances().len(), SUPPORTED_PROPERTIES.len());
        assert_eq!(
            admitted
                .provenance(REPORTGENERATOR_STATISTIC_WINDOW)
                .expect("statistic provenance")
                .operation,
            3
        );
        assert_eq!(
            admitted
                .provenance(AGGREGATE_RPT_PCT3)
                .expect("third percentile provenance")
                .operation,
            8
        );
    }

    #[test]
    fn system_and_global_properties_are_ignored_when_local_map_is_empty() {
        let mut resolved = ResolvedConfig::new();
        let mut system = ConfigPlan::new();
        system.push_assignment(
            ConfigNamespace::System,
            REPORTGENERATOR_OVERALL_GRANULARITY,
            "2000",
            0,
        );
        let system_resolved = ConfigLoader::new()
            .resolve(&system)
            .expect("system fixture resolves");
        resolved.system = system_resolved.system;
        let admitted = admit_report_policy(&resolved, interval()).expect("non-local ignored");
        assert_eq!(admitted.dashboard().overall_granularity_millis(), 60_000);
    }

    #[test]
    fn effective_map_precedence_uses_last_value_and_winning_source() {
        let admitted = policy(&[
            (REPORTGENERATOR_OVERALL_GRANULARITY, "2000"),
            (REPORTGENERATOR_OVERALL_GRANULARITY, "3000"),
        ])
        .expect("effective override admits");
        assert_eq!(admitted.dashboard().overall_granularity_millis(), 3_000);
        assert_eq!(
            admitted
                .provenance(REPORTGENERATOR_OVERALL_GRANULARITY)
                .expect("winning provenance")
                .operation,
            1
        );
    }

    #[test]
    fn supported_empty_values_are_invalid_and_absence_is_distinct() {
        let empty = policy(&[(REPORTGENERATOR_STATISTIC_WINDOW, "")])
            .expect_err("present-empty numeric property is invalid");
        assert_eq!(empty.code(), "report.policy.invalid-property");
        assert_eq!(empty.key(), Some(REPORTGENERATOR_STATISTIC_WINDOW));
        assert_eq!(
            policy(&[])
                .expect("absent statistic default")
                .dashboard()
                .statistic_window(),
            DEFAULT_REPORT_STATISTIC_WINDOW
        );
    }

    #[test]
    fn each_supported_parser_rejects_invalid_values_without_value_leakage() {
        let cases = [
            (AGGREGATE_RPT_PCT1, "not-a-number"),
            (AGGREGATE_RPT_PCT2, ""),
            (AGGREGATE_RPT_PCT3, "101"),
            (REPORTGENERATOR_APDEX_SATISFIED_THRESHOLD, "not-a-number"),
            (REPORTGENERATOR_APDEX_TOLERATED_THRESHOLD, ""),
            (REPORTGENERATOR_OVERALL_GRANULARITY, "not-a-number"),
            (REPORTGENERATOR_STATISTIC_WINDOW, "not-a-number"),
            (
                REPORTGENERATOR_EXCLUDE_TC_FROM_TOP5_ERRORS_BY_SAMPLER,
                "maybe",
            ),
            (REPORTGENERATOR_RESPONSE_TIME_DISTRIBUTION_GRANULARITY, ""),
        ];
        for (key, value) in cases {
            let error = policy(&[(key, value)]).expect_err("invalid report value rejected");
            assert_eq!(error.code(), "report.policy.invalid-property");
            assert_eq!(error.key(), Some(key));
            if !value.is_empty() {
                assert!(!error.to_string().contains(value));
            }
        }
    }

    #[test]
    fn aggregate_percentile_bounds_are_rejected_with_the_exact_key() {
        for (key, value) in [(AGGREGATE_RPT_PCT1, "-0.1"), (AGGREGATE_RPT_PCT2, "100.1")] {
            let error = policy(&[(key, value)]).expect_err("percentile bound rejected");
            assert_eq!(error.code(), "report.policy.invalid-property");
            assert_eq!(error.key(), Some(key));
            assert!(!error.to_string().contains(value));
        }
    }

    #[test]
    fn dashboard_bounds_are_rejected_with_the_exact_key() {
        let cases = [
            (REPORTGENERATOR_OVERALL_GRANULARITY, "1000"),
            (REPORTGENERATOR_STATISTIC_WINDOW, "0"),
            (REPORTGENERATOR_RESPONSE_TIME_DISTRIBUTION_GRANULARITY, "0"),
        ];
        for (key, value) in cases {
            let error = policy(&[(key, value)]).expect_err("dashboard bound rejected");
            assert_eq!(error.code(), "report.policy.invalid-property");
            assert_eq!(error.key(), Some(key));
        }
        let error = policy(&[
            (REPORTGENERATOR_APDEX_SATISFIED_THRESHOLD, "2000"),
            (REPORTGENERATOR_APDEX_TOLERATED_THRESHOLD, "1000"),
        ])
        .expect_err("APDEX ordering rejected");
        assert_eq!(error.code(), "report.policy.invalid-property");
        assert_eq!(error.key(), Some(REPORTGENERATOR_APDEX_SATISFIED_THRESHOLD));
    }

    #[test]
    fn explicitly_present_known_but_unapplied_fields_fail_closed() {
        let cases = [
            REPORTGENERATOR_SAMPLE_FILTER,
            REPORTGENERATOR_REPORT_TITLE,
            REPORTGENERATOR_DATE_FORMAT,
            REPORTGENERATOR_START_DATE,
            REPORTGENERATOR_END_DATE,
        ];
        for key in cases {
            let error = policy(&[(key, "")]).expect_err("unapplied known field rejected");
            assert_eq!(error.code(), "report.policy.unsupported-property");
            assert_eq!(error.key(), Some(key));
            assert!(!error.to_string().contains("secret"));
        }
    }

    #[test]
    fn unknown_report_generator_keys_fail_closed_and_non_report_keys_do_not() {
        let error = policy(&[("jmeter.reportgenerator.graph.custom.classname", "secret")])
            .expect_err("custom graph property rejected");
        assert_eq!(error.code(), "report.policy.unsupported-property");
        assert_eq!(
            error.key(),
            Some("jmeter.reportgenerator.graph.custom.classname")
        );
        assert!(!error.to_string().contains("secret"));

        let admitted = policy(&[
            ("jmeter.save.saveservice.output_format", "csv"),
            ("some.unrelated.property", "value"),
        ])
        .expect("non-report properties ignored");
        assert_eq!(
            admitted.dashboard().statistic_window(),
            DEFAULT_REPORT_STATISTIC_WINDOW
        );
    }

    #[test]
    fn property_value_bound_is_typed_and_redacts_the_value() {
        let value = "x".repeat(MAX_REPORT_PROPERTY_BYTES + 1);
        let error = policy(&[(REPORTGENERATOR_STATISTIC_WINDOW, &value)])
            .expect_err("oversized value rejected");
        assert_eq!(error.code(), "report.policy.property-bound");
        assert_eq!(error.key(), Some(REPORTGENERATOR_STATISTIC_WINDOW));
        assert!(!error.to_string().contains(&value));
        assert!(!error.retryable());
        assert_eq!(error.redacted_message(), error.to_string());
        assert!(matches!(
            error,
            ReportPolicyError::PropertyBound {
                bound: ReportPropertyBound::Value,
                ..
            }
        ));
    }

    #[test]
    fn unsupported_after_supported_value_never_returns_a_partial_policy() {
        let error = policy(&[
            (REPORTGENERATOR_STATISTIC_WINDOW, "5"),
            ("jmeter.reportgenerator.graph.custom", "x"),
        ])
        .expect_err("unknown property rejects complete admission");
        assert_eq!(error.code(), "report.policy.unsupported-property");
        assert!(error.key().is_some());
    }
}
