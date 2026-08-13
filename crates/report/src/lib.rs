// SPDX-License-Identifier: Apache-2.0
//! Deterministic listener aggregates and dashboard/report data models.
//!
//! The crate is deliberately pure and in-process: callers provide immutable
//! [`jmeter_rs_results::SampleResult`] snapshots, explicit report intervals,
//! and resource bounds.  Listener and dashboard algorithms are separate so a
//! dashboard percentile estimate can never silently replace the listener's
//! exact nearest-rank value.

#![forbid(unsafe_code)]

mod backend;
mod config;
mod dashboard;
mod error;
mod graph;
mod graphs;
mod listener;
mod metrics;

pub use backend::{
    ActiveThreadSnapshot, BackendAnnotation, BackendClock, BackendConfigField,
    BackendContextSnapshot, BackendEndpoint, BackendError, BackendLifecycleState, BackendListener,
    BackendMetricBatch, BackendMetricsSnapshot, BackendOperation, BackendPayload,
    BackendPercentile, BackendQueueConfig, BackendResource, BackendRuntimeConfig, BackendScheduler,
    BackendSecret, BackendSender, BackendStatusSnapshot, BackendTransportErrorKind,
    BackendWindowConfig, BackendWindowMode, CompiledPattern, DEFAULT_BACKEND_BATCH_BYTES,
    DEFAULT_BACKEND_BATCH_CAPACITY, DEFAULT_BACKEND_MAX_ANNOTATIONS, DEFAULT_BACKEND_MAX_CONTEXTS,
    DEFAULT_BACKEND_MAX_RETRIES, DEFAULT_BACKEND_QUEUE_BYTES, DEFAULT_BACKEND_QUEUE_CAPACITY,
    DEFAULT_BACKEND_SHUTDOWN_TIMEOUT_MILLIS, DEFAULT_BACKEND_WINDOW_SAMPLES,
    DEFAULT_GRAPHITE_SEND_INTERVAL_MILLIS, DEFAULT_INFLUX_SEND_INTERVAL_MILLIS, EnqueueOutcome,
    FlushOutcome, GraphiteConfig, GraphiteMetricLine, GraphiteSenderKind, InfluxConfig,
    InfluxFieldValue, InfluxHttpRequest, InfluxPoint, InfluxTag, InfluxTimestampPrecision,
    JavaBackendListenerDescriptor, MAX_BACKEND_RETRIES, QueueFullPolicy, SamplerFilter,
    build_influx_http_request, encode_graphite_plaintext, encode_influx_line_protocol,
    graphite_metric_lines, influx_points, sanitize_graphite_context,
};
pub use config::{
    AGGREGATE_RPT_PCT1, AGGREGATE_RPT_PCT2, AGGREGATE_RPT_PCT3, AggregateLimits, ApdexThresholds,
    DEFAULT_REPORT_OVERALL_GRANULARITY_MILLIS, DEFAULT_REPORT_PERCENTILES,
    DEFAULT_REPORT_STATISTIC_WINDOW, DEFAULT_RESPONSE_TIME_DISTRIBUTION_GRANULARITY_MILLIS,
    DashboardConfig, DashboardPercentileEstimator, LabelGrouping, ListenerConfig,
    MAX_REPORT_PROPERTIES, MAX_REPORT_PROPERTY_BYTES, MIN_REPORT_OVERALL_GRANULARITY_MILLIS,
    PercentileConfiguration, PercentileLevel, REPORTGENERATOR_APDEX_SATISFIED_THRESHOLD,
    REPORTGENERATOR_APDEX_TOLERATED_THRESHOLD, REPORTGENERATOR_DATE_FORMAT,
    REPORTGENERATOR_END_DATE, REPORTGENERATOR_EXCLUDE_TC_FROM_TOP5_ERRORS_BY_SAMPLER,
    REPORTGENERATOR_OVERALL_GRANULARITY, REPORTGENERATOR_REPORT_TITLE,
    REPORTGENERATOR_RESPONSE_TIME_DISTRIBUTION_GRANULARITY, REPORTGENERATOR_SAMPLE_FILTER,
    REPORTGENERATOR_START_DATE, REPORTGENERATOR_STATISTIC_WINDOW, ReportGeneratorProperties,
    ReportInterval, ReportProperty,
};
pub use dashboard::{
    DASHBOARD_GRAPH_INVENTORY, DASHBOARD_SECTIONS, Dashboard, DashboardGraphDefinition,
    DashboardGraphPayload, DashboardGraphSection, DashboardGraphSections, DashboardGraphStatus,
    DashboardMetrics, DashboardReport,
};
pub use error::{
    ConfigField, MAX_REPORT_DIAGNOSTIC_BYTES, ReportError, ReportErrorCode, ReportField,
    ReportLimit, SampleField,
};
pub use graph::{
    GraphAggregationOptions, GraphPoint, GraphSample, GraphSampleCountMode, GraphTimestampPolicy,
    aggregate_graph_samples, aggregate_graph_samples_with_options,
};
pub use graphs::{
    ActiveThreadsGraphPoint, BytesGraphPoint, ConnectGraphPoint, GraphBucket, HitsPerSecondPoint,
    LabelGraphPoint, LatencyGraphPoint, LatencyRequestPoint, ResponseCodeGraphPoint,
    ResponseTimeDistributionPoint, ResponseTimeGraphPoint, ResponseTimePercentileGraphPoint,
    ResponseTimeRequestPoint, SyntheticResponseTimePoint, TimeVsThreadsGraphPoint, TotalTpsPoint,
    TransactionTpsPoint, aggregate_active_threads_graph_samples, aggregate_bytes_graph_samples,
    aggregate_connect_graph_samples, aggregate_hits_per_second_graph_samples,
    aggregate_label_graph_samples, aggregate_latency_graph_samples,
    aggregate_latency_vs_request_graph_samples, aggregate_response_code_graph_samples,
    aggregate_response_time_distribution_graph_samples, aggregate_response_time_graph_samples,
    aggregate_response_time_percentile_graph_samples,
    aggregate_response_time_percentile_graph_samples_with_estimator,
    aggregate_response_time_vs_request_graph_samples,
    aggregate_synthetic_response_time_graph_samples, aggregate_time_vs_threads_graph_samples,
    aggregate_total_tps_graph_samples, aggregate_transactions_per_second_graph_samples,
    graph_labels,
};
pub use listener::{
    AggregateReport, ListenerAggregate, ListenerMetrics, ListenerReport, SummaryConfig,
    SummaryReport,
};
pub use metrics::{ApdexCounts, ErrorKey, SampleMetadata, SummaryMetrics, TopError};

#[cfg(test)]
// Fixed configuration constants are asserted by these tests; failures should
// identify the broken fixture rather than be converted into test plumbing.
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn invalid_configuration_is_typed_and_stable() {
        assert_eq!(
            AggregateLimits::new(0, 1, 1),
            Err(ReportError::InvalidConfig {
                field: ConfigField::MaxLabels
            })
        );
        assert_eq!(
            ApdexThresholds::new(2, 1),
            Err(ReportError::InvalidConfig {
                field: ConfigField::ApdexThresholds
            })
        );
        assert_eq!(
            ListenerConfig::new(ReportInterval::from_millis(0, 1).unwrap())
                .with_percentiles([90, 95, 101]),
            Err(ReportError::InvalidConfig {
                field: ConfigField::Percentiles
            })
        );
        assert_eq!(
            ReportInterval::from_millis(10, 10),
            Err(ReportError::InvalidInterval { start: 10, end: 10 })
        );
        assert_eq!(
            ReportError::LimitExceeded {
                resource: ReportLimit::Labels,
                actual: 2,
                maximum: 1,
            }
            .stable_code(),
            "report.limit_exceeded"
        );
        assert!(
            DashboardConfig::new(ReportInterval::from_millis(0, 1).unwrap())
                .unwrap()
                .with_decimal_percentiles([12.345, 50.0, 99.0])
                .is_ok()
        );
        assert_eq!(
            AggregateLimits::default().with_max_input_samples(
                AggregateLimits::default()
                    .max_input_samples()
                    .saturating_add(1)
            ),
            Err(ReportError::InvalidConfig {
                field: ConfigField::MaxInputSamples
            })
        );
        assert_eq!(
            AggregateLimits::default().with_string_limits(
                AggregateLimits::default()
                    .max_label_bytes()
                    .saturating_add(1),
                AggregateLimits::default().max_error_key_bytes(),
            ),
            Err(ReportError::InvalidConfig {
                field: ConfigField::MaxLabelBytes
            })
        );
    }

    #[test]
    fn empty_serializer_bytes_are_golden_and_bounded() {
        let interval = ReportInterval::from_millis(0, 1_000).unwrap();
        let listener = ListenerReport::new(ListenerConfig::new(interval));
        let summary = SummaryReport::new(SummaryConfig::new(interval));
        let dashboard = DashboardReport::new(DashboardConfig::new(interval).unwrap());
        let listener_json = r#"{"total":{"sample_count":0,"success_count":0,"error_count":0,"elapsed_count":0,"average_millis":null,"min_millis":null,"max_millis":null,"stddev_millis":null,"elapsed_variance_population_millis2":null,"error_percentage":0,"throughput_per_second":0,"error_throughput_per_second":0,"received_bytes":0,"sent_bytes":0,"received_bytes_per_second":0,"sent_bytes_per_second":0,"success_percentage":0,"apdex":{"satisfied":0,"tolerated":0,"frustrated":0,"score":null},"percentiles":[null,null,null],"errors":[],"error_counts":[],"top_errors":[],"percentile_sample_count":0,"percentiles_millis":{"0":null,"25":null,"50":null,"75":null,"90":null,"95":null,"99":null,"100":null},"percentiles_millis_rounded":{"0":null,"25":null,"50":null,"75":null,"90":null,"95":null,"99":null,"100":null}},"labels":[],"graph":[]}"#;
        let summary_json = r#"{"total":{"sample_count":0,"success_count":0,"error_count":0,"elapsed_count":0,"average_millis":null,"min_millis":null,"max_millis":null,"stddev_millis":null,"elapsed_variance_population_millis2":null,"error_percentage":0,"success_percentage":0,"throughput_per_second":0,"error_throughput_per_second":0,"received_bytes":0,"sent_bytes":0,"received_bytes_per_second":0,"sent_bytes_per_second":0,"apdex":{"satisfied":0,"tolerated":0,"frustrated":0,"score":null},"error_counts":[],"errors":[],"top_errors":[],"percentile_sample_count":0,"percentiles":null,"percentiles_millis":null,"percentiles_millis_rounded":null},"labels":[],"graph":[]}"#;
        assert_eq!(
            listener.to_json().unwrap().as_bytes(),
            listener_json.as_bytes()
        );
        assert_eq!(
            summary.to_json().unwrap().as_bytes(),
            summary_json.as_bytes()
        );
        assert_eq!(listener.to_json().unwrap(), listener.to_json().unwrap());
        assert_eq!(
            summary.to_html().unwrap().as_bytes(),
            summary.to_html().unwrap().as_bytes()
        );
        let dashboard_json = dashboard.to_json().unwrap();
        assert!(
            dashboard_json
                .as_bytes()
                .starts_with(b"{\"config\":{\"percentile_estimator\":\"LEGACY\"")
        );
        assert!(dashboard_json.as_bytes().ends_with(b"]}"));
        assert_eq!(dashboard_json, dashboard.to_json().unwrap());
    }
}
