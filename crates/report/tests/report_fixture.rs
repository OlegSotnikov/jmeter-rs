// SPDX-License-Identifier: Apache-2.0
//! Static REPORT-001/002 corpus checks.
//!
//! The corpus is deliberately consumed as a local fixture.  These assertions
//! exercise the result codecs and pure report algorithms; they are not a
//! differential JMeter run and do not promote the profile's `not_run` oracle
//! evidence to conformance.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use jmeter_rs_report::{
    AggregateLimits, DASHBOARD_GRAPH_INVENTORY, DASHBOARD_SECTIONS, DashboardConfig,
    DashboardGraphStatus, DashboardReport, GraphSample, ListenerConfig, ListenerReport,
    ReportError, ReportInterval, ReportLimit, SummaryReport,
};
use jmeter_rs_results::{
    CsvDecoder, JtlLimits, SampleEvent, SampleSaveConfiguration, VariableValue, WallTimestamp,
    XmlDecodeConfiguration, XmlDecoder,
};

const AGGREGATE_CSV: &[u8] = include_bytes!(
    "../../../compat/fixtures/jmeter-5.6.3/reports/aggregate-dashboard/inputs/aggregate.csv"
);
const AGGREGATE_XML: &[u8] = include_bytes!(
    "../../../compat/fixtures/jmeter-5.6.3/reports/aggregate-dashboard/inputs/aggregate.xml"
);
const EMPTY_XML: &[u8] = include_bytes!(
    "../../../compat/fixtures/jmeter-5.6.3/reports/aggregate-dashboard/inputs/empty.xml"
);

#[derive(Debug, Eq, PartialEq)]
struct ReportRowProjection {
    timestamp_ms: Option<i64>,
    elapsed_millis: Option<u64>,
    idle_millis: Option<u64>,
    latency_millis: Option<u64>,
    connect_millis: Option<u64>,
    label: Option<String>,
    response_code: Option<String>,
    response_message: Option<String>,
    failure_message: Option<String>,
    successful: Option<bool>,
    received_bytes: Option<u64>,
    sent_bytes: Option<u64>,
    group_threads: Option<u64>,
    all_threads: Option<u64>,
    sample_count: Option<u64>,
    error_count: Option<u64>,
    variables: Vec<(String, Option<String>)>,
}

fn project_event(event: &SampleEvent) -> ReportRowProjection {
    let result = event.result();
    let failure_message = result
        .failure_message()
        .or_else(|| {
            result
                .assertions()
                .iter()
                .find_map(|assertion| assertion.failure_message().or(assertion.error_message()))
        })
        .filter(|message| !message.is_empty())
        .map(ToOwned::to_owned);
    ReportRowProjection {
        timestamp_ms: result.timestamp().map(WallTimestamp::as_millis),
        elapsed_millis: result.elapsed().map(|value| value.as_millis()),
        idle_millis: result.idle_time().map(|value| value.as_millis()),
        latency_millis: result.latency().map(|value| value.as_millis()),
        connect_millis: result.connect_time().map(|value| value.as_millis()),
        label: result.label_field().map(ToOwned::to_owned),
        response_code: result.response_code().map(ToOwned::to_owned),
        response_message: result.response_message().map(ToOwned::to_owned),
        failure_message,
        successful: result.success(),
        received_bytes: result.received_bytes().map(|value| value.as_u64()),
        sent_bytes: result.sent_bytes().map(|value| value.as_u64()),
        group_threads: result.group_threads().map(|value| value.as_u64()),
        all_threads: result.all_threads().map(|value| value.as_u64()),
        sample_count: result.sample_count().map(|value| value.as_u64()),
        error_count: result.error_count().map(|value| value.as_u64()),
        variables: event
            .variables()
            .iter()
            .map(|(name, value)| (name.to_owned(), value.as_str().map(ToOwned::to_owned)))
            .collect(),
    }
}

fn save_configuration(format: &str) -> SampleSaveConfiguration {
    SampleSaveConfiguration::from_properties([
        ("jmeter.save.saveservice.output_format", format),
        ("jmeter.save.saveservice.timestamp_format", "ms"),
        ("jmeter.save.saveservice.hostname", "false"),
        ("jmeter.save.saveservice.sample_count", "true"),
        ("jmeter.save.saveservice.assertions", "all"),
        ("sample_variables", "sample_id,suite_id"),
    ])
    .expect("fixture save configuration")
}

fn decode_csv() -> Vec<SampleEvent> {
    let mut decoder = CsvDecoder::with_limits(
        AGGREGATE_CSV,
        save_configuration("csv"),
        JtlLimits::default(),
    )
    .expect("fixture CSV decoder");
    let mut events = Vec::new();
    while let Some(event) = decoder.next_event().expect("fixture CSV event") {
        events.push(event);
    }
    events
}

fn decode_xml(bytes: &'static [u8]) -> Vec<SampleEvent> {
    let configuration = XmlDecodeConfiguration::new()
        .with_sample_variables(["sample_id", "suite_id"])
        .expect("fixture XML variables");
    let mut decoder = XmlDecoder::with_configuration(bytes, JtlLimits::default(), configuration)
        .expect("fixture XML decoder");
    let mut events = Vec::new();
    while let Some(event) = decoder.next_event().expect("fixture XML event") {
        events.push(event);
    }
    events
}

fn interval() -> ReportInterval {
    ReportInterval::from_millis(1_704_067_200_000, 1_704_067_210_000).expect("fixture interval")
}

fn add_events(report: &mut ListenerReport, events: &[SampleEvent]) {
    for event in events {
        report.add_event(event).expect("listener fixture event");
    }
}

fn add_events_to_summary(report: &mut SummaryReport, events: &[SampleEvent]) {
    for event in events {
        report.add_event(event).expect("summary fixture event");
    }
}

fn add_events_to_dashboard(report: &mut DashboardReport, events: &[SampleEvent]) {
    for event in events {
        report.add_event(event).expect("dashboard fixture event");
    }
}

fn assert_close(actual: f64, expected: f64) {
    assert!((actual - expected).abs() < 1.0e-9, "{actual} != {expected}");
}

#[test]
fn aggregate_dashboard_fixture_normalizes_csv_and_xml_with_identical_report_rows() {
    let csv_events = decode_csv();
    let xml_events = decode_xml(AGGREGATE_XML);
    let csv_rows: Vec<_> = csv_events.iter().map(project_event).collect();
    let xml_rows: Vec<_> = xml_events.iter().map(project_event).collect();

    assert_eq!(csv_rows, xml_rows);
    assert_eq!(csv_rows.len(), 7);
    assert_eq!(
        csv_rows
            .iter()
            .map(|row| row.label.as_deref())
            .collect::<Vec<_>>(),
        vec![
            Some("api/login"),
            Some("api/search"),
            Some("api/search"),
            Some("api/write"),
            Some("api/write"),
            Some("api/health"),
            Some("api/cache"),
        ]
    );
    assert_eq!(
        csv_rows
            .iter()
            .map(|row| row.elapsed_millis)
            .collect::<Vec<_>>(),
        vec![
            Some(100),
            Some(500),
            Some(600),
            Some(1_500),
            Some(1_501),
            None,
            Some(2_500),
        ]
    );
    assert_eq!(
        csv_rows[0].variables,
        vec![
            ("sample_id".to_owned(), Some("s01".to_owned())),
            ("suite_id".to_owned(), Some("reports-static".to_owned())),
        ]
    );
    assert_eq!(
        csv_rows[5].variables,
        vec![
            ("sample_id".to_owned(), Some("s06".to_owned())),
            ("suite_id".to_owned(), Some("reports-static".to_owned())),
        ]
    );

    let weighted_elapsed: Vec<u64> = csv_events
        .iter()
        .flat_map(|event| {
            let result = event.result();
            let count = result.sample_count().map_or(1, |value| value.as_u64());
            let elapsed = result.elapsed().map_or(0, |value| value.as_millis());
            std::iter::repeat_n(elapsed / count, count as usize)
        })
        .collect();
    assert_eq!(
        weighted_elapsed,
        vec![100, 500, 300, 300, 1_500, 1_501, 0, 2_500]
    );
    assert_eq!(
        csv_events
            .iter()
            .map(|event| event
                .result()
                .sample_count()
                .map_or(1, |value| value.as_u64()))
            .sum::<u64>(),
        8
    );
}

#[test]
fn aggregate_and_dashboard_keep_weighting_windows_apdex_percentiles_and_error_ties_distinct() {
    let events = decode_xml(AGGREGATE_XML);
    let mut listener = ListenerReport::new(ListenerConfig::new(interval()));
    let dashboard_config = DashboardConfig::new(interval())
        .expect("dashboard config")
        .with_percentile_window(5)
        .expect("dashboard window");
    let mut dashboard = DashboardReport::new(dashboard_config);
    add_events(&mut listener, &events);
    add_events_to_dashboard(&mut dashboard, &events);

    let listener_total = listener.total();
    assert_eq!(listener_total.sample_count(), 8);
    assert_eq!(listener_total.success_count(), 6);
    assert_eq!(listener_total.error_count(), 2);
    assert_eq!(listener_total.elapsed_count(), 8);
    assert_eq!(listener_total.elapsed_min(), Some(0));
    assert_eq!(listener_total.elapsed_max(), Some(2_500));
    assert_close(
        listener_total.elapsed_mean().expect("listener mean"),
        837.625,
    );
    assert_eq!(listener_total.apdex().satisfied(), 4);
    assert_eq!(listener_total.apdex().tolerated(), 1);
    assert_eq!(listener_total.apdex().frustrated(), 3);
    assert_close(
        listener_total.apdex().score().expect("listener APDEX"),
        0.5625,
    );
    assert_eq!(
        listener_total
            .percentile_millis(50.0)
            .expect("listener p50"),
        Some(300)
    );
    assert_eq!(
        listener_total
            .percentile_millis(90.0)
            .expect("listener p90"),
        Some(1_501)
    );
    assert_eq!(
        listener_total
            .percentile_millis(99.0)
            .expect("listener p99"),
        Some(2_500)
    );
    assert_eq!(listener_total.top_errors().len(), 2);
    assert_eq!(listener_total.top_errors()[0].key().code(), "409");
    assert_eq!(listener_total.top_errors()[0].key().message(), "conflict");
    assert_eq!(listener_total.top_errors()[1].key().code(), "503");

    let dashboard_total = dashboard.total();
    assert_eq!(dashboard_total.sample_count(), 7);
    assert_eq!(dashboard_total.success_count(), 5);
    assert_eq!(dashboard_total.error_count(), 2);
    assert_eq!(dashboard_total.elapsed_count(), 7);
    assert_eq!(dashboard_total.elapsed_min(), Some(0));
    assert_eq!(dashboard_total.elapsed_max(), Some(2_500));
    assert_close(
        dashboard_total.elapsed_mean().expect("dashboard mean"),
        957.2857142857143,
    );
    assert_eq!(dashboard_total.apdex().satisfied(), 3);
    assert_eq!(dashboard_total.apdex().tolerated(), 1);
    assert_eq!(dashboard_total.apdex().frustrated(), 3);
    assert_close(
        dashboard_total.apdex().score().expect("dashboard APDEX"),
        0.5,
    );
    assert_eq!(
        dashboard_total.percentile_window_observations(),
        vec![600, 1_500, 1_501, 0, 2_500]
    );
    assert_eq!(
        dashboard_total
            .percentile_millis(50.0)
            .expect("dashboard p50"),
        Some(1_500)
    );
    assert_eq!(
        dashboard_total
            .percentile_millis(90.0)
            .expect("dashboard p90"),
        Some(2_500)
    );
    assert_eq!(
        dashboard_total
            .percentile_millis(99.0)
            .expect("dashboard p99"),
        Some(2_500)
    );
    assert_eq!(dashboard_total.error_counts().len(), 2);
    assert_eq!(dashboard_total.error_counts()[0].key().code(), "409");
    assert_eq!(dashboard_total.error_counts()[1].key().code(), "503");

    let labels: Vec<_> = dashboard.labels().map(|(label, _)| label).collect();
    assert_eq!(
        labels,
        vec![
            "api/cache",
            "api/health",
            "api/login",
            "api/search",
            "api/write"
        ]
    );
    assert_eq!(
        DASHBOARD_SECTIONS,
        [
            "apdex",
            "request_summary",
            "statistics",
            "errors",
            "top_errors",
            "time_series",
            "response_time_distribution",
        ]
    );
    let graph_ids: Vec<_> = DASHBOARD_GRAPH_INVENTORY
        .iter()
        .map(|definition| definition.id)
        .collect();
    assert_eq!(
        graph_ids,
        vec![
            "responseTimePercentiles",
            "responseTimeDistribution",
            "activeThreadsOverTime",
            "timeVsThreads",
            "bytesThroughputOverTime",
            "responseTimesOverTime",
            "responseTimePercentilesOverTime",
            "syntheticResponseTimeDistribution",
            "latenciesOverTime",
            "connectTimeOverTime",
            "responseTimeVsRequest",
            "latencyVsRequest",
            "hitsPerSecond",
            "codesPerSecond",
            "totalTPS",
            "transactionsPerSecond",
        ]
    );
    let sections = dashboard.materialize_graph_sections(&[], 8);
    assert!(
        sections
            .sections()
            .all(|section| section.status() == DashboardGraphStatus::NotMaterialized)
    );
}

#[test]
fn empty_fixture_preserves_zero_metrics_and_planned_graph_sections() {
    let events = decode_xml(EMPTY_XML);
    assert!(events.is_empty());
    let mut listener = ListenerReport::new(ListenerConfig::new(interval()));
    let mut dashboard = DashboardReport::new(
        DashboardConfig::new(interval())
            .expect("dashboard config")
            .with_percentile_window(5)
            .expect("dashboard window"),
    );
    add_events(&mut listener, &events);
    add_events_to_dashboard(&mut dashboard, &events);
    assert_eq!(listener.total().sample_count(), 0);
    assert_eq!(listener.total().elapsed_mean(), None);
    assert_eq!(listener.total().apdex().score(), None);
    assert_eq!(
        listener.total().percentile_millis(50.0).expect("empty p50"),
        None
    );
    assert_eq!(dashboard.total().sample_count(), 0);
    assert_eq!(dashboard.total().elapsed_mean(), None);
    assert_eq!(dashboard.total().apdex().score(), None);
    assert_eq!(
        dashboard
            .total()
            .percentile_millis(50.0)
            .expect("empty p50"),
        None
    );
    assert!(
        dashboard
            .materialize_graph_sections(&[], 8)
            .sections()
            .all(|section| section.status() == DashboardGraphStatus::NotMaterialized)
    );
}

#[test]
fn summary_html_uses_configured_top_error_limit_and_slice_inputs_are_bounded() {
    let events = decode_xml(AGGREGATE_XML);
    let summary_config = ListenerConfig::new(interval())
        .with_top_error_limit(1)
        .expect("summary top-error limit");
    let mut summary = SummaryReport::new(summary_config);
    assert_eq!(summary.config().top_error_limit(), 1);
    add_events_to_summary(&mut summary, &events);
    let summary_html = summary.to_html().expect("summary HTML");
    let top_errors = summary_html
        .split("<section id=\"top-errors\">")
        .nth(1)
        .expect("summary top-error section")
        .split("</section>")
        .next()
        .expect("summary top-error body");
    assert!(top_errors.contains("409/conflict"));
    assert!(!top_errors.contains("503/overload"));

    let limits = AggregateLimits::new(8, 8, 8)
        .expect("aggregate limits")
        .with_max_input_samples(1)
        .expect("input limit");
    let samples = vec![
        GraphSample::new(
            WallTimestamp::from_millis(1_704_067_200_000),
            Some(1),
            false,
            0,
            0,
        ),
        GraphSample::new(
            WallTimestamp::from_millis(1_704_067_201_000),
            Some(1),
            false,
            0,
            0,
        ),
    ];
    let listener = ListenerReport::new(ListenerConfig::new(interval()).with_limits(limits));
    assert_eq!(
        listener.graph_series(&samples, 10_000, 8),
        Err(ReportError::LimitExceeded {
            resource: ReportLimit::InputSamples,
            actual: 2,
            maximum: 1,
        })
    );
    let dashboard_config = DashboardConfig::new(interval())
        .expect("dashboard config")
        .with_percentile_window(1)
        .expect("dashboard window")
        .with_limits(limits)
        .expect("dashboard limits");
    let dashboard = DashboardReport::new(dashboard_config);
    assert_eq!(
        dashboard.graph_series(&samples, 8),
        Err(ReportError::LimitExceeded {
            resource: ReportLimit::InputSamples,
            actual: 2,
            maximum: 1,
        })
    );
    let sections = dashboard.materialize_graph_sections(&samples, 8);
    assert!(sections.sections().all(|section| {
        section.status() == DashboardGraphStatus::Unsupported
            && section.error()
                == Some(ReportError::LimitExceeded {
                    resource: ReportLimit::InputSamples,
                    actual: 2,
                    maximum: 1,
                })
    }));

    let string_limits = AggregateLimits::new(8, 8, 8)
        .expect("aggregate limits")
        .with_string_limits(3, 8)
        .expect("string limits");
    let long_label = GraphSample::new(
        WallTimestamp::from_millis(1_704_067_200_000),
        Some(1),
        false,
        0,
        0,
    )
    .with_label("abcd");
    let bounded_listener =
        ListenerReport::new(ListenerConfig::new(interval()).with_limits(string_limits));
    assert_eq!(
        bounded_listener.graph_series(std::slice::from_ref(&long_label), 10_000, 8),
        Err(ReportError::LimitExceeded {
            resource: ReportLimit::LabelBytes,
            actual: 4,
            maximum: 3,
        })
    );
}

#[test]
fn report_fixture_projection_retains_absent_values_without_fabricating_variables() {
    let csv = decode_csv();
    let health = project_event(&csv[5]);
    assert_eq!(health.elapsed_millis, None);
    assert_eq!(health.latency_millis, None);
    assert_eq!(health.connect_millis, None);
    assert_eq!(health.failure_message, None);
    assert_eq!(health.successful, Some(true));
    assert!(
        health
            .variables
            .iter()
            .all(|(_, value)| matches!(value, Some(value) if !value.is_empty()))
    );
    assert!(matches!(
        csv[5].variables().get("sample_id"),
        Some(VariableValue::Present(value)) if value == "s06"
    ));
}
