// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::expect_used, clippy::panic, missing_docs)]

use std::sync::{Arc, Mutex};

use jmeter_rs_report::{
    BackendClock, BackendContextSnapshot, BackendEndpoint, BackendError, BackendListener,
    BackendMetricsSnapshot, BackendPayload, BackendScheduler, BackendSender, BackendStatusSnapshot,
    EnqueueOutcome, FlushOutcome, GraphiteConfig, GraphiteMetricLine, InfluxConfig,
    InfluxFieldValue, InfluxPoint, JavaBackendListenerDescriptor, SamplerFilter,
    build_influx_http_request, encode_graphite_plaintext, encode_influx_line_protocol,
    influx_points,
};
use jmeter_rs_results::{
    ByteCount, ElapsedTime, ErrorCount, SampleCount, SampleEvent, SampleResult, VariableSnapshot,
};

#[derive(Clone, Default)]
struct SenderState {
    setup_count: usize,
    teardown_count: usize,
    payloads: Vec<BackendPayload>,
    fail_send: bool,
}

struct FakeSender {
    state: Arc<Mutex<SenderState>>,
}

impl BackendSender for FakeSender {
    fn setup(&mut self, _endpoint: &BackendEndpoint) -> Result<(), BackendError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.setup_count += 1;
        Ok(())
    }

    fn send(&mut self, payload: &BackendPayload) -> Result<(), BackendError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.fail_send {
            return Err(BackendError::Transport {
                kind: jmeter_rs_report::BackendTransportErrorKind::Write,
                retryable: false,
            });
        }
        state.payloads.push(payload.clone());
        Ok(())
    }

    fn teardown(&mut self) -> Result<(), BackendError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.teardown_count += 1;
        Ok(())
    }
}

struct FakeClock {
    now: i64,
}

impl BackendClock for FakeClock {
    fn now_millis(&self) -> i64 {
        self.now
    }
}

#[derive(Default)]
struct FakeScheduler {
    deadlines: Vec<i64>,
    cancelled: usize,
}

impl BackendScheduler for FakeScheduler {
    fn schedule(&mut self, at_millis: i64) -> Result<(), BackendError> {
        self.deadlines.push(at_millis);
        Ok(())
    }

    fn cancel(&mut self) -> Result<(), BackendError> {
        self.cancelled += 1;
        Ok(())
    }
}

fn event(label: &str, elapsed: u64, successful: bool) -> SampleEvent {
    let mut result = SampleResult::new(label);
    assert!(
        result
            .set_elapsed(Some(ElapsedTime::from_millis(elapsed)))
            .is_ok()
    );
    result.set_successful(successful);
    result.set_response_code_text(if successful { "200" } else { "500" });
    result.set_response_message_text(if successful { "OK" } else { "boom" });
    result.set_received_bytes(Some(ByteCount::new(20)));
    result.set_sent_bytes(Some(ByteCount::new(3)));
    SampleEvent::new(result, "run", "thread-1", "host", VariableSnapshot::new())
}

fn weighted_failed_event(
    label: &str,
    elapsed: u64,
    sample_count: u64,
    error_count: Option<u64>,
) -> SampleEvent {
    let mut result = SampleResult::new(label);
    assert!(
        result
            .set_elapsed(Some(ElapsedTime::from_millis(elapsed)))
            .is_ok()
    );
    result.set_successful(false);
    result.set_response_code_text("500");
    result.set_response_message_text("boom");
    result.set_sample_count(Some(SampleCount::from_u64(sample_count)));
    if let Some(error_count) = error_count {
        result.set_error_count(Some(ErrorCount::from_u64(error_count)));
    }
    SampleEvent::new(result, "run", "thread-1", "host", VariableSnapshot::new())
}

#[test]
fn graphite_plaintext_has_stable_lines_and_timestamp_precision() {
    let lines = [
        GraphiteMetricLine {
            path: "jmeter.all.ok.count".to_owned(),
            value: 2.0,
            timestamp_seconds: 1_704_067_203,
        },
        GraphiteMetricLine {
            path: "jmeter.all.ok.avg".to_owned(),
            value: 175.5,
            timestamp_seconds: 1_704_067_203,
        },
    ];
    let body = encode_graphite_plaintext(&lines, 512, 1_024).expect("bounded Graphite body");
    assert_eq!(
        body,
        b"jmeter.all.ok.count 2 1704067203\njmeter.all.ok.avg 175.5 1704067203\n"
    );
}

#[test]
fn influx_line_protocol_escapes_measurements_tags_fields_and_strings() {
    let mut point = InfluxPoint::new("j meter", Some(1_704_067_200_000));
    point.add_tag("tag key", "a,b=c").expect("tag");
    point
        .add_field(
            "field key",
            InfluxFieldValue::String("quote \" slash \\".to_owned()),
        )
        .expect("string field");
    point
        .add_field("count", InfluxFieldValue::Unsigned(2))
        .expect("integer field");
    let body = encode_influx_line_protocol(&[point], 512, 1_024).expect("bounded line protocol");
    assert_eq!(
        String::from_utf8(body).expect("line protocol is UTF-8"),
        r#"j\ meter,tag\ key=a\,b\=c field\ key="quote \" slash \\",count=2u 1704067200000
"#
    );
}

#[test]
fn filters_keep_graphite_full_match_and_influx_find_distinct() {
    let full = SamplerFilter::regex_full("backend/(login|failure)").expect("full regex");
    assert!(full.matches("backend/login").expect("match"));
    assert!(!full.matches("prefix/backend/login").expect("match"));

    let find = SamplerFilter::regex_find("login").expect("find regex");
    assert!(find.matches("backend/login").expect("match"));
    assert!(!find.matches("backend/logout").expect("match"));
}

#[test]
fn backend_listener_is_bounded_and_failed_send_retains_events() {
    let mut config = GraphiteConfig::new("127.0.0.1", 2_003).expect("config");
    config.runtime.queue =
        jmeter_rs_report::BackendQueueConfig::new(1, 1_024, 1, 1_024).expect("queue");
    config.runtime.shutdown_timeout_millis = 1;
    let endpoint = BackendEndpoint::Graphite(config);
    let state = Arc::new(Mutex::new(SenderState {
        fail_send: true,
        ..SenderState::default()
    }));
    let sender = FakeSender {
        state: Arc::clone(&state),
    };
    let mut listener = BackendListener::new(
        endpoint,
        Box::new(sender),
        Box::new(FakeClock {
            now: 1_704_067_200_000,
        }),
        Box::new(FakeScheduler::default()),
    )
    .expect("listener");
    listener.start().expect("start");
    assert_eq!(
        listener.enqueue(event("backend/login", 100, true)),
        Ok(EnqueueOutcome::Accepted)
    );
    assert!(matches!(
        listener.enqueue(event("backend/failure", 700, false)),
        Err(BackendError::QueueFull { capacity: 1 })
    ));
    assert_eq!(listener.queued_events(), 1);
    assert!(matches!(
        listener.flush(),
        Err(BackendError::Transport { .. })
    ));
    assert_eq!(listener.queued_events(), 1);
    assert!(matches!(
        listener.finish(),
        Err(BackendError::Transport { .. })
    ));
    assert_eq!(
        listener.state(),
        jmeter_rs_report::BackendLifecycleState::Failed
    );
    assert_eq!(listener.queued_events(), 1);
}

#[test]
fn drop_policy_and_cancellation_are_explicit() {
    let mut config = GraphiteConfig::new("127.0.0.1", 2_003).expect("config");
    config.runtime.queue = jmeter_rs_report::BackendQueueConfig::new(1, 1_024, 1, 1_024)
        .expect("queue")
        .with_full_policy(jmeter_rs_report::QueueFullPolicy::DropWithDiagnostic);
    let state = Arc::new(Mutex::new(SenderState::default()));
    let mut listener = BackendListener::new(
        BackendEndpoint::Graphite(config),
        Box::new(FakeSender {
            state: Arc::clone(&state),
        }),
        Box::new(FakeClock {
            now: 1_704_067_200_000,
        }),
        Box::new(FakeScheduler::default()),
    )
    .expect("listener");
    listener.start().expect("start");
    assert_eq!(
        listener.enqueue(event("first", 1, true)),
        Ok(EnqueueOutcome::Accepted)
    );
    assert_eq!(
        listener.enqueue(event("second", 1, true)),
        Ok(EnqueueOutcome::DroppedWithDiagnostic { dropped_total: 1 })
    );
    assert_eq!(listener.dropped_events(), 1);
    listener.cancel().expect("cancel");
    assert_eq!(listener.queued_events(), 1);
    assert_eq!(listener.finish(), Err(BackendError::Cancelled));
    assert_eq!(listener.queued_events(), 1);
    assert!(
        state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .payloads
            .is_empty()
    );
}

#[test]
fn backend_listener_flushes_metrics_and_tears_down_in_order() {
    let mut config = GraphiteConfig::new("127.0.0.1", 2_003)
        .expect("config")
        .with_summary_only(false)
        .with_sampler_filter(SamplerFilter::exact(["backend/login"]).expect("filter"));
    config.runtime.queue =
        jmeter_rs_report::BackendQueueConfig::new(2, 4_096, 2, 4_096).expect("queue");
    let state = Arc::new(Mutex::new(SenderState::default()));
    let mut listener = BackendListener::new(
        BackendEndpoint::Graphite(config),
        Box::new(FakeSender {
            state: Arc::clone(&state),
        }),
        Box::new(FakeClock {
            now: 1_704_067_200_000,
        }),
        Box::new(FakeScheduler::default()),
    )
    .expect("listener");
    listener.start().expect("start");
    listener
        .test_started("fixture")
        .expect("annotation is accepted");
    listener
        .enqueue(event("backend/login", 100, true))
        .expect("enqueue");
    assert_eq!(listener.flush(), Ok(FlushOutcome::Sent { events: 1 }));
    assert_eq!(listener.queued_events(), 0);
    listener
        .test_ended("fixture")
        .expect("annotation is accepted");
    listener.finish().expect("finish");
    let state = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(state.setup_count, 1);
    assert_eq!(state.teardown_count, 1);
    assert_eq!(state.payloads.len(), 2);
    let BackendPayload::Graphite { body, .. } = &state.payloads[0] else {
        panic!("expected Graphite payload");
    };
    let text = String::from_utf8(body.clone()).expect("UTF-8 Graphite");
    assert!(text.contains("jmeter.all.ok.count"));
    assert!(text.contains("jmeter.backend/login.ok.count"));
}

#[test]
fn influx_request_redacts_token_in_debug_but_sends_authorization() {
    let config = InfluxConfig::new(
        "https://user:password@example.invalid/write?org=o&bucket=b&token=query-secret",
        "report-fixture",
    )
    .expect("config")
    .with_token("header-secret")
    .expect("token");
    let mut point = InfluxPoint::new("jmeter", Some(1_704_067_200_000));
    point.add_tag("application", "report-fixture").expect("tag");
    point
        .add_field("count", InfluxFieldValue::Unsigned(1))
        .expect("field");
    let request = build_influx_http_request(&config, &[point], 512, 1_024).expect("request");
    let debug = format!("{request:?}");
    assert!(!debug.contains("header-secret"));
    assert!(!debug.contains("query-secret"));
    assert!(!debug.contains("password"));
    assert!(
        request
            .headers
            .iter()
            .any(|(name, value)| name == "Authorization" && value == "Token header-secret")
    );
}

#[test]
fn influx_backend_uses_decimal_percentile_suffix_and_context_order() {
    let mut config = InfluxConfig::new("http://127.0.0.1:8086/write?db=jmeter", "fixture")
        .expect("config")
        .with_summary_only(false)
        .with_sampler_filter(SamplerFilter::regex_find("backend").expect("filter"));
    config.percentiles = [99.0, 95.0, 90.0]
        .into_iter()
        .map(|value| jmeter_rs_report::BackendPercentile::from_percent(value).expect("percentile"))
        .collect();
    let p99 = jmeter_rs_report::BackendPercentile::from_percent(99.0).expect("percentile");
    let p95 = jmeter_rs_report::BackendPercentile::from_percent(95.0).expect("percentile");
    let p90 = jmeter_rs_report::BackendPercentile::from_percent(90.0).expect("percentile");
    let mut status = BackendStatusSnapshot {
        count: 1,
        min_millis: Some(7),
        max_millis: Some(7),
        average_millis: Some(7.0),
        ..BackendStatusSnapshot::default()
    };
    status.percentiles.insert(p99, 7.0);
    status.percentiles.insert(p95, 7.0);
    status.percentiles.insert(p90, 7.0);
    let mut snapshot = BackendMetricsSnapshot::default();
    snapshot.contexts.insert(
        "backend/login".to_owned(),
        BackendContextSnapshot {
            ok: status.clone(),
            all: status,
            hit_count: 1,
            sent_bytes: 2,
            received_bytes: 3,
            ..BackendContextSnapshot::default()
        },
    );
    snapshot.contexts.insert(
        "all".to_owned(),
        BackendContextSnapshot {
            // JMeter's cumulative writer skips a zero total; keep this
            // synthetic row source-observable while testing ordering.
            all: BackendStatusSnapshot {
                count: 1,
                ..BackendStatusSnapshot::default()
            },
            ..BackendContextSnapshot::default()
        },
    );
    let points = influx_points(&config, &snapshot, 1_704_067_200_000).expect("points");
    assert_eq!(points[0].tags[1].value, "all");
    let body = encode_influx_line_protocol(&points, 2_048, 16_384).expect("body");
    let text = String::from_utf8(body).expect("UTF-8 line protocol");
    assert!(text.contains("pct99.0=7"));
    assert!(text.contains("pct95.0"));
    assert!(text.contains("pct90.0"));
    assert!(
        text.find("transaction=all").unwrap_or(usize::MAX)
            < text.find("transaction=backend/login").unwrap_or(usize::MAX)
    );
}

#[test]
fn backend_error_descriptor_preserves_explicit_weighted_sample_counts() {
    let mut config = InfluxConfig::new("http://127.0.0.1:8086/write?db=jmeter", "fixture")
        .expect("config")
        .with_summary_only(false)
        .with_sampler_filter(
            SamplerFilter::exact(["backend/failure-weighted", "backend/failure-explicit"])
                .expect("filter"),
        );
    config.runtime.queue =
        jmeter_rs_report::BackendQueueConfig::new(2, 4_096, 2, 4_096).expect("queue");
    let state = Arc::new(Mutex::new(SenderState::default()));
    let mut listener = BackendListener::new(
        BackendEndpoint::Influx(config),
        Box::new(FakeSender {
            state: Arc::clone(&state),
        }),
        Box::new(FakeClock {
            now: 1_704_067_200_000,
        }),
        Box::new(FakeScheduler::default()),
    )
    .expect("listener");
    listener.start().expect("start");
    listener
        .enqueue(weighted_failed_event(
            "backend/failure-weighted",
            600,
            2,
            Some(2),
        ))
        .expect("weighted error count");
    listener
        .enqueue(weighted_failed_event(
            "backend/failure-explicit",
            600,
            2,
            Some(2),
        ))
        .expect("explicit error count");
    listener.flush().expect("flush");

    let state = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let BackendPayload::Influx(request) = &state.payloads[0] else {
        panic!("expected Influx payload");
    };
    let body = String::from_utf8(request.body.clone()).expect("UTF-8 line protocol");
    assert!(body.lines().any(|line| {
        line.contains("transaction=all,statut=all") && line.contains("countError=4u")
    }));
    assert!(body.lines().any(|line| {
        line.contains("transaction=backend/failure-weighted")
            && line.contains("responseCode=500")
            && line.contains("count=2u")
    }));
    assert!(body.lines().any(|line| {
        line.contains("transaction=backend/failure-explicit")
            && line.contains("responseCode=500")
            && line.contains("count=2u")
    }));
}

#[test]
fn backend_failed_ordinary_weighted_row_is_treated_as_all_errors() {
    // An ordinary failed SampleResult omits ec on the wire. Its derived
    // error_count() is one, but JMeter's backend projection treats the result
    // as wholly failed even when a statistical sample count is present.
    let mut config = InfluxConfig::new("http://127.0.0.1:8086/write?db=jmeter", "fixture")
        .expect("config")
        .with_summary_only(false)
        .with_sampler_filter(SamplerFilter::exact(["backend/failure-default"]).expect("filter"));
    config.runtime.queue =
        jmeter_rs_report::BackendQueueConfig::new(1, 4_096, 1, 4_096).expect("queue");
    let state = Arc::new(Mutex::new(SenderState::default()));
    let mut listener = BackendListener::new(
        BackendEndpoint::Influx(config),
        Box::new(FakeSender {
            state: Arc::clone(&state),
        }),
        Box::new(FakeClock {
            now: 1_704_067_200_000,
        }),
        Box::new(FakeScheduler::default()),
    )
    .expect("listener");
    listener.start().expect("start");
    listener
        .enqueue(weighted_failed_event(
            "backend/failure-default",
            600,
            2,
            None,
        ))
        .expect("ordinary failed event");
    listener.flush().expect("ordinary failed event flush");

    let state = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let BackendPayload::Influx(request) = &state.payloads[0] else {
        panic!("expected Influx payload");
    };
    let body = String::from_utf8(request.body.clone()).expect("UTF-8 line protocol");
    assert!(body.lines().any(|line| {
        line.contains("transaction=all,statut=all") && line.contains("countError=2u")
    }));
    assert!(body.lines().any(|line| {
        line.contains("transaction=backend/failure-default")
            && line.contains("responseCode=500")
            && line.contains("count=2u")
    }));
}

#[test]
fn backend_partial_weighted_status_timing_is_typed_unsupported() {
    let mut config = InfluxConfig::new("http://127.0.0.1:8086/write?db=jmeter", "fixture")
        .expect("config")
        .with_summary_only(false)
        .with_sampler_filter(SamplerFilter::exact(["backend/failure-partial"]).expect("filter"));
    config.runtime.queue =
        jmeter_rs_report::BackendQueueConfig::new(1, 4_096, 1, 4_096).expect("queue");
    let state = Arc::new(Mutex::new(SenderState::default()));
    let mut listener = BackendListener::new(
        BackendEndpoint::Influx(config),
        Box::new(FakeSender {
            state: Arc::clone(&state),
        }),
        Box::new(FakeClock {
            now: 1_704_067_200_000,
        }),
        Box::new(FakeScheduler::default()),
    )
    .expect("listener");
    listener.start().expect("start");
    listener
        .enqueue(weighted_failed_event(
            "backend/failure-partial",
            600,
            2,
            Some(1),
        ))
        .expect("partial weighted event");
    assert_eq!(
        listener.flush(),
        Err(BackendError::Unsupported {
            capability: "backend.weighted_partial_status_timing".to_owned(),
        })
    );
    assert_eq!(listener.queued_events(), 1);
}

#[test]
fn custom_java_backend_listener_is_explicitly_external() {
    let descriptor = JavaBackendListenerDescriptor::new(
        "com.example.CustomBackend",
        "jmeter-5.6.3",
        [("influxdbToken".to_owned(), "secret".to_owned())],
    )
    .expect("descriptor");
    assert_eq!(
        descriptor.unsupported_error(),
        BackendError::ExternalUnavailable {
            capability: "java.backend_listener".to_owned()
        }
    );
    let debug = format!("{descriptor:?}");
    assert!(!debug.contains("secret"));
}

#[test]
fn backend_snapshot_context_can_be_serialized_without_a_live_sender() {
    let mut snapshot = BackendMetricsSnapshot::default();
    let mut status = BackendStatusSnapshot {
        count: 2,
        min_millis: Some(100),
        max_millis: Some(250),
        average_millis: Some(175.0),
        ..BackendStatusSnapshot::default()
    };
    let p90 = jmeter_rs_report::BackendPercentile::from_percent(90.0).expect("percentile");
    status.percentiles.insert(p90, 250.0);
    snapshot.contexts.insert(
        "all".to_owned(),
        jmeter_rs_report::BackendContextSnapshot {
            ok: status.clone(),
            ko: BackendStatusSnapshot::default(),
            all: status,
            hit_count: 2,
            sent_bytes: 3,
            received_bytes: 20,
            error_count: 0,
        },
    );
    let config = GraphiteConfig::new("127.0.0.1", 2_003).expect("config");
    let lines = jmeter_rs_report::graphite_metric_lines(&config, &snapshot, 1_704_067_200_000)
        .expect("metric lines");
    assert!(lines.iter().any(|line| line.path == "jmeter.all.ok.pct90"));
}
