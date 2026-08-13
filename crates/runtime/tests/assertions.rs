// SPDX-License-Identifier: Apache-2.0
//! Deterministic integration coverage for native assertion components.

#![allow(
    clippy::expect_used,
    clippy::manual_noop_waker,
    reason = "assertion setup is entirely local and test failures should identify the fixture"
)]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use jmeter_rs_model::NodeId;
use jmeter_rs_results::{ByteCount, ElapsedTime, SampleData, SampleResult, WallTimestamp};
use jmeter_rs_runtime::{
    Assertion, AssertionLimits, Clock, ClockReading, ComponentError, ComponentFuture,
    ControlSignal, DurationAssertion, ExecutionContext, ExecutionPipeline, ExecutionReport,
    Md5HexAssertion, PatternMode, PipelineError, ResponseAssertion, ResponseField,
    ResponsePatternMode, RuntimeCapabilities, SampleContext, SamplePackage, Sampler, SamplerOutput,
    SizeAssertion, SizeComparison, SizeField, UnsupportedJsonAssertion, XPathAssertion,
    XPathOptions, XmlAssertion,
};

fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = Box::pin(future);
    loop {
        match Pin::new(&mut future).poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::hint::spin_loop(),
        }
    }
}

struct StaticSampler {
    result: SampleResult,
}

struct TwoPointClock {
    calls: AtomicU64,
}

impl TwoPointClock {
    fn new() -> Self {
        Self {
            calls: AtomicU64::new(0),
        }
    }
}

impl Clock for TwoPointClock {
    fn now(&self) -> ClockReading {
        let millis = if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            0
        } else {
            10
        };
        ClockReading {
            wall: WallTimestamp::from_millis(millis),
            monotonic: Duration::from_millis(millis as u64),
        }
    }
}

impl Sampler for StaticSampler {
    fn sample<'a>(
        &'a self,
        _context: &'a mut SampleContext<'_>,
    ) -> ComponentFuture<'a, SamplerOutput> {
        Box::pin(std::future::ready(Ok(SamplerOutput::result(
            self.result.clone(),
        ))))
    }
}

fn sample(response: &str) -> SampleResult {
    let mut result = SampleResult::new("assertion-sample");
    result.set_successful(true);
    result.set_response_data_bytes(SampleData::from(response));
    result.set_response_code_text("200");
    result.set_response_message_text("OK");
    result.set_response_headers_text("Content-Type: text/plain\r\n");
    result.set_request_headers_text("Accept: */*\r\n");
    result.set_url_text("https://example.invalid/path");
    result.set_received_bytes(Some(ByteCount::from_u64(response.len() as u64)));
    result
}

fn assertion_result(report: &ExecutionReport) -> &jmeter_rs_results::AssertionResult {
    report
        .result
        .as_ref()
        .and_then(|result| result.assertions().first())
        .expect("assertion result")
}

fn run<A>(assertion: A, result: SampleResult) -> Result<ExecutionReport, PipelineError>
where
    A: Assertion + 'static,
{
    let package = SamplePackage::new(NodeId::new(901), Arc::new(StaticSampler { result }))
        .with_assertions(vec![Arc::new(assertion)]);
    let capabilities = RuntimeCapabilities::default().with_clock(Arc::new(TwoPointClock::new()));
    let mut context = ExecutionContext::with_capabilities(capabilities);
    block_on(ExecutionPipeline::execute(&package, &mut context))
}

#[test]
fn response_fields_modes_or_not_and_messages_are_preserved() {
    let mut result = sample("alpha beta");

    let contains = ResponseAssertion::single(
        "contains",
        ResponseField::ResponseData,
        ResponsePatternMode::Contains,
        "alpha",
    );
    let report = run(contains, result.clone()).expect("contains succeeds");
    assert!(assertion_result(&report).outcome().is_success());

    let matches = ResponseAssertion::single(
        "matches",
        ResponseField::ResponseCode,
        ResponsePatternMode::Matches,
        r"20\d",
    );
    let report = run(matches, result.clone()).expect("matches succeeds");
    assert!(assertion_result(&report).outcome().is_success());

    let equals = ResponseAssertion::single(
        "equals",
        ResponseField::ResponseMessage,
        ResponsePatternMode::Equals,
        "OK",
    );
    let report = run(equals, result.clone()).expect("equals succeeds");
    assert!(assertion_result(&report).outcome().is_success());

    let substring = ResponseAssertion::single(
        "substring",
        ResponseField::ResponseHeaders,
        ResponsePatternMode::Substring,
        "Content-Type",
    );
    let report = run(substring, result.clone()).expect("substring succeeds");
    assert!(assertion_result(&report).outcome().is_success());

    let or = ResponseAssertion::new(
        "or",
        ResponseField::ResponseData,
        ResponsePatternMode::Substring,
        ["absent", "beta"],
    )
    .with_or(true);
    let report = run(or, result.clone()).expect("OR succeeds");
    assert!(assertion_result(&report).outcome().is_success());

    let not = ResponseAssertion::single(
        "not",
        ResponseField::ResponseData,
        ResponsePatternMode::Substring,
        "absent",
    )
    .with_negate(true);
    let report = run(not, result.clone()).expect("NOT succeeds");
    assert!(assertion_result(&report).outcome().is_success());

    let failing = ResponseAssertion::single(
        "named",
        ResponseField::ResponseData,
        ResponsePatternMode::Substring,
        "missing",
    )
    .with_custom_failure_message(Some("custom diagnostic".to_owned()));
    let report = run(failing, result.clone()).expect("failed assertion is data");
    let assertion = assertion_result(&report);
    assert_eq!(assertion.name(), "named");
    assert!(assertion.is_failure());
    assert!(!assertion.is_error());
    assert_eq!(assertion.failure_message(), Some("custom diagnostic"));
    assert!(!report.result.as_ref().expect("sample").is_successful());

    result.set_stop_thread(true);
    let report = run(
        ResponseAssertion::single(
            "stop-preserved",
            ResponseField::ResponseData,
            PatternMode::Substring,
            "alpha",
        ),
        result,
    )
    .expect("stop flag does not change assertion evaluation");
    assert_eq!(report.signal, ControlSignal::StopThread);
}

#[test]
fn response_wire_url_and_request_fields_are_decoded() {
    assert_eq!(
        ResponseField::from_wire("Assertion.sample_label"),
        ResponseField::Url
    );
    let result = sample("request body");
    let request = ResponseAssertion::single(
        "request",
        ResponseField::RequestHeaders,
        ResponsePatternMode::Substring,
        "Accept",
    );
    let report = run(request, result.clone()).expect("request headers succeed");
    assert!(assertion_result(&report).outcome().is_success());
    let url = ResponseAssertion::single(
        "url",
        ResponseField::from_wire("Assertion.sample_label"),
        ResponsePatternMode::Substring,
        "example.invalid",
    );
    let report = run(url, result).expect("URL succeeds");
    assert!(assertion_result(&report).outcome().is_success());
}

#[test]
fn duration_and_size_assertions_cover_boundary_operators() {
    let mut result = sample("abc");
    result
        .set_elapsed(Some(ElapsedTime::from_millis(10)))
        .expect("valid timing");
    let report = run(DurationAssertion::new("duration", 10), result.clone())
        .expect("duration equality passes");
    assert!(assertion_result(&report).outcome().is_success());
    let report = run(DurationAssertion::new("duration", 9), result.clone())
        .expect("duration failure is data");
    assert!(assertion_result(&report).is_failure());
    assert!(
        run(DurationAssertion::new("disabled", 0), result.clone())
            .expect("zero duration is disabled")
            .result
            .as_ref()
            .expect("sample")
            .assertions()[0]
            .outcome()
            .is_success()
    );
    assert!(
        run(
            DurationAssertion::from_wire("invalid", "nope"),
            result.clone()
        )
        .expect("invalid duration is an assertion error")
        .result
        .as_ref()
        .expect("sample")
        .assertions()[0]
            .is_error()
    );

    let header_size = result
        .response_headers()
        .expect("response headers")
        .as_str()
        .len() as i64;
    let fields = [
        (SizeField::ResponseBody, 3),
        (SizeField::ResponseHeaders, header_size),
        (SizeField::ResponseCode, 3),
        (SizeField::ResponseMessage, 2),
        (SizeField::Network, 3),
    ];
    for (field, expected) in fields {
        let assertion = SizeAssertion::new("size", field, SizeComparison::Equal, expected);
        let report = run(assertion, result.clone()).expect("size equality passes");
        assert!(assertion_result(&report).outcome().is_success());
    }

    for (comparison, expected) in [
        (SizeComparison::NotEqual, 2),
        (SizeComparison::Greater, 2),
        (SizeComparison::Less, 4),
        (SizeComparison::GreaterOrEqual, 3),
        (SizeComparison::LessOrEqual, 3),
    ] {
        let report = run(
            SizeAssertion::new("operator", SizeField::ResponseBody, comparison, expected),
            result.clone(),
        )
        .expect("size operator passes");
        assert!(assertion_result(&report).outcome().is_success());
    }

    let negative = SizeAssertion::from_wire("negative", "SizeAssertion.response_code", 1, "-1");
    let report = run(negative, result).expect("negative size is a failure");
    assert!(assertion_result(&report).is_failure());

    let invalid = SizeAssertion::from_wire(
        "invalid-size",
        "SizeAssertion.response_code",
        1,
        "not-a-number",
    );
    let report = run(invalid, sample("abc")).expect("invalid size is an assertion error");
    let assertion = assertion_result(&report);
    assert!(assertion.is_error());
    assert!(assertion.failure_message().is_some());
}

#[test]
fn md5_xml_xpath_and_json_capability_boundaries_are_explicit() {
    let mut digest_input = sample("abc");
    let digest = Md5HexAssertion::new("md5", "900150983CD24FB0D6963F7D28E17F72");
    let report = run(digest, digest_input.clone()).expect("MD5 passes case-insensitively");
    assert!(assertion_result(&report).outcome().is_success());

    let digest = Md5HexAssertion::new("md5", "00000000000000000000000000000000");
    let report = run(digest, digest_input.clone()).expect("MD5 mismatch is data");
    assert!(assertion_result(&report).is_failure());

    let xml = XmlAssertion::new("xml");
    digest_input
        .set_response_data_bytes(SampleData::from("<root><item id=\"x\">value</item></root>"));
    let report = run(xml, digest_input.clone()).expect("well-formed XML passes");
    assert!(assertion_result(&report).outcome().is_success());
    let xpath = XPathAssertion::new("xpath", "//item[@id='x']");
    let report = run(xpath, digest_input.clone()).expect("bounded XPath passes");
    assert!(assertion_result(&report).outcome().is_success());
    let count = XPathAssertion::new("count", "count(//item)=1");
    let report = run(count, digest_input.clone()).expect("bounded XPath count passes");
    assert!(assertion_result(&report).outcome().is_success());

    let mut invalid_xml = digest_input.clone();
    invalid_xml.set_response_data_bytes(SampleData::from("<root>"));
    let report = run(XmlAssertion::new("invalid-xml"), invalid_xml)
        .expect("invalid XML is an assertion failure");
    assert!(assertion_result(&report).is_failure());

    let mut dtd_xml = digest_input.clone();
    dtd_xml.set_response_data_bytes(SampleData::from("<!DOCTYPE root><root><item/></root>"));
    assert!(matches!(
        run(XmlAssertion::new("dtd-xml"), dtd_xml),
        Err(PipelineError::Assertion {
            source: ComponentError::Unsupported(_),
            ..
        })
    ));

    let unsupported_options = XPathAssertion::new("xpath", "/root").with_options(XPathOptions {
        namespace: true,
        ..XPathOptions::default()
    });
    assert!(matches!(
        run(unsupported_options, digest_input.clone()),
        Err(PipelineError::Assertion {
            source: ComponentError::Unsupported(_),
            ..
        })
    ));
    assert!(matches!(
        run(UnsupportedJsonAssertion::jmespath("jmespath"), digest_input),
        Err(PipelineError::Assertion {
            source: ComponentError::Unsupported(_),
            ..
        })
    ));
}

#[test]
fn assertion_inputs_and_diagnostics_are_bounded() {
    let response_limit = AssertionLimits::default().with_response_limit(2);
    let assertion = ResponseAssertion::single(
        "response-limit",
        ResponseField::ResponseData,
        ResponsePatternMode::Substring,
        "a",
    )
    .with_limits(response_limit);
    assert!(matches!(
        run(assertion, sample("abc")),
        Err(PipelineError::Assertion {
            source: ComponentError::ResourceLimit(_),
            ..
        })
    ));

    let pattern_limit = AssertionLimits::default().with_pattern_limit(1);
    let assertion = ResponseAssertion::new(
        "pattern-limit",
        ResponseField::ResponseData,
        ResponsePatternMode::Substring,
        ["a", "b"],
    )
    .with_limits(pattern_limit);
    assert!(matches!(
        run(assertion, sample("abc")),
        Err(PipelineError::Assertion {
            source: ComponentError::ResourceLimit(_),
            ..
        })
    ));

    let malformed = ResponseAssertion::single(
        "malformed",
        ResponseField::ResponseData,
        ResponsePatternMode::Contains,
        "[",
    );
    let report = run(malformed, sample("abc")).expect("malformed regex is assertion error data");
    assert!(assertion_result(&report).is_error());

    let unknown_field = ResponseAssertion::single(
        "unknown-field",
        ResponseField::from_wire("Assertion.unknown_field"),
        ResponsePatternMode::Contains,
        "anything",
    );
    assert!(matches!(
        run(unknown_field, sample("abc")),
        Err(PipelineError::Assertion {
            source: ComponentError::Unsupported(_),
            ..
        })
    ));

    let diagnostic_limit = AssertionLimits::default().with_diagnostic_limit(12);
    let bounded_message = ResponseAssertion::single(
        "bounded-message",
        ResponseField::ResponseData,
        ResponsePatternMode::Substring,
        "missing",
    )
    .with_custom_failure_message(Some("a diagnostic that is intentionally long".to_owned()))
    .with_limits(diagnostic_limit);
    let report = run(bounded_message, sample("abc")).expect("failure remains assertion data");
    assert!(
        assertion_result(&report)
            .failure_message()
            .is_some_and(|message| message.len() <= 12)
    );
}
