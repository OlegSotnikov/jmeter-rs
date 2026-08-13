// SPDX-License-Identifier: Apache-2.0
//! Focused coverage for immutable native provider selection.

#![allow(
    clippy::expect_used,
    reason = "the tests use explicit bounded construction failures as assertions"
)]

use jmeter_rs_http::{
    CancellationToken, ClockReading, Deadline, DecompressionPolicy, DnsCache, HttpVersionPolicy,
    Request, RetryPolicy, Route, TimeoutConfig, TlsConfig, Transport, TransportContext,
    TransportError,
};
use jmeter_rs_http_native::{
    NativeHttpTransport, NativeTransport, NativeTransportLimits, NativeTransportV2,
    StaticDnsResolver,
};
use std::sync::Arc;
use std::time::Duration;

const TEST_DEADLINE: Duration = Duration::from_secs(2);

fn context() -> TransportContext {
    TransportContext {
        route: Route::Direct,
        timeouts: TimeoutConfig::default(),
        deadline: Some(Deadline::at(TEST_DEADLINE)),
        tls: TlsConfig::default(),
        http_version: HttpVersionPolicy::Http11Only,
        decompression: DecompressionPolicy::Disabled,
        retries: RetryPolicy::default(),
        dns: DnsCache::default(),
        attempt: 0,
        started_at: ClockReading::new(0, Duration::ZERO),
        cancellation: CancellationToken::default(),
    }
}

fn v2_without_tls() -> NativeHttpTransport {
    let resolver = StaticDnsResolver::new(8).expect("bounded static resolver");
    NativeTransportV2::with_defaults(Arc::new(resolver), None)
        .map(NativeHttpTransport::from)
        .expect("default V2 transport")
}

#[test]
fn constructors_and_conversions_preserve_exact_variant_and_identity() {
    let limits = NativeTransportLimits::default();
    let v1 = NativeHttpTransport::new_v1(limits).expect("default V1 transport");
    assert!(v1.is_v1());
    assert!(!v1.is_v2());
    assert_eq!(v1.capability_id(), "http.native/1");
    assert_eq!(v1.limits(), &limits);
    assert_eq!(v1.as_limits(), &limits);
    assert!(v1.as_v1().is_some());
    assert!(v1.as_v2().is_none());
    assert!(format!("{v1:?}").contains("V1"));

    let v2 = v2_without_tls();
    assert!(v2.is_v2());
    assert!(!v2.is_v1());
    assert_eq!(v2.capability_id(), "http.native/2");
    assert_eq!(v2.limits(), &limits);
    assert_eq!(v2.as_limits(), &limits);
    assert!(v2.as_v1().is_none());
    assert!(v2.as_v2().is_some());
    assert!(format!("{v2:?}").contains("V2"));

    let from_v1: NativeHttpTransport = NativeTransport::new(limits).expect("V1 transport").into();
    assert!(matches!(from_v1, NativeHttpTransport::V1(_)));

    let from_v2: NativeHttpTransport = v2_without_tls();
    assert!(matches!(from_v2, NativeHttpTransport::V2(_)));
}

#[test]
fn each_transport_method_delegates_to_the_selected_variant_without_fallback() {
    // V1 rejects HTTPS before opening a socket.  If this enum ever tried V2,
    // the V2-specific explicit-TLS error below would be observed instead.
    let request = Request::get("https://127.0.0.1/").expect("bounded HTTPS request");
    let mut v1_stream =
        NativeHttpTransport::from(NativeTransport::with_defaults().expect("default V1 transport"));
    let stream_error = v1_stream
        .send_stream(&request, &context())
        .expect_err("V1 must reject HTTPS during preflight");
    assert!(matches!(
        stream_error,
        TransportError::Unsupported(message) if message.contains("plain HTTP")
    ));

    let mut v1_control = v1_stream.clone();
    let control_error = v1_control
        .send_with_control(&request, &context())
        .expect_err("V1 control path must use V1 preflight");
    assert!(matches!(
        control_error,
        TransportError::Unsupported(message) if message.contains("plain HTTP")
    ));

    // V2 accepts HTTPS as a protocol but requires its explicitly configured
    // TLS capability.  It must not downgrade to V1's plain-HTTP rejection.
    let mut v2_stream = v2_without_tls();
    let stream_error = v2_stream
        .send_stream(&request, &context())
        .expect_err("V2 must require explicit TLS configuration");
    assert!(matches!(
        stream_error,
        TransportError::Unsupported(message) if message.contains("explicit TLS configuration")
    ));

    let mut v2_control = v2_stream.clone();
    let control_error = v2_control
        .send_with_control(&request, &context())
        .expect_err("V2 control path must use V2 preflight");
    assert!(matches!(
        control_error,
        TransportError::Unsupported(message) if message.contains("explicit TLS configuration")
    ));
}
