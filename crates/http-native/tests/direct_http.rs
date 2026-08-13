// SPDX-License-Identifier: Apache-2.0
//! Deterministic loopback coverage for the materialized native capability.

#![allow(
    clippy::expect_used,
    reason = "the fixture owns every in-process handle and assertions are bounded"
)]
#![allow(
    clippy::panic,
    reason = "negative connection assertions must fail the deterministic test"
)]

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use jmeter_rs_http::{
    CancellationToken, ClockReading, Deadline, DecompressionPolicy, DnsCache, HttpVersionPolicy,
    Proxy, ProxyScheme, Request, ResponseBodyPresence, ResponsePresence, RetryPolicy, Route,
    TimeoutConfig, TlsConfig, Transport, TransportContext, TransportError,
};
use jmeter_rs_http_native::{CAPABILITY_ID, NativeTransport};

const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Fixture: direct\r\n\r\nhello";
const CHUNKED_RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
const CLOSE_DELIMITED_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nX-Fixture: close\r\n\r\nhello";
const HEAD_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
const NO_CONTENT_RESPONSE: &[u8] = b"HTTP/1.1 204\r\n\r\n";
const NOT_MODIFIED_RESPONSE: &[u8] = b"HTTP/1.1 304 Not Modified\r\n\r\n";
const EMPTY_CONTENT_LENGTH_RESPONSE: &[u8] = b"HTTP/1.1 200 \r\nContent-Length: 0\r\n\r\n";
const EMPTY_CHUNKED_RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
const EMPTY_CLOSE_DELIMITED_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n";
const ORDERED_INFORMATIONAL_RESPONSE: &[u8] = b"HTTP/1.1 100\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </asset>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
const IO_TIMEOUT: Duration = Duration::from_secs(2);

struct LoopbackFixture {
    address: SocketAddr,
    thread: Option<JoinHandle<io::Result<Vec<u8>>>>,
    response_ready: Option<Receiver<()>>,
}

impl LoopbackFixture {
    fn start(response: &'static [u8]) -> Self {
        Self::start_mode(response, false)
    }

    fn start_keep_alive(response: &'static [u8]) -> Self {
        Self::start_mode(response, true)
    }

    fn start_mode(response: &'static [u8], keep_alive: bool) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback listener");
        let address = listener.local_addr().expect("loopback address");
        let (response_ready, response_ready_rx) = mpsc::sync_channel(1);
        let thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept()?;
            stream.set_read_timeout(Some(IO_TIMEOUT))?;
            stream.set_write_timeout(Some(IO_TIMEOUT))?;
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.len() > 64 * 1024 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "request head exceeded fixture bound",
                    ));
                }
            }
            // A cleanup wake-up may be the only accepted connection when a
            // transport fails before opening its socket.  Treat the empty
            // request as an owned shutdown handshake, not as a response case.
            if request.is_empty() {
                return Ok(request);
            }
            stream.write_all(response)?;
            let _ = response_ready.send(());
            if keep_alive {
                // The client must stop at explicit framing and close its
                // exact socket. This read is a bounded synchronization point;
                // no wall-clock sleep is used.
                let mut client_close = [0_u8; 1];
                let _ = stream.read(&mut client_close)?;
            } else {
                stream.shutdown(Shutdown::Write)?;
            }
            Ok(request)
        });
        Self {
            address,
            thread: Some(thread),
            response_ready: Some(response_ready_rx),
        }
    }

    fn wait_response_sent(&mut self) -> io::Result<()> {
        let Some(response_ready) = self.response_ready.take() else {
            return Ok(());
        };
        response_ready
            .recv_timeout(IO_TIMEOUT)
            .map_err(|error| io::Error::new(io::ErrorKind::TimedOut, error.to_string()))
            .map(|_| ())
    }

    fn join(mut self) -> io::Result<Vec<u8>> {
        wake_listener(self.address);
        self.thread
            .take()
            .expect("loopback fixture join handle")
            .join()
            .expect("loopback fixture thread did not panic")
    }
}

impl Drop for LoopbackFixture {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            wake_listener(self.address);
            let _ = thread.join();
        }
    }
}

fn wake_listener(address: SocketAddr) {
    if let Ok(stream) = TcpStream::connect_timeout(&address, IO_TIMEOUT) {
        let _ = stream.shutdown(Shutdown::Both);
    }
}

fn context(cancellation: CancellationToken) -> TransportContext {
    TransportContext {
        route: Route::Direct,
        timeouts: TimeoutConfig::default(),
        deadline: Some(Deadline::at(IO_TIMEOUT)),
        tls: TlsConfig::default(),
        http_version: HttpVersionPolicy::Http11Only,
        decompression: DecompressionPolicy::Disabled,
        retries: RetryPolicy::default(),
        dns: DnsCache::default(),
        attempt: 0,
        started_at: ClockReading::new(0, Duration::ZERO),
        cancellation,
    }
}

fn local_request(address: SocketAddr, scheme: &str) -> Request {
    Request::get(format!("{scheme}://{address}/fixture?case=direct")).expect("bounded request")
}

fn assert_no_connection(listener: &TcpListener) {
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    match listener.accept() {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        Ok(_) => panic!("preflight opened a loopback connection"),
        Err(error) => panic!("unexpected listener error: {error}"),
    }
}

fn collect_loopback(
    response: &'static [u8],
    request: impl FnOnce(SocketAddr) -> Request,
) -> jmeter_rs_http::Response {
    let fixture = LoopbackFixture::start(response);
    let request = request(fixture.address);
    let mut transport = NativeTransport::with_defaults().expect("default native limits");
    let response = transport
        .send_stream(&request, &context(CancellationToken::default()))
        .expect("direct HTTP response")
        .collect(1024)
        .expect("bounded response collection");
    let _request_wire = fixture.join().expect("fixture I/O");
    response
}

#[test]
fn direct_plain_http11_success_projects_wire_observations() {
    assert_eq!(CAPABILITY_ID, "http.native/1");
    let fixture = LoopbackFixture::start(RESPONSE);
    let request = local_request(fixture.address, "http");
    let mut transport = NativeTransport::with_defaults().expect("default native limits");
    let response = transport
        .send_stream(&request, &context(CancellationToken::default()))
        .expect("direct HTTP response")
        .collect(1024)
        .expect("bounded response collection");
    let request_wire = fixture.join().expect("fixture I/O");

    assert!(request_wire.starts_with(b"GET /fixture?case=direct HTTP/1.1\r\n"));
    assert!(
        !request_wire
            .windows(b"Connection:".len())
            .any(|window| window.eq_ignore_ascii_case(b"Connection:"))
    );
    assert_eq!(response.status(), 200);
    assert_eq!(response.reason(), "OK");
    assert_eq!(response.body(), b"hello");
    assert_eq!(
        response.headers().values("x-fixture").collect::<Vec<_>>(),
        ["direct"]
    );
    assert_eq!(
        response.protocol(),
        Some(jmeter_rs_http::ProtocolVersion::Http11)
    );
    assert_eq!(
        response.framing(),
        Some(jmeter_rs_http::Framing::ContentLength)
    );
    assert_eq!(
        response.decompression().coding,
        Some(jmeter_rs_http::Compression::Identity)
    );
    assert_eq!(response.decompression().wire_bytes, Some(5));
    assert_eq!(response.decompression().decoded_bytes, Some(5));
}

#[test]
fn content_length_completes_on_keep_alive_without_waiting_for_eof() {
    let mut fixture = LoopbackFixture::start_keep_alive(RESPONSE);
    let request = local_request(fixture.address, "http");
    let mut transport = NativeTransport::with_defaults().expect("default native limits");
    let response = transport
        .send_stream(&request, &context(CancellationToken::default()))
        .expect("content-length response")
        .collect(1024)
        .expect("bounded response collection");
    fixture
        .wait_response_sent()
        .expect("fixture sent the complete response");
    let request_wire = fixture.join().expect("fixture I/O");

    assert_eq!(response.body(), b"hello");
    assert!(
        !request_wire
            .windows(b"Connection:".len())
            .any(|window| window.eq_ignore_ascii_case(b"Connection:"))
    );
}

#[test]
fn chunked_completes_on_keep_alive_without_waiting_for_eof() {
    let mut fixture = LoopbackFixture::start_keep_alive(CHUNKED_RESPONSE);
    let request = local_request(fixture.address, "http");
    let mut transport = NativeTransport::with_defaults().expect("default native limits");
    let response = transport
        .send_stream(&request, &context(CancellationToken::default()))
        .expect("chunked response")
        .collect(1024)
        .expect("bounded response collection");
    fixture
        .wait_response_sent()
        .expect("fixture sent the complete response");
    let _request_wire = fixture.join().expect("fixture I/O");

    assert_eq!(response.body(), b"hello");
    assert_eq!(response.framing(), Some(jmeter_rs_http::Framing::Chunked));
    assert_eq!(response.bytes().received_body, 5);
}

#[test]
fn close_delimited_completes_only_after_peer_eof() {
    let fixture = LoopbackFixture::start(CLOSE_DELIMITED_RESPONSE);
    let request = local_request(fixture.address, "http");
    let mut transport = NativeTransport::with_defaults().expect("default native limits");
    let response = transport
        .send_stream(&request, &context(CancellationToken::default()))
        .expect("close-delimited response")
        .collect(1024)
        .expect("bounded response collection");
    let _request_wire = fixture.join().expect("fixture I/O");

    assert_eq!(response.body(), b"hello");
    assert_eq!(
        response.framing(),
        Some(jmeter_rs_http::Framing::CloseDelimited)
    );
}

#[test]
fn source_connection_header_is_preserved_without_rewriting() {
    let mut fixture = LoopbackFixture::start_keep_alive(RESPONSE);
    let mut request = local_request(fixture.address, "http");
    request
        .add_header("Connection", "keep-alive")
        .expect("validated header");
    let mut transport = NativeTransport::with_defaults().expect("default native limits");
    let _response = transport
        .send_stream(&request, &context(CancellationToken::default()))
        .expect("explicit source connection policy is supported")
        .collect(1024)
        .expect("bounded response collection");
    fixture
        .wait_response_sent()
        .expect("fixture sent the complete response");
    let request_wire = fixture.join().expect("fixture I/O");

    assert!(
        request_wire
            .windows(b"Connection: keep-alive\r\n".len())
            .any(|window| { window.eq_ignore_ascii_case(b"Connection: keep-alive\r\n") })
    );
    assert!(
        !request_wire
            .windows(b"Connection: close\r\n".len())
            .any(|window| window.eq_ignore_ascii_case(b"Connection: close\r\n"))
    );
}

#[test]
fn unsupported_https_is_rejected_before_socket_side_effect() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback listener");
    let request = local_request(listener.local_addr().expect("listener address"), "https");
    let mut transport = NativeTransport::default();
    let error = transport
        .send_stream(&request, &context(CancellationToken::default()))
        .expect_err("TLS must fail closed");
    assert!(
        matches!(error, TransportError::Unsupported(message) if message.contains("plain HTTP"))
    );
    assert_no_connection(&listener);
}

#[test]
fn hostname_is_rejected_before_listener_or_resolver_side_effect() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback listener");
    let port = listener.local_addr().expect("listener address").port();
    let request = Request::get(format!("http://example.test:{port}/fixture"))
        .expect("bounded hostname request");
    let mut transport = NativeTransport::default();
    let error = transport
        .send_stream(&request, &context(CancellationToken::default()))
        .expect_err("hostnames are unavailable in bootstrap native/1");
    assert!(
        matches!(error, TransportError::Unsupported(message) if message.contains("numeric IP"))
    );
    assert_no_connection(&listener);
}

#[test]
fn cancellation_before_connect_makes_no_attempt() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback listener");
    let request = local_request(listener.local_addr().expect("listener address"), "http");
    let cancellation = CancellationToken::default();
    cancellation.cancel();

    let mut transport = NativeTransport::default();
    let error = transport
        .send_stream(&request, &context(cancellation))
        .expect_err("cancelled operation must stop before connect");
    assert!(matches!(error, TransportError::Cancelled));
    assert_no_connection(&listener);
}

#[test]
fn configured_proxy_is_rejected_before_socket_side_effect() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback listener");
    let address = listener.local_addr().expect("listener address");
    let request = local_request(address, "http");
    let proxy = Proxy::new(ProxyScheme::Http, "127.0.0.1", address.port()).expect("proxy");
    let mut operation = context(CancellationToken::default());
    operation.route = Route::Proxy(proxy);
    let mut transport = NativeTransport::default();
    let error = transport
        .send_stream(&request, &operation)
        .expect_err("proxy must fail closed");
    assert!(
        matches!(error, TransportError::Unsupported(message) if message.contains("proxy routes"))
    );
    assert_no_connection(&listener);
}

#[test]
fn unsupported_response_encoding_is_not_reported_as_identity() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 5\r\n\r\nhello";
    let fixture = LoopbackFixture::start(response);
    let request = local_request(fixture.address, "http");
    let mut transport = NativeTransport::default();
    let error = transport
        .send_stream(&request, &context(CancellationToken::default()))
        .expect_err("compressed input must fail closed");
    let _request_wire = fixture.join().expect("fixture I/O");
    assert!(
        matches!(error, TransportError::Unsupported(message) if message.contains("Content-Encoding"))
    );
}

#[test]
fn no_body_semantics_keep_head_204_and_304_absent() {
    let head = collect_loopback(HEAD_RESPONSE, |address| {
        Request::head(format!("http://{address}/head")).expect("HEAD request")
    });
    assert_eq!(head.body_presence(), ResponseBodyPresence::Absent);
    assert!(!head.body_present());
    assert_eq!(head.body(), b"");

    let no_content = collect_loopback(NO_CONTENT_RESPONSE, |address| {
        Request::get(format!("http://{address}/no-content")).expect("GET request")
    });
    assert_eq!(no_content.body_presence(), ResponseBodyPresence::Absent);
    assert!(matches!(
        no_content.reason_presence(),
        ResponsePresence::Absent
    ));

    let not_modified = collect_loopback(NOT_MODIFIED_RESPONSE, |address| {
        Request::get(format!("http://{address}/not-modified")).expect("GET request")
    });
    assert_eq!(not_modified.body_presence(), ResponseBodyPresence::Absent);
    assert!(not_modified.reason_present());
    assert!(not_modified.body().is_empty());
}

#[test]
fn ordinary_zero_length_framings_and_reason_presence_are_present_explicitly() {
    let content_length = collect_loopback(EMPTY_CONTENT_LENGTH_RESPONSE, |address| {
        Request::get(format!("http://{address}/content-length")).expect("GET request")
    });
    assert_eq!(
        content_length.body_presence(),
        ResponseBodyPresence::Present
    );
    assert!(content_length.body_present());
    assert!(matches!(
        content_length.reason_presence(),
        ResponsePresence::Present("")
    ));
    assert_eq!(
        content_length.framing(),
        Some(jmeter_rs_http::Framing::ContentLength)
    );

    let chunked = collect_loopback(EMPTY_CHUNKED_RESPONSE, |address| {
        Request::get(format!("http://{address}/chunked")).expect("GET request")
    });
    assert_eq!(chunked.body_presence(), ResponseBodyPresence::Present);
    assert!(chunked.body_present());
    assert_eq!(chunked.framing(), Some(jmeter_rs_http::Framing::Chunked));

    let close_delimited = collect_loopback(EMPTY_CLOSE_DELIMITED_RESPONSE, |address| {
        Request::get(format!("http://{address}/close")).expect("GET request")
    });
    assert_eq!(
        close_delimited.body_presence(),
        ResponseBodyPresence::Present
    );
    assert!(close_delimited.body_present());
    assert_eq!(
        close_delimited.framing(),
        Some(jmeter_rs_http::Framing::CloseDelimited)
    );
}

#[test]
fn informational_heads_are_ordered_and_retain_wire_presence() {
    let response = collect_loopback(ORDERED_INFORMATIONAL_RESPONSE, |address| {
        Request::get(format!("http://{address}/informational")).expect("GET request")
    });
    let informational = response.informational_responses();
    assert_eq!(
        informational
            .iter()
            .map(|head| head.status)
            .collect::<Vec<_>>(),
        [100, 103]
    );
    assert!(matches!(&informational[0].reason, ResponsePresence::Absent));
    assert!(matches!(
        &informational[1].reason,
        ResponsePresence::Present(reason) if reason == "Early Hints"
    ));
    assert_eq!(
        informational[1].headers.values("link").collect::<Vec<_>>(),
        ["</asset>; rel=preload"]
    );
    assert_eq!(
        informational[0].framing,
        Some(jmeter_rs_http::Framing::NoBody)
    );
    assert_eq!(response.body_presence(), ResponseBodyPresence::Present);
}
