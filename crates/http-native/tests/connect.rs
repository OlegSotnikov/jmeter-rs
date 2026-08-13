// SPDX-License-Identifier: Apache-2.0
//! Focused loopback coverage for the single-attempt Mio connect edge.

#![allow(
    clippy::expect_used,
    reason = "the fixture owns every bounded handle and assertions are explicit"
)]
#![allow(
    clippy::panic,
    reason = "capability-aware loopback setup reports unsupported platforms"
)]

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Barrier};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use jmeter_rs_http::{
    CancellationToken, ClockReading, Deadline, DecompressionPolicy, DnsCache, HttpVersionPolicy,
    Request, RetryPolicy, Route, TimeoutConfig, TlsConfig, Transport, TransportContext,
    TransportError,
};
use jmeter_rs_http_native::NativeTransport;
use mio::{Events, Poll, Token, Waker};

const FIXTURE_TIMEOUT: Duration = Duration::from_secs(2);
const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";

struct LoopbackServer {
    address: SocketAddr,
    request_seen: Receiver<Vec<u8>>,
    release: Option<SyncSender<()>>,
    thread: Option<JoinHandle<io::Result<()>>>,
}

impl LoopbackServer {
    fn bind(address: SocketAddr) -> Self {
        let listener = TcpListener::bind(address).expect("loopback fixture listener");
        Self::from_listener(listener)
    }

    fn from_listener(listener: TcpListener) -> Self {
        let address = listener.local_addr().expect("loopback fixture address");
        let (request_seen, request_seen_rx) = mpsc::sync_channel(1);
        let (release, release_rx) = mpsc::sync_channel(1);
        let thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept()?;
            stream.set_read_timeout(Some(FIXTURE_TIMEOUT))?;
            stream.set_write_timeout(Some(FIXTURE_TIMEOUT))?;
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
                        "fixture request exceeded bound",
                    ));
                }
            }
            request_seen.send(request).map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "request observer closed")
            })?;
            release_rx
                .recv_timeout(FIXTURE_TIMEOUT)
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "response release timeout"))?;
            stream.write_all(RESPONSE)
        });
        Self {
            address,
            request_seen: request_seen_rx,
            release: Some(release),
            thread: Some(thread),
        }
    }

    fn release_response(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }

    fn join(mut self) -> io::Result<()> {
        self.release_response();
        wake_listener(self.address);
        self.thread
            .take()
            .expect("fixture thread handle")
            .join()
            .expect("fixture thread did not panic")
    }
}

impl Drop for LoopbackServer {
    fn drop(&mut self) {
        self.release_response();
        if let Some(thread) = self.thread.take() {
            // If no client reached `accept`, wake this exact loopback
            // listener before joining.  The temporary stream is immediately
            // shut down, so the fixture's bounded request read observes EOF
            // and exits without an unbounded destructor wait.
            wake_listener(self.address);
            let _ = thread.join();
        }
    }
}

fn wake_listener(address: SocketAddr) {
    if let Ok(stream) = std::net::TcpStream::connect_timeout(&address, FIXTURE_TIMEOUT) {
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }
}

fn context(cancellation: CancellationToken, deadline: Duration) -> TransportContext {
    TransportContext {
        route: Route::Direct,
        timeouts: TimeoutConfig::default(),
        deadline: Some(Deadline::at(deadline)),
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

fn request(address: SocketAddr) -> Request {
    Request::get(format!("http://{address}/connect-fixture")).expect("bounded fixture request")
}

#[test]
fn one_mio_connect_converts_to_blocking_stream_before_http_io() {
    let mut server = LoopbackServer::bind("127.0.0.1:0".parse().expect("IPv4 loopback"));
    let address = server.address;
    let cancellation = CancellationToken::default();
    let request = request(address);
    let (worker_done, worker_done_rx) = mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        let mut transport = NativeTransport::with_defaults().expect("native limits");
        let result = transport
            .send_stream(&request, &context(cancellation, FIXTURE_TIMEOUT))
            .and_then(|response| response.collect(1024));
        worker_done.send(result).expect("worker result observer");
    });

    let request_wire = server
        .request_seen
        .recv_timeout(FIXTURE_TIMEOUT)
        .expect("server observed request before response");
    assert!(request_wire.starts_with(b"GET /connect-fixture HTTP/1.1\r\n"));

    // The request channel is a deterministic barrier after the post-connect
    // write.  Release the response only after that barrier; a stream that was
    // not converted back to blocking mode reports WouldBlock here, while the
    // required conversion waits for this release and returns the response.
    server.release_response();
    let response = worker_done_rx
        .recv_timeout(FIXTURE_TIMEOUT)
        .expect("loopback worker result")
        .expect("loopback response");
    worker.join().expect("connect worker did not panic");
    assert_eq!(response.body(), b"hello");
    server.join().expect("fixture I/O");
}

#[test]
fn loopback_ipv6_is_capability_aware() {
    let listener = match TcpListener::bind("[::1]:0") {
        Ok(listener) => listener,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::AddrNotAvailable | io::ErrorKind::PermissionDenied
            ) =>
        {
            return;
        }
        Err(error) => panic!("IPv6 loopback capability probe failed: {error}"),
    };
    let mut server = LoopbackServer::from_listener(listener);
    server.release_response();
    let mut transport = NativeTransport::with_defaults().expect("native limits");
    let response = transport
        .send_stream(
            &request(server.address),
            &context(CancellationToken::default(), FIXTURE_TIMEOUT),
        )
        .expect("IPv6 direct response")
        .collect(1024)
        .expect("bounded IPv6 response");
    assert_eq!(response.body(), b"hello");
    server.join().expect("IPv6 fixture I/O");
}

#[test]
fn expired_connect_budget_is_observed_before_socket_creation() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
    let address = listener.local_addr().expect("listener address");
    let mut transport = NativeTransport::with_defaults().expect("native limits");
    let error = transport
        .send_stream(
            &request(address),
            &context(CancellationToken::default(), Duration::ZERO),
        )
        .expect_err("expired operation must not start connect");
    assert!(matches!(error, TransportError::Timeout(_)));
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener probe");
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    ));
}

#[test]
fn refused_loopback_connect_preserves_connect_error_category() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
    let address = listener.local_addr().expect("listener address");
    drop(listener);
    let mut transport = NativeTransport::with_defaults().expect("native limits");
    let error = transport
        .send_stream(
            &request(address),
            &context(CancellationToken::default(), FIXTURE_TIMEOUT),
        )
        .expect_err("closed loopback port must fail connect");
    assert!(matches!(error, TransportError::Connect(_)));
}

#[test]
fn cancellation_callback_wakes_one_poll_promptly() {
    const TEST_CANCEL_TOKEN: Token = Token(17);
    let mut poll = Poll::new().expect("Mio poll");
    let mut events = Events::with_capacity(2);
    let waker = Arc::new(Waker::new(poll.registry(), TEST_CANCEL_TOKEN).expect("Mio waker"));
    let cancellation = CancellationToken::default();
    let (callback_seen, callback_seen_rx) = mpsc::sync_channel(1);
    let callback_waker = Arc::clone(&waker);
    let registration = cancellation.register_waker(move || {
        let _ = callback_waker.wake();
        callback_seen.send(()).expect("callback observer");
    });
    assert!(registration.is_registered());

    let barrier = Arc::new(Barrier::new(2));
    let cancel_barrier = Arc::clone(&barrier);
    let cancel_token = cancellation.clone();
    let cancel_thread = thread::spawn(move || {
        cancel_barrier.wait();
        cancel_token.cancel();
    });
    barrier.wait();
    callback_seen_rx
        .recv_timeout(FIXTURE_TIMEOUT)
        .expect("cancellation callback was prompt");
    poll.poll(&mut events, Some(FIXTURE_TIMEOUT))
        .expect("Mio cancellation wake");
    assert!(
        events
            .iter()
            .any(|event| event.token() == TEST_CANCEL_TOKEN)
    );
    cancel_thread.join().expect("cancellation thread");
}
