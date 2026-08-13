// SPDX-License-Identifier: Apache-2.0
//! Deterministic coverage for the injected `http.native/2` transport.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "the loopback fixtures own bounded handles and assertions are explicit"
)]

use jmeter_rs_http::{
    CancellationToken, ClockReading, Deadline, DecompressionPolicy, DnsCache, HttpVersionPolicy,
    Request, ResponseBodyPresence, RetryPolicy, Route, TimeoutConfig, TlsConfig, Transport,
    TransportContext, TransportError,
};
use jmeter_rs_http_native::{
    CanonicalName, DnsFuture, DnsQuery, DnsResolver, NativeTlsConfig, NativeTransportLimits,
    NativeTransportV2, StaticDnsResolver,
};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection};
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const IO_TIMEOUT: Duration = Duration::from_secs(2);
const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-V2: yes\r\n\r\nok";
const EMPTY_RESPONSE: &[u8] = b"HTTP/1.1 200 \r\nContent-Length: 0\r\n\r\n";

struct Fixture {
    address: SocketAddr,
    join: Option<JoinHandle<Vec<u8>>>,
    ready: mpsc::Receiver<()>,
}

impl Fixture {
    fn start(response: &'static [u8]) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback listener");
        let address = listener.local_addr().expect("loopback address");
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let join = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("fixture accept");
            stream
                .set_read_timeout(Some(IO_TIMEOUT))
                .expect("fixture read timeout");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).expect("fixture request");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                assert!(request.len() <= 64 * 1024, "fixture request bound");
            }
            stream.write_all(response).expect("fixture response");
            let _ = ready_tx.send(());
            request
        });
        Self {
            address,
            join: Some(join),
            ready: ready_rx,
        }
    }

    fn join(mut self) -> Vec<u8> {
        self.ready
            .recv_timeout(IO_TIMEOUT)
            .expect("fixture response readiness");
        self.join
            .take()
            .expect("fixture join handle")
            .join()
            .expect("fixture thread")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            let _ = std::net::TcpStream::connect_timeout(&self.address, IO_TIMEOUT);
            let _ = join.join();
        }
    }
}

#[derive(Debug)]
struct HttpsObservation {
    sni: Option<String>,
    alpn: Option<Vec<u8>>,
    request: Vec<u8>,
}

struct HttpsFixture {
    address: SocketAddr,
    root_der: Vec<u8>,
    join: Option<JoinHandle<Result<HttpsObservation, String>>>,
}

impl HttpsFixture {
    fn start(subject_alt_names: &[&str], alpn: &[&[u8]]) -> Self {
        let certified = generate_simple_self_signed(
            subject_alt_names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>(),
        )
        .expect("HTTPS fixture certificate");
        let root_der = certified.cert.der().to_vec();
        let certificate = CertificateDer::from(root_der.clone());
        let private_key = PrivateKeyDer::try_from(certified.signing_key.serialize_der())
            .expect("HTTPS fixture private key");
        let versions = [&rustls::version::TLS13, &rustls::version::TLS12];
        let mut server_config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&versions)
                .expect("HTTPS fixture versions")
                .with_no_client_auth()
                .with_single_cert(vec![certificate], private_key)
                .expect("HTTPS fixture server certificate");
        server_config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("HTTPS fixture listener");
        let address = listener.local_addr().expect("HTTPS fixture address");
        let join = thread::spawn(move || {
            let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
            stream
                .set_read_timeout(Some(Duration::from_millis(50)))
                .map_err(|error| error.to_string())?;
            stream
                .set_write_timeout(Some(Duration::from_millis(50)))
                .map_err(|error| error.to_string())?;
            let mut connection = ServerConnection::new(Arc::new(server_config))
                .map_err(|error| format!("HTTPS fixture connection: {error:?}"))?;
            let request = drive_https_server(&mut connection, &mut stream)?;
            Ok(HttpsObservation {
                sni: connection.server_name().map(str::to_owned),
                alpn: connection.alpn_protocol().map(ToOwned::to_owned),
                request,
            })
        });
        Self {
            address,
            root_der,
            join: Some(join),
        }
    }

    fn join(mut self) -> Result<HttpsObservation, String> {
        self.join
            .take()
            .expect("HTTPS fixture join handle")
            .join()
            .expect("HTTPS fixture thread")
    }
}

impl Drop for HttpsFixture {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            let _ = std::net::TcpStream::connect_timeout(&self.address, IO_TIMEOUT);
            let _ = join.join();
        }
    }
}

fn drive_https_server(
    connection: &mut ServerConnection,
    stream: &mut std::net::TcpStream,
) -> Result<Vec<u8>, String> {
    let deadline = Instant::now() + IO_TIMEOUT;
    while connection.is_handshaking() {
        if Instant::now() >= deadline {
            return Err("HTTPS fixture handshake deadline".to_owned());
        }
        if connection.wants_write() {
            match connection.write_tls(stream) {
                Ok(0) => return Err("HTTPS fixture wrote zero bytes".to_owned()),
                Ok(_) => {}
                Err(error) if retryable_io(&error) => continue,
                Err(error) => return Err(format!("HTTPS fixture write: {error}")),
            }
        }
        if connection.wants_read() {
            match connection.read_tls(stream) {
                Ok(0) => return Err("HTTPS fixture peer EOF".to_owned()),
                Ok(_) => match connection.process_new_packets() {
                    Ok(_) => {}
                    Err(error) => {
                        let detail = format!("HTTPS fixture TLS: {error:?}");
                        while connection.wants_write() {
                            match connection.write_tls(stream) {
                                Ok(0) | Err(_) => break,
                                Ok(_) => {}
                            }
                        }
                        return Err(detail);
                    }
                },
                Err(error) if retryable_io(&error) => continue,
                Err(error) => return Err(format!("HTTPS fixture read: {error}")),
            }
        }
    }
    while connection.wants_write() {
        if Instant::now() >= deadline {
            return Err("HTTPS fixture final-write deadline".to_owned());
        }
        match connection.write_tls(stream) {
            Ok(0) => return Err("HTTPS fixture final write was empty".to_owned()),
            Ok(_) => {}
            Err(error) if retryable_io(&error) => {}
            Err(error) => return Err(format!("HTTPS fixture final write: {error}")),
        }
    }
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        if Instant::now() >= deadline {
            return Err("HTTPS fixture request deadline".to_owned());
        }
        if connection.wants_read() {
            match connection.read_tls(stream) {
                Ok(0) => return Err("HTTPS fixture peer EOF before request".to_owned()),
                Ok(_) => match connection.process_new_packets() {
                    Ok(_) => {}
                    Err(error) => {
                        let detail = format!("HTTPS fixture request TLS: {error:?}");
                        while connection.wants_write() {
                            match connection.write_tls(stream) {
                                Ok(0) | Err(_) => break,
                                Ok(_) => {}
                            }
                        }
                        return Err(detail);
                    }
                },
                Err(error) if retryable_io(&error) => continue,
                Err(error) => return Err(format!("HTTPS fixture request read: {error}")),
            }
        }
        match connection.reader().read(&mut buffer) {
            Ok(0) if !connection.wants_read() => {
                return Err("HTTPS fixture request EOF".to_owned());
            }
            Ok(0) => {}
            Ok(read) => {
                request.extend_from_slice(&buffer[..read]);
                if request.len() > 64 * 1024 {
                    return Err("HTTPS fixture request bound".to_owned());
                }
            }
            Err(error) if retryable_io(&error) => {}
            Err(error) => return Err(format!("HTTPS fixture plaintext read: {error}")),
        }
    }
    connection
        .writer()
        .write_all(RESPONSE)
        .map_err(|error| format!("HTTPS fixture response: {error}"))?;
    while connection.wants_write() {
        if Instant::now() >= deadline {
            return Err("HTTPS fixture response deadline".to_owned());
        }
        match connection.write_tls(stream) {
            Ok(0) => return Err("HTTPS fixture response wrote zero bytes".to_owned()),
            Ok(_) => {}
            Err(error) if retryable_io(&error) => {}
            Err(error) => return Err(format!("HTTPS fixture response write: {error}")),
        }
    }
    Ok(request)
}

fn retryable_io(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

fn tls_config(root_der: &[u8]) -> NativeTlsConfig {
    let mut config = NativeTlsConfig::builder();
    config
        .add_root_der(root_der)
        .expect("HTTPS fixture trust root");
    config
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

fn resolver_for(host: &str, addresses: impl IntoIterator<Item = IpAddr>) -> Arc<dyn DnsResolver> {
    let mut resolver = StaticDnsResolver::new(8).expect("resolver bound");
    resolver
        .insert(
            CanonicalName::parse(host).expect("canonical host"),
            addresses,
        )
        .expect("resolver record");
    Arc::new(resolver)
}

fn get_response(
    transport: &mut NativeTransportV2,
    request: Request,
    cancellation: CancellationToken,
) -> jmeter_rs_http::Response {
    transport
        .send_stream(&request, &context(cancellation))
        .expect("native v2 response")
        .collect(1024)
        .expect("bounded response collection")
}

#[test]
fn hostname_resolution_preserves_original_authority_and_host_header() {
    let fixture = Fixture::start(RESPONSE);
    let port = fixture.address.port();
    let resolver = resolver_for("fixture.test", [fixture.address.ip()]);
    let mut transport = NativeTransportV2::with_defaults(resolver, None).expect("v2 transport");
    let request =
        Request::get(format!("http://Fixture.TEST:{port}/v2?case=host")).expect("hostname request");
    let response = get_response(&mut transport, request, CancellationToken::default());
    assert_eq!(response.body(), b"ok");
    assert_eq!(response.status(), 200);
    let request_wire = fixture.join();
    let expected_host = format!("Host: Fixture.TEST:{port}");
    assert!(
        request_wire
            .windows(expected_host.len())
            .any(|window| window.eq_ignore_ascii_case(expected_host.as_bytes()))
    );
}

#[test]
fn numeric_host_bypasses_injected_dns() {
    struct CountingResolver(AtomicUsize);

    impl DnsResolver for CountingResolver {
        fn resolve(&self, _query: DnsQuery) -> DnsFuture<'static> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Box::pin(std::future::ready(Err(
                jmeter_rs_http_native::DnsError::new(jmeter_rs_http_native::DnsErrorCode::Provider),
            )))
        }
    }

    let fixture = Fixture::start(RESPONSE);
    let resolver = Arc::new(CountingResolver(AtomicUsize::new(0)));
    let resolver_for_assert = Arc::clone(&resolver);
    let mut transport = NativeTransportV2::with_defaults(resolver, None).expect("v2 transport");
    let request =
        Request::get(format!("http://{}/v2/numeric", fixture.address)).expect("numeric request");
    let response = get_response(&mut transport, request, CancellationToken::default());
    assert_eq!(response.body(), b"ok");
    assert_eq!(resolver_for_assert.0.load(Ordering::SeqCst), 0);
    let _ = fixture.join();
}

#[test]
fn resolver_first_address_is_selected_without_fallback() {
    let fixture = Fixture::start(RESPONSE);
    let resolver = resolver_for(
        "ordered.test",
        [
            fixture.address.ip(),
            IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 2)),
        ],
    );
    let mut transport = NativeTransportV2::with_defaults(resolver, None).expect("v2 transport");
    let request = Request::get(format!(
        "http://ordered.test:{}/ordered",
        fixture.address.port()
    ))
    .expect("ordered request");
    let response = get_response(&mut transport, request, CancellationToken::default());
    assert_eq!(response.body(), b"ok");
    let _ = fixture.join();
}

#[test]
fn dns_error_and_over_limit_responses_fail_before_connect() {
    let resolver = resolver_for("known.test", [IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]);
    let mut transport = NativeTransportV2::with_defaults(resolver, None).expect("v2 transport");
    let request = Request::get("http://missing.test/").expect("missing request");
    let error = transport
        .send_stream(&request, &context(CancellationToken::default()))
        .expect_err("missing DNS record");
    assert_eq!(error.code(), "http.transport.dns");
    assert!(matches!(error, TransportError::Dns(message) if message == "http.dns.nxdomain"));

    let resolver = resolver_for(
        "overlimit.test",
        [
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 2)),
        ],
    );
    let limits = NativeTransportLimits {
        max_dns_addresses: 1,
        ..NativeTransportLimits::default()
    };
    let mut transport = NativeTransportV2::new(limits, resolver, None).expect("bounded v2");
    let request = Request::get("http://overlimit.test/").expect("over-limit request");
    let error = transport
        .send_stream(&request, &context(CancellationToken::default()))
        .expect_err("DNS address bound");
    assert!(
        matches!(error, TransportError::ResourceLimit(message) if message == "DNS address records")
    );
}

#[test]
fn cancellation_wins_before_dns_and_expired_deadline_is_typed() {
    let resolver = resolver_for("fixture.test", [IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]);
    let mut transport =
        NativeTransportV2::with_defaults(Arc::clone(&resolver), None).expect("v2 transport");
    let cancellation = CancellationToken::default();
    cancellation.cancel();
    let request = Request::get("http://fixture.test/").expect("hostname request");
    assert!(matches!(
        transport.send_stream(&request, &context(cancellation)),
        Err(TransportError::Cancelled)
    ));

    let mut expired = context(CancellationToken::default());
    expired.deadline = Some(Deadline::at(Duration::ZERO));
    assert!(matches!(
        transport.send_stream(&request, &expired),
        Err(TransportError::Timeout(
            jmeter_rs_http::TimeoutPhase::Overall
        ))
    ));
}

#[test]
fn response_presence_is_retained_for_present_empty_entity() {
    let fixture = Fixture::start(EMPTY_RESPONSE);
    let resolver = resolver_for("empty.test", [fixture.address.ip()]);
    let mut transport = NativeTransportV2::with_defaults(resolver, None).expect("v2 transport");
    let request = Request::get(format!(
        "http://empty.test:{}/empty",
        fixture.address.port()
    ))
    .expect("empty request");
    let response = get_response(&mut transport, request, CancellationToken::default());
    assert_eq!(response.body_presence(), ResponseBodyPresence::Present);
    assert!(response.body_present());
    assert!(response.body().is_empty());
    let _ = fixture.join();
}

#[test]
fn https_uses_explicit_root_original_hostname_sni_and_http11_alpn() {
    let fixture = HttpsFixture::start(&["fixture.test"], &[b"http/1.1"]);
    let resolver = resolver_for("fixture.test", [fixture.address.ip()]);
    let tls = tls_config(&fixture.root_der);
    let mut transport = NativeTransportV2::with_defaults(resolver, Some(tls)).expect("v2 TLS");
    let port = fixture.address.port();
    let request =
        Request::get(format!("https://Fixture.TEST:{port}/tls")).expect("HTTPS hostname request");
    let response = get_response(&mut transport, request, CancellationToken::default());
    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"ok");
    let observation = fixture.join().expect("HTTPS fixture handshake");
    assert_eq!(observation.sni.as_deref(), Some("fixture.test"));
    assert_eq!(observation.alpn.as_deref(), Some(b"http/1.1".as_slice()));
    let expected_host = format!("Host: Fixture.TEST:{port}");
    assert!(
        observation
            .request
            .windows(expected_host.len())
            .any(|window| window.eq_ignore_ascii_case(expected_host.as_bytes()))
    );
}

#[test]
fn https_numeric_ip_uses_ip_san_without_sni() {
    let fixture = HttpsFixture::start(&["127.0.0.1"], &[b"http/1.1"]);
    let tls = tls_config(&fixture.root_der);
    let mut transport = NativeTransportV2::with_defaults(
        resolver_for("unused.test", [fixture.address.ip()]),
        Some(tls),
    )
    .expect("v2 IP TLS");
    let request = Request::get(format!("https://{}/ip", fixture.address)).expect("IP request");
    let response = get_response(&mut transport, request, CancellationToken::default());
    assert_eq!(response.body(), b"ok");
    let observation = fixture.join().expect("IP HTTPS fixture handshake");
    assert_eq!(observation.sni, None);
    assert_eq!(observation.alpn.as_deref(), Some(b"http/1.1".as_slice()));
}

#[test]
fn https_wrong_root_and_name_are_stable_verification_errors() {
    let fixture = HttpsFixture::start(&["fixture.test"], &[b"http/1.1"]);
    let wrong_root =
        generate_simple_self_signed(vec!["wrong-root.test".to_owned()]).expect("wrong root");
    let resolver = resolver_for("fixture.test", [fixture.address.ip()]);
    let tls = tls_config(wrong_root.cert.der());
    let mut transport = NativeTransportV2::with_defaults(resolver, Some(tls)).expect("v2 TLS");
    let request = Request::get(format!(
        "https://fixture.test:{}/wrong-root",
        fixture.address.port()
    ))
    .expect("wrong root request");
    let error = transport
        .send_stream(&request, &context(CancellationToken::default()))
        .expect_err("wrong root must fail");
    assert_eq!(error.adapter_code(), Some("tls.verification"));
    assert!(fixture.join().is_err());

    let fixture = HttpsFixture::start(&["fixture.test"], &[b"http/1.1"]);
    let resolver = resolver_for("wrong-name.test", [fixture.address.ip()]);
    let tls = tls_config(&fixture.root_der);
    let mut transport = NativeTransportV2::with_defaults(resolver, Some(tls)).expect("v2 TLS");
    let request = Request::get(format!(
        "https://wrong-name.test:{}/wrong-name",
        fixture.address.port()
    ))
    .expect("wrong name request");
    let error = transport
        .send_stream(&request, &context(CancellationToken::default()))
        .expect_err("wrong name must fail");
    assert_eq!(error.adapter_code(), Some("tls.verification"));
    assert!(fixture.join().is_err());
}

#[test]
fn https_rejects_non_http11_alpn() {
    let fixture = HttpsFixture::start(&["fixture.test"], &[b"h2"]);
    let resolver = resolver_for("fixture.test", [fixture.address.ip()]);
    let tls = tls_config(&fixture.root_der);
    let mut transport = NativeTransportV2::with_defaults(resolver, Some(tls)).expect("v2 TLS");
    let request = Request::get(format!(
        "https://fixture.test:{}/alpn",
        fixture.address.port()
    ))
    .expect("ALPN request");
    let error = transport
        .send_stream(&request, &context(CancellationToken::default()))
        .expect_err("non-HTTP/1.1 ALPN must fail");
    assert_eq!(error.adapter_code(), Some("tls.alpn"));
    assert!(fixture.join().is_err());
}
