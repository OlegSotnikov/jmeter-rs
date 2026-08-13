// SPDX-License-Identifier: Apache-2.0
//! Deterministic loopback coverage for the bounded native TLS edge.

#![allow(
    clippy::expect_used,
    reason = "the fixture owns every bounded handle and assertions are explicit"
)]

use jmeter_rs_http::{CancellationToken, TlsConfig};
use jmeter_rs_http_native::{
    MAX_TLS_INPUT_BYTES, MAX_TLS_ROOT_CERTIFICATE_BYTES, MAX_TLS_ROOT_CERTIFICATES,
    NativeTlsConfig, NativeTlsStream, NativeTlsVersion, ServerNameKind, SniPolicy,
    TLS_EXPLICIT_RUSTLS_RING_CAPABILITY_ID, TlsDeadline, TlsErrorCode, TlsIo,
};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, generate_simple_self_signed,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Barrier};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const FIXTURE_TIMEOUT: Duration = Duration::from_secs(2);
const FIXTURE_IO_SLICE: Duration = Duration::from_millis(50);

#[test]
fn explicit_rustls_ring_identity_is_a_native_v2_subordinate() {
    assert_eq!(
        TLS_EXPLICIT_RUSTLS_RING_CAPABILITY_ID,
        "http.tls.explicit-rustls-ring/1"
    );
    assert_ne!(TLS_EXPLICIT_RUSTLS_RING_CAPABILITY_ID, "http.native/2");
}

#[derive(Debug)]
struct ServerObservation {
    sni: Option<String>,
    alpn: Option<Vec<u8>>,
    client_certificate_present: bool,
}

struct Fixture {
    address: SocketAddr,
    root_der: Vec<u8>,
    server: JoinHandle<Result<ServerObservation, String>>,
}

fn make_config(root_der: &[u8], version: Option<NativeTlsVersion>) -> NativeTlsConfig {
    let mut config = NativeTlsConfig::builder();
    if let Some(version) = version {
        config = config.versions(version, version);
    }
    config.add_root_der(root_der).expect("fixture root");
    config
}

#[test]
fn prepared_client_config_is_reused_across_builds_and_clones() {
    let certificate =
        generate_simple_self_signed(vec!["cache.test".to_owned()]).expect("cache certificate");
    let config = make_config(certificate.cert.der(), None);
    let clone = config.clone();

    let first = config.client_config().expect("first client config");
    let second = config
        .build_client_config()
        .expect("cached client config alias");
    let cloned = clone.client_config().expect("cloned client config");

    assert!(Arc::ptr_eq(&first, &second));
    assert!(Arc::ptr_eq(&first, &cloned));
}

#[test]
fn prepared_client_config_mutation_is_copy_on_write() {
    let first_certificate =
        generate_simple_self_signed(vec!["cache-first.test".to_owned()]).expect("first root");
    let second_certificate =
        generate_simple_self_signed(vec!["cache-second.test".to_owned()]).expect("second root");
    let mut config = make_config(first_certificate.cert.der(), None);
    let original = config.client_config().expect("original client config");

    let sibling = config.clone().sni_policy(SniPolicy::Disabled);
    let sibling_prepared = sibling.client_config().expect("mutated policy config");
    assert!(!Arc::ptr_eq(&original, &sibling_prepared));
    assert!(Arc::ptr_eq(
        &original,
        &config
            .client_config()
            .expect("sibling mutation leaves original")
    ));

    config
        .add_root_der(second_certificate.cert.der())
        .expect("mutated root config");
    let root_mutated = config.client_config().expect("mutated root client config");
    assert!(!Arc::ptr_eq(&original, &root_mutated));
}

#[test]
fn failed_client_config_preparation_recovers_after_mutation() {
    let mut config = NativeTlsConfig::default();
    let first_error = config
        .client_config()
        .expect_err("missing explicit root must fail");
    let cached_error = config
        .client_config()
        .expect_err("the deterministic preparation error is cached");
    assert_eq!(first_error, cached_error);

    let certificate =
        generate_simple_self_signed(vec!["recovery.test".to_owned()]).expect("recovery root");
    config
        .add_root_der(certificate.cert.der())
        .expect("recovery root mutation");
    let recovered = config
        .client_config()
        .expect("mutation invalidates cached error");
    assert!(Arc::ptr_eq(
        &recovered,
        &config
            .client_config()
            .expect("recovered config remains cached")
    ));
}

#[test]
fn concurrent_client_config_calls_share_one_prepared_arc() {
    const THREADS: usize = 16;

    let certificate = generate_simple_self_signed(vec!["concurrent-cache.test".to_owned()])
        .expect("concurrency certificate");
    let config = Arc::new(make_config(certificate.cert.der(), None));
    let barrier = Arc::new(Barrier::new(THREADS));
    let prepared = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(THREADS);
        for _ in 0..THREADS {
            let config = Arc::clone(&config);
            let barrier = Arc::clone(&barrier);
            handles.push(scope.spawn(move || {
                barrier.wait();
                config.client_config().expect("concurrent client config")
            }));
        }
        handles
            .into_iter()
            .map(|handle| handle.join().expect("client config worker"))
            .collect::<Vec<_>>()
    });

    let first = &prepared[0];
    assert!(
        prepared
            .iter()
            .all(|candidate| Arc::ptr_eq(first, candidate))
    );
}

#[test]
fn client_config_cache_is_transparent_to_equality_and_debug() {
    let certificate = generate_simple_self_signed(vec!["transparent-cache.test".to_owned()])
        .expect("transparency certificate");
    let config = make_config(certificate.cert.der(), None);
    let clone = config.clone();
    let debug_before = format!("{config:?}");

    assert_eq!(config, clone);
    config.client_config().expect("prepare config");
    assert_eq!(config, clone);
    assert_eq!(debug_before, format!("{config:?}"));
    assert_eq!(debug_before, format!("{clone:?}"));
}

fn start_fixture(subject_alt_names: &[&str], alpn: &[&[u8]]) -> Fixture {
    start_fixture_with_lifetime(subject_alt_names, alpn, false)
}

fn start_hold_fixture(subject_alt_names: &[&str], alpn: &[&[u8]]) -> Fixture {
    start_fixture_with_lifetime(subject_alt_names, alpn, true)
}

fn start_fixture_with_lifetime(
    subject_alt_names: &[&str],
    alpn: &[&[u8]],
    hold_open: bool,
) -> Fixture {
    let certified = generate_simple_self_signed(
        subject_alt_names
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>(),
    )
    .expect("fixture certificate");
    let root_der = certified.cert.der().to_vec();
    let certificate = CertificateDer::from(root_der.clone());
    let private_key = PrivateKeyDer::try_from(certified.signing_key.serialize_der())
        .expect("fixture private key");
    let versions = [&rustls::version::TLS13, &rustls::version::TLS12];
    let mut server_config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&versions)
            .expect("fixture versions")
            .with_no_client_auth()
            .with_single_cert(vec![certificate], private_key)
            .expect("fixture server certificate");
    server_config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("fixture listener");
    let address = listener.local_addr().expect("fixture address");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
        stream
            .set_read_timeout(Some(FIXTURE_IO_SLICE))
            .map_err(|error| error.to_string())?;
        stream
            .set_write_timeout(Some(FIXTURE_IO_SLICE))
            .map_err(|error| error.to_string())?;
        let mut connection = ServerConnection::new(Arc::new(server_config))
            .map_err(|error| format!("server connection: {error:?}"))?;
        drive_server(&mut connection, &mut stream)?;
        if hold_open {
            hold_server_connection(&mut stream)?;
        }
        Ok(ServerObservation {
            sni: connection.server_name().map(str::to_owned),
            alpn: connection.alpn_protocol().map(ToOwned::to_owned),
            client_certificate_present: connection.peer_certificates().is_some(),
        })
    });
    Fixture {
        address,
        root_der,
        server,
    }
}

struct MtlsClientMaterial {
    certificate_der: Vec<u8>,
    private_key_der: Vec<u8>,
    certificate_pem: Vec<u8>,
    private_key_pem: Vec<u8>,
}

fn start_mtls_fixture() -> (Fixture, MtlsClientMaterial) {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA parameters");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    ca_params.key_usages.push(KeyUsagePurpose::CrlSign);
    let ca_key = KeyPair::generate().expect("CA key");
    let ca_certificate = ca_params.self_signed(&ca_key).expect("CA certificate");
    let ca_der = ca_certificate.der().to_vec();
    let ca_issuer = Issuer::new(ca_params, ca_key);

    let mut server_params =
        CertificateParams::new(vec!["localhost".to_owned()]).expect("server parameters");
    server_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    server_params
        .key_usages
        .push(KeyUsagePurpose::DigitalSignature);
    let server_key = KeyPair::generate().expect("server key");
    let server_certificate = server_params
        .signed_by(&server_key, &ca_issuer)
        .expect("server certificate");
    let server_der = server_certificate.der().to_vec();
    let server_private_key =
        PrivateKeyDer::try_from(server_key.serialize_der()).expect("server private key");

    let mut client_params =
        CertificateParams::new(Vec::<String>::new()).expect("client parameters");
    client_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    client_params
        .key_usages
        .push(KeyUsagePurpose::DigitalSignature);
    let client_key = KeyPair::generate().expect("client key");
    let client_certificate = client_params
        .signed_by(&client_key, &ca_issuer)
        .expect("client certificate");
    let client_der = client_certificate.der().to_vec();
    let client_private_der = client_key.serialize_der();

    let mut client_roots = RootCertStore::empty();
    client_roots
        .add(CertificateDer::from(ca_der.clone()))
        .expect("client root");
    let client_verifier = WebPkiClientVerifier::builder_with_provider(
        Arc::new(client_roots),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()
    .expect("client verifier");
    let versions = [&rustls::version::TLS13, &rustls::version::TLS12];
    let mut server_config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&versions)
            .expect("fixture versions")
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(vec![CertificateDer::from(server_der)], server_private_key)
            .expect("fixture server certificate");
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("mTLS fixture listener");
    let address = listener.local_addr().expect("mTLS fixture address");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
        stream
            .set_read_timeout(Some(FIXTURE_IO_SLICE))
            .map_err(|error| error.to_string())?;
        stream
            .set_write_timeout(Some(FIXTURE_IO_SLICE))
            .map_err(|error| error.to_string())?;
        let mut connection = ServerConnection::new(Arc::new(server_config))
            .map_err(|error| format!("server connection: {error:?}"))?;
        drive_server(&mut connection, &mut stream)?;
        Ok(ServerObservation {
            sni: connection.server_name().map(str::to_owned),
            alpn: connection.alpn_protocol().map(ToOwned::to_owned),
            client_certificate_present: connection.peer_certificates().is_some(),
        })
    });

    let client_material = MtlsClientMaterial {
        certificate_pem: pem_encode("CERTIFICATE", &client_der),
        private_key_pem: pem_encode("PRIVATE KEY", &client_private_der),
        certificate_der: client_der,
        private_key_der: client_private_der,
    };
    (
        Fixture {
            address,
            root_der: ca_der,
            server,
        },
        client_material,
    )
}

fn drive_server(connection: &mut ServerConnection, stream: &mut TcpStream) -> Result<(), String> {
    let deadline = Instant::now() + FIXTURE_TIMEOUT;
    while connection.is_handshaking() {
        if Instant::now() >= deadline {
            return Err("fixture handshake deadline".to_owned());
        }
        if connection.wants_write() {
            stream
                .set_write_timeout(Some(FIXTURE_IO_SLICE))
                .map_err(|error| error.to_string())?;
            match connection.write_tls(stream) {
                Ok(0) => return Err("fixture wrote zero bytes".to_owned()),
                Ok(_) => {}
                Err(error) if is_retryable(&error) => continue,
                Err(error) => return Err(format!("fixture write: {error}")),
            }
        }
        if connection.wants_read() {
            stream
                .set_read_timeout(Some(FIXTURE_IO_SLICE))
                .map_err(|error| error.to_string())?;
            match connection.read_tls(stream) {
                Ok(0) => return Err("fixture peer eof".to_owned()),
                Ok(_) => match connection.process_new_packets() {
                    Ok(_) => {}
                    Err(error) => {
                        let detail = format!("fixture TLS: {error:?}");
                        while connection.wants_write() {
                            match connection.write_tls(stream) {
                                Ok(0) | Err(_) => break,
                                Ok(_) => {}
                            }
                        }
                        return Err(detail);
                    }
                },
                Err(error) if is_retryable(&error) => continue,
                Err(error) => return Err(format!("fixture read: {error}")),
            }
        }
    }
    while connection.wants_write() {
        stream
            .set_write_timeout(Some(FIXTURE_IO_SLICE))
            .map_err(|error| error.to_string())?;
        match connection.write_tls(stream) {
            Ok(0) => return Err("fixture wrote zero bytes".to_owned()),
            Ok(_) => {}
            Err(error) if is_retryable(&error) => {
                if Instant::now() >= deadline {
                    return Err("fixture final-write deadline".to_owned());
                }
            }
            Err(error) => return Err(format!("fixture final write: {error}")),
        }
    }
    Ok(())
}

fn hold_server_connection(stream: &mut TcpStream) -> Result<(), String> {
    let deadline = Instant::now() + FIXTURE_TIMEOUT;
    let mut buffer = [0_u8; 1];
    loop {
        if Instant::now() >= deadline {
            return Ok(());
        }
        match stream.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error) if is_retryable(&error) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::BrokenPipe
                        | io::ErrorKind::UnexpectedEof
                ) =>
            {
                return Ok(());
            }
            Err(error) => return Err(format!("fixture hold read: {error}")),
        }
    }
}

fn is_retryable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

struct ControlledTcpStream {
    stream: TcpStream,
    read_slice_started: Option<mpsc::Sender<()>>,
    write_slice_started: Option<mpsc::Sender<()>>,
    block_writes: Arc<AtomicBool>,
}

impl Read for ControlledTcpStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buffer)
    }
}

impl Write for ControlledTcpStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.block_writes.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "test write blocked",
            ));
        }
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl TlsIo for ControlledTcpStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        if let Some(channel) = &self.read_slice_started {
            let _ = channel.send(());
        }
        self.stream.set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        if let Some(channel) = &self.write_slice_started {
            let _ = channel.send(());
        }
        self.stream.set_write_timeout(timeout)
    }

    fn cancellation_waker(&self) -> io::Result<Box<dyn Fn() + Send + Sync + 'static>> {
        self.stream.cancellation_waker()
    }
}

fn pem_encode(label: &str, der: &[u8]) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = Vec::with_capacity(der.len().div_ceil(3) * 4);
    for chunk in der.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied();
        let third = chunk.get(2).copied();
        encoded.push(ALPHABET[usize::from(first >> 2)]);
        encoded.push(
            ALPHABET[usize::from(((first & 0x03) << 4) | second.map_or(0, |value| value >> 4))],
        );
        encoded.push(match second {
            Some(value) => {
                ALPHABET[usize::from(((value & 0x0f) << 2) | third.map_or(0, |item| item >> 6))]
            }
            None => b'=',
        });
        encoded.push(match third {
            Some(value) => ALPHABET[usize::from(value & 0x3f)],
            None => b'=',
        });
    }
    let mut pem = format!("-----BEGIN {label}-----\n").into_bytes();
    for line in encoded.chunks(64) {
        pem.extend_from_slice(line);
        pem.push(b'\n');
    }
    pem.extend_from_slice(format!("-----END {label}-----\n").as_bytes());
    pem
}

fn join_fixture(fixture: Fixture) -> ServerObservation {
    fixture
        .server
        .join()
        .expect("fixture thread")
        .expect("fixture handshake")
}

fn join_fixture_result(fixture: Fixture) -> Result<ServerObservation, String> {
    fixture.server.join().expect("fixture thread")
}

fn connect_fixture(
    fixture: Fixture,
    server_name: &str,
    config: &NativeTlsConfig,
    cancellation: &CancellationToken,
) -> (
    Result<jmeter_rs_http_native::TlsNegotiated, jmeter_rs_http_native::TlsError>,
    Fixture,
) {
    let stream = TcpStream::connect(fixture.address).expect("fixture connect");
    let result = NativeTlsStream::connect_with_timeout(
        stream,
        server_name,
        config,
        FIXTURE_TIMEOUT,
        cancellation,
    )
    .and_then(|stream| stream.negotiated());
    (result, fixture)
}

#[test]
fn tls12_and_tls13_use_the_requested_explicit_protocol() {
    for version in [NativeTlsVersion::Tls1_2, NativeTlsVersion::Tls1_3] {
        let fixture = start_fixture(&["localhost"], &[b"http/1.1"]);
        let config = make_config(&fixture.root_der, Some(version));
        let cancellation = CancellationToken::default();
        let (result, fixture) = connect_fixture(fixture, "localhost", &config, &cancellation);
        assert_eq!(result.expect("TLS handshake").protocol, version);
        let observation = join_fixture(fixture);
        assert_eq!(observation.alpn.as_deref(), Some(b"http/1.1".as_slice()));
    }
}

#[test]
fn explicit_root_sni_and_alpn_are_observable_without_peer_data_in_errors() {
    let fixture = start_fixture(&["localhost"], &[b"http/1.1"]);
    let config = make_config(&fixture.root_der, None);
    let cancellation = CancellationToken::default();
    let (result, fixture) = connect_fixture(fixture, "localhost", &config, &cancellation);
    let negotiated = result.expect("TLS handshake");
    assert_eq!(negotiated.server_name_kind, ServerNameKind::Dns);
    assert!(negotiated.sni_sent);
    assert!(negotiated.alpn_http11);
    let observation = join_fixture(fixture);
    assert_eq!(observation.sni.as_deref(), Some("localhost"));
    assert_eq!(observation.alpn.as_deref(), Some(b"http/1.1".as_slice()));

    let fixture = start_fixture(&["localhost"], &[b"http/1.1"]);
    let config = make_config(&fixture.root_der, None).sni_policy(SniPolicy::Disabled);
    let (result, fixture) = connect_fixture(fixture, "localhost", &config, &cancellation);
    assert!(!result.expect("TLS handshake").sni_sent);
    assert_eq!(join_fixture(fixture).sni, None);

    let fixture = start_fixture(&["localhost"], &[b"h2"]);
    let config = make_config(&fixture.root_der, None);
    let (result, fixture) = connect_fixture(fixture, "localhost", &config, &cancellation);
    assert_eq!(
        result.expect_err("non-HTTP/1.1 ALPN must fail").code(),
        TlsErrorCode::Alpn
    );
    let _server_result = join_fixture_result(fixture);
}

#[test]
fn client_certificate_der_completes_explicit_mtls() {
    let (fixture, client) = start_mtls_fixture();
    let mut config = NativeTlsConfig::builder();
    config
        .add_root_der(&fixture.root_der)
        .expect("mTLS trust root");
    let config = config
        .client_identity_der(&client.certificate_der, &client.private_key_der)
        .expect("mTLS client identity");
    let cancellation = CancellationToken::default();
    let (result, fixture) = connect_fixture(fixture, "localhost", &config, &cancellation);
    let negotiated = result.expect("mTLS handshake");
    assert_eq!(negotiated.server_name_kind, ServerNameKind::Dns);
    let observation = join_fixture(fixture);
    assert!(observation.client_certificate_present);
}

#[test]
fn client_certificate_and_root_pem_complete_explicit_mtls() {
    let (fixture, client) = start_mtls_fixture();
    let mut config = NativeTlsConfig::builder();
    let root_pem = pem_encode("CERTIFICATE", &fixture.root_der);
    config.add_root_pem(&root_pem).expect("PEM trust root");
    let config = config
        .client_identity_pem(&client.certificate_pem, &client.private_key_pem)
        .expect("PEM client identity");
    let cancellation = CancellationToken::default();
    let (result, fixture) = connect_fixture(fixture, "localhost", &config, &cancellation);
    result.expect("PEM mTLS handshake");
    assert!(join_fixture(fixture).client_certificate_present);
}

#[test]
fn bundled_root_additions_are_atomic_on_malformed_and_over_limit_items() {
    let first = generate_simple_self_signed(vec!["first.test".to_owned()]).expect("first root");
    let second = generate_simple_self_signed(vec!["second.test".to_owned()]).expect("second root");
    let mut malformed_chain = first.cert.der().to_vec();
    malformed_chain.extend_from_slice(&[0x30, 0x00]);
    let mut config = NativeTlsConfig::default();
    config.add_root_der(first.cert.der()).expect("initial root");
    assert_eq!(config.root_count(), 1);
    assert_eq!(
        config
            .add_root_der_chain(&malformed_chain)
            .expect_err("malformed second item")
            .code(),
        TlsErrorCode::MalformedCertificate
    );
    assert_eq!(config.root_count(), 1);

    let valid_pem = pem_encode("CERTIFICATE", second.cert.der());
    let mut malformed_pem = valid_pem.clone();
    malformed_pem
        .extend_from_slice(b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n");
    assert_eq!(
        config
            .add_root_pem(&malformed_pem)
            .expect_err("malformed PEM item")
            .code(),
        TlsErrorCode::MalformedCertificate
    );
    assert_eq!(config.root_count(), 1);

    let oversized_pem = pem_encode(
        "CERTIFICATE",
        &vec![0_u8; MAX_TLS_ROOT_CERTIFICATE_BYTES + 1],
    );
    assert_eq!(
        config
            .add_root_pem(&oversized_pem)
            .expect_err("over-limit PEM item")
            .code(),
        TlsErrorCode::InputLimit
    );
    assert_eq!(config.root_count(), 1);

    let mut count_limited = NativeTlsConfig::default();
    for _ in 0..(MAX_TLS_ROOT_CERTIFICATES - 1) {
        count_limited
            .add_root_der(first.cert.der())
            .expect("bounded root");
    }
    let mut two_roots = first.cert.der().to_vec();
    two_roots.extend_from_slice(second.cert.der());
    assert_eq!(
        count_limited
            .add_root_der_chain(&two_roots)
            .expect_err("root count overflow")
            .code(),
        TlsErrorCode::InputLimit
    );
    assert_eq!(count_limited.root_count(), MAX_TLS_ROOT_CERTIFICATES - 1);
}

#[test]
fn absolute_deadline_constructor_enforces_finite_bound() {
    assert!(TlsDeadline::at(Instant::now() + Duration::from_secs(1)).is_ok());
    assert_eq!(
        TlsDeadline::at(Instant::now() + Duration::from_secs(24 * 60 * 60 + 1))
            .expect_err("deadline over maximum")
            .code(),
        TlsErrorCode::InvalidConfig
    );
    assert!(TlsDeadline::at(Instant::now() - Duration::from_secs(1)).is_ok());
}

#[test]
fn ip_san_is_exact_and_does_not_send_ip_sni() {
    let fixture = start_fixture(&["127.0.0.1"], &[b"http/1.1"]);
    let config = make_config(&fixture.root_der, None);
    let cancellation = CancellationToken::default();
    let (result, fixture) = connect_fixture(fixture, "127.0.0.1", &config, &cancellation);
    let negotiated = result.expect("IP SAN handshake");
    assert_eq!(negotiated.server_name_kind, ServerNameKind::Ip);
    assert!(!negotiated.sni_sent);
    assert_eq!(join_fixture(fixture).sni, None);

    let fixture = start_fixture(&["127.0.0.1"], &[b"http/1.1"]);
    let config = make_config(&fixture.root_der, None);
    let (result, fixture) = connect_fixture(fixture, "127.0.0.2", &config, &cancellation);
    let error = result.expect_err("wrong IP SAN must fail");
    assert_eq!(error.code(), TlsErrorCode::Verification);
    assert!(!format!("{error:?}").contains("127.0.0.2"));
    let _server_result = join_fixture_result(fixture);
}

#[test]
fn wrong_root_and_wrong_dns_name_fail_closed() {
    let fixture = start_fixture(&["localhost"], &[b"http/1.1"]);
    let wrong_root = generate_simple_self_signed(vec!["wrong-root.test".to_owned()])
        .expect("wrong root fixture");
    let config = make_config(wrong_root.cert.der(), None);
    let cancellation = CancellationToken::default();
    let (result, fixture) = connect_fixture(fixture, "localhost", &config, &cancellation);
    let error = result.expect_err("wrong root must fail");
    assert_eq!(error.code(), TlsErrorCode::Verification);
    assert_eq!(error.phase(), jmeter_rs_http_native::TlsPhase::Handshake);
    let _server_result = join_fixture_result(fixture);

    let fixture = start_fixture(&["localhost"], &[b"http/1.1"]);
    let config = make_config(&fixture.root_der, None);
    let (result, fixture) = connect_fixture(fixture, "other.test", &config, &cancellation);
    let error = result.expect_err("wrong DNS name must fail");
    assert_eq!(error.code(), TlsErrorCode::Verification);
    assert!(!format!("{error}").contains("other.test"));
    let _server_result = join_fixture_result(fixture);
}

#[test]
fn malformed_and_over_limit_inputs_are_bounded() {
    let mut config = NativeTlsConfig::default();
    assert_eq!(
        config.add_root_der(&[]).expect_err("empty root").code(),
        TlsErrorCode::InputLimit
    );
    assert_eq!(
        config
            .add_root_der(&vec![0_u8; MAX_TLS_ROOT_CERTIFICATE_BYTES + 1])
            .expect_err("large root")
            .code(),
        TlsErrorCode::InputLimit
    );
    let valid_root =
        generate_simple_self_signed(vec!["root.test".to_owned()]).expect("valid root fixture");
    for _ in 0..MAX_TLS_ROOT_CERTIFICATES {
        config
            .add_root_der(valid_root.cert.der())
            .expect("bounded root entry");
    }
    assert_eq!(
        config
            .add_root_der(valid_root.cert.der())
            .expect_err("root count")
            .code(),
        TlsErrorCode::InputLimit
    );
    assert_eq!(
        NativeTlsConfig::default()
            .add_root_der(&[0x30, 0x00])
            .expect_err("malformed root")
            .code(),
        TlsErrorCode::MalformedCertificate
    );

    assert_eq!(
        NativeTlsConfig::default()
            .add_root_pem(&vec![b'x'; MAX_TLS_INPUT_BYTES + 1])
            .expect_err("large PEM")
            .code(),
        TlsErrorCode::InputLimit
    );
    assert_eq!(
        jmeter_rs_http_native::NativeClientIdentity::from_der([vec![1_u8]], &[1_u8])
            .expect_err("malformed certificate")
            .code(),
        TlsErrorCode::MalformedCertificate
    );
    assert_eq!(
        jmeter_rs_http_native::NativeClientIdentity::from_der(
            [valid_root.cert.der().to_vec()],
            &[1_u8],
        )
        .expect_err("malformed key")
        .code(),
        TlsErrorCode::MalformedKey
    );
}

#[test]
fn stalled_handshake_observes_deadline_and_pre_cancellation() {
    let (address, accepted, server) = start_stalled_server();
    let stream = TcpStream::connect(address).expect("stalled fixture connect");
    accepted
        .recv_timeout(FIXTURE_TIMEOUT)
        .expect("fixture accepted");
    let config = NativeTlsConfig::default();
    let cancellation = CancellationToken::default();
    let error = NativeTlsStream::connect_with_timeout(
        stream,
        "localhost",
        &config,
        Duration::from_millis(100),
        &cancellation,
    )
    .expect_err("missing roots should fail before handshake");
    assert_eq!(error.code(), TlsErrorCode::InvalidConfig);
    server.join().expect("stalled fixture thread");

    let (address, accepted, server) = start_stalled_server();
    let stream = TcpStream::connect(address).expect("stalled fixture connect");
    accepted
        .recv_timeout(FIXTURE_TIMEOUT)
        .expect("fixture accepted");
    let mut config = NativeTlsConfig::default();
    let root = generate_simple_self_signed(vec!["localhost".to_owned()]).expect("root fixture");
    config
        .add_root_der(root.cert.der())
        .expect("valid root fixture");
    let cancellation = CancellationToken::default();
    let error = NativeTlsStream::connect_with_timeout(
        stream,
        "localhost",
        &config,
        Duration::from_millis(100),
        &cancellation,
    )
    .expect_err("stalled handshake");
    assert_eq!(error.code(), TlsErrorCode::Timeout);
    server.join().expect("stalled fixture thread");

    let (address, accepted, server) = start_stalled_server();
    let stream = TcpStream::connect(address).expect("stalled fixture connect");
    accepted
        .recv_timeout(FIXTURE_TIMEOUT)
        .expect("fixture accepted");
    let mut config = NativeTlsConfig::default();
    let root = generate_simple_self_signed(vec!["localhost".to_owned()]).expect("root fixture");
    config
        .add_root_der(root.cert.der())
        .expect("valid root fixture");
    let cancellation = CancellationToken::default();
    cancellation.cancel();
    let error = NativeTlsStream::connect_with_timeout(
        stream,
        "localhost",
        &config,
        Duration::from_millis(100),
        &cancellation,
    )
    .expect_err("cancelled handshake");
    assert_eq!(error.code(), TlsErrorCode::Cancelled);
    server.join().expect("stalled fixture thread");
}

#[test]
fn plaintext_read_deadline_and_cancellation_are_observed() {
    let fixture = start_hold_fixture(&["localhost"], &[b"http/1.1"]);
    let config = make_config(&fixture.root_der, None);
    let stream = TcpStream::connect(fixture.address).expect("read fixture connect");
    let mut tls = NativeTlsStream::connect_with_timeout(
        ControlledTcpStream {
            stream,
            read_slice_started: None,
            write_slice_started: None,
            block_writes: Arc::new(AtomicBool::new(false)),
        },
        "localhost",
        &config,
        FIXTURE_TIMEOUT,
        &CancellationToken::default(),
    )
    .expect("read fixture handshake");
    let error = tls
        .read_with_timeout(
            &mut [0_u8; 1],
            Duration::from_millis(100),
            &CancellationToken::default(),
        )
        .expect_err("read deadline");
    assert_eq!(error.code(), TlsErrorCode::Timeout);
    assert_eq!(error.phase(), jmeter_rs_http_native::TlsPhase::Read);
    drop(tls);
    assert!(join_fixture(fixture).sni.is_some());

    let fixture = start_hold_fixture(&["localhost"], &[b"http/1.1"]);
    let config = make_config(&fixture.root_der, None);
    let stream = TcpStream::connect(fixture.address).expect("cancellation fixture connect");
    let cancellation = CancellationToken::default();
    let mut tls = NativeTlsStream::connect_with_timeout(
        ControlledTcpStream {
            stream,
            read_slice_started: None,
            write_slice_started: None,
            block_writes: Arc::new(AtomicBool::new(false)),
        },
        "localhost",
        &config,
        FIXTURE_TIMEOUT,
        &cancellation,
    )
    .expect("cancellation fixture handshake");
    let (started_tx, started_rx) = mpsc::channel();
    tls.get_mut().read_slice_started = Some(started_tx);
    let thread_cancellation = cancellation.clone();
    let reader = thread::spawn(move || {
        tls.read_plain(
            &mut [0_u8; 1],
            TlsDeadline::after(FIXTURE_TIMEOUT).expect("read deadline"),
            &thread_cancellation,
        )
    });
    started_rx
        .recv_timeout(FIXTURE_TIMEOUT)
        .expect("read entered bounded I/O");
    cancellation.cancel();
    let error = reader
        .join()
        .expect("read worker thread")
        .expect_err("cancelled read");
    assert_eq!(error.code(), TlsErrorCode::Cancelled);
    assert_eq!(error.phase(), jmeter_rs_http_native::TlsPhase::Read);
    assert!(join_fixture(fixture).sni.is_some());
}

#[test]
fn plaintext_write_deadline_and_cancellation_are_observed() {
    let fixture = start_hold_fixture(&["localhost"], &[b"http/1.1"]);
    let config = make_config(&fixture.root_der, None);
    let block_writes = Arc::new(AtomicBool::new(false));
    let stream = TcpStream::connect(fixture.address).expect("write fixture connect");
    let mut tls = NativeTlsStream::connect_with_timeout(
        ControlledTcpStream {
            stream,
            read_slice_started: None,
            write_slice_started: None,
            block_writes: Arc::clone(&block_writes),
        },
        "localhost",
        &config,
        FIXTURE_TIMEOUT,
        &CancellationToken::default(),
    )
    .expect("write fixture handshake");
    block_writes.store(true, Ordering::Release);
    let error = tls
        .write_all_with_timeout(
            b"blocked",
            Duration::from_millis(100),
            &CancellationToken::default(),
        )
        .expect_err("write deadline");
    assert_eq!(error.code(), TlsErrorCode::Timeout);
    assert_eq!(error.phase(), jmeter_rs_http_native::TlsPhase::Flush);
    drop(tls);
    assert!(join_fixture(fixture).sni.is_some());

    let fixture = start_hold_fixture(&["localhost"], &[b"http/1.1"]);
    let config = make_config(&fixture.root_der, None);
    let block_writes = Arc::new(AtomicBool::new(false));
    let stream = TcpStream::connect(fixture.address).expect("write cancellation connect");
    let cancellation = CancellationToken::default();
    let mut tls = NativeTlsStream::connect_with_timeout(
        ControlledTcpStream {
            stream,
            read_slice_started: None,
            write_slice_started: None,
            block_writes: Arc::clone(&block_writes),
        },
        "localhost",
        &config,
        FIXTURE_TIMEOUT,
        &cancellation,
    )
    .expect("write cancellation handshake");
    block_writes.store(true, Ordering::Release);
    let (started_tx, started_rx) = mpsc::channel();
    tls.get_mut().write_slice_started = Some(started_tx);
    let thread_cancellation = cancellation.clone();
    let writer = thread::spawn(move || {
        tls.write_all_plain(
            b"blocked",
            TlsDeadline::after(FIXTURE_TIMEOUT).expect("write deadline"),
            &thread_cancellation,
        )
    });
    started_rx
        .recv_timeout(FIXTURE_TIMEOUT)
        .expect("write entered bounded I/O");
    cancellation.cancel();
    let error = writer
        .join()
        .expect("write worker thread")
        .expect_err("cancelled write");
    assert_eq!(error.code(), TlsErrorCode::Cancelled);
    assert_eq!(error.phase(), jmeter_rs_http_native::TlsPhase::Flush);
    assert!(join_fixture(fixture).sni.is_some());
}

fn start_stalled_server() -> (SocketAddr, Receiver<()>, JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("stalled listener");
    let address = listener.local_addr().expect("stalled address");
    let (accepted_tx, accepted_rx) = mpsc::sync_channel(1);
    let server = thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let _ = accepted_tx.send(());
        let _ = stream.set_read_timeout(Some(FIXTURE_TIMEOUT));
        let mut buffer = [0_u8; 1];
        let deadline = Instant::now() + FIXTURE_TIMEOUT;
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(_) if Instant::now() >= deadline => break,
                Ok(_) => {}
                Err(error) if is_retryable(&error) && Instant::now() < deadline => {}
                Err(_) => break,
            }
        }
    });
    (address, accepted_rx, server)
}

#[test]
fn diagnostics_redact_certificate_bytes_and_private_keys() {
    const SECRET_SENTINEL: &str = "tls-private-key-secret-sentinel-7f2a";
    let config = NativeTlsConfig::default();
    let debug = format!("{config:?}");
    assert!(debug.contains("root_count"));
    assert!(!debug.contains("0xde"));
    let certificate = generate_simple_self_signed(vec!["redaction.test".to_owned()])
        .expect("redaction certificate");
    let error = jmeter_rs_http_native::NativeClientIdentity::from_der(
        [certificate.cert.der().to_vec()],
        SECRET_SENTINEL.as_bytes(),
    )
    .expect_err("sentinel is not a private key");
    assert_eq!(error.code(), TlsErrorCode::MalformedKey);
    assert!(!format!("{error:?}").contains(SECRET_SENTINEL));
    assert!(!error.to_string().contains(SECRET_SENTINEL));
    assert!(
        !error
            .into_transport_error()
            .to_string()
            .contains(SECRET_SENTINEL)
    );
    let certified =
        generate_simple_self_signed(vec!["redaction.test".to_owned()]).expect("redaction identity");
    let key_der = certified.signing_key.serialize_der();
    let identity = jmeter_rs_http_native::NativeClientIdentity::from_der(
        [certified.cert.der().to_vec()],
        &key_der,
    )
    .expect("valid redaction identity");
    let identity_debug = format!("{identity:?}");
    assert!(identity_debug.contains("private_key_bytes"));
    assert!(!identity_debug.contains("PRIVATE KEY"));
    let config_debug = format!("{:?}", NativeTlsConfig::default().client_identity(identity));
    assert!(!config_debug.contains("PRIVATE KEY"));
    assert!(!config_debug.contains(SECRET_SENTINEL));
    let error = TlsDeadline::after(Duration::ZERO).expect_err("zero deadline");
    assert_eq!(error.stable_code(), "tls.invalid-config");
    assert!(!format!("{error:?}").contains("certificate"));
    let transport = error.into_transport_error();
    assert_eq!(transport.adapter_code(), Some("tls.invalid-config"));
    assert!(transport.to_string().contains("tls.invalid-config"));
}

#[test]
fn core_platform_and_insecure_modes_are_explicitly_unsupported() {
    assert_eq!(
        NativeTlsConfig::from_core(&TlsConfig::with_platform_roots())
            .expect_err("platform roots")
            .code(),
        TlsErrorCode::Unsupported
    );
    assert_eq!(
        NativeTlsConfig::from_core(&TlsConfig::jmeter_compatibility())
            .expect_err("trust-all verification")
            .code(),
        TlsErrorCode::Unsupported
    );
    let invalid_versions = TlsConfig {
        minimum_version: jmeter_rs_http::TlsVersion::Tls1_3,
        maximum_version: jmeter_rs_http::TlsVersion::Tls1_2,
        ..TlsConfig::default()
    };
    assert_eq!(
        NativeTlsConfig::from_core(&invalid_versions)
            .expect_err("invalid version range")
            .code(),
        TlsErrorCode::InvalidConfig
    );
}
