// SPDX-License-Identifier: Apache-2.0
//! Bounded rustls client TLS for the independently named native HTTP/1.1 edge.
//!
//! This module is intentionally not part of [`crate::NativeTransport`].  The
//! plain HTTP provider is `http.native/1`; this module is the TLS groundwork
//! for the separately selected `http.native/2` provider.  Its subordinate
//! rustls policy identity is `http.tls.explicit-rustls-ring/1`; the enclosing
//! provider identity belongs to `transport_v2`.  This module owns no DNS,
//! sockets, files, platform trust stores, or process state.  Callers provide
//! an already-authorized stream and an explicit, finite operation deadline.
//!
//! The public configuration is deliberately narrower than rustls' full
//! surface: ring is the only cryptographic provider, TLS 1.2/1.3 are the only
//! protocol versions, ALPN is fixed to HTTP/1.1, and server verification uses
//! only roots supplied by the caller.  Trust-all, OS roots, JKS/PKCS12 and
//! platform certificate selection are not represented by this adapter.

use jmeter_rs_http::{
    CancellationRegistration, CancellationToken, TlsConfig as CoreTlsConfig,
    TlsTrustSource as CoreTlsTrustSource, TlsVerification as CoreTlsVerification,
    TlsVersion as CoreTlsVersion, TransportError,
};
use rustls::pki_types::pem::{PemObject, SectionKind};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, TcpStream};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

/// Canonical identity of the explicit rustls-with-ring TLS policy.
pub const TLS_EXPLICIT_RUSTLS_RING_CAPABILITY_ID: &str = "http.tls.explicit-rustls-ring/1";
/// The sole ALPN value advertised by this module.
pub const HTTP11_ALPN: &[u8] = b"http/1.1";

/// Maximum number of explicit trust roots in one configuration.
pub const MAX_TLS_ROOT_CERTIFICATES: usize = 128;
/// Maximum bytes in one encoded trust-root certificate.
pub const MAX_TLS_ROOT_CERTIFICATE_BYTES: usize = 1024 * 1024;
/// Maximum aggregate bytes in all explicit roots.
pub const MAX_TLS_ROOT_BYTES: usize = 16 * 1024 * 1024;
/// Maximum certificates in a client identity chain.
pub const MAX_TLS_CLIENT_CERTIFICATES: usize = 8;
/// Maximum bytes in one client certificate.
pub const MAX_TLS_CLIENT_CERTIFICATE_BYTES: usize = 1024 * 1024;
/// Maximum bytes in an encoded client private key.
pub const MAX_TLS_PRIVATE_KEY_BYTES: usize = 1024 * 1024;
/// Maximum aggregate bytes in a client certificate chain and key.
pub const MAX_TLS_CLIENT_IDENTITY_BYTES: usize = 4 * 1024 * 1024;
/// Maximum input accepted by a DER/PEM parser before decoding.
pub const MAX_TLS_INPUT_BYTES: usize = 16 * 1024 * 1024;
/// Maximum rustls plaintext/TLS scratch buffer retained by one connection.
pub const MAX_TLS_BUFFER_BYTES: usize = 64 * 1024;
/// Maximum application bytes accepted by one bounded write operation.
pub const MAX_TLS_APPLICATION_BYTES: usize = 16 * 1024 * 1024;
/// Maximum time accepted for one handshake/read/write operation.
pub const MAX_TLS_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
/// Upper bound for one blocking I/O slice, allowing cancellation to be
/// observed without an unbounded wait on a `TcpStream`.
const IO_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// TLS protocol versions exposed by the native adapter.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum NativeTlsVersion {
    /// TLS 1.2.
    Tls1_2,
    /// TLS 1.3.
    Tls1_3,
}

/// Compatibility alias for code that calls the setting a protocol version.
pub type TlsProtocolVersion = NativeTlsVersion;

/// Explicit policy for SNI transmission.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum SniPolicy {
    /// Send SNI for DNS names; IP literals never receive an SNI extension.
    #[default]
    DnsOnly,
    /// Do not send SNI, while still verifying the certificate against the
    /// exact DNS or IP `ServerName` supplied to rustls.
    Disabled,
}

/// The only ALPN policy implemented by this provider.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum AlpnPolicy {
    /// Offer and accept HTTP/1.1 only.
    #[default]
    Http11Only,
}

/// Whether the peer name is a DNS name or an IP literal.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ServerNameKind {
    /// DNS SAN verification and, when enabled, DNS SNI.
    Dns,
    /// IP SAN verification; rustls never sends IP literals in SNI.
    Ip,
}

/// Operation phases used by stable TLS errors.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TlsPhase {
    /// Configuration and certificate/key parsing.
    Config,
    /// Server-name conversion.
    ServerName,
    /// TLS handshake records.
    Handshake,
    /// Plaintext read.
    Read,
    /// Plaintext write.
    Write,
    /// Flushing encrypted records.
    Flush,
}

/// Stable, typed TLS failure categories.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TlsErrorCode {
    /// A configuration value was invalid or incomplete.
    InvalidConfig,
    /// A requested provider policy is intentionally unavailable.
    Unsupported,
    /// A finite input/count/buffer bound was exceeded.
    InputLimit,
    /// A certificate could not be parsed or added to the root store.
    MalformedCertificate,
    /// A private key could not be parsed or used.
    MalformedKey,
    /// The requested DNS name or IP literal was invalid.
    InvalidServerName,
    /// The peer certificate did not verify against the explicit roots.
    Verification,
    /// The peer selected an ALPN value outside the HTTP/1.1 policy.
    Alpn,
    /// The TLS state machine rejected the peer or stalled.
    Handshake,
    /// The underlying stream returned an I/O failure.
    Io,
    /// A finite deadline expired.
    Timeout,
    /// The explicit cancellation token was set.
    Cancelled,
    /// The peer closed the stream during a required operation.
    Eof,
}

impl TlsErrorCode {
    /// Stable dotted code used in diagnostics and transport adaptation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidConfig => "tls.invalid-config",
            Self::Unsupported => "tls.unsupported",
            Self::InputLimit => "tls.input-limit",
            Self::MalformedCertificate => "tls.malformed-certificate",
            Self::MalformedKey => "tls.malformed-key",
            Self::InvalidServerName => "tls.invalid-server-name",
            Self::Verification => "tls.verification",
            Self::Alpn => "tls.alpn",
            Self::Handshake => "tls.handshake",
            Self::Io => "tls.io",
            Self::Timeout => "tls.timeout",
            Self::Cancelled => "tls.cancelled",
            Self::Eof => "tls.eof",
        }
    }
}

impl fmt::Display for TlsErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A stable TLS error that intentionally stores no provider text, certificate
/// bytes, private-key bytes, path, or peer name.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct TlsError {
    code: TlsErrorCode,
    phase: TlsPhase,
    retryable: bool,
}

impl TlsError {
    const fn new(code: TlsErrorCode, phase: TlsPhase) -> Self {
        Self {
            code,
            phase,
            retryable: false,
        }
    }

    const fn retryable(code: TlsErrorCode, phase: TlsPhase) -> Self {
        Self {
            code,
            phase,
            retryable: true,
        }
    }

    /// Returns the stable category.
    #[must_use]
    pub const fn code(self) -> TlsErrorCode {
        self.code
    }

    /// Returns the operation phase.
    #[must_use]
    pub const fn phase(self) -> TlsPhase {
        self.phase
    }

    /// Returns whether the bounded I/O slice should be retried after checking
    /// the same deadline and cancellation token.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        self.retryable
    }

    /// Returns the stable dotted code.
    #[must_use]
    pub const fn stable_code(self) -> &'static str {
        self.code.as_str()
    }

    /// Adapts the failure to the pure HTTP transport error without retaining
    /// the rustls/OS provider detail.
    #[must_use]
    pub fn into_transport_error(self) -> TransportError {
        TransportError::adapter(self.stable_code(), "redacted TLS provider failure")
    }
}

impl fmt::Debug for TlsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsError")
            .field("code", &self.stable_code())
            .field("phase", &self.phase)
            .finish()
    }
}

impl fmt::Display for TlsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} ({:?})", self.stable_code(), self.phase)
    }
}

impl std::error::Error for TlsError {}

/// A finite monotonic deadline used for one handshake, read, write, or flush.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsDeadline {
    at: Instant,
}

impl TlsDeadline {
    /// Creates a deadline relative to the current monotonic instant.
    pub fn after(timeout: Duration) -> Result<Self, TlsError> {
        if timeout.is_zero() || timeout > MAX_TLS_TIMEOUT {
            return Err(TlsError::new(TlsErrorCode::InvalidConfig, TlsPhase::Config));
        }
        Instant::now()
            .checked_add(timeout)
            .map(|at| Self { at })
            .ok_or_else(|| TlsError::new(TlsErrorCode::InvalidConfig, TlsPhase::Config))
    }

    /// Creates a deadline from an existing monotonic instant.
    ///
    /// A past instant is retained as an already-expired deadline; operations
    /// report a timeout without entering I/O.  A future instant may not be
    /// farther away than [`MAX_TLS_TIMEOUT`].  Keeping this constructor
    /// checked prevents a caller from bypassing the finite timeout bound
    /// enforced by [`Self::after`].
    pub fn at(at: Instant) -> Result<Self, TlsError> {
        if at
            .checked_duration_since(Instant::now())
            .is_some_and(|remaining| remaining > MAX_TLS_TIMEOUT)
        {
            return Err(TlsError::new(TlsErrorCode::InvalidConfig, TlsPhase::Config));
        }
        Ok(Self { at })
    }

    /// Returns the absolute instant represented by this deadline.
    #[must_use]
    pub const fn instant(self) -> Instant {
        self.at
    }

    fn remaining(self) -> Option<Duration> {
        self.at.checked_duration_since(Instant::now())
    }
}

/// Stream capability required by [`NativeTlsStream`].
///
/// The timeout hooks are called before every bounded I/O slice.  `TcpStream`
/// implements them with its native socket deadlines.  Implementations must
/// provide an exact cancellation wake in addition to bounded read/write
/// timeout hooks; a failure to create that wake is a typed I/O error before a
/// blocking operation starts.  The standard TCP implementation shuts down an
/// exact cloned handle and never signals a process or process group.
pub trait TlsIo: Read + Write {
    /// Sets a bounded read timeout for the next blocking slice.
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;

    /// Sets a bounded write timeout for the next blocking slice.
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;

    /// Returns an exact-stream cancellation callback.
    ///
    /// Returning an error makes cancellation capability unavailable and
    /// causes the TLS operation to fail closed before entering I/O.
    fn cancellation_waker(&self) -> io::Result<Box<dyn Fn() + Send + Sync + 'static>>;
}

/// Transparent adapter for a stream that already implements [`TlsIo`].
///
/// An ordinary `Read + Write` value cannot be wrapped: the constructor and
/// accessors require an underlying [`TlsIo`] so timeout hooks and the exact
/// cancellation wake cannot silently become no-ops.  Test streams without
/// enforceable bounded I/O must implement their own explicit `TlsIo`
/// capability; this wrapper never claims unavailable controls are supported.
pub struct TlsIoAdapter<T>(T);

impl<T: TlsIo> TlsIoAdapter<T> {
    /// Wraps an in-process stream.
    #[must_use]
    pub const fn new(stream: T) -> Self {
        Self(stream)
    }

    /// Returns the wrapped stream.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }

    /// Borrows the wrapped stream.
    #[must_use]
    pub const fn get_ref(&self) -> &T {
        &self.0
    }

    /// Mutably borrows the wrapped stream.
    #[must_use]
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: TlsIo> Read for TlsIoAdapter<T> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.0.read(buffer)
    }
}

impl<T: TlsIo> Write for TlsIoAdapter<T> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl<T: TlsIo> TlsIo for TlsIoAdapter<T> {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.0.set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.0.set_write_timeout(timeout)
    }

    fn cancellation_waker(&self) -> io::Result<Box<dyn Fn() + Send + Sync + 'static>> {
        self.0.cancellation_waker()
    }
}

impl TlsIo for TcpStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_write_timeout(self, timeout)
    }

    fn cancellation_waker(&self) -> io::Result<Box<dyn Fn() + Send + Sync + 'static>> {
        let wake_stream = self.try_clone()?;
        Ok(Box::new(move || {
            let _ = wake_stream.shutdown(Shutdown::Both);
        }))
    }
}

/// A bounded client certificate chain and matching private key.
pub struct NativeClientIdentity {
    certificate_chain: Vec<Vec<u8>>,
    private_key: Arc<PrivateKeyDer<'static>>,
}

impl Clone for NativeClientIdentity {
    fn clone(&self) -> Self {
        Self {
            certificate_chain: self.certificate_chain.clone(),
            private_key: Arc::clone(&self.private_key),
        }
    }
}

impl PartialEq for NativeClientIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.certificate_chain == other.certificate_chain
            && self.private_key.secret_der() == other.private_key.secret_der()
    }
}

impl Eq for NativeClientIdentity {}

impl fmt::Debug for NativeClientIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeClientIdentity")
            .field("certificate_count", &self.certificate_chain.len())
            .field(
                "certificate_bytes",
                &self
                    .certificate_chain
                    .iter()
                    .map(Vec::len)
                    .try_fold(0usize, usize::checked_add),
            )
            .field("private_key_bytes", &self.private_key.secret_der().len())
            .finish()
    }
}

impl NativeClientIdentity {
    /// Creates an identity from one or more DER certificates and one DER
    /// PKCS#1, SEC1, or PKCS#8 private key.
    pub fn from_der<I, B>(certificates: I, private_key: &[u8]) -> Result<Self, TlsError>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        if private_key.is_empty() || private_key.len() > MAX_TLS_PRIVATE_KEY_BYTES {
            return Err(TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config));
        }
        let mut certificate_chain = Vec::new();
        let mut total = 0usize;
        for certificate in certificates {
            if certificate_chain.len() >= MAX_TLS_CLIENT_CERTIFICATES {
                return Err(TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config));
            }
            let certificate = certificate.as_ref();
            if certificate.is_empty() || certificate.len() > MAX_TLS_CLIENT_CERTIFICATE_BYTES {
                return Err(TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config));
            }
            total = total
                .checked_add(certificate.len())
                .ok_or_else(|| TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config))?;
            if total > MAX_TLS_CLIENT_IDENTITY_BYTES {
                return Err(TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config));
            }
            certificate_chain.push(certificate.to_vec());
        }
        validate_certificate_chain(&certificate_chain)?;
        Self::from_parts(certificate_chain, private_key_from_slice(private_key)?)
    }

    /// Creates an identity from a concatenated DER certificate chain and a
    /// DER private key.
    pub fn from_der_chain(certificate_chain: &[u8], private_key: &[u8]) -> Result<Self, TlsError> {
        if private_key.is_empty() || private_key.len() > MAX_TLS_PRIVATE_KEY_BYTES {
            return Err(TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config));
        }
        let certificates = split_der_items(
            certificate_chain,
            TlsErrorCode::MalformedCertificate,
            MAX_TLS_CLIENT_CERTIFICATES,
        )?;
        validate_certificate_chain(&certificates)?;
        Self::from_parts(certificates, private_key_from_slice(private_key)?)
    }

    /// Creates an identity from a PEM certificate chain and PEM private key.
    pub fn from_pem(certificate_chain: &[u8], private_key: &[u8]) -> Result<Self, TlsError> {
        let certificates = parse_pem_certificates(certificate_chain)?;
        validate_certificate_chain(&certificates)?;
        let key = parse_pem_private_key(private_key)?;
        Self::from_parts(certificates, key)
    }

    fn from_parts(
        certificate_chain: Vec<Vec<u8>>,
        private_key: PrivateKeyDer<'static>,
    ) -> Result<Self, TlsError> {
        validate_certificate_chain(&certificate_chain)?;
        if private_key.secret_der().is_empty()
            || private_key.secret_der().len() > MAX_TLS_PRIVATE_KEY_BYTES
        {
            return Err(TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config));
        }
        let certificate_bytes = certificate_chain
            .iter()
            .try_fold(0usize, |total, certificate| {
                total.checked_add(certificate.len())
            })
            .ok_or_else(|| TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config))?;
        let total = certificate_bytes
            .checked_add(private_key.secret_der().len())
            .ok_or_else(|| TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config))?;
        if total > MAX_TLS_CLIENT_IDENTITY_BYTES {
            return Err(TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config));
        }
        Ok(Self {
            certificate_chain,
            private_key: Arc::new(private_key),
        })
    }

    /// Returns the DER certificate chain.  The private key has no byte getter
    /// so callers cannot accidentally include it in diagnostics.
    #[must_use]
    pub fn certificate_chain(&self) -> &[Vec<u8>] {
        &self.certificate_chain
    }

    /// Returns the number of private-key bytes without exposing the key.
    #[must_use]
    pub fn private_key_bytes(&self) -> usize {
        self.private_key.secret_der().len()
    }
}

/// One immutable prepared rustls configuration shared by equivalent config
/// values.  The lock stores the result as well as the successful config: both
/// outcomes are deterministic for this explicit, input-only policy and
/// caching the error avoids repeatedly parsing the same malformed material.
/// A mutable builder operation replaces the owning [`Arc`] so a sibling clone
/// can never observe a cache invalidation or a prepared config for another
/// policy.
struct PreparedClientConfig {
    value: OnceLock<Result<Arc<ClientConfig>, TlsError>>,
}

impl PreparedClientConfig {
    fn new() -> Self {
        Self {
            value: OnceLock::new(),
        }
    }
}

/// Explicit native TLS configuration.  It contains no path, password,
/// platform-root selector, or insecure-verifier option.  The prepared rustls
/// configuration is an internal copy-on-write cache and is intentionally not
/// part of equality or debug output.
pub struct NativeTlsConfig {
    minimum_version: NativeTlsVersion,
    maximum_version: NativeTlsVersion,
    roots: Vec<Vec<u8>>,
    client_identity: Option<NativeClientIdentity>,
    sni_policy: SniPolicy,
    alpn_policy: AlpnPolicy,
    prepared: Arc<PreparedClientConfig>,
}

impl Clone for NativeTlsConfig {
    fn clone(&self) -> Self {
        Self {
            minimum_version: self.minimum_version,
            maximum_version: self.maximum_version,
            roots: self.roots.clone(),
            client_identity: self.client_identity.clone(),
            sni_policy: self.sni_policy,
            alpn_policy: self.alpn_policy,
            // Clones share both a lazy cache and an already prepared Arc.  A
            // subsequent builder mutation replaces only that clone's cache.
            prepared: Arc::clone(&self.prepared),
        }
    }
}

impl PartialEq for NativeTlsConfig {
    fn eq(&self, other: &Self) -> bool {
        self.minimum_version == other.minimum_version
            && self.maximum_version == other.maximum_version
            && self.roots == other.roots
            && self.client_identity == other.client_identity
            && self.sni_policy == other.sni_policy
            && self.alpn_policy == other.alpn_policy
    }
}

impl Eq for NativeTlsConfig {}

impl fmt::Debug for NativeTlsConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeTlsConfig")
            .field("minimum_version", &self.minimum_version)
            .field("maximum_version", &self.maximum_version)
            .field("root_count", &self.roots.len())
            .field("root_bytes", &self.root_bytes().ok())
            .field("client_identity", &self.client_identity)
            .field("sni_policy", &self.sni_policy)
            .field("alpn_policy", &self.alpn_policy)
            .finish()
    }
}

/// Builder alias retained for callers that prefer a separate construction
/// name; the value remains immutable after it is moved into a connection.
pub type NativeTlsConfigBuilder = NativeTlsConfig;

impl Default for NativeTlsConfig {
    fn default() -> Self {
        Self {
            minimum_version: NativeTlsVersion::Tls1_2,
            maximum_version: NativeTlsVersion::Tls1_3,
            roots: Vec::new(),
            client_identity: None,
            sni_policy: SniPolicy::DnsOnly,
            alpn_policy: AlpnPolicy::Http11Only,
            prepared: Arc::new(PreparedClientConfig::new()),
        }
    }
}

impl NativeTlsConfig {
    /// Starts an explicit configuration with TLS 1.2/1.3 and DNS-only SNI.
    #[must_use]
    pub fn builder() -> NativeTlsConfigBuilder {
        Self::default()
    }

    /// Sets the inclusive protocol-version range.
    #[must_use]
    pub fn versions(
        mut self,
        minimum_version: NativeTlsVersion,
        maximum_version: NativeTlsVersion,
    ) -> Self {
        self.minimum_version = minimum_version;
        self.maximum_version = maximum_version;
        self.invalidate_prepared();
        self
    }

    /// Sets the SNI policy.
    #[must_use]
    pub fn sni_policy(mut self, policy: SniPolicy) -> Self {
        self.sni_policy = policy;
        self.invalidate_prepared();
        self
    }

    /// Sets the ALPN policy.  Only [`AlpnPolicy::Http11Only`] is accepted.
    #[must_use]
    pub fn alpn_policy(mut self, policy: AlpnPolicy) -> Self {
        self.alpn_policy = policy;
        self.invalidate_prepared();
        self
    }

    /// Adds one DER trust root after applying the per-entry and aggregate
    /// bounds.  Parsing/semantic certificate validation occurs before config
    /// construction and never falls back to another root source.
    pub fn add_root_der(&mut self, root: &[u8]) -> Result<(), TlsError> {
        if root.is_empty() || root.len() > MAX_TLS_ROOT_CERTIFICATE_BYTES {
            return Err(TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config));
        }
        if self.roots.len() >= MAX_TLS_ROOT_CERTIFICATES {
            return Err(TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config));
        }
        let current = self.root_bytes()?;
        let proposed = current
            .checked_add(root.len())
            .ok_or_else(|| TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config))?;
        if proposed > MAX_TLS_ROOT_BYTES {
            return Err(TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config));
        }
        let mut root_store = RootCertStore::empty();
        root_store
            .add(CertificateDer::from(root.to_vec()))
            .map_err(|_| TlsError::new(TlsErrorCode::MalformedCertificate, TlsPhase::Config))?;
        self.roots.push(root.to_vec());
        self.invalidate_prepared();
        Ok(())
    }

    /// Adds every certificate in a concatenated DER chain as an explicit
    /// trust root.
    pub fn add_root_der_chain(&mut self, roots: &[u8]) -> Result<(), TlsError> {
        let roots = split_der_items(
            roots,
            TlsErrorCode::MalformedCertificate,
            MAX_TLS_ROOT_CERTIFICATES,
        )?;
        self.add_root_der_items(roots)
    }

    /// Adds every `CERTIFICATE` section in a bounded PEM bundle.
    pub fn add_root_pem(&mut self, roots: &[u8]) -> Result<(), TlsError> {
        self.add_root_der_items(parse_pem_certificates(roots)?)
    }

    /// Adds a validated client identity.
    #[must_use]
    pub fn client_identity(mut self, identity: NativeClientIdentity) -> Self {
        self.client_identity = Some(identity);
        self.invalidate_prepared();
        self
    }

    /// Adds a client identity from a DER chain and matching DER private key.
    pub fn client_identity_der(
        mut self,
        certificate_chain: &[u8],
        private_key: &[u8],
    ) -> Result<Self, TlsError> {
        self.client_identity = Some(NativeClientIdentity::from_der_chain(
            certificate_chain,
            private_key,
        )?);
        self.invalidate_prepared();
        Ok(self)
    }

    /// Adds a client identity from a PEM chain and matching PEM private key.
    pub fn client_identity_pem(
        mut self,
        certificate_chain: &[u8],
        private_key: &[u8],
    ) -> Result<Self, TlsError> {
        self.client_identity = Some(NativeClientIdentity::from_pem(
            certificate_chain,
            private_key,
        )?);
        self.invalidate_prepared();
        Ok(self)
    }

    /// Converts the pure-core TLS policy to the native typed adapter.
    ///
    /// Platform roots and insecure verification deliberately return typed
    /// unsupported errors.  This preserves the pure-core policy without
    /// silently making a security-sensitive choice in the native edge.
    pub fn from_core(config: &CoreTlsConfig) -> Result<Self, TlsError> {
        if config.trust_source != CoreTlsTrustSource::Explicit {
            return Err(TlsError::new(TlsErrorCode::Unsupported, TlsPhase::Config));
        }
        if config.verification != CoreTlsVerification::Verify {
            return Err(TlsError::new(TlsErrorCode::Unsupported, TlsPhase::Config));
        }
        if config.minimum_version > config.maximum_version {
            return Err(TlsError::new(TlsErrorCode::InvalidConfig, TlsPhase::Config));
        }
        let minimum_version = match config.minimum_version {
            CoreTlsVersion::Tls1_2 => NativeTlsVersion::Tls1_2,
            CoreTlsVersion::Tls1_3 => NativeTlsVersion::Tls1_3,
        };
        let maximum_version = match config.maximum_version {
            CoreTlsVersion::Tls1_2 => NativeTlsVersion::Tls1_2,
            CoreTlsVersion::Tls1_3 => NativeTlsVersion::Tls1_3,
        };
        let mut native = Self::default().versions(minimum_version, maximum_version);
        native.sni_policy = if config.use_sni {
            SniPolicy::DnsOnly
        } else {
            SniPolicy::Disabled
        };
        for root in &config.extra_roots {
            native.add_root_der_chain(root)?;
        }
        if let Some(identity) = &config.client_identity {
            native.client_identity = Some(NativeClientIdentity::from_der_chain(
                identity.certificate_chain(),
                identity.private_key(),
            )?);
        }
        Ok(native)
    }

    /// Alias for [`Self::from_core`].
    pub fn try_from_core(config: &CoreTlsConfig) -> Result<Self, TlsError> {
        Self::from_core(config)
    }

    /// Returns the configured protocol range.
    #[must_use]
    pub const fn versions_range(&self) -> (NativeTlsVersion, NativeTlsVersion) {
        (self.minimum_version, self.maximum_version)
    }

    /// Returns the explicit root count.
    #[must_use]
    pub const fn root_count(&self) -> usize {
        self.roots.len()
    }

    /// Returns the selected SNI policy.
    #[must_use]
    pub const fn sni(&self) -> SniPolicy {
        self.sni_policy
    }

    /// Returns the selected ALPN policy.
    #[must_use]
    pub const fn alpn(&self) -> AlpnPolicy {
        self.alpn_policy
    }

    /// Validates all finite policy and material bounds without building a
    /// rustls config.
    pub fn validate(&self) -> Result<(), TlsError> {
        if self.minimum_version > self.maximum_version {
            return Err(TlsError::new(TlsErrorCode::InvalidConfig, TlsPhase::Config));
        }
        if self.alpn_policy != AlpnPolicy::Http11Only {
            return Err(TlsError::new(TlsErrorCode::Unsupported, TlsPhase::Config));
        }
        if self.roots.len() > MAX_TLS_ROOT_CERTIFICATES || self.root_bytes()? > MAX_TLS_ROOT_BYTES {
            return Err(TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config));
        }
        if let Some(identity) = &self.client_identity {
            validate_certificate_chain(&identity.certificate_chain)?;
            if identity.private_key.secret_der().is_empty()
                || identity.private_key.secret_der().len() > MAX_TLS_PRIVATE_KEY_BYTES
            {
                return Err(TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config));
            }
            PrivateKeyDer::try_from(identity.private_key.secret_der())
                .map_err(|_| TlsError::new(TlsErrorCode::MalformedKey, TlsPhase::Config))?;
        }
        Ok(())
    }

    fn root_bytes(&self) -> Result<usize, TlsError> {
        self.roots
            .iter()
            .try_fold(0usize, |total, root| total.checked_add(root.len()))
            .ok_or_else(|| TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config))
    }

    fn add_root_der_items(&mut self, roots: Vec<Vec<u8>>) -> Result<(), TlsError> {
        let current_count = self.roots.len();
        let current_bytes = self.root_bytes()?;
        let proposed_count = current_count
            .checked_add(roots.len())
            .ok_or_else(|| TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config))?;
        if proposed_count > MAX_TLS_ROOT_CERTIFICATES {
            return Err(TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config));
        }

        let mut proposed_bytes = current_bytes;
        // Validate every item before changing `self`.  This is deliberately a
        // separate staging pass: a malformed or over-limit item cannot leave
        // an earlier root from the same DER/PEM bundle installed.
        for root in &roots {
            if root.is_empty() || root.len() > MAX_TLS_ROOT_CERTIFICATE_BYTES {
                return Err(TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config));
            }
            proposed_bytes = proposed_bytes
                .checked_add(root.len())
                .ok_or_else(|| TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config))?;
            if proposed_bytes > MAX_TLS_ROOT_BYTES {
                return Err(TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config));
            }
            let mut root_store = RootCertStore::empty();
            root_store
                .add(CertificateDer::from(root.clone()))
                .map_err(|_| TlsError::new(TlsErrorCode::MalformedCertificate, TlsPhase::Config))?;
        }
        self.roots.extend(roots);
        self.invalidate_prepared();
        Ok(())
    }

    fn invalidate_prepared(&mut self) {
        self.prepared = Arc::new(PreparedClientConfig::new());
    }

    /// Builds (or reuses) a rustls client config with the explicit ring
    /// provider.  The returned `Arc` is immutable and may be shared by every
    /// connection created from this unchanged policy.
    pub fn build_client_config(&self) -> Result<Arc<ClientConfig>, TlsError> {
        self.client_config()
    }

    fn build_client_config_uncached(&self) -> Result<Arc<ClientConfig>, TlsError> {
        self.validate()?;
        if self.roots.is_empty() {
            return Err(TlsError::new(TlsErrorCode::InvalidConfig, TlsPhase::Config));
        }
        let mut root_store = RootCertStore::empty();
        for root in &self.roots {
            root_store
                .add(CertificateDer::from(root.clone()))
                .map_err(|_| TlsError::new(TlsErrorCode::MalformedCertificate, TlsPhase::Config))?;
        }
        if root_store.is_empty() {
            return Err(TlsError::new(
                TlsErrorCode::MalformedCertificate,
                TlsPhase::Config,
            ));
        }
        let versions = match (self.minimum_version, self.maximum_version) {
            (NativeTlsVersion::Tls1_2, NativeTlsVersion::Tls1_2) => {
                vec![&rustls::version::TLS12]
            }
            (NativeTlsVersion::Tls1_3, NativeTlsVersion::Tls1_3) => {
                vec![&rustls::version::TLS13]
            }
            (NativeTlsVersion::Tls1_2, NativeTlsVersion::Tls1_3) => {
                vec![&rustls::version::TLS13, &rustls::version::TLS12]
            }
            (NativeTlsVersion::Tls1_3, NativeTlsVersion::Tls1_2) => {
                return Err(TlsError::new(TlsErrorCode::InvalidConfig, TlsPhase::Config));
            }
        };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&versions)
            .map_err(|_| TlsError::new(TlsErrorCode::Unsupported, TlsPhase::Config))?
            .with_root_certificates(root_store);
        let mut config = if let Some(identity) = &self.client_identity {
            let certificates = identity
                .certificate_chain
                .iter()
                .cloned()
                .map(CertificateDer::from)
                .collect::<Vec<_>>();
            // rustls takes ownership of its own provider key.  The
            // application-owned key remains in `NativeClientIdentity` while
            // any application config/identity clone is alive; the returned
            // cached `ClientConfig` may retain a provider-owned signer copy
            // until the cache and every returned config Arc are dropped.
            // There is no portable API to force that residual provider
            // lifetime earlier.
            let private_key = identity.private_key.as_ref().clone_key();
            builder
                .with_client_auth_cert(certificates, private_key)
                .map_err(|_| TlsError::new(TlsErrorCode::MalformedKey, TlsPhase::Config))?
        } else {
            builder.with_no_client_auth()
        };
        config.alpn_protocols = vec![HTTP11_ALPN.to_vec()];
        config.enable_sni = self.sni_policy != SniPolicy::Disabled;
        config.resumption = rustls::client::Resumption::disabled();
        config.max_fragment_size = Some(MAX_TLS_BUFFER_BYTES / 4);
        Ok(Arc::new(config))
    }

    /// Returns the immutable prepared rustls configuration for this policy.
    ///
    /// The first caller validates and parses the explicit roots and optional
    /// client identity.  Concurrent callers, subsequent connections, and
    /// clones of this unchanged config receive the same `Arc`; deterministic
    /// preparation errors are cached until a builder mutation invalidates this
    /// value's cache.
    pub fn client_config(&self) -> Result<Arc<ClientConfig>, TlsError> {
        self.prepared
            .value
            .get_or_init(|| self.build_client_config_uncached())
            .clone()
    }
}

impl TryFrom<&CoreTlsConfig> for NativeTlsConfig {
    type Error = TlsError;

    fn try_from(config: &CoreTlsConfig) -> Result<Self, Self::Error> {
        Self::from_core(config)
    }
}

/// Negotiated, non-secret TLS observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsNegotiated {
    /// DNS or IP interpretation of the requested server name.
    pub server_name_kind: ServerNameKind,
    /// Whether SNI was enabled for this connection.
    pub sni_sent: bool,
    /// Negotiated TLS protocol version.
    pub protocol: NativeTlsVersion,
    /// HTTP/1.1 ALPN when the peer selected it; `None` means no ALPN was
    /// selected by a legacy HTTP/1.1 peer.
    pub alpn_http11: bool,
}

/// A synchronous, bounded rustls client stream.
pub struct NativeTlsStream<S: TlsIo> {
    connection: ClientConnection,
    io: S,
    server_name_kind: ServerNameKind,
    sni_sent: bool,
}

/// Common short name for the native TLS stream.
pub type TlsStream<S> = NativeTlsStream<S>;

impl<S: TlsIo> fmt::Debug for NativeTlsStream<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeTlsStream")
            .field("handshaking", &self.connection.is_handshaking())
            .field("server_name_kind", &self.server_name_kind)
            .field("sni_sent", &self.sni_sent)
            .field(
                "alpn",
                &self
                    .connection
                    .alpn_protocol()
                    .map(|value| value == HTTP11_ALPN),
            )
            .finish()
    }
}

impl<S: TlsIo> NativeTlsStream<S> {
    /// Creates and completes one TLS client handshake with a finite deadline.
    pub fn connect(
        io: S,
        server_name: &str,
        config: &NativeTlsConfig,
        deadline: TlsDeadline,
        cancellation: &CancellationToken,
    ) -> Result<Self, TlsError> {
        let client_config = config.client_config()?;
        let (name, kind) = make_server_name(server_name)?;
        let sni_sent = config.sni_policy == SniPolicy::DnsOnly && kind == ServerNameKind::Dns;
        let mut connection = ClientConnection::new(client_config, name)
            .map_err(|error| map_rustls_error(error, TlsPhase::Handshake))?;
        connection.set_buffer_limit(Some(MAX_TLS_BUFFER_BYTES));
        let mut stream = Self {
            connection,
            io,
            server_name_kind: kind,
            sni_sent,
        };
        stream.handshake(deadline, cancellation)?;
        Ok(stream)
    }

    /// Convenience constructor that creates a finite deadline from a
    /// duration.
    pub fn connect_with_timeout(
        io: S,
        server_name: &str,
        config: &NativeTlsConfig,
        timeout: Duration,
        cancellation: &CancellationToken,
    ) -> Result<Self, TlsError> {
        Self::connect(
            io,
            server_name,
            config,
            TlsDeadline::after(timeout)?,
            cancellation,
        )
    }

    /// Completes a handshake on a stream constructed by a caller.
    pub fn handshake(
        &mut self,
        deadline: TlsDeadline,
        cancellation: &CancellationToken,
    ) -> Result<(), TlsError> {
        let _registration = self.register_cancellation(cancellation, TlsPhase::Handshake)?;
        while self.connection.is_handshaking() {
            let remaining = check_controls(deadline, cancellation, TlsPhase::Handshake)?;
            if self.connection.wants_write() {
                match self.write_tls_slice(remaining, deadline, cancellation, TlsPhase::Handshake) {
                    Ok(()) => {}
                    Err(error) if error.is_retryable() => continue,
                    Err(error) => return Err(error),
                }
            }
            if self.connection.wants_read() {
                match self.read_tls_slice(remaining, deadline, cancellation, TlsPhase::Handshake) {
                    Ok(()) => {
                        self.connection
                            .process_new_packets()
                            .map_err(|error| map_rustls_error(error, TlsPhase::Handshake))?;
                    }
                    Err(error) if error.is_retryable() => {
                        // A socket timeout is represented as a retryable
                        // internal marker by `read_tls_slice`; all other I/O
                        // failures return directly.
                        if !self.connection.is_handshaking() {
                            return Err(error);
                        }
                        continue;
                    }
                    Err(error) => return Err(error),
                }
            }
            if !self.connection.wants_read()
                && !self.connection.wants_write()
                && self.connection.is_handshaking()
            {
                return Err(TlsError::new(TlsErrorCode::Handshake, TlsPhase::Handshake));
            }
        }
        // `process_new_packets` may mark the handshake complete while the
        // final client Finished (or a post-handshake record) remains queued.
        // Drain every pending encrypted record before exposing the stream to
        // the caller; otherwise a peer can observe EOF while waiting for the
        // client's final flight.
        while self.connection.wants_write() {
            let remaining = check_controls(deadline, cancellation, TlsPhase::Handshake)?;
            match self.write_tls_slice(remaining, deadline, cancellation, TlsPhase::Handshake) {
                Ok(()) => {}
                Err(error) if error.is_retryable() => continue,
                Err(error) => return Err(error),
            }
        }
        match self.connection.alpn_protocol() {
            Some(protocol) if protocol != HTTP11_ALPN => {
                Err(TlsError::new(TlsErrorCode::Alpn, TlsPhase::Handshake))
            }
            _ => Ok(()),
        }
    }

    /// Returns non-secret negotiated TLS observations.
    pub fn negotiated(&self) -> Result<TlsNegotiated, TlsError> {
        let protocol = match self.connection.protocol_version() {
            Some(rustls::ProtocolVersion::TLSv1_2) => NativeTlsVersion::Tls1_2,
            Some(rustls::ProtocolVersion::TLSv1_3) => NativeTlsVersion::Tls1_3,
            _ => return Err(TlsError::new(TlsErrorCode::Handshake, TlsPhase::Handshake)),
        };
        Ok(TlsNegotiated {
            server_name_kind: self.server_name_kind,
            sni_sent: self.sni_sent,
            protocol,
            alpn_http11: self.connection.alpn_protocol() == Some(HTTP11_ALPN),
        })
    }

    /// Reads bounded plaintext bytes under an absolute deadline.
    pub fn read_plain(
        &mut self,
        buffer: &mut [u8],
        deadline: TlsDeadline,
        cancellation: &CancellationToken,
    ) -> Result<usize, TlsError> {
        if buffer.len() > MAX_TLS_BUFFER_BYTES {
            return Err(TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Read));
        }
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.connection.is_handshaking() {
            self.handshake(deadline, cancellation)?;
        }
        let _registration = self.register_cancellation(cancellation, TlsPhase::Read)?;
        loop {
            let remaining = check_controls(deadline, cancellation, TlsPhase::Read)?;
            let read = match self.connection.reader().read(buffer) {
                Ok(read) => read,
                // rustls reports an empty plaintext buffer as WouldBlock while
                // it still needs an encrypted record.  Drive the underlying
                // bounded I/O below instead of mistaking this state for a
                // caller-visible timeout.
                Err(error) if is_retryable_io(&error) => 0,
                Err(error) => return Err(map_io_error(error, TlsPhase::Read)),
            };
            if read > 0 {
                return Ok(read);
            }
            if !self.connection.wants_read() && !self.connection.wants_write() {
                return Ok(0);
            }
            if self.connection.wants_write() {
                match self.write_tls_slice(remaining, deadline, cancellation, TlsPhase::Read) {
                    Ok(()) => {}
                    Err(error) if error.is_retryable() => continue,
                    Err(error) => return Err(error),
                }
            }
            if self.connection.wants_read() {
                match self.read_tls_slice(remaining, deadline, cancellation, TlsPhase::Read) {
                    Ok(()) => {
                        self.connection
                            .process_new_packets()
                            .map_err(|error| map_rustls_error(error, TlsPhase::Read))?;
                    }
                    Err(error) if error.is_retryable() => continue,
                    Err(error) => return Err(error),
                }
            }
        }
    }

    /// Reads plaintext with a finite relative timeout.
    pub fn read_with_timeout(
        &mut self,
        buffer: &mut [u8],
        timeout: Duration,
        cancellation: &CancellationToken,
    ) -> Result<usize, TlsError> {
        self.read_plain(buffer, TlsDeadline::after(timeout)?, cancellation)
    }

    /// Writes plaintext with a finite relative timeout without forcing a
    /// flush.  Call [`Self::flush_with_timeout`] when the caller needs the
    /// encrypted records on the underlying stream.
    pub fn write_with_timeout(
        &mut self,
        buffer: &[u8],
        timeout: Duration,
        cancellation: &CancellationToken,
    ) -> Result<usize, TlsError> {
        self.write_plain(buffer, TlsDeadline::after(timeout)?, cancellation)
    }

    /// Writes bounded plaintext bytes into rustls' output buffer.
    pub fn write_plain(
        &mut self,
        buffer: &[u8],
        deadline: TlsDeadline,
        cancellation: &CancellationToken,
    ) -> Result<usize, TlsError> {
        if buffer.len() > MAX_TLS_APPLICATION_BYTES {
            return Err(TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Write));
        }
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.connection.is_handshaking() {
            self.handshake(deadline, cancellation)?;
        }
        check_controls(deadline, cancellation, TlsPhase::Write)?;
        self.connection
            .writer()
            .write(buffer)
            .map_err(|error| map_io_error(error, TlsPhase::Write))
    }

    /// Writes all bounded plaintext bytes and flushes encrypted records.
    pub fn write_all_plain(
        &mut self,
        buffer: &[u8],
        deadline: TlsDeadline,
        cancellation: &CancellationToken,
    ) -> Result<(), TlsError> {
        if buffer.len() > MAX_TLS_APPLICATION_BYTES {
            return Err(TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Write));
        }
        let mut offset = 0usize;
        while offset < buffer.len() {
            let written = self.write_plain(&buffer[offset..], deadline, cancellation)?;
            if written == 0 {
                // rustls can fill its bounded plaintext staging buffer before
                // all application bytes have been accepted.  Drain encrypted
                // records and retry under the same absolute deadline.
                self.flush_plain(deadline, cancellation)?;
                continue;
            }
            offset = offset
                .checked_add(written)
                .ok_or_else(|| TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Write))?;
            if offset < buffer.len() {
                self.flush_plain(deadline, cancellation)?;
            }
        }
        self.flush_plain(deadline, cancellation)
    }

    /// Writes plaintext with a finite relative timeout and flushes it.
    pub fn write_all_with_timeout(
        &mut self,
        buffer: &[u8],
        timeout: Duration,
        cancellation: &CancellationToken,
    ) -> Result<(), TlsError> {
        self.write_all_plain(buffer, TlsDeadline::after(timeout)?, cancellation)
    }

    /// Flushes encrypted records with a finite relative timeout.
    pub fn flush_with_timeout(
        &mut self,
        timeout: Duration,
        cancellation: &CancellationToken,
    ) -> Result<(), TlsError> {
        self.flush_plain(TlsDeadline::after(timeout)?, cancellation)
    }

    /// Flushes pending encrypted records under a finite deadline.
    pub fn flush_plain(
        &mut self,
        deadline: TlsDeadline,
        cancellation: &CancellationToken,
    ) -> Result<(), TlsError> {
        let _registration = self.register_cancellation(cancellation, TlsPhase::Flush)?;
        loop {
            let remaining = check_controls(deadline, cancellation, TlsPhase::Flush)?;
            if !self.connection.wants_write() {
                return Ok(());
            }
            match self.write_tls_slice(remaining, deadline, cancellation, TlsPhase::Flush) {
                Ok(()) => {}
                Err(error) if error.is_retryable() => continue,
                Err(error) => return Err(error),
            }
        }
    }

    /// Returns the exact underlying stream to the owner.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.io
    }

    /// Returns a shared reference to the underlying stream.
    #[must_use]
    pub fn get_ref(&self) -> &S {
        &self.io
    }

    /// Returns a mutable reference to the underlying stream.
    #[must_use]
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.io
    }

    fn register_cancellation(
        &self,
        cancellation: &CancellationToken,
        phase: TlsPhase,
    ) -> Result<Option<CancellationRegistration>, TlsError> {
        let waker = self
            .io
            .cancellation_waker()
            .map_err(|_| TlsError::new(TlsErrorCode::Io, phase))?;
        let registration = cancellation.register_waker(waker);
        if !registration.is_registered() {
            return Err(TlsError::new(TlsErrorCode::Cancelled, phase));
        }
        Ok(Some(registration))
    }

    fn write_tls_slice(
        &mut self,
        remaining: Duration,
        deadline: TlsDeadline,
        cancellation: &CancellationToken,
        phase: TlsPhase,
    ) -> Result<(), TlsError> {
        self.io
            .set_write_timeout(Some(remaining.min(IO_POLL_INTERVAL)))
            .map_err(|_| {
                if cancellation.is_cancelled() {
                    TlsError::new(TlsErrorCode::Cancelled, phase)
                } else {
                    TlsError::new(TlsErrorCode::Io, phase)
                }
            })?;
        match self.connection.write_tls(&mut self.io) {
            Ok(0) if cancellation.is_cancelled() => {
                Err(TlsError::new(TlsErrorCode::Cancelled, phase))
            }
            Ok(0) => Err(TlsError::new(TlsErrorCode::Io, phase)),
            Ok(_) => Ok(()),
            Err(error) if is_retryable_io(&error) => {
                if cancellation.is_cancelled() {
                    Err(TlsError::new(TlsErrorCode::Cancelled, phase))
                } else if deadline.remaining().is_none() {
                    Err(TlsError::new(TlsErrorCode::Timeout, phase))
                } else {
                    Err(TlsError::retryable(TlsErrorCode::Io, phase))
                }
            }
            Err(_error) if cancellation.is_cancelled() => {
                Err(TlsError::new(TlsErrorCode::Cancelled, phase))
            }
            Err(error) => Err(map_io_error(error, phase)),
        }
    }

    fn read_tls_slice(
        &mut self,
        remaining: Duration,
        deadline: TlsDeadline,
        cancellation: &CancellationToken,
        phase: TlsPhase,
    ) -> Result<(), TlsError> {
        self.io
            .set_read_timeout(Some(remaining.min(IO_POLL_INTERVAL)))
            .map_err(|_| {
                if cancellation.is_cancelled() {
                    TlsError::new(TlsErrorCode::Cancelled, phase)
                } else {
                    TlsError::new(TlsErrorCode::Io, phase)
                }
            })?;
        match self.connection.read_tls(&mut self.io) {
            Ok(0) if cancellation.is_cancelled() => {
                Err(TlsError::new(TlsErrorCode::Cancelled, phase))
            }
            Ok(0) => Err(TlsError::new(TlsErrorCode::Eof, phase)),
            Ok(_) => Ok(()),
            Err(error) if is_retryable_io(&error) => {
                if cancellation.is_cancelled() {
                    Err(TlsError::new(TlsErrorCode::Cancelled, phase))
                } else if deadline.remaining().is_none() {
                    Err(TlsError::new(TlsErrorCode::Timeout, phase))
                } else {
                    Err(TlsError::retryable(TlsErrorCode::Io, phase))
                }
            }
            Err(_error) if cancellation.is_cancelled() => {
                Err(TlsError::new(TlsErrorCode::Cancelled, phase))
            }
            Err(error) => Err(map_io_error(error, phase)),
        }
    }
}

fn check_controls(
    deadline: TlsDeadline,
    cancellation: &CancellationToken,
    phase: TlsPhase,
) -> Result<Duration, TlsError> {
    if cancellation.is_cancelled() {
        return Err(TlsError::new(TlsErrorCode::Cancelled, phase));
    }
    deadline
        .remaining()
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| TlsError::new(TlsErrorCode::Timeout, phase))
}

fn is_retryable_io(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

fn map_io_error(error: io::Error, phase: TlsPhase) -> TlsError {
    match error.kind() {
        io::ErrorKind::UnexpectedEof => TlsError::new(TlsErrorCode::Eof, phase),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => {
            TlsError::new(TlsErrorCode::Timeout, phase)
        }
        _ => TlsError::new(TlsErrorCode::Io, phase),
    }
}

fn map_rustls_error(error: rustls::Error, phase: TlsPhase) -> TlsError {
    match error {
        rustls::Error::InvalidCertificate(_) => TlsError::new(TlsErrorCode::Verification, phase),
        rustls::Error::NoApplicationProtocol
        | rustls::Error::AlertReceived(rustls::AlertDescription::NoApplicationProtocol) => {
            TlsError::new(TlsErrorCode::Alpn, phase)
        }
        _ => TlsError::new(TlsErrorCode::Handshake, phase),
    }
}

fn make_server_name(value: &str) -> Result<(ServerName<'static>, ServerNameKind), TlsError> {
    if value.is_empty()
        || value.len() > 255
        || value
            .bytes()
            .any(|byte| byte < 0x20 || byte == 0x7f || byte >= 0x80)
    {
        return Err(TlsError::new(
            TlsErrorCode::InvalidServerName,
            TlsPhase::ServerName,
        ));
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok((ServerName::from(ip), ServerNameKind::Ip));
    }
    let name = ServerName::try_from(value.to_owned())
        .map_err(|_| TlsError::new(TlsErrorCode::InvalidServerName, TlsPhase::ServerName))?;
    Ok((name, ServerNameKind::Dns))
}

fn validate_certificate_chain(certificates: &[Vec<u8>]) -> Result<(), TlsError> {
    if certificates.is_empty() || certificates.len() > MAX_TLS_CLIENT_CERTIFICATES {
        return Err(TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config));
    }
    let mut total = 0usize;
    for certificate in certificates {
        if certificate.is_empty() || certificate.len() > MAX_TLS_CLIENT_CERTIFICATE_BYTES {
            return Err(TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config));
        }
        total = total
            .checked_add(certificate.len())
            .ok_or_else(|| TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config))?;
        let mut certificate_store = RootCertStore::empty();
        certificate_store
            .add(CertificateDer::from(certificate.clone()))
            .map_err(|_| TlsError::new(TlsErrorCode::MalformedCertificate, TlsPhase::Config))?;
    }
    if total > MAX_TLS_CLIENT_IDENTITY_BYTES {
        return Err(TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config));
    }
    Ok(())
}

fn private_key_from_slice(input: &[u8]) -> Result<PrivateKeyDer<'static>, TlsError> {
    if input.is_empty() || input.len() > MAX_TLS_PRIVATE_KEY_BYTES {
        return Err(TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config));
    }
    // Validate against the caller's bytes before allocating an owned copy.
    // The owned conversion then gives rustls the one application-to-provider
    // copy that is required for a `'static` key; `PrivateKeyDer` zeroizes that
    // allocation when it is dropped.
    PrivateKeyDer::try_from(input)
        .map_err(|_| TlsError::new(TlsErrorCode::MalformedKey, TlsPhase::Config))?;
    PrivateKeyDer::try_from(input.to_vec())
        .map_err(|_| TlsError::new(TlsErrorCode::MalformedKey, TlsPhase::Config))
}

fn parse_pem_certificates(input: &[u8]) -> Result<Vec<Vec<u8>>, TlsError> {
    validate_pem_input(
        input,
        |kind| kind == SectionKind::Certificate,
        TlsErrorCode::MalformedCertificate,
    )?;
    let mut certificates = Vec::new();
    for item in CertificateDer::pem_slice_iter(input) {
        let certificate =
            item.map_err(|_| TlsError::new(TlsErrorCode::MalformedCertificate, TlsPhase::Config))?;
        certificates.push(certificate.as_ref().to_vec());
        if certificates.len() > MAX_TLS_ROOT_CERTIFICATES {
            return Err(TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config));
        }
    }
    if certificates.is_empty() {
        return Err(TlsError::new(
            TlsErrorCode::MalformedCertificate,
            TlsPhase::Config,
        ));
    }
    let total = certificates
        .iter()
        .try_fold(0usize, |sum, certificate| {
            sum.checked_add(certificate.len())
        })
        .ok_or_else(|| TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config))?;
    if total > MAX_TLS_ROOT_BYTES {
        return Err(TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config));
    }
    Ok(certificates)
}

fn parse_pem_private_key(input: &[u8]) -> Result<PrivateKeyDer<'static>, TlsError> {
    let section_count = validate_pem_input(
        input,
        |kind| {
            matches!(
                kind,
                SectionKind::PrivateKey | SectionKind::RsaPrivateKey | SectionKind::EcPrivateKey
            )
        },
        TlsErrorCode::MalformedKey,
    )?;
    if section_count != 1 {
        return Err(TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config));
    }
    let key = PrivateKeyDer::from_pem_slice(input)
        .map_err(|_| TlsError::new(TlsErrorCode::MalformedKey, TlsPhase::Config))?;
    if key.secret_der().is_empty() || key.secret_der().len() > MAX_TLS_PRIVATE_KEY_BYTES {
        return Err(TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config));
    }
    Ok(key)
}

fn validate_pem_input<F>(
    input: &[u8],
    allowed: F,
    malformed_code: TlsErrorCode,
) -> Result<usize, TlsError>
where
    F: Fn(SectionKind) -> bool,
{
    if input.is_empty() || input.len() > MAX_TLS_INPUT_BYTES {
        return Err(TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config));
    }
    let mut active: Option<Vec<u8>> = None;
    let mut section_count = 0usize;
    for line in input.split(|byte| *byte == b'\r' || *byte == b'\n') {
        if let Some(rest) = line.strip_prefix(b"-----BEGIN ") {
            let Some(label) = rest.strip_suffix(b"-----") else {
                return Err(TlsError::new(malformed_code, TlsPhase::Config));
            };
            if active.is_some() {
                return Err(TlsError::new(malformed_code, TlsPhase::Config));
            }
            let kind = SectionKind::try_from(label)
                .map_err(|_| TlsError::new(TlsErrorCode::Unsupported, TlsPhase::Config))?;
            if !allowed(kind) {
                return Err(TlsError::new(TlsErrorCode::Unsupported, TlsPhase::Config));
            }
            active = Some(label.to_vec());
            section_count = section_count
                .checked_add(1)
                .ok_or_else(|| TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config))?;
        } else if let Some(rest) = line.strip_prefix(b"-----END ") {
            let Some(label) = rest.strip_suffix(b"-----") else {
                return Err(TlsError::new(malformed_code, TlsPhase::Config));
            };
            if active.as_deref() != Some(label) {
                return Err(TlsError::new(malformed_code, TlsPhase::Config));
            }
            active = None;
        } else if active.is_none() && !line.iter().all(u8::is_ascii_whitespace) {
            return Err(TlsError::new(malformed_code, TlsPhase::Config));
        }
    }
    if active.is_some() || section_count == 0 {
        return Err(TlsError::new(malformed_code, TlsPhase::Config));
    }
    Ok(section_count)
}

fn split_der_items(
    input: &[u8],
    error_code: TlsErrorCode,
    max_items: usize,
) -> Result<Vec<Vec<u8>>, TlsError> {
    if input.is_empty() || input.len() > MAX_TLS_INPUT_BYTES {
        return Err(TlsError::new(error_code, TlsPhase::Config));
    }
    let mut items = Vec::new();
    let mut offset = 0usize;
    while offset < input.len() {
        let remaining = &input[offset..];
        let item_len = der_sequence_len(remaining)
            .ok_or_else(|| TlsError::new(error_code, TlsPhase::Config))?;
        let end = offset
            .checked_add(item_len)
            .ok_or_else(|| TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config))?;
        if end > input.len() {
            return Err(TlsError::new(error_code, TlsPhase::Config));
        }
        items.push(input[offset..end].to_vec());
        offset = end;
        if items.len() > max_items {
            return Err(TlsError::new(TlsErrorCode::InputLimit, TlsPhase::Config));
        }
    }
    Ok(items)
}

fn der_sequence_len(input: &[u8]) -> Option<usize> {
    if input.len() < 2 || input[0] != 0x30 {
        return None;
    }
    let first = input[1];
    let (length_bytes, content_len) = if first & 0x80 == 0 {
        (0usize, usize::from(first))
    } else {
        let length_bytes = usize::from(first & 0x7f);
        if length_bytes == 0 || length_bytes > 4 || input.len() < 2 + length_bytes {
            return None;
        }
        let mut content_len = 0usize;
        for byte in &input[2..2 + length_bytes] {
            content_len = content_len
                .checked_mul(256)?
                .checked_add(usize::from(*byte))?;
        }
        (length_bytes, content_len)
    };
    2usize.checked_add(length_bytes)?.checked_add(content_len)
}
