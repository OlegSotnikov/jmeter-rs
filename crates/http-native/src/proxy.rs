// SPDX-License-Identifier: Apache-2.0
//! Pure HTTP/1.1 proxy route planning and handshake framing.
//!
//! This module is intentionally an isolated protocol boundary.  It plans
//! direct, forward-proxy, and CONNECT routes and validates only the request
//! and response heads used by a proxy handshake.  It does not resolve names,
//! open sockets, read environment or system-proxy settings, perform TLS, or
//! retry an operation.  Those effects belong to the application-owned native
//! transport adapter.
//!
//! The public endpoint and TLS identities in this module are opaque values
//! supplied by the caller.  They are never derived from a URL, a DNS answer,
//! a certificate, or a credential.  Proxy credentials cross the boundary as
//! a non-secret reference and a short-lived material handoff; neither type's
//! [`Debug`] implementation reveals secret bytes.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str;

/// HTTP/1.1 protocol identity used by this pure proxy boundary.
pub const PROXY_PROTOCOL_SCHEMA_ID: &str = "http.proxy/1";
/// Maximum request-target bytes accepted by the proxy protocol.
pub const HARD_MAX_REQUEST_TARGET_BYTES: usize = 64 * 1024;
/// Maximum authority bytes accepted by the proxy protocol.
pub const HARD_MAX_AUTHORITY_BYTES: usize = 8 * 1024;
/// Maximum status-line bytes, including its CRLF.
pub const HARD_MAX_STATUS_LINE_BYTES: usize = 8 * 1024;
/// Maximum reason-phrase bytes.
pub const HARD_MAX_REASON_BYTES: usize = 4 * 1024;
/// Maximum number of fields in one request or response head.
pub const HARD_MAX_HEADER_COUNT: usize = 1_024;
/// Maximum field-name bytes.
pub const HARD_MAX_HEADER_NAME_BYTES: usize = 8 * 1024;
/// Maximum field-value bytes.
pub const HARD_MAX_HEADER_VALUE_BYTES: usize = 64 * 1024;
/// Maximum aggregate field bytes, excluding the request/status line.
pub const HARD_MAX_HEADER_BYTES: usize = 1024 * 1024;
/// Maximum informational responses preceding a CONNECT result.
pub const HARD_MAX_INFORMATIONAL_COUNT: usize = 32;
/// Maximum aggregate bytes occupied by informational response heads.
pub const HARD_MAX_INFORMATIONAL_BYTES: usize = 256 * 1024;
/// Maximum bytes retained for a proxy credential field.
pub const HARD_MAX_CREDENTIAL_BYTES: usize = 8 * 1024;

const DEFAULT_REQUEST_HEAD_BYTES: usize = 256 * 1024;
const DEFAULT_RESPONSE_HEAD_BYTES: usize = 256 * 1024;
const DEFAULT_STATUS_LINE_BYTES: usize = 4 * 1024;
const DEFAULT_REASON_BYTES: usize = 1024;
const DEFAULT_HEADER_COUNT: usize = 128;
const DEFAULT_HEADER_NAME_BYTES: usize = 1024;
const DEFAULT_HEADER_VALUE_BYTES: usize = 16 * 1024;
const DEFAULT_HEADER_BYTES: usize = 256 * 1024;
const DEFAULT_INFORMATIONAL_COUNT: usize = 8;
const DEFAULT_INFORMATIONAL_BYTES: usize = 64 * 1024;

/// A stable, redacted error from route planning or proxy-head validation.
///
/// Variants deliberately carry no untrusted strings or status text.  The
/// caller can use [`ProxyProtocolError::code`] as a machine-readable key;
/// [`Display`](fmt::Display) and [`Debug`](fmt::Debug) expose that key only.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub enum ProxyProtocolError {
    /// A bounded parser or route limit was exceeded.
    Limit(ProxyLimit),
    /// A public authority was not valid or lacked an explicit port.
    InvalidAuthority,
    /// An endpoint or identity was empty/degenerate.
    InvalidIdentity,
    /// A request line or method was malformed.
    InvalidRequestLine,
    /// A request target was malformed or used the wrong form.
    InvalidRequestTarget,
    /// A status line was malformed.
    InvalidStatusLine,
    /// A field name or field value was malformed.
    InvalidHeader,
    /// A parser needs more bytes to prove a complete head.
    Incomplete,
    /// Bytes followed a complete request head.
    RequestSurplus,
    /// Bytes followed a complete CONNECT response head.
    ResponseSurplus,
    /// A body-bearing header is forbidden on this control head.
    BodyForbidden,
    /// A transfer-framing header is forbidden on this control head.
    FramingForbidden,
    /// Upgrade semantics are not part of this HTTP/1.1 boundary.
    UpgradeUnsupported,
    /// A proxy authentication challenge was received; no retry is performed.
    AuthChallenge,
    /// The CONNECT status was not a successful 2xx status.
    ConnectStatus,
    /// The selected route cannot perform the requested head operation.
    InvalidRoute,
    /// A credential reference needs a material handoff.
    CredentialsRequired,
    /// A material handoff did not match the route reference.
    CredentialMismatch,
    /// A caller tried to provide a raw Proxy-Authorization field.
    CredentialHeader,
    /// A parser was fed after it had already completed.
    AlreadyComplete,
    /// A protocol version or request form is outside this boundary.
    UnsupportedProtocol,
}

impl ProxyProtocolError {
    /// Returns the stable redacted error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Limit(limit) => limit.code(),
            Self::InvalidAuthority => "http.proxy.invalid-authority",
            Self::InvalidIdentity => "http.proxy.invalid-identity",
            Self::InvalidRequestLine => "http.proxy.invalid-request-line",
            Self::InvalidRequestTarget => "http.proxy.invalid-request-target",
            Self::InvalidStatusLine => "http.proxy.invalid-status-line",
            Self::InvalidHeader => "http.proxy.invalid-header",
            Self::Incomplete => "http.proxy.incomplete",
            Self::RequestSurplus => "http.proxy.request-surplus",
            Self::ResponseSurplus => "http.proxy.response-surplus",
            Self::BodyForbidden => "http.proxy.body-forbidden",
            Self::FramingForbidden => "http.proxy.framing-forbidden",
            Self::UpgradeUnsupported => "http.proxy.upgrade-unsupported",
            Self::AuthChallenge => "http.proxy.auth-challenge",
            Self::ConnectStatus => "http.proxy.connect-status",
            Self::InvalidRoute => "http.proxy.invalid-route",
            Self::CredentialsRequired => "http.proxy.credentials-required",
            Self::CredentialMismatch => "http.proxy.credential-mismatch",
            Self::CredentialHeader => "http.proxy.credential-header",
            Self::AlreadyComplete => "http.proxy.already-complete",
            Self::UnsupportedProtocol => "http.proxy.unsupported-protocol",
        }
    }
}

impl fmt::Debug for ProxyProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Display for ProxyProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ProxyProtocolError {}

/// A named parser limit with a stable redacted code.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProxyLimit {
    /// Request-head aggregate bytes.
    RequestHead,
    /// Response-head aggregate bytes.
    ResponseHead,
    /// Status-line bytes.
    StatusLine,
    /// Reason-phrase bytes.
    Reason,
    /// Request-target bytes.
    RequestTarget,
    /// Authority bytes.
    Authority,
    /// Field count.
    HeaderCount,
    /// One field name.
    HeaderName,
    /// One field value.
    HeaderValue,
    /// Aggregate field bytes.
    HeaderAggregate,
    /// Informational response count.
    InformationalCount,
    /// Informational response aggregate bytes.
    InformationalAggregate,
    /// Credential bytes.
    Credential,
}

impl ProxyLimit {
    /// Returns the stable redacted limit code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::RequestHead => "http.proxy.limit.request-head",
            Self::ResponseHead => "http.proxy.limit.response-head",
            Self::StatusLine => "http.proxy.limit.status-line",
            Self::Reason => "http.proxy.limit.reason",
            Self::RequestTarget => "http.proxy.limit.request-target",
            Self::Authority => "http.proxy.limit.authority",
            Self::HeaderCount => "http.proxy.limit.header-count",
            Self::HeaderName => "http.proxy.limit.header-name",
            Self::HeaderValue => "http.proxy.limit.header-value",
            Self::HeaderAggregate => "http.proxy.limit.header-aggregate",
            Self::InformationalCount => "http.proxy.limit.informational-count",
            Self::InformationalAggregate => "http.proxy.limit.informational-aggregate",
            Self::Credential => "http.proxy.limit.credential",
        }
    }
}

/// A non-secret endpoint identity supplied by the application.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EndpointIdentity([u8; 16]);

impl EndpointIdentity {
    /// Creates an identity, rejecting the all-zero sentinel.
    pub fn new(bytes: [u8; 16]) -> Result<Self, ProxyProtocolError> {
        if bytes == [0; 16] {
            return Err(ProxyProtocolError::InvalidIdentity);
        }
        Ok(Self(bytes))
    }

    /// Returns the opaque identity bytes.
    #[must_use]
    pub const fn bytes(self) -> [u8; 16] {
        self.0
    }
}

impl TryFrom<[u8; 16]> for EndpointIdentity {
    type Error = ProxyProtocolError;

    fn try_from(value: [u8; 16]) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl fmt::Debug for EndpointIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("EndpointIdentity")
            .field(&self.0)
            .finish()
    }
}

/// An opaque identity for a proxy TLS policy/provider.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProxyTlsIdentity(EndpointIdentity);

impl ProxyTlsIdentity {
    /// Creates a proxy-side TLS identity from a public identity.
    pub const fn new(identity: EndpointIdentity) -> Self {
        Self(identity)
    }

    /// Returns the underlying public identity.
    #[must_use]
    pub const fn identity(self) -> EndpointIdentity {
        self.0
    }
}

impl fmt::Debug for ProxyTlsIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyTlsIdentity")
            .field("identity", &self.0)
            .finish()
    }
}

/// An opaque identity for an origin TLS policy/provider.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OriginTlsIdentity(EndpointIdentity);

impl OriginTlsIdentity {
    /// Creates an origin-side TLS identity from a public identity.
    pub const fn new(identity: EndpointIdentity) -> Self {
        Self(identity)
    }

    /// Returns the underlying public identity.
    #[must_use]
    pub const fn identity(self) -> EndpointIdentity {
        self.0
    }
}

impl fmt::Debug for OriginTlsIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OriginTlsIdentity")
            .field("identity", &self.0)
            .finish()
    }
}

/// A parsed authority with a required explicit port.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Authority {
    host: String,
    port: u16,
}

impl Authority {
    /// Parses `host:port` or `[ipv6]:port` without resolving the host.
    pub fn parse(value: &str) -> Result<Self, ProxyProtocolError> {
        if value.is_empty() || value.len() > HARD_MAX_AUTHORITY_BYTES {
            return Err(if value.len() > HARD_MAX_AUTHORITY_BYTES {
                ProxyProtocolError::Limit(ProxyLimit::Authority)
            } else {
                ProxyProtocolError::InvalidAuthority
            });
        }
        if value.bytes().any(is_forbidden_authority_byte) {
            return Err(ProxyProtocolError::InvalidAuthority);
        }
        if let Some(rest) = value.strip_prefix('[') {
            let Some(close) = rest.find(']') else {
                return Err(ProxyProtocolError::InvalidAuthority);
            };
            let host = &rest[..close];
            if host.is_empty() || host.parse::<Ipv6Addr>().is_err() {
                return Err(ProxyProtocolError::InvalidAuthority);
            }
            let Some(port) = rest
                .get(close + 1..)
                .and_then(|suffix| suffix.strip_prefix(':'))
            else {
                return Err(ProxyProtocolError::InvalidAuthority);
            };
            if port.is_empty() || port.bytes().any(|byte| !byte.is_ascii_digit()) {
                return Err(ProxyProtocolError::InvalidAuthority);
            }
            let port = parse_port(port)?;
            if rest
                .get(close + 1..)
                .is_none_or(|suffix| !suffix.starts_with(':'))
            {
                return Err(ProxyProtocolError::InvalidAuthority);
            }
            if rest[close + 1..].matches(':').count() != 1 {
                return Err(ProxyProtocolError::InvalidAuthority);
            }
            return Self::from_host_port(host, port);
        }

        let Some(colon) = value.rfind(':') else {
            return Err(ProxyProtocolError::InvalidAuthority);
        };
        let host = &value[..colon];
        let port = &value[colon + 1..];
        if host.is_empty()
            || host.contains(':')
            || port.is_empty()
            || port.bytes().any(|byte| !byte.is_ascii_digit())
        {
            return Err(ProxyProtocolError::InvalidAuthority);
        }
        let port = parse_port(port)?;
        Self::from_host_port(host, port)
    }

    /// Creates an authority from a host and non-zero port.
    pub fn new(host: &str, port: u16) -> Result<Self, ProxyProtocolError> {
        Self::from_host_port(host, port)
    }

    fn from_host_port(host: &str, port: u16) -> Result<Self, ProxyProtocolError> {
        if port == 0 || host.is_empty() || host.len() > HARD_MAX_AUTHORITY_BYTES {
            return Err(ProxyProtocolError::InvalidAuthority);
        }
        if host.bytes().any(is_forbidden_host_byte) {
            return Err(ProxyProtocolError::InvalidAuthority);
        }
        if !valid_percent_encoding(host) {
            return Err(ProxyProtocolError::InvalidAuthority);
        }
        if host.contains(':') {
            if host.parse::<Ipv6Addr>().is_err() {
                return Err(ProxyProtocolError::InvalidAuthority);
            }
        } else if host.parse::<Ipv4Addr>().is_err() {
            // A non-numeric host is retained for the application resolver;
            // this module intentionally performs no DNS or IDNA work.
            if !host.bytes().all(is_reg_name_byte) {
                return Err(ProxyProtocolError::InvalidAuthority);
            }
        }
        Ok(Self {
            host: host.to_ascii_lowercase(),
            port,
        })
    }

    /// Returns the host without IPv6 brackets.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Returns the explicit non-zero port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Returns whether the host is an IPv6 literal.
    #[must_use]
    pub fn is_ipv6(&self) -> bool {
        self.host.contains(':')
    }

    /// Returns the wire authority, including required IPv6 brackets.
    #[must_use]
    pub fn wire(&self) -> String {
        if self.is_ipv6() {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

impl TryFrom<&str> for Authority {
    type Error = ProxyProtocolError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl TryFrom<String> for Authority {
    type Error = ProxyProtocolError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl fmt::Debug for Authority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Authority")
            .field("host", &self.host)
            .field("port", &self.port)
            .finish()
    }
}

impl fmt::Display for Authority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_ipv6() {
            write!(formatter, "[{}]:{}", self.host, self.port)
        } else {
            write!(formatter, "{}:{}", self.host, self.port)
        }
    }
}

/// A public endpoint identity paired with a wire authority.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct PublicEndpoint {
    identity: EndpointIdentity,
    authority: Authority,
}

impl PublicEndpoint {
    /// Creates an endpoint from already-validated public values.
    #[must_use]
    pub fn new(identity: EndpointIdentity, authority: Authority) -> Self {
        Self {
            identity,
            authority,
        }
    }

    /// Parses an endpoint authority while retaining the supplied identity.
    pub fn parse(identity: EndpointIdentity, authority: &str) -> Result<Self, ProxyProtocolError> {
        Ok(Self::new(identity, Authority::parse(authority)?))
    }

    /// Returns the endpoint identity.
    #[must_use]
    pub const fn identity(&self) -> EndpointIdentity {
        self.identity
    }

    /// Returns the public authority.
    #[must_use]
    pub const fn authority(&self) -> &Authority {
        &self.authority
    }
}

impl fmt::Debug for PublicEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicEndpoint")
            .field("identity", &self.identity)
            .field("authority", &self.authority)
            .finish()
    }
}

/// Origin protocol used by a route recipe.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OriginScheme {
    /// Plain HTTP origin.
    Http,
    /// TLS-protected HTTPS origin.
    Https,
}

impl OriginScheme {
    /// Returns the lower-case URL scheme.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

/// Proxy transport scheme used by a route recipe.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProxyScheme {
    /// Plain HTTP proxy connection.
    Http,
    /// TLS-protected connection to the proxy.
    Https,
}

/// A non-secret provider/lease reference for one proxy credential.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ProxyCredentialReference {
    provider_identity: EndpointIdentity,
    handle_identity: EndpointIdentity,
}

impl ProxyCredentialReference {
    /// Creates an opaque reference.  The handle is not a secret value.
    #[must_use]
    pub const fn new(
        provider_identity: EndpointIdentity,
        handle_identity: EndpointIdentity,
    ) -> Self {
        Self {
            provider_identity,
            handle_identity,
        }
    }

    /// Returns the non-secret provider identity.
    #[must_use]
    pub const fn provider_identity(self) -> EndpointIdentity {
        self.provider_identity
    }

    /// Returns the non-secret handle identity.
    #[must_use]
    pub const fn handle_identity(self) -> EndpointIdentity {
        self.handle_identity
    }
}

impl fmt::Debug for ProxyCredentialReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyCredentialReference")
            .field("provider_identity", &self.provider_identity)
            .field("handle_present", &true)
            .finish()
    }
}

/// A short-lived credential material handoff owned by an application secret
/// provider.  The material is borrowed and is never retained by a route.
pub struct ProxyCredentialMaterial<'a> {
    reference: &'a ProxyCredentialReference,
    username: &'a str,
    password: &'a [u8],
}

impl<'a> ProxyCredentialMaterial<'a> {
    /// Validates a Basic-auth material handoff without copying its secret.
    pub fn new(
        reference: &'a ProxyCredentialReference,
        username: &'a str,
        password: &'a [u8],
    ) -> Result<Self, ProxyProtocolError> {
        validate_credential_material(username, password)?;
        Ok(Self {
            reference,
            username,
            password,
        })
    }

    /// Returns the reference this material was issued for.
    #[must_use]
    pub const fn reference(&self) -> &ProxyCredentialReference {
        self.reference
    }
}

impl fmt::Debug for ProxyCredentialMaterial<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyCredentialMaterial")
            .field("reference", self.reference)
            .field("username_bytes", &self.username.len())
            .field("password_bytes", &self.password.len())
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Route kind used by the planner.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RouteKind {
    /// Connect directly to the origin.
    Direct,
    /// Send an HTTP origin request through a forward proxy.
    HttpForward,
    /// Establish an HTTPS origin tunnel with CONNECT.
    HttpsConnect,
}

/// Wire-visible route variant used in attempt identities.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RouteVariant {
    /// No proxy is involved.
    Direct,
    /// Plain or TLS forward proxy.
    ForwardProxy,
    /// Plain HTTP proxy CONNECT tunnel.
    ConnectTunnel,
    /// TLS-protected proxy CONNECT tunnel.
    TlsForwardProxy,
}

/// A route identity containing only caller-supplied public identities.
///
/// The two TLS fields are distinct types and fields so a proxy TLS policy can
/// never be accidentally used as the origin policy.  Authorities and
/// credential references are intentionally absent from this identity.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct RouteIdentity {
    /// Wire route variant.
    pub variant: RouteVariant,
    /// Opaque origin endpoint identity.
    pub origin_endpoint_id: EndpointIdentity,
    /// Opaque proxy endpoint identity, when a proxy is selected.
    pub proxy_endpoint_id: Option<EndpointIdentity>,
    /// Opaque proxy TLS identity, when the proxy connection uses TLS.
    pub proxy_tls_identity: Option<ProxyTlsIdentity>,
    /// Opaque origin TLS identity, when the origin connection uses TLS.
    pub origin_tls_identity: Option<OriginTlsIdentity>,
    /// Caller-supplied non-secret route-policy identity.
    pub policy_identity: [u8; 32],
}

impl fmt::Debug for RouteIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RouteIdentity")
            .field("variant", &self.variant)
            .field("origin_endpoint_id", &self.origin_endpoint_id)
            .field("proxy_endpoint_id", &self.proxy_endpoint_id)
            .field("proxy_tls_identity", &self.proxy_tls_identity)
            .field("origin_tls_identity", &self.origin_tls_identity)
            .field("policy_identity", &self.policy_identity)
            .finish()
    }
}

impl RouteIdentity {
    /// Validates route identity shape without performing any I/O.
    pub fn validate(&self) -> Result<(), ProxyProtocolError> {
        match self.variant {
            RouteVariant::Direct => {
                if self.proxy_endpoint_id.is_some() || self.proxy_tls_identity.is_some() {
                    return Err(ProxyProtocolError::InvalidRoute);
                }
            }
            RouteVariant::ForwardProxy
            | RouteVariant::ConnectTunnel
            | RouteVariant::TlsForwardProxy => {
                if self.proxy_endpoint_id.is_none() {
                    return Err(ProxyProtocolError::InvalidRoute);
                }
            }
        }
        match self.variant {
            RouteVariant::Direct => {}
            RouteVariant::ForwardProxy => {
                if self.proxy_tls_identity.is_some() || self.origin_tls_identity.is_some() {
                    return Err(ProxyProtocolError::InvalidRoute);
                }
            }
            RouteVariant::ConnectTunnel => {
                if self.proxy_tls_identity.is_some() || self.origin_tls_identity.is_none() {
                    return Err(ProxyProtocolError::InvalidRoute);
                }
            }
            RouteVariant::TlsForwardProxy => {
                if self.proxy_tls_identity.is_none() {
                    return Err(ProxyProtocolError::InvalidRoute);
                }
            }
        }
        Ok(())
    }
}

/// A fully typed route recipe.  It contains no sockets, resolved addresses,
/// TLS contexts, environment settings, or plaintext credential material.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct RouteRecipe {
    kind: RouteKind,
    origin: PublicEndpoint,
    origin_scheme: OriginScheme,
    proxy: Option<PublicEndpoint>,
    proxy_scheme: Option<ProxyScheme>,
    proxy_tls_identity: Option<ProxyTlsIdentity>,
    origin_tls_identity: Option<OriginTlsIdentity>,
    credentials: Option<ProxyCredentialReference>,
    policy_identity: [u8; 32],
}

impl fmt::Debug for RouteRecipe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RouteRecipe")
            .field("kind", &self.kind)
            .field("origin", &self.origin)
            .field("origin_scheme", &self.origin_scheme)
            .field("proxy", &self.proxy)
            .field("proxy_scheme", &self.proxy_scheme)
            .field("proxy_tls_identity", &self.proxy_tls_identity)
            .field("origin_tls_identity", &self.origin_tls_identity)
            .field(
                "proxy_credentials",
                &self.credentials.as_ref().map(|_| "<reference>"),
            )
            .field("policy_identity", &self.policy_identity)
            .finish()
    }
}

impl RouteRecipe {
    /// Creates a direct route and validates TLS identity pairing.
    pub fn direct(
        origin: PublicEndpoint,
        origin_scheme: OriginScheme,
        origin_tls_identity: Option<OriginTlsIdentity>,
    ) -> Result<Self, ProxyProtocolError> {
        Self::direct_with(origin, origin_scheme, origin_tls_identity, [0; 32])
    }

    /// Creates a direct route with an explicit non-secret policy identity.
    pub fn direct_with(
        origin: PublicEndpoint,
        origin_scheme: OriginScheme,
        origin_tls_identity: Option<OriginTlsIdentity>,
        policy_identity: [u8; 32],
    ) -> Result<Self, ProxyProtocolError> {
        let route = Self {
            kind: RouteKind::Direct,
            origin,
            origin_scheme,
            proxy: None,
            proxy_scheme: None,
            proxy_tls_identity: None,
            origin_tls_identity,
            credentials: None,
            policy_identity,
        };
        route.validate()?;
        Ok(route)
    }

    /// Creates a direct HTTP route without TLS.
    pub fn direct_http(origin: PublicEndpoint) -> Result<Self, ProxyProtocolError> {
        Self::direct(origin, OriginScheme::Http, None)
    }

    /// Creates a direct HTTPS route with a distinct origin TLS identity.
    pub fn direct_https(
        origin: PublicEndpoint,
        origin_tls_identity: OriginTlsIdentity,
    ) -> Result<Self, ProxyProtocolError> {
        Self::direct(origin, OriginScheme::Https, Some(origin_tls_identity))
    }

    /// Creates an HTTP-origin forward route through a proxy.
    pub fn http_forward(
        proxy: PublicEndpoint,
        origin: PublicEndpoint,
    ) -> Result<Self, ProxyProtocolError> {
        Self::http_forward_with(proxy, ProxyScheme::Http, origin, None, None, [0; 32])
    }

    /// Creates an HTTP-origin forward route with explicit proxy policy.
    pub fn http_forward_with(
        proxy: PublicEndpoint,
        proxy_scheme: ProxyScheme,
        origin: PublicEndpoint,
        proxy_tls_identity: Option<ProxyTlsIdentity>,
        credentials: Option<ProxyCredentialReference>,
        policy_identity: [u8; 32],
    ) -> Result<Self, ProxyProtocolError> {
        let route = Self {
            kind: RouteKind::HttpForward,
            origin,
            origin_scheme: OriginScheme::Http,
            proxy: Some(proxy),
            proxy_scheme: Some(proxy_scheme),
            proxy_tls_identity,
            origin_tls_identity: None,
            credentials,
            policy_identity,
        };
        route.validate()?;
        Ok(route)
    }

    /// Creates an HTTPS-origin CONNECT route through an HTTP proxy.
    pub fn https_connect(
        proxy: PublicEndpoint,
        origin: PublicEndpoint,
        origin_tls_identity: OriginTlsIdentity,
    ) -> Result<Self, ProxyProtocolError> {
        Self::https_connect_with(
            proxy,
            ProxyScheme::Http,
            origin,
            None,
            origin_tls_identity,
            None,
            [0; 32],
        )
    }

    /// Creates an HTTPS-origin CONNECT route with explicit proxy TLS and
    /// credential/policy identities.
    pub fn https_connect_with(
        proxy: PublicEndpoint,
        proxy_scheme: ProxyScheme,
        origin: PublicEndpoint,
        proxy_tls_identity: Option<ProxyTlsIdentity>,
        origin_tls_identity: OriginTlsIdentity,
        credentials: Option<ProxyCredentialReference>,
        policy_identity: [u8; 32],
    ) -> Result<Self, ProxyProtocolError> {
        let route = Self {
            kind: RouteKind::HttpsConnect,
            origin,
            origin_scheme: OriginScheme::Https,
            proxy: Some(proxy),
            proxy_scheme: Some(proxy_scheme),
            proxy_tls_identity,
            origin_tls_identity: Some(origin_tls_identity),
            credentials,
            policy_identity,
        };
        route.validate()?;
        Ok(route)
    }

    /// Returns the planner route kind.
    #[must_use]
    pub const fn kind(&self) -> RouteKind {
        self.kind
    }

    /// Returns the origin endpoint.
    #[must_use]
    pub const fn origin(&self) -> &PublicEndpoint {
        &self.origin
    }

    /// Returns the optional proxy endpoint.
    #[must_use]
    pub const fn proxy(&self) -> Option<&PublicEndpoint> {
        self.proxy.as_ref()
    }

    /// Returns the route's proxy TLS identity, if any.
    #[must_use]
    pub const fn proxy_tls_identity(&self) -> Option<ProxyTlsIdentity> {
        self.proxy_tls_identity
    }

    /// Returns the route's origin TLS identity, if any.
    #[must_use]
    pub const fn origin_tls_identity(&self) -> Option<OriginTlsIdentity> {
        self.origin_tls_identity
    }

    /// Returns the non-secret proxy credential reference, if any.
    #[must_use]
    pub const fn credential_reference(&self) -> Option<ProxyCredentialReference> {
        self.credentials
    }

    /// Returns the route identity used by attempt observations.
    #[must_use]
    pub fn route_identity(&self) -> RouteIdentity {
        let variant = match self.kind {
            RouteKind::Direct => RouteVariant::Direct,
            RouteKind::HttpForward => {
                if matches!(self.proxy_scheme, Some(ProxyScheme::Https)) {
                    RouteVariant::TlsForwardProxy
                } else {
                    RouteVariant::ForwardProxy
                }
            }
            RouteKind::HttpsConnect => {
                if matches!(self.proxy_scheme, Some(ProxyScheme::Https)) {
                    RouteVariant::TlsForwardProxy
                } else {
                    RouteVariant::ConnectTunnel
                }
            }
        };
        RouteIdentity {
            variant,
            origin_endpoint_id: self.origin.identity(),
            proxy_endpoint_id: self.proxy.as_ref().map(PublicEndpoint::identity),
            proxy_tls_identity: self.proxy_tls_identity,
            origin_tls_identity: self.origin_tls_identity,
            policy_identity: self.policy_identity,
        }
    }

    /// Validates route shape and TLS identity separation.
    pub fn validate(&self) -> Result<(), ProxyProtocolError> {
        match self.kind {
            RouteKind::Direct => {
                if self.proxy.is_some()
                    || self.proxy_scheme.is_some()
                    || self.proxy_tls_identity.is_some()
                    || self.credentials.is_some()
                {
                    return Err(ProxyProtocolError::InvalidRoute);
                }
                match (self.origin_scheme, self.origin_tls_identity) {
                    (OriginScheme::Http, None) | (OriginScheme::Https, Some(_)) => {}
                    _ => return Err(ProxyProtocolError::InvalidRoute),
                }
            }
            RouteKind::HttpForward => {
                let Some(proxy_scheme) = self.proxy_scheme else {
                    return Err(ProxyProtocolError::InvalidRoute);
                };
                if self.proxy.is_none()
                    || self.origin_scheme != OriginScheme::Http
                    || self.origin_tls_identity.is_some()
                {
                    return Err(ProxyProtocolError::InvalidRoute);
                }
                if matches!(proxy_scheme, ProxyScheme::Https) != self.proxy_tls_identity.is_some() {
                    return Err(ProxyProtocolError::InvalidRoute);
                }
            }
            RouteKind::HttpsConnect => {
                let Some(proxy_scheme) = self.proxy_scheme else {
                    return Err(ProxyProtocolError::InvalidRoute);
                };
                if self.proxy.is_none()
                    || self.origin_scheme != OriginScheme::Https
                    || self.origin_tls_identity.is_none()
                {
                    return Err(ProxyProtocolError::InvalidRoute);
                }
                if matches!(proxy_scheme, ProxyScheme::Https) != self.proxy_tls_identity.is_some() {
                    return Err(ProxyProtocolError::InvalidRoute);
                }
            }
        }
        self.route_identity().validate()
    }

    /// Builds a direct or forward-proxy origin request head.
    ///
    /// For a direct route the target is origin-form.  For an HTTP forward
    /// route it is absolute-form and retains the origin authority.  An HTTPS
    /// CONNECT route must first use [`Self::connect_head`].
    pub fn request_head(
        &self,
        method: &str,
        path_and_query: &str,
        headers: &OrderedHeaders,
        material: Option<&ProxyCredentialMaterial<'_>>,
    ) -> Result<EncodedRequestHead, ProxyProtocolError> {
        self.validate()?;
        let target = match self.kind {
            RouteKind::Direct => RequestTarget::origin(path_and_query)?,
            RouteKind::HttpForward => RequestTarget::absolute(
                self.origin_scheme,
                self.origin.authority().clone(),
                path_and_query,
            )?,
            RouteKind::HttpsConnect => return Err(ProxyProtocolError::InvalidRoute),
        };
        let headers = self.prepare_headers(
            headers,
            material,
            matches!(self.kind, RouteKind::HttpForward),
        )?;
        RequestHead::from_route(method, target, headers)?.encode()
    }

    /// Builds the authority-form CONNECT request head for an HTTPS route.
    pub fn connect_head(
        &self,
        headers: &OrderedHeaders,
        material: Option<&ProxyCredentialMaterial<'_>>,
    ) -> Result<EncodedRequestHead, ProxyProtocolError> {
        self.validate()?;
        if self.kind != RouteKind::HttpsConnect {
            return Err(ProxyProtocolError::InvalidRoute);
        }
        let target = RequestTarget::Authority(self.origin.authority().clone());
        let headers = self.prepare_headers(headers, material, true)?;
        RequestHead::from_route("CONNECT", target, headers)?.encode()
    }

    /// Builds the origin-form request sent after a successful CONNECT.
    pub fn tunneled_request_head(
        &self,
        method: &str,
        path_and_query: &str,
        headers: &OrderedHeaders,
    ) -> Result<EncodedRequestHead, ProxyProtocolError> {
        self.validate()?;
        if self.kind != RouteKind::HttpsConnect {
            return Err(ProxyProtocolError::InvalidRoute);
        }
        let target = RequestTarget::origin(path_and_query)?;
        let headers = self.prepare_headers(headers, None, false)?;
        RequestHead::new(method, target, headers)?.encode()
    }

    fn prepare_headers(
        &self,
        input: &OrderedHeaders,
        material: Option<&ProxyCredentialMaterial<'_>>,
        proxy_handshake: bool,
    ) -> Result<OrderedHeaders, ProxyProtocolError> {
        let mut headers = input.clone();
        headers.validate(&ProxyProtocolLimits::default())?;
        let host_values = headers.values("host");
        if host_values.len() > 1 {
            return Err(ProxyProtocolError::InvalidHeader);
        }
        if let Some(host) = host_values.first() {
            if !host.eq_ignore_ascii_case(self.origin.authority().wire().as_bytes()) {
                return Err(ProxyProtocolError::InvalidHeader);
            }
        } else {
            headers.push(HeaderField::new("Host", self.origin.authority().wire())?)?;
        }

        if headers.contains("proxy-authorization") {
            return Err(ProxyProtocolError::CredentialHeader);
        }
        validate_control_request_headers(&headers)?;

        if proxy_handshake {
            let has_reference = self.credentials.is_some();
            if has_reference != material.is_some() {
                if has_reference {
                    return Err(ProxyProtocolError::CredentialsRequired);
                }
                return Err(ProxyProtocolError::CredentialMismatch);
            }
            if let Some(material) = material {
                let Some(reference) = self.credentials else {
                    return Err(ProxyProtocolError::CredentialMismatch);
                };
                if *material.reference() != reference {
                    return Err(ProxyProtocolError::CredentialMismatch);
                }
                headers.push(HeaderField::new(
                    "Proxy-Authorization",
                    basic_authorization(material)?,
                )?)?;
            }
        } else if material.is_some() {
            // A proxy credential is valid only on the proxy request, never on
            // a direct origin request or the post-CONNECT origin request.
            return Err(ProxyProtocolError::CredentialMismatch);
        }
        Ok(headers)
    }
}

/// One ordered HTTP field.  Field values are kept private from `Debug` so a
/// parsed `Proxy-Authorization` value cannot enter diagnostics accidentally.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct HeaderField {
    name: String,
    value: Vec<u8>,
}

impl HeaderField {
    /// Validates and creates one field.
    pub fn new(
        name: impl Into<String>,
        value: impl Into<Vec<u8>>,
    ) -> Result<Self, ProxyProtocolError> {
        let name = name.into();
        let value = value.into();
        validate_header_name(&name)?;
        validate_header_value(&value)?;
        if name.len() > HARD_MAX_HEADER_NAME_BYTES {
            return Err(ProxyProtocolError::Limit(ProxyLimit::HeaderName));
        }
        if value.len() > HARD_MAX_HEADER_VALUE_BYTES {
            return Err(ProxyProtocolError::Limit(ProxyLimit::HeaderValue));
        }
        Ok(Self { name, value })
    }

    /// Returns the field name with source spelling preserved.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the field value bytes.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

impl fmt::Debug for HeaderField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeaderField")
            .field("name", &self.name)
            .field("value_bytes", &self.value.len())
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Ordered duplicate-preserving HTTP fields.
#[derive(Clone, Default, Eq, Hash, PartialEq)]
pub struct OrderedHeaders {
    fields: Vec<HeaderField>,
}

impl OrderedHeaders {
    /// Creates an empty ordered field list.
    #[must_use]
    pub const fn new() -> Self {
        Self { fields: Vec::new() }
    }

    /// Creates a list from fields while preserving order and duplicates.
    pub fn from_fields(
        fields: impl IntoIterator<Item = HeaderField>,
    ) -> Result<Self, ProxyProtocolError> {
        let mut headers = Self::new();
        for field in fields {
            headers.push(field)?;
        }
        Ok(headers)
    }

    /// Appends a field with hard-limit checks.
    pub fn push(&mut self, field: HeaderField) -> Result<(), ProxyProtocolError> {
        let next = self
            .fields
            .len()
            .checked_add(1)
            .ok_or(ProxyProtocolError::Limit(ProxyLimit::HeaderCount))?;
        if next > HARD_MAX_HEADER_COUNT {
            return Err(ProxyProtocolError::Limit(ProxyLimit::HeaderCount));
        }
        let aggregate = self
            .aggregate_bytes()?
            .checked_add(field.wire_len()?)
            .ok_or(ProxyProtocolError::Limit(ProxyLimit::HeaderAggregate))?;
        if aggregate > HARD_MAX_HEADER_BYTES {
            return Err(ProxyProtocolError::Limit(ProxyLimit::HeaderAggregate));
        }
        self.fields.push(field);
        Ok(())
    }

    /// Returns fields in exact wire order.
    #[must_use]
    pub fn fields(&self) -> &[HeaderField] {
        &self.fields
    }

    /// Returns the number of fields, including duplicates.
    #[must_use]
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Returns whether no fields are present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Returns aggregate wire bytes occupied by fields and CRLF delimiters.
    #[must_use = "check the aggregate byte count for overflow"]
    pub fn aggregate_bytes(&self) -> Result<usize, ProxyProtocolError> {
        self.fields.iter().try_fold(0usize, |aggregate, field| {
            aggregate
                .checked_add(field.wire_len()?)
                .ok_or(ProxyProtocolError::Limit(ProxyLimit::HeaderAggregate))
        })
    }

    /// Returns whether a case-insensitive field name is present.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.fields
            .iter()
            .any(|field| field.name.eq_ignore_ascii_case(name))
    }

    /// Returns all values for a case-insensitive name in original order.
    #[must_use]
    pub fn values(&self, name: &str) -> Vec<&[u8]> {
        self.fields
            .iter()
            .filter(|field| field.name.eq_ignore_ascii_case(name))
            .map(HeaderField::value)
            .collect()
    }

    /// Validates active limits without changing order or duplicate fields.
    pub fn validate(&self, limits: &ProxyProtocolLimits) -> Result<(), ProxyProtocolError> {
        limits.validate()?;
        if self.fields.len() > limits.max_header_count {
            return Err(ProxyProtocolError::Limit(ProxyLimit::HeaderCount));
        }
        let mut aggregate = 0usize;
        for field in &self.fields {
            if field.name.len() > limits.max_header_name_bytes {
                return Err(ProxyProtocolError::Limit(ProxyLimit::HeaderName));
            }
            if field.value.len() > limits.max_header_value_bytes {
                return Err(ProxyProtocolError::Limit(ProxyLimit::HeaderValue));
            }
            aggregate = aggregate
                .checked_add(field.wire_len()?)
                .ok_or(ProxyProtocolError::Limit(ProxyLimit::HeaderAggregate))?;
        }
        if aggregate > limits.max_header_bytes {
            return Err(ProxyProtocolError::Limit(ProxyLimit::HeaderAggregate));
        }
        Ok(())
    }
}

impl fmt::Debug for OrderedHeaders {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.aggregate_bytes() {
            Ok(bytes) => formatter
                .debug_struct("OrderedHeaders")
                .field("count", &self.fields.len())
                .field("aggregate_bytes", &bytes)
                .field("fields", &self.fields)
                .finish(),
            Err(error) => formatter
                .debug_struct("OrderedHeaders")
                .field("count", &self.fields.len())
                .field("aggregate_error", &error.code())
                .field("fields", &self.fields)
                .finish(),
        }
    }
}

impl HeaderField {
    fn wire_len(&self) -> Result<usize, ProxyProtocolError> {
        checked_wire_len(self.name.len(), self.value.len())
    }
}

fn checked_wire_len(name_bytes: usize, value_bytes: usize) -> Result<usize, ProxyProtocolError> {
    name_bytes
        .checked_add(2)
        .and_then(|bytes| bytes.checked_add(value_bytes))
        .and_then(|bytes| bytes.checked_add(2))
        .ok_or(ProxyProtocolError::Limit(ProxyLimit::HeaderAggregate))
}

/// Active proxy parser limits.  Every field is finite and may only be lower
/// than the corresponding protocol ceiling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProxyProtocolLimits {
    /// Maximum complete request-head bytes.
    pub max_request_head_bytes: usize,
    /// Maximum complete response-head bytes, including informational heads.
    pub max_response_head_bytes: usize,
    /// Maximum status-line bytes.
    pub max_status_line_bytes: usize,
    /// Maximum reason phrase bytes.
    pub max_reason_bytes: usize,
    /// Maximum request-target bytes.
    pub max_request_target_bytes: usize,
    /// Maximum authority bytes.
    pub max_authority_bytes: usize,
    /// Maximum fields in one head.
    pub max_header_count: usize,
    /// Maximum bytes in one field name.
    pub max_header_name_bytes: usize,
    /// Maximum bytes in one field value.
    pub max_header_value_bytes: usize,
    /// Maximum aggregate field bytes.
    pub max_header_bytes: usize,
    /// Maximum informational response count.
    pub max_informational_count: usize,
    /// Maximum aggregate informational response bytes.
    pub max_informational_bytes: usize,
}

impl Default for ProxyProtocolLimits {
    fn default() -> Self {
        Self {
            max_request_head_bytes: DEFAULT_REQUEST_HEAD_BYTES,
            max_response_head_bytes: DEFAULT_RESPONSE_HEAD_BYTES,
            max_status_line_bytes: DEFAULT_STATUS_LINE_BYTES,
            max_reason_bytes: DEFAULT_REASON_BYTES,
            max_request_target_bytes: HARD_MAX_REQUEST_TARGET_BYTES,
            max_authority_bytes: HARD_MAX_AUTHORITY_BYTES,
            max_header_count: DEFAULT_HEADER_COUNT,
            max_header_name_bytes: DEFAULT_HEADER_NAME_BYTES,
            max_header_value_bytes: DEFAULT_HEADER_VALUE_BYTES,
            max_header_bytes: DEFAULT_HEADER_BYTES,
            max_informational_count: DEFAULT_INFORMATIONAL_COUNT,
            max_informational_bytes: DEFAULT_INFORMATIONAL_BYTES,
        }
    }
}

impl ProxyProtocolLimits {
    /// Validates all active values against non-zero and hard maxima.
    pub fn validate(&self) -> Result<(), ProxyProtocolError> {
        check_limit(
            self.max_request_head_bytes,
            HARD_MAX_HEADER_BYTES + HARD_MAX_REQUEST_TARGET_BYTES + HARD_MAX_STATUS_LINE_BYTES,
            ProxyLimit::RequestHead,
        )?;
        check_limit(
            self.max_response_head_bytes,
            HARD_MAX_HEADER_BYTES + HARD_MAX_STATUS_LINE_BYTES,
            ProxyLimit::ResponseHead,
        )?;
        check_limit(
            self.max_status_line_bytes,
            HARD_MAX_STATUS_LINE_BYTES,
            ProxyLimit::StatusLine,
        )?;
        check_limit(
            self.max_reason_bytes,
            HARD_MAX_REASON_BYTES,
            ProxyLimit::Reason,
        )?;
        check_limit(
            self.max_request_target_bytes,
            HARD_MAX_REQUEST_TARGET_BYTES,
            ProxyLimit::RequestTarget,
        )?;
        check_limit(
            self.max_authority_bytes,
            HARD_MAX_AUTHORITY_BYTES,
            ProxyLimit::Authority,
        )?;
        check_limit(
            self.max_header_count,
            HARD_MAX_HEADER_COUNT,
            ProxyLimit::HeaderCount,
        )?;
        check_limit(
            self.max_header_name_bytes,
            HARD_MAX_HEADER_NAME_BYTES,
            ProxyLimit::HeaderName,
        )?;
        check_limit(
            self.max_header_value_bytes,
            HARD_MAX_HEADER_VALUE_BYTES,
            ProxyLimit::HeaderValue,
        )?;
        check_limit(
            self.max_header_bytes,
            HARD_MAX_HEADER_BYTES,
            ProxyLimit::HeaderAggregate,
        )?;
        check_limit(
            self.max_informational_count,
            HARD_MAX_INFORMATIONAL_COUNT,
            ProxyLimit::InformationalCount,
        )?;
        check_limit(
            self.max_informational_bytes,
            HARD_MAX_INFORMATIONAL_BYTES,
            ProxyLimit::InformationalAggregate,
        )?;
        Ok(())
    }
}

/// A parsed HTTP request target form.
#[derive(Clone, Eq, Hash, PartialEq)]
pub enum RequestTarget {
    /// Origin-form path and query, such as `/health?ready=1`.
    Origin(String),
    /// Absolute-form URL target used by an HTTP forward proxy.
    Absolute {
        /// URL scheme.
        scheme: OriginScheme,
        /// Origin authority.
        authority: Authority,
        /// Path and query in origin form.
        path_and_query: String,
    },
    /// Authority-form target used by CONNECT.
    Authority(Authority),
    /// Asterisk-form target.
    Asterisk,
}

impl fmt::Debug for RequestTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Origin(path) => formatter
                .debug_struct("Origin")
                .field("bytes", &path.len())
                .finish(),
            Self::Absolute {
                scheme,
                authority,
                path_and_query,
            } => formatter
                .debug_struct("Absolute")
                .field("scheme", scheme)
                .field("authority", authority)
                .field("path_query_bytes", &path_and_query.len())
                .finish(),
            Self::Authority(authority) => {
                formatter.debug_tuple("Authority").field(authority).finish()
            }
            Self::Asterisk => formatter.write_str("Asterisk"),
        }
    }
}

impl RequestTarget {
    /// Constructs an origin-form target.
    pub fn origin(path_and_query: &str) -> Result<Self, ProxyProtocolError> {
        validate_path(path_and_query)?;
        Ok(Self::Origin(path_and_query.to_owned()))
    }

    /// Constructs an absolute-form target.
    pub fn absolute(
        scheme: OriginScheme,
        authority: Authority,
        path_and_query: &str,
    ) -> Result<Self, ProxyProtocolError> {
        validate_path(path_and_query)?;
        Ok(Self::Absolute {
            scheme,
            authority,
            path_and_query: path_and_query.to_owned(),
        })
    }

    /// Returns the exact target wire spelling.
    #[must_use]
    pub fn wire(&self) -> String {
        match self {
            Self::Origin(path) => path.clone(),
            Self::Absolute {
                scheme,
                authority,
                path_and_query,
            } => format!("{}://{}{}", scheme.as_str(), authority, path_and_query),
            Self::Authority(authority) => authority.wire(),
            Self::Asterisk => "*".to_owned(),
        }
    }

    /// Returns whether this is authority-form.
    #[must_use]
    pub const fn is_authority(&self) -> bool {
        matches!(self, Self::Authority(_))
    }

    /// Returns whether this is absolute-form.
    #[must_use]
    pub const fn is_absolute(&self) -> bool {
        matches!(self, Self::Absolute { .. })
    }

    /// Returns whether this is origin-form.
    #[must_use]
    pub const fn is_origin(&self) -> bool {
        matches!(self, Self::Origin(_))
    }
}

/// A validated HTTP/1.1 request head with no body/framing semantics.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct RequestHead {
    method: String,
    target: RequestTarget,
    headers: OrderedHeaders,
}

impl RequestHead {
    /// Creates a request head and rejects body/framing/upgrade fields.
    pub fn new(
        method: &str,
        target: RequestTarget,
        headers: OrderedHeaders,
    ) -> Result<Self, ProxyProtocolError> {
        Self::new_checked(method, target, headers, false)
    }

    fn from_route(
        method: &str,
        target: RequestTarget,
        headers: OrderedHeaders,
    ) -> Result<Self, ProxyProtocolError> {
        Self::new_checked(method, target, headers, true)
    }

    fn new_checked(
        method: &str,
        target: RequestTarget,
        headers: OrderedHeaders,
        allow_proxy_authorization: bool,
    ) -> Result<Self, ProxyProtocolError> {
        validate_method(method)?;
        validate_request_target_for_method(method, &target)?;
        headers.validate(&ProxyProtocolLimits::default())?;
        if !allow_proxy_authorization && headers.contains("proxy-authorization") {
            return Err(ProxyProtocolError::CredentialHeader);
        }
        validate_request_headers(&headers)?;
        Ok(Self {
            method: method.to_owned(),
            target,
            headers,
        })
    }

    /// Returns the method token.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Returns the parsed target.
    #[must_use]
    pub const fn target(&self) -> &RequestTarget {
        &self.target
    }

    /// Returns ordered fields, including duplicates.
    #[must_use]
    pub const fn headers(&self) -> &OrderedHeaders {
        &self.headers
    }

    /// Encodes the exact HTTP/1.1 request head.
    pub fn encode(&self) -> Result<EncodedRequestHead, ProxyProtocolError> {
        let mut bytes = Vec::new();
        append_request_head(&mut bytes, self)?;
        Ok(EncodedRequestHead { bytes })
    }
}

impl fmt::Debug for RequestHead {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestHead")
            .field("method", &self.method)
            .field("target", &self.target)
            .field("headers", &self.headers)
            .finish()
    }
}

/// Owned encoded request bytes.  `Debug` reports only size, never wire bytes.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct EncodedRequestHead {
    bytes: Vec<u8>,
}

impl EncodedRequestHead {
    /// Returns the encoded head bytes for the transport handoff.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the encoded head length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns whether the encoded head is empty (it should never be).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl fmt::Debug for EncodedRequestHead {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncodedRequestHead")
            .field("bytes", &self.bytes.len())
            .field("wire", &"<redacted>")
            .finish()
    }
}

/// A parsed status/field head received during CONNECT.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ResponseHead {
    status: u16,
    reason: Option<String>,
    headers: OrderedHeaders,
}

impl ResponseHead {
    /// Returns the status code.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Returns the optional reason phrase, preserving absent vs present-empty.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    /// Returns ordered response fields.
    #[must_use]
    pub const fn headers(&self) -> &OrderedHeaders {
        &self.headers
    }
}

impl fmt::Debug for ResponseHead {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResponseHead")
            .field("status", &self.status)
            .field("reason_present", &self.reason.is_some())
            .field("reason_bytes", &self.reason.as_ref().map_or(0, String::len))
            .field("headers", &self.headers)
            .finish()
    }
}

/// A complete successful CONNECT response and any preceding informational
/// responses.  No body bytes are accepted or retained.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ConnectResponse {
    informational: Vec<ResponseHead>,
    final_response: ResponseHead,
}

impl ConnectResponse {
    /// Returns preceding 1xx responses in wire order.
    #[must_use]
    pub fn informational(&self) -> &[ResponseHead] {
        &self.informational
    }

    /// Returns the successful final 2xx response.
    #[must_use]
    pub const fn final_response(&self) -> &ResponseHead {
        &self.final_response
    }

    /// Returns the successful CONNECT status.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.final_response.status
    }
}

/// Incremental parser progress for fragmented request/response heads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseProgress<T> {
    /// More bytes are required to identify the complete head.
    NeedMore,
    /// The complete, validated head.
    Complete(T),
}

/// Incremental request-head parser.  It owns at most the configured bounded
/// head bytes and rejects any bytes after the terminating empty line.
pub struct RequestHeadParser {
    limits: ProxyProtocolLimits,
    bytes: Vec<u8>,
    complete: bool,
}

impl RequestHeadParser {
    /// Creates an empty parser with active limits.
    pub fn new(limits: ProxyProtocolLimits) -> Result<Self, ProxyProtocolError> {
        limits.validate()?;
        Ok(Self {
            limits,
            bytes: Vec::new(),
            complete: false,
        })
    }

    /// Feeds one arbitrary fragment, returning complete only at CRLFCRLF.
    pub fn feed(
        &mut self,
        fragment: &[u8],
    ) -> Result<ParseProgress<RequestHead>, ProxyProtocolError> {
        if self.complete {
            return Err(if fragment.is_empty() {
                ProxyProtocolError::AlreadyComplete
            } else {
                ProxyProtocolError::RequestSurplus
            });
        }
        append_bounded(
            &mut self.bytes,
            fragment,
            self.limits.max_request_head_bytes,
            ProxyLimit::RequestHead,
        )?;
        let Some(end) = find_head_end(&self.bytes) else {
            return Ok(ParseProgress::NeedMore);
        };
        if end != self.bytes.len() {
            return Err(ProxyProtocolError::RequestSurplus);
        }
        let head = parse_request_head_exact(&self.bytes, &self.limits)?;
        self.complete = true;
        Ok(ParseProgress::Complete(head))
    }

    /// Finishes parsing, returning incomplete if CRLFCRLF was not observed.
    pub fn finish(&mut self) -> Result<RequestHead, ProxyProtocolError> {
        if self.complete {
            return Err(ProxyProtocolError::AlreadyComplete);
        }
        let Some(end) = find_head_end(&self.bytes) else {
            return Err(ProxyProtocolError::Incomplete);
        };
        if end != self.bytes.len() {
            return Err(ProxyProtocolError::RequestSurplus);
        }
        let head = parse_request_head_exact(&self.bytes, &self.limits)?;
        self.complete = true;
        Ok(head)
    }
}

/// Incremental CONNECT-response parser.  It accepts informational 1xx heads,
/// then one final 2xx head, and rejects body/framing/tunnel surplus bytes.
pub struct ConnectResponseParser {
    limits: ProxyProtocolLimits,
    bytes: Vec<u8>,
    complete: bool,
}

impl ConnectResponseParser {
    /// Creates an empty parser with active limits.
    pub fn new(limits: ProxyProtocolLimits) -> Result<Self, ProxyProtocolError> {
        limits.validate()?;
        Ok(Self {
            limits,
            bytes: Vec::new(),
            complete: false,
        })
    }

    /// Feeds one arbitrary fragment.
    pub fn feed(
        &mut self,
        fragment: &[u8],
    ) -> Result<ParseProgress<ConnectResponse>, ProxyProtocolError> {
        if self.complete {
            return Err(if fragment.is_empty() {
                ProxyProtocolError::AlreadyComplete
            } else {
                ProxyProtocolError::ResponseSurplus
            });
        }
        append_bounded(
            &mut self.bytes,
            fragment,
            self.limits.max_response_head_bytes,
            ProxyLimit::ResponseHead,
        )?;
        if find_head_end(&self.bytes).is_none() {
            return Ok(ParseProgress::NeedMore);
        }
        match parse_connect_response_exact(&self.bytes, &self.limits) {
            Ok(response) => {
                self.complete = true;
                Ok(ParseProgress::Complete(response))
            }
            Err(ProxyProtocolError::Incomplete) => Ok(ParseProgress::NeedMore),
            Err(error) => Err(error),
        }
    }

    /// Finishes parsing and rejects a partial or surplus response.
    pub fn finish(&mut self) -> Result<ConnectResponse, ProxyProtocolError> {
        if self.complete {
            return Err(ProxyProtocolError::AlreadyComplete);
        }
        let response = parse_connect_response_exact(&self.bytes, &self.limits)?;
        self.complete = true;
        Ok(response)
    }
}

/// Parses one complete request head with the default active limits.
pub fn parse_request_head(bytes: &[u8]) -> Result<RequestHead, ProxyProtocolError> {
    parse_request_head_with_limits(bytes, &ProxyProtocolLimits::default())
}

/// Parses one complete request head with explicit active limits.
pub fn parse_request_head_with_limits(
    bytes: &[u8],
    limits: &ProxyProtocolLimits,
) -> Result<RequestHead, ProxyProtocolError> {
    limits.validate()?;
    parse_request_head_exact(bytes, limits)
}

/// Parses one complete CONNECT response with the default active limits.
pub fn parse_connect_response(bytes: &[u8]) -> Result<ConnectResponse, ProxyProtocolError> {
    parse_connect_response_with_limits(bytes, &ProxyProtocolLimits::default())
}

/// Parses one complete CONNECT response with explicit active limits.
pub fn parse_connect_response_with_limits(
    bytes: &[u8],
    limits: &ProxyProtocolLimits,
) -> Result<ConnectResponse, ProxyProtocolError> {
    limits.validate()?;
    parse_connect_response_exact(bytes, limits)
}

fn parse_request_head_exact(
    bytes: &[u8],
    limits: &ProxyProtocolLimits,
) -> Result<RequestHead, ProxyProtocolError> {
    if bytes.len() > limits.max_request_head_bytes {
        return Err(ProxyProtocolError::Limit(ProxyLimit::RequestHead));
    }
    let Some(end) = find_head_end(bytes) else {
        return Err(ProxyProtocolError::Incomplete);
    };
    if end != bytes.len() {
        return Err(ProxyProtocolError::RequestSurplus);
    }
    let (first_line, headers) = parse_head_lines(bytes, limits, true)?;
    // Raw wire credentials are never accepted as a parsed protocol value.
    // Route construction is the sole path that can add this field, after a
    // reference/material handoff has been checked.
    if headers.contains("proxy-authorization") {
        return Err(ProxyProtocolError::CredentialHeader);
    }
    let mut parts = first_line.split(' ');
    let method = parts.next().ok_or(ProxyProtocolError::InvalidRequestLine)?;
    let target = parts.next().ok_or(ProxyProtocolError::InvalidRequestLine)?;
    let protocol = parts.next().ok_or(ProxyProtocolError::InvalidRequestLine)?;
    if parts.next().is_some() || protocol != "HTTP/1.1" || target.is_empty() {
        return if protocol != "HTTP/1.1" {
            Err(ProxyProtocolError::UnsupportedProtocol)
        } else {
            Err(ProxyProtocolError::InvalidRequestLine)
        };
    }
    validate_method(method)?;
    let target = parse_request_target(method, target, limits)?;
    RequestHead::new(method, target, headers)
}

fn parse_connect_response_exact(
    bytes: &[u8],
    limits: &ProxyProtocolLimits,
) -> Result<ConnectResponse, ProxyProtocolError> {
    if bytes.len() > limits.max_response_head_bytes {
        return Err(ProxyProtocolError::Limit(ProxyLimit::ResponseHead));
    }
    let mut cursor = 0usize;
    let mut informational = Vec::new();
    let mut informational_bytes = 0usize;
    loop {
        let Some(relative_end) = find_head_end(&bytes[cursor..]) else {
            return Err(ProxyProtocolError::Incomplete);
        };
        let end = cursor
            .checked_add(relative_end)
            .ok_or(ProxyProtocolError::Limit(ProxyLimit::ResponseHead))?;
        let head = parse_response_head(&bytes[cursor..end], limits)?;
        cursor = end;
        if head.status < 200 {
            if head.status == 101 {
                return Err(ProxyProtocolError::UpgradeUnsupported);
            }
            validate_informational(&head)?;
            let next_count = informational
                .len()
                .checked_add(1)
                .ok_or(ProxyProtocolError::Limit(ProxyLimit::InformationalCount))?;
            if next_count > limits.max_informational_count {
                return Err(ProxyProtocolError::Limit(ProxyLimit::InformationalCount));
            }
            informational_bytes =
                informational_bytes
                    .checked_add(relative_end)
                    .ok_or(ProxyProtocolError::Limit(
                        ProxyLimit::InformationalAggregate,
                    ))?;
            if informational_bytes > limits.max_informational_bytes {
                return Err(ProxyProtocolError::Limit(
                    ProxyLimit::InformationalAggregate,
                ));
            }
            informational.push(head);
            if cursor == bytes.len() {
                return Err(ProxyProtocolError::Incomplete);
            }
            continue;
        }
        validate_final_connect_head(&head)?;
        if cursor != bytes.len() {
            return Err(ProxyProtocolError::ResponseSurplus);
        }
        return Ok(ConnectResponse {
            informational,
            final_response: head,
        });
    }
}

fn parse_response_head(
    bytes: &[u8],
    limits: &ProxyProtocolLimits,
) -> Result<ResponseHead, ProxyProtocolError> {
    let (first_line, headers) = parse_head_lines(bytes, limits, false)?;
    if first_line.len() > limits.max_status_line_bytes {
        return Err(ProxyProtocolError::Limit(ProxyLimit::StatusLine));
    }
    let mut parts = first_line.splitn(3, ' ');
    let protocol = parts.next().ok_or(ProxyProtocolError::InvalidStatusLine)?;
    let status = parts.next().ok_or(ProxyProtocolError::InvalidStatusLine)?;
    let reason = parts.next();
    if protocol != "HTTP/1.1"
        || status.len() != 3
        || !status.bytes().all(|byte| byte.is_ascii_digit())
    {
        return if protocol != "HTTP/1.1" {
            Err(ProxyProtocolError::UnsupportedProtocol)
        } else {
            Err(ProxyProtocolError::InvalidStatusLine)
        };
    }
    let status = status
        .parse::<u16>()
        .map_err(|_| ProxyProtocolError::InvalidStatusLine)?;
    if !(100..=599).contains(&status) {
        return Err(ProxyProtocolError::InvalidStatusLine);
    }
    if let Some(reason) = reason {
        if reason.len() > limits.max_reason_bytes || reason.len() > HARD_MAX_REASON_BYTES {
            return Err(ProxyProtocolError::Limit(ProxyLimit::Reason));
        }
        if reason.bytes().any(is_forbidden_reason_byte) {
            return Err(ProxyProtocolError::InvalidStatusLine);
        }
    }
    Ok(ResponseHead {
        status,
        reason: reason.map(str::to_owned),
        headers,
    })
}

fn parse_head_lines(
    bytes: &[u8],
    limits: &ProxyProtocolLimits,
    request: bool,
) -> Result<(String, OrderedHeaders), ProxyProtocolError> {
    let Some(end) = find_head_end(bytes) else {
        return Err(ProxyProtocolError::Incomplete);
    };
    if end != bytes.len() {
        return if request {
            Err(ProxyProtocolError::RequestSurplus)
        } else {
            Err(ProxyProtocolError::ResponseSurplus)
        };
    }
    // Retain the CRLF terminating the last line.  The final two bytes are
    // the empty-line delimiter's second CRLF; splitting the retained region
    // therefore gives every real line a required trailing CR.
    let mut lines = bytes[..bytes.len() - 2].split(|byte| *byte == b'\n');
    let first = lines.next().ok_or(if request {
        ProxyProtocolError::InvalidRequestLine
    } else {
        ProxyProtocolError::InvalidStatusLine
    })?;
    let first = first.strip_suffix(b"\r").ok_or(if request {
        ProxyProtocolError::InvalidRequestLine
    } else {
        ProxyProtocolError::InvalidStatusLine
    })?;
    let first = str::from_utf8(first).map_err(|_| {
        if request {
            ProxyProtocolError::InvalidRequestLine
        } else {
            ProxyProtocolError::InvalidStatusLine
        }
    })?;
    if (request && first.len() > limits.max_request_head_bytes)
        || (!request && first.len() > limits.max_status_line_bytes)
    {
        return Err(if request {
            ProxyProtocolError::Limit(ProxyLimit::RequestHead)
        } else {
            ProxyProtocolError::Limit(ProxyLimit::StatusLine)
        });
    }
    let mut headers = OrderedHeaders::new();
    for line in lines {
        // A trailing LF after the retained final CRLF produces one empty
        // iterator item.  It is the delimiter, not an empty header field.
        if line.is_empty() {
            continue;
        }
        let line = line
            .strip_suffix(b"\r")
            .ok_or(ProxyProtocolError::InvalidHeader)?;
        if line.is_empty() {
            return Err(ProxyProtocolError::InvalidHeader);
        }
        if line
            .first()
            .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
        {
            return Err(ProxyProtocolError::InvalidHeader);
        }
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            return Err(ProxyProtocolError::InvalidHeader);
        };
        let name = str::from_utf8(&line[..colon]).map_err(|_| ProxyProtocolError::InvalidHeader)?;
        validate_header_name(name)?;
        let mut value = &line[colon + 1..];
        while value
            .first()
            .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
        {
            value = &value[1..];
        }
        while value
            .last()
            .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
        {
            value = &value[..value.len() - 1];
        }
        validate_header_value(value)?;
        headers.push(HeaderField::new(name, value.to_vec())?)?;
    }
    headers.validate(limits)?;
    Ok((first.to_owned(), headers))
}

fn validate_informational(head: &ResponseHead) -> Result<(), ProxyProtocolError> {
    if head.headers.contains("content-length")
        || head.headers.contains("transfer-encoding")
        || head.headers.contains("trailer")
    {
        return Err(ProxyProtocolError::FramingForbidden);
    }
    if head.headers.contains("upgrade") || connection_has_upgrade(&head.headers) {
        return Err(ProxyProtocolError::UpgradeUnsupported);
    }
    if head.headers.contains("proxy-authenticate") {
        return Err(ProxyProtocolError::AuthChallenge);
    }
    Ok(())
}

fn validate_final_connect_head(head: &ResponseHead) -> Result<(), ProxyProtocolError> {
    if head.headers.contains("proxy-authenticate") || head.status == 407 {
        return Err(ProxyProtocolError::AuthChallenge);
    }
    if head.headers.contains("upgrade")
        || connection_has_upgrade(&head.headers)
        || head.status == 101
    {
        return Err(ProxyProtocolError::UpgradeUnsupported);
    }
    if head.headers.contains("content-length") || head.headers.contains("transfer-encoding") {
        return Err(ProxyProtocolError::FramingForbidden);
    }
    if head.headers.contains("trailer") {
        return Err(ProxyProtocolError::BodyForbidden);
    }
    if !(200..300).contains(&head.status) {
        return Err(ProxyProtocolError::ConnectStatus);
    }
    Ok(())
}

fn validate_request_headers(headers: &OrderedHeaders) -> Result<(), ProxyProtocolError> {
    if headers.contains("content-length") || headers.contains("transfer-encoding") {
        return Err(ProxyProtocolError::FramingForbidden);
    }
    if headers.contains("expect") || headers.contains("trailer") {
        return Err(ProxyProtocolError::BodyForbidden);
    }
    validate_control_request_headers(headers)
}

fn validate_control_request_headers(headers: &OrderedHeaders) -> Result<(), ProxyProtocolError> {
    if headers.contains("upgrade") || connection_has_upgrade(headers) {
        return Err(ProxyProtocolError::UpgradeUnsupported);
    }
    Ok(())
}

fn connection_has_upgrade(headers: &OrderedHeaders) -> bool {
    headers.values("connection").into_iter().any(|value| {
        value
            .split(|byte| *byte == b',')
            .any(|token| trim_ascii(token).eq_ignore_ascii_case(b"upgrade"))
    })
}

fn parse_request_target(
    method: &str,
    target: &str,
    limits: &ProxyProtocolLimits,
) -> Result<RequestTarget, ProxyProtocolError> {
    if target.len() > limits.max_request_target_bytes {
        return Err(ProxyProtocolError::Limit(ProxyLimit::RequestTarget));
    }
    if target
        .bytes()
        .any(|byte| byte.is_ascii_whitespace() || byte < 0x20 || byte == 0x7f)
    {
        return Err(ProxyProtocolError::InvalidRequestTarget);
    }
    if method.eq_ignore_ascii_case("CONNECT") {
        if target.starts_with('[') || target.bytes().filter(|byte| *byte == b':').count() == 1 {
            return Ok(RequestTarget::Authority(Authority::parse(target)?));
        }
        return Err(ProxyProtocolError::InvalidRequestTarget);
    }
    if target == "*" {
        return Ok(RequestTarget::Asterisk);
    }
    if target.starts_with('/') {
        return RequestTarget::origin(target);
    }
    let Some(scheme_end) = target.find("://") else {
        return Err(ProxyProtocolError::InvalidRequestTarget);
    };
    let scheme = match &target[..scheme_end] {
        "http" => OriginScheme::Http,
        // An HTTPS absolute-form target would put the origin bytes directly
        // on the proxy connection.  This boundary requires CONNECT for an
        // HTTPS origin, so reject it before any tunnel bytes are possible.
        "https" => return Err(ProxyProtocolError::InvalidRequestTarget),
        _ => return Err(ProxyProtocolError::InvalidRequestTarget),
    };
    let rest = &target[scheme_end + 3..];
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = Authority::parse(&rest[..authority_end])?;
    let path = if authority_end == rest.len() {
        "/"
    } else if rest[authority_end..].starts_with('?') {
        // Absolute-form still has an origin-form path.  A missing path is `/`.
        // Preserve the query bytes exactly after inserting that slash.
        return RequestTarget::absolute(scheme, authority, &format!("/{}", &rest[authority_end..]));
    } else {
        &rest[authority_end..]
    };
    RequestTarget::absolute(scheme, authority, path)
}

fn append_request_head(bytes: &mut Vec<u8>, head: &RequestHead) -> Result<(), ProxyProtocolError> {
    bytes.extend_from_slice(head.method.as_bytes());
    bytes.push(b' ');
    bytes.extend_from_slice(head.target.wire().as_bytes());
    bytes.extend_from_slice(b" HTTP/1.1\r\n");
    for field in head.headers.fields() {
        bytes.extend_from_slice(field.name.as_bytes());
        bytes.extend_from_slice(b": ");
        bytes.extend_from_slice(&field.value);
        bytes.extend_from_slice(b"\r\n");
    }
    bytes.extend_from_slice(b"\r\n");
    if bytes.len() > DEFAULT_REQUEST_HEAD_BYTES {
        return Err(ProxyProtocolError::Limit(ProxyLimit::RequestHead));
    }
    Ok(())
}

fn basic_authorization(
    material: &ProxyCredentialMaterial<'_>,
) -> Result<Vec<u8>, ProxyProtocolError> {
    validate_credential_material(material.username, material.password)?;
    let combined_len = material
        .username
        .len()
        .checked_add(1)
        .and_then(|value| value.checked_add(material.password.len()))
        .ok_or(ProxyProtocolError::Limit(ProxyLimit::Credential))?;
    if combined_len > HARD_MAX_CREDENTIAL_BYTES {
        return Err(ProxyProtocolError::Limit(ProxyLimit::Credential));
    }
    let mut plain = Vec::with_capacity(combined_len);
    plain.extend_from_slice(material.username.as_bytes());
    plain.push(b':');
    plain.extend_from_slice(material.password);
    let encoded = base64_encode(&plain);
    let mut header = b"Basic ".to_vec();
    header.extend_from_slice(encoded.as_bytes());
    Ok(header)
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let output_len = bytes.len().div_ceil(3) * 4;
    let mut output = String::with_capacity(output_len);
    let mut index = 0usize;
    while index < bytes.len() {
        let first = bytes[index];
        let second = bytes.get(index + 1).copied();
        let third = bytes.get(index + 2).copied();
        output.push(TABLE[(first >> 2) as usize] as char);
        output.push(
            TABLE[(((first & 0x03) << 4) | second.map_or(0, |value| value >> 4)) as usize] as char,
        );
        match second {
            Some(second) => {
                output.push(
                    TABLE[(((second & 0x0f) << 2) | third.map_or(0, |value| value >> 6)) as usize]
                        as char,
                );
                output.push(third.map_or('=', |value| TABLE[(value & 0x3f) as usize] as char));
            }
            None => {
                output.push('=');
                output.push('=');
            }
        }
        index += 3;
    }
    output
}

fn validate_credential_material(username: &str, password: &[u8]) -> Result<(), ProxyProtocolError> {
    if username.is_empty()
        || username.len() > HARD_MAX_CREDENTIAL_BYTES
        || password.len() > HARD_MAX_CREDENTIAL_BYTES
        || username.contains(':')
        || username
            .bytes()
            .any(|byte| byte < 0x20 || byte == 0x7f || byte >= 0x80)
        || password
            .iter()
            .any(|byte| *byte == b'\r' || *byte == b'\n' || *byte < 0x20 || *byte == 0x7f)
    {
        return Err(ProxyProtocolError::Limit(ProxyLimit::Credential));
    }
    Ok(())
}

fn validate_method(method: &str) -> Result<(), ProxyProtocolError> {
    if method.is_empty() || method.len() > 256 || !method.bytes().all(is_token_byte) {
        return Err(ProxyProtocolError::InvalidRequestLine);
    }
    Ok(())
}

fn validate_request_target_for_method(
    method: &str,
    target: &RequestTarget,
) -> Result<(), ProxyProtocolError> {
    if method.eq_ignore_ascii_case("CONNECT") != target.is_authority() {
        return Err(ProxyProtocolError::InvalidRequestTarget);
    }
    if !method.eq_ignore_ascii_case("CONNECT") && target.is_authority() {
        return Err(ProxyProtocolError::InvalidRequestTarget);
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<(), ProxyProtocolError> {
    if path.is_empty()
        || path.len() > HARD_MAX_REQUEST_TARGET_BYTES
        || !path.starts_with('/')
        || path.contains('#')
        || !valid_percent_encoding(path)
        || path
            .bytes()
            .any(|byte| byte < 0x20 || byte == 0x7f || byte == b' ')
    {
        return Err(if path.len() > HARD_MAX_REQUEST_TARGET_BYTES {
            ProxyProtocolError::Limit(ProxyLimit::RequestTarget)
        } else {
            ProxyProtocolError::InvalidRequestTarget
        });
    }
    Ok(())
}

fn valid_percent_encoding(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

fn validate_header_name(name: &str) -> Result<(), ProxyProtocolError> {
    if name.is_empty()
        || name.len() > HARD_MAX_HEADER_NAME_BYTES
        || !name.bytes().all(is_token_byte)
    {
        return Err(ProxyProtocolError::InvalidHeader);
    }
    Ok(())
}

fn validate_header_value(value: &[u8]) -> Result<(), ProxyProtocolError> {
    if value.len() > HARD_MAX_HEADER_VALUE_BYTES
        || value.iter().any(|byte| {
            *byte == b'\r' || *byte == b'\n' || *byte < 0x20 && *byte != b'\t' || *byte == 0x7f
        })
    {
        return Err(ProxyProtocolError::InvalidHeader);
    }
    Ok(())
}

fn find_head_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn append_bounded(
    destination: &mut Vec<u8>,
    fragment: &[u8],
    limit: usize,
    kind: ProxyLimit,
) -> Result<(), ProxyProtocolError> {
    let next = destination
        .len()
        .checked_add(fragment.len())
        .ok_or(ProxyProtocolError::Limit(kind))?;
    if next > limit {
        return Err(ProxyProtocolError::Limit(kind));
    }
    destination
        .try_reserve(fragment.len())
        .map_err(|_| ProxyProtocolError::Limit(kind))?;
    destination.extend_from_slice(fragment);
    Ok(())
}

fn check_limit(value: usize, maximum: usize, kind: ProxyLimit) -> Result<(), ProxyProtocolError> {
    if value == 0 || value > maximum {
        return Err(ProxyProtocolError::Limit(kind));
    }
    Ok(())
}

fn parse_port(value: &str) -> Result<u16, ProxyProtocolError> {
    let port = value
        .parse::<u32>()
        .map_err(|_| ProxyProtocolError::InvalidAuthority)?;
    if port == 0 || port > u16::MAX as u32 {
        return Err(ProxyProtocolError::InvalidAuthority);
    }
    Ok(port as u16)
}

fn trim_ascii(value: &[u8]) -> &[u8] {
    let mut start = 0usize;
    let mut end = value.len();
    while start < end && (value[start] == b' ' || value[start] == b'\t') {
        start += 1;
    }
    while end > start && (value[end - 1] == b' ' || value[end - 1] == b'\t') {
        end -= 1;
    }
    &value[start..end]
}

fn is_token_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'0'..=b'9'
            | b'a'..=b'z'
            | b'A'..=b'Z'
            | b'!'
            | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
    )
}

fn is_forbidden_authority_byte(byte: u8) -> bool {
    byte < 0x21 || byte == 0x7f || matches!(byte, b'/' | b'?' | b'#' | b'@' | b'\\')
}

fn is_forbidden_host_byte(byte: u8) -> bool {
    byte < 0x21
        || byte == 0x7f
        || byte >= 0x80
        || matches!(byte, b'/' | b'?' | b'#' | b'@' | b'[' | b']' | b'\\')
}

fn is_reg_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'.' | b'-'
                | b'_'
                | b'~'
                | b'%'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
        )
}

fn is_forbidden_reason_byte(byte: u8) -> bool {
    byte < 0x20 && byte != b'\t' || byte == 0x7f
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::panic,
        clippy::unwrap_used,
        reason = "fixed in-process protocol fixtures use assertion-boundary panics and unwraps"
    )]

    use super::*;

    fn identity(value: u8) -> EndpointIdentity {
        EndpointIdentity::new([value; 16]).expect("non-zero identity")
    }

    fn endpoint(identity_value: u8, authority: &str) -> PublicEndpoint {
        PublicEndpoint::parse(identity(identity_value), authority).expect("endpoint")
    }

    fn empty_headers() -> OrderedHeaders {
        OrderedHeaders::new()
    }

    #[test]
    fn authority_accepts_ipv4_and_bracketed_ipv6_only() {
        let ipv4 = Authority::parse("127.0.0.1:8080").expect("ipv4");
        assert_eq!(ipv4.wire(), "127.0.0.1:8080");
        let ipv6 = Authority::parse("[2001:db8::1]:443").expect("ipv6");
        assert_eq!(ipv6.wire(), "[2001:db8::1]:443");
        assert_eq!(ipv6.host(), "2001:db8::1");
        assert!(matches!(
            Authority::parse("2001:db8::1:443"),
            Err(ProxyProtocolError::InvalidAuthority)
        ));
        assert!(matches!(
            Authority::parse("127.0.0.1:0"),
            Err(ProxyProtocolError::InvalidAuthority)
        ));
        assert!(matches!(
            Authority::parse("bad%2:8080"),
            Err(ProxyProtocolError::InvalidAuthority)
        ));
    }

    #[test]
    fn route_identity_preserves_route_and_tls_roles() {
        let route = RouteRecipe::https_connect_with(
            endpoint(1, "[::1]:8080"),
            ProxyScheme::Https,
            endpoint(2, "[2001:db8::2]:443"),
            Some(ProxyTlsIdentity::new(identity(3))),
            OriginTlsIdentity::new(identity(4)),
            None,
            [9; 32],
        )
        .expect("route");
        let route_identity = route.route_identity();
        assert_eq!(route_identity.variant, RouteVariant::TlsForwardProxy);
        assert_eq!(route_identity.proxy_endpoint_id, Some(identity(1)));
        assert_eq!(route_identity.origin_endpoint_id, identity(2));
        assert_eq!(
            route_identity.proxy_tls_identity.unwrap().identity(),
            identity(3)
        );
        assert_eq!(
            route_identity.origin_tls_identity.unwrap().identity(),
            identity(4)
        );
        assert_ne!(
            route_identity.proxy_tls_identity.unwrap().identity(),
            route_identity.origin_tls_identity.unwrap().identity()
        );
        assert!(!format!("{route:?}").contains("secret"));
    }

    #[test]
    fn forward_and_connect_request_forms_are_exact() {
        let origin = endpoint(2, "origin.test:80");
        let forward = RouteRecipe::http_forward(endpoint(1, "proxy.test:3128"), origin.clone())
            .expect("forward route");
        let mut headers = OrderedHeaders::new();
        headers
            .push(HeaderField::new("X-Duplicate", "one").expect("header"))
            .expect("push");
        headers
            .push(HeaderField::new("X-Duplicate", "two").expect("header"))
            .expect("push");
        let encoded = forward
            .request_head("GET", "/path?q=1", &headers, None)
            .expect("forward head");
        assert_eq!(
            encoded.as_bytes(),
            b"GET http://origin.test:80/path?q=1 HTTP/1.1\r\nX-Duplicate: one\r\nX-Duplicate: two\r\nHost: origin.test:80\r\n\r\n"
        );
        let parsed = parse_request_head(encoded.as_bytes()).expect("parse forward");
        assert!(parsed.target().is_absolute());
        assert_eq!(parsed.headers().values("x-duplicate").len(), 2);

        let connect = RouteRecipe::https_connect(
            endpoint(1, "proxy.test:3128"),
            endpoint(2, "[::1]:443"),
            OriginTlsIdentity::new(identity(3)),
        )
        .expect("connect route");
        let encoded = connect
            .connect_head(&empty_headers(), None)
            .expect("connect head");
        assert_eq!(
            encoded.as_bytes(),
            b"CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n\r\n"
        );
        let parsed = parse_request_head(encoded.as_bytes()).expect("parse connect");
        assert!(parsed.target().is_authority());
    }

    #[test]
    fn request_parser_handles_every_fragment_boundary() {
        let bytes = b"GET /path HTTP/1.1\r\nX-A: one\r\nX-A: two\r\nHost: example.test:80\r\n\r\n";
        for split in 0..=bytes.len() {
            let mut parser =
                RequestHeadParser::new(ProxyProtocolLimits::default()).expect("parser");
            let left = parser.feed(&bytes[..split]).expect("left");
            let head = match left {
                ParseProgress::Complete(head) => head,
                ParseProgress::NeedMore => {
                    let ParseProgress::Complete(head) =
                        parser.feed(&bytes[split..]).expect("right")
                    else {
                        panic!("split {split} did not complete")
                    };
                    head
                }
            };
            assert_eq!(head.method(), "GET");
            assert_eq!(head.headers().values("x-a").len(), 2);
        }
    }

    #[test]
    fn connect_parser_handles_informational_fragments_and_preserves_order() {
        let bytes = b"HTTP/1.1 100 Continue\r\nX-Info: first\r\n\r\nHTTP/1.1 200 Connection Established\r\nX-Duplicate: one\r\nX-Duplicate: two\r\n\r\n";
        for split in 0..=bytes.len() {
            let mut parser =
                ConnectResponseParser::new(ProxyProtocolLimits::default()).expect("parser");
            let left = parser.feed(&bytes[..split]).expect("left");
            let response = match left {
                ParseProgress::Complete(response) => response,
                ParseProgress::NeedMore => {
                    let ParseProgress::Complete(response) =
                        parser.feed(&bytes[split..]).expect("right")
                    else {
                        panic!("split {split} did not complete")
                    };
                    response
                }
            };
            assert_eq!(response.informational().len(), 1);
            assert_eq!(response.status(), 200);
            assert_eq!(
                response
                    .final_response()
                    .headers()
                    .values("x-duplicate")
                    .len(),
                2
            );
        }
    }

    #[test]
    fn response_rejects_status_bodies_framing_upgrade_auth_and_surplus() {
        let cases = [
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".as_slice(),
                "http.proxy.framing-forbidden",
            ),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
                "http.proxy.framing-forbidden",
            ),
            (
                b"HTTP/1.1 200 OK\r\nUpgrade: h2c\r\n\r\n",
                "http.proxy.upgrade-unsupported",
            ),
            (
                b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n",
                "http.proxy.auth-challenge",
            ),
            (
                b"HTTP/1.1 502 Bad Gateway\r\n\r\n",
                "http.proxy.connect-status",
            ),
            (
                b"HTTP/1.1 200 OK\r\n\r\nTUNNEL",
                "http.proxy.response-surplus",
            ),
        ];
        for (bytes, code) in cases {
            let error = parse_connect_response(bytes).expect_err("must reject");
            assert_eq!(error.code(), code);
        }
    }

    #[test]
    fn malformed_and_limit_inputs_fail_closed() {
        assert_eq!(
            parse_request_head(b"GET / HTTP/1.0\r\nHost: x:80\r\n\r\n")
                .expect_err("version")
                .code(),
            "http.proxy.unsupported-protocol"
        );
        assert_eq!(
            parse_request_head(b"GET / HTTP/1.1\r\nHost: x:80\r\nContent-Length: 1\r\n\r\n")
                .expect_err("body")
                .code(),
            "http.proxy.framing-forbidden"
        );
        assert_eq!(
            parse_request_head(
                b"GET / HTTP/1.1\r\nHost: x:80\r\nProxy-Authorization: Basic leaked\r\n\r\n"
            )
            .expect_err("raw credential")
            .code(),
            "http.proxy.credential-header"
        );
        assert_eq!(
            parse_request_head(
                b"GET https://origin.test:443/ HTTP/1.1\r\nHost: origin.test:443\r\n\r\n"
            )
            .expect_err("https absolute form")
            .code(),
            "http.proxy.invalid-request-target"
        );
        assert_eq!(
            parse_request_head(b"GET /bad%2 HTTP/1.1\r\nHost: x:80\r\n\r\n")
                .expect_err("bad percent encoding")
                .code(),
            "http.proxy.invalid-request-target"
        );
        let limits = ProxyProtocolLimits {
            max_header_count: 1,
            ..ProxyProtocolLimits::default()
        };
        let error = parse_request_head_with_limits(
            b"GET / HTTP/1.1\r\nHost: x:80\r\nX: y\r\n\r\n",
            &limits,
        )
        .expect_err("header count");
        assert_eq!(error.code(), "http.proxy.limit.header-count");
        let mut parser = ConnectResponseParser::new(ProxyProtocolLimits {
            max_response_head_bytes: 8,
            ..ProxyProtocolLimits::default()
        })
        .expect("limits");
        assert_eq!(
            parser.feed(b"HTTP/1.1 200").expect_err("head limit").code(),
            "http.proxy.limit.response-head"
        );
    }

    #[test]
    fn header_wire_length_overflow_is_typed() {
        for (name_bytes, value_bytes) in [
            (usize::MAX, 0),
            (usize::MAX - 2, 0),
            (usize::MAX - 3, usize::MAX),
        ] {
            assert_eq!(
                checked_wire_len(name_bytes, value_bytes)
                    .expect_err("wire-length arithmetic must be checked")
                    .code(),
                "http.proxy.limit.header-aggregate"
            );
        }
        assert_eq!(checked_wire_len(1, 1).expect("small field length"), 6);
    }

    #[test]
    fn credential_reference_and_material_debug_are_redacted() {
        let reference = ProxyCredentialReference::new(identity(5), identity(6));
        let password = b"super-secret-password";
        let material =
            ProxyCredentialMaterial::new(&reference, "fixture", password).expect("material");
        let debug_reference = format!("{reference:?}");
        let debug_material = format!("{material:?}");
        assert!(!debug_reference.contains("super-secret"));
        assert!(!debug_material.contains("super-secret"));
        assert!(!debug_material.contains("fixture"));
        assert_eq!(
            format!("{error:?}", error = ProxyProtocolError::CredentialMismatch),
            "http.proxy.credential-mismatch"
        );

        let route = RouteRecipe::https_connect_with(
            endpoint(1, "proxy.test:3128"),
            ProxyScheme::Http,
            endpoint(2, "origin.test:443"),
            None,
            OriginTlsIdentity::new(identity(3)),
            Some(reference),
            [0; 32],
        )
        .expect("route");
        let request = route
            .connect_head(&empty_headers(), Some(&material))
            .expect("credential request");
        assert!(String::from_utf8_lossy(request.as_bytes()).contains("Basic "));
        assert!(
            String::from_utf8_lossy(request.as_bytes())
                .contains("Zml4dHVyZTpzdXBlci1zZWNyZXQtcGFzc3dvcmQ=")
        );
        let route_debug = format!("{route:?}");
        assert!(!route_debug.contains("super-secret"));
        let tunneled = route
            .tunneled_request_head("GET", "/", &empty_headers())
            .expect("origin head must not require proxy material");
        assert!(!String::from_utf8_lossy(tunneled.as_bytes()).contains("Proxy-Authorization"));

        let forward = RouteRecipe::http_forward_with(
            endpoint(1, "proxy.test:3128"),
            ProxyScheme::Http,
            endpoint(2, "origin.test:80"),
            None,
            Some(reference),
            [0; 32],
        )
        .expect("forward route");
        let forward_head = forward
            .request_head("GET", "/", &empty_headers(), Some(&material))
            .expect("forward auth request");
        assert!(String::from_utf8_lossy(forward_head.as_bytes()).contains("Proxy-Authorization"));
    }

    #[test]
    fn no_body_or_proxy_auth_can_cross_into_tunnel_origin_head() {
        let route = RouteRecipe::https_connect(
            endpoint(1, "proxy.test:3128"),
            endpoint(2, "origin.test:443"),
            OriginTlsIdentity::new(identity(3)),
        )
        .expect("route");
        let mut headers = OrderedHeaders::new();
        headers
            .push(HeaderField::new("Proxy-Authorization", "Basic leaked").expect("header"))
            .expect("push");
        assert_eq!(
            route
                .tunneled_request_head("GET", "/", &headers)
                .expect_err("proxy auth")
                .code(),
            "http.proxy.credential-header"
        );
        assert!(
            route
                .connect_head(&empty_headers(), None)
                .expect("connect")
                .as_bytes()
                .ends_with(b"\r\n\r\n"),
        );
    }
}
