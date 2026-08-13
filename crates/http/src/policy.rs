// SPDX-License-Identifier: Apache-2.0
//! Redirect, proxy, TLS, and timeout policy values.

use std::time::Duration;

use crate::{HttpError, Method, TimeoutPhase, Url};

/// Hard upper bound for a single proxy credential component.
pub const HARD_MAX_PROXY_CREDENTIAL_BYTES: usize = 16 * 1024;
/// Hard upper bound for configured no-proxy patterns.
pub const HARD_MAX_NO_PROXY_PATTERNS: usize = 4_096;
/// Hard upper bound for the aggregate no-proxy pattern bytes.
pub const HARD_MAX_NO_PROXY_PATTERN_BYTES: usize = 64 * 1024;
/// Hard upper bound for retained redirect metadata and response bodies.
pub const HARD_MAX_REDIRECT_RETAINED_BYTES: usize = 64 * 1024 * 1024;
/// Hard upper bound for a decompression expansion ratio.
pub const HARD_MAX_DECOMPRESSION_RATIO: u64 = 1_000;
/// Hard upper bound for decoded response bytes produced by decompression.
pub const HARD_MAX_DECOMPRESSED_BYTES: usize = 512 * 1024 * 1024;
/// Hard upper bound accepted for any caller-supplied retained response body
/// limit. This is deliberately the same product ceiling as decoded bytes so
/// a context/constructor cannot raise the bound above the parser maximum.
pub const HARD_MAX_RESPONSE_BODY_BYTES: usize = HARD_MAX_DECOMPRESSED_BYTES;
/// Hard upper bound for codec state retained by a decompressor.
pub const HARD_MAX_DECOMPRESSION_STATE_BYTES: usize = 1024 * 1024;
/// The native policy never permits a transparent transport retry.
pub const HARD_MAX_TRANSPARENT_RETRIES: usize = 0;
/// Hard upper bound for trust-root entries in one TLS configuration.
pub const HARD_MAX_TLS_ROOTS: usize = 128;
/// Hard upper bound for one encoded trust-root entry.
pub const HARD_MAX_TLS_ROOT_BYTES: usize = 1024 * 1024;
/// Hard upper bound for a client identity (certificate chain plus key).
pub const HARD_MAX_TLS_IDENTITY_BYTES: usize = 4 * 1024 * 1024;
/// Hard upper bound for all TLS material in one operation.
pub const HARD_MAX_TLS_MATERIAL_BYTES: usize = 16 * 1024 * 1024;
/// Hard upper bound for any configured timeout or phase budget.
pub const HARD_MAX_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
/// Hard upper bound for semantic authentication challenge attempts.
pub const HARD_MAX_AUTH_CHALLENGES: usize = 1;
/// Hard upper bound for advertised decompression codecs.
pub const HARD_MAX_DECOMPRESSION_CODECS: usize = 3;

/// Validates a caller-supplied retained response-body limit against the
/// product hard maximum. A caller may choose a smaller finite limit, but a
/// value above the hard parser/decompression ceiling is rejected rather than
/// silently clamped or passed to an allocating collector.
pub fn validate_response_body_limit(maximum: usize) -> Result<(), HttpError> {
    if maximum == 0 || maximum > HARD_MAX_RESPONSE_BODY_BYTES {
        return Err(HttpError::resource_limit(
            "response body limit must be non-zero and no greater than the product hard maximum",
        ));
    }
    Ok(())
}

/// Validates limits supplied to a decompression/response observation
/// validator. Both caller controls are checked against the same hard maxima
/// used by concrete response models.
pub fn validate_decompression_limits(
    maximum_decoded_bytes: u64,
    maximum_ratio: u64,
) -> Result<(), HttpError> {
    let hard_decoded_bytes = u64::try_from(HARD_MAX_DECOMPRESSED_BYTES)
        .map_err(|_| HttpError::resource_limit("decompressed response hard maximum"))?;
    if maximum_decoded_bytes == 0 || maximum_decoded_bytes > hard_decoded_bytes {
        return Err(HttpError::resource_limit(
            "decompressed response limit exceeds product hard maximum",
        ));
    }
    if maximum_ratio == 0 || maximum_ratio > HARD_MAX_DECOMPRESSION_RATIO {
        return Err(HttpError::resource_limit(
            "decompression ratio exceeds product hard maximum",
        ));
    }
    Ok(())
}

/// An HTTP or HTTPS proxy endpoint.
#[derive(Clone, Eq, PartialEq)]
pub struct Proxy {
    scheme: ProxyScheme,
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
}

impl std::fmt::Debug for Proxy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Proxy")
            .field("scheme", &self.scheme)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username.as_ref().map(|_| "<redacted>"))
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl Proxy {
    const MAX_CREDENTIAL_BYTES: usize = HARD_MAX_PROXY_CREDENTIAL_BYTES;

    /// Creates an unauthenticated proxy endpoint.
    pub fn new(scheme: ProxyScheme, host: impl Into<String>, port: u16) -> Result<Self, HttpError> {
        let host = normalize_proxy_host(&host.into())?;
        if port == 0 {
            return Err(HttpError::Proxy("proxy port must be non-zero".to_owned()));
        }
        Ok(Self {
            scheme,
            host: host.to_ascii_lowercase(),
            port,
            username: None,
            password: None,
        })
    }

    /// Parses `http://host:port` or `https://host:port`.
    pub fn parse(value: impl Into<String>) -> Result<Self, HttpError> {
        let url = Url::parse(value)?;
        if url.path_and_query() != "/" || url.fragment().is_some() {
            return Err(HttpError::Proxy(
                "proxy URL must not contain a path, query, or fragment".to_owned(),
            ));
        }
        let scheme = ProxyScheme::parse(url.scheme())?;
        Self::new(scheme, url.host(), url.port())
    }

    /// Configures proxy credentials. Credentials are never exposed by Debug.
    ///
    /// Validation happens before either field is replaced, so an invalid
    /// update cannot leave the proxy with a partially changed credential pair
    /// or silently fall back to an unauthenticated route.
    pub fn set_credentials(
        &mut self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<(), HttpError> {
        let username = username.into();
        let password = password.into();
        if username.len() > Self::MAX_CREDENTIAL_BYTES
            || password.len() > Self::MAX_CREDENTIAL_BYTES
        {
            return Err(HttpError::resource_limit("proxy credential bytes"));
        }
        if username
            .bytes()
            .chain(password.bytes())
            .any(|byte| byte < 0x20 || byte == 0x7f)
        {
            return Err(HttpError::Proxy(
                "proxy credentials contain a control byte".to_owned(),
            ));
        }
        self.username = Some(username);
        self.password = Some(password);
        Ok(())
    }

    /// Returns the proxy scheme.
    #[must_use]
    pub const fn scheme(&self) -> ProxyScheme {
        self.scheme
    }

    /// Returns the proxy host.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Returns the proxy port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Returns configured credentials to a transport adapter.
    #[must_use]
    pub fn credentials(&self) -> Option<(&str, &str)> {
        self.username.as_deref().zip(self.password.as_deref())
    }
}

fn normalize_proxy_host(value: &str) -> Result<String, HttpError> {
    if value.is_empty() || value.len() > 255 {
        return Err(HttpError::Proxy(
            "proxy host is empty or too long".to_owned(),
        ));
    }
    if value.bytes().any(|byte| {
        byte <= 0x20 || byte == 0x7f || matches!(byte, b'@' | b'/' | b'?' | b'#' | b'%')
    }) {
        return Err(HttpError::Proxy(
            "proxy host contains userinfo, path, query, or control syntax".to_owned(),
        ));
    }
    let bracketed = value.starts_with('[') || value.ends_with(']');
    let host = if bracketed {
        let Some(host) = value
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
        else {
            return Err(HttpError::Proxy(
                "proxy IPv6 host brackets are unbalanced".to_owned(),
            ));
        };
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(HttpError::Proxy(
                "brackets are only valid around an IPv6 proxy host".to_owned(),
            ));
        }
        host
    } else {
        value
    };
    if host.is_empty() {
        return Err(HttpError::Proxy("proxy host is empty".to_owned()));
    }
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        return Ok(host.to_ascii_lowercase());
    }
    if host.parse::<std::net::Ipv4Addr>().is_ok() || valid_proxy_dns_host(host) {
        return Ok(host.to_ascii_lowercase());
    }
    Err(HttpError::Proxy(
        "proxy host is not a valid IP or DNS name".to_owned(),
    ))
}

fn valid_proxy_dns_host(value: &str) -> bool {
    if value.is_empty() || value.len() > 255 {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

/// Supported proxy endpoint schemes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProxyScheme {
    /// Clear-text HTTP proxy, including CONNECT for HTTPS origins.
    Http,
    /// HTTPS proxy endpoint.
    Https,
}

impl ProxyScheme {
    /// Parses a proxy scheme.
    pub fn parse(value: &str) -> Result<Self, HttpError> {
        match value.to_ascii_lowercase().as_str() {
            "http" => Ok(Self::Http),
            "https" => Ok(Self::Https),
            _ => Err(HttpError::Proxy(format!(
                "unsupported proxy scheme {value:?}"
            ))),
        }
    }
}

/// Pipe-separated host patterns used by JMeter's `nonProxyHosts` option.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NoProxy {
    patterns: Vec<NoProxyPattern>,
    pattern_bytes: usize,
}

impl NoProxy {
    const MAX_PATTERNS: usize = HARD_MAX_NO_PROXY_PATTERNS;
    const MAX_PATTERN_BYTES: usize = 256;
    const MAX_PATTERN_TOTAL_BYTES: usize = HARD_MAX_NO_PROXY_PATTERN_BYTES;

    /// Parses `|`-separated patterns. Empty patterns are ignored; malformed
    /// or over-budget patterns return a typed proxy error.
    pub fn parse(value: &str) -> Result<Self, HttpError> {
        let mut no_proxy = Self::none();
        for pattern in value.split('|') {
            no_proxy.add(pattern)?;
        }
        Ok(no_proxy)
    }

    /// Creates no bypass patterns.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            patterns: Vec::new(),
            pattern_bytes: 0,
        }
    }

    /// Adds one bypass pattern.
    pub fn add(&mut self, pattern: impl Into<String>) -> Result<(), HttpError> {
        let pattern = pattern.into();
        let Some(pattern) = NoProxyPattern::parse(&pattern)? else {
            return Ok(());
        };
        if self.patterns.len() >= Self::MAX_PATTERNS {
            return Err(HttpError::resource_limit("no-proxy pattern count"));
        }
        let proposed = self
            .pattern_bytes
            .checked_add(pattern.raw.len())
            .ok_or_else(|| HttpError::resource_limit("no-proxy pattern bytes"))?;
        if proposed > Self::MAX_PATTERN_TOTAL_BYTES {
            return Err(HttpError::resource_limit("no-proxy pattern bytes"));
        }
        self.pattern_bytes = proposed;
        self.patterns.push(pattern);
        Ok(())
    }

    /// Returns whether the URL should bypass its configured proxy.
    #[must_use]
    pub fn matches(&self, url: &Url) -> bool {
        self.patterns.iter().any(|pattern| pattern.matches(url))
    }

    /// Returns patterns in insertion order.
    #[must_use]
    pub fn patterns(&self) -> impl ExactSizeIterator<Item = &str> {
        self.patterns.iter().map(|pattern| pattern.raw.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NoProxyPattern {
    raw: String,
    host: String,
    port: Option<u16>,
    wildcard: bool,
}

impl NoProxyPattern {
    fn parse(value: &str) -> Result<Option<Self>, HttpError> {
        if value.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
            return Err(HttpError::Proxy(
                "no-proxy pattern contains a control or whitespace byte".to_owned(),
            ));
        }
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        if trimmed.len() > NoProxy::MAX_PATTERN_BYTES {
            return Err(HttpError::resource_limit("no-proxy pattern bytes"));
        }
        if trimmed == "*" {
            return Ok(Some(Self {
                raw: trimmed.to_owned(),
                host: String::new(),
                port: None,
                wildcard: true,
            }));
        }
        let without_scheme = trimmed
            .strip_prefix("http://")
            .or_else(|| trimmed.strip_prefix("https://"))
            .unwrap_or(trimmed);
        if without_scheme
            .bytes()
            .any(|byte| matches!(byte, b'/' | b'?' | b'#' | b'@'))
        {
            return Err(HttpError::Proxy(
                "no-proxy pattern must contain only a host and optional port".to_owned(),
            ));
        }
        let authority = without_scheme;
        if authority.is_empty() {
            return Err(HttpError::Proxy("invalid no-proxy pattern".to_owned()));
        }
        let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
            let close = stripped
                .find(']')
                .ok_or_else(|| HttpError::Proxy("unterminated no-proxy IPv6 pattern".to_owned()))?;
            let host = stripped[..close].to_ascii_lowercase();
            if host.parse::<std::net::Ipv6Addr>().is_err() {
                return Err(HttpError::Proxy(
                    "brackets are only valid around an IPv6 no-proxy host".to_owned(),
                ));
            }
            let suffix = &stripped[close + 1..];
            let port = if suffix.is_empty() {
                None
            } else {
                let value = suffix
                    .strip_prefix(':')
                    .ok_or_else(|| HttpError::Proxy("invalid no-proxy IPv6 port".to_owned()))?;
                Some(parse_no_proxy_port(value)?)
            };
            (host, port)
        } else if let Some(index) = authority.rfind(':') {
            let suffix = &authority[index + 1..];
            if !authority[..index].contains(':') {
                (
                    authority[..index].to_ascii_lowercase(),
                    Some(parse_no_proxy_port(suffix)?),
                )
            } else {
                (authority.to_ascii_lowercase(), None)
            }
        } else {
            (authority.to_ascii_lowercase(), None)
        };
        if host.is_empty() || host.len() > 255 {
            return Err(HttpError::Proxy("invalid no-proxy host".to_owned()));
        }
        if !valid_no_proxy_host(&host) {
            return Err(HttpError::Proxy("invalid no-proxy host".to_owned()));
        }
        Ok(Some(Self {
            raw: trimmed.to_owned(),
            host,
            port,
            wildcard: false,
        }))
    }

    fn matches(&self, url: &Url) -> bool {
        if self.wildcard {
            return true;
        }
        if self.port.is_some_and(|port| port != url.port()) {
            return false;
        }
        let host = url.host().to_ascii_lowercase();
        if let Some(suffix) = self.host.strip_prefix("*.") {
            host == suffix || host.ends_with(&format!(".{suffix}"))
        } else if let Some(suffix) = self.host.strip_prefix('.') {
            host == suffix || host.ends_with(&format!(".{suffix}"))
        } else if self.host.contains('*') {
            wildcard_match(&self.host, &host)
        } else {
            host == self.host
        }
    }
}

fn valid_no_proxy_host(value: &str) -> bool {
    if value.parse::<std::net::Ipv4Addr>().is_ok() || value.parse::<std::net::Ipv6Addr>().is_ok() {
        return true;
    }
    let value = value.strip_prefix("*.").unwrap_or(value);
    let value = value.strip_prefix('.').unwrap_or(value);
    if value.is_empty() || value.len() > 255 || value.contains(':') {
        return false;
    }
    value.split('.').all(|label| {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        let first = label
            .bytes()
            .find(|byte| *byte != b'*')
            .filter(|byte| byte.is_ascii_alphanumeric());
        let last = label
            .bytes()
            .rfind(|byte| *byte != b'*')
            .filter(|byte| byte.is_ascii_alphanumeric());
        first.is_some()
            && last.is_some()
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'*'))
    })
}

fn parse_no_proxy_port(value: &str) -> Result<u16, HttpError> {
    let port = value
        .parse::<u16>()
        .map_err(|_| HttpError::Proxy("invalid no-proxy port".to_owned()))?;
    if port == 0 {
        return Err(HttpError::Proxy(
            "no-proxy port must be non-zero".to_owned(),
        ));
    }
    Ok(port)
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    let mut pattern_parts = pattern.split('*');
    let Some(first) = pattern_parts.next() else {
        return true;
    };
    if !value.starts_with(first) {
        return false;
    }
    let mut offset = first.len();
    let parts: Vec<&str> = pattern_parts.collect();
    for (index, part) in parts.iter().enumerate() {
        if index + 1 == parts.len() {
            return value[offset..].ends_with(part);
        }
        let Some(found) = value[offset..].find(part) else {
            return false;
        };
        offset += found + part.len();
    }
    true
}

/// A proxy selection policy with explicit HTTP and HTTPS endpoints.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProxyPolicy {
    /// HTTP-origin proxy.
    pub http: Option<Proxy>,
    /// HTTPS-origin proxy.
    pub https: Option<Proxy>,
    /// Hosts that bypass both proxy endpoints.
    pub no_proxy: NoProxy,
}

impl ProxyPolicy {
    /// Validates endpoint and no-proxy resource bounds.
    pub fn validate(&self) -> Result<(), HttpError> {
        if self.no_proxy.patterns.len() > HARD_MAX_NO_PROXY_PATTERNS
            || self.no_proxy.pattern_bytes > HARD_MAX_NO_PROXY_PATTERN_BYTES
        {
            return Err(HttpError::resource_limit("no-proxy policy bounds"));
        }
        for proxy in [self.http.as_ref(), self.https.as_ref()]
            .into_iter()
            .flatten()
        {
            if proxy.credentials().is_some_and(|(username, password)| {
                username.len() > HARD_MAX_PROXY_CREDENTIAL_BYTES
                    || password.len() > HARD_MAX_PROXY_CREDENTIAL_BYTES
            }) {
                return Err(HttpError::resource_limit("proxy credential bytes"));
            }
        }
        Ok(())
    }

    /// Selects a route for a URL without consulting ambient environment state.
    #[must_use]
    pub fn route(&self, url: &Url) -> Route {
        if self.no_proxy.matches(url) {
            return Route::Direct;
        }
        let proxy = match url.scheme() {
            "http" => self.http.as_ref(),
            "https" => self.https.as_ref().or(self.http.as_ref()),
            _ => None,
        };
        proxy.map_or(Route::Direct, |proxy| Route::Proxy(proxy.clone()))
    }
}

/// The selected route passed to a transport adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Route {
    /// Connect directly to the origin.
    Direct,
    /// Connect through this explicitly configured proxy.
    Proxy(Proxy),
}

/// Redirect handling policy for the semantic client's one-hop state machine.
///
/// This policy intentionally models manual semantic following only. Provider
/// automatic-redirect switches (including JMeter's HttpClient4 mode) are not
/// represented here; the selected adapter must reject or implement that
/// capability explicitly rather than silently changing this state machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedirectPolicy {
    /// Whether redirects are followed.
    pub follow: bool,
    /// Maximum number of followed redirects.
    pub maximum: usize,
    /// Whether cross-origin redirects are allowed.
    pub allow_cross_origin: bool,
    /// Whether `Authorization` may cross an origin boundary.
    pub forward_authorization: bool,
    /// Maximum metadata and response bytes retained across redirect hops.
    pub maximum_retained_bytes: usize,
}

/// Absolute safety ceiling for redirects, independent of user configuration.
pub const HARD_MAX_REDIRECTS: usize = 64;

impl Default for RedirectPolicy {
    fn default() -> Self {
        Self {
            follow: true,
            maximum: 20,
            allow_cross_origin: true,
            forward_authorization: false,
            maximum_retained_bytes: HARD_MAX_REDIRECT_RETAINED_BYTES,
        }
    }
}

impl RedirectPolicy {
    /// Validates the configured redirect count against the hard safety cap.
    pub fn validate(&self) -> Result<(), HttpError> {
        if self.maximum > HARD_MAX_REDIRECTS {
            return Err(HttpError::resource_limit("redirect count hard limit"));
        }
        if self.maximum_retained_bytes == 0
            || self.maximum_retained_bytes > HARD_MAX_REDIRECT_RETAINED_BYTES
        {
            return Err(HttpError::resource_limit(
                "redirect retained-bytes hard limit",
            ));
        }
        Ok(())
    }

    /// Checks whether retaining one more bounded hop stays within policy.
    pub fn retain(
        &self,
        retained_bytes: usize,
        additional_bytes: usize,
    ) -> Result<usize, HttpError> {
        self.validate()?;
        let next = retained_bytes
            .checked_add(additional_bytes)
            .ok_or_else(|| HttpError::resource_limit("redirect retained bytes"))?;
        if next > self.maximum_retained_bytes {
            return Err(HttpError::resource_limit("redirect retained bytes"));
        }
        Ok(next)
    }

    /// Returns the method to use for one redirect status.
    ///
    /// 301/302/303 rewrite non-GET/HEAD methods to GET, while 307/308 retain
    /// the original method so the caller can replay its body only when the
    /// request representation is materialized and bounded.
    #[must_use]
    pub fn redirected_method(status: u16, method: &Method) -> Method {
        match status {
            301..=303 if !matches!(method, Method::Get | Method::Head) => Method::Get,
            _ => method.clone(),
        }
    }
}

/// TLS protocol versions understood by the semantic policy.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TlsVersion {
    /// TLS 1.2.
    Tls1_2,
    /// TLS 1.3.
    Tls1_3,
}

/// Certificate verification mode.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TlsVerification {
    /// Verify the peer against configured roots.
    Verify,
    /// Skip certificate verification only when explicitly requested.
    Insecure,
}

/// Trust-root source selected by the application for one TLS operation.
///
/// The default never consults process, OS, or JVM trust-store state. Platform
/// roots require an explicit adapter selection and recorded provider identity.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum TlsTrustSource {
    /// Use only roots supplied in [`TlsConfig::extra_roots`].
    #[default]
    Explicit,
    /// Use an explicitly selected platform-root adapter.
    Platform,
}

/// HTTP protocol negotiation policy supplied to a transport adapter.
///
/// `Http11Only` is the default JMeter comparison policy.  Negotiation is an
/// explicit opt-in; a client library must never opportunistically enable
/// HTTP/2 merely because ALPN or a platform default makes it available.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum HttpVersionPolicy {
    /// Use HTTP/1.1 only.
    #[default]
    Http11Only,
    /// Negotiate HTTP/1.1 or HTTP/2 through an explicit adapter policy.
    Negotiated,
    /// Require HTTP/2; no fallback to HTTP/1.1 is permitted.
    Http2Only,
}

impl HttpVersionPolicy {
    /// Returns whether this policy permits HTTP/1.1.
    #[must_use]
    pub const fn allows_http11(self) -> bool {
        matches!(self, Self::Http11Only | Self::Negotiated)
    }

    /// Returns whether this policy permits HTTP/2.
    #[must_use]
    pub const fn allows_http2(self) -> bool {
        matches!(self, Self::Negotiated | Self::Http2Only)
    }
}

/// Content codec explicitly admitted for response decompression.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CompressionCodec {
    /// gzip content coding.
    Gzip,
    /// deflate content coding.
    Deflate,
    /// Brotli content coding.
    Brotli,
}

/// Explicit decompression policy and expansion bounds.
///
/// The default is [`DecompressionPolicy::Disabled`].  A transport must reject
/// compressed input when disabled; it may not silently enable a convenience
/// decoder or report decoded bytes as wire bytes.  `Enabled` carries every
/// active bound needed by a decoder so an adapter cannot inherit an ambient
/// library limit.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum DecompressionPolicy {
    /// Do not decode any content coding.
    #[default]
    Disabled,
    /// Decode only the listed codecs under the listed finite limits.
    Enabled {
        /// Ordered, duplicate-free codec allowlist.
        codecs: Vec<CompressionCodec>,
        /// Maximum decoded-to-wire expansion ratio.
        maximum_expansion_ratio: u64,
        /// Maximum decoded bytes retained for one response.
        maximum_output_bytes: usize,
        /// Maximum codec state retained while decoding.
        maximum_state_bytes: usize,
    },
}

impl DecompressionPolicy {
    /// Creates a bounded policy admitting the three native codecs.
    #[must_use]
    pub fn common() -> Self {
        Self::Enabled {
            codecs: vec![
                CompressionCodec::Gzip,
                CompressionCodec::Deflate,
                CompressionCodec::Brotli,
            ],
            maximum_expansion_ratio: HARD_MAX_DECOMPRESSION_RATIO,
            maximum_output_bytes: HARD_MAX_DECOMPRESSED_BYTES,
            maximum_state_bytes: HARD_MAX_DECOMPRESSION_STATE_BYTES,
        }
    }

    /// Returns whether compressed response bodies may be decoded.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        matches!(self, Self::Enabled { .. })
    }

    /// Returns whether a codec is explicitly admitted.
    #[must_use]
    pub fn allows(&self, codec: CompressionCodec) -> bool {
        match self {
            Self::Disabled => false,
            Self::Enabled { codecs, .. } => codecs.contains(&codec),
        }
    }

    /// Validates codec identity and all expansion/state bounds.
    pub fn validate(&self) -> Result<(), HttpError> {
        let Self::Enabled {
            codecs,
            maximum_expansion_ratio,
            maximum_output_bytes,
            maximum_state_bytes,
        } = self
        else {
            return Ok(());
        };
        if codecs.is_empty() || codecs.len() > HARD_MAX_DECOMPRESSION_CODECS {
            return Err(HttpError::resource_limit("decompression codec count"));
        }
        if codecs
            .iter()
            .enumerate()
            .any(|(index, codec)| codecs[..index].contains(codec))
        {
            return Err(HttpError::InvalidHeader(
                "decompression codec allowlist contains duplicates".to_owned(),
            ));
        }
        if *maximum_expansion_ratio == 0 || *maximum_expansion_ratio > HARD_MAX_DECOMPRESSION_RATIO
        {
            return Err(HttpError::resource_limit("decompression expansion ratio"));
        }
        if *maximum_output_bytes == 0 || *maximum_output_bytes > HARD_MAX_DECOMPRESSED_BYTES {
            return Err(HttpError::resource_limit("decompressed output bytes"));
        }
        if *maximum_state_bytes == 0 || *maximum_state_bytes > HARD_MAX_DECOMPRESSION_STATE_BYTES {
            return Err(HttpError::resource_limit("decompression codec state bytes"));
        }
        Ok(())
    }
}

/// Retry ownership policy for one logical sampler.
///
/// Transparent transport retries are permanently disabled in this semantic
/// core.  Redirects and explicitly admitted authentication challenges are
/// semantic retries and produce a distinct request/attempt.  A native edge
/// adapter must reject any configuration that attempts to raise the
/// transparent count above zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    /// Number of transparent adapter retries.  This must remain zero.
    pub maximum_transparent_retries: usize,
    /// Number of semantic authentication challenges to follow.
    pub maximum_auth_challenges: usize,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            maximum_transparent_retries: HARD_MAX_TRANSPARENT_RETRIES,
            maximum_auth_challenges: HARD_MAX_AUTH_CHALLENGES,
        }
    }
}

impl RetryPolicy {
    /// Validates retry ownership and finite challenge bounds.
    pub fn validate(&self) -> Result<(), HttpError> {
        if self.maximum_transparent_retries > HARD_MAX_TRANSPARENT_RETRIES {
            return Err(HttpError::Unsupported(
                "transparent HTTP retries are disabled; use semantic retries".to_owned(),
            ));
        }
        if self.maximum_auth_challenges > HARD_MAX_AUTH_CHALLENGES {
            return Err(HttpError::resource_limit("authentication challenge count"));
        }
        Ok(())
    }

    /// Returns whether an adapter may retry without a new semantic attempt.
    #[must_use]
    pub const fn transparent_retries_enabled(self) -> bool {
        self.maximum_transparent_retries != 0
    }
}

/// Explicit TLS policy passed to a transport adapter.
#[derive(Clone, Eq, PartialEq)]
pub struct TlsConfig {
    /// Certificate verification mode.
    pub verification: TlsVerification,
    /// Explicit source for trust roots.
    pub trust_source: TlsTrustSource,
    /// Minimum negotiated protocol version.
    pub minimum_version: TlsVersion,
    /// Maximum negotiated protocol version.
    pub maximum_version: TlsVersion,
    /// DER-encoded additional trust roots.
    pub extra_roots: Vec<Vec<u8>>,
    /// Optional client certificate/key material owned by the adapter.
    pub client_identity: Option<ClientIdentity>,
    /// Whether the adapter should send SNI for the origin host.
    pub use_sni: bool,
}

impl std::fmt::Debug for TlsConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TlsConfig")
            .field("verification", &self.verification)
            .field("trust_source", &self.trust_source)
            .field("minimum_version", &self.minimum_version)
            .field("maximum_version", &self.maximum_version)
            .field("extra_root_count", &self.extra_roots.len())
            .field(
                "extra_root_bytes",
                &self
                    .extra_roots
                    .iter()
                    .try_fold(0usize, |total, root| total.checked_add(root.len())),
            )
            .field("client_identity", &self.client_identity)
            .field("use_sni", &self.use_sni)
            .finish()
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            verification: TlsVerification::Verify,
            trust_source: TlsTrustSource::Explicit,
            minimum_version: TlsVersion::Tls1_2,
            maximum_version: TlsVersion::Tls1_3,
            extra_roots: Vec::new(),
            client_identity: None,
            use_sni: true,
        }
    }
}

impl TlsConfig {
    /// Explicit JMeter-compatible opt-in for deployments that intentionally
    /// accept untrusted certificates.  The normal default remains verified so
    /// callers cannot silently inherit the compatibility profile's weaker
    /// trust behavior.
    #[must_use]
    pub fn jmeter_compatibility() -> Self {
        Self {
            verification: TlsVerification::Insecure,
            ..Self::default()
        }
    }

    /// Explicitly opts into an adapter backed by platform trust roots.
    #[must_use]
    pub fn with_platform_roots() -> Self {
        Self {
            trust_source: TlsTrustSource::Platform,
            ..Self::default()
        }
    }
}

impl TlsConfig {
    /// Checks protocol ordering and root/identity bounds.
    pub fn validate(&self, maximum_material_bytes: usize) -> Result<(), HttpError> {
        if maximum_material_bytes == 0 {
            return Err(HttpError::resource_limit("TLS material limit"));
        }
        if self.minimum_version > self.maximum_version {
            return Err(HttpError::Tls(
                "minimum TLS version exceeds maximum".to_owned(),
            ));
        }
        if self.extra_roots.len() > HARD_MAX_TLS_ROOTS {
            return Err(HttpError::resource_limit("TLS trust-root count"));
        }
        let roots = self
            .extra_roots
            .iter()
            .try_fold(0usize, |total, root| {
                if root.is_empty() || root.len() > HARD_MAX_TLS_ROOT_BYTES {
                    return None;
                }
                total.checked_add(root.len())
            })
            .ok_or_else(|| HttpError::resource_limit("TLS trust-root bytes"))?;
        let identity = self.client_identity.as_ref().map_or(Ok(0), |identity| {
            if identity.certificate_chain.is_empty() || identity.private_key.is_empty() {
                return Err(HttpError::Tls(
                    "TLS client identity must contain certificate and private key material"
                        .to_owned(),
                ));
            }
            let length = identity.checked_len()?;
            if length > HARD_MAX_TLS_IDENTITY_BYTES {
                return Err(HttpError::resource_limit("TLS client identity bytes"));
            }
            Ok(length)
        })?;
        let actual = roots
            .checked_add(identity)
            .ok_or_else(|| HttpError::resource_limit("TLS material bytes"))?;
        if actual > maximum_material_bytes.min(HARD_MAX_TLS_MATERIAL_BYTES) {
            return Err(HttpError::resource_limit("TLS material bytes"));
        }
        Ok(())
    }
}

/// Client certificate and private-key material handed to a TLS adapter.
#[derive(Clone, Eq, PartialEq)]
pub struct ClientIdentity {
    certificate_chain: Vec<u8>,
    private_key: Vec<u8>,
}

impl std::fmt::Debug for ClientIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientIdentity")
            .field("certificate_chain_bytes", &self.certificate_chain.len())
            .field("private_key", &"<redacted>")
            .finish()
    }
}

impl ClientIdentity {
    /// Creates an identity from DER/adapter-specific material.
    #[must_use]
    pub fn new(certificate_chain: impl Into<Vec<u8>>, private_key: impl Into<Vec<u8>>) -> Self {
        Self {
            certificate_chain: certificate_chain.into(),
            private_key: private_key.into(),
        }
    }

    /// Returns certificate bytes.
    #[must_use]
    pub fn certificate_chain(&self) -> &[u8] {
        &self.certificate_chain
    }

    /// Returns private-key bytes to a transport adapter.
    #[must_use]
    pub fn private_key(&self) -> &[u8] {
        &self.private_key
    }

    /// Returns total identity material size.
    #[must_use]
    #[deprecated(note = "use checked_len for typed overflow handling")]
    pub fn len(&self) -> usize {
        self.checked_len().unwrap_or(usize::MAX)
    }

    /// Returns identity size without saturating on arithmetic overflow.
    pub fn checked_len(&self) -> Result<usize, HttpError> {
        self.certificate_chain
            .len()
            .checked_add(self.private_key.len())
            .ok_or_else(|| HttpError::resource_limit("TLS identity material bytes"))
    }

    /// Returns whether both identity components are empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.certificate_chain.is_empty() && self.private_key.is_empty()
    }
}

/// Per-operation phase timeouts. Phase-specific fields may be `None`, but a
/// client operation always requires a finite overall deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimeoutConfig {
    /// Overall logical request limit.
    pub overall: Option<Duration>,
    /// Connection-establishment limit.
    pub connect: Option<Duration>,
    /// Request-write limit.
    pub write: Option<Duration>,
    /// Response-read limit.
    pub read: Option<Duration>,
    /// TLS-handshake limit.
    pub tls: Option<Duration>,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            overall: Some(Duration::from_secs(120)),
            connect: None,
            write: None,
            read: None,
            tls: None,
        }
    }
}

impl TimeoutConfig {
    /// Validates finite, non-zero timeout values.
    pub fn validate(&self) -> Result<(), HttpError> {
        let phases = [self.overall, self.connect, self.write, self.read, self.tls];
        if self.overall.is_none()
            || phases
                .iter()
                .flatten()
                .any(|duration| duration.is_zero() || *duration > HARD_MAX_TIMEOUT)
        {
            return Err(HttpError::InvalidTimeout(
                "overall and configured phase timeouts must be finite, non-zero, and no greater than 24 hours"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Returns a configured phase duration.
    #[must_use]
    pub const fn for_phase(self, phase: TimeoutPhase) -> Option<Duration> {
        match phase {
            TimeoutPhase::Overall => self.overall,
            TimeoutPhase::Connect => self.connect,
            TimeoutPhase::Write => self.write,
            TimeoutPhase::Read => self.read,
            TimeoutPhase::Tls => self.tls,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "policy tests use expect only for fixed bounded fixtures"
    )]

    use super::*;

    #[test]
    fn defaults_are_explicit_and_fail_closed_for_ambient_features() {
        assert_eq!(HttpVersionPolicy::default(), HttpVersionPolicy::Http11Only);
        assert!(HttpVersionPolicy::Http11Only.allows_http11());
        assert!(!HttpVersionPolicy::Http11Only.allows_http2());
        assert!(HttpVersionPolicy::Negotiated.allows_http11());
        assert!(HttpVersionPolicy::Negotiated.allows_http2());
        assert!(!HttpVersionPolicy::Http2Only.allows_http11());
        assert!(HttpVersionPolicy::Http2Only.allows_http2());
        assert!(!DecompressionPolicy::default().is_enabled());
        assert_eq!(RetryPolicy::default().maximum_transparent_retries, 0);
        assert_eq!(RetryPolicy::default().maximum_auth_challenges, 1);
        assert!(ProxyPolicy::default().validate().is_ok());
        assert!(RedirectPolicy::default().validate().is_ok());
        assert_eq!(TlsConfig::default().trust_source, TlsTrustSource::Explicit);
        assert_eq!(
            TlsConfig::with_platform_roots().trust_source,
            TlsTrustSource::Platform
        );
    }

    #[test]
    fn response_body_limit_accepts_exact_hard_bound_without_allocating() {
        assert!(validate_response_body_limit(1).is_ok());
        assert!(validate_response_body_limit(HARD_MAX_RESPONSE_BODY_BYTES).is_ok());
        assert!(validate_response_body_limit(HARD_MAX_RESPONSE_BODY_BYTES + 1).is_err());
        assert!(validate_response_body_limit(usize::MAX).is_err());
        assert!(validate_response_body_limit(0).is_err());
    }

    #[test]
    fn decompression_limit_accepts_exact_hard_bound_and_rejects_overflow() {
        let decoded = u64::try_from(HARD_MAX_DECOMPRESSED_BYTES).expect("hard bound fits u64");
        assert!(validate_decompression_limits(decoded, HARD_MAX_DECOMPRESSION_RATIO).is_ok());
        assert!(validate_decompression_limits(decoded + 1, HARD_MAX_DECOMPRESSION_RATIO).is_err());
        assert!(validate_decompression_limits(decoded, HARD_MAX_DECOMPRESSION_RATIO + 1).is_err());
        assert!(validate_decompression_limits(0, HARD_MAX_DECOMPRESSION_RATIO).is_err());
        assert!(validate_decompression_limits(decoded, 0).is_err());
    }

    #[test]
    fn redirect_retention_is_checked_with_checked_arithmetic() {
        let policy = RedirectPolicy {
            maximum_retained_bytes: 8,
            ..RedirectPolicy::default()
        };
        assert_eq!(policy.retain(3, 5).expect("within bound"), 8);
        assert!(policy.retain(8, 1).is_err());
        assert!(policy.retain(usize::MAX, 1).is_err());
        assert!(
            RedirectPolicy {
                maximum_retained_bytes: 0,
                ..policy
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn redirect_method_policy_distinguishes_rewrite_and_replay_statuses() {
        let post = Method::Post;
        let get = Method::Get;
        let head = Method::Head;
        for status in [301, 302, 303] {
            assert_eq!(
                RedirectPolicy::redirected_method(status, &post),
                Method::Get
            );
            assert_eq!(RedirectPolicy::redirected_method(status, &get), Method::Get);
            assert_eq!(
                RedirectPolicy::redirected_method(status, &head),
                Method::Head
            );
        }
        for status in [307, 308] {
            assert_eq!(
                RedirectPolicy::redirected_method(status, &post),
                Method::Post
            );
            assert_eq!(RedirectPolicy::redirected_method(status, &get), Method::Get);
            assert_eq!(
                RedirectPolicy::redirected_method(status, &head),
                Method::Head
            );
        }
    }

    #[test]
    fn decompression_limits_never_accept_zero_or_hard_overflow() {
        for ratio in 0..=HARD_MAX_DECOMPRESSION_RATIO + 1 {
            let policy = DecompressionPolicy::Enabled {
                codecs: vec![CompressionCodec::Gzip],
                maximum_expansion_ratio: ratio,
                maximum_output_bytes: 1,
                maximum_state_bytes: 1,
            };
            assert_eq!(
                policy.validate().is_ok(),
                (1..=HARD_MAX_DECOMPRESSION_RATIO).contains(&ratio)
            );
        }
        let duplicate = DecompressionPolicy::Enabled {
            codecs: vec![
                CompressionCodec::Gzip,
                CompressionCodec::Deflate,
                CompressionCodec::Gzip,
            ],
            maximum_expansion_ratio: 1,
            maximum_output_bytes: 1,
            maximum_state_bytes: 1,
        };
        assert!(duplicate.validate().is_err());
        assert!(DecompressionPolicy::common().validate().is_ok());
    }

    #[test]
    fn retry_policy_rejects_transparent_retry_and_unbounded_challenges() {
        assert!(!RetryPolicy::default().transparent_retries_enabled());
        assert!(
            RetryPolicy {
                maximum_transparent_retries: 1,
                ..RetryPolicy::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            RetryPolicy {
                maximum_auth_challenges: HARD_MAX_AUTH_CHALLENGES + 1,
                ..RetryPolicy::default()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn tls_and_timeout_material_are_bounded_and_explicit() {
        let mut tls = TlsConfig::default();
        assert!(tls.validate(HARD_MAX_TLS_MATERIAL_BYTES).is_ok());
        tls.extra_roots.push(vec![1]);
        assert!(tls.validate(HARD_MAX_TLS_MATERIAL_BYTES).is_ok());
        tls.extra_roots.push(Vec::new());
        assert!(tls.validate(HARD_MAX_TLS_MATERIAL_BYTES).is_err());

        let empty_identity = ClientIdentity::new(Vec::new(), Vec::new());
        tls.extra_roots.clear();
        tls.client_identity = Some(empty_identity);
        assert!(tls.validate(HARD_MAX_TLS_MATERIAL_BYTES).is_err());

        let timeout = TimeoutConfig {
            read: Some(HARD_MAX_TIMEOUT),
            ..TimeoutConfig::default()
        };
        assert!(timeout.validate().is_ok());
        let invalid_timeout = TimeoutConfig {
            read: Some(HARD_MAX_TIMEOUT + Duration::from_nanos(1)),
            ..timeout
        };
        assert!(invalid_timeout.validate().is_err());
    }
}
