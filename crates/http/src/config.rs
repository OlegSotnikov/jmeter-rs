// SPDX-License-Identifier: Apache-2.0
//! Pure HTTP configuration-element descriptors and lifecycle adapters.
//!
//! This module is deliberately independent of [`crate::HttpClient`].  It
//! models the fields written by JMeter's HTTP configuration elements and
//! provides deterministic scope merging without opening sockets, resolving
//! names, reading files, or consulting process state.  A decoder boundary is
//! represented by [`OpaqueField`] and [`WireConfig`], which retain unhandled
//! fields rather than inventing defaults or discarding plugin data.

use std::fmt;

use crate::{AuthEntry, CacheStore, CookieJar, DnsCache, HttpError, Method, Request, Url};

/// Maximum number of fields retained by one wire configuration element.
pub const MAX_CONFIG_FIELDS: usize = 256;
/// Maximum bytes retained by one wire configuration element.
pub const MAX_CONFIG_BYTES: usize = 128 * 1024;
/// Maximum static DNS hosts in one DNS Cache Manager descriptor.
pub const MAX_STATIC_DNS_HOSTS: usize = 256;
/// Maximum DNS resolver addresses in one DNS Cache Manager descriptor.
pub const MAX_DNS_SERVERS: usize = 32;
/// Maximum authentication entries accepted by one AuthManager descriptor.
pub const MAX_AUTH_ENTRIES: usize = 128;
/// Maximum concurrent embedded-resource workers accepted from an HTTP
/// Request Defaults element.
pub const MAX_CONCURRENT_POOL: u16 = 256;
/// Maximum timeout accepted by an HTTP Request Defaults element.
pub const MAX_HTTP_TIMEOUT_MS: u64 = 86_400_000;
/// Maximum statically configured cookies retained by one Cookie Manager.
pub const MAX_INITIAL_COOKIES: usize = 512;
/// Maximum cache entries accepted by a Cache Manager descriptor.
pub const MAX_CACHE_ENTRIES: usize = 1_000_000;
/// JMeter HTTP sampler defaults that apply when a wire property is absent.
pub const DEFAULT_HTTP_METHOD: &str = "GET";
/// JMeter's default sampler protocol.
pub const DEFAULT_HTTP_PROTOCOL: &str = "http";
/// JMeter's default request content encoding.
pub const DEFAULT_HTTP_CONTENT_ENCODING: &str = "UTF-8";
/// JMeter's semantic redirect default.
pub const DEFAULT_HTTP_FOLLOW_REDIRECTS: bool = true;
/// JMeter's automatic-client-redirect default.
pub const DEFAULT_HTTP_AUTO_REDIRECTS: bool = false;
/// JMeter's persistent-connection default.
pub const DEFAULT_HTTP_KEEPALIVE: bool = true;
/// JMeter's embedded-resource concurrency default.
pub const DEFAULT_HTTP_CONCURRENT_DOWNLOADS: bool = false;
/// JMeter's embedded-resource worker-pool default.
pub const DEFAULT_CONCURRENT_POOL: u16 = 6;
/// JMeter's CacheManager maximum-entry default.
pub const DEFAULT_CACHE_MAX_SIZE: usize = 5_000;
/// JMeter's CookieManager policy default.
pub const DEFAULT_COOKIE_POLICY: &str = "standard";
/// JMeter's CookieManager handler default.
pub const DEFAULT_COOKIE_IMPLEMENTATION: &str =
    "org.apache.jmeter.protocol.http.control.HC4CookieHandler";
/// JMeter wire names used by the HTTP configuration descriptors.
pub const JMX_HTTP_DOMAIN: &str = "HTTPSampler.domain";
/// JMeter HTTP sampler port property.
pub const JMX_HTTP_PORT: &str = "HTTPSampler.port";
/// JMeter HTTP sampler protocol property.
pub const JMX_HTTP_PROTOCOL: &str = "HTTPSampler.protocol";
/// JMeter HTTP sampler method property.
pub const JMX_HTTP_METHOD: &str = "HTTPSampler.method";
/// JMeter HTTP sampler content-encoding property.
pub const JMX_HTTP_CONTENT_ENCODING: &str = "HTTPSampler.contentEncoding";
/// JMeter HTTP sampler path property.
pub const JMX_HTTP_PATH: &str = "HTTPSampler.path";
/// JMeter HTTP sampler implementation property.
pub const JMX_HTTP_IMPLEMENTATION: &str = "HTTPSampler.implementation";
/// JMeter HTTP sampler connect-timeout property.
pub const JMX_HTTP_CONNECT_TIMEOUT: &str = "HTTPSampler.connect_timeout";
/// JMeter HTTP sampler response-timeout property.
pub const JMX_HTTP_RESPONSE_TIMEOUT: &str = "HTTPSampler.response_timeout";
/// JMeter HTTP sampler embedded-download concurrency property.
pub const JMX_HTTP_CONCURRENT_DOWNLOADS: &str = "HTTPSampler.concurrentDwn";
/// JMeter HTTP sampler embedded-download pool property.
pub const JMX_HTTP_CONCURRENT_POOL: &str = "HTTPSampler.concurrentPool";
/// JMeter HTTP sampler proxy-scheme property.
pub const JMX_HTTP_PROXY_SCHEME: &str = "HTTPSampler.proxyScheme";
/// JMeter HTTP sampler proxy-host property.
pub const JMX_HTTP_PROXY_HOST: &str = "HTTPSampler.proxyHost";
/// JMeter HTTP sampler proxy-port property.
pub const JMX_HTTP_PROXY_PORT: &str = "HTTPSampler.proxyPort";
/// JMeter HTTP sampler proxy-user property.
pub const JMX_HTTP_PROXY_USER: &str = "HTTPSampler.proxyUser";
/// JMeter HTTP sampler proxy-password property.
pub const JMX_HTTP_PROXY_PASSWORD: &str = "HTTPSampler.proxyPass";
/// JMeter HTTP sampler semantic-redirect property.
pub const JMX_HTTP_FOLLOW_REDIRECTS: &str = "HTTPSampler.follow_redirects";
/// JMeter HTTP sampler automatic-redirect property.
pub const JMX_HTTP_AUTO_REDIRECTS: &str = "HTTPSampler.auto_redirects";
/// JMeter HTTP sampler keep-alive property.
pub const JMX_HTTP_KEEPALIVE: &str = "HTTPSampler.use_keepalive";
/// JMeter HTTP sampler embedded-resource include expression.
pub const JMX_HTTP_EMBEDDED_URL_REGEX: &str = "HTTPSampler.embedded_url_re";
/// JMeter HTTP sampler embedded-resource exclusion expression.
pub const JMX_HTTP_EMBEDDED_URL_EXCLUDE_REGEX: &str = "HTTPSampler.embedded_url_exclude_re";
/// JMeter DNS manager iteration-reset property.
pub const JMX_DNS_CLEAR_EACH_ITERATION: &str = "DNSCacheManager.clearEachIteration";
/// JMeter DNS manager static-host collection property.
pub const JMX_DNS_HOSTS: &str = "DNSCacheManager.hosts";
/// JMeter DNS manager resolver-server property.
pub const JMX_DNS_SERVERS: &str = "DNSCacheManager.servers";
/// JMeter DNS manager custom-resolver property.
pub const JMX_DNS_CUSTOM_RESOLVER: &str = "DNSCacheManager.isCustomResolver";
/// JMeter cookie manager iteration-reset property.
pub const JMX_COOKIE_CLEAR_EACH_ITERATION: &str = "CookieManager.clearEachIteration";
/// JMeter cookie manager initial-cookie collection property.
pub const JMX_COOKIE_ENTRIES: &str = "CookieManager.cookies";
/// JMeter cookie manager variable-publication property.
pub const JMX_COOKIE_SAVE_COOKIES: &str = "CookieManager.save.cookies";
/// JMeter cookie manager validation property.
pub const JMX_COOKIE_CHECK_COOKIES: &str = "CookieManager.check.cookies";
/// JMeter cookie manager null-cookie deletion property.
pub const JMX_COOKIE_DELETE_NULL_COOKIES: &str = "CookieManager.delete_null_cookies";
/// JMeter cookie manager policy property.
pub const JMX_COOKIE_POLICY: &str = "CookieManager.policy";
/// JMeter cookie manager handler implementation property.
pub const JMX_COOKIE_IMPLEMENTATION: &str = "CookieManager.implementation";
/// JMeter cookie manager thread-group ownership property.
pub const JMX_COOKIE_CONTROLLED_BY_THREAD_GROUP: &str = "CookieManager.controlledByThreadGroup";
/// JMeter cache manager maximum-entry property.
pub const JMX_CACHE_MAX_SIZE: &str = "maxSize";
/// JMeter cache manager iteration-reset property.
pub const JMX_CACHE_CLEAR_EACH_ITERATION: &str = "clearEachIteration";
/// JMeter cache manager thread ownership property.
pub const JMX_CACHE_CONTROLLED_BY_THREAD: &str = "CacheManager.controlledByThread";
/// JMeter cache manager freshness property.
pub const JMX_CACHE_USE_EXPIRES: &str = "useExpires";
/// JMeter auth manager entry collection property.
pub const JMX_AUTH_ENTRIES: &str = "AuthManager.auth_list";
/// JMeter auth manager iteration-reset property.
pub const JMX_AUTH_CLEAR_EACH_ITERATION: &str = "AuthManager.clearEachIteration";
/// JMeter auth manager thread-group ownership property.
pub const JMX_AUTH_CONTROLLED_BY_THREAD_GROUP: &str = "AuthManager.controlledByThreadGroup";
const MAX_CONFIG_NAME_BYTES: usize = 256;
const MAX_DNS_NAME_BYTES: usize = 255;
const MAX_DNS_ADDRESS_BYTES: usize = 128;

/// A field whose upstream type or name is not interpreted by this module.
///
/// Unknown fields remain ordered and retain whether the upstream value was
/// absent or explicitly empty.  The value is redacted from `Debug` because a
/// plugin property may contain credentials or other sensitive data.
#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueField {
    name: String,
    value: Option<String>,
}

impl fmt::Debug for OpaqueField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueField")
            .field("name", &self.name)
            .field("present", &self.value.is_some())
            .field("value_bytes", &self.value.as_ref().map_or(0, String::len))
            .finish()
    }
}

impl OpaqueField {
    /// Constructs an opaque field, retaining an absent value as `None`.
    pub fn new(
        name: impl Into<String>,
        value: Option<impl Into<String>>,
    ) -> Result<Self, HttpError> {
        let name = name.into();
        let value = value.map(Into::into);
        validate_field(&name, value.as_deref())?;
        Ok(Self { name, value })
    }

    /// Returns the exact upstream field name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns `None` for absent and `Some("")` for explicitly empty values.
    #[must_use]
    pub fn value(&self) -> Option<&str> {
        self.value.as_deref()
    }
}

/// An ordered, lossless wire property collection used at decoder boundaries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireConfig {
    fields: Vec<OpaqueField>,
    maximum_fields: usize,
    maximum_bytes: usize,
}

impl Default for WireConfig {
    fn default() -> Self {
        Self {
            fields: Vec::new(),
            maximum_fields: MAX_CONFIG_FIELDS,
            maximum_bytes: MAX_CONFIG_BYTES,
        }
    }
}

impl WireConfig {
    /// Creates an empty bounded wire collection.
    pub fn new(maximum_fields: usize, maximum_bytes: usize) -> Result<Self, HttpError> {
        if maximum_fields == 0
            || maximum_fields > MAX_CONFIG_FIELDS
            || maximum_bytes == 0
            || maximum_bytes > MAX_CONFIG_BYTES
        {
            return Err(HttpError::resource_limit("HTTP configuration bounds"));
        }
        Ok(Self {
            fields: Vec::new(),
            maximum_fields,
            maximum_bytes,
        })
    }

    /// Appends an ordered field without interpreting or deduplicating it.
    pub fn push(&mut self, field: OpaqueField) -> Result<(), HttpError> {
        if self.fields.len() >= self.maximum_fields {
            return Err(HttpError::resource_limit("HTTP configuration field count"));
        }
        let next = self
            .bytes()
            .checked_add(field.name().len())
            .and_then(|value| value.checked_add(field.value().map_or(0, str::len)))
            .and_then(|value| value.checked_add(4))
            .ok_or_else(|| HttpError::resource_limit("HTTP configuration bytes"))?;
        if next > self.maximum_bytes {
            return Err(HttpError::resource_limit("HTTP configuration bytes"));
        }
        self.fields.push(field);
        Ok(())
    }

    /// Returns fields in original order.
    #[must_use]
    pub fn fields(&self) -> &[OpaqueField] {
        &self.fields
    }

    /// Iterates fields in original order.
    pub fn iter(&self) -> impl Iterator<Item = &OpaqueField> {
        self.fields.iter()
    }

    /// Returns the first exact-name field, retaining duplicate fields after
    /// the first for callers that need to inspect them through [`Self::iter`].
    #[must_use]
    pub fn first(&self, name: &str) -> Option<&OpaqueField> {
        self.fields.iter().find(|field| field.name() == name)
    }

    /// Returns the estimated retained bytes.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.fields
            .iter()
            .map(|field| field.name().len() + field.value().map_or(0, str::len) + 4)
            .sum()
    }
}

/// An optional string field with absent-versus-empty semantics.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct OptionalString(Option<String>);

impl fmt::Debug for OptionalString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OptionalString")
            .field("present", &self.0.is_some())
            .field("value_bytes", &self.0.as_ref().map_or(0, String::len))
            .finish()
    }
}

impl OptionalString {
    /// Represents an absent property.
    #[must_use]
    pub const fn absent() -> Self {
        Self(None)
    }

    /// Represents a present property, including an explicitly empty value.
    pub fn present(value: impl Into<String>) -> Result<Self, HttpError> {
        let value = value.into();
        validate_text(&value, "HTTP configuration string")?;
        Ok(Self(Some(value)))
    }

    /// Returns the source-preserving value.
    #[must_use]
    pub fn value(&self) -> Option<&str> {
        self.0.as_deref()
    }

    /// Returns whether the wire field was present.
    #[must_use]
    pub const fn is_present(&self) -> bool {
        self.0.is_some()
    }
}

/// An optional boolean field with absent-versus-explicit-`false` semantics.
///
/// Configuration-element defaults are applied only by lifecycle adapters. A
/// descriptor can therefore retain the difference between a missing property
/// and a property whose upstream value is `false`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OptionalBool(Option<bool>);

impl OptionalBool {
    /// Represents an absent property.
    #[must_use]
    pub const fn absent() -> Self {
        Self(None)
    }

    /// Represents a present property, including an explicit `false` value.
    #[must_use]
    pub const fn present(value: bool) -> Self {
        Self(Some(value))
    }

    /// Returns the source-preserving value.
    #[must_use]
    pub const fn value(self) -> Option<bool> {
        self.0
    }

    /// Returns whether the wire field was present.
    #[must_use]
    pub const fn is_present(self) -> bool {
        self.0.is_some()
    }
}

/// Explicit protocol implementation selected by an HTTP Request Defaults
/// descriptor.  Unknown values are retained by the decoder boundary instead
/// of being mapped to an arbitrary implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpImplementation {
    /// JMeter Java URLConnection implementation.
    Java,
    /// JMeter HttpClient 4 implementation.
    HttpClient4,
}

impl HttpImplementation {
    /// Decodes one exact JMeter wire spelling.
    ///
    /// Callers that need to preserve an unknown spelling should retain the
    /// original property as an [`OpaqueField`] instead of mapping it to a
    /// supported implementation.
    pub fn from_wire(value: &str) -> Result<Self, HttpError> {
        match value {
            "Java" => Ok(Self::Java),
            "HttpClient4" => Ok(Self::HttpClient4),
            _ => Err(HttpError::Unsupported(format!(
                "unsupported HTTP implementation {value:?}"
            ))),
        }
    }

    /// Returns the exact JMeter wire spelling for this implementation.
    #[must_use]
    pub const fn as_wire(self) -> &'static str {
        match self {
            Self::Java => "Java",
            Self::HttpClient4 => "HttpClient4",
        }
    }

    /// Returns the versioned execution identity selected by this JMeter wire
    /// value.  The Java and HttpClient4 identities are deliberately separate
    /// from the native Rust transports; neither is silently downgraded to a
    /// native capability when a JVM adapter is unavailable.
    #[must_use]
    pub const fn capability_path(self) -> HttpCapabilityPath {
        match self {
            Self::Java => HttpCapabilityPath::JmeterJavaV563,
            Self::HttpClient4 => HttpCapabilityPath::JmeterHttpClient4V563,
        }
    }

    /// Returns whether this JMeter implementation requires the optional
    /// compatibility pack and a pinned JVM worker.
    #[must_use]
    pub const fn requires_jvm(self) -> bool {
        true
    }

    /// Returns the JMeter wire default for an absent implementation field.
    /// This is a source-format default only; selecting it does not authorize
    /// an adapter or make a native run compatible with Java semantics.
    #[must_use]
    pub const fn jmeter_default() -> Self {
        Self::HttpClient4
    }
}

/// Versioned execution identities for HTTP implementation selection.
///
/// `NativeV1` and `NativeV2` are explicit standalone capabilities and are not
/// JMeter wire spellings.  The two `Jmeter*` variants are compatibility-pack
/// paths and must return a typed unavailable error when their worker is absent.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HttpCapabilityPath {
    /// Independently named native Rust transport.
    NativeV1,
    /// Separately versioned native Rust transport increment.
    NativeV2,
    /// Pinned JMeter Java URLConnection path.
    JmeterJavaV563,
    /// Pinned JMeter HttpClient4 path.
    JmeterHttpClient4V563,
}

impl HttpCapabilityPath {
    /// Returns the stable capability identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NativeV1 => "http.native/1",
            Self::NativeV2 => "http.native/2",
            Self::JmeterJavaV563 => "http.jmeter-java/5.6.3",
            Self::JmeterHttpClient4V563 => "http.jmeter-httpclient4/5.6.3",
        }
    }

    /// Parses only versioned capability identifiers.  JMeter wire values
    /// should be decoded with [`HttpImplementation::from_wire`] instead.
    pub fn parse(value: &str) -> Result<Self, HttpError> {
        match value {
            "http.native/1" => Ok(Self::NativeV1),
            "http.native/2" => Ok(Self::NativeV2),
            "http.jmeter-java/5.6.3" => Ok(Self::JmeterJavaV563),
            "http.jmeter-httpclient4/5.6.3" => Ok(Self::JmeterHttpClient4V563),
            _ => Err(HttpError::Unsupported(format!(
                "unsupported HTTP capability {value:?}"
            ))),
        }
    }

    /// Returns whether this path is a compatibility-pack/JVM path.  Both
    /// explicitly selected native increments are JVM-free.
    #[must_use]
    pub const fn requires_jvm(self) -> bool {
        !matches!(self, Self::NativeV1 | Self::NativeV2)
    }

    /// Fails closed when a caller tries to run an external path in this pure
    /// crate.  The application-owned adapter is responsible for proving the
    /// worker identity before admission.
    pub fn require_native(self) -> Result<(), HttpError> {
        if self.requires_jvm() {
            return Err(HttpError::Unsupported(format!(
                "{} requires the optional pinned JVM compatibility pack",
                self.as_str()
            )));
        }
        Ok(())
    }
}

impl core::str::FromStr for HttpCapabilityPath {
    type Err = HttpError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// HTTP sampler proxy fields as represented by JMeter's request element.
///
/// The password is represented only by its presence.  A decoder that has the
/// wire secret must keep it behind the application-owned secret boundary (or
/// retain an opaque redacted field); this pure descriptor never stores a
/// plaintext proxy password.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProxyConfiguration {
    /// `http` or `https`; absent means no explicit proxy scheme.
    pub scheme: OptionalString,
    /// Proxy host, retaining source spelling until route validation.
    pub host: OptionalString,
    /// Proxy port; `Some(0)` preserves an explicit JMeter unspecified value.
    pub port: Option<u16>,
    /// Optional non-secret username presence/value.
    pub username: OptionalString,
    /// Whether the wire carried a proxy password.
    pub password_present: OptionalBool,
    /// Pipe-separated `nonProxyHosts` patterns.
    pub non_proxy_hosts: OptionalString,
    /// Exact unknown or secret-bearing fields.
    pub opaque: WireConfig,
}

impl ProxyConfiguration {
    /// Returns whether the source carried any proxy property.
    #[must_use]
    pub fn is_present(&self) -> bool {
        self.scheme.is_present()
            || self.host.is_present()
            || self.port.is_some()
            || self.username.is_present()
            || self.password_present.is_present()
            || self.non_proxy_hosts.is_present()
            || !self.opaque.fields().is_empty()
    }

    /// Validates syntax and the bounded field model without opening a route.
    pub fn validate(&self) -> Result<(), HttpError> {
        if let Some(scheme) = self.scheme.value()
            && !scheme.is_empty()
            && !scheme.eq_ignore_ascii_case("http")
            && !scheme.eq_ignore_ascii_case("https")
        {
            return Err(HttpError::Proxy(format!(
                "unsupported HTTP proxy scheme {scheme:?}"
            )));
        }
        if self.port.is_some_and(|port| port == 0)
            && (self.host.is_present() || self.scheme.is_present())
        {
            return Err(HttpError::Proxy(
                "HTTP proxy port must be non-zero when configured".to_owned(),
            ));
        }
        if let Some(patterns) = self.non_proxy_hosts.value() {
            crate::NoProxy::parse(patterns)?;
        }
        Ok(())
    }

    /// Merges a local proxy descriptor while retaining absent-versus-empty
    /// values.  Secret/opaque fields stay ordered and are never deduplicated.
    pub fn merge(&mut self, local: &Self) -> Result<(), HttpError> {
        let mut candidate = self.clone();
        if local.scheme.is_present() {
            candidate.scheme = local.scheme.clone();
        }
        if local.host.is_present() {
            candidate.host = local.host.clone();
        }
        if local.port.is_some() {
            candidate.port = local.port;
        }
        if local.username.is_present() {
            candidate.username = local.username.clone();
        }
        if local.password_present.is_present() {
            candidate.password_present = local.password_present;
        }
        if local.non_proxy_hosts.is_present() {
            candidate.non_proxy_hosts = local.non_proxy_hosts.clone();
        }
        for field in local.opaque.iter() {
            candidate.opaque.push(field.clone())?;
        }
        // An explicit empty local value clears an outer secret-bearing field;
        // preserve the exact field in the opaque stream for round-tripping.
        candidate.validate_without_secret_presence()?;
        *self = candidate;
        Ok(())
    }

    fn validate_without_secret_presence(&self) -> Result<(), HttpError> {
        self.validate()
    }

    /// Builds an unauthenticated explicit policy.  Proxy credentials always
    /// return an unavailable-capability error because the application must
    /// supply them through its protected secret provider.
    pub fn to_policy(&self) -> Result<crate::ProxyPolicy, HttpError> {
        self.validate_without_secret_presence()?;
        if self.username.is_present()
            || self.password_present.value().is_some_and(|present| present)
        {
            return Err(HttpError::Unsupported(
                "http.proxy.credentials requires an application SecretRef adapter".to_owned(),
            ));
        }
        let mut policy = crate::ProxyPolicy::default();
        if let Some(patterns) = self.non_proxy_hosts.value() {
            policy.no_proxy = crate::NoProxy::parse(patterns)?;
        }
        let Some(host) = self.host.value().filter(|value| !value.is_empty()) else {
            return Ok(policy);
        };
        let Some(port) = self.port.filter(|port| *port != 0) else {
            return Err(HttpError::Proxy(
                "HTTP proxy host requires an explicit non-zero port".to_owned(),
            ));
        };
        let scheme = self
            .scheme
            .value()
            .filter(|value| !value.is_empty())
            .unwrap_or("http");
        let proxy_scheme = crate::ProxyScheme::parse(scheme)?;
        let proxy = crate::Proxy::new(proxy_scheme, host, port)?;
        match proxy_scheme {
            crate::ProxyScheme::Http => policy.http = Some(proxy),
            crate::ProxyScheme::Https => policy.https = Some(proxy),
        }
        Ok(policy)
    }
}

/// Compatibility alias used by callers that name the sampler element.
pub type HttpProxyConfiguration = ProxyConfiguration;

/// A pure HTTP Request Defaults descriptor.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HttpRequestDefaults {
    /// Optional server name or IP.
    pub domain: OptionalString,
    /// Optional port; `None` means absent, `Some(0)` preserves JMeter's
    /// explicit unspecified-port wire value.
    pub port: Option<u16>,
    /// Optional HTTP protocol.
    pub protocol: OptionalString,
    /// Optional request content encoding.
    pub content_encoding: OptionalString,
    /// Optional default path.
    pub path: OptionalString,
    /// Optional HTTP method when a defaults element carries one.
    pub method: OptionalString,
    /// Whether redirects should be followed when explicitly configured.
    pub follow_redirects: OptionalBool,
    /// Whether automatic redirect mode is requested.
    pub auto_redirects: OptionalBool,
    /// Whether the transport should use persistent connections.
    pub use_keepalive: OptionalBool,
    /// Whether embedded resources should be downloaded concurrently.
    pub concurrent_downloads: OptionalBool,
    /// Embedded-resource include expression.
    pub embedded_url_regex: OptionalString,
    /// Embedded-resource exclusion expression.
    pub embedded_url_exclude_regex: OptionalString,
    /// Explicit sampler proxy fields.
    pub proxy: ProxyConfiguration,
    /// Optional HTTP implementation.
    pub implementation: Option<HttpImplementation>,
    /// Original implementation spelling when it was present but not decoded
    /// as one of the two JMeter 5.6.3 implementations.
    pub implementation_wire: OptionalString,
    /// Optional connect timeout in milliseconds.
    pub connect_timeout_ms: Option<u64>,
    /// Optional response timeout in milliseconds.
    pub response_timeout_ms: Option<u64>,
    /// Optional embedded-resource connection pool size.
    pub concurrent_pool: Option<u16>,
    /// Exact fields not understood by this native descriptor.
    pub opaque: WireConfig,
}

/// Effective HTTP sampler values after applying an ancestry-ordered set of
/// Request Defaults descriptors.
///
/// The descriptor keeps source presence separately; this type contains only
/// values an execution adapter may consume. Fields that have no equivalent
/// in [`Request`] or [`crate::ClientConfig`] (encoding, embedded-resource
/// parsing, connection reuse, and the implementation identity) remain
/// explicit here so an adapter cannot accidentally replace them with a
/// native default.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectiveHttpRequestConfig {
    /// Parsed request method.
    pub method: Method,
    /// Whether the source carried an explicit method property.
    pub method_explicit: bool,
    /// Effective protocol spelling.
    pub protocol: String,
    /// Effective entity encoding requested by JMeter.
    pub content_encoding: String,
    /// Whether the source carried an explicit encoding property.
    pub content_encoding_explicit: bool,
    /// Whether semantic redirect handling is enabled.
    pub follow_redirects: bool,
    /// Whether the upstream client should perform automatic redirects.
    pub auto_redirects: bool,
    /// Whether persistent connections are requested.
    pub use_keepalive: bool,
    /// Whether embedded resources are downloaded concurrently.
    pub concurrent_downloads: bool,
    /// Include expression for embedded-resource extraction.
    pub embedded_url_regex: OptionalString,
    /// Exclude expression for embedded-resource extraction.
    pub embedded_url_exclude_regex: OptionalString,
    /// Explicit proxy route policy.
    pub proxy: crate::ProxyPolicy,
    /// Whether the source carried any explicit proxy property.
    pub proxy_explicit: bool,
    /// JMeter implementation identity.
    pub implementation: HttpImplementation,
    /// Versioned capability selected by `implementation`.
    pub capability: HttpCapabilityPath,
    /// Optional connection timeout in milliseconds.
    pub connect_timeout_ms: Option<u64>,
    /// Whether the source carried a connect-timeout property, including 0.
    pub connect_timeout_explicit: bool,
    /// Optional response-read timeout in milliseconds.
    pub response_timeout_ms: Option<u64>,
    /// Whether the source carried a response-timeout property, including 0.
    pub response_timeout_explicit: bool,
    /// Embedded-resource worker pool size.
    pub concurrent_pool: u16,
}

impl EffectiveHttpRequestConfig {
    /// Builds effective values from one already-merged descriptor.
    pub fn from_defaults(defaults: &HttpRequestDefaults) -> Result<Self, HttpError> {
        defaults.validate()?;
        let implementation = defaults.selected_implementation()?;
        let method = Method::parse(defaults.effective_method())?;
        Ok(Self {
            method,
            method_explicit: defaults.method.is_present(),
            protocol: defaults.effective_protocol().to_owned(),
            content_encoding: defaults.effective_content_encoding().to_owned(),
            content_encoding_explicit: defaults.content_encoding.is_present(),
            follow_redirects: defaults
                .follow_redirects
                .value()
                .unwrap_or(DEFAULT_HTTP_FOLLOW_REDIRECTS),
            auto_redirects: defaults
                .auto_redirects
                .value()
                .unwrap_or(DEFAULT_HTTP_AUTO_REDIRECTS),
            use_keepalive: defaults
                .use_keepalive
                .value()
                .unwrap_or(DEFAULT_HTTP_KEEPALIVE),
            concurrent_downloads: defaults
                .concurrent_downloads
                .value()
                .unwrap_or(DEFAULT_HTTP_CONCURRENT_DOWNLOADS),
            embedded_url_regex: defaults.embedded_url_regex.clone(),
            embedded_url_exclude_regex: defaults.embedded_url_exclude_regex.clone(),
            proxy: defaults.proxy.to_policy()?,
            proxy_explicit: defaults.proxy.is_present(),
            capability: implementation.capability_path(),
            implementation,
            connect_timeout_ms: defaults.effective_connect_timeout_ms(),
            connect_timeout_explicit: defaults.connect_timeout_ms.is_some(),
            response_timeout_ms: defaults.effective_response_timeout_ms(),
            response_timeout_explicit: defaults.response_timeout_ms.is_some(),
            concurrent_pool: defaults.effective_concurrent_pool(),
        })
    }

    /// Merges a materialized JMX ancestry path (outermost first) and resolves
    /// its effective execution values in one operation.
    pub fn from_ancestry(
        descriptors: impl IntoIterator<Item = Scoped<HttpRequestDefaults>>,
    ) -> Result<Self, HttpError> {
        let defaults = merge_request_defaults_in_ancestry_order(descriptors)?;
        Self::from_defaults(&defaults)
    }

    /// Applies the fields that have a direct request representation.
    ///
    /// Content encoding and embedded-resource options are intentionally not
    /// synthesized into headers: JMeter applies those while constructing the
    /// entity and while parsing the response, respectively. Unsupported
    /// non-default values return a typed error instead of being dropped.
    pub fn apply_to_request(&self, request: &mut Request) -> Result<(), HttpError> {
        if self.content_encoding_explicit
            && !self.content_encoding.is_empty()
            && !self
                .content_encoding
                .eq_ignore_ascii_case(DEFAULT_HTTP_CONTENT_ENCODING)
        {
            return Err(HttpError::Unsupported(
                "non-UTF-8 HTTP request encoding requires an explicit sampler adapter".to_owned(),
            ));
        }
        if self.concurrent_downloads
            || self
                .embedded_url_regex
                .value()
                .is_some_and(|value| !value.is_empty())
            || self
                .embedded_url_exclude_regex
                .value()
                .is_some_and(|value| !value.is_empty())
        {
            return Err(HttpError::Unsupported(
                "embedded-resource extraction requires an explicit sampler adapter".to_owned(),
            ));
        }
        if self.method_explicit {
            request.set_method(self.method.clone());
        }
        if !self.use_keepalive {
            request.remove_header("connection");
            request.add_header("Connection", "close")?;
        }
        Ok(())
    }

    /// Applies the subset represented by the transport-independent client
    /// policy. The caller must select and admit `self.capability` separately;
    /// this method never maps a JMeter implementation to the native path.
    pub fn apply_to_client_config(
        &self,
        config: &mut crate::ClientConfig,
    ) -> Result<(), HttpError> {
        if self.auto_redirects {
            return Err(HttpError::Unsupported(
                "automatic HTTP redirects require an explicit sampler adapter".to_owned(),
            ));
        }
        let mut candidate = config.clone();
        if self.proxy_explicit {
            candidate.proxy = self.proxy.clone();
        }
        candidate.redirects.follow = self.follow_redirects;
        if self.connect_timeout_explicit {
            candidate.timeouts.connect = self
                .connect_timeout_ms
                .map(std::time::Duration::from_millis);
        }
        if self.response_timeout_explicit {
            candidate.timeouts.read = self
                .response_timeout_ms
                .map(std::time::Duration::from_millis);
        }
        candidate.validate()?;
        *config = candidate;
        Ok(())
    }
}

impl HttpRequestDefaults {
    /// Resolves all JMeter sampler fields into an explicit execution value.
    pub fn effective_config(&self) -> Result<EffectiveHttpRequestConfig, HttpError> {
        EffectiveHttpRequestConfig::from_defaults(self)
    }

    /// Applies the effective transport policy selected by this descriptor.
    pub fn apply_to_client_config(
        &self,
        config: &mut crate::ClientConfig,
    ) -> Result<(), HttpError> {
        self.effective_config()?.apply_to_client_config(config)
    }
    /// Decodes and retains the exact implementation property.  An unknown
    /// spelling stays in `implementation_wire` and is rejected only when a
    /// caller asks for an execution path, so JMX round-tripping never loses a
    /// plugin/provider value.
    pub fn set_implementation_wire(&mut self, value: Option<&str>) -> Result<(), HttpError> {
        self.implementation_wire = match value {
            Some(value) => OptionalString::present(value)?,
            None => OptionalString::absent(),
        };
        self.implementation = match value {
            Some(value) => HttpImplementation::from_wire(value).ok(),
            None => None,
        };
        Ok(())
    }

    /// Resolves the implementation selected by the JMeter wire descriptor.
    /// An absent property uses the pinned 5.6.3 HttpClient4 default; an
    /// explicitly unknown spelling is an unavailable capability, never a
    /// native fallback.
    pub fn selected_implementation(&self) -> Result<HttpImplementation, HttpError> {
        if let Some(value) = self.implementation_wire.value() {
            return HttpImplementation::from_wire(value);
        }
        Ok(self
            .implementation
            .unwrap_or_else(HttpImplementation::jmeter_default))
    }

    /// Returns the exact versioned execution path selected by this
    /// descriptor.  Both JMeter implementations require the optional JVM
    /// compatibility pack.
    pub fn capability_path(&self) -> Result<HttpCapabilityPath, HttpError> {
        Ok(self.selected_implementation()?.capability_path())
    }

    /// Returns the effective HTTP method without erasing an explicit empty
    /// wire property in the descriptor itself.
    #[must_use]
    pub fn effective_method(&self) -> &str {
        self.method.value().unwrap_or(DEFAULT_HTTP_METHOD)
    }

    /// Returns the effective protocol used by a sampler.
    #[must_use]
    pub fn effective_protocol(&self) -> &str {
        self.protocol.value().unwrap_or(DEFAULT_HTTP_PROTOCOL)
    }

    /// Returns the effective request encoding.  JMeter 5.6.3's HTTP sampler
    /// uses UTF-8 after the 5.6.1 default-encoding fix.
    #[must_use]
    pub fn effective_content_encoding(&self) -> &str {
        self.content_encoding
            .value()
            .unwrap_or(DEFAULT_HTTP_CONTENT_ENCODING)
    }

    /// Returns the effective embedded-resource worker pool size.
    #[must_use]
    pub const fn effective_concurrent_pool(&self) -> u16 {
        match self.concurrent_pool {
            Some(value) => value,
            None => DEFAULT_CONCURRENT_POOL,
        }
    }

    /// Converts an explicit JMeter timeout into an adapter phase cap.  A
    /// missing or zero JMeter timeout means no per-phase cap; the overall
    /// operation budget remains mandatory at the adapter boundary.
    #[must_use]
    pub fn effective_connect_timeout_ms(&self) -> Option<u64> {
        self.connect_timeout_ms.filter(|value| *value != 0)
    }

    /// Converts an explicit JMeter timeout into an adapter phase cap.
    #[must_use]
    pub fn effective_response_timeout_ms(&self) -> Option<u64> {
        self.response_timeout_ms.filter(|value| *value != 0)
    }

    /// Validates explicit values without filling absent properties.
    pub fn validate(&self) -> Result<(), HttpError> {
        if let Some(method) = self.method.value()
            && !method.is_empty()
        {
            Method::parse(method)?;
        }
        if let Some(protocol) = self.protocol.value()
            && !protocol.is_empty()
            && !protocol.eq_ignore_ascii_case("http")
            && !protocol.eq_ignore_ascii_case("https")
        {
            return Err(HttpError::Unsupported(format!(
                "unsupported HTTP protocol {protocol:?}"
            )));
        }
        for timeout in [self.connect_timeout_ms, self.response_timeout_ms]
            .into_iter()
            .flatten()
        {
            if timeout > MAX_HTTP_TIMEOUT_MS {
                return Err(HttpError::InvalidTimeout(
                    "HTTP defaults timeout is outside the finite profile bound".to_owned(),
                ));
            }
        }
        if self
            .concurrent_pool
            .is_some_and(|pool| pool == 0 || pool > MAX_CONCURRENT_POOL)
        {
            return Err(HttpError::resource_limit("HTTP defaults concurrent pool"));
        }
        self.proxy.validate()?;
        Ok(())
    }

    /// Resolves non-absent fields against an HTTP request descriptor.
    ///
    /// The caller supplies the already-merged sampler/default target in
    /// `request`; this adapter overlays each present descriptor field and
    /// leaves absent fields untouched. Request method and the explicit
    /// keep-alive request header are also applied; encoding and embedded
    /// resource settings are exposed through [`Self::effective_config`].
    pub fn apply_to_request(&self, request: &mut Request) -> Result<(), HttpError> {
        let effective = self.effective_config()?;
        let current = request.url().clone();
        // Empty defaults are an explicit JMeter "no override" value. The
        // descriptor still retains that value, while this adapter leaves the
        // sampler target component intact so an empty default cannot produce
        // an invalid authority or silently rewrite the request host.
        let scheme = self
            .protocol
            .value()
            .filter(|value| !value.is_empty())
            .unwrap_or(current.scheme());
        let host = self
            .domain
            .value()
            .filter(|value| !value.is_empty())
            .unwrap_or(current.host());
        let port = self.port.unwrap_or(current.port());
        let path = self
            .path
            .value()
            .filter(|value| !value.is_empty())
            .unwrap_or(current.path_and_query());
        let authority = if port == 0 {
            host.to_owned()
        } else {
            format!("{host}:{port}")
        };
        let target = format!("{scheme}://{authority}{path}");
        request.set_url(Url::parse(target)?);
        effective.apply_to_request(request)
    }

    /// Merges a more local descriptor over this one, preserving absent fields
    /// and replacing only fields explicitly present in `local`.
    pub fn merge(&mut self, local: &Self) -> Result<(), HttpError> {
        let mut candidate = self.clone();
        if local.domain.is_present() {
            candidate.domain = local.domain.clone();
        }
        if local.port.is_some() {
            candidate.port = local.port;
        }
        if local.protocol.is_present() {
            candidate.protocol = local.protocol.clone();
        }
        if local.content_encoding.is_present() {
            candidate.content_encoding = local.content_encoding.clone();
        }
        if local.path.is_present() {
            candidate.path = local.path.clone();
        }
        if local.method.is_present() {
            candidate.method = local.method.clone();
        }
        if local.follow_redirects.is_present() {
            candidate.follow_redirects = local.follow_redirects;
        }
        if local.auto_redirects.is_present() {
            candidate.auto_redirects = local.auto_redirects;
        }
        if local.use_keepalive.is_present() {
            candidate.use_keepalive = local.use_keepalive;
        }
        if local.concurrent_downloads.is_present() {
            candidate.concurrent_downloads = local.concurrent_downloads;
        }
        if local.embedded_url_regex.is_present() {
            candidate.embedded_url_regex = local.embedded_url_regex.clone();
        }
        if local.embedded_url_exclude_regex.is_present() {
            candidate.embedded_url_exclude_regex = local.embedded_url_exclude_regex.clone();
        }
        candidate.proxy.merge(&local.proxy)?;
        if local.implementation.is_some() {
            candidate.implementation = local.implementation;
            if !local.implementation_wire.is_present() {
                candidate.implementation_wire = OptionalString::absent();
            }
        }
        if local.implementation_wire.is_present() {
            candidate.implementation_wire = local.implementation_wire.clone();
        }
        if local.connect_timeout_ms.is_some() {
            candidate.connect_timeout_ms = local.connect_timeout_ms;
        }
        if local.response_timeout_ms.is_some() {
            candidate.response_timeout_ms = local.response_timeout_ms;
        }
        if local.concurrent_pool.is_some() {
            candidate.concurrent_pool = local.concurrent_pool;
        }
        for field in local.opaque.fields() {
            candidate.opaque.push(field.clone())?;
        }
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }
}

/// One ordered static host mapping for a DNS Cache Manager.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticDnsHost {
    /// Hostname requested by samplers.
    pub name: String,
    /// Hostname or IP address selected by the static table.
    pub address: String,
}

impl StaticDnsHost {
    /// Constructs a bounded static mapping.
    pub fn new(name: impl Into<String>, address: impl Into<String>) -> Result<Self, HttpError> {
        let name = name.into();
        let address = address.into();
        validate_dns_text(&name, "DNS static host name", MAX_DNS_NAME_BYTES)?;
        validate_static_addresses(&address)?;
        Ok(Self { name, address })
    }
}

/// Pure DNS Cache Manager options and static table.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DnsConfiguration {
    /// Clear per-user DNS state at each iteration.
    pub clear_each_iteration: OptionalBool,
    /// Whether a custom resolver is requested.
    pub custom_resolver: OptionalBool,
    /// Ordered custom resolver server values.
    pub servers: Vec<String>,
    /// Ordered static host mappings.
    pub static_hosts: Vec<StaticDnsHost>,
    /// Exact unknown wire fields.
    pub opaque: WireConfig,
}

impl DnsConfiguration {
    /// Validates static values and explicit bounds.
    pub fn validate(&self) -> Result<(), HttpError> {
        if self.servers.len() > MAX_DNS_SERVERS || self.static_hosts.len() > MAX_STATIC_DNS_HOSTS {
            return Err(HttpError::resource_limit("DNS configuration entries"));
        }
        for server in &self.servers {
            validate_dns_text(server, "DNS resolver server", MAX_DNS_ADDRESS_BYTES)?;
        }
        for host in &self.static_hosts {
            validate_dns_text(&host.name, "DNS static host name", MAX_DNS_NAME_BYTES)?;
            validate_static_addresses(&host.address)?;
        }
        Ok(())
    }

    /// Merges a more local DNS manager over this descriptor.
    ///
    /// Scalar switches replace only when present. Resolver servers are a
    /// local replacement when the local descriptor carries entries, while
    /// static mappings replace an outer mapping at its original position or
    /// append in local order when the host is new.
    pub fn merge(&mut self, local: &Self) -> Result<(), HttpError> {
        let mut candidate = self.clone();
        if local.clear_each_iteration.is_present() {
            candidate.clear_each_iteration = local.clear_each_iteration;
        }
        if local.custom_resolver.is_present() {
            candidate.custom_resolver = local.custom_resolver;
        }
        if !local.servers.is_empty() {
            candidate.servers.clone_from(&local.servers);
        }
        for local_host in &local.static_hosts {
            if let Some(existing) = candidate
                .static_hosts
                .iter_mut()
                .find(|host| host.name.eq_ignore_ascii_case(&local_host.name))
            {
                *existing = local_host.clone();
            } else {
                candidate.static_hosts.push(local_host.clone());
            }
        }
        for field in local.opaque.iter() {
            candidate.opaque.push(field.clone())?;
        }
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    /// Applies ordered static entries to a per-user cache snapshot.
    pub fn apply_to_cache(&self, cache: &mut DnsCache) -> Result<(), HttpError> {
        self.validate()?;
        let mut candidate = cache.clone();
        candidate.set_custom_resolver(self.custom_resolver.value().unwrap_or(false));
        candidate.set_resolver_servers(self.servers.iter().cloned())?;
        for host in &self.static_hosts {
            let addresses = host.address.split(',').map(str::trim).map(str::to_owned);
            candidate.insert(&host.name, addresses, std::time::Duration::MAX)?;
        }
        *cache = candidate;
        Ok(())
    }

    /// Applies the per-user iteration reset policy to DNS metadata.
    pub fn reset(&self, cache: &mut DnsCache) {
        if self.clear_each_iteration.value().unwrap_or(false) {
            cache.clear();
        }
    }
}

/// Cookie Manager configuration options and reset policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CookieConfiguration {
    /// Clear server-defined cookies at each main-loop iteration.
    pub clear_each_iteration: OptionalBool,
    /// Clear manager state when the owning thread group starts an iteration.
    pub controlled_by_thread_group: OptionalBool,
    /// Save received cookies into virtual-user variables.
    pub save_cookies: OptionalBool,
    /// Validate received cookie domains.
    pub check_cookies: OptionalBool,
    /// Delete cookies whose value is null/empty.
    pub delete_null_cookies: OptionalBool,
    /// Cookie policy name as written on the wire.
    pub policy: OptionalString,
    /// Handler implementation class/name as written on the wire.
    pub implementation: OptionalString,
    /// Initial GUI-authored cookies copied into each virtual-user jar.
    pub initial_cookies: Vec<crate::Cookie>,
    /// Exact unknown wire fields.
    pub opaque: WireConfig,
}

impl Default for CookieConfiguration {
    fn default() -> Self {
        Self {
            clear_each_iteration: OptionalBool::absent(),
            controlled_by_thread_group: OptionalBool::absent(),
            save_cookies: OptionalBool::absent(),
            check_cookies: OptionalBool::absent(),
            delete_null_cookies: OptionalBool::absent(),
            policy: OptionalString::default(),
            implementation: OptionalString::default(),
            initial_cookies: Vec::new(),
            opaque: WireConfig::default(),
        }
    }
}

impl CookieConfiguration {
    /// Validates bounded initial-cookie data and handler selections.
    pub fn validate(&self) -> Result<(), HttpError> {
        if self.initial_cookies.len() > MAX_INITIAL_COOKIES {
            return Err(HttpError::resource_limit("initial cookie count"));
        }
        Ok(())
    }

    /// Returns the JMeter default policy for an absent property.
    #[must_use]
    pub fn effective_policy(&self) -> &str {
        self.policy.value().unwrap_or(DEFAULT_COOKIE_POLICY)
    }

    /// Returns the JMeter default handler identity for an absent property.
    #[must_use]
    pub fn effective_implementation(&self) -> &str {
        self.implementation
            .value()
            .unwrap_or(DEFAULT_COOKIE_IMPLEMENTATION)
    }

    /// Merges a more local Cookie Manager descriptor over this one.
    pub fn merge(&mut self, local: &Self) -> Result<(), HttpError> {
        let mut candidate = self.clone();
        if local.clear_each_iteration.is_present() {
            candidate.clear_each_iteration = local.clear_each_iteration;
        }
        if local.controlled_by_thread_group.is_present() {
            candidate.controlled_by_thread_group = local.controlled_by_thread_group;
        }
        if local.save_cookies.is_present() {
            candidate.save_cookies = local.save_cookies;
        }
        if local.check_cookies.is_present() {
            candidate.check_cookies = local.check_cookies;
        }
        if local.delete_null_cookies.is_present() {
            candidate.delete_null_cookies = local.delete_null_cookies;
        }
        if local.policy.is_present() {
            candidate.policy = local.policy.clone();
        }
        if local.implementation.is_present() {
            candidate.implementation = local.implementation.clone();
        }
        if !local.initial_cookies.is_empty() {
            candidate
                .initial_cookies
                .extend(local.initial_cookies.iter().cloned());
        }
        for field in local.opaque.iter() {
            candidate.opaque.push(field.clone())?;
        }
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    /// Validates and applies handler selections that this pure state crate
    /// cannot execute. Custom values remain representable for JMX
    /// round-tripping, but an explicit adapter is required at execution.
    /// Applies cookie validation, deletion, and variable-publication options
    /// at the pure state boundary. Variable creation itself remains an
    /// execution-layer concern and is represented by `save_cookies` on the
    /// jar for that adapter.
    pub fn apply(&self, jar: &mut CookieJar) -> Result<(), HttpError> {
        self.validate()?;
        if self.policy.is_present() && self.effective_policy() != DEFAULT_COOKIE_POLICY {
            return Err(HttpError::Unsupported(
                "custom CookieManager policy requires an adapter".to_owned(),
            ));
        }
        if self.implementation.is_present()
            && self.effective_implementation() != DEFAULT_COOKIE_IMPLEMENTATION
        {
            return Err(HttpError::Unsupported(
                "custom CookieManager implementation requires an adapter".to_owned(),
            ));
        }
        let mut candidate = jar.clone();
        candidate.set_check_cookies(self.check_cookies.value().unwrap_or(true));
        candidate.set_delete_null_cookies(self.delete_null_cookies.value().unwrap_or(true));
        candidate.set_save_cookies(self.save_cookies.value().unwrap_or(false));
        for cookie in &self.initial_cookies {
            candidate.add(
                cookie.clone(),
                crate::ClockReading::new(0, std::time::Duration::ZERO),
            )?;
        }
        *jar = candidate;
        Ok(())
    }

    /// Applies reset policy to an existing per-user cookie jar.
    pub fn reset(&self, jar: &mut CookieJar, thread_group_boundary: bool) {
        let clear_each_iteration = self.clear_each_iteration.value().unwrap_or(false);
        let controlled_by_thread_group = self.controlled_by_thread_group.value().unwrap_or(false);
        if clear_each_iteration || (thread_group_boundary && controlled_by_thread_group) {
            jar.reset_for_iteration(true);
        }
    }
}

/// Cache Manager configuration options and reset policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheConfiguration {
    /// Maximum cache entries (`maxSize`).
    pub max_size: Option<usize>,
    /// Clear cache at each iteration.
    pub clear_each_iteration: OptionalBool,
    /// Share cache state through the owning thread group.
    pub controlled_by_thread: OptionalBool,
    /// Honor Cache-Control/Expires freshness headers.
    pub use_expires: OptionalBool,
    /// Exact unknown wire fields.
    pub opaque: WireConfig,
}

impl Default for CacheConfiguration {
    fn default() -> Self {
        Self {
            max_size: None,
            clear_each_iteration: OptionalBool::absent(),
            controlled_by_thread: OptionalBool::absent(),
            use_expires: OptionalBool::absent(),
            opaque: WireConfig::default(),
        }
    }
}

impl CacheConfiguration {
    /// Returns JMeter's 5.6.3 default maximum cache-entry count.
    #[must_use]
    pub const fn effective_max_size(&self) -> usize {
        match self.max_size {
            Some(value) => value,
            None => DEFAULT_CACHE_MAX_SIZE,
        }
    }

    /// Returns whether cache freshness metadata is honored.  JMeter's
    /// CacheManager default is false; this differs from the lower-level
    /// `CacheStore` default and is therefore applied explicitly here.
    #[must_use]
    pub const fn effective_use_expires(&self) -> bool {
        match self.use_expires.value() {
            Some(value) => value,
            None => false,
        }
    }

    /// Merges a more local Cache Manager descriptor over this one.
    pub fn merge(&mut self, local: &Self) -> Result<(), HttpError> {
        let mut candidate = self.clone();
        if local.max_size.is_some() {
            candidate.max_size = local.max_size;
        }
        if local.clear_each_iteration.is_present() {
            candidate.clear_each_iteration = local.clear_each_iteration;
        }
        if local.controlled_by_thread.is_present() {
            candidate.controlled_by_thread = local.controlled_by_thread;
        }
        if local.use_expires.is_present() {
            candidate.use_expires = local.use_expires;
        }
        for field in local.opaque.iter() {
            candidate.opaque.push(field.clone())?;
        }
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    /// Validates options without mutating a cache state.
    pub fn validate(&self) -> Result<(), HttpError> {
        if self
            .max_size
            .is_some_and(|size| size == 0 || size > MAX_CACHE_ENTRIES)
        {
            return Err(HttpError::resource_limit("CacheManager.maxSize"));
        }
        Ok(())
    }

    /// Validates and applies manager options to a cache state.
    pub fn apply(&self, cache: &mut CacheStore) -> Result<(), HttpError> {
        self.validate()?;
        let mut candidate = cache.clone();
        if let Some(max_size) = self.max_size {
            candidate.set_maximum(max_size)?;
        }
        // JMeter's CacheManager default is false, but the descriptor retains
        // an absent field until this explicit adapter boundary.
        if self.max_size.is_none() {
            candidate.set_maximum(DEFAULT_CACHE_MAX_SIZE)?;
        }
        candidate.set_use_expires(self.effective_use_expires());
        *cache = candidate;
        Ok(())
    }

    /// Applies iteration reset policy.
    pub fn reset(&self, cache: &mut CacheStore, thread_group_boundary: bool) {
        let clear_each_iteration = self.clear_each_iteration.value().unwrap_or(false);
        let controlled_by_thread = self.controlled_by_thread.value().unwrap_or(false);
        if clear_each_iteration || (thread_group_boundary && controlled_by_thread) {
            cache.reset_for_iteration(true);
        }
    }
}

/// Pure AuthManager options; mechanism adapters remain explicit capabilities.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuthConfiguration {
    /// Clear authentication state at each iteration.
    pub clear_each_iteration: OptionalBool,
    /// Clear authentication state at the owning thread-group boundary.
    pub controlled_by_thread_group: OptionalBool,
    /// Ordered URL-prefix entries.
    pub entries: Vec<AuthEntry>,
    /// Exact unknown wire fields.
    pub opaque: WireConfig,
}

impl AuthConfiguration {
    /// Validates that every configured mechanism has a native semantic
    /// adapter. Digest and Kerberos remain representable in the descriptor,
    /// but this pure crate does not execute either handshake.
    pub fn validate(&self) -> Result<(), HttpError> {
        if self.entries.len() > MAX_AUTH_ENTRIES {
            return Err(HttpError::resource_limit("authentication entry count"));
        }
        for entry in &self.entries {
            match entry.mechanism() {
                crate::AuthMechanism::Basic | crate::AuthMechanism::Bearer => {}
                crate::AuthMechanism::Digest => {
                    return Err(HttpError::Unsupported(
                        "digest authentication requires a protocol adapter".to_owned(),
                    ));
                }
                crate::AuthMechanism::Kerberos => {
                    return Err(HttpError::Unsupported(
                        "Kerberos authentication requires a JVM security-provider adapter"
                            .to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Merges a more local AuthManager descriptor over this one in insertion
    /// order. Exact duplicate URL prefixes remain in the descriptor; the
    /// store adapter intentionally keeps the first occurrence, matching
    /// JMeter's first-match/duplicate-ignore behavior.
    pub fn merge(&mut self, local: &Self) -> Result<(), HttpError> {
        let mut candidate = self.clone();
        if local.clear_each_iteration.is_present() {
            candidate.clear_each_iteration = local.clear_each_iteration;
        }
        if local.controlled_by_thread_group.is_present() {
            candidate.controlled_by_thread_group = local.controlled_by_thread_group;
        }
        candidate.entries.extend(local.entries.iter().cloned());
        for field in local.opaque.iter() {
            candidate.opaque.push(field.clone())?;
        }
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    /// Applies ordered entries to a per-user authentication store.
    pub fn apply_to_store(&self, store: &mut crate::AuthStore) -> Result<(), HttpError> {
        self.validate()?;
        let mut candidate = store.clone();
        for entry in &self.entries {
            candidate.add(entry.clone())?;
        }
        *store = candidate;
        Ok(())
    }

    /// Clears authentication state when requested by lifecycle policy.
    pub fn reset(&self, store: &mut crate::AuthStore) {
        if self.clear_each_iteration.value().unwrap_or(false) {
            store.clear();
        }
    }

    /// Applies both iteration and thread-group reset policy explicitly.
    pub fn reset_for_boundary(&self, store: &mut crate::AuthStore, thread_group_boundary: bool) {
        if self.clear_each_iteration.value().unwrap_or(false)
            || (thread_group_boundary && self.controlled_by_thread_group.value().unwrap_or(false))
        {
            store.clear();
        }
    }
}

/// Scope order used by deterministic configuration accumulation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ConfigScope {
    /// Test-plan ancestor.
    TestPlan,
    /// Thread-group ancestor.
    ThreadGroup,
    /// Controller ancestor.
    Controller,
    /// Sampler-local configuration.
    Sampler,
}

/// One scoped descriptor paired with its tree order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Scoped<T> {
    /// Scope category.
    pub scope: ConfigScope,
    /// Sibling insertion order within the category.
    pub order: usize,
    /// Descriptor payload.
    pub value: T,
}

/// Merges HTTP Request Defaults in the exact order supplied by the caller.
///
/// The input must be the actual JMX ancestry path, outermost element first
/// and sampler-local element last. Scope labels and sibling order are
/// retained for diagnostics but are deliberately not used to invent an
/// ordering: a plan may contain multiple branches with the same scope.
pub fn merge_request_defaults(
    descriptors: Vec<Scoped<HttpRequestDefaults>>,
) -> Result<HttpRequestDefaults, HttpError> {
    merge_request_defaults_in_ancestry_order(descriptors)
}

/// Merges descriptors from an already materialized JMX ancestry path.
///
/// This named entry point is the preferred API for callers walking a tree;
/// unlike the legacy [`merge_request_defaults`] name it makes the ordering
/// contract visible at the call site.
pub fn merge_request_defaults_in_ancestry_order(
    descriptors: impl IntoIterator<Item = Scoped<HttpRequestDefaults>>,
) -> Result<HttpRequestDefaults, HttpError> {
    let mut effective = HttpRequestDefaults::default();
    for descriptor in descriptors {
        effective.merge(&descriptor.value)?;
    }
    Ok(effective)
}

fn validate_field(name: &str, value: Option<&str>) -> Result<(), HttpError> {
    if name.is_empty()
        || name.len() > MAX_CONFIG_NAME_BYTES
        || name.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
    {
        return Err(HttpError::InvalidHeader(
            "HTTP configuration field name".to_owned(),
        ));
    }
    if let Some(value) = value {
        validate_text(value, "HTTP configuration field")?;
    }
    Ok(())
}

fn validate_text(value: &str, what: &str) -> Result<(), HttpError> {
    if value.len() > MAX_CONFIG_BYTES || value.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err(HttpError::resource_limit(what));
    }
    Ok(())
}

fn validate_dns_text(value: &str, what: &str, maximum_bytes: usize) -> Result<(), HttpError> {
    validate_text(value, what)?;
    if value.len() > maximum_bytes {
        return Err(HttpError::resource_limit(what));
    }
    if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(HttpError::InvalidUrl(what.to_owned()));
    }
    if what == "DNS static host name"
        && !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'%')
        })
    {
        return Err(HttpError::InvalidUrl(what.to_owned()));
    }
    Ok(())
}

fn validate_static_addresses(value: &str) -> Result<(), HttpError> {
    if value.len() > MAX_CONFIG_BYTES || value.is_empty() {
        return Err(HttpError::resource_limit("DNS static host address"));
    }
    let mut count = 0usize;
    for address in value.split(',') {
        let address = address.trim();
        if address.is_empty() {
            return Err(HttpError::InvalidUrl(
                "DNS static host address contains an empty entry".to_owned(),
            ));
        }
        validate_dns_text(address, "DNS static host address", MAX_DNS_ADDRESS_BYTES)?;
        count = count
            .checked_add(1)
            .ok_or_else(|| HttpError::resource_limit("DNS static host address count"))?;
        if count > 64 {
            return Err(HttpError::resource_limit("DNS static host address count"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "tests use expect at assertion boundaries for fixed descriptors"
    )]

    use super::*;

    fn string(value: &str) -> OptionalString {
        OptionalString::present(value).expect("valid config string")
    }

    #[test]
    fn request_defaults_merge_outer_to_inner_and_retain_empty() {
        let outer = HttpRequestDefaults {
            domain: string("outer.example"),
            protocol: string("http"),
            path: string("/outer"),
            ..HttpRequestDefaults::default()
        };
        let inner = HttpRequestDefaults {
            domain: string(""),
            path: OptionalString::absent(),
            port: Some(8080),
            ..HttpRequestDefaults::default()
        };
        let effective = merge_request_defaults(vec![
            Scoped {
                scope: ConfigScope::TestPlan,
                order: 0,
                value: outer,
            },
            Scoped {
                scope: ConfigScope::Sampler,
                order: 0,
                value: inner,
            },
        ])
        .expect("merge");
        assert_eq!(effective.domain.value(), Some(""));
        assert_eq!(effective.protocol.value(), Some("http"));
        assert_eq!(effective.path.value(), Some("/outer"));
        assert_eq!(effective.port, Some(8080));
    }

    #[test]
    fn request_defaults_use_caller_ancestry_order_not_scope_sorting() {
        let outer = HttpRequestDefaults {
            method: string("POST"),
            ..HttpRequestDefaults::default()
        };
        let inner = HttpRequestDefaults {
            method: string("PUT"),
            ..HttpRequestDefaults::default()
        };
        let effective = merge_request_defaults_in_ancestry_order([
            Scoped {
                // Deliberately labels the local value as an outer scope. The
                // tree walk's sequence, not this invented category, is the
                // source of truth.
                scope: ConfigScope::Sampler,
                order: 99,
                value: outer,
            },
            Scoped {
                scope: ConfigScope::TestPlan,
                order: 0,
                value: inner,
            },
        ])
        .expect("ancestry merge");
        assert_eq!(effective.method.value(), Some("PUT"));
        let resolved = EffectiveHttpRequestConfig::from_ancestry([Scoped {
            scope: ConfigScope::TestPlan,
            order: 0,
            value: HttpRequestDefaults {
                method: string("PATCH"),
                ..HttpRequestDefaults::default()
            },
        }])
        .expect("resolved ancestry");
        assert_eq!(resolved.method, Method::Patch);
    }

    #[test]
    fn effective_request_defaults_apply_method_keepalive_and_client_policy() {
        let defaults = HttpRequestDefaults {
            method: string("POST"),
            follow_redirects: OptionalBool::present(false),
            use_keepalive: OptionalBool::present(false),
            connect_timeout_ms: Some(125),
            response_timeout_ms: Some(250),
            proxy: ProxyConfiguration {
                scheme: string("http"),
                host: string("proxy.example"),
                port: Some(8080),
                ..ProxyConfiguration::default()
            },
            ..HttpRequestDefaults::default()
        };
        let effective = defaults.effective_config().expect("effective config");
        assert_eq!(effective.method, Method::Post);
        assert!(!effective.follow_redirects);
        assert!(!effective.use_keepalive);
        assert_eq!(effective.connect_timeout_ms, Some(125));
        assert_eq!(effective.response_timeout_ms, Some(250));

        let mut request = Request::get("http://origin.example/path").expect("request");
        defaults
            .apply_to_request(&mut request)
            .expect("request defaults");
        assert_eq!(request.method(), &Method::Post);
        assert_eq!(request.headers().get("connection"), Some("close"));

        let mut client = crate::ClientConfig::default();
        effective
            .apply_to_client_config(&mut client)
            .expect("client defaults");
        assert!(!client.redirects.follow);
        assert_eq!(
            client.timeouts.connect,
            Some(std::time::Duration::from_millis(125))
        );
        assert_eq!(
            client.timeouts.read,
            Some(std::time::Duration::from_millis(250))
        );
        assert!(matches!(
            client
                .proxy
                .route(&Url::parse("http://origin.example/").expect("url")),
            crate::Route::Proxy(_)
        ));

        let absent_method = HttpRequestDefaults::default();
        let mut existing =
            Request::post("http://origin.example/path", b"body".to_vec()).expect("request");
        absent_method
            .apply_to_request(&mut existing)
            .expect("absent method remains untouched");
        assert_eq!(existing.method(), &Method::Post);

        let inherited_proxy =
            crate::Proxy::new(crate::ProxyScheme::Http, "proxy.example", 8080).expect("proxy");
        let mut inherited = crate::ClientConfig::default();
        inherited.proxy.http = Some(inherited_proxy);
        absent_method
            .apply_to_client_config(&mut inherited)
            .expect("absent proxy remains untouched");
        assert!(matches!(
            inherited
                .proxy
                .route(&Url::parse("http://origin.example/").expect("url")),
            crate::Route::Proxy(_)
        ));
    }

    #[test]
    fn effective_request_defaults_keep_explicit_zero_timeout_as_unlimited() {
        let defaults = HttpRequestDefaults {
            connect_timeout_ms: Some(0),
            response_timeout_ms: Some(0),
            ..HttpRequestDefaults::default()
        };
        let effective = defaults.effective_config().expect("effective config");
        assert_eq!(effective.connect_timeout_ms, None);
        assert!(effective.connect_timeout_explicit);
        assert!(effective.response_timeout_explicit);

        let mut client = crate::ClientConfig::default();
        client.timeouts.connect = Some(std::time::Duration::from_millis(1));
        client.timeouts.read = Some(std::time::Duration::from_millis(1));
        effective
            .apply_to_client_config(&mut client)
            .expect("unlimited timeout");
        assert_eq!(client.timeouts.connect, None);
        assert_eq!(client.timeouts.read, None);
    }

    #[test]
    fn implementation_identity_defaults_and_unknown_values_fail_closed() {
        let defaults = HttpRequestDefaults::default();
        assert_eq!(
            defaults.selected_implementation().expect("JMeter default"),
            HttpImplementation::HttpClient4
        );
        assert_eq!(
            defaults.capability_path().expect("capability").as_str(),
            "http.jmeter-httpclient4/5.6.3"
        );

        let mut unknown = HttpRequestDefaults::default();
        unknown
            .set_implementation_wire(Some("PluginHttp"))
            .expect("retain implementation");
        assert_eq!(unknown.implementation_wire.value(), Some("PluginHttp"));
        assert!(matches!(
            unknown.effective_config(),
            Err(HttpError::Unsupported(_))
        ));
    }

    #[test]
    fn proxy_credentials_are_unavailable_without_a_secret_adapter() {
        let proxy = ProxyConfiguration {
            host: string("proxy.example"),
            port: Some(8080),
            username: string("user"),
            password_present: OptionalBool::present(true),
            ..ProxyConfiguration::default()
        };
        assert!(matches!(proxy.to_policy(), Err(HttpError::Unsupported(_))));
    }

    #[test]
    fn automatic_redirect_mode_is_not_silently_mapped_to_semantic_redirects() {
        let defaults = HttpRequestDefaults {
            auto_redirects: OptionalBool::present(true),
            ..HttpRequestDefaults::default()
        };
        let effective = defaults.effective_config().expect("effective config");
        assert!(matches!(
            effective.apply_to_client_config(&mut crate::ClientConfig::default()),
            Err(HttpError::Unsupported(_))
        ));
    }

    #[test]
    fn unsupported_body_encoding_and_embedded_options_fail_explicitly() {
        let encoding = HttpRequestDefaults {
            content_encoding: string("ISO-8859-1"),
            ..HttpRequestDefaults::default()
        };
        assert!(matches!(
            encoding.apply_to_request(&mut Request::get("http://example.test/").expect("request")),
            Err(HttpError::Unsupported(_))
        ));

        let embedded = HttpRequestDefaults {
            embedded_url_regex: string("img\\.png"),
            ..HttpRequestDefaults::default()
        };
        assert!(matches!(
            embedded.apply_to_request(&mut Request::get("http://example.test/").expect("request")),
            Err(HttpError::Unsupported(_))
        ));
    }

    #[test]
    fn header_manager_replaces_case_insensitively_and_keeps_order() {
        let mut outer = crate::HeaderManager::new(4).expect("manager");
        outer.add("X-Test", "one").expect("header");
        outer.add("Accept", "text/plain").expect("header");
        let mut inner = crate::HeaderManager::new(4).expect("manager");
        inner.add("x-test", "two").expect("header");
        inner.add("X-New", "three").expect("header");
        inner.add("Accept", "").expect("header");
        outer.merge_ordered(&inner).expect("merge");
        let fields = outer.headers().iter().collect::<Vec<_>>();
        assert_eq!(fields[0].name().as_str(), "x-test");
        assert_eq!(fields[0].value().as_str(), "two");
        assert_eq!(fields[1].name().as_str(), "Accept");
        assert_eq!(fields[1].value().as_str(), "");
        assert_eq!(fields[2].name().as_str(), "X-New");
    }

    #[test]
    fn dns_static_mapping_is_bounded_and_ordered() {
        let config = DnsConfiguration {
            custom_resolver: OptionalBool::present(true),
            servers: vec!["127.0.0.1".to_owned()],
            static_hosts: vec![
                StaticDnsHost::new("fixture.test", "127.0.0.1, 127.0.0.2").expect("host"),
            ],
            ..DnsConfiguration::default()
        };
        let mut cache = DnsCache::new(2).expect("cache");
        config.apply_to_cache(&mut cache).expect("mapping");
        assert!(cache.custom_resolver());
        assert_eq!(cache.resolver_servers(), &["127.0.0.1".to_owned()]);
        assert_eq!(
            cache.lookup(
                "FIXTURE.TEST",
                crate::ClockReading::new(0, std::time::Duration::ZERO)
            ),
            Some(vec!["127.0.0.1".to_owned(), "127.0.0.2".to_owned()])
        );
        DnsConfiguration {
            clear_each_iteration: OptionalBool::present(true),
            ..DnsConfiguration::default()
        }
        .reset(&mut cache);
        assert_eq!(
            cache.lookup(
                "fixture.test",
                crate::ClockReading::new(0, std::time::Duration::ZERO)
            ),
            None
        );
    }

    #[test]
    fn cookie_and_cache_reset_follow_explicit_lifecycle() {
        let default_cookie = CookieConfiguration::default();
        assert_eq!(default_cookie.effective_policy(), DEFAULT_COOKIE_POLICY);
        assert_eq!(
            default_cookie.effective_implementation(),
            DEFAULT_COOKIE_IMPLEMENTATION
        );
        assert_eq!(CacheConfiguration::default().effective_max_size(), 5_000);
        assert!(!CacheConfiguration::default().effective_use_expires());

        let cookie_config = CookieConfiguration {
            clear_each_iteration: OptionalBool::present(true),
            check_cookies: OptionalBool::present(false),
            delete_null_cookies: OptionalBool::present(false),
            save_cookies: OptionalBool::present(true),
            ..CookieConfiguration::default()
        };
        let mut jar = CookieJar::new(4).expect("jar");
        cookie_config.apply(&mut jar).expect("cookie options");
        assert!(!jar.check_cookies());
        assert!(!jar.delete_null_cookies());
        assert!(jar.save_cookies());
        jar.add(
            crate::Cookie::new("base", "one", "example.test", "/").expect("cookie"),
            crate::ClockReading::new(0, std::time::Duration::ZERO),
        )
        .expect("cookie");
        jar.capture_initial();
        jar.add(
            crate::Cookie::new("extra", "two", "example.test", "/").expect("cookie"),
            crate::ClockReading::new(0, std::time::Duration::ZERO),
        )
        .expect("cookie");
        cookie_config.reset(&mut jar, false);
        assert_eq!(jar.cookies().len(), 1);

        let cache_config = CacheConfiguration {
            clear_each_iteration: OptionalBool::present(true),
            use_expires: OptionalBool::present(false),
            ..CacheConfiguration::default()
        };
        let mut cache = CacheStore::new(1).expect("cache");
        cache_config.apply(&mut cache).expect("options");
        cache_config.reset(&mut cache, false);
        assert!(!cache.use_expires());

        let request = Request::get("http://example.test/cache").expect("request");
        let mut response = crate::Response::with_body(200, b"body".to_vec()).expect("response");
        response.add_header("ETag", "\"v1\"").expect("etag");
        response
            .add_header("Expires", "not-a-date")
            .expect("expires");
        assert!(
            cache
                .store(
                    &request,
                    &response,
                    crate::ClockReading::new(0, std::time::Duration::ZERO)
                )
                .expect("cache store")
        );
    }

    #[test]
    fn auth_uses_first_matching_entry_and_rejects_unsupported_mechanisms() {
        let mut store = crate::AuthStore::new(4).expect("store");
        store
            .add(
                AuthEntry::new(
                    "http://example.test/api",
                    "first",
                    "secret",
                    crate::AuthMechanism::Basic,
                )
                .expect("entry"),
            )
            .expect("entry");
        store
            .add(
                AuthEntry::new(
                    "http://example.test/api/deep",
                    "second",
                    "secret",
                    crate::AuthMechanism::Basic,
                )
                .expect("entry"),
            )
            .expect("entry");
        let url = Url::parse("http://example.test/api/deep/item").expect("url");
        assert_eq!(
            store.first_matching(&url).expect("match").url_prefix(),
            "http://example.test/api"
        );
        assert_eq!(
            store.authorization(&url).expect("auth").as_deref(),
            Some("Basic Zmlyc3Q6c2VjcmV0")
        );
        store
            .add(
                AuthEntry::new(
                    "http://example.test/api",
                    "duplicate",
                    "different",
                    crate::AuthMechanism::Basic,
                )
                .expect("entry"),
            )
            .expect("duplicate ignored");
        assert_eq!(store.entries().len(), 2);
        let kerberos = AuthEntry::new(
            "http://example.test/kerb",
            "user",
            "secret",
            crate::AuthMechanism::Kerberos,
        )
        .expect("entry");
        store.add(kerberos).expect("entry");
        assert!(matches!(
            store.authorization(&Url::parse("http://example.test/kerb").expect("url")),
            Err(HttpError::Unsupported(_))
        ));
        let config = AuthConfiguration {
            entries: vec![
                AuthEntry::new(
                    "http://example.test/digest",
                    "user",
                    "secret",
                    crate::AuthMechanism::Digest,
                )
                .expect("entry"),
            ],
            ..AuthConfiguration::default()
        };
        assert!(matches!(config.validate(), Err(HttpError::Unsupported(_))));
        let invalid_domain = AuthEntry::new(
            "http://example.test/domain",
            "user",
            "secret",
            crate::AuthMechanism::Basic,
        )
        .expect("entry")
        .domain("invalid\nDomain");
        assert!(matches!(
            store.add(invalid_domain),
            Err(HttpError::Authentication(_))
        ));
    }

    #[test]
    fn opaque_fields_preserve_absent_empty_and_redact_debug() {
        let absent = OpaqueField::new("plugin.absent", None::<String>).expect("field");
        let empty = OpaqueField::new("plugin.empty", Some(String::new())).expect("field");
        let secret =
            OpaqueField::new("plugin.secret", Some("secret-token".to_owned())).expect("field");
        let mut wire = WireConfig::default();
        wire.push(absent.clone()).expect("field");
        wire.push(empty.clone()).expect("field");
        wire.push(secret.clone()).expect("field");
        assert_eq!(wire.fields()[0].value(), None);
        assert_eq!(wire.fields()[1].value(), Some(""));
        assert!(!format!("{wire:?}").contains("secret-token"));
        assert!(
            !format!(
                "{:?}",
                OptionalString::present("secret-token").expect("string")
            )
            .contains("secret-token")
        );
    }

    #[test]
    fn optional_boolean_preserves_absent_and_explicit_false() {
        assert_eq!(OptionalBool::absent().value(), None);
        assert!(!OptionalBool::absent().is_present());
        assert_eq!(OptionalBool::present(false).value(), Some(false));
        assert!(OptionalBool::present(false).is_present());
        assert_ne!(OptionalBool::absent(), OptionalBool::present(false));
    }

    #[test]
    fn manager_merges_are_local_wins_and_ordered() {
        let mut dns = DnsConfiguration {
            clear_each_iteration: OptionalBool::present(true),
            static_hosts: vec![StaticDnsHost::new("fixture.test", "127.0.0.1").expect("host")],
            ..DnsConfiguration::default()
        };
        let local_dns = DnsConfiguration {
            clear_each_iteration: OptionalBool::present(false),
            static_hosts: vec![
                StaticDnsHost::new("FIXTURE.TEST", "127.0.0.2").expect("host"),
                StaticDnsHost::new("other.test", "127.0.0.3").expect("host"),
            ],
            ..DnsConfiguration::default()
        };
        dns.merge(&local_dns).expect("dns merge");
        assert_eq!(dns.clear_each_iteration.value(), Some(false));
        assert_eq!(dns.static_hosts[0].address, "127.0.0.2");
        assert_eq!(dns.static_hosts[1].name, "other.test");

        let mut cookie = CookieConfiguration {
            check_cookies: OptionalBool::present(true),
            policy: string("outer"),
            ..CookieConfiguration::default()
        };
        cookie
            .merge(&CookieConfiguration {
                check_cookies: OptionalBool::present(false),
                policy: string(""),
                ..CookieConfiguration::default()
            })
            .expect("cookie merge");
        assert_eq!(cookie.check_cookies.value(), Some(false));
        assert_eq!(cookie.policy.value(), Some(""));

        let mut cache = CacheConfiguration {
            max_size: Some(8),
            use_expires: OptionalBool::present(true),
            ..CacheConfiguration::default()
        };
        cache
            .merge(&CacheConfiguration {
                max_size: Some(2),
                use_expires: OptionalBool::present(false),
                ..CacheConfiguration::default()
            })
            .expect("cache merge");
        assert_eq!(cache.max_size, Some(2));
        assert_eq!(cache.use_expires.value(), Some(false));
    }

    #[test]
    fn invalid_configurations_fail_with_typed_errors() {
        assert_eq!(
            HttpImplementation::from_wire("Java").expect("implementation"),
            HttpImplementation::Java
        );
        assert!(matches!(
            HttpImplementation::from_wire("PluginHttp"),
            Err(HttpError::Unsupported(_))
        ));
        assert!(matches!(
            (HttpRequestDefaults {
                protocol: string("ftp"),
                ..HttpRequestDefaults::default()
            })
            .validate(),
            Err(HttpError::Unsupported(_))
        ));
        assert!(matches!(
            (HttpRequestDefaults {
                connect_timeout_ms: Some(MAX_HTTP_TIMEOUT_MS + 1),
                ..HttpRequestDefaults::default()
            })
            .validate(),
            Err(HttpError::InvalidTimeout(_))
        ));
        assert!(matches!(
            (DnsConfiguration {
                servers: vec![String::new()],
                ..DnsConfiguration::default()
            })
            .validate(),
            Err(HttpError::InvalidUrl(_))
        ));
        assert!(matches!(
            (CacheConfiguration {
                max_size: Some(0),
                ..CacheConfiguration::default()
            })
            .validate(),
            Err(HttpError::ResourceLimit(_))
        ));
        let custom_cookie = CookieConfiguration {
            implementation: string("custom.CookieHandler"),
            ..CookieConfiguration::default()
        };
        assert!(custom_cookie.validate().is_ok());
        let mut jar = CookieJar::new(2).expect("jar");
        assert!(matches!(
            custom_cookie.apply(&mut jar),
            Err(HttpError::Unsupported(_))
        ));
        assert!(matches!(
            WireConfig::new(MAX_CONFIG_FIELDS + 1, MAX_CONFIG_BYTES),
            Err(HttpError::ResourceLimit(_))
        ));
    }

    #[test]
    fn capability_paths_are_exact_and_exhaustive() {
        let cases = [
            (HttpCapabilityPath::NativeV1, "http.native/1", false),
            (HttpCapabilityPath::NativeV2, "http.native/2", false),
            (
                HttpCapabilityPath::JmeterJavaV563,
                "http.jmeter-java/5.6.3",
                true,
            ),
            (
                HttpCapabilityPath::JmeterHttpClient4V563,
                "http.jmeter-httpclient4/5.6.3",
                true,
            ),
        ];

        for (path, wire, requires_jvm) in cases {
            assert_eq!(path.as_str(), wire);
            assert_eq!(HttpCapabilityPath::parse(wire), Ok(path));
            assert_eq!(wire.parse::<HttpCapabilityPath>(), Ok(path));
            assert_eq!(path.requires_jvm(), requires_jvm);
            if requires_jvm {
                assert!(matches!(
                    path.require_native(),
                    Err(HttpError::Unsupported(_))
                ));
            } else {
                assert!(path.require_native().is_ok());
            }
        }

        assert_ne!(HttpCapabilityPath::NativeV1, HttpCapabilityPath::NativeV2);
        assert_eq!(
            HttpImplementation::Java.capability_path(),
            HttpCapabilityPath::JmeterJavaV563
        );
        assert_eq!(
            HttpImplementation::HttpClient4.capability_path(),
            HttpCapabilityPath::JmeterHttpClient4V563
        );

        for unknown in [
            "http.native/3",
            "http.native/01",
            "http.native/2/",
            "HTTP.NATIVE/2",
            "http.native/2 ",
            "http.native",
            "NativeV2",
            "HttpClient4",
        ] {
            assert!(
                HttpCapabilityPath::parse(unknown).is_err(),
                "unexpected HTTP capability alias: {unknown:?}"
            );
        }
    }
}
