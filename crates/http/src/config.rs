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

use crate::{AuthEntry, CacheStore, CookieJar, DnsCache, HttpError, Request, Url};

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
}

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
    /// Optional HTTP implementation.
    pub implementation: Option<HttpImplementation>,
    /// Optional connect timeout in milliseconds.
    pub connect_timeout_ms: Option<u64>,
    /// Optional response timeout in milliseconds.
    pub response_timeout_ms: Option<u64>,
    /// Optional embedded-resource connection pool size.
    pub concurrent_pool: Option<u16>,
    /// Exact fields not understood by this native descriptor.
    pub opaque: WireConfig,
}

impl HttpRequestDefaults {
    /// Validates explicit values without filling absent properties.
    pub fn validate(&self) -> Result<(), HttpError> {
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
            if timeout == 0 {
                return Err(HttpError::InvalidTimeout(
                    "HTTP defaults timeout must be non-zero".to_owned(),
                ));
            }
        }
        if self.concurrent_pool.is_some_and(|pool| pool == 0) {
            return Err(HttpError::resource_limit("HTTP defaults concurrent pool"));
        }
        Ok(())
    }

    /// Resolves non-absent fields against an HTTP request descriptor.
    ///
    /// The caller supplies the already-merged sampler/default target in
    /// `request`; this adapter overlays each present descriptor field and
    /// leaves absent fields untouched. It changes only the pure request URL.
    pub fn apply_to_request(&self, request: &mut Request) -> Result<(), HttpError> {
        self.validate()?;
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
        Ok(())
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
        if local.implementation.is_some() {
            candidate.implementation = local.implementation;
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
        validate_dns_text(&address, "DNS static host address", MAX_DNS_ADDRESS_BYTES)?;
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
            validate_dns_text(
                &host.address,
                "DNS static host address",
                MAX_DNS_ADDRESS_BYTES,
            )?;
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
            candidate.insert(&host.name, [host.address.clone()], std::time::Duration::MAX)?;
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
            opaque: WireConfig::default(),
        }
    }
}

impl CookieConfiguration {
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
        for field in local.opaque.iter() {
            candidate.opaque.push(field.clone())?;
        }
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    /// Validates handler selections that this pure state crate cannot execute.
    ///
    /// A non-empty custom policy or implementation is retained in the
    /// descriptor but must be handled by an explicit adapter; silently using
    /// the native policy would lose the requested wire semantics.
    pub fn validate(&self) -> Result<(), HttpError> {
        if self.policy.value().is_some_and(|value| !value.is_empty()) {
            return Err(HttpError::Unsupported(
                "custom CookieManager policy requires an adapter".to_owned(),
            ));
        }
        if self
            .implementation
            .value()
            .is_some_and(|value| !value.is_empty())
        {
            return Err(HttpError::Unsupported(
                "custom CookieManager implementation requires an adapter".to_owned(),
            ));
        }
        Ok(())
    }

    /// Applies cookie validation, deletion, and variable-publication options
    /// at the pure state boundary. Variable creation itself remains an
    /// execution-layer concern and is represented by `save_cookies` on the
    /// jar for that adapter.
    pub fn apply(&self, jar: &mut CookieJar) -> Result<(), HttpError> {
        self.validate()?;
        jar.set_check_cookies(self.check_cookies.value().unwrap_or(true));
        jar.set_delete_null_cookies(self.delete_null_cookies.value().unwrap_or(true));
        jar.set_save_cookies(self.save_cookies.value().unwrap_or(false));
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
    /// Maximum cache entries (`CacheManager.maxSize`).
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
        if self.max_size.is_some_and(|size| size == 0) {
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
        // JMeter's CacheManager default is true, but the descriptor retains an
        // absent field until this explicit adapter boundary.
        candidate.set_use_expires(self.use_expires.value().unwrap_or(true));
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

/// Deterministically merges HTTP Request Defaults from outer to inner scope.
pub fn merge_request_defaults(
    mut descriptors: Vec<Scoped<HttpRequestDefaults>>,
) -> Result<HttpRequestDefaults, HttpError> {
    descriptors.sort_by_key(|descriptor| (descriptor.scope, descriptor.order));
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
            static_hosts: vec![StaticDnsHost::new("fixture.test", "127.0.0.1").expect("host")],
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
            Some(vec!["127.0.0.1".to_owned()])
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
                connect_timeout_ms: Some(0),
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
        assert!(matches!(
            (CookieConfiguration {
                implementation: string("custom.CookieHandler"),
                ..CookieConfiguration::default()
            })
            .validate(),
            Err(HttpError::Unsupported(_))
        ));
        assert!(matches!(
            WireConfig::new(MAX_CONFIG_FIELDS + 1, MAX_CONFIG_BYTES),
            Err(HttpError::ResourceLimit(_))
        ));
    }
}
