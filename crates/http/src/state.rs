// SPDX-License-Identifier: Apache-2.0
//! Bounded per-user HTTP protocol state.

use std::time::Duration;

use crate::HttpError;
use crate::clock::ClockReading;
use crate::header::{Headers, is_redirect_sensitive_name};
use crate::request::{Method, Request};
use crate::response::Response;
use crate::url::Url;

/// A bounded header manager applied to requests in insertion order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderManager {
    headers: Headers,
    maximum: usize,
}

impl HeaderManager {
    const MAX_BYTES: usize = 64 * 1024;
    /// Creates an empty manager with a finite field bound.
    pub fn new(maximum: usize) -> Result<Self, HttpError> {
        if maximum == 0 {
            return Err(HttpError::resource_limit(
                "header manager capacity must be non-zero",
            ));
        }
        Ok(Self {
            headers: Headers::new(),
            maximum,
        })
    }

    /// Creates a manager with the default bound of 128 fields.
    #[must_use]
    pub fn default_bounded() -> Self {
        Self {
            headers: Headers::new(),
            maximum: 128,
        }
    }

    /// Returns the manager's capacity.
    #[must_use]
    pub const fn maximum(&self) -> usize {
        self.maximum
    }

    /// Returns configured fields.
    #[must_use]
    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    /// Adds a field, retaining duplicates and order.
    pub fn add(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), HttpError> {
        if self.headers.len() >= self.maximum {
            return Err(HttpError::resource_limit("header manager field count"));
        }
        let field = crate::Header::new(name, value)?;
        let proposed = self
            .headers
            .checked_wire_len()?
            .checked_add(field.name().as_str().len())
            .and_then(|total| total.checked_add(field.value().as_str().len()))
            .and_then(|total| total.checked_add(4))
            .ok_or_else(|| HttpError::resource_limit("header manager bytes"))?;
        if proposed > Self::MAX_BYTES {
            return Err(HttpError::resource_limit("header manager bytes"));
        }
        self.headers.append(field);
        Ok(())
    }

    /// Removes all fields by name.
    pub fn remove(&mut self, name: &str) -> usize {
        self.headers.remove(name)
    }

    /// Removes every configured field without changing this manager's bound.
    pub fn clear(&mut self) {
        self.headers = Headers::new();
    }

    /// Merges another manager with ordered, case-insensitive replacement.
    ///
    /// JMeter header managers form one effective ordered list.  A later field
    /// with the same name replaces the earlier field in its existing position;
    /// fields with new names are appended.  This method is intentionally
    /// separate from [`Self::add`], which remains a low-level duplicate-
    /// preserving operation for callers that are constructing wire state.
    pub fn merge_ordered(&mut self, other: &Self) -> Result<(), HttpError> {
        let mut fields: Vec<crate::Header> = self.headers.iter().cloned().collect();
        for field in &other.headers {
            if let Some(existing) = fields
                .iter_mut()
                .find(|existing| existing.name().eq_ignore_ascii_case(field.name().as_str()))
            {
                *existing = field.clone();
            } else {
                fields.push(field.clone());
            }
        }
        let mut merged = Headers::new();
        for field in fields {
            merged.append(field);
        }
        if merged.len() > self.maximum || merged.checked_wire_len()? > Self::MAX_BYTES {
            return Err(HttpError::resource_limit("header manager merge"));
        }
        self.headers = merged;
        Ok(())
    }

    /// Appends manager fields to a request. Explicit request fields win for
    /// singleton headers; duplicate-safe fields are retained.
    pub fn apply(&self, request: &mut Request) {
        self.apply_with_policy(request, true);
    }

    /// Applies manager fields while optionally suppressing credentials and
    /// entity fields after a cross-origin redirect.  Entity fields are also
    /// suppressed for methods that cannot carry a body.
    pub fn apply_with_policy(&self, request: &mut Request, allow_sensitive: bool) {
        self.apply_with_options(request, allow_sensitive, true);
    }

    /// Applies manager fields with an explicit entity-header allowance.  The
    /// client disables this after a 301/302/303 method rewrite so a manager
    /// cannot restore `Content-*` fields on the new GET request.
    pub(crate) fn apply_with_options(
        &self,
        request: &mut Request,
        allow_sensitive: bool,
        allow_entity: bool,
    ) {
        self.apply_with_redirect_options(
            request,
            allow_sensitive,
            allow_sensitive,
            allow_sensitive,
            allow_entity,
        );
    }

    /// Applies manager fields with separate controls for sensitive values and
    /// redirect-sensitive authorization/host fields.  Redirect handling uses
    /// this seam to prevent a stale `Host` or path-unscoped authorization
    /// field from being restored by the manager.
    pub(crate) fn apply_with_redirect_options(
        &self,
        request: &mut Request,
        allow_sensitive: bool,
        allow_authorization: bool,
        allow_host: bool,
        allow_entity: bool,
    ) {
        for field in &self.headers {
            let name = field.name().as_str();
            let lower = name.to_ascii_lowercase();
            let is_authorization =
                matches!(lower.as_str(), "authorization" | "proxy-authorization");
            if (!allow_sensitive
                && is_redirect_sensitive_name(name)
                && !(is_authorization && allow_authorization))
                || (!allow_authorization && is_authorization)
                || (!allow_host && lower == "host")
                || (!allow_entity && lower.starts_with("content-"))
            {
                continue;
            }
            let singleton = matches!(
                lower.as_str(),
                "host"
                    | "content-length"
                    | "content-type"
                    | "content-encoding"
                    | "connection"
                    | "authorization"
                    | "cookie"
                    | "proxy-authorization"
            );
            if !singleton || !request.headers().contains(field.name().as_str()) {
                request.headers_mut().append(field.clone());
            }
        }
    }
}

impl Default for HeaderManager {
    fn default() -> Self {
        Self::default_bounded()
    }
}

/// One HTTP cookie retained by a per-user jar.
#[derive(Clone, Eq, PartialEq)]
pub struct Cookie {
    name: String,
    value: String,
    domain: String,
    path: String,
    secure: bool,
    host_only: bool,
    expires_at: Option<Duration>,
    creation: u64,
}

impl std::fmt::Debug for Cookie {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Cookie")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .field("domain", &self.domain)
            .field("path", &self.path)
            .field("secure", &self.secure)
            .field("host_only", &self.host_only)
            .field("expires_at", &self.expires_at)
            .field("creation", &self.creation)
            .finish()
    }
}

impl Cookie {
    /// Creates a host-only session cookie.
    pub fn new(
        name: impl Into<String>,
        value: impl Into<String>,
        domain: impl Into<String>,
        path: impl Into<String>,
    ) -> Result<Self, HttpError> {
        let name = name.into();
        let value = value.into();
        let raw_domain = domain.into();
        if raw_domain.trim().ends_with('.') {
            return Err(HttpError::Cookie(
                "cookie domain has a trailing dot".to_owned(),
            ));
        }
        let domain = normalize_domain(&raw_domain);
        let path = normalize_path(&path.into());
        validate_cookie_pair(&name, &value)?;
        if domain.is_empty() || domain.len() > 255 || !valid_cookie_domain(&domain) {
            return Err(HttpError::Cookie("cookie domain is empty".to_owned()));
        }
        if path.len() > 4 * 1024 || path.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
            return Err(HttpError::resource_limit("cookie path bytes"));
        }
        Ok(Self {
            name,
            value,
            domain,
            path,
            secure: false,
            host_only: true,
            expires_at: None,
            creation: 0,
        })
    }

    /// Sets Secure delivery policy.
    #[must_use]
    pub fn secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    /// Sets whether the domain is host-only.
    #[must_use]
    pub fn host_only(mut self, host_only: bool) -> Self {
        self.host_only = host_only;
        self
    }

    /// Sets a monotonic expiry.
    #[must_use]
    pub fn expires_at(mut self, expires_at: Option<Duration>) -> Self {
        self.expires_at = expires_at;
        self
    }

    /// Returns cookie name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns cookie value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Returns cookie domain.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Returns cookie path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns whether Secure is required.
    #[must_use]
    pub const fn is_secure(&self) -> bool {
        self.secure
    }
}

/// One bounded, adapter-independent DNS record retained for a virtual user.
/// Resolution itself remains an injected transport capability; this type only
/// prevents adapters from accidentally sharing a process-global cache.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsRecord {
    host: String,
    addresses: Vec<String>,
    expires_at: Duration,
}

/// Bounded per-user DNS cache metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsCache {
    records: Vec<DnsRecord>,
    maximum: usize,
    custom_resolver: bool,
    resolver_servers: Vec<String>,
}

impl Default for DnsCache {
    fn default() -> Self {
        Self {
            records: Vec::new(),
            maximum: 256,
            custom_resolver: false,
            resolver_servers: Vec::new(),
        }
    }
}

impl DnsCache {
    /// Creates a cache with a finite record bound.
    pub fn new(maximum: usize) -> Result<Self, HttpError> {
        if maximum == 0 {
            return Err(HttpError::resource_limit(
                "DNS cache capacity must be non-zero",
            ));
        }
        Ok(Self {
            records: Vec::new(),
            maximum,
            custom_resolver: false,
            resolver_servers: Vec::new(),
        })
    }

    /// Returns whether the descriptor requests a custom resolver.
    #[must_use]
    pub const fn custom_resolver(&self) -> bool {
        self.custom_resolver
    }

    /// Selects whether the descriptor requests a custom resolver. Resolution
    /// remains an injected transport capability; this only stores policy.
    pub fn set_custom_resolver(&mut self, custom_resolver: bool) {
        self.custom_resolver = custom_resolver;
    }

    /// Returns ordered custom resolver server values.
    #[must_use]
    pub fn resolver_servers(&self) -> &[String] {
        &self.resolver_servers
    }

    /// Stores ordered, bounded custom resolver server values.
    pub fn set_resolver_servers<I, S>(&mut self, servers: I) -> Result<(), HttpError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut values = Vec::new();
        for server in servers {
            if values.len() >= 32 {
                return Err(HttpError::resource_limit("DNS resolver server count"));
            }
            let server = server.into();
            if server.is_empty()
                || server.len() > 128
                || server
                    .bytes()
                    .any(|byte| byte.is_ascii_whitespace() || byte == 0x7f)
            {
                return Err(HttpError::InvalidUrl(
                    "invalid DNS resolver server".to_owned(),
                ));
            }
            values.push(server);
        }
        self.resolver_servers = values;
        Ok(())
    }

    /// Returns the number of retained records after expiry cleanup.
    pub fn len(&mut self, now: ClockReading) -> usize {
        self.remove_expired(now);
        self.records.len()
    }

    /// Stores a resolved address set with an injected monotonic expiry.
    pub fn insert<I, S>(
        &mut self,
        host: impl Into<String>,
        addresses: I,
        expires_at: Duration,
    ) -> Result<(), HttpError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let host = host.into().to_ascii_lowercase();
        if host.is_empty()
            || host.len() > 255
            || (!valid_cookie_domain(&host)
                && !host
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() || matches!(byte, b':' | b'.' | b'%')))
        {
            return Err(HttpError::InvalidUrl("invalid DNS host".to_owned()));
        }
        let addresses = addresses.into_iter().map(Into::into).collect::<Vec<_>>();
        if addresses.is_empty() || addresses.len() > 64 {
            return Err(HttpError::resource_limit("DNS address count"));
        }
        if addresses.iter().any(|address| {
            address.is_empty()
                || address.len() > 128
                || address.bytes().any(|byte| byte <= 0x20 || byte == 0x7f)
        }) {
            return Err(HttpError::InvalidUrl("invalid DNS address".to_owned()));
        }
        let record = DnsRecord {
            host: host.clone(),
            addresses,
            expires_at,
        };
        if let Some(existing) = self
            .records
            .iter_mut()
            .find(|existing| existing.host == host)
        {
            *existing = record;
            return Ok(());
        }
        if self.records.len() >= self.maximum {
            return Err(HttpError::resource_limit("DNS cache capacity"));
        }
        self.records.push(record);
        Ok(())
    }

    /// Returns a cloned address set so callers cannot retain mutable cache
    /// references across cleanup or replacement.
    pub fn lookup(&mut self, host: &str, now: ClockReading) -> Option<Vec<String>> {
        self.remove_expired(now);
        self.records
            .iter()
            .find(|record| record.host == host.to_ascii_lowercase())
            .map(|record| record.addresses.clone())
    }

    /// Looks up a record without mutating the bounded snapshot.  This form is
    /// intended for a transport adapter reading `TransportContext` through a
    /// shared reference; the next client attempt performs expiry cleanup.
    #[must_use]
    pub fn lookup_ref(&self, host: &str, now: ClockReading) -> Option<Vec<String>> {
        let host = host.to_ascii_lowercase();
        self.records
            .iter()
            .find(|record| record.host == host && record.expires_at > now.monotonic)
            .map(|record| record.addresses.clone())
    }

    /// Removes all records.
    pub fn clear(&mut self) {
        self.records.clear();
    }

    fn remove_expired(&mut self, now: ClockReading) {
        self.records
            .retain(|record| record.expires_at > now.monotonic);
    }
}

/// A conservative, pinned public-suffix policy used when no full PSL is
/// supplied by the embedding application.
///
/// The built-in list is intentionally finite and is not a claim of complete
/// Public Suffix List compatibility.  An embedding that needs exact domain
/// cookie behavior must provide a bounded, pinned policy with
/// [`Self::with_suffixes`] without changing cookie matching code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicSuffixPolicy {
    suffixes: Vec<String>,
    reject_single_label: bool,
}

impl Default for PublicSuffixPolicy {
    fn default() -> Self {
        Self::conservative()
    }
}

impl PublicSuffixPolicy {
    /// Returns the built-in conservative policy.  It covers the common
    /// generic and multi-label suffixes that are dangerous for Domain cookies;
    /// unknown single-label domains are rejected as well.
    #[must_use]
    pub fn conservative() -> Self {
        Self {
            suffixes: [
                "com",
                "net",
                "org",
                "edu",
                "gov",
                "mil",
                "io",
                "dev",
                "app",
                "co.uk",
                "org.uk",
                "net.uk",
                "co.jp",
                "co.in",
                "github.io",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            reject_single_label: true,
        }
    }

    /// Builds a policy from a finite list of lowercase suffixes.
    pub fn with_suffixes<I, S>(suffixes: I, reject_single_label: bool) -> Result<Self, HttpError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut values = Vec::new();
        for suffix in suffixes {
            let suffix = normalize_domain(&suffix.into());
            if suffix.is_empty()
                || suffix.len() > 255
                || !suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
            {
                return Err(HttpError::Cookie("invalid public suffix".to_owned()));
            }
            values.push(suffix);
            if values.len() > 4_096 {
                return Err(HttpError::resource_limit("public suffix policy entries"));
            }
        }
        values.sort_unstable();
        values.dedup();
        Ok(Self {
            suffixes: values,
            reject_single_label,
        })
    }

    /// Returns whether a normalized domain is treated as a public suffix.
    #[must_use]
    pub fn is_public_suffix(&self, domain: &str) -> bool {
        let domain = normalize_domain(domain);
        (self.reject_single_label && !domain.contains('.'))
            || self.suffixes.iter().any(|suffix| suffix == &domain)
    }
}

/// Bounded, deterministic per-user cookie state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CookieJar {
    cookies: Vec<Cookie>,
    initial: Vec<Cookie>,
    maximum: usize,
    next_creation: u64,
    public_suffix_policy: PublicSuffixPolicy,
    check_cookies: bool,
    delete_null_cookies: bool,
    save_cookies: bool,
}

impl Default for CookieJar {
    fn default() -> Self {
        Self {
            cookies: Vec::new(),
            initial: Vec::new(),
            maximum: 512,
            next_creation: 0,
            public_suffix_policy: PublicSuffixPolicy::default(),
            check_cookies: true,
            delete_null_cookies: true,
            save_cookies: false,
        }
    }
}

impl CookieJar {
    const MAX_COOKIE_NAME_BYTES: usize = 256;
    const MAX_COOKIE_VALUE_BYTES: usize = 16 * 1024;
    const MAX_COOKIE_HEADER_BYTES: usize = 64 * 1024;

    /// Creates an empty jar with a finite capacity.
    pub fn new(maximum: usize) -> Result<Self, HttpError> {
        if maximum == 0 {
            return Err(HttpError::resource_limit(
                "cookie jar capacity must be non-zero",
            ));
        }
        Ok(Self {
            cookies: Vec::new(),
            initial: Vec::new(),
            maximum,
            next_creation: 0,
            public_suffix_policy: PublicSuffixPolicy::default(),
            check_cookies: true,
            delete_null_cookies: true,
            save_cookies: false,
        })
    }

    /// Creates a jar with an explicit public-suffix policy.
    pub fn with_policy(
        maximum: usize,
        public_suffix_policy: PublicSuffixPolicy,
    ) -> Result<Self, HttpError> {
        let mut jar = Self::new(maximum)?;
        jar.public_suffix_policy = public_suffix_policy;
        Ok(jar)
    }

    /// Returns the policy used for Domain cookie rejection.
    #[must_use]
    pub const fn public_suffix_policy(&self) -> &PublicSuffixPolicy {
        &self.public_suffix_policy
    }

    /// Returns whether incoming Domain attributes undergo suffix validation.
    #[must_use]
    pub const fn check_cookies(&self) -> bool {
        self.check_cookies
    }

    /// Selects whether incoming Domain attributes undergo suffix validation.
    pub fn set_check_cookies(&mut self, check_cookies: bool) {
        self.check_cookies = check_cookies;
    }

    /// Returns whether an empty incoming value removes the matching cookie.
    #[must_use]
    pub const fn delete_null_cookies(&self) -> bool {
        self.delete_null_cookies
    }

    /// Selects whether an empty incoming value removes the matching cookie.
    pub fn set_delete_null_cookies(&mut self, delete_null_cookies: bool) {
        self.delete_null_cookies = delete_null_cookies;
    }

    /// Returns whether received cookies are exposed to the variable adapter.
    #[must_use]
    pub const fn save_cookies(&self) -> bool {
        self.save_cookies
    }

    /// Selects whether received cookies are exposed to the variable adapter.
    /// The pure HTTP crate records this option; variable publication belongs
    /// to the embedding execution adapter.
    pub fn set_save_cookies(&mut self, save_cookies: bool) {
        self.save_cookies = save_cookies;
    }

    /// Returns the number of retained cookies after removing expiry.
    pub fn len(&mut self, now: ClockReading) -> usize {
        self.remove_expired(now);
        self.cookies.len()
    }

    /// Returns an immutable cookie snapshot.
    #[must_use]
    pub fn cookies(&self) -> &[Cookie] {
        &self.cookies
    }

    /// Adds or replaces one cookie.
    pub fn add(&mut self, mut cookie: Cookie, now: ClockReading) -> Result<(), HttpError> {
        self.remove_expired(now);
        if !cookie.host_only && cookie.domain.is_empty() {
            return Err(HttpError::Cookie(
                "domain cookie has empty domain".to_owned(),
            ));
        }
        if self.check_cookies
            && !cookie.host_only
            && (is_ip_literal(&cookie.domain)
                || self.public_suffix_policy.is_public_suffix(&cookie.domain))
        {
            return Err(HttpError::Cookie(
                "cookie Domain is a public suffix".to_owned(),
            ));
        }
        if let Some(existing) = self.cookies.iter_mut().find(|existing| {
            existing.name == cookie.name
                && existing.domain == cookie.domain
                && existing.path == cookie.path
        }) {
            // RFC 6265 section 5.3 preserves the old cookie's creation-time
            // when a new Set-Cookie replaces the same name/domain/path.  The
            // creation sequence is therefore not consumed by a replacement;
            // this also lets a replacement succeed when no new sequence value
            // can be allocated, without changing the jar's generation.
            cookie.creation = existing.creation;
            *existing = cookie;
            return Ok(());
        }
        let creation = self.next_creation;
        let next_creation = self
            .next_creation
            .checked_add(1)
            .ok_or_else(|| HttpError::resource_limit("cookie creation sequence"))?;
        if self.cookies.len() >= self.maximum {
            let Some(index) = self
                .cookies
                .iter()
                .enumerate()
                .min_by_key(|(_, value)| value.creation)
                .map(|(index, _)| index)
            else {
                return Err(HttpError::resource_limit("cookie jar eviction"));
            };
            self.cookies.remove(index);
        }
        cookie.creation = creation;
        self.next_creation = next_creation;
        self.cookies.push(cookie);
        Ok(())
    }

    /// Deletes a matching cookie key.
    pub fn remove(&mut self, name: &str, domain: &str, path: &str) -> bool {
        let before = self.cookies.len();
        let domain = normalize_domain(domain);
        let path = normalize_path(path);
        self.cookies.retain(|cookie| {
            !(cookie.name == name && cookie.domain == domain && cookie.path == path)
        });
        self.cookies.len() != before
    }

    /// Removes all cookies.
    pub fn clear(&mut self) {
        self.cookies.clear();
    }

    /// Captures the current collection as the per-thread initial state.
    ///
    /// JMeter can restore a thread's initial cookie collection at an
    /// iteration boundary.  Keeping the snapshot explicit avoids conflating
    /// a deliberate `clear` with lifecycle reset.
    pub fn capture_initial(&mut self) {
        self.initial = self.cookies.clone();
    }

    /// Restores the captured initial collection and preserves deterministic
    /// creation ordering for subsequent replacement/eviction.
    pub fn restore_initial(&mut self) {
        self.cookies = self.initial.clone();
        self.next_creation = self
            .cookies
            .iter()
            .map(|cookie| cookie.creation)
            .max()
            .and_then(|value| value.checked_add(1))
            .unwrap_or(0);
    }

    /// Applies the configured iteration lifecycle policy.
    pub fn reset_for_iteration(&mut self, clear_each_iteration: bool) {
        if clear_each_iteration {
            self.restore_initial();
        }
    }

    /// Parses and stores all `Set-Cookie` response fields.
    pub fn store_set_cookie_headers(
        &mut self,
        url: &Url,
        headers: &Headers,
        now: ClockReading,
    ) -> Result<usize, HttpError> {
        let mut count = 0;
        for value in headers.values("set-cookie") {
            if let Some(cookie) = parse_set_cookie(
                value,
                url,
                now,
                &self.public_suffix_policy,
                self.check_cookies,
            )? {
                let should_remove = cookie
                    .expires_at
                    .is_some_and(|expiry| expiry <= now.monotonic)
                    || (self.delete_null_cookies && cookie.value().is_empty());
                if should_remove {
                    self.remove(cookie.name(), cookie.domain(), cookie.path());
                } else {
                    self.add(cookie, now)?;
                }
                count += 1;
            }
        }
        Ok(count)
    }

    /// Builds a Cookie header for this URL, sorted by path specificity then
    /// creation order.
    ///
    /// The result is fallible because the header has a finite wire-size
    /// bound.  Callers must not silently drop the cookie state when that
    /// bound is reached; use the typed error to fail the sampler or apply an
    /// explicit policy at the embedding boundary.
    pub fn request_header(
        &mut self,
        url: &Url,
        now: ClockReading,
    ) -> Result<Option<String>, HttpError> {
        self.try_request_header(url, now)
    }

    /// Builds a Cookie header and reports when the bounded wire value cannot
    /// be represented without dropping cookie state.
    pub fn try_request_header(
        &mut self,
        url: &Url,
        now: ClockReading,
    ) -> Result<Option<String>, HttpError> {
        self.remove_expired(now);
        let mut matching: Vec<&Cookie> = self
            .cookies
            .iter()
            .filter(|cookie| cookie.matches(url, now))
            .collect();
        matching.sort_by(|left, right| {
            right
                .path
                .len()
                .cmp(&left.path.len())
                .then_with(|| left.creation.cmp(&right.creation))
        });
        if matching.is_empty() {
            return Ok(None);
        }
        let mut header = String::new();
        for cookie in matching {
            let field = format!("{}={}", cookie.name, cookie.value);
            let separator = usize::from(!header.is_empty()) * 2;
            let length = header
                .len()
                .checked_add(separator)
                .and_then(|total| total.checked_add(field.len()))
                .ok_or_else(|| HttpError::resource_limit("cookie header bytes"))?;
            if length > Self::MAX_COOKIE_HEADER_BYTES {
                return Err(HttpError::resource_limit("cookie header bytes"));
            }
            if separator != 0 {
                header.push_str("; ");
            }
            header.push_str(&field);
        }
        Ok(Some(header))
    }

    fn remove_expired(&mut self, now: ClockReading) {
        self.cookies.retain(|cookie| {
            cookie
                .expires_at
                .is_none_or(|expiry| expiry > now.monotonic)
        });
    }
}

impl Cookie {
    fn matches(&self, url: &Url, now: ClockReading) -> bool {
        if self
            .expires_at
            .is_some_and(|expiry| expiry <= now.monotonic)
        {
            return false;
        }
        if self.secure && url.scheme() != "https" {
            return false;
        }
        let host = url.host().to_ascii_lowercase();
        let domain_match = if self.host_only {
            host == self.domain
        } else {
            host == self.domain || host.ends_with(&format!(".{}", self.domain))
        };
        domain_match && path_match(self.path.as_str(), url.path_and_query())
    }
}

fn parse_set_cookie(
    value: &str,
    url: &Url,
    now: ClockReading,
    public_suffix_policy: &PublicSuffixPolicy,
    check_cookies: bool,
) -> Result<Option<Cookie>, HttpError> {
    let mut parts = value.split(';');
    let Some(pair) = parts.next() else {
        return Ok(None);
    };
    let Some((name, value)) = pair.trim().split_once('=') else {
        return Err(HttpError::Cookie("Set-Cookie lacks name/value".to_owned()));
    };
    let name = name.trim().to_owned();
    let value = value.trim().to_owned();
    validate_cookie_pair(&name, &value)?;
    let mut domain = url.host().to_owned();
    let mut host_only = true;
    let mut path = default_cookie_path(url.path_and_query());
    let mut secure = false;
    let mut expires_at = None;
    let mut max_age_seen = false;
    for attribute in parts {
        let attribute = attribute.trim();
        if attribute.eq_ignore_ascii_case("secure") {
            secure = true;
            continue;
        }
        let Some((key, raw_value)) = attribute.split_once('=') else {
            continue;
        };
        match key.trim().to_ascii_lowercase().as_str() {
            "domain" => {
                if raw_value.trim().ends_with('.') {
                    return Ok(None);
                }
                let candidate = normalize_domain(raw_value.trim());
                if candidate.is_empty() {
                    return Err(HttpError::Cookie("empty cookie domain".to_owned()));
                }
                if candidate.len() > 255 || !valid_cookie_domain(&candidate) {
                    return Ok(None);
                }
                if check_cookies
                    && (is_ip_literal(&candidate)
                        || public_suffix_policy.is_public_suffix(&candidate))
                {
                    return Ok(None);
                }
                let host = url.host();
                if candidate != host && !host.ends_with(&format!(".{candidate}")) {
                    return Ok(None);
                }
                domain = candidate;
                host_only = false;
            }
            "path" => path = normalize_path(raw_value.trim()),
            "max-age" => {
                max_age_seen = true;
                let seconds = raw_value
                    .trim()
                    .parse::<i64>()
                    .map_err(|_| HttpError::Cookie("invalid Max-Age".to_owned()))?;
                expires_at = if seconds <= 0 {
                    Some(now.monotonic)
                } else {
                    let duration = Duration::from_secs(u64::try_from(seconds).map_err(|_| {
                        HttpError::Cookie("Max-Age is outside supported range".to_owned())
                    })?);
                    Some(
                        now.monotonic
                            .checked_add(duration)
                            .ok_or_else(|| HttpError::Cookie("Max-Age overflow".to_owned()))?,
                    )
                };
            }
            "expires" if !max_age_seen => {
                let expires_wall = parse_http_date(raw_value.trim())?;
                expires_at = if expires_wall <= now.wall_millis {
                    Some(now.monotonic)
                } else {
                    let delta =
                        u64::try_from(i128::from(expires_wall) - i128::from(now.wall_millis))
                            .map_err(|_| {
                                HttpError::Cookie("Expires is outside supported range".to_owned())
                            })?;
                    Some(
                        now.monotonic
                            .checked_add(Duration::from_millis(delta))
                            .ok_or_else(|| {
                                HttpError::Cookie("Expires monotonic overflow".to_owned())
                            })?,
                    )
                };
            }
            _ => {}
        }
    }
    Ok(Some(Cookie {
        name,
        value,
        domain,
        path,
        secure,
        host_only,
        expires_at,
        creation: 0,
    }))
}

fn validate_cookie_pair(name: &str, value: &str) -> Result<(), HttpError> {
    if name.len() > CookieJar::MAX_COOKIE_NAME_BYTES
        || value.len() > CookieJar::MAX_COOKIE_VALUE_BYTES
    {
        return Err(HttpError::resource_limit("cookie name/value bytes"));
    }
    if name.is_empty()
        || !name.bytes().all(is_cookie_name_byte)
        || value
            .bytes()
            .any(|byte| byte < 0x20 || byte == 0x7f || byte == b';')
    {
        return Err(HttpError::Cookie("invalid cookie name/value".to_owned()));
    }
    Ok(())
}

fn is_cookie_name_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'!'
            | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'0'..=b'9'
            | b'A'..=b'Z'
            | b'^'
            | b'_'
            | b'`'
            | b'a'..=b'z'
            | b'|'
            | b'~'
    )
}

fn parse_http_date(value: &str) -> Result<i64, HttpError> {
    let mut parts = value.split_whitespace();
    let _weekday = parts
        .next()
        .ok_or_else(|| HttpError::Cookie("invalid Expires date".to_owned()))?;
    let day = parts
        .next()
        .ok_or_else(|| HttpError::Cookie("invalid Expires date".to_owned()))?
        .trim_end_matches(',')
        .parse::<u32>()
        .map_err(|_| HttpError::Cookie("invalid Expires day".to_owned()))?;
    let month = parse_month(
        parts
            .next()
            .ok_or_else(|| HttpError::Cookie("invalid Expires month".to_owned()))?,
    )?;
    let year = parts
        .next()
        .ok_or_else(|| HttpError::Cookie("invalid Expires year".to_owned()))?
        .parse::<i32>()
        .map_err(|_| HttpError::Cookie("invalid Expires year".to_owned()))?;
    let time = parts
        .next()
        .ok_or_else(|| HttpError::Cookie("invalid Expires time".to_owned()))?;
    let zone = parts
        .next()
        .ok_or_else(|| HttpError::Cookie("Expires timezone is missing".to_owned()))?;
    if !zone.eq_ignore_ascii_case("GMT") || parts.next().is_some() {
        return Err(HttpError::Cookie("Expires must use GMT".to_owned()));
    }
    let mut time_parts = time.split(':');
    let hour = time_parts
        .next()
        .ok_or_else(|| HttpError::Cookie("invalid Expires hour".to_owned()))?
        .parse::<u32>()
        .map_err(|_| HttpError::Cookie("invalid Expires hour".to_owned()))?;
    let minute = time_parts
        .next()
        .ok_or_else(|| HttpError::Cookie("invalid Expires minute".to_owned()))?
        .parse::<u32>()
        .map_err(|_| HttpError::Cookie("invalid Expires minute".to_owned()))?;
    let second = time_parts
        .next()
        .ok_or_else(|| HttpError::Cookie("invalid Expires second".to_owned()))?
        .parse::<u32>()
        .map_err(|_| HttpError::Cookie("invalid Expires second".to_owned()))?;
    if time_parts.next().is_some()
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return Err(HttpError::Cookie("invalid Expires time/date".to_owned()));
    }
    let days = days_from_civil(year, month, day)
        .ok_or_else(|| HttpError::Cookie("invalid Expires date".to_owned()))?;
    let seconds = i128::from(days)
        .checked_mul(86_400)
        .and_then(|value| {
            value.checked_add(
                i128::from(hour) * 3_600 + i128::from(minute) * 60 + i128::from(second),
            )
        })
        .ok_or_else(|| HttpError::Cookie("Expires timestamp overflow".to_owned()))?;
    i64::try_from(
        seconds
            .checked_mul(1_000)
            .ok_or_else(|| HttpError::Cookie("Expires timestamp overflow".to_owned()))?,
    )
    .map_err(|_| HttpError::Cookie("Expires timestamp overflow".to_owned()))
}

fn parse_month(value: &str) -> Result<u32, HttpError> {
    match value.to_ascii_lowercase().as_str() {
        "jan" => Ok(1),
        "feb" => Ok(2),
        "mar" => Ok(3),
        "apr" => Ok(4),
        "may" => Ok(5),
        "jun" => Ok(6),
        "jul" => Ok(7),
        "aug" => Ok(8),
        "sep" => Ok(9),
        "oct" => Ok(10),
        "nov" => Ok(11),
        "dec" => Ok(12),
        _ => Err(HttpError::Cookie("invalid Expires month".to_owned())),
    }
}

fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
        return None;
    }
    let year = i64::from(year) - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 }.div_euclid(400);
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Some(era * 146_097 + day_of_era - 719_468)
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn normalize_domain(value: &str) -> String {
    value.trim().trim_start_matches('.').to_ascii_lowercase()
}

fn valid_cookie_domain(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        && !value.starts_with('.')
        && !value.ends_with('.')
}

fn is_ip_literal(value: &str) -> bool {
    value.parse::<std::net::Ipv4Addr>().is_ok() || value.parse::<std::net::Ipv6Addr>().is_ok()
}

fn normalize_path(value: &str) -> String {
    if value.is_empty() || !value.starts_with('/') {
        "/".to_owned()
    } else {
        value.to_owned()
    }
}

fn default_cookie_path(path_and_query: &str) -> String {
    let path = path_and_query.split('?').next().unwrap_or("/");
    if path.is_empty() || path == "/" {
        return "/".to_owned();
    }
    path.rsplit_once('/')
        .map_or(
            "/",
            |(prefix, _)| {
                if prefix.is_empty() { "/" } else { prefix }
            },
        )
        .to_owned()
}

fn path_match(cookie_path: &str, request_path: &str) -> bool {
    let request_path = request_path.split('?').next().unwrap_or("/");
    if cookie_path == "/" {
        return true;
    }
    request_path == cookie_path
        || (request_path.starts_with(cookie_path)
            && if cookie_path.ends_with('/') {
                true
            } else {
                request_path.as_bytes().get(cookie_path.len()) == Some(&b'/')
            })
}

/// A cache decision made before a transport call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CacheDecision {
    /// No usable representation is retained.
    Miss,
    /// A fresh representation can be served without transport.
    Fresh(Response),
    /// A stale representation can be conditionally revalidated.
    Revalidate {
        /// Headers to add to the conditional request.
        headers: Headers,
        /// The stale representation used if the peer returns 304.
        cached: Response,
    },
}

#[derive(Clone, Eq, PartialEq)]
struct CacheEntry {
    url_key: String,
    method: Method,
    response: Response,
    stored_at: Duration,
    expires_at: Option<Duration>,
    requires_revalidation: bool,
    etag: Option<String>,
    last_modified: Option<String>,
    vary: Vec<(String, String)>,
    sequence: u64,
    size_bytes: usize,
}

impl std::fmt::Debug for CacheEntry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CacheEntry")
            .field("url", &redacted_cache_url(&self.url_key))
            .field("method", &self.method)
            .field("response", &self.response)
            .field("stored_at", &self.stored_at)
            .field("expires_at", &self.expires_at)
            .field("requires_revalidation", &self.requires_revalidation)
            .field("has_etag", &self.etag.is_some())
            .field("has_last_modified", &self.last_modified.is_some())
            // Vary values can contain request-derived secrets (for example a
            // token-bearing header). Expose only the field names and byte
            // lengths while retaining enough shape for diagnostics.
            .field(
                "vary",
                &self
                    .vary
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.len()))
                    .collect::<Vec<_>>(),
            )
            .field("sequence", &self.sequence)
            .field("size_bytes", &self.size_bytes)
            .finish()
    }
}

/// Bounded per-user HTTP cache state.
#[derive(Clone, Eq, PartialEq)]
pub struct CacheStore {
    entries: Vec<CacheEntry>,
    maximum: usize,
    maximum_bytes: usize,
    current_bytes: usize,
    next_sequence: u64,
    use_expires: bool,
}

impl std::fmt::Debug for CacheStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CacheStore")
            .field("entry_count", &self.entries.len())
            .field("maximum", &self.maximum)
            .field("maximum_bytes", &self.maximum_bytes)
            .field("current_bytes", &self.current_bytes)
            .field("use_expires", &self.use_expires)
            .field("next_sequence", &self.next_sequence)
            .field("entries", &self.entries.iter().take(32).collect::<Vec<_>>())
            .finish()
    }
}

impl Default for CacheStore {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            maximum: 5_000,
            maximum_bytes: 64 * 1024 * 1024,
            current_bytes: 0,
            next_sequence: 0,
            use_expires: true,
        }
    }
}

impl CacheStore {
    /// Creates an empty cache with a finite entry bound.
    pub fn new(maximum: usize) -> Result<Self, HttpError> {
        if maximum == 0 {
            return Err(HttpError::resource_limit("cache capacity must be non-zero"));
        }
        Ok(Self {
            entries: Vec::new(),
            maximum,
            maximum_bytes: 64 * 1024 * 1024,
            current_bytes: 0,
            next_sequence: 0,
            use_expires: true,
        })
    }

    /// Creates an empty cache with explicit entry and aggregate byte bounds.
    pub fn with_limits(maximum: usize, maximum_bytes: usize) -> Result<Self, HttpError> {
        if maximum == 0 || maximum_bytes == 0 {
            return Err(HttpError::resource_limit(
                "cache entry and byte capacities must be non-zero",
            ));
        }
        Ok(Self {
            entries: Vec::new(),
            maximum,
            maximum_bytes,
            current_bytes: 0,
            next_sequence: 0,
            use_expires: true,
        })
    }

    /// Returns the number of retained representations.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether no entries are retained.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the configured aggregate byte bound.
    #[must_use]
    pub const fn maximum_bytes(&self) -> usize {
        self.maximum_bytes
    }

    /// Returns the aggregate bytes currently retained.
    #[must_use]
    pub const fn current_bytes(&self) -> usize {
        self.current_bytes
    }

    /// Changes the maximum number of retained entries, evicting the oldest
    /// entries first when the new bound is smaller than the current size.
    pub fn set_maximum(&mut self, maximum: usize) -> Result<(), HttpError> {
        if maximum == 0 {
            return Err(HttpError::resource_limit("cache capacity must be non-zero"));
        }
        self.maximum = maximum;
        while self.entries.len() > self.maximum {
            let Some(index) = self
                .entries
                .iter()
                .enumerate()
                .min_by(|(_, left), (_, right)| {
                    left.stored_at
                        .cmp(&right.stored_at)
                        .then_with(|| left.sequence.cmp(&right.sequence))
                })
                .map(|(index, _)| index)
            else {
                return Err(HttpError::Cache("cache eviction".to_owned()));
            };
            let removed = self.entries.remove(index);
            self.current_bytes = self
                .current_bytes
                .checked_sub(removed.size_bytes)
                .ok_or_else(|| HttpError::Cache("cache byte accounting underflow".to_owned()))?;
        }
        Ok(())
    }

    /// Returns whether Cache-Control/Expires freshness metadata is honored.
    #[must_use]
    pub const fn use_expires(&self) -> bool {
        self.use_expires
    }

    /// Selects whether Cache-Control/Expires freshness metadata is honored.
    ///
    /// Conditional validators (ETag and Last-Modified) remain retained when
    /// this is disabled; only the freshness shortcut is disabled.
    pub fn set_use_expires(&mut self, use_expires: bool) {
        self.use_expires = use_expires;
    }

    /// Removes all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.current_bytes = 0;
        self.next_sequence = 0;
    }

    /// Clears all representations at an iteration/thread-group boundary when
    /// the caller enables the corresponding lifecycle switch.
    pub fn reset_for_iteration(&mut self, clear_each_iteration: bool) {
        if clear_each_iteration {
            self.clear();
        }
    }

    /// Looks up a GET/HEAD request.
    pub fn lookup(&self, request: &Request, now: ClockReading) -> CacheDecision {
        if !matches!(request.method(), Method::Get | Method::Head) {
            return CacheDecision::Miss;
        }
        let Some(entry) = self
            .entries
            .iter()
            .filter(|entry| {
                entry.url_key == request.url().cache_key() && entry.method == *request.method()
            })
            .filter(|entry| vary_matches(entry, request))
            .max_by_key(|entry| entry.sequence)
        else {
            return CacheDecision::Miss;
        };
        if !entry.requires_revalidation
            && entry
                .expires_at
                .is_some_and(|expiry| expiry > now.monotonic)
        {
            let mut response = entry.response.clone();
            response.mark_from_cache();
            return CacheDecision::Fresh(response);
        }
        let mut headers = Headers::new();
        if let Some(etag) = &entry.etag
            && headers.insert("If-None-Match", etag.clone()).is_err()
        {
            return CacheDecision::Miss;
        }
        if let Some(last_modified) = &entry.last_modified
            && headers
                .insert("If-Modified-Since", last_modified.clone())
                .is_err()
        {
            return CacheDecision::Miss;
        }
        if headers.is_empty() {
            CacheDecision::Miss
        } else {
            CacheDecision::Revalidate {
                headers,
                cached: entry.response.clone(),
            }
        }
    }

    /// Invalidates every representation for a GET/HEAD target.
    ///
    /// A response that cannot safely become a cache entry must also retire an
    /// older stale representation. Keeping that representation would allow a
    /// later request to replay data that the peer explicitly marked private,
    /// no-store, malformed, or otherwise non-cacheable.
    pub fn invalidate(&mut self, request: &Request) -> Result<usize, HttpError> {
        if !matches!(request.method(), Method::Get | Method::Head) {
            return Ok(0);
        }
        let url_key = request.url().cache_key();
        let removed_bytes = self
            .entries
            .iter()
            .filter(|entry| entry.url_key == url_key && entry.method == *request.method())
            .try_fold(0usize, |total, entry| {
                total
                    .checked_add(entry.size_bytes)
                    .ok_or_else(|| HttpError::resource_limit("cache byte accounting"))
            })?;
        let mut removed = 0usize;
        self.entries.retain(|entry| {
            if entry.url_key == url_key && entry.method == *request.method() {
                removed += 1;
                false
            } else {
                true
            }
        });
        self.current_bytes = self
            .current_bytes
            .checked_sub(removed_bytes)
            .ok_or_else(|| HttpError::Cache("cache byte accounting underflow".to_owned()))?;
        Ok(removed)
    }

    /// Stores a cacheable successful GET/HEAD response.
    pub fn store(
        &mut self,
        request: &Request,
        response: &Response,
        now: ClockReading,
    ) -> Result<bool, HttpError> {
        if let Err(error) = crate::response::validate_status_code(response.status()) {
            self.invalidate(request)?;
            return Err(error);
        }
        // Redirects stay on the sampler's redirect state machine.  Caching a
        // 3xx and returning it as a terminal cache hit would skip Location
        // resolution and could turn an old cross-origin redirect into a
        // credential-bearing replay.
        if !matches!(request.method(), Method::Get | Method::Head)
            || !(200..300).contains(&response.status())
            || response.status() == 204
        {
            self.invalidate(request)?;
            return Ok(false);
        }
        let vary = match vary_values(response, request) {
            Ok(vary) => vary,
            Err(error) => {
                self.invalidate(request)?;
                return Err(error);
            }
        };
        if vary.iter().any(|(name, _)| name == "*") {
            self.invalidate(request)?;
            return Ok(false);
        }
        if request.headers().contains("authorization")
            && !response
                .headers()
                .values("cache-control")
                .any(cache_control_is_public)
        {
            self.invalidate(request)?;
            return Ok(false);
        }
        let entry_url_key = request.url().cache_key();
        let metadata = match cache_metadata(response, now, self.use_expires) {
            Ok(metadata) => metadata,
            Err(error) => {
                self.invalidate(request)?;
                return Err(error);
            }
        };
        let Some(metadata) = metadata else {
            self.invalidate(request)?;
            return Ok(false);
        };
        let entry = CacheEntry {
            url_key: entry_url_key,
            method: request.method().clone(),
            response: response.clone(),
            stored_at: now.monotonic,
            expires_at: if self.use_expires {
                metadata.expires_at
            } else {
                None
            },
            requires_revalidation: metadata.requires_revalidation,
            etag: response.headers().get("etag").map(str::to_owned),
            last_modified: response.headers().get("last-modified").map(str::to_owned),
            vary,
            sequence: self.next_sequence,
            size_bytes: 0,
        };
        let mut entry = entry;
        entry.size_bytes = match cache_entry_size(&entry) {
            Ok(size) => size,
            Err(error) => {
                self.invalidate(request)?;
                return Err(error);
            }
        };
        if entry.size_bytes > self.maximum_bytes {
            self.invalidate(request)?;
            return Ok(false);
        }
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| HttpError::resource_limit("cache sequence"))?;
        if let Some(index) = self.entries.iter().position(|existing| {
            existing.url_key == entry.url_key
                && existing.method == entry.method
                && existing.vary == entry.vary
        }) {
            let old_size = self.entries[index].size_bytes;
            self.current_bytes = self
                .current_bytes
                .checked_sub(old_size)
                .ok_or_else(|| HttpError::Cache("cache byte accounting underflow".to_owned()))?;
            self.entries.remove(index);
            while self
                .current_bytes
                .checked_add(entry.size_bytes)
                .is_none_or(|total| total > self.maximum_bytes)
            {
                let Some(eviction_index) = self
                    .entries
                    .iter()
                    .enumerate()
                    .min_by(|(_, left), (_, right)| {
                        left.stored_at
                            .cmp(&right.stored_at)
                            .then_with(|| left.sequence.cmp(&right.sequence))
                    })
                    .map(|(eviction_index, _)| eviction_index)
                else {
                    return Err(HttpError::resource_limit("cache eviction"));
                };
                let removed = self.entries.remove(eviction_index);
                self.current_bytes = self
                    .current_bytes
                    .checked_sub(removed.size_bytes)
                    .ok_or_else(|| {
                        HttpError::Cache("cache byte accounting underflow".to_owned())
                    })?;
            }
            self.current_bytes = self
                .current_bytes
                .checked_add(entry.size_bytes)
                .ok_or_else(|| HttpError::resource_limit("cache byte accounting"))?;
            self.entries.push(entry);
            return Ok(true);
        }
        while self.entries.len() >= self.maximum
            || self
                .current_bytes
                .checked_add(entry.size_bytes)
                .is_none_or(|total| total > self.maximum_bytes)
        {
            let Some(index) = self
                .entries
                .iter()
                .enumerate()
                .min_by(|(_, left), (_, right)| {
                    left.stored_at
                        .cmp(&right.stored_at)
                        .then_with(|| left.sequence.cmp(&right.sequence))
                })
                .map(|(index, _)| index)
            else {
                return Err(HttpError::resource_limit("cache eviction"));
            };
            let removed = self.entries.remove(index);
            self.current_bytes = self
                .current_bytes
                .checked_sub(removed.size_bytes)
                .ok_or_else(|| HttpError::Cache("cache byte accounting underflow".to_owned()))?;
        }
        self.current_bytes = self
            .current_bytes
            .checked_add(entry.size_bytes)
            .ok_or_else(|| HttpError::resource_limit("cache byte accounting"))?;
        self.entries.push(entry);
        Ok(true)
    }

    /// Returns the cached representation matching a request, if any.
    ///
    /// The request is deliberately required here because a stored
    /// representation's `Vary` fields are part of its cache identity.  A
    /// caller without the current request-header view must not use this
    /// accessor as a convenient URL-only fallback.
    #[must_use]
    pub fn cached_response(&self, request: &Request) -> Option<&Response> {
        self.entries
            .iter()
            .filter(|entry| {
                entry.url_key == request.url().cache_key()
                    && entry.method == *request.method()
                    && vary_matches(entry, request)
            })
            .max_by_key(|entry| entry.sequence)
            .map(|entry| &entry.response)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CacheMetadata {
    expires_at: Option<Duration>,
    requires_revalidation: bool,
}

fn cache_metadata(
    response: &Response,
    now: ClockReading,
    use_expires: bool,
) -> Result<Option<CacheMetadata>, HttpError> {
    let mut max_age = None;
    let mut requires_revalidation = false;
    for cache_control in response.headers().values("cache-control") {
        for directive in cache_control.split(',') {
            let directive = directive.trim();
            let (name, value) = directive
                .split_once('=')
                .map_or((directive, None), |(name, value)| {
                    (name.trim(), Some(value.trim()))
                });
            if name.eq_ignore_ascii_case("no-store") || name.eq_ignore_ascii_case("private") {
                return Ok(None);
            }
            if name.eq_ignore_ascii_case("no-cache") {
                requires_revalidation = true;
            }
            if use_expires && name.eq_ignore_ascii_case("max-age") {
                let Some(value) = value else {
                    return Err(HttpError::Cache(
                        "Cache-Control max-age value is missing".to_owned(),
                    ));
                };
                max_age =
                    Some(value.trim_matches('"').parse::<u64>().map_err(|_| {
                        HttpError::Cache("invalid Cache-Control max-age".to_owned())
                    })?);
            }
        }
    }
    let expires_at = if !use_expires {
        None
    } else if let Some(max_age) = max_age {
        Some(
            now.monotonic
                .checked_add(Duration::from_secs(max_age))
                .ok_or_else(|| HttpError::Cache("cache expiration overflow".to_owned()))?,
        )
    } else if let Some(expires) = response.headers().get("expires") {
        let expires_wall =
            parse_http_date(expires.trim()).map_err(|error| HttpError::Cache(error.to_string()))?;
        if expires_wall <= now.wall_millis {
            Some(now.monotonic)
        } else {
            let delta = u64::try_from(i128::from(expires_wall) - i128::from(now.wall_millis))
                .map_err(|_| HttpError::Cache("Expires is outside supported range".to_owned()))?;
            Some(
                now.monotonic
                    .checked_add(Duration::from_millis(delta))
                    .ok_or_else(|| HttpError::Cache("cache expiration overflow".to_owned()))?,
            )
        }
    } else {
        None
    };
    if expires_at.is_none()
        && response.headers().get("etag").is_none()
        && response.headers().get("last-modified").is_none()
    {
        return Ok(None);
    }
    Ok(Some(CacheMetadata {
        expires_at,
        requires_revalidation,
    }))
}

fn cache_control_is_public(value: &str) -> bool {
    value
        .split(',')
        .any(|directive| directive.trim().eq_ignore_ascii_case("public"))
}

fn cache_entry_size(entry: &CacheEntry) -> Result<usize, HttpError> {
    let mut size = entry.url_key.len();
    size = size
        .checked_add(entry.method.as_str().len())
        .and_then(|value| value.checked_add(entry.response.reason().len()))
        .and_then(|value| value.checked_add(entry.response.body().len()))
        .ok_or_else(|| HttpError::resource_limit("cache representation bytes"))?;
    size = size
        .checked_add(entry.response.headers().checked_wire_len()?)
        .ok_or_else(|| HttpError::resource_limit("cache representation bytes"))?;
    for (name, value) in &entry.vary {
        size = size
            .checked_add(name.len())
            .and_then(|total| total.checked_add(value.len()))
            .ok_or_else(|| HttpError::resource_limit("cache Vary bytes"))?;
    }
    Ok(size)
}

fn redacted_cache_url(value: &str) -> String {
    // Cache keys intentionally include the query for representation identity,
    // but query values commonly carry tokens and other request state. Keep a
    // bounded origin/path diagnostic while never echoing that raw query.
    let without_query = value.split_once('?').map_or(value, |(prefix, _)| prefix);
    bounded_debug(without_query, 128)
}

fn vary_values(response: &Response, request: &Request) -> Result<Vec<(String, String)>, HttpError> {
    response
        .headers()
        .values("vary")
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| {
            if !is_header_token(name) {
                return Err(HttpError::Cache(
                    "Vary contains an invalid field name".to_owned(),
                ));
            }
            let request_value = request
                .headers()
                .values(name)
                .collect::<Vec<_>>()
                .join(", ");
            Ok((name.to_ascii_lowercase(), request_value))
        })
        .collect()
}

fn is_header_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            matches!(
                byte,
                b'!'
                    | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'0'..=b'9'
                    | b'A'..=b'Z'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'a'..=b'z'
                    | b'|'
                    | b'~'
            )
        })
}

fn vary_matches(entry: &CacheEntry, request: &Request) -> bool {
    entry.vary.iter().all(|(name, value)| {
        request
            .headers()
            .values(name)
            .collect::<Vec<_>>()
            .join(", ")
            == *value
    })
}

/// Authentication mechanism understood by the semantic core.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AuthMechanism {
    /// HTTP Basic authentication.
    Basic,
    /// Digest authentication requires a protocol adapter.
    Digest,
    /// Bearer token authentication.
    Bearer,
    /// Kerberos/SPNEGO authentication requires a JVM/security-provider adapter.
    Kerberos,
}

/// One URL-prefix credential entry.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthEntry {
    url_prefix: String,
    origin: crate::Origin,
    path_prefix: String,
    username: String,
    password: String,
    domain: Option<String>,
    domain_valid: bool,
    realm: Option<String>,
    realm_valid: bool,
    mechanism: AuthMechanism,
}

impl std::fmt::Debug for AuthEntry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthEntry")
            .field("url_prefix", &bounded_auth_url(&self.url_prefix))
            .field("username", &bounded_debug(&self.username, 128))
            .field("password", &"<redacted>")
            .field(
                "domain",
                &if self.domain_valid {
                    self.domain.as_ref().map(|_| "<redacted>")
                } else {
                    Some("<invalid>")
                },
            )
            .field(
                "realm",
                &if self.realm_valid {
                    self.realm.as_ref().map(|realm| bounded_debug(realm, 128))
                } else {
                    Some("<invalid>".to_owned())
                },
            )
            .field("mechanism", &self.mechanism)
            .finish()
    }
}

fn bounded_debug(value: &str, maximum: usize) -> String {
    if value.len() <= maximum {
        return value.to_owned();
    }
    let mut end = maximum;
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    format!("{}…", &value[..end])
}

fn bounded_auth_url(value: &str) -> String {
    let value = value.split_once('?').map_or_else(
        || value.to_owned(),
        |(prefix, _)| format!("{prefix}?<redacted>"),
    );
    bounded_debug(&value, 128)
}

impl AuthEntry {
    const MAX_REALM_BYTES: usize = 256;
    const MAX_DOMAIN_BYTES: usize = 256;

    /// Creates a URL-prefix credential entry.
    pub fn new(
        url_prefix: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
        mechanism: AuthMechanism,
    ) -> Result<Self, HttpError> {
        let url_prefix = url_prefix.into();
        let username = username.into();
        let password = password.into();
        if url_prefix.len() > crate::MAX_URL_BYTES
            || username.len() > 16 * 1024
            || password.len() > 16 * 1024
        {
            return Err(HttpError::resource_limit("authentication entry bytes"));
        }
        let parsed = Url::parse(url_prefix.clone())?;
        let url_prefix = format!(
            "{}://{}{}",
            parsed.scheme(),
            parsed.authority(),
            parsed.path()
        );
        Ok(Self {
            url_prefix,
            origin: parsed.origin_key(),
            // Query and fragment components do not scope HTTP credentials;
            // authorization is selected by origin and path boundary.
            path_prefix: parsed.path().to_owned(),
            username,
            password,
            domain: None,
            domain_valid: true,
            realm: None,
            realm_valid: true,
            mechanism,
        })
    }

    /// Sets the optional challenge realm.
    #[must_use]
    pub fn realm(mut self, realm: impl Into<String>) -> Self {
        let realm = realm.into();
        if realm.is_empty() {
            // JMeter's absent/empty Authorization realm is the default
            // wildcard configuration; retain that distinction from an
            // explicitly named realm.
            self.realm = None;
            self.realm_valid = true;
            return self;
        }
        if realm.len() <= Self::MAX_REALM_BYTES
            && !realm.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
        {
            self.realm = Some(realm);
            self.realm_valid = true;
        } else {
            // Preserve the infallible builder's source compatibility while
            // failing closed for an invalid/oversized realm. Callers that
            // need a typed construction error should use `try_realm`.
            self.realm = None;
            self.realm_valid = false;
        }
        self
    }

    /// Sets a bounded challenge realm and reports invalid input explicitly.
    pub fn try_realm(mut self, realm: impl Into<String>) -> Result<Self, HttpError> {
        let realm = realm.into();
        if realm.len() > Self::MAX_REALM_BYTES {
            return Err(HttpError::resource_limit("authentication realm bytes"));
        }
        if realm.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
            return Err(HttpError::Authentication(
                "authentication realm contains a control byte".to_owned(),
            ));
        }
        self.realm = (!realm.is_empty()).then_some(realm);
        self.realm_valid = true;
        Ok(self)
    }

    /// Sets the optional NTLM domain without exposing it in diagnostics.
    #[must_use]
    pub fn domain(mut self, domain: impl Into<String>) -> Self {
        let domain = domain.into();
        if domain.is_empty() {
            self.domain = None;
            self.domain_valid = true;
        } else if domain.len() <= Self::MAX_DOMAIN_BYTES
            && !domain.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
        {
            self.domain = Some(domain);
            self.domain_valid = true;
        } else {
            // Preserve the infallible builder's source compatibility while
            // failing closed when an adapter attempts to add the entry. Use
            // `try_domain` when construction-time errors are preferred.
            self.domain = None;
            self.domain_valid = false;
        }
        self
    }

    /// Sets a bounded NTLM domain and reports invalid input explicitly.
    pub fn try_domain(mut self, domain: impl Into<String>) -> Result<Self, HttpError> {
        let domain = domain.into();
        if domain.len() > Self::MAX_DOMAIN_BYTES {
            return Err(HttpError::resource_limit("authentication domain bytes"));
        }
        if domain.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
            return Err(HttpError::Authentication(
                "authentication domain contains a control byte".to_owned(),
            ));
        }
        self.domain = (!domain.is_empty()).then_some(domain);
        self.domain_valid = true;
        Ok(self)
    }

    /// Returns the configured NTLM domain, if present.
    #[must_use]
    pub fn configured_domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    /// Returns the configured mechanism.
    #[must_use]
    pub const fn mechanism(&self) -> AuthMechanism {
        self.mechanism
    }

    /// Returns the URL prefix.
    #[must_use]
    pub fn url_prefix(&self) -> &str {
        &self.url_prefix
    }

    /// Returns the configured challenge realm, if any.
    #[must_use]
    pub fn configured_realm(&self) -> Option<&str> {
        self.realm.as_deref()
    }
}

/// Bounded per-user authentication state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthStore {
    entries: Vec<AuthEntry>,
    maximum: usize,
}

impl Default for AuthStore {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            maximum: 128,
        }
    }
}

impl AuthStore {
    /// Creates an empty store with a finite entry bound.
    pub fn new(maximum: usize) -> Result<Self, HttpError> {
        if maximum == 0 {
            return Err(HttpError::resource_limit("auth capacity must be non-zero"));
        }
        Ok(Self {
            entries: Vec::new(),
            maximum,
        })
    }

    /// Adds one entry, ignoring an exact duplicate URL prefix.
    pub fn add(&mut self, entry: AuthEntry) -> Result<(), HttpError> {
        if !entry.realm_valid {
            return Err(HttpError::Authentication(
                "authentication realm is invalid".to_owned(),
            ));
        }
        if !entry.domain_valid {
            return Err(HttpError::Authentication(
                "authentication domain is invalid".to_owned(),
            ));
        }
        if self.entries.iter().any(|existing| {
            existing.origin == entry.origin && existing.path_prefix == entry.path_prefix
        }) {
            // AuthManager scans in insertion order and ignores duplicate base
            // URLs.  Keeping the original entry is observable when the
            // duplicate credentials differ.
            return Ok(());
        }
        if self.entries.len() >= self.maximum {
            self.entries.remove(0);
        }
        self.entries.push(entry);
        Ok(())
    }

    /// Returns configured entries without exposing mutable secrets.
    #[must_use]
    pub fn entries(&self) -> &[AuthEntry] {
        &self.entries
    }

    /// Removes all configured credentials.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Returns the first insertion-order entry matching this URL.
    #[must_use]
    pub fn first_matching(&self, url: &Url) -> Option<&AuthEntry> {
        self.entries
            .iter()
            .find(|entry| entry.realm_valid && auth_matches(entry, url))
    }

    /// Builds a preemptive authorization header for the first matching entry.
    pub fn authorization(&self, url: &Url) -> Result<Option<String>, HttpError> {
        let Some(entry) = self.first_matching(url) else {
            return Ok(None);
        };
        match entry.mechanism {
            AuthMechanism::Basic => Ok(Some(format!(
                "Basic {}",
                base64_encode(format!("{}:{}", entry.username, entry.password).as_bytes())
            ))),
            AuthMechanism::Bearer => Ok(Some(format!("Bearer {}", entry.password))),
            AuthMechanism::Digest => Err(HttpError::Unsupported(
                "digest authentication requires a protocol adapter".to_owned(),
            )),
            AuthMechanism::Kerberos => Err(HttpError::Unsupported(
                "Kerberos authentication requires a JVM security-provider adapter".to_owned(),
            )),
        }
    }

    /// Builds an authorization header for an explicit Basic challenge.
    pub fn authorization_for_challenge(
        &self,
        url: &Url,
        challenge: &str,
    ) -> Result<Option<String>, HttpError> {
        let Some(challenge_realm) = basic_challenge_realm(challenge) else {
            return Ok(None);
        };
        let Some(entry) = self.first_matching(url) else {
            return Ok(None);
        };
        if !realm_matches(entry, challenge_realm.as_deref()) {
            return Ok(None);
        }
        if entry.mechanism != AuthMechanism::Basic {
            return Err(HttpError::Unsupported(
                "non-Basic challenge authentication requires a protocol adapter".to_owned(),
            ));
        }
        Ok(Some(format!(
            "Basic {}",
            base64_encode(format!("{}:{}", entry.username, entry.password).as_bytes())
        )))
    }
}

/// Returns the realm from a Basic challenge. A missing realm is represented as
/// `Some(None)` so an explicitly configured realm can be distinguished from an
/// absent/wildcard configuration. Malformed or non-Basic challenges fail
/// closed and do not trigger a retry.
fn basic_challenge_realm(challenge: &str) -> Option<Option<String>> {
    for segment in split_quoted_commas(challenge) {
        let segment = segment.trim();
        let mut words = segment.split_ascii_whitespace();
        let Some(scheme) = words.next() else {
            continue;
        };
        if !scheme.eq_ignore_ascii_case("basic") {
            continue;
        }
        let parameter_start = scheme.len();
        let parameters = segment.get(parameter_start..)?;
        let parameters = parameters.trim();
        let Some(raw_realm) = find_auth_parameter(parameters, "realm") else {
            return Some(None);
        };
        let realm = unquote_auth_value(raw_realm)?;
        if realm.len() > AuthEntry::MAX_REALM_BYTES
            || realm.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
        {
            return None;
        }
        return Some(Some(realm));
    }
    None
}

fn split_quoted_commas(value: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    let mut start = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    for (index, byte) in value.bytes().enumerate() {
        if escaped {
            escaped = false;
        } else if quoted && byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            quoted = !quoted;
        } else if byte == b',' && !quoted {
            segments.push(&value[start..index]);
            start = index + 1;
        }
    }
    segments.push(&value[start..]);
    segments
}

fn find_auth_parameter<'a>(parameters: &'a str, wanted: &str) -> Option<&'a str> {
    for segment in split_quoted_commas(parameters) {
        let Some((name, value)) = segment.trim().split_once('=') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case(wanted) {
            return Some(value.trim());
        }
    }
    None
}

fn unquote_auth_value(value: &str) -> Option<String> {
    if let Some(value) = value.strip_prefix('"') {
        let value = value.strip_suffix('"')?;
        let mut unquoted = String::with_capacity(value.len());
        let mut escaped = false;
        for character in value.chars() {
            if escaped {
                unquoted.push(character);
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else {
                unquoted.push(character);
            }
        }
        if escaped {
            return None;
        }
        Some(unquoted)
    } else if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

fn realm_matches(entry: &AuthEntry, challenge_realm: Option<&str>) -> bool {
    if !entry.realm_valid {
        return false;
    }
    match entry.realm.as_deref() {
        // AuthScope's absent realm is an explicit wildcard: it may satisfy a
        // challenge with a realm, an omitted realm, or an empty realm.
        None | Some("*") => true,
        Some(configured) => challenge_realm.is_some_and(|actual| actual == configured),
    }
}

fn auth_matches(entry: &AuthEntry, url: &Url) -> bool {
    if entry.origin != url.origin_key() {
        return false;
    }
    let path = url.path();
    path == entry.path_prefix
        || (path.starts_with(&entry.path_prefix)
            && (entry.path_prefix.ends_with('/')
                || path.as_bytes().get(entry.path_prefix.len()) == Some(&b'/')))
}

fn base64_encode(value: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(value.len().div_ceil(3) * 4);
    for chunk in value.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(char::from(TABLE[usize::from(first >> 2)]));
        output.push(char::from(
            TABLE[usize::from(((first & 0x03) << 4) | (second >> 4))],
        ));
        output.push(if chunk.len() > 1 {
            char::from(TABLE[usize::from(((second & 0x0f) << 2) | (third >> 6))])
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            char::from(TABLE[usize::from(third & 0x3f)])
        } else {
            '='
        });
    }
    output
}

/// The combined cookie/cache/auth/header state owned by one virtual user.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct UserHttpState {
    /// Per-user DNS metadata cache.
    pub dns: DnsCache,
    /// Cookie state.
    pub cookies: CookieJar,
    /// Cache state.
    pub cache: CacheStore,
    /// Authentication state.
    pub auth: AuthStore,
    /// Configured request headers.
    pub headers: HeaderManager,
}

impl std::fmt::Debug for UserHttpState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UserHttpState")
            .field("dns", &self.dns)
            .field("cookies", &self.cookies)
            .field("cache", &self.cache)
            .field("auth", &self.auth)
            .field("headers", &self.headers)
            .finish()
    }
}

/// Explicit per-iteration reset switches for per-user protocol state.
///
/// The defaults preserve state between iterations, matching JMeter's
/// same-user behavior.  Embeddings that model `clearEachIteration` or a
/// thread-group-controlled reset opt in field by field.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StateLifecycle {
    /// Drop retained DNS records at an iteration boundary.
    pub clear_dns_each_iteration: bool,
    /// Restore the captured initial cookie collection.
    pub clear_cookies_each_iteration: bool,
    /// Drop cached representations at an iteration boundary.
    pub clear_cache_each_iteration: bool,
    /// Drop preemptive/challenge credentials at an iteration boundary.
    pub clear_auth_each_iteration: bool,
}

impl UserHttpState {
    /// Creates all managers with explicit finite capacities.
    pub fn new(limits: SessionLimits) -> Result<Self, HttpError> {
        Ok(Self {
            dns: DnsCache::new(limits.max_dns_entries)?,
            cookies: CookieJar::new(limits.max_cookies)?,
            cache: CacheStore::with_limits(limits.max_cache_entries, limits.max_cache_bytes)?,
            auth: AuthStore::new(limits.max_auth_entries)?,
            headers: HeaderManager::new(limits.max_headers)?,
        })
    }

    /// Applies one explicit iteration lifecycle boundary.
    pub fn reset_for_iteration(&mut self, lifecycle: StateLifecycle) {
        if lifecycle.clear_dns_each_iteration {
            self.dns.clear();
        }
        self.cookies
            .reset_for_iteration(lifecycle.clear_cookies_each_iteration);
        self.cache
            .reset_for_iteration(lifecycle.clear_cache_each_iteration);
        if lifecycle.clear_auth_each_iteration {
            self.auth.clear();
        }
    }
}

/// Bounded state capacities for one virtual user.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionLimits {
    /// Maximum retained DNS records.
    pub max_dns_entries: usize,
    /// Maximum retained cookies.
    pub max_cookies: usize,
    /// Maximum retained cache entries.
    pub max_cache_entries: usize,
    /// Maximum aggregate bytes retained by the cache.
    pub max_cache_bytes: usize,
    /// Maximum retained authentication entries.
    pub max_auth_entries: usize,
    /// Maximum configured header fields.
    pub max_headers: usize,
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            max_dns_entries: 256,
            max_cookies: 512,
            max_cache_entries: 5_000,
            max_cache_bytes: 64 * 1024 * 1024,
            max_auth_entries: 128,
            max_headers: 128,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "tests use expect at assertion boundaries for fixed state fixtures"
    )]

    use super::{CacheDecision, CacheStore, Cookie, CookieJar, DnsCache};
    use crate::{ClockReading, DnsConfiguration, HttpError, Request, Response, StaticDnsHost};
    use std::time::Duration;

    fn now() -> ClockReading {
        ClockReading::new(0, Duration::ZERO)
    }

    fn cacheable_response(body: &str) -> Response {
        Response::with_body(200, body.as_bytes().to_vec())
            .expect("bounded response")
            .with_header("Cache-Control", "max-age=60")
            .expect("cache metadata")
    }

    #[test]
    fn cached_response_requires_matching_vary_request_headers() {
        let mut response = cacheable_response("mode-a");
        response
            .add_header("Vary", "X-Mode")
            .expect("vary metadata");
        let request_a = Request::get("http://example.test/vary")
            .expect("request")
            .with_header("X-Mode", "a")
            .expect("request header");
        let request_b = Request::get("http://example.test/vary")
            .expect("request")
            .with_header("X-Mode", "b")
            .expect("request header");
        let request_without_mode = Request::get("http://example.test/vary").expect("request");
        let mut cache = CacheStore::new(4).expect("cache");

        assert!(
            cache
                .store(&request_a, &response, now())
                .expect("cache store")
        );
        assert_eq!(
            cache
                .cached_response(&request_a)
                .expect("matching representation")
                .body(),
            b"mode-a"
        );
        assert!(cache.cached_response(&request_b).is_none());
        assert!(cache.cached_response(&request_without_mode).is_none());
        assert!(matches!(
            cache.lookup(&request_b, now()),
            CacheDecision::Miss
        ));
    }

    #[test]
    fn cookie_replacement_preserves_creation_order_and_generation() {
        let timestamp = now();
        let url = crate::Url::parse("http://example.test/path").expect("URL");
        let mut jar = CookieJar::new(4).expect("cookie jar");
        jar.add(
            Cookie::new("first", "one", "example.test", "/").expect("cookie"),
            timestamp,
        )
        .expect("first cookie");
        jar.add(
            Cookie::new("second", "two", "example.test", "/").expect("cookie"),
            timestamp,
        )
        .expect("second cookie");
        let generation_before_replacement = jar.next_creation;

        jar.add(
            Cookie::new("first", "updated", "example.test", "/").expect("cookie"),
            timestamp,
        )
        .expect("replacement cookie");
        assert_eq!(jar.next_creation, generation_before_replacement);
        assert_eq!(
            jar.request_header(&url, timestamp).expect("cookie header"),
            Some("first=updated; second=two".to_owned())
        );

        // Replacement does not need a fresh creation sequence, so it remains
        // valid even when the next sequence value is already exhausted.
        jar.next_creation = u64::MAX;
        jar.add(
            Cookie::new("first", "final", "example.test", "/").expect("cookie"),
            timestamp,
        )
        .expect("replacement at sequence boundary");
        assert_eq!(jar.next_creation, u64::MAX);
        assert_eq!(
            jar.request_header(&url, timestamp).expect("cookie header"),
            Some("first=final; second=two".to_owned())
        );
    }

    #[test]
    fn dns_validation_uses_url_configuration_error_not_cookie_error() {
        let mut dns = DnsCache::new(2).expect("DNS cache");
        let invalid_host = dns
            .insert("bad host", ["192.0.2.1"], Duration::from_secs(30))
            .expect_err("invalid DNS host");
        assert!(matches!(invalid_host, HttpError::InvalidUrl(_)));
        assert_eq!(invalid_host.stable_code(), "http.invalid-url");

        let invalid_address = dns
            .insert("fixture.test", ["bad address"], Duration::from_secs(30))
            .expect_err("invalid DNS address");
        assert!(matches!(invalid_address, HttpError::InvalidUrl(_)));
        assert_eq!(invalid_address.stable_code(), "http.invalid-url");
        assert_eq!(dns.len(now()), 0);
    }

    #[test]
    fn dns_capacity_rejects_without_evicting_existing_record() {
        let mut dns = DnsCache::new(1).expect("DNS cache");
        dns.insert("first.example", ["192.0.2.1"], Duration::from_secs(30))
            .expect("first record");
        let before = dns.clone();

        let error = dns
            .insert("second.example", ["192.0.2.2"], Duration::from_secs(30))
            .expect_err("capacity must reject");
        assert!(matches!(error, HttpError::ResourceLimit(_)));
        assert_eq!(dns, before);
        assert_eq!(
            dns.lookup("first.example", now()),
            Some(vec!["192.0.2.1".to_owned()])
        );
        assert_eq!(dns.lookup("second.example", now()), None);
    }

    #[test]
    fn static_dns_capacity_failure_is_transactional() {
        let configuration = DnsConfiguration {
            static_hosts: vec![
                StaticDnsHost::new("first.example", "192.0.2.1").expect("first host"),
                StaticDnsHost::new("second.example", "192.0.2.2").expect("second host"),
            ],
            ..DnsConfiguration::default()
        };
        let mut dns = DnsCache::new(1).expect("DNS cache");
        let before = dns.clone();

        let error = configuration
            .apply_to_cache(&mut dns)
            .expect_err("static mapping capacity must reject");
        assert!(matches!(error, HttpError::ResourceLimit(_)));
        assert_eq!(dns, before);
    }
}
