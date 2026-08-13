// SPDX-License-Identifier: Apache-2.0
//! Small, dependency-free URL representation for request policy.

use crate::HttpError;

/// Maximum bytes accepted for an absolute request URL or redirect location.
pub const MAX_URL_BYTES: usize = 8 * 1024;
/// Maximum bytes accepted for a URL authority.
pub const MAX_AUTHORITY_BYTES: usize = 2 * 1024;
/// Maximum bytes accepted for an origin-form path and query.
pub const MAX_PATH_QUERY_BYTES: usize = 6 * 1024;
/// Maximum bytes accepted for a URL fragment.
pub const MAX_FRAGMENT_BYTES: usize = 2 * 1024;

/// A parsed absolute HTTP(S) URL.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Url {
    raw: String,
    scheme: String,
    authority: String,
    host: String,
    port: u16,
    path_and_query: String,
    fragment: Option<String>,
}

impl std::fmt::Debug for Url {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // URLs commonly contain credentials, tokens, and arbitrarily large
        // query strings.  Keep Debug useful for routing without logging the
        // raw URL or fragment.
        formatter
            .debug_struct("Url")
            .field("scheme", &self.scheme)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("path_query_bytes", &self.path_and_query.len())
            .field(
                "fragment_bytes",
                &self.fragment.as_ref().map_or(0, String::len),
            )
            .finish()
    }
}

impl Url {
    /// Parses an absolute `http` or `https` URL.
    pub fn parse(value: impl Into<String>) -> Result<Self, HttpError> {
        let raw = value.into();
        if raw.len() > MAX_URL_BYTES {
            return Err(HttpError::resource_limit("URL bytes"));
        }
        if raw.bytes().any(is_forbidden_url_byte) {
            return Err(HttpError::InvalidUrl(
                "URL contains a control or whitespace byte".to_owned(),
            ));
        }
        if raw.bytes().any(|byte| byte >= 0x80) {
            return Err(HttpError::InvalidUrl(
                "URL must use ASCII bytes; percent-encode non-ASCII data".to_owned(),
            ));
        }
        let scheme_end = raw
            .find(':')
            .ok_or_else(|| HttpError::InvalidUrl("absolute URL scheme is missing".to_owned()))?;
        if scheme_end == 0 || scheme_end > 32 || !is_scheme(&raw[..scheme_end]) {
            return Err(HttpError::InvalidUrl("invalid URL scheme".to_owned()));
        }
        let scheme = raw[..scheme_end].to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err(HttpError::InvalidUrl(format!(
                "unsupported URL scheme {scheme:?}"
            )));
        }
        if raw.get(scheme_end + 1..scheme_end + 3) != Some("//") {
            return Err(HttpError::InvalidUrl(
                "HTTP URL authority delimiter is missing".to_owned(),
            ));
        }
        let authority_start = scheme_end + 3;
        let remainder = &raw[authority_start..];
        if remainder.is_empty() {
            return Err(HttpError::InvalidUrl("URL authority is empty".to_owned()));
        }
        let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
        let authority = remainder[..authority_end].to_owned();
        if authority.len() > MAX_AUTHORITY_BYTES {
            return Err(HttpError::resource_limit("URL authority bytes"));
        }
        if authority.is_empty() || authority.contains('@') {
            return Err(HttpError::InvalidUrl(
                "userinfo and empty authority are not supported".to_owned(),
            ));
        }
        validate_percent_encoding(&authority, "URL authority")?;
        let (host, port) = parse_authority(&authority, scheme == "https")?;
        let suffix = &remainder[authority_end..];
        let fragment_end = suffix.find('#').unwrap_or(suffix.len());
        let mut path_and_query = suffix[..fragment_end].to_owned();
        validate_percent_encoding(&path_and_query, "URL path/query")?;
        if path_and_query.len() > MAX_PATH_QUERY_BYTES {
            return Err(HttpError::resource_limit("URL path/query bytes"));
        }
        let fragment = suffix
            .get(fragment_end..)
            .and_then(|value| value.strip_prefix('#'))
            .map(str::to_owned);
        if let Some(fragment) = &fragment {
            validate_percent_encoding(fragment, "URL fragment")?;
        }
        if fragment
            .as_ref()
            .is_some_and(|value| value.len() > MAX_FRAGMENT_BYTES)
        {
            return Err(HttpError::resource_limit("URL fragment bytes"));
        }
        if path_and_query.is_empty() {
            path_and_query.push('/');
        } else if path_and_query.starts_with('?') {
            path_and_query.insert(0, '/');
        }
        if path_and_query.len() > MAX_PATH_QUERY_BYTES {
            return Err(HttpError::resource_limit("URL path/query bytes"));
        }
        Ok(Self {
            raw,
            scheme,
            authority,
            host,
            port,
            path_and_query,
            fragment,
        })
    }

    /// Returns the original URL spelling, including any fragment.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Returns the lowercase scheme.
    #[must_use]
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// Returns the authority without user info.
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// Returns the normalized host, without brackets around IPv6 literals.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Returns the explicit or scheme-default port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Returns the origin-form path and query.
    #[must_use]
    pub fn path_and_query(&self) -> &str {
        &self.path_and_query
    }

    /// Returns the absolute URL form suitable for a wire request target or
    /// an adapter's connection policy.  Fragments are intentionally absent:
    /// they are client-side metadata and are never sent to an HTTP peer.
    #[must_use]
    pub fn wire_form(&self) -> String {
        format!(
            "{}://{}{}",
            self.scheme, self.authority, self.path_and_query
        )
    }

    /// Returns the origin-form request target without a fragment.
    #[must_use]
    pub fn wire_target(&self) -> &str {
        &self.path_and_query
    }

    /// Returns the origin-form path without its query.
    #[must_use]
    pub fn path(&self) -> &str {
        self.path_and_query.split('?').next().unwrap_or("/")
    }

    /// Returns the query including its leading `?`, when present.
    #[must_use]
    pub fn query(&self) -> Option<&str> {
        self.path_and_query
            .find('?')
            .map(|index| &self.path_and_query[index..])
    }

    /// Returns the fragment, which is retained for redirect resolution but is
    /// never part of the origin-form request target.
    #[must_use]
    pub fn fragment(&self) -> Option<&str> {
        self.fragment.as_deref()
    }

    /// Returns a stable cache/routing key that excludes the URL fragment.
    #[must_use]
    pub fn cache_key(&self) -> String {
        let authority = if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        };
        format!("{}://{}{}", self.scheme, authority, self.path_and_query)
    }

    /// Returns `scheme://authority` without path/query.
    #[must_use]
    pub fn origin(&self) -> String {
        format!("{}://{}", self.scheme, self.authority)
    }

    /// Returns the URL's origin tuple.
    #[must_use]
    pub fn origin_key(&self) -> Origin {
        Origin {
            scheme: self.scheme.clone(),
            host: self.host.clone(),
            port: self.port,
        }
    }

    /// Compares a host-field authority with this URL's normalized host and
    /// effective port.
    ///
    /// Host fields are authority-only values: user information, paths,
    /// fragments, and an unbracketed IPv6 literal are rejected by the same
    /// bounded parser used for URL authorities.  No DNS lookup or IDNA
    /// conversion occurs here; callers must provide an ASCII/punycode host
    /// or receive an explicit mismatch from the request boundary.
    pub(crate) fn authority_matches(&self, candidate: &str) -> Result<bool, HttpError> {
        if candidate.is_empty() || candidate.len() > MAX_AUTHORITY_BYTES || candidate.contains('@')
        {
            return Ok(false);
        }
        let (host, port) = parse_authority(candidate, self.scheme == "https")?;
        Ok(hosts_equivalent(&host, &self.host) && port == self.port)
    }

    /// Resolves a redirect location against this URL.
    pub fn join(&self, location: &str) -> Result<Self, HttpError> {
        // JMeter replaces literal spaces in a Location header with `%20`
        // before resolving it. Encoding can expand the input, so enforce the
        // URL bound after this transformation too.
        let location = encode_redirect_spaces(location)?;
        let location = location.as_str();
        if location.bytes().any(is_forbidden_url_byte) {
            return Err(HttpError::InvalidRedirect(
                "location contains a control byte".to_owned(),
            ));
        }
        if location.bytes().any(|byte| byte >= 0x80) {
            return Err(HttpError::InvalidRedirect(
                "location must use ASCII bytes; percent-encode non-ASCII data".to_owned(),
            ));
        }
        validate_percent_encoding(location, "redirect location").map_err(|error| match error {
            HttpError::InvalidUrl(message) => HttpError::InvalidRedirect(message),
            other => other,
        })?;
        if location.is_empty() {
            return Ok(self.clone());
        }
        if absolute_scheme_end(location).is_some() {
            return Self::parse(location.to_owned());
        }
        if let Some(network_path) = location.strip_prefix("//") {
            return Self::parse(format!("{}://{network_path}", self.scheme));
        }
        let base = self.origin();
        if location.starts_with('/') {
            return Self::parse(format!("{base}{}", normalize_path_reference(location)));
        }
        if location.starts_with('?') {
            return Self::parse(format!("{base}{}{location}", self.path()));
        }
        if location.starts_with('#') {
            return Self::parse(format!("{}{}{}", base, self.path_and_query, location));
        }
        let directory =
            self.path().rsplit_once('/').map_or(
                "/",
                |(prefix, _)| {
                    if prefix.is_empty() { "/" } else { prefix }
                },
            );
        let combined = if directory.ends_with('/') {
            format!("{directory}{location}")
        } else {
            format!("{directory}/{location}")
        };
        let (path, suffix) = split_path_suffix(&combined);
        Self::parse(format!(
            "{base}{}{}",
            normalize_path_reference(path),
            suffix
        ))
    }
}

impl std::fmt::Display for Url {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.raw)
    }
}

impl From<Url> for String {
    fn from(value: Url) -> Self {
        value.raw
    }
}

/// Origin tuple used by cookie, redirect, and proxy policy.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Origin {
    /// Lowercase scheme.
    pub scheme: String,
    /// Lowercase host.
    pub host: String,
    /// Effective port.
    pub port: u16,
}

impl Origin {
    /// Returns the default port for a scheme.
    #[must_use]
    pub fn default_port(scheme: &str) -> Option<u16> {
        if scheme.eq_ignore_ascii_case("http") {
            Some(80)
        } else if scheme.eq_ignore_ascii_case("https") {
            Some(443)
        } else {
            None
        }
    }
}

fn parse_authority(authority: &str, https: bool) -> Result<(String, u16), HttpError> {
    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        let close = stripped
            .find(']')
            .ok_or_else(|| HttpError::InvalidUrl("unterminated IPv6 authority".to_owned()))?;
        let host = stripped[..close].to_ascii_lowercase();
        if host.is_empty()
            || !host.contains(':')
            || !valid_ipv6_literal(&host)
            || stripped[close + 1..].contains(']')
        {
            return Err(HttpError::InvalidUrl("invalid IPv6 host".to_owned()));
        }
        let after = &stripped[close + 1..];
        let port = if after.is_empty() {
            if https { 443 } else { 80 }
        } else {
            let value = after
                .strip_prefix(':')
                .ok_or_else(|| HttpError::InvalidUrl("invalid IPv6 port".to_owned()))?;
            parse_port(value)?
        };
        (host, port)
    } else {
        let split = authority.rfind(':');
        let (host, port) = match split {
            Some(index) if authority[index + 1..].contains(':') => {
                return Err(HttpError::InvalidUrl(
                    "IPv6 hosts must use brackets".to_owned(),
                ));
            }
            Some(index) => {
                let port = parse_port(&authority[index + 1..])?;
                (&authority[..index], port)
            }
            None => (authority, if https { 443 } else { 80 }),
        };
        if !valid_dns_host(host) {
            return Err(HttpError::InvalidUrl("invalid host".to_owned()));
        }
        (host.to_ascii_lowercase(), port)
    };
    Ok((host, port))
}

fn parse_port(value: &str) -> Result<u16, HttpError> {
    if value.is_empty() || value.len() > 5 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(HttpError::InvalidUrl("empty port".to_owned()));
    }
    let port = value
        .parse::<u16>()
        .map_err(|_| HttpError::InvalidUrl("invalid URL port".to_owned()))?;
    if port == 0 {
        return Err(HttpError::InvalidUrl(
            "URL port must be non-zero".to_owned(),
        ));
    }
    Ok(port)
}

fn is_scheme(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}

fn valid_dns_host(value: &str) -> bool {
    if value.is_empty() || value.len() > 255 {
        return false;
    }
    // A fully-qualified DNS name may carry one terminal root label.  Keep
    // the empty-label allowance narrow so a leading dot, repeated dots, or
    // an all-dot host remains invalid.
    let value = value.strip_suffix('.').unwrap_or(value);
    if value.is_empty() {
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

fn hosts_equivalent(left: &str, right: &str) -> bool {
    let left = if left.contains(':') {
        left
    } else {
        left.strip_suffix('.').unwrap_or(left)
    };
    let right = if right.contains(':') {
        right
    } else {
        right.strip_suffix('.').unwrap_or(right)
    };
    left.eq_ignore_ascii_case(right)
}

fn valid_ipv6_literal(value: &str) -> bool {
    // RFC 6874 zone identifiers in an authority are encoded as `%25`.
    // Keep the zone opaque to this pure parser but require a bounded,
    // token-like spelling after the encoded marker.
    let address = if let Some((address, zone)) = value.split_once('%') {
        let Some(zone) = zone.strip_prefix("25") else {
            return false;
        };
        if zone.is_empty()
            || zone.len() > 64
            || !zone
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return false;
        }
        address
    } else {
        value
    };
    address.parse::<std::net::Ipv6Addr>().is_ok()
}

fn validate_percent_encoding(value: &str, component: &str) -> Result<(), HttpError> {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return Err(HttpError::InvalidUrl(format!(
                    "{component} contains an invalid percent escape"
                )));
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    Ok(())
}

fn is_forbidden_url_byte(byte: u8) -> bool {
    byte <= 0x20 || byte == 0x7f
}

/// Reproduces JMeter's redirect preprocessing for literal spaces while
/// retaining a bound on both the untrusted header value and the encoded
/// result.  A redirect location is not allowed to grow without limit merely
/// because it contains spaces.
fn encode_redirect_spaces(value: &str) -> Result<String, HttpError> {
    if value.len() > MAX_URL_BYTES {
        return Err(HttpError::resource_limit("redirect location bytes"));
    }
    // JMeter's default redirect preprocessing trims Java's ASCII whitespace
    // range before replacing interior spaces with `%20`. Keep this explicit
    // rather than Rust's Unicode-aware `trim`, which would alter non-ASCII
    // input before URL validation can reject it.
    let value = value.trim_matches(|character: char| character <= '\u{20}');
    let spaces = value.bytes().filter(|byte| *byte == b' ').count();
    let encoded_len = value
        .len()
        .checked_add(
            spaces
                .checked_mul(2)
                .ok_or_else(|| HttpError::resource_limit("redirect location bytes"))?,
        )
        .ok_or_else(|| HttpError::resource_limit("redirect location bytes"))?;
    if encoded_len > MAX_URL_BYTES {
        return Err(HttpError::resource_limit("redirect location bytes"));
    }
    if spaces == 0 {
        return Ok(value.to_owned());
    }
    let mut encoded = String::with_capacity(encoded_len);
    for character in value.chars() {
        if character == ' ' {
            encoded.push_str("%20");
        } else {
            encoded.push(character);
        }
    }
    Ok(encoded)
}

/// Returns the scheme delimiter position when `value` starts with an absolute
/// URI scheme. A colon after a path/query delimiter is ordinary data (for
/// example, `/a://b`), while `ftp:...` must not be reinterpreted as a path
/// relative to the current HTTP origin.
fn absolute_scheme_end(value: &str) -> Option<usize> {
    let colon = value.find(':')?;
    let reference_end = value.find(['/', '?', '#']).unwrap_or(value.len());
    (colon < reference_end && is_scheme(&value[..colon])).then_some(colon)
}

fn split_path_suffix(value: &str) -> (&str, &str) {
    let index = value.find(['?', '#']).unwrap_or(value.len());
    (&value[..index], &value[index..])
}

fn normalize_path_reference(value: &str) -> String {
    let (path, suffix) = split_path_suffix(value);
    let absolute = path.starts_with('/');
    let mut segments: Vec<&str> = Vec::new();
    for (index, segment) in path.split('/').enumerate() {
        // The first empty segment is the marker for an absolute path.  Empty
        // segments elsewhere are significant (`/a//b` is not `/a/b`) and
        // must survive dot-segment normalization.
        if absolute && index == 0 {
            continue;
        }
        match segment {
            "." => {}
            ".." => {
                if segments.last().is_some_and(|segment| !segment.is_empty()) {
                    segments.pop();
                }
            }
            value => segments.push(value),
        }
    }
    let mut normalized = String::new();
    if absolute {
        normalized.push('/');
    }
    normalized.push_str(&segments.join("/"));
    if normalized.is_empty() {
        normalized.push('/');
    }
    normalized.push_str(suffix);
    normalized
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "tests use expect at assertion boundaries for fixed URL fixtures"
    )]

    use super::*;

    #[test]
    fn query_includes_leading_question_mark() {
        let with_value = Url::parse("http://example.test/path?mode=fast").expect("URL");
        assert_eq!(with_value.query(), Some("?mode=fast"));

        let empty = Url::parse("http://example.test/path?").expect("URL");
        assert_eq!(empty.query(), Some("?"));

        let without_query = Url::parse("http://example.test/path").expect("URL");
        assert_eq!(without_query.query(), None);
    }

    #[test]
    fn parse_preserves_presence_and_separates_wire_components() {
        let url = Url::parse("HTTPS://Example.test:443/a%20b?mode=fast#section").expect("URL");

        assert_eq!(
            url.as_str(),
            "HTTPS://Example.test:443/a%20b?mode=fast#section"
        );
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.authority(), "Example.test:443");
        assert_eq!(url.host(), "example.test");
        assert_eq!(url.port(), 443);
        assert_eq!(url.path(), "/a%20b");
        assert_eq!(url.query(), Some("?mode=fast"));
        assert_eq!(url.fragment(), Some("section"));
        assert_eq!(url.wire_target(), "/a%20b?mode=fast");
        assert_eq!(url.wire_form(), "https://Example.test:443/a%20b?mode=fast");
        assert_eq!(url.cache_key(), "https://example.test:443/a%20b?mode=fast");
    }

    #[test]
    fn parse_distinguishes_root_path_from_query_and_fragment_presence() {
        let root = Url::parse("http://example.test").expect("URL");
        assert_eq!(root.path_and_query(), "/");
        assert_eq!(root.query(), None);
        assert_eq!(root.fragment(), None);
        assert_eq!(root.wire_target(), "/");

        let query = Url::parse("http://example.test?").expect("URL");
        assert_eq!(query.path_and_query(), "/?");
        assert_eq!(query.query(), Some("?"));

        let fragment = Url::parse("http://example.test#").expect("URL");
        assert_eq!(fragment.path_and_query(), "/");
        assert_eq!(fragment.fragment(), Some(""));
        assert_eq!(fragment.wire_target(), "/");
    }

    #[test]
    fn parse_accepts_default_ports_and_bracketed_ipv6_only() {
        assert_eq!(Origin::default_port("HTTP"), Some(80));
        assert_eq!(Origin::default_port("Https"), Some(443));
        assert_eq!(Origin::default_port("ftp"), None);

        let http = Url::parse("http://example.test/").expect("URL");
        assert_eq!(http.port(), 80);

        let https = Url::parse("https://example.test/").expect("URL");
        assert_eq!(https.port(), 443);

        let ipv6 = Url::parse("http://[2001:DB8::1]:8080/resource").expect("URL");
        assert_eq!(ipv6.host(), "2001:db8::1");
        assert_eq!(ipv6.port(), 8080);
        assert_eq!(ipv6.cache_key(), "http://[2001:db8::1]:8080/resource");

        let scoped = Url::parse("http://[fe80::1%25eth0]/resource").expect("URL");
        assert_eq!(scoped.host(), "fe80::1%25eth0");
        assert_eq!(scoped.port(), 80);

        let fqdn = Url::parse("http://example.test./resource").expect("fully-qualified host");
        assert_eq!(fqdn.host(), "example.test.");
        assert_eq!(fqdn.port(), 80);

        // IDNA conversion belongs to an explicit resolver/provider boundary;
        // already-punycode ASCII labels are safe for this pure parser.
        let punycode = Url::parse("https://xn--caf-dma.example/").expect("punycode host");
        assert_eq!(punycode.host(), "xn--caf-dma.example");
    }

    #[test]
    fn parse_rejects_malformed_authority_and_component_escapes() {
        for value in [
            "http://",
            "http://example.test:",
            "http://example.test:0/",
            "http://example.test:65536/",
            "http://user@example.test/",
            "http://2001:db8::1/",
            "http://[2001:db8::1/",
            "http://example.test/%ZZ",
            "http://example.test/#%ZZ",
        ] {
            assert!(
                matches!(Url::parse(value), Err(HttpError::InvalidUrl(_))),
                "expected invalid URL: {value}"
            );
        }
    }

    #[test]
    fn parse_enforces_each_url_component_bound() {
        let too_long = format!("http://example.test/{}", "x".repeat(MAX_URL_BYTES));
        assert!(matches!(
            Url::parse(too_long),
            Err(HttpError::ResourceLimit(message)) if message == "URL bytes"
        ));

        let too_long_authority = format!("http://{}/", "a".repeat(MAX_AUTHORITY_BYTES + 1));
        assert!(matches!(
            Url::parse(too_long_authority),
            Err(HttpError::ResourceLimit(message)) if message == "URL authority bytes"
        ));

        let too_long_path = format!("http://example.test/{}", "x".repeat(MAX_PATH_QUERY_BYTES));
        assert!(matches!(
            Url::parse(too_long_path),
            Err(HttpError::ResourceLimit(message)) if message == "URL path/query bytes"
        ));

        let too_long_fragment = format!(
            "http://example.test/#{}",
            "x".repeat(MAX_FRAGMENT_BYTES + 1)
        );
        assert!(matches!(
            Url::parse(too_long_fragment),
            Err(HttpError::ResourceLimit(message)) if message == "URL fragment bytes"
        ));
    }

    #[test]
    fn join_resolves_absolute_path_containing_scheme_delimiter() {
        let base = Url::parse("http://example.test/base/item").expect("URL");
        let joined = base.join("/assets/a://b?x=1").expect("redirect URL");

        assert_eq!(joined.as_str(), "http://example.test/assets/a://b?x=1");
    }

    #[test]
    fn join_keeps_true_absolute_urls_and_rejects_unsupported_schemes() {
        let base = Url::parse("http://example.test/base/item").expect("URL");

        assert_eq!(
            base.join("https://other.test/next")
                .expect("absolute redirect")
                .as_str(),
            "https://other.test/next"
        );
        assert!(matches!(
            base.join("ftp://other.test/next"),
            Err(HttpError::InvalidUrl(message)) if message.contains("unsupported URL scheme")
        ));
        assert!(matches!(
            base.join("ftp:other.test/next"),
            Err(HttpError::InvalidUrl(message)) if message.contains("unsupported URL scheme")
        ));
        assert!(matches!(
            base.join("http:/other.test/next"),
            Err(HttpError::InvalidUrl(message))
                if message.contains("authority delimiter is missing")
        ));
    }

    #[test]
    fn join_resolves_reference_forms_and_replaces_only_their_components() {
        let base = Url::parse("http://example.test/a/b/item?old=1#old").expect("URL");
        let cases = [
            ("", "http://example.test/a/b/item?old=1#old"),
            ("child", "http://example.test/a/b/child"),
            ("../sibling", "http://example.test/a/sibling"),
            ("/root/../asset", "http://example.test/asset"),
            ("?new=2", "http://example.test/a/b/item?new=2"),
            ("#new", "http://example.test/a/b/item?old=1#new"),
            ("child?new=2#new", "http://example.test/a/b/child?new=2#new"),
            ("//other.test/next", "http://other.test/next"),
            ("https://other.test/next", "https://other.test/next"),
        ];
        for (location, expected) in cases {
            assert_eq!(
                base.join(location).expect("redirect URL").as_str(),
                expected
            );
        }
    }

    #[test]
    fn join_applies_jmeter_space_encoding_and_rejects_bad_locations() {
        let base = Url::parse("http://example.test/a/b").expect("URL");
        assert_eq!(
            base.join("child page?title=hello world#part two")
                .expect("redirect URL")
                .as_str(),
            "http://example.test/a/child%20page?title=hello%20world#part%20two"
        );
        // JMeter trims ASCII whitespace before escaping spaces.
        assert_eq!(
            base.join("  /next  ").expect("redirect URL").as_str(),
            "http://example.test/next"
        );

        for location in ["/bad\tpath", "/bad%2", "/caf\u{00e9}"] {
            assert!(
                matches!(base.join(location), Err(HttpError::InvalidRedirect(_))),
                "expected invalid redirect: {location:?}"
            );
        }

        let oversized = format!("/{}x", " ".repeat(MAX_URL_BYTES / 3 + 2));
        assert!(matches!(
            base.join(&oversized),
            Err(HttpError::ResourceLimit(message)) if message == "redirect location bytes"
        ));
    }

    #[test]
    fn join_rejects_redirect_locations_over_url_limit_before_resolution() {
        let base = Url::parse("http://example.test/base/item").expect("URL");
        let location = format!("/{}://tail", "x".repeat(MAX_URL_BYTES));

        assert!(matches!(
            base.join(&location),
            Err(HttpError::ResourceLimit(message)) if message == "redirect location bytes"
        ));
    }
}
