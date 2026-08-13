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
            .find("://")
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
        let authority_start = scheme_end + 3;
        let remainder = &raw[authority_start..];
        if remainder.is_empty() {
            return Err(HttpError::InvalidUrl("URL authority is empty".to_owned()));
        }
        let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
        let authority = remainder[..authority_end].to_owned();
        if authority.len() > MAX_AUTHORITY_BYTES || authority.is_empty() || authority.contains('@')
        {
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

    /// Resolves a redirect location against this URL.
    pub fn join(&self, location: &str) -> Result<Self, HttpError> {
        if location.len() > MAX_URL_BYTES {
            return Err(HttpError::resource_limit("redirect location bytes"));
        }
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
        if has_absolute_url_scheme(location) {
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
        match scheme {
            "http" => Some(80),
            "https" => Some(443),
            _ => None,
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

/// Returns whether `value` starts with a syntactically valid absolute URL
/// scheme.  The scheme must be at the beginning of the reference; otherwise
/// a `://` sequence is ordinary path/query data (for example, `/a://b`).
fn has_absolute_url_scheme(value: &str) -> bool {
    value
        .find("://")
        .is_some_and(|scheme_end| scheme_end > 0 && is_scheme(&value[..scheme_end]))
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
