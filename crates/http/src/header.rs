// SPDX-License-Identifier: Apache-2.0
//! Ordered HTTP header names and values.

use crate::HttpError;

/// A validated HTTP field name.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HeaderName(String);

impl HeaderName {
    /// Creates a name after validating RFC token bytes.
    pub fn new(value: impl Into<String>) -> Result<Self, HttpError> {
        let value = value.into();
        if value.len() > 256 || value.is_empty() || !value.bytes().all(is_token_byte) {
            return Err(HttpError::InvalidHeader("invalid field name".to_owned()));
        }
        Ok(Self(value))
    }

    /// Returns the original spelling. Comparisons are case-insensitive.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns whether this name equals another ASCII-insensitively.
    #[must_use]
    pub fn eq_ignore_ascii_case(&self, other: &str) -> bool {
        self.0.eq_ignore_ascii_case(other)
    }
}

impl TryFrom<&str> for HeaderName {
    type Error = HttpError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<String> for HeaderName {
    type Error = HttpError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl std::fmt::Display for HeaderName {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A validated HTTP field value.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct HeaderValue(String);

impl std::fmt::Debug for HeaderValue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HeaderValue")
            .field("bytes", &self.0.len())
            .finish()
    }
}

impl HeaderValue {
    const MAX_BYTES: usize = 64 * 1024;

    /// Creates a value after rejecting controls and line folding.
    pub fn new(value: impl Into<String>) -> Result<Self, HttpError> {
        let value = value.into();
        if value.len() > Self::MAX_BYTES {
            return Err(HttpError::resource_limit("header value bytes"));
        }
        if value.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
            return Err(HttpError::InvalidHeader(
                "header value contains a control byte".to_owned(),
            ));
        }
        Ok(Self(value))
    }

    /// Returns the header value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for HeaderValue {
    type Error = HttpError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<String> for HeaderValue {
    type Error = HttpError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl std::fmt::Display for HeaderValue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// One ordered, duplicate-preserving header field.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct Header {
    name: HeaderName,
    value: HeaderValue,
}

impl std::fmt::Debug for Header {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Header")
            .field("name", &self.name)
            // Header names are useful routing metadata, but arbitrary values
            // may contain credentials or tenant data that a generic allowlist
            // cannot classify safely.  Keep only the length in diagnostics.
            .field("value_bytes", &self.value.as_str().len())
            .finish()
    }
}

impl Header {
    /// Creates a validated field.
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Result<Self, HttpError> {
        Ok(Self {
            name: HeaderName::new(name)?,
            value: HeaderValue::new(value)?,
        })
    }

    /// Returns the field name.
    #[must_use]
    pub fn name(&self) -> &HeaderName {
        &self.name
    }

    /// Returns the field value.
    #[must_use]
    pub fn value(&self) -> &HeaderValue {
        &self.value
    }
}

/// Ordered, duplicate-preserving header collection.
#[derive(Clone, Default, Eq, Hash, PartialEq)]
pub struct Headers {
    fields: Vec<Header>,
}

impl std::fmt::Debug for Headers {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Headers")
            .field("count", &self.fields.len())
            .field("fields", &self.fields.iter().take(32).collect::<Vec<_>>())
            .finish()
    }
}

impl Headers {
    /// Creates an empty collection.
    #[must_use]
    pub const fn new() -> Self {
        Self { fields: Vec::new() }
    }

    /// Creates a collection with a bounded capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            fields: Vec::with_capacity(capacity),
        }
    }

    /// Returns the number of fields, including duplicate names.
    #[must_use]
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Returns a conservative wire-size estimate including field separators.
    #[must_use]
    #[deprecated(note = "use checked_wire_len for typed overflow handling")]
    pub fn wire_len(&self) -> usize {
        self.checked_wire_len().unwrap_or(usize::MAX)
    }

    /// Returns the estimated wire size without silently saturating on
    /// arithmetic overflow.
    pub fn checked_wire_len(&self) -> Result<usize, HttpError> {
        self.fields.iter().try_fold(0usize, |total, field| {
            total
                .checked_add(field.name().as_str().len())
                .and_then(|total| total.checked_add(field.value().as_str().len()))
                .and_then(|total| total.checked_add(4))
                .ok_or_else(|| HttpError::resource_limit("header wire byte accounting"))
        })
    }

    /// Returns whether no fields are present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Adds one field, retaining insertion order and duplicates.
    pub fn append(&mut self, header: Header) {
        self.fields.push(header);
    }

    /// Adds a validated name/value field.
    pub fn insert(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), HttpError> {
        self.append(Header::new(name, value)?);
        Ok(())
    }

    /// Returns all fields in insertion order.
    #[must_use]
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &Header> {
        self.fields.iter()
    }

    /// Returns the first matching field value.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|field| field.name.eq_ignore_ascii_case(name))
            .map(|field| field.value.as_str())
    }

    /// Returns all values for a name in insertion order.
    pub fn values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.fields
            .iter()
            .filter(move |field| field.name.eq_ignore_ascii_case(name))
            .map(|field| field.value.as_str())
    }

    /// Returns whether a field with this name exists.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.fields
            .iter()
            .any(|field| field.name.eq_ignore_ascii_case(name))
    }

    /// Removes all fields with a matching name and returns their count.
    pub fn remove(&mut self, name: &str) -> usize {
        let before = self.fields.len();
        self.fields
            .retain(|field| !field.name.eq_ignore_ascii_case(name));
        before.saturating_sub(self.fields.len())
    }

    /// Returns an owned clone with fields appended from another collection.
    #[must_use]
    pub fn merged(&self, other: &Self) -> Self {
        let mut merged = self.clone();
        merged.fields.extend(other.fields.iter().cloned());
        merged
    }

    /// Removes all entity fields (`Content-*`) from this collection.
    pub(crate) fn remove_entity_headers(&mut self) -> usize {
        let before = self.fields.len();
        self.fields.retain(|field| {
            !field
                .name()
                .as_str()
                .to_ascii_lowercase()
                .starts_with("content-")
        });
        before.saturating_sub(self.fields.len())
    }
}

impl<'a> IntoIterator for &'a Headers {
    type Item = &'a Header;
    type IntoIter = std::slice::Iter<'a, Header>;

    fn into_iter(self) -> Self::IntoIter {
        self.fields.iter()
    }
}

fn is_token_byte(byte: u8) -> bool {
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

/// Returns whether forwarding this field across an origin boundary could
/// disclose credentials, state, or an entity representation for the previous
/// request.  Unknown `X-*` fields containing credential-like names are also
/// treated conservatively because a generic manager cannot inspect their
/// meaning.
pub(crate) fn is_redirect_sensitive_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "www-authenticate"
            | "proxy-authenticate"
    ) || lower.starts_with("content-")
        || [
            "api-key",
            "auth-token",
            "access-token",
            "csrf-token",
            "secret",
            "password",
        ]
        .iter()
        .any(|word| lower.contains(word))
}
