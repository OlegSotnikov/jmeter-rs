// SPDX-License-Identifier: Apache-2.0
//! Ordered HTTP header names and values.

use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

use crate::HttpError;

/// Maximum field-name size accepted by the pure HTTP core.
pub const MAX_HEADER_NAME_BYTES: usize = 256;

/// Maximum field-value size accepted by the pure HTTP core.
pub const MAX_HEADER_VALUE_BYTES: usize = 64 * 1024;

/// Hard maximum number of fields in one bounded header collection.
pub const MAX_HEADER_FIELDS: usize = 1_024;

/// Hard maximum aggregate wire bytes in one bounded header collection.
pub const MAX_HEADER_BYTES: usize = 1024 * 1024;

/// A validated HTTP field name.
#[derive(Clone, Debug)]
pub struct HeaderName(String);

impl PartialEq for HeaderName {
    fn eq(&self, other: &Self) -> bool {
        self.eq_ignore_ascii_case(other.as_str())
    }
}

impl Eq for HeaderName {}

impl Hash for HeaderName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for byte in self.0.bytes() {
            state.write_u8(byte.to_ascii_lowercase());
        }
        state.write_u8(0);
    }
}

impl Ord for HeaderName {
    fn cmp(&self, other: &Self) -> Ordering {
        ascii_case_cmp(self.as_str(), other.as_str())
    }
}

impl PartialOrd for HeaderName {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl HeaderName {
    /// Creates a name after validating RFC token bytes.
    pub fn new(value: impl Into<String>) -> Result<Self, HttpError> {
        let value = value.into();
        if value.len() > MAX_HEADER_NAME_BYTES
            || value.is_empty()
            || !value.bytes().all(is_token_byte)
        {
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
    /// Creates a value after rejecting controls and line folding.
    pub fn new(value: impl Into<String>) -> Result<Self, HttpError> {
        let value = value.into();
        if value.len() > MAX_HEADER_VALUE_BYTES {
            return Err(HttpError::resource_limit("header value bytes"));
        }
        if value
            .bytes()
            .any(|byte| (byte < 0x20 && byte != b'\t') || byte == 0x7f)
        {
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
            fields: Vec::with_capacity(capacity.min(MAX_HEADER_FIELDS)),
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

    /// Validates this collection against the hard core bounds.
    pub fn validate(&self) -> Result<(), HttpError> {
        self.validate_with_limits(MAX_HEADER_FIELDS, MAX_HEADER_BYTES)
    }

    /// Validates this collection against caller-selected lower bounds.
    ///
    /// The caller may lower either limit, but this method never permits a
    /// value above the core hard maximum. This lets request/response policy
    /// apply a stricter per-message limit without weakening the hard bound.
    pub fn validate_with_limits(
        &self,
        maximum_fields: usize,
        maximum_bytes: usize,
    ) -> Result<(), HttpError> {
        if maximum_fields == 0 || maximum_bytes == 0 {
            return Err(HttpError::resource_limit("header limits must be non-zero"));
        }
        let maximum_fields = maximum_fields.min(MAX_HEADER_FIELDS);
        let maximum_bytes = maximum_bytes.min(MAX_HEADER_BYTES);
        if self.fields.len() > maximum_fields {
            return Err(HttpError::resource_limit("header field count"));
        }
        if self.checked_wire_len()? > maximum_bytes {
            return Err(HttpError::resource_limit("header aggregate bytes"));
        }
        Ok(())
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

    /// Appends a field while enforcing the collection's hard bounds.
    ///
    /// [`Self::append`] remains available for adapters that have already
    /// validated a wire collection and need an infallible ordered operation.
    /// Input-facing code should use this method so oversized collections are
    /// reported rather than silently accepted.
    pub fn try_append(&mut self, header: Header) -> Result<(), HttpError> {
        if self.fields.len() >= MAX_HEADER_FIELDS {
            return Err(HttpError::resource_limit("header field count"));
        }
        let field_bytes = header_wire_len(&header)?;
        let current = self.checked_wire_len()?;
        let total = current
            .checked_add(field_bytes)
            .ok_or_else(|| HttpError::resource_limit("header aggregate bytes"))?;
        if total > MAX_HEADER_BYTES {
            return Err(HttpError::resource_limit("header aggregate bytes"));
        }
        self.fields.push(header);
        Ok(())
    }

    /// Adds a validated name/value field.
    pub fn insert(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), HttpError> {
        self.try_append(Header::new(name, value)?)
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

    /// Returns an ordered append-merge after validating both input and output
    /// bounds. Duplicate names are intentionally retained; replacement of a
    /// manager field is a separate scope operation.
    pub fn try_merged(&self, other: &Self) -> Result<Self, HttpError> {
        self.validate()?;
        other.validate()?;
        let mut merged = Self::with_capacity(self.len().saturating_add(other.len()));
        for field in self.iter().chain(other.iter()) {
            merged.try_append(field.clone())?;
        }
        Ok(merged)
    }

    /// Removes all entity fields (`Content-*`) from this collection.
    pub(crate) fn remove_entity_headers(&mut self) -> usize {
        let before = self.fields.len();
        self.fields
            .retain(|field| !starts_with_ignore_ascii_case(field.name().as_str(), "content-"));
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

fn header_wire_len(header: &Header) -> Result<usize, HttpError> {
    header
        .name()
        .as_str()
        .len()
        .checked_add(header.value().as_str().len())
        .and_then(|total| total.checked_add(4))
        .ok_or_else(|| HttpError::resource_limit("header wire byte accounting"))
}

fn ascii_case_cmp(left: &str, right: &str) -> Ordering {
    let mut left_bytes = left.bytes();
    let mut right_bytes = right.bytes();
    loop {
        match (left_bytes.next(), right_bytes.next()) {
            (Some(left), Some(right)) => {
                match left.to_ascii_lowercase().cmp(&right.to_ascii_lowercase()) {
                    Ordering::Equal => {}
                    ordering => return ordering,
                }
            }
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
        }
    }
}

fn starts_with_ignore_ascii_case(value: &str, prefix: &str) -> bool {
    value.len() >= prefix.len() && value[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// Returns whether forwarding this field across an origin boundary could
/// disclose credentials, state, or an entity representation for the previous
/// request.  Unknown `X-*` fields containing credential-like names are also
/// treated conservatively because a generic manager cannot inspect their
/// meaning.
pub(crate) fn is_redirect_sensitive_name(name: &str) -> bool {
    matches_ignore_ascii_case(
        name,
        [
            "authorization",
            "proxy-authorization",
            "cookie",
            "set-cookie",
            "www-authenticate",
            "proxy-authenticate",
        ],
    ) || starts_with_ignore_ascii_case(name, "content-")
        || [
            "api-key",
            "auth-token",
            "access-token",
            "csrf-token",
            "credential",
            "secret",
            "password",
            "session",
            "token",
        ]
        .iter()
        .any(|word| contains_ignore_ascii_case(name, word))
}

fn matches_ignore_ascii_case<const N: usize>(name: &str, values: [&str; N]) -> bool {
    values.iter().any(|value| name.eq_ignore_ascii_case(value))
}

fn contains_ignore_ascii_case(value: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    value
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "header tests use expect at fixed in-process assertion boundaries"
    )]

    use std::collections::HashSet;

    use super::{
        Header, HeaderName, HeaderValue, Headers, MAX_HEADER_BYTES, MAX_HEADER_FIELDS,
        MAX_HEADER_NAME_BYTES, MAX_HEADER_VALUE_BYTES, is_redirect_sensitive_name,
    };

    #[test]
    fn names_compare_and_hash_case_insensitively_but_keep_wire_spelling() {
        let original = HeaderName::new("X-Trace-ID").expect("name");
        let folded = HeaderName::new("x-trace-id").expect("name");
        assert_eq!(original, folded);
        assert_eq!(original.cmp(&folded), std::cmp::Ordering::Equal);
        assert_eq!(original.as_str(), "X-Trace-ID");
        assert_eq!(folded.as_str(), "x-trace-id");

        let mut names = HashSet::new();
        assert!(names.insert(original));
        assert!(!names.insert(folded));
    }

    #[test]
    fn duplicate_lookup_and_remove_are_ordered_and_case_insensitive() {
        let mut headers = Headers::new();
        headers.insert("X-Test", "one").expect("header");
        headers.insert("Other", "kept").expect("header");
        headers.insert("x-test", "two").expect("header");
        headers.insert("X-TEST", "three").expect("header");

        assert_eq!(headers.get("x-TeSt"), Some("one"));
        assert_eq!(
            headers.values("X-TEST").collect::<Vec<_>>(),
            vec!["one", "two", "three"]
        );
        assert_eq!(headers.remove("x-test"), 3);
        let remaining = headers.iter().collect::<Vec<_>>();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].name().as_str(), "Other");
        assert_eq!(remaining[0].value().as_str(), "kept");
    }

    #[test]
    fn checked_merge_preserves_order_and_duplicate_wire_names() {
        let mut left = Headers::new();
        left.insert("X-Base", "outer").expect("header");
        left.insert("X-Duplicate", "one").expect("header");
        let mut right = Headers::new();
        right.insert("x-base", "inner").expect("header");
        right.insert("X-Duplicate", "two").expect("header");

        let merged = left.try_merged(&right).expect("bounded merge");
        let fields = merged.iter().collect::<Vec<_>>();
        assert_eq!(
            fields
                .iter()
                .map(|field| (field.name().as_str(), field.value().as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("X-Base", "outer"),
                ("X-Duplicate", "one"),
                ("x-base", "inner"),
                ("X-Duplicate", "two"),
            ]
        );
    }

    #[test]
    fn header_values_allow_htab_but_reject_line_folding_and_controls() {
        assert!(HeaderValue::new("a\tb").is_ok());
        for value in ["a\rb", "a\nb", "a\0b", "a\u{7f}b"] {
            assert!(HeaderValue::new(value).is_err(), "{value:?}");
        }
    }

    #[test]
    fn field_and_collection_bounds_are_checked_before_append() {
        assert!(HeaderName::new("x".repeat(MAX_HEADER_NAME_BYTES)).is_ok());
        assert!(HeaderName::new("x".repeat(MAX_HEADER_NAME_BYTES + 1)).is_err());
        assert!(HeaderValue::new("x".repeat(MAX_HEADER_VALUE_BYTES)).is_ok());
        assert!(HeaderValue::new("x".repeat(MAX_HEADER_VALUE_BYTES + 1)).is_err());

        let mut by_count = Headers::new();
        for index in 0..MAX_HEADER_FIELDS {
            by_count
                .insert(format!("X-{index}"), "v")
                .expect("field within hard bound");
        }
        assert!(by_count.insert("X-Overflow", "v").is_err());
        assert_eq!(by_count.len(), MAX_HEADER_FIELDS);

        let mut by_bytes = Headers::new();
        let large = "x".repeat(MAX_HEADER_VALUE_BYTES);
        let mut accepted = 0;
        while by_bytes
            .insert(format!("X-{accepted}"), large.clone())
            .is_ok()
        {
            accepted += 1;
        }
        assert!(accepted > 0);
        let wire_bytes = by_bytes.checked_wire_len().expect("wire accounting");
        assert!(wire_bytes <= MAX_HEADER_BYTES);
        assert!(by_bytes.validate().is_ok());
        assert!(
            by_bytes
                .validate_with_limits(MAX_HEADER_FIELDS, wire_bytes - 1)
                .is_err()
        );
    }

    #[test]
    fn sensitive_name_filter_is_ascii_case_insensitive_and_conservative() {
        for name in [
            "AUTHORIZATION",
            "Proxy-AUTHORIZATION",
            "cOoKiE",
            "Content-Type",
            "X-Session-Token",
            "X-API-KEY",
        ] {
            assert!(is_redirect_sensitive_name(name), "{name}");
        }
        for name in ["Accept", "X-Trace", "User-Agent"] {
            assert!(!is_redirect_sensitive_name(name), "{name}");
        }
    }

    #[test]
    fn debug_output_redacts_header_values_and_keeps_only_bounded_metadata() {
        let header = Header::new("Authorization", "Bearer custom-secret").expect("header");
        let value = HeaderValue::new("Bearer custom-secret").expect("value");
        let headers = Headers::with_capacity(8);
        let header_debug = format!("{header:?}");
        let value_debug = format!("{value:?}");
        let headers_debug = format!("{headers:?}");
        assert!(!header_debug.contains("custom-secret"));
        assert!(!value_debug.contains("custom-secret"));
        assert!(!headers_debug.contains("custom-secret"));
        assert!(header_debug.contains("value_bytes"));
        assert!(value_debug.contains("bytes"));
        assert!(headers_debug.contains("count"));
    }

    #[test]
    fn empty_lower_bounds_fail_closed() {
        let headers = Headers::new();
        assert!(headers.validate_with_limits(0, MAX_HEADER_BYTES).is_err());
        assert!(headers.validate_with_limits(MAX_HEADER_FIELDS, 0).is_err());
    }
}
