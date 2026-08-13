// SPDX-License-Identifier: Apache-2.0
//! HTTP response and timing/byte accounting values.

use std::time::Duration;

use crate::{Headers, HttpError, Url};

/// Byte counters kept separate for headers, payload, and aggregate wire data.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ByteAccounting {
    /// Request header bytes emitted by the adapter, when known.
    pub sent_headers: u64,
    /// Request body bytes emitted by the adapter.
    pub sent_body: u64,
    /// Response header bytes received by the adapter, when known.
    pub received_headers: u64,
    /// Response body bytes received by the adapter.
    pub received_body: u64,
}

impl ByteAccounting {
    /// Creates counters from explicit values.
    #[must_use]
    pub const fn new(
        sent_headers: u64,
        sent_body: u64,
        received_headers: u64,
        received_body: u64,
    ) -> Self {
        Self {
            sent_headers,
            sent_body,
            received_headers,
            received_body,
        }
    }

    /// Returns sent bytes including request headers and body.
    #[must_use]
    #[deprecated(note = "use checked_sent_total for typed overflow handling")]
    pub const fn sent_total(self) -> u64 {
        self.sent_headers.saturating_add(self.sent_body)
    }

    /// Returns sent bytes including headers and body, rejecting overflow.
    pub fn checked_sent_total(self) -> Result<u64, HttpError> {
        self.sent_headers
            .checked_add(self.sent_body)
            .ok_or_else(|| HttpError::resource_limit("sent byte total"))
    }

    /// Returns received bytes including response headers and body.
    #[must_use]
    #[deprecated(note = "use checked_received_total for typed overflow handling")]
    pub const fn received_total(self) -> u64 {
        self.received_headers.saturating_add(self.received_body)
    }

    /// Returns received bytes including headers and body, rejecting overflow.
    pub fn checked_received_total(self) -> Result<u64, HttpError> {
        self.received_headers
            .checked_add(self.received_body)
            .ok_or_else(|| HttpError::resource_limit("received byte total"))
    }

    /// Adds counters without wrapping.
    pub fn checked_add(self, other: Self) -> Result<Self, HttpError> {
        let sent_headers = self
            .sent_headers
            .checked_add(other.sent_headers)
            .ok_or_else(|| HttpError::resource_limit("sent header byte counter"))?;
        let sent_body = self
            .sent_body
            .checked_add(other.sent_body)
            .ok_or_else(|| HttpError::resource_limit("sent body byte counter"))?;
        let received_headers = self
            .received_headers
            .checked_add(other.received_headers)
            .ok_or_else(|| HttpError::resource_limit("received header byte counter"))?;
        let received_body = self
            .received_body
            .checked_add(other.received_body)
            .ok_or_else(|| HttpError::resource_limit("received body byte counter"))?;
        Ok(Self::new(
            sent_headers,
            sent_body,
            received_headers,
            received_body,
        ))
    }

    /// Creates counters from a request body and response body when wire
    /// framing is not available.
    #[must_use]
    #[deprecated(note = "use try_from_body_lengths for typed overflow handling")]
    pub fn from_body_lengths(sent_body: usize, received_body: usize) -> Self {
        Self {
            sent_headers: 0,
            sent_body: u64::try_from(sent_body).unwrap_or(u64::MAX),
            received_headers: 0,
            received_body: u64::try_from(received_body).unwrap_or(u64::MAX),
        }
    }

    /// Creates counters from body lengths without silently saturating a
    /// platform conversion.
    pub fn try_from_body_lengths(
        sent_body: usize,
        received_body: usize,
    ) -> Result<Self, HttpError> {
        Ok(Self {
            sent_headers: 0,
            sent_body: u64::try_from(sent_body)
                .map_err(|_| HttpError::resource_limit("sent body byte counter"))?,
            received_headers: 0,
            received_body: u64::try_from(received_body)
                .map_err(|_| HttpError::resource_limit("received body byte counter"))?,
        })
    }
}

/// Timing observations reported by a transport adapter.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResponseTiming {
    /// Time spent establishing a connection.
    pub connect: Option<Duration>,
    /// Time spent completing a TLS handshake.
    pub tls: Option<Duration>,
    /// Time until the first response byte.
    pub latency: Option<Duration>,
    /// Total adapter time for this response.
    pub elapsed: Option<Duration>,
}

impl ResponseTiming {
    /// Adds timing observations without allowing duration overflow.
    pub fn checked_add(self, other: Self) -> Result<Self, HttpError> {
        Ok(Self {
            connect: checked_duration_add(self.connect, other.connect, "connect timing")?,
            tls: checked_duration_add(self.tls, other.tls, "TLS timing")?,
            latency: checked_duration_add(self.latency, other.latency, "latency timing")?,
            elapsed: checked_duration_add(self.elapsed, other.elapsed, "elapsed timing")?,
        })
    }
}

fn checked_duration_add(
    left: Option<Duration>,
    right: Option<Duration>,
    field: &str,
) -> Result<Option<Duration>, HttpError> {
    match (left, right) {
        (Some(left), Some(right)) => left
            .checked_add(right)
            .map(Some)
            .ok_or_else(|| HttpError::resource_limit(field)),
        (Some(value), None) | (None, Some(value)) => Ok(Some(value)),
        (None, None) => Ok(None),
    }
}

/// One HTTP response returned by a transport.
#[derive(Clone, Eq, PartialEq)]
pub struct Response {
    status: u16,
    reason: String,
    headers: Headers,
    body: Vec<u8>,
    url: Option<Url>,
    bytes: ByteAccounting,
    timing: ResponseTiming,
    from_cache: bool,
}

impl std::fmt::Debug for Response {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Response")
            .field("status", &self.status)
            .field("reason", &bounded_preview(&self.reason, 128))
            .field("headers", &self.headers)
            .field("body_bytes", &self.body.len())
            .field("url", &self.url)
            .field("bytes", &self.bytes)
            .field("timing", &self.timing)
            .field("from_cache", &self.from_cache)
            .finish()
    }
}

fn bounded_preview(value: &str, maximum: usize) -> String {
    if value.len() <= maximum {
        return value.to_owned();
    }
    let mut end = maximum;
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    format!("{}…", &value[..end])
}

impl Response {
    /// Creates an empty response with a status code.
    #[must_use]
    pub fn new(status: u16) -> Self {
        Self {
            status,
            reason: String::new(),
            headers: Headers::new(),
            body: Vec::new(),
            url: None,
            bytes: ByteAccounting::default(),
            timing: ResponseTiming::default(),
            from_cache: false,
        }
    }

    /// Creates a response with a body.
    pub fn with_body(status: u16, body: impl Into<Vec<u8>>) -> Result<Self, HttpError> {
        validate_status_code(status)?;
        let body = body.into();
        let mut response = Self::new(status);
        response.set_body(body)?;
        Ok(response)
    }

    /// Returns the numeric status code.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Sets the numeric status code.
    pub const fn set_status(&mut self, status: u16) {
        self.status = status;
    }

    /// Returns the reason phrase, if one was supplied.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Sets the reason phrase.
    pub fn set_reason(&mut self, reason: impl Into<String>) {
        self.reason = reason.into();
    }

    /// Returns response headers in wire order.
    #[must_use]
    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    /// Returns mutable response headers.
    #[must_use]
    pub fn headers_mut(&mut self) -> &mut Headers {
        &mut self.headers
    }

    /// Returns response body bytes.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Returns mutable response body bytes.
    #[must_use]
    pub fn body_mut(&mut self) -> &mut Vec<u8> {
        &mut self.body
    }

    /// Replaces the response body with checked byte accounting.
    pub fn set_body(&mut self, body: impl Into<Vec<u8>>) -> Result<(), HttpError> {
        let body = body.into();
        let received_body = u64::try_from(body.len())
            .map_err(|_| HttpError::resource_limit("received body byte counter"))?;
        self.body = body;
        self.bytes.received_body = received_body;
        Ok(())
    }

    /// Adds a validated response header.
    pub fn add_header(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), HttpError> {
        self.headers.insert(name, value)
    }

    /// Returns this response with one appended header.
    pub fn with_header(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, HttpError> {
        self.add_header(name, value)?;
        Ok(self)
    }

    /// Returns the response's final URL, if supplied by a client.
    #[must_use]
    pub fn url(&self) -> Option<&Url> {
        self.url.as_ref()
    }

    /// Sets the response URL.
    pub fn set_url(&mut self, url: Url) {
        self.url = Some(url);
    }

    /// Returns adapter byte counters.
    #[must_use]
    pub const fn bytes(&self) -> ByteAccounting {
        self.bytes
    }

    /// Sets adapter byte counters.
    pub const fn set_bytes(&mut self, bytes: ByteAccounting) {
        self.bytes = bytes;
    }

    /// Returns adapter timing observations.
    #[must_use]
    pub const fn timing(&self) -> ResponseTiming {
        self.timing
    }

    /// Sets adapter timing observations.
    pub const fn set_timing(&mut self, timing: ResponseTiming) {
        self.timing = timing;
    }

    /// Returns whether this response was served by the semantic cache.
    #[must_use]
    pub const fn from_cache(&self) -> bool {
        self.from_cache
    }

    /// Marks a response as cache-served.
    pub const fn mark_from_cache(&mut self) {
        self.from_cache = true;
    }

    /// Returns whether the status is in JMeter's normal success range.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 400
    }

    /// Returns whether this is a redirect status handled by the client.
    #[must_use]
    pub const fn is_redirect(&self) -> bool {
        matches!(self.status, 301 | 302 | 303 | 307 | 308)
    }

    /// Returns a response with a 304 response's metadata and a cached body.
    pub fn merge_not_modified(cached: &Self, not_modified: &Self) -> Self {
        let mut merged = cached.clone();
        let mut replaced_names: Vec<String> = Vec::new();
        for field in not_modified.headers() {
            if !replaced_names
                .iter()
                .any(|name| name.eq_ignore_ascii_case(field.name().as_str()))
            {
                replaced_names.push(field.name().as_str().to_owned());
            }
        }
        for name in &replaced_names {
            merged.headers.remove(name);
        }
        for field in not_modified.headers() {
            merged.headers.append(field.clone());
        }
        merged.status = 200;
        merged.reason = cached.reason.clone();
        merged.bytes.received_headers = not_modified.bytes.received_headers;
        // The cached body is materialized for the caller but was not received
        // on the 304 wire response.  Keep that distinction in accounting.
        merged.bytes.received_body = not_modified.bytes.received_body;
        merged.timing = not_modified.timing;
        merged.from_cache = true;
        merged
    }
}

/// HTTP status codes are three decimal digits whose first digit identifies a
/// response class.  Values outside 100..=599 are not valid HTTP responses and
/// must not cross the transport boundary as if they were ordinary samples.
pub(crate) fn validate_status_code(status: u16) -> Result<(), HttpError> {
    if (100..=599).contains(&status) {
        Ok(())
    } else {
        Err(HttpError::InvalidHeader(
            "response status code is outside 100..=599".to_owned(),
        ))
    }
}

/// Returns whether a status code is a valid HTTP response code.
#[must_use]
pub(crate) const fn is_valid_status_code(status: u16) -> bool {
    status >= 100 && status <= 599
}

/// Final result of one logical sampler, including redirect attempts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpResult {
    response: Response,
    redirects: usize,
    bytes: ByteAccounting,
    elapsed: Duration,
    started_at_wall_millis: i64,
    ended_at_wall_millis: i64,
}

impl HttpResult {
    /// Creates a result from an executed response.
    #[must_use]
    pub const fn new(
        response: Response,
        redirects: usize,
        bytes: ByteAccounting,
        elapsed: Duration,
        started_at_wall_millis: i64,
        ended_at_wall_millis: i64,
    ) -> Self {
        Self {
            response,
            redirects,
            bytes,
            elapsed,
            started_at_wall_millis,
            ended_at_wall_millis,
        }
    }

    /// Returns the final response.
    #[must_use]
    pub const fn response(&self) -> &Response {
        &self.response
    }

    /// Returns the number of followed redirects.
    #[must_use]
    pub const fn redirects(&self) -> usize {
        self.redirects
    }

    /// Returns aggregate counters across all attempts.
    #[must_use]
    pub const fn bytes(&self) -> ByteAccounting {
        self.bytes
    }

    /// Returns elapsed monotonic time for the logical sampler.
    #[must_use]
    pub const fn elapsed(&self) -> Duration {
        self.elapsed
    }

    /// Returns wall-clock start milliseconds.
    #[must_use]
    pub const fn started_at_wall_millis(&self) -> i64 {
        self.started_at_wall_millis
    }

    /// Returns wall-clock end milliseconds.
    #[must_use]
    pub const fn ended_at_wall_millis(&self) -> i64 {
        self.ended_at_wall_millis
    }

    /// Returns whether the final response was served by cache.
    #[must_use]
    pub const fn from_cache(&self) -> bool {
        self.response.from_cache()
    }
}
