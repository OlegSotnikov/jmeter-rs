// SPDX-License-Identifier: Apache-2.0
//! HTTP response and timing/byte accounting values.

use std::time::Duration;

use crate::policy::{validate_decompression_limits, validate_response_body_limit};
use crate::{Headers, HttpError, Url};
use jmeter_rs_results::{
    ByteCount, ConnectTime, DataEncoding, DataLimits, DataType, ElapsedTime, HeaderBlock, Latency,
    SampleData, SampleResult, SampleTiming, TimestampSource, ValidationLimits, WallTimestamp,
};

/// Maximum number of response trailer fields retained by the pure response
/// model.  The value mirrors the hard HTTP parser limit in Decision 0006.
pub const MAX_RESPONSE_TRAILERS: usize = 256;
/// Maximum aggregate encoded size of response trailers.
pub const MAX_RESPONSE_TRAILER_BYTES: usize = 256 * 1024;
/// Maximum retained sample label size for result projection.
pub const MAX_SAMPLE_LABEL_BYTES: usize = 64 * 1024;
/// Maximum bytes retained for the JTL `samplerData` projection.
///
/// The request method and original URL are both independently bounded by the
/// request core.  Keeping a separate finite ceiling makes the projection
/// safe if either bound changes and lets the context reject before allocating
/// the formatted sampler-data string.
pub const MAX_SAMPLER_DATA_BYTES: usize = MAX_SAMPLE_LABEL_BYTES;
/// Maximum number of redirect responses retained in a logical result.
pub const MAX_REDIRECT_HISTORY: usize = 64;
/// Maximum aggregate bytes retained by redirect metadata and bodies.
pub const MAX_REDIRECT_HISTORY_BYTES: usize = 64 * 1024 * 1024;
/// Maximum decompression expansion ratio accepted by the pure observation
/// validator.  Concrete codecs enforce this incrementally while reading.
pub const MAX_DECOMPRESSION_RATIO: u64 = crate::policy::HARD_MAX_DECOMPRESSION_RATIO;
/// Maximum decoded response bytes accepted by the protocol observation model.
pub const MAX_DECOMPRESSED_RESPONSE_BYTES: u64 = crate::policy::HARD_MAX_DECOMPRESSED_BYTES as u64;
/// Maximum wire response-body bytes accepted by one protocol attempt.
pub const MAX_WIRE_RESPONSE_BYTES: u64 = 256 * 1024 * 1024;
/// Maximum reason-phrase bytes retained by one response head.
pub const MAX_RESPONSE_REASON_BYTES: usize = 4 * 1024;
/// Maximum aggregate bytes retained by informational response observations.
///
/// This is the hard limit from Decision 0006.  It is deliberately separate
/// from the final response body bound: informational responses have no entity
/// body, but their status lines, reason phrases, and ordered headers still
/// consume bounded observation space.
pub const MAX_INFORMATIONAL_RESPONSE_BYTES: usize = 256 * 1024;

/// A response field whose absence is distinct from a present empty value.
///
/// This is an alias for the protocol-level presence discriminator so pure
/// response metadata and `AttemptRecordV1` use the same semantics.  In
/// particular, `Present(String::new())` is not interchangeable with
/// `Absent`.
pub type ResponsePresence<T> = crate::Presence<T>;

/// Explicit body presence carried across the transport body stream.
///
/// A body stream ending without data cannot distinguish an absent entity from
/// a present zero-length entity.  Adapters therefore set this value before
/// collection; the collector never derives it from the status code, method,
/// byte counters, or observed chunks.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum ResponseBodyPresence {
    /// No response entity was observed.
    #[default]
    Absent,
    /// A response entity was observed, including a zero-length entity.
    Present,
}

/// One bounded informational (`1xx`) response head in wire order.
///
/// Informational responses have no body in HTTP/1.1.  The type nevertheless
/// retains explicit framing and protocol observations because those values are
/// needed by the attempt protocol and must not be inferred when an adapter did
/// not expose them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseHeadObservation {
    /// The informational status code.
    pub status: u16,
    /// A reason phrase, including present-empty, or an absent phrase.
    pub reason: ResponsePresence<String>,
    /// Observed protocol version, if exposed by the adapter.
    pub protocol: Option<crate::ProtocolVersion>,
    /// Ordered response headers, including duplicate fields.
    pub headers: Headers,
    /// Observed entity framing, if exposed by the adapter.
    pub framing: Option<crate::Framing>,
}

impl ResponseHeadObservation {
    /// Creates an informational response head with absent reason/metadata.
    pub fn new(status: u16) -> Result<Self, HttpError> {
        validate_informational_status(status)?;
        Ok(Self {
            status,
            reason: ResponsePresence::Absent,
            protocol: None,
            headers: Headers::new(),
            framing: None,
        })
    }

    /// Creates a head with an explicitly observed protocol version.
    pub fn with_protocol(status: u16, protocol: crate::ProtocolVersion) -> Result<Self, HttpError> {
        let mut head = Self::new(status)?;
        head.protocol = Some(protocol);
        Ok(head)
    }

    /// Sets an absent or present (possibly empty) reason phrase.
    pub fn set_reason(&mut self, reason: ResponsePresence<String>) -> Result<(), HttpError> {
        validate_reason_presence(&reason)?;
        self.reason = reason;
        Ok(())
    }

    /// Sets a present reason phrase, including the empty phrase.
    pub fn set_reason_present(&mut self, reason: impl Into<String>) -> Result<(), HttpError> {
        self.set_reason(ResponsePresence::Present(reason.into()))
    }

    /// Marks the reason phrase absent and clears any retained bytes.
    pub fn set_reason_absent(&mut self) {
        self.reason = ResponsePresence::Absent;
    }

    /// Adds one ordered response-header field.
    pub fn add_header(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), HttpError> {
        self.headers.insert(name, value)
    }

    /// Sets the observed protocol version, or clears it when the adapter did
    /// not expose the wire version.
    pub const fn set_protocol(&mut self, protocol: Option<crate::ProtocolVersion>) {
        self.protocol = protocol;
    }

    /// Sets the observed framing, or clears it when the adapter did not expose
    /// the framing boundary.
    pub const fn set_framing(&mut self, framing: Option<crate::Framing>) {
        self.framing = framing;
    }

    /// Validates the head against the response-attempt hard bounds.
    pub fn validate(&self) -> Result<(), HttpError> {
        validate_informational_status(self.status)?;
        validate_reason_presence(&self.reason)?;
        self.headers.validate()
    }

    /// Returns the bounded encoded observation size used by the aggregate
    /// informational-response limit.
    pub fn checked_observation_bytes(&self) -> Result<usize, HttpError> {
        self.validate()?;
        let reason_bytes = match &self.reason {
            ResponsePresence::Absent => 0,
            ResponsePresence::Present(reason) => reason.len(),
        };
        let headers = self.headers.checked_wire_len()?;
        3usize
            .checked_add(reason_bytes)
            .and_then(|size| size.checked_add(headers))
            .ok_or_else(|| HttpError::resource_limit("informational response bytes"))
    }
}

fn validate_informational_status(status: u16) -> Result<(), HttpError> {
    if (100..200).contains(&status) {
        Ok(())
    } else {
        Err(HttpError::InvalidHeader(
            "informational response status must be in 100..=199".to_owned(),
        ))
    }
}

fn validate_reason_presence(reason: &ResponsePresence<String>) -> Result<(), HttpError> {
    let ResponsePresence::Present(reason) = reason else {
        return Ok(());
    };
    if reason.len() > MAX_RESPONSE_REASON_BYTES
        || reason.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
    {
        return Err(HttpError::InvalidHeader(
            "response reason phrase is invalid or too large".to_owned(),
        ));
    }
    Ok(())
}

/// Bounded response metadata carried beside a [`TransportResponse`] body.
///
/// This sidecar keeps the public `TransportResponse` struct source-compatible
/// for existing adapters that construct it with a struct literal.  Such
/// adapters receive the safe absent default.  New adapters should use the
/// explicit `TransportResponse` builder methods to record the wire presence
/// and informational heads they observed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportResponseObservation {
    /// Final response reason presence.
    pub reason: ResponsePresence<String>,
    /// Final response body presence.
    pub body: ResponseBodyPresence,
    /// Ordered informational response heads.
    pub informational_responses: Vec<ResponseHeadObservation>,
}

impl Default for TransportResponseObservation {
    fn default() -> Self {
        Self {
            reason: ResponsePresence::Absent,
            body: ResponseBodyPresence::Absent,
            informational_responses: Vec::new(),
        }
    }
}

impl TransportResponseObservation {
    /// Creates explicit final-head presence metadata with no informational
    /// responses.
    #[must_use]
    pub fn new(reason: ResponsePresence<String>, body: ResponseBodyPresence) -> Self {
        Self {
            reason,
            body,
            informational_responses: Vec::new(),
        }
    }

    /// Returns the final response reason presence without collapsing a
    /// present-empty phrase into absence.
    #[must_use]
    pub const fn reason_presence(&self) -> &ResponsePresence<String> {
        &self.reason
    }

    /// Returns the final response body presence without inspecting body bytes.
    #[must_use]
    pub const fn body_presence(&self) -> ResponseBodyPresence {
        self.body
    }

    /// Validates all reason and informational limits before collection.
    pub fn validate(&self) -> Result<(), HttpError> {
        validate_reason_presence(&self.reason)?;
        if self.informational_responses.len() > crate::MAX_INFORMATIONAL_RESPONSES {
            return Err(HttpError::resource_limit("informational response count"));
        }
        let mut aggregate = 0usize;
        for head in &self.informational_responses {
            let bytes = head.checked_observation_bytes()?;
            aggregate = aggregate
                .checked_add(bytes)
                .ok_or_else(|| HttpError::resource_limit("informational response bytes"))?;
            if aggregate > MAX_INFORMATIONAL_RESPONSE_BYTES {
                return Err(HttpError::resource_limit("informational response bytes"));
            }
        }
        Ok(())
    }

    /// Returns the informational response heads in exact wire order.
    #[must_use]
    pub fn informational_responses(&self) -> &[ResponseHeadObservation] {
        &self.informational_responses
    }

    /// Replaces the ordered informational response list after validation.
    pub fn set_informational_responses(
        &mut self,
        responses: Vec<ResponseHeadObservation>,
    ) -> Result<(), HttpError> {
        let previous = std::mem::replace(&mut self.informational_responses, responses);
        if let Err(error) = self.validate() {
            self.informational_responses = previous;
            return Err(error);
        }
        Ok(())
    }

    /// Appends one informational response atomically after validation.
    pub fn push_informational_response(
        &mut self,
        response: ResponseHeadObservation,
    ) -> Result<(), HttpError> {
        let previous_len = self.informational_responses.len();
        self.informational_responses.push(response);
        if let Err(error) = self.validate() {
            self.informational_responses.truncate(previous_len);
            return Err(error);
        }
        Ok(())
    }
}

/// Completion state of a response body observation.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum ResponseBodyCompletion {
    /// The body was consumed to its framing boundary.
    #[default]
    Complete,
    /// The body failed before its framing boundary was proven.
    Failed,
    /// Cancellation stopped body observation.
    Cancelled,
    /// A configured body/decompression limit stopped observation.
    ResourceLimit,
}

/// A decompression observation kept separate from wire and decoded counters.
///
/// `wire_bytes` is the number of compressed entity bytes received from the
/// adapter, while `decoded_bytes` is the number of bytes exposed to the
/// sampler/result layer.  The fields are optional because a transport may not
/// expose one of the counters; an absent value is never guessed as zero.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct DecompressionObservation {
    /// The selected content-coding, if one was observed.
    pub coding: Option<crate::Compression>,
    /// Compressed entity bytes, when known.
    pub wire_bytes: Option<u64>,
    /// Decoded entity bytes, when known.
    pub decoded_bytes: Option<u64>,
    /// The checked expansion ratio, when both counters are known.
    pub expansion_ratio: Option<u64>,
}

impl DecompressionObservation {
    /// Creates an identity observation with a known decoded length.
    #[must_use]
    pub const fn identity(decoded_bytes: u64) -> Self {
        Self {
            coding: Some(crate::Compression::Identity),
            wire_bytes: Some(decoded_bytes),
            decoded_bytes: Some(decoded_bytes),
            expansion_ratio: Some(1),
        }
    }

    /// Validates finite decoded-byte and expansion-ratio limits.
    pub fn validate(self, maximum_decoded_bytes: u64, maximum_ratio: u64) -> Result<(), HttpError> {
        validate_decompression_limits(maximum_decoded_bytes, maximum_ratio)?;
        if let Some(decoded) = self.decoded_bytes
            && decoded > maximum_decoded_bytes
        {
            return Err(HttpError::resource_limit("decompressed response bytes"));
        }
        if self.expansion_ratio.is_some()
            && (self.wire_bytes.is_none() || self.decoded_bytes.is_none())
        {
            return Err(HttpError::InvalidHeader(
                "decompression expansion ratio requires both byte counters".to_owned(),
            ));
        }
        let Some((wire, decoded)) = self.wire_bytes.zip(self.decoded_bytes) else {
            return Ok(());
        };
        if wire == 0 {
            if decoded != 0 {
                return Err(HttpError::resource_limit("decompression expansion ratio"));
            }
            if let Some(observed) = self.expansion_ratio
                && observed != 1
            {
                return Err(HttpError::InvalidHeader(
                    "decompression expansion ratio observation is inconsistent".to_owned(),
                ));
            }
            return Ok(());
        }
        let ratio = decoded
            .checked_add(wire.saturating_sub(1))
            .ok_or_else(|| HttpError::resource_limit("decompression expansion ratio"))?
            / wire;
        if let Some(observed) = self.expansion_ratio
            && observed != ratio
        {
            return Err(HttpError::InvalidHeader(
                "decompression expansion ratio observation is inconsistent".to_owned(),
            ));
        }
        if ratio > maximum_ratio {
            return Err(HttpError::resource_limit("decompression expansion ratio"));
        }
        Ok(())
    }
}

/// Options controlling conversion of an HTTP response into a JTL
/// [`SampleResult`].  All options are explicit so a caller cannot accidentally
/// read response files, fold trailers, or silently discard a body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SampleResultProjectionOptions {
    /// Result-data bounds applied before the projection retains any bytes.
    pub data_limits: DataLimits,
    /// Whether response bytes should be retained in the result.
    pub include_response_data: bool,
    /// Whether raw response head headers should be retained in the result.
    pub include_response_headers: bool,
    /// Timestamp endpoint used for the JTL `timeStamp` field.
    pub timestamp_source: TimestampSource,
    /// Whether request headers and sampler data are retained in the result.
    pub include_request_metadata: bool,
}

impl Default for SampleResultProjectionOptions {
    fn default() -> Self {
        Self {
            data_limits: DataLimits::default_bounded(),
            include_response_data: true,
            include_response_headers: true,
            timestamp_source: TimestampSource::Start,
            include_request_metadata: true,
        }
    }
}

/// Bounded request information retained for a logical sampler result.
///
/// The context is captured from the prepared request, so duplicate header
/// order and present-empty request entities survive until JTL projection.
/// It contains no transport lease or mutable client state.
#[derive(Clone, Eq, PartialEq)]
pub struct RequestContext {
    method: String,
    url: Url,
    headers: Headers,
    body: Option<Vec<u8>>,
    sampler_data: String,
}

impl std::fmt::Debug for RequestContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RequestContext")
            .field("method", &self.method)
            .field("url_present", &true)
            .field("headers", &self.headers)
            .field("body_bytes", &self.body.as_ref().map(Vec::len))
            .field("sampler_data_bytes", &self.sampler_data.len())
            .finish()
    }
}

impl RequestContext {
    /// Captures a bounded request snapshot before an attempt is dispatched.
    pub fn from_request(request: &crate::Request) -> Result<Self, HttpError> {
        // Validate the borrowed request before cloning any potentially large
        // entity. The owned production path performs the same checks after
        // moving its parts, while this compatibility helper must remain
        // bounded even when called with a manually assembled request.
        request.headers().validate_with_limits(
            crate::MAX_REQUEST_HEADER_FIELDS,
            crate::MAX_REQUEST_HEADER_BYTES,
        )?;
        if request.body().len() > crate::MAX_REQUEST_BODY_BYTES {
            return Err(HttpError::resource_limit("request body context"));
        }
        Self::from_request_owned(request.clone())
    }

    /// Captures a bounded request snapshot by moving the request's owned
    /// parts. This is the production path used by [`HttpClient`](crate::HttpClient)
    /// so request headers and entities are not cloned solely for JTL metadata.
    pub(crate) fn from_request_owned(request: crate::Request) -> Result<Self, HttpError> {
        let (method_value, url, headers, body_value) = request.into_parts();
        let method = method_value.as_str().to_owned();
        if method.len() > 256 {
            return Err(HttpError::resource_limit("request method context"));
        }
        headers.validate_with_limits(
            crate::MAX_REQUEST_HEADER_FIELDS,
            crate::MAX_REQUEST_HEADER_BYTES,
        )?;
        let body = if body_value.is_present() {
            if body_value.len() > crate::MAX_REQUEST_BODY_BYTES {
                return Err(HttpError::resource_limit("request body context"));
            }
            Some(body_value.into_bytes())
        } else {
            None
        };

        // `Method` and `Url` are already validated at their construction
        // boundaries, but calculate the complete projection size before
        // allocating the formatted sampler-data string. The URL is moved
        // into the context and therefore does not need to be cloned here.
        let sampler_data_bytes = method
            .len()
            .checked_add(1)
            .and_then(|size| size.checked_add(url.as_str().len()))
            .ok_or_else(|| HttpError::resource_limit("sampler data"))?;
        if sampler_data_bytes > MAX_SAMPLER_DATA_BYTES {
            return Err(HttpError::resource_limit("sampler data"));
        }
        let mut sampler_data = String::with_capacity(sampler_data_bytes);
        sampler_data.push_str(&method);
        sampler_data.push(' ');
        sampler_data.push_str(url.as_str());

        Ok(Self {
            method,
            url,
            headers,
            body,
            sampler_data,
        })
    }

    /// Returns the method spelling captured from the request.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Returns the request URL.
    #[must_use]
    pub const fn url(&self) -> &Url {
        &self.url
    }

    /// Returns duplicate-preserving request headers.
    #[must_use]
    pub const fn headers(&self) -> &Headers {
        &self.headers
    }

    /// Returns an absent or present (possibly empty) request entity.
    #[must_use]
    pub fn body(&self) -> Option<&[u8]> {
        self.body.as_deref()
    }

    /// Returns the deterministic sampler-data text used by the projection.
    /// The exact upstream formatting remains oracle-gated.
    #[must_use]
    pub fn sampler_data(&self) -> &str {
        &self.sampler_data
    }
}

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
    reason_present: bool,
    headers: Headers,
    trailers: Option<Headers>,
    body: Vec<u8>,
    body_present: bool,
    url: Option<Url>,
    bytes: ByteAccounting,
    timing: ResponseTiming,
    from_cache: bool,
    protocol: Option<crate::ProtocolVersion>,
    framing: Option<crate::Framing>,
    compression: Option<crate::Compression>,
    body_completion: ResponseBodyCompletion,
    decompression: DecompressionObservation,
    informational_responses: Vec<ResponseHeadObservation>,
    charset: Option<String>,
    data_type: Option<DataType>,
}

impl std::fmt::Debug for Response {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Response")
            .field("status", &self.status)
            .field("reason", &bounded_preview(&self.reason, 128))
            .field("reason_present", &self.reason_present)
            .field("headers", &self.headers)
            .field("trailers", &self.trailers.as_ref().map(Headers::len))
            .field("body_bytes", &self.body.len())
            .field("body_present", &self.body_present)
            .field("url", &self.url)
            .field("bytes", &self.bytes)
            .field("timing", &self.timing)
            .field("from_cache", &self.from_cache)
            .field("protocol", &self.protocol)
            .field("framing", &self.framing)
            .field("compression", &self.compression)
            .field("body_completion", &self.body_completion)
            .field("decompression", &self.decompression)
            .field(
                "informational_responses",
                &self.informational_responses.len(),
            )
            .field("charset", &self.charset.as_ref().map(String::len))
            .field("data_type", &self.data_type)
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

fn validate_trailers(trailers: &Headers) -> Result<(), HttpError> {
    if trailers.len() > MAX_RESPONSE_TRAILERS {
        return Err(HttpError::resource_limit("response trailer count"));
    }
    if trailers.checked_wire_len()? > MAX_RESPONSE_TRAILER_BYTES {
        return Err(HttpError::resource_limit("response trailer bytes"));
    }
    Ok(())
}

fn response_retained_bytes(response: &Response) -> Result<usize, HttpError> {
    validate_response_head(response)?;
    let mut total = response
        .body
        .len()
        .checked_add(response.reason.len())
        .ok_or_else(|| HttpError::resource_limit("redirect response history"))?;
    total = total
        .checked_add(response.url.as_ref().map_or(0, |url| url.as_str().len()))
        .ok_or_else(|| HttpError::resource_limit("redirect response history"))?;
    total = total
        .checked_add(response.checked_charset()?.map_or(0, str::len))
        .ok_or_else(|| HttpError::resource_limit("redirect response history"))?;
    total = total
        .checked_add(response.inferred_data_type().as_wire().len())
        .ok_or_else(|| HttpError::resource_limit("redirect response history"))?;
    total = total
        .checked_add(response.headers.checked_wire_len()?)
        .ok_or_else(|| HttpError::resource_limit("redirect response history"))?;
    if let Some(trailers) = &response.trailers {
        total = total
            .checked_add(trailers.checked_wire_len()?)
            .ok_or_else(|| HttpError::resource_limit("redirect response history"))?;
    }
    for informational in &response.informational_responses {
        total = total
            .checked_add(informational.checked_observation_bytes()?)
            .ok_or_else(|| HttpError::resource_limit("redirect response history"))?;
    }
    Ok(total)
}

fn validate_response_head(response: &Response) -> Result<(), HttpError> {
    validate_status_code(response.status)?;
    response
        .decompression
        .validate(MAX_DECOMPRESSED_RESPONSE_BYTES, MAX_DECOMPRESSION_RATIO)?;
    if response.reason.len() > MAX_RESPONSE_REASON_BYTES
        || response
            .reason
            .bytes()
            .any(|byte| byte < 0x20 || byte == 0x7f)
    {
        return Err(HttpError::InvalidHeader(
            "response reason phrase is invalid or too large".to_owned(),
        ));
    }
    response.headers.validate()?;
    if let Some(trailers) = &response.trailers {
        validate_trailers(trailers)?;
    }
    let observation = TransportResponseObservation {
        reason: if response.reason_present {
            ResponsePresence::Present(response.reason.clone())
        } else {
            ResponsePresence::Absent
        },
        body: if response.body_present {
            ResponseBodyPresence::Present
        } else {
            ResponseBodyPresence::Absent
        },
        informational_responses: response.informational_responses.clone(),
    };
    observation.validate()?;
    let body_bytes = u64::try_from(response.body.len())
        .map_err(|_| HttpError::resource_limit("response body byte counter"))?;
    if body_bytes > MAX_DECOMPRESSED_RESPONSE_BYTES {
        return Err(HttpError::ResponseBodyLimit {
            actual: response.body.len(),
            maximum: usize::try_from(MAX_DECOMPRESSED_RESPONSE_BYTES).unwrap_or(usize::MAX),
        });
    }
    if response.bytes.received_headers
        > u64::try_from(crate::MAX_REQUEST_HEADER_BYTES).unwrap_or(u64::MAX)
    {
        return Err(HttpError::resource_limit("received response header bytes"));
    }
    if !response.body_present && response.bytes.received_body != 0 {
        return Err(HttpError::InvalidHeader(
            "absent response body has nonzero received-body bytes".to_owned(),
        ));
    }
    if response.bytes.received_body > MAX_WIRE_RESPONSE_BYTES {
        return Err(HttpError::resource_limit("received response body bytes"));
    }
    if response.bytes.sent_headers
        > u64::try_from(crate::MAX_REQUEST_HEADER_BYTES).unwrap_or(u64::MAX)
        || response.bytes.sent_body
            > u64::try_from(crate::MAX_REQUEST_BODY_BYTES).unwrap_or(u64::MAX)
    {
        return Err(HttpError::resource_limit("sent request bytes"));
    }
    Ok(())
}

fn header_block(headers: &Headers, limits: DataLimits) -> Result<HeaderBlock, HttpError> {
    let estimated = headers.checked_wire_len()?;
    if estimated > limits.max_header_bytes() {
        return Err(HttpError::resource_limit("response result headers"));
    }
    let mut value = String::with_capacity(estimated);
    for field in headers {
        value.push_str(field.name().as_str());
        value.push_str(": ");
        value.push_str(field.value().as_str());
        value.push_str("\r\n");
    }
    HeaderBlock::try_new_with_limits(value, limits)
        .map_err(|_| HttpError::resource_limit("response result headers"))
}

fn optional_elapsed(value: Option<Duration>) -> Result<Option<ElapsedTime>, HttpError> {
    value
        .map(ElapsedTime::try_from_duration)
        .transpose()
        .map_err(|_| HttpError::resource_limit("sample result elapsed time"))
}

fn optional_latency(value: Option<Duration>) -> Result<Option<Latency>, HttpError> {
    value
        .map(Latency::try_from_duration)
        .transpose()
        .map_err(|_| HttpError::resource_limit("sample result latency"))
}

fn optional_connect(value: Option<Duration>) -> Result<Option<ConnectTime>, HttpError> {
    value
        .map(ConnectTime::try_from_duration)
        .transpose()
        .map_err(|_| HttpError::resource_limit("sample result connect time"))
}

impl Response {
    /// Returns the bounded response footprint retained when this response is
    /// kept as a redirect sub-result. This includes the response head, URL,
    /// body, trailers, charset/data type metadata, and informational heads.
    pub(crate) fn checked_retained_bytes(&self) -> Result<usize, HttpError> {
        response_retained_bytes(self)
    }

    /// Creates an empty response with a status code.
    #[must_use]
    pub fn new(status: u16) -> Self {
        Self {
            status,
            reason: String::new(),
            reason_present: false,
            headers: Headers::new(),
            trailers: None,
            body: Vec::new(),
            body_present: false,
            url: None,
            bytes: ByteAccounting::default(),
            timing: ResponseTiming::default(),
            from_cache: false,
            protocol: None,
            framing: None,
            compression: None,
            body_completion: ResponseBodyCompletion::Complete,
            decompression: DecompressionObservation::default(),
            informational_responses: Vec::new(),
            charset: None,
            data_type: None,
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

    /// Returns whether a reason phrase was observed on the response head.
    #[must_use]
    pub const fn reason_present(&self) -> bool {
        self.reason_present
    }

    /// Returns the reason phrase with its explicit presence discriminator.
    ///
    /// `Present("")` is retained as present-empty; callers must not replace
    /// this value with `reason().is_empty()` when building an attempt record.
    #[must_use]
    pub fn reason_presence(&self) -> ResponsePresence<&str> {
        if self.reason_present {
            ResponsePresence::Present(self.reason.as_str())
        } else {
            ResponsePresence::Absent
        }
    }

    /// Sets the reason phrase.
    pub fn set_reason(&mut self, reason: impl Into<String>) {
        self.reason = reason.into();
        self.reason_present = true;
    }

    /// Sets a reason phrase after enforcing the response-head bound.
    pub fn set_reason_bounded(&mut self, reason: &str) -> Result<(), HttpError> {
        if reason.len() > MAX_RESPONSE_REASON_BYTES
            || reason.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
        {
            return Err(HttpError::InvalidHeader(
                "response reason phrase is invalid or too large".to_owned(),
            ));
        }
        self.set_reason(reason);
        Ok(())
    }

    /// Clears a reason phrase while preserving the absent-vs-present-empty
    /// distinction required by HTTP/2 and result projections.
    pub fn set_reason_absent(&mut self) {
        self.reason.clear();
        self.reason_present = false;
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

    /// Returns response trailers, preserving absent versus present-empty.
    #[must_use]
    pub fn trailers(&self) -> Option<&Headers> {
        self.trailers.as_ref()
    }

    /// Replaces response trailers after enforcing parser hard limits.
    /// Trailers are deliberately not merged into ordinary response headers.
    pub fn set_trailers(&mut self, trailers: Option<Headers>) -> Result<(), HttpError> {
        if let Some(value) = &trailers {
            validate_trailers(value)?;
        }
        self.trailers = trailers;
        Ok(())
    }

    /// Adds one trailer field, making the trailer collection present.
    pub fn add_trailer(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), HttpError> {
        let field = crate::Header::new(name, value)?;
        let previous = self.trailers.take();
        let mut trailers = previous.clone().unwrap_or_default();
        trailers.append(field);
        if let Err(error) = validate_trailers(&trailers) {
            self.trailers = previous;
            return Err(error);
        }
        self.trailers = Some(trailers);
        Ok(())
    }

    /// Returns informational response heads in their observed wire order.
    ///
    /// The final response model retains these heads even though the ordinary
    /// JTL sample projection has no dedicated 1xx fields.  Attempt-level
    /// consumers can use this collection to build `AttemptRecordV1` without
    /// reconstructing or reordering the wire exchange.
    #[must_use]
    pub fn informational_responses(&self) -> &[ResponseHeadObservation] {
        &self.informational_responses
    }

    /// Replaces informational response observations after checking their
    /// count, aggregate bytes, status, reason, and ordered-header bounds.
    pub fn set_informational_responses(
        &mut self,
        responses: Vec<ResponseHeadObservation>,
    ) -> Result<(), HttpError> {
        let previous = std::mem::replace(&mut self.informational_responses, responses);
        let observation = TransportResponseObservation {
            reason: if self.reason_present {
                ResponsePresence::Present(self.reason.clone())
            } else {
                ResponsePresence::Absent
            },
            body: if self.body_present {
                ResponseBodyPresence::Present
            } else {
                ResponseBodyPresence::Absent
            },
            informational_responses: self.informational_responses.clone(),
        };
        if let Err(error) = observation.validate() {
            self.informational_responses = previous;
            return Err(error);
        }
        Ok(())
    }

    /// Appends one informational response observation atomically.
    pub fn add_informational_response(
        &mut self,
        response: ResponseHeadObservation,
    ) -> Result<(), HttpError> {
        let previous_len = self.informational_responses.len();
        self.informational_responses.push(response);
        let observation = TransportResponseObservation {
            reason: if self.reason_present {
                ResponsePresence::Present(self.reason.clone())
            } else {
                ResponsePresence::Absent
            },
            body: if self.body_present {
                ResponseBodyPresence::Present
            } else {
                ResponseBodyPresence::Absent
            },
            informational_responses: self.informational_responses.clone(),
        };
        if let Err(error) = observation.validate() {
            self.informational_responses.truncate(previous_len);
            return Err(error);
        }
        Ok(())
    }

    /// Returns response body bytes.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Returns mutable response body bytes.
    #[must_use]
    pub fn body_mut(&mut self) -> &mut Vec<u8> {
        self.body_present = true;
        self.decompression.decoded_bytes = None;
        self.decompression.expansion_ratio = None;
        &mut self.body
    }

    /// Replaces the response body with checked byte accounting.
    pub fn set_body(&mut self, body: impl Into<Vec<u8>>) -> Result<(), HttpError> {
        let body = body.into();
        let received_body = u64::try_from(body.len())
            .map_err(|_| HttpError::resource_limit("received body byte counter"))?;
        if received_body > MAX_DECOMPRESSED_RESPONSE_BYTES {
            return Err(HttpError::ResponseBodyLimit {
                actual: body.len(),
                maximum: usize::try_from(MAX_DECOMPRESSED_RESPONSE_BYTES).unwrap_or(usize::MAX),
            });
        }
        self.body = body;
        self.body_present = true;
        self.bytes.received_body = received_body;
        self.decompression.decoded_bytes = Some(received_body);
        self.refresh_decompression_ratio();
        Ok(())
    }

    /// Replaces the body after checking the bound before copying bytes.
    pub fn set_body_bounded(&mut self, body: &[u8], maximum: usize) -> Result<(), HttpError> {
        validate_response_body_limit(maximum)?;
        if body.len() > maximum {
            return Err(HttpError::ResponseBodyLimit {
                actual: body.len(),
                maximum,
            });
        }
        self.set_body(body.to_vec())
    }

    /// Marks the response body as absent. Any retained bytes are cleared.
    pub fn set_body_absent(&mut self) {
        self.body.clear();
        self.body_present = false;
        self.bytes.received_body = 0;
        self.compression = None;
        self.decompression = DecompressionObservation::default();
    }

    /// Returns whether a response body field was observed. A present empty
    /// body therefore returns `true`, while an absent body returns `false`.
    #[must_use]
    pub const fn body_present(&self) -> bool {
        self.body_present
    }

    /// Returns the body presence discriminator without inspecting body bytes.
    #[must_use]
    pub const fn body_presence(&self) -> ResponseBodyPresence {
        if self.body_present {
            ResponseBodyPresence::Present
        } else {
            ResponseBodyPresence::Absent
        }
    }

    /// Creates a response with a body after checking the bound before
    /// retaining it.
    pub fn with_bounded_body(status: u16, body: &[u8], maximum: usize) -> Result<Self, HttpError> {
        validate_status_code(status)?;
        let mut response = Self::new(status);
        response.set_body_bounded(body, maximum)?;
        Ok(response)
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
    pub fn set_bytes(&mut self, bytes: ByteAccounting) {
        self.bytes = bytes;
        if bytes.received_body != 0 {
            self.decompression.wire_bytes = Some(bytes.received_body);
        }
        if self.body_present && self.body.is_empty() && bytes.received_body == 0 {
            self.decompression.wire_bytes.get_or_insert(0);
            self.decompression.decoded_bytes.get_or_insert(0);
        }
        self.refresh_decompression_ratio();
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

    /// Returns the observed protocol version, if the adapter exposed it.
    #[must_use]
    pub const fn protocol(&self) -> Option<crate::ProtocolVersion> {
        self.protocol
    }

    /// Sets the observed protocol version.
    pub const fn set_protocol(&mut self, value: crate::ProtocolVersion) {
        self.protocol = Some(value);
    }

    /// Returns the observed entity framing, if exposed.
    #[must_use]
    pub const fn framing(&self) -> Option<crate::Framing> {
        self.framing
    }

    /// Sets the observed entity framing.
    pub const fn set_framing(&mut self, value: crate::Framing) {
        self.framing = Some(value);
    }

    /// Returns the observed content coding, if exposed.
    #[must_use]
    pub const fn compression(&self) -> Option<crate::Compression> {
        self.compression
    }

    /// Sets the observed content coding and keeps decompression metadata in
    /// sync with the response head.
    pub const fn set_compression(&mut self, value: crate::Compression) {
        self.compression = Some(value);
        self.decompression.coding = Some(value);
    }

    /// Returns body completion state.
    #[must_use]
    pub const fn body_completion(&self) -> ResponseBodyCompletion {
        self.body_completion
    }

    /// Sets body completion state after the adapter has classified its exit.
    pub const fn set_body_completion(&mut self, value: ResponseBodyCompletion) {
        self.body_completion = value;
    }

    /// Returns decompression counters and coding metadata.
    #[must_use]
    pub const fn decompression(&self) -> DecompressionObservation {
        self.decompression
    }

    /// Replaces decompression observations after checking hard limits.
    pub fn set_decompression(&mut self, value: DecompressionObservation) -> Result<(), HttpError> {
        value.validate(MAX_DECOMPRESSED_RESPONSE_BYTES, MAX_DECOMPRESSION_RATIO)?;
        self.compression = value.coding;
        self.decompression = value;
        Ok(())
    }

    /// Returns the wire entity-body byte count when known.
    #[must_use]
    pub const fn wire_body_bytes(&self) -> Option<u64> {
        self.decompression.wire_bytes
    }

    /// Returns the decoded entity-body byte count when known.
    #[must_use]
    pub const fn decoded_body_bytes(&self) -> Option<u64> {
        self.decompression.decoded_bytes
    }

    /// Returns the parsed response charset, if the content type supplied one.
    #[must_use]
    pub fn charset(&self) -> Option<&str> {
        self.checked_charset().ok().flatten()
    }

    /// Returns the parsed response charset while preserving an oversized
    /// header parameter as a typed resource error.
    pub fn checked_charset(&self) -> Result<Option<&str>, HttpError> {
        if let Some(value) = self.charset.as_deref() {
            return Ok(Some(value));
        }
        self.header_charset()
    }

    /// Sets an explicit response charset. Empty is present and distinct from
    /// an absent charset.
    pub fn set_charset(&mut self, value: Option<String>) -> Result<(), HttpError> {
        if value.as_ref().is_some_and(|value| value.len() > 256) {
            return Err(HttpError::resource_limit("response charset"));
        }
        if value
            .as_ref()
            .is_some_and(|value| value.bytes().any(|byte| byte < 0x20 || byte == 0x7f))
        {
            return Err(HttpError::InvalidHeader(
                "response charset contains a control byte".to_owned(),
            ));
        }
        self.charset = value;
        Ok(())
    }

    /// Returns the explicit JTL data type, when supplied by the adapter.
    #[must_use]
    pub fn data_type(&self) -> Option<&DataType> {
        self.data_type.as_ref()
    }

    /// Sets an explicit JTL data type.
    pub fn set_data_type(&mut self, value: Option<DataType>) {
        self.data_type = value;
    }

    /// Infers JTL text/binary type from media type and body bytes without
    /// changing the response.
    #[must_use]
    pub fn inferred_data_type(&self) -> DataType {
        if let Some(value) = &self.data_type {
            return value.clone();
        }
        let content_type = self.headers.get("content-type").unwrap_or_default();
        let media_type = content_type
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        let textual_media_type = media_type.starts_with("text/")
            || matches!(
                media_type.as_str(),
                "application/json"
                    | "application/javascript"
                    | "application/x-javascript"
                    | "application/xml"
                    | "application/xhtml+xml"
                    | "application/x-www-form-urlencoded"
            )
            || media_type.ends_with("+json")
            || media_type.ends_with("+xml");
        if textual_media_type || (media_type.is_empty() && std::str::from_utf8(&self.body).is_ok())
        {
            DataType::Text
        } else {
            DataType::Binary
        }
    }

    fn header_charset(&self) -> Result<Option<&str>, HttpError> {
        let Some(value) = self.headers.get("content-type") else {
            return Ok(None);
        };
        let parameter = value.split(';').skip(1).find_map(|part| {
            let (name, value) = part.split_once('=')?;
            if name.trim().eq_ignore_ascii_case("charset") {
                Some(value.trim().trim_matches('"'))
            } else {
                None
            }
        });
        let Some(parameter) = parameter else {
            return Ok(None);
        };
        if parameter.len() <= 256 {
            Ok(Some(parameter))
        } else {
            Err(HttpError::resource_limit("response charset"))
        }
    }

    fn refresh_decompression_ratio(&mut self) {
        self.decompression.expansion_ratio = match (
            self.decompression.wire_bytes,
            self.decompression.decoded_bytes,
        ) {
            (Some(wire), Some(decoded)) if wire > 0 => decoded
                .checked_add(wire.saturating_sub(1))
                .map(|value| value / wire),
            (Some(0), Some(0)) => Some(1),
            (Some(0), Some(_)) => None,
            _ => None,
        };
    }

    /// Projects this response into a bounded JTL sample result. The caller
    /// supplies the result label because HTTP response objects do not own a
    /// sampler identity. Timing endpoints are intentionally left absent here;
    /// [`HttpResult::to_sample_result`] adds the logical sampler's wall and
    /// monotonic timing.
    pub fn to_sample_result(
        &self,
        label: impl Into<String>,
        options: &SampleResultProjectionOptions,
    ) -> Result<SampleResult, HttpError> {
        options
            .data_limits
            .validate()
            .map_err(|_| HttpError::resource_limit("sample result data limits"))?;
        let label = label.into();
        if label.len() > MAX_SAMPLE_LABEL_BYTES {
            return Err(HttpError::resource_limit("sample result label"));
        }
        validate_response_head(self)?;
        if self.trailers.is_some() {
            // SampleResult has no trailer field. Refusing this projection is
            // deliberate: folding trailers into response headers would make
            // an extractor observe bytes that JMeter did not expose there.
            return Err(HttpError::Unsupported(
                "response trailers require an explicit result schema".to_owned(),
            ));
        }

        let mut result = SampleResult::new(label);
        result.set_response_code_text(self.status.to_string());
        if self.reason_present {
            result.set_response_message_text(self.reason.clone());
        }
        result.set_successful(
            self.body_completion == ResponseBodyCompletion::Complete && self.is_success(),
        );

        let data_type = self.inferred_data_type();
        DataType::try_from_wire_with_limits(data_type.as_wire(), options.data_limits)
            .map_err(|_| HttpError::resource_limit("response data type"))?;
        if self.body_present {
            result.set_data_type(Some(data_type.clone()));
            if let Some(charset) = self.checked_charset()? {
                let encoding = DataEncoding::try_new_with_limits(charset, options.data_limits)
                    .map_err(|_| HttpError::resource_limit("response charset"))?;
                result.set_data_encoding(Some(encoding));
            }
            if options.include_response_data {
                let maximum = if data_type.is_binary() {
                    options.data_limits.max_binary_bytes()
                } else {
                    options.data_limits.max_text_bytes()
                };
                let data = SampleData::try_from_slice(&self.body, maximum)
                    .map_err(|_| HttpError::resource_limit("response result data"))?;
                result.set_response_data(Some(data));
            }
        }

        if options.include_response_headers {
            let header_block = header_block(&self.headers, options.data_limits)?;
            result.set_response_headers(Some(header_block));
        }
        if let Some(url) = &self.url {
            result.set_url_text(url.to_string());
        }
        result.set_received_bytes(Some(ByteCount::from_u64(
            self.bytes.checked_received_total()?,
        )));
        result.set_sent_bytes(Some(ByteCount::from_u64(self.bytes.checked_sent_total()?)));

        let timing = SampleTiming::from_wire_parts(
            None,
            None,
            None,
            optional_elapsed(self.timing.elapsed)?,
            optional_latency(self.timing.latency)?,
            optional_connect(self.timing.connect)?,
            None,
        );
        result.set_timing_from_wire(timing);
        if self.body_completion != ResponseBodyCompletion::Complete {
            result.set_failure_message(Some("response body did not complete".to_owned()));
        }
        Ok(result)
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
        // All wire counters belong to the revalidation attempt. The cached
        // entity is materialized for the caller but its original transfer
        // must not be charged to this sampler (in particular, a 304 carries
        // no response body bytes).
        merged.bytes = not_modified.bytes;
        merged.timing = not_modified.timing;
        merged.from_cache = true;
        // 1xx heads belong to the wire attempt that produced the selected
        // representation.  Keep the revalidation attempt's ordered heads so
        // an attempt observer does not lose them during the 304 merge.
        merged.informational_responses = not_modified.informational_responses.clone();
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
    redirect_responses: Option<Box<[Response]>>,
    request_context: Option<RequestContext>,
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
            redirect_responses: None,
            request_context: None,
            bytes,
            elapsed,
            started_at_wall_millis,
            ended_at_wall_millis,
        }
    }

    /// Creates a logical result with its ordered redirect responses already
    /// retained. The history is validated before this result is returned.
    pub fn new_with_redirect_responses(
        response: Response,
        redirects: usize,
        redirect_responses: Vec<Response>,
        bytes: ByteAccounting,
        elapsed: Duration,
        started_at_wall_millis: i64,
        ended_at_wall_millis: i64,
    ) -> Result<Self, HttpError> {
        Self::new(
            response,
            redirects,
            bytes,
            elapsed,
            started_at_wall_millis,
            ended_at_wall_millis,
        )
        .with_redirect_responses(redirect_responses)
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

    /// Returns retained redirect responses in wire order. A `None` history is
    /// distinct from an empty history: callers must not infer sub-results from
    /// the redirect count alone.
    #[must_use]
    pub fn redirect_responses(&self) -> Option<&[Response]> {
        self.redirect_responses.as_deref()
    }

    /// Attaches the bounded redirect response history required for complete
    /// JTL sub-result projection.
    pub fn with_redirect_responses(mut self, responses: Vec<Response>) -> Result<Self, HttpError> {
        if responses.len() != self.redirects {
            return Err(HttpError::InvalidRedirect(
                "redirect response history does not match redirect count".to_owned(),
            ));
        }
        if responses.len() > MAX_REDIRECT_HISTORY {
            return Err(HttpError::resource_limit("redirect response history"));
        }
        let mut retained = 0usize;
        for response in &responses {
            retained = retained
                .checked_add(response_retained_bytes(response)?)
                .ok_or_else(|| HttpError::resource_limit("redirect response history"))?;
            if retained > MAX_REDIRECT_HISTORY_BYTES {
                return Err(HttpError::resource_limit("redirect response history bytes"));
            }
        }
        self.redirect_responses = Some(responses.into_boxed_slice());
        Ok(self)
    }

    /// Attaches the prepared request context used by request-header,
    /// sampler-data, and request-entity result fields.
    pub fn with_request_context(mut self, request: &crate::Request) -> Result<Self, HttpError> {
        self.request_context = Some(RequestContext::from_request(request)?);
        Ok(self)
    }

    /// Attaches one already-owned request context without copying its bounded
    /// headers or entity. The client uses this exactly once after its inner
    /// execution path has produced a successful logical result.
    pub(crate) fn with_request_context_owned(
        mut self,
        context: RequestContext,
    ) -> Result<Self, HttpError> {
        if self.request_context.is_some() {
            return Err(HttpError::resource_limit(
                "request context already attached",
            ));
        }
        self.request_context = Some(context);
        Ok(self)
    }

    /// Returns the request context retained for result projection.
    #[must_use]
    pub const fn request_context(&self) -> Option<&RequestContext> {
        self.request_context.as_ref()
    }

    /// Projects the logical sampler and all retained redirect attempts into a
    /// bounded JTL result hierarchy.
    pub fn to_sample_result(
        &self,
        label: impl Into<String>,
        options: &SampleResultProjectionOptions,
    ) -> Result<SampleResult, HttpError> {
        if self.redirects > MAX_REDIRECT_HISTORY {
            return Err(HttpError::resource_limit("redirect response history"));
        }
        if self.redirects != 0 && self.redirect_responses.is_none() {
            return Err(HttpError::Unsupported(
                "redirect response history is required for result projection".to_owned(),
            ));
        }
        let label = label.into();
        if label.len() > MAX_SAMPLE_LABEL_BYTES {
            return Err(HttpError::resource_limit("sample result label"));
        }
        let mut result = self.response.to_sample_result(label.clone(), options)?;
        let elapsed = ElapsedTime::try_from_duration(self.elapsed)
            .map_err(|_| HttpError::resource_limit("sample result elapsed time"))?;
        let timing = SampleTiming::from_wire_parts(
            Some(WallTimestamp::from_millis(
                self.timestamp(options.timestamp_source),
            )),
            Some(WallTimestamp::from_millis(self.started_at_wall_millis)),
            Some(WallTimestamp::from_millis(self.ended_at_wall_millis)),
            Some(elapsed),
            optional_latency(self.response.timing.latency)?,
            optional_connect(self.response.timing.connect)?,
            None,
        );
        result.set_timing_from_wire(timing);
        result.set_received_bytes(Some(ByteCount::from_u64(
            self.bytes.checked_received_total()?,
        )));
        result.set_sent_bytes(Some(ByteCount::from_u64(self.bytes.checked_sent_total()?)));

        if options.include_request_metadata
            && let Some(request) = &self.request_context
        {
            let request_headers = header_block(&request.headers, options.data_limits)?;
            result.set_request_headers(Some(request_headers));
            result.set_sampler_data_text(request.sampler_data());
            if let Some(body) = request.body() {
                let data = SampleData::try_from_slice(body, options.data_limits.max_binary_bytes())
                    .map_err(|_| HttpError::resource_limit("request result data"))?;
                result.set_request_data(Some(data));
            }
        }

        // Child order is transport/wire order.  The `#redirect-N` spelling is
        // deterministic but remains provisional until the pinned JMeter
        // oracle establishes its exact sub-result label-rewrite policy.
        if let Some(responses) = &self.redirect_responses {
            for (index, response) in responses.iter().enumerate() {
                let child_label = format!("{label}#redirect-{}", index.saturating_add(1));
                let child = response.to_sample_result(child_label, options)?;
                result
                    .try_add_sub_result_raw(child, ValidationLimits::default())
                    .map_err(|_| HttpError::resource_limit("response result sub-results"))?;
            }
        }
        Ok(result)
    }

    fn timestamp(&self, source: TimestampSource) -> i64 {
        match source {
            TimestampSource::Start => self.started_at_wall_millis,
            TimestampSource::End => self.ended_at_wall_millis,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "tests use expect at assertion boundaries for fixed byte fixtures"
    )]

    use super::*;

    fn fixture_response(body: &[u8]) -> Response {
        let mut response = Response::with_bounded_body(200, body, 1024).expect("bounded body");
        response
            .add_header("Content-Type", "application/json; charset=UTF-8")
            .expect("content type");
        response
            .add_header("X-Duplicate", "one")
            .expect("duplicate header");
        response
            .add_header("X-Duplicate", "two")
            .expect("duplicate header");
        response.set_reason("OK");
        response
    }

    #[test]
    fn body_presence_distinguishes_absent_from_present_empty() {
        let absent = Response::new(204);
        assert!(!absent.body_present());
        assert!(absent.body().is_empty());

        let mut absent_with_counters = Response::new(204);
        absent_with_counters.set_bytes(ByteAccounting::default());
        assert_eq!(
            absent_with_counters.decompression(),
            DecompressionObservation::default()
        );
        absent_with_counters.set_bytes(ByteAccounting::new(0, 0, 0, 1));
        assert!(
            absent_with_counters
                .to_sample_result("counted-absent", &SampleResultProjectionOptions::default())
                .is_err()
        );

        let present = Response::with_body(204, Vec::<u8>::new()).expect("empty body");
        assert!(present.body_present());
        assert_eq!(present.decoded_body_bytes(), Some(0));
    }

    #[test]
    fn no_entity_statuses_and_head_projection_keep_absence_explicit() {
        for status in [204, 304] {
            let absent = Response::new(status);
            assert!(!absent.body_present());
            let projected = absent
                .to_sample_result(
                    status.to_string(),
                    &SampleResultProjectionOptions::default(),
                )
                .expect("absent response projection");
            assert_eq!(projected.response_data(), None);

            let present = Response::with_body(status, Vec::<u8>::new()).expect("empty body");
            assert!(present.body_present());
            let projected = present
                .to_sample_result(
                    format!("{status}-empty"),
                    &SampleResultProjectionOptions::default(),
                )
                .expect("present-empty response projection");
            assert_eq!(
                projected.response_data().map(SampleData::as_bytes),
                Some([].as_slice())
            );
        }
    }

    #[test]
    fn reason_presence_preserves_absent_and_present_empty_in_jtl() {
        let absent = Response::new(204);
        assert!(!absent.reason_present());
        let absent_result = absent
            .to_sample_result("absent-reason", &SampleResultProjectionOptions::default())
            .expect("absent reason projection");
        assert_eq!(absent_result.response_message(), None);

        let mut present_empty = Response::new(204);
        present_empty.set_reason("");
        assert!(present_empty.reason_present());
        let present_result = present_empty
            .to_sample_result(
                "present-empty-reason",
                &SampleResultProjectionOptions::default(),
            )
            .expect("present empty reason projection");
        assert_eq!(present_result.response_message(), Some(""));
    }

    #[test]
    fn informational_heads_are_ordered_bounded_and_retained_for_projection() {
        let mut first = ResponseHeadObservation::new(103).expect("1xx status");
        first
            .set_reason_present("Early Hints")
            .expect("reason phrase");
        first
            .add_header("Link", "</style.css>; rel=preload")
            .expect("informational header");
        let second = ResponseHeadObservation::new(100).expect("1xx status");

        let mut response = Response::with_body(200, b"ok".to_vec()).expect("body");
        response
            .add_informational_response(first)
            .expect("first informational response");
        response
            .add_informational_response(second)
            .expect("second informational response");
        assert_eq!(
            response
                .informational_responses()
                .iter()
                .map(|head| head.status)
                .collect::<Vec<_>>(),
            [103, 100]
        );

        let projected = response
            .to_sample_result("with-info", &SampleResultProjectionOptions::default())
            .expect("final response projection");
        assert_eq!(projected.response_code(), Some("200"));
        assert_eq!(
            projected.response_data().map(SampleData::as_bytes),
            Some(b"ok".as_slice())
        );

        let mut bounded = TransportResponseObservation::default();
        for status in 0..crate::MAX_INFORMATIONAL_RESPONSES {
            bounded
                .push_informational_response(
                    ResponseHeadObservation::new(100 + (status as u16 % 100))
                        .expect("bounded 1xx status"),
                )
                .expect("head within count bound");
        }
        assert_eq!(
            bounded.informational_responses().len(),
            crate::MAX_INFORMATIONAL_RESPONSES
        );
        assert!(
            bounded
                .push_informational_response(ResponseHeadObservation::new(103).expect("1xx status"))
                .is_err()
        );
        assert_eq!(
            bounded.informational_responses().len(),
            crate::MAX_INFORMATIONAL_RESPONSES
        );
    }

    #[test]
    fn informational_byte_limit_rejects_atomically() {
        let reason = "r".repeat(MAX_RESPONSE_REASON_BYTES);
        let header_value = "h".repeat(4 * 1024);
        let mut bounded = TransportResponseObservation::default();
        for _ in 0..31 {
            let mut head = ResponseHeadObservation::new(103).expect("1xx status");
            head.set_reason_present(reason.clone())
                .expect("reason phrase");
            head.add_header("X-Bounded", header_value.clone())
                .expect("header value");
            bounded
                .push_informational_response(head)
                .expect("aggregate bytes below bound");
        }
        let before = bounded.informational_responses().len();
        let mut overflow = ResponseHeadObservation::new(103).expect("1xx status");
        overflow.set_reason_present(reason).expect("reason phrase");
        overflow
            .add_header("X-Bounded", header_value)
            .expect("header value");
        assert!(bounded.push_informational_response(overflow).is_err());
        assert_eq!(bounded.informational_responses().len(), before);
    }

    #[test]
    fn bounded_body_accepts_exact_product_ceiling_without_large_allocation() {
        let mut response = Response::new(200);
        response
            .set_body_bounded(b"tiny", crate::HARD_MAX_RESPONSE_BODY_BYTES)
            .expect("exact hard bound is valid");
        assert_eq!(response.body(), b"tiny");

        let mut rejected = Response::new(200);
        assert!(
            rejected
                .set_body_bounded(b"tiny", crate::HARD_MAX_RESPONSE_BODY_BYTES + 1)
                .is_err()
        );
        assert!(!rejected.body_present());
    }

    #[test]
    fn trailers_are_ordered_bounded_and_not_response_headers() {
        let mut response = Response::with_body(200, b"ok".to_vec()).expect("body");
        response.add_trailer("Checksum", "abc").expect("trailer");
        response
            .add_trailer("Checksum", "def")
            .expect("duplicate trailer");
        let trailers = response.trailers().expect("present trailers");
        assert_eq!(trailers.len(), 2);
        assert_eq!(
            trailers.values("checksum").collect::<Vec<_>>(),
            ["abc", "def"]
        );
        assert!(!response.headers().contains("checksum"));

        let mut oversized = Headers::new();
        for index in 0..=MAX_RESPONSE_TRAILERS {
            oversized
                .insert(format!("X-{index}"), "v")
                .expect("valid trailer");
        }
        assert!(Response::new(200).set_trailers(Some(oversized)).is_err());

        let mut atomic = Response::new(200);
        let mut near_limit = Headers::new();
        for index in 0..MAX_RESPONSE_TRAILERS {
            near_limit
                .insert(format!("Y-{index}"), "v")
                .expect("valid trailer");
        }
        atomic
            .set_trailers(Some(near_limit))
            .expect("near-limit trailers");
        let before = atomic.trailers().cloned();
        assert!(atomic.add_trailer("overflow", "v").is_err());
        assert_eq!(atomic.trailers(), before.as_ref());
    }

    #[test]
    fn charset_and_data_type_are_inferred_from_byte_fixture() {
        let response = fixture_response(br#"{"ok":true}"#);
        assert_eq!(response.charset(), Some("UTF-8"));
        assert_eq!(response.inferred_data_type(), DataType::Text);

        let mut binary = Response::with_body(200, vec![0, 0xff, 1]).expect("binary");
        binary
            .add_header("Content-Type", "image/png")
            .expect("type");
        assert_eq!(binary.inferred_data_type(), DataType::Binary);
        assert_eq!(binary.charset(), None);
    }

    #[test]
    fn projection_rejects_oversized_charset_and_invalid_reason_metadata() {
        let mut charset = Response::with_body(200, b"body".to_vec()).expect("body");
        charset
            .add_header(
                "Content-Type",
                format!("text/plain; charset={}", "x".repeat(257)),
            )
            .expect("content type");
        assert!(
            charset
                .to_sample_result("http", &SampleResultProjectionOptions::default())
                .is_err()
        );

        let mut reason = Response::with_body(200, b"body".to_vec()).expect("body");
        reason.set_reason("bad\nreason");
        assert!(
            reason
                .to_sample_result("http", &SampleResultProjectionOptions::default())
                .is_err()
        );
    }

    #[test]
    fn decompression_observation_checks_expansion_before_projection() {
        let observation = DecompressionObservation {
            coding: Some(crate::Compression::Gzip),
            wire_bytes: Some(10),
            decoded_bytes: Some(10_001),
            expansion_ratio: None,
        };
        assert!(observation.validate(512 * 1024 * 1024, 1_000).is_err());
        assert!(
            DecompressionObservation {
                coding: Some(crate::Compression::Gzip),
                wire_bytes: Some(4),
                decoded_bytes: None,
                expansion_ratio: Some(1),
            }
            .validate(512 * 1024 * 1024, 1_000)
            .is_err()
        );

        let mut bomb = Response::with_body(200, vec![0; 1_001]).expect("body");
        bomb.set_bytes(ByteAccounting::new(0, 0, 0, 1));
        assert!(
            bomb.to_sample_result("http", &SampleResultProjectionOptions::default())
                .is_err()
        );

        let mut response = Response::with_body(200, b"decoded".to_vec()).expect("body");
        response
            .set_decompression(DecompressionObservation {
                coding: Some(crate::Compression::Gzip),
                wire_bytes: Some(4),
                decoded_bytes: Some(7),
                expansion_ratio: Some(2),
            })
            .expect("bounded decompression");
        assert_eq!(response.compression(), Some(crate::Compression::Gzip));
        assert_eq!(response.wire_body_bytes(), Some(4));
        assert_eq!(response.decoded_body_bytes(), Some(7));
    }

    #[test]
    fn decompression_observation_accepts_exact_hard_bounds_without_large_allocation() {
        let exact_decoded = DecompressionObservation {
            coding: Some(crate::Compression::Gzip),
            wire_bytes: None,
            decoded_bytes: Some(crate::HARD_MAX_DECOMPRESSED_BYTES as u64),
            expansion_ratio: None,
        };
        assert!(
            exact_decoded
                .validate(
                    crate::HARD_MAX_DECOMPRESSED_BYTES as u64,
                    crate::HARD_MAX_DECOMPRESSION_RATIO,
                )
                .is_ok()
        );
        assert!(
            DecompressionObservation {
                decoded_bytes: Some(crate::HARD_MAX_DECOMPRESSED_BYTES as u64 + 1),
                ..exact_decoded
            }
            .validate(
                crate::HARD_MAX_DECOMPRESSED_BYTES as u64,
                crate::HARD_MAX_DECOMPRESSION_RATIO,
            )
            .is_err()
        );
        assert!(
            exact_decoded
                .validate(
                    crate::HARD_MAX_DECOMPRESSED_BYTES as u64 + 1,
                    crate::HARD_MAX_DECOMPRESSION_RATIO,
                )
                .is_err()
        );

        let exact_ratio = DecompressionObservation {
            coding: Some(crate::Compression::Gzip),
            wire_bytes: Some(1_000),
            decoded_bytes: Some(1_000_000),
            expansion_ratio: Some(crate::HARD_MAX_DECOMPRESSION_RATIO),
        };
        assert!(
            exact_ratio
                .validate(
                    crate::HARD_MAX_DECOMPRESSED_BYTES as u64,
                    crate::HARD_MAX_DECOMPRESSION_RATIO,
                )
                .is_ok()
        );
        assert!(
            exact_ratio
                .validate(
                    crate::HARD_MAX_DECOMPRESSED_BYTES as u64,
                    crate::HARD_MAX_DECOMPRESSION_RATIO + 1,
                )
                .is_err()
        );
        assert!(
            DecompressionObservation {
                wire_bytes: Some(1),
                decoded_bytes: Some(crate::HARD_MAX_DECOMPRESSION_RATIO + 1),
                expansion_ratio: Some(crate::HARD_MAX_DECOMPRESSION_RATIO + 1),
                ..exact_ratio
            }
            .validate(
                crate::HARD_MAX_DECOMPRESSED_BYTES as u64,
                crate::HARD_MAX_DECOMPRESSION_RATIO,
            )
            .is_err()
        );
    }

    #[test]
    fn sample_projection_preserves_byte_fixture_metadata_and_presence() {
        let mut response = fixture_response(br#"{"ok":true}"#);
        response.set_bytes(ByteAccounting::new(12, 7, 54, 12));
        response.set_timing(ResponseTiming {
            connect: Some(Duration::from_millis(3)),
            tls: None,
            latency: Some(Duration::from_millis(5)),
            elapsed: Some(Duration::from_millis(11)),
        });
        let result = response
            .to_sample_result("http", &SampleResultProjectionOptions::default())
            .expect("sample result");
        assert_eq!(result.response_code(), Some("200"));
        assert_eq!(result.response_message(), Some("OK"));
        assert_eq!(result.success(), Some(true));
        assert_eq!(
            result.response_data().map(SampleData::as_bytes),
            Some(br#"{"ok":true}"#.as_slice())
        );
        assert_eq!(
            result.response_headers().map(HeaderBlock::as_str),
            Some(
                "Content-Type: application/json; charset=UTF-8\r\nX-Duplicate: one\r\nX-Duplicate: two\r\n"
            )
        );
        assert_eq!(result.data_type(), Some(&DataType::Text));
        assert_eq!(
            result.data_encoding().map(DataEncoding::as_str),
            Some("UTF-8")
        );
        assert_eq!(result.received_bytes(), Some(ByteCount::from_u64(66)));
        assert_eq!(result.sent_bytes(), Some(ByteCount::from_u64(19)));
        assert_eq!(result.latency(), Some(Latency::from_millis(5)));
        assert_eq!(result.connect_time(), Some(ConnectTime::from_millis(3)));
    }

    #[test]
    fn logical_projection_requires_redirect_history_and_adds_subresults() {
        let final_response = fixture_response(b"final");
        let redirect = fixture_response(b"redirect");
        let result = HttpResult::new(
            final_response,
            1,
            ByteAccounting::new(2, 3, 4, 5),
            Duration::from_millis(20),
            1_700_000_000_000,
            1_700_000_000_020,
        );
        assert!(
            result
                .to_sample_result("http", &SampleResultProjectionOptions::default())
                .is_err()
        );
        let result = result
            .with_redirect_responses(vec![redirect])
            .expect("history");
        let projected = result
            .to_sample_result("http", &SampleResultProjectionOptions::default())
            .expect("projected hierarchy");
        assert_eq!(projected.sub_results().len(), 1);
        assert_eq!(projected.sub_results()[0].label(), "http#redirect-1");
        assert_eq!(
            projected.timestamp(),
            Some(WallTimestamp::from_millis(1_700_000_000_000))
        );
        assert_eq!(projected.elapsed(), Some(ElapsedTime::from_millis(20)));
    }

    #[test]
    fn not_modified_merge_charges_only_revalidation_wire_bytes() {
        let mut cached = fixture_response(b"cached");
        cached.set_bytes(ByteAccounting::new(19, 7, 42, 7));
        let mut not_modified = Response::new(304);
        not_modified
            .add_header("Cache-Control", "max-age=30")
            .expect("cache header");
        not_modified.set_bytes(ByteAccounting::new(31, 0, 17, 0));

        let merged = Response::merge_not_modified(&cached, &not_modified);
        assert_eq!(merged.body(), b"cached");
        assert!(merged.from_cache());
        assert_eq!(merged.bytes(), not_modified.bytes());
        assert_eq!(merged.bytes().received_body, 0);
    }

    #[test]
    fn request_context_projects_headers_sampler_data_and_present_empty_body() {
        let mut request =
            crate::Request::post("http://example.test/submit", Vec::<u8>::new()).expect("request");
        request
            .add_header("X-Request", "one")
            .expect("request header");
        request
            .add_header("X-Request", "two")
            .expect("duplicate request header");
        let result = HttpResult::new(
            fixture_response(b"ok"),
            0,
            ByteAccounting::new(3, 0, 5, 2),
            Duration::from_millis(2),
            10,
            12,
        )
        .with_request_context(&request)
        .expect("request context")
        .to_sample_result("http", &SampleResultProjectionOptions::default())
        .expect("projection");
        assert_eq!(
            result.request_headers().map(HeaderBlock::as_str),
            Some("X-Request: one\r\nX-Request: two\r\n")
        );
        assert_eq!(
            result.sampler_data(),
            Some("POST http://example.test/submit")
        );
        assert_eq!(
            result.request_data().map(SampleData::as_bytes),
            Some([].as_slice())
        );
        let context = RequestContext::from_request(&request).expect("context");
        let debug = format!("{context:?}");
        assert!(!debug.contains("example.test"));
    }

    #[test]
    fn redirect_history_rejects_oversized_retention_before_storing() {
        let result = HttpResult::new(
            fixture_response(b"final"),
            MAX_REDIRECT_HISTORY.saturating_add(1),
            ByteAccounting::default(),
            Duration::ZERO,
            0,
            0,
        );
        let responses = (0..=MAX_REDIRECT_HISTORY)
            .map(|_| fixture_response(b"redirect"))
            .collect();
        assert!(result.with_redirect_responses(responses).is_err());
    }

    #[test]
    fn trailers_fail_projection_instead_of_being_folded_into_headers() {
        let mut response = fixture_response(b"body");
        response.add_trailer("X-Trailer", "value").expect("trailer");
        let error = response
            .to_sample_result("http", &SampleResultProjectionOptions::default())
            .expect_err("trailer projection must be explicit");
        assert_eq!(error.stable_code(), "http.unsupported");
    }
}
