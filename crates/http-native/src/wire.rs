// SPDX-License-Identifier: Apache-2.0
//! Bounded HTTP/1 wire framing for the native transport.
//!
//! This module deliberately deals in complete byte slices.  Socket reads,
//! connection reuse, TLS, and cancellation belong to the transport adapter;
//! this codec only validates one request or one response and materialises the
//! bounded entity bytes.  It is kept separate from the semantic HTTP core so
//! that no socket, executor, or ambient policy can enter the parser.

use std::str;

use jmeter_rs_http::{
    Framing, Header, Headers, Method, ProtocolVersion, Request, ResponseBodyPresence,
    ResponseHeadObservation, ResponsePresence, TransportError,
};

use crate::config::{
    HARD_MAX_AUTHORITY_BYTES, HARD_MAX_REQUEST_TARGET_BYTES, NativeTransportLimits,
};

/// A fully framed HTTP/1.1 origin-form request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EncodedRequest {
    /// Request-line, fields, separator, and entity bytes in wire order.
    pub(crate) bytes: Vec<u8>,
    /// Number of bytes through the empty line after the request fields.
    pub(crate) head_bytes: u64,
    /// Number of entity bytes emitted after the request head.
    pub(crate) body_bytes: u64,
}

/// A decoded HTTP/1 response, retaining the final response's ordered fields
/// and the presence observations made while parsing the wire syntax.
///
/// Presence is recorded here, at the status-line/framing boundary.  The
/// transport response collector must not reconstruct it from an empty string,
/// an empty body, or byte counters because all of those values are ambiguous.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DecodedResponse {
    pub(crate) status: u16,
    pub(crate) reason: String,
    pub(crate) reason_presence: ResponsePresence<String>,
    pub(crate) headers: Headers,
    pub(crate) body: Vec<u8>,
    pub(crate) body_presence: ResponseBodyPresence,
    pub(crate) informational_responses: Vec<ResponseHeadObservation>,
    /// Wire bytes occupied by every informational and final response head.
    pub(crate) received_head_bytes: u64,
    /// Entity bytes exposed after framing (chunk metadata is not included).
    pub(crate) received_body_bytes: u64,
    pub(crate) protocol: ProtocolVersion,
    pub(crate) framing: Framing,
}

type ParsedHead = (
    ProtocolVersion,
    u16,
    String,
    ResponsePresence<String>,
    Headers,
    usize,
);

/// Result of incrementally inspecting a response prefix.
///
/// `Complete` carries the exact number of bytes occupied by one response
/// message.  Bytes after that offset are not part of the response and are
/// rejected by the non-pipelining transport.  A close-delimited response is
/// deliberately `Incomplete` until the caller reports EOF.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResponseCompletion {
    /// More bytes are required to prove the response boundary.
    Incomplete,
    /// One complete response occupies `wire_len` bytes of the supplied
    /// prefix and uses the reported entity framing.
    Complete { wire_len: usize, framing: Framing },
}

/// Incrementally validates a bounded HTTP/1 response prefix.
///
/// The parser and resource checks are shared with [`decode_response`].  The
/// `eof` flag is meaningful only for close-delimited messages (and for
/// turning an otherwise partial fixed/chunked message into a protocol error):
/// framing with an explicit length completes before EOF, while a response
/// without either `Content-Length` or `Transfer-Encoding` completes only when
/// the peer closes the stream.
pub(crate) fn scan_response_completion(
    bytes: &[u8],
    method: &Method,
    limits: &NativeTransportLimits,
    eof: bool,
) -> Result<ResponseCompletion, TransportError> {
    validate_limits(limits)?;
    let wire_limit = limit_usize(limits.max_response_total_bytes, "wire response bytes")?;
    if bytes.len() > wire_limit {
        return Err(resource_limit("wire response bytes"));
    }

    let mut cursor = 0usize;
    let mut head_bytes = 0usize;
    let mut informational_count = 0usize;
    let informational_limit = limit_usize(
        limits.max_informational_count,
        "informational response count",
    )?;
    let informational_bytes_limit = limit_usize(
        limits.max_informational_bytes,
        "informational response bytes",
    )?;
    let response_head_limit = limit_usize(limits.max_response_head_bytes, "response head bytes")?;
    let head_limits = HeadLimits::from_native(limits)?;

    let (status, headers) = loop {
        let before = cursor;
        let (_, status, _, _, headers, head_len) =
            match parse_head_for_scan(bytes, &mut cursor, &head_limits, eof) {
                Ok(head) => head,
                Err(ScanFailure::Incomplete) => {
                    return Ok(ResponseCompletion::Incomplete);
                }
                Err(ScanFailure::Error(error)) => return Err(error),
            };
        head_bytes = head_bytes
            .checked_add(head_len)
            .ok_or_else(|| resource_limit("response head bytes"))?;
        if head_len > response_head_limit {
            return Err(resource_limit("response head bytes"));
        }
        if status < 200 {
            informational_count = informational_count
                .checked_add(1)
                .ok_or_else(|| resource_limit("informational response count"))?;
            if informational_count > informational_limit {
                return Err(resource_limit("informational response count"));
            }
            if head_bytes > informational_bytes_limit {
                return Err(resource_limit("informational response bytes"));
            }
            if headers.contains("transfer-encoding") {
                return Err(unsupported("informational Transfer-Encoding"));
            }
            // A 1xx response has no content or trailers, and RFC 9110
            // forbids Content-Length on every informational response.  The
            // 101 upgrade case was rejected while parsing its status line;
            // no other 1xx may be treated as a body-bearing response.
            if headers.contains("content-length") {
                return Err(protocol_error(
                    "Content-Length is forbidden on informational response",
                ));
            }
            if cursor == before {
                return Err(protocol_error("response parser made no progress"));
            }
            continue;
        }
        break (status, headers);
    };

    validate_content_length_headers(&headers)?;
    let content_length = parse_single_content_length(&headers)?;
    let transfer_encoding = parse_response_transfer_encoding(&headers)?;
    if transfer_encoding.is_some() && content_length.is_some() {
        return Err(protocol_error(
            "Transfer-Encoding and Content-Length conflict",
        ));
    }
    let no_body = matches!(method, Method::Head)
        || status == 204
        || status == 304
        || (100..200).contains(&status);
    if no_body {
        // RFC 9110 forbids Content-Length on 204 responses.  HEAD and 304
        // responses are different: their Content-Length, when present, is
        // metadata for the representation that would have been sent, so it
        // does not describe bytes in this response and must not be checked
        // against the retained entity limit.
        if status == 204 && content_length.is_some() {
            return Err(protocol_error("Content-Length is forbidden on 204"));
        }
        if transfer_encoding.is_some() {
            return Err(unsupported("Transfer-Encoding on a no-body response"));
        }
        return Ok(ResponseCompletion::Complete {
            wire_len: cursor,
            framing: Framing::NoBody,
        });
    }

    let body_limit = limit_usize(limits.max_response_body_bytes, "response body bytes")?;
    if content_length
        .is_some_and(|length| usize::try_from(length).map_or(true, |value| value > body_limit))
    {
        return Err(resource_limit("response body bytes"));
    }

    if transfer_encoding.is_some() {
        match consume_chunked(bytes, &mut cursor, body_limit, limits, eof, false) {
            Ok(_) => {}
            Err(ScanFailure::Incomplete) => return Ok(ResponseCompletion::Incomplete),
            Err(ScanFailure::Error(error)) => return Err(error),
        }
        return Ok(ResponseCompletion::Complete {
            wire_len: cursor,
            framing: Framing::Chunked,
        });
    }

    if let Some(content_length) = content_length {
        let body_len = usize_from_u64(content_length, "Content-Length")?;
        if body_len > body_limit {
            return Err(resource_limit("response body bytes"));
        }
        let end = cursor
            .checked_add(body_len)
            .ok_or_else(|| resource_limit("response body arithmetic"))?;
        if end > bytes.len() {
            return if eof {
                Err(protocol_error("Content-Length exceeds received bytes"))
            } else {
                Ok(ResponseCompletion::Incomplete)
            };
        }
        return Ok(ResponseCompletion::Complete {
            wire_len: end,
            framing: Framing::ContentLength,
        });
    }

    let close_body_len = bytes
        .len()
        .checked_sub(cursor)
        .ok_or_else(|| resource_limit("close-delimited response arithmetic"))?;
    if close_body_len > body_limit {
        // Close-delimited framing has no boundary until EOF, but the active
        // entity limit still applies to every incremental scan.  Waiting for
        // EOF would allow an over-limit peer to consume the full wire bound
        // before the parser noticed.
        return Err(resource_limit("close-delimited response body"));
    }
    if eof {
        Ok(ResponseCompletion::Complete {
            wire_len: bytes.len(),
            framing: Framing::CloseDelimited,
        })
    } else {
        Ok(ResponseCompletion::Incomplete)
    }
}

/// Head limits are kept as one parser input so the scanner and decoder use
/// exactly the same active values and validation order.
#[derive(Clone, Copy, Debug)]
struct HeadLimits {
    status_line: usize,
    reason: usize,
    line: usize,
    header_count: usize,
    header_bytes: usize,
    name: usize,
    value: usize,
}

impl HeadLimits {
    fn from_native(limits: &NativeTransportLimits) -> Result<Self, TransportError> {
        let line = limit_usize(limits.max_line_bytes, "line bytes")?;
        Ok(Self {
            status_line: limit_usize(limits.max_status_line_bytes, "status line bytes")?,
            reason: limit_usize(limits.max_reason_bytes, "reason bytes")?,
            line,
            header_count: limit_usize(limits.max_header_count, "response header count")?,
            header_bytes: limit_usize(limits.max_header_aggregate_bytes, "response header bytes")?,
            name: limit_usize(limits.max_header_name_bytes, "header name bytes")?,
            value: limit_usize(limits.max_header_value_bytes, "header value bytes")?,
        })
    }
}

#[derive(Debug)]
enum ScanFailure {
    Incomplete,
    Error(TransportError),
}

impl From<TransportError> for ScanFailure {
    fn from(error: TransportError) -> Self {
        Self::Error(error)
    }
}

impl From<ScanFailure> for TransportError {
    fn from(failure: ScanFailure) -> Self {
        match failure {
            ScanFailure::Incomplete => protocol_error("response is incomplete"),
            ScanFailure::Error(error) => error,
        }
    }
}

fn parse_head_for_scan(
    bytes: &[u8],
    cursor: &mut usize,
    limits: &HeadLimits,
    eof: bool,
) -> Result<ParsedHead, ScanFailure> {
    match parse_head(
        bytes,
        cursor,
        limits.status_line,
        limits.reason,
        limits.line,
        limits.header_count,
        limits.header_bytes,
        limits.name,
        limits.value,
    ) {
        Ok(head) => Ok(head),
        Err(error) if !eof && is_incomplete_line_error(&error) => Err(ScanFailure::Incomplete),
        Err(error) => Err(ScanFailure::Error(error)),
    }
}

fn is_incomplete_line_error(error: &TransportError) -> bool {
    matches!(
        error,
        TransportError::Protocol(message) if message == "response line is not CRLF terminated"
    )
}

/// Encodes one origin-form HTTP/1.1 request.
///
/// Existing field order and duplicate fields are preserved.  A Host field is
/// appended exactly once when absent; Content-Length is appended only for a
/// present entity when the caller did not supply it.  Transfer-Encoding is
/// intentionally unsupported by this first native capability.
pub(crate) fn encode_request(
    request: &Request,
    limits: &NativeTransportLimits,
) -> Result<EncodedRequest, TransportError> {
    validate_limits(limits)?;

    let method = request.method().as_str();
    if method.is_empty() || method.len() > HARD_METHOD_BYTES || !is_token(method.as_bytes()) {
        return Err(invalid_request("invalid method token"));
    }
    let target = request.wire_target();
    let target_limit = limits
        .max_request_head_bytes
        .min(HARD_MAX_REQUEST_TARGET_BYTES);
    if target.is_empty()
        || !target.starts_with('/')
        || target.len() > target_limit
        || contains_forbidden_control(target.as_bytes())
    {
        return Err(invalid_request("request target is not bounded origin-form"));
    }

    let body = request.body().as_bytes();
    let body_limit = limit_usize(limits.max_request_body_bytes, "request body limit")?;
    if body.len() > body_limit {
        return Err(resource_limit("request body"));
    }
    if !request.method().allows_body() && !body.is_empty() {
        return Err(invalid_request("method cannot carry a non-empty entity"));
    }

    let mut host_count = 0usize;
    let mut content_lengths = Vec::new();
    let mut transfer_encoding = false;
    let mut header_fields = 0usize;
    let mut supplied_header_bytes = 0usize;
    let header_field_limit = limit_usize(limits.max_header_count, "request header count")?;
    let header_bytes_limit =
        limit_usize(limits.max_header_aggregate_bytes, "request header bytes")?;
    let name_limit = limit_usize(limits.max_header_name_bytes, "header name bytes")?;
    let value_limit = limit_usize(limits.max_header_value_bytes, "header value bytes")?;

    for field in request.headers().iter() {
        validate_field(field, name_limit, value_limit)?;
        header_fields = header_fields
            .checked_add(1)
            .ok_or_else(|| resource_limit("request header count"))?;
        let encoded = field_wire_len(field)?;
        supplied_header_bytes = supplied_header_bytes
            .checked_add(encoded)
            .ok_or_else(|| resource_limit("request header bytes"))?;
        if header_fields > header_field_limit || supplied_header_bytes > header_bytes_limit {
            return Err(resource_limit("request headers"));
        }
        if field.name().eq_ignore_ascii_case("host") {
            host_count = host_count
                .checked_add(1)
                .ok_or_else(|| resource_limit("host fields"))?;
            if host_count > 1 {
                return Err(invalid_request("duplicate Host fields"));
            }
            if !host_matches_url(field.value().as_str(), request)? {
                return Err(invalid_request("Host conflicts with request authority"));
            }
        } else if field.name().eq_ignore_ascii_case("content-length") {
            content_lengths.push(parse_content_length(field.value().as_str())?);
        } else if field.name().eq_ignore_ascii_case("transfer-encoding") {
            transfer_encoding = true;
        }
    }

    if content_lengths.len() > 1 {
        return Err(invalid_request("multiple Content-Length fields"));
    }
    if transfer_encoding {
        return Err(TransportError::Unsupported(
            "request Transfer-Encoding is unsupported by native/1".to_owned(),
        ));
    }
    if let Some(declared) = content_lengths.first().copied() {
        let body_len = u64::try_from(body.len()).map_err(|_| resource_limit("request body"))?;
        if declared != body_len {
            return Err(invalid_request("Content-Length does not match entity"));
        }
    } else if request.body().is_present() {
        // A present empty body is intentionally distinct from Body::Empty.
        // Its only HTTP/1 representation here is Content-Length: 0.
        header_fields = header_fields
            .checked_add(1)
            .ok_or_else(|| resource_limit("request header count"))?;
        if header_fields > header_field_limit {
            return Err(resource_limit("request header count"));
        }
    }

    let authority = request.url().authority();
    if host_count == 0 {
        validate_authority(authority)?;
        header_fields = header_fields
            .checked_add(1)
            .ok_or_else(|| resource_limit("request header count"))?;
        if header_fields > header_field_limit {
            return Err(resource_limit("request header count"));
        }
        let host_len = authority
            .len()
            .checked_add(HOST_FIELD_OVERHEAD)
            .ok_or_else(|| resource_limit("Host field bytes"))?;
        supplied_header_bytes = supplied_header_bytes
            .checked_add(host_len)
            .ok_or_else(|| resource_limit("request header bytes"))?;
    }
    if content_lengths.is_empty() && request.body().is_present() {
        supplied_header_bytes = supplied_header_bytes
            .checked_add(CONTENT_LENGTH_ZERO_OVERHEAD + decimal_len(body.len()))
            .ok_or_else(|| resource_limit("request header bytes"))?;
    }
    if supplied_header_bytes > header_bytes_limit {
        return Err(resource_limit("request header bytes"));
    }

    // Calculate all output sizes before allocating the final buffer.
    let request_line_bytes = method
        .len()
        .checked_add(1)
        .and_then(|n| n.checked_add(target.len()))
        .and_then(|n| n.checked_add(1 + HTTP11_BYTES.len() + CRLF.len()))
        .ok_or_else(|| resource_limit("request head bytes"))?;
    let head_bytes_usize = request_line_bytes
        .checked_add(supplied_header_bytes)
        .and_then(|n| n.checked_add(CRLF.len()))
        .ok_or_else(|| resource_limit("request head bytes"))?;
    let request_head_limit = limit_usize(limits.max_request_head_bytes, "request head bytes")?;
    if head_bytes_usize > request_head_limit {
        return Err(resource_limit("request head bytes"));
    }
    let total = head_bytes_usize
        .checked_add(body.len())
        .ok_or_else(|| resource_limit("wire request bytes"))?;
    let wire_limit = limit_usize(limits.max_request_total_bytes, "wire request bytes")?;
    if total > wire_limit {
        return Err(resource_limit("wire request bytes"));
    }
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(method.as_bytes());
    bytes.push(b' ');
    bytes.extend_from_slice(target.as_bytes());
    bytes.extend_from_slice(b" HTTP/1.1\r\n");
    for field in request.headers().iter() {
        append_field(&mut bytes, field);
    }
    if host_count == 0 {
        bytes.extend_from_slice(b"Host: ");
        bytes.extend_from_slice(authority.as_bytes());
        bytes.extend_from_slice(CRLF);
    }
    if content_lengths.is_empty() && request.body().is_present() {
        bytes.extend_from_slice(b"Content-Length: ");
        append_decimal(&mut bytes, body.len());
        bytes.extend_from_slice(CRLF);
    }
    bytes.extend_from_slice(CRLF);
    debug_assert_eq!(bytes.len(), head_bytes_usize);
    bytes.extend_from_slice(body);
    let head_bytes =
        u64::try_from(head_bytes_usize).map_err(|_| resource_limit("request head byte counter"))?;
    let body_bytes =
        u64::try_from(body.len()).map_err(|_| resource_limit("request body byte counter"))?;
    Ok(EncodedRequest {
        bytes,
        head_bytes,
        body_bytes,
    })
}

/// Decodes one or more bounded informational responses followed by a final
/// HTTP/1.0 or HTTP/1.1 response.
pub(crate) fn decode_response(
    bytes: &[u8],
    method: &Method,
    limits: &NativeTransportLimits,
) -> Result<DecodedResponse, TransportError> {
    validate_limits(limits)?;
    let wire_limit = limit_usize(limits.max_response_total_bytes, "wire response bytes")?;
    if bytes.len() > wire_limit {
        return Err(resource_limit("wire response bytes"));
    }
    let mut cursor = 0usize;
    let mut head_bytes = 0usize;
    let mut informational_count = 0usize;
    let informational_limit = limit_usize(
        limits.max_informational_count,
        "informational response count",
    )?;
    let informational_bytes_limit = limit_usize(
        limits.max_informational_bytes,
        "informational response bytes",
    )?;
    let header_field_limit = limit_usize(limits.max_header_count, "response header count")?;
    let header_bytes_limit =
        limit_usize(limits.max_header_aggregate_bytes, "response header bytes")?;
    let name_limit = limit_usize(limits.max_header_name_bytes, "header name bytes")?;
    let value_limit = limit_usize(limits.max_header_value_bytes, "header value bytes")?;
    let status_line_limit = limit_usize(limits.max_status_line_bytes, "status line bytes")?;
    let reason_limit = limit_usize(limits.max_reason_bytes, "reason bytes")?;
    let line_limit = limit_usize(limits.max_line_bytes, "line bytes")?;

    let response_head_limit = limit_usize(limits.max_response_head_bytes, "response head bytes")?;
    let mut informational_responses = Vec::new();
    let (protocol, status, reason, reason_presence, headers, _final_head_len) = loop {
        let before = cursor;
        let (protocol, status, reason, reason_presence, headers, head_len) = parse_head(
            bytes,
            &mut cursor,
            status_line_limit,
            reason_limit,
            line_limit,
            header_field_limit,
            header_bytes_limit,
            name_limit,
            value_limit,
        )?;
        head_bytes = head_bytes
            .checked_add(head_len)
            .ok_or_else(|| resource_limit("response head bytes"))?;
        if head_len > response_head_limit {
            return Err(resource_limit("response head bytes"));
        }
        if status < 200 {
            informational_count = informational_count
                .checked_add(1)
                .ok_or_else(|| resource_limit("informational response count"))?;
            if informational_count > informational_limit {
                return Err(resource_limit("informational response count"));
            }
            let informational_bytes = head_bytes;
            if informational_bytes > informational_bytes_limit {
                return Err(resource_limit("informational response bytes"));
            }
            if headers.contains("transfer-encoding") {
                return Err(unsupported("informational Transfer-Encoding"));
            }
            // A 1xx response has no content or trailers, and RFC 9110
            // forbids Content-Length on every informational response.  The
            // 101 upgrade case was rejected while parsing its status line.
            if headers.contains("content-length") {
                return Err(protocol_error(
                    "Content-Length is forbidden on informational response",
                ));
            }
            if cursor == before {
                return Err(protocol_error("response parser made no progress"));
            }
            informational_responses.push(ResponseHeadObservation {
                status,
                reason: reason_presence,
                protocol: Some(protocol),
                headers,
                framing: Some(Framing::NoBody),
            });
            continue;
        }
        break (protocol, status, reason, reason_presence, headers, head_len);
    };

    validate_content_length_headers(&headers)?;
    let content_length = parse_single_content_length(&headers)?;
    let transfer_encoding = parse_response_transfer_encoding(&headers)?;
    if transfer_encoding.is_some() && content_length.is_some() {
        return Err(protocol_error(
            "Transfer-Encoding and Content-Length conflict",
        ));
    }
    let no_body = matches!(method, Method::Head)
        || status == 204
        || status == 304
        || (100..200).contains(&status);
    if no_body {
        // RFC 9110 forbids Content-Length on 204 responses.  HEAD and 304
        // responses are different: their Content-Length, when present, is
        // metadata for the representation that would have been sent, so it
        // does not describe bytes in this response and must not be checked
        // against the retained entity limit.
        if status == 204 && content_length.is_some() {
            return Err(protocol_error("Content-Length is forbidden on 204"));
        }
        if transfer_encoding.is_some() {
            return Err(unsupported("Transfer-Encoding on a no-body response"));
        }
        if cursor != bytes.len() {
            return Err(protocol_error("bytes follow a response with no body"));
        }
        return Ok(DecodedResponse {
            status,
            reason,
            reason_presence,
            headers,
            body: Vec::new(),
            body_presence: ResponseBodyPresence::Absent,
            informational_responses,
            received_head_bytes: u64::try_from(head_bytes)
                .map_err(|_| resource_limit("response head byte counter"))?,
            received_body_bytes: 0,
            protocol,
            framing: Framing::NoBody,
        });
    }
    let body_limit = limit_usize(limits.max_response_body_bytes, "response body bytes")?;
    if content_length
        .is_some_and(|length| usize::try_from(length).map_or(true, |value| value > body_limit))
    {
        return Err(resource_limit("response body bytes"));
    }

    let (body, framing) = if transfer_encoding.is_some() {
        decode_chunked(bytes, &mut cursor, body_limit, limits)?
    } else if let Some(content_length) = content_length {
        let body_len = usize_from_u64(content_length, "Content-Length")?;
        if body_len > body_limit {
            return Err(resource_limit("response body bytes"));
        }
        let end = cursor
            .checked_add(body_len)
            .ok_or_else(|| resource_limit("response body arithmetic"))?;
        if end > bytes.len() {
            return Err(protocol_error("Content-Length exceeds received bytes"));
        }
        let body = bytes[cursor..end].to_vec();
        cursor = end;
        if cursor != bytes.len() {
            return Err(protocol_error("bytes follow Content-Length body"));
        }
        (body, Framing::ContentLength)
    } else {
        let body_len = bytes
            .len()
            .checked_sub(cursor)
            .ok_or_else(|| resource_limit("close-delimited response arithmetic"))?;
        if body_len > body_limit {
            return Err(resource_limit("close-delimited response body"));
        }
        let body = bytes[cursor..].to_vec();
        cursor = bytes.len();
        (body, Framing::CloseDelimited)
    };
    if cursor != bytes.len() {
        return Err(protocol_error("response parser left trailing bytes"));
    }
    let received_body_bytes =
        u64::try_from(body.len()).map_err(|_| resource_limit("response body byte counter"))?;
    Ok(DecodedResponse {
        status,
        reason,
        reason_presence,
        headers,
        body,
        body_presence: ResponseBodyPresence::Present,
        informational_responses,
        received_head_bytes: u64::try_from(head_bytes)
            .map_err(|_| resource_limit("response head byte counter"))?,
        received_body_bytes,
        protocol,
        framing,
    })
}

const CRLF: &[u8] = b"\r\n";
const HTTP11_BYTES: &[u8] = b"HTTP/1.1";
const HARD_METHOD_BYTES: usize = 256;
const HOST_FIELD_OVERHEAD: usize = b"Host: \r\n".len();
const CONTENT_LENGTH_ZERO_OVERHEAD: usize = b"Content-Length: \r\n".len();

#[allow(
    clippy::too_many_arguments,
    reason = "the parser receives each independently bounded wire category"
)]
fn parse_head(
    bytes: &[u8],
    cursor: &mut usize,
    status_line_limit: usize,
    reason_limit: usize,
    line_limit: usize,
    header_field_limit: usize,
    header_bytes_limit: usize,
    name_limit: usize,
    value_limit: usize,
) -> Result<ParsedHead, TransportError> {
    let start = *cursor;
    let (line, _line_end) = take_crlf(
        bytes,
        cursor,
        status_line_limit.min(line_limit),
        "status line",
    )?;
    if line.len() > status_line_limit {
        return Err(resource_limit("status line"));
    }
    let (protocol, status, reason_presence_bytes) = parse_status_line(line)?;
    if reason_presence_bytes
        .as_ref()
        .is_some_and(|reason| reason.len() > reason_limit)
    {
        return Err(resource_limit("reason phrase"));
    }
    let reason_presence = match reason_presence_bytes {
        ResponsePresence::Absent => ResponsePresence::Absent,
        ResponsePresence::Present(reason_bytes) => ResponsePresence::Present(
            str::from_utf8(reason_bytes)
                .map_err(|_| protocol_error("reason phrase is not UTF-8"))?
                .to_owned(),
        ),
    };
    let reason = match &reason_presence {
        ResponsePresence::Absent => String::new(),
        ResponsePresence::Present(reason) => reason.clone(),
    };
    let mut headers = Headers::with_capacity(header_field_limit);
    // Status-line bytes have their own limit.  Header aggregate accounting
    // starts with the first field line and therefore cannot be consumed by a
    // long status line; `head_len` remains the combined response-head bound.
    let mut aggregate = 0usize;
    loop {
        let field_start = *cursor;
        let (field_line, field_end) = take_crlf(
            bytes,
            cursor,
            header_bytes_limit.min(line_limit),
            "header line",
        )?;
        let line_wire = field_end
            .checked_sub(field_start)
            .ok_or_else(|| resource_limit("response header arithmetic"))?;
        aggregate = aggregate
            .checked_add(line_wire)
            .ok_or_else(|| resource_limit("response header bytes"))?;
        if aggregate > header_bytes_limit {
            return Err(resource_limit("response header bytes"));
        }
        if field_line.is_empty() {
            break;
        }
        if field_line[0] == b' ' || field_line[0] == b'\t' {
            return Err(protocol_error("obsolete folded response header"));
        }
        let colon = field_line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(|| protocol_error("response header has no colon"))?;
        let name = &field_line[..colon];
        let value = trim_ows(&field_line[colon + 1..]);
        if name.is_empty()
            || name.len() > name_limit
            || !is_token(name)
            || contains_forbidden_control(value)
            || value.len() > value_limit
        {
            return Err(protocol_error("invalid response header field"));
        }
        let count = headers
            .len()
            .checked_add(1)
            .ok_or_else(|| resource_limit("response header count"))?;
        if count > header_field_limit {
            return Err(resource_limit("response header count"));
        }
        let name = str::from_utf8(name)
            .map_err(|_| protocol_error("response header name is not ASCII"))?;
        let value = str::from_utf8(value)
            .map_err(|_| protocol_error("response header value is not UTF-8"))?;
        headers
            .try_append(
                Header::new(name, value)
                    .map_err(|_| protocol_error("response header field rejected by core"))?,
            )
            .map_err(|_| resource_limit("response headers"))?;
    }
    let head_len = (*cursor)
        .checked_sub(start)
        .ok_or_else(|| resource_limit("response head arithmetic"))?;
    Ok((protocol, status, reason, reason_presence, headers, head_len))
}

fn decode_chunked(
    bytes: &[u8],
    cursor: &mut usize,
    body_limit: usize,
    limits: &NativeTransportLimits,
) -> Result<(Vec<u8>, Framing), TransportError> {
    let result = consume_chunked(bytes, cursor, body_limit, limits, true, true)
        .map_err(TransportError::from)?;
    let body = result
        .body
        .ok_or_else(|| protocol_error("chunked decoder did not collect entity"))?;
    Ok((body, Framing::Chunked))
}

/// Bounded chunked parser shared by the incremental scanner and final
/// materializer.  When `collect_body` is false, only framing and entity byte
/// counts are retained; this keeps every scanner poll allocation-free with
/// respect to the response entity.
#[derive(Debug)]
struct ChunkedResult {
    body: Option<Vec<u8>>,
}

#[allow(
    clippy::too_many_arguments,
    reason = "the scanner receives each independently bounded wire category"
)]
fn consume_chunked(
    bytes: &[u8],
    cursor: &mut usize,
    body_limit: usize,
    limits: &NativeTransportLimits,
    eof: bool,
    collect_body: bool,
) -> Result<ChunkedResult, ScanFailure> {
    let generic_line_limit = limit_usize(limits.max_line_bytes, "line bytes")?;
    let chunk_line_limit =
        limit_usize(limits.max_chunk_line_bytes, "chunk line bytes")?.min(generic_line_limit);
    let chunk_count_limit = limit_usize(limits.max_chunk_count, "chunk count")?;
    let extension_count_limit =
        limit_usize(limits.max_chunk_extension_count, "chunk extension count")?;
    let extension_bytes_limit = limit_usize(
        limits.max_chunk_extension_bytes_per_chunk,
        "chunk extension bytes",
    )?;
    let extension_aggregate_limit = limit_usize(
        limits.max_chunk_extension_aggregate_bytes,
        "chunk extension aggregate bytes",
    )?;
    let trailer_field_limit = limit_usize(limits.max_trailer_count, "trailer count")?;
    let trailer_bytes_limit = limit_usize(limits.max_trailer_aggregate_bytes, "trailer bytes")?;
    let trailer_name_limit = limit_usize(limits.max_trailer_name_bytes, "trailer name bytes")?;
    let trailer_value_limit = limit_usize(limits.max_trailer_value_bytes, "trailer value bytes")?;

    let mut body = collect_body.then(Vec::new);
    let mut entity_bytes = 0usize;
    let mut chunks = 0usize;
    let mut extension_aggregate = 0usize;
    loop {
        let line = take_crlf_for_scan(bytes, cursor, chunk_line_limit, "chunk-size line", eof)?;
        let semicolon = line.iter().position(|byte| *byte == b';');
        let size_bytes = semicolon.map_or(line, |index| &line[..index]);
        if size_bytes.is_empty() || !size_bytes.iter().all(u8::is_ascii_hexdigit) {
            return Err(ScanFailure::Error(protocol_error("invalid chunk-size")));
        }
        let mut size = 0usize;
        for byte in size_bytes {
            size = size
                .checked_mul(16)
                .and_then(|value| value.checked_add(hex_value(*byte) as usize))
                .ok_or_else(|| ScanFailure::Error(resource_limit("chunk-size arithmetic")))?;
        }
        if let Some(index) = semicolon {
            let extension = &line[index + 1..];
            validate_chunk_extensions(extension, extension_count_limit, extension_bytes_limit)
                .map_err(ScanFailure::Error)?;
            extension_aggregate = extension_aggregate
                .checked_add(extension.len())
                .ok_or_else(|| {
                    ScanFailure::Error(resource_limit("chunk extension aggregate bytes"))
                })?;
            if extension_aggregate > extension_aggregate_limit {
                return Err(ScanFailure::Error(resource_limit(
                    "chunk extension aggregate bytes",
                )));
            }
        }
        if size == 0 {
            scan_trailers(
                bytes,
                cursor,
                trailer_field_limit,
                trailer_bytes_limit,
                generic_line_limit,
                trailer_name_limit,
                trailer_value_limit,
                eof,
            )?;
            return Ok(ChunkedResult { body });
        }
        chunks = chunks
            .checked_add(1)
            .ok_or_else(|| ScanFailure::Error(resource_limit("chunk count")))?;
        if chunks > chunk_count_limit {
            return Err(ScanFailure::Error(resource_limit("chunk count")));
        }
        let remaining = body_limit
            .checked_sub(entity_bytes)
            .ok_or_else(|| ScanFailure::Error(resource_limit("response body bytes")))?;
        if size > remaining {
            return Err(ScanFailure::Error(resource_limit("response body bytes")));
        }
        let data_end = cursor
            .checked_add(size)
            .ok_or_else(|| ScanFailure::Error(resource_limit("chunk body arithmetic")))?;
        let end = data_end
            .checked_add(CRLF.len())
            .ok_or_else(|| ScanFailure::Error(resource_limit("chunk body arithmetic")))?;
        if end > bytes.len() {
            return if eof {
                Err(ScanFailure::Error(protocol_error(
                    "chunk exceeds received bytes",
                )))
            } else {
                Err(ScanFailure::Incomplete)
            };
        }
        if &bytes[data_end..end] != CRLF {
            return Err(ScanFailure::Error(protocol_error(
                "chunk data is not followed by CRLF",
            )));
        }
        entity_bytes = entity_bytes
            .checked_add(size)
            .ok_or_else(|| ScanFailure::Error(resource_limit("response body bytes")))?;
        if let Some(body) = &mut body {
            body.try_reserve_exact(size)
                .map_err(|_| ScanFailure::Error(resource_limit("response body allocation")))?;
            body.extend_from_slice(&bytes[*cursor..data_end]);
        }
        *cursor = end;
    }
}

fn take_crlf_for_scan<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    limit: usize,
    kind: &str,
    eof: bool,
) -> Result<&'a [u8], ScanFailure> {
    match take_crlf(bytes, cursor, limit, kind) {
        Ok((line, _)) => Ok(line),
        Err(error) if !eof && is_incomplete_line_error(&error) => Err(ScanFailure::Incomplete),
        Err(error) => Err(ScanFailure::Error(error)),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "trailer parsing receives each independently bounded wire category"
)]
fn scan_trailers(
    bytes: &[u8],
    cursor: &mut usize,
    field_limit: usize,
    bytes_limit: usize,
    line_limit: usize,
    name_limit: usize,
    value_limit: usize,
    eof: bool,
) -> Result<(), ScanFailure> {
    let mut count = 0usize;
    let mut aggregate = 0usize;
    let mut nonempty = false;
    loop {
        let line = take_crlf_for_scan(
            bytes,
            cursor,
            bytes_limit.min(line_limit),
            "trailer line",
            eof,
        )?;
        aggregate = aggregate
            .checked_add(
                line.len()
                    .checked_add(CRLF.len())
                    .ok_or_else(|| ScanFailure::Error(resource_limit("trailer byte accounting")))?,
            )
            .ok_or_else(|| ScanFailure::Error(resource_limit("trailer bytes")))?;
        if aggregate > bytes_limit {
            return Err(ScanFailure::Error(resource_limit("trailer bytes")));
        }
        if line.is_empty() {
            if nonempty {
                return Err(ScanFailure::Error(unsupported(
                    "response trailers are not exposed",
                )));
            }
            return Ok(());
        }
        if line[0] == b' ' || line[0] == b'\t' {
            return Err(ScanFailure::Error(protocol_error(
                "obsolete folded response trailer",
            )));
        }
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(|| ScanFailure::Error(protocol_error("trailer has no colon")))?;
        let name = &line[..colon];
        let value = trim_ows(&line[colon + 1..]);
        if name.is_empty()
            || name.len() > name_limit
            || value.len() > value_limit
            || !is_token(name)
            || contains_forbidden_control(value)
        {
            return Err(ScanFailure::Error(protocol_error(
                "invalid response trailer",
            )));
        }
        count = count
            .checked_add(1)
            .ok_or_else(|| ScanFailure::Error(resource_limit("trailer count")))?;
        if count > field_limit {
            return Err(ScanFailure::Error(resource_limit("trailer count")));
        }
        nonempty = true;
    }
}

fn validate_chunk_extensions(
    extension: &[u8],
    count_limit: usize,
    bytes_limit: usize,
) -> Result<(), TransportError> {
    if extension.len() > bytes_limit {
        return Err(resource_limit("chunk extension bytes"));
    }
    if extension.is_empty() {
        return Err(protocol_error("empty chunk extension"));
    }
    let mut count = 0usize;
    let mut cursor = 0usize;
    loop {
        // `chunk-ext` permits bad whitespace around each separator and the
        // name/value delimiter.  Parsing the bytes directly keeps semicolons
        // inside quoted strings from being mistaken for separators.
        while cursor < extension.len() && is_bad_whitespace(extension[cursor]) {
            cursor += 1;
        }
        let name_start = cursor;
        while cursor < extension.len() && is_token_byte(extension[cursor]) {
            cursor += 1;
        }
        if name_start == cursor {
            return Err(protocol_error("invalid chunk extension name"));
        }
        count = count
            .checked_add(1)
            .ok_or_else(|| resource_limit("chunk extension count"))?;
        if count > count_limit {
            return Err(resource_limit("chunk extension count"));
        }

        while cursor < extension.len() && is_bad_whitespace(extension[cursor]) {
            cursor += 1;
        }
        if cursor < extension.len() && extension[cursor] == b'=' {
            cursor += 1;
            while cursor < extension.len() && is_bad_whitespace(extension[cursor]) {
                cursor += 1;
            }
            if cursor == extension.len() {
                return Err(protocol_error("invalid chunk extension value"));
            }
            if extension[cursor] == b'"' {
                cursor += 1;
                let mut closed = false;
                while cursor < extension.len() {
                    let byte = extension[cursor];
                    if byte == b'"' {
                        cursor += 1;
                        closed = true;
                        break;
                    }
                    if byte == b'\\' {
                        cursor += 1;
                        if cursor == extension.len() || !is_quoted_pair_byte(extension[cursor]) {
                            return Err(protocol_error("invalid chunk extension quoted-pair"));
                        }
                        cursor += 1;
                    } else if is_quoted_text_byte(byte) {
                        cursor += 1;
                    } else {
                        return Err(protocol_error("invalid chunk extension quoted-string"));
                    }
                }
                if !closed {
                    return Err(protocol_error("unterminated chunk extension quoted-string"));
                }
            } else {
                let value_start = cursor;
                while cursor < extension.len() && is_token_byte(extension[cursor]) {
                    cursor += 1;
                }
                if value_start == cursor {
                    return Err(protocol_error("invalid chunk extension value"));
                }
            }
        }

        while cursor < extension.len() && is_bad_whitespace(extension[cursor]) {
            cursor += 1;
        }
        if cursor == extension.len() {
            return Ok(());
        }
        if extension[cursor] != b';' {
            return Err(protocol_error("invalid chunk extension separator"));
        }
        cursor += 1;
    }
}

fn is_bad_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

fn is_quoted_pair_byte(byte: u8) -> bool {
    is_bad_whitespace(byte) || (0x21..=0x7e).contains(&byte) || byte >= 0x80
}

fn is_quoted_text_byte(byte: u8) -> bool {
    is_bad_whitespace(byte)
        || byte == b'!'
        || (0x23..=0x5b).contains(&byte)
        || (0x5d..=0x7e).contains(&byte)
        || byte >= 0x80
}

fn parse_status_line(
    line: &[u8],
) -> Result<(ProtocolVersion, u16, ResponsePresence<&[u8]>), TransportError> {
    let (version, rest) = if let Some(rest) = line.strip_prefix(b"HTTP/1.1 ") {
        (ProtocolVersion::Http11, rest)
    } else if let Some(rest) = line.strip_prefix(b"HTTP/1.0 ") {
        (ProtocolVersion::Http10, rest)
    } else {
        return Err(protocol_error("unsupported HTTP response version"));
    };
    if rest.len() < 3 || !rest[..3].iter().all(u8::is_ascii_digit) {
        return Err(protocol_error("invalid response status"));
    }
    let status = u16::from(rest[0] - b'0') * 100
        + u16::from(rest[1] - b'0') * 10
        + u16::from(rest[2] - b'0');
    if !(100..=599).contains(&status) {
        return Err(protocol_error("response status outside 100..=599"));
    }
    // 101 is a final protocol-switch response, not an interim response that
    // can be skipped while searching for a later HTTP response.  Native/1
    // has no upgraded-protocol capability, so fail before consuming fields
    // or treating any following bytes as another response head.
    if status == 101 {
        return Err(unsupported("101 Switching Protocols is unsupported"));
    }
    if rest.len() == 3 {
        return Ok((version, status, ResponsePresence::Absent));
    }
    if rest[3] != b' ' {
        return Err(protocol_error(
            "response status line missing reason separator",
        ));
    }
    let reason = &rest[4..];
    if contains_forbidden_control(reason) {
        return Err(protocol_error("response reason contains a control byte"));
    }
    Ok((version, status, ResponsePresence::Present(reason)))
}

fn take_crlf<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    limit: usize,
    kind: &str,
) -> Result<(&'a [u8], usize), TransportError> {
    let start = *cursor;
    if start > bytes.len() {
        return Err(protocol_error("response cursor outside input"));
    }
    let remaining = &bytes[start..];
    let Some(relative) = remaining.windows(2).position(|window| window == CRLF) else {
        if remaining.len() >= limit {
            return Err(resource_limit(kind));
        }
        return Err(protocol_error("response line is not CRLF terminated"));
    };
    let line_len = relative;
    let wire_len = line_len
        .checked_add(CRLF.len())
        .ok_or_else(|| resource_limit("response line arithmetic"))?;
    if wire_len > limit {
        return Err(resource_limit(kind));
    }
    let end = start
        .checked_add(relative)
        .and_then(|value| value.checked_add(CRLF.len()))
        .ok_or_else(|| resource_limit("response line arithmetic"))?;
    *cursor = end;
    Ok((&bytes[start..start + line_len], end))
}

fn parse_single_content_length(headers: &Headers) -> Result<Option<u64>, TransportError> {
    let mut values = headers.values("content-length");
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(protocol_error("multiple Content-Length fields"));
    }
    Ok(Some(parse_content_length(value)?))
}

fn validate_content_length_headers(headers: &Headers) -> Result<(), TransportError> {
    let mut values = headers.values("content-length");
    let Some(first) = values.next() else {
        return Ok(());
    };
    if values.next().is_some() {
        return Err(protocol_error("multiple Content-Length fields"));
    }
    let _ = parse_content_length(first)?;
    Ok(())
}

fn parse_response_transfer_encoding(headers: &Headers) -> Result<Option<()>, TransportError> {
    let mut values = headers.values("transfer-encoding");
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(unsupported("multiple Transfer-Encoding fields"));
    }
    let pieces: Vec<&str> = value.split(',').map(str::trim).collect();
    if pieces.len() != 1 || !pieces[0].eq_ignore_ascii_case("chunked") {
        return Err(unsupported("unsupported Transfer-Encoding"));
    }
    Ok(Some(()))
}

fn parse_content_length(value: &str) -> Result<u64, TransportError> {
    let value = value.trim_matches(|byte| byte == ' ' || byte == '\t');
    if value.is_empty() || value.contains(',') || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(protocol_error("malformed Content-Length"));
    }
    let mut parsed = 0u64;
    for byte in value.bytes() {
        parsed = parsed
            .checked_mul(10)
            .and_then(|number| number.checked_add(u64::from(byte - b'0')))
            .ok_or_else(|| resource_limit("Content-Length arithmetic"))?;
    }
    Ok(parsed)
}

fn host_matches_url(value: &str, request: &Request) -> Result<bool, TransportError> {
    if value.is_empty() || contains_forbidden_control(value.as_bytes()) || value.contains(' ') {
        return Ok(false);
    }
    let candidate = jmeter_rs_http::Url::parse(format!("{}://{value}/", request.url().scheme()));
    let Ok(candidate) = candidate else {
        return Ok(false);
    };
    Ok(candidate.host().eq_ignore_ascii_case(request.url().host())
        && candidate.port() == request.url().port())
}

fn validate_authority(authority: &str) -> Result<(), TransportError> {
    if authority.is_empty()
        || authority.len() > HARD_MAX_AUTHORITY_BYTES
        || contains_forbidden_control(authority.as_bytes())
    {
        return Err(invalid_request("URL authority is invalid"));
    }
    Ok(())
}

fn validate_field(
    field: &Header,
    name_limit: usize,
    value_limit: usize,
) -> Result<(), TransportError> {
    let name = field.name().as_str().as_bytes();
    let value = field.value().as_str().as_bytes();
    if name.is_empty()
        || name.len() > name_limit
        || !is_token(name)
        || value.len() > value_limit
        || contains_forbidden_control(value)
    {
        return Err(invalid_request("invalid request header field"));
    }
    Ok(())
}

fn append_field(output: &mut Vec<u8>, field: &Header) {
    output.extend_from_slice(field.name().as_str().as_bytes());
    output.extend_from_slice(b": ");
    output.extend_from_slice(field.value().as_str().as_bytes());
    output.extend_from_slice(CRLF);
}

fn field_wire_len(field: &Header) -> Result<usize, TransportError> {
    field
        .name()
        .as_str()
        .len()
        .checked_add(2)
        .and_then(|size| size.checked_add(field.value().as_str().len()))
        .and_then(|size| size.checked_add(CRLF.len()))
        .ok_or_else(|| resource_limit("header wire bytes"))
}

fn append_decimal(output: &mut Vec<u8>, value: usize) {
    output.extend_from_slice(value.to_string().as_bytes());
}

fn decimal_len(value: usize) -> usize {
    value.to_string().len()
}

fn is_token(value: &[u8]) -> bool {
    !value.is_empty() && value.iter().copied().all(is_token_byte)
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'..=b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
        )
}

fn contains_forbidden_control(value: &[u8]) -> bool {
    value
        .iter()
        .copied()
        .any(|byte| byte < 0x20 || byte == 0x7f)
}

fn trim_ows(value: &[u8]) -> &[u8] {
    let mut start = 0usize;
    let mut end = value.len();
    while start < end && matches!(value[start], b' ' | b'\t') {
        start += 1;
    }
    while end > start && matches!(value[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    &value[start..end]
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}

fn usize_from_u64(value: u64, what: &str) -> Result<usize, TransportError> {
    usize::try_from(value).map_err(|_| resource_limit(what))
}

fn limit_usize<T>(value: T, what: &str) -> Result<usize, TransportError>
where
    T: TryInto<usize>,
{
    let value = value.try_into().map_err(|_| resource_limit(what))?;
    if value == 0 {
        return Err(resource_limit(what));
    }
    Ok(value)
}

fn validate_limits(limits: &NativeTransportLimits) -> Result<(), TransportError> {
    // Every active bound is checked at the operation boundary, before any
    // request/response output allocation.  The config owner caps these values
    // against the parser hard maxima; this check also protects a malformed
    // config object supplied by a caller.
    limits.validate()?;
    let _ = limit_usize(limits.max_request_head_bytes, "request head limit")?;
    let _ = limit_usize(limits.max_request_body_bytes, "request body limit")?;
    let _ = limit_usize(limits.max_response_body_bytes, "response body limit")?;
    let _ = limit_usize(limits.max_header_count, "header count")?;
    let _ = limit_usize(limits.max_header_aggregate_bytes, "header bytes")?;
    let _ = limit_usize(limits.max_header_name_bytes, "header name bytes")?;
    let _ = limit_usize(limits.max_header_value_bytes, "header value bytes")?;
    let _ = limit_usize(limits.max_request_total_bytes, "wire request bytes")?;
    let _ = limit_usize(limits.max_response_total_bytes, "wire response bytes")?;
    let _ = limit_usize(limits.max_status_line_bytes, "status line bytes")?;
    let _ = limit_usize(limits.max_reason_bytes, "reason bytes")?;
    let _ = limit_usize(limits.max_informational_count, "informational count")?;
    let _ = limit_usize(limits.max_informational_bytes, "informational bytes")?;
    let _ = limit_usize(limits.max_chunk_line_bytes, "chunk line bytes")?;
    let _ = limit_usize(limits.max_chunk_count, "chunk count")?;
    let _ = limit_usize(limits.max_chunk_extension_count, "chunk extension count")?;
    let _ = limit_usize(
        limits.max_chunk_extension_bytes_per_chunk,
        "chunk extension bytes",
    )?;
    let _ = limit_usize(
        limits.max_chunk_extension_aggregate_bytes,
        "chunk extension aggregate bytes",
    )?;
    let _ = limit_usize(limits.max_trailer_count, "trailer count")?;
    let _ = limit_usize(limits.max_trailer_aggregate_bytes, "trailer bytes")?;
    let _ = limit_usize(limits.max_trailer_name_bytes, "trailer name bytes")?;
    let _ = limit_usize(limits.max_trailer_value_bytes, "trailer value bytes")?;
    Ok(())
}

fn invalid_request(message: &str) -> TransportError {
    TransportError::InvalidRequest(message.to_owned())
}

fn protocol_error(message: &str) -> TransportError {
    TransportError::Protocol(message.to_owned())
}

fn resource_limit(message: &str) -> TransportError {
    TransportError::ResourceLimit(message.to_owned())
}

fn unsupported(message: &str) -> TransportError {
    TransportError::Unsupported(message.to_owned())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "tests use fixed valid wire fixtures and assert their outcomes"
    )]

    use super::*;
    use jmeter_rs_http::{Body, Url};

    fn limits() -> NativeTransportLimits {
        NativeTransportLimits::default()
    }

    fn request() -> Request {
        Request::new(
            Method::Get,
            Url::parse("http://example.test/path?q=1").unwrap(),
        )
    }

    #[test]
    fn request_synthesizes_host_and_content_length_in_order() {
        let mut request = request();
        request.add_header("X-First", "a").unwrap();
        request.add_header("X-First", "b").unwrap();
        request.set_body(Body::bytes(Vec::new()));
        let encoded = encode_request(&request, &limits()).unwrap();
        let text = String::from_utf8(encoded.bytes).unwrap();
        assert_eq!(
            text,
            "GET /path?q=1 HTTP/1.1\r\nX-First: a\r\nX-First: b\r\nHost: example.test\r\nContent-Length: 0\r\n\r\n"
        );
        assert_eq!(encoded.body_bytes, 0);
    }

    #[test]
    fn request_rejects_host_duplicates_and_conflicts() {
        let mut duplicate = request();
        duplicate.add_header("Host", "example.test").unwrap();
        duplicate.add_header("host", "example.test").unwrap();
        assert!(matches!(
            encode_request(&duplicate, &limits()),
            Err(TransportError::InvalidRequest(_))
        ));
        let mut conflict = request();
        conflict.add_header("Host", "other.test").unwrap();
        assert!(matches!(
            encode_request(&conflict, &limits()),
            Err(TransportError::InvalidRequest(_))
        ));
    }

    #[test]
    fn request_rejects_transfer_encoding_and_conflicting_lengths() {
        let mut transfer = request();
        transfer.add_header("Transfer-Encoding", "chunked").unwrap();
        assert!(matches!(
            encode_request(&transfer, &limits()),
            Err(TransportError::Unsupported(_))
        ));
        let mut conflict = request().with_body(Body::bytes(b"abc".to_vec()));
        conflict.add_header("Content-Length", "2").unwrap();
        assert!(matches!(
            encode_request(&conflict, &limits()),
            Err(TransportError::InvalidRequest(_))
        ));
        conflict.remove_header("content-length");
        conflict.add_header("Content-Length", "3").unwrap();
        conflict.add_header("Content-Length", "3").unwrap();
        assert!(matches!(
            encode_request(&conflict, &limits()),
            Err(TransportError::InvalidRequest(_))
        ));
    }

    #[test]
    fn response_content_length_and_interim_are_accounted() {
        let wire = b"HTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\nHTTP/1.0 200 OK\r\nContent-Length: 5\r\nX-A: one\r\nX-A: two\r\n\r\nhello";
        let decoded = decode_response(wire, &Method::Get, &limits()).unwrap();
        assert_eq!(decoded.status, 200);
        assert_eq!(decoded.protocol, ProtocolVersion::Http10);
        assert_eq!(decoded.framing, Framing::ContentLength);
        assert_eq!(decoded.body, b"hello");
        assert_eq!(decoded.received_body_bytes, 5);
        assert_eq!(
            decoded.headers.values("x-a").collect::<Vec<_>>(),
            ["one", "two"]
        );
        assert_eq!(decoded.received_head_bytes as usize, wire.len() - 5);
    }

    #[test]
    fn scanner_reports_exact_content_length_boundary_before_eof() {
        let wire = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(
            scan_response_completion(wire, &Method::Get, &limits(), false).unwrap(),
            ResponseCompletion::Complete {
                wire_len: wire.len(),
                framing: Framing::ContentLength,
            }
        );
        assert_eq!(
            scan_response_completion(&wire[..wire.len() - 1], &Method::Get, &limits(), false)
                .unwrap(),
            ResponseCompletion::Incomplete
        );
    }

    #[test]
    fn scanner_reports_exact_chunked_boundary_before_eof() {
        let wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n";
        assert_eq!(
            scan_response_completion(wire, &Method::Get, &limits(), false).unwrap(),
            ResponseCompletion::Complete {
                wire_len: wire.len(),
                framing: Framing::Chunked,
            }
        );
        for prefix_len in 0..wire.len() {
            assert_eq!(
                scan_response_completion(&wire[..prefix_len], &Method::Get, &limits(), false)
                    .unwrap(),
                ResponseCompletion::Incomplete,
                "prefix length {prefix_len}"
            );
        }
    }

    #[test]
    fn scanner_keeps_close_delimited_incomplete_until_eof() {
        let wire = b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\nclose-boundary";
        assert_eq!(
            scan_response_completion(wire, &Method::Get, &limits(), false).unwrap(),
            ResponseCompletion::Incomplete
        );
        assert_eq!(
            scan_response_completion(wire, &Method::Get, &limits(), true).unwrap(),
            ResponseCompletion::Complete {
                wire_len: wire.len(),
                framing: Framing::CloseDelimited,
            }
        );
    }

    #[test]
    fn scanner_completes_no_body_and_1xx_chain_without_eof() {
        let no_body = b"HTTP/1.1 204 No Content\r\n\r\n";
        assert_eq!(
            scan_response_completion(no_body, &Method::Get, &limits(), false).unwrap(),
            ResponseCompletion::Complete {
                wire_len: no_body.len(),
                framing: Framing::NoBody,
            }
        );
        let forbidden_length = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
        assert!(matches!(
            scan_response_completion(forbidden_length, &Method::Get, &limits(), false),
            Err(TransportError::Protocol(_))
        ));
        let chain = b"HTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(
            scan_response_completion(chain, &Method::Get, &limits(), false).unwrap(),
            ResponseCompletion::Complete {
                wire_len: chain.len(),
                framing: Framing::ContentLength,
            }
        );
    }

    #[test]
    fn scanner_returns_boundary_before_extra_non_pipelined_bytes() {
        let frame = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let mut wire = frame.to_vec();
        wire.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(
            scan_response_completion(&wire, &Method::Get, &limits(), false).unwrap(),
            ResponseCompletion::Complete {
                wire_len: frame.len(),
                framing: Framing::ContentLength,
            }
        );
    }

    #[test]
    fn scanner_preserves_malformed_and_over_limit_failures() {
        let malformed = b"HTTP/1.1 200 OK\r\nX: a\n\r\nbody";
        assert!(matches!(
            scan_response_completion(malformed, &Method::Get, &limits(), false),
            Err(TransportError::Protocol(_))
        ));
        let mut constrained = limits();
        constrained.max_response_body_bytes = 2;
        let over_limit = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
        assert!(matches!(
            scan_response_completion(over_limit, &Method::Get, &constrained, false),
            Err(TransportError::ResourceLimit(_))
        ));
    }

    #[test]
    fn switching_protocols_is_rejected_before_interim_response_processing() {
        let wire = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n";
        assert!(matches!(
            decode_response(wire, &Method::Get, &limits()),
            Err(TransportError::Unsupported(_))
        ));
        assert!(matches!(
            scan_response_completion(wire, &Method::Get, &limits(), false),
            Err(TransportError::Unsupported(_))
        ));
        let informational_length =
            b"HTTP/1.1 103 Early Hints\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\n\r\n";
        assert!(matches!(
            decode_response(informational_length, &Method::Get, &limits()),
            Err(TransportError::Protocol(_))
        ));
    }

    #[test]
    fn close_delimited_body_limit_is_enforced_during_incremental_scans() {
        let mut constrained = limits();
        constrained.max_response_body_bytes = 2;
        let wire = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nabc";
        let body_start = wire
            .windows(CRLF.len() * 2)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + CRLF.len() * 2;
        for prefix_len in 0..=body_start + 2 {
            assert_eq!(
                scan_response_completion(&wire[..prefix_len], &Method::Get, &constrained, false)
                    .unwrap(),
                ResponseCompletion::Incomplete,
                "prefix length {prefix_len}"
            );
        }
        assert!(matches!(
            scan_response_completion(&wire[..body_start + 3], &Method::Get, &constrained, false),
            Err(TransportError::ResourceLimit(_))
        ));
        assert!(matches!(
            scan_response_completion(wire, &Method::Get, &constrained, true),
            Err(TransportError::ResourceLimit(_))
        ));
    }

    #[test]
    fn response_chunked_decodes_entity_and_rejects_trailers() {
        let wire =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4;foo=bar\r\ntest\r\n0\r\n\r\n";
        let decoded = decode_response(wire, &Method::Get, &limits()).unwrap();
        assert_eq!(decoded.body, b"test");
        assert_eq!(decoded.received_body_bytes, 4);
        assert_eq!(decoded.framing, Framing::Chunked);
        let trailer = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-T: y\r\n\r\n";
        assert!(matches!(
            decode_response(trailer, &Method::Get, &limits()),
            Err(TransportError::Unsupported(_))
        ));
    }

    #[test]
    fn chunk_extensions_honor_quoted_strings_and_escaped_bytes() {
        let wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;foo=\"a;b\\\"c\";bar=token\r\na\r\n0\r\n\r\n";
        let decoded = decode_response(wire, &Method::Get, &limits()).unwrap();
        assert_eq!(decoded.body, b"a");
    }

    #[test]
    fn malformed_chunk_extension_quotes_fail_closed() {
        for size_line in [
            b"1;foo=\"unterminated".as_slice(),
            b"1;foo=\"trailing\\".as_slice(),
        ] {
            let mut wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            wire.extend_from_slice(size_line);
            wire.extend_from_slice(b"\r\na\r\n0\r\n\r\n");
            assert!(matches!(
                decode_response(&wire, &Method::Get, &limits()),
                Err(TransportError::Protocol(_))
            ));
        }
    }

    #[test]
    fn head_and_no_body_statuses_reject_entity_bytes() {
        for (method, status) in [(&Method::Head, 200), (&Method::Get, 304)] {
            let wire = format!("HTTP/1.1 {status} Nope\r\nContent-Length: 9\r\n\r\n");
            let mut constrained = limits();
            constrained.max_response_body_bytes = 1;
            let decoded = decode_response(wire.as_bytes(), method, &constrained).unwrap();
            assert_eq!(decoded.framing, Framing::NoBody);
            assert!(decoded.body.is_empty());

            let with_entity = format!("HTTP/1.1 {status} Nope\r\nContent-Length: 2\r\n\r\nno");
            assert!(decode_response(with_entity.as_bytes(), method, &limits()).is_err());
        }
        for declared in ["0", "9"] {
            let forbidden =
                format!("HTTP/1.1 204 No Content\r\nContent-Length: {declared}\r\n\r\n");
            assert!(matches!(
                decode_response(forbidden.as_bytes(), &Method::Get, &limits()),
                Err(TransportError::Protocol(_))
            ));
        }
        let valid = b"HTTP/1.1 204 No Content\r\n\r\n";
        assert_eq!(
            decode_response(valid, &Method::Get, &limits())
                .unwrap()
                .framing,
            Framing::NoBody
        );
    }

    #[test]
    fn duplicate_response_content_length_is_rejected_by_scan_and_decode() {
        let wire = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n";
        assert!(matches!(
            decode_response(wire, &Method::Get, &limits()),
            Err(TransportError::Protocol(_))
        ));
        assert!(matches!(
            scan_response_completion(wire, &Method::Get, &limits(), false),
            Err(TransportError::Protocol(_))
        ));
    }

    #[test]
    fn status_line_does_not_consume_header_aggregate_budget() {
        let mut constrained = limits();
        constrained.max_header_aggregate_bytes = 4;
        constrained.max_header_name_bytes = 4;
        constrained.max_header_value_bytes = 4;
        constrained.max_response_head_bytes = 8 * 1024;
        let wire = b"HTTP/1.1 200 OK\r\n\r\n";
        let decoded = decode_response(wire, &Method::Get, &constrained).unwrap();
        assert_eq!(decoded.headers.len(), 0);
    }

    #[test]
    fn generic_line_limit_applies_to_chunked_trailers() {
        let mut constrained = limits();
        constrained.max_line_bytes = 8;
        constrained.max_chunk_line_bytes = 8;
        let wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX: 123456\r\n\r\n";
        assert!(matches!(
            decode_response(wire, &Method::Get, &constrained),
            Err(TransportError::ResourceLimit(_))
        ));
        assert!(matches!(
            scan_response_completion(wire, &Method::Get, &constrained, false),
            Err(TransportError::ResourceLimit(_))
        ));
    }

    #[test]
    fn response_without_length_is_close_delimited() {
        let wire = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nclose-body";
        let decoded = decode_response(wire, &Method::Get, &limits()).unwrap();
        assert_eq!(decoded.framing, Framing::CloseDelimited);
        assert_eq!(decoded.body, b"close-body");
    }

    #[test]
    fn request_preserves_bracketed_ipv6_authority() {
        let request = Request::new(Method::Get, Url::parse("http://[::1]:8080/path").unwrap());
        let encoded = encode_request(&request, &limits()).unwrap();
        let text = String::from_utf8(encoded.bytes).unwrap();
        assert!(text.contains("Host: [::1]:8080\r\n"));
    }

    #[test]
    fn malformed_and_conflicting_framing_fail_closed() {
        let malformed = b"HTTP/1.1 200 OK\r\nX: a\n\r\nbody";
        assert!(matches!(
            decode_response(malformed, &Method::Get, &limits()),
            Err(TransportError::Protocol(_))
        ));
        let conflict =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n";
        assert!(matches!(
            decode_response(conflict, &Method::Get, &limits()),
            Err(TransportError::Protocol(_))
        ));
        let folded = b"HTTP/1.1 200 OK\r\nX: a\r\n b\r\n\r\n";
        assert!(matches!(
            decode_response(folded, &Method::Get, &limits()),
            Err(TransportError::Protocol(_))
        ));
    }

    #[test]
    fn every_materialized_body_is_checked_before_copy() {
        let mut limits = limits();
        limits.max_response_body_bytes = 2;
        let content_length = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
        assert!(matches!(
            decode_response(content_length, &Method::Get, &limits),
            Err(TransportError::ResourceLimit(_))
        ));
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
        assert!(matches!(
            decode_response(chunked, &Method::Get, &limits),
            Err(TransportError::ResourceLimit(_))
        ));
    }
}
