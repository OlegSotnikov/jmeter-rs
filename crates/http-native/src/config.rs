// SPDX-License-Identifier: Apache-2.0
//! Bounded policy for the native synchronous HTTP/1.1 edge.
//!
//! This module contains sizes only.  Endpoint selection, credentials, TLS
//! identities, retry policy, and every other string or boolean policy belong
//! to the surrounding application/core layers.  Keeping this type numeric
//! also makes its [`Debug`] representation safe to use in diagnostics.

use jmeter_rs_http::TransportError;

// Decision 0006, `http.parser-limits/1`, gives the parser ceilings.  Keep the
// numbers here as compile-time constants so a native adapter cannot increase
// a bound by converting from a wider configuration type at runtime.  The
// request/response head ceilings include the corresponding request target or
// status line plus the aggregate header ceiling; wire totals remain the
// decision's request/response wire-body ceilings.
/// Decision 0006 hard maximum for addresses returned by one DNS lookup.
///
/// The decision requires bounded DNS state; the core's `MAX_DNS_SERVERS` is
/// the repository-wide ceiling for one resolver descriptor and is therefore
/// used here as the native edge ceiling.
pub const HARD_MAX_DNS_ADDRESSES: usize = 32;
/// Decision 0006 hard maximum for one request target.
pub const HARD_MAX_REQUEST_TARGET_BYTES: usize = 64 * 1024;
/// Decision 0006 hard maximum for one authority.
pub const HARD_MAX_AUTHORITY_BYTES: usize = 8 * 1024;
/// Decision 0006 hard maximum for one HTTP status line.
pub const HARD_MAX_STATUS_LINE_BYTES: usize = 8 * 1024;
/// Decision 0006 hard maximum for one reason phrase.
pub const HARD_MAX_REASON_BYTES: usize = 4 * 1024;
/// Decision 0006 hard maximum for aggregate header bytes.
pub const HARD_MAX_HEADER_AGGREGATE_BYTES: usize = 1024 * 1024;
/// Decision 0006 hard maximum for one request head.
pub const HARD_MAX_REQUEST_HEAD_BYTES: usize =
    HARD_MAX_HEADER_AGGREGATE_BYTES + HARD_MAX_REQUEST_TARGET_BYTES + HARD_MAX_AUTHORITY_BYTES;
/// Decision 0006 hard maximum for one response head.
pub const HARD_MAX_RESPONSE_HEAD_BYTES: usize =
    HARD_MAX_HEADER_AGGREGATE_BYTES + HARD_MAX_STATUS_LINE_BYTES;
/// Decision 0006 hard maximum for a request wire total.
pub const HARD_MAX_REQUEST_TOTAL_BYTES: usize = 64 * 1024 * 1024;
/// Alias for the request wire ceiling used by the request-body field.
pub const HARD_MAX_REQUEST_BODY_BYTES: usize = HARD_MAX_REQUEST_TOTAL_BYTES;
/// Decision 0006 hard maximum for a response wire body.
pub const HARD_MAX_RESPONSE_BODY_BYTES: usize = 256 * 1024 * 1024;
/// Decision 0006 hard maximum for a response wire total.
pub const HARD_MAX_RESPONSE_TOTAL_BYTES: usize = 256 * 1024 * 1024;
/// Decision 0006 hard maximum for header fields per message.
pub const HARD_MAX_HEADER_COUNT: usize = 1_024;
/// Decision 0006 hard maximum for one header name.
pub const HARD_MAX_HEADER_NAME_BYTES: usize = 8 * 1024;
/// Decision 0006 hard maximum for one header value.
pub const HARD_MAX_HEADER_VALUE_BYTES: usize = 64 * 1024;
/// Decision 0006 hard maximum for informational responses per message.
pub const HARD_MAX_INFORMATIONAL_COUNT: usize = 32;
/// Decision 0006 hard maximum for aggregate informational-response bytes.
pub const HARD_MAX_INFORMATIONAL_BYTES: usize = 256 * 1024;
/// Decision 0006 hard maximum for one chunk-size line.
pub const HARD_MAX_CHUNK_LINE_BYTES: usize = 8 * 1024;
/// Alias for the generic HTTP/1.1 line ceiling.
pub const HARD_MAX_LINE_BYTES: usize = HARD_MAX_CHUNK_LINE_BYTES;
/// Decision 0006 hard maximum for chunks in one message.
pub const HARD_MAX_CHUNK_COUNT: usize = 16_777_216;
/// Decision 0006 hard maximum for chunk extensions per chunk.
pub const HARD_MAX_CHUNK_EXTENSION_COUNT: usize = 128;
/// Decision 0006 hard maximum for chunk-extension bytes per chunk.
pub const HARD_MAX_CHUNK_EXTENSION_BYTES_PER_CHUNK: usize = 8 * 1024;
/// Decision 0006 hard maximum for aggregate chunk-extension bytes.
pub const HARD_MAX_CHUNK_EXTENSION_AGGREGATE_BYTES: usize = 64 * 1024;
/// Decision 0006 hard maximum for trailer fields per response.
pub const HARD_MAX_TRAILER_COUNT: usize = 256;
/// Decision 0006 hard maximum for one trailer name.
pub const HARD_MAX_TRAILER_NAME_BYTES: usize = 8 * 1024;
/// Decision 0006 hard maximum for one trailer value.
pub const HARD_MAX_TRAILER_VALUE_BYTES: usize = 64 * 1024;
/// Decision 0006 hard maximum for aggregate trailer bytes.
pub const HARD_MAX_TRAILER_AGGREGATE_BYTES: usize = 256 * 1024;
/// Native edge hard maximum for one I/O buffer.
///
/// Decision 0006 does not assign a separate wire category to an adapter's
/// scratch buffer.  One aggregate header block is the conservative ceiling:
/// it is finite, is already part of the decision's hard table, and prevents a
/// buffer setting from becoming a larger implicit parser allowance.
pub const HARD_MAX_IO_BUFFER_BYTES: usize = HARD_MAX_HEADER_AGGREGATE_BYTES;
/// Default generic line bound used by the synchronous HTTP/1.1 parser.
pub const DEFAULT_MAX_LINE_BYTES: usize = 4 * 1024;

// Compatibility aliases make the relationship to the terminology used by
// `ParserHardLimitsV1` explicit without adding policy fields or stringly
// options to `NativeTransportLimits`.
/// Alias for [`HARD_MAX_HEADER_COUNT`].
pub const HARD_MAX_HEADER_FIELDS: usize = HARD_MAX_HEADER_COUNT;
/// Alias for [`HARD_MAX_INFORMATIONAL_COUNT`].
pub const HARD_MAX_INFORMATIONAL_RESPONSES: usize = HARD_MAX_INFORMATIONAL_COUNT;
/// Alias for [`HARD_MAX_CHUNK_EXTENSION_COUNT`].
pub const HARD_MAX_CHUNK_EXTENSIONS: usize = HARD_MAX_CHUNK_EXTENSION_COUNT;
/// Alias for [`HARD_MAX_TRAILER_COUNT`].
pub const HARD_MAX_TRAILER_FIELDS: usize = HARD_MAX_TRAILER_COUNT;

/// Finite parser and buffering limits for one native HTTP/1.1 edge.
///
/// Every value is a byte/count capacity, never an endpoint, credential, or
/// feature switch.  Values are active limits and may be lowered from the
/// compile-time `HARD_MAX_*` ceilings, but zero and values above those
/// ceilings are rejected by [`Self::validate`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeTransportLimits {
    /// Maximum addresses retained from one DNS lookup.
    pub max_dns_addresses: usize,
    /// Maximum bytes retained for a request head.
    pub max_request_head_bytes: usize,
    /// Maximum request entity bytes.
    pub max_request_body_bytes: usize,
    /// Maximum request wire bytes, including head and body.
    pub max_request_total_bytes: usize,
    /// Maximum bytes retained for a response head.
    pub max_response_head_bytes: usize,
    /// Maximum response wire-body bytes.
    pub max_response_body_bytes: usize,
    /// Maximum response wire bytes, including head and body.
    pub max_response_total_bytes: usize,
    /// Maximum header fields in one message.
    pub max_header_count: usize,
    /// Maximum bytes in one header name.
    pub max_header_name_bytes: usize,
    /// Maximum bytes in one header value.
    pub max_header_value_bytes: usize,
    /// Maximum aggregate header bytes in one message.
    pub max_header_aggregate_bytes: usize,
    /// Maximum bytes in one status line.
    pub max_status_line_bytes: usize,
    /// Maximum bytes in one reason phrase.
    pub max_reason_bytes: usize,
    /// Maximum bytes in a generic HTTP/1.1 line.
    pub max_line_bytes: usize,
    /// Maximum informational responses before the final response.
    pub max_informational_count: usize,
    /// Maximum aggregate informational-response bytes.
    pub max_informational_bytes: usize,
    /// Maximum bytes in one chunk-size line.
    pub max_chunk_line_bytes: usize,
    /// Maximum chunks in one chunked message.
    pub max_chunk_count: usize,
    /// Maximum extensions on one chunk.
    pub max_chunk_extension_count: usize,
    /// Maximum extension bytes on one chunk.
    pub max_chunk_extension_bytes_per_chunk: usize,
    /// Maximum aggregate extension bytes in one chunked message.
    pub max_chunk_extension_aggregate_bytes: usize,
    /// Maximum trailer fields in one response.
    pub max_trailer_count: usize,
    /// Maximum bytes in one trailer name.
    pub max_trailer_name_bytes: usize,
    /// Maximum bytes in one trailer value.
    pub max_trailer_value_bytes: usize,
    /// Maximum aggregate trailer bytes in one response.
    pub max_trailer_aggregate_bytes: usize,
    /// Maximum retained scratch bytes for one synchronous I/O operation.
    pub max_io_buffer_bytes: usize,
}

impl Default for NativeTransportLimits {
    fn default() -> Self {
        Self {
            max_dns_addresses: 16,
            max_request_head_bytes: 256 * 1024,
            max_request_body_bytes: 16 * 1024 * 1024,
            max_request_total_bytes: 32 * 1024 * 1024,
            max_response_head_bytes: 256 * 1024,
            max_response_body_bytes: 32 * 1024 * 1024,
            max_response_total_bytes: 64 * 1024 * 1024,
            max_header_count: 128,
            max_header_name_bytes: 1024,
            max_header_value_bytes: 16 * 1024,
            max_header_aggregate_bytes: 256 * 1024,
            max_status_line_bytes: 4 * 1024,
            max_reason_bytes: 1024,
            max_line_bytes: DEFAULT_MAX_LINE_BYTES,
            max_informational_count: 8,
            max_informational_bytes: 64 * 1024,
            max_chunk_line_bytes: 2 * 1024,
            max_chunk_count: 1_000_000,
            max_chunk_extension_count: 32,
            max_chunk_extension_bytes_per_chunk: 2 * 1024,
            max_chunk_extension_aggregate_bytes: 16 * 1024,
            max_trailer_count: 64,
            max_trailer_name_bytes: 1024,
            max_trailer_value_bytes: 16 * 1024,
            max_trailer_aggregate_bytes: 64 * 1024,
            max_io_buffer_bytes: 16 * 1024,
        }
    }
}

impl NativeTransportLimits {
    /// Validates active values before a socket, parser, or allocation is used.
    ///
    /// Aggregate capacities are checked with `checked_add`; a malformed
    /// `usize` configuration therefore returns a typed resource-limit error
    /// rather than wrapping or panicking.
    pub fn validate(&self) -> Result<(), TransportError> {
        let scalar_limits = [
            (
                "max_dns_addresses",
                self.max_dns_addresses,
                HARD_MAX_DNS_ADDRESSES,
            ),
            (
                "max_request_head_bytes",
                self.max_request_head_bytes,
                HARD_MAX_REQUEST_HEAD_BYTES,
            ),
            (
                "max_request_body_bytes",
                self.max_request_body_bytes,
                HARD_MAX_REQUEST_BODY_BYTES,
            ),
            (
                "max_request_total_bytes",
                self.max_request_total_bytes,
                HARD_MAX_REQUEST_TOTAL_BYTES,
            ),
            (
                "max_response_head_bytes",
                self.max_response_head_bytes,
                HARD_MAX_RESPONSE_HEAD_BYTES,
            ),
            (
                "max_response_body_bytes",
                self.max_response_body_bytes,
                HARD_MAX_RESPONSE_BODY_BYTES,
            ),
            (
                "max_response_total_bytes",
                self.max_response_total_bytes,
                HARD_MAX_RESPONSE_TOTAL_BYTES,
            ),
            (
                "max_header_count",
                self.max_header_count,
                HARD_MAX_HEADER_COUNT,
            ),
            (
                "max_header_name_bytes",
                self.max_header_name_bytes,
                HARD_MAX_HEADER_NAME_BYTES,
            ),
            (
                "max_header_value_bytes",
                self.max_header_value_bytes,
                HARD_MAX_HEADER_VALUE_BYTES,
            ),
            (
                "max_header_aggregate_bytes",
                self.max_header_aggregate_bytes,
                HARD_MAX_HEADER_AGGREGATE_BYTES,
            ),
            (
                "max_status_line_bytes",
                self.max_status_line_bytes,
                HARD_MAX_STATUS_LINE_BYTES,
            ),
            (
                "max_reason_bytes",
                self.max_reason_bytes,
                HARD_MAX_REASON_BYTES,
            ),
            ("max_line_bytes", self.max_line_bytes, HARD_MAX_LINE_BYTES),
            (
                "max_informational_count",
                self.max_informational_count,
                HARD_MAX_INFORMATIONAL_COUNT,
            ),
            (
                "max_informational_bytes",
                self.max_informational_bytes,
                HARD_MAX_INFORMATIONAL_BYTES,
            ),
            (
                "max_chunk_line_bytes",
                self.max_chunk_line_bytes,
                HARD_MAX_CHUNK_LINE_BYTES,
            ),
            (
                "max_chunk_count",
                self.max_chunk_count,
                HARD_MAX_CHUNK_COUNT,
            ),
            (
                "max_chunk_extension_count",
                self.max_chunk_extension_count,
                HARD_MAX_CHUNK_EXTENSION_COUNT,
            ),
            (
                "max_chunk_extension_bytes_per_chunk",
                self.max_chunk_extension_bytes_per_chunk,
                HARD_MAX_CHUNK_EXTENSION_BYTES_PER_CHUNK,
            ),
            (
                "max_chunk_extension_aggregate_bytes",
                self.max_chunk_extension_aggregate_bytes,
                HARD_MAX_CHUNK_EXTENSION_AGGREGATE_BYTES,
            ),
            (
                "max_trailer_count",
                self.max_trailer_count,
                HARD_MAX_TRAILER_COUNT,
            ),
            (
                "max_trailer_name_bytes",
                self.max_trailer_name_bytes,
                HARD_MAX_TRAILER_NAME_BYTES,
            ),
            (
                "max_trailer_value_bytes",
                self.max_trailer_value_bytes,
                HARD_MAX_TRAILER_VALUE_BYTES,
            ),
            (
                "max_trailer_aggregate_bytes",
                self.max_trailer_aggregate_bytes,
                HARD_MAX_TRAILER_AGGREGATE_BYTES,
            ),
            (
                "max_io_buffer_bytes",
                self.max_io_buffer_bytes,
                HARD_MAX_IO_BUFFER_BYTES,
            ),
        ];
        for (name, value, maximum) in scalar_limits {
            if value == 0 {
                return Err(limit_error(name, "must be non-zero"));
            }
            if value > maximum {
                return Err(limit_error(name, "exceeds its hard maximum"));
            }
        }

        validate_sum(
            self.max_request_head_bytes,
            self.max_request_body_bytes,
            self.max_request_total_bytes,
            "request head plus body exceeds request total",
        )?;
        validate_sum(
            self.max_response_head_bytes,
            self.max_response_body_bytes,
            self.max_response_total_bytes,
            "response head plus body exceeds response total",
        )?;

        if self.max_header_aggregate_bytes > self.max_request_head_bytes
            || self.max_header_aggregate_bytes > self.max_response_head_bytes
        {
            return Err(limit_error(
                "max_header_aggregate_bytes",
                "must fit within both message-head limits",
            ));
        }
        if self.max_header_name_bytes > self.max_header_aggregate_bytes
            || self.max_header_value_bytes > self.max_header_aggregate_bytes
        {
            return Err(limit_error(
                "header field limits",
                "must fit within the aggregate header limit",
            ));
        }
        if self.max_status_line_bytes > self.max_response_head_bytes
            || self.max_reason_bytes > self.max_status_line_bytes
        {
            return Err(limit_error(
                "status/reason limits",
                "must fit within the response head and status-line limits",
            ));
        }
        if self.max_chunk_extension_bytes_per_chunk > self.max_chunk_extension_aggregate_bytes {
            return Err(limit_error(
                "chunk extension limits",
                "per-chunk bytes exceed aggregate bytes",
            ));
        }
        if self.max_informational_bytes > self.max_response_total_bytes {
            return Err(limit_error(
                "max_informational_bytes",
                "exceeds the response total limit",
            ));
        }
        if self.max_trailer_aggregate_bytes > self.max_response_total_bytes {
            return Err(limit_error(
                "max_trailer_aggregate_bytes",
                "exceeds the response total limit",
            ));
        }

        Ok(())
    }
}

fn validate_sum(
    left: usize,
    right: usize,
    total: usize,
    message: &'static str,
) -> Result<(), TransportError> {
    let sum = left
        .checked_add(right)
        .ok_or_else(|| limit_error("aggregate", "checked addition overflowed"))?;
    if sum > total {
        return Err(limit_error("aggregate", message));
    }
    Ok(())
}

fn limit_error(field: &str, reason: &str) -> TransportError {
    TransportError::ResourceLimit(format!("native HTTP limit {field} {reason}"))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::field_reassign_with_default,
        reason = "limit validation cases mutate one bounded field at a time"
    )]
    #![allow(
        clippy::type_complexity,
        reason = "the table keeps each named hard-limit validation case explicit"
    )]

    use super::*;

    fn valid_with(mut update: impl FnMut(&mut NativeTransportLimits)) -> NativeTransportLimits {
        let mut limits = NativeTransportLimits::default();
        update(&mut limits);
        limits
    }

    #[test]
    fn defaults_are_valid_and_debug_contains_only_sizes() {
        let limits = NativeTransportLimits::default();
        assert!(limits.validate().is_ok());
        let debug = format!("{limits:?}");
        assert!(!debug.contains("endpoint"));
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("password"));
    }

    #[test]
    fn every_limit_rejects_zero() {
        let mut cases: Vec<(&str, Box<dyn Fn(&mut NativeTransportLimits)>)> = vec![
            ("dns", Box::new(|v| v.max_dns_addresses = 0)),
            ("request-head", Box::new(|v| v.max_request_head_bytes = 0)),
            ("request-body", Box::new(|v| v.max_request_body_bytes = 0)),
            ("request-total", Box::new(|v| v.max_request_total_bytes = 0)),
            ("response-head", Box::new(|v| v.max_response_head_bytes = 0)),
            ("response-body", Box::new(|v| v.max_response_body_bytes = 0)),
            (
                "response-total",
                Box::new(|v| v.max_response_total_bytes = 0),
            ),
            ("header-count", Box::new(|v| v.max_header_count = 0)),
            ("header-name", Box::new(|v| v.max_header_name_bytes = 0)),
            ("header-value", Box::new(|v| v.max_header_value_bytes = 0)),
            (
                "header-aggregate",
                Box::new(|v| v.max_header_aggregate_bytes = 0),
            ),
            ("status-line", Box::new(|v| v.max_status_line_bytes = 0)),
            ("reason", Box::new(|v| v.max_reason_bytes = 0)),
            ("line", Box::new(|v| v.max_line_bytes = 0)),
            (
                "informational-count",
                Box::new(|v| v.max_informational_count = 0),
            ),
            (
                "informational-bytes",
                Box::new(|v| v.max_informational_bytes = 0),
            ),
            ("chunk-line", Box::new(|v| v.max_chunk_line_bytes = 0)),
            ("chunk-count", Box::new(|v| v.max_chunk_count = 0)),
            (
                "chunk-extension-count",
                Box::new(|v| v.max_chunk_extension_count = 0),
            ),
            (
                "chunk-extension-bytes",
                Box::new(|v| v.max_chunk_extension_bytes_per_chunk = 0),
            ),
            (
                "chunk-extension-aggregate",
                Box::new(|v| v.max_chunk_extension_aggregate_bytes = 0),
            ),
            ("trailer-count", Box::new(|v| v.max_trailer_count = 0)),
            ("trailer-name", Box::new(|v| v.max_trailer_name_bytes = 0)),
            ("trailer-value", Box::new(|v| v.max_trailer_value_bytes = 0)),
            (
                "trailer-aggregate",
                Box::new(|v| v.max_trailer_aggregate_bytes = 0),
            ),
            ("io-buffer", Box::new(|v| v.max_io_buffer_bytes = 0)),
        ];
        for (name, set_zero) in cases.drain(..) {
            let mut limits = NativeTransportLimits::default();
            set_zero(&mut limits);
            assert!(limits.validate().is_err(), "{name} accepted zero");
        }
    }

    #[test]
    fn every_limit_rejects_values_above_its_hard_ceiling() {
        let mut cases: Vec<(&str, Box<dyn Fn(&mut NativeTransportLimits)>)> = vec![
            (
                "dns",
                Box::new(|v| v.max_dns_addresses = HARD_MAX_DNS_ADDRESSES + 1),
            ),
            (
                "request-head",
                Box::new(|v| v.max_request_head_bytes = HARD_MAX_REQUEST_HEAD_BYTES + 1),
            ),
            (
                "request-body",
                Box::new(|v| v.max_request_body_bytes = HARD_MAX_REQUEST_TOTAL_BYTES + 1),
            ),
            (
                "request-total",
                Box::new(|v| v.max_request_total_bytes = HARD_MAX_REQUEST_TOTAL_BYTES + 1),
            ),
            (
                "response-head",
                Box::new(|v| v.max_response_head_bytes = HARD_MAX_RESPONSE_HEAD_BYTES + 1),
            ),
            (
                "response-body",
                Box::new(|v| v.max_response_body_bytes = HARD_MAX_RESPONSE_BODY_BYTES + 1),
            ),
            (
                "response-total",
                Box::new(|v| v.max_response_total_bytes = HARD_MAX_RESPONSE_TOTAL_BYTES + 1),
            ),
            (
                "header-count",
                Box::new(|v| v.max_header_count = HARD_MAX_HEADER_COUNT + 1),
            ),
            (
                "header-name",
                Box::new(|v| v.max_header_name_bytes = HARD_MAX_HEADER_NAME_BYTES + 1),
            ),
            (
                "header-value",
                Box::new(|v| v.max_header_value_bytes = HARD_MAX_HEADER_VALUE_BYTES + 1),
            ),
            (
                "header-aggregate",
                Box::new(|v| v.max_header_aggregate_bytes = HARD_MAX_HEADER_AGGREGATE_BYTES + 1),
            ),
            (
                "status-line",
                Box::new(|v| v.max_status_line_bytes = HARD_MAX_STATUS_LINE_BYTES + 1),
            ),
            (
                "reason",
                Box::new(|v| v.max_reason_bytes = HARD_MAX_REASON_BYTES + 1),
            ),
            (
                "line",
                Box::new(|v| v.max_line_bytes = HARD_MAX_CHUNK_LINE_BYTES + 1),
            ),
            (
                "informational-count",
                Box::new(|v| v.max_informational_count = HARD_MAX_INFORMATIONAL_COUNT + 1),
            ),
            (
                "informational-bytes",
                Box::new(|v| v.max_informational_bytes = HARD_MAX_INFORMATIONAL_BYTES + 1),
            ),
            (
                "chunk-line",
                Box::new(|v| v.max_chunk_line_bytes = HARD_MAX_CHUNK_LINE_BYTES + 1),
            ),
            (
                "chunk-count",
                Box::new(|v| v.max_chunk_count = HARD_MAX_CHUNK_COUNT + 1),
            ),
            (
                "chunk-extension-count",
                Box::new(|v| v.max_chunk_extension_count = HARD_MAX_CHUNK_EXTENSION_COUNT + 1),
            ),
            (
                "chunk-extension-bytes",
                Box::new(|v| {
                    v.max_chunk_extension_bytes_per_chunk =
                        HARD_MAX_CHUNK_EXTENSION_BYTES_PER_CHUNK + 1
                }),
            ),
            (
                "chunk-extension-aggregate",
                Box::new(|v| {
                    v.max_chunk_extension_aggregate_bytes =
                        HARD_MAX_CHUNK_EXTENSION_AGGREGATE_BYTES + 1
                }),
            ),
            (
                "trailer-count",
                Box::new(|v| v.max_trailer_count = HARD_MAX_TRAILER_COUNT + 1),
            ),
            (
                "trailer-name",
                Box::new(|v| v.max_trailer_name_bytes = HARD_MAX_TRAILER_NAME_BYTES + 1),
            ),
            (
                "trailer-value",
                Box::new(|v| v.max_trailer_value_bytes = HARD_MAX_TRAILER_VALUE_BYTES + 1),
            ),
            (
                "trailer-aggregate",
                Box::new(|v| v.max_trailer_aggregate_bytes = HARD_MAX_TRAILER_AGGREGATE_BYTES + 1),
            ),
            (
                "io-buffer",
                Box::new(|v| v.max_io_buffer_bytes = HARD_MAX_IO_BUFFER_BYTES + 1),
            ),
        ];
        for (name, set_above) in cases.drain(..) {
            let mut limits = NativeTransportLimits::default();
            set_above(&mut limits);
            assert!(limits.validate().is_err(), "{name} accepted above hard max");
        }
    }

    #[test]
    fn exact_hard_bounds_are_accepted_when_aggregate_limits_fit() {
        let limits = valid_with(|v| {
            v.max_dns_addresses = HARD_MAX_DNS_ADDRESSES;
            v.max_request_head_bytes = HARD_MAX_REQUEST_HEAD_BYTES;
            v.max_request_body_bytes = HARD_MAX_REQUEST_TOTAL_BYTES - HARD_MAX_REQUEST_HEAD_BYTES;
            v.max_request_total_bytes = HARD_MAX_REQUEST_TOTAL_BYTES;
            v.max_response_head_bytes = HARD_MAX_RESPONSE_HEAD_BYTES;
            v.max_response_body_bytes = HARD_MAX_RESPONSE_BODY_BYTES - HARD_MAX_RESPONSE_HEAD_BYTES;
            v.max_response_total_bytes = HARD_MAX_RESPONSE_TOTAL_BYTES;
            v.max_header_count = HARD_MAX_HEADER_COUNT;
            v.max_header_name_bytes = HARD_MAX_HEADER_NAME_BYTES;
            v.max_header_value_bytes = HARD_MAX_HEADER_VALUE_BYTES;
            v.max_header_aggregate_bytes = HARD_MAX_HEADER_AGGREGATE_BYTES;
            v.max_status_line_bytes = HARD_MAX_STATUS_LINE_BYTES;
            v.max_reason_bytes = HARD_MAX_REASON_BYTES;
            v.max_line_bytes = HARD_MAX_CHUNK_LINE_BYTES;
            v.max_informational_count = HARD_MAX_INFORMATIONAL_COUNT;
            v.max_informational_bytes = HARD_MAX_INFORMATIONAL_BYTES;
            v.max_chunk_line_bytes = HARD_MAX_CHUNK_LINE_BYTES;
            v.max_chunk_count = HARD_MAX_CHUNK_COUNT;
            v.max_chunk_extension_count = HARD_MAX_CHUNK_EXTENSION_COUNT;
            v.max_chunk_extension_bytes_per_chunk = HARD_MAX_CHUNK_EXTENSION_BYTES_PER_CHUNK;
            v.max_chunk_extension_aggregate_bytes = HARD_MAX_CHUNK_EXTENSION_AGGREGATE_BYTES;
            v.max_trailer_count = HARD_MAX_TRAILER_COUNT;
            v.max_trailer_name_bytes = HARD_MAX_TRAILER_NAME_BYTES;
            v.max_trailer_value_bytes = HARD_MAX_TRAILER_VALUE_BYTES;
            v.max_trailer_aggregate_bytes = HARD_MAX_TRAILER_AGGREGATE_BYTES;
            v.max_io_buffer_bytes = HARD_MAX_IO_BUFFER_BYTES;
        });
        assert!(limits.validate().is_ok());
    }

    #[test]
    fn aggregate_inconsistencies_are_rejected() {
        let mut limits = NativeTransportLimits::default();
        limits.max_request_total_bytes = limits.max_request_head_bytes;
        assert!(limits.validate().is_err());

        let mut limits = NativeTransportLimits::default();
        limits.max_response_total_bytes = limits.max_response_head_bytes;
        assert!(limits.validate().is_err());

        let mut limits = NativeTransportLimits::default();
        limits.max_header_aggregate_bytes = limits.max_request_head_bytes + 1;
        assert!(limits.validate().is_err());

        let mut limits = NativeTransportLimits::default();
        limits.max_chunk_extension_bytes_per_chunk = limits.max_chunk_extension_aggregate_bytes + 1;
        assert!(limits.validate().is_err());

        let mut limits = NativeTransportLimits::default();
        limits.max_reason_bytes = limits.max_status_line_bytes + 1;
        assert!(limits.validate().is_err());
    }

    #[test]
    fn validation_is_overflow_safe_for_usize_values() {
        let mut limits = NativeTransportLimits::default();
        limits.max_request_head_bytes = usize::MAX;
        assert!(limits.validate().is_err());

        let mut limits = NativeTransportLimits::default();
        limits.max_request_body_bytes = usize::MAX;
        assert!(limits.validate().is_err());

        let mut limits = NativeTransportLimits::default();
        limits.max_response_total_bytes = usize::MAX;
        assert!(limits.validate().is_err());
    }
}
