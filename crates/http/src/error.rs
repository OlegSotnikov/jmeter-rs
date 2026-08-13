// SPDX-License-Identifier: Apache-2.0
//! Stable errors for the HTTP semantic boundary.

use core::fmt;

use crate::ErrorContextV1;

/// Maximum bytes in one provider diagnostic retained by the HTTP boundary.
pub const MAX_ERROR_DIAGNOSTIC_BYTES: usize = 4 * 1024;
/// Maximum aggregate bytes retained by one operation's diagnostics.
pub const MAX_ERROR_DIAGNOSTIC_AGGREGATE_BYTES: usize = 64 * 1024;
/// Maximum diagnostic records retained by one operation.
pub const MAX_ERROR_DIAGNOSTICS: usize = 64;
/// Maximum context wrappers traversed when classifying an HTTP error.
///
/// [`HttpError::with_context`] keeps normal construction at one wrapper, but
/// the public enum can still be assembled directly.  Classification and
/// formatting therefore stop at a finite depth instead of allowing an
/// adversarial nested value to exhaust the stack.
pub const MAX_HTTP_ERROR_CONTEXT_DEPTH: usize = 16;

/// Closed retryability classification for one HTTP attempt.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Retryability {
    /// The transport could not prove that replay is safe.
    Unknown,
    /// A retry can make progress when the body policy allows it.
    Retryable,
    /// Retrying is forbidden or cannot make progress.
    Terminal,
}

impl Retryability {
    /// Every retry classification in this revision.
    pub const ALL: &[Self] = &[Self::Unknown, Self::Retryable, Self::Terminal];

    /// Returns the stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Retryable => "retryable",
            Self::Terminal => "terminal",
        }
    }

    /// Returns whether this value alone authorizes a retry.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::Retryable)
    }

    /// Returns whether retrying is forbidden or unproved by this value.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        !self.is_retryable()
    }

    /// Parses a canonical retry classification.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "unknown" => Self::Unknown,
            "retryable" => Self::Retryable,
            "terminal" => Self::Terminal,
            _ => return None,
        })
    }
}

impl fmt::Display for Retryability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl core::str::FromStr for Retryability {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value).ok_or(())
    }
}

/// Closed diagnostic categories accepted by the HTTP error context.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HttpDiagnosticCode {
    /// Detail from a selected provider or client library.
    Provider,
    /// Detail about malformed or unsupported wire syntax.
    ProtocolDetail,
    /// Detail associated with a finite parser/resource limit.
    LimitObservation,
    /// A capability, route, or identity did not match.
    IdentityMismatch,
    /// Cleanup or lease-release detail.
    Cleanup,
    /// A second failure preserved alongside a primary failure.
    SecondaryFailure,
}

impl HttpDiagnosticCode {
    /// Every diagnostic category in this revision.
    pub const ALL: &[Self] = &[
        Self::Provider,
        Self::ProtocolDetail,
        Self::LimitObservation,
        Self::IdentityMismatch,
        Self::Cleanup,
        Self::SecondaryFailure,
    ];

    /// Returns the stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Provider => "provider",
            Self::ProtocolDetail => "protocol-detail",
            Self::LimitObservation => "limit-observation",
            Self::IdentityMismatch => "identity-mismatch",
            Self::Cleanup => "cleanup",
            Self::SecondaryFailure => "secondary-failure",
        }
    }

    /// Parses a canonical diagnostic category.
    ///
    /// This inherent spelling is retained for the protocol-v1 decoder, which
    /// is an out-of-scope compatibility seam and calls the associated method
    /// without importing [`core::str::FromStr`]. New callers may use
    /// `value.parse::<HttpDiagnosticCode>()`.
    #[allow(
        clippy::should_implement_trait,
        reason = "protocol_v1 retains this source-compatible associated parser"
    )]
    #[must_use]
    pub fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "provider" => Self::Provider,
            "protocol-detail" => Self::ProtocolDetail,
            "limit-observation" => Self::LimitObservation,
            "identity-mismatch" => Self::IdentityMismatch,
            "cleanup" => Self::Cleanup,
            "secondary-failure" => Self::SecondaryFailure,
            _ => return None,
        })
    }
}

impl fmt::Display for HttpDiagnosticCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl core::str::FromStr for HttpDiagnosticCode {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_str(value).ok_or(())
    }
}

/// Closed parser/resource-limit vocabulary from Decision 0006.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HttpLimitCode {
    /// Request target length.
    RequestTarget = 1,
    /// Authority length.
    Authority,
    /// Status-line length.
    StatusLine,
    /// Reason-phrase length.
    Reason,
    /// Header field count.
    HeaderCount,
    /// Header name length.
    HeaderName,
    /// Header value length.
    HeaderValue,
    /// Aggregate header bytes.
    HeaderAggregate,
    /// Informational-response count.
    InformationalCount,
    /// Aggregate informational-response bytes.
    InformationalAggregate,
    /// Trailer field count.
    TrailerCount,
    /// Trailer name length.
    TrailerName,
    /// Trailer value length.
    TrailerValue,
    /// Aggregate trailer bytes.
    TrailerAggregate,
    /// Chunk framing-line length.
    ChunkLine,
    /// Chunk count.
    ChunkCount,
    /// Chunk extension count.
    ChunkExtensionCount,
    /// Chunk extension bytes per chunk.
    ChunkExtensionBytesPerChunk,
    /// Aggregate chunk-extension bytes.
    ChunkExtensionAggregate,
    /// Wire request-body bytes.
    WireRequestBody,
    /// Wire response-body bytes.
    WireResponseBody,
    /// Declared content length.
    ContentLength,
    /// Compressed input bytes.
    CompressedInput,
    /// Decoded output bytes.
    DecodedOutput,
    /// Decompression expansion ratio.
    ExpansionRatio,
    /// Retained codec state bytes.
    CodecState,
    /// URL-encoded field count.
    UrlFieldCount,
    /// URL-encoded aggregate bytes.
    UrlFieldBytes,
    /// Multipart part count.
    MultipartPartCount,
    /// Multipart boundary length.
    MultipartBoundary,
    /// Multipart part-header bytes.
    MultipartPartHeaders,
    /// Multipart part-body bytes.
    MultipartPartBody,
    /// Redirect hop count.
    RedirectCount,
    /// Retained redirect bytes.
    RedirectRetained,
    /// Embedded-resource candidate count.
    EmbeddedCandidateCount,
    /// Embedded-resource nesting depth.
    EmbeddedDepth,
    /// Embedded-resource concurrency.
    EmbeddedConcurrency,
    /// Retained embedded-resource bytes.
    EmbeddedRetained,
    /// Trace-record count.
    TraceCount,
    /// Aggregate trace bytes.
    TraceBytes,
    /// Diagnostic-record count.
    DiagnosticCount,
    /// One diagnostic text length.
    DiagnosticText,
    /// Aggregate diagnostic bytes.
    DiagnosticAggregate,
}

impl HttpLimitCode {
    /// Every parser/resource-limit category in canonical profile order.
    pub const ALL: &[Self] = &[
        Self::RequestTarget,
        Self::Authority,
        Self::StatusLine,
        Self::Reason,
        Self::HeaderCount,
        Self::HeaderName,
        Self::HeaderValue,
        Self::HeaderAggregate,
        Self::InformationalCount,
        Self::InformationalAggregate,
        Self::TrailerCount,
        Self::TrailerName,
        Self::TrailerValue,
        Self::TrailerAggregate,
        Self::ChunkLine,
        Self::ChunkCount,
        Self::ChunkExtensionCount,
        Self::ChunkExtensionBytesPerChunk,
        Self::ChunkExtensionAggregate,
        Self::WireRequestBody,
        Self::WireResponseBody,
        Self::ContentLength,
        Self::CompressedInput,
        Self::DecodedOutput,
        Self::ExpansionRatio,
        Self::CodecState,
        Self::UrlFieldCount,
        Self::UrlFieldBytes,
        Self::MultipartPartCount,
        Self::MultipartBoundary,
        Self::MultipartPartHeaders,
        Self::MultipartPartBody,
        Self::RedirectCount,
        Self::RedirectRetained,
        Self::EmbeddedCandidateCount,
        Self::EmbeddedDepth,
        Self::EmbeddedConcurrency,
        Self::EmbeddedRetained,
        Self::TraceCount,
        Self::TraceBytes,
        Self::DiagnosticCount,
        Self::DiagnosticText,
        Self::DiagnosticAggregate,
    ];

    /// Returns the stable dotted code used in evidence and diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RequestTarget => "http.limit.request-target",
            Self::Authority => "http.limit.authority",
            Self::StatusLine => "http.limit.status-line",
            Self::Reason => "http.limit.reason",
            Self::HeaderCount => "http.limit.header-count",
            Self::HeaderName => "http.limit.header-name",
            Self::HeaderValue => "http.limit.header-value",
            Self::HeaderAggregate => "http.limit.header-aggregate",
            Self::InformationalCount => "http.limit.informational-count",
            Self::InformationalAggregate => "http.limit.informational-aggregate",
            Self::TrailerCount => "http.limit.trailer-count",
            Self::TrailerName => "http.limit.trailer-name",
            Self::TrailerValue => "http.limit.trailer-value",
            Self::TrailerAggregate => "http.limit.trailer-aggregate",
            Self::ChunkLine => "http.limit.chunk-line",
            Self::ChunkCount => "http.limit.chunk-count",
            Self::ChunkExtensionCount => "http.limit.chunk-extension-count",
            Self::ChunkExtensionBytesPerChunk => "http.limit.chunk-extension-bytes-per-chunk",
            Self::ChunkExtensionAggregate => "http.limit.chunk-extension-aggregate",
            Self::WireRequestBody => "http.limit.wire-request-body",
            Self::WireResponseBody => "http.limit.wire-response-body",
            Self::ContentLength => "http.limit.content-length",
            Self::CompressedInput => "http.limit.compressed-input",
            Self::DecodedOutput => "http.limit.decoded-output",
            Self::ExpansionRatio => "http.limit.expansion-ratio",
            Self::CodecState => "http.limit.codec-state",
            Self::UrlFieldCount => "http.limit.url-field-count",
            Self::UrlFieldBytes => "http.limit.url-field-bytes",
            Self::MultipartPartCount => "http.limit.multipart-part-count",
            Self::MultipartBoundary => "http.limit.multipart-boundary",
            Self::MultipartPartHeaders => "http.limit.multipart-part-headers",
            Self::MultipartPartBody => "http.limit.multipart-part-body",
            Self::RedirectCount => "http.limit.redirect-count",
            Self::RedirectRetained => "http.limit.redirect-retained",
            Self::EmbeddedCandidateCount => "http.limit.embedded-candidate-count",
            Self::EmbeddedDepth => "http.limit.embedded-depth",
            Self::EmbeddedConcurrency => "http.limit.embedded-concurrency",
            Self::EmbeddedRetained => "http.limit.embedded-retained",
            Self::TraceCount => "http.limit.trace-count",
            Self::TraceBytes => "http.limit.trace-bytes",
            Self::DiagnosticCount => "http.limit.diagnostic-count",
            Self::DiagnosticText => "http.limit.diagnostic-text",
            Self::DiagnosticAggregate => "http.limit.diagnostic-aggregate",
        }
    }

    /// Returns the fixed numeric discriminant.
    #[must_use]
    pub const fn discriminant(self) -> u16 {
        self as u16
    }

    /// Parses only a canonical code or its bare profile-defined suffix.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.strip_prefix("http.limit.").unwrap_or(value);
        Some(match value {
            "request-target" => Self::RequestTarget,
            "authority" => Self::Authority,
            "status-line" => Self::StatusLine,
            "reason" => Self::Reason,
            "header-count" => Self::HeaderCount,
            "header-name" => Self::HeaderName,
            "header-value" => Self::HeaderValue,
            "header-aggregate" => Self::HeaderAggregate,
            "informational-count" => Self::InformationalCount,
            "informational-aggregate" => Self::InformationalAggregate,
            "trailer-count" => Self::TrailerCount,
            "trailer-name" => Self::TrailerName,
            "trailer-value" => Self::TrailerValue,
            "trailer-aggregate" => Self::TrailerAggregate,
            "chunk-line" => Self::ChunkLine,
            "chunk-count" => Self::ChunkCount,
            "chunk-extension-count" => Self::ChunkExtensionCount,
            "chunk-extension-bytes-per-chunk" => Self::ChunkExtensionBytesPerChunk,
            "chunk-extension-aggregate" => Self::ChunkExtensionAggregate,
            "wire-request-body" => Self::WireRequestBody,
            "wire-response-body" => Self::WireResponseBody,
            "content-length" => Self::ContentLength,
            "compressed-input" => Self::CompressedInput,
            "decoded-output" => Self::DecodedOutput,
            "expansion-ratio" => Self::ExpansionRatio,
            "codec-state" => Self::CodecState,
            "url-field-count" => Self::UrlFieldCount,
            "url-field-bytes" => Self::UrlFieldBytes,
            "multipart-part-count" => Self::MultipartPartCount,
            "multipart-boundary" => Self::MultipartBoundary,
            "multipart-part-headers" => Self::MultipartPartHeaders,
            "multipart-part-body" => Self::MultipartPartBody,
            "redirect-count" => Self::RedirectCount,
            "redirect-retained" => Self::RedirectRetained,
            "embedded-candidate-count" => Self::EmbeddedCandidateCount,
            "embedded-depth" => Self::EmbeddedDepth,
            "embedded-concurrency" => Self::EmbeddedConcurrency,
            "embedded-retained" => Self::EmbeddedRetained,
            "trace-count" => Self::TraceCount,
            "trace-bytes" => Self::TraceBytes,
            "diagnostic-count" => Self::DiagnosticCount,
            "diagnostic-text" => Self::DiagnosticText,
            "diagnostic-aggregate" => Self::DiagnosticAggregate,
            _ => return None,
        })
    }

    /// Parses a canonical stable limit code.
    #[must_use]
    pub fn from_stable_code(value: &str) -> Option<Self> {
        value
            .starts_with("http.limit.")
            .then(|| Self::parse(value))
            .flatten()
    }

    /// Parses a provider/parser description into a closed limit category.
    ///
    /// This intentionally remains private: aliases are accepted only at the
    /// boundary where descriptive provider prose is normalized.  Wire and
    /// evidence-facing parsers use [`Self::parse`] and accept canonical
    /// spellings only.
    fn from_message(value: &str) -> Option<Self> {
        Self::parse(value).or_else(|| {
            Some(match value {
                "header-fields" => Self::HeaderCount,
                "informational" => Self::InformationalCount,
                "trailer-fields" | "trailers" => Self::TrailerCount,
                "chunk-framing" => Self::ChunkLine,
                "chunk-extensions" => Self::ChunkExtensionCount,
                "chunk-extension-bytes" => Self::ChunkExtensionAggregate,
                "wire-request" => Self::WireRequestBody,
                "wire-response" | "wire-body" => Self::WireResponseBody,
                "decompressed-output-bytes" => Self::DecodedOutput,
                "decompression-ratio" => Self::ExpansionRatio,
                "urlencoded-fields" => Self::UrlFieldCount,
                "urlencoded-aggregate" => Self::UrlFieldBytes,
                "multipart-parts" => Self::MultipartPartCount,
                "multipart-boundary-bytes" => Self::MultipartBoundary,
                "multipart-header-bytes" => Self::MultipartPartHeaders,
                "multipart-body-bytes" => Self::MultipartPartBody,
                "redirect-hops" | "redirects" => Self::RedirectCount,
                "redirect-retained-bytes" => Self::RedirectRetained,
                "embedded-candidates" => Self::EmbeddedCandidateCount,
                "embedded-retained-bytes" => Self::EmbeddedRetained,
                "trace-records" => Self::TraceCount,
                "trace-aggregate" => Self::TraceBytes,
                "diagnostic-text-bytes" => Self::DiagnosticText,
                _ => return None,
            })
        })
    }
}

impl fmt::Display for HttpLimitCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl core::str::FromStr for HttpLimitCode {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value).ok_or(())
    }
}

impl TryFrom<u8> for HttpLimitCode {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::RequestTarget),
            2 => Ok(Self::Authority),
            3 => Ok(Self::StatusLine),
            4 => Ok(Self::Reason),
            5 => Ok(Self::HeaderCount),
            6 => Ok(Self::HeaderName),
            7 => Ok(Self::HeaderValue),
            8 => Ok(Self::HeaderAggregate),
            9 => Ok(Self::InformationalCount),
            10 => Ok(Self::InformationalAggregate),
            11 => Ok(Self::TrailerCount),
            12 => Ok(Self::TrailerName),
            13 => Ok(Self::TrailerValue),
            14 => Ok(Self::TrailerAggregate),
            15 => Ok(Self::ChunkLine),
            16 => Ok(Self::ChunkCount),
            17 => Ok(Self::ChunkExtensionCount),
            18 => Ok(Self::ChunkExtensionBytesPerChunk),
            19 => Ok(Self::ChunkExtensionAggregate),
            20 => Ok(Self::WireRequestBody),
            21 => Ok(Self::WireResponseBody),
            22 => Ok(Self::ContentLength),
            23 => Ok(Self::CompressedInput),
            24 => Ok(Self::DecodedOutput),
            25 => Ok(Self::ExpansionRatio),
            26 => Ok(Self::CodecState),
            27 => Ok(Self::UrlFieldCount),
            28 => Ok(Self::UrlFieldBytes),
            29 => Ok(Self::MultipartPartCount),
            30 => Ok(Self::MultipartBoundary),
            31 => Ok(Self::MultipartPartHeaders),
            32 => Ok(Self::MultipartPartBody),
            33 => Ok(Self::RedirectCount),
            34 => Ok(Self::RedirectRetained),
            35 => Ok(Self::EmbeddedCandidateCount),
            36 => Ok(Self::EmbeddedDepth),
            37 => Ok(Self::EmbeddedConcurrency),
            38 => Ok(Self::EmbeddedRetained),
            39 => Ok(Self::TraceCount),
            40 => Ok(Self::TraceBytes),
            41 => Ok(Self::DiagnosticCount),
            42 => Ok(Self::DiagnosticText),
            43 => Ok(Self::DiagnosticAggregate),
            _ => Err(()),
        }
    }
}

/// Closed stable HTTP error categories from Decision 0006.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum StableHttpErrorCode {
    /// DNS resolution failure.
    Dns,
    /// Connection-pool failure.
    Pool,
    /// Connection establishment failure.
    Connect,
    /// Proxy routing or handshake failure.
    Proxy,
    /// TLS policy or handshake failure.
    Tls,
    /// Request write failure.
    Write,
    /// Response read failure.
    Read,
    /// HTTP framing failure.
    Framing,
    /// Content decompression failure.
    Decompression,
    /// Operation deadline exceeded.
    Timeout,
    /// Explicit cancellation.
    Cancelled,
    /// Request body cannot be replayed.
    BodyReplay,
    /// Response body state failure.
    BodyState,
    /// Response lease failure.
    ResponseLease,
    /// User-state compare-and-swap conflict.
    StateConflict,
    /// Requested implementation is unavailable.
    UnsupportedImplementation,
    /// Requested authentication is unavailable.
    UnsupportedAuth,
    /// Requested key-store is unavailable.
    UnsupportedStore,
    /// Adapter automation was not disabled/proven.
    AutomationEnabled,
    /// Budget configuration is invalid.
    BudgetInvalid,
    /// Recorder failure.
    Recorder,
    /// Mirror-server failure.
    Mirror,
    /// Internal invariant failure.
    InternalInvariant,
    /// A closed parser/resource limit.
    Limit(HttpLimitCode),
    /// URL validation failure.
    InvalidUrl,
    /// Method validation failure.
    InvalidMethod,
    /// Header validation failure.
    InvalidHeader,
    /// Request-body limit failure.
    RequestBodyLimit,
    /// Response-body limit failure.
    ResponseBodyLimit,
    /// Timeout configuration failure.
    InvalidTimeout,
    /// Redirect-location validation failure.
    InvalidRedirect,
    /// Redirect policy limit failure.
    RedirectLimit,
    /// Redirect origin policy denial.
    RedirectOriginDenied,
    /// Cookie state failure.
    Cookie,
    /// Cache state failure.
    Cache,
    /// Authentication state failure.
    Authentication,
    /// Generic unsupported operation.
    Unsupported,
    /// Peer reset/closed connection.
    Reset,
    /// Adapter supplied an invalid request.
    InvalidRequest,
    /// Adapter-local error.
    Adapter,
}

impl StableHttpErrorCode {
    /// Every stable error category admitted by Decision 0006 plus the
    /// pre-existing semantic categories retained for local API compatibility.
    pub const ALL: &[Self] = &[
        Self::Dns,
        Self::Pool,
        Self::Connect,
        Self::Proxy,
        Self::Tls,
        Self::Write,
        Self::Read,
        Self::Framing,
        Self::Decompression,
        Self::Timeout,
        Self::Cancelled,
        Self::BodyReplay,
        Self::BodyState,
        Self::ResponseLease,
        Self::StateConflict,
        Self::UnsupportedImplementation,
        Self::UnsupportedAuth,
        Self::UnsupportedStore,
        Self::AutomationEnabled,
        Self::BudgetInvalid,
        Self::Recorder,
        Self::Mirror,
        Self::InternalInvariant,
        Self::Limit(HttpLimitCode::RequestTarget),
        Self::Limit(HttpLimitCode::Authority),
        Self::Limit(HttpLimitCode::StatusLine),
        Self::Limit(HttpLimitCode::Reason),
        Self::Limit(HttpLimitCode::HeaderCount),
        Self::Limit(HttpLimitCode::HeaderName),
        Self::Limit(HttpLimitCode::HeaderValue),
        Self::Limit(HttpLimitCode::HeaderAggregate),
        Self::Limit(HttpLimitCode::InformationalCount),
        Self::Limit(HttpLimitCode::InformationalAggregate),
        Self::Limit(HttpLimitCode::TrailerCount),
        Self::Limit(HttpLimitCode::TrailerName),
        Self::Limit(HttpLimitCode::TrailerValue),
        Self::Limit(HttpLimitCode::TrailerAggregate),
        Self::Limit(HttpLimitCode::ChunkLine),
        Self::Limit(HttpLimitCode::ChunkCount),
        Self::Limit(HttpLimitCode::ChunkExtensionCount),
        Self::Limit(HttpLimitCode::ChunkExtensionBytesPerChunk),
        Self::Limit(HttpLimitCode::ChunkExtensionAggregate),
        Self::Limit(HttpLimitCode::WireRequestBody),
        Self::Limit(HttpLimitCode::WireResponseBody),
        Self::Limit(HttpLimitCode::ContentLength),
        Self::Limit(HttpLimitCode::CompressedInput),
        Self::Limit(HttpLimitCode::DecodedOutput),
        Self::Limit(HttpLimitCode::ExpansionRatio),
        Self::Limit(HttpLimitCode::CodecState),
        Self::Limit(HttpLimitCode::UrlFieldCount),
        Self::Limit(HttpLimitCode::UrlFieldBytes),
        Self::Limit(HttpLimitCode::MultipartPartCount),
        Self::Limit(HttpLimitCode::MultipartBoundary),
        Self::Limit(HttpLimitCode::MultipartPartHeaders),
        Self::Limit(HttpLimitCode::MultipartPartBody),
        Self::Limit(HttpLimitCode::RedirectCount),
        Self::Limit(HttpLimitCode::RedirectRetained),
        Self::Limit(HttpLimitCode::EmbeddedCandidateCount),
        Self::Limit(HttpLimitCode::EmbeddedDepth),
        Self::Limit(HttpLimitCode::EmbeddedConcurrency),
        Self::Limit(HttpLimitCode::EmbeddedRetained),
        Self::Limit(HttpLimitCode::TraceCount),
        Self::Limit(HttpLimitCode::TraceBytes),
        Self::Limit(HttpLimitCode::DiagnosticCount),
        Self::Limit(HttpLimitCode::DiagnosticText),
        Self::Limit(HttpLimitCode::DiagnosticAggregate),
        Self::InvalidUrl,
        Self::InvalidMethod,
        Self::InvalidHeader,
        Self::RequestBodyLimit,
        Self::ResponseBodyLimit,
        Self::InvalidTimeout,
        Self::InvalidRedirect,
        Self::RedirectLimit,
        Self::RedirectOriginDenied,
        Self::Cookie,
        Self::Cache,
        Self::Authentication,
        Self::Unsupported,
        Self::Reset,
        Self::InvalidRequest,
        Self::Adapter,
    ];

    /// Returns the canonical dotted spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dns => "http.dns",
            Self::Pool => "http.pool",
            Self::Connect => "http.connect",
            Self::Proxy => "http.proxy",
            Self::Tls => "http.tls",
            Self::Write => "http.write",
            Self::Read => "http.read",
            Self::Framing => "http.framing",
            Self::Decompression => "http.decompression",
            Self::Timeout => "http.timeout",
            Self::Cancelled => "http.cancelled",
            Self::BodyReplay => "http.body-replay",
            Self::BodyState => "http.body-state",
            Self::ResponseLease => "http.response-lease",
            Self::StateConflict => "http.state-conflict",
            Self::UnsupportedImplementation => "http.unsupported-implementation",
            Self::UnsupportedAuth => "http.unsupported-auth",
            Self::UnsupportedStore => "http.unsupported-store",
            Self::AutomationEnabled => "http.automation-enabled",
            Self::BudgetInvalid => "http.budget-invalid",
            Self::Recorder => "http.recorder",
            Self::Mirror => "http.mirror",
            Self::InternalInvariant => "http.internal-invariant",
            Self::Limit(code) => code.as_str(),
            Self::InvalidUrl => "http.invalid-url",
            Self::InvalidMethod => "http.invalid-method",
            Self::InvalidHeader => "http.invalid-header",
            Self::RequestBodyLimit => "http.request-body-limit",
            Self::ResponseBodyLimit => "http.response-body-limit",
            Self::InvalidTimeout => "http.invalid-timeout",
            Self::InvalidRedirect => "http.invalid-redirect",
            Self::RedirectLimit => "http.redirect-limit",
            Self::RedirectOriginDenied => "http.redirect-origin-denied",
            Self::Cookie => "http.cookie",
            Self::Cache => "http.cache",
            Self::Authentication => "http.authentication",
            Self::Unsupported => "http.unsupported",
            Self::Reset => "http.reset",
            Self::InvalidRequest => "http.invalid-request",
            Self::Adapter => "http.adapter",
        }
    }

    /// Returns a fixed numeric identity for this code.
    #[must_use]
    pub const fn discriminant(self) -> u16 {
        match self {
            Self::Dns => 1,
            Self::Pool => 2,
            Self::Connect => 3,
            Self::Proxy => 4,
            Self::Tls => 5,
            Self::Write => 6,
            Self::Read => 7,
            Self::Framing => 8,
            Self::Decompression => 9,
            Self::Timeout => 10,
            Self::Cancelled => 11,
            Self::BodyReplay => 12,
            Self::BodyState => 13,
            Self::ResponseLease => 14,
            Self::StateConflict => 15,
            Self::UnsupportedImplementation => 16,
            Self::UnsupportedAuth => 17,
            Self::UnsupportedStore => 18,
            Self::AutomationEnabled => 19,
            Self::BudgetInvalid => 20,
            Self::Recorder => 21,
            Self::Mirror => 22,
            Self::InternalInvariant => 23,
            Self::Limit(code) => 100 + code.discriminant(),
            Self::InvalidUrl => 200,
            Self::InvalidMethod => 201,
            Self::InvalidHeader => 202,
            Self::RequestBodyLimit => 203,
            Self::ResponseBodyLimit => 204,
            Self::InvalidTimeout => 205,
            Self::InvalidRedirect => 206,
            Self::RedirectLimit => 207,
            Self::RedirectOriginDenied => 208,
            Self::Cookie => 209,
            Self::Cache => 210,
            Self::Authentication => 211,
            Self::Unsupported => 212,
            Self::Reset => 213,
            Self::InvalidRequest => 214,
            Self::Adapter => 215,
        }
    }

    /// Returns whether this category represents a finite parser/resource
    /// bound.
    #[must_use]
    pub const fn is_limit(self) -> bool {
        matches!(self, Self::Limit(_))
    }

    /// Parses a canonical stable code; unknown/custom text is rejected.
    ///
    /// This inherent spelling is retained for the protocol-v1 decoder, which
    /// is an out-of-scope compatibility seam and calls the associated method
    /// without importing [`core::str::FromStr`]. New callers may use
    /// `value.parse::<StableHttpErrorCode>()`.
    #[allow(
        clippy::should_implement_trait,
        reason = "protocol_v1 retains this source-compatible associated parser"
    )]
    #[must_use]
    pub fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "http.transport.dns" | "http.dns" => Self::Dns,
            "http.pool" => Self::Pool,
            "http.transport.connect" | "http.connect" => Self::Connect,
            "http.proxy" => Self::Proxy,
            "http.tls" => Self::Tls,
            "http.transport.write" | "http.write" => Self::Write,
            "http.transport.read" | "http.read" => Self::Read,
            "http.framing" => Self::Framing,
            "http.decompression" => Self::Decompression,
            "http.timeout" => Self::Timeout,
            "http.cancelled" => Self::Cancelled,
            "http.body-replay" => Self::BodyReplay,
            "http.body-state" => Self::BodyState,
            "http.response-lease" => Self::ResponseLease,
            "http.state-conflict" => Self::StateConflict,
            "http.unsupported-implementation" => Self::UnsupportedImplementation,
            "http.unsupported-auth" => Self::UnsupportedAuth,
            "http.unsupported-store" => Self::UnsupportedStore,
            "http.automation-enabled" => Self::AutomationEnabled,
            "http.budget-invalid" => Self::BudgetInvalid,
            "http.recorder" => Self::Recorder,
            "http.mirror" => Self::Mirror,
            "http.internal-invariant" => Self::InternalInvariant,
            "http.invalid-url" => Self::InvalidUrl,
            "http.invalid-method" => Self::InvalidMethod,
            "http.invalid-header" => Self::InvalidHeader,
            "http.request-body-limit" => Self::RequestBodyLimit,
            "http.response-body-limit" => Self::ResponseBodyLimit,
            "http.invalid-timeout" => Self::InvalidTimeout,
            "http.invalid-redirect" => Self::InvalidRedirect,
            "http.redirect-limit" => Self::RedirectLimit,
            "http.redirect-origin-denied" => Self::RedirectOriginDenied,
            "http.cookie" => Self::Cookie,
            "http.cache" => Self::Cache,
            "http.authentication" => Self::Authentication,
            "http.unsupported" => Self::Unsupported,
            "http.transport.reset" | "http.reset" => Self::Reset,
            "http.transport.invalid-request" | "http.invalid-request" => Self::InvalidRequest,
            "http.transport.adapter" | "http.adapter" => Self::Adapter,
            value if value.starts_with("http.limit.") => Self::Limit(HttpLimitCode::parse(value)?),
            _ => return None,
        })
    }

    /// Parses a canonical stable HTTP error code.
    #[must_use]
    pub fn from_stable_code(value: &str) -> Option<Self> {
        let code = Self::from_str(value)?;
        (code.as_str() == value).then_some(code)
    }
}

impl fmt::Display for StableHttpErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl core::str::FromStr for StableHttpErrorCode {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_str(value).ok_or(())
    }
}

impl TryFrom<u16> for StableHttpErrorCode {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Dns),
            2 => Ok(Self::Pool),
            3 => Ok(Self::Connect),
            4 => Ok(Self::Proxy),
            5 => Ok(Self::Tls),
            6 => Ok(Self::Write),
            7 => Ok(Self::Read),
            8 => Ok(Self::Framing),
            9 => Ok(Self::Decompression),
            10 => Ok(Self::Timeout),
            11 => Ok(Self::Cancelled),
            12 => Ok(Self::BodyReplay),
            13 => Ok(Self::BodyState),
            14 => Ok(Self::ResponseLease),
            15 => Ok(Self::StateConflict),
            16 => Ok(Self::UnsupportedImplementation),
            17 => Ok(Self::UnsupportedAuth),
            18 => Ok(Self::UnsupportedStore),
            19 => Ok(Self::AutomationEnabled),
            20 => Ok(Self::BudgetInvalid),
            21 => Ok(Self::Recorder),
            22 => Ok(Self::Mirror),
            23 => Ok(Self::InternalInvariant),
            value @ 101..=143 => {
                let code = HttpLimitCode::try_from((value - 100) as u8)?;
                Ok(Self::Limit(code))
            }
            200 => Ok(Self::InvalidUrl),
            201 => Ok(Self::InvalidMethod),
            202 => Ok(Self::InvalidHeader),
            203 => Ok(Self::RequestBodyLimit),
            204 => Ok(Self::ResponseBodyLimit),
            205 => Ok(Self::InvalidTimeout),
            206 => Ok(Self::InvalidRedirect),
            207 => Ok(Self::RedirectLimit),
            208 => Ok(Self::RedirectOriginDenied),
            209 => Ok(Self::Cookie),
            210 => Ok(Self::Cache),
            211 => Ok(Self::Authentication),
            212 => Ok(Self::Unsupported),
            213 => Ok(Self::Reset),
            214 => Ok(Self::InvalidRequest),
            215 => Ok(Self::Adapter),
            _ => Err(()),
        }
    }
}

/// One bounded, redacted diagnostic record.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct HttpDiagnostic {
    code: HttpDiagnosticCode,
    message_len: usize,
}

impl HttpDiagnostic {
    /// Creates a redacted diagnostic record. The message is never retained.
    pub fn new(code: HttpDiagnosticCode, message: impl AsRef<str>) -> Result<Self, HttpLimitCode> {
        let message = message.as_ref();
        let message_len = message.len();
        if message.is_empty() || message_len > MAX_ERROR_DIAGNOSTIC_BYTES || message.contains('\0')
        {
            return Err(HttpLimitCode::DiagnosticText);
        }
        Ok(Self { code, message_len })
    }

    /// Returns the closed diagnostic category.
    #[must_use]
    pub const fn code(&self) -> HttpDiagnosticCode {
        self.code
    }

    /// Returns the original bounded length without exposing its content.
    #[must_use]
    pub const fn message_len(&self) -> usize {
        self.message_len
    }

    /// Returns a safe placeholder for ordinary diagnostic consumers.
    #[must_use]
    pub const fn message(&self) -> &'static str {
        "<redacted HTTP diagnostic>"
    }

    /// Returns the bounded encoded size used for aggregate accounting.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.code.as_str().len().saturating_add(self.message_len)
    }
}

impl fmt::Display for HttpDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message())
    }
}

/// A bounded ordered diagnostic collection.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct HttpDiagnostics {
    records: Vec<HttpDiagnostic>,
    bytes: usize,
}

impl HttpDiagnostics {
    /// Adds one record while enforcing count and aggregate bounds.
    pub fn push(&mut self, diagnostic: HttpDiagnostic) -> Result<(), HttpLimitCode> {
        if self.records.len() >= MAX_ERROR_DIAGNOSTICS {
            return Err(HttpLimitCode::DiagnosticCount);
        }
        if diagnostic.message_len() > MAX_ERROR_DIAGNOSTIC_BYTES {
            return Err(HttpLimitCode::DiagnosticText);
        }
        let next = self
            .bytes
            .checked_add(diagnostic.encoded_len())
            .ok_or(HttpLimitCode::DiagnosticAggregate)?;
        if next > MAX_ERROR_DIAGNOSTIC_AGGREGATE_BYTES {
            return Err(HttpLimitCode::DiagnosticAggregate);
        }
        self.bytes = next;
        self.records.push(diagnostic);
        Ok(())
    }

    /// Returns records in insertion order.
    #[must_use]
    pub fn records(&self) -> &[HttpDiagnostic] {
        &self.records
    }

    /// Returns the checked aggregate encoded size.
    #[must_use]
    pub const fn bytes(&self) -> usize {
        self.bytes
    }
}

impl fmt::Display for HttpDiagnostics {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} diagnostic(s), {} bytes",
            self.records.len(),
            self.bytes
        )
    }
}

/// The phase in which an injected transport observed a timeout.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TimeoutPhase {
    /// The complete operation exceeded its deadline.
    Overall,
    /// Establishing a connection exceeded its deadline.
    Connect,
    /// Writing request bytes exceeded its deadline.
    Write,
    /// Reading response bytes exceeded its deadline.
    Read,
    /// A TLS handshake exceeded its deadline.
    Tls,
}

/// A transport failure reported by an injected transport.
#[derive(Clone, Eq, PartialEq)]
pub enum TransportError {
    /// Name resolution failed.
    Dns(String),
    /// A connection could not be established.
    Connect(String),
    /// Request bytes could not be written.
    Write(String),
    /// Response bytes could not be read.
    Read(String),
    /// The peer returned malformed protocol data.
    Protocol(String),
    /// The transport was reset or closed before completion.
    Reset(String),
    /// A transport-specific timeout occurred.
    Timeout(TimeoutPhase),
    /// The operation was cancelled through the explicit cancellation token.
    Cancelled,
    /// The transport capability is not available in this build/profile.
    Unsupported(String),
    /// A transport resource bound was reached.
    ResourceLimit(String),
    /// An adapter supplied an invalid request.
    InvalidRequest(String),
    /// A transport adapter supplied a stable code and diagnostic detail.
    ///
    /// The detail is bounded and redacted in `Debug`/`Display`; adapters must
    /// not force callers to choose between useful typed failures and leaking
    /// credentials in diagnostics.
    Adapter {
        /// Adapter-local stable code.
        code: String,
        /// Bounded diagnostic detail.
        message: String,
    },
}

impl fmt::Debug for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns(message) => formatter
                .debug_tuple("Dns")
                .field(&redacted(message))
                .finish(),
            Self::Connect(message) => formatter
                .debug_tuple("Connect")
                .field(&redacted(message))
                .finish(),
            Self::Write(message) => formatter
                .debug_tuple("Write")
                .field(&redacted(message))
                .finish(),
            Self::Read(message) => formatter
                .debug_tuple("Read")
                .field(&redacted(message))
                .finish(),
            Self::Protocol(message) => formatter
                .debug_tuple("Protocol")
                .field(&redacted(message))
                .finish(),
            Self::Reset(message) => formatter
                .debug_tuple("Reset")
                .field(&redacted(message))
                .finish(),
            Self::Timeout(phase) => formatter.debug_tuple("Timeout").field(phase).finish(),
            Self::Cancelled => formatter.write_str("Cancelled"),
            Self::Unsupported(message) => formatter
                .debug_tuple("Unsupported")
                .field(&redacted(message))
                .finish(),
            Self::ResourceLimit(message) => formatter
                .debug_tuple("ResourceLimit")
                .field(&redacted(message))
                .finish(),
            Self::InvalidRequest(message) => formatter
                .debug_tuple("InvalidRequest")
                .field(&redacted(message))
                .finish(),
            Self::Adapter { code, message } => formatter
                .debug_struct("Adapter")
                .field("code", &bounded(code))
                .field("message", &redacted(message))
                .finish(),
        }
    }
}

impl TransportError {
    /// Creates a bounded adapter error with an explicit local code.
    pub fn adapter(code: impl Into<String>, message: impl Into<String>) -> Self {
        let code = code.into();
        let message = message.into();
        if code.is_empty()
            || code.len() > 128
            || !code
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Self::Adapter {
                code: "invalid-adapter-code".to_owned(),
                message: "adapter supplied an invalid error code".to_owned(),
            };
        }
        Self::Adapter {
            code,
            message: bounded(&message),
        }
    }

    /// Returns the adapter-local code when this is an adapter error.
    #[must_use]
    pub fn adapter_code(&self) -> Option<&str> {
        match self {
            Self::Adapter { code, .. } => Some(code),
            _ => None,
        }
    }

    /// Returns the stable machine-readable transport code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Dns(_) => "http.transport.dns",
            Self::Connect(_) => "http.transport.connect",
            Self::Write(_) => "http.transport.write",
            Self::Read(_) => "http.transport.read",
            Self::Protocol(_) => "http.transport.protocol",
            Self::Reset(_) => "http.transport.reset",
            Self::Timeout(_) => "http.transport.timeout",
            Self::Cancelled => "http.transport.cancelled",
            Self::Unsupported(_) => "http.transport.unsupported",
            Self::ResourceLimit(_) => "http.transport.resource-limit",
            Self::InvalidRequest(_) => "http.transport.invalid-request",
            Self::Adapter { .. } => "http.transport.adapter",
        }
    }

    /// Returns the closed stable category for this transport failure.
    #[must_use]
    pub fn stable_error_code(&self) -> StableHttpErrorCode {
        match self {
            Self::Dns(_) => StableHttpErrorCode::Dns,
            Self::Connect(_) => StableHttpErrorCode::Connect,
            Self::Write(_) => StableHttpErrorCode::Write,
            Self::Read(_) => StableHttpErrorCode::Read,
            Self::Protocol(message)
                if contains_ascii_case_insensitive(message, "decompress")
                    || contains_ascii_case_insensitive(message, "content-encoding")
                    || contains_ascii_case_insensitive(message, "gzip")
                    || contains_ascii_case_insensitive(message, "deflate")
                    || contains_ascii_case_insensitive(message, "brotli") =>
            {
                StableHttpErrorCode::Decompression
            }
            Self::Protocol(_) => StableHttpErrorCode::Framing,
            Self::Reset(_) => StableHttpErrorCode::Reset,
            Self::Timeout(_) => StableHttpErrorCode::Timeout,
            Self::Cancelled => StableHttpErrorCode::Cancelled,
            Self::Unsupported(_) => StableHttpErrorCode::UnsupportedImplementation,
            Self::ResourceLimit(message) => limit_code_for_message(message).map_or(
                StableHttpErrorCode::InternalInvariant,
                StableHttpErrorCode::Limit,
            ),
            Self::InvalidRequest(_) => StableHttpErrorCode::InvalidRequest,
            Self::Adapter { .. } => StableHttpErrorCode::Adapter,
        }
    }

    /// Returns the canonical stable spelling for this transport failure.
    #[must_use]
    pub fn stable_code(&self) -> &'static str {
        self.stable_error_code().as_str()
    }

    /// Returns a closed parser/resource limit when this is a limit failure.
    #[must_use]
    pub fn limit_code(&self) -> Option<HttpLimitCode> {
        match self {
            Self::ResourceLimit(message) => limit_code_for_message(message),
            _ => None,
        }
    }

    /// Returns whether this transport failure is a finite resource bound.
    #[must_use]
    pub fn is_limit(&self) -> bool {
        self.limit_code().is_some()
    }

    /// Returns the retryability proved by the transport phase.
    #[must_use]
    pub const fn retryability(&self) -> Retryability {
        match self {
            Self::Dns(_) | Self::Connect(_) => Retryability::Retryable,
            Self::Write(_) | Self::Read(_) | Self::Reset(_) | Self::Timeout(_) => {
                Retryability::Unknown
            }
            Self::Protocol(_)
            | Self::Cancelled
            | Self::Unsupported(_)
            | Self::ResourceLimit(_)
            | Self::InvalidRequest(_)
            | Self::Adapter { .. } => Retryability::Terminal,
        }
    }

    /// Returns whether the transport has proved that retry may proceed.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        self.retryability().is_retryable()
    }

    /// Alias for callers using the positive/verb-style spelling.
    #[must_use]
    pub const fn retryable(&self) -> bool {
        self.is_retryable()
    }

    /// Returns whether this transport failure is terminal for the attempt.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        !self.is_retryable()
    }
}

fn limit_code_for_message(message: &str) -> Option<HttpLimitCode> {
    let normalized = message
        .strip_prefix("HTTP parser limit: ")
        .or_else(|| message.strip_prefix("http.limit."))
        .unwrap_or(message);
    if normalized.len() > MAX_ERROR_DIAGNOSTIC_BYTES {
        return None;
    }
    HttpLimitCode::from_message(normalized).or_else(|| {
        let lower = normalized.to_ascii_lowercase();
        HttpLimitCode::from_message(&lower).or_else(|| {
            if lower.contains("authority") {
                Some(HttpLimitCode::Authority)
            } else if lower.contains("status") && lower.contains("line") {
                Some(HttpLimitCode::StatusLine)
            } else if lower.contains("reason") && lower.contains("phrase") {
                Some(HttpLimitCode::Reason)
            } else if lower.contains("decompress")
                && (lower.contains("output") || lower.contains("response"))
            {
                Some(HttpLimitCode::DecodedOutput)
            } else if lower.contains("decompress") && lower.contains("ratio") {
                Some(HttpLimitCode::ExpansionRatio)
            } else if (lower.contains("decompress") && lower.contains("codec"))
                || (lower.contains("codec") && lower.contains("state"))
                || (lower.contains("content-encoding") && lower.contains("count"))
            {
                Some(HttpLimitCode::CodecState)
            } else if lower.contains("request")
                && (lower.contains("target") || lower.contains("url"))
            {
                Some(HttpLimitCode::RequestTarget)
            } else if lower.contains("request") && lower.contains("body") {
                Some(HttpLimitCode::WireRequestBody)
            } else if (lower.contains("response") || lower.contains("received"))
                && lower.contains("body")
            {
                Some(HttpLimitCode::WireResponseBody)
            } else if (lower.contains("received") || lower.contains("sent"))
                && lower.contains("header")
                && lower.contains("byte")
            {
                Some(HttpLimitCode::HeaderAggregate)
            } else if lower.contains("sent") && (lower.contains("body") || lower.contains("byte")) {
                Some(HttpLimitCode::WireRequestBody)
            } else if lower.contains("received") && lower.contains("byte") {
                Some(HttpLimitCode::WireResponseBody)
            } else if lower.contains("form") && lower.contains("entity") {
                Some(HttpLimitCode::WireRequestBody)
            } else if lower.contains("content-length") || lower.contains("content length") {
                Some(HttpLimitCode::ContentLength)
            } else if lower.contains("multipart") {
                if lower.contains("count") || lower.contains("parts") {
                    Some(HttpLimitCode::MultipartPartCount)
                } else if lower.contains("boundary") {
                    Some(HttpLimitCode::MultipartBoundary)
                } else if lower.contains("header") {
                    Some(HttpLimitCode::MultipartPartHeaders)
                } else {
                    Some(HttpLimitCode::MultipartPartBody)
                }
            } else if lower.contains("header")
                && (lower.contains("field") || lower.contains("header"))
                && lower.contains("count")
            {
                Some(HttpLimitCode::HeaderCount)
            } else if lower.contains("header") && lower.contains("name") {
                Some(HttpLimitCode::HeaderName)
            } else if lower.contains("header") && lower.contains("value") {
                Some(HttpLimitCode::HeaderValue)
            } else if lower.contains("header")
                && (lower.contains("byte") || lower.contains("aggregate"))
            {
                Some(HttpLimitCode::HeaderAggregate)
            } else if lower.contains("informational") && lower.contains("count") {
                Some(HttpLimitCode::InformationalCount)
            } else if lower.contains("informational") {
                Some(HttpLimitCode::InformationalAggregate)
            } else if lower.contains("trailer") && lower.contains("count") {
                Some(HttpLimitCode::TrailerCount)
            } else if lower.contains("trailer") && lower.contains("name") {
                Some(HttpLimitCode::TrailerName)
            } else if lower.contains("trailer") && lower.contains("value") {
                Some(HttpLimitCode::TrailerValue)
            } else if lower.contains("trailer") {
                Some(HttpLimitCode::TrailerAggregate)
            } else if lower.contains("chunk") && lower.contains("line") {
                Some(HttpLimitCode::ChunkLine)
            } else if lower.contains("chunk") && lower.contains("count") {
                Some(HttpLimitCode::ChunkCount)
            } else if lower.contains("chunk") && lower.contains("extension") {
                if lower.contains("per chunk") || lower.contains("per-chunk") {
                    Some(HttpLimitCode::ChunkExtensionBytesPerChunk)
                } else if lower.contains("count") {
                    Some(HttpLimitCode::ChunkExtensionCount)
                } else {
                    Some(HttpLimitCode::ChunkExtensionAggregate)
                }
            } else if lower.contains("compressed") && lower.contains("input") {
                Some(HttpLimitCode::CompressedInput)
            } else if (lower.contains("argument") && lower.contains("count"))
                || ((lower.contains("url") || lower.contains("form"))
                    && lower.contains("field")
                    && lower.contains("count"))
            {
                Some(HttpLimitCode::UrlFieldCount)
            } else if (lower.contains("url") || lower.contains("form")) && lower.contains("field") {
                Some(HttpLimitCode::UrlFieldBytes)
            } else if lower.contains("redirect") {
                if lower.contains("retain")
                    || lower.contains("histor")
                    || lower.contains("byte")
                    || lower.contains("location")
                {
                    Some(HttpLimitCode::RedirectRetained)
                } else {
                    Some(HttpLimitCode::RedirectCount)
                }
            } else if lower.contains("embedded") {
                if lower.contains("candidate") {
                    Some(HttpLimitCode::EmbeddedCandidateCount)
                } else if lower.contains("depth") {
                    Some(HttpLimitCode::EmbeddedDepth)
                } else if lower.contains("concurr") {
                    Some(HttpLimitCode::EmbeddedConcurrency)
                } else {
                    Some(HttpLimitCode::EmbeddedRetained)
                }
            } else if lower.contains("trace") {
                if lower.contains("count") || lower.contains("record") {
                    Some(HttpLimitCode::TraceCount)
                } else {
                    Some(HttpLimitCode::TraceBytes)
                }
            } else if lower.contains("diagnostic") {
                if lower.contains("count") {
                    Some(HttpLimitCode::DiagnosticCount)
                } else if lower.contains("aggregate") || lower.contains("total") {
                    Some(HttpLimitCode::DiagnosticAggregate)
                } else {
                    Some(HttpLimitCode::DiagnosticText)
                }
            } else if lower.contains("url") {
                Some(HttpLimitCode::RequestTarget)
            } else {
                None
            }
        })
    })
}

fn contains_ascii_case_insensitive(value: &str, needle: &str) -> bool {
    let bytes = value.as_bytes();
    let prefix = &bytes[..bytes.len().min(MAX_ERROR_DIAGNOSTIC_BYTES)];
    prefix
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns(message)
            | Self::Connect(message)
            | Self::Write(message)
            | Self::Read(message)
            | Self::Protocol(message)
            | Self::Reset(message)
            | Self::Unsupported(message)
            | Self::ResourceLimit(message)
            | Self::InvalidRequest(message) => {
                write!(formatter, "{}: {}", self.code(), redacted(message))
            }
            Self::Adapter { code, message } => {
                write!(formatter, "{}:{code}: {}", self.code(), redacted(message))
            }
            Self::Timeout(phase) => write!(formatter, "{}: {phase:?}", self.code()),
            Self::Cancelled => formatter.write_str(self.code()),
        }
    }
}

impl std::error::Error for TransportError {}

/// Errors produced while constructing or executing an HTTP request.
#[derive(Clone, Eq, PartialEq)]
pub enum HttpError {
    /// A URL was empty, malformed, or used an unsupported scheme.
    InvalidUrl(String),
    /// A method name was empty or contained invalid bytes.
    InvalidMethod(String),
    /// A header name or value violated HTTP field syntax.
    InvalidHeader(String),
    /// A request or response exceeded a configured bound.
    ResourceLimit(String),
    /// The request body exceeded its configured bound.
    RequestBodyLimit {
        /// Actual body length.
        actual: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// The response body exceeded its configured bound.
    ResponseBodyLimit {
        /// Actual body length.
        actual: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// A transport capability failed.
    Transport(TransportError),
    /// An operation exceeded a configured deadline.
    Timeout(TimeoutPhase),
    /// The operation was cancelled through the explicit cancellation token.
    Cancelled,
    /// Timeout configuration was missing a finite overall deadline or had an
    /// invalid duration.
    InvalidTimeout(String),
    /// A redirect response did not contain a usable location.
    InvalidRedirect(String),
    /// The redirect limit was reached.
    RedirectLimit {
        /// Configured maximum number of redirects.
        maximum: usize,
    },
    /// A redirect would cross an origin and credentials were not allowed.
    RedirectOriginDenied,
    /// A proxy configuration is invalid or cannot route the URL.
    Proxy(String),
    /// TLS policy is invalid or unsupported by the selected transport.
    Tls(String),
    /// Cookie parsing or matching failed.
    Cookie(String),
    /// Cache metadata is invalid or exceeds a bound.
    Cache(String),
    /// Authentication configuration or challenge handling failed.
    Authentication(String),
    /// The requested HTTP capability is intentionally not implemented.
    Unsupported(String),
    /// A failure with bounded source-node/run/sample context.
    ///
    /// Context is diagnostic only and never changes the underlying stable
    /// code. Repeated wrappers are flattened by [`Self::with_context`].
    Context {
        /// The underlying typed HTTP failure.
        source: Box<HttpError>,
        /// Canonical source/operation identity and redacted diagnostics.
        context: Box<ErrorContextV1>,
    },
}

impl fmt::Debug for HttpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl(message) => formatter
                .debug_tuple("InvalidUrl")
                .field(&redacted(message))
                .finish(),
            Self::InvalidMethod(message) => formatter
                .debug_tuple("InvalidMethod")
                .field(&redacted(message))
                .finish(),
            Self::InvalidHeader(message) => formatter
                .debug_tuple("InvalidHeader")
                .field(&redacted(message))
                .finish(),
            Self::ResourceLimit(message) => formatter
                .debug_tuple("ResourceLimit")
                .field(&redacted(message))
                .finish(),
            Self::RequestBodyLimit { actual, maximum } => formatter
                .debug_struct("RequestBodyLimit")
                .field("actual", actual)
                .field("maximum", maximum)
                .finish(),
            Self::ResponseBodyLimit { actual, maximum } => formatter
                .debug_struct("ResponseBodyLimit")
                .field("actual", actual)
                .field("maximum", maximum)
                .finish(),
            Self::Transport(error) => formatter.debug_tuple("Transport").field(error).finish(),
            Self::Timeout(phase) => formatter.debug_tuple("Timeout").field(phase).finish(),
            Self::Cancelled => formatter.write_str("Cancelled"),
            Self::InvalidTimeout(message) => formatter
                .debug_tuple("InvalidTimeout")
                .field(&redacted(message))
                .finish(),
            Self::InvalidRedirect(message) => formatter
                .debug_tuple("InvalidRedirect")
                .field(&redacted(message))
                .finish(),
            Self::RedirectLimit { maximum } => formatter
                .debug_struct("RedirectLimit")
                .field("maximum", maximum)
                .finish(),
            Self::RedirectOriginDenied => formatter.write_str("RedirectOriginDenied"),
            Self::Proxy(message) => formatter
                .debug_tuple("Proxy")
                .field(&redacted(message))
                .finish(),
            Self::Tls(message) => formatter
                .debug_tuple("Tls")
                .field(&redacted(message))
                .finish(),
            Self::Cookie(message) => formatter
                .debug_tuple("Cookie")
                .field(&redacted(message))
                .finish(),
            Self::Cache(message) => formatter
                .debug_tuple("Cache")
                .field(&redacted(message))
                .finish(),
            Self::Authentication(message) => formatter
                .debug_tuple("Authentication")
                .field(&redacted(message))
                .finish(),
            Self::Unsupported(message) => formatter
                .debug_tuple("Unsupported")
                .field(&redacted(message))
                .finish(),
            Self::Context { source, context } => {
                let mut source = source.as_ref();
                let mut depth = 0;
                while let Self::Context { source: nested, .. } = source {
                    if depth >= MAX_HTTP_ERROR_CONTEXT_DEPTH {
                        return formatter
                            .debug_struct("Context")
                            .field("source", &"<context depth limit>")
                            .field("context", context)
                            .finish();
                    }
                    source = nested;
                    depth += 1;
                }
                formatter
                    .debug_struct("Context")
                    .field("source", source)
                    .field("context", context)
                    .finish()
            }
        }
    }
}

fn bounded(value: &str) -> String {
    const MAX_DEBUG_BYTES: usize = 256;
    if value.len() <= MAX_DEBUG_BYTES {
        return value.to_owned();
    }
    let mut end = MAX_DEBUG_BYTES;
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    format!("{}…", &value[..end])
}

fn redacted(_value: &str) -> String {
    // Transport adapters receive request targets, headers, and credentials in
    // the same operation.  A message supplied by an arbitrary adapter cannot
    // be classified safely as public: even a value that does not contain a
    // familiar key name may be a bare Basic token, base64 credential, or a
    // tenant-specific secret.  Keep the stable error code and phase as the
    // diagnostic contract and never echo adapter text.
    "<redacted transport detail>".to_owned()
}

impl HttpError {
    /// Creates a bounded-resource error.
    #[must_use]
    pub fn resource_limit(message: impl Into<String>) -> Self {
        let message = message.into();
        Self::ResourceLimit(bounded(&message))
    }

    /// Returns the stable machine-readable code for this error.
    #[must_use]
    pub fn stable_code(&self) -> &'static str {
        let mut current = self;
        let mut depth = 0;
        while let Self::Context { source, .. } = current {
            if depth >= MAX_HTTP_ERROR_CONTEXT_DEPTH {
                return "http.internal-invariant";
            }
            current = source;
            depth += 1;
        }
        match current {
            Self::InvalidUrl(_) => "http.invalid-url",
            Self::InvalidMethod(_) => "http.invalid-method",
            Self::InvalidHeader(_) => "http.invalid-header",
            Self::ResourceLimit(_) => "http.resource-limit",
            Self::RequestBodyLimit { .. } => "http.request-body-limit",
            Self::ResponseBodyLimit { .. } => "http.response-body-limit",
            Self::Transport(error) => error.code(),
            Self::Timeout(_) => "http.timeout",
            Self::Cancelled => "http.cancelled",
            Self::InvalidTimeout(_) => "http.invalid-timeout",
            Self::InvalidRedirect(_) => "http.invalid-redirect",
            Self::RedirectLimit { .. } => "http.redirect-limit",
            Self::RedirectOriginDenied => "http.redirect-origin-denied",
            Self::Proxy(_) => "http.proxy",
            Self::Tls(_) => "http.tls",
            Self::Cookie(_) => "http.cookie",
            Self::Cache(_) => "http.cache",
            Self::Authentication(_) => "http.authentication",
            Self::Unsupported(_) => "http.unsupported",
            Self::Context { .. } => "http.internal-invariant",
        }
    }

    /// Returns the closed stable code required by the HTTP error contract.
    #[must_use]
    pub fn stable_error_code(&self) -> StableHttpErrorCode {
        let mut current = self;
        let mut depth = 0;
        while let Self::Context { source, .. } = current {
            if depth >= MAX_HTTP_ERROR_CONTEXT_DEPTH {
                return StableHttpErrorCode::InternalInvariant;
            }
            current = source;
            depth += 1;
        }
        match current {
            Self::InvalidUrl(_) => StableHttpErrorCode::InvalidUrl,
            Self::InvalidMethod(_) => StableHttpErrorCode::InvalidMethod,
            Self::InvalidHeader(_) => StableHttpErrorCode::InvalidHeader,
            Self::ResourceLimit(message) => limit_code_for_message(message).map_or(
                StableHttpErrorCode::InternalInvariant,
                StableHttpErrorCode::Limit,
            ),
            Self::RequestBodyLimit { .. } => {
                StableHttpErrorCode::Limit(HttpLimitCode::WireRequestBody)
            }
            Self::ResponseBodyLimit { .. } => {
                StableHttpErrorCode::Limit(HttpLimitCode::WireResponseBody)
            }
            Self::Transport(error) => error.stable_error_code(),
            Self::Timeout(_) => StableHttpErrorCode::Timeout,
            Self::Cancelled => StableHttpErrorCode::Cancelled,
            Self::InvalidTimeout(_) => StableHttpErrorCode::InvalidTimeout,
            Self::InvalidRedirect(_) => StableHttpErrorCode::InvalidRedirect,
            Self::RedirectLimit { .. } => StableHttpErrorCode::Limit(HttpLimitCode::RedirectCount),
            Self::RedirectOriginDenied => StableHttpErrorCode::RedirectOriginDenied,
            Self::Proxy(_) => StableHttpErrorCode::Proxy,
            Self::Tls(_) => StableHttpErrorCode::Tls,
            Self::Cookie(_) => StableHttpErrorCode::Cookie,
            Self::Cache(_) => StableHttpErrorCode::Cache,
            Self::Authentication(_) => StableHttpErrorCode::Authentication,
            Self::Unsupported(_) => StableHttpErrorCode::UnsupportedImplementation,
            Self::Context { .. } => StableHttpErrorCode::InternalInvariant,
        }
    }

    /// Returns the canonical stable spelling while retaining the legacy
    /// [`Self::stable_code`] accessor for callers that depend on old local
    /// transport prefixes.
    #[must_use]
    pub fn canonical_code(&self) -> &'static str {
        self.stable_error_code().as_str()
    }

    /// Returns the closed parser/resource limit, if this error is one.
    #[must_use]
    pub fn limit_code(&self) -> Option<HttpLimitCode> {
        let mut current = self;
        let mut depth = 0;
        while let Self::Context { source, .. } = current {
            if depth >= MAX_HTTP_ERROR_CONTEXT_DEPTH {
                return None;
            }
            current = source;
            depth += 1;
        }
        match current {
            Self::ResourceLimit(message) => limit_code_for_message(message),
            Self::RequestBodyLimit { .. } => Some(HttpLimitCode::WireRequestBody),
            Self::ResponseBodyLimit { .. } => Some(HttpLimitCode::WireResponseBody),
            Self::RedirectLimit { .. } => Some(HttpLimitCode::RedirectCount),
            Self::Transport(error) => error.limit_code(),
            Self::Context { .. } => None,
            _ => None,
        }
    }

    /// Returns whether this error is a finite parser/resource bound.
    #[must_use]
    pub fn is_limit(&self) -> bool {
        self.limit_code().is_some()
    }

    /// Returns the retryability proved by this error's phase and ownership.
    #[must_use]
    pub const fn retryability(&self) -> Retryability {
        let mut current = self;
        let mut depth = 0;
        while let Self::Context { source, .. } = current {
            if depth >= MAX_HTTP_ERROR_CONTEXT_DEPTH {
                return Retryability::Unknown;
            }
            current = source;
            depth += 1;
        }
        match current {
            Self::Transport(error) => error.retryability(),
            Self::Timeout(_) => Retryability::Unknown,
            Self::Context { .. } => Retryability::Unknown,
            _ => Retryability::Terminal,
        }
    }

    /// Returns whether this error alone authorizes another attempt.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        self.retryability().is_retryable()
    }

    /// Alias for callers using the positive/verb-style spelling.
    #[must_use]
    pub const fn retryable(&self) -> bool {
        self.is_retryable()
    }

    /// Returns whether this error is terminal for the attempt.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        !self.is_retryable()
    }

    /// Attaches canonical source/run/sample context without changing the
    /// underlying stable code. Repeated attachment replaces the outer
    /// diagnostic context rather than creating an unbounded wrapper chain.
    #[must_use]
    pub fn with_context(self, context: ErrorContextV1) -> Self {
        let source = match self {
            Self::Context { source, .. } => *source,
            source => source,
        };
        Self::Context {
            source: Box::new(source),
            context: Box::new(context),
        }
    }

    /// Returns the attached canonical source context, if present.
    #[must_use]
    pub fn context(&self) -> Option<&ErrorContextV1> {
        match self {
            Self::Context { context, .. } => Some(context.as_ref()),
            _ => None,
        }
    }

    /// Alias emphasizing that this is source identity, not display text.
    #[must_use]
    pub fn source_context(&self) -> Option<&ErrorContextV1> {
        self.context()
    }

    /// Returns the underlying failure for a context wrapper, if present.
    #[must_use]
    pub fn source_error(&self) -> Option<&HttpError> {
        if self.context_depth() > MAX_HTTP_ERROR_CONTEXT_DEPTH {
            return None;
        }
        match self {
            Self::Context { source, .. } => Some(source),
            _ => None,
        }
    }

    /// Returns the number of directly nested context wrappers, bounded by the
    /// traversal limit plus one when the limit was exceeded.
    #[must_use]
    pub fn context_depth(&self) -> usize {
        let mut depth = 0;
        let mut current = self;
        while let Self::Context { source, .. } = current {
            if depth >= MAX_HTTP_ERROR_CONTEXT_DEPTH {
                return MAX_HTTP_ERROR_CONTEXT_DEPTH.saturating_add(1);
            }
            depth += 1;
            current = source;
        }
        depth
    }
}

impl fmt::Display for HttpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl(message)
            | Self::InvalidMethod(message)
            | Self::InvalidHeader(message)
            | Self::ResourceLimit(message)
            | Self::InvalidRedirect(message)
            | Self::Proxy(message)
            | Self::Tls(message)
            | Self::Cookie(message)
            | Self::Cache(message)
            | Self::Authentication(message)
            | Self::Unsupported(message)
            | Self::InvalidTimeout(message) => {
                write!(formatter, "{}: {}", self.stable_code(), redacted(message))
            }
            Self::RequestBodyLimit { actual, maximum } => write!(
                formatter,
                "{}: {actual} bytes exceeds {maximum}",
                self.stable_code()
            ),
            Self::ResponseBodyLimit { actual, maximum } => write!(
                formatter,
                "{}: {actual} bytes exceeds {maximum}",
                self.stable_code()
            ),
            Self::Transport(error) => error.fmt(formatter),
            Self::Timeout(phase) => write!(formatter, "{}: {phase:?}", self.stable_code()),
            Self::Cancelled => formatter.write_str(self.stable_code()),
            Self::RedirectLimit { maximum } => {
                write!(formatter, "{}: maximum {maximum}", self.stable_code())
            }
            Self::RedirectOriginDenied => formatter.write_str(self.stable_code()),
            Self::Context { source, .. } => {
                let mut source = source.as_ref();
                let mut depth = 0;
                while let Self::Context { source: nested, .. } = source {
                    if depth >= MAX_HTTP_ERROR_CONTEXT_DEPTH {
                        return write!(formatter, "http.internal-invariant: <context depth limit>");
                    }
                    source = nested;
                    depth += 1;
                }
                source.fmt(formatter)
            }
        }
    }
}

impl std::error::Error for HttpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source_error()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

impl From<TransportError> for HttpError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "tests use expect at assertion boundaries for fixed in-process fixtures"
    )]

    use super::*;

    const LIMITS: [HttpLimitCode; 43] = [
        HttpLimitCode::RequestTarget,
        HttpLimitCode::Authority,
        HttpLimitCode::StatusLine,
        HttpLimitCode::Reason,
        HttpLimitCode::HeaderCount,
        HttpLimitCode::HeaderName,
        HttpLimitCode::HeaderValue,
        HttpLimitCode::HeaderAggregate,
        HttpLimitCode::InformationalCount,
        HttpLimitCode::InformationalAggregate,
        HttpLimitCode::TrailerCount,
        HttpLimitCode::TrailerName,
        HttpLimitCode::TrailerValue,
        HttpLimitCode::TrailerAggregate,
        HttpLimitCode::ChunkLine,
        HttpLimitCode::ChunkCount,
        HttpLimitCode::ChunkExtensionCount,
        HttpLimitCode::ChunkExtensionBytesPerChunk,
        HttpLimitCode::ChunkExtensionAggregate,
        HttpLimitCode::WireRequestBody,
        HttpLimitCode::WireResponseBody,
        HttpLimitCode::ContentLength,
        HttpLimitCode::CompressedInput,
        HttpLimitCode::DecodedOutput,
        HttpLimitCode::ExpansionRatio,
        HttpLimitCode::CodecState,
        HttpLimitCode::UrlFieldCount,
        HttpLimitCode::UrlFieldBytes,
        HttpLimitCode::MultipartPartCount,
        HttpLimitCode::MultipartBoundary,
        HttpLimitCode::MultipartPartHeaders,
        HttpLimitCode::MultipartPartBody,
        HttpLimitCode::RedirectCount,
        HttpLimitCode::RedirectRetained,
        HttpLimitCode::EmbeddedCandidateCount,
        HttpLimitCode::EmbeddedDepth,
        HttpLimitCode::EmbeddedConcurrency,
        HttpLimitCode::EmbeddedRetained,
        HttpLimitCode::TraceCount,
        HttpLimitCode::TraceBytes,
        HttpLimitCode::DiagnosticCount,
        HttpLimitCode::DiagnosticText,
        HttpLimitCode::DiagnosticAggregate,
    ];

    #[test]
    fn every_limit_code_has_stable_round_trip_and_discriminant() {
        assert_eq!(HttpLimitCode::ALL.len(), LIMITS.len());
        for (index, code) in LIMITS.into_iter().enumerate() {
            assert_eq!(code.discriminant(), (index + 1) as u16);
            assert_eq!(HttpLimitCode::parse(code.as_str()), Some(code));
            assert_eq!(code.as_str().parse::<HttpLimitCode>(), Ok(code));
            assert_eq!(HttpLimitCode::try_from((index + 1) as u8), Ok(code));
            assert!(code.as_str().starts_with("http.limit."));
        }
        assert_eq!(HttpLimitCode::try_from(0), Err(()));
        assert_eq!(HttpLimitCode::try_from(44), Err(()));
        assert_eq!(HttpLimitCode::parse("http.limit.custom"), None);
        assert_eq!(HttpLimitCode::parse("header-fields"), None);
        assert_eq!(
            Retryability::parse("retryable"),
            Some(Retryability::Retryable)
        );
        assert_eq!(Retryability::parse("retry"), None);
        assert_eq!(
            "retryable".parse::<Retryability>(),
            Ok(Retryability::Retryable)
        );
        assert!("retry".parse::<Retryability>().is_err());
        assert_eq!(
            HttpDiagnosticCode::from_str("cleanup"),
            Some(HttpDiagnosticCode::Cleanup)
        );
        assert_eq!(
            "cleanup".parse::<HttpDiagnosticCode>(),
            Ok(HttpDiagnosticCode::Cleanup)
        );
        assert!("unknown".parse::<HttpDiagnosticCode>().is_err());
    }

    #[test]
    fn stable_error_code_rejects_unknown_text_and_preserves_numeric_identity() {
        let code = StableHttpErrorCode::Limit(HttpLimitCode::HeaderCount);
        assert_eq!(code.as_str(), "http.limit.header-count");
        assert_eq!(code.discriminant(), 105);
        assert_eq!(StableHttpErrorCode::from_str(code.as_str()), Some(code));
        assert_eq!(StableHttpErrorCode::from_str("http.limit.not-a-code"), None);
        assert_eq!(
            StableHttpErrorCode::from_str("http.transport.dns"),
            Some(StableHttpErrorCode::Dns)
        );
        assert_eq!(
            "http.transport.dns".parse::<StableHttpErrorCode>(),
            Ok(StableHttpErrorCode::Dns)
        );
        assert!("http.custom".parse::<StableHttpErrorCode>().is_err());
        assert_eq!(
            StableHttpErrorCode::from_stable_code("http.transport.dns"),
            None
        );
        assert_eq!(StableHttpErrorCode::ALL.len(), 82);
        for code in StableHttpErrorCode::ALL {
            assert_eq!(StableHttpErrorCode::from_str(code.as_str()), Some(*code));
            assert_eq!(code.as_str().parse::<StableHttpErrorCode>(), Ok(*code));
            assert_eq!(
                StableHttpErrorCode::try_from(code.discriminant()),
                Ok(*code)
            );
        }
        assert_eq!(StableHttpErrorCode::try_from(0), Err(()));
        assert_eq!(StableHttpErrorCode::try_from(99), Err(()));
        assert_eq!(StableHttpErrorCode::try_from(216), Err(()));
        assert_ne!(
            StableHttpErrorCode::Proxy.discriminant(),
            StableHttpErrorCode::Tls.discriminant()
        );
    }

    #[test]
    fn limit_messages_map_to_closed_codes_without_generic_success() {
        let cases = [
            ("request header count", HttpLimitCode::HeaderCount),
            (
                "HTTP parser limit: header-fields",
                HttpLimitCode::HeaderCount,
            ),
            ("header value bytes", HttpLimitCode::HeaderValue),
            ("response trailer count", HttpLimitCode::TrailerCount),
            (
                "response body byte accounting",
                HttpLimitCode::WireResponseBody,
            ),
            ("decompressed response bytes", HttpLimitCode::DecodedOutput),
            ("decompressed output bytes", HttpLimitCode::DecodedOutput),
            (
                "multipart part header bytes",
                HttpLimitCode::MultipartPartHeaders,
            ),
            ("redirect location bytes", HttpLimitCode::RedirectRetained),
            ("http.limit.decoded-output", HttpLimitCode::DecodedOutput),
        ];
        for (message, code) in cases {
            let error = HttpError::resource_limit(message);
            assert_eq!(error.limit_code(), Some(code));
            assert_eq!(error.stable_error_code(), StableHttpErrorCode::Limit(code));
            assert_eq!(error.canonical_code(), code.as_str());
        }
    }

    #[test]
    fn redaction_applies_to_semantic_proxy_tls_and_url_errors() {
        let secret = "https://alice:password@example.test/private?token=secret-token";
        let errors = [
            (HttpError::InvalidUrl(secret.to_owned()), "http.invalid-url"),
            (HttpError::Proxy(secret.to_owned()), "http.proxy"),
            (HttpError::Tls(secret.to_owned()), "http.tls"),
            (
                HttpError::InvalidHeader("Authorization: Bearer secret-token".to_owned()),
                "http.invalid-header",
            ),
        ];
        for (error, stable_code) in errors {
            let display = error.to_string();
            let debug = format!("{error:?}");
            assert!(!display.contains("secret-token"));
            assert!(!display.contains("password"));
            assert!(!debug.contains("secret-token"));
            assert!(!debug.contains("password"));
            assert_eq!(error.stable_code(), stable_code);
        }
    }

    #[test]
    fn retryability_is_conservative_about_written_or_unknown_bytes() {
        assert_eq!(
            TransportError::Dns("resolver unavailable".to_owned()).retryability(),
            Retryability::Retryable
        );
        assert_eq!(
            TransportError::Connect("refused".to_owned()).retryability(),
            Retryability::Retryable
        );
        assert_eq!(
            TransportError::Write("write outcome unknown".to_owned()).retryability(),
            Retryability::Unknown
        );
        assert_eq!(
            TransportError::Read("partial response".to_owned()).retryability(),
            Retryability::Unknown
        );
        assert_eq!(
            TransportError::Protocol("bad framing".to_owned()).retryability(),
            Retryability::Terminal
        );
        assert!(!HttpError::Cancelled.is_retryable());
        assert_eq!(
            HttpError::Timeout(TimeoutPhase::Read).retryability(),
            Retryability::Unknown
        );
        assert_eq!(
            TransportError::Protocol("gzip decompression failed".to_owned()).stable_error_code(),
            StableHttpErrorCode::Decompression
        );
        assert_eq!(
            TransportError::Dns("resolver unavailable".to_owned()).stable_code(),
            "http.dns"
        );
    }

    #[test]
    fn diagnostic_collection_is_bounded_and_never_retains_message_text() {
        let diagnostic = HttpDiagnostic::new(
            HttpDiagnosticCode::Provider,
            "Authorization: Bearer secret-token",
        )
        .expect("diagnostic bound");
        assert_eq!(diagnostic.message(), "<redacted HTTP diagnostic>");
        assert_eq!(
            diagnostic.message_len(),
            "Authorization: Bearer secret-token".len()
        );
        assert!(!format!("{diagnostic:?}").contains("secret-token"));
        assert!(!diagnostic.to_string().contains("secret-token"));

        let too_large = HttpDiagnostic::new(
            HttpDiagnosticCode::Provider,
            "x".repeat(MAX_ERROR_DIAGNOSTIC_BYTES + 1),
        )
        .expect_err("diagnostic text bound");
        assert_eq!(too_large, HttpLimitCode::DiagnosticText);
        assert_eq!(
            HttpDiagnostic::new(HttpDiagnosticCode::Provider, "nul\0value")
                .expect_err("diagnostic NUL rejection"),
            HttpLimitCode::DiagnosticText
        );
        assert_eq!(
            HttpDiagnostic::new(HttpDiagnosticCode::Provider, "")
                .expect_err("diagnostic empty rejection"),
            HttpLimitCode::DiagnosticText
        );

        let mut diagnostics = HttpDiagnostics::default();
        for _ in 0..MAX_ERROR_DIAGNOSTICS {
            diagnostics
                .push(HttpDiagnostic::new(HttpDiagnosticCode::Cleanup, "x").expect("bound"))
                .expect("record bound");
        }
        assert_eq!(
            diagnostics
                .push(HttpDiagnostic::new(HttpDiagnosticCode::Cleanup, "x").expect("bound"))
                .expect_err("count bound"),
            HttpLimitCode::DiagnosticCount
        );
    }

    #[test]
    fn context_preserves_source_identity_without_changing_error_code() {
        let context = ErrorContextV1::new("http.proxy").expect("context");
        let error = HttpError::Proxy("proxy password=secret-token".to_owned())
            .with_context(context.clone());
        assert_eq!(error.stable_code(), "http.proxy");
        assert_eq!(error.stable_error_code(), StableHttpErrorCode::Proxy);
        assert_eq!(error.context(), Some(&context));
        assert!(error.source_error().is_some());
        assert!(!error.to_string().contains("secret-token"));
        assert!(!format!("{error:?}").contains("secret-token"));

        let replacement = ErrorContextV1::new("http.tls").expect("context");
        let replaced = error.with_context(replacement.clone());
        assert_eq!(replaced.context(), Some(&replacement));
        assert_eq!(replaced.stable_code(), "http.proxy");

        let mut nested = replaced;
        for _ in 0..=MAX_HTTP_ERROR_CONTEXT_DEPTH {
            nested = HttpError::Context {
                source: Box::new(nested),
                context: Box::new(replacement.clone()),
            };
        }
        assert_eq!(
            nested.context_depth(),
            MAX_HTTP_ERROR_CONTEXT_DEPTH.saturating_add(1)
        );
        assert_eq!(
            nested.stable_error_code(),
            StableHttpErrorCode::InternalInvariant
        );
        assert!(nested.to_string().contains("http.internal-invariant"));
    }
}
