// SPDX-License-Identifier: Apache-2.0
//! Bounded, streaming HTTP response decompression.
//!
//! The module is intentionally not registered by `lib.rs` yet.  It is the
//! concrete codec edge for the separately versioned `http.native/3` provider;
//! registration belongs to that provider's admission change.  The public
//! reader is nevertheless complete on its own so the provider can compose it
//! around any caller-owned `AsyncRead` without collecting the wire body first.
//!
//! `async-compression` supplies the format parsers and trailer/checksum
//! validation.  This module supplies the policy that a generic codec cannot
//! know: one content coding only, explicit limits, checked wire/decoded
//! counters, ratio accounting, cancellation, deadlines, and a final EOF check
//! for bytes left after one compressed member.

use async_compression::tokio::bufread::{BrotliDecoder, DeflateDecoder, GzipDecoder, ZlibDecoder};
use jmeter_rs_http::{CancellationRegistration, CancellationToken};
use std::fmt;
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::Instant;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncReadExt, BufReader, ReadBuf};

/// The separately identified subordinate codec capability.
pub const DECOMPRESSION_CAPABILITY_ID: &str = "http.decompression/1";

/// Hard maximum compressed response bytes accepted by this edge.
pub const HARD_MAX_WIRE_BYTES: u64 = 256 * 1024 * 1024;
/// Hard maximum decoded response bytes accepted by this edge.
pub const HARD_MAX_DECODED_BYTES: u64 = 512 * 1024 * 1024;
/// Hard maximum decoded-to-wire expansion multiplier.
pub const HARD_MAX_EXPANSION_RATIO: u64 = 1_000;
/// Hard maximum configured codec-state budget.
pub const HARD_MAX_CODEC_STATE_BYTES: u64 = 1024 * 1024;
/// Hard maximum input/output chunk size retained by this adapter.
pub const HARD_MAX_CHUNK_BYTES: usize = 64 * 1024;
/// Default bounded input chunk size.
pub const DEFAULT_INPUT_CHUNK_BYTES: usize = 16 * 1024;
/// Default bounded output chunk size.
pub const DEFAULT_OUTPUT_CHUNK_BYTES: usize = 16 * 1024;
/// Maximum content-encoding header bytes parsed by this edge.
pub const MAX_ENCODING_HEADER_BYTES: usize = 8 * 1024;
/// Maximum comma-separated coding tokens retained while parsing a header.
pub const MAX_ENCODING_TOKENS: usize = 8;

/// A single response content coding understood by the native codec edge.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ContentEncoding {
    /// No content coding (`identity`).
    Identity,
    /// RFC gzip coding.
    Gzip,
    /// HTTP `deflate` coding, whose wire representation is zlib-wrapped.
    Deflate,
    /// An explicitly represented zlib-wrapped DEFLATE stream (not an HTTP
    /// `Content-Encoding` token).
    Zlib,
    /// A raw DEFLATE stream, only when a caller has explicitly represented it
    /// (not an HTTP `Content-Encoding` token).
    RawDeflate,
    /// Brotli (`br`) coding.
    Brotli,
    /// More than one coding was supplied.  Stacking is represented so the
    /// caller can retain the source observation, but the decoder rejects it.
    Stacked(usize),
    /// A coding outside the explicitly represented set.
    Unknown,
}

impl ContentEncoding {
    /// Returns the canonical non-secret spelling of this coding.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Gzip => "gzip",
            Self::Deflate => "deflate",
            Self::Zlib => "zlib",
            Self::RawDeflate => "raw-deflate",
            Self::Brotli => "br",
            Self::Stacked(_) => "stacked",
            Self::Unknown => "unknown",
        }
    }

    /// Parses one or more `Content-Encoding` field values.
    ///
    /// Header fields are supplied separately so duplicate fields and comma
    /// lists are handled identically.  A missing field list means identity.
    /// Only the HTTP tokens `identity`, `gzip`, `deflate`, and `br` are
    /// admitted; explicit internal wrapper variants are not header aliases.
    /// A stacked list is returned as [`Self::Stacked`] for lossless admission
    /// diagnostics and is rejected by [`DecompressionReader::new`].  Unknown
    /// values fail without retaining the untrusted spelling.
    pub fn parse<I, S>(values: I) -> Result<Self, DecompressionError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut total_bytes = 0usize;
        let mut tokens = [None; MAX_ENCODING_TOKENS];
        let mut token_count = 0usize;

        for value in values {
            let value = value.as_ref();
            total_bytes = total_bytes
                .checked_add(value.len())
                .ok_or(DecompressionError::new(
                    DecompressionErrorCode::EncodingHeaderLimit,
                ))?;
            if total_bytes > MAX_ENCODING_HEADER_BYTES {
                return Err(DecompressionError::new(
                    DecompressionErrorCode::EncodingHeaderLimit,
                ));
            }
            for token in value.split(',') {
                let token = token.trim();
                if token.is_empty() {
                    return Err(DecompressionError::new(
                        DecompressionErrorCode::InvalidEncoding,
                    ));
                }
                token_count = token_count.checked_add(1).ok_or(DecompressionError::new(
                    DecompressionErrorCode::EncodingHeaderLimit,
                ))?;
                if token_count > MAX_ENCODING_TOKENS {
                    return Err(DecompressionError::new(
                        DecompressionErrorCode::EncodingHeaderLimit,
                    ));
                }
                let encoding = match token.to_ascii_lowercase().as_str() {
                    "identity" => Self::Identity,
                    "gzip" => Self::Gzip,
                    "deflate" => Self::Deflate,
                    "br" => Self::Brotli,
                    _ => {
                        return Err(DecompressionError::new(
                            DecompressionErrorCode::UnknownEncoding,
                        ));
                    }
                };
                tokens[token_count - 1] = Some(encoding);
            }
        }

        match token_count {
            0 => Ok(Self::Identity),
            1 => tokens[0].ok_or(DecompressionError::new(
                DecompressionErrorCode::InvalidEncoding,
            )),
            count => Ok(Self::Stacked(count)),
        }
    }

    /// Parses one `Content-Encoding` field value.
    pub fn parse_value(value: &str) -> Result<Self, DecompressionError> {
        Self::parse([value])
    }

    fn is_single_codec(self) -> bool {
        matches!(
            self,
            Self::Identity
                | Self::Gzip
                | Self::Deflate
                | Self::Zlib
                | Self::Brotli
                | Self::RawDeflate
        )
    }
}

/// Finite limits for one response-decompression operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecompressionLimits {
    /// Maximum bytes read from the wire, including bytes left after a member.
    pub max_wire_bytes: u64,
    /// Maximum bytes emitted by the decoder.
    pub max_decoded_bytes: u64,
    /// Maximum decoded-to-wire expansion multiplier.
    pub max_expansion_ratio: u64,
    /// Configured budget for codec state.  The selected codecs have no
    /// unbounded input buffer; this field is retained in the capability
    /// identity and must stay under the architecture hard ceiling.
    pub max_codec_state_bytes: u64,
    /// Maximum bytes requested from the caller's source in one read.
    pub input_chunk_bytes: usize,
    /// Maximum bytes requested from the decoder in one read.
    pub output_chunk_bytes: usize,
}

impl Default for DecompressionLimits {
    fn default() -> Self {
        Self {
            max_wire_bytes: HARD_MAX_WIRE_BYTES,
            max_decoded_bytes: HARD_MAX_DECODED_BYTES,
            max_expansion_ratio: HARD_MAX_EXPANSION_RATIO,
            max_codec_state_bytes: HARD_MAX_CODEC_STATE_BYTES,
            input_chunk_bytes: DEFAULT_INPUT_CHUNK_BYTES,
            output_chunk_bytes: DEFAULT_OUTPUT_CHUNK_BYTES,
        }
    }
}

impl DecompressionLimits {
    /// Validates all active limits against the compile-time hard ceilings.
    pub fn validate(self) -> Result<(), DecompressionError> {
        if self.max_wire_bytes == 0 || self.max_wire_bytes > HARD_MAX_WIRE_BYTES {
            return Err(DecompressionError::new(DecompressionErrorCode::WireLimit));
        }
        if self.max_decoded_bytes == 0 || self.max_decoded_bytes > HARD_MAX_DECODED_BYTES {
            return Err(DecompressionError::new(
                DecompressionErrorCode::DecodedLimit,
            ));
        }
        if self.max_expansion_ratio == 0 || self.max_expansion_ratio > HARD_MAX_EXPANSION_RATIO {
            return Err(DecompressionError::new(DecompressionErrorCode::RatioLimit));
        }
        if self.max_codec_state_bytes == 0
            || self.max_codec_state_bytes > HARD_MAX_CODEC_STATE_BYTES
        {
            return Err(DecompressionError::new(
                DecompressionErrorCode::CodecStateLimit,
            ));
        }
        if self.input_chunk_bytes == 0
            || self.input_chunk_bytes > HARD_MAX_CHUNK_BYTES
            || self.output_chunk_bytes == 0
            || self.output_chunk_bytes > HARD_MAX_CHUNK_BYTES
        {
            return Err(DecompressionError::new(
                DecompressionErrorCode::InvalidLimit,
            ));
        }
        Ok(())
    }
}

/// Typed failures from a caller-owned deadline wake provider.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DeadlineWakeError {
    /// The provider could not retain a bounded registration.
    Unavailable,
    /// The provider violated its registration contract.
    ProviderInvariant,
}

/// A registration held while a deadline-bearing read is pending.
///
/// The caller-owned scheduler returns this guard after arranging a wake at or
/// before the supplied deadline. Dropping it must unregister that one wake
/// from the scheduler so a completed operation does not retain its waker.
pub struct DeadlineRegistration {
    retire: Option<Box<dyn FnOnce() -> Result<(), DeadlineWakeError> + Send + 'static>>,
}

impl DeadlineRegistration {
    /// Creates a registration whose callback releases the scheduler slot.
    #[must_use]
    pub fn new<F>(retire: F) -> Self
    where
        F: FnOnce() -> Result<(), DeadlineWakeError> + Send + 'static,
    {
        Self {
            retire: Some(Box::new(retire)),
        }
    }

    /// Creates a registration for schedulers that do not need explicit
    /// unregistration.
    #[must_use]
    pub const fn detached() -> Self {
        Self { retire: None }
    }

    /// Explicitly retires this registration and reports provider failure.
    ///
    /// The callback is consumed exactly once. A callback panic is contained at
    /// this boundary and reported as a provider-invariant violation.
    pub fn retire(&mut self) -> Result<(), DeadlineWakeError> {
        let Some(retire) = self.retire.take() else {
            return Ok(());
        };
        match catch_unwind(AssertUnwindSafe(retire)) {
            Ok(result) => result,
            Err(_) => Err(DeadlineWakeError::ProviderInvariant),
        }
    }
}

impl Drop for DeadlineRegistration {
    fn drop(&mut self) {
        if let Some(retire) = self.retire.take() {
            // Drop cannot return an error. Keep this fallback bounded to one
            // callback and contain both provider errors and panics.
            let _ = catch_unwind(AssertUnwindSafe(retire));
        }
    }
}

/// Caller-owned finite wake capability for an absolute deadline.
///
/// Implementations must arrange one non-blocking wake at or before `deadline`
/// and return a guard that releases the registration. They must not create an
/// executor, discover an ambient runtime, sleep, or silently downgrade a
/// failed registration. A typed registration error is mapped to a stable,
/// redacted decompression error by the reader.
pub trait DeadlineWake: Send + Sync + 'static {
    /// Registers `waker` for the caller's authoritative absolute deadline.
    fn register(
        &self,
        deadline: Instant,
        waker: &Waker,
    ) -> Result<DeadlineRegistration, DeadlineWakeError>;
}

/// Caller-owned cancellation and absolute deadline controls.
#[derive(Clone, Default)]
pub struct DecompressionControls {
    cancellation: CancellationToken,
    deadline: Option<Instant>,
    deadline_wake: Option<std::sync::Arc<dyn DeadlineWake>>,
}

impl fmt::Debug for DecompressionControls {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecompressionControls")
            .field("cancellation", &self.cancellation)
            .field("deadline", &self.deadline)
            .field("deadline_wake", &self.deadline_wake.is_some())
            .finish()
    }
}

impl DecompressionControls {
    /// Creates controls from a caller-owned cancellation token.
    #[must_use]
    pub fn new(cancellation: &CancellationToken) -> Self {
        Self {
            cancellation: cancellation.clone(),
            deadline: None,
            deadline_wake: None,
        }
    }

    /// Adds one absolute monotonic deadline without changing the token.
    ///
    /// A future deadline must be paired with [`Self::with_deadline_wake`]; the
    /// constructor rejects a deadline that has no caller-owned wake source.
    #[must_use]
    pub const fn with_deadline(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// Supplies the explicit caller-owned scheduler used to wake a pending
    /// read at the configured absolute deadline.
    #[must_use]
    pub fn with_deadline_wake(mut self, wake: std::sync::Arc<dyn DeadlineWake>) -> Self {
        self.deadline_wake = Some(wake);
        self
    }

    /// Returns the copied cancellation token used by this operation.
    #[must_use]
    pub const fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }

    /// Returns the absolute deadline, if one was supplied.
    #[must_use]
    pub const fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// Returns whether an explicit deadline wake capability was supplied.
    #[must_use]
    pub fn has_deadline_wake(&self) -> bool {
        self.deadline_wake.is_some()
    }

    fn check(&self) -> Result<(), DecompressionError> {
        if self.cancellation.is_cancelled() {
            return Err(DecompressionError::new(DecompressionErrorCode::Cancelled));
        }
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(DecompressionError::new(DecompressionErrorCode::Deadline));
        }
        Ok(())
    }

    fn check_admission(&self) -> Result<(), DecompressionError> {
        self.check()?;
        if self.deadline.is_some() && self.deadline_wake.is_none() {
            return Err(DecompressionError::new(
                DecompressionErrorCode::DeadlineWakeUnavailable,
            ));
        }
        Ok(())
    }
}

/// Stable error categories emitted by the decompression edge.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DecompressionErrorCode {
    /// A configured bound or caller-provided chunk was invalid.
    InvalidLimit,
    /// The content-encoding spelling or list shape is invalid.
    InvalidEncoding,
    /// A content coding is outside this explicit capability.
    UnknownEncoding,
    /// More than one coding was supplied.
    StackedEncoding,
    /// The bounded encoding-header parser rejected its input size/count.
    EncodingHeaderLimit,
    /// The compressed wire-byte bound was exceeded.
    WireLimit,
    /// The decoded-byte bound was exceeded.
    DecodedLimit,
    /// The decoded-to-wire expansion bound was exceeded.
    RatioLimit,
    /// The configured codec-state budget was invalid.
    CodecStateLimit,
    /// A compressed member ended before its trailer/end marker.
    Truncated,
    /// A codec rejected the member or its checksum/trailer.
    Malformed,
    /// Bytes remained after exactly one complete compressed member.
    TrailingData,
    /// The caller requested cancellation.
    Cancelled,
    /// The bounded cancellation wake table could not retain this operation.
    CancellationWakeUnavailable,
    /// The caller's absolute deadline elapsed.
    Deadline,
    /// No caller-owned wake capability was supplied for a future deadline.
    DeadlineWakeUnavailable,
    /// The caller-owned deadline wake provider rejected registration.
    DeadlineRegistration,
    /// The caller-owned deadline wake provider rejected retirement.
    DeadlineRetirement,
    /// The caller-owned deadline wake provider violated its contract.
    ProviderInvariant,
    /// A checked wire/decoded counter could not be advanced.
    CounterOverflow,
    /// A bounded destination allocation failed.
    Allocation,
    /// The underlying reader failed without exposing provider text.
    Io,
}

impl DecompressionErrorCode {
    /// Returns the stable redacted machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidLimit => "http.decompression.invalid-limit",
            Self::InvalidEncoding => "http.decompression.invalid-encoding",
            Self::UnknownEncoding => "http.decompression.unknown-encoding",
            Self::StackedEncoding => "http.decompression.stacked-encoding",
            Self::EncodingHeaderLimit => "http.limit.content-encoding",
            Self::WireLimit => "http.limit.compressed-input",
            Self::DecodedLimit => "http.limit.decoded-output",
            Self::RatioLimit => "http.limit.expansion-ratio",
            Self::CodecStateLimit => "http.limit.codec-state",
            Self::Truncated => "http.decompression.truncated",
            Self::Malformed => "http.decompression.malformed",
            Self::TrailingData => "http.decompression.trailing-data",
            Self::Cancelled => "http.cancelled",
            Self::CancellationWakeUnavailable => "http.cancelled.wake-unavailable",
            Self::Deadline => "http.timeout.decompression",
            Self::DeadlineWakeUnavailable => "http.timeout.deadline-wake-unavailable",
            Self::DeadlineRegistration => "http.timeout.deadline-registration",
            Self::DeadlineRetirement => "http.timeout.deadline-retirement",
            Self::ProviderInvariant => "http.decompression.provider-invariant",
            Self::CounterOverflow => "http.decompression.counter-overflow",
            Self::Allocation => "http.decompression.allocation",
            Self::Io => "http.decompression.io",
        }
    }
}

/// A typed, redacted decompression failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DecompressionError {
    code: DecompressionErrorCode,
    cleanup_code: Option<DecompressionErrorCode>,
}

impl DecompressionError {
    const fn new(code: DecompressionErrorCode) -> Self {
        Self {
            code,
            cleanup_code: None,
        }
    }

    /// Returns the stable error category.
    #[must_use]
    pub const fn code(self) -> DecompressionErrorCode {
        self.code
    }

    /// Returns the stable cleanup category when the primary operation and its
    /// deadline-registration retirement both failed.
    #[must_use]
    pub const fn cleanup_code(self) -> Option<DecompressionErrorCode> {
        self.cleanup_code
    }

    fn with_cleanup(self, cleanup: Self) -> Self {
        Self {
            code: self.code,
            cleanup_code: self.cleanup_code.or(Some(cleanup.code)),
        }
    }

    fn into_io(self) -> io::Error {
        io::Error::other(self)
    }
}

fn map_deadline_registration_error(error: DeadlineWakeError) -> DecompressionError {
    match error {
        DeadlineWakeError::Unavailable => {
            DecompressionError::new(DecompressionErrorCode::DeadlineRegistration)
        }
        DeadlineWakeError::ProviderInvariant => {
            DecompressionError::new(DecompressionErrorCode::ProviderInvariant)
        }
    }
}

fn map_deadline_retirement_error(error: DeadlineWakeError) -> DecompressionError {
    match error {
        DeadlineWakeError::Unavailable => {
            DecompressionError::new(DecompressionErrorCode::DeadlineRetirement)
        }
        DeadlineWakeError::ProviderInvariant => {
            DecompressionError::new(DecompressionErrorCode::ProviderInvariant)
        }
    }
}

impl fmt::Display for DecompressionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for DecompressionError {}

/// Checked counters returned only after a complete, validated stream.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DecompressionStats {
    /// The one explicitly selected coding.
    pub encoding: ContentEncoding,
    /// Bytes read from the caller's wire source.
    pub wire_bytes: u64,
    /// Bytes emitted by the decoder.
    pub decoded_bytes: u64,
}

impl DecompressionStats {
    /// Returns whether the result represents an empty body.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.wire_bytes == 0 && self.decoded_bytes == 0
    }
}

struct CountedReader<R> {
    inner: R,
    wire_bytes: Option<u64>,
}

impl<R> CountedReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            wire_bytes: Some(0),
        }
    }

    fn wire_bytes(&self) -> Result<u64, DecompressionError> {
        self.wire_bytes.ok_or(DecompressionError::new(
            DecompressionErrorCode::CounterOverflow,
        ))
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for CountedReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buffer);
        if let Poll::Ready(Ok(())) = result {
            let Some(read) = buffer.filled().len().checked_sub(before) else {
                self.wire_bytes = None;
                return Poll::Ready(Err(io::Error::other(
                    DecompressionErrorCode::CounterOverflow.as_str(),
                )));
            };
            let Some(current) = self.wire_bytes else {
                return Poll::Ready(Err(io::Error::other(
                    DecompressionErrorCode::CounterOverflow.as_str(),
                )));
            };
            let Ok(read) = u64::try_from(read) else {
                self.wire_bytes = None;
                return Poll::Ready(Err(io::Error::other(
                    DecompressionErrorCode::CounterOverflow.as_str(),
                )));
            };
            self.wire_bytes = current.checked_add(read);
            if self.wire_bytes.is_none() {
                return Poll::Ready(Err(io::Error::other(
                    DecompressionErrorCode::CounterOverflow.as_str(),
                )));
            }
        }
        result
    }
}

type BufferedInput<R> = BufReader<CountedReader<R>>;

enum Decoder<R> {
    Identity(Pin<Box<BufferedInput<R>>>),
    Gzip(Pin<Box<GzipDecoder<BufferedInput<R>>>>),
    Deflate(Pin<Box<ZlibDecoder<BufferedInput<R>>>>),
    Zlib(Pin<Box<ZlibDecoder<BufferedInput<R>>>>),
    RawDeflate(Pin<Box<DeflateDecoder<BufferedInput<R>>>>),
    Brotli(Pin<Box<BrotliDecoder<BufferedInput<R>>>>),
}

impl<R: AsyncRead + Unpin> Decoder<R> {
    fn new(reader: R, encoding: ContentEncoding, limits: DecompressionLimits) -> Self {
        // The validated wire limit is nonzero, but the lower bound keeps the
        // capacity calculation checked on every supported target.
        let max_wire_as_usize = usize::try_from(limits.max_wire_bytes).unwrap_or(usize::MAX);
        let capacity = limits.input_chunk_bytes.min(max_wire_as_usize.max(1));
        let input = BufReader::with_capacity(capacity, CountedReader::new(reader));
        match encoding {
            ContentEncoding::Identity => Self::Identity(Box::pin(input)),
            ContentEncoding::Gzip => {
                let mut decoder = GzipDecoder::new(input);
                decoder.multiple_members(false);
                Self::Gzip(Box::pin(decoder))
            }
            ContentEncoding::Deflate => {
                let mut decoder = ZlibDecoder::new(input);
                decoder.multiple_members(false);
                Self::Deflate(Box::pin(decoder))
            }
            ContentEncoding::Zlib => {
                let mut decoder = ZlibDecoder::new(input);
                decoder.multiple_members(false);
                Self::Zlib(Box::pin(decoder))
            }
            ContentEncoding::RawDeflate => {
                let mut decoder = DeflateDecoder::new(input);
                decoder.multiple_members(false);
                Self::RawDeflate(Box::pin(decoder))
            }
            ContentEncoding::Brotli => {
                let mut decoder = BrotliDecoder::new(input);
                decoder.multiple_members(false);
                Self::Brotli(Box::pin(decoder))
            }
            ContentEncoding::Stacked(_) | ContentEncoding::Unknown => {
                // Callers validate this before constructing the enum.  Keep a
                // total constructor for the type system; the unreachable
                // variant is never exposed by `DecompressionReader::new`.
                Self::Identity(Box::pin(input))
            }
        }
    }

    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self {
            Self::Identity(reader) => reader.as_mut().poll_read(cx, buffer),
            Self::Gzip(decoder) => decoder.as_mut().poll_read(cx, buffer),
            Self::Deflate(decoder) => decoder.as_mut().poll_read(cx, buffer),
            Self::Zlib(decoder) => decoder.as_mut().poll_read(cx, buffer),
            Self::RawDeflate(decoder) => decoder.as_mut().poll_read(cx, buffer),
            Self::Brotli(decoder) => decoder.as_mut().poll_read(cx, buffer),
        }
    }

    fn poll_member_eof(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        match self {
            Self::Identity(_) => Poll::Ready(Ok(true)),
            Self::Gzip(decoder) => poll_input_eof(decoder.as_mut().get_pin_mut(), cx),
            Self::Deflate(decoder) => poll_input_eof(decoder.as_mut().get_pin_mut(), cx),
            Self::Zlib(decoder) => poll_input_eof(decoder.as_mut().get_pin_mut(), cx),
            Self::RawDeflate(decoder) => poll_input_eof(decoder.as_mut().get_pin_mut(), cx),
            Self::Brotli(decoder) => poll_input_eof(decoder.as_mut().get_pin_mut(), cx),
        }
    }

    fn wire_bytes(&self) -> Result<u64, DecompressionError> {
        match self {
            Self::Identity(reader) => reader.as_ref().get_ref().get_ref().wire_bytes(),
            Self::Gzip(decoder) => decoder.as_ref().get_ref().get_ref().get_ref().wire_bytes(),
            Self::Deflate(decoder) => decoder.as_ref().get_ref().get_ref().get_ref().wire_bytes(),
            Self::Zlib(decoder) => decoder.as_ref().get_ref().get_ref().get_ref().wire_bytes(),
            Self::RawDeflate(decoder) => {
                decoder.as_ref().get_ref().get_ref().get_ref().wire_bytes()
            }
            Self::Brotli(decoder) => decoder.as_ref().get_ref().get_ref().get_ref().wire_bytes(),
        }
    }
}

fn poll_input_eof<R: AsyncRead + Unpin>(
    mut input: Pin<&mut BufferedInput<R>>,
    cx: &mut Context<'_>,
) -> Poll<io::Result<bool>> {
    match input.as_mut().poll_fill_buf(cx) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Ok(bytes)) => Poll::Ready(Ok(bytes.is_empty())),
        Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
    }
}

#[derive(Clone, Copy)]
enum ReaderState {
    Reading,
    CheckingEof,
    Done,
    Failed(DecompressionError),
}

/// Incremental response decoder over one caller-owned asynchronous reader.
///
/// The decoder emits into caller-owned `ReadBuf`s and never stores decoded
/// body bytes.  Use [`Self::decode_to`] when a transactional, bounded `Vec`
/// projection is desired; that helper removes all bytes appended by the
/// failed operation before returning an error.
pub struct DecompressionReader<R> {
    encoding: ContentEncoding,
    limits: DecompressionLimits,
    controls: DecompressionControls,
    decoder: Decoder<R>,
    state: ReaderState,
    decoded_bytes: Option<u64>,
    registration: Option<CancellationRegistration>,
    deadline_registration: Option<DeadlineRegistration>,
}

impl<R: AsyncRead + Unpin> Unpin for DecompressionReader<R> {}

impl<R: AsyncRead + Unpin> DecompressionReader<R> {
    /// Creates one bounded decoder with explicit caller controls.
    pub fn new(
        reader: R,
        encoding: ContentEncoding,
        limits: DecompressionLimits,
        controls: DecompressionControls,
    ) -> Result<Self, DecompressionError> {
        limits.validate()?;
        if !encoding.is_single_codec() {
            let code = match encoding {
                ContentEncoding::Stacked(_) => DecompressionErrorCode::StackedEncoding,
                ContentEncoding::Unknown => DecompressionErrorCode::UnknownEncoding,
                _ => DecompressionErrorCode::InvalidEncoding,
            };
            return Err(DecompressionError::new(code));
        }
        controls.check_admission()?;
        Ok(Self {
            decoder: Decoder::new(reader, encoding, limits),
            encoding,
            limits,
            controls,
            state: ReaderState::Reading,
            decoded_bytes: Some(0),
            registration: None,
            deadline_registration: None,
        })
    }

    /// Creates a decoder using one copied token and optional absolute
    /// `std::time::Instant` deadline. A future deadline without an explicit
    /// wake capability is rejected before the source is touched.
    pub fn new_with_controls(
        reader: R,
        encoding: ContentEncoding,
        limits: DecompressionLimits,
        cancellation: &CancellationToken,
        deadline: Option<Instant>,
    ) -> Result<Self, DecompressionError> {
        Self::new(
            reader,
            encoding,
            limits,
            DecompressionControls::new(cancellation).with_optional_deadline(deadline),
        )
    }

    /// Creates a decoder with a caller-owned deadline wake capability.
    pub fn new_with_controls_and_deadline_wake(
        reader: R,
        encoding: ContentEncoding,
        limits: DecompressionLimits,
        cancellation: &CancellationToken,
        deadline: Option<Instant>,
        deadline_wake: std::sync::Arc<dyn DeadlineWake>,
    ) -> Result<Self, DecompressionError> {
        Self::new(
            reader,
            encoding,
            limits,
            DecompressionControls::new(cancellation)
                .with_optional_deadline(deadline)
                .with_deadline_wake(deadline_wake),
        )
    }

    /// Returns the selected coding.
    #[must_use]
    pub const fn encoding(&self) -> ContentEncoding {
        self.encoding
    }

    /// Returns the caller's finite policy.
    #[must_use]
    pub const fn limits(&self) -> DecompressionLimits {
        self.limits
    }

    /// Returns checked counters observed so far.
    pub fn counters(&self) -> Result<(u64, u64), DecompressionError> {
        Ok((
            self.decoder.wire_bytes()?,
            self.decoded_bytes.ok_or(DecompressionError::new(
                DecompressionErrorCode::CounterOverflow,
            ))?,
        ))
    }

    /// Returns final stats after successful EOF validation, or the current
    /// checked counters while the stream is still in progress.
    pub fn stats(&self) -> Result<DecompressionStats, DecompressionError> {
        let (wire_bytes, decoded_bytes) = self.counters()?;
        Ok(DecompressionStats {
            encoding: self.encoding,
            wire_bytes,
            decoded_bytes,
        })
    }

    /// Reads one caller-owned bounded chunk and maps provider I/O to the
    /// stable, redacted error type.
    pub async fn read_chunk(&mut self, buffer: &mut [u8]) -> Result<usize, DecompressionError> {
        if buffer.is_empty() {
            let error = self.fail(DecompressionError::new(
                DecompressionErrorCode::InvalidLimit,
            ));
            return Err(error);
        }
        match AsyncReadExt::read(self, buffer).await {
            Ok(size) => Ok(size),
            Err(_) => match self.state {
                ReaderState::Failed(error) => Err(error),
                _ => Err(self.fail(DecompressionError::new(DecompressionErrorCode::Io))),
            },
        }
    }

    /// Collects decoded chunks into a caller-owned vector transactionally.
    ///
    /// The vector may contain an existing prefix.  On any error, including a
    /// codec/trailer failure after earlier output, the prefix is restored and
    /// no partial decoded bytes from this operation remain visible.
    pub async fn decode_to(
        &mut self,
        destination: &mut Vec<u8>,
    ) -> Result<DecompressionStats, DecompressionError> {
        let original_len = destination.len();
        let mut chunk = vec![0_u8; self.limits.output_chunk_bytes];
        loop {
            let read = self.read_chunk(&mut chunk).await;
            let read = match read {
                Ok(read) => read,
                Err(error) => {
                    destination.truncate(original_len);
                    if !matches!(self.state, ReaderState::Failed(_)) {
                        let error = self.fail(error);
                        return Err(error);
                    }
                    return Err(error);
                }
            };
            if read == 0 {
                return match self.stats() {
                    Ok(stats) => Ok(stats),
                    Err(error) => {
                        destination.truncate(original_len);
                        let error = self.fail(error);
                        Err(error)
                    }
                };
            }
            if destination.try_reserve_exact(read).is_err() {
                destination.truncate(original_len);
                let error = DecompressionError::new(DecompressionErrorCode::Allocation);
                let error = self.fail(error);
                return Err(error);
            }
            destination.extend_from_slice(&chunk[..read]);
        }
    }

    fn ensure_registration(&mut self, waker: &Waker) -> Result<(), DecompressionError> {
        self.registration.take();
        let waker = waker.clone();
        let registration = self.controls.cancellation.register_waker(move || {
            waker.wake_by_ref();
        });
        if !registration.is_registered() {
            return if self.controls.cancellation.is_cancelled() {
                Err(DecompressionError::new(DecompressionErrorCode::Cancelled))
            } else {
                Err(DecompressionError::new(
                    DecompressionErrorCode::CancellationWakeUnavailable,
                ))
            };
        }
        self.registration = Some(registration);
        Ok(())
    }

    fn ensure_deadline_registration(&mut self, waker: &Waker) -> Result<(), DecompressionError> {
        let Some(deadline) = self.controls.deadline else {
            return self.retire_deadline_registration();
        };
        let Some(wake) = self.controls.deadline_wake.as_ref().cloned() else {
            return Err(DecompressionError::new(
                DecompressionErrorCode::DeadlineWakeUnavailable,
            ));
        };
        self.retire_deadline_registration()?;
        let registration = catch_unwind(AssertUnwindSafe(|| wake.register(deadline, waker)))
            .map_err(|_| map_deadline_registration_error(DeadlineWakeError::ProviderInvariant))?
            .map_err(map_deadline_registration_error)?;
        self.deadline_registration = Some(registration);
        Ok(())
    }

    fn retire_deadline_registration(&mut self) -> Result<(), DecompressionError> {
        let Some(mut registration) = self.deadline_registration.take() else {
            return Ok(());
        };
        registration.retire().map_err(map_deadline_retirement_error)
    }

    fn check_controls(&self) -> Result<(), DecompressionError> {
        self.controls.check()
    }

    fn check_limits(&self) -> Result<(), DecompressionError> {
        let wire_bytes = self.decoder.wire_bytes()?;
        if wire_bytes > self.limits.max_wire_bytes {
            return Err(DecompressionError::new(DecompressionErrorCode::WireLimit));
        }
        let decoded_bytes = self.decoded_bytes.ok_or(DecompressionError::new(
            DecompressionErrorCode::CounterOverflow,
        ))?;
        if decoded_bytes > self.limits.max_decoded_bytes {
            return Err(DecompressionError::new(
                DecompressionErrorCode::DecodedLimit,
            ));
        }
        let maximum = wire_bytes
            .checked_mul(self.limits.max_expansion_ratio)
            .ok_or(DecompressionError::new(
                DecompressionErrorCode::CounterOverflow,
            ))?;
        if decoded_bytes > maximum {
            return Err(DecompressionError::new(DecompressionErrorCode::RatioLimit));
        }
        Ok(())
    }

    fn record_decoded(&mut self, bytes: usize) -> Result<(), DecompressionError> {
        let bytes = u64::try_from(bytes)
            .map_err(|_| DecompressionError::new(DecompressionErrorCode::CounterOverflow))?;
        let current = self.decoded_bytes.ok_or(DecompressionError::new(
            DecompressionErrorCode::CounterOverflow,
        ))?;
        self.decoded_bytes = Some(current.checked_add(bytes).ok_or(DecompressionError::new(
            DecompressionErrorCode::CounterOverflow,
        ))?);
        Ok(())
    }

    fn fail(&mut self, error: DecompressionError) -> DecompressionError {
        self.registration.take();
        let error = match self.retire_deadline_registration() {
            Ok(()) => error,
            Err(cleanup) => error.with_cleanup(cleanup),
        };
        self.state = ReaderState::Failed(error);
        error
    }

    fn map_codec_error(&self, error: io::Error) -> DecompressionError {
        if self.decoder.wire_bytes().is_err() {
            return DecompressionError::new(DecompressionErrorCode::CounterOverflow);
        }
        match error.kind() {
            io::ErrorKind::UnexpectedEof => {
                DecompressionError::new(DecompressionErrorCode::Truncated)
            }
            io::ErrorKind::InvalidData => {
                DecompressionError::new(DecompressionErrorCode::Malformed)
            }
            _ => DecompressionError::new(DecompressionErrorCode::Io),
        }
    }

    fn poll_inner(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() > self.limits.output_chunk_bytes {
            let error = DecompressionError::new(DecompressionErrorCode::InvalidLimit);
            let error = self.fail(error);
            return Poll::Ready(Err(error.into_io()));
        }
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            match self.state {
                ReaderState::Done => return Poll::Ready(Ok(())),
                ReaderState::Failed(error) => return Poll::Ready(Err(error.into_io())),
                ReaderState::Reading => {
                    if let Err(error) = self.check_controls() {
                        let error = self.fail(error);
                        return Poll::Ready(Err(error.into_io()));
                    }
                    if let Err(error) = self.ensure_deadline_registration(cx.waker()) {
                        let error = self.fail(error);
                        return Poll::Ready(Err(error.into_io()));
                    }
                    if let Err(error) = self.ensure_registration(cx.waker()) {
                        let error = self.fail(error);
                        return Poll::Ready(Err(error.into_io()));
                    }
                    let before = buffer.filled().len();
                    match self.decoder.poll_read(cx, buffer) {
                        Poll::Pending => {
                            if let Err(error) = self.check_controls() {
                                buffer.set_filled(before);
                                let error = self.fail(error);
                                return Poll::Ready(Err(error.into_io()));
                            }
                            if let Err(error) = self.check_limits() {
                                buffer.set_filled(before);
                                let error = self.fail(error);
                                return Poll::Ready(Err(error.into_io()));
                            }
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(io_error)) => {
                            buffer.set_filled(before);
                            let error = self.map_codec_error(io_error);
                            let error = self.fail(error);
                            return Poll::Ready(Err(error.into_io()));
                        }
                        Poll::Ready(Ok(())) => {
                            if let Err(error) = self.retire_deadline_registration() {
                                buffer.set_filled(before);
                                let error = self.fail(error);
                                return Poll::Ready(Err(error.into_io()));
                            }
                            if let Err(error) = self.check_controls() {
                                buffer.set_filled(before);
                                let error = self.fail(error);
                                return Poll::Ready(Err(error.into_io()));
                            }
                            let Some(produced) = buffer.filled().len().checked_sub(before) else {
                                buffer.set_filled(before);
                                let error = DecompressionError::new(
                                    DecompressionErrorCode::CounterOverflow,
                                );
                                let error = self.fail(error);
                                return Poll::Ready(Err(error.into_io()));
                            };
                            if let Err(error) = self
                                .record_decoded(produced)
                                .and_then(|()| self.check_limits())
                            {
                                buffer.set_filled(before);
                                let error = self.fail(error);
                                return Poll::Ready(Err(error.into_io()));
                            }
                            if produced != 0 {
                                return Poll::Ready(Ok(()));
                            }
                            self.state = ReaderState::CheckingEof;
                        }
                    }
                }
                ReaderState::CheckingEof => {
                    if let Err(error) = self.check_controls() {
                        let error = self.fail(error);
                        return Poll::Ready(Err(error.into_io()));
                    }
                    if let Err(error) = self.ensure_deadline_registration(cx.waker()) {
                        let error = self.fail(error);
                        return Poll::Ready(Err(error.into_io()));
                    }
                    match self.decoder.poll_member_eof(cx) {
                        Poll::Pending => {
                            if let Err(error) = self.check_limits() {
                                let error = self.fail(error);
                                return Poll::Ready(Err(error.into_io()));
                            }
                            if let Err(error) = self.ensure_registration(cx.waker()) {
                                let error = self.fail(error);
                                return Poll::Ready(Err(error.into_io()));
                            }
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(io_error)) => {
                            let error = self.map_codec_error(io_error);
                            let error = self.fail(error);
                            return Poll::Ready(Err(error.into_io()));
                        }
                        Poll::Ready(Ok(true)) => {
                            if let Err(error) = self.check_limits() {
                                let error = self.fail(error);
                                return Poll::Ready(Err(error.into_io()));
                            }
                            if let Err(error) = self.retire_deadline_registration() {
                                let error = self.fail(error);
                                return Poll::Ready(Err(error.into_io()));
                            }
                            self.registration.take();
                            self.state = ReaderState::Done;
                            return Poll::Ready(Ok(()));
                        }
                        Poll::Ready(Ok(false)) => {
                            let error =
                                DecompressionError::new(DecompressionErrorCode::TrailingData);
                            let error = self.fail(error);
                            return Poll::Ready(Err(error.into_io()));
                        }
                    }
                }
            }
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for DecompressionReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.as_mut().get_mut().poll_inner(cx, buffer)
    }
}

impl DecompressionControls {
    fn with_optional_deadline(mut self, deadline: Option<Instant>) -> Self {
        self.deadline = deadline;
        self
    }
}

/// Decodes one response into a caller-owned vector with transactional output.
pub async fn decode_to<R: AsyncRead + Unpin>(
    reader: R,
    encoding: ContentEncoding,
    limits: DecompressionLimits,
    cancellation: &CancellationToken,
    deadline: Option<Instant>,
    destination: &mut Vec<u8>,
) -> Result<DecompressionStats, DecompressionError> {
    let mut decoder =
        DecompressionReader::new_with_controls(reader, encoding, limits, cancellation, deadline)?;
    decoder.decode_to(destination).await
}

/// Decodes one response using an explicit caller-owned deadline wake
/// capability and transactional output.
pub async fn decode_to_with_deadline_wake<R: AsyncRead + Unpin>(
    reader: R,
    encoding: ContentEncoding,
    limits: DecompressionLimits,
    cancellation: &CancellationToken,
    deadline: Option<Instant>,
    deadline_wake: std::sync::Arc<dyn DeadlineWake>,
    destination: &mut Vec<u8>,
) -> Result<DecompressionStats, DecompressionError> {
    let mut decoder = DecompressionReader::new_with_controls_and_deadline_wake(
        reader,
        encoding,
        limits,
        cancellation,
        deadline,
        deadline_wake,
    )?;
    decoder.decode_to(destination).await
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::panic,
        reason = "fixed in-process codec fixtures use assertion-context expectations"
    )]

    use super::*;
    use async_compression::tokio::write::{
        BrotliEncoder, DeflateEncoder, GzipEncoder, ZlibEncoder,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Poll;
    use tokio::io::{AsyncWrite, AsyncWriteExt};

    #[derive(Default)]
    struct VecWriter {
        bytes: Vec<u8>,
    }

    impl AsyncWrite for VecWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.bytes.extend_from_slice(bytes);
            Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct FragmentedReader {
        bytes: Vec<u8>,
        offset: usize,
        maximum: usize,
    }

    impl FragmentedReader {
        fn new(bytes: Vec<u8>, maximum: usize) -> Self {
            Self {
                bytes,
                offset: 0,
                maximum,
            }
        }
    }

    impl AsyncRead for FragmentedReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.offset == self.bytes.len() {
                return Poll::Ready(Ok(()));
            }
            let amount = self
                .maximum
                .min(self.bytes.len() - self.offset)
                .min(buffer.remaining());
            buffer.put_slice(&self.bytes[self.offset..self.offset + amount]);
            self.offset += amount;
            Poll::Ready(Ok(()))
        }
    }

    struct PendingReader;

    impl AsyncRead for PendingReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    #[derive(Default)]
    struct ReadyDeadlineWake {
        registrations: AtomicUsize,
    }

    impl DeadlineWake for ReadyDeadlineWake {
        fn register(
            &self,
            _deadline: Instant,
            _waker: &Waker,
        ) -> Result<DeadlineRegistration, DeadlineWakeError> {
            self.registrations.fetch_add(1, Ordering::Relaxed);
            Ok(DeadlineRegistration::detached())
        }
    }

    struct ErrorDeadlineWake {
        error: DeadlineWakeError,
    }

    impl DeadlineWake for ErrorDeadlineWake {
        fn register(
            &self,
            _deadline: Instant,
            _waker: &Waker,
        ) -> Result<DeadlineRegistration, DeadlineWakeError> {
            Err(self.error)
        }
    }

    struct RetirementErrorDeadlineWake;

    impl DeadlineWake for RetirementErrorDeadlineWake {
        fn register(
            &self,
            _deadline: Instant,
            _waker: &Waker,
        ) -> Result<DeadlineRegistration, DeadlineWakeError> {
            Ok(DeadlineRegistration::new(|| {
                Err(DeadlineWakeError::Unavailable)
            }))
        }
    }

    async fn encode(encoding: ContentEncoding, body: &[u8]) -> Vec<u8> {
        let writer = VecWriter::default();
        match encoding {
            ContentEncoding::Gzip => {
                let mut encoder = GzipEncoder::new(writer);
                encoder.write_all(body).await.expect("gzip write");
                encoder.shutdown().await.expect("gzip shutdown");
                encoder.into_inner().bytes
            }
            ContentEncoding::Deflate => {
                let mut encoder = ZlibEncoder::new(writer);
                encoder.write_all(body).await.expect("deflate write");
                encoder.shutdown().await.expect("deflate shutdown");
                encoder.into_inner().bytes
            }
            ContentEncoding::Zlib => {
                let mut encoder = ZlibEncoder::new(writer);
                encoder.write_all(body).await.expect("zlib write");
                encoder.shutdown().await.expect("zlib shutdown");
                encoder.into_inner().bytes
            }
            ContentEncoding::Brotli => {
                let mut encoder = BrotliEncoder::new(writer);
                encoder.write_all(body).await.expect("brotli write");
                encoder.shutdown().await.expect("brotli shutdown");
                encoder.into_inner().bytes
            }
            ContentEncoding::RawDeflate => {
                let mut encoder = DeflateEncoder::new(writer);
                encoder.write_all(body).await.expect("raw deflate write");
                encoder.shutdown().await.expect("raw deflate shutdown");
                encoder.into_inner().bytes
            }
            ContentEncoding::Identity | ContentEncoding::Stacked(_) | ContentEncoding::Unknown => {
                body.to_vec()
            }
        }
    }

    fn limits() -> DecompressionLimits {
        DecompressionLimits {
            max_wire_bytes: 128 * 1024,
            max_decoded_bytes: 128 * 1024,
            max_expansion_ratio: 1_000,
            max_codec_state_bytes: 1024 * 1024,
            input_chunk_bytes: 3,
            output_chunk_bytes: 5,
        }
    }

    #[test]
    fn parses_identity_and_rejects_unknown_or_stacked_codings() {
        assert_eq!(
            ContentEncoding::parse(std::iter::empty::<&str>()).expect("identity"),
            ContentEncoding::Identity
        );
        assert_eq!(
            ContentEncoding::parse_value("br").expect("brotli"),
            ContentEncoding::Brotli
        );
        assert_eq!(
            ContentEncoding::parse(["gzip", "br"]).expect("stacked"),
            ContentEncoding::Stacked(2)
        );
        assert_eq!(
            ContentEncoding::parse_value("compress")
                .expect_err("unknown")
                .code(),
            DecompressionErrorCode::UnknownEncoding
        );
        for value in ["zlib", "brotli", "raw-deflate"] {
            assert_eq!(
                ContentEncoding::parse_value(value)
                    .expect_err("nonstandard HTTP token")
                    .code(),
                DecompressionErrorCode::UnknownEncoding
            );
        }
    }

    #[tokio::test]
    async fn all_supported_codecs_stream_through_fragmented_input() {
        let body = b"bounded native response body".repeat(80);
        for encoding in [
            ContentEncoding::Gzip,
            ContentEncoding::Deflate,
            ContentEncoding::Zlib,
            ContentEncoding::RawDeflate,
            ContentEncoding::Brotli,
        ] {
            let compressed = encode(encoding, &body).await;
            let token = CancellationToken::default();
            let mut output = Vec::new();
            let stats = decode_to(
                FragmentedReader::new(compressed, 1),
                encoding,
                limits(),
                &token,
                None,
                &mut output,
            )
            .await
            .expect("decode");
            assert_eq!(output, body);
            assert!(stats.wire_bytes > 0);
            assert_eq!(stats.decoded_bytes, body.len() as u64);
        }
    }

    #[tokio::test]
    async fn malformed_and_truncated_inputs_never_commit_partial_output() {
        let body = b"partial output must be discarded".repeat(32);
        let compressed = encode(ContentEncoding::Gzip, &body).await;
        let mut truncated = compressed.clone();
        let truncated_len = truncated.len().checked_sub(2).expect("fixture trailer");
        truncated.truncate(truncated_len);
        let token = CancellationToken::default();
        let mut output = b"prefix".to_vec();
        let error = decode_to(
            FragmentedReader::new(truncated, 2),
            ContentEncoding::Gzip,
            limits(),
            &token,
            None,
            &mut output,
        )
        .await
        .expect_err("truncated");
        assert_eq!(error.code(), DecompressionErrorCode::Truncated);
        assert_eq!(output, b"prefix");

        let mut malformed = b"not-a-gzip-stream".to_vec();
        malformed.extend_from_slice(&compressed);
        output.truncate(6);
        let error = decode_to(
            FragmentedReader::new(malformed, 1),
            ContentEncoding::Gzip,
            limits(),
            &token,
            None,
            &mut output,
        )
        .await
        .expect_err("malformed");
        assert_eq!(error.code(), DecompressionErrorCode::Malformed);
        assert_eq!(output, b"prefix");
    }

    #[tokio::test]
    async fn stacked_members_and_trailing_data_fail_closed() {
        let body = b"member".repeat(16);
        let member = encode(ContentEncoding::Gzip, &body).await;
        let mut stacked = member.clone();
        stacked.extend_from_slice(&member);
        let token = CancellationToken::default();
        let mut output = Vec::new();
        let error = decode_to(
            FragmentedReader::new(stacked, 2),
            ContentEncoding::Gzip,
            limits(),
            &token,
            None,
            &mut output,
        )
        .await
        .expect_err("stacked member");
        assert_eq!(error.code(), DecompressionErrorCode::TrailingData);
        assert!(output.is_empty());

        let mut trailing = member;
        trailing.extend_from_slice(b"trailing");
        let error = decode_to(
            FragmentedReader::new(trailing, 2),
            ContentEncoding::Gzip,
            limits(),
            &token,
            None,
            &mut output,
        )
        .await
        .expect_err("trailing data");
        assert_eq!(error.code(), DecompressionErrorCode::TrailingData);
    }

    #[tokio::test]
    async fn ratio_and_wire_limits_cover_tiny_and_empty_inputs() {
        let token = CancellationToken::default();
        let mut output = Vec::new();
        let mut ratio_limits = limits();
        ratio_limits.max_expansion_ratio = 1;
        let compressed = encode(ContentEncoding::Gzip, &b"ratio bomb".repeat(64)).await;
        let error = decode_to(
            FragmentedReader::new(compressed, 1),
            ContentEncoding::Gzip,
            ratio_limits,
            &token,
            None,
            &mut output,
        )
        .await
        .expect_err("ratio");
        assert_eq!(error.code(), DecompressionErrorCode::RatioLimit);
        assert!(output.is_empty());

        let empty_limits = limits();
        let stats = decode_to(
            FragmentedReader::new(Vec::new(), 1),
            ContentEncoding::Identity,
            empty_limits,
            &token,
            None,
            &mut output,
        )
        .await
        .expect("empty identity");
        assert!(stats.is_empty());

        let mut tiny_limits = limits();
        tiny_limits.max_wire_bytes = 1;
        let error = decode_to(
            FragmentedReader::new(vec![1, 2], 1),
            ContentEncoding::Identity,
            tiny_limits,
            &token,
            None,
            &mut output,
        )
        .await
        .expect_err("wire limit");
        assert_eq!(error.code(), DecompressionErrorCode::WireLimit);
    }

    #[tokio::test]
    async fn cancellation_and_expired_deadline_are_checked_before_output() {
        let token = CancellationToken::default();
        token.cancel();
        let mut output = b"prefix".to_vec();
        let error = decode_to(
            FragmentedReader::new(b"body".to_vec(), 1),
            ContentEncoding::Identity,
            limits(),
            &token,
            None,
            &mut output,
        )
        .await
        .expect_err("cancelled");
        assert_eq!(error.code(), DecompressionErrorCode::Cancelled);
        assert_eq!(output, b"prefix");

        let deadline = Instant::now()
            .checked_sub(std::time::Duration::from_secs(1))
            .expect("past deadline");
        let token = CancellationToken::default();
        let error = decode_to(
            FragmentedReader::new(b"body".to_vec(), 1),
            ContentEncoding::Identity,
            limits(),
            &token,
            Some(deadline),
            &mut output,
        )
        .await
        .expect_err("deadline");
        assert_eq!(error.code(), DecompressionErrorCode::Deadline);
        assert_eq!(output, b"prefix");

        let future_deadline = Instant::now() + std::time::Duration::from_secs(60);
        let token = CancellationToken::default();
        let result = DecompressionReader::new(
            FragmentedReader::new(b"body".to_vec(), 1),
            ContentEncoding::Identity,
            limits(),
            DecompressionControls::new(&token).with_deadline(future_deadline),
        );
        assert!(matches!(
            result,
            Err(error) if error.code() == DecompressionErrorCode::DeadlineWakeUnavailable
        ));
    }

    #[tokio::test]
    async fn cancellation_wakes_a_pending_source() {
        let token = CancellationToken::default();
        let controls = DecompressionControls::new(&token);
        let mut decoder =
            DecompressionReader::new(PendingReader, ContentEncoding::Identity, limits(), controls)
                .expect("decoder");
        let mut output = [0_u8; 5];
        let mut read = Box::pin(decoder.read_chunk(&mut output));
        let cancellation = async {
            tokio::task::yield_now().await;
            token.cancel();
        };
        tokio::select! {
            result = &mut read => {
                assert_eq!(result.expect_err("pending source must cancel").code(), DecompressionErrorCode::Cancelled);
            }
            () = cancellation => {
                let error = read
                    .as_mut()
                    .await
                    .expect_err("cancelled pending source");
                assert_eq!(error.code(), DecompressionErrorCode::Cancelled);
            }
        }
        drop(read);
        assert_eq!(output, [0; 5]);
    }

    #[tokio::test]
    async fn future_deadline_uses_only_the_caller_owned_wake_capability() {
        let wake = std::sync::Arc::new(ReadyDeadlineWake::default());
        let token = CancellationToken::default();
        let deadline = Instant::now() + std::time::Duration::from_secs(60);
        let mut output = Vec::new();
        let stats = decode_to_with_deadline_wake(
            FragmentedReader::new(b"body".to_vec(), 1),
            ContentEncoding::Identity,
            limits(),
            &token,
            Some(deadline),
            wake.clone(),
            &mut output,
        )
        .await
        .expect("explicit deadline wake");
        assert_eq!(output, b"body");
        assert_eq!(stats.decoded_bytes, 4);
        assert!(wake.registrations.load(Ordering::Relaxed) >= 1);
    }

    #[tokio::test]
    async fn deadline_registration_error_is_typed_and_transactional() {
        let wake = std::sync::Arc::new(ErrorDeadlineWake {
            error: DeadlineWakeError::Unavailable,
        });
        let token = CancellationToken::default();
        let deadline = Instant::now() + std::time::Duration::from_secs(60);
        let mut output = b"prefix".to_vec();
        let error = decode_to_with_deadline_wake(
            FragmentedReader::new(b"body".to_vec(), 1),
            ContentEncoding::Identity,
            limits(),
            &token,
            Some(deadline),
            wake,
            &mut output,
        )
        .await
        .expect_err("registration failure");
        assert_eq!(error.code(), DecompressionErrorCode::DeadlineRegistration);
        assert_eq!(error.cleanup_code(), None);
        assert_eq!(output, b"prefix");
    }

    #[tokio::test]
    async fn deadline_retirement_error_is_typed_on_success_path() {
        let wake = std::sync::Arc::new(RetirementErrorDeadlineWake);
        let token = CancellationToken::default();
        let deadline = Instant::now() + std::time::Duration::from_secs(60);
        let mut output = b"prefix".to_vec();
        let error = decode_to_with_deadline_wake(
            FragmentedReader::new(b"body".to_vec(), 1),
            ContentEncoding::Identity,
            limits(),
            &token,
            Some(deadline),
            wake,
            &mut output,
        )
        .await
        .expect_err("retirement failure");
        assert_eq!(error.code(), DecompressionErrorCode::DeadlineRetirement);
        assert_eq!(error.cleanup_code(), None);
        assert_eq!(output, b"prefix");
    }

    #[tokio::test]
    async fn primary_codec_error_precedes_deadline_retirement_error() {
        let malformed = b"not-a-gzip-stream".to_vec();
        let wake = std::sync::Arc::new(RetirementErrorDeadlineWake);
        let token = CancellationToken::default();
        let deadline = Instant::now() + std::time::Duration::from_secs(60);
        let mut output = b"prefix".to_vec();
        let error = decode_to_with_deadline_wake(
            FragmentedReader::new(malformed, 1),
            ContentEncoding::Gzip,
            limits(),
            &token,
            Some(deadline),
            wake,
            &mut output,
        )
        .await
        .expect_err("malformed stream");
        assert_eq!(error.code(), DecompressionErrorCode::Malformed);
        assert_eq!(
            error.cleanup_code(),
            Some(DecompressionErrorCode::DeadlineRetirement)
        );
        assert_eq!(output, b"prefix");
    }

    #[test]
    fn explicit_retirement_contains_callback_panic() {
        let mut registration = DeadlineRegistration::new(|| -> Result<(), DeadlineWakeError> {
            std::panic::panic_any("deadline callback panic");
        });
        assert_eq!(
            registration.retire(),
            Err(DeadlineWakeError::ProviderInvariant)
        );
    }

    #[test]
    fn drop_contains_callback_panic_without_unwinding() {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _registration = DeadlineRegistration::new(|| -> Result<(), DeadlineWakeError> {
                std::panic::panic_any("deadline drop callback panic");
            });
        }));
        assert!(result.is_ok());
    }
}
