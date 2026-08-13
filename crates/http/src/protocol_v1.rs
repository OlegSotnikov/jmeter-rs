// SPDX-License-Identifier: Apache-2.0
//! Pure HTTP protocol-domain contracts from Decision 0006 revision 5.
//!
//! This module deliberately contains no executor, socket, DNS, filesystem, or
//! JVM integration.  It is the bounded value/state boundary used by those
//! adapters.  In particular, an adapter may implement the futures traits here
//! without this crate selecting an async runtime.

#![allow(missing_docs)]

use crate::clock::{Clock, ClockReading, Deadline};
use crate::{CancellationToken, Request, TransportError};
use core::fmt;
use core::future::Future;
use core::marker::PhantomData;
use core::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use core::pin::Pin;
use core::task::{Context, Poll};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub use crate::error::{HttpDiagnosticCode, StableHttpErrorCode};

/// The maximum duration accepted by a cross-process budget capability.
pub const MAX_BUDGET_DURATION: Duration = Duration::from_secs(24 * 60 * 60);
/// The maximum complete attempt record size.
pub const MAX_ATTEMPT_RECORD_BYTES: usize = 4 * 1024 * 1024;
/// The maximum number of ordered response/request headers.
pub const MAX_ATTEMPT_HEADERS: usize = 1_024;
/// The maximum aggregate header bytes in an attempt record.
pub const MAX_ATTEMPT_HEADER_BYTES: usize = 1024 * 1024;
/// The maximum informational responses retained in one attempt.
pub const MAX_INFORMATIONAL_RESPONSES: usize = 32;
/// The maximum trailers retained in one response.
pub const MAX_TRAILERS: usize = 256;
/// The maximum phase observations in one attempt.
pub const MAX_PHASE_OBSERVATIONS: usize = 32;
/// The maximum byte counters in one attempt.
pub const MAX_BYTE_COUNTERS: usize = 32;
/// The maximum diagnostic records in one context/attempt.
pub const MAX_DIAGNOSTICS: usize = 64;
/// The maximum bytes in one diagnostic record.
pub const MAX_DIAGNOSTIC_BYTES: usize = 4 * 1024;
/// The maximum aggregate diagnostic bytes.
pub const MAX_DIAGNOSTIC_AGGREGATE_BYTES: usize = 64 * 1024;
/// The maximum bounded scalar used by opaque protocol values.
pub const MAX_BOUNDED_BYTES: usize = MAX_ATTEMPT_RECORD_BYTES;
/// Canonical protocol schema domains required by Decision0006 revision 5.
pub const ATTEMPT_SCHEMA_ID: &str = "http.attempt";
pub const STATE_DELTA_SCHEMA_ID: &str = "http.state-delta";
pub const ERROR_CONTEXT_SCHEMA_ID: &str = "http.error-context";
pub const PARSER_LIMITS_SCHEMA_ID: &str = "http.parser-limits";
pub const BODY_STATE_SCHEMA_ID: &str = "http.body-state";
pub const BODY_REPLAY_SCHEMA_ID: &str = "http.body-replay";
pub const BUDGET_GRANT_SCHEMA_ID: &str = "http.budget-grant";

/// A typed failure in the pure HTTP protocol domain.
#[derive(Clone, Eq, PartialEq)]
pub enum ProtocolDomainError {
    InvalidInput(&'static str),
    ResourceLimit(&'static str),
    Unsupported(&'static str),
    UnsupportedCapability(UnsupportedCapabilityV1),
    ClockInvalid,
    BudgetExpired,
    Cancelled,
    Conflict,
    Overflow,
    Body(BodyStateError),
    ParserLimitsInvalid(&'static str),
    Lease(ResponseLeaseError),
    BudgetInvalid(&'static str),
    BudgetClockStalled,
    HandoffConsumed,
    HandoffIdentityMismatch,
}

impl ProtocolDomainError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidInput(_) => "http.domain.invalid",
            Self::ResourceLimit(_) => "http.resource-limit",
            Self::Unsupported(_) => "http.capability.unsupported",
            Self::UnsupportedCapability(capability) => capability.code(),
            Self::ClockInvalid => "http.budget.clock-invalid",
            Self::BudgetExpired => "http.budget.expired",
            Self::Cancelled => "http.cancelled",
            Self::Conflict => "http.state.conflict",
            Self::Overflow => "http.arithmetic.overflow",
            Self::Body(error) => error.code(),
            Self::ParserLimitsInvalid(name) => parser_limit_error_code(name),
            Self::Lease(error) => error.code(),
            Self::BudgetInvalid(_) => "http.budget-invalid",
            Self::BudgetClockStalled => "http.budget.clock-stalled",
            Self::HandoffConsumed => "http.budget.grant-consumed",
            Self::HandoffIdentityMismatch => "http.budget.grant-identity-mismatch",
        }
    }
}

fn parser_limit_error_code(name: &'static str) -> &'static str {
    match name {
        "request-target" => "http.limit.request-target",
        "authority" => "http.limit.authority",
        "status-line" => "http.limit.status-line",
        "reason" => "http.limit.reason",
        "header-count" => "http.limit.header-count",
        "header-name" => "http.limit.header-name",
        "header-value" => "http.limit.header-value",
        "header-aggregate" => "http.limit.header-aggregate",
        "informational-count" => "http.limit.informational-count",
        "informational-aggregate" => "http.limit.informational-aggregate",
        "trailer-count" => "http.limit.trailer-count",
        "trailer-name" => "http.limit.trailer-name",
        "trailer-value" => "http.limit.trailer-value",
        "trailer-aggregate" => "http.limit.trailer-aggregate",
        "chunk-line" => "http.limit.chunk-line",
        "chunk-count" => "http.limit.chunk-count",
        "chunk-extension-count" => "http.limit.chunk-extension-count",
        "chunk-extension-bytes-per-chunk" => "http.limit.chunk-extension-bytes-per-chunk",
        "chunk-extension-aggregate" => "http.limit.chunk-extension-aggregate",
        "wire-request-body" => "http.limit.wire-request-body",
        "wire-response-body" => "http.limit.wire-response-body",
        "content-length" => "http.limit.content-length",
        "compressed-input" => "http.limit.compressed-input",
        "decoded-output" => "http.limit.decoded-output",
        "expansion-ratio" => "http.limit.expansion-ratio",
        "codec-state" => "http.limit.codec-state",
        "url-field-count" => "http.limit.url-field-count",
        "url-field-bytes" => "http.limit.url-field-bytes",
        "multipart-part-count" => "http.limit.multipart-part-count",
        "multipart-boundary" => "http.limit.multipart-boundary",
        "multipart-part-headers" => "http.limit.multipart-part-headers",
        "multipart-part-body" => "http.limit.multipart-part-body",
        "redirect-count" => "http.limit.redirect-count",
        "redirect-retained" => "http.limit.redirect-retained",
        "embedded-candidate-count" => "http.limit.embedded-candidate-count",
        "embedded-depth" => "http.limit.embedded-depth",
        "embedded-concurrency" => "http.limit.embedded-concurrency",
        "embedded-retained" => "http.limit.embedded-retained",
        "trace-count" => "http.limit.trace-count",
        "trace-bytes" => "http.limit.trace-bytes",
        "diagnostic-count" => "http.limit.diagnostic-count",
        "diagnostic-text" => "http.limit.diagnostic-text",
        "diagnostic-aggregate" => "http.limit.diagnostic-aggregate",
        _ => "http.parser-limits.invalid",
    }
}

impl fmt::Debug for ProtocolDomainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple(self.code()).finish()
    }
}

impl fmt::Display for ProtocolDomainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ProtocolDomainError {}

/// Closed failures for the response/connection lease.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ResponseLeaseError {
    Invalid,
    Released,
    CloseCancelled,
    CloseDeadline,
}

impl ResponseLeaseError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Invalid => "http.response.lease-invalid",
            Self::Released => "http.response.lease-released",
            Self::CloseCancelled => "http.response.close-cancelled",
            Self::CloseDeadline => "http.response.close-deadline",
        }
    }
}

impl fmt::Display for ResponseLeaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ResponseLeaseError {}

/// Compatibility alias for callers that refer to the domain error by its
/// HTTP-specific name.
pub type HttpDomainError = ProtocolDomainError;

/// Explicitly unsupported capabilities that must fail closed at the boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum UnsupportedCapabilityV1 {
    Sockets,
    Jks,
    DigestAuthentication,
    KerberosAuthentication,
}

impl UnsupportedCapabilityV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Sockets => "http.capability.sockets-unsupported",
            Self::Jks => "http.capability.jks-unsupported",
            Self::DigestAuthentication => "http.auth.digest-unsupported",
            Self::KerberosAuthentication => "http.auth.kerberos-unsupported",
        }
    }

    #[must_use]
    pub const fn error(self) -> ProtocolDomainError {
        ProtocolDomainError::UnsupportedCapability(self)
    }
}

/// An immutable byte string with a checked maximum length.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct BoundedBytes(Vec<u8>);

impl BoundedBytes {
    pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, ProtocolDomainError> {
        Self::with_limit(value, MAX_BOUNDED_BYTES)
    }

    pub fn with_limit(
        value: impl Into<Vec<u8>>,
        limit: usize,
    ) -> Result<Self, ProtocolDomainError> {
        let value = value.into();
        if limit == 0 || value.len() > limit {
            return Err(ProtocolDomainError::ResourceLimit("bounded-bytes"));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl TryFrom<Vec<u8>> for BoundedBytes {
    type Error = ProtocolDomainError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl fmt::Debug for BoundedBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedBytes")
            .field("len", &self.len())
            .finish()
    }
}

/// A bounded ASCII identifier.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BoundedAscii(String);

impl BoundedAscii {
    pub fn new(value: impl Into<String>) -> Result<Self, ProtocolDomainError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 256
            || !value.is_ascii()
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':')
            })
        {
            return Err(ProtocolDomainError::InvalidInput("ascii-identifier"));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for BoundedAscii {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedAscii")
            .field("len", &self.0.len())
            .finish()
    }
}

/// A bounded UTF-8 identifier/value.  Its contents are redacted from Debug.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BoundedUtf8(String);

impl BoundedUtf8 {
    pub fn new(value: impl Into<String>) -> Result<Self, ProtocolDomainError> {
        let value = value.into();
        if value.is_empty() || value.len() > 256 || value.contains('\0') {
            return Err(ProtocolDomainError::InvalidInput("utf8-value"));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for BoundedUtf8 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedUtf8")
            .field("len", &self.0.len())
            .finish()
    }
}

/// UTF-8 diagnostic text with the larger per-record diagnostic bound.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct BoundedDiagnosticText(String);

impl BoundedDiagnosticText {
    pub fn new(value: impl Into<String>) -> Result<Self, ProtocolDomainError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_DIAGNOSTIC_BYTES || value.contains('\0') {
            return Err(ProtocolDomainError::InvalidInput("diagnostic-text"));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for BoundedDiagnosticText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted-diagnostic>")
    }
}

/// A field whose absence is distinct from a present empty value.
#[derive(Clone, Eq, Hash, PartialEq)]
pub enum Presence<T> {
    Absent,
    Present(T),
}

impl<T> Presence<T> {
    #[must_use]
    pub const fn is_present(&self) -> bool {
        matches!(self, Self::Present(_))
    }

    #[must_use]
    pub const fn as_ref(&self) -> Option<&T> {
        match self {
            Self::Absent => None,
            Self::Present(value) => Some(value),
        }
    }
}

impl<T> fmt::Debug for Presence<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => formatter.write_str("Absent"),
            Self::Present(_) => formatter.write_str("Present(..)"),
        }
    }
}

/// Executor-independent cancellation capability.
pub trait Cancellation: Send + Sync {
    fn is_cancelled(&self) -> bool;
}

impl Cancellation for CancellationToken {
    fn is_cancelled(&self) -> bool {
        CancellationToken::is_cancelled(self)
    }
}

impl Cancellation for AtomicBool {
    fn is_cancelled(&self) -> bool {
        self.load(Ordering::Acquire)
    }
}

/// A small request-attempt context supplied to an async adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptContext {
    pub source_context: ErrorContextV1,
    pub operation_id: [u8; 16],
    pub attempt_index: NonZeroU32,
    pub capability_identity: CapabilityIdentityV1,
    pub route_identity: RouteIdentityV1,
}

/// Response metadata separated from the response body stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseHead {
    pub status: u16,
    pub reason: Presence<BoundedBytes>,
    pub protocol: ProtocolVersion,
    pub headers: HeaderListV1,
}

impl ResponseHead {
    pub fn new(status: u16, protocol: ProtocolVersion) -> Self {
        Self {
            status,
            reason: Presence::Absent,
            protocol,
            headers: HeaderListV1::default(),
        }
    }
}

/// A bounded ordered trailer collection.
#[derive(Clone, Default, Eq, Hash, PartialEq)]
pub struct TrailerCollection {
    fields: Vec<HeaderFieldV1>,
}

impl fmt::Debug for TrailerCollection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrailerCollection")
            .field("count", &self.fields.len())
            .finish()
    }
}

impl TrailerCollection {
    pub fn push(&mut self, field: HeaderFieldV1) -> Result<(), ProtocolDomainError> {
        if self.fields.len() >= MAX_TRAILERS {
            return Err(ProtocolDomainError::ResourceLimit("trailers.count"));
        }
        let current = self.aggregate_bytes();
        let next = current
            .checked_add(field.encoded_len())
            .ok_or(ProtocolDomainError::Overflow)?;
        if next > 256 * 1024 {
            return Err(ProtocolDomainError::ResourceLimit("trailers.bytes"));
        }
        let mut field = field;
        let ordinal =
            u32::try_from(self.fields.len() + 1).map_err(|_| ProtocolDomainError::Overflow)?;
        field.ordinal = NonZeroU32::new(ordinal).ok_or(ProtocolDomainError::Overflow)?;
        self.fields.push(field);
        Ok(())
    }

    #[must_use]
    pub fn fields(&self) -> &[HeaderFieldV1] {
        &self.fields
    }

    #[must_use]
    pub fn aggregate_bytes(&self) -> usize {
        self.fields.iter().fold(0usize, |total, field| {
            total.saturating_add(field.encoded_len())
        })
    }

    pub fn validate(&self) -> Result<(), ProtocolDomainError> {
        if self.fields.len() > MAX_TRAILERS || self.aggregate_bytes() > 256 * 1024 {
            return Err(ProtocolDomainError::ResourceLimit("trailers"));
        }
        for (index, field) in self.fields.iter().enumerate() {
            let expected = u32::try_from(index + 1).map_err(|_| ProtocolDomainError::Overflow)?;
            if field.ordinal.get() != expected {
                return Err(ProtocolDomainError::InvalidInput("headers.ordinal"));
            }
            if field.name.length() > 8 * 1024 || field.value.length() > 64 * 1024 {
                return Err(ProtocolDomainError::ResourceLimit("headers.field"));
            }
            field.name.validate()?;
            field.value.validate()?;
        }
        Ok(())
    }
}

/// The result of one exclusive body read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadChunk {
    Data {
        written: NonZeroUsize,
    },
    End {
        trailers: Presence<TrailerCollection>,
    },
}

/// Stable body state-machine failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyStateError {
    EmptyBuffer,
    ConcurrentRead,
    AfterEnd,
    Aborted,
    InvalidWrite,
    Failed,
}

impl BodyStateError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::EmptyBuffer => "http.body.empty-buffer",
            Self::ConcurrentRead => "http.body.concurrent-read",
            Self::AfterEnd => "http.body.after-end",
            Self::Aborted => "http.body.aborted",
            Self::InvalidWrite => "http.body.invalid-write",
            Self::Failed => "http.body.failed",
        }
    }
}

impl fmt::Display for BodyStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for BodyStateError {}

/// Closed response-body lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyLeaseState {
    Fresh,
    Reading,
    Ended,
    Failed,
    Cancelled,
}

/// A deterministic pure body-state reducer used by stream adapters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseBodyState {
    state: BodyLeaseState,
    read_capacity: usize,
}

impl Default for ResponseBodyState {
    fn default() -> Self {
        Self {
            state: BodyLeaseState::Fresh,
            read_capacity: 0,
        }
    }
}

impl ResponseBodyState {
    pub fn schema_identity() -> Result<CapabilityIdentityV1, ProtocolDomainError> {
        CapabilityIdentityV1::new(
            BODY_STATE_SCHEMA_ID,
            NonZeroU32::MIN,
            sha256(b"http.body-state/1\0"),
        )
    }

    #[must_use]
    pub const fn state(&self) -> BodyLeaseState {
        self.state
    }

    pub fn begin_read(&mut self, destination_len: usize) -> Result<(), BodyStateError> {
        if destination_len == 0 {
            return Err(BodyStateError::EmptyBuffer);
        }
        match self.state {
            BodyLeaseState::Fresh => {
                self.state = BodyLeaseState::Reading;
                self.read_capacity = destination_len;
                Ok(())
            }
            BodyLeaseState::Reading => Err(BodyStateError::ConcurrentRead),
            BodyLeaseState::Ended => Err(BodyStateError::AfterEnd),
            BodyLeaseState::Failed | BodyLeaseState::Cancelled => Err(BodyStateError::Aborted),
        }
    }

    pub fn begin_read_guard(
        &mut self,
        destination_len: usize,
    ) -> Result<BodyReadOperation<'_>, BodyStateError> {
        self.begin_read(destination_len)?;
        Ok(BodyReadOperation {
            state: self,
            completed: false,
        })
    }

    pub fn finish_data(&mut self, written: usize) -> Result<ReadChunk, BodyStateError> {
        if self.state != BodyLeaseState::Reading {
            return match self.state {
                BodyLeaseState::Fresh => Err(BodyStateError::ConcurrentRead),
                BodyLeaseState::Ended => Err(BodyStateError::AfterEnd),
                BodyLeaseState::Failed | BodyLeaseState::Cancelled => Err(BodyStateError::Aborted),
                BodyLeaseState::Reading => unreachable!(),
            };
        }
        let Some(written) = NonZeroUsize::new(written) else {
            return Err(BodyStateError::InvalidWrite);
        };
        if written.get() > self.read_capacity {
            return Err(BodyStateError::InvalidWrite);
        }
        self.state = BodyLeaseState::Fresh;
        self.read_capacity = 0;
        Ok(ReadChunk::Data { written })
    }

    pub fn finish_end(
        &mut self,
        trailers: Presence<TrailerCollection>,
    ) -> Result<ReadChunk, BodyStateError> {
        if self.state != BodyLeaseState::Reading {
            return match self.state {
                BodyLeaseState::Fresh => Err(BodyStateError::ConcurrentRead),
                BodyLeaseState::Ended => Err(BodyStateError::AfterEnd),
                BodyLeaseState::Failed | BodyLeaseState::Cancelled => Err(BodyStateError::Aborted),
                BodyLeaseState::Reading => unreachable!(),
            };
        }
        self.state = BodyLeaseState::Ended;
        self.read_capacity = 0;
        Ok(ReadChunk::End { trailers })
    }

    pub fn fail(&mut self) {
        self.state = BodyLeaseState::Failed;
        self.read_capacity = 0;
    }

    pub fn abort(&mut self) {
        self.state = BodyLeaseState::Cancelled;
        self.read_capacity = 0;
    }
}

/// An exclusive pending read.  Dropping it aborts the body.
pub struct BodyReadOperation<'a> {
    state: &'a mut ResponseBodyState,
    completed: bool,
}

impl<'a> BodyReadOperation<'a> {
    pub fn data(mut self, written: usize) -> Result<ReadChunk, BodyStateError> {
        let result = self.state.finish_data(written);
        self.completed = result.is_ok();
        result
    }

    pub fn end(
        mut self,
        trailers: Presence<TrailerCollection>,
    ) -> Result<ReadChunk, BodyStateError> {
        let result = self.state.finish_end(trailers);
        self.completed = result.is_ok();
        result
    }

    pub fn cancel(mut self) {
        self.state.abort();
        self.completed = true;
    }
}

impl Drop for BodyReadOperation<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.state.abort();
        }
    }
}

/// A bounded response-connection lease.
pub struct ResponseLease<'a> {
    state: AtomicU8,
    releases: AtomicU8,
    marker: PhantomData<&'a mut ()>,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LeaseState {
    Held = 0,
    Released = 1,
    Aborted = 2,
}

impl<'a> ResponseLease<'a> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: AtomicU8::new(LeaseState::Held as u8),
            releases: AtomicU8::new(0),
            marker: PhantomData,
        }
    }

    pub fn release(&mut self) {
        let _ = self.try_release();
    }

    pub fn abort(&mut self) {
        let _ = self.try_abort();
    }

    /// Releases the lease exactly once after a complete framing boundary.
    pub fn try_release(&self) -> Result<(), ProtocolDomainError> {
        match self.state.compare_exchange(
            LeaseState::Held as u8,
            LeaseState::Released as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                self.releases.store(1, Ordering::Release);
                Ok(())
            }
            Err(value) if value == LeaseState::Released as u8 => {
                Err(ProtocolDomainError::Lease(ResponseLeaseError::Released))
            }
            Err(_) => Err(ProtocolDomainError::Lease(ResponseLeaseError::Invalid)),
        }
    }

    /// Marks an unread/failed/cancelled lease non-reusable exactly once.
    pub fn try_abort(&self) -> Result<(), ProtocolDomainError> {
        match self.state.compare_exchange(
            LeaseState::Held as u8,
            LeaseState::Aborted as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                self.releases.store(1, Ordering::Release);
                Ok(())
            }
            Err(value) if value == LeaseState::Released as u8 => {
                Err(ProtocolDomainError::Lease(ResponseLeaseError::Released))
            }
            Err(_) => Err(ProtocolDomainError::Lease(ResponseLeaseError::Invalid)),
        }
    }

    /// Explicitly closes an unread response using the caller's existing
    /// cancellation/budget capability.  Concrete adapters override body
    /// draining in [`AsyncResponseBody::close`]; this method only owns the
    /// linear lease transition.
    pub fn close(
        &self,
        budget: &OperationBudget,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ProtocolDomainError> {
        if cancellation.is_cancelled() || budget.is_cancelled() {
            let _ = self.try_abort();
            return Err(ProtocolDomainError::Lease(
                ResponseLeaseError::CloseCancelled,
            ));
        }
        self.try_release()
    }

    /// Deadline-aware close used by adapters that have an injected clock
    /// sample available at the framing boundary.
    pub fn close_at(
        &self,
        budget: &OperationBudget,
        now: ClockReading,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ProtocolDomainError> {
        if cancellation.is_cancelled() || budget.is_cancelled() {
            let _ = self.try_abort();
            return Err(ProtocolDomainError::Lease(
                ResponseLeaseError::CloseCancelled,
            ));
        }
        match budget.remaining(now) {
            Ok(remaining) if remaining.is_zero() => {
                let _ = self.try_abort();
                Err(ProtocolDomainError::Lease(
                    ResponseLeaseError::CloseDeadline,
                ))
            }
            Ok(_) => self.try_release(),
            Err(ProtocolDomainError::ClockInvalid) => {
                let _ = self.try_abort();
                Err(ProtocolDomainError::Lease(
                    ResponseLeaseError::CloseDeadline,
                ))
            }
            Err(error) => Err(error),
        }
    }

    #[must_use]
    pub fn is_released(&self) -> bool {
        self.state.load(Ordering::Acquire) != LeaseState::Held as u8
    }

    #[must_use]
    pub fn release_count(&self) -> u8 {
        self.releases.load(Ordering::Acquire)
    }
}

impl Default for ResponseLease<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ResponseLease<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResponseLease")
            .field("released", &self.is_released())
            .field("release_count", &self.release_count())
            .finish()
    }
}

impl Drop for ResponseLease<'_> {
    fn drop(&mut self) {
        // Drop is constant-time and nonblocking.  An unread body is never
        // returned to a pool by this path; it is marked aborted instead.
        let _ = self.try_abort();
    }
}

/// An opaque body-plus-lease owner.  The lease cannot be moved independently
/// of the response body, and dropping it always takes the non-reusable path.
pub struct ResponseLeaseBody<'a> {
    body: Box<dyn AsyncResponseBody + Send + 'a>,
    lease: ResponseLease<'a>,
    body_state: ResponseBodyState,
}

/// The adapter read future owns the cancellation transition for a pending
/// body operation.  Its inner future is pinned in a box, so moving this small
/// wrapper never moves adapter state; the wrapper itself can therefore be
/// safely `Unpin` and perform the state transition from `Drop`.
struct ResponseBodyReadFuture<'a, 'lease> {
    inner: Pin<Box<dyn Future<Output = Result<ReadChunk, TransportError>> + Send + 'a>>,
    body_state: &'a mut ResponseBodyState,
    lease: &'a ResponseLease<'lease>,
    destination_len: usize,
    budget: &'a OperationBudget,
    cancellation: &'a dyn Cancellation,
    completed: bool,
}

impl Unpin for ResponseBodyReadFuture<'_, '_> {}

impl Future for ResponseBodyReadFuture<'_, '_> {
    type Output = Result<ReadChunk, TransportError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.cancellation.is_cancelled() || this.budget.is_cancelled() {
            this.completed = true;
            this.body_state.abort();
            let _ = this.lease.try_abort();
            return Poll::Ready(Err(TransportError::Cancelled));
        }
        let result = match this.inner.as_mut().poll(context) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result,
        };
        this.completed = true;
        if this.cancellation.is_cancelled() || this.budget.is_cancelled() {
            this.body_state.abort();
            let _ = this.lease.try_abort();
            return Poll::Ready(Err(TransportError::Cancelled));
        }
        let result = match result {
            Ok(ReadChunk::Data { written }) if written.get() > this.destination_len => {
                this.body_state.abort();
                let _ = this.lease.try_abort();
                Err(TransportError::adapter(
                    "http.body.invalid-write",
                    "adapter wrote beyond the destination prefix",
                ))
            }
            Ok(ReadChunk::Data { written }) => match this.body_state.finish_data(written.get()) {
                Ok(chunk) => Ok(chunk),
                Err(error) => {
                    this.body_state.abort();
                    let _ = this.lease.try_abort();
                    Err(TransportError::adapter(
                        error.code(),
                        "invalid response read",
                    ))
                }
            },
            Ok(ReadChunk::End { trailers }) => {
                if let Presence::Present(value) = &trailers
                    && let Err(error) = value.validate()
                {
                    this.body_state.abort();
                    let _ = this.lease.try_abort();
                    return Poll::Ready(Err(TransportError::adapter(
                        error.code(),
                        "response trailers exceeded protocol bounds",
                    )));
                }
                let trailers_for_state = trailers.clone();
                if let Err(error) = this.body_state.finish_end(trailers_for_state) {
                    this.body_state.abort();
                    let _ = this.lease.try_abort();
                    Err(TransportError::adapter(
                        error.code(),
                        "invalid response end",
                    ))
                } else {
                    this.lease.try_release().map_or_else(
                        |error| {
                            Err(TransportError::adapter(
                                error.code(),
                                "response lease release failed",
                            ))
                        },
                        |_| Ok(ReadChunk::End { trailers }),
                    )
                }
            }
            Err(error) => {
                this.body_state.abort();
                let _ = this.lease.try_abort();
                Err(error)
            }
        };
        Poll::Ready(result)
    }
}

impl Drop for ResponseBodyReadFuture<'_, '_> {
    fn drop(&mut self) {
        if !self.completed {
            self.body_state.abort();
            let _ = self.lease.try_abort();
        }
    }
}

impl fmt::Debug for ResponseLeaseBody<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResponseLeaseBody")
            .field("lease", &self.lease)
            .finish()
    }
}

impl<'a> ResponseLeaseBody<'a> {
    pub fn new(body: Box<dyn AsyncResponseBody + Send + 'a>, lease: ResponseLease<'a>) -> Self {
        Self {
            body,
            lease,
            body_state: ResponseBodyState::default(),
        }
    }

    pub fn read_chunk<'b>(
        &'b mut self,
        destination: &'b mut [u8],
        budget: &'b OperationBudget,
        cancellation: &'b dyn Cancellation,
    ) -> Pin<Box<dyn Future<Output = Result<ReadChunk, TransportError>> + Send + 'b>> {
        if destination.is_empty() {
            return Box::pin(async {
                Err(TransportError::adapter(
                    "http.body.empty-buffer",
                    "response read destination is empty",
                ))
            });
        }
        if let Err(error) = self.body_state.begin_read(destination.len()) {
            let code = error.code();
            return Box::pin(async move {
                Err(TransportError::adapter(
                    code,
                    "response body state rejected read",
                ))
            });
        }
        if self.lease.is_released() {
            self.body_state.abort();
            return Box::pin(async {
                Err(TransportError::adapter(
                    "http.response.lease-released",
                    "response lease was already released",
                ))
            });
        }
        if cancellation.is_cancelled() || budget.is_cancelled() {
            self.body_state.abort();
            let _ = self.lease.try_abort();
            return Box::pin(async { Err(TransportError::Cancelled) });
        }
        let destination_len = destination.len();
        let inner = self.body.read_chunk(destination, budget, cancellation);
        Box::pin(ResponseBodyReadFuture {
            inner,
            body_state: &mut self.body_state,
            lease: &self.lease,
            destination_len,
            budget,
            cancellation,
            completed: false,
        })
    }

    pub fn close(
        self,
        budget: &'a OperationBudget,
        cancellation: &'a dyn Cancellation,
    ) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + 'a>> {
        let Self {
            mut body,
            lease,
            body_state: _,
        } = self;
        Box::pin(async move {
            if cancellation.is_cancelled() || budget.is_cancelled() {
                drop(lease);
                return Err(TransportError::Cancelled);
            }
            let body_result = body.close(budget, cancellation).await;
            if let Err(error) = body_result {
                drop(lease);
                return Err(error);
            }
            lease.close(budget, cancellation).map_err(|error| {
                TransportError::adapter(error.code(), "response lease close failed")
            })
        })
    }
}

/// A response whose body and lease are owned by one adapter attempt.
pub struct AsyncResponse<'a> {
    head: ResponseHead,
    body_and_lease: ResponseLeaseBody<'a>,
}

impl<'a> AsyncResponse<'a> {
    pub fn new(
        head: ResponseHead,
        body: Box<dyn AsyncResponseBody + Send + 'a>,
        lease: ResponseLease<'a>,
    ) -> Self {
        Self {
            head,
            body_and_lease: ResponseLeaseBody::new(body, lease),
        }
    }

    #[must_use]
    pub const fn head(&self) -> &ResponseHead {
        &self.head
    }

    pub fn head_mut(&mut self) -> &mut ResponseHead {
        &mut self.head
    }

    pub fn body_mut(&mut self) -> &mut ResponseLeaseBody<'a> {
        &mut self.body_and_lease
    }

    pub fn close(
        self,
        budget: &'a OperationBudget,
        cancellation: &'a dyn Cancellation,
    ) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + 'a>> {
        let Self {
            head: _,
            body_and_lease,
        } = self;
        body_and_lease.close(budget, cancellation)
    }
}

impl fmt::Debug for AsyncResponse<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AsyncResponse")
            .field("head", &self.head)
            .field("body_and_lease", &self.body_and_lease)
            .finish()
    }
}

/// Executor-neutral async response-body capability.
pub trait AsyncResponseBody: Send {
    fn read_chunk<'a>(
        &'a mut self,
        destination: &'a mut [u8],
        budget: &'a OperationBudget,
        cancellation: &'a dyn Cancellation,
    ) -> Pin<Box<dyn Future<Output = Result<ReadChunk, TransportError>> + Send + 'a>>;

    /// Drains or otherwise invalidates the underlying response framing.  The
    /// default is a no-op for deterministic fake bodies; concrete adapters
    /// must override it when unread bytes make a connection reusable.
    fn close<'a>(
        &'a mut self,
        budget: &'a OperationBudget,
        cancellation: &'a dyn Cancellation,
    ) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + 'a>> {
        Box::pin(async move {
            if cancellation.is_cancelled() || budget.is_cancelled() {
                return Err(TransportError::Cancelled);
            }
            Ok(())
        })
    }
}

/// Executor-neutral one-attempt HTTP capability.
pub trait AsyncTransport: Send {
    fn send<'a>(
        &'a mut self,
        request: &'a Request,
        context: &'a AttemptContext,
        budget: &'a OperationBudget,
        cancellation: &'a dyn Cancellation,
    ) -> Pin<Box<dyn Future<Output = Result<AsyncResponse<'a>, TransportError>> + Send + 'a>>;
}

/// Replayability of an outbound body source.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Replayability {
    Replayable,
    OneShot,
}

/// A pure capability describing an already-authorized file-like body.
#[derive(Clone, Eq, PartialEq)]
pub struct FileCapability {
    pub handle_id: [u8; 16],
    pub byte_limit: u64,
    pub digest: Presence<[u8; 32]>,
    pub replayability: Replayability,
}

impl fmt::Debug for FileCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileCapability")
            .field("handle_id", &"<opaque>")
            .field("byte_limit", &self.byte_limit)
            .field("digest", &self.digest)
            .field("replayability", &self.replayability)
            .finish()
    }
}

impl FileCapability {
    pub fn new(
        handle_id: [u8; 16],
        byte_limit: u64,
        digest: Presence<[u8; 32]>,
        replayability: Replayability,
    ) -> Result<Self, ProtocolDomainError> {
        Ok(Self {
            handle_id,
            byte_limit,
            digest,
            replayability,
        })
    }
}

/// A one-shot bounded body reader supplied by an application adapter.
pub trait BoundedBodyReader: Send {
    fn read(&mut self, destination: &mut [u8]) -> Result<usize, ProtocolDomainError>;
    fn is_consumed(&self) -> bool;
}

/// An explicit request-body source.  `Empty` is not a present empty entity.
pub enum BodySource {
    Empty,
    Bytes(BoundedBytes),
    File(FileCapability),
    OneShot(Box<dyn BoundedBodyReader>),
}

impl fmt::Debug for BodySource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("Empty"),
            Self::Bytes(value) => formatter
                .debug_struct("Bytes")
                .field("len", &value.len())
                .finish(),
            Self::File(value) => value.fmt(formatter),
            Self::OneShot(_) => formatter.write_str("OneShot(<reader>)"),
        }
    }
}

impl BodySource {
    pub fn replay_schema_identity() -> Result<CapabilityIdentityV1, ProtocolDomainError> {
        CapabilityIdentityV1::new(
            BODY_REPLAY_SCHEMA_ID,
            NonZeroU32::MIN,
            sha256(b"http.body-replay/1\0"),
        )
    }

    #[must_use]
    pub const fn replayability(&self) -> Replayability {
        match self {
            Self::Empty
            | Self::Bytes(_)
            | Self::File(FileCapability {
                replayability: Replayability::Replayable,
                ..
            }) => Replayability::Replayable,
            Self::File(FileCapability {
                replayability: Replayability::OneShot,
                ..
            })
            | Self::OneShot(_) => Replayability::OneShot,
        }
    }

    #[must_use]
    pub const fn is_present(&self) -> bool {
        !matches!(self, Self::Empty)
    }
}

/// A single finite local monotonic deadline.
pub struct OperationBudget {
    deadline: Duration,
    last_observed: Mutex<Duration>,
    cancelled: Arc<AtomicBool>,
    budget_id: [u8; 16],
    handoffs: Mutex<HandoffLedger>,
}

#[derive(Default)]
struct HandoffLedger {
    next_ordinal: u64,
    reserved_ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetCancellationState {
    Active,
    Cancelled,
}

/// An optional per-phase cap. `Absent` is the only spelling for no extra cap;
/// zero is never interpreted as unlimited.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhaseCap {
    Absent,
    Limited(NonZeroU64),
}

impl PhaseCap {
    pub fn from_duration(value: Option<Duration>) -> Result<Self, ProtocolDomainError> {
        let Some(value) = value else {
            return Ok(Self::Absent);
        };
        let nanos = duration_to_ns_floor(value)?;
        let nanos =
            NonZeroU64::new(nanos).ok_or(ProtocolDomainError::BudgetInvalid("phase-cap"))?;
        Ok(Self::Limited(nanos))
    }
}

impl fmt::Debug for OperationBudget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperationBudget")
            .field("deadline", &self.deadline)
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

impl OperationBudget {
    pub fn new(now: ClockReading, timeout: Duration) -> Result<Self, ProtocolDomainError> {
        if timeout.is_zero() {
            return Err(ProtocolDomainError::InvalidInput("budget-duration"));
        }
        let deadline = now
            .monotonic
            .checked_add(timeout)
            .ok_or(ProtocolDomainError::ClockInvalid)?;
        Ok(Self {
            deadline,
            last_observed: Mutex::new(now.monotonic),
            cancelled: Arc::new(AtomicBool::new(false)),
            budget_id: budget_identity(now.monotonic, timeout),
            handoffs: Mutex::new(HandoffLedger::default()),
        })
    }

    pub fn from_clock(clock: &dyn Clock, timeout: Duration) -> Result<Self, ProtocolDomainError> {
        if !clock.can_progress() {
            return Err(ProtocolDomainError::BudgetClockStalled);
        }
        Self::new(clock.now(), timeout)
    }

    pub fn from_deadline(
        now: ClockReading,
        timeout: Duration,
    ) -> Result<Self, ProtocolDomainError> {
        Self::new(now, timeout)
    }

    pub fn from_handoff(
        receiver_now: ClockReading,
        handoff: HandoffGrantV1,
    ) -> Result<Self, ProtocolDomainError> {
        handoff.validate()?;
        let grant = handoff.grant_duration()?;
        let cap = handoff.receiver_cap_duration()?;
        let timeout = grant.min(cap);
        if timeout.is_zero() {
            return Err(ProtocolDomainError::BudgetExpired);
        }
        let mut budget = Self::new(receiver_now, timeout)?;
        budget.budget_id = handoff.budget_id;
        Ok(budget)
    }

    #[must_use]
    pub const fn deadline(&self) -> Deadline {
        Deadline { at: self.deadline }
    }

    pub fn remaining(&self, now: ClockReading) -> Result<Duration, ProtocolDomainError> {
        let mut last = self
            .last_observed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if now.monotonic < *last {
            return Err(ProtocolDomainError::ClockInvalid);
        }
        *last = now.monotonic;
        Ok(self.deadline.saturating_sub(now.monotonic))
    }

    /// Validates an injected clock sample against an earlier sample.  A
    /// runnable operation must not accept a clock that has stopped; callers
    /// that intentionally use a fixed fixture can pass `runnable = false`.
    pub fn validate_clock_progress(
        previous: ClockReading,
        current: ClockReading,
        runnable: bool,
    ) -> Result<(), ProtocolDomainError> {
        if current.monotonic < previous.monotonic {
            return Err(ProtocolDomainError::ClockInvalid);
        }
        if runnable && current.monotonic == previous.monotonic {
            return Err(ProtocolDomainError::BudgetClockStalled);
        }
        Ok(())
    }

    /// Samples and validates an injected clock without serializing a local
    /// instant.  The caller supplies the prior sample from its phase loop.
    pub fn observe_clock(
        &self,
        clock: &dyn Clock,
        previous: ClockReading,
        runnable: bool,
    ) -> Result<ClockReading, ProtocolDomainError> {
        if !clock.can_progress() && runnable {
            return Err(ProtocolDomainError::BudgetClockStalled);
        }
        let current = clock.now();
        Self::validate_clock_progress(previous, current, runnable)?;
        let _ = self.remaining(current)?;
        Ok(current)
    }

    pub fn phase_deadline(
        &self,
        now: ClockReading,
        phase_cap: Duration,
    ) -> Result<Deadline, ProtocolDomainError> {
        if phase_cap.is_zero() {
            return Err(ProtocolDomainError::BudgetInvalid("phase-cap"));
        }
        let remaining = self.remaining(now)?;
        if remaining.is_zero() {
            return Err(ProtocolDomainError::BudgetExpired);
        }
        let phase_deadline = now
            .monotonic
            .checked_add(remaining.min(phase_cap))
            .ok_or(ProtocolDomainError::ClockInvalid)?;
        Ok(Deadline { at: phase_deadline })
    }

    pub fn phase_deadline_with_cap(
        &self,
        now: ClockReading,
        phase_cap: PhaseCap,
    ) -> Result<Deadline, ProtocolDomainError> {
        let remaining = self.remaining(now)?;
        if remaining.is_zero() {
            return Err(ProtocolDomainError::BudgetExpired);
        }
        let cap = match phase_cap {
            PhaseCap::Absent => remaining,
            PhaseCap::Limited(cap) => remaining.min(ns_to_duration(cap.get())?),
        };
        let at = now
            .monotonic
            .checked_add(cap)
            .ok_or(ProtocolDomainError::ClockInvalid)?;
        Ok(Deadline { at })
    }

    pub fn remaining_ns(&self, now: ClockReading) -> Result<u64, ProtocolDomainError> {
        duration_to_ns_floor(self.remaining(now)?)
    }

    pub fn phase_deadline_ns(
        &self,
        now: ClockReading,
        phase_cap_ns: u64,
    ) -> Result<u64, ProtocolDomainError> {
        let deadline = self.phase_deadline(now, ns_to_duration(phase_cap_ns)?)?;
        duration_to_ns_floor(deadline.at)
    }

    pub fn handoff(
        &self,
        now: ClockReading,
        reservation: Duration,
        receiver_cap: Duration,
    ) -> Result<HandoffGrantV1, ProtocolDomainError> {
        self.allocate_handoff(now, reservation, receiver_cap)
    }

    /// Allocates one linear grant and advances the parent reservation ledger
    /// before the token can be handed to an adapter frame.
    pub fn reserve_handoff(
        &mut self,
        now: ClockReading,
        reservation: Duration,
        receiver_cap: Duration,
    ) -> Result<HandoffGrantV1, ProtocolDomainError> {
        self.allocate_handoff(now, reservation, receiver_cap)
    }

    fn allocate_handoff(
        &self,
        now: ClockReading,
        reservation: Duration,
        receiver_cap: Duration,
    ) -> Result<HandoffGrantV1, ProtocolDomainError> {
        if receiver_cap.is_zero() || receiver_cap > MAX_BUDGET_DURATION {
            return Err(ProtocolDomainError::InvalidInput("receiver-cap"));
        }
        let remaining_ns = duration_to_ns_floor(self.remaining(now)?)?;
        let reservation_ns = duration_to_ns_ceil(reservation)?;
        let receiver_cap_ns = duration_to_ns_floor(receiver_cap)?;
        if receiver_cap_ns == 0 {
            return Err(ProtocolDomainError::InvalidInput("receiver-cap"));
        }
        let mut ledger = self
            .handoffs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let available_ns = remaining_ns
            .checked_sub(ledger.reserved_ns)
            .ok_or(ProtocolDomainError::BudgetExpired)?;
        let grant_ns = available_ns
            .checked_sub(reservation_ns)
            .ok_or(ProtocolDomainError::BudgetExpired)?;
        if grant_ns == 0 {
            return Err(ProtocolDomainError::BudgetExpired);
        }
        let ordinal = ledger
            .next_ordinal
            .checked_add(1)
            .ok_or(ProtocolDomainError::Overflow)?;
        let ordinal = NonZeroU64::new(ordinal).ok_or(ProtocolDomainError::Overflow)?;
        let reserved = grant_ns
            .checked_add(reservation_ns)
            .ok_or(ProtocolDomainError::Overflow)?;
        ledger.reserved_ns = ledger
            .reserved_ns
            .checked_add(reserved)
            .ok_or(ProtocolDomainError::Overflow)?;
        ledger.next_ordinal = ordinal.get();
        HandoffGrantV1::with_identity(
            self.budget_id,
            ordinal,
            grant_ns,
            reservation_ns,
            receiver_cap_ns,
        )
    }

    pub fn handoff_ns(
        &self,
        now: ClockReading,
        reservation_ns: u64,
        receiver_cap_ns: u64,
    ) -> Result<HandoffGrantV1, ProtocolDomainError> {
        self.handoff(
            now,
            ns_to_duration(reservation_ns)?,
            ns_to_duration(receiver_cap_ns)?,
        )
    }

    /// Nanosecond spelling of [`Self::reserve_handoff`].
    pub fn reserve_handoff_ns(
        &mut self,
        now: ClockReading,
        reservation_ns: u64,
        receiver_cap_ns: u64,
    ) -> Result<HandoffGrantV1, ProtocolDomainError> {
        self.reserve_handoff(
            now,
            ns_to_duration(reservation_ns)?,
            ns_to_duration(receiver_cap_ns)?,
        )
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn cancellation_state(&self) -> BudgetCancellationState {
        if self.is_cancelled() {
            BudgetCancellationState::Cancelled
        } else {
            BudgetCancellationState::Active
        }
    }

    pub fn check(&self, now: ClockReading) -> Result<(), ProtocolDomainError> {
        if self.is_cancelled() {
            return Err(ProtocolDomainError::Cancelled);
        }
        if self.remaining(now)?.is_zero() {
            return Err(ProtocolDomainError::BudgetExpired);
        }
        Ok(())
    }
}

fn duration_to_ns_floor(value: Duration) -> Result<u64, ProtocolDomainError> {
    u64::try_from(value.as_nanos()).map_err(|_| ProtocolDomainError::Overflow)
}

fn duration_to_ns_ceil(value: Duration) -> Result<u64, ProtocolDomainError> {
    let nanos = value.as_nanos();
    let rounded = nanos.checked_add(0).ok_or(ProtocolDomainError::Overflow)?;
    u64::try_from(rounded).map_err(|_| ProtocolDomainError::Overflow)
}

fn ns_to_duration(value: u64) -> Result<Duration, ProtocolDomainError> {
    Ok(Duration::from_nanos(value))
}

fn budget_identity(start: Duration, timeout: Duration) -> [u8; 16] {
    let mut encoded = Vec::with_capacity(32);
    encoded.extend_from_slice(b"http.budget/1\0");
    append_u64(&mut encoded, start.as_secs());
    append_u64(&mut encoded, u64::from(start.subsec_nanos()));
    append_u64(&mut encoded, timeout.as_secs());
    append_u64(&mut encoded, u64::from(timeout.subsec_nanos()));
    let digest = sha256(&encoded);
    let mut identity = [0_u8; 16];
    identity.copy_from_slice(&digest[..16]);
    identity
}

fn handoff_identity_digest(
    budget_id: [u8; 16],
    ordinal: NonZeroU64,
    grant_ns: u64,
    reservation_ns: u64,
    receiver_cap_ns: u64,
) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(64);
    encoded.extend_from_slice(b"http.budget-grant/1\0");
    encoded.extend_from_slice(&budget_id);
    append_u64(&mut encoded, ordinal.get());
    append_u64(&mut encoded, grant_ns);
    append_u64(&mut encoded, reservation_ns);
    append_u64(&mut encoded, receiver_cap_ns);
    sha256(&encoded)
}

/// A cross-process budget reservation/grant, expressed only in unsigned ns.
#[derive(Debug, Eq, PartialEq)]
pub struct HandoffGrantV1 {
    pub budget_id: [u8; 16],
    pub grant_ordinal: NonZeroU64,
    pub grant_ns: NonZeroU64,
    pub reservation_ns: u64,
    pub receiver_cap_ns: NonZeroU64,
    pub identity_digest: [u8; 32],
}

impl HandoffGrantV1 {
    pub fn schema_identity() -> Result<CapabilityIdentityV1, ProtocolDomainError> {
        CapabilityIdentityV1::new(
            BUDGET_GRANT_SCHEMA_ID,
            NonZeroU32::MIN,
            sha256(b"http.budget-grant/1\0"),
        )
    }

    pub fn new(
        grant_ns: u64,
        reservation_ns: u64,
        receiver_cap_ns: u64,
    ) -> Result<Self, ProtocolDomainError> {
        Self::with_identity(
            [0; 16],
            NonZeroU64::MIN,
            grant_ns,
            reservation_ns,
            receiver_cap_ns,
        )
    }

    fn with_identity(
        budget_id: [u8; 16],
        grant_ordinal: NonZeroU64,
        grant_ns: u64,
        reservation_ns: u64,
        receiver_cap_ns: u64,
    ) -> Result<Self, ProtocolDomainError> {
        let grant_ns =
            NonZeroU64::new(grant_ns).ok_or(ProtocolDomainError::InvalidInput("handoff-zero"))?;
        let receiver_cap_ns = NonZeroU64::new(receiver_cap_ns)
            .ok_or(ProtocolDomainError::InvalidInput("handoff-zero"))?;
        let cap = ns_to_duration(receiver_cap_ns.get())?;
        if cap > MAX_BUDGET_DURATION {
            return Err(ProtocolDomainError::InvalidInput("handoff-cap"));
        }
        let identity_digest = handoff_identity_digest(
            budget_id,
            grant_ordinal,
            grant_ns.get(),
            reservation_ns,
            receiver_cap_ns.get(),
        );
        Ok(Self {
            budget_id,
            grant_ordinal,
            grant_ns,
            reservation_ns,
            receiver_cap_ns,
            identity_digest,
        })
    }

    pub fn validate(&self) -> Result<(), ProtocolDomainError> {
        if self.identity_digest
            != handoff_identity_digest(
                self.budget_id,
                self.grant_ordinal,
                self.grant_ns.get(),
                self.reservation_ns,
                self.receiver_cap_ns.get(),
            )
        {
            return Err(ProtocolDomainError::HandoffIdentityMismatch);
        }
        let cap = ns_to_duration(self.receiver_cap_ns.get())?;
        if cap.is_zero() || cap > MAX_BUDGET_DURATION {
            return Err(ProtocolDomainError::InvalidInput("handoff-cap"));
        }
        Ok(())
    }

    pub fn grant_duration(&self) -> Result<Duration, ProtocolDomainError> {
        ns_to_duration(self.grant_ns.get())
    }

    pub fn receiver_cap_duration(&self) -> Result<Duration, ProtocolDomainError> {
        ns_to_duration(self.receiver_cap_ns.get())
    }

    pub fn reservation_duration(&self) -> Result<Duration, ProtocolDomainError> {
        ns_to_duration(self.reservation_ns)
    }
}

/// A closed reason for an unavailable observation.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum UnavailableReason {
    NotObserved,
    ProtocolDoesNotExpose,
    CapabilityDoesNotExpose,
    CancelledBeforeObservation,
    FailedBeforeObservation,
    Redacted,
}

/// A closed outcome for one transport attempt.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AttemptOutcome {
    ResponseComplete,
    TransportFailure,
    ProtocolFailure,
    TimedOut,
    Cancelled,
    ResourceLimit,
    CapabilityUnavailable,
}

/// A phase in the one-attempt lifecycle.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Phase {
    Queue,
    Dns,
    Pool,
    ProxyConnect,
    Connect,
    ProxyTls,
    OriginTls,
    RequestHeaders,
    RequestBody,
    ResponseHeaders,
    ResponseBody,
    Decompression,
    StateCommit,
    ResultRouting,
    Cleanup,
}

/// Closed timing/observation status for a phase or counter.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TimingValue {
    Known(u64),
    Unavailable(UnavailableReason),
}

/// A closed byte counter value.  `Known(0)` is distinct from unavailable.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CounterValue {
    Known(u64),
    Unavailable(UnavailableReason),
}

/// Why classified bytes are not retained as public data.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SensitivityReason {
    Credential,
    Credentials,
    Cookie,
    Token,
    Authorization,
    Body,
    RequestBodyPolicy,
    ResponseBodyPolicy,
    Url,
    UrlQuery,
    UrlPath,
    CertificatePath,
    UserClassified,
    UpstreamClassified,
    Other,
}

/// Decision0006's closed sensitivity vocabulary under its compatibility name.
pub type SensitiveReason = SensitivityReason;

impl SensitivityReason {
    fn validate(self) -> Result<(), ProtocolDomainError> {
        match self {
            Self::Credential
            | Self::Cookie
            | Self::Token
            | Self::UrlQuery
            | Self::UrlPath
            | Self::RequestBodyPolicy
            | Self::ResponseBodyPolicy
            | Self::CertificatePath
            | Self::UserClassified
            | Self::UpstreamClassified => Ok(()),
            Self::Credentials | Self::Authorization | Self::Body | Self::Url | Self::Other => {
                Err(ProtocolDomainError::InvalidInput("sensitivity-reason"))
            }
        }
    }
}

/// Closed purpose vocabulary for a secret reference.  The provider identity
/// remains non-secret metadata; no secret bytes enter this crate.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SecretPurpose {
    ProxyCredential,
    OriginCredential,
    ClientPrivateKey,
    StorePassword,
    SessionToken,
    RequestPayload,
    ResponsePayload,
}

impl SecretPurpose {
    pub fn parse(value: &str) -> Result<Self, ProtocolDomainError> {
        match value {
            "ProxyCredential" | "proxy-credential" => Ok(Self::ProxyCredential),
            "OriginCredential" | "origin-credential" => Ok(Self::OriginCredential),
            "ClientPrivateKey" | "client-private-key" => Ok(Self::ClientPrivateKey),
            "StorePassword" | "store-password" => Ok(Self::StorePassword),
            "SessionToken" | "session-token" => Ok(Self::SessionToken),
            "RequestPayload" | "request-payload" => Ok(Self::RequestPayload),
            "ResponsePayload" | "response-payload" => Ok(Self::ResponsePayload),
            _ => Err(ProtocolDomainError::InvalidInput("secret-purpose")),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProxyCredential => "proxy-credential",
            Self::OriginCredential => "origin-credential",
            Self::ClientPrivateKey => "client-private-key",
            Self::StorePassword => "store-password",
            Self::SessionToken => "session-token",
            Self::RequestPayload => "request-payload",
            Self::ResponsePayload => "response-payload",
        }
    }
}

/// A value that has been classified before canonical encoding.
#[derive(Clone, Eq, Hash, PartialEq)]
pub enum ObservationValue {
    Public(BoundedBytes),
    Sensitive {
        length: u64,
        reason: SensitivityReason,
    },
    SecretReference {
        provider_identity: BoundedAscii,
        purpose: BoundedAscii,
        length: u64,
    },
}

impl fmt::Debug for ObservationValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public(bytes) => formatter
                .debug_struct("Public")
                .field("len", &bytes.len())
                .finish(),
            Self::Sensitive { length, reason } => formatter
                .debug_struct("Sensitive")
                .field("length", length)
                .field("reason", reason)
                .finish(),
            Self::SecretReference {
                provider_identity,
                purpose,
                length,
            } => formatter
                .debug_struct("SecretReference")
                .field("provider_identity", provider_identity)
                .field("purpose", purpose)
                .field("length", length)
                .finish(),
        }
    }
}

impl ObservationValue {
    pub fn public(value: impl Into<Vec<u8>>) -> Result<Self, ProtocolDomainError> {
        Ok(Self::Public(BoundedBytes::new(value)?))
    }

    pub fn sensitive(length: u64, reason: SensitivityReason) -> Result<Self, ProtocolDomainError> {
        if length > MAX_ATTEMPT_RECORD_BYTES as u64 {
            return Err(ProtocolDomainError::ResourceLimit("classified-value"));
        }
        reason.validate()?;
        Ok(Self::Sensitive { length, reason })
    }

    pub fn secret_reference(
        provider_identity: impl Into<String>,
        purpose: impl Into<String>,
        length: u64,
    ) -> Result<Self, ProtocolDomainError> {
        if length > MAX_ATTEMPT_RECORD_BYTES as u64 {
            return Err(ProtocolDomainError::ResourceLimit("classified-value"));
        }
        let purpose = SecretPurpose::parse(&purpose.into())?;
        Ok(Self::SecretReference {
            provider_identity: BoundedAscii::new(provider_identity)?,
            purpose: BoundedAscii::new(purpose.as_str())?,
            length,
        })
    }

    #[must_use]
    pub fn length(&self) -> u64 {
        match self {
            Self::Public(value) => value.len() as u64,
            Self::Sensitive { length, .. } | Self::SecretReference { length, .. } => *length,
        }
    }

    #[must_use]
    pub const fn public_bytes(&self) -> Option<&BoundedBytes> {
        match self {
            Self::Public(value) => Some(value),
            Self::Sensitive { .. } | Self::SecretReference { .. } => None,
        }
    }

    pub fn digest(&self) -> Presence<[u8; 32]> {
        match self {
            Self::Public(value) => Presence::Present(sha256(value.as_slice())),
            Self::Sensitive { .. } | Self::SecretReference { .. } => Presence::Absent,
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolDomainError> {
        if self.length() > MAX_ATTEMPT_RECORD_BYTES as u64 {
            return Err(ProtocolDomainError::ResourceLimit("classified-value"));
        }
        if let Self::Sensitive { reason, .. } = self {
            reason.validate()?;
        }
        if let Self::SecretReference {
            purpose,
            provider_identity,
            ..
        } = self
        {
            SecretPurpose::parse(purpose.as_str())?;
            if provider_identity.as_str().is_empty() {
                return Err(ProtocolDomainError::InvalidInput("secret-provider"));
            }
        }
        Ok(())
    }
}

impl Default for ObservationValue {
    fn default() -> Self {
        Self::Public(BoundedBytes::empty())
    }
}

/// A request/response header retaining order and duplicate names.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct HeaderFieldV1 {
    pub ordinal: NonZeroU32,
    pub name: ObservationValue,
    pub value: ObservationValue,
}

impl fmt::Debug for HeaderFieldV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeaderFieldV1")
            .field("ordinal", &self.ordinal)
            .field("name_len", &self.name.length())
            .field("value", &self.value)
            .finish()
    }
}

impl HeaderFieldV1 {
    pub fn new(
        name: impl Into<Vec<u8>>,
        value: ObservationValue,
    ) -> Result<Self, ProtocolDomainError> {
        Self::new_classified(ObservationValue::public(name.into())?, value)
    }

    pub fn new_classified(
        name: ObservationValue,
        value: ObservationValue,
    ) -> Result<Self, ProtocolDomainError> {
        if name.length() == 0 || name.length() > 8 * 1024 || value.length() > 64 * 1024 {
            return Err(ProtocolDomainError::InvalidInput("header-field"));
        }
        name.validate()?;
        value.validate()?;
        Ok(Self {
            ordinal: NonZeroU32::MIN,
            name,
            value,
        })
    }

    #[must_use]
    pub fn encoded_len(&self) -> usize {
        usize::try_from(self.name.length())
            .unwrap_or(usize::MAX)
            .saturating_add(1)
            .saturating_add(usize::try_from(self.value.length()).unwrap_or(usize::MAX))
    }
}

/// Ordered bounded headers.  No map folding or duplicate elimination occurs.
#[derive(Clone, Default, Eq, Hash, PartialEq)]
pub struct HeaderListV1 {
    fields: Vec<HeaderFieldV1>,
}

impl fmt::Debug for HeaderListV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeaderListV1")
            .field("count", &self.fields.len())
            .field("aggregate_bytes", &self.aggregate_bytes())
            .finish()
    }
}

impl HeaderListV1 {
    pub fn push(&mut self, field: HeaderFieldV1) -> Result<(), ProtocolDomainError> {
        if self.fields.len() >= MAX_ATTEMPT_HEADERS {
            return Err(ProtocolDomainError::ResourceLimit("headers.count"));
        }
        let next = self
            .aggregate_bytes()
            .checked_add(field.encoded_len())
            .ok_or(ProtocolDomainError::Overflow)?;
        if next > MAX_ATTEMPT_HEADER_BYTES {
            return Err(ProtocolDomainError::ResourceLimit("headers.bytes"));
        }
        let mut field = field;
        let ordinal =
            u32::try_from(self.fields.len() + 1).map_err(|_| ProtocolDomainError::Overflow)?;
        field.ordinal = NonZeroU32::new(ordinal).ok_or(ProtocolDomainError::Overflow)?;
        self.fields.push(field);
        Ok(())
    }

    #[must_use]
    pub fn fields(&self) -> &[HeaderFieldV1] {
        &self.fields
    }

    #[must_use]
    pub fn aggregate_bytes(&self) -> usize {
        self.fields.iter().fold(0usize, |total, field| {
            total.saturating_add(field.encoded_len())
        })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    pub fn validate(&self) -> Result<(), ProtocolDomainError> {
        if self.fields.len() > MAX_ATTEMPT_HEADERS
            || self.aggregate_bytes() > MAX_ATTEMPT_HEADER_BYTES
        {
            return Err(ProtocolDomainError::ResourceLimit("headers"));
        }
        for (index, field) in self.fields.iter().enumerate() {
            let expected = u32::try_from(index + 1).map_err(|_| ProtocolDomainError::Overflow)?;
            if field.ordinal.get() != expected {
                return Err(ProtocolDomainError::InvalidInput("headers.ordinal"));
            }
            if field.name.length() > 8 * 1024 || field.value.length() > 64 * 1024 {
                return Err(ProtocolDomainError::ResourceLimit("headers.field"));
            }
            field.name.validate()?;
            field.value.validate()?;
        }
        Ok(())
    }
}

/// Closed HTTP protocol version observation.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum ProtocolVersion {
    Http10,
    #[default]
    Http11,
    Http2,
}

/// Closed entity framing observation.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum Framing {
    #[default]
    NoBody,
    ContentLength,
    Chunked,
    CloseDelimited,
    Http2Data,
    Tunnel,
}

impl Framing {
    #[allow(non_upper_case_globals)]
    pub const None: Self = Self::NoBody;
}

/// Closed content-compression observation.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum Compression {
    #[default]
    Identity,
    Gzip,
    Deflate,
    Brotli,
    Unsupported,
}

/// Closed TLS version observation.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AttemptTlsVersion {
    Tls12,
    Tls13,
}

/// TLS observation state in the canonical attempt record.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum TlsState {
    NotUsed,
    Observed,
    #[default]
    Unavailable,
}

/// Proxy/origin route variant used by the attempt record.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum RouteVariant {
    #[default]
    Direct,
    ForwardProxy,
    ConnectTunnel,
    TlsForwardProxy,
}

/// Non-secret route identity. Endpoint IDs are application-owned opaque IDs,
/// never URL or host hashes.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RouteIdentityV1 {
    pub variant: RouteVariant,
    pub proxy_endpoint_id: Presence<[u8; 16]>,
    pub origin_endpoint_id: [u8; 16],
    pub policy_digest: [u8; 32],
}

impl Default for RouteIdentityV1 {
    fn default() -> Self {
        Self {
            variant: RouteVariant::Direct,
            proxy_endpoint_id: Presence::Absent,
            origin_endpoint_id: [0; 16],
            policy_digest: [0; 32],
        }
    }
}

impl RouteIdentityV1 {
    pub fn direct(origin_endpoint_id: [u8; 16], policy_digest: [u8; 32]) -> Self {
        Self {
            origin_endpoint_id,
            policy_digest,
            ..Self::default()
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolDomainError> {
        if matches!(self.variant, RouteVariant::Direct) && self.proxy_endpoint_id.is_present() {
            return Err(ProtocolDomainError::InvalidInput("route.proxy-endpoint"));
        }
        if !matches!(self.variant, RouteVariant::Direct) && !self.proxy_endpoint_id.is_present() {
            return Err(ProtocolDomainError::InvalidInput("route.proxy-endpoint"));
        }
        Ok(())
    }

    pub fn canonical_digest(&self) -> Result<[u8; 32], ProtocolDomainError> {
        self.validate()?;
        let mut preimage = Vec::new();
        preimage.extend_from_slice(b"http.route/1\0");
        preimage.push(self.variant as u8);
        match self.proxy_endpoint_id {
            Presence::Absent => preimage.push(0),
            Presence::Present(id) => {
                preimage.push(1);
                preimage.extend_from_slice(&id);
            }
        }
        preimage.extend_from_slice(&self.origin_endpoint_id);
        preimage.extend_from_slice(&self.policy_digest);
        Ok(sha256(&preimage))
    }
}

/// Closed connection reuse state.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ConnectionState {
    New,
    Reused,
    Closed,
    Unavailable(UnavailableReason),
}

macro_rules! closed_u8_enum {
    ($type:ty, $( $value:literal => $variant:path ),+ $(,)?) => {
        impl TryFrom<u8> for $type {
            type Error = ProtocolDomainError;

            fn try_from(value: u8) -> Result<Self, Self::Error> {
                match value {
                    $( $value => Ok($variant), )+
                    _ => Err(ProtocolDomainError::InvalidInput("closed-enum-value")),
                }
            }
        }
    };
}

closed_u8_enum!(
    UnavailableReason,
    0 => UnavailableReason::NotObserved,
    1 => UnavailableReason::ProtocolDoesNotExpose,
    2 => UnavailableReason::CapabilityDoesNotExpose,
    3 => UnavailableReason::CancelledBeforeObservation,
    4 => UnavailableReason::FailedBeforeObservation,
    5 => UnavailableReason::Redacted,
);
closed_u8_enum!(
    AttemptOutcome,
    0 => AttemptOutcome::ResponseComplete,
    1 => AttemptOutcome::TransportFailure,
    2 => AttemptOutcome::ProtocolFailure,
    3 => AttemptOutcome::TimedOut,
    4 => AttemptOutcome::Cancelled,
    5 => AttemptOutcome::ResourceLimit,
    6 => AttemptOutcome::CapabilityUnavailable,
);
closed_u8_enum!(
    Phase,
    0 => Phase::Queue,
    1 => Phase::Dns,
    2 => Phase::Pool,
    3 => Phase::ProxyConnect,
    4 => Phase::Connect,
    5 => Phase::ProxyTls,
    6 => Phase::OriginTls,
    7 => Phase::RequestHeaders,
    8 => Phase::RequestBody,
    9 => Phase::ResponseHeaders,
    10 => Phase::ResponseBody,
    11 => Phase::Decompression,
    12 => Phase::StateCommit,
    13 => Phase::ResultRouting,
    14 => Phase::Cleanup,
);
closed_u8_enum!(
    PhaseStatus,
    0 => PhaseStatus::Completed,
    1 => PhaseStatus::Failed,
    2 => PhaseStatus::TimedOut,
    3 => PhaseStatus::Cancelled,
    4 => PhaseStatus::Skipped,
);
closed_u8_enum!(
    ProtocolVersion,
    0 => ProtocolVersion::Http10,
    1 => ProtocolVersion::Http11,
    2 => ProtocolVersion::Http2,
);
closed_u8_enum!(
    Framing,
    0 => Framing::NoBody,
    1 => Framing::ContentLength,
    2 => Framing::Chunked,
    3 => Framing::CloseDelimited,
    4 => Framing::Http2Data,
    5 => Framing::Tunnel,
);
closed_u8_enum!(
    Compression,
    0 => Compression::Identity,
    1 => Compression::Gzip,
    2 => Compression::Deflate,
    3 => Compression::Brotli,
    4 => Compression::Unsupported,
);
closed_u8_enum!(
    AttemptTlsVersion,
    0 => AttemptTlsVersion::Tls12,
    1 => AttemptTlsVersion::Tls13,
);
closed_u8_enum!(
    RouteVariant,
    0 => RouteVariant::Direct,
    1 => RouteVariant::ForwardProxy,
    2 => RouteVariant::ConnectTunnel,
    3 => RouteVariant::TlsForwardProxy,
);
closed_u8_enum!(
    TlsState,
    0 => TlsState::NotUsed,
    1 => TlsState::Observed,
    2 => TlsState::Unavailable,
);
impl TryFrom<u8> for ConnectionState {
    type Error = ProtocolDomainError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::New),
            1 => Ok(Self::Reused),
            2 => Ok(Self::Closed),
            3 => Ok(Self::Unavailable(UnavailableReason::NotObserved)),
            _ => Err(ProtocolDomainError::InvalidInput("closed-enum-value")),
        }
    }
}
closed_u8_enum!(
    CounterKind,
    0 => CounterKind::RequestHeader,
    1 => CounterKind::RequestBody,
    2 => CounterKind::ResponseHeader,
    3 => CounterKind::ResponseBody,
    4 => CounterKind::Entity,
    5 => CounterKind::Decoded,
    6 => CounterKind::Sent,
    7 => CounterKind::Received,
    8 => CounterKind::ConnectionWire,
);
closed_u8_enum!(
    WriteState,
    0 => WriteState::NotStarted,
    1 => WriteState::HeadersWritten,
    2 => WriteState::BodyWritten,
    3 => WriteState::Complete,
    4 => WriteState::Failed,
);

/// A bounded public/sensitive body observation retaining presence and framing.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct BodyObservationV1 {
    pub presence: Presence<ObservationValue>,
    pub framing: Framing,
    pub digest: Presence<[u8; 32]>,
    /// Effective body representation after protocol framing.
    pub wire_form: BodyWireForm,
    /// Replayability of the source/body projection.
    pub replayability: Replayability,
}

/// Closed body wire-form projection used by `http.attempt/1`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum BodyWireForm {
    #[default]
    Empty,
    Bytes,
    File,
    Stream,
}

impl BodyObservationV1 {
    #[must_use]
    pub fn absent(framing: Framing) -> Self {
        Self {
            presence: Presence::Absent,
            framing,
            digest: Presence::Absent,
            wire_form: BodyWireForm::Empty,
            replayability: Replayability::Replayable,
        }
    }

    pub fn present(value: ObservationValue, framing: Framing) -> Result<Self, ProtocolDomainError> {
        value.validate()?;
        let digest = public_body_digest(&value);
        Ok(Self {
            presence: Presence::Present(value),
            framing,
            digest,
            wire_form: BodyWireForm::Bytes,
            replayability: Replayability::Replayable,
        })
    }

    pub fn present_with(
        value: ObservationValue,
        framing: Framing,
        wire_form: BodyWireForm,
        replayability: Replayability,
    ) -> Result<Self, ProtocolDomainError> {
        let mut body = Self::present(value, framing)?;
        body.wire_form = wire_form;
        body.replayability = replayability;
        Ok(body)
    }

    pub fn validate(&self) -> Result<(), ProtocolDomainError> {
        match &self.presence {
            Presence::Present(value) => {
                value.validate()?;
                if matches!(self.wire_form, BodyWireForm::Empty) {
                    return Err(ProtocolDomainError::InvalidInput("body-wire-form"));
                }
                if self.digest != public_body_digest(value) {
                    return Err(ProtocolDomainError::InvalidInput("body-digest"));
                }
            }
            Presence::Absent => {
                if !matches!(self.wire_form, BodyWireForm::Empty)
                    || !matches!(self.digest, Presence::Absent)
                {
                    return Err(ProtocolDomainError::InvalidInput("body-wire-form"));
                }
            }
        }
        Ok(())
    }
}

fn public_body_digest(value: &ObservationValue) -> Presence<[u8; 32]> {
    let ObservationValue::Public(bytes) = value else {
        return Presence::Absent;
    };
    let mut preimage = Vec::with_capacity(32 + bytes.len());
    preimage.extend_from_slice(b"http.public-body/1\0");
    append_u64(&mut preimage, bytes.len() as u64);
    preimage.extend_from_slice(bytes.as_slice());
    Presence::Present(sha256(&preimage))
}

impl Default for BodyObservationV1 {
    fn default() -> Self {
        Self::absent(Framing::None)
    }
}

/// A request observation in canonical attempt order.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RequestObservationV1 {
    pub method: ObservationValue,
    pub target: ObservationValue,
    pub protocol: ProtocolVersion,
    pub headers: HeaderListV1,
    pub body: BodyObservationV1,
    pub framing: Framing,
    pub write_state: WriteState,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum WriteState {
    #[default]
    NotStarted,
    HeadersWritten,
    BodyWritten,
    Complete,
    Failed,
}

impl Default for RequestObservationV1 {
    fn default() -> Self {
        Self {
            method: ObservationValue::Public(BoundedBytes(b"GET".to_vec())),
            target: ObservationValue::default(),
            protocol: ProtocolVersion::Http11,
            headers: HeaderListV1::default(),
            body: BodyObservationV1::default(),
            framing: Framing::NoBody,
            write_state: WriteState::NotStarted,
        }
    }
}

/// An informational response retained before the final response.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct InformationalResponseV1 {
    pub ordinal: NonZeroU32,
    pub status: u16,
    pub reason: Presence<ObservationValue>,
    pub protocol: ProtocolVersion,
    pub headers: HeaderListV1,
    pub framing: Framing,
}

/// A response observation in canonical attempt order.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ResponseObservationV1 {
    pub ordinal: NonZeroU32,
    pub status: u16,
    pub reason: Presence<ObservationValue>,
    pub protocol: ProtocolVersion,
    pub framing: Framing,
    pub compression: Compression,
    pub headers: HeaderListV1,
    pub trailers: Presence<TrailerCollection>,
    pub body: BodyObservationV1,
    pub completion_state: CompletionState,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum CompletionState {
    #[default]
    Incomplete,
    Complete,
    Failed,
    Cancelled,
}

closed_u8_enum!(
    CompletionState,
    0 => CompletionState::Incomplete,
    1 => CompletionState::Complete,
    2 => CompletionState::Failed,
    3 => CompletionState::Cancelled,
);

/// A bounded TLS identity observation.  Certificate bytes are represented
/// only by a digest, never by a path or raw certificate.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TlsIdentityV1 {
    pub state: TlsState,
    pub provider_identity: CapabilityIdentityV1,
    pub protocol: BoundedAscii,
    pub cipher: BoundedAscii,
    pub peer_public_fingerprints: Vec<[u8; 32]>,
    pub reuse_state: ConnectionState,
}

pub type TlsObservationV1 = TlsIdentityV1;

impl TlsIdentityV1 {
    #[must_use]
    pub fn unavailable() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<(), ProtocolDomainError> {
        if self.peer_public_fingerprints.len() > 64 {
            return Err(ProtocolDomainError::ResourceLimit("tls.peer-fingerprints"));
        }
        Ok(())
    }
}

impl Default for TlsIdentityV1 {
    fn default() -> Self {
        Self {
            state: TlsState::Unavailable,
            provider_identity: CapabilityIdentityV1::unknown(),
            protocol: BoundedAscii("unknown".to_owned()),
            cipher: BoundedAscii("unknown".to_owned()),
            peer_public_fingerprints: Vec::new(),
            reuse_state: ConnectionState::Unavailable(UnavailableReason::NotObserved),
        }
    }
}

/// Connection-reuse observation.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ConnectionObservationV1 {
    pub state: ConnectionState,
    pub pool_identity: Presence<[u8; 16]>,
    pub connection_identity: Presence<[u8; 16]>,
    pub reuse_ordinal: Presence<NonZeroU64>,
}

impl Default for ConnectionObservationV1 {
    fn default() -> Self {
        Self {
            state: ConnectionState::Unavailable(UnavailableReason::NotObserved),
            pool_identity: Presence::Absent,
            connection_identity: Presence::Absent,
            reuse_ordinal: Presence::Absent,
        }
    }
}

impl ConnectionObservationV1 {
    pub fn validate(&self) -> Result<(), ProtocolDomainError> {
        if matches!(self.state, ConnectionState::Unavailable(_))
            && (self.pool_identity.is_present()
                || self.connection_identity.is_present()
                || self.reuse_ordinal.is_present())
        {
            return Err(ProtocolDomainError::InvalidInput("connection.identity"));
        }
        Ok(())
    }
}

/// Phase status retained with an unsigned duration.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PhaseStatus {
    Completed,
    Failed,
    TimedOut,
    Cancelled,
    Skipped,
}

/// One phase observation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PhaseObservationV1 {
    pub ordinal: NonZeroU32,
    pub phase: Phase,
    pub status: PhaseStatus,
    pub elapsed_ns: TimingValue,
}

/// One named byte counter.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ByteCounterV1 {
    pub ordinal: NonZeroU32,
    pub kind: CounterKind,
    pub value: CounterValue,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CounterKind {
    RequestHeader,
    RequestBody,
    ResponseHeader,
    ResponseBody,
    Entity,
    Decoded,
    Sent,
    Received,
    ConnectionWire,
}

/// Budget values included in an attempt record.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct BudgetObservationV1 {
    pub budget_id: [u8; 16],
    pub grant_ordinal: Presence<NonZeroU64>,
    pub start_remaining_ns: CounterValue,
    pub end_remaining_ns: CounterValue,
    pub grant_ns: CounterValue,
    pub reservation_ns: CounterValue,
    pub receiver_cap_ns: CounterValue,
    pub expired_phase: Presence<Phase>,
}

impl Default for BudgetObservationV1 {
    fn default() -> Self {
        Self {
            budget_id: [0; 16],
            grant_ordinal: Presence::Absent,
            start_remaining_ns: CounterValue::Known(0),
            end_remaining_ns: CounterValue::Known(0),
            grant_ns: CounterValue::Unavailable(UnavailableReason::NotObserved),
            reservation_ns: CounterValue::Unavailable(UnavailableReason::NotObserved),
            receiver_cap_ns: CounterValue::Unavailable(UnavailableReason::NotObserved),
            expired_phase: Presence::Absent,
        }
    }
}

/// Opaque schema/version/digest identity for a selected capability.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct CapabilityIdentityV1 {
    pub schema_id: BoundedAscii,
    pub version: NonZeroU32,
    pub sha256: [u8; 32],
}

impl fmt::Debug for CapabilityIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityIdentityV1")
            .field("schema_id", &self.schema_id)
            .field("version", &self.version)
            .field("sha256", &"<digest>")
            .finish()
    }
}

impl CapabilityIdentityV1 {
    pub fn new(
        schema_id: impl Into<String>,
        version: NonZeroU32,
        sha256: [u8; 32],
    ) -> Result<Self, ProtocolDomainError> {
        let schema_id = schema_id.into();
        if schema_id.len() > 64 {
            return Err(ProtocolDomainError::ResourceLimit("schema-id"));
        }
        Ok(Self {
            schema_id: BoundedAscii::new(schema_id)?,
            version,
            sha256,
        })
    }

    #[must_use]
    pub fn unknown() -> Self {
        Self {
            schema_id: BoundedAscii("unknown".to_owned()),
            version: NonZeroU32::MIN,
            sha256: [0; 32],
        }
    }
}

fn fixed_identity(schema_id: &'static str, digest_domain: &'static [u8]) -> CapabilityIdentityV1 {
    CapabilityIdentityV1 {
        schema_id: BoundedAscii(schema_id.to_owned()),
        version: NonZeroU32::MIN,
        sha256: sha256(digest_domain),
    }
}

/// The plan-domain namespace for a source node.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct PlanDomainId {
    pub schema: BoundedAscii,
    pub value: BoundedUtf8,
}

impl fmt::Debug for PlanDomainId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlanDomainId")
            .field("schema", &self.schema)
            .field("value", &self.value)
            .finish()
    }
}

impl PlanDomainId {
    pub fn new(value: impl Into<String>) -> Result<Self, ProtocolDomainError> {
        Ok(Self {
            schema: BoundedAscii::new("plan-domain/1")?,
            value: BoundedUtf8::new(value)?,
        })
    }
}

/// A node qualified by the plan domain and opaque document/node identities.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DomainQualifiedNode {
    pub plan_domain: PlanDomainId,
    pub document_id: [u8; 32],
    pub node_id: NonZeroU64,
}

/// A closed source-node context.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum SourceNodeV1 {
    Unknown,
    DomainQualified(DomainQualifiedNode),
}

/// A bounded source-node path.
#[derive(Clone, Default, Eq, Hash, PartialEq)]
pub struct PlanPathV1 {
    nodes: Vec<DomainQualifiedNode>,
    encoded_bytes: usize,
}

impl fmt::Debug for PlanPathV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlanPathV1")
            .field("nodes", &self.nodes.len())
            .field("encoded_bytes", &self.encoded_bytes)
            .finish()
    }
}

impl PlanPathV1 {
    pub fn push(&mut self, node: DomainQualifiedNode) -> Result<(), ProtocolDomainError> {
        if self.nodes.len() >= 128 {
            return Err(ProtocolDomainError::ResourceLimit("plan-path.nodes"));
        }
        let node_bytes = node
            .plan_domain
            .schema
            .as_str()
            .len()
            .checked_add(node.plan_domain.value.as_str().len())
            // Four length-delimited node fields plus the ordered-item
            // wrapper contribute nine bytes each (tag + u64 length).
            .and_then(|bytes| bytes.checked_add(32 + 8 + 5 * 9))
            .ok_or(ProtocolDomainError::Overflow)?;
        let next = self
            .encoded_bytes
            .checked_add(node_bytes)
            .ok_or(ProtocolDomainError::Overflow)?;
        if next > 16 * 1024 {
            return Err(ProtocolDomainError::ResourceLimit("plan-path.bytes"));
        }
        if let Some(previous) = self.nodes.last()
            && (previous.plan_domain != node.plan_domain
                || previous.document_id != node.document_id
                || previous.node_id == node.node_id)
        {
            return Err(ProtocolDomainError::InvalidInput("plan-path.identity"));
        }
        self.nodes.push(node);
        self.encoded_bytes = next;
        Ok(())
    }

    #[must_use]
    pub fn nodes(&self) -> &[DomainQualifiedNode] {
        &self.nodes
    }
}

/// Identity of the logical sampler/user operation.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SamplerIdentityV1 {
    pub run_id: [u8; 16],
    pub user_id: u64,
    pub iteration: u64,
    pub sample_id: NonZeroU64,
}

impl Default for SamplerIdentityV1 {
    fn default() -> Self {
        Self {
            run_id: [0; 16],
            user_id: 0,
            iteration: 0,
            sample_id: NonZeroU64::MIN,
        }
    }
}

/// A redacted bounded diagnostic entry.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DiagnosticVisibilityV1 {
    PublicRedacted,
}

closed_u8_enum!(DiagnosticVisibilityV1, 0 => DiagnosticVisibilityV1::PublicRedacted,);

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct DiagnosticV1 {
    pub ordinal: NonZeroU32,
    pub code: HttpDiagnosticCode,
    pub visibility: DiagnosticVisibilityV1,
    pub message: BoundedDiagnosticText,
}

impl fmt::Debug for DiagnosticV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiagnosticV1")
            .field("ordinal", &self.ordinal)
            .field("code", &self.code)
            .field("visibility", &self.visibility)
            .field("message", &"<redacted>")
            .finish()
    }
}

impl DiagnosticV1 {
    pub fn new(
        code: impl AsRef<str>,
        message: impl AsRef<str>,
    ) -> Result<Self, ProtocolDomainError> {
        if message.as_ref().len() > MAX_DIAGNOSTIC_BYTES {
            return Err(ProtocolDomainError::ResourceLimit("diagnostic.bytes"));
        }
        let message = redact_diagnostic_message(message.as_ref());
        let code = HttpDiagnosticCode::from_str(code.as_ref())
            .ok_or(ProtocolDomainError::InvalidInput("diagnostic-code"))?;
        Ok(Self {
            ordinal: NonZeroU32::MIN,
            code,
            visibility: DiagnosticVisibilityV1::PublicRedacted,
            message: BoundedDiagnosticText::new(message)?,
        })
    }

    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.code.as_str().len() + self.message.as_str().len()
    }
}

fn redact_diagnostic_message(message: &str) -> String {
    // Provider text is not a classified protocol value at this boundary.  A
    // fixed marker is therefore the only fail-closed representation; callers
    // retain the closed code and can attach separately audited diagnostics.
    let _ = message;
    "<redacted>".to_owned()
}

/// Canonical context attached to errors and attempts.
pub struct ErrorContextV1 {
    pub source_node: SourceNodeV1,
    pub plan_path: PlanPathV1,
    pub sampler_identity: SamplerIdentityV1,
    pub capability_identity: CapabilityIdentityV1,
    pub attempt_index: NonZeroU32,
    pub embedded_resource_index: Presence<u32>,
    pub phase: Phase,
    pub stable_error_code: StableHttpErrorCode,
    diagnostics: Vec<DiagnosticV1>,
    diagnostic_bytes: usize,
}

impl Clone for ErrorContextV1 {
    fn clone(&self) -> Self {
        Self {
            source_node: self.source_node.clone(),
            plan_path: self.plan_path.clone(),
            sampler_identity: self.sampler_identity.clone(),
            capability_identity: self.capability_identity.clone(),
            attempt_index: self.attempt_index,
            embedded_resource_index: self.embedded_resource_index.clone(),
            phase: self.phase,
            stable_error_code: self.stable_error_code,
            diagnostics: self.diagnostics.clone(),
            diagnostic_bytes: self.diagnostic_bytes,
        }
    }
}

impl fmt::Debug for ErrorContextV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ErrorContextV1")
            .field("source_node", &self.source_node)
            .field("plan_path", &self.plan_path)
            .field("sampler_identity", &self.sampler_identity)
            .field("capability_identity", &self.capability_identity)
            .field("attempt_index", &self.attempt_index)
            .field("embedded_resource_index", &self.embedded_resource_index)
            .field("phase", &self.phase)
            .field("stable_error_code", &self.stable_error_code)
            .field("diagnostics", &self.diagnostics.len())
            .finish()
    }
}

impl PartialEq for ErrorContextV1 {
    fn eq(&self, other: &Self) -> bool {
        self.source_node == other.source_node
            && self.plan_path == other.plan_path
            && self.sampler_identity == other.sampler_identity
            && self.capability_identity == other.capability_identity
            && self.attempt_index == other.attempt_index
            && self.embedded_resource_index == other.embedded_resource_index
            && self.phase == other.phase
            && self.stable_error_code == other.stable_error_code
    }
}

impl Eq for ErrorContextV1 {}

impl Default for ErrorContextV1 {
    fn default() -> Self {
        Self {
            source_node: SourceNodeV1::Unknown,
            plan_path: PlanPathV1::default(),
            sampler_identity: SamplerIdentityV1::default(),
            capability_identity: CapabilityIdentityV1::unknown(),
            attempt_index: NonZeroU32::MIN,
            embedded_resource_index: Presence::Absent,
            phase: Phase::Queue,
            stable_error_code: StableHttpErrorCode::InternalInvariant,
            diagnostics: Vec::new(),
            diagnostic_bytes: 0,
        }
    }
}

impl ErrorContextV1 {
    pub fn new(stable_error_code: impl AsRef<str>) -> Result<Self, ProtocolDomainError> {
        let stable_error_code = StableHttpErrorCode::from_str(stable_error_code.as_ref())
            .ok_or(ProtocolDomainError::InvalidInput("stable-error-code"))?;
        Ok(Self {
            source_node: SourceNodeV1::Unknown,
            plan_path: PlanPathV1::default(),
            sampler_identity: SamplerIdentityV1::default(),
            capability_identity: CapabilityIdentityV1::unknown(),
            attempt_index: NonZeroU32::MIN,
            embedded_resource_index: Presence::Absent,
            phase: Phase::Queue,
            stable_error_code,
            diagnostics: Vec::new(),
            diagnostic_bytes: 0,
        })
    }

    pub fn add_diagnostic(&mut self, diagnostic: DiagnosticV1) -> Result<(), ProtocolDomainError> {
        if self.diagnostics.len() >= MAX_DIAGNOSTICS {
            return Err(ProtocolDomainError::ResourceLimit("diagnostics.count"));
        }
        let next = self
            .diagnostic_bytes
            .checked_add(diagnostic.encoded_len())
            .ok_or(ProtocolDomainError::Overflow)?;
        if next > MAX_DIAGNOSTIC_AGGREGATE_BYTES {
            return Err(ProtocolDomainError::ResourceLimit("diagnostics.bytes"));
        }
        self.diagnostic_bytes = next;
        let mut diagnostic = diagnostic;
        let ordinal =
            u32::try_from(self.diagnostics.len() + 1).map_err(|_| ProtocolDomainError::Overflow)?;
        diagnostic.ordinal = NonZeroU32::new(ordinal).ok_or(ProtocolDomainError::Overflow)?;
        self.diagnostics.push(diagnostic);
        Ok(())
    }

    pub fn schema_identity() -> Result<CapabilityIdentityV1, ProtocolDomainError> {
        CapabilityIdentityV1::new(
            ERROR_CONTEXT_SCHEMA_ID,
            NonZeroU32::MIN,
            sha256(b"http.error-context/1\0"),
        )
    }

    #[must_use]
    pub fn diagnostics(&self) -> &[DiagnosticV1] {
        &self.diagnostics
    }

    pub fn validate(&self) -> Result<(), ProtocolDomainError> {
        if self.diagnostics.len() > MAX_DIAGNOSTICS
            || self.diagnostic_bytes > MAX_DIAGNOSTIC_AGGREGATE_BYTES
            || self
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.encoded_len() > MAX_DIAGNOSTIC_BYTES)
        {
            return Err(ProtocolDomainError::ResourceLimit("error-context"));
        }
        match (&self.source_node, self.plan_path.nodes.last()) {
            (SourceNodeV1::Unknown, Some(_)) => {
                return Err(ProtocolDomainError::InvalidInput("error-context.source"));
            }
            (SourceNodeV1::DomainQualified(source), Some(last)) => {
                if source != last {
                    return Err(ProtocolDomainError::InvalidInput("error-context.source"));
                }
            }
            (SourceNodeV1::DomainQualified(_), None) => {
                return Err(ProtocolDomainError::InvalidInput("error-context.path"));
            }
            (SourceNodeV1::Unknown, None) => {}
        }
        for pair in self.plan_path.nodes().windows(2) {
            if pair[0].plan_domain != pair[1].plan_domain
                || pair[0].document_id != pair[1].document_id
                || pair[0].node_id == pair[1].node_id
            {
                return Err(ProtocolDomainError::InvalidInput("error-context.path"));
            }
        }
        for (index, diagnostic) in self.diagnostics.iter().enumerate() {
            let expected = u32::try_from(index + 1).map_err(|_| ProtocolDomainError::Overflow)?;
            if diagnostic.ordinal.get() != expected {
                return Err(ProtocolDomainError::InvalidInput("diagnostics.ordinal"));
            }
        }
        Ok(())
    }
}

/// Canonical immutable record for one transport attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptRecordV1 {
    pub source_context: ErrorContextV1,
    pub operation_id: [u8; 16],
    pub attempt_index: NonZeroU32,
    pub capability_identity: CapabilityIdentityV1,
    pub route_identity: RouteIdentityV1,
    pub request_observation: RequestObservationV1,
    pub informational_responses: Vec<InformationalResponseV1>,
    pub response_observation: Presence<ResponseObservationV1>,
    pub proxy_tls_identity: TlsIdentityV1,
    pub origin_tls_identity: TlsIdentityV1,
    pub connection_observation: ConnectionObservationV1,
    pub phase_observations: Vec<PhaseObservationV1>,
    pub byte_counters: Vec<ByteCounterV1>,
    pub budget_observation: BudgetObservationV1,
    pub outcome: AttemptOutcome,
    pub diagnostics: Vec<DiagnosticV1>,
}

impl Default for AttemptRecordV1 {
    fn default() -> Self {
        Self {
            source_context: ErrorContextV1::default(),
            operation_id: [0; 16],
            attempt_index: NonZeroU32::MIN,
            capability_identity: CapabilityIdentityV1::unknown(),
            route_identity: RouteIdentityV1::default(),
            request_observation: RequestObservationV1::default(),
            informational_responses: Vec::new(),
            response_observation: Presence::Absent,
            proxy_tls_identity: TlsIdentityV1::default(),
            origin_tls_identity: TlsIdentityV1::default(),
            connection_observation: ConnectionObservationV1::default(),
            phase_observations: Vec::new(),
            byte_counters: Vec::new(),
            budget_observation: BudgetObservationV1::default(),
            outcome: AttemptOutcome::CapabilityUnavailable,
            diagnostics: Vec::new(),
        }
    }
}

impl AttemptRecordV1 {
    pub fn validate(&self) -> Result<(), ProtocolDomainError> {
        self.request_observation.method.validate()?;
        self.request_observation.target.validate()?;
        self.request_observation.body.validate()?;
        if self.request_observation.body.framing != self.request_observation.framing {
            return Err(ProtocolDomainError::InvalidInput("request.framing"));
        }
        self.source_context.validate()?;
        if self.source_context.attempt_index != self.attempt_index {
            return Err(ProtocolDomainError::InvalidInput("attempt.index"));
        }
        self.route_identity.validate()?;
        self.connection_observation.validate()?;
        self.proxy_tls_identity.validate()?;
        self.origin_tls_identity.validate()?;
        if self.informational_responses.len() > MAX_INFORMATIONAL_RESPONSES {
            return Err(ProtocolDomainError::ResourceLimit("informational.count"));
        }
        if self.phase_observations.len() > MAX_PHASE_OBSERVATIONS {
            return Err(ProtocolDomainError::ResourceLimit("phases.count"));
        }
        if self.byte_counters.len() > MAX_BYTE_COUNTERS {
            return Err(ProtocolDomainError::ResourceLimit("counters.count"));
        }
        for (index, phase) in self.phase_observations.iter().enumerate() {
            let expected = u32::try_from(index + 1).map_err(|_| ProtocolDomainError::Overflow)?;
            if phase.ordinal.get() != expected {
                return Err(ProtocolDomainError::InvalidInput("phases.ordinal"));
            }
        }
        for (index, counter) in self.byte_counters.iter().enumerate() {
            let expected = u32::try_from(index + 1).map_err(|_| ProtocolDomainError::Overflow)?;
            if counter.ordinal.get() != expected {
                return Err(ProtocolDomainError::InvalidInput("counters.ordinal"));
            }
        }
        if self.diagnostics.len() > MAX_DIAGNOSTICS
            || self
                .diagnostics
                .iter()
                .map(DiagnosticV1::encoded_len)
                .try_fold(0usize, usize::checked_add)
                .ok_or(ProtocolDomainError::Overflow)?
                > MAX_DIAGNOSTIC_AGGREGATE_BYTES
        {
            return Err(ProtocolDomainError::ResourceLimit("diagnostics"));
        }
        for informational in &self.informational_responses {
            if !(100..200).contains(&informational.status) {
                return Err(ProtocolDomainError::InvalidInput("informational.status"));
            }
            informational
                .reason
                .as_ref()
                .map_or(Ok(()), ObservationValue::validate)?;
            informational.headers.validate()?;
        }
        for (index, informational) in self.informational_responses.iter().enumerate() {
            let expected = u32::try_from(index + 1).map_err(|_| ProtocolDomainError::Overflow)?;
            if informational.ordinal.get() != expected {
                return Err(ProtocolDomainError::InvalidInput("informational.ordinal"));
            }
        }
        self.request_observation.headers.validate()?;
        if let Presence::Present(response) = &self.response_observation {
            if response.status < 200 {
                return Err(ProtocolDomainError::InvalidInput("response.status"));
            }
            if response.ordinal.get() != 1 {
                return Err(ProtocolDomainError::InvalidInput("response.ordinal"));
            }
            response
                .reason
                .as_ref()
                .map_or(Ok(()), ObservationValue::validate)?;
            response.body.validate()?;
            if response.body.framing != response.framing {
                return Err(ProtocolDomainError::InvalidInput("response.framing"));
            }
            response.headers.validate()?;
            if let Presence::Present(trailers) = &response.trailers
                && trailers.fields().len() > MAX_TRAILERS
            {
                return Err(ProtocolDomainError::ResourceLimit("response.trailers"));
            }
            if let Presence::Present(trailers) = &response.trailers {
                trailers.validate()?;
            }
        }
        for (index, diagnostic) in self.diagnostics.iter().enumerate() {
            let expected = u32::try_from(index + 1).map_err(|_| ProtocolDomainError::Overflow)?;
            if diagnostic.ordinal.get() != expected {
                return Err(ProtocolDomainError::InvalidInput("diagnostic.ordinal"));
            }
        }
        if self.estimated_bytes() > MAX_ATTEMPT_RECORD_BYTES {
            return Err(ProtocolDomainError::ResourceLimit("attempt-record.bytes"));
        }
        Ok(())
    }

    #[must_use]
    pub fn estimated_bytes(&self) -> usize {
        let request = self.request_observation.headers.aggregate_bytes();
        let response = match &self.response_observation {
            Presence::Absent => 0,
            Presence::Present(value) => value.headers.aggregate_bytes(),
        };
        // Body bytes are never retained in the canonical record.  Count only
        // the bounded metadata envelope here; a classified 4 MiB payload is
        // still a small record containing presence, length, and digest state.
        let bodies = usize::from(self.request_observation.body.presence.is_present()) * 32
            + match &self.response_observation {
                Presence::Absent => 0,
                Presence::Present(value) => usize::from(value.body.presence.is_present()) * 32,
            };
        request
            .saturating_add(response)
            .saturating_add(bodies)
            .saturating_add(self.informational_responses.len() * 32)
            .saturating_add(self.phase_observations.len() * 24)
            .saturating_add(self.byte_counters.len() * 24)
            .saturating_add(self.source_context.diagnostics().len() * 64)
    }

    /// Encodes the redacted, ordered `http.attempt/1` representation. The
    /// encoder never traverses an unclassified byte field.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProtocolDomainError> {
        self.validate()?;
        let mut output = Vec::new();
        output.extend_from_slice(b"http.attempt/1\0");
        append_attempt_field(&mut output, 1, &encode_context(&self.source_context)?);
        append_attempt_field(&mut output, 2, &self.operation_id);
        append_attempt_field(&mut output, 3, &self.attempt_index.get().to_be_bytes());
        append_attempt_field(
            &mut output,
            4,
            &encode_capability(&self.capability_identity),
        );
        append_attempt_field(&mut output, 5, &encode_route(&self.route_identity));
        append_attempt_field(&mut output, 6, &encode_request(&self.request_observation));
        let informational = encode_informational(&self.informational_responses);
        append_attempt_field(&mut output, 7, &informational);
        match &self.response_observation {
            Presence::Absent => append_attempt_field(&mut output, 8, &[0]),
            Presence::Present(response) => {
                let encoded = encode_response(response);
                let mut value = vec![1];
                value.extend_from_slice(&encoded);
                append_attempt_field(&mut output, 8, &value);
            }
        }
        append_attempt_field(&mut output, 9, &encode_tls(&self.proxy_tls_identity));
        append_attempt_field(&mut output, 10, &encode_tls(&self.origin_tls_identity));
        append_attempt_field(
            &mut output,
            11,
            &encode_connection(&self.connection_observation),
        );
        append_attempt_field(&mut output, 12, &encode_phases(&self.phase_observations));
        append_attempt_field(&mut output, 13, &encode_counters(&self.byte_counters));
        append_attempt_field(&mut output, 14, &encode_budget(&self.budget_observation));
        append_attempt_field(&mut output, 15, &[self.outcome as u8]);
        append_attempt_field(&mut output, 16, &encode_diagnostics(&self.diagnostics));
        if output.len() > MAX_ATTEMPT_RECORD_BYTES {
            return Err(ProtocolDomainError::ResourceLimit("attempt-record.bytes"));
        }
        Ok(output)
    }

    pub fn canonical_digest(&self) -> Result<[u8; 32], ProtocolDomainError> {
        Ok(sha256(&self.canonical_bytes()?))
    }

    pub fn schema_identity() -> Result<CapabilityIdentityV1, ProtocolDomainError> {
        CapabilityIdentityV1::new(
            ATTEMPT_SCHEMA_ID,
            NonZeroU32::MIN,
            sha256(b"http.attempt/1\0"),
        )
    }
}

fn append_attempt_field(output: &mut Vec<u8>, tag: u8, value: &[u8]) {
    output.push(tag);
    append_u64(output, value.len() as u64);
    output.extend_from_slice(value);
}

fn encode_context(context: &ErrorContextV1) -> Result<Vec<u8>, ProtocolDomainError> {
    let mut output = Vec::new();
    match &context.source_node {
        SourceNodeV1::Unknown => append_attempt_field(&mut output, 1, &[0]),
        SourceNodeV1::DomainQualified(node) => {
            append_attempt_field(&mut output, 1, &encode_domain_node(node));
        }
    }
    let mut path = Vec::new();
    for node in context.plan_path.nodes() {
        append_attempt_field(&mut path, 1, &encode_domain_node(node));
    }
    append_attempt_field(&mut output, 2, &path);
    append_attempt_field(&mut output, 3, &context.sampler_identity.run_id);
    append_attempt_field(
        &mut output,
        4,
        &context.sampler_identity.user_id.to_be_bytes(),
    );
    append_attempt_field(
        &mut output,
        5,
        &context.sampler_identity.iteration.to_be_bytes(),
    );
    append_attempt_field(
        &mut output,
        6,
        &context.sampler_identity.sample_id.get().to_be_bytes(),
    );
    append_attempt_field(
        &mut output,
        7,
        &encode_capability(&context.capability_identity),
    );
    append_attempt_field(&mut output, 8, &context.attempt_index.get().to_be_bytes());
    match context.embedded_resource_index {
        Presence::Absent => append_attempt_field(&mut output, 9, &[0]),
        Presence::Present(index) => append_attempt_field(&mut output, 9, &index.to_be_bytes()),
    }
    append_attempt_field(&mut output, 10, &[context.phase as u8]);
    append_attempt_field(
        &mut output,
        11,
        context.stable_error_code.as_str().as_bytes(),
    );
    append_attempt_field(&mut output, 12, &encode_diagnostics(context.diagnostics()));
    Ok(output)
}

fn encode_domain_node(node: &DomainQualifiedNode) -> Vec<u8> {
    let mut output = Vec::new();
    append_attempt_field(&mut output, 1, node.plan_domain.schema.as_str().as_bytes());
    append_attempt_field(&mut output, 2, node.plan_domain.value.as_str().as_bytes());
    append_attempt_field(&mut output, 3, &node.document_id);
    append_attempt_field(&mut output, 4, &node.node_id.get().to_be_bytes());
    output
}

fn encode_capability(identity: &CapabilityIdentityV1) -> Vec<u8> {
    let mut output = Vec::new();
    append_attempt_field(&mut output, 1, identity.schema_id.as_str().as_bytes());
    append_attempt_field(&mut output, 2, &identity.version.get().to_be_bytes());
    append_attempt_field(&mut output, 3, &identity.sha256);
    output
}

fn encode_route(route: &RouteIdentityV1) -> Vec<u8> {
    let mut output = Vec::new();
    append_attempt_field(&mut output, 1, &[route.variant as u8]);
    match route.proxy_endpoint_id {
        Presence::Absent => append_attempt_field(&mut output, 2, &[0]),
        Presence::Present(id) => {
            let mut value = vec![1];
            value.extend_from_slice(&id);
            append_attempt_field(&mut output, 2, &value);
        }
    }
    append_attempt_field(&mut output, 3, &route.origin_endpoint_id);
    append_attempt_field(&mut output, 4, &route.policy_digest);
    output
}

fn encode_header_list(headers: &HeaderListV1) -> Vec<u8> {
    let mut output = Vec::new();
    for field in headers.fields() {
        let mut item = Vec::new();
        append_attempt_field(&mut item, 1, &field.ordinal.get().to_be_bytes());
        let mut name = Vec::new();
        append_observation(&mut name, &field.name);
        append_attempt_field(&mut item, 2, &name);
        let mut value = Vec::new();
        append_observation(&mut value, &field.value);
        append_attempt_field(&mut item, 3, &value);
        append_attempt_field(&mut output, 1, &item);
    }
    output
}

fn encode_body(body: &BodyObservationV1) -> Vec<u8> {
    let mut output = Vec::new();
    match &body.presence {
        Presence::Absent => append_attempt_field(&mut output, 1, &[0]),
        // Presence is intentionally only a discriminant.  Even public body
        // bytes never enter an attempt record; the digest is the sole body
        // content projection below.
        Presence::Present(_) => append_attempt_field(&mut output, 1, &[1]),
    }
    let classification = match body.presence {
        Presence::Absent => 0_u8,
        Presence::Present(ObservationValue::Public(_)) => 1,
        Presence::Present(ObservationValue::Sensitive { .. }) => 2,
        Presence::Present(ObservationValue::SecretReference { .. }) => 3,
    };
    append_attempt_field(&mut output, 2, &[classification]);
    let length = body.presence.as_ref().map_or(0, ObservationValue::length);
    append_attempt_field(&mut output, 3, &length.to_be_bytes());
    match body.digest {
        Presence::Absent => append_attempt_field(&mut output, 4, &[0]),
        Presence::Present(digest) => {
            append_attempt_field(&mut output, 4, &[1]);
            append_attempt_field(&mut output, 5, &digest);
        }
    }
    append_attempt_field(&mut output, 6, &[body.wire_form as u8]);
    append_attempt_field(&mut output, 7, &[body.replayability as u8]);
    output
}

fn encode_request(request: &RequestObservationV1) -> Vec<u8> {
    let mut output = Vec::new();
    let mut method = Vec::new();
    append_observation(&mut method, &request.method);
    append_attempt_field(&mut output, 1, &method);
    let mut target = Vec::new();
    append_observation(&mut target, &request.target);
    append_attempt_field(&mut output, 2, &target);
    append_attempt_field(&mut output, 3, &[request.protocol as u8]);
    append_attempt_field(&mut output, 4, &encode_header_list(&request.headers));
    match request.body.presence {
        Presence::Absent => append_attempt_field(&mut output, 5, &[0]),
        Presence::Present(_) => append_attempt_field(&mut output, 5, &[1]),
    }
    append_attempt_field(&mut output, 6, &encode_body(&request.body));
    append_attempt_field(&mut output, 7, &[request.framing as u8]);
    append_attempt_field(&mut output, 8, &[request.write_state as u8]);
    output
}

fn encode_informational(values: &[InformationalResponseV1]) -> Vec<u8> {
    let mut output = Vec::new();
    for value in values {
        let mut item = Vec::new();
        append_attempt_field(&mut item, 1, &value.ordinal.get().to_be_bytes());
        append_attempt_field(&mut item, 2, &value.status.to_be_bytes());
        match &value.reason {
            Presence::Absent => append_attempt_field(&mut item, 3, &[0]),
            Presence::Present(reason) => {
                append_attempt_field(&mut item, 3, &[1]);
                let mut encoded = Vec::new();
                append_observation(&mut encoded, reason);
                append_attempt_field(&mut item, 4, &encoded);
            }
        }
        append_attempt_field(&mut item, 5, &[value.protocol as u8]);
        append_attempt_field(&mut item, 6, &encode_header_list(&value.headers));
        append_attempt_field(&mut item, 7, &[value.framing as u8]);
        append_attempt_field(&mut output, 1, &item);
    }
    output
}

fn encode_response(response: &ResponseObservationV1) -> Vec<u8> {
    let mut output = Vec::new();
    append_attempt_field(&mut output, 1, &response.ordinal.get().to_be_bytes());
    append_attempt_field(&mut output, 2, &response.status.to_be_bytes());
    match &response.reason {
        Presence::Absent => append_attempt_field(&mut output, 3, &[0]),
        Presence::Present(reason) => {
            append_attempt_field(&mut output, 3, &[1]);
            let mut encoded = Vec::new();
            append_observation(&mut encoded, reason);
            append_attempt_field(&mut output, 4, &encoded);
        }
    }
    append_attempt_field(&mut output, 5, &[response.protocol as u8]);
    append_attempt_field(&mut output, 6, &encode_header_list(&response.headers));
    append_attempt_field(&mut output, 7, &[response.framing as u8]);
    append_attempt_field(&mut output, 8, &[response.compression as u8]);
    append_attempt_field(&mut output, 9, &encode_body(&response.body));
    match &response.trailers {
        Presence::Absent => append_attempt_field(&mut output, 10, &[0]),
        Presence::Present(trailers) => {
            append_attempt_field(&mut output, 10, &[1]);
            append_attempt_field(
                &mut output,
                11,
                &encode_header_list(&HeaderListV1 {
                    fields: trailers.fields.clone(),
                }),
            );
        }
    }
    append_attempt_field(
        &mut output,
        12,
        &[completion_state_byte(response.completion_state)],
    );
    output
}

fn completion_state_byte(value: CompletionState) -> u8 {
    match value {
        CompletionState::Incomplete => 0,
        CompletionState::Complete => 1,
        CompletionState::Failed => 2,
        CompletionState::Cancelled => 3,
    }
}

fn encode_tls(value: &TlsIdentityV1) -> Vec<u8> {
    let mut output = Vec::new();
    append_attempt_field(&mut output, 1, &[value.state as u8]);
    append_attempt_field(&mut output, 2, &encode_capability(&value.provider_identity));
    append_attempt_field(&mut output, 3, value.protocol.as_str().as_bytes());
    append_attempt_field(&mut output, 4, value.cipher.as_str().as_bytes());
    let mut fingerprints = Vec::new();
    for (index, fingerprint) in value.peer_public_fingerprints.iter().enumerate() {
        append_attempt_field(&mut fingerprints, 1, &fingerprint[..]);
        if index == 63 {
            break;
        }
    }
    append_attempt_field(&mut output, 5, &fingerprints);
    append_attempt_field(&mut output, 6, &[connection_state_byte(value.reuse_state)]);
    output
}

fn encode_connection(value: &ConnectionObservationV1) -> Vec<u8> {
    let mut output = Vec::new();
    append_attempt_field(&mut output, 1, &[connection_state_byte(value.state)]);
    if let Presence::Present(id) = value.pool_identity {
        append_attempt_field(&mut output, 2, &id);
    }
    if let Presence::Present(id) = value.connection_identity {
        append_attempt_field(&mut output, 3, &id);
    }
    if let Presence::Present(ordinal) = value.reuse_ordinal {
        append_attempt_field(&mut output, 4, &ordinal.get().to_be_bytes());
    }
    output
}

fn connection_state_byte(value: ConnectionState) -> u8 {
    match value {
        ConnectionState::New => 0,
        ConnectionState::Reused => 1,
        ConnectionState::Closed => 2,
        ConnectionState::Unavailable(_) => 3,
    }
}

fn encode_phases(values: &[PhaseObservationV1]) -> Vec<u8> {
    let mut output = Vec::new();
    for value in values {
        let mut item = Vec::new();
        append_attempt_field(&mut item, 1, &value.ordinal.get().to_be_bytes());
        append_attempt_field(&mut item, 2, &[value.phase as u8]);
        append_attempt_field(&mut item, 3, &[phase_status_byte(value.status)]);
        append_attempt_field(&mut item, 4, &timing_bytes(value.elapsed_ns));
        append_attempt_field(&mut output, 1, &item);
    }
    output
}

fn phase_status_byte(status: PhaseStatus) -> u8 {
    match status {
        PhaseStatus::Completed => 0,
        PhaseStatus::Failed => 1,
        PhaseStatus::TimedOut => 2,
        PhaseStatus::Cancelled => 3,
        PhaseStatus::Skipped => 4,
    }
}

fn timing_bytes(value: TimingValue) -> Vec<u8> {
    match value {
        TimingValue::Known(value) => {
            let mut output = vec![0];
            output.extend_from_slice(&value.to_be_bytes());
            output
        }
        TimingValue::Unavailable(reason) => vec![1, reason as u8],
    }
}

fn encode_counters(values: &[ByteCounterV1]) -> Vec<u8> {
    let mut output = Vec::new();
    for value in values {
        let mut item = Vec::new();
        append_attempt_field(&mut item, 1, &value.ordinal.get().to_be_bytes());
        append_attempt_field(&mut item, 2, &[value.kind as u8]);
        append_attempt_field(&mut item, 3, &counter_bytes(value.value));
        append_attempt_field(&mut output, 1, &item);
    }
    output
}

fn counter_bytes(value: CounterValue) -> Vec<u8> {
    match value {
        CounterValue::Known(value) => {
            let mut output = vec![0];
            output.extend_from_slice(&value.to_be_bytes());
            output
        }
        CounterValue::Unavailable(reason) => vec![1, reason as u8],
    }
}

fn encode_budget(value: &BudgetObservationV1) -> Vec<u8> {
    let mut output = Vec::new();
    append_attempt_field(&mut output, 1, &value.budget_id);
    if let Presence::Present(ordinal) = value.grant_ordinal {
        append_attempt_field(&mut output, 2, &ordinal.get().to_be_bytes());
    }
    append_attempt_field(&mut output, 3, &counter_bytes(value.start_remaining_ns));
    append_attempt_field(&mut output, 4, &counter_bytes(value.end_remaining_ns));
    append_attempt_field(&mut output, 5, &counter_bytes(value.reservation_ns));
    append_attempt_field(&mut output, 6, &counter_bytes(value.receiver_cap_ns));
    if let Presence::Present(phase) = value.expired_phase {
        append_attempt_field(&mut output, 7, &[phase as u8]);
    }
    output
}

fn encode_diagnostics(values: &[DiagnosticV1]) -> Vec<u8> {
    let mut output = Vec::new();
    for value in values {
        let mut item = Vec::new();
        append_attempt_field(&mut item, 1, &value.ordinal.get().to_be_bytes());
        append_attempt_field(&mut item, 2, value.code.as_str().as_bytes());
        append_attempt_field(&mut item, 3, &[value.visibility as u8]);
        append_attempt_field(&mut item, 4, value.message.as_str().as_bytes());
        append_attempt_field(&mut output, 1, &item);
    }
    output
}

/// A bounded typed cookie-manager key.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CookieKeyV1 {
    pub name: BoundedAscii,
    pub scope: BoundedAscii,
}

/// A bounded typed cache-manager key.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CacheKeyV1 {
    pub method: BoundedAscii,
    pub uri: ObservationValue,
}

/// A bounded typed authentication-challenge key.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AuthChallengeKeyV1 {
    pub origin: BoundedAscii,
    pub scheme: BoundedAscii,
}

/// A bounded typed DNS key.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DnsKeyV1 {
    pub host: BoundedAscii,
    pub port: u16,
}

/// A bounded typed header-manager key.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct HeaderKeyV1 {
    pub name: ObservationValue,
}

/// A bounded typed connection-observation key.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ConnectionKeyV1 {
    pub route: BoundedAscii,
}

/// Keys are closed over the six state ledgers.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum StateKeyV1 {
    Cookie(CookieKeyV1),
    Cache(CacheKeyV1),
    AuthChallenge(AuthChallengeKeyV1),
    Dns(DnsKeyV1),
    Header(HeaderKeyV1),
    Connection(ConnectionKeyV1),
}

/// One ordered value in a state ledger.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct StateValueV1 {
    pub order: u64,
    pub value: Presence<ObservationValue>,
}

impl StateValueV1 {
    pub fn new(order: u64, value: Presence<ObservationValue>) -> Result<Self, ProtocolDomainError> {
        if matches!(&value, Presence::Present(value) if value.length() > MAX_ATTEMPT_RECORD_BYTES as u64)
        {
            return Err(ProtocolDomainError::ResourceLimit("state-value"));
        }
        if let Presence::Present(value) = &value {
            value.validate()?;
        }
        Ok(Self { order, value })
    }

    pub fn validate(&self) -> Result<(), ProtocolDomainError> {
        if let Presence::Present(value) = &self.value {
            value.validate()?;
        }
        Ok(())
    }

    #[must_use]
    pub fn encoded_len(&self) -> usize {
        8 + self.value.as_ref().map_or(0, |value| {
            usize::try_from(value.length()).unwrap_or(usize::MAX)
        })
    }
}

/// Closed aggregate state operations.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum HttpStateOpV1 {
    CookieUpsert {
        key: CookieKeyV1,
        value: StateValueV1,
    },
    CookieDelete {
        key: CookieKeyV1,
    },
    CookieClear,
    CacheUpsert {
        key: CacheKeyV1,
        value: StateValueV1,
    },
    CacheDelete {
        key: CacheKeyV1,
    },
    CacheInvalidate {
        key: CacheKeyV1,
    },
    AuthChallengeUpsert {
        key: AuthChallengeKeyV1,
        value: StateValueV1,
    },
    AuthChallengeDelete {
        key: AuthChallengeKeyV1,
    },
    AuthChallengeClear,
    DnsUpsert {
        key: DnsKeyV1,
        value: StateValueV1,
    },
    DnsDelete {
        key: DnsKeyV1,
    },
    DnsClear,
    HeaderReplace {
        key: HeaderKeyV1,
        value: StateValueV1,
    },
    HeaderAppend {
        key: HeaderKeyV1,
        value: StateValueV1,
    },
    HeaderRemove {
        key: HeaderKeyV1,
    },
    ConnectionObserve {
        key: ConnectionKeyV1,
        value: StateValueV1,
    },
    ConnectionForget {
        key: ConnectionKeyV1,
    },
}

/// An atomic aggregate replacement request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpStateDeltaV1 {
    pub schema_identity: CapabilityIdentityV1,
    pub base_generation: u64,
    pub base_digest: [u8; 32],
    pub policy_identity: CapabilityIdentityV1,
    pub candidate_digest: [u8; 32],
    pub candidate_generation: NonZeroU64,
    pub operations: Vec<HttpStateOpV1>,
    operation_ordinals: Vec<NonZeroU32>,
    operation_source_attempts: Vec<NonZeroU32>,
}

impl HttpStateDeltaV1 {
    pub fn schema_identity() -> Result<CapabilityIdentityV1, ProtocolDomainError> {
        CapabilityIdentityV1::new(
            STATE_DELTA_SCHEMA_ID,
            NonZeroU32::MIN,
            sha256(b"http.state-delta/1\0"),
        )
    }

    pub fn policy_identity() -> Result<CapabilityIdentityV1, ProtocolDomainError> {
        CapabilityIdentityV1::new(
            "http.state-policy",
            NonZeroU32::MIN,
            sha256(b"http.state/1\0"),
        )
    }

    #[must_use]
    pub fn new(base_generation: u64, base_digest: [u8; 32], candidate_digest: [u8; 32]) -> Self {
        let candidate_generation = match NonZeroU64::new(base_generation.saturating_add(1)) {
            Some(value) => value,
            None => NonZeroU64::MAX,
        };
        Self {
            schema_identity: fixed_identity("http.state-delta", b"http.state-delta/1\0"),
            base_generation,
            base_digest,
            policy_identity: fixed_identity("http.state-policy", b"http.state/1\0"),
            candidate_digest,
            candidate_generation,
            operations: Vec::new(),
            operation_ordinals: Vec::new(),
            operation_source_attempts: Vec::new(),
        }
    }

    pub fn push(&mut self, operation: HttpStateOpV1) -> Result<(), ProtocolDomainError> {
        self.push_from_attempt(operation, NonZeroU32::MIN)
    }

    pub fn push_from_attempt(
        &mut self,
        operation: HttpStateOpV1,
        source_attempt_index: NonZeroU32,
    ) -> Result<(), ProtocolDomainError> {
        validate_state_operation(&operation)?;
        if self.operations.len() >= 1_024 {
            return Err(ProtocolDomainError::ResourceLimit("state-delta.operations"));
        }
        let ordinal =
            u32::try_from(self.operations.len() + 1).map_err(|_| ProtocolDomainError::Overflow)?;
        let ordinal = NonZeroU32::new(ordinal).ok_or(ProtocolDomainError::Overflow)?;
        self.operations.push(operation);
        self.operation_ordinals.push(ordinal);
        self.operation_source_attempts.push(source_attempt_index);
        Ok(())
    }

    pub fn validate(&self) -> Result<(), ProtocolDomainError> {
        if self.schema_identity != Self::schema_identity()? {
            return Err(ProtocolDomainError::InvalidInput("state-delta.schema"));
        }
        if self.policy_identity != Self::policy_identity()? {
            return Err(ProtocolDomainError::InvalidInput("state-delta.policy"));
        }
        if self.operations.len() > 1_024 {
            return Err(ProtocolDomainError::ResourceLimit("state-delta.operations"));
        }
        if self.operation_ordinals.len() != self.operations.len()
            || self.operation_source_attempts.len() != self.operations.len()
        {
            return Err(ProtocolDomainError::InvalidInput("state-delta.ordinal"));
        }
        if self.candidate_generation.get() != self.base_generation.saturating_add(1) {
            return Err(ProtocolDomainError::InvalidInput("state-delta.generation"));
        }
        for (index, ordinal) in self.operation_ordinals.iter().enumerate() {
            let expected = u32::try_from(index + 1).map_err(|_| ProtocolDomainError::Overflow)?;
            if ordinal.get() != expected {
                return Err(ProtocolDomainError::InvalidInput("state-delta.ordinal"));
            }
        }
        for operation in &self.operations {
            validate_state_operation(operation)?;
        }
        Ok(())
    }

    #[must_use]
    pub fn operation_ordinals(&self) -> &[NonZeroU32] {
        &self.operation_ordinals
    }

    #[must_use]
    pub fn operation_source_attempts(&self) -> &[NonZeroU32] {
        &self.operation_source_attempts
    }

    /// Encodes the atomic compare-and-swap envelope using the declared
    /// `http.state-delta/1` field order.  Values are classified before this
    /// boundary; no raw secret-bearing observation can enter the digest.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProtocolDomainError> {
        self.validate()?;
        let mut output = Vec::new();
        output.extend_from_slice(b"http.state-delta/1\0");
        append_attempt_field(&mut output, 1, &encode_capability(&self.schema_identity));
        append_attempt_field(&mut output, 2, &self.base_generation.to_be_bytes());
        append_attempt_field(&mut output, 3, &self.base_digest);
        append_attempt_field(&mut output, 4, &encode_capability(&self.policy_identity));
        let mut operations = Vec::new();
        for ((operation, ordinal), source_attempt) in self
            .operations
            .iter()
            .zip(&self.operation_ordinals)
            .zip(&self.operation_source_attempts)
        {
            let mut item = Vec::new();
            append_attempt_field(&mut item, 1, &ordinal.get().to_be_bytes());
            append_attempt_field(&mut item, 2, &[state_operation_byte(operation)]);
            encode_state_operation_fields(&mut item, operation);
            append_attempt_field(&mut item, 6, &source_attempt.get().to_be_bytes());
            append_attempt_field(&mut operations, 1, &item);
        }
        append_attempt_field(&mut output, 5, &operations);
        append_attempt_field(
            &mut output,
            6,
            &self.candidate_generation.get().to_be_bytes(),
        );
        append_attempt_field(&mut output, 7, &self.candidate_digest);
        if output.len() > MAX_ATTEMPT_RECORD_BYTES {
            return Err(ProtocolDomainError::ResourceLimit("state-delta.bytes"));
        }
        Ok(output)
    }

    pub fn canonical_digest(&self) -> Result<[u8; 32], ProtocolDomainError> {
        Ok(sha256(&self.canonical_bytes()?))
    }
}

fn state_operation_byte(operation: &HttpStateOpV1) -> u8 {
    match operation {
        HttpStateOpV1::CookieUpsert { .. } => 0,
        HttpStateOpV1::CookieDelete { .. } => 1,
        HttpStateOpV1::CookieClear => 2,
        HttpStateOpV1::CacheUpsert { .. } => 3,
        HttpStateOpV1::CacheDelete { .. } => 4,
        HttpStateOpV1::CacheInvalidate { .. } => 5,
        HttpStateOpV1::AuthChallengeUpsert { .. } => 6,
        HttpStateOpV1::AuthChallengeDelete { .. } => 7,
        HttpStateOpV1::AuthChallengeClear => 8,
        HttpStateOpV1::DnsUpsert { .. } => 9,
        HttpStateOpV1::DnsDelete { .. } => 10,
        HttpStateOpV1::DnsClear => 11,
        HttpStateOpV1::HeaderReplace { .. } => 12,
        HttpStateOpV1::HeaderAppend { .. } => 13,
        HttpStateOpV1::HeaderRemove { .. } => 14,
        HttpStateOpV1::ConnectionObserve { .. } => 15,
        HttpStateOpV1::ConnectionForget { .. } => 16,
    }
}

fn validate_state_operation(operation: &HttpStateOpV1) -> Result<(), ProtocolDomainError> {
    match operation {
        HttpStateOpV1::CookieUpsert { value, .. }
        | HttpStateOpV1::AuthChallengeUpsert { value, .. }
        | HttpStateOpV1::DnsUpsert { value, .. }
        | HttpStateOpV1::ConnectionObserve { value, .. } => value.validate(),
        HttpStateOpV1::CacheUpsert { key, value } => {
            key.uri.validate()?;
            value.validate()
        }
        HttpStateOpV1::HeaderReplace { key, value }
        | HttpStateOpV1::HeaderAppend { key, value } => {
            if key.name.length() == 0 {
                return Err(ProtocolDomainError::InvalidInput("state.header-name"));
            }
            key.name.validate()?;
            value.validate()
        }
        HttpStateOpV1::CacheDelete { key } | HttpStateOpV1::CacheInvalidate { key } => {
            key.uri.validate()
        }
        HttpStateOpV1::HeaderRemove { key } => {
            if key.name.length() == 0 {
                return Err(ProtocolDomainError::InvalidInput("state.header-name"));
            }
            key.name.validate()
        }
        HttpStateOpV1::CookieDelete { .. }
        | HttpStateOpV1::CookieClear
        | HttpStateOpV1::AuthChallengeDelete { .. }
        | HttpStateOpV1::AuthChallengeClear
        | HttpStateOpV1::DnsDelete { .. }
        | HttpStateOpV1::DnsClear
        | HttpStateOpV1::ConnectionForget { .. } => Ok(()),
    }
}

fn encode_state_operation_fields(output: &mut Vec<u8>, operation: &HttpStateOpV1) {
    match operation {
        HttpStateOpV1::CookieUpsert { key, value } => {
            append_attempt_field(output, 3, &encode_cookie_key(key));
            append_state_value(output, value);
        }
        HttpStateOpV1::CookieDelete { key } => {
            append_attempt_field(output, 3, &encode_cookie_key(key));
            append_attempt_field(output, 4, &[0]);
        }
        HttpStateOpV1::CookieClear => {}
        HttpStateOpV1::CacheUpsert { key, value } => {
            append_attempt_field(output, 3, &encode_cache_key(key));
            append_state_value(output, value);
        }
        HttpStateOpV1::CacheDelete { key } | HttpStateOpV1::CacheInvalidate { key } => {
            append_attempt_field(output, 3, &encode_cache_key(key));
            append_attempt_field(output, 4, &[0]);
        }
        HttpStateOpV1::AuthChallengeUpsert { key, value } => {
            append_attempt_field(output, 3, &encode_auth_key(key));
            append_state_value(output, value);
        }
        HttpStateOpV1::AuthChallengeDelete { key } => {
            append_attempt_field(output, 3, &encode_auth_key(key));
            append_attempt_field(output, 4, &[0]);
        }
        HttpStateOpV1::AuthChallengeClear => {}
        HttpStateOpV1::DnsUpsert { key, value } => {
            append_attempt_field(output, 3, &encode_dns_key(key));
            append_state_value(output, value);
        }
        HttpStateOpV1::DnsDelete { key } => {
            append_attempt_field(output, 3, &encode_dns_key(key));
            append_attempt_field(output, 4, &[0]);
        }
        HttpStateOpV1::DnsClear => {}
        HttpStateOpV1::HeaderReplace { key, value }
        | HttpStateOpV1::HeaderAppend { key, value } => {
            append_attempt_field(output, 3, &encode_header_key(key));
            append_state_value(output, value);
        }
        HttpStateOpV1::HeaderRemove { key } => {
            append_attempt_field(output, 3, &encode_header_key(key));
            append_attempt_field(output, 4, &[0]);
        }
        HttpStateOpV1::ConnectionObserve { key, value } => {
            append_attempt_field(output, 3, &encode_connection_key(key));
            append_state_value(output, value);
        }
        HttpStateOpV1::ConnectionForget { key } => {
            append_attempt_field(output, 3, &encode_connection_key(key));
            append_attempt_field(output, 4, &[0]);
        }
    }
}

fn append_state_value(output: &mut Vec<u8>, value: &StateValueV1) {
    let mut encoded = Vec::new();
    append_attempt_field(&mut encoded, 1, &value.order.to_be_bytes());
    match &value.value {
        Presence::Absent => append_attempt_field(&mut encoded, 2, &[0]),
        Presence::Present(observation) => {
            append_attempt_field(&mut encoded, 2, &[1]);
            let mut value = Vec::new();
            append_observation(&mut value, observation);
            append_attempt_field(&mut encoded, 3, &value);
        }
    }
    append_attempt_field(output, 4, &[1]);
    append_attempt_field(output, 5, &encoded);
}

fn encode_cookie_key(key: &CookieKeyV1) -> Vec<u8> {
    let mut output = Vec::new();
    append_ascii(&mut output, &key.name);
    append_ascii(&mut output, &key.scope);
    output
}

fn encode_cache_key(key: &CacheKeyV1) -> Vec<u8> {
    let mut output = Vec::new();
    append_ascii(&mut output, &key.method);
    append_observation(&mut output, &key.uri);
    output
}

fn encode_auth_key(key: &AuthChallengeKeyV1) -> Vec<u8> {
    let mut output = Vec::new();
    append_ascii(&mut output, &key.origin);
    append_ascii(&mut output, &key.scheme);
    output
}

fn encode_dns_key(key: &DnsKeyV1) -> Vec<u8> {
    let mut output = Vec::new();
    append_ascii(&mut output, &key.host);
    output.extend_from_slice(&key.port.to_be_bytes());
    output
}

fn encode_header_key(key: &HeaderKeyV1) -> Vec<u8> {
    let mut output = Vec::new();
    append_header_key(&mut output, key);
    output
}

fn encode_connection_key(key: &ConnectionKeyV1) -> Vec<u8> {
    let mut output = Vec::new();
    append_ascii(&mut output, &key.route);
    output
}

const MAX_STATE_ENTRIES: usize = 4_096;
const MAX_STATE_BYTES: usize = 4 * 1024 * 1024;

/// One bounded per-user state aggregate.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct HttpUserStateV1 {
    pub generation: u64,
    cookies: Vec<(CookieKeyV1, StateValueV1)>,
    cache: Vec<(CacheKeyV1, StateValueV1)>,
    auth_challenges: Vec<(AuthChallengeKeyV1, StateValueV1)>,
    dns: Vec<(DnsKeyV1, StateValueV1)>,
    headers: Vec<(HeaderKeyV1, StateValueV1)>,
    connections: Vec<(ConnectionKeyV1, StateValueV1)>,
}

impl fmt::Debug for HttpUserStateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpUserStateV1")
            .field("generation", &self.generation)
            .field("cookies", &self.cookies.len())
            .field("cache", &self.cache.len())
            .field("auth_challenges", &self.auth_challenges.len())
            .field("dns", &self.dns.len())
            .field("headers", &self.headers.len())
            .field("connections", &self.connections.len())
            .finish()
    }
}

impl HttpUserStateV1 {
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        self.digest_with_domain(b"http.state-base/1\0")
    }

    fn digest_with_domain(&self, domain: &[u8]) -> [u8; 32] {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(domain);
        append_entries(&mut encoded, 1, &self.cookies, |output, key| {
            append_ascii(output, &key.name);
            append_ascii(output, &key.scope);
        });
        append_entries(&mut encoded, 2, &self.cache, |output, key| {
            append_ascii(output, &key.method);
            append_observation(output, &key.uri);
        });
        append_entries(&mut encoded, 3, &self.auth_challenges, |output, key| {
            append_ascii(output, &key.origin);
            append_ascii(output, &key.scheme);
        });
        append_entries(&mut encoded, 4, &self.dns, |output, key| {
            append_ascii(output, &key.host);
            output.extend_from_slice(&key.port.to_be_bytes());
        });
        append_entries(&mut encoded, 5, &self.headers, |output, key| {
            append_header_key(output, key);
        });
        append_entries(&mut encoded, 6, &self.connections, |output, key| {
            append_ascii(output, &key.route);
        });
        sha256(&encoded)
    }

    #[must_use]
    pub fn base_digest(&self) -> [u8; 32] {
        self.digest()
    }

    #[must_use]
    pub fn candidate_digest(&self) -> [u8; 32] {
        self.digest_with_domain(b"http.state-candidate/1\0")
    }

    pub fn validate(&self) -> Result<(), ProtocolDomainError> {
        let counts = [
            self.cookies.len(),
            self.cache.len(),
            self.auth_challenges.len(),
            self.dns.len(),
            self.headers.len(),
            self.connections.len(),
        ];
        let total = counts.iter().try_fold(0usize, |sum, count| {
            sum.checked_add(*count).ok_or(ProtocolDomainError::Overflow)
        })?;
        if total > MAX_STATE_ENTRIES {
            return Err(ProtocolDomainError::ResourceLimit("state.entries"));
        }
        fn validate_values<K>(entries: &[(K, StateValueV1)]) -> Result<(), ProtocolDomainError> {
            for (_, value) in entries {
                value.validate()?;
            }
            Ok(())
        }
        validate_values(&self.cookies)?;
        validate_values(&self.cache)?;
        validate_values(&self.auth_challenges)?;
        validate_values(&self.dns)?;
        validate_values(&self.headers)?;
        validate_values(&self.connections)?;
        for (key, _) in &self.cache {
            key.uri.validate()?;
        }
        for (key, _) in &self.headers {
            if key.name.length() == 0 {
                return Err(ProtocolDomainError::InvalidInput("state.header-name"));
            }
            key.name.validate()?;
        }
        let bytes = self.encoded_state_bytes()?;
        if bytes > MAX_STATE_BYTES {
            return Err(ProtocolDomainError::ResourceLimit("state.bytes"));
        }
        Ok(())
    }

    pub fn candidate(&self, delta: &HttpStateDeltaV1) -> Result<Self, ProtocolDomainError> {
        delta.validate()?;
        if self.generation != delta.base_generation || self.digest() != delta.base_digest {
            return Err(ProtocolDomainError::Conflict);
        }
        let candidate = self.project(&delta.operations)?;
        candidate.validate()?;
        if candidate.candidate_digest() != delta.candidate_digest {
            return Err(ProtocolDomainError::Conflict);
        }
        Ok(candidate)
    }

    pub fn reduce_candidate(&self, delta: &HttpStateDeltaV1) -> Result<Self, ProtocolDomainError> {
        self.candidate(delta)
    }

    /// Projects a bounded operation list without doing a generation/digest
    /// compare.  Callers use this to calculate the candidate digest before
    /// constructing the compare-and-swap envelope.
    pub fn project(&self, operations: &[HttpStateOpV1]) -> Result<Self, ProtocolDomainError> {
        if operations.len() > 1_024 {
            return Err(ProtocolDomainError::ResourceLimit("state-delta.operations"));
        }
        let mut candidate = self.clone();
        for operation in operations {
            candidate.apply_operation(operation)?;
            candidate.validate()?;
        }
        Ok(candidate)
    }

    pub fn digest_after(
        &self,
        operations: &[HttpStateOpV1],
    ) -> Result<[u8; 32], ProtocolDomainError> {
        Ok(self.project(operations)?.candidate_digest())
    }

    pub fn compare_and_swap(
        &mut self,
        delta: &HttpStateDeltaV1,
    ) -> Result<(), ProtocolDomainError> {
        let mut candidate = self.candidate(delta)?;
        candidate.generation = self
            .generation
            .checked_add(1)
            .ok_or(ProtocolDomainError::Overflow)?;
        if candidate.generation != delta.candidate_generation.get() {
            return Err(ProtocolDomainError::Conflict);
        }
        if candidate.candidate_digest() != delta.candidate_digest {
            return Err(ProtocolDomainError::Conflict);
        }
        *self = candidate;
        Ok(())
    }

    pub fn apply_delta(&mut self, delta: &HttpStateDeltaV1) -> Result<(), ProtocolDomainError> {
        self.compare_and_swap(delta)
    }

    #[must_use]
    pub fn cookies(&self) -> &[(CookieKeyV1, StateValueV1)] {
        &self.cookies
    }

    #[must_use]
    pub fn cache(&self) -> &[(CacheKeyV1, StateValueV1)] {
        &self.cache
    }

    #[must_use]
    pub fn auth_challenges(&self) -> &[(AuthChallengeKeyV1, StateValueV1)] {
        &self.auth_challenges
    }

    #[must_use]
    pub fn dns(&self) -> &[(DnsKeyV1, StateValueV1)] {
        &self.dns
    }

    #[must_use]
    pub fn headers(&self) -> &[(HeaderKeyV1, StateValueV1)] {
        &self.headers
    }

    #[must_use]
    pub fn connections(&self) -> &[(ConnectionKeyV1, StateValueV1)] {
        &self.connections
    }

    fn encoded_state_bytes(&self) -> Result<usize, ProtocolDomainError> {
        fn add_values<K>(
            total: &mut usize,
            entries: &[(K, StateValueV1)],
        ) -> Result<(), ProtocolDomainError> {
            for (_, value) in entries {
                *total = total
                    .checked_add(value.encoded_len())
                    .ok_or(ProtocolDomainError::Overflow)?;
            }
            Ok(())
        }
        let mut total = 0usize;
        add_values(&mut total, &self.cookies)?;
        add_values(&mut total, &self.cache)?;
        add_values(&mut total, &self.auth_challenges)?;
        add_values(&mut total, &self.dns)?;
        add_values(&mut total, &self.headers)?;
        add_values(&mut total, &self.connections)?;
        Ok(total)
    }

    fn apply_operation(&mut self, operation: &HttpStateOpV1) -> Result<(), ProtocolDomainError> {
        match operation {
            HttpStateOpV1::CookieUpsert { key, value } => {
                upsert(&mut self.cookies, key.clone(), value.clone())
            }
            HttpStateOpV1::CookieDelete { key } => delete(&mut self.cookies, key),
            HttpStateOpV1::CookieClear => {
                self.cookies.clear();
                Ok(())
            }
            HttpStateOpV1::CacheUpsert { key, value } => {
                upsert(&mut self.cache, key.clone(), value.clone())
            }
            HttpStateOpV1::CacheDelete { key } | HttpStateOpV1::CacheInvalidate { key } => {
                delete(&mut self.cache, key)
            }
            HttpStateOpV1::AuthChallengeUpsert { key, value } => {
                upsert(&mut self.auth_challenges, key.clone(), value.clone())
            }
            HttpStateOpV1::AuthChallengeDelete { key } => delete(&mut self.auth_challenges, key),
            HttpStateOpV1::AuthChallengeClear => {
                self.auth_challenges.clear();
                Ok(())
            }
            HttpStateOpV1::DnsUpsert { key, value } => {
                upsert(&mut self.dns, key.clone(), value.clone())
            }
            HttpStateOpV1::DnsDelete { key } => delete(&mut self.dns, key),
            HttpStateOpV1::DnsClear => {
                self.dns.clear();
                Ok(())
            }
            HttpStateOpV1::HeaderReplace { key, value } => {
                let first = self
                    .headers
                    .iter()
                    .position(|(existing, _)| existing == key)
                    .unwrap_or(self.headers.len());
                self.headers.retain(|(existing, _)| existing != key);
                let index = first.min(self.headers.len());
                self.headers.insert(index, (key.clone(), value.clone()));
                Ok(())
            }
            HttpStateOpV1::HeaderAppend { key, value } => {
                self.headers.push((key.clone(), value.clone()));
                Ok(())
            }
            HttpStateOpV1::HeaderRemove { key } => delete(&mut self.headers, key),
            HttpStateOpV1::ConnectionObserve { key, value } => {
                upsert(&mut self.connections, key.clone(), value.clone())
            }
            HttpStateOpV1::ConnectionForget { key } => delete(&mut self.connections, key),
        }
    }
}

fn upsert<K: Eq, V>(
    entries: &mut Vec<(K, V)>,
    key: K,
    value: V,
) -> Result<(), ProtocolDomainError> {
    if let Some(existing) = entries.iter_mut().find(|(existing, _)| *existing == key) {
        existing.1 = value;
    } else {
        entries.push((key, value));
    }
    Ok(())
}

fn delete<K: Eq, V>(entries: &mut Vec<(K, V)>, key: &K) -> Result<(), ProtocolDomainError> {
    entries.retain(|(existing, _)| existing != key);
    Ok(())
}

fn append_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn append_entries<K>(
    output: &mut Vec<u8>,
    tag: u8,
    entries: &[(K, StateValueV1)],
    mut append_key: impl FnMut(&mut Vec<u8>, &K),
) {
    output.push(tag);
    append_u64(output, entries.len() as u64);
    for (key, value) in entries {
        let start = output.len();
        append_key(output, key);
        append_u64(output, value.order);
        match &value.value {
            Presence::Absent => output.push(0),
            Presence::Present(observation) => {
                output.push(1);
                append_observation(output, observation);
            }
        }
        let encoded = output.len().saturating_sub(start);
        let bytes = output[start..].to_vec();
        output.truncate(start);
        append_u64(output, encoded as u64);
        output.extend_from_slice(&bytes);
    }
}

fn append_ascii(output: &mut Vec<u8>, value: &BoundedAscii) {
    append_bytes(output, value.as_str().as_bytes());
}

fn append_header_key(output: &mut Vec<u8>, key: &HeaderKeyV1) {
    append_observation(output, &key.name);
}

fn append_bytes(output: &mut Vec<u8>, value: &[u8]) {
    append_u64(output, value.len() as u64);
    output.extend_from_slice(value);
}

fn append_observation(output: &mut Vec<u8>, value: &ObservationValue) {
    match value {
        ObservationValue::Public(bytes) => {
            output.push(0);
            append_bytes(output, bytes.as_slice());
        }
        ObservationValue::Sensitive { length, reason } => {
            output.push(1);
            output.push(*reason as u8);
            append_u64(output, *length);
        }
        ObservationValue::SecretReference {
            provider_identity,
            purpose,
            length,
        } => {
            output.push(2);
            append_ascii(output, provider_identity);
            append_ascii(output, purpose);
            append_u64(output, *length);
        }
    }
}

/// Compile-time parser ceilings from the `http.parser-limits/1` capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParserHardLimitsV1 {
    pub request_target_bytes: u64,
    pub authority_bytes: u64,
    pub status_line_bytes: u64,
    pub reason_bytes: u64,
    pub header_fields: u64,
    pub header_name_bytes: u64,
    pub header_value_bytes: u64,
    pub header_aggregate_bytes: u64,
    pub informational_responses: u64,
    pub informational_aggregate_bytes: u64,
    pub trailer_fields: u64,
    pub trailer_name_bytes: u64,
    pub trailer_value_bytes: u64,
    pub trailer_aggregate_bytes: u64,
    pub chunk_line_bytes: u64,
    pub chunk_count: u64,
    pub chunk_extensions: u64,
    pub chunk_extension_bytes_per_chunk: u64,
    pub chunk_extension_aggregate_bytes: u64,
    pub wire_request_bytes: u64,
    pub wire_response_bytes: u64,
    pub content_length: u64,
    pub compressed_input_bytes: u64,
    pub decoded_response_bytes: u64,
    pub decompression_ratio: u64,
    pub codec_state_bytes: u64,
    pub urlencoded_fields: u64,
    pub urlencoded_aggregate_bytes: u64,
    pub multipart_parts: u64,
    pub multipart_boundary_bytes: u64,
    pub multipart_headers_bytes_per_part: u64,
    pub multipart_body_bytes_per_part: u64,
    pub redirects: u64,
    pub redirect_retained_bytes: u64,
    pub embedded_candidates: u64,
    pub embedded_depth: u64,
    pub embedded_concurrency: u64,
    pub embedded_retained_bytes: u64,
    pub trace_records: u64,
    pub trace_aggregate_bytes: u64,
    pub diagnostic_count: u64,
    pub diagnostic_text_bytes: u64,
    pub diagnostic_aggregate_bytes: u64,
}

impl ParserHardLimitsV1 {
    #[must_use]
    pub const fn hard() -> Self {
        Self {
            request_target_bytes: 64 * 1024,
            authority_bytes: 8 * 1024,
            status_line_bytes: 8 * 1024,
            reason_bytes: 4 * 1024,
            header_fields: 1_024,
            header_name_bytes: 8 * 1024,
            header_value_bytes: 64 * 1024,
            header_aggregate_bytes: 1024 * 1024,
            informational_responses: 32,
            informational_aggregate_bytes: 256 * 1024,
            trailer_fields: 256,
            trailer_name_bytes: 8 * 1024,
            trailer_value_bytes: 64 * 1024,
            trailer_aggregate_bytes: 256 * 1024,
            chunk_line_bytes: 8 * 1024,
            chunk_count: 16_777_216,
            chunk_extensions: 128,
            chunk_extension_bytes_per_chunk: 8 * 1024,
            chunk_extension_aggregate_bytes: 64 * 1024,
            wire_request_bytes: 64 * 1024 * 1024,
            wire_response_bytes: 256 * 1024 * 1024,
            content_length: 256 * 1024 * 1024,
            compressed_input_bytes: 256 * 1024 * 1024,
            decoded_response_bytes: 512 * 1024 * 1024,
            decompression_ratio: 1_000,
            codec_state_bytes: 1024 * 1024,
            urlencoded_fields: 4_096,
            urlencoded_aggregate_bytes: 1024 * 1024,
            multipart_parts: 1_024,
            multipart_boundary_bytes: 256,
            multipart_headers_bytes_per_part: 256 * 1024,
            multipart_body_bytes_per_part: 256 * 1024 * 1024,
            redirects: 64,
            redirect_retained_bytes: 64 * 1024 * 1024,
            embedded_candidates: 4_096,
            embedded_depth: 32,
            embedded_concurrency: 256,
            embedded_retained_bytes: 512 * 1024 * 1024,
            trace_records: 16_384,
            trace_aggregate_bytes: 4 * 1024 * 1024,
            diagnostic_count: 64,
            diagnostic_text_bytes: 4 * 1024,
            diagnostic_aggregate_bytes: 64 * 1024,
        }
    }

    #[must_use]
    pub const fn hard_table() -> Self {
        Self::hard()
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        parser_limits_digest("http.parser-limits/1", parser_hard_values(self))
    }

    pub fn schema_identity() -> Result<CapabilityIdentityV1, ProtocolDomainError> {
        CapabilityIdentityV1::new(
            PARSER_LIMITS_SCHEMA_ID,
            NonZeroU32::MIN,
            sha256(b"http.parser-limits/1\0"),
        )
    }
}

/// Active parser limits.  Every field is checked against
/// [`ParserHardLimitsV1::hard`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParserLimitsV1 {
    pub request_target_bytes: u64,
    pub authority_bytes: u64,
    pub status_line_bytes: u64,
    pub reason_bytes: u64,
    pub header_fields: u64,
    pub header_name_bytes: u64,
    pub header_value_bytes: u64,
    pub header_aggregate_bytes: u64,
    pub informational_responses: u64,
    pub informational_aggregate_bytes: u64,
    pub trailer_fields: u64,
    pub trailer_name_bytes: u64,
    pub trailer_value_bytes: u64,
    pub trailer_aggregate_bytes: u64,
    pub chunk_line_bytes: u64,
    pub chunk_count: u64,
    pub chunk_extensions: u64,
    pub chunk_extension_bytes_per_chunk: u64,
    pub chunk_extension_aggregate_bytes: u64,
    pub wire_request_bytes: u64,
    pub wire_response_bytes: u64,
    pub content_length: u64,
    pub compressed_input_bytes: u64,
    pub decoded_response_bytes: u64,
    pub decompression_ratio: u64,
    pub codec_state_bytes: u64,
    pub urlencoded_fields: u64,
    pub urlencoded_aggregate_bytes: u64,
    pub multipart_parts: u64,
    pub multipart_boundary_bytes: u64,
    pub multipart_headers_bytes_per_part: u64,
    pub multipart_body_bytes_per_part: u64,
    pub redirects: u64,
    pub redirect_retained_bytes: u64,
    pub embedded_candidates: u64,
    pub embedded_depth: u64,
    pub embedded_concurrency: u64,
    pub embedded_retained_bytes: u64,
    pub trace_records: u64,
    pub trace_aggregate_bytes: u64,
    pub diagnostic_count: u64,
    pub diagnostic_text_bytes: u64,
    pub diagnostic_aggregate_bytes: u64,
}

impl Default for ParserLimitsV1 {
    fn default() -> Self {
        Self {
            request_target_bytes: 16 * 1024,
            authority_bytes: 4 * 1024,
            status_line_bytes: 4 * 1024,
            reason_bytes: 1024,
            header_fields: 128,
            header_name_bytes: 1024,
            header_value_bytes: 16 * 1024,
            header_aggregate_bytes: 256 * 1024,
            informational_responses: 8,
            informational_aggregate_bytes: 64 * 1024,
            trailer_fields: 64,
            trailer_name_bytes: 1024,
            trailer_value_bytes: 16 * 1024,
            trailer_aggregate_bytes: 64 * 1024,
            chunk_line_bytes: 2 * 1024,
            chunk_count: 1_000_000,
            chunk_extensions: 32,
            chunk_extension_bytes_per_chunk: 2 * 1024,
            chunk_extension_aggregate_bytes: 16 * 1024,
            wire_request_bytes: 16 * 1024 * 1024,
            wire_response_bytes: 64 * 1024 * 1024,
            content_length: 64 * 1024 * 1024,
            compressed_input_bytes: 64 * 1024 * 1024,
            decoded_response_bytes: 128 * 1024 * 1024,
            decompression_ratio: 100,
            codec_state_bytes: 256 * 1024,
            urlencoded_fields: 512,
            urlencoded_aggregate_bytes: 256 * 1024,
            multipart_parts: 128,
            multipart_boundary_bytes: 128,
            multipart_headers_bytes_per_part: 64 * 1024,
            multipart_body_bytes_per_part: 16 * 1024 * 1024,
            redirects: 16,
            redirect_retained_bytes: 8 * 1024 * 1024,
            embedded_candidates: 1_024,
            embedded_depth: 16,
            embedded_concurrency: 64,
            embedded_retained_bytes: 128 * 1024 * 1024,
            trace_records: 4_096,
            trace_aggregate_bytes: 1024 * 1024,
            diagnostic_count: 32,
            diagnostic_text_bytes: 2 * 1024,
            diagnostic_aggregate_bytes: 32 * 1024,
        }
    }
}

impl ParserLimitsV1 {
    #[must_use]
    pub const fn hard() -> ParserHardLimitsV1 {
        ParserHardLimitsV1::hard()
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        parser_limits_digest("http.parser-limits/1", parser_active_values(self))
    }

    pub fn validate(&self) -> Result<(), ProtocolDomainError> {
        let hard = ParserHardLimitsV1::hard();
        let active = [
            (
                "request-target",
                self.request_target_bytes,
                hard.request_target_bytes,
            ),
            ("authority", self.authority_bytes, hard.authority_bytes),
            (
                "status-line",
                self.status_line_bytes,
                hard.status_line_bytes,
            ),
            ("reason", self.reason_bytes, hard.reason_bytes),
            ("header-count", self.header_fields, hard.header_fields),
            (
                "header-name",
                self.header_name_bytes,
                hard.header_name_bytes,
            ),
            (
                "header-value",
                self.header_value_bytes,
                hard.header_value_bytes,
            ),
            (
                "header-aggregate",
                self.header_aggregate_bytes,
                hard.header_aggregate_bytes,
            ),
            (
                "informational-count",
                self.informational_responses,
                hard.informational_responses,
            ),
            (
                "informational-aggregate",
                self.informational_aggregate_bytes,
                hard.informational_aggregate_bytes,
            ),
            ("trailer-count", self.trailer_fields, hard.trailer_fields),
            (
                "trailer-name",
                self.trailer_name_bytes,
                hard.trailer_name_bytes,
            ),
            (
                "trailer-value",
                self.trailer_value_bytes,
                hard.trailer_value_bytes,
            ),
            (
                "trailer-aggregate",
                self.trailer_aggregate_bytes,
                hard.trailer_aggregate_bytes,
            ),
            ("chunk-line", self.chunk_line_bytes, hard.chunk_line_bytes),
            ("chunk-count", self.chunk_count, hard.chunk_count),
            (
                "chunk-extension-count",
                self.chunk_extensions,
                hard.chunk_extensions,
            ),
            (
                "chunk-extension-bytes-per-chunk",
                self.chunk_extension_bytes_per_chunk,
                hard.chunk_extension_bytes_per_chunk,
            ),
            (
                "chunk-extension-aggregate",
                self.chunk_extension_aggregate_bytes,
                hard.chunk_extension_aggregate_bytes,
            ),
            (
                "wire-request-body",
                self.wire_request_bytes,
                hard.wire_request_bytes,
            ),
            (
                "wire-response-body",
                self.wire_response_bytes,
                hard.wire_response_bytes,
            ),
            ("content-length", self.content_length, hard.content_length),
            (
                "compressed-input",
                self.compressed_input_bytes,
                hard.compressed_input_bytes,
            ),
            (
                "decoded-output",
                self.decoded_response_bytes,
                hard.decoded_response_bytes,
            ),
            (
                "expansion-ratio",
                self.decompression_ratio,
                hard.decompression_ratio,
            ),
            (
                "codec-state",
                self.codec_state_bytes,
                hard.codec_state_bytes,
            ),
            (
                "url-field-count",
                self.urlencoded_fields,
                hard.urlencoded_fields,
            ),
            (
                "url-field-bytes",
                self.urlencoded_aggregate_bytes,
                hard.urlencoded_aggregate_bytes,
            ),
            (
                "multipart-part-count",
                self.multipart_parts,
                hard.multipart_parts,
            ),
            (
                "multipart-boundary",
                self.multipart_boundary_bytes,
                hard.multipart_boundary_bytes,
            ),
            (
                "multipart-part-headers",
                self.multipart_headers_bytes_per_part,
                hard.multipart_headers_bytes_per_part,
            ),
            (
                "multipart-part-body",
                self.multipart_body_bytes_per_part,
                hard.multipart_body_bytes_per_part,
            ),
            ("redirect-count", self.redirects, hard.redirects),
            (
                "redirect-retained",
                self.redirect_retained_bytes,
                hard.redirect_retained_bytes,
            ),
            (
                "embedded-candidate-count",
                self.embedded_candidates,
                hard.embedded_candidates,
            ),
            ("embedded-depth", self.embedded_depth, hard.embedded_depth),
            (
                "embedded-concurrency",
                self.embedded_concurrency,
                hard.embedded_concurrency,
            ),
            (
                "embedded-retained",
                self.embedded_retained_bytes,
                hard.embedded_retained_bytes,
            ),
            ("trace-count", self.trace_records, hard.trace_records),
            (
                "trace-bytes",
                self.trace_aggregate_bytes,
                hard.trace_aggregate_bytes,
            ),
            (
                "diagnostic-count",
                self.diagnostic_count,
                hard.diagnostic_count,
            ),
            (
                "diagnostic-text",
                self.diagnostic_text_bytes,
                hard.diagnostic_text_bytes,
            ),
            (
                "diagnostic-aggregate",
                self.diagnostic_aggregate_bytes,
                hard.diagnostic_aggregate_bytes,
            ),
        ];
        for (name, value, maximum) in active {
            if value == 0 || value > maximum {
                return Err(ProtocolDomainError::ParserLimitsInvalid(name));
            }
        }
        if self.content_length > self.wire_response_bytes {
            return Err(ProtocolDomainError::ParserLimitsInvalid("content-length"));
        }
        if self.compressed_input_bytes > self.wire_response_bytes {
            return Err(ProtocolDomainError::ParserLimitsInvalid("compressed-input"));
        }
        Ok(())
    }
}

fn parser_limits_digest<const N: usize>(domain: &str, values: [u64; N]) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(domain.len() + N * 8);
    encoded.extend_from_slice(domain.as_bytes());
    encoded.push(0);
    for value in values {
        encoded.extend_from_slice(&value.to_be_bytes());
    }
    sha256(&encoded)
}

fn parser_hard_values(value: &ParserHardLimitsV1) -> [u64; 43] {
    [
        value.request_target_bytes,
        value.authority_bytes,
        value.status_line_bytes,
        value.reason_bytes,
        value.header_fields,
        value.header_name_bytes,
        value.header_value_bytes,
        value.header_aggregate_bytes,
        value.informational_responses,
        value.informational_aggregate_bytes,
        value.trailer_fields,
        value.trailer_name_bytes,
        value.trailer_value_bytes,
        value.trailer_aggregate_bytes,
        value.chunk_line_bytes,
        value.chunk_count,
        value.chunk_extensions,
        value.chunk_extension_bytes_per_chunk,
        value.chunk_extension_aggregate_bytes,
        value.wire_request_bytes,
        value.wire_response_bytes,
        value.content_length,
        value.compressed_input_bytes,
        value.decoded_response_bytes,
        value.decompression_ratio,
        value.codec_state_bytes,
        value.urlencoded_fields,
        value.urlencoded_aggregate_bytes,
        value.multipart_parts,
        value.multipart_boundary_bytes,
        value.multipart_headers_bytes_per_part,
        value.multipart_body_bytes_per_part,
        value.redirects,
        value.redirect_retained_bytes,
        value.embedded_candidates,
        value.embedded_depth,
        value.embedded_concurrency,
        value.embedded_retained_bytes,
        value.trace_records,
        value.trace_aggregate_bytes,
        value.diagnostic_count,
        value.diagnostic_text_bytes,
        value.diagnostic_aggregate_bytes,
    ]
}

fn parser_active_values(value: &ParserLimitsV1) -> [u64; 43] {
    [
        value.request_target_bytes,
        value.authority_bytes,
        value.status_line_bytes,
        value.reason_bytes,
        value.header_fields,
        value.header_name_bytes,
        value.header_value_bytes,
        value.header_aggregate_bytes,
        value.informational_responses,
        value.informational_aggregate_bytes,
        value.trailer_fields,
        value.trailer_name_bytes,
        value.trailer_value_bytes,
        value.trailer_aggregate_bytes,
        value.chunk_line_bytes,
        value.chunk_count,
        value.chunk_extensions,
        value.chunk_extension_bytes_per_chunk,
        value.chunk_extension_aggregate_bytes,
        value.wire_request_bytes,
        value.wire_response_bytes,
        value.content_length,
        value.compressed_input_bytes,
        value.decoded_response_bytes,
        value.decompression_ratio,
        value.codec_state_bytes,
        value.urlencoded_fields,
        value.urlencoded_aggregate_bytes,
        value.multipart_parts,
        value.multipart_boundary_bytes,
        value.multipart_headers_bytes_per_part,
        value.multipart_body_bytes_per_part,
        value.redirects,
        value.redirect_retained_bytes,
        value.embedded_candidates,
        value.embedded_depth,
        value.embedded_concurrency,
        value.embedded_retained_bytes,
        value.trace_records,
        value.trace_aggregate_bytes,
        value.diagnostic_count,
        value.diagnostic_text_bytes,
        value.diagnostic_aggregate_bytes,
    ]
}

/// Returns the normative hard-limit table.
#[must_use]
pub const fn parser_limit_hard_table() -> ParserHardLimitsV1 {
    ParserHardLimitsV1::hard()
}

/// Compatibility aliases used by parser adapters.
pub type ParserHardLimits = ParserHardLimitsV1;
/// Compatibility alias used by parser adapters.
pub type ParserLimits = ParserLimitsV1;

pub type BodyState = ResponseBodyState;
pub type BodyLease<'a> = ResponseLease<'a>;
pub type AsyncHttpTransport = dyn AsyncTransport;
pub type AttemptRecord = AttemptRecordV1;
pub type ErrorContext = ErrorContextV1;
pub type HttpUserState = HttpUserStateV1;
pub type HttpStateDelta = HttpStateDeltaV1;
pub type HttpStateOperation = HttpStateOpV1;
pub type HttpTlsVersion = AttemptTlsVersion;
pub type CapabilityIdentity = CapabilityIdentityV1;
pub type SamplerIdentity = SamplerIdentityV1;
pub type SourceNode = SourceNodeV1;
pub type PlanPath = PlanPathV1;
pub type Diagnostic = DiagnosticV1;
pub type StateOperation = HttpStateOpV1;

// Small dependency-free SHA-256 implementation used for public observation
// and aggregate-state digests.  It accepts only already-bounded byte slices.
fn sha256(input: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];
    let mut state: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(input.len().saturating_add(72));
    padded.extend_from_slice(input);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    for block in padded.chunks_exact(64) {
        let mut words = [0u32; 64];
        for (index, word) in words.iter_mut().take(16).enumerate() {
            let offset = index * 4;
            *word = u32::from_be_bytes([
                block[offset],
                block[offset + 1],
                block[offset + 2],
                block[offset + 3],
            ]);
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
            state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
        );
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(choice)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(majority);
            (h, g, f, e, d, c, b, a) = (
                g,
                f,
                e,
                d.wrapping_add(temp1),
                c,
                b,
                a,
                temp1.wrapping_add(temp2),
            );
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }
    let mut output = [0u8; 32];
    for (index, word) in state.iter().enumerate() {
        output[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    output
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "tests use expect at assertion boundaries for fixed in-process fixtures"
    )]

    use super::*;
    use std::time::Duration;

    fn ascii(value: &str) -> BoundedAscii {
        BoundedAscii::new(value).expect("test identifier")
    }

    fn public(value: &[u8]) -> ObservationValue {
        ObservationValue::public(value.to_vec()).expect("test public bytes")
    }

    fn cookie_key() -> CookieKeyV1 {
        CookieKeyV1 {
            name: ascii("sid"),
            scope: ascii("example.test"),
        }
    }

    fn state_value(order: u64, bytes: &[u8]) -> StateValueV1 {
        StateValueV1::new(order, Presence::Present(public(bytes))).expect("test state value")
    }

    #[test]
    fn body_state_enforces_empty_concurrent_terminal_and_drop_paths() {
        let mut body = ResponseBodyState::default();
        assert_eq!(body.begin_read(0), Err(BodyStateError::EmptyBuffer));
        body.begin_read(4).expect("start read");
        assert_eq!(body.begin_read(4), Err(BodyStateError::ConcurrentRead));
        assert_eq!(body.finish_data(5), Err(BodyStateError::InvalidWrite));
        body.abort();
        assert_eq!(body.begin_read(4), Err(BodyStateError::Aborted));

        let mut body = ResponseBodyState::default();
        {
            let pending = body.begin_read_guard(4).expect("guard");
            drop(pending);
        }
        assert_eq!(body.state(), BodyLeaseState::Cancelled);

        let mut body = ResponseBodyState::default();
        body.begin_read(1).expect("start read");
        let end = body
            .finish_end(Presence::Present(TrailerCollection::default()))
            .expect("end");
        assert!(matches!(end, ReadChunk::End { .. }));
        assert_eq!(body.begin_read(1), Err(BodyStateError::AfterEnd));
    }

    #[test]
    fn dropping_pending_async_read_aborts_body_and_lease() {
        struct PendingBody;

        impl AsyncResponseBody for PendingBody {
            fn read_chunk<'a>(
                &'a mut self,
                _destination: &'a mut [u8],
                _budget: &'a OperationBudget,
                _cancellation: &'a dyn Cancellation,
            ) -> Pin<Box<dyn Future<Output = Result<ReadChunk, TransportError>> + Send + 'a>>
            {
                Box::pin(std::future::pending())
            }
        }

        let budget =
            OperationBudget::new(ClockReading::new(0, Duration::ZERO), Duration::from_secs(1))
                .expect("budget");
        let cancellation = AtomicBool::new(false);
        let mut body = ResponseLeaseBody::new(Box::new(PendingBody), ResponseLease::new());
        let mut destination = [0_u8; 4];
        let mut pending = body.read_chunk(&mut destination, &budget, &cancellation);
        let waker = std::task::Waker::noop();
        let mut context = std::task::Context::from_waker(waker);
        assert!(matches!(pending.as_mut().poll(&mut context), Poll::Pending));
        drop(pending);

        let mut next = body.read_chunk(&mut destination, &budget, &cancellation);
        assert!(matches!(
            next.as_mut().poll(&mut context),
            Poll::Ready(Err(TransportError::Adapter { code, .. }))
                if code == "http.body.aborted"
        ));
    }

    #[test]
    fn lease_release_is_idempotent_and_drop_releases_once() {
        let mut lease = ResponseLease::new();
        lease.release();
        lease.abort();
        assert_eq!(lease.release_count(), 1);
        assert!(lease.is_released());
        let count = {
            let mut lease = ResponseLease::new();
            lease.release();
            lease.release_count()
        };
        assert_eq!(count, 1);
    }

    #[test]
    fn operation_budget_handoff_rounds_and_clamps_without_extension() {
        let start = ClockReading::new(0, Duration::from_nanos(10));
        let budget = OperationBudget::new(start, Duration::from_nanos(20)).expect("budget");
        assert_eq!(
            budget
                .remaining(ClockReading::new(0, Duration::from_nanos(15)))
                .expect("remaining"),
            Duration::from_nanos(15)
        );
        let grant = budget
            .handoff(
                ClockReading::new(0, Duration::from_nanos(15)),
                Duration::from_nanos(4),
                Duration::from_nanos(7),
            )
            .expect("handoff");
        assert_eq!(grant.grant_ns.get(), 11);
        assert_eq!(grant.reservation_ns, 4);
        assert_eq!(grant.receiver_cap_ns.get(), 7);
        assert_eq!(grant.grant_ordinal.get(), 1);
        assert!(matches!(
            budget.handoff(
                ClockReading::new(0, Duration::from_nanos(15)),
                Duration::from_nanos(1),
                Duration::from_nanos(1),
            ),
            Err(ProtocolDomainError::BudgetExpired)
        ));
        let received =
            OperationBudget::from_handoff(ClockReading::new(0, Duration::from_nanos(100)), grant)
                .expect("receiver budget");
        assert_eq!(
            received
                .remaining(ClockReading::new(0, Duration::from_nanos(100)))
                .expect("receiver remaining"),
            Duration::from_nanos(7)
        );
        assert!(matches!(
            budget.remaining(ClockReading::new(0, Duration::from_nanos(9))),
            Err(ProtocolDomainError::ClockInvalid)
        ));
        assert!(matches!(
            OperationBudget::validate_clock_progress(
                ClockReading::new(0, Duration::from_nanos(1)),
                ClockReading::new(0, Duration::from_nanos(1)),
                true,
            ),
            Err(ProtocolDomainError::BudgetClockStalled)
        ));
    }

    #[test]
    fn classification_digest_and_debug_never_retain_sensitive_bytes() {
        let value =
            ObservationValue::sensitive(12, SensitivityReason::Token).expect("sensitive value");
        assert_eq!(value.digest(), Presence::Absent);
        let debug = format!("{value:?}");
        assert!(!debug.contains("secret-token"));
        let public_value = ObservationValue::public(b"abc".to_vec()).expect("public");
        assert_eq!(
            public_value.digest(),
            Presence::Present([
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ])
        );
    }

    #[test]
    fn canonical_attempt_record_redacts_diagnostics_and_sensitive_body_digest() {
        let mut record = AttemptRecordV1::default();
        record.request_observation.body = BodyObservationV1::present(
            ObservationValue::sensitive(12, SensitivityReason::Token).expect("sensitive"),
            Framing::ContentLength,
        )
        .expect("body");
        record.request_observation.framing = Framing::ContentLength;
        record
            .diagnostics
            .push(DiagnosticV1::new("provider", "secret-token").expect("diagnostic"));
        let encoded = record.canonical_bytes().expect("canonical record");
        assert!(
            !encoded
                .windows(b"secret-token".len())
                .any(|window| window == b"secret-token")
        );
        assert!(record.canonical_digest().is_ok());

        record.request_observation.body = BodyObservationV1::present(
            ObservationValue::public(b"public-body".to_vec()).expect("public body"),
            Framing::ContentLength,
        )
        .expect("public body observation");
        let encoded = record.canonical_bytes().expect("public canonical record");
        assert!(
            !encoded
                .windows(b"public-body".len())
                .any(|window| window == b"public-body")
        );
    }

    #[test]
    fn parser_digest_changes_for_any_active_vector_and_includes_all_hard_fields() {
        let hard = ParserHardLimitsV1::hard();
        let active = ParserLimitsV1::default();
        assert_ne!(hard.digest(), active.digest());
        let mut changed = active;
        changed.codec_state_bytes -= 1;
        assert_ne!(active.digest(), changed.digest());
        assert!(active.validate().is_ok());
    }

    #[test]
    fn closed_enums_reject_unknown_wire_values() {
        assert_eq!(
            AttemptOutcome::try_from(6),
            Ok(AttemptOutcome::CapabilityUnavailable)
        );
        assert_eq!(Phase::try_from(14), Ok(Phase::Cleanup));
        assert!(AttemptOutcome::try_from(7).is_err());
        assert!(ProtocolVersion::try_from(99).is_err());
    }

    #[test]
    fn state_cas_is_ordered_atomic_and_conflict_safe() {
        let mut state = HttpUserStateV1::default();
        assert_ne!(state.base_digest(), state.candidate_digest());
        let operations = vec![HttpStateOpV1::CookieUpsert {
            key: cookie_key(),
            value: state_value(1, b"one"),
        }];
        let candidate_digest = state.digest_after(&operations).expect("candidate digest");
        let mut delta = HttpStateDeltaV1::new(state.generation, state.digest(), candidate_digest);
        delta.push(operations[0].clone()).expect("delta operation");
        state.compare_and_swap(&delta).expect("cas");
        assert_eq!(state.generation, 1);
        assert_eq!(state.cookies().len(), 1);
        let digest = state.digest();

        let stale = HttpStateDeltaV1::new(0, delta.base_digest, [0; 32]);
        assert_eq!(
            state.compare_and_swap(&stale),
            Err(ProtocolDomainError::Conflict)
        );
        assert_eq!(state.digest(), digest);
    }

    #[test]
    fn header_replace_keeps_first_order_and_append_keeps_duplicates() {
        let mut state = HttpUserStateV1::default();
        let first = HeaderKeyV1 {
            name: public(b"x-a"),
        };
        let second = HeaderKeyV1 {
            name: public(b"x-b"),
        };
        let operations = vec![
            HttpStateOpV1::HeaderAppend {
                key: first.clone(),
                value: state_value(1, b"a1"),
            },
            HttpStateOpV1::HeaderAppend {
                key: second,
                value: state_value(2, b"b"),
            },
            HttpStateOpV1::HeaderReplace {
                key: first,
                value: state_value(3, b"a2"),
            },
        ];
        let digest = state.digest_after(&operations).expect("digest");
        let mut delta = HttpStateDeltaV1::new(0, state.digest(), digest);
        for operation in operations {
            delta.push(operation).expect("operation");
        }
        state.compare_and_swap(&delta).expect("cas");
        assert_eq!(state.headers().len(), 2);
        assert_eq!(
            state.headers()[0]
                .1
                .value
                .as_ref()
                .and_then(ObservationValue::public_bytes)
                .map(BoundedBytes::as_slice),
            Some(&b"a2"[..])
        );
    }

    #[test]
    fn error_context_ignores_redacted_diagnostics_for_equality() {
        let mut first = ErrorContextV1::new("http.internal-invariant").expect("context");
        let mut second = first.clone();
        first
            .add_diagnostic(DiagnosticV1::new("provider", "secret-token").expect("diagnostic"))
            .expect("diagnostic bound");
        second
            .add_diagnostic(DiagnosticV1::new("provider", "different-secret").expect("diagnostic"))
            .expect("diagnostic bound");
        assert_eq!(first, second);
        assert!(!format!("{first:?}").contains("secret-token"));
    }

    #[test]
    fn parser_hard_table_and_active_validation_are_fail_closed() {
        let hard = ParserHardLimitsV1::hard_table();
        assert_eq!(hard.request_target_bytes, 64 * 1024);
        assert_eq!(hard.header_fields, 1_024);
        let active = ParserLimitsV1::default();
        active.validate().expect("default active limits");
        let mut invalid = active;
        invalid.header_fields = 0;
        assert_eq!(
            invalid.validate().expect_err("zero active limit").code(),
            "http.limit.header-count"
        );
        let mut invalid = active;
        invalid.header_fields = hard.header_fields + 1;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn explicit_unsupported_capabilities_are_typed() {
        assert_eq!(
            UnsupportedCapabilityV1::Jks.error().code(),
            "http.capability.jks-unsupported"
        );
        assert_eq!(
            UnsupportedCapabilityV1::DigestAuthentication.error().code(),
            "http.auth.digest-unsupported"
        );
    }
}
