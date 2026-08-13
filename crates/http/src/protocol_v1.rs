// SPDX-License-Identifier: Apache-2.0
//! Pure HTTP protocol-domain contracts from Decision 0006 revision 4.
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
}

impl ProtocolDomainError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
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
            Self::ParserLimitsInvalid(_) => "http.parser-limits.invalid",
        }
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
    pub route_identity: CapabilityIdentityV1,
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
        for field in &self.fields {
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
    state: LeaseState,
    releases: u8,
    marker: PhantomData<&'a mut ()>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LeaseState {
    Held,
    Released,
    Aborted,
}

impl<'a> ResponseLease<'a> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: LeaseState::Held,
            releases: 0,
            marker: PhantomData,
        }
    }

    pub fn release(&mut self) {
        if self.state == LeaseState::Held {
            self.state = LeaseState::Released;
            self.releases = 1;
        }
    }

    pub fn abort(&mut self) {
        if self.state == LeaseState::Held {
            self.state = LeaseState::Aborted;
            self.releases = 1;
        }
    }

    #[must_use]
    pub const fn is_released(&self) -> bool {
        !matches!(self.state, LeaseState::Held)
    }

    #[must_use]
    pub const fn release_count(&self) -> u8 {
        self.releases
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
            .field("release_count", &self.releases)
            .finish()
    }
}

impl Drop for ResponseLease<'_> {
    fn drop(&mut self) {
        self.release();
    }
}

/// A response whose body and lease are owned by one adapter attempt.
pub struct AsyncResponse<'a> {
    pub head: ResponseHead,
    pub body: Box<dyn AsyncResponseBody + Send + 'a>,
    pub lease: ResponseLease<'a>,
}

impl fmt::Debug for AsyncResponse<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AsyncResponse")
            .field("head", &self.head)
            .field("lease", &self.lease)
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
        if byte_limit == 0 {
            return Err(ProtocolDomainError::InvalidInput("file-capability-limit"));
        }
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
        matches!(self, Self::Bytes(_))
    }
}

/// A single finite local monotonic deadline.
pub struct OperationBudget {
    deadline: Duration,
    last_observed: Mutex<Duration>,
    cancelled: Arc<AtomicBool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetCancellationState {
    Active,
    Cancelled,
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
        })
    }

    pub fn from_clock(clock: &dyn Clock, timeout: Duration) -> Result<Self, ProtocolDomainError> {
        if !clock.can_progress() {
            return Err(ProtocolDomainError::ClockInvalid);
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
        let grant = handoff.grant_duration()?;
        let cap = handoff.receiver_cap_duration()?;
        let timeout = grant.min(cap);
        if timeout.is_zero() {
            return Err(ProtocolDomainError::BudgetExpired);
        }
        Self::new(receiver_now, timeout)
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
        if current.monotonic < previous.monotonic
            || (runnable && current.monotonic == previous.monotonic)
        {
            return Err(ProtocolDomainError::ClockInvalid);
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
            return Err(ProtocolDomainError::ClockInvalid);
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
        let remaining = self.remaining(now)?;
        let phase_deadline = now
            .monotonic
            .checked_add(remaining.min(phase_cap))
            .ok_or(ProtocolDomainError::ClockInvalid)?;
        Ok(Deadline { at: phase_deadline })
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
        if receiver_cap.is_zero() || receiver_cap > MAX_BUDGET_DURATION {
            return Err(ProtocolDomainError::InvalidInput("receiver-cap"));
        }
        let remaining_ns = duration_to_ns_floor(self.remaining(now)?)?;
        let reservation_ns = duration_to_ns_ceil(reservation)?;
        let grant_ns = remaining_ns
            .checked_sub(reservation_ns)
            .ok_or(ProtocolDomainError::BudgetExpired)?;
        if grant_ns == 0 {
            return Err(ProtocolDomainError::BudgetExpired);
        }
        HandoffGrantV1::new(
            grant_ns,
            reservation_ns,
            duration_to_ns_floor(receiver_cap)?,
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

/// A cross-process budget reservation/grant, expressed only in unsigned ns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandoffGrantV1 {
    pub grant_ns: u64,
    pub reservation_ns: u64,
    pub receiver_cap_ns: u64,
}

impl HandoffGrantV1 {
    pub fn new(
        grant_ns: u64,
        reservation_ns: u64,
        receiver_cap_ns: u64,
    ) -> Result<Self, ProtocolDomainError> {
        if grant_ns == 0 || receiver_cap_ns == 0 {
            return Err(ProtocolDomainError::InvalidInput("handoff-zero"));
        }
        let cap = ns_to_duration(receiver_cap_ns)?;
        if cap > MAX_BUDGET_DURATION {
            return Err(ProtocolDomainError::InvalidInput("handoff-cap"));
        }
        Ok(Self {
            grant_ns,
            reservation_ns,
            receiver_cap_ns,
        })
    }

    pub fn grant_duration(self) -> Result<Duration, ProtocolDomainError> {
        ns_to_duration(self.grant_ns)
    }

    pub fn receiver_cap_duration(self) -> Result<Duration, ProtocolDomainError> {
        ns_to_duration(self.receiver_cap_ns)
    }

    pub fn reservation_duration(self) -> Result<Duration, ProtocolDomainError> {
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
    Credentials,
    Cookie,
    Authorization,
    Body,
    Url,
    CertificatePath,
    Other,
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
        Ok(Self::SecretReference {
            provider_identity: BoundedAscii::new(provider_identity)?,
            purpose: BoundedAscii::new(purpose)?,
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
    pub name: BoundedBytes,
    pub value: ObservationValue,
}

impl fmt::Debug for HeaderFieldV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeaderFieldV1")
            .field("name_len", &self.name.len())
            .field("value", &self.value)
            .finish()
    }
}

impl HeaderFieldV1 {
    pub fn new(
        name: impl Into<Vec<u8>>,
        value: ObservationValue,
    ) -> Result<Self, ProtocolDomainError> {
        let name = BoundedBytes::with_limit(name, 8 * 1024)?;
        if name.is_empty() || value.length() > 64 * 1024 {
            return Err(ProtocolDomainError::InvalidInput("header-field"));
        }
        Ok(Self { name, value })
    }

    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.name
            .len()
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
        for field in &self.fields {
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
    Http3,
}

/// Closed entity framing observation.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum Framing {
    #[default]
    None,
    ContentLength,
    Chunked,
    CloseDelimited,
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
    Zstd,
}

/// Closed TLS version observation.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AttemptTlsVersion {
    Tls12,
    Tls13,
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
    ProtocolVersion,
    0 => ProtocolVersion::Http10,
    1 => ProtocolVersion::Http11,
    2 => ProtocolVersion::Http2,
    3 => ProtocolVersion::Http3,
);
closed_u8_enum!(
    Framing,
    0 => Framing::None,
    1 => Framing::ContentLength,
    2 => Framing::Chunked,
    3 => Framing::CloseDelimited,
);
closed_u8_enum!(
    Compression,
    0 => Compression::Identity,
    1 => Compression::Gzip,
    2 => Compression::Deflate,
    3 => Compression::Brotli,
    4 => Compression::Zstd,
);
closed_u8_enum!(
    AttemptTlsVersion,
    0 => AttemptTlsVersion::Tls12,
    1 => AttemptTlsVersion::Tls13,
);

/// A bounded public/sensitive body observation retaining presence and framing.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct BodyObservationV1 {
    pub presence: Presence<ObservationValue>,
    pub framing: Framing,
    pub digest: Presence<[u8; 32]>,
}

impl BodyObservationV1 {
    #[must_use]
    pub fn absent(framing: Framing) -> Self {
        Self {
            presence: Presence::Absent,
            framing,
            digest: Presence::Absent,
        }
    }

    pub fn present(value: ObservationValue, framing: Framing) -> Result<Self, ProtocolDomainError> {
        value.validate()?;
        let digest = value.digest();
        Ok(Self {
            presence: Presence::Present(value),
            framing,
            digest,
        })
    }

    pub fn validate(&self) -> Result<(), ProtocolDomainError> {
        if let Presence::Present(value) = &self.presence {
            value.validate()?;
        }
        Ok(())
    }
}

impl Default for BodyObservationV1 {
    fn default() -> Self {
        Self::absent(Framing::None)
    }
}

/// A request observation in canonical attempt order.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RequestObservationV1 {
    pub method: BoundedAscii,
    pub target: ObservationValue,
    pub headers: HeaderListV1,
    pub body: BodyObservationV1,
}

impl Default for RequestObservationV1 {
    fn default() -> Self {
        Self {
            method: BoundedAscii("GET".to_owned()),
            target: ObservationValue::default(),
            headers: HeaderListV1::default(),
            body: BodyObservationV1::default(),
        }
    }
}

/// An informational response retained before the final response.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct InformationalResponseV1 {
    pub status: u16,
    pub reason: Presence<ObservationValue>,
    pub headers: HeaderListV1,
}

/// A response observation in canonical attempt order.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ResponseObservationV1 {
    pub status: u16,
    pub reason: Presence<ObservationValue>,
    pub protocol: ProtocolVersion,
    pub framing: Framing,
    pub compression: Presence<Compression>,
    pub headers: HeaderListV1,
    pub trailers: Presence<TrailerCollection>,
    pub body: BodyObservationV1,
}

/// A bounded TLS identity observation.  Certificate bytes are represented
/// only by a digest, never by a path or raw certificate.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TlsIdentityV1 {
    pub version: AttemptTlsVersion,
    pub cipher: BoundedAscii,
    pub sni: Presence<ObservationValue>,
    pub alpn: Presence<BoundedAscii>,
    pub certificate_digest: Presence<[u8; 32]>,
}

/// Connection-reuse observation.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ConnectionObservationV1 {
    pub state: ConnectionState,
    pub identity_digest: Presence<[u8; 32]>,
}

impl Default for ConnectionObservationV1 {
    fn default() -> Self {
        Self {
            state: ConnectionState::Unavailable(UnavailableReason::NotObserved),
            identity_digest: Presence::Absent,
        }
    }
}

/// Phase status retained with an unsigned duration.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PhaseStatus {
    Started,
    Completed,
    Failed,
    Cancelled,
    Unavailable(UnavailableReason),
}

/// One phase observation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PhaseObservationV1 {
    pub phase: Phase,
    pub status: PhaseStatus,
    pub elapsed_ns: TimingValue,
}

/// One named byte counter.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ByteCounterV1 {
    pub name: BoundedAscii,
    pub value: CounterValue,
}

/// Budget values included in an attempt record.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct BudgetObservationV1 {
    pub remaining_ns: CounterValue,
    pub grant_ns: CounterValue,
    pub reservation_ns: CounterValue,
    pub receiver_cap_ns: CounterValue,
    pub expired_phase: Presence<Phase>,
}

impl Default for BudgetObservationV1 {
    fn default() -> Self {
        Self {
            remaining_ns: CounterValue::Known(0),
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
        let next = self
            .encoded_bytes
            .checked_add(32 + 8 + node.plan_domain.value.as_str().len())
            .ok_or(ProtocolDomainError::Overflow)?;
        if next > 16 * 1024 {
            return Err(ProtocolDomainError::ResourceLimit("plan-path.bytes"));
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
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct DiagnosticV1 {
    pub code: BoundedAscii,
    pub message: BoundedDiagnosticText,
}

impl fmt::Debug for DiagnosticV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiagnosticV1")
            .field("code", &self.code)
            .field("message", &"<redacted>")
            .finish()
    }
}

impl DiagnosticV1 {
    pub fn new(
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Result<Self, ProtocolDomainError> {
        let message = message.into();
        if message.len() > MAX_DIAGNOSTIC_BYTES {
            return Err(ProtocolDomainError::ResourceLimit("diagnostic.bytes"));
        }
        Ok(Self {
            code: BoundedAscii::new(code)?,
            message: BoundedDiagnosticText::new(message)?,
        })
    }

    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.code.as_str().len() + self.message.as_str().len()
    }
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
    pub stable_error_code: BoundedAscii,
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
            stable_error_code: self.stable_error_code.clone(),
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
            stable_error_code: BoundedAscii("http.unknown".to_owned()),
            diagnostics: Vec::new(),
            diagnostic_bytes: 0,
        }
    }
}

impl ErrorContextV1 {
    pub fn new(stable_error_code: impl Into<String>) -> Result<Self, ProtocolDomainError> {
        Ok(Self {
            source_node: SourceNodeV1::Unknown,
            plan_path: PlanPathV1::default(),
            sampler_identity: SamplerIdentityV1::default(),
            capability_identity: CapabilityIdentityV1::unknown(),
            attempt_index: NonZeroU32::MIN,
            embedded_resource_index: Presence::Absent,
            phase: Phase::Queue,
            stable_error_code: BoundedAscii::new(stable_error_code)?,
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
        self.diagnostics.push(diagnostic);
        Ok(())
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
    pub route_identity: CapabilityIdentityV1,
    pub request_observation: RequestObservationV1,
    pub informational_responses: Vec<InformationalResponseV1>,
    pub response_observation: Presence<ResponseObservationV1>,
    pub proxy_tls_identity: Presence<TlsIdentityV1>,
    pub origin_tls_identity: Presence<TlsIdentityV1>,
    pub connection_observation: ConnectionObservationV1,
    pub phase_observations: Vec<PhaseObservationV1>,
    pub byte_counters: Vec<ByteCounterV1>,
    pub budget_observation: BudgetObservationV1,
    pub outcome: AttemptOutcome,
}

impl Default for AttemptRecordV1 {
    fn default() -> Self {
        Self {
            source_context: ErrorContextV1::default(),
            operation_id: [0; 16],
            attempt_index: NonZeroU32::MIN,
            capability_identity: CapabilityIdentityV1::unknown(),
            route_identity: CapabilityIdentityV1::unknown(),
            request_observation: RequestObservationV1::default(),
            informational_responses: Vec::new(),
            response_observation: Presence::Absent,
            proxy_tls_identity: Presence::Absent,
            origin_tls_identity: Presence::Absent,
            connection_observation: ConnectionObservationV1::default(),
            phase_observations: Vec::new(),
            byte_counters: Vec::new(),
            budget_observation: BudgetObservationV1::default(),
            outcome: AttemptOutcome::CapabilityUnavailable,
        }
    }
}

impl AttemptRecordV1 {
    pub fn validate(&self) -> Result<(), ProtocolDomainError> {
        self.request_observation.target.validate()?;
        self.request_observation.body.validate()?;
        self.source_context.validate()?;
        if self.informational_responses.len() > MAX_INFORMATIONAL_RESPONSES {
            return Err(ProtocolDomainError::ResourceLimit("informational.count"));
        }
        if self.phase_observations.len() > MAX_PHASE_OBSERVATIONS {
            return Err(ProtocolDomainError::ResourceLimit("phases.count"));
        }
        if self.byte_counters.len() > MAX_BYTE_COUNTERS {
            return Err(ProtocolDomainError::ResourceLimit("counters.count"));
        }
        for informational in &self.informational_responses {
            informational
                .reason
                .as_ref()
                .map_or(Ok(()), ObservationValue::validate)?;
            informational.headers.validate()?;
        }
        self.request_observation.headers.validate()?;
        if let Presence::Present(response) = &self.response_observation {
            response
                .reason
                .as_ref()
                .map_or(Ok(()), ObservationValue::validate)?;
            response.body.validate()?;
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
        let bodies = self
            .request_observation
            .body
            .presence
            .as_ref()
            .map_or(0, |value| {
                usize::try_from(value.length()).unwrap_or(usize::MAX)
            })
            + match &self.response_observation {
                Presence::Absent => 0,
                Presence::Present(value) => value.body.presence.as_ref().map_or(0, |body| {
                    usize::try_from(body.length()).unwrap_or(usize::MAX)
                }),
            };
        request
            .saturating_add(response)
            .saturating_add(bodies)
            .saturating_add(self.informational_responses.len() * 32)
            .saturating_add(self.phase_observations.len() * 24)
            .saturating_add(self.byte_counters.len() * 24)
            .saturating_add(self.source_context.diagnostics().len() * 64)
    }
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
    pub name: BoundedAscii,
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
        Ok(Self { order, value })
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
    pub base_generation: u64,
    pub base_digest: [u8; 32],
    pub candidate_digest: [u8; 32],
    pub operations: Vec<HttpStateOpV1>,
}

impl HttpStateDeltaV1 {
    #[must_use]
    pub const fn new(
        base_generation: u64,
        base_digest: [u8; 32],
        candidate_digest: [u8; 32],
    ) -> Self {
        Self {
            base_generation,
            base_digest,
            candidate_digest,
            operations: Vec::new(),
        }
    }

    pub fn push(&mut self, operation: HttpStateOpV1) -> Result<(), ProtocolDomainError> {
        if self.operations.len() >= 1_024 {
            return Err(ProtocolDomainError::ResourceLimit("state-delta.operations"));
        }
        self.operations.push(operation);
        Ok(())
    }

    pub fn validate(&self) -> Result<(), ProtocolDomainError> {
        if self.operations.len() > 1_024 {
            return Err(ProtocolDomainError::ResourceLimit("state-delta.operations"));
        }
        Ok(())
    }
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
        let mut encoded = Vec::new();
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
            append_ascii(output, &key.name);
        });
        append_entries(&mut encoded, 6, &self.connections, |output, key| {
            append_ascii(output, &key.route);
        });
        sha256(&encoded)
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
        if candidate.digest() != delta.candidate_digest {
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
        Ok(self.project(operations)?.digest())
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
        if candidate.digest() != delta.candidate_digest {
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
    pub chunk_extensions: u64,
    pub chunk_extension_aggregate_bytes: u64,
    pub wire_request_bytes: u64,
    pub wire_response_bytes: u64,
    pub decoded_response_bytes: u64,
    pub decompression_ratio: u64,
    pub decompression_absolute_bytes: u64,
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
    pub diagnostic_bytes: u64,
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
            chunk_extensions: 128,
            chunk_extension_aggregate_bytes: 64 * 1024,
            wire_request_bytes: 64 * 1024 * 1024,
            wire_response_bytes: 256 * 1024 * 1024,
            decoded_response_bytes: 512 * 1024 * 1024,
            decompression_ratio: 1_000,
            decompression_absolute_bytes: 512 * 1024 * 1024,
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
            diagnostic_bytes: 4 * 1024,
        }
    }

    #[must_use]
    pub const fn hard_table() -> Self {
        Self::hard()
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
    pub chunk_extensions: u64,
    pub chunk_extension_aggregate_bytes: u64,
    pub wire_request_bytes: u64,
    pub wire_response_bytes: u64,
    pub decoded_response_bytes: u64,
    pub decompression_ratio: u64,
    pub decompression_absolute_bytes: u64,
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
    pub diagnostic_bytes: u64,
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
            chunk_extensions: 32,
            chunk_extension_aggregate_bytes: 16 * 1024,
            wire_request_bytes: 16 * 1024 * 1024,
            wire_response_bytes: 64 * 1024 * 1024,
            decoded_response_bytes: 128 * 1024 * 1024,
            decompression_ratio: 100,
            decompression_absolute_bytes: 128 * 1024 * 1024,
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
            diagnostic_bytes: 2 * 1024,
        }
    }
}

impl ParserLimitsV1 {
    #[must_use]
    pub const fn hard() -> ParserHardLimitsV1 {
        ParserHardLimitsV1::hard()
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
            ("header-fields", self.header_fields, hard.header_fields),
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
                "informational",
                self.informational_responses,
                hard.informational_responses,
            ),
            (
                "informational-aggregate",
                self.informational_aggregate_bytes,
                hard.informational_aggregate_bytes,
            ),
            ("trailer-fields", self.trailer_fields, hard.trailer_fields),
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
            (
                "chunk-extensions",
                self.chunk_extensions,
                hard.chunk_extensions,
            ),
            (
                "chunk-extension-aggregate",
                self.chunk_extension_aggregate_bytes,
                hard.chunk_extension_aggregate_bytes,
            ),
            (
                "wire-request",
                self.wire_request_bytes,
                hard.wire_request_bytes,
            ),
            (
                "wire-response",
                self.wire_response_bytes,
                hard.wire_response_bytes,
            ),
            (
                "decoded-response",
                self.decoded_response_bytes,
                hard.decoded_response_bytes,
            ),
            (
                "decompression-ratio",
                self.decompression_ratio,
                hard.decompression_ratio,
            ),
            (
                "decompression-absolute",
                self.decompression_absolute_bytes,
                hard.decompression_absolute_bytes,
            ),
            (
                "urlencoded-fields",
                self.urlencoded_fields,
                hard.urlencoded_fields,
            ),
            (
                "urlencoded-aggregate",
                self.urlencoded_aggregate_bytes,
                hard.urlencoded_aggregate_bytes,
            ),
            (
                "multipart-parts",
                self.multipart_parts,
                hard.multipart_parts,
            ),
            (
                "multipart-boundary",
                self.multipart_boundary_bytes,
                hard.multipart_boundary_bytes,
            ),
            (
                "multipart-headers",
                self.multipart_headers_bytes_per_part,
                hard.multipart_headers_bytes_per_part,
            ),
            (
                "multipart-body",
                self.multipart_body_bytes_per_part,
                hard.multipart_body_bytes_per_part,
            ),
            ("redirects", self.redirects, hard.redirects),
            (
                "redirect-retained",
                self.redirect_retained_bytes,
                hard.redirect_retained_bytes,
            ),
            (
                "embedded-candidates",
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
            ("trace-records", self.trace_records, hard.trace_records),
            (
                "trace-aggregate",
                self.trace_aggregate_bytes,
                hard.trace_aggregate_bytes,
            ),
            ("diagnostic", self.diagnostic_bytes, hard.diagnostic_bytes),
        ];
        for (name, value, maximum) in active {
            if value == 0 || value > maximum {
                return Err(ProtocolDomainError::ParserLimitsInvalid(name));
            }
        }
        Ok(())
    }
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
        assert_eq!(grant.grant_ns, 11);
        assert_eq!(grant.reservation_ns, 4);
        assert_eq!(grant.receiver_cap_ns, 7);
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
            Err(ProtocolDomainError::ClockInvalid)
        ));
    }

    #[test]
    fn classification_digest_and_debug_never_retain_sensitive_bytes() {
        let value = ObservationValue::sensitive(12, SensitivityReason::Authorization)
            .expect("sensitive value");
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
        let first = HeaderKeyV1 { name: ascii("x-a") };
        let second = HeaderKeyV1 { name: ascii("x-b") };
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
        let mut first = ErrorContextV1::new("http.test.failure").expect("context");
        let mut second = first.clone();
        first
            .add_diagnostic(DiagnosticV1::new("detail", "secret-token").expect("diagnostic"))
            .expect("diagnostic bound");
        second
            .add_diagnostic(DiagnosticV1::new("detail", "different-secret").expect("diagnostic"))
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
            "http.parser-limits.invalid"
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
