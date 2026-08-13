// SPDX-License-Identifier: Apache-2.0
//! An in-memory scripted transport for deterministic protocol tests.
//!
//! This module deliberately does not bind a socket or consult proxy,
//! filesystem, environment, or clock state.  A response is an explicit
//! sequence of data, delay, end, and reset steps.  Delays are values returned
//! to the caller; they never sleep the host thread.  Requests must match the
//! next scripted expectation exactly, including header order and body bytes.
//! Exchange cancellation is explicit and logged.  Dropping an unfinished
//! explicitly owned exchange attempts bounded cancellation;
//! [`FakeTransport::assert_no_leaks`] reports any event-capacity failure that
//! Drop cannot return.

use crate::error::{ErrorCode, StableError};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Bounds enforced by a [`FakeTransport`] script and its exchanges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportLimits {
    /// Maximum number of one-shot scripted requests.
    pub max_script_entries: usize,
    /// Maximum method bytes in one request.
    pub max_method_bytes: usize,
    /// Maximum target/URL bytes in one request.
    pub max_target_bytes: usize,
    /// Maximum request body bytes.
    pub max_request_body_bytes: usize,
    /// Maximum response body bytes across all data steps.
    pub max_response_body_bytes: usize,
    /// Maximum response steps in one exchange.
    pub max_steps: usize,
    /// Maximum retained request/step events.
    pub max_events: usize,
    /// Maximum request headers, including zero-byte headers.
    pub max_request_headers: usize,
    /// Maximum response headers, including zero-byte headers.
    pub max_response_headers: usize,
    /// Maximum header-name bytes.
    pub max_header_name_bytes: usize,
    /// Maximum header-value bytes.
    pub max_header_value_bytes: usize,
    /// Maximum aggregate bytes across one request or response's headers.
    pub max_header_bytes: usize,
    /// Maximum aggregate bytes retained by the complete script.
    pub max_script_bytes: usize,
    /// Maximum bytes retained by one transport event.
    pub max_event_bytes: usize,
    /// Maximum aggregate bytes retained by all transport events.
    pub max_total_event_bytes: usize,
    /// Maximum duration represented by one logical [`TransportStep::Delay`].
    pub max_delay_per_step: Duration,
    /// Maximum aggregate logical delay in one response plan.
    pub max_total_delay: Duration,
}

impl TransportLimits {
    /// Creates explicit finite bounds.
    #[must_use]
    pub const fn new(
        max_script_entries: usize,
        max_request_body_bytes: usize,
        max_response_body_bytes: usize,
        max_steps: usize,
        max_events: usize,
    ) -> Self {
        Self {
            max_script_entries,
            max_method_bytes: 128,
            max_target_bytes: 16 * 1024,
            max_request_body_bytes,
            max_response_body_bytes,
            max_steps,
            max_events,
            max_request_headers: 256,
            max_response_headers: 256,
            max_header_name_bytes: 256,
            max_header_value_bytes: 16 * 1024,
            max_header_bytes: 64 * 1024,
            max_script_bytes: 16 * 1024 * 1024,
            max_event_bytes: 64 * 1024,
            max_total_event_bytes: 16 * 1024 * 1024,
            max_delay_per_step: Duration::from_secs(60 * 60),
            max_total_delay: Duration::from_secs(24 * 60 * 60),
        }
    }

    /// A useful finite default for local protocol fixtures.
    #[must_use]
    pub const fn default_bounded() -> Self {
        Self::new(256, 1024 * 1024, 4 * 1024 * 1024, 4_096, 16_384)
    }

    /// Sets the maximum header-name bytes.
    #[must_use]
    pub const fn with_header_name_limit(mut self, limit: usize) -> Self {
        self.max_header_name_bytes = limit;
        self
    }

    /// Sets the maximum header-value bytes.
    #[must_use]
    pub const fn with_header_value_limit(mut self, limit: usize) -> Self {
        self.max_header_value_bytes = limit;
        self
    }

    /// Sets the maximum number of request headers.
    #[must_use]
    pub const fn with_request_header_limit(mut self, limit: usize) -> Self {
        self.max_request_headers = limit;
        self
    }

    /// Alias emphasizing that the request bound counts headers, not bytes.
    #[must_use]
    pub const fn with_request_header_count_limit(self, limit: usize) -> Self {
        self.with_request_header_limit(limit)
    }

    /// Sets the maximum number of response headers.
    #[must_use]
    pub const fn with_response_header_limit(mut self, limit: usize) -> Self {
        self.max_response_headers = limit;
        self
    }

    /// Alias emphasizing that the response bound counts headers, not bytes.
    #[must_use]
    pub const fn with_response_header_count_limit(self, limit: usize) -> Self {
        self.with_response_header_limit(limit)
    }

    /// Sets the maximum request-method bytes.
    #[must_use]
    pub const fn with_method_limit(mut self, limit: usize) -> Self {
        self.max_method_bytes = limit;
        self
    }

    /// Alias for [`Self::with_method_limit`].
    #[must_use]
    pub const fn with_method_bytes_limit(self, limit: usize) -> Self {
        self.with_method_limit(limit)
    }

    /// Sets the maximum request-target bytes.
    #[must_use]
    pub const fn with_target_limit(mut self, limit: usize) -> Self {
        self.max_target_bytes = limit;
        self
    }

    /// Alias for [`Self::with_target_limit`].
    #[must_use]
    pub const fn with_target_bytes_limit(self, limit: usize) -> Self {
        self.with_target_limit(limit)
    }

    /// Sets the aggregate header-byte bound.
    #[must_use]
    pub const fn with_header_bytes_limit(mut self, limit: usize) -> Self {
        self.max_header_bytes = limit;
        self
    }

    /// Sets the complete script-byte bound.
    #[must_use]
    pub const fn with_script_bytes_limit(mut self, limit: usize) -> Self {
        self.max_script_bytes = limit;
        self
    }

    /// Sets the per-event byte bound.
    #[must_use]
    pub const fn with_event_bytes_limit(mut self, limit: usize) -> Self {
        self.max_event_bytes = limit;
        self
    }

    /// Sets the aggregate retained event-byte bound.
    #[must_use]
    pub const fn with_total_event_bytes_limit(mut self, limit: usize) -> Self {
        self.max_total_event_bytes = limit;
        self
    }

    /// Sets the maximum duration of one logical delay step.
    #[must_use]
    pub const fn with_delay_limit(mut self, limit: Duration) -> Self {
        self.max_delay_per_step = limit;
        self
    }

    /// Alias emphasizing that this is a per-step bound.
    #[must_use]
    pub const fn with_delay_per_step_limit(self, limit: Duration) -> Self {
        self.with_delay_limit(limit)
    }

    /// Sets the maximum aggregate logical delay in one response plan.
    #[must_use]
    pub const fn with_total_delay_limit(mut self, limit: Duration) -> Self {
        self.max_total_delay = limit;
        self
    }

    /// Alias emphasizing that this is an aggregate response bound.
    #[must_use]
    pub const fn with_delay_total_limit(self, limit: Duration) -> Self {
        self.with_total_delay_limit(limit)
    }
}

impl Default for TransportLimits {
    fn default() -> Self {
        Self::default_bounded()
    }
}

/// A request or response header with order and duplicate names preserved.
#[derive(Clone, PartialEq, Eq)]
pub struct TransportHeader {
    /// Wire spelling of the header name.
    pub name: String,
    /// Wire bytes of the header value.
    pub value: Vec<u8>,
}

/// A redacted header projection suitable for diagnostics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportHeaderDiagnostic {
    /// Header name, retained for routing/debug correlation.
    pub name: String,
    /// Number of raw value bytes.
    pub value_bytes: usize,
}

impl TransportHeader {
    /// Returns an explicit redacted diagnostic projection.
    #[must_use]
    pub fn redacted(&self) -> TransportHeaderDiagnostic {
        TransportHeaderDiagnostic {
            name: self.name.clone(),
            value_bytes: self.value.len(),
        }
    }
}

impl fmt::Debug for TransportHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.redacted().fmt(formatter)
    }
}

/// Which side of a transport exchange supplied a header list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportHeaderDirection {
    /// Request headers.
    Request,
    /// Response headers.
    Response,
}

impl TransportHeader {
    /// Creates a header without applying transport limits.
    #[must_use]
    pub fn new(name: impl Into<String>, value: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    /// Returns the aggregate bytes represented by this header name and value.
    pub fn wire_bytes(&self) -> Result<usize, TransportError> {
        self.name
            .len()
            .checked_add(self.value.len())
            .ok_or(TransportError::InvalidSize)
    }
}

/// An exact in-memory request fixture.
#[derive(Clone, PartialEq, Eq)]
pub struct TransportRequest {
    /// Wire method spelling.
    pub method: String,
    /// Exact target/URL spelling.
    pub target: String,
    /// Ordered headers, including duplicates.
    pub headers: Vec<TransportHeader>,
    /// Request body bytes.
    pub body: Vec<u8>,
}

/// A redacted request projection.  Header values and body bytes are never
/// included; callers that need raw data must use the request fields or
/// [`TransportRequest::wire_bytes`] explicitly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportRequestDiagnostic {
    /// Wire method spelling.
    pub method: String,
    /// Target byte length; the target itself may contain credentials/query
    /// data and is therefore not retained in this projection.
    pub target_bytes: usize,
    /// Ordered redacted headers.
    pub headers: Vec<TransportHeaderDiagnostic>,
    /// Request body byte length.
    pub body_bytes: usize,
}

impl TransportRequest {
    /// Returns an explicit redacted diagnostic projection.
    #[must_use]
    pub fn redacted(&self) -> TransportRequestDiagnostic {
        TransportRequestDiagnostic {
            method: self.method.clone(),
            target_bytes: self.target.len(),
            headers: self.headers.iter().map(TransportHeader::redacted).collect(),
            body_bytes: self.body.len(),
        }
    }

    /// Creates an empty request.
    #[must_use]
    pub fn new(method: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            target: target.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Adds one ordered header and returns the request for builder-style use.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<Vec<u8>>) -> Self {
        self.headers.push(TransportHeader::new(name, value));
        self
    }

    /// Alias for [`Self::header`].
    #[must_use]
    pub fn with_header(self, name: impl Into<String>, value: impl Into<Vec<u8>>) -> Self {
        self.header(name, value)
    }

    /// Sets the request body.
    #[must_use]
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// Alias for [`Self::body`].
    #[must_use]
    pub fn with_body(self, body: impl Into<Vec<u8>>) -> Self {
        self.body(body)
    }

    /// Returns the aggregate request bytes used by script and event bounds.
    pub fn wire_bytes(&self) -> Result<usize, TransportError> {
        let headers = header_bytes(&self.headers)?;
        self.method
            .len()
            .checked_add(self.target.len())
            .and_then(|bytes| bytes.checked_add(headers))
            .and_then(|bytes| bytes.checked_add(self.body.len()))
            .ok_or(TransportError::InvalidSize)
    }
}

impl fmt::Debug for TransportRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.redacted().fmt(formatter)
    }
}

/// One explicit response-stream action.
#[derive(Clone, PartialEq, Eq)]
pub enum TransportStep {
    /// A bounded response-data chunk.
    Data(Vec<u8>),
    /// A logical delay; the caller must advance its own virtual clock.
    Delay(Duration),
    /// End of response body.
    End,
    /// A deterministic connection reset and terminal stream marker.
    Reset {
        /// Optional protocol/platform code associated with the reset.
        code: Option<u16>,
    },
}

impl fmt::Debug for TransportStep {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Data(bytes) => formatter
                .debug_struct("Data")
                .field("byte_len", &bytes.len())
                .finish(),
            Self::Delay(delay) => formatter.debug_tuple("Delay").field(delay).finish(),
            Self::End => formatter.write_str("End"),
            Self::Reset { code } => formatter.debug_struct("Reset").field("code", code).finish(),
        }
    }
}

impl TransportStep {
    /// Returns the number of data bytes in this step.
    #[must_use]
    pub fn data_len(&self) -> usize {
        match self {
            Self::Data(bytes) => bytes.len(),
            Self::Delay(_) | Self::End | Self::Reset { .. } => 0,
        }
    }

    /// Returns the bounded payload bytes represented by this step.
    pub fn wire_bytes(&self) -> usize {
        self.data_len()
    }
}

/// A scripted response, including its explicit stream steps.
#[derive(Clone, PartialEq, Eq)]
pub struct TransportResponsePlan {
    /// Status code delivered before response steps.
    pub status: u16,
    /// Ordered response headers.
    pub headers: Vec<TransportHeader>,
    /// Explicit response stream.
    pub steps: Vec<TransportStep>,
}

/// A redacted response-plan projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportResponsePlanDiagnostic {
    /// Response status.
    pub status: u16,
    /// Ordered redacted response headers.
    pub headers: Vec<TransportHeaderDiagnostic>,
    /// Stream step summaries without data bytes.
    pub steps: Vec<TransportStepDiagnostic>,
}

/// A redacted response-step projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportStepDiagnostic {
    /// Data step represented by its byte length.
    Data {
        /// Number of raw data bytes.
        byte_len: usize,
    },
    /// Logical delay.
    Delay {
        /// Logical duration.
        duration: Duration,
    },
    /// End marker.
    End,
    /// Reset marker.
    Reset {
        /// Optional reset code.
        code: Option<u16>,
    },
}

impl TransportResponsePlan {
    /// Returns an explicit redacted diagnostic projection.
    #[must_use]
    pub fn redacted(&self) -> TransportResponsePlanDiagnostic {
        TransportResponsePlanDiagnostic {
            status: self.status,
            headers: self.headers.iter().map(TransportHeader::redacted).collect(),
            steps: self
                .steps
                .iter()
                .map(|step| match step {
                    TransportStep::Data(bytes) => TransportStepDiagnostic::Data {
                        byte_len: bytes.len(),
                    },
                    TransportStep::Delay(delay) => {
                        TransportStepDiagnostic::Delay { duration: *delay }
                    }
                    TransportStep::End => TransportStepDiagnostic::End,
                    TransportStep::Reset { code } => TransportStepDiagnostic::Reset { code: *code },
                })
                .collect(),
        }
    }

    /// Creates an empty response plan.  Call [`Self::validate`] before use.
    #[must_use]
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            steps: vec![TransportStep::End],
        }
    }

    /// Adds an ordered response header.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<Vec<u8>>) -> Self {
        self.headers.push(TransportHeader::new(name, value));
        self
    }

    /// Replaces the response stream with one data chunk followed by end.
    #[must_use]
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.steps = vec![TransportStep::Data(body.into()), TransportStep::End];
        self
    }

    /// Validates all bounded response fields.
    pub fn validate(&self, limits: TransportLimits) -> Result<(), TransportError> {
        validate_headers(
            &self.headers,
            limits.max_response_headers,
            TransportHeaderDirection::Response,
            limits,
        )?;
        if self.steps.len() > limits.max_steps {
            return Err(TransportError::CapacityExceeded {
                kind: TransportCapacityKind::Steps,
                actual: self.steps.len(),
                limit: limits.max_steps,
            });
        }
        let mut terminal = None;
        let mut total_delay = Duration::ZERO;
        for (position, step) in self.steps.iter().enumerate() {
            if let Some(reset_terminal) = terminal {
                return if reset_terminal {
                    Err(TransportError::UnexpectedAfterReset { position })
                } else {
                    Err(TransportError::UnexpectedEnd { position })
                };
            }
            let event_bytes = step.wire_bytes();
            if event_bytes > limits.max_event_bytes {
                return Err(TransportError::EventTooLarge {
                    actual: event_bytes,
                    limit: limits.max_event_bytes,
                });
            }
            match step {
                TransportStep::End => terminal = Some(false),
                TransportStep::Reset { .. } => terminal = Some(true),
                TransportStep::Data(_) => {}
                TransportStep::Delay(delay) => {
                    if *delay > limits.max_delay_per_step {
                        return Err(TransportError::DelayTooLarge {
                            actual: *delay,
                            limit: limits.max_delay_per_step,
                        });
                    }
                    total_delay = total_delay.checked_add(*delay).ok_or(
                        TransportError::DelayAggregateTooLarge {
                            actual: Duration::MAX,
                            limit: limits.max_total_delay,
                        },
                    )?;
                    if total_delay > limits.max_total_delay {
                        return Err(TransportError::DelayAggregateTooLarge {
                            actual: total_delay,
                            limit: limits.max_total_delay,
                        });
                    }
                }
            }
        }
        if terminal.is_none() {
            return Err(TransportError::MissingEnd);
        }
        let total = self
            .steps
            .iter()
            .map(TransportStep::data_len)
            .try_fold(0_usize, usize::checked_add)
            .ok_or(TransportError::InvalidSize)?;
        if total > limits.max_response_body_bytes {
            return Err(TransportError::BodyTooLarge {
                direction: TransportBodyDirection::Response,
                actual: total,
                limit: limits.max_response_body_bytes,
            });
        }
        Ok(())
    }

    /// Returns aggregate response bytes used by script and event bounds.
    pub fn wire_bytes(&self) -> Result<usize, TransportError> {
        let headers = header_bytes(&self.headers)?;
        self.steps
            .iter()
            .map(TransportStep::wire_bytes)
            .try_fold(headers, usize::checked_add)
            .ok_or(TransportError::InvalidSize)
    }
}

impl fmt::Debug for TransportResponsePlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.redacted().fmt(formatter)
    }
}

/// Builder for a response stream with explicit delay/reset steps.
///
/// The fallible `try_*` methods validate a cloned candidate and return the
/// original builder unchanged when a bound or stream invariant fails.  A
/// builder created with [`Self::with_limits`] also preflights its fluent
/// methods, retaining the first typed failure for [`Self::build`] while
/// leaving the committed response unchanged.  [`Self::new`] keeps the legacy
/// explicit-limits-at-build behavior; use `with_limits` for early preflight.
#[derive(Clone, Debug)]
pub struct TransportResponseBuilder {
    limits: Option<TransportLimits>,
    response: TransportResponsePlan,
    pending_error: Option<TransportError>,
}

impl TransportResponseBuilder {
    /// Starts a response with an empty body.
    #[must_use]
    pub fn new(status: u16) -> Self {
        Self {
            limits: None,
            response: TransportResponsePlan::new(status),
            pending_error: None,
        }
    }

    /// Starts a response with explicit bounds used by fallible builder
    /// operations and [`Self::build_default`].
    #[must_use]
    pub fn with_limits(status: u16, limits: TransportLimits) -> Self {
        Self {
            limits: Some(limits),
            response: TransportResponsePlan::new(status),
            pending_error: None,
        }
    }

    /// Adds an ordered response header, retaining a typed preflight failure.
    #[must_use]
    pub fn header(self, name: impl Into<String>, value: impl Into<Vec<u8>>) -> Self {
        self.apply_candidate(|response| {
            response.headers.push(TransportHeader::new(name, value));
        })
    }

    /// Adds an ordered response header and reports a bound violation
    /// immediately without committing a partial candidate.
    pub fn try_header(
        self,
        name: impl Into<String>,
        value: impl Into<Vec<u8>>,
    ) -> Result<Self, TransportError> {
        self.try_candidate(|response| {
            response.headers.push(TransportHeader::new(name, value));
        })
    }

    /// Replaces the body with one data chunk and an end marker, retaining a
    /// typed preflight failure.
    #[must_use]
    pub fn body(self, body: impl Into<Vec<u8>>) -> Self {
        self.apply_candidate(|response| {
            response.steps = vec![TransportStep::Data(body.into()), TransportStep::End];
        })
    }

    /// Replaces the body and reports a bound violation immediately without
    /// committing a partial candidate.
    pub fn try_body(self, body: impl Into<Vec<u8>>) -> Result<Self, TransportError> {
        self.try_candidate(|response| {
            response.steps = vec![TransportStep::Data(body.into()), TransportStep::End];
        })
    }

    /// Appends a response data chunk before the current end marker, retaining
    /// a typed preflight failure.
    #[must_use]
    pub fn chunk(self, bytes: impl Into<Vec<u8>>) -> Self {
        self.apply_candidate(|response| {
            insert_before_end(&mut response.steps, TransportStep::Data(bytes.into()));
        })
    }

    /// Appends a response data chunk and reports a bound violation
    /// immediately without committing a partial candidate.
    pub fn try_chunk(self, bytes: impl Into<Vec<u8>>) -> Result<Self, TransportError> {
        self.try_candidate(|response| {
            insert_before_end(&mut response.steps, TransportStep::Data(bytes.into()));
        })
    }

    /// Appends a logical delay before the current end marker, retaining a typed
    /// preflight failure.
    #[must_use]
    pub fn delay(self, delay: Duration) -> Self {
        self.apply_candidate(|response| {
            insert_before_end(&mut response.steps, TransportStep::Delay(delay));
        })
    }

    /// Appends a logical delay and reports a bound violation immediately
    /// without committing a partial candidate.
    pub fn try_delay(self, delay: Duration) -> Result<Self, TransportError> {
        self.try_candidate(|response| {
            insert_before_end(&mut response.steps, TransportStep::Delay(delay));
        })
    }

    /// Replaces the implicit end marker with a terminal deterministic reset,
    /// retaining a typed preflight failure.
    #[must_use]
    pub fn reset(self, code: Option<u16>) -> Self {
        self.apply_candidate(|response| {
            if matches!(response.steps.last(), Some(TransportStep::End)) {
                let _ = response.steps.pop();
            }
            response.steps.push(TransportStep::Reset { code });
        })
    }

    /// Replaces the implicit end marker with a reset and reports a bound
    /// violation immediately without committing a partial candidate.
    pub fn try_reset(self, code: Option<u16>) -> Result<Self, TransportError> {
        self.try_candidate(|response| {
            if matches!(response.steps.last(), Some(TransportStep::End)) {
                let _ = response.steps.pop();
            }
            response.steps.push(TransportStep::Reset { code });
        })
    }

    /// Builds and validates the response under explicit limits.
    ///
    /// A failure retained by a fluent builder operation is returned before the
    /// final validation, so no invalid candidate is ever returned.
    pub fn build(self, limits: TransportLimits) -> Result<TransportResponsePlan, TransportError> {
        if let Some(error) = self.pending_error {
            return Err(error);
        }
        self.response.validate(limits)?;
        Ok(self.response)
    }

    /// Builds with the finite default limits.
    pub fn build_default(self) -> Result<TransportResponsePlan, TransportError> {
        let limits = self.limits.unwrap_or_default();
        self.build(limits)
    }

    fn apply_candidate<F>(mut self, update: F) -> Self
    where
        F: FnOnce(&mut TransportResponsePlan),
    {
        if self.pending_error.is_some() {
            return self;
        }
        let mut candidate = self.response.clone();
        update(&mut candidate);
        if let Some(limits) = self.limits {
            match candidate.validate(limits) {
                Ok(()) => self.response = candidate,
                Err(error) => self.pending_error = Some(error),
            }
        } else {
            self.response = candidate;
        }
        self
    }

    fn try_candidate<F>(mut self, update: F) -> Result<Self, TransportError>
    where
        F: FnOnce(&mut TransportResponsePlan),
    {
        if let Some(error) = self.pending_error.clone() {
            return Err(error);
        }
        let mut candidate = self.response.clone();
        update(&mut candidate);
        candidate.validate(self.limits.unwrap_or_default())?;
        self.response = candidate;
        Ok(self)
    }
}

/// Which side of an exchange exceeded a body bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportBodyDirection {
    /// Request data.
    Request,
    /// Response data.
    Response,
}

/// Which transport collection exceeded a count bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportCapacityKind {
    /// Script entries.
    Script,
    /// Response stream steps.
    Steps,
    /// Retained request/step events.
    Events,
    /// Complete script bytes.
    ScriptBytes,
    /// Aggregate retained event bytes.
    EventBytes,
}

/// Errors returned by scripted transport setup and consumption.
#[derive(Clone, PartialEq, Eq)]
pub enum TransportError {
    /// The script has no response left.
    ScriptExhausted {
        /// Number of requests already accepted.
        request_count: usize,
    },
    /// The request differs from the next expected request.
    RequestMismatch {
        /// Zero-based script position.
        position: usize,
        /// Expected request.
        expected: Box<TransportRequest>,
        /// Actual request.
        actual: Box<TransportRequest>,
    },
    /// A request or response body exceeded a limit.
    BodyTooLarge {
        /// Request or response side.
        direction: TransportBodyDirection,
        /// Actual bytes.
        actual: usize,
        /// Configured limit.
        limit: usize,
    },
    /// A script, response, or event collection exceeded a limit.
    CapacityExceeded {
        /// Collection that exceeded its bound.
        kind: TransportCapacityKind,
        /// Actual count.
        actual: usize,
        /// Configured limit.
        limit: usize,
    },
    /// A header exceeded a name/value limit.
    HeaderTooLarge {
        /// Header name or value bytes.
        name_bytes: usize,
        /// Header value bytes.
        value_bytes: usize,
        /// Configured name limit.
        name_limit: usize,
        /// Configured value limit.
        value_limit: usize,
    },
    /// Aggregate header bytes exceeded the configured bound.
    HeaderBytesTooLarge {
        /// Actual aggregate header bytes.
        actual: usize,
        /// Configured aggregate header limit.
        limit: usize,
    },
    /// A request or response exceeded its header-count bound.
    HeaderCountTooLarge {
        /// Request or response side.
        direction: TransportHeaderDirection,
        /// Actual header count.
        actual: usize,
        /// Configured header-count limit.
        limit: usize,
    },
    /// The request method exceeded its configured bound.
    MethodTooLarge {
        /// Actual method bytes.
        actual: usize,
        /// Configured method limit.
        limit: usize,
    },
    /// The request target exceeded its configured bound.
    TargetTooLarge {
        /// Actual target bytes.
        actual: usize,
        /// Configured target limit.
        limit: usize,
    },
    /// The aggregate script exceeded its configured byte bound.
    ScriptTooLarge {
        /// Actual script bytes.
        actual: usize,
        /// Configured script limit.
        limit: usize,
    },
    /// A retained event exceeded its configured byte bound.
    EventTooLarge {
        /// Actual event bytes.
        actual: usize,
        /// Configured event limit.
        limit: usize,
    },
    /// The transport request/event sequence cannot be incremented.
    SequenceOverflow,
    /// A size calculation overflowed before a bound check.
    InvalidSize,
    /// A response reset the exchange.
    Reset {
        /// Optional reset code.
        code: Option<u16>,
    },
    /// An exchange was cancelled before its terminal response step.
    Cancelled,
    /// A response contained a step after its terminal reset.
    UnexpectedAfterReset {
        /// Zero-based response-step position after the reset marker.
        position: usize,
    },
    /// A scripted response did not end with [`TransportStep::End`] or a
    /// terminal [`TransportStep::Reset`].
    MissingEnd,
    /// A response contains one or more steps after its first end marker.
    UnexpectedEnd {
        /// Zero-based response-step position after the first end marker.
        position: usize,
    },
    /// The response stream ended without a terminal marker being consumed.
    Incomplete,
    /// A response delay was observed while collecting data.
    DelayPending {
        /// Logical delay the caller must handle.
        delay: Duration,
    },
    /// One response delay exceeded the configured per-step bound.
    DelayTooLarge {
        /// Rejected logical delay.
        actual: Duration,
        /// Configured per-step bound.
        limit: Duration,
    },
    /// Aggregate response delays exceeded the configured bound or overflowed.
    DelayAggregateTooLarge {
        /// Rejected aggregate delay.
        actual: Duration,
        /// Configured aggregate bound.
        limit: Duration,
    },
}

impl TransportError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::ScriptExhausted { .. } => ErrorCode::TransportScriptExhausted,
            Self::RequestMismatch { .. } => ErrorCode::TransportRequestMismatch,
            Self::BodyTooLarge { .. } => ErrorCode::TransportBodyTooLarge,
            Self::HeaderTooLarge { .. } | Self::HeaderBytesTooLarge { .. } => {
                ErrorCode::TransportHeaderTooLarge
            }
            Self::HeaderCountTooLarge { .. } => ErrorCode::TransportHeaderCountTooLarge,
            Self::MethodTooLarge { .. } => ErrorCode::TransportMethodTooLarge,
            Self::TargetTooLarge { .. } => ErrorCode::TransportTargetTooLarge,
            Self::ScriptTooLarge { .. } => ErrorCode::TransportScriptTooLarge,
            Self::EventTooLarge { .. } => ErrorCode::TransportEventTooLarge,
            Self::SequenceOverflow => ErrorCode::TransportSequenceOverflow,
            Self::CapacityExceeded { .. } => ErrorCode::TransportCapacity,
            Self::InvalidSize => ErrorCode::TransportInvalidSize,
            Self::Reset { .. } => ErrorCode::TransportReset,
            Self::Cancelled => ErrorCode::TransportCancelled,
            Self::UnexpectedAfterReset { .. } => ErrorCode::TransportUnexpectedAfterReset,
            Self::MissingEnd => ErrorCode::TransportMissingEnd,
            Self::UnexpectedEnd { .. } => ErrorCode::TransportUnexpectedEnd,
            Self::Incomplete => ErrorCode::TransportIncomplete,
            Self::DelayPending { .. } => ErrorCode::TransportDelayPending,
            Self::DelayTooLarge { .. } => ErrorCode::TransportDelayTooLarge,
            Self::DelayAggregateTooLarge { .. } => ErrorCode::TransportDelayAggregateTooLarge,
        }
    }
}

impl fmt::Debug for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("TransportError");
        match self {
            Self::ScriptExhausted { request_count } => debug
                .field("kind", &"ScriptExhausted")
                .field("request_count", request_count),
            Self::RequestMismatch {
                position,
                expected,
                actual,
            } => debug
                .field("kind", &"RequestMismatch")
                .field("position", position)
                .field("expected", &expected.redacted())
                .field("actual", &actual.redacted()),
            Self::BodyTooLarge {
                direction,
                actual,
                limit,
            } => debug
                .field("kind", &"BodyTooLarge")
                .field("direction", direction)
                .field("actual", actual)
                .field("limit", limit),
            Self::CapacityExceeded {
                kind,
                actual,
                limit,
            } => debug
                .field("kind", &"CapacityExceeded")
                .field("collection", kind)
                .field("actual", actual)
                .field("limit", limit),
            Self::HeaderTooLarge {
                name_bytes,
                value_bytes,
                name_limit,
                value_limit,
            } => debug
                .field("kind", &"HeaderTooLarge")
                .field("name_bytes", name_bytes)
                .field("value_bytes", value_bytes)
                .field("name_limit", name_limit)
                .field("value_limit", value_limit),
            Self::HeaderBytesTooLarge { actual, limit } => debug
                .field("kind", &"HeaderBytesTooLarge")
                .field("actual", actual)
                .field("limit", limit),
            Self::HeaderCountTooLarge {
                direction,
                actual,
                limit,
            } => debug
                .field("kind", &"HeaderCountTooLarge")
                .field("direction", direction)
                .field("actual", actual)
                .field("limit", limit),
            Self::MethodTooLarge { actual, limit } => debug
                .field("kind", &"MethodTooLarge")
                .field("actual", actual)
                .field("limit", limit),
            Self::TargetTooLarge { actual, limit } => debug
                .field("kind", &"TargetTooLarge")
                .field("actual", actual)
                .field("limit", limit),
            Self::ScriptTooLarge { actual, limit } => debug
                .field("kind", &"ScriptTooLarge")
                .field("actual", actual)
                .field("limit", limit),
            Self::EventTooLarge { actual, limit } => debug
                .field("kind", &"EventTooLarge")
                .field("actual", actual)
                .field("limit", limit),
            Self::SequenceOverflow => debug.field("kind", &"SequenceOverflow"),
            Self::InvalidSize => debug.field("kind", &"InvalidSize"),
            Self::Reset { code } => debug.field("kind", &"Reset").field("code", code),
            Self::Cancelled => debug.field("kind", &"Cancelled"),
            Self::UnexpectedAfterReset { position } => debug
                .field("kind", &"UnexpectedAfterReset")
                .field("position", position),
            Self::MissingEnd => debug.field("kind", &"MissingEnd"),
            Self::UnexpectedEnd { position } => debug
                .field("kind", &"UnexpectedEnd")
                .field("position", position),
            Self::Incomplete => debug.field("kind", &"Incomplete"),
            Self::DelayPending { delay } => {
                debug.field("kind", &"DelayPending").field("delay", delay)
            }
            Self::DelayTooLarge { actual, limit } => debug
                .field("kind", &"DelayTooLarge")
                .field("actual", actual)
                .field("limit", limit),
            Self::DelayAggregateTooLarge { actual, limit } => debug
                .field("kind", &"DelayAggregateTooLarge")
                .field("actual", actual)
                .field("limit", limit),
        };
        debug.finish()
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ScriptExhausted { request_count } => write!(
                formatter,
                "{}: no scripted response remains after {request_count} request(s)",
                self.code()
            ),
            Self::RequestMismatch { position, .. } => write!(
                formatter,
                "{}: request mismatch at script position {position}",
                self.code()
            ),
            Self::BodyTooLarge {
                direction,
                actual,
                limit,
            } => write!(
                formatter,
                "{}: {direction:?} body bytes {actual} exceed {limit}",
                self.code()
            ),
            Self::CapacityExceeded {
                kind,
                actual,
                limit,
            } => write!(
                formatter,
                "{}: {kind:?} count {actual} exceeds {limit}",
                self.code()
            ),
            Self::HeaderTooLarge {
                name_bytes,
                value_bytes,
                name_limit,
                value_limit,
            } => write!(
                formatter,
                "{}: header name/value {name_bytes}/{value_bytes} exceed {name_limit}/{value_limit}",
                self.code()
            ),
            Self::HeaderCountTooLarge {
                direction,
                actual,
                limit,
            } => write!(
                formatter,
                "{}: {direction:?} header count {actual} exceeds {limit}",
                self.code()
            ),
            Self::InvalidSize => write!(formatter, "{}: transport size overflow", self.code()),
            Self::Reset { code } => write!(formatter, "{}: response reset ({code:?})", self.code()),
            Self::Cancelled => write!(formatter, "{}: response exchange cancelled", self.code()),
            Self::MissingEnd => write!(
                formatter,
                "{}: response has no terminal end step",
                self.code()
            ),
            Self::UnexpectedEnd { position } => write!(
                formatter,
                "{}: response step {position} appears after the first end marker",
                self.code()
            ),
            Self::UnexpectedAfterReset { position } => write!(
                formatter,
                "{}: response step {position} appears after the terminal reset",
                self.code()
            ),
            Self::Incomplete => write!(formatter, "{}: response stream is incomplete", self.code()),
            Self::DelayPending { delay } => write!(
                formatter,
                "{}: response delay {delay:?} requires explicit clock handling",
                self.code()
            ),
            Self::DelayTooLarge { actual, limit } => write!(
                formatter,
                "{}: logical delay {actual:?} exceeds per-step limit {limit:?}",
                self.code()
            ),
            Self::DelayAggregateTooLarge { actual, limit } => write!(
                formatter,
                "{}: aggregate logical delay {actual:?} exceeds {limit:?}",
                self.code()
            ),
            Self::HeaderBytesTooLarge { actual, limit } => write!(
                formatter,
                "{}: aggregate header bytes {actual} exceed {limit}",
                self.code()
            ),
            Self::MethodTooLarge { actual, limit } => write!(
                formatter,
                "{}: method bytes {actual} exceed {limit}",
                self.code()
            ),
            Self::TargetTooLarge { actual, limit } => write!(
                formatter,
                "{}: target bytes {actual} exceed {limit}",
                self.code()
            ),
            Self::ScriptTooLarge { actual, limit } => write!(
                formatter,
                "{}: script bytes {actual} exceed {limit}",
                self.code()
            ),
            Self::EventTooLarge { actual, limit } => write!(
                formatter,
                "{}: event bytes {actual} exceed {limit}",
                self.code()
            ),
            Self::SequenceOverflow => {
                write!(formatter, "{}: transport sequence overflow", self.code())
            }
        }
    }
}

impl std::error::Error for TransportError {}

impl StableError for TransportError {
    fn code(&self) -> ErrorCode {
        self.code()
    }
}

/// Errors returned when an explicit transport owner finds an exchange that
/// was dropped before terminal completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportLeakError {
    /// One or more exchanges remain active.
    ActiveExchanges {
        /// Number of exchanges that were not terminally consumed or cancelled.
        active: usize,
    },
    /// Drop cancellation could not append its bounded cancellation event.
    DropCancellationFailed {
        /// Number of failed best-effort drop cancellations.
        failures: usize,
    },
}

impl TransportLeakError {
    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> ErrorCode {
        ErrorCode::TransportLeak
    }
}

impl fmt::Display for TransportLeakError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ActiveExchanges { active } => {
                write!(formatter, "{}: {active} active exchange(s)", self.code())
            }
            Self::DropCancellationFailed { failures } => write!(
                formatter,
                "{}: {failures} drop cancellation(s) could not be recorded",
                self.code()
            ),
        }
    }
}

impl std::error::Error for TransportLeakError {}

impl StableError for TransportLeakError {
    fn code(&self) -> ErrorCode {
        TransportLeakError::code(*self)
    }
}

#[derive(Clone, Debug)]
struct ScriptEntry {
    expected: TransportRequest,
    response: TransportResponsePlan,
}

/// A bounded request/response event retained by a fake transport.
#[derive(Clone, PartialEq, Eq)]
pub enum TransportEvent {
    /// A request matched and began an exchange.
    RequestAccepted {
        /// Zero-based script position.
        position: usize,
        /// Request sequence number.
        sequence: u64,
        /// Exact request snapshot.
        request: TransportRequest,
    },
    /// One response step was consumed.
    Step {
        /// Request sequence number.
        sequence: u64,
        /// Zero-based response-step index.
        step: usize,
        /// Consumed step snapshot.
        value: TransportStep,
    },
    /// An exchange was explicitly cancelled before terminal completion.
    ExchangeCancelled {
        /// Request sequence number.
        sequence: u64,
        /// Next response-step index at cancellation.
        step: usize,
    },
}

/// A redacted transport lifecycle-event projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportEventDiagnostic {
    /// A request was accepted, with request content represented by metadata.
    RequestAccepted {
        /// Zero-based script position.
        position: usize,
        /// Request sequence number.
        sequence: u64,
        /// Redacted request metadata.
        request: TransportRequestDiagnostic,
    },
    /// A response step was consumed.
    Step {
        /// Request sequence number.
        sequence: u64,
        /// Response-step index.
        step: usize,
        /// Redacted step metadata.
        value: TransportStepDiagnostic,
    },
    /// An exchange was cancelled.
    ExchangeCancelled {
        /// Request sequence number.
        sequence: u64,
        /// Next response-step index.
        step: usize,
    },
}

impl TransportEvent {
    /// Returns an explicit redacted diagnostic projection.
    #[must_use]
    pub fn redacted(&self) -> TransportEventDiagnostic {
        match self {
            Self::RequestAccepted {
                position,
                sequence,
                request,
            } => TransportEventDiagnostic::RequestAccepted {
                position: *position,
                sequence: *sequence,
                request: request.redacted(),
            },
            Self::Step {
                sequence,
                step,
                value,
            } => TransportEventDiagnostic::Step {
                sequence: *sequence,
                step: *step,
                value: match value {
                    TransportStep::Data(bytes) => TransportStepDiagnostic::Data {
                        byte_len: bytes.len(),
                    },
                    TransportStep::Delay(delay) => {
                        TransportStepDiagnostic::Delay { duration: *delay }
                    }
                    TransportStep::End => TransportStepDiagnostic::End,
                    TransportStep::Reset { code } => TransportStepDiagnostic::Reset { code: *code },
                },
            },
            Self::ExchangeCancelled { sequence, step } => {
                TransportEventDiagnostic::ExchangeCancelled {
                    sequence: *sequence,
                    step: *step,
                }
            }
        }
    }

    /// Returns aggregate bytes represented by this retained event.
    pub fn wire_bytes(&self) -> Result<usize, TransportError> {
        match self {
            Self::RequestAccepted { request, .. } => request.wire_bytes(),
            Self::Step { value, .. } => Ok(value.wire_bytes()),
            Self::ExchangeCancelled { .. } => Ok(std::mem::size_of::<u64>() * 2),
        }
    }
}

impl fmt::Debug for TransportEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.redacted().fmt(formatter)
    }
}

#[derive(Debug)]
struct TransportState {
    limits: TransportLimits,
    script: Vec<ScriptEntry>,
    script_bytes: usize,
    next_position: usize,
    next_sequence: u64,
    events: Vec<TransportEvent>,
    event_bytes: usize,
    active_exchanges: usize,
    drop_cancellation_failures: usize,
}

/// Builder for a finite, ordered transport script.
#[derive(Clone, Debug)]
pub struct FakeTransportBuilder {
    limits: TransportLimits,
    script: Vec<ScriptEntry>,
    script_bytes: usize,
}

impl FakeTransportBuilder {
    /// Creates an empty script with explicit bounds.
    #[must_use]
    pub fn new(limits: TransportLimits) -> Self {
        Self {
            limits,
            script: Vec::new(),
            script_bytes: 0,
        }
    }

    /// Creates an empty script with finite default bounds.
    #[must_use]
    pub fn default_bounded() -> Self {
        Self::new(TransportLimits::default())
    }

    /// Adds one exact request/response pair.
    pub fn push(
        mut self,
        request: TransportRequest,
        response: TransportResponsePlan,
    ) -> Result<Self, TransportError> {
        if self.script.len() >= self.limits.max_script_entries {
            return Err(TransportError::CapacityExceeded {
                kind: TransportCapacityKind::Script,
                actual: self.script.len().saturating_add(1),
                limit: self.limits.max_script_entries,
            });
        }
        validate_request(&request, self.limits)?;
        response.validate(self.limits)?;
        let entry_bytes = request
            .wire_bytes()?
            .checked_add(response.wire_bytes()?)
            .ok_or(TransportError::InvalidSize)?;
        let script_bytes = self
            .script_bytes
            .checked_add(entry_bytes)
            .ok_or(TransportError::InvalidSize)?;
        if script_bytes > self.limits.max_script_bytes {
            return Err(TransportError::ScriptTooLarge {
                actual: script_bytes,
                limit: self.limits.max_script_bytes,
            });
        }
        self.script_bytes = script_bytes;
        self.script.push(ScriptEntry {
            expected: request,
            response,
        });
        Ok(self)
    }

    /// Alias for [`Self::push`] emphasizing request matching.
    pub fn expect(
        self,
        request: TransportRequest,
        response: TransportResponsePlan,
    ) -> Result<Self, TransportError> {
        self.push(request, response)
    }

    /// Builds the cloneable fake transport.
    #[must_use]
    pub fn build(self) -> FakeTransport {
        FakeTransport {
            state: Arc::new(Mutex::new(TransportState {
                limits: self.limits,
                script: self.script,
                script_bytes: self.script_bytes,
                next_position: 0,
                next_sequence: 0,
                events: Vec::new(),
                event_bytes: 0,
                active_exchanges: 0,
                drop_cancellation_failures: 0,
            })),
        }
    }
}

/// A cloneable in-memory transport whose script is consumed in order.
#[derive(Clone, Debug)]
pub struct FakeTransport {
    state: Arc<Mutex<TransportState>>,
}

impl FakeTransport {
    /// Creates an empty transport with finite default limits.
    #[must_use]
    pub fn new() -> Self {
        FakeTransportBuilder::default_bounded().build()
    }

    /// Returns configured bounds.
    #[must_use]
    pub fn limits(&self) -> TransportLimits {
        recover_lock(&self.state).limits
    }

    /// Returns the number of unconsumed scripted exchanges.
    #[must_use]
    pub fn remaining(&self) -> usize {
        let state = recover_lock(&self.state);
        state.script.len().saturating_sub(state.next_position)
    }

    /// Returns the number of accepted requests.
    #[must_use]
    pub fn accepted_count(&self) -> usize {
        recover_lock(&self.state).next_position
    }

    /// Returns aggregate bytes in the validated script.
    #[must_use]
    pub fn script_bytes(&self) -> usize {
        recover_lock(&self.state).script_bytes
    }

    /// Returns aggregate bytes retained by request/step events.
    #[must_use]
    pub fn event_bytes(&self) -> usize {
        recover_lock(&self.state).event_bytes
    }

    /// Returns the number of exchanges not yet terminally completed or
    /// cancelled.
    #[must_use]
    pub fn active_exchange_count(&self) -> usize {
        recover_lock(&self.state).active_exchanges
    }

    /// Checks the bounded owner invariant for dropped exchanges.
    ///
    /// Every explicitly owned `TransportExchange` attempts a safe
    /// cancellation in `Drop`.  Non-owning exchanges retain their historical
    /// semantics and are still visible to this check as active registrations.
    /// If the event budget is already full, the failed attempt is retained as
    /// a diagnostic instead of silently accepting a leaked logical exchange.
    pub fn assert_no_leaks(&self) -> Result<(), TransportLeakError> {
        let state = recover_lock(&self.state);
        if state.drop_cancellation_failures != 0 {
            return Err(TransportLeakError::DropCancellationFailed {
                failures: state.drop_cancellation_failures,
            });
        }
        if state.active_exchanges != 0 {
            return Err(TransportLeakError::ActiveExchanges {
                active: state.active_exchanges,
            });
        }
        Ok(())
    }

    /// Returns retained request/step events.
    #[must_use]
    pub fn events(&self) -> Vec<TransportEvent> {
        recover_lock(&self.state).events.clone()
    }

    /// Clears retained events while preserving script position and sequence.
    pub fn clear_events(&self) {
        let mut state = recover_lock(&self.state);
        state.events.clear();
        state.event_bytes = 0;
    }

    /// Sends one exact request and returns its explicit response stream.
    pub fn send(&self, request: TransportRequest) -> Result<TransportExchange, TransportError> {
        self.send_with_ownership(request, false)
    }

    /// Sends one exact request and returns an explicitly owned exchange whose
    /// last handle drop attempts bounded cancellation.
    ///
    /// The ordinary [`Self::send`] API preserves its historical non-owning
    /// semantics.  Use this owner variant with [`Self::assert_no_leaks`] when
    /// automatic cleanup is desired.
    pub fn send_owned(
        &self,
        request: TransportRequest,
    ) -> Result<TransportExchange, TransportError> {
        self.send_with_ownership(request, true)
    }

    fn send_with_ownership(
        &self,
        request: TransportRequest,
        owned: bool,
    ) -> Result<TransportExchange, TransportError> {
        let mut state = recover_lock(&self.state);
        validate_request(&request, state.limits)?;
        let position = state.next_position;
        let Some(entry) = state.script.get(position) else {
            return Err(TransportError::ScriptExhausted {
                request_count: position,
            });
        };
        if entry.expected != request {
            return Err(TransportError::RequestMismatch {
                position,
                expected: Box::new(entry.expected.clone()),
                actual: Box::new(request),
            });
        }
        let response = entry.response.clone();
        let sequence = state.next_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(TransportError::SequenceOverflow)?;
        let next_position = position.checked_add(1).ok_or(TransportError::InvalidSize)?;
        let event = TransportEvent::RequestAccepted {
            position,
            sequence,
            request: request.clone(),
        };
        let event_bytes = event.wire_bytes()?;
        ensure_event_capacity(&state, event_bytes)?;
        let total_event_bytes = state
            .event_bytes
            .checked_add(event_bytes)
            .ok_or(TransportError::InvalidSize)?;
        let active_exchanges = state
            .active_exchanges
            .checked_add(1)
            .ok_or(TransportError::InvalidSize)?;
        state.next_sequence = next_sequence;
        state.next_position = next_position;
        state.event_bytes = total_event_bytes;
        state.events.push(event);
        state.active_exchanges = active_exchanges;
        Ok(TransportExchange {
            state: Arc::clone(&self.state),
            sequence,
            request,
            response,
            next_step: 0,
            finished: false,
            complete: false,
            reset_error: None,
            cancelled: false,
            body: Vec::new(),
            owned,
        })
    }
}

impl Default for FakeTransport {
    fn default() -> Self {
        Self::new()
    }
}

/// One response stream returned by [`FakeTransport::send`].
pub struct TransportExchange {
    state: Arc<Mutex<TransportState>>,
    sequence: u64,
    request: TransportRequest,
    response: TransportResponsePlan,
    next_step: usize,
    finished: bool,
    complete: bool,
    reset_error: Option<TransportError>,
    cancelled: bool,
    body: Vec<u8>,
    owned: bool,
}

/// A redacted diagnostic projection of an open transport exchange.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportExchangeDiagnostic {
    /// Redacted request metadata.
    pub request: TransportRequestDiagnostic,
    /// Response status.
    pub status: u16,
    /// Ordered redacted response headers.
    pub headers: Vec<TransportHeaderDiagnostic>,
    /// Exchange sequence number.
    pub sequence: u64,
    /// Number of the next response step.
    pub next_step: usize,
    /// Collected body byte length.
    pub body_bytes: usize,
    /// Whether a terminal response was consumed.
    pub finished: bool,
    /// Whether the response ended normally.
    pub complete: bool,
    /// Whether explicit cancellation was recorded.
    pub cancelled: bool,
}

impl TransportExchange {
    /// Returns an explicit redacted diagnostic projection.
    #[must_use]
    pub fn redacted(&self) -> TransportExchangeDiagnostic {
        TransportExchangeDiagnostic {
            request: self.request.redacted(),
            status: self.response.status,
            headers: self
                .response
                .headers
                .iter()
                .map(TransportHeader::redacted)
                .collect(),
            sequence: self.sequence,
            next_step: self.next_step,
            body_bytes: self.body.len(),
            finished: self.finished,
            complete: self.complete,
            cancelled: self.cancelled,
        }
    }

    /// Returns the exact request that opened this exchange.
    #[must_use]
    pub fn request(&self) -> &TransportRequest {
        &self.request
    }

    /// Returns the response status.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.response.status
    }

    /// Returns ordered response headers.
    #[must_use]
    pub fn headers(&self) -> &[TransportHeader] {
        &self.response.headers
    }

    /// Returns the exchange sequence number.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns whether this exchange owns cancellation-on-drop behavior.
    #[must_use]
    pub const fn is_owned(&self) -> bool {
        self.owned
    }

    /// Returns whether all response steps were consumed or reset.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.finished
    }

    /// Returns whether the terminal [`TransportStep::End`] was consumed.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    /// Returns whether the exchange is not complete, including reset and
    /// pending-delay states.
    #[must_use]
    pub const fn is_incomplete(&self) -> bool {
        !self.complete
    }

    /// Returns whether this exchange was explicitly cancelled.
    #[must_use]
    pub const fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    /// Returns the reset error retained by this exchange, if any.
    #[must_use]
    pub fn reset_error(&self) -> Option<&TransportError> {
        self.reset_error.as_ref()
    }

    /// Returns data chunks consumed so far, without copying.
    #[must_use]
    pub fn collected_body(&self) -> &[u8] {
        &self.body
    }

    /// Requires a complete response, preserving reset and incomplete errors.
    pub fn finish(&self) -> Result<(), TransportError> {
        if self.complete {
            Ok(())
        } else if let Some(error) = &self.reset_error {
            Err(error.clone())
        } else if self.cancelled {
            Err(TransportError::Cancelled)
        } else {
            Err(TransportError::Incomplete)
        }
    }

    /// Explicitly cancels this exchange at its current response boundary.
    ///
    /// Cancellation is observable as one bounded transport event.  A
    /// complete, reset, or already-cancelled exchange returns `Ok(false)`.
    /// Dropping an unfinished exchange also attempts this cancellation, but
    /// callers that need the typed result should call this method explicitly.
    pub fn cancel(&mut self) -> Result<bool, TransportError> {
        if self.finished {
            return Ok(false);
        }
        self.cancel_inner()
    }

    fn cancel_inner(&mut self) -> Result<bool, TransportError> {
        let mut state = recover_lock(&self.state);
        let event = TransportEvent::ExchangeCancelled {
            sequence: self.sequence,
            step: self.next_step,
        };
        let event_bytes = event.wire_bytes()?;
        ensure_event_capacity(&state, event_bytes)?;
        let total_event_bytes = state
            .event_bytes
            .checked_add(event_bytes)
            .ok_or(TransportError::InvalidSize)?;
        state.event_bytes = total_event_bytes;
        state.events.push(event);
        state.active_exchanges = state.active_exchanges.saturating_sub(1);
        self.finished = true;
        self.cancelled = true;
        Ok(true)
    }

    /// Consumes the next explicit response step without sleeping.
    pub fn next_step(&mut self) -> Result<Option<TransportStep>, TransportError> {
        if self.finished {
            if let Some(error) = &self.reset_error {
                return Err(error.clone());
            }
            if self.cancelled {
                return Err(TransportError::Cancelled);
            }
            return if self.complete {
                Ok(None)
            } else {
                Err(TransportError::Incomplete)
            };
        }
        let Some(value) = self.response.steps.get(self.next_step).cloned() else {
            self.finished = true;
            let mut state = recover_lock(&self.state);
            state.active_exchanges = state.active_exchanges.saturating_sub(1);
            return Err(TransportError::Incomplete);
        };
        let mut state = recover_lock(&self.state);
        let event = TransportEvent::Step {
            sequence: self.sequence,
            step: self.next_step,
            value: value.clone(),
        };
        let event_bytes = event.wire_bytes()?;
        ensure_event_capacity(&state, event_bytes)?;
        let total_event_bytes = state
            .event_bytes
            .checked_add(event_bytes)
            .ok_or(TransportError::InvalidSize)?;
        state.event_bytes = total_event_bytes;
        state.events.push(event);
        self.next_step += 1;
        match value {
            TransportStep::Reset { code } => {
                self.finished = true;
                state.active_exchanges = state.active_exchanges.saturating_sub(1);
                let error = TransportError::Reset { code };
                self.reset_error = Some(error.clone());
                Err(error)
            }
            TransportStep::End => {
                self.finished = true;
                self.complete = true;
                state.active_exchanges = state.active_exchanges.saturating_sub(1);
                Ok(Some(TransportStep::End))
            }
            TransportStep::Data(bytes) => {
                self.body.extend_from_slice(&bytes);
                Ok(Some(TransportStep::Data(bytes)))
            }
            step => Ok(Some(step)),
        }
    }

    /// Collects data until end, returning a typed delay/reset instead of
    /// sleeping or hiding a transport boundary.
    pub fn collect_body(&mut self) -> Result<Vec<u8>, TransportError> {
        if self.complete {
            return Ok(self.body.clone());
        }
        while let Some(step) = self.next_step()? {
            match step {
                TransportStep::Data(_) => {}
                TransportStep::Delay(delay) => {
                    return Err(TransportError::DelayPending { delay });
                }
                TransportStep::End => return Ok(self.body.clone()),
                TransportStep::Reset { code } => return Err(TransportError::Reset { code }),
            }
        }
        self.finish()?;
        Ok(self.body.clone())
    }
}

impl fmt::Debug for TransportExchange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.redacted().fmt(formatter)
    }
}

impl Drop for TransportExchange {
    fn drop(&mut self) {
        if !self.owned || self.finished {
            return;
        }
        if self.cancel_inner().is_err() {
            let mut state = recover_lock(&self.state);
            state.drop_cancellation_failures = state.drop_cancellation_failures.saturating_add(1);
        }
    }
}

fn insert_before_end(steps: &mut Vec<TransportStep>, step: TransportStep) {
    let position = steps
        .iter()
        .position(|candidate| matches!(candidate, TransportStep::End))
        .unwrap_or(steps.len());
    steps.insert(position, step);
}

fn validate_request(
    request: &TransportRequest,
    limits: TransportLimits,
) -> Result<(), TransportError> {
    if request.method.len() > limits.max_method_bytes {
        return Err(TransportError::MethodTooLarge {
            actual: request.method.len(),
            limit: limits.max_method_bytes,
        });
    }
    if request.target.len() > limits.max_target_bytes {
        return Err(TransportError::TargetTooLarge {
            actual: request.target.len(),
            limit: limits.max_target_bytes,
        });
    }
    validate_headers(
        &request.headers,
        limits.max_request_headers,
        TransportHeaderDirection::Request,
        limits,
    )?;
    if request.body.len() > limits.max_request_body_bytes {
        return Err(TransportError::BodyTooLarge {
            direction: TransportBodyDirection::Request,
            actual: request.body.len(),
            limit: limits.max_request_body_bytes,
        });
    }
    Ok(())
}

fn validate_headers(
    headers: &[TransportHeader],
    max_count: usize,
    direction: TransportHeaderDirection,
    limits: TransportLimits,
) -> Result<(), TransportError> {
    if headers.len() > max_count {
        return Err(TransportError::HeaderCountTooLarge {
            direction,
            actual: headers.len(),
            limit: max_count,
        });
    }
    let total = header_bytes(headers)?;
    for header in headers {
        if header.name.len() > limits.max_header_name_bytes
            || header.value.len() > limits.max_header_value_bytes
        {
            return Err(TransportError::HeaderTooLarge {
                name_bytes: header.name.len(),
                value_bytes: header.value.len(),
                name_limit: limits.max_header_name_bytes,
                value_limit: limits.max_header_value_bytes,
            });
        }
    }
    if total > limits.max_header_bytes {
        return Err(TransportError::HeaderBytesTooLarge {
            actual: total,
            limit: limits.max_header_bytes,
        });
    }
    Ok(())
}

fn header_bytes(headers: &[TransportHeader]) -> Result<usize, TransportError> {
    headers
        .iter()
        .map(TransportHeader::wire_bytes)
        .try_fold(0_usize, |total, bytes| {
            let bytes = bytes?;
            total.checked_add(bytes).ok_or(TransportError::InvalidSize)
        })
}

fn ensure_event_capacity(state: &TransportState, event_bytes: usize) -> Result<(), TransportError> {
    if state.events.len() >= state.limits.max_events {
        Err(TransportError::CapacityExceeded {
            kind: TransportCapacityKind::Events,
            actual: state.events.len().saturating_add(1),
            limit: state.limits.max_events,
        })
    } else if event_bytes > state.limits.max_event_bytes {
        Err(TransportError::EventTooLarge {
            actual: event_bytes,
            limit: state.limits.max_event_bytes,
        })
    } else if state
        .event_bytes
        .checked_add(event_bytes)
        .is_none_or(|total| total > state.limits.max_total_event_bytes)
    {
        let actual = state.event_bytes.saturating_add(event_bytes);
        Err(TransportError::CapacityExceeded {
            kind: TransportCapacityKind::EventBytes,
            actual,
            limit: state.limits.max_total_event_bytes,
        })
    } else {
        Ok(())
    }
}

fn recover_lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    fn limits() -> TransportLimits {
        TransportLimits::new(4, 8, 16, 8, 16)
    }

    #[test]
    fn exact_script_preserves_order_duplicates_and_chunks() {
        let request = TransportRequest::new("POST", "/fixture")
            .header("X-Test", b"one".to_vec())
            .header("X-Test", b"two".to_vec())
            .body(b"request".to_vec());
        let response = TransportResponseBuilder::new(207)
            .header("Content-Type", b"application/octet-stream".to_vec())
            .chunk(b"ab".to_vec())
            .delay(Duration::from_secs(2))
            .chunk(b"cd".to_vec())
            .build(limits())
            .unwrap();
        let transport = FakeTransportBuilder::new(limits())
            .expect(request.clone(), response)
            .unwrap()
            .build();
        let mut exchange = transport.send(request).unwrap();
        assert_eq!(exchange.status(), 207);
        assert_eq!(
            exchange.next_step().unwrap(),
            Some(TransportStep::Data(b"ab".to_vec()))
        );
        assert_eq!(
            exchange.next_step().unwrap(),
            Some(TransportStep::Delay(Duration::from_secs(2)))
        );
        assert_eq!(
            exchange.next_step().unwrap(),
            Some(TransportStep::Data(b"cd".to_vec()))
        );
        assert_eq!(exchange.next_step().unwrap(), Some(TransportStep::End));
        assert!(exchange.is_finished());
        assert_eq!(transport.remaining(), 0);
    }

    #[test]
    fn mismatch_and_exhaustion_do_not_consume_script() {
        let expected = TransportRequest::new("GET", "/expected");
        let transport = FakeTransportBuilder::new(limits())
            .push(expected.clone(), TransportResponsePlan::new(200))
            .unwrap()
            .build();
        let error = transport.send(TransportRequest::new("GET", "/actual"));
        assert_eq!(
            error.unwrap_err().code(),
            ErrorCode::TransportRequestMismatch
        );
        assert_eq!(transport.remaining(), 1);
        transport.send(expected).unwrap();
        assert_eq!(
            transport
                .send(TransportRequest::new("GET", "/extra"))
                .unwrap_err()
                .code(),
            ErrorCode::TransportScriptExhausted
        );
    }

    #[test]
    fn body_and_step_limits_are_checked_before_build_or_send() {
        let error = TransportResponseBuilder::new(200)
            .body(vec![0; 17])
            .build(limits())
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::TransportBodyTooLarge);

        let request = TransportRequest::new("POST", "/large").body(vec![0; 9]);
        let transport = FakeTransportBuilder::new(limits()).build();
        assert_eq!(
            transport.send(request).unwrap_err().code(),
            ErrorCode::TransportBodyTooLarge
        );
    }

    #[test]
    fn response_builder_preflights_bounded_candidates_atomically() {
        let limits = TransportLimits::new(4, 8, 4, 8, 16);
        let builder = TransportResponseBuilder::with_limits(200, limits);
        let error = builder.clone().try_body(vec![0; 5]).unwrap_err();
        assert_eq!(error.code(), ErrorCode::TransportBodyTooLarge);
        assert_eq!(
            builder.build_default().unwrap().steps,
            vec![TransportStep::End]
        );

        let pending = TransportResponseBuilder::with_limits(200, limits).body(vec![0; 5]);
        assert_eq!(
            pending.build_default().unwrap_err().code(),
            ErrorCode::TransportBodyTooLarge
        );

        let event_limits = limits.with_event_bytes_limit(1);
        let builder = TransportResponseBuilder::with_limits(200, event_limits);
        let error = builder.clone().try_chunk(vec![0, 1]).unwrap_err();
        assert_eq!(error.code(), ErrorCode::TransportEventTooLarge);
        assert_eq!(
            builder.build_default().unwrap().steps,
            vec![TransportStep::End]
        );
    }

    #[test]
    fn response_without_terminal_end_is_rejected() {
        let response = TransportResponsePlan {
            status: 200,
            headers: Vec::new(),
            steps: vec![TransportStep::Data(b"truncated".to_vec())],
        };
        assert_eq!(
            response.validate(limits()).unwrap_err().code(),
            ErrorCode::TransportMissingEnd
        );
    }

    #[test]
    fn reset_and_delay_are_explicit_errors_when_collecting() {
        let response = TransportResponseBuilder::new(200)
            .delay(Duration::from_millis(5))
            .reset(Some(7))
            .build(limits())
            .unwrap();
        let transport = FakeTransportBuilder::new(limits())
            .push(TransportRequest::new("GET", "/reset"), response)
            .unwrap()
            .build();
        let mut exchange = transport
            .send(TransportRequest::new("GET", "/reset"))
            .unwrap();
        assert_eq!(
            exchange.collect_body().unwrap_err().code(),
            ErrorCode::TransportDelayPending
        );
        assert_eq!(
            exchange.next_step().unwrap_err().code(),
            ErrorCode::TransportReset
        );
        assert!(exchange.is_incomplete());
        assert_eq!(
            exchange.reset_error().map(TransportError::code),
            Some(ErrorCode::TransportReset)
        );
        assert_eq!(
            exchange.finish().unwrap_err().code(),
            ErrorCode::TransportReset
        );
        assert_eq!(
            exchange.next_step().unwrap_err().code(),
            ErrorCode::TransportReset
        );
    }

    #[test]
    fn reset_is_a_terminal_alternative_and_post_reset_steps_are_diagnostic() {
        let response = TransportResponseBuilder::new(503)
            .reset(Some(7))
            .build(limits())
            .unwrap();
        assert_eq!(response.steps, vec![TransportStep::Reset { code: Some(7) }]);

        let transport = FakeTransportBuilder::new(limits())
            .push(TransportRequest::new("GET", "/reset-only"), response)
            .unwrap()
            .build();
        let mut exchange = transport
            .send(TransportRequest::new("GET", "/reset-only"))
            .unwrap();
        assert_eq!(
            exchange.collect_body().unwrap_err().code(),
            ErrorCode::TransportReset
        );
        assert!(exchange.is_finished());
        assert!(exchange.is_incomplete());
        assert_eq!(
            exchange.finish().unwrap_err().code(),
            ErrorCode::TransportReset
        );

        for (steps, position) in [
            (
                vec![TransportStep::Reset { code: None }, TransportStep::End],
                1,
            ),
            (
                vec![
                    TransportStep::Reset { code: None },
                    TransportStep::Data(b"after".to_vec()),
                ],
                1,
            ),
            (
                vec![
                    TransportStep::Data(b"before".to_vec()),
                    TransportStep::Reset { code: None },
                    TransportStep::Delay(Duration::from_secs(1)),
                ],
                2,
            ),
        ] {
            let response = TransportResponsePlan {
                status: 503,
                headers: Vec::new(),
                steps,
            };
            let error = response.validate(limits()).unwrap_err();
            assert_eq!(error.code(), ErrorCode::TransportUnexpectedAfterReset);
            assert!(matches!(
                error,
                TransportError::UnexpectedAfterReset { position: actual }
                    if actual == position
            ));
        }
    }

    #[test]
    fn collect_body_retains_chunks_across_delay_pending() {
        let response = TransportResponseBuilder::new(200)
            .chunk(b"first".to_vec())
            .delay(Duration::from_secs(1))
            .chunk(b"second".to_vec())
            .build(limits())
            .unwrap();
        let request = TransportRequest::new("GET", "/body");
        let transport = FakeTransportBuilder::new(limits())
            .push(request.clone(), response)
            .unwrap()
            .build();
        let mut exchange = transport.send(request).unwrap();

        assert_eq!(
            exchange.collect_body().unwrap_err().code(),
            ErrorCode::TransportDelayPending
        );
        assert_eq!(exchange.collected_body(), b"first");
        assert!(exchange.is_incomplete());
        assert_eq!(
            exchange.finish().unwrap_err().code(),
            ErrorCode::TransportIncomplete
        );
        assert_eq!(exchange.collect_body().unwrap(), b"firstsecond".to_vec());
        assert!(exchange.is_complete());
        assert_eq!(exchange.finish(), Ok(()));
        assert_eq!(exchange.collect_body().unwrap(), b"firstsecond".to_vec());
    }

    #[test]
    fn steps_after_first_end_are_rejected() {
        for steps in [
            vec![TransportStep::End, TransportStep::End],
            vec![
                TransportStep::Data(b"before".to_vec()),
                TransportStep::End,
                TransportStep::Data(b"after".to_vec()),
            ],
        ] {
            let response = TransportResponsePlan {
                status: 200,
                headers: Vec::new(),
                steps,
            };
            assert_eq!(
                response.validate(limits()).unwrap_err().code(),
                ErrorCode::TransportUnexpectedEnd
            );
        }
    }

    #[test]
    fn transport_method_target_header_script_and_event_bounds_are_aggregate() {
        let request = TransportRequest::new("GET", "/target");
        let method_limited = FakeTransportBuilder::new(limits().with_method_limit(2)).build();
        assert_eq!(
            method_limited.send(request.clone()).unwrap_err().code(),
            ErrorCode::TransportMethodTooLarge
        );

        let target_limited = FakeTransportBuilder::new(limits().with_target_limit(3)).build();
        assert_eq!(
            target_limited.send(request.clone()).unwrap_err().code(),
            ErrorCode::TransportTargetTooLarge
        );

        let header_limited = limits().with_header_bytes_limit(3);
        let response = TransportResponsePlan::new(200).header("x", b"123".to_vec());
        assert_eq!(
            response.validate(header_limited).unwrap_err().code(),
            ErrorCode::TransportHeaderTooLarge
        );

        let script_limited = limits().with_script_bytes_limit(7);
        let response = TransportResponsePlan::new(200);
        let request = TransportRequest::new("GET", "/");
        let builder = FakeTransportBuilder::new(script_limited)
            .push(request.clone(), response.clone())
            .unwrap();
        assert_eq!(
            builder.push(request, response).unwrap_err().code(),
            ErrorCode::TransportScriptTooLarge
        );

        let event_limited = limits().with_event_bytes_limit(3);
        let request = TransportRequest::new("GET", "/");
        let transport = FakeTransportBuilder::new(event_limited)
            .push(request.clone(), TransportResponsePlan::new(200))
            .unwrap()
            .build();
        assert_eq!(
            transport.send(request).unwrap_err().code(),
            ErrorCode::TransportEventTooLarge
        );
    }

    #[test]
    fn script_entry_capacity_is_checked_before_appending() {
        let limits = limits();
        let mut builder = FakeTransportBuilder::new(limits);
        for position in 0..limits.max_script_entries {
            builder = builder
                .push(
                    TransportRequest::new("GET", format!("/entry-{position}")),
                    TransportResponsePlan::new(200),
                )
                .unwrap();
        }
        let error = builder
            .push(
                TransportRequest::new("GET", "/entry-overflow"),
                TransportResponsePlan::new(200),
            )
            .unwrap_err();
        assert_eq!(
            error,
            TransportError::CapacityExceeded {
                kind: TransportCapacityKind::Script,
                actual: limits.max_script_entries + 1,
                limit: limits.max_script_entries,
            }
        );
    }

    #[test]
    fn response_step_capacity_is_checked_before_stream_use() {
        let limits = limits();
        let response = TransportResponsePlan {
            status: 200,
            headers: Vec::new(),
            steps: (0..limits.max_steps)
                .map(|_| TransportStep::Data(Vec::new()))
                .chain(std::iter::once(TransportStep::End))
                .collect(),
        };
        let error = response.validate(limits).unwrap_err();
        assert_eq!(
            error,
            TransportError::CapacityExceeded {
                kind: TransportCapacityKind::Steps,
                actual: limits.max_steps + 1,
                limit: limits.max_steps,
            }
        );
    }

    #[test]
    fn request_and_response_header_counts_include_zero_byte_headers() {
        let response_limits = limits().with_response_header_count_limit(1);
        let response = TransportResponsePlan::new(200)
            .header("", Vec::new())
            .header("", Vec::new());
        let error = response.validate(response_limits).unwrap_err();
        assert_eq!(error.code(), ErrorCode::TransportHeaderCountTooLarge);
        assert!(matches!(
            error,
            TransportError::HeaderCountTooLarge {
                direction: TransportHeaderDirection::Response,
                actual: 2,
                limit: 1,
            }
        ));

        let request_limits = limits().with_request_header_limit(1);
        let request = TransportRequest::new("GET", "/headers")
            .header("", Vec::new())
            .header("", Vec::new());
        let error = FakeTransportBuilder::new(request_limits)
            .push(request, TransportResponsePlan::new(200))
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::TransportHeaderCountTooLarge);
        assert!(matches!(
            error,
            TransportError::HeaderCountTooLarge {
                direction: TransportHeaderDirection::Request,
                actual: 2,
                limit: 1,
            }
        ));
    }

    #[test]
    fn event_byte_capacity_can_be_cleared_without_resetting_script() {
        let limits = limits().with_total_event_bytes_limit(4);
        let request = TransportRequest::new("GET", "/");
        let transport = FakeTransportBuilder::new(limits)
            .push(
                request.clone(),
                TransportResponsePlan::new(200).body(b"x".to_vec()),
            )
            .unwrap()
            .build();
        let mut exchange = transport.send(request).unwrap();
        assert_eq!(transport.event_bytes(), 4);
        assert_eq!(
            exchange.next_step().unwrap_err().code(),
            ErrorCode::TransportCapacity
        );
        transport.clear_events();
        assert_eq!(transport.event_bytes(), 0);
        assert_eq!(
            exchange.next_step().unwrap(),
            Some(TransportStep::Data(b"x".to_vec()))
        );
    }

    #[test]
    fn transport_sequence_overflow_does_not_accept_request() {
        let request = TransportRequest::new("GET", "/");
        let transport = FakeTransportBuilder::new(limits())
            .push(request.clone(), TransportResponsePlan::new(200))
            .unwrap()
            .build();
        recover_lock(&transport.state).next_sequence = u64::MAX;
        assert_eq!(
            transport.send(request).unwrap_err().code(),
            ErrorCode::TransportSequenceOverflow
        );
        assert_eq!(transport.accepted_count(), 0);
        assert!(transport.events().is_empty());
    }

    #[test]
    fn exchange_cancellation_is_explicit_at_each_boundary() {
        let mut cancel_limits = limits();
        cancel_limits.max_script_entries = 8;
        let before_request = TransportRequest::new("GET", "/cancel-before");
        let data_request = TransportRequest::new("GET", "/cancel-data");
        let delay_request = TransportRequest::new("GET", "/cancel-delay");
        let response = TransportResponseBuilder::new(200)
            .chunk(b"body".to_vec())
            .delay(Duration::from_secs(1))
            .build(cancel_limits)
            .unwrap();
        let transport = FakeTransportBuilder::new(cancel_limits)
            .push(before_request.clone(), TransportResponsePlan::new(200))
            .unwrap()
            .push(data_request.clone(), response)
            .unwrap()
            .push(
                delay_request.clone(),
                TransportResponseBuilder::new(200)
                    .chunk(b"body".to_vec())
                    .delay(Duration::from_secs(1))
                    .build(cancel_limits)
                    .unwrap(),
            )
            .unwrap()
            .push(
                TransportRequest::new("GET", "/complete"),
                TransportResponsePlan::new(200),
            )
            .unwrap()
            .push(
                TransportRequest::new("GET", "/reset"),
                TransportResponseBuilder::new(503)
                    .reset(None)
                    .build(cancel_limits)
                    .unwrap(),
            )
            .unwrap()
            .build();

        let mut before_steps = transport.send(before_request).unwrap();
        assert!(before_steps.cancel().unwrap());
        assert!(before_steps.is_cancelled());
        assert_eq!(
            before_steps.finish().unwrap_err().code(),
            ErrorCode::TransportCancelled
        );
        assert_eq!(
            before_steps.next_step().unwrap_err().code(),
            ErrorCode::TransportCancelled
        );
        assert!(!before_steps.cancel().unwrap());
        assert!(matches!(
            transport.events().last(),
            Some(TransportEvent::ExchangeCancelled { .. })
        ));

        let mut after_data = transport.send(data_request).unwrap();
        assert_eq!(
            after_data.next_step().unwrap(),
            Some(TransportStep::Data(b"body".to_vec()))
        );
        assert!(after_data.cancel().unwrap());
        assert_eq!(after_data.collected_body(), b"body");

        let mut after_delay = transport.send(delay_request).unwrap();
        assert_eq!(
            after_delay.next_step().unwrap(),
            Some(TransportStep::Data(b"body".to_vec()))
        );
        assert_eq!(
            after_delay.next_step().unwrap(),
            Some(TransportStep::Delay(Duration::from_secs(1)))
        );
        assert!(after_delay.cancel().unwrap());
        assert_eq!(
            after_delay.finish().unwrap_err().code(),
            ErrorCode::TransportCancelled
        );

        let mut complete = transport
            .send(TransportRequest::new("GET", "/complete"))
            .unwrap();
        assert_eq!(complete.next_step().unwrap(), Some(TransportStep::End));
        assert!(!complete.cancel().unwrap());
        assert!(complete.finish().is_ok());

        let mut reset = transport
            .send(TransportRequest::new("GET", "/reset"))
            .unwrap();
        assert_eq!(
            reset.next_step().unwrap_err().code(),
            ErrorCode::TransportReset
        );
        assert!(!reset.cancel().unwrap());
        let cancellation_steps = transport
            .events()
            .into_iter()
            .filter_map(|event| match event {
                TransportEvent::ExchangeCancelled { step, .. } => Some(step),
                TransportEvent::RequestAccepted { .. } | TransportEvent::Step { .. } => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(cancellation_steps, vec![0, 1, 2]);
    }

    #[test]
    fn exchange_cancel_capacity_failure_does_not_change_state() {
        let mut limits = limits();
        limits.max_events = 1;
        let request = TransportRequest::new("GET", "/cancel-capacity");
        let transport = FakeTransportBuilder::new(limits)
            .push(request.clone(), TransportResponsePlan::new(200))
            .unwrap()
            .build();
        let mut exchange = transport.send(request).unwrap();
        let before_events = transport.events();
        assert_eq!(
            exchange.cancel().unwrap_err().code(),
            ErrorCode::TransportCapacity
        );
        assert!(!exchange.is_cancelled());
        assert!(!exchange.is_finished());
        assert_eq!(transport.events(), before_events);
        transport.clear_events();
        assert_eq!(exchange.next_step().unwrap(), Some(TransportStep::End));
    }

    #[test]
    fn dropping_exchange_is_explicitly_non_cancelling() {
        let request = TransportRequest::new("GET", "/drop");
        let transport = FakeTransportBuilder::new(limits())
            .push(request.clone(), TransportResponsePlan::new(200))
            .unwrap()
            .build();
        let exchange = transport.send(request).unwrap();
        let before = transport.events().len();
        drop(exchange);
        assert_eq!(transport.events().len(), before);
        assert_eq!(
            transport.assert_no_leaks().unwrap_err(),
            TransportLeakError::ActiveExchanges { active: 1 }
        );
    }

    #[test]
    fn owned_exchange_drop_cancels_and_is_visible_to_owner_checks() {
        let request = TransportRequest::new("GET", "/owned");
        let transport = FakeTransportBuilder::new(limits())
            .push(request.clone(), TransportResponsePlan::new(200))
            .unwrap()
            .build();
        let exchange = transport.send_owned(request).unwrap();
        assert!(exchange.is_owned());
        drop(exchange);
        assert_eq!(transport.active_exchange_count(), 0);
        assert!(matches!(
            transport.events().last(),
            Some(TransportEvent::ExchangeCancelled { .. })
        ));
        transport.assert_no_leaks().unwrap();
    }

    #[test]
    fn owned_exchange_drop_failure_is_reported_as_a_leak() {
        let mut limits = limits();
        limits.max_events = 1;
        let request = TransportRequest::new("GET", "/owned-drop-failure");
        let transport = FakeTransportBuilder::new(limits)
            .push(request.clone(), TransportResponsePlan::new(200))
            .unwrap()
            .build();
        let exchange = transport.send_owned(request).unwrap();
        drop(exchange);
        assert_eq!(
            transport.assert_no_leaks().unwrap_err(),
            TransportLeakError::DropCancellationFailed { failures: 1 }
        );
        assert_eq!(transport.active_exchange_count(), 1);
    }

    #[test]
    fn delay_limits_are_per_step_aggregate_and_checked() {
        let limits = limits()
            .with_delay_per_step_limit(Duration::from_secs(2))
            .with_total_delay_limit(Duration::from_secs(3));
        let too_large = TransportResponseBuilder::new(200)
            .delay(Duration::from_secs(3))
            .build(limits)
            .unwrap_err();
        assert_eq!(too_large.code(), ErrorCode::TransportDelayTooLarge);

        let aggregate = TransportResponseBuilder::new(200)
            .delay(Duration::from_secs(2))
            .delay(Duration::from_secs(2))
            .build(limits)
            .unwrap_err();
        assert_eq!(aggregate.code(), ErrorCode::TransportDelayAggregateTooLarge);

        let overflow = TransportResponsePlan {
            status: 200,
            headers: Vec::new(),
            steps: vec![
                TransportStep::Delay(Duration::MAX),
                TransportStep::Delay(Duration::MAX),
                TransportStep::End,
            ],
        }
        .validate(
            TransportLimits::default()
                .with_delay_per_step_limit(Duration::MAX)
                .with_total_delay_limit(Duration::MAX),
        )
        .unwrap_err();
        assert_eq!(overflow.code(), ErrorCode::TransportDelayAggregateTooLarge);
    }

    #[test]
    fn transport_debug_projections_omit_request_and_response_bytes() {
        let limits = TransportLimits::new(4, 64, 64, 8, 16);
        let request = TransportRequest::new("POST", "/secret?token=secret-target")
            .header("Authorization", b"secret-header".to_vec())
            .body(b"secret-request-body".to_vec());
        let response = TransportResponseBuilder::new(200)
            .header("Set-Cookie", b"secret-cookie".to_vec())
            .body(b"secret-response-body".to_vec())
            .build(limits)
            .unwrap();
        let transport = FakeTransportBuilder::new(limits)
            .push(request.clone(), response)
            .unwrap()
            .build();
        let mut exchange = transport.send(request.clone()).unwrap();
        let mismatch = TransportError::RequestMismatch {
            position: 0,
            expected: Box::new(request.clone()),
            actual: Box::new(TransportRequest::new("POST", "/different")),
        };
        let output = format!(
            "{:?}{:?}{:?}{:?}",
            request,
            exchange.next_step().unwrap(),
            transport.events(),
            mismatch
        );
        assert!(!output.contains("secret-header"));
        assert!(!output.contains("secret-request-body"));
        assert!(!output.contains("secret-response-body"));
        assert!(!output.contains("secret-target"));
    }
}
