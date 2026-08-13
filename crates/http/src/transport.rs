// SPDX-License-Identifier: Apache-2.0
//! Transport capability passed to the HTTP semantic client.

use crate::TimeoutPhase;
use crate::TransportError;
use crate::clock::Clock;
use crate::clock::{ClockReading, Deadline};
use crate::policy::{
    DecompressionPolicy, HttpVersionPolicy, RetryPolicy, Route, TimeoutConfig, TlsConfig,
    validate_response_body_limit,
};
use crate::request::Request;
use crate::response::{
    ByteAccounting, DecompressionObservation, Response, ResponseBodyPresence,
    ResponseHeadObservation, ResponsePresence, ResponseTiming, TransportResponseObservation,
};
use crate::state::DnsCache;
use crate::url::Url;
use std::sync::atomic::AtomicU64;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

/// Explicit cancellation capability shared by a logical operation and its
/// adapter.  It is deliberately independent of any executor.
#[derive(Clone, Default)]
pub struct CancellationToken {
    state: Arc<CancellationState>,
}

type CancellationWake = Arc<dyn Fn() + Send + Sync + 'static>;

/// Maximum number of in-flight adapter wake registrations retained by one
/// cancellation token. Keeping this finite prevents a long-lived operation
/// from turning cancellation into an unbounded callback allocation.
pub const MAX_CANCELLATION_WAKERS: usize = 64;

struct CancellationState {
    cancelled: AtomicBool,
    callbacks: Mutex<Vec<(u64, CancellationWake)>>,
    next_callback: AtomicU64,
}

impl Default for CancellationState {
    fn default() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            callbacks: Mutex::new(Vec::new()),
            next_callback: AtomicU64::new(0),
        }
    }
}

/// Registration returned by [`CancellationToken::register_waker`].
///
/// Dropping the registration removes the callback, which keeps a long-lived
/// token from retaining per-request adapter state after an operation ends.
pub struct CancellationRegistration {
    state: Option<std::sync::Weak<CancellationState>>,
    id: u64,
}

impl std::fmt::Debug for CancellationRegistration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CancellationRegistration")
            .field("registered", &self.state.is_some())
            .finish()
    }
}

impl CancellationRegistration {
    /// Returns whether this registration occupies a slot in the token.
    ///
    /// A `false` value means cancellation was already requested, the bounded
    /// registration table was full, or the registration id space was
    /// exhausted. In all three cases the wake callback has already run and an
    /// adapter must check cancellation before entering a blocking operation.
    #[must_use]
    pub const fn is_registered(&self) -> bool {
        self.state.is_some()
    }
}

impl Drop for CancellationRegistration {
    fn drop(&mut self) {
        let Some(state) = self.state.take().and_then(|state| state.upgrade()) else {
            return;
        };
        let mut callbacks = state
            .callbacks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        callbacks.retain(|(id, _)| *id != self.id);
    }
}

impl std::fmt::Debug for CancellationToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CancellationToken")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

impl PartialEq for CancellationToken {
    fn eq(&self, other: &Self) -> bool {
        self.is_cancelled() == other.is_cancelled()
    }
}

impl Eq for CancellationToken {}

impl CancellationToken {
    /// Requests cancellation of the logical operation.
    pub fn cancel(&self) {
        if self.state.cancelled.swap(true, Ordering::AcqRel) {
            return;
        }
        let callbacks = std::mem::take(
            &mut *self
                .state
                .callbacks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for (_, callback) in callbacks {
            callback();
        }
    }

    /// Returns whether cancellation was requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.state.cancelled.load(Ordering::Acquire)
    }

    /// Registers a callback that wakes an adapter's blocked read/write.
    ///
    /// The callback is invoked synchronously by [`Self::cancel`].  Adapters
    /// should use a non-blocking wake/close primitive and return from their
    /// operation with [`TransportError::Cancelled`].  A callback registered
    /// after cancellation is invoked immediately and is not retained.  If
    /// the bounded registration table is full, the callback is also invoked
    /// immediately so the adapter can fail closed instead of blocking without
    /// a cancellation wake.
    pub fn register_waker<F>(&self, wake: F) -> CancellationRegistration
    where
        F: Fn() + Send + Sync + 'static,
    {
        let wake: CancellationWake = Arc::new(wake);
        if self.is_cancelled() {
            wake();
            return CancellationRegistration { state: None, id: 0 };
        }
        let id = match self.state.next_callback.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |next| next.checked_add(1),
        ) {
            Ok(id) => id,
            Err(_) => {
                // Do not wrap an id and accidentally remove another active
                // registration when the finite id space is exhausted.
                wake();
                return CancellationRegistration { state: None, id: 0 };
            }
        };
        let mut callbacks = self
            .state
            .callbacks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.is_cancelled() {
            drop(callbacks);
            wake();
            return CancellationRegistration { state: None, id };
        }
        if callbacks.len() >= MAX_CANCELLATION_WAKERS {
            // Keep cancellation bounded without silently dropping an older
            // blocked operation's wake callback.  Tell the newest adapter to
            // terminate cooperatively before it enters its read.
            drop(callbacks);
            wake();
            return CancellationRegistration { state: None, id };
        }
        callbacks.push((id, wake));
        CancellationRegistration {
            state: Some(Arc::downgrade(&self.state)),
            id,
        }
    }
}

/// Context supplied for every transport attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportContext {
    /// Explicitly selected direct/proxy route.
    pub route: Route,
    /// Per-phase timeout settings.
    pub timeouts: TimeoutConfig,
    /// Overall deadline, if configured.
    pub deadline: Option<Deadline>,
    /// Explicit TLS policy.
    pub tls: TlsConfig,
    /// Explicit HTTP protocol version policy.
    pub http_version: HttpVersionPolicy,
    /// Explicit response decompression policy.
    pub decompression: DecompressionPolicy,
    /// Explicit retry ownership policy.
    pub retries: RetryPolicy,
    /// Bounded per-user DNS state available to the adapter.
    ///
    /// The semantic core never resolves names itself.  Passing this bounded
    /// snapshot through the context prevents a production adapter from
    /// silently falling back to an unbounded process-global resolver cache.
    /// Adapters that resolve a name may use the snapshot for lookup and
    /// return updated records through their own transport-owned capability;
    /// the core remains responsible for the per-user bound.
    pub dns: DnsCache,
    /// Zero-based redirect/attempt number.
    pub attempt: usize,
    /// Clock reading taken immediately before dispatch.
    pub started_at: ClockReading,
    /// Explicit cancellation state for this operation.
    pub cancellation: CancellationToken,
}

impl TransportContext {
    /// Returns the selected route.
    #[must_use]
    pub const fn route(&self) -> &Route {
        &self.route
    }

    /// Computes a phase deadline from this attempt's start reading.
    #[must_use]
    pub fn phase_deadline(&self, phase: TimeoutPhase) -> Option<Deadline> {
        self.timeouts
            .for_phase(phase)
            .and_then(|duration| Deadline::after(self.started_at, duration))
    }

    /// Returns the earlier of the phase and overall deadlines.
    #[must_use]
    pub fn effective_deadline(&self, phase: TimeoutPhase) -> Option<Deadline> {
        match (self.deadline, self.phase_deadline(phase)) {
            (Some(overall), Some(phase)) => Some(Deadline {
                at: overall.at.min(phase.at),
            }),
            (Some(overall), None) => Some(overall),
            (None, Some(phase)) => Some(phase),
            (None, None) => None,
        }
    }

    /// Returns whether the adapter must stop work before reading/writing more
    /// bytes.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    /// Returns whether an absolute deadline has expired at `now`.
    #[must_use]
    pub fn deadline_expired(&self, now: ClockReading) -> bool {
        self.deadline.is_some_and(|deadline| deadline.expired(now))
    }

    /// Returns remaining overall time at `now`, if a deadline exists.
    #[must_use]
    pub fn remaining(&self, now: ClockReading) -> Option<std::time::Duration> {
        self.deadline.and_then(|deadline| deadline.remaining(now))
    }

    /// Reads a non-expired DNS record from the bounded per-user snapshot.
    #[must_use]
    pub fn dns_lookup(&self, host: &str, now: ClockReading) -> Option<Vec<String>> {
        self.dns.lookup_ref(host, now)
    }
}

/// Adapter body stream. Implementations must honor the supplied maximum and
/// return chunks no larger than it; the semantic client checks this again
/// before appending, so a faulty adapter cannot force unbounded materializing.
pub trait ResponseBody {
    /// Returns the next bounded chunk, or `None` at end of stream.
    fn next_chunk(&mut self, maximum_bytes: usize) -> Result<Option<Vec<u8>>, TransportError>;

    /// Returns explicit response-head/body presence and ordered informational
    /// observations associated with this stream.
    ///
    /// The default is intentionally all-absent so a legacy body cannot cause
    /// the collector to infer a present-empty entity from an empty stream.
    /// Existing adapters remain source-compatible because this method has a
    /// default implementation; adapters that expose wire metadata should use
    /// [`TransportResponse::with_observation`] or the builder methods instead
    /// of overriding it directly.
    #[must_use]
    fn response_observation(&self) -> TransportResponseObservation {
        TransportResponseObservation::default()
    }

    /// Returns the next chunk while exposing cancellation and deadline
    /// controls to a streaming adapter.
    ///
    /// The default delegates to [`Self::next_chunk`] for existing adapters.
    /// A real adapter that may block in a read should override this method,
    /// register a wake callback with the token, and arrange for its read to
    /// terminate when the callback fires.  The semantic core checks the
    /// controls both before and after every chunk, so cooperative adapters
    /// cannot continue materializing after cancellation or timeout.
    fn next_chunk_with_control(
        &mut self,
        maximum_bytes: usize,
        cancellation: &CancellationToken,
        deadline: Option<Deadline>,
        clock: Option<&dyn Clock>,
    ) -> Result<Option<Vec<u8>>, TransportError> {
        if cancellation.is_cancelled() {
            return Err(TransportError::Cancelled);
        }
        if deadline.is_some() && clock.is_none() {
            return Err(TransportError::Unsupported(
                "deadline checking requires a clock capability".to_owned(),
            ));
        }
        if deadline.is_some_and(|deadline| clock.is_some_and(|clock| deadline.expired(clock.now())))
        {
            return Err(TransportError::Timeout(TimeoutPhase::Overall));
        }
        self.next_chunk(maximum_bytes)
    }
}

#[cfg(test)]
#[derive(Debug)]
struct OwnedResponseBody {
    body: Option<Vec<u8>>,
}

#[cfg(test)]
impl ResponseBody for OwnedResponseBody {
    fn next_chunk(&mut self, maximum_bytes: usize) -> Result<Option<Vec<u8>>, TransportError> {
        let Some(body) = self.body.take() else {
            return Ok(None);
        };
        if body.is_empty() {
            return Ok(None);
        }
        if body.len() > maximum_bytes {
            return Err(TransportError::ResourceLimit(
                "adapter response chunk exceeds configured bound".to_owned(),
            ));
        }
        Ok(Some(body))
    }
}

/// Response-body decorator used by the compatibility-preserving transport
/// builders.  Metadata is kept beside the body stream so adding presence and
/// informational fields does not invalidate existing public struct literals.
struct ObservedResponseBody {
    inner: Box<dyn ResponseBody>,
    observation: TransportResponseObservation,
}

impl ResponseBody for ObservedResponseBody {
    fn next_chunk(&mut self, maximum_bytes: usize) -> Result<Option<Vec<u8>>, TransportError> {
        self.inner.next_chunk(maximum_bytes)
    }

    fn response_observation(&self) -> TransportResponseObservation {
        self.observation.clone()
    }

    fn next_chunk_with_control(
        &mut self,
        maximum_bytes: usize,
        cancellation: &CancellationToken,
        deadline: Option<Deadline>,
        clock: Option<&dyn Clock>,
    ) -> Result<Option<Vec<u8>>, TransportError> {
        self.inner
            .next_chunk_with_control(maximum_bytes, cancellation, deadline, clock)
    }
}

/// Response metadata plus a bounded body stream returned by an adapter.
pub struct TransportResponse {
    /// Numeric response status.
    pub status: u16,
    /// Optional reason phrase.
    pub reason: String,
    /// Response headers, validated by the semantic client before collection.
    pub headers: crate::Headers,
    /// Body stream.
    pub body: Box<dyn ResponseBody>,
    /// Adapter-provided byte counters.
    pub bytes: ByteAccounting,
    /// Adapter timing observations.
    pub timing: ResponseTiming,
    /// Adapter-reported final URL, when available.
    pub url: Option<Url>,
    /// Wire protocol version observed by the adapter, when exposed.
    pub protocol: Option<crate::ProtocolVersion>,
    /// Entity framing observed by the adapter, when exposed.
    pub framing: Option<crate::Framing>,
    /// Explicit decompression observations, when the adapter exposes them.
    ///
    /// `None` is intentional: collection must not infer an identity coding or
    /// wire/decoded counter merely from the materialized body and byte totals.
    pub decompression: Option<DecompressionObservation>,
}

fn map_observation_error(error: crate::HttpError) -> TransportError {
    match error {
        crate::HttpError::ResourceLimit(message) => TransportError::ResourceLimit(message),
        crate::HttpError::ResponseBodyLimit { .. } => {
            TransportError::ResourceLimit("response body observation limit".to_owned())
        }
        crate::HttpError::Transport(error) => error,
        crate::HttpError::Timeout(phase) => TransportError::Timeout(phase),
        crate::HttpError::Cancelled => TransportError::Cancelled,
        crate::HttpError::Unsupported(message) => TransportError::Unsupported(message),
        _ => TransportError::Protocol("invalid response observation".to_owned()),
    }
}

impl std::fmt::Debug for TransportResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TransportResponse")
            .field("status", &self.status)
            .field("reason_bytes", &self.reason.len())
            .field("headers", &self.headers)
            .field("bytes", &self.bytes)
            .field("timing", &self.timing)
            .field("url", &self.url)
            .field("protocol", &self.protocol)
            .field("framing", &self.framing)
            .field("decompression", &self.decompression)
            .finish()
    }
}

impl TransportResponse {
    /// Wraps a materialized response for an in-crate deterministic fixture.
    ///
    /// This helper is intentionally unavailable to production adapters.  A
    /// materialized response has already paid its allocation cost before the
    /// semantic body bound can be checked; production transports must create a
    /// bounded [`ResponseBody`] directly.
    #[must_use]
    #[cfg(test)]
    #[allow(
        clippy::expect_used,
        reason = "the test-only adapter fixture must fail closed if its source metadata is invalid"
    )]
    pub(crate) fn from_response_for_test(response: Response) -> Self {
        let decompression = response.decompression();
        let transport = Self {
            status: response.status(),
            reason: response.reason().to_owned(),
            headers: response.headers().clone(),
            body: Box::new(OwnedResponseBody {
                body: Some(response.body().to_vec()),
            }),
            bytes: response.bytes(),
            timing: response.timing(),
            url: response.url().cloned(),
            protocol: response.protocol(),
            framing: response.framing(),
            decompression: (decompression != DecompressionObservation::default())
                .then_some(decompression),
        };
        transport
            .with_observation(TransportResponseObservation {
                reason: match response.reason_presence() {
                    ResponsePresence::Absent => ResponsePresence::Absent,
                    ResponsePresence::Present(reason) => {
                        ResponsePresence::Present(reason.to_owned())
                    }
                },
                body: response.body_presence(),
                informational_responses: response.informational_responses().to_vec(),
            })
            .expect("response test observation is bounded")
    }

    /// Attaches explicit response presence and informational observations.
    ///
    /// This is the preferred constructor path for adapters.  The metadata is
    /// stored in a body-stream sidecar to preserve source compatibility for
    /// existing `TransportResponse` struct literals.  Calling this method a
    /// second time replaces the previous observation; it never merges or
    /// infers fields from the replaced value.
    pub fn with_observation(
        self,
        observation: TransportResponseObservation,
    ) -> Result<Self, TransportError> {
        observation.validate().map_err(map_observation_error)?;
        Ok(Self {
            status: self.status,
            reason: self.reason,
            headers: self.headers,
            body: Box::new(ObservedResponseBody {
                inner: self.body,
                observation,
            }),
            bytes: self.bytes,
            timing: self.timing,
            url: self.url,
            protocol: self.protocol,
            framing: self.framing,
            decompression: self.decompression,
        })
    }

    /// Attaches explicit final reason/body presence with no informational
    /// responses.
    pub fn with_presence(
        self,
        reason: ResponsePresence<String>,
        body: ResponseBodyPresence,
    ) -> Result<Self, TransportError> {
        self.with_observation(TransportResponseObservation::new(reason, body))
    }

    /// Attaches an ordered informational response list while retaining
    /// explicit final reason/body presence.
    pub fn with_informational_responses(
        self,
        reason: ResponsePresence<String>,
        body: ResponseBodyPresence,
        informational_responses: Vec<ResponseHeadObservation>,
    ) -> Result<Self, TransportError> {
        self.with_observation(TransportResponseObservation {
            reason,
            body,
            informational_responses,
        })
    }

    /// Returns the explicit response observations carried by this transport
    /// response.  Legacy struct literals return the all-absent default; this
    /// method never derives presence from the public reason string, status,
    /// counters, or body stream.
    #[must_use]
    pub fn response_observation(&self) -> TransportResponseObservation {
        self.body.response_observation()
    }

    /// Collects a bounded body into the public response model.
    pub fn collect(self, maximum_body_bytes: usize) -> Result<Response, TransportError> {
        self.collect_with_cancellation(maximum_body_bytes, &CancellationToken::default())
    }

    /// Collects a bounded body while checking explicit cancellation between
    /// chunks.
    pub fn collect_with_cancellation(
        self,
        maximum_body_bytes: usize,
        cancellation: &CancellationToken,
    ) -> Result<Response, TransportError> {
        self.collect_with_limits(maximum_body_bytes, cancellation, None, None)
    }

    /// Collects a bounded body while checking cancellation and an injected
    /// overall deadline between adapter chunks.
    pub fn collect_with_limits(
        self,
        maximum_body_bytes: usize,
        cancellation: &CancellationToken,
        deadline: Option<Deadline>,
        clock: Option<&dyn Clock>,
    ) -> Result<Response, TransportError> {
        self.collect_with_deadline(
            maximum_body_bytes,
            cancellation,
            deadline,
            clock,
            TimeoutPhase::Overall,
        )
    }

    /// Collects a bounded body and reports a timeout in the supplied phase.
    pub fn collect_with_deadline(
        mut self,
        maximum_body_bytes: usize,
        cancellation: &CancellationToken,
        deadline: Option<Deadline>,
        clock: Option<&dyn Clock>,
        timeout_phase: TimeoutPhase,
    ) -> Result<Response, TransportError> {
        // `HttpError` diagnostics are intentionally redacted by `Display`.
        // Do not convert that presentation string into the transport's stable
        // category: this boundary already knows the closed limit kind.
        validate_response_body_limit(maximum_body_bytes)
            .map_err(|_| TransportError::ResourceLimit("wire-response".to_owned()))?;
        if !crate::response::is_valid_status_code(self.status) {
            return Err(TransportError::Protocol(
                "response status code is outside 100..=599".to_owned(),
            ));
        }
        if deadline.is_some() && clock.is_none() {
            return Err(TransportError::Unsupported(
                "deadline checking requires a clock capability".to_owned(),
            ));
        }
        let observation = self.body.response_observation();
        observation.validate().map_err(map_observation_error)?;
        let mut body = Vec::new();
        loop {
            if cancellation.is_cancelled() {
                return Err(TransportError::Cancelled);
            }
            if deadline
                .is_some_and(|deadline| clock.is_some_and(|clock| deadline.expired(clock.now())))
            {
                return Err(TransportError::Timeout(timeout_phase));
            }
            let remaining = maximum_body_bytes.checked_sub(body.len()).ok_or_else(|| {
                TransportError::ResourceLimit("response body byte accounting".to_owned())
            })?;
            let chunk = self
                .body
                .next_chunk_with_control(remaining, cancellation, deadline, clock)
                .map_err(|error| match error {
                    // A legacy body implementation only knows that its
                    // deadline expired and reports Overall.  Once the
                    // semantic collector has selected a phase, preserve that
                    // attribution instead of turning a read timeout into an
                    // indistinguishable overall timeout.  The public
                    // collect_with_limits path passes Overall and is
                    // unaffected.
                    TransportError::Timeout(TimeoutPhase::Overall)
                        if timeout_phase != TimeoutPhase::Overall =>
                    {
                        TransportError::Timeout(timeout_phase)
                    }
                    other => other,
                })?;
            if cancellation.is_cancelled() {
                return Err(TransportError::Cancelled);
            }
            if deadline
                .is_some_and(|deadline| clock.is_some_and(|clock| deadline.expired(clock.now())))
            {
                return Err(TransportError::Timeout(timeout_phase));
            }
            let Some(chunk) = chunk else {
                break;
            };
            if chunk.len() > remaining {
                return Err(TransportError::ResourceLimit(
                    "response body exceeds configured bound".to_owned(),
                ));
            }
            if chunk.is_empty() {
                return Err(TransportError::Protocol(
                    "response body stream returned an empty chunk".to_owned(),
                ));
            }
            body.extend_from_slice(&chunk);
        }
        let collected_len = u64::try_from(body.len())
            .map_err(|_| TransportError::ResourceLimit("response body byte counter".to_owned()))?;
        if observation.body == ResponseBodyPresence::Absent && self.bytes.received_body != 0 {
            return Err(TransportError::Protocol(
                "adapter received-body counter is nonzero while body presence was absent"
                    .to_owned(),
            ));
        }
        if self.bytes.received_body == 0 {
            self.bytes.received_body = collected_len;
        } else if self.bytes.received_body < collected_len {
            return Err(TransportError::Protocol(
                "adapter received-body counter is smaller than collected body".to_owned(),
            ));
        }
        let mut response = Response::new(self.status);
        match observation.body {
            ResponseBodyPresence::Absent if !body.is_empty() => {
                return Err(TransportError::Protocol(
                    "response body bytes arrived while body presence was absent".to_owned(),
                ));
            }
            ResponseBodyPresence::Absent => response.set_body_absent(),
            ResponseBodyPresence::Present => response.set_body(body).map_err(|_| {
                TransportError::ResourceLimit("response body byte counter".to_owned())
            })?,
        }
        match observation.reason {
            ResponsePresence::Absent => response.set_reason_absent(),
            ResponsePresence::Present(reason) => response
                .set_reason_bounded(&reason)
                .map_err(map_observation_error)?,
        }
        for field in &self.headers {
            response.headers_mut().append(field.clone());
        }
        response.set_bytes(self.bytes);
        response.set_timing(self.timing);
        if let Some(url) = self.url {
            response.set_url(url);
        }
        if let Some(protocol) = self.protocol {
            response.set_protocol(protocol);
        }
        if let Some(framing) = self.framing {
            response.set_framing(framing);
        }
        response
            .set_informational_responses(observation.informational_responses)
            .map_err(map_observation_error)?;
        // Response::with_body and Response::set_bytes maintain convenient
        // local accounting defaults.  They are not adapter observations, so
        // always replace those defaults with the explicit adapter value (or
        // with an all-absent value when the adapter did not expose one).
        response
            .set_decompression(self.decompression.unwrap_or_default())
            .map_err(|error| match error {
                crate::HttpError::ResourceLimit(message) => TransportError::ResourceLimit(message),
                crate::HttpError::ResponseBodyLimit { .. } => {
                    TransportError::ResourceLimit("response body observation limit".to_owned())
                }
                crate::HttpError::Transport(error) => error,
                crate::HttpError::Timeout(phase) => TransportError::Timeout(phase),
                crate::HttpError::Cancelled => TransportError::Cancelled,
                crate::HttpError::Unsupported(message) => TransportError::Unsupported(message),
                _ => TransportError::Protocol("invalid response observation".to_owned()),
            })?;
        Ok(response)
    }
}

/// In-process transport capability.
///
/// This trait is the executor-neutral seam for the semantic HTTP client. A
/// concrete application adapter owns the executor, sockets, DNS, proxy relay,
/// and TLS implementation; this crate only supplies the request/context and
/// consumes a bounded response stream. Deterministic tests can implement the
/// seam without opening a socket.
pub trait Transport {
    /// Sends one already constructed request and returns one materialized
    /// response.
    ///
    /// This legacy hook is retained for source compatibility with simple
    /// deterministic fixtures, but it is not a client execution path.  A
    /// production adapter must implement [`Transport::send_stream`] so the
    /// response body bound is enforced before materialization.
    fn send(
        &mut self,
        request: &Request,
        context: &TransportContext,
    ) -> Result<Response, TransportError> {
        let _ = (request, context);
        Err(TransportError::Unsupported(
            "transport adapter must implement bounded streaming".to_owned(),
        ))
    }

    /// Sends one response through a bounded body seam.
    ///
    /// The default deliberately fails instead of wrapping [`Self::send`]:
    /// doing so would let a materialized response bypass the semantic body's
    /// preallocation bound.  A transport that owns a streaming adapter must
    /// implement this method explicitly.
    fn send_stream(
        &mut self,
        request: &Request,
        context: &TransportContext,
    ) -> Result<TransportResponse, TransportError> {
        let _ = (request, context);
        Err(TransportError::Unsupported(
            "transport adapter must implement bounded streaming".to_owned(),
        ))
    }

    /// Sends one request through a cooperative cancellation/deadline seam.
    ///
    /// A socket adapter that can block in connect/write/read should override
    /// this method, register `context.cancellation.register_waker(...)`, and
    /// close/wake its owned operation from that callback.  The default checks
    /// cancellation before dispatch and then delegates to the required
    /// bounded-streaming seam.
    fn send_with_control(
        &mut self,
        request: &Request,
        context: &TransportContext,
    ) -> Result<TransportResponse, TransportError> {
        if context.is_cancelled() {
            return Err(TransportError::Cancelled);
        }
        self.send_stream(request, context)
    }
}

/// Compatibility alias for adapters that call the capability a sender.
pub trait TransportAdapter: Transport {}

impl<T: Transport + ?Sized> TransportAdapter for T {}

/// A transport that always reports an explicit unavailable-capability error.
#[derive(Clone, Copy, Debug)]
pub struct UnsupportedTransport;

impl Transport for UnsupportedTransport {
    fn send(
        &mut self,
        _request: &Request,
        _context: &TransportContext,
    ) -> Result<Response, TransportError> {
        Err(TransportError::Unsupported(
            "no HTTP transport adapter is configured".to_owned(),
        ))
    }

    fn send_stream(
        &mut self,
        _request: &Request,
        _context: &TransportContext,
    ) -> Result<TransportResponse, TransportError> {
        Err(TransportError::Unsupported(
            "no HTTP transport adapter is configured".to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "transport tests use expect at assertion boundaries for fixed in-process fixtures"
    )]

    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn collection_rejects_zero_body_bound_before_reading() {
        let response = TransportResponse::from_response_for_test(Response::new(200));
        let error = response
            .collect(0)
            .expect_err("zero is not an enabled body bound");
        assert_eq!(
            error.limit_code(),
            Some(crate::error::HttpLimitCode::WireResponseBody)
        );
        assert_eq!(error.stable_code(), "http.limit.wire-response-body");
    }

    #[test]
    fn collection_accepts_a_body_exactly_at_the_configured_bound() {
        let response = TransportResponse::from_response_for_test(
            Response::with_body(200, b"four".to_vec()).expect("response"),
        );
        let collected = response.collect(4).expect("exactly bounded body");
        assert_eq!(collected.body(), b"four");
    }

    #[test]
    fn collection_projects_explicit_protocol_framing_and_decompression() {
        let response = TransportResponse {
            status: 200,
            reason: "OK".to_owned(),
            headers: crate::Headers::new(),
            body: Box::new(OwnedResponseBody {
                body: Some(b"body".to_vec()),
            }),
            bytes: ByteAccounting::new(0, 0, 12, 4),
            timing: ResponseTiming::default(),
            url: None,
            protocol: Some(crate::ProtocolVersion::Http2),
            framing: Some(crate::Framing::Http2Data),
            decompression: Some(DecompressionObservation {
                coding: Some(crate::Compression::Gzip),
                wire_bytes: Some(8),
                decoded_bytes: Some(4),
                expansion_ratio: Some(1),
            }),
        }
        .with_presence(
            ResponsePresence::Present("OK".to_owned()),
            ResponseBodyPresence::Present,
        )
        .expect("response observation");

        let collected = response.collect(16).expect("bounded response");
        assert_eq!(collected.protocol(), Some(crate::ProtocolVersion::Http2));
        assert_eq!(collected.framing(), Some(crate::Framing::Http2Data));
        assert_eq!(
            collected.decompression(),
            DecompressionObservation {
                coding: Some(crate::Compression::Gzip),
                wire_bytes: Some(8),
                decoded_bytes: Some(4),
                expansion_ratio: Some(1),
            }
        );
        assert_eq!(collected.compression(), Some(crate::Compression::Gzip));
    }

    #[test]
    fn collection_keeps_unobserved_protocol_framing_and_decompression_absent() {
        let response = TransportResponse {
            status: 200,
            reason: String::new(),
            headers: crate::Headers::new(),
            body: Box::new(OwnedResponseBody {
                body: Some(Vec::new()),
            }),
            bytes: ByteAccounting::default(),
            timing: ResponseTiming::default(),
            url: None,
            protocol: None,
            framing: None,
            decompression: None,
        }
        .with_presence(ResponsePresence::Absent, ResponseBodyPresence::Absent)
        .expect("response observation");

        let collected = response.collect(16).expect("bounded response");
        assert_eq!(collected.protocol(), None);
        assert_eq!(collected.framing(), None);
        assert_eq!(
            collected.decompression(),
            DecompressionObservation::default()
        );
        assert_eq!(collected.compression(), None);
    }

    #[test]
    fn collection_does_not_infer_reason_or_body_presence_from_legacy_fields() {
        for status in [200, 204, 304] {
            let absent = TransportResponse {
                status,
                reason: String::new(),
                headers: crate::Headers::new(),
                body: Box::new(OwnedResponseBody {
                    body: Some(Vec::new()),
                }),
                bytes: ByteAccounting::default(),
                timing: ResponseTiming::default(),
                url: None,
                protocol: None,
                framing: None,
                decompression: None,
            };
            let absent = absent.collect(16).expect("legacy empty response");
            assert!(!absent.reason_present());
            assert!(!absent.body_present());
        }

        let counted_absent = TransportResponse {
            status: 204,
            reason: String::new(),
            headers: crate::Headers::new(),
            body: Box::new(OwnedResponseBody {
                body: Some(Vec::new()),
            }),
            bytes: ByteAccounting::new(0, 0, 0, 1),
            timing: ResponseTiming::default(),
            url: None,
            protocol: None,
            framing: None,
            decompression: None,
        }
        .with_presence(ResponsePresence::Absent, ResponseBodyPresence::Absent)
        .expect("absent observation");
        assert!(matches!(
            counted_absent.collect(16),
            Err(TransportError::Protocol(message))
                if message.contains("received-body counter")
        ));

        let present = TransportResponse {
            status: 204,
            reason: String::new(),
            headers: crate::Headers::new(),
            body: Box::new(OwnedResponseBody {
                body: Some(Vec::new()),
            }),
            bytes: ByteAccounting::default(),
            timing: ResponseTiming::default(),
            url: None,
            protocol: None,
            framing: None,
            decompression: None,
        }
        .with_presence(
            ResponsePresence::Present(String::new()),
            ResponseBodyPresence::Present,
        )
        .expect("explicit empty observations")
        .collect(16)
        .expect("present empty response");
        assert!(present.reason_present());
        assert!(present.body_present());

        let inferred = TransportResponse {
            status: 200,
            reason: "OK".to_owned(),
            headers: crate::Headers::new(),
            body: Box::new(OwnedResponseBody {
                body: Some(b"body".to_vec()),
            }),
            bytes: ByteAccounting::default(),
            timing: ResponseTiming::default(),
            url: None,
            protocol: None,
            framing: None,
            decompression: None,
        };
        assert!(matches!(
            inferred.collect(16),
            Err(TransportError::Protocol(message))
                if message.contains("body presence was absent")
        ));
    }

    #[test]
    fn collection_retains_ordered_informational_heads_and_limits() {
        let mut early = ResponseHeadObservation::new(103).expect("1xx status");
        early
            .set_reason_present("Early Hints")
            .expect("reason phrase");
        early
            .add_header("Link", "</asset>; rel=preload")
            .expect("informational header");
        let continue_head = ResponseHeadObservation::new(100).expect("1xx status");
        let response = TransportResponse {
            status: 200,
            reason: "OK".to_owned(),
            headers: crate::Headers::new(),
            body: Box::new(OwnedResponseBody {
                body: Some(b"ok".to_vec()),
            }),
            bytes: ByteAccounting::default(),
            timing: ResponseTiming::default(),
            url: None,
            protocol: None,
            framing: None,
            decompression: None,
        }
        .with_informational_responses(
            ResponsePresence::Present("OK".to_owned()),
            ResponseBodyPresence::Present,
            vec![early, continue_head],
        )
        .expect("informational observations")
        .collect(16)
        .expect("response collection");
        assert_eq!(
            response
                .informational_responses()
                .iter()
                .map(|head| head.status)
                .collect::<Vec<_>>(),
            [103, 100]
        );
        assert!(response.body_present());
    }

    #[test]
    fn collection_accepts_exact_product_ceiling_without_large_allocation() {
        let response = TransportResponse::from_response_for_test(
            Response::with_body(200, b"tiny".to_vec()).expect("response"),
        );
        let collected = response
            .collect(crate::HARD_MAX_RESPONSE_BODY_BYTES)
            .expect("exact hard bound is valid");
        assert_eq!(collected.body(), b"tiny");
    }

    #[test]
    fn collection_rejects_bound_above_product_ceiling_before_reading() {
        struct ReadCountingBody {
            reads: Arc<AtomicUsize>,
        }

        impl ResponseBody for ReadCountingBody {
            fn next_chunk(
                &mut self,
                _maximum_bytes: usize,
            ) -> Result<Option<Vec<u8>>, TransportError> {
                self.reads.fetch_add(1, Ordering::SeqCst);
                Ok(None)
            }
        }

        let reads = Arc::new(AtomicUsize::new(0));
        let response = TransportResponse {
            status: 200,
            reason: String::new(),
            headers: crate::Headers::new(),
            body: Box::new(ReadCountingBody {
                reads: Arc::clone(&reads),
            }),
            bytes: ByteAccounting::default(),
            timing: ResponseTiming::default(),
            url: None,
            protocol: None,
            framing: None,
            decompression: None,
        };
        let error = response
            .collect(crate::HARD_MAX_RESPONSE_BODY_BYTES + 1)
            .expect_err("a caller cannot raise the product body ceiling");
        assert_eq!(
            error.limit_code(),
            Some(crate::error::HttpLimitCode::WireResponseBody)
        );
        assert_eq!(error.stable_code(), "http.limit.wire-response-body");
        assert_eq!(reads.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn unsupported_transport_fails_through_streaming_seam() {
        let request = Request::get("http://example.test/").expect("request");
        let mut transport = UnsupportedTransport;
        let context = TransportContext {
            route: Route::Direct,
            timeouts: TimeoutConfig::default(),
            deadline: None,
            tls: TlsConfig::default(),
            http_version: HttpVersionPolicy::default(),
            decompression: DecompressionPolicy::default(),
            retries: RetryPolicy::default(),
            dns: DnsCache::default(),
            attempt: 0,
            started_at: ClockReading::new(0, std::time::Duration::ZERO),
            cancellation: CancellationToken::default(),
        };
        let error = transport
            .send_stream(&request, &context)
            .expect_err("unavailable capability");
        assert!(
            matches!(error, TransportError::Unsupported(message) if message.contains("no HTTP transport"))
        );
    }

    #[test]
    fn cancellation_waker_slots_are_bounded_and_report_overflow() {
        let token = CancellationToken::default();
        let wakes = Arc::new(AtomicUsize::new(0));
        let mut registrations = Vec::with_capacity(MAX_CANCELLATION_WAKERS);
        for _ in 0..MAX_CANCELLATION_WAKERS {
            let wakes = Arc::clone(&wakes);
            let registration = token.register_waker(move || {
                wakes.fetch_add(1, Ordering::SeqCst);
            });
            assert!(registration.is_registered());
            registrations.push(registration);
        }
        let wakes_for_overflow = Arc::clone(&wakes);
        let overflow = token.register_waker(move || {
            wakes_for_overflow.fetch_add(1, Ordering::SeqCst);
        });
        assert!(!overflow.is_registered());
        assert_eq!(wakes.load(Ordering::SeqCst), 1);
        token.cancel();
        assert_eq!(wakes.load(Ordering::SeqCst), MAX_CANCELLATION_WAKERS + 1);
        token.cancel();
        assert_eq!(wakes.load(Ordering::SeqCst), MAX_CANCELLATION_WAKERS + 1);
    }

    #[test]
    fn dropping_a_cancellation_registration_removes_its_wake() {
        let token = CancellationToken::default();
        let wakes = Arc::new(AtomicUsize::new(0));
        let wakes_for_callback = Arc::clone(&wakes);
        let registration = token.register_waker(move || {
            wakes_for_callback.fetch_add(1, Ordering::SeqCst);
        });
        assert!(registration.is_registered());
        drop(registration);
        token.cancel();
        assert_eq!(wakes.load(Ordering::SeqCst), 0);
    }
}
