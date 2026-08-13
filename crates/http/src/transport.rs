// SPDX-License-Identifier: Apache-2.0
//! Transport capability passed to the HTTP semantic client.

use crate::TimeoutPhase;
use crate::TransportError;
use crate::clock::Clock;
use crate::clock::{ClockReading, Deadline};
use crate::policy::{Route, TimeoutConfig, TlsConfig};
use crate::request::Request;
use crate::response::{ByteAccounting, Response, ResponseTiming};
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
        let id = self.state.next_callback.fetch_add(1, Ordering::Relaxed);
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
        if callbacks.len() >= 64 {
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
    pub(crate) fn from_response_for_test(response: Response) -> Self {
        Self {
            status: response.status(),
            reason: response.reason().to_owned(),
            headers: response.headers().clone(),
            body: Box::new(OwnedResponseBody {
                body: Some(response.body().to_vec()),
            }),
            bytes: response.bytes(),
            timing: response.timing(),
            url: response.url().cloned(),
        }
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
        if self.bytes.received_body == 0 {
            self.bytes.received_body = collected_len;
        } else if self.bytes.received_body < collected_len {
            return Err(TransportError::Protocol(
                "adapter received-body counter is smaller than collected body".to_owned(),
            ));
        }
        let mut response = Response::with_body(self.status, body)
            .map_err(|_| TransportError::ResourceLimit("response body byte counter".to_owned()))?;
        response.set_reason(self.reason);
        for field in &self.headers {
            response.headers_mut().append(field.clone());
        }
        response.set_bytes(self.bytes);
        response.set_timing(self.timing);
        if let Some(url) = self.url {
            response.set_url(url);
        }
        Ok(response)
    }
}

/// In-process transport capability. Production adapters may wrap hyper,
/// reqwest, or another client, while tests provide deterministic fakes.
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
}
