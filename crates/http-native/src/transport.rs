// SPDX-License-Identifier: Apache-2.0
//! Bounded, direct HTTP/1.1 socket transport.
//!
//! This module intentionally implements only the smallest native capability:
//! one direct, plain-HTTP/1.1 attempt.  TLS, proxy routing, HTTP/2,
//! decompression, and transparent retries are separate capabilities and are
//! rejected during preflight.  Response reads stop at the first bounded HTTP
//! framing boundary that can be proven; only close-delimited responses wait
//! for EOF.  The adapter never rewrites a source connection policy.

use crate::config::NativeTransportLimits;
use crate::wire::{
    EncodedRequest, ResponseCompletion, decode_response, encode_request, scan_response_completion,
};
use jmeter_rs_http::{
    ByteAccounting, CancellationRegistration, CancellationToken, DecompressionObservation,
    DecompressionPolicy, HttpVersionPolicy, Request, ResponseBody, ResponseTiming, Route,
    TimeoutPhase, TlsConfig, Transport, TransportContext, TransportError, TransportResponse,
    TransportResponseObservation,
};
use mio::{Events, Interest, Poll, Token, Waker};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Maximum bytes emitted by one private response-body chunk.
///
/// The retained response itself is bounded by [`NativeTransportLimits`], but
/// the semantic core asks a body stream for chunks.  Keeping each chunk fixed
/// and small ensures a caller cannot cause a single chunk allocation larger
/// than its current remaining body budget.
pub(crate) const BODY_CHUNK_BYTES: usize = 16 * 1024;
/// Token returned for the one in-progress connect socket.
const CONNECT_TOKEN: Token = Token(0);
/// Token returned by the one cancellation waker registered for a connect.
const CANCELLATION_TOKEN: Token = Token(1);
/// The event storage is deliberately finite.  A long-running connect is
/// bounded by its absolute deadline, not by a global readiness-event count.
const CONNECT_EVENT_CAPACITY: usize = 16;
/// A synchronous native HTTP transport.
///
/// One value is safe to reuse across attempts because it owns no sockets,
/// resolver cache, or connection pool.  Every attempt resolves and connects
/// using only the supplied request/context and the immutable limits value.
#[derive(Clone, Debug, Default)]
pub struct NativeTransport {
    limits: NativeTransportLimits,
}

impl NativeTransport {
    /// Creates a transport with explicit bounded resource limits.
    ///
    /// The limits are checked again at every operation.  Revalidation is
    /// intentional: configuration values are allowed to be shared through an
    /// application edge, and a stale constructor check must not permit an
    /// oversized socket buffer or response allocation.
    pub fn new(limits: NativeTransportLimits) -> Result<Self, TransportError> {
        limits.validate()?;
        Ok(Self { limits })
    }

    /// Returns a transport using [`NativeTransportLimits::default`].
    pub fn with_defaults() -> Result<Self, TransportError> {
        Self::new(NativeTransportLimits::default())
    }

    /// Returns the immutable limits used by this adapter.
    #[must_use]
    pub const fn limits(&self) -> &NativeTransportLimits {
        &self.limits
    }

    fn preflight(
        &self,
        request: &Request,
        context: &TransportContext,
        operation_started: Instant,
    ) -> Result<(EncodedRequest, SocketAddr), TransportError> {
        self.limits.validate()?;
        check_cancellation(context)?;
        context.timeouts.validate().map_err(|_| {
            TransportError::InvalidRequest("invalid HTTP timeout policy".to_owned())
        })?;
        ensure_remaining(context, TimeoutPhase::Overall, operation_started)?;

        if request.url().scheme() != "http" {
            return Err(TransportError::Unsupported(
                "native transport supports plain HTTP only".to_owned(),
            ));
        }
        if !matches!(context.route, Route::Direct) {
            return Err(TransportError::Unsupported(
                "native transport does not support proxy routes".to_owned(),
            ));
        }
        if context.http_version != HttpVersionPolicy::Http11Only {
            return Err(TransportError::Unsupported(
                "native transport supports HTTP/1.1 only".to_owned(),
            ));
        }
        if context.decompression != DecompressionPolicy::Disabled {
            return Err(TransportError::Unsupported(
                "native transport does not decode response content".to_owned(),
            ));
        }
        if context.retries.transparent_retries_enabled() {
            return Err(TransportError::Unsupported(
                "native transport does not retry transparently".to_owned(),
            ));
        }
        if context.tls != TlsConfig::default() {
            return Err(TransportError::Unsupported(
                "native transport does not provide TLS".to_owned(),
            ));
        }

        // The bootstrap edge intentionally has no resolver capability.  A
        // numeric origin is parsed locally and converted directly to one
        // socket address, so a hostname can never enter a potentially
        // blocking system resolver or create an ambient DNS side effect.
        let origin_ip = request.url().host().parse::<IpAddr>().map_err(|_| {
            TransportError::Unsupported(
                "native transport requires a numeric IP origin host".to_owned(),
            )
        })?;
        let origin = SocketAddr::new(origin_ip, request.url().port());

        // Keep request validation at the edge as well as in the pure client.
        // The request wire encoder performs its own framing/header checks; a
        // failed conversion is intentionally reported without provider text.
        request
            .validate(request_body_limit(&self.limits), 1_024)
            .map_err(map_request_validation_error)?;
        check_cancellation(context)?;
        let encoded = encode_request(request, &self.limits).map_err(map_encoding_error)?;
        if encoded.bytes.len() > request_wire_limit(&self.limits) {
            return Err(TransportError::ResourceLimit(
                "HTTP request wire bytes".to_owned(),
            ));
        }
        check_cancellation(context)?;
        Ok((encoded, origin))
    }

    fn connect(
        &self,
        address: SocketAddr,
        context: &TransportContext,
        operation_started: Instant,
    ) -> Result<(TcpStream, Duration), TransportError> {
        connect_once(address, context, operation_started)
    }

    fn send_inner(
        &self,
        request: &Request,
        context: &TransportContext,
    ) -> Result<TransportResponse, TransportError> {
        let operation_started = Instant::now();
        let (encoded_request, origin) = self.preflight(request, context, operation_started)?;
        let (mut stream, connect_duration) = self.connect(origin, context, operation_started)?;

        let wake_registration = register_socket_waker(&stream, &context.cancellation)?;
        check_cancellation(context)?;

        let write_timeout = ensure_remaining(context, TimeoutPhase::Write, operation_started)?;
        set_write_timeout(&stream, write_timeout)?;
        check_cancellation(context)?;
        stream.write_all(&encoded_request.bytes).map_err(|_| {
            map_io_failure(
                context,
                TimeoutPhase::Write,
                operation_started,
                "request write failed",
            )
        })?;
        check_cancellation(context)?;
        ensure_remaining(context, TimeoutPhase::Write, operation_started)?;

        let read_timeout = ensure_remaining(context, TimeoutPhase::Read, operation_started)?;
        set_read_timeout(&stream, read_timeout)?;
        check_cancellation(context)?;
        let response_started = Instant::now();
        let mut buffer = vec![0_u8; read_buffer_limit(&self.limits)];
        let mut wire_response = Vec::new();
        let mut first_byte_latency = None;
        let complete_wire_len = loop {
            check_cancellation(context)?;
            ensure_remaining(context, TimeoutPhase::Read, operation_started)?;
            let read = match stream.read(&mut buffer) {
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    return Err(map_io_failure(
                        context,
                        TimeoutPhase::Read,
                        operation_started,
                        "response read failed",
                    ));
                }
            };
            if read == 0 {
                if wire_response.is_empty() {
                    return Err(TransportError::Read("empty HTTP response".to_owned()));
                }
                match scan_response_completion(
                    &wire_response,
                    request.method(),
                    &self.limits,
                    true,
                )? {
                    ResponseCompletion::Incomplete => {
                        return Err(TransportError::Protocol(
                            "HTTP response ended before framing completed".to_owned(),
                        ));
                    }
                    ResponseCompletion::Complete { wire_len, .. } => {
                        if wire_len != wire_response.len() {
                            return Err(TransportError::Protocol(
                                "bytes follow complete HTTP response".to_owned(),
                            ));
                        }
                        break wire_len;
                    }
                }
            }
            if first_byte_latency.is_none() {
                first_byte_latency = Some(response_started.elapsed());
            }
            let next_len = wire_response.len().checked_add(read).ok_or_else(|| {
                TransportError::ResourceLimit("HTTP response wire bytes".to_owned())
            })?;
            if next_len > response_wire_limit(&self.limits) {
                return Err(TransportError::ResourceLimit(
                    "HTTP response wire bytes".to_owned(),
                ));
            }
            // Reserve exactly the initialized prefix before extending.  This
            // avoids the Vec doubling heuristic creating capacity beyond the
            // configured total response bound.
            wire_response.try_reserve_exact(read).map_err(|_| {
                TransportError::ResourceLimit("HTTP response wire bytes".to_owned())
            })?;
            wire_response.extend_from_slice(&buffer[..read]);
            match scan_response_completion(&wire_response, request.method(), &self.limits, false)? {
                ResponseCompletion::Incomplete => {}
                ResponseCompletion::Complete { wire_len, .. } => {
                    if wire_len != wire_response.len() {
                        return Err(TransportError::Protocol(
                            "bytes follow complete HTTP response".to_owned(),
                        ));
                    }
                    break wire_len;
                }
            }
            check_cancellation(context)?;
            ensure_remaining(context, TimeoutPhase::Read, operation_started)?;
        };
        drop(wake_registration);
        check_cancellation(context)?;
        ensure_remaining(context, TimeoutPhase::Read, operation_started)?;
        if wire_response.is_empty() {
            return Err(TransportError::Read("empty HTTP response".to_owned()));
        }
        wire_response.truncate(complete_wire_len);

        let decoded = match decode_response(&wire_response, request.method(), &self.limits) {
            Ok(decoded) => decoded,
            Err(error) => {
                // Preserve a parser/limit error unless cancellation or the
                // shared read budget won the race while decoding completed.
                check_cancellation(context)?;
                ensure_remaining(context, TimeoutPhase::Read, operation_started)?;
                return Err(error);
            }
        };
        check_cancellation(context)?;
        ensure_remaining(context, TimeoutPhase::Read, operation_started)?;
        if decoded
            .headers
            .values("content-encoding")
            .any(|value| !value.trim().eq_ignore_ascii_case("identity"))
        {
            return Err(TransportError::Unsupported(
                "native transport does not decode Content-Encoding".to_owned(),
            ));
        }
        let body_len = decoded.body.len();
        if body_len > response_body_limit(&self.limits) {
            return Err(TransportError::ResourceLimit(
                "HTTP response body bytes".to_owned(),
            ));
        }
        let decoded_body_bytes = u64::try_from(body_len)
            .map_err(|_| TransportError::ResourceLimit("HTTP response body bytes".to_owned()))?;
        let timing = ResponseTiming {
            connect: Some(connect_duration),
            tls: None,
            latency: first_byte_latency,
            elapsed: Some(operation_started.elapsed()),
        };
        let response = TransportResponse {
            status: decoded.status,
            reason: decoded.reason,
            headers: decoded.headers,
            body: Box::new(OwnedBody::new(decoded.body)),
            bytes: ByteAccounting::new(
                encoded_request.head_bytes,
                encoded_request.body_bytes,
                decoded.received_head_bytes,
                decoded.received_body_bytes,
            ),
            timing,
            url: Some(request.url().clone()),
            protocol: Some(decoded.protocol),
            framing: Some(decoded.framing),
            decompression: Some(DecompressionObservation::identity(decoded_body_bytes)),
        };
        response.with_observation(TransportResponseObservation {
            reason: decoded.reason_presence,
            body: decoded.body_presence,
            informational_responses: decoded.informational_responses,
        })
    }
}

/// Performs exactly one nonblocking Mio connection attempt for an already
/// selected socket address.
///
/// Both native provider increments use this edge.  Keeping selection outside
/// this function is deliberate: callers must choose one deterministic address
/// before entering Mio, and a failed attempt must never trigger an alternate
/// address retry.
pub(crate) fn connect_once(
    address: SocketAddr,
    context: &TransportContext,
    operation_started: Instant,
) -> Result<(TcpStream, Duration), TransportError> {
    let connect_started = Instant::now();
    check_cancellation(context)?;
    let Some(_) = ensure_remaining(context, TimeoutPhase::Connect, operation_started)? else {
        return Err(TransportError::Unsupported(
            "native transport requires a finite connect deadline".to_owned(),
        ));
    };

    let mut poll = Poll::new()
        .map_err(|_| TransportError::Connect("connect readiness poll setup failed".to_owned()))?;
    // This is the only connect invocation for the admitted address.  Mio
    // starts one nonblocking socket attempt; readiness is then observed
    // without creating another socket or retrying the handshake.
    let mut stream = mio_connect(address)
        .map_err(|_| TransportError::Connect("connection attempt failed".to_owned()))?;
    if poll
        .registry()
        .register(
            &mut stream,
            CONNECT_TOKEN,
            Interest::READABLE | Interest::WRITABLE,
        )
        .is_err()
    {
        // Registration failed after the socket was created.  Best-effort
        // deregistration keeps this exit explicit even on selectors that
        // report a partially completed registration.
        let _ = poll.registry().deregister(&mut stream);
        return Err(TransportError::Connect(
            "connect readiness registration failed".to_owned(),
        ));
    }

    // The callback owns only the one Waker associated with this Poll.  It
    // never closes or replaces the in-progress socket; dropping this exact
    // socket below is the cancellation cleanup path.
    let cancellation_waker = match Waker::new(poll.registry(), CANCELLATION_TOKEN) {
        Ok(waker) => Arc::new(waker),
        Err(_) => {
            // The stream is already registered at this point, so perform the
            // best-effort deregistration before returning the setup error.
            let _ = poll.registry().deregister(&mut stream);
            return Err(TransportError::Connect(
                "connect cancellation wake setup failed".to_owned(),
            ));
        }
    };
    let callback_waker = Arc::clone(&cancellation_waker);
    let cancellation_registration = context.cancellation.register_waker(move || {
        let _ = callback_waker.wake();
    });

    // Registration can synchronously invoke the callback when cancellation
    // won the race, or when the bounded callback table is full.  Check the
    // token after registration before entering Poll::poll in both cases.
    let result = (|| {
        if context.is_cancelled() {
            return Err(TransportError::Cancelled);
        }
        if !cancellation_registration.is_registered() {
            return Err(TransportError::Unsupported(
                "native transport cannot register connect cancellation wake".to_owned(),
            ));
        }

        let mut events = Events::with_capacity(CONNECT_EVENT_CAPACITY);
        loop {
            // Cancellation is checked before every deadline check so a
            // simultaneous cancellation/deadline race is cancellation-
            // winning. The operation deadline includes all work before this
            // connect (including any caller-owned queue handoff).
            check_cancellation(context)?;
            let Some(remaining) =
                ensure_remaining(context, TimeoutPhase::Connect, operation_started)?
            else {
                return Err(TransportError::Unsupported(
                    "native transport requires a finite connect deadline".to_owned(),
                ));
            };
            match poll.poll(&mut events, Some(remaining)) {
                Ok(()) => {}
                Err(error) if poll_interrupted(&error) => continue,
                Err(_) => {
                    check_cancellation(context)?;
                    return Err(TransportError::Connect(
                        "connect readiness poll failed".to_owned(),
                    ));
                }
            }

            // A poll timeout returns with an empty event collection. A
            // cancellation wake and a socket timeout can race, so check
            // cancellation first and then let the shared deadline decide.
            check_cancellation(context)?;
            ensure_remaining(context, TimeoutPhase::Connect, operation_started)?;

            let mut socket_ready = false;
            // `Events` has a fixed capacity, so this loop has a bounded
            // per-poll event budget. There is intentionally no alternate
            // connect attempt when readiness remains inconclusive.
            for event in events.iter().take(CONNECT_EVENT_CAPACITY) {
                match event.token() {
                    CANCELLATION_TOKEN => check_cancellation(context)?,
                    CONNECT_TOKEN => socket_ready |= connect_event_ready(event),
                    _ => {}
                }
            }
            if !socket_ready {
                continue;
            }

            // Writable/readable readiness is only a hint for a nonblocking
            // connect. SO_ERROR is authoritative, then peer_addr confirms
            // the connection has actually completed. NotConnected (and a
            // defensive WouldBlock from a platform selector) remains
            // pending; it does not create a second connect attempt.
            match stream.take_error() {
                Ok(Some(_)) => {
                    check_cancellation(context)?;
                    return Err(TransportError::Connect(
                        "connection attempt failed".to_owned(),
                    ));
                }
                Ok(None) => {}
                Err(_) => {
                    check_cancellation(context)?;
                    return Err(TransportError::Connect(
                        "connect error status unavailable".to_owned(),
                    ));
                }
            }
            match stream.peer_addr() {
                Ok(_) => {
                    check_cancellation(context)?;
                    ensure_remaining(context, TimeoutPhase::Connect, operation_started)?;
                    break Ok(());
                }
                Err(error) if connect_peer_pending(&error) => {}
                Err(_) => {
                    check_cancellation(context)?;
                    return Err(TransportError::Connect(
                        "connection peer status failed".to_owned(),
                    ));
                }
            }
        }
    })();

    // Deregistration is attempted on every exit after registration. A
    // cleanup failure must never replace a primary connect/cancellation/
    // timeout error; only a successful connect with failed cleanup can
    // report the cleanup failure.
    drop(cancellation_registration);
    drop(cancellation_waker);
    let deregister = poll.registry().deregister(&mut stream);
    match result {
        Err(primary) => Err(primary),
        Ok(()) => {
            deregister.map_err(|_| {
                TransportError::Connect("connect readiness deregistration failed".to_owned())
            })?;
            let stream: TcpStream = stream.into();
            restore_blocking(&stream).map_err(|_| {
                TransportError::Connect("failed to restore blocking socket mode".to_owned())
            })?;
            Ok((stream, connect_started.elapsed()))
        }
    }
}

/// Starts the one nonblocking Mio connect attempt.
///
/// Keeping this tiny seam separate makes the exactly-one-attempt invariant
/// visible to the unit tests without introducing a socket abstraction into
/// production transport code.
fn mio_connect(address: SocketAddr) -> io::Result<mio::net::TcpStream> {
    #[cfg(test)]
    CONNECT_INVOCATIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    mio::net::TcpStream::connect(address)
}

fn restore_blocking(stream: &TcpStream) -> io::Result<()> {
    #[cfg(test)]
    BLOCKING_RESTORE_INVOCATIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    stream.set_nonblocking(false)
}

fn poll_interrupted(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::Interrupted
}

fn connect_event_ready(event: &mio::event::Event) -> bool {
    event.token() == CONNECT_TOKEN
        && (event.is_readable()
            || event.is_writable()
            || event.is_error()
            || event.is_read_closed()
            || event.is_write_closed())
}

fn connect_peer_pending(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotConnected | io::ErrorKind::WouldBlock
    )
}

#[cfg(test)]
static CONNECT_INVOCATIONS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static BLOCKING_RESTORE_INVOCATIONS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

impl Transport for NativeTransport {
    fn send_stream(
        &mut self,
        request: &Request,
        context: &TransportContext,
    ) -> Result<TransportResponse, TransportError> {
        self.send_inner(request, context)
    }

    fn send_with_control(
        &mut self,
        request: &Request,
        context: &TransportContext,
    ) -> Result<TransportResponse, TransportError> {
        self.send_inner(request, context)
    }
}

/// Bounded body owner used after the response decoder has validated framing.
///
/// The response decoder owns one bounded wire buffer; this stream owns only
/// the decoded entity and yields fixed-size copied chunks.  It never returns a
/// chunk larger than the semantic caller's remaining `maximum_bytes`.
#[derive(Debug)]
pub(crate) struct OwnedBody {
    bytes: Vec<u8>,
    offset: usize,
}

impl OwnedBody {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, offset: 0 }
    }
}

impl ResponseBody for OwnedBody {
    fn next_chunk(&mut self, maximum_bytes: usize) -> Result<Option<Vec<u8>>, TransportError> {
        if maximum_bytes == 0 {
            return Err(TransportError::ResourceLimit(
                "response body chunk bound".to_owned(),
            ));
        }
        if self.offset >= self.bytes.len() {
            return Ok(None);
        }
        let remaining = self.bytes.len() - self.offset;
        let length = remaining.min(maximum_bytes).min(BODY_CHUNK_BYTES);
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| TransportError::ResourceLimit("response body chunk".to_owned()))?;
        let chunk = self.bytes[self.offset..end].to_vec();
        self.offset = end;
        Ok(Some(chunk))
    }
}

pub(crate) fn register_socket_waker(
    stream: &TcpStream,
    cancellation: &CancellationToken,
) -> Result<CancellationRegistration, TransportError> {
    let owned_clone = stream.try_clone().map_err(|_| {
        TransportError::Unsupported(
            "native transport cannot register socket cancellation wake".to_owned(),
        )
    })?;
    let registration = cancellation.register_waker(move || {
        // This is an exact clone of the still-owned direct socket.  Shutdown
        // is the only callback operation; it does not wait for or reap any
        // unrelated resource.  If the operation already completed, the
        // benign error is intentionally ignored.
        let _ = owned_clone.shutdown(Shutdown::Both);
    });
    if registration.is_registered() {
        return Ok(registration);
    }
    if cancellation.is_cancelled() {
        return Err(TransportError::Cancelled);
    }
    Err(TransportError::Unsupported(
        "native transport cannot register socket cancellation wake".to_owned(),
    ))
}

fn map_request_validation_error(error: jmeter_rs_http::HttpError) -> TransportError {
    match error {
        jmeter_rs_http::HttpError::ResourceLimit(message) => TransportError::ResourceLimit(message),
        jmeter_rs_http::HttpError::RequestBodyLimit { .. } => {
            TransportError::ResourceLimit("request body bytes".to_owned())
        }
        jmeter_rs_http::HttpError::ResponseBodyLimit { .. } => {
            TransportError::ResourceLimit("response body bytes".to_owned())
        }
        jmeter_rs_http::HttpError::Transport(error) => error,
        jmeter_rs_http::HttpError::Timeout(phase) => TransportError::Timeout(phase),
        jmeter_rs_http::HttpError::Cancelled => TransportError::Cancelled,
        jmeter_rs_http::HttpError::Unsupported(message) => TransportError::Unsupported(message),
        _ => TransportError::InvalidRequest("invalid HTTP request".to_owned()),
    }
}

fn map_encoding_error(error: TransportError) -> TransportError {
    match error {
        TransportError::ResourceLimit(_) | TransportError::Unsupported(_) => error,
        _ => TransportError::InvalidRequest("request encoding failed".to_owned()),
    }
}

fn check_cancellation(context: &TransportContext) -> Result<(), TransportError> {
    if context.is_cancelled() {
        Err(TransportError::Cancelled)
    } else {
        Ok(())
    }
}

fn ensure_remaining(
    context: &TransportContext,
    phase: TimeoutPhase,
    operation_started: Instant,
) -> Result<Option<Duration>, TransportError> {
    check_cancellation(context)?;
    let Some(deadline) = context.effective_deadline(phase) else {
        return Ok(None);
    };
    let relative = deadline
        .at
        .checked_sub(context.started_at.monotonic)
        .ok_or(TransportError::Timeout(phase))?;
    let elapsed = operation_started.elapsed();
    let remaining = relative
        .checked_sub(elapsed)
        .ok_or(TransportError::Timeout(phase))?;
    if remaining.is_zero() {
        return Err(TransportError::Timeout(phase));
    }
    Ok(Some(remaining))
}

fn deadline_reached(
    context: &TransportContext,
    phase: TimeoutPhase,
    operation_started: Instant,
) -> bool {
    ensure_remaining(context, phase, operation_started).is_err()
}

fn set_write_timeout(stream: &TcpStream, timeout: Option<Duration>) -> Result<(), TransportError> {
    let Some(timeout) = timeout else {
        return Err(TransportError::Unsupported(
            "native transport requires a finite write deadline".to_owned(),
        ));
    };
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|_| TransportError::Write("write timeout setup failed".to_owned()))
}

fn set_read_timeout(stream: &TcpStream, timeout: Option<Duration>) -> Result<(), TransportError> {
    let Some(timeout) = timeout else {
        return Err(TransportError::Unsupported(
            "native transport requires a finite read deadline".to_owned(),
        ));
    };
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|_| TransportError::Read("read timeout setup failed".to_owned()))
}

fn map_io_failure(
    context: &TransportContext,
    phase: TimeoutPhase,
    operation_started: Instant,
    message: &'static str,
) -> TransportError {
    if context.is_cancelled() {
        TransportError::Cancelled
    } else if deadline_reached(context, phase, operation_started) {
        TransportError::Timeout(phase)
    } else {
        match phase {
            TimeoutPhase::Connect | TimeoutPhase::Overall => {
                TransportError::Connect(message.to_owned())
            }
            TimeoutPhase::Write => TransportError::Write(message.to_owned()),
            TimeoutPhase::Read => TransportError::Read(message.to_owned()),
            TimeoutPhase::Tls => TransportError::Unsupported("TLS is unavailable".to_owned()),
        }
    }
}

// These accessors are kept in one place because the limits module is shared
// with the wire encoder.  The names mirror the explicit native config fields;
// no process-global or library default is consulted.
fn request_wire_limit(limits: &NativeTransportLimits) -> usize {
    limits.max_request_total_bytes
}

fn response_wire_limit(limits: &NativeTransportLimits) -> usize {
    limits.max_response_total_bytes
}

fn response_body_limit(limits: &NativeTransportLimits) -> usize {
    limits.max_response_body_bytes
}

fn request_body_limit(limits: &NativeTransportLimits) -> usize {
    limits.max_request_body_bytes
}

fn read_buffer_limit(limits: &NativeTransportLimits) -> usize {
    limits.max_io_buffer_bytes
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "tests construct fixed valid requests and assert exact failures"
    )]

    use super::*;
    use jmeter_rs_http::{
        CancellationToken, ClockReading, Deadline, DnsCache, HttpVersionPolicy, RetryPolicy,
        TimeoutConfig,
    };

    fn context(cancellation: CancellationToken) -> TransportContext {
        TransportContext {
            route: Route::Direct,
            timeouts: TimeoutConfig::default(),
            deadline: Some(Deadline::at(Duration::from_secs(5))),
            tls: TlsConfig::default(),
            http_version: HttpVersionPolicy::Http11Only,
            decompression: DecompressionPolicy::Disabled,
            retries: RetryPolicy::default(),
            dns: DnsCache::default(),
            attempt: 0,
            started_at: ClockReading::new(0, Duration::ZERO),
            cancellation,
        }
    }

    #[test]
    fn cancellation_fails_before_url_or_dns_work() {
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let mut transport = NativeTransport::default();
        let request = Request::get("http://invalid.test/").expect("bounded request");
        let error = transport
            .send_stream(&request, &context(cancellation))
            .expect_err("cancelled operation");
        assert!(matches!(error, TransportError::Cancelled));
    }

    #[test]
    fn unsupported_https_fails_before_dns_or_socket() {
        let mut transport = NativeTransport::default();
        let request = Request::get("https://invalid.test/").expect("bounded request");
        let error = transport
            .send_stream(&request, &context(CancellationToken::default()))
            .expect_err("TLS is outside this capability");
        assert!(matches!(error, TransportError::Unsupported(_)));
    }

    #[test]
    fn hostname_is_unavailable_before_resolution() {
        let mut transport = NativeTransport::default();
        let request = Request::get("http://example.test/").expect("bounded request");
        let error = transport
            .send_stream(&request, &context(CancellationToken::default()))
            .expect_err("hostname resolution is outside bootstrap native/1");
        assert!(
            matches!(error, TransportError::Unsupported(message) if message.contains("numeric IP"))
        );
    }

    #[test]
    fn constructor_preserves_original_limit_error() {
        let limits = NativeTransportLimits {
            max_line_bytes: 0,
            ..NativeTransportLimits::default()
        };
        let error = NativeTransport::new(limits).expect_err("zero line bound must fail closed");
        assert!(
            matches!(error, TransportError::ResourceLimit(message) if message.contains("max_line_bytes"))
        );
    }

    #[test]
    fn preflight_preserves_original_limit_error() {
        let mut transport = NativeTransport::default();
        transport.limits.max_line_bytes = 0;
        let request = Request::get("http://127.0.0.1/").expect("bounded request");
        let error = transport
            .send_stream(&request, &context(CancellationToken::default()))
            .expect_err("invalid limits must fail before socket work");
        assert!(
            matches!(error, TransportError::ResourceLimit(message) if message.contains("max_line_bytes"))
        );
    }

    #[test]
    fn preflight_preserves_unsupported_request_encoding() {
        let mut request = Request::get("http://127.0.0.1/").expect("bounded request");
        request
            .add_header("Transfer-Encoding", "chunked")
            .expect("bounded header");
        let mut transport = NativeTransport::default();
        let error = transport
            .send_stream(&request, &context(CancellationToken::default()))
            .expect_err("unsupported request encoding must fail before connect");
        assert!(
            matches!(error, TransportError::Unsupported(message) if message.contains("Transfer-Encoding"))
        );
    }

    #[test]
    fn preflight_preserves_request_body_limit_category() {
        let limits = NativeTransportLimits {
            max_request_body_bytes: 1,
            ..NativeTransportLimits::default()
        };
        let mut transport = NativeTransport::new(limits).expect("bounded limits");
        let request =
            Request::post("http://127.0.0.1/", b"too large".to_vec()).expect("bounded request");
        let error = transport
            .send_stream(&request, &context(CancellationToken::default()))
            .expect_err("request body limit must fail before connect");
        assert!(matches!(error, TransportError::ResourceLimit(_)));
    }

    #[test]
    fn connect_starts_exactly_one_mio_attempt() {
        use std::net::TcpListener;

        CONNECT_INVOCATIONS.store(0, std::sync::atomic::Ordering::Relaxed);
        BLOCKING_RESTORE_INVOCATIONS.store(0, std::sync::atomic::Ordering::Relaxed);
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback listener");
        let address = listener.local_addr().expect("listener address");
        let transport = NativeTransport::default();
        let result = transport.connect(
            address,
            &context(CancellationToken::default()),
            Instant::now(),
        );
        assert!(
            !matches!(result.as_ref(), Err(TransportError::Unsupported(_))),
            "one loopback connect unexpectedly returned unsupported: {result:?}"
        );
        let (stream, _) = result.expect("one loopback connect");

        assert_eq!(
            CONNECT_INVOCATIONS.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "connect readiness must never retry by starting another socket"
        );
        assert_eq!(
            BLOCKING_RESTORE_INVOCATIONS.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "a successful Mio connection must restore blocking mode exactly once"
        );
        drop(stream);
        drop(listener);
    }

    #[test]
    fn spurious_events_and_interrupted_poll_are_nonterminal() {
        assert!(poll_interrupted(&io::Error::from(
            io::ErrorKind::Interrupted
        )));
        assert!(!poll_interrupted(&io::Error::from(io::ErrorKind::Other)));

        let mut poll = Poll::new().expect("Mio poll");
        let mut events = Events::with_capacity(1);
        let waker = Waker::new(poll.registry(), Token(99)).expect("spurious-event waker");
        waker.wake().expect("spurious-event wake");
        poll.poll(&mut events, Some(Duration::from_secs(1)))
            .expect("spurious-event poll");
        let event = events.iter().next().expect("spurious event");
        assert!(!connect_event_ready(event));
    }

    #[test]
    fn not_connected_peer_status_remains_pending() {
        assert!(connect_peer_pending(&io::Error::from(
            io::ErrorKind::NotConnected,
        )));
        assert!(connect_peer_pending(&io::Error::from(
            io::ErrorKind::WouldBlock,
        )));
        assert!(!connect_peer_pending(&io::Error::from(
            io::ErrorKind::ConnectionRefused
        )));
    }
}
