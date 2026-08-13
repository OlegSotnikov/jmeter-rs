// SPDX-License-Identifier: Apache-2.0
//! Direct HTTP/1.1 transport with injected DNS and explicit rustls TLS.
//!
//! `NativeTransportV2` is the independently named `http.native/2` provider.
//! It keeps the bootstrap provider's one-attempt Mio connector and repository
//! HTTP/1.1 framing, while adding one bounded hostname lookup and explicit
//! root-based rustls HTTPS.  The adapter owns no resolver cache or connection
//! pool and never retries a second DNS answer after the selected address has
//! entered the connector.

use crate::config::NativeTransportLimits;
use crate::dns::{
    CanonicalName, DnsCancellationToken, DnsError, DnsErrorCode, DnsFuture, DnsQuery, DnsResolver,
};
use crate::tls::{NativeTlsConfig, NativeTlsStream, TlsDeadline, TlsError, TlsErrorCode};
use crate::transport::{OwnedBody, connect_once, register_socket_waker};
use crate::wire::{
    EncodedRequest, ResponseCompletion, decode_response, encode_request, scan_response_completion,
};
use jmeter_rs_http::{
    ByteAccounting, CancellationRegistration, DecompressionObservation, DecompressionPolicy,
    HttpVersionPolicy, Request, ResponseTiming, Route, TimeoutPhase, TlsConfig, Transport,
    TransportContext, TransportError, TransportResponse, TransportResponseObservation,
};
use std::fmt;
use std::future::Future;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};
use std::time::{Duration, Instant};

/// Stable identity of the independently named native HTTP/1.1 provider.
pub const CAPABILITY_ID: &str = "http.native/2";

/// Maximum number of resolver future polls for one HTTP operation.
///
/// A resolver future is expected to hand work to an actor and remain cheap to
/// poll.  This bound prevents a faulty provider from turning a bounded worker
/// into a wake/poll spin loop.
const MAX_DNS_POLLS: usize = 4_096;
/// Maximum total wake notifications accepted from one resolver future.
const MAX_DNS_WAKES: usize = 4_096;
/// Maximum retained response scratch buffer, matching the native TLS edge.
const MAX_TLS_READ_BUFFER: usize = crate::tls::MAX_TLS_BUFFER_BYTES;

/// A direct native HTTP/1.1 transport with injected bounded DNS and optional
/// explicit-root rustls configuration.
pub struct NativeTransportV2 {
    limits: NativeTransportLimits,
    resolver: Arc<dyn DnsResolver>,
    tls: Option<NativeTlsConfig>,
}

impl Clone for NativeTransportV2 {
    fn clone(&self) -> Self {
        Self {
            limits: self.limits,
            resolver: Arc::clone(&self.resolver),
            tls: self.tls.clone(),
        }
    }
}

impl fmt::Debug for NativeTransportV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeTransportV2")
            .field("limits", &self.limits)
            .field("resolver", &"injected")
            .field("tls", &self.tls)
            .finish()
    }
}

impl NativeTransportV2 {
    /// Creates a V2 transport from immutable limits, resolver, and TLS policy.
    ///
    /// The resolver handle is retained but never polled here.  DNS work is
    /// submitted and synchronously driven only by [`Transport::send_stream`]
    /// on its caller's bounded HTTP worker thread.  HTTPS operations require
    /// `tls` to be `Some`; HTTP operations do not need TLS material.
    pub fn new(
        limits: NativeTransportLimits,
        resolver: Arc<dyn DnsResolver>,
        tls: Option<NativeTlsConfig>,
    ) -> Result<Self, TransportError> {
        limits.validate()?;
        if let Some(config) = &tls {
            config
                .validate()
                .map_err(|error| error.into_transport_error())?;
        }
        Ok(Self {
            limits,
            resolver,
            tls,
        })
    }

    /// Creates a V2 transport with the standard bounded HTTP limits.
    pub fn with_defaults(
        resolver: Arc<dyn DnsResolver>,
        tls: Option<NativeTlsConfig>,
    ) -> Result<Self, TransportError> {
        Self::new(NativeTransportLimits::default(), resolver, tls)
    }

    /// Returns the immutable limits used by this adapter.
    #[must_use]
    pub const fn limits(&self) -> &NativeTransportLimits {
        &self.limits
    }

    fn send_inner(
        &self,
        request: &Request,
        context: &TransportContext,
    ) -> Result<TransportResponse, TransportError> {
        let operation_started = Instant::now();
        self.preflight(request, context, operation_started)?;
        let encoded = encode_request(request, &self.limits).map_err(map_encoding_error)?;
        if encoded.bytes.len() > self.limits.max_request_total_bytes {
            return Err(TransportError::ResourceLimit(
                "HTTP request wire bytes".to_owned(),
            ));
        }
        check_cancellation(context)?;

        let address = self.select_address(request, context, operation_started)?;
        let origin = SocketAddr::new(address, request.url().port());
        let (stream, connect_duration) = connect_once(origin, context, operation_started)?;
        check_cancellation(context)?;

        let (mut stream, tls_duration) = if request.url().scheme() == "https" {
            let config = self.tls.as_ref().ok_or_else(|| {
                TransportError::Unsupported(
                    "native transport requires explicit TLS configuration for HTTPS".to_owned(),
                )
            })?;
            let deadline = tls_deadline(context, operation_started)?;
            let tls_started = Instant::now();
            let stream = NativeTlsStream::connect(
                stream,
                request.url().host(),
                config,
                deadline,
                &context.cancellation,
            )
            .map_err(map_tls_error)?;
            check_cancellation(context)?;
            (
                WireStream::Tls(Box::new(stream)),
                Some(tls_started.elapsed()),
            )
        } else {
            (WireStream::Plain(stream), None)
        };

        let plain_registration = match &stream {
            WireStream::Plain(stream) => {
                Some(register_socket_waker(stream, &context.cancellation)?)
            }
            WireStream::Tls(_) => None,
        };
        let result = self.write_and_read(
            &mut stream,
            plain_registration.as_ref(),
            request,
            context,
            operation_started,
            encoded,
            connect_duration,
            tls_duration,
        );
        drop(plain_registration);
        result
    }

    fn preflight(
        &self,
        request: &Request,
        context: &TransportContext,
        operation_started: Instant,
    ) -> Result<(), TransportError> {
        self.limits.validate()?;
        check_cancellation(context)?;
        context.timeouts.validate().map_err(|_| {
            TransportError::InvalidRequest("invalid HTTP timeout policy".to_owned())
        })?;
        absolute_deadline(context, TimeoutPhase::Overall, operation_started)?;

        if !matches!(request.url().scheme(), "http" | "https") {
            return Err(TransportError::Unsupported(
                "native transport supports HTTP and HTTPS only".to_owned(),
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
        // The native TLS policy is explicit and immutable at this edge.  A
        // non-default core policy would otherwise be silently ignored.
        if context.tls != TlsConfig::default() {
            return Err(TransportError::Unsupported(
                "native transport requires its explicit TLS configuration".to_owned(),
            ));
        }
        request
            .validate(
                self.limits.max_request_body_bytes,
                self.limits.max_header_count,
            )
            .map_err(map_request_validation_error)?;
        if request.url().scheme() == "https" && self.tls.is_none() {
            return Err(TransportError::Unsupported(
                "native transport requires explicit TLS configuration for HTTPS".to_owned(),
            ));
        }
        check_cancellation(context)
    }

    fn select_address(
        &self,
        request: &Request,
        context: &TransportContext,
        operation_started: Instant,
    ) -> Result<IpAddr, TransportError> {
        let host = request.url().host();
        if let Ok(address) = host.parse::<IpAddr>() {
            return Ok(address);
        }
        let name = CanonicalName::parse(host).map_err(map_dns_error)?;
        let deadline = absolute_deadline(context, TimeoutPhase::Overall, operation_started)?;
        let cancellation = DnsCancellationToken::default();
        let query = DnsQuery::with_cancellation(name.clone(), deadline, cancellation.clone());
        let future = self.resolver.resolve(query);
        let response = block_on_dns(future, &name, cancellation, context, deadline)?;
        check_cancellation(context)?;
        let addresses = response.addresses();
        if addresses.len() > self.limits.max_dns_addresses {
            return Err(TransportError::ResourceLimit(
                "DNS address records".to_owned(),
            ));
        }
        addresses
            .first()
            .copied()
            .ok_or_else(|| TransportError::Dns("http.dns.no-records".to_owned()))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the response path carries one explicit bounded observation for every transport phase"
    )]
    fn write_and_read(
        &self,
        stream: &mut WireStream,
        plain_registration: Option<&CancellationRegistration>,
        request: &Request,
        context: &TransportContext,
        operation_started: Instant,
        encoded: EncodedRequest,
        connect_duration: Duration,
        tls_duration: Option<Duration>,
    ) -> Result<TransportResponse, TransportError> {
        check_cancellation(context)?;
        let write_deadline = absolute_deadline(context, TimeoutPhase::Write, operation_started)?;
        stream.write_all(
            &encoded.bytes,
            write_deadline,
            context,
            TimeoutPhase::Write,
            plain_registration.is_some(),
        )?;
        check_cancellation(context)?;
        let read_deadline = absolute_deadline(context, TimeoutPhase::Read, operation_started)?;
        let response_started = Instant::now();
        let mut buffer = vec![0_u8; self.limits.max_io_buffer_bytes.min(MAX_TLS_READ_BUFFER)];
        let mut wire_response = Vec::new();
        let mut first_byte_latency = None;
        let complete_wire_len = loop {
            check_cancellation(context)?;
            ensure_absolute_deadline(read_deadline, context, TimeoutPhase::Read)?;
            let read = stream.read(
                &mut buffer,
                read_deadline,
                context,
                TimeoutPhase::Read,
                plain_registration.is_some(),
            )?;
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
            if next_len > self.limits.max_response_total_bytes {
                return Err(TransportError::ResourceLimit(
                    "HTTP response wire bytes".to_owned(),
                ));
            }
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
            ensure_absolute_deadline(read_deadline, context, TimeoutPhase::Read)?;
        };
        check_cancellation(context)?;
        ensure_absolute_deadline(read_deadline, context, TimeoutPhase::Read)?;
        wire_response.truncate(complete_wire_len);
        let decoded = decode_response(&wire_response, request.method(), &self.limits)?;
        check_cancellation(context)?;
        ensure_absolute_deadline(read_deadline, context, TimeoutPhase::Read)?;
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
        if body_len > self.limits.max_response_body_bytes {
            return Err(TransportError::ResourceLimit(
                "HTTP response body bytes".to_owned(),
            ));
        }
        let decoded_body_bytes = u64::try_from(body_len)
            .map_err(|_| TransportError::ResourceLimit("HTTP response body bytes".to_owned()))?;
        let response = TransportResponse {
            status: decoded.status,
            reason: decoded.reason,
            headers: decoded.headers,
            body: Box::new(OwnedBody::new(decoded.body)),
            bytes: ByteAccounting::new(
                encoded.head_bytes,
                encoded.body_bytes,
                decoded.received_head_bytes,
                decoded.received_body_bytes,
            ),
            timing: ResponseTiming {
                connect: Some(connect_duration),
                tls: tls_duration,
                latency: first_byte_latency,
                elapsed: Some(operation_started.elapsed()),
            },
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

impl Transport for NativeTransportV2 {
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

/// One connected direct stream.  TLS keeps its own bounded cancellation and
/// deadline controls; plain TCP uses the shared socket wake registration.
enum WireStream {
    Plain(TcpStream),
    Tls(Box<NativeTlsStream<TcpStream>>),
}

impl WireStream {
    fn write_all(
        &mut self,
        bytes: &[u8],
        deadline: Instant,
        context: &TransportContext,
        phase: TimeoutPhase,
        plain_wake_registered: bool,
    ) -> Result<(), TransportError> {
        match self {
            Self::Plain(stream) => {
                if !plain_wake_registered {
                    return Err(TransportError::Unsupported(
                        "native transport cannot register socket cancellation wake".to_owned(),
                    ));
                }
                set_socket_timeout(stream, deadline, false, context, phase)?;
                stream
                    .write_all(bytes)
                    .map_err(|_| map_io_failure(context, phase, deadline, "request write failed"))
            }
            Self::Tls(stream) => stream
                .write_all_plain(bytes, tls_deadline_at(deadline)?, &context.cancellation)
                .map_err(map_tls_error),
        }
    }

    fn read(
        &mut self,
        buffer: &mut [u8],
        deadline: Instant,
        context: &TransportContext,
        phase: TimeoutPhase,
        plain_wake_registered: bool,
    ) -> Result<usize, TransportError> {
        match self {
            Self::Plain(stream) => {
                if !plain_wake_registered {
                    return Err(TransportError::Unsupported(
                        "native transport cannot register socket cancellation wake".to_owned(),
                    ));
                }
                set_socket_timeout(stream, deadline, true, context, phase)?;
                stream
                    .read(buffer)
                    .map_err(|_| map_io_failure(context, phase, deadline, "response read failed"))
            }
            Self::Tls(stream) => stream
                .read_plain(buffer, tls_deadline_at(deadline)?, &context.cancellation)
                .map_err(map_tls_error),
        }
    }
}

fn block_on_dns(
    mut future: DnsFuture<'static>,
    name: &CanonicalName,
    dns_cancellation: DnsCancellationToken,
    context: &TransportContext,
    deadline: Instant,
) -> Result<crate::dns::DnsResponse, TransportError> {
    let thread = thread::current();
    let wake_state = Arc::new(DnsThreadWake::new(thread.clone()));
    let waker = Waker::from(Arc::clone(&wake_state));
    let registration = {
        let cancellation = dns_cancellation.clone();
        let thread = thread.clone();
        context.cancellation.register_waker(move || {
            cancellation.cancel();
            thread.unpark();
        })
    };
    if !registration.is_registered() {
        return if context.is_cancelled() {
            Err(TransportError::Cancelled)
        } else {
            Err(TransportError::adapter(
                "http.native.v2.dns.cancellation-wake",
                "DNS cancellation wake registration unavailable",
            ))
        };
    }
    let mut task_context = Context::from_waker(&waker);
    let mut polls = 0usize;
    loop {
        check_cancellation(context)?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or(TransportError::Timeout(TimeoutPhase::Overall))?;
        polls = polls
            .checked_add(1)
            .ok_or_else(|| dns_poll_limit_error(name))?;
        if polls > MAX_DNS_POLLS {
            dns_cancellation.cancel();
            return Err(dns_poll_limit_error(name));
        }
        match Pin::new(&mut future).poll(&mut task_context) {
            Poll::Ready(result) => {
                check_cancellation(context)?;
                if Instant::now() >= deadline {
                    return Err(TransportError::Timeout(TimeoutPhase::Overall));
                }
                return result.map_err(map_dns_error);
            }
            Poll::Pending => {
                if wake_state.wakes.load(Ordering::Acquire) > MAX_DNS_WAKES {
                    dns_cancellation.cancel();
                    return Err(dns_wake_limit_error(name));
                }
                thread::park_timeout(remaining);
            }
        }
    }
}

struct DnsThreadWake {
    thread: Thread,
    wakes: AtomicUsize,
}

impl DnsThreadWake {
    fn new(thread: Thread) -> Self {
        Self {
            thread,
            wakes: AtomicUsize::new(0),
        }
    }
}

impl Wake for DnsThreadWake {
    fn wake(self: Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::AcqRel);
        self.thread.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::AcqRel);
        self.thread.unpark();
    }
}

fn absolute_deadline(
    context: &TransportContext,
    phase: TimeoutPhase,
    operation_started: Instant,
) -> Result<Instant, TransportError> {
    let deadline = context.effective_deadline(phase).ok_or_else(|| {
        TransportError::Unsupported("native transport requires a finite deadline".to_owned())
    })?;
    let relative = deadline
        .at
        .checked_sub(context.started_at.monotonic)
        .ok_or(TransportError::Timeout(phase))?;
    operation_started
        .checked_add(relative)
        .ok_or_else(|| TransportError::ResourceLimit("HTTP operation deadline".to_owned()))
}

fn ensure_absolute_deadline(
    deadline: Instant,
    context: &TransportContext,
    phase: TimeoutPhase,
) -> Result<(), TransportError> {
    check_cancellation(context)?;
    if Instant::now() >= deadline {
        return Err(TransportError::Timeout(phase));
    }
    Ok(())
}

fn tls_deadline(
    context: &TransportContext,
    operation_started: Instant,
) -> Result<TlsDeadline, TransportError> {
    tls_deadline_at(absolute_deadline(
        context,
        TimeoutPhase::Tls,
        operation_started,
    )?)
}

fn tls_deadline_at(deadline: Instant) -> Result<TlsDeadline, TransportError> {
    TlsDeadline::at(deadline).map_err(map_tls_error)
}

fn set_socket_timeout(
    stream: &TcpStream,
    deadline: Instant,
    read: bool,
    context: &TransportContext,
    phase: TimeoutPhase,
) -> Result<(), TransportError> {
    ensure_absolute_deadline(deadline, context, phase)?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(TransportError::Timeout(phase))?;
    let result = if read {
        stream.set_read_timeout(Some(remaining))
    } else {
        stream.set_write_timeout(Some(remaining))
    };
    result.map_err(|_| {
        if context.is_cancelled() {
            TransportError::Cancelled
        } else {
            TransportError::adapter(
                "http.native.v2.socket-timeout",
                "socket timeout setup failed",
            )
        }
    })
}

fn map_io_failure(
    context: &TransportContext,
    phase: TimeoutPhase,
    deadline: Instant,
    message: &'static str,
) -> TransportError {
    if context.is_cancelled() {
        TransportError::Cancelled
    } else if Instant::now() >= deadline {
        TransportError::Timeout(phase)
    } else if phase == TimeoutPhase::Write {
        TransportError::Write(message.to_owned())
    } else {
        TransportError::Read(message.to_owned())
    }
}

fn check_cancellation(context: &TransportContext) -> Result<(), TransportError> {
    if context.is_cancelled() {
        Err(TransportError::Cancelled)
    } else {
        Ok(())
    }
}

fn map_request_validation_error(error: jmeter_rs_http::HttpError) -> TransportError {
    match error {
        jmeter_rs_http::HttpError::ResourceLimit(message) => TransportError::ResourceLimit(message),
        jmeter_rs_http::HttpError::RequestBodyLimit { .. }
        | jmeter_rs_http::HttpError::ResponseBodyLimit { .. } => {
            TransportError::ResourceLimit("request body bytes".to_owned())
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

fn map_dns_error(error: DnsError) -> TransportError {
    match error.code() {
        DnsErrorCode::Cancelled => TransportError::Cancelled,
        DnsErrorCode::Deadline => TransportError::Timeout(TimeoutPhase::Overall),
        code => TransportError::Dns(format!("http.dns.{}", code.as_str())),
    }
}

fn map_tls_error(error: TlsError) -> TransportError {
    match error.code() {
        TlsErrorCode::Cancelled => TransportError::Cancelled,
        TlsErrorCode::Timeout => match error.phase() {
            crate::tls::TlsPhase::Handshake => TransportError::Timeout(TimeoutPhase::Tls),
            crate::tls::TlsPhase::Read => TransportError::Timeout(TimeoutPhase::Read),
            crate::tls::TlsPhase::Write | crate::tls::TlsPhase::Flush => {
                TransportError::Timeout(TimeoutPhase::Write)
            }
            crate::tls::TlsPhase::Config | crate::tls::TlsPhase::ServerName => {
                TransportError::Timeout(TimeoutPhase::Tls)
            }
        },
        _ => error.into_transport_error(),
    }
}

fn dns_poll_limit_error(_name: &CanonicalName) -> TransportError {
    TransportError::adapter(
        "http.native.v2.dns.poll-limit",
        "DNS future poll bound exceeded",
    )
}

fn dns_wake_limit_error(_name: &CanonicalName) -> TransportError {
    TransportError::adapter(
        "http.native.v2.dns.wake-limit",
        "DNS future wake bound exceeded",
    )
}
