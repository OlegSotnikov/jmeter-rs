// SPDX-License-Identifier: Apache-2.0
//! HTTP execution orchestration over an injected transport.

use std::sync::Arc;
use std::time::Duration;

use crate::clock::{Clock, Deadline, SystemClock};
use crate::policy::{ProxyPolicy, RedirectPolicy, TimeoutConfig, TlsConfig};
use crate::request::{Body, Method, Request};
use crate::response::{ByteAccounting, HttpResult, Response};
use crate::state::{CacheDecision, SessionLimits, StateLifecycle, UserHttpState};
use crate::transport::{CancellationToken, Transport, TransportContext};
use crate::{HttpError, TimeoutPhase};

/// Explicit limits applied to one HTTP client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientLimits {
    /// Maximum request body bytes.
    pub max_request_body_bytes: usize,
    /// Maximum response body bytes.
    pub max_response_body_bytes: usize,
    /// Maximum request/response header fields per message.
    pub max_header_fields: usize,
    /// Maximum estimated request/response header bytes per message.
    pub max_header_bytes: usize,
    /// Maximum aggregate cookie/header/cache/auth state.
    pub session: SessionLimits,
}

impl Default for ClientLimits {
    fn default() -> Self {
        Self {
            max_request_body_bytes: 16 * 1024 * 1024,
            max_response_body_bytes: 64 * 1024 * 1024,
            max_header_fields: 256,
            max_header_bytes: 64 * 1024,
            session: SessionLimits::default(),
        }
    }
}

/// HTTP sampler configuration. Every ambient client default is represented
/// explicitly here; this struct never reads process environment state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientConfig {
    /// Redirect policy.
    pub redirects: RedirectPolicy,
    /// Proxy routing policy.
    pub proxy: ProxyPolicy,
    /// TLS policy passed to the transport.
    pub tls: TlsConfig,
    /// Per-operation timeout settings.
    pub timeouts: TimeoutConfig,
    /// Resource bounds.
    pub limits: ClientLimits,
    /// Whether cookie state is applied and updated.
    pub cookies_enabled: bool,
    /// Whether cache state is consulted and updated.
    pub cache_enabled: bool,
    /// Whether auth state is applied and challenged.
    pub auth_enabled: bool,
    /// Whether configured headers are applied.
    pub headers_enabled: bool,
    /// Whether a Basic challenge may cause one retry.
    pub retry_basic_challenge: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            redirects: RedirectPolicy::default(),
            proxy: ProxyPolicy::default(),
            tls: TlsConfig::default(),
            timeouts: TimeoutConfig::default(),
            limits: ClientLimits::default(),
            cookies_enabled: true,
            cache_enabled: true,
            auth_enabled: true,
            headers_enabled: true,
            retry_basic_challenge: true,
        }
    }
}

impl ClientConfig {
    /// Validates all static policy and resource limits.
    pub fn validate(&self) -> Result<(), HttpError> {
        if self.limits.max_request_body_bytes == 0
            || self.limits.max_response_body_bytes == 0
            || self.limits.max_header_fields == 0
            || self.limits.max_header_bytes == 0
            || self.limits.session.max_dns_entries == 0
            || self.limits.session.max_cookies == 0
            || self.limits.session.max_cache_entries == 0
            || self.limits.session.max_cache_bytes == 0
            || self.limits.session.max_auth_entries == 0
            || self.limits.session.max_headers == 0
        {
            return Err(HttpError::resource_limit(
                "HTTP request/response limits must be non-zero",
            ));
        }
        self.redirects.validate()?;
        self.timeouts.validate()?;
        let maximum_tls_material = self
            .limits
            .max_response_body_bytes
            .checked_mul(2)
            .ok_or_else(|| HttpError::resource_limit("TLS material limit"))?;
        self.tls.validate(maximum_tls_material)
    }
}

/// The HTTP client owns transport-independent state for one virtual user.
pub struct HttpClient<T, C = SystemClock> {
    transport: T,
    config: ClientConfig,
    state: UserHttpState,
    clock: Arc<C>,
}

impl<T> HttpClient<T, SystemClock>
where
    T: Transport,
{
    /// Creates a client with a progressing monotonic system clock.
    pub fn new(transport: T, config: ClientConfig) -> Result<Self, HttpError> {
        Self::with_clock(transport, config, SystemClock::default())
    }
}

impl<T, C> HttpClient<T, C>
where
    T: Transport,
    C: Clock + 'static,
{
    /// Creates a client with an injected clock. The clock is shared only with
    /// this client and may be a deterministic fixture clock.
    pub fn with_clock(transport: T, config: ClientConfig, clock: C) -> Result<Self, HttpError> {
        if !clock.can_progress() {
            return Err(HttpError::Unsupported(
                "a progressing clock capability is required for HTTP execution".to_owned(),
            ));
        }
        config.validate()?;
        let state = UserHttpState::new(config.limits.session)?;
        Ok(Self {
            transport,
            config,
            state,
            clock: Arc::new(clock),
        })
    }

    /// Creates a client with a shared clock capability.
    pub fn with_shared_clock(
        transport: T,
        config: ClientConfig,
        clock: Arc<C>,
    ) -> Result<Self, HttpError> {
        if !clock.can_progress() {
            return Err(HttpError::Unsupported(
                "a progressing clock capability is required for HTTP execution".to_owned(),
            ));
        }
        config.validate()?;
        let state = UserHttpState::new(config.limits.session)?;
        Ok(Self {
            transport,
            config,
            state,
            clock,
        })
    }

    /// Returns immutable client configuration.
    #[must_use]
    pub const fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// Returns mutable client configuration. Callers should validate after
    /// changing limits or TLS material.
    #[must_use]
    pub fn config_mut(&mut self) -> &mut ClientConfig {
        &mut self.config
    }

    /// Returns per-user protocol state.
    #[must_use]
    pub const fn state(&self) -> &UserHttpState {
        &self.state
    }

    /// Returns mutable per-user protocol state.
    #[must_use]
    pub const fn state_mut(&mut self) -> &mut UserHttpState {
        &mut self.state
    }

    /// Returns the underlying transport.
    #[must_use]
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    /// Returns mutable access to the underlying transport for fixture setup.
    #[must_use]
    pub const fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Applies an explicit per-iteration lifecycle boundary to protocol
    /// state.  The default caller policy can preserve state between
    /// iterations; JMeter's clear-each-iteration options are represented by
    /// [`StateLifecycle`] rather than hidden global resets.
    pub fn reset_for_iteration(&mut self, lifecycle: StateLifecycle) {
        self.state.reset_for_iteration(lifecycle);
    }

    /// Executes one logical HTTP sampler with bounded redirects and state.
    pub fn execute(&mut self, request: Request) -> Result<HttpResult, HttpError> {
        self.execute_with_cancellation(request, CancellationToken::default())
    }

    /// Executes one logical sampler with an explicit cancellation capability.
    /// The same token is passed to every redirect attempt and body-stream
    /// read, so cancellation cannot accidentally apply only to the first hop.
    pub fn execute_with_cancellation(
        &mut self,
        request: Request,
        cancellation: CancellationToken,
    ) -> Result<HttpResult, HttpError> {
        self.config.validate()?;
        request.validate(
            self.config.limits.max_request_body_bytes,
            self.config.limits.max_header_fields,
        )?;
        if request.headers().checked_wire_len()? > self.config.limits.max_header_bytes {
            return Err(HttpError::resource_limit("request header bytes"));
        }
        let started = self.clock.now();
        let overall_deadline = self
            .config
            .timeouts
            .overall
            .map(|duration| {
                Deadline::after(started, duration)
                    .ok_or_else(|| HttpError::resource_limit("overall HTTP deadline"))
            })
            .transpose()?;
        let mut current = request;
        let mut redirects = 0usize;
        let mut total_bytes = ByteAccounting::default();
        let mut challenge_retried = false;
        let mut allow_manager_sensitive = true;
        let mut allow_cookie_state = true;
        let mut allow_entity_headers = true;
        let mut allow_redirect_authorization = true;
        let mut allow_auth_state = true;
        let mut allow_host_header = true;
        loop {
            let before = self.clock.now();
            if cancellation.is_cancelled() {
                return Err(HttpError::Cancelled);
            }
            if overall_deadline.is_some_and(|deadline| deadline.expired(before)) {
                return Err(HttpError::Timeout(TimeoutPhase::Overall));
            }
            let mut prepared = current.clone();
            prepared.ensure_content_length()?;
            if self.config.headers_enabled {
                self.state.headers.apply_with_redirect_options(
                    &mut prepared,
                    allow_manager_sensitive,
                    allow_redirect_authorization,
                    allow_host_header,
                    allow_entity_headers,
                );
            }
            if self.config.cookies_enabled
                && allow_cookie_state
                && !prepared.headers().contains("cookie")
                && let Some(cookie) = self
                    .state
                    .cookies
                    .try_request_header(prepared.url(), before)?
            {
                prepared.add_header("Cookie", cookie)?;
            }
            if self.config.auth_enabled
                && allow_cookie_state
                && allow_auth_state
                && !prepared.headers().contains("authorization")
                && let Some(authorization) = self.state.auth.authorization(prepared.url())?
            {
                prepared.add_header("Authorization", authorization)?;
            }
            // Managers are applied after the caller's initial validation. A
            // fresh cache hit still represents this fully prepared request,
            // so enforce request header count/bytes before consulting the
            // cache rather than allowing manager state to bypass the bound.
            prepared.validate(
                self.config.limits.max_request_body_bytes,
                self.config.limits.max_header_fields,
            )?;
            if prepared.headers().checked_wire_len()? > self.config.limits.max_header_bytes {
                return Err(HttpError::resource_limit("request header bytes"));
            }
            let cache_decision = if self.config.cache_enabled {
                self.state.cache.lookup(&prepared, before)
            } else {
                CacheDecision::Miss
            };
            if let CacheDecision::Fresh(mut response) = cache_decision.clone() {
                if let Err(error) = validate_response(
                    &response,
                    self.config.limits.max_response_body_bytes,
                    self.config.limits.max_header_fields,
                    self.config.limits.max_header_bytes,
                ) {
                    return self.response_error(&prepared, error);
                }
                response.set_url(prepared.url().clone());
                // A cache hit emits no wire bytes for this logical sampler.
                response.set_bytes(ByteAccounting::default());
                // Network timing belongs to the original population of the
                // representation, not to a cache hit.  Exposing it again
                // makes a zero-wire hit look like a network request.
                response.set_timing(crate::ResponseTiming::default());
                let elapsed = self.elapsed_since(started.monotonic)?;
                let ended = self.clock.now();
                return Ok(HttpResult::new(
                    response,
                    redirects,
                    total_bytes,
                    elapsed,
                    started.wall_millis,
                    ended.wall_millis,
                ));
            }
            let stale_cache = match cache_decision {
                CacheDecision::Revalidate { headers, cached } => {
                    for field in &headers {
                        if !prepared.headers().contains(field.name().as_str()) {
                            prepared.headers_mut().append(field.clone());
                        }
                    }
                    Some(cached)
                }
                _ => None,
            };
            prepared.validate(
                self.config.limits.max_request_body_bytes,
                self.config.limits.max_header_fields,
            )?;
            if prepared.headers().checked_wire_len()? > self.config.limits.max_header_bytes {
                return Err(HttpError::resource_limit("request header bytes"));
            }
            let context = TransportContext {
                route: self.config.proxy.route(prepared.url()),
                timeouts: self.config.timeouts,
                deadline: overall_deadline,
                tls: self.config.tls.clone(),
                dns: self.state.dns.clone(),
                attempt: redirects,
                started_at: before,
                cancellation: cancellation.clone(),
            };
            let read_deadline = context.effective_deadline(TimeoutPhase::Read);
            let transport_response = self
                .transport
                .send_with_control(&prepared, &context)
                .map_err(map_transport_error)?;
            if cancellation.is_cancelled() {
                return Err(HttpError::Cancelled);
            }
            let transport_validation = validate_transport_response(
                &transport_response,
                self.config.limits.max_header_fields,
                self.config.limits.max_header_bytes,
                self.config.limits.max_response_body_bytes,
                self.config.limits.max_request_body_bytes,
                prepared.body().len(),
            );
            if let Err(error) = transport_validation {
                if self.config.cache_enabled {
                    self.state.cache.invalidate(&prepared)?;
                }
                return Err(error);
            }
            let mut response = match transport_response
                .collect_with_deadline(
                    self.config.limits.max_response_body_bytes,
                    &cancellation,
                    read_deadline,
                    Some(self.clock.as_ref()),
                    TimeoutPhase::Read,
                )
                .map_err(map_transport_error)
            {
                Ok(response) => response,
                Err(error) => {
                    if self.config.cache_enabled && prepared.method().is_idempotent() {
                        self.state.cache.invalidate(&prepared)?;
                    }
                    return Err(error);
                }
            };
            let response_validation = validate_response(
                &response,
                self.config.limits.max_response_body_bytes,
                self.config.limits.max_header_fields,
                self.config.limits.max_header_bytes,
            );
            if let Err(error) = response_validation {
                if self.config.cache_enabled {
                    self.state.cache.invalidate(&prepared)?;
                }
                return Err(error);
            }
            response.set_url(prepared.url().clone());
            if let Some(deadline) = overall_deadline
                && deadline.expired(self.clock.now())
            {
                return self.response_error(&prepared, HttpError::Timeout(TimeoutPhase::Overall));
            }
            if let Some(stale) = stale_cache
                && response.status() == 304
            {
                response = Response::merge_not_modified(&stale, &response);
            }
            if self.config.cookies_enabled {
                let now = self.clock.now();
                if let Err(error) = self.state.cookies.store_set_cookie_headers(
                    prepared.url(),
                    response.headers(),
                    now,
                ) {
                    return self.response_error(&prepared, error);
                }
            }
            let mut response_bytes = response.bytes();
            if response_bytes.sent_headers == 0 && !prepared.headers().is_empty() {
                let header_bytes = match prepared.headers().checked_wire_len() {
                    Ok(bytes) => bytes,
                    Err(error) => return self.response_error(&prepared, error),
                };
                response_bytes.sent_headers = match u64::try_from(header_bytes) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        return self.response_error(
                            &prepared,
                            HttpError::resource_limit("sent header byte accounting"),
                        );
                    }
                };
            }
            if response_bytes.sent_body == 0 && !prepared.body().is_empty() {
                response_bytes.sent_body = match u64::try_from(prepared.body().len()) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        return self.response_error(
                            &prepared,
                            HttpError::resource_limit("sent body byte accounting"),
                        );
                    }
                };
            }
            if response_bytes.received_headers == 0 && !response.headers().is_empty() {
                let header_bytes = match response.headers().checked_wire_len() {
                    Ok(bytes) => bytes,
                    Err(error) => return self.response_error(&prepared, error),
                };
                response_bytes.received_headers = match u64::try_from(header_bytes) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        return self.response_error(
                            &prepared,
                            HttpError::resource_limit("received header byte accounting"),
                        );
                    }
                };
            }
            if response_bytes.received_body == 0
                && !response.body().is_empty()
                && !response.from_cache()
            {
                response_bytes.received_body = match u64::try_from(response.body().len()) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        return self.response_error(
                            &prepared,
                            HttpError::resource_limit("received body byte accounting"),
                        );
                    }
                };
            }
            response.set_bytes(response_bytes);
            total_bytes = match total_bytes.checked_add(response_bytes) {
                Ok(bytes) => bytes,
                Err(error) => return self.response_error(&prepared, error),
            };
            if self.config.cache_enabled
                && response.status() != 304
                && let Err(error) = self
                    .state
                    .cache
                    .store(&prepared, &response, self.clock.now())
            {
                return self.response_error(&prepared, error);
            }
            if self.config.auth_enabled
                && response.status() == 401
                && self.config.retry_basic_challenge
                && !challenge_retried
                && allow_auth_state
                && !prepared.headers().contains("authorization")
                && let Some(authorization) = self.state.auth.authorization_for_challenge(
                    prepared.url(),
                    &response
                        .headers()
                        .values("www-authenticate")
                        .collect::<Vec<_>>()
                        .join(", "),
                )?
            {
                challenge_retried = true;
                prepared.add_header("Authorization", authorization)?;
                current = prepared;
                continue;
            }
            if self.config.redirects.follow && response.is_redirect() {
                let Some(location) = response.headers().get("location") else {
                    return self.finish(response, redirects, total_bytes, started);
                };
                if redirects >= self.config.redirects.maximum {
                    return Err(HttpError::RedirectLimit {
                        maximum: self.config.redirects.maximum,
                    });
                }
                let next_url = prepared.url().join(location)?;
                let cross_origin = prepared.url().origin_key() != next_url.origin_key();
                if cross_origin && !self.config.redirects.allow_cross_origin {
                    return Err(HttpError::RedirectOriginDenied);
                }
                let method =
                    RedirectPolicy::redirected_method(response.status(), prepared.method());
                let forwarded_authorization =
                    if cross_origin && self.config.redirects.forward_authorization {
                        prepared.headers().get("authorization").map(str::to_owned)
                    } else {
                        None
                    };
                prepared.set_method(method);
                prepared.set_url(next_url);
                // The transport must derive Host from the new authority.  A
                // configured Host field is never safe to carry across a
                // redirect, even when the authority happens to be equal.
                prepared.remove_header("host");
                prepared.remove_header("authorization");
                prepared.remove_header("proxy-authorization");
                prepared.remove_header("cookie");
                if matches!(prepared.method(), Method::Get | Method::Head) {
                    allow_entity_headers = false;
                    prepared.set_body(Body::Empty);
                    prepared.headers_mut().remove_entity_headers();
                }
                prepared.remove_header("cookie");
                if cross_origin {
                    // Cookies and proxy credentials are origin/route scoped.
                    // Authorization is forwarded only when the caller made
                    // the explicit compatibility choice and the source hop
                    // actually carried one.
                    allow_manager_sensitive = false;
                    allow_cookie_state = false;
                    allow_redirect_authorization = false;
                    allow_auth_state = false;
                    if let Some(authorization) = forwarded_authorization {
                        prepared.add_header("Authorization", authorization)?;
                    }
                } else {
                    // Recompute path-scoped auth for the destination instead
                    // of carrying a stale source path's credential.
                    allow_manager_sensitive = false;
                    allow_cookie_state = true;
                    allow_redirect_authorization = false;
                    allow_auth_state = true;
                }
                allow_host_header = false;
                current = prepared;
                redirects += 1;
                challenge_retried = false;
                continue;
            }
            return self.finish(response, redirects, total_bytes, started);
        }
    }

    fn finish(
        &self,
        response: Response,
        redirects: usize,
        bytes: ByteAccounting,
        started: crate::ClockReading,
    ) -> Result<HttpResult, HttpError> {
        let ended = self.clock.now();
        let elapsed = ended
            .monotonic
            .checked_sub(started.monotonic)
            .ok_or_else(|| HttpError::resource_limit("monotonic clock moved backwards"))?;
        Ok(HttpResult::new(
            response,
            redirects,
            bytes,
            elapsed,
            started.wall_millis,
            ended.wall_millis,
        ))
    }

    fn elapsed_since(&self, started: Duration) -> Result<Duration, HttpError> {
        self.clock
            .now()
            .monotonic
            .checked_sub(started)
            .ok_or_else(|| HttpError::resource_limit("monotonic clock moved backwards"))
    }

    fn response_error<R>(&mut self, request: &Request, error: HttpError) -> Result<R, HttpError> {
        if self.config.cache_enabled {
            self.state.cache.invalidate(request)?;
        }
        Err(error)
    }
}

fn map_transport_error(error: crate::TransportError) -> HttpError {
    match error {
        crate::TransportError::Timeout(phase) => HttpError::Timeout(phase),
        crate::TransportError::Cancelled => HttpError::Cancelled,
        error => HttpError::Transport(error),
    }
}

fn validate_transport_response(
    response: &crate::TransportResponse,
    maximum_headers: usize,
    maximum_header_bytes: usize,
    maximum_body_bytes: usize,
    maximum_request_body_bytes: usize,
    request_body_bytes: usize,
) -> Result<(), HttpError> {
    crate::response::validate_status_code(response.status).map_err(|error| {
        HttpError::Transport(crate::TransportError::Protocol(error.to_string()))
    })?;
    if response.reason.len() > 256
        || response
            .reason
            .bytes()
            .any(|byte| byte < 0x20 || byte == 0x7f)
    {
        return Err(HttpError::InvalidHeader(
            "response reason phrase is invalid or too large".to_owned(),
        ));
    }
    if response.headers.len() > maximum_headers {
        return Err(HttpError::resource_limit("response header count"));
    }
    if response.headers.checked_wire_len()? > maximum_header_bytes {
        return Err(HttpError::resource_limit("response header bytes"));
    }
    let maximum_header_bytes = u64::try_from(maximum_header_bytes)
        .map_err(|_| HttpError::resource_limit("adapter header byte bound"))?;
    if response.bytes.received_headers > maximum_header_bytes
        || response.bytes.sent_headers > maximum_header_bytes
    {
        return Err(HttpError::resource_limit("adapter header byte accounting"));
    }
    let maximum_body_bytes = u64::try_from(maximum_body_bytes)
        .map_err(|_| HttpError::resource_limit("adapter body byte bound"))?;
    if response.bytes.received_body > maximum_body_bytes {
        return Err(HttpError::ResponseBodyLimit {
            actual: usize::try_from(response.bytes.received_body)
                .map_err(|_| HttpError::resource_limit("adapter response body byte count"))?,
            maximum: usize::try_from(maximum_body_bytes)
                .map_err(|_| HttpError::resource_limit("adapter body byte bound"))?,
        });
    }
    let maximum_request_body_bytes_u64 = u64::try_from(maximum_request_body_bytes)
        .map_err(|_| HttpError::resource_limit("adapter request body byte bound"))?;
    if response.bytes.sent_body > maximum_request_body_bytes_u64 {
        return Err(HttpError::RequestBodyLimit {
            actual: usize::try_from(response.bytes.sent_body)
                .map_err(|_| HttpError::resource_limit("adapter request body byte count"))?,
            maximum: maximum_request_body_bytes,
        });
    }
    let request_body_bytes = u64::try_from(request_body_bytes)
        .map_err(|_| HttpError::resource_limit("request body byte accounting"))?;
    if response.bytes.sent_body != 0 && response.bytes.sent_body < request_body_bytes {
        return Err(HttpError::Transport(crate::TransportError::Protocol(
            "adapter sent-body counter is smaller than request body".to_owned(),
        )));
    }
    Ok(())
}

fn validate_response(
    response: &Response,
    maximum_body_bytes: usize,
    maximum_headers: usize,
    maximum_header_bytes: usize,
) -> Result<(), HttpError> {
    crate::response::validate_status_code(response.status())?;
    if response.body().len() > maximum_body_bytes {
        return Err(HttpError::ResponseBodyLimit {
            actual: response.body().len(),
            maximum: maximum_body_bytes,
        });
    }
    if response.headers().len() > maximum_headers {
        return Err(HttpError::resource_limit("response header count"));
    }
    if response.headers().checked_wire_len()? > maximum_header_bytes {
        return Err(HttpError::resource_limit("response header bytes"));
    }
    Ok(())
}
