// SPDX-License-Identifier: Apache-2.0
//! HTTP execution orchestration over an injected transport.

use std::sync::Arc;

use crate::clock::{Clock, Deadline, SystemClock};
use crate::policy::{
    CompressionCodec, DecompressionPolicy, HARD_MAX_DECOMPRESSION_RATIO, HttpVersionPolicy,
    ProxyPolicy, RedirectPolicy, RetryPolicy, TimeoutConfig, TlsConfig,
    validate_decompression_limits, validate_response_body_limit,
};
use crate::request::{Body, Method, Request};
use crate::response::{ByteAccounting, HttpResult, Response};
use crate::state::{
    CacheDecision, DnsCache, ManagerPresence, SessionLimits, StateCommitError, StateCommitMode,
    StateLifecycle, UserHttpState,
};
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

impl ClientLimits {
    /// Validates caller-selected limits before any transport or body
    /// allocation is allowed.  The response-body and decompression helpers
    /// are deliberately called here as well as at the operation boundary so
    /// a config cannot raise the parser ceiling with a large `usize` value.
    pub fn validate(&self) -> Result<(), HttpError> {
        if self.max_request_body_bytes == 0
            || self.max_response_body_bytes == 0
            || self.max_header_fields == 0
            || self.max_header_bytes == 0
            || self.session.max_dns_entries == 0
            || self.session.max_cookies == 0
            || self.session.max_cache_entries == 0
            || self.session.max_cache_bytes == 0
            || self.session.max_auth_entries == 0
            || self.session.max_headers == 0
        {
            return Err(HttpError::resource_limit(
                "HTTP request/response limits must be non-zero",
            ));
        }
        validate_response_body_limit(self.max_response_body_bytes)?;
        let maximum_decoded_bytes = u64::try_from(self.max_response_body_bytes)
            .map_err(|_| HttpError::resource_limit("decompressed response hard maximum"))?;
        validate_decompression_limits(maximum_decoded_bytes, HARD_MAX_DECOMPRESSION_RATIO)
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
    /// HTTP protocol version policy passed to the transport.
    pub http_version: HttpVersionPolicy,
    /// Response decompression policy passed to the transport.
    pub decompression: DecompressionPolicy,
    /// Explicit retry ownership and bounds.
    pub retries: RetryPolicy,
    /// Per-operation timeout settings.
    pub timeouts: TimeoutConfig,
    /// Resource bounds.
    pub limits: ClientLimits,
    /// Whether cookie state is applied and updated when a Cookie Manager is
    /// present in the effective scope.
    pub cookies_enabled: bool,
    /// Whether cache state is consulted and updated when a Cache Manager is
    /// present in the effective scope.
    pub cache_enabled: bool,
    /// Whether auth state is applied and challenged when an Auth Manager is
    /// present in the effective scope.
    pub auth_enabled: bool,
    /// Whether configured headers are applied when a Header Manager is present
    /// in the effective scope.
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
            http_version: HttpVersionPolicy::default(),
            decompression: DecompressionPolicy::default(),
            retries: RetryPolicy::default(),
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
        self.limits.validate()?;
        validate_decompression_policy(&self.decompression, self.limits.max_response_body_bytes)?;
        self.redirects.validate()?;
        self.proxy.validate()?;
        self.decompression.validate()?;
        self.retries.validate()?;
        self.timeouts.validate()?;
        let maximum_tls_material = self
            .limits
            .max_response_body_bytes
            .checked_mul(2)
            .ok_or_else(|| HttpError::resource_limit("TLS material limit"))?;
        self.tls.validate(maximum_tls_material)
    }

    /// Returns manager capabilities that are active after applying both the
    /// config feature switches and effective-scope presence. An absent
    /// manager cannot be synthesized by a lower-level default switch.
    #[must_use]
    pub const fn effective_manager_presence(&self, presence: ManagerPresence) -> ManagerPresence {
        ManagerPresence {
            cookies: self.cookies_enabled && presence.cookies,
            cache: self.cache_enabled && presence.cache,
            auth: self.auth_enabled && presence.auth,
            headers: self.headers_enabled && presence.headers,
            dns: presence.dns,
        }
    }
}

/// The HTTP client owns transport-independent state for one virtual user.
pub struct HttpClient<T, C = SystemClock> {
    transport: T,
    config: ClientConfig,
    state: UserHttpState,
    clock: Arc<C>,
    manager_presence_explicit: bool,
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
            manager_presence_explicit: false,
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
            manager_presence_explicit: false,
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

    /// Returns the effective manager-presence flags supplied by the app edge.
    #[must_use]
    pub const fn manager_presence(&self) -> ManagerPresence {
        self.state.manager_presence()
    }

    /// Sets the effective manager-presence flags for subsequent samplers.
    ///
    /// The app edge resolves scope and precedence; the native semantic client
    /// only consumes the resulting presence set and never fabricates manager
    /// state for an absent component.
    pub const fn set_manager_presence(&mut self, presence: ManagerPresence) {
        self.manager_presence_explicit = true;
        self.state.set_manager_presence(presence);
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
        // Validate mutable configuration before taking the bounded state
        // snapshot. In particular, an above-hard-max response limit must
        // fail without cloning manager state or entering the transport path.
        self.config.validate()?;
        // Manager updates are staged for the complete logical sampler. A
        // transport/body/redirect failure must not expose a partially
        // applied cookie or cache update to the next sampler. `UserHttpState`
        // is bounded and cloneable, so this is a deterministic transaction
        // boundary for the synchronous semantic core. Native adapters have
        // their own lease/connection cleanup; this snapshot only protects
        // the core's observable per-user state.
        let state_before = self.state.clone();
        match self.execute_with_cancellation_inner(request, cancellation) {
            Ok((result, original_request)) => {
                match crate::RequestContext::from_request_owned(original_request)
                    .and_then(|context| result.with_request_context_owned(context))
                {
                    Ok(result) => Ok(result),
                    Err(error) => {
                        self.state = state_before;
                        Err(error)
                    }
                }
            }
            Err(error) => {
                self.state = state_before;
                Err(error)
            }
        }
    }

    fn execute_with_cancellation_inner(
        &mut self,
        request: Request,
        cancellation: CancellationToken,
    ) -> Result<(HttpResult, Request), HttpError> {
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
        // Keep the logical sampler's original request independent from the
        // per-hop request. `prepared` is already cloned for manager/header
        // application; moving `current` here avoids another full clone while
        // preserving the original method, URL, duplicate headers, and body
        // presence for the eventual JTL context.
        let mut original_request = None;
        let mut redirects = 0usize;
        let mut attempt_index = 0usize;
        let mut redirect_responses = Vec::new();
        let mut total_bytes = ByteAccounting::default();
        let mut retained_redirect_bytes = 0usize;
        let mut auth_challenges = 0usize;
        let mut allow_manager_sensitive = true;
        let mut allow_cookie_state = true;
        let mut allow_entity_headers = true;
        let mut allow_entity_manager_headers = true;
        let mut allow_redirect_authorization = true;
        let mut allow_auth_state = true;
        let mut allow_host_header = true;
        let presence = self.effective_manager_presence();
        let cookies_enabled = presence.cookies;
        let cache_enabled = presence.cache;
        let auth_enabled = presence.auth;
        let headers_enabled = presence.headers;
        let dns = if presence.dns {
            self.state.dns.clone()
        } else {
            DnsCache::default()
        };
        // Keep the last aggregate state that crossed a semantic commit
        // boundary. Comparing the complete bounded state (rather than only a
        // shape digest) also catches same-length cookie/cache replacements.
        let mut committed_state = self.state.clone();
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
            if headers_enabled {
                self.state.headers.apply_with_redirect_options(
                    &mut prepared,
                    allow_manager_sensitive,
                    allow_redirect_authorization,
                    allow_host_header,
                    allow_entity_headers,
                );
                if allow_entity_manager_headers && !allow_manager_sensitive {
                    self.apply_preserved_entity_manager_headers(&mut prepared);
                }
            }
            if cookies_enabled
                && allow_cookie_state
                && !prepared.headers().contains("cookie")
                && let Some(cookie) = self
                    .state
                    .cookies
                    .try_request_header(prepared.url(), before)?
            {
                prepared.add_header("Cookie", cookie)?;
            }
            if auth_enabled
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
            let cache_decision = if cache_enabled {
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
                self.check_operation_controls(
                    &cancellation,
                    overall_deadline,
                    TimeoutPhase::Overall,
                )?;
                self.commit_state_if_changed(
                    &mut committed_state,
                    StateCommitMode::CommitOnFinalSuccess,
                )?;
                return self.finish(
                    response,
                    redirect_responses,
                    total_bytes,
                    started,
                    original_request,
                    current,
                );
            }
            let has_stale_cache = match cache_decision {
                CacheDecision::Revalidate { headers, .. } => {
                    for field in &headers {
                        if !prepared.headers().contains(field.name().as_str()) {
                            prepared.headers_mut().append(field.clone());
                        }
                    }
                    true
                }
                _ => false,
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
                http_version: self.config.http_version,
                decompression: self.config.decompression.clone(),
                retries: self.config.retries,
                dns: dns.clone(),
                attempt: attempt_index,
                started_at: before,
                cancellation: cancellation.clone(),
            };
            attempt_index = attempt_index
                .checked_add(1)
                .ok_or_else(|| HttpError::resource_limit("HTTP attempt count"))?;
            let read_deadline = context.effective_deadline(TimeoutPhase::Read);
            let transport_response = match self.transport.send_with_control(&prepared, &context) {
                Ok(response) => response,
                Err(error) => {
                    self.check_operation_controls(
                        &cancellation,
                        overall_deadline,
                        TimeoutPhase::Overall,
                    )?;
                    return Err(map_transport_error(error));
                }
            };
            self.check_operation_controls(&cancellation, overall_deadline, TimeoutPhase::Overall)?;
            let transport_validation = validate_transport_response(
                &transport_response,
                self.config.limits.max_header_fields,
                self.config.limits.max_header_bytes,
                self.config.limits.max_response_body_bytes,
                self.config.limits.max_request_body_bytes,
                prepared.body().len(),
                &context.decompression,
            );
            if let Err(error) = transport_validation {
                if cache_enabled {
                    self.state.cache.invalidate(&prepared)?;
                }
                return Err(error);
            }
            // Recheck the caller-controlled limits immediately before body
            // collection.  `config_mut` is intentionally exposed for the app
            // edge, so a stale constructor validation must never become an
            // oversized `Vec` allocation or a decoder budget.
            self.config.limits.validate()?;
            validate_decompression_policy(
                &context.decompression,
                self.config.limits.max_response_body_bytes,
            )?;
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
                    if cache_enabled && prepared.method().is_idempotent() {
                        self.state.cache.invalidate(&prepared)?;
                    }
                    return Err(error);
                }
            };
            self.check_operation_controls(&cancellation, overall_deadline, TimeoutPhase::Overall)?;
            let response_validation = validate_response(
                &response,
                self.config.limits.max_response_body_bytes,
                self.config.limits.max_header_fields,
                self.config.limits.max_header_bytes,
            );
            if let Err(error) = response_validation {
                if cache_enabled {
                    self.state.cache.invalidate(&prepared)?;
                }
                return Err(error);
            }
            response.set_url(prepared.url().clone());
            self.check_operation_controls(&cancellation, overall_deadline, TimeoutPhase::Overall)?;
            // Manager deltas observe the wire response, not the cached
            // representation that may later be merged into a 304 result.
            // Process Set-Cookie before revalidation so stale cached headers
            // are never replayed as fresh response state.
            if cookies_enabled {
                let now = self.clock.now();
                if let Err(error) = self.state.cookies.store_set_cookie_headers(
                    prepared.url(),
                    response.headers(),
                    now,
                ) {
                    return self.response_error(&prepared, error);
                }
            }
            let mut revalidation_header_bytes = None;
            let was_revalidated = if has_stale_cache && response.status() == 304 {
                // A 304 has no selected representation body. Some test
                // transports model that as present-empty; canonicalize that
                // wire observation before entering the atomic cache
                // revalidation operation while retaining the cached entity.
                if !response.body().is_empty() {
                    return self.response_error(
                        &prepared,
                        HttpError::Cache("304 response must not contain an entity body".to_owned()),
                    );
                }
                let mut not_modified = response.clone();
                not_modified.set_body_absent();
                revalidation_header_bytes = Some(not_modified.headers().checked_wire_len()?);
                response =
                    self.state
                        .cache
                        .revalidate(&prepared, &not_modified, self.clock.now())?;
                if let Err(error) = validate_response(
                    &response,
                    self.config.limits.max_response_body_bytes,
                    self.config.limits.max_header_fields,
                    self.config.limits.max_header_bytes,
                ) {
                    return self.response_error(&prepared, error);
                }
                true
            } else {
                false
            };
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
                let header_bytes = match revalidation_header_bytes {
                    Some(bytes) => Ok(bytes),
                    None => response.headers().checked_wire_len(),
                };
                let header_bytes = match header_bytes {
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
            if cache_enabled
                && !was_revalidated
                && response.status() != 304
                && let Err(error) = self
                    .state
                    .cache
                    .store(&prepared, &response, self.clock.now())
            {
                return self.response_error(&prepared, error);
            }
            self.check_operation_controls(&cancellation, overall_deadline, TimeoutPhase::Overall)?;
            if auth_enabled
                && response.status() == 401
                && self.config.retry_basic_challenge
                && self.config.retries.maximum_auth_challenges != 0
                && auth_challenges < self.config.retries.maximum_auth_challenges
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
                auth_challenges = auth_challenges
                    .checked_add(1)
                    .ok_or_else(|| HttpError::resource_limit("authentication challenge count"))?;
                prepared.add_header("Authorization", authorization)?;
                if original_request.is_none() {
                    original_request = Some(current);
                }
                current = prepared;
                self.commit_state_if_changed(
                    &mut committed_state,
                    StateCommitMode::CommitBeforeNextAttempt,
                )?;
                continue;
            }
            if self.config.redirects.follow && response.is_redirect() {
                let Some(location) = response.headers().get("location") else {
                    self.check_operation_controls(
                        &cancellation,
                        overall_deadline,
                        TimeoutPhase::Overall,
                    )?;
                    self.commit_state_if_changed(
                        &mut committed_state,
                        StateCommitMode::CommitOnFinalSuccess,
                    )?;
                    return self.finish(
                        response,
                        redirect_responses,
                        total_bytes,
                        started,
                        original_request,
                        current,
                    );
                };
                if redirects >= self.config.redirects.maximum {
                    return Err(HttpError::RedirectLimit {
                        maximum: self.config.redirects.maximum,
                    });
                }
                let hop_bytes = response.checked_retained_bytes()?;
                retained_redirect_bytes = self
                    .config
                    .redirects
                    .retain(retained_redirect_bytes, hop_bytes)?;
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
                    allow_entity_manager_headers = false;
                    prepared.set_body(Body::Empty);
                    prepared.headers_mut().remove_entity_headers();
                }
                prepared.remove_header("cookie");
                if cross_origin {
                    // Cookies and proxy credentials are origin/route scoped.
                    // Authorization is forwarded only when the caller made
                    // the explicit compatibility choice and the source hop
                    // actually carried one. Entity metadata is also not
                    // forwarded across origins; the next hop will derive
                    // only the framing header required for a preserved body.
                    allow_manager_sensitive = false;
                    allow_cookie_state = false;
                    allow_redirect_authorization = false;
                    allow_auth_state = false;
                    allow_entity_manager_headers = false;
                    prepared.headers_mut().remove_entity_headers();
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
                if original_request.is_none() {
                    original_request = Some(current);
                }
                redirect_responses.push(response);
                current = prepared;
                redirects += 1;
                self.commit_state_if_changed(
                    &mut committed_state,
                    StateCommitMode::CommitBeforeNextAttempt,
                )?;
                continue;
            }
            self.check_operation_controls(&cancellation, overall_deadline, TimeoutPhase::Overall)?;
            self.commit_state_if_changed(
                &mut committed_state,
                StateCommitMode::CommitOnFinalSuccess,
            )?;
            return self.finish(
                response,
                redirect_responses,
                total_bytes,
                started,
                original_request,
                current,
            );
        }
    }

    fn finish(
        &self,
        response: Response,
        redirect_responses: Vec<Response>,
        bytes: ByteAccounting,
        started: crate::ClockReading,
        original_request: Option<Request>,
        current_request: Request,
    ) -> Result<(HttpResult, Request), HttpError> {
        let redirects = redirect_responses.len();
        let ended = self.clock.now();
        let elapsed = ended
            .monotonic
            .checked_sub(started.monotonic)
            .ok_or_else(|| HttpError::resource_limit("monotonic clock moved backwards"))?;
        let result = HttpResult::new(
            response,
            redirects,
            bytes,
            elapsed,
            started.wall_millis,
            ended.wall_millis,
        );
        let result = if redirects == 0 {
            result
        } else {
            result.with_redirect_responses(redirect_responses)?
        };
        Ok((result, original_request.unwrap_or(current_request)))
    }

    fn commit_state_if_changed(
        &mut self,
        committed_state: &mut UserHttpState,
        mode: StateCommitMode,
    ) -> Result<(), HttpError> {
        if self.state == *committed_state {
            return Ok(());
        }
        let transaction = self.state.begin_transaction();
        self.state
            .commit(mode, transaction)
            .map_err(map_state_commit_error)?;
        *committed_state = self.state.clone();
        Ok(())
    }

    fn apply_preserved_entity_manager_headers(&self, request: &mut Request) {
        for field in self.state.headers.headers() {
            let name = field.name().as_str();
            if name.len() >= 8
                && name.as_bytes()[..8].eq_ignore_ascii_case(b"content-")
                && !request.headers().contains(name)
            {
                request.headers_mut().append(field.clone());
            }
        }
    }

    fn check_operation_controls(
        &self,
        cancellation: &CancellationToken,
        overall_deadline: Option<Deadline>,
        timeout_phase: TimeoutPhase,
    ) -> Result<(), HttpError> {
        if cancellation.is_cancelled() {
            return Err(HttpError::Cancelled);
        }
        if overall_deadline.is_some_and(|deadline| deadline.expired(self.clock.now())) {
            return Err(HttpError::Timeout(timeout_phase));
        }
        Ok(())
    }

    fn response_error<R>(&mut self, request: &Request, error: HttpError) -> Result<R, HttpError> {
        if self.effective_manager_presence().cache {
            self.state.cache.invalidate(request)?;
        }
        Err(error)
    }

    fn effective_manager_presence(&self) -> ManagerPresence {
        let configured_presence = self.state.manager_presence();
        // Older embedders predate ManagerPresence and configure manager
        // stores directly through `state_mut`. Preserve that source-compatible
        // behavior until the app edge supplies an explicit presence set. Once
        // `set_manager_presence` is called (including with all fields absent),
        // absence is authoritative and no manager state is synthesized.
        if self.manager_presence_explicit || configured_presence != ManagerPresence::absent() {
            self.config.effective_manager_presence(configured_presence)
        } else {
            ManagerPresence {
                cookies: self.config.cookies_enabled,
                cache: self.config.cache_enabled,
                auth: self.config.auth_enabled,
                headers: self.config.headers_enabled,
                dns: true,
            }
        }
    }
}

fn map_transport_error(error: crate::TransportError) -> HttpError {
    match error {
        crate::TransportError::Timeout(phase) => HttpError::Timeout(phase),
        crate::TransportError::Cancelled => HttpError::Cancelled,
        error => HttpError::Transport(error),
    }
}

fn map_state_commit_error(error: StateCommitError) -> HttpError {
    match error {
        StateCommitError::Conflict => HttpError::Unsupported(
            "HTTP aggregate state commit conflicted with another owner".to_owned(),
        ),
        StateCommitError::InvalidCandidate(error) => *error,
    }
}

fn validate_decompression_policy(
    policy: &DecompressionPolicy,
    maximum_response_body_bytes: usize,
) -> Result<(), HttpError> {
    let DecompressionPolicy::Enabled {
        maximum_expansion_ratio,
        maximum_output_bytes,
        ..
    } = policy
    else {
        return Ok(());
    };
    let maximum_decoded_bytes = u64::try_from(*maximum_output_bytes)
        .map_err(|_| HttpError::resource_limit("decompressed response hard maximum"))?;
    validate_decompression_limits(maximum_decoded_bytes, *maximum_expansion_ratio)?;
    if *maximum_output_bytes > maximum_response_body_bytes {
        return Err(HttpError::resource_limit(
            "decompressed output exceeds response body limit",
        ));
    }
    Ok(())
}

fn validate_transport_response(
    response: &crate::TransportResponse,
    maximum_headers: usize,
    maximum_header_bytes: usize,
    maximum_body_bytes: usize,
    maximum_request_body_bytes: usize,
    request_body_bytes: usize,
    decompression: &DecompressionPolicy,
) -> Result<(), HttpError> {
    // Keep this boundary defensive for callers that mutate config between
    // construction and dispatch.  No adapter-supplied response metadata is
    // trusted until both product ceilings have been checked.
    validate_response_body_limit(maximum_body_bytes)?;
    validate_decompression_policy(decompression, maximum_body_bytes)?;
    crate::response::validate_status_code(response.status).map_err(|error| {
        HttpError::Transport(crate::TransportError::Protocol(error.to_string()))
    })?;
    if response.reason.len() > crate::response::MAX_RESPONSE_REASON_BYTES
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
    validate_content_encoding(&response.headers, decompression)?;
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

fn validate_content_encoding(
    headers: &crate::Headers,
    decompression: &DecompressionPolicy,
) -> Result<(), HttpError> {
    let mut codings = 0usize;
    for value in headers.values("content-encoding") {
        for coding in value.split(',') {
            codings = codings
                .checked_add(1)
                .ok_or_else(|| HttpError::resource_limit("content-encoding count"))?;
            if codings > 16 {
                return Err(HttpError::resource_limit("content-encoding count"));
            }
            let coding = coding.trim();
            if coding.is_empty() {
                return Err(HttpError::InvalidHeader(
                    "content-encoding contains an empty coding".to_owned(),
                ));
            }
            if coding.eq_ignore_ascii_case("identity") {
                continue;
            }
            let codec = if coding.eq_ignore_ascii_case("gzip") {
                CompressionCodec::Gzip
            } else if coding.eq_ignore_ascii_case("deflate") {
                CompressionCodec::Deflate
            } else if coding.eq_ignore_ascii_case("br") {
                CompressionCodec::Brotli
            } else {
                return Err(HttpError::Unsupported(
                    "response content encoding is unsupported".to_owned(),
                ));
            };
            if !decompression.allows(codec) {
                return Err(HttpError::Unsupported(
                    "response content encoding is not explicitly admitted".to_owned(),
                ));
            }
        }
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

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "tests use expect at assertion boundaries for fixed in-process fixtures"
    )]

    use super::*;
    use crate::response::{MAX_SAMPLER_DATA_BYTES, SampleResultProjectionOptions};
    use crate::{
        AuthEntry, AuthMechanism, HARD_MAX_RESPONSE_BODY_BYTES, ManagerPresence, ManualClock,
        TransportError, TransportResponse, Url,
    };
    use jmeter_rs_results::DataLimits;
    use std::collections::VecDeque;
    use std::sync::{Arc as TestArc, Mutex};

    #[derive(Debug)]
    struct OneResponse {
        response: Option<Response>,
    }

    impl Transport for OneResponse {
        fn send_stream(
            &mut self,
            _request: &Request,
            _context: &TransportContext,
        ) -> Result<TransportResponse, TransportError> {
            self.response
                .take()
                .map(TransportResponse::from_response_for_test)
                .ok_or_else(|| TransportError::ResourceLimit("test response queue".to_owned()))
        }
    }

    #[derive(Debug)]
    struct FixedResponses {
        responses: VecDeque<Response>,
    }

    impl FixedResponses {
        fn new(responses: impl IntoIterator<Item = Response>) -> Self {
            Self {
                responses: responses.into_iter().collect(),
            }
        }
    }

    impl Transport for FixedResponses {
        fn send_stream(
            &mut self,
            _request: &Request,
            _context: &TransportContext,
        ) -> Result<TransportResponse, TransportError> {
            self.responses
                .pop_front()
                .map(TransportResponse::from_response_for_test)
                .ok_or_else(|| TransportError::ResourceLimit("test response queue".to_owned()))
        }
    }

    fn response(status: u16, body: &str) -> Response {
        Response::with_body(status, body.as_bytes().to_vec()).expect("bounded response body")
    }

    #[derive(Debug)]
    struct CancelAfterDispatch {
        token: CancellationToken,
        response: Option<Response>,
    }

    impl Transport for CancelAfterDispatch {
        fn send_stream(
            &mut self,
            _request: &Request,
            _context: &TransportContext,
        ) -> Result<TransportResponse, TransportError> {
            self.token.cancel();
            self.response
                .take()
                .map(TransportResponse::from_response_for_test)
                .ok_or_else(|| TransportError::ResourceLimit("test response queue".to_owned()))
        }
    }

    #[test]
    fn config_manager_switches_cannot_enable_absent_managers() {
        let config = ClientConfig::default();
        assert_eq!(
            config.effective_manager_presence(ManagerPresence::absent()),
            ManagerPresence::absent()
        );
        let enabled = config.effective_manager_presence(ManagerPresence {
            cookies: true,
            cache: true,
            auth: true,
            headers: true,
            dns: true,
        });
        assert_eq!(enabled.cookies, config.cookies_enabled);
        assert_eq!(enabled.cache, config.cache_enabled);
        assert_eq!(enabled.auth, config.auth_enabled);
        assert_eq!(enabled.headers, config.headers_enabled);
        assert!(enabled.dns);
    }

    #[test]
    fn failed_logical_sampler_rolls_back_cookie_and_cache_state() {
        let mut response = Response::with_body(200, b"body".to_vec()).expect("response");
        response
            .add_header("Set-Cookie", "session=secret; Path=/")
            .expect("cookie");
        response
            .add_header("Cache-Control", "max-age=not-a-number")
            .expect("cache metadata");
        let clock = ManualClock::epoch();
        let transport = OneResponse {
            response: Some(response),
        };
        let mut client = HttpClient::with_clock(transport, ClientConfig::default(), clock.clone())
            .expect("client");
        client.set_manager_presence(ManagerPresence {
            cookies: true,
            cache: true,
            ..ManagerPresence::absent()
        });
        let request = Request::get("http://example.test/").expect("request");

        assert!(matches!(client.execute(request), Err(HttpError::Cache(_))));
        assert_eq!(
            client
                .state_mut()
                .cookies
                .try_request_header(
                    &Url::parse("http://example.test/").expect("url"),
                    clock.now(),
                )
                .expect("cookie lookup"),
            None
        );
        assert!(client.state().cache.is_empty());
    }

    #[test]
    fn redirect_retained_bytes_are_bounded_before_next_hop() {
        let mut redirect = Response::with_body(302, b"123456789".to_vec()).expect("response");
        redirect.add_header("Location", "/next").expect("location");
        let transport = OneResponse {
            response: Some(redirect),
        };
        let mut config = ClientConfig::default();
        config.redirects.maximum_retained_bytes = 8;
        let mut client = HttpClient::new(transport, config).expect("client");

        assert!(matches!(
            client.execute(Request::get("http://example.test/").expect("request")),
            Err(HttpError::ResourceLimit(message)) if message == "redirect retained bytes"
        ));
    }

    #[test]
    fn redirect_loop_stops_at_the_configured_hop_limit() {
        let mut first = response(302, "");
        first
            .add_header("Location", "/loop")
            .expect("redirect location");
        let mut second = response(302, "");
        second
            .add_header("Location", "/loop")
            .expect("redirect location");
        let mut third = response(302, "");
        third
            .add_header("Location", "/loop")
            .expect("redirect location");
        let mut config = ClientConfig::default();
        config.redirects.maximum = 2;
        let transport = FixedResponses::new([first, second, third]);
        let mut client = HttpClient::new(transport, config).expect("client");

        assert!(matches!(
            client.execute(Request::get("http://example.test/loop").expect("request")),
            Err(HttpError::RedirectLimit { maximum: 2 })
        ));
    }

    #[test]
    fn disabled_follow_mode_returns_the_redirect_without_a_second_attempt() {
        let mut redirect = response(302, "");
        redirect
            .add_header("Location", "/next")
            .expect("redirect location");
        let mut config = ClientConfig::default();
        config.redirects.follow = false;
        let transport = OneResponse {
            response: Some(redirect),
        };
        let mut client = HttpClient::new(transport, config).expect("client");

        let result = client
            .execute(Request::get("http://example.test/start").expect("request"))
            .expect("terminal redirect result");
        assert_eq!(result.response().status(), 302);
        assert_eq!(result.redirects(), 0);
        assert!(result.redirect_responses().is_none());
    }

    #[test]
    fn cancellation_after_dispatch_cannot_commit_response_state() {
        let token = CancellationToken::default();
        let mut response = Response::with_body(200, b"body".to_vec()).expect("response");
        response
            .add_header("Set-Cookie", "session=secret; Path=/")
            .expect("cookie");
        let transport = CancelAfterDispatch {
            token: token.clone(),
            response: Some(response),
        };
        let mut client = HttpClient::new(transport, ClientConfig::default()).expect("client");
        client.set_manager_presence(ManagerPresence {
            cookies: true,
            cache: true,
            ..ManagerPresence::absent()
        });

        assert_eq!(
            client
                .execute_with_cancellation(
                    Request::get("http://example.test/").expect("request"),
                    token,
                )
                .expect_err("cancellation after dispatch"),
            HttpError::Cancelled
        );
        assert!(client.state().cookies.cookies().is_empty());
        assert!(client.state().cache.is_empty());
    }

    #[test]
    fn absent_managers_do_not_synthesize_cookie_or_cache_effects() {
        let mut response = Response::with_body(200, b"body".to_vec()).expect("response");
        response
            .add_header("Set-Cookie", "session=secret; Path=/")
            .expect("cookie");
        response
            .add_header("Cache-Control", "max-age=60")
            .expect("cache metadata");
        let transport = OneResponse {
            response: Some(response),
        };
        let mut client = HttpClient::new(transport, ClientConfig::default()).expect("client");
        client.set_manager_presence(ManagerPresence::absent());

        client
            .execute(Request::get("http://example.test/").expect("request"))
            .expect("response");

        assert!(client.state().cookies.cookies().is_empty());
        assert!(client.state().cache.is_empty());
    }

    #[test]
    fn absent_auth_manager_does_not_apply_or_retry_credentials() {
        let mut challenge = Response::with_body(401, Vec::new()).expect("response");
        challenge
            .add_header("WWW-Authenticate", "Basic realm=fixture")
            .expect("challenge");
        let transport = OneResponse {
            response: Some(challenge),
        };
        let mut client = HttpClient::new(transport, ClientConfig::default()).expect("client");
        client.set_manager_presence(ManagerPresence::absent());
        client
            .state_mut()
            .auth
            .add(
                AuthEntry::new(
                    "http://example.test/",
                    "user",
                    "secret",
                    AuthMechanism::Basic,
                )
                .expect("auth entry"),
            )
            .expect("auth manager");

        let result = client
            .execute(Request::get("http://example.test/").expect("request"))
            .expect("challenge response");
        assert_eq!(result.response().status(), 401);
    }

    #[test]
    fn response_limit_above_hard_max_is_rejected_before_dispatch() {
        #[derive(Debug)]
        struct NoDispatch;

        impl Transport for NoDispatch {
            fn send_stream(
                &mut self,
                _request: &Request,
                _context: &TransportContext,
            ) -> Result<TransportResponse, TransportError> {
                Err(TransportError::ResourceLimit(
                    "transport was called unexpectedly".to_owned(),
                ))
            }
        }

        let mut client = HttpClient::new(NoDispatch, ClientConfig::default()).expect("client");
        client.config_mut().limits.max_response_body_bytes = HARD_MAX_RESPONSE_BODY_BYTES + 1;
        assert!(matches!(
            client.execute(Request::get("http://example.test/").expect("request")),
            Err(HttpError::ResourceLimit(message))
                if message == "response body limit must be non-zero and no greater than the product hard maximum"
        ));
    }

    #[test]
    fn transport_reason_phrase_uses_the_profiled_four_kib_bound() {
        let mut response = response(200, "ok");
        response.set_reason("r".repeat(crate::response::MAX_RESPONSE_REASON_BYTES));
        let transport = OneResponse {
            response: Some(response),
        };
        let mut client = HttpClient::new(transport, ClientConfig::default()).expect("client");

        assert!(
            client
                .execute(Request::get("http://example.test/").expect("request"))
                .is_ok()
        );
    }

    #[test]
    fn compressed_response_requires_explicit_decoder_policy() {
        let mut response = Response::with_body(200, b"encoded".to_vec()).expect("response");
        response
            .add_header("Content-Encoding", "gzip")
            .expect("content encoding");
        let transport = OneResponse {
            response: Some(response.clone()),
        };
        let mut client = HttpClient::new(transport, ClientConfig::default()).expect("client");
        assert!(matches!(
            client.execute(Request::get("http://example.test/").expect("request")),
            Err(HttpError::Unsupported(message)) if message == "response content encoding is not explicitly admitted"
        ));

        let transport = OneResponse {
            response: Some(response),
        };
        let config = ClientConfig {
            decompression: DecompressionPolicy::Enabled {
                codecs: vec![CompressionCodec::Gzip],
                maximum_expansion_ratio: 10,
                maximum_output_bytes: 1024,
                maximum_state_bytes: 1024,
            },
            ..ClientConfig::default()
        };
        let mut client = HttpClient::new(transport, config).expect("client");
        assert!(
            client
                .execute(Request::get("http://example.test/").expect("request"))
                .is_ok()
        );
    }

    #[test]
    fn successful_result_attaches_original_request_and_projects_standard_fields() {
        let transport = FixedResponses::new([response(200, "ok")]);
        let mut client = HttpClient::new(transport, ClientConfig::default()).expect("client");
        let request = Request::post("http://example.test/submit", b"body".to_vec())
            .expect("request")
            .with_header("X-Request", "one")
            .expect("header")
            .with_header("X-Request", "two")
            .expect("duplicate header");

        let result = client.execute(request).expect("successful request");
        let context = result.request_context().expect("automatic request context");
        assert_eq!(context.method(), "POST");
        assert_eq!(context.url().as_str(), "http://example.test/submit");
        assert_eq!(
            context.headers().values("x-request").collect::<Vec<_>>(),
            vec!["one", "two"]
        );
        assert_eq!(context.body(), Some(b"body".as_slice()));
        assert!(context.sampler_data().len() <= MAX_SAMPLER_DATA_BYTES);

        let projected = result
            .to_sample_result("http", &SampleResultProjectionOptions::default())
            .expect("sample projection");
        assert_eq!(projected.response_code(), Some("200"));
        assert_eq!(projected.response_message(), None);
        assert_eq!(projected.success(), Some(true));
        assert_eq!(projected.url(), Some("http://example.test/submit"));
        assert_eq!(
            projected.sampler_data(),
            Some("POST http://example.test/submit")
        );
        assert_eq!(
            projected.request_headers().map(|headers| headers.as_str()),
            Some("X-Request: one\r\nX-Request: two\r\n")
        );
        assert_eq!(
            projected.request_data().map(|data| data.as_bytes()),
            Some(b"body".as_slice())
        );
    }

    #[test]
    fn automatic_context_preserves_absent_and_present_empty_entities() {
        let transport = FixedResponses::new([response(200, "empty")]);
        let mut client = HttpClient::new(transport, ClientConfig::default()).expect("client");
        let absent = client
            .execute(Request::get("http://example.test/absent").expect("request"))
            .expect("absent-body result");
        assert_eq!(absent.request_context().expect("context").body(), None);

        let transport = FixedResponses::new([response(200, "empty")]);
        let mut client = HttpClient::new(transport, ClientConfig::default()).expect("client");
        let present = client
            .execute(
                Request::post("http://example.test/present", Vec::<u8>::new()).expect("request"),
            )
            .expect("present-empty result");
        assert_eq!(
            present.request_context().expect("context").body(),
            Some([].as_slice())
        );
    }

    #[test]
    fn cache_hit_and_redirect_results_keep_the_logical_original_context() {
        let mut cached = response(200, "cached");
        cached
            .add_header("Cache-Control", "max-age=60")
            .expect("cache header");
        let transport = FixedResponses::new([cached]);
        let mut client = HttpClient::new(transport, ClientConfig::default()).expect("client");
        let request = Request::get("http://example.test/cache").expect("request");
        client.execute(request.clone()).expect("populate cache");
        let cache_hit = client.execute(request).expect("cache hit");
        assert!(cache_hit.from_cache());
        assert_eq!(
            cache_hit
                .request_context()
                .expect("cache context")
                .url()
                .as_str(),
            "http://example.test/cache"
        );

        let mut redirect = response(302, "");
        redirect
            .add_header("Location", "/next")
            .expect("redirect location");
        let transport = FixedResponses::new([redirect, response(200, "final")]);
        let mut client = HttpClient::new(transport, ClientConfig::default()).expect("client");
        let request =
            Request::post("http://example.test/start", b"payload".to_vec()).expect("request");
        let redirected = client.execute(request).expect("redirect result");
        let context = redirected.request_context().expect("redirect context");
        assert_eq!(context.method(), "POST");
        assert_eq!(context.url().as_str(), "http://example.test/start");
        assert_eq!(context.body(), Some(b"payload".as_slice()));
    }

    #[test]
    fn followed_redirect_retains_wire_history_for_result_projection() {
        let mut redirect = response(302, "redirect");
        redirect
            .add_header("Location", "/next")
            .expect("redirect location");
        let transport = FixedResponses::new([redirect, response(200, "final")]);
        let mut client = HttpClient::new(transport, ClientConfig::default()).expect("client");

        let result = client
            .execute(Request::get("http://example.test/start").expect("request"))
            .expect("redirect result");
        assert_eq!(result.redirects(), 1);
        assert_eq!(result.redirect_responses().expect("history").len(), 1);

        let projected = result
            .to_sample_result("http", &SampleResultProjectionOptions::default())
            .expect("projected result");
        assert_eq!(projected.response_code(), Some("200"));
        assert_eq!(projected.sub_results().len(), 1);
        assert_eq!(projected.sub_results()[0].response_code(), Some("302"));
        assert_eq!(projected.sub_results()[0].label(), "http#redirect-1");
    }

    #[derive(Debug)]
    struct AttemptRecordingTransport {
        responses: VecDeque<Response>,
        attempts: TestArc<Mutex<Vec<usize>>>,
    }

    impl Transport for AttemptRecordingTransport {
        fn send_stream(
            &mut self,
            _request: &Request,
            context: &TransportContext,
        ) -> Result<TransportResponse, TransportError> {
            self.attempts
                .lock()
                .expect("attempt recording lock")
                .push(context.attempt);
            self.responses
                .pop_front()
                .map(TransportResponse::from_response_for_test)
                .ok_or_else(|| TransportError::ResourceLimit("test response queue".to_owned()))
        }
    }

    #[test]
    fn attempt_indices_advance_for_each_redirect_transport_attempt() {
        let attempts = TestArc::new(Mutex::new(Vec::new()));
        let mut first = response(302, "");
        first
            .add_header("Location", "/second")
            .expect("redirect location");
        let mut second = response(302, "");
        second
            .add_header("Location", "/final")
            .expect("redirect location");
        let transport = AttemptRecordingTransport {
            responses: [first, second, response(200, "final")]
                .into_iter()
                .collect(),
            attempts: attempts.clone(),
        };
        let mut client = HttpClient::new(transport, ClientConfig::default()).expect("client");

        client
            .execute(Request::get("http://example.test/start").expect("request"))
            .expect("redirect result");
        assert_eq!(
            attempts.lock().expect("attempt recording lock").as_slice(),
            &[0, 1, 2]
        );
    }

    #[derive(Debug)]
    struct RequestRecordingTransport {
        responses: VecDeque<Response>,
        requests: TestArc<Mutex<Vec<Request>>>,
    }

    impl Transport for RequestRecordingTransport {
        fn send_stream(
            &mut self,
            request: &Request,
            _context: &TransportContext,
        ) -> Result<TransportResponse, TransportError> {
            self.requests
                .lock()
                .expect("request recording lock")
                .push(request.clone());
            self.responses
                .pop_front()
                .map(TransportResponse::from_response_for_test)
                .ok_or_else(|| TransportError::ResourceLimit("test response queue".to_owned()))
        }
    }

    #[test]
    fn cross_origin_preserved_body_drops_entity_metadata() {
        let mut redirect = response(307, "");
        redirect
            .add_header("Location", "https://other.test/next")
            .expect("redirect location");
        let requests = TestArc::new(Mutex::new(Vec::new()));
        let transport = RequestRecordingTransport {
            responses: [redirect, response(200, "final")].into_iter().collect(),
            requests: requests.clone(),
        };
        let mut client = HttpClient::new(transport, ClientConfig::default()).expect("client");
        let request = Request::post("https://source.test/start", b"payload".to_vec())
            .expect("request")
            .with_header("Content-Type", "application/json")
            .expect("content type");

        client.execute(request).expect("redirect result");
        let requests = requests.lock().expect("request recording lock");
        assert_eq!(requests[1].method(), &Method::Post);
        assert_eq!(requests[1].body().as_bytes(), b"payload");
        assert!(!requests[1].headers().contains("content-type"));
        assert!(requests[1].headers().contains("content-length"));
    }

    #[test]
    fn same_origin_preserved_body_reapplies_entity_manager_headers() {
        let mut redirect = response(307, "");
        redirect
            .add_header("Location", "/next")
            .expect("redirect location");
        let requests = TestArc::new(Mutex::new(Vec::new()));
        let transport = RequestRecordingTransport {
            responses: [redirect, response(200, "final")].into_iter().collect(),
            requests: requests.clone(),
        };
        let mut client = HttpClient::new(transport, ClientConfig::default()).expect("client");
        client
            .state_mut()
            .headers
            .add("Content-Type", "application/json")
            .expect("content type");

        client
            .execute(
                Request::post("http://example.test/start", b"payload".to_vec()).expect("request"),
            )
            .expect("redirect result");
        let requests = requests.lock().expect("request recording lock");
        assert_eq!(requests[1].body().as_bytes(), b"payload");
        assert_eq!(
            requests[1].headers().get("content-type"),
            Some("application/json")
        );
    }

    #[test]
    fn state_generation_commits_each_successful_redirect_boundary() {
        let mut first = response(302, "");
        first
            .add_header("Location", "/next")
            .expect("redirect location");
        first
            .add_header("Set-Cookie", "first=1; Path=/")
            .expect("cookie");
        let mut final_response = response(200, "ok");
        final_response
            .add_header("Set-Cookie", "second=2; Path=/")
            .expect("cookie");
        let transport = FixedResponses::new([first, final_response]);
        let mut client = HttpClient::new(transport, ClientConfig::default()).expect("client");
        client.set_manager_presence(ManagerPresence {
            cookies: true,
            ..ManagerPresence::absent()
        });

        assert_eq!(client.state().generation(), 0);
        client
            .execute(Request::get("http://example.test/start").expect("request"))
            .expect("redirect result");
        assert_eq!(client.state().generation(), 2);
    }

    #[test]
    fn cache_revalidation_keeps_304_wire_header_and_body_accounting() {
        let clock = ManualClock::epoch();
        let mut stale = response(200, "old");
        stale
            .add_header("Cache-Control", "max-age=0")
            .expect("cache header");
        stale.add_header("ETag", "\"v1\"").expect("etag");
        let mut not_modified = response(304, "");
        not_modified
            .add_header("Cache-Control", "max-age=30")
            .expect("cache header");
        let expected_headers = not_modified
            .headers()
            .checked_wire_len()
            .expect("304 header bytes");
        let transport = FixedResponses::new([stale, not_modified]);
        let mut client =
            HttpClient::with_clock(transport, ClientConfig::default(), clock).expect("client");
        let request = Request::get("http://example.test/cache").expect("request");
        client.execute(request.clone()).expect("populate cache");
        let result = client.execute(request).expect("revalidation");

        assert!(result.from_cache());
        assert_eq!(result.response().body(), b"old");
        assert_eq!(result.response().bytes().received_body, 0);
        assert_eq!(
            result.response().bytes().received_headers,
            u64::try_from(expected_headers).expect("header bytes")
        );
    }

    #[test]
    fn cache_revalidation_rejects_a_body_bearing_304_without_replaying_it() {
        let mut stale = response(200, "old");
        stale
            .add_header("Cache-Control", "max-age=0")
            .expect("cache header");
        stale.add_header("ETag", "\"v1\"").expect("etag");
        let invalid = response(304, "unexpected-body");
        let transport = FixedResponses::new([stale, invalid]);
        let mut client = HttpClient::new(transport, ClientConfig::default()).expect("client");
        let request = Request::get("http://example.test/cache").expect("request");
        client.execute(request.clone()).expect("populate cache");

        assert!(matches!(
            client.execute(request),
            Err(HttpError::Cache(message))
                if message == "304 response must not contain an entity body"
        ));
    }

    #[test]
    fn request_metadata_projection_accepts_exact_body_limit_and_rejects_one_byte_over() {
        let transport = FixedResponses::new([response(200, "ok")]);
        let mut client = HttpClient::new(transport, ClientConfig::default()).expect("client");
        let result = client
            .execute(Request::post("http://example.test/body", b"1234".to_vec()).expect("request"))
            .expect("result");
        let exact = SampleResultProjectionOptions {
            data_limits: DataLimits::new(4, 4, 256, 256, 256),
            ..SampleResultProjectionOptions::default()
        };
        let projected = result
            .to_sample_result("http", &exact)
            .expect("exact bound");
        assert_eq!(
            projected.request_data().map(|data| data.as_bytes()),
            Some(b"1234".as_slice())
        );

        let too_small = SampleResultProjectionOptions {
            data_limits: DataLimits::new(3, 4, 256, 256, 256),
            ..SampleResultProjectionOptions::default()
        };
        let error = result
            .to_sample_result("http", &too_small)
            .expect_err("one byte over request body limit");
        assert_eq!(error.stable_code(), "http.resource-limit");
    }
}
