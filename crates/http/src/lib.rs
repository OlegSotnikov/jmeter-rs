// SPDX-License-Identifier: Apache-2.0
//! Explicit HTTP sampler and transport-policy boundary.
//!
//! The crate is deliberately a pure protocol core: it constructs requests,
//! applies bounded per-user state, selects explicit routes/TLS policy, follows
//! bounded redirects, and accounts for bytes/timing through an injected
//! [`Transport`]. It performs no socket, DNS, filesystem, environment, or
//! executor I/O. Production clients belong behind the transport seam.

#![forbid(unsafe_code)]

mod client;
mod clock;
mod config;
mod error;
mod header;
mod policy;
mod protocol_v1;
mod request;
mod response;
mod state;
mod transport;
mod url;

pub use client::{ClientConfig, ClientLimits, HttpClient};
pub use clock::{Clock, ClockError, ClockReading, Deadline, EpochClock, ManualClock, SystemClock};
pub use config::{
    AuthConfiguration, CacheConfiguration, ConfigScope, CookieConfiguration, DnsConfiguration,
    HttpImplementation, HttpRequestDefaults, MAX_AUTH_ENTRIES, MAX_CONFIG_BYTES, MAX_CONFIG_FIELDS,
    MAX_DNS_SERVERS, MAX_STATIC_DNS_HOSTS, OpaqueField, OptionalBool, OptionalString, Scoped,
    StaticDnsHost, WireConfig, merge_request_defaults,
};
pub use error::{HttpError, TimeoutPhase, TransportError};
pub use header::{Header, HeaderName, HeaderValue, Headers};
pub use policy::{
    ClientIdentity, HARD_MAX_REDIRECTS, NoProxy, Proxy, ProxyPolicy, ProxyScheme, RedirectPolicy,
    Route, TimeoutConfig, TlsConfig, TlsVerification, TlsVersion,
};
pub use protocol_v1::*;
pub use request::{Body, Method, Request, RequestBuilder, form_encode};
pub use response::{ByteAccounting, HttpResult, Response, ResponseTiming};
pub use state::{
    AuthEntry, AuthMechanism, AuthStore, CacheDecision, CacheStore, Cookie, CookieJar, DnsCache,
    DnsRecord, HeaderManager, PublicSuffixPolicy, SessionLimits, StateLifecycle, UserHttpState,
};
pub use transport::{
    CancellationRegistration, CancellationToken, ResponseBody, Transport, TransportAdapter,
    TransportContext, TransportResponse, UnsupportedTransport,
};
pub use url::{
    MAX_AUTHORITY_BYTES, MAX_FRAGMENT_BYTES, MAX_PATH_QUERY_BYTES, MAX_URL_BYTES, Origin, Url,
};

/// Compatibility alias for [`Method`] at HTTP-facing call sites.
pub type HttpMethod = Method;
/// Compatibility alias for [`Body`] at HTTP-facing call sites.
pub type RequestBody = Body;
/// Compatibility alias for [`Request`] at HTTP-facing call sites.
pub type HttpRequest = Request;
/// Compatibility alias for [`Response`] at HTTP-facing call sites.
pub type HttpResponse = Response;
/// Compatibility alias for [`Headers`] at HTTP-facing call sites.
pub type HeaderMap = Headers;
/// Compatibility alias for [`ClientConfig`].
pub type HttpClientConfig = ClientConfig;
/// Compatibility alias for [`CookieJar`].
pub type CookieManager = CookieJar;
/// Compatibility alias for [`CacheStore`].
pub type CacheManager = CacheStore;
/// Compatibility alias for [`AuthStore`].
pub type AuthManager = AuthStore;

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "tests use expect at assertion boundaries for fixed in-process fixtures"
    )]

    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::*;

    #[derive(Clone, Debug)]
    struct FakeTransport {
        responses: VecDeque<Result<Response, TransportError>>,
        requests: Arc<Mutex<Vec<(Request, TransportContext)>>>,
        clock: Option<ManualClock>,
        advance: Option<Duration>,
    }

    type CapturedRequests = Arc<Mutex<Vec<(Request, TransportContext)>>>;

    impl FakeTransport {
        fn new(responses: impl IntoIterator<Item = Response>) -> (Self, CapturedRequests) {
            let requests = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    responses: responses.into_iter().map(Ok).collect(),
                    requests: Arc::clone(&requests),
                    clock: None,
                    advance: None,
                },
                requests,
            )
        }

        fn with_clock(mut self, clock: ManualClock, advance: Duration) -> Self {
            self.clock = Some(clock);
            self.advance = Some(advance);
            self
        }
    }

    impl Transport for FakeTransport {
        fn send(
            &mut self,
            request: &Request,
            context: &TransportContext,
        ) -> Result<Response, TransportError> {
            self.requests
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((request.clone(), context.clone()));
            if let (Some(clock), Some(advance)) = (&self.clock, self.advance) {
                clock
                    .advance(advance)
                    .map_err(|_| TransportError::Timeout(TimeoutPhase::Overall))?;
            }
            self.responses.pop_front().unwrap_or_else(|| {
                Err(TransportError::ResourceLimit(
                    "fake response queue".to_owned(),
                ))
            })
        }

        fn send_stream(
            &mut self,
            request: &Request,
            context: &TransportContext,
        ) -> Result<TransportResponse, TransportError> {
            self.send(request, context)
                .map(TransportResponse::from_response_for_test)
        }
    }

    fn response(status: u16, body: &str) -> Response {
        Response::with_body(status, body.as_bytes().to_vec()).expect("bounded response body")
    }

    #[test]
    fn request_builder_validates_methods_headers_and_forms() {
        let request = Request::builder()
            .method_name("post")
            .expect("method")
            .url("http://example.test/submit")
            .expect("url")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .expect("header")
            .body(Body::text("a=1"))
            .build()
            .expect("request");
        assert_eq!(request.method().as_str(), "POST");
        assert_eq!(request.body().as_bytes(), b"a=1");
        assert_eq!(form_encode("a b&c"), "a+b%26c");
        assert!(HeaderName::new("bad name").is_err());
        assert!(HeaderValue::new("bad\r\nvalue").is_err());
    }

    #[test]
    fn redirect_changes_post_for_302_but_preserves_it_for_307() {
        let first = {
            let mut value = response(302, "");
            value.add_header("Location", "/next").expect("location");
            value
        };
        let second = response(200, "ok");
        let (transport, requests) = FakeTransport::new([first, second]);
        let mut client = HttpClient::new(transport, ClientConfig::default()).expect("client");
        let request =
            Request::post("http://example.test/start", b"payload".to_vec()).expect("request");
        let result = client.execute(request).expect("redirect");
        assert_eq!(result.redirects(), 1);
        let captured = requests.lock().expect("requests");
        assert_eq!(captured[0].0.method().as_str(), "POST");
        assert_eq!(captured[1].0.method().as_str(), "GET");
        assert!(captured[1].0.body().is_empty());

        let first = {
            let mut value = response(307, "");
            value.add_header("Location", "/next").expect("location");
            value
        };
        let second = response(200, "ok");
        let (transport, requests) = FakeTransport::new([first, second]);
        let mut client = HttpClient::new(transport, ClientConfig::default()).expect("client");
        client
            .execute(
                Request::post("http://example.test/start", b"payload".to_vec()).expect("request"),
            )
            .expect("redirect");
        let captured = requests.lock().expect("requests");
        assert_eq!(captured[1].0.method().as_str(), "POST");
        assert_eq!(captured[1].0.body().as_bytes(), b"payload");
    }

    #[test]
    fn redirects_are_not_served_as_terminal_cache_hits() {
        let mut redirect = response(302, "");
        redirect.add_header("Location", "/next").expect("location");
        redirect
            .add_header("Cache-Control", "max-age=60")
            .expect("cache");
        let (transport, requests) =
            FakeTransport::new([redirect, response(200, "first"), response(200, "second")]);
        let mut client = HttpClient::new(transport, ClientConfig::default()).expect("client");
        client
            .execute(Request::get("http://example.test/start").expect("request"))
            .expect("first");
        client
            .execute(Request::get("http://example.test/start").expect("request"))
            .expect("second");
        assert_eq!(requests.lock().expect("requests").len(), 3);
    }

    #[test]
    fn method_changing_redirect_does_not_reapply_entity_manager_headers() {
        let mut redirect = response(302, "");
        redirect.add_header("Location", "/next").expect("location");
        let (transport, requests) = FakeTransport::new([redirect, response(200, "ok")]);
        let mut client = HttpClient::new(transport, ClientConfig::default()).expect("client");
        client
            .state_mut()
            .headers
            .add("Content-Type", "application/json")
            .expect("header");
        client
            .execute(Request::post("http://example.test/start", b"body".to_vec()).expect("request"))
            .expect("redirect");
        let requests = requests.lock().expect("requests");
        assert!(requests[0].0.headers().contains("content-type"));
        assert!(!requests[1].0.headers().contains("content-type"));
    }

    #[test]
    fn cookies_are_scoped_sorted_and_expire_with_injected_clock() {
        let clock = ManualClock::epoch();
        let mut jar = CookieJar::new(4).expect("jar");
        let url = Url::parse("https://example.test/path/item").expect("url");
        let mut headers = Headers::new();
        headers
            .insert("Set-Cookie", "root=one; Path=/; Max-Age=10; Secure")
            .expect("cookie");
        headers
            .insert("Set-Cookie", "nested=two; Path=/path")
            .expect("cookie");
        jar.store_set_cookie_headers(&url, &headers, clock.now())
            .expect("store");
        assert_eq!(
            jar.request_header(&url, clock.now())
                .expect("cookie header")
                .as_deref(),
            Some("nested=two; root=one")
        );
        clock.advance(Duration::from_secs(11)).expect("advance");
        assert_eq!(
            jar.request_header(&url, clock.now())
                .expect("cookie header")
                .as_deref(),
            Some("nested=two")
        );
        let insecure = Url::parse("http://example.test/other").expect("url");
        assert_eq!(
            jar.request_header(&insecure, clock.now())
                .expect("cookie header"),
            None
        );
    }

    #[test]
    fn cache_serves_fresh_entries_and_revalidates_stale_entries() {
        let clock = ManualClock::epoch();
        let mut fresh = response(200, "cached");
        fresh
            .add_header("Cache-Control", "max-age=60")
            .expect("cache header");
        let (transport, requests) = FakeTransport::new([fresh]);
        let mut client = HttpClient::with_clock(transport, ClientConfig::default(), clock.clone())
            .expect("client");
        let request = Request::get("http://example.test/cache").expect("request");
        client.execute(request.clone()).expect("first");
        let second = client.execute(request).expect("cached");
        assert!(second.from_cache());
        assert_eq!(requests.lock().expect("requests").len(), 1);

        let clock = ManualClock::epoch();
        let mut stale = response(200, "old");
        stale
            .add_header("Cache-Control", "max-age=0")
            .expect("cache");
        stale.add_header("ETag", "\"v1\"").expect("etag");
        let mut not_modified = response(304, "");
        not_modified
            .add_header("Cache-Control", "max-age=30")
            .expect("cache");
        let (transport, requests) = FakeTransport::new([stale, not_modified]);
        let mut client =
            HttpClient::with_clock(transport, ClientConfig::default(), clock).expect("client");
        let request = Request::get("http://example.test/cache").expect("request");
        client.execute(request.clone()).expect("first");
        let result = client.execute(request).expect("revalidated");
        assert_eq!(result.response().body(), b"old");
        assert!(
            requests.lock().expect("requests")[1]
                .0
                .headers()
                .contains("If-None-Match")
        );
    }

    #[test]
    fn cache_honors_no_cache_vary_and_authorization_ordering() {
        let clock = ManualClock::epoch();
        let mut no_cache = response(200, "no-cache");
        no_cache
            .add_header("Cache-Control", "max-age=60, no-cache")
            .expect("cache");
        no_cache.add_header("ETag", "\"nc\"").expect("etag");
        let mut not_modified = response(304, "");
        not_modified
            .add_header("Cache-Control", "max-age=60")
            .expect("cache");
        let (transport, requests) = FakeTransport::new([no_cache, not_modified]);
        let mut client = HttpClient::with_clock(transport, ClientConfig::default(), clock.clone())
            .expect("client");
        let request = Request::get("http://example.test/no-cache").expect("request");
        client.execute(request.clone()).expect("first");
        client.execute(request).expect("revalidate");
        assert!(
            requests.lock().expect("requests")[1]
                .0
                .headers()
                .contains("if-none-match")
        );

        let mut varied = response(200, "varied-a");
        varied
            .add_header("Cache-Control", "max-age=60")
            .expect("cache");
        varied.add_header("Vary", "X-Mode").expect("vary");
        let (transport, requests) = FakeTransport::new([varied, response(200, "varied-b")]);
        let mut client =
            HttpClient::with_clock(transport, ClientConfig::default(), clock).expect("client");
        let first = Request::get("http://example.test/vary")
            .expect("request")
            .with_header("X-Mode", "a")
            .expect("header");
        let second = Request::get("http://example.test/vary")
            .expect("request")
            .with_header("X-Mode", "b")
            .expect("header");
        client.execute(first).expect("first varied");
        client.execute(second).expect("second varied");
        assert_eq!(requests.lock().expect("requests").len(), 2);

        let mut private = response(200, "private");
        private
            .add_header("Cache-Control", "max-age=60")
            .expect("cache");
        let (transport, requests) = FakeTransport::new([private, response(200, "private-2")]);
        let mut client =
            HttpClient::with_clock(transport, ClientConfig::default(), ManualClock::epoch())
                .expect("client");
        client
            .state_mut()
            .auth
            .add(
                AuthEntry::new(
                    "http://example.test/private",
                    "user",
                    "secret",
                    AuthMechanism::Basic,
                )
                .expect("auth"),
            )
            .expect("auth");
        let private_request = Request::get("http://example.test/private").expect("request");
        client
            .execute(private_request.clone())
            .expect("first private");
        client.execute(private_request).expect("second private");
        assert_eq!(requests.lock().expect("requests").len(), 2);
    }

    #[test]
    fn proxy_no_proxy_and_tls_policy_are_explicit_in_transport_context() {
        let mut proxy = Proxy::new(ProxyScheme::Http, "proxy.test", 8080).expect("proxy");
        proxy
            .set_credentials("user", "secret")
            .expect("proxy credentials");
        let mut config = ClientConfig::default();
        config.proxy.http = Some(proxy);
        config.proxy.no_proxy =
            NoProxy::parse("*.internal.test|localhost").expect("no-proxy patterns");
        config.tls.minimum_version = TlsVersion::Tls1_3;
        let (transport, requests) = FakeTransport::new([response(200, "ok"), response(200, "ok")]);
        let mut client = HttpClient::new(transport, config).expect("client");
        client
            .execute(Request::get("https://public.test/").expect("request"))
            .expect("public");
        client
            .execute(Request::get("https://api.internal.test/").expect("request"))
            .expect("internal");
        let captured = requests.lock().expect("requests");
        assert!(matches!(captured[0].1.route, Route::Proxy(_)));
        assert!(matches!(captured[1].1.route, Route::Direct));
        assert_eq!(captured[0].1.tls.minimum_version, TlsVersion::Tls1_3);
    }

    #[test]
    fn overall_timeout_is_checked_without_wall_clock_sleep() {
        let clock = ManualClock::epoch();
        let mut config = ClientConfig::default();
        config.timeouts.overall = Some(Duration::from_secs(1));
        let (transport, _) = FakeTransport::new([response(200, "late")]);
        let transport = transport.with_clock(clock.clone(), Duration::from_secs(2));
        let mut client = HttpClient::with_clock(transport, config, clock).expect("client");
        let error = client
            .execute(Request::get("http://example.test/").expect("request"))
            .expect_err("timeout");
        assert_eq!(error.stable_code(), "http.timeout");
    }

    #[test]
    fn client_rejects_an_unbounded_overall_deadline() {
        let mut config = ClientConfig::default();
        config.timeouts.overall = None;
        let (transport, _) = FakeTransport::new([response(200, "never")]);
        assert!(matches!(
            HttpClient::new(transport, config),
            Err(HttpError::InvalidTimeout(_))
        ));
    }

    #[test]
    fn byte_accounting_accumulates_redirect_attempts() {
        let mut redirect = response(302, "x");
        redirect.add_header("Location", "/next").expect("location");
        let (transport, _) = FakeTransport::new([redirect, response(200, "done")]);
        let mut client = HttpClient::new(transport, ClientConfig::default()).expect("client");
        let result = client
            .execute(Request::get("http://example.test/").expect("request"))
            .expect("result");
        assert_eq!(result.bytes().received_body, 5);
        assert_eq!(result.response().body(), b"done");
    }

    #[test]
    fn url_redirect_resolution_handles_network_paths_and_dot_segments() {
        let base = Url::parse("http://example.test/a/b").expect("url");
        assert_eq!(base.join("next").expect("join").path(), "/a/next");
        assert_eq!(base.join("../next").expect("join").path(), "/next");
        assert_eq!(
            base.join("//other.test/x").expect("join").as_str(),
            "http://other.test/x"
        );
        assert_eq!(
            base.join("?q=1").expect("join").path_and_query(),
            "/a/b?q=1"
        );
    }

    #[test]
    fn auth_state_builds_basic_headers_and_rejects_digest_without_adapter() {
        let mut auth = AuthStore::new(2).expect("store");
        auth.add(
            AuthEntry::new(
                "http://example.test/api",
                "alice",
                "secret",
                AuthMechanism::Basic,
            )
            .expect("entry"),
        )
        .expect("add");
        let api = Url::parse("http://example.test/api/items").expect("url");
        assert_eq!(
            auth.authorization(&api).expect("authorization").as_deref(),
            Some("Basic YWxpY2U6c2VjcmV0")
        );
        let outside = Url::parse("http://example.test/apix").expect("url");
        assert_eq!(auth.authorization(&outside).expect("authorization"), None);
        auth.add(
            AuthEntry::new(
                "http://example.test/other",
                "alice",
                "secret",
                AuthMechanism::Digest,
            )
            .expect("entry"),
        )
        .expect("add");
        let error = auth.authorization(&Url::parse("http://example.test/other").expect("url"));
        assert!(matches!(error, Err(HttpError::Unsupported(_))));

        let mut challenged = response(401, "");
        challenged
            .add_header("WWW-Authenticate", "Basic realm=fixture")
            .expect("challenge");
        let (transport, requests) = FakeTransport::new([challenged, response(200, "ok")]);
        let config = ClientConfig {
            auth_enabled: false,
            ..ClientConfig::default()
        };
        let mut client = HttpClient::new(transport, config).expect("client");
        client
            .state_mut()
            .auth
            .add(
                AuthEntry::new(
                    "http://challenge.test/",
                    "alice",
                    "secret",
                    AuthMechanism::Basic,
                )
                .expect("entry"),
            )
            .expect("add");
        client
            .state_mut()
            .auth
            .add(
                AuthEntry::new(
                    "http://challenge.test/private",
                    "bearer-user",
                    "bearer-secret",
                    AuthMechanism::Bearer,
                )
                .expect("entry"),
            )
            .expect("add");
        client
            .execute(Request::get("http://challenge.test/private").expect("request"))
            .expect("challenge remains a single request when auth is disabled");
        let requests = requests.lock().expect("requests");
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].0.headers().get("authorization"), None);
    }

    #[test]
    fn expires_attribute_uses_the_injected_wall_clock() {
        let clock = ManualClock::new(1_500_000_000_000, Duration::ZERO);
        let url = Url::parse("http://example.test/").expect("url");
        let mut headers = Headers::new();
        headers
            .insert(
                "Set-Cookie",
                "old=value; Expires=Wed, 21 Oct 2015 07:28:00 GMT",
            )
            .expect("header");
        let mut jar = CookieJar::new(2).expect("jar");
        jar.store_set_cookie_headers(&url, &headers, clock.now())
            .expect("cookie");
        assert_eq!(
            jar.request_header(&url, clock.now())
                .expect("cookie header"),
            None
        );
    }

    #[test]
    fn public_suffix_domain_cookie_is_rejected_before_storage() {
        let url = Url::parse("https://foo.com/set").expect("url");
        let mut headers = Headers::new();
        headers
            .insert("Set-Cookie", "wide=value; Domain=.com; Path=/")
            .expect("cookie");
        let mut jar = CookieJar::new(8).expect("jar");
        assert_eq!(
            jar.store_set_cookie_headers(&url, &headers, ClockReading::new(0, Duration::ZERO))
                .expect("ignored public suffix"),
            0
        );
        let other = Url::parse("https://bar.com/").expect("url");
        assert_eq!(
            jar.request_header(&other, ClockReading::new(0, Duration::ZERO))
                .expect("cookie header"),
            None
        );
    }

    #[test]
    fn cross_origin_redirect_does_not_reapply_configured_secret_or_entity_headers() {
        let mut redirect = response(302, "");
        redirect
            .add_header("Location", "https://other.test/next")
            .expect("location");
        let (transport, requests) = FakeTransport::new([redirect, response(200, "ok")]);
        let mut client = HttpClient::new(transport, ClientConfig::default()).expect("client");
        client
            .state_mut()
            .headers
            .add("Authorization", "Bearer source")
            .expect("header");
        client
            .state_mut()
            .headers
            .add("Proxy-Authorization", "Basic source")
            .expect("header");
        client
            .state_mut()
            .headers
            .add("Cookie", "source=secret")
            .expect("header");
        client
            .state_mut()
            .headers
            .add("Content-Type", "application/json")
            .expect("header");
        client
            .execute(Request::get("https://source.test/start").expect("request"))
            .expect("redirect");
        let requests = requests.lock().expect("requests");
        assert_eq!(requests.len(), 2);
        for name in [
            "authorization",
            "proxy-authorization",
            "cookie",
            "content-type",
        ] {
            assert!(!requests[1].0.headers().contains(name), "{name}");
        }
    }

    #[test]
    fn cross_origin_redirect_does_not_send_a_shared_domain_cookie() {
        let mut redirect = response(302, "");
        redirect
            .add_header("Location", "https://other.example.test/next")
            .expect("location");
        let (transport, requests) = FakeTransport::new([redirect, response(200, "ok")]);
        let clock = ManualClock::epoch();
        let mut client = HttpClient::with_clock(transport, ClientConfig::default(), clock.clone())
            .expect("client");
        let source = Url::parse("https://source.example.test/start").expect("url");
        let mut set_cookie = Headers::new();
        set_cookie
            .insert("Set-Cookie", "shared=secret; Domain=.example.test; Path=/")
            .expect("cookie");
        client
            .state_mut()
            .cookies
            .store_set_cookie_headers(&source, &set_cookie, clock.now())
            .expect("cookie");
        client
            .execute(Request::get(source.as_str()).expect("request"))
            .expect("redirect");
        assert!(
            !requests.lock().expect("requests")[1]
                .0
                .headers()
                .contains("cookie")
        );
    }

    #[test]
    fn url_rejects_controls_ports_and_unbounded_locations() {
        assert!(Url::parse("http://example.test/a\u{7f}").is_err());
        assert!(Url::parse("http://example.test:0/").is_err());
        assert!(
            Url::parse("http://example.test/")
                .expect("url")
                .join(&"/x".repeat(5000))
                .is_err()
        );
    }

    #[test]
    fn cancellation_is_observed_before_transport_dispatch() {
        let token = CancellationToken::default();
        token.cancel();
        let (transport, requests) = FakeTransport::new([response(200, "never")]);
        let mut client = HttpClient::new(transport, ClientConfig::default()).expect("client");
        let error = client
            .execute_with_cancellation(
                Request::get("http://example.test/").expect("request"),
                token,
            )
            .expect_err("cancelled");
        assert_eq!(error, HttpError::Cancelled);
        assert!(requests.lock().expect("requests").is_empty());
    }

    #[test]
    fn cache_evicts_by_aggregate_bytes_and_expires_header() {
        let clock = ManualClock::new(1_500_000_000_000, Duration::ZERO);
        let url = Url::parse("http://example.test/cache").expect("url");
        let request = Request::get(url.as_str()).expect("request");
        let mut first = response(200, "first");
        first
            .add_header("Expires", "Wed, 21 Oct 2030 07:28:00 GMT")
            .expect("expires");
        let mut second = response(200, "second");
        second
            .add_header("Cache-Control", "max-age=60")
            .expect("cache");
        let mut cache = CacheStore::with_limits(4, 120).expect("cache");
        assert!(cache.store(&request, &first, clock.now()).expect("store"));
        assert!(cache.current_bytes() <= cache.maximum_bytes());
        let other = Request::get("http://example.test/other").expect("request");
        let _ = cache.store(&other, &second, clock.now()).expect("store");
        assert!(cache.current_bytes() <= 120);
    }

    #[test]
    fn dns_cache_is_bounded_and_uses_injected_expiry() {
        let clock = ManualClock::epoch();
        let mut dns = DnsCache::new(1).expect("dns");
        dns.insert(
            "example.test",
            ["192.0.2.1".to_owned()],
            Duration::from_secs(5),
        )
        .expect("record");
        assert_eq!(
            dns.lookup("EXAMPLE.TEST", clock.now()),
            Some(vec!["192.0.2.1".to_owned()])
        );
        clock.advance(Duration::from_secs(6)).expect("advance");
        assert_eq!(dns.lookup("example.test", clock.now()), None);
    }

    #[test]
    fn streaming_transport_body_is_bounded_before_response_materialization() {
        #[derive(Debug)]
        struct OneChunk;

        impl ResponseBody for OneChunk {
            fn next_chunk(
                &mut self,
                _maximum_bytes: usize,
            ) -> Result<Option<Vec<u8>>, TransportError> {
                Ok(Some(b"too-large".to_vec()))
            }
        }

        let response = TransportResponse {
            status: 200,
            reason: String::new(),
            headers: Headers::new(),
            body: Box::new(OneChunk),
            bytes: ByteAccounting::default(),
            timing: ResponseTiming::default(),
            url: None,
        };
        assert!(matches!(
            response.collect(2),
            Err(TransportError::ResourceLimit(_))
        ));
    }

    #[test]
    fn fixed_clock_is_rejected_for_client_execution() {
        let (transport, _) = FakeTransport::new([response(200, "never")]);
        assert!(matches!(
            HttpClient::with_clock(transport, ClientConfig::default(), EpochClock),
            Err(HttpError::Unsupported(_))
        ));
    }

    #[test]
    fn transport_context_carries_bounded_dns_state() {
        let clock = ManualClock::epoch();
        let (transport, requests) = FakeTransport::new([response(200, "ok")]);
        let mut client = HttpClient::with_clock(transport, ClientConfig::default(), clock.clone())
            .expect("client");
        client
            .state_mut()
            .dns
            .insert("example.test", ["192.0.2.10"], Duration::from_secs(30))
            .expect("dns");
        client
            .execute(Request::get("http://example.test/").expect("request"))
            .expect("response");
        let captured = requests.lock().expect("requests");
        assert_eq!(
            captured[0].1.dns_lookup("example.test", clock.now()),
            Some(vec!["192.0.2.10".to_owned()])
        );
    }

    #[test]
    fn cancellation_waker_is_called_and_registration_is_bounded() {
        let token = CancellationToken::default();
        let called = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let called_by_waker = Arc::clone(&called);
        let registration = token.register_waker(move || {
            called_by_waker.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        token.cancel();
        assert_eq!(called.load(std::sync::atomic::Ordering::SeqCst), 1);
        drop(registration);
        let late = Arc::clone(&called);
        let late_registration = token.register_waker(move || {
            late.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        assert_eq!(called.load(std::sync::atomic::Ordering::SeqCst), 2);
        drop(late_registration);
    }

    #[test]
    fn controlled_body_seam_rechecks_cancellation_after_adapter_read() {
        #[derive(Debug)]
        struct OneChunk;
        impl ResponseBody for OneChunk {
            fn next_chunk(
                &mut self,
                _maximum_bytes: usize,
            ) -> Result<Option<Vec<u8>>, TransportError> {
                Ok(Some(b"body".to_vec()))
            }

            fn next_chunk_with_control(
                &mut self,
                _maximum_bytes: usize,
                cancellation: &CancellationToken,
                _deadline: Option<Deadline>,
                _clock: Option<&dyn Clock>,
            ) -> Result<Option<Vec<u8>>, TransportError> {
                cancellation.cancel();
                Ok(Some(b"body".to_vec()))
            }
        }
        let token = CancellationToken::default();
        let response = TransportResponse {
            status: 200,
            reason: String::new(),
            headers: Headers::new(),
            body: Box::new(OneChunk),
            bytes: ByteAccounting::default(),
            timing: ResponseTiming::default(),
            url: None,
        };
        let clock = ManualClock::epoch();
        let error = response
            .collect_with_limits(
                16,
                &token,
                Some(Deadline::after(clock.now(), Duration::from_secs(1)).expect("deadline")),
                Some(&clock),
            )
            .expect_err("cancelled after adapter read");
        assert_eq!(error, TransportError::Cancelled);
    }

    #[test]
    fn redirects_strip_host_and_reselect_path_scoped_auth() {
        let mut redirect = response(302, "");
        redirect
            .add_header("Location", "http://example.test/private/next")
            .expect("location");
        let (transport, requests) = FakeTransport::new([redirect, response(200, "ok")]);
        let mut client = HttpClient::new(transport, ClientConfig::default()).expect("client");
        client
            .state_mut()
            .headers
            .add("Host", "wrong.example.test")
            .expect("host");
        client
            .state_mut()
            .auth
            .add(
                AuthEntry::new(
                    "http://example.test/private",
                    "user",
                    "secret",
                    AuthMechanism::Basic,
                )
                .expect("auth"),
            )
            .expect("auth");
        client
            .execute(Request::get("http://example.test/public/start").expect("request"))
            .expect("redirect");
        let captured = requests.lock().expect("requests");
        assert_eq!(captured[1].0.headers().get("host"), None);
        assert_eq!(
            captured[1].0.headers().get("authorization"),
            Some("Basic dXNlcjpzZWNyZXQ=")
        );
    }

    #[test]
    fn url_wire_form_excludes_fragment_and_rejects_bad_escapes() {
        let url = Url::parse("http://[2001:db8::1]/path?q=%2F#fragment").expect("url");
        assert_eq!(url.wire_target(), "/path?q=%2F");
        assert_eq!(url.wire_form(), "http://[2001:db8::1]/path?q=%2F");
        assert!(Url::parse("http://example.test/%ZZ").is_err());
        assert!(Url::parse("http://[2001:db8::1").is_err());
        assert_eq!(
            Url::parse("http://example.test/a//b")
                .expect("url")
                .join("../c")
                .expect("join")
                .path(),
            "/c"
        );
        assert_eq!(
            Url::parse("http://example.test/a//b")
                .expect("url")
                .join("./c")
                .expect("join")
                .path(),
            "/a/c"
        );
        assert_eq!(
            Url::parse("http://example.test/base")
                .expect("url")
                .join("/a//c")
                .expect("join")
                .path(),
            "/a//c"
        );
    }

    #[test]
    fn lifecycle_reset_and_cookie_names_are_explicitly_scoped() {
        let clock = ManualClock::epoch();
        let url = Url::parse("http://example.test/").expect("url");
        let mut jar = CookieJar::new(4).expect("jar");
        jar.add(
            Cookie::new("Name", "one", "example.test", "/").expect("cookie"),
            clock.now(),
        )
        .expect("cookie");
        jar.capture_initial();
        jar.add(
            Cookie::new("name", "two", "example.test", "/").expect("cookie"),
            clock.now(),
        )
        .expect("cookie");
        assert_eq!(
            jar.request_header(&url, clock.now())
                .expect("cookie header"),
            Some("Name=one; name=two".to_owned())
        );
        jar.reset_for_iteration(true);
        assert_eq!(
            jar.request_header(&url, clock.now())
                .expect("cookie header"),
            Some("Name=one".to_owned())
        );
    }

    #[test]
    fn adapter_errors_are_typed_and_redacted() {
        let error = TransportError::Adapter {
            code: "read-failed".to_owned(),
            message: "authorization=Bearer secret-token".to_owned(),
        };
        assert_eq!(error.code(), "http.transport.adapter");
        assert!(!error.to_string().contains("secret-token"));
    }

    #[test]
    fn header_debug_redacts_unknown_custom_values() {
        let header = Header::new("X-Internal-Token", "custom-secret-value").expect("header");
        let debug = format!("{header:?}");
        assert!(debug.contains("value_bytes"));
        assert!(!debug.contains("custom-secret-value"));
    }

    #[test]
    fn adapter_sent_body_counter_is_bounded_before_collection() {
        #[derive(Debug)]
        struct BadAccounting;
        impl Transport for BadAccounting {
            fn send(
                &mut self,
                _request: &Request,
                _context: &TransportContext,
            ) -> Result<Response, TransportError> {
                Err(TransportError::Adapter {
                    code: "unused".to_owned(),
                    message: "send should not be called".to_owned(),
                })
            }

            fn send_stream(
                &mut self,
                _request: &Request,
                _context: &TransportContext,
            ) -> Result<TransportResponse, TransportError> {
                let mut response = TransportResponse::from_response_for_test(response(200, "ok"));
                response.bytes.sent_body = 9;
                Ok(response)
            }
        }
        let mut config = ClientConfig::default();
        config.limits.max_request_body_bytes = 4;
        let mut client = HttpClient::new(BadAccounting, config).expect("client");
        let error = client
            .execute(Request::post("http://example.test/", b"x".to_vec()).expect("request"))
            .expect_err("sent body bound");
        assert!(matches!(error, HttpError::RequestBodyLimit { .. }));
    }

    #[test]
    fn phase_deadlines_never_extend_overall_deadline() {
        let config = TimeoutConfig {
            overall: Some(Duration::from_secs(2)),
            read: Some(Duration::from_secs(10)),
            ..TimeoutConfig::default()
        };
        let context = TransportContext {
            route: Route::Direct,
            timeouts: config,
            deadline: Some(Deadline {
                at: Duration::from_secs(2),
            }),
            tls: TlsConfig::default(),
            dns: DnsCache::default(),
            attempt: 0,
            started_at: ClockReading::new(0, Duration::ZERO),
            cancellation: CancellationToken::default(),
        };
        assert_eq!(
            context.effective_deadline(TimeoutPhase::Read),
            Some(Deadline {
                at: Duration::from_secs(2)
            })
        );
    }

    #[test]
    fn cache_hits_report_zero_wire_bytes_and_adapter_timing() {
        let clock = ManualClock::epoch();
        let mut cached = response(200, "cached");
        cached
            .add_header("Cache-Control", "max-age=60")
            .expect("cache header");
        cached.set_bytes(ByteAccounting::new(11, 7, 13, 7));
        cached.set_timing(ResponseTiming {
            connect: Some(Duration::from_millis(3)),
            tls: Some(Duration::from_millis(4)),
            latency: Some(Duration::from_millis(5)),
            elapsed: Some(Duration::from_millis(6)),
        });
        let (transport, requests) = FakeTransport::new([cached]);
        let mut client =
            HttpClient::with_clock(transport, ClientConfig::default(), clock).expect("client");
        let request = Request::get("http://example.test/cache-hit").expect("request");
        client.execute(request.clone()).expect("network response");
        let hit = client.execute(request).expect("cache response");
        assert!(hit.from_cache());
        assert_eq!(hit.bytes(), ByteAccounting::default());
        assert_eq!(hit.response().bytes(), ByteAccounting::default());
        assert_eq!(hit.response().timing(), ResponseTiming::default());
        assert_eq!(requests.lock().expect("requests").len(), 1);
    }

    #[test]
    fn duplicate_cache_fields_drive_revalidation_and_vary_selection() {
        let clock = ManualClock::epoch();
        let mut first = response(200, "varied-a");
        first
            .add_header("Cache-Control", "max-age=60")
            .expect("cache header");
        first
            .add_header("Cache-Control", "no-cache")
            .expect("cache header");
        first.add_header("ETag", "\"v1\"").expect("etag");
        first.add_header("Vary", "X-Mode").expect("vary");
        first.add_header("Vary", "X-Mode").expect("vary");
        let mut not_modified = response(304, "");
        not_modified
            .add_header("Cache-Control", "max-age=60")
            .expect("cache header");
        let (transport, requests) =
            FakeTransport::new([first, not_modified, response(200, "varied-b")]);
        let mut client =
            HttpClient::with_clock(transport, ClientConfig::default(), clock).expect("client");
        let first_request = Request::get("http://example.test/vary")
            .expect("request")
            .with_header("X-Mode", "a")
            .expect("header");
        client
            .execute(first_request.clone())
            .expect("initial response");
        let revalidated = client.execute(first_request).expect("revalidated response");
        assert_eq!(revalidated.response().body(), b"varied-a");
        let other_request = Request::get("http://example.test/vary")
            .expect("request")
            .with_header("X-Mode", "b")
            .expect("header");
        client.execute(other_request).expect("other variant");
        let requests = requests.lock().expect("requests");
        assert_eq!(requests.len(), 3);
        assert!(requests[1].0.headers().contains("if-none-match"));
        assert!(!requests[2].0.headers().contains("if-none-match"));
    }

    #[test]
    fn cache_switch_and_iteration_reset_are_explicit() {
        let clock = ManualClock::epoch();
        let mut config = ClientConfig {
            cache_enabled: false,
            ..ClientConfig::default()
        };
        let (transport, requests) =
            FakeTransport::new([response(200, "one"), response(200, "two")]);
        let mut client =
            HttpClient::with_clock(transport, config.clone(), clock.clone()).expect("client");
        let request = Request::get("http://example.test/switch").expect("request");
        assert!(!client.execute(request.clone()).expect("first").from_cache());
        assert!(!client.execute(request).expect("second").from_cache());
        assert_eq!(requests.lock().expect("requests").len(), 2);

        config.cache_enabled = true;
        let mut cached = response(200, "cached");
        cached
            .add_header("Cache-Control", "max-age=60")
            .expect("cache header");
        let (transport, requests) = FakeTransport::new([cached, response(200, "after-reset")]);
        let mut client = HttpClient::with_clock(transport, config, clock).expect("client");
        let request = Request::get("http://example.test/lifecycle").expect("request");
        client.execute(request.clone()).expect("initial response");
        client.reset_for_iteration(StateLifecycle {
            clear_cache_each_iteration: true,
            ..StateLifecycle::default()
        });
        assert!(!client.execute(request).expect("after reset").from_cache());
        assert_eq!(requests.lock().expect("requests").len(), 2);
    }

    #[test]
    fn cooperative_blocked_body_wakes_on_cancellation() {
        #[derive(Debug)]
        struct CooperativeBody {
            woke: Arc<AtomicBool>,
        }

        impl ResponseBody for CooperativeBody {
            fn next_chunk(
                &mut self,
                _maximum_bytes: usize,
            ) -> Result<Option<Vec<u8>>, TransportError> {
                Ok(None)
            }

            fn next_chunk_with_control(
                &mut self,
                _maximum_bytes: usize,
                cancellation: &CancellationToken,
                _deadline: Option<Deadline>,
                _clock: Option<&dyn Clock>,
            ) -> Result<Option<Vec<u8>>, TransportError> {
                let woke = Arc::clone(&self.woke);
                let registration = cancellation.register_waker(move || {
                    woke.store(true, Ordering::SeqCst);
                });
                cancellation.cancel();
                assert!(self.woke.load(Ordering::SeqCst));
                drop(registration);
                Ok(Some(b"late".to_vec()))
            }
        }

        let woke = Arc::new(AtomicBool::new(false));
        let token = CancellationToken::default();
        let response = TransportResponse {
            status: 200,
            reason: String::new(),
            headers: Headers::new(),
            body: Box::new(CooperativeBody {
                woke: Arc::clone(&woke),
            }),
            bytes: ByteAccounting::default(),
            timing: ResponseTiming::default(),
            url: None,
        };
        assert_eq!(
            response
                .collect_with_cancellation(16, &token)
                .expect_err("cancellation must stop collection"),
            TransportError::Cancelled
        );
        assert!(woke.load(Ordering::SeqCst));
    }

    #[test]
    fn cooperative_body_observes_manual_read_deadline_without_sleeping() {
        #[derive(Debug)]
        struct DeadlineBody {
            clock: ManualClock,
            woke: Arc<AtomicBool>,
        }

        impl ResponseBody for DeadlineBody {
            fn next_chunk(
                &mut self,
                _maximum_bytes: usize,
            ) -> Result<Option<Vec<u8>>, TransportError> {
                Ok(None)
            }

            fn next_chunk_with_control(
                &mut self,
                _maximum_bytes: usize,
                _cancellation: &CancellationToken,
                deadline: Option<Deadline>,
                _clock: Option<&dyn Clock>,
            ) -> Result<Option<Vec<u8>>, TransportError> {
                self.clock
                    .advance(Duration::from_secs(2))
                    .map_err(|_| TransportError::ResourceLimit("clock advance".to_owned()))?;
                if deadline.is_some_and(|deadline| deadline.expired(self.clock.now())) {
                    self.woke.store(true, Ordering::SeqCst);
                    return Err(TransportError::Timeout(TimeoutPhase::Read));
                }
                Ok(Some(b"body".to_vec()))
            }
        }

        let clock = ManualClock::epoch();
        let woke = Arc::new(AtomicBool::new(false));
        let deadline = Deadline::after(clock.now(), Duration::from_secs(1)).expect("deadline");
        let response = TransportResponse {
            status: 200,
            reason: String::new(),
            headers: Headers::new(),
            body: Box::new(DeadlineBody {
                clock: clock.clone(),
                woke: Arc::clone(&woke),
            }),
            bytes: ByteAccounting::default(),
            timing: ResponseTiming::default(),
            url: None,
        };
        assert_eq!(
            response
                .collect_with_deadline(
                    16,
                    &CancellationToken::default(),
                    Some(deadline),
                    Some(&clock),
                    TimeoutPhase::Read,
                )
                .expect_err("read deadline must stop collection"),
            TransportError::Timeout(TimeoutPhase::Read)
        );
        assert!(woke.load(Ordering::SeqCst));
    }

    #[test]
    fn tls_default_verification_and_jmeter_compatibility_are_explicit() {
        assert_eq!(TlsConfig::default().verification, TlsVerification::Verify);
        assert_eq!(
            TlsConfig::jmeter_compatibility().verification,
            TlsVerification::Insecure
        );
        assert_eq!(TlsConfig::default().minimum_version, TlsVersion::Tls1_2);
        assert_eq!(TlsConfig::default().maximum_version, TlsVersion::Tls1_3);
    }

    #[test]
    fn materialized_transport_default_fails_closed() {
        #[derive(Debug)]
        struct LegacyOnly;

        impl Transport for LegacyOnly {
            fn send(
                &mut self,
                _request: &Request,
                _context: &TransportContext,
            ) -> Result<Response, TransportError> {
                Ok(response(200, "materialized"))
            }
        }

        let mut client = HttpClient::new(LegacyOnly, ClientConfig::default()).expect("client");
        let error = client
            .execute(Request::get("http://example.test/").expect("request"))
            .expect_err("legacy materialization must not bypass streaming");
        assert_eq!(error.stable_code(), "http.transport.unsupported");
    }

    #[test]
    fn proxy_and_no_proxy_bounds_fail_atomically() {
        let mut proxy = Proxy::new(ProxyScheme::Http, "proxy.test", 8080).expect("proxy");
        proxy
            .set_credentials("user", "secret")
            .expect("credentials");
        let oversized = "x".repeat(16 * 1024 + 1);
        assert!(proxy.set_credentials(oversized, "new-secret").is_err());
        assert_eq!(proxy.credentials(), Some(("user", "secret")));

        let mut no_proxy = NoProxy::none();
        assert!(no_proxy.add("bad pattern").is_err());
        assert_eq!(no_proxy.patterns().len(), 0);
        for index in 0..800 {
            let result = no_proxy.add(format!(
                "host-{index}-{}.{}.example.test",
                "x".repeat(50),
                "y".repeat(50)
            ));
            if result.is_err() {
                break;
            }
        }
        assert!(no_proxy.patterns().len() < 800);
        assert!(no_proxy.patterns().len() > 0);
    }

    #[test]
    fn cookie_header_overflow_is_returned_as_a_typed_error() {
        let clock = ManualClock::epoch();
        let mut jar = CookieJar::new(8).expect("jar");
        for index in 0..5 {
            jar.add(
                Cookie::new(
                    format!("cookie-{index}"),
                    "x".repeat(16 * 1024),
                    "example.test",
                    "/",
                )
                .expect("cookie"),
                clock.now(),
            )
            .expect("cookie");
        }
        let url = Url::parse("http://example.test/").expect("url");
        assert!(jar.request_header(&url, clock.now()).is_err());
    }

    #[test]
    fn checked_accounting_rejects_overflow() {
        let bytes = ByteAccounting::new(u64::MAX, 1, u64::MAX, 1);
        assert!(bytes.checked_sent_total().is_err());
        assert!(bytes.checked_received_total().is_err());
        assert!(bytes.checked_add(ByteAccounting::new(1, 0, 0, 0)).is_err());
        let timing = ResponseTiming {
            connect: Some(Duration::MAX),
            ..ResponseTiming::default()
        };
        assert!(timing.checked_add(timing).is_err());
    }

    #[test]
    fn fresh_cache_hits_validate_manager_header_count_and_bytes() {
        let mut cached = response(200, "cached");
        cached
            .add_header("Cache-Control", "max-age=60")
            .expect("cache header");
        let (transport, requests) = FakeTransport::new([cached]);
        let mut config = ClientConfig::default();
        config.limits.max_header_fields = 1;
        let mut client = HttpClient::new(transport, config).expect("client");
        let request = Request::get("http://example.test/manager-limit").expect("request");
        client.execute(request.clone()).expect("initial response");
        client
            .state_mut()
            .headers
            .add("X-First", "one")
            .expect("manager header");
        client
            .state_mut()
            .headers
            .add("X-Second", "two")
            .expect("manager header");
        assert!(matches!(
            client.execute(request),
            Err(HttpError::ResourceLimit(message)) if message == "request header count"
        ));
        assert_eq!(requests.lock().expect("requests").len(), 1);

        let mut cached = response(200, "cached");
        cached
            .add_header("Cache-Control", "max-age=60")
            .expect("cache header");
        let (transport, requests) = FakeTransport::new([cached]);
        let mut config = ClientConfig::default();
        config.limits.max_header_bytes = 32;
        let mut client = HttpClient::new(transport, config).expect("client");
        let request = Request::get("http://example.test/manager-bytes").expect("request");
        client.execute(request.clone()).expect("initial response");
        client
            .state_mut()
            .headers
            .add("X-Large", "x".repeat(30))
            .expect("manager header");
        assert!(matches!(
            client.execute(request),
            Err(HttpError::ResourceLimit(message)) if message == "request header bytes"
        ));
        assert_eq!(requests.lock().expect("requests").len(), 1);
    }

    #[test]
    fn non_cacheable_or_malformed_responses_invalidate_old_entries() {
        for directive in [
            Some("no-store, max-age=60"),
            Some("private, max-age=60"),
            None,
        ] {
            let now = ClockReading::new(0, Duration::ZERO);
            let request = Request::get("http://example.test/invalidate").expect("request");
            let mut stale = response(200, "stale");
            stale
                .add_header("Cache-Control", "max-age=0")
                .expect("cache header");
            stale.add_header("ETag", "\"old\"").expect("etag");
            let mut cache = CacheStore::new(8).expect("cache");
            assert!(cache.store(&request, &stale, now).expect("stale store"));
            let mut replacement = response(200, "replacement");
            if let Some(directive) = directive {
                replacement
                    .add_header("Cache-Control", directive)
                    .expect("cache header");
            }
            assert!(
                !cache
                    .store(&request, &replacement, now)
                    .expect("replacement store")
            );
            assert!(matches!(cache.lookup(&request, now), CacheDecision::Miss));
        }

        let now = ClockReading::new(0, Duration::ZERO);
        let request = Request::get("http://example.test/malformed").expect("request");
        let mut stale = response(200, "stale");
        stale
            .add_header("Cache-Control", "max-age=0")
            .expect("cache header");
        stale.add_header("ETag", "\"old\"").expect("etag");
        let mut cache = CacheStore::new(8).expect("cache");
        assert!(cache.store(&request, &stale, now).expect("stale store"));
        let invalid_status = Response::new(600);
        assert!(matches!(
            cache.store(&request, &invalid_status, now),
            Err(HttpError::InvalidHeader(_))
        ));
        assert!(matches!(cache.lookup(&request, now), CacheDecision::Miss));

        assert!(cache.store(&request, &stale, now).expect("stale restore"));
        let mut malformed = response(200, "malformed");
        malformed
            .add_header("Cache-Control", "max-age=not-a-number")
            .expect("cache header");
        assert!(matches!(
            cache.store(&request, &malformed, now),
            Err(HttpError::Cache(_))
        ));
        assert!(matches!(cache.lookup(&request, now), CacheDecision::Miss));

        let mut invalid_vary = response(200, "invalid-vary");
        invalid_vary
            .add_header("Cache-Control", "max-age=60")
            .expect("cache header");
        invalid_vary
            .add_header("Vary", "not a field")
            .expect("vary header");
        assert!(matches!(
            cache.store(&request, &invalid_vary, now),
            Err(HttpError::Cache(_))
        ));
        assert!(matches!(cache.lookup(&request, now), CacheDecision::Miss));
    }

    #[test]
    fn cache_and_user_state_debug_redact_query_strings() {
        let now = ClockReading::new(0, Duration::ZERO);
        let mut request = Request::get("http://example.test/path?access_token=raw-query-secret")
            .expect("request");
        request
            .add_header("X-Secret", "vary-secret-value")
            .expect("request header");
        let mut cached = response(200, "cached");
        cached
            .add_header("Cache-Control", "max-age=60")
            .expect("cache header");
        cached.add_header("Vary", "X-Secret").expect("vary header");
        let mut cache = CacheStore::new(2).expect("cache");
        assert!(cache.store(&request, &cached, now).expect("cache store"));
        let cache_debug = format!("{cache:?}");
        assert!(!cache_debug.contains("raw-query-secret"));
        assert!(!cache_debug.contains("access_token"));
        assert!(!cache_debug.contains("vary-secret-value"));

        let state = UserHttpState {
            cache,
            ..UserHttpState::default()
        };
        let state_debug = format!("{state:?}");
        assert!(!state_debug.contains("raw-query-secret"));
        assert!(!state_debug.contains("access_token"));
    }

    #[test]
    fn auth_challenges_require_matching_realms_and_support_wildcards() {
        let url = Url::parse("http://example.test/private").expect("url");
        let matching = AuthEntry::new(
            "http://example.test/private",
            "user",
            "secret",
            AuthMechanism::Basic,
        )
        .expect("entry")
        .try_realm("fixture")
        .expect("realm");
        let mut auth = AuthStore::new(8).expect("store");
        auth.add(matching).expect("add");
        assert!(
            auth.authorization_for_challenge(&url, "Basic realm=\"fixture\"")
                .expect("challenge")
                .is_some()
        );
        let unicode = AuthEntry::new(
            "http://example.test/private",
            "user",
            "secret",
            AuthMechanism::Basic,
        )
        .expect("entry")
        .try_realm("réalm")
        .expect("realm");
        let mut unicode_store = AuthStore::new(2).expect("store");
        unicode_store.add(unicode).expect("add");
        assert!(
            unicode_store
                .authorization_for_challenge(&url, "Basic realm=\"réalm\"")
                .expect("challenge")
                .is_some()
        );
        assert_eq!(
            auth.authorization_for_challenge(&url, "Basic realm=\"other\"")
                .expect("challenge"),
            None
        );
        assert_eq!(
            auth.authorization_for_challenge(&url, "Basic")
                .expect("challenge"),
            None
        );

        let wildcard = AuthEntry::new(
            "http://example.test/private",
            "user",
            "secret",
            AuthMechanism::Basic,
        )
        .expect("entry")
        .realm("*");
        let mut wildcard_store = AuthStore::new(2).expect("store");
        wildcard_store.add(wildcard).expect("add");
        assert!(
            wildcard_store
                .authorization_for_challenge(&url, "Basic realm=\"other\"")
                .expect("challenge")
                .is_some()
        );
        assert!(
            wildcard_store
                .authorization_for_challenge(&url, "Basic")
                .expect("challenge")
                .is_some()
        );

        let absent = AuthEntry::new(
            "http://example.test/private",
            "user",
            "secret",
            AuthMechanism::Basic,
        )
        .expect("entry");
        let mut absent_store = AuthStore::new(2).expect("store");
        absent_store.add(absent).expect("add");
        assert!(
            absent_store
                .authorization_for_challenge(&url, "Basic realm=\"other\"")
                .expect("challenge")
                .is_some()
        );
        let empty = AuthEntry::new(
            "http://example.test/private",
            "user",
            "secret",
            AuthMechanism::Basic,
        )
        .expect("entry")
        .realm("");
        let mut empty_store = AuthStore::new(2).expect("store");
        empty_store.add(empty).expect("add");
        assert!(
            empty_store
                .authorization_for_challenge(&url, "Basic realm=\"other\"")
                .expect("challenge")
                .is_some()
        );
        assert!(
            AuthEntry::new(
                "http://example.test/private",
                "user",
                "secret",
                AuthMechanism::Basic,
            )
            .expect("entry")
            .try_realm("x".repeat(257))
            .is_err()
        );
    }

    #[test]
    fn proxy_endpoints_require_strict_host_syntax_and_redact_credentials() {
        assert!(Proxy::new(ProxyScheme::Http, "proxy.example.test", 8080).is_ok());
        assert!(Proxy::new(ProxyScheme::Http, "192.0.2.1", 8080).is_ok());
        assert!(Proxy::new(ProxyScheme::Https, "2001:db8::1", 8443).is_ok());
        assert!(Proxy::new(ProxyScheme::Https, "[2001:db8::1]", 8443).is_ok());
        for host in [
            "",
            "proxy.example.test:8080",
            "user@proxy.example.test",
            "proxy.example.test/path",
            "proxy.example.test?token=secret",
            "proxy.example.test#fragment",
            "[proxy.example.test]",
            "[2001:db8::1",
            "proxy.example.test\n",
            "-proxy.example.test",
            "proxy..example.test",
            "proxy_example.test",
            "2001:db8::bad::address",
        ] {
            assert!(
                Proxy::new(ProxyScheme::Http, host, 8080).is_err(),
                "{host:?}"
            );
        }
        for value in [
            "http://proxy.example.test:8080/path",
            "http://proxy.example.test:8080?token=secret",
            "http://proxy.example.test:8080#fragment",
            "http://user:password@proxy.example.test:8080",
        ] {
            assert!(Proxy::parse(value).is_err(), "{value:?}");
        }
        let mut proxy = Proxy::new(ProxyScheme::Http, "proxy.example.test", 8080).expect("proxy");
        proxy
            .set_credentials("proxy-user", "proxy-password")
            .expect("credentials");
        let debug = format!("{proxy:?}");
        assert!(!debug.contains("proxy-user"));
        assert!(!debug.contains("proxy-password"));
        assert!(
            proxy
                .set_credentials("proxy\nuser", "new-password")
                .is_err()
        );
        assert_eq!(proxy.credentials(), Some(("proxy-user", "proxy-password")));
        for pattern in [
            "proxy.example.test/path",
            "proxy.example.test?token=secret",
            "user@proxy.example.test",
            "[proxy.example.test]",
            "proxy.example.test\n",
            "proxy_example.test",
            "proxy..example.test",
        ] {
            assert!(NoProxy::parse(pattern).is_err(), "{pattern:?}");
        }
    }

    #[test]
    fn invalid_http_status_codes_fail_at_transport_boundaries() {
        assert!(Response::with_body(99, b"bad".to_vec()).is_err());
        assert!(Response::with_body(600, b"bad".to_vec()).is_err());
        let invalid = TransportResponse::from_response_for_test(Response::new(600));
        assert!(matches!(
            invalid.collect(16),
            Err(TransportError::Protocol(message)) if message.contains("status code")
        ));
    }

    #[test]
    fn read_timeout_phase_is_preserved_for_legacy_body_adapters() {
        #[derive(Debug)]
        struct OverallTimeoutBody;
        impl ResponseBody for OverallTimeoutBody {
            fn next_chunk(
                &mut self,
                _maximum_bytes: usize,
            ) -> Result<Option<Vec<u8>>, TransportError> {
                Ok(None)
            }

            fn next_chunk_with_control(
                &mut self,
                _maximum_bytes: usize,
                _cancellation: &CancellationToken,
                _deadline: Option<Deadline>,
                _clock: Option<&dyn Clock>,
            ) -> Result<Option<Vec<u8>>, TransportError> {
                Err(TransportError::Timeout(TimeoutPhase::Overall))
            }
        }
        let clock = ManualClock::epoch();
        let response = TransportResponse {
            status: 200,
            reason: String::new(),
            headers: Headers::new(),
            body: Box::new(OverallTimeoutBody),
            bytes: ByteAccounting::default(),
            timing: ResponseTiming::default(),
            url: None,
        };
        let deadline = Deadline::after(clock.now(), Duration::from_secs(1)).expect("deadline");
        assert_eq!(
            response
                .collect_with_deadline(
                    16,
                    &CancellationToken::default(),
                    Some(deadline),
                    Some(&clock),
                    TimeoutPhase::Read,
                )
                .expect_err("read timeout"),
            TransportError::Timeout(TimeoutPhase::Read)
        );
    }

    #[test]
    fn every_transport_error_message_is_bounded_and_fully_redacted() {
        let secret_messages = [
            "Basic YWxpY2U6c2VjcmV0",
            "YWxpY2U6c2VjcmV0",
            "unknown-credential-value",
        ];
        let errors = secret_messages.into_iter().map(|message| {
            TransportError::Connect(format!("adapter detail: {message} {}", "x".repeat(2048)))
        });
        for error in errors {
            let debug = format!("{error:?}");
            let display = error.to_string();
            assert!(debug.len() < 512);
            assert!(display.len() < 512);
            assert!(!debug.contains("Basic"));
            assert!(!debug.contains("YWxpY2U6c2VjcmV0"));
            assert!(!debug.contains("unknown-credential-value"));
            assert!(!display.contains("Basic"));
            assert!(!display.contains("YWxpY2U6c2VjcmV0"));
            assert!(!display.contains("unknown-credential-value"));
        }
    }
}
