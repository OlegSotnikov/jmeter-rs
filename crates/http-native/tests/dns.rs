// SPDX-License-Identifier: Apache-2.0
//! DNS module harness.
//!
//! This path-based harness exercises the explicit DNS subordinate identity
//! used by `http.native/2` without changing the enclosing provider identity.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "fixture setup and panic-boundary assertions are intentional test inputs"
)]

#[path = "../src/dns.rs"]
mod dns;
#[path = "../src/dns_hickory.rs"]
mod dns_hickory;

use dns::{
    CanonicalName, DnsCancellationToken, DnsErrorCode, DnsQuery, DnsResolver, DnsResponse,
    FakeDnsResolver, MAX_DNS_ADDRESSES, PromiseFuture, PromiseState, StaticDnsResolver,
};
use dns_hickory::{HickoryDnsConfig, HickoryDnsResolver};
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

fn run_future<F>(future: F) -> F::Output
where
    F: Future,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("test runtime");
    runtime.block_on(future)
}

fn name(value: &str) -> CanonicalName {
    CanonicalName::parse(value).expect("canonical fixture name")
}

fn query(value: &str, deadline: Instant) -> DnsQuery {
    DnsQuery::new(name(value), deadline)
}

#[test]
fn canonical_names_are_absolute_and_reject_ambiguous_input() {
    assert_eq!(dns::DNS_EXPLICIT_CAPABILITY_ID, "http.dns.explicit/1");
    assert_eq!(name("Mixed.TEST").as_str(), "mixed.test.");
    assert_eq!(name("mixed.test").diagnostic().as_str(), "mixed.test.");
    assert_eq!(name("mixed.test.").as_str(), "mixed.test.");
    for invalid in ["", ".", "mixed..test", "mixed test", "mixed.test/"] {
        assert_eq!(
            CanonicalName::parse(invalid).map_err(|error| error.code()),
            Err(DnsErrorCode::InvalidHostname)
        );
    }
}

#[test]
fn response_order_deduplicates_and_rejects_over_limit_without_truncation() {
    let response = DnsResponse::from_addresses(
        name("mixed.test"),
        [
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
        ],
        5,
    )
    .expect("bounded response");
    assert_eq!(
        response.addresses(),
        &[
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ]
    );

    let too_many = (0..=MAX_DNS_ADDRESSES).map(|_| IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(
        DnsResponse::from_addresses(name("many.test"), too_many, MAX_DNS_ADDRESSES)
            .map_err(|error| error.code()),
        Err(DnsErrorCode::ResponseLimit)
    );
}

#[test]
fn retained_response_bytes_are_bounded_before_collection() {
    let name = name("a.test");
    let retained = name.as_str().len() + 4 + 16;
    let response = DnsResponse::from_addresses_with_limits(
        name.clone(),
        [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ],
        2,
        retained,
    )
    .expect("exact retained-byte budget");
    assert_eq!(response.retained_bytes(), retained);
    assert_eq!(
        DnsResponse::from_addresses_with_limits(
            name,
            [
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ],
            2,
            retained - 1,
        )
        .map_err(|error| error.code()),
        Err(DnsErrorCode::ResponseLimit)
    );

    let mut config = HickoryDnsConfig {
        nameservers: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53)],
        max_response_bytes: 0,
        ..HickoryDnsConfig::default()
    };
    assert_eq!(
        config.validate().map_err(|error| error.code()),
        Err(DnsErrorCode::InvalidConfig)
    );
    config.max_response_bytes = dns::MAX_DNS_RESPONSE_BYTES + 1;
    assert_eq!(
        config.validate().map_err(|error| error.code()),
        Err(DnsErrorCode::InvalidConfig)
    );
}

#[test]
fn static_and_fake_resolvers_are_executor_neutral_and_do_not_discover_hosts() {
    let mut static_resolver = StaticDnsResolver::new(4).expect("static bound");
    static_resolver
        .insert(
            name("fixture.test"),
            [
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::LOCALHOST),
            ],
        )
        .expect("static entry");
    assert_eq!(static_resolver.maximum_addresses(), 4);
    let response = run_future(static_resolver.resolve(query(
        "FIXTURE.TEST",
        Instant::now() + Duration::from_secs(1),
    )));
    assert_eq!(
        response.expect("static response").addresses(),
        &[IpAddr::V4(Ipv4Addr::LOCALHOST)]
    );
    let unknown = run_future(static_resolver.resolve(query(
        "unknown.test",
        Instant::now() + Duration::from_secs(1),
    )));
    assert_eq!(
        unknown.map_err(|error| error.code()),
        Err(DnsErrorCode::NxDomain)
    );

    let mut fake = FakeDnsResolver::new(2).expect("fake bound");
    fake.insert_error(name("malformed.test"), DnsErrorCode::MalformedResponse)
        .expect("fake error");
    fake.insert_addresses(name("address.test"), [IpAddr::V4(Ipv4Addr::LOCALHOST)])
        .expect("fake address");
    let malformed = run_future(fake.resolve(query(
        "malformed.test",
        Instant::now() + Duration::from_secs(1),
    )));
    assert_eq!(
        malformed.as_ref().err().map(|error| error.code()),
        Some(DnsErrorCode::MalformedResponse)
    );
    assert_eq!(
        malformed
            .as_ref()
            .err()
            .and_then(|error| error.hostname())
            .map(|hostname| hostname.as_str()),
        Some("malformed.test.")
    );
}

#[test]
fn cancellation_and_absolute_deadline_are_typed_without_sleeping() {
    let resolver = StaticDnsResolver::new(2).expect("static bound");
    let cancellation = DnsCancellationToken::default();
    cancellation.cancel();
    let cancelled = run_future(resolver.resolve(DnsQuery::with_cancellation(
        name("fixture.test"),
        Instant::now() + Duration::from_secs(1),
        cancellation,
    )));
    assert_eq!(
        cancelled.map_err(|error| error.code()),
        Err(DnsErrorCode::Cancelled)
    );

    let deadline = run_future(resolver.resolve(query("fixture.test", Instant::now())));
    assert_eq!(
        deadline.map_err(|error| error.code()),
        Err(DnsErrorCode::Deadline)
    );
}

#[test]
fn hickory_uses_only_explicit_loopback_nameserver_and_normalizes_a_aaaa() {
    let fixture = LocalDnsFixture::start().expect("loopback DNS fixture");
    let config = HickoryDnsConfig {
        nameservers: vec![fixture.address()],
        queue_capacity: 4,
        max_active_requests: 4,
        max_addresses: 8,
        max_response_bytes: dns::MAX_DNS_RESPONSE_BYTES,
        timeout: Duration::from_millis(250),
        attempts: 1,
        nameserver_concurrency: 1,
        startup_timeout: Duration::from_secs(1),
    };
    let (resolver, owner) = HickoryDnsResolver::start(config).expect("hickory actor");
    let _: Option<dns_hickory::HickoryResolver> = None;
    assert_eq!(resolver.configuration().max_addresses, 8);
    let response =
        run_future(resolver.resolve(query("mixed.test", Instant::now() + Duration::from_secs(1))))
            .expect("mixed DNS response");
    assert_eq!(response.name().as_str(), "mixed.test.");
    assert_eq!(
        response.addresses(),
        &[
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ]
    );
    assert_eq!(response.retained_bytes(), 11 + 4 + 4 + 16 + 16);
    owner.shutdown_and_join().expect("exact actor join");
}

#[test]
fn hickory_maps_nxdomain_malformed_and_response_limits() {
    let fixture = LocalDnsFixture::start().expect("loopback DNS fixture");
    let base = HickoryDnsConfig {
        nameservers: vec![fixture.address()],
        queue_capacity: 4,
        max_active_requests: 4,
        max_addresses: 2,
        max_response_bytes: dns::MAX_DNS_RESPONSE_BYTES,
        timeout: Duration::from_millis(250),
        attempts: 1,
        nameserver_concurrency: 1,
        startup_timeout: Duration::from_secs(1),
    };
    let (resolver, mut owner) = HickoryDnsResolver::start(base).expect("hickory actor");
    for (host, expected) in [
        ("nx.test", DnsErrorCode::NxDomain),
        ("malformed.test", DnsErrorCode::MalformedResponse),
        ("many.test", DnsErrorCode::ResponseLimit),
    ] {
        let result =
            run_future(resolver.resolve(query(host, Instant::now() + Duration::from_secs(1))));
        assert_eq!(result.map_err(|error| error.code()), Err(expected));
    }
    assert_eq!(
        owner.join().map_err(|error| error.code()),
        Err(DnsErrorCode::ShutdownRequired)
    );
    owner.shutdown().expect("shutdown request");
    owner.join().expect("exact finalization");
}

#[test]
fn hickory_cancellation_deadline_queue_and_stopped_paths_are_bounded() {
    let fixture = LocalDnsFixture::start().expect("loopback DNS fixture");
    let config = HickoryDnsConfig {
        nameservers: vec![fixture.address()],
        queue_capacity: 1,
        max_active_requests: 1,
        max_addresses: 2,
        max_response_bytes: dns::MAX_DNS_RESPONSE_BYTES,
        timeout: Duration::from_millis(100),
        attempts: 1,
        nameserver_concurrency: 1,
        startup_timeout: Duration::from_secs(1),
    };
    let (resolver, mut owner) = HickoryDnsResolver::start(config).expect("hickory actor");

    let cancellation = DnsCancellationToken::default();
    let in_flight = resolver.resolve(DnsQuery::with_cancellation(
        name("slow.test"),
        Instant::now() + Duration::from_secs(1),
        cancellation.clone(),
    ));
    fixture.wait_for_query();
    cancellation.cancel();
    assert_eq!(
        run_future(in_flight).map_err(|error| error.code()),
        Err(DnsErrorCode::Cancelled)
    );

    let deadline = run_future(resolver.resolve(query("slow.test", Instant::now())));
    assert_eq!(
        deadline.map_err(|error| error.code()),
        Err(DnsErrorCode::Deadline)
    );

    let mut pending = Vec::new();
    for _ in 0..128 {
        pending.push(resolver.resolve(query("slow.test", Instant::now() + Duration::from_secs(1))));
    }
    let mut queue_full = false;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("test runtime");
    for future in pending {
        match runtime.block_on(async { tokio::time::timeout(Duration::ZERO, future).await }) {
            Ok(Err(error)) if error.code() == DnsErrorCode::QueueFull => queue_full = true,
            Ok(_) | Err(_) => {}
        }
    }
    assert!(queue_full, "bounded submission must expose queue-full");

    owner.shutdown().expect("shutdown request");
    owner.join().expect("actor finalization");
    let stopped = run_future(resolver.resolve(query(
        "fixture.test",
        Instant::now() + Duration::from_secs(1),
    )));
    assert_eq!(
        stopped.map_err(|error| error.code()),
        Err(DnsErrorCode::Stopped)
    );
}

#[test]
fn promise_finalization_and_poll_use_cancellation_then_deadline_precedence() {
    let response =
        DnsResponse::from_addresses(name("result.test"), [IpAddr::V4(Ipv4Addr::LOCALHOST)], 1)
            .expect("fixture response");

    let deadline_state = PromiseState::new();
    let deadline_query = query("deadline.test", Instant::now());
    deadline_state.complete_observed(&deadline_query, Ok(response.clone()));
    let deadline_callbacks = Arc::new(AtomicUsize::new(0));
    let deadline_callbacks_for_future = deadline_callbacks.clone();
    let deadline_future = PromiseFuture::new(
        deadline_state,
        &deadline_query,
        Box::new(move |_| {
            deadline_callbacks_for_future.fetch_add(1, Ordering::SeqCst);
        }),
    );
    assert_eq!(
        run_future(deadline_future).map_err(|error| error.code()),
        Err(DnsErrorCode::Deadline)
    );
    assert_eq!(deadline_callbacks.load(Ordering::SeqCst), 1);

    let cancellation = DnsCancellationToken::default();
    let cancelled_state = PromiseState::new();
    let cancelled_query = DnsQuery::with_cancellation(
        name("cancelled.test"),
        Instant::now() + Duration::from_secs(1),
        cancellation.clone(),
    );
    cancellation.cancel();
    cancelled_state.complete_observed(&cancelled_query, Ok(response));
    let cancelled_future = PromiseFuture::new(cancelled_state, &cancelled_query, Box::new(|_| {}));
    assert_eq!(
        run_future(cancelled_future).map_err(|error| error.code()),
        Err(DnsErrorCode::Cancelled)
    );
}

#[test]
fn cancellation_callback_failure_keeps_terminal_promise_bounded() {
    let cancellation = DnsCancellationToken::default();
    cancellation.cancel();
    let query = DnsQuery::with_cancellation(
        name("callback-failure.test"),
        Instant::now() + Duration::from_secs(1),
        cancellation,
    );
    let future = PromiseFuture::new(
        PromiseState::new(),
        &query,
        Box::new(|_| panic!("callback failure fixture")),
    );
    assert_eq!(
        run_future(future).map_err(|error| error.code()),
        Err(DnsErrorCode::Cancelled)
    );
}

#[test]
fn provider_panic_is_a_typed_result_and_does_not_escape_the_task() {
    let panic_future = dns_hickory::PanicSafeLookup::new(
        async {
            panic!("deterministic provider panic fixture");
        },
        name("panic.test"),
    );
    assert_eq!(
        run_future(panic_future).map_err(|error| error.code()),
        Err(DnsErrorCode::Provider)
    );
}

#[test]
fn owner_drop_reaps_active_actor_without_detaching() {
    let fixture = LocalDnsFixture::start().expect("loopback DNS fixture");
    let config = HickoryDnsConfig {
        nameservers: vec![fixture.address()],
        queue_capacity: 2,
        max_active_requests: 1,
        max_addresses: 2,
        max_response_bytes: dns::MAX_DNS_RESPONSE_BYTES,
        timeout: Duration::from_secs(1),
        attempts: 1,
        nameserver_concurrency: 1,
        startup_timeout: Duration::from_secs(1),
    };
    let (resolver, owner) = HickoryDnsResolver::start(config).expect("hickory actor");
    let pending = resolver.resolve(query("slow.test", Instant::now() + Duration::from_secs(1)));
    fixture.wait_for_query();
    drop(pending);

    let (done_tx, done_rx) = mpsc::sync_channel(0);
    thread::spawn(move || {
        drop(owner);
        done_tx.send(()).expect("owner drop completion");
    });
    done_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("actor owner must join after bounded shutdown");
    assert_eq!(
        run_future(resolver.resolve(query(
            "fixture.test",
            Instant::now() + Duration::from_secs(1),
        )))
        .map_err(|error| error.code()),
        Err(DnsErrorCode::Stopped)
    );
}

#[test]
fn owner_shutdown_and_join_are_idempotent_for_the_exact_actor() {
    let fixture = LocalDnsFixture::start().expect("loopback DNS fixture");
    let config = HickoryDnsConfig {
        nameservers: vec![fixture.address()],
        queue_capacity: 1,
        max_active_requests: 1,
        max_addresses: 1,
        max_response_bytes: dns::MAX_DNS_RESPONSE_BYTES,
        timeout: Duration::from_millis(100),
        attempts: 1,
        nameserver_concurrency: 1,
        startup_timeout: Duration::from_secs(1),
    };
    let (resolver, mut owner) = HickoryDnsResolver::start(config).expect("hickory actor");

    owner.shutdown().expect("first shutdown request");
    owner.shutdown().expect("repeated shutdown request");
    owner.join().expect("first exact actor join");
    owner.join().expect("repeated exact actor join");
    assert_eq!(
        run_future(resolver.resolve(query(
            "after-stop.test",
            Instant::now() + Duration::from_secs(1),
        )))
        .map_err(|error| error.code()),
        Err(DnsErrorCode::Stopped)
    );
}

struct LocalDnsFixture {
    address: SocketAddr,
    shutdown_socket: UdpSocket,
    started_rx: mpsc::Receiver<()>,
    thread: Option<JoinHandle<()>>,
}

impl LocalDnsFixture {
    fn start() -> io::Result<Self> {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        let address = socket.local_addr()?;
        let shutdown_socket = socket.try_clone()?;
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name("jmeter-rs-test-dns".to_owned())
            .spawn(move || serve_dns(socket, started_tx))
            .map_err(io::Error::other)?;
        Ok(Self {
            address,
            shutdown_socket,
            started_rx,
            thread: Some(thread),
        })
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    fn wait_for_query(&self) {
        self.started_rx
            .recv()
            .expect("DNS fixture query notification");
    }
}

impl Drop for LocalDnsFixture {
    fn drop(&mut self) {
        let _ = self.shutdown_socket.send_to(b"__shutdown__", self.address);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve_dns(socket: UdpSocket, started_tx: mpsc::SyncSender<()>) {
    let mut packet = [0_u8; 2048];
    while let Ok((length, peer)) = socket.recv_from(&mut packet) {
        if &packet[..length] == b"__shutdown__" {
            break;
        }
        let _ = started_tx.try_send(());
        if let Some(response) = dns_response(&packet[..length]) {
            let _ = socket.send_to(&response, peer);
        }
    }
}

fn dns_response(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let transaction_id = [query[0], query[1]];
    let mut offset = 12usize;
    let mut labels = Vec::new();
    loop {
        let length = *query.get(offset)? as usize;
        offset = offset.checked_add(1)?;
        if length == 0 {
            break;
        }
        let end = offset.checked_add(length)?;
        if end > query.len() || length > 63 {
            return None;
        }
        labels.push(
            std::str::from_utf8(&query[offset..end])
                .ok()?
                .to_ascii_lowercase(),
        );
        offset = end;
    }
    let question_end = offset.checked_add(4)?;
    if question_end > query.len() {
        return None;
    }
    let host = format!("{}.", labels.join("."));
    let qtype = u16::from_be_bytes([query[offset], query[offset + 1]]);
    if host == "slow.test." {
        return None;
    }
    if host == "malformed.test." {
        return Some(transaction_id.to_vec());
    }
    let mut response = Vec::with_capacity(512);
    response.extend_from_slice(&transaction_id);
    let flags = if host == "nx.test." {
        0x8183_u16
    } else {
        0x8180_u16
    };
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    let answers = fixture_answers(&host, qtype);
    response.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&query[12..question_end]);
    for (record_type, bytes) in answers {
        response.extend_from_slice(&0xc00c_u16.to_be_bytes());
        response.extend_from_slice(&record_type.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&60_u32.to_be_bytes());
        response.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        response.extend_from_slice(&bytes);
    }
    Some(response)
}

fn fixture_answers(host: &str, qtype: u16) -> Vec<(u16, Vec<u8>)> {
    match (host, qtype) {
        ("mixed.test.", 1) => vec![
            (1, vec![127, 0, 0, 2]),
            (1, vec![127, 0, 0, 1]),
            (1, vec![127, 0, 0, 2]),
        ],
        ("mixed.test.", 28) => vec![
            (28, Ipv6Addr::LOCALHOST.octets().to_vec()),
            (28, Ipv6Addr::UNSPECIFIED.octets().to_vec()),
            (28, Ipv6Addr::LOCALHOST.octets().to_vec()),
        ],
        ("many.test.", 1) => vec![
            (1, vec![127, 0, 0, 1]),
            (1, vec![127, 0, 0, 2]),
            (1, vec![127, 0, 0, 3]),
        ],
        _ => Vec::new(),
    }
}
