// SPDX-License-Identifier: Apache-2.0
//! Explicit Hickory DNS adapter for the standalone `http.native/2` edge.
//!
//! One [`HickoryDnsResolverOwner`] owns one Tokio current-thread runtime and
//! one actor thread for the lifetime of the application. Query futures only
//! submit to bounded channels and observe a bounded promise; they never run
//! socket or DNS work in `Future::poll`.

use crate::dns::{
    DnsCancellationRegistration, DnsError, DnsErrorCode, DnsFuture, DnsQuery, DnsResolver,
    DnsResponse, MAX_DNS_ACTIVE_REQUESTS, MAX_DNS_ADDRESSES, MAX_DNS_ATTEMPTS,
    MAX_DNS_QUEUE_CAPACITY, MAX_DNS_RESPONSE_BYTES, MAX_DNS_TIMEOUT, PromiseFuture, PromiseState,
};
use hickory_resolver::config::{
    ConnectionConfig, LookupIpStrategy, NameServerConfig, ProtocolConfig, ResolveHosts,
    ResolverConfig, ResolverOpts, ServerOrderingStrategy,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::{Resolver, TokioResolver};
use std::collections::{BTreeSet, HashMap};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU64;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::task::{Context, Poll};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tokio::sync::{Notify, mpsc as tokio_mpsc};
use tokio::task::{AbortHandle, Id, JoinSet};

/// Maximum explicit numeric nameservers in one resolver configuration.
pub const MAX_DNS_NAMESERVERS: usize = 16;

/// Configuration for one bounded explicit Hickory resolver actor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HickoryDnsConfig {
    /// Numeric UDP nameserver endpoints.  No hostnames are accepted here.
    pub nameservers: Vec<SocketAddr>,
    /// Capacity of the request submission channel.
    pub queue_capacity: usize,
    /// Maximum DNS lookups active in the actor at once.
    pub max_active_requests: usize,
    /// Maximum A/AAAA records retained from one response.
    pub max_addresses: usize,
    /// Maximum canonical hostname plus unique address bytes retained from one
    /// response. Responses over this bound fail instead of being truncated.
    pub max_response_bytes: usize,
    /// One resolver-attempt timeout.  The query deadline remains authoritative.
    pub timeout: Duration,
    /// Number of upstream retries after an initial failure.
    pub attempts: usize,
    /// Number of nameservers queried concurrently for one lookup.
    pub nameserver_concurrency: usize,
    /// Finite startup handshake timeout.
    pub startup_timeout: Duration,
}

impl Default for HickoryDnsConfig {
    fn default() -> Self {
        Self {
            nameservers: Vec::new(),
            queue_capacity: 32,
            max_active_requests: 8,
            max_addresses: 16,
            max_response_bytes: MAX_DNS_RESPONSE_BYTES,
            timeout: Duration::from_secs(5),
            attempts: 2,
            nameserver_concurrency: 1,
            startup_timeout: Duration::from_secs(2),
        }
    }
}

impl HickoryDnsConfig {
    /// Validates all finite values before a runtime or socket is created.
    pub fn validate(&self) -> Result<(), DnsError> {
        if self.nameservers.is_empty() {
            return Err(DnsError::new(DnsErrorCode::NoNameservers));
        }
        if self.nameservers.len() > MAX_DNS_NAMESERVERS
            || self.nameservers.iter().any(|address| address.port() == 0)
        {
            return Err(DnsError::new(DnsErrorCode::InvalidConfig));
        }
        if self.queue_capacity == 0 || self.queue_capacity > MAX_DNS_QUEUE_CAPACITY {
            return Err(DnsError::new(DnsErrorCode::InvalidConfig));
        }
        if self.max_active_requests == 0 || self.max_active_requests > MAX_DNS_ACTIVE_REQUESTS {
            return Err(DnsError::new(DnsErrorCode::InvalidConfig));
        }
        if self.max_addresses == 0 || self.max_addresses > MAX_DNS_ADDRESSES {
            return Err(DnsError::new(DnsErrorCode::InvalidConfig));
        }
        if self.max_response_bytes == 0 || self.max_response_bytes > MAX_DNS_RESPONSE_BYTES {
            return Err(DnsError::new(DnsErrorCode::InvalidConfig));
        }
        if self.timeout.is_zero() || self.timeout > MAX_DNS_TIMEOUT {
            return Err(DnsError::new(DnsErrorCode::InvalidConfig));
        }
        if self.attempts == 0 || self.attempts > MAX_DNS_ATTEMPTS {
            return Err(DnsError::new(DnsErrorCode::InvalidConfig));
        }
        if self.nameserver_concurrency == 0 || self.nameserver_concurrency > self.nameservers.len()
        {
            return Err(DnsError::new(DnsErrorCode::InvalidConfig));
        }
        if self.startup_timeout.is_zero() || self.startup_timeout > MAX_DNS_TIMEOUT {
            return Err(DnsError::new(DnsErrorCode::InvalidConfig));
        }
        Ok(())
    }
}

/// Cloneable resolver handle backed by one application-owned actor.
#[derive(Clone, Debug)]
pub struct HickoryDnsResolver {
    request_tx: tokio_mpsc::Sender<ResolveCommand>,
    request_ids: Arc<RequestIdAllocator>,
    configuration: HickoryDnsConfig,
}

/// Allocates request IDs from one monotonically increasing, shared sequence.
///
/// Zero is reserved as the terminal exhausted state and is never returned as
/// an ID. A request ID is consumed before queue admission and is never
/// returned to the sequence when the queue is full, closed, or the caller
/// cancels the operation. This makes a rejected queue reservation an explicit
/// retirement rather than an opportunity to reuse an ID that may already have
/// escaped to an actor.
#[derive(Debug)]
struct RequestIdAllocator {
    next: AtomicU64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestIdAllocationError {
    Exhausted,
}

impl Default for RequestIdAllocator {
    fn default() -> Self {
        Self {
            next: AtomicU64::new(NonZeroU64::MIN.get()),
        }
    }
}

impl RequestIdAllocator {
    /// Reserves one nonzero ID, failing closed before an atomic wrap.
    fn allocate(&self) -> Result<NonZeroU64, RequestIdAllocationError> {
        let mut current = self.next.load(Ordering::Acquire);
        loop {
            let Some(request_id) = NonZeroU64::new(current) else {
                return Err(RequestIdAllocationError::Exhausted);
            };
            let next = current.checked_add(1).map_or(0, |next| next);
            match self.next.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(request_id),
                Err(observed) => current = observed,
            }
        }
    }

    #[cfg(test)]
    fn with_next_for_test(next: u64) -> Self {
        Self {
            next: AtomicU64::new(next),
        }
    }
}

/// Compatibility-friendly alias for the explicit Hickory resolver handle.
pub type HickoryResolver = HickoryDnsResolver;

/// Owner for the one actor runtime and its exact thread join handle.
pub struct HickoryDnsResolverOwner {
    control: Arc<ActorControl>,
    join: Option<JoinHandle<Result<(), DnsError>>>,
}

impl std::fmt::Debug for HickoryDnsResolverOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HickoryDnsResolverOwner")
            .field("shutdown_requested", &self.control.shutdown_requested())
            .field("joined", &self.join.is_none())
            .finish()
    }
}

impl HickoryDnsResolverOwner {
    /// Requests actor shutdown without waiting for the owned thread.
    pub fn shutdown(&self) -> Result<(), DnsError> {
        self.control.request_shutdown();
        Ok(())
    }

    /// Joins the owned actor thread after [`Self::shutdown`] was requested.
    pub fn join(&mut self) -> Result<(), DnsError> {
        if !self.control.shutdown_requested() {
            return Err(DnsError::new(DnsErrorCode::ShutdownRequired));
        }
        let Some(join) = self.join.take() else {
            return Ok(());
        };
        match join.join() {
            Ok(result) => result,
            Err(_) => Err(DnsError::new(DnsErrorCode::Internal)),
        }
    }

    /// Requests shutdown and joins the exact actor thread.
    pub fn shutdown_and_join(mut self) -> Result<(), DnsError> {
        self.shutdown()?;
        self.join()
    }
}

impl Drop for HickoryDnsResolverOwner {
    fn drop(&mut self) {
        if self.join.is_none() {
            return;
        }
        self.control.request_shutdown();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl HickoryDnsResolver {
    /// Starts one actor thread and its Tokio current-thread runtime.
    pub fn start(
        configuration: HickoryDnsConfig,
    ) -> Result<(Self, HickoryDnsResolverOwner), DnsError> {
        configuration.validate()?;

        let (request_tx, request_rx) = tokio_mpsc::channel(configuration.queue_capacity);
        let actor_control = Arc::new(ActorControl::default());
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let actor_configuration = configuration.clone();
        let actor_control_for_thread = actor_control.clone();
        let thread = thread::Builder::new()
            .name("jmeter-rs-dns-actor".to_owned())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(_) => {
                        let error = DnsError::new(DnsErrorCode::RuntimeUnavailable);
                        let _ = ready_tx.send(Err(error.clone()));
                        return Err(error);
                    }
                };
                let resolver = match build_hickory_resolver(&actor_configuration) {
                    Ok(resolver) => Arc::new(resolver),
                    Err(error) => {
                        let _ = ready_tx.send(Err(error.clone()));
                        return Err(error);
                    }
                };
                if ready_tx.send(Ok(())).is_err() {
                    return Ok(());
                }
                runtime.block_on(run_actor(
                    request_rx,
                    actor_control_for_thread,
                    resolver,
                    actor_configuration,
                ))
            })
            .map_err(|_| DnsError::new(DnsErrorCode::RuntimeUnavailable))?;

        match ready_rx.recv_timeout(configuration.startup_timeout) {
            Ok(Ok(())) => {
                let resolver = Self {
                    request_tx,
                    request_ids: Arc::new(RequestIdAllocator::default()),
                    configuration,
                };
                let owner = HickoryDnsResolverOwner {
                    control: actor_control,
                    join: Some(thread),
                };
                Ok((resolver, owner))
            }
            Ok(Err(error)) => {
                let _ = thread.join();
                Err(error)
            }
            Err(_) => {
                actor_control.request_shutdown();
                let _ = thread.join();
                Err(DnsError::new(DnsErrorCode::RuntimeUnavailable))
            }
        }
    }

    /// Returns the exact bounded configuration used by this handle.
    #[must_use]
    pub const fn configuration(&self) -> &HickoryDnsConfig {
        &self.configuration
    }
}

impl DnsResolver for HickoryDnsResolver {
    fn resolve(&self, query: DnsQuery) -> DnsFuture<'static> {
        if query.cancellation().is_cancelled() {
            return crate::dns::ready_future(Err(DnsError::for_name(
                DnsErrorCode::Cancelled,
                query.name(),
            )));
        }
        if Instant::now() >= query.deadline() {
            return crate::dns::ready_future(Err(DnsError::for_name(
                DnsErrorCode::Deadline,
                query.name(),
            )));
        }

        let request_id = match self.request_ids.allocate() {
            Ok(request_id) => request_id,
            Err(RequestIdAllocationError::Exhausted) => {
                // `DnsErrorCode::Internal` is the existing stable invariant
                // failure for this contract; do not expose atomic wraparound
                // or provider text as an ad-hoc error category.
                return crate::dns::ready_future(Err(DnsError::for_name(
                    DnsErrorCode::Internal,
                    query.name(),
                )));
            }
        };
        // Allocation itself is a reservation. Recheck the authoritative
        // cancellation/deadline state after reserving so a race cannot turn a
        // cancelled or expired query into a queue admission. The reserved ID
        // remains retired on either early return; it is never reused.
        if query.cancellation().is_cancelled() {
            return crate::dns::ready_future(Err(DnsError::for_name(
                DnsErrorCode::Cancelled,
                query.name(),
            )));
        }
        if Instant::now() >= query.deadline() {
            return crate::dns::ready_future(Err(DnsError::for_name(
                DnsErrorCode::Deadline,
                query.name(),
            )));
        }
        let promise = PromiseState::new();
        let cancellation = Arc::new(RequestCancellation::new(
            promise.clone(),
            query.name().clone(),
        ));
        let command = ResolveCommand {
            request_id,
            query: query.clone(),
            promise: promise.clone(),
            cancellation: cancellation.clone(),
        };
        match self.request_tx.try_send(command) {
            Ok(()) => {
                let on_cancel = Box::new(move |code| {
                    if code == DnsErrorCode::Cancelled {
                        cancellation.cancel();
                    } else {
                        cancellation.abort();
                    }
                });
                Box::pin(PromiseFuture::new(promise, &query, on_cancel))
            }
            Err(tokio_mpsc::error::TrySendError::Full(_)) => crate::dns::ready_future(Err(
                DnsError::for_name(DnsErrorCode::QueueFull, query.name()),
            )),
            Err(tokio_mpsc::error::TrySendError::Closed(_)) => crate::dns::ready_future(Err(
                DnsError::for_name(DnsErrorCode::Stopped, query.name()),
            )),
        }
    }
}

struct ActorControl {
    shutting_down: AtomicBool,
    shutdown_notify: Notify,
}

impl Default for ActorControl {
    fn default() -> Self {
        Self {
            shutting_down: AtomicBool::new(false),
            shutdown_notify: Notify::new(),
        }
    }
}

impl ActorControl {
    fn request_shutdown(&self) {
        if !self.shutting_down.swap(true, Ordering::AcqRel) {
            self.shutdown_notify.notify_one();
        }
    }

    fn shutdown_requested(&self) -> bool {
        self.shutting_down.load(Ordering::Acquire)
    }
}

struct ResolveCommand {
    request_id: NonZeroU64,
    query: DnsQuery,
    promise: Arc<PromiseState>,
    cancellation: Arc<RequestCancellation>,
}

struct ActiveRequest {
    promise: Arc<PromiseState>,
    query: DnsQuery,
    _cancellation: DnsCancellationRegistration,
    abort: AbortHandle,
}

type DnsTaskOutput = (NonZeroU64, Result<DnsResponse, DnsError>);
type DnsTaskJoin = Result<(Id, DnsTaskOutput), tokio::task::JoinError>;

/// Per-request cancellation bridge. Cancellation is a persistent notification
/// permit, so it cannot be lost between admission and task polling. The
/// promise is terminalized synchronously before the task is woken.
struct RequestCancellation {
    promise: Arc<PromiseState>,
    name: crate::dns::CanonicalName,
    requested: AtomicBool,
    notify: Arc<Notify>,
}

impl RequestCancellation {
    fn new(promise: Arc<PromiseState>, name: crate::dns::CanonicalName) -> Self {
        Self {
            promise,
            name,
            requested: AtomicBool::new(false),
            notify: Arc::new(Notify::new()),
        }
    }

    fn cancel(&self) {
        if !self.requested.swap(true, Ordering::AcqRel) {
            self.promise.complete_cancelled(&self.name);
        }
        self.abort();
    }

    fn abort(&self) {
        // Notify stores one permit when the task has not reached its select
        // yet, so cancellation cannot be lost between admission and polling.
        self.notify.notify_one();
    }

    async fn notified(&self) {
        self.notify.notified().await;
    }

    fn is_requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }
}

async fn run_actor(
    mut request_rx: tokio_mpsc::Receiver<ResolveCommand>,
    actor_control: Arc<ActorControl>,
    resolver: Arc<TokioResolver>,
    configuration: HickoryDnsConfig,
) -> Result<(), DnsError> {
    let mut tasks: JoinSet<DnsTaskOutput> = JoinSet::new();
    let mut active = HashMap::<NonZeroU64, ActiveRequest>::new();
    let mut task_ids = HashMap::<Id, NonZeroU64>::new();

    loop {
        tokio::select! {
            biased;
            _ = actor_control.shutdown_notify.notified() => break,
            Some(command) = request_rx.recv() => {
                handle_request(
                    command,
                    &mut active,
                    &mut tasks,
                    &mut task_ids,
                    &configuration,
                    resolver.clone(),
                );
            }
            Some(joined) = tasks.join_next_with_id() => {
                finish_task(joined, &mut active, &mut task_ids);
            }
            else => break,
        }
    }

    request_rx.close();
    while let Some(command) = request_rx.recv().await {
        command.promise.complete(Err(DnsError::for_name(
            DnsErrorCode::Stopped,
            command.query.name(),
        )));
    }
    for (_, request) in active.drain() {
        request.abort.abort();
        request
            .promise
            .complete(Err(DnsError::new(DnsErrorCode::Stopped)));
    }
    task_ids.clear();
    while let Some(joined) = tasks.join_next().await {
        if let Ok((request_id, _)) = joined {
            // The promise was terminalized above.  This branch only reaps the
            // exact owned task; no result is retained after shutdown.
            let _ = request_id;
        }
    }
    Ok(())
}

fn handle_request(
    command: ResolveCommand,
    active: &mut HashMap<NonZeroU64, ActiveRequest>,
    tasks: &mut JoinSet<DnsTaskOutput>,
    task_ids: &mut HashMap<Id, NonZeroU64>,
    configuration: &HickoryDnsConfig,
    resolver: Arc<TokioResolver>,
) {
    if command.promise.cancellation_requested() || command.query.cancellation().is_cancelled() {
        command.promise.complete_cancelled(command.query.name());
        return;
    }
    if Instant::now() >= command.query.deadline() {
        command.promise.complete(Err(DnsError::for_name(
            DnsErrorCode::Deadline,
            command.query.name(),
        )));
        return;
    }
    if active.len() >= configuration.max_active_requests {
        command.promise.complete(Err(DnsError::for_name(
            DnsErrorCode::ActiveLimit,
            command.query.name(),
        )));
        return;
    }

    let request_id = command.request_id;
    let promise = command.promise;
    let query = command.query;
    let request_cancellation = command.cancellation;
    let cancellation = query.cancellation().register(Arc::new({
        let request_cancellation = request_cancellation.clone();
        move || request_cancellation.cancel()
    }));
    if promise.cancellation_requested()
        || query.cancellation().is_cancelled()
        || request_cancellation.is_requested()
    {
        promise.complete_cancelled(query.name());
        drop(cancellation);
        return;
    }
    let max_addresses = configuration.max_addresses;
    let max_response_bytes = configuration.max_response_bytes;
    let diagnostic_name = query.name().clone();
    let cancel_name = diagnostic_name.clone();
    let task_query = query.clone();
    let task = tasks.spawn(async move {
        (
            request_id,
            tokio::select! {
                biased;
                _ = request_cancellation.notified() => {
                    let code = if request_cancellation.is_requested() {
                        DnsErrorCode::Cancelled
                    } else {
                        DnsErrorCode::Deadline
                    };
                    Err(DnsError::for_name(code, &cancel_name))
                }
                result = PanicSafeLookup::new(
                    lookup_one(resolver, task_query, max_addresses, max_response_bytes),
                    diagnostic_name,
                ) => result,
            },
        )
    });
    let task_id = task.id();
    let active_request = ActiveRequest {
        promise,
        query,
        _cancellation: cancellation,
        abort: task,
    };
    task_ids.insert(task_id, request_id);
    active.insert(request_id, active_request);
}

fn finish_task(
    joined: DnsTaskJoin,
    active: &mut HashMap<NonZeroU64, ActiveRequest>,
    task_ids: &mut HashMap<Id, NonZeroU64>,
) {
    match joined {
        Ok((task_id, (reported_request_id, result))) => {
            let Some(request_id) = task_ids.remove(&task_id) else {
                // A completed task without an ownership entry is an actor
                // invariant failure. Retire all bounded entries rather than
                // silently leaving an admission slot occupied.
                finish_join_error(None, active);
                return;
            };
            if request_id != reported_request_id {
                if let Some(request) = active.remove(&request_id) {
                    complete_join_error(request);
                }
            } else if let Some(request) = active.remove(&request_id) {
                request.promise.complete_observed(&request.query, result);
            }
        }
        Err(error) => {
            let task_id = error.id();
            let request_id = task_ids.remove(&task_id);
            finish_join_error(request_id, active);
        }
    }
}

fn finish_join_error(
    request_id: Option<NonZeroU64>,
    active: &mut HashMap<NonZeroU64, ActiveRequest>,
) {
    // Provider panics are contained by `PanicSafeLookup`, so a JoinError here
    // is an abort/runtime failure.  Tokio exposes the exact task ID on the
    // error; the task-id map above lets us retire only the corresponding
    // request and never strand or corrupt another active slot.
    if let Some(request_id) = request_id {
        if let Some(request) = active.remove(&request_id) {
            complete_join_error(request);
        }
        return;
    }

    // A missing task-ID entry violates the actor's ownership invariant. Fail
    // closed and retire every remaining bounded slot so an invariant failure
    // cannot silently strand promises or consume admission forever.
    for (_, request) in active.drain() {
        complete_join_error(request);
    }
}

fn complete_join_error(request: ActiveRequest) {
    request.abort.abort();
    request.promise.complete_observed(
        &request.query,
        Err(DnsError::for_name(
            DnsErrorCode::Internal,
            request.query.name(),
        )),
    );
}

/// A provider future whose panic becomes a typed provider failure.  A panic
/// must never turn a Tokio JoinError into an uncompleted promise/active slot.
pub(crate) struct PanicSafeLookup {
    inner: Pin<Box<dyn Future<Output = Result<DnsResponse, DnsError>> + Send>>,
    name: crate::dns::CanonicalName,
}

impl PanicSafeLookup {
    pub(crate) fn new(
        future: impl Future<Output = Result<DnsResponse, DnsError>> + Send + 'static,
        name: crate::dns::CanonicalName,
    ) -> Self {
        Self {
            inner: Box::pin(future),
            name,
        }
    }
}

impl Future for PanicSafeLookup {
    type Output = Result<DnsResponse, DnsError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.inner.as_mut().poll(context)
        })) {
            Ok(poll) => poll,
            Err(_) => Poll::Ready(Err(DnsError::for_name(DnsErrorCode::Provider, &self.name))),
        }
    }
}

async fn lookup_one(
    resolver: Arc<TokioResolver>,
    query: DnsQuery,
    maximum_addresses: usize,
    maximum_response_bytes: usize,
) -> Result<DnsResponse, DnsError> {
    if query.cancellation().is_cancelled() {
        return Err(DnsError::for_name(DnsErrorCode::Cancelled, query.name()));
    }
    let deadline = tokio::time::Instant::from_std(query.deadline());
    let lookup = resolver.lookup_ip(query.name().as_str());
    let result = tokio::time::timeout_at(deadline, lookup).await;
    let lookup = match result {
        Ok(Ok(lookup)) => lookup,
        Ok(Err(error)) => return Err(map_provider_error(error, query.name())),
        Err(_) => return Err(DnsError::for_name(DnsErrorCode::Deadline, query.name())),
    };

    // Hickory's own per-attempt timeout is configured explicitly.  The
    // operation deadline above remains authoritative and cannot be extended;
    // this check catches a provider that returns just after it expired.
    if query.cancellation().is_cancelled() {
        return Err(DnsError::for_name(DnsErrorCode::Cancelled, query.name()));
    }
    if Instant::now() >= query.deadline() {
        return Err(DnsError::for_name(DnsErrorCode::Deadline, query.name()));
    }
    if maximum_response_bytes == 0 || maximum_response_bytes > MAX_DNS_RESPONSE_BYTES {
        return Err(DnsError::new(DnsErrorCode::InvalidConfig));
    }
    let mut addresses = Vec::new();
    let mut seen = BTreeSet::<IpAddr>::new();
    let mut retained_bytes = query.name().as_str().len();
    if retained_bytes > maximum_response_bytes {
        return Err(DnsError::for_name(
            DnsErrorCode::ResponseLimit,
            query.name(),
        ));
    }
    let mut records = 0usize;
    for address in lookup.iter() {
        if query.cancellation().is_cancelled() {
            return Err(DnsError::for_name(DnsErrorCode::Cancelled, query.name()));
        }
        if Instant::now() >= query.deadline() {
            return Err(DnsError::for_name(DnsErrorCode::Deadline, query.name()));
        }
        records = records
            .checked_add(1)
            .ok_or_else(|| DnsError::for_name(DnsErrorCode::ResponseLimit, query.name()))?;
        if records > maximum_addresses {
            return Err(DnsError::for_name(
                DnsErrorCode::ResponseLimit,
                query.name(),
            ));
        }
        if !seen.contains(&address) {
            let address_bytes = match address {
                IpAddr::V4(_) => std::mem::size_of::<std::net::Ipv4Addr>(),
                IpAddr::V6(_) => std::mem::size_of::<std::net::Ipv6Addr>(),
            };
            let next = retained_bytes
                .checked_add(address_bytes)
                .ok_or_else(|| DnsError::for_name(DnsErrorCode::ResponseLimit, query.name()))?;
            if next > maximum_response_bytes {
                return Err(DnsError::for_name(
                    DnsErrorCode::ResponseLimit,
                    query.name(),
                ));
            }
            retained_bytes = next;
            seen.insert(address);
            addresses.push(address);
        }
    }
    DnsResponse::from_addresses_with_limits(
        query.name().clone(),
        addresses,
        maximum_addresses,
        maximum_response_bytes,
    )
}

fn map_provider_error(
    error: hickory_resolver::net::NetError,
    name: &crate::dns::CanonicalName,
) -> DnsError {
    use hickory_resolver::net::NetError;
    if error.is_nx_domain() {
        return DnsError::for_name(DnsErrorCode::NxDomain, name);
    }
    if error.is_no_records_found() {
        return DnsError::for_name(DnsErrorCode::NoRecords, name);
    }
    match error {
        NetError::Busy => DnsError::for_name(DnsErrorCode::ActiveLimit, name),
        NetError::Proto(_) => DnsError::for_name(DnsErrorCode::MalformedResponse, name),
        _ => DnsError::for_name(DnsErrorCode::Provider, name),
    }
}

fn build_hickory_resolver(configuration: &HickoryDnsConfig) -> Result<TokioResolver, DnsError> {
    let name_servers = configuration
        .nameservers
        .iter()
        .map(|endpoint| {
            let mut connection = ConnectionConfig::new(ProtocolConfig::Udp);
            connection.port = endpoint.port();
            NameServerConfig::new(endpoint.ip(), true, vec![connection])
        })
        .collect::<Vec<_>>();
    let resolver_config = ResolverConfig::from_parts(None, Vec::new(), name_servers);
    let mut options = ResolverOpts::default();
    options.ndots = 1;
    options.timeout = configuration.timeout;
    options.attempts = configuration.attempts;
    options.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
    options.cache_size = 0;
    options.use_hosts_file = ResolveHosts::Never;
    options.positive_min_ttl = None;
    options.negative_min_ttl = None;
    options.positive_max_ttl = None;
    options.negative_max_ttl = None;
    options.num_concurrent_reqs = configuration.nameserver_concurrency;
    options.max_active_requests = configuration.max_active_requests;
    options.preserve_intermediates = false;
    options.try_tcp_on_error = false;
    options.server_ordering_strategy = ServerOrderingStrategy::UserProvidedOrder;
    options.recursion_desired = true;
    options.case_randomization = false;
    options.edns0 = false;

    Resolver::builder_with_config(resolver_config, TokioRuntimeProvider::default())
        .with_options(options)
        .build()
        .map_err(|_| DnsError::new(DnsErrorCode::InvalidConfig))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::pending;

    #[test]
    fn request_id_allocator_fails_closed_before_zero_or_reuse() {
        let allocator = RequestIdAllocator::with_next_for_test(u64::MAX - 1);
        let Some(first_expected) = NonZeroU64::new(u64::MAX - 1) else {
            return;
        };
        let Some(last_expected) = NonZeroU64::new(u64::MAX) else {
            return;
        };
        assert_eq!(allocator.allocate(), Ok(first_expected));
        assert_eq!(allocator.allocate(), Ok(last_expected));
        assert_eq!(
            allocator.allocate(),
            Err(RequestIdAllocationError::Exhausted)
        );
        assert_eq!(
            allocator.allocate(),
            Err(RequestIdAllocationError::Exhausted)
        );

        let zero = RequestIdAllocator::with_next_for_test(0);
        assert_eq!(zero.allocate(), Err(RequestIdAllocationError::Exhausted));
    }

    #[test]
    fn queue_rejection_retires_reserved_request_id_without_network() {
        let allocator = Arc::new(RequestIdAllocator::with_next_for_test(u64::MAX));
        let (request_tx, _request_rx) = tokio_mpsc::channel(1);
        let filler_name = crate::dns::CanonicalName::parse("queue-full.test");
        assert!(filler_name.is_ok(), "queue-full test name");
        let Some(filler_name) = filler_name.ok() else {
            return;
        };
        let filler_query =
            DnsQuery::new(filler_name.clone(), Instant::now() + Duration::from_secs(1));
        let filler_promise = PromiseState::new();
        let filler_cancellation = Arc::new(RequestCancellation::new(
            filler_promise.clone(),
            filler_name,
        ));
        let filler_id = NonZeroU64::MIN;
        let filler = ResolveCommand {
            request_id: filler_id,
            query: filler_query,
            promise: filler_promise,
            cancellation: filler_cancellation,
        };
        assert!(request_tx.try_send(filler).is_ok());

        let resolver = HickoryDnsResolver {
            request_tx,
            request_ids: allocator,
            configuration: HickoryDnsConfig::default(),
        };
        let full_name = crate::dns::CanonicalName::parse("full.test");
        assert!(full_name.is_ok(), "queue-failure full query name");
        let Some(full_name) = full_name.ok() else {
            return;
        };
        let exhausted_name = crate::dns::CanonicalName::parse("exhausted.test");
        assert!(exhausted_name.is_ok(), "queue-failure exhausted query name");
        let Some(exhausted_name) = exhausted_name.ok() else {
            return;
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build();
        assert!(runtime.is_ok(), "queue-failure test runtime");
        let Some(runtime) = runtime.ok() else {
            return;
        };
        let full = runtime.block_on(resolver.resolve(DnsQuery::new(
            full_name,
            Instant::now() + Duration::from_secs(1),
        )));
        assert_eq!(
            full.map_err(|error| error.code()),
            Err(DnsErrorCode::QueueFull)
        );
        let exhausted = runtime.block_on(resolver.resolve(DnsQuery::new(
            exhausted_name,
            Instant::now() + Duration::from_secs(1),
        )));
        assert_eq!(
            exhausted.map_err(|error| error.code()),
            Err(DnsErrorCode::Internal)
        );
    }

    #[test]
    fn join_error_retires_the_exact_active_request() {
        let runtime_result = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build();
        assert!(
            runtime_result.is_ok(),
            "join-error test runtime: {:?}",
            runtime_result.as_ref().err()
        );
        let Ok(runtime) = runtime_result else {
            return;
        };
        runtime.block_on(async {
            let mut tasks = JoinSet::<DnsTaskOutput>::new();
            let task = tasks.spawn(async {
                pending::<()>().await;
                (NonZeroU64::MIN, Err(DnsError::new(DnsErrorCode::Provider)))
            });
            let task_id = task.id();
            let active_abort = task.clone();
            task.abort();

            let name_result = crate::dns::CanonicalName::parse("join-error.test");
            assert!(
                name_result.is_ok(),
                "join-error test name: {:?}",
                name_result.as_ref().err()
            );
            let Ok(name) = name_result else {
                return;
            };
            let query = DnsQuery::new(name, Instant::now() + Duration::from_secs(1));
            let promise = PromiseState::new();
            let registration = query.cancellation().register(Arc::new(|| {}));
            let mut active = HashMap::new();
            active.insert(
                NonZeroU64::MIN,
                ActiveRequest {
                    promise: promise.clone(),
                    query: query.clone(),
                    _cancellation: registration,
                    abort: active_abort,
                },
            );
            let mut task_ids = HashMap::new();
            task_ids.insert(task_id, NonZeroU64::MIN);

            let joined = tasks.join_next_with_id().await;
            assert!(joined.is_some(), "aborted task must produce a join result");
            let Some(joined) = joined else {
                return;
            };
            finish_task(joined, &mut active, &mut task_ids);

            assert!(active.is_empty(), "JoinError must retire the active slot");
            assert!(task_ids.is_empty(), "JoinError task ID must be retired");
            let observed = promise.observe(&query);
            assert!(observed.is_some(), "JoinError must complete the promise");
            let Some(observed) = observed else {
                return;
            };
            assert_eq!(
                observed.map_err(|error| error.code()),
                Err(DnsErrorCode::Internal)
            );
        });
    }
}
