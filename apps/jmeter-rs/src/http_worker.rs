// SPDX-License-Identifier: Apache-2.0
//! Application-owned blocking boundary for the standalone native HTTP path.
//!
//! [`jmeter_rs_http_native::NativeHttpTransport`] and the semantic
//! [`jmeter_rs_http::HttpClient`] are synchronous by design.  This module is
//! the application edge that keeps their DNS/socket work off the runtime
//! executor.  A pool is created once for a local run, owns a fixed set of
//! worker threads, and accepts only bounded operations.  It is deliberately
//! not a general executor: operation admission is non-blocking and a full
//! pool reports a typed error instead of running work inline or creating a
//! temporary thread.  The selected native provider is immutable for each
//! client; V1 and V2 therefore use the same pool without changing capability
//! identity or falling back between variants.
//!
//! A caller must retain one pool owner for the complete local run and call
//! [`HttpWorkerPool::finalize`] at the run boundary.  `Drop` performs the same
//! idempotent finalization as a safety net; it never sends a process signal or
//! leaves an owned worker handle unreaped.  Native transport operations have
//! finite socket bounds, so finalization can wait for exact worker handles to
//! finish.  A custom operation supplied by an in-crate test must obey the
//! same finite-work contract.

#![allow(
    clippy::module_name_repetitions,
    reason = "the application module names its pool/future types explicitly"
)]
#![forbid(unsafe_code)]

use std::cell::Cell;
use std::fmt;
use std::future::Future;
use std::marker::PhantomData;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::task::{Context, Poll, Waker};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use jmeter_rs_http::{
    CancellationToken, HttpClient, HttpError, HttpResult, Request, TimeoutPhase, TransportError,
};
use jmeter_rs_http_native::{NativeHttpTransport, NativeTransport, NativeTransportV2};
use jmeter_rs_results::DataLimits;
use jmeter_rs_runtime::MonotonicInstant;

#[cfg(test)]
use jmeter_rs_http::{ByteAccounting, ClientConfig, Method, Response, Url};

/// Maximum worker threads admitted by the standalone application edge.
pub const MAX_HTTP_WORKERS: usize = 256;
/// Maximum queued operations admitted by one pool.
pub const MAX_HTTP_QUEUE_JOBS: usize = 65_536;
/// Maximum aggregate request/response reservation admitted by one pool.
pub const MAX_HTTP_RETAINED_BYTES: usize = 512 * 1024 * 1024;
/// Default number of blocking HTTP workers for a local run.
pub const DEFAULT_HTTP_WORKERS: usize = 4;
/// Default pending-operation queue capacity for a local run.
pub const DEFAULT_HTTP_QUEUE_JOBS: usize = 32;
/// Default aggregate retained request/response budget for a local run.
pub const DEFAULT_HTTP_RETAINED_BYTES: usize = MAX_HTTP_RETAINED_BYTES;
/// A run-owned monotonic source used by the queue deadline seam.
///
/// The returned value belongs to the runtime's one run-scoped monotonic
/// domain. The pool never adapts it through a process-local clock domain, and
/// the caller must provide the same capability (or an equivalent adapter
/// backed by the same run owner) when creating an [`OperationDeadline`].
pub trait OperationClock: Send + Sync {
    /// Returns the current run-scoped monotonic instant.
    fn now(&self) -> Result<MonotonicInstant, OperationClockError>;
}

/// Bounded failures an application clock adapter may report.
///
/// Provider-specific diagnostics (including `TimeDriverError`) stay on the
/// owning application edge.  The worker pool records only this stable,
/// redacted capability outcome.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OperationClockError {
    /// The run-owned clock could not produce a coherent reading.
    Unavailable,
    /// The run-owned clock explicitly reported a backwards reading.
    Reversed,
}

impl OperationClockError {
    /// Returns the stable machine-readable clock capability code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "http.pool.clock-source",
            Self::Reversed => "http.budget.clock-invalid",
        }
    }
}

/// Closure-backed adapter for the application-owned runtime/time-driver
/// capability.
///
/// The closure should call the exact `TimeDriverHandle::try_now` seam and map
/// provider failures to [`OperationClockError::Unavailable`] (or an explicit
/// [`OperationClockError::Reversed`] when the provider reports reversal).
/// This local adapter avoids coupling this module to the sibling private
/// time-driver implementation while still requiring a fallible production
/// clock.
pub struct OperationClockAdapter<F> {
    read: F,
}

impl<F> OperationClockAdapter<F> {
    /// Creates an adapter around one explicit clock-reading closure.
    #[must_use]
    pub const fn new(read: F) -> Self {
        Self { read }
    }
}

impl<F> OperationClock for OperationClockAdapter<F>
where
    F: Fn() -> Result<MonotonicInstant, OperationClockError> + Send + Sync + 'static,
{
    fn now(&self) -> Result<MonotonicInstant, OperationClockError> {
        (self.read)()
    }
}

/// One absolute finite operation deadline.
///
/// The value is deliberately not a relative timeout. It is created before
/// queue admission, checked when a worker dequeues the job, and used to cap
/// the native client's overall timeout once execution starts.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OperationDeadline {
    at: MonotonicInstant,
}

impl OperationDeadline {
    /// Creates a deadline relative to an explicit current runtime instant.
    ///
    /// A zero duration is rejected: it is an expired operation, not an
    /// unbounded or disabled timeout.  The checked addition keeps a long but
    /// representable schedule valid while failing closed at the domain's
    /// representational boundary.
    pub fn after_at(now: MonotonicInstant, timeout: Duration) -> Result<Self, PoolError> {
        if timeout.is_zero() {
            return Err(PoolError::InvalidDeadline);
        }
        now.checked_add(timeout)
            .map(Self::from_absolute)
            .ok_or(PoolError::DeadlineOverflow)
    }

    const fn from_absolute(at: MonotonicInstant) -> Self {
        Self { at }
    }

    /// Creates an absolute deadline for a deterministic manual-clock fixture.
    /// Production callers must use [`Self::after_at`].
    #[cfg(test)]
    #[must_use]
    const fn at(at: MonotonicInstant) -> Self {
        Self::from_absolute(at)
    }

    /// Returns the absolute monotonic instant.
    #[must_use]
    pub const fn instant(self) -> MonotonicInstant {
        self.at
    }

    /// Returns whether this deadline has expired at `now`.
    #[must_use]
    pub fn expired(self, now: MonotonicInstant) -> bool {
        now >= self.at
    }

    /// Returns remaining time, or zero when expired.
    #[must_use]
    pub fn remaining(self, now: MonotonicInstant) -> Duration {
        self.instant().duration_since(now).unwrap_or(Duration::ZERO)
    }
}

/// How an owner treats work that is still queued when finalization begins.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum ShutdownBehavior {
    /// Finish accepted queued and running operations before joining workers.
    #[default]
    Drain,
    /// Complete queued operations as cancelled; a running operation is
    /// allowed to finish under its own finite operation bound.
    CancelQueued,
}

/// Fixed resource limits for one application-owned HTTP pool.
///
/// `max_retained_bytes` accounts for a conservative checked peak across the
/// request snapshot, native request/response wire buffers, semantic response,
/// result projection, and bounded session state. Every accepted operation,
/// including one still queued, reserves its complete estimate atomically
/// before enqueueing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoolLimits {
    /// Number of worker threads created once for this pool.
    pub worker_count: usize,
    /// Maximum number of operations waiting in worker queues in aggregate.
    pub queue_jobs: usize,
    /// Maximum aggregate retained request plus maximum-response bytes.
    pub max_retained_bytes: usize,
    /// Finalization behavior for queued work.
    pub shutdown: ShutdownBehavior,
}

impl Default for PoolLimits {
    fn default() -> Self {
        Self {
            worker_count: DEFAULT_HTTP_WORKERS,
            queue_jobs: DEFAULT_HTTP_QUEUE_JOBS,
            max_retained_bytes: DEFAULT_HTTP_RETAINED_BYTES,
            shutdown: ShutdownBehavior::Drain,
        }
    }
}

impl PoolLimits {
    /// Creates and validates explicit pool limits.
    pub fn new(
        worker_count: usize,
        queue_jobs: usize,
        max_retained_bytes: usize,
        shutdown: ShutdownBehavior,
    ) -> Result<Self, PoolError> {
        let limits = Self {
            worker_count,
            queue_jobs,
            max_retained_bytes,
            shutdown,
        };
        limits.validate()?;
        Ok(limits)
    }

    /// Validates all finite pool limits before worker creation.
    pub fn validate(self) -> Result<(), PoolError> {
        if self.worker_count == 0 || self.worker_count > MAX_HTTP_WORKERS {
            return Err(PoolError::InvalidLimits {
                field: PoolLimitField::WorkerCount,
            });
        }
        if self.queue_jobs == 0 || self.queue_jobs > MAX_HTTP_QUEUE_JOBS {
            return Err(PoolError::InvalidLimits {
                field: PoolLimitField::QueueJobs,
            });
        }
        if self.max_retained_bytes == 0 || self.max_retained_bytes > MAX_HTTP_RETAINED_BYTES {
            return Err(PoolError::InvalidLimits {
                field: PoolLimitField::RetainedBytes,
            });
        }
        Ok(())
    }

    /// Returns the per-worker channel capacity used by the pool.
    #[must_use]
    fn per_worker_queue(self) -> Result<usize, PoolError> {
        let remainder = self
            .worker_count
            .checked_sub(1)
            .ok_or(PoolError::InternalInvariant)?;
        let numerator = self
            .queue_jobs
            .checked_add(remainder)
            .ok_or(PoolError::InternalInvariant)?;
        Ok(numerator / self.worker_count)
    }
}

/// The numeric field that made a [`PoolLimits`] value invalid.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PoolLimitField {
    /// Worker count was zero or above the hard maximum.
    WorkerCount,
    /// Queue capacity was zero or above the hard maximum.
    QueueJobs,
    /// Aggregate retained bytes were zero or above the hard maximum.
    RetainedBytes,
}

impl PoolLimitField {
    #[must_use]
    const fn as_str(self) -> &'static str {
        match self {
            Self::WorkerCount => "worker-count",
            Self::QueueJobs => "queue-jobs",
            Self::RetainedBytes => "retained-bytes",
        }
    }
}

/// Errors returned while admitting or finalizing a blocking HTTP pool.
///
/// Variants carry only bounded numeric context.  In particular, OS error
/// strings, panic payloads, executable paths, and thread identifiers never
/// cross this boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PoolError {
    /// A pool limit was invalid before any thread was started.
    InvalidLimits { field: PoolLimitField },
    /// An operation's reservation cannot fit in the aggregate byte budget.
    RetainedLimit { requested: usize, maximum: usize },
    /// Every bounded queue slot was occupied at admission.
    Full,
    /// The owner has begun finalization and no more work is accepted.
    Stopped,
    /// An exact worker thread could not be created.
    WorkerStart { worker_index: usize },
    /// A worker observed a panic while processing an operation or exiting.
    WorkerPanic { worker_index: usize },
    /// An operation or native client did not satisfy its checked boundary.
    InvalidOperation,
    /// Finalization was attempted from one of the owned worker threads.
    FinalizeFromWorker { worker_index: usize },
    /// Joining an exact worker handle failed.
    WorkerJoin { worker_index: usize },
    /// A shared-state accounting invariant failed.
    InternalInvariant,
    /// An absolute deadline could not be represented by the monotonic source.
    DeadlineOverflow,
    /// A deadline duration was zero and therefore did not establish a finite
    /// operation grant.
    InvalidDeadline,
    /// The injected run monotonic source moved backwards.
    ClockInvalid,
    /// The run-owned clock capability could not produce a reading.
    ClockSource,
}

impl PoolError {
    /// Returns the stable machine-readable pool error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidLimits { .. } => "http.pool.limits",
            Self::RetainedLimit { .. } => "http.pool.retained-limit",
            Self::Full => "http.pool.full",
            Self::Stopped => "http.pool.stopped",
            Self::WorkerStart { .. } => "http.pool.start",
            Self::WorkerPanic { .. } => "http.pool.worker-panic",
            Self::InvalidOperation => "http.pool.operation",
            Self::FinalizeFromWorker { .. } => "http.pool.finalize-from-worker",
            Self::WorkerJoin { .. } => "http.pool.finalize",
            Self::InternalInvariant => "http.pool.internal-invariant",
            Self::DeadlineOverflow => "http.pool.deadline-overflow",
            Self::InvalidDeadline => "http.pool.deadline-invalid",
            Self::ClockInvalid => "http.budget.clock-invalid",
            Self::ClockSource => "http.pool.clock-source",
        }
    }
}

impl fmt::Display for PoolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits { field } => {
                write!(formatter, "{}: {}", self.code(), field.as_str())
            }
            Self::RetainedLimit { requested, maximum } => {
                write!(formatter, "{}: {requested} > {maximum}", self.code())
            }
            Self::Full
            | Self::Stopped
            | Self::InternalInvariant
            | Self::DeadlineOverflow
            | Self::InvalidOperation
            | Self::InvalidDeadline
            | Self::ClockInvalid
            | Self::ClockSource => formatter.write_str(self.code()),
            Self::WorkerStart { worker_index }
            | Self::WorkerPanic { worker_index }
            | Self::FinalizeFromWorker { worker_index }
            | Self::WorkerJoin { worker_index } => {
                write!(formatter, "{}: worker {worker_index}", self.code())
            }
        }
    }
}

impl std::error::Error for PoolError {}

/// Summary returned after all exact worker handles have been joined.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalizeReport {
    /// Number of workers that were created for this pool.
    pub worker_count: usize,
    /// Number of workers that reported a panic during their lifetime.
    pub observed_worker_panics: usize,
}

/// Result returned by one accepted blocking HTTP operation.
pub type HttpOperationResult = Result<HttpResult, HttpError>;
type OperationFn = Box<
    dyn FnOnce(CancellationToken, OperationDeadline, MonotonicInstant) -> HttpOperationResult
        + Send
        + 'static,
>;

/// The native transport limits exposed to the application worker boundary.
///
/// This private compatibility seam keeps the existing V1 runner call sites
/// source-compatible while the preferred worker client is
/// `HttpClient<NativeHttpTransport>`.  Only the versioned native transports
/// implement it, so an unrelated transport cannot enter this pool by accident.
pub(crate) trait NativeClientTransport: jmeter_rs_http::Transport + Send + 'static {
    /// Returns the limits selected by this immutable native provider.
    fn native_limits(&self) -> &jmeter_rs_http_native::NativeTransportLimits;
}

impl NativeClientTransport for NativeTransport {
    fn native_limits(&self) -> &jmeter_rs_http_native::NativeTransportLimits {
        self.limits()
    }
}

impl NativeClientTransport for NativeTransportV2 {
    fn native_limits(&self) -> &jmeter_rs_http_native::NativeTransportLimits {
        self.limits()
    }
}

impl NativeClientTransport for NativeHttpTransport {
    fn native_limits(&self) -> &jmeter_rs_http_native::NativeTransportLimits {
        self.limits()
    }
}

/// One bounded native HTTP operation admitted to a [`HttpWorkerPool`].
///
/// The public constructor is intentionally tied to a native semantic client;
/// the test-only closure constructor below exists solely to exercise queue,
/// wake, cancellation, and panic invariants without opening a socket.
pub struct HttpOperation {
    retained_bytes: usize,
    operation: Option<OperationFn>,
}

impl HttpOperation {
    /// Builds an operation around a caller-owned per-user client handle.
    ///
    /// A virtual user may retain its [`HttpClient`] in an application-owned
    /// `Arc<Mutex<_>>` and submit one operation at a time. A poisoned client
    /// mutex is rejected as an invariant failure; it is never silently
    /// recovered with an unknown client state.
    pub(crate) fn from_shared_client<T>(
        client: Arc<Mutex<HttpClient<T>>>,
        request: Request,
    ) -> Result<Self, PoolError>
    where
        T: NativeClientTransport,
    {
        let retained_bytes = {
            let client_guard = client.lock().map_err(|_| PoolError::InternalInvariant)?;
            estimate_retained_bytes(&client_guard, &request)?.total_bytes
        };
        Ok(Self {
            retained_bytes,
            operation: Some(Box::new(move |cancellation, deadline, now| {
                let mut client = match client.lock() {
                    Ok(client) => client,
                    Err(_) => {
                        return Err(HttpError::Transport(TransportError::adapter(
                            "http.pool.internal-invariant",
                            "native client mutex poisoned",
                        )));
                    }
                };
                execute_client_with_deadline(&mut client, request, cancellation, deadline, now)
            })),
        })
    }

    /// Returns the complete admission reservation for this operation.
    #[must_use]
    pub const fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    #[cfg(test)]
    fn from_test_fn<F>(retained_bytes: usize, operation: F) -> Result<Self, PoolError>
    where
        F: FnOnce(CancellationToken) -> HttpOperationResult + Send + 'static,
    {
        if retained_bytes == 0 {
            return Err(PoolError::RetainedLimit {
                requested: 0,
                maximum: 0,
            });
        }
        Ok(Self {
            retained_bytes,
            operation: Some(Box::new(move |cancellation, _deadline, _now| {
                operation(cancellation)
            })),
        })
    }
}

/// A future representing one accepted operation.
///
/// Polling this future never executes transport work.  Dropping it cancels
/// the exact operation token. The operation state owns the aggregate
/// reservation until its final owner is dropped, keeping a completed,
/// unpolled result accounted and carrying the lease through projection.
pub struct HttpOperationFuture {
    state: Arc<OperationState>,
    cancellation: CancellationToken,
}

impl HttpOperationFuture {
    /// Requests cancellation of this operation without dropping the future.
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    /// Returns whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }
}

impl fmt::Debug for HttpOperationFuture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpOperationFuture")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

impl Future for HttpOperationFuture {
    type Output = HttpOperationResult;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut state = lock_or_record_invariant(&this.state.state, &this.state.invariant);
        if let Some(result) = state.result.take() {
            state.finished = true;
            drop(state);
            return Poll::Ready(result);
        }
        if state.finished {
            drop(state);
            return Poll::Ready(Err(HttpError::Transport(TransportError::adapter(
                "http.pool.future-polled-after-ready",
                "future was polled after completion",
            ))));
        }
        if state.closed {
            // `Drop` cannot be followed by a legal poll, but keeping this
            // branch explicit makes accidental misuse deterministic rather
            // than leaving a permanently pending future.
            state.finished = true;
            drop(state);
            return Poll::Ready(Err(HttpError::Transport(TransportError::adapter(
                "http.pool.future-closed",
                "future was closed",
            ))));
        }
        state.waker = Some(context.waker().clone());
        Poll::Pending
    }
}

impl Drop for HttpOperationFuture {
    fn drop(&mut self) {
        {
            let mut state = lock_or_record_invariant(&self.state.state, &self.state.invariant);
            state.closed = true;
            state.waker = None;
        }
        // Cancellation callbacks belong to the transport boundary.  A
        // malformed/test callback must not make dropping a future unwind. The
        // queued/running Job still owns the request/client through its state
        // Arc at this point, and the state keeps the result reservation live.
        let _ = panic::catch_unwind(AssertUnwindSafe(|| self.cancellation.cancel()));
    }
}

/// Cloneable submission-only view of a worker pool.
///
/// This handle never owns or exposes worker join handles. The one
/// [`HttpWorkerPool`] owner remains on the run-owner thread and must finalize
/// after all submission handles and operation futures have been dropped.
#[derive(Clone)]
pub struct HttpWorkerSubmitter {
    limits: PoolLimits,
    shared: Arc<PoolShared>,
}

impl fmt::Debug for HttpWorkerSubmitter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dispatch = lock_or_record_invariant(&self.shared.dispatch, &self.shared.invariant);
        formatter
            .debug_struct("HttpWorkerSubmitter")
            .field("limits", &self.limits)
            .field("stopped", &self.shared.stopping())
            .field("queued_jobs", &dispatch.queued_jobs)
            .field("retained_bytes", &self.shared.retained_bytes())
            .finish()
    }
}

impl HttpWorkerSubmitter {
    /// Submits one operation with an absolute deadline created before queue
    /// admission. Queue wait and worker execution share this same deadline.
    pub fn submit_with_deadline(
        &self,
        operation: HttpOperation,
        deadline: OperationDeadline,
    ) -> Result<HttpOperationFuture, PoolError> {
        submit_inner(&self.shared, self.limits, operation, deadline)
    }
}

fn submit_inner(
    shared: &Arc<PoolShared>,
    limits: PoolLimits,
    operation: HttpOperation,
    deadline: OperationDeadline,
) -> Result<HttpOperationFuture, PoolError> {
    // Validate the run-owned clock capability before reserving bytes or
    // enqueueing. This is only an admission probe; the worker samples again
    // at dequeue and never reconstructs or refreshes the supplied deadline.
    shared.now()?;
    let retained_bytes = operation.retained_bytes();
    if !shared.reserve_bytes(retained_bytes, limits.max_retained_bytes) {
        return Err(PoolError::RetainedLimit {
            requested: retained_bytes,
            maximum: limits.max_retained_bytes,
        });
    }
    let reservation = Arc::new(Reservation::new(&shared.accounting, retained_bytes));
    let cancellation = CancellationToken::default();
    let state = Arc::new(OperationState::new(
        Arc::clone(&shared.invariant),
        Arc::clone(&reservation),
    ));
    let job = Job {
        operation: operation.operation,
        cancellation: cancellation.clone(),
        state: Arc::clone(&state),
        shared: Arc::downgrade(shared),
        deadline,
        queue_accounted: false,
        terminal: false,
    };

    let mut dispatch = lock_or_record_invariant(&shared.dispatch, &shared.invariant);
    if shared.stopping() || dispatch.senders.is_none() {
        drop(dispatch);
        drop(job);
        return Err(PoolError::Stopped);
    }
    if dispatch.queued_jobs >= limits.queue_jobs {
        drop(dispatch);
        drop(job);
        return Err(PoolError::Full);
    }

    let start = dispatch.next_worker;
    let mut job = Some(job);
    let mut saw_full = false;
    let Some(senders) = dispatch.senders.clone() else {
        drop(dispatch);
        drop(job);
        return Err(PoolError::Stopped);
    };
    for offset in 0..senders.len() {
        let worker_index = (start + offset) % senders.len();
        let Some(mut pending) = job.take() else {
            drop(dispatch);
            return Err(PoolError::InternalInvariant);
        };
        match senders[worker_index].try_send({
            pending.queue_accounted = true;
            pending
        }) {
            Ok(()) => {
                dispatch.queued_jobs = match dispatch.queued_jobs.checked_add(1) {
                    Some(value) => value,
                    None => {
                        shared.record_invariant();
                        drop(dispatch);
                        return Err(PoolError::InternalInvariant);
                    }
                };
                dispatch.next_worker = (worker_index + 1) % senders.len();
                return Ok(HttpOperationFuture {
                    state,
                    cancellation,
                });
            }
            Err(TrySendError::Full(mut pending)) => {
                pending.queue_accounted = false;
                saw_full = true;
                job = Some(pending);
            }
            Err(TrySendError::Disconnected(mut pending)) => {
                pending.queue_accounted = false;
                job = Some(pending);
            }
        }
    }
    drop(dispatch);
    drop(job);
    if saw_full {
        Err(PoolError::Full)
    } else {
        Err(PoolError::Stopped)
    }
}

/// Fixed-size, bounded native HTTP worker pool.
pub struct HttpWorkerPool {
    limits: PoolLimits,
    shared: Arc<PoolShared>,
    handles: Mutex<Option<Vec<JoinHandle<()>>>>,
    finalize_gate: Mutex<()>,
    finalization: Mutex<Option<Result<FinalizeReport, PoolError>>>,
    // Rc makes the owner intentionally !Send and !Sync. A run owner cannot
    // accidentally move its join handles into a worker; only the submitter
    // view crosses the worker/application boundary.
    _owner_thread: PhantomData<Rc<()>>,
}

impl fmt::Debug for HttpWorkerPool {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dispatch = lock_or_record_invariant(&self.shared.dispatch, &self.shared.invariant);
        formatter
            .debug_struct("HttpWorkerPool")
            .field("limits", &self.limits)
            .field("stopped", &self.shared.stopping())
            .field("queued_jobs", &dispatch.queued_jobs)
            .field("retained_bytes", &self.shared.retained_bytes())
            .field("worker_handles", &self.limits.worker_count)
            .finish()
    }
}

impl HttpWorkerPool {
    /// Starts the fixed worker set for one local run with an explicit,
    /// run-owned monotonic clock capability.
    ///
    /// There is intentionally no default constructor: production admission
    /// must wire the exact [`OperationClock`] used by the runtime/time-driver
    /// domain.  The caller should retain a clone of that capability to create
    /// each [`OperationDeadline`] before queue submission.
    pub fn new(limits: PoolLimits, clock: Arc<dyn OperationClock>) -> Result<Self, PoolError> {
        let limits = PoolLimits::new(
            limits.worker_count,
            limits.queue_jobs,
            limits.max_retained_bytes,
            limits.shutdown,
        )?;
        let worker_count = limits.worker_count;
        let mut senders = Vec::with_capacity(worker_count);
        let mut receivers = Vec::with_capacity(worker_count);
        let queue_capacity = limits.per_worker_queue()?;
        for _ in 0..worker_count {
            let (sender, receiver) = mpsc::sync_channel(queue_capacity);
            senders.push(sender);
            receivers.push(receiver);
        }

        let shared = Arc::new(PoolShared::new(limits, senders, clock));
        let mut handles = Vec::with_capacity(worker_count);
        for (worker_index, receiver) in receivers.into_iter().enumerate() {
            let worker_shared = Arc::clone(&shared);
            match thread::Builder::new()
                .spawn(move || worker_entry(worker_index, receiver, worker_shared))
            {
                Ok(handle) => handles.push(handle),
                Err(_) => {
                    shared
                        .stopping
                        .store(true, std::sync::atomic::Ordering::Release);
                    let mut dispatch =
                        lock_or_record_invariant(&shared.dispatch, &shared.invariant);
                    dispatch.senders = None;
                    drop(dispatch);
                    for (joined_index, handle) in handles.into_iter().enumerate() {
                        if handle.join().is_err() {
                            shared.record_panic(joined_index);
                        }
                    }
                    return Err(PoolError::WorkerStart { worker_index });
                }
            }
        }

        Ok(Self {
            limits,
            shared,
            handles: Mutex::new(Some(handles)),
            finalize_gate: Mutex::new(()),
            finalization: Mutex::new(None),
            _owner_thread: PhantomData,
        })
    }

    /// Returns the cloneable submission-only view for sampler/application
    /// clones. It contains no worker handles and therefore cannot leak joins.
    #[must_use]
    pub fn submitter(&self) -> HttpWorkerSubmitter {
        HttpWorkerSubmitter {
            limits: self.limits(),
            shared: Arc::clone(&self.shared),
        }
    }

    /// Returns the immutable limits used by this pool.
    #[must_use]
    pub const fn limits(&self) -> PoolLimits {
        self.limits
    }

    /// Test-only helper using an explicit manual absolute deadline.
    #[cfg(test)]
    fn submit(&self, operation: HttpOperation) -> Result<HttpOperationFuture, PoolError> {
        self.submit_with_deadline(
            operation,
            OperationDeadline::at(MonotonicInstant::from_duration(Duration::from_secs(3_600))),
        )
    }

    /// Submits an operation with an already-established absolute deadline.
    ///
    /// The worker never derives or refreshes this deadline.  A caller that
    /// also registers a runtime wait must pass [`OperationDeadline::instant`]
    /// to that registration, preserving one exact absolute value across both
    /// boundaries.
    pub fn submit_with_deadline(
        &self,
        operation: HttpOperation,
        deadline: OperationDeadline,
    ) -> Result<HttpOperationFuture, PoolError> {
        self.submitter().submit_with_deadline(operation, deadline)
    }

    /// Stops admission, drops exact queue senders, and joins every owned
    /// worker handle.  Repeated calls return the same cached outcome.
    pub fn finalize(&self) -> Result<FinalizeReport, PoolError> {
        if let Some(worker_index) = current_worker_index() {
            return Err(PoolError::FinalizeFromWorker { worker_index });
        }
        let _gate = lock_or_record_invariant(&self.finalize_gate, &self.shared.invariant);
        if let Some(result) =
            lock_or_record_invariant(&self.finalization, &self.shared.invariant).as_ref()
        {
            return result.clone();
        }

        self.shared
            .stopping
            .store(true, std::sync::atomic::Ordering::Release);
        if self.limits.shutdown == ShutdownBehavior::CancelQueued {
            self.shared
                .cancel_queued
                .store(true, std::sync::atomic::Ordering::Release);
        }
        self.shared.signal_finalization_started();
        {
            let mut dispatch =
                lock_or_record_invariant(&self.shared.dispatch, &self.shared.invariant);
            dispatch.senders = None;
        }

        let handles = lock_or_record_invariant(&self.handles, &self.shared.invariant)
            .take()
            .unwrap_or_default();
        let mut join_error = None;
        for (worker_index, handle) in handles.into_iter().enumerate() {
            if handle.join().is_err() {
                self.shared.record_panic(worker_index);
                if join_error.is_none() {
                    join_error = Some(worker_index);
                }
            }
        }

        let result = if let Some(worker_index) = join_error {
            Err(PoolError::WorkerJoin { worker_index })
        } else if let Some(worker_index) = self.shared.first_panic() {
            Err(PoolError::WorkerPanic { worker_index })
        } else if let Some(error) = self.shared.clock_failure() {
            Err(error)
        } else if self.shared.has_invariant()
            || lock_or_record_invariant(&self.shared.dispatch, &self.shared.invariant).queued_jobs
                != 0
        {
            Err(PoolError::InternalInvariant)
        } else {
            Ok(FinalizeReport {
                worker_count: self.limits.worker_count,
                observed_worker_panics: self.shared.panic_count(),
            })
        };
        *lock_or_record_invariant(&self.finalization, &self.shared.invariant) =
            Some(result.clone());
        result
    }
}

impl Drop for HttpWorkerPool {
    fn drop(&mut self) {
        // A Drop implementation cannot report a finalization error.  It still
        // performs the exact join path and deliberately never panics.
        let _ = self.finalize();
    }
}

struct PoolShared {
    dispatch: Mutex<DispatchState>,
    clock: Arc<dyn OperationClock>,
    clock_state: Mutex<ClockState>,
    invariant: Arc<AtomicBool>,
    accounting: Arc<PoolAccounting>,
    stopping: std::sync::atomic::AtomicBool,
    cancel_queued: std::sync::atomic::AtomicBool,
    finalization_started: Mutex<bool>,
    finalization_condition: Condvar,
    health: Mutex<WorkerHealth>,
    #[cfg(test)]
    panic_worker_loop: AtomicBool,
}

impl PoolShared {
    fn new(
        limits: PoolLimits,
        senders: Vec<SyncSender<Job>>,
        clock: Arc<dyn OperationClock>,
    ) -> Self {
        let invariant = Arc::new(AtomicBool::new(false));
        Self {
            dispatch: Mutex::new(DispatchState {
                senders: Some(senders),
                queued_jobs: 0,
                next_worker: 0,
            }),
            clock,
            clock_state: Mutex::new(ClockState::default()),
            accounting: Arc::new(PoolAccounting::new(Arc::clone(&invariant))),
            invariant,
            stopping: std::sync::atomic::AtomicBool::new(false),
            cancel_queued: std::sync::atomic::AtomicBool::new(false),
            finalization_started: Mutex::new(false),
            finalization_condition: Condvar::new(),
            health: Mutex::new(WorkerHealth {
                panic_workers: vec![false; limits.worker_count],
            }),
            #[cfg(test)]
            panic_worker_loop: AtomicBool::new(false),
        }
    }

    #[must_use]
    fn stopping(&self) -> bool {
        self.stopping.load(std::sync::atomic::Ordering::Acquire)
    }

    #[must_use]
    fn retained_bytes(&self) -> usize {
        self.accounting.retained_bytes()
    }

    #[must_use]
    fn reserve_bytes(&self, requested: usize, maximum: usize) -> bool {
        self.accounting.reserve_bytes(requested, maximum)
    }

    /// Reads and validates the one run-scoped monotonic domain.
    ///
    /// The clock call and last-reading update are serialized so concurrent
    /// workers cannot reorder observations and accidentally accept a
    /// reversal. Once a reversal is observed, all subsequent jobs fail
    /// closed with the same typed clock error; no operation receives an
    /// extended grant.
    fn now(&self) -> Result<MonotonicInstant, PoolError> {
        let mut state = lock_or_record_invariant(&self.clock_state, &self.invariant);
        if let Some(error) = state.failure.clone() {
            return Err(error);
        }
        let current = match panic::catch_unwind(AssertUnwindSafe(|| self.clock.now())) {
            Ok(Ok(current)) => current,
            Ok(Err(OperationClockError::Unavailable)) | Err(_) => {
                state.failure = Some(PoolError::ClockSource);
                return Err(PoolError::ClockSource);
            }
            Ok(Err(OperationClockError::Reversed)) => {
                state.failure = Some(PoolError::ClockInvalid);
                return Err(PoolError::ClockInvalid);
            }
        };
        if let Some(previous) = state.last
            && current < previous
        {
            state.failure = Some(PoolError::ClockInvalid);
            return Err(PoolError::ClockInvalid);
        }
        state.last = Some(current);
        Ok(current)
    }

    fn dequeue(&self) {
        let mut dispatch = lock_or_record_invariant(&self.dispatch, &self.invariant);
        if dispatch.queued_jobs == 0 {
            self.record_invariant();
        } else {
            dispatch.queued_jobs -= 1;
        }
    }

    fn record_panic(&self, worker_index: usize) {
        let mut health = lock_or_record_invariant(&self.health, &self.invariant);
        if let Some(panicked) = health.panic_workers.get_mut(worker_index) {
            *panicked = true;
        } else {
            self.record_invariant();
        }
    }

    fn record_invariant(&self) {
        self.invariant.store(true, Ordering::Release);
    }

    fn signal_finalization_started(&self) {
        let mut started = lock_or_record_invariant(&self.finalization_started, &self.invariant);
        *started = true;
        self.finalization_condition.notify_all();
    }

    #[must_use]
    fn first_panic(&self) -> Option<usize> {
        lock_or_record_invariant(&self.health, &self.invariant)
            .panic_workers
            .iter()
            .position(|panicked| *panicked)
    }

    #[must_use]
    fn panic_count(&self) -> usize {
        lock_or_record_invariant(&self.health, &self.invariant)
            .panic_workers
            .iter()
            .filter(|panicked| **panicked)
            .count()
    }

    #[must_use]
    fn has_invariant(&self) -> bool {
        self.invariant.load(Ordering::Acquire)
    }

    #[must_use]
    fn clock_failure(&self) -> Option<PoolError> {
        lock_or_record_invariant(&self.clock_state, &self.invariant)
            .failure
            .clone()
    }

    #[cfg(test)]
    fn request_worker_loop_panic(&self) {
        self.panic_worker_loop.store(true, Ordering::Release);
    }

    #[cfg(test)]
    fn should_panic_worker_loop(&self) -> bool {
        self.panic_worker_loop.swap(false, Ordering::AcqRel)
    }
}

#[derive(Default)]
struct ClockState {
    last: Option<MonotonicInstant>,
    failure: Option<PoolError>,
}

struct DispatchState {
    senders: Option<Vec<SyncSender<Job>>>,
    queued_jobs: usize,
    next_worker: usize,
}

struct WorkerHealth {
    panic_workers: Vec<bool>,
}

struct PoolAccounting {
    invariant: Arc<AtomicBool>,
    retained_bytes: std::sync::atomic::AtomicUsize,
}

impl PoolAccounting {
    fn new(invariant: Arc<AtomicBool>) -> Self {
        Self {
            invariant,
            retained_bytes: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    #[must_use]
    fn retained_bytes(&self) -> usize {
        self.retained_bytes.load(Ordering::Acquire)
    }

    #[must_use]
    fn reserve_bytes(&self, requested: usize, maximum: usize) -> bool {
        let mut current = self.retained_bytes.load(Ordering::Acquire);
        loop {
            let Some(next) = current.checked_add(requested) else {
                return false;
            };
            if next > maximum {
                return false;
            }
            match self.retained_bytes.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    fn release_bytes(&self, released: usize) {
        let mut current = self.retained_bytes.load(Ordering::Acquire);
        loop {
            let Some(next) = current.checked_sub(released) else {
                self.invariant.store(true, Ordering::Release);
                return;
            };
            match self.retained_bytes.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }
}

struct Reservation {
    accounting: Arc<PoolAccounting>,
    bytes: usize,
    released: std::sync::atomic::AtomicBool,
}

impl Reservation {
    fn new(accounting: &Arc<PoolAccounting>, bytes: usize) -> Self {
        Self {
            accounting: Arc::clone(accounting),
            bytes,
            released: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn release(&self) {
        if !self
            .released
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            self.accounting.release_bytes(self.bytes);
        }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.release();
    }
}

struct OperationState {
    state: Mutex<OperationStateInner>,
    invariant: Arc<AtomicBool>,
    // The state, rather than the worker job, owns the reservation.  A worker
    // can therefore publish a completed result and drop its job without
    // making the result's retained bytes look available to another submitter.
    // `Reservation` is idempotent so every admission/error/drop path remains
    // safe even when temporary Arcs overlap the state lifetime.
    reservation: Arc<Reservation>,
    #[cfg(test)]
    completion_condition: Condvar,
}

#[derive(Default)]
struct OperationStateInner {
    result: Option<HttpOperationResult>,
    waker: Option<Waker>,
    finished: bool,
    closed: bool,
}

impl OperationState {
    fn new(invariant: Arc<AtomicBool>, reservation: Arc<Reservation>) -> Self {
        Self {
            state: Mutex::new(OperationStateInner::default()),
            invariant,
            reservation,
            #[cfg(test)]
            completion_condition: Condvar::new(),
        }
    }

    fn complete(&self, result: HttpOperationResult) {
        let wake = {
            let mut state = lock_or_record_invariant(&self.state, &self.invariant);
            if state.closed || state.finished || state.result.is_some() {
                return;
            }
            state.result = Some(result);
            state.waker.take()
        };
        #[cfg(test)]
        self.completion_condition.notify_all();
        if let Some(waker) = wake {
            // A caller-provided waker is outside the pool's ownership.  A
            // panic in it must not tear down an owned worker or strand its
            // reservation; the result remains stored for the next poll.
            if panic::catch_unwind(AssertUnwindSafe(|| waker.wake())).is_err() {
                self.invariant.store(true, Ordering::Release);
            }
        }
    }
}

impl Drop for OperationState {
    fn drop(&mut self) {
        // Completed results can outlive the worker job.  Release only when
        // the final state owner goes away; Reservation's idempotence also
        // covers admission failure and overlapping cleanup paths.
        self.reservation.release();
    }
}

struct Job {
    operation: Option<OperationFn>,
    cancellation: CancellationToken,
    state: Arc<OperationState>,
    shared: Weak<PoolShared>,
    deadline: OperationDeadline,
    queue_accounted: bool,
    terminal: bool,
}

impl Drop for Job {
    fn drop(&mut self) {
        if self.queue_accounted {
            self.queue_accounted = false;
            if let Some(shared) = self.shared.upgrade() {
                shared.dequeue();
            }
        }
        if !self.terminal {
            let _ = panic::catch_unwind(AssertUnwindSafe(|| self.cancellation.cancel()));
            self.state.complete(stopped_result());
        }
    }
}

#[cfg_attr(
    test,
    allow(
        clippy::panic,
        reason = "the test-only loop panic exercises worker recovery"
    )
)]
fn worker_entry(worker_index: usize, receiver: Receiver<Job>, shared: Arc<PoolShared>) {
    WORKER_INDEX.with(|current| current.set(Some(worker_index)));
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        while let Ok(mut job) = receiver.recv() {
            if job.queue_accounted {
                job.queue_accounted = false;
                shared.dequeue();
            } else {
                shared.record_invariant();
            }
            let state = Arc::clone(&job.state);
            let cancellation = job.cancellation.clone();
            let iteration = panic::catch_unwind(AssertUnwindSafe(|| {
                #[cfg(test)]
                if shared.should_panic_worker_loop() {
                    panic!("test worker loop panic");
                }
                process_job(worker_index, &mut job, &shared);
            }));
            if let Err(payload) = iteration {
                shared.record_panic(worker_index);
                let _ = panic::catch_unwind(AssertUnwindSafe(|| cancellation.cancel()));
                state.complete(worker_panic_result());
                job.terminal = true;
                panic::resume_unwind(payload);
            }
        }
    }));
    if result.is_err() {
        shared.record_panic(worker_index);
        drain_after_worker_panic(worker_index, receiver, &shared);
    }
    WORKER_INDEX.with(|current| current.set(None));
}

fn drain_after_worker_panic(
    worker_index: usize,
    receiver: Receiver<Job>,
    shared: &Arc<PoolShared>,
) {
    while let Ok(mut job) = receiver.try_recv() {
        if job.queue_accounted {
            job.queue_accounted = false;
            shared.dequeue();
        } else {
            shared.record_invariant();
        }
        let state = Arc::clone(&job.state);
        let cancellation = job.cancellation.clone();
        let _ = panic::catch_unwind(AssertUnwindSafe(|| cancellation.cancel()));
        state.complete(worker_panic_result());
        job.terminal = true;
        shared.record_panic(worker_index);
        // Dropping the job releases its state Arc. The state result above
        // wakes a live future; a dropped future remains closed. The final
        // state owner releases the exact reservation.
    }
}

fn process_job(worker_index: usize, job: &mut Job, shared: &Arc<PoolShared>) {
    let cancelled_before_start = job.cancellation.is_cancelled()
        || shared
            .cancel_queued
            .load(std::sync::atomic::Ordering::Acquire);
    let result = if cancelled_before_start {
        Err(HttpError::Cancelled)
    } else {
        match shared.now() {
            Err(error) => clock_failure_result(error),
            Ok(observed_now) if job.deadline.expired(observed_now) => {
                Err(HttpError::Timeout(TimeoutPhase::Overall))
            }
            Ok(observed_now) => match job.operation.take() {
                None => {
                    shared.record_invariant();
                    Err(HttpError::Transport(TransportError::adapter(
                        "http.pool.internal-invariant",
                        "missing operation body",
                    )))
                }
                Some(operation) => match panic::catch_unwind(AssertUnwindSafe(|| {
                    operation(job.cancellation.clone(), job.deadline, observed_now)
                })) {
                    Ok(result) => result,
                    Err(_) => {
                        shared.record_panic(worker_index);
                        worker_panic_result()
                    }
                },
            },
        }
    };
    if result
        .as_ref()
        .err()
        .is_some_and(is_internal_invariant_error)
    {
        shared.record_invariant();
    }
    job.state.complete(result);
    job.terminal = true;
}

fn clock_failure_result(error: PoolError) -> HttpOperationResult {
    let code = match error {
        PoolError::ClockInvalid => "http.budget.clock-invalid",
        PoolError::ClockSource => "http.pool.clock-source",
        _ => "http.budget.clock-invalid",
    };
    Err(HttpError::Transport(TransportError::adapter(
        code,
        "run monotonic clock capability failed",
    )))
}

fn worker_panic_result() -> HttpOperationResult {
    Err(HttpError::Transport(TransportError::adapter(
        "http.pool.worker-panic",
        "worker operation panicked",
    )))
}

fn stopped_result() -> HttpOperationResult {
    Err(HttpError::Transport(TransportError::adapter(
        "http.pool.stopped",
        "worker stopped before operation completion",
    )))
}

fn is_internal_invariant_error(error: &HttpError) -> bool {
    matches!(
        error,
        HttpError::Transport(TransportError::Adapter { code, .. })
            if code == "http.pool.internal-invariant"
    )
}

/// Checked peak-retention components reserved for one native operation.
///
/// The formula intentionally sums independently bounded request, native wire,
/// semantic response, and result-projection components. Some components may
/// coexist only briefly, so this is conservative; every addition is checked
/// and a malformed configuration cannot wrap into a small reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedMemoryEstimate {
    /// Prepared request snapshot retained by the semantic result/client.
    pub request_snapshot_bytes: usize,
    /// Native request head capacity.
    pub native_request_head_bytes: usize,
    /// Native request body capacity.
    pub native_request_body_bytes: usize,
    /// Native request total-wire capacity.
    pub native_request_total_bytes: usize,
    /// Native response head capacity.
    pub native_response_head_bytes: usize,
    /// Native response body capacity.
    pub native_response_body_bytes: usize,
    /// Native response total-wire capacity.
    pub native_response_total_bytes: usize,
    /// Native synchronous I/O scratch capacity.
    pub native_io_buffer_bytes: usize,
    /// Decoded semantic response body capacity.
    pub semantic_response_body_bytes: usize,
    /// Result and redirect projection capacity, including request metadata.
    pub semantic_result_projection_bytes: usize,
    /// Bounded per-user cache state that may be retained while the operation
    /// updates the client.
    pub session_cache_bytes: usize,
    /// Checked sum of all components above.
    pub total_bytes: usize,
}

fn checked_sum<I>(values: I) -> Result<usize, PoolError>
where
    I: IntoIterator<Item = usize>,
{
    values.into_iter().try_fold(0usize, |total, value| {
        total.checked_add(value).ok_or(PoolError::InternalInvariant)
    })
}

pub(crate) fn estimate_retained_bytes<T: NativeClientTransport>(
    client: &HttpClient<T>,
    request: &Request,
) -> Result<RetainedMemoryEstimate, PoolError> {
    client
        .config()
        .validate()
        .map_err(|_| PoolError::InvalidOperation)?;
    let header_bytes = request
        .headers()
        .checked_wire_len()
        .map_err(|_| PoolError::InvalidOperation)?;
    let request_bytes = request
        .method()
        .as_str()
        .len()
        .checked_add(request.wire_target().len())
        .and_then(|value| value.checked_add(header_bytes))
        .and_then(|value| value.checked_add(request.body().len()))
        .ok_or(PoolError::InternalInvariant)?;
    let native = client.transport().native_limits();
    let client_limits = &client.config().limits;
    let redirects = client.config().redirects.maximum_retained_bytes;
    let data_limits = DataLimits::default_bounded();
    let native_request_head = native
        .max_request_head_bytes
        .min(client_limits.max_header_bytes);
    let native_request_body = native
        .max_request_body_bytes
        .min(client_limits.max_request_body_bytes);
    let native_request_total = native.max_request_total_bytes;
    let native_response_head = native
        .max_response_head_bytes
        .min(client_limits.max_header_bytes);
    let native_response_body = native
        .max_response_body_bytes
        .min(client_limits.max_response_body_bytes);
    let native_response_total = native.max_response_total_bytes;
    let semantic_result_projection = checked_sum([
        request_bytes,
        data_limits.max_binary_bytes(),
        data_limits.max_text_bytes(),
        data_limits.max_encoding_bytes(),
        data_limits.max_header_bytes(),
        data_limits.max_file_reference_bytes(),
        redirects,
    ])?;
    let total_bytes = checked_sum([
        request_bytes,
        native_request_head,
        native_request_body,
        native_request_total,
        native_response_head,
        native_response_body,
        native_response_total,
        native.max_io_buffer_bytes,
        client_limits.max_response_body_bytes,
        semantic_result_projection,
        client_limits.session.max_cache_bytes,
    ])?;
    Ok(RetainedMemoryEstimate {
        request_snapshot_bytes: request_bytes,
        native_request_head_bytes: native_request_head,
        native_request_body_bytes: native_request_body,
        native_request_total_bytes: native_request_total,
        native_response_head_bytes: native_response_head,
        native_response_body_bytes: native_response_body,
        native_response_total_bytes: native_response_total,
        native_io_buffer_bytes: native.max_io_buffer_bytes,
        semantic_response_body_bytes: client_limits.max_response_body_bytes,
        semantic_result_projection_bytes: semantic_result_projection,
        session_cache_bytes: client_limits.session.max_cache_bytes,
        total_bytes,
    })
}

fn execute_client_with_deadline<T: NativeClientTransport>(
    client: &mut HttpClient<T>,
    request: Request,
    cancellation: CancellationToken,
    deadline: OperationDeadline,
    now: MonotonicInstant,
) -> HttpOperationResult {
    // This is the one explicit application-edge conversion between the
    // runtime's absolute monotonic domain and the synchronous HTTP client's
    // relative timeout configuration. The absolute value is never compared
    // with the client's private clock epoch; only the already-computed
    // remaining duration crosses this boundary.
    let remaining = deadline.remaining(now);
    if remaining.is_zero() {
        return Err(HttpError::Timeout(TimeoutPhase::Overall));
    }
    let previous = client.config().timeouts.overall;
    let capped = previous.map_or(remaining, |configured| configured.min(remaining));
    client.config_mut().timeouts.overall = Some(capped);
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        client.execute_with_cancellation(request, cancellation)
    }));
    client.config_mut().timeouts.overall = previous;
    match result {
        Ok(result) => result,
        Err(payload) => panic::resume_unwind(payload),
    }
}

/// Locks shared state while making mutex poisoning observable.
///
/// Terminal cleanup still takes the poisoned value so a reservation or future
/// cannot remain pending, but the shared invariant flag makes finalization
/// fail closed and records the defect for the run owner.
fn lock_or_record_invariant<'a, T>(
    mutex: &'a Mutex<T>,
    invariant: &AtomicBool,
) -> MutexGuard<'a, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            invariant.store(true, Ordering::Release);
            poisoned.into_inner()
        }
    }
}

thread_local! {
    static WORKER_INDEX: Cell<Option<usize>> = const { Cell::new(None) };
}

fn current_worker_index() -> Option<usize> {
    WORKER_INDEX.with(Cell::get)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "tests use expect at assertion boundaries for fixed in-process fixtures"
    )]
    #![allow(
        clippy::panic,
        reason = "one test intentionally exercises worker panic recovery"
    )]

    use super::*;
    use std::sync::Condvar;
    use std::sync::PoisonError;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    fn result_ok() -> HttpOperationResult {
        Ok(HttpResult::new(
            Response::new(200),
            0,
            ByteAccounting::default(),
            Duration::ZERO,
            0,
            0,
        ))
    }

    fn operation<F>(retained_bytes: usize, function: F) -> HttpOperation
    where
        F: FnOnce(CancellationToken) -> HttpOperationResult + Send + 'static,
    {
        HttpOperation::from_test_fn(retained_bytes, function).expect("valid test operation")
    }

    fn limits(workers: usize, queue_jobs: usize, retained: usize) -> PoolLimits {
        let limits = PoolLimits {
            worker_count: workers,
            queue_jobs,
            max_retained_bytes: retained,
            shutdown: ShutdownBehavior::Drain,
        };
        limits.validate().expect("valid test limits");
        limits
    }

    fn lock_test<'a, T>(mutex: &'a Mutex<T>) -> MutexGuard<'a, T> {
        mutex
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[derive(Clone)]
    struct ManualMonotonicClock {
        now: Arc<Mutex<MonotonicInstant>>,
    }

    impl ManualMonotonicClock {
        fn new(now: MonotonicInstant) -> Self {
            Self {
                now: Arc::new(Mutex::new(now)),
            }
        }

        fn set(&self, now: MonotonicInstant) {
            *lock_test(&self.now) = now;
        }
    }

    impl OperationClock for ManualMonotonicClock {
        fn now(&self) -> Result<MonotonicInstant, OperationClockError> {
            Ok(*lock_test(&self.now))
        }
    }

    fn test_clock() -> Arc<ManualMonotonicClock> {
        Arc::new(ManualMonotonicClock::new(MonotonicInstant::zero()))
    }

    fn test_pool(limits: PoolLimits) -> HttpWorkerPool {
        HttpWorkerPool::new(limits, test_clock()).expect("pool")
    }

    struct WakeSignal {
        state: Arc<(Mutex<bool>, Condvar)>,
    }

    impl std::task::Wake for WakeSignal {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            let (ready, condition) = &*self.state;
            let mut ready = lock_test(ready);
            *ready = true;
            condition.notify_one();
        }
    }

    fn block_on(mut future: HttpOperationFuture) -> HttpOperationResult {
        block_on_ref(&mut future)
    }

    fn block_on_ref(future: &mut HttpOperationFuture) -> HttpOperationResult {
        let state = Arc::new((Mutex::new(false), Condvar::new()));
        let waker = Waker::from(Arc::new(WakeSignal {
            state: Arc::clone(&state),
        }));
        let mut context = Context::from_waker(&waker);
        let mut future = Pin::new(future);
        loop {
            match Future::poll(future.as_mut(), &mut context) {
                Poll::Ready(result) => return result,
                Poll::Pending => {
                    let (ready, condition) = &*state;
                    let mut ready = lock_test(ready);
                    while !*ready {
                        ready = condition
                            .wait(ready)
                            .unwrap_or_else(PoisonError::into_inner);
                    }
                    *ready = false;
                }
            }
        }
    }

    fn wait_for_completion(state: &Arc<OperationState>) {
        let mut inner = lock_test(&state.state);
        while inner.result.is_none() && !inner.finished {
            inner = state
                .completion_condition
                .wait(inner)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    #[test]
    fn limits_validate_every_required_dimension() {
        assert_eq!(
            PoolLimits {
                worker_count: 0,
                queue_jobs: 1,
                max_retained_bytes: 1,
                shutdown: ShutdownBehavior::Drain,
            }
            .validate()
            .expect_err("zero worker count must fail")
            .code(),
            "http.pool.limits"
        );
        assert_eq!(
            PoolLimits {
                worker_count: 1,
                queue_jobs: 0,
                max_retained_bytes: 1,
                shutdown: ShutdownBehavior::Drain,
            }
            .validate()
            .expect_err("zero queue capacity must fail")
            .code(),
            "http.pool.limits"
        );
        assert_eq!(
            PoolLimits {
                worker_count: 1,
                queue_jobs: 1,
                max_retained_bytes: 0,
                shutdown: ShutdownBehavior::Drain,
            }
            .validate()
            .expect_err("zero retained bytes must fail")
            .code(),
            "http.pool.limits"
        );
        assert_eq!(
            PoolLimits {
                worker_count: 1,
                queue_jobs: 1,
                max_retained_bytes: MAX_HTTP_RETAINED_BYTES + 1,
                shutdown: ShutdownBehavior::Drain,
            }
            .validate()
            .expect_err("oversized retained budget must fail")
            .code(),
            "http.pool.limits"
        );
        assert!(PoolLimits::default().validate().is_ok());
    }

    #[test]
    fn deadline_requires_explicit_nonzero_duration_and_checked_runtime_domain() {
        let now = MonotonicInstant::from_duration(Duration::from_secs(7));
        assert_eq!(
            OperationDeadline::after_at(now, Duration::ZERO),
            Err(PoolError::InvalidDeadline)
        );
        let long = OperationDeadline::after_at(MonotonicInstant::zero(), Duration::MAX)
            .expect("representable long deadline");
        assert_eq!(long.remaining(MonotonicInstant::zero()), Duration::MAX);
        assert_eq!(
            OperationDeadline::after_at(
                MonotonicInstant::from_duration(Duration::from_nanos(1)),
                Duration::MAX,
            ),
            Err(PoolError::DeadlineOverflow)
        );
    }

    #[test]
    fn clock_source_failure_rejects_admission_and_is_preserved_by_finalization() {
        let clock = Arc::new(OperationClockAdapter::new(|| {
            Err(OperationClockError::Unavailable)
        }));
        let pool = HttpWorkerPool::new(limits(1, 1, 64), clock).expect("pool");
        assert_eq!(
            pool.submit(operation(8, move |_token| result_ok()))
                .expect_err("clock source must reject queue admission"),
            PoolError::ClockSource
        );
        assert_eq!(
            pool.finalize()
                .expect_err("clock source failure must remain observable"),
            PoolError::ClockSource
        );
    }

    #[test]
    fn explicit_clock_reversal_failure_is_typed_and_fail_closed() {
        let clock = Arc::new(OperationClockAdapter::new(|| {
            Err(OperationClockError::Reversed)
        }));
        let pool = HttpWorkerPool::new(limits(1, 1, 64), clock).expect("pool");
        assert_eq!(
            pool.submit(operation(8, move |_token| result_ok()))
                .expect_err("reversal must reject queue admission"),
            PoolError::ClockInvalid
        );
        assert_eq!(
            pool.finalize()
                .expect_err("reversal must remain observable"),
            PoolError::ClockInvalid
        );
    }

    #[test]
    fn clock_source_failure_during_dequeue_fails_operation_and_finalization() {
        let reads = Arc::new(AtomicUsize::new(0));
        let clock = {
            let reads = Arc::clone(&reads);
            Arc::new(OperationClockAdapter::new(move || {
                if reads.fetch_add(1, Ordering::AcqRel) == 0 {
                    Ok(MonotonicInstant::zero())
                } else {
                    Err(OperationClockError::Unavailable)
                }
            }))
        };
        let pool = HttpWorkerPool::new(limits(1, 1, 64), clock).expect("pool");
        let future = pool
            .submit(operation(8, move |_token| result_ok()))
            .expect("admission clock read succeeds");
        let error = block_on(future).expect_err("dequeue clock failure");
        assert!(matches!(
            error,
            HttpError::Transport(TransportError::Adapter { ref code, .. })
                if code == "http.pool.clock-source"
        ));
        assert_eq!(
            pool.finalize()
                .expect_err("dequeue clock failure must remain observable"),
            PoolError::ClockSource
        );
    }

    #[test]
    fn accounting_and_mutex_poison_are_recorded_for_finalization() {
        let pool = test_pool(limits(1, 1, 64));
        pool.shared.accounting.release_bytes(1);
        assert_eq!(
            pool.finalize()
                .expect_err("underflow is an invariant failure"),
            PoolError::InternalInvariant
        );

        let pool = test_pool(limits(1, 2, 64));
        let (started_sender, started_receiver) = mpsc::sync_channel(0);
        let (release_sender, release_receiver) = mpsc::sync_channel(0);
        let first = pool
            .submit(operation(8, move |_token| {
                started_sender.send(()).expect("started receiver");
                release_receiver.recv().expect("release receiver");
                result_ok()
            }))
            .expect("running operation");
        started_receiver.recv().expect("worker started");
        let second = pool
            .submit(operation(8, move |_token| result_ok()))
            .expect("queued operation");
        let state = Arc::clone(&second.state);
        thread::spawn(move || {
            let _guard = state.state.lock().expect("state lock");
            panic!("intentional state mutex poison");
        })
        .join()
        .expect_err("poison fixture must panic");
        release_sender.send(()).expect("release receiver");
        assert!(block_on(first).is_ok());
        drop(second);
        assert_eq!(
            pool.finalize().expect_err("poison is an invariant failure"),
            PoolError::InternalInvariant
        );
    }

    #[test]
    fn default_native_estimate_fits_default_budget_and_checked_sum_rejects_overflow() {
        let transport = NativeTransport::with_defaults().expect("native defaults");
        let client = HttpClient::new(transport, ClientConfig::default()).expect("client");
        let request = Request::new(Method::Get, Url::parse("http://127.0.0.1:1/").expect("URL"));
        let estimate = estimate_retained_bytes(&client, &request).expect("estimate");
        assert!(estimate.total_bytes <= DEFAULT_HTTP_RETAINED_BYTES);
        assert_eq!(
            checked_sum([usize::MAX, 1]),
            Err(PoolError::InternalInvariant)
        );
    }

    #[test]
    fn versioned_clients_use_selected_limits_for_checked_reservations() {
        let request = Request::new(
            Method::Get,
            Url::parse("https://127.0.0.1:1/").expect("bounded HTTPS URL"),
        );
        let mut client_config = ClientConfig::default();
        client_config.redirects.maximum_retained_bytes = 1024 * 1024;
        let v1_transport = NativeTransport::with_defaults().expect("V1 transport");
        let v1_client = Arc::new(Mutex::new(
            HttpClient::new(
                NativeHttpTransport::from_v1(v1_transport),
                client_config.clone(),
            )
            .expect("V1 client"),
        ));

        let mut v2_limits = jmeter_rs_http_native::NativeTransportLimits::default();
        v2_limits.max_response_body_bytes = 1024 * 1024;
        v2_limits.max_response_total_bytes = v2_limits
            .max_response_head_bytes
            .checked_add(v2_limits.max_response_body_bytes)
            .expect("bounded V2 response total");
        let resolver =
            jmeter_rs_http_native::StaticDnsResolver::new(4).expect("bounded static resolver");
        let v2_transport =
            NativeTransportV2::new(v2_limits, Arc::new(resolver), None).expect("V2 transport");
        let v2_client = Arc::new(Mutex::new(
            HttpClient::new(NativeHttpTransport::from_v2(v2_transport), client_config)
                .expect("V2 client"),
        ));

        let v1_estimate = {
            let client = lock_test(&v1_client);
            estimate_retained_bytes(&client, &request).expect("V1 estimate")
        };
        let v2_estimate = {
            let client = lock_test(&v2_client);
            estimate_retained_bytes(&client, &request).expect("V2 estimate")
        };
        assert_eq!(
            v1_client
                .lock()
                .expect("V1 mutex")
                .transport()
                .capability_id(),
            NativeHttpTransport::V1_CAPABILITY_ID
        );
        assert_eq!(
            v2_client
                .lock()
                .expect("V2 mutex")
                .transport()
                .capability_id(),
            NativeHttpTransport::V2_CAPABILITY_ID
        );
        assert_ne!(
            v1_estimate.native_response_body_bytes,
            v2_estimate.native_response_body_bytes
        );
        assert_eq!(v1_estimate.native_response_body_bytes, 32 * 1024 * 1024);
        assert_eq!(v2_estimate.native_response_body_bytes, 1024 * 1024);

        let operation_v1 =
            HttpOperation::from_shared_client(v1_client, request.clone()).expect("V1 operation");
        let operation_v2 =
            HttpOperation::from_shared_client(v2_client, request).expect("V2 operation");
        assert_eq!(operation_v1.retained_bytes(), v1_estimate.total_bytes);
        assert_eq!(operation_v2.retained_bytes(), v2_estimate.total_bytes);

        let pool_budget = v1_estimate
            .total_bytes
            .checked_add(v2_estimate.total_bytes)
            .expect("bounded pool budget");
        assert!(pool_budget <= MAX_HTTP_RETAINED_BYTES);
        let pool = test_pool(limits(2, 2, pool_budget));
        let future_v1 = pool.submit(operation_v1).expect("V1 operation admission");
        let future_v2 = pool.submit(operation_v2).expect("V2 operation admission");
        assert_eq!(pool.shared.retained_bytes(), pool_budget);

        // HTTPS is rejected during each selected transport's preflight.  No
        // socket or DNS operation is reached, so this verifies exact variant
        // dispatch and no V1/V2 fallback using only deterministic local data.
        let v1_error = block_on(future_v1).expect_err("V1 must reject HTTPS");
        assert!(matches!(
            v1_error,
            HttpError::Transport(TransportError::Unsupported(message))
                if message.contains("plain HTTP")
        ));
        assert_eq!(pool.shared.retained_bytes(), v2_estimate.total_bytes);
        let v2_error = block_on(future_v2).expect_err("V2 must require explicit TLS");
        assert!(matches!(
            v2_error,
            HttpError::Transport(TransportError::Unsupported(message))
                if message.contains("explicit TLS configuration")
        ));
        assert_eq!(pool.shared.retained_bytes(), 0);
        pool.finalize().expect("finalize");
    }

    #[test]
    fn workers_execute_in_parallel_without_inline_execution() {
        let pool = test_pool(limits(2, 4, 64));
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let active = Arc::new(AtomicUsize::new(0));
        let saw_parallel = Arc::new(AtomicBool::new(false));
        let caller_is_worker = current_worker_index().is_some();
        let first = {
            let barrier = Arc::clone(&barrier);
            let active = Arc::clone(&active);
            let saw_parallel = Arc::clone(&saw_parallel);
            pool.submit(operation(8, move |_token| {
                assert!(current_worker_index().is_some());
                let current = active.fetch_add(1, Ordering::AcqRel) + 1;
                if current == 2 {
                    saw_parallel.store(true, Ordering::Release);
                }
                barrier.wait();
                active.fetch_sub(1, Ordering::AcqRel);
                result_ok()
            }))
            .expect("first operation")
        };
        let second = {
            let barrier = Arc::clone(&barrier);
            let active = Arc::clone(&active);
            let saw_parallel = Arc::clone(&saw_parallel);
            pool.submit(operation(8, move |_token| {
                assert!(current_worker_index().is_some());
                let current = active.fetch_add(1, Ordering::AcqRel) + 1;
                if current == 2 {
                    saw_parallel.store(true, Ordering::Release);
                }
                barrier.wait();
                active.fetch_sub(1, Ordering::AcqRel);
                result_ok()
            }))
            .expect("second operation")
        };
        assert!(!caller_is_worker);
        assert!(block_on(first).is_ok());
        assert!(block_on(second).is_ok());
        assert!(saw_parallel.load(Ordering::Acquire));
        pool.finalize().expect("finalize");
    }

    #[test]
    fn queue_full_is_distinct_from_stopped_and_never_runs_inline() {
        let pool = test_pool(limits(1, 1, 128));
        let (started_sender, started_receiver) = mpsc::sync_channel(0);
        let (release_sender, release_receiver) = mpsc::sync_channel(0);
        let first = pool
            .submit(operation(8, move |_token| {
                started_sender.send(()).expect("started receiver");
                release_receiver.recv().expect("release sender");
                result_ok()
            }))
            .expect("first operation");
        started_receiver.recv().expect("worker started");
        let second = pool
            .submit(operation(8, move |_token| result_ok()))
            .expect("one queued operation");
        let third = pool
            .submit(operation(8, move |_token| result_ok()))
            .expect_err("queue is full");
        assert_eq!(third.code(), "http.pool.full");
        release_sender.send(()).expect("release receiver");
        assert!(block_on(first).is_ok());
        assert!(block_on(second).is_ok());
        pool.finalize().expect("finalize");
    }

    #[test]
    fn aggregate_byte_reservation_is_atomic_and_released_once() {
        let pool = test_pool(limits(1, 4, 10));
        let (release_sender, release_receiver) = mpsc::sync_channel(0);
        let first = pool
            .submit(operation(6, move |_token| {
                release_receiver.recv().expect("release sender");
                result_ok()
            }))
            .expect("first reservation");
        let second = pool
            .submit(operation(5, move |_token| result_ok()))
            .expect_err("aggregate bytes are full");
        assert_eq!(second.code(), "http.pool.retained-limit");
        release_sender.send(()).expect("release receiver");
        assert!(block_on(first).is_ok());
        let third = pool
            .submit(operation(10, move |_token| result_ok()))
            .expect("released reservation is reusable");
        assert!(block_on(third).is_ok());
        pool.finalize().expect("finalize");
    }

    #[test]
    fn completed_unpolled_result_retains_budget_until_future_drop() {
        let pool = test_pool(limits(1, 2, 10));
        let first = pool
            .submit(operation(6, move |_token| result_ok()))
            .expect("first operation");
        let state = Arc::clone(&first.state);
        wait_for_completion(&state);
        drop(state);

        // The worker has published the result and released its Job, but the
        // caller has not projected or dropped the future yet. The result's
        // retained bytes therefore still consume the aggregate budget.
        assert_eq!(pool.shared.retained_bytes(), 6);
        assert_eq!(
            pool.submit(operation(5, move |_token| result_ok()))
                .expect_err("completed result must retain its reservation"),
            PoolError::RetainedLimit {
                requested: 5,
                maximum: 10,
            }
        );

        assert!(block_on(first).is_ok());
        assert_eq!(pool.shared.retained_bytes(), 0);
        let replacement = pool
            .submit(operation(10, move |_token| result_ok()))
            .expect("future drop releases completed-result reservation");
        assert!(block_on(replacement).is_ok());
        pool.finalize().expect("finalize");
    }

    #[test]
    fn completion_before_first_poll_and_registered_waker_both_work() {
        let pool = test_pool(limits(1, 2, 64));
        let future = pool
            .submit(operation(8, move |_token| result_ok()))
            .expect("operation");
        let state = Arc::clone(&future.state);
        wait_for_completion(&state);
        drop(state);
        assert!(block_on(future).is_ok());
        pool.finalize().expect("finalize");

        let pool = test_pool(limits(1, 2, 64));
        let (started_sender, started_receiver) = mpsc::sync_channel(0);
        let (release_sender, release_receiver) = mpsc::sync_channel(0);
        let mut future = pool
            .submit(operation(8, move |_token| {
                started_sender.send(()).expect("started receiver");
                release_receiver.recv().expect("release sender");
                result_ok()
            }))
            .expect("operation");
        let state = Arc::new((Mutex::new(false), Condvar::new()));
        let waker = Waker::from(Arc::new(WakeSignal {
            state: Arc::clone(&state),
        }));
        let mut context = Context::from_waker(&waker);
        assert!(matches!(
            Pin::new(&mut future).poll(&mut context),
            Poll::Pending
        ));
        started_receiver.recv().expect("worker started");
        release_sender.send(()).expect("release receiver");
        let (ready, condition) = &*state;
        let mut ready = lock_test(ready);
        while !*ready {
            ready = condition
                .wait(ready)
                .unwrap_or_else(PoisonError::into_inner);
        }
        drop(ready);
        assert!(matches!(
            Pin::new(&mut future).poll(&mut context),
            Poll::Ready(Ok(_))
        ));
        assert_eq!(pool.shared.retained_bytes(), 8);
        drop(future);
        assert_eq!(pool.shared.retained_bytes(), 0);
        pool.finalize().expect("finalize");
    }

    #[test]
    fn cancellation_reaches_running_operation_and_drop_cancels_queued_operation() {
        let pool = test_pool(limits(1, 2, 64));
        let (started_sender, started_receiver) = mpsc::sync_channel(0);
        let (cancel_sender, cancel_receiver) = mpsc::sync_channel(0);
        let mut future = pool
            .submit(operation(8, move |token| {
                let registration = token.register_waker(move || {
                    cancel_sender.send(()).expect("cancel receiver");
                });
                started_sender.send(()).expect("started receiver");
                cancel_receiver.recv().expect("cancellation callback");
                assert!(token.is_cancelled());
                drop(registration);
                Err(HttpError::Cancelled)
            }))
            .expect("operation");
        started_receiver.recv().expect("worker started");
        future.cancel();
        let result = block_on_ref(&mut future);
        assert!(matches!(result, Err(HttpError::Cancelled)));
        assert_eq!(pool.shared.retained_bytes(), 8);
        drop(future);
        assert_eq!(pool.shared.retained_bytes(), 0);
        pool.finalize().expect("finalize");

        let pool = test_pool(limits(1, 1, 64));
        let (started_sender, started_receiver) = mpsc::sync_channel(0);
        let (release_sender, release_receiver) = mpsc::sync_channel(0);
        let first = pool
            .submit(operation(8, move |_token| {
                started_sender.send(()).expect("started receiver");
                release_receiver.recv().expect("release sender");
                result_ok()
            }))
            .expect("first operation");
        started_receiver.recv().expect("worker started");
        let second = pool
            .submit(operation(8, move |_token| result_ok()))
            .expect("queued operation");
        drop(second);
        release_sender.send(()).expect("release receiver");
        assert!(block_on(first).is_ok());
        pool.finalize().expect("finalize");
    }

    #[test]
    fn dropping_future_keeps_queued_job_reservation_until_terminal_completion() {
        let pool = test_pool(limits(1, 2, 10));
        let (started_sender, started_receiver) = mpsc::sync_channel(0);
        let (release_sender, release_receiver) = mpsc::sync_channel(0);
        let first = pool
            .submit(operation(6, move |_token| {
                started_sender.send(()).expect("started receiver");
                release_receiver.recv().expect("release receiver");
                result_ok()
            }))
            .expect("running operation");
        started_receiver.recv().expect("worker started");
        let queued = pool
            .submit(operation(4, move |_token| result_ok()))
            .expect("queued operation");
        drop(queued);
        assert_eq!(pool.shared.retained_bytes(), 10);
        assert_eq!(
            pool.submit(operation(1, move |_token| result_ok()))
                .expect_err("dropped future must not release queued reservation"),
            PoolError::RetainedLimit {
                requested: 1,
                maximum: 10,
            }
        );
        release_sender.send(()).expect("release receiver");
        assert!(block_on(first).is_ok());
        pool.finalize().expect("finalize");
        assert_eq!(pool.shared.retained_bytes(), 0);
    }

    #[test]
    fn queued_operation_uses_absolute_deadline_and_expires_without_running() {
        let base = MonotonicInstant::from_duration(Duration::from_secs(10));
        let clock = ManualMonotonicClock::new(base);
        let pool = HttpWorkerPool::new(limits(1, 2, 64), Arc::new(clock.clone())).expect("pool");
        let (started_sender, started_receiver) = mpsc::sync_channel(0);
        let (release_sender, release_receiver) = mpsc::sync_channel(0);
        let first = pool
            .submit(operation(8, move |_token| {
                started_sender.send(()).expect("started receiver");
                release_receiver.recv().expect("release receiver");
                result_ok()
            }))
            .expect("running operation");
        started_receiver.recv().expect("worker started");
        let ran = Arc::new(AtomicBool::new(false));
        let deadline = OperationDeadline::after_at(base, Duration::from_secs(5))
            .expect("nonzero explicit deadline");
        let queued = {
            let ran = Arc::clone(&ran);
            pool.submit_with_deadline(
                operation(8, move |_token| {
                    ran.store(true, Ordering::Release);
                    result_ok()
                }),
                deadline,
            )
            .expect("queued operation")
        };
        clock.set(base.checked_add(Duration::from_secs(5)).expect("deadline"));
        release_sender.send(()).expect("release receiver");
        assert!(block_on(first).is_ok());
        assert!(matches!(
            block_on(queued),
            Err(HttpError::Timeout(TimeoutPhase::Overall))
        ));
        assert!(!ran.load(Ordering::Acquire));
        pool.finalize().expect("finalize");
    }

    #[test]
    fn clock_reversal_fails_closed_without_refreshing_queued_deadline() {
        let base = MonotonicInstant::from_duration(Duration::from_secs(10));
        let clock = Arc::new(ManualMonotonicClock::new(base));
        let pool = HttpWorkerPool::new(
            limits(1, 2, 64),
            Arc::clone(&clock) as Arc<dyn OperationClock>,
        )
        .expect("pool");
        let (started_sender, started_receiver) = mpsc::sync_channel(0);
        let (release_sender, release_receiver) = mpsc::sync_channel(0);
        let first = pool
            .submit(operation(8, move |_token| {
                started_sender.send(()).expect("started receiver");
                release_receiver.recv().expect("release receiver");
                result_ok()
            }))
            .expect("running operation");
        started_receiver.recv().expect("worker started");
        let queued = pool
            .submit_with_deadline(
                operation(8, move |_token| result_ok()),
                OperationDeadline::after_at(base, Duration::from_secs(60))
                    .expect("explicit deadline"),
            )
            .expect("queued operation");
        clock.set(MonotonicInstant::from_duration(Duration::from_secs(9)));
        release_sender.send(()).expect("release receiver");
        assert!(block_on(first).is_ok());
        let error = block_on(queued).expect_err("reversed clock must fail closed");
        assert!(matches!(
            error,
            HttpError::Transport(TransportError::Adapter { ref code, .. })
                if code == "http.budget.clock-invalid"
        ));
        assert_eq!(
            pool.finalize()
                .expect_err("clock reversal must remain observable"),
            PoolError::ClockInvalid
        );
    }

    #[test]
    fn worker_errors_are_bounded_and_panics_are_observed() {
        let pool = test_pool(limits(1, 2, 64));
        let mut error_future = pool
            .submit(operation(8, move |_token| {
                Err(HttpError::Transport(TransportError::Read(
                    "sensitive provider detail".to_owned(),
                )))
            }))
            .expect("error operation");
        let error = block_on_ref(&mut error_future).expect_err("worker error");
        assert_eq!(error.stable_code(), "http.transport.read");
        assert!(!format!("{error:?}").contains("sensitive provider detail"));
        assert_eq!(pool.shared.retained_bytes(), 8);
        drop(error_future);
        assert_eq!(pool.shared.retained_bytes(), 0);
        let mut panic_future = pool
            .submit(operation(8, move |_token| {
                panic!("operation panic payload");
            }))
            .expect("panic operation");
        let panic_error = block_on_ref(&mut panic_future).expect_err("panic error");
        assert_eq!(panic_error.stable_code(), "http.transport.adapter");
        assert_eq!(
            match panic_error {
                HttpError::Transport(TransportError::Adapter { ref code, .. }) => code.as_str(),
                _ => "",
            },
            "http.pool.worker-panic"
        );
        assert_eq!(pool.shared.retained_bytes(), 8);
        drop(panic_future);
        assert_eq!(pool.shared.retained_bytes(), 0);
        assert_eq!(
            pool.finalize().expect_err("panic must fail finalization"),
            PoolError::WorkerPanic { worker_index: 0 }
        );
        assert_eq!(
            pool.finalize()
                .expect_err("cached panic must remain an error"),
            PoolError::WorkerPanic { worker_index: 0 }
        );
    }

    #[test]
    fn unexpected_worker_loop_panic_completes_current_and_queued_futures() {
        let pool = test_pool(limits(1, 3, 64));
        let (started_sender, started_receiver) = mpsc::sync_channel(0);
        let (release_sender, release_receiver) = mpsc::sync_channel(0);
        let first = pool
            .submit(operation(8, move |_token| {
                started_sender.send(()).expect("started receiver");
                release_receiver.recv().expect("release receiver");
                result_ok()
            }))
            .expect("running operation");
        started_receiver.recv().expect("worker started");
        let second = pool
            .submit(operation(8, move |_token| result_ok()))
            .expect("first queued operation");
        let third = pool
            .submit(operation(8, move |_token| result_ok()))
            .expect("second queued operation");
        pool.shared.request_worker_loop_panic();
        release_sender.send(()).expect("release receiver");
        assert!(block_on(first).is_ok());
        let current_error = block_on(second).expect_err("panic must wake queued future");
        let queued_error = block_on(third).expect_err("panic must wake queued future");
        assert!(matches!(
            current_error,
            HttpError::Transport(TransportError::Adapter { ref code, .. })
                if code == "http.pool.worker-panic"
        ));
        assert!(matches!(
            queued_error,
            HttpError::Transport(TransportError::Adapter { ref code, .. })
                if code == "http.pool.worker-panic"
        ));
        assert_eq!(
            pool.finalize().expect_err("worker panic must be observed"),
            PoolError::WorkerPanic { worker_index: 0 }
        );
    }

    #[test]
    fn finalize_drains_and_submit_after_stop_is_typed_and_idempotent() {
        let pool = test_pool(limits(2, 4, 64));
        let completed = Arc::new(AtomicUsize::new(0));
        let first = {
            let completed = Arc::clone(&completed);
            pool.submit(operation(8, move |_token| {
                completed.fetch_add(1, Ordering::AcqRel);
                result_ok()
            }))
            .expect("first operation")
        };
        let second = {
            let completed = Arc::clone(&completed);
            pool.submit(operation(8, move |_token| {
                completed.fetch_add(1, Ordering::AcqRel);
                result_ok()
            }))
            .expect("second operation")
        };
        assert!(block_on(first).is_ok());
        assert!(block_on(second).is_ok());
        let report = pool.finalize().expect("finalize");
        assert_eq!(report.worker_count, 2);
        assert_eq!(report.observed_worker_panics, 0);
        assert_eq!(completed.load(Ordering::Acquire), 2);
        assert_eq!(
            pool.submit(operation(8, move |_token| result_ok()))
                .expect_err("submit after finalize must fail")
                .code(),
            "http.pool.stopped"
        );
        assert_eq!(pool.finalize().expect("idempotent finalize"), report);
    }

    #[test]
    fn cancel_queued_shutdown_finishes_without_running_queued_work() {
        let shutdown = PoolLimits {
            worker_count: 1,
            queue_jobs: 2,
            max_retained_bytes: 64,
            shutdown: ShutdownBehavior::CancelQueued,
        };
        shutdown.validate().expect("limits");
        let pool = test_pool(shutdown);
        let (started_sender, started_receiver) = mpsc::sync_channel(0);
        let finalization_started = Arc::clone(&pool.shared);
        let first = pool
            .submit(operation(8, move |_token| {
                started_sender.send(()).expect("started receiver");
                let mut started = lock_test(&finalization_started.finalization_started);
                while !*started {
                    started = finalization_started
                        .finalization_condition
                        .wait(started)
                        .unwrap_or_else(PoisonError::into_inner);
                }
                result_ok()
            }))
            .expect("first operation");
        started_receiver.recv().expect("worker started");
        let ran = Arc::new(AtomicBool::new(false));
        let queued = {
            let ran = Arc::clone(&ran);
            pool.submit(operation(8, move |_token| {
                ran.store(true, Ordering::Release);
                result_ok()
            }))
            .expect("queued operation")
        };
        let report = pool.finalize().expect("cancel-queued finalize");
        assert!(block_on(first).is_ok());
        assert!(matches!(block_on(queued), Err(HttpError::Cancelled)));
        assert_eq!(report.observed_worker_panics, 0);
        assert!(!ran.load(Ordering::Acquire));
    }
}
