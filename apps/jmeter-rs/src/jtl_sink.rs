// SPDX-License-Identifier: Apache-2.0
//! Run-owned, bounded streaming JTL output at the application boundary.
//!
//! The result model and codecs are deliberately executor-neutral.  This
//! module owns the one blocking writer thread needed by a local application
//! run and exposes cloneable legacy [`ResultSink`] and typed
//! [`TypedJtlSinkAdapter`] views to runtime/router code.  Both views perform
//! bounded admission under a short mutex critical section; encoding, writing,
//! flushing, and joining are all kept off future polling paths. Typed futures
//! borrow the runtime's run-owned result wait registrar for exact Provider
//! liveness ownership.

#![forbid(unsafe_code)]
#![allow(
    clippy::module_name_repetitions,
    reason = "the application boundary names owner, submitter, and future types explicitly"
)]
use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::io::{self, Write};
use std::marker::PhantomData;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::thread::{self, JoinHandle};

use jmeter_rs_results::{JtlEncoder, JtlError, SampleEvent, SampleSaveConfiguration};
use jmeter_rs_runtime::{
    DeliveryLease, DurabilityAck, DurabilityBoundary, QualifiedSinkId, ResultEnvelope,
    ResultOperationKind, ResultOperationLease, ResultOperationScope, ResultSink, ResultSinkFuture,
    ResultWaitRegistrar, ResultWaitRegistration, SinkError, SinkLimits, TypedSinkAdapter,
    TypedSinkError, TypedSinkFuture, WaitOwnerClass,
};

/// Maximum queue slots accepted by this application boundary.
pub const MAX_JTL_SINK_QUEUE_ITEMS: usize = 1_000_000;
/// Maximum aggregate envelope bytes retained by one sink queue.
///
/// This is a queue-retention bound, not a JTL output-size bound.  The
/// streaming codec owns checked output counters and may write a run whose
/// total output is larger than this value as long as the queue drains.
pub const MAX_JTL_SINK_QUEUE_BYTES: usize = 512 * 1024 * 1024;
/// Default queue limits for a local JTL sink.
pub const DEFAULT_JTL_SINK_QUEUE_ITEMS: usize = 256;
/// Default aggregate queue-byte limit for a local JTL sink.
pub const DEFAULT_JTL_SINK_QUEUE_BYTES: usize = 64 * 1024 * 1024;

/// Fixed queue limits for one run-owned JTL sink.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct JtlSinkLimits {
    /// Maximum number of write envelopes admitted, including one currently
    /// being encoded by the worker.
    pub max_items: usize,
    /// Maximum sum of [`ResultEnvelope::byte_size`] for admitted writes,
    /// including the item currently being encoded.
    pub max_bytes: usize,
}

impl Default for JtlSinkLimits {
    fn default() -> Self {
        Self {
            max_items: DEFAULT_JTL_SINK_QUEUE_ITEMS,
            max_bytes: DEFAULT_JTL_SINK_QUEUE_BYTES,
        }
    }
}

impl JtlSinkLimits {
    /// Creates finite limits and rejects zero or product-wide overlarge
    /// values before a worker is started.
    #[cfg(test)]
    pub fn new(max_items: usize, max_bytes: usize) -> Result<Self, JtlSinkError> {
        let limits = Self {
            max_items,
            max_bytes,
        };
        limits.validate()?;
        Ok(limits)
    }

    /// Validates this queue policy.
    pub fn validate(self) -> Result<(), JtlSinkError> {
        if self.max_items == 0 || self.max_items > MAX_JTL_SINK_QUEUE_ITEMS {
            return Err(JtlSinkError::InvalidLimits {
                field: JtlSinkLimitField::Items,
            });
        }
        if self.max_bytes == 0 || self.max_bytes > MAX_JTL_SINK_QUEUE_BYTES {
            return Err(JtlSinkError::InvalidLimits {
                field: JtlSinkLimitField::Bytes,
            });
        }
        Ok(())
    }
}

impl From<SinkLimits> for JtlSinkLimits {
    fn from(value: SinkLimits) -> Self {
        Self {
            max_items: value.max_items,
            max_bytes: value.max_bytes,
        }
    }
}

/// Which queue limit rejected a sink policy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum JtlSinkLimitField {
    /// The item-count bound was zero or too large.
    Items,
    /// The aggregate byte bound was zero or too large.
    Bytes,
}

impl JtlSinkLimitField {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Items => "items",
            Self::Bytes => "bytes",
        }
    }
}

/// Errors raised while creating or joining a run-owned JTL sink.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JtlSinkError {
    /// The finite queue policy was invalid.
    InvalidLimits { field: JtlSinkLimitField },
    /// The exact writer thread could not be started.
    WorkerStart,
    /// The exact writer thread panicked; its payload is intentionally not
    /// retained or formatted.
    WorkerPanic,
    /// Joining the exact writer thread failed.
    WorkerJoin,
    /// Finalization was attempted from the writer thread itself.
    FinalizeFromWorker,
    /// The sink's shared state observed a poisoned lock or accounting error.
    InternalInvariant,
    /// The writer/codec reported a bounded sink failure.
    Sink(SinkError),
}

impl JtlSinkError {
    /// Returns a stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidLimits { .. } => "app.jtl-sink.limits",
            Self::WorkerStart => "app.jtl-sink.worker-start",
            Self::WorkerPanic => "app.jtl-sink.worker-panic",
            Self::WorkerJoin => "app.jtl-sink.worker-join",
            Self::FinalizeFromWorker => "app.jtl-sink.finalize-from-worker",
            Self::InternalInvariant => "app.jtl-sink.internal-invariant",
            Self::Sink(error) => error.code(),
        }
    }
}

impl fmt::Display for JtlSinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits { field } => {
                write!(formatter, "{}: {}", self.code(), field.as_str())
            }
            Self::Sink(error) => error.fmt(formatter),
            Self::WorkerStart
            | Self::WorkerPanic
            | Self::WorkerJoin
            | Self::FinalizeFromWorker
            | Self::InternalInvariant => formatter.write_str(self.code()),
        }
    }
}

impl std::error::Error for JtlSinkError {}

/// Summary returned after the exact writer thread has been joined.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JtlSinkFinalizeReport {
    /// Whether the FIFO finish command completed successfully.
    pub finished: bool,
    /// Whether cancellation was requested before finalization completed.
    pub cancelled: bool,
    /// Whether the writer thread observed a panic.
    pub worker_panicked: bool,
}

/// Cloneable submission-only view of a [`JtlSinkOwner`].
///
/// This handle contains no writer or join handle.  It can therefore be
/// cloned into runtime/router state while the owner remains on its run
/// thread.
#[derive(Clone)]
pub struct JtlSinkSubmitter {
    shared: Arc<Shared>,
    limits: JtlSinkLimits,
}

impl fmt::Debug for JtlSinkSubmitter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.shared.lock_state();
        formatter
            .debug_struct("JtlSinkSubmitter")
            .field("limits", &self.limits)
            .field("phase", &state.phase)
            .field("queued_items", &state.queued_items)
            .field("queued_bytes", &state.queued_bytes)
            .finish()
    }
}

impl JtlSinkSubmitter {
    /// Requests cancellation without waiting for the writer thread.
    pub fn cancel(&self) -> Result<(), SinkError> {
        self.shared.cancel()
    }

    /// Returns a future for one FIFO flush command.
    pub fn flush(&self) -> ResultSinkFuture<'static> {
        match self.shared.enqueue_flush() {
            Ok(completion) => Box::pin(SinkCompletionFuture::new(completion)),
            Err(error) => Box::pin(std::future::ready(Err(error))),
        }
    }

    /// Returns the writer-initialization readiness completion.
    ///
    /// The worker constructs and validates its encoder before completing this
    /// future.  A typed router therefore cannot begin sampling while a
    /// malformed save configuration or encoder startup failure is still
    /// hidden on the writer thread.
    fn readiness(&self) -> ResultSinkFuture<'static> {
        Box::pin(SinkCompletionFuture::new(self.shared.readiness()))
    }

    /// Returns an idempotent future for the FIFO finish command.
    pub fn finish(&self) -> ResultSinkFuture<'static> {
        match self.shared.enqueue_finish() {
            Ok(completion) => Box::pin(SinkCompletionFuture::new(completion)),
            Err(error) => Box::pin(std::future::ready(Err(error))),
        }
    }

    fn write_envelope(&self, envelope: &ResultEnvelope) -> ResultSinkFuture<'static> {
        match self.shared.enqueue_write(envelope, self.limits) {
            Ok(completion) => Box::pin(SinkCompletionFuture::new(completion)),
            Err(error) => Box::pin(std::future::ready(Err(error))),
        }
    }

    /// Enqueues the original typed event without reconstructing a legacy
    /// [`ResultEnvelope`].  The returned completion is consumed by the typed
    /// adapter, which owns the operation lease and wait registration.
    fn write_sample_event(
        &self,
        event: &SampleEvent,
        bytes: usize,
    ) -> Result<Arc<Completion>, SinkError> {
        self.shared.enqueue_sample_event(event, bytes, self.limits)
    }

    fn enqueue_flush_completion(&self) -> Result<Arc<Completion>, SinkError> {
        self.shared.enqueue_flush()
    }

    fn enqueue_finish_completion(&self) -> Result<Arc<Completion>, SinkError> {
        self.shared.enqueue_finish()
    }
}

impl ResultSink for JtlSinkSubmitter {
    fn write<'a>(&'a self, envelope: &'a ResultEnvelope) -> ResultSinkFuture<'a> {
        // `write_envelope` clones the immutable envelope before admission.
        // The returned future owns only an Arc completion and has no borrow
        // of the input event despite the executor-neutral trait lifetime.
        self.write_envelope(envelope)
    }

    fn flush<'a>(&'a self) -> ResultSinkFuture<'a> {
        self.flush()
    }

    fn finish<'a>(&'a self) -> ResultSinkFuture<'a> {
        self.finish()
    }

    fn cancel(&self) -> Result<(), SinkError> {
        self.cancel()
    }
}

/// The one run-owned JTL writer and exact writer-thread handle.
pub struct JtlSinkOwner {
    shared: Arc<Shared>,
    limits: JtlSinkLimits,
    handle: Mutex<Option<JoinHandle<()>>>,
    finalize_gate: Mutex<()>,
    finalization: Mutex<Option<Result<JtlSinkFinalizeReport, JtlSinkError>>>,
    // A run owner must not move into the worker or an executor task.  The
    // cloneable submitter above is the only cross-thread view.
    _owner_thread: PhantomData<Rc<()>>,
}

impl fmt::Debug for JtlSinkOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.shared.lock_state();
        formatter
            .debug_struct("JtlSinkOwner")
            .field("limits", &self.limits)
            .field("phase", &state.phase)
            .field("queued_items", &state.queued_items)
            .field("queued_bytes", &state.queued_bytes)
            .field(
                "worker_handle",
                &self.handle.lock().is_ok_and(|value| value.is_some()),
            )
            .finish()
    }
}

impl JtlSinkOwner {
    /// Starts one run-owned streaming JTL writer over an already-opened
    /// writer.  This constructor never resolves or reopens a path.
    pub fn new<L>(
        writer: Box<dyn Write + Send>,
        configuration: SampleSaveConfiguration,
        limits: L,
    ) -> Result<Self, JtlSinkError>
    where
        L: Into<JtlSinkLimits>,
    {
        Self::new_with_factory(writer, configuration, limits.into(), production_factory())
    }

    /// Returns the cloneable submission-only view.
    #[must_use]
    pub fn submitter(&self) -> JtlSinkSubmitter {
        JtlSinkSubmitter {
            shared: Arc::clone(&self.shared),
            limits: self.limits,
        }
    }

    /// Finishes in FIFO order and joins the exact writer thread.
    ///
    /// The operation is idempotent.  It is intentionally synchronous at this
    /// owner boundary; asynchronous callers use the submitter's `finish`
    /// future and invoke this method at the run boundary.
    pub fn finalize(&self) -> Result<JtlSinkFinalizeReport, JtlSinkError> {
        if is_writer_thread() {
            return Err(JtlSinkError::FinalizeFromWorker);
        }
        let _gate = lock_or_recover(&self.finalize_gate, &self.shared.invariant);
        if let Some(result) = lock_or_recover(&self.finalization, &self.shared.invariant).as_ref() {
            return result.clone();
        }

        let completion = self.shared.enqueue_finish().map_err(map_sink_error)?;
        let finish_result = completion.wait_blocking();
        let join_result = self.join_handle();
        let result = match (finish_result, join_result) {
            (Ok(()), Ok(())) => {
                let state = self.shared.lock_state();
                if state.worker_panicked {
                    Err(JtlSinkError::WorkerPanic)
                } else if self.shared.invariant.load(Ordering::Acquire) {
                    Err(JtlSinkError::InternalInvariant)
                } else {
                    Ok(JtlSinkFinalizeReport {
                        finished: true,
                        cancelled: state.phase == Phase::Cancelled,
                        worker_panicked: false,
                    })
                }
            }
            (Err(error), Ok(())) => Err(JtlSinkError::Sink(error)),
            (_, Err(error)) => Err(error),
        };
        *lock_or_recover(&self.finalization, &self.shared.invariant) = Some(result.clone());
        result
    }

    /// Requests cancellation and joins without manufacturing a finish or
    /// publication success.  This is used by `Drop` and is also useful to a
    /// caller that deliberately aborts a run.
    pub fn cancel_and_join(&self) -> Result<(), JtlSinkError> {
        if is_writer_thread() {
            return Err(JtlSinkError::FinalizeFromWorker);
        }
        self.shared.cancel().map_err(map_sink_error)?;
        let result = self.join_handle();
        if result.is_ok() && self.shared.invariant.load(Ordering::Acquire) {
            Err(JtlSinkError::InternalInvariant)
        } else {
            result
        }
    }

    fn new_with_factory(
        writer: Box<dyn Write + Send>,
        configuration: SampleSaveConfiguration,
        limits: JtlSinkLimits,
        factory: EncoderFactory,
    ) -> Result<Self, JtlSinkError> {
        limits.validate()?;
        configuration
            .validate()
            .map_err(|error| JtlSinkError::Sink(map_jtl_error("configuration", error)))?;

        let shared = Arc::new(Shared::new());
        let worker_shared = Arc::clone(&shared);
        let panic_shared = Arc::clone(&shared);
        let worker_configuration = configuration;
        let handle = thread::Builder::new()
            .name("jmeter-rs-jtl-sink".to_owned())
            .spawn(move || {
                set_writer_thread(true);
                let result = panic::catch_unwind(AssertUnwindSafe(|| {
                    worker_main(worker_shared, writer, worker_configuration, factory)
                }));
                if result.is_err() {
                    // Never retain or format an arbitrary panic payload.
                    // `worker_main` normally handles this path itself; this
                    // outer catch protects the exact thread boundary too.
                    // The shared failure path also wakes every pending future.
                    // The worker has no process or signal side effects.
                    //
                    panic_shared.record_worker_panic();
                    panic_shared.complete_worker();
                }
                set_writer_thread(false);
            })
            .map_err(|_| JtlSinkError::WorkerStart)?;

        Ok(Self {
            shared,
            limits,
            handle: Mutex::new(Some(handle)),
            finalize_gate: Mutex::new(()),
            finalization: Mutex::new(None),
            _owner_thread: PhantomData,
        })
    }

    fn join_handle(&self) -> Result<(), JtlSinkError> {
        let handle = lock_or_recover(&self.handle, &self.shared.invariant).take();
        let Some(handle) = handle else {
            return Ok(());
        };
        if handle.join().is_err() {
            self.shared.record_worker_panic();
            return Err(JtlSinkError::WorkerJoin);
        }
        if self.shared.lock_state().worker_panicked {
            return Err(JtlSinkError::WorkerPanic);
        }
        Ok(())
    }
}

impl Drop for JtlSinkOwner {
    fn drop(&mut self) {
        // Drop cannot report an error.  It still stops admission, wakes all
        // queued completions, and reaps the exact owned thread.  There is no
        // process discovery, signal, or shell cleanup here.
        let _ = self.shared.cancel();
        if is_writer_thread() {
            // The owner is !Send, so this is unreachable in normal use. Keep
            // the guard explicit so a test seam or future unsafe integration
            // cannot make a writer thread join itself.
            return;
        }
        let handle = lock_or_recover(&self.handle, &self.shared.invariant).take();
        if let Some(handle) = handle
            && handle.join().is_err()
        {
            self.shared.record_worker_panic();
        }
    }
}

/// Application-owned typed JTL sink adapter.
///
/// This is only the executor-facing submission view.  [`JtlSinkOwner`] stays
/// with the application run transaction and retains the exact writer join
/// handle.  The adapter contains no path, payload, secret, or join state. The
/// runtime supplies the run-owned provider-wait registrar and the immutable
/// [`ResultOperationLease`] authority to each operation.
#[derive(Clone)]
pub struct TypedJtlSinkAdapter {
    submitter: JtlSinkSubmitter,
    sink_id: QualifiedSinkId,
}

impl fmt::Debug for TypedJtlSinkAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TypedJtlSinkAdapter")
            .field("submitter", &self.submitter)
            .field("sink_id", &self.sink_id)
            .finish()
    }
}

impl TypedJtlSinkAdapter {
    /// Creates one typed adapter over a run-owned writer submission handle.
    #[must_use]
    pub fn new(submitter: JtlSinkSubmitter, sink_id: QualifiedSinkId) -> Self {
        Self { submitter, sink_id }
    }

    fn operation_error(error: SinkError, kind: TypedJtlOperationKind) -> TypedSinkError {
        classify_sink_error(error, kind, false)
    }

    fn check_lease_scope(&self, lease_sink_id: QualifiedSinkId) -> Result<(), TypedSinkError> {
        if lease_sink_id != self.sink_id {
            return Err(TypedSinkError::permanent("app.jtl-sink.lease-scope"));
        }
        Ok(())
    }

    fn check_operation(
        &self,
        operation: &ResultOperationLease,
        expected: ResultOperationKind,
        sink_id: QualifiedSinkId,
    ) -> Result<(), TypedSinkError> {
        if operation.kind() != expected {
            return Err(TypedSinkError::permanent("app.jtl-sink.operation-kind"));
        }
        let expected_scope = ResultOperationScope::Sink {
            run: sink_id.run_id(),
            sink: sink_id,
        };
        if operation.scope() != expected_scope {
            return Err(TypedSinkError::permanent("app.jtl-sink.operation-scope"));
        }
        operation.check().map_err(TypedSinkError::Budget)
    }

    fn completion_wait<'a>(
        &'a self,
        completion: Arc<Completion>,
        operation: &'a ResultOperationLease,
        wait_registrar: &'a dyn ResultWaitRegistrar,
        kind: TypedJtlOperationKind,
        submitted: bool,
    ) -> CompletionWait<'a> {
        CompletionWait {
            completion,
            operation,
            wait_registrar,
            registration: None,
            kind,
            submitted,
        }
    }
}

impl TypedSinkAdapter for TypedJtlSinkAdapter {
    fn start<'a>(
        &'a self,
        operation: &'a ResultOperationLease,
        wait_registrar: &'a dyn ResultWaitRegistrar,
    ) -> TypedSinkFuture<'a, ()> {
        if let Err(error) =
            self.check_operation(operation, ResultOperationKind::Start, self.sink_id)
        {
            return Box::pin(std::future::ready(Err(error)));
        }
        let completion = self.submitter.shared.readiness();
        Box::pin(TypedJtlUnitFuture {
            wait: self.completion_wait(
                completion,
                operation,
                wait_registrar,
                TypedJtlOperationKind::Start,
                false,
            ),
        })
    }

    fn process<'a>(
        &'a self,
        lease: &'a DeliveryLease,
        operation: &'a ResultOperationLease,
        wait_registrar: &'a dyn ResultWaitRegistrar,
    ) -> TypedSinkFuture<'a, DurabilityAck> {
        if lease.durability_boundary() != DurabilityBoundary::FormatWritten {
            return Box::pin(std::future::ready(Err(TypedSinkError::permanent(
                "app.jtl-sink.durability-boundary",
            ))));
        }
        let lease_sink_id = lease.key().sink_id;
        if let Err(error) = self.check_lease_scope(lease_sink_id) {
            return Box::pin(std::future::ready(Err(error)));
        }
        if let Err(error) =
            self.check_operation(operation, ResultOperationKind::Process, lease_sink_id)
        {
            return Box::pin(std::future::ready(Err(error)));
        }
        let completion = match self
            .submitter
            .write_sample_event(lease.envelope().event(), lease.envelope().byte_size())
        {
            Ok(completion) => completion,
            Err(error) => {
                return Box::pin(std::future::ready(Err(Self::operation_error(
                    error,
                    TypedJtlOperationKind::Process,
                ))));
            }
        };
        Box::pin(TypedJtlProcessFuture {
            wait: self.completion_wait(
                completion,
                operation,
                wait_registrar,
                TypedJtlOperationKind::Process,
                true,
            ),
            lease,
        })
    }

    fn flush<'a>(
        &'a self,
        operation: &'a ResultOperationLease,
        wait_registrar: &'a dyn ResultWaitRegistrar,
    ) -> TypedSinkFuture<'a, ()> {
        if let Err(error) =
            self.check_operation(operation, ResultOperationKind::Flush, self.sink_id)
        {
            return Box::pin(std::future::ready(Err(error)));
        }
        let completion = match self.submitter.enqueue_flush_completion() {
            Ok(completion) => completion,
            Err(error) => {
                return Box::pin(std::future::ready(Err(Self::operation_error(
                    error,
                    TypedJtlOperationKind::Flush,
                ))));
            }
        };
        Box::pin(TypedJtlUnitFuture {
            wait: self.completion_wait(
                completion,
                operation,
                wait_registrar,
                TypedJtlOperationKind::Flush,
                true,
            ),
        })
    }

    fn finish<'a>(
        &'a self,
        operation: &'a ResultOperationLease,
        wait_registrar: &'a dyn ResultWaitRegistrar,
    ) -> TypedSinkFuture<'a, ()> {
        if let Err(error) =
            self.check_operation(operation, ResultOperationKind::Finish, self.sink_id)
        {
            return Box::pin(std::future::ready(Err(error)));
        }
        let completion = match self.submitter.enqueue_finish_completion() {
            Ok(completion) => completion,
            Err(error) => {
                return Box::pin(std::future::ready(Err(Self::operation_error(
                    error,
                    TypedJtlOperationKind::Finish,
                ))));
            }
        };
        Box::pin(TypedJtlUnitFuture {
            wait: self.completion_wait(
                completion,
                operation,
                wait_registrar,
                TypedJtlOperationKind::Finish,
                true,
            ),
        })
    }

    fn cancel(&self) -> Result<(), TypedSinkError> {
        self.submitter
            .cancel()
            .map_err(|error| Self::operation_error(error, TypedJtlOperationKind::Cancel))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TypedJtlOperationKind {
    Start,
    Process,
    Flush,
    Finish,
    Cancel,
}

/// The shared state held by every typed completion future.
///
/// Its poll implementation deliberately has no I/O, blocking wait, join,
/// sleep, self-wake, or grace timeout. The worker owns command execution and
/// wakes the stored completion waker; the run-owned result wait registrar owns
/// the one Provider registration for the operation lease deadline.
struct CompletionWait<'a> {
    completion: Arc<Completion>,
    operation: &'a ResultOperationLease,
    wait_registrar: &'a dyn ResultWaitRegistrar,
    registration: Option<ResultWaitRegistration>,
    kind: TypedJtlOperationKind,
    submitted: bool,
}

impl CompletionWait<'_> {
    fn retire_registration(&mut self) {
        // Retire the exact paired runtime WaitRegistration before returning.
        // Drop remains the safety net for a future that is abandoned.
        if let Some(registration) = self.registration.take() {
            let _ = registration.retire();
        }
    }

    fn completion_result(&self, context: &Context<'_>) -> Option<Result<(), SinkError>> {
        self.completion.poll_result(context)
    }

    fn poll(&mut self, context: &mut Context<'_>) -> Poll<Result<(), TypedSinkError>> {
        // 1. Completion wins every race and avoids creating a wait for work
        // that is already done.
        if let Some(result) = self.completion_result(context) {
            self.retire_registration();
            return Poll::Ready(classify_completion_result(
                result,
                self.kind,
                self.submitted,
            ));
        }

        // 2. Check the shared cancellation/operation budget before retaining
        // a waker or admitting a provider wait.
        if let Err(error) = self.operation.check() {
            self.retire_registration();
            return Poll::Ready(Err(TypedSinkError::Budget(error)));
        }

        // 3. Subscribe to the run-owned cancellation source before
        // registering the provider wait. It retains only this future's waker.
        self.operation.register_waker(context.waker());

        // 4. Establish exactly one Provider-owned RAII registration for this
        // operation lease.  A missing registration is a typed capability
        // failure; a self-wake is never used as a substitute.
        if self.registration.is_none() {
            match self.operation.register_wait(
                self.wait_registrar,
                WaitOwnerClass::Provider,
                context.waker(),
            ) {
                Ok(registration) => self.registration = Some(registration),
                Err(error) => {
                    self.retire_registration();
                    return Poll::Ready(Err(TypedSinkError::Budget(error)));
                }
            }
        }

        // 5. Close the completion-versus-registration race and recheck
        // cancellation/deadline after the registration is live.
        if let Some(result) = self.completion_result(context) {
            self.retire_registration();
            return Poll::Ready(classify_completion_result(
                result,
                self.kind,
                self.submitted,
            ));
        }
        if let Err(error) = self.operation.check() {
            self.retire_registration();
            return Poll::Ready(Err(TypedSinkError::Budget(error)));
        }

        // 6. The exact registration remains live for the only Pending path.
        Poll::Pending
    }
}

impl Future for CompletionWait<'_> {
    type Output = Result<(), TypedSinkError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().poll(context)
    }
}

struct TypedJtlUnitFuture<'a> {
    wait: CompletionWait<'a>,
}

impl Future for TypedJtlUnitFuture<'_> {
    type Output = Result<(), TypedSinkError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().wait.poll(context)
    }
}

struct TypedJtlProcessFuture<'a> {
    wait: CompletionWait<'a>,
    lease: &'a DeliveryLease,
}

impl Future for TypedJtlProcessFuture<'_> {
    type Output = Result<DurabilityAck, TypedSinkError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match this.wait.poll(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(
                this.lease
                    .acknowledge(DurabilityBoundary::FormatWritten)
                    .map_err(|_| TypedSinkError::permanent("app.jtl-sink.acknowledgement-binding")),
            ),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        }
    }
}

fn classify_sink_error(
    error: SinkError,
    kind: TypedJtlOperationKind,
    submitted: bool,
) -> TypedSinkError {
    match error {
        SinkError::Cancelled => TypedSinkError::Cancelled,
        SinkError::ResourceLimit(message) => TypedSinkError::retryable(message),
        SinkError::Unsupported(message) => TypedSinkError::permanent(message),
        SinkError::Failed(_) | SinkError::Combined { .. } => {
            if submitted
                && matches!(
                    kind,
                    TypedJtlOperationKind::Process
                        | TypedJtlOperationKind::Flush
                        | TypedJtlOperationKind::Finish
                )
            {
                TypedSinkError::unknown_outcome(error.to_string())
            } else {
                TypedSinkError::permanent(error.to_string())
            }
        }
    }
}

fn classify_completion_result(
    result: Result<(), SinkError>,
    kind: TypedJtlOperationKind,
    submitted: bool,
) -> Result<(), TypedSinkError> {
    result.map_err(|error| classify_sink_error(error, kind, submitted))
}

/// An encoder implementation used only on the writer thread.
trait SinkEncoder {
    fn write_event(&mut self, event: &SampleEvent) -> Result<(), SinkError>;
    fn flush(&mut self) -> Result<(), SinkError>;
    fn finish(&mut self) -> Result<(), SinkError>;
}

type EncoderFactory = Arc<
    dyn Fn(
            Box<dyn Write + Send>,
            SampleSaveConfiguration,
        ) -> Result<Box<dyn SinkEncoder>, SinkError>
        + Send
        + Sync,
>;

fn production_factory() -> EncoderFactory {
    Arc::new(|writer, configuration| {
        let writer = SharedWriter::new(writer);
        let encoder = JtlEncoder::streaming(writer.clone(), configuration)
            .map_err(|error| map_jtl_error("create", error))?;
        Ok(Box::new(ProductionEncoder {
            encoder: Some(encoder),
            writer,
            finished: false,
        }))
    })
}

/// The current results API keeps the underlying writer inside the generic
/// encoder. A small shared writer lets this application issue a FIFO flush
/// command without taking ownership away from the encoder. `finish` remains
/// the only operation that consumes the encoder and writes the final CSV
/// header/XML root footer.
#[derive(Clone)]
struct SharedWriter {
    inner: Arc<Mutex<Box<dyn Write + Send>>>,
}

impl SharedWriter {
    fn new(writer: Box<dyn Write + Send>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(writer)),
        }
    }

    fn flush_shared(&self) -> Result<(), SinkError> {
        let mut writer = self
            .inner
            .lock()
            .map_err(|_| SinkError::failed("jtl writer lock poisoned"))?;
        writer
            .flush()
            .map_err(|_| SinkError::failed("jtl writer flush failed"))
    }
}

impl Write for SharedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut writer = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("jtl writer lock poisoned"))?;
        writer.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut writer = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("jtl writer lock poisoned"))?;
        writer.flush()
    }
}

struct ProductionEncoder {
    encoder: Option<JtlEncoder<'static, SharedWriter>>,
    writer: SharedWriter,
    finished: bool,
}

impl SinkEncoder for ProductionEncoder {
    fn write_event(&mut self, event: &SampleEvent) -> Result<(), SinkError> {
        let Some(encoder) = self.encoder.as_mut() else {
            return Err(SinkError::failed("jtl encoder is finished"));
        };
        encoder
            .write_event(event)
            .map_err(|error| map_jtl_error("write", error))
    }

    fn flush(&mut self) -> Result<(), SinkError> {
        if self.finished {
            return Ok(());
        }
        self.writer.flush_shared()
    }

    fn finish(&mut self) -> Result<(), SinkError> {
        if self.finished {
            return Ok(());
        }
        let Some(encoder) = self.encoder.take() else {
            return Err(SinkError::failed("jtl encoder finish state"));
        };
        encoder
            .finish()
            .map_err(|error| map_jtl_error("finish", error))?;
        self.finished = true;
        Ok(())
    }
}

fn map_jtl_error(operation: &'static str, error: JtlError) -> SinkError {
    // JtlError's stable code is intentionally the only diagnostic that crosses
    // this boundary; writer paths, OS text, and payload values are redacted.
    SinkError::failed(format!("jtl.{operation}: {}", error.stable_code()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Open,
    Finishing,
    Finished,
    Cancelled,
    Failed,
}

enum Command {
    Write {
        envelope: Arc<ResultEnvelope>,
        completion: Arc<Completion>,
        // The reservation owns the queue permit and releases it exactly when
        // the command is dropped, including cancellation and writer failure.
        _reservation: Reservation,
    },
    TypedWrite {
        event: Arc<SampleEvent>,
        completion: Arc<Completion>,
        // The reservation owns the queue permit and releases it exactly when
        // the command is dropped, including cancellation and writer failure.
        _reservation: Reservation,
    },
    Flush {
        completion: Arc<Completion>,
    },
    Finish {
        completion: Arc<Completion>,
    },
}

impl Command {
    fn completion(&self) -> &Arc<Completion> {
        match self {
            Self::Write { completion, .. }
            | Self::TypedWrite { completion, .. }
            | Self::Flush { completion }
            | Self::Finish { completion } => completion,
        }
    }

    fn is_finish(&self) -> bool {
        matches!(self, Self::Finish { .. })
    }

    fn is_write(&self) -> bool {
        matches!(self, Self::Write { .. } | Self::TypedWrite { .. })
    }
}

struct State {
    phase: Phase,
    queue: VecDeque<Command>,
    /// Completion currently owned by the writer thread. Cancellation marks
    /// this completion as cancelled even when an encoder call is blocked;
    /// the worker still must return and be joined before owner cleanup ends.
    active_completion: Option<Arc<Completion>>,
    queued_items: usize,
    queued_bytes: usize,
    finish_completion: Option<Arc<Completion>>,
    failure: Option<SinkError>,
    worker_done: bool,
    worker_panicked: bool,
}

impl Default for State {
    fn default() -> Self {
        Self {
            phase: Phase::Open,
            queue: VecDeque::new(),
            active_completion: None,
            queued_items: 0,
            queued_bytes: 0,
            finish_completion: None,
            failure: None,
            worker_done: false,
            worker_panicked: false,
        }
    }
}

struct Shared {
    state: Mutex<State>,
    condition: Condvar,
    invariant: Arc<AtomicBool>,
    ready_completion: Arc<Completion>,
}

impl Shared {
    fn new() -> Self {
        let invariant = Arc::new(AtomicBool::new(false));
        Self {
            state: Mutex::new(State::default()),
            condition: Condvar::new(),
            ready_completion: Arc::new(Completion::new(Arc::clone(&invariant))),
            invariant,
        }
    }

    fn readiness(&self) -> Arc<Completion> {
        Arc::clone(&self.ready_completion)
    }

    fn lock_state(&self) -> MutexGuard<'_, State> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                self.invariant.store(true, Ordering::Release);
                poisoned.into_inner()
            }
        }
    }

    fn enqueue_write(
        self: &Arc<Self>,
        envelope: &ResultEnvelope,
        limits: JtlSinkLimits,
    ) -> Result<Arc<Completion>, SinkError> {
        let bytes = envelope.byte_size();
        if bytes == 0 {
            return Err(SinkError::resource_limit("jtl envelope has zero size"));
        }
        // Clone the immutable Arc-backed event before the queue lock.  This
        // is the only result ownership operation performed by submission.
        let envelope = Arc::new(envelope.clone());
        let completion = Arc::new(Completion::new(Arc::clone(&self.invariant)));
        let mut state = self.lock_state();
        match state.phase {
            Phase::Open => {}
            Phase::Cancelled => return Err(SinkError::Cancelled),
            Phase::Failed => return Err(state_failure(&state)),
            Phase::Finishing | Phase::Finished => {
                return Err(SinkError::failed("jtl sink admission is closed"));
            }
        }
        if state.queued_items >= limits.max_items {
            return Err(SinkError::resource_limit("jtl sink queue item capacity"));
        }
        let Some(next_bytes) = state.queued_bytes.checked_add(bytes) else {
            return Err(SinkError::resource_limit("jtl sink queue byte counter"));
        };
        if next_bytes > limits.max_bytes {
            return Err(SinkError::resource_limit("jtl sink queue byte capacity"));
        }
        state.queued_items += 1;
        state.queued_bytes = next_bytes;
        state.queue.push_back(Command::Write {
            envelope,
            completion: Arc::clone(&completion),
            _reservation: Reservation::new(Arc::clone(self), bytes),
        });
        drop(state);
        self.condition.notify_one();
        Ok(completion)
    }

    fn enqueue_sample_event(
        self: &Arc<Self>,
        event: &SampleEvent,
        bytes: usize,
        limits: JtlSinkLimits,
    ) -> Result<Arc<Completion>, SinkError> {
        if bytes == 0 {
            return Err(SinkError::resource_limit("jtl event has zero size"));
        }
        // The typed adapter receives the immutable event from the original
        // DeliveryLease.  It may retain that snapshot for the bounded FIFO
        // command, but it never rebuilds a second result envelope or copies
        // identity/path metadata into an application-owned substitute.
        let event = Arc::new(event.clone());
        let completion = Arc::new(Completion::new(Arc::clone(&self.invariant)));
        let mut state = self.lock_state();
        match state.phase {
            Phase::Open => {}
            Phase::Cancelled => return Err(SinkError::Cancelled),
            Phase::Failed => return Err(state_failure(&state)),
            Phase::Finishing | Phase::Finished => {
                return Err(SinkError::failed("jtl sink admission is closed"));
            }
        }
        if state.queued_items >= limits.max_items {
            return Err(SinkError::resource_limit("jtl sink queue item capacity"));
        }
        let Some(next_bytes) = state.queued_bytes.checked_add(bytes) else {
            return Err(SinkError::resource_limit("jtl sink queue byte counter"));
        };
        if next_bytes > limits.max_bytes {
            return Err(SinkError::resource_limit("jtl sink queue byte capacity"));
        }
        state.queued_items += 1;
        state.queued_bytes = next_bytes;
        state.queue.push_back(Command::TypedWrite {
            event,
            completion: Arc::clone(&completion),
            _reservation: Reservation::new(Arc::clone(self), bytes),
        });
        drop(state);
        self.condition.notify_one();
        Ok(completion)
    }

    fn enqueue_flush(self: &Arc<Self>) -> Result<Arc<Completion>, SinkError> {
        let completion = Arc::new(Completion::new(Arc::clone(&self.invariant)));
        let mut state = self.lock_state();
        match state.phase {
            Phase::Open => {
                state.queue.push_back(Command::Flush {
                    completion: Arc::clone(&completion),
                });
            }
            Phase::Cancelled => return Err(SinkError::Cancelled),
            Phase::Failed => return Err(state_failure(&state)),
            Phase::Finishing | Phase::Finished => {
                return Err(SinkError::failed("jtl sink flush is closed"));
            }
        }
        drop(state);
        self.condition.notify_one();
        Ok(completion)
    }

    fn enqueue_finish(self: &Arc<Self>) -> Result<Arc<Completion>, SinkError> {
        let mut state = self.lock_state();
        if let Some(completion) = &state.finish_completion {
            return Ok(Arc::clone(completion));
        }
        let completion = Arc::new(Completion::new(Arc::clone(&self.invariant)));
        state.finish_completion = Some(Arc::clone(&completion));
        match state.phase {
            Phase::Open => {
                state.phase = Phase::Finishing;
                state.queue.push_back(Command::Finish {
                    completion: Arc::clone(&completion),
                });
                drop(state);
                self.condition.notify_one();
                Ok(completion)
            }
            Phase::Cancelled => {
                completion.complete(Err(SinkError::Cancelled));
                Ok(completion)
            }
            Phase::Failed => {
                completion.complete(Err(state_failure(&state)));
                Ok(completion)
            }
            Phase::Finishing | Phase::Finished => Ok(completion),
        }
    }

    fn cancel(self: &Arc<Self>) -> Result<(), SinkError> {
        let (drained, active) = {
            let mut state = self.lock_state();
            if matches!(
                state.phase,
                Phase::Cancelled | Phase::Finished | Phase::Failed
            ) {
                return Ok(());
            }
            state.phase = Phase::Cancelled;
            (
                state.queue.drain(..).collect::<Vec<_>>(),
                state.active_completion.take(),
            )
        };
        for command in drained {
            command.completion().complete(Err(SinkError::Cancelled));
            // Dropping a write command releases its permit after its
            // completion has been made observable.
        }
        if let Some(completion) = active {
            completion.complete(Err(SinkError::Cancelled));
        }
        self.ready_completion.complete(Err(SinkError::Cancelled));
        self.condition.notify_all();
        Ok(())
    }

    fn next_command(self: &Arc<Self>) -> Option<Command> {
        let mut state = self.lock_state();
        loop {
            if let Some(command) = state.queue.pop_front() {
                state.active_completion = Some(Arc::clone(command.completion()));
                return Some(command);
            }
            if matches!(
                state.phase,
                Phase::Cancelled | Phase::Failed | Phase::Finished
            ) {
                state.worker_done = true;
                self.condition.notify_all();
                return None;
            }
            state = match self.condition.wait(state) {
                Ok(state) => state,
                Err(poisoned) => {
                    self.invariant.store(true, Ordering::Release);
                    poisoned.into_inner()
                }
            };
        }
    }

    fn fail_and_drain(self: &Arc<Self>, error: SinkError) {
        let drained = {
            let mut state = self.lock_state();
            state.phase = Phase::Failed;
            if state.failure.is_none() {
                state.failure = Some(error.clone());
            }
            state.queue.drain(..).collect::<Vec<_>>()
        };
        for command in drained {
            command.completion().complete(Err(error.clone()));
        }
        self.ready_completion.complete(Err(error));
        self.condition.notify_all();
    }

    fn complete_worker(self: &Arc<Self>) {
        let mut state = self.lock_state();
        state.active_completion = None;
        state.worker_done = true;
        self.condition.notify_all();
    }

    fn clear_active(self: &Arc<Self>, completion: &Arc<Completion>) {
        let mut state = self.lock_state();
        if state
            .active_completion
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, completion))
        {
            state.active_completion = None;
        }
    }

    fn record_worker_panic(self: &Arc<Self>) {
        self.invariant.store(true, Ordering::Release);
        let drained = {
            let mut state = self.lock_state();
            state.worker_panicked = true;
            state.phase = Phase::Failed;
            let error = SinkError::failed("jtl sink worker panic");
            state.failure = Some(error.clone());
            state.queue.drain(..).collect::<Vec<_>>()
        };
        for command in drained {
            command
                .completion()
                .complete(Err(SinkError::failed("jtl sink worker panic")));
        }
        self.ready_completion
            .complete(Err(SinkError::failed("jtl sink worker panic")));
        self.condition.notify_all();
    }
}

fn state_failure(state: &State) -> SinkError {
    state
        .failure
        .clone()
        .unwrap_or_else(|| SinkError::failed("jtl sink failed without diagnostic"))
}

struct Reservation {
    shared: Arc<Shared>,
    bytes: usize,
    released: AtomicBool,
}

impl Reservation {
    fn new(shared: Arc<Shared>, bytes: usize) -> Self {
        Self {
            shared,
            bytes,
            released: AtomicBool::new(false),
        }
    }

    fn release(&self) {
        if self.released.swap(true, Ordering::AcqRel) {
            return;
        }
        let mut state = self.shared.lock_state();
        if state.queued_items == 0 || state.queued_bytes < self.bytes {
            self.shared.invariant.store(true, Ordering::Release);
            return;
        }
        state.queued_items -= 1;
        state.queued_bytes -= self.bytes;
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.release();
    }
}

struct Completion {
    state: Mutex<CompletionState>,
    condition: Condvar,
    invariant: Arc<AtomicBool>,
}

struct CompletionState {
    result: Option<Result<(), SinkError>>,
    wakers: Vec<Waker>,
}

impl Completion {
    fn new(invariant: Arc<AtomicBool>) -> Self {
        Self {
            state: Mutex::new(CompletionState {
                result: None,
                wakers: Vec::new(),
            }),
            condition: Condvar::new(),
            invariant,
        }
    }

    fn complete(&self, result: Result<(), SinkError>) {
        let wakers = {
            let mut state = match self.state.lock() {
                Ok(state) => state,
                Err(poisoned) => {
                    self.invariant.store(true, Ordering::Release);
                    poisoned.into_inner()
                }
            };
            if state.result.is_some() {
                return;
            }
            state.result = Some(result);
            std::mem::take(&mut state.wakers)
        };
        self.condition.notify_all();
        for waker in wakers {
            if panic::catch_unwind(AssertUnwindSafe(|| waker.wake())).is_err() {
                self.invariant.store(true, Ordering::Release);
            }
        }
    }

    fn poll_result(&self, context: &Context<'_>) -> Option<Result<(), SinkError>> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                self.invariant.store(true, Ordering::Release);
                poisoned.into_inner()
            }
        };
        if let Some(result) = &state.result {
            return Some(result.clone());
        }
        if !state
            .wakers
            .iter()
            .any(|waker| waker.will_wake(context.waker()))
        {
            state.wakers.push(context.waker().clone());
        }
        None
    }

    fn wait_blocking(&self) -> Result<(), SinkError> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                self.invariant.store(true, Ordering::Release);
                poisoned.into_inner()
            }
        };
        loop {
            if let Some(result) = &state.result {
                return result.clone();
            }
            state = match self.condition.wait(state) {
                Ok(state) => state,
                Err(poisoned) => {
                    self.invariant.store(true, Ordering::Release);
                    poisoned.into_inner()
                }
            };
        }
    }
}

struct SinkCompletionFuture {
    completion: Arc<Completion>,
    consumed: bool,
}

impl SinkCompletionFuture {
    fn new(completion: Arc<Completion>) -> Self {
        Self {
            completion,
            consumed: false,
        }
    }
}

impl Future for SinkCompletionFuture {
    type Output = Result<(), SinkError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.consumed {
            return Poll::Ready(Err(SinkError::failed(
                "jtl sink future polled after completion",
            )));
        }
        match this.completion.poll_result(context) {
            Some(result) => {
                this.consumed = true;
                Poll::Ready(result)
            }
            None => Poll::Pending,
        }
    }
}

fn worker_main(
    shared: Arc<Shared>,
    writer: Box<dyn Write + Send>,
    configuration: SampleSaveConfiguration,
    factory: EncoderFactory,
) {
    let encoder = match panic::catch_unwind(AssertUnwindSafe(|| factory(writer, configuration))) {
        Ok(Ok(encoder)) => {
            shared.ready_completion.complete(Ok(()));
            encoder
        }
        Ok(Err(error)) => {
            shared.ready_completion.complete(Err(error.clone()));
            shared.fail_and_drain(error);
            shared.complete_worker();
            return;
        }
        Err(_) => {
            shared
                .ready_completion
                .complete(Err(SinkError::failed("jtl sink worker panic")));
            shared.record_worker_panic();
            shared.complete_worker();
            return;
        }
    };
    let mut encoder = encoder;
    while let Some(command) = shared.next_command() {
        let completion = Arc::clone(command.completion());
        let is_finish = command.is_finish();
        let is_write = command.is_write();
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            if shared.lock_state().phase == Phase::Cancelled {
                return Err(SinkError::Cancelled);
            }
            match &command {
                Command::Write { envelope, .. } => encoder.write_event(envelope.event()),
                Command::TypedWrite { event, .. } => encoder.write_event(event),
                Command::Flush { .. } => encoder.flush(),
                Command::Finish { .. } => encoder.finish(),
            }
        }));
        match result {
            Ok(Ok(())) => {
                let cancelled = shared.lock_state().phase == Phase::Cancelled;
                let outcome = if cancelled && (is_write || is_finish) {
                    Err(SinkError::Cancelled)
                } else {
                    Ok(())
                };
                completion.complete(outcome);
                shared.clear_active(&completion);
                drop(command);
                if is_finish {
                    let mut state = shared.lock_state();
                    if state.phase != Phase::Cancelled {
                        state.phase = Phase::Finished;
                    }
                    state.worker_done = true;
                    shared.condition.notify_all();
                    break;
                }
            }
            Ok(Err(error)) => {
                completion.complete(Err(error.clone()));
                shared.clear_active(&completion);
                drop(command);
                shared.fail_and_drain(error);
                break;
            }
            Err(_) => {
                completion.complete(Err(SinkError::failed("jtl sink worker panic")));
                shared.clear_active(&completion);
                drop(command);
                shared.record_worker_panic();
                break;
            }
        }
    }
    shared.complete_worker();
}

fn map_sink_error(error: SinkError) -> JtlSinkError {
    JtlSinkError::Sink(error)
}

thread_local! {
    static IS_WRITER_THREAD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn set_writer_thread(value: bool) {
    IS_WRITER_THREAD.with(|flag| flag.set(value));
}

fn is_writer_thread() -> bool {
    IS_WRITER_THREAD.with(std::cell::Cell::get)
}

fn lock_or_recover<'a, T>(mutex: &'a Mutex<T>, invariant: &AtomicBool) -> MutexGuard<'a, T> {
    match mutex.lock() {
        Ok(value) => value,
        Err(poisoned) => {
            invariant.store(true, Ordering::Release);
            poisoned.into_inner()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::mpsc::{self, Sender};
    use std::task::{Wake, Waker};
    use std::time::Duration;

    use jmeter_rs_model::NodeId;
    use jmeter_rs_results::{
        HostIdentity, RunIdentity, SampleResult, ThreadIdentity, VariableSnapshot,
    };
    use jmeter_rs_runtime::{
        CancellationToken, MonotonicInstant, PlanDomain, ResultClockError, ResultDeliveryBudget,
        ResultMonotonicClock, ResultOperationKind, ResultOperationScope, ResultOperationWindows,
        ResultOrigin, ResultWaitError, ResultWaitRegistrationHandle, ResultWaitSpec, RunGeneration,
        RunSequence, SampleIdentity, SinkPlanGeneration, TypedRouterIdentity, TypedRunId,
        UserIdentity, WorkerGeneration, WorkerId,
    };

    struct ManualResultClock {
        now_nanos: AtomicU64,
    }

    impl ManualResultClock {
        fn new() -> Self {
            Self {
                now_nanos: AtomicU64::new(0),
            }
        }

        fn set(&self, now: Duration) {
            let nanos = u64::try_from(now.as_nanos())
                .unwrap_or_else(|_| panic!("test clock duration must fit u64 nanos"));
            self.now_nanos.store(nanos, Ordering::Release);
        }
    }

    impl ResultMonotonicClock for ManualResultClock {
        fn now(&self) -> Result<MonotonicInstant, ResultClockError> {
            Ok(MonotonicInstant::from_duration(Duration::from_nanos(
                self.now_nanos.load(Ordering::Acquire),
            )))
        }
    }

    #[derive(Default)]
    struct WaitCounts {
        registrations: AtomicUsize,
        retirements: AtomicUsize,
    }

    struct ManualWaitRegistrar {
        counts: Arc<WaitCounts>,
    }

    struct ManualWaitHandle {
        counts: Arc<WaitCounts>,
        active: bool,
    }

    impl ResultWaitRegistrar for ManualWaitRegistrar {
        fn register(
            &self,
            spec: ResultWaitSpec,
        ) -> Result<Box<dyn ResultWaitRegistrationHandle>, ResultWaitError> {
            assert_eq!(spec.owner, WaitOwnerClass::Provider);
            assert_ne!(spec.operation.get(), 0);
            self.counts.registrations.fetch_add(1, Ordering::AcqRel);
            Ok(Box::new(ManualWaitHandle {
                counts: Arc::clone(&self.counts),
                active: true,
            }))
        }
    }

    impl ResultWaitRegistrationHandle for ManualWaitHandle {
        fn retire(&mut self) -> Result<(), ResultWaitError> {
            if !self.active {
                return Err(ResultWaitError::AlreadyRetired);
            }
            self.active = false;
            self.counts.retirements.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
    }

    fn result_operation_fixture() -> (
        ResultOperationLease,
        Arc<ManualResultClock>,
        Arc<CancellationToken>,
    ) {
        let clock = Arc::new(ManualResultClock::new());
        let cancellation = Arc::new(CancellationToken::new());
        let budget = ResultDeliveryBudget::from_parts(
            ResultOperationScope::sink_set(
                TypedRunId::from_u128(1).unwrap_or_else(|error| panic!("test run: {error}")),
                SinkPlanGeneration::new(1)
                    .unwrap_or_else(|error| panic!("test sink plan: {error}")),
            ),
            clock.clone(),
            cancellation.clone(),
            ResultOperationWindows::uniform(Duration::from_secs(10), Duration::from_secs(10)),
            2,
            None,
        )
        .unwrap_or_else(|error| panic!("test result budget: {error}"));
        let operation = budget
            .begin_operation(ResultOperationKind::Process)
            .unwrap_or_else(|error| panic!("test result operation: {error}"));
        (operation, clock, cancellation)
    }

    fn qualified_sink_fixture(node: u64) -> QualifiedSinkId {
        let run_text = RunIdentity::new("run");
        let run = TypedRunId::from_run_identity(&run_text)
            .unwrap_or_else(|error| panic!("test run: {error}"));
        let generation =
            SinkPlanGeneration::new(1).unwrap_or_else(|error| panic!("test sink plan: {error}"));
        let domain = PlanDomain::from_canonical_plan_and_profile_text(
            b"typed-jtl-adapter",
            b"local",
            "test-profile",
            "1",
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("test plan domain: {error}"));
        let identity = TypedRouterIdentity::new(
            domain,
            run,
            RunGeneration::new(1).unwrap_or_else(|error| panic!("test run generation: {error}")),
            WorkerId::new(1).unwrap_or_else(|error| panic!("test worker: {error}")),
            WorkerGeneration::new(1)
                .unwrap_or_else(|error| panic!("test worker generation: {error}")),
        );
        let collector = identity
            .node(NodeId::new(node))
            .unwrap_or_else(|error| panic!("test collector: {error}"));
        QualifiedSinkId::from_parts(run, generation, collector)
    }

    fn completion_for_test() -> Arc<Completion> {
        Arc::new(Completion::new(Arc::new(AtomicBool::new(false))))
    }

    #[derive(Default)]
    struct RecordingWriter {
        bytes: Arc<Mutex<Vec<u8>>>,
        flushes: Arc<AtomicUsize>,
    }

    impl Write for RecordingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes
                .lock()
                .map_err(|_| io::Error::other("recording writer poisoned"))?
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
    }

    struct CountingWriter {
        bytes: Arc<AtomicUsize>,
        flushes: Arc<AtomicUsize>,
    }

    impl Write for CountingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes.fetch_add(bytes.len(), Ordering::AcqRel);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
    }

    struct FakeEncoder {
        labels: Arc<Mutex<Vec<String>>>,
        flushes: Arc<AtomicUsize>,
        finishes: Arc<AtomicUsize>,
        writes: Arc<AtomicUsize>,
        fail_write: bool,
        fail_flush: bool,
        fail_finish: bool,
        panic_write: bool,
        gate: Option<Arc<(Mutex<bool>, Condvar)>>,
    }

    impl SinkEncoder for FakeEncoder {
        fn write_event(&mut self, event: &SampleEvent) -> Result<(), SinkError> {
            if let Some(gate) = &self.gate {
                let (lock, condition) = &**gate;
                let mut released = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                while !*released {
                    released = condition
                        .wait(released)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
            }
            if self.panic_write {
                panic!("test-only encoder panic payload must not escape");
            }
            if self.fail_write {
                return Err(SinkError::failed("test.encoder.write"));
            }
            self.writes.fetch_add(1, Ordering::AcqRel);
            self.labels
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(event.result().label().to_owned());
            Ok(())
        }

        fn flush(&mut self) -> Result<(), SinkError> {
            if self.fail_flush {
                return Err(SinkError::failed("test.encoder.flush"));
            }
            self.flushes.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }

        fn finish(&mut self) -> Result<(), SinkError> {
            self.finishes.fetch_add(1, Ordering::AcqRel);
            if self.fail_finish {
                return Err(SinkError::failed("test.encoder.finish"));
            }
            Ok(())
        }
    }

    #[allow(
        deprecated,
        reason = "the module-local seam uses the legacy envelope until runtime exposes a small test constructor"
    )]
    fn envelope(label: &str, sequence: u64) -> ResultEnvelope {
        let result = SampleResult::new(label);
        let event = SampleEvent::new(
            result,
            RunIdentity::new("run"),
            ThreadIdentity::new("thread"),
            HostIdentity::new("host"),
            VariableSnapshot::new(),
        );
        ResultEnvelope::new(
            RunSequence::new(sequence),
            NodeId::new(1),
            vec![NodeId::new(1)],
            RunIdentity::new("run"),
            UserIdentity::new(1, NodeId::new(2), 1, 0),
            ThreadIdentity::new("thread"),
            SampleIdentity::new(sequence),
            ResultOrigin::Sampler {
                sampler_id: NodeId::new(1),
                parent: None,
            },
            event,
        )
        .unwrap_or_else(|_| panic!("test envelope must be valid"))
    }

    fn test_factory(
        labels: Arc<Mutex<Vec<String>>>,
        flushes: Arc<AtomicUsize>,
        finishes: Arc<AtomicUsize>,
        writes: Arc<AtomicUsize>,
        fail_write: bool,
        fail_flush: bool,
        fail_finish: bool,
        panic_write: bool,
        gate: Option<Arc<(Mutex<bool>, Condvar)>>,
    ) -> EncoderFactory {
        Arc::new(move |_writer, _configuration| {
            Ok(Box::new(FakeEncoder {
                labels: Arc::clone(&labels),
                flushes: Arc::clone(&flushes),
                finishes: Arc::clone(&finishes),
                writes: Arc::clone(&writes),
                fail_write,
                fail_flush,
                fail_finish,
                panic_write,
                gate: gate.clone(),
            }) as Box<dyn SinkEncoder>)
        })
    }

    fn owner_with_factory(limits: JtlSinkLimits, factory: EncoderFactory) -> JtlSinkOwner {
        JtlSinkOwner::new_with_factory(
            Box::new(RecordingWriter::default()),
            SampleSaveConfiguration::default(),
            limits,
            factory,
        )
        .unwrap_or_else(|_| panic!("test sink should start"))
    }

    fn poll_once<F: Future + Unpin>(future: &mut F) -> Poll<F::Output> {
        let waker = Waker::from(Arc::new(FlagWake::default()));
        let mut context = Context::from_waker(&waker);
        let mut future = Pin::new(future);
        future.as_mut().poll(&mut context)
    }

    fn wait_future<F: Future + Unpin>(future: &mut F) -> F::Output {
        let (sender, receiver) = mpsc::channel();
        let waker = Waker::from(Arc::new(ChannelWake {
            sender: Mutex::new(sender),
        }));
        let mut context = Context::from_waker(&waker);
        let mut future = Pin::new(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(result) => return result,
                Poll::Pending => {
                    receiver
                        .recv()
                        .unwrap_or_else(|_| panic!("sink completion waker disconnected"));
                }
            }
        }
    }

    #[test]
    fn typed_completion_wait_drop_retires_provider_registration() {
        let (operation, _clock, _cancellation) = result_operation_fixture();
        let counts = Arc::new(WaitCounts::default());
        let registrar = ManualWaitRegistrar {
            counts: Arc::clone(&counts),
        };
        let completion = completion_for_test();
        let mut wait = CompletionWait {
            completion,
            operation: &operation,
            wait_registrar: &registrar,
            registration: None,
            kind: TypedJtlOperationKind::Process,
            submitted: true,
        };

        assert!(matches!(poll_once(&mut wait), Poll::Pending));
        assert_eq!(counts.registrations.load(Ordering::Acquire), 1);
        assert_eq!(counts.retirements.load(Ordering::Acquire), 0);
        drop(wait);
        assert_eq!(counts.retirements.load(Ordering::Acquire), 1);
    }

    #[test]
    fn typed_completion_wait_races_retire_exact_registration() {
        let (operation, _clock, _cancellation) = result_operation_fixture();
        let counts = Arc::new(WaitCounts::default());
        let registrar = ManualWaitRegistrar {
            counts: Arc::clone(&counts),
        };
        let completion = completion_for_test();
        let mut wait = CompletionWait {
            completion: Arc::clone(&completion),
            operation: &operation,
            wait_registrar: &registrar,
            registration: None,
            kind: TypedJtlOperationKind::Process,
            submitted: true,
        };

        assert!(matches!(poll_once(&mut wait), Poll::Pending));
        completion.complete(Ok(()));
        assert!(matches!(poll_once(&mut wait), Poll::Ready(Ok(()))));
        assert_eq!(counts.registrations.load(Ordering::Acquire), 1);
        assert_eq!(counts.retirements.load(Ordering::Acquire), 1);
        drop(wait);
        assert_eq!(counts.retirements.load(Ordering::Acquire), 1);
    }

    #[test]
    fn typed_completion_wait_completion_before_registration_owns_zero_waits() {
        let (operation, _clock, _cancellation) = result_operation_fixture();
        let counts = Arc::new(WaitCounts::default());
        let registrar = ManualWaitRegistrar {
            counts: Arc::clone(&counts),
        };
        let completion = completion_for_test();
        completion.complete(Ok(()));
        let mut wait = CompletionWait {
            completion,
            operation: &operation,
            wait_registrar: &registrar,
            registration: None,
            kind: TypedJtlOperationKind::Process,
            submitted: true,
        };

        assert!(matches!(poll_once(&mut wait), Poll::Ready(Ok(()))));
        assert_eq!(counts.registrations.load(Ordering::Acquire), 0);
        assert_eq!(counts.retirements.load(Ordering::Acquire), 0);
    }

    #[test]
    fn typed_completion_wait_worker_failure_is_unknown_and_redacted() {
        let (operation, _clock, _cancellation) = result_operation_fixture();
        let counts = Arc::new(WaitCounts::default());
        let registrar = ManualWaitRegistrar {
            counts: Arc::clone(&counts),
        };
        let completion = completion_for_test();
        completion.complete(Err(SinkError::failed("password=supersecret")));
        let mut wait = CompletionWait {
            completion,
            operation: &operation,
            wait_registrar: &registrar,
            registration: None,
            kind: TypedJtlOperationKind::Process,
            submitted: true,
        };

        let result = poll_once(&mut wait);
        match result {
            Poll::Ready(Err(TypedSinkError::UnknownOutcome(detail))) => {
                assert!(!detail.as_str().contains("supersecret"));
                assert!(detail.as_str().contains("<redacted>"));
            }
            other => panic!("unexpected typed sink result: {other:?}"),
        }
        assert_eq!(counts.registrations.load(Ordering::Acquire), 0);
        assert_eq!(counts.retirements.load(Ordering::Acquire), 0);
    }

    #[test]
    fn typed_completion_wait_cancellation_and_deadline_leave_zero_waits() {
        let (operation, _clock, cancellation) = result_operation_fixture();
        let counts = Arc::new(WaitCounts::default());
        let registrar = ManualWaitRegistrar {
            counts: Arc::clone(&counts),
        };
        let completion = completion_for_test();
        let mut wait = CompletionWait {
            completion,
            operation: &operation,
            wait_registrar: &registrar,
            registration: None,
            kind: TypedJtlOperationKind::Process,
            submitted: true,
        };

        assert!(matches!(poll_once(&mut wait), Poll::Pending));
        assert_eq!(counts.registrations.load(Ordering::Acquire), 1);
        cancellation.cancel_immediate();
        assert!(matches!(
            poll_once(&mut wait),
            Poll::Ready(Err(TypedSinkError::Budget(
                jmeter_rs_runtime::BudgetError::Cancelled
            )))
        ));
        assert_eq!(counts.retirements.load(Ordering::Acquire), 1);
        drop(wait);
        assert_eq!(counts.retirements.load(Ordering::Acquire), 1);

        let (operation, clock, _cancellation) = result_operation_fixture();
        let counts = Arc::new(WaitCounts::default());
        let registrar = ManualWaitRegistrar {
            counts: Arc::clone(&counts),
        };
        let completion = completion_for_test();
        let mut wait = CompletionWait {
            completion,
            operation: &operation,
            wait_registrar: &registrar,
            registration: None,
            kind: TypedJtlOperationKind::Process,
            submitted: true,
        };

        clock.set(Duration::from_secs(10));
        assert!(matches!(
            poll_once(&mut wait),
            Poll::Ready(Err(TypedSinkError::Budget(
                jmeter_rs_runtime::BudgetError::Expired
            )))
        ));
        assert_eq!(counts.registrations.load(Ordering::Acquire), 0);
        assert_eq!(counts.retirements.load(Ordering::Acquire), 0);
    }

    #[test]
    fn typed_adapter_rejects_non_exact_lifecycle_scopes_before_enqueue() {
        let sink_id = qualified_sink_fixture(1);
        let foreign_sink_id = qualified_sink_fixture(2);
        let owner = owner_with_factory(
            JtlSinkLimits::default(),
            test_factory(
                Arc::new(Mutex::new(Vec::new())),
                Arc::new(AtomicUsize::new(0)),
                Arc::new(AtomicUsize::new(0)),
                Arc::new(AtomicUsize::new(0)),
                false,
                false,
                false,
                false,
                None,
            ),
        );
        let adapter = TypedJtlSinkAdapter::new(owner.submitter(), sink_id);
        let clock = Arc::new(ManualResultClock::new());
        let cancellation = Arc::new(CancellationToken::new());
        let budget = ResultDeliveryBudget::from_parts(
            ResultOperationScope::sink_set(sink_id.run_id(), sink_id.sink_plan_generation()),
            clock.clone(),
            cancellation.clone(),
            ResultOperationWindows::uniform(Duration::from_secs(10), Duration::from_secs(10)),
            2,
            None,
        )
        .unwrap_or_else(|error| panic!("test result budget: {error}"));
        let registrar = ManualWaitRegistrar {
            counts: Arc::new(WaitCounts::default()),
        };

        let sink_set_start = budget
            .begin_operation(ResultOperationKind::Start)
            .unwrap_or_else(|error| panic!("test sink-set operation: {error}"));
        let mut start = adapter.start(&sink_set_start, &registrar);
        assert!(matches!(
            poll_once(&mut start),
            Poll::Ready(Err(TypedSinkError::Permanent(detail)))
                if detail.as_str() == "app.jtl-sink.operation-scope"
        ));

        let foreign_start = budget
            .begin_sink_operation(foreign_sink_id, ResultOperationKind::Start)
            .unwrap_or_else(|error| panic!("test foreign operation: {error}"));
        let mut start = adapter.start(&foreign_start, &registrar);
        assert!(matches!(
            poll_once(&mut start),
            Poll::Ready(Err(TypedSinkError::Permanent(detail)))
                if detail.as_str() == "app.jtl-sink.operation-scope"
        ));
        assert!(adapter.check_lease_scope(sink_id).is_ok());
        assert!(matches!(
            adapter.check_lease_scope(foreign_sink_id),
            Err(TypedSinkError::Permanent(detail))
                if detail.as_str() == "app.jtl-sink.lease-scope"
        ));
        drop(owner);
    }

    #[derive(Default)]
    struct FlagWake {
        woke: AtomicBool,
    }

    impl Wake for FlagWake {
        fn wake(self: Arc<Self>) {
            self.woke.store(true, Ordering::Release);
        }
    }

    struct ChannelWake {
        sender: Mutex<Sender<()>>,
    }

    impl Wake for ChannelWake {
        fn wake(self: Arc<Self>) {
            let _ = self
                .sender
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .send(());
        }
    }

    #[test]
    fn fifo_delivery_and_permit_release() {
        let labels = Arc::new(Mutex::new(Vec::new()));
        let flushes = Arc::new(AtomicUsize::new(0));
        let finishes = Arc::new(AtomicUsize::new(0));
        let writes = Arc::new(AtomicUsize::new(0));
        let factory = test_factory(
            Arc::clone(&labels),
            Arc::clone(&flushes),
            Arc::clone(&finishes),
            Arc::clone(&writes),
            false,
            false,
            false,
            false,
            None,
        );
        let owner = owner_with_factory(
            JtlSinkLimits::new(2, DEFAULT_JTL_SINK_QUEUE_BYTES).unwrap_or_default(),
            factory,
        );
        let sink = owner.submitter();
        let first_envelope = envelope("one", 1);
        let second_envelope = envelope("two", 2);
        let first = sink.write(&first_envelope);
        let second = sink.write(&second_envelope);
        let mut first = first;
        let mut second = second;
        assert!(wait_future(&mut first).is_ok());
        assert!(wait_future(&mut second).is_ok());
        owner
            .finalize()
            .unwrap_or_else(|_| panic!("finish should succeed"));
        assert_eq!(
            labels
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_slice(),
            ["one", "two"]
        );
        assert_eq!(writes.load(Ordering::Acquire), 2);
        assert_eq!(finishes.load(Ordering::Acquire), 1);
    }

    #[test]
    fn queue_item_and_byte_full_are_typed_without_worker_polling() {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let labels = Arc::new(Mutex::new(Vec::new()));
        let flushes = Arc::new(AtomicUsize::new(0));
        let finishes = Arc::new(AtomicUsize::new(0));
        let writes = Arc::new(AtomicUsize::new(0));
        let factory = test_factory(
            labels,
            flushes,
            finishes,
            writes,
            false,
            false,
            false,
            false,
            Some(Arc::clone(&gate)),
        );
        let owner = owner_with_factory(
            JtlSinkLimits::new(1, DEFAULT_JTL_SINK_QUEUE_BYTES)
                .unwrap_or_else(|_| panic!("test limits")),
            factory,
        );
        let sink = owner.submitter();
        let first = envelope("first", 1);
        let second = envelope("second", 2);
        let mut first_future = sink.write(&first);
        assert!(matches!(poll_once(&mut first_future), Poll::Pending));
        let mut second_future = sink.write(&second);
        assert!(matches!(
            poll_once(&mut second_future),
            Poll::Ready(Err(SinkError::ResourceLimit(_)))
        ));
        {
            let (lock, condition) = &*gate;
            *lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = true;
            condition.notify_all();
        }
        drop(first_future);
        owner
            .cancel_and_join()
            .unwrap_or_else(|_| panic!("cancel should join"));
    }

    #[test]
    fn queue_byte_full_is_distinct_from_item_full() {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let labels = Arc::new(Mutex::new(Vec::new()));
        let flushes = Arc::new(AtomicUsize::new(0));
        let finishes = Arc::new(AtomicUsize::new(0));
        let writes = Arc::new(AtomicUsize::new(0));
        let factory = test_factory(
            labels,
            flushes,
            finishes,
            writes,
            false,
            false,
            false,
            false,
            Some(Arc::clone(&gate)),
        );
        let first = envelope("first", 1);
        let second = envelope("second", 2);
        let byte_limit = first
            .byte_size()
            .checked_add(second.byte_size())
            .and_then(|value| value.checked_sub(1))
            .unwrap_or(first.byte_size());
        let owner = owner_with_factory(
            JtlSinkLimits::new(8, byte_limit).unwrap_or_else(|_| panic!("test limits")),
            factory,
        );
        let sink = owner.submitter();
        let mut first_future = sink.write(&first);
        assert!(matches!(poll_once(&mut first_future), Poll::Pending));
        let mut second_future = sink.write(&second);
        assert!(matches!(
            poll_once(&mut second_future),
            Poll::Ready(Err(SinkError::ResourceLimit(_)))
        ));
        {
            let (lock, condition) = &*gate;
            *lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = true;
            condition.notify_all();
        }
        assert!(wait_future(&mut first_future).is_ok());
        owner
            .finalize()
            .unwrap_or_else(|_| panic!("finish should succeed"));
    }

    #[test]
    fn one_oversized_envelope_is_rejected_before_worker_admission() {
        let labels = Arc::new(Mutex::new(Vec::new()));
        let flushes = Arc::new(AtomicUsize::new(0));
        let finishes = Arc::new(AtomicUsize::new(0));
        let writes = Arc::new(AtomicUsize::new(0));
        let factory = test_factory(
            Arc::clone(&labels),
            Arc::clone(&flushes),
            Arc::clone(&finishes),
            Arc::clone(&writes),
            false,
            false,
            false,
            false,
            None,
        );
        let owner = owner_with_factory(JtlSinkLimits::new(8, 1).unwrap_or_default(), factory);
        let sink = owner.submitter();
        let event = envelope("oversized", 1);
        let mut future = sink.write(&event);
        assert!(matches!(
            poll_once(&mut future),
            Poll::Ready(Err(SinkError::ResourceLimit(_)))
        ));
        assert_eq!(writes.load(Ordering::Acquire), 0);
        owner
            .cancel_and_join()
            .unwrap_or_else(|_| panic!("cancel should join"));
    }

    #[test]
    fn wake_before_first_poll_and_no_io_in_poll() {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let labels = Arc::new(Mutex::new(Vec::new()));
        let flushes = Arc::new(AtomicUsize::new(0));
        let finishes = Arc::new(AtomicUsize::new(0));
        let writes = Arc::new(AtomicUsize::new(0));
        let factory = test_factory(
            labels,
            flushes,
            finishes,
            Arc::clone(&writes),
            false,
            false,
            false,
            false,
            Some(Arc::clone(&gate)),
        );
        let owner = owner_with_factory(JtlSinkLimits::default(), factory);
        let sink = owner.submitter();
        let event = envelope("wake", 1);
        let mut future = sink.write(&event);
        assert_eq!(writes.load(Ordering::Acquire), 0);
        assert!(matches!(poll_once(&mut future), Poll::Pending));
        assert_eq!(writes.load(Ordering::Acquire), 0);
        {
            let (lock, condition) = &*gate;
            *lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = true;
            condition.notify_all();
        }
        assert!(wait_future(&mut future).is_ok());
        owner
            .finalize()
            .unwrap_or_else(|_| panic!("finish should succeed"));
    }

    #[test]
    fn cancellation_wakes_queued_completions_and_does_not_finish() {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let labels = Arc::new(Mutex::new(Vec::new()));
        let flushes = Arc::new(AtomicUsize::new(0));
        let finishes = Arc::new(AtomicUsize::new(0));
        let writes = Arc::new(AtomicUsize::new(0));
        let factory = test_factory(
            labels,
            flushes,
            Arc::clone(&finishes),
            writes,
            false,
            false,
            false,
            false,
            Some(Arc::clone(&gate)),
        );
        let owner = owner_with_factory(JtlSinkLimits::new(8, 10_000).unwrap_or_default(), factory);
        let sink = owner.submitter();
        let event = envelope("cancel", 1);
        let mut write = sink.write(&event);
        assert!(matches!(poll_once(&mut write), Poll::Pending));
        let mut finish = sink.finish();
        assert!(matches!(poll_once(&mut finish), Poll::Pending));
        sink.cancel()
            .unwrap_or_else(|_| panic!("cancel should be bounded"));
        assert!(matches!(
            poll_once(&mut write),
            Poll::Ready(Err(SinkError::Cancelled))
        ));
        assert!(matches!(
            poll_once(&mut finish),
            Poll::Ready(Err(SinkError::Cancelled))
        ));
        {
            let (lock, condition) = &*gate;
            *lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = true;
            condition.notify_all();
        }
        owner
            .cancel_and_join()
            .unwrap_or_else(|_| panic!("cancel join"));
        assert_eq!(finishes.load(Ordering::Acquire), 0);
    }

    #[test]
    fn encode_flush_finish_failures_wake_all_pending() {
        let labels = Arc::new(Mutex::new(Vec::new()));
        let flushes = Arc::new(AtomicUsize::new(0));
        let finishes = Arc::new(AtomicUsize::new(0));
        let writes = Arc::new(AtomicUsize::new(0));
        let factory = test_factory(
            labels, flushes, finishes, writes, false, true, false, false, None,
        );
        let owner = owner_with_factory(JtlSinkLimits::default(), factory);
        let sink = owner.submitter();
        let mut flush = sink.flush();
        assert!(matches!(poll_once(&mut flush), Poll::Pending));
        assert!(matches!(wait_future(&mut flush), Err(SinkError::Failed(_))));
        assert!(matches!(
            owner.finalize(),
            Err(JtlSinkError::Sink(SinkError::Failed(_)))
        ));
    }

    #[test]
    fn encode_and_finish_failures_are_reported_without_retrying() {
        for (fail_write, fail_finish) in [(true, false), (false, true)] {
            let labels = Arc::new(Mutex::new(Vec::new()));
            let flushes = Arc::new(AtomicUsize::new(0));
            let finishes = Arc::new(AtomicUsize::new(0));
            let writes = Arc::new(AtomicUsize::new(0));
            let factory = test_factory(
                Arc::clone(&labels),
                Arc::clone(&flushes),
                Arc::clone(&finishes),
                Arc::clone(&writes),
                fail_write,
                false,
                fail_finish,
                false,
                None,
            );
            let owner = owner_with_factory(JtlSinkLimits::default(), factory);
            let sink = owner.submitter();
            if fail_write {
                let event = envelope("write-failure", 1);
                let mut write = sink.write(&event);
                assert!(matches!(
                    wait_future(&mut write),
                    Err(SinkError::Failed(message)) if message == "test.encoder.write"
                ));
            } else {
                let mut first = sink.finish();
                let mut second = sink.finish();
                assert!(matches!(
                    wait_future(&mut first),
                    Err(SinkError::Failed(message)) if message == "test.encoder.finish"
                ));
                assert!(matches!(
                    wait_future(&mut second),
                    Err(SinkError::Failed(message)) if message == "test.encoder.finish"
                ));
                assert_eq!(finishes.load(Ordering::Acquire), 1);
            }
            assert!(matches!(
                owner.finalize(),
                Err(JtlSinkError::Sink(SinkError::Failed(_)))
            ));
        }
    }

    #[test]
    fn worker_panic_is_redacted_and_finishes_pending_futures() {
        let labels = Arc::new(Mutex::new(Vec::new()));
        let flushes = Arc::new(AtomicUsize::new(0));
        let finishes = Arc::new(AtomicUsize::new(0));
        let writes = Arc::new(AtomicUsize::new(0));
        let factory = test_factory(
            labels, flushes, finishes, writes, false, false, false, true, None,
        );
        let owner = owner_with_factory(JtlSinkLimits::default(), factory);
        let sink = owner.submitter();
        let event = envelope("secret-event", 1);
        let mut write = sink.write(&event);
        let result = wait_future(&mut write);
        assert!(
            matches!(result, Err(SinkError::Failed(message)) if message == "jtl sink worker panic")
        );
        let debug = format!("{owner:?} {:?}", sink);
        assert!(!debug.contains("secret-event"));
        assert!(matches!(
            owner.finalize(),
            Err(JtlSinkError::Sink(_)) | Err(JtlSinkError::WorkerPanic)
        ));
    }

    #[test]
    fn finish_is_idempotent_and_exactly_once() {
        let labels = Arc::new(Mutex::new(Vec::new()));
        let flushes = Arc::new(AtomicUsize::new(0));
        let finishes = Arc::new(AtomicUsize::new(0));
        let writes = Arc::new(AtomicUsize::new(0));
        let factory = test_factory(
            labels,
            flushes,
            Arc::clone(&finishes),
            writes,
            false,
            false,
            false,
            false,
            None,
        );
        let owner = owner_with_factory(JtlSinkLimits::default(), factory);
        let sink = owner.submitter();
        let mut first = sink.finish();
        let mut second = sink.finish();
        assert!(wait_future(&mut first).is_ok());
        assert!(wait_future(&mut second).is_ok());
        assert!(owner.finalize().is_ok());
        assert!(owner.finalize().is_ok());
        assert_eq!(finishes.load(Ordering::Acquire), 1);
    }

    #[test]
    fn owner_drop_cancels_and_reaps_an_idle_worker() {
        let labels = Arc::new(Mutex::new(Vec::new()));
        let flushes = Arc::new(AtomicUsize::new(0));
        let finishes = Arc::new(AtomicUsize::new(0));
        let writes = Arc::new(AtomicUsize::new(0));
        let factory = test_factory(
            labels,
            flushes,
            Arc::clone(&finishes),
            writes,
            false,
            false,
            false,
            false,
            None,
        );
        let owner = owner_with_factory(JtlSinkLimits::default(), factory);
        drop(owner);
        assert_eq!(finishes.load(Ordering::Acquire), 0);
    }

    #[test]
    fn owner_and_submitter_have_distinct_send_contracts() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<JtlSinkSubmitter>();
        // `JtlSinkOwner` intentionally contains PhantomData<Rc<()>>; the
        // compile-time negative assertion is represented by its API shape and
        // does not rely on unstable auto-trait introspection.
    }

    #[test]
    fn production_csv_and_xml_finish_structure() {
        for (format, prefix, suffix) in [
            (jmeter_rs_results::JtlFormat::Csv, "timeStamp", ""),
            (jmeter_rs_results::JtlFormat::Xml, "<?xml", "</testResults>"),
        ] {
            let bytes = Arc::new(Mutex::new(Vec::new()));
            let writer = RecordingWriter {
                bytes: Arc::clone(&bytes),
                flushes: Arc::new(AtomicUsize::new(0)),
            };
            let mut configuration = SampleSaveConfiguration::default();
            configuration.set_format(format);
            let owner =
                JtlSinkOwner::new(Box::new(writer), configuration, JtlSinkLimits::default())
                    .unwrap_or_else(|_| panic!("production sink"));
            let sink = owner.submitter();
            let event = envelope("sample", 1);
            let mut write = sink.write(&event);
            assert!(wait_future(&mut write).is_ok());
            let mut first_finish = sink.finish();
            let mut second_finish = sink.finish();
            assert!(wait_future(&mut first_finish).is_ok());
            assert!(wait_future(&mut second_finish).is_ok());
            owner
                .finalize()
                .unwrap_or_else(|_| panic!("production finish"));
            let bytes = bytes
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let output = String::from_utf8_lossy(&bytes);
            assert!(output.starts_with(prefix));
            if suffix.is_empty() {
                assert!(output.contains("sample"));
                assert_eq!(output.matches("timeStamp").count(), 1);
            } else {
                assert!(output.contains(suffix));
                assert_eq!(output.matches("<testResults").count(), 1);
                assert_eq!(output.matches("</testResults>").count(), 1);
            }
        }
    }

    #[test]
    fn production_writer_streams_past_64_kib_without_retaining_output() {
        let bytes = Arc::new(AtomicUsize::new(0));
        let flushes = Arc::new(AtomicUsize::new(0));
        let writer = CountingWriter {
            bytes: Arc::clone(&bytes),
            flushes: Arc::clone(&flushes),
        };
        let owner = JtlSinkOwner::new(
            Box::new(writer),
            SampleSaveConfiguration::default(),
            JtlSinkLimits::default(),
        )
        .unwrap_or_else(|_| panic!("production sink"));
        let sink = owner.submitter();
        let label = "x".repeat(70 * 1024);
        let event = envelope(&label, 1);
        let mut write = sink.write(&event);
        assert!(wait_future(&mut write).is_ok());
        owner
            .finalize()
            .unwrap_or_else(|_| panic!("production finish"));
        assert!(bytes.load(Ordering::Acquire) > 64 * 1024);
        assert!(flushes.load(Ordering::Acquire) >= 1);
    }

    #[test]
    fn production_writer_counts_logically_over_64_mib_without_a_large_buffer() {
        let bytes = Arc::new(AtomicUsize::new(0));
        let flushes = Arc::new(AtomicUsize::new(0));
        let writer = CountingWriter {
            bytes: Arc::clone(&bytes),
            flushes,
        };
        let owner = JtlSinkOwner::new(
            Box::new(writer),
            SampleSaveConfiguration::default(),
            JtlSinkLimits::new(32, 4 * 1024 * 1024).unwrap_or_else(|_| panic!("test limits")),
        )
        .unwrap_or_else(|_| panic!("production sink"));
        let sink = owner.submitter();
        // Reusing one Arc-backed event keeps retained memory bounded while
        // the counting writer observes a logically larger-than-64-MiB stream.
        let label = "x".repeat(1024);
        let event = envelope(&label, 1);
        for _ in 0..66_000 {
            let mut write = sink.write(&event);
            assert!(wait_future(&mut write).is_ok());
        }
        owner
            .finalize()
            .unwrap_or_else(|_| panic!("production finish"));
        assert!(bytes.load(Ordering::Acquire) > 64 * 1024 * 1024);
    }
}
