// SPDX-License-Identifier: Apache-2.0
//! A bounded current-thread adapter for one executor-neutral runtime future.
//!
//! The runtime deliberately does not own an executor.  This application-edge
//! adapter drives one pinned future on the calling thread and observes only
//! the run's read-only progress and wait snapshots.  It does not infer a
//! timeout from a plan, request, or JMX field: a pending future either owns a
//! finite wait registration or is diagnosed as stalled after one bounded
//! register/wake race window.
//!
//! [`RuntimeEngineFuture`](jmeter_rs_runtime::RuntimeEngineFuture) is one
//! intended input, although the API is generic over every standard-library
//! future.  The progress handle passed to the adapter must be the exact handle
//! belonging to that run future.  The wait handle must be the read-only handle
//! for the same run-owned registry, and the time-driver handle must be the
//! corresponding run owner used by that registry.

#![forbid(unsafe_code)]
#![allow(
    clippy::module_name_repetitions,
    reason = "the application capability is intentionally named by its executor owner"
)]

use std::any::Any;
use std::fmt;
use std::future::Future;
use std::num::NonZeroU64;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};
use std::time::Duration;

use jmeter_rs_runtime::{
    CancellationToken, MonotonicInstant, ProgressHandle, ProgressSnapshot, ProgressTerminalState,
    RuntimeEngineFuture, WaitRegistryHandle, WaitSnapshot,
};

use crate::time_driver::{TimeDriverError, TimeDriverHandle};

/// Default consecutive no-progress polls permitted by the production edge.
pub const DEFAULT_POLL_BUDGET: u64 = 1_000_000;

/// Default consecutive no-progress wake notifications permitted by the
/// production edge.
pub const DEFAULT_WAKE_BUDGET: u64 = 1_000_000;

/// Fixed grace used after an absolute driver deadline so the driver worker can
/// deliver its exact waker notification before the provider watchdog fires.
/// This is delivery allowance, not an operation-duration ceiling.
pub const DRIVER_DELIVERY_GRACE: Duration = Duration::from_millis(1);

/// Fixed one-shot window used to close a future's register/wake race when it
/// returns `Pending` without a live wait registration.
pub const NO_WAIT_RACE_GRACE: Duration = Duration::from_millis(1);

/// One operating-system park chunk.  It avoids platform timeout
/// representation limits without imposing a product duration ceiling; a
/// long absolute deadline is revisited in further chunks.
const MAX_PARK_CHUNK: Duration = Duration::from_secs(24 * 60 * 60);

/// Which consecutive no-progress budget was invalid or exceeded.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExecutorBudget {
    /// The poll budget.
    Poll,
    /// The wake-storm budget.
    Wake,
}

impl ExecutorBudget {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Poll => "poll",
            Self::Wake => "wake",
        }
    }
}

/// The bounded executor state that could not be locked safely.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExecutorLock {
    /// The current-thread wake bookkeeping mutex.
    WakeBookkeeping,
}

impl ExecutorLock {
    const fn as_str(self) -> &'static str {
        match self {
            Self::WakeBookkeeping => "wake-bookkeeping",
        }
    }
}

/// The bounded cleanup failure retained alongside a primary executor error.
#[allow(
    clippy::enum_variant_names,
    reason = "the suffix identifies the exact cleanup operation that panicked"
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExecutorCleanupError {
    /// Immediate cancellation notification panicked.
    CancellationPanicked,
    /// Dropping the owned future panicked.
    FutureDropPanicked,
    /// Both immediate cancellation and future drop panicked.
    CancellationAndFutureDropPanicked,
}

impl ExecutorCleanupError {
    const fn as_str(self) -> &'static str {
        match self {
            Self::CancellationPanicked => "cancellation-panic",
            Self::FutureDropPanicked => "future-drop-panic",
            Self::CancellationAndFutureDropPanicked => "cancellation-and-future-drop-panic",
        }
    }
}

/// Typed failures raised by the current-thread executor.
///
/// Error variants contain only stable enum values, bounded counters, absolute
/// monotonic instants, or the already-bounded time-driver error.  No future,
/// result payload, request value, secret, or arbitrary diagnostic string is
/// retained here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CurrentThreadExecutorError {
    /// A configured consecutive budget was zero.
    InvalidBudget { budget: ExecutorBudget },
    /// The supplied run-owned time driver failed or rejected its waker.
    TimeDriver { source: TimeDriverError },
    /// The supplied wait registry has already been finalized.
    WaitRegistryShutdown,
    /// A wait snapshot violated the registry's finite-deadline invariant.
    WaitSnapshotInconsistent,
    /// A progress generation moved backwards.
    ProgressGenerationReversed,
    /// A wait generation moved backwards.
    WaitGenerationReversed,
    /// A wake generation moved backwards or disagreed with its checked count.
    WakeBookkeepingInconsistent,
    /// A wake generation reached the reserved overflow boundary.
    WakeGenerationOverflow,
    /// A wake counter reached the reserved overflow boundary.
    WakeCounterOverflow,
    /// The consecutive poll counter overflowed before a policy comparison.
    PollCounterOverflow,
    /// The consecutive wake counter overflowed before a policy comparison.
    WakeStreakOverflow,
    /// Consecutive no-progress polls exceeded the policy.
    PollBudgetExceeded { limit: NonZeroU64 },
    /// Consecutive no-progress wakes exceeded the policy.
    WakeBudgetExceeded { limit: NonZeroU64 },
    /// The future remained pending without owning a wait after one race
    /// closure.
    Stalled,
    /// An expired wait remained unchanged after its one final repoll.
    StalledProvider { deadline: MonotonicInstant },
    /// The engine reported a terminal state while its future remained pending.
    TerminalFuturePending { terminal: ProgressTerminalState },
    /// The supplied cancellation token was already or became stopped.
    Cancelled,
    /// A future poll panicked and was converted to a typed executor failure.
    FuturePanicked,
    /// Dropping a future after cancellation or completion panicked.
    FutureDropPanicked,
    /// Cancellation notification itself panicked.
    CancellationPanicked,
    /// A primary failure and one or more bounded cleanup failures occurred.
    /// The primary error remains intact rather than being replaced.
    PrimaryWithCleanup {
        /// The original failure that triggered cleanup.
        primary: Box<Self>,
        /// Bounded cleanup category/categories.
        cleanup: ExecutorCleanupError,
    },
    /// The executor's own bounded mutex was poisoned.
    MutexPoisoned { lock: ExecutorLock },
}

impl CurrentThreadExecutorError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidBudget { .. } => "runtime.executor.policy",
            Self::TimeDriver { source } => source.code(),
            Self::WaitRegistryShutdown => "runtime.executor.wait-shutdown",
            Self::WaitSnapshotInconsistent => "runtime.executor.wait-invariant",
            Self::ProgressGenerationReversed => "runtime.executor.progress-generation",
            Self::WaitGenerationReversed => "runtime.executor.wait-generation",
            Self::WakeBookkeepingInconsistent => "runtime.executor.wake-invariant",
            Self::WakeGenerationOverflow => "runtime.executor.wake-generation-overflow",
            Self::WakeCounterOverflow => "runtime.executor.wake-counter-overflow",
            Self::PollCounterOverflow => "runtime.executor.poll-counter-overflow",
            Self::WakeStreakOverflow => "runtime.executor.wake-streak-overflow",
            Self::PollBudgetExceeded { .. } => "runtime.executor.poll-budget",
            Self::WakeBudgetExceeded { .. } => "runtime.executor.wake-budget",
            Self::Stalled => "runtime.executor.stalled",
            Self::StalledProvider { .. } => "runtime.executor.stalled-provider",
            Self::TerminalFuturePending { .. } => "runtime.executor.terminal-pending",
            Self::Cancelled => "runtime.executor.cancelled",
            Self::FuturePanicked => "runtime.executor.future-panic",
            Self::FutureDropPanicked => "runtime.executor.future-drop-panic",
            Self::CancellationPanicked => "runtime.executor.cancellation-panic",
            Self::PrimaryWithCleanup { .. } => "runtime.executor.cleanup",
            Self::MutexPoisoned { .. } => "runtime.executor.mutex-poisoned",
        }
    }

    /// Returns the bounded time-driver source when this is a driver failure.
    #[must_use]
    pub const fn time_driver_source(&self) -> Option<&TimeDriverError> {
        match self {
            Self::TimeDriver { source } => Some(source),
            _ => None,
        }
    }
}

impl fmt::Display for CurrentThreadExecutorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBudget { budget } => {
                write!(formatter, "{}: {}", self.code(), budget.as_str())
            }
            Self::TimeDriver { source } => write!(formatter, "{}: {}", self.code(), source.code()),
            Self::PollBudgetExceeded { limit } => {
                write!(formatter, "{}: limit={}", self.code(), limit.get())
            }
            Self::WakeBudgetExceeded { limit } => {
                write!(formatter, "{}: limit={}", self.code(), limit.get())
            }
            Self::StalledProvider { deadline } => {
                write!(formatter, "{}: deadline={:?}", self.code(), deadline)
            }
            Self::TerminalFuturePending { terminal } => {
                write!(formatter, "{}: terminal={terminal:?}", self.code())
            }
            Self::PrimaryWithCleanup { primary, cleanup } => write!(
                formatter,
                "{}: primary={}, cleanup={}",
                self.code(),
                primary.code(),
                cleanup.as_str()
            ),
            Self::MutexPoisoned { lock } => write!(formatter, "{}: {}", self.code(), lock.as_str()),
            Self::WaitRegistryShutdown
            | Self::WaitSnapshotInconsistent
            | Self::ProgressGenerationReversed
            | Self::WaitGenerationReversed
            | Self::WakeBookkeepingInconsistent
            | Self::WakeGenerationOverflow
            | Self::WakeCounterOverflow
            | Self::PollCounterOverflow
            | Self::WakeStreakOverflow
            | Self::Stalled
            | Self::Cancelled
            | Self::FuturePanicked
            | Self::FutureDropPanicked
            | Self::CancellationPanicked => formatter.write_str(self.code()),
        }
    }
}

impl std::error::Error for CurrentThreadExecutorError {}

/// Bounded policy for one current-thread drive.
///
/// Budgets count only consecutive no-progress work.  They are reset by
/// semantic progress; a wait-generation change resets the poll budget but is
/// deliberately not treated as semantic progress.  No deadline or duration
/// ceiling is part of this policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CurrentThreadExecutorPolicy {
    /// Maximum consecutive polls without semantic or wait-generation change.
    pub poll_budget: NonZeroU64,
    /// Maximum consecutive wake notifications without semantic or
    /// wait-generation change.
    pub wake_budget: NonZeroU64,
    /// Fixed delivery allowance after a wait's absolute deadline.
    pub driver_delivery_grace: Duration,
    /// One-shot race window for a pending future with no registered wait.
    pub no_wait_race_grace: Duration,
}

impl Default for CurrentThreadExecutorPolicy {
    fn default() -> Self {
        Self {
            poll_budget: NonZeroU64::new(DEFAULT_POLL_BUDGET).unwrap_or(NonZeroU64::MIN),
            wake_budget: NonZeroU64::new(DEFAULT_WAKE_BUDGET).unwrap_or(NonZeroU64::MIN),
            driver_delivery_grace: DRIVER_DELIVERY_GRACE,
            no_wait_race_grace: NO_WAIT_RACE_GRACE,
        }
    }
}

impl CurrentThreadExecutorPolicy {
    /// Creates a policy with the fixed production delivery windows.
    pub fn new(poll_budget: u64, wake_budget: u64) -> Result<Self, CurrentThreadExecutorError> {
        let poll_budget =
            NonZeroU64::new(poll_budget).ok_or(CurrentThreadExecutorError::InvalidBudget {
                budget: ExecutorBudget::Poll,
            })?;
        let wake_budget =
            NonZeroU64::new(wake_budget).ok_or(CurrentThreadExecutorError::InvalidBudget {
                budget: ExecutorBudget::Wake,
            })?;
        Ok(Self {
            poll_budget,
            wake_budget,
            ..Self::default()
        })
    }

    /// Returns the default production policy.
    #[must_use]
    pub fn production() -> Self {
        Self::default()
    }

    /// Replaces the poll budget while retaining all other policy fields.
    pub fn with_poll_budget(
        mut self,
        poll_budget: u64,
    ) -> Result<Self, CurrentThreadExecutorError> {
        self.poll_budget =
            NonZeroU64::new(poll_budget).ok_or(CurrentThreadExecutorError::InvalidBudget {
                budget: ExecutorBudget::Poll,
            })?;
        Ok(self)
    }

    /// Replaces the wake budget while retaining all other policy fields.
    pub fn with_wake_budget(
        mut self,
        wake_budget: u64,
    ) -> Result<Self, CurrentThreadExecutorError> {
        self.wake_budget =
            NonZeroU64::new(wake_budget).ok_or(CurrentThreadExecutorError::InvalidBudget {
                budget: ExecutorBudget::Wake,
            })?;
        Ok(self)
    }

    /// Sets the fixed delivery grace.  The default is the production value;
    /// a zero value is useful for deterministic tests with already-expired
    /// waits.
    #[must_use]
    pub const fn with_driver_delivery_grace(mut self, grace: Duration) -> Self {
        self.driver_delivery_grace = grace;
        self
    }

    /// Sets the one-shot no-wait race window.  This does not create an idle
    /// timeout; it is used once only for a missing-registration race.
    #[must_use]
    pub const fn with_no_wait_race_grace(mut self, grace: Duration) -> Self {
        self.no_wait_race_grace = grace;
        self
    }

    fn validate(self) -> Result<Self, CurrentThreadExecutorError> {
        if self.poll_budget.get() == 0 {
            return Err(CurrentThreadExecutorError::InvalidBudget {
                budget: ExecutorBudget::Poll,
            });
        }
        if self.wake_budget.get() == 0 {
            return Err(CurrentThreadExecutorError::InvalidBudget {
                budget: ExecutorBudget::Wake,
            });
        }
        Ok(self)
    }
}

/// The exact current-thread executor owner for one future.
pub struct CurrentThreadExecutor<F> {
    future: Option<Pin<Box<F>>>,
    progress: ProgressHandle,
    waits: WaitRegistryHandle,
    driver: TimeDriverHandle,
    cancellation: CancellationToken,
    policy: CurrentThreadExecutorPolicy,
}

impl<F: Future> CurrentThreadExecutor<F> {
    /// Creates an executor using the default production policy.
    #[must_use]
    pub fn new(
        future: F,
        progress: ProgressHandle,
        waits: WaitRegistryHandle,
        driver: TimeDriverHandle,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            future: Some(Box::pin(future)),
            progress,
            waits,
            driver,
            cancellation,
            policy: CurrentThreadExecutorPolicy::default(),
        }
    }

    /// Creates an executor with an explicit bounded policy.
    ///
    /// If policy validation fails, the supplied future is cancelled before it
    /// is dropped, preserving the same watchdog ordering as a drive failure.
    pub fn with_policy(
        future: F,
        progress: ProgressHandle,
        waits: WaitRegistryHandle,
        driver: TimeDriverHandle,
        cancellation: CancellationToken,
        policy: CurrentThreadExecutorPolicy,
    ) -> Result<Self, CurrentThreadExecutorError> {
        let policy = match policy.validate() {
            Ok(policy) => policy,
            Err(error) => {
                let cancellation_failed = request_immediate_cancellation(&cancellation).is_err();
                let drop_failed = drop_future(future);
                return Err(with_cleanup(error, cancellation_failed, drop_failed));
            }
        };
        Ok(Self {
            future: Some(Box::pin(future)),
            progress,
            waits,
            driver,
            cancellation,
            policy,
        })
    }

    /// Drives the owned future on the current thread until it is ready or a
    /// typed watchdog/error boundary is reached.
    pub fn run(mut self) -> Result<F::Output, CurrentThreadExecutorError> {
        let outcome = panic::catch_unwind(AssertUnwindSafe(|| self.drive_loop()));
        match outcome {
            Ok(Ok(value)) => match self.drop_completed_future() {
                Ok(()) => Ok(value),
                Err(error) => Err(error),
            },
            Ok(Err(error)) => Err(self.abort(error)),
            Err(payload) => {
                discard_panic_payload(payload);
                Err(self.abort(CurrentThreadExecutorError::FuturePanicked))
            }
        }
    }

    fn drive_loop(&mut self) -> Result<F::Output, CurrentThreadExecutorError> {
        let signal = Arc::new(WakeSignal::new(thread::current()));
        let waker = Waker::from(Arc::clone(&signal));

        if self.waits.is_shutdown() {
            return Err(CurrentThreadExecutorError::WaitRegistryShutdown);
        }
        self.driver
            .set_wait_waker(&waker)
            .map_err(|source| CurrentThreadExecutorError::TimeDriver { source })?;
        register_cancellation_waker(&self.cancellation, &waker)?;

        let progress = self.progress.snapshot();
        let waits = self.waits.snapshot();
        validate_wait_snapshot(waits)?;
        let wake = signal.snapshot()?;
        let mut state = DriveState::new(progress, waits, wake);

        loop {
            if self.cancellation.is_cancelled() {
                return Err(CurrentThreadExecutorError::Cancelled);
            }
            if self.waits.is_shutdown() {
                return Err(CurrentThreadExecutorError::WaitRegistryShutdown);
            }

            let poll_result = {
                let future = self
                    .future
                    .as_mut()
                    .ok_or(CurrentThreadExecutorError::FutureDropPanicked)?;
                // No executor lock is held while user/runtime code is polled.
                panic::catch_unwind(AssertUnwindSafe(|| {
                    future.as_mut().poll(&mut Context::from_waker(&waker))
                }))
            };
            let poll_result = match poll_result {
                Ok(result) => result,
                Err(payload) => {
                    discard_panic_payload(payload);
                    return Err(CurrentThreadExecutorError::FuturePanicked);
                }
            };

            match poll_result {
                Poll::Ready(value) => return Ok(value),
                Poll::Pending => {
                    let progress_after = self.progress.snapshot();
                    let waits_after = self.waits.snapshot();
                    validate_wait_snapshot(waits_after)?;
                    let wake_after = signal.snapshot()?;
                    if self.cancellation.is_cancelled() {
                        return Err(CurrentThreadExecutorError::Cancelled);
                    }
                    let pending =
                        state.observe(progress_after, waits_after, wake_after, self.policy)?;
                    if progress_after.terminal.is_terminal() {
                        return Err(CurrentThreadExecutorError::TerminalFuturePending {
                            terminal: progress_after.terminal,
                        });
                    }

                    // Semantic progress means the future may have retired its
                    // last wait while leaving a runnable continuation.  A
                    // wait-generation change with no registrations has the
                    // same observable shape.  Repoll both cases before
                    // considering the missing-wait stall; the streak remains
                    // checked in `observe`, so this cannot bypass the poll
                    // watchdog.  Unchanged pending/no-wait and self-wakes stay
                    // on their respective bounded watchdog paths below.
                    if pending.semantic_progress
                        || (pending.wait_changed && waits_after.registrations == 0)
                    {
                        if pending.poll_budget_exceeded {
                            return Err(CurrentThreadExecutorError::PollBudgetExceeded {
                                limit: self.policy.poll_budget,
                            });
                        }
                        continue;
                    }

                    // A wake with no progress or wait change is a wake storm;
                    // it is accounted for before the missing-wait branch so a
                    // self-waking future cannot evade its wake budget.
                    if pending.wake_notifications != 0 {
                        if pending.poll_budget_exceeded {
                            return Err(CurrentThreadExecutorError::PollBudgetExceeded {
                                limit: self.policy.poll_budget,
                            });
                        }
                        if waits_after.registrations == 0 {
                            state.no_wait_race_used = true;
                        }
                        continue;
                    }

                    if waits_after.registrations == 0 {
                        // This is the one and only bounded missing-wait race
                        // closure for this no-progress episode.  A second
                        // pending/no-wait result is a typed stall, never an
                        // invented idle timeout.
                        if state.no_wait_race_used {
                            return Err(CurrentThreadExecutorError::Stalled);
                        }
                        if pending.poll_budget_exceeded {
                            // The explicit missing-registration contract has
                            // priority over a poll ceiling on its first race
                            // window; the next pending turn is stalled.
                        }
                        state.no_wait_race_used = true;
                        if close_no_wait_race(
                            &self.progress,
                            &self.waits,
                            &signal,
                            self.cancellation.clone(),
                            state.observed_progress,
                            state.observed_wait,
                            state.observed_wake,
                            self.policy.no_wait_race_grace,
                        )? {
                            continue;
                        }
                        return Err(CurrentThreadExecutorError::Stalled);
                    }

                    state.no_wait_race_used = false;
                    let now = MonotonicInstant::from_duration(
                        self.driver
                            .try_now()
                            .map_err(|source| CurrentThreadExecutorError::TimeDriver { source })?
                            .monotonic,
                    );
                    match state.expired_action(waits_after, now)? {
                        ExpiredAction::Repoll => continue,
                        ExpiredAction::Stalled { deadline } => {
                            return Err(CurrentThreadExecutorError::StalledProvider { deadline });
                        }
                        ExpiredAction::NotExpired => {}
                    }
                    if pending.poll_budget_exceeded {
                        return Err(CurrentThreadExecutorError::PollBudgetExceeded {
                            limit: self.policy.poll_budget,
                        });
                    }
                    match park_until_wait(
                        &self.progress,
                        &self.waits,
                        &self.driver,
                        &signal,
                        &self.cancellation,
                        state.observed_progress,
                        waits_after,
                        state.observed_wake,
                        self.policy.driver_delivery_grace,
                    )? {
                        ParkOutcome::Changed => continue,
                        ParkOutcome::Deadline => continue,
                    }
                }
            }
        }
    }

    fn drop_completed_future(&mut self) -> Result<(), CurrentThreadExecutorError> {
        let Some(future) = self.future.take() else {
            return Ok(());
        };
        if drop_pinned_future(future) {
            Err(CurrentThreadExecutorError::FutureDropPanicked)
        } else {
            Ok(())
        }
    }

    fn abort(&mut self, primary: CurrentThreadExecutorError) -> CurrentThreadExecutorError {
        let cancellation_panicked = request_immediate_cancellation(&self.cancellation).is_err();
        let drop_panicked = self.future.take().is_some_and(drop_pinned_future);
        with_cleanup(primary, cancellation_panicked, drop_panicked)
    }
}

impl<'a> CurrentThreadExecutor<RuntimeEngineFuture<'a>> {
    /// Creates an executor from the runtime's run future and its exact
    /// progress handle.  The handle is obtained before the future is moved
    /// into the pinned owner, so callers cannot accidentally pair it with a
    /// later run's progress state.
    #[must_use]
    pub fn from_runtime_engine(
        future: RuntimeEngineFuture<'a>,
        waits: WaitRegistryHandle,
        driver: TimeDriverHandle,
        cancellation: CancellationToken,
    ) -> Self {
        let progress = future.progress_handle();
        Self::new(future, progress, waits, driver, cancellation)
    }
}

fn with_cleanup(
    primary: CurrentThreadExecutorError,
    cancellation_failed: bool,
    drop_failed: bool,
) -> CurrentThreadExecutorError {
    let cleanup = match (cancellation_failed, drop_failed) {
        (false, false) => return primary,
        (true, false) => ExecutorCleanupError::CancellationPanicked,
        (false, true) => ExecutorCleanupError::FutureDropPanicked,
        (true, true) => ExecutorCleanupError::CancellationAndFutureDropPanicked,
    };
    CurrentThreadExecutorError::PrimaryWithCleanup {
        primary: Box::new(primary),
        cleanup,
    }
}

/// Drives a generic future with the default production policy.
pub fn drive<F: Future>(
    future: F,
    progress: ProgressHandle,
    waits: WaitRegistryHandle,
    driver: TimeDriverHandle,
    cancellation: CancellationToken,
) -> Result<F::Output, CurrentThreadExecutorError> {
    CurrentThreadExecutor::new(future, progress, waits, driver, cancellation).run()
}

/// Drives a generic future with an explicit bounded policy.
pub fn drive_with_policy<F: Future>(
    future: F,
    progress: ProgressHandle,
    waits: WaitRegistryHandle,
    driver: TimeDriverHandle,
    cancellation: CancellationToken,
    policy: CurrentThreadExecutorPolicy,
) -> Result<F::Output, CurrentThreadExecutorError> {
    CurrentThreadExecutor::with_policy(future, progress, waits, driver, cancellation, policy)?.run()
}

/// Alias with an application-edge-oriented name for callers that prefer a
/// function over [`CurrentThreadExecutor::run`].
pub fn drive_current_thread<F: Future>(
    future: F,
    progress: ProgressHandle,
    waits: WaitRegistryHandle,
    driver: TimeDriverHandle,
    cancellation: CancellationToken,
) -> Result<F::Output, CurrentThreadExecutorError> {
    drive(future, progress, waits, driver, cancellation)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WakeBookkeeping {
    generation: NonZeroU64,
    notifications: u64,
}

#[derive(Debug)]
struct WakeSignal {
    thread: Thread,
    state: Mutex<WakeBookkeeping>,
    poisoned: AtomicBool,
    generation_overflow: AtomicBool,
    counter_overflow: AtomicBool,
}

impl WakeSignal {
    fn new(thread: Thread) -> Self {
        Self {
            thread,
            state: Mutex::new(WakeBookkeeping {
                generation: NonZeroU64::MIN,
                notifications: 0,
            }),
            poisoned: AtomicBool::new(false),
            generation_overflow: AtomicBool::new(false),
            counter_overflow: AtomicBool::new(false),
        }
    }

    fn snapshot(&self) -> Result<WakeBookkeeping, CurrentThreadExecutorError> {
        if self.generation_overflow.load(Ordering::Acquire) {
            return Err(CurrentThreadExecutorError::WakeGenerationOverflow);
        }
        if self.counter_overflow.load(Ordering::Acquire) {
            return Err(CurrentThreadExecutorError::WakeCounterOverflow);
        }
        if self.poisoned.load(Ordering::Acquire) {
            return Err(CurrentThreadExecutorError::MutexPoisoned {
                lock: ExecutorLock::WakeBookkeeping,
            });
        }
        let state = self.state.lock().map_err(|_| {
            self.poisoned.store(true, Ordering::Release);
            CurrentThreadExecutorError::MutexPoisoned {
                lock: ExecutorLock::WakeBookkeeping,
            }
        })?;
        if !wake_bookkeeping_is_valid(*state) {
            return Err(CurrentThreadExecutorError::WakeBookkeepingInconsistent);
        }
        Ok(*state)
    }

    fn signal(&self) {
        let thread = self.thread.clone();
        match self.state.lock() {
            Ok(mut state) => {
                let Some(generation) = state.generation.get().checked_add(1) else {
                    self.generation_overflow.store(true, Ordering::Release);
                    thread.unpark();
                    return;
                };
                let Some(notifications) = state.notifications.checked_add(1) else {
                    self.counter_overflow.store(true, Ordering::Release);
                    thread.unpark();
                    return;
                };
                let Some(generation) = NonZeroU64::new(generation) else {
                    self.generation_overflow.store(true, Ordering::Release);
                    thread.unpark();
                    return;
                };
                state.generation = generation;
                state.notifications = notifications;
            }
            Err(_) => {
                self.poisoned.store(true, Ordering::Release);
            }
        }
        // Never hold the bookkeeping lock while unparking the exact owner
        // thread.  A wake racing this call is observed by generation.
        thread.unpark();
    }

    #[cfg(test)]
    fn force_generation_for_test(&self, value: NonZeroU64) {
        if let Ok(mut state) = self.state.lock() {
            state.generation = value;
        }
    }

    #[cfg(test)]
    fn force_notification_count_for_test(&self, value: u64) {
        if let Ok(mut state) = self.state.lock() {
            state.notifications = value;
        }
    }
}

impl Wake for WakeSignal {
    fn wake(self: Arc<Self>) {
        self.signal();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.signal();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DriveState {
    observed_progress: ProgressSnapshot,
    observed_wait: WaitSnapshot,
    observed_wake: WakeBookkeeping,
    poll_streak: u64,
    wake_streak: u64,
    no_wait_race_used: bool,
    expired_wait: Option<ExpiredWait>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExpiredWait {
    deadline: MonotonicInstant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingObservation {
    wake_notifications: u64,
    poll_budget_exceeded: bool,
    semantic_progress: bool,
    wait_changed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExpiredAction {
    NotExpired,
    Repoll,
    Stalled { deadline: MonotonicInstant },
}

impl DriveState {
    fn new(progress: ProgressSnapshot, waits: WaitSnapshot, wake: WakeBookkeeping) -> Self {
        Self {
            observed_progress: progress,
            observed_wait: waits,
            observed_wake: wake,
            poll_streak: 0,
            wake_streak: 0,
            no_wait_race_used: false,
            expired_wait: None,
        }
    }

    fn observe(
        &mut self,
        progress: ProgressSnapshot,
        waits: WaitSnapshot,
        wake: WakeBookkeeping,
        policy: CurrentThreadExecutorPolicy,
    ) -> Result<PendingObservation, CurrentThreadExecutorError> {
        if progress.generation < self.observed_progress.generation {
            return Err(CurrentThreadExecutorError::ProgressGenerationReversed);
        }
        if waits.generation < self.observed_wait.generation {
            return Err(CurrentThreadExecutorError::WaitGenerationReversed);
        }
        if wake.generation < self.observed_wake.generation
            || wake.notifications < self.observed_wake.notifications
            || (wake.generation != self.observed_wake.generation
                && wake.notifications == self.observed_wake.notifications)
        {
            return Err(CurrentThreadExecutorError::WakeBookkeepingInconsistent);
        }
        let wake_notifications = wake
            .notifications
            .checked_sub(self.observed_wake.notifications)
            .ok_or(CurrentThreadExecutorError::WakeCounterOverflow)?;
        if !wake_bookkeeping_is_valid(wake) {
            return Err(CurrentThreadExecutorError::WakeBookkeepingInconsistent);
        }
        let semantic_progress = progress.generation > self.observed_progress.generation;
        let wait_changed = waits.generation > self.observed_wait.generation;
        if semantic_progress {
            self.poll_streak = 0;
            self.wake_streak = 0;
            self.no_wait_race_used = false;
        } else if wait_changed {
            // A registration mutation is a real state change for polling but
            // is deliberately not semantic engine progress.
            self.poll_streak = 0;
            self.no_wait_race_used = false;
        } else {
            self.poll_streak = checked_streak(
                self.poll_streak,
                CurrentThreadExecutorError::PollCounterOverflow,
            )?;
        }
        if !semantic_progress && !wait_changed && wake_notifications != 0 {
            self.wake_streak = self
                .wake_streak
                .checked_add(wake_notifications)
                .ok_or(CurrentThreadExecutorError::WakeStreakOverflow)?;
            if self.wake_streak > policy.wake_budget.get() {
                return Err(CurrentThreadExecutorError::WakeBudgetExceeded {
                    limit: policy.wake_budget,
                });
            }
        }
        if self
            .expired_wait
            .is_some_and(|expired| waits.earliest_deadline != Some(expired.deadline))
        {
            self.expired_wait = None;
        }
        let poll_budget_exceeded = self.poll_streak > policy.poll_budget.get();
        self.observed_progress = progress;
        self.observed_wait = waits;
        self.observed_wake = wake;
        Ok(PendingObservation {
            wake_notifications,
            poll_budget_exceeded,
            semantic_progress,
            wait_changed,
        })
    }

    fn expired_action(
        &mut self,
        waits: WaitSnapshot,
        now: MonotonicInstant,
    ) -> Result<ExpiredAction, CurrentThreadExecutorError> {
        validate_wait_snapshot(waits)?;
        let Some(deadline) = waits.earliest_deadline else {
            self.expired_wait = None;
            return Ok(ExpiredAction::NotExpired);
        };
        if now < deadline {
            self.expired_wait = None;
            return Ok(ExpiredAction::NotExpired);
        }
        match self.expired_wait {
            Some(expired) if expired.deadline == deadline => {
                Ok(ExpiredAction::Stalled { deadline })
            }
            Some(_) | None => {
                self.expired_wait = Some(ExpiredWait { deadline });
                Ok(ExpiredAction::Repoll)
            }
        }
    }
}

fn checked_streak(
    value: u64,
    overflow: CurrentThreadExecutorError,
) -> Result<u64, CurrentThreadExecutorError> {
    value.checked_add(1).ok_or(overflow)
}

fn wake_bookkeeping_is_valid(wake: WakeBookkeeping) -> bool {
    wake.notifications
        .checked_add(1)
        .is_some_and(|next| next == wake.generation.get())
}

fn validate_wait_snapshot(snapshot: WaitSnapshot) -> Result<(), CurrentThreadExecutorError> {
    match (snapshot.registrations, snapshot.earliest_deadline) {
        (0, None) | (1.., Some(_)) => Ok(()),
        _ => Err(CurrentThreadExecutorError::WaitSnapshotInconsistent),
    }
}

fn register_cancellation_waker(
    cancellation: &CancellationToken,
    waker: &Waker,
) -> Result<(), CurrentThreadExecutorError> {
    panic::catch_unwind(AssertUnwindSafe(|| cancellation.register_waker(waker))).map_err(
        |payload| {
            discard_panic_payload(payload);
            CurrentThreadExecutorError::CancellationPanicked
        },
    )
}

fn request_immediate_cancellation(cancellation: &CancellationToken) -> Result<(), ()> {
    panic::catch_unwind(AssertUnwindSafe(|| cancellation.cancel_immediate())).map_err(|payload| {
        discard_panic_payload(payload);
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "each snapshot and capability is explicit at this race boundary"
)]
fn close_no_wait_race(
    progress: &ProgressHandle,
    waits: &WaitRegistryHandle,
    signal: &WakeSignal,
    cancellation: CancellationToken,
    observed_progress: ProgressSnapshot,
    observed_wait: WaitSnapshot,
    observed_wake: WakeBookkeeping,
    grace: Duration,
) -> Result<bool, CurrentThreadExecutorError> {
    let before_progress = progress.snapshot();
    let before_wait = waits.snapshot();
    validate_wait_snapshot(before_wait)?;
    let before_wake = signal.snapshot()?;
    if cancellation.is_cancelled() {
        return Err(CurrentThreadExecutorError::Cancelled);
    }
    if before_progress.generation != observed_progress.generation
        || before_wait.generation != observed_wait.generation
        || before_wake.generation != observed_wake.generation
    {
        return Ok(true);
    }
    thread::park_timeout(grace);
    if cancellation.is_cancelled() {
        return Err(CurrentThreadExecutorError::Cancelled);
    }
    let after_progress = progress.snapshot();
    let after_wait = waits.snapshot();
    validate_wait_snapshot(after_wait)?;
    let after_wake = signal.snapshot()?;
    Ok(after_progress.generation != observed_progress.generation
        || after_wait.generation != observed_wait.generation
        || after_wake.generation != observed_wake.generation)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ParkOutcome {
    Changed,
    Deadline,
}

#[allow(
    clippy::too_many_arguments,
    reason = "each snapshot and capability is explicit at this park boundary"
)]
fn park_until_wait(
    progress: &ProgressHandle,
    waits: &WaitRegistryHandle,
    driver: &TimeDriverHandle,
    signal: &WakeSignal,
    cancellation: &CancellationToken,
    observed_progress: ProgressSnapshot,
    observed_wait: WaitSnapshot,
    observed_wake: WakeBookkeeping,
    grace: Duration,
) -> Result<ParkOutcome, CurrentThreadExecutorError> {
    validate_wait_snapshot(observed_wait)?;
    let deadline = observed_wait
        .earliest_deadline
        .ok_or(CurrentThreadExecutorError::WaitSnapshotInconsistent)?;
    loop {
        if cancellation.is_cancelled() {
            return Err(CurrentThreadExecutorError::Cancelled);
        }
        let current_progress = progress.snapshot();
        let current_wait = waits.snapshot();
        validate_wait_snapshot(current_wait)?;
        let current_wake = signal.snapshot()?;
        if current_progress.generation != observed_progress.generation
            || current_wait.generation != observed_wait.generation
            || current_wake.generation != observed_wake.generation
        {
            return Ok(ParkOutcome::Changed);
        }
        // A caller can unpark this thread spuriously.  A changed wake count
        // is an exact notification; an unchanged snapshot simply returns to
        // this park loop without polling the future.
        let now = MonotonicInstant::from_duration(
            driver
                .try_now()
                .map_err(|source| CurrentThreadExecutorError::TimeDriver { source })?
                .monotonic,
        );
        if now >= deadline {
            if !grace.is_zero() {
                thread::park_timeout(grace.min(MAX_PARK_CHUNK));
                let wake_after = signal.snapshot()?;
                let wait_after = waits.snapshot();
                validate_wait_snapshot(wait_after)?;
                let progress_after = progress.snapshot();
                if wake_after.generation != observed_wake.generation
                    || wait_after.generation != observed_wait.generation
                    || progress_after.generation != observed_progress.generation
                {
                    return Ok(ParkOutcome::Changed);
                }
            }
            return Ok(ParkOutcome::Deadline);
        }
        let remaining = deadline
            .duration_since(now)
            .ok_or(CurrentThreadExecutorError::WaitSnapshotInconsistent)?;
        thread::park_timeout(remaining.min(MAX_PARK_CHUNK));
        let wake_after = signal.snapshot()?;
        let wait_after = waits.snapshot();
        validate_wait_snapshot(wait_after)?;
        let progress_after = progress.snapshot();
        if wake_after.generation != observed_wake.generation
            || wait_after.generation != observed_wait.generation
            || progress_after.generation != observed_progress.generation
        {
            return Ok(ParkOutcome::Changed);
        }
        // No state changed.  Re-read the injected driver clock on the next
        // iteration; a spurious unpark therefore never becomes a busy poll.
    }
}

fn drop_pinned_future<F>(future: Pin<Box<F>>) -> bool {
    panic::catch_unwind(AssertUnwindSafe(|| drop(future)))
        .map_err(|payload| {
            discard_panic_payload(payload);
        })
        .is_err()
}

fn drop_future<F>(future: F) -> bool {
    panic::catch_unwind(AssertUnwindSafe(|| drop(future)))
        .map_err(|payload| {
            discard_panic_payload(payload);
        })
        .is_err()
}

fn discard_panic_payload(payload: Box<dyn Any + Send>) {
    if let Err(second_payload) = panic::catch_unwind(AssertUnwindSafe(|| drop(payload))) {
        std::mem::forget(second_payload);
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "executor tests use assertion-context setup and deterministic fixtures"
)]
mod tests {
    use super::*;
    use jmeter_rs_model::NodeId;
    use jmeter_rs_runtime::{
        CompiledPackages, ComponentError, ComponentFuture, ControllerNode, ControllerProgram,
        Deadline, EnginePlan, OpaqueWaitIdentity, RuntimeCapabilities, RuntimeEngine,
        RuntimeEngineFuture, SampleContext, SamplePackage, Sampler, SamplerFactory, SamplerOutput,
        Scheduler, ThreadGroupPlan, WaitOwnerClass, WaitRegistrationSpec, WaitRegistry,
        WaitRegistryConfig, WakeRegistration,
    };
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::sync::{Arc, Barrier};

    fn driver() -> (crate::time_driver::TimeDriver, TimeDriverHandle) {
        let owner = crate::time_driver::TimeDriver::new(
            crate::time_driver::TimeDriverLimits::new(16).expect("driver limits"),
        )
        .expect("driver");
        let handle = owner.handle();
        (owner, handle)
    }

    fn runtime_engine() -> RuntimeEngine {
        RuntimeEngine::new(
            EnginePlan::new(),
            RuntimeCapabilities::default(),
            "executor-test",
            "localhost",
        )
    }

    fn zero_race_policy(poll_budget: u64, wake_budget: u64) -> CurrentThreadExecutorPolicy {
        CurrentThreadExecutorPolicy::new(poll_budget, wake_budget)
            .expect("policy")
            .with_driver_delivery_grace(Duration::ZERO)
            .with_no_wait_race_grace(Duration::ZERO)
    }

    #[test]
    fn immediate_ready_does_not_park() {
        let (owner, _handle) = driver();
        let mut engine = runtime_engine();
        let future_progress = engine.run();
        let progress = future_progress.progress_handle();
        let waits = owner.wait_registry();
        let time = owner.handle();
        let cancellation = CancellationToken::new();
        let value = drive(
            std::future::ready(7_u8),
            progress,
            waits,
            time,
            cancellation,
        )
        .expect("ready");
        assert_eq!(value, 7);
        owner.finalize().expect("finalize");
    }

    #[test]
    fn runtime_engine_constructor_uses_exact_progress_handle() {
        let (owner, _handle) = driver();
        let mut engine = runtime_engine();
        let future = engine.run();
        let result = CurrentThreadExecutor::from_runtime_engine(
            future,
            owner.wait_registry(),
            owner.handle(),
            CancellationToken::new(),
        )
        .run();
        assert!(result.is_ok());
        owner.finalize().expect("finalize");
    }

    struct WakeThenReady {
        polled: bool,
    }

    impl Future for WakeThenReady {
        type Output = u8;

        fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
            if self.polled {
                Poll::Ready(9)
            } else {
                self.polled = true;
                context.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    #[test]
    fn synchronous_wake_before_park_is_repolled() {
        let (owner, _handle) = driver();
        let mut engine = runtime_engine();
        let future_progress = engine.run();
        let progress = future_progress.progress_handle();
        let waits = owner.wait_registry();
        let time = owner.handle();
        let cancellation = CancellationToken::new();
        let value = drive_with_policy(
            WakeThenReady { polled: false },
            progress,
            waits,
            time,
            cancellation,
            zero_race_policy(4, 4),
        )
        .expect("synchronous wake");
        assert_eq!(value, 9);
        owner.finalize().expect("finalize");
    }

    #[test]
    fn semantic_progress_resets_both_consecutive_budgets() {
        let progress = ProgressSnapshot {
            generation: NonZeroU64::new(1).expect("generation"),
            terminal: ProgressTerminalState::Running,
        };
        let waits = WaitSnapshot::initial();
        let wake = WakeBookkeeping {
            generation: NonZeroU64::new(1).expect("generation"),
            notifications: 0,
        };
        let mut state = DriveState::new(progress, waits, wake);
        state.poll_streak = 8;
        state.wake_streak = 8;
        let next_progress = ProgressSnapshot {
            generation: NonZeroU64::new(2).expect("generation"),
            terminal: ProgressTerminalState::Running,
        };
        let pending = state
            .observe(next_progress, waits, wake, zero_race_policy(1, 1))
            .expect("semantic progress");
        assert!(!pending.poll_budget_exceeded);
        assert_eq!(state.poll_streak, 0);
        assert_eq!(state.wake_streak, 0);
    }

    #[test]
    fn wait_generation_resets_only_poll_budget() {
        let progress = ProgressSnapshot::initial();
        let waits = WaitSnapshot::initial();
        let wake = WakeBookkeeping {
            generation: NonZeroU64::MIN,
            notifications: 0,
        };
        let mut state = DriveState::new(progress, waits, wake);
        state.poll_streak = 8;
        state.wake_streak = 8;
        let next_wait = WaitSnapshot {
            registrations: 1,
            earliest_deadline: Some(MonotonicInstant::zero()),
            generation: NonZeroU64::new(2).expect("generation"),
        };
        let pending = state
            .observe(progress, next_wait, wake, zero_race_policy(1, 1))
            .expect("wait generation change");
        assert!(!pending.poll_budget_exceeded);
        assert_eq!(state.poll_streak, 0);
        assert_eq!(state.wake_streak, 8);
    }

    #[test]
    fn wait_generation_resets_poll_budget_without_semantic_progress() {
        let (owner, _handle) = driver();
        let mut engine = runtime_engine();
        let future_progress = engine.run();
        let progress = future_progress.progress_handle();
        let waits = owner.wait_registry();
        let time = owner.handle();
        let token = CancellationToken::new();
        let mut registration: Option<WakeRegistration> = None;
        let register_time = time.clone();
        let register_token = token.clone();
        let future = std::future::poll_fn(move |context| {
            if registration.is_none() {
                let spec = WaitRegistrationSpec::new(
                    WaitOwnerClass::Provider,
                    OpaqueWaitIdentity::from_u64(1),
                    MonotonicInstant::zero(),
                );
                registration = Some(waits_owner_register(&register_time, spec, &register_token));
                return Poll::Pending;
            }
            registration.take();
            context.waker().wake_by_ref();
            Poll::Ready(11_u8)
        });
        let value = drive_with_policy(future, progress, waits, time, token, zero_race_policy(1, 4))
            .expect("wait generation reset");
        assert_eq!(value, 11);
        owner.finalize().expect("finalize");
    }

    fn waits_owner_register(
        time: &TimeDriverHandle,
        spec: WaitRegistrationSpec,
        token: &CancellationToken,
    ) -> WakeRegistration {
        Scheduler::register_wake(time, Deadline::at(spec.deadline()), 1, token).expect("register")
    }

    struct SelfWakeStorm;

    impl Future for SelfWakeStorm {
        type Output = ();

        fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
            context.waker().wake_by_ref();
            Poll::Pending
        }
    }

    #[test]
    fn repeated_self_wakes_hit_wake_storm_budget() {
        let (owner, _handle) = driver();
        let mut engine = runtime_engine();
        let future_progress = engine.run();
        let progress = future_progress.progress_handle();
        let waits = owner.wait_registry();
        let time = owner.handle();
        let cancellation = CancellationToken::new();
        let error = drive_with_policy(
            SelfWakeStorm,
            progress,
            waits,
            time,
            cancellation,
            zero_race_policy(64, 2),
        )
        .expect_err("wake storm");
        assert_eq!(error.code(), "runtime.executor.wake-budget");
        owner.finalize().expect("finalize");
    }

    #[test]
    fn repeated_self_wakes_hit_poll_budget() {
        let (owner, _handle) = driver();
        let mut engine = runtime_engine();
        let future_progress = engine.run();
        let progress = future_progress.progress_handle();
        let waits = owner.wait_registry();
        let time = owner.handle();
        let cancellation = CancellationToken::new();
        let error = drive_with_policy(
            SelfWakeStorm,
            progress,
            waits,
            time,
            cancellation,
            zero_race_policy(2, 64),
        )
        .expect_err("poll storm");
        assert_eq!(error.code(), "runtime.executor.poll-budget");
        owner.finalize().expect("finalize");
    }

    #[test]
    fn pending_without_wait_stalls_after_one_zero_window() {
        let (owner, _handle) = driver();
        let mut engine = runtime_engine();
        let future_progress = engine.run();
        let progress = future_progress.progress_handle();
        let waits = owner.wait_registry();
        let time = owner.handle();
        let cancellation = CancellationToken::new();
        let polls = Arc::new(AtomicUsize::new(0));
        let poll_count = Arc::clone(&polls);
        let future = std::future::poll_fn(move |_| {
            poll_count.fetch_add(1, Ordering::AcqRel);
            Poll::<()>::Pending
        });
        let error = drive_with_policy(
            future,
            progress,
            waits,
            time,
            cancellation,
            zero_race_policy(64, 64),
        )
        .expect_err("missing wait");
        assert_eq!(error.code(), "runtime.executor.stalled");
        assert_eq!(polls.load(Ordering::Acquire), 1);
        owner.finalize().expect("finalize");
    }

    struct NeverReadySampler;

    impl Sampler for NeverReadySampler {
        fn sample<'a>(
            &'a self,
            _context: &'a mut SampleContext<'_>,
        ) -> ComponentFuture<'a, SamplerOutput> {
            Box::pin(std::future::poll_fn(|_| {
                Poll::<Result<SamplerOutput, ComponentError>>::Pending
            }))
        }
    }

    struct NeverReadySamplerFactory;

    impl SamplerFactory for NeverReadySamplerFactory {
        fn create(&self) -> Arc<dyn Sampler> {
            Arc::new(NeverReadySampler)
        }
    }

    struct ProgressThenPending<'a> {
        inner: RuntimeEngineFuture<'a>,
        progress: ProgressHandle,
        waits: WaitRegistry,
        first: bool,
    }

    impl Future for ProgressThenPending<'_> {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
            if self.first {
                self.first = false;
                let mut inner_context = Context::from_waker(Waker::noop());
                assert!(
                    Pin::new(&mut self.inner)
                        .poll(&mut inner_context)
                        .is_pending(),
                    "inner runtime must remain pending at the semantic-progress boundary"
                );
                assert!(self.progress.snapshot().generation > NonZeroU64::MIN);
                let registration = self
                    .waits
                    .register(WaitRegistrationSpec::new(
                        WaitOwnerClass::Provider,
                        OpaqueWaitIdentity::from_u64(88),
                        MonotonicInstant::zero(),
                    ))
                    .expect("regression wait");
                registration.retire().expect("retire regression wait");
                // There is deliberately no wake here: the progress snapshot
                // and wait generation are the only observations making this
                // continuation immediately runnable.
                return Poll::Pending;
            }
            Poll::Ready(())
        }
    }

    #[test]
    fn semantic_progress_retiring_wait_is_repolled_before_stall() {
        let (owner, _handle) = driver();
        let time = owner.handle();
        let package = SamplePackage::builder(NodeId::new(1), Arc::new(NeverReadySampler))
            .sampler_factory(Arc::new(NeverReadySamplerFactory))
            .build();
        let packages = CompiledPackages::from_packages([package]).expect("packages");
        let controller = ControllerProgram::compile(ControllerNode::sample(1)).expect("controller");
        let group = ThreadGroupPlan::new(
            NodeId::new(2),
            "executor-regression",
            1,
            controller,
            packages,
        )
        .expect("group");
        let mut plan = EnginePlan::new();
        plan.push_group(group).expect("group admission");
        let capabilities = RuntimeCapabilities::default().with_scheduler(Arc::new(time.clone()));
        let mut engine = RuntimeEngine::new(plan, capabilities, "executor-test", "localhost");
        let inner = engine.run();
        let progress = inner.progress_handle();
        let waits = WaitRegistry::new(WaitRegistryConfig::default());
        drive_with_policy(
            ProgressThenPending {
                inner,
                progress: progress.clone(),
                waits: waits.clone(),
                first: true,
            },
            progress,
            waits.handle(),
            time,
            CancellationToken::new(),
            zero_race_policy(64, 64),
        )
        .expect("semantic progress after wait retirement");
        assert_eq!(waits.snapshot().registrations, 0);
        waits.shutdown().expect("wait shutdown");
        owner.finalize().expect("finalize");
    }

    struct DeadlineReady {
        time: TimeDriverHandle,
        token: CancellationToken,
        first: bool,
        registrations: Vec<WakeRegistration>,
    }

    impl Future for DeadlineReady {
        type Output = u8;

        fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
            if self.first {
                self.first = false;
                let first = jmeter_rs_runtime::Scheduler::register_wake(
                    &self.time,
                    Deadline::at(MonotonicInstant::from_duration(Duration::from_secs(3_600))),
                    1,
                    &self.token,
                )
                .expect("wait");
                self.registrations.push(first);
                let earlier = jmeter_rs_runtime::Scheduler::register_wake(
                    &self.time,
                    Deadline::at(MonotonicInstant::zero()),
                    2,
                    &self.token,
                )
                .expect("earlier wait");
                self.registrations.push(earlier);
                context.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.registrations.clear();
            Poll::Ready(12)
        }
    }

    #[test]
    fn earlier_deadline_registration_wakes_exact_executor_waker() {
        let (owner, _handle) = driver();
        let mut engine = runtime_engine();
        let future_progress = engine.run();
        let progress = future_progress.progress_handle();
        let waits = owner.wait_registry();
        let time = owner.handle();
        let token = CancellationToken::new();
        let value = drive_with_policy(
            DeadlineReady {
                time: time.clone(),
                token: token.clone(),
                first: true,
                registrations: Vec::new(),
            },
            progress,
            waits,
            time,
            token,
            zero_race_policy(8, 8),
        )
        .expect("deadline wake");
        assert_eq!(value, 12);
        owner.finalize().expect("finalize");
    }

    #[test]
    fn expired_provider_wait_is_repolled_once_then_stalls() {
        let (owner, _handle) = driver();
        let mut engine = runtime_engine();
        let future_progress = engine.run();
        let progress = future_progress.progress_handle();
        let time = owner.handle();
        let token = CancellationToken::new();
        let token_observer = token.clone();
        let polls = Arc::new(AtomicUsize::new(0));
        let registry = WaitRegistry::new(WaitRegistryConfig::default());
        let waits = registry.handle();
        // Register directly in a bounded registry fixture for a deterministic
        // provider-watchdog seam.  No worker owns this fixture's registration,
        // so the finite wait remains unchanged until executor finalization
        // drops the future.
        let registration = registry
            .register(WaitRegistrationSpec::new(
                WaitOwnerClass::Provider,
                OpaqueWaitIdentity::from_u64(44),
                MonotonicInstant::zero(),
            ))
            .expect("provider wait");
        let poll_count = Arc::clone(&polls);
        let future = std::future::poll_fn(move |_| {
            poll_count.fetch_add(1, Ordering::AcqRel);
            let _ = &registration;
            Poll::<()>::Pending
        });
        let error = drive_with_policy(
            future,
            progress,
            waits,
            time,
            token,
            zero_race_policy(64, 64),
        )
        .expect_err("stalled provider");
        assert_eq!(error.code(), "runtime.executor.stalled-provider");
        assert_eq!(polls.load(Ordering::Acquire), 2);
        assert!(token_observer.is_cancelled());
        registry.shutdown().expect("registry shutdown");
        owner.finalize().expect("finalize");
    }

    #[test]
    fn unchanged_expired_wait_is_repolled_once_then_stalled_provider() {
        let progress = ProgressSnapshot::initial();
        let waits = WaitSnapshot {
            registrations: 1,
            earliest_deadline: Some(MonotonicInstant::zero()),
            generation: NonZeroU64::MIN,
        };
        let wake = WakeBookkeeping {
            generation: NonZeroU64::MIN,
            notifications: 0,
        };
        let mut state = DriveState::new(progress, waits, wake);
        assert_eq!(
            state
                .expired_action(waits, MonotonicInstant::zero())
                .expect("first expired observation"),
            ExpiredAction::Repoll
        );
        assert_eq!(
            state
                .expired_action(waits, MonotonicInstant::zero())
                .expect("unchanged expired observation"),
            ExpiredAction::Stalled {
                deadline: MonotonicInstant::zero()
            }
        );
    }

    #[test]
    fn expired_wait_marker_survives_unrelated_progress_or_wait_changes() {
        let progress = ProgressSnapshot::initial();
        let waits = WaitSnapshot {
            registrations: 1,
            earliest_deadline: Some(MonotonicInstant::zero()),
            generation: NonZeroU64::MIN,
        };
        let wake = WakeBookkeeping {
            generation: NonZeroU64::MIN,
            notifications: 0,
        };
        let mut state = DriveState::new(progress, waits, wake);
        assert_eq!(
            state
                .expired_action(waits, MonotonicInstant::zero())
                .expect("first expired observation"),
            ExpiredAction::Repoll
        );
        let changed_wait = WaitSnapshot {
            generation: NonZeroU64::new(2).expect("generation"),
            ..waits
        };
        let changed_progress = ProgressSnapshot {
            generation: NonZeroU64::new(2).expect("generation"),
            terminal: ProgressTerminalState::Running,
        };
        state
            .observe(changed_progress, changed_wait, wake, zero_race_policy(8, 8))
            .expect("unrelated changes");
        assert_eq!(
            state
                .expired_action(changed_wait, MonotonicInstant::zero())
                .expect("unchanged expired wait"),
            ExpiredAction::Stalled {
                deadline: MonotonicInstant::zero()
            }
        );
    }

    struct DropObservesCancellation {
        saw_cancel: Arc<AtomicBool>,
        cancellation: CancellationToken,
    }

    impl Future for DropObservesCancellation {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Pending
        }
    }

    impl Drop for DropObservesCancellation {
        fn drop(&mut self) {
            if self.cancellation.is_cancelled() {
                self.saw_cancel.store(true, Ordering::Release);
            }
        }
    }

    struct DropPanics;

    impl Future for DropPanics {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Pending
        }
    }

    impl Drop for DropPanics {
        fn drop(&mut self) {
            panic!("intentional future-drop test panic");
        }
    }

    #[test]
    fn watchdog_cancels_before_future_drop() {
        let (owner, _handle) = driver();
        let mut engine = runtime_engine();
        let future_progress = engine.run();
        let progress = future_progress.progress_handle();
        let waits = owner.wait_registry();
        let time = owner.handle();
        let cancellation = CancellationToken::new();
        let saw_cancel = Arc::new(AtomicBool::new(false));
        let value = Arc::clone(&saw_cancel);
        let error = drive_with_policy(
            DropObservesCancellation {
                saw_cancel: value,
                cancellation: cancellation.clone(),
            },
            progress,
            waits,
            time,
            cancellation.clone(),
            zero_race_policy(64, 64),
        )
        .expect_err("watchdog");
        assert_eq!(error.code(), "runtime.executor.stalled");
        assert!(cancellation.is_cancelled());
        assert!(saw_cancel.load(Ordering::Acquire));
        owner.finalize().expect("finalize");
    }

    #[test]
    fn watchdog_primary_survives_future_drop_panic() {
        let (owner, _handle) = driver();
        let mut engine = runtime_engine();
        let future_progress = engine.run();
        let progress = future_progress.progress_handle();
        let waits = owner.wait_registry();
        let time = owner.handle();
        let cancellation = CancellationToken::new();
        let error = drive_with_policy(
            DropPanics,
            progress,
            waits,
            time,
            cancellation,
            zero_race_policy(64, 64),
        )
        .expect_err("watchdog with drop panic");
        match error {
            CurrentThreadExecutorError::PrimaryWithCleanup { primary, cleanup } => {
                assert_eq!(*primary, CurrentThreadExecutorError::Stalled);
                assert_eq!(cleanup, ExecutorCleanupError::FutureDropPanicked);
            }
            other => panic!("unexpected error: {other:?}"),
        }
        owner.finalize().expect("finalize");
    }

    #[test]
    fn long_representable_deadline_is_not_rejected() {
        let long = MonotonicInstant::from_duration(Duration::from_secs(90 * 24 * 60 * 60));
        let snapshot = WaitSnapshot {
            registrations: 1,
            earliest_deadline: Some(long),
            generation: NonZeroU64::MIN,
        };
        validate_wait_snapshot(snapshot).expect("long wait remains representable");
        let remaining = long
            .duration_since(MonotonicInstant::zero())
            .expect("remaining");
        assert_eq!(remaining, Duration::from_secs(90 * 24 * 60 * 60));
    }

    #[test]
    fn generation_and_counter_overflow_are_typed() {
        let signal = Arc::new(WakeSignal::new(thread::current()));
        signal.force_generation_for_test(NonZeroU64::new(u64::MAX).expect("max"));
        Waker::from(Arc::clone(&signal)).wake_by_ref();
        assert_eq!(
            signal.snapshot(),
            Err(CurrentThreadExecutorError::WakeGenerationOverflow)
        );
        let signal = Arc::new(WakeSignal::new(thread::current()));
        signal.force_notification_count_for_test(u64::MAX);
        Waker::from(Arc::clone(&signal)).wake_by_ref();
        assert_eq!(
            signal.snapshot(),
            Err(CurrentThreadExecutorError::WakeCounterOverflow)
        );
        // Exercise the pure checked streak seam as well; no wrapping is
        // allowed even when a policy itself is representably maximal.
        assert_eq!(
            checked_streak(u64::MAX, CurrentThreadExecutorError::PollCounterOverflow),
            Err(CurrentThreadExecutorError::PollCounterOverflow)
        );
        assert_eq!(
            checked_streak(u64::MAX, CurrentThreadExecutorError::WakeStreakOverflow),
            Err(CurrentThreadExecutorError::WakeStreakOverflow)
        );
        let progress = ProgressSnapshot::initial();
        let waits = WaitSnapshot::initial();
        let mut state = DriveState::new(
            progress,
            waits,
            WakeBookkeeping {
                generation: NonZeroU64::MIN,
                notifications: 0,
            },
        );
        assert_eq!(
            state.observe(
                progress,
                waits,
                WakeBookkeeping {
                    generation: NonZeroU64::new(2).expect("generation"),
                    notifications: 0,
                },
                zero_race_policy(8, 8),
            ),
            Err(CurrentThreadExecutorError::WakeBookkeepingInconsistent)
        );
    }

    #[test]
    fn spurious_unpark_does_not_change_exact_wake_bookkeeping() {
        let signal = Arc::new(WakeSignal::new(thread::current()));
        let observed = signal.snapshot().expect("initial wake state");
        let barrier = Arc::new(Barrier::new(2));
        let worker_signal = Arc::clone(&signal);
        let worker_barrier = Arc::clone(&barrier);
        let owner_thread = thread::current();
        let worker = thread::spawn(move || {
            // The worker deliberately unparks without going through the exact
            // executor waker, modeling an OS-level spurious unpark.
            let _ = worker_signal;
            worker_barrier.wait();
            owner_thread.unpark();
        });
        barrier.wait();
        thread::park();
        worker.join().expect("spurious-unpark worker");
        assert_eq!(signal.snapshot().expect("wake state"), observed);
    }

    #[test]
    fn poisoned_wake_bookkeeping_is_typed() {
        let signal = Arc::new(WakeSignal::new(thread::current()));
        let poisoned = Arc::clone(&signal);
        let worker = thread::spawn(move || {
            let _guard = poisoned.state.lock().expect("poison setup lock");
            panic!("intentional test poison");
        });
        let _ = worker.join();
        assert_eq!(
            signal.snapshot(),
            Err(CurrentThreadExecutorError::MutexPoisoned {
                lock: ExecutorLock::WakeBookkeeping,
            })
        );
    }

    #[test]
    fn time_driver_failure_is_typed() {
        let (owner, time) = driver();
        owner.finalize().expect("stop driver");
        let registry = WaitRegistry::new(WaitRegistryConfig::default());
        let waits = registry.handle();
        let mut engine = runtime_engine();
        let future_progress = engine.run();
        let progress = future_progress.progress_handle();
        let error = drive(
            std::future::ready(()),
            progress,
            waits,
            time,
            CancellationToken::new(),
        )
        .expect_err("stopped driver");
        assert!(matches!(
            error,
            CurrentThreadExecutorError::TimeDriver { .. }
        ));
        assert!(error.time_driver_source().is_some());
        registry.shutdown().expect("registry shutdown");
    }

    #[test]
    fn invalid_zero_budgets_are_typed() {
        assert_eq!(
            CurrentThreadExecutorPolicy::new(0, 1).expect_err("poll budget"),
            CurrentThreadExecutorError::InvalidBudget {
                budget: ExecutorBudget::Poll
            }
        );
        assert_eq!(
            CurrentThreadExecutorPolicy::new(1, 0).expect_err("wake budget"),
            CurrentThreadExecutorError::InvalidBudget {
                budget: ExecutorBudget::Wake
            }
        );
    }

    #[test]
    fn production_policy_matches_default_policy() {
        assert_eq!(
            CurrentThreadExecutorPolicy::production(),
            CurrentThreadExecutorPolicy::default()
        );
    }

    #[test]
    fn cleanup_failure_keeps_primary_error_and_both_cleanup_categories() {
        let primary = CurrentThreadExecutorError::StalledProvider {
            deadline: MonotonicInstant::zero(),
        };
        let combined = with_cleanup(primary.clone(), true, true);
        match combined {
            CurrentThreadExecutorError::PrimaryWithCleanup {
                primary: retained,
                cleanup,
            } => {
                assert_eq!(*retained, primary);
                assert_eq!(
                    cleanup,
                    ExecutorCleanupError::CancellationAndFutureDropPanicked
                );
            }
            other => panic!("unexpected cleanup result: {other:?}"),
        }
    }
}
