// SPDX-License-Identifier: Apache-2.0
//! One run-owned production clock, sleeper, and scheduler.
//!
//! The standalone application cannot use the runtime's epoch clock or its
//! immediate capabilities for a real run.  [`TimeDriver`] therefore owns one
//! monotonic/wall-clock origin, one bounded runtime scheduler, and one exact
//! worker thread.  The worker advances the runtime scheduler from the same
//! monotonic source used by [`Clock::now`], then parks on a condition variable
//! until the next absolute deadline or an explicit registration/shutdown
//! notification.
//!
//! A driver is a run owner.  Keep the owner alive until [`TimeDriver::finalize`]
//! has returned, and pass either the owner or [`TimeDriver::handle`] to
//! [`RuntimeCapabilities`](jmeter_rs_runtime::RuntimeCapabilities).  Handles
//! are cloneable views; they do not own the worker and therefore do not make
//! finalization optional.  `Drop` is a cancellation-and-join fallback only.
//!
//! Every admitted wait is intended to have two exact owners: the runtime
//! scheduler's linear wake registration and this run owner's bounded record.
//! The runtime wake-registration/`WaitRegistry` bridge is supplied by the
//! runtime contract; this module keeps no application-only substitute for
//! that semantic registration.

#![forbid(unsafe_code)]
#![allow(
    clippy::module_name_repetitions,
    reason = "the application capability is intentionally named by its owner and handles"
)]

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use jmeter_rs_results::WallTimestamp;
use jmeter_rs_runtime::{
    CancellationToken, CapabilityError, CapabilityFuture, Clock, ClockReading, Deadline,
    MonotonicInstant, OpaqueWaitIdentity, ResultWaitError, ResultWaitRegistrar,
    ResultWaitRegistrationHandle, ResultWaitSpec, ScheduledWake, Scheduler, SchedulerError,
    Sleeper, WaitOwnerClass, WaitRegistration, WaitRegistrationSpec, WaitRegistry,
    WaitRegistryConfig, WaitRegistryError, WaitRegistryHandle, WakeRegistration,
};

/// Maximum number of active registrations retained by a production driver.
///
/// This matches the runtime deterministic scheduler's hard bounded wake
/// registry.  Registrations are not limited by a product-defined duration;
/// a representable multi-month deadline is still valid.
pub const MAX_TIME_REGISTRATIONS: usize = 65_536;

/// Default active-registration capacity for one run.
pub const DEFAULT_TIME_REGISTRATIONS: usize = 65_536;

/// Maximum condition-variable wait used by the driver worker.
///
/// This is only an OS wait chunk.  It is not a schedule or operation cap.  A
/// long deadline is checked again after each chunk, avoiding platform timeout
/// representation limits while preserving the complete absolute deadline.
const MAX_WAIT_CHUNK: Duration = Duration::from_secs(24 * 60 * 60);

/// A finite policy for one run-owned time driver.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TimeDriverLimits {
    /// Maximum number of live absolute waits retained by this run.
    pub max_registrations: usize,
}

impl Default for TimeDriverLimits {
    fn default() -> Self {
        Self {
            max_registrations: DEFAULT_TIME_REGISTRATIONS,
        }
    }
}

impl TimeDriverLimits {
    /// Creates and validates a registration policy.
    pub fn new(max_registrations: usize) -> Result<Self, TimeDriverError> {
        let limits = Self { max_registrations };
        limits.validate()?;
        Ok(limits)
    }

    /// Validates this policy before a worker is started.
    pub fn validate(self) -> Result<(), TimeDriverError> {
        if self.max_registrations == 0 || self.max_registrations > MAX_TIME_REGISTRATIONS {
            return Err(TimeDriverError::InvalidLimits {
                field: TimeDriverLimitField::Registrations,
            });
        }
        Ok(())
    }
}

/// The numeric policy field that made a time-driver limit invalid.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TimeDriverLimitField {
    /// The active-registration bound was zero or too large.
    Registrations,
}

impl TimeDriverLimitField {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Registrations => "registrations",
        }
    }
}

/// The clock axis that could not be represented without wrapping.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TimeDriverClockAxis {
    /// Monotonic elapsed time from the run origin.
    Monotonic,
    /// Wall time in Unix epoch milliseconds.
    Wall,
}

impl TimeDriverClockAxis {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Monotonic => "monotonic",
            Self::Wall => "wall",
        }
    }
}

/// Stable failures returned by the production time owner and its handles.
///
/// Error payloads contain only bounded numeric values or stable enum names.
/// No system error text, path, hostname, or request data crosses this
/// boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TimeDriverError {
    /// A finite driver limit was invalid.
    InvalidLimits { field: TimeDriverLimitField },
    /// The wall clock could not be read at run construction.
    ClockOrigin,
    /// A clock axis overflowed during a checked projection.
    ClockOverflow { axis: TimeDriverClockAxis },
    /// The monotonic source moved backwards.
    ClockMovedBackward {
        /// Earlier monotonic reading.
        previous: Duration,
        /// Reversed monotonic reading.
        current: Duration,
    },
    /// The owner has begun shutdown and cannot admit a new wait.
    Stopped,
    /// The active-registration bound was reached.
    Capacity { limit: usize },
    /// A provider wait used the reserved zero identity/key.
    InvalidProviderKey,
    /// A nonzero runtime registration ID could not be represented.
    RegistrationIdOverflow,
    /// A checked internal wake-epoch increment overflowed.
    GenerationOverflow,
    /// The wrapped runtime scheduler rejected an operation.
    ///
    /// Only the stable scheduler code is retained; runtime `Unsupported`
    /// text is intentionally discarded at this application boundary.
    Scheduler { code: &'static str },
    /// The exact worker thread could not be started.
    WorkerStart,
    /// The exact worker thread panicked.
    WorkerPanic,
    /// Joining the exact worker failed.
    WorkerJoin,
    /// Finalization was attempted by the exact worker itself.
    FinalizeFromWorker,
    /// A bounded diagnostic counter overflowed.
    DiagnosticOverflow,
}

impl TimeDriverError {
    /// Returns a stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidLimits { .. } => "app.time-driver.limits",
            Self::ClockOrigin => "app.time-driver.clock-origin",
            Self::ClockOverflow { .. } => "app.time-driver.clock-overflow",
            Self::ClockMovedBackward { .. } => "app.time-driver.clock-backward",
            Self::Stopped => "app.time-driver.stopped",
            Self::Capacity { .. } => "app.time-driver.capacity",
            Self::InvalidProviderKey => "app.time-driver.provider-key",
            Self::RegistrationIdOverflow => "app.time-driver.registration-id-overflow",
            Self::GenerationOverflow => "app.time-driver.generation-overflow",
            Self::Scheduler { code } => code,
            Self::WorkerStart => "app.time-driver.worker-start",
            Self::WorkerPanic => "app.time-driver.worker-panic",
            Self::WorkerJoin => "app.time-driver.worker-join",
            Self::FinalizeFromWorker => "app.time-driver.finalize-from-worker",
            Self::DiagnosticOverflow => "app.time-driver.diagnostic-overflow",
        }
    }
}

impl fmt::Display for TimeDriverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits { field } => {
                write!(formatter, "{}: {}", self.code(), field.as_str())
            }
            Self::ClockOverflow { axis } => write!(formatter, "{}: {}", self.code(), axis.as_str()),
            Self::ClockMovedBackward { previous, current } => write!(
                formatter,
                "{}: previous={previous:?}, current={current:?}",
                self.code()
            ),
            Self::Capacity { limit } => write!(formatter, "{}: limit={limit}", self.code()),
            // Preserve only the stable scheduler capability code.  In
            // particular, never expose `SchedulerError::Unsupported`'s
            // caller-provided text through this bounded app boundary.
            Self::Scheduler { code } => formatter.write_str(code),
            Self::ClockOrigin
            | Self::Stopped
            | Self::InvalidProviderKey
            | Self::RegistrationIdOverflow
            | Self::GenerationOverflow
            | Self::WorkerStart
            | Self::WorkerPanic
            | Self::WorkerJoin
            | Self::FinalizeFromWorker
            | Self::DiagnosticOverflow => formatter.write_str(self.code()),
        }
    }
}

impl std::error::Error for TimeDriverError {}

impl From<SchedulerError> for TimeDriverError {
    fn from(error: SchedulerError) -> Self {
        match error {
            SchedulerError::Capacity { limit } => Self::Capacity { limit },
            SchedulerError::WakeIdOverflow => Self::RegistrationIdOverflow,
            other => Self::Scheduler { code: other.code() },
        }
    }
}

impl From<WaitRegistryError> for TimeDriverError {
    fn from(error: WaitRegistryError) -> Self {
        match error {
            WaitRegistryError::Capacity { limit } => Self::Capacity { limit },
            WaitRegistryError::GenerationOverflow => Self::GenerationOverflow,
            other => Self::Scheduler { code: other.code() },
        }
    }
}

/// Summary returned after exact worker finalization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimeDriverFinalizeReport {
    /// Number of registrations cancelled as part of owner shutdown.
    pub cancelled_registrations: usize,
    /// Whether the exact worker observed a panic.
    pub worker_panicked: bool,
}

/// A bounded, read-only diagnostic snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimeDriverDiagnostics {
    /// Number of registrations admitted since construction.
    pub registrations: u64,
    /// Number of registrations consumed by their deadlines.
    pub completed_registrations: u64,
    /// Number of registrations cancelled explicitly or by owner shutdown.
    pub cancelled_registrations: u64,
    /// Number of worker wake/advance passes.
    pub worker_advances: u64,
    /// Number of currently retained registration records.
    pub active_registrations: usize,
    /// Earliest deadline currently known to the runtime scheduler.
    pub earliest_deadline: Option<MonotonicInstant>,
    /// Whether the owner has stopped accepting registrations.
    pub stopped: bool,
    /// Last stable error observed by the owner, if any.
    pub last_error: Option<&'static str>,
}

#[derive(Debug)]
struct SystemClockSource {
    monotonic_origin: Instant,
    wall_origin_millis: i64,
}

impl SystemClockSource {
    fn new() -> Result<Self, TimeDriverError> {
        let wall_origin_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| i64::try_from(duration.as_millis()).ok())
            .ok_or(TimeDriverError::ClockOrigin)?;
        Ok(Self {
            monotonic_origin: Instant::now(),
            wall_origin_millis,
        })
    }

    fn reading(&self) -> Result<ClockReading, TimeDriverError> {
        let monotonic = self.monotonic_origin.elapsed();
        // The elapsed value is bounded by the process lifetime.  Still use
        // checked arithmetic so a far-future platform cannot silently extend
        // a deadline or wrap a result timestamp.
        let elapsed_millis =
            i64::try_from(monotonic.as_millis()).map_err(|_| TimeDriverError::ClockOverflow {
                axis: TimeDriverClockAxis::Wall,
            })?;
        let wall_millis = self.wall_origin_millis.checked_add(elapsed_millis).ok_or(
            TimeDriverError::ClockOverflow {
                axis: TimeDriverClockAxis::Wall,
            },
        )?;
        Ok(ClockReading {
            wall: WallTimestamp::from_millis(wall_millis),
            monotonic,
        })
    }
}

trait ClockSource: Send + Sync + fmt::Debug {
    fn reading(&self) -> Result<ClockReading, TimeDriverError>;
}

impl ClockSource for SystemClockSource {
    fn reading(&self) -> Result<ClockReading, TimeDriverError> {
        Self::reading(self)
    }
}

#[derive(Debug)]
struct WaitState {
    stopped: bool,
    in_flight_registrations: usize,
    /// Internal condition-variable event epoch. Runtime semantic wait
    /// generations live in the paired `WaitRegistry`; this epoch only closes
    /// the map-publication wake race for the single owner worker.
    wake_epoch: u64,
    failure: Option<TimeDriverError>,
}

#[derive(Debug, Default)]
struct DiagnosticState {
    registrations: u64,
    completed_registrations: u64,
    cancelled_registrations: u64,
    worker_advances: u64,
    last_error: Option<&'static str>,
    overflowed: bool,
}

type WakeRegistrationCallback =
    dyn Fn(u64, &CancellationToken) -> Result<bool, SchedulerError> + Send + Sync + 'static;
type WorkerNotify = dyn Fn() + Send + Sync + 'static;

struct DriverWakeRecord {
    wake: ScheduledWake,
    token: CancellationToken,
    wait_registration: WaitRegistration,
}

#[derive(Debug, Default)]
struct SchedulerShutdownState {
    started: bool,
    result: Option<Result<usize, SchedulerError>>,
}

struct DriverSchedulerState {
    wakes: Mutex<BTreeMap<u64, DriverWakeRecord>>,
    shutdown: Mutex<SchedulerShutdownState>,
    shutdown_wake: Condvar,
    notify: Mutex<Option<Arc<WorkerNotify>>>,
    owner: Arc<WakeRegistrationCallback>,
    wait_registry: WaitRegistry,
}

impl fmt::Debug for DriverSchedulerState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DriverSchedulerState")
            .field("active", &Self::lock(&self.wakes).len())
            .finish_non_exhaustive()
    }
}

impl DriverSchedulerState {
    fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
        value
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn cancel_registration(
        &self,
        id: u64,
        token: &CancellationToken,
    ) -> Result<bool, SchedulerError> {
        let Some(record) = Self::lock(&self.wakes).remove(&id) else {
            return Ok(false);
        };
        let retire_result = record.wait_registration.retire();
        drop(record.wait_registration);
        if let Err(error) = retire_result {
            // Keep a failed callback visible to the owner while ensuring the
            // exact token is not stranded.  Drop uses the registry's bounded
            // cleanup policy for the final retirement attempt.
            let wake_error = wake_token(token).err();
            return Err(wake_error.unwrap_or_else(|| wait_scheduler_error(error)));
        }
        Ok(true)
    }

    fn notify_worker(&self) {
        let notify = Self::lock(&self.notify).clone();
        if let Some(notify) = notify {
            // The callback is cloned under the short state lock and invoked
            // only after that lock has been released.
            notify();
        }
    }
}

/// The application-owned bounded scheduler paired with the runtime wait
/// registry.  Runtime `WakeRegistration` values remain linear handles; this
/// map retains only each wake's exact ID, deadline, token, and one RAII wait
/// registration, never a second runtime handle.
struct DriverScheduler {
    state: Arc<DriverSchedulerState>,
    now: Arc<Mutex<MonotonicInstant>>,
    next_id: Arc<std::sync::atomic::AtomicU64>,
    max_wakes: usize,
}

impl fmt::Debug for DriverScheduler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DriverScheduler")
            .field("active", &self.active_count())
            .field("next_deadline", &self.next_deadline())
            .finish()
    }
}

impl DriverScheduler {
    fn new(registry: WaitRegistry, now: MonotonicInstant, max_wakes: usize) -> Self {
        let state = Arc::new_cyclic(|weak_state: &std::sync::Weak<DriverSchedulerState>| {
            let weak_state = weak_state.clone();
            let owner: Arc<WakeRegistrationCallback> = Arc::new(move |id, token| {
                let Some(state) = weak_state.upgrade() else {
                    return Ok(false);
                };
                state.cancel_registration(id, token)
            });
            DriverSchedulerState {
                wakes: Mutex::new(BTreeMap::new()),
                shutdown: Mutex::new(SchedulerShutdownState::default()),
                shutdown_wake: Condvar::new(),
                notify: Mutex::new(None),
                owner,
                wait_registry: registry.clone(),
            }
        });
        Self {
            state,
            now: Arc::new(Mutex::new(now)),
            next_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            max_wakes,
        }
    }

    fn set_worker_notify(&self, notify: Arc<WorkerNotify>) {
        *DriverSchedulerState::lock(&self.state.notify) = Some(notify);
    }

    fn active_count(&self) -> usize {
        DriverSchedulerState::lock(&self.state.wakes).len()
    }

    fn is_active(&self, id: u64) -> bool {
        DriverSchedulerState::lock(&self.state.wakes).contains_key(&id)
    }

    fn next_deadline(&self) -> Option<Deadline> {
        DriverSchedulerState::lock(&self.state.wakes)
            .values()
            .map(|record| record.wake.deadline)
            .min_by_key(|deadline| deadline.instant())
    }

    fn register_wake_as(
        &self,
        deadline: Deadline,
        key: u64,
        token: &CancellationToken,
        owner: WaitOwnerClass,
    ) -> Result<WakeRegistration, SchedulerError> {
        if DriverSchedulerState::lock(&self.state.wakes).len() >= self.max_wakes {
            return Err(SchedulerError::Capacity {
                limit: self.max_wakes,
            });
        }
        let id = self
            .next_id
            .fetch_update(
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
                |current| {
                    if current == 0 {
                        None
                    } else {
                        Some(current.checked_add(1).unwrap_or(0))
                    }
                },
            )
            .map_err(|_| SchedulerError::WakeIdOverflow)?;
        let wait_registration = self
            .state
            .wait_registry
            .register(WaitRegistrationSpec::new(
                owner,
                OpaqueWaitIdentity::from_u64(id),
                deadline.instant(),
            ))
            .map_err(wait_scheduler_error)?;
        let mut wakes = DriverSchedulerState::lock(&self.state.wakes);
        if wakes.len() >= self.max_wakes {
            drop(wakes);
            drop(wait_registration);
            return Err(SchedulerError::Capacity {
                limit: self.max_wakes,
            });
        }
        let expired = deadline.expired(self.now());
        wakes.insert(
            id,
            DriverWakeRecord {
                wake: ScheduledWake { id, deadline, key },
                token: token.clone(),
                wait_registration,
            },
        );
        drop(wakes);
        // The registry notification can race this map publication: an
        // executor may wake between `register` and the insertion above.
        // Notify once more after the application-owned record is visible so
        // the worker cannot miss a newly admitted deadline.
        self.state.notify_worker();
        if expired {
            match wake_token(token) {
                Ok(()) => {}
                Err(error) => {
                    let _ = self.state.cancel_registration(id, token);
                    return Err(error);
                }
            }
        }
        let owner = Arc::downgrade(&self.state.owner);
        Ok(WakeRegistration::from_weak_owner(id, token.clone(), owner))
    }

    fn advance_to(&self, target: MonotonicInstant) -> Result<Vec<ScheduledWake>, SchedulerError> {
        let mut now = DriverSchedulerState::lock(&self.now);
        if target < *now {
            return Err(SchedulerError::TimeWentBackwards {
                current: *now,
                target,
            });
        }
        *now = target;
        drop(now);

        let due_ids = {
            let wakes = DriverSchedulerState::lock(&self.state.wakes);
            wakes
                .iter()
                .filter(|(_, record)| record.wake.deadline.expired(target))
                .map(|(id, _)| *id)
                .collect::<Vec<_>>()
        };
        let mut due = Vec::new();
        due.try_reserve(due_ids.len())
            .map_err(|_| SchedulerError::Unsupported("runtime.scheduler.allocation".to_owned()))?;
        for id in due_ids {
            if let Some(record) = DriverSchedulerState::lock(&self.state.wakes).remove(&id) {
                due.push(record);
            }
        }
        let mut wakes = Vec::new();
        wakes
            .try_reserve(due.len())
            .map_err(|_| SchedulerError::Unsupported("runtime.scheduler.allocation".to_owned()))?;
        let mut first_error = None;
        for record in due {
            wakes.push(record.wake.clone());
            if let Err(error) = record.wait_registration.complete() {
                first_error.get_or_insert(wait_scheduler_error(error));
            }
            drop(record.wait_registration);
            if let Err(error) = wake_token(&record.token) {
                first_error.get_or_insert(error);
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        wakes.sort_by(|left, right| {
            left.deadline
                .instant()
                .cmp(&right.deadline.instant())
                .then_with(|| left.key.cmp(&right.key))
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(wakes)
    }

    fn shutdown(&self) -> Result<usize, SchedulerError> {
        let mut shutdown = DriverSchedulerState::lock(&self.state.shutdown);
        if shutdown.started {
            loop {
                if let Some(result) = shutdown.result.clone() {
                    return result;
                }
                shutdown = self
                    .state
                    .shutdown_wake
                    .wait(shutdown)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        }
        shutdown.started = true;
        drop(shutdown);
        let records = {
            let mut wakes = DriverSchedulerState::lock(&self.state.wakes);
            std::mem::take(&mut *wakes)
                .into_values()
                .collect::<Vec<_>>()
        };
        let mut cancelled = 0_usize;
        let mut first_error = None;
        for record in records {
            if let Some(next) = cancelled.checked_add(1) {
                cancelled = next;
            } else {
                first_error.get_or_insert(SchedulerError::Unsupported(
                    "runtime.scheduler.diagnostic-overflow".to_owned(),
                ));
                continue;
            }
            if let Err(error) = record.wait_registration.retire() {
                first_error.get_or_insert(wait_scheduler_error(error));
            }
            drop(record.wait_registration);
            if let Err(error) = wake_token(&record.token) {
                first_error.get_or_insert(error);
            }
        }
        if let Err(error) = self.state.wait_registry.shutdown() {
            first_error.get_or_insert(wait_scheduler_error(error));
        }
        let result = first_error.map_or(Ok(cancelled), Err);
        let mut shutdown = DriverSchedulerState::lock(&self.state.shutdown);
        shutdown.result = Some(result.clone());
        drop(shutdown);
        self.state.shutdown_wake.notify_all();
        result
    }
}

impl Scheduler for DriverScheduler {
    fn now(&self) -> MonotonicInstant {
        *DriverSchedulerState::lock(&self.now)
    }

    fn register_wake(
        &self,
        deadline: Deadline,
        key: u64,
        token: &CancellationToken,
    ) -> Result<WakeRegistration, SchedulerError> {
        self.register_wake_as(deadline, key, token, WaitOwnerClass::Scheduler)
    }

    fn cancel(&self, registration: &WakeRegistration) -> Result<bool, SchedulerError> {
        if !registration.belongs_to_owner(&self.state.owner) {
            return Err(SchedulerError::UnknownWake {
                id: registration.id(),
            });
        }
        registration.cancel_for_owner(&self.state.owner)
    }
}

fn wait_scheduler_error(error: WaitRegistryError) -> SchedulerError {
    SchedulerError::Unsupported(error.code().to_owned())
}

fn wake_token(token: &CancellationToken) -> Result<(), SchedulerError> {
    panic::catch_unwind(AssertUnwindSafe(|| token.wake()))
        .map_err(|_| SchedulerError::CancellationPanicked)
}

#[derive(Debug, Default)]
struct FinalizationState {
    in_progress: bool,
    result: Option<Result<TimeDriverFinalizeReport, TimeDriverError>>,
}

#[derive(Debug)]
struct Shared {
    source: Arc<dyn ClockSource>,
    last_reading: Mutex<ClockReading>,
    scheduler: DriverScheduler,
    wait_registry: WaitRegistry,
    limits: TimeDriverLimits,
    wait: Mutex<WaitState>,
    wake: Condvar,
    diagnostics: Mutex<DiagnosticState>,
}

impl Shared {
    fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
        value
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn new(source: Arc<dyn ClockSource>, initial: ClockReading, limits: TimeDriverLimits) -> Self {
        let wait_registry = WaitRegistry::new(WaitRegistryConfig::with_limits(
            limits.max_registrations,
            256,
            1_024,
            1_048_576,
        ));
        Self {
            source,
            last_reading: Mutex::new(initial),
            scheduler: DriverScheduler::new(
                wait_registry.clone(),
                MonotonicInstant::zero(),
                limits.max_registrations,
            ),
            wait_registry,
            limits,
            wait: Mutex::new(WaitState {
                stopped: false,
                in_flight_registrations: 0,
                wake_epoch: 0,
                failure: None,
            }),
            wake: Condvar::new(),
            diagnostics: Mutex::new(DiagnosticState::default()),
        }
    }

    fn checked_wake_epoch(wait: &mut WaitState) -> Result<(), TimeDriverError> {
        wait.wake_epoch = wait
            .wake_epoch
            .checked_add(1)
            .ok_or(TimeDriverError::GenerationOverflow)?;
        Ok(())
    }

    fn record_error(&self, error: &TimeDriverError) {
        let mut wait = Self::lock(&self.wait);
        self.record_error_locked(&mut wait, error);
    }

    fn record_error_locked(&self, wait: &mut WaitState, error: &TimeDriverError) {
        if wait.failure.is_none() {
            wait.failure = Some(error.clone());
        }
        let mut diagnostics = Self::lock(&self.diagnostics);
        diagnostics.last_error = Some(error.code());
    }

    fn record_counter(&self, counter: &mut u64) -> Result<(), TimeDriverError> {
        *counter = counter
            .checked_add(1)
            .ok_or(TimeDriverError::DiagnosticOverflow)?;
        Ok(())
    }

    fn worker_advance_record(&self) -> Result<(), TimeDriverError> {
        let mut diagnostics = Self::lock(&self.diagnostics);
        let result = self.record_counter(&mut diagnostics.worker_advances);
        if result.is_err() {
            diagnostics.overflowed = true;
        }
        result
    }

    fn read(&self) -> Result<ClockReading, TimeDriverError> {
        let reading = self.source.reading()?;
        let mut previous = Self::lock(&self.last_reading);
        if reading.monotonic < previous.monotonic {
            return Err(TimeDriverError::ClockMovedBackward {
                previous: previous.monotonic,
                current: reading.monotonic,
            });
        }
        *previous = reading;
        Ok(reading)
    }

    fn read_lossy(&self) -> ClockReading {
        // Hold the owner admission lock across the source read. This makes
        // the lossy `Clock::now` fallback linearize before or after owner
        // finalization; a source failure cannot be observed after a
        // successful finalization check has already passed.
        let mut wait = Self::lock(&self.wait);
        if wait.stopped {
            drop(wait);
            return *Self::lock(&self.last_reading);
        }
        match self.read() {
            Ok(reading) => {
                drop(wait);
                reading
            }
            Err(error) => {
                // `Clock::now` is an infallible runtime trait method. A
                // source failure therefore becomes a terminal owner
                // transition before the compatibility reading is returned;
                // required owner finalization observes `failure()` and
                // refuses that success.
                wait.stopped = true;
                self.record_error_locked(&mut wait, &error);
                if let Err(epoch_error) = Self::checked_wake_epoch(&mut wait) {
                    self.record_error_locked(&mut wait, &epoch_error);
                }
                drop(wait);
                self.wake.notify_all();
                *Self::lock(&self.last_reading)
            }
        }
    }

    fn is_stopped(&self) -> bool {
        Self::lock(&self.wait).stopped
    }

    fn failure(&self) -> Option<TimeDriverError> {
        Self::lock(&self.wait).failure.clone()
    }

    fn diagnostics(&self) -> TimeDriverDiagnostics {
        // Take each short snapshot independently.  The scheduler retires
        // runtime registrations before updating diagnostics, while shutdown
        // uses wait-then-scheduler; retaining two of these locks while taking
        // a read-only snapshot would create an avoidable lock-order cycle.
        let wait_snapshot = self.wait_registry.snapshot();
        let diagnostics = {
            let diagnostics = Self::lock(&self.diagnostics);
            (
                diagnostics.registrations,
                diagnostics.completed_registrations,
                diagnostics.cancelled_registrations,
                diagnostics.worker_advances,
                diagnostics.last_error,
            )
        };
        let stopped = Self::lock(&self.wait).stopped;
        TimeDriverDiagnostics {
            registrations: diagnostics.0,
            completed_registrations: diagnostics.1,
            cancelled_registrations: diagnostics.2,
            worker_advances: diagnostics.3,
            active_registrations: wait_snapshot.registrations,
            earliest_deadline: wait_snapshot.earliest_deadline,
            stopped,
            last_error: diagnostics.4,
        }
    }

    fn complete_records(&self, wakes: &[ScheduledWake]) -> Result<(), TimeDriverError> {
        if wakes.is_empty() {
            return Ok(());
        }
        let mut diagnostics = Self::lock(&self.diagnostics);
        for _wake in wakes {
            if self
                .record_counter(&mut diagnostics.completed_registrations)
                .is_err()
            {
                diagnostics.overflowed = true;
                return Err(TimeDriverError::DiagnosticOverflow);
            }
        }
        Ok(())
    }

    fn cancelled_record(&self) -> Result<(), TimeDriverError> {
        let mut diagnostics = Self::lock(&self.diagnostics);
        if self
            .record_counter(&mut diagnostics.cancelled_registrations)
            .is_err()
        {
            diagnostics.overflowed = true;
            return Err(TimeDriverError::DiagnosticOverflow);
        }
        Ok(())
    }

    /// Stops admission, waits for any registration currently crossing the
    /// runtime scheduler boundary, and removes all exact records.  It never
    /// wakes a user future while a shared-state lock is held.
    fn begin_shutdown(&self, error: Option<TimeDriverError>) -> Result<usize, TimeDriverError> {
        let mut wait = Self::lock(&self.wait);
        let was_stopped = wait.stopped;
        wait.stopped = true;
        if let Some(error) = error.as_ref() {
            self.record_error_locked(&mut wait, error);
        }
        if !was_stopped {
            match Self::checked_wake_epoch(&mut wait) {
                Ok(()) => {}
                Err(error) => self.record_error_locked(&mut wait, &error),
            }
        }
        while wait.in_flight_registrations != 0 {
            wait = self
                .wake
                .wait(wait)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        drop(wait);
        self.wake.notify_all();
        let result = self.scheduler.shutdown().map_err(TimeDriverError::from);
        if let Err(error) = &result {
            self.record_error(error);
        }
        result
    }
}

/// The run-owned production time owner.
pub struct TimeDriver {
    shared: Arc<Shared>,
    worker: Mutex<Option<JoinHandle<()>>>,
    finalization: Mutex<FinalizationState>,
    finalization_wake: Condvar,
}

impl fmt::Debug for TimeDriver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TimeDriver")
            .field("diagnostics", &self.diagnostics())
            .finish_non_exhaustive()
    }
}

impl TimeDriver {
    /// Starts one production driver with bounded registration state.
    pub fn new(limits: TimeDriverLimits) -> Result<Self, TimeDriverError> {
        limits.validate()?;
        let source = Arc::new(SystemClockSource::new()?);
        let initial = source.reading()?;
        Self::from_source(source, initial, limits)
    }

    fn from_source(
        source: Arc<dyn ClockSource>,
        initial: ClockReading,
        limits: TimeDriverLimits,
    ) -> Result<Self, TimeDriverError> {
        limits.validate()?;
        let shared = Arc::new(Shared::new(source, initial, limits));
        let worker_notify_shared = Arc::downgrade(&shared);
        shared.scheduler.set_worker_notify(Arc::new(move || {
            if let Some(shared) = worker_notify_shared.upgrade() {
                shared.wake.notify_all();
            }
        }));
        let weak_shared = Arc::downgrade(&shared);
        shared
            .wait_registry
            .set_callback(move |_| {
                if let Some(shared) = weak_shared.upgrade() {
                    shared.wake.notify_all();
                }
            })
            .map_err(TimeDriverError::from)?;
        let worker_shared = Arc::clone(&shared);
        let worker_thread = thread::Builder::new()
            .name("jmeter-rs-time-driver".to_owned())
            .spawn(move || {
                let result = panic::catch_unwind(AssertUnwindSafe(|| worker_main(&worker_shared)));
                if result.is_err() {
                    worker_shared.record_error(&TimeDriverError::WorkerPanic);
                    if let Err(error) =
                        worker_shared.begin_shutdown(Some(TimeDriverError::WorkerPanic))
                    {
                        worker_shared.record_error(&error);
                    }
                }
            })
            .map_err(|_| TimeDriverError::WorkerStart)?;

        Ok(Self {
            shared,
            worker: Mutex::new(Some(worker_thread)),
            finalization: Mutex::new(FinalizationState::default()),
            finalization_wake: Condvar::new(),
        })
    }

    /// Returns a cloneable capability view backed by this exact run owner.
    #[must_use]
    pub fn handle(&self) -> TimeDriverHandle {
        TimeDriverHandle {
            shared: Arc::clone(&self.shared),
        }
    }

    /// Returns the read-only wait-registry handle for this exact run.
    #[must_use]
    pub fn wait_registry(&self) -> WaitRegistryHandle {
        self.shared.wait_registry.handle()
    }

    /// Installs the exact executor waker used for earlier-deadline delivery.
    pub fn set_wait_waker(&self, waker: &Waker) -> Result<(), TimeDriverError> {
        self.shared
            .wait_registry
            .set_waker(waker)
            .map_err(TimeDriverError::from)
    }

    /// Returns a bounded diagnostic snapshot.
    #[must_use]
    pub fn diagnostics(&self) -> TimeDriverDiagnostics {
        self.shared.diagnostics()
    }

    /// Returns the exact worker count owned by this driver.
    ///
    /// This is deliberately a constant: a production driver never scales
    /// worker threads with registration count or virtual-user count.
    #[must_use]
    pub const fn worker_count(&self) -> usize {
        1
    }

    /// Finalizes the exact worker and cancels every outstanding registration.
    ///
    /// All registration cancellation and token wakes happen before the exact
    /// join, and no driver lock is held while joining.  The operation is
    /// idempotent; a repeated call returns the first finalization result.
    pub fn finalize(&self) -> Result<TimeDriverFinalizeReport, TimeDriverError> {
        if self.is_worker_thread() {
            return Err(TimeDriverError::FinalizeFromWorker);
        }
        {
            let mut state = Shared::lock(&self.finalization);
            loop {
                if let Some(result) = state.result.as_ref() {
                    return result.clone();
                }
                if !state.in_progress {
                    state.in_progress = true;
                    break;
                }
                state = self
                    .finalization_wake
                    .wait(state)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        }

        let cancellation_result = self.shared.begin_shutdown(None);
        if let Err(error) = &cancellation_result {
            self.shared.record_error(error);
        }
        let handle = Shared::lock(&self.worker).take();
        let join_result = handle.map_or(Ok(()), |handle| {
            handle.join().map_err(|_| TimeDriverError::WorkerJoin)
        });
        let result = match join_result {
            Err(error) => Err(error),
            Ok(()) => match cancellation_result {
                Err(error) => Err(error),
                Ok(cancelled_registrations) => match self.shared.failure() {
                    Some(TimeDriverError::WorkerPanic) => Err(TimeDriverError::WorkerPanic),
                    Some(error) if error.code() != TimeDriverError::Stopped.code() => Err(error),
                    _ => Ok(TimeDriverFinalizeReport {
                        cancelled_registrations,
                        worker_panicked: false,
                    }),
                },
            },
        };
        let mut state = Shared::lock(&self.finalization);
        state.result = Some(result.clone());
        state.in_progress = false;
        drop(state);
        self.finalization_wake.notify_all();
        result
    }

    /// Cancels outstanding waits and joins the exact worker without
    /// manufacturing a successful completion report.
    pub fn cancel_and_join(&self) -> Result<(), TimeDriverError> {
        self.finalize().map(|_| ())
    }

    #[cfg(test)]
    fn notify_worker_for_test(&self) {
        self.shared.wake.notify_all();
    }

    fn is_worker_thread(&self) -> bool {
        let current = thread::current().id();
        let handle = Shared::lock(&self.worker);
        handle
            .as_ref()
            .is_some_and(|handle| handle.thread().id() == current)
    }
}

impl Drop for TimeDriver {
    fn drop(&mut self) {
        if self.is_worker_thread() {
            return;
        }
        let _ = self.finalize();
    }
}

/// A cloneable capability view for a [`TimeDriver`].
#[derive(Clone)]
pub struct TimeDriverHandle {
    shared: Arc<Shared>,
}

impl fmt::Debug for TimeDriverHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TimeDriverHandle")
            .field("diagnostics", &self.diagnostics())
            .finish()
    }
}

impl TimeDriverHandle {
    /// Reads a checked coherent wall/monotonic pair.
    pub fn try_now(&self) -> Result<ClockReading, TimeDriverError> {
        self.shared.read()
    }

    /// Returns a bounded diagnostic snapshot.
    #[must_use]
    pub fn diagnostics(&self) -> TimeDriverDiagnostics {
        self.shared.diagnostics()
    }

    /// Returns whether owner finalization has started.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.shared.is_stopped()
    }

    /// Returns whether an exact registration is still retained by the owner.
    #[must_use]
    pub fn is_registration_active(&self, id: u64) -> bool {
        self.shared.scheduler.is_active(id)
    }

    /// Returns the run-owned wait-registry handle used by the executor.
    #[must_use]
    pub fn wait_registry(&self) -> WaitRegistryHandle {
        self.shared.wait_registry.handle()
    }

    /// Installs the exact executor waker used for earlier-deadline delivery.
    pub fn set_wait_waker(&self, waker: &Waker) -> Result<(), TimeDriverError> {
        self.shared
            .wait_registry
            .set_waker(waker)
            .map_err(TimeDriverError::from)
    }

    /// Registers an already-established absolute HTTP wait deadline.
    ///
    /// The deadline must already be selected by HTTP admission in this run's
    /// monotonic epoch; this seam never derives, refreshes, or caps it. The
    /// numeric key is a bounded opaque ordering/identity token and must not
    /// encode request data, hostnames, or secrets. The caller retains the
    /// supplied cancellation token. The returned linear wake registration is
    /// retired by [`Scheduler::cancel`] or by dropping it, and both paths
    /// retire the paired runtime `WaitRegistration` exactly.
    pub fn register_http_wait(
        &self,
        deadline: Deadline,
        key: u64,
        token: &CancellationToken,
    ) -> Result<WakeRegistration, TimeDriverError> {
        self.register(deadline, key, token, WaitOwnerClass::Http)
    }

    /// Registers an already-established absolute provider operation deadline.
    ///
    /// The provider owns deadline selection before calling this seam. The
    /// supplied [`Deadline`] is forwarded unchanged in this run's monotonic
    /// epoch; this method does not read the clock, reconstruct the deadline,
    /// refresh it, or apply a second timeout. `key` is a bounded opaque
    /// nonzero numeric ordering/identity value. Zero is reserved and rejected
    /// before the scheduler or wait registry is touched. It must not encode
    /// request data, hostnames, credentials, or other secrets. The supplied cancellation
    /// token is the exact token associated with the pending operation.
    ///
    /// The returned [`WakeRegistration`] is linear. Use [`Scheduler::cancel`]
    /// for explicit retirement or drop it for exact RAII retirement; both
    /// paths retire the paired run-owned wait-registry entry.
    #[allow(
        dead_code,
        reason = "the typed JTL/provider adapter consumes this narrow seam"
    )]
    pub fn register_provider_wait(
        &self,
        deadline: Deadline,
        key: u64,
        token: &CancellationToken,
    ) -> Result<WakeRegistration, TimeDriverError> {
        if key == 0 {
            return Err(TimeDriverError::InvalidProviderKey);
        }
        self.register(deadline, key, token, WaitOwnerClass::Provider)
    }

    fn register(
        &self,
        deadline: Deadline,
        key: u64,
        token: &CancellationToken,
        owner: WaitOwnerClass,
    ) -> Result<WakeRegistration, TimeDriverError> {
        let mut wait = Shared::lock(&self.shared.wait);
        if wait.stopped {
            return Err(TimeDriverError::Stopped);
        }
        if let Some(error) = wait.failure.clone() {
            return Err(error);
        }
        let occupied = self
            .shared
            .scheduler
            .active_count()
            .checked_add(wait.in_flight_registrations)
            .ok_or(TimeDriverError::Capacity {
                limit: self.shared.limits.max_registrations,
            })?;
        if occupied >= self.shared.limits.max_registrations {
            return Err(TimeDriverError::Capacity {
                limit: self.shared.limits.max_registrations,
            });
        }
        wait.in_flight_registrations =
            wait.in_flight_registrations
                .checked_add(1)
                .ok_or(TimeDriverError::Capacity {
                    limit: self.shared.limits.max_registrations,
                })?;
        drop(wait);

        // This call can notify an already-expired token. No driver lock is
        // held while the scheduler or wait registry dispatches notifications.
        let registration = self
            .shared
            .scheduler
            .register_wake_as(deadline, key, token, owner)
            .map_err(TimeDriverError::from);

        let mut wait = Shared::lock(&self.shared.wait);
        wait.in_flight_registrations = wait
            .in_flight_registrations
            .checked_sub(1)
            .ok_or(TimeDriverError::GenerationOverflow)?;
        let mut accepted = None;
        let mut registration_error = None;
        let mut cancel_after: Option<(WakeRegistration, TimeDriverError)> = None;
        match registration {
            Err(error) => registration_error = Some(error),
            Ok(registration) => {
                let rejection = if reg_id(registration.id()).is_none() {
                    Some(TimeDriverError::RegistrationIdOverflow)
                } else if wait.stopped {
                    Some(TimeDriverError::Stopped)
                } else if self.shared.scheduler.active_count()
                    > self.shared.limits.max_registrations
                {
                    Some(TimeDriverError::Capacity {
                        limit: self.shared.limits.max_registrations,
                    })
                } else {
                    let mut diagnostics = Shared::lock(&self.shared.diagnostics);
                    match Shared::record_counter(&self.shared, &mut diagnostics.registrations) {
                        Ok(()) => None,
                        Err(error) => {
                            diagnostics.overflowed = true;
                            Some(error)
                        }
                    }
                };
                if let Some(error) = rejection {
                    cancel_after = Some((registration, error));
                } else {
                    accepted = Some(registration);
                }
            }
        }
        let epoch_result = Shared::checked_wake_epoch(&mut wait);
        if epoch_result.is_err() {
            cancel_after = accepted
                .take()
                .map(|registration| (registration, TimeDriverError::GenerationOverflow));
        }
        drop(wait);
        self.shared.wake.notify_all();
        if let Some((registration, error)) = cancel_after {
            if let Err(cancel_error) = Scheduler::cancel(&self.shared.scheduler, &registration) {
                self.shared
                    .record_error(&TimeDriverError::from(cancel_error));
            }
            drop(registration);
            return Err(error);
        }
        if epoch_result.is_err() {
            return Err(TimeDriverError::GenerationOverflow);
        }
        if let Some(error) = registration_error {
            return Err(error);
        }
        accepted.ok_or(TimeDriverError::Stopped)
    }

    fn cancel_registration(
        &self,
        registration: &WakeRegistration,
    ) -> Result<bool, TimeDriverError> {
        let scheduler_result = Scheduler::cancel(&self.shared.scheduler, registration);
        let cancelled = match &scheduler_result {
            Ok(value) => *value,
            Err(_) => false,
        };
        if cancelled {
            match self.shared.cancelled_record() {
                Ok(()) => {}
                Err(error) => {
                    self.shared.record_error(&error);
                    return Err(error);
                }
            }
        }
        if let Err(error) = scheduler_result {
            let error = TimeDriverError::from(error);
            self.shared.record_error(&error);
            return Err(error);
        }
        let epoch_result = {
            let mut wait = Shared::lock(&self.shared.wait);
            Shared::checked_wake_epoch(&mut wait)
        };
        self.shared.wake.notify_all();
        epoch_result.map(|()| cancelled)
    }
}

fn result_wait_error(error: TimeDriverError) -> ResultWaitError {
    match error {
        TimeDriverError::Stopped => ResultWaitError::Shutdown,
        TimeDriverError::InvalidProviderKey
        | TimeDriverError::InvalidLimits { .. }
        | TimeDriverError::ClockOrigin
        | TimeDriverError::ClockOverflow { .. }
        | TimeDriverError::ClockMovedBackward { .. }
        | TimeDriverError::Capacity { .. }
        | TimeDriverError::RegistrationIdOverflow
        | TimeDriverError::GenerationOverflow
        | TimeDriverError::Scheduler { .. }
        | TimeDriverError::WorkerStart
        | TimeDriverError::WorkerPanic
        | TimeDriverError::WorkerJoin
        | TimeDriverError::FinalizeFromWorker
        | TimeDriverError::DiagnosticOverflow => ResultWaitError::Rejected,
    }
}

struct TimeDriverResultWaitRegistration {
    driver: TimeDriverHandle,
    _token: CancellationToken,
    registration: Option<WakeRegistration>,
}

impl ResultWaitRegistrationHandle for TimeDriverResultWaitRegistration {
    fn retire(&mut self) -> Result<(), ResultWaitError> {
        let Some(registration) = self.registration.as_ref() else {
            return Err(ResultWaitError::AlreadyRetired);
        };
        let result = Scheduler::cancel(&self.driver, registration);
        match result {
            Ok(true) => {
                drop(self.registration.take());
                Ok(())
            }
            Ok(false) => {
                drop(self.registration.take());
                Err(ResultWaitError::AlreadyRetired)
            }
            Err(error) => Err(result_wait_error(TimeDriverError::from(error))),
        }
    }
}

impl Drop for TimeDriverResultWaitRegistration {
    fn drop(&mut self) {
        if let Some(registration) = self.registration.take() {
            let _ = Scheduler::cancel(&self.driver, &registration);
            drop(registration);
        }
    }
}

impl ResultWaitRegistrar for TimeDriverHandle {
    fn register(
        &self,
        spec: ResultWaitSpec,
    ) -> Result<Box<dyn ResultWaitRegistrationHandle>, ResultWaitError> {
        if spec.owner != WaitOwnerClass::Provider {
            return Err(ResultWaitError::Rejected);
        }
        let token = CancellationToken::new();
        token.register_waker(&spec.waker);
        let registration = self
            .register_provider_wait(Deadline::at(spec.deadline), spec.operation.get(), &token)
            .map_err(result_wait_error)?;
        Ok(Box::new(TimeDriverResultWaitRegistration {
            driver: self.clone(),
            _token: token,
            registration: Some(registration),
        }))
    }
}

impl Clock for TimeDriverHandle {
    fn now(&self) -> ClockReading {
        self.shared.read_lossy()
    }
}

impl Sleeper for TimeDriverHandle {
    fn sleep<'a>(&'a self, duration: Duration) -> CapabilityFuture<'a, ()> {
        self.sleep_owned(duration)
    }
}

impl TimeDriverHandle {
    fn sleep_owned(&self, duration: Duration) -> CapabilityFuture<'static, ()> {
        let now = self.shared.read_lossy();
        let deadline = match now.monotonic.checked_add(duration) {
            Some(monotonic) => Deadline::at(MonotonicInstant::from_duration(monotonic)),
            None => {
                return Box::pin(std::future::ready(Err(CapabilityError::resource_limit(
                    TimeDriverError::ClockOverflow {
                        axis: TimeDriverClockAxis::Monotonic,
                    }
                    .code(),
                ))));
            }
        };
        Box::pin(TimeSleepFuture {
            driver: self.clone(),
            deadline,
            token: CancellationToken::new(),
            registration: None,
        })
    }
}

impl Scheduler for TimeDriverHandle {
    fn now(&self) -> MonotonicInstant {
        MonotonicInstant::from_duration(self.shared.read_lossy().monotonic)
    }

    fn register_wake(
        &self,
        deadline: Deadline,
        key: u64,
        token: &CancellationToken,
    ) -> Result<WakeRegistration, SchedulerError> {
        self.register(deadline, key, token, WaitOwnerClass::Scheduler)
            .map_err(scheduler_error)
    }

    fn cancel(&self, registration: &WakeRegistration) -> Result<bool, SchedulerError> {
        self.cancel_registration(registration)
            .map_err(scheduler_error)
    }
}

impl Clock for TimeDriver {
    fn now(&self) -> ClockReading {
        Clock::now(&self.handle())
    }
}

impl Sleeper for TimeDriver {
    fn sleep<'a>(&'a self, duration: Duration) -> CapabilityFuture<'a, ()> {
        self.handle().sleep_owned(duration)
    }
}

impl Scheduler for TimeDriver {
    fn now(&self) -> MonotonicInstant {
        Scheduler::now(&self.handle())
    }

    fn register_wake(
        &self,
        deadline: Deadline,
        key: u64,
        token: &CancellationToken,
    ) -> Result<WakeRegistration, SchedulerError> {
        self.handle().register_wake(deadline, key, token)
    }

    fn cancel(&self, registration: &WakeRegistration) -> Result<bool, SchedulerError> {
        self.handle().cancel(registration)
    }
}

struct TimeSleepFuture {
    driver: TimeDriverHandle,
    deadline: Deadline,
    token: CancellationToken,
    registration: Option<WakeRegistration>,
}

impl TimeSleepFuture {
    fn retire(&mut self) {
        if let Some(registration) = self.registration.take() {
            let _ = self.driver.cancel_registration(&registration);
        }
    }
}

impl Future for TimeSleepFuture {
    type Output = Result<(), CapabilityError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if self.token.signal().is_stop() {
            let signal = self.token.signal();
            self.retire();
            return Poll::Ready(Err(CapabilityError::Control(signal)));
        }
        let now = match self.driver.try_now() {
            Ok(reading) => reading.monotonic,
            Err(error) => {
                self.retire();
                return Poll::Ready(Err(CapabilityError::failure(error.code())));
            }
        };
        if self.deadline.expired(MonotonicInstant::from_duration(now)) {
            self.retire();
            return Poll::Ready(Ok(()));
        }
        if self.registration.is_none() {
            let registration =
                match self
                    .driver
                    .register(self.deadline, 0, &self.token, WaitOwnerClass::Sleeper)
                {
                    Ok(registration) => registration,
                    Err(error) => {
                        self.retire();
                        return Poll::Ready(Err(capability_error(error)));
                    }
                };
            self.registration = Some(registration);
        }
        self.token.register_waker(context.waker());
        let retired = self
            .registration
            .as_ref()
            .is_some_and(|registration| !self.driver.is_registration_active(registration.id()));
        let raced = self.token.take_wake();
        if retired || raced || self.token.signal().is_stop() {
            context.waker().wake_by_ref();
        }
        Poll::Pending
    }
}

impl Drop for TimeSleepFuture {
    fn drop(&mut self) {
        self.retire();
    }
}

fn capability_error(error: TimeDriverError) -> CapabilityError {
    match error {
        TimeDriverError::Capacity { .. } | TimeDriverError::DiagnosticOverflow => {
            CapabilityError::resource_limit(error.code())
        }
        TimeDriverError::Stopped => CapabilityError::failure(error.code()),
        _ => CapabilityError::failure(error.code()),
    }
}

fn scheduler_error(error: TimeDriverError) -> SchedulerError {
    match error {
        TimeDriverError::Capacity { limit } => SchedulerError::Capacity { limit },
        TimeDriverError::Scheduler { code } => SchedulerError::Unsupported((*code).to_owned()),
        TimeDriverError::ClockOverflow { .. } => SchedulerError::DeadlineOverflow {
            delay: Duration::MAX,
        },
        TimeDriverError::RegistrationIdOverflow => SchedulerError::WakeIdOverflow,
        other => SchedulerError::Unsupported(other.code().to_owned()),
    }
}

fn reg_id(value: u64) -> Option<std::num::NonZeroU64> {
    std::num::NonZeroU64::new(value)
}

fn worker_main(shared: &Arc<Shared>) {
    loop {
        if shared.is_stopped() {
            if let Err(error) = shared.begin_shutdown(None) {
                shared.record_error(&error);
            }
            return;
        }
        let reading = match shared.read() {
            Ok(reading) => reading,
            Err(error) => {
                if let Err(error) = shared.begin_shutdown(Some(error)) {
                    shared.record_error(&error);
                }
                return;
            }
        };
        if shared.worker_advance_record().is_err() {
            let error = TimeDriverError::DiagnosticOverflow;
            if let Err(error) = shared.begin_shutdown(Some(error)) {
                shared.record_error(&error);
            }
            return;
        }
        let target = MonotonicInstant::from_duration(reading.monotonic);
        match shared.scheduler.advance_to(target) {
            Ok(wakes) => {
                if let Err(error) = shared.complete_records(&wakes) {
                    if let Err(error) = shared.begin_shutdown(Some(error)) {
                        shared.record_error(&error);
                    }
                    return;
                }
            }
            Err(error) => {
                if let Err(error) = shared.begin_shutdown(Some(TimeDriverError::from(error))) {
                    shared.record_error(&error);
                }
                return;
            }
        }
        if shared.is_stopped() {
            if let Err(error) = shared.begin_shutdown(None) {
                shared.record_error(&error);
            }
            return;
        }

        let wake_epoch = Shared::lock(&shared.wait).wake_epoch;
        let wait_duration = shared
            .scheduler
            .next_deadline()
            .and_then(|deadline| deadline.instant().duration_since(target))
            .map(|duration| duration.min(MAX_WAIT_CHUNK));
        let mut wait = Shared::lock(&shared.wait);
        if wait.stopped {
            drop(wait);
            continue;
        }
        if wait.wake_epoch != wake_epoch {
            drop(wait);
            continue;
        }
        wait = match wait_duration {
            Some(duration) => shared
                .wake
                .wait_timeout(wait, duration)
                .map(|(guard, _)| guard)
                .unwrap_or_else(|poisoned| poisoned.into_inner().0),
            None => shared
                .wake
                .wait(wait)
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        };
        drop(wait);
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    reason = "test failures include bounded assertion context without production panic paths"
)]
mod tests {
    use super::*;
    use jmeter_rs_runtime::ResultOperationId;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    #[derive(Debug)]
    struct ManualSource {
        reading: Mutex<ClockReading>,
    }

    impl ManualSource {
        fn new(reading: ClockReading) -> Self {
            Self {
                reading: Mutex::new(reading),
            }
        }

        fn advance(&self, amount: Duration) {
            let mut reading = self
                .reading
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let millis = i64::try_from(amount.as_millis()).unwrap_or(i64::MAX);
            reading.monotonic = reading
                .monotonic
                .checked_add(amount)
                .unwrap_or(Duration::MAX);
            reading.wall = WallTimestamp::from_millis(
                reading
                    .wall
                    .as_millis()
                    .checked_add(millis)
                    .unwrap_or(i64::MAX),
            );
        }
    }

    impl ClockSource for ManualSource {
        fn reading(&self) -> Result<ClockReading, TimeDriverError> {
            Ok(*self
                .reading
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner))
        }
    }

    #[derive(Debug)]
    struct FailingSource {
        reading: ClockReading,
        error: Mutex<Option<TimeDriverError>>,
    }

    impl FailingSource {
        fn new(reading: ClockReading) -> Self {
            Self {
                reading,
                error: Mutex::new(None),
            }
        }

        fn fail(&self, error: TimeDriverError) {
            *self
                .error
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(error);
        }
    }

    impl ClockSource for FailingSource {
        fn reading(&self) -> Result<ClockReading, TimeDriverError> {
            match self
                .error
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
            {
                Some(error) => Err(error),
                None => Ok(self.reading),
            }
        }
    }

    #[derive(Debug)]
    struct WakeCounter {
        count: Mutex<usize>,
        wake: Condvar,
        calls: AtomicUsize,
    }

    impl WakeCounter {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                count: Mutex::new(0),
                wake: Condvar::new(),
                calls: AtomicUsize::new(0),
            })
        }

        fn wait_one(&self) {
            let mut count = self
                .count
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            while *count == 0 {
                count = self
                    .wake
                    .wait(count)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            *count -= 1;
        }
    }

    impl Wake for WakeCounter {
        fn wake(self: Arc<Self>) {
            self.calls.fetch_add(1, Ordering::AcqRel);
            let mut count = self
                .count
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *count = count.saturating_add(1);
            drop(count);
            self.wake.notify_all();
        }
    }

    fn initial() -> ClockReading {
        ClockReading {
            wall: WallTimestamp::from_millis(1_700_000_000_000),
            monotonic: Duration::ZERO,
        }
    }

    fn manual_driver(capacity: usize) -> (TimeDriver, Arc<ManualSource>, TimeDriverHandle) {
        let source = Arc::new(ManualSource::new(initial()));
        let owner = TimeDriver::from_source(
            Arc::clone(&source) as Arc<dyn ClockSource>,
            initial(),
            TimeDriverLimits::new(capacity).unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let handle = owner.handle();
        (owner, source, handle)
    }

    #[test]
    fn coherent_system_reading_has_monotonic_epoch_and_wall_pair() {
        let owner =
            TimeDriver::new(TimeDriverLimits::new(4).unwrap_or_else(|error| panic!("{error}")))
                .unwrap_or_else(|error| panic!("{error}"));
        let handle = owner.handle();
        let first = handle.try_now().unwrap_or_else(|error| panic!("{error}"));
        let second = handle.try_now().unwrap_or_else(|error| panic!("{error}"));
        assert!(second.monotonic >= first.monotonic);
        assert!(second.wall >= first.wall);
        assert_eq!(owner.worker_count(), 1);
        assert!(owner.finalize().is_ok());
    }

    #[test]
    fn infallible_clock_failure_is_terminal_before_compatibility_reading() {
        let source = Arc::new(FailingSource::new(initial()));
        let owner = TimeDriver::from_source(
            Arc::clone(&source) as Arc<dyn ClockSource>,
            initial(),
            TimeDriverLimits::new(2).unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let handle = owner.handle();
        source.fail(TimeDriverError::ClockOverflow {
            axis: TimeDriverClockAxis::Monotonic,
        });

        // The runtime Clock contract cannot return the source error.  It may
        // return the last coherent pair only after atomically making the run
        // terminal; finalization is the publication gate and must fail.
        assert_eq!(Clock::now(&handle), initial());
        assert!(handle.is_stopped());
        assert_eq!(
            handle.diagnostics().last_error,
            Some("app.time-driver.clock-overflow")
        );
        assert!(matches!(
            owner.finalize(),
            Err(TimeDriverError::ClockOverflow {
                axis: TimeDriverClockAxis::Monotonic
            })
        ));
    }

    #[test]
    fn scheduler_error_diagnostics_discard_unsupported_text() {
        let error = TimeDriverError::from(SchedulerError::Unsupported(
            "private-request-or-host-detail".to_owned(),
        ));
        assert_eq!(error.code(), "runtime.scheduler.unsupported");
        assert_eq!(error.to_string(), "runtime.scheduler.unsupported");
        assert!(!format!("{error:?}").contains("private-request-or-host-detail"));
    }

    #[test]
    fn many_registrations_share_one_worker_and_shutdown_exactly() {
        let (owner, _source, handle) = manual_driver(32);
        let registry = owner.wait_registry();
        let token = CancellationToken::new();
        let mut registrations = Vec::new();
        for key in 0..32_u64 {
            let registration = Scheduler::register_wake(
                &handle,
                Deadline::at(MonotonicInstant::from_duration(Duration::from_secs(3_600))),
                key,
                &token,
            )
            .unwrap_or_else(|error| panic!("{error}"));
            registrations.push(registration);
        }
        assert_eq!(owner.worker_count(), 1);
        assert_eq!(owner.diagnostics().active_registrations, 32);
        let report = owner.finalize().unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(report.cancelled_registrations, 32);
        assert_eq!(owner.diagnostics().active_registrations, 0);
        assert!(registry.is_shutdown());
        assert!(owner.finalize().is_ok());
        drop(registrations);
    }

    #[test]
    fn earlier_deadline_is_visible_and_wakes_registration_worker() {
        let (owner, _source, handle) = manual_driver(4);
        let executor_wake = WakeCounter::new();
        let executor_waker = Waker::from(Arc::clone(&executor_wake));
        handle
            .set_wait_waker(&executor_waker)
            .unwrap_or_else(|error| panic!("{error}"));
        let token = CancellationToken::new();
        let first = Scheduler::register_wake(
            &handle,
            Deadline::at(MonotonicInstant::from_duration(Duration::from_secs(60))),
            1,
            &token,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(executor_wake.calls.load(Ordering::Acquire) >= 1);
        let second = Scheduler::register_wake(
            &handle,
            Deadline::at(MonotonicInstant::from_duration(Duration::from_secs(1))),
            2,
            &token,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(executor_wake.calls.load(Ordering::Acquire) >= 2);
        assert_eq!(
            handle.diagnostics().earliest_deadline,
            Some(MonotonicInstant::from_duration(Duration::from_secs(1)))
        );
        assert!(Scheduler::cancel(&handle, &second).unwrap_or(false));
        assert!(Scheduler::cancel(&handle, &first).unwrap_or(false));
        assert_eq!(handle.diagnostics().active_registrations, 0);
        assert!(owner.finalize().is_ok());
    }

    #[test]
    fn http_wait_uses_exact_owner_deadline_and_cancel_retires_both_registrations() {
        let (owner, _source, handle) = manual_driver(2);
        let token = CancellationToken::new();
        let deadline = Deadline::at(MonotonicInstant::from_duration(Duration::from_secs(17)));
        let registration = handle
            .register_http_wait(deadline, 0x48_5454, &token)
            .unwrap_or_else(|error| panic!("{error}"));

        {
            let wakes = DriverSchedulerState::lock(&handle.shared.scheduler.state.wakes);
            let wait_registration = &wakes
                .get(&registration.id())
                .unwrap_or_else(|| panic!("missing HTTP wake record"))
                .wait_registration;
            assert_eq!(wait_registration.owner(), Some(WaitOwnerClass::Http));
            assert_eq!(wait_registration.deadline(), Some(deadline.instant()));
            assert_ne!(wait_registration.id().get(), 0);
        }
        assert_eq!(handle.wait_registry().snapshot().registrations, 1);
        assert_eq!(
            handle.wait_registry().snapshot().earliest_deadline,
            Some(deadline.instant())
        );
        assert!(Scheduler::cancel(&handle, &registration).unwrap_or(false));
        assert_eq!(handle.wait_registry().snapshot().registrations, 0);
        assert_eq!(handle.diagnostics().active_registrations, 0);

        let wake_token = CancellationToken::new();
        let wake_registration = handle
            .register_http_wait(
                Deadline::at(MonotonicInstant::zero()),
                0x5741_4954,
                &wake_token,
            )
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(wake_token.is_wake_ready());
        drop(wake_registration);
        assert_eq!(handle.wait_registry().snapshot().registrations, 0);
        assert!(owner.finalize().is_ok());
    }

    #[test]
    fn http_wait_drop_retires_exact_runtime_registration_and_capacity_is_bounded() {
        let (owner, _source, handle) = manual_driver(1);
        let token = CancellationToken::new();
        let deadline = Deadline::at(MonotonicInstant::from_duration(Duration::from_secs(9)));
        let registration = handle
            .register_http_wait(deadline, 7, &token)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(matches!(
            handle.register_http_wait(deadline, 8, &token),
            Err(TimeDriverError::Capacity { limit: 1 })
        ));
        assert_eq!(handle.wait_registry().snapshot().registrations, 1);
        drop(registration);
        assert_eq!(handle.wait_registry().snapshot().registrations, 0);
        assert_eq!(handle.diagnostics().active_registrations, 0);
        assert!(owner.finalize().is_ok());
    }

    #[test]
    fn provider_wait_exposes_owner_and_preserves_absolute_deadline() {
        let (owner, _source, handle) = manual_driver(3);
        let token = CancellationToken::new();
        let deadline = Deadline::at(MonotonicInstant::from_duration(Duration::from_secs(17)));
        let registration = handle
            .register_provider_wait(deadline, 0x5052_4f56, &token)
            .unwrap_or_else(|error| panic!("{error}"));

        {
            let wakes = DriverSchedulerState::lock(&handle.shared.scheduler.state.wakes);
            let wait_registration = &wakes
                .get(&registration.id())
                .unwrap_or_else(|| panic!("missing provider wake record"))
                .wait_registration;
            assert_eq!(wait_registration.owner(), Some(WaitOwnerClass::Provider));
            assert_eq!(wait_registration.deadline(), Some(deadline.instant()));
            assert_eq!(
                wait_registration.identity().map(|identity| identity.len()),
                Some(8)
            );
        }
        assert_eq!(handle.wait_registry().snapshot().registrations, 1);
        assert_eq!(
            handle.wait_registry().snapshot().earliest_deadline,
            Some(deadline.instant())
        );

        assert!(Scheduler::cancel(&handle, &registration).unwrap_or(false));
        assert_eq!(handle.wait_registry().snapshot().registrations, 0);
        assert_eq!(handle.diagnostics().active_registrations, 0);

        let expired_token = CancellationToken::new();
        let expired = handle
            .register_provider_wait(
                Deadline::at(MonotonicInstant::zero()),
                0x4558_5049,
                &expired_token,
            )
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(expired_token.is_wake_ready());
        assert_eq!(handle.wait_registry().snapshot().registrations, 1);
        drop(expired);
        assert_eq!(handle.wait_registry().snapshot().registrations, 0);
        assert_eq!(handle.diagnostics().active_registrations, 0);
        assert!(owner.finalize().is_ok());
    }

    #[test]
    fn provider_wait_zero_key_rejects_before_any_admission() {
        let (owner, _source, handle) = manual_driver(1);
        let token = CancellationToken::new();
        let deadline = Deadline::at(MonotonicInstant::from_duration(Duration::from_secs(9)));
        let registry_before = handle.wait_registry().snapshot();
        let diagnostics_before = handle.diagnostics();

        let error = handle
            .register_provider_wait(deadline, 0, &token)
            .unwrap_err();
        assert_eq!(error, TimeDriverError::InvalidProviderKey);
        assert_eq!(error.code(), "app.time-driver.provider-key");
        assert_eq!(error.to_string(), "app.time-driver.provider-key");
        assert!(!token.is_wake_ready());

        let registry_after = handle.wait_registry().snapshot();
        let diagnostics_after = handle.diagnostics();
        assert_eq!(registry_after, registry_before);
        assert_eq!(
            diagnostics_after.registrations,
            diagnostics_before.registrations
        );
        assert_eq!(
            diagnostics_after.active_registrations,
            diagnostics_before.active_registrations
        );
        assert_eq!(
            diagnostics_after.earliest_deadline,
            diagnostics_before.earliest_deadline
        );
        assert_eq!(diagnostics_after.last_error, diagnostics_before.last_error);
        assert_eq!(registry_after.registrations, 0);
        assert_eq!(diagnostics_after.registrations, 0);
        assert_eq!(diagnostics_after.active_registrations, 0);
        assert!(owner.finalize().is_ok());
    }

    #[test]
    fn result_wait_registrar_preserves_provider_id_deadline_and_wakes() {
        let (owner, _source, handle) = manual_driver(2);
        let wake = WakeCounter::new();
        let waker = Waker::from(Arc::clone(&wake));
        let operation = ResultOperationId::new(41).unwrap_or_else(|| panic!("operation id"));
        let deadline = MonotonicInstant::from_duration(Duration::from_secs(23));
        let spec = ResultWaitSpec {
            operation,
            owner: WaitOwnerClass::Provider,
            deadline,
            waker,
        };
        let mut registration = <TimeDriverHandle as ResultWaitRegistrar>::register(&handle, spec)
            .unwrap_or_else(|error| panic!("{error}"));

        {
            let wakes = DriverSchedulerState::lock(&handle.shared.scheduler.state.wakes);
            let record = wakes
                .values()
                .find(|record| record.wake.key == operation.get())
                .unwrap_or_else(|| panic!("missing result provider wake"));
            assert_eq!(record.wake.key, operation.get());
            assert_eq!(record.wake.deadline.instant(), deadline);
            assert_eq!(
                record.wait_registration.owner(),
                Some(WaitOwnerClass::Provider)
            );
            assert_eq!(record.wait_registration.deadline(), Some(deadline));
        }
        assert_eq!(handle.wait_registry().snapshot().registrations, 1);
        assert!(registration.retire().is_ok());
        wake.wait_one();
        assert_eq!(handle.wait_registry().snapshot().registrations, 0);
        assert_eq!(handle.diagnostics().active_registrations, 0);
        assert!(owner.finalize().is_ok());
    }

    #[test]
    fn result_wait_registrar_drop_retires_exact_registration() {
        let (owner, _source, handle) = manual_driver(1);
        let wake = WakeCounter::new();
        let spec = ResultWaitSpec {
            operation: ResultOperationId::new(7).unwrap_or_else(|| panic!("operation id")),
            owner: WaitOwnerClass::Provider,
            deadline: MonotonicInstant::from_duration(Duration::from_secs(23)),
            waker: Waker::from(Arc::clone(&wake)),
        };
        let registration = <TimeDriverHandle as ResultWaitRegistrar>::register(&handle, spec)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(handle.wait_registry().snapshot().registrations, 1);
        drop(registration);
        assert_eq!(handle.wait_registry().snapshot().registrations, 0);
        assert_eq!(handle.diagnostics().active_registrations, 0);
        assert!(owner.finalize().is_ok());
    }

    #[test]
    fn result_wait_registrar_rejects_zero_impossible_and_non_provider_atomically() {
        assert!(ResultOperationId::new(0).is_none());

        let (owner, _source, handle) = manual_driver(1);
        let wake = WakeCounter::new();
        let registry_before = handle.wait_registry().snapshot();
        let diagnostics_before = handle.diagnostics();
        let spec = ResultWaitSpec {
            operation: ResultOperationId::new(8).unwrap_or_else(|| panic!("operation id")),
            owner: WaitOwnerClass::Queue,
            deadline: MonotonicInstant::from_duration(Duration::from_secs(23)),
            waker: Waker::from(Arc::clone(&wake)),
        };
        let result = <TimeDriverHandle as ResultWaitRegistrar>::register(&handle, spec);
        assert!(matches!(result, Err(ResultWaitError::Rejected)));
        let registry_after = handle.wait_registry().snapshot();
        let diagnostics_after = handle.diagnostics();
        assert_eq!(registry_after, registry_before);
        assert_eq!(
            diagnostics_after.registrations,
            diagnostics_before.registrations
        );
        assert_eq!(
            diagnostics_after.active_registrations,
            diagnostics_before.active_registrations
        );
        assert_eq!(diagnostics_after.last_error, diagnostics_before.last_error);
        assert_eq!(registry_after.registrations, 0);
        assert_eq!(wake.calls.load(Ordering::Acquire), 0);
        assert!(owner.finalize().is_ok());
    }

    #[test]
    fn result_wait_registrar_maps_capacity_and_shutdown() {
        let (owner, _source, handle) = manual_driver(1);
        let first_spec = ResultWaitSpec {
            operation: ResultOperationId::new(51).unwrap_or_else(|| panic!("operation id")),
            owner: WaitOwnerClass::Provider,
            deadline: MonotonicInstant::from_duration(Duration::from_secs(23)),
            waker: Waker::noop().clone(),
        };
        let first = <TimeDriverHandle as ResultWaitRegistrar>::register(&handle, first_spec)
            .unwrap_or_else(|error| panic!("{error}"));
        let second_spec = ResultWaitSpec {
            operation: ResultOperationId::new(52).unwrap_or_else(|| panic!("operation id")),
            owner: WaitOwnerClass::Provider,
            deadline: MonotonicInstant::from_duration(Duration::from_secs(23)),
            waker: Waker::noop().clone(),
        };
        let second = <TimeDriverHandle as ResultWaitRegistrar>::register(&handle, second_spec);
        assert!(matches!(second, Err(ResultWaitError::Rejected)));

        let report = owner.finalize().unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(report.cancelled_registrations, 1);
        let third_spec = ResultWaitSpec {
            operation: ResultOperationId::new(53).unwrap_or_else(|| panic!("operation id")),
            owner: WaitOwnerClass::Provider,
            deadline: MonotonicInstant::from_duration(Duration::from_secs(23)),
            waker: Waker::noop().clone(),
        };
        let third = <TimeDriverHandle as ResultWaitRegistrar>::register(&handle, third_spec);
        assert!(matches!(third, Err(ResultWaitError::Shutdown)));
        drop(first);
        assert!(owner.finalize().is_ok());
    }

    #[test]
    fn provider_wait_preserves_capacity_shutdown_and_drop_retirement() {
        let (owner, _source, handle) = manual_driver(1);
        let token = CancellationToken::new();
        let deadline = Deadline::at(MonotonicInstant::from_duration(Duration::from_secs(9)));
        let registration = handle
            .register_provider_wait(deadline, 11, &token)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(matches!(
            handle.register_provider_wait(deadline, 12, &token),
            Err(TimeDriverError::Capacity { limit: 1 })
        ));
        assert_eq!(handle.wait_registry().snapshot().registrations, 1);

        let report = owner.finalize().unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(report.cancelled_registrations, 1);
        assert!(handle.wait_registry().is_shutdown());
        assert_eq!(handle.wait_registry().snapshot().registrations, 0);
        assert!(matches!(
            handle.register_provider_wait(deadline, 13, &token),
            Err(TimeDriverError::Stopped)
        ));
        drop(registration);
        assert!(owner.finalize().is_ok());
    }

    #[test]
    fn provider_wait_earlier_deadline_wakes_executor() {
        let (owner, _source, handle) = manual_driver(3);
        let executor_wake = WakeCounter::new();
        let executor_waker = Waker::from(Arc::clone(&executor_wake));
        handle
            .set_wait_waker(&executor_waker)
            .unwrap_or_else(|error| panic!("{error}"));
        let first_token = CancellationToken::new();
        let first = handle
            .register_provider_wait(
                Deadline::at(MonotonicInstant::from_duration(Duration::from_secs(60))),
                21,
                &first_token,
            )
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(executor_wake.calls.load(Ordering::Acquire) >= 1);

        let second_token = CancellationToken::new();
        let second = handle
            .register_provider_wait(
                Deadline::at(MonotonicInstant::from_duration(Duration::from_secs(1))),
                22,
                &second_token,
            )
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(executor_wake.calls.load(Ordering::Acquire) >= 2);
        assert_eq!(
            handle.diagnostics().earliest_deadline,
            Some(MonotonicInstant::from_duration(Duration::from_secs(1)))
        );
        assert!(Scheduler::cancel(&handle, &second).unwrap_or(false));
        assert!(Scheduler::cancel(&handle, &first).unwrap_or(false));
        assert_eq!(handle.diagnostics().active_registrations, 0);
        assert!(owner.finalize().is_ok());
    }

    #[test]
    fn provider_wait_cancellation_wakes_exact_token() {
        let (owner, _source, handle) = manual_driver(2);
        let token = CancellationToken::new();
        let token_wake = WakeCounter::new();
        let token_waker = Waker::from(Arc::clone(&token_wake));
        token.register_waker(&token_waker);
        let registration = handle
            .register_provider_wait(
                Deadline::at(MonotonicInstant::from_duration(Duration::from_secs(60))),
                31,
                &token,
            )
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!token.is_wake_ready());
        assert!(Scheduler::cancel(&handle, &registration).unwrap_or(false));
        assert!(token.is_wake_ready());
        token_wake.wait_one();
        assert_eq!(handle.wait_registry().snapshot().registrations, 0);
        assert_eq!(handle.diagnostics().active_registrations, 0);
        assert!(owner.finalize().is_ok());
    }

    #[test]
    fn sleeper_drop_retires_its_registration_without_a_worker_per_wait() {
        let (owner, _source, handle) = manual_driver(2);
        let wake = WakeCounter::new();
        let waker = Waker::from(Arc::clone(&wake));
        let mut context = Context::from_waker(&waker);
        let mut future = handle.sleep_owned(Duration::from_secs(3_600));
        assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
        assert_eq!(handle.diagnostics().active_registrations, 1);
        drop(future);
        assert_eq!(handle.diagnostics().active_registrations, 0);

        let token = CancellationToken::new();
        let registration = Scheduler::register_wake(
            &handle,
            Deadline::at(MonotonicInstant::from_duration(Duration::from_secs(3_600))),
            9,
            &token,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(handle.diagnostics().active_registrations, 1);
        drop(registration);
        assert_eq!(handle.diagnostics().active_registrations, 0);
        assert!(owner.finalize().is_ok());
    }

    #[test]
    fn capacity_and_checked_overflow_are_typed() {
        let (owner, _source, handle) = manual_driver(1);
        let token = CancellationToken::new();
        let registration =
            Scheduler::register_after(&handle, Duration::from_secs(3_600), 1, &token)
                .unwrap_or_else(|error| panic!("{error}"));
        assert!(matches!(
            Scheduler::register_after(&handle, Duration::from_secs(3_600), 2, &token),
            Err(SchedulerError::Capacity { limit: 1 })
        ));
        assert!(
            Deadline::after(
                MonotonicInstant::from_duration(Duration::MAX),
                Duration::from_nanos(1)
            )
            .is_none()
        );
        assert!(Scheduler::cancel(&handle, &registration).unwrap_or(false));

        handle
            .shared
            .scheduler
            .next_id
            .store(u64::MAX, std::sync::atomic::Ordering::Release);
        let max_id_registration = Scheduler::register_wake(
            &handle,
            Deadline::at(MonotonicInstant::from_duration(Duration::from_secs(3_600))),
            3,
            &token,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(max_id_registration.id(), u64::MAX);
        drop(max_id_registration);
        assert!(matches!(
            Scheduler::register_wake(
                &handle,
                Deadline::at(MonotonicInstant::from_duration(Duration::from_secs(3_600))),
                4,
                &token,
            ),
            Err(SchedulerError::WakeIdOverflow)
        ));
        assert!(owner.finalize().is_ok());
    }

    #[test]
    fn synchronous_and_cross_thread_cancellation_wake_exact_token() {
        let (owner, _source, handle) = manual_driver(4);
        let sync_token = CancellationToken::new();
        let sync_wake = WakeCounter::new();
        let sync_waker = Waker::from(Arc::clone(&sync_wake));
        sync_token.register_waker(&sync_waker);
        let sync_registration = Scheduler::register_wake(
            &handle,
            Deadline::at(MonotonicInstant::zero()),
            1,
            &sync_token,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(sync_token.is_wake_ready());
        assert!(sync_wake.calls.load(Ordering::Acquire) >= 1);
        drop(sync_registration);

        let cross_token = CancellationToken::new();
        let cross_wake = WakeCounter::new();
        let cross_waker = Waker::from(Arc::clone(&cross_wake));
        cross_token.register_waker(&cross_waker);
        let cross_registration = Scheduler::register_wake(
            &handle,
            Deadline::at(MonotonicInstant::from_duration(Duration::from_secs(3_600))),
            2,
            &cross_token,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let cross_handle = handle.clone();
        let join = thread::spawn(move || {
            Scheduler::cancel(&cross_handle, &cross_registration)
                .unwrap_or_else(|error| panic!("{error}"))
        });
        assert!(join.join().unwrap_or(false));
        cross_wake.wait_one();
        assert_eq!(handle.diagnostics().active_registrations, 0);
        assert!(owner.finalize().is_ok());
    }

    #[test]
    fn injected_clock_advancement_consumes_due_wait_without_sleeping() {
        let (owner, source, handle) = manual_driver(2);
        let token = CancellationToken::new();
        let wake = WakeCounter::new();
        let waker = Waker::from(Arc::clone(&wake));
        token.register_waker(&waker);
        let _registration = Scheduler::register_wake(
            &handle,
            Deadline::at(MonotonicInstant::from_duration(Duration::from_millis(5))),
            4,
            &token,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        source.advance(Duration::from_millis(5));
        owner.notify_worker_for_test();
        wake.wait_one();
        assert_eq!(handle.diagnostics().active_registrations, 0);
        assert!(owner.finalize().is_ok());
    }
}
