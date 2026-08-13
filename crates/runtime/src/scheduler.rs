// SPDX-License-Identifier: Apache-2.0
//! Executor-neutral scheduling, deadlines, and cancellation tokens.
//!
//! The runtime never parks a thread or creates an executor.  An application
//! edge supplies a [`Scheduler`] implementation and components receive the
//! [`CancellationToken`] through [`crate::ExecutionContext`].  The bounded
//! in-memory implementation in this module is useful for deterministic tests
//! and for small embedders; production adapters may translate the same
//! contract to an async runtime.

use std::collections::BTreeMap;
use std::fmt;
use std::future::{self, Future};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::task::Waker;
use std::time::Duration;

use crate::ControlSignal;

const MAX_SCHEDULED_WAKEUPS: usize = 65_536;
const WAKE_PENDING: u8 = 0;
const WAKE_CANCELLED: u8 = 1;
const WAKE_CONSUMED: u8 = 2;
const WAKE_CANCELLING: u8 = 3;

fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A monotonic absolute instant used by scheduler implementations.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct MonotonicInstant(Duration);

impl MonotonicInstant {
    /// Returns the zero instant.
    #[must_use]
    pub const fn zero() -> Self {
        Self(Duration::ZERO)
    }

    /// Creates an instant from a duration since the scheduler epoch.
    #[must_use]
    pub const fn from_duration(value: Duration) -> Self {
        Self(value)
    }

    /// Returns the duration since the scheduler epoch.
    #[must_use]
    pub const fn as_duration(self) -> Duration {
        self.0
    }

    /// Adds a bounded duration, returning `None` on overflow.
    #[must_use]
    pub const fn checked_add(self, duration: Duration) -> Option<Self> {
        match self.0.checked_add(duration) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Returns the non-negative distance between two instants.
    #[must_use]
    pub const fn duration_since(self, earlier: Self) -> Option<Duration> {
        self.0.checked_sub(earlier.0)
    }
}

/// An absolute deadline passed to an interruptible operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Deadline {
    instant: MonotonicInstant,
}

impl Deadline {
    /// Creates a deadline at an absolute monotonic instant.
    #[must_use]
    pub const fn at(instant: MonotonicInstant) -> Self {
        Self { instant }
    }

    /// Creates a deadline relative to `now`.
    pub const fn after(now: MonotonicInstant, duration: Duration) -> Option<Self> {
        match now.checked_add(duration) {
            Some(instant) => Some(Self { instant }),
            None => None,
        }
    }

    /// Returns the absolute instant.
    #[must_use]
    pub const fn instant(self) -> MonotonicInstant {
        self.instant
    }

    /// Returns whether the deadline has elapsed at `now`.
    #[must_use]
    pub fn expired(self, now: MonotonicInstant) -> bool {
        now >= self.instant
    }

    /// Returns the remaining duration, or zero when expired.
    #[must_use]
    pub const fn remaining(self, now: MonotonicInstant) -> Duration {
        match self.instant.duration_since(now) {
            Some(value) => value,
            None => Duration::ZERO,
        }
    }
}

/// A cancellation token with monotonic severity and a de-duplicated wake list.
///
/// `NextLoop` and `StopThread` are per-user actions. Graceful and immediate
/// test-stop requests are shared by cloned tokens and can only escalate. A
/// token never maps graceful and immediate stop to the same state, which lets
/// an edge choose whether to drain or interrupt an in-flight operation.
#[derive(Clone, Debug)]
pub struct CancellationToken {
    shared: Arc<SharedCancellation>,
    thread_stop: Arc<AtomicBool>,
    next_loop: Arc<AtomicBool>,
    wake_ready: Arc<AtomicBool>,
    local_generation: Arc<AtomicU64>,
    local_owner: Arc<()>,
}

#[derive(Debug)]
struct SharedCancellation {
    stop: AtomicU8,
    generation: AtomicU64,
    wakers: Mutex<Vec<RegisteredWaker>>,
}

/// One executor waker with one or more token-local subscriptions.
///
/// A deadline future needs the same executor waker for both shared test-stop
/// and token-local scheduler events. Keeping those subscriptions in one entry
/// makes identity and capacity accounting unambiguous while the owner list
/// keeps local signals isolated between cloned user tokens.
#[derive(Debug)]
struct RegisteredWaker {
    waker: Waker,
    identity: WakerIdentity,
    owners: Vec<Weak<()>>,
}

/// Stable identity of a raw waker target.
///
/// `Waker::will_wake` is allowed to conservatively return `false`, including
/// for a cloned no-op waker. The raw data/vtable pair is the executor-defined
/// identity used by `Waker` itself, so retaining it lets capacity accounting
/// de-duplicate such registrations without guessing from waker values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WakerIdentity {
    data: usize,
    vtable: usize,
}

impl WakerIdentity {
    fn of(waker: &Waker) -> Self {
        Self {
            data: waker.data() as usize,
            vtable: waker.vtable() as *const _ as usize,
        }
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

impl CancellationToken {
    /// Creates a token with no pending request.
    #[must_use]
    pub fn new() -> Self {
        Self {
            shared: Arc::new(SharedCancellation {
                stop: AtomicU8::new(ControlSignal::Continue as u8),
                generation: AtomicU64::new(0),
                wakers: Mutex::new(Vec::new()),
            }),
            thread_stop: Arc::new(AtomicBool::new(false)),
            next_loop: Arc::new(AtomicBool::new(false)),
            wake_ready: Arc::new(AtomicBool::new(false)),
            local_generation: Arc::new(AtomicU64::new(0)),
            local_owner: Arc::new(()),
        }
    }

    /// Creates a user-local view. Test-stop severity is shared; thread-stop,
    /// `NextLoop`, wake readiness, and local waker ownership are not.
    #[must_use]
    pub fn clone_for_user(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
            thread_stop: Arc::new(AtomicBool::new(false)),
            next_loop: Arc::new(AtomicBool::new(false)),
            wake_ready: Arc::new(AtomicBool::new(false)),
            local_generation: Arc::new(AtomicU64::new(0)),
            local_owner: Arc::new(()),
        }
    }

    /// Returns a process/run-shared child token with fresh user-local stop,
    /// logical-action, wake, and waker state.
    #[must_use]
    pub fn child(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
            thread_stop: Arc::new(AtomicBool::new(false)),
            next_loop: Arc::new(AtomicBool::new(false)),
            wake_ready: Arc::new(AtomicBool::new(false)),
            local_generation: Arc::new(AtomicU64::new(0)),
            local_owner: Arc::new(()),
        }
    }

    /// Requests a signal, retaining the most severe stop request.
    pub fn request(&self, signal: ControlSignal) {
        if signal == ControlSignal::NextLoop {
            self.next_loop.store(true, Ordering::Release);
            self.bump_local_generation();
            self.wake_local();
            return;
        }
        if signal == ControlSignal::StopThread {
            self.thread_stop.store(true, Ordering::Release);
            self.bump_local_generation();
            self.wake_local();
            return;
        }
        if !matches!(
            signal,
            ControlSignal::StopTestGraceful | ControlSignal::StopTestImmediate
        ) {
            return;
        }
        let requested = signal as u8;
        let mut current = self.shared.stop.load(Ordering::Acquire);
        while current < requested {
            match self.shared.stop.compare_exchange_weak(
                current,
                requested,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.bump_generation();
                    self.wake_all();
                    break;
                }
                Err(observed) => current = observed,
            }
        }
    }

    /// Requests a graceful test stop.
    pub fn cancel_graceful(&self) {
        self.request(ControlSignal::StopTestGraceful);
    }

    /// Requests an immediate test stop.
    pub fn cancel_immediate(&self) {
        self.request(ControlSignal::StopTestImmediate);
    }

    /// Returns the current signal without consuming `NextLoop`.
    #[must_use]
    pub fn signal(&self) -> ControlSignal {
        let stop = signal_from_u8(self.shared.stop.load(Ordering::Acquire));
        if stop.is_stop() {
            stop
        } else if self.thread_stop.load(Ordering::Acquire) {
            ControlSignal::StopThread
        } else if self.next_loop.load(Ordering::Acquire) {
            ControlSignal::NextLoop
        } else {
            ControlSignal::Continue
        }
    }

    /// Takes one pending logical action. Stop requests remain visible.
    #[must_use]
    pub fn take_signal(&self) -> ControlSignal {
        let stop = signal_from_u8(self.shared.stop.load(Ordering::Acquire));
        if stop.is_stop() {
            stop
        } else if self.thread_stop.load(Ordering::Acquire) {
            ControlSignal::StopThread
        } else if self.next_loop.swap(false, Ordering::AcqRel) {
            ControlSignal::NextLoop
        } else {
            ControlSignal::Continue
        }
    }

    /// Returns whether any stop request is pending.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.signal().is_stop()
    }

    /// Returns a monotonic wake generation.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.shared
            .generation
            .load(Ordering::Acquire)
            .max(self.local_generation.load(Ordering::Acquire))
    }

    /// Registers a waker for shared cancellation and token-local wake events.
    ///
    /// Duplicate registration is harmless and the list is bounded. A full
    /// list simply leaves the caller responsible for polling again; it cannot
    /// allocate without limit.
    pub fn register_waker(&self, waker: &Waker) {
        let mut registrations = lock(&self.shared.wakers);
        for registration in &mut *registrations {
            registration.owners.retain(|owner| owner.strong_count() > 0);
        }
        registrations.retain(|registration| !registration.owners.is_empty());

        let owner = Arc::downgrade(&self.local_owner);
        let identity = WakerIdentity::of(waker);
        let owner_count = registrations.iter().fold(0_usize, |count, registration| {
            count.saturating_add(registration.owners.len())
        });
        let owner_capacity = owner_count < MAX_SCHEDULED_WAKEUPS;
        if let Some(registration) = registrations
            .iter_mut()
            .find(|registration| registration.identity == identity)
        {
            if !registration
                .owners
                .iter()
                .any(|registered| owner_matches(registered, &self.local_owner))
                && owner_capacity
            {
                registration.owners.push(owner);
            }
            return;
        }

        if owner_capacity && registrations.len() < MAX_SCHEDULED_WAKEUPS {
            registrations.push(RegisteredWaker {
                waker: waker.clone(),
                identity,
                owners: vec![owner],
            });
        }
    }

    /// Marks this token as ready for a scheduler wake and wakes registered
    /// futures. Scheduler readiness is independent from logical control
    /// signals, so a timer wake cannot accidentally become `NextLoop`.
    pub fn wake(&self) {
        self.wake_ready.store(true, Ordering::Release);
        self.bump_local_generation();
        self.wake_local();
    }

    /// Returns whether a scheduler wake is pending.
    #[must_use]
    pub fn is_wake_ready(&self) -> bool {
        self.wake_ready.load(Ordering::Acquire)
    }

    /// Consumes one scheduler wake readiness bit.
    #[must_use]
    pub fn take_wake(&self) -> bool {
        self.wake_ready.swap(false, Ordering::AcqRel)
    }

    fn bump_generation(&self) {
        let _ =
            self.shared
                .generation
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    current.checked_add(1)
                });
    }

    fn wake_all(&self) {
        let registrations = std::mem::take(&mut *lock(&self.shared.wakers));
        for registration in registrations {
            registration.waker.wake();
        }
    }

    fn bump_local_generation(&self) {
        let _ =
            self.local_generation
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    current.checked_add(1)
                });
    }

    fn wake_local(&self) {
        let mut wakers = Vec::new();
        let mut registrations = lock(&self.shared.wakers);
        let mut index = 0;
        while index < registrations.len() {
            let registration = &mut registrations[index];
            registration.owners.retain(|owner| owner.strong_count() > 0);
            if registration
                .owners
                .iter()
                .any(|owner| owner_matches(owner, &self.local_owner))
            {
                wakers.push(registration.waker.clone());
                registration
                    .owners
                    .retain(|owner| !owner_matches(owner, &self.local_owner));
            }
            if registration.owners.is_empty() {
                registrations.swap_remove(index);
            } else {
                index += 1;
            }
        }
        drop(registrations);
        for waker in wakers {
            waker.wake();
        }
    }
}

fn owner_matches(owner: &Weak<()>, expected: &Arc<()>) -> bool {
    owner
        .upgrade()
        .is_some_and(|actual| Arc::ptr_eq(&actual, expected))
}

impl PartialEq for CancellationToken {
    fn eq(&self, other: &Self) -> bool {
        self.signal() == other.signal()
    }
}

impl Eq for CancellationToken {}

fn signal_from_u8(value: u8) -> ControlSignal {
    match value {
        1 => ControlSignal::NextLoop,
        2 => ControlSignal::StopThread,
        3 => ControlSignal::StopTestGraceful,
        4..=u8::MAX => ControlSignal::StopTestImmediate,
        _ => ControlSignal::Continue,
    }
}

/// Stable scheduler failures.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    missing_docs,
    reason = "error payload fields are documented by variant semantics"
)]
pub enum SchedulerError {
    /// The wake registry reached its configured capacity.
    Capacity { limit: usize },
    /// A deadline addition overflowed.
    DeadlineOverflow { delay: Duration },
    /// The bounded wake-registration ID space was exhausted.
    WakeIdOverflow,
    /// A registration referred to an unknown wake ID.
    UnknownWake { id: u64 },
    /// A wake registration was already cancelled or consumed.
    WakeNotPending { id: u64 },
    /// A registration owner panicked while cancelling a wake.
    CancellationPanicked,
    /// A scheduler operation would move virtual time backwards.
    TimeWentBackwards {
        current: MonotonicInstant,
        target: MonotonicInstant,
    },
    /// An injected scheduler is not available in this profile.
    Unsupported(String),
}

impl SchedulerError {
    /// Returns the stable diagnostic code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Capacity { .. } => "runtime.scheduler.capacity",
            Self::DeadlineOverflow { .. } => "runtime.scheduler.deadline-overflow",
            Self::WakeIdOverflow => "runtime.scheduler.wake-id-overflow",
            Self::UnknownWake { .. } => "runtime.scheduler.unknown-wake",
            Self::WakeNotPending { .. } => "runtime.scheduler.wake-not-pending",
            Self::CancellationPanicked => "runtime.scheduler.cancellation-panicked",
            Self::TimeWentBackwards { .. } => "runtime.scheduler.time-backwards",
            Self::Unsupported(_) => "runtime.scheduler.unsupported",
        }
    }
}

impl fmt::Display for SchedulerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capacity { limit } => write!(formatter, "{}: limit {limit}", self.code()),
            Self::DeadlineOverflow { delay } => {
                write!(formatter, "{}: delay {delay:?}", self.code())
            }
            Self::WakeIdOverflow => write!(formatter, "{}", self.code()),
            Self::UnknownWake { id } | Self::WakeNotPending { id } => {
                write!(formatter, "{}: wake {id}", self.code())
            }
            Self::CancellationPanicked => formatter.write_str(self.code()),
            Self::TimeWentBackwards { current, target } => write!(
                formatter,
                "{}: current={:?}, target={:?}",
                self.code(),
                current,
                target
            ),
            Self::Unsupported(message) => write!(formatter, "{}: {}", self.code(), message),
        }
    }
}

impl std::error::Error for SchedulerError {}

/// A bounded owner callback for one wake registration.
///
/// The callback atomically retires exactly its `id` and does not retain the
/// token or any run payload. The registration wakes its token after a
/// successful retirement. Callback work is constant-time and nonblocking;
/// panics are contained by the registration, including during `Drop`.
pub type WakeRegistrationCallback =
    dyn Fn(u64, &CancellationToken) -> Result<bool, SchedulerError> + Send + Sync + 'static;

struct WakeRegistrationState {
    owner: Weak<WakeRegistrationCallback>,
    status: AtomicU8,
}

impl fmt::Debug for WakeRegistrationState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WakeRegistrationState")
            .field("owner_alive", &self.owner.strong_count())
            .field("status", &self.status.load(Ordering::Acquire))
            .finish()
    }
}

/// A linear wake registration returned by a scheduler.
///
/// This handle is deliberately not [`Clone`].  Exactly one future or owner
/// holds it, and dropping it performs the same bounded cancellation callback
/// as explicit scheduler cancellation.  The callback is held weakly, so a
/// scheduler may be finalized without a registration keeping its owner (or
/// any engine/result/request data reachable from that owner) alive.
pub struct WakeRegistration {
    id: u64,
    token: CancellationToken,
    state: Arc<WakeRegistrationState>,
}

impl fmt::Debug for WakeRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WakeRegistration")
            .field("id", &self.id)
            .field("token", &self.token)
            .field("state", &self.state)
            .finish()
    }
}

impl WakeRegistration {
    /// Constructs a registration from a weak owner callback.
    ///
    /// The owner is intentionally weak.  Callers should retain the owner in
    /// the scheduler/run state and pass only this handle to a future.  A dead
    /// owner is treated as an already-retired registration during cleanup.
    #[must_use]
    pub fn from_weak_owner(
        id: u64,
        token: CancellationToken,
        owner: Weak<WakeRegistrationCallback>,
    ) -> Self {
        Self {
            id,
            token,
            state: Arc::new(WakeRegistrationState {
                owner,
                status: AtomicU8::new(WAKE_PENDING),
            }),
        }
    }

    /// Constructs a registration from a run-owned callback owner.
    ///
    /// Only a weak owner reference is retained by the returned handle; the
    /// caller's `Arc` remains the strong owner. This helper performs the
    /// callback-owner unsizing for concrete closure types.
    #[must_use]
    pub fn from_owner<F>(id: u64, token: CancellationToken, owner: &Arc<F>) -> Self
    where
        F: Fn(u64, &CancellationToken) -> Result<bool, SchedulerError> + Send + Sync + 'static,
    {
        let owner: Arc<WakeRegistrationCallback> = owner.clone();
        Self::from_weak_owner(id, token, Arc::downgrade(&owner))
    }

    /// Returns the stable registration ID.
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Returns the token associated with this registration.
    #[must_use]
    pub fn token(&self) -> &CancellationToken {
        &self.token
    }

    /// Returns whether this registration belongs to an exact callback owner.
    #[must_use]
    pub fn belongs_to_owner(&self, owner: &Arc<WakeRegistrationCallback>) -> bool {
        let owner: Arc<WakeRegistrationCallback> = owner.clone();
        let weak = Arc::downgrade(&owner);
        Weak::ptr_eq(&self.state.owner, &weak)
    }

    /// Cancels this registration through an exact callback owner.
    ///
    /// Scheduler implementations use this narrow capability to reject
    /// foreign registrations before dispatching cancellation. It is not a
    /// handle-wide cancellation bypass: the owner identity must match the
    /// weak callback captured at construction.
    pub fn cancel_for_owner(
        &self,
        owner: &Arc<WakeRegistrationCallback>,
    ) -> Result<bool, SchedulerError> {
        if !self.belongs_to_owner(owner) {
            return Err(SchedulerError::UnknownWake { id: self.id });
        }
        self.cancel_with_owner()
    }

    /// Performs one owner callback, with a linearized idempotence guard.
    ///
    /// This is intentionally private: callers must use the [`Scheduler`]
    /// capability so a production scheduler can enforce its own ownership
    /// and accounting policy.  The `Drop` implementation uses this same path
    /// for the final best-effort retirement.
    fn cancel_with_owner(&self) -> Result<bool, SchedulerError> {
        if self
            .state
            .status
            .compare_exchange(
                WAKE_PENDING,
                WAKE_CANCELLING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return Ok(false);
        }

        let Some(owner) = self.state.owner.upgrade() else {
            self.state.status.store(WAKE_CANCELLED, Ordering::Release);
            return Ok(false);
        };

        let callback = catch_unwind(AssertUnwindSafe(|| owner(self.id, &self.token)));
        match callback {
            Ok(Ok(cancelled)) => {
                self.state.status.store(WAKE_CANCELLED, Ordering::Release);
                if cancelled {
                    self.wake_token()?;
                }
                Ok(cancelled)
            }
            Ok(Err(error)) => {
                // Keep a failed registration retryable for an explicit
                // caller.  Drop performs one bounded retry and cannot expose
                // the error, so owner callbacks must make the registry
                // operation atomic and return errors only for a terminal
                // invariant/resource failure.
                self.state.status.store(WAKE_PENDING, Ordering::Release);
                Err(error)
            }
            Err(_) => {
                // A panic must never cross a destructor boundary.  Mark the
                // linear handle retired and wake its token so an executor can
                // observe the failed cancellation rather than stall forever.
                self.state.status.store(WAKE_CANCELLED, Ordering::Release);
                let _ = self.wake_token();
                Err(SchedulerError::CancellationPanicked)
            }
        }
    }

    fn wake_token(&self) -> Result<(), SchedulerError> {
        catch_unwind(AssertUnwindSafe(|| self.token.wake()))
            .map_err(|_| SchedulerError::CancellationPanicked)
    }
}

impl Drop for WakeRegistration {
    fn drop(&mut self) {
        let _ = self.cancel_with_owner();
    }
}

/// One scheduler wake record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScheduledWake {
    /// Registration ID.
    pub id: u64,
    /// Absolute deadline at which it became ready.
    pub deadline: Deadline,
    /// Caller-provided stable ordering key.
    pub key: u64,
}

#[derive(Clone, Debug)]
struct WakeRecord {
    wake: ScheduledWake,
    pending: bool,
    consumed: bool,
    token: CancellationToken,
    state: Arc<WakeRegistrationState>,
}

struct SchedulerState {
    wakes: Mutex<BTreeMap<u64, WakeRecord>>,
    owner: Arc<WakeRegistrationCallback>,
}

impl fmt::Debug for SchedulerState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SchedulerState")
            .field("wakes", &lock(&self.wakes).len())
            .finish_non_exhaustive()
    }
}

impl SchedulerState {
    fn cancel_registration(&self, id: u64) -> Result<bool, SchedulerError> {
        let mut wakes = lock(&self.wakes);
        let Some(record) = wakes.get(&id) else {
            return Err(SchedulerError::UnknownWake { id });
        };
        if !record.pending {
            return Ok(false);
        }
        let record = wakes
            .remove(&id)
            .ok_or(SchedulerError::UnknownWake { id })?;
        record.state.status.store(WAKE_CANCELLED, Ordering::Release);
        Ok(true)
    }
}

/// A scheduler capability used by runtime and component adapters.
pub trait Scheduler: Send + Sync {
    /// Returns the current monotonic instant.
    fn now(&self) -> MonotonicInstant;

    /// Registers a wake at an absolute deadline.
    fn register_wake(
        &self,
        deadline: Deadline,
        key: u64,
        token: &CancellationToken,
    ) -> Result<WakeRegistration, SchedulerError>;

    /// Registers a wake after a relative delay.
    fn register_after(
        &self,
        delay: Duration,
        key: u64,
        token: &CancellationToken,
    ) -> Result<WakeRegistration, SchedulerError> {
        let deadline =
            Deadline::after(self.now(), delay).ok_or(SchedulerError::DeadlineOverflow { delay })?;
        self.register_wake(deadline, key, token)
    }

    /// Cancels a wake registration.
    ///
    /// The default dispatches the registration's exact callback. Production
    /// schedulers that wrap additional owner state should override this
    /// method and call [`WakeRegistration::cancel_for_owner`] after checking
    /// their callback identity.
    fn cancel(&self, registration: &WakeRegistration) -> Result<bool, SchedulerError> {
        registration.cancel_with_owner()
    }
}

/// A no-op scheduler used when an application does not need virtual wakeups.
#[derive(Clone, Copy, Debug, Default)]
pub struct ImmediateScheduler;

impl Scheduler for ImmediateScheduler {
    fn now(&self) -> MonotonicInstant {
        MonotonicInstant::zero()
    }

    fn register_wake(
        &self,
        deadline: Deadline,
        key: u64,
        token: &CancellationToken,
    ) -> Result<WakeRegistration, SchedulerError> {
        if deadline.expired(self.now()) {
            token.wake();
        }
        Err(SchedulerError::Unsupported(format!(
            "immediate scheduler cannot retain wake {key}"
        )))
    }

    fn cancel(&self, registration: &WakeRegistration) -> Result<bool, SchedulerError> {
        Err(SchedulerError::UnknownWake {
            id: registration.id(),
        })
    }
}

/// A bounded deterministic scheduler for unit and integration seams.
#[derive(Clone, Debug)]
pub struct DeterministicScheduler {
    state: Arc<SchedulerState>,
    now: Arc<Mutex<MonotonicInstant>>,
    next_id: Arc<AtomicU64>,
    max_wakes: usize,
}

impl Default for DeterministicScheduler {
    fn default() -> Self {
        Self::new(MonotonicInstant::zero(), MAX_SCHEDULED_WAKEUPS)
    }
}

impl DeterministicScheduler {
    /// Creates a scheduler with a bounded wake registry.
    #[must_use]
    pub fn new(now: MonotonicInstant, max_wakes: usize) -> Self {
        let state = Arc::new_cyclic(|weak_state: &Weak<SchedulerState>| {
            let weak_state = weak_state.clone();
            let owner: Arc<WakeRegistrationCallback> = Arc::new(move |id, _token| {
                let Some(state) = weak_state.upgrade() else {
                    return Ok(false);
                };
                state.cancel_registration(id)
            });
            SchedulerState {
                wakes: Mutex::new(BTreeMap::new()),
                owner,
            }
        });
        Self {
            state,
            now: Arc::new(Mutex::new(now)),
            next_id: Arc::new(AtomicU64::new(1)),
            max_wakes: max_wakes.min(MAX_SCHEDULED_WAKEUPS),
        }
    }

    /// Returns all ready wakes in deadline/key/ID order and marks them
    /// consumed. Cancelled wakes are omitted.
    pub fn poll_ready(&self) -> Vec<ScheduledWake> {
        let now = self.now();
        let mut wakes = lock(&self.state.wakes);
        let mut ready = wakes
            .values_mut()
            .filter(|record| {
                record.pending
                    && record.state.status.load(Ordering::Acquire) == WAKE_PENDING
                    && record.wake.deadline.expired(now)
            })
            .map(|record| {
                record.pending = false;
                record.consumed = true;
                record.state.status.store(WAKE_CONSUMED, Ordering::Release);
                (record.wake.clone(), record.token.clone())
            })
            .collect::<Vec<_>>();
        let ready_ids = ready.iter().map(|(wake, _)| wake.id).collect::<Vec<_>>();
        for id in ready_ids {
            wakes.remove(&id);
        }
        drop(wakes);
        ready.sort_by(|left, right| {
            left.0
                .deadline
                .instant()
                .cmp(&right.0.deadline.instant())
                .then_with(|| left.0.key.cmp(&right.0.key))
                .then_with(|| left.0.id.cmp(&right.0.id))
        });
        ready.iter().for_each(|(_, token)| token.wake());
        ready.into_iter().map(|(wake, _)| wake).collect()
    }

    /// Advances virtual time and returns ready wakes.
    pub fn advance_to(
        &self,
        target: MonotonicInstant,
    ) -> Result<Vec<ScheduledWake>, SchedulerError> {
        let mut now = lock(&self.now);
        if target < *now {
            return Err(SchedulerError::TimeWentBackwards {
                current: *now,
                target,
            });
        }
        *now = target;
        drop(now);
        Ok(self.poll_ready())
    }

    /// Advances by a relative duration and returns ready wakes.
    pub fn advance_by(&self, duration: Duration) -> Result<Vec<ScheduledWake>, SchedulerError> {
        let target = self
            .now()
            .checked_add(duration)
            .ok_or(SchedulerError::DeadlineOverflow { delay: duration })?;
        self.advance_to(target)
    }

    /// Returns the earliest pending deadline.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Deadline> {
        lock(&self.state.wakes)
            .values()
            .filter(|record| record.pending)
            .map(|record| record.wake.deadline)
            .min_by_key(|deadline| deadline.instant())
    }
}

impl Scheduler for DeterministicScheduler {
    fn now(&self) -> MonotonicInstant {
        *lock(&self.now)
    }

    fn register_wake(
        &self,
        deadline: Deadline,
        key: u64,
        token: &CancellationToken,
    ) -> Result<WakeRegistration, SchedulerError> {
        let mut wakes = lock(&self.state.wakes);
        if wakes.len() >= self.max_wakes {
            wakes.retain(|_, record| record.pending);
        }
        if wakes.len() >= self.max_wakes {
            return Err(SchedulerError::Capacity {
                limit: self.max_wakes,
            });
        }
        let id = self
            .next_id
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                if current == 0 {
                    None
                } else {
                    Some(current.checked_add(1).unwrap_or_default())
                }
            })
            .map_err(|_| SchedulerError::WakeIdOverflow)?;
        let wake = ScheduledWake { id, deadline, key };
        let expired = deadline.expired(self.now());
        let state = Arc::new(WakeRegistrationState {
            owner: Arc::downgrade(&self.state.owner),
            status: AtomicU8::new(WAKE_PENDING),
        });
        wakes.insert(
            id,
            WakeRecord {
                wake,
                pending: true,
                consumed: false,
                token: token.clone(),
                state: Arc::clone(&state),
            },
        );
        drop(wakes);
        // Arrange an immediate wake for an already-expired absolute
        // deadline. This closes the register-then-wake race for futures that
        // have not registered their executor waker yet.
        if expired {
            token.wake();
        }
        Ok(WakeRegistration {
            id,
            token: token.clone(),
            state,
        })
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

/// A future that completes when a deadline expires or a token is cancelled.
///
/// The future does not spawn or sleep. The caller must poll it after advancing
/// its scheduler or after the token wakes its registered waker.
pub struct DeadlineFuture<'a> {
    scheduler: &'a dyn Scheduler,
    deadline: Deadline,
    token: CancellationToken,
    registration: Option<WakeRegistration>,
}

/// A bounded, monotonic scheduler window for a thread group.
///
/// The window has an optional absolute end. A delay that would begin after
/// the end is rejected with [`ScheduleWindow::EARLY_STOP`]; a delay that
/// reaches beyond the end is clipped to the remaining duration. This mirrors
/// JMeter's `TimerService` pre-sampler contract while keeping the sampler
/// itself free to cross the boundary once started.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScheduleWindow {
    start: MonotonicInstant,
    end: Option<MonotonicInstant>,
}

impl ScheduleWindow {
    /// Sentinel returned when a thread should stop before invoking its sampler.
    pub const EARLY_STOP: Option<Duration> = None;

    /// Creates a window with an optional duration from `start`.
    pub fn new(
        start: MonotonicInstant,
        duration: Option<Duration>,
    ) -> Result<Self, SchedulerError> {
        let end = duration
            .map(|value| {
                start
                    .checked_add(value)
                    .ok_or(SchedulerError::DeadlineOverflow { delay: value })
            })
            .transpose()?;
        Ok(Self { start, end })
    }

    /// Returns the window start instant.
    #[must_use]
    pub const fn start(self) -> MonotonicInstant {
        self.start
    }

    /// Returns the optional absolute end instant.
    #[must_use]
    pub const fn end(self) -> Option<MonotonicInstant> {
        self.end
    }

    /// Returns whether the scheduler window has elapsed at `now`.
    #[must_use]
    pub fn expired(self, now: MonotonicInstant) -> bool {
        self.end.is_some_and(|end| now >= end)
    }

    /// Clips a pre-sampler delay to the remaining window.
    ///
    /// `None` means that the sampler must not be invoked. Zero-duration
    /// delays remain eligible at the exact end instant only when the caller
    /// asks before the boundary; at/after the boundary they return `None`.
    pub fn delay_before_sampler(
        self,
        now: MonotonicInstant,
        delay: Duration,
    ) -> Result<Option<Duration>, SchedulerError> {
        if now < self.start {
            return Err(SchedulerError::TimeWentBackwards {
                current: now,
                target: self.start,
            });
        }
        let Some(end) = self.end else {
            return Ok(Some(delay));
        };
        if now >= end {
            return Ok(Self::EARLY_STOP);
        }
        let remaining = end
            .duration_since(now)
            .ok_or(SchedulerError::TimeWentBackwards {
                current: now,
                target: end,
            })?;
        Ok(Some(delay.min(remaining)))
    }
}

impl<'a> DeadlineFuture<'a> {
    /// Creates a deadline future.
    #[must_use]
    pub fn new(scheduler: &'a dyn Scheduler, deadline: Deadline, token: CancellationToken) -> Self {
        Self {
            scheduler,
            deadline,
            token,
            registration: None,
        }
    }

    fn cancel_registration(&mut self) -> Result<(), SchedulerError> {
        let Some(registration) = self.registration.take() else {
            return Ok(());
        };
        self.scheduler.cancel(&registration).map(|_| ())
    }
}

impl Future for DeadlineFuture<'_> {
    type Output = Result<ControlSignal, SchedulerError>;

    fn poll(
        self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.get_mut();
        let signal = this.token.signal();
        if signal.is_stop() {
            return std::task::Poll::Ready(this.cancel_registration().map(|()| signal));
        }
        if this.deadline.expired(this.scheduler.now()) {
            return std::task::Poll::Ready(
                this.cancel_registration()
                    .map(|()| ControlSignal::StopTestGraceful),
            );
        }
        let mut registered = false;
        if this.registration.is_none() {
            match this.scheduler.register_wake(this.deadline, 0, &this.token) {
                Ok(registration) => {
                    this.registration = Some(registration);
                    registered = true;
                }
                Err(error) => return std::task::Poll::Ready(Err(error)),
            }
        }
        this.token.register_waker(context.waker());
        // Cancellation or a scheduler wake can race the registration above.
        // Re-check after installing the waker and explicitly reschedule the
        // owner when the event happened before the waker was visible.
        let raced_wake = registered && this.token.take_wake();
        if this.token.signal().is_stop()
            || raced_wake
            || this.deadline.expired(this.scheduler.now())
        {
            context.waker().wake_by_ref();
        }
        std::task::Poll::Pending
    }
}

impl Drop for DeadlineFuture<'_> {
    fn drop(&mut self) {
        let _ = catch_unwind(AssertUnwindSafe(|| self.cancel_registration()));
    }
}

/// An executor-neutral future returning a capability result.
pub type SchedulerFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, SchedulerError>> + 'a>>;

/// Returns an immediately-ready scheduler future for adapters that need a
/// standard boxed future shape.
pub fn ready<T>(value: Result<T, SchedulerError>) -> SchedulerFuture<'static, T>
where
    T: 'static,
{
    Box::pin(future::ready(value))
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "deterministic scheduler setup")]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::atomic::AtomicUsize;

    #[derive(Debug)]
    struct CountingWake(Arc<AtomicUsize>);

    impl std::task::Wake for CountingWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }

    #[derive(Debug)]
    struct TestOwner {
        active: Mutex<BTreeSet<u64>>,
        callbacks: AtomicUsize,
    }

    impl TestOwner {
        fn new(id: u64) -> Arc<Self> {
            Arc::new(Self {
                active: Mutex::new(BTreeSet::from([id])),
                callbacks: AtomicUsize::new(0),
            })
        }

        fn active_count(&self) -> usize {
            lock(&self.active).len()
        }
    }

    fn test_owner_callback(owner: &Arc<TestOwner>) -> Arc<WakeRegistrationCallback> {
        let owner = Arc::clone(owner);
        Arc::new(move |id, _token| {
            owner.callbacks.fetch_add(1, Ordering::AcqRel);
            let removed = lock(&owner.active).remove(&id);
            Ok(removed)
        })
    }

    fn registration_from_callback(
        id: u64,
        token: CancellationToken,
        callback: &Arc<WakeRegistrationCallback>,
    ) -> WakeRegistration {
        WakeRegistration::from_weak_owner(id, token, Arc::downgrade(callback))
    }

    fn panicking_owner_callback() -> Arc<WakeRegistrationCallback> {
        Arc::new(|_id, _token| -> Result<bool, SchedulerError> {
            panic!("test callback panic");
        })
    }

    #[derive(Debug, Default)]
    struct TestDispatchScheduler;

    impl Scheduler for TestDispatchScheduler {
        fn now(&self) -> MonotonicInstant {
            MonotonicInstant::zero()
        }

        fn register_wake(
            &self,
            _deadline: Deadline,
            _key: u64,
            _token: &CancellationToken,
        ) -> Result<WakeRegistration, SchedulerError> {
            Err(SchedulerError::Unsupported(
                "test dispatch scheduler does not register wakes".to_owned(),
            ))
        }
    }

    #[test]
    fn deadline_and_cancellation_remain_distinct() {
        let token = CancellationToken::new();
        let scheduler = DeterministicScheduler::default();
        let registration = scheduler
            .register_after(Duration::from_millis(5), 4, &token)
            .expect("registration");
        assert_eq!(registration.id(), 1);
        assert!(scheduler.poll_ready().is_empty());
        assert_eq!(
            scheduler
                .advance_by(Duration::from_millis(5))
                .expect("advance")
                .len(),
            1
        );
        token.cancel_graceful();
        assert_eq!(token.signal(), ControlSignal::StopTestGraceful);
        token.cancel_immediate();
        assert_eq!(token.signal(), ControlSignal::StopTestImmediate);
    }

    #[test]
    fn dropping_linear_registration_before_deadline_retires_exact_owner_entry() {
        let owner = TestOwner::new(17);
        let token = CancellationToken::new();
        let callback = test_owner_callback(&owner);
        let registration = registration_from_callback(17, token, &callback);
        assert_eq!(owner.active_count(), 1);
        drop(registration);
        assert_eq!(owner.active_count(), 0);
        assert_eq!(owner.callbacks.load(Ordering::Acquire), 1);
    }

    #[test]
    fn explicit_scheduler_cancellation_is_idempotent_and_drop_does_not_repeat_it() {
        let owner = TestOwner::new(19);
        let token = CancellationToken::new();
        let callback = test_owner_callback(&owner);
        let registration = registration_from_callback(19, token, &callback);
        let scheduler = TestDispatchScheduler;

        // A scheduler capability dispatches the exact owner callback.  The
        // registration itself exposes no public cancellation bypass.
        assert!(scheduler.cancel(&registration).is_ok());
        assert_eq!(owner.active_count(), 0);
        assert_eq!(owner.callbacks.load(Ordering::Acquire), 1);
        assert!(
            !scheduler
                .cancel(&registration)
                .expect("second cancellation is idempotent")
        );
        drop(registration);
        assert_eq!(owner.callbacks.load(Ordering::Acquire), 1);
    }

    #[test]
    fn deterministic_drop_reclaims_capacity_before_deadline() {
        let scheduler = DeterministicScheduler::new(MonotonicInstant::zero(), 1);
        let token = CancellationToken::new();
        let first = scheduler
            .register_after(Duration::from_secs(1), 1, &token)
            .expect("first registration");
        let first_id = first.id();
        drop(first);
        assert_eq!(scheduler.next_deadline(), None);
        assert!(lock(&scheduler.state.wakes).is_empty());

        let replacement = scheduler
            .register_after(Duration::from_secs(2), 2, &token)
            .expect("drop must release bounded capacity");
        assert_eq!(replacement.id(), first_id + 1);
    }

    #[test]
    fn foreign_scheduler_rejects_without_touching_registration_owner() {
        let owner = TestOwner::new(23);
        let token = CancellationToken::new();
        let callback = test_owner_callback(&owner);
        let registration = registration_from_callback(23, token, &callback);
        let scheduler = DeterministicScheduler::default();
        let foreign = DeterministicScheduler::default();

        assert!(matches!(
            foreign.cancel(&registration),
            Err(SchedulerError::UnknownWake { id: 23 })
        ));
        assert_eq!(owner.active_count(), 1);
        assert_eq!(owner.callbacks.load(Ordering::Acquire), 0);
        assert_eq!(scheduler.next_deadline(), None);
        drop(registration);
        assert_eq!(owner.active_count(), 0);
    }

    #[test]
    fn owner_callback_panic_is_contained_during_drop() {
        let token = CancellationToken::new();
        let callback = panicking_owner_callback();
        let registration = registration_from_callback(29, token, &callback);
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| drop(registration)));
        assert!(result.is_ok());
    }

    #[test]
    fn owner_callback_panic_is_reported_by_explicit_cancellation() {
        let token = CancellationToken::new();
        let callback = panicking_owner_callback();
        let registration = registration_from_callback(31, token, &callback);
        let scheduler = TestDispatchScheduler;
        assert_eq!(
            scheduler.cancel(&registration),
            Err(SchedulerError::CancellationPanicked)
        );
        drop(registration);
    }

    #[derive(Debug)]
    struct OverrideScheduler {
        inner: DeterministicScheduler,
        cancellations: Arc<AtomicUsize>,
    }

    impl Scheduler for OverrideScheduler {
        fn now(&self) -> MonotonicInstant {
            self.inner.now()
        }

        fn register_wake(
            &self,
            deadline: Deadline,
            key: u64,
            token: &CancellationToken,
        ) -> Result<WakeRegistration, SchedulerError> {
            self.inner.register_wake(deadline, key, token)
        }

        fn cancel(&self, registration: &WakeRegistration) -> Result<bool, SchedulerError> {
            self.cancellations.fetch_add(1, Ordering::AcqRel);
            self.inner.cancel(registration)
        }
    }

    #[test]
    fn deadline_future_drop_uses_the_scheduler_owned_cancellation_path() {
        let scheduler = OverrideScheduler {
            inner: DeterministicScheduler::default(),
            cancellations: Arc::new(AtomicUsize::new(0)),
        };
        let token = CancellationToken::new();
        let deadline = Deadline::after(scheduler.now(), Duration::from_secs(1)).expect("deadline");
        let mut future = DeadlineFuture::new(&scheduler, deadline, token);
        let waker = Waker::noop();
        let mut context = std::task::Context::from_waker(waker);
        assert!(matches!(
            Pin::new(&mut future).poll(&mut context),
            std::task::Poll::Pending
        ));
        assert!(scheduler.inner.next_deadline().is_some());
        drop(future);
        assert_eq!(
            scheduler.cancellations.load(Ordering::Acquire),
            1,
            "DeadlineFuture must not call the handle's private owner directly"
        );
        assert_eq!(scheduler.inner.next_deadline(), None);
    }

    #[test]
    fn equal_deadlines_use_key_then_id_and_cancellation_is_idempotent() {
        let scheduler = DeterministicScheduler::default();
        let token = CancellationToken::new();
        let first = scheduler
            .register_after(Duration::from_millis(1), 10, &token)
            .expect("first");
        let second = scheduler
            .register_after(Duration::from_millis(1), 2, &token)
            .expect("second");
        assert!(scheduler.cancel(&first).expect("cancel"));
        assert!(!scheduler.cancel(&first).expect("idempotent cancel"));
        let wakes = scheduler
            .advance_by(Duration::from_millis(1))
            .expect("advance");
        assert_eq!(
            wakes.iter().map(|wake| wake.id).collect::<Vec<_>>(),
            vec![second.id()]
        );
    }

    #[test]
    fn scheduler_capacity_and_backwards_time_are_typed() {
        let scheduler = DeterministicScheduler::new(MonotonicInstant::zero(), 1);
        let token = CancellationToken::new();
        let _first = scheduler
            .register_after(Duration::from_millis(1), 1, &token)
            .expect("first wake");
        assert!(matches!(
            scheduler.register_after(Duration::from_millis(1), 2, &token),
            Err(SchedulerError::Capacity { limit: 1 })
        ));
        scheduler
            .advance_to(MonotonicInstant::from_duration(Duration::from_millis(1)))
            .expect("advance");
        assert!(matches!(
            scheduler.advance_to(MonotonicInstant::zero()),
            Err(SchedulerError::TimeWentBackwards { .. })
        ));
    }

    #[test]
    fn relative_deadline_overflow_is_typed_and_does_not_move_time() {
        let scheduler =
            DeterministicScheduler::new(MonotonicInstant::from_duration(Duration::MAX), 1);
        let token = CancellationToken::new();
        assert!(matches!(
            scheduler.register_after(Duration::from_nanos(1), 1, &token),
            Err(SchedulerError::DeadlineOverflow { .. })
        ));
        assert!(matches!(
            scheduler.advance_by(Duration::from_nanos(1)),
            Err(SchedulerError::DeadlineOverflow { .. })
        ));
        assert_eq!(
            scheduler.now(),
            MonotonicInstant::from_duration(Duration::MAX)
        );
    }

    #[test]
    fn expired_absolute_registration_wakes_immediately() {
        let scheduler =
            DeterministicScheduler::new(MonotonicInstant::from_duration(Duration::from_secs(1)), 2);
        let token = CancellationToken::new();
        let registration = scheduler
            .register_wake(Deadline::at(MonotonicInstant::zero()), 7, &token)
            .expect("expired wake registration");
        assert!(token.is_wake_ready());
        assert_eq!(
            scheduler.poll_ready(),
            vec![ScheduledWake {
                id: registration.id(),
                deadline: Deadline::at(MonotonicInstant::zero()),
                key: 7,
            }]
        );
    }

    #[test]
    fn wake_registration_id_overflow_is_typed() {
        let scheduler = DeterministicScheduler::new(MonotonicInstant::zero(), 2);
        scheduler.next_id.store(u64::MAX, Ordering::Release);
        let token = CancellationToken::new();
        let registration = scheduler
            .register_after(Duration::ZERO, 1, &token)
            .expect("last wake ID");
        assert_eq!(registration.id(), u64::MAX);
        assert!(matches!(
            scheduler.register_after(Duration::ZERO, 2, &token),
            Err(SchedulerError::WakeIdOverflow)
        ));
    }

    #[test]
    fn duplicate_waker_registration_does_not_consume_capacity() {
        let token = CancellationToken::new();
        let waker = Waker::noop();
        token.register_waker(waker);
        token.register_waker(waker);
        assert_eq!(lock(&token.shared.wakers).len(), 1);
        assert_eq!(lock(&token.shared.wakers)[0].owners.len(), 1);
    }

    #[test]
    fn shared_waker_identity_keeps_local_owners_isolated() {
        let first = CancellationToken::new();
        let second = first.clone_for_user();
        let wake_count = Arc::new(AtomicUsize::new(0));
        let waker = Waker::from(Arc::new(CountingWake(Arc::clone(&wake_count))));

        first.register_waker(&waker);
        second.register_waker(&waker);
        {
            let registrations = lock(&first.shared.wakers);
            assert_eq!(registrations.len(), 1);
            assert_eq!(registrations[0].owners.len(), 2);
        }

        first.request(ControlSignal::NextLoop);
        assert_eq!(wake_count.load(Ordering::Acquire), 1);
        assert_eq!(lock(&first.shared.wakers)[0].owners.len(), 1);

        second.request(ControlSignal::NextLoop);
        assert_eq!(wake_count.load(Ordering::Acquire), 2);
        assert!(lock(&first.shared.wakers).is_empty());

        first.register_waker(&waker);
        second.register_waker(&waker);
        first.cancel_graceful();
        assert_eq!(wake_count.load(Ordering::Acquire), 3);
        assert!(lock(&first.shared.wakers).is_empty());
    }

    #[test]
    fn cancellation_generation_saturates_instead_of_wrapping() {
        let token = CancellationToken::new();
        token.shared.generation.store(u64::MAX, Ordering::Release);
        token.cancel_graceful();
        assert_eq!(token.generation(), u64::MAX);
    }

    #[test]
    fn scheduler_cannot_cancel_a_registration_owned_by_another_scheduler() {
        let first = DeterministicScheduler::default();
        let second = DeterministicScheduler::default();
        let token = CancellationToken::new();
        let registration = first
            .register_after(Duration::from_secs(1), 1, &token)
            .expect("registration");
        assert!(matches!(
            second.cancel(&registration),
            Err(SchedulerError::UnknownWake { id: 1 })
        ));
        assert!(first.next_deadline().is_some());
    }

    #[test]
    fn consumed_registration_remains_idempotently_cancellable_after_reclamation() {
        let scheduler = DeterministicScheduler::new(MonotonicInstant::zero(), 1);
        let token = CancellationToken::new();
        let consumed = scheduler
            .register_after(Duration::ZERO, 1, &token)
            .expect("consumed registration");
        scheduler.advance_by(Duration::ZERO).expect("consume wake");
        let replacement = scheduler
            .register_after(Duration::from_secs(1), 2, &token)
            .expect("replacement registration");
        assert_eq!(replacement.id(), consumed.id() + 1);
        assert!(!scheduler.cancel(&consumed).expect("consumed cancellation"));
        assert!(scheduler.next_deadline().is_some());
    }

    #[test]
    fn schedule_window_clips_delay_and_returns_early_stop_at_end() {
        let start = MonotonicInstant::zero();
        let window = ScheduleWindow::new(start, Some(Duration::from_secs(1))).expect("window");
        assert_eq!(
            window.delay_before_sampler(
                MonotonicInstant::from_duration(Duration::from_millis(400)),
                Duration::from_millis(800)
            ),
            Ok(Some(Duration::from_millis(600)))
        );
        assert_eq!(
            window.delay_before_sampler(
                MonotonicInstant::from_duration(Duration::from_secs(1)),
                Duration::ZERO
            ),
            Ok(ScheduleWindow::EARLY_STOP)
        );
    }

    #[test]
    fn schedule_window_rejects_time_before_start_and_overflow() {
        let start = MonotonicInstant::from_duration(Duration::from_secs(1));
        let window = ScheduleWindow::new(start, None).expect("unbounded window");
        assert!(matches!(
            window.delay_before_sampler(MonotonicInstant::zero(), Duration::ZERO),
            Err(SchedulerError::TimeWentBackwards { .. })
        ));
        assert!(matches!(
            ScheduleWindow::new(start, Some(Duration::MAX)),
            Err(SchedulerError::DeadlineOverflow { .. })
        ));
        assert_eq!(
            window.delay_before_sampler(start, Duration::from_millis(3)),
            Ok(Some(Duration::from_millis(3)))
        );
    }

    #[test]
    fn clone_for_user_does_not_share_next_loop() {
        let parent = CancellationToken::new();
        let first = parent.clone_for_user();
        let second = parent.clone_for_user();
        first.request(ControlSignal::NextLoop);
        assert_eq!(first.take_signal(), ControlSignal::NextLoop);
        assert_eq!(second.signal(), ControlSignal::Continue);
        parent.cancel_graceful();
        assert_eq!(first.signal(), ControlSignal::StopTestGraceful);
        assert_eq!(second.signal(), ControlSignal::StopTestGraceful);
    }

    #[test]
    fn child_stop_thread_is_local_and_ready_wake_marks_original_token() {
        let parent = CancellationToken::new();
        let child = parent.child();
        child.request(ControlSignal::StopThread);
        assert_eq!(child.signal(), ControlSignal::StopThread);
        assert_eq!(parent.signal(), ControlSignal::Continue);

        let scheduler = DeterministicScheduler::default();
        let registration = scheduler
            .register_after(Duration::from_millis(1), 1, &parent)
            .expect("wake registration");
        scheduler
            .advance_by(Duration::from_millis(1))
            .expect("wake advance");
        assert!(registration.token().is_wake_ready());
        assert!(registration.token().take_wake());
        assert!(!registration.token().take_wake());
    }

    #[test]
    fn immediate_scheduler_reports_unsupported_wake_without_pending() {
        let scheduler = ImmediateScheduler;
        let token = CancellationToken::new();
        let deadline =
            Deadline::after(MonotonicInstant::zero(), Duration::from_secs(1)).expect("deadline");
        let mut future = DeadlineFuture::new(&scheduler, deadline, token);
        let waker = Waker::noop();
        let mut context = std::task::Context::from_waker(waker);
        let result = Pin::new(&mut future).poll(&mut context);
        assert!(matches!(
            result,
            std::task::Poll::Ready(Err(SchedulerError::Unsupported(_)))
        ));
    }

    #[test]
    fn deadline_future_unregisters_on_cancel_and_drop() {
        let scheduler = DeterministicScheduler::default();
        let token = CancellationToken::new();
        let deadline =
            Deadline::after(MonotonicInstant::zero(), Duration::from_secs(1)).expect("deadline");
        let waker = Waker::noop();
        let mut context = std::task::Context::from_waker(waker);
        let mut future = DeadlineFuture::new(&scheduler, deadline, token.clone());
        assert!(matches!(
            Pin::new(&mut future).poll(&mut context),
            std::task::Poll::Pending
        ));
        assert!(scheduler.next_deadline().is_some());
        token.cancel_graceful();
        assert!(matches!(
            Pin::new(&mut future).poll(&mut context),
            std::task::Poll::Ready(Ok(ControlSignal::StopTestGraceful))
        ));
        assert!(scheduler.next_deadline().is_none());

        let token = CancellationToken::new();
        let mut future = DeadlineFuture::new(&scheduler, deadline, token);
        assert!(matches!(
            Pin::new(&mut future).poll(&mut context),
            std::task::Poll::Pending
        ));
        assert!(scheduler.next_deadline().is_some());
        drop(future);
        assert!(scheduler.next_deadline().is_none());
    }
}
