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
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::task::Waker;
use std::time::Duration;

use crate::ControlSignal;

const MAX_SCHEDULED_WAKEUPS: usize = 65_536;

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

/// A cancellation token with monotonic severity and a wake list.
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
    local_wakers: Arc<Mutex<Vec<Waker>>>,
}

#[derive(Debug)]
struct SharedCancellation {
    stop: AtomicU8,
    generation: AtomicU64,
    wakers: Mutex<Vec<Waker>>,
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
            local_wakers: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Creates a user-local view. Test-stop severity is shared; thread-stop,
    /// `NextLoop`, wake readiness, and wakers are not.
    #[must_use]
    pub fn clone_for_user(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
            thread_stop: Arc::new(AtomicBool::new(false)),
            next_loop: Arc::new(AtomicBool::new(false)),
            wake_ready: Arc::new(AtomicBool::new(false)),
            local_generation: Arc::new(AtomicU64::new(0)),
            local_wakers: Arc::new(Mutex::new(Vec::new())),
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
            local_wakers: Arc::new(Mutex::new(Vec::new())),
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

    /// Registers a waker to be called on cancellation.
    ///
    /// Duplicate registration is harmless and the list is bounded. A full
    /// list simply leaves the caller responsible for polling again; it cannot
    /// allocate without limit.
    pub fn register_waker(&self, waker: &Waker) {
        {
            let mut wakers = lock(&self.shared.wakers);
            if wakers.len() < MAX_SCHEDULED_WAKEUPS {
                wakers.push(waker.clone());
            }
        }
        let mut wakers = lock(&self.local_wakers);
        if wakers.len() < MAX_SCHEDULED_WAKEUPS {
            wakers.push(waker.clone());
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
        let _ = self.shared.generation.fetch_add(1, Ordering::AcqRel);
    }

    fn wake_all(&self) {
        let wakers = std::mem::take(&mut *lock(&self.shared.wakers));
        for waker in wakers {
            waker.wake();
        }
    }

    fn bump_local_generation(&self) {
        let _ = self.local_generation.fetch_add(1, Ordering::AcqRel);
    }

    fn wake_local(&self) {
        let wakers = std::mem::take(&mut *lock(&self.local_wakers));
        for waker in wakers {
            waker.wake();
        }
    }
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
    /// A registration referred to an unknown wake ID.
    UnknownWake { id: u64 },
    /// A wake registration was already cancelled or consumed.
    WakeNotPending { id: u64 },
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
            Self::UnknownWake { .. } => "runtime.scheduler.unknown-wake",
            Self::WakeNotPending { .. } => "runtime.scheduler.wake-not-pending",
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
            Self::UnknownWake { id } | Self::WakeNotPending { id } => {
                write!(formatter, "{}: wake {id}", self.code())
            }
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

/// A wake registration returned by a scheduler.
#[derive(Clone, Debug)]
pub struct WakeRegistration {
    id: u64,
    scheduler: Weak<SchedulerState>,
    token: CancellationToken,
}

impl WakeRegistration {
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

    /// Cancels this registration. Repeated cancellation is idempotent.
    pub fn cancel(&self) -> Result<bool, SchedulerError> {
        let Some(scheduler) = self.scheduler.upgrade() else {
            return Ok(false);
        };
        let mut state = lock(&scheduler.wakes);
        let Some(wake) = state.get_mut(&self.id) else {
            return Err(SchedulerError::UnknownWake { id: self.id });
        };
        if !wake.pending {
            return Ok(false);
        }
        wake.pending = false;
        Ok(true)
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
}

#[derive(Debug)]
struct SchedulerState {
    wakes: Mutex<BTreeMap<u64, WakeRecord>>,
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
    fn cancel(&self, registration: &WakeRegistration) -> Result<bool, SchedulerError> {
        registration.cancel()
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
        Self {
            state: Arc::new(SchedulerState {
                wakes: Mutex::new(BTreeMap::new()),
            }),
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
            .filter(|record| record.pending && record.wake.deadline.expired(now))
            .map(|record| {
                record.pending = false;
                record.consumed = true;
                (record.wake.clone(), record.token.clone())
            })
            .collect::<Vec<_>>();
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
        let id = self.next_id.fetch_add(1, Ordering::AcqRel);
        if id == 0 {
            return Err(SchedulerError::Capacity {
                limit: self.max_wakes,
            });
        }
        let wake = ScheduledWake { id, deadline, key };
        wakes.insert(
            id,
            WakeRecord {
                wake,
                pending: true,
                consumed: false,
                token: token.clone(),
            },
        );
        Ok(WakeRegistration {
            id,
            scheduler: Arc::downgrade(&self.state),
            token: token.clone(),
        })
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
        registration.cancel().map(|_| ())
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
        if this.registration.is_none() {
            match this.scheduler.register_wake(this.deadline, 0, &this.token) {
                Ok(registration) => this.registration = Some(registration),
                Err(error) => return std::task::Poll::Ready(Err(error)),
            }
        }
        this.token.register_waker(context.waker());
        std::task::Poll::Pending
    }
}

impl Drop for DeadlineFuture<'_> {
    fn drop(&mut self) {
        let _ = self.cancel_registration();
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
    fn equal_deadlines_use_key_then_id_and_cancellation_is_idempotent() {
        let scheduler = DeterministicScheduler::default();
        let token = CancellationToken::new();
        let first = scheduler
            .register_after(Duration::from_millis(1), 10, &token)
            .expect("first");
        let second = scheduler
            .register_after(Duration::from_millis(1), 2, &token)
            .expect("second");
        assert!(first.cancel().expect("cancel"));
        assert!(!first.cancel().expect("idempotent cancel"));
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
        scheduler
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
