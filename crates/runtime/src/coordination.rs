// SPDX-License-Identifier: Apache-2.0
//! Executor-neutral coordination capabilities used by runtime controllers.
//!
//! Coordination is deliberately represented as polling state machines.  A
//! caller which cannot make progress receives [`Poll::Pending`] and owns the
//! future that will poll again; a coordinator never parks an executor thread,
//! sleeps, or starts a task.  The small `Mutex` critical sections below only
//! protect the bounded in-memory state transition and are never held while a
//! caller supplied [`Waker`] is invoked.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::{Mutex, MutexGuard};
use std::task::{Poll, Waker};
use std::time::Duration;

use crate::ComponentError;
use crate::timers::{
    SynchronizingCoordinator, SynchronizingOutcome, SynchronizingRequest, ThroughputCoordinator,
    ThroughputRequest,
};

const MAX_LOCK_NAME_BYTES: usize = 4_096;
const MAX_HELD_LOCKS: usize = 65_536;
const MAX_CRITICAL_WAITERS: usize = 65_536;
const MAX_BARRIER_NAME_BYTES: usize = 4_096;
const MAX_BARRIER_GROUP_BYTES: usize = 4_096;
const MAX_BARRIER_PARTICIPANT_BYTES: usize = 4_096;
const MAX_BARRIER_PARTICIPANTS: usize = 65_536;
const MAX_BARRIER_SLOTS: usize = 65_536;
const MAX_THROUGHPUT_PARTICIPANT_BYTES: usize = 4_096;
const MAX_THROUGHPUT_PARTICIPANTS: usize = 65_536;
const MAX_THROUGHPUT_SCOPES: usize = 65_536;
const NANOS_PER_MILLISECOND: u128 = 1_000_000;
const HALF_MILLISECOND_NANOS: u128 = NANOS_PER_MILLISECOND / 2;

/// A bounded snapshot that lets an executor edge observe coordination waits
/// without taking ownership of a future or an executor handle.
///
/// A coordinator never parks a caller.  The caller translates `pending` and
/// `earliest_deadline` into its own scheduler registration, while
/// `generation` closes the register-then-wake race.  `None` means the
/// coordinator has a wait which is intentionally unbounded (for example a
/// synchronizing timer with timeout zero); the caller still owns cancellation
/// of that wait.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoordinationWaitSnapshot {
    /// Checked generation of wait-state changes.
    pub generation: CoordinationGeneration,
    /// Number of bounded pending arrivals/acquisitions.
    pub pending: usize,
    /// Earliest absolute monotonic deadline, if one is known.
    pub earliest_deadline: Option<Duration>,
}

impl CoordinationWaitSnapshot {
    const fn empty() -> Self {
        Self {
            generation: CoordinationGeneration::initial(),
            pending: 0,
            earliest_deadline: None,
        }
    }
}

/// Executor-neutral observation seam for a coordinator that can remain
/// pending.  The snapshot contains only bounded state; the caller still owns
/// the scheduler registration, cancellation, and wake race handling.
#[allow(
    dead_code,
    reason = "application edges may opt into this executor seam"
)]
pub trait CoordinationWaitSource: Send + Sync {
    /// Returns the current wait generation, count, and earliest deadline.
    #[must_use]
    fn wait_snapshot(&self) -> CoordinationWaitSnapshot;
}

fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn bounded_component_text(value: impl Into<String>, limit: usize) -> String {
    let mut value = value.into();
    if value.len() <= limit {
        return value;
    }
    let mut end = limit;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    value
}

fn invalid_component(message: impl Into<String>) -> ComponentError {
    ComponentError::failure(bounded_component_text(message, MAX_LOCK_NAME_BYTES))
}

/// Applies Java's non-negative `Math.round` at JMeter's millisecond boundary
/// to a duration supplied by the throughput request contract.
///
/// The timer request currently exposes a `Duration`, rather than the original
/// floating-point samples-per-minute property.  This preserves exact
/// round-before-scheduling behavior for an unrounded duration and fails closed
/// on values which cannot be represented as a checked `Duration` in whole
/// milliseconds.  A caller which has already discarded the raw rate cannot
/// reconstruct distinctions between rates that round to the same base period.
fn jmeter_rounded_period(period: Duration) -> Result<Duration, ComponentError> {
    let nanos = period.as_nanos();
    let rounded_millis = nanos
        .checked_add(HALF_MILLISECOND_NANOS)
        .ok_or_else(|| ComponentError::resource_limit("throughput period rounding"))?
        / NANOS_PER_MILLISECOND;
    if rounded_millis == 0 {
        return Err(ComponentError::resource_limit(
            "throughput period precision",
        ));
    }
    duration_from_millis(rounded_millis)
}

fn jmeter_scaled_period(period: Duration, active: u32) -> Result<Duration, ComponentError> {
    let nanos = period
        .as_nanos()
        .checked_mul(u128::from(active))
        .ok_or_else(|| ComponentError::resource_limit("throughput active period"))?;
    let rounded_millis = nanos
        .checked_add(HALF_MILLISECOND_NANOS)
        .ok_or_else(|| ComponentError::resource_limit("throughput active period rounding"))?
        / NANOS_PER_MILLISECOND;
    if rounded_millis == 0 {
        return Err(ComponentError::resource_limit(
            "throughput active period precision",
        ));
    }
    duration_from_millis(rounded_millis)
}

fn duration_from_millis(millis: u128) -> Result<Duration, ComponentError> {
    let seconds = u64::try_from(millis / 1_000)
        .map_err(|_| ComponentError::resource_limit("throughput period seconds"))?;
    let nanos = u32::try_from((millis % 1_000) * 1_000_000)
        .map_err(|_| ComponentError::resource_limit("throughput period nanoseconds"))?;
    Ok(Duration::new(seconds, nanos))
}

/// A non-zero generation for a run-scoped coordination state machine.
///
/// Generation zero is reserved for an absent/uninitialized identity.  A
/// caller can advance a coordinator only after it has drained all active
/// reservations, so a stale release cannot affect a later run.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CoordinationGeneration(NonZeroU64);

impl CoordinationGeneration {
    /// Creates a generation.  Zero is rejected because it represents no
    /// generation in wire and diagnostic identities.
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Returns the numeric generation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    const fn initial() -> Self {
        Self(NonZeroU64::MIN)
    }

    fn next(self) -> Option<Self> {
        Self::new(self.get().checked_add(1)?)
    }
}

fn bump_generation(generation: &mut CoordinationGeneration) -> bool {
    let Some(next) = generation.next() else {
        return false;
    };
    *generation = next;
    true
}

/// Typed failures from a critical-section coordinator.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    missing_docs,
    reason = "error payload fields are documented by variant semantics"
)]
pub enum CriticalSectionError {
    /// A lock name was empty or exceeded the bounded name size.
    InvalidName,
    /// A lifecycle identity was zero where an explicit generation identity is
    /// required.
    InvalidOwner,
    /// The bounded coordinator has no room for another held lock.
    Capacity { limit: usize },
    /// The bounded coordinator has no room for another queued acquisition.
    WaiterCapacity { limit: usize },
    /// Another virtual user currently owns the requested lock.
    Busy { name: String, owner: u64 },
    /// A lock is free but an earlier waiter owns the next fair admission.
    Queued { name: String },
    /// A release did not match the owner that acquired the lock.
    NotOwner { name: String, owner: u64 },
    /// Internal checked accounting did not match the retained locks/waiters.
    AccountingInvariant,
    /// A caller supplied a generation other than the coordinator's current
    /// generation.
    StaleGeneration {
        name: String,
        expected: CoordinationGeneration,
        actual: CoordinationGeneration,
    },
    /// No generation remains after the maximum representable generation.
    GenerationOverflow,
}

impl CriticalSectionError {
    /// Returns a stable diagnostic code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidName => "runtime.critical-section.invalid-name",
            Self::InvalidOwner => "runtime.critical-section.invalid-owner",
            Self::Capacity { .. } => "runtime.critical-section.capacity",
            Self::WaiterCapacity { .. } => "runtime.critical-section.waiter-capacity",
            Self::Busy { .. } => "runtime.critical-section.busy",
            Self::Queued { .. } => "runtime.critical-section.queued",
            Self::NotOwner { .. } => "runtime.critical-section.not-owner",
            Self::AccountingInvariant => "runtime.critical-section.accounting-invariant",
            Self::StaleGeneration { .. } => "runtime.critical-section.stale-generation",
            Self::GenerationOverflow => "runtime.critical-section.generation-overflow",
        }
    }
}

impl fmt::Display for CriticalSectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName
            | Self::InvalidOwner
            | Self::GenerationOverflow
            | Self::AccountingInvariant => {
                write!(formatter, "{}", self.code())
            }
            Self::Capacity { limit } | Self::WaiterCapacity { limit } => {
                write!(formatter, "{}: limit {limit}", self.code())
            }
            Self::Busy { name, owner } => {
                write!(formatter, "{}: {name:?} owned by {owner}", self.code())
            }
            Self::Queued { name } => write!(formatter, "{}: {name:?}", self.code()),
            Self::NotOwner { name, owner } => {
                write!(formatter, "{}: {name:?} owner {owner}", self.code())
            }
            Self::StaleGeneration {
                name,
                expected,
                actual,
            } => write!(
                formatter,
                "{}: {name:?} expected generation {}, got {}",
                self.code(),
                expected.get(),
                actual.get()
            ),
        }
    }
}

impl std::error::Error for CriticalSectionError {}

/// Executor-neutral critical-section coordinator.
pub trait CriticalSectionCoordinator: Send + Sync {
    /// Attempts to acquire a named section for one lifecycle identity.
    fn try_acquire(&self, name: &str, lifecycle_id: u64) -> Result<(), CriticalSectionError>;

    /// Releases a section held by one lifecycle identity.
    fn release(&self, name: &str, lifecycle_id: u64) -> Result<(), CriticalSectionError>;

    /// Polls a fair acquisition.  Implementations that support waiting keep
    /// the request queued and wake the supplied waker when the owner releases
    /// the section.  The default preserves the legacy fail-fast behavior.
    fn poll_acquire(
        &self,
        name: &str,
        lifecycle_id: u64,
        _waker: &Waker,
    ) -> Poll<Result<(), CriticalSectionError>> {
        Poll::Ready(self.try_acquire(name, lifecycle_id))
    }

    /// Cancels a queued acquisition.  The default has no queued state.
    fn cancel_acquire(
        &self,
        _name: &str,
        _lifecycle_id: u64,
    ) -> Result<bool, CriticalSectionError> {
        Ok(false)
    }

    /// Returns the current run generation.  Legacy coordinators have the
    /// initial generation and therefore cannot accept stale-generation calls.
    #[must_use]
    fn generation(&self) -> CoordinationGeneration {
        CoordinationGeneration::initial()
    }

    /// Returns the bounded wait state for an executor edge.  A custom
    /// coordinator may leave this empty when it is fail-fast; a coordinator
    /// which returns `Pending` should override it so the caller can register
    /// an exact finite wait and compare generations after registration.
    #[must_use]
    fn wait_snapshot(&self) -> CoordinationWaitSnapshot {
        CoordinationWaitSnapshot::empty()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HeldLock {
    owner: u64,
    generation: CoordinationGeneration,
}

#[derive(Debug)]
struct CriticalWaiter {
    owner: u64,
    generation: CoordinationGeneration,
    waker: Waker,
}

#[derive(Debug)]
struct CriticalState {
    generation: CoordinationGeneration,
    wait_generation: CoordinationGeneration,
    held: BTreeMap<String, HeldLock>,
    waiters: BTreeMap<String, VecDeque<CriticalWaiter>>,
    waiter_count: usize,
}

impl Default for CriticalState {
    fn default() -> Self {
        Self {
            generation: CoordinationGeneration::initial(),
            wait_generation: CoordinationGeneration::initial(),
            held: BTreeMap::new(),
            waiters: BTreeMap::new(),
            waiter_count: 0,
        }
    }
}

/// Bounded, deterministic named-lock coordination.
///
/// `try_acquire` retains the original fail-fast API.  Async/controller edges
/// should use [`CriticalSectionCoordinator::poll_acquire`], which queues
/// contending users FIFO per lock and wakes only the next eligible waiter.
/// Names, held locks, waiters, and generations are all bounded.
#[derive(Debug)]
pub struct DeterministicCriticalSectionCoordinator {
    state: Mutex<CriticalState>,
    max_held: usize,
    max_waiters: usize,
}

impl Default for DeterministicCriticalSectionCoordinator {
    fn default() -> Self {
        Self::new(MAX_HELD_LOCKS)
    }
}

impl DeterministicCriticalSectionCoordinator {
    /// Creates a coordinator with a finite held-lock bound.  The waiter bound
    /// defaults to the same value and both limits are capped by the runtime
    /// safety bound.
    #[must_use]
    pub fn new(max_held: usize) -> Self {
        Self::with_limits(max_held, max_held)
    }

    /// Creates a coordinator with independent held-lock and waiter bounds.
    #[must_use]
    pub fn with_limits(max_held: usize, max_waiters: usize) -> Self {
        Self {
            state: Mutex::new(CriticalState::default()),
            max_held: max_held.min(MAX_HELD_LOCKS),
            max_waiters: max_waiters.min(MAX_CRITICAL_WAITERS),
        }
    }

    /// Returns the current generation.
    #[must_use]
    pub fn generation(&self) -> CoordinationGeneration {
        lock(&self.state).generation
    }

    /// Returns bounded state needed by an executor edge to drive queued
    /// acquisitions.  Critical sections have no timer-owned deadline; the
    /// exact owner release is the wake source.
    #[must_use]
    pub fn wait_snapshot(&self) -> CoordinationWaitSnapshot {
        let state = lock(&self.state);
        CoordinationWaitSnapshot {
            generation: state.wait_generation,
            pending: state.waiter_count,
            earliest_deadline: None,
        }
    }

    /// Advances to a fresh generation after all locks and waiters have been
    /// drained.  Refusing to advance while state is active prevents a stale
    /// drop from releasing a lock belonging to a later run.
    pub fn advance_generation(&self) -> Result<CoordinationGeneration, CriticalSectionError> {
        let mut state = lock(&self.state);
        if !state.held.is_empty() || state.waiter_count != 0 {
            let owner = state
                .held
                .values()
                .next()
                .map(|held| held.owner)
                .or_else(|| {
                    state
                        .waiters
                        .values()
                        .find_map(|waiters| waiters.front().map(|waiter| waiter.owner))
                })
                .unwrap_or(1);
            return Err(CriticalSectionError::Busy {
                name: "generation".to_owned(),
                owner,
            });
        }
        let generation = state
            .generation
            .next()
            .ok_or(CriticalSectionError::GenerationOverflow)?;
        bump_wait_generation(&mut state)?;
        state.generation = generation;
        Ok(generation)
    }

    /// Acquires using an explicit generation identity.
    pub fn try_acquire_generation(
        &self,
        name: &str,
        lifecycle_id: u64,
        generation: CoordinationGeneration,
    ) -> Result<(), CriticalSectionError> {
        validate_lock_name(name)?;
        validate_owner(lifecycle_id)?;
        let mut state = lock(&self.state);
        validate_generation(&state, generation, name)?;
        try_acquire_locked(&mut state, name, lifecycle_id, self.max_held)
    }

    /// Releases using an explicit generation identity.
    pub fn release_generation(
        &self,
        name: &str,
        lifecycle_id: u64,
        generation: CoordinationGeneration,
    ) -> Result<(), CriticalSectionError> {
        validate_lock_name(name)?;
        validate_owner(lifecycle_id)?;
        let mut state = lock(&self.state);
        validate_generation(&state, generation, name)?;
        release_locked(&mut state, name, lifecycle_id)
    }

    /// Polls a fair acquisition using the current generation.
    pub fn poll_acquire_generation(
        &self,
        name: &str,
        lifecycle_id: u64,
        generation: CoordinationGeneration,
        waker: &Waker,
    ) -> Poll<Result<(), CriticalSectionError>> {
        if let Err(error) = validate_lock_name(name) {
            return Poll::Ready(Err(error));
        }
        if let Err(error) = validate_owner(lifecycle_id) {
            return Poll::Ready(Err(error));
        }
        let mut state = lock(&self.state);
        match validate_generation(&state, generation, name) {
            Err(error) => Poll::Ready(Err(error)),
            Ok(()) => poll_acquire_locked(
                &mut state,
                name,
                lifecycle_id,
                generation,
                waker,
                self.max_held,
                self.max_waiters,
            ),
        }
    }

    /// Cancels one queued acquisition and returns whether it was present.
    pub fn cancel_acquire_generation(
        &self,
        name: &str,
        lifecycle_id: u64,
        generation: CoordinationGeneration,
    ) -> Result<bool, CriticalSectionError> {
        validate_lock_name(name)?;
        validate_owner(lifecycle_id)?;
        let wake = {
            let mut state = lock(&self.state);
            validate_generation(&state, generation, name)?;
            let canceled = cancel_waiter_locked(&mut state, name, lifecycle_id, generation)?;
            let wake = canceled.then(|| next_waiter_waker(&state, name)).flatten();
            (canceled, wake)
        };
        if let Some(waker) = wake.1 {
            waker.wake();
        }
        Ok(wake.0)
    }
}

impl CriticalSectionCoordinator for DeterministicCriticalSectionCoordinator {
    fn try_acquire(&self, name: &str, lifecycle_id: u64) -> Result<(), CriticalSectionError> {
        validate_lock_name(name)?;
        validate_owner(lifecycle_id)?;
        let mut state = lock(&self.state);
        try_acquire_locked(&mut state, name, lifecycle_id, self.max_held)
    }

    fn release(&self, name: &str, lifecycle_id: u64) -> Result<(), CriticalSectionError> {
        validate_lock_name(name)?;
        validate_owner(lifecycle_id)?;
        let (result, wake) = {
            let mut state = lock(&self.state);
            let result = release_locked(&mut state, name, lifecycle_id);
            let wake = if result.is_ok() {
                available_waiter_wakers(&state, self.max_held)
            } else {
                Vec::new()
            };
            (result, wake)
        };
        for waker in wake {
            waker.wake();
        }
        result
    }

    fn poll_acquire(
        &self,
        name: &str,
        lifecycle_id: u64,
        waker: &Waker,
    ) -> Poll<Result<(), CriticalSectionError>> {
        self.poll_acquire_generation(name, lifecycle_id, self.generation(), waker)
    }

    fn cancel_acquire(&self, name: &str, lifecycle_id: u64) -> Result<bool, CriticalSectionError> {
        self.cancel_acquire_generation(name, lifecycle_id, self.generation())
    }

    fn wait_snapshot(&self) -> CoordinationWaitSnapshot {
        DeterministicCriticalSectionCoordinator::wait_snapshot(self)
    }
}

impl CoordinationWaitSource for DeterministicCriticalSectionCoordinator {
    fn wait_snapshot(&self) -> CoordinationWaitSnapshot {
        DeterministicCriticalSectionCoordinator::wait_snapshot(self)
    }
}

fn validate_lock_name(name: &str) -> Result<(), CriticalSectionError> {
    if name.is_empty() || name.len() > MAX_LOCK_NAME_BYTES {
        Err(CriticalSectionError::InvalidName)
    } else {
        Ok(())
    }
}

fn validate_owner(lifecycle_id: u64) -> Result<(), CriticalSectionError> {
    if lifecycle_id == 0 {
        Err(CriticalSectionError::InvalidOwner)
    } else {
        Ok(())
    }
}

fn validate_generation(
    state: &CriticalState,
    generation: CoordinationGeneration,
    name: &str,
) -> Result<(), CriticalSectionError> {
    if state.generation != generation {
        return Err(CriticalSectionError::StaleGeneration {
            name: name.to_owned(),
            expected: state.generation,
            actual: generation,
        });
    }
    Ok(())
}

fn bump_wait_generation(state: &mut CriticalState) -> Result<(), CriticalSectionError> {
    if bump_generation(&mut state.wait_generation) {
        Ok(())
    } else {
        Err(CriticalSectionError::GenerationOverflow)
    }
}

fn try_acquire_locked(
    state: &mut CriticalState,
    name: &str,
    lifecycle_id: u64,
    max_held: usize,
) -> Result<(), CriticalSectionError> {
    if let Some(held) = state.held.get(name) {
        return Err(CriticalSectionError::Busy {
            name: name.to_owned(),
            owner: held.owner,
        });
    }
    if state
        .waiters
        .get(name)
        .is_some_and(|waiters| !waiters.is_empty())
    {
        return Err(CriticalSectionError::Queued {
            name: name.to_owned(),
        });
    }
    if state.held.len() >= max_held {
        return Err(CriticalSectionError::Capacity { limit: max_held });
    }
    state.held.insert(
        name.to_owned(),
        HeldLock {
            owner: lifecycle_id,
            generation: state.generation,
        },
    );
    Ok(())
}

fn release_locked(
    state: &mut CriticalState,
    name: &str,
    lifecycle_id: u64,
) -> Result<(), CriticalSectionError> {
    match state.held.get(name).copied() {
        Some(held) if held.owner == lifecycle_id && held.generation == state.generation => {
            if state.waiter_count != 0 {
                bump_wait_generation(state)?;
            }
            state.held.remove(name);
            Ok(())
        }
        Some(held) => Err(CriticalSectionError::NotOwner {
            name: name.to_owned(),
            owner: held.owner,
        }),
        None => Err(CriticalSectionError::NotOwner {
            name: name.to_owned(),
            owner: lifecycle_id,
        }),
    }
}

#[allow(clippy::too_many_arguments, reason = "one bounded state transition")]
fn poll_acquire_locked(
    state: &mut CriticalState,
    name: &str,
    lifecycle_id: u64,
    generation: CoordinationGeneration,
    waker: &Waker,
    max_held: usize,
    max_waiters: usize,
) -> Poll<Result<(), CriticalSectionError>> {
    if let Some(held) = state.held.get(name)
        && held.owner == lifecycle_id
        && held.generation == generation
    {
        return Poll::Ready(Err(CriticalSectionError::Busy {
            name: name.to_owned(),
            owner: held.owner,
        }));
    }

    let admitted = if !state.held.contains_key(name) {
        let admitted = state.waiters.get(name).is_some_and(|queue| {
            queue.front().is_some_and(|waiter| {
                waiter.owner == lifecycle_id && waiter.generation == generation
            })
        });
        if admitted {
            // A release normally leaves one held-lock slot available, but a
            // concurrent acquisition on another name may have filled the
            // global held-lock bound before this waiter was polled. Keep the
            // waiter queued until capacity is available; the wait-generation
            // seam lets the executor retry after that other release.
            if state.held.len() >= max_held {
                if let Some(waiter) = state.waiters.get_mut(name).and_then(|queue| {
                    queue.iter_mut().find(|waiter| {
                        waiter.owner == lifecycle_id && waiter.generation == generation
                    })
                }) {
                    waiter.waker = waker.clone();
                }
                return Poll::Pending;
            }
            if let Err(error) = bump_wait_generation(state) {
                return Poll::Ready(Err(error));
            }
            let Some(waiter_count) = state.waiter_count.checked_sub(1) else {
                return Poll::Ready(Err(CriticalSectionError::AccountingInvariant));
            };
            let queue = state
                .waiters
                .get_mut(name)
                .ok_or(CriticalSectionError::AccountingInvariant);
            match queue {
                Ok(queue) => {
                    queue.pop_front();
                    if queue.is_empty() {
                        state.waiters.remove(name);
                    }
                }
                Err(error) => return Poll::Ready(Err(error)),
            }
            state.waiter_count = waiter_count;
        }
        admitted
    } else {
        false
    };
    if admitted {
        state.held.insert(
            name.to_owned(),
            HeldLock {
                owner: lifecycle_id,
                generation,
            },
        );
        return Poll::Ready(Ok(()));
    }
    if let Some(waiter) = state.waiters.get_mut(name).and_then(|queue| {
        queue
            .iter_mut()
            .find(|waiter| waiter.owner == lifecycle_id && waiter.generation == generation)
    }) {
        waiter.waker = waker.clone();
        return Poll::Pending;
    }

    let held = state.held.contains_key(name);
    let queued = state
        .waiters
        .get(name)
        .is_some_and(|queue| !queue.is_empty());
    if held || queued {
        if state.waiter_count >= max_waiters {
            return Poll::Ready(Err(CriticalSectionError::WaiterCapacity {
                limit: max_waiters,
            }));
        }
        let Some(waiter_count) = state.waiter_count.checked_add(1) else {
            return Poll::Ready(Err(CriticalSectionError::AccountingInvariant));
        };
        if let Err(error) = bump_wait_generation(state) {
            return Poll::Ready(Err(error));
        }
        state
            .waiters
            .entry(name.to_owned())
            .or_default()
            .push_back(CriticalWaiter {
                owner: lifecycle_id,
                generation,
                waker: waker.clone(),
            });
        state.waiter_count = waiter_count;
        return Poll::Pending;
    }

    if state.held.len() >= max_held {
        return Poll::Ready(Err(CriticalSectionError::Capacity { limit: max_held }));
    }
    state.held.insert(
        name.to_owned(),
        HeldLock {
            owner: lifecycle_id,
            generation,
        },
    );
    Poll::Ready(Ok(()))
}

fn next_waiter_waker(state: &CriticalState, name: &str) -> Option<Waker> {
    state
        .waiters
        .get(name)
        .and_then(|waiters| waiters.front())
        .map(|waiter| waiter.waker.clone())
}

fn available_waiter_wakers(state: &CriticalState, max_held: usize) -> Vec<Waker> {
    let Some(available) = max_held.checked_sub(state.held.len()) else {
        return Vec::new();
    };
    state
        .waiters
        .iter()
        .filter(|(name, waiters)| !waiters.is_empty() && !state.held.contains_key(*name))
        .filter_map(|(_, waiters)| waiters.front().map(|waiter| waiter.waker.clone()))
        .take(available)
        .collect()
}

fn cancel_waiter_locked(
    state: &mut CriticalState,
    name: &str,
    lifecycle_id: u64,
    generation: CoordinationGeneration,
) -> Result<bool, CriticalSectionError> {
    let Some(waiters) = state.waiters.get(name) else {
        return Ok(false);
    };
    let Some(index) = waiters
        .iter()
        .position(|waiter| waiter.owner == lifecycle_id && waiter.generation == generation)
    else {
        return Ok(false);
    };
    bump_wait_generation(state)?;
    let waiters = state
        .waiters
        .get_mut(name)
        .ok_or(CriticalSectionError::AccountingInvariant)?;
    waiters.remove(index);
    let empty = waiters.is_empty();
    state.waiter_count = state
        .waiter_count
        .checked_sub(1)
        .ok_or(CriticalSectionError::AccountingInvariant)?;
    if empty {
        state.waiters.remove(name);
    }
    Ok(true)
}

/// The scope used by a deterministic shared-throughput coordinator.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ThroughputScope {
    /// All users in the run.
    Global,
    /// Users in one non-empty thread group.
    Group(String),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ThroughputParticipant {
    scope: ThroughputScope,
    mode: &'static str,
    group: Option<String>,
    name: String,
    number: Option<u64>,
    lifecycle_id: Option<u64>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ThroughputIdentity {
    group: Option<String>,
    name: String,
    number: Option<u64>,
    lifecycle_id: Option<u64>,
}

impl ThroughputParticipant {
    fn identity(&self) -> ThroughputIdentity {
        ThroughputIdentity {
            group: self.group.clone(),
            name: self.name.clone(),
            number: self.number,
            lifecycle_id: self.lifecycle_id,
        }
    }
}

#[derive(Debug)]
struct ThroughputState {
    generation: CoordinationGeneration,
    next_shared: BTreeMap<ThroughputScope, Duration>,
    next_per_user: BTreeMap<ThroughputParticipant, Duration>,
    active_modes: BTreeSet<ThroughputParticipant>,
}

impl Default for ThroughputState {
    fn default() -> Self {
        Self {
            generation: CoordinationGeneration::initial(),
            next_shared: BTreeMap::new(),
            next_per_user: BTreeMap::new(),
            active_modes: BTreeSet::new(),
        }
    }
}

/// Bounded deterministic implementation of JMeter's run-shared constant
/// throughput modes.
///
/// Shared modes reserve one monotonic cursor per run or thread group.  The
/// non-shared active-thread modes reserve one cursor per participant and scale
/// each participant's period by the number of observed active participants.
/// Every mode records a bounded participant token so active-thread accounting
/// includes users whose own timer uses a shared cursor; physical identities
/// are deduplicated when calculating the active count. A reservation is a
/// pure arithmetic result; sleeping remains the injected execution pipeline's
/// responsibility.
#[derive(Debug)]
pub struct DeterministicThroughputCoordinator {
    state: Mutex<ThroughputState>,
    max_participants: usize,
    max_scopes: usize,
}

impl Default for DeterministicThroughputCoordinator {
    fn default() -> Self {
        Self::with_limits(MAX_THROUGHPUT_PARTICIPANTS, MAX_THROUGHPUT_SCOPES)
    }
}

impl DeterministicThroughputCoordinator {
    /// Creates a coordinator with finite participant and scope bounds.
    #[must_use]
    pub fn with_limits(max_participants: usize, max_scopes: usize) -> Self {
        Self {
            state: Mutex::new(ThroughputState::default()),
            max_participants: max_participants.min(MAX_THROUGHPUT_PARTICIPANTS),
            max_scopes: max_scopes.min(MAX_THROUGHPUT_SCOPES),
        }
    }

    /// Creates a coordinator with default safety bounds.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the current generation.
    #[must_use]
    pub fn generation(&self) -> CoordinationGeneration {
        lock(&self.state).generation
    }

    /// Starts a fresh run generation.  Existing reservations are discarded
    /// only through this explicit operation; stale callers can use
    /// [`Self::reserve_generation`] to receive a typed mismatch.
    pub fn advance_generation(&self) -> Result<CoordinationGeneration, ComponentError> {
        let mut state = lock(&self.state);
        let generation = state
            .generation
            .next()
            .ok_or_else(|| ComponentError::resource_limit("throughput generation"))?;
        state.generation = generation;
        state.next_shared.clear();
        state.next_per_user.clear();
        state.active_modes.clear();
        Ok(generation)
    }

    /// Reserves a delay using an explicit coordinator generation.
    pub fn reserve_generation(
        &self,
        request: &ThroughputRequest,
        generation: CoordinationGeneration,
    ) -> Result<Duration, ComponentError> {
        let mut state = lock(&self.state);
        if state.generation != generation {
            return Err(ComponentError::failure(format!(
                "throughput stale generation: expected {}, got {}",
                state.generation.get(),
                generation.get()
            )));
        }
        reserve_locked(&mut state, request, self.max_participants, self.max_scopes)
    }

    /// Cancels a participant's per-user reservation state.  Shared cursors
    /// are intentionally not rewound: doing so would duplicate a reservation
    /// already observed by another user.
    pub fn cancel(&self, request: &ThroughputRequest) -> Result<bool, ComponentError> {
        self.cancel_generation(request, self.generation())
    }

    /// Cancels one participant using an explicit generation.  Shared cursors
    /// are never rewound: another participant may already have observed the
    /// reservation.  A stale cancellation cannot remove a fresh participant
    /// that happens to reuse the same identity.
    pub fn cancel_generation(
        &self,
        request: &ThroughputRequest,
        generation: CoordinationGeneration,
    ) -> Result<bool, ComponentError> {
        let mut state = lock(&self.state);
        if state.generation != generation {
            return Err(ComponentError::failure(format!(
                "throughput stale generation: expected {}, got {}",
                state.generation.get(),
                generation.get()
            )));
        }
        let (_scope, participant) = throughput_identity(request)?;
        let removed_per_user = state.next_per_user.remove(&participant).is_some();
        let removed_mode = state.active_modes.remove(&participant);
        let removed = removed_per_user || removed_mode;
        Ok(removed)
    }
}

impl ThroughputCoordinator for DeterministicThroughputCoordinator {
    fn reserve(&self, request: &ThroughputRequest) -> Result<Duration, ComponentError> {
        self.reserve_generation(request, self.generation())
    }
}

impl CoordinationWaitSource for DeterministicThroughputCoordinator {
    fn wait_snapshot(&self) -> CoordinationWaitSnapshot {
        CoordinationWaitSnapshot {
            generation: self.generation(),
            pending: 0,
            earliest_deadline: None,
        }
    }
}

fn reserve_locked(
    state: &mut ThroughputState,
    request: &ThroughputRequest,
    max_participants: usize,
    max_scopes: usize,
) -> Result<Duration, ComponentError> {
    validate_throughput_request(request)?;
    if request.period().is_zero() {
        return Err(invalid_component("throughput period must be positive"));
    }
    if request.thread_name().is_empty()
        || request.thread_name().len() > MAX_THROUGHPUT_PARTICIPANT_BYTES
        || request
            .thread_group()
            .is_some_and(|group| group.is_empty() || group.len() > MAX_THROUGHPUT_PARTICIPANT_BYTES)
    {
        return Err(invalid_component("throughput participant identity"));
    }

    let mode = request.mode();
    let jmeter_period = match mode {
        crate::ConstantThroughputMode::ThisThreadOnly
        | crate::ConstantThroughputMode::AllActiveThreads
        | crate::ConstantThroughputMode::AllActiveThreadsInCurrentThreadGroup => request.period(),
        crate::ConstantThroughputMode::AllActiveThreadsShared
        | crate::ConstantThroughputMode::AllActiveThreadsInCurrentThreadGroupShared => {
            jmeter_rounded_period(request.period())?
        }
    };
    let group = request.thread_group().map(str::to_owned);
    let scope = match mode {
        crate::ConstantThroughputMode::AllActiveThreadsInCurrentThreadGroup
        | crate::ConstantThroughputMode::AllActiveThreadsInCurrentThreadGroupShared => {
            let Some(group) = group.as_ref() else {
                return Err(ComponentError::unsupported(
                    "thread-group throughput mode requires a thread-group identity",
                ));
            };
            ThroughputScope::Group(group.clone())
        }
        crate::ConstantThroughputMode::AllActiveThreads
        | crate::ConstantThroughputMode::AllActiveThreadsShared
        | crate::ConstantThroughputMode::ThisThreadOnly => ThroughputScope::Global,
    };

    let participant = ThroughputParticipant {
        scope: scope.clone(),
        mode: mode.jmeter_name(),
        group: group.clone(),
        name: request.thread_name().to_owned(),
        number: request.thread_number(),
        lifecycle_id: request.lifecycle_id(),
    };
    let is_new_mode = !state.active_modes.contains(&participant);
    if is_new_mode && state.active_modes.len() >= max_participants {
        return Err(ComponentError::resource_limit(
            "throughput participant capacity",
        ));
    }

    let shared = matches!(
        mode,
        crate::ConstantThroughputMode::AllActiveThreadsShared
            | crate::ConstantThroughputMode::AllActiveThreadsInCurrentThreadGroupShared
    );
    if shared {
        if !state.next_shared.contains_key(&scope) && state.next_shared.len() >= max_scopes {
            return Err(ComponentError::resource_limit("throughput scope capacity"));
        }
        let previous = state
            .next_shared
            .get(&scope)
            .copied()
            .unwrap_or(request.now());
        let delay = previous
            .checked_sub(request.now())
            .unwrap_or(Duration::ZERO);
        let base = previous.max(request.now());
        let target = base
            .checked_add(jmeter_period)
            .ok_or_else(|| ComponentError::resource_limit("throughput target time"))?;
        if is_new_mode {
            state.active_modes.insert(participant);
        }
        state.next_shared.insert(scope, target);
        return Ok(delay);
    }

    let is_new = !state.next_per_user.contains_key(&participant);
    if is_new && state.next_per_user.len() >= max_participants {
        return Err(ComponentError::resource_limit(
            "throughput participant capacity",
        ));
    }

    if mode == crate::ConstantThroughputMode::ThisThreadOnly {
        let previous = state
            .next_per_user
            .get(&participant)
            .copied()
            .unwrap_or(request.now());
        let delay = previous
            .checked_sub(request.now())
            .unwrap_or(Duration::ZERO);
        let base = previous.max(request.now());
        let target = base
            .checked_add(jmeter_period)
            .ok_or_else(|| ComponentError::resource_limit("throughput target time"))?;
        state.next_per_user.insert(participant.clone(), target);
        if is_new_mode {
            state.active_modes.insert(participant);
        }
        return Ok(delay);
    }

    let mut active_users = BTreeSet::new();
    for existing in state.active_modes.iter().filter(|existing| match mode {
        crate::ConstantThroughputMode::AllActiveThreads => true,
        crate::ConstantThroughputMode::AllActiveThreadsInCurrentThreadGroup => {
            existing.group.as_deref() == group.as_deref()
        }
        _ => false,
    }) {
        active_users.insert(existing.identity());
    }
    active_users.insert(participant.identity());
    let active = active_users.len();
    let active = u32::try_from(active)
        .map_err(|_| ComponentError::resource_limit("throughput active participant count"))?;
    let scaled_period = jmeter_scaled_period(request.period(), active)?;
    let previous = state
        .next_per_user
        .get(&participant)
        .copied()
        .unwrap_or(request.now());
    let delay = previous
        .checked_sub(request.now())
        .unwrap_or(Duration::ZERO);
    let base = previous.max(request.now());
    let target = base
        .checked_add(scaled_period)
        .ok_or_else(|| ComponentError::resource_limit("throughput target time"))?;
    state.next_per_user.insert(participant.clone(), target);
    if is_new_mode {
        state.active_modes.insert(participant);
    }
    Ok(delay)
}

fn throughput_identity(
    request: &ThroughputRequest,
) -> Result<(ThroughputScope, ThroughputParticipant), ComponentError> {
    validate_throughput_request(request)?;
    let group = request.thread_group().map(str::to_owned);
    let scope = match request.mode() {
        crate::ConstantThroughputMode::AllActiveThreadsInCurrentThreadGroup
        | crate::ConstantThroughputMode::AllActiveThreadsInCurrentThreadGroupShared => {
            let Some(group) = group.as_ref() else {
                return Err(ComponentError::unsupported(
                    "thread-group throughput mode requires a thread-group identity",
                ));
            };
            ThroughputScope::Group(group.clone())
        }
        _ => ThroughputScope::Global,
    };
    Ok((
        scope.clone(),
        ThroughputParticipant {
            scope,
            mode: request.mode().jmeter_name(),
            group,
            name: request.thread_name().to_owned(),
            number: request.thread_number(),
            lifecycle_id: request.lifecycle_id(),
        },
    ))
}

fn validate_throughput_request(request: &ThroughputRequest) -> Result<(), ComponentError> {
    if request.thread_name().is_empty()
        || request.thread_name().len() > MAX_THROUGHPUT_PARTICIPANT_BYTES
        || request
            .thread_group()
            .is_some_and(|group| group.is_empty() || group.len() > MAX_THROUGHPUT_PARTICIPANT_BYTES)
        || request.thread_number().is_some_and(|number| number == 0)
        || request
            .lifecycle_id()
            .is_some_and(|lifecycle_id| lifecycle_id == 0)
    {
        return Err(invalid_component("throughput participant identity"));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct BarrierKey {
    name: String,
    group: Option<String>,
}

#[derive(Debug)]
struct BarrierSlot {
    generation: CoordinationGeneration,
    expected: usize,
    deadline: Option<Duration>,
    arrivals: BTreeMap<String, Waker>,
    /// Participants canceled before this generation closed. Keeping the
    /// tombstone until the slot drains prevents a stale arrival from
    /// rejoining the already-broken generation under the same identity.
    retired: BTreeSet<String>,
    outcome: Option<SynchronizingOutcome>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BarrierLease {
    generation: CoordinationGeneration,
}

#[derive(Debug)]
struct BarrierState {
    slots: BTreeMap<BarrierKey, BarrierSlot>,
    next_generation: BTreeMap<BarrierKey, CoordinationGeneration>,
    generation_overflow: BTreeSet<BarrierKey>,
    configured_group_sizes: BTreeMap<String, NonZeroUsize>,
    leases: BTreeMap<(BarrierKey, String), BarrierLease>,
    participant_count: usize,
    wait_generation: CoordinationGeneration,
    wait_generation_overflow: bool,
}

impl Default for BarrierState {
    fn default() -> Self {
        Self {
            slots: BTreeMap::new(),
            next_generation: BTreeMap::new(),
            generation_overflow: BTreeSet::new(),
            configured_group_sizes: BTreeMap::new(),
            leases: BTreeMap::new(),
            participant_count: 0,
            wait_generation: CoordinationGeneration::initial(),
            wait_generation_overflow: false,
        }
    }
}

/// Bounded deterministic implementation of the synchronizing timer barrier.
///
/// Explicit group sizes are keyed by timer name.  `groupSize=0` requests are
/// keyed by `(name, thread-group)` and require the caller to register the
/// current thread-group size before admission.  Each participant appears at
/// most once per generation; release and timeout wake all waiters in sorted
/// participant order, and completion/cancellation retires their reservation.
#[derive(Debug)]
pub struct DeterministicSynchronizingCoordinator {
    state: Mutex<BarrierState>,
    max_slots: usize,
    max_participants: usize,
}

impl Default for DeterministicSynchronizingCoordinator {
    fn default() -> Self {
        Self::with_limits(MAX_BARRIER_SLOTS, MAX_BARRIER_PARTICIPANTS)
    }
}

impl DeterministicSynchronizingCoordinator {
    /// Creates a coordinator with finite barrier-slot and participant bounds.
    #[must_use]
    pub fn with_limits(max_slots: usize, max_participants: usize) -> Self {
        Self {
            state: Mutex::new(BarrierState::default()),
            max_slots: max_slots.min(MAX_BARRIER_SLOTS),
            max_participants: max_participants.min(MAX_BARRIER_PARTICIPANTS),
        }
    }

    /// Creates a coordinator with default safety bounds.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers the participant count for a `groupSize=0` thread group.
    pub fn register_thread_group(
        &self,
        group: impl Into<String>,
        size: NonZeroUsize,
    ) -> Result<(), ComponentError> {
        let group = group.into();
        if group.is_empty() || group.len() > MAX_BARRIER_GROUP_BYTES {
            return Err(invalid_component("synchronizing thread-group identity"));
        }
        if size.get() > self.max_participants {
            return Err(ComponentError::resource_limit(
                "synchronizing participant capacity",
            ));
        }
        let mut state = lock(&self.state);
        if !state.configured_group_sizes.contains_key(&group)
            && state.configured_group_sizes.len() >= self.max_slots
        {
            return Err(ComponentError::resource_limit(
                "synchronizing thread-group capacity",
            ));
        }
        state.configured_group_sizes.insert(group, size);
        Ok(())
    }

    /// Removes a previously registered current-thread-group count.
    pub fn unregister_thread_group(&self, group: &str) -> bool {
        lock(&self.state)
            .configured_group_sizes
            .remove(group)
            .is_some()
    }

    /// Returns the generation currently active for a barrier key, or the next
    /// generation that will be assigned when it first admits a participant.
    pub fn generation(&self, name: &str, group: Option<&str>) -> Option<CoordinationGeneration> {
        let state = lock(&self.state);
        let key = BarrierKey {
            name: name.to_owned(),
            group: group.map(str::to_owned),
        };
        state
            .slots
            .get(&key)
            .map(|slot| slot.generation)
            .or_else(|| state.next_generation.get(&key).copied())
    }

    fn key_for(request: &SynchronizingRequest) -> Result<BarrierKey, ComponentError> {
        if request.name().is_empty() || request.name().len() > MAX_BARRIER_NAME_BYTES {
            return Err(invalid_component("invalid synchronizing barrier name"));
        }
        if request.participant().is_empty()
            || request.participant().len() > MAX_BARRIER_PARTICIPANT_BYTES
            || request.thread_number().is_some_and(|number| number == 0)
            || request
                .lifecycle_id()
                .is_some_and(|lifecycle_id| lifecycle_id == 0)
        {
            return Err(invalid_component(
                "invalid synchronizing participant identity",
            ));
        }
        let group = if request.uses_current_thread_group() {
            let Some(group) = request.thread_group() else {
                return Err(ComponentError::unsupported(
                    "current-thread-group barrier requires a thread-group identity",
                ));
            };
            if group.is_empty() || group.len() > MAX_BARRIER_GROUP_BYTES {
                return Err(invalid_component(
                    "invalid synchronizing thread-group identity",
                ));
            }
            Some(group.to_owned())
        } else {
            None
        };
        Ok(BarrierKey {
            name: request.name().to_owned(),
            group,
        })
    }

    fn expected_size(
        state: &BarrierState,
        request: &SynchronizingRequest,
    ) -> Result<usize, ComponentError> {
        let size = request.group_size().map_or_else(
            || {
                request
                    .thread_group()
                    .and_then(|group| state.configured_group_sizes.get(group))
                    .map(|size| size.get())
                    .ok_or_else(|| {
                        ComponentError::unsupported(
                            "current-thread-group barrier requires a registered participant count",
                        )
                    })
            },
            |size| Ok(size.get()),
        )?;
        if size == 0 || size > MAX_BARRIER_PARTICIPANTS {
            return Err(ComponentError::resource_limit(
                "synchronizing participant capacity",
            ));
        }
        Ok(size)
    }

    /// Returns the bounded wait state consumed by an executor edge.
    #[must_use]
    pub fn wait_snapshot(&self) -> CoordinationWaitSnapshot {
        let state = lock(&self.state);
        let earliest_deadline = state
            .slots
            .values()
            .filter(|slot| slot.outcome.is_none())
            .filter_map(|slot| slot.deadline)
            .min();
        let pending = state
            .slots
            .values()
            .filter(|slot| slot.outcome.is_none())
            .map(|slot| slot.arrivals.len())
            .sum();
        CoordinationWaitSnapshot {
            generation: state.wait_generation,
            pending,
            earliest_deadline,
        }
    }
}

fn bump_barrier_wait_generation(state: &mut BarrierState) -> Result<(), ComponentError> {
    if bump_generation(&mut state.wait_generation) {
        Ok(())
    } else {
        state.wait_generation_overflow = true;
        Err(ComponentError::resource_limit(
            "synchronizing barrier wait generation",
        ))
    }
}

fn advance_barrier_generation(
    state: &mut BarrierState,
    key: &BarrierKey,
) -> Result<(), ComponentError> {
    let Some(current) = state.next_generation.get(key).copied() else {
        return Err(ComponentError::failure(
            "synchronizing barrier generation accounting invariant",
        ));
    };
    let Some(generation) = current.next() else {
        state.generation_overflow.insert(key.clone());
        return Err(ComponentError::resource_limit(
            "synchronizing barrier generation",
        ));
    };
    state.next_generation.insert(key.clone(), generation);
    Ok(())
}

impl SynchronizingCoordinator for DeterministicSynchronizingCoordinator {
    fn poll_arrival(
        &self,
        request: &SynchronizingRequest,
        waker: &Waker,
    ) -> Poll<Result<SynchronizingOutcome, ComponentError>> {
        let key = match Self::key_for(request) {
            Ok(key) => key,
            Err(error) => return Poll::Ready(Err(error)),
        };
        let mut wake = Vec::new();
        let result = {
            let mut state = lock(&self.state);
            if state.wait_generation_overflow {
                return Poll::Ready(Err(ComponentError::resource_limit(
                    "synchronizing barrier wait generation",
                )));
            }
            let expected = match Self::expected_size(&state, request) {
                Ok(expected) => expected,
                Err(error) => return Poll::Ready(Err(error)),
            };
            if expected > self.max_participants {
                return Poll::Ready(Err(ComponentError::resource_limit(
                    "synchronizing participant capacity",
                )));
            }
            if !state.slots.contains_key(&key)
                && (state.slots.len() >= self.max_slots
                    || (!state.next_generation.contains_key(&key)
                        && state.next_generation.len() >= self.max_slots))
            {
                return Poll::Ready(Err(ComponentError::resource_limit(
                    "synchronizing barrier capacity",
                )));
            }
            if state.generation_overflow.contains(&key) {
                return Poll::Ready(Err(ComponentError::resource_limit(
                    "synchronizing barrier generation",
                )));
            }
            let generation = *state
                .next_generation
                .entry(key.clone())
                .or_insert(CoordinationGeneration::initial());
            let requested_deadline = if request.timeout().is_zero() {
                None
            } else {
                Some(
                    request
                        .now()
                        .checked_add(request.timeout())
                        .ok_or_else(|| {
                            ComponentError::resource_limit("synchronizing barrier deadline")
                        })?,
                )
            };
            if state
                .slots
                .get(&key)
                .is_some_and(|slot| slot.expected != expected)
            {
                return Poll::Ready(Err(ComponentError::failure(
                    "synchronizing barrier participant count changed within a generation",
                )));
            }
            let participant = request.participant().to_owned();
            let lease_key = (key.clone(), participant.clone());
            if let Some(lease) = state.leases.get(&lease_key)
                && lease.generation != generation
            {
                return Poll::Ready(Err(ComponentError::failure(
                    "synchronizing participant reused before its prior arrival completed",
                )));
            }
            let has_lease = state.leases.contains_key(&lease_key);
            if !has_lease && state.participant_count >= self.max_participants {
                return Poll::Ready(Err(ComponentError::resource_limit(
                    "synchronizing participant capacity",
                )));
            }
            let slot_exists = state.slots.contains_key(&key);
            let expired = state
                .slots
                .get(&key)
                .and_then(|slot| slot.deadline)
                .is_some_and(|deadline| request.now() >= deadline);

            // A participant that polls again owns the same lease.  Retire it
            // exactly once when the deadline is observed; inserting the lease
            // again would double-count the bounded participant accounting.
            if has_lease {
                if expired
                    && state
                        .slots
                        .get(&key)
                        .is_some_and(|slot| slot.outcome.is_none())
                {
                    bump_barrier_wait_generation(&mut state)?;
                    let slot = state.slots.get_mut(&key).ok_or_else(|| {
                        ComponentError::failure("synchronizing barrier slot missing")
                    })?;
                    slot.outcome = Some(SynchronizingOutcome::TimedOut);
                    wake.extend(slot.arrivals.values().cloned());
                    drop(state);
                    for waker in wake {
                        waker.wake();
                    }
                    return Poll::Ready(Ok(SynchronizingOutcome::TimedOut));
                }
                if let Some(outcome) = state.slots.get(&key).and_then(|slot| slot.outcome) {
                    return Poll::Ready(Ok(outcome));
                }
                let slot = state
                    .slots
                    .get_mut(&key)
                    .ok_or_else(|| ComponentError::failure("synchronizing barrier slot missing"))?;
                let existing = slot.arrivals.get_mut(&participant).ok_or_else(|| {
                    ComponentError::failure("synchronizing participant lease accounting invariant")
                })?;
                *existing = waker.clone();
                return Poll::Pending;
            }

            let slot_outcome = state.slots.get(&key).and_then(|slot| slot.outcome);
            if let Some(outcome) = slot_outcome {
                if outcome != SynchronizingOutcome::TimedOut {
                    return Poll::Ready(Err(ComponentError::failure(
                        "synchronizing barrier generation is closed",
                    )));
                }
                if state
                    .slots
                    .get(&key)
                    .is_some_and(|slot| slot.retired.contains(&participant))
                {
                    return Poll::Ready(Err(ComponentError::failure(
                        "synchronizing participant was canceled for the current generation",
                    )));
                }
                let slot = state
                    .slots
                    .get_mut(&key)
                    .ok_or_else(|| ComponentError::failure("synchronizing barrier slot missing"))?;
                if slot.retired.len() >= self.max_participants {
                    return Poll::Ready(Err(ComponentError::resource_limit(
                        "synchronizing participant capacity",
                    )));
                }
                bump_barrier_wait_generation(&mut state)?;
                let slot = state
                    .slots
                    .get_mut(&key)
                    .ok_or_else(|| ComponentError::failure("synchronizing barrier slot missing"))?;
                slot.retired.insert(participant);
                return Poll::Ready(Ok(outcome));
            }

            if expired {
                bump_barrier_wait_generation(&mut state)?;
                state.leases.insert(lease_key, BarrierLease { generation });
                state.participant_count =
                    state.participant_count.checked_add(1).ok_or_else(|| {
                        ComponentError::failure(
                            "synchronizing barrier participant accounting invariant",
                        )
                    })?;
                let slot = state
                    .slots
                    .get_mut(&key)
                    .ok_or_else(|| ComponentError::failure("synchronizing barrier slot missing"))?;
                slot.outcome = Some(SynchronizingOutcome::TimedOut);
                wake.extend(slot.arrivals.values().cloned());
                drop(state);
                for waker in wake {
                    waker.wake();
                }
                return Poll::Ready(Ok(SynchronizingOutcome::TimedOut));
            }

            bump_barrier_wait_generation(&mut state)?;
            if !slot_exists {
                state.slots.insert(
                    key.clone(),
                    BarrierSlot {
                        generation,
                        expected,
                        deadline: requested_deadline,
                        arrivals: BTreeMap::new(),
                        retired: BTreeSet::new(),
                        outcome: None,
                    },
                );
            }
            state.leases.insert(lease_key, BarrierLease { generation });
            state.participant_count = state.participant_count.checked_add(1).ok_or_else(|| {
                ComponentError::failure("synchronizing barrier participant accounting invariant")
            })?;
            let slot = state
                .slots
                .get_mut(&key)
                .ok_or_else(|| ComponentError::failure("synchronizing barrier slot missing"))?;
            slot.arrivals.insert(participant, waker.clone());
            if slot.arrivals.len() >= slot.expected {
                slot.outcome = Some(SynchronizingOutcome::Released);
                wake.extend(slot.arrivals.values().cloned());
                Poll::Ready(Ok(SynchronizingOutcome::Released))
            } else {
                Poll::Pending
            }
        };
        for waker in wake {
            waker.wake();
        }
        result
    }

    fn cancel(&self, request: &SynchronizingRequest) {
        let Ok(key) = Self::key_for(request) else {
            return;
        };
        let mut state = lock(&self.state);
        let mut wake = Vec::new();
        let lease_key = (key.clone(), request.participant().to_owned());
        let Some(lease) = state.leases.remove(&lease_key) else {
            return;
        };
        let removed = state
            .slots
            .get_mut(&key)
            .and_then(|slot| {
                (slot.generation == lease.generation)
                    .then(|| slot.arrivals.remove(request.participant()))
                    .flatten()
            })
            .is_some();
        if let Some(count) = state.participant_count.checked_sub(1) {
            state.participant_count = count;
        } else {
            state.wait_generation_overflow = true;
        }
        if removed && let Some(slot) = state.slots.get_mut(&key) {
            slot.retired.insert(request.participant().to_owned());
        }
        if removed
            && state
                .slots
                .get(&key)
                .is_some_and(|slot| slot.outcome.is_none())
        {
            state.wait_generation_overflow |= bump_barrier_wait_generation(&mut state).is_err();
            if let Some(slot) = state.slots.get_mut(&key) {
                slot.outcome = Some(SynchronizingOutcome::TimedOut);
                wake.extend(slot.arrivals.values().cloned());
            }
        }
        let remove_slot = state.slots.get(&key).is_some_and(|slot| {
            slot.arrivals.is_empty() && !state.leases.keys().any(|(lease_key, _)| lease_key == &key)
        });
        if remove_slot {
            state.slots.remove(&key);
            if advance_barrier_generation(&mut state, &key).is_err() {
                state.generation_overflow.insert(key.clone());
            }
        }
        drop(state);
        for waker in wake {
            waker.wake();
        }
    }

    fn complete(&self, request: &SynchronizingRequest, outcome: SynchronizingOutcome) {
        let Ok(key) = Self::key_for(request) else {
            return;
        };
        let mut state = lock(&self.state);
        let lease_key = (key.clone(), request.participant().to_owned());
        let Some(lease) = state.leases.remove(&lease_key) else {
            return;
        };
        state.wait_generation_overflow |= bump_barrier_wait_generation(&mut state).is_err();
        if let Some(count) = state.participant_count.checked_sub(1) {
            state.participant_count = count;
        } else {
            state.wait_generation_overflow = true;
        }
        if let Some(slot) = state.slots.get_mut(&key)
            && slot.generation == lease.generation
        {
            if slot.outcome.is_none() {
                slot.outcome = Some(outcome);
            }
            slot.arrivals.remove(request.participant());
            if slot.outcome == Some(SynchronizingOutcome::TimedOut) {
                slot.retired.insert(request.participant().to_owned());
            }
        }
        let remove_slot = state.slots.get(&key).is_some_and(|slot| {
            slot.arrivals.is_empty() && !state.leases.keys().any(|(lease_key, _)| lease_key == &key)
        });
        if remove_slot {
            state.slots.remove(&key);
            if advance_barrier_generation(&mut state, &key).is_err() {
                state.generation_overflow.insert(key);
            }
        }
    }
}

impl CoordinationWaitSource for DeterministicSynchronizingCoordinator {
    fn wait_snapshot(&self) -> CoordinationWaitSnapshot {
        DeterministicSynchronizingCoordinator::wait_snapshot(self)
    }
}

/// Descriptive alias for [`DeterministicSynchronizingCoordinator`].
pub type DeterministicBarrierCoordinator = DeterministicSynchronizingCoordinator;

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "deterministic coordinator setup and state-machine assertions"
)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;

    struct CountingWake(Arc<AtomicUsize>);

    impl Wake for CountingWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn poll_waker() -> Waker {
        Waker::noop().clone()
    }

    fn counting_waker(counter: &Arc<AtomicUsize>) -> Waker {
        Waker::from(Arc::new(CountingWake(Arc::clone(counter))))
    }

    #[test]
    fn coordinator_has_owner_and_capacity_semantics() {
        let coordinator = DeterministicCriticalSectionCoordinator::new(1);
        coordinator.try_acquire("gate", 1).expect("first owner");
        assert!(matches!(
            coordinator.try_acquire("gate", 2),
            Err(CriticalSectionError::Busy { owner: 1, .. })
        ));
        assert!(matches!(
            coordinator.try_acquire("other", 2),
            Err(CriticalSectionError::Capacity { limit: 1 })
        ));
        assert!(matches!(
            coordinator.release("gate", 2),
            Err(CriticalSectionError::NotOwner { .. })
        ));
        coordinator.release("gate", 1).expect("owner release");
    }

    #[test]
    fn critical_section_waiters_are_fifo_and_cancellation_releases_capacity() {
        let coordinator = DeterministicCriticalSectionCoordinator::with_limits(1, 2);
        let first = poll_waker();
        let second = poll_waker();
        coordinator.try_acquire("gate", 1).expect("first owner");
        assert!(matches!(
            coordinator.poll_acquire("gate", 2, &first),
            Poll::Pending
        ));
        assert!(matches!(
            coordinator.poll_acquire("gate", 3, &second),
            Poll::Pending
        ));
        assert!(coordinator.cancel_acquire("gate", 2).expect("cancel"));
        coordinator.release("gate", 1).expect("release");
        assert!(matches!(
            coordinator.poll_acquire("gate", 3, &second),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            coordinator.poll_acquire("gate", 4, &first),
            Poll::Pending
        ));
    }

    #[test]
    fn critical_section_generation_rejects_stale_release() {
        let coordinator = DeterministicCriticalSectionCoordinator::new(1);
        let first = coordinator.generation();
        coordinator
            .try_acquire_generation("gate", 1, first)
            .expect("acquire");
        assert!(matches!(
            coordinator.advance_generation(),
            Err(CriticalSectionError::Busy { .. })
        ));
        coordinator
            .release_generation("gate", 1, first)
            .expect("release");
        let second = coordinator.advance_generation().expect("next generation");
        assert_ne!(first, second);
        assert!(matches!(
            coordinator.release_generation("gate", 1, first),
            Err(CriticalSectionError::StaleGeneration { .. })
        ));
    }

    #[test]
    fn critical_section_rejects_zero_id_and_wakes_only_next_fifo_waiter() {
        let coordinator = DeterministicCriticalSectionCoordinator::with_limits(1, 2);
        assert_eq!(
            coordinator
                .try_acquire("gate", 0)
                .expect_err("zero owner")
                .code(),
            "runtime.critical-section.invalid-owner"
        );
        assert!(matches!(
            coordinator.try_acquire("", 1),
            Err(CriticalSectionError::InvalidName)
        ));

        let first_wakes = Arc::new(AtomicUsize::new(0));
        let second_wakes = Arc::new(AtomicUsize::new(0));
        let first = counting_waker(&first_wakes);
        let second = counting_waker(&second_wakes);
        coordinator.try_acquire("gate", 1).expect("owner");
        assert!(matches!(
            coordinator.poll_acquire("gate", 2, &first),
            Poll::Pending
        ));
        assert!(matches!(
            coordinator.poll_acquire("gate", 3, &second),
            Poll::Pending
        ));
        let before = coordinator.wait_snapshot();
        assert_eq!(before.pending, 2);
        coordinator.release("gate", 1).expect("release");
        assert_eq!(first_wakes.load(Ordering::Acquire), 1);
        assert_eq!(second_wakes.load(Ordering::Acquire), 0);
        assert!(matches!(
            coordinator.poll_acquire("gate", 2, &first),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(coordinator.wait_snapshot().pending, 1);
    }

    #[test]
    fn critical_section_waiter_capacity_and_stale_cancel_are_bounded() {
        let coordinator = DeterministicCriticalSectionCoordinator::with_limits(1, 1);
        let generation = coordinator.generation();
        coordinator.try_acquire("gate", 1).expect("owner");
        assert!(matches!(
            coordinator.poll_acquire_generation("gate", 2, generation, &poll_waker()),
            Poll::Pending
        ));
        assert!(matches!(
            coordinator.poll_acquire_generation("gate", 3, generation, &poll_waker()),
            Poll::Ready(Err(CriticalSectionError::WaiterCapacity { limit: 1 }))
        ));
        coordinator
            .cancel_acquire_generation("gate", 2, generation)
            .expect("cancel");
        coordinator
            .release_generation("gate", 1, generation)
            .expect("release");
        let next = coordinator.advance_generation().expect("advance");
        assert!(matches!(
            coordinator.cancel_acquire_generation("gate", 2, generation),
            Err(CriticalSectionError::StaleGeneration { .. })
        ));
        // The wait generation also records enqueue/cancel/release changes;
        // it is intentionally distinct from the run generation used for
        // stale-owner rejection.
        assert!(coordinator.wait_snapshot().generation > next);
    }

    #[test]
    fn critical_section_cross_lock_capacity_race_is_woken() {
        let coordinator = DeterministicCriticalSectionCoordinator::with_limits(1, 2);
        let first_wakes = Arc::new(AtomicUsize::new(0));
        let first_waker = counting_waker(&first_wakes);
        let second_wakes = Arc::new(AtomicUsize::new(0));
        let second_waker = counting_waker(&second_wakes);
        coordinator.try_acquire("gate", 1).expect("owner");
        assert!(matches!(
            coordinator.poll_acquire("gate", 2, &first_waker),
            Poll::Pending
        ));
        coordinator.release("gate", 1).expect("release gate");
        assert!(first_wakes.load(Ordering::Acquire) > 0);
        // Another lock can fill the only held-lock slot before the woken
        // waiter is polled. The later release must wake that waiter again.
        coordinator.try_acquire("other", 3).expect("racing owner");
        assert!(matches!(
            coordinator.poll_acquire("gate", 2, &second_waker),
            Poll::Pending
        ));
        coordinator.release("other", 3).expect("release other");
        assert!(second_wakes.load(Ordering::Acquire) > 0);
        assert!(matches!(
            coordinator.poll_acquire("gate", 2, &second_waker),
            Poll::Ready(Ok(()))
        ));
    }

    #[test]
    fn throughput_shared_cursor_is_checked_and_generation_scoped() {
        let coordinator = DeterministicThroughputCoordinator::new();
        let request = ThroughputRequest::new(
            crate::ConstantThroughputMode::AllActiveThreadsShared,
            Duration::from_millis(10),
            Duration::ZERO,
            "user-1",
            None,
            Some(1),
            Some(1),
        );
        assert_eq!(
            coordinator.reserve(&request).expect("first reservation"),
            Duration::ZERO
        );
        assert_eq!(
            coordinator.reserve(&request).expect("second reservation"),
            Duration::from_millis(10)
        );
        let old = coordinator.generation();
        let new = coordinator.advance_generation().expect("new generation");
        assert_ne!(old, new);
        assert_eq!(
            coordinator
                .reserve_generation(&request, old)
                .expect_err("stale reservation")
                .code(),
            "runtime.component.failure"
        );
        assert_eq!(
            coordinator.reserve(&request).expect("fresh reservation"),
            Duration::ZERO
        );
    }

    #[test]
    fn throughput_active_thread_modes_scale_by_observed_participants() {
        let coordinator = DeterministicThroughputCoordinator::new();
        let first = ThroughputRequest::new(
            crate::ConstantThroughputMode::AllActiveThreads,
            Duration::from_millis(10),
            Duration::ZERO,
            "user-1",
            None,
            Some(1),
            Some(1),
        );
        let second = ThroughputRequest::new(
            crate::ConstantThroughputMode::AllActiveThreads,
            Duration::from_millis(10),
            Duration::ZERO,
            "user-2",
            None,
            Some(2),
            Some(2),
        );
        assert_eq!(coordinator.reserve(&first).expect("first"), Duration::ZERO);
        assert_eq!(
            coordinator.reserve(&second).expect("second"),
            Duration::ZERO
        );
        assert_eq!(
            coordinator.reserve(&first).expect("first next"),
            Duration::from_millis(10)
        );
        assert_eq!(
            coordinator.reserve(&second).expect("second next"),
            Duration::from_millis(20)
        );
    }

    #[test]
    fn throughput_active_period_rounds_after_scaling_the_request_duration() {
        // This is the public request boundary equivalent of JMeter's raw
        // 3_600 samples/minute period (16.666...ms).  Keeping the fractional
        // duration here proves that scaling occurs before Java-style
        // millisecond rounding: three active users target 50ms, not 51ms.
        let coordinator = DeterministicThroughputCoordinator::new();
        let request = |name: &str| {
            ThroughputRequest::new(
                crate::ConstantThroughputMode::AllActiveThreads,
                Duration::from_nanos(16_666_667),
                Duration::ZERO,
                name,
                Some("group".to_owned()),
                None,
                None,
            )
        };
        assert_eq!(
            coordinator.reserve(&request("one")).expect("one"),
            Duration::ZERO
        );
        assert_eq!(
            coordinator.reserve(&request("two")).expect("two"),
            Duration::ZERO
        );
        assert_eq!(
            coordinator.reserve(&request("three")).expect("three"),
            Duration::ZERO
        );
        assert_eq!(
            coordinator.reserve(&request("three")).expect("three next"),
            Duration::from_millis(50)
        );
    }

    #[test]
    fn throughput_active_group_mode_counts_only_the_current_group() {
        let coordinator = DeterministicThroughputCoordinator::new();
        let group_a_one = ThroughputRequest::new(
            crate::ConstantThroughputMode::AllActiveThreadsInCurrentThreadGroup,
            Duration::from_millis(10),
            Duration::ZERO,
            "a-1",
            Some("a".to_owned()),
            Some(1),
            Some(1),
        );
        let group_a_two = ThroughputRequest::new(
            crate::ConstantThroughputMode::AllActiveThreadsInCurrentThreadGroup,
            Duration::from_millis(10),
            Duration::ZERO,
            "a-2",
            Some("a".to_owned()),
            Some(2),
            Some(2),
        );
        let group_b_one = ThroughputRequest::new(
            crate::ConstantThroughputMode::AllActiveThreadsInCurrentThreadGroup,
            Duration::from_millis(10),
            Duration::ZERO,
            "b-1",
            Some("b".to_owned()),
            Some(1),
            Some(3),
        );
        assert_eq!(
            coordinator.reserve(&group_a_one).expect("group a first"),
            Duration::ZERO
        );
        assert_eq!(
            coordinator.reserve(&group_a_two).expect("group a second"),
            Duration::ZERO
        );
        assert_eq!(
            coordinator.reserve(&group_b_one).expect("group b first"),
            Duration::ZERO
        );
        assert_eq!(
            coordinator.reserve(&group_a_one).expect("group a next"),
            Duration::from_millis(10)
        );
        assert_eq!(
            coordinator.reserve(&group_b_one).expect("group b next"),
            Duration::from_millis(10)
        );
    }

    #[test]
    fn throughput_active_modes_count_observed_users_across_mode_scopes() {
        // Active-thread accounting is about physical participants, not the
        // calculation mode used by the participant's own timer. A group
        // timer must include a same-group this-thread participant, while a
        // global timer must include a participant carrying a group scope.
        let group_coordinator = DeterministicThroughputCoordinator::new();
        let local = ThroughputRequest::new(
            crate::ConstantThroughputMode::ThisThreadOnly,
            Duration::from_millis(10),
            Duration::ZERO,
            "local",
            Some("group-a".to_owned()),
            Some(1),
            Some(1),
        );
        let group = ThroughputRequest::new(
            crate::ConstantThroughputMode::AllActiveThreadsInCurrentThreadGroup,
            Duration::from_millis(10),
            Duration::ZERO,
            "group-user",
            Some("group-a".to_owned()),
            Some(2),
            Some(2),
        );
        assert_eq!(
            group_coordinator.reserve(&local).expect("local first"),
            Duration::ZERO
        );
        assert_eq!(
            group_coordinator.reserve(&group).expect("group first"),
            Duration::ZERO
        );
        assert_eq!(
            group_coordinator.reserve(&group).expect("group next"),
            Duration::from_millis(20)
        );

        let global_coordinator = DeterministicThroughputCoordinator::new();
        let group_scoped = ThroughputRequest::new(
            crate::ConstantThroughputMode::AllActiveThreadsInCurrentThreadGroup,
            Duration::from_millis(10),
            Duration::ZERO,
            "group-user",
            Some("group-a".to_owned()),
            Some(1),
            Some(3),
        );
        let global = ThroughputRequest::new(
            crate::ConstantThroughputMode::AllActiveThreads,
            Duration::from_millis(10),
            Duration::ZERO,
            "global-user",
            Some("group-b".to_owned()),
            Some(1),
            Some(4),
        );
        assert_eq!(
            global_coordinator
                .reserve(&group_scoped)
                .expect("group scoped first"),
            Duration::ZERO
        );
        assert_eq!(
            global_coordinator.reserve(&global).expect("global first"),
            Duration::ZERO
        );
        assert_eq!(
            global_coordinator.reserve(&global).expect("global next"),
            Duration::from_millis(20)
        );
    }

    #[test]
    fn throughput_active_modes_include_shared_cursor_participants() {
        let coordinator = DeterministicThroughputCoordinator::new();
        let shared = ThroughputRequest::new(
            crate::ConstantThroughputMode::AllActiveThreadsShared,
            Duration::from_millis(10),
            Duration::ZERO,
            "shared-user",
            Some("group-a".to_owned()),
            Some(1),
            Some(1),
        );
        let active = ThroughputRequest::new(
            crate::ConstantThroughputMode::AllActiveThreads,
            Duration::from_millis(10),
            Duration::ZERO,
            "active-user",
            Some("group-b".to_owned()),
            Some(1),
            Some(2),
        );
        assert_eq!(
            coordinator.reserve(&shared).expect("shared first"),
            Duration::ZERO
        );
        assert_eq!(
            coordinator.reserve(&active).expect("active first"),
            Duration::ZERO
        );
        assert_eq!(
            coordinator.reserve(&active).expect("active next"),
            Duration::from_millis(20)
        );
        assert!(coordinator.cancel(&shared).expect("shared cancellation"));
        let active_at_40 = ThroughputRequest::new(
            crate::ConstantThroughputMode::AllActiveThreads,
            Duration::from_millis(10),
            Duration::from_millis(40),
            "active-user",
            Some("group-b".to_owned()),
            Some(1),
            Some(2),
        );
        assert_eq!(
            coordinator
                .reserve(&active_at_40)
                .expect("active after cancellation"),
            Duration::ZERO
        );
        assert_eq!(
            coordinator
                .reserve(&active_at_40)
                .expect("active after cancellation next"),
            Duration::from_millis(10)
        );
    }

    #[test]
    fn throughput_active_scaling_can_make_submillisecond_period_representable() {
        let coordinator = DeterministicThroughputCoordinator::new();
        let shared = ThroughputRequest::new(
            crate::ConstantThroughputMode::AllActiveThreadsShared,
            Duration::from_millis(10),
            Duration::ZERO,
            "shared-user",
            None,
            Some(1),
            Some(1),
        );
        let active = ThroughputRequest::new(
            crate::ConstantThroughputMode::AllActiveThreads,
            Duration::from_micros(400),
            Duration::ZERO,
            "active-user",
            None,
            Some(2),
            Some(2),
        );
        coordinator.reserve(&shared).expect("shared participant");
        assert_eq!(
            coordinator.reserve(&active).expect("scaled active period"),
            Duration::ZERO
        );
        let active_again = ThroughputRequest::new(
            crate::ConstantThroughputMode::AllActiveThreads,
            Duration::from_micros(400),
            Duration::ZERO,
            "active-user",
            None,
            Some(2),
            Some(2),
        );
        assert_eq!(
            coordinator
                .reserve(&active_again)
                .expect("scaled active period next"),
            Duration::from_millis(1)
        );
    }

    #[test]
    fn throughput_shared_cursors_are_global_or_group_local() {
        let coordinator = DeterministicThroughputCoordinator::new();
        let global = ThroughputRequest::new(
            crate::ConstantThroughputMode::AllActiveThreadsShared,
            Duration::from_millis(10),
            Duration::ZERO,
            "global",
            Some("a".to_owned()),
            Some(1),
            Some(1),
        );
        let other_global = ThroughputRequest::new(
            crate::ConstantThroughputMode::AllActiveThreadsShared,
            Duration::from_millis(10),
            Duration::ZERO,
            "other",
            Some("b".to_owned()),
            Some(1),
            Some(2),
        );
        assert_eq!(
            coordinator.reserve(&global).expect("global first"),
            Duration::ZERO
        );
        assert_eq!(
            coordinator.reserve(&other_global).expect("global second"),
            Duration::from_millis(10)
        );

        let group_a = ThroughputRequest::new(
            crate::ConstantThroughputMode::AllActiveThreadsInCurrentThreadGroupShared,
            Duration::from_millis(10),
            Duration::ZERO,
            "a-1",
            Some("a".to_owned()),
            Some(1),
            Some(3),
        );
        let group_b = ThroughputRequest::new(
            crate::ConstantThroughputMode::AllActiveThreadsInCurrentThreadGroupShared,
            Duration::from_millis(10),
            Duration::ZERO,
            "b-1",
            Some("b".to_owned()),
            Some(1),
            Some(4),
        );
        assert_eq!(
            coordinator.reserve(&group_a).expect("group a first"),
            Duration::ZERO
        );
        assert_eq!(
            coordinator.reserve(&group_b).expect("group b first"),
            Duration::ZERO
        );
        assert_eq!(
            coordinator.reserve(&group_a).expect("group a second"),
            Duration::from_millis(10)
        );
        assert_eq!(
            coordinator.reserve(&group_b).expect("group b second"),
            Duration::from_millis(10)
        );
    }

    #[test]
    fn throughput_cancellation_is_generation_scoped_and_ids_are_nonzero() {
        let coordinator = DeterministicThroughputCoordinator::with_limits(1, 1);
        let request = ThroughputRequest::new(
            crate::ConstantThroughputMode::AllActiveThreads,
            Duration::from_millis(10),
            Duration::ZERO,
            "user",
            Some("group".to_owned()),
            Some(1),
            Some(7),
        );
        assert_eq!(
            coordinator.reserve(&request).expect("reserve"),
            Duration::ZERO
        );
        let old = coordinator.generation();
        let next = coordinator.advance_generation().expect("new generation");
        assert!(coordinator.cancel_generation(&request, old).is_err());
        assert_eq!(
            coordinator
                .reserve_generation(&request, next)
                .expect("fresh reserve"),
            Duration::ZERO
        );
        assert!(
            coordinator
                .cancel_generation(&request, next)
                .expect("cancel")
        );
        let invalid = ThroughputRequest::new(
            crate::ConstantThroughputMode::ThisThreadOnly,
            Duration::from_millis(10),
            Duration::ZERO,
            "user",
            None,
            Some(0),
            Some(1),
        );
        assert!(coordinator.reserve(&invalid).is_err());
    }

    #[test]
    fn throughput_per_user_cursors_are_isolated_by_calculation_mode() {
        let coordinator = DeterministicThroughputCoordinator::new();
        let this_thread = ThroughputRequest::new(
            crate::ConstantThroughputMode::ThisThreadOnly,
            Duration::from_millis(10),
            Duration::ZERO,
            "user",
            Some("group".to_owned()),
            Some(1),
            Some(1),
        );
        let all_threads = ThroughputRequest::new(
            crate::ConstantThroughputMode::AllActiveThreads,
            Duration::from_millis(10),
            Duration::ZERO,
            "user",
            Some("group".to_owned()),
            Some(1),
            Some(1),
        );
        assert_eq!(
            coordinator.reserve(&this_thread).expect("this"),
            Duration::ZERO
        );
        assert_eq!(
            coordinator.reserve(&all_threads).expect("all"),
            Duration::ZERO
        );
        assert!(coordinator.cancel(&this_thread).expect("cancel this"));
        assert!(coordinator.cancel(&all_threads).expect("cancel all"));
    }

    #[test]
    fn throughput_checked_target_overflow_is_not_saturated() {
        let coordinator = DeterministicThroughputCoordinator::new();
        let request = ThroughputRequest::new(
            crate::ConstantThroughputMode::AllActiveThreadsShared,
            Duration::from_nanos(1),
            Duration::MAX,
            "user",
            None,
            Some(1),
            Some(1),
        );
        assert!(coordinator.reserve(&request).is_err());
    }

    fn barrier_request(
        name: &str,
        participant: &str,
        group_size: usize,
        now: Duration,
    ) -> SynchronizingRequest {
        SynchronizingRequest::new(
            name,
            group_size,
            Duration::from_secs(1),
            participant,
            "thread",
            Some("group".to_owned()),
            None,
            None,
            now,
        )
        .expect("barrier request")
    }

    #[test]
    fn synchronizing_barrier_releases_once_and_starts_next_generation() {
        let coordinator = DeterministicSynchronizingCoordinator::new();
        let first = barrier_request("gate", "one", 2, Duration::ZERO);
        let second = barrier_request("gate", "two", 2, Duration::from_millis(1));
        let waker = poll_waker();
        assert!(matches!(
            coordinator.poll_arrival(&first, &waker),
            Poll::Pending
        ));
        assert_eq!(
            coordinator.generation("gate", None),
            CoordinationGeneration::new(1)
        );
        assert!(matches!(
            coordinator.poll_arrival(&second, &waker),
            Poll::Ready(Ok(SynchronizingOutcome::Released))
        ));
        coordinator.complete(&first, SynchronizingOutcome::Released);
        coordinator.complete(&second, SynchronizingOutcome::Released);
        let third = barrier_request("gate", "three", 2, Duration::from_millis(2));
        assert!(matches!(
            coordinator.poll_arrival(&third, &waker),
            Poll::Pending
        ));
        assert_eq!(
            coordinator.generation("gate", None),
            CoordinationGeneration::new(2)
        );
    }

    #[test]
    fn synchronizing_barrier_timeout_and_cancel_do_not_leak_participants() {
        let coordinator = DeterministicSynchronizingCoordinator::new();
        let first = barrier_request("gate", "one", 2, Duration::ZERO);
        let waker = poll_waker();
        assert!(matches!(
            coordinator.poll_arrival(&first, &waker),
            Poll::Pending
        ));
        let late = barrier_request("gate", "two", 2, Duration::from_secs(1));
        assert!(matches!(
            coordinator.poll_arrival(&late, &waker),
            Poll::Ready(Ok(SynchronizingOutcome::TimedOut))
        ));
        coordinator.complete(&first, SynchronizingOutcome::TimedOut);
        coordinator.complete(&late, SynchronizingOutcome::TimedOut);
        let next = barrier_request("gate", "fresh", 2, Duration::from_secs(2));
        assert!(matches!(
            coordinator.poll_arrival(&next, &waker),
            Poll::Pending
        ));
        coordinator.cancel(&next);
        assert!(coordinator.generation("gate", None).is_some());
    }

    #[test]
    fn synchronizing_barrier_deadline_and_wait_generation_are_executor_neutral() {
        let coordinator = DeterministicSynchronizingCoordinator::new();
        let first = barrier_request("gate", "one", 2, Duration::ZERO);
        let wakes = Arc::new(AtomicUsize::new(0));
        let waker = counting_waker(&wakes);
        assert!(matches!(
            coordinator.poll_arrival(&first, &waker),
            Poll::Pending
        ));
        let snapshot = coordinator.wait_snapshot();
        assert_eq!(snapshot.pending, 1);
        assert_eq!(snapshot.earliest_deadline, Some(Duration::from_secs(1)));
        assert!(snapshot.generation.get() > 0);

        let second = barrier_request("gate", "two", 2, Duration::from_millis(1_000));
        assert!(matches!(
            coordinator.poll_arrival(&second, &waker),
            Poll::Ready(Ok(SynchronizingOutcome::TimedOut))
        ));
        assert!(wakes.load(Ordering::Acquire) >= 1);
        coordinator.complete(&first, SynchronizingOutcome::TimedOut);
        coordinator.complete(&second, SynchronizingOutcome::TimedOut);
        assert_eq!(coordinator.wait_snapshot().pending, 0);
    }

    #[test]
    fn synchronizing_barrier_cancellation_breaks_only_current_generation() {
        let coordinator = DeterministicSynchronizingCoordinator::new();
        let first = barrier_request("gate", "one", 3, Duration::ZERO);
        let second = barrier_request("gate", "two", 3, Duration::ZERO);
        let wakes = Arc::new(AtomicUsize::new(0));
        let waker = counting_waker(&wakes);
        assert!(matches!(
            coordinator.poll_arrival(&first, &waker),
            Poll::Pending
        ));
        assert!(matches!(
            coordinator.poll_arrival(&second, &waker),
            Poll::Pending
        ));
        let before = coordinator.generation("gate", None).expect("generation");
        coordinator.cancel(&first);
        assert!(wakes.load(Ordering::Acquire) >= 1);
        assert!(matches!(
            coordinator.poll_arrival(&first, &waker),
            Poll::Ready(Err(ComponentError::Failure(_)))
        ));
        assert!(matches!(
            coordinator.poll_arrival(&second, &waker),
            Poll::Ready(Ok(SynchronizingOutcome::TimedOut))
        ));
        coordinator.complete(&second, SynchronizingOutcome::TimedOut);
        let after = coordinator
            .generation("gate", None)
            .expect("next generation");
        assert!(after > before);
    }

    #[test]
    fn synchronizing_barrier_rejects_participant_reuse_until_completion() {
        let coordinator = DeterministicSynchronizingCoordinator::with_limits(2, 2);
        let first = barrier_request("gate", "one", 2, Duration::ZERO);
        let waker = poll_waker();
        assert!(matches!(
            coordinator.poll_arrival(&first, &waker),
            Poll::Pending
        ));
        let duplicate = barrier_request("gate", "one", 2, Duration::ZERO);
        assert!(matches!(
            coordinator.poll_arrival(&duplicate, &waker),
            Poll::Pending
        ));
        let second = barrier_request("gate", "two", 2, Duration::ZERO);
        assert!(matches!(
            coordinator.poll_arrival(&second, &waker),
            Poll::Ready(Ok(SynchronizingOutcome::Released))
        ));
        coordinator.complete(&first, SynchronizingOutcome::Released);
        coordinator.complete(&second, SynchronizingOutcome::Released);
        let next = barrier_request("gate", "one", 2, Duration::ZERO);
        assert!(matches!(
            coordinator.poll_arrival(&next, &waker),
            Poll::Pending
        ));
    }

    #[test]
    fn synchronizing_barrier_rejects_deadline_overflow_and_bounds_slots() {
        let coordinator = DeterministicSynchronizingCoordinator::with_limits(1, 2);
        assert!(matches!(
            SynchronizingRequest::new(
                "gate",
                2,
                Duration::from_nanos(1),
                "one",
                "thread",
                Some("group".to_owned()),
                Some(1),
                Some(1),
                Duration::MAX,
            ),
            Err(ComponentError::ResourceLimit(_))
        ));
        let first = barrier_request("first", "one", 2, Duration::ZERO);
        assert!(matches!(
            coordinator.poll_arrival(&first, &poll_waker()),
            Poll::Pending
        ));
        let second = barrier_request("second", "two", 2, Duration::ZERO);
        assert!(matches!(
            coordinator.poll_arrival(&second, &poll_waker()),
            Poll::Ready(Err(ComponentError::ResourceLimit(_)))
        ));
    }

    #[test]
    fn current_group_barrier_requires_registered_count() {
        let coordinator = DeterministicSynchronizingCoordinator::new();
        let request = SynchronizingRequest::new(
            "gate",
            0,
            Duration::ZERO,
            "one",
            "thread",
            Some("group".to_owned()),
            None,
            None,
            Duration::ZERO,
        )
        .expect("request");
        assert!(matches!(
            coordinator.poll_arrival(&request, &poll_waker()),
            Poll::Ready(Err(ComponentError::Unsupported(_)))
        ));
        coordinator
            .register_thread_group("group", NonZeroUsize::new(1).expect("one"))
            .expect("register");
        assert!(matches!(
            coordinator.poll_arrival(&request, &poll_waker()),
            Poll::Ready(Ok(SynchronizingOutcome::Released))
        ));
    }

    #[test]
    fn current_group_barriers_are_isolated_by_thread_group() {
        let coordinator = DeterministicSynchronizingCoordinator::new();
        coordinator
            .register_thread_group("alpha", NonZeroUsize::new(2).expect("two"))
            .expect("alpha");
        coordinator
            .register_thread_group("beta", NonZeroUsize::new(2).expect("two"))
            .expect("beta");
        let alpha_one = SynchronizingRequest::new(
            "gate",
            0,
            Duration::ZERO,
            "alpha-1",
            "thread",
            Some("alpha".to_owned()),
            Some(1),
            Some(1),
            Duration::ZERO,
        )
        .expect("alpha request");
        let alpha_two = SynchronizingRequest::new(
            "gate",
            0,
            Duration::ZERO,
            "alpha-2",
            "thread",
            Some("alpha".to_owned()),
            Some(2),
            Some(2),
            Duration::ZERO,
        )
        .expect("alpha request");
        let beta_one = SynchronizingRequest::new(
            "gate",
            0,
            Duration::ZERO,
            "beta-1",
            "thread",
            Some("beta".to_owned()),
            Some(1),
            Some(3),
            Duration::ZERO,
        )
        .expect("beta request");
        let beta_two = SynchronizingRequest::new(
            "gate",
            0,
            Duration::ZERO,
            "beta-2",
            "thread",
            Some("beta".to_owned()),
            Some(2),
            Some(4),
            Duration::ZERO,
        )
        .expect("beta request");
        let waker = poll_waker();
        assert!(matches!(
            coordinator.poll_arrival(&alpha_one, &waker),
            Poll::Pending
        ));
        assert!(matches!(
            coordinator.poll_arrival(&beta_one, &waker),
            Poll::Pending
        ));
        assert!(matches!(
            coordinator.poll_arrival(&alpha_two, &waker),
            Poll::Ready(Ok(SynchronizingOutcome::Released))
        ));
        assert!(matches!(
            coordinator.poll_arrival(&beta_two, &waker),
            Poll::Ready(Ok(SynchronizingOutcome::Released))
        ));
        coordinator.complete(&alpha_one, SynchronizingOutcome::Released);
        coordinator.complete(&alpha_two, SynchronizingOutcome::Released);
        coordinator.complete(&beta_one, SynchronizingOutcome::Released);
        coordinator.complete(&beta_two, SynchronizingOutcome::Released);
    }
}
