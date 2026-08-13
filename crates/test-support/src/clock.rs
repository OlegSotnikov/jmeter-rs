// SPDX-License-Identifier: Apache-2.0
//! Virtual wall and monotonic time plus a deterministic timer queue.
//!
//! Timer handles are non-owning by default.  The explicit owned registration
//! helpers attempt bounded cancellation on last-handle drop; callers can use
//! [`FakeSleeper::assert_no_leaks`] to make lifecycle failures explicit.

use crate::error::{ErrorCode, StableError};
use crate::trace::{ReplayCursor, ReplayError, ReplayLog, TraceError, TraceEvent, TraceLimits};
use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A wall-clock instant owned by the deterministic clock.
///
/// The wrapper prevents accidental mixing with a monotonic deadline while
/// still allowing adapters to use [`SystemTime`] at their boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WallTime(SystemTime);

impl WallTime {
    /// The Unix epoch.
    pub const UNIX_EPOCH: Self = Self(UNIX_EPOCH);

    /// Wraps a system time.
    #[must_use]
    pub const fn from_system_time(time: SystemTime) -> Self {
        Self(time)
    }

    /// Returns the wrapped system time.
    #[must_use]
    pub const fn as_system_time(self) -> SystemTime {
        self.0
    }

    /// Adds a non-negative duration without saturating.
    #[must_use]
    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        self.0.checked_add(duration).map(Self)
    }

    /// Returns the duration from `earlier` to this time, if this is later.
    #[must_use]
    pub fn checked_duration_since(self, earlier: Self) -> Option<Duration> {
        self.0.duration_since(earlier.0).ok()
    }

    /// Creates a wall time from a duration after the Unix epoch.
    #[must_use]
    pub fn from_unix_duration(duration: Duration) -> Option<Self> {
        UNIX_EPOCH.checked_add(duration).map(Self)
    }
}

impl From<SystemTime> for WallTime {
    fn from(time: SystemTime) -> Self {
        Self::from_system_time(time)
    }
}

impl From<WallTime> for SystemTime {
    fn from(time: WallTime) -> Self {
        time.as_system_time()
    }
}

impl Default for WallTime {
    fn default() -> Self {
        Self::UNIX_EPOCH
    }
}

/// A monotonic instant measured from the virtual clock's configured origin.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MonotonicInstant(Duration);

impl MonotonicInstant {
    /// The configured monotonic origin.
    pub const ZERO: Self = Self(Duration::ZERO);

    /// Wraps a duration from the monotonic origin.
    #[must_use]
    pub const fn from_duration(duration: Duration) -> Self {
        Self(duration)
    }

    /// Returns the duration from the monotonic origin.
    #[must_use]
    pub const fn as_duration(self) -> Duration {
        self.0
    }

    /// Adds a duration without saturating.
    #[must_use]
    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        self.0.checked_add(duration).map(Self)
    }

    /// Returns the non-negative duration between two instants.
    #[must_use]
    pub fn checked_duration_since(self, earlier: Self) -> Option<Duration> {
        self.0.checked_sub(earlier.0)
    }
}

impl From<Duration> for MonotonicInstant {
    fn from(duration: Duration) -> Self {
        Self::from_duration(duration)
    }
}

impl From<MonotonicInstant> for Duration {
    fn from(instant: MonotonicInstant) -> Self {
        instant.as_duration()
    }
}

/// A consistent wall/monotonic reading from a [`VirtualClock`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockSnapshot {
    /// The controlled wall timestamp.
    pub wall: WallTime,
    /// The controlled monotonic timestamp.
    pub monotonic: MonotonicInstant,
}

impl ClockSnapshot {
    /// Returns the wall timestamp.
    #[must_use]
    pub const fn wall_time(self) -> WallTime {
        self.wall
    }

    /// Returns the monotonic timestamp.
    #[must_use]
    pub const fn monotonic_time(self) -> MonotonicInstant {
        self.monotonic
    }

    /// Returns the elapsed monotonic duration from `earlier`.
    ///
    /// Wall time is deliberately not used for elapsed-time calculations.  A
    /// fixture may move wall time independently (for example, to model an
    /// NTP correction) while deadlines and timer ordering continue to use
    /// this monotonic axis.
    pub fn checked_duration_since(self, earlier: Self) -> Result<Duration, ClockError> {
        self.monotonic
            .checked_duration_since(earlier.monotonic)
            .ok_or(ClockError::MovedBackward {
                current: earlier.monotonic,
                requested: self.monotonic,
            })
    }

    /// Checks progress between two observations without consulting the host
    /// clock or sleeping.
    ///
    /// `Ok(None)` is an intentional fixture stall when work is marked
    /// `runnable` and the monotonic value did not change.  A non-runnable
    /// observation may remain equal and returns `Ok(Some(Duration::ZERO))`.
    /// A reversal is always an error.  This keeps a stalled source distinct
    /// from a source that moved backwards without adding a polling heuristic.
    pub fn checked_progress_since(
        self,
        earlier: Self,
        runnable: bool,
    ) -> Result<Option<Duration>, ClockError> {
        let elapsed = self.checked_duration_since(earlier)?;
        if runnable && elapsed.is_zero() {
            Ok(None)
        } else {
            Ok(Some(elapsed))
        }
    }
}

/// The part of a clock state that overflowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockComponent {
    /// The monotonic instant could not represent the requested advance.
    Monotonic,
    /// The wall timestamp could not represent the requested advance.
    Wall,
}

/// Errors returned by checked virtual-clock operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockError {
    /// A requested target precedes the current monotonic instant.
    MovedBackward {
        /// The current virtual monotonic time.
        current: MonotonicInstant,
        /// The rejected target.
        requested: MonotonicInstant,
    },
    /// The requested advance exceeded a representable clock component.
    Overflow {
        /// The component that would overflow.
        component: ClockComponent,
        /// The attempted non-negative advance.
        amount: Duration,
    },
}

impl ClockError {
    /// Returns the stable error code.
    #[must_use]
    pub const fn code(self) -> ErrorCode {
        match self {
            Self::MovedBackward { .. } => ErrorCode::ClockMovedBackward,
            Self::Overflow { .. } => ErrorCode::ClockOverflow,
        }
    }
}

impl fmt::Display for ClockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MovedBackward { current, requested } => write!(
                formatter,
                "{}: requested monotonic time {requested:?} precedes current {current:?}",
                self.code()
            ),
            Self::Overflow { component, amount } => write!(
                formatter,
                "{}: advancing {component:?} by {amount:?} would overflow",
                self.code()
            ),
        }
    }
}

impl std::error::Error for ClockError {}
impl StableError for ClockError {
    fn code(&self) -> ErrorCode {
        (*self).code()
    }
}

#[derive(Debug)]
struct ClockState {
    wall: WallTime,
    monotonic: MonotonicInstant,
}

/// A cloneable deterministic clock.
///
/// Clones share the same state.  Advancing one clone advances every clone, a
/// useful property for a runtime test that gives the clock to multiple fake
/// components.  The clock never advances implicitly and never saturates: an
/// overflow or backwards target is returned as a typed error before state is
/// changed.
#[derive(Clone, Debug)]
pub struct VirtualClock {
    state: Arc<Mutex<ClockState>>,
}

impl VirtualClock {
    /// Creates a clock at explicit wall and monotonic origins.
    #[must_use]
    pub fn new(wall: WallTime, monotonic: MonotonicInstant) -> Self {
        Self {
            state: Arc::new(Mutex::new(ClockState { wall, monotonic })),
        }
    }

    /// Creates a clock at the Unix epoch and monotonic zero.
    #[must_use]
    pub fn at_epoch() -> Self {
        Self::new(WallTime::UNIX_EPOCH, MonotonicInstant::ZERO)
    }

    /// Creates a clock at a supplied wall timestamp and monotonic zero.
    #[must_use]
    pub fn from_system_time(wall: SystemTime) -> Self {
        Self::new(WallTime::from_system_time(wall), MonotonicInstant::ZERO)
    }

    /// Replaces the paired reading without validating monotonic order.
    ///
    /// This is intentionally a fault-injection seam for tests of consumers
    /// that observe an unreliable provider.  Normal timer tests should use
    /// [`VirtualClock::advance`] or [`VirtualClock::advance_to`], both of
    /// which reject reversals and overflow atomically.
    pub fn set_unchecked(&self, snapshot: ClockSnapshot) {
        let mut state = recover_lock(&self.state);
        state.wall = snapshot.wall;
        state.monotonic = snapshot.monotonic;
    }

    /// Replaces only the wall-clock component and returns the resulting
    /// paired reading.
    ///
    /// Wall time is allowed to jump in either direction because it is a
    /// timestamp, not a deadline source.  Monotonic time is unchanged, so
    /// timer ordering and elapsed durations remain stable across the jump.
    pub fn set_wall_time(&self, wall: WallTime) -> ClockSnapshot {
        let mut state = recover_lock(&self.state);
        state.wall = wall;
        ClockSnapshot {
            wall: state.wall,
            monotonic: state.monotonic,
        }
    }

    /// Observes this clock relative to `previous` without sleeping.
    ///
    /// See [`ClockSnapshot::checked_progress_since`] for the meaning of the
    /// optional result.  Consumers can use `None` to report a provider stall
    /// and avoid extending a deadline while still accepting equal samples for
    /// explicitly quiescent work.
    pub fn observe(
        &self,
        previous: ClockSnapshot,
        runnable: bool,
    ) -> Result<Option<ClockSnapshot>, ClockError> {
        let current = self.snapshot();
        current
            .checked_progress_since(previous, runnable)
            .map(|progress| progress.map(|_| current))
    }

    /// Returns a clone sharing this clock's state.
    #[must_use]
    pub fn shared(&self) -> Self {
        self.clone()
    }

    /// Reads both clocks atomically.
    #[must_use]
    pub fn snapshot(&self) -> ClockSnapshot {
        let state = recover_lock(&self.state);
        ClockSnapshot {
            wall: state.wall,
            monotonic: state.monotonic,
        }
    }

    /// Alias for [`VirtualClock::snapshot`].
    #[must_use]
    pub fn now(&self) -> ClockSnapshot {
        self.snapshot()
    }

    /// Reads the controlled wall timestamp.
    #[must_use]
    pub fn wall_time(&self) -> WallTime {
        self.snapshot().wall
    }

    /// Alias for [`VirtualClock::wall_time`].
    #[must_use]
    pub fn wall_now(&self) -> WallTime {
        self.wall_time()
    }

    /// Reads the controlled monotonic instant.
    #[must_use]
    pub fn monotonic(&self) -> MonotonicInstant {
        self.snapshot().monotonic
    }

    /// Alias for [`VirtualClock::monotonic`].
    #[must_use]
    pub fn monotonic_now(&self) -> MonotonicInstant {
        self.monotonic()
    }

    /// Advances wall and monotonic time by exactly `amount`.
    pub fn advance(&self, amount: Duration) -> Result<ClockSnapshot, ClockError> {
        let mut state = recover_lock(&self.state);
        advance_locked(&mut state, amount)
    }

    /// Advances to a monotonic target while holding the clock state lock for
    /// the complete read/check/update transaction.
    pub fn advance_to(&self, target: MonotonicInstant) -> Result<ClockSnapshot, ClockError> {
        let mut state = recover_lock(&self.state);
        let current = state.monotonic;
        let amount = target
            .checked_duration_since(current)
            .ok_or(ClockError::MovedBackward {
                current,
                requested: target,
            })?;
        advance_locked(&mut state, amount)
    }

    /// Alias for [`VirtualClock::advance`] that emphasizes checked behavior.
    pub fn checked_advance(&self, amount: Duration) -> Result<ClockSnapshot, ClockError> {
        self.advance(amount)
    }

    /// Alias for [`VirtualClock::advance_to`] that emphasizes checked behavior.
    pub fn checked_advance_to(
        &self,
        target: MonotonicInstant,
    ) -> Result<ClockSnapshot, ClockError> {
        self.advance_to(target)
    }
}

fn advance_locked(state: &mut ClockState, amount: Duration) -> Result<ClockSnapshot, ClockError> {
    let monotonic = state
        .monotonic
        .checked_add(amount)
        .ok_or(ClockError::Overflow {
            component: ClockComponent::Monotonic,
            amount,
        })?;
    let wall = state.wall.checked_add(amount).ok_or(ClockError::Overflow {
        component: ClockComponent::Wall,
        amount,
    })?;
    state.monotonic = monotonic;
    state.wall = wall;
    Ok(ClockSnapshot { wall, monotonic })
}

fn recover_lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// A stable identifier assigned to a timer registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimerId(u64);

impl TimerId {
    /// Creates an identifier from its numeric representation.
    #[must_use]
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric identifier.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// The state of one registered timer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerState {
    /// The timer has not reached its deadline and can be cancelled.
    Pending,
    /// The timer reached its deadline and is eligible to wake its owner.
    Ready,
    /// The timer was cancelled before it became ready.
    Cancelled,
    /// The ready event was consumed from the fake sleeper queue.
    Consumed,
}

impl TimerState {
    /// Returns whether the registration is still waiting for its deadline.
    #[must_use]
    pub const fn is_pending(self) -> bool {
        matches!(self, Self::Pending)
    }

    /// Returns whether the registration was cancelled before wake-up.
    #[must_use]
    pub const fn is_cancelled(self) -> bool {
        matches!(self, Self::Cancelled)
    }

    /// Returns whether the registration has become eligible or was consumed.
    #[must_use]
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Ready | Self::Consumed)
    }
}

/// The immutable details assigned at timer registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimerRegistration {
    /// The timer identifier.
    pub id: TimerId,
    /// The absolute monotonic deadline.
    pub deadline: MonotonicInstant,
    /// The insertion sequence used to break equal-deadline ties.
    pub sequence: u64,
}

/// A timer event returned in deterministic deadline/sequence order.
pub type TimerEvent = TimerRegistration;

/// A lifecycle event retained by the sleeper's bounded timer trace.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TimerLifecycleEvent {
    /// A timer registration was accepted.
    Registered(TimerRegistration),
    /// A pending timer was cancelled.
    Cancelled(TimerRegistration),
    /// A ready timer was consumed by the caller.
    Consumed(TimerRegistration),
}

impl fmt::Debug for TimerLifecycleEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, registration) = match self {
            Self::Registered(registration) => ("Registered", registration),
            Self::Cancelled(registration) => ("Cancelled", registration),
            Self::Consumed(registration) => ("Consumed", registration),
        };
        formatter
            .debug_struct("TimerLifecycleEvent")
            .field("kind", &kind)
            .field("registration", registration)
            .finish()
    }
}

/// Errors returned by the fake sleeper/timer queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerError {
    /// No additional active registrations fit in the configured bound.
    CapacityExceeded {
        /// The configured active-registration bound.
        limit: usize,
    },
    /// A relative deadline would overflow the monotonic instant.
    DeadlineOverflow {
        /// The requested relative delay.
        delay: Duration,
    },
    /// The sequence or timer identifier would overflow.
    SequenceOverflow,
    /// A handle does not refer to a currently known registration.
    UnknownTimer {
        /// The missing identifier.
        id: TimerId,
    },
    /// The bounded timer lifecycle trace could not retain another event.
    TraceCapacity,
}

impl TimerError {
    /// Returns the stable error code.
    #[must_use]
    pub const fn code(self) -> ErrorCode {
        match self {
            Self::CapacityExceeded { .. } => ErrorCode::TimerCapacity,
            Self::DeadlineOverflow { .. } => ErrorCode::TimerDeadlineOverflow,
            Self::SequenceOverflow => ErrorCode::TimerSequenceOverflow,
            Self::UnknownTimer { .. } => ErrorCode::TimerUnknown,
            Self::TraceCapacity => ErrorCode::TimerTraceCapacity,
        }
    }
}

impl fmt::Display for TimerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityExceeded { limit } => {
                write!(formatter, "{}: timer capacity is {limit}", self.code())
            }
            Self::DeadlineOverflow { delay } => write!(
                formatter,
                "{}: timer delay {delay:?} overflows the monotonic clock",
                self.code()
            ),
            Self::SequenceOverflow => write!(formatter, "{}: timer sequence overflow", self.code()),
            Self::UnknownTimer { id } => {
                write!(formatter, "{}: unknown timer {}", self.code(), id.get())
            }
            Self::TraceCapacity => write!(formatter, "{}: timer trace capacity", self.code()),
        }
    }
}

impl std::error::Error for TimerError {}
impl StableError for TimerError {
    fn code(&self) -> ErrorCode {
        (*self).code()
    }
}

/// Errors returned while advancing virtual time and draining timer wake-ups.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerAdvanceError {
    /// The virtual clock rejected the requested movement.
    Clock(ClockError),
    /// The sleeper could not retain or consume a wake event.
    Timer(TimerError),
}

impl TimerAdvanceError {
    /// Returns the underlying stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> ErrorCode {
        match self {
            Self::Clock(error) => error.code(),
            Self::Timer(error) => error.code(),
        }
    }
}

impl fmt::Display for TimerAdvanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clock(error) => error.fmt(formatter),
            Self::Timer(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for TimerAdvanceError {}

impl StableError for TimerAdvanceError {
    fn code(&self) -> ErrorCode {
        (*self).code()
    }
}

impl From<ClockError> for TimerAdvanceError {
    fn from(error: ClockError) -> Self {
        Self::Clock(error)
    }
}

impl From<TimerError> for TimerAdvanceError {
    fn from(error: TimerError) -> Self {
        Self::Timer(error)
    }
}

/// A validated, bounded timer lifecycle replay log.
#[derive(Clone, PartialEq, Eq)]
pub struct TimerReplayLog {
    events: Vec<TimerLifecycleEvent>,
    trace: ReplayLog,
}

impl fmt::Debug for TimerReplayLog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TimerReplayLog")
            .field("event_count", &self.events.len())
            .field("trace", &self.trace)
            .finish()
    }
}

impl TimerReplayLog {
    /// Validates timer lifecycle events under finite trace bounds.
    pub fn new(events: Vec<TimerLifecycleEvent>, limits: TraceLimits) -> Result<Self, TraceError> {
        let trace_events = events
            .iter()
            .enumerate()
            .map(|(sequence, event)| {
                let sequence = u64::try_from(sequence).map_err(|_| TraceError::InvalidLimit)?;
                Ok(timer_event_trace(sequence, *event))
            })
            .collect::<Result<Vec<_>, TraceError>>()?;
        let trace = ReplayLog::new(trace_events, limits)?;
        Ok(Self { events, trace })
    }

    /// Returns the ordered timer lifecycle events.
    #[must_use]
    pub fn events(&self) -> &[TimerLifecycleEvent] {
        &self.events
    }

    /// Returns the bounded encoded trace events.
    #[must_use]
    pub fn trace_events(&self) -> &[TraceEvent] {
        self.trace.events()
    }

    /// Returns the number of lifecycle events.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Returns whether no lifecycle events are retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Starts a replay cursor over the encoded timer events.
    #[must_use]
    pub fn replay(&self) -> ReplayCursor {
        self.trace.replay()
    }
}

/// Errors returned by explicit sleeper-owner leak checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerLeakError {
    /// Registrations remain active after their handles were dropped.
    ActiveTimers {
        /// Number of active registrations.
        active: usize,
    },
    /// Drop cancellation could not append its bounded lifecycle event.
    DropCancellationFailed {
        /// Number of failed drop cancellations.
        failures: usize,
    },
}

impl TimerLeakError {
    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> ErrorCode {
        ErrorCode::TimerLeak
    }
}

impl fmt::Display for TimerLeakError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ActiveTimers { active } => {
                write!(formatter, "{}: {active} active timer(s)", self.code())
            }
            Self::DropCancellationFailed { failures } => write!(
                formatter,
                "{}: {failures} timer drop cancellation(s) could not be recorded",
                self.code()
            ),
        }
    }
}

impl std::error::Error for TimerLeakError {}

impl StableError for TimerLeakError {
    fn code(&self) -> ErrorCode {
        TimerLeakError::code(*self)
    }
}

#[derive(Debug)]
struct TimerRecord {
    registration: TimerRegistration,
    state: TimerState,
}

#[derive(Debug)]
struct SleeperState {
    capacity: usize,
    trace_limits: TraceLimits,
    trace_bytes: usize,
    next_id: u64,
    next_sequence: u64,
    active: Vec<Arc<Mutex<TimerRecord>>>,
    ready: VecDeque<Arc<Mutex<TimerRecord>>>,
    lifecycle: Vec<TimerLifecycleEvent>,
    trace_error: Option<TimerError>,
    drop_cancellation_failures: usize,
}

#[derive(Debug)]
struct SleeperInner {
    clock: VirtualClock,
    state: Mutex<SleeperState>,
}

/// A cloneable deterministic sleeper and timer registration queue.
///
/// Registration is absolute and executor-neutral.  Advancing the associated
/// [`VirtualClock`] does not run callbacks; callers explicitly call
/// [`FakeSleeper::poll_ready`] or [`FakeSleeper::drain_ready`].  Ready events
/// are sorted by absolute deadline and then by the monotonic insertion
/// sequence, so equal deadlines are reproducible regardless of collection
/// timing.  Clones share registrations and capacity.
#[derive(Clone, Debug)]
pub struct FakeSleeper {
    inner: Arc<SleeperInner>,
}

impl FakeSleeper {
    /// Creates a sleeper with an active-registration capacity.
    #[must_use]
    pub fn new(clock: VirtualClock, capacity: usize) -> Self {
        Self {
            inner: Arc::new(SleeperInner {
                clock,
                state: Mutex::new(SleeperState {
                    capacity,
                    trace_limits: timer_trace_limits(capacity),
                    trace_bytes: 0,
                    next_id: 0,
                    next_sequence: 0,
                    active: Vec::new(),
                    ready: VecDeque::new(),
                    lifecycle: Vec::new(),
                    trace_error: None,
                    drop_cancellation_failures: 0,
                }),
            }),
        }
    }

    /// Creates a sleeper with an explicit bounded lifecycle trace.
    #[must_use]
    pub fn with_trace_limits(
        clock: VirtualClock,
        capacity: usize,
        trace_limits: TraceLimits,
    ) -> Self {
        Self {
            inner: Arc::new(SleeperInner {
                clock,
                state: Mutex::new(SleeperState {
                    capacity,
                    trace_limits,
                    trace_bytes: 0,
                    next_id: 0,
                    next_sequence: 0,
                    active: Vec::new(),
                    ready: VecDeque::new(),
                    lifecycle: Vec::new(),
                    trace_error: None,
                    drop_cancellation_failures: 0,
                }),
            }),
        }
    }

    /// Returns a clone sharing the clock, registrations, and queue.
    #[must_use]
    pub fn shared(&self) -> Self {
        self.clone()
    }

    /// Returns the virtual clock used for absolute deadlines.
    #[must_use]
    pub fn clock(&self) -> VirtualClock {
        self.inner.clock.clone()
    }

    /// Returns the configured active-registration capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        recover_lock(&self.inner.state).capacity
    }

    /// Returns the number of registrations not yet consumed or cancelled.
    #[must_use]
    pub fn registered_count(&self) -> usize {
        recover_lock(&self.inner.state).active.len()
    }

    /// Returns the number of pending (not-yet-ready) registrations.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        let state = recover_lock(&self.inner.state);
        state
            .active
            .iter()
            .filter(|record| record_state(record) == TimerState::Pending)
            .count()
    }

    /// Returns the number of ready events waiting to be consumed.
    #[must_use]
    pub fn ready_count(&self) -> usize {
        recover_lock(&self.inner.state).ready.len()
    }

    /// Returns configured lifecycle trace bounds.
    #[must_use]
    pub fn trace_limits(&self) -> TraceLimits {
        recover_lock(&self.inner.state).trace_limits
    }

    /// Returns retained timer lifecycle events.
    #[must_use]
    pub fn lifecycle_events(&self) -> Vec<TimerLifecycleEvent> {
        recover_lock(&self.inner.state).lifecycle.clone()
    }

    /// Returns a trace-capacity error observed by an infallible legacy poll
    /// method, if one occurred.
    #[must_use]
    pub fn trace_error(&self) -> Option<TimerError> {
        recover_lock(&self.inner.state).trace_error
    }

    /// Builds a bounded replay log from the retained timer lifecycle.
    pub fn replay_log(&self) -> Result<TimerReplayLog, TraceError> {
        let state = recover_lock(&self.inner.state);
        TimerReplayLog::new(state.lifecycle.clone(), state.trace_limits)
    }

    /// Verifies retained timer lifecycle against an expected replay log.
    pub fn verify_replay(&self, expected: &TimerReplayLog) -> Result<(), ReplayError> {
        let mut cursor = expected.replay();
        for event in self.lifecycle_events() {
            let sequence = u64::try_from(cursor.position())
                .map_err(|_| ReplayError::InvalidInput(TraceError::InvalidLimit))?;
            cursor.expect_event(&timer_event_trace(sequence, event))?;
        }
        cursor.finish()
    }

    /// Checks that no timer registrations remain active.
    ///
    /// Explicitly owned handles attempt cancellation on drop; non-owning
    /// handles retain their historical semantics and remain visible here as
    /// active registrations.
    pub fn assert_no_leaks(&self) -> Result<(), TimerLeakError> {
        let state = recover_lock(&self.inner.state);
        if state.drop_cancellation_failures != 0 {
            return Err(TimerLeakError::DropCancellationFailed {
                failures: state.drop_cancellation_failures,
            });
        }
        if !state.active.is_empty() {
            return Err(TimerLeakError::ActiveTimers {
                active: state.active.len(),
            });
        }
        Ok(())
    }

    /// Returns active registrations in deadline/sequence order.
    #[must_use]
    pub fn registrations(&self) -> Vec<TimerRegistration> {
        let state = recover_lock(&self.inner.state);
        let mut registrations = state
            .active
            .iter()
            .map(record_registration)
            .collect::<Vec<_>>();
        registrations.sort_by_key(|registration| (registration.deadline, registration.sequence));
        registrations
    }

    /// Registers a timer at an absolute monotonic deadline.
    pub fn register_at(&self, deadline: MonotonicInstant) -> Result<TimerHandle, TimerError> {
        self.register_at_with_ownership(deadline, false)
    }

    /// Registers an owned timer whose last handle drop attempts cancellation.
    ///
    /// The ordinary [`Self::register_at`] API preserves its historical
    /// non-owning handle semantics.  Use this bounded-owner variant when a
    /// test wants lifecycle cleanup to be automatic and checked with
    /// [`Self::assert_no_leaks`].
    pub fn register_owned_at(&self, deadline: MonotonicInstant) -> Result<TimerHandle, TimerError> {
        self.register_at_with_ownership(deadline, true)
    }

    fn register_at_with_ownership(
        &self,
        deadline: MonotonicInstant,
        owned: bool,
    ) -> Result<TimerHandle, TimerError> {
        let mut state = recover_lock(&self.inner.state);
        if state.active.len() >= state.capacity {
            return Err(TimerError::CapacityExceeded {
                limit: state.capacity,
            });
        }
        let id = TimerId(state.next_id);
        let sequence = state.next_sequence;
        let next_id = state
            .next_id
            .checked_add(1)
            .ok_or(TimerError::SequenceOverflow)?;
        let next_sequence = state
            .next_sequence
            .checked_add(1)
            .ok_or(TimerError::SequenceOverflow)?;
        let registration = TimerRegistration {
            id,
            deadline,
            sequence,
        };
        record_lifecycle(&mut state, TimerLifecycleEvent::Registered(registration))?;
        state.next_id = next_id;
        state.next_sequence = next_sequence;
        let record = Arc::new(Mutex::new(TimerRecord {
            registration,
            state: TimerState::Pending,
        }));
        state.active.push(Arc::clone(&record));
        drop(state);
        self.collect_due();
        Ok(TimerHandle {
            inner: Arc::clone(&self.inner),
            record,
            owned,
        })
    }

    /// Alias for [`FakeSleeper::register_at`].
    pub fn register(&self, deadline: MonotonicInstant) -> Result<TimerHandle, TimerError> {
        self.register_at(deadline)
    }

    /// Registers a timer after a relative delay from the current clock.
    pub fn sleep_for(&self, delay: Duration) -> Result<TimerHandle, TimerError> {
        let now = self.inner.clock.monotonic();
        let deadline = now
            .checked_add(delay)
            .ok_or(TimerError::DeadlineOverflow { delay })?;
        self.register_at(deadline)
    }

    /// Registers an owned timer after a relative delay.
    pub fn sleep_owned_for(&self, delay: Duration) -> Result<TimerHandle, TimerError> {
        let now = self.inner.clock.monotonic();
        let deadline = now
            .checked_add(delay)
            .ok_or(TimerError::DeadlineOverflow { delay })?;
        self.register_owned_at(deadline)
    }

    /// Alias for [`FakeSleeper::sleep_for`].
    pub fn sleep(&self, delay: Duration) -> Result<TimerHandle, TimerError> {
        self.sleep_for(delay)
    }

    /// Advances virtual time and returns all timers that became ready.
    ///
    /// Clock validation and the bounded lifecycle-trace preflight happen
    /// before either the clock or timer readiness changes.  A trace-capacity
    /// error therefore leaves the clock and every ready registration exactly
    /// as they were when this method was called.
    pub fn advance_by(&self, amount: Duration) -> Result<Vec<TimerEvent>, TimerAdvanceError> {
        let current = self.inner.clock.snapshot().monotonic;
        let target =
            current
                .checked_add(amount)
                .ok_or(TimerAdvanceError::Clock(ClockError::Overflow {
                    component: ClockComponent::Monotonic,
                    amount,
                }))?;
        self.advance_to_inner(target)
    }

    /// Advances virtual time to a target and returns newly ready timers.
    ///
    /// Clock validation and the bounded lifecycle-trace preflight happen
    /// before either the clock or timer readiness changes.  A trace-capacity
    /// error therefore leaves the clock and every ready registration exactly
    /// as they were when this method was called.
    pub fn advance_to(
        &self,
        target: MonotonicInstant,
    ) -> Result<Vec<TimerEvent>, TimerAdvanceError> {
        self.advance_to_inner(target)
    }

    /// Collects due timers and consumes at most one ready event.
    #[must_use]
    pub fn poll_ready(&self) -> Option<TimerEvent> {
        match self.poll_ready_checked() {
            Ok(event) => event,
            Err(error) => {
                recover_lock(&self.inner.state).trace_error = Some(error);
                None
            }
        }
    }

    /// Checked variant of [`Self::poll_ready`] that reports trace-capacity
    /// failure without consuming the ready timer.
    pub fn poll_ready_checked(&self) -> Result<Option<TimerEvent>, TimerError> {
        self.collect_due();
        let mut state = recover_lock(&self.inner.state);
        let Some(record) = state.ready.front().cloned() else {
            return Ok(None);
        };
        let registration = record_registration(&record);
        record_lifecycle(&mut state, TimerLifecycleEvent::Consumed(registration))?;
        let _ = state.ready.pop_front();
        let mut record_state = recover_lock(&record);
        record_state.state = TimerState::Consumed;
        state
            .active
            .retain(|candidate| !Arc::ptr_eq(candidate, &record));
        Ok(Some(registration))
    }

    /// Collects and consumes all currently ready timers in deterministic order.
    #[must_use]
    pub fn drain_ready(&self) -> Vec<TimerEvent> {
        let mut events = Vec::new();
        while let Some(event) = self.poll_ready() {
            events.push(event);
        }
        events
    }

    /// Checked variant of [`Self::drain_ready`] that reports bounded trace
    /// failure instead of silently stopping at the first unrecordable wake.
    pub fn drain_ready_checked(&self) -> Result<Vec<TimerEvent>, TimerError> {
        let mut events = Vec::new();
        while let Some(event) = self.poll_ready_checked()? {
            events.push(event);
        }
        Ok(events)
    }

    fn advance_to_inner(
        &self,
        target: MonotonicInstant,
    ) -> Result<Vec<TimerEvent>, TimerAdvanceError> {
        // Hold sleeper state across clock validation, trace-capacity
        // preflight, clock movement, and wake consumption.  A failed
        // preflight therefore cannot leave time advanced with ready events
        // stranded, or consume a subset of a ready queue.
        let mut state = recover_lock(&self.inner.state);
        let plan = preflight_advance_locked(&self.inner.clock, &state, target)?;

        self.inner.clock.advance_to(target)?;
        collect_due_locked(&mut state, target);

        let mut events = Vec::with_capacity(plan.ready_count);
        while let Some(record) = state.ready.pop_front() {
            let registration = record_registration(&record);
            let event = TimerLifecycleEvent::Consumed(registration);
            // `preflight_advance_locked` checked every bound needed by these
            // exact lifecycle events while the state lock was held.  Commit
            // directly so there is no fallible operation after clock advance.
            state.lifecycle.push(event);
            {
                let mut record_state = recover_lock(&record);
                record_state.state = TimerState::Consumed;
            }
            state
                .active
                .retain(|candidate| !Arc::ptr_eq(candidate, &record));
            events.push(registration);
        }
        state.trace_bytes = plan.total_trace_bytes;
        Ok(events)
    }

    /// Cancels a registration through its owning handle.
    ///
    /// `Ok(true)` means a pending registration was cancelled.  Cancelling an
    /// already-ready, consumed, or previously-cancelled timer returns
    /// `Ok(false)`; a handle from another sleeper returns a typed error even
    /// when its numeric identifier collides with a local timer.
    pub fn cancel(&self, handle: &TimerHandle) -> Result<bool, TimerError> {
        let id = handle.id();
        if !Arc::ptr_eq(&self.inner, &handle.inner) {
            return Err(TimerError::UnknownTimer { id });
        }
        let mut state = recover_lock(&self.inner.state);
        let Some(position) = state
            .active
            .iter()
            .position(|record| Arc::ptr_eq(record, &handle.record))
        else {
            return if record_state(&handle.record) == TimerState::Pending {
                Err(TimerError::UnknownTimer { id })
            } else {
                Ok(false)
            };
        };
        let record = Arc::clone(&state.active[position]);
        let cancelled = {
            let mut record_state = recover_lock(&record);
            if record_state.state == TimerState::Pending {
                record_lifecycle(
                    &mut state,
                    TimerLifecycleEvent::Cancelled(record_state.registration),
                )?;
                record_state.state = TimerState::Cancelled;
                true
            } else {
                false
            }
        };
        if cancelled {
            state.active.remove(position);
        }
        Ok(cancelled)
    }

    fn collect_due(&self) {
        let now = self.inner.clock.monotonic();
        let mut state = recover_lock(&self.inner.state);
        collect_due_locked(&mut state, now);
    }
}

struct TimerAdvancePlan {
    ready_count: usize,
    total_trace_bytes: usize,
}

fn preflight_advance_locked(
    clock: &VirtualClock,
    state: &SleeperState,
    target: MonotonicInstant,
) -> Result<TimerAdvancePlan, TimerAdvanceError> {
    let current = clock.snapshot();
    let amount =
        target
            .checked_duration_since(current.monotonic)
            .ok_or(TimerAdvanceError::Clock(ClockError::MovedBackward {
                current: current.monotonic,
                requested: target,
            }))?;
    current
        .monotonic
        .checked_add(amount)
        .ok_or(TimerAdvanceError::Clock(ClockError::Overflow {
            component: ClockComponent::Monotonic,
            amount,
        }))?;
    current
        .wall
        .checked_add(amount)
        .ok_or(TimerAdvanceError::Clock(ClockError::Overflow {
            component: ClockComponent::Wall,
            amount,
        }))?;

    let due = state
        .active
        .iter()
        .filter(|record| {
            let registration = record_registration(record);
            record_state(record) == TimerState::Pending && registration.deadline <= target
        })
        .count();
    let ready_count = state
        .ready
        .len()
        .checked_add(due)
        .ok_or(TimerAdvanceError::Timer(TimerError::TraceCapacity))?;
    let total_events = state
        .lifecycle
        .len()
        .checked_add(ready_count)
        .ok_or(TimerAdvanceError::Timer(TimerError::TraceCapacity))?;
    if total_events > state.trace_limits.max_events {
        return Err(TimerAdvanceError::Timer(TimerError::TraceCapacity));
    }

    let event_bytes = timer_event_bytes(TimerLifecycleEvent::Consumed(TimerRegistration {
        id: TimerId::from_u64(0),
        deadline: MonotonicInstant::ZERO,
        sequence: 0,
    }));
    if ready_count != 0 && event_bytes > state.trace_limits.max_event_bytes {
        return Err(TimerAdvanceError::Timer(TimerError::TraceCapacity));
    }
    let added_bytes = event_bytes
        .checked_mul(ready_count)
        .ok_or(TimerAdvanceError::Timer(TimerError::TraceCapacity))?;
    let total_trace_bytes = state
        .trace_bytes
        .checked_add(added_bytes)
        .ok_or(TimerAdvanceError::Timer(TimerError::TraceCapacity))?;
    if total_trace_bytes > state.trace_limits.max_total_bytes {
        return Err(TimerAdvanceError::Timer(TimerError::TraceCapacity));
    }

    Ok(TimerAdvancePlan {
        ready_count,
        total_trace_bytes,
    })
}

fn collect_due_locked(state: &mut SleeperState, now: MonotonicInstant) {
    let mut newly_ready = Vec::new();
    for record in &state.active {
        let mut record_state = recover_lock(record);
        if record_state.state == TimerState::Pending && record_state.registration.deadline <= now {
            record_state.state = TimerState::Ready;
            newly_ready.push(Arc::clone(record));
        }
    }
    newly_ready.sort_by_key(|record| {
        let registration = record_registration(record);
        (registration.deadline, registration.sequence)
    });
    for record in newly_ready {
        state.ready.push_back(record);
    }
    // A registration can be added after time has already advanced.  The
    // queue remains sorted even when that registration is immediately due.
    let mut ready = state.ready.drain(..).collect::<Vec<_>>();
    ready.sort_by_key(|record| {
        let registration = record_registration(record);
        (registration.deadline, registration.sequence)
    });
    state.ready.extend(ready);
}

/// A cloneable handle for one fake timer registration.
#[derive(Clone, Debug)]
pub struct TimerHandle {
    inner: Arc<SleeperInner>,
    record: Arc<Mutex<TimerRecord>>,
    owned: bool,
}

impl TimerHandle {
    /// Returns this handle's registration details.
    #[must_use]
    pub fn registration(&self) -> TimerRegistration {
        record_registration(&self.record)
    }

    /// Returns this handle's stable identifier.
    #[must_use]
    pub fn id(&self) -> TimerId {
        self.registration().id
    }

    /// Returns the absolute deadline.
    #[must_use]
    pub fn deadline(&self) -> MonotonicInstant {
        self.registration().deadline
    }

    /// Returns the insertion sequence.
    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.registration().sequence
    }

    /// Returns whether this handle owns cancellation-on-drop behavior.
    #[must_use]
    pub const fn is_owned(&self) -> bool {
        self.owned
    }

    /// Returns the current state of this timer.
    #[must_use]
    pub fn state(&self) -> TimerState {
        record_state(&self.record)
    }

    /// Returns whether this timer reached its deadline.  A consumed event is
    /// still considered ready for handle-level assertions.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.state().is_ready()
    }

    /// Cancels this timer if it is still pending.
    ///
    /// Explicitly cancels this timer or reports a bounded trace failure.
    pub fn cancel(&self) -> Result<bool, TimerError> {
        self.inner_owner().cancel(self)
    }

    fn inner_owner(&self) -> FakeSleeper {
        FakeSleeper {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Drop for TimerHandle {
    fn drop(&mut self) {
        // The sleeper's active vector owns one record reference.  For an
        // explicitly owned handle, the last user handle can cancel a pending
        // registration without retaining it past its owner.  Cancellation is
        // best-effort because Drop cannot return a bounded trace error; the
        // owner records that failure for `assert_no_leaks`.
        if !self.owned || Arc::strong_count(&self.record) != 2 {
            return;
        }
        let mut state = recover_lock(&self.inner.state);
        let Some(position) = state
            .active
            .iter()
            .position(|record| Arc::ptr_eq(record, &self.record))
        else {
            return;
        };
        if record_state(&self.record) != TimerState::Pending {
            return;
        }
        let registration = record_registration(&self.record);
        if record_lifecycle(&mut state, TimerLifecycleEvent::Cancelled(registration)).is_err() {
            state.drop_cancellation_failures = state.drop_cancellation_failures.saturating_add(1);
            state.trace_error = Some(TimerError::TraceCapacity);
            return;
        }
        {
            let mut record_state = recover_lock(&self.record);
            record_state.state = TimerState::Cancelled;
        }
        state.active.remove(position);
    }
}

fn record_registration(record: &Arc<Mutex<TimerRecord>>) -> TimerRegistration {
    recover_lock(record).registration
}

fn record_state(record: &Arc<Mutex<TimerRecord>>) -> TimerState {
    recover_lock(record).state
}

fn timer_trace_limits(capacity: usize) -> TraceLimits {
    let max_events = capacity.saturating_mul(4).max(1);
    TraceLimits::new(max_events, 64, max_events.saturating_mul(64))
}

fn record_lifecycle(
    state: &mut SleeperState,
    event: TimerLifecycleEvent,
) -> Result<(), TimerError> {
    let event_bytes = timer_event_bytes(event);
    let event_count = state
        .lifecycle
        .len()
        .checked_add(1)
        .ok_or(TimerError::TraceCapacity)?;
    let total_bytes = state
        .trace_bytes
        .checked_add(event_bytes)
        .ok_or(TimerError::TraceCapacity)?;
    if event_count > state.trace_limits.max_events
        || event_bytes > state.trace_limits.max_event_bytes
        || total_bytes > state.trace_limits.max_total_bytes
    {
        return Err(TimerError::TraceCapacity);
    }
    state.lifecycle.push(event);
    state.trace_bytes = total_bytes;
    Ok(())
}

fn timer_event_bytes(event: TimerLifecycleEvent) -> usize {
    let kind_bytes = match event {
        TimerLifecycleEvent::Registered(_) => "timer.registered".len(),
        TimerLifecycleEvent::Cancelled(_) => "timer.cancelled".len(),
        TimerLifecycleEvent::Consumed(_) => "timer.consumed".len(),
    };
    kind_bytes + std::mem::size_of::<u64>() * 3 + std::mem::size_of::<u32>()
}

fn timer_event_trace(sequence: u64, event: TimerLifecycleEvent) -> TraceEvent {
    let (kind, registration) = match event {
        TimerLifecycleEvent::Registered(registration) => ("timer.registered", registration),
        TimerLifecycleEvent::Cancelled(registration) => ("timer.cancelled", registration),
        TimerLifecycleEvent::Consumed(registration) => ("timer.consumed", registration),
    };
    let duration = registration.deadline.as_duration();
    let mut payload = Vec::with_capacity(36);
    payload.extend_from_slice(&registration.id.get().to_le_bytes());
    payload.extend_from_slice(&duration.as_secs().to_le_bytes());
    payload.extend_from_slice(&duration.subsec_nanos().to_le_bytes());
    payload.extend_from_slice(&registration.sequence.to_le_bytes());
    TraceEvent::new(sequence, kind, payload)
}

#[cfg(test)]
mod tests {
    // Test fixtures use unwrap to keep the assertion setup concise; every
    // value is deliberately within the bounds being tested.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn clock_advances_wall_and_monotonic_together() {
        let clock = VirtualClock::new(
            WallTime::from_unix_duration(Duration::from_secs(10)).unwrap(),
            MonotonicInstant::from_duration(Duration::from_secs(4)),
        );
        let snapshot = clock.advance(Duration::from_millis(250)).unwrap();
        assert_eq!(
            snapshot.monotonic.as_duration(),
            Duration::from_secs(4) + Duration::from_millis(250)
        );
        assert_eq!(
            snapshot.wall.checked_duration_since(WallTime::UNIX_EPOCH),
            Some(Duration::from_secs(10) + Duration::from_millis(250))
        );
    }

    #[test]
    fn wall_adjustment_does_not_change_monotonic_elapsed_time() {
        let clock = VirtualClock::new(
            WallTime::from_unix_duration(Duration::from_secs(20)).unwrap(),
            MonotonicInstant::from_duration(Duration::from_secs(3)),
        );
        let before = clock.snapshot();
        let adjusted =
            clock.set_wall_time(WallTime::from_unix_duration(Duration::from_secs(5)).unwrap());

        assert_eq!(adjusted.monotonic, before.monotonic);
        assert_eq!(
            adjusted.wall,
            WallTime::from_unix_duration(Duration::from_secs(5)).unwrap()
        );
        assert_eq!(adjusted.checked_duration_since(before), Ok(Duration::ZERO));

        let after = clock.advance(Duration::from_secs(2)).unwrap();
        assert_eq!(
            after.wall.checked_duration_since(adjusted.wall),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            after.monotonic.checked_duration_since(adjusted.monotonic),
            Some(Duration::from_secs(2))
        );
    }

    #[test]
    fn progress_observation_distinguishes_quiescence_stall_and_reversal() {
        let clock = VirtualClock::at_epoch();
        let first = clock.snapshot();
        assert_eq!(clock.observe(first, false), Ok(Some(first)));
        assert_eq!(clock.observe(first, true), Ok(None));

        clock.advance(Duration::from_secs(1)).unwrap();
        let second = clock.snapshot();
        assert_eq!(clock.observe(first, true), Ok(Some(second)));

        clock.set_unchecked(ClockSnapshot {
            wall: second.wall,
            monotonic: MonotonicInstant::from_duration(Duration::from_millis(500)),
        });
        assert_eq!(
            clock.observe(second, true),
            Err(ClockError::MovedBackward {
                current: second.monotonic,
                requested: MonotonicInstant::from_duration(Duration::from_millis(500)),
            })
        );
    }

    #[test]
    fn clock_rejects_backwards_target_without_mutation() {
        let clock = VirtualClock::at_epoch();
        clock.advance(Duration::from_secs(2)).unwrap();
        let before = clock.snapshot();
        let error = clock
            .advance_to(MonotonicInstant::from_duration(Duration::from_secs(1)))
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::ClockMovedBackward);
        assert_eq!(clock.snapshot(), before);
    }

    #[test]
    fn clock_overflow_is_checked_for_both_components() {
        let clock = VirtualClock::new(
            WallTime::UNIX_EPOCH,
            MonotonicInstant::from_duration(Duration::MAX),
        );
        let before = clock.snapshot();
        let error = clock.advance(Duration::from_nanos(1)).unwrap_err();
        assert_eq!(error.code(), ErrorCode::ClockOverflow);
        assert_eq!(clock.snapshot(), before);
    }

    #[test]
    fn unchecked_fault_injection_does_not_bypass_checked_advance() {
        let clock = VirtualClock::at_epoch();
        clock.set_unchecked(ClockSnapshot {
            wall: WallTime::UNIX_EPOCH,
            monotonic: MonotonicInstant::from_duration(Duration::from_secs(4)),
        });
        let before = clock.snapshot();
        assert_eq!(
            clock.advance_to(MonotonicInstant::from_duration(Duration::from_secs(3))),
            Err(ClockError::MovedBackward {
                current: before.monotonic,
                requested: MonotonicInstant::from_duration(Duration::from_secs(3)),
            })
        );
        assert_eq!(clock.snapshot(), before);
    }

    #[test]
    fn advance_to_wall_overflow_is_atomic() {
        let near_max = SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(i64::MAX as u64))
            .unwrap();
        let clock = VirtualClock::new(WallTime::from_system_time(near_max), MonotonicInstant::ZERO);
        let before = clock.snapshot();
        let error = clock
            .advance_to(MonotonicInstant::from_duration(Duration::from_secs(1)))
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::ClockOverflow);
        assert_eq!(clock.snapshot(), before);
    }

    #[test]
    fn equal_deadlines_are_returned_by_registration_sequence() {
        let sleeper = FakeSleeper::new(VirtualClock::at_epoch(), 8);
        let first = sleeper.sleep_for(Duration::from_secs(2)).unwrap();
        let second = sleeper.sleep_for(Duration::from_secs(2)).unwrap();
        let third = sleeper.sleep_for(Duration::from_secs(1)).unwrap();
        let events = sleeper.advance_by(Duration::from_secs(2)).unwrap();
        assert_eq!(
            events,
            vec![
                third.registration(),
                first.registration(),
                second.registration()
            ]
        );
    }

    #[test]
    fn cancelling_pending_timer_removes_it_and_ready_timer_cannot_be_cancelled() {
        let sleeper = FakeSleeper::new(VirtualClock::at_epoch(), 4);
        let cancelled = sleeper.sleep_for(Duration::from_secs(1)).unwrap();
        assert!(cancelled.cancel().unwrap());
        assert_eq!(cancelled.state(), TimerState::Cancelled);
        assert_eq!(sleeper.registered_count(), 0);

        let ready = sleeper.sleep_for(Duration::from_secs(1)).unwrap();
        sleeper.advance_by(Duration::from_secs(1)).unwrap();
        assert_eq!(ready.state(), TimerState::Consumed);
        assert!(!ready.cancel().unwrap());
    }

    #[test]
    fn direct_clock_advance_requires_explicit_poll_and_cancel_wins_before_wake() {
        let clock = VirtualClock::at_epoch();
        let sleeper = FakeSleeper::new(clock.clone(), 2);
        let timer = sleeper.sleep_for(Duration::from_secs(1)).unwrap();

        clock.advance(Duration::from_secs(1)).unwrap();
        assert_eq!(timer.state(), TimerState::Pending);
        assert_eq!(sleeper.ready_count(), 0);
        assert!(timer.cancel().unwrap());
        assert_eq!(timer.state(), TimerState::Cancelled);
        assert_eq!(sleeper.poll_ready(), None);
        assert_eq!(sleeper.registered_count(), 0);
    }

    #[test]
    fn direct_clock_advance_then_poll_preserves_deadline_and_sequence_order() {
        let clock = VirtualClock::at_epoch();
        let sleeper = FakeSleeper::new(clock.clone(), 4);
        let later = sleeper.sleep_for(Duration::from_secs(2)).unwrap();
        let earlier = sleeper.sleep_for(Duration::from_secs(1)).unwrap();

        clock.advance(Duration::from_secs(2)).unwrap();
        assert_eq!(
            sleeper.drain_ready(),
            vec![earlier.registration(), later.registration()]
        );
        assert_eq!(
            sleeper.clock().snapshot().monotonic,
            MonotonicInstant::from_duration(Duration::from_secs(2))
        );
    }

    #[test]
    fn timer_capacity_and_deadline_overflow_are_bounded() {
        let clock = VirtualClock::new(
            WallTime::UNIX_EPOCH,
            MonotonicInstant::from_duration(Duration::MAX),
        );
        let sleeper = FakeSleeper::new(clock, 1);
        let error = sleeper.sleep_for(Duration::from_nanos(1)).unwrap_err();
        assert_eq!(error.code(), ErrorCode::TimerDeadlineOverflow);

        let sleeper = FakeSleeper::new(VirtualClock::at_epoch(), 1);
        let _timer = sleeper.sleep_for(Duration::ZERO).unwrap();
        let error = sleeper.sleep_for(Duration::ZERO).unwrap_err();
        assert_eq!(error.code(), ErrorCode::TimerCapacity);
    }

    #[test]
    fn timer_sequence_overflow_does_not_mutate_queue() {
        let sleeper = FakeSleeper::new(VirtualClock::at_epoch(), 2);
        {
            let mut state = recover_lock(&sleeper.inner.state);
            state.next_sequence = u64::MAX;
        }
        let error = sleeper.sleep_for(Duration::ZERO).unwrap_err();
        assert_eq!(error.code(), ErrorCode::TimerSequenceOverflow);
        assert_eq!(sleeper.registered_count(), 0);
    }

    #[test]
    fn cloned_sleeper_shares_queue_and_clock() {
        let sleeper = FakeSleeper::new(VirtualClock::at_epoch(), 2);
        let clone = sleeper.clone();
        let timer = clone.sleep_for(Duration::from_secs(3)).unwrap();
        assert_eq!(
            sleeper.advance_by(Duration::from_secs(3)).unwrap(),
            vec![timer.registration()]
        );
    }

    #[test]
    fn dropping_a_timer_handle_is_explicitly_non_cancelling() {
        let sleeper = FakeSleeper::new(VirtualClock::at_epoch(), 2);
        let timer = sleeper.sleep_for(Duration::from_secs(1)).unwrap();
        let id = timer.id();
        drop(timer);
        assert_eq!(sleeper.pending_count(), 1);
        assert_eq!(
            sleeper.advance_by(Duration::from_secs(1)).unwrap()[0].id,
            id
        );
    }

    #[test]
    fn cancellation_is_owner_scoped_when_timer_ids_collide() {
        let first = FakeSleeper::new(VirtualClock::at_epoch(), 2);
        let second = FakeSleeper::new(VirtualClock::at_epoch(), 2);
        let first_timer = first.sleep_for(Duration::from_secs(1)).unwrap();
        let second_timer = second.sleep_for(Duration::from_secs(1)).unwrap();
        assert_eq!(first_timer.id(), second_timer.id());

        assert_eq!(
            first.cancel(&second_timer).unwrap_err().code(),
            ErrorCode::TimerUnknown
        );
        assert_eq!(second_timer.state(), TimerState::Pending);
        assert!(first.cancel(&first_timer).unwrap());
        assert!(!first_timer.cancel().unwrap());
    }

    #[test]
    fn owned_timer_drop_cancels_and_releases_capacity() {
        let sleeper = FakeSleeper::new(VirtualClock::at_epoch(), 1);
        let timer = sleeper.sleep_owned_for(Duration::from_secs(1)).unwrap();
        assert!(timer.is_owned());
        drop(timer);
        assert_eq!(sleeper.pending_count(), 0);
        sleeper.assert_no_leaks().unwrap();
        let replacement = sleeper.sleep_for(Duration::ZERO).unwrap();
        assert_eq!(replacement.state(), TimerState::Ready);
    }

    #[test]
    fn owned_timer_drop_failure_is_reported_as_a_leak() {
        let sleeper = FakeSleeper::with_trace_limits(
            VirtualClock::at_epoch(),
            1,
            TraceLimits::new(1, 64, 64),
        );
        let timer = sleeper.sleep_owned_for(Duration::from_secs(1)).unwrap();
        drop(timer);
        assert_eq!(
            sleeper.assert_no_leaks().unwrap_err(),
            TimerLeakError::DropCancellationFailed { failures: 1 }
        );
        assert_eq!(sleeper.registered_count(), 1);
    }

    #[test]
    fn timer_replay_records_register_cancel_and_consumed_order() {
        let sleeper = FakeSleeper::with_trace_limits(
            VirtualClock::at_epoch(),
            2,
            TraceLimits::new(8, 64, 512),
        );
        let cancelled = sleeper.sleep_for(Duration::from_secs(2)).unwrap();
        assert!(cancelled.cancel().unwrap());
        let consumed = sleeper.sleep_for(Duration::from_secs(1)).unwrap();
        sleeper.advance_by(Duration::from_secs(1)).unwrap();
        let log = sleeper.replay_log().unwrap();
        assert_eq!(
            log.events(),
            &[
                TimerLifecycleEvent::Registered(cancelled.registration()),
                TimerLifecycleEvent::Cancelled(cancelled.registration()),
                TimerLifecycleEvent::Registered(consumed.registration()),
                TimerLifecycleEvent::Consumed(consumed.registration()),
            ]
        );
        sleeper.verify_replay(&log).unwrap();
    }

    #[test]
    fn timer_trace_capacity_does_not_consume_ready_event() {
        let sleeper = FakeSleeper::with_trace_limits(
            VirtualClock::at_epoch(),
            1,
            TraceLimits::new(1, 64, 64),
        );
        let timer = sleeper.sleep_for(Duration::ZERO).unwrap();
        assert_eq!(sleeper.poll_ready(), None);
        assert_eq!(timer.state(), TimerState::Ready);
        assert_eq!(sleeper.trace_error(), Some(TimerError::TraceCapacity));
    }

    #[test]
    fn advance_by_trace_capacity_is_explicit_and_atomic() {
        let sleeper = FakeSleeper::with_trace_limits(
            VirtualClock::at_epoch(),
            2,
            TraceLimits::new(2, 64, 128),
        );
        let first = sleeper.sleep_for(Duration::ZERO).unwrap();
        let second = sleeper.sleep_for(Duration::ZERO).unwrap();
        let before = sleeper.clock().snapshot();

        let error = sleeper.advance_by(Duration::ZERO).unwrap_err();
        assert_eq!(error, TimerAdvanceError::Timer(TimerError::TraceCapacity));
        assert_eq!(sleeper.clock().snapshot(), before);
        assert_eq!(sleeper.ready_count(), 2);
        assert_eq!(first.state(), TimerState::Ready);
        assert_eq!(second.state(), TimerState::Ready);
        assert_eq!(sleeper.lifecycle_events().len(), 2);
    }

    #[test]
    fn advance_to_trace_capacity_is_explicit_and_atomic() {
        let sleeper = FakeSleeper::with_trace_limits(
            VirtualClock::at_epoch(),
            1,
            TraceLimits::new(1, 64, 64),
        );
        let timer = sleeper.sleep_for(Duration::from_secs(1)).unwrap();
        let before = sleeper.clock().snapshot();

        let error = sleeper
            .advance_to(MonotonicInstant::from_duration(Duration::from_secs(1)))
            .unwrap_err();
        assert_eq!(error, TimerAdvanceError::Timer(TimerError::TraceCapacity));
        assert_eq!(sleeper.clock().snapshot(), before);
        assert_eq!(sleeper.pending_count(), 1);
        assert_eq!(sleeper.ready_count(), 0);
        assert_eq!(timer.state(), TimerState::Pending);
        assert_eq!(sleeper.lifecycle_events().len(), 1);
    }

    #[test]
    fn timer_trace_total_bytes_use_each_event_size() {
        let sleeper = FakeSleeper::with_trace_limits(
            VirtualClock::at_epoch(),
            1,
            TraceLimits::new(2, 64, 86),
        );
        let timer = sleeper.sleep_for(Duration::from_secs(1)).unwrap();
        assert_eq!(sleeper.lifecycle_events().len(), 1);
        assert_eq!(timer.cancel().unwrap_err(), TimerError::TraceCapacity);
        assert_eq!(sleeper.lifecycle_events().len(), 1);
        assert_eq!(timer.state(), TimerState::Pending);
    }
}
