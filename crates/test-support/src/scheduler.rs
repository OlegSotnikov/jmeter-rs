// SPDX-License-Identifier: Apache-2.0
//! A bounded, executor-neutral scheduler for deterministic tests.
//!
//! The scheduler only orders logical wake-ups.  It never creates a thread,
//! polls a future, reads the host clock, or sleeps the caller.  A test advances
//! the supplied [`VirtualClock`] explicitly and consumes ready registrations
//! through [`DeterministicScheduler::poll_ready`] or
//! [`DeterministicScheduler::drain_ready`].  Lifecycle events can be encoded
//! into a bounded replay log, and [`DeterministicScheduler::run_with_watchdog`]
//! provides finite deadlock, starvation, and runaway checks for small models.

use crate::clock::{ClockComponent, ClockError, MonotonicInstant, VirtualClock};
use crate::error::{ErrorCode, StableError};
use crate::trace::{ReplayCursor, ReplayError, ReplayLog, TraceError, TraceEvent, TraceLimits};
use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Bounds for active logical tasks and retained scheduler events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchedulerLimits {
    /// Maximum number of pending or ready tasks retained at once.
    pub max_tasks: usize,
    /// Maximum number of schedule, wake, and cancellation events retained.
    pub max_events: usize,
}

impl SchedulerLimits {
    /// Creates explicit finite bounds.
    #[must_use]
    pub const fn new(max_tasks: usize, max_events: usize) -> Self {
        Self {
            max_tasks,
            max_events,
        }
    }

    /// A useful finite default for unit and integration tests.
    #[must_use]
    pub const fn default_bounded() -> Self {
        Self::new(1_024, 16_384)
    }
}

impl Default for SchedulerLimits {
    fn default() -> Self {
        Self::default_bounded()
    }
}

/// Stable identifier assigned to a scheduled logical task.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaskId(u64);

impl TaskId {
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

/// Immutable details assigned when a task is registered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScheduledTask {
    /// The task identifier.
    pub id: TaskId,
    /// The virtual monotonic deadline.
    pub deadline: MonotonicInstant,
    /// The stable key used before insertion order for equal deadlines.
    pub key: u64,
    /// The insertion sequence used as the final tie-breaker.
    pub sequence: u64,
}

/// A task wake-up or lifecycle event retained by the scheduler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedulerEvent {
    /// A task was registered.
    Scheduled(ScheduledTask),
    /// A ready task was consumed by the caller.
    Woken(ScheduledTask),
    /// A pending task was cancelled.
    Cancelled(ScheduledTask),
}

/// A validated replay stream for deterministic scheduler lifecycle events.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerReplayLog {
    scheduler_events: Vec<SchedulerEvent>,
    trace: ReplayLog,
}

impl SchedulerReplayLog {
    /// Builds a replay log from an ordered scheduler event snapshot.
    pub fn new(
        scheduler_events: Vec<SchedulerEvent>,
        max_events: usize,
    ) -> Result<Self, TraceError> {
        let trace_events = scheduler_events
            .iter()
            .enumerate()
            .map(|(sequence, event)| {
                u64::try_from(sequence)
                    .map(|sequence| scheduler_event_trace(sequence, *event))
                    .map_err(|_| TraceError::InvalidLimit)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let max_total_bytes = max_events.saturating_mul(64);
        let trace = ReplayLog::new(
            trace_events,
            TraceLimits::new(max_events, 64, max_total_bytes),
        )?;
        Ok(Self {
            scheduler_events,
            trace,
        })
    }

    /// Returns the original ordered scheduler events.
    #[must_use]
    pub fn events(&self) -> &[SchedulerEvent] {
        &self.scheduler_events
    }

    /// Returns the encoded bounded trace events.
    #[must_use]
    pub fn trace_events(&self) -> &[TraceEvent] {
        self.trace.events()
    }

    /// Returns the number of scheduler events in the replay stream.
    #[must_use]
    pub fn len(&self) -> usize {
        self.scheduler_events.len()
    }

    /// Returns whether the replay stream is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.scheduler_events.is_empty()
    }

    /// Starts a replay cursor over the encoded event stream.
    #[must_use]
    pub fn replay(&self) -> ReplayCursor {
        self.trace.replay()
    }
}

impl SchedulerEvent {
    /// Returns the task associated with this event.
    #[must_use]
    pub const fn task(self) -> ScheduledTask {
        match self {
            Self::Scheduled(task) | Self::Woken(task) | Self::Cancelled(task) => task,
        }
    }
}

/// The state of a logical task registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedulerTaskState {
    /// The deadline has not been reached.
    Pending,
    /// The deadline has been reached but the wake has not been consumed.
    Ready,
    /// The task was cancelled before its wake was consumed.
    Cancelled,
    /// The wake was consumed by the caller.
    Consumed,
}

impl SchedulerTaskState {
    /// Returns whether the task can still be cancelled.
    #[must_use]
    pub const fn is_pending(self) -> bool {
        matches!(self, Self::Pending)
    }

    /// Returns whether the task is eligible for consumption or was consumed.
    #[must_use]
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Ready | Self::Consumed)
    }
}

/// Errors returned by bounded scheduler operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedulerError {
    /// The active-task bound was reached.
    CapacityExceeded {
        /// Configured active-task bound.
        limit: usize,
    },
    /// The retained event-log bound was reached.
    EventCapacityExceeded {
        /// Configured event-log bound.
        limit: usize,
    },
    /// A relative deadline could not be represented.
    DeadlineOverflow {
        /// Requested relative delay.
        delay: Duration,
    },
    /// A task identifier or insertion sequence could not be incremented.
    SequenceOverflow,
    /// A task identifier is not owned by this scheduler or is no longer active.
    UnknownTask {
        /// Missing task identifier.
        id: TaskId,
    },
}

impl SchedulerError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> ErrorCode {
        match self {
            Self::CapacityExceeded { .. } => ErrorCode::SchedulerCapacity,
            Self::EventCapacityExceeded { .. } => ErrorCode::SchedulerEventCapacity,
            Self::DeadlineOverflow { .. } => ErrorCode::SchedulerDeadlineOverflow,
            Self::SequenceOverflow => ErrorCode::SchedulerSequenceOverflow,
            Self::UnknownTask { .. } => ErrorCode::SchedulerUnknownTask,
        }
    }
}

impl fmt::Display for SchedulerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityExceeded { limit } => {
                write!(
                    formatter,
                    "{}: active task capacity is {limit}",
                    self.code()
                )
            }
            Self::EventCapacityExceeded { limit } => {
                write!(formatter, "{}: event capacity is {limit}", self.code())
            }
            Self::DeadlineOverflow { delay } => write!(
                formatter,
                "{}: relative delay {delay:?} overflows the virtual clock",
                self.code()
            ),
            Self::SequenceOverflow => write!(formatter, "{}: task sequence overflow", self.code()),
            Self::UnknownTask { id } => {
                write!(formatter, "{}: unknown task {}", self.code(), id.get())
            }
        }
    }
}

impl std::error::Error for SchedulerError {}

impl StableError for SchedulerError {
    fn code(&self) -> ErrorCode {
        (*self).code()
    }
}

/// Errors returned by explicit scheduler-owner leak checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedulerLeakError {
    /// Tasks remain active after their handles were dropped.
    ActiveTasks {
        /// Number of pending or ready tasks retained by the scheduler.
        active: usize,
    },
    /// Drop cancellation could not append its bounded cancellation event.
    DropCancellationFailed {
        /// Number of failed best-effort drop cancellations.
        failures: usize,
    },
}

impl SchedulerLeakError {
    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> ErrorCode {
        ErrorCode::SchedulerLeak
    }
}

impl fmt::Display for SchedulerLeakError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ActiveTasks { active } => {
                write!(formatter, "{}: {active} active task(s)", self.code())
            }
            Self::DropCancellationFailed { failures } => write!(
                formatter,
                "{}: {failures} task drop cancellation(s) could not be recorded",
                self.code()
            ),
        }
    }
}

impl std::error::Error for SchedulerLeakError {}

impl StableError for SchedulerLeakError {
    fn code(&self) -> ErrorCode {
        SchedulerLeakError::code(*self)
    }
}

/// Errors returned while advancing time and draining scheduler wake-ups.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedulerAdvanceError {
    /// The virtual clock rejected the requested movement.
    Clock(ClockError),
    /// The scheduler could not retain or consume a wake event.
    Scheduler(SchedulerError),
}

impl SchedulerAdvanceError {
    /// Returns the underlying stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> ErrorCode {
        match self {
            Self::Clock(error) => error.code(),
            Self::Scheduler(error) => error.code(),
        }
    }
}

impl fmt::Display for SchedulerAdvanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clock(error) => error.fmt(formatter),
            Self::Scheduler(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for SchedulerAdvanceError {}

impl StableError for SchedulerAdvanceError {
    fn code(&self) -> ErrorCode {
        (*self).code()
    }
}

impl From<ClockError> for SchedulerAdvanceError {
    fn from(error: ClockError) -> Self {
        Self::Clock(error)
    }
}

impl From<SchedulerError> for SchedulerAdvanceError {
    fn from(error: SchedulerError) -> Self {
        Self::Scheduler(error)
    }
}

/// Finite budgets for a deterministic scheduler watchdog run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchedulerWatchdogLimits {
    /// Maximum wake callbacks processed.
    pub max_steps: usize,
    /// Maximum logical task registrations observed after watchdog entry.
    pub max_task_creations: u64,
    /// Maximum consecutive blocked callbacks while ready work remains.
    pub max_ready_wait_steps: usize,
}

impl SchedulerWatchdogLimits {
    /// Creates explicit finite watchdog budgets.
    #[must_use]
    pub const fn new(
        max_steps: usize,
        max_task_creations: u64,
        max_ready_wait_steps: usize,
    ) -> Self {
        Self {
            max_steps,
            max_task_creations,
            max_ready_wait_steps,
        }
    }

    /// A useful finite watchdog budget for small deterministic models.
    #[must_use]
    pub const fn default_bounded() -> Self {
        Self::new(16_384, 4_096, 16)
    }
}

impl Default for SchedulerWatchdogLimits {
    fn default() -> Self {
        Self::default_bounded()
    }
}

/// Outcome reported by a wake callback to the deterministic watchdog.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedulerWakeOutcome {
    /// The callback made logical progress.
    Progress,
    /// The callback cannot progress without another logical event.
    Blocked,
}

/// A bounded watchdog result after a scheduler reaches quiescence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchedulerWatchdogReport {
    /// Number of wake callbacks processed.
    pub steps: usize,
    /// Number of logical task registrations made after watchdog entry.
    pub task_creations: u64,
    /// Number of callbacks that reported blocked state at termination.
    pub blocked_tasks: usize,
}

/// Errors produced by deterministic deadlock, starvation, and runaway checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchedulerWatchdogError {
    /// The callback reported a blocked task and no logical event can wake it.
    Deadlock {
        /// Number of blocked callbacks retained by the watchdog.
        blocked_tasks: usize,
    },
    /// Ready work remained unserved for the configured finite budget.
    Starvation {
        /// Number of ready tasks still waiting.
        ready_tasks: usize,
        /// Number of blocked observations while ready work remained.
        waited_steps: usize,
        /// Configured wait budget.
        limit: usize,
    },
    /// Logical task creation exceeded the configured finite budget.
    Runaway {
        /// Number of registrations observed.
        task_creations: u64,
        /// Configured creation budget.
        limit: u64,
    },
    /// Wake processing exceeded the configured finite budget.
    StepLimit {
        /// Number of callbacks already processed.
        steps: usize,
        /// Configured step budget.
        limit: usize,
    },
    /// The scheduler could not consume a ready event.
    Scheduler(SchedulerError),
    /// The virtual clock rejected a deterministic advance.
    Clock(ClockError),
    /// The scheduler event snapshot could not be encoded for replay.
    Replay(TraceError),
}

impl SchedulerWatchdogError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Deadlock { .. } => ErrorCode::SchedulerDeadlock,
            Self::Starvation { .. } => ErrorCode::SchedulerStarvation,
            Self::Runaway { .. } => ErrorCode::SchedulerRunaway,
            Self::StepLimit { .. } => ErrorCode::SchedulerWatchdogLimit,
            Self::Scheduler(error) => (*error).code(),
            Self::Clock(error) => (*error).code(),
            Self::Replay(error) => (*error).code(),
        }
    }
}

impl fmt::Display for SchedulerWatchdogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deadlock { blocked_tasks } => write!(
                formatter,
                "{}: {blocked_tasks} blocked task(s) have no logical wake",
                self.code()
            ),
            Self::Starvation {
                ready_tasks,
                waited_steps,
                limit,
            } => write!(
                formatter,
                "{}: {ready_tasks} ready task(s) waited {waited_steps} step(s), limit {limit}",
                self.code()
            ),
            Self::Runaway {
                task_creations,
                limit,
            } => write!(
                formatter,
                "{}: task creations {task_creations} exceed {limit}",
                self.code()
            ),
            Self::StepLimit { steps, limit } => {
                write!(
                    formatter,
                    "{}: watchdog steps {steps} exceed {limit}",
                    self.code()
                )
            }
            Self::Scheduler(error) => error.fmt(formatter),
            Self::Clock(error) => error.fmt(formatter),
            Self::Replay(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for SchedulerWatchdogError {}

impl StableError for SchedulerWatchdogError {
    fn code(&self) -> ErrorCode {
        self.code()
    }
}

impl From<SchedulerError> for SchedulerWatchdogError {
    fn from(error: SchedulerError) -> Self {
        Self::Scheduler(error)
    }
}

impl From<ClockError> for SchedulerWatchdogError {
    fn from(error: ClockError) -> Self {
        Self::Clock(error)
    }
}

impl From<TraceError> for SchedulerWatchdogError {
    fn from(error: TraceError) -> Self {
        Self::Replay(error)
    }
}

impl From<SchedulerAdvanceError> for SchedulerWatchdogError {
    fn from(error: SchedulerAdvanceError) -> Self {
        match error {
            SchedulerAdvanceError::Clock(error) => Self::Clock(error),
            SchedulerAdvanceError::Scheduler(error) => Self::Scheduler(error),
        }
    }
}

#[derive(Debug)]
struct TaskRecord {
    task: ScheduledTask,
    state: SchedulerTaskState,
}

#[derive(Debug)]
struct SchedulerState {
    limits: SchedulerLimits,
    next_id: u64,
    next_sequence: u64,
    active: Vec<Arc<Mutex<TaskRecord>>>,
    ready: VecDeque<Arc<Mutex<TaskRecord>>>,
    events: Vec<SchedulerEvent>,
    drop_cancellation_failures: usize,
}

#[derive(Debug)]
struct SchedulerInner {
    clock: VirtualClock,
    state: Mutex<SchedulerState>,
}

/// A cloneable deterministic scheduler backed by a virtual clock.
#[derive(Clone, Debug)]
pub struct DeterministicScheduler {
    inner: Arc<SchedulerInner>,
}

impl DeterministicScheduler {
    /// Creates a scheduler with explicit active-task and event-log bounds.
    #[must_use]
    pub fn new(clock: VirtualClock, limits: SchedulerLimits) -> Self {
        Self {
            inner: Arc::new(SchedulerInner {
                clock,
                state: Mutex::new(SchedulerState {
                    limits,
                    next_id: 0,
                    next_sequence: 0,
                    active: Vec::new(),
                    ready: VecDeque::new(),
                    events: Vec::new(),
                    drop_cancellation_failures: 0,
                }),
            }),
        }
    }

    /// Creates a scheduler at epoch/zero with default finite bounds.
    #[must_use]
    pub fn at_epoch() -> Self {
        Self::new(VirtualClock::at_epoch(), SchedulerLimits::default())
    }

    /// Returns a clone sharing clock, registrations, and event history.
    #[must_use]
    pub fn shared(&self) -> Self {
        self.clone()
    }

    /// Returns the associated virtual clock.
    #[must_use]
    pub fn clock(&self) -> VirtualClock {
        self.inner.clock.clone()
    }

    /// Returns configured bounds.
    #[must_use]
    pub fn limits(&self) -> SchedulerLimits {
        recover_lock(&self.inner.state).limits
    }

    /// Returns the number of active (pending or ready) tasks.
    #[must_use]
    pub fn registered_count(&self) -> usize {
        recover_lock(&self.inner.state).active.len()
    }

    /// Returns the number of pending tasks.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        let state = recover_lock(&self.inner.state);
        state
            .active
            .iter()
            .filter(|record| record_state(record) == SchedulerTaskState::Pending)
            .count()
    }

    /// Returns the number of ready tasks waiting to be consumed.
    #[must_use]
    pub fn ready_count(&self) -> usize {
        recover_lock(&self.inner.state).ready.len()
    }

    /// Returns the number of active task registrations.
    #[must_use]
    pub fn active_task_count(&self) -> usize {
        self.registered_count()
    }

    /// Checks the bounded owner invariant for task handles.
    ///
    /// An explicitly owned dropped last handle attempts safe cancellation.
    /// Non-owning handles retain their historical semantics and remain visible
    /// here as active tasks.  If the event log is full, the failed attempt is
    /// retained as a diagnostic so tests cannot silently accept a leak.
    pub fn assert_no_leaks(&self) -> Result<(), SchedulerLeakError> {
        let state = recover_lock(&self.inner.state);
        if state.drop_cancellation_failures != 0 {
            return Err(SchedulerLeakError::DropCancellationFailed {
                failures: state.drop_cancellation_failures,
            });
        }
        if !state.active.is_empty() {
            return Err(SchedulerLeakError::ActiveTasks {
                active: state.active.len(),
            });
        }
        Ok(())
    }

    /// Cancels every pending task in one bounded owner operation.
    ///
    /// The operation preflights the complete cancellation event count, so a
    /// full event log leaves all task state unchanged.
    pub fn cancel_all(&self) -> Result<usize, SchedulerError> {
        let mut state = recover_lock(&self.inner.state);
        let pending = state
            .active
            .iter()
            .filter(|record| record_state(record) == SchedulerTaskState::Pending)
            .count();
        let total = state.events.len().checked_add(pending).ok_or(
            SchedulerError::EventCapacityExceeded {
                limit: state.limits.max_events,
            },
        )?;
        if total > state.limits.max_events {
            return Err(SchedulerError::EventCapacityExceeded {
                limit: state.limits.max_events,
            });
        }
        let mut cancelled_tasks = Vec::with_capacity(pending);
        for record in &state.active {
            let mut task_state = recover_lock(record);
            if task_state.state == SchedulerTaskState::Pending {
                task_state.state = SchedulerTaskState::Cancelled;
                cancelled_tasks.push(task_state.task);
            }
        }
        for task in &cancelled_tasks {
            state.events.push(SchedulerEvent::Cancelled(*task));
        }
        state
            .active
            .retain(|record| record_state(record) != SchedulerTaskState::Cancelled);
        Ok(cancelled_tasks.len())
    }

    /// Returns a snapshot of active registrations in wake order.
    #[must_use]
    pub fn registrations(&self) -> Vec<ScheduledTask> {
        let state = recover_lock(&self.inner.state);
        let mut tasks = state.active.iter().map(record_task).collect::<Vec<_>>();
        tasks.sort_by_key(task_order);
        tasks
    }

    /// Returns a snapshot of retained scheduler events.
    #[must_use]
    pub fn events(&self) -> Vec<SchedulerEvent> {
        recover_lock(&self.inner.state).events.clone()
    }

    /// Returns a bounded replay log for the retained scheduler lifecycle.
    pub fn replay_log(&self) -> Result<SchedulerReplayLog, TraceError> {
        let state = recover_lock(&self.inner.state);
        SchedulerReplayLog::new(state.events.clone(), state.limits.max_events)
    }

    /// Verifies this scheduler's retained lifecycle against an expected replay.
    pub fn verify_replay(&self, expected: &SchedulerReplayLog) -> Result<(), ReplayError> {
        let mut cursor = expected.replay();
        for (sequence, event) in self.events().into_iter().enumerate() {
            let sequence = u64::try_from(sequence)
                .map_err(|_| ReplayError::InvalidInput(TraceError::InvalidLimit))?;
            cursor.expect_event(&scheduler_event_trace(sequence, event))?;
        }
        cursor.finish()
    }

    /// Runs wake callbacks while advancing only to the next known deadline.
    ///
    /// The callback is the deterministic model of one logical task.  It may
    /// register/cancel tasks through the supplied scheduler and must report
    /// whether it made progress.  No host clock, thread, or sleep is used.
    /// Task-creation accounting starts at watchdog entry, so registrations
    /// that were already present do not consume this run's budget.
    pub fn run_with_watchdog<F>(
        &self,
        limits: SchedulerWatchdogLimits,
        mut on_wake: F,
    ) -> Result<SchedulerWatchdogReport, SchedulerWatchdogError>
    where
        F: FnMut(
            ScheduledTask,
            &DeterministicScheduler,
        ) -> Result<SchedulerWakeOutcome, SchedulerError>,
    {
        let creation_baseline = self.task_creations();
        let mut steps = 0_usize;
        let mut blocked_tasks = 0_usize;
        let mut ready_wait_steps = 0_usize;
        loop {
            let task_creations = self.task_creations().saturating_sub(creation_baseline);
            if task_creations > limits.max_task_creations {
                return Err(SchedulerWatchdogError::Runaway {
                    task_creations,
                    limit: limits.max_task_creations,
                });
            }
            // Check the step budget before collecting or consuming any ready
            // registration.  This keeps an exhausted watchdog from changing
            // readiness or appending a Woken event merely to report its limit.
            if steps >= limits.max_steps && self.registered_count() != 0 {
                return Err(SchedulerWatchdogError::StepLimit {
                    steps,
                    limit: limits.max_steps,
                });
            }
            if let Some(task) = self.poll_ready()? {
                steps += 1;
                let outcome = on_wake(task, self)?;
                match outcome {
                    SchedulerWakeOutcome::Progress => {
                        blocked_tasks = 0;
                        ready_wait_steps = 0;
                    }
                    SchedulerWakeOutcome::Blocked => {
                        blocked_tasks = blocked_tasks.saturating_add(1);
                        if self.ready_count() > 0 {
                            ready_wait_steps = ready_wait_steps.saturating_add(1);
                            if ready_wait_steps > limits.max_ready_wait_steps {
                                return Err(SchedulerWatchdogError::Starvation {
                                    ready_tasks: self.ready_count(),
                                    waited_steps: ready_wait_steps,
                                    limit: limits.max_ready_wait_steps,
                                });
                            }
                        }
                        if self.ready_count() == 0 && self.pending_count() == 0 {
                            return Err(SchedulerWatchdogError::Deadlock { blocked_tasks });
                        }
                    }
                }
                continue;
            }

            let Some(deadline) = self.next_pending_deadline() else {
                if blocked_tasks != 0 {
                    return Err(SchedulerWatchdogError::Deadlock { blocked_tasks });
                }
                return Ok(SchedulerWatchdogReport {
                    steps,
                    task_creations,
                    blocked_tasks,
                });
            };
            self.advance_to_ready(deadline)?;
        }
    }

    /// Clears retained events without changing task state or sequence.
    pub fn clear_events(&self) {
        recover_lock(&self.inner.state).events.clear();
    }

    /// Registers a task at an absolute virtual deadline.
    pub fn schedule_at(
        &self,
        deadline: MonotonicInstant,
        key: u64,
    ) -> Result<TaskHandle, SchedulerError> {
        self.schedule_at_with_ownership(deadline, key, false)
    }

    /// Registers an owned task whose last handle drop attempts cancellation.
    ///
    /// Ordinary scheduling preserves the historical non-owning handle
    /// semantics; use this variant together with [`Self::assert_no_leaks`]
    /// when a bounded owner should clean up automatically.
    pub fn schedule_owned_at(
        &self,
        deadline: MonotonicInstant,
        key: u64,
    ) -> Result<TaskHandle, SchedulerError> {
        self.schedule_at_with_ownership(deadline, key, true)
    }

    fn schedule_at_with_ownership(
        &self,
        deadline: MonotonicInstant,
        key: u64,
        owned: bool,
    ) -> Result<TaskHandle, SchedulerError> {
        let mut state = recover_lock(&self.inner.state);
        if state.active.len() >= state.limits.max_tasks {
            return Err(SchedulerError::CapacityExceeded {
                limit: state.limits.max_tasks,
            });
        }
        ensure_event_capacity(&state)?;
        let id = TaskId(state.next_id);
        let sequence = state.next_sequence;
        let next_id = state
            .next_id
            .checked_add(1)
            .ok_or(SchedulerError::SequenceOverflow)?;
        let next_sequence = state
            .next_sequence
            .checked_add(1)
            .ok_or(SchedulerError::SequenceOverflow)?;
        state.next_id = next_id;
        state.next_sequence = next_sequence;
        let task = ScheduledTask {
            id,
            deadline,
            key,
            sequence,
        };
        let record = Arc::new(Mutex::new(TaskRecord {
            task,
            state: SchedulerTaskState::Pending,
        }));
        state.active.push(Arc::clone(&record));
        state.events.push(SchedulerEvent::Scheduled(task));
        drop(state);
        self.collect_due();
        Ok(TaskHandle {
            inner: Arc::clone(&self.inner),
            record,
            owned,
        })
    }

    /// Registers a task after a relative virtual delay.
    pub fn schedule_after(&self, delay: Duration, key: u64) -> Result<TaskHandle, SchedulerError> {
        let deadline = self
            .inner
            .clock
            .monotonic()
            .checked_add(delay)
            .ok_or(SchedulerError::DeadlineOverflow { delay })?;
        self.schedule_at(deadline, key)
    }

    /// Registers an owned task after a relative virtual delay.
    pub fn schedule_owned_after(
        &self,
        delay: Duration,
        key: u64,
    ) -> Result<TaskHandle, SchedulerError> {
        let deadline = self
            .inner
            .clock
            .monotonic()
            .checked_add(delay)
            .ok_or(SchedulerError::DeadlineOverflow { delay })?;
        self.schedule_owned_at(deadline, key)
    }

    /// Alias for [`Self::schedule_after`].
    pub fn schedule(&self, delay: Duration, key: u64) -> Result<TaskHandle, SchedulerError> {
        self.schedule_after(delay, key)
    }

    /// Advances the virtual clock and consumes all newly ready tasks.
    pub fn advance_by(
        &self,
        amount: Duration,
    ) -> Result<Vec<ScheduledTask>, SchedulerAdvanceError> {
        let current = self.inner.clock.snapshot().monotonic;
        let target = current.checked_add(amount).ok_or({
            SchedulerAdvanceError::Clock(ClockError::Overflow {
                component: ClockComponent::Monotonic,
                amount,
            })
        })?;
        self.advance_to_inner(target)
    }

    /// Advances to a virtual target and consumes all newly ready tasks.
    pub fn advance_to(
        &self,
        target: MonotonicInstant,
    ) -> Result<Vec<ScheduledTask>, SchedulerAdvanceError> {
        self.advance_to_inner(target)
    }

    /// Consumes at most one ready task in deadline/key/sequence order.
    pub fn poll_ready(&self) -> Result<Option<ScheduledTask>, SchedulerError> {
        let now = self.inner.clock.monotonic();
        let mut state = recover_lock(&self.inner.state);
        let has_due = has_due_locked(&state, now);
        if state.ready.is_empty() && !has_due {
            return Ok(None);
        }
        // Preflight before collecting due tasks.  If the event log is full,
        // a task that became due through direct clock advancement must remain
        // Pending rather than being marked Ready by a failed poll.
        ensure_event_capacity(&state)?;
        collect_due_locked(&mut state, now);
        let Some(record) = state.ready.front().cloned() else {
            return Ok(None);
        };
        state.ready.pop_front();
        let task = {
            let mut record_state = recover_lock(&record);
            record_state.state = SchedulerTaskState::Consumed;
            record_state.task
        };
        state
            .active
            .retain(|candidate| !Arc::ptr_eq(candidate, &record));
        state.events.push(SchedulerEvent::Woken(task));
        Ok(Some(task))
    }

    /// Consumes all currently ready tasks in deterministic order.
    ///
    /// The complete wake batch is preflighted before any task is consumed.
    /// This makes a bounded event-log failure atomic: callers never receive
    /// an error after only a prefix of the ready queue has been removed.
    pub fn drain_ready(&self) -> Result<Vec<ScheduledTask>, SchedulerError> {
        let mut state = recover_lock(&self.inner.state);
        let now = self.inner.clock.monotonic();
        let due = state
            .active
            .iter()
            .filter(|record| {
                let task = record_task(record);
                record_state(record) == SchedulerTaskState::Pending && task.deadline <= now
            })
            .count();
        let required_events =
            state
                .ready
                .len()
                .checked_add(due)
                .ok_or(SchedulerError::EventCapacityExceeded {
                    limit: state.limits.max_events,
                })?;
        let total_events = state.events.len().checked_add(required_events).ok_or(
            SchedulerError::EventCapacityExceeded {
                limit: state.limits.max_events,
            },
        )?;
        if total_events > state.limits.max_events {
            return Err(SchedulerError::EventCapacityExceeded {
                limit: state.limits.max_events,
            });
        }

        collect_due_locked(&mut state, now);
        let mut tasks = Vec::with_capacity(required_events);
        while let Some(task) = poll_ready_locked(&mut state)? {
            tasks.push(task);
        }
        Ok(tasks)
    }

    /// Cancels a pending task through its owning handle.
    ///
    /// A handle from another scheduler returns a typed error even when its
    /// numeric identifier collides with a local task.
    pub fn cancel(&self, handle: &TaskHandle) -> Result<bool, SchedulerError> {
        let id = handle.id();
        if !Arc::ptr_eq(&self.inner, &handle.inner) {
            return Err(SchedulerError::UnknownTask { id });
        }
        let mut state = recover_lock(&self.inner.state);
        let Some(position) = state
            .active
            .iter()
            .position(|record| Arc::ptr_eq(record, &handle.record))
        else {
            return if record_state(&handle.record) == SchedulerTaskState::Pending {
                Err(SchedulerError::UnknownTask { id })
            } else {
                Ok(false)
            };
        };
        let record = Arc::clone(&state.active[position]);
        if record_state(&record) != SchedulerTaskState::Pending {
            return Ok(false);
        }
        ensure_event_capacity(&state)?;
        let task = {
            let mut task_state = recover_lock(&record);
            task_state.state = SchedulerTaskState::Cancelled;
            task_state.task
        };
        state.active.remove(position);
        state.events.push(SchedulerEvent::Cancelled(task));
        Ok(true)
    }

    fn collect_due(&self) {
        let now = self.inner.clock.monotonic();
        let mut state = recover_lock(&self.inner.state);
        collect_due_locked(&mut state, now);
    }

    fn task_creations(&self) -> u64 {
        recover_lock(&self.inner.state).next_id
    }

    fn next_pending_deadline(&self) -> Option<MonotonicInstant> {
        let state = recover_lock(&self.inner.state);
        state
            .active
            .iter()
            .filter_map(|record| {
                let record_state = recover_lock(record);
                (record_state.state == SchedulerTaskState::Pending)
                    .then_some(record_state.task.deadline)
            })
            .min()
    }

    fn advance_to_inner(
        &self,
        target: MonotonicInstant,
    ) -> Result<Vec<ScheduledTask>, SchedulerAdvanceError> {
        // Hold scheduler state across the clock movement and wake drain.  A
        // failed event-capacity preflight therefore leaves both logical time
        // and task state unchanged.
        let mut state = recover_lock(&self.inner.state);
        let required_events = preflight_advance_locked(&self.inner.clock, &state, target)?;

        self.inner.clock.advance_to(target)?;
        collect_due_locked(&mut state, target);
        let mut tasks = Vec::with_capacity(required_events);
        while let Some(task) = poll_ready_locked(&mut state)? {
            tasks.push(task);
        }
        Ok(tasks)
    }

    /// Advances time and marks due tasks ready without consuming a wake.
    ///
    /// The scheduler state lock is held through clock validation, event
    /// capacity preflight, clock movement, and due-task collection.  A full
    /// event log therefore leaves both time and readiness unchanged.
    fn advance_to_ready(&self, target: MonotonicInstant) -> Result<(), SchedulerAdvanceError> {
        let mut state = recover_lock(&self.inner.state);
        let _required_events = preflight_advance_locked(&self.inner.clock, &state, target)?;
        self.inner.clock.advance_to(target)?;
        collect_due_locked(&mut state, target);
        Ok(())
    }
}

/// A cloneable handle for one scheduler registration.
#[derive(Clone, Debug)]
pub struct TaskHandle {
    inner: Arc<SchedulerInner>,
    record: Arc<Mutex<TaskRecord>>,
    owned: bool,
}

impl TaskHandle {
    /// Returns the immutable task registration.
    #[must_use]
    pub fn task(&self) -> ScheduledTask {
        record_task(&self.record)
    }

    /// Returns this task's identifier.
    #[must_use]
    pub fn id(&self) -> TaskId {
        self.task().id
    }

    /// Returns this task's virtual deadline.
    #[must_use]
    pub fn deadline(&self) -> MonotonicInstant {
        self.task().deadline
    }

    /// Returns this task's deterministic tie-break key.
    #[must_use]
    pub fn key(&self) -> u64 {
        self.task().key
    }

    /// Returns this task's insertion sequence.
    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.task().sequence
    }

    /// Returns whether this handle owns cancellation-on-drop behavior.
    #[must_use]
    pub const fn is_owned(&self) -> bool {
        self.owned
    }

    /// Returns the current task state.
    #[must_use]
    pub fn state(&self) -> SchedulerTaskState {
        record_state(&self.record)
    }

    /// Returns whether the task is ready or already consumed.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.state().is_ready()
    }

    /// Explicitly cancels this task if it is still pending.
    pub fn cancel(&self) -> Result<bool, SchedulerError> {
        DeterministicScheduler {
            inner: Arc::clone(&self.inner),
        }
        .cancel(self)
    }
}

impl Drop for TaskHandle {
    fn drop(&mut self) {
        // The scheduler's active vector owns one record reference.  Only an
        // explicitly owned handle may perform implicit cancellation; clones
        // remain authoritative until their final owner is dropped.
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
        if record_state(&self.record) != SchedulerTaskState::Pending {
            return;
        }
        if ensure_event_capacity(&state).is_err() {
            state.drop_cancellation_failures = state.drop_cancellation_failures.saturating_add(1);
            return;
        }
        let task = {
            let mut task_state = recover_lock(&self.record);
            task_state.state = SchedulerTaskState::Cancelled;
            task_state.task
        };
        state.active.remove(position);
        state.events.push(SchedulerEvent::Cancelled(task));
    }
}

fn task_order(task: &ScheduledTask) -> (MonotonicInstant, u64, u64) {
    (task.deadline, task.key, task.sequence)
}

fn scheduler_event_trace(sequence: u64, event: SchedulerEvent) -> TraceEvent {
    let (kind, task) = match event {
        SchedulerEvent::Scheduled(task) => ("scheduler.scheduled", task),
        SchedulerEvent::Woken(task) => ("scheduler.woken", task),
        SchedulerEvent::Cancelled(task) => ("scheduler.cancelled", task),
    };
    let mut payload = Vec::with_capacity(36);
    payload.extend_from_slice(&task.id.get().to_le_bytes());
    payload.extend_from_slice(&task.deadline.as_duration().as_secs().to_le_bytes());
    payload.extend_from_slice(&task.deadline.as_duration().subsec_nanos().to_le_bytes());
    payload.extend_from_slice(&task.key.to_le_bytes());
    payload.extend_from_slice(&task.sequence.to_le_bytes());
    TraceEvent::new(sequence, kind, payload)
}

fn ensure_event_capacity(state: &SchedulerState) -> Result<(), SchedulerError> {
    if state.events.len() >= state.limits.max_events {
        Err(SchedulerError::EventCapacityExceeded {
            limit: state.limits.max_events,
        })
    } else {
        Ok(())
    }
}

fn preflight_advance_locked(
    clock: &VirtualClock,
    state: &SchedulerState,
    target: MonotonicInstant,
) -> Result<usize, SchedulerAdvanceError> {
    let current = clock.snapshot();
    let amount =
        target
            .checked_duration_since(current.monotonic)
            .ok_or(SchedulerAdvanceError::Clock(ClockError::MovedBackward {
                current: current.monotonic,
                requested: target,
            }))?;
    current
        .monotonic
        .checked_add(amount)
        .ok_or(SchedulerAdvanceError::Clock(ClockError::Overflow {
            component: ClockComponent::Monotonic,
            amount,
        }))?;
    current
        .wall
        .checked_add(amount)
        .ok_or(SchedulerAdvanceError::Clock(ClockError::Overflow {
            component: ClockComponent::Wall,
            amount,
        }))?;

    let due = state
        .active
        .iter()
        .filter(|record| {
            let task = record_task(record);
            record_state(record) == SchedulerTaskState::Pending && task.deadline <= target
        })
        .count();
    let required_events =
        state
            .ready
            .len()
            .checked_add(due)
            .ok_or(SchedulerAdvanceError::Scheduler(
                SchedulerError::EventCapacityExceeded {
                    limit: state.limits.max_events,
                },
            ))?;
    let total_events =
        state
            .events
            .len()
            .checked_add(required_events)
            .ok_or(SchedulerAdvanceError::Scheduler(
                SchedulerError::EventCapacityExceeded {
                    limit: state.limits.max_events,
                },
            ))?;
    if total_events > state.limits.max_events {
        return Err(SchedulerAdvanceError::Scheduler(
            SchedulerError::EventCapacityExceeded {
                limit: state.limits.max_events,
            },
        ));
    }
    Ok(required_events)
}

fn collect_due_locked(state: &mut SchedulerState, now: MonotonicInstant) {
    let mut newly_ready = Vec::new();
    for record in &state.active {
        let mut record_state = recover_lock(record);
        if record_state.state == SchedulerTaskState::Pending && record_state.task.deadline <= now {
            record_state.state = SchedulerTaskState::Ready;
            newly_ready.push(Arc::clone(record));
        }
    }
    newly_ready.sort_by_key(|record| task_order(&record_task(record)));
    state.ready.extend(newly_ready);
    let mut ready = state.ready.drain(..).collect::<Vec<_>>();
    ready.sort_by_key(|record| task_order(&record_task(record)));
    state.ready.extend(ready);
}

fn has_due_locked(state: &SchedulerState, now: MonotonicInstant) -> bool {
    state.active.iter().any(|record| {
        let record_state = recover_lock(record);
        record_state.state == SchedulerTaskState::Pending && record_state.task.deadline <= now
    })
}

fn poll_ready_locked(state: &mut SchedulerState) -> Result<Option<ScheduledTask>, SchedulerError> {
    let Some(record) = state.ready.front().cloned() else {
        return Ok(None);
    };
    ensure_event_capacity(state)?;
    state.ready.pop_front();
    let task = {
        let mut record_state = recover_lock(&record);
        record_state.state = SchedulerTaskState::Consumed;
        record_state.task
    };
    state
        .active
        .retain(|candidate| !Arc::ptr_eq(candidate, &record));
    state.events.push(SchedulerEvent::Woken(task));
    Ok(Some(task))
}

fn record_task(record: &Arc<Mutex<TaskRecord>>) -> ScheduledTask {
    recover_lock(record).task
}

fn record_state(record: &Arc<Mutex<TaskRecord>>) -> SchedulerTaskState {
    recover_lock(record).state
}

fn recover_lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn equal_deadlines_use_key_then_sequence() {
        let scheduler =
            DeterministicScheduler::new(VirtualClock::at_epoch(), SchedulerLimits::new(8, 32));
        let high = scheduler.schedule_after(Duration::from_secs(1), 2).unwrap();
        let first = scheduler.schedule_after(Duration::from_secs(1), 1).unwrap();
        let second = scheduler.schedule_after(Duration::from_secs(1), 1).unwrap();
        let tasks = scheduler.advance_by(Duration::from_secs(1)).unwrap();
        assert_eq!(tasks, vec![first.task(), second.task(), high.task()]);
        assert!(high.state().is_ready());
    }

    #[test]
    fn cancellation_is_bounded_and_releases_capacity() {
        let scheduler =
            DeterministicScheduler::new(VirtualClock::at_epoch(), SchedulerLimits::new(1, 8));
        let task = scheduler.schedule_after(Duration::from_secs(1), 0).unwrap();
        assert!(task.cancel().unwrap());
        assert_eq!(task.state(), SchedulerTaskState::Cancelled);
        assert_eq!(scheduler.registered_count(), 0);
        let replacement = scheduler.schedule_after(Duration::ZERO, 0).unwrap();
        assert_eq!(scheduler.drain_ready().unwrap(), vec![replacement.task()]);
        assert!(!replacement.cancel().unwrap());
    }

    #[test]
    fn capacities_and_sequence_overflow_do_not_partially_register() {
        let scheduler =
            DeterministicScheduler::new(VirtualClock::at_epoch(), SchedulerLimits::new(1, 1));
        let _task = scheduler.schedule_after(Duration::ZERO, 0).unwrap();
        assert_eq!(
            scheduler
                .schedule_after(Duration::ZERO, 0)
                .unwrap_err()
                .code(),
            ErrorCode::SchedulerCapacity
        );

        let scheduler =
            DeterministicScheduler::new(VirtualClock::at_epoch(), SchedulerLimits::new(2, 4));
        {
            let mut state = recover_lock(&scheduler.inner.state);
            state.next_sequence = u64::MAX;
        }
        assert_eq!(
            scheduler
                .schedule_after(Duration::ZERO, 0)
                .unwrap_err()
                .code(),
            ErrorCode::SchedulerSequenceOverflow
        );
        assert_eq!(scheduler.registered_count(), 0);
    }

    #[test]
    fn event_log_capacity_keeps_task_state_unchanged() {
        let scheduler =
            DeterministicScheduler::new(VirtualClock::at_epoch(), SchedulerLimits::new(2, 1));
        let task = scheduler.schedule_after(Duration::ZERO, 0).unwrap();
        assert_eq!(
            scheduler.drain_ready().unwrap_err().code(),
            ErrorCode::SchedulerEventCapacity
        );
        assert_eq!(task.state(), SchedulerTaskState::Ready);
        assert_eq!(scheduler.registered_count(), 1);
    }

    #[test]
    fn advance_to_event_capacity_failure_is_atomic() {
        let scheduler =
            DeterministicScheduler::new(VirtualClock::at_epoch(), SchedulerLimits::new(2, 1));
        let task = scheduler.schedule_after(Duration::from_secs(1), 0).unwrap();
        let before = scheduler.clock().snapshot();
        assert_eq!(
            scheduler
                .advance_to(MonotonicInstant::from_duration(Duration::from_secs(1)))
                .unwrap_err()
                .code(),
            ErrorCode::SchedulerEventCapacity
        );
        assert_eq!(scheduler.clock().snapshot(), before);
        assert_eq!(task.state(), SchedulerTaskState::Pending);
        assert_eq!(scheduler.registered_count(), 1);
    }

    #[test]
    fn poll_ready_event_capacity_failure_after_direct_clock_advance_is_atomic() {
        let scheduler =
            DeterministicScheduler::new(VirtualClock::at_epoch(), SchedulerLimits::new(2, 1));
        let task = scheduler.schedule_after(Duration::from_secs(1), 0).unwrap();
        let before_events = scheduler.events();
        scheduler.clock().advance(Duration::from_secs(1)).unwrap();

        assert_eq!(
            scheduler.poll_ready().unwrap_err().code(),
            ErrorCode::SchedulerEventCapacity
        );
        assert_eq!(task.state(), SchedulerTaskState::Pending);
        assert_eq!(scheduler.ready_count(), 0);
        assert_eq!(scheduler.registered_count(), 1);
        assert_eq!(scheduler.events(), before_events);

        scheduler.clear_events();
        assert_eq!(scheduler.poll_ready().unwrap(), Some(task.task()));
    }

    #[test]
    fn drain_ready_event_capacity_failure_is_atomic() {
        let scheduler =
            DeterministicScheduler::new(VirtualClock::at_epoch(), SchedulerLimits::new(4, 3));
        let high = scheduler.schedule_after(Duration::ZERO, 2).unwrap();
        let low = scheduler.schedule_after(Duration::ZERO, 1).unwrap();
        let events = scheduler.events();

        assert_eq!(
            scheduler.drain_ready().unwrap_err(),
            SchedulerError::EventCapacityExceeded { limit: 3 }
        );
        assert_eq!(scheduler.events(), events);
        assert_eq!(scheduler.ready_count(), 2);
        assert_eq!(high.state(), SchedulerTaskState::Ready);
        assert_eq!(low.state(), SchedulerTaskState::Ready);

        scheduler.clear_events();
        assert_eq!(
            scheduler.drain_ready().unwrap(),
            vec![low.task(), high.task()]
        );
        assert_eq!(scheduler.registered_count(), 0);
    }

    #[test]
    fn already_due_registrations_use_deadline_order_and_replay() {
        let scheduler =
            DeterministicScheduler::new(VirtualClock::at_epoch(), SchedulerLimits::new(4, 8));
        scheduler.clock().advance(Duration::from_secs(5)).unwrap();
        let later = scheduler
            .schedule_at(MonotonicInstant::from_duration(Duration::from_secs(5)), 0)
            .unwrap();
        let earlier = scheduler
            .schedule_at(MonotonicInstant::from_duration(Duration::from_secs(3)), 0)
            .unwrap();

        assert_eq!(
            scheduler.drain_ready().unwrap(),
            vec![earlier.task(), later.task()]
        );
        let replay = scheduler.replay_log().unwrap();
        assert_eq!(
            replay.events(),
            &[
                SchedulerEvent::Scheduled(later.task()),
                SchedulerEvent::Scheduled(earlier.task()),
                SchedulerEvent::Woken(earlier.task()),
                SchedulerEvent::Woken(later.task()),
            ]
        );
    }

    #[test]
    fn cancellation_is_owner_scoped_when_task_ids_collide() {
        let first =
            DeterministicScheduler::new(VirtualClock::at_epoch(), SchedulerLimits::new(2, 8));
        let second =
            DeterministicScheduler::new(VirtualClock::at_epoch(), SchedulerLimits::new(2, 8));
        let first_task = first.schedule_after(Duration::from_secs(1), 0).unwrap();
        let second_task = second.schedule_after(Duration::from_secs(1), 0).unwrap();
        assert_eq!(first_task.id(), second_task.id());

        assert_eq!(
            first.cancel(&second_task).unwrap_err().code(),
            ErrorCode::SchedulerUnknownTask
        );
        assert_eq!(second_task.state(), SchedulerTaskState::Pending);
        assert!(first.cancel(&first_task).unwrap());
        assert!(!first_task.cancel().unwrap());
    }

    #[test]
    fn replay_log_verifies_ordered_scheduler_lifecycle() {
        let expected_scheduler =
            DeterministicScheduler::new(VirtualClock::at_epoch(), SchedulerLimits::new(8, 32));
        let task = expected_scheduler
            .schedule_after(Duration::from_secs(1), 7)
            .unwrap();
        expected_scheduler
            .advance_by(Duration::from_secs(1))
            .unwrap();
        let expected = expected_scheduler.replay_log().unwrap();
        assert_eq!(expected.len(), 2);

        let actual_scheduler =
            DeterministicScheduler::new(VirtualClock::at_epoch(), SchedulerLimits::new(8, 32));
        let actual_task = actual_scheduler
            .schedule_after(Duration::from_secs(1), 7)
            .unwrap();
        actual_scheduler.advance_by(Duration::from_secs(1)).unwrap();
        assert_eq!(actual_task.task(), task.task());
        actual_scheduler.verify_replay(&expected).unwrap();

        let mismatched =
            DeterministicScheduler::new(VirtualClock::at_epoch(), SchedulerLimits::new(8, 32));
        mismatched
            .schedule_after(Duration::from_secs(2), 7)
            .unwrap();
        assert_eq!(
            mismatched.verify_replay(&expected).unwrap_err().code(),
            ErrorCode::ReplayMismatch
        );
    }

    #[test]
    fn watchdog_advances_virtual_time_and_reaches_quiescence() {
        let scheduler =
            DeterministicScheduler::new(VirtualClock::at_epoch(), SchedulerLimits::new(8, 32));
        scheduler.schedule_after(Duration::from_secs(2), 0).unwrap();
        let report = scheduler
            .run_with_watchdog(SchedulerWatchdogLimits::new(4, 4, 1), |_, _| {
                Ok(SchedulerWakeOutcome::Progress)
            })
            .unwrap();
        assert_eq!(report.steps, 1);
        assert_eq!(report.task_creations, 0);
        assert_eq!(
            scheduler.clock().monotonic(),
            MonotonicInstant::from_duration(Duration::from_secs(2))
        );
    }

    #[test]
    fn watchdog_step_budget_is_preflighted_without_consuming_ready_work() {
        let scheduler =
            DeterministicScheduler::new(VirtualClock::at_epoch(), SchedulerLimits::new(4, 8));
        let task = scheduler.schedule_after(Duration::ZERO, 0).unwrap();
        let events = scheduler.events();
        let error = scheduler
            .run_with_watchdog(SchedulerWatchdogLimits::new(0, 4, 1), |_, _| {
                Ok(SchedulerWakeOutcome::Progress)
            })
            .unwrap_err();
        assert!(matches!(
            error,
            SchedulerWatchdogError::StepLimit { steps: 0, limit: 0 }
        ));
        assert_eq!(task.state(), SchedulerTaskState::Ready);
        assert_eq!(scheduler.ready_count(), 1);
        assert_eq!(scheduler.events(), events);
    }

    #[test]
    fn watchdog_exhausted_budget_leaves_remaining_ready_work_untouched() {
        let scheduler =
            DeterministicScheduler::new(VirtualClock::at_epoch(), SchedulerLimits::new(4, 8));
        let first = scheduler.schedule_after(Duration::ZERO, 0).unwrap();
        let second = scheduler.schedule_after(Duration::ZERO, 1).unwrap();
        let events_before = scheduler.events();
        let report = scheduler.run_with_watchdog(SchedulerWatchdogLimits::new(1, 4, 1), |_, _| {
            Ok(SchedulerWakeOutcome::Progress)
        });
        assert_eq!(
            report.unwrap_err(),
            SchedulerWatchdogError::StepLimit { steps: 1, limit: 1 }
        );
        assert_eq!(first.state(), SchedulerTaskState::Consumed);
        assert_eq!(second.state(), SchedulerTaskState::Ready);
        assert_eq!(scheduler.ready_count(), 1);
        assert_eq!(scheduler.events().len(), events_before.len() + 1);
        assert!(matches!(
            scheduler.events().last(),
            Some(SchedulerEvent::Woken(task)) if *task == first.task()
        ));
    }

    #[test]
    fn watchdog_task_creation_budget_uses_run_start_baseline() {
        let existing =
            DeterministicScheduler::new(VirtualClock::at_epoch(), SchedulerLimits::new(4, 8));
        existing.schedule_after(Duration::ZERO, 0).unwrap();
        let report = existing
            .run_with_watchdog(SchedulerWatchdogLimits::new(2, 0, 1), |_, _| {
                Ok(SchedulerWakeOutcome::Progress)
            })
            .unwrap();
        assert_eq!(report.task_creations, 0);

        let runaway =
            DeterministicScheduler::new(VirtualClock::at_epoch(), SchedulerLimits::new(4, 8));
        runaway.schedule_after(Duration::ZERO, 0).unwrap();
        let error = runaway
            .run_with_watchdog(SchedulerWatchdogLimits::new(2, 0, 1), |_, scheduler| {
                scheduler
                    .schedule_after(Duration::ZERO, 1)
                    .map(|_| SchedulerWakeOutcome::Progress)
            })
            .unwrap_err();
        assert_eq!(
            error,
            SchedulerWatchdogError::Runaway {
                task_creations: 1,
                limit: 0,
            }
        );
    }

    #[test]
    fn watchdog_deadline_overflow_is_atomic() {
        let scheduler =
            DeterministicScheduler::new(VirtualClock::at_epoch(), SchedulerLimits::new(2, 4));
        let task = scheduler
            .schedule_at(MonotonicInstant::from_duration(Duration::MAX), 0)
            .unwrap();
        let before_clock = scheduler.clock().snapshot();
        let before_events = scheduler.events();
        let error = scheduler
            .run_with_watchdog(SchedulerWatchdogLimits::new(2, 1, 1), |_, _| {
                Ok(SchedulerWakeOutcome::Progress)
            })
            .unwrap_err();
        assert!(matches!(
            error,
            SchedulerWatchdogError::Clock(ClockError::Overflow {
                component: ClockComponent::Wall,
                ..
            })
        ));
        assert_eq!(scheduler.clock().snapshot(), before_clock);
        assert_eq!(scheduler.events(), before_events);
        assert_eq!(task.state(), SchedulerTaskState::Pending);
    }

    #[test]
    fn watchdog_event_capacity_failure_does_not_advance_or_mark_due() {
        let scheduler =
            DeterministicScheduler::new(VirtualClock::at_epoch(), SchedulerLimits::new(2, 1));
        let task = scheduler.schedule_after(Duration::from_secs(1), 0).unwrap();
        let before_clock = scheduler.clock().snapshot();
        let before_events = scheduler.events();
        let error = scheduler
            .run_with_watchdog(SchedulerWatchdogLimits::new(2, 1, 1), |_, _| {
                Ok(SchedulerWakeOutcome::Progress)
            })
            .unwrap_err();
        assert_eq!(
            error,
            SchedulerWatchdogError::Scheduler(SchedulerError::EventCapacityExceeded { limit: 1 })
        );
        assert_eq!(scheduler.clock().snapshot(), before_clock);
        assert_eq!(scheduler.events(), before_events);
        assert_eq!(task.state(), SchedulerTaskState::Pending);
        assert_eq!(scheduler.ready_count(), 0);
    }

    #[test]
    fn watchdog_reports_deadlock_starvation_and_runaway_deterministically() {
        let deadlocked =
            DeterministicScheduler::new(VirtualClock::at_epoch(), SchedulerLimits::new(8, 32));
        deadlocked.schedule_after(Duration::ZERO, 0).unwrap();
        assert_eq!(
            deadlocked
                .run_with_watchdog(SchedulerWatchdogLimits::new(4, 4, 1), |_, _| {
                    Ok(SchedulerWakeOutcome::Blocked)
                })
                .unwrap_err()
                .code(),
            ErrorCode::SchedulerDeadlock
        );

        let starving =
            DeterministicScheduler::new(VirtualClock::at_epoch(), SchedulerLimits::new(8, 32));
        starving.schedule_after(Duration::ZERO, 0).unwrap();
        starving.schedule_after(Duration::ZERO, 1).unwrap();
        assert_eq!(
            starving
                .run_with_watchdog(SchedulerWatchdogLimits::new(4, 4, 0), |_, _| {
                    Ok(SchedulerWakeOutcome::Blocked)
                })
                .unwrap_err()
                .code(),
            ErrorCode::SchedulerStarvation
        );

        let runaway =
            DeterministicScheduler::new(VirtualClock::at_epoch(), SchedulerLimits::new(8, 32));
        runaway.schedule_after(Duration::ZERO, 0).unwrap();
        assert_eq!(
            runaway
                .run_with_watchdog(SchedulerWatchdogLimits::new(8, 1, 1), |_, scheduler| {
                    scheduler
                        .schedule_after(Duration::ZERO, 0)
                        .map(|_| SchedulerWakeOutcome::Progress)
                })
                .unwrap_err()
                .code(),
            ErrorCode::SchedulerRunaway
        );
    }

    #[test]
    fn dropping_a_task_handle_is_explicitly_non_cancelling() {
        let scheduler =
            DeterministicScheduler::new(VirtualClock::at_epoch(), SchedulerLimits::new(2, 8));
        let task = scheduler.schedule_after(Duration::from_secs(1), 0).unwrap();
        let task_id = task.id();
        drop(task);
        assert_eq!(scheduler.pending_count(), 1);
        assert_eq!(
            scheduler.advance_by(Duration::from_secs(1)).unwrap().len(),
            1
        );
        assert_eq!(scheduler.events()[0].task().id, task_id);
    }

    #[test]
    fn owned_task_drop_cancels_and_releases_capacity() {
        let scheduler =
            DeterministicScheduler::new(VirtualClock::at_epoch(), SchedulerLimits::new(1, 4));
        let task = scheduler
            .schedule_owned_after(Duration::from_secs(1), 0)
            .unwrap();
        assert!(task.is_owned());
        drop(task);
        assert_eq!(scheduler.pending_count(), 0);
        scheduler.assert_no_leaks().unwrap();
        let replacement = scheduler.schedule_after(Duration::ZERO, 0).unwrap();
        assert_eq!(scheduler.drain_ready().unwrap(), vec![replacement.task()]);
    }

    #[test]
    fn owned_task_drop_failure_is_reported_as_a_leak() {
        let scheduler =
            DeterministicScheduler::new(VirtualClock::at_epoch(), SchedulerLimits::new(1, 1));
        let task = scheduler
            .schedule_owned_after(Duration::from_secs(1), 0)
            .unwrap();
        drop(task);
        assert_eq!(
            scheduler.assert_no_leaks().unwrap_err(),
            SchedulerLeakError::DropCancellationFailed { failures: 1 }
        );
        assert_eq!(scheduler.active_task_count(), 1);
    }

    #[test]
    fn cancel_all_preflights_event_capacity() {
        let scheduler =
            DeterministicScheduler::new(VirtualClock::at_epoch(), SchedulerLimits::new(2, 2));
        let first = scheduler.schedule_after(Duration::from_secs(1), 0).unwrap();
        let second = scheduler.schedule_after(Duration::from_secs(1), 1).unwrap();
        let events = scheduler.events();
        assert_eq!(
            scheduler.cancel_all().unwrap_err(),
            SchedulerError::EventCapacityExceeded { limit: 2 }
        );
        assert_eq!(first.state(), SchedulerTaskState::Pending);
        assert_eq!(second.state(), SchedulerTaskState::Pending);
        assert_eq!(scheduler.events(), events);
    }
}
