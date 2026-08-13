// SPDX-License-Identifier: Apache-2.0
//! Setup/main/teardown lifecycle and virtual-user scheduling seams.
//!
//! The engine is an executor-neutral async state machine. It preserves the
//! three JMeter group phases, per-user controller/context ownership, loop and
//! sample error signals, and the distinction between graceful and immediate
//! stop. A production edge can poll the returned future on any executor.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::{self, Future};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::Duration;

use jmeter_rs_model::NodeId;
use jmeter_rs_results::{ElapsedTime, HostIdentity, RunIdentity, SampleResult, ThreadIdentity};

use crate::observation::{
    ObservationError, ObservationState, RunObservationPolicyV1, RunObservationSummaryV1,
    RunObservationTerminalState, RunObservationTraceV1,
};
use crate::progress::{ProgressError, ProgressHandle, ProgressOwner};
use crate::result_router::{
    TypedAdmissionOutcome, TypedResultEnvelope, TypedResultOrigin, TypedResultRouterAdapter,
    TypedRouterError, TypedSampleId, TypedUserIdentity,
};
use crate::{
    AdmissionOutcome, CancellationToken, CompiledPackages, ControlSignal, ControllerError,
    ControllerProgram, ControllerStep, CriticalSectionError, ExecutionContext, ExecutionPipeline,
    InitialVariables, InitialVariablesError, LogicInput, LogicProgram, LogicSharedState, LogicStep,
    PackageCompileError, PipelineError, ResultEventMetadata, ResultOrigin, ResultRouter,
    ResultRouterError, RuntimeCapabilities, SampleFailure, SampleIdentity, TransactionInfo,
    UserIdentity,
};

const MAX_GROUPS: usize = 1_024;
const MAX_THREADS: usize = 1_000_000;
const MAX_CONCURRENT_TASKS: usize = 65_536;
const MAX_TYPED_ADMISSION_WAITERS: usize = MAX_CONCURRENT_TASKS;

/// A small async gate for the one run-owned typed admission sequence.
///
/// The router itself is protected by its own mutex, but admission includes a
/// potentially pending sink drain.  Holding a synchronous mutex across that
/// await would block the current-thread executor when another scheduler clone
/// reaches the next sample.  This gate therefore parks contenders by waker,
/// while keeping the number of retained waiters bounded by the existing task
/// limit.
struct TypedAdmissionGate {
    state: Mutex<TypedAdmissionGateState>,
}

#[derive(Default)]
struct TypedAdmissionGateState {
    held: bool,
    waiters: Vec<std::task::Waker>,
}

impl TypedAdmissionGate {
    fn new() -> Self {
        Self {
            state: Mutex::new(TypedAdmissionGateState::default()),
        }
    }

    fn acquire(self: &Arc<Self>) -> TypedAdmissionAcquire {
        TypedAdmissionAcquire {
            gate: Arc::clone(self),
            waiter: None,
        }
    }

    fn release(&self) {
        let waiters = {
            let mut state = lock(&self.state);
            state.held = false;
            std::mem::take(&mut state.waiters)
        };
        for waiter in waiters {
            waiter.wake();
        }
    }
}

struct TypedAdmissionAcquire {
    gate: Arc<TypedAdmissionGate>,
    waiter: Option<std::task::Waker>,
}

impl Future for TypedAdmissionAcquire {
    type Output = Result<TypedAdmissionPermit, EngineError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        // Clone the gate before borrowing its state. This keeps the mutex
        // guard independent from the pinned future's mutable waiter slot.
        let gate = Arc::clone(&self.gate);
        let mut state = lock(&gate.state);
        if !state.held {
            state.held = true;
            if let Some(waiter) = self.waiter.take() {
                state.waiters.retain(|candidate| !candidate.will_wake(&waiter));
            }
            drop(state);
            return Poll::Ready(Ok(TypedAdmissionPermit {
                gate,
            }));
        }

        let waker = context.waker();
        if !self
            .waiter
            .as_ref()
            .is_some_and(|waiter| waiter.will_wake(waker))
        {
            if state.waiters.len() >= MAX_TYPED_ADMISSION_WAITERS {
                return Poll::Ready(Err(EngineError::ResourceLimit {
                    detail: "typed admission waiter limit".to_owned(),
                }));
            }
            if let Some(previous) = self.waiter.replace(waker.clone()) {
                state
                    .waiters
                    .retain(|candidate| !candidate.will_wake(&previous));
            }
            state.waiters.push(waker.clone());
        }
        Poll::Pending
    }
}

impl Drop for TypedAdmissionAcquire {
    fn drop(&mut self) {
        let Some(waiter) = self.waiter.take() else {
            return;
        };
        lock(&self.gate.state)
            .waiters
            .retain(|candidate| !candidate.will_wake(&waiter));
    }
}

struct TypedAdmissionPermit {
    gate: Arc<TypedAdmissionGate>,
}

impl Drop for TypedAdmissionPermit {
    fn drop(&mut self) {
        self.gate.release();
    }
}

fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn combine_engine_error(slot: &mut Option<EngineError>, error: EngineError) {
    if let Some(primary) = slot.take() {
        *slot = Some(EngineError::Combined {
            primary: Box::new(primary),
            secondary: Box::new(error),
        });
    } else {
        *slot = Some(error);
    }
}

fn combined_engine_error(primary: EngineError, secondary: EngineError) -> EngineError {
    EngineError::Combined {
        primary: Box::new(primary),
        secondary: Box::new(secondary),
    }
}

fn group_allowed_after_stop(
    plan: &EnginePlan,
    group: &ThreadGroupPlan,
    signal: ControlSignal,
) -> bool {
    match signal {
        ControlSignal::StopTestImmediate => {
            group.kind == GroupKind::Teardown
                && plan.teardown_on_shutdown
                && group.teardown_on_shutdown
        }
        // A graceful stop drains setup/teardown boundaries. The shutdown
        // teardown policy is specifically an immediate-stop policy.
        ControlSignal::StopTestGraceful => group.kind != GroupKind::Main,
        _ => true,
    }
}

fn add_transaction_timer(
    result: &mut SampleResult,
    delay: Duration,
) -> Result<(), jmeter_rs_results::ResultError> {
    let millis =
        u64::try_from(delay.as_millis()).map_err(|_| jmeter_rs_results::ResultError::Overflow {
            field: jmeter_rs_results::ResultField::Elapsed,
        })?;
    let timer = ElapsedTime::from_millis(millis);
    let elapsed = result.elapsed().unwrap_or_default().checked_add(timer)?;
    if let Some(start) = result.start_time() {
        let shift =
            i64::try_from(millis).map_err(|_| jmeter_rs_results::ResultError::Overflow {
                field: jmeter_rs_results::ResultField::Timestamp,
            })?;
        result.set_start_time(Some(start.checked_add_millis(-shift)?))?;
    }
    result.set_elapsed(Some(elapsed))
}

/// Lifecycle group category.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GroupKind {
    /// Runs before main groups.
    Setup,
    /// Normal load-test group.
    Main,
    /// Runs after main groups when policy permits.
    Teardown,
}

/// Engine stop/lifecycle phase.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EngineMode {
    /// Setup groups are executing.
    Setup,
    /// Main groups are executing.
    Main,
    /// Teardown groups are executing.
    Teardown,
    /// The engine has completed.
    Complete,
}

/// Policy applied after a sample-level failure or failed result.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SampleErrorPolicy {
    /// Continue selecting samplers.
    Continue,
    /// Skip to the next root loop iteration.
    StartNextLoop,
    /// Stop only this virtual user.
    StopThread,
    /// Stop the test at a safe group boundary.
    StopTestGraceful,
    /// Interrupt the test at the next boundary.
    StopTestImmediate,
}

impl SampleErrorPolicy {
    /// Converts the policy to its typed control signal.
    #[must_use]
    pub const fn signal(self) -> ControlSignal {
        match self {
            Self::Continue => ControlSignal::Continue,
            Self::StartNextLoop => ControlSignal::NextLoop,
            Self::StopThread => ControlSignal::StopThread,
            Self::StopTestGraceful => ControlSignal::StopTestGraceful,
            Self::StopTestImmediate => ControlSignal::StopTestImmediate,
        }
    }
}

/// A pure ramp-up offset calculation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RampSchedule {
    /// Number of virtual users.
    pub threads: usize,
    /// Total ramp interval.
    pub ramp_up: Duration,
}

impl RampSchedule {
    fn validate(self) -> Result<(), EngineError> {
        if self.threads > MAX_THREADS {
            return Err(EngineError::InvalidSchedule {
                detail: "thread count exceeds runtime bound".to_owned(),
            });
        }
        Ok(())
    }

    /// Creates a validated schedule.
    pub fn new(threads: usize, ramp_up: Duration) -> Result<Self, EngineError> {
        let schedule = Self { threads, ramp_up };
        schedule.validate()?;
        Ok(schedule)
    }

    /// Returns the start offset for a zero-based thread index.
    ///
    /// The calculation is performed at nanosecond precision and uses checked
    /// multiplication.  The index is clamped to the last executable user,
    /// matching the execution loop's one task per configured user semantics.
    pub fn offset(self, index: usize) -> Result<Duration, EngineError> {
        self.validate()?;
        if self.threads <= 1 || index == 0 || self.ramp_up.is_zero() {
            return Ok(Duration::ZERO);
        }
        let last_index =
            self.threads
                .checked_sub(1)
                .ok_or_else(|| EngineError::InvalidSchedule {
                    detail: "ramp thread index underflow".to_owned(),
                })?;
        let bounded = index.min(last_index) as u128;
        let numerator = self
            .ramp_up
            .as_nanos()
            .checked_mul(bounded)
            .ok_or_else(|| EngineError::InvalidSchedule {
                detail: "ramp offset arithmetic overflow".to_owned(),
            })?;
        let denominator = self.threads as u128;
        let nanos = numerator / denominator;
        let seconds = nanos / 1_000_000_000;
        let subnanos = (nanos % 1_000_000_000) as u32;
        let seconds = u64::try_from(seconds).map_err(|_| EngineError::InvalidSchedule {
            detail: "ramp offset duration overflow".to_owned(),
        })?;
        Ok(Duration::new(seconds, subnanos))
    }

    /// Alias for [`RampSchedule::offset`] that makes its checked contract
    /// explicit at call sites that calculate startup bounds.
    pub fn checked_offset(self, index: usize) -> Result<Duration, EngineError> {
        self.offset(index)
    }

    /// Returns the greatest offset actually used by the execution loop.
    pub fn max_actual_user_offset(self) -> Result<Duration, EngineError> {
        self.validate()?;
        match self.threads.checked_sub(1) {
            Some(last_index) => self.offset(last_index),
            None => Ok(Duration::ZERO),
        }
    }

    /// Returns all offsets in deterministic thread-number order.
    pub fn offsets(self) -> Result<Vec<Duration>, EngineError> {
        self.validate()?;
        (0..self.threads).map(|index| self.offset(index)).collect()
    }
}

/// Group delay/duration scheduler settings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupSchedule {
    /// Delay before the first virtual user.
    pub delay: Duration,
    /// Ramp-up interval between first and final users.
    pub ramp_up: Duration,
    /// Optional scheduler duration. `None` means no duration boundary.
    pub duration: Option<Duration>,
}

impl Default for GroupSchedule {
    fn default() -> Self {
        Self {
            delay: Duration::ZERO,
            ramp_up: Duration::ZERO,
            duration: None,
        }
    }
}

impl GroupSchedule {
    /// Validates schedule values and creates a ramp calculation.
    pub fn ramp(self, threads: usize) -> Result<RampSchedule, EngineError> {
        let ramp = RampSchedule::new(threads, self.ramp_up)?;
        // The startup bound must use the same clamped offset calculation as
        // execution.  This rejects delay + ramp overflow before any user
        // task is admitted, without imposing a duration policy of its own.
        self.delay
            .checked_add(ramp.max_actual_user_offset()?)
            .ok_or_else(|| EngineError::InvalidSchedule {
                detail: "group startup offset arithmetic overflow".to_owned(),
            })?;
        Ok(ramp)
    }

    /// Returns the maximum actual user offset, excluding the group delay.
    pub fn max_actual_user_offset(self, threads: usize) -> Result<Duration, EngineError> {
        RampSchedule::new(threads, self.ramp_up)?.max_actual_user_offset()
    }

    /// Returns the checked delay through the final user's actual startup.
    pub fn startup_bound(self, threads: usize) -> Result<Duration, EngineError> {
        let ramp = self.ramp(threads)?;
        self.delay
            .checked_add(ramp.max_actual_user_offset()?)
            .ok_or_else(|| EngineError::InvalidSchedule {
                detail: "group startup offset arithmetic overflow".to_owned(),
            })
    }

    /// Returns the checked absolute duration boundary for a group start.
    pub fn checked_duration_end(
        self,
        group_start: Duration,
    ) -> Result<Option<Duration>, EngineError> {
        self.duration
            .map(|duration| {
                group_start
                    .checked_add(duration)
                    .ok_or_else(|| EngineError::InvalidSchedule {
                        detail: "group duration end arithmetic overflow".to_owned(),
                    })
            })
            .transpose()
    }
}

/// Per-user iteration counters. The root controller loop is independent from
/// nested controller counters and this value is never shared across users.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IterationState {
    current: u64,
    completed: u64,
}

impl IterationState {
    /// Returns the current zero-based iteration.
    #[must_use]
    pub const fn current(self) -> u64 {
        self.current
    }

    /// Returns the number of completed root iterations.
    #[must_use]
    pub const fn completed(self) -> u64 {
        self.completed
    }

    /// Advances to the next root iteration with checked arithmetic.
    pub fn advance(&mut self) -> Result<(), EngineError> {
        self.completed =
            self.completed
                .checked_add(1)
                .ok_or_else(|| EngineError::InvalidSchedule {
                    detail: "iteration counter overflow".to_owned(),
                })?;
        self.current = self
            .current
            .checked_add(1)
            .ok_or_else(|| EngineError::InvalidSchedule {
                detail: "iteration counter overflow".to_owned(),
            })?;
        Ok(())
    }

    /// Resets the per-user current iteration while retaining completion count.
    pub const fn reset_current(&mut self) {
        self.current = 0;
    }
}

/// One executable thread-group plan.
#[derive(Clone, Debug)]
pub struct ThreadGroupPlan {
    /// Stable group identity.
    pub id: NodeId,
    /// Display/thread-group name.
    pub name: String,
    /// Setup/main/teardown category.
    pub kind: GroupKind,
    /// Number of virtual users.
    pub threads: usize,
    /// Ramp/delay/duration settings.
    pub schedule: GroupSchedule,
    /// Root controller program.
    pub controller: ControllerProgram,
    /// Complete built-in controller program, when the group was compiled by
    /// the logic-controller state machine. This is an explicit alternative to
    /// the compact legacy controller seam above.
    pub logic_controller: Option<LogicProgram>,
    /// Identity-keyed sampler packages.
    pub packages: CompiledPackages,
    /// Policy after sample failure.
    pub on_sample_error: SampleErrorPolicy,
    /// Whether a user retains context across root iterations.
    pub same_user_on_next_iteration: bool,
    /// Root-controller iteration count. `None` is unbounded and requires a
    /// finite group duration or the engine transition bound to terminate.
    pub iterations: Option<u64>,
    /// Whether teardown is allowed after shutdown/cancellation.
    pub teardown_on_shutdown: bool,
}

impl ThreadGroupPlan {
    /// Creates a main group with the normal JMeter defaults.
    pub fn new(
        id: NodeId,
        name: impl Into<String>,
        threads: usize,
        controller: ControllerProgram,
        packages: CompiledPackages,
    ) -> Result<Self, EngineError> {
        if threads > MAX_THREADS {
            return Err(EngineError::InvalidSchedule {
                detail: "thread count exceeds runtime bound".to_owned(),
            });
        }
        Ok(Self {
            id,
            name: name.into(),
            kind: GroupKind::Main,
            threads,
            schedule: GroupSchedule::default(),
            controller,
            logic_controller: None,
            packages,
            on_sample_error: SampleErrorPolicy::Continue,
            same_user_on_next_iteration: true,
            iterations: Some(1),
            teardown_on_shutdown: true,
        })
    }

    /// Creates a group backed by the complete built-in logic-controller
    /// state machine. The compact controller field remains populated with an
    /// empty plan only for API compatibility and is not selected at runtime.
    pub fn new_logic(
        id: NodeId,
        name: impl Into<String>,
        threads: usize,
        controller: LogicProgram,
        packages: CompiledPackages,
    ) -> Result<Self, EngineError> {
        let legacy = ControllerProgram::compile(crate::ControllerNode::simple(0, vec![])).map_err(
            |source| EngineError::Controller {
                group_id: id,
                source,
            },
        )?;
        Ok(Self::new(id, name, threads, legacy, packages)?.with_logic_controller(controller))
    }

    /// Changes the setup/main/teardown group category.
    #[must_use]
    pub const fn with_kind(mut self, kind: GroupKind) -> Self {
        self.kind = kind;
        self
    }

    /// Changes group schedule.
    #[must_use]
    pub const fn with_schedule(mut self, schedule: GroupSchedule) -> Self {
        self.schedule = schedule;
        self
    }

    /// Changes sample error policy.
    #[must_use]
    pub const fn with_error_policy(mut self, policy: SampleErrorPolicy) -> Self {
        self.on_sample_error = policy;
        self
    }

    /// Changes same-user iteration behavior.
    #[must_use]
    pub const fn with_same_user_on_next_iteration(mut self, value: bool) -> Self {
        self.same_user_on_next_iteration = value;
        self
    }

    /// Sets the number of root-controller iterations for each user.
    #[must_use]
    pub const fn with_iterations(mut self, value: Option<u64>) -> Self {
        self.iterations = value;
        self
    }

    /// Uses the complete built-in controller state machine for this group.
    #[must_use]
    pub fn with_logic_controller(mut self, controller: LogicProgram) -> Self {
        self.logic_controller = Some(controller);
        self
    }
}

/// Immutable test plan plus run-wide lifecycle policy.
#[derive(Clone, Debug, Default)]
pub struct EnginePlan {
    /// Setup/main/teardown groups in source order.
    pub groups: Vec<ThreadGroupPlan>,
    /// Whether groups are started serially.
    pub serialize_thread_groups: bool,
    /// Whether teardown groups run after an immediate stop.
    pub teardown_on_shutdown: bool,
    /// Immutable TestPlan user-defined variables copied into each fresh user
    /// lifecycle before its first component or condition is evaluated.
    initial_variables: InitialVariables,
}

impl EnginePlan {
    /// Creates an empty engine plan.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            groups: Vec::new(),
            serialize_thread_groups: false,
            teardown_on_shutdown: true,
            initial_variables: InitialVariables::empty(),
        }
    }

    /// Returns the immutable TestPlan variable seed.
    #[must_use]
    pub const fn initial_variables(&self) -> &InitialVariables {
        &self.initial_variables
    }

    /// Installs a previously validated immutable TestPlan variable seed.
    #[must_use]
    pub fn with_initial_variables(mut self, initial: InitialVariables) -> Self {
        self.initial_variables = initial;
        self
    }

    /// Validates and installs a TestPlan variable map without exposing a
    /// mutable map inside the executable plan.
    pub fn try_with_initial_variables(
        self,
        values: BTreeMap<String, String>,
    ) -> Result<Self, InitialVariablesError> {
        Ok(self.with_initial_variables(InitialVariables::try_from_map(values)?))
    }

    /// Replaces the seed before a run is admitted.
    pub fn set_initial_variables(&mut self, initial: InitialVariables) {
        self.initial_variables = initial;
    }

    /// Validates a replacement map before mutating this plan.  On error the
    /// existing immutable seed remains unchanged.
    pub fn try_set_initial_variables(
        &mut self,
        values: BTreeMap<String, String>,
    ) -> Result<(), InitialVariablesError> {
        let initial = InitialVariables::try_from_map(values)?;
        self.set_initial_variables(initial);
        Ok(())
    }

    /// Adds a source-order group, enforcing a finite group bound.
    pub fn push_group(&mut self, group: ThreadGroupPlan) -> Result<(), EngineError> {
        if self.groups.len() >= MAX_GROUPS {
            return Err(EngineError::ResourceLimit {
                detail: "thread-group limit".to_owned(),
            });
        }
        self.groups.push(group);
        Ok(())
    }
}

/// One runtime virtual user's owned mutable state.
#[derive(Debug)]
pub struct VirtualUser {
    /// Stable lifecycle identity used by expression state.
    pub lifecycle_id: u64,
    /// Group identity.
    pub group_id: NodeId,
    /// User number within the group.
    pub thread_number: usize,
    /// Per-user iteration counters.
    pub iteration: IterationState,
    /// Per-user execution context.
    pub context: ExecutionContext,
}

impl VirtualUser {
    fn new(
        lifecycle_id: u64,
        group: &ThreadGroupPlan,
        thread_number: usize,
        run_id: &RunIdentity,
        host: &HostIdentity,
        capabilities: &RuntimeCapabilities,
        initial_variables: &InitialVariables,
    ) -> Result<Self, InitialVariablesError> {
        let mut context = ExecutionContext::with_capabilities(capabilities.clone_for_user());
        context.seed_initial_variables(initial_variables)?;
        context.set_run(run_id.clone());
        context.set_host(host.clone());
        context.set_thread(ThreadIdentity::with_group(
            format!("{}-{}", group.name, thread_number),
            Some(group.name.clone()),
            Some(thread_number as u64),
        ));
        context.set_lifecycle_id(Some(lifecycle_id));
        context.set_iteration_id(Some(0));
        Ok(Self {
            lifecycle_id,
            group_id: group.id,
            thread_number,
            iteration: IterationState::default(),
            context,
        })
    }
}

/// Observable engine lifecycle and sample events.
#[derive(Clone, Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "event consumers use one stable inline sample payload"
)]
#[allow(
    missing_docs,
    reason = "event payload fields are documented by variant semantics"
)]
pub enum EngineEvent {
    /// Test run began.
    TestStarted,
    /// Engine entered a lifecycle mode.
    ModeStarted(EngineMode),
    /// Group began spawning users.
    GroupStarted { id: NodeId, kind: GroupKind },
    /// A virtual user started.
    UserStarted {
        group_id: NodeId,
        thread_number: usize,
        lifecycle_id: u64,
    },
    /// A sample report was produced.
    Sample {
        group_id: NodeId,
        thread_number: usize,
        sampler_id: NodeId,
        result: Option<SampleResult>,
        failure: Option<SampleFailure>,
        signal: ControlSignal,
    },
    /// A root iteration completed.
    Iteration {
        group_id: NodeId,
        thread_number: usize,
        iteration: u64,
    },
    /// A virtual user finished.
    UserFinished {
        group_id: NodeId,
        thread_number: usize,
        lifecycle_id: u64,
    },
    /// Group finished.
    GroupFinished { id: NodeId, kind: GroupKind },
    /// Test run ended.
    TestFinished { signal: ControlSignal },
}

/// Aggregate report returned by a run.
#[derive(Clone, Debug)]
pub struct EngineReport {
    /// Immutable ordered lifecycle/sample trace.  Summary mode leaves this
    /// allocation empty; full-trace reports clone only the `Arc` handle.
    pub trace: RunObservationTraceV1,
    /// Backwards-compatible alias for [`EngineReport::trace`].  Both fields
    /// point at the same immutable allocation and never deep-clone events.
    pub events: RunObservationTraceV1,
    /// Checked constant-memory observation counters.
    pub summary: RunObservationSummaryV1,
    /// Highest cancellation signal observed.
    pub signal: ControlSignal,
    /// Number of users started.
    pub users_started: usize,
    /// Number of users finished.
    pub users_finished: usize,
}

impl Default for EngineReport {
    fn default() -> Self {
        let trace: RunObservationTraceV1 = Arc::from(Vec::<EngineEvent>::new().into_boxed_slice());
        Self {
            trace: Arc::clone(&trace),
            events: trace,
            summary: RunObservationSummaryV1::default(),
            signal: ControlSignal::Continue,
            users_started: 0,
            users_finished: 0,
        }
    }
}

struct ActiveTransaction {
    info: TransactionInfo,
    parent_id: Option<u64>,
    plan_path: Vec<NodeId>,
    result: SampleResult,
    unrepresented_timers: Duration,
}

struct CriticalSectionScope {
    controller_id: u64,
    name: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CriticalSectionSyncOutcome {
    /// The desired scope stack is held and the sampler may run.
    Acquired,
    /// Runtime cancellation was observed while waiting for a scope.
    Cancelled(ControlSignal),
}

struct PendingCriticalAcquisition {
    coordinator: Arc<dyn crate::CriticalSectionCoordinator>,
    name: String,
    lifecycle_id: u64,
    armed: bool,
}

impl PendingCriticalAcquisition {
    fn new(
        coordinator: Arc<dyn crate::CriticalSectionCoordinator>,
        name: impl Into<String>,
        lifecycle_id: u64,
    ) -> Self {
        Self {
            coordinator,
            name: name.into(),
            lifecycle_id,
            armed: false,
        }
    }

    fn arm(&mut self) {
        self.armed = true;
    }

    fn disarm(&mut self) {
        self.armed = false;
    }

    fn cancel(&mut self) -> Result<(), CriticalSectionError> {
        if !self.armed {
            return Ok(());
        }
        self.armed = false;
        self.coordinator
            .cancel_acquire(&self.name, self.lifecycle_id)
            .map(|_| ())
    }
}

impl Drop for PendingCriticalAcquisition {
    fn drop(&mut self) {
        if self.armed {
            // A dropped run future is itself cancellation. The coordinator
            // operation is synchronous and bounded, so it is safe to retire
            // the exact queued request from Drop when no poll can observe the
            // cancellation signal again.
            let _ = self
                .coordinator
                .cancel_acquire(&self.name, self.lifecycle_id);
            self.armed = false;
        }
    }
}

struct CriticalSectionLeases {
    coordinator: Arc<dyn crate::CriticalSectionCoordinator>,
    lifecycle_id: u64,
    /// Held scopes in outer-to-inner order. This stack spans sampler
    /// selections until the controller path exits the corresponding scope.
    scopes: Vec<CriticalSectionScope>,
    drop_error: Arc<Mutex<Vec<CriticalSectionError>>>,
}

impl CriticalSectionLeases {
    fn new(context: &ExecutionContext) -> Self {
        Self {
            coordinator: context.capabilities().critical_sections_arc(),
            lifecycle_id: context.lifecycle_id().unwrap_or(0),
            scopes: Vec::new(),
            drop_error: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn set_lifecycle(&mut self, lifecycle_id: u64) {
        self.lifecycle_id = lifecycle_id;
    }

    fn release_all(&mut self) -> Vec<CriticalSectionError> {
        let scopes = std::mem::take(&mut self.scopes);
        let mut errors = Vec::new();
        for scope in scopes.into_iter().rev() {
            if let Err(error) = self.coordinator.release(&scope.name, self.lifecycle_id) {
                errors.push(error);
            }
        }
        errors
    }

    fn take_drop_errors(&self) -> Vec<CriticalSectionError> {
        std::mem::take(&mut *lock(&self.drop_error))
    }

    async fn synchronize(
        &mut self,
        group_id: NodeId,
        selection: &crate::LogicSelection,
        cancellation: &CancellationToken,
    ) -> Result<CriticalSectionSyncOutcome, EngineError> {
        if selection.critical_sections.len() != selection.critical_section_ids.len() {
            return Err(EngineError::ResourceLimit {
                detail: "critical-section selection identity/name mismatch".to_owned(),
            });
        }

        let desired = selection
            .critical_section_ids
            .iter()
            .copied()
            .zip(selection.critical_sections.iter().cloned())
            .map(|(controller_id, name)| CriticalSectionScope {
                controller_id,
                name,
            })
            .collect::<Vec<_>>();
        let common = self
            .scopes
            .iter()
            .zip(&desired)
            .take_while(|(held, wanted)| {
                held.controller_id == wanted.controller_id && held.name == wanted.name
            })
            .count();

        let mut release_errors = Vec::new();
        while self.scopes.len() > common {
            let scope = self
                .scopes
                .pop()
                .ok_or_else(|| EngineError::ResourceLimit {
                    detail: "critical-section lease stack underflow".to_owned(),
                })?;
            if let Err(error) = self.coordinator.release(&scope.name, self.lifecycle_id) {
                release_errors.push(error);
            }
        }
        if let Some(error) = critical_section_errors(group_id, release_errors) {
            return Err(error);
        }
        if cancellation.signal().is_stop() {
            return Ok(CriticalSectionSyncOutcome::Cancelled(cancellation.signal()));
        }

        for scope in desired.into_iter().skip(common) {
            match poll_critical_section_acquire(
                Arc::clone(&self.coordinator),
                group_id,
                scope.name.clone(),
                self.lifecycle_id,
                cancellation.clone(),
            )
            .await?
            {
                CriticalSectionSyncOutcome::Acquired => self.scopes.push(scope),
                CriticalSectionSyncOutcome::Cancelled(signal) => {
                    return Ok(CriticalSectionSyncOutcome::Cancelled(signal));
                }
            }
        }
        if cancellation.signal().is_stop() {
            return Ok(CriticalSectionSyncOutcome::Cancelled(cancellation.signal()));
        }
        Ok(CriticalSectionSyncOutcome::Acquired)
    }

    fn release_error(&mut self, group_id: NodeId) -> Option<EngineError> {
        let mut errors = self.release_all();
        errors.extend(self.take_drop_errors());
        critical_section_errors(group_id, errors)
    }
}

impl Drop for CriticalSectionLeases {
    fn drop(&mut self) {
        let errors = self.release_all();
        if !errors.is_empty() {
            lock(&self.drop_error).extend(errors);
        }
    }
}

fn critical_section_errors(
    group_id: NodeId,
    errors: Vec<CriticalSectionError>,
) -> Option<EngineError> {
    let mut aggregate = None;
    for source in errors {
        combine_engine_error(
            &mut aggregate,
            EngineError::CriticalSection { group_id, source },
        );
    }
    aggregate
}

async fn poll_critical_section_acquire(
    coordinator: Arc<dyn crate::CriticalSectionCoordinator>,
    group_id: NodeId,
    name: String,
    lifecycle_id: u64,
    cancellation: CancellationToken,
) -> Result<CriticalSectionSyncOutcome, EngineError> {
    let mut pending =
        PendingCriticalAcquisition::new(Arc::clone(&coordinator), name.clone(), lifecycle_id);
    let mut acquired = false;
    future::poll_fn(|context| {
        let signal = cancellation.signal();
        if signal.is_stop() {
            let cancel_result = pending
                .cancel()
                .map_err(|source| EngineError::CriticalSection { group_id, source });
            let release_result = if acquired {
                acquired = false;
                coordinator
                    .release(&name, lifecycle_id)
                    .map_err(|source| EngineError::CriticalSection { group_id, source })
            } else {
                Ok(())
            };
            return Poll::Ready(match (cancel_result, release_result) {
                (Ok(()), Ok(())) => Ok(CriticalSectionSyncOutcome::Cancelled(signal)),
                (Err(primary), Ok(())) | (Ok(()), Err(primary)) => Err(primary),
                (Err(primary), Err(secondary)) => Err(combined_engine_error(primary, secondary)),
            });
        }

        match coordinator.poll_acquire(&name, lifecycle_id, context.waker()) {
            Poll::Pending => {
                pending.arm();
                cancellation.register_waker(context.waker());
                // Close the race where cancellation was requested between
                // the signal check and waker registration.
                if cancellation.signal().is_stop() {
                    context.waker().wake_by_ref();
                }
                Poll::Pending
            }
            Poll::Ready(Ok(())) => {
                acquired = true;
                if cancellation.signal().is_stop() {
                    let signal = cancellation.signal();
                    let cancel_result = pending
                        .cancel()
                        .map_err(|source| EngineError::CriticalSection { group_id, source });
                    acquired = false;
                    let release_result = coordinator
                        .release(&name, lifecycle_id)
                        .map_err(|source| EngineError::CriticalSection { group_id, source });
                    return Poll::Ready(match (cancel_result, release_result) {
                        (Ok(()), Ok(())) => Ok(CriticalSectionSyncOutcome::Cancelled(signal)),
                        (Err(primary), Ok(())) | (Ok(()), Err(primary)) => Err(primary),
                        (Err(primary), Err(secondary)) => {
                            Err(combined_engine_error(primary, secondary))
                        }
                    });
                }
                pending.disarm();
                Poll::Ready(Ok(CriticalSectionSyncOutcome::Acquired))
            }
            Poll::Ready(Err(source)) => {
                Poll::Ready(Err(EngineError::CriticalSection { group_id, source }))
            }
        }
    })
    .await
}

struct LifecycleCleanupGuard {
    cleanup: Arc<dyn crate::ExpressionStateCleanup>,
    lifecycle_id: Option<u64>,
    armed: bool,
    drop_error: Arc<Mutex<Option<EngineError>>>,
}

impl LifecycleCleanupGuard {
    fn new(context: &ExecutionContext) -> Self {
        Self {
            cleanup: context.capabilities().expression_cleanup(),
            lifecycle_id: context.lifecycle_id(),
            armed: true,
            drop_error: Arc::new(Mutex::new(None)),
        }
    }

    fn clear(&mut self) -> Result<(), EngineError> {
        if self.armed {
            self.armed = false;
            if let Some(lifecycle_id) = self.lifecycle_id {
                self.cleanup
                    .clear_for_lifecycle(lifecycle_id)
                    .map_err(|source| EngineError::ExpressionCleanup {
                        lifecycle_id,
                        source,
                    })?;
            }
        }
        Ok(())
    }

    fn take_drop_error(&self) -> Option<EngineError> {
        lock(&self.drop_error).take()
    }

    fn set_lifecycle(&mut self, lifecycle_id: u64) {
        self.lifecycle_id = Some(lifecycle_id);
        self.armed = true;
    }
}

impl Drop for LifecycleCleanupGuard {
    fn drop(&mut self) {
        if let Err(error) = self.clear() {
            let mut slot = lock(&self.drop_error);
            if slot.is_none() {
                *slot = Some(error);
            }
        }
    }
}

/// Typed engine failures.
#[derive(Clone, Debug, PartialEq)]
#[allow(
    missing_docs,
    reason = "error payload fields are documented by variant semantics"
)]
pub enum EngineError {
    /// Invalid schedule or lifecycle setting.
    InvalidSchedule { detail: String },
    /// Resource limit was exceeded.
    ResourceLimit { detail: String },
    /// An injected scheduler/sleeper capability rejected a lifecycle delay.
    Capability { detail: String },
    /// Controller transition failed.
    Controller {
        group_id: NodeId,
        source: ControllerError,
    },
    /// Complete logic-controller traversal failed.
    Logic {
        group_id: NodeId,
        source: crate::LogicControllerError,
    },
    /// Required sampler package was absent.
    MissingPackage {
        group_id: NodeId,
        sampler_id: NodeId,
    },
    /// A user package could not be isolated from the immutable plan.
    Package {
        group_id: NodeId,
        source: PackageCompileError,
    },
    /// The immutable TestPlan initial-variable seed could not be applied to a
    /// fresh virtual-user context.
    InitialVariables { source: InitialVariablesError },
    /// A critical-section acquisition or release failed.
    CriticalSection {
        group_id: NodeId,
        source: CriticalSectionError,
    },
    /// Expression state cleanup failed while ending a virtual-user lifecycle.
    ExpressionCleanup {
        lifecycle_id: u64,
        source: crate::ComponentError,
    },
    /// Sample pipeline failed.
    Pipeline {
        group_id: NodeId,
        sampler_id: NodeId,
        source: PipelineError,
    },
    /// Run-level result routing or sink admission failed.
    ResultRouter { source: ResultRouterError },
    /// Run-level typed result routing or effectful sink finalization failed.
    TypedResultRouter { source: TypedRouterError },
    /// Run-level observation retention or counter accounting failed.
    Observation { source: ObservationError },
    /// Run-level semantic progress accounting failed.
    Progress { source: ProgressError },
    /// A lifecycle failure occurred while another failure was already active.
    Combined {
        primary: Box<Self>,
        secondary: Box<Self>,
    },
}

impl EngineError {
    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidSchedule { .. } => "runtime.engine.invalid-schedule",
            Self::ResourceLimit { .. } => "runtime.engine.resource-limit",
            Self::Capability { .. } => "runtime.engine.capability",
            Self::Controller { .. } => "runtime.engine.controller",
            Self::Logic { .. } => "runtime.engine.logic",
            Self::MissingPackage { .. } => "runtime.engine.missing-package",
            Self::Package { .. } => "runtime.engine.package",
            Self::InitialVariables { .. } => "runtime.engine.initial-variables",
            Self::CriticalSection { .. } => "runtime.engine.critical-section",
            Self::ExpressionCleanup { .. } => "runtime.engine.expression-cleanup",
            Self::Pipeline { .. } => "runtime.engine.pipeline",
            Self::ResultRouter { .. } => "runtime.engine.result-router",
            Self::TypedResultRouter { .. } => "runtime.engine.typed-result-router",
            Self::Observation { .. } => "runtime.engine.observation",
            Self::Progress { .. } => "runtime.engine.progress",
            Self::Combined { .. } => "runtime.engine.combined",
        }
    }
}

impl fmt::Display for EngineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSchedule { detail }
            | Self::ResourceLimit { detail }
            | Self::Capability { detail } => {
                write!(formatter, "{}: {detail}", self.code())
            }
            Self::Controller { group_id, source } => {
                write!(formatter, "{} at group {group_id}: {source}", self.code())
            }
            Self::Logic { group_id, source } => {
                write!(formatter, "{} at group {group_id}: {source}", self.code())
            }
            Self::MissingPackage {
                group_id,
                sampler_id,
            } => write!(
                formatter,
                "{}: group {group_id}, sampler {sampler_id}",
                self.code()
            ),
            Self::Package { group_id, source } => {
                write!(formatter, "{} at group {group_id}: {source}", self.code())
            }
            Self::InitialVariables { source } => write!(formatter, "{}: {source}", self.code()),
            Self::CriticalSection { group_id, source } => {
                write!(formatter, "{} at group {group_id}: {source}", self.code())
            }
            Self::ExpressionCleanup {
                lifecycle_id,
                source,
            } => write!(
                formatter,
                "{} for lifecycle {lifecycle_id}: {source}",
                self.code()
            ),
            Self::Pipeline {
                group_id,
                sampler_id,
                source,
            } => write!(
                formatter,
                "{} at group {group_id}, sampler {sampler_id}: {source}",
                self.code()
            ),
            Self::ResultRouter { source } => write!(formatter, "{}: {source}", self.code()),
            Self::TypedResultRouter { source } => write!(formatter, "{}: {source}", self.code()),
            Self::Observation { source } => write!(formatter, "{}: {source}", self.code()),
            Self::Progress { source } => write!(formatter, "{}: {source}", self.code()),
            Self::Combined { primary, secondary } => write!(
                formatter,
                "{}: primary={primary}; secondary={secondary}",
                self.code()
            ),
        }
    }
}

impl std::error::Error for EngineError {}

/// Deterministic, executor-neutral polling of a bounded task set.
///
/// Tasks are visited in insertion order on every poll. The future never
/// creates an OS thread or chooses an ambient executor; pending component
/// futures retain ownership of their own wake registrations. Each parent
/// poll visits at most the bounded task set once; no lifetime poll counter is
/// used. A production/current-thread driver owns no-progress and wake-storm
/// detection, while this join never loops internally when all tasks are
/// pending.
struct DeterministicJoin<'a, T> {
    tasks: Vec<Pin<Box<dyn Future<Output = T> + 'a>>>,
    results: Vec<Option<T>>,
}

impl<'a, T> DeterministicJoin<'a, T> {
    fn new(tasks: Vec<Pin<Box<dyn Future<Output = T> + 'a>>>) -> Result<Self, EngineError> {
        if tasks.len() > MAX_CONCURRENT_TASKS {
            return Err(EngineError::ResourceLimit {
                detail: "deterministic concurrent task limit".to_owned(),
            });
        }
        let result_count = tasks.len();
        Ok(Self {
            tasks,
            results: (0..result_count).map(|_| None).collect(),
        })
    }
}

impl<T> Unpin for DeterministicJoin<'_, T> {}

impl<T> Future for DeterministicJoin<'_, T> {
    type Output = Result<Vec<T>, EngineError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.tasks.is_empty() {
            return Poll::Ready(Ok(Vec::new()));
        }
        for index in 0..this.tasks.len() {
            if this.results[index].is_some() {
                continue;
            }
            // One visit per task per parent poll is the complete turn.  The
            // task count is bounded by MAX_CONCURRENT_TASKS at every caller,
            // so this loop has a finite per-turn work bound.  Do not retain a
            // lifetime poll counter: a long run with real progress is not a
            // stalled scheduler merely because it has many turns.
            if let Poll::Ready(result) = this.tasks[index].as_mut().poll(context) {
                this.results[index] = Some(result);
            }
        }
        if this.results.iter().all(Option::is_some) {
            let mut values = Vec::with_capacity(this.results.len());
            for result in &mut this.results {
                if let Some(value) = result.take() {
                    values.push(value);
                } else {
                    return Poll::Ready(Err(EngineError::ResourceLimit {
                        detail: "deterministic concurrent scheduler state".to_owned(),
                    }));
                }
            }
            return Poll::Ready(Ok(values));
        }
        Poll::Pending
    }
}

/// Yields one deterministic scheduler turn without sleeping or touching an
/// executor. The waker notification lets a real executor resume the join;
/// deterministic test executors may simply poll again.
async fn cooperative_yield() {
    let mut yielded = false;
    future::poll_fn(move |context| {
        if yielded {
            Poll::Ready(())
        } else {
            yielded = true;
            context.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await;
}

async fn sleep_interruptibly(
    sleeper: &dyn crate::Sleeper,
    duration: Duration,
    cancellation: &CancellationToken,
) -> Result<bool, crate::CapabilityError> {
    let mut sleep = sleeper.sleep(duration);
    future::poll_fn(|context| {
        if cancellation.signal().is_stop() {
            return Poll::Ready(Ok(false));
        }
        match sleep.as_mut().poll(context) {
            Poll::Ready(result) => Poll::Ready(result.map(|()| true)),
            Poll::Pending => {
                cancellation.register_waker(context.waker());
                Poll::Pending
            }
        }
    })
    .await
}

struct UserTaskResult {
    result: Result<(), EngineError>,
    signal: ControlSignal,
    started: usize,
    finished: usize,
}

struct GroupTaskResult {
    id: NodeId,
    kind: GroupKind,
    report: EngineReport,
    result: Result<(), EngineError>,
}

/// A future returned by [`RuntimeEngine::run`].
///
/// The wrapper keeps the read-only progress handle alongside the borrowed run
/// future.  An application can therefore obtain progress before polling or
/// awaiting the run, without attempting a second mutable borrow of the
/// [`RuntimeEngine`].
pub struct RuntimeEngineFuture<'a> {
    inner: Pin<Box<dyn Future<Output = Result<EngineReport, EngineError>> + 'a>>,
    progress: ProgressHandle,
}

impl<'a> RuntimeEngineFuture<'a> {
    fn new(
        inner: Pin<Box<dyn Future<Output = Result<EngineReport, EngineError>> + 'a>>,
        progress: ProgressHandle,
    ) -> Self {
        Self { inner, progress }
    }

    /// Returns a cloned, read-only handle for this run's semantic progress.
    #[must_use]
    pub fn progress_handle(&self) -> ProgressHandle {
        self.progress.clone()
    }
}

impl Unpin for RuntimeEngineFuture<'_> {}

impl Future for RuntimeEngineFuture<'_> {
    type Output = Result<EngineReport, EngineError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.as_mut().poll(context)
    }
}

struct EngineRunDropGuard {
    router: Option<ResultRouter>,
    typed_router: Option<Arc<TypedResultRouterAdapter>>,
    cancellation: CancellationToken,
    observation: Arc<Mutex<ObservationState>>,
    progress: ProgressOwner,
    progress_error: Arc<Mutex<Option<ProgressError>>>,
    result_router_error: Arc<Mutex<Option<EngineError>>>,
    armed: bool,
}

impl EngineRunDropGuard {
    fn new(
        router: Option<ResultRouter>,
        typed_router: Option<Arc<TypedResultRouterAdapter>>,
        cancellation: CancellationToken,
        observation: Arc<Mutex<ObservationState>>,
        progress: ProgressOwner,
        progress_error: Arc<Mutex<Option<ProgressError>>>,
        result_router_error: Arc<Mutex<Option<EngineError>>>,
    ) -> Self {
        Self {
            router,
            typed_router,
            cancellation,
            observation,
            progress,
            progress_error,
            result_router_error,
            armed: true,
        }
    }

    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for EngineRunDropGuard {
    fn drop(&mut self) {
        if self.armed {
            // Publish the terminal progress state before waking interruptible
            // capability futures so observers cannot see an immediate stop
            // paired with a still-running progress owner.
            if let Err(source) = self.progress.cancel() {
                let mut error = lock(&self.progress_error);
                if error.is_none() {
                    *error = Some(source);
                }
            }
            // Dropping the run future is cancellation, not successful
            // completion.  Raise the run-wide immediate signal before
            // dropping child futures so interruptible capabilities can
            // observe it while their owners are being unwound.
            self.cancellation.cancel_immediate();
            lock(&self.observation).mark_cancelled();
            if let Some(router) = self.typed_router.as_ref()
                && let Err(source) = router.cancel()
            {
                let mut error = lock(&self.result_router_error);
                if error.is_none() {
                    *error = Some(EngineError::TypedResultRouter { source });
                }
            }
            if let Some(router) = self.router.as_ref() {
                if let Err(source) = router.cancel() {
                    let mut error = lock(&self.result_router_error);
                    if error.is_none() {
                        *error = Some(EngineError::ResultRouter { source });
                    }
                }
            }
        }
    }
}

/// Executor-neutral lifecycle engine.
pub struct RuntimeEngine {
    plan: EnginePlan,
    capabilities: RuntimeCapabilities,
    run_id: RunIdentity,
    host: HostIdentity,
    result_router: Option<ResultRouter>,
    typed_result_router: Option<Arc<TypedResultRouterAdapter>>,
    cancellation: CancellationToken,
    observation: Arc<Mutex<ObservationState>>,
    progress: Option<ProgressOwner>,
    progress_signal: Arc<Mutex<ControlSignal>>,
    progress_error: Arc<Mutex<Option<ProgressError>>>,
    result_router_error: Arc<Mutex<Option<EngineError>>>,
    next_lifecycle: Arc<AtomicU64>,
    next_sample: Arc<AtomicU64>,
    typed_admission_lock: Arc<Mutex<()>>,
    mode: EngineMode,
}

impl fmt::Debug for RuntimeEngine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeEngine")
            .field("plan", &self.plan)
            .field("run_id", &self.run_id)
            .field("host", &self.host)
            .field("result_router", &self.result_router)
            .field("typed_result_router", &self.typed_result_router)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl RuntimeEngine {
    /// Creates an engine for an immutable plan and explicit capabilities.
    #[must_use]
    pub fn new(
        plan: EnginePlan,
        capabilities: RuntimeCapabilities,
        run_id: impl Into<RunIdentity>,
        host: impl Into<HostIdentity>,
    ) -> Self {
        Self {
            plan,
            capabilities,
            run_id: run_id.into(),
            host: host.into(),
            result_router: None,
            typed_result_router: None,
            cancellation: CancellationToken::new(),
            observation: Arc::new(Mutex::new(ObservationState::new(
                RunObservationPolicyV1::Summary,
            ))),
            progress: None,
            progress_signal: Arc::new(Mutex::new(ControlSignal::Continue)),
            progress_error: Arc::new(Mutex::new(None)),
            result_router_error: Arc::new(Mutex::new(None)),
            next_lifecycle: Arc::new(AtomicU64::new(1)),
            next_sample: Arc::new(AtomicU64::new(1)),
            typed_admission_lock: Arc::new(Mutex::new(())),
            mode: EngineMode::Setup,
        }
    }

    fn clone_for_scheduler(&self) -> Self {
        Self {
            plan: self.plan.clone(),
            capabilities: self.capabilities.clone(),
            run_id: self.run_id.clone(),
            host: self.host.clone(),
            result_router: self.result_router.clone(),
            typed_result_router: self.typed_result_router.clone(),
            cancellation: self.cancellation.clone(),
            observation: Arc::clone(&self.observation),
            progress: self.progress.clone(),
            progress_signal: Arc::clone(&self.progress_signal),
            progress_error: Arc::clone(&self.progress_error),
            result_router_error: Arc::clone(&self.result_router_error),
            next_lifecycle: Arc::clone(&self.next_lifecycle),
            next_sample: Arc::clone(&self.next_sample),
            typed_admission_lock: Arc::clone(&self.typed_admission_lock),
            mode: self.mode,
        }
    }

    /// Returns the run-wide cancellation token.
    #[must_use]
    pub fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }

    /// Installs one run-owned result router.  The router is started
    /// transactionally by [`RuntimeEngine::run`] before any group begins.
    #[must_use]
    pub fn with_result_router(mut self, router: ResultRouter) -> Self {
        self.result_router = Some(router);
        self
    }

    /// Replaces the optional run-owned result router before a run starts.
    pub fn set_result_router(&mut self, router: Option<ResultRouter>) {
        self.result_router = router;
    }

    /// Returns the configured run-owned result router, if any.
    #[must_use]
    pub const fn result_router(&self) -> Option<&ResultRouter> {
        self.result_router.as_ref()
    }

    /// Installs the run-owned typed router/sink contract.  Its explicit
    /// plan/run/worker identity is used for every event; the deprecated
    /// compatibility router is disabled when this production path is chosen.
    #[must_use]
    pub fn with_typed_result_router(mut self, router: TypedResultRouterAdapter) -> Self {
        self.result_router = None;
        self.typed_result_router = Some(Arc::new(router));
        self
    }

    /// Replaces the run-owned typed router/sink contract before a run starts.
    pub fn set_typed_result_router(&mut self, router: Option<TypedResultRouterAdapter>) {
        self.result_router = None;
        self.typed_result_router = router.map(Arc::new);
    }

    /// Returns the shared typed router/sink contract, if configured.
    #[must_use]
    pub fn typed_result_router(&self) -> Option<Arc<TypedResultRouterAdapter>> {
        self.typed_result_router.clone()
    }

    /// Returns the immutable plan.
    #[must_use]
    pub const fn plan(&self) -> &EnginePlan {
        &self.plan
    }

    /// Returns the configured observation policy.
    #[must_use]
    pub fn observation_policy(&self) -> RunObservationPolicyV1 {
        lock(&self.observation).policy()
    }

    /// Selects an observation policy before a run starts.
    pub fn set_observation_policy(
        &mut self,
        policy: RunObservationPolicyV1,
    ) -> Result<(), EngineError> {
        lock(&self.observation)
            .set_policy(policy)
            .map_err(|source| EngineError::Observation { source })
    }

    /// Returns the run summary without exposing mutable observation state.
    #[must_use]
    pub fn summary(&self) -> RunObservationSummaryV1 {
        lock(&self.observation).summary()
    }

    /// Returns a progress error captured while a pending run was dropped.
    ///
    /// A `Drop` implementation cannot return an error. Keeping this typed
    /// diagnostic on the owning engine prevents an exceptional terminal path
    /// from becoming an ignored progress mutation.
    #[must_use]
    pub fn last_progress_error(&self) -> Option<ProgressError> {
        lock(&self.progress_error).as_ref().copied()
    }

    /// Returns a result-router error captured while a pending run was
    /// dropped. A drop path cannot return an error, so the owning engine keeps
    /// this diagnostic for explicit inspection.
    #[must_use]
    pub fn last_result_router_error(&self) -> Option<EngineError> {
        lock(&self.result_router_error).clone()
    }

    /// Returns an immutable shared trace from the most recent terminal run.
    #[must_use]
    pub fn trace(&self) -> RunObservationTraceV1 {
        lock(&self.observation).trace()
    }

    /// Returns retained event snapshots from a previous/current run.
    #[must_use]
    pub fn events(&self) -> RunObservationTraceV1 {
        self.trace()
    }

    /// Selects a policy while constructing an engine.
    #[must_use]
    pub fn with_observation_policy(mut self, policy: RunObservationPolicyV1) -> Self {
        // A newly-created engine cannot be running, so replacing the state is
        // infallible while the mutable setter remains explicit.
        self.observation = Arc::new(Mutex::new(ObservationState::new(policy)));
        self
    }

    /// Starts one run. The future owns no executor and performs no ambient
    /// I/O; all component effects enter through their explicit capabilities.
    pub fn run<'a>(&'a mut self) -> RuntimeEngineFuture<'a> {
        // Every invocation gets a new allocation.  Replacing the engine's
        // owner (rather than resetting it) keeps handles from an earlier run
        // permanently attached to that run's terminal state.
        let progress = ProgressOwner::new();
        self.progress = Some(progress.clone());
        self.progress_signal = Arc::new(Mutex::new(ControlSignal::Continue));
        let progress_handle = progress.handle();
        debug_assert_eq!(progress.snapshot(), progress_handle.snapshot());
        let begin = lock(&self.observation)
            .begin_run()
            .map_err(|source| EngineError::Observation { source });
        let typed_router_for_guard = self.typed_result_router.clone();
        let guard = begin.as_ref().ok().map(|_| {
            EngineRunDropGuard::new(
                self.result_router.clone(),
                typed_router_for_guard,
                self.cancellation.clone(),
                Arc::clone(&self.observation),
                progress.clone(),
                Arc::clone(&self.progress_error),
                Arc::clone(&self.result_router_error),
            )
        });
        let inner = Box::pin(async move {
            let guard = match guard {
                Some(guard) => guard,
                None => {
                    let primary = match begin {
                        Ok(()) => EngineError::Observation {
                            source: ObservationError::AlreadyRunning,
                        },
                        Err(error) => error,
                    };
                    return Err(match progress.fail() {
                        Ok(_) => primary,
                        Err(source) => {
                            combined_engine_error(primary, EngineError::Progress { source })
                        }
                    });
                }
            };
            let (primary, finalization) = if let Some(router) = self.typed_result_router.clone() {
                // The typed adapter owns one run-shared ResultDeliveryBudget
                // and its wait registrar. Runtime only drives the lifecycle;
                // it never borrows mutable budget state across unrelated
                // awaits and never invents a run-duration ceiling.
                let primary = self.run_inner().await;
                let finish = router
                    .finish()
                    .await
                    .err()
                    .map(|source| EngineError::TypedResultRouter { source });
                (primary, finish)
            } else {
                let primary = self.run_inner().await;
                let finalization = if let Some(router) = self.result_router.as_ref() {
                    let delivered_before = router.stats().delivered_items;
                    let finish = router
                        .finish()
                        .await
                        .err()
                        .map(|source| EngineError::ResultRouter { source });
                    let delivery_progress = if router.stats().delivered_items > delivered_before {
                        progress
                            .advance()
                            .err()
                            .map(|source| EngineError::Progress { source })
                    } else {
                        None
                    };
                    match (finish, delivery_progress) {
                        (None, None) => None,
                        (Some(error), None) | (None, Some(error)) => Some(error),
                        (Some(primary), Some(secondary)) => {
                            Some(combined_engine_error(primary, secondary))
                        }
                    }
                } else {
                    None
                };
                (primary, finalization)
            };
            let result = match (primary, finalization) {
                (Ok(report), None) => Ok(report),
                (Ok(_), Some(error)) => Err(error),
                (Err(primary), None) => Err(primary),
                (Err(primary), Some(secondary)) => Err(EngineError::Combined {
                    primary: Box::new(primary),
                    secondary: Box::new(secondary),
                }),
            };
            let result = match result {
                Ok(report) => match progress.complete() {
                    Ok(_) => Ok(report),
                    Err(source) => Err(EngineError::Progress { source }),
                },
                Err(primary) => match progress.fail() {
                    Ok(_) => Err(primary),
                    Err(source) => Err(combined_engine_error(
                        primary,
                        EngineError::Progress { source },
                    )),
                },
            };
            let terminal = if result.is_ok() {
                RunObservationTerminalState::Completed
            } else {
                RunObservationTerminalState::Failed
            };
            let (summary, trace) = {
                let mut observation = lock(&self.observation);
                observation.finish(terminal);
                (observation.summary(), observation.trace())
            };
            // Terminalization was attempted exactly once, including the
            // typed-error path. Do not let Drop attempt a second terminal
            // transition with a different state.
            guard.disarm();
            match result {
                Ok(mut report) => {
                    report.summary = summary;
                    report.signal = report.summary.highest_control_signal;
                    report.trace = Arc::clone(&trace);
                    report.events = trace;
                    Ok(report)
                }
                Err(error) => Err(error),
            }
        });
        RuntimeEngineFuture::new(inner, progress_handle)
    }

    async fn run_inner(&mut self) -> Result<EngineReport, EngineError> {
        if let Some(router) = self.typed_result_router.as_ref() {
            router
                .start()
                .await
                .map_err(|source| EngineError::TypedResultRouter { source })?;
        } else if let Some(router) = self.result_router.as_ref() {
            router
                .start()
                .await
                .map_err(|source| EngineError::ResultRouter { source })?;
        }
        self.push_event(EngineEvent::TestStarted)?;
        let mut report = EngineReport::default();
        let groups = self.plan.groups.clone();
        let shared_logic = Arc::new(LogicSharedState::default());
        let mut failure: Option<EngineError> = None;
        for mode in [EngineMode::Setup, EngineMode::Main, EngineMode::Teardown] {
            self.mode = mode;
            if let Err(error) = self.push_event(EngineEvent::ModeStarted(mode)) {
                combine_engine_error(&mut failure, error);
                self.cancellation.cancel_immediate();
                continue;
            }
            let kind = match mode {
                EngineMode::Setup => GroupKind::Setup,
                EngineMode::Main => GroupKind::Main,
                EngineMode::Teardown => GroupKind::Teardown,
                EngineMode::Complete => continue,
            };
            let candidates = groups
                .iter()
                .filter(|group| group.kind == kind)
                .filter(|group| {
                    group_allowed_after_stop(&self.plan, group, self.cancellation.signal())
                })
                .cloned()
                .collect::<Vec<_>>();
            if !self.plan.serialize_thread_groups && candidates.len() > 1 {
                let phase_start = self.capabilities.clock().now().monotonic;
                let mut tasks = Vec::with_capacity(candidates.len());
                for group in candidates {
                    if tasks.len() >= MAX_CONCURRENT_TASKS {
                        combine_engine_error(
                            &mut failure,
                            EngineError::ResourceLimit {
                                detail: "thread-group task limit".to_owned(),
                            },
                        );
                        self.cancellation.cancel_immediate();
                        break;
                    }
                    let shared_logic = Arc::clone(&shared_logic);
                    let mut runtime = self.clone_for_scheduler();
                    tasks.push(Box::pin(async move {
                        let id = group.id;
                        let kind = group.kind;
                        let mut group_report = EngineReport::default();
                        let result = runtime
                            .run_group(&group, &mut group_report, shared_logic, phase_start, true)
                            .await;
                        let result = match result {
                            Ok(()) => Ok(()),
                            Err(primary) => {
                                runtime.cancellation.cancel_immediate();
                                let mut group_error = Some(primary);
                                if let Err(secondary) =
                                    runtime.push_event(EngineEvent::GroupFinished { id, kind })
                                {
                                    combine_engine_error(&mut group_error, secondary);
                                }
                                match group_error {
                                    Some(error) => Err(error),
                                    None => Ok(()),
                                }
                            }
                        };
                        GroupTaskResult {
                            id,
                            kind,
                            report: group_report,
                            result,
                        }
                    })
                        as Pin<Box<dyn Future<Output = GroupTaskResult>>>);
                }
                match DeterministicJoin::new(tasks) {
                    Ok(join) => match join.await {
                        Ok(results) => {
                            for result in results {
                                let _ = (result.id, result.kind);
                                report.users_started = report
                                    .users_started
                                    .saturating_add(result.report.users_started);
                                report.users_finished = report
                                    .users_finished
                                    .saturating_add(result.report.users_finished);
                                report.signal = report.signal.combine(result.report.signal);
                                if let Err(error) = result.result {
                                    combine_engine_error(&mut failure, error);
                                    self.cancellation.cancel_immediate();
                                }
                            }
                        }
                        Err(error) => {
                            combine_engine_error(&mut failure, error);
                            self.cancellation.cancel_immediate();
                        }
                    },
                    Err(error) => {
                        combine_engine_error(&mut failure, error);
                        self.cancellation.cancel_immediate();
                    }
                }
                continue;
            }
            for group in candidates {
                let signal = self.cancellation.signal();
                if !group_allowed_after_stop(&self.plan, &group, signal) {
                    continue;
                }
                let group_start = self.capabilities.clock().now().monotonic;
                if let Err(error) = self
                    .run_group(
                        &group,
                        &mut report,
                        Arc::clone(&shared_logic),
                        group_start,
                        group.threads > 1,
                    )
                    .await
                {
                    let mut group_error = Some(error);
                    if let Err(close_error) = self.push_event(EngineEvent::GroupFinished {
                        id: group.id,
                        kind: group.kind,
                    }) {
                        combine_engine_error(&mut group_error, close_error);
                    }
                    if let Some(group_error) = group_error {
                        combine_engine_error(&mut failure, group_error);
                    }
                    self.cancellation.cancel_immediate();
                    if kind != GroupKind::Teardown {
                        break;
                    }
                }
                if self.cancellation.signal() == ControlSignal::StopTestImmediate
                    && kind != GroupKind::Teardown
                {
                    break;
                }
            }
            // Immediate stop bypasses the remainder of setup/main. Teardown
            // policy is evaluated in its own phase above.
        }
        self.mode = EngineMode::Complete;
        report.signal = report.signal.combine(self.cancellation.signal());
        if let Err(error) = self.push_event(EngineEvent::TestFinished {
            signal: report.signal,
        }) {
            combine_engine_error(&mut failure, error);
        }
        if let Some(router) = self.typed_result_router.as_ref()
            && let Err(error) = router.deliver().await
        {
            combine_engine_error(
                &mut failure,
                EngineError::TypedResultRouter { source: error },
            );
        }
        report.summary = self.summary();
        if let Some(error) = failure {
            Err(error)
        } else {
            Ok(report)
        }
    }

    async fn run_group(
        &mut self,
        group: &ThreadGroupPlan,
        report: &mut EngineReport,
        shared_logic: Arc<LogicSharedState>,
        group_start: Duration,
        cooperative: bool,
    ) -> Result<(), EngineError> {
        if group.threads > MAX_THREADS {
            return Err(EngineError::InvalidSchedule {
                detail: "thread count exceeds runtime bound".to_owned(),
            });
        }
        if group.threads > MAX_CONCURRENT_TASKS {
            return Err(EngineError::ResourceLimit {
                detail: "virtual-user task limit".to_owned(),
            });
        }
        let ramp = group.schedule.ramp(group.threads)?;
        let duration_end = group.schedule.checked_duration_end(group_start)?;
        self.push_event(EngineEvent::GroupStarted {
            id: group.id,
            kind: group.kind,
        })?;
        if cooperative {
            cooperative_yield().await;
        }
        let mut tasks = Vec::with_capacity(group.threads);
        let mut preparation_error = None;
        for thread_index in 0..group.threads {
            if self.cancellation.signal().is_stop() && group.kind != GroupKind::Teardown {
                break;
            }
            if duration_end.is_some_and(|end| self.capabilities.clock().now().monotonic >= end) {
                break;
            }
            let offset = group
                .schedule
                .delay
                .checked_add(ramp.offset(thread_index)?)
                .ok_or_else(|| EngineError::InvalidSchedule {
                    detail: "group schedule delay overflow".to_owned(),
                })?;
            let target =
                group_start
                    .checked_add(offset)
                    .ok_or_else(|| EngineError::InvalidSchedule {
                        detail: "group user startup target overflow".to_owned(),
                    })?;
            let thread_number =
                thread_index
                    .checked_add(1)
                    .ok_or_else(|| EngineError::InvalidSchedule {
                        detail: "thread number overflow".to_owned(),
                    })?;
            let group_id = group.id;
            let group_kind = group.kind;
            let mut runtime = self.clone_for_scheduler();
            let shared_logic = Arc::clone(&shared_logic);
            tasks.push(Box::pin(async move {
                let mut task_report = EngineReport::default();
                let now = runtime.capabilities.clock().now().monotonic;
                let delta = target.saturating_sub(now);
                if !delta.is_zero() {
                    let sleep_result = if group_kind == GroupKind::Teardown {
                        runtime
                            .capabilities
                            .sleeper()
                            .sleep(delta)
                            .await
                            .map(|()| true)
                    } else {
                        sleep_interruptibly(
                            runtime.capabilities.sleeper(),
                            delta,
                            &runtime.cancellation,
                        )
                        .await
                    };
                    match sleep_result {
                        Ok(true) => {}
                        Ok(false) => {
                            return UserTaskResult {
                                result: Ok(()),
                                signal: runtime.cancellation.signal(),
                                started: 0,
                                finished: 0,
                            };
                        }
                        Err(error) => {
                            return UserTaskResult {
                                result: Err(EngineError::Capability {
                                    detail: error.to_string(),
                                }),
                                signal: runtime.cancellation.signal(),
                                started: 0,
                                finished: 0,
                            };
                        }
                    }
                }
                if (runtime.cancellation.signal().is_stop() && group_kind != GroupKind::Teardown)
                    || duration_end
                        .is_some_and(|end| runtime.capabilities.clock().now().monotonic >= end)
                {
                    return UserTaskResult {
                        result: Ok(()),
                        signal: runtime.cancellation.signal(),
                        started: 0,
                        finished: 0,
                    };
                }
                let lifecycle_id = match runtime.allocate_lifecycle_id() {
                    Ok(id) => id,
                    Err(error) => {
                        return UserTaskResult {
                            result: Err(error),
                            signal: runtime.cancellation.signal(),
                            started: 0,
                            finished: 0,
                        };
                    }
                };
                let mut user = match VirtualUser::new(
                    lifecycle_id,
                    group,
                    thread_number,
                    &runtime.run_id,
                    &runtime.host,
                    &runtime.capabilities,
                    &runtime.plan.initial_variables,
                ) {
                    Ok(user) => user,
                    Err(source) => {
                        return UserTaskResult {
                            result: Err(EngineError::InitialVariables { source }),
                            signal: runtime.cancellation.signal(),
                            started: 0,
                            finished: 0,
                        };
                    }
                };
                let mut cleanup = LifecycleCleanupGuard::new(&user.context);
                if group_kind != GroupKind::Teardown {
                    user.context.attach_cancellation(&runtime.cancellation);
                }
                task_report.users_started = 1;
                if let Err(error) = runtime.push_event(EngineEvent::UserStarted {
                    group_id,
                    thread_number,
                    lifecycle_id,
                }) {
                    let result = match cleanup.clear() {
                        Ok(()) => error,
                        Err(cleanup_error) => combined_engine_error(error, cleanup_error),
                    };
                    return UserTaskResult {
                        result: Err(result),
                        signal: runtime.cancellation.signal(),
                        started: 1,
                        finished: 0,
                    };
                }
                if cooperative {
                    cooperative_yield().await;
                }
                let packages = match group.packages.clone_for_user() {
                    Ok(packages) => packages,
                    Err(source) => {
                        let cleanup_result = cleanup.clear();
                        task_report.users_finished = 1;
                        let finish_result = runtime.push_event(EngineEvent::UserFinished {
                            group_id,
                            thread_number,
                            lifecycle_id,
                        });
                        let package_error = EngineError::Package { group_id, source };
                        let mut result = package_error;
                        if let Err(cleanup_error) = cleanup_result {
                            result = combined_engine_error(result, cleanup_error);
                        }
                        if let Err(finish_error) = finish_result {
                            result = combined_engine_error(result, finish_error);
                        }
                        runtime.cancellation.cancel_immediate();
                        return UserTaskResult {
                            result: Err(result),
                            signal: runtime.cancellation.signal(),
                            started: 1,
                            finished: 1,
                        };
                    }
                };
                let run_result = runtime
                    .run_user(
                        group,
                        group_start,
                        duration_end,
                        &mut user,
                        &mut task_report,
                        packages,
                        shared_logic,
                        &mut cleanup,
                        cooperative,
                    )
                    .await;
                let cleanup_result = cleanup.clear();
                let cleanup_result = match (cleanup_result, cleanup.take_drop_error()) {
                    (Ok(()), None) => Ok(()),
                    (Ok(()), Some(error)) => Err(error),
                    (Err(primary), None) => Err(primary),
                    (Err(primary), Some(secondary)) => {
                        Err(combined_engine_error(primary, secondary))
                    }
                };
                task_report.users_finished = 1;
                let finish_result = runtime.push_event(EngineEvent::UserFinished {
                    group_id,
                    thread_number,
                    lifecycle_id: user.lifecycle_id,
                });
                let mut result = None;
                if let Err(error) = run_result {
                    combine_engine_error(&mut result, error);
                }
                if let Err(error) = cleanup_result {
                    combine_engine_error(&mut result, error);
                }
                if let Err(error) = finish_result {
                    combine_engine_error(&mut result, error);
                }
                let result = result.map_or(Ok(()), Err);
                if result.is_err() {
                    runtime.cancellation.cancel_immediate();
                }
                UserTaskResult {
                    result,
                    signal: task_report.signal.combine(runtime.cancellation.signal()),
                    started: task_report.users_started,
                    finished: task_report.users_finished,
                }
            })
                as Pin<Box<dyn Future<Output = UserTaskResult>>>);
        }
        match DeterministicJoin::new(tasks) {
            Ok(join) => match join.await {
                Ok(results) => {
                    for result in results {
                        report.users_started = report.users_started.saturating_add(result.started);
                        report.users_finished =
                            report.users_finished.saturating_add(result.finished);
                        report.signal = report.signal.combine(result.signal);
                        if let Err(error) = result.result {
                            combine_engine_error(&mut preparation_error, error);
                        }
                    }
                }
                Err(error) => combine_engine_error(&mut preparation_error, error),
            },
            Err(error) => combine_engine_error(&mut preparation_error, error),
        }
        if let Some(error) = preparation_error {
            return Err(error);
        }
        self.push_event(EngineEvent::GroupFinished {
            id: group.id,
            kind: group.kind,
        })?;
        Ok(())
    }

    fn allocate_lifecycle_id(&self) -> Result<u64, EngineError> {
        self.next_lifecycle
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .map_err(|_| EngineError::InvalidSchedule {
                detail: "lifecycle identity overflow".to_owned(),
            })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the legacy and complete logic paths share explicit lifecycle state"
    )]
    async fn run_user(
        &mut self,
        group: &ThreadGroupPlan,
        group_start: Duration,
        duration_end: Option<Duration>,
        user: &mut VirtualUser,
        report: &mut EngineReport,
        mut packages: CompiledPackages,
        shared_logic: Arc<LogicSharedState>,
        cleanup: &mut LifecycleCleanupGuard,
        cooperative: bool,
    ) -> Result<(), EngineError> {
        if group.iterations == Some(0) {
            return Ok(());
        }
        if let Some(program) = group.logic_controller.clone() {
            return self
                .run_logic_user(
                    group,
                    group_start,
                    duration_end,
                    user,
                    report,
                    packages,
                    shared_logic,
                    program,
                    cleanup,
                    cooperative,
                )
                .await;
        }
        let mut runner = group.controller.runner();
        let mut completed_iterations = 0_u64;
        let mut transitions = 0usize;
        let max_transitions = group.packages.len().saturating_mul(65_536).max(65_536);
        loop {
            if transitions >= max_transitions {
                return Err(EngineError::ResourceLimit {
                    detail: "virtual-user controller transition limit".to_owned(),
                });
            }
            transitions = transitions.saturating_add(1);
            let signal = user.context.take_control_signal();
            let mut budget = crate::StepBudget::new(1_024);
            let step = runner
                .step_with_signal(signal, &mut budget)
                .map_err(|source| EngineError::Controller {
                    group_id: group.id,
                    source,
                })?;
            match step {
                ControllerStep::Complete => {
                    self.push_event(EngineEvent::Iteration {
                        group_id: group.id,
                        thread_number: user.thread_number,
                        iteration: user.iteration.current(),
                    })?;
                    user.iteration.advance()?;
                    user.context
                        .set_iteration_id(Some(user.iteration.current()));
                    completed_iterations = completed_iterations.saturating_add(1);
                    let continue_iterations = group
                        .iterations
                        .is_none_or(|limit| completed_iterations < limit)
                        && duration_end
                            .is_none_or(|end| self.capabilities.clock().now().monotonic < end);
                    if !continue_iterations {
                        break;
                    }
                    if !group.same_user_on_next_iteration {
                        cleanup.clear()?;
                        let lifecycle_id = self.allocate_lifecycle_id()?;
                        user.lifecycle_id = lifecycle_id;
                        user.context = VirtualUser::new(
                            lifecycle_id,
                            group,
                            user.thread_number,
                            &self.run_id,
                            &self.host,
                            &self.capabilities,
                            &self.plan.initial_variables,
                        )
                        .map_err(|source| EngineError::InitialVariables { source })?
                        .context;
                        if group.kind != GroupKind::Teardown {
                            user.context.attach_cancellation(&self.cancellation);
                        }
                        cleanup.set_lifecycle(lifecycle_id);
                        packages = group.packages.clone_for_user().map_err(|source| {
                            EngineError::Package {
                                group_id: group.id,
                                source,
                            }
                        })?;
                        runner = group.controller.runner();
                    } else {
                        runner
                            .next_root_iteration()
                            .map_err(|source| EngineError::Controller {
                                group_id: group.id,
                                source,
                            })?;
                    }
                }
                ControllerStep::Stopped(signal) => {
                    report.signal = report.signal.combine(signal);
                    self.observe_control_signal(signal)?;
                    if matches!(
                        signal,
                        ControlSignal::StopTestGraceful | ControlSignal::StopTestImmediate
                    ) {
                        self.cancellation.request(signal);
                    }
                    break;
                }
                ControllerStep::Sample(selection) => {
                    if duration_end
                        .is_some_and(|end| self.capabilities.clock().now().monotonic >= end)
                    {
                        break;
                    }
                    user.context
                        .set_sampler_name(Some(selection.sampler_id.to_string()));
                    let package = packages.get(NodeId::new(selection.sampler_id)).ok_or(
                        EngineError::MissingPackage {
                            group_id: group.id,
                            sampler_id: NodeId::new(selection.sampler_id),
                        },
                    )?;
                    let mut result = ExecutionPipeline::execute(package, &mut user.context)
                        .await
                        .map_err(|source| EngineError::Pipeline {
                            group_id: group.id,
                            sampler_id: package.sampler_id(),
                            source,
                        })?;
                    let signal = result.signal;
                    if !result.result.as_ref().is_some_and(SampleResult::is_ignored)
                        && let Some(event) = result.event.take()
                    {
                        self.route_event(
                            event,
                            group,
                            user,
                            vec![group.id, result.sampler_id],
                            ResultOrigin::Sampler {
                                sampler_id: result.sampler_id,
                                parent: None,
                            },
                        )?;
                    }
                    self.deliver_result_router().await?;
                    self.push_sample_event(
                        group.id,
                        user.thread_number,
                        result.sampler_id,
                        result.result.as_ref(),
                        result.sample_failure.as_ref(),
                        signal,
                        false,
                    )?;
                    report.signal = report.signal.combine(signal);
                    if result.sample_failure.is_some()
                        || result
                            .result
                            .as_ref()
                            .is_some_and(|result| result.success() == Some(false))
                    {
                        let policy_signal = group.on_sample_error.signal();
                        user.context.request_control(policy_signal);
                        report.signal = report.signal.combine(policy_signal);
                        self.observe_control_signal(policy_signal)?;
                        if matches!(
                            policy_signal,
                            ControlSignal::StopTestGraceful | ControlSignal::StopTestImmediate
                        ) {
                            self.cancellation.request(policy_signal);
                        }
                    }
                    if matches!(
                        signal,
                        ControlSignal::StopTestGraceful | ControlSignal::StopTestImmediate
                    ) {
                        self.cancellation.request(signal);
                    }
                    if signal == ControlSignal::NextLoop {
                        user.context.request_control(ControlSignal::NextLoop);
                    }
                    if cooperative {
                        cooperative_yield().await;
                    }
                }
            }
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the lifecycle seam keeps group, clock, user, report, package, shared-state, and program ownership explicit"
    )]
    async fn run_logic_user(
        &mut self,
        group: &ThreadGroupPlan,
        group_start: Duration,
        duration_end: Option<Duration>,
        user: &mut VirtualUser,
        report: &mut EngineReport,
        packages: CompiledPackages,
        shared_logic: Arc<LogicSharedState>,
        program: LogicProgram,
        cleanup: &mut LifecycleCleanupGuard,
        cooperative: bool,
    ) -> Result<(), EngineError> {
        let mut leases = CriticalSectionLeases::new(&user.context);
        let primary = self
            .run_logic_user_inner(
                group,
                group_start,
                duration_end,
                user,
                report,
                packages,
                shared_logic,
                program,
                cleanup,
                cooperative,
                &mut leases,
            )
            .await;
        let release_error = leases.release_error(group.id);
        match (primary, release_error) {
            (Ok(()), None) => Ok(()),
            (Ok(()), Some(secondary)) => Err(secondary),
            (Err(primary), None) => Err(primary),
            (Err(primary), Some(secondary)) => Err(combined_engine_error(primary, secondary)),
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the lifecycle seam keeps group, clock, user, report, package, shared-state, program, cleanup, and lease ownership explicit"
    )]
    async fn run_logic_user_inner(
        &mut self,
        group: &ThreadGroupPlan,
        group_start: Duration,
        duration_end: Option<Duration>,
        user: &mut VirtualUser,
        report: &mut EngineReport,
        mut packages: CompiledPackages,
        shared_logic: Arc<LogicSharedState>,
        program: LogicProgram,
        cleanup: &mut LifecycleCleanupGuard,
        cooperative: bool,
        leases: &mut CriticalSectionLeases,
    ) -> Result<(), EngineError> {
        if group.iterations == Some(0) {
            return Ok(());
        }
        let mut completed_iterations = 0_u64;
        let mut total_steps = 0usize;
        let max_steps = group
            .packages
            .len()
            .saturating_mul(program.limits().max_transitions)
            .max(program.limits().max_transitions);
        let mut runner = program.runner_with_shared_state(Arc::clone(&shared_logic));
        let mut last_sample_success = None;
        let mut transactions = BTreeMap::<u64, ActiveTransaction>::new();
        let mut transaction_order = Vec::<u64>::new();
        loop {
            let mut steps = 0usize;
            loop {
                steps = steps.saturating_add(1);
                total_steps = total_steps.saturating_add(1);
                if steps > max_steps || total_steps > max_steps {
                    return Err(EngineError::ResourceLimit {
                        detail: "virtual-user logic transition limit".to_owned(),
                    });
                }
                let signal = user.context.take_control_signal();
                let elapsed = user
                    .context
                    .capabilities()
                    .clock()
                    .now()
                    .monotonic
                    .checked_sub(group_start)
                    .ok_or_else(|| EngineError::InvalidSchedule {
                        detail: "group clock moved before startup".to_owned(),
                    })?;
                runner.replace_variables(&user.context.variables());
                let mut input = LogicInput {
                    signal,
                    last_sample_success,
                    elapsed,
                    random_value: None,
                };
                let step =
                    loop {
                        let step =
                            runner
                                .step(input.clone())
                                .map_err(|source| EngineError::Logic {
                                    group_id: group.id,
                                    source,
                                })?;
                        if !matches!(step, LogicStep::NeedsRandom) {
                            break step;
                        }
                        input.random_value =
                            Some(user.context.capabilities().random().next_u64().map_err(
                                |error| EngineError::Capability {
                                    detail: error.to_string(),
                                },
                            )?);
                    };
                match step {
                    LogicStep::Complete => {
                        if let Some(error) = leases.release_error(group.id) {
                            return Err(error);
                        }
                        break;
                    }
                    LogicStep::NeedsRandom => continue,
                    LogicStep::Stopped(signal) => {
                        report.signal = report.signal.combine(signal);
                        self.observe_control_signal(signal)?;
                        let lease_error = leases.release_error(group.id);
                        let mut stop_error = None;
                        if let Err(error) = self.finish_transactions(
                            group,
                            user,
                            report,
                            &mut transactions,
                            &mut transaction_order,
                        ) {
                            combine_engine_error(&mut stop_error, error);
                        }
                        if let Err(error) = self.deliver_result_router().await {
                            combine_engine_error(&mut stop_error, error);
                        }
                        if matches!(
                            signal,
                            ControlSignal::StopTestGraceful | ControlSignal::StopTestImmediate
                        ) {
                            self.cancellation.request(signal);
                        }
                        if let Some(error) = lease_error {
                            combine_engine_error(&mut stop_error, error);
                        }
                        if let Some(error) = stop_error {
                            return Err(error);
                        }
                        return Ok(());
                    }
                    LogicStep::Sample(selection) => {
                        if duration_end.is_some_and(|end| {
                            user.context.capabilities().clock().now().monotonic >= end
                        }) {
                            let lease_error = leases.release_error(group.id);
                            let mut duration_error = None;
                            if let Err(error) = self.finish_transactions(
                                group,
                                user,
                                report,
                                &mut transactions,
                                &mut transaction_order,
                            ) {
                                combine_engine_error(&mut duration_error, error);
                            }
                            if let Err(error) = self.deliver_result_router().await {
                                combine_engine_error(&mut duration_error, error);
                            }
                            if let Some(error) = lease_error {
                                combine_engine_error(&mut duration_error, error);
                            }
                            if let Some(error) = duration_error {
                                return Err(error);
                            }
                            return Ok(());
                        }
                        let runner_variables = runner.variables_owned();
                        user.context.variables_mut().clone_from(&runner_variables);
                        self.sync_transactions(
                            group,
                            user,
                            report,
                            &mut transactions,
                            &mut transaction_order,
                            &selection.path,
                            &selection.transaction_details,
                        )?;
                        user.context
                            .set_sampler_name(Some(selection.sampler_id.to_string()));
                        let package = packages.get(NodeId::new(selection.sampler_id)).ok_or(
                            EngineError::MissingPackage {
                                group_id: group.id,
                                sampler_id: NodeId::new(selection.sampler_id),
                            },
                        )?;
                        let cancellation = user.context.cancellation_token().clone();
                        match leases
                            .synchronize(group.id, &selection, &cancellation)
                            .await?
                        {
                            CriticalSectionSyncOutcome::Acquired => {}
                            CriticalSectionSyncOutcome::Cancelled(signal) => {
                                report.signal = report.signal.combine(signal);
                                self.observe_control_signal(signal)?;
                                let lease_error = leases.release_error(group.id);
                                let mut cancellation_error = None;
                                if let Err(error) = self.finish_transactions(
                                    group,
                                    user,
                                    report,
                                    &mut transactions,
                                    &mut transaction_order,
                                ) {
                                    combine_engine_error(&mut cancellation_error, error);
                                }
                                if let Err(error) = self.deliver_result_router().await {
                                    combine_engine_error(&mut cancellation_error, error);
                                }
                                if let Some(error) = lease_error {
                                    combine_engine_error(&mut cancellation_error, error);
                                }
                                if let Some(error) = cancellation_error {
                                    return Err(error);
                                }
                                return Ok(());
                            }
                        };
                        let mut result = ExecutionPipeline::execute(package, &mut user.context)
                            .await
                            .map_err(|source| EngineError::Pipeline {
                                group_id: group.id,
                                sampler_id: package.sampler_id(),
                                source,
                            })?;
                        let context_variables = user.context.variables().clone();
                        runner.replace_variables(&context_variables);
                        if let Some(sample) = result.result.as_ref() {
                            last_sample_success = sample.success();
                        }
                        let result_signal = result.signal;
                        if !result.result.as_ref().is_some_and(SampleResult::is_ignored)
                            && let Some(event) = result.event.take()
                        {
                            let mut plan_path = Vec::with_capacity(selection.path.len() + 2);
                            plan_path.push(group.id);
                            plan_path
                                .extend(selection.path.iter().map(|cursor| NodeId::new(cursor.id)));
                            plan_path.push(result.sampler_id);
                            self.route_event(
                                event,
                                group,
                                user,
                                plan_path,
                                ResultOrigin::Sampler {
                                    sampler_id: result.sampler_id,
                                    parent: transaction_order.last().copied().map(NodeId::new),
                                },
                            )?;
                        }
                        self.deliver_result_router().await?;
                        if let Some(child) = result.result.clone()
                            && let Some(id) = transaction_order.last().copied()
                            && let Some(transaction) = transactions.get_mut(&id)
                        {
                            transaction
                                .result
                                .append_sub_result(child)
                                .map_err(|error| EngineError::ResourceLimit {
                                    detail: format!(
                                        "transaction {} aggregation: {error}",
                                        transaction.info.id
                                    ),
                                })?;
                            if transaction.info.include_timers && !result.timer_delay.is_zero() {
                                add_transaction_timer(&mut transaction.result, result.timer_delay)
                                    .map_err(|error| EngineError::ResourceLimit {
                                        detail: format!(
                                            "transaction {} timer aggregation: {error}",
                                            transaction.info.id
                                        ),
                                    })?;
                            }
                            if !transaction.info.include_timers {
                                transaction.unrepresented_timers = transaction
                                    .unrepresented_timers
                                    .checked_add(result.timer_delay)
                                    .ok_or_else(|| EngineError::ResourceLimit {
                                        detail: format!(
                                            "transaction {} timer overflow",
                                            transaction.info.id
                                        ),
                                    })?;
                            }
                        }
                        if result.result.is_none()
                            && !result.timer_delay.is_zero()
                            && let Some(id) = transaction_order.last().copied()
                            && let Some(transaction) = transactions.get_mut(&id)
                        {
                            if transaction.info.include_timers {
                                add_transaction_timer(&mut transaction.result, result.timer_delay)
                                    .map_err(|error| EngineError::ResourceLimit {
                                        detail: format!(
                                            "transaction {} timer aggregation: {error}",
                                            transaction.info.id
                                        ),
                                    })?;
                            } else {
                                transaction.unrepresented_timers = transaction
                                    .unrepresented_timers
                                    .checked_add(result.timer_delay)
                                    .ok_or_else(|| EngineError::ResourceLimit {
                                        detail: format!(
                                            "transaction {} timer overflow",
                                            transaction.info.id
                                        ),
                                    })?;
                            }
                        }
                        self.push_sample_event(
                            group.id,
                            user.thread_number,
                            result.sampler_id,
                            result.result.as_ref(),
                            result.sample_failure.as_ref(),
                            result_signal,
                            false,
                        )?;
                        report.signal = report.signal.combine(result_signal);
                        if result.sample_failure.is_some()
                            || result
                                .result
                                .as_ref()
                                .is_some_and(|result| result.success() == Some(false))
                        {
                            let policy_signal = group.on_sample_error.signal();
                            user.context.request_control(policy_signal);
                            report.signal = report.signal.combine(policy_signal);
                            self.observe_control_signal(policy_signal)?;
                            if matches!(
                                policy_signal,
                                ControlSignal::StopTestGraceful | ControlSignal::StopTestImmediate
                            ) {
                                self.cancellation.request(policy_signal);
                            }
                        }
                        if matches!(
                            result_signal,
                            ControlSignal::StopTestGraceful | ControlSignal::StopTestImmediate
                        ) {
                            self.cancellation.request(result_signal);
                        }
                        if cooperative {
                            cooperative_yield().await;
                        }
                    }
                }
            }
            let lease_error = leases.release_error(group.id);
            let transaction_result = self.finish_transactions(
                group,
                user,
                report,
                &mut transactions,
                &mut transaction_order,
            );
            if let Err(primary) = transaction_result {
                return Err(match lease_error {
                    Some(secondary) => combined_engine_error(primary, secondary),
                    None => primary,
                });
            }
            if let Some(error) = lease_error {
                return Err(error);
            }
            self.deliver_result_router().await?;
            self.push_event(EngineEvent::Iteration {
                group_id: group.id,
                thread_number: user.thread_number,
                iteration: user.iteration.current(),
            })?;
            user.iteration.advance()?;
            user.context
                .set_iteration_id(Some(user.iteration.current()));
            completed_iterations = completed_iterations.saturating_add(1);
            if !group
                .iterations
                .is_none_or(|limit| completed_iterations < limit)
                || duration_end
                    .is_some_and(|end| user.context.capabilities().clock().now().monotonic >= end)
            {
                break;
            }
            if !group.same_user_on_next_iteration {
                cleanup.clear()?;
                let lifecycle_id = self.allocate_lifecycle_id()?;
                user.lifecycle_id = lifecycle_id;
                user.context = VirtualUser::new(
                    lifecycle_id,
                    group,
                    user.thread_number,
                    &self.run_id,
                    &self.host,
                    &self.capabilities,
                    &self.plan.initial_variables,
                )
                .map_err(|source| EngineError::InitialVariables { source })?
                .context;
                if group.kind != GroupKind::Teardown {
                    user.context.attach_cancellation(&self.cancellation);
                }
                cleanup.set_lifecycle(lifecycle_id);
                leases.set_lifecycle(lifecycle_id);
                packages =
                    group
                        .packages
                        .clone_for_user()
                        .map_err(|source| EngineError::Package {
                            group_id: group.id,
                            source,
                        })?;
                runner = program.runner_with_shared_state(Arc::clone(&shared_logic));
                last_sample_success = None;
            } else {
                runner
                    .next_root_iteration()
                    .map_err(|source| EngineError::Logic {
                        group_id: group.id,
                        source,
                    })?;
            }
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "transaction synchronization keeps runtime ownership, user identity, active state, and selected plan path explicit"
    )]
    fn sync_transactions(
        &self,
        group: &ThreadGroupPlan,
        user: &VirtualUser,
        report: &mut EngineReport,
        active: &mut BTreeMap<u64, ActiveTransaction>,
        order: &mut Vec<u64>,
        path: &[crate::LogicCursor],
        current: &[TransactionInfo],
    ) -> Result<(), EngineError> {
        let current_ids = current.iter().map(|info| info.id).collect::<BTreeSet<_>>();
        let closed = order
            .iter()
            .rev()
            .filter(|id| !current_ids.contains(id))
            .copied()
            .collect::<Vec<_>>();
        for id in closed {
            if let Some(transaction) = active.remove(&id) {
                if let Some(parent_id) = transaction.parent_id
                    && let Some(parent) = active.get_mut(&parent_id)
                {
                    append_nested_transaction(parent, &transaction)?;
                }
                self.emit_transaction(group, user, report, transaction)?;
            }
        }
        for (index, info) in current.iter().enumerate() {
            if active.contains_key(&info.id) {
                continue;
            }
            active.insert(
                info.id,
                ActiveTransaction {
                    info: info.clone(),
                    parent_id: index
                        .checked_sub(1)
                        .and_then(|parent| current.get(parent).map(|transaction| transaction.id)),
                    plan_path: {
                        let mut plan_path = Vec::with_capacity(path.len() + 2);
                        plan_path.push(group.id);
                        for cursor in path {
                            plan_path.push(NodeId::new(cursor.id));
                            if cursor.id == info.id {
                                break;
                            }
                        }
                        if plan_path.last().copied() != Some(NodeId::new(info.id)) {
                            plan_path.push(NodeId::new(info.id));
                        }
                        plan_path
                    },
                    result: SampleResult::new(format!("Transaction-{}", info.id)),
                    unrepresented_timers: Duration::ZERO,
                },
            );
            order.push(info.id);
        }
        order.retain(|id| active.contains_key(id));
        Ok(())
    }

    fn finish_transactions(
        &self,
        group: &ThreadGroupPlan,
        user: &VirtualUser,
        report: &mut EngineReport,
        active: &mut BTreeMap<u64, ActiveTransaction>,
        order: &mut Vec<u64>,
    ) -> Result<(), EngineError> {
        let transaction_order = std::mem::take(order);
        for id in transaction_order.into_iter().rev() {
            if let Some(transaction) = active.remove(&id) {
                if let Some(parent_id) = transaction.parent_id
                    && let Some(parent) = active.get_mut(&parent_id)
                {
                    append_nested_transaction(parent, &transaction)?;
                }
                self.emit_transaction(group, user, report, transaction)?;
            }
        }
        Ok(())
    }

    fn emit_transaction(
        &self,
        group: &ThreadGroupPlan,
        user: &VirtualUser,
        report: &mut EngineReport,
        transaction: ActiveTransaction,
    ) -> Result<(), EngineError> {
        let result = if transaction.info.parent {
            transaction.result
        } else {
            transaction_result_without_children(&transaction.result).map_err(|error| {
                EngineError::ResourceLimit {
                    detail: format!("transaction {} flattening: {error}", transaction.info.id),
                }
            })?
        };
        let event =
            user.context
                .sample_event(&result)
                .map_err(|source| EngineError::ResultRouter {
                    source: ResultRouterError::InvalidConfiguration {
                        detail: format!("transaction event snapshot failed: {source}"),
                    },
                })?;
        self.route_event(
            event,
            group,
            user,
            transaction.plan_path,
            ResultOrigin::Transaction {
                controller_id: NodeId::new(transaction.info.id),
                parent: transaction.parent_id.map(NodeId::new),
            },
        )?;
        self.push_sample_event(
            group.id,
            user.thread_number,
            NodeId::new(transaction.info.id),
            Some(&result),
            None,
            ControlSignal::Continue,
            true,
        )?;
        report.signal = report.signal.combine(ControlSignal::Continue);
        Ok(())
    }

    fn push_event(&self, event: EngineEvent) -> Result<(), EngineError> {
        let signal = match &event {
            EngineEvent::Sample { signal, .. } | EngineEvent::TestFinished { signal } => {
                Some(*signal)
            }
            _ => None,
        };
        lock(&self.observation)
            .record_event(event)
            .map_err(|source| EngineError::Observation { source })?;
        self.advance_progress()?;
        if let Some(signal) = signal {
            self.observe_control_signal(signal)?;
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "sample observation keeps lifecycle identities and borrowed payload facts explicit"
    )]
    fn push_sample_event(
        &self,
        group_id: NodeId,
        thread_number: usize,
        sampler_id: NodeId,
        result: Option<&SampleResult>,
        failure: Option<&SampleFailure>,
        signal: ControlSignal,
        transaction: bool,
    ) -> Result<(), EngineError> {
        lock(&self.observation)
            .record_sample(
                group_id,
                thread_number,
                sampler_id,
                result,
                failure,
                signal,
                transaction,
            )
            .map_err(|source| EngineError::Observation { source })?;
        self.advance_progress()?;
        self.observe_control_signal(signal)
    }

    fn advance_progress(&self) -> Result<(), EngineError> {
        self.progress
            .as_ref()
            .ok_or(EngineError::Progress {
                source: ProgressError::NotRunning {
                    state: crate::ProgressTerminalState::Cancelled,
                },
            })?
            .advance()
            .map(|_| ())
            .map_err(|source| EngineError::Progress { source })
    }

    fn observe_control_signal(&self, signal: ControlSignal) -> Result<(), EngineError> {
        let escalated = {
            let mut observed = lock(&self.progress_signal);
            if signal > *observed {
                *observed = signal;
                true
            } else {
                false
            }
        };
        if escalated {
            self.advance_progress()?;
        }
        Ok(())
    }

    fn route_event(
        &self,
        event: jmeter_rs_results::SampleEvent,
        group: &ThreadGroupPlan,
        user: &VirtualUser,
        plan_path: Vec<NodeId>,
        origin: ResultOrigin,
    ) -> Result<(), EngineError> {
        if let Some(router) = self.typed_result_router.as_ref() {
            // Sequence allocation and all-sink admission are one run-owned
            // transaction. Scheduler clones share this lock so two users
            // cannot both observe the same next sequence before admission.
            let _admission_guard = lock(&self.typed_admission_lock);
            let identity = router.identity();
            let source = router.node(origin.source_node()).map_err(|source| {
                EngineError::TypedResultRouter {
                    source: TypedRouterError::Identity(source),
                }
            })?;
            let qualified_path =
                router
                    .path(&plan_path)
                    .map_err(|source| EngineError::TypedResultRouter {
                        source: TypedRouterError::Identity(source),
                    })?;
            let group_ref =
                router
                    .node(group.id)
                    .map_err(|source| EngineError::TypedResultRouter {
                        source: TypedRouterError::Identity(source),
                    })?;
            let user_identity = TypedUserIdentity::new(
                user.lifecycle_id,
                group_ref,
                u64::try_from(user.thread_number).map_err(|_| EngineError::TypedResultRouter {
                    source: TypedRouterError::Identity(
                        crate::result_router::IdentityError::Overflow {
                            field: "thread-number",
                        },
                    ),
                })?,
                user.iteration.current(),
            )
            .map_err(|source| EngineError::TypedResultRouter {
                source: TypedRouterError::Identity(source),
            })?;
            let typed_origin = match origin {
                ResultOrigin::Sampler { sampler_id, parent } => TypedResultOrigin::Sampler {
                    sampler: router.node(sampler_id).map_err(|source| {
                        EngineError::TypedResultRouter {
                            source: TypedRouterError::Identity(source),
                        }
                    })?,
                    parent: parent
                        .map(|parent| router.node(parent))
                        .transpose()
                        .map_err(|source| EngineError::TypedResultRouter {
                            source: TypedRouterError::Identity(source),
                        })?,
                },
                ResultOrigin::Transaction {
                    controller_id,
                    parent,
                } => TypedResultOrigin::Transaction {
                    controller: router.node(controller_id).map_err(|source| {
                        EngineError::TypedResultRouter {
                            source: TypedRouterError::Identity(source),
                        }
                    })?,
                    parent: parent
                        .map(|parent| router.node(parent))
                        .transpose()
                        .map_err(|source| EngineError::TypedResultRouter {
                            source: TypedRouterError::Identity(source),
                        })?,
                },
            };
            let sample_value = self
                .next_sample
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    current.checked_add(1)
                })
                .map_err(|_| EngineError::TypedResultRouter {
                    source: TypedRouterError::Identity(
                        crate::result_router::IdentityError::Overflow { field: "sample-id" },
                    ),
                })?;
            let sample = TypedSampleId::new(sample_value).map_err(|source| {
                EngineError::TypedResultRouter {
                    source: TypedRouterError::Identity(source),
                }
            })?;
            let sequence = router
                .next_sequence()
                .map_err(|source| EngineError::TypedResultRouter { source })?;
            let envelope = TypedResultEnvelope::new(
                sequence,
                identity.run(),
                identity.run_generation(),
                identity.worker(),
                identity.worker_generation(),
                source,
                qualified_path,
                user_identity,
                event.thread().clone(),
                sample,
                typed_origin,
                event,
            )
            .map_err(|source| EngineError::TypedResultRouter {
                source: TypedRouterError::Identity(source),
            })?;
            let outcome = router
                .admit(envelope)
                .map_err(|source| EngineError::TypedResultRouter { source })?;
            return match outcome {
                TypedAdmissionOutcome::Accepted { .. } | TypedAdmissionOutcome::Ignored => Ok(()),
                outcome => Err(EngineError::TypedResultRouter {
                    source: TypedRouterError::Admission(outcome),
                }),
            };
        }
        let Some(router) = self.result_router.as_ref() else {
            return Ok(());
        };
        let metadata = ResultEventMetadata::new(
            origin.source_node(),
            plan_path,
            UserIdentity::new(
                user.lifecycle_id,
                group.id,
                user.thread_number as u64,
                user.iteration.current(),
            ),
            SampleIdentity::new(0),
            origin,
        )
        .map_err(|source| EngineError::ResultRouter { source })?;
        match router.admit(event, metadata) {
            AdmissionOutcome::Accepted { .. } | AdmissionOutcome::Ignored => Ok(()),
            outcome => Err(EngineError::ResultRouter {
                source: ResultRouterError::Admission { outcome },
            }),
        }
    }

    async fn deliver_result_router(&self) -> Result<(), EngineError> {
        // Typed production routing drains with the single run-owned budget at
        // the lifecycle boundary.  Per-sample calls remain no-ops here so
        // concurrently scheduled users cannot alias one mutable budget.
        if self.typed_result_router.is_some() {
            return Ok(());
        }
        if let Some(router) = self.result_router.as_ref() {
            let delivered_before = router.stats().delivered_items;
            router
                .deliver()
                .await
                .map_err(|source| EngineError::ResultRouter { source })?;
            // A successful delivery boundary is semantic progress distinct
            // from sample/transaction observation.  Waker activity while the
            // delivery future is pending does not reach this point.  An
            // empty drain is not an event and therefore does not advance the
            // run generation.
            if router.stats().delivered_items > delivered_before {
                self.advance_progress()?;
            }
        }
        Ok(())
    }
}

fn append_nested_transaction(
    parent: &mut ActiveTransaction,
    child: &ActiveTransaction,
) -> Result<(), EngineError> {
    if parent.info.include_timers && !child.unrepresented_timers.is_zero() {
        add_transaction_timer(&mut parent.result, child.unrepresented_timers).map_err(|error| {
            EngineError::ResourceLimit {
                detail: format!(
                    "transaction {} nested timer aggregation: {error}",
                    parent.info.id
                ),
            }
        })?;
    }
    parent
        .result
        .append_sub_result(child.result.clone())
        .map_err(|error| EngineError::ResourceLimit {
            detail: format!("transaction {} nested aggregation: {error}", parent.info.id),
        })?;
    if !parent.info.include_timers {
        parent.unrepresented_timers = parent
            .unrepresented_timers
            .checked_add(child.unrepresented_timers)
            .ok_or_else(|| EngineError::ResourceLimit {
                detail: format!("transaction {} timer overflow", parent.info.id),
            })?;
    }
    Ok(())
}

fn transaction_result_without_children(
    source: &SampleResult,
) -> Result<SampleResult, jmeter_rs_results::ResultError> {
    let mut result = SampleResult::new(source.label());
    result.set_success(source.success());
    result.set_response_code(source.response_code().map(str::to_owned));
    result.set_response_message(source.response_message().map(str::to_owned));
    result.set_failure_message(source.failure_message().map(str::to_owned));
    result.set_data_type(source.data_type().cloned());
    result.set_data_encoding(source.data_encoding().cloned());
    result.set_request_data(source.request_data().cloned());
    result.set_response_data(source.response_data().cloned());
    result.set_request_headers(source.request_headers().cloned());
    result.set_response_headers(source.response_headers().cloned());
    result.set_sampler_data(source.sampler_data().map(str::to_owned));
    result.set_response_file(source.response_file().map(str::to_owned));
    result.set_url(source.url().map(str::to_owned));
    result.set_start_time(source.start_time())?;
    result.set_end_time(source.end_time())?;
    result.set_elapsed(source.elapsed())?;
    result.set_latency(source.latency())?;
    result.set_connect_time(source.connect_time())?;
    result.set_idle_time(source.idle_time())?;
    result.set_received_bytes(source.received_bytes());
    result.set_sent_bytes(source.sent_bytes());
    result.set_group_threads(source.group_threads());
    result.set_all_threads(source.all_threads());
    result.set_sample_count(source.sample_count());
    result.set_error_count(source.error_count());
    result.set_flags(source.flags().clone());
    for assertion in source.assertions() {
        result.add_assertion(assertion.clone())?;
    }
    Ok(result)
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "deterministic lifecycle setup")]
mod tests {
    use super::*;
    use crate::result_router::{
        DeliveryLease, DurabilityAck, FullPolicy, PlanDomain, QualifiedSinkId,
        ResultDeliveryBudget, ResultMonotonicClock, ResultOperationScope, ResultOperationWindows,
        RetryBudget, RunGeneration, SinkPlanGeneration, TypedResultOrigin, TypedResultRouter,
        TypedResultRouterAdapter, TypedRouterIdentity, TypedRouterPhase, TypedRunId,
        TypedSinkAdapter, TypedSinkError, TypedSinkFuture, TypedSinkPlan, WorkerGeneration,
        WorkerId,
    };
    use crate::{
        CapabilityFuture, Clock, ClockReading, ComponentFuture, CriticalSectionCoordinator,
        ResultEnvelope, ResultOrigin, ResultRouter, ResultSink, ResultSinkFuture, ResultSinkSpec,
        RunSequence, SamplePackage, SamplerFactory, SamplerOutput, SinkId, SinkLimits, Sleeper,
        TimerFactory,
    };
    use jmeter_rs_expr::BuiltinFunctions;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

    struct TestResultClock;

    impl ResultMonotonicClock for TestResultClock {
        fn now(&self) -> Result<crate::MonotonicInstant, crate::result_router::ResultClockError> {
            Ok(crate::MonotonicInstant::zero())
        }
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = Box::pin(future);
        loop {
            match Pin::new(&mut future).poll(&mut context) {
                Poll::Ready(value) => return value,
                Poll::Pending => std::hint::spin_loop(),
            }
        }
    }

    fn trace_engine(
        plan: EnginePlan,
        capabilities: RuntimeCapabilities,
        run_id: &str,
        host: &str,
    ) -> RuntimeEngine {
        RuntimeEngine::new(plan, capabilities, run_id, host).with_observation_policy(
            RunObservationPolicyV1::full_trace(
                std::num::NonZeroUsize::new(100_000).expect("finite trace event bound"),
                std::num::NonZeroUsize::new(128 * 1024 * 1024).expect("finite trace byte bound"),
            ),
        )
    }

    struct Sampler;
    impl crate::Sampler for Sampler {
        fn sample<'a>(
            &'a self,
            _context: &'a mut crate::SampleContext<'_>,
        ) -> ComponentFuture<'a, SamplerOutput> {
            Box::pin(std::future::ready(Ok(SamplerOutput::result(
                SampleResult::new("sample"),
            ))))
        }
    }

    #[derive(Default)]
    struct RoutedEvents {
        events: Vec<(
            RunSequence,
            NodeId,
            ResultOrigin,
            String,
            RunIdentity,
            ThreadIdentity,
        )>,
        paths: Vec<Vec<NodeId>>,
    }

    struct RecordingResultSink {
        state: Arc<Mutex<RoutedEvents>>,
    }

    impl ResultSink for RecordingResultSink {
        fn write<'a>(&'a self, envelope: &'a ResultEnvelope) -> ResultSinkFuture<'a> {
            let state = Arc::clone(&self.state);
            Box::pin(std::future::ready({
                let mut state = lock(&state);
                state.events.push((
                    envelope.sequence(),
                    envelope.source_node(),
                    envelope.origin(),
                    envelope.event().result().label().to_owned(),
                    envelope.run().clone(),
                    envelope.thread().clone(),
                ));
                state.paths.push(envelope.plan_path().to_vec());
                Ok(())
            }))
        }
    }

    struct RecordingTypedSink {
        envelopes: Arc<Mutex<Vec<crate::result_router::TypedResultEnvelope>>>,
    }

    impl TypedSinkAdapter for RecordingTypedSink {
        fn process<'a>(
            &'a self,
            lease: &'a DeliveryLease,
            _operation: &'a crate::result_router::ResultOperationLease,
            _wait_registrar: &'a dyn crate::result_router::ResultWaitRegistrar,
        ) -> TypedSinkFuture<'a, DurabilityAck> {
            let envelope = lease.envelope().clone();
            let result = lease
                .acknowledge(lease.durability_boundary())
                .map_err(|error| TypedSinkError::permanent(error.to_string()));
            let envelopes = Arc::clone(&self.envelopes);
            Box::pin(std::future::ready({
                if result.is_ok() {
                    lock(&envelopes).push(envelope);
                }
                result
            }))
        }
    }

    struct SamplerFactoryImpl;
    impl SamplerFactory for SamplerFactoryImpl {
        fn create(&self) -> Arc<dyn crate::Sampler> {
            Arc::new(Sampler)
        }
    }

    struct ScopeTraceSampler {
        trace: Arc<Mutex<Vec<String>>>,
    }

    impl crate::Sampler for ScopeTraceSampler {
        fn sample<'a>(
            &'a self,
            context: &'a mut crate::SampleContext<'_>,
        ) -> ComponentFuture<'a, SamplerOutput> {
            let thread = context.execution().thread().name().to_owned();
            let sampler = context
                .execution()
                .sampler_name()
                .unwrap_or("unknown")
                .to_owned();
            lock(&self.trace).push(format!("{thread}:{sampler}"));
            Box::pin(std::future::ready(Ok(SamplerOutput::result(
                SampleResult::new(sampler),
            ))))
        }
    }

    struct ScopeTraceSamplerFactory {
        trace: Arc<Mutex<Vec<String>>>,
    }

    impl SamplerFactory for ScopeTraceSamplerFactory {
        fn create(&self) -> Arc<dyn crate::Sampler> {
            Arc::new(ScopeTraceSampler {
                trace: Arc::clone(&self.trace),
            })
        }
    }

    struct FailingScopeSampler;

    impl crate::Sampler for FailingScopeSampler {
        fn sample<'a>(
            &'a self,
            _context: &'a mut crate::SampleContext<'_>,
        ) -> ComponentFuture<'a, SamplerOutput> {
            Box::pin(std::future::ready(Err(crate::ComponentError::failure(
                "critical-section pipeline failure",
            ))))
        }
    }

    struct FailingScopeSamplerFactory;

    impl SamplerFactory for FailingScopeSamplerFactory {
        fn create(&self) -> Arc<dyn crate::Sampler> {
            Arc::new(FailingScopeSampler)
        }
    }

    struct RecordingCriticalCoordinator {
        inner: crate::DeterministicCriticalSectionCoordinator,
        events: Arc<Mutex<Vec<String>>>,
        cancellations: Arc<AtomicUsize>,
        fail_release: Arc<AtomicBool>,
    }

    impl crate::CriticalSectionCoordinator for RecordingCriticalCoordinator {
        fn try_acquire(
            &self,
            name: &str,
            lifecycle_id: u64,
        ) -> Result<(), crate::CriticalSectionError> {
            self.inner.try_acquire(name, lifecycle_id)
        }

        fn release(
            &self,
            name: &str,
            lifecycle_id: u64,
        ) -> Result<(), crate::CriticalSectionError> {
            lock(&self.events).push(format!("release:{name}:{lifecycle_id}"));
            if self.fail_release.load(Ordering::Acquire) {
                return Err(crate::CriticalSectionError::NotOwner {
                    name: name.to_owned(),
                    owner: lifecycle_id,
                });
            }
            self.inner.release(name, lifecycle_id)
        }

        fn poll_acquire(
            &self,
            name: &str,
            lifecycle_id: u64,
            waker: &Waker,
        ) -> Poll<Result<(), crate::CriticalSectionError>> {
            let result = self.inner.poll_acquire(name, lifecycle_id, waker);
            if matches!(result, Poll::Ready(Ok(()))) {
                lock(&self.events).push(format!("acquire:{name}:{lifecycle_id}"));
            }
            result
        }

        fn cancel_acquire(
            &self,
            name: &str,
            lifecycle_id: u64,
        ) -> Result<bool, crate::CriticalSectionError> {
            self.cancellations.fetch_add(1, Ordering::AcqRel);
            self.inner.cancel_acquire(name, lifecycle_id)
        }
    }

    struct CounterSampler {
        values: Arc<Mutex<Vec<String>>>,
        functions: Arc<BuiltinFunctions>,
    }

    impl crate::Sampler for CounterSampler {
        fn sample<'a>(
            &'a self,
            context: &'a mut crate::SampleContext<'_>,
        ) -> ComponentFuture<'a, SamplerOutput> {
            let value = context
                .execution()
                .evaluate_expression("${__counter(true)}", self.functions.as_ref())
                .map_err(|error| crate::ComponentError::failure(error.to_string()));
            let values = Arc::clone(&self.values);
            Box::pin(std::future::ready(value.map(|value| {
                lock(&values).push(value.clone());
                SamplerOutput::result(SampleResult::new(value))
            })))
        }
    }

    struct CounterSamplerFactory {
        values: Arc<Mutex<Vec<String>>>,
        functions: Arc<BuiltinFunctions>,
    }

    impl SamplerFactory for CounterSamplerFactory {
        fn create(&self) -> Arc<dyn crate::Sampler> {
            Arc::new(CounterSampler {
                values: Arc::clone(&self.values),
                functions: Arc::clone(&self.functions),
            })
        }
    }

    #[derive(Clone, Copy)]
    struct StaticClock;

    impl Clock for StaticClock {
        fn now(&self) -> ClockReading {
            ClockReading {
                wall: jmeter_rs_results::WallTimestamp::from_millis(0),
                monotonic: Duration::ZERO,
            }
        }
    }

    struct RecordingSleeper {
        delays: Arc<Mutex<Vec<Duration>>>,
    }

    impl Sleeper for RecordingSleeper {
        fn sleep<'a>(&'a self, duration: Duration) -> CapabilityFuture<'a, ()> {
            lock(&self.delays).push(duration);
            Box::pin(std::future::ready(Ok(())))
        }
    }

    struct PropertyRecordingSampler {
        values: Arc<Mutex<Vec<Option<String>>>>,
    }

    impl crate::Sampler for PropertyRecordingSampler {
        fn sample<'a>(
            &'a self,
            context: &'a mut crate::SampleContext<'_>,
        ) -> ComponentFuture<'a, SamplerOutput> {
            lock(&self.values).push(context.execution().property("shared"));
            Box::pin(std::future::ready(Ok(SamplerOutput::result(
                SampleResult::new("property"),
            ))))
        }
    }

    struct PropertyRecordingSamplerFactory {
        values: Arc<Mutex<Vec<Option<String>>>>,
    }

    impl SamplerFactory for PropertyRecordingSamplerFactory {
        fn create(&self) -> Arc<dyn crate::Sampler> {
            Arc::new(PropertyRecordingSampler {
                values: Arc::clone(&self.values),
            })
        }
    }

    struct InitialVariableSampler {
        seen: Arc<Mutex<Vec<String>>>,
    }

    impl crate::Sampler for InitialVariableSampler {
        fn sample<'a>(
            &'a self,
            context: &'a mut crate::SampleContext<'_>,
        ) -> ComponentFuture<'a, SamplerOutput> {
            let before = context
                .execution()
                .variable("seed")
                .unwrap_or_else(|| "<missing>".to_owned());
            lock(&self.seen).push(before);
            context.execution_mut().set_variable("seed", "mutated");
            Box::pin(std::future::ready(Ok(SamplerOutput::result(
                SampleResult::new("initial-variable"),
            ))))
        }
    }

    struct InitialVariableSamplerFactory {
        seen: Arc<Mutex<Vec<String>>>,
    }

    impl SamplerFactory for InitialVariableSamplerFactory {
        fn create(&self) -> Arc<dyn crate::Sampler> {
            Arc::new(InitialVariableSampler {
                seen: Arc::clone(&self.seen),
            })
        }
    }

    fn initial_variable_packages(seen: Arc<Mutex<Vec<String>>>) -> CompiledPackages {
        let package = SamplePackage::builder(
            NodeId::new(1),
            Arc::new(InitialVariableSampler {
                seen: Arc::clone(&seen),
            }),
        )
        .sampler_factory(Arc::new(InitialVariableSamplerFactory { seen }))
        .build();
        CompiledPackages::from_packages([package]).expect("initial-variable package")
    }

    struct StopFirstSampler {
        first: Arc<AtomicBool>,
        signal: ControlSignal,
    }

    impl crate::Sampler for StopFirstSampler {
        fn sample<'a>(
            &'a self,
            _context: &'a mut crate::SampleContext<'_>,
        ) -> ComponentFuture<'a, SamplerOutput> {
            let signal = if self.first.swap(false, Ordering::AcqRel) {
                self.signal
            } else {
                ControlSignal::Continue
            };
            Box::pin(std::future::ready(Ok(SamplerOutput::result(
                SampleResult::new("stop-thread"),
            )
            .with_signal(signal))))
        }
    }

    struct StopFirstSamplerFactory {
        first: Arc<AtomicBool>,
        signal: ControlSignal,
    }

    impl SamplerFactory for StopFirstSamplerFactory {
        fn create(&self) -> Arc<dyn crate::Sampler> {
            Arc::new(StopFirstSampler {
                first: Arc::clone(&self.first),
                signal: self.signal,
            })
        }
    }

    struct PolicyFailureSampler {
        invocations: Arc<AtomicUsize>,
    }

    impl crate::Sampler for PolicyFailureSampler {
        fn sample<'a>(
            &'a self,
            _context: &'a mut crate::SampleContext<'_>,
        ) -> ComponentFuture<'a, SamplerOutput> {
            self.invocations.fetch_add(1, Ordering::AcqRel);
            let mut result = SampleResult::new("policy-failure");
            result.set_successful(false);
            Box::pin(std::future::ready(Ok(SamplerOutput::failure(
                SampleFailure::new(NodeId::new(1), "deterministic sample failure")
                    .with_result(result),
            ))))
        }
    }

    struct PolicyFailureSamplerFactory {
        invocations: Arc<AtomicUsize>,
    }

    impl SamplerFactory for PolicyFailureSamplerFactory {
        fn create(&self) -> Arc<dyn crate::Sampler> {
            Arc::new(PolicyFailureSampler {
                invocations: Arc::clone(&self.invocations),
            })
        }
    }

    #[derive(Clone)]
    struct AdvancingClock {
        nanos: Arc<AtomicU64>,
    }

    impl Clock for AdvancingClock {
        fn now(&self) -> ClockReading {
            let nanos = self.nanos.load(Ordering::Acquire);
            let millis = nanos / 1_000_000;
            ClockReading {
                wall: jmeter_rs_results::WallTimestamp::from_millis(millis as i64),
                monotonic: Duration::from_nanos(nanos),
            }
        }
    }

    struct AdvanceClockSampler {
        nanos: Arc<AtomicU64>,
        invocations: Arc<AtomicUsize>,
    }

    impl crate::Sampler for AdvanceClockSampler {
        fn sample<'a>(
            &'a self,
            _context: &'a mut crate::SampleContext<'_>,
        ) -> ComponentFuture<'a, SamplerOutput> {
            self.invocations.fetch_add(1, Ordering::AcqRel);
            self.nanos.store(
                Duration::from_millis(10).as_nanos() as u64,
                Ordering::Release,
            );
            Box::pin(std::future::ready(Ok(SamplerOutput::result(
                SampleResult::new("advance-clock"),
            ))))
        }
    }

    struct AdvanceClockSamplerFactory {
        nanos: Arc<AtomicU64>,
        invocations: Arc<AtomicUsize>,
    }

    impl SamplerFactory for AdvanceClockSamplerFactory {
        fn create(&self) -> Arc<dyn crate::Sampler> {
            Arc::new(AdvanceClockSampler {
                nanos: Arc::clone(&self.nanos),
                invocations: Arc::clone(&self.invocations),
            })
        }
    }

    struct SequenceSampler {
        outputs: Arc<Mutex<Vec<SamplerOutput>>>,
    }

    impl crate::Sampler for SequenceSampler {
        fn sample<'a>(
            &'a self,
            _context: &'a mut crate::SampleContext<'_>,
        ) -> ComponentFuture<'a, SamplerOutput> {
            let output = lock(&self.outputs).pop().unwrap_or_default();
            Box::pin(std::future::ready(Ok(output)))
        }
    }

    struct SequenceSamplerFactory {
        outputs: Arc<Mutex<Vec<SamplerOutput>>>,
    }

    impl SamplerFactory for SequenceSamplerFactory {
        fn create(&self) -> Arc<dyn crate::Sampler> {
            Arc::new(SequenceSampler {
                outputs: Arc::clone(&self.outputs),
            })
        }
    }

    struct LifecycleRecordingSampler {
        lifecycle_ids: Arc<Mutex<Vec<Option<u64>>>>,
    }

    impl crate::Sampler for LifecycleRecordingSampler {
        fn sample<'a>(
            &'a self,
            context: &'a mut crate::SampleContext<'_>,
        ) -> ComponentFuture<'a, SamplerOutput> {
            lock(&self.lifecycle_ids).push(context.execution().lifecycle_id());
            Box::pin(std::future::ready(Ok(SamplerOutput::result(
                SampleResult::new("sample"),
            ))))
        }
    }

    struct LifecycleRecordingSamplerFactory {
        lifecycle_ids: Arc<Mutex<Vec<Option<u64>>>>,
    }

    impl SamplerFactory for LifecycleRecordingSamplerFactory {
        fn create(&self) -> Arc<dyn crate::Sampler> {
            Arc::new(LifecycleRecordingSampler {
                lifecycle_ids: Arc::clone(&self.lifecycle_ids),
            })
        }
    }

    struct RecordingExpressionCleanup {
        lifecycle_ids: Arc<Mutex<Vec<u64>>>,
    }

    impl crate::ExpressionStateCleanup for RecordingExpressionCleanup {
        fn clear_for_lifecycle(&self, lifecycle_id: u64) -> Result<(), crate::ComponentError> {
            lock(&self.lifecycle_ids).push(lifecycle_id);
            Ok(())
        }
    }

    #[derive(Clone, Copy, Default)]
    struct FailingExpressionCleanup;

    impl crate::ExpressionStateCleanup for FailingExpressionCleanup {
        fn clear_for_lifecycle(&self, _lifecycle_id: u64) -> Result<(), crate::ComponentError> {
            Err(crate::ComponentError::failure("expression cleanup failed"))
        }
    }

    struct FixedTimer;

    impl crate::Timer for FixedTimer {
        fn delay<'a>(
            &'a self,
            _context: &'a mut crate::SampleContext<'_>,
        ) -> ComponentFuture<'a, Duration> {
            Box::pin(std::future::ready(Ok(Duration::from_millis(5))))
        }
    }

    struct FixedTimerFactory;

    impl TimerFactory for FixedTimerFactory {
        fn create(&self) -> Arc<dyn crate::Timer> {
            Arc::new(FixedTimer)
        }
    }

    #[test]
    fn ramp_offsets_use_first_immediate_and_last_before_end() {
        let ramp = RampSchedule::new(10, Duration::from_secs(100)).expect("ramp");
        assert_eq!(ramp.offset(0).expect("first offset"), Duration::ZERO);
        assert_eq!(
            ramp.offset(9).expect("last offset"),
            Duration::from_secs(90)
        );
    }

    #[test]
    fn ramp_offsets_use_checked_arithmetic_at_duration_boundary() {
        let ramp = RampSchedule::new(3, Duration::MAX).expect("boundary ramp");
        let offset = ramp.offset(usize::MAX).expect("clamped boundary offset");
        let nanos = Duration::MAX.as_nanos() * 2 / 3;
        let expected = Duration::new(
            u64::try_from(nanos / 1_000_000_000).expect("seconds fit"),
            u32::try_from(nanos % 1_000_000_000).expect("subseconds fit"),
        );
        assert_eq!(offset, expected);
        assert_eq!(
            ramp.max_actual_user_offset().expect("maximum offset"),
            offset
        );
        assert_eq!(ramp.offsets().expect("all offsets").len(), 3);

        let empty = RampSchedule::new(0, Duration::MAX).expect("empty ramp");
        assert_eq!(
            empty.max_actual_user_offset().expect("empty maximum"),
            Duration::ZERO
        );
        assert!(empty.offsets().expect("empty offsets").is_empty());

        let unvalidated = RampSchedule {
            threads: MAX_THREADS + 1,
            ramp_up: Duration::MAX,
        };
        assert_eq!(
            unvalidated
                .offset(0)
                .expect_err("unvalidated public fields must remain bounded")
                .code(),
            "runtime.engine.invalid-schedule"
        );
    }

    #[test]
    fn group_schedule_checks_startup_and_duration_boundaries() {
        let overflow = GroupSchedule {
            delay: Duration::MAX,
            ramp_up: Duration::from_nanos(2),
            duration: None,
        };
        let error = overflow
            .startup_bound(3)
            .expect_err("delay plus actual ramp offset must reject overflow");
        assert_eq!(error.code(), "runtime.engine.invalid-schedule");
        assert!(matches!(
            error,
            EngineError::InvalidSchedule { detail }
                if detail == "group startup offset arithmetic overflow"
        ));

        let duration = GroupSchedule {
            delay: Duration::ZERO,
            ramp_up: Duration::ZERO,
            duration: Some(Duration::from_nanos(1)),
        };
        let error = duration
            .checked_duration_end(Duration::MAX)
            .expect_err("duration end must reject overflow");
        assert_eq!(error.code(), "runtime.engine.invalid-schedule");
    }

    #[test]
    fn representable_eight_day_schedule_has_no_product_ceiling() {
        let eight_days = Duration::from_secs(8 * 24 * 60 * 60);
        let schedule = GroupSchedule {
            delay: eight_days,
            ramp_up: eight_days,
            duration: None,
        };
        let ramp = schedule.ramp(2).expect("eight-day schedule");
        assert_eq!(ramp.offset(1).expect("last user offset"), eight_days / 2);
        assert_eq!(
            schedule.startup_bound(2).expect("startup bound"),
            eight_days + eight_days / 2
        );
    }

    #[test]
    fn deterministic_join_allows_progressing_runs_beyond_lifetime_poll_count() {
        const REQUIRED_POLLS: usize = 1_000_001;
        let mut remaining = REQUIRED_POLLS;
        let task: Pin<Box<dyn Future<Output = ()>>> = Box::pin(future::poll_fn(move |context| {
            if remaining == 0 {
                Poll::Ready(())
            } else {
                remaining -= 1;
                context.waker().wake_by_ref();
                Poll::Pending
            }
        }));
        let join = DeterministicJoin::new(vec![task]).expect("bounded join task set");
        let result = block_on(join);
        assert_eq!(result.expect("progressing join must complete"), vec![()]);
    }

    #[test]
    fn concurrent_users_use_absolute_ramp_offsets_and_shared_properties() {
        let delays = Arc::new(Mutex::new(Vec::new()));
        let values = Arc::new(Mutex::new(Vec::new()));
        let package = SamplePackage::builder(
            NodeId::new(1),
            Arc::new(PropertyRecordingSampler {
                values: Arc::clone(&values),
            }),
        )
        .sampler_factory(Arc::new(PropertyRecordingSamplerFactory {
            values: Arc::clone(&values),
        }))
        .build();
        let packages = CompiledPackages::from_packages([package]).expect("packages");
        let controller =
            ControllerProgram::compile(crate::ControllerNode::sample(1)).expect("controller");
        let group = ThreadGroupPlan::new(NodeId::new(10), "ramp", 3, controller, packages)
            .expect("group")
            .with_schedule(GroupSchedule {
                delay: Duration::from_secs(2),
                ramp_up: Duration::from_secs(6),
                duration: None,
            });
        let mut plan = EnginePlan::new();
        plan.push_group(group).expect("group");
        let properties = Arc::new(std::sync::RwLock::new(BTreeMap::from([(
            "shared".to_owned(),
            "yes".to_owned(),
        )])));
        let capabilities = RuntimeCapabilities::default()
            .with_clock(Arc::new(StaticClock))
            .with_sleeper(Arc::new(RecordingSleeper {
                delays: Arc::clone(&delays),
            }))
            .with_properties(properties);
        let mut engine = trace_engine(plan, capabilities, "run", "host");
        let report = block_on(engine.run()).expect("run");
        assert_eq!(report.users_started, 3);
        assert_eq!(report.users_finished, 3);
        assert_eq!(
            lock(&delays).clone(),
            vec![
                Duration::from_secs(2),
                Duration::from_secs(4),
                Duration::from_secs(6)
            ]
        );
        assert_eq!(
            lock(&values).clone(),
            vec![
                Some("yes".to_owned()),
                Some("yes".to_owned()),
                Some("yes".to_owned())
            ]
        );
        let thread_numbers = report
            .events
            .iter()
            .filter_map(|event| match event {
                EngineEvent::UserStarted { thread_number, .. } => Some(*thread_number),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(thread_numbers, vec![1, 2, 3]);
    }

    #[test]
    fn initial_variables_are_seeded_once_and_isolated_between_users() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let packages = initial_variable_packages(Arc::clone(&seen));
        let controller =
            ControllerProgram::compile(crate::ControllerNode::sample(1)).expect("controller");
        let group = ThreadGroupPlan::new(NodeId::new(10), "initial", 2, controller, packages)
            .expect("group");
        let initial =
            InitialVariables::try_from_iter([("seed", "compiled")]).expect("initial variables");
        let mut plan = EnginePlan::new().with_initial_variables(initial);
        plan.push_group(group).expect("group");

        let mut engine = trace_engine(plan, RuntimeCapabilities::default(), "run", "host");
        let report = block_on(engine.run()).expect("run");

        assert_eq!(report.users_started, 2);
        assert_eq!(
            lock(&seen).as_slice(),
            ["compiled".to_owned(), "compiled".to_owned()]
        );
    }

    #[test]
    fn initial_variables_are_visible_to_the_first_condition() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let packages = initial_variable_packages(Arc::clone(&seen));
        let program = LogicProgram::compile(crate::LogicNode::If {
            id: 2,
            condition: crate::LogicCondition::VariableBoolean {
                name: "enabled".to_owned(),
            },
            evaluate_each_iteration: true,
            children: vec![crate::LogicNode::Sample { id: 1 }],
        })
        .expect("logic controller");
        let group = ThreadGroupPlan::new_logic(NodeId::new(10), "condition", 1, program, packages)
            .expect("group");
        let initial = InitialVariables::try_from_iter([("enabled", "true"), ("seed", "compiled")])
            .expect("initial variables");
        let mut plan = EnginePlan::new().with_initial_variables(initial);
        plan.push_group(group).expect("group");

        let mut engine = trace_engine(plan, RuntimeCapabilities::default(), "run", "host");
        let report = block_on(engine.run()).expect("run");

        assert_eq!(
            report
                .events
                .iter()
                .filter(|event| matches!(event, EngineEvent::Sample { .. }))
                .count(),
            1
        );
        assert_eq!(
            lock(&seen).as_slice(),
            ["compiled".to_owned()],
            "condition must not let the sampler rewrite its input"
        );
    }

    #[test]
    fn initial_variables_survive_same_user_iterations_but_not_a_fresh_run() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let packages = initial_variable_packages(Arc::clone(&seen));
        let controller =
            ControllerProgram::compile(crate::ControllerNode::sample(1)).expect("controller");
        let group = ThreadGroupPlan::new(NodeId::new(10), "iterations", 1, controller, packages)
            .expect("group")
            .with_iterations(Some(2));
        let initial =
            InitialVariables::try_from_iter([("seed", "compiled")]).expect("initial variables");
        let mut plan = EnginePlan::new().with_initial_variables(initial);
        plan.push_group(group).expect("group");

        let mut engine = trace_engine(plan, RuntimeCapabilities::default(), "run", "host");
        block_on(engine.run()).expect("first run");
        assert_eq!(
            lock(&seen).as_slice(),
            ["compiled".to_owned(), "mutated".to_owned()]
        );

        block_on(engine.run()).expect("second run");
        assert_eq!(
            lock(&seen).as_slice(),
            [
                "compiled".to_owned(),
                "mutated".to_owned(),
                "compiled".to_owned(),
                "mutated".to_owned(),
            ]
        );
    }

    #[test]
    fn each_setup_main_and_teardown_user_gets_the_compiled_seed() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let packages = initial_variable_packages(Arc::clone(&seen));
        let controller =
            ControllerProgram::compile(crate::ControllerNode::sample(1)).expect("controller");
        let setup = ThreadGroupPlan::new(
            NodeId::new(1),
            "setup",
            1,
            controller.clone(),
            packages.clone(),
        )
        .expect("setup")
        .with_kind(GroupKind::Setup);
        let main = ThreadGroupPlan::new(
            NodeId::new(2),
            "main",
            1,
            controller.clone(),
            packages.clone(),
        )
        .expect("main");
        let teardown = ThreadGroupPlan::new(NodeId::new(3), "teardown", 1, controller, packages)
            .expect("teardown")
            .with_kind(GroupKind::Teardown);
        let initial =
            InitialVariables::try_from_iter([("seed", "compiled")]).expect("initial variables");
        let mut plan = EnginePlan::new().with_initial_variables(initial);
        for group in [setup, main, teardown] {
            plan.push_group(group).expect("group");
        }

        let mut engine = trace_engine(plan, RuntimeCapabilities::default(), "run", "host");
        block_on(engine.run()).expect("run");

        assert_eq!(
            lock(&seen).as_slice(),
            [
                "compiled".to_owned(),
                "compiled".to_owned(),
                "compiled".to_owned(),
            ]
        );
    }

    #[test]
    fn initial_variables_reset_only_when_same_user_iteration_is_disabled() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let packages = initial_variable_packages(Arc::clone(&seen));
        let controller =
            ControllerProgram::compile(crate::ControllerNode::sample(1)).expect("controller");
        let group = ThreadGroupPlan::new(NodeId::new(10), "fresh-loop", 1, controller, packages)
            .expect("group")
            .with_iterations(Some(2))
            .with_same_user_on_next_iteration(false);
        let initial =
            InitialVariables::try_from_iter([("seed", "compiled")]).expect("initial variables");
        let mut plan = EnginePlan::new().with_initial_variables(initial);
        plan.push_group(group).expect("group");

        let mut engine = trace_engine(plan, RuntimeCapabilities::default(), "run", "host");
        block_on(engine.run()).expect("run");

        assert_eq!(
            lock(&seen).as_slice(),
            ["compiled".to_owned(), "compiled".to_owned()]
        );
    }

    #[test]
    fn initial_variable_seed_rejects_bounds_and_preserves_context_on_collision() {
        let too_many = (0..=crate::MAX_INITIAL_VARIABLES)
            .map(|index| (format!("v{index}"), String::from("value")));
        let error = InitialVariables::try_from_iter(too_many).expect_err("count bound");
        assert_eq!(error.code(), "runtime.initial-variables.count-limit");

        let error = InitialVariables::try_from_iter([("", "value")]).expect_err("empty name");
        assert_eq!(error.code(), "runtime.initial-variables.empty-name");

        let error =
            InitialVariables::try_from_iter([("duplicate", "first"), ("duplicate", "second")])
                .expect_err("duplicate name");
        assert_eq!(error.code(), "runtime.initial-variables.duplicate-name");

        let oversized = "x".repeat(crate::MAX_INITIAL_VARIABLE_VALUE_BYTES + 1);
        let error =
            InitialVariables::try_from_iter([("large", oversized)]).expect_err("value bound");
        assert_eq!(error.code(), "runtime.initial-variables.value-limit");

        let mut plan = EnginePlan::new();
        let error = plan
            .try_set_initial_variables(BTreeMap::from([(
                "large".to_owned(),
                "x".repeat(crate::MAX_INITIAL_VARIABLE_VALUE_BYTES + 1),
            )]))
            .expect_err("plan replacement bound");
        assert_eq!(error.code(), "runtime.initial-variables.value-limit");
        assert!(plan.initial_variables().is_empty());

        let seed = InitialVariables::try_from_iter([("existing", "seed"), ("new", "value")])
            .expect("seed");
        let mut context = ExecutionContext::new();
        context.set_variable("existing", "before");
        let error = context
            .seed_initial_variables(&seed)
            .expect_err("collision must not overwrite");
        assert_eq!(error.code(), "runtime.initial-variables.duplicate-name");
        assert_eq!(context.variable("existing").as_deref(), Some("before"));
        assert_eq!(context.variable("new"), None);
    }

    #[test]
    fn expression_counter_receives_each_root_iteration_identity() {
        let values = Arc::new(Mutex::new(Vec::new()));
        let functions = Arc::new(BuiltinFunctions::new());
        let package = SamplePackage::builder(
            NodeId::new(1),
            Arc::new(CounterSampler {
                values: Arc::clone(&values),
                functions: Arc::clone(&functions),
            }),
        )
        .sampler_factory(Arc::new(CounterSamplerFactory {
            values: Arc::clone(&values),
            functions: Arc::clone(&functions),
        }))
        .build();
        let packages = CompiledPackages::from_packages([package]).expect("packages");
        let controller =
            ControllerProgram::compile(crate::ControllerNode::sample(1)).expect("controller");
        let group = ThreadGroupPlan::new(NodeId::new(10), "counter", 1, controller, packages)
            .expect("group")
            .with_iterations(Some(2));
        let mut plan = EnginePlan::new();
        plan.push_group(group).expect("group");
        let capabilities =
            RuntimeCapabilities::default().with_expression_cleanup(functions.clone());
        let mut engine = trace_engine(plan, capabilities, "run", "host");
        block_on(engine.run()).expect("run");
        assert_eq!(lock(&values).clone(), vec!["1", "2"]);
    }

    #[test]
    fn lifecycle_propagates_expression_cleanup_failure() {
        let package = SamplePackage::builder(NodeId::new(1), Arc::new(Sampler))
            .sampler_factory(Arc::new(SamplerFactoryImpl))
            .build();
        let packages = CompiledPackages::from_packages([package]).expect("packages");
        let controller =
            ControllerProgram::compile(crate::ControllerNode::sample(1)).expect("controller");
        let group = ThreadGroupPlan::new(NodeId::new(10), "cleanup", 1, controller, packages)
            .expect("group");
        let mut plan = EnginePlan::new();
        plan.push_group(group).expect("group");
        let capabilities = RuntimeCapabilities::default()
            .with_expression_cleanup(Arc::new(FailingExpressionCleanup));
        let mut engine = trace_engine(plan, capabilities, "run", "host");
        let error = block_on(engine.run()).expect_err("cleanup failure");
        assert!(
            error
                .to_string()
                .contains("runtime.engine.expression-cleanup")
        );
        assert_eq!(
            engine.summary().terminal_state,
            RunObservationTerminalState::Failed
        );
    }

    #[test]
    fn concurrent_groups_finish_before_teardown_phase_starts() {
        let package = SamplePackage::builder(NodeId::new(1), Arc::new(Sampler))
            .sampler_factory(Arc::new(SamplerFactoryImpl))
            .build();
        let packages = CompiledPackages::from_packages([package]).expect("packages");
        let controller =
            ControllerProgram::compile(crate::ControllerNode::sample(1)).expect("controller");
        let setup = ThreadGroupPlan::new(
            NodeId::new(1),
            "setup",
            1,
            controller.clone(),
            packages.clone(),
        )
        .expect("setup")
        .with_kind(GroupKind::Setup);
        let main_a = ThreadGroupPlan::new(
            NodeId::new(2),
            "main-a",
            1,
            controller.clone(),
            packages.clone(),
        )
        .expect("main-a");
        let main_b =
            ThreadGroupPlan::new(NodeId::new(3), "main-b", 1, controller, packages.clone())
                .expect("main-b");
        let teardown = ThreadGroupPlan::new(
            NodeId::new(4),
            "teardown",
            1,
            ControllerProgram::compile(crate::ControllerNode::sample(1)).expect("controller"),
            packages,
        )
        .expect("teardown")
        .with_kind(GroupKind::Teardown);
        let mut plan = EnginePlan::new();
        plan.push_group(setup).expect("setup");
        plan.push_group(main_a).expect("main-a");
        plan.push_group(main_b).expect("main-b");
        plan.push_group(teardown).expect("teardown");
        let mut engine = trace_engine(plan, RuntimeCapabilities::default(), "run", "host");
        let report = block_on(engine.run()).expect("run");
        let group_starts = report
            .events
            .iter()
            .filter_map(|event| match event {
                EngineEvent::GroupStarted { id, .. } => Some(*id),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            group_starts,
            vec![
                NodeId::new(1),
                NodeId::new(2),
                NodeId::new(3),
                NodeId::new(4)
            ]
        );
        let teardown_start = report
            .events
            .iter()
            .position(|event| {
                matches!(
                    event,
                    EngineEvent::GroupStarted {
                        id,
                        kind: GroupKind::Teardown
                    } if *id == NodeId::new(4)
                )
            })
            .expect("teardown start");
        for id in [NodeId::new(2), NodeId::new(3)] {
            let finish = report
                .events
                .iter()
                .position(|event| {
                    matches!(
                        event,
                        EngineEvent::GroupFinished { id: event_id, .. } if *event_id == id
                    )
                })
                .expect("main finish");
            assert!(finish < teardown_start);
        }
    }

    #[test]
    fn serialized_groups_finish_before_the_next_group_starts() {
        let package = SamplePackage::builder(NodeId::new(1), Arc::new(Sampler))
            .sampler_factory(Arc::new(SamplerFactoryImpl))
            .build();
        let packages = CompiledPackages::from_packages([package]).expect("packages");
        let controller =
            ControllerProgram::compile(crate::ControllerNode::sample(1)).expect("controller");
        let first = ThreadGroupPlan::new(
            NodeId::new(1),
            "first",
            1,
            controller.clone(),
            packages.clone(),
        )
        .expect("first");
        let second = ThreadGroupPlan::new(NodeId::new(2), "second", 1, controller, packages)
            .expect("second");
        let mut plan = EnginePlan::new();
        plan.serialize_thread_groups = true;
        plan.push_group(first).expect("first");
        plan.push_group(second).expect("second");
        let mut engine = trace_engine(plan, RuntimeCapabilities::default(), "run", "host");
        let report = block_on(engine.run()).expect("run");
        let first_finished = report
            .events
            .iter()
            .position(|event| {
                matches!(
                    event,
                    EngineEvent::GroupFinished { id, .. } if *id == NodeId::new(1)
                )
            })
            .expect("first finish");
        let second_started = report
            .events
            .iter()
            .position(|event| {
                matches!(
                    event,
                    EngineEvent::GroupStarted { id, .. } if *id == NodeId::new(2)
                )
            })
            .expect("second start");
        assert!(first_finished < second_started);
    }

    #[test]
    fn stop_thread_is_local_across_concurrent_users_and_cleanup_runs() {
        let first = Arc::new(AtomicBool::new(true));
        let cleaned = Arc::new(Mutex::new(Vec::new()));
        let package = SamplePackage::builder(
            NodeId::new(1),
            Arc::new(StopFirstSampler {
                first: Arc::clone(&first),
                signal: ControlSignal::StopThread,
            }),
        )
        .sampler_factory(Arc::new(StopFirstSamplerFactory {
            first: Arc::clone(&first),
            signal: ControlSignal::StopThread,
        }))
        .build();
        let packages = CompiledPackages::from_packages([package]).expect("packages");
        let controller =
            ControllerProgram::compile(crate::ControllerNode::sample(1)).expect("controller");
        let group =
            ThreadGroupPlan::new(NodeId::new(10), "main", 2, controller, packages).expect("group");
        let mut plan = EnginePlan::new();
        plan.push_group(group).expect("group");
        let capabilities = RuntimeCapabilities::default().with_expression_cleanup(Arc::new(
            RecordingExpressionCleanup {
                lifecycle_ids: Arc::clone(&cleaned),
            },
        ));
        let mut engine = trace_engine(plan, capabilities, "run", "host");
        let report = block_on(engine.run()).expect("run");
        assert_eq!(report.users_started, 2);
        assert_eq!(report.users_finished, 2);
        assert_eq!(report.signal, ControlSignal::StopThread);
        assert_eq!(
            report
                .events
                .iter()
                .filter(|event| matches!(event, EngineEvent::Sample { .. }))
                .count(),
            2
        );
        assert_eq!(lock(&cleaned).len(), 2);
    }

    #[test]
    fn shared_immediate_stop_cancels_sibling_user_but_runs_allowed_teardown() {
        let first = Arc::new(AtomicBool::new(true));
        let package = SamplePackage::builder(
            NodeId::new(1),
            Arc::new(StopFirstSampler {
                first: Arc::clone(&first),
                signal: ControlSignal::StopTestImmediate,
            }),
        )
        .sampler_factory(Arc::new(StopFirstSamplerFactory {
            first: Arc::clone(&first),
            signal: ControlSignal::StopTestImmediate,
        }))
        .build();
        let packages = CompiledPackages::from_packages([package]).expect("packages");
        let controller =
            ControllerProgram::compile(crate::ControllerNode::sample(1)).expect("controller");
        let main = ThreadGroupPlan::new(
            NodeId::new(10),
            "main",
            2,
            controller.clone(),
            packages.clone(),
        )
        .expect("main");
        let teardown = ThreadGroupPlan::new(NodeId::new(11), "teardown", 1, controller, packages)
            .expect("teardown")
            .with_kind(GroupKind::Teardown);
        let mut plan = EnginePlan::new();
        plan.push_group(main).expect("main");
        plan.push_group(teardown).expect("teardown");
        let mut engine = trace_engine(plan, RuntimeCapabilities::default(), "run", "host");
        let report = block_on(engine.run()).expect("immediate stop is a report");
        assert_eq!(report.signal, ControlSignal::StopTestImmediate);
        let events = engine.events();
        assert!(events.iter().any(|event| {
            matches!(
                event,
                EngineEvent::GroupStarted {
                    id,
                    kind: GroupKind::Teardown
                } if *id == NodeId::new(11)
            )
        }));
        assert_eq!(
            events
                .iter()
                .filter(|event| {
                    matches!(
                        event,
                        EngineEvent::Sample {
                            group_id,
                            ..
                        } if *group_id == NodeId::new(10)
                    )
                })
                .count(),
            1
        );
    }

    #[test]
    fn sample_error_test_stop_propagates_to_both_users_deterministically() {
        for logic_controller in [false, true] {
            for (policy, expected_signal) in [
                (
                    SampleErrorPolicy::StopTestGraceful,
                    ControlSignal::StopTestGraceful,
                ),
                (
                    SampleErrorPolicy::StopTestImmediate,
                    ControlSignal::StopTestImmediate,
                ),
            ] {
                let invocations = Arc::new(AtomicUsize::new(0));
                let package = SamplePackage::builder(
                    NodeId::new(1),
                    Arc::new(PolicyFailureSampler {
                        invocations: Arc::clone(&invocations),
                    }),
                )
                .sampler_factory(Arc::new(PolicyFailureSamplerFactory {
                    invocations: Arc::clone(&invocations),
                }))
                .build();
                let packages = CompiledPackages::from_packages([package]).expect("packages");
                let group = if logic_controller {
                    let program = LogicProgram::compile(crate::LogicNode::Sequence {
                        id: 2,
                        children: vec![crate::LogicNode::Sample { id: 1 }],
                    })
                    .expect("logic program");
                    ThreadGroupPlan::new_logic(NodeId::new(10), "main", 2, program, packages)
                } else {
                    let controller = ControllerProgram::compile(crate::ControllerNode::sample(1))
                        .expect("controller");
                    ThreadGroupPlan::new(NodeId::new(10), "main", 2, controller, packages)
                }
                .expect("group")
                .with_error_policy(policy);
                let mut plan = EnginePlan::new();
                plan.push_group(group).expect("group");
                let mut engine = trace_engine(plan, RuntimeCapabilities::default(), "run", "host");

                let report = block_on(engine.run()).expect("test stop is a report");

                assert_eq!(report.signal, expected_signal);
                assert_eq!(report.users_started, 2);
                assert_eq!(report.users_finished, 2);
                assert_eq!(
                    report
                        .events
                        .iter()
                        .filter(|event| matches!(event, EngineEvent::Sample { .. }))
                        .count(),
                    1
                );
                assert_eq!(invocations.load(Ordering::Acquire), 1);
            }
        }
    }

    #[test]
    fn group_duration_is_checked_before_each_legacy_sample() {
        let nanos = Arc::new(AtomicU64::new(0));
        let invocations = Arc::new(AtomicUsize::new(0));
        let package = SamplePackage::builder(
            NodeId::new(1),
            Arc::new(AdvanceClockSampler {
                nanos: Arc::clone(&nanos),
                invocations: Arc::clone(&invocations),
            }),
        )
        .sampler_factory(Arc::new(AdvanceClockSamplerFactory {
            nanos: Arc::clone(&nanos),
            invocations: Arc::clone(&invocations),
        }))
        .build();
        let packages = CompiledPackages::from_packages([package]).expect("packages");
        let controller = ControllerProgram::compile(crate::ControllerNode::loop_controller(
            2,
            crate::LoopCount::finite(2),
            vec![crate::ControllerNode::sample(1)],
        ))
        .expect("controller");
        let group = ThreadGroupPlan::new(NodeId::new(10), "duration", 1, controller, packages)
            .expect("group")
            .with_schedule(GroupSchedule {
                delay: Duration::ZERO,
                ramp_up: Duration::ZERO,
                duration: Some(Duration::from_millis(5)),
            });
        let mut plan = EnginePlan::new();
        plan.push_group(group).expect("group");
        let capabilities = RuntimeCapabilities::default().with_clock(Arc::new(AdvancingClock {
            nanos: Arc::clone(&nanos),
        }));
        let mut engine = trace_engine(plan, capabilities, "run", "host");

        let report = block_on(engine.run()).expect("duration run");

        assert_eq!(invocations.load(Ordering::Acquire), 1);
        assert_eq!(
            report
                .events
                .iter()
                .filter(|event| matches!(event, EngineEvent::Sample { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn group_duration_is_checked_before_each_logic_sample() {
        let nanos = Arc::new(AtomicU64::new(0));
        let invocations = Arc::new(AtomicUsize::new(0));
        let package = SamplePackage::builder(
            NodeId::new(1),
            Arc::new(AdvanceClockSampler {
                nanos: Arc::clone(&nanos),
                invocations: Arc::clone(&invocations),
            }),
        )
        .sampler_factory(Arc::new(AdvanceClockSamplerFactory {
            nanos: Arc::clone(&nanos),
            invocations: Arc::clone(&invocations),
        }))
        .build();
        let packages = CompiledPackages::from_packages([package]).expect("packages");
        let program = LogicProgram::compile(crate::LogicNode::Loop {
            id: 2,
            count: crate::LoopCount::finite(2),
            children: vec![crate::LogicNode::Sample { id: 1 }],
        })
        .expect("logic program");
        let group = ThreadGroupPlan::new_logic(NodeId::new(10), "duration", 1, program, packages)
            .expect("group")
            .with_schedule(GroupSchedule {
                delay: Duration::ZERO,
                ramp_up: Duration::ZERO,
                duration: Some(Duration::from_millis(5)),
            });
        let mut plan = EnginePlan::new();
        plan.push_group(group).expect("group");
        let capabilities = RuntimeCapabilities::default().with_clock(Arc::new(AdvancingClock {
            nanos: Arc::clone(&nanos),
        }));
        let mut engine = trace_engine(plan, capabilities, "run", "host");

        let report = block_on(engine.run()).expect("duration run");

        assert_eq!(invocations.load(Ordering::Acquire), 1);
        assert_eq!(
            report
                .events
                .iter()
                .filter(|event| matches!(event, EngineEvent::Sample { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn critical_section_spans_child_sequence_and_waits_fifo_between_users() {
        let trace = Arc::new(Mutex::new(Vec::new()));
        let package_one = SamplePackage::builder(
            NodeId::new(10),
            Arc::new(ScopeTraceSampler {
                trace: Arc::clone(&trace),
            }),
        )
        .sampler_factory(Arc::new(ScopeTraceSamplerFactory {
            trace: Arc::clone(&trace),
        }))
        .build();
        let package_two = SamplePackage::builder(
            NodeId::new(11),
            Arc::new(ScopeTraceSampler {
                trace: Arc::clone(&trace),
            }),
        )
        .sampler_factory(Arc::new(ScopeTraceSamplerFactory {
            trace: Arc::clone(&trace),
        }))
        .build();
        let packages =
            CompiledPackages::from_packages([package_one, package_two]).expect("packages");
        let program = LogicProgram::compile(crate::LogicNode::CriticalSection {
            id: 100,
            lock_name: "gate".to_owned(),
            children: vec![
                crate::LogicNode::Sample { id: 10 },
                crate::LogicNode::Sample { id: 11 },
            ],
        })
        .expect("logic program");
        let group = ThreadGroupPlan::new_logic(NodeId::new(20), "critical", 2, program, packages)
            .expect("group");
        let mut plan = EnginePlan::new();
        plan.push_group(group).expect("group");

        let coordinator_events = Arc::new(Mutex::new(Vec::new()));
        let coordinator = Arc::new(RecordingCriticalCoordinator {
            inner: crate::DeterministicCriticalSectionCoordinator::new(1),
            events: Arc::clone(&coordinator_events),
            cancellations: Arc::new(AtomicUsize::new(0)),
            fail_release: Arc::new(AtomicBool::new(false)),
        });
        let capabilities = RuntimeCapabilities::default()
            .with_critical_section_coordinator(coordinator)
            .with_random(Arc::new(crate::ZeroRandom));
        let mut engine = trace_engine(plan, capabilities, "run", "host");
        block_on(engine.run()).expect("critical-section run");

        let trace = lock(&trace).clone();
        assert_eq!(trace.len(), 4);
        let users = trace
            .iter()
            .map(|entry| entry.split(':').next().unwrap_or_default().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(users[0], "critical-1");
        assert_eq!(users[0], users[1]);
        assert_eq!(users[2], "critical-2");
        assert_eq!(users[2], users[3]);
        assert_ne!(users[1], users[2]);
        assert_eq!(
            lock(&coordinator_events)
                .iter()
                .filter(|event| event.starts_with("acquire:"))
                .count(),
            2
        );
        assert_eq!(
            lock(&coordinator_events)
                .iter()
                .filter(|event| event.starts_with("release:"))
                .count(),
            2
        );
    }

    #[test]
    fn critical_section_releases_when_group_duration_ends() {
        let nanos = Arc::new(AtomicU64::new(0));
        let invocations = Arc::new(AtomicUsize::new(0));
        let package = SamplePackage::builder(
            NodeId::new(10),
            Arc::new(AdvanceClockSampler {
                nanos: Arc::clone(&nanos),
                invocations: Arc::clone(&invocations),
            }),
        )
        .sampler_factory(Arc::new(AdvanceClockSamplerFactory {
            nanos: Arc::clone(&nanos),
            invocations: Arc::clone(&invocations),
        }))
        .build();
        let packages = CompiledPackages::from_packages([package]).expect("packages");
        let program = LogicProgram::compile(crate::LogicNode::Loop {
            id: 1,
            count: crate::LoopCount::finite(2),
            children: vec![crate::LogicNode::CriticalSection {
                id: 100,
                lock_name: "gate".to_owned(),
                children: vec![crate::LogicNode::Sample { id: 10 }],
            }],
        })
        .expect("logic program");
        let group = ThreadGroupPlan::new_logic(NodeId::new(20), "critical", 1, program, packages)
            .expect("group")
            .with_schedule(GroupSchedule {
                delay: Duration::ZERO,
                ramp_up: Duration::ZERO,
                duration: Some(Duration::from_millis(5)),
            });
        let mut plan = EnginePlan::new();
        plan.push_group(group).expect("group");
        let coordinator_events = Arc::new(Mutex::new(Vec::new()));
        let capabilities = RuntimeCapabilities::default()
            .with_clock(Arc::new(AdvancingClock { nanos }))
            .with_critical_section_coordinator(Arc::new(RecordingCriticalCoordinator {
                inner: crate::DeterministicCriticalSectionCoordinator::new(1),
                events: Arc::clone(&coordinator_events),
                cancellations: Arc::new(AtomicUsize::new(0)),
                fail_release: Arc::new(AtomicBool::new(false)),
            }));
        let mut engine = trace_engine(plan, capabilities, "run", "host");

        block_on(engine.run()).expect("duration run");

        assert_eq!(invocations.load(Ordering::Acquire), 1);
        let events = lock(&coordinator_events);
        assert_eq!(
            events
                .iter()
                .filter(|event| event.starts_with("acquire:"))
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.starts_with("release:"))
                .count(),
            1
        );
    }

    #[test]
    fn queued_critical_section_cancellation_calls_cancel_once() {
        let cancellations = Arc::new(AtomicUsize::new(0));
        let coordinator = Arc::new(RecordingCriticalCoordinator {
            inner: crate::DeterministicCriticalSectionCoordinator::new(1),
            events: Arc::new(Mutex::new(Vec::new())),
            cancellations: Arc::clone(&cancellations),
            fail_release: Arc::new(AtomicBool::new(false)),
        });
        coordinator.try_acquire("gate", 1).expect("first owner");
        let cancellation = CancellationToken::new();
        let mut future = Box::pin(poll_critical_section_acquire(
            coordinator,
            NodeId::new(20),
            "gate".to_owned(),
            2,
            cancellation.clone(),
        ));
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
        cancellation.request(ControlSignal::StopThread);
        assert!(matches!(
            future.as_mut().poll(&mut context),
            Poll::Ready(Ok(CriticalSectionSyncOutcome::Cancelled(
                ControlSignal::StopThread
            )))
        ));
        assert_eq!(cancellations.load(Ordering::Acquire), 1);
    }

    #[test]
    fn pipeline_failure_and_release_failure_preserve_primary_error() {
        let package = SamplePackage::builder(NodeId::new(10), Arc::new(FailingScopeSampler))
            .sampler_factory(Arc::new(FailingScopeSamplerFactory))
            .build();
        let packages = CompiledPackages::from_packages([package]).expect("packages");
        let program = LogicProgram::compile(crate::LogicNode::CriticalSection {
            id: 100,
            lock_name: "gate".to_owned(),
            children: vec![crate::LogicNode::Sample { id: 10 }],
        })
        .expect("logic program");
        let group = ThreadGroupPlan::new_logic(NodeId::new(20), "critical", 1, program, packages)
            .expect("group");
        let mut plan = EnginePlan::new();
        plan.push_group(group).expect("group");
        let fail_release = Arc::new(AtomicBool::new(true));
        let capabilities = RuntimeCapabilities::default().with_critical_section_coordinator(
            Arc::new(RecordingCriticalCoordinator {
                inner: crate::DeterministicCriticalSectionCoordinator::new(1),
                events: Arc::new(Mutex::new(Vec::new())),
                cancellations: Arc::new(AtomicUsize::new(0)),
                fail_release,
            }),
        );
        let mut engine = trace_engine(plan, capabilities, "run", "host");
        let error = block_on(engine.run()).expect_err("pipeline failure");
        assert!(matches!(
            error,
            EngineError::Combined { primary, secondary }
                if primary.code() == "runtime.engine.pipeline"
                    && secondary.code() == "runtime.engine.critical-section"
        ));
    }

    #[test]
    fn adjacent_same_name_nested_and_iteration_scopes_are_not_collapsed() {
        let trace = Arc::new(Mutex::new(Vec::new()));
        let package = |id| {
            SamplePackage::builder(
                NodeId::new(id),
                Arc::new(ScopeTraceSampler {
                    trace: Arc::clone(&trace),
                }),
            )
            .sampler_factory(Arc::new(ScopeTraceSamplerFactory {
                trace: Arc::clone(&trace),
            }))
            .build()
        };
        let packages = CompiledPackages::from_packages([package(10), package(11), package(12)])
            .expect("packages");
        let program = LogicProgram::compile(crate::LogicNode::Loop {
            id: 1,
            count: crate::LoopCount::finite(2),
            children: vec![crate::LogicNode::Sequence {
                id: 2,
                children: vec![
                    crate::LogicNode::CriticalSection {
                        id: 100,
                        lock_name: "gate".to_owned(),
                        children: vec![
                            crate::LogicNode::Sample { id: 10 },
                            crate::LogicNode::CriticalSection {
                                id: 101,
                                lock_name: "inner".to_owned(),
                                children: vec![crate::LogicNode::Sample { id: 11 }],
                            },
                        ],
                    },
                    crate::LogicNode::CriticalSection {
                        id: 102,
                        lock_name: "gate".to_owned(),
                        children: vec![crate::LogicNode::Sample { id: 12 }],
                    },
                ],
            }],
        })
        .expect("logic program");
        let group = ThreadGroupPlan::new_logic(NodeId::new(20), "critical", 1, program, packages)
            .expect("group");
        let mut plan = EnginePlan::new();
        plan.push_group(group).expect("group");
        let coordinator_events = Arc::new(Mutex::new(Vec::new()));
        let coordinator = Arc::new(RecordingCriticalCoordinator {
            inner: crate::DeterministicCriticalSectionCoordinator::new(2),
            events: Arc::clone(&coordinator_events),
            cancellations: Arc::new(AtomicUsize::new(0)),
            fail_release: Arc::new(AtomicBool::new(false)),
        });
        let capabilities =
            RuntimeCapabilities::default().with_critical_section_coordinator(coordinator);
        let mut engine = trace_engine(plan, capabilities, "run", "host");
        block_on(engine.run()).expect("critical-section run");

        let events = lock(&coordinator_events).clone();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.starts_with("acquire:"))
                .count(),
            6
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.starts_with("release:"))
                .count(),
            6
        );
        let trace = lock(&trace).clone();
        assert_eq!(trace.len(), 6);
        // The two adjacent `gate` controllers have different IDs and must
        // each acquire/release; otherwise the inner same-name section would
        // be silently collapsed into its parent.
        assert!(events.windows(4).any(|window| {
            window[0].starts_with("acquire:gate:")
                && window[1].starts_with("acquire:inner:")
                && window[2].starts_with("release:inner:")
                && window[3].starts_with("release:gate:")
        }));
    }

    #[test]
    fn concurrent_task_bound_is_typed_and_test_finished_is_emitted() {
        let group = ThreadGroupPlan::new(
            NodeId::new(1),
            "too-many",
            MAX_CONCURRENT_TASKS + 1,
            ControllerProgram::compile(crate::ControllerNode::simple(0, vec![]))
                .expect("controller"),
            CompiledPackages::default(),
        )
        .expect("group");
        let mut plan = EnginePlan::new();
        plan.push_group(group).expect("group");
        let mut engine = trace_engine(plan, RuntimeCapabilities::default(), "run", "host");
        let error = block_on(engine.run()).expect_err("task bound");
        assert_eq!(error.code(), "runtime.engine.resource-limit");
        assert!(
            engine
                .events()
                .iter()
                .any(|event| matches!(event, EngineEvent::TestFinished { .. }))
        );
    }

    #[test]
    fn lifecycle_runs_setup_main_and_teardown_in_order() {
        let package = SamplePackage::builder(NodeId::new(1), Arc::new(Sampler))
            .sampler_factory(Arc::new(SamplerFactoryImpl))
            .build();
        let packages = CompiledPackages::from_packages([package]).expect("packages");
        let controller =
            ControllerProgram::compile(crate::ControllerNode::sample(1)).expect("controller");
        let base = ThreadGroupPlan::new(
            NodeId::new(1),
            "main",
            1,
            controller.clone(),
            packages.clone(),
        )
        .expect("group");
        let setup = ThreadGroupPlan::new(
            NodeId::new(2),
            "setup",
            1,
            controller.clone(),
            packages.clone(),
        )
        .expect("setup")
        .with_kind(GroupKind::Setup);
        let teardown = ThreadGroupPlan::new(NodeId::new(3), "teardown", 1, controller, packages)
            .expect("teardown")
            .with_kind(GroupKind::Teardown);
        let mut plan = EnginePlan::new();
        plan.push_group(setup).expect("push");
        plan.push_group(base).expect("push");
        plan.push_group(teardown).expect("push");
        let mut engine = trace_engine(plan, RuntimeCapabilities::default(), "run", "host");
        let report = block_on(engine.run()).expect("run");
        assert!(report.events.iter().any(|event| {
            matches!(
                event,
                EngineEvent::UserStarted {
                    group_id,
                    thread_number: 1,
                    ..
                } if *group_id == NodeId::new(2)
            )
        }));
        let groups = report
            .events
            .iter()
            .filter_map(|event| match event {
                EngineEvent::GroupStarted { id, .. } => Some(*id),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(groups, vec![NodeId::new(2), NodeId::new(1), NodeId::new(3)]);
    }

    #[test]
    #[allow(
        deprecated,
        reason = "RuntimeEngine currently exercises the legacy result-router bridge; typed runtime routing is a separate migration"
    )]
    fn ignored_sample_is_retained_for_diagnostics_but_not_routed() {
        let mut ignored = SampleResult::new("ignored");
        ignored.set_ignored(true);
        let outputs = Arc::new(Mutex::new(vec![SamplerOutput::result(ignored)]));
        let package = SamplePackage::builder(
            NodeId::new(1),
            Arc::new(SequenceSampler {
                outputs: Arc::clone(&outputs),
            }),
        )
        .sampler_factory(Arc::new(SequenceSamplerFactory {
            outputs: Arc::clone(&outputs),
        }))
        .build();
        let packages = CompiledPackages::from_packages([package]).expect("packages");
        let controller =
            ControllerProgram::compile(crate::ControllerNode::sample(1)).expect("controller");
        let group = ThreadGroupPlan::new(NodeId::new(10), "ignored", 1, controller, packages)
            .expect("group");
        let mut plan = EnginePlan::new();
        plan.push_group(group).expect("group");

        let state = Arc::new(Mutex::new(RoutedEvents::default()));
        let router = ResultRouter::new(
            "run",
            [ResultSinkSpec::new(
                SinkId::new(1),
                SinkLimits::new(4, 100_000),
                Arc::new(RecordingResultSink {
                    state: Arc::clone(&state),
                }),
            )],
        )
        .expect("router");
        let mut engine = trace_engine(plan, RuntimeCapabilities::default(), "run", "host")
            .with_result_router(router);

        let report = block_on(engine.run()).expect("ignored run");

        assert!(lock(&state).events.is_empty());
        assert!(Arc::ptr_eq(&report.trace, &report.events));
        assert!(report.events.iter().any(|event| {
            matches!(
                event,
                EngineEvent::Sample {
                    result: Some(result),
                    ..
                } if result.is_ignored()
            )
        }));
    }

    #[test]
    fn typed_router_is_engine_owned_and_preserves_original_snapshot() {
        let package = SamplePackage::builder(NodeId::new(1), Arc::new(Sampler))
            .sampler_factory(Arc::new(SamplerFactoryImpl))
            .build();
        let packages = CompiledPackages::from_packages([package]).expect("packages");
        let controller =
            ControllerProgram::compile(crate::ControllerNode::sample(1)).expect("controller");
        let group =
            ThreadGroupPlan::new(NodeId::new(10), "typed", 2, controller, packages).expect("group");
        let mut plan = EnginePlan::new();
        plan.push_group(group).expect("group");

        let typed_run =
            TypedRunId::from_run_identity(&RunIdentity::from("run")).expect("typed run");
        let generation = RunGeneration::new(1).expect("generation");
        let domain = PlanDomain::from_canonical_plan_and_profile_text(
            b"typed-engine-plan",
            b"local-import",
            "jmeter-5.6.3",
            "5.6.3",
            Vec::new(),
        )
        .expect("plan domain");
        let worker = WorkerId::new(1).expect("worker");
        let worker_generation = WorkerGeneration::new(1).expect("worker generation");
        let collector = crate::result_router::PlanNodeRef::from_u64(domain, 99).expect("collector");
        let sink_id = QualifiedSinkId::from_parts(
            typed_run,
            SinkPlanGeneration::new(1).expect("sink generation"),
            collector,
        );
        let sink_plan = TypedSinkPlan::new(
            sink_id,
            SinkLimits::with_finalization(64, 1024 * 1024, 256),
            FullPolicy::FailRun,
        );
        let router =
            TypedResultRouter::new(typed_run, generation, RetryBudget::new(32), [sink_plan])
                .expect("typed router");
        let envelopes = Arc::new(Mutex::new(Vec::new()));
        let cancellation = Arc::new(crate::CancellationToken::new());
        let budget = ResultDeliveryBudget::from_parts(
            ResultOperationScope::sink_set(typed_run, sink_id.sink_plan_generation()),
            Arc::new(TestResultClock),
            cancellation,
            ResultOperationWindows::uniform(Duration::from_secs(1), Duration::from_secs(1)),
            32,
            None,
        )
        .expect("result budget");
        let wait_registrar = Arc::new(crate::WaitRegistry::default());
        let adapter = TypedResultRouterAdapter::new_with_liveness(
            router,
            TypedRouterIdentity::new(domain, typed_run, generation, worker, worker_generation),
            [(
                sink_id,
                Arc::new(RecordingTypedSink {
                    envelopes: Arc::clone(&envelopes),
                }) as Arc<dyn TypedSinkAdapter>,
            )],
            budget,
            wait_registrar,
        )
        .expect("typed adapter");
        let mut engine = trace_engine(plan, RuntimeCapabilities::default(), "run", "host")
            .with_typed_result_router(adapter);

        let report = block_on(engine.run()).expect("typed run");

        let envelopes = lock(&envelopes);
        assert_eq!(envelopes.len(), 2);
        let envelope = &envelopes[0];
        assert_eq!(envelope.event().result().label(), "sample");
        assert_eq!(envelope.source().node_id(), NodeId::new(1));
        assert!(matches!(
            envelope.origin(),
            TypedResultOrigin::Sampler { sampler, parent: None }
                if sampler.node_id() == NodeId::new(1)
        ));
        assert_eq!(envelope.plan_path().len(), 2);
        assert!(
            envelopes
                .iter()
                .all(|envelope| envelope.user().thread_number() > 0)
        );
        assert_eq!(
            report
                .events
                .iter()
                .filter(|event| matches!(event, EngineEvent::Sample { .. }))
                .count(),
            2
        );
        assert_eq!(
            engine.typed_result_router().expect("adapter").phase(),
            TypedRouterPhase::Finished
        );
    }

    #[test]
    fn logic_controller_state_survives_root_iterations_per_user() {
        let package = SamplePackage::builder(NodeId::new(10), Arc::new(Sampler))
            .sampler_factory(Arc::new(SamplerFactoryImpl))
            .build();
        let packages = CompiledPackages::from_packages([package]).expect("packages");
        let program = LogicProgram::compile(crate::LogicNode::OnceOnly {
            id: 1,
            children: vec![crate::LogicNode::Sample { id: 10 }],
        })
        .expect("logic program");
        let group = ThreadGroupPlan::new_logic(NodeId::new(20), "main", 1, program, packages)
            .expect("logic group")
            .with_iterations(Some(2));
        let mut plan = EnginePlan::new();
        plan.push_group(group).expect("group");
        let mut engine = trace_engine(plan, RuntimeCapabilities::default(), "run", "host");
        let report = block_on(engine.run()).expect("run");
        let samples = report
            .events
            .iter()
            .filter(|event| matches!(event, EngineEvent::Sample { sampler_id, .. } if *sampler_id == NodeId::new(10)))
            .count();
        assert_eq!(samples, 1);
        assert_eq!(
            report
                .events
                .iter()
                .filter(|event| matches!(event, EngineEvent::Iteration { .. }))
                .count(),
            2
        );
    }

    #[test]
    fn null_result_preserves_last_non_null_success_for_conditions() {
        let mut failed = SampleResult::new("failed");
        failed.set_successful(false);
        let outputs = Arc::new(Mutex::new(vec![
            SamplerOutput::result(SampleResult::new("condition")),
            SamplerOutput::no_result(),
            SamplerOutput::result(failed),
        ]));
        let packages = CompiledPackages::from_packages((10..=12).map(|id| {
            SamplePackage::builder(
                NodeId::new(id),
                Arc::new(SequenceSampler {
                    outputs: Arc::clone(&outputs),
                }),
            )
            .sampler_factory(Arc::new(SequenceSamplerFactory {
                outputs: Arc::clone(&outputs),
            }))
            .build()
        }))
        .expect("packages");
        let program = LogicProgram::compile(crate::LogicNode::Sequence {
            id: 1,
            children: vec![
                crate::LogicNode::Sample { id: 10 },
                crate::LogicNode::Sample { id: 11 },
                crate::LogicNode::If {
                    id: 2,
                    condition: crate::LogicCondition::LastSampleSuccess { expected: false },
                    evaluate_each_iteration: true,
                    children: vec![crate::LogicNode::Sample { id: 12 }],
                },
            ],
        })
        .expect("logic program");
        let group = ThreadGroupPlan::new_logic(NodeId::new(20), "main", 1, program, packages)
            .expect("logic group");
        let mut plan = EnginePlan::new();
        plan.push_group(group).expect("group");
        let mut engine = trace_engine(plan, RuntimeCapabilities::default(), "run", "host");
        let report = block_on(engine.run()).expect("run");
        let samples = report
            .events
            .iter()
            .filter_map(|event| match event {
                EngineEvent::Sample { sampler_id, .. } => Some(*sampler_id),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            samples,
            vec![NodeId::new(10), NodeId::new(11), NodeId::new(12)]
        );
    }

    #[test]
    fn same_user_false_isolates_lifecycle_identity_and_package_instance() {
        let lifecycle_ids: Arc<Mutex<Vec<Option<u64>>>> = Arc::new(Mutex::new(Vec::new()));
        let cleanup_ids: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        let package = SamplePackage::builder(
            NodeId::new(10),
            Arc::new(LifecycleRecordingSampler {
                lifecycle_ids: Arc::clone(&lifecycle_ids),
            }),
        )
        .sampler_factory(Arc::new(LifecycleRecordingSamplerFactory {
            lifecycle_ids: Arc::clone(&lifecycle_ids),
        }))
        .build();
        let packages = CompiledPackages::from_packages([package]).expect("packages");
        let controller =
            ControllerProgram::compile(crate::ControllerNode::sample(10)).expect("controller");
        let group = ThreadGroupPlan::new(NodeId::new(20), "main", 1, controller, packages)
            .expect("group")
            .with_iterations(Some(2))
            .with_same_user_on_next_iteration(false);
        let mut plan = EnginePlan::new();
        plan.push_group(group).expect("group");
        let capabilities = RuntimeCapabilities::default().with_expression_cleanup(Arc::new(
            RecordingExpressionCleanup {
                lifecycle_ids: Arc::clone(&cleanup_ids),
            },
        ));
        let mut engine = trace_engine(plan, capabilities, "run", "host");
        block_on(engine.run()).expect("run");
        let ids = lock(&lifecycle_ids).clone();
        assert_eq!(ids.len(), 2);
        assert_ne!(ids[0], ids[1]);
        let cleaned = lock(&cleanup_ids).clone();
        assert_eq!(
            cleaned,
            ids.iter()
                .map(|id| id.expect("lifecycle identity"))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn transaction_controller_emits_bounded_parent_aggregate() {
        let package = SamplePackage::builder(NodeId::new(10), Arc::new(Sampler))
            .sampler_factory(Arc::new(SamplerFactoryImpl))
            .build();
        let packages = CompiledPackages::from_packages([package]).expect("packages");
        let program = LogicProgram::compile(crate::LogicNode::Transaction {
            id: 11,
            parent: true,
            include_timers: false,
            children: vec![crate::LogicNode::Sample { id: 10 }],
        })
        .expect("logic program");
        let group = ThreadGroupPlan::new_logic(NodeId::new(20), "main", 1, program, packages)
            .expect("logic group");
        let mut plan = EnginePlan::new();
        plan.push_group(group).expect("group");
        let mut engine = trace_engine(plan, RuntimeCapabilities::default(), "run", "host");
        let report = block_on(engine.run()).expect("run");
        let transaction = report.events.iter().find_map(|event| match event {
            EngineEvent::Sample {
                sampler_id,
                result: Some(result),
                ..
            } if *sampler_id == NodeId::new(11) => Some(result),
            _ => None,
        });
        assert_eq!(
            transaction.map(|result| result.sub_results().len()),
            Some(1)
        );
    }

    #[test]
    #[allow(
        deprecated,
        reason = "RuntimeEngine currently exercises the legacy result-router bridge; typed runtime routing is a separate migration"
    )]
    fn result_router_receives_original_sampler_and_transaction_snapshots() {
        let package = SamplePackage::builder(NodeId::new(10), Arc::new(Sampler))
            .sampler_factory(Arc::new(SamplerFactoryImpl))
            .build();
        let packages = CompiledPackages::from_packages([package]).expect("packages");
        let program = LogicProgram::compile(crate::LogicNode::Transaction {
            id: 11,
            parent: true,
            include_timers: false,
            children: vec![crate::LogicNode::Sample { id: 10 }],
        })
        .expect("logic program");
        let group = ThreadGroupPlan::new_logic(NodeId::new(20), "main", 1, program, packages)
            .expect("logic group");
        let mut plan = EnginePlan::new();
        plan.push_group(group).expect("group");

        let state = Arc::new(Mutex::new(RoutedEvents::default()));
        let router = ResultRouter::new(
            "run",
            [ResultSinkSpec::new(
                SinkId::new(1),
                SinkLimits::new(4, 100_000),
                Arc::new(RecordingResultSink {
                    state: Arc::clone(&state),
                }),
            )],
        )
        .expect("router");
        let mut engine = trace_engine(plan, RuntimeCapabilities::default(), "run", "host")
            .with_result_router(router.clone());
        let report = block_on(engine.run()).expect("run");

        let recorded = lock(&state);
        let routed = recorded.events.clone();
        let paths = recorded.paths.clone();
        drop(recorded);
        assert_eq!(routed.len(), 2);
        assert_eq!(
            paths,
            vec![
                vec![NodeId::new(20), NodeId::new(11), NodeId::new(10)],
                vec![NodeId::new(20), NodeId::new(11)],
            ]
        );
        assert_eq!(routed[0].0, RunSequence::new(1));
        assert_eq!(routed[0].1, NodeId::new(10));
        assert_eq!(
            routed[0].2,
            ResultOrigin::Sampler {
                sampler_id: NodeId::new(10),
                parent: Some(NodeId::new(11)),
            }
        );
        assert_eq!(routed[0].3, "sample");
        assert_eq!(routed[1].0, RunSequence::new(2));
        assert_eq!(routed[1].1, NodeId::new(11));
        assert_eq!(
            routed[1].2,
            ResultOrigin::Transaction {
                controller_id: NodeId::new(11),
                parent: None,
            }
        );
        assert_eq!(routed[1].3, "Transaction-11");
        assert_eq!(routed[0].4, RunIdentity::new("run"));
        assert_eq!(routed[0].5.number(), Some(1));
        assert_eq!(routed[1].5, routed[0].5);
        assert_eq!(router.stats().phase, crate::RouterPhase::Finished);

        let transaction = report.events.iter().find_map(|event| match event {
            EngineEvent::Sample {
                sampler_id,
                result: Some(result),
                ..
            } if *sampler_id == NodeId::new(11) => Some(result),
            _ => None,
        });
        assert_eq!(
            transaction.map(|result| result.label()),
            Some("Transaction-11")
        );
    }

    #[test]
    fn nested_transactions_assign_samples_once_and_propagate_unrepresented_timers() {
        let package = SamplePackage::builder(NodeId::new(10), Arc::new(Sampler))
            .sampler_factory(Arc::new(SamplerFactoryImpl))
            .timer_factories(vec![Arc::new(FixedTimerFactory)])
            .build();
        let packages = CompiledPackages::from_packages([package]).expect("packages");
        let program = LogicProgram::compile(crate::LogicNode::Transaction {
            id: 11,
            parent: true,
            include_timers: true,
            children: vec![crate::LogicNode::Transaction {
                id: 12,
                parent: true,
                include_timers: false,
                children: vec![crate::LogicNode::Sample { id: 10 }],
            }],
        })
        .expect("logic program");
        let group = ThreadGroupPlan::new_logic(NodeId::new(20), "main", 1, program, packages)
            .expect("logic group");
        let mut plan = EnginePlan::new();
        plan.push_group(group).expect("group");
        let mut engine = trace_engine(plan, RuntimeCapabilities::default(), "run", "host");
        let report = block_on(engine.run()).expect("run");
        let inner = report.events.iter().find_map(|event| match event {
            EngineEvent::Sample {
                sampler_id,
                result: Some(result),
                ..
            } if *sampler_id == NodeId::new(12) => Some(result),
            _ => None,
        });
        let outer = report.events.iter().find_map(|event| match event {
            EngineEvent::Sample {
                sampler_id,
                result: Some(result),
                ..
            } if *sampler_id == NodeId::new(11) => Some(result),
            _ => None,
        });
        assert_eq!(inner.map(|result| result.sub_results().len()), Some(1));
        assert_eq!(outer.map(|result| result.sub_results().len()), Some(1));
        assert_eq!(
            outer
                .and_then(SampleResult::elapsed)
                .map(ElapsedTime::as_millis),
            Some(5)
        );
        assert_eq!(
            outer.map(|result| result.sub_results()[0].sub_results().len()),
            Some(1)
        );
    }

    #[test]
    fn non_parent_transaction_flattens_children_but_keeps_timer_duration() {
        let package = SamplePackage::builder(NodeId::new(10), Arc::new(Sampler))
            .sampler_factory(Arc::new(SamplerFactoryImpl))
            .timer_factories(vec![Arc::new(FixedTimerFactory)])
            .build();
        let packages = CompiledPackages::from_packages([package]).expect("packages");
        let program = LogicProgram::compile(crate::LogicNode::Transaction {
            id: 11,
            parent: false,
            include_timers: true,
            children: vec![crate::LogicNode::Sample { id: 10 }],
        })
        .expect("logic program");
        let group = ThreadGroupPlan::new_logic(NodeId::new(20), "main", 1, program, packages)
            .expect("logic group");
        let mut plan = EnginePlan::new();
        plan.push_group(group).expect("group");
        let mut engine = trace_engine(plan, RuntimeCapabilities::default(), "run", "host");
        let report = block_on(engine.run()).expect("run");
        let transaction = report.events.iter().find_map(|event| match event {
            EngineEvent::Sample {
                sampler_id,
                result: Some(result),
                ..
            } if *sampler_id == NodeId::new(11) => Some(result),
            _ => None,
        });
        assert_eq!(
            transaction.map(|result| result.sub_results().len()),
            Some(0)
        );
        assert_eq!(
            transaction
                .and_then(SampleResult::elapsed)
                .map(ElapsedTime::as_millis),
            Some(5)
        );
    }

    #[test]
    fn lifecycle_error_still_runs_teardown_and_test_finished() {
        let failing = ThreadGroupPlan::new(
            NodeId::new(1),
            "setup",
            1,
            ControllerProgram::compile(crate::ControllerNode::sample(99)).expect("controller"),
            CompiledPackages::default(),
        )
        .expect("group")
        .with_kind(GroupKind::Setup);
        let teardown = ThreadGroupPlan::new(
            NodeId::new(2),
            "teardown",
            1,
            ControllerProgram::compile(crate::ControllerNode::simple(0, vec![]))
                .expect("controller"),
            CompiledPackages::default(),
        )
        .expect("group")
        .with_kind(GroupKind::Teardown);
        let mut plan = EnginePlan::new();
        plan.push_group(failing).expect("setup");
        plan.push_group(teardown).expect("teardown");
        let mut engine = trace_engine(plan, RuntimeCapabilities::default(), "run", "host");
        assert!(block_on(engine.run()).is_err());
        let events = engine.events();
        assert!(events.iter().any(|event| {
            matches!(
                event,
                EngineEvent::GroupStarted {
                    id,
                    kind: GroupKind::Teardown
                } if *id == NodeId::new(2)
            )
        }));
        assert!(
            events
                .iter()
                .any(|event| matches!(event, EngineEvent::TestFinished { .. }))
        );
    }

    #[test]
    fn multi_user_group_runs_bounded_users_with_one_based_identity() {
        let group = ThreadGroupPlan::new(
            NodeId::new(1),
            "main",
            2,
            ControllerProgram::compile(crate::ControllerNode::simple(0, vec![]))
                .expect("controller"),
            CompiledPackages::default(),
        )
        .expect("group");
        let mut plan = EnginePlan::new();
        plan.push_group(group).expect("group");
        let mut engine = trace_engine(plan, RuntimeCapabilities::default(), "run", "host");
        let report = block_on(engine.run()).expect("concurrent users");
        assert_eq!(report.users_started, 2);
        assert_eq!(report.users_finished, 2);
        let started = report
            .events
            .iter()
            .filter_map(|event| match event {
                EngineEvent::UserStarted { thread_number, .. } => Some(*thread_number),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(started, vec![1, 2]);
        assert!(
            report
                .events
                .iter()
                .any(|event| matches!(event, EngineEvent::TestFinished { .. }))
        );
    }

    #[test]
    fn zero_thread_group_emits_group_boundaries_without_users() {
        let package = SamplePackage::builder(NodeId::new(1), Arc::new(Sampler))
            .sampler_factory(Arc::new(SamplerFactoryImpl))
            .build();
        let packages = CompiledPackages::from_packages([package]).expect("packages");
        let controller =
            ControllerProgram::compile(crate::ControllerNode::sample(1)).expect("controller");
        let group =
            ThreadGroupPlan::new(NodeId::new(10), "empty", 0, controller, packages).expect("group");
        let mut plan = EnginePlan::new();
        plan.push_group(group).expect("group");
        let mut engine = trace_engine(plan, RuntimeCapabilities::default(), "run", "host");

        let report = block_on(engine.run()).expect("zero-thread run");

        assert_eq!(report.users_started, 0);
        assert_eq!(report.users_finished, 0);
        assert!(report.events.iter().any(
            |event| matches!(event, EngineEvent::GroupStarted { id, .. } if *id == NodeId::new(10))
        ));
        assert!(report.events.iter().any(
            |event| matches!(event, EngineEvent::GroupFinished { id, .. } if *id == NodeId::new(10))
        ));
        assert!(!report.events.iter().any(|event| matches!(
            event,
            EngineEvent::UserStarted { .. } | EngineEvent::Sample { .. }
        )));
    }

    #[test]
    fn zero_iterations_starts_and_finishes_user_without_iteration_or_sample() {
        let package = SamplePackage::builder(NodeId::new(1), Arc::new(Sampler))
            .sampler_factory(Arc::new(SamplerFactoryImpl))
            .build();
        let packages = CompiledPackages::from_packages([package]).expect("packages");
        let controller =
            ControllerProgram::compile(crate::ControllerNode::sample(1)).expect("controller");
        let group = ThreadGroupPlan::new(NodeId::new(10), "zero-loops", 1, controller, packages)
            .expect("group")
            .with_iterations(Some(0));
        let mut plan = EnginePlan::new();
        plan.push_group(group).expect("group");
        let mut engine = trace_engine(plan, RuntimeCapabilities::default(), "run", "host");

        let report = block_on(engine.run()).expect("zero-iteration run");

        assert_eq!(report.users_started, 1);
        assert_eq!(report.users_finished, 1);
        assert!(!report.events.iter().any(|event| matches!(
            event,
            EngineEvent::Sample { .. } | EngineEvent::Iteration { .. }
        )));
    }

    #[test]
    fn graceful_stop_skips_remaining_main_groups() {
        let first = Arc::new(AtomicBool::new(true));
        let stopping_package = SamplePackage::builder(
            NodeId::new(1),
            Arc::new(StopFirstSampler {
                first: Arc::clone(&first),
                signal: ControlSignal::StopTestGraceful,
            }),
        )
        .sampler_factory(Arc::new(StopFirstSamplerFactory {
            first,
            signal: ControlSignal::StopTestGraceful,
        }))
        .build();
        let normal_package = SamplePackage::builder(NodeId::new(1), Arc::new(Sampler))
            .sampler_factory(Arc::new(SamplerFactoryImpl))
            .build();
        let stopping_packages =
            CompiledPackages::from_packages([stopping_package]).expect("stopping packages");
        let normal_packages =
            CompiledPackages::from_packages([normal_package]).expect("normal packages");
        let controller =
            ControllerProgram::compile(crate::ControllerNode::sample(1)).expect("controller");
        let setup = ThreadGroupPlan::new(
            NodeId::new(1),
            "setup",
            1,
            controller.clone(),
            normal_packages.clone(),
        )
        .expect("setup")
        .with_kind(GroupKind::Setup);
        let main = ThreadGroupPlan::new(
            NodeId::new(2),
            "main-stop",
            1,
            controller.clone(),
            stopping_packages,
        )
        .expect("main");
        let remaining_main = ThreadGroupPlan::new(
            NodeId::new(3),
            "main-remaining",
            1,
            controller.clone(),
            normal_packages.clone(),
        )
        .expect("main");
        let teardown =
            ThreadGroupPlan::new(NodeId::new(4), "teardown", 1, controller, normal_packages)
                .expect("teardown")
                .with_kind(GroupKind::Teardown);
        let mut plan = EnginePlan::new();
        plan.serialize_thread_groups = true;
        for group in [setup, main, remaining_main, teardown] {
            plan.push_group(group).expect("group");
        }
        let mut engine = trace_engine(plan, RuntimeCapabilities::default(), "run", "host");

        let report = block_on(engine.run()).expect("graceful stop is a report");

        assert_eq!(report.signal, ControlSignal::StopTestGraceful);
        let started = report
            .events
            .iter()
            .filter_map(|event| match event {
                EngineEvent::GroupStarted { id, .. } => Some(*id),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            started,
            vec![NodeId::new(1), NodeId::new(2), NodeId::new(4)]
        );
    }

    #[test]
    fn teardown_policy_does_not_block_graceful_teardown() {
        let first = Arc::new(AtomicBool::new(true));
        let stopping_package = SamplePackage::builder(
            NodeId::new(1),
            Arc::new(StopFirstSampler {
                first: Arc::clone(&first),
                signal: ControlSignal::StopTestGraceful,
            }),
        )
        .sampler_factory(Arc::new(StopFirstSamplerFactory {
            first,
            signal: ControlSignal::StopTestGraceful,
        }))
        .build();
        let packages = CompiledPackages::from_packages([stopping_package]).expect("packages");
        let controller =
            ControllerProgram::compile(crate::ControllerNode::sample(1)).expect("controller");
        let main = ThreadGroupPlan::new(
            NodeId::new(1),
            "main",
            1,
            controller.clone(),
            packages.clone(),
        )
        .expect("main");
        let mut teardown =
            ThreadGroupPlan::new(NodeId::new(2), "teardown", 1, controller, packages)
                .expect("teardown")
                .with_kind(GroupKind::Teardown);
        teardown.teardown_on_shutdown = false;
        let mut plan = EnginePlan::new();
        plan.push_group(main).expect("main");
        plan.push_group(teardown).expect("teardown");
        let mut engine = trace_engine(plan, RuntimeCapabilities::default(), "run", "host");

        let report = block_on(engine.run()).expect("graceful stop is a report");

        assert_eq!(report.signal, ControlSignal::StopTestGraceful);
        assert!(report.events.iter().any(|event| {
            matches!(event, EngineEvent::GroupStarted { id, kind: GroupKind::Teardown } if *id == NodeId::new(2))
        }));
    }

    #[test]
    fn run_wrapper_exposes_one_fresh_read_only_handle_per_run() {
        let mut engine = trace_engine(
            EnginePlan::new(),
            RuntimeCapabilities::default(),
            "run",
            "host",
        );

        let first = engine.run();
        let first_handle = first.progress_handle();
        assert_eq!(
            first_handle.snapshot().terminal,
            crate::ProgressTerminalState::Running
        );
        let first_report = block_on(first).expect("first run");
        assert_eq!(
            first_handle.snapshot().terminal,
            crate::ProgressTerminalState::Completed
        );

        let second = engine.run();
        let second_handle = second.progress_handle();
        assert_eq!(
            second_handle.snapshot().terminal,
            crate::ProgressTerminalState::Running
        );
        assert_eq!(
            first_handle.snapshot().terminal,
            crate::ProgressTerminalState::Completed
        );
        let second_report = block_on(second).expect("second run");
        assert_eq!(
            second_handle.snapshot().terminal,
            crate::ProgressTerminalState::Completed
        );
        assert_eq!(
            first_handle.generation(),
            first_report
                .events
                .len()
                .checked_add(2)
                .and_then(|value| std::num::NonZeroU64::new(value as u64))
                .expect("first generation")
        );
        assert_eq!(
            second_handle.generation(),
            second_report
                .events
                .len()
                .checked_add(2)
                .and_then(|value| std::num::NonZeroU64::new(value as u64))
                .expect("second generation")
        );
    }

    #[test]
    fn lifecycle_and_sample_observations_share_one_checked_progress_owner() {
        let package = SamplePackage::builder(NodeId::new(1), Arc::new(Sampler))
            .sampler_factory(Arc::new(SamplerFactoryImpl))
            .build();
        let packages = CompiledPackages::from_packages([package]).expect("packages");
        let controller =
            ControllerProgram::compile(crate::ControllerNode::sample(1)).expect("controller");
        let group =
            ThreadGroupPlan::new(NodeId::new(1), "main", 1, controller, packages).expect("group");
        let mut plan = EnginePlan::new();
        plan.push_group(group).expect("group");
        let mut engine = trace_engine(plan, RuntimeCapabilities::default(), "run", "host");

        let run = engine.run();
        let handle = run.progress_handle();
        let report = block_on(run).expect("sample run");

        let expected = report
            .events
            .len()
            .checked_add(2)
            .and_then(|value| u64::try_from(value).ok())
            .and_then(std::num::NonZeroU64::new)
            .expect("bounded progress generation");
        assert_eq!(
            handle.snapshot().terminal,
            crate::ProgressTerminalState::Completed
        );
        assert_eq!(handle.generation(), expected);
        assert!(
            report
                .events
                .iter()
                .any(|event| matches!(event, EngineEvent::Sample { .. }))
        );
    }

    #[test]
    fn failed_and_dropped_runs_have_distinct_terminal_progress_states() {
        let controller =
            ControllerProgram::compile(crate::ControllerNode::sample(1)).expect("controller");
        let group = ThreadGroupPlan::new(
            NodeId::new(1),
            "missing-package",
            1,
            controller,
            CompiledPackages::default(),
        )
        .expect("group");
        let mut plan = EnginePlan::new();
        plan.push_group(group).expect("group");
        let mut engine = trace_engine(plan, RuntimeCapabilities::default(), "run", "host");

        let failed = engine.run();
        let failed_handle = failed.progress_handle();
        assert!(block_on(failed).is_err());
        assert_eq!(
            failed_handle.snapshot().terminal,
            crate::ProgressTerminalState::Failed
        );

        struct SelfWakingPendingSleeper {
            wakes: Arc<AtomicUsize>,
        }

        impl Sleeper for SelfWakingPendingSleeper {
            fn sleep<'a>(&'a self, _duration: Duration) -> CapabilityFuture<'a, ()> {
                let wakes = Arc::clone(&self.wakes);
                Box::pin(std::future::poll_fn(move |context| {
                    wakes.fetch_add(1, Ordering::AcqRel);
                    context.waker().wake_by_ref();
                    Poll::Pending
                }))
            }
        }

        let controller =
            ControllerProgram::compile(crate::ControllerNode::sample(1)).expect("controller");
        let group = ThreadGroupPlan::new(
            NodeId::new(2),
            "pending",
            1,
            controller,
            CompiledPackages::default(),
        )
        .expect("group")
        .with_schedule(GroupSchedule {
            delay: Duration::from_secs(1),
            ..GroupSchedule::default()
        });
        let mut pending_plan = EnginePlan::new();
        pending_plan.push_group(group).expect("group");
        let wakes = Arc::new(AtomicUsize::new(0));
        let capabilities = RuntimeCapabilities::default()
            .with_clock(Arc::new(StaticClock))
            .with_sleeper(Arc::new(SelfWakingPendingSleeper {
                wakes: Arc::clone(&wakes),
            }));
        let mut pending_engine = trace_engine(pending_plan, capabilities, "run", "host");
        let mut pending = pending_engine.run();
        let pending_handle = pending.progress_handle();
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        assert!(Pin::new(&mut pending).poll(&mut context).is_pending());
        let after_first_poll = pending_handle.snapshot();
        assert!(Pin::new(&mut pending).poll(&mut context).is_pending());
        assert_eq!(pending_handle.snapshot(), after_first_poll);
        assert!(wakes.load(Ordering::Acquire) >= 2);
        drop(pending);
        assert_eq!(
            pending_handle.snapshot().terminal,
            crate::ProgressTerminalState::Cancelled
        );
        assert_eq!(
            pending_engine.cancellation().signal(),
            ControlSignal::StopTestImmediate
        );
        assert_eq!(pending_engine.last_progress_error(), None);
    }
}
