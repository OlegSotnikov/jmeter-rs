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

use crate::{
    AdmissionOutcome, CancellationToken, CompiledPackages, ControlSignal, ControllerError,
    ControllerProgram, ControllerStep, CriticalSectionError, ExecutionContext, ExecutionPipeline,
    LogicInput, LogicProgram, LogicSharedState, LogicStep, PackageCompileError, PipelineError,
    ResultEventMetadata, ResultOrigin, ResultRouter, ResultRouterError, RuntimeCapabilities,
    SampleFailure, SampleIdentity, TransactionInfo, UserIdentity,
};

const MAX_GROUPS: usize = 1_024;
const MAX_THREADS: usize = 1_000_000;
const MAX_EVENTS: usize = 1_000_000;
const MAX_CONCURRENT_TASKS: usize = 65_536;
const MAX_SCHEDULER_POLLS: usize = 1_000_000;

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
    /// Creates a validated schedule.
    pub fn new(threads: usize, ramp_up: Duration) -> Result<Self, EngineError> {
        if threads > MAX_THREADS {
            return Err(EngineError::InvalidSchedule {
                detail: "thread count exceeds runtime bound".to_owned(),
            });
        }
        Ok(Self { threads, ramp_up })
    }

    /// Returns the start offset for a zero-based thread index.
    #[must_use]
    pub fn offset(self, index: usize) -> Duration {
        if self.threads <= 1 || index == 0 || self.ramp_up.is_zero() {
            return Duration::ZERO;
        }
        let bounded = index.min(self.threads.saturating_sub(1)) as u128;
        let numerator = self.ramp_up.as_nanos().saturating_mul(bounded);
        let denominator = self.threads as u128;
        let nanos = numerator / denominator;
        let seconds = nanos / 1_000_000_000;
        let subnanos = (nanos % 1_000_000_000) as u32;
        if seconds > u64::MAX as u128 {
            Duration::MAX
        } else {
            Duration::new(seconds as u64, subnanos)
        }
    }

    /// Returns all offsets in deterministic thread-number order.
    #[must_use]
    pub fn offsets(self) -> Vec<Duration> {
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
        if let Some(duration) = self.duration
            && duration.is_zero()
            && self.delay.is_zero()
        {
            return RampSchedule::new(threads, self.ramp_up);
        }
        RampSchedule::new(threads, self.ramp_up)
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
}

impl EnginePlan {
    /// Creates an empty engine plan.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            groups: Vec::new(),
            serialize_thread_groups: false,
            teardown_on_shutdown: true,
        }
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
    ) -> Self {
        let mut context = ExecutionContext::with_capabilities(capabilities.clone_for_user());
        context.set_run(run_id.clone());
        context.set_host(host.clone());
        context.set_thread(ThreadIdentity::with_group(
            format!("{}-{}", group.name, thread_number),
            Some(group.name.clone()),
            Some(thread_number as u64),
        ));
        context.set_lifecycle_id(Some(lifecycle_id));
        context.set_iteration_id(Some(0));
        Self {
            lifecycle_id,
            group_id: group.id,
            thread_number,
            iteration: IterationState::default(),
            context,
        }
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
#[derive(Clone, Debug, Default)]
pub struct EngineReport {
    /// Ordered lifecycle/sample events.
    pub events: Vec<EngineEvent>,
    /// Highest cancellation signal observed.
    pub signal: ControlSignal,
    /// Number of users started.
    pub users_started: usize,
    /// Number of users finished.
    pub users_finished: usize,
}

struct ActiveTransaction {
    info: TransactionInfo,
    parent_id: Option<u64>,
    plan_path: Vec<NodeId>,
    result: SampleResult,
    unrepresented_timers: Duration,
}

struct CriticalSectionLeases {
    coordinator: Arc<dyn crate::CriticalSectionCoordinator>,
    lifecycle_id: u64,
    names: Vec<String>,
    drop_error: Arc<Mutex<Option<CriticalSectionError>>>,
}

impl CriticalSectionLeases {
    fn release(&mut self) -> Result<(), CriticalSectionError> {
        while let Some(name) = self.names.pop() {
            if let Err(error) = self.coordinator.release(&name, self.lifecycle_id) {
                self.names.push(name);
                return Err(error);
            }
        }
        Ok(())
    }
}

impl Drop for CriticalSectionLeases {
    fn drop(&mut self) {
        while let Some(name) = self.names.pop() {
            if let Err(error) = self.coordinator.release(&name, self.lifecycle_id) {
                let mut slot = lock(&self.drop_error);
                if slot.is_none() {
                    *slot = Some(error);
                }
            }
        }
    }
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
            Self::CriticalSection { .. } => "runtime.engine.critical-section",
            Self::ExpressionCleanup { .. } => "runtime.engine.expression-cleanup",
            Self::Pipeline { .. } => "runtime.engine.pipeline",
            Self::ResultRouter { .. } => "runtime.engine.result-router",
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
/// futures retain ownership of their own wake registrations. A task-set poll
/// bound converts a broken/non-waking capability into a typed resource error
/// instead of spinning forever.
struct DeterministicJoin<'a, T> {
    tasks: Vec<Pin<Box<dyn Future<Output = T> + 'a>>>,
    results: Vec<Option<T>>,
    polls: usize,
    max_polls: usize,
}

impl<'a, T> DeterministicJoin<'a, T> {
    fn new(tasks: Vec<Pin<Box<dyn Future<Output = T> + 'a>>>) -> Self {
        let result_count = tasks.len();
        Self {
            tasks,
            results: (0..result_count).map(|_| None).collect(),
            polls: 0,
            max_polls: MAX_SCHEDULER_POLLS,
        }
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
            if this.polls >= this.max_polls {
                return Poll::Ready(Err(EngineError::ResourceLimit {
                    detail: "deterministic concurrent scheduler poll limit".to_owned(),
                }));
            }
            this.polls = this.polls.saturating_add(1);
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
pub type RuntimeEngineFuture<'a> =
    Pin<Box<dyn Future<Output = Result<EngineReport, EngineError>> + 'a>>;

struct EngineRunDropGuard {
    router: Option<ResultRouter>,
    armed: bool,
}

impl EngineRunDropGuard {
    fn new(router: Option<ResultRouter>) -> Self {
        Self {
            router,
            armed: true,
        }
    }

    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for EngineRunDropGuard {
    fn drop(&mut self) {
        if self.armed
            && let Some(router) = self.router.as_ref()
        {
            let _ = router.cancel();
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
    cancellation: CancellationToken,
    events: Arc<Mutex<Vec<EngineEvent>>>,
    next_lifecycle: Arc<AtomicU64>,
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
            cancellation: CancellationToken::new(),
            events: Arc::new(Mutex::new(Vec::new())),
            next_lifecycle: Arc::new(AtomicU64::new(1)),
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
            cancellation: self.cancellation.clone(),
            events: Arc::clone(&self.events),
            next_lifecycle: Arc::clone(&self.next_lifecycle),
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

    /// Returns the immutable plan.
    #[must_use]
    pub const fn plan(&self) -> &EnginePlan {
        &self.plan
    }

    /// Returns retained event snapshots from a previous/current run.
    #[must_use]
    pub fn events(&self) -> Vec<EngineEvent> {
        lock(&self.events).clone()
    }

    /// Starts one run. The future owns no executor and performs no ambient
    /// I/O; all component effects enter through their explicit capabilities.
    pub fn run<'a>(&'a mut self) -> RuntimeEngineFuture<'a> {
        Box::pin(async move {
            let guard = EngineRunDropGuard::new(self.result_router.clone());
            let primary = self.run_inner().await;
            let finalization = if let Some(router) = self.result_router.as_ref() {
                router
                    .finish()
                    .await
                    .err()
                    .map(|source| EngineError::ResultRouter { source })
            } else {
                None
            };
            guard.disarm();
            match (primary, finalization) {
                (Ok(report), None) => Ok(report),
                (Ok(_), Some(error)) => Err(error),
                (Err(primary), None) => Err(primary),
                (Err(primary), Some(secondary)) => Err(EngineError::Combined {
                    primary: Box::new(primary),
                    secondary: Box::new(secondary),
                }),
            }
        })
    }

    async fn run_inner(&mut self) -> Result<EngineReport, EngineError> {
        if let Some(router) = self.result_router.as_ref() {
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
                    let signal = self.cancellation.signal();
                    !((signal == ControlSignal::StopTestImmediate
                        && (kind != GroupKind::Teardown
                            || !self.plan.teardown_on_shutdown
                            || !group.teardown_on_shutdown))
                        || (signal == ControlSignal::StopTestGraceful && kind == GroupKind::Main))
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
                match DeterministicJoin::new(tasks).await {
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
                }
                continue;
            }
            for group in candidates {
                let signal = self.cancellation.signal();
                if (signal == ControlSignal::StopTestImmediate
                    && (kind != GroupKind::Teardown
                        || !self.plan.teardown_on_shutdown
                        || !group.teardown_on_shutdown))
                    || (signal == ControlSignal::StopTestGraceful && kind == GroupKind::Main)
                {
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
        report.events = self.events();
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
        self.push_event(EngineEvent::GroupStarted {
            id: group.id,
            kind: group.kind,
        })?;
        let mut tasks = Vec::with_capacity(group.threads);
        let mut preparation_error = None;
        for thread_index in 0..group.threads {
            if self.cancellation.signal().is_stop() && group.kind != GroupKind::Teardown {
                break;
            }
            if group.schedule.duration.is_some_and(|duration| {
                self.capabilities
                    .clock()
                    .now()
                    .monotonic
                    .saturating_sub(group_start)
                    >= duration
            }) {
                break;
            }
            let offset = group
                .schedule
                .delay
                .checked_add(ramp.offset(thread_index))
                .ok_or_else(|| EngineError::InvalidSchedule {
                    detail: "group schedule delay overflow".to_owned(),
                })?;
            let target = group_start.saturating_add(offset);
            let thread_number =
                thread_index
                    .checked_add(1)
                    .ok_or_else(|| EngineError::InvalidSchedule {
                        detail: "thread number overflow".to_owned(),
                    })?;
            let group_id = group.id;
            let group_kind = group.kind;
            let duration = group.schedule.duration;
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
                    || duration.is_some_and(|limit| {
                        runtime
                            .capabilities
                            .clock()
                            .now()
                            .monotonic
                            .saturating_sub(group_start)
                            >= limit
                    })
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
                let mut user = VirtualUser::new(
                    lifecycle_id,
                    group,
                    thread_number,
                    &runtime.run_id,
                    &runtime.host,
                    &runtime.capabilities,
                );
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
        match DeterministicJoin::new(tasks).await {
            Ok(results) => {
                for result in results {
                    report.users_started = report.users_started.saturating_add(result.started);
                    report.users_finished = report.users_finished.saturating_add(result.finished);
                    report.signal = report.signal.combine(result.signal);
                    if let Err(error) = result.result {
                        combine_engine_error(&mut preparation_error, error);
                    }
                }
            }
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
        user: &mut VirtualUser,
        report: &mut EngineReport,
        mut packages: CompiledPackages,
        shared_logic: Arc<LogicSharedState>,
        cleanup: &mut LifecycleCleanupGuard,
        cooperative: bool,
    ) -> Result<(), EngineError> {
        if let Some(program) = group.logic_controller.clone() {
            return self
                .run_logic_user(
                    group,
                    group_start,
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
                        && group.schedule.duration.is_none_or(|duration| {
                            self.capabilities
                                .clock()
                                .now()
                                .monotonic
                                .saturating_sub(group_start)
                                < duration
                        });
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
                        )
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
                    if matches!(
                        signal,
                        ControlSignal::StopTestGraceful | ControlSignal::StopTestImmediate
                    ) {
                        self.cancellation.request(signal);
                    }
                    break;
                }
                ControllerStep::Sample(selection) => {
                    user.context
                        .set_sampler_name(Some(selection.sampler_id.to_string()));
                    let package = packages.get(NodeId::new(selection.sampler_id)).ok_or(
                        EngineError::MissingPackage {
                            group_id: group.id,
                            sampler_id: NodeId::new(selection.sampler_id),
                        },
                    )?;
                    let result = ExecutionPipeline::execute(package, &mut user.context)
                        .await
                        .map_err(|source| EngineError::Pipeline {
                            group_id: group.id,
                            sampler_id: package.sampler_id(),
                            source,
                        })?;
                    let signal = result.signal;
                    if let Some(event) = result.event.clone() {
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
                    self.push_event(EngineEvent::Sample {
                        group_id: group.id,
                        thread_number: user.thread_number,
                        sampler_id: result.sampler_id,
                        result: result.result.clone(),
                        failure: result.sample_failure.clone(),
                        signal,
                    })?;
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
        user: &mut VirtualUser,
        report: &mut EngineReport,
        mut packages: CompiledPackages,
        shared_logic: Arc<LogicSharedState>,
        program: LogicProgram,
        cleanup: &mut LifecycleCleanupGuard,
        cooperative: bool,
    ) -> Result<(), EngineError> {
        let mut completed_iterations = 0_u64;
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
                if steps > max_steps {
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
                    .saturating_sub(group_start);
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
                    LogicStep::Complete => break,
                    LogicStep::NeedsRandom => continue,
                    LogicStep::Stopped(signal) => {
                        report.signal = report.signal.combine(signal);
                        self.finish_transactions(
                            group,
                            user,
                            report,
                            &mut transactions,
                            &mut transaction_order,
                        )?;
                        self.deliver_result_router().await?;
                        if matches!(
                            signal,
                            ControlSignal::StopTestGraceful | ControlSignal::StopTestImmediate
                        ) {
                            self.cancellation.request(signal);
                        }
                        return Ok(());
                    }
                    LogicStep::Sample(selection) => {
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
                        let mut acquired =
                            self.acquire_critical_sections(group, user, &selection)?;
                        let pipeline_result =
                            ExecutionPipeline::execute(package, &mut user.context)
                                .await
                                .map_err(|source| EngineError::Pipeline {
                                    group_id: group.id,
                                    sampler_id: package.sampler_id(),
                                    source,
                                });
                        let release_result =
                            acquired
                                .release()
                                .map_err(|source| EngineError::CriticalSection {
                                    group_id: group.id,
                                    source,
                                });
                        let result = match (pipeline_result, release_result) {
                            (Ok(result), Ok(())) => result,
                            (Err(primary), Ok(())) => return Err(primary),
                            (Ok(_), Err(secondary)) => return Err(secondary),
                            (Err(primary), Err(secondary)) => {
                                return Err(EngineError::Combined {
                                    primary: Box::new(primary),
                                    secondary: Box::new(secondary),
                                });
                            }
                        };
                        let context_variables = user.context.variables().clone();
                        runner.replace_variables(&context_variables);
                        if let Some(sample) = result.result.as_ref() {
                            last_sample_success = sample.success();
                        }
                        let result_signal = result.signal;
                        if let Some(event) = result.event.clone() {
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
                        self.push_event(EngineEvent::Sample {
                            group_id: group.id,
                            thread_number: user.thread_number,
                            sampler_id: result.sampler_id,
                            result: result.result.clone(),
                            failure: result.sample_failure.clone(),
                            signal: result_signal,
                        })?;
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
            self.finish_transactions(
                group,
                user,
                report,
                &mut transactions,
                &mut transaction_order,
            )?;
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
                || group.schedule.duration.is_some_and(|duration| {
                    user.context
                        .capabilities()
                        .clock()
                        .now()
                        .monotonic
                        .saturating_sub(group_start)
                        >= duration
                })
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
                )
                .context;
                if group.kind != GroupKind::Teardown {
                    user.context.attach_cancellation(&self.cancellation);
                }
                cleanup.set_lifecycle(lifecycle_id);
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
        self.push_event(EngineEvent::Sample {
            group_id: group.id,
            thread_number: user.thread_number,
            sampler_id: NodeId::new(transaction.info.id),
            result: Some(result),
            failure: None,
            signal: ControlSignal::Continue,
        })?;
        report.signal = report.signal.combine(ControlSignal::Continue);
        Ok(())
    }

    fn acquire_critical_sections(
        &self,
        group: &ThreadGroupPlan,
        user: &VirtualUser,
        selection: &crate::LogicSelection,
    ) -> Result<CriticalSectionLeases, EngineError> {
        let coordinator = user.context.capabilities().critical_sections_arc();
        let mut acquired: Vec<String> = Vec::new();
        let mut seen = BTreeSet::new();
        for name in &selection.critical_sections {
            if !seen.insert(name.clone()) {
                continue;
            }
            if let Err(source) = coordinator.try_acquire(name, user.lifecycle_id) {
                let primary = EngineError::CriticalSection {
                    group_id: group.id,
                    source,
                };
                let mut rollback_error = None;
                for held in acquired.iter().rev() {
                    if let Err(error) = coordinator.release(held, user.lifecycle_id) {
                        combine_engine_error(
                            &mut rollback_error,
                            EngineError::CriticalSection {
                                group_id: group.id,
                                source: error,
                            },
                        );
                    }
                }
                return Err(match rollback_error {
                    Some(secondary) => EngineError::Combined {
                        primary: Box::new(primary),
                        secondary: Box::new(secondary),
                    },
                    None => primary,
                });
            }
            acquired.push(name.clone());
        }
        Ok(CriticalSectionLeases {
            coordinator,
            lifecycle_id: user.lifecycle_id,
            names: acquired,
            drop_error: Arc::new(Mutex::new(None)),
        })
    }

    fn push_event(&self, event: EngineEvent) -> Result<(), EngineError> {
        let mut events = lock(&self.events);
        if events.len() >= MAX_EVENTS {
            return Err(EngineError::ResourceLimit {
                detail: "engine event capacity".to_owned(),
            });
        }
        events.push(event);
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
            AdmissionOutcome::Accepted { .. } => Ok(()),
            outcome => Err(EngineError::ResultRouter {
                source: ResultRouterError::Admission { outcome },
            }),
        }
    }

    async fn deliver_result_router(&self) -> Result<(), EngineError> {
        if let Some(router) = self.result_router.as_ref() {
            router
                .deliver()
                .await
                .map_err(|source| EngineError::ResultRouter { source })?;
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
    use crate::{
        CapabilityFuture, Clock, ClockReading, ComponentFuture, ResultEnvelope, ResultOrigin,
        ResultRouter, ResultSink, ResultSinkFuture, ResultSinkSpec, RunSequence, SamplePackage,
        SamplerFactory, SamplerOutput, SinkId, SinkLimits, Sleeper, TimerFactory,
    };
    use jmeter_rs_expr::BuiltinFunctions;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll, Waker};

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

    struct SamplerFactoryImpl;
    impl SamplerFactory for SamplerFactoryImpl {
        fn create(&self) -> Arc<dyn crate::Sampler> {
            Arc::new(Sampler)
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
        assert_eq!(ramp.offset(0), Duration::ZERO);
        assert_eq!(ramp.offset(9), Duration::from_secs(90));
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
        let mut engine = RuntimeEngine::new(plan, capabilities, "run", "host");
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
        let mut engine = RuntimeEngine::new(plan, capabilities, "run", "host");
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
        let mut engine = RuntimeEngine::new(plan, capabilities, "run", "host");
        let error = block_on(engine.run()).expect_err("cleanup failure");
        assert!(
            error
                .to_string()
                .contains("runtime.engine.expression-cleanup")
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
        let mut engine = RuntimeEngine::new(plan, RuntimeCapabilities::default(), "run", "host");
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
        let mut engine = RuntimeEngine::new(plan, RuntimeCapabilities::default(), "run", "host");
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
        let mut engine = RuntimeEngine::new(plan, capabilities, "run", "host");
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
        let mut engine = RuntimeEngine::new(plan, RuntimeCapabilities::default(), "run", "host");
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
        let mut engine = RuntimeEngine::new(plan, RuntimeCapabilities::default(), "run", "host");
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
        let mut engine = RuntimeEngine::new(plan, RuntimeCapabilities::default(), "run", "host");
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
        let mut engine = RuntimeEngine::new(plan, RuntimeCapabilities::default(), "run", "host");
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
        let mut engine = RuntimeEngine::new(plan, RuntimeCapabilities::default(), "run", "host");
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
        let mut engine = RuntimeEngine::new(plan, capabilities, "run", "host");
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
        let mut engine = RuntimeEngine::new(plan, RuntimeCapabilities::default(), "run", "host");
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
        let mut engine = RuntimeEngine::new(plan, RuntimeCapabilities::default(), "run", "host")
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
        let mut engine = RuntimeEngine::new(plan, RuntimeCapabilities::default(), "run", "host");
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
        let mut engine = RuntimeEngine::new(plan, RuntimeCapabilities::default(), "run", "host");
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
        let mut engine = RuntimeEngine::new(plan, RuntimeCapabilities::default(), "run", "host");
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
        let mut engine = RuntimeEngine::new(plan, RuntimeCapabilities::default(), "run", "host");
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
}
