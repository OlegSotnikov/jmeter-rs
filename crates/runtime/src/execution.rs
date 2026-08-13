// SPDX-License-Identifier: Apache-2.0
//! Executor-neutral component contracts and the per-sampler execution phase.
//!
//! A [`SamplePackage`] is an immutable, identity-keyed description of one
//! sampler and its already-resolved scope.  [`ExecutionPipeline`] executes a
//! package for one [`ExecutionContext`] and never chooses component order on
//! its own: the vectors in the package are the compiler's verified order.
//! Components return boxed standard-library futures, so this module does not
//! require Tokio (or any other executor).

#![allow(
    missing_docs,
    reason = "the public execution vocabulary is documented by its module and trait contracts"
)]

use std::collections::BTreeMap;
use std::fmt;
use std::future::{self, Future};
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;

use jmeter_rs_expr::{
    EvaluationCapabilities, EvaluationError, Evaluator, FileCapability as ExprFileCapability,
    FunctionError, FunctionOccurrence, FunctionResolver, PropertySetter as ExprPropertySetter,
    VariableSetter as ExprVariableSetter,
};
use jmeter_rs_model::NodeId;
use jmeter_rs_results::{
    AssertionOutcome, AssertionResult, ElapsedTime, HostIdentity, LogicalAction, ResultError,
    SampleEvent, SampleResult, ThreadCount, ThreadIdentity, VariableSnapshot, WallTimestamp,
};

use crate::controllers::{Cancellation, ControlSignal};
use crate::coordination::{CriticalSectionCoordinator, DeterministicCriticalSectionCoordinator};
use crate::scheduler::{
    CancellationToken, Deadline, DeadlineFuture, MonotonicInstant, Scheduler, SchedulerError,
    WakeRegistration,
};

const DEFAULT_MAX_TRACE_DETAIL_BYTES: usize = 1_024;
const MAX_DIAGNOSTIC_BYTES: usize = 4_096;
const MAX_EXPRESSION_FILE_CURSORS: usize = 65_536;
const MAX_EXPRESSION_FILE_BYTES: usize = 1024 * 1024;

/// Returns a stable identity for one plan field without relying on process
/// addresses or a caller-provided numeric sentinel.  The evaluator accepts a
/// `u64` namespace, so the domain-qualified source tuple is reduced with a
/// fixed FNV-1a stream.  Runtime package execution supplies a non-empty
/// domain, plan node, and phase field before evaluating component expressions;
/// standalone contexts intentionally retain the expression crate's
/// source-local compatibility namespace.
fn expression_field_namespace(domain: &str, plan_node: NodeId, field: &str) -> u64 {
    const OFFSET: u64 = 14_695_981_039_346_656_037;
    const PRIME: u64 = 1_099_511_628_211;
    let mut hash = OFFSET;
    for byte in domain
        .bytes()
        .chain(std::iter::once(b':'))
        .chain(plan_node.get().to_be_bytes())
        .chain(std::iter::once(b':'))
        .chain(field.bytes())
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(PRIME);
    }
    // This is an identity value, not a fallback.  Keep the reserved evaluator
    // compatibility namespace out of plan-aware execution even if the hash
    // stream ever produces zero.
    if hash == 0 { 1 } else { hash }
}

fn bounded_text(value: impl Into<String>, limit: usize) -> String {
    let value = value.into();
    if value.len() <= limit {
        return value;
    }
    let suffix = "...";
    let keep = limit.saturating_sub(suffix.len());
    let mut end = keep.min(value.len());
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    let mut bounded = value;
    bounded.truncate(end);
    bounded.push_str(suffix);
    bounded
}

fn read_lock<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write_lock<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn mutex_lock<T>(lock: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    lock.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A future returned by an executor-neutral component.
pub type ComponentFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, ComponentError>> + 'a>>;

/// A future returned by an injected runtime capability.
pub type CapabilityFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, CapabilityError>> + 'a>>;

/// The phase currently being executed by a sampler package.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Phase {
    /// Configuration elements merge their state into the sample context.
    Configuration,
    /// Preprocessors run before timers and the sampler.
    Preprocessor,
    /// Timers are evaluated and summed before the sampler.
    Timer,
    /// The sampler performs its operation.
    Sampler,
    /// Postprocessors run after a non-null sampler result.
    Postprocessor,
    /// Assertions inspect and may annotate a non-null sampler result.
    Assertion,
    /// Listeners observe an immutable event snapshot.
    Listener,
    /// Package finish lifecycle.
    Finish,
    /// Package cleanup lifecycle.
    Cleanup,
}

/// One deterministic phase trace entry recorded by an execution context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionTraceEvent {
    /// Phase which emitted the event.
    pub phase: Phase,
    /// Component identity, when the event belongs to a component.
    pub node_id: Option<NodeId>,
    /// Optional caller-provided detail.
    pub detail: String,
}

/// A bounded in-memory trace of package activity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhaseTrace {
    events: Vec<ExecutionTraceEvent>,
    max_events: usize,
    max_detail_bytes: usize,
}

impl Default for PhaseTrace {
    fn default() -> Self {
        Self::new(4_096)
    }
}

impl PhaseTrace {
    /// Creates a trace with a finite event capacity.
    #[must_use]
    pub const fn new(max_events: usize) -> Self {
        Self::new_with_limits(max_events, DEFAULT_MAX_TRACE_DETAIL_BYTES)
    }

    /// Creates a trace with finite event and detail capacities.
    #[must_use]
    pub const fn new_with_limits(max_events: usize, max_detail_bytes: usize) -> Self {
        Self {
            events: Vec::new(),
            max_events,
            max_detail_bytes,
        }
    }

    /// Returns the configured event capacity.
    #[must_use]
    pub const fn max_events(&self) -> usize {
        self.max_events
    }

    /// Returns the maximum UTF-8 byte length of one detail string.
    #[must_use]
    pub const fn max_detail_bytes(&self) -> usize {
        self.max_detail_bytes
    }

    /// Returns retained entries in insertion order.
    #[must_use]
    pub fn events(&self) -> &[ExecutionTraceEvent] {
        &self.events
    }

    /// Removes all entries without changing the capacity.
    pub fn clear(&mut self) {
        self.events.clear();
    }

    fn push(
        &mut self,
        phase: Phase,
        node_id: Option<NodeId>,
        detail: impl Into<String>,
    ) -> Result<(), ComponentError> {
        if self.events.len() >= self.max_events {
            return Err(ComponentError::resource_limit("execution trace capacity"));
        }
        let detail = detail.into();
        if detail.len() > self.max_detail_bytes {
            return Err(ComponentError::resource_limit(
                "execution trace detail capacity",
            ));
        }
        self.events.push(ExecutionTraceEvent {
            phase,
            node_id,
            detail,
        });
        Ok(())
    }
}

/// A wall and monotonic reading supplied by an injected clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockReading {
    /// Wall timestamp used for result serialization.
    pub wall: WallTimestamp,
    /// Monotonic timestamp used for elapsed duration.
    pub monotonic: Duration,
}

/// Supplies controlled wall and monotonic time to the runtime.
pub trait Clock: Send + Sync {
    /// Reads an atomic wall/monotonic pair.
    fn now(&self) -> ClockReading;
}

/// Sleeps without coupling the runtime to an executor.
pub trait Sleeper: Send + Sync {
    /// Waits for the supplied non-negative duration.
    fn sleep<'a>(&'a self, duration: Duration) -> CapabilityFuture<'a, ()>;
}

/// Supplies deterministic random values to components.
pub trait RandomSource: Send + Sync {
    /// Returns the next value in the component's scoped stream.
    fn next_u64(&self) -> Result<u64, CapabilityError>;

    /// Creates the independent stream used by a cloned virtual-user context.
    ///
    /// Implementations must not return a view that shares mutable cursor
    /// state with `self`; immutable deterministic sources may return a fresh
    /// equivalent value object.
    fn clone_for_user(&self) -> Arc<dyn RandomSource>;
}

/// Provides explicit filesystem access to components.
pub trait FileSystem: Send + Sync {
    /// Reads an allowlisted path.
    fn read(&self, path: &str) -> Result<Vec<u8>, CapabilityError>;
}

/// Provides an explicit environment view to components.
pub trait Environment: Send + Sync {
    /// Returns an allowlisted variable, if present.
    fn get(&self, name: &str) -> Option<String>;
}

/// Errors returned by an injected capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityError {
    /// The capability failed without producing a sampler result.
    Failure(String),
    /// The capability is unavailable in the active profile.
    Unsupported(String),
    /// The capability observed a control signal.
    Control(ControlSignal),
    /// A capability-specific resource limit was reached.
    ResourceLimit(String),
}

impl CapabilityError {
    /// Creates a capability failure.
    #[must_use]
    pub fn failure(message: impl Into<String>) -> Self {
        Self::Failure(bounded_text(message, MAX_DIAGNOSTIC_BYTES))
    }

    /// Creates an unavailable-capability failure.
    #[must_use]
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::Unsupported(bounded_text(message, MAX_DIAGNOSTIC_BYTES))
    }

    /// Creates a bounded-resource failure.
    #[must_use]
    pub fn resource_limit(message: impl Into<String>) -> Self {
        Self::ResourceLimit(bounded_text(message, MAX_DIAGNOSTIC_BYTES))
    }

    /// Returns a stable machine-readable code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Failure(_) => "runtime.capability.failure",
            Self::Unsupported(_) => "runtime.capability.unsupported",
            Self::Control(_) => "runtime.capability.control",
            Self::ResourceLimit(_) => "runtime.capability.resource-limit",
        }
    }
}

impl fmt::Display for CapabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Failure(message) => write!(formatter, "{}: {message}", self.code()),
            Self::Unsupported(message) => write!(formatter, "{}: {message}", self.code()),
            Self::Control(signal) => write!(formatter, "{}: {signal:?}", self.code()),
            Self::ResourceLimit(message) => write!(formatter, "{}: {message}", self.code()),
        }
    }
}

impl std::error::Error for CapabilityError {}

/// Errors returned by a component before a sample result exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ComponentError {
    /// The component rejected its input or failed during evaluation.
    Failure(String),
    /// The component requires an unavailable capability.
    Unsupported(String),
    /// The component requested a control signal.
    Control(ControlSignal),
    /// The component exceeded a local resource bound.
    ResourceLimit(String),
    /// Multiple component diagnostics were raised at one boundary.
    Combined {
        /// First component diagnostic.
        primary: Box<Self>,
        /// Additional component diagnostic.
        secondary: Box<Self>,
    },
}

impl ComponentError {
    /// Creates a component failure.
    #[must_use]
    pub fn failure(message: impl Into<String>) -> Self {
        Self::Failure(bounded_text(message, MAX_DIAGNOSTIC_BYTES))
    }

    /// Creates an unsupported-component error.
    #[must_use]
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::Unsupported(bounded_text(message, MAX_DIAGNOSTIC_BYTES))
    }

    /// Creates a resource-limit error.
    #[must_use]
    pub fn resource_limit(message: impl Into<String>) -> Self {
        Self::ResourceLimit(bounded_text(message, MAX_DIAGNOSTIC_BYTES))
    }

    /// Returns a stable machine-readable code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Failure(_) => "runtime.component.failure",
            Self::Unsupported(_) => "runtime.component.unsupported",
            Self::Control(_) => "runtime.component.control",
            Self::ResourceLimit(_) => "runtime.component.resource-limit",
            Self::Combined { .. } => "runtime.component.combined",
        }
    }
}

impl fmt::Display for ComponentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Failure(message) => write!(formatter, "{}: {message}", self.code()),
            Self::Unsupported(message) => write!(formatter, "{}: {message}", self.code()),
            Self::Control(signal) => write!(formatter, "{}: {signal:?}", self.code()),
            Self::ResourceLimit(message) => write!(formatter, "{}: {message}", self.code()),
            Self::Combined { primary, secondary } => {
                write!(
                    formatter,
                    "{}: primary={primary}; secondary={secondary}",
                    self.code()
                )
            }
        }
    }
}

impl std::error::Error for ComponentError {}

impl From<CapabilityError> for ComponentError {
    fn from(error: CapabilityError) -> Self {
        match error {
            CapabilityError::Failure(message) => Self::failure(message),
            CapabilityError::Unsupported(message) => Self::unsupported(message),
            CapabilityError::Control(signal) => Self::Control(signal),
            CapabilityError::ResourceLimit(message) => Self::resource_limit(message),
        }
    }
}

impl From<FunctionError> for ComponentError {
    fn from(error: FunctionError) -> Self {
        match error {
            FunctionError::InvalidArguments(message) | FunctionError::Execution(message) => {
                Self::failure(message)
            }
            FunctionError::Unsupported(message) => Self::unsupported(message),
            FunctionError::StopThread(_) => Self::Control(ControlSignal::StopThread),
            FunctionError::ResourceLimit(message) => Self::resource_limit(message),
        }
    }
}

/// Default wall/monotonic clock for contexts that do not need timing.
#[derive(Clone, Copy, Debug, Default)]
pub struct EpochClock;

impl Clock for EpochClock {
    fn now(&self) -> ClockReading {
        ClockReading {
            wall: WallTimestamp::from_millis(0),
            monotonic: Duration::ZERO,
        }
    }
}

/// Immediate no-op sleeper used by the default capability set.
#[derive(Clone, Copy, Debug, Default)]
pub struct ImmediateSleeper;

impl Sleeper for ImmediateSleeper {
    fn sleep<'a>(&'a self, _duration: Duration) -> CapabilityFuture<'a, ()> {
        Box::pin(future::ready(Ok(())))
    }
}

/// Deterministic zero-valued random source used by the default capability set.
#[derive(Clone, Copy, Debug, Default)]
pub struct ZeroRandom;

impl RandomSource for ZeroRandom {
    fn next_u64(&self) -> Result<u64, CapabilityError> {
        Ok(0)
    }

    fn clone_for_user(&self) -> Arc<dyn RandomSource> {
        Arc::new(Self)
    }
}

/// Empty filesystem implementation used by the default capability set.
#[derive(Clone, Copy, Debug, Default)]
pub struct EmptyFileSystem;

impl FileSystem for EmptyFileSystem {
    fn read(&self, path: &str) -> Result<Vec<u8>, CapabilityError> {
        Err(CapabilityError::unsupported(format!(
            "filesystem path {path:?}"
        )))
    }
}

/// Empty environment implementation used by the default capability set.
#[derive(Clone, Copy, Debug, Default)]
pub struct EmptyEnvironment;

impl Environment for EmptyEnvironment {
    fn get(&self, _name: &str) -> Option<String> {
        None
    }
}

/// Lifecycle hook used to remove per-user expression state automatically when
/// a runtime lifecycle finishes.
pub trait ExpressionStateCleanup: Send + Sync {
    /// Clears state associated with one virtual-user lifecycle identity.
    ///
    /// A registry lock or bounded-state failure is returned to the lifecycle
    /// owner so teardown cannot silently claim that cleanup succeeded.
    fn clear_for_lifecycle(&self, lifecycle_id: u64) -> Result<(), ComponentError>;
}

impl ExpressionStateCleanup for jmeter_rs_expr::BuiltinFunctions {
    fn clear_for_lifecycle(&self, lifecycle_id: u64) -> Result<(), ComponentError> {
        self.clear_counters_for_lifecycle(lifecycle_id)
            .map_err(ComponentError::from)
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct NoopExpressionStateCleanup;

impl ExpressionStateCleanup for NoopExpressionStateCleanup {
    fn clear_for_lifecycle(&self, _lifecycle_id: u64) -> Result<(), ComponentError> {
        Ok(())
    }
}

/// Explicit capabilities supplied to one virtual-user context.
pub struct RuntimeCapabilities {
    clock: Arc<dyn Clock>,
    sleeper: Arc<dyn Sleeper>,
    random: Arc<dyn RandomSource>,
    filesystem: Arc<dyn FileSystem>,
    environment: Arc<dyn Environment>,
    scheduler: Arc<dyn Scheduler>,
    properties: Arc<RwLock<BTreeMap<String, String>>>,
    critical_sections: Arc<dyn CriticalSectionCoordinator>,
    expression_cleanup: Arc<dyn ExpressionStateCleanup>,
}

impl Clone for RuntimeCapabilities {
    fn clone(&self) -> Self {
        self.clone_for_user()
    }
}

impl fmt::Debug for RuntimeCapabilities {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeCapabilities")
            .finish_non_exhaustive()
    }
}

impl Default for RuntimeCapabilities {
    fn default() -> Self {
        Self {
            clock: Arc::new(EpochClock),
            sleeper: Arc::new(ImmediateSleeper),
            random: Arc::new(ZeroRandom),
            filesystem: Arc::new(EmptyFileSystem),
            environment: Arc::new(EmptyEnvironment),
            scheduler: Arc::new(crate::scheduler::ImmediateScheduler),
            properties: Arc::new(RwLock::new(BTreeMap::new())),
            critical_sections: Arc::new(DeterministicCriticalSectionCoordinator::default()),
            expression_cleanup: Arc::new(NoopExpressionStateCleanup),
        }
    }
}

impl RuntimeCapabilities {
    /// Creates a fully explicit capability set.
    #[must_use]
    pub fn new(
        clock: Arc<dyn Clock>,
        sleeper: Arc<dyn Sleeper>,
        random: Arc<dyn RandomSource>,
        filesystem: Arc<dyn FileSystem>,
        environment: Arc<dyn Environment>,
    ) -> Self {
        Self {
            clock,
            sleeper,
            random,
            filesystem,
            environment,
            scheduler: Arc::new(crate::scheduler::ImmediateScheduler),
            properties: Arc::new(RwLock::new(BTreeMap::new())),
            critical_sections: Arc::new(DeterministicCriticalSectionCoordinator::default()),
            expression_cleanup: Arc::new(NoopExpressionStateCleanup),
        }
    }

    /// Replaces the clock while retaining the other capabilities.
    #[must_use]
    pub fn with_clock(mut self, value: Arc<dyn Clock>) -> Self {
        self.clock = value;
        self
    }

    /// Replaces the sleeper while retaining the other capabilities.
    #[must_use]
    pub fn with_sleeper(mut self, value: Arc<dyn Sleeper>) -> Self {
        self.sleeper = value;
        self
    }

    /// Replaces the random source while retaining the other capabilities.
    #[must_use]
    pub fn with_random(mut self, value: Arc<dyn RandomSource>) -> Self {
        self.random = value;
        self
    }

    /// Replaces the filesystem while retaining the other capabilities.
    #[must_use]
    pub fn with_filesystem(mut self, value: Arc<dyn FileSystem>) -> Self {
        self.filesystem = value;
        self
    }

    /// Replaces the environment while retaining the other capabilities.
    #[must_use]
    pub fn with_environment(mut self, value: Arc<dyn Environment>) -> Self {
        self.environment = value;
        self
    }

    /// Replaces the scheduler capability while retaining all other services.
    #[must_use]
    pub fn with_scheduler(mut self, value: Arc<dyn Scheduler>) -> Self {
        self.scheduler = value;
        self
    }

    /// Replaces the run-shared property map. All user contexts cloned from
    /// these capabilities observe the same map.
    #[must_use]
    pub fn with_properties(mut self, value: Arc<RwLock<BTreeMap<String, String>>>) -> Self {
        self.properties = value;
        self
    }

    /// Replaces the critical-section coordinator.
    #[must_use]
    pub fn with_critical_section_coordinator(
        mut self,
        value: Arc<dyn CriticalSectionCoordinator>,
    ) -> Self {
        self.critical_sections = value;
        self
    }

    /// Installs an expression-registry cleanup hook.
    #[must_use]
    pub fn with_expression_cleanup(mut self, value: Arc<dyn ExpressionStateCleanup>) -> Self {
        self.expression_cleanup = value;
        self
    }

    /// Returns the injected clock.
    #[must_use]
    pub fn clock(&self) -> &dyn Clock {
        self.clock.as_ref()
    }

    /// Returns the injected sleeper.
    #[must_use]
    pub fn sleeper(&self) -> &dyn Sleeper {
        self.sleeper.as_ref()
    }

    /// Returns the injected random source.
    #[must_use]
    pub fn random(&self) -> &dyn RandomSource {
        self.random.as_ref()
    }

    /// Returns the injected filesystem.
    #[must_use]
    pub fn filesystem(&self) -> &dyn FileSystem {
        self.filesystem.as_ref()
    }

    /// Returns the injected environment.
    #[must_use]
    pub fn environment(&self) -> &dyn Environment {
        self.environment.as_ref()
    }

    /// Returns the explicit scheduler capability.
    #[must_use]
    pub fn scheduler(&self) -> &dyn Scheduler {
        self.scheduler.as_ref()
    }

    /// Returns the run-shared property map.
    #[must_use]
    pub(crate) fn properties(&self) -> Arc<RwLock<BTreeMap<String, String>>> {
        Arc::clone(&self.properties)
    }

    /// Returns the explicit critical-section coordinator.
    #[must_use]
    pub fn critical_sections(&self) -> &dyn CriticalSectionCoordinator {
        self.critical_sections.as_ref()
    }

    /// Returns an owned coordinator handle for guards that must release locks
    /// if an executor drops an in-flight component future.
    #[must_use]
    pub(crate) fn critical_sections_arc(&self) -> Arc<dyn CriticalSectionCoordinator> {
        Arc::clone(&self.critical_sections)
    }

    /// Returns the engine-owned expression cleanup hook.
    #[must_use]
    pub(crate) fn expression_cleanup(&self) -> Arc<dyn ExpressionStateCleanup> {
        Arc::clone(&self.expression_cleanup)
    }

    /// Creates capabilities for an independent virtual-user context.
    ///
    /// Clock, sleeper, filesystem, and environment providers are capability
    /// services and remain shared. Random state is explicitly forked so a
    /// mutable random cursor cannot leak between users.
    #[must_use]
    pub fn clone_for_user(&self) -> Self {
        Self {
            clock: Arc::clone(&self.clock),
            sleeper: Arc::clone(&self.sleeper),
            random: self.random.clone_for_user(),
            filesystem: Arc::clone(&self.filesystem),
            environment: Arc::clone(&self.environment),
            scheduler: Arc::clone(&self.scheduler),
            properties: Arc::clone(&self.properties),
            critical_sections: Arc::clone(&self.critical_sections),
            expression_cleanup: Arc::clone(&self.expression_cleanup),
        }
    }
}

/// Mutable state shared by all phases of one sampler invocation.
pub struct ExecutionContext {
    capabilities: RuntimeCapabilities,
    variables: Arc<RwLock<BTreeMap<String, String>>>,
    properties: Arc<RwLock<BTreeMap<String, String>>>,
    run: jmeter_rs_results::RunIdentity,
    thread: ThreadIdentity,
    host: HostIdentity,
    sample_variables: Vec<String>,
    cancellation: Cancellation,
    cancellation_token: CancellationToken,
    trace: PhaseTrace,
    group_threads: Option<ThreadCount>,
    all_threads: Option<ThreadCount>,
    timer_factor: f64,
    deadline: Option<Duration>,
    lifecycle_id: Option<u64>,
    iteration_id: Option<u64>,
    expression_namespace: Option<u64>,
    expression_file_cursors: Arc<Mutex<BTreeMap<(String, FunctionOccurrence), usize>>>,
    sampler_name: Option<String>,
    cancellation_error: Arc<Mutex<Option<ComponentError>>>,
}

impl fmt::Debug for ExecutionContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionContext")
            .field("variables", &read_lock(&self.variables))
            .field("properties", &read_lock(&self.properties))
            .field("run", &self.run)
            .field("thread", &self.thread)
            .field("host", &self.host)
            .field("sample_variables", &self.sample_variables)
            .field("cancellation", &self.cancellation)
            .field("trace", &self.trace)
            .field("timer_factor", &self.timer_factor)
            .field("deadline", &self.deadline)
            .field("iteration_id", &self.iteration_id)
            .field("expression_namespace", &self.expression_namespace)
            .finish_non_exhaustive()
    }
}

impl ExecutionContext {
    /// Creates a context with default capabilities and empty identities.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capabilities(RuntimeCapabilities::default())
    }

    /// Creates a context with explicit runtime capabilities.
    #[must_use]
    pub fn with_capabilities(capabilities: RuntimeCapabilities) -> Self {
        let properties = capabilities.properties();
        Self {
            capabilities,
            variables: Arc::new(RwLock::new(BTreeMap::new())),
            properties,
            run: jmeter_rs_results::RunIdentity::new(""),
            thread: ThreadIdentity::new(""),
            host: HostIdentity::new(""),
            sample_variables: Vec::new(),
            cancellation: Cancellation::new(),
            cancellation_token: CancellationToken::new(),
            trace: PhaseTrace::default(),
            group_threads: None,
            all_threads: None,
            timer_factor: 1.0,
            deadline: None,
            lifecycle_id: None,
            iteration_id: None,
            expression_namespace: None,
            expression_file_cursors: Arc::new(Mutex::new(BTreeMap::new())),
            sampler_name: None,
            cancellation_error: Arc::new(Mutex::new(None)),
        }
    }

    /// Creates an independent per-user clone of this context.
    #[must_use]
    pub fn clone_for_user(&self) -> Self {
        Self {
            capabilities: self.capabilities.clone_for_user(),
            variables: Arc::new(RwLock::new(read_lock(&self.variables).clone())),
            properties: Arc::clone(&self.properties),
            run: self.run.clone(),
            thread: self.thread.clone(),
            host: self.host.clone(),
            sample_variables: self.sample_variables.clone(),
            cancellation: self.cancellation.clone_for_user(),
            cancellation_token: self.cancellation_token.clone_for_user(),
            trace: PhaseTrace::new_with_limits(
                self.trace.max_events(),
                self.trace.max_detail_bytes(),
            ),
            group_threads: self.group_threads,
            all_threads: self.all_threads,
            timer_factor: self.timer_factor,
            deadline: self.deadline,
            lifecycle_id: self.lifecycle_id,
            iteration_id: self.iteration_id,
            expression_namespace: self.expression_namespace,
            expression_file_cursors: Arc::clone(&self.expression_file_cursors),
            sampler_name: self.sampler_name.clone(),
            cancellation_error: Arc::new(Mutex::new(None)),
        }
    }

    /// Returns the context's explicit capabilities.
    #[must_use]
    pub fn capabilities(&self) -> &RuntimeCapabilities {
        &self.capabilities
    }

    /// Returns thread-local variables.
    pub fn variables(&self) -> RwLockReadGuard<'_, BTreeMap<String, String>> {
        read_lock(&self.variables)
    }

    /// Returns mutable thread-local variables.
    pub fn variables_mut(&mut self) -> RwLockWriteGuard<'_, BTreeMap<String, String>> {
        write_lock(&self.variables)
    }

    /// Sets a thread-local variable.
    pub fn set_variable(&mut self, name: impl Into<String>, value: impl Into<String>) {
        write_lock(&self.variables).insert(name.into(), value.into());
    }

    /// Returns a thread-local variable.
    #[must_use]
    pub fn variable(&self, name: &str) -> Option<String> {
        read_lock(&self.variables).get(name).cloned()
    }

    /// Returns run-scoped properties.
    pub fn properties(&self) -> RwLockReadGuard<'_, BTreeMap<String, String>> {
        read_lock(&self.properties)
    }

    /// Returns mutable run-scoped properties.
    pub fn properties_mut(&self) -> RwLockWriteGuard<'_, BTreeMap<String, String>> {
        write_lock(&self.properties)
    }

    /// Sets a run-scoped property in this context's explicit view.
    pub fn set_property(&self, name: impl Into<String>, value: impl Into<String>) {
        write_lock(&self.properties).insert(name.into(), value.into());
    }

    /// Returns a property from this context's explicit view.
    #[must_use]
    pub fn property(&self, name: &str) -> Option<String> {
        read_lock(&self.properties).get(name).cloned()
    }

    /// Expands one expression against the current variable/property view.
    pub fn evaluate(
        &self,
        input: &str,
        functions: &dyn FunctionResolver,
    ) -> Result<String, EvaluationError> {
        self.evaluate_expression(input, functions)
    }

    /// Expands an expression with the runtime's explicit capability set.
    ///
    /// In addition to variables and run-scoped properties, the evaluator sees
    /// this context's per-user random stream, injected clock, allowlisted
    /// filesystem, environment-backed host identity, and thread identity.
    /// Capability failures remain typed expression errors; no ambient process
    /// state or empty capability fallback is consulted.
    ///
    /// A package phase installs a domain-qualified field namespace before
    /// calling this method.  Standalone callers have no plan/field identity;
    /// this method deliberately leaves the expression evaluator's source-local
    /// compatibility namespace untouched rather than fabricating a numeric
    /// plan identity.  Call [`Self::set_expression_field_namespace`] when the
    /// owning field is known.
    pub fn evaluate_expression(
        &self,
        input: &str,
        functions: &dyn FunctionResolver,
    ) -> Result<String, EvaluationError> {
        let random_error = Arc::new(Mutex::new(None));
        let random = RuntimeExprRandom {
            source: self.capabilities.random(),
            error: Arc::clone(&random_error),
        };
        let clock = RuntimeExprClock {
            source: self.capabilities.clock(),
        };
        let execution = RuntimeExprExecution { context: self };
        let host = RuntimeExprHost {
            environment: self.capabilities.environment(),
        };
        let files = RuntimeExprFiles {
            filesystem: self.capabilities.filesystem(),
            cursors: Arc::clone(&self.expression_file_cursors),
        };
        let properties = RuntimeExprProperties { context: self };
        let properties_snapshot = read_lock(&self.properties).clone();
        let variables_snapshot = read_lock(&self.variables).clone();
        let variable_setter = RuntimeExprVariables {
            values: Arc::clone(&self.variables),
        };
        let capabilities = EvaluationCapabilities::new()
            .with_variable_setter(&variable_setter)
            .with_property_setter(&properties)
            .with_random_source(&random)
            .with_clock(&clock)
            .with_execution_context(&execution)
            .with_host_resolver(&host)
            .with_file_capability(&files);
        let evaluator = Evaluator::with_capabilities(
            &variables_snapshot,
            &properties_snapshot,
            functions,
            capabilities,
        );
        let evaluator = match self.expression_namespace {
            Some(namespace) => evaluator.with_function_instance_namespace(namespace),
            None => evaluator,
        };
        let result = evaluator.evaluate(input);
        if let Some(error) = mutex_lock(&random_error).take() {
            return Err(EvaluationError::Function {
                name: "runtime.random".to_owned(),
                source: capability_to_function_error(error),
            });
        }
        result
    }

    /// Sets the run identity copied into result events.
    pub fn set_run(&mut self, run: impl Into<jmeter_rs_results::RunIdentity>) {
        self.run = run.into();
    }

    /// Returns the run identity.
    #[must_use]
    pub fn run(&self) -> &jmeter_rs_results::RunIdentity {
        &self.run
    }

    /// Sets the thread identity copied into result events.
    pub fn set_thread(&mut self, thread: impl Into<ThreadIdentity>) {
        self.thread = thread.into();
    }

    /// Returns the thread identity.
    #[must_use]
    pub fn thread(&self) -> &ThreadIdentity {
        &self.thread
    }

    /// Sets the host identity copied into result events.
    pub fn set_host(&mut self, host: impl Into<HostIdentity>) {
        self.host = host.into();
    }

    /// Returns the host identity.
    #[must_use]
    pub fn host(&self) -> &HostIdentity {
        &self.host
    }

    /// Sets the variable names captured into listener events.
    pub fn set_sample_variables<I, S>(&mut self, names: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.sample_variables = names.into_iter().map(Into::into).collect();
    }

    /// Returns configured listener snapshot variable names.
    #[must_use]
    pub fn sample_variables(&self) -> &[String] {
        &self.sample_variables
    }

    /// Requests a monotonic control signal.
    pub fn request_control(&mut self, signal: ControlSignal) {
        self.cancellation.request(signal);
        self.cancellation_token.request(signal);
    }

    /// Returns the current monotonic control signal.
    #[must_use]
    pub fn control_signal(&self) -> ControlSignal {
        self.cancellation
            .signal()
            .combine(self.cancellation_token.signal())
    }

    /// Takes one pending controller signal at the controller boundary.
    #[must_use]
    pub fn take_control_signal(&self) -> ControlSignal {
        self.cancellation
            .take_signal()
            .combine(self.cancellation_token.take_signal())
    }

    /// Sets the factor applied to modifiable timers. Values must be finite
    /// and non-negative; zero is a valid way to disable timer delay.
    pub fn set_timer_factor(&mut self, factor: f64) -> Result<(), ComponentError> {
        if !factor.is_finite() || factor < 0.0 {
            return Err(ComponentError::failure("invalid timer factor"));
        }
        self.timer_factor = factor;
        Ok(())
    }

    /// Returns the active modifiable-timer factor.
    #[must_use]
    pub const fn timer_factor(&self) -> f64 {
        self.timer_factor
    }

    /// Sets an absolute monotonic deadline for the current package invocation.
    /// The deadline is checked when the executor polls the returned pipeline
    /// future; injected clocks keep this deterministic without wall sleeps.
    pub fn set_deadline(&mut self, deadline: Option<Duration>) {
        self.deadline = deadline;
    }

    /// Returns the configured absolute monotonic deadline, if any.
    #[must_use]
    pub const fn deadline(&self) -> Option<Duration> {
        self.deadline
    }

    /// Returns the cancellation token supplied to component futures.
    #[must_use]
    pub fn cancellation_token(&self) -> &CancellationToken {
        &self.cancellation_token
    }

    /// Attaches a run-wide cancellation parent while retaining a user-local
    /// `NextLoop` slot. Stop severity raised by the parent is therefore
    /// visible to every component future owned by this context.
    pub fn attach_cancellation(&mut self, parent: &CancellationToken) {
        self.cancellation_token = parent.child();
    }

    /// Returns the explicit scheduler supplied to component futures.
    #[must_use]
    pub fn scheduler(&self) -> &dyn Scheduler {
        self.capabilities.scheduler()
    }

    /// Creates a future that wakes at this invocation's deadline or when its
    /// cancellation token is signalled.  The future is executor-neutral and
    /// must be polled by the component that owns the operation.
    pub fn deadline_future(&self) -> Option<DeadlineFuture<'_>> {
        self.deadline.map(|deadline| {
            DeadlineFuture::new(
                self.scheduler(),
                Deadline::at(MonotonicInstant::from_duration(deadline)),
                self.cancellation_token.clone(),
            )
        })
    }

    /// Registers a scheduler wake owned by this invocation.
    pub fn register_wake_after(
        &self,
        delay: Duration,
        key: u64,
    ) -> Result<WakeRegistration, SchedulerError> {
        self.scheduler()
            .register_after(delay, key, &self.cancellation_token)
    }

    /// Sets the owning virtual-user lifecycle identity used by stateful
    /// expression functions.
    pub fn set_lifecycle_id(&mut self, lifecycle_id: Option<u64>) {
        self.lifecycle_id = lifecycle_id;
    }

    /// Returns the owning virtual-user lifecycle identity.
    #[must_use]
    pub const fn lifecycle_id(&self) -> Option<u64> {
        self.lifecycle_id
    }

    /// Sets the explicit root-iteration identity used by stateful expression
    /// functions. Runtime lifecycle code sets this to zero when a virtual
    /// user starts and advances it only after the completed iteration event
    /// has been emitted. A context created outside a virtual user leaves it
    /// absent so iteration-sensitive functions fail closed.
    pub fn set_iteration_id(&mut self, iteration_id: Option<u64>) {
        self.iteration_id = iteration_id;
    }

    /// Returns the explicit root-iteration identity, when this context is
    /// owned by a running virtual user.
    #[must_use]
    pub const fn iteration_id(&self) -> Option<u64> {
        self.iteration_id
    }

    /// Sets the domain-qualified plan/field identity used by stateful
    /// expression occurrences in the next phase.
    ///
    /// A package executor should call this immediately before invoking each
    /// configuration, preprocessor, timer, sampler, postprocessor, assertion,
    /// listener, or lifecycle hook.  Standalone callers that do not have a
    /// plan field should leave the namespace unset; they must not invent a
    /// numeric identity to stand in for one.
    pub fn set_expression_field_namespace(&mut self, domain: &str, plan_node: NodeId, field: &str) {
        self.expression_namespace = Some(expression_field_namespace(domain, plan_node, field));
    }

    /// Clears the package field identity after a phase-owned expression
    /// operation has completed.
    pub fn clear_expression_field_namespace(&mut self) {
        self.expression_namespace = None;
    }

    /// Clears stateful built-in expression counters for this completed
    /// virtual-user lifecycle. The caller owns the function registry, so the
    /// runtime does not create or globally retain expression state.
    pub fn clear_expression_state(
        &self,
        functions: &jmeter_rs_expr::BuiltinFunctions,
    ) -> Result<(), ComponentError> {
        if let Some(lifecycle_id) = self.lifecycle_id {
            functions
                .clear_counters_for_lifecycle(lifecycle_id)
                .map_err(ComponentError::from)?;
        }
        Ok(())
    }

    /// Automatically clears expression state through the engine-owned
    /// lifecycle hook. The default hook is intentionally a typed no-op, while
    /// expression registries such as [`jmeter_rs_expr::BuiltinFunctions`] can
    /// be installed with [`RuntimeCapabilities::with_expression_cleanup`].
    pub fn cleanup_expression_state(&self) -> Result<(), ComponentError> {
        if let Some(lifecycle_id) = self.lifecycle_id {
            let cleanup = self.capabilities.expression_cleanup();
            cleanup.clear_for_lifecycle(lifecycle_id)?;
        }
        Ok(())
    }

    /// Sets the current sampler name used by expression information helpers.
    pub fn set_sampler_name(&mut self, sampler_name: Option<String>) {
        self.sampler_name = sampler_name;
    }

    /// Returns the current sampler name.
    #[must_use]
    pub fn sampler_name(&self) -> Option<&str> {
        self.sampler_name.as_deref()
    }

    /// Returns whether the configured deadline has elapsed on the injected
    /// monotonic clock.
    #[must_use]
    pub fn deadline_expired(&self) -> bool {
        self.deadline
            .is_some_and(|deadline| self.capabilities.clock().now().monotonic >= deadline)
    }

    /// Returns a cancellation-cleanup error recorded while a pending future
    /// was dropped, if one was reported by the lifecycle hook.
    #[must_use]
    pub fn cancellation_error(&self) -> Option<ComponentError> {
        mutex_lock(&self.cancellation_error).clone()
    }

    /// Replaces the trace capacity with a fresh empty trace.
    pub fn set_trace_capacity(&mut self, max_events: usize) {
        self.trace = PhaseTrace::new_with_limits(max_events, self.trace.max_detail_bytes());
    }

    /// Replaces event and detail capacities with a fresh empty trace.
    pub fn set_trace_limits(&mut self, max_events: usize, max_detail_bytes: usize) {
        self.trace = PhaseTrace::new_with_limits(max_events, max_detail_bytes);
    }

    /// Returns the recorded phase trace.
    #[must_use]
    pub fn trace(&self) -> &PhaseTrace {
        &self.trace
    }

    /// Returns mutable access to the recorded phase trace.
    pub fn trace_mut(&mut self) -> &mut PhaseTrace {
        &mut self.trace
    }

    /// Sets active thread counts used for non-null result updates.
    pub fn set_thread_counts(&mut self, group: Option<ThreadCount>, all: Option<ThreadCount>) {
        self.group_threads = group;
        self.all_threads = all;
    }

    fn snapshot_variables(&self) -> VariableSnapshot {
        self.sample_variables
            .iter()
            .map(|name| (name.clone(), read_lock(&self.variables).get(name).cloned()))
            .collect()
    }

    /// Creates the immutable event snapshot used by a run-level result
    /// router.  The snapshot is taken from this context's exact run, thread,
    /// host, and selected-variable state; callers must pass the original
    /// result produced by the current phase and must not rebuild it from
    /// labels or serialized fields.
    pub fn sample_event(&self, result: &SampleResult) -> Result<SampleEvent, ResultError> {
        SampleEvent::snapshot(
            result,
            self.run.clone(),
            self.thread.clone(),
            self.host.clone(),
            self.snapshot_variables(),
        )
    }
}

impl Default for ExecutionContext {
    fn default() -> Self {
        Self::new()
    }
}

fn capability_to_function_error(error: CapabilityError) -> FunctionError {
    match error {
        CapabilityError::Unsupported(message) => FunctionError::unsupported(message),
        CapabilityError::Failure(message) | CapabilityError::ResourceLimit(message) => {
            FunctionError::execution(message)
        }
        CapabilityError::Control(signal) => {
            FunctionError::execution(format!("control signal {signal:?}"))
        }
    }
}

fn combine_component_errors(primary: ComponentError, secondary: ComponentError) -> ComponentError {
    ComponentError::Combined {
        primary: Box::new(primary),
        secondary: Box::new(secondary),
    }
}

struct RuntimeExprVariables {
    values: Arc<RwLock<BTreeMap<String, String>>>,
}

impl ExprVariableSetter for RuntimeExprVariables {
    fn set_variable(&self, name: &str, value: &str) -> Result<(), FunctionError> {
        write_lock(&self.values).insert(name.to_owned(), value.to_owned());
        Ok(())
    }

    fn get_variable(&self, name: &str) -> Option<String> {
        read_lock(&self.values).get(name).cloned()
    }

    fn remove_variable(&self, name: &str) -> Result<(), FunctionError> {
        write_lock(&self.values).remove(name);
        Ok(())
    }
}

struct RuntimeExprRandom<'a> {
    source: &'a dyn RandomSource,
    error: Arc<Mutex<Option<CapabilityError>>>,
}

impl jmeter_rs_expr::RandomSource for RuntimeExprRandom<'_> {
    fn next_u64(&self) -> u64 {
        match self.source.next_u64() {
            Ok(value) => value,
            Err(error) => {
                let mut slot = mutex_lock(&self.error);
                if slot.is_none() {
                    *slot = Some(error);
                }
                0
            }
        }
    }
}

struct RuntimeExprClock<'a> {
    source: &'a dyn Clock,
}

impl jmeter_rs_expr::ClockSource for RuntimeExprClock<'_> {
    fn now_millis(&self) -> Result<i64, FunctionError> {
        Ok(self.source.now().wall.as_millis())
    }
}

struct RuntimeExprExecution<'a> {
    context: &'a ExecutionContext,
}

impl jmeter_rs_expr::ExecutionContext for RuntimeExprExecution<'_> {
    fn thread_num(&self) -> Option<u32> {
        self.context
            .thread
            .number()
            .and_then(|number| u32::try_from(number).ok())
    }

    fn thread_group_name(&self) -> Option<String> {
        self.context.thread.group().map(str::to_owned)
    }

    fn lifecycle_id(&self) -> Option<u64> {
        self.context.lifecycle_id
    }

    fn iteration_id(&self) -> Option<u64> {
        self.context.iteration_id
    }

    fn sampler_name(&self) -> Option<String> {
        self.context.sampler_name.clone()
    }
}

struct RuntimeExprHost<'a> {
    environment: &'a dyn Environment,
}

impl jmeter_rs_expr::HostResolver for RuntimeExprHost<'_> {
    fn machine_name(&self) -> Result<String, FunctionError> {
        bounded_environment_value(self.environment, "HOSTNAME")
    }

    fn machine_ip(&self) -> Result<String, FunctionError> {
        bounded_environment_value(self.environment, "HOST_IP")
    }
}

fn bounded_environment_value(
    environment: &dyn Environment,
    name: &str,
) -> Result<String, FunctionError> {
    let value = environment.get(name).ok_or_else(|| {
        FunctionError::unsupported(format!("environment value {name} is unavailable"))
    })?;
    if value.len() > MAX_DIAGNOSTIC_BYTES {
        return Err(FunctionError::execution(
            "environment value exceeds runtime bound",
        ));
    }
    Ok(value)
}

struct RuntimeExprFiles<'a> {
    filesystem: &'a dyn FileSystem,
    cursors: Arc<Mutex<BTreeMap<(String, FunctionOccurrence), usize>>>,
}

impl RuntimeExprFiles<'_> {
    fn read_bytes(&self, path: &str) -> Result<Vec<u8>, FunctionError> {
        if path.len() > MAX_DIAGNOSTIC_BYTES {
            return Err(FunctionError::invalid_arguments(
                "filesystem path exceeds runtime bound",
            ));
        }
        let bytes = self
            .filesystem
            .read(path)
            .map_err(capability_to_function_error)?;
        if bytes.len() > MAX_EXPRESSION_FILE_BYTES {
            return Err(FunctionError::execution(
                "filesystem result exceeds runtime bound",
            ));
        }
        Ok(bytes)
    }
}

impl ExprFileCapability for RuntimeExprFiles<'_> {
    fn read_to_string(&self, path: &str, encoding: Option<&str>) -> Result<String, FunctionError> {
        if encoding.is_some_and(|encoding| !encoding.eq_ignore_ascii_case("UTF-8")) {
            return Err(FunctionError::unsupported(
                "runtime filesystem adapter supports UTF-8 only",
            ));
        }
        String::from_utf8(self.read_bytes(path)?)
            .map_err(|_| FunctionError::execution("filesystem result is not valid UTF-8"))
    }

    fn read_line(
        &self,
        _path: &str,
        _key: &str,
        _start_sequence: Option<i64>,
        _end_sequence: Option<i64>,
    ) -> Result<String, FunctionError> {
        Err(FunctionError::unsupported(
            "line-oriented expression file capability requires a function occurrence",
        ))
    }

    fn read_line_for_occurrence(
        &self,
        _path: &str,
        _key: &str,
        _occurrence: u64,
        _start_sequence: Option<i64>,
        _end_sequence: Option<i64>,
    ) -> Result<String, FunctionError> {
        Err(FunctionError::unsupported(
            "line-oriented expression file capability requires a structural function occurrence",
        ))
    }

    fn read_line_for_function_occurrence(
        &self,
        path: &str,
        key: &str,
        occurrence: &FunctionOccurrence,
        start_sequence: Option<i64>,
        end_sequence: Option<i64>,
    ) -> Result<String, FunctionError> {
        if key.len() > MAX_DIAGNOSTIC_BYTES {
            return Err(FunctionError::invalid_arguments(
                "StringFromFile key exceeds runtime bound",
            ));
        }
        let contents = String::from_utf8(self.read_bytes(path)?)
            .map_err(|_| FunctionError::execution("StringFromFile source is not valid UTF-8"))?;
        let lines = contents.lines().collect::<Vec<_>>();
        let mut cursors = self
            .cursors
            .lock()
            .map_err(|_| FunctionError::execution("expression file cursor lock is poisoned"))?;
        let cursor = if let Some(cursor) = cursors.get_mut(&(path.to_owned(), occurrence.clone())) {
            cursor
        } else {
            if cursors.len() >= MAX_EXPRESSION_FILE_CURSORS {
                return Err(FunctionError::resource_limit(
                    "expression file cursor capacity",
                ));
            }
            cursors.insert((path.to_owned(), occurrence.clone()), 0);
            cursors
                .get_mut(&(path.to_owned(), occurrence.clone()))
                .ok_or_else(|| {
                    FunctionError::execution("expression file cursor insertion failed")
                })?
        };
        if let Some(start) = start_sequence {
            if start < 0 {
                return Err(FunctionError::invalid_arguments(
                    "StringFromFile start sequence must be non-negative",
                ));
            }
            let start = usize::try_from(start).map_err(|_| {
                FunctionError::invalid_arguments("StringFromFile start sequence overflow")
            })?;
            *cursor = (*cursor).max(start);
        }
        if let Some(end) = end_sequence {
            if end < 0 {
                return Err(FunctionError::invalid_arguments(
                    "StringFromFile end sequence must be non-negative",
                ));
            }
            let end = usize::try_from(end).map_err(|_| {
                FunctionError::invalid_arguments("StringFromFile end sequence overflow")
            })?;
            if *cursor > end {
                return Err(FunctionError::stop_thread("end of StringFromFile sequence"));
            }
        }
        let Some(value) = lines.get(*cursor) else {
            return Err(FunctionError::stop_thread("end of StringFromFile sequence"));
        };
        *cursor = cursor.saturating_add(1);
        Ok((*value).to_owned())
    }

    fn read_csv_field(
        &self,
        _path: &str,
        _selector: &str,
        _delimiter: char,
    ) -> Result<String, FunctionError> {
        Err(FunctionError::unsupported(
            "CSV expression file capability is unavailable",
        ))
    }

    fn write_string(
        &self,
        _path: &str,
        _value: &str,
        _append: bool,
        _encoding: Option<&str>,
    ) -> Result<(), FunctionError> {
        Err(FunctionError::unsupported(
            "filesystem writes are unavailable in the runtime expression adapter",
        ))
    }
}

struct RuntimeExprProperties<'a> {
    context: &'a ExecutionContext,
}

impl ExprPropertySetter for RuntimeExprProperties<'_> {
    fn set_property(&self, name: &str, value: &str) -> Result<Option<String>, FunctionError> {
        let mut properties = write_lock(&self.context.properties);
        let previous = properties.insert(name.to_owned(), value.to_owned());
        Ok(previous)
    }

    fn get_property(&self, name: &str) -> Option<String> {
        self.context.property(name)
    }
}

/// Mutable state scoped to one sampler package invocation.
pub struct SampleContext<'a> {
    execution: ExecutionSlot<'a>,
    sampler_id: NodeId,
    request: BTreeMap<String, String>,
    result: Option<SampleResult>,
}

/// The execution state held by a sampler invocation.
///
/// Normal pipeline execution borrows the caller's context so that all phase
/// mutations are visible to the virtual-user owner.  [`SampleContext::clone_for_user`]
/// needs an independent state, however, and therefore stores a value-owned
/// clone in the returned context.  Keeping the two cases in one private enum
/// avoids aliasing a mutable reference while preserving the executor-neutral
/// component API.
enum ExecutionSlot<'a> {
    Borrowed(&'a mut ExecutionContext),
    Owned(Box<ExecutionContext>),
}

impl<'a> SampleContext<'a> {
    fn new(execution: &'a mut ExecutionContext, sampler_id: NodeId) -> Self {
        Self {
            execution: ExecutionSlot::Borrowed(execution),
            sampler_id,
            request: BTreeMap::new(),
            result: None,
        }
    }

    /// Returns the sampler identity.
    #[must_use]
    pub const fn sampler_id(&self) -> NodeId {
        self.sampler_id
    }

    /// Clones this invocation into an independent virtual-user state.
    ///
    /// The returned context owns a clone of the execution state and of the
    /// request/result values accumulated so far.  Mutating it cannot affect
    /// the borrowed context used by the original invocation.
    #[must_use]
    pub fn clone_for_user(&self) -> Self {
        Self {
            execution: ExecutionSlot::Owned(Box::new(self.execution().clone_for_user())),
            sampler_id: self.sampler_id,
            request: self.request.clone(),
            result: self.result.clone(),
        }
    }

    /// Returns the execution context.
    #[must_use]
    pub fn execution(&self) -> &ExecutionContext {
        match &self.execution {
            ExecutionSlot::Borrowed(execution) => execution,
            ExecutionSlot::Owned(execution) => execution,
        }
    }

    /// Returns mutable access to the execution context.
    pub fn execution_mut(&mut self) -> &mut ExecutionContext {
        match &mut self.execution {
            ExecutionSlot::Borrowed(execution) => execution,
            ExecutionSlot::Owned(execution) => execution,
        }
    }

    /// Returns the current merged request/configuration values.
    #[must_use]
    pub fn request(&self) -> &BTreeMap<String, String> {
        &self.request
    }

    /// Sets one merged request/configuration value.
    pub fn set_request_value(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.request.insert(name.into(), value.into());
    }

    /// Returns one merged request/configuration value.
    #[must_use]
    pub fn request_value(&self, name: &str) -> Option<&str> {
        self.request.get(name).map(String::as_str)
    }

    /// Returns the result currently produced by the sampler.
    #[must_use]
    pub fn result(&self) -> Option<&SampleResult> {
        self.result.as_ref()
    }

    /// Returns mutable access to the current result.
    pub fn result_mut(&mut self) -> Option<&mut SampleResult> {
        self.result.as_mut()
    }

    /// Replaces the result held by this invocation.
    pub fn set_result(&mut self, result: Option<SampleResult>) {
        self.result = result;
    }

    /// Records one trace entry, returning a bounded failure if full.
    pub fn record(
        &mut self,
        phase: Phase,
        detail: impl Into<String>,
    ) -> Result<(), ComponentError> {
        let sampler_id = self.sampler_id;
        self.execution_mut()
            .trace
            .push(phase, Some(sampler_id), detail)
    }
}

impl Clone for SampleContext<'_> {
    fn clone(&self) -> Self {
        self.clone_for_user()
    }
}

/// Applies an already-resolved configuration element to the sample context.
pub trait Configuration: Send + Sync {
    /// Merges this configuration into the invocation context.
    fn apply<'a>(&'a self, context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, ()>;
}

/// Runs before timers and the sampler.
pub trait Preprocessor: Send + Sync {
    /// Processes mutable invocation state.
    fn process<'a>(&'a self, context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, ()>;
}

/// Supplies one additive sampler delay.
pub trait Timer: Send + Sync {
    /// Evaluates the delay for this invocation.
    fn delay<'a>(&'a self, context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, Duration>;

    /// Indicates whether the timer participates in a caller-provided timer
    /// factor.  The first runtime phase only sums the returned duration; the
    /// flag is retained for future profile-specific factors.
    fn is_modifiable(&self) -> bool {
        true
    }
}

/// Runs one sampler operation.
pub trait Sampler: Send + Sync {
    /// Produces a result, no result, or a typed sample failure.
    fn sample<'a>(
        &'a self,
        context: &'a mut SampleContext<'_>,
    ) -> ComponentFuture<'a, SamplerOutput>;
}

/// Runs after a non-null sampler result.
pub trait Postprocessor: Send + Sync {
    /// Processes mutable result/request/variable state.
    fn process<'a>(&'a self, context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, ()>;
}

/// Evaluates one assertion against a non-null result.
pub trait Assertion: Send + Sync {
    /// Returns an assertion result; a failed assertion is data, not an engine
    /// error.
    fn evaluate<'a>(
        &'a self,
        context: &'a mut SampleContext<'_>,
    ) -> ComponentFuture<'a, AssertionResult>;
}

/// Observes an immutable listener event snapshot.
pub trait Listener: Send + Sync {
    /// Consumes a read-only event and cannot mutate the stored snapshot.
    fn on_event<'a>(&'a self, event: &'a SampleEvent) -> ComponentFuture<'a, ()>;
}

/// Constructs a fresh configuration component for one virtual user.
pub trait ConfigurationFactory: Send + Sync {
    /// Builds an isolated component instance.
    fn create(&self) -> Arc<dyn Configuration>;
}

/// Constructs a fresh preprocessor component for one virtual user.
pub trait PreprocessorFactory: Send + Sync {
    /// Builds an isolated component instance.
    fn create(&self) -> Arc<dyn Preprocessor>;
}

/// Constructs a fresh timer component for one virtual user.
pub trait TimerFactory: Send + Sync {
    /// Builds an isolated component instance.
    fn create(&self) -> Arc<dyn Timer>;
}

/// Constructs a fresh sampler component for one virtual user.
pub trait SamplerFactory: Send + Sync {
    /// Builds an isolated component instance.
    fn create(&self) -> Arc<dyn Sampler>;
}

/// Constructs a fresh postprocessor component for one virtual user.
pub trait PostprocessorFactory: Send + Sync {
    /// Builds an isolated component instance.
    fn create(&self) -> Arc<dyn Postprocessor>;
}

/// Constructs a fresh assertion component for one virtual user.
pub trait AssertionFactory: Send + Sync {
    /// Builds an isolated component instance.
    fn create(&self) -> Arc<dyn Assertion>;
}

/// Constructs a fresh listener component for one virtual user.
pub trait ListenerFactory: Send + Sync {
    /// Builds an isolated component instance.
    fn create(&self) -> Arc<dyn Listener>;
}

/// Constructs fresh package lifecycle hooks for one virtual user.
pub trait PackageLifecycleFactory: Send + Sync {
    /// Builds isolated lifecycle hooks.
    fn create(&self) -> Arc<dyn PackageLifecycle>;
}

/// Owns package-level finish and cleanup hooks.
pub trait PackageLifecycle: Send + Sync {
    /// Finishes a package after its normal result phases.
    fn finish<'a>(&'a self, context: &'a mut ExecutionContext) -> ComponentFuture<'a, ()>;

    /// Releases package invocation resources. This hook runs even when an
    /// earlier phase failed.
    fn cleanup<'a>(&'a self, context: &'a mut ExecutionContext) -> ComponentFuture<'a, ()>;

    /// Synchronously releases resources when the execution future is dropped
    /// while pending. This hook is intentionally context-free so it remains
    /// safe to call from `Drop`; implementations should make it idempotent.
    fn cancel(&self) -> Result<(), ComponentError> {
        Err(ComponentError::unsupported(
            "synchronous cancellation cleanup is not implemented",
        ))
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct NoopLifecycle;

impl PackageLifecycle for NoopLifecycle {
    fn finish<'a>(&'a self, _context: &'a mut ExecutionContext) -> ComponentFuture<'a, ()> {
        Box::pin(future::ready(Ok(())))
    }

    fn cleanup<'a>(&'a self, _context: &'a mut ExecutionContext) -> ComponentFuture<'a, ()> {
        Box::pin(future::ready(Ok(())))
    }

    fn cancel(&self) -> Result<(), ComponentError> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct NoopLifecycleFactory;

impl PackageLifecycleFactory for NoopLifecycleFactory {
    fn create(&self) -> Arc<dyn PackageLifecycle> {
        Arc::new(NoopLifecycle)
    }
}

/// A sample failure that remains distinct from assertion and engine errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SampleFailure {
    /// Sampler identity that failed.
    pub sampler_id: NodeId,
    /// Stable diagnostic message.
    pub message: String,
    /// Optional failed result supplied by the sampler.
    pub result: Option<SampleResult>,
}

impl SampleFailure {
    /// Creates a sample failure without a result.
    #[must_use]
    pub fn new(sampler_id: NodeId, message: impl Into<String>) -> Self {
        Self {
            sampler_id,
            message: bounded_text(message, MAX_DIAGNOSTIC_BYTES),
            result: None,
        }
    }

    /// Attaches a failed result to this sample failure.
    #[must_use]
    pub fn with_result(mut self, result: SampleResult) -> Self {
        self.result = Some(result);
        self
    }

    /// Returns the stable machine-readable category for this failure.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        "runtime.sample.failure"
    }
}

impl fmt::Display for SampleFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} at sampler {}: {}",
            self.code(),
            self.sampler_id,
            self.message
        )
    }
}

impl std::error::Error for SampleFailure {}

/// Result returned by a sampler component.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SamplerOutput {
    /// Optional sample result. `None` skips all result phases and listeners.
    pub result: Option<SampleResult>,
    /// Optional sample-level failure.
    pub failure: Option<SampleFailure>,
    /// Control signal requested by this sampler.
    pub signal: ControlSignal,
}

impl Default for SamplerOutput {
    fn default() -> Self {
        Self::no_result()
    }
}

impl SamplerOutput {
    /// Creates a normal non-null sample output.
    #[must_use]
    pub fn result(result: SampleResult) -> Self {
        Self {
            result: Some(result),
            failure: None,
            signal: ControlSignal::Continue,
        }
    }

    /// Creates a null-result output.
    #[must_use]
    pub const fn no_result() -> Self {
        Self {
            result: None,
            failure: None,
            signal: ControlSignal::Continue,
        }
    }

    /// Creates an output carrying only a control signal.
    #[must_use]
    pub const fn control(signal: ControlSignal) -> Self {
        Self {
            result: None,
            failure: None,
            signal,
        }
    }

    /// Creates a sample failure without a separate result.
    #[must_use]
    pub fn failure(failure: SampleFailure) -> Self {
        Self {
            result: failure.result.clone(),
            failure: Some(failure),
            signal: ControlSignal::Continue,
        }
    }

    /// Attaches a control signal while retaining the output.
    #[must_use]
    pub fn with_signal(mut self, signal: ControlSignal) -> Self {
        self.signal = self.signal.combine(signal);
        self
    }
}

/// An error associated with a concrete execution phase.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PipelineError {
    /// Configuration merge failed.
    Configuration {
        node_id: NodeId,
        source: ComponentError,
    },
    /// Preprocessor failed.
    Preprocessor {
        node_id: NodeId,
        source: ComponentError,
    },
    /// Timer evaluation failed.
    Timer {
        node_id: NodeId,
        source: ComponentError,
    },
    /// Additive timer duration overflowed.
    TimerOverflow { sampler_id: NodeId },
    /// Injected sleeper failed.
    Sleeper {
        sampler_id: NodeId,
        source: CapabilityError,
    },
    /// Sampler component failed before producing a typed sample failure.
    Sampler {
        node_id: NodeId,
        source: ComponentError,
    },
    /// Postprocessor failed.
    Postprocessor {
        node_id: NodeId,
        source: ComponentError,
    },
    /// Assertion component failed to evaluate.
    Assertion {
        node_id: NodeId,
        source: ComponentError,
    },
    /// Listener failed while consuming an immutable event.
    Listener {
        node_id: NodeId,
        source: ComponentError,
    },
    /// Result timing, hierarchy, or assertion invariant failed.
    Result {
        sampler_id: NodeId,
        source: ResultError,
    },
    /// Package finish hook failed.
    Finish {
        sampler_id: NodeId,
        source: ComponentError,
    },
    /// Package cleanup hook failed.
    Cleanup {
        sampler_id: NodeId,
        source: ComponentError,
    },
    /// The injected monotonic clock reached the package deadline.
    DeadlineExceeded { sampler_id: NodeId },
    /// Both the primary execution path and cleanup produced errors. Keeping
    /// both sources prevents cleanup diagnostics from being silently dropped.
    Combined {
        primary: Box<Self>,
        cleanup: Box<Self>,
    },
    /// Compilation found duplicate or malformed package identity.
    Compile(PackageCompileError),
}

impl PipelineError {
    /// Returns a stable machine-readable code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Configuration { .. } => "runtime.configuration",
            Self::Preprocessor { .. } => "runtime.preprocessor",
            Self::Timer { .. } => "runtime.timer",
            Self::TimerOverflow { .. } => "runtime.timer.overflow",
            Self::Sleeper { .. } => "runtime.sleeper",
            Self::Sampler { .. } => "runtime.sampler",
            Self::Postprocessor { .. } => "runtime.postprocessor",
            Self::Assertion { .. } => "runtime.assertion",
            Self::Listener { .. } => "runtime.listener",
            Self::Result { .. } => "runtime.result",
            Self::Finish { .. } => "runtime.finish",
            Self::Cleanup { .. } => "runtime.cleanup",
            Self::DeadlineExceeded { .. } => "runtime.deadline",
            Self::Combined { .. } => "runtime.combined",
            Self::Compile(_) => "runtime.compile",
        }
    }
}

impl fmt::Display for PipelineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration { node_id, source } => {
                write!(
                    formatter,
                    "{} at configuration {node_id}: {source}",
                    self.code()
                )
            }
            Self::Preprocessor { node_id, source } => {
                write!(
                    formatter,
                    "{} at preprocessor {node_id}: {source}",
                    self.code()
                )
            }
            Self::Timer { node_id, source } => {
                write!(formatter, "{} at timer {node_id}: {source}", self.code())
            }
            Self::TimerOverflow { sampler_id } => {
                write!(formatter, "{} for sampler {sampler_id}", self.code())
            }
            Self::Sleeper { sampler_id, source } => {
                write!(
                    formatter,
                    "{} for sampler {sampler_id}: {source}",
                    self.code()
                )
            }
            Self::Sampler { node_id, source } => {
                write!(formatter, "{} at sampler {node_id}: {source}", self.code())
            }
            Self::Postprocessor { node_id, source } => {
                write!(
                    formatter,
                    "{} at postprocessor {node_id}: {source}",
                    self.code()
                )
            }
            Self::Assertion { node_id, source } => {
                write!(
                    formatter,
                    "{} at assertion {node_id}: {source}",
                    self.code()
                )
            }
            Self::Listener { node_id, source } => {
                write!(formatter, "{} at listener {node_id}: {source}", self.code())
            }
            Self::Result { sampler_id, source } => {
                write!(
                    formatter,
                    "{} for sampler {sampler_id}: {source}",
                    self.code()
                )
            }
            Self::Finish { sampler_id, source } => {
                write!(
                    formatter,
                    "{} for sampler {sampler_id}: {source}",
                    self.code()
                )
            }
            Self::Cleanup { sampler_id, source } => {
                write!(
                    formatter,
                    "{} for sampler {sampler_id}: {source}",
                    self.code()
                )
            }
            Self::DeadlineExceeded { sampler_id } => {
                write!(formatter, "{} for sampler {sampler_id}", self.code())
            }
            Self::Combined { primary, cleanup } => {
                write!(
                    formatter,
                    "{}: primary={primary}; cleanup={cleanup}",
                    self.code()
                )
            }
            Self::Compile(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for PipelineError {}

/// Errors raised while constructing the immutable package map.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PackageCompileError {
    /// Two package specifications use one sampler identity.
    DuplicateSampler { sampler_id: NodeId },
    /// A package was supplied without a sampler component.
    MissingSampler { sampler_id: NodeId },
    /// Compilation input exceeded a caller-provided package bound.
    PackageLimit { limit: usize },
    /// A required package identity was not compiled.
    MissingPackage { sampler_id: NodeId },
    /// A package cannot be isolated because it was built without factories.
    MissingFactory {
        sampler_id: NodeId,
        component: &'static str,
    },
    /// An assembler returned a package for a different source sampler.
    SamplerIdentityMismatch { expected: NodeId, actual: NodeId },
}

impl PackageCompileError {
    /// Returns a stable machine-readable code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::DuplicateSampler { .. } => "runtime.compile.duplicate-sampler",
            Self::MissingSampler { .. } => "runtime.compile.missing-sampler",
            Self::PackageLimit { .. } => "runtime.compile.package-limit",
            Self::MissingPackage { .. } => "runtime.compile.missing-package",
            Self::MissingFactory { .. } => "runtime.compile.missing-factory",
            Self::SamplerIdentityMismatch { .. } => "runtime.compile.sampler-identity-mismatch",
        }
    }
}

impl fmt::Display for PackageCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateSampler { sampler_id } => {
                write!(formatter, "{}: sampler {sampler_id}", self.code())
            }
            Self::MissingSampler { sampler_id } => {
                write!(formatter, "{}: sampler {sampler_id}", self.code())
            }
            Self::PackageLimit { limit } => {
                write!(formatter, "{}: package limit {limit}", self.code())
            }
            Self::MissingPackage { sampler_id } => {
                write!(formatter, "{}: sampler {sampler_id}", self.code())
            }
            Self::MissingFactory {
                sampler_id,
                component,
            } => write!(
                formatter,
                "{}: {component} for sampler {sampler_id}",
                self.code()
            ),
            Self::SamplerIdentityMismatch { expected, actual } => write!(
                formatter,
                "{}: expected sampler {expected}, got {actual}",
                self.code()
            ),
        }
    }
}

impl std::error::Error for PackageCompileError {}

/// An immutable execution package keyed by one model [`NodeId`].
pub struct SamplePackage {
    sampler_id: NodeId,
    configurations: Arc<[Arc<dyn Configuration>]>,
    preprocessors: Arc<[Arc<dyn Preprocessor>]>,
    timers: Arc<[Arc<dyn Timer>]>,
    sampler: Arc<dyn Sampler>,
    postprocessors: Arc<[Arc<dyn Postprocessor>]>,
    assertions: Arc<[Arc<dyn Assertion>]>,
    listeners: Arc<[Arc<dyn Listener>]>,
    lifecycle: Arc<dyn PackageLifecycle>,
    configuration_factories: Option<Arc<[Arc<dyn ConfigurationFactory>]>>,
    preprocessor_factories: Option<Arc<[Arc<dyn PreprocessorFactory>]>>,
    timer_factories: Option<Arc<[Arc<dyn TimerFactory>]>>,
    sampler_factory: Option<Arc<dyn SamplerFactory>>,
    postprocessor_factories: Option<Arc<[Arc<dyn PostprocessorFactory>]>>,
    assertion_factories: Option<Arc<[Arc<dyn AssertionFactory>]>>,
    listener_factories: Option<Arc<[Arc<dyn ListenerFactory>]>>,
    lifecycle_factory: Option<Arc<dyn PackageLifecycleFactory>>,
}

fn build_components<F, T>(
    sampler_id: NodeId,
    component_count: usize,
    factories: Option<&[Arc<F>]>,
    component: &'static str,
    create: fn(&F) -> Arc<T>,
) -> Result<Vec<Arc<T>>, PackageCompileError>
where
    F: ?Sized,
    T: ?Sized,
{
    if component_count == 0 {
        return Ok(Vec::new());
    }
    let factories = factories.ok_or(PackageCompileError::MissingFactory {
        sampler_id,
        component,
    })?;
    if factories.len() != component_count {
        return Err(PackageCompileError::MissingFactory {
            sampler_id,
            component,
        });
    }
    Ok(factories
        .iter()
        .map(|factory| create(factory.as_ref()))
        .collect())
}

impl fmt::Debug for SamplePackage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SamplePackage")
            .field("sampler_id", &self.sampler_id)
            .field("configuration_count", &self.configurations.len())
            .field("preprocessor_count", &self.preprocessors.len())
            .field("timer_count", &self.timers.len())
            .field("postprocessor_count", &self.postprocessors.len())
            .field("assertion_count", &self.assertions.len())
            .field("listener_count", &self.listeners.len())
            .finish_non_exhaustive()
    }
}

impl Clone for SamplePackage {
    fn clone(&self) -> Self {
        Self {
            sampler_id: self.sampler_id,
            configurations: Arc::clone(&self.configurations),
            preprocessors: Arc::clone(&self.preprocessors),
            timers: Arc::clone(&self.timers),
            sampler: Arc::clone(&self.sampler),
            postprocessors: Arc::clone(&self.postprocessors),
            assertions: Arc::clone(&self.assertions),
            listeners: Arc::clone(&self.listeners),
            lifecycle: Arc::clone(&self.lifecycle),
            configuration_factories: self.configuration_factories.clone(),
            preprocessor_factories: self.preprocessor_factories.clone(),
            timer_factories: self.timer_factories.clone(),
            sampler_factory: self.sampler_factory.clone(),
            postprocessor_factories: self.postprocessor_factories.clone(),
            assertion_factories: self.assertion_factories.clone(),
            listener_factories: self.listener_factories.clone(),
            lifecycle_factory: self.lifecycle_factory.clone(),
        }
    }
}

impl SamplePackage {
    /// Creates a package containing only its sampler.
    #[must_use]
    pub fn new(sampler_id: NodeId, sampler: Arc<dyn Sampler>) -> Self {
        Self {
            sampler_id,
            configurations: Arc::from(Vec::<Arc<dyn Configuration>>::new()),
            preprocessors: Arc::from(Vec::<Arc<dyn Preprocessor>>::new()),
            timers: Arc::from(Vec::<Arc<dyn Timer>>::new()),
            sampler,
            postprocessors: Arc::from(Vec::<Arc<dyn Postprocessor>>::new()),
            assertions: Arc::from(Vec::<Arc<dyn Assertion>>::new()),
            listeners: Arc::from(Vec::<Arc<dyn Listener>>::new()),
            lifecycle: Arc::new(NoopLifecycle),
            configuration_factories: None,
            preprocessor_factories: None,
            timer_factories: None,
            sampler_factory: None,
            postprocessor_factories: None,
            assertion_factories: None,
            listener_factories: None,
            lifecycle_factory: Some(Arc::new(NoopLifecycleFactory)),
        }
    }

    /// Starts a package builder with a sampler identity and component.
    #[must_use]
    pub fn builder(sampler_id: NodeId, sampler: Arc<dyn Sampler>) -> SamplePackageBuilder {
        SamplePackageBuilder::new(sampler_id, sampler)
    }

    /// Returns this package's sampler identity.
    #[must_use]
    pub const fn sampler_id(&self) -> NodeId {
        self.sampler_id
    }

    /// Returns configuration components in compiler-supplied order.
    #[must_use]
    pub fn configurations(&self) -> &[Arc<dyn Configuration>] {
        &self.configurations
    }

    /// Returns preprocessors in compiler-supplied order.
    #[must_use]
    pub fn preprocessors(&self) -> &[Arc<dyn Preprocessor>] {
        &self.preprocessors
    }

    /// Returns timers in compiler-supplied order.
    #[must_use]
    pub fn timers(&self) -> &[Arc<dyn Timer>] {
        &self.timers
    }

    /// Returns postprocessors in compiler-supplied order.
    #[must_use]
    pub fn postprocessors(&self) -> &[Arc<dyn Postprocessor>] {
        &self.postprocessors
    }

    /// Returns assertions in compiler-supplied order.
    #[must_use]
    pub fn assertions(&self) -> &[Arc<dyn Assertion>] {
        &self.assertions
    }

    /// Returns listeners in compiler-supplied order and scope.
    #[must_use]
    pub fn listeners(&self) -> &[Arc<dyn Listener>] {
        &self.listeners
    }

    /// Returns a package with the supplied configuration order.
    #[must_use]
    pub fn with_configurations(mut self, values: Vec<Arc<dyn Configuration>>) -> Self {
        self.configurations = values.into();
        self.configuration_factories = None;
        self
    }

    /// Returns a package with the supplied preprocessor order.
    #[must_use]
    pub fn with_preprocessors(mut self, values: Vec<Arc<dyn Preprocessor>>) -> Self {
        self.preprocessors = values.into();
        self.preprocessor_factories = None;
        self
    }

    /// Returns a package with the supplied timer order.
    #[must_use]
    pub fn with_timers(mut self, values: Vec<Arc<dyn Timer>>) -> Self {
        self.timers = values.into();
        self.timer_factories = None;
        self
    }

    /// Returns a package with the supplied postprocessor order.
    #[must_use]
    pub fn with_postprocessors(mut self, values: Vec<Arc<dyn Postprocessor>>) -> Self {
        self.postprocessors = values.into();
        self.postprocessor_factories = None;
        self
    }

    /// Returns a package with the supplied assertion order.
    #[must_use]
    pub fn with_assertions(mut self, values: Vec<Arc<dyn Assertion>>) -> Self {
        self.assertions = values.into();
        self.assertion_factories = None;
        self
    }

    /// Returns a package with the supplied listener scope/order.
    #[must_use]
    pub fn with_listeners(mut self, values: Vec<Arc<dyn Listener>>) -> Self {
        self.listeners = values.into();
        self.listener_factories = None;
        self
    }

    /// Returns a package with custom lifecycle hooks.
    #[must_use]
    pub fn with_lifecycle(mut self, value: Arc<dyn PackageLifecycle>) -> Self {
        self.lifecycle = value;
        self.lifecycle_factory = None;
        self
    }

    /// Builds an isolated package instance for one virtual user.
    ///
    /// The ordinary [`Clone`] implementation only clones the immutable
    /// package template and therefore retains component Arcs. Callers that
    /// execute the same package concurrently must use this method and supply
    /// factories through the builder; a missing factory is a typed error,
    /// never an implicit shared mutable component.
    pub fn clone_for_user(&self) -> Result<Self, PackageCompileError> {
        let sampler = self
            .sampler_factory
            .as_ref()
            .ok_or(PackageCompileError::MissingFactory {
                sampler_id: self.sampler_id,
                component: "sampler",
            })?
            .create();
        let configurations = build_components(
            self.sampler_id,
            self.configurations.len(),
            self.configuration_factories.as_deref(),
            "configuration",
            ConfigurationFactory::create,
        )?;
        let preprocessors = build_components(
            self.sampler_id,
            self.preprocessors.len(),
            self.preprocessor_factories.as_deref(),
            "preprocessor",
            PreprocessorFactory::create,
        )?;
        let timers = build_components(
            self.sampler_id,
            self.timers.len(),
            self.timer_factories.as_deref(),
            "timer",
            TimerFactory::create,
        )?;
        let postprocessors = build_components(
            self.sampler_id,
            self.postprocessors.len(),
            self.postprocessor_factories.as_deref(),
            "postprocessor",
            PostprocessorFactory::create,
        )?;
        let assertions = build_components(
            self.sampler_id,
            self.assertions.len(),
            self.assertion_factories.as_deref(),
            "assertion",
            AssertionFactory::create,
        )?;
        let listeners = build_components(
            self.sampler_id,
            self.listeners.len(),
            self.listener_factories.as_deref(),
            "listener",
            ListenerFactory::create,
        )?;
        let lifecycle = self
            .lifecycle_factory
            .as_ref()
            .ok_or(PackageCompileError::MissingFactory {
                sampler_id: self.sampler_id,
                component: "lifecycle",
            })?
            .create();
        Ok(Self {
            sampler_id: self.sampler_id,
            configurations: configurations.into(),
            preprocessors: preprocessors.into(),
            timers: timers.into(),
            sampler,
            postprocessors: postprocessors.into(),
            assertions: assertions.into(),
            listeners: listeners.into(),
            lifecycle,
            configuration_factories: self.configuration_factories.clone(),
            preprocessor_factories: self.preprocessor_factories.clone(),
            timer_factories: self.timer_factories.clone(),
            sampler_factory: self.sampler_factory.clone(),
            postprocessor_factories: self.postprocessor_factories.clone(),
            assertion_factories: self.assertion_factories.clone(),
            listener_factories: self.listener_factories.clone(),
            lifecycle_factory: self.lifecycle_factory.clone(),
        })
    }

    /// Executes this package using the fixed phase protocol.
    pub fn execute<'a>(
        &'a self,
        context: &'a mut ExecutionContext,
    ) -> PipelineFuture<'a, ExecutionReport> {
        ExecutionPipeline::execute(self, context)
    }
}

/// Builder for one immutable sampler package.
pub struct SamplePackageBuilder {
    package: SamplePackage,
}

impl SamplePackageBuilder {
    fn new(sampler_id: NodeId, sampler: Arc<dyn Sampler>) -> Self {
        Self {
            package: SamplePackage::new(sampler_id, sampler),
        }
    }

    /// Replaces configuration elements in their already-resolved order.
    #[must_use]
    pub fn configurations(mut self, values: Vec<Arc<dyn Configuration>>) -> Self {
        self.package.configurations = values.into();
        self.package.configuration_factories = None;
        self
    }

    /// Supplies per-user configuration factories in resolved order.
    #[must_use]
    pub fn configuration_factories(mut self, values: Vec<Arc<dyn ConfigurationFactory>>) -> Self {
        self.package.configuration_factories = Some(values.into());
        self.package.configurations = self
            .package
            .configuration_factories
            .as_ref()
            .map(|factories| factories.iter().map(|factory| factory.create()).collect())
            .unwrap_or_default();
        self
    }

    /// Replaces preprocessors in their already-resolved order.
    #[must_use]
    pub fn preprocessors(mut self, values: Vec<Arc<dyn Preprocessor>>) -> Self {
        self.package.preprocessors = values.into();
        self.package.preprocessor_factories = None;
        self
    }

    /// Supplies per-user preprocessor factories in resolved order.
    #[must_use]
    pub fn preprocessor_factories(mut self, values: Vec<Arc<dyn PreprocessorFactory>>) -> Self {
        self.package.preprocessor_factories = Some(values.into());
        self.package.preprocessors = self
            .package
            .preprocessor_factories
            .as_ref()
            .map(|factories| factories.iter().map(|factory| factory.create()).collect())
            .unwrap_or_default();
        self
    }

    /// Replaces timers in their already-resolved order.
    #[must_use]
    pub fn timers(mut self, values: Vec<Arc<dyn Timer>>) -> Self {
        self.package.timers = values.into();
        self.package.timer_factories = None;
        self
    }

    /// Supplies per-user timer factories in resolved order.
    #[must_use]
    pub fn timer_factories(mut self, values: Vec<Arc<dyn TimerFactory>>) -> Self {
        self.package.timer_factories = Some(values.into());
        self.package.timers = self
            .package
            .timer_factories
            .as_ref()
            .map(|factories| factories.iter().map(|factory| factory.create()).collect())
            .unwrap_or_default();
        self
    }

    /// Replaces postprocessors in their already-resolved order.
    #[must_use]
    pub fn postprocessors(mut self, values: Vec<Arc<dyn Postprocessor>>) -> Self {
        self.package.postprocessors = values.into();
        self.package.postprocessor_factories = None;
        self
    }

    /// Supplies per-user postprocessor factories in resolved order.
    #[must_use]
    pub fn postprocessor_factories(mut self, values: Vec<Arc<dyn PostprocessorFactory>>) -> Self {
        self.package.postprocessor_factories = Some(values.into());
        self.package.postprocessors = self
            .package
            .postprocessor_factories
            .as_ref()
            .map(|factories| factories.iter().map(|factory| factory.create()).collect())
            .unwrap_or_default();
        self
    }

    /// Replaces assertions in their already-resolved order.
    #[must_use]
    pub fn assertions(mut self, values: Vec<Arc<dyn Assertion>>) -> Self {
        self.package.assertions = values.into();
        self.package.assertion_factories = None;
        self
    }

    /// Supplies per-user assertion factories in resolved order.
    #[must_use]
    pub fn assertion_factories(mut self, values: Vec<Arc<dyn AssertionFactory>>) -> Self {
        self.package.assertion_factories = Some(values.into());
        self.package.assertions = self
            .package
            .assertion_factories
            .as_ref()
            .map(|factories| factories.iter().map(|factory| factory.create()).collect())
            .unwrap_or_default();
        self
    }

    /// Replaces listeners in their already-resolved scope/order.
    #[must_use]
    pub fn listeners(mut self, values: Vec<Arc<dyn Listener>>) -> Self {
        self.package.listeners = values.into();
        self.package.listener_factories = None;
        self
    }

    /// Supplies per-user listener factories in resolved order.
    #[must_use]
    pub fn listener_factories(mut self, values: Vec<Arc<dyn ListenerFactory>>) -> Self {
        self.package.listener_factories = Some(values.into());
        self.package.listeners = self
            .package
            .listener_factories
            .as_ref()
            .map(|factories| factories.iter().map(|factory| factory.create()).collect())
            .unwrap_or_default();
        self
    }

    /// Installs package finish and cleanup hooks.
    #[must_use]
    pub fn lifecycle(mut self, value: Arc<dyn PackageLifecycle>) -> Self {
        self.package.lifecycle = value;
        self.package.lifecycle_factory = None;
        self
    }

    /// Supplies a per-user lifecycle factory.
    #[must_use]
    pub fn lifecycle_factory(mut self, value: Arc<dyn PackageLifecycleFactory>) -> Self {
        self.package.lifecycle_factory = Some(value);
        self.package.lifecycle = self
            .package
            .lifecycle_factory
            .as_ref()
            .map(|factory| factory.create())
            .unwrap_or_else(|| Arc::new(NoopLifecycle));
        self
    }

    /// Supplies the per-user sampler factory. The initial sampler argument is
    /// retained only as the immutable template used by callers that inspect
    /// this builder before selecting a user instance.
    #[must_use]
    pub fn sampler_factory(mut self, value: Arc<dyn SamplerFactory>) -> Self {
        self.package.sampler_factory = Some(value);
        self
    }

    /// Finishes the immutable package construction.
    #[must_use]
    pub fn build(self) -> SamplePackage {
        self.package
    }
}

/// An immutable map of sampler IDs to compiled packages.
#[derive(Clone, Debug)]
pub struct PackageCompiler {
    max_packages: usize,
}

impl Default for PackageCompiler {
    fn default() -> Self {
        Self::new(16_384)
    }
}

impl PackageCompiler {
    /// Creates a compiler with a finite package bound.
    #[must_use]
    pub const fn new(max_packages: usize) -> Self {
        Self { max_packages }
    }

    /// Compiles already-resolved packages keyed by their model node IDs.
    pub fn compile<I>(&self, packages: I) -> Result<CompiledPackages, PackageCompileError>
    where
        I: IntoIterator<Item = SamplePackage>,
    {
        let mut map = BTreeMap::new();
        for package in packages {
            if map.len() >= self.max_packages {
                return Err(PackageCompileError::PackageLimit {
                    limit: self.max_packages,
                });
            }
            let sampler_id = package.sampler_id();
            if map.insert(sampler_id, package).is_some() {
                return Err(PackageCompileError::DuplicateSampler { sampler_id });
            }
        }
        Ok(CompiledPackages { packages: map })
    }

    /// Compiles with a useful finite default bound.
    pub fn compile_default<I>(packages: I) -> Result<CompiledPackages, PackageCompileError>
    where
        I: IntoIterator<Item = SamplePackage>,
    {
        Self::new(16_384).compile(packages)
    }
}

/// Immutable compiled package storage.
#[derive(Clone, Debug, Default)]
pub struct CompiledPackages {
    packages: BTreeMap<NodeId, SamplePackage>,
}

impl CompiledPackages {
    /// Compiles packages with the default finite package bound.
    pub fn from_packages<I>(packages: I) -> Result<Self, PackageCompileError>
    where
        I: IntoIterator<Item = SamplePackage>,
    {
        PackageCompiler::default().compile(packages)
    }

    /// Returns a package by model identity.
    #[must_use]
    pub fn get(&self, sampler_id: NodeId) -> Option<&SamplePackage> {
        self.packages.get(&sampler_id)
    }

    /// Looks up a mandatory package without collapsing absence into `None`.
    pub fn require(&self, sampler_id: NodeId) -> Result<&SamplePackage, PackageCompileError> {
        self.get(sampler_id)
            .ok_or(PackageCompileError::MissingPackage { sampler_id })
    }

    /// Builds an isolated package map for one virtual user.
    pub fn clone_for_user(&self) -> Result<Self, PackageCompileError> {
        self.packages
            .iter()
            .map(|(id, package)| package.clone_for_user().map(|package| (*id, package)))
            .collect::<Result<BTreeMap<_, _>, _>>()
            .map(|packages| Self { packages })
    }

    /// Returns the number of compiled packages.
    #[must_use]
    pub fn len(&self) -> usize {
        self.packages.len()
    }

    /// Returns whether no packages were compiled.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.packages.is_empty()
    }

    /// Iterates package identities and packages in stable node-ID order.
    pub fn iter(&self) -> impl Iterator<Item = (NodeId, &SamplePackage)> {
        self.packages.iter().map(|(id, package)| (*id, package))
    }
}

/// A report from one sampler package invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionReport {
    /// Sampler identity.
    pub sampler_id: NodeId,
    /// Result, if the sampler was non-null.
    pub result: Option<SampleResult>,
    /// Immutable event snapshot, if the sampler was non-null.
    pub event: Option<SampleEvent>,
    /// Sample-level failure, distinct from engine errors.
    pub sample_failure: Option<SampleFailure>,
    /// Highest control signal observed during this invocation.
    pub signal: ControlSignal,
    /// Additive timer delay applied before the sampler.
    pub timer_delay: Duration,
}

impl ExecutionReport {
    fn controlled(sampler_id: NodeId, signal: ControlSignal) -> Self {
        Self {
            sampler_id,
            result: None,
            event: None,
            sample_failure: None,
            signal,
            timer_delay: Duration::ZERO,
        }
    }
}

/// A future returned by [`ExecutionPipeline::execute`].
///
/// Dropping a pending future synchronously invokes the package lifecycle's
/// [`PackageLifecycle::cancel`] hook. Implementations that own resources must
/// provide an idempotent cancellation hook; the default records a typed
/// unsupported error in [`ExecutionContext::cancellation_error`] rather than
/// silently claiming cleanup succeeded.
pub struct PipelineFuture<'a, T> {
    inner: Pin<Box<dyn Future<Output = Result<T, PipelineError>> + 'a>>,
    guard: Option<PipelineDropGuard>,
    clock: Arc<dyn Clock>,
    deadline: Option<Duration>,
    sampler_id: NodeId,
}

struct PipelineDropGuard {
    lifecycle: Arc<dyn PackageLifecycle>,
    cancellation_error: Arc<Mutex<Option<ComponentError>>>,
    armed: bool,
}

impl PipelineDropGuard {
    fn disarm(&mut self) {
        self.armed = false;
    }

    fn cancel(&mut self) -> Option<ComponentError> {
        if !self.armed {
            return None;
        }
        self.armed = false;
        match self.lifecycle.cancel() {
            Ok(()) => None,
            Err(error) => {
                let mut slot = mutex_lock(&self.cancellation_error);
                if slot.is_none() {
                    *slot = Some(error.clone());
                }
                Some(error)
            }
        }
    }
}

impl Drop for PipelineDropGuard {
    fn drop(&mut self) {
        // `cancel` stores any failure in the invocation's shared diagnostic
        // slot because `Drop` cannot return it to the executor.
        self.cancel();
    }
}

impl<'a, T> PipelineFuture<'a, T> {
    fn new(
        inner: Pin<Box<dyn Future<Output = Result<T, PipelineError>> + 'a>>,
        lifecycle: Arc<dyn PackageLifecycle>,
        cancellation_error: Arc<Mutex<Option<ComponentError>>>,
        clock: Arc<dyn Clock>,
        deadline: Option<Duration>,
        sampler_id: NodeId,
    ) -> Self {
        Self {
            inner,
            guard: Some(PipelineDropGuard {
                lifecycle,
                cancellation_error,
                armed: true,
            }),
            clock,
            deadline,
            sampler_id,
        }
    }
}

impl<T> Unpin for PipelineFuture<'_, T> {}

impl<T> Future for PipelineFuture<'_, T> {
    type Output = Result<T, PipelineError>;

    fn poll(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        if self
            .deadline
            .is_some_and(|deadline| self.clock.now().monotonic >= deadline)
        {
            let primary = PipelineError::DeadlineExceeded {
                sampler_id: self.sampler_id,
            };
            let cleanup = self
                .guard
                .as_mut()
                .and_then(PipelineDropGuard::cancel)
                .map(|source| PipelineError::Cleanup {
                    sampler_id: self.sampler_id,
                    source,
                });
            self.guard = None;
            return std::task::Poll::Ready(match cleanup {
                Some(cleanup) => Err(PipelineError::Combined {
                    primary: Box::new(primary),
                    cleanup: Box::new(cleanup),
                }),
                None => Err(primary),
            });
        }
        match self.inner.as_mut().poll(context) {
            std::task::Poll::Ready(value) => {
                if let Some(mut guard) = self.guard.take() {
                    guard.disarm();
                }
                std::task::Poll::Ready(value)
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

type BoxedPipelineFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, PipelineError>> + 'a>>;

/// Runs the fixed per-sampler execution protocol.
#[derive(Clone, Copy, Debug, Default)]
pub struct ExecutionPipeline;

impl ExecutionPipeline {
    /// Executes configuration, preprocessors, additive timers, sampler,
    /// result phases, listeners, and lifecycle hooks in order.
    pub fn execute<'a>(
        package: &'a SamplePackage,
        context: &'a mut ExecutionContext,
    ) -> PipelineFuture<'a, ExecutionReport> {
        let cancellation_error = Arc::clone(&context.cancellation_error);
        let clock = Arc::clone(&context.capabilities.clock);
        let deadline = context.deadline;
        let inner = Box::pin(async move {
            let primary = Self::execute_phases(package, context).await;
            let finish = if primary.is_ok() {
                Self::finish(package, context).await.err()
            } else {
                None
            };
            let cleanup = Self::cleanup(package, context).await.err();
            match (primary, finish, cleanup) {
                (Err(primary), _, Some(cleanup)) => Err(PipelineError::Combined {
                    primary: Box::new(primary),
                    cleanup: Box::new(cleanup),
                }),
                (Err(primary), _, None) => Err(primary),
                (Ok(_), Some(primary), Some(cleanup)) => Err(PipelineError::Combined {
                    primary: Box::new(primary),
                    cleanup: Box::new(cleanup),
                }),
                (Ok(_), Some(error), None) => Err(error),
                (Ok(_), None, Some(error)) => Err(error),
                (Ok(report), None, None) => Ok(report),
            }
        });
        PipelineFuture::new(
            inner,
            Arc::clone(&package.lifecycle),
            cancellation_error,
            clock,
            deadline,
            package.sampler_id,
        )
    }

    /// Instance-method spelling for callers that keep a configured pipeline
    /// value at an application edge. The first runtime pipeline has no
    /// mutable scheduler state, so this delegates to [`Self::execute`].
    pub fn run<'a>(
        &self,
        package: &'a SamplePackage,
        context: &'a mut ExecutionContext,
    ) -> PipelineFuture<'a, ExecutionReport> {
        Self::execute(package, context)
    }

    fn finish<'a>(
        package: &'a SamplePackage,
        context: &'a mut ExecutionContext,
    ) -> BoxedPipelineFuture<'a, ()> {
        Box::pin(async move {
            context.set_expression_field_namespace(
                "runtime.plan.finish",
                package.sampler_id,
                "lifecycle",
            );
            let trace_error = context
                .trace
                .push(Phase::Finish, Some(package.sampler_id), "package.finish")
                .err();
            let hook_error = package.lifecycle.finish(context).await.err();
            let source = match (trace_error, hook_error) {
                (Some(primary), Some(secondary)) => {
                    Some(combine_component_errors(primary, secondary))
                }
                (Some(error), None) | (None, Some(error)) => Some(error),
                (None, None) => None,
            };
            match source {
                Some(source) => Err(PipelineError::Finish {
                    sampler_id: package.sampler_id,
                    source,
                }),
                None => Ok(()),
            }
        })
    }

    fn cleanup<'a>(
        package: &'a SamplePackage,
        context: &'a mut ExecutionContext,
    ) -> BoxedPipelineFuture<'a, ()> {
        Box::pin(async move {
            context.set_expression_field_namespace(
                "runtime.plan.cleanup",
                package.sampler_id,
                "lifecycle",
            );
            let trace_error = context
                .trace
                .push(Phase::Cleanup, Some(package.sampler_id), "package.cleanup")
                .err();
            let hook_error = package.lifecycle.cleanup(context).await.err();
            let source = match (trace_error, hook_error) {
                (Some(primary), Some(secondary)) => {
                    Some(combine_component_errors(primary, secondary))
                }
                (Some(error), None) | (None, Some(error)) => Some(error),
                (None, None) => None,
            };
            match source {
                Some(source) => Err(PipelineError::Cleanup {
                    sampler_id: package.sampler_id,
                    source,
                }),
                None => Ok(()),
            }
        })
    }

    async fn execute_phases(
        package: &SamplePackage,
        context: &mut ExecutionContext,
    ) -> Result<ExecutionReport, PipelineError> {
        let mut sample_context = SampleContext::new(context, package.sampler_id);
        check_phase_deadline(&sample_context, package.sampler_id)?;
        if sample_context.execution().control_signal().is_stop() {
            let signal = sample_context.execution().control_signal();
            return Ok(ExecutionReport::controlled(package.sampler_id, signal));
        }
        for (index, component) in package.configurations.iter().enumerate() {
            sample_context
                .execution_mut()
                .set_expression_field_namespace(
                    "runtime.plan.configuration",
                    package.sampler_id,
                    &format!("configuration:{index}"),
                );
            check_phase_deadline(&sample_context, package.sampler_id)?;
            sample_context
                .record(Phase::Configuration, format!("configuration[{index}]"))
                .map_err(|source| PipelineError::Configuration {
                    node_id: package.sampler_id,
                    source,
                })?;
            match component.apply(&mut sample_context).await {
                Ok(()) => {}
                Err(ComponentError::Control(signal)) => {
                    sample_context.execution_mut().request_control(signal);
                    return Ok(ExecutionReport::controlled(
                        package.sampler_id,
                        sample_context.execution().control_signal(),
                    ));
                }
                Err(source) => {
                    return Err(PipelineError::Configuration {
                        node_id: package.sampler_id,
                        source,
                    });
                }
            }
            if sample_context.execution().control_signal().is_stop() {
                return Ok(ExecutionReport::controlled(
                    package.sampler_id,
                    sample_context.execution().control_signal(),
                ));
            }
        }

        for (index, component) in package.preprocessors.iter().enumerate() {
            sample_context
                .execution_mut()
                .set_expression_field_namespace(
                    "runtime.plan.preprocessor",
                    package.sampler_id,
                    &format!("preprocessor:{index}"),
                );
            check_phase_deadline(&sample_context, package.sampler_id)?;
            sample_context
                .record(Phase::Preprocessor, format!("preprocessor[{index}]"))
                .map_err(|source| PipelineError::Preprocessor {
                    node_id: package.sampler_id,
                    source,
                })?;
            match component.process(&mut sample_context).await {
                Ok(()) => {}
                Err(ComponentError::Control(signal)) => {
                    sample_context.execution_mut().request_control(signal);
                    return Ok(ExecutionReport::controlled(
                        package.sampler_id,
                        sample_context.execution().control_signal(),
                    ));
                }
                Err(source) => {
                    return Err(PipelineError::Preprocessor {
                        node_id: package.sampler_id,
                        source,
                    });
                }
            }
            if sample_context.execution().control_signal().is_stop() {
                return Ok(ExecutionReport::controlled(
                    package.sampler_id,
                    sample_context.execution().control_signal(),
                ));
            }
        }

        let mut total_delay = Duration::ZERO;
        for (index, component) in package.timers.iter().enumerate() {
            sample_context
                .execution_mut()
                .set_expression_field_namespace(
                    "runtime.plan.timer",
                    package.sampler_id,
                    &format!("timer:{index}"),
                );
            check_phase_deadline(&sample_context, package.sampler_id)?;
            sample_context
                .record(Phase::Timer, format!("timer[{index}]"))
                .map_err(|source| PipelineError::Timer {
                    node_id: package.sampler_id,
                    source,
                })?;
            let delay = match component.delay(&mut sample_context).await {
                Ok(delay) => delay,
                Err(ComponentError::Control(signal)) => {
                    sample_context.execution_mut().request_control(signal);
                    return Ok(ExecutionReport::controlled(
                        package.sampler_id,
                        sample_context.execution().control_signal(),
                    ));
                }
                Err(source) => {
                    return Err(PipelineError::Timer {
                        node_id: package.sampler_id,
                        source,
                    });
                }
            };
            let delay = if component.is_modifiable() {
                scale_timer_delay(
                    delay,
                    sample_context.execution().timer_factor(),
                    package.sampler_id,
                )?
            } else {
                delay
            };
            total_delay = total_delay
                .checked_add(delay)
                .ok_or(PipelineError::TimerOverflow {
                    sampler_id: package.sampler_id,
                })?;
            if sample_context.execution().control_signal().is_stop() {
                return Ok(ExecutionReport::controlled(
                    package.sampler_id,
                    sample_context.execution().control_signal(),
                ));
            }
        }
        if sample_context.execution().control_signal().is_stop() {
            let signal = sample_context.execution().control_signal();
            return Ok(ExecutionReport::controlled(package.sampler_id, signal));
        }
        if !total_delay.is_zero() {
            check_phase_deadline(&sample_context, package.sampler_id)?;
            match sample_context
                .execution()
                .capabilities()
                .sleeper()
                .sleep(total_delay)
                .await
            {
                Ok(()) => {}
                Err(CapabilityError::Control(signal)) => {
                    sample_context.execution_mut().request_control(signal);
                    return Ok(ExecutionReport::controlled(
                        package.sampler_id,
                        sample_context.execution().control_signal(),
                    ));
                }
                Err(source) => {
                    return Err(PipelineError::Sleeper {
                        sampler_id: package.sampler_id,
                        source,
                    });
                }
            }
        }

        let start = sample_context.execution().capabilities().clock().now();
        sample_context
            .execution_mut()
            .set_expression_field_namespace("runtime.plan.sampler", package.sampler_id, "sampler");
        check_phase_deadline(&sample_context, package.sampler_id)?;
        sample_context
            .record(Phase::Sampler, "sampler")
            .map_err(|source| PipelineError::Sampler {
                node_id: package.sampler_id,
                source,
            })?;
        let sampler_output = match package.sampler.sample(&mut sample_context).await {
            Ok(output) => output,
            Err(ComponentError::Control(signal)) => {
                sample_context.execution_mut().request_control(signal);
                return Ok(ExecutionReport::controlled(
                    package.sampler_id,
                    sample_context.execution().control_signal(),
                ));
            }
            Err(source) => {
                return Err(PipelineError::Sampler {
                    node_id: package.sampler_id,
                    source,
                });
            }
        };
        let end = sample_context.execution().capabilities().clock().now();
        sample_context
            .execution_mut()
            .request_control(sampler_output.signal);
        sample_context.set_result(sampler_output.result);
        let sample_failure = sampler_output.failure;
        if let Some(result) = sample_context.result() {
            let signal = result_control_signal(result);
            sample_context.execution_mut().request_control(signal);
        }
        if sample_context.result().is_none() {
            return Ok(ExecutionReport {
                sampler_id: package.sampler_id,
                result: None,
                event: None,
                sample_failure,
                signal: sample_context.execution().control_signal(),
                timer_delay: total_delay,
            });
        }
        update_result_timing(&mut sample_context, start, end)?;

        for (index, component) in package.postprocessors.iter().enumerate() {
            sample_context
                .execution_mut()
                .set_expression_field_namespace(
                    "runtime.plan.postprocessor",
                    package.sampler_id,
                    &format!("postprocessor:{index}"),
                );
            check_phase_deadline(&sample_context, package.sampler_id)?;
            sample_context
                .record(Phase::Postprocessor, format!("postprocessor[{index}]"))
                .map_err(|source| PipelineError::Postprocessor {
                    node_id: package.sampler_id,
                    source,
                })?;
            match component.process(&mut sample_context).await {
                Ok(()) => {}
                Err(ComponentError::Control(signal)) => {
                    sample_context.execution_mut().request_control(signal);
                    break;
                }
                Err(source) => {
                    return Err(PipelineError::Postprocessor {
                        node_id: package.sampler_id,
                        source,
                    });
                }
            }
        }

        for (index, component) in package.assertions.iter().enumerate() {
            sample_context
                .execution_mut()
                .set_expression_field_namespace(
                    "runtime.plan.assertion",
                    package.sampler_id,
                    &format!("assertion:{index}"),
                );
            check_phase_deadline(&sample_context, package.sampler_id)?;
            sample_context
                .record(Phase::Assertion, format!("assertion[{index}]"))
                .map_err(|source| PipelineError::Assertion {
                    node_id: package.sampler_id,
                    source,
                })?;
            let assertion = match component.evaluate(&mut sample_context).await {
                Ok(assertion) => assertion,
                Err(ComponentError::Control(signal)) => {
                    sample_context.execution_mut().request_control(signal);
                    break;
                }
                Err(source) => {
                    return Err(PipelineError::Assertion {
                        node_id: package.sampler_id,
                        source,
                    });
                }
            };
            let result = sample_context.result_mut().ok_or(PipelineError::Result {
                sampler_id: package.sampler_id,
                source: ResultError::InvalidHierarchy {
                    field: jmeter_rs_results::ResultField::Assertion,
                },
            })?;
            append_assertion_result(result, assertion).map_err(|source| PipelineError::Result {
                sampler_id: package.sampler_id,
                source,
            })?;
        }

        let event = {
            let result = sample_context.result().ok_or(PipelineError::Result {
                sampler_id: package.sampler_id,
                source: ResultError::InvalidHierarchy {
                    field: jmeter_rs_results::ResultField::Assertion,
                },
            })?;
            SampleEvent::snapshot(
                result,
                sample_context.execution().run().clone(),
                sample_context.execution().thread().clone(),
                sample_context.execution().host().clone(),
                sample_context.execution().snapshot_variables(),
            )
            .map_err(|source| PipelineError::Result {
                sampler_id: package.sampler_id,
                source,
            })?
        };
        for (index, component) in package.listeners.iter().enumerate() {
            sample_context
                .execution_mut()
                .set_expression_field_namespace(
                    "runtime.plan.listener",
                    package.sampler_id,
                    &format!("listener:{index}"),
                );
            check_phase_deadline(&sample_context, package.sampler_id)?;
            sample_context
                .record(Phase::Listener, format!("listener[{index}]"))
                .map_err(|source| PipelineError::Listener {
                    node_id: package.sampler_id,
                    source,
                })?;
            match component.on_event(&event).await {
                Ok(()) => {}
                Err(ComponentError::Control(signal)) => {
                    sample_context.execution_mut().request_control(signal);
                    break;
                }
                Err(source) => {
                    return Err(PipelineError::Listener {
                        node_id: package.sampler_id,
                        source,
                    });
                }
            }
        }
        if let Some(result) = sample_context.result() {
            let signal = result_control_signal(result);
            sample_context.execution_mut().request_control(signal);
        }
        let result = sample_context.result.take();
        Ok(ExecutionReport {
            sampler_id: package.sampler_id,
            result,
            event: Some(event),
            sample_failure,
            signal: sample_context.execution().control_signal(),
            timer_delay: total_delay,
        })
    }
}

/// Attaches one assertion result and projects a failed/error assertion onto
/// the JMeter sample-level outcome.  Ordinary JMeter `SampleResult` does not
/// store an error counter: `getErrorCount()` derives the value as 0 or 1 from
/// `isSuccessful()`.  The result model owns that projection; this phase must
/// not overwrite an explicit count belonging to an aggregate/statistical
/// result.
fn append_assertion_result(
    result: &mut SampleResult,
    assertion: AssertionResult,
) -> jmeter_rs_results::Result<()> {
    let failed = matches!(
        assertion.outcome(),
        AssertionOutcome::Failure | AssertionOutcome::Error
    );
    result.add_assertion(assertion)?;
    if failed {
        result.set_successful(false);
    }
    Ok(())
}

fn check_phase_deadline(
    context: &SampleContext<'_>,
    sampler_id: NodeId,
) -> Result<(), PipelineError> {
    if context.execution().deadline_expired() {
        return Err(PipelineError::DeadlineExceeded { sampler_id });
    }
    Ok(())
}

fn result_control_signal(result: &SampleResult) -> ControlSignal {
    let mut signal = ControlSignal::Continue;
    if result.start_next_loop() {
        signal = signal.combine(ControlSignal::NextLoop);
    }
    if result.stop_thread() {
        signal = signal.combine(ControlSignal::StopThread);
    }
    if result.stop_test() {
        signal = signal.combine(ControlSignal::StopTestGraceful);
    }
    if result.stop_test_now() {
        signal = signal.combine(ControlSignal::StopTestImmediate);
    }
    if let Some(action) = result.logical_action() {
        signal = signal.combine(match action {
            LogicalAction::Continue => ControlSignal::Continue,
            LogicalAction::StartNextIteration => ControlSignal::NextLoop,
            LogicalAction::StopThread => ControlSignal::StopThread,
            LogicalAction::StopTest => ControlSignal::StopTestGraceful,
            LogicalAction::StopTestNow => ControlSignal::StopTestImmediate,
        });
    }
    signal
}

fn scale_timer_delay(
    delay: Duration,
    factor: f64,
    sampler_id: NodeId,
) -> Result<Duration, PipelineError> {
    if factor == 1.0 || delay.is_zero() {
        return Ok(delay);
    }
    let seconds = delay.as_secs_f64() * factor;
    if !seconds.is_finite() || seconds > Duration::MAX.as_secs_f64() {
        return Err(PipelineError::TimerOverflow { sampler_id });
    }
    Duration::try_from_secs_f64(seconds).map_err(|_| PipelineError::TimerOverflow { sampler_id })
}

fn update_result_timing(
    context: &mut SampleContext<'_>,
    start: ClockReading,
    end: ClockReading,
) -> Result<(), PipelineError> {
    let sampler_id = context.sampler_id;
    let elapsed = end
        .monotonic
        .checked_sub(start.monotonic)
        .ok_or(PipelineError::Result {
            sampler_id,
            source: ResultError::InvalidTiming {
                violation: jmeter_rs_results::TimingViolation::EndBeforeStart,
            },
        })?;
    let elapsed_millis = u64::try_from(elapsed.as_millis()).map_err(|_| PipelineError::Result {
        sampler_id,
        source: ResultError::Overflow {
            field: jmeter_rs_results::ResultField::Elapsed,
        },
    })?;
    let group_threads = context.execution().group_threads;
    let all_threads = context.execution().all_threads;
    let result = context.result_mut().ok_or(PipelineError::Result {
        sampler_id,
        source: ResultError::InvalidHierarchy {
            field: jmeter_rs_results::ResultField::Elapsed,
        },
    })?;
    if result.timestamp().is_none() {
        result.set_timestamp(Some(start.wall));
    }
    if result.start_time().is_none() {
        result
            .set_start_time(Some(start.wall))
            .map_err(|source| PipelineError::Result { sampler_id, source })?;
    }
    if result.end_time().is_none() {
        result
            .set_end_time(Some(end.wall))
            .map_err(|source| PipelineError::Result { sampler_id, source })?;
    }
    if result.elapsed().is_none() {
        result
            .set_elapsed(Some(ElapsedTime::from_millis(elapsed_millis)))
            .map_err(|source| PipelineError::Result { sampler_id, source })?;
    }
    if result.group_threads().is_none() {
        result.set_group_threads(group_threads);
    }
    if result.all_threads().is_none() {
        result.set_all_threads(all_threads);
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "the unit test uses expect only for values constructed in the test"
)]
mod tests {
    use super::*;

    #[test]
    fn sample_context_clone_isolated_from_borrowed_invocation() {
        let mut execution = ExecutionContext::new();
        execution.set_variable("scope", "original");
        let mut original = SampleContext::new(&mut execution, NodeId::new(1));
        original.set_request_value("header", "original");
        original.set_result(Some(SampleResult::new("original")));

        let mut clone = original.clone_for_user();
        clone.execution_mut().set_variable("scope", "clone");
        clone.set_request_value("header", "clone");
        clone
            .result_mut()
            .expect("cloned result")
            .set_label("clone");

        assert_eq!(
            original.execution().variable("scope"),
            Some("original".to_owned())
        );
        assert_eq!(original.request_value("header"), Some("original"));
        assert_eq!(original.result().map(SampleResult::label), Some("original"));
        assert_eq!(
            clone.execution().variable("scope"),
            Some("clone".to_owned())
        );
        assert_eq!(clone.request_value("header"), Some("clone"));
        assert_eq!(clone.result().map(SampleResult::label), Some("clone"));
    }

    #[test]
    fn assertion_failures_count_once_per_sample() {
        let mut result = SampleResult::new("assertions");
        result.set_successful(true);
        assert_eq!(result.error_count(), None);

        append_assertion_result(
            &mut result,
            AssertionResult::failed("first", Some("mismatch".to_owned())),
        )
        .expect("first assertion");
        append_assertion_result(
            &mut result,
            AssertionResult::errored("second", Some("evaluation error".to_owned())),
        )
        .expect("second assertion");
        append_assertion_result(&mut result, AssertionResult::passed("third"))
            .expect("third assertion");

        assert_eq!(result.assertions().len(), 3);
        assert!(!result.is_successful());
        assert_eq!(
            result.error_count(),
            Some(jmeter_rs_results::ErrorCount::new(1))
        );

        let mut preexisting = SampleResult::new("preexisting");
        preexisting.set_successful(true);
        preexisting.set_error_count(Some(jmeter_rs_results::ErrorCount::new(7)));
        append_assertion_result(&mut preexisting, AssertionResult::failed("failure", None))
            .expect("pre-existing assertion");
        assert_eq!(
            preexisting.error_count(),
            Some(jmeter_rs_results::ErrorCount::new(7))
        );
    }
}
