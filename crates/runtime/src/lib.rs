// SPDX-License-Identifier: Apache-2.0
//! Executor-neutral plan compilation and virtual-user state machines.
//!
//! Runtime behavior is built around explicit capabilities at the application
//! edge. The controller module deliberately has no scheduler, clock,
//! transport, or result dependency: it only advances an ordered executable
//! tree and reports typed selections, completion, cancellation, and resource
//! failures.

mod adapters;
mod assertions;
mod capabilities;
mod compiler;
mod controllers;
mod coordination;
mod execution;
mod lifecycle;
mod logic;
mod plan_compiler;
mod result_router;
mod scheduler;
mod scope;
mod timers;

pub use compiler::{ComponentFactoryRegistry, FactoryComponent, ScopeComponentFactory};

pub use controllers::{
    Cancellation, ControlSignal, ControllerCursor, ControllerError, ControllerKind,
    ControllerLimits, ControllerNode, ControllerOutcome, ControllerProgram, ControllerRunner,
    ControllerStep, ElementId, ExecutionTrace, LoopCount, RunBudget, SampleSelection, StepBudget,
};

pub use coordination::{
    CriticalSectionCoordinator, CriticalSectionError, DeterministicCriticalSectionCoordinator,
};

pub use execution::{
    Assertion, AssertionFactory, CapabilityError, CapabilityFuture, Clock, ClockReading,
    CompiledPackages, ComponentError, ComponentFuture, Configuration, ConfigurationFactory,
    EmptyEnvironment, EmptyFileSystem, Environment, EpochClock, ExecutionContext,
    ExecutionPipeline, ExecutionReport, ExecutionTraceEvent, ExpressionStateCleanup, FileSystem,
    ImmediateSleeper, Listener, ListenerFactory, PackageCompileError, PackageCompiler,
    PackageLifecycle, PackageLifecycleFactory, Phase, PhaseTrace, PipelineError, PipelineFuture,
    Postprocessor, PostprocessorFactory, Preprocessor, PreprocessorFactory, RandomSource,
    RuntimeCapabilities, SampleContext, SampleFailure, SamplePackage, SamplePackageBuilder,
    Sampler, SamplerFactory, SamplerOutput, Sleeper, Timer, TimerFactory, ZeroRandom,
};

pub use adapters::{
    CapturingListener, ContainsAssertion, ExpressionConfiguration, ExpressionPreprocessor,
    LiteralExtractor, UnsupportedAssertion, UnsupportedConfiguration, UnsupportedExtractor,
    UnsupportedListener, UnsupportedProcessor, UnsupportedSampler,
};
pub use assertions::{
    AssertionLimits, DurationAssertion, MD5HexAssertion, Md5HexAssertion, PatternMode,
    ResponseAssertion, ResponseAssertionField, ResponseField, ResponsePatternMode, SizeAssertion,
    SizeComparison, SizeField, UnsupportedJsonAssertion, UnsupportedNativeAssertion, XMLAssertion,
    XPathAssertion, XPathOptions, XmlAssertion,
};
pub use capabilities::{
    AdmissionMode, CapabilityIdentityError, CapabilityIdentityErrorCode,
    Digest32, ImplementationPath, ImplementationPathFamily, ImplementationPathIdentity,
    ImplementationPathManifest, ManifestError, NegotiatedCapability, PlanAdmission,
    PlanAdmissionError, ProfileIdentity, ProviderIdentity, RuntimeCapabilitySet,
    SourceIdentity, UnavailableReason, UnavailableReasonCode, VersionedCapability,
};
pub use lifecycle::{
    EngineError, EngineEvent, EngineMode, EnginePlan, EngineReport, GroupKind, GroupSchedule,
    IterationState, RampSchedule, RuntimeEngine, RuntimeEngineFuture, SampleErrorPolicy,
    ThreadGroupPlan, VirtualUser,
};
pub use logic::{
    LogicCondition, LogicControllerError, LogicCursor, LogicInput, LogicLimits, LogicNode,
    LogicProgram, LogicRunner, LogicSelection, LogicSharedState, LogicStep, SwitchSelection,
    ThroughputMode, TransactionInfo,
};
pub use plan_compiler::{
    CompiledPlanDraft, CompiledThreadGroupDraft, IndexedCategory, IndexedNode, PlanCompileError,
    PlanCompileLimits, PlanCompiler, PlanIndex, PlanSourceView, SemanticSource, SourceRef,
};
pub use result_router::{
    AdmissionOutcome, ResultEnvelope, ResultEventMetadata, ResultOrigin, ResultRouter,
    ResultRouterError, ResultRouterFuture, ResultSink, ResultSinkFuture, ResultSinkSpec,
    RouterPhase, RouterStats, RunSequence, SampleIdentity, SinkError, SinkId, SinkLimits,
    SinkQueueStats, UserIdentity,
};
pub use scheduler::{
    CancellationToken, Deadline, DeadlineFuture, DeterministicScheduler, ImmediateScheduler,
    MonotonicInstant, ScheduledWake, Scheduler, SchedulerError, SchedulerFuture, WakeRegistration,
    ready,
};
pub use scope::{
    CompiledScopePlan, ComponentBinding, ComponentCategory, ComponentRegistry, ResultCollectorKind,
    ScopeCompileError, ScopeCompiler, ScopeComponent, ScopeFactoryError, ScopeLimits, ScopeNode,
    ScopePackageAssembler, ScopePlan, TimerAlias, TimerBinding, UnsupportedComponent,
    builtin_timer_aliases,
};
pub use timers::{
    ConstantThroughputCalculationMode, ConstantThroughputMode, ConstantThroughputTimer,
    ConstantTimer, GaussianRandomTimer, PoissonRandomTimer, PreciseThroughputTimer,
    SynchronizingCoordinator, SynchronizingOutcome, SynchronizingRequest, SynchronizingTimer,
    ThroughputCoordinator, ThroughputRequest, UniformRandomTimer, UnsupportedTimer,
};

/// Alias for an executor-neutral assertion component.
pub use execution::Assertion as AssertionComponent;
/// Alias matching JMeter's configuration-element terminology.
pub use execution::Configuration as ConfigElement;
/// Alias for an executor-neutral listener component.
pub use execution::Listener as SampleListener;
/// Alias matching common component naming in adapters.
pub use execution::Postprocessor as PostProcessor;
/// Alias matching common component naming in adapters.
pub use execution::Preprocessor as PreProcessor;
/// Alias for an executor-neutral sampler component.
pub use execution::Sampler as SamplerComponent;
