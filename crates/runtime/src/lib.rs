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
mod mutation;
mod observation;
mod plan_compiler;
mod progress;
mod result_router;
mod sample_monitor;
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
    CoordinationGeneration, CriticalSectionCoordinator, CriticalSectionError,
    DeterministicBarrierCoordinator, DeterministicCriticalSectionCoordinator,
    DeterministicSynchronizingCoordinator, DeterministicThroughputCoordinator,
};

pub use execution::{
    Assertion, AssertionFactory, CapabilityError, CapabilityFuture, Clock, ClockReading,
    CompiledPackages, ComponentError, ComponentFuture, Configuration, ConfigurationFactory,
    EmptyEnvironment, EmptyFileSystem, Environment, EpochClock, ExecutionContext,
    ExecutionPipeline, ExecutionReport, ExecutionTraceEvent, ExpressionStateCleanup, FileSystem,
    ImmediateSleeper, InitialVariables, InitialVariablesError, Listener, ListenerFactory,
    MAX_INITIAL_VARIABLE_NAME_BYTES, MAX_INITIAL_VARIABLE_TOTAL_BYTES,
    MAX_INITIAL_VARIABLE_VALUE_BYTES, MAX_INITIAL_VARIABLES, PackageCompileError, PackageCompiler,
    PackageLifecycle, PackageLifecycleFactory, Phase, PhaseTrace, PipelineError, PipelineFuture,
    Postprocessor, PostprocessorFactory, Preprocessor, PreprocessorFactory, RandomSource,
    RuntimeCapabilities, SampleContext, SampleFailure, SamplePackage, SamplePackageBuilder,
    Sampler, SamplerFactory, SamplerOutput, Sleeper, Timer, TimerFactory, ZeroRandom,
};

pub use adapters::{
    ADAPTER_CAPABILITIES, AdapterCapability, AdapterCapabilityRecord, AdapterConfigurationError,
    AdapterImplementationPath, AdapterUnavailable, AdapterUnavailableReason, BoundedFakeSampler,
    BoundedFakeTimer, CapturingListener, ContainsAssertion, ExpressionConfiguration,
    ExpressionPreprocessor, LiteralExtractor, MAX_ADAPTER_TEXT_BYTES, MAX_CAPTURED_EVENTS,
    MAX_FAKE_INVOCATIONS, MAX_LITERAL_CAPTURE_BYTES, UnsupportedAssertion,
    UnsupportedConfiguration, UnsupportedExtractor, UnsupportedListener, UnsupportedProcessor,
    UnsupportedSampler, adapter_capabilities,
};
pub use assertions::{
    AssertionLimits, DurationAssertion, MD5HexAssertion, Md5HexAssertion, PatternMode,
    ResponseAssertion, ResponseAssertionField, ResponseField, ResponsePatternMode, SizeAssertion,
    SizeComparison, SizeField, UnsupportedJsonAssertion, UnsupportedNativeAssertion, XMLAssertion,
    XPathAssertion, XPathOptions, XmlAssertion,
};
pub use capabilities::{
    AdmissionMode, CapabilityIdentityError, CapabilityIdentityErrorCode, Digest32,
    ImplementationPath, ImplementationPathFamily, ImplementationPathIdentity,
    ImplementationPathManifest, ManifestError, NegotiatedCapability, PlanAdmission,
    PlanAdmissionError, ProfileIdentity, ProviderIdentity, RuntimeCapabilitySet, SourceIdentity,
    UnavailableReason, UnavailableReasonCode, VersionedCapability,
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
pub use mutation::{
    AllowlistedFileResolver, BoundedBytes, BoundedText, ContextGeneration, ControlPatch,
    DEFAULT_MAX_DIAGNOSTIC_BYTES, DEFAULT_MAX_DIAGNOSTICS, DEFAULT_MAX_MUTATIONS,
    DEFAULT_MAX_OUTPUT_BYTES, DEFAULT_MAX_OUTPUTS, DEFAULT_MAX_REQUEST_BYTES,
    DEFAULT_MAX_REQUEST_HEADERS, DEFAULT_MAX_REQUEST_PATH_SEGMENTS,
    DEFAULT_MAX_REQUEST_QUERY_FIELDS, DEFAULT_MAX_RESPONSE_BYTES,
    DEFAULT_MAX_RESPONSE_METADATA_BYTES, DEFAULT_MAX_RESULT_DEPTH, DEFAULT_MAX_RESULT_NODES,
    DEFAULT_MAX_VALUE_BYTES, EncodedField, FileCapability, HeaderOperation, InvocationCommit,
    InvocationDelta, InvocationGeneration, InvocationSnapshot, MutationDiagnostic, MutationError,
    MutationErrorCode, MutationLimits, MutationLimitsParts, Presence, PropertyMutation, QueryField,
    RequestAuthority, RequestDigest, RequestGeneration, RequestHeader, RequestPatch,
    RequestPatchError, RequestState, RequestStateError, RequestStateParts, ResponseMetadata,
    ResponseResolveError, ResponseResolver, ResponseSource, ResponseView, ResultPatch,
    SampleResultResponseResolver, StagedInvocation, VariableMutation,
};
pub use observation::{
    ObservationError, RunObservationPolicyV1, RunObservationSummaryV1, RunObservationTerminalState,
    RunObservationTraceV1,
};
pub use plan_compiler::{
    CompiledPlanDraft, CompiledThreadGroupDraft, IndexedCategory, IndexedNode, PlanCompileError,
    PlanCompileLimits, PlanCompiler, PlanIndex, PlanLimitKind, PlanPathContext, PlanPathManifest,
    PlanSourceView, SemanticSource, SourceRef,
};
pub use progress::{
    DEFAULT_WAIT_ITEM_DIAGNOSTIC_BYTES, DEFAULT_WAIT_REGISTRATION_CAPACITY,
    DEFAULT_WAIT_TOTAL_DIAGNOSTIC_BYTES, MAX_OPAQUE_WAIT_IDENTITY_BYTES, OpaqueWaitIdentity,
    ProgressError, ProgressHandle, ProgressOwner, ProgressSnapshot, ProgressTerminalState,
    WaitIdentityError, WaitNotification, WaitNotificationCallback, WaitNotificationKind,
    WaitNotifier, WaitOwnerClass, WaitRegistration, WaitRegistrationId, WaitRegistrationSpec,
    WaitRegistry, WaitRegistryConfig, WaitRegistryError, WaitRegistryHandle, WaitSnapshot,
};
pub use result_router::{
    AdmissionOutcome, AttemptOrdinal, BoundedDiagnostic, BudgetError, DeliveryKey, DeliveryLease,
    DurabilityAck, DurabilityBoundary, FailureReason, FullPolicy, LegacyResultEnvelope,
    LegacyResultRouter, LegacySinkId, MonotonicClock, NotAdmittedReason, PlanDomain,
    QualifiedSinkId, ResultClockError, ResultDeliveryBudget, ResultDeliveryBudgetConfig,
    ResultEnvelope, ResultEventMetadata, ResultFinalizationLease, ResultMonotonicClock,
    ResultOperationId, ResultOperationKind, ResultOperationLease, ResultOperationScope,
    ResultOperationWindows, ResultOrigin, ResultRouter, ResultRouterError, ResultRouterFuture,
    ResultRouterV3, ResultSink, ResultSinkFuture, ResultSinkSpec, ResultWaitError,
    ResultWaitRegistrar, ResultWaitRegistration, ResultWaitRegistrationHandle, ResultWaitSpec,
    RetryBudget, RouterPhase, RouterStats, RunGeneration, RunOperationBudget, RunSequence,
    SampleIdentity, SinkError, SinkId, SinkLimits, SinkPlanGeneration, SinkQueueStats,
    TypedAdmissionOutcome, TypedResultEnvelope, TypedResultOrigin, TypedResultRouter,
    TypedResultRouterAdapter, TypedRouterError, TypedRouterIdentity, TypedRouterPhase, TypedRunId,
    TypedRunSequence, TypedSampleId, TypedSinkAdapter, TypedSinkError, TypedSinkFuture,
    TypedSinkPlan, UnavailableResultWaitRegistrar, UserIdentity, WorkerGeneration, WorkerId,
};
pub use sample_monitor::{
    DEFAULT_MAX_SAMPLE_DIAGNOSTIC_BYTES, DEFAULT_MAX_SAMPLE_DIAGNOSTICS,
    DEFAULT_MAX_SAMPLE_MONITORS, DEFAULT_MAX_SAMPLE_REGISTRATIONS, InterruptActivationError,
    InterruptEndOutcome, InterruptOutcome, InterruptReason, InterruptRequest,
    MAX_SAMPLE_MONITOR_CLASS_BYTES, MAX_SAMPLE_MONITOR_DETAIL_BYTES, MAX_SAMPLE_MONITOR_PATH_NODES,
    MonitorEndStatus, RegistrationError, RegistrationId, RegistrationRetireOutcome,
    RegistrationRetirer, SampleInvocationIdentity, SampleMonitor, SampleMonitorAccounting,
    SampleMonitorCleanup, SampleMonitorCleanupFailure, SampleMonitorCleanupPhase,
    SampleMonitorDiagnostic, SampleMonitorEndReport, SampleMonitorError, SampleMonitorFactory,
    SampleMonitorFactorySpec, SampleMonitorFuture, SampleMonitorHookContext,
    SampleMonitorIdentityError, SampleMonitorInstances, SampleMonitorLifecycleError,
    SampleMonitorLimits, SampleMonitorMetadata, SampleMonitorPlan, SampleMonitorRegistration,
    SampleMonitorRegistrationRegistrar, SampleMonitorRegistrationRequest, SampleMonitorStart,
    SampleMonitorStartReport, SamplerInterrupt, SamplerInterruptCapability, SamplerInterruptError,
    SamplerInterruptFactory, SamplerInterruptFuture, SamplerInterruptHandle,
};
pub use scheduler::{
    CancellationToken, Deadline, DeadlineFuture, DeterministicScheduler, ImmediateScheduler,
    MonotonicInstant, ScheduleWindow, ScheduledWake, Scheduler, SchedulerError, SchedulerFuture,
    WakeRegistration, ready,
};
pub use scope::{
    CompiledScopePlan, ComponentAvailability, ComponentBinding, ComponentCategory,
    ComponentRegistry, ResultCollectorKind, ScopeCompileError, ScopeCompiler, ScopeComponent,
    ScopeFactoryError, ScopeLimits, ScopeNode, ScopePackageAssembler, ScopePlan, TimerAlias,
    TimerBinding, UnsupportedComponent, builtin_timer_aliases,
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
