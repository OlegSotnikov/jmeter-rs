// SPDX-License-Identifier: Apache-2.0
//! Source-ordered, executor-neutral listener effects.
//!
//! This module deliberately has no dependency on an executor, result sink,
//! transport, filesystem, or JVM.  It is the semantic boundary described by
//! Decisions 0003 (revision 5) and 0016: a listener program walks one ordered
//! list, native effects commit typed proposals to a generation-tracked live
//! result, observers receive immutable revisions at their source positions,
//! and control is consumed only after the list and all admissions finish.
//!
//! The module is currently unregistered by `runtime::lib`; that is intentional
//! while the lifecycle and result-router owners migrate to this contract.  It
//! can therefore also be compiled directly with `rustc --test` as a strict,
//! dependency-free harness.

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![deny(clippy::todo, clippy::unimplemented)]

use std::fmt;
use std::num::{NonZeroU32, NonZeroU64};

/// Hard upper bound for one compiled listener program.
pub const MAX_PROGRAM_ENTRIES: usize = 4_096;
/// Hard upper bound for immutable observer revisions retained by one run.
pub const MAX_REVISIONS: usize = 16_384;
/// Hard upper bound for diagnostics retained by one run.
pub const MAX_DIAGNOSTICS: usize = 4_096;
/// Hard upper bound for the bytes in one diagnostic detail.
pub const MAX_DIAGNOSTIC_BYTES: usize = 4_096;
/// Hard upper bound for all diagnostic detail bytes retained by one run.
pub const MAX_DIAGNOSTIC_TOTAL_BYTES: usize = 1_048_576;

// ---------------------------------------------------------------------------
// Domain-qualified identities
// ---------------------------------------------------------------------------

/// Stable errors raised while constructing domain-qualified identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    /// An identity's numeric representation was zero.
    Zero { kind: IdentityKind },
    /// A plan domain contained no entropy and is therefore not a domain.
    EmptyPlanDomain,
}

impl IdentityError {
    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Zero { .. } => "listener.identity.zero",
            Self::EmptyPlanDomain => "listener.identity.empty-plan-domain",
        }
    }
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for IdentityError {}

/// The typed identity family associated with an identity error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityKind {
    /// A plan node identity.
    Node,
    /// A listener instance identity.
    ListenerInstance,
    /// A run identity.
    Run,
    /// A worker identity.
    Worker,
    /// A virtual-user identity.
    User,
    /// A sample identity.
    Sample,
    /// A source position ordinal.
    SourcePosition,
    /// An observer occurrence sequence.
    RevisionSequence,
    /// A live result generation.
    ResultGeneration,
}

/// A domain-qualified immutable executable-plan identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PlanDomain {
    bytes: [u8; 32],
}

impl PlanDomain {
    /// Creates a plan domain, rejecting an all-zero placeholder.
    pub fn new(bytes: [u8; 32]) -> Result<Self, IdentityError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(IdentityError::EmptyPlanDomain);
        }
        Ok(Self { bytes })
    }

    /// Returns the canonical domain bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.bytes
    }
}

/// A nonzero plan-local node number.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NodeId(NonZeroU64);

impl NodeId {
    /// Creates a node identity from a nonzero number.
    pub fn new(value: u64) -> Result<Self, IdentityError> {
        NonZeroU64::new(value).map(Self).ok_or(IdentityError::Zero {
            kind: IdentityKind::Node,
        })
    }

    /// Returns the numeric node identity.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// A plan node reference whose number cannot alias another plan domain.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PlanNodeRef {
    domain: PlanDomain,
    node: NodeId,
}

impl PlanNodeRef {
    /// Creates a domain-qualified node reference.
    #[must_use]
    pub const fn new(domain: PlanDomain, node: NodeId) -> Self {
        Self { domain, node }
    }

    /// Returns the plan domain.
    #[must_use]
    pub const fn domain(self) -> PlanDomain {
        self.domain
    }

    /// Returns the plan-local node identity.
    #[must_use]
    pub const fn node(self) -> NodeId {
        self.node
    }
}

macro_rules! nonzero_identity {
    (
        $(#[$meta:meta])* $name:ident, $kind:expr
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(NonZeroU64);

        impl $name {
            /// Creates this identity from a nonzero number.
            pub fn new(value: u64) -> Result<Self, IdentityError> {
                NonZeroU64::new(value)
                    .map(Self)
                    .ok_or(IdentityError::Zero { kind: $kind })
            }

            /// Returns the numeric identity.
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0.get()
            }
        }
    };
}

nonzero_identity!(
    /// A listener instance identity distinct from its source node.
    ListenerInstanceId,
    IdentityKind::ListenerInstance
);
nonzero_identity!(
    /// A run identity.
    RunId,
    IdentityKind::Run
);
nonzero_identity!(
    /// A worker identity.
    WorkerId,
    IdentityKind::Worker
);
nonzero_identity!(
    /// A virtual-user identity.
    UserId,
    IdentityKind::User
);
nonzero_identity!(
    /// A run-qualified sample identity.
    SampleId,
    IdentityKind::Sample
);
nonzero_identity!(
    /// A checked live-result generation.
    ResultGeneration,
    IdentityKind::ResultGeneration
);

/// A source position in the immutable executable plan.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SourcePosition {
    ordinal: NonZeroU32,
    node: PlanNodeRef,
}

impl SourcePosition {
    /// Creates a one-based source position.
    pub fn new(ordinal: u32, node: PlanNodeRef) -> Result<Self, IdentityError> {
        NonZeroU32::new(ordinal)
            .map(|ordinal| Self { ordinal, node })
            .ok_or(IdentityError::Zero {
                kind: IdentityKind::SourcePosition,
            })
    }

    /// Returns the one-based source ordinal.
    #[must_use]
    pub const fn ordinal(self) -> u32 {
        self.ordinal.get()
    }

    /// Returns the source node reference.
    #[must_use]
    pub const fn node(self) -> PlanNodeRef {
        self.node
    }
}

/// An identity for one run-qualified sample occurrence.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SampleIdentity {
    run: RunId,
    sample: SampleId,
}

impl SampleIdentity {
    /// Creates a run-qualified sample identity.
    #[must_use]
    pub const fn new(run: RunId, sample: SampleId) -> Self {
        Self { run, sample }
    }

    /// Returns the run identity.
    #[must_use]
    pub const fn run(self) -> RunId {
        self.run
    }

    /// Returns the sample identity.
    #[must_use]
    pub const fn sample(self) -> SampleId {
        self.sample
    }
}

/// A parent sample reference for a synthetic transaction result.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ParentSampleRef {
    identity: SampleIdentity,
}

impl ParentSampleRef {
    /// Creates a parent sample reference.
    #[must_use]
    pub const fn new(identity: SampleIdentity) -> Self {
        Self { identity }
    }

    /// Returns the referenced sample.
    #[must_use]
    pub const fn identity(self) -> SampleIdentity {
        self.identity
    }
}

/// A source-qualified result origin.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SampleOrigin {
    /// A regular sampler result.
    Sampler {
        /// Source sampler identity.
        sampler: PlanNodeRef,
    },
    /// A transaction-controller aggregate result.
    Transaction {
        /// Source transaction-controller identity.
        controller: PlanNodeRef,
        /// Optional parent sample that caused the aggregate notification.
        parent: Option<ParentSampleRef>,
    },
}

impl SampleOrigin {
    /// Returns the source node that created this result.
    #[must_use]
    pub const fn source(self) -> PlanNodeRef {
        match self {
            Self::Sampler { sampler } => sampler,
            Self::Transaction { controller, .. } => controller,
        }
    }

    /// Returns whether this is an aggregate synthetic transaction origin.
    #[must_use]
    pub const fn is_transaction(self) -> bool {
        matches!(self, Self::Transaction { .. })
    }
}

/// Which package emitted a listener notification.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NotificationScope {
    /// A normal sampler notification.
    Ordinary,
    /// A child result under an active transaction package.
    TransactionChild {
        /// Listener instance owned by the aggregate transaction package.
        aggregate_instance: ListenerInstanceId,
    },
    /// The aggregate transaction notification itself.
    TransactionAggregate {
        /// Listener/controller instance that owns the aggregate package.
        controller_instance: ListenerInstanceId,
    },
}

/// Metadata needed to identify one listener notification.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SampleNotification {
    run: RunId,
    worker: WorkerId,
    user: UserId,
    sample: SampleIdentity,
    origin: SampleOrigin,
    scope: NotificationScope,
}

impl SampleNotification {
    /// Creates a notification with explicit typed identities.
    #[must_use]
    pub const fn new(
        run: RunId,
        worker: WorkerId,
        user: UserId,
        sample: SampleIdentity,
        origin: SampleOrigin,
        scope: NotificationScope,
    ) -> Self {
        Self {
            run,
            worker,
            user,
            sample,
            origin,
            scope,
        }
    }

    /// Returns the run identity.
    #[must_use]
    pub const fn run(self) -> RunId {
        self.run
    }

    /// Returns the worker identity.
    #[must_use]
    pub const fn worker(self) -> WorkerId {
        self.worker
    }

    /// Returns the virtual-user identity.
    #[must_use]
    pub const fn user(self) -> UserId {
        self.user
    }

    /// Returns the sample identity.
    #[must_use]
    pub const fn sample(self) -> SampleIdentity {
        self.sample
    }

    /// Returns the source origin.
    #[must_use]
    pub const fn origin(self) -> SampleOrigin {
        self.origin
    }

    /// Returns the notification package scope.
    #[must_use]
    pub const fn scope(self) -> NotificationScope {
        self.scope
    }
}

/// A one-based observer occurrence sequence assigned at capture time.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RevisionSequence(NonZeroU64);

impl RevisionSequence {
    /// Creates a checked sequence number.
    pub fn new(value: u64) -> Result<Self, IdentityError> {
        NonZeroU64::new(value).map(Self).ok_or(IdentityError::Zero {
            kind: IdentityKind::RevisionSequence,
        })
    }

    /// Returns the sequence number.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

// ---------------------------------------------------------------------------
// Typed live result and control state
// ---------------------------------------------------------------------------

/// The explicit success state visible to listener filters and effects.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ResultStatus {
    /// The result completed successfully.
    Success,
    /// The result is unsuccessful.
    Failure,
    /// The result has no success value yet.
    Unknown,
}

/// A loop-local action kept separate from run cancellation severity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LoopAction {
    /// Start the next iteration of the current loop.
    StartNextIterationOfCurrentLoop,
    /// Break the current loop.
    BreakCurrentLoop,
}

/// Typed, independent result-control fields.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ControlState {
    stop_thread: bool,
    stop_test: bool,
    stop_test_now: bool,
    start_next_loop: bool,
    start_next_iteration: bool,
    break_current_loop: bool,
}

impl ControlState {
    /// Creates an empty control state.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            stop_thread: false,
            stop_test: false,
            stop_test_now: false,
            start_next_loop: false,
            start_next_iteration: false,
            break_current_loop: false,
        }
    }

    /// Returns whether the current thread should stop.
    #[must_use]
    pub const fn stop_thread(self) -> bool {
        self.stop_thread
    }

    /// Returns whether the test should stop gracefully.
    #[must_use]
    pub const fn stop_test(self) -> bool {
        self.stop_test
    }

    /// Returns whether the test should stop immediately.
    #[must_use]
    pub const fn stop_test_now(self) -> bool {
        self.stop_test_now
    }

    /// Returns whether the next thread-group loop should begin.
    #[must_use]
    pub const fn start_next_loop(self) -> bool {
        self.start_next_loop
    }

    /// Returns whether the current loop should start its next iteration.
    #[must_use]
    pub const fn start_next_iteration(self) -> bool {
        self.start_next_iteration
    }

    /// Returns whether the current loop should break.
    #[must_use]
    pub const fn break_current_loop(self) -> bool {
        self.break_current_loop
    }

    /// Returns a copy with the stop-thread field set.
    #[must_use]
    pub const fn with_stop_thread(mut self, value: bool) -> Self {
        self.stop_thread = value;
        self
    }

    /// Returns a copy with the graceful-stop-test field set.
    #[must_use]
    pub const fn with_stop_test(mut self, value: bool) -> Self {
        self.stop_test = value;
        self
    }

    /// Returns a copy with the immediate-stop-test field set.
    #[must_use]
    pub const fn with_stop_test_now(mut self, value: bool) -> Self {
        self.stop_test_now = value;
        self
    }

    /// Returns a copy with the next-thread-loop field set.
    #[must_use]
    pub const fn with_start_next_loop(mut self, value: bool) -> Self {
        self.start_next_loop = value;
        self
    }

    /// Returns a copy with the current-loop next-iteration field set.
    #[must_use]
    pub const fn with_start_next_iteration(mut self, value: bool) -> Self {
        self.start_next_iteration = value;
        self
    }

    /// Returns a copy with the current-loop break field set.
    #[must_use]
    pub const fn with_break_current_loop(mut self, value: bool) -> Self {
        self.break_current_loop = value;
        self
    }

    /// Returns one loop-local action when exactly one is set.
    #[must_use]
    pub const fn loop_action(self) -> Option<LoopAction> {
        match (self.start_next_iteration, self.break_current_loop) {
            (true, false) => Some(LoopAction::StartNextIterationOfCurrentLoop),
            (false, true) => Some(LoopAction::BreakCurrentLoop),
            // Both flags remain independently observable.  The controller
            // owns any profile-specific conflict handling, so this helper is
            // intentionally conservative and reports no single action.
            (true, true) | (false, false) => None,
        }
    }

    fn apply_patch(&mut self, patch: ControlPatch) {
        if let Some(value) = patch.stop_thread {
            self.stop_thread = value;
        }
        if let Some(value) = patch.stop_test {
            self.stop_test = value;
        }
        if let Some(value) = patch.stop_test_now {
            self.stop_test_now = value;
        }
        if let Some(value) = patch.start_next_loop {
            self.start_next_loop = value;
        }
        if let Some(value) = patch.start_next_iteration {
            self.start_next_iteration = value;
        }
        if let Some(value) = patch.break_current_loop {
            self.break_current_loop = value;
        }
    }

    fn clear(&mut self) {
        *self = Self::empty();
    }
}

/// Typed result fields that a native effect may propose atomically.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ResultPatch {
    status: Option<ResultStatus>,
    ignored: Option<bool>,
    control: ControlPatch,
}

impl ResultPatch {
    /// Creates an empty typed patch.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            status: None,
            ignored: None,
            control: ControlPatch::empty(),
        }
    }

    /// Sets a replacement success status.
    #[must_use]
    pub const fn with_status(mut self, status: ResultStatus) -> Self {
        self.status = Some(status);
        self
    }

    /// Sets the ignored field.
    #[must_use]
    pub const fn with_ignored(mut self, ignored: bool) -> Self {
        self.ignored = Some(ignored);
        self
    }

    /// Replaces the typed control patch.
    #[must_use]
    pub const fn with_control(mut self, control: ControlPatch) -> Self {
        self.control = control;
        self
    }

    /// Returns the proposed status, if any.
    #[must_use]
    pub const fn status(self) -> Option<ResultStatus> {
        self.status
    }

    /// Returns the proposed ignored value, if any.
    #[must_use]
    pub const fn ignored(self) -> Option<bool> {
        self.ignored
    }

    /// Returns the typed control patch.
    #[must_use]
    pub const fn control(self) -> ControlPatch {
        self.control
    }
}

/// Typed optional updates to independent result-control fields.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ControlPatch {
    stop_thread: Option<bool>,
    stop_test: Option<bool>,
    stop_test_now: Option<bool>,
    start_next_loop: Option<bool>,
    start_next_iteration: Option<bool>,
    break_current_loop: Option<bool>,
}

impl ControlPatch {
    /// Creates an empty control patch.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            stop_thread: None,
            stop_test: None,
            stop_test_now: None,
            start_next_loop: None,
            start_next_iteration: None,
            break_current_loop: None,
        }
    }

    /// Sets the stop-thread field.
    #[must_use]
    pub const fn with_stop_thread(mut self, value: bool) -> Self {
        self.stop_thread = Some(value);
        self
    }

    /// Sets the graceful-stop-test field.
    #[must_use]
    pub const fn with_stop_test(mut self, value: bool) -> Self {
        self.stop_test = Some(value);
        self
    }

    /// Sets the immediate-stop-test field.
    #[must_use]
    pub const fn with_stop_test_now(mut self, value: bool) -> Self {
        self.stop_test_now = Some(value);
        self
    }

    /// Sets the next-thread-loop field.
    #[must_use]
    pub const fn with_start_next_loop(mut self, value: bool) -> Self {
        self.start_next_loop = Some(value);
        self
    }

    /// Sets the current-loop next-iteration field.
    #[must_use]
    pub const fn with_start_next_iteration(mut self, value: bool) -> Self {
        self.start_next_iteration = Some(value);
        self
    }

    /// Sets the current-loop break field.
    #[must_use]
    pub const fn with_break_current_loop(mut self, value: bool) -> Self {
        self.break_current_loop = Some(value);
        self
    }

    /// Returns the stop-thread update.
    #[must_use]
    pub const fn stop_thread(self) -> Option<bool> {
        self.stop_thread
    }

    /// Returns the graceful-stop-test update.
    #[must_use]
    pub const fn stop_test(self) -> Option<bool> {
        self.stop_test
    }

    /// Returns the immediate-stop-test update.
    #[must_use]
    pub const fn stop_test_now(self) -> Option<bool> {
        self.stop_test_now
    }

    /// Returns the next-thread-loop update.
    #[must_use]
    pub const fn start_next_loop(self) -> Option<bool> {
        self.start_next_loop
    }

    /// Returns the current-loop next-iteration update.
    #[must_use]
    pub const fn start_next_iteration(self) -> Option<bool> {
        self.start_next_iteration
    }

    /// Returns the current-loop break update.
    #[must_use]
    pub const fn break_current_loop(self) -> Option<bool> {
        self.break_current_loop
    }
}

/// A live result whose generation advances only on an atomic committed patch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveResult {
    generation: ResultGeneration,
    status: ResultStatus,
    ignored: bool,
    synthetic: bool,
    control: ControlState,
}

impl LiveResult {
    /// Creates a normal result at generation one.
    #[must_use]
    pub fn new(status: ResultStatus) -> Self {
        Self {
            generation: ResultGeneration(NonZeroU64::MIN),
            status,
            ignored: false,
            synthetic: false,
            control: ControlState::empty(),
        }
    }

    /// Creates a result with explicit initial metadata and generation.
    pub fn from_parts(
        generation: ResultGeneration,
        status: ResultStatus,
        ignored: bool,
        synthetic: bool,
        control: ControlState,
    ) -> Self {
        Self {
            generation,
            status,
            ignored,
            synthetic,
            control,
        }
    }

    /// Returns the current live generation.
    #[must_use]
    pub const fn generation(&self) -> ResultGeneration {
        self.generation
    }

    /// Returns the current typed status.
    #[must_use]
    pub const fn status(&self) -> ResultStatus {
        self.status
    }

    /// Returns whether this result is ignored.
    #[must_use]
    pub const fn ignored(&self) -> bool {
        self.ignored
    }

    /// Returns whether this result is a synthetic aggregate.
    #[must_use]
    pub const fn synthetic(&self) -> bool {
        self.synthetic
    }

    /// Returns a copy marked as a synthetic transaction result.
    #[must_use]
    pub const fn with_synthetic(mut self, synthetic: bool) -> Self {
        self.synthetic = synthetic;
        self
    }

    /// Captures an immutable revision of the current live state.
    #[must_use]
    pub fn snapshot(&self) -> ResultRevision {
        ResultRevision {
            generation: self.generation,
            status: self.status,
            ignored: self.ignored,
            synthetic: self.synthetic,
            control: self.control,
        }
    }

    fn commit(
        &mut self,
        base: ResultGeneration,
        patch: ResultPatch,
    ) -> Result<(), ListenerProgramError> {
        if self.generation != base {
            return Err(ListenerProgramError::StaleEffect {
                expected: self.generation,
                actual: base,
            });
        }

        let next_generation = self
            .generation
            .get()
            .checked_add(1)
            .and_then(|value| ResultGeneration::new(value).ok())
            .ok_or(ListenerProgramError::GenerationOverflow {
                generation: self.generation,
            })?;

        // Build a complete candidate before changing `self`; a rejected
        // patch cannot leave one field applied and another field untouched.
        let mut candidate = self.clone();
        candidate.generation = next_generation;
        if let Some(status) = patch.status {
            candidate.status = status;
        }
        if let Some(ignored) = patch.ignored {
            candidate.ignored = ignored;
        }
        candidate.control.apply_patch(patch.control);
        *self = candidate;
        Ok(())
    }

    fn consume_control(&mut self) -> ConsumedControl {
        let consumed = ConsumedControl::from_state(self.control);
        self.control.clear();
        consumed
    }
}

/// An immutable result revision captured from the live result.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ResultRevision {
    generation: ResultGeneration,
    status: ResultStatus,
    ignored: bool,
    synthetic: bool,
    control: ControlState,
}

impl ResultRevision {
    /// Returns the generation visible at capture time.
    #[must_use]
    pub const fn generation(self) -> ResultGeneration {
        self.generation
    }

    /// Returns the captured status.
    #[must_use]
    pub const fn status(self) -> ResultStatus {
        self.status
    }

    /// Returns whether the captured result was ignored.
    #[must_use]
    pub const fn ignored(self) -> bool {
        self.ignored
    }

    /// Returns whether the captured result was synthetic.
    #[must_use]
    pub const fn synthetic(self) -> bool {
        self.synthetic
    }

    /// Returns the independent captured control fields.
    #[must_use]
    pub const fn control(self) -> ControlState {
        self.control
    }
}

/// The global severity consumed after all listener entries have run.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ControlSeverity {
    /// Continue the current execution flow.
    #[default]
    Continue,
    /// Start the next thread-group loop.
    StartNextLoop,
    /// Stop the current virtual user thread.
    StopThread,
    /// Gracefully stop the test.
    StopTest,
    /// Immediately stop the test.
    StopTestNow,
}

/// The final control state consumed after source-ordered notification.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ConsumedControl {
    severity: ControlSeverity,
    stop_thread: bool,
    stop_test: bool,
    stop_test_now: bool,
    start_next_loop: bool,
    start_next_iteration: bool,
    break_current_loop: bool,
}

impl ConsumedControl {
    fn from_state(state: ControlState) -> Self {
        let severity = if state.stop_test_now {
            ControlSeverity::StopTestNow
        } else if state.stop_test {
            ControlSeverity::StopTest
        } else if state.stop_thread {
            ControlSeverity::StopThread
        } else if state.start_next_loop {
            ControlSeverity::StartNextLoop
        } else {
            ControlSeverity::Continue
        };
        Self {
            severity,
            stop_thread: state.stop_thread,
            stop_test: state.stop_test,
            stop_test_now: state.stop_test_now,
            start_next_loop: state.start_next_loop,
            start_next_iteration: state.start_next_iteration,
            break_current_loop: state.break_current_loop,
        }
    }

    /// Returns the severity-ordered global control.
    #[must_use]
    pub const fn severity(self) -> ControlSeverity {
        self.severity
    }

    /// Returns the stop-thread field independently of severity.
    #[must_use]
    pub const fn stop_thread(self) -> bool {
        self.stop_thread
    }

    /// Returns the graceful-stop-test field independently of severity.
    #[must_use]
    pub const fn stop_test(self) -> bool {
        self.stop_test
    }

    /// Returns the immediate-stop-test field independently of severity.
    #[must_use]
    pub const fn stop_test_now(self) -> bool {
        self.stop_test_now
    }

    /// Returns the next-thread-loop field independently of severity.
    #[must_use]
    pub const fn start_next_loop(self) -> bool {
        self.start_next_loop
    }

    /// Returns the loop-local next-iteration field.
    #[must_use]
    pub const fn start_next_iteration(self) -> bool {
        self.start_next_iteration
    }

    /// Returns the loop-local break field.
    #[must_use]
    pub const fn break_current_loop(self) -> bool {
        self.break_current_loop
    }
}

// ---------------------------------------------------------------------------
// Bounded diagnostics and typed errors
// ---------------------------------------------------------------------------

/// Stable categories for retained listener diagnostics.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DiagnosticCode {
    /// A native effect returned a recoverable failure.
    NativeEffectFailed,
    /// A native effect proposal was stale or invalid.
    NativeEffectRejected,
    /// An observer admission failed after its revision was captured.
    ObserverAdmissionFailed,
    /// An external listener committed state while reporting an exception.
    ExternalCaughtException,
    /// An external listener reported an exception without mutation.
    ExternalNoMutationException,
    /// An explicitly negotiated external capability is unavailable.
    ExternalUnsupported,
    /// A fatal external worker/process uncertainty occurred.
    ExternalUncertain,
    /// A listener entry was suppressed by transaction instance identity.
    TransactionSuppressed,
}

impl DiagnosticCode {
    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NativeEffectFailed => "listener.native-effect.failed",
            Self::NativeEffectRejected => "listener.native-effect.rejected",
            Self::ObserverAdmissionFailed => "listener.observer.admission-failed",
            Self::ExternalCaughtException => "listener.external.caught-exception",
            Self::ExternalNoMutationException => "listener.external.no-mutation-exception",
            Self::ExternalUnsupported => "listener.external.unsupported",
            Self::ExternalUncertain => "listener.external.uncertain",
            Self::TransactionSuppressed => "listener.transaction.suppressed",
        }
    }
}

/// Errors raised while creating one bounded diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticError {
    /// Detail exceeded the hard per-diagnostic limit.
    TooLong { actual: usize, maximum: usize },
}

impl DiagnosticError {
    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        "listener.diagnostic.too-long"
    }
}

impl fmt::Display for DiagnosticError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { actual, maximum } => {
                write!(formatter, "{}: {actual}>{maximum}", self.code())
            }
        }
    }
}

impl std::error::Error for DiagnosticError {}

/// A bounded, typed diagnostic retained after listener notification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListenerDiagnostic {
    code: DiagnosticCode,
    detail: String,
}

impl ListenerDiagnostic {
    /// Creates a diagnostic with a bounded detail string.
    pub fn new(code: DiagnosticCode, detail: impl Into<String>) -> Result<Self, DiagnosticError> {
        let detail = detail.into();
        if detail.len() > MAX_DIAGNOSTIC_BYTES {
            return Err(DiagnosticError::TooLong {
                actual: detail.len(),
                maximum: MAX_DIAGNOSTIC_BYTES,
            });
        }
        Ok(Self { code, detail })
    }

    /// Returns the typed diagnostic code.
    #[must_use]
    pub const fn kind(&self) -> DiagnosticCode {
        self.code
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code.code()
    }

    /// Returns the bounded diagnostic detail.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for ListenerDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code(), self.detail)
    }
}

impl std::error::Error for ListenerDiagnostic {}

/// Bounded listener-program execution limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListenerProgramLimits {
    max_entries: usize,
    max_revisions: usize,
    max_diagnostics: usize,
    max_diagnostic_bytes: usize,
}

impl Default for ListenerProgramLimits {
    fn default() -> Self {
        Self {
            max_entries: MAX_PROGRAM_ENTRIES,
            max_revisions: MAX_REVISIONS,
            max_diagnostics: MAX_DIAGNOSTICS,
            max_diagnostic_bytes: MAX_DIAGNOSTIC_TOTAL_BYTES,
        }
    }
}

impl ListenerProgramLimits {
    /// Creates finite limits and rejects zero or hard-limit overflow.
    pub fn new(
        max_entries: usize,
        max_revisions: usize,
        max_diagnostics: usize,
        max_diagnostic_bytes: usize,
    ) -> Result<Self, ListenerProgramError> {
        if max_entries == 0 || max_entries > MAX_PROGRAM_ENTRIES {
            return Err(ListenerProgramError::InvalidLimit {
                kind: LimitKind::ProgramEntries,
                actual: max_entries,
                maximum: MAX_PROGRAM_ENTRIES,
            });
        }
        if max_revisions == 0 || max_revisions > MAX_REVISIONS {
            return Err(ListenerProgramError::InvalidLimit {
                kind: LimitKind::Revisions,
                actual: max_revisions,
                maximum: MAX_REVISIONS,
            });
        }
        if max_diagnostics == 0 || max_diagnostics > MAX_DIAGNOSTICS {
            return Err(ListenerProgramError::InvalidLimit {
                kind: LimitKind::Diagnostics,
                actual: max_diagnostics,
                maximum: MAX_DIAGNOSTICS,
            });
        }
        if max_diagnostic_bytes == 0 || max_diagnostic_bytes > MAX_DIAGNOSTIC_TOTAL_BYTES {
            return Err(ListenerProgramError::InvalidLimit {
                kind: LimitKind::DiagnosticBytes,
                actual: max_diagnostic_bytes,
                maximum: MAX_DIAGNOSTIC_TOTAL_BYTES,
            });
        }
        Ok(Self {
            max_entries,
            max_revisions,
            max_diagnostics,
            max_diagnostic_bytes,
        })
    }

    /// Returns the entry limit.
    #[must_use]
    pub const fn max_entries(self) -> usize {
        self.max_entries
    }

    /// Returns the immutable-revision limit.
    #[must_use]
    pub const fn max_revisions(self) -> usize {
        self.max_revisions
    }

    /// Returns the diagnostic-count limit.
    #[must_use]
    pub const fn max_diagnostics(self) -> usize {
        self.max_diagnostics
    }

    /// Returns the diagnostic-byte limit.
    #[must_use]
    pub const fn max_diagnostic_bytes(self) -> usize {
        self.max_diagnostic_bytes
    }
}

/// Kinds of finite listener resource limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LimitKind {
    /// Number of source-ordered entries.
    ProgramEntries,
    /// Number of immutable revisions.
    Revisions,
    /// Number of retained diagnostics.
    Diagnostics,
    /// Total diagnostic detail bytes.
    DiagnosticBytes,
}

/// Stable errors raised by listener-program construction or execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ListenerProgramError {
    /// A finite limit was zero or above its hard bound.
    InvalidLimit {
        /// Limit family.
        kind: LimitKind,
        /// Supplied value.
        actual: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// The program did not retain strict source order.
    SourceOrder {
        /// Previous one-based ordinal.
        previous: u32,
        /// Repeated or lower ordinal.
        current: u32,
    },
    /// An entry or origin belongs to another plan domain.
    DomainMismatch,
    /// An invocation's sample identity disagreed with its run identity.
    SampleRunMismatch,
    /// A transaction aggregate's source did not match its controller identity.
    TransactionSourceMismatch,
    /// The revision bound was reached before a new observer capture.
    RevisionLimitExceeded { maximum: usize },
    /// A checked generation increment overflowed.
    GenerationOverflow { generation: ResultGeneration },
    /// An effect proposal used a stale generation.
    StaleEffect {
        /// Current live generation.
        expected: ResultGeneration,
        /// Proposal base generation.
        actual: ResultGeneration,
    },
    /// A diagnostic could not be retained under the run budget.
    DiagnosticLimitExceeded {
        /// Count or byte budget category.
        kind: DiagnosticLimitKind,
        /// Requested value after the rejected append.
        actual: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// A bounded vector allocation failed.
    AllocationFailure,
    /// An uncertain external operation poisoned the listener authority.
    ExternalUncertain { diagnostic: ListenerDiagnostic },
    /// A negotiated external capability was unavailable; no native fallback
    /// is selected.
    ExternalUnsupported { diagnostic: ListenerDiagnostic },
}

impl ListenerProgramError {
    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidLimit { .. } => "listener.limit.invalid",
            Self::SourceOrder { .. } => "listener.program.source-order",
            Self::DomainMismatch => "listener.identity.domain-mismatch",
            Self::SampleRunMismatch => "listener.sample.run-mismatch",
            Self::TransactionSourceMismatch => "listener.transaction.source-mismatch",
            Self::RevisionLimitExceeded { .. } => "listener.revision.limit",
            Self::GenerationOverflow { .. } => "listener.result.generation-overflow",
            Self::StaleEffect { .. } => "listener.effect.stale-generation",
            Self::DiagnosticLimitExceeded { .. } => "listener.diagnostic.limit",
            Self::AllocationFailure => "listener.resource.allocation",
            Self::ExternalUncertain { .. } => "listener.external.uncertain",
            Self::ExternalUnsupported { .. } => "listener.external.unsupported",
        }
    }
}

impl fmt::Display for ListenerProgramError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ListenerProgramError {}

/// Diagnostic budget category used by an execution error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticLimitKind {
    /// Diagnostic count was exhausted.
    Count,
    /// Diagnostic bytes were exhausted.
    Bytes,
}

// ---------------------------------------------------------------------------
// Listener entry domain types
// ---------------------------------------------------------------------------

/// Closed native ResultAction vocabulary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ResultActionKind {
    /// Leave the result and controls unchanged.
    Continue,
    /// Stop the current virtual-user thread.
    StopThread,
    /// Gracefully stop the test.
    StopTest,
    /// Immediately stop the test.
    StopTestNow,
    /// Start the next thread-group loop.
    StartNextThreadLoop,
    /// Start the next iteration of the current controller loop.
    StartNextIterationOfCurrentLoop,
    /// Break the current controller loop.
    BreakCurrentLoop,
}

/// A typed native ResultAction listener effect.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ResultAction {
    action: ResultActionKind,
}

impl ResultAction {
    /// Creates one typed ResultAction.
    #[must_use]
    pub const fn new(action: ResultActionKind) -> Self {
        Self { action }
    }

    /// Returns the configured action.
    #[must_use]
    pub const fn action(self) -> ResultActionKind {
        self.action
    }
}

/// A bounded proposal returned by a native effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeEffectProposal {
    base_generation: ResultGeneration,
    patch: ResultPatch,
    diagnostics: Vec<ListenerDiagnostic>,
}

impl NativeEffectProposal {
    /// Creates a proposal with no diagnostics.
    #[must_use]
    pub fn new(base_generation: ResultGeneration, patch: ResultPatch) -> Self {
        Self {
            base_generation,
            patch,
            diagnostics: Vec::new(),
        }
    }

    /// Creates a proposal with a bounded diagnostic list.
    pub fn with_diagnostics(
        base_generation: ResultGeneration,
        patch: ResultPatch,
        diagnostics: Vec<ListenerDiagnostic>,
    ) -> Result<Self, ListenerProgramError> {
        if diagnostics.len() > MAX_DIAGNOSTICS {
            return Err(ListenerProgramError::InvalidLimit {
                kind: LimitKind::Diagnostics,
                actual: diagnostics.len(),
                maximum: MAX_DIAGNOSTICS,
            });
        }
        let diagnostic_bytes = diagnostics.iter().try_fold(0usize, |total, diagnostic| {
            total.checked_add(diagnostic.detail.len())
        });
        if diagnostic_bytes.is_none_or(|bytes| bytes > MAX_DIAGNOSTIC_TOTAL_BYTES) {
            let actual = match diagnostic_bytes {
                Some(bytes) => bytes,
                None => usize::MAX,
            };
            return Err(ListenerProgramError::InvalidLimit {
                kind: LimitKind::DiagnosticBytes,
                actual,
                maximum: MAX_DIAGNOSTIC_TOTAL_BYTES,
            });
        }
        Ok(Self {
            base_generation,
            patch,
            diagnostics,
        })
    }

    /// Returns the proposal's base generation.
    #[must_use]
    pub const fn base_generation(&self) -> ResultGeneration {
        self.base_generation
    }

    /// Returns the typed result patch.
    #[must_use]
    pub const fn patch(&self) -> ResultPatch {
        self.patch
    }

    /// Returns proposal diagnostics.
    #[must_use]
    pub fn diagnostics(&self) -> &[ListenerDiagnostic] {
        &self.diagnostics
    }
}

/// A native listener effect.  There is no stringly-typed mutation variant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeEffect {
    /// Apply a ResultAction according to the current typed result status.
    ResultAction(ResultAction),
    /// Apply one generation-checked typed proposal.
    Proposal(NativeEffectProposal),
    /// Retain a recoverable native listener failure and continue notification.
    Failure(ListenerDiagnostic),
}

/// Closed filter configuration for a snapshot observer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SnapshotFilter {
    error_only: bool,
    success_only: bool,
}

impl SnapshotFilter {
    /// Creates the pinned two-flag filter, including the both-set no-match case.
    #[must_use]
    pub const fn new(error_only: bool, success_only: bool) -> Self {
        Self {
            error_only,
            success_only,
        }
    }

    /// Returns whether only unsuccessful revisions are selected.
    #[must_use]
    pub const fn error_only(self) -> bool {
        self.error_only
    }

    /// Returns whether only successful revisions are selected.
    #[must_use]
    pub const fn success_only(self) -> bool {
        self.success_only
    }

    fn matches(self, status: ResultStatus) -> bool {
        // Decision 0016 closes the two-flag state as a no-match.  Keeping the
        // explicit guard also prevents the algebraic expression below from
        // accidentally treating both flags as an all-samples selector.
        if self.error_only && self.success_only {
            return false;
        }
        let successful = matches!(status, ResultStatus::Success);
        (!self.error_only && !self.success_only)
            || (successful && self.success_only)
            || (!successful && self.error_only)
    }
}

/// A native immutable observer configuration.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SnapshotObserver {
    filter: SnapshotFilter,
}

impl SnapshotObserver {
    /// Creates a result collector observer with explicit filter flags.
    #[must_use]
    pub const fn new(filter: SnapshotFilter) -> Self {
        Self { filter }
    }

    /// Returns the effective pinned filter.
    #[must_use]
    pub const fn filter(self) -> SnapshotFilter {
        self.filter
    }

    fn selects(self, revision: ResultRevision) -> bool {
        self.filter.matches(revision.status())
    }
}

/// An explicitly negotiated external listener capability.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExternalCapability {
    /// Pinned JVM listener authority version one.
    JvmListenerV1,
    /// Pinned Java plugin listener authority version one.
    PluginListenerV1,
}

/// An external listener entry with no implicit native fallback.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ExternalAuthority {
    capability: ExternalCapability,
}

impl ExternalAuthority {
    /// Creates an explicitly negotiated authority capability.
    #[must_use]
    pub const fn new(capability: ExternalCapability) -> Self {
        Self { capability }
    }

    /// Returns the negotiated capability identity.
    #[must_use]
    pub const fn capability(self) -> ExternalCapability {
        self.capability
    }
}

/// A final state returned by an external authority after listener execution.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ExternalCommittedState {
    status: ResultStatus,
    ignored: bool,
    synthetic: bool,
    control: ControlState,
}

impl ExternalCommittedState {
    /// Creates a typed external final state.
    #[must_use]
    pub const fn new(
        status: ResultStatus,
        ignored: bool,
        synthetic: bool,
        control: ControlState,
    ) -> Self {
        Self {
            status,
            ignored,
            synthetic,
            control,
        }
    }

    /// Returns the committed status.
    #[must_use]
    pub const fn status(self) -> ResultStatus {
        self.status
    }

    /// Returns the committed ignored flag.
    #[must_use]
    pub const fn ignored(self) -> bool {
        self.ignored
    }

    /// Returns the committed synthetic flag.
    #[must_use]
    pub const fn synthetic(self) -> bool {
        self.synthetic
    }

    /// Returns the committed independent controls.
    #[must_use]
    pub const fn control(self) -> ControlState {
        self.control
    }
}

/// The versioned outcome of one external listener authority invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExternalAuthorityReply {
    /// The authority committed a complete final state, possibly after catching
    /// an exception.  Later source entries must see this state.
    Committed {
        /// Final typed state.
        state: ExternalCommittedState,
        /// Optional caught-exception diagnostic.
        diagnostic: Option<ListenerDiagnostic>,
    },
    /// The authority caught an exception without mutating result state.
    NoMutation {
        /// Optional caught-exception diagnostic.
        diagnostic: Option<ListenerDiagnostic>,
    },
    /// The worker/process outcome is uncertain; no guessed delta is allowed.
    Uncertain {
        /// Bounded uncertainty diagnostic.
        diagnostic: ListenerDiagnostic,
    },
    /// The negotiated capability was unavailable.
    Unsupported {
        /// Stable capability diagnostic.
        diagnostic: ListenerDiagnostic,
    },
}

/// An observer envelope captured immutably at one source position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObserverEnvelope {
    notification: SampleNotification,
    position: SourcePosition,
    observer: ListenerInstanceId,
    sequence: RevisionSequence,
    revision: ResultRevision,
}

impl ObserverEnvelope {
    fn new(
        notification: SampleNotification,
        position: SourcePosition,
        observer: ListenerInstanceId,
        sequence: RevisionSequence,
        revision: ResultRevision,
    ) -> Self {
        Self {
            notification,
            position,
            observer,
            sequence,
            revision,
        }
    }

    /// Returns the complete notification metadata.
    #[must_use]
    pub const fn notification(&self) -> SampleNotification {
        self.notification
    }

    /// Returns the exact observer source position.
    #[must_use]
    pub const fn position(&self) -> SourcePosition {
        self.position
    }

    /// Returns the observer instance identity.
    #[must_use]
    pub const fn observer(&self) -> ListenerInstanceId {
        self.observer
    }

    /// Returns the unique source-order sequence.
    #[must_use]
    pub const fn sequence(&self) -> RevisionSequence {
        self.sequence
    }

    /// Returns the immutable revision captured at this observer position.
    #[must_use]
    pub const fn revision(&self) -> ResultRevision {
        self.revision
    }
}

/// A listener entry's source and instance metadata.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ListenerEntryMetadata {
    position: SourcePosition,
    instance: ListenerInstanceId,
    transaction_owner: Option<ListenerInstanceId>,
}

impl ListenerEntryMetadata {
    /// Creates metadata for one source-ordered listener instance.
    #[must_use]
    pub const fn new(position: SourcePosition, instance: ListenerInstanceId) -> Self {
        Self {
            position,
            instance,
            transaction_owner: None,
        }
    }

    /// Associates this listener instance with a transaction package owner.
    #[must_use]
    pub const fn with_transaction_owner(mut self, owner: ListenerInstanceId) -> Self {
        self.transaction_owner = Some(owner);
        self
    }

    /// Returns the source position.
    #[must_use]
    pub const fn position(self) -> SourcePosition {
        self.position
    }

    /// Returns the listener instance identity.
    #[must_use]
    pub const fn instance(self) -> ListenerInstanceId {
        self.instance
    }

    /// Returns the owning transaction instance, if any.
    #[must_use]
    pub const fn transaction_owner(self) -> Option<ListenerInstanceId> {
        self.transaction_owner
    }
}

/// One closed-kind source-ordered listener program entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ListenerProgramEntry {
    /// A bounded typed native mutation.
    NativeEffect {
        /// Source and instance metadata.
        metadata: ListenerEntryMetadata,
        /// Effect implementation.
        effect: NativeEffect,
    },
    /// An immutable observer/sink snapshot point.
    SnapshotObserver {
        /// Source and instance metadata.
        metadata: ListenerEntryMetadata,
        /// Observer configuration.
        observer: SnapshotObserver,
    },
    /// A negotiated external listener authority.
    ExternalAuthority {
        /// Source and instance metadata.
        metadata: ListenerEntryMetadata,
        /// External capability.
        authority: ExternalAuthority,
    },
}

impl ListenerProgramEntry {
    /// Creates a native effect entry.
    #[must_use]
    pub const fn native(metadata: ListenerEntryMetadata, effect: NativeEffect) -> Self {
        Self::NativeEffect { metadata, effect }
    }

    /// Creates a snapshot observer entry.
    #[must_use]
    pub const fn observer(metadata: ListenerEntryMetadata, observer: SnapshotObserver) -> Self {
        Self::SnapshotObserver { metadata, observer }
    }

    /// Creates an external authority entry.
    #[must_use]
    pub const fn external(metadata: ListenerEntryMetadata, authority: ExternalAuthority) -> Self {
        Self::ExternalAuthority {
            metadata,
            authority,
        }
    }

    /// Returns source metadata for this entry.
    #[must_use]
    pub const fn metadata(&self) -> ListenerEntryMetadata {
        match self {
            Self::NativeEffect { metadata, .. }
            | Self::SnapshotObserver { metadata, .. }
            | Self::ExternalAuthority { metadata, .. } => *metadata,
        }
    }

    /// Returns the source position.
    #[must_use]
    pub const fn position(&self) -> SourcePosition {
        self.metadata().position()
    }
}

/// A sample input to one listener program.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SampleInput {
    notification: SampleNotification,
    result: Option<LiveResult>,
    initially_ignored: bool,
}

impl SampleInput {
    /// Creates a materialized sample input.
    #[must_use]
    pub const fn new(notification: SampleNotification, result: LiveResult) -> Self {
        Self {
            notification,
            result: Some(result),
            initially_ignored: false,
        }
    }

    /// Creates a null sampler result.  It invokes no listener entry.
    #[must_use]
    pub const fn null(notification: SampleNotification) -> Self {
        Self {
            notification,
            result: None,
            initially_ignored: false,
        }
    }

    /// Creates an input that was ignored before result phases began.
    #[must_use]
    pub const fn initially_ignored(notification: SampleNotification, result: LiveResult) -> Self {
        Self {
            notification,
            result: Some(result),
            initially_ignored: true,
        }
    }

    /// Returns notification metadata.
    #[must_use]
    pub const fn notification(&self) -> SampleNotification {
        self.notification
    }
}

/// An admission failure returned by a sink/router adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionError {
    code: AdmissionErrorCode,
    diagnostic: ListenerDiagnostic,
}

impl AdmissionError {
    /// Creates an admission error with a typed code and bounded detail.
    pub fn new(
        code: AdmissionErrorCode,
        detail: impl Into<String>,
    ) -> Result<Self, DiagnosticError> {
        Ok(Self {
            code,
            diagnostic: ListenerDiagnostic::new(DiagnosticCode::ObserverAdmissionFailed, detail)?,
        })
    }

    /// Creates a full-queue admission error.
    pub fn full(detail: impl Into<String>) -> Result<Self, DiagnosticError> {
        Self::new(AdmissionErrorCode::Full, detail)
    }

    /// Creates a closed-sink admission error.
    pub fn closed(detail: impl Into<String>) -> Result<Self, DiagnosticError> {
        Self::new(AdmissionErrorCode::Closed, detail)
    }

    /// Creates a cancellation admission error.
    pub fn cancelled(detail: impl Into<String>) -> Result<Self, DiagnosticError> {
        Self::new(AdmissionErrorCode::Cancelled, detail)
    }

    /// Returns the typed admission code.
    #[must_use]
    pub const fn kind(&self) -> AdmissionErrorCode {
        self.code
    }

    /// Returns the bounded retained diagnostic.
    #[must_use]
    pub fn diagnostic(&self) -> &ListenerDiagnostic {
        &self.diagnostic
    }
}

/// Closed admission failure categories.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AdmissionErrorCode {
    /// Queue/sink capacity is full.
    Full,
    /// Sink has closed.
    Closed,
    /// Run admission was cancelled.
    Cancelled,
    /// Adapter failed for another typed reason.
    Failed,
}

/// The result of admitting one observer envelope.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AdmissionOutcome {
    /// The original immutable envelope was accepted by the adapter.
    Accepted,
}

/// Versioned listener-runtime seam supplied by the application/router edge.
pub trait ListenerRuntime {
    /// Admits the original immutable envelope without reconstructing it.
    fn admit_snapshot(
        &mut self,
        observer: &SnapshotObserver,
        envelope: &ObserverEnvelope,
    ) -> Result<AdmissionOutcome, AdmissionError>;

    /// Invokes one negotiated external authority against a read-only revision.
    fn invoke_external(
        &mut self,
        authority: &ExternalAuthority,
        revision: &ResultRevision,
    ) -> ExternalAuthorityReply;
}

/// A source-order entry outcome retained in the bounded execution report.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EntryOutcome {
    /// A native effect committed or did nothing successfully.
    NativeEffectApplied,
    /// A native effect failed but notification continued.
    NativeEffectFailed,
    /// An observer revision was accepted.
    ObserverAdmitted,
    /// An observer revision was captured but admission failed.
    ObserverAdmissionFailed,
    /// An observer revision was filtered by its exact flags.
    ObserverFiltered,
    /// An external authority committed state.
    ExternalCommitted,
    /// An external authority reported no mutation.
    ExternalNoMutation,
    /// An entry was suppressed by transaction instance identity.
    TransactionSuppressed,
}

/// A bounded source-order execution trace item.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EntryObservation {
    position: SourcePosition,
    instance: ListenerInstanceId,
    outcome: EntryOutcome,
}

impl EntryObservation {
    /// Returns the source position.
    #[must_use]
    pub const fn position(self) -> SourcePosition {
        self.position
    }

    /// Returns the listener instance.
    #[must_use]
    pub const fn instance(self) -> ListenerInstanceId {
        self.instance
    }

    /// Returns the source-order outcome.
    #[must_use]
    pub const fn outcome(self) -> EntryOutcome {
        self.outcome
    }
}

/// Terminal status of a listener-program invocation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ListenerRunStatus {
    /// Every selected entry completed without a recoverable failure.
    Completed,
    /// A recoverable listener/admission error was retained; later entries ran.
    Failed,
    /// The sampler returned no result.
    NullResult,
    /// The result was ignored before listener notification.
    Ignored,
}

/// Bounded report returned after one source-ordered listener walk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListenerRunReport {
    status: ListenerRunStatus,
    final_revision: Option<ResultRevision>,
    consumed_control: Option<ConsumedControl>,
    envelopes: Vec<ObserverEnvelope>,
    observations: Vec<EntryObservation>,
    diagnostics: Vec<ListenerDiagnostic>,
    suppressed_entries: usize,
    filtered_observers: usize,
    admitted_observers: usize,
}

impl ListenerRunReport {
    fn empty(status: ListenerRunStatus) -> Self {
        Self {
            status,
            final_revision: None,
            consumed_control: None,
            envelopes: Vec::new(),
            observations: Vec::new(),
            diagnostics: Vec::new(),
            suppressed_entries: 0,
            filtered_observers: 0,
            admitted_observers: 0,
        }
    }

    /// Returns terminal status.
    #[must_use]
    pub const fn status(&self) -> ListenerRunStatus {
        self.status
    }

    /// Returns the final pre-consumption immutable revision, if materialized.
    #[must_use]
    pub const fn final_revision(&self) -> Option<ResultRevision> {
        self.final_revision
    }

    /// Returns the control consumed after all entries/admissions.
    #[must_use]
    pub const fn consumed_control(&self) -> Option<ConsumedControl> {
        self.consumed_control
    }

    /// Returns all immutable observer envelopes in source order.
    #[must_use]
    pub fn envelopes(&self) -> &[ObserverEnvelope] {
        &self.envelopes
    }

    /// Returns all entry observations in source order.
    #[must_use]
    pub fn observations(&self) -> &[EntryObservation] {
        &self.observations
    }

    /// Returns retained diagnostics in source order.
    #[must_use]
    pub fn diagnostics(&self) -> &[ListenerDiagnostic] {
        &self.diagnostics
    }

    /// Returns the number of transaction-suppressed entries.
    #[must_use]
    pub const fn suppressed_entries(&self) -> usize {
        self.suppressed_entries
    }

    /// Returns the number of filtered observers.
    #[must_use]
    pub const fn filtered_observers(&self) -> usize {
        self.filtered_observers
    }

    /// Returns the number of admitted observers.
    #[must_use]
    pub const fn admitted_observers(&self) -> usize {
        self.admitted_observers
    }
}

/// One compiled source-ordered listener program.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListenerProgram {
    domain: PlanDomain,
    limits: ListenerProgramLimits,
    entries: Vec<ListenerProgramEntry>,
}

impl ListenerProgram {
    /// Validates and creates one source-ordered listener program.
    pub fn new(
        domain: PlanDomain,
        entries: Vec<ListenerProgramEntry>,
        limits: ListenerProgramLimits,
    ) -> Result<Self, ListenerProgramError> {
        if entries.len() > limits.max_entries {
            return Err(ListenerProgramError::InvalidLimit {
                kind: LimitKind::ProgramEntries,
                actual: entries.len(),
                maximum: limits.max_entries,
            });
        }
        let mut previous = None;
        for entry in &entries {
            let position = entry.position();
            if position.node().domain() != domain {
                return Err(ListenerProgramError::DomainMismatch);
            }
            if let Some(previous) = previous
                && position.ordinal() <= previous
            {
                return Err(ListenerProgramError::SourceOrder {
                    previous,
                    current: position.ordinal(),
                });
            }
            previous = Some(position.ordinal());
        }
        Ok(Self {
            domain,
            limits,
            entries,
        })
    }

    /// Creates an empty program with default finite limits.
    pub fn empty(domain: PlanDomain) -> Self {
        Self {
            domain,
            limits: ListenerProgramLimits::default(),
            entries: Vec::new(),
        }
    }

    /// Returns the plan domain.
    #[must_use]
    pub const fn domain(&self) -> PlanDomain {
        self.domain
    }

    /// Returns the configured finite limits.
    #[must_use]
    pub const fn limits(&self) -> ListenerProgramLimits {
        self.limits
    }

    /// Returns entries in exactly their validated source order.
    #[must_use]
    pub fn entries(&self) -> &[ListenerProgramEntry] {
        &self.entries
    }

    /// Executes one notification and consumes controls only after the walk.
    pub fn execute<R: ListenerRuntime>(
        &self,
        input: SampleInput,
        runtime: &mut R,
    ) -> Result<ListenerRunReport, ListenerProgramError> {
        let notification = input.notification;
        if notification.sample().run() != notification.run() {
            return Err(ListenerProgramError::SampleRunMismatch);
        }
        if notification.origin().source().domain() != self.domain {
            return Err(ListenerProgramError::DomainMismatch);
        }
        if let SampleOrigin::Transaction { controller, .. } = notification.origin()
            && controller.domain() != self.domain
        {
            return Err(ListenerProgramError::DomainMismatch);
        }
        if let SampleOrigin::Transaction {
            parent: Some(parent),
            ..
        } = notification.origin()
            && parent.identity().run() != notification.run()
        {
            return Err(ListenerProgramError::SampleRunMismatch);
        }
        match (notification.scope(), notification.origin()) {
            (NotificationScope::TransactionAggregate { .. }, SampleOrigin::Transaction { .. })
            | (NotificationScope::Ordinary, _)
            | (NotificationScope::TransactionChild { .. }, SampleOrigin::Sampler { .. }) => {}
            _ => return Err(ListenerProgramError::TransactionSourceMismatch),
        }
        let Some(mut live) = input.result else {
            return Ok(ListenerRunReport::empty(ListenerRunStatus::NullResult));
        };
        if input.initially_ignored || live.ignored() {
            return Ok(ListenerRunReport::empty(ListenerRunStatus::Ignored));
        }

        let mut report = ListenerRunReport::empty(ListenerRunStatus::Completed);
        let mut diagnostics = DiagnosticAccumulator::new(self.limits);
        let mut sequence = 1u64;
        let mut recoverable_failure = false;

        for entry in &self.entries {
            let metadata = entry.metadata();
            if is_suppressed(
                notification.scope(),
                metadata.instance(),
                metadata.transaction_owner(),
            ) {
                report.suppressed_entries = report.suppressed_entries.checked_add(1).ok_or(
                    ListenerProgramError::RevisionLimitExceeded {
                        maximum: self.limits.max_revisions,
                    },
                )?;
                push_observation(
                    &mut report,
                    EntryObservation {
                        position: metadata.position(),
                        instance: metadata.instance(),
                        outcome: EntryOutcome::TransactionSuppressed,
                    },
                )?;
                continue;
            }

            match entry {
                ListenerProgramEntry::NativeEffect { effect, .. } => {
                    let applied = apply_native_effect(
                        &mut live,
                        effect,
                        &mut diagnostics,
                        &mut recoverable_failure,
                    )?;
                    push_observation(
                        &mut report,
                        EntryObservation {
                            position: metadata.position(),
                            instance: metadata.instance(),
                            outcome: if applied {
                                EntryOutcome::NativeEffectApplied
                            } else {
                                EntryOutcome::NativeEffectFailed
                            },
                        },
                    )?;
                }
                ListenerProgramEntry::SnapshotObserver { observer, .. } => {
                    if report.envelopes.len() >= self.limits.max_revisions {
                        return Err(ListenerProgramError::RevisionLimitExceeded {
                            maximum: self.limits.max_revisions,
                        });
                    }
                    let revision = live.snapshot();
                    let sequence_value = sequence;
                    sequence = sequence.checked_add(1).ok_or(
                        ListenerProgramError::GenerationOverflow {
                            generation: live.generation(),
                        },
                    )?;
                    let sequence = RevisionSequence::new(sequence_value).map_err(|_| {
                        ListenerProgramError::GenerationOverflow {
                            generation: live.generation(),
                        }
                    })?;
                    let envelope = ObserverEnvelope::new(
                        notification,
                        metadata.position(),
                        metadata.instance(),
                        sequence,
                        revision,
                    );
                    let selected = observer.selects(revision);
                    if !selected {
                        report.filtered_observers = report
                            .filtered_observers
                            .checked_add(1)
                            .ok_or(ListenerProgramError::RevisionLimitExceeded {
                                maximum: self.limits.max_revisions,
                            })?;
                        push_envelope(&mut report, envelope)?;
                        push_observation(
                            &mut report,
                            EntryObservation {
                                position: metadata.position(),
                                instance: metadata.instance(),
                                outcome: EntryOutcome::ObserverFiltered,
                            },
                        )?;
                        continue;
                    }
                    match runtime.admit_snapshot(observer, &envelope) {
                        Ok(AdmissionOutcome::Accepted) => {
                            report.admitted_observers = report
                                .admitted_observers
                                .checked_add(1)
                                .ok_or(ListenerProgramError::RevisionLimitExceeded {
                                    maximum: self.limits.max_revisions,
                                })?;
                            push_envelope(&mut report, envelope)?;
                            push_observation(
                                &mut report,
                                EntryObservation {
                                    position: metadata.position(),
                                    instance: metadata.instance(),
                                    outcome: EntryOutcome::ObserverAdmitted,
                                },
                            )?;
                        }
                        Err(error) => {
                            recoverable_failure = true;
                            diagnostics.push(error.diagnostic().clone())?;
                            push_envelope(&mut report, envelope)?;
                            push_observation(
                                &mut report,
                                EntryObservation {
                                    position: metadata.position(),
                                    instance: metadata.instance(),
                                    outcome: EntryOutcome::ObserverAdmissionFailed,
                                },
                            )?;
                        }
                    }
                }
                ListenerProgramEntry::ExternalAuthority { authority, .. } => {
                    let revision = live.snapshot();
                    match runtime.invoke_external(authority, &revision) {
                        ExternalAuthorityReply::Committed { state, diagnostic } => {
                            let patch = ResultPatch::empty()
                                .with_status(state.status())
                                .with_ignored(state.ignored());
                            let mut candidate = live.clone();
                            candidate.synthetic = state.synthetic();
                            candidate.control = state.control();
                            candidate.commit(live.generation(), patch)?;
                            live = candidate;
                            if let Some(diagnostic) = diagnostic {
                                recoverable_failure = true;
                                diagnostics.push(diagnostic)?;
                            }
                            push_observation(
                                &mut report,
                                EntryObservation {
                                    position: metadata.position(),
                                    instance: metadata.instance(),
                                    outcome: EntryOutcome::ExternalCommitted,
                                },
                            )?;
                        }
                        ExternalAuthorityReply::NoMutation { diagnostic } => {
                            if let Some(diagnostic) = diagnostic {
                                recoverable_failure = true;
                                diagnostics.push(diagnostic)?;
                            }
                            push_observation(
                                &mut report,
                                EntryObservation {
                                    position: metadata.position(),
                                    instance: metadata.instance(),
                                    outcome: EntryOutcome::ExternalNoMutation,
                                },
                            )?;
                        }
                        ExternalAuthorityReply::Unsupported { diagnostic } => {
                            return Err(ListenerProgramError::ExternalUnsupported { diagnostic });
                        }
                        ExternalAuthorityReply::Uncertain { diagnostic } => {
                            diagnostics.push(diagnostic.clone())?;
                            return Err(ListenerProgramError::ExternalUncertain { diagnostic });
                        }
                    }
                }
            }
        }

        // This is intentionally after the complete source-ordered loop.  An
        // observer following ResultAction therefore still sees every action
        // field before the controller receives the consumed severity.
        let final_revision = live.snapshot();
        let consumed_control = live.consume_control();
        report.final_revision = Some(final_revision);
        report.consumed_control = Some(consumed_control);
        report.diagnostics = diagnostics.finish()?;
        report.status = if recoverable_failure {
            ListenerRunStatus::Failed
        } else {
            ListenerRunStatus::Completed
        };
        Ok(report)
    }
}

fn is_suppressed(
    scope: NotificationScope,
    instance: ListenerInstanceId,
    transaction_owner: Option<ListenerInstanceId>,
) -> bool {
    match scope {
        NotificationScope::TransactionChild { aggregate_instance } => {
            instance == aggregate_instance || transaction_owner == Some(aggregate_instance)
        }
        _ => false,
    }
}

fn push_observation(
    report: &mut ListenerRunReport,
    observation: EntryObservation,
) -> Result<(), ListenerProgramError> {
    report
        .observations
        .try_reserve(1)
        .map_err(|_| ListenerProgramError::AllocationFailure)?;
    report.observations.push(observation);
    Ok(())
}

fn push_envelope(
    report: &mut ListenerRunReport,
    envelope: ObserverEnvelope,
) -> Result<(), ListenerProgramError> {
    report
        .envelopes
        .try_reserve(1)
        .map_err(|_| ListenerProgramError::AllocationFailure)?;
    report.envelopes.push(envelope);
    Ok(())
}

fn apply_native_effect(
    live: &mut LiveResult,
    effect: &NativeEffect,
    diagnostics: &mut DiagnosticAccumulator,
    recoverable_failure: &mut bool,
) -> Result<bool, ListenerProgramError> {
    match effect {
        NativeEffect::ResultAction(action) => {
            let patch = result_action_patch(live.status(), action.action());
            if patch == ResultPatch::empty() {
                return Ok(true);
            }
            live.commit(live.generation(), patch)?;
            Ok(true)
        }
        NativeEffect::Proposal(proposal) => {
            for diagnostic in proposal.diagnostics() {
                diagnostics.push(diagnostic.clone())?;
            }
            match live.commit(proposal.base_generation(), proposal.patch()) {
                Ok(()) => Ok(true),
                Err(ListenerProgramError::StaleEffect { .. }) => {
                    *recoverable_failure = true;
                    let diagnostic = ListenerDiagnostic::new(
                        DiagnosticCode::NativeEffectRejected,
                        "proposal base generation is stale",
                    )
                    .map_err(|_| ListenerProgramError::AllocationFailure)?;
                    diagnostics.push(diagnostic)?;
                    Ok(false)
                }
                Err(error) => Err(error),
            }
        }
        NativeEffect::Failure(diagnostic) => {
            *recoverable_failure = true;
            diagnostics.push(diagnostic.clone())?;
            Ok(false)
        }
    }
}

fn result_action_patch(status: ResultStatus, action: ResultActionKind) -> ResultPatch {
    if status != ResultStatus::Failure {
        return ResultPatch::empty();
    }
    let control = match action {
        ResultActionKind::Continue => ControlPatch::empty(),
        ResultActionKind::StopThread => ControlPatch::empty().with_stop_thread(true),
        ResultActionKind::StopTest => ControlPatch::empty().with_stop_test(true),
        ResultActionKind::StopTestNow => ControlPatch::empty().with_stop_test_now(true),
        ResultActionKind::StartNextThreadLoop => ControlPatch::empty().with_start_next_loop(true),
        ResultActionKind::StartNextIterationOfCurrentLoop => {
            ControlPatch::empty().with_start_next_iteration(true)
        }
        ResultActionKind::BreakCurrentLoop => ControlPatch::empty().with_break_current_loop(true),
    };
    ResultPatch::empty().with_control(control)
}

struct DiagnosticAccumulator {
    limits: ListenerProgramLimits,
    values: Vec<ListenerDiagnostic>,
    bytes: usize,
}

impl DiagnosticAccumulator {
    fn new(limits: ListenerProgramLimits) -> Self {
        Self {
            limits,
            values: Vec::new(),
            bytes: 0,
        }
    }

    fn push(&mut self, diagnostic: ListenerDiagnostic) -> Result<(), ListenerProgramError> {
        let count = self.values.len().checked_add(1).ok_or(
            ListenerProgramError::DiagnosticLimitExceeded {
                kind: DiagnosticLimitKind::Count,
                actual: usize::MAX,
                maximum: self.limits.max_diagnostics,
            },
        )?;
        if count > self.limits.max_diagnostics {
            return Err(ListenerProgramError::DiagnosticLimitExceeded {
                kind: DiagnosticLimitKind::Count,
                actual: count,
                maximum: self.limits.max_diagnostics,
            });
        }
        let bytes = self.bytes.checked_add(diagnostic.detail.len()).ok_or(
            ListenerProgramError::DiagnosticLimitExceeded {
                kind: DiagnosticLimitKind::Bytes,
                actual: usize::MAX,
                maximum: self.limits.max_diagnostic_bytes,
            },
        )?;
        if bytes > self.limits.max_diagnostic_bytes {
            return Err(ListenerProgramError::DiagnosticLimitExceeded {
                kind: DiagnosticLimitKind::Bytes,
                actual: bytes,
                maximum: self.limits.max_diagnostic_bytes,
            });
        }
        self.values
            .try_reserve(1)
            .map_err(|_| ListenerProgramError::AllocationFailure)?;
        self.values.push(diagnostic);
        self.bytes = bytes;
        Ok(())
    }

    fn finish(self) -> Result<Vec<ListenerDiagnostic>, ListenerProgramError> {
        Ok(self.values)
    }
}

// ---------------------------------------------------------------------------
// Deterministic unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    reason = "tests use fixed typed in-memory fixtures and explicit assertions"
)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FixtureRuntime {
        admitted: Vec<ObserverEnvelope>,
        observed_statuses: Vec<ResultStatus>,
        admission_error: Option<AdmissionError>,
        external: Vec<ExternalAuthorityReply>,
    }

    impl ListenerRuntime for FixtureRuntime {
        fn admit_snapshot(
            &mut self,
            _observer: &SnapshotObserver,
            envelope: &ObserverEnvelope,
        ) -> Result<AdmissionOutcome, AdmissionError> {
            self.observed_statuses.push(envelope.revision().status());
            if let Some(error) = self.admission_error.take() {
                return Err(error);
            }
            self.admitted.push(envelope.clone());
            Ok(AdmissionOutcome::Accepted)
        }

        fn invoke_external(
            &mut self,
            _authority: &ExternalAuthority,
            _revision: &ResultRevision,
        ) -> ExternalAuthorityReply {
            if self.external.is_empty() {
                let diagnostic = ListenerDiagnostic::new(
                    DiagnosticCode::ExternalUnsupported,
                    "fixture authority has no reply",
                )
                .expect("fixture diagnostic");
                ExternalAuthorityReply::Unsupported { diagnostic }
            } else {
                self.external.remove(0)
            }
        }
    }

    fn domain() -> PlanDomain {
        PlanDomain::new([7; 32]).expect("non-empty plan domain")
    }

    fn node(number: u64) -> PlanNodeRef {
        PlanNodeRef::new(domain(), NodeId::new(number).expect("node"))
    }

    fn instance(number: u64) -> ListenerInstanceId {
        ListenerInstanceId::new(number).expect("listener instance")
    }

    fn notification(origin: SampleOrigin, scope: NotificationScope) -> SampleNotification {
        let run = RunId::new(1).expect("run");
        let sample = SampleIdentity::new(run, SampleId::new(1).expect("sample"));
        SampleNotification::new(
            run,
            WorkerId::new(2).expect("worker"),
            UserId::new(3).expect("user"),
            sample,
            origin,
            scope,
        )
    }

    fn metadata(position: u32, instance_number: u64) -> ListenerEntryMetadata {
        ListenerEntryMetadata::new(
            SourcePosition::new(position, node(position as u64)).expect("position"),
            instance(instance_number),
        )
    }

    fn program(entries: Vec<ListenerProgramEntry>) -> ListenerProgram {
        ListenerProgram::new(
            domain(),
            entries,
            ListenerProgramLimits::new(32, 32, 32, 4_096).expect("limits"),
        )
        .expect("program")
    }

    fn failed_input() -> SampleInput {
        SampleInput::new(
            notification(
                SampleOrigin::Sampler { sampler: node(99) },
                NotificationScope::Ordinary,
            ),
            LiveResult::new(ResultStatus::Failure),
        )
    }

    #[test]
    fn collector_before_and_after_action_capture_distinct_immutable_revisions() {
        let before = ListenerProgramEntry::observer(
            metadata(1, 1),
            SnapshotObserver::new(SnapshotFilter::new(false, false)),
        );
        let action = ListenerProgramEntry::native(
            metadata(2, 2),
            NativeEffect::ResultAction(ResultAction::new(ResultActionKind::StopTestNow)),
        );
        let after = ListenerProgramEntry::observer(
            metadata(3, 3),
            SnapshotObserver::new(SnapshotFilter::new(false, false)),
        );
        let mut runtime = FixtureRuntime::default();
        let report = program(vec![before, action, after])
            .execute(failed_input(), &mut runtime)
            .expect("listener walk");

        assert_eq!(runtime.admitted.len(), 2);
        assert_eq!(runtime.admitted[0].revision().generation().get(), 1);
        assert_eq!(runtime.admitted[1].revision().generation().get(), 2);
        assert!(!runtime.admitted[0].revision().control().stop_test_now());
        assert!(runtime.admitted[1].revision().control().stop_test_now());
        assert_eq!(
            report.consumed_control().expect("control").severity(),
            ControlSeverity::StopTestNow
        );
        // The first queued revision remains unchanged after the later effect.
        assert!(!runtime.admitted[0].revision().control().stop_test_now());
    }

    #[test]
    fn multiple_actions_keep_fields_and_use_stop_now_precedence() {
        let entries = vec![
            ListenerProgramEntry::native(
                metadata(1, 1),
                NativeEffect::ResultAction(ResultAction::new(
                    ResultActionKind::StartNextThreadLoop,
                )),
            ),
            ListenerProgramEntry::native(
                metadata(2, 2),
                NativeEffect::ResultAction(ResultAction::new(ResultActionKind::StopThread)),
            ),
            ListenerProgramEntry::native(
                metadata(3, 3),
                NativeEffect::ResultAction(ResultAction::new(ResultActionKind::StopTest)),
            ),
            ListenerProgramEntry::native(
                metadata(4, 4),
                NativeEffect::ResultAction(ResultAction::new(ResultActionKind::StopTestNow)),
            ),
            ListenerProgramEntry::native(
                metadata(5, 5),
                NativeEffect::ResultAction(ResultAction::new(
                    ResultActionKind::StartNextIterationOfCurrentLoop,
                )),
            ),
            ListenerProgramEntry::native(
                metadata(6, 6),
                NativeEffect::ResultAction(ResultAction::new(ResultActionKind::BreakCurrentLoop)),
            ),
        ];
        let mut runtime = FixtureRuntime::default();
        let report = program(entries)
            .execute(failed_input(), &mut runtime)
            .expect("actions");
        let control = report.consumed_control().expect("control");
        assert_eq!(control.severity(), ControlSeverity::StopTestNow);
        assert!(control.start_next_loop());
        assert!(control.stop_thread());
        assert!(control.stop_test());
        assert!(control.stop_test_now());
        assert!(control.start_next_iteration());
        assert!(control.break_current_loop());
    }

    #[test]
    fn successful_result_does_not_apply_result_action() {
        let input = SampleInput::new(
            notification(
                SampleOrigin::Sampler { sampler: node(99) },
                NotificationScope::Ordinary,
            ),
            LiveResult::new(ResultStatus::Success),
        );
        let mut runtime = FixtureRuntime::default();
        let report = program(vec![ListenerProgramEntry::native(
            metadata(1, 1),
            NativeEffect::ResultAction(ResultAction::new(ResultActionKind::StopTestNow)),
        )])
        .execute(input, &mut runtime)
        .expect("successful action");
        assert_eq!(
            report.consumed_control().expect("control").severity(),
            ControlSeverity::Continue
        );
    }

    #[test]
    fn listener_exception_is_retained_and_later_entries_continue() {
        let diagnostic = ListenerDiagnostic::new(
            DiagnosticCode::NativeEffectFailed,
            "native listener raised a bounded exception",
        )
        .expect("diagnostic");
        let entries = vec![
            ListenerProgramEntry::native(metadata(1, 1), NativeEffect::Failure(diagnostic)),
            ListenerProgramEntry::observer(
                metadata(2, 2),
                SnapshotObserver::new(SnapshotFilter::new(false, false)),
            ),
        ];
        let mut runtime = FixtureRuntime::default();
        let report = program(entries)
            .execute(failed_input(), &mut runtime)
            .expect("recoverable listener exception");
        assert_eq!(report.status(), ListenerRunStatus::Failed);
        assert_eq!(runtime.admitted.len(), 1);
        assert_eq!(
            report.diagnostics()[0].kind(),
            DiagnosticCode::NativeEffectFailed
        );
    }

    #[test]
    fn external_committed_state_with_exception_is_visible_to_later_observer() {
        let exception = ListenerDiagnostic::new(
            DiagnosticCode::ExternalCaughtException,
            "authority committed then caught exception",
        )
        .expect("exception");
        let state = ExternalCommittedState::new(
            ResultStatus::Failure,
            false,
            true,
            ControlState::empty().with_stop_test_now(true),
        );
        let entries = vec![
            ListenerProgramEntry::external(
                metadata(1, 1),
                ExternalAuthority::new(ExternalCapability::JvmListenerV1),
            ),
            ListenerProgramEntry::observer(
                metadata(2, 2),
                SnapshotObserver::new(SnapshotFilter::new(false, false)),
            ),
        ];
        let mut runtime = FixtureRuntime {
            external: vec![ExternalAuthorityReply::Committed {
                state,
                diagnostic: Some(exception),
            }],
            ..FixtureRuntime::default()
        };
        let report = program(entries)
            .execute(failed_input(), &mut runtime)
            .expect("external committed state");
        assert_eq!(report.status(), ListenerRunStatus::Failed);
        assert_eq!(runtime.admitted[0].revision().generation().get(), 2);
        assert!(runtime.admitted[0].revision().synthetic());
        assert!(runtime.admitted[0].revision().control().stop_test_now());
        assert_eq!(
            report.diagnostics()[0].kind(),
            DiagnosticCode::ExternalCaughtException
        );
    }

    #[test]
    fn unavailable_external_authority_is_an_explicit_error_without_native_fallback() {
        let diagnostic = ListenerDiagnostic::new(
            DiagnosticCode::ExternalUnsupported,
            "negotiated listener capability is unavailable",
        )
        .expect("unsupported diagnostic");
        let entries = vec![
            ListenerProgramEntry::external(
                metadata(1, 1),
                ExternalAuthority::new(ExternalCapability::PluginListenerV1),
            ),
            ListenerProgramEntry::observer(
                metadata(2, 2),
                SnapshotObserver::new(SnapshotFilter::new(false, false)),
            ),
        ];
        let mut runtime = FixtureRuntime {
            external: vec![ExternalAuthorityReply::Unsupported { diagnostic }],
            ..FixtureRuntime::default()
        };
        let error = program(entries)
            .execute(failed_input(), &mut runtime)
            .expect_err("unsupported authority");
        assert_eq!(error.code(), "listener.external.unsupported");
        assert!(runtime.admitted.is_empty());
    }

    #[test]
    fn observer_admission_error_does_not_suppress_later_observers() {
        let first = ListenerProgramEntry::observer(
            metadata(1, 1),
            SnapshotObserver::new(SnapshotFilter::new(false, false)),
        );
        let second = ListenerProgramEntry::observer(
            metadata(2, 2),
            SnapshotObserver::new(SnapshotFilter::new(false, false)),
        );
        let mut runtime = FixtureRuntime {
            admission_error: Some(
                AdmissionError::full("bounded sink queue full").expect("admission"),
            ),
            ..FixtureRuntime::default()
        };
        let report = program(vec![first, second])
            .execute(failed_input(), &mut runtime)
            .expect("observer continuation");
        assert_eq!(report.status(), ListenerRunStatus::Failed);
        assert_eq!(
            runtime.observed_statuses,
            vec![ResultStatus::Failure, ResultStatus::Failure]
        );
        assert_eq!(runtime.admitted.len(), 1);
        assert_eq!(report.diagnostics().len(), 1);
    }

    #[test]
    fn null_and_ignored_samples_skip_all_listener_entries() {
        let entries = vec![ListenerProgramEntry::observer(
            metadata(1, 1),
            SnapshotObserver::new(SnapshotFilter::new(false, false)),
        )];
        let mut runtime = FixtureRuntime::default();
        let null_report = program(entries.clone())
            .execute(
                SampleInput::null(notification(
                    SampleOrigin::Sampler { sampler: node(99) },
                    NotificationScope::Ordinary,
                )),
                &mut runtime,
            )
            .expect("null");
        assert_eq!(null_report.status(), ListenerRunStatus::NullResult);
        assert!(runtime.admitted.is_empty());

        let mut ignored = LiveResult::new(ResultStatus::Failure);
        let ignored_patch = ResultPatch::empty().with_ignored(true);
        ignored
            .commit(ignored.generation(), ignored_patch)
            .expect("ignored patch");
        let ignored_report = program(entries)
            .execute(
                SampleInput::new(
                    notification(
                        SampleOrigin::Sampler { sampler: node(99) },
                        NotificationScope::Ordinary,
                    ),
                    ignored,
                ),
                &mut runtime,
            )
            .expect("postprocessor ignored");
        assert_eq!(ignored_report.status(), ListenerRunStatus::Ignored);
        assert!(runtime.admitted.is_empty());
    }

    #[test]
    fn transaction_child_suppresses_matching_instance_but_aggregate_is_synthetic() {
        let owner = instance(44);
        let suppressed = ListenerProgramEntry::observer(
            metadata(1, 1).with_transaction_owner(owner),
            SnapshotObserver::new(SnapshotFilter::new(false, false)),
        );
        let same_instance = ListenerProgramEntry::observer(
            ListenerEntryMetadata::new(SourcePosition::new(3, node(3)).expect("position"), owner),
            SnapshotObserver::new(SnapshotFilter::new(false, false)),
        );
        let retained = ListenerProgramEntry::observer(
            metadata(4, 2),
            SnapshotObserver::new(SnapshotFilter::new(false, false)),
        );
        let child_notification = notification(
            SampleOrigin::Sampler { sampler: node(99) },
            NotificationScope::TransactionChild {
                aggregate_instance: owner,
            },
        );
        let mut runtime = FixtureRuntime::default();
        let child_report = program(vec![suppressed.clone(), same_instance, retained.clone()])
            .execute(
                SampleInput::new(child_notification, LiveResult::new(ResultStatus::Success)),
                &mut runtime,
            )
            .expect("child");
        assert_eq!(child_report.suppressed_entries(), 2);
        assert_eq!(runtime.admitted.len(), 1);
        assert_eq!(
            child_report.observations()[0].outcome(),
            EntryOutcome::TransactionSuppressed
        );

        let aggregate_notification = notification(
            SampleOrigin::Transaction {
                controller: node(77),
                parent: Some(ParentSampleRef::new(child_notification.sample())),
            },
            NotificationScope::TransactionAggregate {
                controller_instance: owner,
            },
        );
        let mut aggregate_result = LiveResult::new(ResultStatus::Success);
        let aggregate_patch = ResultPatch::empty();
        aggregate_result
            .commit(aggregate_result.generation(), aggregate_patch)
            .expect("aggregate generation");
        aggregate_result = aggregate_result.with_synthetic(true);
        let aggregate_report = program(vec![retained])
            .execute(
                SampleInput::new(aggregate_notification, aggregate_result),
                &mut runtime,
            )
            .expect("aggregate");
        assert!(aggregate_report.envelopes()[0].revision().synthetic());
        assert!(
            aggregate_report.envelopes()[0]
                .notification()
                .origin()
                .is_transaction()
        );
    }

    #[test]
    fn both_filter_flags_select_no_revision_but_capture_exact_position() {
        let observer = ListenerProgramEntry::observer(
            metadata(1, 1),
            SnapshotObserver::new(SnapshotFilter::new(true, true)),
        );
        let mut runtime = FixtureRuntime::default();
        let report = program(vec![observer])
            .execute(failed_input(), &mut runtime)
            .expect("filter");
        assert_eq!(report.filtered_observers(), 1);
        assert!(runtime.admitted.is_empty());
        assert_eq!(report.envelopes().len(), 1);
    }

    #[test]
    fn stale_proposal_and_generation_overflow_mutate_nothing() {
        let mut runtime = FixtureRuntime::default();
        let stale = NativeEffectProposal::new(
            ResultGeneration::new(99).expect("generation"),
            ResultPatch::empty().with_status(ResultStatus::Success),
        );
        let report = program(vec![ListenerProgramEntry::native(
            metadata(1, 1),
            NativeEffect::Proposal(stale),
        )])
        .execute(failed_input(), &mut runtime)
        .expect("stale proposal");
        assert_eq!(report.status(), ListenerRunStatus::Failed);
        assert_eq!(
            report.final_revision().expect("revision").status(),
            ResultStatus::Failure
        );

        let max_generation = ResultGeneration::new(u64::MAX).expect("max generation");
        let live = LiveResult::from_parts(
            max_generation,
            ResultStatus::Failure,
            false,
            false,
            ControlState::empty(),
        );
        let input = SampleInput::new(
            notification(
                SampleOrigin::Sampler { sampler: node(99) },
                NotificationScope::Ordinary,
            ),
            live,
        );
        let error = program(vec![ListenerProgramEntry::native(
            metadata(1, 1),
            NativeEffect::ResultAction(ResultAction::new(ResultActionKind::StopThread)),
        )])
        .execute(input, &mut runtime)
        .expect_err("generation overflow");
        assert_eq!(error.code(), "listener.result.generation-overflow");
    }

    #[test]
    fn source_order_and_resource_bounds_are_fail_closed() {
        let out_of_order = ListenerProgram::new(
            domain(),
            vec![
                ListenerProgramEntry::observer(
                    metadata(2, 1),
                    SnapshotObserver::new(SnapshotFilter::new(false, false)),
                ),
                ListenerProgramEntry::observer(
                    metadata(1, 2),
                    SnapshotObserver::new(SnapshotFilter::new(false, false)),
                ),
            ],
            ListenerProgramLimits::new(2, 2, 2, 32).expect("limits"),
        )
        .expect_err("source order");
        assert_eq!(out_of_order.code(), "listener.program.source-order");

        let limits = ListenerProgramLimits::new(1, 1, 1, 32).expect("tight limits");
        let error = ListenerProgram::new(
            domain(),
            vec![
                ListenerProgramEntry::observer(
                    metadata(1, 1),
                    SnapshotObserver::new(SnapshotFilter::new(false, false)),
                ),
                ListenerProgramEntry::observer(
                    metadata(2, 2),
                    SnapshotObserver::new(SnapshotFilter::new(false, false)),
                ),
            ],
            limits,
        )
        .expect_err("entry bound");
        assert_eq!(error.code(), "listener.limit.invalid");

        let too_many = ListenerProgramLimits::new(1, 1, 1, 32)
            .expect("limits")
            .max_diagnostics();
        assert_eq!(too_many, 1);
        assert!(ListenerProgramLimits::new(0, 1, 1, 1).is_err());
        assert!(ListenerProgramLimits::new(1, MAX_REVISIONS + 1, 1, 1).is_err());
    }

    #[test]
    fn diagnostic_count_and_byte_bounds_fail_closed() {
        let first = ListenerDiagnostic::new(DiagnosticCode::NativeEffectFailed, "abcd")
            .expect("first diagnostic");
        let second = ListenerDiagnostic::new(DiagnosticCode::NativeEffectFailed, "efgh")
            .expect("second diagnostic");
        let limits = ListenerProgramLimits::new(2, 2, 1, 64).expect("count limits");
        let count_error = ListenerProgram::new(
            domain(),
            vec![
                ListenerProgramEntry::native(metadata(1, 1), NativeEffect::Failure(first)),
                ListenerProgramEntry::native(metadata(2, 2), NativeEffect::Failure(second)),
            ],
            limits,
        )
        .expect("count program")
        .execute(failed_input(), &mut FixtureRuntime::default())
        .expect_err("diagnostic count");
        assert_eq!(count_error.code(), "listener.diagnostic.limit");

        let bytes = ListenerDiagnostic::new(DiagnosticCode::NativeEffectFailed, "abcd")
            .expect("byte diagnostic");
        let limits = ListenerProgramLimits::new(1, 1, 1, 3).expect("byte limits");
        let byte_error = ListenerProgram::new(
            domain(),
            vec![ListenerProgramEntry::native(
                metadata(1, 1),
                NativeEffect::Failure(bytes),
            )],
            limits,
        )
        .expect("byte program")
        .execute(failed_input(), &mut FixtureRuntime::default())
        .expect_err("diagnostic bytes");
        assert_eq!(byte_error.code(), "listener.diagnostic.limit");
    }

    #[test]
    fn control_is_consumed_after_observer_admission_and_revision_keeps_flags() {
        let entries = vec![
            ListenerProgramEntry::native(
                metadata(1, 1),
                NativeEffect::ResultAction(ResultAction::new(ResultActionKind::StopTest)),
            ),
            ListenerProgramEntry::observer(
                metadata(2, 2),
                SnapshotObserver::new(SnapshotFilter::new(false, false)),
            ),
        ];
        let mut runtime = FixtureRuntime::default();
        let report = program(entries)
            .execute(failed_input(), &mut runtime)
            .expect("control order");
        assert!(runtime.admitted[0].revision().control().stop_test());
        assert_eq!(
            report.consumed_control().expect("consumed").severity(),
            ControlSeverity::StopTest
        );
        // The public report only exposes the immutable pre-consumption
        // revision; live control reset is not observable as a mutation of it.
        assert!(
            report
                .final_revision()
                .expect("final")
                .control()
                .stop_test()
        );
    }
}
