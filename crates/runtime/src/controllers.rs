// SPDX-License-Identifier: Apache-2.0
//! Deterministic state machines for the ordered controller subset.
//!
//! The public plan types in this module are intentionally executor-neutral.
//! They are a small adaptation seam for the semantic model and do not claim
//! to be the model's final representation. A caller compiles a tree once and
//! creates one [`ControllerRunner`] per virtual user. A runner owns all mutable
//! traversal state, so a user cannot share loop counters with another user.
//!
//! The legacy [`ControllerNode`] surface remains a compact Simple/Loop seam.
//! The complete built-in controller vocabulary is provided by the sibling
//! [`crate::LogicNode`] state machine, which preserves explicit ordering and
//! reports unsupported JVM/plugin conditions instead of silently approximating
//! them.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

/// An executor-neutral identifier for a sampler or controller.
pub type ElementId = u64;

type NodeIndex = usize;

const DEFAULT_MAX_NODES: usize = 16_384;
const DEFAULT_MAX_DEPTH: usize = 128;
const MAX_ALLOWED_DEPTH: usize = 4_096;
const MAX_CONTROLLER_KIND_BYTES: usize = 4_096;

fn bounded_kind(value: impl Into<String>) -> String {
    let value = value.into();
    if value.len() <= MAX_CONTROLLER_KIND_BYTES {
        value
    } else {
        let mut end = MAX_CONTROLLER_KIND_BYTES;
        while end > 0 && !value.is_char_boundary(end) {
            end -= 1;
        }
        let mut bounded = value;
        bounded.truncate(end);
        bounded
    }
}

/// The ordered control signals understood by a controller runner.
///
/// The declaration order is the severity order. [`ControlSignal::combine`]
/// therefore never downgrades a previously observed signal. `NextLoop` is a
/// one-shot logical action when passed to [`ControllerRunner::step_with_signal`];
/// stop signals become terminal runner state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum ControlSignal {
    /// Continue selecting children normally.
    #[default]
    Continue = 0,
    /// Skip the remainder of the innermost active loop iteration.
    NextLoop = 1,
    /// Stop the current virtual user at the next controller boundary.
    StopThread = 2,
    /// Stop the test after safe, graceful boundaries are reached.
    StopTestGraceful = 3,
    /// Stop the test immediately at the next interruptible boundary.
    StopTestImmediate = 4,
}

impl ControlSignal {
    /// Returns the more severe of two signals.
    #[must_use]
    pub const fn combine(self, other: Self) -> Self {
        if self as u8 >= other as u8 {
            self
        } else {
            other
        }
    }

    /// Returns whether this signal stops traversal rather than selecting a
    /// next loop iteration.
    #[must_use]
    pub const fn is_stop(self) -> bool {
        matches!(
            self,
            Self::StopThread | Self::StopTestGraceful | Self::StopTestImmediate
        )
    }
}

/// A monotonic externally-owned cancellation state.
///
/// `NextLoop` is normally supplied as a one-shot signal to `step_with_signal`.
/// This type is useful for stop requests that can be raised by an outer
/// scheduler or signal handler and must never be downgraded by a later event.
#[derive(Debug)]
pub struct Cancellation {
    /// Test-stop requests are shared by every virtual-user view of one run.
    /// A per-user StopThread bit is kept separately below.
    test_stop: Arc<AtomicU8>,
    /// Stop-this-user is deliberately local to a virtual-user view.
    thread_stop: Arc<AtomicBool>,
    /// Next-loop is deliberately local and consumed at a controller boundary.
    next_loop: Arc<AtomicBool>,
}

impl Clone for Cancellation {
    fn clone(&self) -> Self {
        self.clone_for_user()
    }
}

impl Default for Cancellation {
    fn default() -> Self {
        Self::new()
    }
}

impl Cancellation {
    /// Creates a cancellation state with no request pending.
    #[must_use]
    pub fn new() -> Self {
        Self {
            test_stop: Arc::new(AtomicU8::new(ControlSignal::Continue as u8)),
            thread_stop: Arc::new(AtomicBool::new(false)),
            next_loop: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Creates a per-user view sharing only run-scoped stop state.
    #[must_use]
    pub fn clone_for_user(&self) -> Self {
        Self {
            test_stop: Arc::clone(&self.test_stop),
            thread_stop: Arc::new(AtomicBool::new(false)),
            next_loop: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Raises the cancellation state, retaining the most severe request seen.
    /// `NextLoop` and `StopThread` are local one-shot actions; test-stop
    /// requests are shared by all per-user views derived from this state.
    pub fn request(&self, signal: ControlSignal) {
        if signal == ControlSignal::NextLoop {
            self.next_loop.store(true, Ordering::Release);
            return;
        }
        if signal == ControlSignal::StopThread {
            self.thread_stop.store(true, Ordering::Release);
            return;
        }
        if !matches!(
            signal,
            ControlSignal::StopTestGraceful | ControlSignal::StopTestImmediate
        ) {
            return;
        }
        let requested = signal as u8;
        let mut current = self.test_stop.load(Ordering::Acquire);
        while current < requested {
            match self.test_stop.compare_exchange_weak(
                current,
                requested,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }

    /// Returns the current request without consuming a one-shot action.
    #[must_use]
    pub fn signal(&self) -> ControlSignal {
        let stop = signal_from_u8(self.test_stop.load(Ordering::Acquire));
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

    /// Takes one pending signal at a controller boundary.
    ///
    /// Persistent stop requests remain visible. `NextLoop` is cleared before
    /// it is returned, so copying a context or polling a boundary twice cannot
    /// replay the logical action for another virtual user.
    #[must_use]
    pub fn take_signal(&self) -> ControlSignal {
        let stop = signal_from_u8(self.test_stop.load(Ordering::Acquire));
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
}

impl PartialEq for Cancellation {
    fn eq(&self, other: &Self) -> bool {
        self.signal() == other.signal()
    }
}

impl Eq for Cancellation {}

fn signal_from_u8(value: u8) -> ControlSignal {
    match value {
        1 => ControlSignal::NextLoop,
        2 => ControlSignal::StopThread,
        3 => ControlSignal::StopTestGraceful,
        4..=u8::MAX => ControlSignal::StopTestImmediate,
        _ => ControlSignal::Continue,
    }
}

/// The number of times a Loop controller visits its ordered children.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LoopCount {
    /// Visit the child list exactly this many times. Zero is valid and means
    /// that the child list is not visited.
    Finite(u64),
    /// Visit the child list until an external stop or resource budget ends
    /// execution.
    Forever,
}

impl LoopCount {
    /// Creates a finite loop count, including zero.
    #[must_use]
    pub const fn finite(count: u64) -> Self {
        Self::Finite(count)
    }

    /// Creates a zero-iteration loop.
    #[must_use]
    pub const fn zero() -> Self {
        Self::Finite(0)
    }

    /// Creates an unbounded loop. Callers must provide a finite external
    /// budget or cancellation request when executing it.
    #[must_use]
    pub const fn forever() -> Self {
        Self::Forever
    }

    /// Converts JMeter's wire representation (`-1` means forever) into a
    /// typed loop count.
    pub const fn from_jmeter(value: i64) -> Result<Self, ControllerError> {
        if value == -1 {
            Ok(Self::Forever)
        } else if value >= 0 {
            Ok(Self::Finite(value as u64))
        } else {
            Err(ControllerError::InvalidLoopCount { value })
        }
    }

    /// Returns the finite count, or `None` for a forever loop.
    #[must_use]
    pub const fn finite_count(self) -> Option<u64> {
        match self {
            Self::Finite(count) => Some(count),
            Self::Forever => None,
        }
    }
}

/// A controller tree node accepted by the first runtime foundation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControllerNode {
    /// A leaf selected by the runner. The runtime does not execute the
    /// sampler; it reports this ID to an executor-neutral caller.
    Sample {
        /// Sampler identity.
        id: ElementId,
    },
    /// An ordered controller whose children are visited once.
    Simple {
        /// The identity of this controller.
        id: ElementId,
        /// Children in execution order.
        children: Vec<Self>,
    },
    /// An ordered controller whose children are visited according to
    /// [`LoopCount`].
    Loop {
        /// The identity of this controller.
        id: ElementId,
        /// Number of child-list visits.
        count: LoopCount,
        /// Children in execution order.
        children: Vec<Self>,
    },
    /// A controller retained at the runtime boundary but deliberately not
    /// executable by this subset.
    Unsupported {
        /// The identity of this controller.
        id: ElementId,
        /// Upstream capability/class name used in the diagnostic.
        kind: String,
    },
}

impl ControllerNode {
    /// Creates a sampler leaf.
    #[must_use]
    pub const fn sample(id: ElementId) -> Self {
        Self::Sample { id }
    }

    /// Creates an ordered Simple controller.
    #[must_use]
    pub const fn simple(id: ElementId, children: Vec<Self>) -> Self {
        Self::Simple { id, children }
    }

    /// Creates an ordered Loop controller.
    #[must_use]
    pub const fn loop_controller(id: ElementId, count: LoopCount, children: Vec<Self>) -> Self {
        Self::Loop {
            id,
            count,
            children,
        }
    }

    /// Creates a retained but unsupported controller node.
    #[must_use]
    pub fn unsupported(id: ElementId, kind: impl Into<String>) -> Self {
        Self::Unsupported {
            id,
            kind: bounded_kind(kind),
        }
    }
}

/// The controller kind included in each emitted traversal cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ControllerKind {
    /// An ordered, single-pass controller.
    Simple,
    /// An ordered, repeated controller.
    Loop,
}

/// Limits applied while compiling a controller tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControllerLimits {
    max_nodes: usize,
    max_depth: usize,
}

impl Default for ControllerLimits {
    fn default() -> Self {
        Self {
            max_nodes: DEFAULT_MAX_NODES,
            max_depth: DEFAULT_MAX_DEPTH,
        }
    }
}

impl ControllerLimits {
    /// Creates limits. Both values may be zero for a deliberately rejecting
    /// policy; compilation then reports the corresponding typed limit error.
    /// Depth is capped to keep source-tree conversion bounded.
    pub const fn new(max_nodes: usize, max_depth: usize) -> Result<Self, ControllerError> {
        if max_depth > MAX_ALLOWED_DEPTH {
            Err(ControllerError::InvalidLimits {
                max_nodes,
                max_depth,
            })
        } else {
            Ok(Self {
                max_nodes,
                max_depth,
            })
        }
    }

    /// Returns the maximum number of nodes accepted by compilation.
    #[must_use]
    pub const fn max_nodes(self) -> usize {
        self.max_nodes
    }

    /// Returns the maximum zero-based tree depth accepted by compilation.
    #[must_use]
    pub const fn max_depth(self) -> usize {
        self.max_depth
    }
}

/// A typed failure from plan compilation or bounded state-machine progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControllerError {
    /// A JMeter loop count other than `-1` or a non-negative number was given.
    InvalidLoopCount {
        /// The rejected wire value.
        value: i64,
    },
    /// A limit could not be represented by the bounded compiler policy.
    InvalidLimits {
        /// Requested node limit.
        max_nodes: usize,
        /// Requested depth limit.
        max_depth: usize,
    },
    /// The source tree contains more nodes than the configured bound.
    PlanTooLarge {
        /// Number of nodes encountered.
        nodes: usize,
        /// Configured maximum.
        max_nodes: usize,
    },
    /// The source tree exceeds the configured nesting bound.
    PlanTooDeep {
        /// Depth encountered.
        depth: usize,
        /// Configured maximum.
        max_depth: usize,
    },
    /// This runtime subset cannot execute the named controller.
    UnsupportedController {
        /// Controller identity.
        id: ElementId,
        /// Upstream capability/class name.
        kind: String,
    },
    /// A per-step transition budget was exhausted before an outcome could be
    /// emitted.
    StepBudgetExhausted {
        /// Transitions consumed.
        used: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// A whole-run transition budget was exhausted.
    RunBudgetExhausted {
        /// Transitions consumed.
        used: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// A whole-run sample budget was exhausted.
    SampleBudgetExhausted {
        /// Samples emitted.
        emitted: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// A forever loop's diagnostic iteration counter would wrap.
    IterationOverflow {
        /// Controller whose diagnostic counter wrapped.
        controller: ElementId,
    },
    /// The internal cursor could not find the compiled node it references.
    InvalidState {
        /// Compiled node index referenced by the cursor.
        node: NodeIndex,
    },
    /// Two nodes in one compiled tree use the same element identity.
    DuplicateElementId {
        /// The repeated identity.
        id: ElementId,
    },
}

impl fmt::Display for ControllerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLoopCount { value } => {
                write!(
                    formatter,
                    "invalid JMeter loop count {value}; expected -1 or >= 0"
                )
            }
            Self::InvalidLimits {
                max_nodes,
                max_depth,
            } => write!(
                formatter,
                "controller limits exceed the bounded depth policy: max_nodes={max_nodes}, max_depth={max_depth}"
            ),
            Self::PlanTooLarge { nodes, max_nodes } => {
                write!(
                    formatter,
                    "controller plan has {nodes} nodes; limit is {max_nodes}"
                )
            }
            Self::PlanTooDeep { depth, max_depth } => {
                write!(
                    formatter,
                    "controller plan depth {depth}; limit is {max_depth}"
                )
            }
            Self::UnsupportedController { id, kind } => {
                write!(formatter, "controller {id} of kind {kind:?} is unsupported")
            }
            Self::StepBudgetExhausted { used, limit } => {
                write!(
                    formatter,
                    "controller step budget exhausted at {used}/{limit} transitions"
                )
            }
            Self::RunBudgetExhausted { used, limit } => {
                write!(
                    formatter,
                    "controller run budget exhausted at {used}/{limit} transitions"
                )
            }
            Self::SampleBudgetExhausted { emitted, limit } => {
                write!(
                    formatter,
                    "controller sample budget exhausted at {emitted}/{limit} samples"
                )
            }
            Self::IterationOverflow { controller } => {
                write!(
                    formatter,
                    "loop controller {controller} iteration counter overflowed"
                )
            }
            Self::InvalidState { node } => {
                write!(
                    formatter,
                    "controller cursor references invalid node {node}"
                )
            }
            Self::DuplicateElementId { id } => {
                write!(formatter, "controller element identity {id} is duplicated")
            }
        }
    }
}

impl std::error::Error for ControllerError {}

impl ControllerError {
    /// Returns the stable machine-readable category for this error.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidLoopCount { .. } => "runtime.controller.invalid-loop-count",
            Self::InvalidLimits { .. } => "runtime.controller.invalid-limits",
            Self::PlanTooLarge { .. } => "runtime.controller.plan-too-large",
            Self::PlanTooDeep { .. } => "runtime.controller.plan-too-deep",
            Self::UnsupportedController { .. } => "runtime.controller.unsupported",
            Self::StepBudgetExhausted { .. } => "runtime.controller.step-budget",
            Self::RunBudgetExhausted { .. } => "runtime.controller.run-budget",
            Self::SampleBudgetExhausted { .. } => "runtime.controller.sample-budget",
            Self::IterationOverflow { .. } => "runtime.controller.iteration-overflow",
            Self::InvalidState { .. } => "runtime.controller.invalid-state",
            Self::DuplicateElementId { .. } => "runtime.controller.duplicate-element-id",
        }
    }
}

/// A bounded transition budget for one call to a runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepBudget {
    limit: usize,
    used: usize,
}

impl StepBudget {
    /// Creates a budget. A zero budget is valid and deterministically returns
    /// [`ControllerError::StepBudgetExhausted`] on the first required action.
    #[must_use]
    pub const fn new(limit: usize) -> Self {
        Self { limit, used: 0 }
    }

    /// Returns the configured transition limit.
    #[must_use]
    pub const fn limit(self) -> usize {
        self.limit
    }

    /// Returns transitions consumed so far.
    #[must_use]
    pub const fn used(self) -> usize {
        self.used
    }

    /// Returns remaining transitions.
    #[must_use]
    pub const fn remaining(self) -> usize {
        self.limit.saturating_sub(self.used)
    }

    fn spend(&mut self) -> Result<(), ControllerError> {
        if self.used >= self.limit {
            return Err(ControllerError::StepBudgetExhausted {
                used: self.used,
                limit: self.limit,
            });
        }
        self.used = self.used.saturating_add(1);
        Ok(())
    }
}

/// A bounded budget for [`ControllerRunner::run_to_completion`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunBudget {
    max_samples: usize,
    max_transitions: usize,
    emitted: usize,
    transitions: usize,
}

impl RunBudget {
    /// Creates a whole-run budget. Both limits are explicit; no unbounded
    /// execution mode is exposed for a forever loop.
    #[must_use]
    pub const fn new(max_samples: usize, max_transitions: usize) -> Self {
        Self {
            max_samples,
            max_transitions,
            emitted: 0,
            transitions: 0,
        }
    }

    /// Returns the sample limit.
    #[must_use]
    pub const fn max_samples(self) -> usize {
        self.max_samples
    }

    /// Returns the transition limit.
    #[must_use]
    pub const fn max_transitions(self) -> usize {
        self.max_transitions
    }

    /// Returns samples emitted so far.
    #[must_use]
    pub const fn emitted(self) -> usize {
        self.emitted
    }

    /// Returns transitions consumed so far.
    #[must_use]
    pub const fn transitions(self) -> usize {
        self.transitions
    }

    fn next_step_budget(&self) -> Result<StepBudget, ControllerError> {
        if self.transitions >= self.max_transitions {
            return Err(ControllerError::RunBudgetExhausted {
                used: self.transitions,
                limit: self.max_transitions,
            });
        }
        Ok(StepBudget::new(self.max_transitions - self.transitions))
    }

    fn record_step(&mut self, budget: StepBudget) {
        self.transitions = self.transitions.saturating_add(budget.used());
    }

    fn reserve_sample(&mut self) -> Result<(), ControllerError> {
        if self.emitted >= self.max_samples {
            return Err(ControllerError::SampleBudgetExhausted {
                emitted: self.emitted,
                limit: self.max_samples,
            });
        }
        self.emitted = self.emitted.saturating_add(1);
        Ok(())
    }
}

/// A controller cursor included in a sampler trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ControllerCursor {
    /// Controller identity.
    pub id: ElementId,
    /// Controller kind.
    pub kind: ControllerKind,
    /// Zero-based iteration of this controller at selection time.
    pub iteration: u64,
}

/// One sampler selection emitted by the state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampleSelection {
    /// Selected sampler identity.
    pub sampler_id: ElementId,
    /// Number of complete root traversals before this selection.
    pub execution_iteration: u64,
    /// Active ordered controller path, from outermost to innermost.
    pub path: Vec<ControllerCursor>,
}

/// A single bounded runner outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControllerStep {
    /// A sampler is ready for the executor-neutral sampler phase.
    Sample(SampleSelection),
    /// The root controller has no more selections.
    Complete,
    /// Traversal was stopped by a monotonic stop signal.
    Stopped(ControlSignal),
}

/// Alias for callers that refer to each step as an execution outcome.
pub type ControllerOutcome = ControllerStep;

/// A collected deterministic trace from a bounded run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionTrace {
    /// Samplers selected in order.
    pub samples: Vec<SampleSelection>,
    /// Terminal state reached by the run.
    pub terminal: ControllerStep,
}

#[derive(Debug, Clone)]
enum CompiledNode {
    Sample {
        id: ElementId,
    },
    Simple {
        id: ElementId,
        children: Box<[NodeIndex]>,
    },
    Loop {
        id: ElementId,
        count: LoopCount,
        children: Box<[NodeIndex]>,
    },
}

#[derive(Debug, Clone)]
struct CompiledProgram {
    nodes: Vec<CompiledNode>,
    root: NodeIndex,
}

/// An immutable, compiled ordered controller tree.
#[derive(Debug, Clone)]
pub struct ControllerProgram {
    compiled: Arc<CompiledProgram>,
}

impl ControllerProgram {
    /// Compiles a tree with the default node/depth limits.
    ///
    /// This alias keeps construction concise at executor boundaries; it is
    /// equivalent to [`Self::compile`].
    pub fn new(root: ControllerNode) -> Result<Self, ControllerError> {
        Self::compile(root)
    }

    /// Compiles a tree with the default node/depth limits.
    pub fn compile(root: ControllerNode) -> Result<Self, ControllerError> {
        Self::compile_with_limits(root, ControllerLimits::default())
    }

    /// Compiles a tree with explicit resource limits.
    pub fn compile_with_limits(
        root: ControllerNode,
        limits: ControllerLimits,
    ) -> Result<Self, ControllerError> {
        let (nodes, root_index) = compile_tree(&root, limits)?;
        Ok(Self {
            compiled: Arc::new(CompiledProgram {
                nodes,
                root: root_index,
            }),
        })
    }

    /// Creates a fresh per-user runner with independent traversal state.
    #[must_use]
    pub fn runner(&self) -> ControllerRunner {
        ControllerRunner::from_program(self.clone())
    }
}

enum CompileTask<'a> {
    Enter {
        node: &'a ControllerNode,
        depth: usize,
    },
    Build {
        node: &'a ControllerNode,
    },
}

fn compile_tree(
    root: &ControllerNode,
    limits: ControllerLimits,
) -> Result<(Vec<CompiledNode>, NodeIndex), ControllerError> {
    // Postorder compilation avoids recursive calls on user-provided trees.
    // The task and result stacks are bounded by max_nodes, while depth is
    // checked before any child task is scheduled.
    let mut tasks = vec![CompileTask::Enter {
        node: root,
        depth: 0,
    }];
    let mut results = Vec::new();
    let mut nodes = Vec::new();
    let mut seen = 0usize;
    let mut seen_ids = BTreeSet::new();

    while let Some(task) = tasks.pop() {
        match task {
            CompileTask::Enter { node, depth } => {
                if depth > limits.max_depth {
                    return Err(ControllerError::PlanTooDeep {
                        depth,
                        max_depth: limits.max_depth,
                    });
                }
                if seen >= limits.max_nodes {
                    return Err(ControllerError::PlanTooLarge {
                        nodes: seen.saturating_add(1),
                        max_nodes: limits.max_nodes,
                    });
                }
                seen = seen.saturating_add(1);
                let id = match node {
                    ControllerNode::Sample { id }
                    | ControllerNode::Simple { id, .. }
                    | ControllerNode::Loop { id, .. }
                    | ControllerNode::Unsupported { id, .. } => *id,
                };
                if !seen_ids.insert(id) {
                    return Err(ControllerError::DuplicateElementId { id });
                }
                match node {
                    ControllerNode::Sample { id } => {
                        let index = nodes.len();
                        nodes.push(CompiledNode::Sample { id: *id });
                        results.push(index);
                    }
                    ControllerNode::Unsupported { id, kind } => {
                        return Err(ControllerError::UnsupportedController {
                            id: *id,
                            kind: kind.clone(),
                        });
                    }
                    ControllerNode::Simple { children, .. }
                    | ControllerNode::Loop { children, .. } => {
                        let remaining = limits.max_nodes.saturating_sub(seen);
                        if children.len() > remaining {
                            return Err(ControllerError::PlanTooLarge {
                                nodes: seen.saturating_add(children.len()),
                                max_nodes: limits.max_nodes,
                            });
                        }
                        tasks.push(CompileTask::Build { node });
                        for child in children.iter().rev() {
                            tasks.push(CompileTask::Enter {
                                node: child,
                                depth: depth.saturating_add(1),
                            });
                        }
                    }
                }
            }
            CompileTask::Build { node } => {
                let child_count = match node {
                    ControllerNode::Simple { children, .. }
                    | ControllerNode::Loop { children, .. } => children.len(),
                    ControllerNode::Sample { .. } | ControllerNode::Unsupported { .. } => {
                        return Err(ControllerError::InvalidState { node: nodes.len() });
                    }
                };
                if results.len() < child_count {
                    return Err(ControllerError::InvalidState { node: nodes.len() });
                }
                let children = results.split_off(results.len() - child_count);
                let compiled = match node {
                    ControllerNode::Simple { id, .. } => CompiledNode::Simple {
                        id: *id,
                        children: children.into_boxed_slice(),
                    },
                    ControllerNode::Loop { id, count, .. } => CompiledNode::Loop {
                        id: *id,
                        count: *count,
                        children: children.into_boxed_slice(),
                    },
                    ControllerNode::Sample { .. } | ControllerNode::Unsupported { .. } => {
                        return Err(ControllerError::InvalidState { node: nodes.len() });
                    }
                };
                let index = nodes.len();
                nodes.push(compiled);
                results.push(index);
            }
        }
    }

    let root = results
        .pop()
        .ok_or(ControllerError::InvalidState { node: 0 })?;
    if !results.is_empty() {
        return Err(ControllerError::InvalidState { node: root });
    }
    Ok((nodes, root))
}

#[derive(Debug, Clone, Copy)]
struct Frame {
    node: NodeIndex,
    next_child: usize,
    iteration: u64,
}

/// Per-virtual-user mutable state for an immutable [`ControllerProgram`].
#[derive(Debug, Clone)]
pub struct ControllerRunner {
    program: ControllerProgram,
    stack: Vec<Frame>,
    root_started: bool,
    finished: bool,
    terminal: Option<ControlSignal>,
    completed_iterations: u64,
}

impl ControllerRunner {
    fn from_program(program: ControllerProgram) -> Self {
        Self {
            program,
            stack: Vec::new(),
            root_started: false,
            finished: false,
            terminal: None,
            completed_iterations: 0,
        }
    }

    /// Creates a runner for a compiled program.
    #[must_use]
    pub fn new(program: ControllerProgram) -> Self {
        Self::from_program(program)
    }

    /// Creates an independent, freshly initialized runner for the same
    /// compiled program. This is the normal per-user clone operation.
    #[must_use]
    pub fn clone_for_user(&self) -> Self {
        self.program.runner()
    }

    /// Resets traversal, terminal signal, and completed-iteration state.
    pub fn reset(&mut self) {
        self.stack.clear();
        self.root_started = false;
        self.finished = false;
        self.terminal = None;
        self.completed_iterations = 0;
    }

    /// Starts the next root traversal while retaining the completed-iteration
    /// identity used by selection metadata.
    pub fn next_root_iteration(&mut self) -> Result<(), ControllerError> {
        if !self.finished {
            return Err(ControllerError::InvalidState { node: 0 });
        }
        self.stack.clear();
        self.root_started = false;
        self.finished = false;
        self.terminal = None;
        Ok(())
    }

    /// Returns the number of complete root traversals since the last reset.
    #[must_use]
    pub const fn completed_iterations(&self) -> u64 {
        self.completed_iterations
    }

    /// Returns the current zero-based iteration for an active controller.
    #[must_use]
    pub fn current_iteration(&self, controller: ElementId) -> Option<u64> {
        self.stack.iter().rev().find_map(|frame| {
            let node = self.program.compiled.nodes.get(frame.node)?;
            match node {
                CompiledNode::Loop { id, .. } if *id == controller => Some(frame.iteration),
                CompiledNode::Simple { id, .. } if *id == controller => Some(0),
                CompiledNode::Sample { .. } => None,
                CompiledNode::Loop { .. } | CompiledNode::Simple { .. } => None,
            }
        })
    }

    /// Advances one bounded controller step with no incoming signal.
    pub fn step(&mut self, budget: &mut StepBudget) -> Result<ControllerStep, ControllerError> {
        self.step_with_signal(ControlSignal::Continue, budget)
    }

    /// Advances one step using the current monotonic request from an external
    /// cancellation source.
    pub fn step_with_cancellation(
        &mut self,
        cancellation: &Cancellation,
        budget: &mut StepBudget,
    ) -> Result<ControllerStep, ControllerError> {
        self.step_with_signal(cancellation.take_signal(), budget)
    }

    /// Advances one bounded controller step with a typed control signal.
    ///
    /// Stop signals are terminal and monotonic. `NextLoop` is consumed once:
    /// it discards nested frames and advances the innermost active Loop before
    /// normal selection resumes. If no Loop is active it completes the current
    /// root traversal.
    pub fn step_with_signal(
        &mut self,
        signal: ControlSignal,
        budget: &mut StepBudget,
    ) -> Result<ControllerStep, ControllerError> {
        if let Some(existing) = self.terminal {
            if signal.is_stop() {
                let combined = existing.combine(signal);
                self.terminal = Some(combined);
                return Ok(ControllerStep::Stopped(combined));
            }
            return Ok(ControllerStep::Stopped(existing));
        }
        if signal.is_stop() {
            budget.spend()?;
            self.terminal = Some(signal);
            return Ok(ControllerStep::Stopped(signal));
        }
        if signal == ControlSignal::NextLoop {
            budget.spend()?;
            self.apply_next_loop()?;
            if self.finished {
                return Ok(ControllerStep::Complete);
            }
        }
        self.select_next(budget)
    }

    /// Runs until completion or a stop request, collecting a bounded trace.
    ///
    /// The optional initial signal is consumed once, which makes `NextLoop`
    /// suitable for a logical action while a persistent stop request should be
    /// represented by the returned terminal outcome. For a live external
    /// cancellation source, call [`Self::step_with_signal`] at each boundary.
    pub fn run_to_completion(
        &mut self,
        budget: &mut RunBudget,
    ) -> Result<ExecutionTrace, ControllerError> {
        self.run_to_completion_with_signal(budget, ControlSignal::Continue)
    }

    /// Runs until completion or a supplied one-shot signal is observed.
    pub fn run_to_completion_with_signal(
        &mut self,
        budget: &mut RunBudget,
        initial_signal: ControlSignal,
    ) -> Result<ExecutionTrace, ControllerError> {
        let mut samples = Vec::new();
        let mut signal = initial_signal;
        loop {
            let mut step_budget = budget.next_step_budget()?;
            let outcome = self.step_with_run_budget(signal, &mut step_budget, budget);
            budget.record_step(step_budget);
            let outcome = outcome?;
            signal = ControlSignal::Continue;
            match &outcome {
                ControllerStep::Sample(selection) => {
                    samples.push(selection.clone());
                }
                ControllerStep::Complete | ControllerStep::Stopped(_) => {
                    return Ok(ExecutionTrace {
                        samples,
                        terminal: outcome,
                    });
                }
            }
        }
    }

    fn step_with_run_budget(
        &mut self,
        signal: ControlSignal,
        budget: &mut StepBudget,
        run_budget: &mut RunBudget,
    ) -> Result<ControllerStep, ControllerError> {
        if let Some(existing) = self.terminal {
            if signal.is_stop() {
                let combined = existing.combine(signal);
                self.terminal = Some(combined);
                return Ok(ControllerStep::Stopped(combined));
            }
            return Ok(ControllerStep::Stopped(existing));
        }
        if signal.is_stop() {
            budget.spend()?;
            self.terminal = Some(signal);
            return Ok(ControllerStep::Stopped(signal));
        }
        if signal == ControlSignal::NextLoop {
            budget.spend()?;
            self.apply_next_loop()?;
            if self.finished {
                return Ok(ControllerStep::Complete);
            }
        }
        self.select_next_with_sample_budget(budget, run_budget)
    }

    fn select_next(&mut self, budget: &mut StepBudget) -> Result<ControllerStep, ControllerError> {
        self.select_next_with_sample_budget(budget, &mut RunBudget::new(usize::MAX, usize::MAX))
    }

    fn select_next_with_sample_budget(
        &mut self,
        budget: &mut StepBudget,
        run_budget: &mut RunBudget,
    ) -> Result<ControllerStep, ControllerError> {
        if self.finished {
            return Ok(ControllerStep::Complete);
        }
        loop {
            if self.terminal.is_some() {
                // The terminal state is only set through this module's stop
                // branch, but retaining this guard makes future state changes
                // fail closed rather than selecting another sampler.
                let signal = self.terminal.ok_or(ControllerError::InvalidState {
                    node: self.program.compiled.root,
                })?;
                return Ok(ControllerStep::Stopped(signal));
            }
            budget.spend()?;

            if !self.root_started {
                match self.program.compiled.nodes.get(self.program.compiled.root) {
                    Some(CompiledNode::Sample { id }) => {
                        run_budget.reserve_sample()?;
                        self.root_started = true;
                        return Ok(ControllerStep::Sample(self.selection(*id)));
                    }
                    Some(CompiledNode::Simple { .. } | CompiledNode::Loop { .. }) => {
                        self.root_started = true;
                        self.stack.push(Frame {
                            node: self.program.compiled.root,
                            next_child: 0,
                            iteration: 0,
                        });
                        continue;
                    }
                    None => {
                        return Err(ControllerError::InvalidState {
                            node: self.program.compiled.root,
                        });
                    }
                }
            }

            let Some(frame_index) = self.stack.len().checked_sub(1) else {
                self.finished = true;
                self.completed_iterations = self.completed_iterations.checked_add(1).ok_or(
                    ControllerError::IterationOverflow {
                        controller: self.program.compiled.root as ElementId,
                    },
                )?;
                return Ok(ControllerStep::Complete);
            };

            let action = self.frame_action(frame_index)?;
            match action {
                FrameAction::Select(child) => match self.program.compiled.nodes.get(child) {
                    Some(CompiledNode::Sample { id }) => {
                        run_budget.reserve_sample()?;
                        let frame = self.stack.get_mut(frame_index).ok_or(
                            ControllerError::InvalidState {
                                node: self.program.compiled.root,
                            },
                        )?;
                        frame.next_child = frame.next_child.saturating_add(1);
                        return Ok(ControllerStep::Sample(self.selection(*id)));
                    }
                    Some(CompiledNode::Simple { .. } | CompiledNode::Loop { .. }) => {
                        let frame = self.stack.get_mut(frame_index).ok_or(
                            ControllerError::InvalidState {
                                node: self.program.compiled.root,
                            },
                        )?;
                        frame.next_child = frame.next_child.saturating_add(1);
                        self.stack.push(Frame {
                            node: child,
                            next_child: 0,
                            iteration: 0,
                        });
                    }
                    None => return Err(ControllerError::InvalidState { node: child }),
                },
                FrameAction::Finish => {
                    self.stack.pop();
                }
                FrameAction::AdvanceLoop => {
                    let node = self
                        .stack
                        .get(frame_index)
                        .ok_or(ControllerError::InvalidState {
                            node: self.program.compiled.root,
                        })?
                        .node;
                    let iteration = self
                        .stack
                        .get(frame_index)
                        .ok_or(ControllerError::InvalidState { node })?
                        .iteration
                        .checked_add(1)
                        .ok_or_else(|| self.iteration_overflow(node))?;
                    let frame = self
                        .stack
                        .get_mut(frame_index)
                        .ok_or(ControllerError::InvalidState { node })?;
                    frame.next_child = 0;
                    frame.iteration = iteration;
                }
            }
        }
    }

    fn frame_action(&self, frame_index: usize) -> Result<FrameAction, ControllerError> {
        let frame = self
            .stack
            .get(frame_index)
            .ok_or(ControllerError::InvalidState {
                node: self.program.compiled.root,
            })?;
        let node = self
            .program
            .compiled
            .nodes
            .get(frame.node)
            .ok_or(ControllerError::InvalidState { node: frame.node })?;
        match node {
            CompiledNode::Sample { .. } => Err(ControllerError::InvalidState { node: frame.node }),
            CompiledNode::Simple { children, .. } => {
                if frame.next_child < children.len() {
                    Ok(FrameAction::Select(children[frame.next_child]))
                } else {
                    Ok(FrameAction::Finish)
                }
            }
            CompiledNode::Loop {
                count, children, ..
            } => match count {
                LoopCount::Finite(0) => Ok(FrameAction::Finish),
                LoopCount::Finite(total) if frame.next_child < children.len() => {
                    Ok(FrameAction::Select(children[frame.next_child]))
                }
                LoopCount::Finite(total) => {
                    if frame.iteration.saturating_add(1) >= *total {
                        Ok(FrameAction::Finish)
                    } else {
                        Ok(FrameAction::AdvanceLoop)
                    }
                }
                LoopCount::Forever if frame.next_child < children.len() => {
                    Ok(FrameAction::Select(children[frame.next_child]))
                }
                LoopCount::Forever => Ok(FrameAction::AdvanceLoop),
            },
        }
    }

    fn iteration_overflow(&self, node: NodeIndex) -> ControllerError {
        let controller = match self.program.compiled.nodes.get(node) {
            Some(CompiledNode::Simple { id, .. } | CompiledNode::Loop { id, .. }) => *id,
            Some(CompiledNode::Sample { id }) => *id,
            None => node as ElementId,
        };
        ControllerError::IterationOverflow { controller }
    }

    fn apply_next_loop(&mut self) -> Result<(), ControllerError> {
        let Some(loop_index) = self.stack.iter().rposition(|frame| {
            matches!(
                self.program.compiled.nodes.get(frame.node),
                Some(CompiledNode::Loop { .. })
            )
        }) else {
            self.stack.clear();
            self.root_started = true;
            self.finished = true;
            return Ok(());
        };

        let frame = self
            .stack
            .get(loop_index)
            .copied()
            .ok_or(ControllerError::InvalidState {
                node: self.program.compiled.root,
            })?;
        let (controller, count) = match self.program.compiled.nodes.get(frame.node) {
            Some(CompiledNode::Loop { id, count, .. }) => (*id, *count),
            Some(CompiledNode::Sample { .. } | CompiledNode::Simple { .. }) | None => {
                return Err(ControllerError::InvalidState { node: frame.node });
            }
        };
        let next_iteration = match count {
            LoopCount::Finite(total) if frame.iteration.saturating_add(1) >= total => None,
            LoopCount::Finite(_) => Some(
                frame
                    .iteration
                    .checked_add(1)
                    .ok_or(ControllerError::IterationOverflow { controller })?,
            ),
            LoopCount::Forever => Some(
                frame
                    .iteration
                    .checked_add(1)
                    .ok_or(ControllerError::IterationOverflow { controller })?,
            ),
        };

        self.stack.truncate(loop_index.saturating_add(1));
        let loop_frame = self
            .stack
            .get_mut(loop_index)
            .ok_or(ControllerError::InvalidState { node: frame.node })?;
        match next_iteration {
            Some(iteration) => {
                loop_frame.iteration = iteration;
                loop_frame.next_child = 0;
            }
            None => {
                let child_count = match self.program.compiled.nodes.get(loop_frame.node) {
                    Some(CompiledNode::Loop { children, .. }) => children.len(),
                    _ => {
                        return Err(ControllerError::InvalidState {
                            node: loop_frame.node,
                        });
                    }
                };
                loop_frame.next_child = child_count;
            }
        }
        Ok(())
    }

    fn selection(&self, sampler_id: ElementId) -> SampleSelection {
        let path = self
            .stack
            .iter()
            .filter_map(|frame| {
                self.program
                    .compiled
                    .nodes
                    .get(frame.node)
                    .and_then(|node| match node {
                        CompiledNode::Simple { id, .. } => Some(ControllerCursor {
                            id: *id,
                            kind: ControllerKind::Simple,
                            iteration: 0,
                        }),
                        CompiledNode::Loop { id, .. } => Some(ControllerCursor {
                            id: *id,
                            kind: ControllerKind::Loop,
                            iteration: frame.iteration,
                        }),
                        CompiledNode::Sample { .. } => None,
                    })
            })
            .collect();
        SampleSelection {
            sampler_id,
            execution_iteration: self.completed_iterations,
            path,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum FrameAction {
    Select(NodeIndex),
    Finish,
    AdvanceLoop,
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "tests use expect to make the asserted deterministic setup failure explicit"
)]
mod tests {
    use super::*;

    fn ids(trace: &ExecutionTrace) -> Vec<ElementId> {
        trace
            .samples
            .iter()
            .map(|sample| sample.sampler_id)
            .collect()
    }

    fn run(root: ControllerNode, max_samples: usize, max_transitions: usize) -> ExecutionTrace {
        let program = ControllerProgram::compile(root).expect("test plan compiles");
        let mut runner = program.runner();
        runner
            .run_to_completion(&mut RunBudget::new(max_samples, max_transitions))
            .expect("bounded test plan completes")
    }

    #[test]
    fn simple_controller_preserves_order() {
        let trace = run(
            ControllerNode::simple(
                10,
                vec![ControllerNode::sample(1), ControllerNode::sample(2)],
            ),
            2,
            16,
        );
        assert_eq!(ids(&trace), vec![1, 2]);
        assert_eq!(trace.terminal, ControllerStep::Complete);
        assert_eq!(trace.samples[0].path[0].kind, ControllerKind::Simple);
    }

    #[test]
    fn zero_and_one_iteration_loops_are_distinct_and_bounded() {
        let zero = run(
            ControllerNode::loop_controller(10, LoopCount::zero(), vec![ControllerNode::sample(1)]),
            0,
            8,
        );
        assert!(zero.samples.is_empty());

        let one = run(
            ControllerNode::loop_controller(
                10,
                LoopCount::finite(1),
                vec![ControllerNode::sample(1)],
            ),
            1,
            8,
        );
        assert_eq!(ids(&one), vec![1]);
        assert_eq!(one.samples[0].path[0].iteration, 0);
    }

    #[test]
    fn finite_loop_repeats_in_order() {
        let trace = run(
            ControllerNode::loop_controller(
                10,
                LoopCount::finite(3),
                vec![ControllerNode::sample(1), ControllerNode::sample(2)],
            ),
            6,
            32,
        );
        assert_eq!(ids(&trace), vec![1, 2, 1, 2, 1, 2]);
        let iterations: Vec<u64> = trace
            .samples
            .iter()
            .map(|sample| sample.path[0].iteration)
            .collect();
        assert_eq!(iterations, vec![0, 0, 1, 1, 2, 2]);
    }

    #[test]
    fn nested_loops_are_depth_first_and_multiply_visits() {
        let trace = run(
            ControllerNode::loop_controller(
                100,
                LoopCount::finite(2),
                vec![ControllerNode::loop_controller(
                    200,
                    LoopCount::finite(2),
                    vec![ControllerNode::sample(1)],
                )],
            ),
            4,
            64,
        );
        assert_eq!(ids(&trace), vec![1, 1, 1, 1]);
        assert_eq!(trace.samples[0].path[0].iteration, 0);
        assert_eq!(trace.samples[0].path[1].iteration, 0);
        assert_eq!(trace.samples[1].path[1].iteration, 1);
        assert_eq!(trace.samples[2].path[0].iteration, 1);
    }

    #[test]
    fn forever_loop_requires_external_sample_budget() {
        let program = ControllerProgram::compile(ControllerNode::loop_controller(
            10,
            LoopCount::forever(),
            vec![ControllerNode::sample(1)],
        ))
        .expect("test plan compiles");
        let mut runner = program.runner();
        let error = runner
            .run_to_completion(&mut RunBudget::new(3, 32))
            .expect_err("forever loop must stop at the external budget");
        assert_eq!(
            error,
            ControllerError::SampleBudgetExhausted {
                emitted: 3,
                limit: 3
            }
        );
    }

    #[test]
    fn empty_forever_loop_hits_transition_budget_without_spinning() {
        let program = ControllerProgram::compile(ControllerNode::loop_controller(
            10,
            LoopCount::forever(),
            Vec::new(),
        ))
        .expect("test plan compiles");
        let mut runner = program.runner();
        let error = runner
            .run_to_completion(&mut RunBudget::new(1, 5))
            .expect_err("empty forever loop must be bounded");
        assert!(matches!(
            error,
            ControllerError::StepBudgetExhausted { .. }
                | ControllerError::RunBudgetExhausted { .. }
        ));
    }

    #[test]
    fn forever_iteration_counter_overflow_is_typed() {
        let program = ControllerProgram::compile(ControllerNode::loop_controller(
            10,
            LoopCount::forever(),
            vec![ControllerNode::sample(1)],
        ))
        .expect("test plan compiles");
        let mut runner = program.runner();
        let mut budget = StepBudget::new(16);
        assert!(matches!(
            runner.step(&mut budget).expect("first sample"),
            ControllerStep::Sample(_)
        ));
        // Reaching this value naturally would require an unbounded run. The
        // test places the diagnostic cursor at the boundary to exercise the
        // checked transition without a wall-clock wait or a giant trace.
        runner.stack[0].iteration = u64::MAX;
        let mut budget = StepBudget::new(16);
        assert_eq!(
            runner
                .step(&mut budget)
                .expect_err("overflow must be reported"),
            ControllerError::IterationOverflow { controller: 10 }
        );
    }

    #[test]
    fn next_loop_skips_nested_remainder_at_boundary() {
        let program = ControllerProgram::compile(ControllerNode::loop_controller(
            10,
            LoopCount::finite(2),
            vec![ControllerNode::sample(1), ControllerNode::sample(2)],
        ))
        .expect("test plan compiles");
        let mut runner = program.runner();
        let mut budget = StepBudget::new(16);
        assert_eq!(
            runner.step(&mut budget).expect("sample"),
            ControllerStep::Sample(SampleSelection {
                sampler_id: 1,
                execution_iteration: 0,
                path: vec![ControllerCursor {
                    id: 10,
                    kind: ControllerKind::Loop,
                    iteration: 0
                }],
            })
        );
        let mut budget = StepBudget::new(16);
        assert_eq!(
            runner
                .step_with_signal(ControlSignal::NextLoop, &mut budget)
                .expect("next loop"),
            ControllerStep::Sample(SampleSelection {
                sampler_id: 1,
                execution_iteration: 0,
                path: vec![ControllerCursor {
                    id: 10,
                    kind: ControllerKind::Loop,
                    iteration: 1
                }],
            })
        );
    }

    #[test]
    fn stop_signals_are_distinct_and_monotonic() {
        assert_eq!(
            ControlSignal::Continue.combine(ControlSignal::NextLoop),
            ControlSignal::NextLoop
        );
        assert_eq!(
            ControlSignal::StopThread.combine(ControlSignal::StopTestGraceful),
            ControlSignal::StopTestGraceful
        );
        assert_eq!(
            ControlSignal::StopTestImmediate.combine(ControlSignal::Continue),
            ControlSignal::StopTestImmediate
        );

        let cancellation = Cancellation::new();
        cancellation.request(ControlSignal::StopThread);
        cancellation.request(ControlSignal::Continue);
        cancellation.request(ControlSignal::StopTestImmediate);
        assert_eq!(cancellation.signal(), ControlSignal::StopTestImmediate);
    }

    #[test]
    fn stop_is_observed_before_selecting_another_sampler() {
        let program = ControllerProgram::compile(ControllerNode::simple(
            10,
            vec![ControllerNode::sample(1), ControllerNode::sample(2)],
        ))
        .expect("test plan compiles");
        let mut runner = program.runner();
        let mut budget = StepBudget::new(8);
        let first = runner.step(&mut budget).expect("sample");
        assert!(matches!(first, ControllerStep::Sample(_)));
        let mut budget = StepBudget::new(8);
        assert_eq!(
            runner
                .step_with_signal(ControlSignal::StopThread, &mut budget)
                .expect("stop"),
            ControllerStep::Stopped(ControlSignal::StopThread)
        );
        let mut budget = StepBudget::new(8);
        assert_eq!(
            runner
                .step_with_signal(ControlSignal::StopTestGraceful, &mut budget)
                .expect("escalated stop"),
            ControllerStep::Stopped(ControlSignal::StopTestGraceful)
        );
    }

    #[test]
    fn reset_restores_iteration_and_trace() {
        let program = ControllerProgram::compile(ControllerNode::loop_controller(
            10,
            LoopCount::finite(2),
            vec![ControllerNode::sample(1)],
        ))
        .expect("test plan compiles");
        let mut runner = program.runner();
        let first = runner
            .run_to_completion(&mut RunBudget::new(2, 16))
            .expect("complete");
        assert_eq!(ids(&first), vec![1, 1]);
        assert_eq!(runner.completed_iterations(), 1);
        runner.reset();
        assert_eq!(runner.completed_iterations(), 0);
        let second = runner
            .run_to_completion(&mut RunBudget::new(2, 16))
            .expect("complete after reset");
        assert_eq!(ids(&second), vec![1, 1]);
        assert_eq!(second.samples[0].execution_iteration, 0);
    }

    #[test]
    fn clone_for_user_does_not_share_counters() {
        let program = ControllerProgram::compile(ControllerNode::loop_controller(
            10,
            LoopCount::finite(2),
            vec![ControllerNode::sample(1)],
        ))
        .expect("test plan compiles");
        let mut first = program.runner();
        let mut second = first.clone_for_user();
        let mut first_budget = StepBudget::new(16);
        let mut second_budget = StepBudget::new(16);
        let first_sample = first.step(&mut first_budget).expect("first sample");
        let second_sample = second.step(&mut second_budget).expect("second sample");
        assert_eq!(first_sample, second_sample);
        let mut first_budget = StepBudget::new(16);
        let first_next = first.step(&mut first_budget).expect("first next sample");
        let mut second_budget = StepBudget::new(16);
        let second_next = second.step(&mut second_budget).expect("second next sample");
        assert_eq!(first_next, second_next);
        assert_eq!(first.completed_iterations(), 0);
        assert_eq!(second.completed_iterations(), 0);
    }

    #[test]
    fn unsupported_controllers_fail_explicitly_and_limits_are_enforced() {
        let error = ControllerProgram::compile(ControllerNode::unsupported(9, "IfController"))
            .expect_err("unsupported controller must not silently disappear");
        assert_eq!(
            error,
            ControllerError::UnsupportedController {
                id: 9,
                kind: "IfController".to_owned()
            }
        );
        let limits = ControllerLimits::new(2, 4).expect("valid limits");
        let too_large = ControllerProgram::compile_with_limits(
            ControllerNode::simple(
                1,
                vec![ControllerNode::sample(2), ControllerNode::sample(3)],
            ),
            limits,
        )
        .expect_err("node limit");
        assert!(matches!(too_large, ControllerError::PlanTooLarge { .. }));
        assert!(matches!(
            LoopCount::from_jmeter(-2),
            Err(ControllerError::InvalidLoopCount { value: -2 })
        ));
    }

    #[test]
    fn duplicate_legacy_element_ids_are_rejected_before_execution() {
        let error = ControllerProgram::compile(ControllerNode::simple(
            1,
            vec![ControllerNode::sample(2), ControllerNode::sample(2)],
        ))
        .expect_err("duplicate identity");
        assert_eq!(error, ControllerError::DuplicateElementId { id: 2 });
    }

    #[test]
    fn zero_step_budget_is_a_typed_failure() {
        let program = ControllerProgram::compile(ControllerNode::sample(1)).expect("compile");
        let mut runner = program.runner();
        let mut budget = StepBudget::new(0);
        assert_eq!(
            runner
                .step(&mut budget)
                .expect_err("no transitions allowed"),
            ControllerError::StepBudgetExhausted { used: 0, limit: 0 }
        );
    }

    #[test]
    fn per_user_next_loop_and_stop_thread_are_local_while_test_stops_are_shared() {
        let run = Cancellation::new();
        let first = run.clone_for_user();
        let second = run.clone_for_user();

        first.request(ControlSignal::NextLoop);
        assert_eq!(first.signal(), ControlSignal::NextLoop);
        assert_eq!(second.signal(), ControlSignal::Continue);
        assert_eq!(first.take_signal(), ControlSignal::NextLoop);
        assert_eq!(first.take_signal(), ControlSignal::Continue);

        first.request(ControlSignal::StopThread);
        assert_eq!(first.signal(), ControlSignal::StopThread);
        assert_eq!(second.signal(), ControlSignal::Continue);
        first.request(ControlSignal::StopTestGraceful);
        assert_eq!(second.signal(), ControlSignal::StopTestGraceful);
    }

    #[test]
    fn sample_budget_is_checked_before_root_selection() {
        let program =
            ControllerProgram::compile(ControllerNode::sample(1)).expect("sample plan compiles");
        let mut runner = program.runner();
        let error = runner
            .run_to_completion(&mut RunBudget::new(0, 4))
            .expect_err("zero sample budget");
        assert_eq!(
            error,
            ControllerError::SampleBudgetExhausted {
                emitted: 0,
                limit: 0
            }
        );
        assert_eq!(runner.completed_iterations(), 0);
    }
}
