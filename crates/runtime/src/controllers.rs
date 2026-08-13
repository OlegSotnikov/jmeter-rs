// SPDX-License-Identifier: Apache-2.0
//! Deterministic state machines for the ordered controller subset.
//!
//! The public plan types in this module are intentionally executor-neutral.
//! They are a small adaptation seam for the semantic model and do not claim
//! to be the model's final representation. A caller compiles a tree once and
//! creates one [`ControllerRunner`] per virtual user. A runner owns all mutable
//! traversal state, so a user cannot share loop counters with another user.
//!
//! [`ControllerNode`] is the dependency-free traversal seam: it handles
//! ordered/looping structure, disabled ancestry, Once Only/Interleave, and
//! explicitly seeded random contracts.  The complete expression- and
//! context-driven controller vocabulary is provided by the sibling
//! [`crate::LogicNode`] state machine.  This module does not guess those
//! semantics; callers must use that typed machine or receive an explicit
//! unsupported-controller error.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

/// An executor-neutral identifier for a sampler or controller.
pub type ElementId = u64;

type NodeIndex = usize;

const DEFAULT_MAX_NODES: usize = 16_384;
const DEFAULT_MAX_DEPTH: usize = 128;
const MAX_ALLOWED_NODES: usize = 1_048_576;
const MAX_ALLOWED_DEPTH: usize = 4_096;
const MAX_CONTROLLER_KIND_BYTES: usize = 4_096;

/// A deterministic SplitMix64 increment.  Random controller state is kept in
/// the runner and is never sourced from a process-global or ambient RNG.
const SPLITMIX64_INCREMENT: u64 = 0x9E37_79B9_7F4A_7C15;

/// Returns an unbiased index for one deterministic random value.  The caller
/// must retry with a fresh value when the value is in the rejected prefix.
fn uniform_index(value: u64, bound: usize) -> Option<usize> {
    let bound = u64::try_from(bound).ok()?;
    if bound == 0 {
        return None;
    }
    let remainder = u64::MAX % bound;
    let threshold = (remainder + 1) % bound;
    if value < threshold {
        return None;
    }
    usize::try_from(value % bound).ok()
}

/// Advances a SplitMix64 stream.  The wrapping operations are the specified
/// PRNG algorithm, rather than resource-limit arithmetic.
fn next_seeded_value(state: &mut u64) -> u64 {
    *state = state.wrapping_add(SPLITMIX64_INCREMENT);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

fn restore_random_state(
    states: &mut BTreeMap<ElementId, u64>,
    id: ElementId,
    previous: Option<u64>,
) {
    if let Some(previous) = previous {
        states.insert(id, previous);
    } else {
        states.remove(&id);
    }
}

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
    /// A disabled source element.  Compilation retains the source identity for
    /// validation while the executable projection removes the complete
    /// descendant subtree, including unsupported descendants.
    Disabled {
        /// The identity of the disabled controller.
        id: ElementId,
        /// Source descendants retained only for bounded validation.
        children: Vec<Self>,
    },
    /// A controller that admits its children only on the first root
    /// iteration of one virtual user.
    OnceOnly {
        /// The identity of this controller.
        id: ElementId,
        /// Children in execution order.
        children: Vec<Self>,
    },
    /// A controller that selects one child in round-robin order on each
    /// entry.  The cursor is retained across root iterations for one user.
    Interleave {
        /// The identity of this controller.
        id: ElementId,
        /// Children in execution order.
        children: Vec<Self>,
    },
    /// A controller that selects one child using an explicit deterministic
    /// seed on each entry.
    Random {
        /// The identity of this controller.
        id: ElementId,
        /// Seed for the per-user deterministic stream.
        seed: u64,
        /// Children in execution order.
        children: Vec<Self>,
    },
    /// A controller that visits every child once in a deterministic seeded
    /// permutation on each entry.
    RandomOrder {
        /// The identity of this controller.
        id: ElementId,
        /// Seed for the per-user deterministic stream.
        seed: u64,
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

    /// Creates a disabled source controller.  Disabled descendants are
    /// validated for bounded size/identity but are never executable.
    #[must_use]
    pub fn disabled(id: ElementId, children: Vec<Self>) -> Self {
        Self::Disabled { id, children }
    }

    /// Creates a Once Only controller.
    #[must_use]
    pub fn once_only(id: ElementId, children: Vec<Self>) -> Self {
        Self::OnceOnly { id, children }
    }

    /// Creates an Interleave controller with deterministic round-robin
    /// selection.
    #[must_use]
    pub fn interleave(id: ElementId, children: Vec<Self>) -> Self {
        Self::Interleave { id, children }
    }

    /// Creates a Random controller whose stream is explicitly seeded.
    #[must_use]
    pub fn random(id: ElementId, seed: u64, children: Vec<Self>) -> Self {
        Self::Random { id, seed, children }
    }

    /// Creates a Random Order controller whose stream is explicitly seeded.
    #[must_use]
    pub fn random_order(id: ElementId, seed: u64, children: Vec<Self>) -> Self {
        Self::RandomOrder { id, seed, children }
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
    /// A first-root-iteration-only controller.
    OnceOnly,
    /// A round-robin one-child controller.
    Interleave,
    /// A one-child seeded random controller.
    Random,
    /// A seeded random permutation controller.
    RandomOrder,
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
    /// Node count and depth are capped to keep source-tree conversion bounded.
    pub const fn new(max_nodes: usize, max_depth: usize) -> Result<Self, ControllerError> {
        if max_nodes > MAX_ALLOWED_NODES || max_depth > MAX_ALLOWED_DEPTH {
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
    /// A bounded counter or index could not be incremented without wrapping.
    CounterOverflow {
        /// Stable name of the counter that reached its representational limit.
        counter: &'static str,
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
                "controller limits exceed the bounded policy: max_nodes={max_nodes}, max_depth={max_depth}"
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
            Self::CounterOverflow { counter } => {
                write!(formatter, "controller counter {counter} overflowed")
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
            Self::CounterOverflow { .. } => "runtime.controller.counter-overflow",
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
        match self.limit.checked_sub(self.used) {
            Some(remaining) => remaining,
            None => 0,
        }
    }

    fn spend(&mut self) -> Result<(), ControllerError> {
        if self.used >= self.limit {
            return Err(ControllerError::StepBudgetExhausted {
                used: self.used,
                limit: self.limit,
            });
        }
        self.used = self
            .used
            .checked_add(1)
            .ok_or(ControllerError::CounterOverflow {
                counter: "step-budget",
            })?;
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

    fn record_step(&mut self, budget: StepBudget) -> Result<(), ControllerError> {
        self.transitions = self.transitions.checked_add(budget.used()).ok_or(
            ControllerError::CounterOverflow {
                counter: "run-budget.transitions",
            },
        )?;
        Ok(())
    }

    fn reserve_sample(&mut self) -> Result<(), ControllerError> {
        if self.emitted >= self.max_samples {
            return Err(ControllerError::SampleBudgetExhausted {
                emitted: self.emitted,
                limit: self.max_samples,
            });
        }
        self.emitted = self
            .emitted
            .checked_add(1)
            .ok_or(ControllerError::CounterOverflow {
                counter: "run-budget.samples",
            })?;
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
    Disabled {
        id: ElementId,
    },
    OnceOnly {
        id: ElementId,
        children: Box<[NodeIndex]>,
    },
    Interleave {
        id: ElementId,
        children: Box<[NodeIndex]>,
    },
    Random {
        id: ElementId,
        seed: u64,
        children: Box<[NodeIndex]>,
    },
    RandomOrder {
        id: ElementId,
        seed: u64,
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
    InspectDisabled {
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
    // Every source node is accounted before descendants are scheduled, so the
    // task/result vectors stay proportional to the configured node bound;
    // depth is checked before any child task is scheduled.
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
                account_source_node(node, depth, limits, &mut seen, &mut seen_ids)?;
                match node {
                    ControllerNode::Sample { id } => {
                        let index = nodes.len();
                        nodes.push(CompiledNode::Sample { id: *id });
                        results.push(index);
                    }
                    ControllerNode::Disabled { id, children } => {
                        let index = nodes.len();
                        nodes.push(CompiledNode::Disabled { id: *id });
                        results.push(index);
                        ensure_child_capacity(children.len(), seen, limits)?;
                        let child_depth =
                            depth
                                .checked_add(1)
                                .ok_or(ControllerError::CounterOverflow {
                                    counter: "controller-depth",
                                })?;
                        // Disabled descendants remain subject to resource and
                        // identity validation, but their unsupported kinds
                        // cannot reject an executable plan because the whole
                        // subtree is intentionally removed before traversal.
                        for child in children.iter().rev() {
                            tasks.push(CompileTask::InspectDisabled {
                                node: child,
                                depth: child_depth,
                            });
                        }
                    }
                    ControllerNode::Unsupported { id, kind } => {
                        return Err(ControllerError::UnsupportedController {
                            id: *id,
                            // The enum variant is public, so callers can
                            // construct it without going through
                            // `ControllerNode::unsupported`. Keep the
                            // diagnostic bounded at the compilation
                            // boundary as well as at the convenience
                            // constructor.
                            kind: bounded_kind(kind.clone()),
                        });
                    }
                    ControllerNode::Simple { children, .. }
                    | ControllerNode::Loop { children, .. }
                    | ControllerNode::OnceOnly { children, .. }
                    | ControllerNode::Interleave { children, .. }
                    | ControllerNode::Random { children, .. }
                    | ControllerNode::RandomOrder { children, .. } => {
                        ensure_child_capacity(children.len(), seen, limits)?;
                        tasks.push(CompileTask::Build { node });
                        let child_depth =
                            depth
                                .checked_add(1)
                                .ok_or(ControllerError::CounterOverflow {
                                    counter: "controller-depth",
                                })?;
                        for child in children.iter().rev() {
                            tasks.push(CompileTask::Enter {
                                node: child,
                                depth: child_depth,
                            });
                        }
                    }
                }
            }
            CompileTask::InspectDisabled { node, depth } => {
                account_source_node(node, depth, limits, &mut seen, &mut seen_ids)?;
                let Some(children) = source_children(node) else {
                    continue;
                };
                ensure_child_capacity(children.len(), seen, limits)?;
                let child_depth = depth
                    .checked_add(1)
                    .ok_or(ControllerError::CounterOverflow {
                        counter: "controller-depth",
                    })?;
                for child in children.iter().rev() {
                    tasks.push(CompileTask::InspectDisabled {
                        node: child,
                        depth: child_depth,
                    });
                }
            }
            CompileTask::Build { node } => {
                let child_count = match node {
                    ControllerNode::Simple { children, .. }
                    | ControllerNode::Loop { children, .. }
                    | ControllerNode::OnceOnly { children, .. }
                    | ControllerNode::Interleave { children, .. }
                    | ControllerNode::Random { children, .. }
                    | ControllerNode::RandomOrder { children, .. } => children.len(),
                    ControllerNode::Sample { .. }
                    | ControllerNode::Disabled { .. }
                    | ControllerNode::Unsupported { .. } => {
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
                    ControllerNode::OnceOnly { id, .. } => CompiledNode::OnceOnly {
                        id: *id,
                        children: children.into_boxed_slice(),
                    },
                    ControllerNode::Interleave { id, .. } => CompiledNode::Interleave {
                        id: *id,
                        children: children.into_boxed_slice(),
                    },
                    ControllerNode::Random { id, seed, .. } => CompiledNode::Random {
                        id: *id,
                        seed: *seed,
                        children: children.into_boxed_slice(),
                    },
                    ControllerNode::RandomOrder { id, seed, .. } => CompiledNode::RandomOrder {
                        id: *id,
                        seed: *seed,
                        children: children.into_boxed_slice(),
                    },
                    ControllerNode::Sample { .. }
                    | ControllerNode::Disabled { .. }
                    | ControllerNode::Unsupported { .. } => {
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

fn source_id(node: &ControllerNode) -> ElementId {
    match node {
        ControllerNode::Sample { id }
        | ControllerNode::Simple { id, .. }
        | ControllerNode::Loop { id, .. }
        | ControllerNode::Disabled { id, .. }
        | ControllerNode::OnceOnly { id, .. }
        | ControllerNode::Interleave { id, .. }
        | ControllerNode::Random { id, .. }
        | ControllerNode::RandomOrder { id, .. }
        | ControllerNode::Unsupported { id, .. } => *id,
    }
}

fn source_children(node: &ControllerNode) -> Option<&[ControllerNode]> {
    match node {
        ControllerNode::Simple { children, .. }
        | ControllerNode::Loop { children, .. }
        | ControllerNode::Disabled { children, .. }
        | ControllerNode::OnceOnly { children, .. }
        | ControllerNode::Interleave { children, .. }
        | ControllerNode::Random { children, .. }
        | ControllerNode::RandomOrder { children, .. } => Some(children),
        ControllerNode::Sample { .. } | ControllerNode::Unsupported { .. } => None,
    }
}

fn account_source_node(
    node: &ControllerNode,
    depth: usize,
    limits: ControllerLimits,
    seen: &mut usize,
    seen_ids: &mut BTreeSet<ElementId>,
) -> Result<(), ControllerError> {
    if depth > limits.max_depth {
        return Err(ControllerError::PlanTooDeep {
            depth,
            max_depth: limits.max_depth,
        });
    }
    let next = seen
        .checked_add(1)
        .ok_or(ControllerError::CounterOverflow {
            counter: "controller-nodes",
        })?;
    if next > limits.max_nodes {
        return Err(ControllerError::PlanTooLarge {
            nodes: next,
            max_nodes: limits.max_nodes,
        });
    }
    *seen = next;
    let id = source_id(node);
    if !seen_ids.insert(id) {
        return Err(ControllerError::DuplicateElementId { id });
    }
    Ok(())
}

fn ensure_child_capacity(
    child_count: usize,
    seen: usize,
    limits: ControllerLimits,
) -> Result<(), ControllerError> {
    let remaining = limits
        .max_nodes
        .checked_sub(seen)
        .ok_or(ControllerError::CounterOverflow {
            counter: "controller-node-budget",
        })?;
    if child_count > remaining {
        let nodes = seen
            .checked_add(child_count)
            .ok_or(ControllerError::CounterOverflow {
                counter: "controller-node-budget",
            })?;
        return Err(ControllerError::PlanTooLarge {
            nodes,
            max_nodes: limits.max_nodes,
        });
    }
    Ok(())
}

#[derive(Debug, Clone)]
enum FrameMode {
    /// Ordinary ordered traversal.
    Ordered,
    /// Disabled or already-consumed Once Only subtree.
    Skip,
    /// One-child controller whose selected node is retained until the frame
    /// is popped.
    OneShot { child: Option<NodeIndex> },
    /// Random-order controller.  The order is generated lazily at entry so a
    /// zero-child controller makes no random draw and cannot spin.
    RandomOrder { order: Option<Box<[NodeIndex]>> },
}

#[derive(Debug, Clone, Copy)]
enum CompiledNodeKind {
    Sample,
    Disabled,
    Simple,
    Loop { count: LoopCount },
    OnceOnly,
    Interleave { id: ElementId },
    Random { id: ElementId, seed: u64 },
    RandomOrder { id: ElementId, seed: u64 },
}

#[derive(Debug, Clone, Copy)]
enum FrameState {
    Ordered,
    Skip,
    OneShot(Option<NodeIndex>),
    RandomOrder {
        child: Option<NodeIndex>,
        missing: bool,
    },
}

#[derive(Debug, Clone)]
struct Frame {
    node: NodeIndex,
    next_child: usize,
    iteration: u64,
    mode: FrameMode,
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
    once_done: BTreeSet<ElementId>,
    interleave_next: BTreeMap<ElementId, usize>,
    random_states: BTreeMap<ElementId, u64>,
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
            once_done: BTreeSet::new(),
            interleave_next: BTreeMap::new(),
            random_states: BTreeMap::new(),
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
        self.once_done.clear();
        self.interleave_next.clear();
        self.random_states.clear();
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
                CompiledNode::OnceOnly { id, .. } if *id == controller => Some(0),
                CompiledNode::Interleave { id, .. } if *id == controller => Some(0),
                CompiledNode::Random { id, .. } if *id == controller => Some(0),
                CompiledNode::RandomOrder { id, .. } if *id == controller => Some(0),
                CompiledNode::Sample { .. } => None,
                CompiledNode::Disabled { .. }
                | CompiledNode::Loop { .. }
                | CompiledNode::Simple { .. }
                | CompiledNode::OnceOnly { .. }
                | CompiledNode::Interleave { .. }
                | CompiledNode::Random { .. }
                | CompiledNode::RandomOrder { .. } => None,
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
        // Peek before executing so a one-shot NextLoop is not lost when the
        // caller supplied an exhausted budget or the cursor reports an
        // invariant error.  A successful transition acknowledges the action
        // afterwards; persistent stop signals remain visible.
        let signal = cancellation.signal();
        let result = self.step_with_signal(signal, budget);
        if result.is_ok() && signal == ControlSignal::NextLoop {
            let _ = cancellation.take_signal();
        }
        result
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
            if !self.finished {
                budget.spend()?;
                self.apply_next_loop()?;
            }
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
            budget.record_step(step_budget)?;
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
            if !self.finished {
                budget.spend()?;
                self.apply_next_loop()?;
            }
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
                    Some(
                        CompiledNode::Simple { .. }
                        | CompiledNode::Loop { .. }
                        | CompiledNode::Disabled { .. }
                        | CompiledNode::OnceOnly { .. }
                        | CompiledNode::Interleave { .. }
                        | CompiledNode::Random { .. }
                        | CompiledNode::RandomOrder { .. },
                    ) => {
                        self.root_started = true;
                        self.push_frame(self.program.compiled.root, 0)?;
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
                let controller = self.root_identity()?;
                let completed_iterations = self
                    .completed_iterations
                    .checked_add(1)
                    .ok_or(ControllerError::IterationOverflow { controller })?;
                self.finished = true;
                self.completed_iterations = completed_iterations;
                return Ok(ControllerStep::Complete);
            };

            let action = self.frame_action(frame_index, budget, run_budget)?;
            match action {
                FrameAction::Select(child) => match self.program.compiled.nodes.get(child) {
                    Some(CompiledNode::Sample { id }) => {
                        return Ok(ControllerStep::Sample(self.selection(*id)));
                    }
                    Some(
                        CompiledNode::Simple { .. }
                        | CompiledNode::Loop { .. }
                        | CompiledNode::Disabled { .. }
                        | CompiledNode::OnceOnly { .. }
                        | CompiledNode::Interleave { .. }
                        | CompiledNode::Random { .. }
                        | CompiledNode::RandomOrder { .. },
                    ) => self.push_frame(child, 0)?,
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
                    frame.mode = FrameMode::Ordered;
                }
            }
        }
    }

    fn push_frame(&mut self, node: NodeIndex, iteration: u64) -> Result<(), ControllerError> {
        let mode = match self.program.compiled.nodes.get(node) {
            Some(CompiledNode::Disabled { .. }) => FrameMode::Skip,
            Some(CompiledNode::OnceOnly { id, .. }) => {
                if self.once_done.insert(*id) {
                    FrameMode::Ordered
                } else {
                    FrameMode::Skip
                }
            }
            Some(CompiledNode::Interleave { .. } | CompiledNode::Random { .. }) => {
                FrameMode::OneShot { child: None }
            }
            Some(CompiledNode::RandomOrder { .. }) => FrameMode::RandomOrder { order: None },
            Some(
                CompiledNode::Sample { .. }
                | CompiledNode::Simple { .. }
                | CompiledNode::Loop { .. },
            ) => FrameMode::Ordered,
            None => return Err(ControllerError::InvalidState { node }),
        };
        self.stack.push(Frame {
            node,
            next_child: 0,
            iteration,
            mode,
        });
        Ok(())
    }

    fn advance_child(&mut self, frame_index: usize) -> Result<(), ControllerError> {
        let frame = self
            .stack
            .get_mut(frame_index)
            .ok_or(ControllerError::InvalidState {
                node: self.program.compiled.root,
            })?;
        frame.next_child =
            frame
                .next_child
                .checked_add(1)
                .ok_or(ControllerError::CounterOverflow {
                    counter: "controller-child-index",
                })?;
        Ok(())
    }

    fn reserve_child_sample(
        &self,
        child: NodeIndex,
        run_budget: &mut RunBudget,
    ) -> Result<(), ControllerError> {
        if matches!(
            self.program.compiled.nodes.get(child),
            Some(CompiledNode::Sample { .. })
        ) {
            run_budget.reserve_sample()?;
        }
        Ok(())
    }

    fn random_index(
        &mut self,
        id: ElementId,
        seed: u64,
        bound: usize,
        budget: &mut StepBudget,
    ) -> Result<usize, ControllerError> {
        if bound <= 1 {
            return Ok(0);
        }
        if u64::try_from(bound).is_err() {
            return Err(ControllerError::CounterOverflow {
                counter: "random-bound",
            });
        }
        let state = self.random_states.entry(id).or_insert(seed);
        loop {
            let value = next_seeded_value(state);
            if let Some(index) = uniform_index(value, bound) {
                return Ok(index);
            }
            // Rejected-prefix draws are bounded transitions, so an
            // adversarial seed cannot turn one controller step into an
            // unbounded loop.
            budget.spend()?;
        }
    }

    fn compiled_node_kind(&self, node: NodeIndex) -> Result<CompiledNodeKind, ControllerError> {
        match self.program.compiled.nodes.get(node) {
            Some(CompiledNode::Sample { .. }) => Ok(CompiledNodeKind::Sample),
            Some(CompiledNode::Disabled { .. }) => Ok(CompiledNodeKind::Disabled),
            Some(CompiledNode::Simple { .. }) => Ok(CompiledNodeKind::Simple),
            Some(CompiledNode::Loop { count, .. }) => Ok(CompiledNodeKind::Loop { count: *count }),
            Some(CompiledNode::OnceOnly { .. }) => Ok(CompiledNodeKind::OnceOnly),
            Some(CompiledNode::Interleave { id, .. }) => {
                Ok(CompiledNodeKind::Interleave { id: *id })
            }
            Some(CompiledNode::Random { id, seed, .. }) => Ok(CompiledNodeKind::Random {
                id: *id,
                seed: *seed,
            }),
            Some(CompiledNode::RandomOrder { id, seed, .. }) => Ok(CompiledNodeKind::RandomOrder {
                id: *id,
                seed: *seed,
            }),
            None => Err(ControllerError::InvalidState { node }),
        }
    }

    fn compiled_children(&self, node: NodeIndex) -> Result<&[NodeIndex], ControllerError> {
        match self.program.compiled.nodes.get(node) {
            Some(CompiledNode::Simple { children, .. })
            | Some(CompiledNode::Loop { children, .. })
            | Some(CompiledNode::OnceOnly { children, .. })
            | Some(CompiledNode::Interleave { children, .. })
            | Some(CompiledNode::Random { children, .. })
            | Some(CompiledNode::RandomOrder { children, .. }) => Ok(children),
            Some(CompiledNode::Sample { .. } | CompiledNode::Disabled { .. }) | None => {
                Err(ControllerError::InvalidState { node })
            }
        }
    }

    fn compiled_child_at(
        &self,
        node: NodeIndex,
        position: usize,
    ) -> Result<Option<NodeIndex>, ControllerError> {
        Ok(self.compiled_children(node)?.get(position).copied())
    }

    fn frame_action(
        &mut self,
        frame_index: usize,
        budget: &mut StepBudget,
        run_budget: &mut RunBudget,
    ) -> Result<FrameAction, ControllerError> {
        let (node, next_child, iteration, mode) = {
            let frame = self
                .stack
                .get(frame_index)
                .ok_or(ControllerError::InvalidState {
                    node: self.program.compiled.root,
                })?;
            let mode = match &frame.mode {
                FrameMode::Ordered => FrameState::Ordered,
                FrameMode::Skip => FrameState::Skip,
                FrameMode::OneShot { child } => FrameState::OneShot(*child),
                FrameMode::RandomOrder { order } => FrameState::RandomOrder {
                    child: order
                        .as_deref()
                        .and_then(|order| order.get(frame.next_child).copied()),
                    missing: order.is_none(),
                },
            };
            (frame.node, frame.next_child, frame.iteration, mode)
        };
        match self.compiled_node_kind(node)? {
            CompiledNodeKind::Sample => Err(ControllerError::InvalidState { node }),
            CompiledNodeKind::Disabled => Ok(FrameAction::Finish),
            CompiledNodeKind::Simple => {
                if let Some(child) = self.compiled_child_at(node, next_child)? {
                    self.reserve_child_sample(child, run_budget)?;
                    self.advance_child(frame_index)?;
                    Ok(FrameAction::Select(child))
                } else {
                    Ok(FrameAction::Finish)
                }
            }
            CompiledNodeKind::Loop { count } => match count {
                LoopCount::Finite(0) => Ok(FrameAction::Finish),
                LoopCount::Finite(_total)
                    if self.compiled_child_at(node, next_child)?.is_some() =>
                {
                    let child = self
                        .compiled_child_at(node, next_child)?
                        .ok_or(ControllerError::InvalidState { node })?;
                    self.reserve_child_sample(child, run_budget)?;
                    self.advance_child(frame_index)?;
                    Ok(FrameAction::Select(child))
                }
                LoopCount::Finite(total) => {
                    let next = iteration
                        .checked_add(1)
                        .ok_or_else(|| self.iteration_overflow(node))?;
                    if next >= total {
                        Ok(FrameAction::Finish)
                    } else {
                        Ok(FrameAction::AdvanceLoop)
                    }
                }
                LoopCount::Forever if self.compiled_child_at(node, next_child)?.is_some() => {
                    let child = self
                        .compiled_child_at(node, next_child)?
                        .ok_or(ControllerError::InvalidState { node })?;
                    self.reserve_child_sample(child, run_budget)?;
                    self.advance_child(frame_index)?;
                    Ok(FrameAction::Select(child))
                }
                LoopCount::Forever => Ok(FrameAction::AdvanceLoop),
            },
            CompiledNodeKind::OnceOnly => {
                if matches!(mode, FrameState::Skip) {
                    return Ok(FrameAction::Finish);
                }
                if let Some(child) = self.compiled_child_at(node, next_child)? {
                    self.reserve_child_sample(child, run_budget)?;
                    self.advance_child(frame_index)?;
                    Ok(FrameAction::Select(child))
                } else {
                    Ok(FrameAction::Finish)
                }
            }
            CompiledNodeKind::Interleave { id } => {
                let child_count = self.compiled_children(node)?.len();
                if child_count == 0 {
                    return Ok(FrameAction::Finish);
                }
                let FrameState::OneShot(selected) = mode else {
                    return Err(ControllerError::InvalidState { node });
                };
                if selected.is_some() {
                    return Ok(FrameAction::Finish);
                }
                let cursor = match self.interleave_next.get(&id) {
                    Some(cursor) => *cursor,
                    None => 0,
                };
                let index = cursor % child_count;
                let child = self
                    .compiled_child_at(node, index)?
                    .ok_or(ControllerError::InvalidState { node })?;
                let next_cursor =
                    cursor
                        .checked_add(1)
                        .ok_or(ControllerError::CounterOverflow {
                            counter: "interleave-cursor",
                        })?;
                self.reserve_child_sample(child, run_budget)?;
                self.interleave_next.insert(id, next_cursor);
                self.stack[frame_index].mode = FrameMode::OneShot { child: Some(child) };
                Ok(FrameAction::Select(child))
            }
            CompiledNodeKind::Random { id, seed } => {
                let child_count = self.compiled_children(node)?.len();
                if child_count == 0 {
                    return Ok(FrameAction::Finish);
                }
                let FrameState::OneShot(selected) = mode else {
                    return Err(ControllerError::InvalidState { node });
                };
                if selected.is_some() {
                    return Ok(FrameAction::Finish);
                }
                let previous_state = self.random_states.get(&id).copied();
                let index = match self.random_index(id, seed, child_count, budget) {
                    Ok(index) => index,
                    Err(error) => {
                        restore_random_state(&mut self.random_states, id, previous_state);
                        return Err(error);
                    }
                };
                let child = self
                    .compiled_child_at(node, index)?
                    .ok_or(ControllerError::InvalidState { node })?;
                if let Err(error) = self.reserve_child_sample(child, run_budget) {
                    restore_random_state(&mut self.random_states, id, previous_state);
                    return Err(error);
                }
                self.stack[frame_index].mode = FrameMode::OneShot { child: Some(child) };
                Ok(FrameAction::Select(child))
            }
            CompiledNodeKind::RandomOrder { id, seed } => {
                let child_count = self.compiled_children(node)?.len();
                if child_count == 0 {
                    return Ok(FrameAction::Finish);
                }
                let FrameState::RandomOrder {
                    child: current_child,
                    missing: order_missing,
                } = mode
                else {
                    return Err(ControllerError::InvalidState { node });
                };
                if order_missing {
                    let previous_state = self.random_states.get(&id).copied();
                    let mut order = self.compiled_children(node)?.to_vec();
                    for position in (1..order.len()).rev() {
                        let bound =
                            position
                                .checked_add(1)
                                .ok_or(ControllerError::CounterOverflow {
                                    counter: "random-order-bound",
                                })?;
                        let index = match self.random_index(id, seed, bound, budget) {
                            Ok(index) => index,
                            Err(error) => {
                                restore_random_state(&mut self.random_states, id, previous_state);
                                return Err(error);
                            }
                        };
                        order.swap(position, index);
                    }
                    if let Some(child) = order.first().copied()
                        && let Err(error) = self.reserve_child_sample(child, run_budget)
                    {
                        restore_random_state(&mut self.random_states, id, previous_state);
                        return Err(error);
                    }
                    self.stack[frame_index].mode = FrameMode::RandomOrder {
                        order: Some(order.into_boxed_slice()),
                    };
                }
                let child = current_child.or_else(|| {
                    self.stack
                        .get(frame_index)
                        .and_then(|frame| match &frame.mode {
                            FrameMode::RandomOrder { order: Some(order) } => {
                                order.get(next_child).copied()
                            }
                            _ => None,
                        })
                });
                let Some(child) = child else {
                    return Ok(FrameAction::Finish);
                };
                if !order_missing {
                    self.reserve_child_sample(child, run_budget)?;
                }
                self.advance_child(frame_index)?;
                Ok(FrameAction::Select(child))
            }
        }
    }

    fn iteration_overflow(&self, node: NodeIndex) -> ControllerError {
        match self.node_identity(node) {
            Some(controller) => ControllerError::IterationOverflow { controller },
            None => ControllerError::CounterOverflow {
                counter: "controller-identity",
            },
        }
    }

    fn root_identity(&self) -> Result<ElementId, ControllerError> {
        self.node_identity(self.program.compiled.root)
            .ok_or(ControllerError::CounterOverflow {
                counter: "controller-identity",
            })
    }

    fn node_identity(&self, node: NodeIndex) -> Option<ElementId> {
        match self.program.compiled.nodes.get(node) {
            Some(
                CompiledNode::Simple { id, .. }
                | CompiledNode::Loop { id, .. }
                | CompiledNode::Disabled { id, .. }
                | CompiledNode::OnceOnly { id, .. }
                | CompiledNode::Interleave { id, .. }
                | CompiledNode::Random { id, .. }
                | CompiledNode::RandomOrder { id, .. }
                | CompiledNode::Sample { id },
            ) => Some(*id),
            None => u64::try_from(node).ok(),
        }
    }

    fn apply_next_loop(&mut self) -> Result<(), ControllerError> {
        if self.finished {
            return Ok(());
        }
        let Some(loop_index) = self.stack.iter().rposition(|frame| {
            matches!(
                self.program.compiled.nodes.get(frame.node),
                Some(CompiledNode::Loop { .. })
            )
        }) else {
            let controller = self.root_identity()?;
            let completed_iterations = self
                .completed_iterations
                .checked_add(1)
                .ok_or(ControllerError::IterationOverflow { controller })?;
            self.stack.clear();
            self.root_started = true;
            self.completed_iterations = completed_iterations;
            self.finished = true;
            return Ok(());
        };

        let frame = self
            .stack
            .get(loop_index)
            .cloned()
            .ok_or(ControllerError::InvalidState {
                node: self.program.compiled.root,
            })?;
        let (controller, count) = match self.program.compiled.nodes.get(frame.node) {
            Some(CompiledNode::Loop { id, count, .. }) => (*id, *count),
            Some(_) | None => return Err(ControllerError::InvalidState { node: frame.node }),
        };
        let next_iteration = match count {
            LoopCount::Finite(total)
                if frame
                    .iteration
                    .checked_add(1)
                    .is_some_and(|next| next >= total) =>
            {
                None
            }
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

        let stack_len = loop_index
            .checked_add(1)
            .ok_or(ControllerError::CounterOverflow {
                counter: "controller-stack-index",
            })?;
        self.stack.truncate(stack_len);
        let loop_frame = self
            .stack
            .get_mut(loop_index)
            .ok_or(ControllerError::InvalidState { node: frame.node })?;
        match next_iteration {
            Some(iteration) => {
                loop_frame.iteration = iteration;
                loop_frame.next_child = 0;
                loop_frame.mode = FrameMode::Ordered;
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
                loop_frame.mode = FrameMode::Ordered;
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
                        CompiledNode::OnceOnly { id, .. } => Some(ControllerCursor {
                            id: *id,
                            kind: ControllerKind::OnceOnly,
                            iteration: 0,
                        }),
                        CompiledNode::Interleave { id, .. } => Some(ControllerCursor {
                            id: *id,
                            kind: ControllerKind::Interleave,
                            iteration: 0,
                        }),
                        CompiledNode::Random { id, .. } => Some(ControllerCursor {
                            id: *id,
                            kind: ControllerKind::Random,
                            iteration: 0,
                        }),
                        CompiledNode::RandomOrder { id, .. } => Some(ControllerCursor {
                            id: *id,
                            kind: ControllerKind::RandomOrder,
                            iteration: 0,
                        }),
                        CompiledNode::Disabled { .. } => None,
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
        assert!(matches!(
            ControllerLimits::new(MAX_ALLOWED_NODES + 1, 1),
            Err(ControllerError::InvalidLimits { .. })
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
    fn cancellation_next_loop_is_not_lost_when_the_first_budget_is_exhausted() {
        let program = ControllerProgram::compile(ControllerNode::loop_controller(
            1,
            LoopCount::finite(2),
            vec![ControllerNode::sample(2)],
        ))
        .expect("compile");
        let mut runner = program.runner();
        let cancellation = Cancellation::new();
        assert!(matches!(
            runner
                .step_with_cancellation(&cancellation, &mut StepBudget::new(8))
                .expect("first sample"),
            ControllerStep::Sample(_)
        ));
        cancellation.request(ControlSignal::NextLoop);
        assert_eq!(
            runner
                .step_with_cancellation(&cancellation, &mut StepBudget::new(0))
                .expect_err("exhausted budget"),
            ControllerError::StepBudgetExhausted { used: 0, limit: 0 }
        );
        assert_eq!(cancellation.signal(), ControlSignal::NextLoop);
        assert!(matches!(
            runner
                .step_with_cancellation(&cancellation, &mut StepBudget::new(8))
                .expect("retry next-loop"),
            ControllerStep::Sample(_)
        ));
        assert_eq!(cancellation.signal(), ControlSignal::Continue);
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

    #[test]
    fn sample_budget_failure_does_not_consume_a_nested_selection() {
        let program =
            ControllerProgram::compile(ControllerNode::simple(1, vec![ControllerNode::sample(2)]))
                .expect("compile");
        let mut runner = program.runner();
        let error = runner
            .run_to_completion(&mut RunBudget::new(0, 8))
            .expect_err("sample budget");
        assert_eq!(
            error,
            ControllerError::SampleBudgetExhausted {
                emitted: 0,
                limit: 0
            }
        );
        let trace = runner
            .run_to_completion(&mut RunBudget::new(1, 8))
            .expect("retry with a larger budget");
        assert_eq!(ids(&trace), vec![2]);
    }

    #[test]
    fn random_order_sample_budget_failure_retries_the_same_seeded_order() {
        let root = ControllerNode::random_order(
            1,
            0x1234,
            vec![ControllerNode::sample(2), ControllerNode::sample(3)],
        );
        let program = ControllerProgram::compile(root).expect("compile");
        let mut runner = program.runner();
        assert_eq!(
            runner
                .run_to_completion(&mut RunBudget::new(0, 16))
                .expect_err("sample budget"),
            ControllerError::SampleBudgetExhausted {
                emitted: 0,
                limit: 0
            }
        );
        let retry = runner
            .run_to_completion(&mut RunBudget::new(2, 32))
            .expect("retry seeded order");

        let mut fresh = program.runner();
        let expected = fresh
            .run_to_completion(&mut RunBudget::new(2, 32))
            .expect("fresh seeded order");
        assert_eq!(ids(&retry), ids(&expected));
    }

    #[test]
    fn one_child_selection_budget_failures_leave_controller_state_retryable() {
        let interleave = ControllerProgram::compile(ControllerNode::interleave(
            1,
            vec![ControllerNode::sample(2), ControllerNode::sample(3)],
        ))
        .expect("interleave compiles");
        let mut interleave_runner = interleave.runner();
        assert!(matches!(
            interleave_runner.run_to_completion(&mut RunBudget::new(0, 16)),
            Err(ControllerError::SampleBudgetExhausted { .. })
        ));
        let retry = interleave_runner
            .run_to_completion(&mut RunBudget::new(1, 16))
            .expect("interleave retry");
        assert_eq!(ids(&retry), vec![2]);

        let random = ControllerProgram::compile(ControllerNode::random(
            4,
            0xCAFE,
            vec![ControllerNode::sample(5), ControllerNode::sample(6)],
        ))
        .expect("random controller compiles");
        let mut random_runner = random.runner();
        assert!(matches!(
            random_runner.run_to_completion(&mut RunBudget::new(0, 16)),
            Err(ControllerError::SampleBudgetExhausted { .. })
        ));
        let retry = random_runner
            .run_to_completion(&mut RunBudget::new(1, 16))
            .expect("random retry");
        let mut fresh = random.runner();
        let expected = fresh
            .run_to_completion(&mut RunBudget::new(1, 16))
            .expect("fresh random run");
        assert_eq!(ids(&retry), ids(&expected));
    }

    #[test]
    fn interleave_cursor_overflow_is_reported_before_sample_reservation() {
        let program = ControllerProgram::compile(ControllerNode::interleave(
            1,
            vec![ControllerNode::sample(2)],
        ))
        .expect("interleave compiles");
        let mut runner = program.runner();
        runner.interleave_next.insert(1, usize::MAX);
        let mut budget = StepBudget::new(16);
        assert_eq!(
            runner
                .step(&mut budget)
                .expect_err("cursor overflow must be typed"),
            ControllerError::CounterOverflow {
                counter: "interleave-cursor"
            }
        );
    }

    #[test]
    fn root_iteration_overflow_reports_the_root_element_identity() {
        let program = ControllerProgram::compile(ControllerNode::simple(42, Vec::new()))
            .expect("empty root compiles");
        let mut runner = program.runner();
        runner.completed_iterations = u64::MAX;
        let mut budget = StepBudget::new(8);
        assert_eq!(
            runner
                .step(&mut budget)
                .expect_err("root iteration must use checked arithmetic"),
            ControllerError::IterationOverflow { controller: 42 }
        );
    }

    #[test]
    fn unsupported_variant_diagnostics_are_bounded_at_compile_time() {
        let error = ControllerProgram::compile(ControllerNode::Unsupported {
            id: 9,
            kind: "x".repeat(MAX_CONTROLLER_KIND_BYTES + 1),
        })
        .expect_err("unsupported controller must fail during compilation");
        let ControllerError::UnsupportedController { kind, .. } = error else {
            panic!("expected unsupported-controller error");
        };
        assert_eq!(kind.len(), MAX_CONTROLLER_KIND_BYTES);
    }

    #[test]
    fn finite_loop_model_matches_trace_for_generated_counts_and_children() {
        for count in 0..=8_u64 {
            for child_count in 0..=4_u64 {
                let children: Vec<_> = (0..child_count)
                    .map(|id| ControllerNode::sample(100 + id))
                    .collect();
                let expected: Vec<_> = (0..count)
                    .flat_map(|_| (0..child_count).map(|id| 100 + id))
                    .collect();
                let program = ControllerProgram::compile(ControllerNode::loop_controller(
                    1,
                    LoopCount::finite(count),
                    children,
                ))
                .expect("generated finite loop compiles");
                let mut runner = program.runner();
                let trace = runner
                    .run_to_completion(&mut RunBudget::new(expected.len(), 1_000))
                    .expect("generated finite loop completes");
                assert_eq!(ids(&trace), expected);
                assert_eq!(trace.terminal, ControllerStep::Complete);
            }
        }
    }

    #[test]
    fn next_loop_without_an_active_loop_completes_one_root_iteration() {
        let program =
            ControllerProgram::compile(ControllerNode::simple(42, vec![ControllerNode::sample(1)]))
                .expect("simple plan compiles");
        let mut runner = program.runner();
        let mut budget = StepBudget::new(8);
        assert_eq!(
            runner
                .step_with_signal(ControlSignal::NextLoop, &mut budget)
                .expect("next-loop action completes root"),
            ControllerStep::Complete
        );
        assert_eq!(runner.completed_iterations(), 1);
        let mut budget = StepBudget::new(8);
        assert_eq!(
            runner
                .step_with_signal(ControlSignal::NextLoop, &mut budget)
                .expect("replayed next-loop action is a no-op"),
            ControllerStep::Complete
        );
        assert_eq!(runner.completed_iterations(), 1);
    }

    #[test]
    fn disabled_ancestor_prunes_children_without_executing_unsupported_descendants() {
        let root = ControllerNode::simple(
            1,
            vec![
                ControllerNode::sample(2),
                ControllerNode::disabled(
                    3,
                    vec![ControllerNode::unsupported(4, "plugin.controller")],
                ),
                ControllerNode::sample(5),
            ],
        );
        let program = ControllerProgram::compile(root).expect("disabled subtree compiles");
        let mut runner = program.runner();
        let trace = runner
            .run_to_completion(&mut RunBudget::new(2, 32))
            .expect("disabled subtree is skipped");
        assert_eq!(ids(&trace), vec![2, 5]);
        assert_eq!(trace.terminal, ControllerStep::Complete);
    }

    #[test]
    fn disabled_descendants_still_obey_depth_and_identity_bounds() {
        let root = ControllerNode::disabled(1, vec![ControllerNode::sample(2)]);
        let limits = ControllerLimits::new(8, 0).expect("zero depth is valid");
        assert_eq!(
            ControllerProgram::compile_with_limits(root, limits)
                .expect_err("disabled child depth is source-bounded"),
            ControllerError::PlanTooDeep {
                depth: 1,
                max_depth: 0
            }
        );

        let duplicate = ControllerNode::disabled(1, vec![ControllerNode::sample(1)]);
        assert_eq!(
            ControllerProgram::compile(duplicate).expect_err("identity remains source-visible"),
            ControllerError::DuplicateElementId { id: 1 }
        );
    }

    #[test]
    fn once_only_is_per_user_and_survives_root_iteration_reset_boundary() {
        let program = ControllerProgram::compile(ControllerNode::once_only(
            10,
            vec![ControllerNode::sample(1)],
        ))
        .expect("once-only compiles");
        let mut first = program.runner();
        let mut second = program.runner();

        assert_eq!(
            first
                .run_to_completion(&mut RunBudget::new(1, 16))
                .expect("first user")
                .samples
                .len(),
            1
        );
        first.next_root_iteration().expect("next root");
        assert!(
            first
                .run_to_completion(&mut RunBudget::new(1, 16))
                .expect("once-only second iteration")
                .samples
                .is_empty()
        );

        assert_eq!(
            second
                .run_to_completion(&mut RunBudget::new(1, 16))
                .expect("independent user")
                .samples
                .len(),
            1
        );
    }

    #[test]
    fn interleave_preserves_round_robin_order_across_root_iterations() {
        let program = ControllerProgram::compile(ControllerNode::loop_controller(
            10,
            LoopCount::finite(3),
            vec![ControllerNode::interleave(
                20,
                vec![ControllerNode::sample(1), ControllerNode::sample(2)],
            )],
        ))
        .expect("interleave compiles");
        let mut runner = program.runner();
        let trace = runner
            .run_to_completion(&mut RunBudget::new(3, 64))
            .expect("interleave run");
        assert_eq!(ids(&trace), vec![1, 2, 1]);
        assert!(trace.samples.iter().all(|sample| {
            sample
                .path
                .iter()
                .any(|cursor| cursor.kind == ControllerKind::Interleave)
        }));
    }

    #[test]
    fn seeded_random_and_random_order_are_reproducible_without_ambient_rng() {
        let root = ControllerNode::loop_controller(
            10,
            LoopCount::finite(3),
            vec![ControllerNode::simple(
                11,
                vec![
                    ControllerNode::random(
                        12,
                        0xA5A5,
                        vec![ControllerNode::sample(1), ControllerNode::sample(2)],
                    ),
                    ControllerNode::random_order(
                        13,
                        0x5A5A,
                        vec![
                            ControllerNode::sample(3),
                            ControllerNode::sample(4),
                            ControllerNode::sample(5),
                        ],
                    ),
                ],
            )],
        );
        let first = run(root.clone(), 12, 256);
        let second = run(root, 12, 256);
        assert_eq!(ids(&first), ids(&second));
        assert_eq!(first.samples.len(), 12);

        let different = run(
            ControllerNode::loop_controller(
                10,
                LoopCount::finite(3),
                vec![ControllerNode::random_order(
                    13,
                    0x5A5B,
                    vec![
                        ControllerNode::sample(3),
                        ControllerNode::sample(4),
                        ControllerNode::sample(5),
                    ],
                )],
            ),
            9,
            256,
        );
        assert_ne!(ids(&first), ids(&different));
    }

    #[test]
    fn deep_iterative_compilation_and_traversal_do_not_use_call_stack() {
        let mut root = ControllerNode::sample(9_999);
        for id in 1..=512 {
            root = ControllerNode::simple(id, vec![root]);
        }
        let limits = ControllerLimits::new(1_024, 512).expect("deep limits");
        let program = ControllerProgram::compile_with_limits(root, limits)
            .expect("deep tree compiles iteratively");
        let mut runner = program.runner();
        let trace = runner
            .run_to_completion(&mut RunBudget::new(1, 4_096))
            .expect("deep traversal");
        assert_eq!(ids(&trace), vec![9_999]);
    }

    #[test]
    fn empty_selection_controllers_complete_without_no_progress_spin() {
        for node in [
            ControllerNode::once_only(1, Vec::new()),
            ControllerNode::interleave(2, Vec::new()),
            ControllerNode::random(3, 7, Vec::new()),
            ControllerNode::random_order(4, 7, Vec::new()),
        ] {
            let program = ControllerProgram::compile(node).expect("empty controller compiles");
            let mut runner = program.runner();
            let trace = runner
                .run_to_completion(&mut RunBudget::new(0, 16))
                .expect("empty controller completes");
            assert!(trace.samples.is_empty());
            assert_eq!(trace.terminal, ControllerStep::Complete);
        }
    }

    #[test]
    fn checked_budget_arithmetic_never_saturates() {
        let program = ControllerProgram::compile(ControllerNode::sample(1)).expect("compile");
        let mut runner = program.runner();
        let mut budget = StepBudget::new(usize::MAX);
        budget.used = usize::MAX;
        assert_eq!(
            runner
                .step(&mut budget)
                .expect_err("used budget cannot wrap"),
            ControllerError::StepBudgetExhausted {
                used: usize::MAX,
                limit: usize::MAX
            }
        );
        assert_eq!(budget.remaining(), 0);

        let mut run_budget = RunBudget::new(usize::MAX, usize::MAX);
        run_budget.transitions = usize::MAX;
        let mut spent = StepBudget::new(usize::MAX);
        spent.used = 1;
        assert_eq!(
            run_budget
                .record_step(spent)
                .expect_err("run transition count cannot wrap"),
            ControllerError::CounterOverflow {
                counter: "run-budget.transitions"
            }
        );

        run_budget.emitted = usize::MAX;
        assert_eq!(
            run_budget
                .reserve_sample()
                .expect_err("maximum sample budget rejects without wrapping"),
            ControllerError::SampleBudgetExhausted {
                emitted: usize::MAX,
                limit: usize::MAX
            }
        );
    }

    #[test]
    fn completed_runner_is_idempotent_even_when_next_loop_has_no_budget() {
        let program = ControllerProgram::compile(ControllerNode::simple(1, Vec::new()))
            .expect("empty controller compiles");
        let mut runner = program.runner();
        runner
            .run_to_completion(&mut RunBudget::new(0, 8))
            .expect("empty controller completes");
        let mut no_budget = StepBudget::new(0);
        assert_eq!(
            runner
                .step_with_signal(ControlSignal::NextLoop, &mut no_budget)
                .expect("next-loop after completion is a no-op"),
            ControllerStep::Complete
        );
    }
}
