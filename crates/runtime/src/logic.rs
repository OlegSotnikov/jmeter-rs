// SPDX-License-Identifier: Apache-2.0
//! Stateful logic-controller machines.
//!
//! [`LogicProgram`] is a bounded immutable tree and [`LogicRunner`] owns the
//! mutable state for one virtual user. Every controller in the ELEM-003
//! surface has an explicit node kind. Conditions and substitutions are kept
//! deliberately small and deterministic; JVM/plugin-specific expressions are
//! represented as typed unsupported conditions instead of being guessed.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use crate::{ControlSignal, LoopCount};

const DEFAULT_MAX_NODES: usize = 65_536;
const DEFAULT_MAX_DEPTH: usize = 256;
const DEFAULT_MAX_TRANSITIONS: usize = 65_536;
const MAX_KIND_BYTES: usize = 4_096;

fn bounded_text(value: impl Into<String>) -> String {
    let value = value.into();
    if value.len() <= MAX_KIND_BYTES {
        return value;
    }
    let mut result = value;
    let mut end = MAX_KIND_BYTES;
    while end > 0 && !result.is_char_boundary(end) {
        end -= 1;
    }
    result.truncate(end);
    result
}

fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A deterministic condition accepted by native logic controllers.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    missing_docs,
    reason = "logic condition payload fields are documented by variant semantics"
)]
pub enum LogicCondition {
    /// Always enter the controller.
    Always,
    /// Never enter the controller.
    Never,
    /// Compare a virtual-user variable as an exact string.
    VariableEquals { name: String, value: String },
    /// Interpret a variable as JMeter's true/false expression value.
    VariableBoolean { name: String },
    /// Match the last sample success state.
    LastSampleSuccess { expected: bool },
    /// Native literal boolean expression (`true`, `false`, `1`, `0`).
    Literal(String),
    /// A Java/script expression requiring an external evaluator.
    External { capability_id: String },
}

impl LogicCondition {
    /// Evaluates the condition against runner state.
    pub fn evaluate(
        &self,
        variables: &BTreeMap<String, String>,
        last_sample_success: Option<bool>,
    ) -> Result<bool, LogicControllerError> {
        match self {
            Self::Always => Ok(true),
            Self::Never => Ok(false),
            Self::VariableEquals { name, value } => Ok(variables.get(name) == Some(value)),
            Self::VariableBoolean { name } => {
                Ok(parse_bool(variables.get(name).map(String::as_str)))
            }
            Self::LastSampleSuccess { expected } => Ok(last_sample_success == Some(*expected)),
            Self::Literal(value) => Ok(parse_bool(Some(value.as_str()))),
            Self::External { capability_id } => Err(LogicControllerError::Unsupported {
                controller: "If/While condition".to_owned(),
                capability_id: bounded_text(capability_id.clone()),
            }),
        }
    }
}

fn parse_bool(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "true" | "1" | "yes" | "on"
        )
    })
}

/// Maps one injected 64-bit value to an unbiased index in `[0, bound)`.
///
/// The rejected prefix has the same size as `2^64 % bound`; retrying with a
/// fresh capability value is therefore required instead of using `% bound`,
/// which would bias controller choices whenever the bound does not divide the
/// full random-value domain.
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

/// Implements the pinned ThroughputController decision before accounting for
/// the current visit. JMeter's percentage mode intentionally rounds the
/// numerator by 50 before dividing, so 50% over four visits admits visits
/// two and four rather than relying on a probabilistic draw.
fn throughput_decide(
    counters: ThroughputState,
    mode: ThroughputMode,
    limit: u64,
    percent: f64,
) -> bool {
    match mode {
        ThroughputMode::Total => counters.executions < limit,
        ThroughputMode::Percentage => {
            // JMeter's per-thread field starts at -1 and is incremented to
            // zero before the first decision. The shared global field follows
            // the same observable sequence, so our zero-based visit counter
            // maps directly to the denominator (iterations + 1).
            let iteration = counters.iterations.saturating_add(1);
            let percent = f64::from(percent as f32);
            let estimate = (100.0 * counters.executions as f64 + 50.0) / iteration as f64;
            estimate < percent
        }
    }
}

/// Switch selection policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SwitchSelection {
    /// Select a fixed zero-based child.
    Index(usize),
    /// Read a zero-based child index from a variable.
    ///
    /// An empty value (including an unset variable) selects child zero, and
    /// an index outside the child range also selects child zero. Non-numeric
    /// values require [`Self::VariableWithNames`] so that child names are
    /// available without guessing from sampler IDs.
    Variable(String),
    /// Read a numeric index or child name from a variable.
    ///
    /// `child_names` is ordered in parallel with the `Switch` node's
    /// children. Numeric values use the same zero-based rules as
    /// [`Self::Variable`]. Non-numeric values match a child name exactly; if
    /// no name matches, the first child whose name is `default` (ASCII
    /// case-insensitive) is selected. With neither a name nor a default,
    /// no child is selected.
    ///
    /// This keeps the existing `LogicNode::Switch` shape usable while making
    /// the source names explicit at the compilation boundary. A caller that
    /// only has `Vec<LogicNode>` and no source names must use `Variable`,
    /// which returns an explicit unsupported-capability error for a
    /// non-numeric value instead of silently selecting an arbitrary child.
    VariableWithNames {
        /// Variable containing the Switch Controller value.
        variable: String,
        /// Direct-child names in source order.
        child_names: Vec<String>,
    },
    /// Select using the supplied deterministic random value.
    Random,
}

/// Applies JMeter's numeric Switch Controller selection rules.
///
/// Empty input is the zero index. A decimal numeric value outside the
/// non-negative child range falls back to the first child. JMeter's
/// `StringUtils.isNumeric` accepts only digit-only input, so a sign (`-1`,
/// `+1`) is a name lookup rather than a numeric selection. Parsing as `i32`
/// matches JMeter's integer parser and keeps oversized numeric values on the
/// name-resolution path without panicking or relying on host pointer width.
fn switch_numeric_index(value: &str, child_count: usize) -> Option<usize> {
    if value.is_empty() {
        return Some(0);
    }
    if !value.chars().all(|character| character.is_ascii_digit()) {
        return None;
    }
    // JMeter parses numeric selections with Integer.parseInt. Values outside
    // the signed 32-bit range are therefore treated as names (and may select
    // a `default` child), rather than being silently clamped to child zero.
    let value = value.parse::<i32>().ok()?;
    let index = usize::try_from(value).unwrap_or(usize::MAX);
    Some(if index < child_count { index } else { 0 })
}

/// Resolves a non-numeric Switch Controller value against source child names.
///
/// Name matching is case-sensitive. The fallback child named `default` is
/// matched case-insensitively, and the first matching child wins in source
/// order. Labels beyond the executable child list are ignored so a malformed
/// compiler projection cannot enqueue an impossible child.
fn switch_named_index(value: &str, child_names: &[String], child_count: usize) -> Option<usize> {
    child_names
        .iter()
        .enumerate()
        .find(|(index, name)| *index < child_count && *name == value)
        .map(|(index, _)| index)
        .or_else(|| {
            child_names
                .iter()
                .enumerate()
                .find(|(index, name)| *index < child_count && name.eq_ignore_ascii_case("default"))
                .map(|(index, _)| index)
        })
}

/// Throughput controller mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThroughputMode {
    /// Allow exactly `limit` visits per selected scope.
    Total,
    /// Allow `percent` of visits using JMeter's rounded percentage decision.
    Percentage,
}

/// A full native logic controller node.
#[derive(Clone, Debug, PartialEq)]
#[allow(
    missing_docs,
    reason = "logic node payload fields are documented by variant semantics"
)]
pub enum LogicNode {
    /// Select one sampler.
    Sample { id: u64 },
    /// Visit children in order once.
    Sequence { id: u64, children: Vec<Self> },
    /// Repeat children a finite/forever number of times.
    Loop {
        id: u64,
        count: LoopCount,
        children: Vec<Self>,
    },
    /// Conditional controller.
    If {
        id: u64,
        condition: LogicCondition,
        evaluate_each_iteration: bool,
        children: Vec<Self>,
    },
    /// Condition checked before each body visit.
    While {
        id: u64,
        condition: LogicCondition,
        max_iterations: Option<u64>,
        children: Vec<Self>,
    },
    /// Iterate variables `${prefix}_1` … `${prefix}_matchNr`.
    ForEach {
        id: u64,
        input_prefix: String,
        output_variable: String,
        children: Vec<Self>,
    },
    /// Select one child.
    Switch {
        id: u64,
        selection: SwitchSelection,
        children: Vec<Self>,
    },
    /// Select one child in round-robin order.
    Interleave { id: u64, children: Vec<Self> },
    /// Select one child from a deterministic random value.
    Random { id: u64, children: Vec<Self> },
    /// Visit every child once in a seeded random order.
    RandomOrder { id: u64, children: Vec<Self> },
    /// Visit children only during the first root iteration.
    OnceOnly { id: u64, children: Vec<Self> },
    /// Permit a bounded total or percentage number of visits.
    Throughput {
        id: u64,
        mode: ThroughputMode,
        limit: u64,
        percent: f64,
        per_user: bool,
        children: Vec<Self>,
    },
    /// Stop selecting children after the duration relative to run start.
    Runtime {
        id: u64,
        duration: Duration,
        children: Vec<Self>,
    },
    /// Preserve child result grouping metadata.
    Transaction {
        id: u64,
        parent: bool,
        include_timers: bool,
        children: Vec<Self>,
    },
    /// Replace children with a resolved module target.
    Module { id: u64, target: Option<Box<Self>> },
    /// Replace children with a resolved include target.
    Include { id: u64, target: Option<Box<Self>> },
    /// Recording is a no-op wrapper in non-GUI execution.
    Recording { id: u64, children: Vec<Self> },
    /// Critical section wrapper; lock ownership is represented in the path.
    CriticalSection {
        id: u64,
        lock_name: String,
        children: Vec<Self>,
    },
}

impl LogicNode {
    /// Returns the node identity.
    #[must_use]
    pub const fn id(&self) -> u64 {
        match self {
            Self::Sample { id }
            | Self::Sequence { id, .. }
            | Self::Loop { id, .. }
            | Self::If { id, .. }
            | Self::While { id, .. }
            | Self::ForEach { id, .. }
            | Self::Switch { id, .. }
            | Self::Interleave { id, .. }
            | Self::Random { id, .. }
            | Self::RandomOrder { id, .. }
            | Self::OnceOnly { id, .. }
            | Self::Throughput { id, .. }
            | Self::Runtime { id, .. }
            | Self::Transaction { id, .. }
            | Self::Module { id, .. }
            | Self::Include { id, .. }
            | Self::Recording { id, .. }
            | Self::CriticalSection { id, .. } => *id,
        }
    }

    fn children(&self) -> Option<&[Self]> {
        match self {
            Self::Sequence { children, .. }
            | Self::Loop { children, .. }
            | Self::If { children, .. }
            | Self::While { children, .. }
            | Self::ForEach { children, .. }
            | Self::Switch { children, .. }
            | Self::Interleave { children, .. }
            | Self::Random { children, .. }
            | Self::RandomOrder { children, .. }
            | Self::OnceOnly { children, .. }
            | Self::Throughput { children, .. }
            | Self::Runtime { children, .. }
            | Self::Transaction { children, .. }
            | Self::Recording { children, .. }
            | Self::CriticalSection { children, .. } => Some(children),
            Self::Sample { .. } | Self::Module { .. } | Self::Include { .. } => None,
        }
    }
}

/// Resource policy for a logic program.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogicLimits {
    /// Maximum source node count, including replacement nodes.
    pub max_nodes: usize,
    /// Maximum source depth.
    pub max_depth: usize,
    /// Maximum transitions in one `step` call.
    pub max_transitions: usize,
}

impl Default for LogicLimits {
    fn default() -> Self {
        Self {
            max_nodes: DEFAULT_MAX_NODES,
            max_depth: DEFAULT_MAX_DEPTH,
            max_transitions: DEFAULT_MAX_TRANSITIONS,
        }
    }
}

/// Logic compilation failures.
#[derive(Clone, Debug, PartialEq)]
#[allow(
    missing_docs,
    reason = "error payload fields are documented by variant semantics"
)]
pub enum LogicControllerError {
    /// Source tree exceeds node bound.
    PlanTooLarge { count: usize, limit: usize },
    /// Source tree exceeds depth bound.
    PlanTooDeep { depth: usize, limit: usize },
    /// Work transition bound was exhausted.
    TransitionLimit { used: usize, limit: usize },
    /// A controller requires an unavailable external capability.
    Unsupported {
        controller: String,
        capability_id: String,
    },
    /// A module/include target was not resolved.
    UnresolvedReplacement { controller: u64 },
    /// A switch variable was not an unsigned index.
    InvalidSwitchIndex { controller: u64, value: String },
    /// A ForEach range contains malformed values.
    InvalidForEachValue { controller: u64, variable: String },
    /// A percentage is outside JMeter's accepted range.
    InvalidPercentage { controller: u64, value: f64 },
    /// A global (all-user) throughput controller was run without the
    /// run-scoped state required to coordinate its counters.
    MissingGlobalState { controller: u64 },
    /// Two nodes in one compiled tree use the same controller identity.
    DuplicateControllerId { controller: u64 },
    /// An internal state-machine invariant was violated.
    InvariantViolation { detail: String },
}

impl LogicControllerError {
    /// Returns the stable diagnostic code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::PlanTooLarge { .. } => "runtime.logic.plan-too-large",
            Self::PlanTooDeep { .. } => "runtime.logic.plan-too-deep",
            Self::TransitionLimit { .. } => "runtime.logic.transition-limit",
            Self::Unsupported { .. } => "runtime.logic.unsupported",
            Self::UnresolvedReplacement { .. } => "runtime.logic.unresolved-replacement",
            Self::InvalidSwitchIndex { .. } => "runtime.logic.invalid-switch",
            Self::InvalidForEachValue { .. } => "runtime.logic.invalid-foreach",
            Self::InvalidPercentage { .. } => "runtime.logic.invalid-percentage",
            Self::MissingGlobalState { .. } => "runtime.logic.missing-global-state",
            Self::DuplicateControllerId { .. } => "runtime.logic.duplicate-controller-id",
            Self::InvariantViolation { .. } => "runtime.logic.invariant",
        }
    }
}

impl fmt::Display for LogicControllerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlanTooLarge { count, limit }
            | Self::PlanTooDeep {
                depth: count,
                limit,
            } => {
                write!(formatter, "{}: {count}/{limit}", self.code())
            }
            Self::TransitionLimit { used, limit } => {
                write!(formatter, "{}: {used}/{limit}", self.code())
            }
            Self::Unsupported {
                controller,
                capability_id,
            } => write!(
                formatter,
                "{}: {controller} requires {capability_id}",
                self.code()
            ),
            Self::UnresolvedReplacement { controller } => {
                write!(formatter, "{}: controller {controller}", self.code())
            }
            Self::InvalidSwitchIndex { controller, value } => {
                write!(
                    formatter,
                    "{}: controller {controller}, value {value:?}",
                    self.code()
                )
            }
            Self::InvalidForEachValue {
                controller,
                variable,
            } => {
                write!(
                    formatter,
                    "{}: controller {controller}, variable {variable:?}",
                    self.code()
                )
            }
            Self::InvalidPercentage { controller, value } => {
                write!(
                    formatter,
                    "{}: controller {controller}, value {value}",
                    self.code()
                )
            }
            Self::MissingGlobalState { controller } => {
                write!(
                    formatter,
                    "{}: controller {controller} requires run-shared state",
                    self.code()
                )
            }
            Self::InvariantViolation { detail } => {
                write!(formatter, "{}: {detail}", self.code())
            }
            Self::DuplicateControllerId { controller } => {
                write!(formatter, "{}: controller {controller}", self.code())
            }
        }
    }
}

impl std::error::Error for LogicControllerError {}

/// Immutable compiled logic program.
#[derive(Clone, Debug)]
pub struct LogicProgram {
    root: Arc<LogicNode>,
    limits: LogicLimits,
    uses_random: bool,
}

/// Run-shared state used by throughput controllers configured for all-user
/// scope. Per-user throughput counters remain in each [`LogicRunner`].
#[derive(Debug, Default)]
pub struct LogicSharedState {
    throughput: Mutex<BTreeMap<u64, ThroughputState>>,
}

/// Counters used by one Throughput Controller instance.
///
/// `iterations` is the number of controller visits observed so far and
/// `executions` is the number of visits admitted by the controller. JMeter's
/// percentage mode makes its decision from these two counters; retaining both
/// rather than deriving one from the other also keeps total and percentage
/// modes independent when a plan is reused.
#[derive(Clone, Copy, Debug, Default)]
struct ThroughputState {
    iterations: u64,
    executions: u64,
}

impl LogicProgram {
    /// Compiles with default bounds.
    pub fn compile(root: LogicNode) -> Result<Self, LogicControllerError> {
        Self::compile_with_limits(root, LogicLimits::default())
    }

    /// Compiles with explicit resource bounds.
    pub fn compile_with_limits(
        root: LogicNode,
        limits: LogicLimits,
    ) -> Result<Self, LogicControllerError> {
        let mut stack = vec![(&root, 0usize)];
        let mut count = 0usize;
        let mut uses_random = false;
        let mut seen_ids = BTreeSet::new();
        while let Some((node, depth)) = stack.pop() {
            if depth > limits.max_depth {
                return Err(LogicControllerError::PlanTooDeep {
                    depth,
                    limit: limits.max_depth,
                });
            }
            count = count.saturating_add(1);
            if count > limits.max_nodes {
                return Err(LogicControllerError::PlanTooLarge {
                    count,
                    limit: limits.max_nodes,
                });
            }
            if !seen_ids.insert(node.id()) {
                return Err(LogicControllerError::DuplicateControllerId {
                    controller: node.id(),
                });
            }
            if let Some(children) = node.children() {
                for child in children.iter().rev() {
                    stack.push((child, depth.saturating_add(1)));
                }
            }
            match node {
                LogicNode::Random { children, .. } | LogicNode::RandomOrder { children, .. }
                    if children.len() > 1 =>
                {
                    uses_random = true;
                }
                LogicNode::Switch {
                    selection: SwitchSelection::Random,
                    children,
                    ..
                } if children.len() > 1 => uses_random = true,
                LogicNode::Module { target, .. } | LogicNode::Include { target, .. } => {
                    let replacement =
                        target
                            .as_deref()
                            .ok_or(LogicControllerError::UnresolvedReplacement {
                                controller: node.id(),
                            })?;
                    stack.push((replacement, depth.saturating_add(1)));
                }
                LogicNode::Throughput {
                    id,
                    mode: ThroughputMode::Percentage,
                    percent,
                    ..
                } if !percent.is_finite() || !(0.0..=100.0).contains(percent) => {
                    return Err(LogicControllerError::InvalidPercentage {
                        controller: *id,
                        value: *percent,
                    });
                }
                _ => {}
            }
        }
        Ok(Self {
            root: Arc::new(root),
            limits,
            uses_random,
        })
    }

    /// Creates an independent runner for one virtual user.
    #[must_use]
    pub fn runner(&self) -> LogicRunner {
        LogicRunner::new(self.clone())
    }

    /// Creates a runner using run-shared counters for non-user throughput
    /// controllers. The state object must be newly created for each run.
    #[must_use]
    pub fn runner_with_shared_state(&self, state: Arc<LogicSharedState>) -> LogicRunner {
        let mut runner = LogicRunner::new(self.clone());
        runner.shared_state = Some(state);
        runner
    }

    /// Returns the resource policy.
    #[must_use]
    pub const fn limits(&self) -> LogicLimits {
        self.limits
    }

    /// Returns whether traversal requires an injected random capability.
    #[must_use]
    pub const fn uses_random(&self) -> bool {
        self.uses_random
    }
}

#[derive(Clone, Debug)]
enum WorkItem {
    Node {
        node: LogicNode,
        path: Vec<LogicCursor>,
        iteration: u64,
    },
    IfEnd {
        id: u64,
    },
    LoopAgain {
        id: u64,
        count: LoopCount,
        children: Vec<LogicNode>,
        path: Vec<LogicCursor>,
        iteration: u64,
    },
    WhileAgain {
        id: u64,
        condition: LogicCondition,
        max_iterations: Option<u64>,
        children: Vec<LogicNode>,
        path: Vec<LogicCursor>,
        iteration: u64,
    },
    ForEachAgain {
        id: u64,
        input_prefix: String,
        output_variable: String,
        count: usize,
        children: Vec<LogicNode>,
        path: Vec<LogicCursor>,
        index: usize,
    },
    RuntimeAgain {
        id: u64,
        duration: Duration,
        children: Vec<LogicNode>,
        path: Vec<LogicCursor>,
        iteration: u64,
        deadline: Duration,
    },
}

/// In-progress Fisher-Yates shuffle for one Random Order Controller.
///
/// The state is kept separately from the work item because a random draw may
/// be rejected by unbiased range sampling. In that case the original node is
/// retried while this state retains every accepted swap.
#[derive(Clone, Debug)]
struct PendingRandomOrder {
    id: u64,
    path: Vec<LogicCursor>,
    iteration: u64,
    order: Vec<LogicNode>,
    remaining: usize,
}

/// Metadata for a selected sampler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicCursor {
    /// Controller identity.
    pub id: u64,
    /// Controller kind as its upstream wire name.
    pub kind: String,
    /// Zero-based controller iteration.
    pub iteration: u64,
}

/// One selected sampler and its active controller path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicSelection {
    /// Selected sampler ID.
    pub sampler_id: u64,
    /// Root iteration.
    pub execution_iteration: u64,
    /// Active path from outermost to innermost.
    pub path: Vec<LogicCursor>,
    /// Transaction IDs enclosing this sampler.
    pub transactions: Vec<u64>,
    /// Transaction metadata in the same outer-to-inner order as `transactions`.
    pub transaction_details: Vec<TransactionInfo>,
    /// Critical-section lock names enclosing this sampler. The runner emits
    /// these as lease requirements; an application edge must acquire/release
    /// them through its explicit coordinator before running the sampler.
    pub critical_sections: Vec<String>,
    /// Critical-section controller identities parallel to
    /// [`Self::critical_sections`]. Names are not identities: adjacent
    /// controllers may use the same lock name while still representing
    /// distinct scope boundaries.
    pub critical_section_ids: Vec<u64>,
}

/// Transaction metadata active for one selected sampler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionInfo {
    /// Transaction controller identity.
    pub id: u64,
    /// Whether the transaction is represented as a parent result.
    pub parent: bool,
    /// Whether timer duration should be included in the aggregate.
    pub include_timers: bool,
}

/// Input observed at each state-machine boundary.
#[derive(Clone, Debug, Default)]
pub struct LogicInput {
    /// Incoming cancellation/logical signal.
    pub signal: ControlSignal,
    /// Last non-null sample success value.
    pub last_sample_success: Option<bool>,
    /// Monotonic elapsed run time.
    pub elapsed: Duration,
    /// Deterministic random value, if a random capability is available.
    pub random_value: Option<u64>,
}

/// State-machine outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LogicStep {
    /// A sampler is ready for execution.
    Sample(LogicSelection),
    /// The next transition is a random decision and requires one injected
    /// value. The work item remains pending and must be retried with a value.
    NeedsRandom,
    /// No work remains.
    Complete,
    /// A typed stop signal ended traversal.
    Stopped(ControlSignal),
}

/// One-user mutable logic runner.
#[derive(Clone, Debug)]
pub struct LogicRunner {
    program: LogicProgram,
    work: Vec<WorkItem>,
    variables: BTreeMap<String, String>,
    root_started: bool,
    finished: bool,
    terminal: Option<ControlSignal>,
    root_iteration: u64,
    loop_iterations: BTreeMap<u64, u64>,
    once_done: BTreeSet<u64>,
    interleave_next: BTreeMap<u64, usize>,
    throughput: BTreeMap<u64, ThroughputState>,
    runtime_starts: BTreeMap<u64, Duration>,
    transition_count: usize,
    shared_state: Option<Arc<LogicSharedState>>,
    transaction_metadata: BTreeMap<u64, (bool, bool)>,
    pending_random_order: Option<PendingRandomOrder>,
    active_ifs: Vec<ActiveIfFrame>,
    if_check_pending: bool,
}

impl LogicRunner {
    fn new(program: LogicProgram) -> Self {
        Self {
            program,
            work: Vec::new(),
            variables: BTreeMap::new(),
            root_started: false,
            finished: false,
            terminal: None,
            root_iteration: 0,
            loop_iterations: BTreeMap::new(),
            once_done: BTreeSet::new(),
            interleave_next: BTreeMap::new(),
            throughput: BTreeMap::new(),
            runtime_starts: BTreeMap::new(),
            transition_count: 0,
            shared_state: None,
            transaction_metadata: BTreeMap::new(),
            pending_random_order: None,
            active_ifs: Vec::new(),
            if_check_pending: false,
        }
    }

    /// Creates an independent runner from this runner's immutable program.
    #[must_use]
    pub fn clone_for_user(&self) -> Self {
        let mut runner = Self::new(self.program.clone());
        runner.shared_state = self.shared_state.clone();
        runner
    }

    /// Returns user variables owned by this runner.
    #[must_use]
    pub fn variables(&self) -> &BTreeMap<String, String> {
        &self.variables
    }

    /// Sets one virtual-user variable used by conditions/ForEach.
    pub fn set_variable(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.variables.insert(name.into(), value.into());
    }

    /// Replaces the runner's variable view with the current execution-context
    /// snapshot. This is the bridge used at sampler boundaries.
    pub fn replace_variables(&mut self, values: &BTreeMap<String, String>) {
        self.variables.clone_from(values);
    }

    /// Returns an owned snapshot suitable for writing back to an execution
    /// context after controller transitions or a sampler pipeline.
    #[must_use]
    pub fn variables_owned(&self) -> BTreeMap<String, String> {
        self.variables.clone()
    }

    /// Resets all traversal and controller state while retaining no variables.
    pub fn reset(&mut self) {
        self.work.clear();
        self.variables.clear();
        self.root_started = false;
        self.finished = false;
        self.terminal = None;
        self.root_iteration = 0;
        self.loop_iterations.clear();
        self.once_done.clear();
        self.interleave_next.clear();
        self.throughput.clear();
        self.runtime_starts.clear();
        self.transition_count = 0;
        self.transaction_metadata.clear();
        self.pending_random_order = None;
        self.active_ifs.clear();
        self.if_check_pending = false;
    }

    /// Returns the current root iteration.
    #[must_use]
    pub const fn root_iteration(&self) -> u64 {
        self.root_iteration
    }

    /// Starts the next root iteration while retaining per-user controller
    /// state such as OnceOnly, interleave, throughput, and runtime timing.
    pub fn next_root_iteration(&mut self) -> Result<(), LogicControllerError> {
        if !self.finished {
            return Err(LogicControllerError::TransitionLimit {
                used: self.transition_count,
                limit: self.program.limits.max_transitions,
            });
        }
        self.root_iteration =
            self.root_iteration
                .checked_add(1)
                .ok_or(LogicControllerError::TransitionLimit {
                    used: self.transition_count,
                    limit: self.program.limits.max_transitions,
                })?;
        self.work.clear();
        self.root_started = false;
        self.finished = false;
        self.terminal = None;
        self.loop_iterations.clear();
        self.runtime_starts.clear();
        self.pending_random_order = None;
        self.active_ifs.clear();
        self.if_check_pending = false;
        Ok(())
    }

    /// Advances one controller transition.
    pub fn step(&mut self, mut input: LogicInput) -> Result<LogicStep, LogicControllerError> {
        if let Some(existing) = self.terminal {
            if input.signal.is_stop() {
                let signal = existing.combine(input.signal);
                self.terminal = Some(signal);
                self.pending_random_order = None;
                return Ok(LogicStep::Stopped(signal));
            }
            return Ok(LogicStep::Stopped(existing));
        }
        if input.signal.is_stop() {
            self.terminal = Some(input.signal);
            self.pending_random_order = None;
            return Ok(LogicStep::Stopped(input.signal));
        }
        if input.signal == ControlSignal::NextLoop {
            self.pending_random_order = None;
            self.next_loop(&mut input)?;
            if self.finished {
                return Ok(LogicStep::Complete);
            }
        }
        if self.if_check_pending {
            self.if_check_pending = false;
            self.recheck_active_ifs(&input)?;
        }
        let mut used = 0usize;
        loop {
            used = used.saturating_add(1);
            if used > self.program.limits.max_transitions {
                return Err(LogicControllerError::TransitionLimit {
                    used,
                    limit: self.program.limits.max_transitions,
                });
            }
            self.transition_count = self.transition_count.saturating_add(1);
            if self.finished {
                return Ok(LogicStep::Complete);
            }
            if !self.root_started {
                self.root_started = true;
                self.work.push(WorkItem::Node {
                    node: (*self.program.root).clone(),
                    path: Vec::new(),
                    iteration: 0,
                });
            }
            let Some(item) = self.work.pop() else {
                self.finished = true;
                return Ok(LogicStep::Complete);
            };
            let retry = item.clone();
            match self.process_item(item, &mut input)? {
                Some(LogicStep::NeedsRandom) => {
                    self.work.push(retry);
                    return Ok(LogicStep::NeedsRandom);
                }
                Some(step @ LogicStep::Sample(_)) => {
                    self.if_check_pending = !self.active_ifs.is_empty();
                    return Ok(step);
                }
                Some(step) => return Ok(step),
                None => continue,
            }
        }
    }

    fn process_item(
        &mut self,
        item: WorkItem,
        input: &mut LogicInput,
    ) -> Result<Option<LogicStep>, LogicControllerError> {
        match item {
            WorkItem::Node {
                node,
                path,
                iteration,
            } => self.process_node(node, path, iteration, input),
            WorkItem::IfEnd { id } => {
                self.finish_if(id)?;
                Ok(None)
            }
            WorkItem::LoopAgain {
                id,
                count,
                children,
                mut path,
                iteration,
            } => {
                let next =
                    iteration
                        .checked_add(1)
                        .ok_or(LogicControllerError::TransitionLimit {
                            used: self.transition_count,
                            limit: self.program.limits.max_transitions,
                        })?;
                if count.finite_count().is_some_and(|total| next >= total) {
                    return Ok(None);
                }
                update_cursor_iteration(&mut path, id, "LoopController", next)?;
                self.schedule_children(
                    children.clone(),
                    path.clone(),
                    next,
                    Some(WorkItem::LoopAgain {
                        id,
                        count,
                        children,
                        path,
                        iteration: next,
                    }),
                );
                Ok(None)
            }
            WorkItem::WhileAgain {
                id,
                condition,
                max_iterations,
                children,
                mut path,
                iteration,
            } => {
                let next =
                    iteration
                        .checked_add(1)
                        .ok_or(LogicControllerError::TransitionLimit {
                            used: self.transition_count,
                            limit: self.program.limits.max_transitions,
                        })?;
                if max_iterations.is_some_and(|maximum| next >= maximum)
                    || !condition.evaluate(&self.variables, input.last_sample_success)?
                {
                    return Ok(None);
                }
                update_cursor_iteration(&mut path, id, "WhileController", next)?;
                self.schedule_children(
                    children.clone(),
                    path.clone(),
                    next,
                    Some(WorkItem::WhileAgain {
                        id,
                        condition,
                        max_iterations,
                        children,
                        path,
                        iteration: next,
                    }),
                );
                Ok(None)
            }
            WorkItem::ForEachAgain {
                id,
                input_prefix,
                output_variable,
                count,
                children,
                mut path,
                index,
            } => {
                if index >= count {
                    self.loop_iterations.insert(id, 0);
                    return Ok(None);
                }
                let key = format!("{input_prefix}_{}", index.saturating_add(1));
                let value = self.variables.get(&key).cloned().unwrap_or_default();
                self.variables.insert(output_variable.clone(), value);
                self.loop_iterations
                    .insert(id, index.saturating_add(1) as u64);
                update_cursor_iteration(&mut path, id, "ForeachController", index as u64)?;
                self.schedule_children(
                    children.clone(),
                    path.clone(),
                    index as u64,
                    Some(WorkItem::ForEachAgain {
                        id,
                        input_prefix,
                        output_variable,
                        count,
                        children,
                        path,
                        index: index.saturating_add(1),
                    }),
                );
                Ok(None)
            }
            WorkItem::RuntimeAgain {
                id,
                duration,
                children,
                mut path,
                iteration,
                deadline,
            } => {
                if input.elapsed >= deadline {
                    self.runtime_starts.remove(&id);
                    return Ok(None);
                }
                let next =
                    iteration
                        .checked_add(1)
                        .ok_or(LogicControllerError::TransitionLimit {
                            used: self.transition_count,
                            limit: self.program.limits.max_transitions,
                        })?;
                update_cursor_iteration(&mut path, id, "RunTime", next)?;
                self.schedule_children(
                    children.clone(),
                    path.clone(),
                    next,
                    Some(WorkItem::RuntimeAgain {
                        id,
                        duration,
                        children,
                        path,
                        iteration: next,
                        deadline,
                    }),
                );
                Ok(None)
            }
        }
    }

    fn process_node(
        &mut self,
        node: LogicNode,
        path: Vec<LogicCursor>,
        iteration: u64,
        input: &mut LogicInput,
    ) -> Result<Option<LogicStep>, LogicControllerError> {
        match node {
            LogicNode::Sample { id } => {
                let transactions: Vec<u64> = path
                    .iter()
                    .filter(|cursor| cursor.kind == "TransactionController")
                    .map(|cursor| cursor.id)
                    .collect();
                let transaction_details = transactions
                    .iter()
                    .filter_map(|id| {
                        self.transaction_metadata
                            .get(id)
                            .map(|(parent, include_timers)| TransactionInfo {
                                id: *id,
                                parent: *parent,
                                include_timers: *include_timers,
                            })
                    })
                    .collect();
                let critical_section_cursors = path
                    .iter()
                    .filter(|cursor| cursor.kind.starts_with("CriticalSection:"))
                    .collect::<Vec<_>>();
                let critical_sections = critical_section_cursors
                    .iter()
                    .filter_map(|cursor| cursor.kind.strip_prefix("CriticalSection:"))
                    .map(str::to_owned)
                    .collect();
                let critical_section_ids = critical_section_cursors
                    .iter()
                    .map(|cursor| cursor.id)
                    .collect();
                Ok(Some(LogicStep::Sample(LogicSelection {
                    sampler_id: id,
                    execution_iteration: self.root_iteration,
                    path,
                    transactions,
                    transaction_details,
                    critical_sections,
                    critical_section_ids,
                })))
            }
            LogicNode::Sequence { id, children } => {
                let mut path = path;
                path.push(cursor(id, "GenericController", iteration));
                self.schedule_children(children, path, iteration, None);
                Ok(None)
            }
            LogicNode::Loop {
                id,
                count,
                children,
            } => {
                if matches!(count, LoopCount::Finite(0)) {
                    return Ok(None);
                }
                let mut path = path;
                path.push(cursor(id, "LoopController", iteration));
                let marker = WorkItem::LoopAgain {
                    id,
                    count,
                    children: children.clone(),
                    path: path.clone(),
                    iteration,
                };
                self.schedule_children(children, path, iteration, Some(marker));
                Ok(None)
            }
            LogicNode::If {
                id,
                condition,
                evaluate_each_iteration,
                children,
            } => {
                let enters = condition.evaluate(&self.variables, input.last_sample_success)?;
                if !enters {
                    // A false IfController entry resets its descendants in
                    // JMeter. Otherwise a later re-entry could observe stale
                    // ForEach/OnceOnly/Interleave/Throughput state from a
                    // skipped branch.
                    let reset_state_ids = collect_if_state_ids(&children);
                    self.reset_if_state(&reset_state_ids);
                    return Ok(None);
                }

                let mut path = path;
                path.push(cursor(id, "IfController", iteration));
                if evaluate_each_iteration {
                    let reset_state_ids = collect_if_state_ids(&children);
                    self.active_ifs.push(ActiveIfFrame {
                        id,
                        condition,
                        reset_state_ids,
                    });
                    self.schedule_children(children, path, iteration, Some(WorkItem::IfEnd { id }));
                } else {
                    // This node is the controller-entry boundary. Parent
                    // loop markers enqueue it again for each nested/repeated
                    // visit, so entry-only evaluation must not be cached by
                    // node ID across visits.
                    self.schedule_children(children, path, iteration, None);
                }
                Ok(None)
            }
            LogicNode::While {
                id,
                condition,
                max_iterations,
                children,
            } => {
                if max_iterations.is_some_and(|maximum| maximum == 0) {
                    return Ok(None);
                }
                if !condition.evaluate(&self.variables, input.last_sample_success)? {
                    return Ok(None);
                }
                let mut path = path;
                path.push(cursor(id, "WhileController", iteration));
                let marker = WorkItem::WhileAgain {
                    id,
                    condition,
                    max_iterations,
                    children: children.clone(),
                    path: path.clone(),
                    iteration: 0,
                };
                self.schedule_children(children, path, 0, Some(marker));
                Ok(None)
            }
            LogicNode::ForEach {
                id,
                input_prefix,
                output_variable,
                children,
            } => {
                let match_nr_name = format!("{input_prefix}_matchNr");
                let count = self
                    .variables
                    .get(&match_nr_name)
                    .map(String::as_str)
                    .unwrap_or("0")
                    .parse::<usize>()
                    .map_err(|_| LogicControllerError::InvalidForEachValue {
                        controller: id,
                        variable: match_nr_name.clone(),
                    })?;
                if count == 0 {
                    return Ok(None);
                }
                let index = self.loop_iterations.entry(id).or_insert(0);
                if *index >= count as u64 {
                    *index = 0;
                    return Ok(None);
                }
                let key = format!("{input_prefix}_{}", index.saturating_add(1));
                let value = self.variables.get(&key).cloned().unwrap_or_default();
                self.variables.insert(output_variable.clone(), value);
                let current = *index;
                *index = index.saturating_add(1);
                let mut path = path;
                path.push(cursor(id, "ForeachController", current));
                let marker = WorkItem::ForEachAgain {
                    id,
                    input_prefix,
                    output_variable,
                    count,
                    children: children.clone(),
                    path: path.clone(),
                    index: current as usize + 1,
                };
                self.schedule_children(children, path, current, Some(marker));
                Ok(None)
            }
            LogicNode::Switch {
                id,
                selection,
                children,
            } => {
                if children.is_empty() {
                    return Ok(None);
                }
                let index = match selection {
                    SwitchSelection::Index(value) => {
                        if value < children.len() {
                            value
                        } else {
                            0
                        }
                    }
                    SwitchSelection::Variable(name) => {
                        let value = self.variables.get(&name).map(String::as_str).unwrap_or("");
                        let Some(index) = switch_numeric_index(value, children.len()) else {
                            return Err(LogicControllerError::Unsupported {
                                controller: format!("SwitchController {id}"),
                                capability_id: "switch-child-names".to_owned(),
                            });
                        };
                        index
                    }
                    SwitchSelection::VariableWithNames {
                        variable,
                        child_names,
                    } => {
                        let value = self
                            .variables
                            .get(&variable)
                            .map(String::as_str)
                            .unwrap_or("");
                        if let Some(index) = switch_numeric_index(value, children.len()) {
                            index
                        } else {
                            let Some(index) =
                                switch_named_index(value, &child_names, children.len())
                            else {
                                return Ok(None);
                            };
                            index
                        }
                    }
                    SwitchSelection::Random => {
                        if children.len() == 1 {
                            0
                        } else {
                            let Some(value) = input.random_value.take() else {
                                return Ok(Some(LogicStep::NeedsRandom));
                            };
                            let Some(index) = uniform_index(value, children.len()) else {
                                return Ok(Some(LogicStep::NeedsRandom));
                            };
                            index
                        }
                    }
                };
                // Numeric selection already applies the pinned out-of-range
                // fallback. Keep this checked access as a defensive guard for
                // future selection policies rather than indexing user input.
                let Some(child) = children.get(index) else {
                    return Ok(None);
                };
                let mut path = path;
                path.push(cursor(id, "SwitchController", iteration));
                self.work.push(WorkItem::Node {
                    node: child.clone(),
                    path,
                    iteration,
                });
                Ok(None)
            }
            LogicNode::Interleave { id, children } => {
                if children.is_empty() {
                    return Ok(None);
                }
                let index = self.interleave_next.entry(id).or_insert(0);
                let child = children[*index % children.len()].clone();
                *index = index.saturating_add(1);
                let mut path = path;
                path.push(cursor(id, "InterleaveControl", iteration));
                self.work.push(WorkItem::Node {
                    node: child,
                    path,
                    iteration,
                });
                Ok(None)
            }
            LogicNode::Random { id, children } => {
                if children.is_empty() {
                    return Ok(None);
                }
                let index = if children.len() == 1 {
                    0
                } else {
                    let Some(value) = input.random_value.take() else {
                        return Ok(Some(LogicStep::NeedsRandom));
                    };
                    let Some(index) = uniform_index(value, children.len()) else {
                        return Ok(Some(LogicStep::NeedsRandom));
                    };
                    index
                };
                let mut path = path;
                path.push(cursor(id, "RandomController", iteration));
                self.work.push(WorkItem::Node {
                    node: children[index].clone(),
                    path,
                    iteration,
                });
                Ok(None)
            }
            LogicNode::RandomOrder { id, children } => {
                if children.len() <= 1 {
                    if let Some(child) = children.into_iter().next() {
                        let mut path = path;
                        path.push(cursor(id, "RandomOrderController", iteration));
                        self.work.push(WorkItem::Node {
                            node: child,
                            path,
                            iteration,
                        });
                    }
                    return Ok(None);
                }

                if self
                    .pending_random_order
                    .as_ref()
                    .is_none_or(|pending| pending.id != id)
                {
                    self.pending_random_order = Some(PendingRandomOrder {
                        id,
                        path: {
                            let mut path = path;
                            path.push(cursor(id, "RandomOrderController", iteration));
                            path
                        },
                        iteration,
                        remaining: children.len(),
                        order: children,
                    });
                }

                let Some(value) = input.random_value.take() else {
                    return Ok(Some(LogicStep::NeedsRandom));
                };
                let Some(pending) = self.pending_random_order.as_mut() else {
                    return Err(LogicControllerError::InvariantViolation {
                        detail: "random-order state disappeared before selection".to_owned(),
                    });
                };
                let Some(index) = uniform_index(value, pending.remaining) else {
                    return Ok(Some(LogicStep::NeedsRandom));
                };
                let last = pending.remaining.saturating_sub(1);
                pending.order.swap(index, last);
                pending.remaining = last;
                if pending.remaining > 1 {
                    return Ok(Some(LogicStep::NeedsRandom));
                }
                let Some(pending) = self.pending_random_order.take() else {
                    return Err(LogicControllerError::InvariantViolation {
                        detail: "random-order state disappeared at completion".to_owned(),
                    });
                };
                self.schedule_children(pending.order, pending.path, pending.iteration, None);
                Ok(None)
            }
            LogicNode::OnceOnly { id, children } => {
                if self.once_done.contains(&id) {
                    return Ok(None);
                }
                self.once_done.insert(id);
                let mut path = path;
                path.push(cursor(id, "OnceOnlyController", iteration));
                self.schedule_children(children, path, iteration, None);
                Ok(None)
            }
            LogicNode::Throughput {
                id,
                mode,
                limit,
                percent,
                per_user,
                children,
            } => {
                let allow = self.throughput_allow(id, mode, limit, percent, per_user)?;
                if !allow {
                    return Ok(None);
                }
                let mut path = path;
                path.push(cursor(id, "ThroughputController", iteration));
                self.schedule_children(children, path, iteration, None);
                Ok(None)
            }
            LogicNode::Runtime {
                id,
                duration,
                children,
            } => {
                let start = *self.runtime_starts.entry(id).or_insert(input.elapsed);
                let deadline = start.saturating_add(duration);
                if input.elapsed >= deadline {
                    self.runtime_starts.remove(&id);
                    return Ok(None);
                }
                let mut path = path;
                path.push(cursor(id, "RunTime", iteration));
                self.schedule_children(
                    children.clone(),
                    path.clone(),
                    iteration,
                    Some(WorkItem::RuntimeAgain {
                        id,
                        duration,
                        children,
                        path,
                        iteration,
                        deadline,
                    }),
                );
                Ok(None)
            }
            LogicNode::Transaction {
                id,
                parent,
                include_timers,
                children,
            } => {
                self.transaction_metadata
                    .insert(id, (parent, include_timers));
                let mut path = path;
                path.push(cursor(id, "TransactionController", iteration));
                self.schedule_children(children, path, iteration, None);
                Ok(None)
            }
            LogicNode::Module { id, target } => {
                self.replace_node(id, "ModuleController", target, path, iteration)
            }
            LogicNode::Include { id, target } => {
                self.replace_node(id, "IncludeController", target, path, iteration)
            }
            LogicNode::Recording { id, children } => {
                let mut path = path;
                path.push(cursor(id, "RecordingController", iteration));
                self.schedule_children(children, path, iteration, None);
                Ok(None)
            }
            LogicNode::CriticalSection {
                id,
                lock_name,
                children,
            } => {
                // The deterministic coordinator intentionally has no
                // re-entrant ownership semantics. A nested scope with the
                // same name would otherwise queue behind the same user's
                // held lock forever; fail explicitly until an oracle-backed
                // re-entrant contract is available.
                let lock_kind = format!("CriticalSection:{lock_name}");
                if path.iter().any(|cursor| cursor.kind == lock_kind) {
                    return Err(LogicControllerError::Unsupported {
                        controller: format!("CriticalSectionController {id}"),
                        capability_id: "critical-section-reentrant-name".to_owned(),
                    });
                }
                let mut path = path;
                path.push(cursor(id, "CriticalSectionController", iteration));
                path.push(LogicCursor {
                    id,
                    kind: lock_kind,
                    iteration,
                });
                self.schedule_children(children, path, iteration, None);
                Ok(None)
            }
        }
    }

    fn throughput_allow(
        &mut self,
        id: u64,
        mode: ThroughputMode,
        limit: u64,
        percent: f64,
        per_user: bool,
    ) -> Result<bool, LogicControllerError> {
        if !per_user {
            let Some(shared) = &self.shared_state else {
                return Err(LogicControllerError::MissingGlobalState { controller: id });
            };
            let mut state = lock(&shared.throughput);
            let counters = state.entry(id).or_default();
            let allow = throughput_decide(*counters, mode, limit, percent);
            counters.iterations = counters.iterations.saturating_add(1);
            if allow {
                counters.executions = counters.executions.saturating_add(1);
            }
            return Ok(allow);
        }

        let counters = self.throughput.entry(id).or_default();
        let allow = throughput_decide(*counters, mode, limit, percent);
        counters.iterations = counters.iterations.saturating_add(1);
        if allow {
            counters.executions = counters.executions.saturating_add(1);
        }
        Ok(allow)
    }

    fn recheck_active_ifs(&mut self, input: &LogicInput) -> Result<(), LogicControllerError> {
        for index in 0..self.active_ifs.len() {
            let enters = {
                let frame = &self.active_ifs[index];
                frame
                    .condition
                    .evaluate(&self.variables, input.last_sample_success)?
            };
            if !enters {
                self.abort_if_frame(index)?;
                break;
            }
        }
        Ok(())
    }

    fn finish_if(&mut self, id: u64) -> Result<(), LogicControllerError> {
        let Some(frame) = self.active_ifs.last() else {
            return Err(LogicControllerError::InvariantViolation {
                detail: format!("IfController {id} ended without an active frame"),
            });
        };
        if frame.id != id {
            return Err(LogicControllerError::InvariantViolation {
                detail: format!(
                    "IfController end marker {id} mismatched active frame {}",
                    frame.id
                ),
            });
        }
        self.active_ifs.pop();
        Ok(())
    }

    fn abort_if_frame(&mut self, index: usize) -> Result<(), LogicControllerError> {
        let Some(frame) = self.active_ifs.get(index) else {
            return Err(LogicControllerError::InvariantViolation {
                detail: format!("missing active IfController frame at index {index}"),
            });
        };
        let id = frame.id;
        let reset_state_ids = frame.reset_state_ids.clone();
        let mut marker_found = false;
        while let Some(item) = self.work.pop() {
            if matches!(item, WorkItem::IfEnd { id: marker_id } if marker_id == id) {
                marker_found = true;
                break;
            }
        }
        if !marker_found {
            return Err(LogicControllerError::InvariantViolation {
                detail: format!("IfController {id} frame has no end marker"),
            });
        }
        self.active_ifs.truncate(index);
        self.reset_if_state(&reset_state_ids);
        self.if_check_pending = false;
        Ok(())
    }

    fn reset_if_state(&mut self, ids: &BTreeSet<u64>) {
        for id in ids {
            self.loop_iterations.remove(id);
            self.once_done.remove(id);
            self.interleave_next.remove(id);
            self.throughput.remove(id);
            self.transaction_metadata.remove(id);
        }
        if self
            .pending_random_order
            .as_ref()
            .is_some_and(|pending| ids.contains(&pending.id))
        {
            self.pending_random_order = None;
        }
    }

    fn drop_unbacked_if_frames(&mut self) {
        let marker_ids: BTreeSet<u64> = self
            .work
            .iter()
            .filter_map(|item| match item {
                WorkItem::IfEnd { id } => Some(*id),
                _ => None,
            })
            .collect();
        while self
            .active_ifs
            .last()
            .is_some_and(|frame| !marker_ids.contains(&frame.id))
        {
            let Some(frame) = self.active_ifs.pop() else {
                break;
            };
            self.reset_if_state(&frame.reset_state_ids);
        }
    }

    fn replace_node(
        &mut self,
        id: u64,
        kind: &str,
        target: Option<Box<LogicNode>>,
        mut path: Vec<LogicCursor>,
        iteration: u64,
    ) -> Result<Option<LogicStep>, LogicControllerError> {
        let Some(target) = target else {
            return Err(LogicControllerError::UnresolvedReplacement { controller: id });
        };
        path.push(cursor(id, kind, iteration));
        self.work.push(WorkItem::Node {
            node: *target,
            path,
            iteration,
        });
        Ok(None)
    }

    fn schedule_children(
        &mut self,
        children: Vec<LogicNode>,
        path: Vec<LogicCursor>,
        iteration: u64,
        marker: Option<WorkItem>,
    ) {
        if let Some(marker) = marker {
            self.work.push(marker);
        }
        for child in children.into_iter().rev() {
            self.work.push(WorkItem::Node {
                node: child,
                path: path.clone(),
                iteration,
            });
        }
    }

    fn next_loop(&mut self, input: &mut LogicInput) -> Result<(), LogicControllerError> {
        // JMeter propagates a logical next-loop action through every active
        // non-iterating controller, including RunTime, before restarting the
        // selected loop. Clear their per-entry clocks at that boundary.
        self.runtime_starts.clear();
        let Some(marker_index) = self.work.iter().rposition(|item| {
            matches!(
                item,
                WorkItem::LoopAgain { .. }
                    | WorkItem::WhileAgain { .. }
                    | WorkItem::ForEachAgain { .. }
            )
        }) else {
            self.work.clear();
            while let Some(frame) = self.active_ifs.pop() {
                self.reset_if_state(&frame.reset_state_ids);
            }
            self.if_check_pending = false;
            self.finished = true;
            return Ok(());
        };
        let marker = self.work.remove(marker_index);
        self.work.truncate(marker_index);
        self.drop_unbacked_if_frames();
        let _ = self.process_item(marker, input)?;
        Ok(())
    }
}

/// A currently active `IfController` configured to evaluate its condition for
/// every runnable child. The marker in [`WorkItem`] bounds this frame to one
/// controller entry, while the condition is retained for sampler-boundary
/// re-evaluation.
#[derive(Clone, Debug)]
struct ActiveIfFrame {
    id: u64,
    condition: LogicCondition,
    reset_state_ids: BTreeSet<u64>,
}

fn collect_if_state_ids(children: &[LogicNode]) -> BTreeSet<u64> {
    let mut ids = BTreeSet::new();
    for child in children {
        collect_if_state_ids_from_node(child, &mut ids);
    }
    ids
}

fn collect_if_state_ids_from_node(node: &LogicNode, ids: &mut BTreeSet<u64>) {
    if matches!(
        node,
        LogicNode::ForEach { .. }
            | LogicNode::Interleave { .. }
            | LogicNode::OnceOnly { .. }
            | LogicNode::Throughput { .. }
            | LogicNode::Transaction { .. }
            | LogicNode::RandomOrder { .. }
    ) {
        ids.insert(node.id());
    }
    match node {
        LogicNode::Module { target, .. } | LogicNode::Include { target, .. } => {
            if let Some(target) = target.as_deref() {
                collect_if_state_ids_from_node(target, ids);
            }
        }
        _ => {
            if let Some(children) = node.children() {
                for child in children {
                    collect_if_state_ids_from_node(child, ids);
                }
            }
        }
    }
}

fn cursor(id: u64, kind: &str, iteration: u64) -> LogicCursor {
    LogicCursor {
        id,
        kind: kind.to_owned(),
        iteration,
    }
}

/// Updates the iteration metadata for a controller frame that is being
/// resumed by one of its finite/repeating work markers.
///
/// Markers retain the full active path so nested selections do not lose their
/// ancestor identity.  The controller's own cursor is the one field that
/// changes between visits; keeping it in sync is important to listeners and
/// transaction/result routing, which use the path as their execution
/// identity.  A missing cursor indicates a corrupted work frame and must not
/// silently produce a plausible but wrong selection.
fn update_cursor_iteration(
    path: &mut [LogicCursor],
    id: u64,
    kind: &str,
    iteration: u64,
) -> Result<(), LogicControllerError> {
    let Some(cursor) = path
        .iter_mut()
        .rev()
        .find(|cursor| cursor.id == id && cursor.kind == kind)
    else {
        return Err(LogicControllerError::InvariantViolation {
            detail: format!("{kind} {id} marker has no matching path cursor"),
        });
    };
    cursor.iteration = iteration;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "deterministic logic setup")]
mod tests {
    use super::*;

    fn sample_ids(program: &LogicProgram, limit: usize) -> Vec<u64> {
        let mut runner = program.runner();
        let mut values = Vec::new();
        for _ in 0..limit {
            let step = runner.step(LogicInput::default()).expect("step");
            match step {
                LogicStep::Sample(selection) => values.push(selection.sampler_id),
                LogicStep::NeedsRandom => break,
                LogicStep::Complete => break,
                LogicStep::Stopped(_) => break,
            }
        }
        values
    }

    #[test]
    fn all_basic_ordering_controllers_select_explicitly() {
        let root = LogicNode::Sequence {
            id: 1,
            children: vec![
                LogicNode::Loop {
                    id: 2,
                    count: LoopCount::finite(2),
                    children: vec![LogicNode::Sample { id: 10 }],
                },
                LogicNode::Interleave {
                    id: 3,
                    children: vec![LogicNode::Sample { id: 11 }, LogicNode::Sample { id: 12 }],
                },
                LogicNode::OnceOnly {
                    id: 4,
                    children: vec![LogicNode::Sample { id: 13 }],
                },
            ],
        };
        let program = LogicProgram::compile(root).expect("program");
        assert_eq!(sample_ids(&program, 8), vec![10, 10, 11, 13]);
    }

    #[test]
    fn if_while_foreach_and_switch_use_user_state() {
        let root = LogicNode::Sequence {
            id: 1,
            children: vec![
                LogicNode::If {
                    id: 2,
                    condition: LogicCondition::VariableBoolean {
                        name: "ok".to_owned(),
                    },
                    evaluate_each_iteration: true,
                    children: vec![LogicNode::Sample { id: 10 }],
                },
                LogicNode::ForEach {
                    id: 3,
                    input_prefix: "item".to_owned(),
                    output_variable: "current".to_owned(),
                    children: vec![LogicNode::Sample { id: 11 }],
                },
                LogicNode::Switch {
                    id: 4,
                    selection: SwitchSelection::Variable("choice".to_owned()),
                    children: vec![LogicNode::Sample { id: 12 }, LogicNode::Sample { id: 13 }],
                },
            ],
        };
        let program = LogicProgram::compile(root).expect("program");
        let mut runner = program.runner();
        runner.set_variable("ok", "true");
        runner.set_variable("item_matchNr", "2");
        runner.set_variable("item_1", "a");
        runner.set_variable("item_2", "b");
        runner.set_variable("choice", "1");
        assert_eq!(sample_ids_with_runner(&mut runner, 8), vec![10, 11, 11, 13]);
        assert_eq!(
            runner.variables().get("current").map(String::as_str),
            Some("b")
        );
    }

    fn sample_ids_with_runner(runner: &mut LogicRunner, limit: usize) -> Vec<u64> {
        let mut values = Vec::new();
        for _ in 0..limit {
            match runner.step(LogicInput::default()).expect("step") {
                LogicStep::Sample(selection) => values.push(selection.sampler_id),
                LogicStep::NeedsRandom | LogicStep::Complete | LogicStep::Stopped(_) => break,
            }
        }
        values
    }

    #[test]
    fn random_order_shuffles_once_with_unbiased_injected_values() {
        let root = LogicNode::RandomOrder {
            id: 2,
            children: vec![
                LogicNode::Sample { id: 20 },
                LogicNode::Sample { id: 21 },
                LogicNode::Sample { id: 22 },
            ],
        };
        let program = LogicProgram::compile(root).expect("program");
        let mut runner = program.runner();
        assert!(program.uses_random());
        assert_eq!(
            runner.step(LogicInput::default()).expect("request"),
            LogicStep::NeedsRandom
        );
        // For a three-way draw, value zero is the rejected prefix. The next
        // value selects an unbiased index, then zero selects index zero of
        // the remaining two elements.
        assert_eq!(
            runner
                .step(LogicInput {
                    random_value: Some(0),
                    ..LogicInput::default()
                })
                .expect("reject and request"),
            LogicStep::NeedsRandom
        );
        assert_eq!(
            runner
                .step(LogicInput {
                    random_value: Some(2),
                    ..LogicInput::default()
                })
                .expect("second request"),
            LogicStep::NeedsRandom
        );
        assert!(matches!(
            runner
                .step(LogicInput {
                    random_value: Some(0),
                    ..LogicInput::default()
                })
                .expect("first shuffled sample"),
            LogicStep::Sample(LogicSelection { sampler_id: 21, .. })
        ));
        assert_eq!(sample_ids_with_runner(&mut runner, 4), vec![20, 22]);
    }

    #[test]
    fn unbiased_index_rejects_only_the_non_divisible_prefix() {
        assert_eq!(uniform_index(0, 0), None);
        assert_eq!(uniform_index(0, 1), Some(0));
        assert_eq!(uniform_index(0, 3), None);
        assert_eq!(uniform_index(1, 3), Some(1));
        assert_eq!(uniform_index(u64::MAX, 3), Some(0));
    }

    #[test]
    fn switch_random_uses_an_unbiased_injected_value() {
        let root = LogicNode::Switch {
            id: 1,
            selection: SwitchSelection::Random,
            children: vec![
                LogicNode::Sample { id: 10 },
                LogicNode::Sample { id: 11 },
                LogicNode::Sample { id: 12 },
            ],
        };
        let program = LogicProgram::compile(root).expect("program");
        assert!(program.uses_random());
        let mut runner = program.runner();
        assert_eq!(
            runner.step(LogicInput::default()).expect("request"),
            LogicStep::NeedsRandom
        );
        assert!(matches!(
            runner
                .step(LogicInput {
                    random_value: Some(1),
                    ..LogicInput::default()
                })
                .expect("sample"),
            LogicStep::Sample(LogicSelection { sampler_id: 11, .. })
        ));
    }

    #[test]
    fn switch_numeric_selection_uses_first_child_for_empty_or_out_of_range() {
        let root = |selection| LogicNode::Switch {
            id: 1,
            selection,
            children: vec![LogicNode::Sample { id: 10 }, LogicNode::Sample { id: 11 }],
        };

        let program = LogicProgram::compile(root(SwitchSelection::Index(9))).expect("program");
        assert_eq!(sample_ids(&program, 4), vec![10]);

        for value in [None, Some(""), Some("9")] {
            let program =
                LogicProgram::compile(root(SwitchSelection::Variable("choice".to_owned())))
                    .expect("program");
            let mut runner = program.runner();
            if let Some(value) = value {
                runner.set_variable("choice", value);
            }
            assert_eq!(sample_ids_with_runner(&mut runner, 4), vec![10]);
        }

        // A signed value is a non-numeric name in JMeter's SwitchController;
        // the compact Variable form cannot resolve names without source
        // child-name metadata and therefore fails explicitly.
        let program = LogicProgram::compile(root(SwitchSelection::Variable("choice".to_owned())))
            .expect("program");
        let mut runner = program.runner();
        runner.set_variable("choice", "-1");
        assert!(matches!(
            runner.step(LogicInput::default()),
            Err(LogicControllerError::Unsupported { .. })
        ));

        let program = LogicProgram::compile(root(SwitchSelection::Variable("choice".to_owned())))
            .expect("program");
        let mut runner = program.runner();
        runner.set_variable("choice", "1");
        assert_eq!(sample_ids_with_runner(&mut runner, 4), vec![11]);
    }

    #[test]
    fn switch_oversized_numeric_value_uses_default_name() {
        let program = LogicProgram::compile(LogicNode::Switch {
            id: 1,
            selection: SwitchSelection::VariableWithNames {
                variable: "choice".to_owned(),
                child_names: vec!["first".to_owned(), "DEFAULT".to_owned()],
            },
            children: vec![LogicNode::Sample { id: 10 }, LogicNode::Sample { id: 11 }],
        })
        .expect("program");
        let mut runner = program.runner();
        runner.set_variable("choice", "2147483648");
        assert_eq!(sample_ids_with_runner(&mut runner, 4), vec![11]);
    }

    #[test]
    fn switch_named_selection_matches_names_then_case_insensitive_default() {
        let root = LogicNode::Switch {
            id: 1,
            selection: SwitchSelection::VariableWithNames {
                variable: "choice".to_owned(),
                child_names: vec![
                    "first".to_owned(),
                    "Second".to_owned(),
                    "DeFaUlT".to_owned(),
                ],
            },
            children: vec![
                LogicNode::Sample { id: 10 },
                LogicNode::Sample { id: 11 },
                LogicNode::Sample { id: 12 },
            ],
        };
        let program = LogicProgram::compile(root).expect("program");

        for (value, expected) in [("Second", 11), ("second", 12), ("unknown", 12), ("", 10)] {
            let mut runner = program.runner();
            runner.set_variable("choice", value);
            assert_eq!(sample_ids_with_runner(&mut runner, 4), vec![expected]);
        }

        let no_default = LogicNode::Switch {
            id: 2,
            selection: SwitchSelection::VariableWithNames {
                variable: "choice".to_owned(),
                child_names: vec!["first".to_owned(), "second".to_owned()],
            },
            children: vec![LogicNode::Sample { id: 20 }, LogicNode::Sample { id: 21 }],
        };
        let program = LogicProgram::compile(no_default).expect("program");
        let mut runner = program.runner();
        runner.set_variable("choice", "unknown");
        assert!(sample_ids_with_runner(&mut runner, 4).is_empty());
    }

    #[test]
    fn switch_nonnumeric_value_without_names_is_explicitly_unsupported() {
        let program = LogicProgram::compile(LogicNode::Switch {
            id: 1,
            selection: SwitchSelection::Variable("choice".to_owned()),
            children: vec![LogicNode::Sample { id: 10 }],
        })
        .expect("program");
        let mut runner = program.runner();
        runner.set_variable("choice", "named-child");
        assert!(matches!(
            runner.step(LogicInput::default()),
            Err(LogicControllerError::Unsupported {
                controller,
                capability_id
            }) if controller == "SwitchController 1" && capability_id == "switch-child-names"
        ));
    }

    #[test]
    fn random_controllers_do_not_request_randomness_for_one_child() {
        for node in [
            LogicNode::Random {
                id: 1,
                children: vec![LogicNode::Sample { id: 10 }],
            },
            LogicNode::Switch {
                id: 2,
                selection: SwitchSelection::Random,
                children: vec![LogicNode::Sample { id: 11 }],
            },
            LogicNode::RandomOrder {
                id: 3,
                children: vec![LogicNode::Sample { id: 12 }],
            },
        ] {
            let program = LogicProgram::compile(node).expect("program");
            assert!(!program.uses_random());
            let mut runner = program.runner();
            assert!(matches!(
                runner.step(LogicInput::default()).expect("sample"),
                LogicStep::Sample(_)
            ));
        }
    }

    #[test]
    fn throughput_percentage_matches_jmeter_rounded_decision() {
        let root = LogicNode::Loop {
            id: 10,
            count: LoopCount::finite(10),
            children: vec![LogicNode::Throughput {
                id: 1,
                mode: ThroughputMode::Percentage,
                limit: 0,
                percent: 50.0,
                per_user: true,
                children: vec![LogicNode::Sample { id: 9 }],
            }],
        };
        let program = LogicProgram::compile(root).expect("program");
        let mut runner = program.runner();
        let mut selected_iterations = Vec::new();
        for _ in 0..32 {
            match runner.step(LogicInput::default()).expect("step") {
                LogicStep::Sample(selection) => selected_iterations
                    .push(selection.path.last().expect("throughput path").iteration),
                LogicStep::Complete => break,
                LogicStep::NeedsRandom | LogicStep::Stopped(_) => break,
            }
        }
        assert_eq!(selected_iterations, vec![1, 3, 5, 7, 9]);
    }

    #[test]
    fn throughput_zero_and_full_percent_boundaries_are_deterministic() {
        for (percent, expected) in [(0.0, Vec::new()), (100.0, vec![9, 9, 9, 9])] {
            let program = LogicProgram::compile(LogicNode::Loop {
                id: 10,
                count: LoopCount::finite(4),
                children: vec![LogicNode::Throughput {
                    id: 1,
                    mode: ThroughputMode::Percentage,
                    limit: 0,
                    percent,
                    per_user: true,
                    children: vec![LogicNode::Sample { id: 9 }],
                }],
            })
            .expect("program");
            assert_eq!(sample_ids(&program, 16), expected);
        }
    }

    #[test]
    fn global_throughput_requires_explicit_run_state() {
        let program = LogicProgram::compile(LogicNode::Throughput {
            id: 1,
            mode: ThroughputMode::Total,
            limit: 1,
            percent: 0.0,
            per_user: false,
            children: vec![LogicNode::Sample { id: 2 }],
        })
        .expect("program");
        assert!(matches!(
            program.runner().step(LogicInput::default()),
            Err(LogicControllerError::MissingGlobalState { controller: 1 })
        ));
    }

    #[test]
    fn global_throughput_percentage_shares_one_counter_across_users() {
        let program = LogicProgram::compile(LogicNode::Loop {
            id: 10,
            count: LoopCount::finite(2),
            children: vec![LogicNode::Throughput {
                id: 1,
                mode: ThroughputMode::Percentage,
                limit: 0,
                percent: 50.0,
                per_user: false,
                children: vec![LogicNode::Sample { id: 2 }],
            }],
        })
        .expect("program");
        let shared = Arc::new(LogicSharedState::default());
        let mut first = program.runner_with_shared_state(Arc::clone(&shared));
        let mut second = program.runner_with_shared_state(shared);
        assert_eq!(sample_ids_with_runner(&mut first, 8), vec![2]);
        assert_eq!(sample_ids_with_runner(&mut second, 8), vec![2]);
    }

    #[test]
    fn invalid_percentage_boundaries_are_rejected_before_execution() {
        for percent in [f64::NAN, f64::NEG_INFINITY, -0.1, 100.1, f64::INFINITY] {
            assert!(matches!(
                LogicProgram::compile(LogicNode::Throughput {
                    id: 1,
                    mode: ThroughputMode::Percentage,
                    limit: 0,
                    percent,
                    per_user: true,
                    children: vec![LogicNode::Sample { id: 2 }],
                }),
                Err(LogicControllerError::InvalidPercentage { controller: 1, .. })
            ));
        }
    }

    #[test]
    fn throughput_reset_restarts_per_user_total_counter() {
        let program = LogicProgram::compile(LogicNode::Throughput {
            id: 1,
            mode: ThroughputMode::Total,
            limit: 1,
            percent: 0.0,
            per_user: true,
            children: vec![LogicNode::Sample { id: 2 }],
        })
        .expect("program");
        let mut runner = program.runner();
        assert!(matches!(
            runner.step(LogicInput::default()).expect("first sample"),
            LogicStep::Sample(LogicSelection { sampler_id: 2, .. })
        ));
        assert!(matches!(
            runner.step(LogicInput::default()).expect("complete"),
            LogicStep::Complete
        ));
        runner.reset();
        assert!(matches!(
            runner
                .step(LogicInput::default())
                .expect("sample after reset"),
            LogicStep::Sample(LogicSelection { sampler_id: 2, .. })
        ));
    }

    #[test]
    fn runtime_expiry_only_closes_runtime_frame_and_preserves_siblings() {
        let program = LogicProgram::compile(LogicNode::Sequence {
            id: 1,
            children: vec![
                LogicNode::Runtime {
                    id: 2,
                    duration: Duration::from_secs(2),
                    children: vec![LogicNode::Sample { id: 10 }],
                },
                LogicNode::Sample { id: 20 },
            ],
        })
        .expect("program");
        let mut runner = program.runner();
        assert!(matches!(
            runner.step(LogicInput::default()).expect("runtime sample"),
            LogicStep::Sample(LogicSelection { sampler_id: 10, .. })
        ));
        assert!(matches!(
            runner
                .step(LogicInput {
                    elapsed: Duration::from_secs(3),
                    ..LogicInput::default()
                })
                .expect("sibling sample"),
            LogicStep::Sample(LogicSelection { sampler_id: 20, .. })
        ));
    }

    #[test]
    fn finite_controller_frames_update_path_iterations() {
        let cases = [
            (
                LogicNode::Loop {
                    id: 1,
                    count: LoopCount::finite(3),
                    children: vec![LogicNode::Sample { id: 10 }],
                },
                "LoopController",
                1,
                vec![0, 1, 2],
            ),
            (
                LogicNode::While {
                    id: 2,
                    condition: LogicCondition::Always,
                    max_iterations: Some(3),
                    children: vec![LogicNode::Sample { id: 20 }],
                },
                "WhileController",
                2,
                vec![0, 1, 2],
            ),
            (
                LogicNode::ForEach {
                    id: 3,
                    input_prefix: "item".to_owned(),
                    output_variable: "current".to_owned(),
                    children: vec![LogicNode::Sample { id: 30 }],
                },
                "ForeachController",
                3,
                vec![0, 1, 2],
            ),
        ];

        for (node, kind, id, expected) in cases {
            let program = LogicProgram::compile(node).expect("program");
            let mut runner = program.runner();
            if id == 3 {
                runner.set_variable("item_matchNr", "3");
                runner.set_variable("item_1", "a");
                runner.set_variable("item_2", "b");
                runner.set_variable("item_3", "c");
            }
            let mut actual = Vec::new();
            for _ in 0..expected.len() {
                let LogicStep::Sample(selection) =
                    runner.step(LogicInput::default()).expect("sample")
                else {
                    panic!("finite controller ended before all samples");
                };
                actual.push(
                    selection
                        .path
                        .iter()
                        .find(|cursor| cursor.id == id && cursor.kind == kind)
                        .expect("controller path cursor")
                        .iteration,
                );
            }
            assert_eq!(actual, expected);
        }

        let program = LogicProgram::compile(LogicNode::Runtime {
            id: 4,
            duration: Duration::from_secs(1),
            children: vec![LogicNode::Sample { id: 40 }],
        })
        .expect("program");
        let mut runner = program.runner();
        let mut actual = Vec::new();
        for _ in 0..3 {
            let LogicStep::Sample(selection) =
                runner.step(LogicInput::default()).expect("runtime sample")
            else {
                panic!("runtime controller ended before the clock advanced");
            };
            actual.push(
                selection
                    .path
                    .iter()
                    .find(|cursor| cursor.id == 4 && cursor.kind == "RunTime")
                    .expect("runtime path cursor")
                    .iteration,
            );
        }
        assert_eq!(actual, vec![0, 1, 2]);
        assert_eq!(
            runner
                .step(LogicInput {
                    elapsed: Duration::from_secs(1),
                    ..LogicInput::default()
                })
                .expect("runtime completion"),
            LogicStep::Complete
        );
    }

    #[test]
    fn next_root_iteration_restarts_finite_frames_without_leaking_markers() {
        let program = LogicProgram::compile(LogicNode::Loop {
            id: 1,
            count: LoopCount::finite(2),
            children: vec![LogicNode::Sample { id: 2 }],
        })
        .expect("program");
        let mut runner = program.runner();
        for expected_iteration in [0, 1] {
            let LogicStep::Sample(selection) = runner
                .step(LogicInput::default())
                .expect("finite-loop sample")
            else {
                panic!("finite loop ended before its second frame");
            };
            assert_eq!(
                selection.path.last().map(|cursor| cursor.iteration),
                Some(expected_iteration)
            );
        }
        assert_eq!(
            runner.step(LogicInput::default()).expect("first complete"),
            LogicStep::Complete
        );
        runner.next_root_iteration().expect("next root iteration");
        let LogicStep::Sample(selection) = runner
            .step(LogicInput::default())
            .expect("restarted finite-loop sample")
        else {
            panic!("finite loop marker leaked across root iterations");
        };
        assert_eq!(
            selection.path.last().map(|cursor| cursor.iteration),
            Some(0)
        );
    }

    #[test]
    fn skipped_if_reinitializes_finite_descendants_before_reentry() {
        let program = LogicProgram::compile(LogicNode::Loop {
            id: 1,
            count: LoopCount::finite(2),
            children: vec![LogicNode::Sequence {
                id: 2,
                children: vec![
                    LogicNode::If {
                        id: 3,
                        condition: LogicCondition::VariableBoolean {
                            name: "allow".to_owned(),
                        },
                        evaluate_each_iteration: true,
                        children: vec![LogicNode::ForEach {
                            id: 4,
                            input_prefix: "item".to_owned(),
                            output_variable: "current".to_owned(),
                            children: vec![LogicNode::Sample { id: 10 }],
                        }],
                    },
                    LogicNode::Sample { id: 20 },
                ],
            }],
        })
        .expect("program");
        let mut runner = program.runner();
        runner.set_variable("allow", "true");
        runner.set_variable("item_matchNr", "2");
        runner.set_variable("item_1", "a");
        runner.set_variable("item_2", "b");

        assert!(matches!(
            runner.step(LogicInput::default()).expect("first foreach"),
            LogicStep::Sample(LogicSelection { sampler_id: 10, .. })
        ));
        assert!(matches!(
            runner.step(LogicInput::default()).expect("second foreach"),
            LogicStep::Sample(LogicSelection { sampler_id: 10, .. })
        ));
        runner.set_variable("allow", "false");
        assert!(matches!(
            runner
                .step(LogicInput::default())
                .expect("sibling after skip"),
            LogicStep::Sample(LogicSelection { sampler_id: 20, .. })
        ));

        runner.set_variable("allow", "true");
        assert!(matches!(
            runner
                .step(LogicInput::default())
                .expect("reentered foreach"),
            LogicStep::Sample(LogicSelection { sampler_id: 10, .. })
        ));
        assert_eq!(
            runner.variables().get("current").map(String::as_str),
            Some("a")
        );
    }

    #[test]
    fn selection_retains_transaction_and_critical_section_identity() {
        let root = LogicNode::Transaction {
            id: 2,
            parent: true,
            include_timers: true,
            children: vec![LogicNode::CriticalSection {
                id: 3,
                lock_name: "gate".to_owned(),
                children: vec![LogicNode::Sample { id: 4 }],
            }],
        };
        let program = LogicProgram::compile(root).expect("program");
        let mut runner = program.runner();
        let step = runner.step(LogicInput::default()).expect("step");
        assert!(matches!(step, LogicStep::Sample(_)));
        let LogicStep::Sample(selection) = step else {
            return;
        };
        assert_eq!(selection.transactions, vec![2]);
        assert_eq!(selection.critical_sections, vec!["gate"]);
        assert_eq!(selection.critical_section_ids, vec![3]);
    }

    #[test]
    fn nested_same_name_critical_sections_fail_before_coordination() {
        let program = LogicProgram::compile(LogicNode::CriticalSection {
            id: 1,
            lock_name: "gate".to_owned(),
            children: vec![LogicNode::CriticalSection {
                id: 2,
                lock_name: "gate".to_owned(),
                children: vec![LogicNode::Sample { id: 3 }],
            }],
        })
        .expect("program compiles until runtime path is entered");
        let mut runner = program.runner();
        assert!(matches!(
            runner.step(LogicInput::default()),
            Err(LogicControllerError::Unsupported {
                capability_id,
                ..
            }) if capability_id == "critical-section-reentrant-name"
        ));
    }

    #[test]
    fn root_iteration_keeps_once_only_state_and_reports_iteration() {
        let program = LogicProgram::compile(LogicNode::OnceOnly {
            id: 1,
            children: vec![LogicNode::Sample { id: 2 }],
        })
        .expect("program");
        let mut runner = program.runner();
        assert!(matches!(
            runner.step(LogicInput::default()).expect("sample"),
            LogicStep::Sample(_)
        ));
        assert!(matches!(
            runner.step(LogicInput::default()).expect("complete"),
            LogicStep::Complete
        ));
        runner.next_root_iteration().expect("next iteration");
        assert_eq!(runner.root_iteration(), 1);
        assert!(matches!(
            runner
                .step(LogicInput::default())
                .expect("once-only complete"),
            LogicStep::Complete
        ));
    }

    #[test]
    fn if_evaluate_all_false_rechecks_each_root_iteration() {
        let program = LogicProgram::compile(LogicNode::If {
            id: 1,
            condition: LogicCondition::VariableBoolean {
                name: "allow".to_owned(),
            },
            evaluate_each_iteration: false,
            children: vec![LogicNode::Sample { id: 2 }],
        })
        .expect("program");
        let mut runner = program.runner();
        runner.set_variable("allow", "true");
        assert_eq!(sample_ids_with_runner(&mut runner, 4), vec![2]);

        runner.set_variable("allow", "false");
        runner.next_root_iteration().expect("second iteration");
        assert!(sample_ids_with_runner(&mut runner, 4).is_empty());

        runner.set_variable("allow", "true");
        runner.next_root_iteration().expect("third iteration");
        assert_eq!(sample_ids_with_runner(&mut runner, 4), vec![2]);
    }

    #[test]
    fn if_evaluate_all_false_rechecks_nested_controller_entries() {
        let program = LogicProgram::compile(LogicNode::Loop {
            id: 1,
            count: LoopCount::finite(2),
            children: vec![LogicNode::If {
                id: 2,
                condition: LogicCondition::VariableBoolean {
                    name: "allow".to_owned(),
                },
                evaluate_each_iteration: false,
                children: vec![LogicNode::Sample { id: 3 }],
            }],
        })
        .expect("program");
        let mut runner = program.runner();
        runner.set_variable("allow", "true");
        assert!(matches!(
            runner.step(LogicInput::default()).expect("first visit"),
            LogicStep::Sample(LogicSelection { sampler_id: 3, .. })
        ));

        runner.set_variable("allow", "false");
        assert!(matches!(
            runner
                .step(LogicInput::default())
                .expect("second visit skipped"),
            LogicStep::Complete
        ));
    }

    #[test]
    fn if_evaluate_all_rechecks_before_each_child_and_aborts_remaining_body() {
        let program = LogicProgram::compile(LogicNode::Sequence {
            id: 1,
            children: vec![
                LogicNode::If {
                    id: 2,
                    condition: LogicCondition::VariableBoolean {
                        name: "allow".to_owned(),
                    },
                    evaluate_each_iteration: true,
                    children: vec![LogicNode::Sample { id: 10 }, LogicNode::Sample { id: 11 }],
                },
                LogicNode::Sample { id: 20 },
            ],
        })
        .expect("program");
        let mut runner = program.runner();
        runner.set_variable("allow", "true");
        assert!(matches!(
            runner.step(LogicInput::default()).expect("first child"),
            LogicStep::Sample(LogicSelection { sampler_id: 10, .. })
        ));

        runner.set_variable("allow", "false");
        assert!(matches!(
            runner
                .step(LogicInput::default())
                .expect("sibling after abort"),
            LogicStep::Sample(LogicSelection { sampler_id: 20, .. })
        ));
        assert!(matches!(
            runner.step(LogicInput::default()).expect("complete"),
            LogicStep::Complete
        ));
    }

    #[test]
    fn if_evaluate_all_rechecks_nested_frames_inner_false_keeps_outer_siblings() {
        let program = LogicProgram::compile(LogicNode::Sequence {
            id: 1,
            children: vec![
                LogicNode::If {
                    id: 2,
                    condition: LogicCondition::VariableBoolean {
                        name: "outer".to_owned(),
                    },
                    evaluate_each_iteration: true,
                    children: vec![
                        LogicNode::If {
                            id: 3,
                            condition: LogicCondition::VariableBoolean {
                                name: "inner".to_owned(),
                            },
                            evaluate_each_iteration: true,
                            children: vec![
                                LogicNode::Sample { id: 10 },
                                LogicNode::Sample { id: 11 },
                            ],
                        },
                        LogicNode::Sample { id: 12 },
                    ],
                },
                LogicNode::Sample { id: 20 },
            ],
        })
        .expect("program");
        let mut runner = program.runner();
        runner.set_variable("outer", "true");
        runner.set_variable("inner", "true");
        assert!(matches!(
            runner.step(LogicInput::default()).expect("inner child"),
            LogicStep::Sample(LogicSelection { sampler_id: 10, .. })
        ));

        runner.set_variable("inner", "false");
        assert!(matches!(
            runner.step(LogicInput::default()).expect("outer sibling"),
            LogicStep::Sample(LogicSelection { sampler_id: 12, .. })
        ));
        runner.set_variable("outer", "false");
        assert!(matches!(
            runner.step(LogicInput::default()).expect("root sibling"),
            LogicStep::Sample(LogicSelection { sampler_id: 20, .. })
        ));
    }

    #[test]
    fn if_abort_resets_descendant_foreach_state_before_reentry() {
        let program = LogicProgram::compile(LogicNode::Loop {
            id: 1,
            count: LoopCount::finite(2),
            children: vec![
                LogicNode::If {
                    id: 2,
                    condition: LogicCondition::VariableBoolean {
                        name: "allow".to_owned(),
                    },
                    evaluate_each_iteration: true,
                    children: vec![LogicNode::ForEach {
                        id: 3,
                        input_prefix: "item".to_owned(),
                        output_variable: "current".to_owned(),
                        children: vec![LogicNode::Sample { id: 10 }],
                    }],
                },
                LogicNode::Sample { id: 20 },
            ],
        })
        .expect("program");
        let mut runner = program.runner();
        runner.set_variable("allow", "true");
        runner.set_variable("item_matchNr", "2");
        runner.set_variable("item_1", "a");
        runner.set_variable("item_2", "b");
        assert!(matches!(
            runner
                .step(LogicInput::default())
                .expect("first foreach child"),
            LogicStep::Sample(LogicSelection { sampler_id: 10, .. })
        ));
        assert_eq!(
            runner.variables().get("current").map(String::as_str),
            Some("a")
        );

        runner.set_variable("allow", "false");
        assert!(matches!(
            runner
                .step(LogicInput::default())
                .expect("loop sibling after abort"),
            LogicStep::Sample(LogicSelection { sampler_id: 20, .. })
        ));

        runner.set_variable("allow", "true");
        assert!(matches!(
            runner
                .step(LogicInput::default())
                .expect("reentered foreach child"),
            LogicStep::Sample(LogicSelection { sampler_id: 10, .. })
        ));
        assert_eq!(
            runner.variables().get("current").map(String::as_str),
            Some("a")
        );
    }

    #[test]
    fn random_decisions_request_exactly_one_seeded_value() {
        let program = LogicProgram::compile(LogicNode::Random {
            id: 1,
            children: vec![LogicNode::Sample { id: 2 }, LogicNode::Sample { id: 3 }],
        })
        .expect("program");
        let mut runner = program.runner();
        assert_eq!(
            runner.step(LogicInput::default()).expect("request"),
            LogicStep::NeedsRandom
        );
        assert!(matches!(
            runner
                .step(LogicInput {
                    random_value: Some(1),
                    ..LogicInput::default()
                })
                .expect("sample"),
            LogicStep::Sample(LogicSelection { sampler_id: 3, .. })
        ));
    }

    #[test]
    fn nested_random_controllers_consume_distinct_seeded_values() {
        let program = LogicProgram::compile(LogicNode::Random {
            id: 1,
            children: vec![
                LogicNode::Sample { id: 99 },
                LogicNode::Random {
                    id: 2,
                    children: vec![LogicNode::Sample { id: 10 }, LogicNode::Sample { id: 11 }],
                },
            ],
        })
        .expect("program");
        let mut runner = program.runner();

        assert_eq!(
            runner.step(LogicInput::default()).expect("outer request"),
            LogicStep::NeedsRandom
        );
        // The first value is consumed by the outer controller. A nested
        // decision must request another value instead of accidentally
        // reusing it within this same step call.
        assert_eq!(
            runner
                .step(LogicInput {
                    random_value: Some(1),
                    ..LogicInput::default()
                })
                .expect("inner request"),
            LogicStep::NeedsRandom
        );
        assert!(matches!(
            runner
                .step(LogicInput {
                    random_value: Some(0),
                    ..LogicInput::default()
                })
                .expect("nested sample"),
            LogicStep::Sample(LogicSelection { sampler_id: 10, .. })
        ));
    }

    #[test]
    fn next_loop_without_an_active_loop_ends_the_current_root_iteration() {
        let program = LogicProgram::compile(LogicNode::Sequence {
            id: 1,
            children: vec![LogicNode::Sample { id: 10 }, LogicNode::Sample { id: 11 }],
        })
        .expect("program");
        let mut runner = program.runner();
        assert!(matches!(
            runner.step(LogicInput::default()).expect("first sample"),
            LogicStep::Sample(LogicSelection { sampler_id: 10, .. })
        ));
        assert_eq!(
            runner
                .step(LogicInput {
                    signal: ControlSignal::NextLoop,
                    ..LogicInput::default()
                })
                .expect("next-loop action"),
            LogicStep::Complete
        );
        runner.next_root_iteration().expect("next root iteration");
        assert!(matches!(
            runner.step(LogicInput::default()).expect("restarted root"),
            LogicStep::Sample(LogicSelection { sampler_id: 10, .. })
        ));
    }

    #[test]
    fn duplicate_logic_ids_are_rejected_before_execution() {
        assert!(matches!(
            LogicProgram::compile(LogicNode::Sequence {
                id: 1,
                children: vec![LogicNode::Sample { id: 2 }, LogicNode::Sample { id: 2 }],
            }),
            Err(LogicControllerError::DuplicateControllerId { controller: 2 })
        ));
    }

    #[test]
    fn total_throughput_uses_run_shared_state_when_not_per_user() {
        let program = LogicProgram::compile(LogicNode::Throughput {
            id: 1,
            mode: ThroughputMode::Total,
            limit: 1,
            percent: 0.0,
            per_user: false,
            children: vec![LogicNode::Sample { id: 2 }],
        })
        .expect("program");
        let shared = Arc::new(LogicSharedState::default());
        let mut first = program.runner_with_shared_state(Arc::clone(&shared));
        let mut second = program.runner_with_shared_state(shared);
        assert!(matches!(
            first.step(LogicInput::default()).expect("first sample"),
            LogicStep::Sample(_)
        ));
        assert!(matches!(
            second.step(LogicInput::default()).expect("second complete"),
            LogicStep::Complete
        ));
    }

    #[test]
    fn unsupported_condition_and_resource_limits_are_typed() {
        let error = LogicProgram::compile(LogicNode::If {
            id: 4,
            condition: LogicCondition::External {
                capability_id: "jvm.groovy".to_owned(),
            },
            evaluate_each_iteration: true,
            children: vec![LogicNode::Sample { id: 1 }],
        })
        .expect("compile does not evaluate condition");
        let mut runner = error.runner();
        assert!(matches!(
            runner.step(LogicInput::default()),
            Err(LogicControllerError::Unsupported { .. })
        ));
        let limits = LogicLimits {
            max_nodes: 1,
            ..LogicLimits::default()
        };
        assert!(matches!(
            LogicProgram::compile_with_limits(
                LogicNode::Sequence {
                    id: 1,
                    children: vec![LogicNode::Sample { id: 2 }],
                },
                limits,
            ),
            Err(LogicControllerError::PlanTooLarge { .. })
        ));
    }
}
