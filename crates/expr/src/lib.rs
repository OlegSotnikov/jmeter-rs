// SPDX-License-Identifier: Apache-2.0
//! Bounded, executor-independent JMeter expression expansion.
//!
//! The crate contains the syntax and evaluation foundation shared by the
//! model and runtime crates.  Callers can provide their own read-only
//! function resolver, or use the explicit native registry for the deterministic
//! JMeter 5.6.3 functions implemented here.  File, clock, random, network,
//! and JVM capabilities remain outside the pure expression boundary unless a
//! future resolver injects them explicitly.
//!
//! The supported syntax is the part of JMeter's expression language needed by
//! the foundation:
//!
//! * literal text;
//! * `${NAME}` variable references (variable names are trimmed);
//! * `${__name(args)}` function calls; and
//! * `${__name}` no-argument calls.
//!
//! Function arguments may contain nested references and are split on
//! unescaped commas, except while scanning a nested `${...}` reference.  A
//! backslash before `$`, `,`, or `\` escapes that character when the
//! containing expression has a reference; otherwise it remains literal.
//! Undefined variables and functions are emitted verbatim, as required by the
//! JMeter 5.6.3 behavior map.  Malformed references and resource-limit
//! violations are explicit errors rather than silent fallbacks.

use std::borrow::Borrow;
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::fmt;
use std::hash::{BuildHasher, Hash};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

mod builtins;

pub use builtins::{
    BuiltinFunctions, BuiltinRegistry, EXTENDED_FUNCTION_NAMES, FunctionCapability,
    FunctionInvocationRequirements, FunctionSupport, KNOWN_FUNCTION_NAMES, MapPropertyCapability,
    MapVariableCapability, SharedBuiltinFunctions, SharedBuiltinRegistry, StaticTestPlanName,
};

/// Limits applied to one expansion operation.
///
/// Limits are checked before allocating output for a segment.  The input
/// limit is measured in UTF-8 bytes, as are the output and function result
/// limits.  Nesting counts references currently being evaluated, while the
/// expansion count includes each unescaped `${...}` reference encountered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvaluationLimits {
    /// Maximum UTF-8 bytes accepted in the input expression.
    pub max_input_bytes: usize,
    /// Maximum number of nested references evaluated at once.
    pub max_nesting: usize,
    /// Maximum number of references encountered in one operation.
    pub max_expansions: usize,
    /// Maximum UTF-8 bytes in the resulting expression.
    pub max_output_bytes: usize,
}

impl EvaluationLimits {
    /// Creates a limits policy from the four resource ceilings.
    #[must_use]
    pub const fn new(
        max_input_bytes: usize,
        max_nesting: usize,
        max_expansions: usize,
        max_output_bytes: usize,
    ) -> Self {
        Self {
            max_input_bytes,
            max_nesting,
            max_expansions,
            max_output_bytes,
        }
    }
}

impl Default for EvaluationLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 64 * 1024,
            max_nesting: 32,
            max_expansions: 1_024,
            max_output_bytes: 256 * 1024,
        }
    }
}

/// Maximum structural segments retained for one function occurrence.
///
/// The default evaluator's nesting ceiling needs at most three segments per
/// level (parent, argument selector, local offset); this larger fixed bound
/// also leaves room for explicitly configured deeper policies without making
/// identity state unbounded.
pub const MAX_FUNCTION_OCCURRENCE_PATH_SEGMENTS: usize = 128;

const OCCURRENCE_INDIRECTION_MARKER: u64 = u64::MAX;

/// Stable categories for expression-evaluation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCode {
    /// The input exceeded [`EvaluationLimits::max_input_bytes`].
    InputLimit,
    /// Evaluation exceeded [`EvaluationLimits::max_nesting`].
    NestingLimit,
    /// Evaluation exceeded [`EvaluationLimits::max_expansions`].
    ExpansionLimit,
    /// Evaluation exceeded [`EvaluationLimits::max_output_bytes`].
    OutputLimit,
    /// A `${` reference did not have a matching closing brace.
    UnclosedReference,
    /// A function call did not have a matching closing parenthesis.
    UnclosedFunction,
    /// A function call had invalid trailing syntax.
    InvalidFunction,
    /// A supplied function resolver rejected a call.
    FunctionError,
    /// The structural function-occurrence path exceeded its bound.
    OccurrencePathLimit,
}

impl ErrorCode {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InputLimit => "EXPR_INPUT_LIMIT",
            Self::NestingLimit => "EXPR_NESTING_LIMIT",
            Self::ExpansionLimit => "EXPR_EXPANSION_LIMIT",
            Self::OutputLimit => "EXPR_OUTPUT_LIMIT",
            Self::UnclosedReference => "EXPR_UNCLOSED_REFERENCE",
            Self::UnclosedFunction => "EXPR_UNCLOSED_FUNCTION",
            Self::InvalidFunction => "EXPR_INVALID_FUNCTION",
            Self::FunctionError => "EXPR_FUNCTION_ERROR",
            Self::OccurrencePathLimit => "EXPR_OCCURRENCE_PATH_LIMIT",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A failure returned by a function implementation.
///
/// The resolver can use these constructors for test fakes and for future
/// built-in functions.  No constructor performs I/O or supplies a fallback
/// value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FunctionError {
    /// The argument list does not satisfy the function contract.
    InvalidArguments(String),
    /// The function failed while evaluating its supplied arguments.
    Execution(String),
    /// The function is known but unavailable in the active capability set.
    Unsupported(String),
    /// A stateful function reached an explicit thread-stop boundary.
    ///
    /// This is kept separate from an ordinary execution failure so an outer
    /// runtime can map an exhausted data sequence to JMeter's stop-thread
    /// control action without guessing from a human-readable message.
    StopThread(String),
    /// A bounded state store or identity reached its explicit capacity.
    ///
    /// Capacity failures are fail-closed: state is never evicted, reset, or
    /// silently reused to make room for a new occurrence.
    ResourceLimit(String),
    /// A state capability or session authority is poisoned and cannot safely
    /// continue.  Poison is deliberately distinct from an ordinary function
    /// execution failure so callers cannot accidentally recover with a stale
    /// or partially applied state value.
    Poisoned(String),
}

impl FunctionError {
    /// Creates an invalid-argument error.
    #[must_use]
    pub fn invalid_arguments(message: impl Into<String>) -> Self {
        Self::InvalidArguments(message.into())
    }

    /// Creates an execution error.
    #[must_use]
    pub fn execution(message: impl Into<String>) -> Self {
        Self::Execution(message.into())
    }

    /// Creates an unsupported-capability error.
    #[must_use]
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::Unsupported(message.into())
    }

    /// Creates a stop-thread control result.
    #[must_use]
    pub fn stop_thread(message: impl Into<String>) -> Self {
        Self::StopThread(message.into())
    }

    /// Creates a bounded-resource failure.
    #[must_use]
    pub fn resource_limit(message: impl Into<String>) -> Self {
        Self::ResourceLimit(message.into())
    }

    /// Creates a typed poisoned-state failure.
    #[must_use]
    pub fn poisoned(message: impl Into<String>) -> Self {
        Self::Poisoned(message.into())
    }

    /// Returns a stable code for this function failure.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidArguments(_) => "FUNC_INVALID_ARGUMENTS",
            Self::Execution(_) => "FUNC_EXECUTION",
            Self::Unsupported(_) => "FUNC_UNSUPPORTED",
            Self::StopThread(_) => "FUNC_STOP_THREAD",
            Self::ResourceLimit(_) => "FUNC_RESOURCE_LIMIT",
            Self::Poisoned(_) => "FUNC_POISONED",
        }
    }
}

impl fmt::Display for FunctionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArguments(message) => write!(formatter, "invalid arguments: {message}"),
            Self::Execution(message) => write!(formatter, "function execution failed: {message}"),
            Self::Unsupported(message) => write!(formatter, "function unsupported: {message}"),
            Self::StopThread(message) => {
                write!(formatter, "function requested thread stop: {message}")
            }
            Self::ResourceLimit(message) => {
                write!(formatter, "function resource limit reached: {message}")
            }
            Self::Poisoned(message) => write!(formatter, "function state is poisoned: {message}"),
        }
    }
}

impl Error for FunctionError {}

/// A bounded expression-evaluation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvaluationError {
    /// The input was larger than the configured input ceiling.
    InputTooLong {
        /// Configured maximum input bytes.
        limit: usize,
        /// Actual input bytes.
        actual: usize,
    },
    /// A nested reference exceeded the configured nesting ceiling.
    NestingLimitExceeded {
        /// Configured maximum nesting.
        limit: usize,
        /// Byte offset of the reference that exceeded the limit.
        offset: usize,
    },
    /// The number of encountered references exceeded the configured ceiling.
    ExpansionLimitExceeded {
        /// Configured maximum expansions.
        limit: usize,
        /// Byte offset of the reference that exceeded the limit.
        offset: usize,
    },
    /// The output would exceed the configured output ceiling.
    OutputTooLong {
        /// Configured maximum output bytes.
        limit: usize,
        /// Output bytes that would have been produced.
        actual: usize,
    },
    /// A reference began with `${` but did not close.
    UnclosedReference {
        /// Byte offset of the opening `$`.
        offset: usize,
    },
    /// A function call did not close its argument list.
    UnclosedFunction {
        /// Byte offset of the function body.
        offset: usize,
    },
    /// A function call had text after its closing parenthesis.
    InvalidFunction {
        /// Byte offset of the function body.
        offset: usize,
    },
    /// A resolver rejected a function call.
    Function {
        /// Exact, case-sensitive function reference name.
        name: String,
        /// Resolver-provided typed failure.
        source: FunctionError,
    },
    /// A nested function occurrence could not be assigned a bounded path.
    OccurrencePathLimitExceeded {
        /// Configured maximum path segments.
        limit: usize,
        /// Byte offset of the reference whose path exceeded the bound.
        offset: usize,
    },
}

impl EvaluationError {
    /// Returns the stable machine-readable category for this error.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::InputTooLong { .. } => ErrorCode::InputLimit,
            Self::NestingLimitExceeded { .. } => ErrorCode::NestingLimit,
            Self::ExpansionLimitExceeded { .. } => ErrorCode::ExpansionLimit,
            Self::OutputTooLong { .. } => ErrorCode::OutputLimit,
            Self::UnclosedReference { .. } => ErrorCode::UnclosedReference,
            Self::UnclosedFunction { .. } => ErrorCode::UnclosedFunction,
            Self::InvalidFunction { .. } => ErrorCode::InvalidFunction,
            Self::Function { .. } => ErrorCode::FunctionError,
            Self::OccurrencePathLimitExceeded { .. } => ErrorCode::OccurrencePathLimit,
        }
    }

    /// Returns the byte offset associated with a syntax or limit failure.
    ///
    /// Function resolver failures do not have a source offset because a
    /// resolver may derive its result from a capability outside this crate.
    #[must_use]
    pub const fn offset(&self) -> Option<usize> {
        match self {
            Self::NestingLimitExceeded { offset, .. }
            | Self::ExpansionLimitExceeded { offset, .. }
            | Self::UnclosedReference { offset }
            | Self::UnclosedFunction { offset }
            | Self::InvalidFunction { offset } => Some(*offset),
            Self::InputTooLong { .. } | Self::OutputTooLong { .. } | Self::Function { .. } => None,
            Self::OccurrencePathLimitExceeded { offset, .. } => Some(*offset),
        }
    }
}

impl fmt::Display for EvaluationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLong { limit, actual } => {
                write!(
                    formatter,
                    "{}: input is {actual} bytes (limit {limit})",
                    self.code()
                )
            }
            Self::NestingLimitExceeded { limit, offset } => write!(
                formatter,
                "{}: nesting limit {limit} exceeded at byte {offset}",
                self.code()
            ),
            Self::ExpansionLimitExceeded { limit, offset } => write!(
                formatter,
                "{}: expansion limit {limit} exceeded at byte {offset}",
                self.code()
            ),
            Self::OutputTooLong { limit, actual } => write!(
                formatter,
                "{}: output would be {actual} bytes (limit {limit})",
                self.code()
            ),
            Self::UnclosedReference { offset } => {
                write!(formatter, "{} at byte {offset}", self.code())
            }
            Self::UnclosedFunction { offset } => {
                write!(formatter, "{} at byte {offset}", self.code())
            }
            Self::InvalidFunction { offset } => {
                write!(formatter, "{} at byte {offset}", self.code())
            }
            Self::Function { name, source } => {
                write!(formatter, "{} for {name}: {source}", self.code())
            }
            Self::OccurrencePathLimitExceeded { limit, offset } => write!(
                formatter,
                "{}: occurrence path limit {limit} exceeded at byte {offset}",
                self.code()
            ),
        }
    }
}

impl Error for EvaluationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Function { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// A read-only source of thread-local JMeter variables.
pub trait VariableResolver: Sync {
    /// Resolves an exact, case-sensitive variable name.
    fn resolve_variable(&self, name: &str) -> Option<&str>;
}

/// A read-only source of run-scoped JMeter properties.
pub trait PropertyResolver: Sync {
    /// Resolves an exact, case-sensitive property name.
    fn resolve_property(&self, name: &str) -> Option<&str>;
}

/// An explicitly injected capability for variable side effects.
///
/// The read-only [`VariableResolver`] API remains unchanged.  A caller that
/// wants functions such as `__changeCase` to write a result variable must
/// provide this capability through [`EvaluationCapabilities`].  Implementors
/// use an interior synchronization primitive when they are shared by worker
/// threads; the expression core never assumes a particular storage model.
pub trait VariableSetter: Sync + Send {
    /// Stores a value under an exact, case-sensitive variable name.
    fn set_variable(&self, name: &str, value: &str) -> Result<(), FunctionError>;

    /// Stores several values as one logical mutation.
    ///
    /// Implementors backed by a map should override this method to commit all
    /// entries while holding their store lock. The default supplies a
    /// recoverable transaction for setter-only capabilities by snapshotting
    /// values and rolling back on the first failed write; a rollback failure
    /// is returned explicitly rather than being ignored.
    fn set_variables_atomic(&self, values: &[(&str, &str)]) -> Result<(), FunctionError> {
        let mut previous = Vec::with_capacity(values.len());
        for (name, _) in values {
            if previous.iter().all(|(existing, _)| existing != name) {
                previous.push(((*name).to_owned(), self.get_variable_checked(name)?));
            }
        }
        for (name, value) in values {
            if let Err(error) = self.set_variable(name, value) {
                let mut rollback_error = None;
                for (name, old_value) in previous.iter().rev() {
                    let result = match old_value {
                        Some(value) => self.set_variable(name, value),
                        None => self.remove_variable(name),
                    };
                    if let Err(error) = result {
                        rollback_error = Some(error);
                        break;
                    }
                }
                return match rollback_error {
                    Some(rollback @ FunctionError::Poisoned(_)) => Err(rollback),
                    Some(rollback) => Err(FunctionError::execution(format!(
                        "variable mutation failed ({error}); rollback failed ({rollback})"
                    ))),
                    None => Err(error),
                };
            }
        }
        Ok(())
    }

    /// Reads a value owned by the capability, when it also acts as the
    /// mutable variable store.  Setter-only capabilities may return `None`.
    #[must_use]
    fn get_variable(&self, _name: &str) -> Option<String> {
        None
    }

    /// Reads a variable while preserving a poisoned-lock diagnostic.
    ///
    /// This checked companion keeps the original optional getter available to
    /// existing capability implementations while giving new implementations
    /// a fail-closed read path.  A lock-backed capability should override this
    /// method; returning `Ok(None)` means the variable is genuinely absent.
    fn get_variable_checked(&self, name: &str) -> Result<Option<String>, FunctionError> {
        Ok(self.get_variable(name))
    }

    /// Removes a variable from the mutable store.
    ///
    /// JMeter's split and extractor functions clear stale numbered values.
    /// A capability that cannot remove values may retain the default no-op,
    /// but callers must not treat that as a guarantee that a value existed.
    fn remove_variable(&self, _name: &str) -> Result<(), FunctionError> {
        Ok(())
    }
}

/// An explicitly injected capability for run-scoped property side effects.
///
/// [`PropertyResolver`] remains read-only.  This separate capability is
/// required by `__setProperty`; omitting it produces a typed unsupported
/// capability error rather than silently dropping a global mutation.
pub trait PropertySetter: Sync + Send {
    /// Sets a property and returns its previous value, if any.
    fn set_property(&self, name: &str, value: &str) -> Result<Option<String>, FunctionError>;

    /// Reads a value owned by the capability, when it also acts as the
    /// mutable property store.  Setter-only capabilities may return `None`.
    #[must_use]
    fn get_property(&self, _name: &str) -> Option<String> {
        None
    }

    /// Reads a property while preserving a poisoned-lock diagnostic.
    fn get_property_checked(&self, name: &str) -> Result<Option<String>, FunctionError> {
        Ok(self.get_property(name))
    }
}

/// Supplies the current test-plan name to `__TestPlanName`.
pub trait TestPlanNameResolver: Sync + Send {
    /// Returns the saved test-plan name, or `None` when no plan is saved.
    #[must_use]
    fn test_plan_name(&self) -> Option<String>;
}

/// Supplies deterministic random bits to functions that need randomness.
///
/// The expression crate never reaches for process-global randomness.  A
/// runtime may inject a cryptographically secure or seeded source according
/// to its execution policy; tests commonly inject a fixed sequence.
pub trait RandomSource: Sync + Send {
    /// Returns the next uniformly distributed 64-bit value from the source.
    fn next_u64(&self) -> u64;
}

/// Supplies wall-clock time and an optional fixed offset for date functions.
///
/// The offset is expressed in seconds east of UTC.  A caller that needs a
/// named time-zone or locale must perform that policy at the capability
/// boundary; the pure evaluator never consults the host environment.
pub trait ClockSource: Sync + Send {
    /// Returns milliseconds since the Unix epoch.
    fn now_millis(&self) -> Result<i64, FunctionError>;

    /// Returns the offset used when formatting local date/time values.
    fn offset_seconds(&self) -> i32 {
        0
    }

    /// Returns the locale name used by locale-sensitive date/time patterns.
    ///
    /// The default is the profile's deterministic `en_US` locale.  A runtime
    /// with a pinned Java-compatible locale may override this; unknown names
    /// are reported as an explicit capability error by the native registry.
    fn locale(&self) -> Option<String> {
        Some("en_US".to_owned())
    }
}

/// Supplies per-thread execution identity to information and stateful
/// functions.  Any field may be absent when the expression is evaluated
/// before a virtual user has been created.
pub trait ExecutionContext: Sync + Send {
    /// Returns the one-based JMeter thread number, if one exists.
    fn thread_num(&self) -> Option<u32> {
        None
    }

    /// Returns the containing thread-group name, if one exists.
    fn thread_group_name(&self) -> Option<String> {
        None
    }

    /// Returns the current sampler label, if one exists.
    fn sampler_name(&self) -> Option<String> {
        None
    }

    /// Returns a stable identity for the owning virtual-user lifecycle.
    ///
    /// A new lifecycle identity is required when a runtime reuses a thread
    /// number for another virtual user.  Implementations that do not expose
    /// this distinction may leave it absent; stateful functions then retain
    /// their process-local lifecycle.
    fn lifecycle_id(&self) -> Option<u64> {
        None
    }

    /// Returns the explicit root-iteration identity for the current
    /// virtual-user evaluation, if one has been established.
    ///
    /// Function state must never infer an iteration from wall-clock time,
    /// evaluator calls, or process-global mutable state.  Runtime adapters
    /// should return the stable zero-based iteration supplied by their
    /// lifecycle state.  The default is absent so callers that evaluate
    /// expressions outside an iteration receive a typed capability error from
    /// iteration-sensitive functions rather than a guessed value.
    fn iteration_id(&self) -> Option<u64> {
        None
    }

    /// Returns the complete identity used to scope iteration-sensitive
    /// function state.
    ///
    /// Implementors normally only need to provide [`Self::iteration_id`].
    /// Lifecycle and thread identity are included when available so a shared
    /// global function occurrence can cache one value per user's iteration
    /// without conflating two users that happen to be on the same iteration
    /// number.  An adapter with a stronger identity may override this method
    /// directly.
    fn iteration_identity(&self) -> Option<IterationIdentity> {
        self.iteration_id().map(|iteration| {
            IterationIdentity::scoped(self.lifecycle_id(), self.thread_num(), iteration)
        })
    }
}

/// Explicit identity of one virtual-user root iteration.
///
/// The iteration number alone is not globally unique: two users can both be
/// in iteration zero.  Optional lifecycle and thread fields therefore travel
/// with the identity when the execution adapter exposes them.  No field is
/// derived from ambient process state.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IterationIdentity {
    lifecycle_id: Option<u64>,
    thread_num: Option<u32>,
    iteration: u64,
}

impl IterationIdentity {
    /// Creates an identity with only an explicit iteration number.
    #[must_use]
    pub const fn new(iteration: u64) -> Self {
        Self {
            lifecycle_id: None,
            thread_num: None,
            iteration,
        }
    }

    /// Creates an identity with explicit virtual-user scope.
    #[must_use]
    pub const fn for_user(lifecycle_id: u64, thread_num: u32, iteration: u64) -> Self {
        Self {
            lifecycle_id: Some(lifecycle_id),
            thread_num: Some(thread_num),
            iteration,
        }
    }

    /// Creates an identity from optional adapter-provided scope fields.
    #[must_use]
    pub const fn scoped(
        lifecycle_id: Option<u64>,
        thread_num: Option<u32>,
        iteration: u64,
    ) -> Self {
        Self {
            lifecycle_id,
            thread_num,
            iteration,
        }
    }

    /// Returns the explicit zero-based (or adapter-defined) iteration number.
    #[must_use]
    pub const fn iteration(self) -> u64 {
        self.iteration
    }

    /// Returns the virtual-user lifecycle identity, when supplied.
    #[must_use]
    pub const fn lifecycle_id(self) -> Option<u64> {
        self.lifecycle_id
    }

    /// Returns the one-based thread number, when supplied.
    #[must_use]
    pub const fn thread_num(self) -> Option<u32> {
        self.thread_num
    }
}

/// Supplies the machine identity functions without permitting ambient host
/// or DNS access inside the expression core.
pub trait HostResolver: Sync + Send {
    /// Returns the local host name.
    fn machine_name(&self) -> Result<String, FunctionError>;

    /// Returns the local host address.
    fn machine_ip(&self) -> Result<String, FunctionError>;
}

/// Receives log records emitted by `__log` and `__logn`.
pub trait LogSink: Sync + Send {
    /// Records a function log call.  Level names use JMeter's `OUT`, `ERR`,
    /// `DEBUG`, `INFO`, `WARN`, and `ERROR` vocabulary.
    fn log(
        &self,
        level: &str,
        message: &str,
        throwable: Option<&str>,
        comment: Option<&str>,
    ) -> Result<(), FunctionError>;
}

/// A capability for file-backed built-ins.
///
/// Paths, encodings, cursor sharing, and filesystem policy belong to the
/// injected implementation.  This trait keeps those effects out of the
/// pure crate while still allowing deterministic local adapters.
pub trait FileCapability: Sync + Send {
    /// Reads an entire file using the requested encoding name.
    fn read_to_string(&self, path: &str, encoding: Option<&str>) -> Result<String, FunctionError>;

    /// Reads the next line for one function occurrence and path key.
    fn read_line(
        &self,
        path: &str,
        key: &str,
        start_sequence: Option<i64>,
        end_sequence: Option<i64>,
    ) -> Result<String, FunctionError>;

    /// Reads the next line for one exact function occurrence.
    ///
    /// JMeter creates one `StringFromFile` instance per source occurrence,
    /// even though that instance is shared by all threads.  Adapters that
    /// maintain their own cursor state can override this hook to include the
    /// occurrence identity in their cursor key.  The default preserves the
    /// original adapter contract for capability implementations that already
    /// own occurrence state themselves.
    fn read_line_for_occurrence(
        &self,
        path: &str,
        key: &str,
        _occurrence: u64,
        start_sequence: Option<i64>,
        end_sequence: Option<i64>,
    ) -> Result<String, FunctionError> {
        self.read_line(path, key, start_sequence, end_sequence)
    }

    /// Reads the next line for a structural function occurrence.
    ///
    /// New adapters should override this method when cursor state is keyed by
    /// the full plan/field namespace and nested path.  The default preserves
    /// compatibility with existing adapters that implement the scalar hook.
    fn read_line_for_function_occurrence(
        &self,
        path: &str,
        key: &str,
        occurrence: &FunctionOccurrence,
        start_sequence: Option<i64>,
        end_sequence: Option<i64>,
    ) -> Result<String, FunctionError> {
        self.read_line_for_occurrence(
            path,
            key,
            occurrence.legacy_id(),
            start_sequence,
            end_sequence,
        )
    }

    /// Reads a zero-based CSV field from a path and cursor selector.
    fn read_csv_field(
        &self,
        path: &str,
        selector: &str,
        delimiter: char,
    ) -> Result<String, FunctionError>;

    /// Writes a string, replacing or appending according to `append`.
    fn write_string(
        &self,
        path: &str,
        value: &str,
        append: bool,
        encoding: Option<&str>,
    ) -> Result<(), FunctionError>;
}

/// Explicit run-owned hooks for stateful native function inputs.
///
/// Counters, random streams, and file cursors are not ambient globals and are
/// not inferred from evaluator call order.  A runtime may install this hook
/// to give those functions an identity-bound state authority.  Each returned
/// value is journaled by an [`ExpressionSession`] by the caller that performs
/// the evaluation.  The default rollback operation is deliberately
/// unsupported: callers must not claim to have restored state that an
/// adapter cannot restore exactly.
pub trait NativeStateCapability: Sync + Send {
    /// Advances or reads the counter associated with one exact occurrence.
    fn next_counter(
        &self,
        occurrence: &FunctionOccurrence,
        per_user: bool,
        iteration: Option<IterationIdentity>,
        thread_num: Option<u32>,
    ) -> Result<i64, FunctionError>;

    /// Draws one random value from the occurrence-bound stream.
    fn next_random(&self, occurrence: &FunctionOccurrence) -> Result<u64, FunctionError>;

    /// Advances one file cursor and returns its new position.
    fn advance_file_cursor(
        &self,
        occurrence: &FunctionOccurrence,
        path: &str,
    ) -> Result<u64, FunctionError>;

    /// Attempts to roll back one state token.
    ///
    /// Adapters that do not have a proven transactional protocol must keep the
    /// default error.  An unsuccessful rollback is an uncertain outcome, not
    /// a successful no-op.
    fn rollback(&self, _token: &str) -> Result<(), FunctionError> {
        Err(FunctionError::unsupported(
            "native state rollback capability is unavailable",
        ))
    }
}

/// Supplies the previous sample/response body for response-extraction
/// functions.  The matcher remains an injected capability because JMeter's
/// regular-expression and XPath engines are versioned dependencies.
pub trait ResponseExtractor: Sync + Send {
    /// Applies JMeter's regex-function contract and returns the rendered
    /// result, optionally including captured groups for variable storage.
    fn regex_function(
        &self,
        arguments: &[String],
    ) -> Result<(String, Vec<(String, String)>), FunctionError>;

    /// Evaluates an XPath function call against its configured input.
    fn xpath_function(&self, arguments: &[String]) -> Result<String, FunctionError>;
}

/// Evaluates a script-backed function through an explicitly versioned
/// external engine adapter.
pub trait ScriptCapability: Sync + Send {
    /// Evaluates a named scripting function such as `__groovy`.
    fn evaluate(&self, function_name: &str, arguments: &[String]) -> Result<String, FunctionError>;
}

/// Explicit optional capabilities available during one expansion operation.
///
/// The structure is copyable and borrows all capabilities from the caller;
/// it performs no I/O and owns no global state.  Use
/// [`Evaluator::with_capabilities`] (or [`Evaluator::with_function_capabilities`])
/// to preserve the existing read-only constructor while opting into effects.
#[derive(Clone, Copy, Default)]
pub struct EvaluationCapabilities<'a> {
    variable_setter: Option<&'a dyn VariableSetter>,
    property_setter: Option<&'a dyn PropertySetter>,
    test_plan_name: Option<&'a dyn TestPlanNameResolver>,
    random: Option<&'a dyn RandomSource>,
    native_state: Option<&'a dyn NativeStateCapability>,
    clock: Option<&'a dyn ClockSource>,
    execution: Option<&'a dyn ExecutionContext>,
    host: Option<&'a dyn HostResolver>,
    log: Option<&'a dyn LogSink>,
    files: Option<&'a dyn FileCapability>,
    response: Option<&'a dyn ResponseExtractor>,
    scripts: Option<&'a dyn ScriptCapability>,
}

impl<'a> EvaluationCapabilities<'a> {
    /// Creates an empty, read-only capability set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            variable_setter: None,
            property_setter: None,
            test_plan_name: None,
            random: None,
            native_state: None,
            clock: None,
            execution: None,
            host: None,
            log: None,
            files: None,
            response: None,
            scripts: None,
        }
    }

    /// Adds an explicit variable setter/store.
    #[must_use]
    pub const fn with_variable_setter(mut self, setter: &'a dyn VariableSetter) -> Self {
        self.variable_setter = Some(setter);
        self
    }

    /// Adds an explicit property setter/store.
    #[must_use]
    pub const fn with_property_setter(mut self, setter: &'a dyn PropertySetter) -> Self {
        self.property_setter = Some(setter);
        self
    }

    /// Adds an explicit test-plan-name provider.
    #[must_use]
    pub const fn with_test_plan_name(mut self, provider: &'a dyn TestPlanNameResolver) -> Self {
        self.test_plan_name = Some(provider);
        self
    }

    /// Adds a random source for random/UUID functions.
    #[must_use]
    pub const fn with_random_source(mut self, source: &'a dyn RandomSource) -> Self {
        self.random = Some(source);
        self
    }

    /// Adds occurrence-bound native state hooks for counters, random streams,
    /// and file cursors.
    #[must_use]
    pub const fn with_native_state(mut self, state: &'a dyn NativeStateCapability) -> Self {
        self.native_state = Some(state);
        self
    }

    /// Adds a clock for time/date functions.
    #[must_use]
    pub const fn with_clock(mut self, clock: &'a dyn ClockSource) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Adds virtual-user identity for information/stateful functions.
    #[must_use]
    pub const fn with_execution_context(mut self, execution: &'a dyn ExecutionContext) -> Self {
        self.execution = Some(execution);
        self
    }

    /// Adds an explicit host identity provider.
    #[must_use]
    pub const fn with_host_resolver(mut self, host: &'a dyn HostResolver) -> Self {
        self.host = Some(host);
        self
    }

    /// Adds an explicit log sink.
    #[must_use]
    pub const fn with_log_sink(mut self, sink: &'a dyn LogSink) -> Self {
        self.log = Some(sink);
        self
    }

    /// Adds a file-backed function capability.
    #[must_use]
    pub const fn with_file_capability(mut self, files: &'a dyn FileCapability) -> Self {
        self.files = Some(files);
        self
    }

    /// Adds a response extraction capability.
    #[must_use]
    pub const fn with_response_extractor(mut self, response: &'a dyn ResponseExtractor) -> Self {
        self.response = Some(response);
        self
    }

    /// Adds a script-engine capability.
    #[must_use]
    pub const fn with_script_capability(mut self, scripts: &'a dyn ScriptCapability) -> Self {
        self.scripts = Some(scripts);
        self
    }

    /// Returns whether variable mutation was supplied for this evaluation.
    #[must_use]
    pub const fn has_variable_setter(self) -> bool {
        self.variable_setter.is_some()
    }

    /// Returns whether property mutation was supplied for this evaluation.
    #[must_use]
    pub const fn has_property_setter(self) -> bool {
        self.property_setter.is_some()
    }

    /// Returns whether a test-plan-name provider was supplied for this
    /// evaluation.
    #[must_use]
    pub const fn has_test_plan_name(self) -> bool {
        self.test_plan_name.is_some()
    }

    /// Returns whether deterministic/random input was supplied for this
    /// evaluation.
    #[must_use]
    pub const fn has_random_source(self) -> bool {
        self.random.is_some()
    }

    /// Returns whether occurrence-bound native state was supplied.
    #[must_use]
    pub const fn has_native_state(self) -> bool {
        self.native_state.is_some()
    }

    /// Returns whether a clock was supplied for this evaluation.
    #[must_use]
    pub const fn has_clock(self) -> bool {
        self.clock.is_some()
    }

    /// Returns whether virtual-user execution identity was supplied for this
    /// evaluation.
    #[must_use]
    pub const fn has_execution_context(self) -> bool {
        self.execution.is_some()
    }

    /// Returns the execution identity supplied for this evaluation.
    #[must_use]
    pub fn execution_context(self) -> Option<&'a dyn ExecutionContext> {
        self.execution
    }

    /// Returns occurrence-bound native state hooks, if supplied.
    #[must_use]
    pub fn native_state(self) -> Option<&'a dyn NativeStateCapability> {
        self.native_state
    }

    /// Returns whether a host identity provider was supplied for this
    /// evaluation.
    #[must_use]
    pub const fn has_host_resolver(self) -> bool {
        self.host.is_some()
    }

    /// Returns whether a log sink was supplied for this evaluation.
    #[must_use]
    pub const fn has_log_sink(self) -> bool {
        self.log.is_some()
    }

    /// Returns whether file access was supplied for this evaluation.
    #[must_use]
    pub const fn has_file_capability(self) -> bool {
        self.files.is_some()
    }

    /// Returns whether response extraction was supplied for this evaluation.
    #[must_use]
    pub const fn has_response_extractor(self) -> bool {
        self.response.is_some()
    }

    /// Returns whether a script engine was supplied for this evaluation.
    #[must_use]
    pub const fn has_script_capability(self) -> bool {
        self.scripts.is_some()
    }
}

/// Stable structural identity for one function occurrence.
///
/// The namespace identifies the owning plan/field definition.  The path is
/// a collision-free sequence of source and argument segments: a top-level
/// function has one source-offset segment, a function in an argument adds the
/// argument index and its local offset, and an indirection expansion adds a
/// reserved marker before its local offset.  Unlike the legacy `u64` hash,
/// this value is safe to use as a state-store key without collision-based
/// resets or cross-occurrence sharing.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FunctionOccurrence {
    namespace: u64,
    path: Box<[u64]>,
    function_name: Box<str>,
}

impl FunctionOccurrence {
    /// Creates an occurrence from its field namespace, structural path, and
    /// exact function name.
    ///
    /// The evaluator uses source-byte offsets and argument indexes in `path`;
    /// callers compiling another syntax representation may use any stable
    /// bounded structural segments.  No hash is used for identity.
    #[must_use]
    pub fn new(namespace: u64, path: Vec<u64>, function_name: &str) -> Self {
        Self {
            namespace,
            path: path.into_boxed_slice(),
            function_name: function_name.to_owned().into_boxed_str(),
        }
    }

    /// Returns the plan/field namespace supplied to the evaluator.
    #[must_use]
    pub const fn namespace(&self) -> u64 {
        self.namespace
    }

    /// Returns the collision-free structural path for this occurrence.
    #[must_use]
    pub fn path(&self) -> &[u64] {
        &self.path
    }

    /// Alias for [`Self::path`] emphasizing that segments are structural
    /// source identity rather than a hash.
    #[must_use]
    pub fn structural_path(&self) -> &[u64] {
        self.path()
    }

    /// Returns the exact, case-sensitive upstream function name.
    #[must_use]
    pub fn function_name(&self) -> &str {
        &self.function_name
    }

    /// Returns a stable legacy scalar for capability adapters that still use
    /// the original occurrence hook.  Stateful native maps use the full
    /// structural value instead of this lossy compatibility projection.
    #[must_use]
    fn legacy_id(&self) -> u64 {
        occurrence_id(self.namespace, &self.path, &self.function_name)
    }

    /// Creates a top-level occurrence at one source-byte offset.
    #[must_use]
    pub fn at_source_offset(namespace: u64, offset: usize, function_name: &str) -> Self {
        let segment = u64::try_from(offset).unwrap_or(u64::MAX);
        Self::new(namespace, vec![segment], function_name)
    }
}

/// Stable identity of one compiled function-bearing field.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExpressionFieldId(u64);

impl ExpressionFieldId {
    /// Creates an identity from a plan/compiler-assigned value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the plan/compiler-assigned value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

impl From<u64> for ExpressionFieldId {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

/// Cache policy for one compiled expression field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpressionCachePolicy {
    /// Evaluate on every getter/read.
    Disabled,
    /// Cache one value while the field is in running-version mode.
    Once,
    /// Cache one value for each complete [`IterationIdentity`].
    PerIteration,
}

impl ExpressionCachePolicy {
    /// A spelling that makes the no-cache policy clear at call sites.
    pub const NO_CACHE: Self = Self::Disabled;
    /// A spelling matching the JMeter property vocabulary.
    pub const CACHE_PER_ITERATION: Self = Self::PerIteration;
    /// A spelling for the one-value running-version cache.
    pub const CACHE_ONCE: Self = Self::Once;
}

/// Lifecycle state of a compiled expression field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpressionFieldState {
    /// The raw source has not entered running-version mode.
    RawBeforeRunningVersion,
    /// Running-version state exists, but sampling has not started.
    RunningBeforeSampling,
    /// Sampling is active for the complete supplied iteration identity.
    RunningDuringSampling {
        /// Identity used for per-iteration cache keys.
        iteration: IterationIdentity,
    },
    /// The owning component/run has finished and the field is no longer
    /// readable.
    Finished,
}

/// Compatibility alias for callers that name the lifecycle vocabulary
/// `FieldLifecycleState`.
pub type FieldLifecycleState = ExpressionFieldState;

/// Bounds for compiling and caching one expression field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpressionFieldLimits {
    /// Maximum source bytes retained by a field.
    pub max_source_bytes: usize,
    /// Maximum structural occurrences retained by a field.
    pub max_occurrences: usize,
    /// Maximum cache entries retained for per-iteration caching.
    pub max_cached_iterations: usize,
}

impl ExpressionFieldLimits {
    /// Creates explicit field bounds.
    #[must_use]
    pub const fn new(
        max_source_bytes: usize,
        max_occurrences: usize,
        max_cached_iterations: usize,
    ) -> Self {
        Self {
            max_source_bytes,
            max_occurrences,
            max_cached_iterations,
        }
    }
}

impl Default for ExpressionFieldLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: 64 * 1024,
            max_occurrences: 4_096,
            max_cached_iterations: 1_024,
        }
    }
}

/// A checked failure while compiling or advancing a field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExpressionFieldError {
    /// The field source exceeded its configured bound.
    SourceLimit {
        /// Configured source-byte limit.
        limit: usize,
        /// Source/value bytes observed.
        actual: usize,
    },
    /// The field contained malformed expression syntax.
    InvalidSource(EvaluationError),
    /// A lifecycle transition was not valid from the current state.
    InvalidTransition {
        /// State before the attempted transition.
        from: ExpressionFieldState,
        /// Requested state.
        to: ExpressionFieldState,
    },
    /// A per-iteration read did not provide the active complete identity.
    IterationRequired,
    /// A supplied identity did not match the active sampling identity.
    IterationMismatch {
        /// Active identity.
        expected: IterationIdentity,
        /// Supplied identity.
        actual: IterationIdentity,
    },
    /// The field cache reached its explicit bound.
    CacheLimit {
        /// Configured cache limit.
        limit: usize,
    },
    /// The structural occurrence bound was reached.
    OccurrenceLimit {
        /// Configured occurrence limit.
        limit: usize,
    },
    /// The field's internal state lock was poisoned.
    Poisoned {
        /// Logical lock identity.
        lock: String,
    },
    /// The field was read after it finished.
    Finished,
    /// The field's evaluator returned a bounded session failure.
    Session(SessionError),
}

impl fmt::Display for ExpressionFieldError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceLimit { limit, actual } => {
                write!(
                    formatter,
                    "expression field source is {actual} bytes (limit {limit})"
                )
            }
            Self::InvalidSource(error) => {
                write!(formatter, "invalid expression field source: {error}")
            }
            Self::InvalidTransition { from, to } => {
                write!(
                    formatter,
                    "invalid expression field transition {from:?} -> {to:?}"
                )
            }
            Self::IterationRequired => {
                formatter.write_str("expression field iteration identity is required")
            }
            Self::IterationMismatch { expected, actual } => {
                write!(
                    formatter,
                    "expression field iteration mismatch: expected {expected:?}, got {actual:?}"
                )
            }
            Self::CacheLimit { limit } => {
                write!(formatter, "expression field cache limit {limit} reached")
            }
            Self::OccurrenceLimit { limit } => {
                write!(
                    formatter,
                    "expression field occurrence limit {limit} reached"
                )
            }
            Self::Poisoned { lock } => {
                write!(formatter, "expression field state lock is poisoned: {lock}")
            }
            Self::Finished => formatter.write_str("expression field is finished"),
            Self::Session(error) => write!(formatter, "expression session failed: {error}"),
        }
    }
}

impl Error for ExpressionFieldError {}

/// A source-preserving, occurrence-bound compiled expression field.
pub struct ExpressionField {
    id: ExpressionFieldId,
    namespace: u64,
    source_property: Box<str>,
    source: String,
    occurrences: Box<[FunctionOccurrence]>,
    cache_policy: ExpressionCachePolicy,
    limits: ExpressionFieldLimits,
    state: Mutex<ExpressionFieldStateData>,
}

struct ExpressionFieldStateData {
    state: ExpressionFieldState,
    once: Option<String>,
    per_iteration: BTreeMap<IterationIdentity, String>,
}

impl fmt::Debug for ExpressionField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExpressionField")
            .field("id", &self.id)
            .field("namespace", &self.namespace)
            .field("source_property", &self.source_property)
            .field("source_bytes", &self.source.len())
            .field("occurrences", &self.occurrences.len())
            .field("cache_policy", &self.cache_policy)
            .field("state", &self.state())
            .finish()
    }
}

impl ExpressionField {
    /// Compiles a field using its field ID as the occurrence namespace.
    pub fn new(
        id: ExpressionFieldId,
        source_property: impl Into<String>,
        source: impl Into<String>,
        cache_policy: ExpressionCachePolicy,
    ) -> Result<Self, ExpressionFieldError> {
        Self::compile_with_limits(
            id,
            id.value(),
            source_property,
            source,
            cache_policy,
            ExpressionFieldLimits::default(),
        )
    }

    /// Compiles a field with an explicit namespace and default bounds.
    pub fn compile(
        id: ExpressionFieldId,
        namespace: u64,
        source_property: impl Into<String>,
        source: impl Into<String>,
        cache_policy: ExpressionCachePolicy,
    ) -> Result<Self, ExpressionFieldError> {
        Self::compile_with_limits(
            id,
            namespace,
            source_property,
            source,
            cache_policy,
            ExpressionFieldLimits::default(),
        )
    }

    /// Compiles a field with an explicit function-occurrence namespace.
    pub fn compile_with_limits(
        id: ExpressionFieldId,
        namespace: u64,
        source_property: impl Into<String>,
        source: impl Into<String>,
        cache_policy: ExpressionCachePolicy,
        limits: ExpressionFieldLimits,
    ) -> Result<Self, ExpressionFieldError> {
        let source = source.into();
        if source.len() > limits.max_source_bytes {
            return Err(ExpressionFieldError::SourceLimit {
                limit: limits.max_source_bytes,
                actual: source.len(),
            });
        }
        let occurrences = collect_field_occurrences(&source, namespace, &limits)?;
        Ok(Self {
            id,
            namespace,
            source_property: source_property.into().into_boxed_str(),
            source,
            occurrences: occurrences.into_boxed_slice(),
            cache_policy,
            limits,
            state: Mutex::new(ExpressionFieldStateData {
                state: ExpressionFieldState::RawBeforeRunningVersion,
                once: None,
                per_iteration: BTreeMap::new(),
            }),
        })
    }

    /// Returns the field's stable compiler identity.
    #[must_use]
    pub const fn id(&self) -> ExpressionFieldId {
        self.id
    }

    /// Alias for [`Self::id`].
    #[must_use]
    pub const fn identity(&self) -> ExpressionFieldId {
        self.id()
    }

    /// Returns the namespace used by structural function occurrences.
    #[must_use]
    pub const fn namespace(&self) -> u64 {
        self.namespace
    }

    /// Returns the exact source property identity.
    #[must_use]
    pub fn source_property(&self) -> &str {
        &self.source_property
    }

    /// Returns the exact unmodified expression source.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Returns all structural function occurrences in source order.
    #[must_use]
    pub fn occurrences(&self) -> &[FunctionOccurrence] {
        &self.occurrences
    }

    /// Returns the field cache policy.
    #[must_use]
    pub const fn cache_policy(&self) -> ExpressionCachePolicy {
        self.cache_policy
    }

    /// Returns the field resource bounds.
    #[must_use]
    pub const fn limits(&self) -> ExpressionFieldLimits {
        self.limits
    }

    /// Returns the current lifecycle state, failing closed if its lock is
    /// poisoned.
    pub fn state(&self) -> Result<ExpressionFieldState, ExpressionFieldError> {
        self.state
            .lock()
            .map(|state| state.state)
            .map_err(|_| ExpressionFieldError::Poisoned {
                lock: "expression-field-state".to_owned(),
            })
    }

    /// Alias for [`Self::state`].
    pub fn lifecycle(&self) -> Result<ExpressionFieldState, ExpressionFieldError> {
        self.state()
    }

    /// Enters running-version mode before sampling starts.
    pub fn start_running_version(&self) -> Result<(), ExpressionFieldError> {
        self.transition(ExpressionFieldState::RunningBeforeSampling)
    }

    /// Alias for [`Self::start_running_version`].
    pub fn begin_running(&self) -> Result<(), ExpressionFieldError> {
        self.start_running_version()
    }

    /// Enters sampling mode for one complete iteration identity.
    pub fn start_sampling(&self, iteration: IterationIdentity) -> Result<(), ExpressionFieldError> {
        let mut state = self.lock_state()?;
        match state.state {
            ExpressionFieldState::RunningBeforeSampling
            | ExpressionFieldState::RunningDuringSampling { .. } => {
                state.state = ExpressionFieldState::RunningDuringSampling { iteration };
                state.per_iteration.clear();
                Ok(())
            }
            current => Err(ExpressionFieldError::InvalidTransition {
                from: current,
                to: ExpressionFieldState::RunningDuringSampling { iteration },
            }),
        }
    }

    /// Alias for [`Self::start_sampling`].
    pub fn begin_sampling(&self, iteration: IterationIdentity) -> Result<(), ExpressionFieldError> {
        self.start_sampling(iteration)
    }

    /// Marks the field finished.  A finished field rejects further reads.
    pub fn finish(&self) -> Result<(), ExpressionFieldError> {
        let mut state = self.lock_state()?;
        match state.state {
            ExpressionFieldState::RawBeforeRunningVersion => {
                return Err(ExpressionFieldError::InvalidTransition {
                    from: state.state,
                    to: ExpressionFieldState::Finished,
                });
            }
            ExpressionFieldState::Finished => return Ok(()),
            _ => {}
        }
        state.state = ExpressionFieldState::Finished;
        state.once = None;
        state.per_iteration.clear();
        Ok(())
    }

    /// Clears cached values while retaining lifecycle state.
    pub fn clear_cache(&self) -> Result<(), ExpressionFieldError> {
        let mut state = self.lock_state()?;
        state.once = None;
        state.per_iteration.clear();
        Ok(())
    }

    /// Clones field metadata and the current lifecycle/cache state without
    /// recovering a poisoned state lock.
    pub fn try_clone(&self) -> Result<Self, ExpressionFieldError> {
        let state = self.lock_state()?;
        Ok(Self {
            id: self.id,
            namespace: self.namespace,
            source_property: self.source_property.clone(),
            source: self.source.clone(),
            occurrences: self.occurrences.clone(),
            cache_policy: self.cache_policy,
            limits: self.limits,
            state: Mutex::new(ExpressionFieldStateData {
                state: state.state,
                once: state.once.clone(),
                per_iteration: state.per_iteration.clone(),
            }),
        })
    }

    /// Reads the field and evaluates only when its lifecycle/cache policy
    /// requires it.  The callback receives the exact source text and is never
    /// called for a raw or cached read.
    pub fn read_with<F>(
        &self,
        iteration: Option<IterationIdentity>,
        evaluate: F,
    ) -> Result<String, ExpressionFieldError>
    where
        F: FnOnce(&str) -> Result<String, ExpressionFieldError>,
    {
        let mut state = self.lock_state()?;
        match state.state {
            ExpressionFieldState::RawBeforeRunningVersion => Ok(self.source.clone()),
            ExpressionFieldState::Finished => Err(ExpressionFieldError::Finished),
            ExpressionFieldState::RunningBeforeSampling => {
                if self.cache_policy == ExpressionCachePolicy::Once
                    && let Some(value) = state.once.clone()
                {
                    return Ok(value);
                }
                drop(state);
                let value = evaluate(&self.source)?;
                if value.len() > self.limits.max_source_bytes {
                    return Err(ExpressionFieldError::SourceLimit {
                        limit: self.limits.max_source_bytes,
                        actual: value.len(),
                    });
                }
                state = self.lock_state()?;
                if self.cache_policy == ExpressionCachePolicy::Once {
                    state.once = Some(value.clone());
                }
                Ok(value)
            }
            ExpressionFieldState::RunningDuringSampling { iteration: active } => {
                if let Some(actual) = iteration {
                    if actual != active {
                        return Err(ExpressionFieldError::IterationMismatch {
                            expected: active,
                            actual,
                        });
                    }
                } else if self.cache_policy == ExpressionCachePolicy::PerIteration {
                    return Err(ExpressionFieldError::IterationRequired);
                }
                if self.cache_policy == ExpressionCachePolicy::Once
                    && let Some(value) = state.once.clone()
                {
                    return Ok(value);
                }
                if self.cache_policy == ExpressionCachePolicy::PerIteration {
                    if let Some(value) = state.per_iteration.get(&active).cloned() {
                        return Ok(value);
                    }
                    drop(state);
                    let value = evaluate(&self.source)?;
                    if value.len() > self.limits.max_source_bytes {
                        return Err(ExpressionFieldError::SourceLimit {
                            limit: self.limits.max_source_bytes,
                            actual: value.len(),
                        });
                    }
                    state = self.lock_state()?;
                    if state.per_iteration.len() >= self.limits.max_cached_iterations {
                        return Err(ExpressionFieldError::CacheLimit {
                            limit: self.limits.max_cached_iterations,
                        });
                    }
                    state.per_iteration.insert(active, value.clone());
                    Ok(value)
                } else {
                    drop(state);
                    let value = evaluate(&self.source)?;
                    if value.len() > self.limits.max_source_bytes {
                        return Err(ExpressionFieldError::SourceLimit {
                            limit: self.limits.max_source_bytes,
                            actual: value.len(),
                        });
                    }
                    state = self.lock_state()?;
                    if self.cache_policy == ExpressionCachePolicy::Once {
                        state.once = Some(value.clone());
                    }
                    Ok(value)
                }
            }
        }
    }

    fn transition(&self, target: ExpressionFieldState) -> Result<(), ExpressionFieldError> {
        let mut state = self.lock_state()?;
        let valid = matches!(
            (state.state, target),
            (
                ExpressionFieldState::RawBeforeRunningVersion,
                ExpressionFieldState::RunningBeforeSampling
            )
        );
        if !valid {
            return Err(ExpressionFieldError::InvalidTransition {
                from: state.state,
                to: target,
            });
        }
        state.state = target;
        state.once = None;
        state.per_iteration.clear();
        Ok(())
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, ExpressionFieldStateData>, ExpressionFieldError> {
        self.state
            .lock()
            .map_err(|_| ExpressionFieldError::Poisoned {
                lock: "expression-field-state".to_owned(),
            })
    }
}

/// Effect classification for expression capabilities.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EffectClass {
    /// No observable state is touched.
    Pure,
    /// The run can journal and publish the native state exactly.
    JournaledNative,
    /// An external adapter exposes prepare/commit/abort semantics.
    TransactionalExternal,
    /// The operation may escape the session and cannot be rolled back by the
    /// pure expression crate.
    IrreversibleExternal,
}

/// Compatibility alias for effect-class callers.
pub type ExpressionEffectClass = EffectClass;

impl EffectClass {
    /// Returns whether this class is natively rollback-capable.
    #[must_use]
    pub const fn rollback_supported(self) -> bool {
        matches!(
            self,
            Self::Pure | Self::JournaledNative | Self::TransactionalExternal
        )
    }
}

/// One native state transition recorded by an expression session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeStateEffect {
    /// A counter value advanced for one occurrence.
    Counter {
        /// Exact function occurrence.
        occurrence: FunctionOccurrence,
        /// Value before the transition.
        previous: i64,
        /// Value after the transition.
        value: i64,
    },
    /// A random stream returned one value.
    Random {
        /// Exact function occurrence.
        occurrence: FunctionOccurrence,
        /// Drawn value.
        value: u64,
    },
    /// A file cursor advanced for one occurrence/path.
    FileCursor {
        /// Exact function occurrence.
        occurrence: FunctionOccurrence,
        /// Capability-defined path/cursor key.
        key: String,
        /// Position before the transition.
        previous: u64,
        /// Position after the transition.
        value: u64,
    },
}

/// One observable expression effect in source order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExpressionEffect {
    /// A variable overlay write.
    Variable {
        /// Exact variable name.
        name: String,
        /// Value visible before this write.
        previous: Option<String>,
        /// New value.
        value: String,
    },
    /// A run-scoped property overlay write.
    Property {
        /// Exact property name.
        name: String,
        /// Value visible before this write.
        previous: Option<String>,
        /// New value.
        value: String,
    },
    /// A journaled native state transition.
    Native(NativeStateEffect),
    /// A transactional or irreversible external operation.
    External {
        /// Effect class declared by the adapter.
        class: EffectClass,
        /// Bounded capability operation identity.
        operation: String,
    },
}

/// A journal entry containing one effect and its class.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpressionEffectRecord {
    class: EffectClass,
    effect: ExpressionEffect,
}

impl ExpressionEffectRecord {
    /// Creates a journal entry.  Session APIs should normally be preferred so
    /// bounds and class/effect consistency are checked together.
    #[must_use]
    pub fn new(class: EffectClass, effect: ExpressionEffect) -> Self {
        Self { class, effect }
    }

    /// Returns the declared effect class.
    #[must_use]
    pub const fn class(&self) -> EffectClass {
        self.class
    }

    /// Returns the effect payload.
    #[must_use]
    pub fn effect(&self) -> &ExpressionEffect {
        &self.effect
    }
}

/// Alias used by callers that model the journal as a list of entries.
pub type EffectJournalEntry = ExpressionEffectRecord;

/// A bounded, source-ordered effect journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectJournal {
    entries: Vec<ExpressionEffectRecord>,
    max_entries: usize,
    max_bytes: usize,
    bytes: usize,
}

impl EffectJournal {
    /// Creates an empty journal with explicit entry and byte bounds.
    #[must_use]
    pub fn new(max_entries: usize, max_bytes: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_entries,
            max_bytes,
            bytes: 0,
        }
    }

    /// Returns the configured journal bounds.
    #[must_use]
    pub const fn limits(&self) -> (usize, usize) {
        (self.max_entries, self.max_bytes)
    }

    /// Returns the number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether no effects have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the retained byte count.
    #[must_use]
    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    /// Returns entries in exact evaluation order.
    #[must_use]
    pub fn entries(&self) -> &[ExpressionEffectRecord] {
        &self.entries
    }

    /// Appends an entry if both journal bounds permit it.
    pub fn push(&mut self, entry: ExpressionEffectRecord) -> Result<(), SessionError> {
        if self.entries.len() >= self.max_entries {
            return Err(SessionError::JournalLimit {
                limit: self.max_entries,
            });
        }
        let entry_bytes = effect_bytes(&entry);
        let bytes = self
            .bytes
            .checked_add(entry_bytes)
            .ok_or(SessionError::JournalBytesLimit {
                limit: self.max_bytes,
            })?;
        if bytes > self.max_bytes {
            return Err(SessionError::JournalBytesLimit {
                limit: self.max_bytes,
            });
        }
        self.entries.push(entry);
        self.bytes = bytes;
        Ok(())
    }

    /// Returns an owned, ordered snapshot of the entries.
    #[must_use]
    pub fn snapshot(&self) -> Box<[ExpressionEffectRecord]> {
        self.entries.clone().into_boxed_slice()
    }

    /// Drops all entries after an abort-before-effects outcome.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.bytes = 0;
    }
}

impl Default for EffectJournal {
    fn default() -> Self {
        let limits = ExpressionSessionLimits::default();
        Self::new(limits.max_journal_entries, limits.max_journal_bytes)
    }
}

/// Bounds for one expression session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpressionSessionLimits {
    /// Maximum source/input bytes accepted by the session.
    pub max_input_bytes: usize,
    /// Maximum value/diagnostic bytes retained by the session.
    pub max_output_bytes: usize,
    /// Maximum nested capability call depth.
    pub max_call_depth: usize,
    /// Maximum function/capability calls.
    pub max_calls: usize,
    /// Maximum overlay/native mutations.
    pub max_mutations: usize,
    /// Maximum ordered journal entries.
    pub max_journal_entries: usize,
    /// Maximum aggregate journal bytes.
    pub max_journal_bytes: usize,
    /// Maximum diagnostic bytes.
    pub max_diagnostic_bytes: usize,
}

impl ExpressionSessionLimits {
    /// Creates explicit session limits.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "the session limit tuple is a stable, explicit resource policy"
    )]
    pub const fn new(
        max_input_bytes: usize,
        max_output_bytes: usize,
        max_call_depth: usize,
        max_calls: usize,
        max_mutations: usize,
        max_journal_entries: usize,
        max_journal_bytes: usize,
        max_diagnostic_bytes: usize,
    ) -> Self {
        Self {
            max_input_bytes,
            max_output_bytes,
            max_call_depth,
            max_calls,
            max_mutations,
            max_journal_entries,
            max_journal_bytes,
            max_diagnostic_bytes,
        }
    }
}

impl Default for ExpressionSessionLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 64 * 1024,
            max_output_bytes: 256 * 1024,
            max_call_depth: 32,
            max_calls: 1_024,
            max_mutations: 1_024,
            max_journal_entries: 4_096,
            max_journal_bytes: 4 * 1024 * 1024,
            max_diagnostic_bytes: 16 * 1024,
        }
    }
}

/// Identity binding an expression session to one run/user/component phase.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExpressionSessionIdentity {
    run_id: u64,
    user_id: u64,
    lifecycle_id: u64,
    component_id: u64,
    field_id: ExpressionFieldId,
    phase: Box<str>,
    iteration: Option<IterationIdentity>,
}

impl ExpressionSessionIdentity {
    /// Creates an identity without an active iteration.
    #[must_use]
    pub fn new(
        run_id: u64,
        user_id: u64,
        lifecycle_id: u64,
        component_id: u64,
        field_id: ExpressionFieldId,
        phase: impl Into<String>,
    ) -> Self {
        Self {
            run_id,
            user_id,
            lifecycle_id,
            component_id,
            field_id,
            phase: phase.into().into_boxed_str(),
            iteration: None,
        }
    }

    /// Returns a convenient user/lifecycle identity for a field phase.
    #[must_use]
    pub fn for_user(
        run_id: u64,
        user_id: u64,
        lifecycle_id: u64,
        field_id: ExpressionFieldId,
        phase: impl Into<String>,
    ) -> Self {
        Self::new(run_id, user_id, lifecycle_id, 0, field_id, phase)
    }

    /// Sets the complete active iteration identity.
    #[must_use]
    pub fn with_iteration(mut self, iteration: IterationIdentity) -> Self {
        self.iteration = Some(iteration);
        self
    }

    /// Returns the run identity.
    #[must_use]
    pub const fn run_id(&self) -> u64 {
        self.run_id
    }

    /// Returns the virtual-user identity.
    #[must_use]
    pub const fn user_id(&self) -> u64 {
        self.user_id
    }

    /// Returns the lifecycle identity.
    #[must_use]
    pub const fn lifecycle_id(&self) -> u64 {
        self.lifecycle_id
    }

    /// Returns the component identity.
    #[must_use]
    pub const fn component_id(&self) -> u64 {
        self.component_id
    }

    /// Returns the field identity.
    #[must_use]
    pub const fn field_id(&self) -> ExpressionFieldId {
        self.field_id
    }

    /// Returns the expression phase label.
    #[must_use]
    pub fn phase(&self) -> &str {
        &self.phase
    }

    /// Returns the optional complete iteration identity.
    #[must_use]
    pub const fn iteration(&self) -> Option<IterationIdentity> {
        self.iteration
    }
}

/// Typed reasons why an expression authority or session is poisoned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExpressionPoisonReason {
    /// An external operation may have happened but its result is ambiguous.
    ExternalEffectUncertain,
    /// A mutex protecting expression state was poisoned.
    LockPoisoned {
        /// Logical lock identity.
        lock: String,
    },
    /// A checked generation counter could not advance.
    GenerationExhausted,
    /// A capability did not provide a required rollback protocol.
    UnsupportedRollback {
        /// Effect class that could not be rolled back.
        class: EffectClass,
    },
    /// An internal invariant was lost.
    InvariantViolation(String),
}

/// Compatibility alias for typed authority poison state.
pub type PoisonReason = ExpressionPoisonReason;

/// A bounded, typed authority poison marker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpressionPoison {
    reason: ExpressionPoisonReason,
    detail: String,
}

impl ExpressionPoison {
    /// Creates an external-uncertainty poison marker.
    #[must_use]
    pub fn external_effect(detail: impl Into<String>) -> Self {
        Self {
            reason: ExpressionPoisonReason::ExternalEffectUncertain,
            detail: bounded_diagnostic(detail.into(), 4 * 1024),
        }
    }

    /// Creates a lock-poison marker.
    #[must_use]
    pub fn lock_poisoned(lock: impl Into<String>) -> Self {
        let lock = bounded_diagnostic(lock.into(), 256);
        Self {
            reason: ExpressionPoisonReason::LockPoisoned { lock: lock.clone() },
            detail: lock,
        }
    }

    /// Creates a generation-exhaustion marker.
    #[must_use]
    pub fn generation_exhausted() -> Self {
        Self {
            reason: ExpressionPoisonReason::GenerationExhausted,
            detail: "expression generation exhausted".to_owned(),
        }
    }

    /// Returns the poison reason.
    #[must_use]
    pub fn reason(&self) -> &ExpressionPoisonReason {
        &self.reason
    }

    /// Returns bounded diagnostic detail.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

/// A checked failure from an expression session or authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionError {
    /// Input exceeded the session's configured bound.
    InputLimit {
        /// Configured input limit.
        limit: usize,
        /// Observed input bytes.
        actual: usize,
    },
    /// Output/value exceeded the session's configured bound.
    OutputLimit {
        /// Configured output limit.
        limit: usize,
        /// Observed output bytes.
        actual: usize,
    },
    /// Nested call depth exceeded its bound.
    CallDepthLimit {
        /// Configured call-depth limit.
        limit: usize,
    },
    /// Call count exceeded its bound.
    CallLimit {
        /// Configured call-count limit.
        limit: usize,
    },
    /// Mutation count exceeded its bound.
    MutationLimit {
        /// Configured mutation limit.
        limit: usize,
    },
    /// Journal entry count exceeded its bound.
    JournalLimit {
        /// Configured journal-entry limit.
        limit: usize,
    },
    /// Journal bytes exceeded its bound.
    JournalBytesLimit {
        /// Configured journal-byte limit.
        limit: usize,
    },
    /// Diagnostic bytes exceeded its bound.
    DiagnosticLimit {
        /// Configured diagnostic limit.
        limit: usize,
    },
    /// A session used an old generation.
    StaleGeneration {
        /// Generation captured by this session.
        expected: u64,
        /// Generation supplied at publication.
        actual: u64,
    },
    /// A session was already closed.
    Closed,
    /// The authority/session is poisoned.
    Poisoned(ExpressionPoison),
    /// A lock was poisoned; its inner value was not recovered.
    LockPoisoned {
        /// Logical lock identity.
        lock: String,
    },
    /// A requested effect classification is inconsistent or unsupported.
    UnsupportedEffect {
        /// Rejected class.
        class: EffectClass,
    },
    /// An outcome cannot be produced in the current session state.
    InvalidOutcome(String),
}

/// Compatibility alias for session failures.
pub type ExpressionSessionError = SessionError;

/// Explicit generation token alias used by invocation-bound callers.
pub type ExpressionGeneration = u64;

/// Alias for the generation captured by a session.
pub type InvocationGeneration = u64;

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputLimit { limit, actual } => {
                write!(formatter, "session input {actual} exceeds {limit}")
            }
            Self::OutputLimit { limit, actual } => {
                write!(formatter, "session output {actual} exceeds {limit}")
            }
            Self::CallDepthLimit { limit } => {
                write!(formatter, "session call depth exceeds {limit}")
            }
            Self::CallLimit { limit } => write!(formatter, "session call count exceeds {limit}"),
            Self::MutationLimit { limit } => {
                write!(formatter, "session mutation count exceeds {limit}")
            }
            Self::JournalLimit { limit } => {
                write!(formatter, "session journal entry limit {limit} reached")
            }
            Self::JournalBytesLimit { limit } => {
                write!(formatter, "session journal byte limit {limit} reached")
            }
            Self::DiagnosticLimit { limit } => {
                write!(formatter, "session diagnostic limit {limit} reached")
            }
            Self::StaleGeneration { expected, actual } => write!(
                formatter,
                "stale expression generation: expected {expected}, got {actual}"
            ),
            Self::Closed => formatter.write_str("expression session is closed"),
            Self::Poisoned(poison) => write!(
                formatter,
                "expression authority is poisoned: {}",
                poison.detail()
            ),
            Self::LockPoisoned { lock } => write!(formatter, "expression lock is poisoned: {lock}"),
            Self::UnsupportedEffect { class } => {
                write!(formatter, "unsupported expression effect class: {class:?}")
            }
            Self::InvalidOutcome(message) => {
                write!(formatter, "invalid expression session outcome: {message}")
            }
        }
    }
}

impl Error for SessionError {}

/// One ordered variable overlay entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OverlayWrite {
    name: String,
    previous: Option<String>,
    value: String,
}

impl OverlayWrite {
    /// Returns the exact key.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the value visible before this write.
    #[must_use]
    pub fn previous(&self) -> Option<&str> {
        self.previous.as_deref()
    }

    /// Returns the written value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// A result of evaluating one bounded expression session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExpressionSessionOutcome {
    /// All effects and the final value are committed.
    Commit {
        /// Final expression value.
        value: String,
        /// Ordered committed effects.
        effects: Box<[ExpressionEffectRecord]>,
    },
    /// A pinned, observable prefix committed with a diagnostic.
    CommitWithDiagnostic {
        /// Observable partial/final value.
        value: String,
        /// Bounded diagnostic.
        diagnostic: String,
        /// Ordered committed effects.
        effects: Box<[ExpressionEffectRecord]>,
    },
    /// No effect was published because failure happened before effects.
    AbortBeforeEffects {
        /// Typed failure explaining the abort.
        error: SessionError,
    },
    /// An external effect may have escaped; the authority is poisoned.
    UncertainAfterExternalEffect {
        /// Typed external failure.
        error: SessionError,
        /// Exact poison marker.
        poison: ExpressionPoison,
    },
}

/// Short alias for [`ExpressionSessionOutcome`].
pub type SessionOutcome = ExpressionSessionOutcome;

/// Mutable, bounded, source-ordered expression evaluation session.
pub struct ExpressionSession {
    identity: ExpressionSessionIdentity,
    generation: u64,
    base_variables: BTreeMap<String, String>,
    base_properties: BTreeMap<String, String>,
    variables: Vec<OverlayWrite>,
    properties: Vec<OverlayWrite>,
    occurrences: Vec<FunctionOccurrence>,
    journal: EffectJournal,
    limits: ExpressionSessionLimits,
    calls: usize,
    mutations: usize,
    depth: usize,
    state: SessionLifecycle,
    authority: Option<Arc<ExpressionRuntimeState>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SessionLifecycle {
    Open,
    Committed,
    Aborted,
    Poisoned(ExpressionPoison),
}

impl fmt::Debug for ExpressionSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExpressionSession")
            .field("identity", &self.identity)
            .field("generation", &self.generation)
            .field("base_variable_count", &self.base_variables.len())
            .field("base_property_count", &self.base_properties.len())
            .field("variable_overlay_count", &self.variables.len())
            .field("property_overlay_count", &self.properties.len())
            .field("occurrence_count", &self.occurrences.len())
            .field("journal_entries", &self.journal.len())
            .field("calls", &self.calls)
            .field("mutations", &self.mutations)
            .field("depth", &self.depth)
            .field("state", &self.state)
            .finish()
    }
}

impl ExpressionSession {
    /// Creates a standalone session with generation zero.
    pub fn new(
        identity: ExpressionSessionIdentity,
        base_variables: BTreeMap<String, String>,
        base_properties: BTreeMap<String, String>,
        limits: ExpressionSessionLimits,
    ) -> Result<Self, SessionError> {
        Self::with_generation(identity, 0, base_variables, base_properties, limits)
    }

    /// Creates a standalone session bound to an explicit generation.
    pub fn with_generation(
        identity: ExpressionSessionIdentity,
        generation: u64,
        base_variables: BTreeMap<String, String>,
        base_properties: BTreeMap<String, String>,
        limits: ExpressionSessionLimits,
    ) -> Result<Self, SessionError> {
        validate_base_maps(&base_variables, &base_properties, &limits)?;
        Ok(Self {
            identity,
            generation,
            base_variables,
            base_properties,
            variables: Vec::new(),
            properties: Vec::new(),
            occurrences: Vec::new(),
            journal: EffectJournal::new(limits.max_journal_entries, limits.max_journal_bytes),
            limits,
            calls: 0,
            mutations: 0,
            depth: 0,
            state: SessionLifecycle::Open,
            authority: None,
        })
    }

    /// Returns the session identity.
    #[must_use]
    pub fn identity(&self) -> &ExpressionSessionIdentity {
        &self.identity
    }

    /// Returns the expected authority generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns session bounds.
    #[must_use]
    pub const fn limits(&self) -> ExpressionSessionLimits {
        self.limits
    }

    /// Resolves a variable from the latest overlay write or immutable base.
    #[must_use]
    pub fn resolve_variable(&self, name: &str) -> Option<&str> {
        self.variables
            .iter()
            .rev()
            .find(|entry| entry.name == name)
            .map(OverlayWrite::value)
            .or_else(|| self.base_variables.get(name).map(String::as_str))
    }

    /// Resolves a property from the latest overlay write or immutable base.
    #[must_use]
    pub fn resolve_property(&self, name: &str) -> Option<&str> {
        self.properties
            .iter()
            .rev()
            .find(|entry| entry.name == name)
            .map(OverlayWrite::value)
            .or_else(|| self.base_properties.get(name).map(String::as_str))
    }

    /// Returns the immutable base variable map.
    #[must_use]
    pub fn base_variables(&self) -> &BTreeMap<String, String> {
        &self.base_variables
    }

    /// Returns the immutable base property map.
    #[must_use]
    pub fn base_properties(&self) -> &BTreeMap<String, String> {
        &self.base_properties
    }

    /// Returns ordered variable writes, including duplicates.
    #[must_use]
    pub fn variable_overlay(&self) -> &[OverlayWrite] {
        &self.variables
    }

    /// Returns ordered property writes, including duplicates.
    #[must_use]
    pub fn property_overlay(&self) -> &[OverlayWrite] {
        &self.properties
    }

    /// Returns exact function occurrences observed by this session in source
    /// evaluation order.
    #[must_use]
    pub fn occurrences(&self) -> &[FunctionOccurrence] {
        &self.occurrences
    }

    /// Records one exact structural occurrence, rejecting a call-count
    /// overflow rather than refreshing or reusing an identity.
    pub fn record_occurrence(
        &mut self,
        occurrence: FunctionOccurrence,
    ) -> Result<(), SessionError> {
        self.ensure_open()?;
        if self.occurrences.len() >= self.limits.max_calls {
            return Err(SessionError::CallLimit {
                limit: self.limits.max_calls,
            });
        }
        self.occurrences.push(occurrence);
        Ok(())
    }

    /// Returns the final variable projection (last overlay write wins).
    #[must_use]
    pub fn final_variables(&self) -> BTreeMap<String, String> {
        let mut values = self.base_variables.clone();
        for entry in &self.variables {
            values.insert(entry.name.clone(), entry.value.clone());
        }
        values
    }

    /// Returns the final property projection (last overlay write wins).
    #[must_use]
    pub fn final_properties(&self) -> BTreeMap<String, String> {
        let mut values = self.base_properties.clone();
        for entry in &self.properties {
            values.insert(entry.name.clone(), entry.value.clone());
        }
        values
    }

    /// Returns the ordered effect journal.
    #[must_use]
    pub fn journal(&self) -> &EffectJournal {
        &self.journal
    }

    /// Appends one explicitly classified effect to the ordered journal.
    ///
    /// Variable/property overlay writes should use [`Self::set_variable`] or
    /// [`Self::set_property`] so subsequent reads see the write immediately.
    pub fn record_effect(
        &mut self,
        class: EffectClass,
        effect: ExpressionEffect,
    ) -> Result<(), SessionError> {
        self.ensure_open()?;
        if !effect_class_matches(class, &effect) {
            return Err(SessionError::InvalidOutcome(
                "effect class does not match effect payload".to_owned(),
            ));
        }
        self.ensure_mutation("effect", "record")?;
        self.journal
            .push(ExpressionEffectRecord::new(class, effect))
    }

    /// Records one bounded input/capability call.
    pub fn record_call(&mut self, input_bytes: usize) -> Result<(), SessionError> {
        self.ensure_open()?;
        if input_bytes > self.limits.max_input_bytes {
            return Err(SessionError::InputLimit {
                limit: self.limits.max_input_bytes,
                actual: input_bytes,
            });
        }
        self.calls = self.calls.checked_add(1).ok_or(SessionError::CallLimit {
            limit: self.limits.max_calls,
        })?;
        if self.calls > self.limits.max_calls {
            return Err(SessionError::CallLimit {
                limit: self.limits.max_calls,
            });
        }
        Ok(())
    }

    /// Checks input bytes without consuming a call-count slot.
    pub fn check_input_bytes(&self, bytes: usize) -> Result<(), SessionError> {
        if bytes > self.limits.max_input_bytes {
            Err(SessionError::InputLimit {
                limit: self.limits.max_input_bytes,
                actual: bytes,
            })
        } else {
            Ok(())
        }
    }

    /// Checks output bytes against the session bound.
    pub fn check_output_bytes(&self, bytes: usize) -> Result<(), SessionError> {
        self.check_output(bytes)
    }

    /// Returns the number of recorded calls.
    #[must_use]
    pub const fn call_count(&self) -> usize {
        self.calls
    }

    /// Returns the number of recorded mutations.
    #[must_use]
    pub const fn mutation_count(&self) -> usize {
        self.mutations
    }

    /// Enters one nested capability call depth.
    pub fn enter_call(&mut self) -> Result<(), SessionError> {
        self.ensure_open()?;
        let depth = self
            .depth
            .checked_add(1)
            .ok_or(SessionError::CallDepthLimit {
                limit: self.limits.max_call_depth,
            })?;
        if depth > self.limits.max_call_depth {
            return Err(SessionError::CallDepthLimit {
                limit: self.limits.max_call_depth,
            });
        }
        self.depth = depth;
        Ok(())
    }

    /// Leaves one nested capability call depth.
    pub fn leave_call(&mut self) -> Result<(), SessionError> {
        self.ensure_open()?;
        self.depth = self
            .depth
            .checked_sub(1)
            .ok_or_else(|| SessionError::InvalidOutcome("call depth underflow".to_owned()))?;
        Ok(())
    }

    /// Writes a variable to the ordered overlay and journals it.
    pub fn set_variable(&mut self, name: &str, value: &str) -> Result<(), SessionError> {
        self.ensure_mutation(name, value)?;
        let previous = self.resolve_variable(name).map(str::to_owned);
        let entry = ExpressionEffectRecord::new(
            EffectClass::JournaledNative,
            ExpressionEffect::Variable {
                name: name.to_owned(),
                previous: previous.clone(),
                value: value.to_owned(),
            },
        );
        self.journal.push(entry)?;
        self.variables.push(OverlayWrite {
            name: name.to_owned(),
            previous,
            value: value.to_owned(),
        });
        Ok(())
    }

    /// Writes several variables as one bounded session mutation.
    ///
    /// The writes remain source ordered and later entries see earlier values,
    /// but a failed bound check restores the session's pre-call overlay,
    /// journal, and mutation count.  This rollback is limited to the
    /// session-local proposal; it never claims to undo an already-published
    /// external/native capability effect.
    pub fn set_variables_atomic(&mut self, values: &[(&str, &str)]) -> Result<(), SessionError> {
        self.ensure_open()?;
        let variables_len = self.variables.len();
        let journal = self.journal.clone();
        let mutations = self.mutations;
        for (name, value) in values {
            if let Err(error) = self.set_variable(name, value) {
                self.variables.truncate(variables_len);
                self.journal = journal;
                self.mutations = mutations;
                return Err(error);
            }
        }
        Ok(())
    }

    /// Writes a property to the ordered overlay and journals it.
    pub fn set_property(&mut self, name: &str, value: &str) -> Result<(), SessionError> {
        self.ensure_mutation(name, value)?;
        let previous = self.resolve_property(name).map(str::to_owned);
        let entry = ExpressionEffectRecord::new(
            EffectClass::JournaledNative,
            ExpressionEffect::Property {
                name: name.to_owned(),
                previous: previous.clone(),
                value: value.to_owned(),
            },
        );
        self.journal.push(entry)?;
        self.properties.push(OverlayWrite {
            name: name.to_owned(),
            previous,
            value: value.to_owned(),
        });
        Ok(())
    }

    /// Journals a counter transition.
    pub fn journal_counter(
        &mut self,
        occurrence: FunctionOccurrence,
        previous: i64,
        value: i64,
    ) -> Result<(), SessionError> {
        self.record_native(NativeStateEffect::Counter {
            occurrence,
            previous,
            value,
        })
    }

    /// Journals a random draw without pretending the draw is reversible.
    pub fn journal_random(
        &mut self,
        occurrence: FunctionOccurrence,
        value: u64,
    ) -> Result<(), SessionError> {
        self.record_native(NativeStateEffect::Random { occurrence, value })
    }

    /// Journals a file-cursor transition.
    pub fn journal_file_cursor(
        &mut self,
        occurrence: FunctionOccurrence,
        key: &str,
        previous: u64,
        value: u64,
    ) -> Result<(), SessionError> {
        self.ensure_mutation(key, "cursor")?;
        self.journal.push(ExpressionEffectRecord::new(
            EffectClass::JournaledNative,
            ExpressionEffect::Native(NativeStateEffect::FileCursor {
                occurrence,
                key: key.to_owned(),
                previous,
                value,
            }),
        ))
    }

    /// Journals an explicitly classified external operation.
    pub fn journal_external(
        &mut self,
        class: EffectClass,
        operation: &str,
    ) -> Result<(), SessionError> {
        self.ensure_open()?;
        if matches!(class, EffectClass::Pure | EffectClass::JournaledNative) {
            return Err(SessionError::UnsupportedEffect { class });
        }
        self.ensure_mutation(operation, "external")?;
        self.journal.push(ExpressionEffectRecord::new(
            class,
            ExpressionEffect::External {
                class,
                operation: operation.to_owned(),
            },
        ))
    }

    /// Checks the generation supplied by an authority before publication.
    pub fn check_generation(&self, actual: u64) -> Result<(), SessionError> {
        if self.generation == actual {
            Ok(())
        } else {
            Err(SessionError::StaleGeneration {
                expected: self.generation,
                actual,
            })
        }
    }

    /// Commits a final expression value and ordered effects.
    pub fn commit(
        &mut self,
        value: impl Into<String>,
    ) -> Result<ExpressionSessionOutcome, SessionError> {
        self.commit_at(self.generation, value)
    }

    /// Commits after checking an explicit current generation.
    pub fn commit_at(
        &mut self,
        actual_generation: u64,
        value: impl Into<String>,
    ) -> Result<ExpressionSessionOutcome, SessionError> {
        self.ensure_open()?;
        self.check_authority_generation(actual_generation)?;
        let value = value.into();
        self.check_output(value.len())?;
        self.state = SessionLifecycle::Committed;
        Ok(ExpressionSessionOutcome::Commit {
            value,
            effects: self.journal.snapshot(),
        })
    }

    /// Commits a pinned observable value together with a bounded diagnostic.
    pub fn commit_with_diagnostic(
        &mut self,
        value: impl Into<String>,
        diagnostic: impl Into<String>,
    ) -> Result<ExpressionSessionOutcome, SessionError> {
        self.ensure_open()?;
        self.check_authority_generation(self.generation)?;
        let value = value.into();
        let diagnostic = diagnostic.into();
        self.check_output(value.len())?;
        if diagnostic.len() > self.limits.max_diagnostic_bytes {
            return Err(SessionError::DiagnosticLimit {
                limit: self.limits.max_diagnostic_bytes,
            });
        }
        self.state = SessionLifecycle::Committed;
        Ok(ExpressionSessionOutcome::CommitWithDiagnostic {
            value,
            diagnostic,
            effects: self.journal.snapshot(),
        })
    }

    /// Aborts before effects are published.  This outcome is valid only while
    /// the session has no journaled effect; after an effect, callers must use
    /// a commit, diagnostic commit, or uncertain/poisoned outcome.  The
    /// returned outcome never exposes a guessed or partial journal.
    pub fn abort_before_effects(
        &mut self,
        error: SessionError,
    ) -> Result<ExpressionSessionOutcome, SessionError> {
        self.ensure_open()?;
        if !self.journal.is_empty() || !self.variables.is_empty() || !self.properties.is_empty() {
            return Err(SessionError::InvalidOutcome(
                "abort-before-effects requires an empty effect journal".to_owned(),
            ));
        }
        self.variables.clear();
        self.properties.clear();
        self.journal.clear();
        self.state = SessionLifecycle::Aborted;
        Ok(ExpressionSessionOutcome::AbortBeforeEffects { error })
    }

    /// Records an uncertain external effect, poisons this session and its run
    /// authority, and returns a typed non-rollback outcome.
    pub fn uncertain_after_external_effect(
        &mut self,
        error: SessionError,
    ) -> Result<ExpressionSessionOutcome, SessionError> {
        self.ensure_open()?;
        let poison = ExpressionPoison::external_effect(error.to_string());
        if let Some(authority) = &self.authority {
            poison_authority(authority, poison.clone())?;
        }
        self.state = SessionLifecycle::Poisoned(poison.clone());
        Ok(ExpressionSessionOutcome::UncertainAfterExternalEffect { error, poison })
    }

    /// Returns whether this session is closed or poisoned.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        !matches!(self.state, SessionLifecycle::Open)
    }

    /// Wraps this session in an explicit shared capability handle.
    #[must_use]
    pub fn into_handle(self) -> ExpressionSessionHandle {
        ExpressionSessionHandle::new(self)
    }

    fn record_native(&mut self, effect: NativeStateEffect) -> Result<(), SessionError> {
        self.ensure_mutation("native", "state")?;
        self.journal.push(ExpressionEffectRecord::new(
            EffectClass::JournaledNative,
            ExpressionEffect::Native(effect),
        ))
    }

    fn ensure_open(&self) -> Result<(), SessionError> {
        match &self.state {
            SessionLifecycle::Open => {}
            SessionLifecycle::Committed | SessionLifecycle::Aborted => {
                return Err(SessionError::Closed);
            }
            SessionLifecycle::Poisoned(poison) => {
                return Err(SessionError::Poisoned(poison.clone()));
            }
        }
        if let Some(authority) = &self.authority {
            ensure_authority_healthy(authority)?;
        }
        Ok(())
    }

    fn ensure_mutation(&mut self, name: &str, value: &str) -> Result<(), SessionError> {
        self.ensure_open()?;
        let bytes = name
            .len()
            .checked_add(value.len())
            .ok_or(SessionError::OutputLimit {
                limit: self.limits.max_output_bytes,
                actual: usize::MAX,
            })?;
        if bytes > self.limits.max_output_bytes {
            return Err(SessionError::OutputLimit {
                limit: self.limits.max_output_bytes,
                actual: bytes,
            });
        }
        self.mutations = self
            .mutations
            .checked_add(1)
            .ok_or(SessionError::MutationLimit {
                limit: self.limits.max_mutations,
            })?;
        if self.mutations > self.limits.max_mutations {
            return Err(SessionError::MutationLimit {
                limit: self.limits.max_mutations,
            });
        }
        Ok(())
    }

    fn check_output(&self, bytes: usize) -> Result<(), SessionError> {
        if bytes > self.limits.max_output_bytes {
            Err(SessionError::OutputLimit {
                limit: self.limits.max_output_bytes,
                actual: bytes,
            })
        } else {
            Ok(())
        }
    }

    fn check_authority_generation(&self, actual: u64) -> Result<(), SessionError> {
        if let Some(authority) = &self.authority {
            ensure_authority_healthy(authority)?;
            let current = authority.generation.load(Ordering::Acquire);
            if current != actual || self.generation != current {
                return Err(SessionError::StaleGeneration {
                    expected: self.generation,
                    actual: current,
                });
            }
        } else {
            self.check_generation(actual)?;
        }
        Ok(())
    }
}

impl VariableResolver for ExpressionSession {
    fn resolve_variable(&self, name: &str) -> Option<&str> {
        self.resolve_variable(name)
    }
}

impl PropertyResolver for ExpressionSession {
    fn resolve_property(&self, name: &str) -> Option<&str> {
        self.resolve_property(name)
    }
}

/// A lock-backed capability handle for an [`ExpressionSession`].
pub struct ExpressionSessionHandle {
    session: Arc<Mutex<ExpressionSession>>,
}

impl Clone for ExpressionSessionHandle {
    fn clone(&self) -> Self {
        Self {
            session: Arc::clone(&self.session),
        }
    }
}

impl fmt::Debug for ExpressionSessionHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExpressionSessionHandle(..)")
    }
}

impl ExpressionSessionHandle {
    /// Creates a shared session capability handle.
    #[must_use]
    pub fn new(session: ExpressionSession) -> Self {
        Self {
            session: Arc::new(Mutex::new(session)),
        }
    }

    /// Locks the session and fails with a typed error if it is poisoned.
    pub fn lock(&self) -> Result<MutexGuard<'_, ExpressionSession>, SessionError> {
        self.session.lock().map_err(|_| SessionError::LockPoisoned {
            lock: "expression-session".to_owned(),
        })
    }

    /// Runs a bounded operation under the session lock.
    pub fn with_session<T>(
        &self,
        operation: impl FnOnce(&mut ExpressionSession) -> Result<T, SessionError>,
    ) -> Result<T, SessionError> {
        let mut session = self.lock()?;
        operation(&mut session)
    }

    /// Returns a deterministic final variable projection.
    pub fn final_variables(&self) -> Result<BTreeMap<String, String>, SessionError> {
        Ok(self.lock()?.final_variables())
    }

    /// Returns a deterministic final property projection.
    pub fn final_properties(&self) -> Result<BTreeMap<String, String>, SessionError> {
        Ok(self.lock()?.final_properties())
    }

    /// Returns whether the underlying session is closed.
    pub fn is_closed(&self) -> Result<bool, SessionError> {
        Ok(self.lock()?.is_closed())
    }
}

impl VariableSetter for ExpressionSessionHandle {
    fn set_variable(&self, name: &str, value: &str) -> Result<(), FunctionError> {
        self.with_session(|session| session.set_variable(name, value))
            .map_err(session_error_to_function_error)
    }

    fn set_variables_atomic(&self, values: &[(&str, &str)]) -> Result<(), FunctionError> {
        self.with_session(|session| session.set_variables_atomic(values))
            .map_err(session_error_to_function_error)
    }

    fn get_variable(&self, name: &str) -> Option<String> {
        // This legacy trait method cannot represent a typed lock failure.  All
        // expression evaluation uses `get_variable_checked`; retain `None`
        // here solely for source compatibility with older callers.
        match self.session.lock() {
            Ok(session) => session.resolve_variable(name).map(str::to_owned),
            Err(_) => None,
        }
    }

    fn get_variable_checked(&self, name: &str) -> Result<Option<String>, FunctionError> {
        self.lock()
            .map(|session| session.resolve_variable(name).map(str::to_owned))
            .map_err(session_error_to_function_error)
    }

    fn remove_variable(&self, _name: &str) -> Result<(), FunctionError> {
        Err(FunctionError::unsupported(
            "expression session variable removal is not represented by this foundation",
        ))
    }
}

impl PropertySetter for ExpressionSessionHandle {
    fn set_property(&self, name: &str, value: &str) -> Result<Option<String>, FunctionError> {
        self.with_session(|session| {
            let previous = session.resolve_property(name).map(str::to_owned);
            session.set_property(name, value)?;
            Ok(previous)
        })
        .map_err(session_error_to_function_error)
    }

    fn get_property(&self, name: &str) -> Option<String> {
        // This legacy trait method cannot represent a typed lock failure.  All
        // expression evaluation uses `get_property_checked`; retain `None`
        // here solely for source compatibility with older callers.
        match self.session.lock() {
            Ok(session) => session.resolve_property(name).map(str::to_owned),
            Err(_) => None,
        }
    }

    fn get_property_checked(&self, name: &str) -> Result<Option<String>, FunctionError> {
        self.lock()
            .map(|session| session.resolve_property(name).map(str::to_owned))
            .map_err(session_error_to_function_error)
    }
}

/// One shared run-owned expression authority.
pub struct ExpressionRuntime {
    inner: Arc<ExpressionRuntimeState>,
}

struct ExpressionRuntimeState {
    registry: SharedBuiltinFunctions,
    generation: AtomicU64,
    poison: Mutex<Option<ExpressionPoison>>,
}

impl Clone for ExpressionRuntime {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl fmt::Debug for ExpressionRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExpressionRuntime")
            .field("generation", &self.current_generation())
            .field("poisoned", &self.is_poisoned().unwrap_or(true))
            .finish()
    }
}

impl ExpressionRuntime {
    /// Creates a fresh run authority and a fresh native function registry.
    #[must_use]
    pub fn new() -> Self {
        Self::with_registry(BuiltinFunctions::new_shared())
    }

    /// Creates a run authority around an explicitly selected shared registry.
    #[must_use]
    pub fn with_registry(registry: SharedBuiltinFunctions) -> Self {
        Self {
            inner: Arc::new(ExpressionRuntimeState {
                registry,
                generation: AtomicU64::new(0),
                poison: Mutex::new(None),
            }),
        }
    }

    /// Returns a clone of the run-shared authority handle.
    #[must_use]
    pub fn shared(&self) -> Arc<Self> {
        Arc::new(self.clone())
    }

    /// Returns the one shared native function registry.
    #[must_use]
    pub fn registry(&self) -> &SharedBuiltinFunctions {
        &self.inner.registry
    }

    /// Returns the current checked invocation generation.
    #[must_use]
    pub fn current_generation(&self) -> u64 {
        self.inner.generation.load(Ordering::Acquire)
    }

    /// Advances the generation, poisoning the run if it would overflow.
    pub fn advance_generation(&self) -> Result<u64, SessionError> {
        ensure_authority_healthy(&self.inner)?;
        loop {
            let current = self.inner.generation.load(Ordering::Acquire);
            let next = current.checked_add(1).ok_or_else(|| {
                let poison = ExpressionPoison::generation_exhausted();
                let _ = poison_authority(&self.inner, poison.clone());
                SessionError::Poisoned(poison)
            })?;
            match self.inner.generation.compare_exchange(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(next),
                Err(_) => continue,
            }
        }
    }

    /// Begins a bounded session at the authority's current generation.
    pub fn begin_session(
        &self,
        identity: ExpressionSessionIdentity,
        base_variables: BTreeMap<String, String>,
        base_properties: BTreeMap<String, String>,
        limits: ExpressionSessionLimits,
    ) -> Result<ExpressionSession, SessionError> {
        ensure_authority_healthy(&self.inner)?;
        let generation = self.current_generation();
        let mut session = ExpressionSession::with_generation(
            identity,
            generation,
            base_variables,
            base_properties,
            limits,
        )?;
        session.authority = Some(Arc::clone(&self.inner));
        Ok(session)
    }

    /// Poisons this exact run authority.
    pub fn poison(&self, poison: ExpressionPoison) -> Result<(), SessionError> {
        poison_authority(&self.inner, poison)
    }

    /// Returns the current poison marker, if any.
    pub fn poison_state(&self) -> Result<Option<ExpressionPoison>, SessionError> {
        self.inner
            .poison
            .lock()
            .map(|poison| poison.clone())
            .map_err(|_| SessionError::LockPoisoned {
                lock: "expression-runtime-poison".to_owned(),
            })
    }

    /// Returns whether this run is poisoned, failing closed on a poisoned
    /// poison-state lock.
    pub fn is_poisoned(&self) -> Result<bool, SessionError> {
        Ok(self.poison_state()?.is_some())
    }
}

impl Default for ExpressionRuntime {
    fn default() -> Self {
        Self::new()
    }
}

fn ensure_authority_healthy(authority: &ExpressionRuntimeState) -> Result<(), SessionError> {
    let poison = authority
        .poison
        .lock()
        .map_err(|_| SessionError::LockPoisoned {
            lock: "expression-runtime-poison".to_owned(),
        })?
        .clone();
    poison.map_or(Ok(()), |poison| Err(SessionError::Poisoned(poison)))
}

fn poison_authority(
    authority: &ExpressionRuntimeState,
    poison: ExpressionPoison,
) -> Result<(), SessionError> {
    let mut state = authority
        .poison
        .lock()
        .map_err(|_| SessionError::LockPoisoned {
            lock: "expression-runtime-poison".to_owned(),
        })?;
    if state.is_none() {
        *state = Some(poison);
    }
    Ok(())
}

fn session_error_to_function_error(error: SessionError) -> FunctionError {
    match error {
        SessionError::Poisoned(poison) => FunctionError::poisoned(poison.detail()),
        SessionError::LockPoisoned { lock } => FunctionError::poisoned(lock),
        SessionError::InputLimit { limit, actual } => {
            FunctionError::resource_limit(format!("session input {actual} exceeds {limit}"))
        }
        SessionError::OutputLimit { limit, actual } => {
            FunctionError::resource_limit(format!("session output {actual} exceeds {limit}"))
        }
        SessionError::CallDepthLimit { limit }
        | SessionError::CallLimit { limit }
        | SessionError::MutationLimit { limit }
        | SessionError::JournalLimit { limit }
        | SessionError::JournalBytesLimit { limit }
        | SessionError::DiagnosticLimit { limit } => {
            FunctionError::resource_limit(format!("session limit {limit} reached"))
        }
        SessionError::StaleGeneration { expected, actual } => FunctionError::execution(format!(
            "stale expression generation: expected {expected}, got {actual}"
        )),
        SessionError::Closed => FunctionError::execution("expression session is closed"),
        SessionError::UnsupportedEffect { class } => {
            FunctionError::unsupported(format!("effect class {class:?} is unavailable"))
        }
        SessionError::InvalidOutcome(message) => FunctionError::execution(message),
    }
}

fn bounded_diagnostic(mut value: String, limit: usize) -> String {
    if value.len() <= limit {
        return value;
    }
    let mut end = limit;
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    value.truncate(end);
    value
}

fn validate_base_maps(
    variables: &BTreeMap<String, String>,
    properties: &BTreeMap<String, String>,
    limits: &ExpressionSessionLimits,
) -> Result<(), SessionError> {
    let total =
        variables
            .iter()
            .chain(properties.iter())
            .try_fold(0usize, |total, (name, value)| {
                total
                    .checked_add(name.len())
                    .and_then(|total| total.checked_add(value.len()))
                    .ok_or(SessionError::OutputLimit {
                        limit: limits.max_output_bytes,
                        actual: usize::MAX,
                    })
            })?;
    if total > limits.max_output_bytes {
        return Err(SessionError::OutputLimit {
            limit: limits.max_output_bytes,
            actual: total,
        });
    }
    Ok(())
}

fn effect_bytes(record: &ExpressionEffectRecord) -> usize {
    let class_bytes = std::mem::size_of_val(&record.class);
    let effect_bytes = match &record.effect {
        ExpressionEffect::Variable {
            name,
            previous,
            value,
        }
        | ExpressionEffect::Property {
            name,
            previous,
            value,
        } => name
            .len()
            .saturating_add(previous.as_ref().map_or(0, String::len))
            .saturating_add(value.len()),
        ExpressionEffect::Native(NativeStateEffect::Counter { occurrence, .. })
        | ExpressionEffect::Native(NativeStateEffect::Random { occurrence, .. }) => {
            occurrence.function_name().len().saturating_add(
                occurrence
                    .path()
                    .len()
                    .saturating_mul(std::mem::size_of::<u64>()),
            )
        }
        ExpressionEffect::Native(NativeStateEffect::FileCursor {
            occurrence, key, ..
        }) => occurrence
            .function_name()
            .len()
            .saturating_add(key.len())
            .saturating_add(
                occurrence
                    .path()
                    .len()
                    .saturating_mul(std::mem::size_of::<u64>()),
            ),
        ExpressionEffect::External { operation, .. } => operation.len(),
    };
    class_bytes.saturating_add(effect_bytes)
}

fn effect_class_matches(class: EffectClass, effect: &ExpressionEffect) -> bool {
    match effect {
        ExpressionEffect::Variable { .. }
        | ExpressionEffect::Property { .. }
        | ExpressionEffect::Native(_) => class == EffectClass::JournaledNative,
        ExpressionEffect::External {
            class: effect_class,
            ..
        } => {
            class == *effect_class
                && matches!(
                    class,
                    EffectClass::TransactionalExternal | EffectClass::IrreversibleExternal
                )
        }
    }
}

fn collect_field_occurrences(
    source: &str,
    namespace: u64,
    limits: &ExpressionFieldLimits,
) -> Result<Vec<FunctionOccurrence>, ExpressionFieldError> {
    let mut occurrences = Vec::new();
    collect_field_occurrences_in(source, namespace, &[], limits, &mut occurrences)?;
    Ok(occurrences)
}

fn collect_field_occurrences_in(
    source: &str,
    namespace: u64,
    prefix: &[u64],
    limits: &ExpressionFieldLimits,
    occurrences: &mut Vec<FunctionOccurrence>,
) -> Result<(), ExpressionFieldError> {
    let mut index = 0usize;
    while index < source.len() {
        let Some(character) = source[index..].chars().next() else {
            break;
        };
        if character == '\\' {
            let slash_end = index + character.len_utf8();
            if let Some(next) = source[slash_end..].chars().next() {
                index = slash_end + next.len_utf8();
                continue;
            }
            index = slash_end;
            continue;
        }
        if character == '$' {
            let dollar_end = index + character.len_utf8();
            if source[dollar_end..].starts_with('{') {
                let end = find_reference_end(source, index, false)
                    .map_err(ExpressionFieldError::InvalidSource)?;
                let reference = &source[index..end];
                let body = &reference[2..reference.len() - 1];
                let parsed = parse_reference_body(body, index + 2)
                    .map_err(ExpressionFieldError::InvalidSource)?;
                let function_name = parsed
                    .function
                    .as_ref()
                    .map(|function| function.name.as_str())
                    .or_else(|| {
                        parsed
                            .bare_name
                            .starts_with("__")
                            .then_some(parsed.bare_name.as_str())
                    });
                if let Some(function_name) = function_name {
                    let mut path = prefix.to_vec();
                    let segment = u64::try_from(index).map_err(|_| {
                        ExpressionFieldError::InvalidSource(
                            EvaluationError::OccurrencePathLimitExceeded {
                                limit: MAX_FUNCTION_OCCURRENCE_PATH_SEGMENTS,
                                offset: index,
                            },
                        )
                    })?;
                    append_occurrence_segment(&mut path, segment, index)
                        .map_err(ExpressionFieldError::InvalidSource)?;
                    if occurrences.len() >= limits.max_occurrences {
                        return Err(ExpressionFieldError::OccurrenceLimit {
                            limit: limits.max_occurrences,
                        });
                    }
                    occurrences.push(FunctionOccurrence::new(
                        namespace,
                        path.clone(),
                        function_name,
                    ));
                    if let Some(function) = parsed.function {
                        for (argument_index, argument) in function.arguments.into_iter().enumerate()
                        {
                            let mut argument_prefix = path.clone();
                            let argument_segment = u64::try_from(argument_index).map_err(|_| {
                                ExpressionFieldError::InvalidSource(
                                    EvaluationError::OccurrencePathLimitExceeded {
                                        limit: MAX_FUNCTION_OCCURRENCE_PATH_SEGMENTS,
                                        offset: index,
                                    },
                                )
                            })?;
                            append_occurrence_segment(
                                &mut argument_prefix,
                                argument_segment,
                                index,
                            )
                            .map_err(ExpressionFieldError::InvalidSource)?;
                            collect_field_occurrences_in(
                                &argument,
                                namespace,
                                &argument_prefix,
                                limits,
                                occurrences,
                            )?;
                        }
                    }
                }
                index = end;
                continue;
            }
        }
        index += character.len_utf8();
    }
    Ok(())
}

/// A private hook used by indirection functions to re-enter the evaluator.
trait NestedEvaluator {
    fn evaluate_nested(&self, input: &str) -> Result<String, FunctionError>;
}

/// Read-only context exposed to a function resolver.
///
/// The context exposes resolver views plus only the explicitly injected
/// capability handles.  Without a capability, mutation and external effects
/// are unavailable; no executor, ambient filesystem, network, or environment
/// access is available here.
pub struct FunctionContext<'a> {
    variables: &'a dyn VariableResolver,
    properties: &'a dyn PropertyResolver,
    capabilities: EvaluationCapabilities<'a>,
    nested_evaluator: Option<&'a dyn NestedEvaluator>,
    function_occurrence: FunctionOccurrence,
    max_output_bytes: usize,
}

impl<'a> FunctionContext<'a> {
    fn new(
        variables: &'a dyn VariableResolver,
        properties: &'a dyn PropertyResolver,
        capabilities: EvaluationCapabilities<'a>,
        nested_evaluator: Option<&'a dyn NestedEvaluator>,
        function_occurrence: FunctionOccurrence,
        max_output_bytes: usize,
    ) -> Self {
        Self {
            variables,
            properties,
            capabilities,
            nested_evaluator,
            function_occurrence,
            max_output_bytes,
        }
    }

    /// Returns a stable scalar compatibility identity for this invocation.
    ///
    /// Native stateful functions use [`Self::function_occurrence`] directly;
    /// this method remains for adapters that still accept the original scalar
    /// occurrence hook.
    #[must_use]
    pub fn function_instance_id(&self) -> u64 {
        self.function_occurrence.legacy_id()
    }

    /// Returns the full structural identity for this invocation.
    #[must_use]
    pub fn function_occurrence(&self) -> &FunctionOccurrence {
        &self.function_occurrence
    }

    /// Returns the evaluator's output ceiling for one function result.
    ///
    /// Functions use this before allocating variable-size results.  The
    /// evaluator still checks the complete expression after each expansion;
    /// this accessor prevents a malicious length argument from bypassing that
    /// check with a large intermediate allocation.
    #[must_use]
    pub fn max_output_bytes(&self) -> usize {
        self.max_output_bytes
    }

    /// Resolves a variable for a function implementation.
    #[must_use]
    pub fn variable(&self, name: &str) -> Option<&str> {
        self.variables.resolve_variable(name)
    }

    /// Resolves a variable as an owned value, consulting an injected mutable
    /// store before the read-only resolver.
    #[must_use]
    pub fn variable_value(&self, name: &str) -> Option<String> {
        self.capabilities
            .variable_setter
            .and_then(|setter| setter.get_variable(name))
            .or_else(|| self.variable(name).map(str::to_owned))
    }

    /// Resolves a variable and preserves a capability's poisoned-lock error.
    pub fn variable_value_checked(&self, name: &str) -> Result<Option<String>, FunctionError> {
        match self.capabilities.variable_setter {
            Some(setter) => setter
                .get_variable_checked(name)
                .map(|value| value.or_else(|| self.variable(name).map(str::to_owned))),
            None => Ok(self.variable(name).map(str::to_owned)),
        }
    }

    /// Resolves a property for a function implementation.
    #[must_use]
    pub fn property(&self, name: &str) -> Option<&str> {
        self.properties.resolve_property(name)
    }

    /// Resolves a property as an owned value, consulting an injected mutable
    /// store before the read-only resolver.
    #[must_use]
    pub fn property_value(&self, name: &str) -> Option<String> {
        self.capabilities
            .property_setter
            .and_then(|setter| setter.get_property(name))
            .or_else(|| self.property(name).map(str::to_owned))
    }

    /// Resolves a property and preserves a capability's poisoned-lock error.
    pub fn property_value_checked(&self, name: &str) -> Result<Option<String>, FunctionError> {
        match self.capabilities.property_setter {
            Some(setter) => setter
                .get_property_checked(name)
                .map(|value| value.or_else(|| self.property(name).map(str::to_owned))),
            None => Ok(self.property(name).map(str::to_owned)),
        }
    }

    /// Stores a variable through the explicitly supplied mutable capability.
    pub fn set_variable(&self, name: &str, value: &str) -> Result<(), FunctionError> {
        self.capabilities
            .variable_setter
            .ok_or_else(|| {
                FunctionError::unsupported("variable mutation capability is unavailable")
            })?
            .set_variable(name, value)
    }

    /// Stores several variables through the explicitly supplied mutable
    /// capability as one logical mutation.
    pub fn set_variables_atomic(&self, values: &[(&str, &str)]) -> Result<(), FunctionError> {
        self.capabilities
            .variable_setter
            .ok_or_else(|| {
                FunctionError::unsupported("variable mutation capability is unavailable")
            })?
            .set_variables_atomic(values)
    }

    /// Returns whether variable mutation was explicitly supplied.
    #[must_use]
    pub fn has_variable_setter(&self) -> bool {
        self.capabilities.variable_setter.is_some()
    }

    /// Returns whether property mutation was explicitly supplied.
    #[must_use]
    pub fn has_property_setter(&self) -> bool {
        self.capabilities.property_setter.is_some()
    }

    /// Removes a variable through the explicitly supplied mutable capability.
    pub fn remove_variable(&self, name: &str) -> Result<(), FunctionError> {
        self.capabilities
            .variable_setter
            .ok_or_else(|| {
                FunctionError::unsupported("variable mutation capability is unavailable")
            })?
            .remove_variable(name)
    }

    /// Sets a property through the explicitly supplied mutable capability.
    pub fn set_property(&self, name: &str, value: &str) -> Result<Option<String>, FunctionError> {
        self.capabilities
            .property_setter
            .ok_or_else(|| {
                FunctionError::unsupported("property mutation capability is unavailable")
            })?
            .set_property(name, value)
    }

    /// Resolves the optional test-plan name capability.
    #[must_use]
    pub fn test_plan_name(&self) -> Option<String> {
        self.capabilities
            .test_plan_name
            .and_then(TestPlanNameResolver::test_plan_name)
    }

    /// Returns whether a test-plan-name capability was explicitly supplied.
    #[must_use]
    pub fn has_test_plan_name_capability(&self) -> bool {
        self.capabilities.test_plan_name.is_some()
    }

    /// Returns the injected random source, if one is available.
    #[must_use]
    pub fn random_source(&self) -> Option<&dyn RandomSource> {
        self.capabilities.random
    }

    /// Returns occurrence-bound native state hooks, if supplied.
    #[must_use]
    pub fn native_state(&self) -> Option<&dyn NativeStateCapability> {
        self.capabilities.native_state
    }

    /// Returns the injected clock, if one is available.
    #[must_use]
    pub fn clock(&self) -> Option<&dyn ClockSource> {
        self.capabilities.clock
    }

    /// Returns the injected virtual-user identity, if one is available.
    #[must_use]
    pub fn execution_context(&self) -> Option<&dyn ExecutionContext> {
        self.capabilities.execution
    }

    /// Returns the explicit iteration number supplied by the execution
    /// capability, if this evaluation belongs to a virtual-user iteration.
    #[must_use]
    pub fn iteration_id(&self) -> Option<u64> {
        self.capabilities
            .execution
            .and_then(ExecutionContext::iteration_id)
    }

    /// Returns the complete explicit iteration identity supplied by the
    /// execution capability, if available.
    #[must_use]
    pub fn iteration_identity(&self) -> Option<IterationIdentity> {
        self.capabilities
            .execution
            .and_then(ExecutionContext::iteration_identity)
    }

    /// Returns the injected host resolver, if one is available.
    #[must_use]
    pub fn host_resolver(&self) -> Option<&dyn HostResolver> {
        self.capabilities.host
    }

    /// Returns the injected log sink, if one is available.
    #[must_use]
    pub fn log_sink(&self) -> Option<&dyn LogSink> {
        self.capabilities.log
    }

    /// Returns the injected file capability, if one is available.
    #[must_use]
    pub fn file_capability(&self) -> Option<&dyn FileCapability> {
        self.capabilities.files
    }

    /// Returns the injected response extractor, if one is available.
    #[must_use]
    pub fn response_extractor(&self) -> Option<&dyn ResponseExtractor> {
        self.capabilities.response
    }

    /// Returns the injected script capability, if one is available.
    #[must_use]
    pub fn script_capability(&self) -> Option<&dyn ScriptCapability> {
        self.capabilities.scripts
    }

    /// Evaluates a string again using the current variable/property/function
    /// context.  This is intentionally only available to indirection
    /// functions such as `__eval` and `__evalVar`.
    pub fn evaluate_nested(&self, input: &str) -> Result<String, FunctionError> {
        self.nested_evaluator
            .ok_or_else(|| {
                FunctionError::unsupported("nested expression capability is unavailable")
            })?
            .evaluate_nested(input)
    }
}

/// A read-only function registry/evaluator.
pub trait FunctionResolver: Sync {
    /// Evaluates a function by its exact, case-sensitive reference name.
    ///
    /// `Ok(None)` means that the function is undefined.  The evaluator then
    /// preserves the complete source reference unchanged.  `Ok(Some(value))`
    /// distinguishes a defined function returning an empty string from an
    /// undefined function.
    fn resolve_function(
        &self,
        name: &str,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<Option<String>, FunctionError>;

    /// Reports whether a function name is defined without evaluating its
    /// arguments.  `Some(false)` lets the evaluator preserve an unknown
    /// function reference verbatim and avoid side effects in nested
    /// arguments.  `None` retains compatibility with resolvers that cannot
    /// answer this question ahead of evaluation.
    fn is_defined(&self, _name: &str) -> Option<bool> {
        None
    }
}

/// A no-op variable resolver useful for literal-only expansion.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoVariables;

impl VariableResolver for NoVariables {
    fn resolve_variable(&self, _name: &str) -> Option<&str> {
        None
    }
}

/// A no-op property resolver useful for function fakes without properties.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoProperties;

impl PropertyResolver for NoProperties {
    fn resolve_property(&self, _name: &str) -> Option<&str> {
        None
    }
}

/// A no-op function resolver.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoFunctions;

impl FunctionResolver for NoFunctions {
    fn resolve_function(
        &self,
        _name: &str,
        _arguments: &[String],
        _context: &FunctionContext<'_>,
    ) -> Result<Option<String>, FunctionError> {
        Ok(None)
    }
}

impl<K, V, S> VariableResolver for HashMap<K, V, S>
where
    K: Borrow<str> + Eq + Hash + Sync,
    V: AsRef<str> + Sync,
    S: BuildHasher + Sync,
{
    fn resolve_variable(&self, name: &str) -> Option<&str> {
        self.get(name).map(AsRef::as_ref)
    }
}

impl<K, V> VariableResolver for BTreeMap<K, V>
where
    K: Borrow<str> + Ord + Sync,
    V: AsRef<str> + Sync,
{
    fn resolve_variable(&self, name: &str) -> Option<&str> {
        self.get(name).map(AsRef::as_ref)
    }
}

impl<K, V, S> PropertyResolver for HashMap<K, V, S>
where
    K: Borrow<str> + Eq + Hash + Sync,
    V: AsRef<str> + Sync,
    S: BuildHasher + Sync,
{
    fn resolve_property(&self, name: &str) -> Option<&str> {
        self.get(name).map(AsRef::as_ref)
    }
}

impl<K, V> PropertyResolver for BTreeMap<K, V>
where
    K: Borrow<str> + Ord + Sync,
    V: AsRef<str> + Sync,
{
    fn resolve_property(&self, name: &str) -> Option<&str> {
        self.get(name).map(AsRef::as_ref)
    }
}

impl VariableResolver for () {
    fn resolve_variable(&self, _name: &str) -> Option<&str> {
        None
    }
}

impl PropertyResolver for () {
    fn resolve_property(&self, _name: &str) -> Option<&str> {
        None
    }
}

impl FunctionResolver for () {
    fn resolve_function(
        &self,
        _name: &str,
        _arguments: &[String],
        _context: &FunctionContext<'_>,
    ) -> Result<Option<String>, FunctionError> {
        Ok(None)
    }
}

/// Pure expression evaluator with explicit read-only capabilities.
pub struct Evaluator<'a> {
    variables: &'a dyn VariableResolver,
    properties: &'a dyn PropertyResolver,
    functions: &'a dyn FunctionResolver,
    limits: EvaluationLimits,
    capabilities: EvaluationCapabilities<'a>,
    function_instance_namespace: u64,
}

impl<'a> Evaluator<'a> {
    /// Creates an evaluator with [`EvaluationLimits::default`].
    #[must_use]
    pub fn new(
        variables: &'a dyn VariableResolver,
        properties: &'a dyn PropertyResolver,
        functions: &'a dyn FunctionResolver,
    ) -> Self {
        Self {
            variables,
            properties,
            functions,
            limits: EvaluationLimits::default(),
            capabilities: EvaluationCapabilities::new(),
            function_instance_namespace: 0,
        }
    }

    /// Creates an evaluator with an explicit resource policy.
    #[must_use]
    pub fn with_limits(
        variables: &'a dyn VariableResolver,
        properties: &'a dyn PropertyResolver,
        functions: &'a dyn FunctionResolver,
        limits: EvaluationLimits,
    ) -> Self {
        Self {
            variables,
            properties,
            functions,
            limits,
            capabilities: EvaluationCapabilities::new(),
            function_instance_namespace: 0,
        }
    }

    /// Creates an evaluator with explicit resource and capability policies.
    #[must_use]
    pub fn with_capabilities(
        variables: &'a dyn VariableResolver,
        properties: &'a dyn PropertyResolver,
        functions: &'a dyn FunctionResolver,
        capabilities: EvaluationCapabilities<'a>,
    ) -> Self {
        Self {
            variables,
            properties,
            functions,
            limits: EvaluationLimits::default(),
            capabilities,
            function_instance_namespace: 0,
        }
    }

    /// Creates an evaluator with explicit limits and capability policies.
    #[must_use]
    pub fn with_limits_and_capabilities(
        variables: &'a dyn VariableResolver,
        properties: &'a dyn PropertyResolver,
        functions: &'a dyn FunctionResolver,
        limits: EvaluationLimits,
        capabilities: EvaluationCapabilities<'a>,
    ) -> Self {
        Self {
            variables,
            properties,
            functions,
            limits,
            capabilities,
            function_instance_namespace: 0,
        }
    }

    /// Adds capabilities to an evaluator created by [`Evaluator::new`].
    #[must_use]
    pub fn with_function_capabilities(mut self, capabilities: EvaluationCapabilities<'a>) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Alias for [`Evaluator::with_function_capabilities`].
    #[must_use]
    pub fn with_capability_set(self, capabilities: EvaluationCapabilities<'a>) -> Self {
        self.with_function_capabilities(capabilities)
    }

    /// Sets the stable namespace used when deriving function occurrence IDs.
    ///
    /// The default namespace is zero and keeps source-offset identity for
    /// callers that evaluate one expression string repeatedly.  A plan-aware
    /// caller should provide a stable, unique ID for the owning field or
    /// function-definition occurrence so identical expression text in two
    /// fields cannot share stateful built-in state accidentally.  The value
    /// is only an identity namespace; it is never exposed to function output.
    #[must_use]
    pub const fn with_function_instance_namespace(mut self, namespace: u64) -> Self {
        self.function_instance_namespace = namespace;
        self
    }

    /// Returns the resource policy used by this evaluator.
    #[must_use]
    pub const fn limits(&self) -> EvaluationLimits {
        self.limits
    }

    /// Expands one expression without mutating any resolver or global state.
    pub fn evaluate(&self, input: &str) -> Result<String, EvaluationError> {
        if input.len() > self.limits.max_input_bytes {
            return Err(EvaluationError::InputTooLong {
                limit: self.limits.max_input_bytes,
                actual: input.len(),
            });
        }

        let state = Rc::new(RefCell::new(EvaluationState { expansions: 0 }));
        self.evaluate_text(
            input,
            0,
            &state,
            self.limits.max_output_bytes,
            &[],
            contains_reference(input),
        )
    }

    fn evaluate_text(
        &self,
        input: &str,
        depth: usize,
        state: &Rc<RefCell<EvaluationState>>,
        output_limit: usize,
        occurrence_prefix: &[u64],
        remove_escapes: bool,
    ) -> Result<String, EvaluationError> {
        let mut output = String::new();
        let mut index = 0;

        while index < input.len() {
            let Some(character) = input[index..].chars().next() else {
                break;
            };

            if character == '\\' {
                let slash_end = index + character.len_utf8();
                if let Some(next) = input[slash_end..].chars().next()
                    && is_escapable(next)
                {
                    let next_end = slash_end + next.len_utf8();
                    let segment = if remove_escapes {
                        &input[slash_end..next_end]
                    } else {
                        &input[index..next_end]
                    };
                    append_segment(&mut output, segment, output_limit)?;
                    index = next_end;
                    continue;
                }
                append_segment(&mut output, "\\", output_limit)?;
                index = slash_end;
                continue;
            }

            if character == '$' {
                let dollar_end = index + character.len_utf8();
                if input[dollar_end..].starts_with('{') {
                    let end = find_reference_end(input, index, false)?;
                    let reference = &input[index..end];
                    let expanded = self.evaluate_reference(
                        reference,
                        index,
                        depth,
                        state,
                        output_limit,
                        occurrence_prefix,
                    )?;
                    append_segment(&mut output, &expanded, output_limit)?;
                    index = end;
                    continue;
                }
            }

            let end = index + character.len_utf8();
            append_segment(&mut output, &input[index..end], output_limit)?;
            index = end;
        }

        Ok(output)
    }

    fn evaluate_reference(
        &self,
        reference: &str,
        offset: usize,
        depth: usize,
        state: &Rc<RefCell<EvaluationState>>,
        output_limit: usize,
        occurrence_prefix: &[u64],
    ) -> Result<String, EvaluationError> {
        if depth >= self.limits.max_nesting {
            return Err(EvaluationError::NestingLimitExceeded {
                limit: self.limits.max_nesting,
                offset,
            });
        }

        {
            let mut state = state.borrow_mut();
            state.expansions = state.expansions.saturating_add(1);
            if state.expansions > self.limits.max_expansions {
                return Err(EvaluationError::ExpansionLimitExceeded {
                    limit: self.limits.max_expansions,
                    offset,
                });
            }
        }

        let body = &reference[2..reference.len() - 1];
        let parsed = parse_reference_body(body, offset + 2)?;

        if let Some(function) = parsed.function {
            if matches!(
                self.functions.is_defined(function.name.as_str()),
                Some(false)
            ) {
                return Ok(reference.to_owned());
            }

            let mut occurrence_path = occurrence_prefix.to_vec();
            append_occurrence_segment(
                &mut occurrence_path,
                u64::try_from(offset).map_err(|_| {
                    EvaluationError::OccurrencePathLimitExceeded {
                        limit: MAX_FUNCTION_OCCURRENCE_PATH_SEGMENTS,
                        offset,
                    }
                })?,
                offset,
            )?;
            let occurrence = FunctionOccurrence::new(
                self.function_instance_namespace,
                occurrence_path.clone(),
                function.name.as_str(),
            );
            let mut arguments = Vec::with_capacity(function.arguments.len());
            for (argument_index, argument) in function.arguments.into_iter().enumerate() {
                // A function may deliberately shrink an argument (for
                // example, __unescape converts a six-byte Unicode escape to
                // one output byte).  Keep argument expansion bounded by the
                // input ceiling rather than the final-expression ceiling so
                // a small result limit cannot reject valid shrinking calls.
                let argument_limit = self
                    .limits
                    .max_input_bytes
                    .max(self.limits.max_output_bytes)
                    .max(output_limit);
                let mut argument_prefix = occurrence_path.clone();
                append_occurrence_segment(
                    &mut argument_prefix,
                    u64::try_from(argument_index).map_err(|_| {
                        EvaluationError::OccurrencePathLimitExceeded {
                            limit: MAX_FUNCTION_OCCURRENCE_PATH_SEGMENTS,
                            offset,
                        }
                    })?,
                    offset,
                )?;
                arguments.push(self.evaluate_text(
                    &argument,
                    depth + 1,
                    state,
                    argument_limit,
                    &argument_prefix,
                    true,
                )?);
            }
            let nested_evaluator = NestedExpansion {
                evaluator: self,
                state: Rc::clone(state),
                depth,
                occurrence_path: occurrence.path().to_vec(),
            };
            let context = FunctionContext::new(
                self.variables,
                self.properties,
                self.capabilities,
                Some(&nested_evaluator),
                occurrence,
                self.limits.max_output_bytes,
            );

            match self
                .functions
                .resolve_function(function.name.as_str(), &arguments, &context)
            {
                Ok(Some(value)) => Ok(value),
                Ok(None) => Ok(reference.to_owned()),
                Err(source) => Err(EvaluationError::Function {
                    name: function.name,
                    source,
                }),
            }
        } else {
            let name = parsed.variable_name;
            // JMeter's parser permits the no-parentheses form for functions;
            // an unknown no-argument `__name` is represented as a simple
            // variable by the upstream parser.  Unlike variable names, the
            // parser does not trim the no-parentheses lookup key, so `${__V
            // }` is not the same function reference as `${__V}`.  A static
            // variable with the same exact name as a built-in takes
            // precedence over that no-argument function form.
            let variable = self.resolve_variable(name.as_str())?;
            if parsed.bare_name.starts_with("__")
                && !parsed.had_parentheses
                && variable.is_none()
                && !matches!(
                    self.functions.is_defined(parsed.bare_name.as_str()),
                    Some(false)
                )
            {
                let mut occurrence_path = occurrence_prefix.to_vec();
                append_occurrence_segment(
                    &mut occurrence_path,
                    u64::try_from(offset).map_err(|_| {
                        EvaluationError::OccurrencePathLimitExceeded {
                            limit: MAX_FUNCTION_OCCURRENCE_PATH_SEGMENTS,
                            offset,
                        }
                    })?,
                    offset,
                )?;
                let occurrence = FunctionOccurrence::new(
                    self.function_instance_namespace,
                    occurrence_path.clone(),
                    parsed.bare_name.as_str(),
                );
                let nested_evaluator = NestedExpansion {
                    evaluator: self,
                    state: Rc::clone(state),
                    depth,
                    occurrence_path: occurrence.path().to_vec(),
                };
                let context = FunctionContext::new(
                    self.variables,
                    self.properties,
                    self.capabilities,
                    Some(&nested_evaluator),
                    occurrence,
                    self.limits.max_output_bytes,
                );
                match self
                    .functions
                    .resolve_function(parsed.bare_name.as_str(), &[], &context)
                {
                    Ok(Some(value)) => return Ok(value),
                    Ok(None) => {}
                    Err(source) => {
                        return Err(EvaluationError::Function {
                            name: parsed.bare_name,
                            source,
                        });
                    }
                }
            }

            if let Some(value) = variable {
                return Ok(value);
            }

            Ok(reference.to_owned())
        }
    }

    fn resolve_variable(&self, name: &str) -> Result<Option<String>, EvaluationError> {
        match self.capabilities.variable_setter {
            Some(setter) => setter
                .get_variable_checked(name)
                .map(|value| {
                    value.or_else(|| self.variables.resolve_variable(name).map(str::to_owned))
                })
                .map_err(|source| EvaluationError::Function {
                    name: name.to_owned(),
                    source,
                }),
            None => Ok(self.variables.resolve_variable(name).map(str::to_owned)),
        }
    }
}

struct NestedExpansion<'e, 'r> {
    evaluator: &'e Evaluator<'r>,
    state: Rc<RefCell<EvaluationState>>,
    depth: usize,
    occurrence_path: Vec<u64>,
}

impl NestedEvaluator for NestedExpansion<'_, '_> {
    fn evaluate_nested(&self, input: &str) -> Result<String, FunctionError> {
        if input.len() > self.evaluator.limits.max_input_bytes {
            return Err(FunctionError::execution(format!(
                "EXPR_INPUT_LIMIT: input length {} exceeds limit {}",
                input.len(),
                self.evaluator.limits.max_input_bytes
            )));
        }
        let mut occurrence_prefix = self.occurrence_path.clone();
        append_occurrence_segment(
            &mut occurrence_prefix,
            OCCURRENCE_INDIRECTION_MARKER,
            self.depth,
        )
        .map_err(|error| FunctionError::resource_limit(error.to_string()))?;
        self.evaluator
            .evaluate_text(
                input,
                self.depth.saturating_add(1),
                &self.state,
                self.evaluator.limits.max_output_bytes,
                &occurrence_prefix,
                contains_reference(input),
            )
            .map_err(|error| FunctionError::execution(error.to_string()))
    }
}

/// Expands an expression with explicit resolvers and limits.
pub fn expand(
    input: &str,
    variables: &dyn VariableResolver,
    properties: &dyn PropertyResolver,
    functions: &dyn FunctionResolver,
    limits: EvaluationLimits,
) -> Result<String, EvaluationError> {
    Evaluator::with_limits(variables, properties, functions, limits).evaluate(input)
}

#[derive(Default)]
struct EvaluationState {
    expansions: usize,
}

fn append_segment(
    output: &mut String,
    segment: &str,
    output_limit: usize,
) -> Result<(), EvaluationError> {
    let actual = output.len().saturating_add(segment.len());
    if actual > output_limit {
        return Err(EvaluationError::OutputTooLong {
            limit: output_limit,
            actual,
        });
    }
    output.push_str(segment);
    Ok(())
}

fn append_occurrence_segment(
    path: &mut Vec<u64>,
    segment: u64,
    offset: usize,
) -> Result<(), EvaluationError> {
    if path.len() >= MAX_FUNCTION_OCCURRENCE_PATH_SEGMENTS {
        return Err(EvaluationError::OccurrencePathLimitExceeded {
            limit: MAX_FUNCTION_OCCURRENCE_PATH_SEGMENTS,
            offset,
        });
    }
    path.push(segment);
    Ok(())
}

fn occurrence_id(namespace: u64, path: &[u64], name: &str) -> u64 {
    // FNV-1a gives a stable, allocation-free compatibility projection while
    // retaining the exact namespace, path boundaries, and case-sensitive
    // name.  Native stateful maps use FunctionOccurrence itself and therefore
    // do not depend on this intentionally lossy scalar projection.
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in namespace
        .to_le_bytes()
        .into_iter()
        .chain((path.len() as u64).to_le_bytes())
        .chain(path.iter().flat_map(|segment| segment.to_le_bytes()))
        .chain(name.bytes())
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    hash
}

fn is_escapable(character: char) -> bool {
    matches!(character, '$' | ',' | '\\')
}

fn contains_reference(input: &str) -> bool {
    let mut index = 0;
    while index < input.len() {
        let Some(character) = input[index..].chars().next() else {
            break;
        };
        if character == '\\' {
            let slash_end = index + character.len_utf8();
            if let Some(next) = input[slash_end..].chars().next()
                && is_escapable(next)
            {
                index = slash_end + next.len_utf8();
                continue;
            }
        }
        if character == '$' {
            let dollar_end = index + character.len_utf8();
            if input[dollar_end..].starts_with('{') {
                return true;
            }
        }
        index += character.len_utf8();
    }
    false
}

fn is_java_trim_character(character: char) -> bool {
    character <= '\u{20}'
}

/// Java's `Character.isSpaceChar`, used by JMeter's function parser when it
/// scans the close of a function reference.  This is deliberately distinct
/// from `String.trim()`/`Character <= U+0020`, which is used for names.
fn is_java_space_char(character: char) -> bool {
    matches!(
        character,
        '\u{0020}' | '\u{00A0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200A}' | '\u{2028}' | '\u{2029}' | '\u{202F}' | '\u{205F}' | '\u{3000}'
    )
}

fn trim_name(value: &str) -> &str {
    value.trim_matches(is_java_trim_character)
}

fn unescape_name(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        let Some(character) = value[index..].chars().next() else {
            break;
        };
        if character == '\\' {
            let slash_end = index + character.len_utf8();
            if let Some(next) = value[slash_end..].chars().next() {
                result.push(next);
                index = slash_end + next.len_utf8();
                continue;
            }
        }
        result.push(character);
        index += character.len_utf8();
    }
    result
}

fn reference_is_function(input: &str, start: usize) -> bool {
    let mut index = start + 2;
    let name_start = index;
    let mut previous = ' ';
    while index < input.len() {
        let Some(character) = input[index..].chars().next() else {
            break;
        };
        if character == '\\' {
            let slash_end = index + character.len_utf8();
            if let Some(next) = input[slash_end..].chars().next() {
                previous = ' ';
                index = slash_end + next.len_utf8();
                continue;
            }
            break;
        }
        if character == '(' && previous != ' ' {
            let unescaped = unescape_name(&input[name_start..index]);
            return trim_name(&unescaped).starts_with("__");
        }
        if character == '}' || character == '$' {
            return false;
        }
        previous = character;
        index += character.len_utf8();
    }
    false
}

fn find_reference_end(
    input: &str,
    start: usize,
    _nested_call: bool,
) -> Result<usize, EvaluationError> {
    let function_mode = reference_is_function(input, start);
    let mut index = start + 2;
    let mut nested_references = 0usize;
    let mut parenthesis_depth = 0usize;

    while index < input.len() {
        let Some(character) = input[index..].chars().next() else {
            break;
        };
        if character == '\\' {
            let slash_end = index + character.len_utf8();
            if let Some(next) = input[slash_end..].chars().next() {
                index = slash_end + next.len_utf8();
                continue;
            }
            return Err(EvaluationError::UnclosedReference { offset: start });
        }
        if character == '$' && input[index + character.len_utf8()..].starts_with('{') {
            nested_references = nested_references.saturating_add(1);
            index += character.len_utf8() + '{'.len_utf8();
            continue;
        }
        if character == '}' {
            if nested_references > 0 {
                nested_references -= 1;
                index += character.len_utf8();
                continue;
            }
            if !function_mode || parenthesis_depth == 0 {
                return Ok(index + character.len_utf8());
            }
            index += character.len_utf8();
            continue;
        }
        if nested_references == 0 && function_mode {
            if character == '(' {
                parenthesis_depth = parenthesis_depth.saturating_add(1);
            } else if character == ')' && parenthesis_depth > 0 {
                parenthesis_depth -= 1;
            }
        }
        index += character.len_utf8();
    }

    if function_mode && parenthesis_depth > 0 {
        Err(EvaluationError::UnclosedFunction { offset: start + 2 })
    } else {
        Err(EvaluationError::UnclosedReference { offset: start })
    }
}

struct ParsedReference {
    variable_name: String,
    bare_name: String,
    function: Option<ParsedFunction>,
    had_parentheses: bool,
}

struct ParsedFunction {
    name: String,
    arguments: Vec<String>,
}

fn parse_reference_body(body: &str, offset: usize) -> Result<ParsedReference, EvaluationError> {
    let Some(open) = find_top_level_open_paren(body) else {
        let bare_name = unescape_name(body);
        let name = trim_name(&bare_name).to_owned();
        return Ok(ParsedReference {
            variable_name: name,
            bare_name,
            function: None,
            had_parentheses: false,
        });
    };

    let function_name = trim_name(unescape_name(&body[..open]).as_str()).to_owned();
    if !function_name.starts_with("__") {
        return Ok(ParsedReference {
            variable_name: trim_name(unescape_name(body).as_str()).to_owned(),
            bare_name: String::new(),
            function: None,
            had_parentheses: true,
        });
    }

    let Some(close) = find_function_close(body, open + 1) else {
        return Err(EvaluationError::UnclosedFunction { offset });
    };
    if !body[close + 1..].chars().all(is_java_space_char) {
        return Err(EvaluationError::InvalidFunction { offset });
    }

    let arguments = split_arguments(&body[open + 1..close]);
    Ok(ParsedReference {
        variable_name: String::new(),
        bare_name: String::new(),
        function: Some(ParsedFunction {
            name: function_name,
            arguments,
        }),
        had_parentheses: true,
    })
}

fn find_top_level_open_paren(body: &str) -> Option<usize> {
    let mut index = 0;
    let mut previous = ' ';
    while index < body.len() {
        let character = body[index..].chars().next()?;
        if character == '\\' {
            let slash_end = index + character.len_utf8();
            if let Some(next) = body[slash_end..].chars().next() {
                // FunctionParser resets its `previous` marker after an
                // escape.  In particular, `${__name (arg)}` is not a
                // function call, while `${__name\t(arg)}` is (the parser's
                // historical check is specifically against ASCII space).
                previous = ' ';
                index = slash_end + next.len_utf8();
                continue;
            }
            return None;
        }
        if character == '$' && body[index + character.len_utf8()..].starts_with('{') {
            return None;
        }
        if character == '(' && previous != ' ' {
            return Some(index);
        }
        previous = character;
        index += character.len_utf8();
    }
    None
}

fn find_function_close(body: &str, start: usize) -> Option<usize> {
    let mut index = start;
    let mut nested_references = 0usize;
    let mut parenthesis_depth = 0usize;
    while index < body.len() {
        let character = body[index..].chars().next()?;
        if character == '\\' {
            let slash_end = index + character.len_utf8();
            if let Some(next) = body[slash_end..].chars().next() {
                index = slash_end + next.len_utf8();
                continue;
            }
            return None;
        }
        if character == '$' && body[index + character.len_utf8()..].starts_with('{') {
            nested_references = nested_references.saturating_add(1);
            index += character.len_utf8() + '{'.len_utf8();
            continue;
        }
        if nested_references > 0 {
            if character == '}' {
                nested_references -= 1;
            }
            index += character.len_utf8();
            continue;
        }
        if character == '(' {
            parenthesis_depth = parenthesis_depth.saturating_add(1);
        } else if character == ')' {
            if parenthesis_depth == 0 {
                return Some(index);
            }
            parenthesis_depth -= 1;
        }
        index += character.len_utf8();
    }
    None
}

fn split_arguments(arguments: &str) -> Vec<String> {
    if arguments.is_empty() {
        return Vec::new();
    }

    let mut result = Vec::new();
    let mut start = 0;
    let mut index = 0;
    let mut nested_references = 0usize;
    while index < arguments.len() {
        let Some(character) = arguments[index..].chars().next() else {
            break;
        };
        if character == '\\' {
            let slash_end = index + character.len_utf8();
            if let Some(next) = arguments[slash_end..].chars().next() {
                index = slash_end + next.len_utf8();
                continue;
            }
            index += character.len_utf8();
            continue;
        }
        if character == '$' && arguments[index + character.len_utf8()..].starts_with('{') {
            nested_references = nested_references.saturating_add(1);
            index += character.len_utf8() + '{'.len_utf8();
            continue;
        }
        if nested_references > 0 {
            if character == '}' {
                nested_references -= 1;
            }
            index += character.len_utf8();
            continue;
        }
        // JMeter only treats commas inside a nested `${...}` reference as
        // protected.  Ordinary parentheses are just function-argument text:
        // `${__javaScript(Math.max(2,5))}` is parsed as two arguments unless
        // the comma is escaped.  Parentheses still participate in locating a
        // function's closing `)` in `find_function_close`, but they must not
        // change comma splitting here.
        if character == ',' {
            result.push(arguments[start..index].to_owned());
            start = index + character.len_utf8();
        }
        index += character.len_utf8();
    }
    result.push(arguments[start..].to_owned());
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    #[derive(Default)]
    struct FakeFunctions;

    impl FunctionResolver for FakeFunctions {
        fn resolve_function(
            &self,
            name: &str,
            arguments: &[String],
            context: &FunctionContext<'_>,
        ) -> Result<Option<String>, FunctionError> {
            match name {
                "__join" => Ok(Some(arguments.join("|"))),
                "__echo" => Ok(Some(arguments.first().cloned().unwrap_or_default())),
                "__count" => Ok(Some(arguments.len().to_string())),
                "__property" => Ok(context
                    .property(arguments.first().map_or("", String::as_str))
                    .map(str::to_owned)),
                "__var" => Ok(context
                    .variable(arguments.first().map_or("", String::as_str))
                    .map(str::to_owned)),
                "__error" => Err(FunctionError::invalid_arguments("fake rejection")),
                _ => Ok(None),
            }
        }
    }

    struct UnknownAwareFunctions {
        calls: AtomicUsize,
    }

    impl FunctionResolver for UnknownAwareFunctions {
        fn resolve_function(
            &self,
            _name: &str,
            _arguments: &[String],
            _context: &FunctionContext<'_>,
        ) -> Result<Option<String>, FunctionError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(None)
        }

        fn is_defined(&self, _name: &str) -> Option<bool> {
            Some(false)
        }
    }

    fn evaluator<'a>(
        variables: &'a HashMap<String, String>,
        properties: &'a HashMap<String, String>,
    ) -> Evaluator<'a> {
        Evaluator::new(variables, properties, &FakeFunctions)
    }

    #[test]
    fn table_driven_literals_variables_functions_and_undefined_values() {
        let variables = HashMap::from([
            ("NAME".to_owned(), "Ada".to_owned()),
            ("UNICODE".to_owned(), "東京🦀".to_owned()),
            ("__echo".to_owned(), "static".to_owned()),
            ("__unknown".to_owned(), "variable-fallback".to_owned()),
        ]);
        let properties = HashMap::from([("region".to_owned(), "test".to_owned())]);
        let cases = [
            ("literal", "literal"),
            ("hello ${NAME}", "hello Ada"),
            ("${ NAME }/${UNICODE}", "Ada/東京🦀"),
            ("${MISSING}", "${MISSING}"),
            ("${__missing(x)}", "${__missing(x)}"),
            ("${__echo(value)}", "value"),
            ("${__count()}", "0"),
            ("${__count}", "0"),
            ("${__echo}", "static"),
            ("${__unknown}", "variable-fallback"),
            ("${__property(region)}", "test"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                evaluator(&variables, &properties).evaluate(input),
                Ok(expected.to_owned()),
                "{input}"
            );
        }
    }

    #[test]
    fn unknown_resolver_contract_preserves_arguments_without_side_effects() {
        let variables = HashMap::<String, String>::new();
        let properties = HashMap::<String, String>::new();
        let property_store = MapPropertyCapability::default();
        let functions = UnknownAwareFunctions {
            calls: AtomicUsize::new(0),
        };
        let evaluator = Evaluator::with_capabilities(
            &variables,
            &properties,
            &functions,
            EvaluationCapabilities::new().with_property_setter(&property_store),
        );
        let source = "${__missing(${__setProperty(side,effect)})}";
        assert_eq!(evaluator.evaluate(source), Ok(source.to_owned()));
        assert_eq!(functions.calls.load(Ordering::Relaxed), 0);
        assert_eq!(property_store.snapshot(), Ok(BTreeMap::new()));
    }

    #[test]
    fn names_are_case_sensitive_and_variable_names_trim_java_spaces() {
        let variables = HashMap::from([("NAME".to_owned(), "yes".to_owned())]);
        let properties: HashMap<String, String> = HashMap::new();
        let eval = evaluator(&variables, &properties);
        assert_eq!(eval.evaluate("${\tNAME\n}"), Ok("yes".to_owned()));
        assert_eq!(eval.evaluate("${name}"), Ok("${name}".to_owned()));
        assert_eq!(eval.evaluate("${__ECHO(x)}"), Ok("${__ECHO(x)}".to_owned()));
    }

    #[test]
    fn an_ascii_space_before_function_parenthesis_keeps_the_reference_undefined() {
        let variables: HashMap<String, String> = HashMap::new();
        let properties: HashMap<String, String> = HashMap::new();
        let eval = evaluator(&variables, &properties);

        // FunctionParser's recognition rule is `previous != ' '`.  The
        // function name itself is trimmed once a call is recognized, but an
        // ASCII space before `(` prevents recognition altogether.
        assert_eq!(
            eval.evaluate("${__echo (value)}"),
            Ok("${__echo (value)}".to_owned())
        );
        assert_eq!(
            eval.evaluate("${__echo (value}"),
            Ok("${__echo (value}".to_owned())
        );
        assert_eq!(eval.evaluate("${__echo\t(value)}"), Ok("value".to_owned()));
        assert_eq!(eval.evaluate("${__echo }"), Ok("${__echo }".to_owned()));
    }

    #[test]
    fn function_close_uses_java_space_char_but_names_use_java_trim() {
        let variables = HashMap::new();
        let properties: HashMap<String, String> = HashMap::new();
        let eval = evaluator(&variables, &properties);
        assert_eq!(
            eval.evaluate("${__echo(value)\u{00A0}}"),
            Ok("value".to_owned())
        );
        assert_eq!(
            eval.evaluate("${\u{00A0}NAME\u{00A0}}"),
            Ok("${\u{00A0}NAME\u{00A0}}".to_owned())
        );
        assert_eq!(eval.evaluate("${\tNAME\n}"), Ok("${\tNAME\n}".to_owned()));
    }

    #[test]
    fn escaping_is_removed_only_for_referenced_expressions() {
        let variables = HashMap::from([("NAME".to_owned(), "Ada".to_owned())]);
        let properties: HashMap<String, String> = HashMap::new();
        let eval = evaluator(&variables, &properties);
        assert_eq!(
            eval.evaluate(r"C:\\test\${NAME}"),
            Ok(r"C:\\test\${NAME}".to_owned())
        );
        assert_eq!(
            eval.evaluate(r"C:\\test\${NAME} ${NAME}"),
            Ok(r"C:\test${NAME} Ada".to_owned())
        );
        assert_eq!(eval.evaluate(r"${__join(a\,b,c)}"), Ok("a,b|c".to_owned()));
        assert_eq!(eval.evaluate(r"slash\q"), Ok(r"slash\q".to_owned()));
        assert_eq!(eval.evaluate(r"backslash\\"), Ok(r"backslash\\".to_owned()));
        assert_eq!(
            eval.evaluate(r"literal\,comma"),
            Ok(r"literal\,comma".to_owned())
        );
        assert_eq!(
            eval.evaluate(r"literal\${NAME}"),
            Ok(r"literal\${NAME}".to_owned())
        );
    }

    #[test]
    fn nested_functions_and_arguments_split_at_top_level_only() {
        let variables = HashMap::from([("NAME".to_owned(), "Ada".to_owned())]);
        let properties: HashMap<String, String> = HashMap::new();
        let eval = evaluator(&variables, &properties);
        assert_eq!(
            eval.evaluate(r"${__join(${__echo(a,b)},${NAME},c(d\,e))}"),
            Ok("a|Ada|c(d,e)".to_owned())
        );
        assert_eq!(eval.evaluate("${__join(,x,)}"), Ok("|x|".to_owned()));
        assert_eq!(eval.evaluate("${__join()}"), Ok(String::new()));
    }

    #[test]
    fn commas_inside_nested_references_are_protected_but_parentheses_are_not() {
        let variables: HashMap<String, String> = HashMap::new();
        let properties: HashMap<String, String> = HashMap::new();
        let eval = evaluator(&variables, &properties);

        // A nested function/reference is parsed as one argument, while the
        // comma in ordinary function text is a delimiter.  JMeter therefore
        // requires the comma in Math.max to be escaped.
        assert_eq!(
            eval.evaluate(r"${__join(Math.max(2,5),tail)}"),
            Ok("Math.max(2|5)|tail".to_owned())
        );
        assert_eq!(
            eval.evaluate(r"${__join(Math.max(2\,5),tail)}"),
            Ok("Math.max(2,5)|tail".to_owned())
        );
        assert_eq!(
            eval.evaluate(r"${__join(${__join(a,b)},tail)}"),
            Ok("a|b|tail".to_owned())
        );
    }

    #[test]
    fn function_context_is_read_only_and_supports_properties_and_variables() {
        let variables = HashMap::from([("KEY".to_owned(), "variable-value".to_owned())]);
        let properties = HashMap::from([("KEY".to_owned(), "property-value".to_owned())]);
        let eval = evaluator(&variables, &properties);
        assert_eq!(
            eval.evaluate("${__var(KEY)}"),
            Ok("variable-value".to_owned())
        );
        assert_eq!(
            eval.evaluate("${__property(KEY)}"),
            Ok("property-value".to_owned())
        );
    }

    #[test]
    fn malformed_inputs_return_typed_errors() {
        let variables = HashMap::new();
        let properties: HashMap<String, String> = HashMap::new();
        let eval = evaluator(&variables, &properties);
        assert_eq!(
            eval.evaluate("prefix ${NAME"),
            Err(EvaluationError::UnclosedReference { offset: 7 })
        );
        assert_eq!(
            eval.evaluate("${__join(value"),
            Err(EvaluationError::UnclosedFunction { offset: 2 })
        );
        assert_eq!(
            eval.evaluate("${__join(value) trailing}"),
            Err(EvaluationError::InvalidFunction { offset: 2 })
        );
    }

    #[test]
    fn limits_bound_input_nesting_expansion_and_output() {
        let variables = HashMap::from([("X".to_owned(), "0123456789".to_owned())]);
        let properties: HashMap<String, String> = HashMap::new();
        let tiny_input = Evaluator::with_limits(
            &variables,
            &properties,
            &FakeFunctions,
            EvaluationLimits::new(3, 10, 10, 100),
        );
        assert_eq!(
            tiny_input.evaluate("abcd"),
            Err(EvaluationError::InputTooLong {
                limit: 3,
                actual: 4
            })
        );

        let tiny_nesting = Evaluator::with_limits(
            &variables,
            &properties,
            &FakeFunctions,
            EvaluationLimits::new(100, 1, 10, 100),
        );
        assert_eq!(
            tiny_nesting.evaluate("${__echo(${X})}"),
            Err(EvaluationError::NestingLimitExceeded {
                limit: 1,
                offset: 0
            })
        );

        let tiny_expansions = Evaluator::with_limits(
            &variables,
            &properties,
            &FakeFunctions,
            EvaluationLimits::new(100, 10, 1, 100),
        );
        assert_eq!(
            tiny_expansions.evaluate("${X}${X}"),
            Err(EvaluationError::ExpansionLimitExceeded {
                limit: 1,
                offset: 4
            })
        );

        let tiny_output = Evaluator::with_limits(
            &variables,
            &properties,
            &FakeFunctions,
            EvaluationLimits::new(100, 10, 10, 5),
        );
        assert_eq!(
            tiny_output.evaluate("${X}"),
            Err(EvaluationError::OutputTooLong {
                limit: 5,
                actual: 10
            })
        );

        let nested_output = Evaluator::with_limits(
            &variables,
            &properties,
            &FakeFunctions,
            EvaluationLimits::new(100, 10, 10, 3),
        );
        assert_eq!(
            nested_output.evaluate("${__echo(abc)}"),
            Ok("abc".to_owned())
        );

        let nested_variables =
            HashMap::from([(String::from("X"), String::from("abcdefghijklmnopqrstu"))]);
        let nested_properties = HashMap::<String, String>::new();
        let nested_functions = crate::builtins::BuiltinFunctions::new();
        let nested_input = Evaluator::with_limits(
            &nested_variables,
            &nested_properties,
            &nested_functions,
            EvaluationLimits::new(20, 10, 10, 100),
        );
        assert!(matches!(
            nested_input.evaluate("${__evalVar(X)}"),
            Err(EvaluationError::Function {
                source: FunctionError::Execution(message),
                ..
            }) if message.contains("EXPR_INPUT_LIMIT")
        ));

        let nested_output_variables = HashMap::from([(String::from("X"), String::from("1234"))]);
        let nested_output = Evaluator::with_limits(
            &nested_output_variables,
            &nested_properties,
            &nested_functions,
            EvaluationLimits::new(100, 10, 10, 3),
        );
        assert!(matches!(
            nested_output.evaluate("${__evalVar(X)}"),
            Err(EvaluationError::Function {
                source: FunctionError::Execution(message),
                ..
            }) if message.contains("EXPR_OUTPUT_LIMIT")
        ));
    }

    #[test]
    fn function_errors_have_stable_codes() {
        let variables = HashMap::new();
        let properties: HashMap<String, String> = HashMap::new();
        let error = evaluator(&variables, &properties).evaluate("${__error()}");
        assert_eq!(
            error,
            Err(EvaluationError::Function {
                name: "__error".to_owned(),
                source: FunctionError::InvalidArguments("fake rejection".to_owned()),
            })
        );
        assert_eq!(
            error.err().map(|value| value.code()),
            Some(ErrorCode::FunctionError)
        );
        assert_eq!(FunctionError::stop_thread("eof").code(), "FUNC_STOP_THREAD");
        assert_eq!(FunctionError::poisoned("lock").code(), "FUNC_POISONED");
        assert!(matches!(
            FunctionError::poisoned("lock"),
            FunctionError::Poisoned(message) if message == "lock"
        ));
    }

    #[test]
    fn deterministic_generated_inputs_do_not_change_results() {
        let variables = HashMap::from([("X".to_owned(), "x".to_owned())]);
        let properties: HashMap<String, String> = HashMap::new();
        let eval = evaluator(&variables, &properties);
        let alphabet = ['a', 'Z', '0', '$', '{', '}', '\\', ',', '(', ')', '🦀'];
        let mut seed = 0x5eed_u64;
        for _ in 0..512 {
            let length = (next_random(&mut seed) % 48) as usize;
            let mut input = String::new();
            for _ in 0..length {
                input.push(alphabet[(next_random(&mut seed) as usize) % alphabet.len()]);
            }
            let first = eval.evaluate(&input);
            let second = eval.evaluate(&input);
            assert_eq!(first, second, "generated input: {input:?}");
        }
    }

    #[test]
    fn evaluator_is_safe_to_share_between_threads() {
        let variables = Arc::new(HashMap::from([("X".to_owned(), "value".to_owned())]));
        let properties = Arc::new(HashMap::<String, String>::new());
        let functions = Arc::new(FakeFunctions);
        let evaluator = Arc::new(Evaluator::new(&*variables, &*properties, &*functions));
        thread::scope(|scope| {
            let mut workers = Vec::new();
            for _ in 0..8 {
                let evaluator = Arc::clone(&evaluator);
                workers.push(scope.spawn(move || {
                    for _ in 0..100 {
                        assert_eq!(evaluator.evaluate("${X}"), Ok("value".to_owned()));
                    }
                }));
            }
            for worker in workers {
                assert!(worker.join().is_ok());
            }
        });
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn field_lifecycle_and_cache_policy_are_explicit() {
        let field = ExpressionField::new(
            ExpressionFieldId::new(7),
            "Arguments.value",
            "${__echo(value)}",
            ExpressionCachePolicy::PerIteration,
        )
        .expect("field source is valid");
        assert_eq!(
            field.state(),
            Ok(ExpressionFieldState::RawBeforeRunningVersion)
        );
        assert_eq!(field.occurrences().len(), 1);
        let escaped = ExpressionField::new(
            ExpressionFieldId::new(8),
            "Arguments.escaped",
            r"\${__echo(raw)} ${__echo(evaluated)}",
            ExpressionCachePolicy::Disabled,
        )
        .expect("escaped field source is valid");
        assert_eq!(escaped.occurrences().len(), 1);
        let calls = std::cell::Cell::new(0usize);
        assert_eq!(
            field.read_with(Some(IterationIdentity::new(0)), |_| {
                calls.set(calls.get() + 1);
                Ok("raw".to_owned())
            }),
            Ok("${__echo(value)}".to_owned())
        );
        field.start_running_version().expect("raw -> running");
        assert_eq!(
            field.read_with(None, |_| {
                calls.set(calls.get() + 1);
                Ok("before-sampling".to_owned())
            }),
            Ok("before-sampling".to_owned())
        );
        field
            .start_sampling(IterationIdentity::for_user(1, 2, 0))
            .expect("running -> sampling");
        assert_eq!(
            field.read_with(Some(IterationIdentity::for_user(1, 2, 0)), |_| {
                calls.set(calls.get() + 1);
                Ok("cached".to_owned())
            }),
            Ok("cached".to_owned())
        );
        assert_eq!(
            field.read_with(Some(IterationIdentity::for_user(1, 2, 0)), |_| {
                calls.set(calls.get() + 1);
                Ok("changed".to_owned())
            }),
            Ok("cached".to_owned())
        );
        assert_eq!(calls.get(), 2);
        assert!(matches!(
            field.read_with(Some(IterationIdentity::new(0)), |_| Ok("bad".to_owned())),
            Err(ExpressionFieldError::IterationMismatch { .. })
        ));
        field.finish().expect("sampling -> finished");
        assert_eq!(
            field.read_with(None, |_| Ok("not-read".to_owned())),
            Err(ExpressionFieldError::Finished)
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn session_overlay_is_ordered_and_duplicate_projection_is_last_wins() {
        let identity =
            ExpressionSessionIdentity::for_user(1, 2, 3, ExpressionFieldId::new(4), "preprocessor");
        let mut session = ExpressionSession::new(
            identity,
            BTreeMap::from([(String::from("A"), String::from("base"))]),
            BTreeMap::new(),
            ExpressionSessionLimits::default(),
        )
        .expect("session is within bounds");
        assert_eq!(session.resolve_variable("A"), Some("base"));
        session.set_variable("A", "first").expect("first write");
        assert_eq!(session.resolve_variable("A"), Some("first"));
        session
            .set_variable("A", "second")
            .expect("duplicate write");
        assert_eq!(session.resolve_variable("A"), Some("second"));
        assert_eq!(session.variable_overlay().len(), 2);
        assert_eq!(
            session.final_variables().get("A").map(String::as_str),
            Some("second")
        );
        assert_eq!(session.journal().len(), 2);
        assert!(matches!(
            session.journal().entries()[0].effect(),
            ExpressionEffect::Variable {
                previous: Some(previous),
                ..
            } if previous == "base"
        ));
        assert!(matches!(
            session.journal().entries()[1].effect(),
            ExpressionEffect::Variable {
                previous: Some(previous),
                ..
            } if previous == "first"
        ));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn session_journal_is_bounded_and_occurrences_are_not_refreshed() {
        let identity =
            ExpressionSessionIdentity::new(1, 2, 3, 4, ExpressionFieldId::new(5), "sampler");
        let limits = ExpressionSessionLimits::new(64, 64, 4, 8, 8, 1, 1_024, 64);
        let mut session =
            ExpressionSession::new(identity, BTreeMap::new(), BTreeMap::new(), limits)
                .expect("session is within bounds");
        let occurrence = FunctionOccurrence::new(11, vec![7, 2], "__counter");
        session
            .record_occurrence(occurrence.clone())
            .expect("first occurrence");
        session
            .record_occurrence(occurrence.clone())
            .expect("duplicate occurrence remains an ordered observation");
        assert_eq!(
            session.occurrences(),
            &[occurrence.clone(), occurrence.clone()]
        );
        session
            .journal_random(occurrence.clone(), 42)
            .expect("first journal entry");
        assert!(matches!(
            session.record_effect(
                EffectClass::Pure,
                ExpressionEffect::External {
                    class: EffectClass::TransactionalExternal,
                    operation: "mismatch".to_owned(),
                },
            ),
            Err(SessionError::InvalidOutcome(message))
                if message == "effect class does not match effect payload"
        ));
        assert!(matches!(
            session.journal_random(occurrence, 43),
            Err(SessionError::JournalLimit { limit: 1 })
        ));
        assert_eq!(session.journal().len(), 1);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn session_limits_outcomes_generation_and_authority_poison_are_typed() {
        let limits = ExpressionSessionLimits::new(64, 64, 2, 2, 1, 1, 256, 8);
        let identity =
            ExpressionSessionIdentity::new(1, 1, 1, 1, ExpressionFieldId::new(1), "phase");
        let mut bounded =
            ExpressionSession::new(identity.clone(), BTreeMap::new(), BTreeMap::new(), limits)
                .expect("bounded session");
        bounded.set_variable("A", "1").expect("first mutation");
        assert!(matches!(
            bounded.set_variable("B", "2"),
            Err(SessionError::MutationLimit { limit: 1 })
        ));
        let committed = bounded.commit("value").expect("commit");
        assert!(matches!(committed, ExpressionSessionOutcome::Commit { .. }));

        let mut diagnostic = ExpressionSession::new(
            identity.clone(),
            BTreeMap::new(),
            BTreeMap::new(),
            ExpressionSessionLimits::default(),
        )
        .expect("diagnostic session");
        let diagnostic_outcome = diagnostic
            .commit_with_diagnostic("partial", "warn")
            .expect("diagnostic commit");
        assert!(matches!(
            diagnostic_outcome,
            ExpressionSessionOutcome::CommitWithDiagnostic { .. }
        ));

        let mut aborted = ExpressionSession::new(
            identity.clone(),
            BTreeMap::new(),
            BTreeMap::new(),
            ExpressionSessionLimits::default(),
        )
        .expect("abort session");
        aborted.set_variable("A", "1").expect("journal prefix");
        assert!(matches!(
            aborted.abort_before_effects(SessionError::InvalidOutcome("known failure".to_owned())),
            Err(SessionError::InvalidOutcome(message))
                if message == "abort-before-effects requires an empty effect journal"
        ));
        let mut clean_abort = ExpressionSession::new(
            identity.clone(),
            BTreeMap::new(),
            BTreeMap::new(),
            ExpressionSessionLimits::default(),
        )
        .expect("clean abort session");
        assert!(matches!(
            clean_abort
                .abort_before_effects(SessionError::InvalidOutcome("known failure".to_owned())),
            Ok(ExpressionSessionOutcome::AbortBeforeEffects { .. })
        ));

        let runtime = ExpressionRuntime::new();
        let mut stale = runtime
            .begin_session(
                identity.clone(),
                BTreeMap::new(),
                BTreeMap::new(),
                ExpressionSessionLimits::default(),
            )
            .expect("runtime session");
        runtime.advance_generation().expect("generation advance");
        assert!(matches!(
            stale.commit("stale"),
            Err(SessionError::StaleGeneration { .. })
        ));

        let mut uncertain = runtime
            .begin_session(
                identity,
                BTreeMap::new(),
                BTreeMap::new(),
                ExpressionSessionLimits::default(),
            )
            .expect("second runtime session");
        let outcome = uncertain
            .uncertain_after_external_effect(SessionError::InvalidOutcome(
                "worker ambiguous".to_owned(),
            ))
            .expect("uncertain outcome");
        assert!(matches!(
            outcome,
            ExpressionSessionOutcome::UncertainAfterExternalEffect { .. }
        ));
        assert!(runtime.is_poisoned().expect("poison state read"));
        assert!(matches!(
            runtime.begin_session(
                ExpressionSessionIdentity::new(1, 1, 1, 1, ExpressionFieldId::new(1), "phase"),
                BTreeMap::new(),
                BTreeMap::new(),
                ExpressionSessionLimits::default(),
            ),
            Err(SessionError::Poisoned(_))
        ));
    }

    #[test]
    fn shared_registry_handle_and_fresh_registry_are_distinct() {
        struct Execution {
            iteration: u64,
        }
        impl ExecutionContext for Execution {
            fn thread_num(&self) -> Option<u32> {
                Some(1)
            }
            fn lifecycle_id(&self) -> Option<u64> {
                Some(1)
            }
            fn iteration_id(&self) -> Option<u64> {
                Some(self.iteration)
            }
        }
        let execution = Execution { iteration: 0 };
        let capabilities = EvaluationCapabilities::new().with_execution_context(&execution);
        let variables = BTreeMap::<String, String>::new();
        let properties = BTreeMap::<String, String>::new();
        let shared = SharedBuiltinFunctions::new();
        let shared_clone = shared.clone();
        assert_eq!(shared.strong_count(), 2);
        let first = Evaluator::with_capabilities(&variables, &properties, &shared, capabilities);
        assert_eq!(first.evaluate("${__counter(false)}"), Ok("1".to_owned()));
        let next_execution = Execution {
            // A new iteration is required because JMeter's global counter
            // caches one value per occurrence and complete iteration.
            iteration: 1,
        };
        let second =
            Evaluator::with_capabilities(&variables, &properties, &shared_clone, capabilities);
        assert_eq!(second.evaluate("${__counter(false)}"), Ok("1".to_owned()));
        let second_iteration_capabilities =
            EvaluationCapabilities::new().with_execution_context(&next_execution);
        let second_iteration = Evaluator::with_capabilities(
            &variables,
            &properties,
            &shared_clone,
            second_iteration_capabilities,
        );
        assert_eq!(
            second_iteration.evaluate("${__counter(false)}"),
            Ok("2".to_owned())
        );
        let fresh = BuiltinFunctions::new();
        let fresh_clone = fresh.fresh_clone();
        let third = Evaluator::with_capabilities(
            &variables,
            &properties,
            &fresh_clone,
            second_iteration_capabilities,
        );
        assert_eq!(third.evaluate("${__counter(false)}"), Ok("1".to_owned()));
    }

    fn next_random(seed: &mut u64) -> u64 {
        *seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        *seed
    }
}
