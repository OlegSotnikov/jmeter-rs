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
//! unescaped, top-level commas.  A backslash before `$`, `,`, or `\` escapes
//! that character when the containing expression has a reference; otherwise
//! it remains literal.  Undefined variables and functions are emitted
//! verbatim, as required by the JMeter 5.6.3 behavior map.  Malformed
//! references and resource-limit violations are explicit errors rather than
//! silent fallbacks.

use std::borrow::Borrow;
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::fmt;
use std::hash::{BuildHasher, Hash};
use std::rc::Rc;

mod builtins;

pub use builtins::{
    BuiltinFunctions, BuiltinRegistry, EXTENDED_FUNCTION_NAMES, FunctionSupport,
    KNOWN_FUNCTION_NAMES, MapPropertyCapability, MapVariableCapability, StaticTestPlanName,
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

    /// Returns a stable code for this function failure.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidArguments(_) => "FUNC_INVALID_ARGUMENTS",
            Self::Execution(_) => "FUNC_EXECUTION",
            Self::Unsupported(_) => "FUNC_UNSUPPORTED",
            Self::StopThread(_) => "FUNC_STOP_THREAD",
            Self::ResourceLimit(_) => "FUNC_RESOURCE_LIMIT",
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

    /// Reads a value owned by the capability, when it also acts as the
    /// mutable variable store.  Setter-only capabilities may return `None`.
    #[must_use]
    fn get_variable(&self, _name: &str) -> Option<String> {
        None
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
    fn new(namespace: u64, path: Vec<u64>, function_name: &str) -> Self {
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

    /// Stores a variable through the explicitly supplied mutable capability.
    pub fn set_variable(&self, name: &str, value: &str) -> Result<(), FunctionError> {
        self.capabilities
            .variable_setter
            .ok_or_else(|| {
                FunctionError::unsupported("variable mutation capability is unavailable")
            })?
            .set_variable(name, value)
    }

    /// Returns whether variable mutation was explicitly supplied.
    #[must_use]
    pub fn has_variable_setter(&self) -> bool {
        self.capabilities.variable_setter.is_some()
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
            // variable by the upstream parser.  A static variable with the
            // same name as a built-in takes precedence over that no-argument
            // function form.
            let variable = self.resolve_variable(name.as_str());
            if name.starts_with("__")
                && !parsed.had_parentheses
                && variable.is_none()
                && !matches!(self.functions.is_defined(name.as_str()), Some(false))
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
                    name.as_str(),
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
                    .resolve_function(name.as_str(), &[], &context)
                {
                    Ok(Some(value)) => return Ok(value),
                    Ok(None) => {}
                    Err(source) => {
                        return Err(EvaluationError::Function { name, source });
                    }
                }
            }

            if let Some(value) = variable {
                return Ok(value);
            }

            Ok(reference.to_owned())
        }
    }

    fn resolve_variable(&self, name: &str) -> Option<String> {
        self.capabilities
            .variable_setter
            .and_then(|setter| setter.get_variable(name))
            .or_else(|| self.variables.resolve_variable(name).map(str::to_owned))
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
            break;
        }
        if character == '(' {
            let unescaped = unescape_name(&input[name_start..index]);
            let name = trim_name(&unescaped);
            return name.starts_with("__");
        }
        if character == '}' || character == '$' {
            return false;
        }
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
    function: Option<ParsedFunction>,
    had_parentheses: bool,
}

struct ParsedFunction {
    name: String,
    arguments: Vec<String>,
}

fn parse_reference_body(body: &str, offset: usize) -> Result<ParsedReference, EvaluationError> {
    let Some(open) = find_top_level_open_paren(body) else {
        let name = trim_name(unescape_name(body).as_str()).to_owned();
        return Ok(ParsedReference {
            variable_name: name,
            function: None,
            had_parentheses: false,
        });
    };

    let function_name = trim_name(unescape_name(&body[..open]).as_str()).to_owned();
    if !function_name.starts_with("__") {
        return Ok(ParsedReference {
            variable_name: trim_name(unescape_name(body).as_str()).to_owned(),
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
        function: Some(ParsedFunction {
            name: function_name,
            arguments,
        }),
        had_parentheses: true,
    })
}

fn find_top_level_open_paren(body: &str) -> Option<usize> {
    let mut index = 0;
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
            return None;
        }
        if character == '(' {
            return Some(index);
        }
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
    let mut parenthesis_depth = 0usize;
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
        match character {
            '(' => parenthesis_depth = parenthesis_depth.saturating_add(1),
            ')' if parenthesis_depth > 0 => parenthesis_depth -= 1,
            ',' if parenthesis_depth == 0 => {
                result.push(arguments[start..index].to_owned());
                start = index + character.len_utf8();
            }
            _ => {}
        }
        index += character.len_utf8();
    }
    result.push(arguments[start..].to_owned());
    result
}

#[cfg(test)]
mod tests {
    use super::*;
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
            eval.evaluate("${__join(${__echo(a,b)},${NAME},c(d,e))}"),
            Ok("a|Ada|c(d,e)".to_owned())
        );
        assert_eq!(eval.evaluate("${__join(,x,)}"), Ok("|x|".to_owned()));
        assert_eq!(eval.evaluate("${__join()}"), Ok(String::new()));
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

    fn next_random(seed: &mut u64) -> u64 {
        *seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        *seed
    }
}
