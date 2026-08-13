//! Native, capability-bounded JMeter function implementations.
//!
//! The registry is deliberately explicit.  A name in the 5.6.3 built-in
//! vocabulary is either implemented below or returns
//! [`FunctionError::Unsupported`]; a name outside that vocabulary returns
//! `Ok(None)` so the evaluator preserves the original expression.  This
//! distinction is important when a plan contains a plugin function that is
//! not installed in the active capability set.

use super::{
    ClockSource, EffectClass, EvaluationCapabilities, ExecutionContext, FileCapability,
    FunctionContext, FunctionError, FunctionOccurrence, FunctionResolver, HostResolver,
    IterationIdentity, LogSink, PropertySetter, RandomSource, ResponseExtractor, ScriptCapability,
    TestPlanNameResolver, VariableSetter,
};
use std::collections::BTreeMap;
use std::fmt;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

type CounterScopeKey = (bool, String, u64, u32, FunctionOccurrence);
type CounterCacheKey = (CounterScopeKey, IterationIdentity);

#[derive(Default)]
struct CounterState {
    next_values: BTreeMap<CounterScopeKey, i32>,
    cached_values: BTreeMap<CounterCacheKey, i32>,
}

impl CounterState {
    const fn new() -> Self {
        Self {
            next_values: BTreeMap::new(),
            cached_values: BTreeMap::new(),
        }
    }
}

/// Bound stale lifecycle/occurrence state held by one shared registry.
const MAX_COUNTER_ENTRIES: usize = 16_384;
/// Maximum UTF-8 bytes retained from one thread-group identity in counter
/// scope state.
pub const MAX_COUNTER_GROUP_BYTES: usize = 1_024;
const MAX_RANDOM_VALUES: usize = 65_536;
const MAX_RANDOM_REJECTIONS: usize = 1_024;
const MAX_VARIABLE_UPDATES: usize = 65_536;

/// Exact, case-sensitive JMeter 5.6.3 built-in function names.
///
/// The list intentionally contains the 49 names in the JMeter 5.6.3
/// compatibility surface.  Functions from the JMeter Plugins project are not
/// part of this registry and therefore remain unresolved when no plugin
/// resolver is installed.
pub const KNOWN_FUNCTION_NAMES: &[&str] = &[
    "__BeanShell",
    "__CSVRead",
    "__FileToString",
    "__P",
    "__Random",
    "__RandomDate",
    "__RandomFromMultipleVars",
    "__RandomString",
    "__StringFromFile",
    "__StringToFile",
    "__TestPlanName",
    "__UUID",
    "__V",
    "__XPath",
    "__changeCase",
    "__char",
    "__counter",
    "__dateTimeConvert",
    "__digest",
    "__escapeHtml",
    "__escapeOroRegexpChars",
    "__escapeXml",
    "__eval",
    "__evalVar",
    "__groovy",
    "__intSum",
    "__isPropDefined",
    "__isVarDefined",
    "__javaScript",
    "__jexl2",
    "__jexl3",
    "__log",
    "__logn",
    "__longSum",
    "__machineIP",
    "__machineName",
    "__property",
    "__regexFunction",
    "__samplerName",
    "__setProperty",
    "__split",
    "__threadGroupName",
    "__threadNum",
    "__time",
    "__timeShift",
    "__unescape",
    "__unescapeHtml",
    "__urldecode",
    "__urlencode",
];

/// Former extension names retained as an empty compatibility slice.
///
/// The native registry does not implement JMeter Plugins functions. Keeping
/// this public accessor empty avoids changing the API shape for callers that
/// used it to enumerate optional names while ensuring those names are treated
/// as unknown by the native resolver.
pub const EXTENDED_FUNCTION_NAMES: &[&str] = &[];

/// A capability that may be needed by one built-in invocation.
///
/// The requirements are derived from the already-expanded argument strings;
/// deriving them never evaluates a function, reads a file, consults a clock,
/// or mutates a variable/property store.  The more specific execution
/// identities are intentional: an `ExecutionContext` object that has no
/// sampler, group, or thread number is not sufficient for every information
/// function.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FunctionCapability {
    /// A function writes one or more JMeter variables.
    VariableMutation,
    /// A function writes a JMeter property.
    PropertyMutation,
    /// A saved-plan-name provider is needed.
    TestPlanName,
    /// A deterministic random source is needed.
    Random,
    /// A deterministic wall-clock/date source is needed.
    Clock,
    /// A virtual-user thread number is needed.
    ThreadIdentity,
    /// An explicit virtual-user iteration identity is needed.
    IterationIdentity,
    /// A virtual-user thread-group name is needed.
    ThreadGroupIdentity,
    /// A current sampler name is needed.
    SamplerIdentity,
    /// A host identity provider is needed.
    HostIdentity,
    /// A log sink is needed.
    Log,
    /// File read/write access is needed.
    Files,
    /// A response extractor is needed.
    Response,
    /// An external script engine is needed.
    Script,
}

/// Side-effect-free capability requirements for one built-in invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FunctionInvocationRequirements {
    required: Box<[FunctionCapability]>,
}

impl FunctionInvocationRequirements {
    fn new(mut required: Vec<FunctionCapability>) -> Self {
        required.sort_unstable();
        required.dedup();
        Self {
            required: required.into_boxed_slice(),
        }
    }

    /// Returns the capabilities required by this invocation.
    #[must_use]
    pub fn required_capabilities(&self) -> &[FunctionCapability] {
        &self.required
    }

    /// Returns whether this invocation requires `capability`.
    #[must_use]
    pub fn requires(&self, capability: FunctionCapability) -> bool {
        self.required.binary_search(&capability).is_ok()
    }

    /// Returns whether this invocation is pure with respect to injected
    /// capabilities.
    #[must_use]
    pub fn is_pure(&self) -> bool {
        self.required.is_empty()
    }
}

/// Active support state for one function name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FunctionSupport {
    /// The name is outside the native 5.6.3 registry.
    Unknown,
    /// The name is registered, but this registry lacks a required capability.
    Registered,
    /// The name is registered and its required registry capabilities exist.
    Executable,
}

/// A stateless built-in function registry.
///
/// The optional `Arc` fields are convenience injection points for callers
/// that want to keep the existing [`Evaluator::new`](super::Evaluator::new)
/// constructor.  [`EvaluationCapabilities`](super::EvaluationCapabilities)
/// is the preferred per-evaluation injection point when a capability's
/// lifetime is shorter than the registry's.
pub struct BuiltinFunctions {
    variable_setter: Option<Arc<dyn VariableSetter>>,
    property_setter: Option<Arc<dyn PropertySetter>>,
    test_plan_name: Option<Arc<dyn TestPlanNameResolver>>,
    random: Option<Arc<dyn RandomSource>>,
    clock: Option<Arc<dyn ClockSource>>,
    execution: Option<Arc<dyn ExecutionContext>>,
    host: Option<Arc<dyn HostResolver>>,
    log: Option<Arc<dyn LogSink>>,
    files: Option<Arc<dyn FileCapability>>,
    response: Option<Arc<dyn ResponseExtractor>>,
    scripts: Option<Arc<dyn ScriptCapability>>,
    counters: Mutex<CounterState>,
}

impl Default for BuiltinFunctions {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for BuiltinFunctions {
    fn clone(&self) -> Self {
        Self {
            variable_setter: self.variable_setter.clone(),
            property_setter: self.property_setter.clone(),
            test_plan_name: self.test_plan_name.clone(),
            random: self.random.clone(),
            clock: self.clock.clone(),
            execution: self.execution.clone(),
            host: self.host.clone(),
            log: self.log.clone(),
            files: self.files.clone(),
            response: self.response.clone(),
            scripts: self.scripts.clone(),
            counters: Mutex::new(CounterState::new()),
        }
    }
}

/// Explicitly shared handle for one run-owned native function registry.
///
/// Cloning this handle shares counters and other registry-owned state.  A
/// fresh registry is created with [`BuiltinFunctions::new`] or
/// [`BuiltinFunctions::fresh_clone`]; ordinary `BuiltinFunctions::clone`
/// remains a compatibility-preserving fresh copy and must not be used as a
/// run-sharing operation.
#[derive(Clone)]
pub struct SharedBuiltinFunctions {
    inner: Arc<BuiltinFunctions>,
}

/// Naming alias that makes the ownership distinction explicit at call sites.
pub type SharedBuiltinRegistry = SharedBuiltinFunctions;

impl fmt::Debug for SharedBuiltinFunctions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedBuiltinFunctions")
            .field("strong_count", &Arc::strong_count(&self.inner))
            .field("registry", &self.inner)
            .finish()
    }
}

impl Deref for SharedBuiltinFunctions {
    type Target = BuiltinFunctions;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl AsRef<BuiltinFunctions> for SharedBuiltinFunctions {
    fn as_ref(&self) -> &BuiltinFunctions {
        &self.inner
    }
}

impl SharedBuiltinFunctions {
    /// Creates a fresh shared registry for one independent run.
    #[must_use]
    pub fn new() -> Self {
        BuiltinFunctions::new().into_shared()
    }

    /// Wraps an already allocated registry in an explicit shared handle.
    #[must_use]
    pub fn from_registry(registry: BuiltinFunctions) -> Self {
        registry.into_shared()
    }

    /// Returns the number of handles sharing this registry.
    #[must_use]
    pub fn strong_count(&self) -> usize {
        Arc::strong_count(&self.inner)
    }

    /// Returns the underlying `Arc` for runtime ownership wiring.
    #[must_use]
    pub fn into_arc(self) -> Arc<BuiltinFunctions> {
        self.inner
    }
}

impl Default for SharedBuiltinFunctions {
    fn default() -> Self {
        Self::new()
    }
}

impl FunctionResolver for SharedBuiltinFunctions {
    fn resolve_function(
        &self,
        name: &str,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<Option<String>, FunctionError> {
        self.inner.resolve_function(name, arguments, context)
    }

    fn is_defined(&self, name: &str) -> Option<bool> {
        self.inner.is_defined(name)
    }
}

impl fmt::Debug for BuiltinFunctions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BuiltinFunctions")
            .field("variable_setter", &self.variable_setter.is_some())
            .field("property_setter", &self.property_setter.is_some())
            .field("test_plan_name", &self.test_plan_name.is_some())
            .field("random", &self.random.is_some())
            .field("clock", &self.clock.is_some())
            .field("execution", &self.execution.is_some())
            .field("host", &self.host.is_some())
            .field("log", &self.log.is_some())
            .field("files", &self.files.is_some())
            .field("response", &self.response.is_some())
            .field("scripts", &self.scripts.is_some())
            .finish()
    }
}

impl BuiltinFunctions {
    /// Creates a registry with no external capabilities.
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
            counters: Mutex::new(CounterState::new()),
        }
    }

    /// Creates a fresh registry and returns an explicitly shared run handle.
    #[must_use]
    pub fn new_shared() -> SharedBuiltinFunctions {
        SharedBuiltinFunctions::new()
    }

    /// Converts this fresh registry into an explicit shared handle.
    #[must_use]
    pub fn into_shared(self) -> SharedBuiltinFunctions {
        SharedBuiltinFunctions {
            inner: Arc::new(self),
        }
    }

    /// Alias for [`Self::into_shared`] emphasizing that the handle is shared.
    #[must_use]
    pub fn shared(self) -> SharedBuiltinFunctions {
        self.into_shared()
    }

    /// Creates an explicit fresh copy of this registry.
    ///
    /// Counters and other registry-owned mutable native state are reset.  Use
    /// [`SharedBuiltinFunctions::clone`] when run-shared state is required.
    #[must_use]
    pub fn fresh_clone(&self) -> Self {
        self.clone()
    }

    /// Returns all names known to the explicit registry.
    #[must_use]
    pub const fn function_names() -> &'static [&'static str] {
        KNOWN_FUNCTION_NAMES
    }

    /// Returns no plugin-function names; plugins require an external resolver.
    #[must_use]
    pub const fn extended_function_names() -> &'static [&'static str] {
        EXTENDED_FUNCTION_NAMES
    }

    /// Drops per-user counter state for a completed virtual-user lifecycle.
    /// Global counter sequences are retained, matching JMeter's
    /// process-wide counter. A poisoned state lock is returned as a typed
    /// error instead of being silently ignored.
    pub fn clear_counters_for_lifecycle(&self, lifecycle_id: u64) -> Result<(), FunctionError> {
        let mut counters = self
            .counters
            .lock()
            .map_err(|_| FunctionError::poisoned("counter state lock is poisoned"))?;
        counters
            .next_values
            .retain(|(per_user, _, lifecycle, _, _), _| !*per_user || *lifecycle != lifecycle_id);
        counters.cached_values.retain(|(scope, iteration), _| {
            let per_user_lifecycle = scope.0 && scope.2 == lifecycle_id;
            let completed_global_user = !scope.0
                && iteration
                    .lifecycle_id()
                    .is_some_and(|value| value == lifecycle_id);
            !per_user_lifecycle && !completed_global_user
        });
        Ok(())
    }

    /// Clears all mutable state before an independent run.  A poisoned state
    /// lock is returned as a typed error.
    pub fn clear_state(&self) -> Result<(), FunctionError> {
        let mut counters = self
            .counters
            .lock()
            .map_err(|_| FunctionError::poisoned("counter state lock is poisoned"))?;
        counters.next_values.clear();
        counters.cached_values.clear();
        Ok(())
    }

    /// Returns whether `name` is a case-sensitive known function name.
    #[must_use]
    pub fn is_known(name: &str) -> bool {
        KNOWN_FUNCTION_NAMES.contains(&name)
    }

    /// Classifies the capabilities required by one already-expanded
    /// invocation.
    ///
    /// `arguments` must contain the strings that would be passed to the
    /// resolver.  This method deliberately performs no argument evaluation
    /// and no capability operation.  `None` means that `name` is outside the
    /// native 5.6.3 registry; a known function with no requirements returns
    /// `Some` with an empty requirement set.
    #[must_use]
    pub fn requirements_for_invocation(
        name: &str,
        arguments: &[String],
    ) -> Option<FunctionInvocationRequirements> {
        if !Self::is_known(name) {
            return None;
        }

        let mut required = Vec::new();
        let optional_variable = |index: usize| {
            arguments
                .get(index)
                .is_some_and(|value| !java_trim(value).is_empty())
        };

        match name {
            "__BeanShell" | "__groovy" | "__javaScript" | "__jexl2" | "__jexl3" => {
                required.push(FunctionCapability::Script);
                if optional_variable(1) {
                    required.push(FunctionCapability::VariableMutation);
                }
            }
            "__CSVRead" => required.push(FunctionCapability::Files),
            "__FileToString" => {
                required.push(FunctionCapability::Files);
                if optional_variable(2) {
                    required.push(FunctionCapability::VariableMutation);
                }
            }
            "__StringFromFile" => {
                required.push(FunctionCapability::Files);
                // JMeter writes StringFromFile_'s default variable when the
                // reference is omitted. An explicit empty/blank reference
                // suppresses that write.
                if arguments
                    .get(1)
                    .is_none_or(|value| !java_trim(value).is_empty())
                {
                    required.push(FunctionCapability::VariableMutation);
                }
            }
            "__StringToFile" => {
                // An empty path returns "false" before the file capability is
                // touched. With no path yet, retain the conservative
                // name-level requirement for the otherwise file-backed call.
                if arguments
                    .first()
                    .is_none_or(|value| !java_trim(value).is_empty())
                {
                    required.push(FunctionCapability::Files);
                }
            }
            "__Random" => {
                required.push(FunctionCapability::Random);
                if optional_variable(2) {
                    required.push(FunctionCapability::VariableMutation);
                }
            }
            "__RandomDate" => {
                required.push(FunctionCapability::Random);
                // RandomDate only consults the clock when the start date is
                // omitted/blank. DateTimeFormatter also supplies the current
                // year when a caller uses a pattern without an explicit year,
                // so that form needs the pinned clock as well.
                if random_date_requires_clock(arguments) {
                    required.push(FunctionCapability::Clock);
                }
                if optional_variable(4) {
                    required.push(FunctionCapability::VariableMutation);
                }
            }
            "__RandomFromMultipleVars" => {
                required.push(FunctionCapability::Random);
                if optional_variable(1) {
                    required.push(FunctionCapability::VariableMutation);
                }
            }
            "__RandomString" => {
                required.push(FunctionCapability::Random);
                if optional_variable(2) {
                    required.push(FunctionCapability::VariableMutation);
                }
            }
            "__UUID" => required.push(FunctionCapability::Random),
            "__TestPlanName" => required.push(FunctionCapability::TestPlanName),
            "__XPath" => required.push(FunctionCapability::Response),
            "__regexFunction" => {
                required.push(FunctionCapability::Response);
                // RegexFunction writes the optional name exactly as
                // supplied (unlike AbstractFunction::addVariableValue), so
                // even an all-space non-empty name is a mutation.
                if arguments.get(5).is_some_and(|value| !value.is_empty()) {
                    required.push(FunctionCapability::VariableMutation);
                }
            }
            "__log" | "__logn" => required.push(FunctionCapability::Log),
            "__machineIP" | "__machineName" => {
                required.push(FunctionCapability::HostIdentity);
                if optional_variable(0) {
                    required.push(FunctionCapability::VariableMutation);
                }
            }
            "__samplerName" => {
                required.push(FunctionCapability::SamplerIdentity);
                if optional_variable(0) {
                    required.push(FunctionCapability::VariableMutation);
                }
            }
            "__threadGroupName" => required.push(FunctionCapability::ThreadGroupIdentity),
            "__threadNum" => required.push(FunctionCapability::ThreadIdentity),
            "__counter" => {
                // Boolean.parseBoolean is false for every value except a
                // case-insensitive "true". Both modes still need an
                // explicit iteration identity: JMeter reuses one value for
                // every occurrence of the same function instance during an
                // iteration. Per-user counters additionally need a thread.
                required.push(FunctionCapability::IterationIdentity);
                if arguments
                    .first()
                    .is_some_and(|value| value.eq_ignore_ascii_case("true"))
                {
                    required.push(FunctionCapability::ThreadIdentity);
                }
                if optional_variable(1) {
                    required.push(FunctionCapability::VariableMutation);
                }
            }
            "__time" => {
                required.push(FunctionCapability::Clock);
                if optional_variable(1) {
                    required.push(FunctionCapability::VariableMutation);
                }
            }
            "__timeShift" => {
                // JMeter's formatted parser/formatter uses the process
                // default zone (and the default locale when the locale slot
                // is empty). The pure boundary therefore needs an injected
                // clock for every formatted call, even when the input date
                // is explicit. Numeric epoch shifting with an explicit date
                // does not consult a clock.
                if arguments
                    .first()
                    .is_none_or(|value| !java_trim(value).is_empty())
                    || arguments
                        .get(1)
                        .is_none_or(|value| java_trim(value).is_empty())
                {
                    required.push(FunctionCapability::Clock);
                }
                let variable_index = match arguments.len() {
                    4 => Some(3),
                    5 => Some(4),
                    _ => None,
                };
                if variable_index.is_some_and(optional_variable) {
                    required.push(FunctionCapability::VariableMutation);
                }
            }
            "__setProperty" => required.push(FunctionCapability::PropertyMutation),
            "__split" => required.push(FunctionCapability::VariableMutation),
            "__property" => {
                // Property.java checks the raw optional name and does not
                // trim it before storing; a literal space is therefore a
                // real (if unusual) variable key.
                if arguments.get(1).is_some_and(|value| !value.is_empty()) {
                    required.push(FunctionCapability::VariableMutation);
                }
            }
            "__changeCase" => {
                if optional_variable(2) {
                    required.push(FunctionCapability::VariableMutation);
                }
            }
            "__escapeOroRegexpChars" => {
                if optional_variable(1) {
                    required.push(FunctionCapability::VariableMutation);
                }
            }
            "__intSum" => {
                if sum_requires_variable(arguments, true) {
                    required.push(FunctionCapability::VariableMutation);
                }
            }
            "__longSum" => {
                if sum_requires_variable(arguments, false) {
                    required.push(FunctionCapability::VariableMutation);
                }
            }
            "__dateTimeConvert" => {
                // DateTimeFormatter.withZone(ZoneId.systemDefault()) is
                // used for both parsing and formatting by JMeter. A clock
                // capability carries the pinned zone/locale at this pure
                // boundary; never silently substitute the host zone.
                required.push(FunctionCapability::Clock);
                if optional_variable(3) {
                    required.push(FunctionCapability::VariableMutation);
                }
            }
            "__digest" => {
                if optional_variable(4) {
                    required.push(FunctionCapability::VariableMutation);
                }
            }
            name if Self::is_known(name) => {}
            _ => unreachable!("known function was not classified"),
        }

        Some(FunctionInvocationRequirements::new(required))
    }

    /// Classifies the observable effect boundary for one already-expanded
    /// invocation.  This is metadata only; it does not execute the function
    /// or claim that an unavailable external adapter can be rolled back.
    #[must_use]
    pub fn effect_class_for_invocation(name: &str, arguments: &[String]) -> Option<EffectClass> {
        let requirements = Self::requirements_for_invocation(name, arguments)?;
        let class = match name {
            "__BeanShell" | "__groovy" | "__javaScript" | "__jexl2" | "__jexl3" | "__log"
            | "__logn" | "__StringToFile" => EffectClass::IrreversibleExternal,
            "__XPath" | "__regexFunction" => EffectClass::TransactionalExternal,
            _ if requirements.is_pure() => EffectClass::Pure,
            _ => EffectClass::JournaledNative,
        };
        Some(class)
    }

    /// Returns whether `name` is registered in the native 5.6.3 vocabulary.
    ///
    /// This legacy query intentionally answers only the registry question.
    /// Use [`Self::is_executable`] or [`Self::support_status`] when the active
    /// capability set matters.
    #[must_use]
    pub fn is_registered(name: &str) -> bool {
        Self::is_known(name)
    }

    /// Returns whether the registry can execute `name` with its installed
    /// capability set.
    ///
    /// Per-evaluation capabilities supplied through
    /// [`crate::EvaluationCapabilities`]
    /// can make additional names executable for one call; this registry-level
    /// query describes only capabilities retained by this registry instance.
    #[must_use]
    pub fn is_executable(&self, name: &str) -> bool {
        self.is_executable_with_capabilities(name, EvaluationCapabilities::new())
    }

    /// Returns whether `name` can execute with this registry plus the
    /// capabilities supplied for one evaluation.
    ///
    /// This name-only compatibility query uses the function's omitted-
    /// argument shape. Call [`Self::is_executable_for_invocation`] when the
    /// expanded arguments are available; optional output variables and
    /// argument-dependent clock/identity requirements cannot be inferred
    /// from a name alone.
    #[must_use]
    pub fn is_executable_with_capabilities(
        &self,
        name: &str,
        capabilities: EvaluationCapabilities<'_>,
    ) -> bool {
        self.is_executable_for_invocation(name, &[], capabilities)
    }

    /// Returns whether one already-expanded invocation can execute with this
    /// registry plus the supplied per-evaluation capabilities.
    #[must_use]
    pub fn is_executable_for_invocation(
        &self,
        name: &str,
        arguments: &[String],
        capabilities: EvaluationCapabilities<'_>,
    ) -> bool {
        self.missing_capabilities_for_invocation(name, arguments, capabilities)
            .is_some_and(|missing| missing.is_empty())
    }

    /// Returns the capabilities missing for one invocation, or `None` for an
    /// unknown function name.
    #[must_use]
    pub fn missing_capabilities_for_invocation(
        &self,
        name: &str,
        arguments: &[String],
        capabilities: EvaluationCapabilities<'_>,
    ) -> Option<Vec<FunctionCapability>> {
        let requirements = Self::requirements_for_invocation(name, arguments)?;
        Some(
            requirements
                .required_capabilities()
                .iter()
                .copied()
                .filter(|capability| !self.has_capability(*capability, capabilities))
                .collect(),
        )
    }

    /// Reports support for one already-expanded invocation, distinguishing an
    /// unknown function from a registered function whose exact arguments need
    /// an unavailable capability.
    #[must_use]
    pub fn support_status_for_invocation(
        &self,
        name: &str,
        arguments: &[String],
        capabilities: EvaluationCapabilities<'_>,
    ) -> FunctionSupport {
        match self.missing_capabilities_for_invocation(name, arguments, capabilities) {
            None => FunctionSupport::Unknown,
            Some(missing) if missing.is_empty() => FunctionSupport::Executable,
            Some(_) => FunctionSupport::Registered,
        }
    }

    fn has_capability(
        &self,
        capability: FunctionCapability,
        capabilities: EvaluationCapabilities<'_>,
    ) -> bool {
        match capability {
            FunctionCapability::VariableMutation => {
                self.variable_setter.is_some() || capabilities.has_variable_setter()
            }
            FunctionCapability::PropertyMutation => {
                self.property_setter.is_some() || capabilities.has_property_setter()
            }
            FunctionCapability::TestPlanName => {
                self.test_plan_name.is_some() || capabilities.has_test_plan_name()
            }
            FunctionCapability::Random => self.random.is_some() || capabilities.has_random_source(),
            FunctionCapability::Clock => self.clock.is_some() || capabilities.has_clock(),
            FunctionCapability::ThreadIdentity => {
                capabilities
                    .execution_context()
                    .and_then(ExecutionContext::thread_num)
                    .is_some()
                    || self
                        .execution
                        .as_deref()
                        .and_then(ExecutionContext::thread_num)
                        .is_some()
            }
            FunctionCapability::IterationIdentity => {
                capabilities
                    .execution_context()
                    .and_then(ExecutionContext::iteration_identity)
                    .is_some()
                    || self
                        .execution
                        .as_deref()
                        .and_then(ExecutionContext::iteration_identity)
                        .is_some()
            }
            FunctionCapability::ThreadGroupIdentity => {
                capabilities
                    .execution_context()
                    .and_then(ExecutionContext::thread_group_name)
                    .is_some()
                    || self
                        .execution
                        .as_deref()
                        .and_then(ExecutionContext::thread_group_name)
                        .is_some()
            }
            FunctionCapability::SamplerIdentity => {
                capabilities
                    .execution_context()
                    .and_then(ExecutionContext::sampler_name)
                    .is_some()
                    || self
                        .execution
                        .as_deref()
                        .and_then(ExecutionContext::sampler_name)
                        .is_some()
            }
            FunctionCapability::HostIdentity => {
                self.host.is_some() || capabilities.has_host_resolver()
            }
            FunctionCapability::Log => self.log.is_some() || capabilities.has_log_sink(),
            FunctionCapability::Files => self.files.is_some() || capabilities.has_file_capability(),
            FunctionCapability::Response => {
                self.response.is_some() || capabilities.has_response_extractor()
            }
            FunctionCapability::Script => {
                self.scripts.is_some() || capabilities.has_script_capability()
            }
        }
    }

    /// Reports the distinction between an unknown name, a registered native
    /// function, and a function executable with this registry's capabilities.
    #[must_use]
    pub fn support_status(&self, name: &str) -> FunctionSupport {
        self.support_status_with_capabilities(name, EvaluationCapabilities::new())
    }

    /// Reports support using both registry capabilities and one evaluation's
    /// explicitly injected capabilities.  This is the authoritative query
    /// for functions whose contract requires mutation, such as `__split` and
    /// `__StringFromFile`'s default-variable write.
    #[must_use]
    pub fn support_status_with_capabilities(
        &self,
        name: &str,
        capabilities: EvaluationCapabilities<'_>,
    ) -> FunctionSupport {
        if !Self::is_registered(name) {
            FunctionSupport::Unknown
        } else if self.is_executable_with_capabilities(name, capabilities) {
            FunctionSupport::Executable
        } else {
            FunctionSupport::Registered
        }
    }

    /// Alias for [`Self::support_status_with_capabilities`].
    #[must_use]
    pub fn support_status_for(
        &self,
        name: &str,
        capabilities: EvaluationCapabilities<'_>,
    ) -> FunctionSupport {
        self.support_status_with_capabilities(name, capabilities)
    }

    /// Returns whether `name` is executable with this registry's capabilities.
    ///
    /// Names that are registered but lack an external capability return
    /// `false`; query [`Self::is_registered`] when only vocabulary membership
    /// is needed.
    #[must_use]
    pub fn is_supported(&self, name: &str) -> bool {
        self.is_executable(name)
    }

    /// Injects a variable setter/store owned by an `Arc`.
    #[must_use]
    pub fn with_variable_setter_arc(mut self, setter: Arc<dyn VariableSetter>) -> Self {
        self.variable_setter = Some(setter);
        self
    }

    /// Injects a property setter/store owned by an `Arc`.
    #[must_use]
    pub fn with_property_setter_arc(mut self, setter: Arc<dyn PropertySetter>) -> Self {
        self.property_setter = Some(setter);
        self
    }

    /// Injects a test-plan-name provider owned by an `Arc`.
    #[must_use]
    pub fn with_test_plan_name_arc(mut self, provider: Arc<dyn TestPlanNameResolver>) -> Self {
        self.test_plan_name = Some(provider);
        self
    }

    /// Injects a variable setter by value.
    #[must_use]
    pub fn with_variable_setter<S>(self, setter: S) -> Self
    where
        S: VariableSetter + 'static,
    {
        self.with_variable_setter_arc(Arc::new(setter))
    }

    /// Injects a property setter by value.
    #[must_use]
    pub fn with_property_setter<S>(self, setter: S) -> Self
    where
        S: PropertySetter + 'static,
    {
        self.with_property_setter_arc(Arc::new(setter))
    }

    /// Injects a test-plan-name provider by value.
    #[must_use]
    pub fn with_test_plan_name<S>(self, provider: S) -> Self
    where
        S: TestPlanNameResolver + 'static,
    {
        self.with_test_plan_name_arc(Arc::new(provider))
    }

    /// Injects a random source owned by an `Arc`.
    #[must_use]
    pub fn with_random_source_arc(mut self, source: Arc<dyn RandomSource>) -> Self {
        self.random = Some(source);
        self
    }

    /// Injects a random source by value.
    #[must_use]
    pub fn with_random_source<S>(self, source: S) -> Self
    where
        S: RandomSource + 'static,
    {
        self.with_random_source_arc(Arc::new(source))
    }

    /// Injects a clock owned by an `Arc`.
    #[must_use]
    pub fn with_clock_arc(mut self, clock: Arc<dyn ClockSource>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Injects a clock by value.
    #[must_use]
    pub fn with_clock<S>(self, clock: S) -> Self
    where
        S: ClockSource + 'static,
    {
        self.with_clock_arc(Arc::new(clock))
    }

    /// Injects virtual-user execution identity by value.
    #[must_use]
    pub fn with_execution_context<S>(self, execution: S) -> Self
    where
        S: ExecutionContext + 'static,
    {
        self.with_execution_context_arc(Arc::new(execution))
    }

    /// Injects virtual-user execution identity owned by an `Arc`.
    #[must_use]
    pub fn with_execution_context_arc(mut self, execution: Arc<dyn ExecutionContext>) -> Self {
        self.execution = Some(execution);
        self
    }

    /// Injects host identity by value.
    #[must_use]
    pub fn with_host_resolver<S>(self, host: S) -> Self
    where
        S: HostResolver + 'static,
    {
        self.with_host_resolver_arc(Arc::new(host))
    }

    /// Injects host identity owned by an `Arc`.
    #[must_use]
    pub fn with_host_resolver_arc(mut self, host: Arc<dyn HostResolver>) -> Self {
        self.host = Some(host);
        self
    }

    /// Injects a log sink by value.
    #[must_use]
    pub fn with_log_sink<S>(self, sink: S) -> Self
    where
        S: LogSink + 'static,
    {
        self.with_log_sink_arc(Arc::new(sink))
    }

    /// Injects a log sink owned by an `Arc`.
    #[must_use]
    pub fn with_log_sink_arc(mut self, sink: Arc<dyn LogSink>) -> Self {
        self.log = Some(sink);
        self
    }

    /// Injects file-backed functions by value.
    #[must_use]
    pub fn with_file_capability<S>(self, files: S) -> Self
    where
        S: FileCapability + 'static,
    {
        self.with_file_capability_arc(Arc::new(files))
    }

    /// Injects file-backed functions owned by an `Arc`.
    #[must_use]
    pub fn with_file_capability_arc(mut self, files: Arc<dyn FileCapability>) -> Self {
        self.files = Some(files);
        self
    }

    /// Injects response extraction by value.
    #[must_use]
    pub fn with_response_extractor<S>(self, response: S) -> Self
    where
        S: ResponseExtractor + 'static,
    {
        self.with_response_extractor_arc(Arc::new(response))
    }

    /// Injects response extraction owned by an `Arc`.
    #[must_use]
    pub fn with_response_extractor_arc(mut self, response: Arc<dyn ResponseExtractor>) -> Self {
        self.response = Some(response);
        self
    }

    /// Injects an external script engine by value.
    #[must_use]
    pub fn with_script_capability<S>(self, scripts: S) -> Self
    where
        S: ScriptCapability + 'static,
    {
        self.with_script_capability_arc(Arc::new(scripts))
    }

    /// Injects an external script engine owned by an `Arc`.
    #[must_use]
    pub fn with_script_capability_arc(mut self, scripts: Arc<dyn ScriptCapability>) -> Self {
        self.scripts = Some(scripts);
        self
    }

    fn variable_value(
        &self,
        context: &FunctionContext<'_>,
        name: &str,
    ) -> Result<Option<String>, FunctionError> {
        if context.has_variable_setter() {
            return context.variable_value_checked(name);
        }
        match self.variable_setter.as_deref() {
            Some(setter) => setter
                .get_variable_checked(name)
                .map(|value| value.or_else(|| context.variable(name).map(str::to_owned))),
            None => context.variable_value_checked(name),
        }
    }

    fn property_value(
        &self,
        context: &FunctionContext<'_>,
        name: &str,
    ) -> Result<Option<String>, FunctionError> {
        if context.has_property_setter() {
            return context.property_value_checked(name);
        }
        match self.property_setter.as_deref() {
            Some(setter) => setter
                .get_property_checked(name)
                .map(|value| value.or_else(|| context.property(name).map(str::to_owned))),
            None => context.property_value_checked(name),
        }
    }

    fn set_variable(
        &self,
        context: &FunctionContext<'_>,
        name: &str,
        value: &str,
    ) -> Result<(), FunctionError> {
        if context.has_variable_setter() {
            return context.set_variable(name, value);
        }
        if let Some(setter) = self.variable_setter.as_deref() {
            setter.set_variable(name, value)
        } else {
            context.set_variable(name, value)
        }
    }

    fn set_variables_atomic(
        &self,
        context: &FunctionContext<'_>,
        values: &[(&str, &str)],
    ) -> Result<(), FunctionError> {
        if context.has_variable_setter() {
            return context.set_variables_atomic(values);
        }
        if let Some(setter) = self.variable_setter.as_deref() {
            setter.set_variables_atomic(values)
        } else {
            context.set_variables_atomic(values)
        }
    }

    fn remove_variable(
        &self,
        context: &FunctionContext<'_>,
        name: &str,
    ) -> Result<(), FunctionError> {
        if context.has_variable_setter() {
            return context.remove_variable(name);
        }
        if let Some(setter) = self.variable_setter.as_deref() {
            setter.remove_variable(name)
        } else {
            context.remove_variable(name)
        }
    }

    fn set_property(
        &self,
        context: &FunctionContext<'_>,
        name: &str,
        value: &str,
    ) -> Result<Option<String>, FunctionError> {
        if context.has_property_setter() {
            return context.set_property(name, value);
        }
        if let Some(setter) = self.property_setter.as_deref() {
            setter.set_property(name, value)
        } else {
            context.set_property(name, value)
        }
    }

    fn test_plan_name(&self, context: &FunctionContext<'_>) -> Option<String> {
        self.test_plan_name
            .as_deref()
            .and_then(TestPlanNameResolver::test_plan_name)
            .or_else(|| context.test_plan_name())
    }

    fn next_random_u64(&self, context: &FunctionContext<'_>) -> Result<u64, FunctionError> {
        if let Some(source) = context.random_source() {
            Ok(source.next_u64())
        } else if let Some(source) = self.random.as_deref() {
            Ok(source.next_u64())
        } else {
            Err(FunctionError::unsupported(
                "random capability is unavailable",
            ))
        }
    }

    fn clock_values(&self, context: &FunctionContext<'_>) -> Result<(i64, i32), FunctionError> {
        if let Some(clock) = context.clock() {
            Ok((clock.now_millis()?, clock.offset_seconds()))
        } else if let Some(clock) = self.clock.as_deref() {
            Ok((clock.now_millis()?, clock.offset_seconds()))
        } else {
            Err(FunctionError::unsupported(
                "clock capability is unavailable",
            ))
        }
    }

    fn clock_offset(&self, context: &FunctionContext<'_>) -> i32 {
        context
            .clock()
            .map(ClockSource::offset_seconds)
            .or_else(|| self.clock.as_deref().map(ClockSource::offset_seconds))
            .unwrap_or(0)
    }

    fn clock_locale(&self, context: &FunctionContext<'_>) -> Result<Locale, FunctionError> {
        let value = if let Some(clock) = context.clock() {
            clock.locale()
        } else {
            self.clock.as_deref().and_then(ClockSource::locale)
        };
        locale_from(value.as_deref())
    }

    fn clock_year(&self, context: &FunctionContext<'_>) -> Result<i64, FunctionError> {
        let (millis, offset) = self.clock_values(context)?;
        Ok(civil_from_days(local_epoch_day(millis, offset)?).0)
    }

    fn require_clock(&self, context: &FunctionContext<'_>) -> Result<(), FunctionError> {
        if context.clock().is_none() && self.clock.is_none() {
            return Err(FunctionError::unsupported(
                "clock capability is unavailable",
            ));
        }
        Ok(())
    }

    fn thread_num_value(&self, context: &FunctionContext<'_>) -> Result<u32, FunctionError> {
        let value = if let Some(execution) = context.execution_context() {
            execution.thread_num()
        } else {
            self.execution
                .as_deref()
                .and_then(ExecutionContext::thread_num)
        };
        value.ok_or_else(|| FunctionError::unsupported("thread number is unavailable"))
    }

    fn thread_group_name_value(
        &self,
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        let value = if let Some(execution) = context.execution_context() {
            execution.thread_group_name()
        } else {
            self.execution
                .as_deref()
                .and_then(ExecutionContext::thread_group_name)
        };
        value.ok_or_else(|| FunctionError::unsupported("thread group name is unavailable"))
    }

    fn sampler_name_value(&self, context: &FunctionContext<'_>) -> Result<String, FunctionError> {
        let value = if let Some(execution) = context.execution_context() {
            execution.sampler_name()
        } else {
            self.execution
                .as_deref()
                .and_then(ExecutionContext::sampler_name)
        };
        value.ok_or_else(|| FunctionError::unsupported("sampler name is unavailable"))
    }

    fn machine_name_value(&self, context: &FunctionContext<'_>) -> Result<String, FunctionError> {
        if let Some(host) = context.host_resolver() {
            host.machine_name()
        } else if let Some(host) = self.host.as_deref() {
            host.machine_name()
        } else {
            Err(FunctionError::unsupported(
                "host identity capability is unavailable",
            ))
        }
    }

    fn machine_ip_value(&self, context: &FunctionContext<'_>) -> Result<String, FunctionError> {
        if let Some(host) = context.host_resolver() {
            host.machine_ip()
        } else if let Some(host) = self.host.as_deref() {
            host.machine_ip()
        } else {
            Err(FunctionError::unsupported(
                "host identity capability is unavailable",
            ))
        }
    }

    fn file_read_to_string(
        &self,
        context: &FunctionContext<'_>,
        path: &str,
        encoding: Option<&str>,
    ) -> Result<String, FunctionError> {
        if let Some(files) = context.file_capability() {
            files.read_to_string(path, encoding)
        } else if let Some(files) = self.files.as_deref() {
            files.read_to_string(path, encoding)
        } else {
            Err(FunctionError::unsupported("file capability is unavailable"))
        }
    }

    fn file_read_line(
        &self,
        context: &FunctionContext<'_>,
        path: &str,
        key: &str,
        occurrence: &FunctionOccurrence,
        start_sequence: Option<i64>,
        end_sequence: Option<i64>,
    ) -> Result<String, FunctionError> {
        if let Some(files) = context.file_capability() {
            files.read_line_for_function_occurrence(
                path,
                key,
                occurrence,
                start_sequence,
                end_sequence,
            )
        } else if let Some(files) = self.files.as_deref() {
            files.read_line_for_function_occurrence(
                path,
                key,
                occurrence,
                start_sequence,
                end_sequence,
            )
        } else {
            Err(FunctionError::unsupported("file capability is unavailable"))
        }
    }

    fn file_read_csv(
        &self,
        context: &FunctionContext<'_>,
        path: &str,
        selector: &str,
        delimiter: char,
    ) -> Result<String, FunctionError> {
        if let Some(files) = context.file_capability() {
            files.read_csv_field(path, selector, delimiter)
        } else if let Some(files) = self.files.as_deref() {
            files.read_csv_field(path, selector, delimiter)
        } else {
            Err(FunctionError::unsupported("file capability is unavailable"))
        }
    }

    fn file_write_string(
        &self,
        context: &FunctionContext<'_>,
        path: &str,
        value: &str,
        append: bool,
        encoding: Option<&str>,
    ) -> Result<(), FunctionError> {
        if let Some(files) = context.file_capability() {
            files.write_string(path, value, append, encoding)
        } else if let Some(files) = self.files.as_deref() {
            files.write_string(path, value, append, encoding)
        } else {
            Err(FunctionError::unsupported("file capability is unavailable"))
        }
    }

    fn regex_value(
        &self,
        context: &FunctionContext<'_>,
        arguments: &[String],
    ) -> Result<(String, Vec<(String, String)>), FunctionError> {
        if let Some(response) = context.response_extractor() {
            response.regex_function(arguments)
        } else if let Some(response) = self.response.as_deref() {
            response.regex_function(arguments)
        } else {
            Err(FunctionError::unsupported(
                "regex capability is unavailable",
            ))
        }
    }

    fn xpath_value(
        &self,
        context: &FunctionContext<'_>,
        arguments: &[String],
    ) -> Result<String, FunctionError> {
        if let Some(response) = context.response_extractor() {
            response.xpath_function(arguments)
        } else if let Some(response) = self.response.as_deref() {
            response.xpath_function(arguments)
        } else {
            Err(FunctionError::unsupported(
                "XPath capability is unavailable",
            ))
        }
    }

    fn script_value(
        &self,
        context: &FunctionContext<'_>,
        name: &str,
        arguments: &[String],
    ) -> Result<String, FunctionError> {
        if let Some(scripts) = context.script_capability() {
            scripts.evaluate(name, arguments)
        } else if let Some(scripts) = self.scripts.as_deref() {
            scripts.evaluate(name, arguments)
        } else {
            Err(FunctionError::unsupported(format!(
                "{name} engine is unavailable"
            )))
        }
    }

    fn log_value(
        &self,
        context: &FunctionContext<'_>,
        level: &str,
        message: &str,
        throwable: Option<&str>,
        comment: Option<&str>,
    ) -> Result<(), FunctionError> {
        if let Some(sink) = context.log_sink() {
            sink.log(level, message, throwable, comment)
        } else if let Some(sink) = self.log.as_deref() {
            sink.log(level, message, throwable, comment)
        } else {
            Err(FunctionError::unsupported("log capability is unavailable"))
        }
    }
}

/// Alias emphasizing that [`BuiltinFunctions`] is an explicit registry.
pub type BuiltinRegistry = BuiltinFunctions;

impl FunctionResolver for BuiltinFunctions {
    fn is_defined(&self, name: &str) -> Option<bool> {
        Some(Self::is_known(name))
    }

    fn resolve_function(
        &self,
        name: &str,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<Option<String>, FunctionError> {
        let value = match name {
            "__V" => Some(self.variable(arguments, context)?),
            "__eval" => Some(eval(arguments, context)?),
            "__evalVar" => Some(self.eval_var(arguments, context)?),
            "__property" => Some(self.property(arguments, context)?),
            "__P" => Some(self.property_short(arguments, context)?),
            "__setProperty" => Some(self.set_property_function(arguments, context)?),
            "__changeCase" => Some(self.change_case(arguments, context)?),
            "__char" => Some(char_function(arguments, context)?),
            "__escapeOroRegexpChars" => Some(self.escape_oro(arguments, context)?),
            "__escapeHtml" => Some(escape_html(arguments, context)?),
            "__escapeXml" => Some(escape_xml(arguments, context)?),
            "__unescape" => Some(unescape_java(arguments, context)?),
            "__unescapeHtml" => Some(unescape_html(arguments, context)?),
            "__urlencode" => Some(url_encode(arguments, context)?),
            "__urldecode" => Some(url_decode(arguments, context)?),
            "__intSum" => Some(self.int_sum(arguments, context)?),
            "__longSum" => Some(self.long_sum(arguments, context)?),
            "__isPropDefined" => Some(self.is_prop_defined(arguments, context)?),
            "__isVarDefined" => Some(self.is_var_defined(arguments, context)?),
            "__TestPlanName" => Some(self.test_plan_name_function(arguments, context)?),
            "__Random" => Some(self.random(arguments, context)?),
            "__RandomDate" => Some(self.random_date(arguments, context)?),
            "__RandomFromMultipleVars" => Some(self.random_from_multiple_vars(arguments, context)?),
            "__RandomString" => Some(self.random_string(arguments, context)?),
            "__UUID" => Some(self.uuid(arguments, context)?),
            "__counter" => Some(self.counter(arguments, context)?),
            "__dateTimeConvert" => Some(self.date_time_convert(arguments, context)?),
            "__digest" => Some(self.digest(arguments, context)?),
            "__log" => Some(self.log(arguments, context, false)?),
            "__logn" => Some(self.log(arguments, context, true)?),
            "__machineIP" => Some(self.machine_ip(arguments, context)?),
            "__machineName" => Some(self.machine_name(arguments, context)?),
            "__samplerName" => Some(self.sampler_name(arguments, context)?),
            "__threadGroupName" => Some(self.thread_group_name(arguments, context)?),
            "__threadNum" => Some(self.thread_num(arguments, context)?),
            "__time" => Some(self.time(arguments, context)?),
            "__timeShift" => Some(self.time_shift(arguments, context)?),
            "__split" => Some(self.split(arguments, context)?),
            "__FileToString" => Some(self.file_to_string(arguments, context)?),
            "__StringFromFile" => Some(self.string_from_file(arguments, context)?),
            "__StringToFile" => Some(self.string_to_file(arguments, context)?),
            "__CSVRead" => Some(self.csv_read(arguments, context)?),
            "__XPath" => Some(self.xpath(arguments, context)?),
            "__regexFunction" => Some(self.regex_function(arguments, context)?),
            "__BeanShell" | "__groovy" | "__javaScript" | "__jexl2" | "__jexl3" => {
                Some(self.script(arguments, context, name)?)
            }
            _ if Self::is_known(name) => {
                return Err(FunctionError::unsupported(format!(
                    "{name} requires an unavailable capability"
                )));
            }
            _ => return Ok(None),
        };
        Ok(value)
    }
}

impl BuiltinFunctions {
    fn variable(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        check_count("__V", arguments, 1, 2)?;
        let name = &arguments[0];
        Ok(self
            .variable_value(context, name)?
            .or_else(|| arguments.get(1).cloned())
            .unwrap_or_else(|| name.clone()))
    }

    fn property(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        check_count("__property", arguments, 1, 3)?;
        let name = &arguments[0];
        let value = self
            .property_value(context, name)?
            .or_else(|| arguments.get(2).cloned())
            .unwrap_or_else(|| name.clone());
        if let Some(variable_name) = arguments.get(1).filter(|name| !name.is_empty()) {
            ensure_variable_mutation_available(self, context)?;
            self.set_variable(context, variable_name, &value)?;
        }
        Ok(value)
    }

    fn property_short(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        check_count("__P", arguments, 1, 2)?;
        let name = &arguments[0];
        Ok(self
            .property_value(context, name)?
            .or_else(|| arguments.get(1).cloned())
            .unwrap_or_else(|| "1".to_owned()))
    }

    fn set_property_function(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        check_count("__setProperty", arguments, 2, 3)?;
        let previous = self.set_property(context, &arguments[0], &arguments[1])?;
        if arguments
            .get(2)
            .is_some_and(|value| value.eq_ignore_ascii_case("true"))
        {
            Ok(previous.unwrap_or_else(|| "null".to_owned()))
        } else {
            Ok(String::new())
        }
    }

    fn change_case(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        check_count("__changeCase", arguments, 1, 3)?;
        ensure_optional_variable_mutation(self, context, arguments.get(2))?;
        // JMeter treats an omitted or empty mode as the default UPPER mode.
        // Other unknown, non-empty modes are logged upstream and leave the
        // input unchanged.
        let mode = arguments
            .get(1)
            .filter(|mode| !mode.is_empty())
            .map_or("UPPER", String::as_str);
        let value = match mode.to_ascii_uppercase().as_str() {
            "UPPER" => arguments[0].to_uppercase(),
            "LOWER" => arguments[0].to_lowercase(),
            "CAPITALIZE" => capitalize(&arguments[0])?,
            _ => arguments[0].clone(),
        };
        // Unicode case mapping can expand a scalar (for example, `ß` to
        // `SS`), so enforce the result ceiling after mapping and before the
        // optional variable side effect.
        if value.len() > context.max_output_bytes() {
            return Err(FunctionError::execution(
                "function result exceeds the expression output bound",
            ));
        }
        set_optional_variable(self, context, arguments.get(2), &value)?;
        Ok(value)
    }

    fn escape_oro(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        check_count("__escapeOroRegexpChars", arguments, 1, 2)?;
        ensure_optional_variable_mutation(self, context, arguments.get(1))?;
        let mut escaped = String::with_capacity(
            arguments[0]
                .len()
                .saturating_mul(2)
                .min(context.max_output_bytes()),
        );
        for character in arguments[0].chars() {
            if character.len_utf16() > 1 {
                // ORO's quotemeta walks Java char units.  It would insert a
                // backslash before each half of a supplementary pair,
                // yielding an intentionally ill-formed UTF-16 Java String.
                // The UTF-8 expression boundary cannot carry that value, so
                // fail explicitly instead of silently changing the regex.
                return Err(FunctionError::unsupported(
                    "__escapeOroRegexpChars produced a surrogate-separated UTF-16 result",
                ));
            }
            // Jakarta ORO delegates word-character checks to
            // Character.isLetterOrDigit plus underscore, rather than the
            // narrower ASCII-only Perl rule.
            if !(character.is_alphanumeric() || character == '_') {
                append_bounded_function_text(&mut escaped, "\\", context.max_output_bytes())?;
            }
            let mut encoded = [0_u8; 4];
            append_bounded_function_text(
                &mut escaped,
                character.encode_utf8(&mut encoded),
                context.max_output_bytes(),
            )?;
        }
        set_optional_variable(self, context, arguments.get(1), &escaped)?;
        Ok(escaped)
    }

    fn int_sum(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        sum(arguments, context, self, true)
    }

    fn long_sum(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        sum(arguments, context, self, false)
    }

    fn test_plan_name_function(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        check_count("__TestPlanName", arguments, 0, 0)?;
        let capability_supplied =
            self.test_plan_name.is_some() || context.has_test_plan_name_capability();
        match self.test_plan_name(context) {
            Some(name) => Ok(name),
            None if capability_supplied => {
                Ok("Save Test plan before calling __TestPlanName function".to_owned())
            }
            None => Err(FunctionError::unsupported(
                "test-plan-name capability is unavailable (the plan may not be saved)",
            )),
        }
    }

    fn eval_var(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        check_count("__evalVar", arguments, 1, 1)?;
        let value = self
            .variable_value(context, &arguments[0])?
            .unwrap_or_default();
        context.evaluate_nested(&value)
    }

    fn is_prop_defined(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        check_count("__isPropDefined", arguments, 1, 1)?;
        Ok(self
            .property_value(context, &arguments[0])?
            .is_some()
            .to_string())
    }

    fn is_var_defined(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        check_count("__isVarDefined", arguments, 1, 1)?;
        Ok(self
            .variable_value(context, &arguments[0])?
            .is_some()
            .to_string())
    }

    fn random(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        check_count("__Random", arguments, 2, 3)?;
        ensure_optional_variable_mutation(self, context, arguments.get(2))?;
        let minimum = parse_i64("__Random", &arguments[0])?;
        let maximum = parse_i64("__Random", &arguments[1])?;
        if minimum > maximum {
            return Err(FunctionError::invalid_arguments(
                "__Random minimum must not exceed maximum",
            ));
        }
        // JMeter passes `max + 1` to ThreadLocalRandom.nextLong.  The
        // addition is performed in Java `long` arithmetic, so Long.MAX_VALUE
        // wraps to Long.MIN_VALUE and the upstream call rejects the range
        // instead of representing the full signed domain.
        if maximum == i64::MAX {
            return Err(FunctionError::invalid_arguments(
                "__Random maximum is outside JMeter's exclusive-bound range",
            ));
        }
        let mut next = || self.next_random_u64(context);
        let value = uniform_inclusive(&mut next, minimum, maximum)?;
        let value = value.to_string();
        set_optional_variable(self, context, arguments.get(2), &value)?;
        Ok(value)
    }

    fn random_date(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        check_count("__RandomDate", arguments, 3, 5)?;
        ensure_optional_variable_mutation(self, context, arguments.get(4))?;
        let format = if java_trim(&arguments[0]).is_empty() {
            "yyyy-MM-dd"
        } else {
            java_trim(&arguments[0])
        };
        let date_start = java_trim(&arguments[1]);
        let locale = if arguments
            .get(3)
            .is_none_or(|value| java_trim(value).is_empty())
        {
            // JMeter uses the process default locale here. The pure boundary
            // supplies a deterministic en_US fallback, while a clock's
            // explicit locale remains available when the start date is
            // omitted and the clock is already required for today's date.
            if date_start.is_empty() || self.clock.is_some() || context.clock().is_some() {
                self.clock_locale(context)?
            } else {
                Locale::EnUs
            }
        } else {
            locale_from(arguments.get(3).map(String::as_str))?
        };
        let default_year = if date_start.is_empty() || !date_pattern_has_year(format) {
            let (now, offset) = self.clock_values(context)?;
            Some(civil_from_days(local_epoch_day(now, offset)?).0)
        } else {
            None
        };
        let start_day = if date_start.is_empty() {
            let (now, offset) = self.clock_values(context)?;
            local_epoch_day(now, offset)?
        } else {
            parse_datetime_with_year_offset(format, date_start, locale, 0, default_year)?
                .div_euclid(86_400_000)
        };
        if arguments[2].is_empty() {
            return Err(FunctionError::invalid_arguments(
                "__RandomDate requires an end date",
            ));
        }
        let end_day = parse_datetime_with_year_offset(
            format,
            java_trim(&arguments[2]),
            locale,
            0,
            default_year,
        )?
        .div_euclid(86_400_000);
        if start_day >= end_day {
            return Err(FunctionError::invalid_arguments(
                "__RandomDate start date must be before the exclusive end date",
            ));
        }
        // JMeter's RandomDate is LocalDate-based: the requested length is a
        // number of calendar days, not a millisecond interval.  Sampling the
        // epoch-day range also keeps the end date exclusive when the format
        // omits a time component.
        let mut next = || self.next_random_u64(context);
        let day = uniform_exclusive(&mut next, start_day, end_day)?;
        let millis = day
            .checked_mul(86_400_000)
            .ok_or_else(|| FunctionError::execution("random date overflowed epoch range"))?;
        let value = format_datetime(millis, format, locale, context.max_output_bytes())?;
        set_optional_variable(self, context, arguments.get(4), &value)?;
        Ok(value)
    }

    fn random_from_multiple_vars(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        check_count("__RandomFromMultipleVars", arguments, 1, 2)?;
        ensure_optional_variable_mutation(self, context, arguments.get(1))?;
        let mut values = Vec::new();
        // JMeter trims the complete source argument once, then splits on the
        // literal pipe. It does not trim each variable name after splitting.
        // This distinction is observable for variable names that themselves
        // contain spaces and must not be normalized at the expression layer.
        for variable in java_trim(&arguments[0]).split('|') {
            if variable.is_empty() {
                continue;
            }
            let match_count_value = self.variable_value(context, &format!("{variable}_matchNr"))?;
            // JMeter parses _matchNr with Integer.parseInt without trimming.
            // A missing, zero, or negative count falls back to the scalar
            // variable; only a positive count selects numbered candidates.
            let match_count = match_count_value
                .as_deref()
                .filter(|value| !value.is_empty())
                .map(|value| {
                    value.parse::<i32>().map(i64::from).map_err(|_| {
                        FunctionError::invalid_arguments(format!(
                            "__RandomFromMultipleVars has an invalid {variable}_matchNr"
                        ))
                    })
                })
                .transpose()?;
            if let Some(match_count) = match_count.filter(|count| *count > 0) {
                let match_count = usize::try_from(match_count).map_err(|_| {
                    FunctionError::invalid_arguments(
                        "__RandomFromMultipleVars matchNr exceeds the function bound",
                    )
                })?;
                if match_count > MAX_RANDOM_VALUES {
                    return Err(FunctionError::invalid_arguments(
                        "__RandomFromMultipleVars matchNr exceeds the function bound",
                    ));
                }
                for index in 1..=match_count {
                    let value_name = format!("{variable}_{index}");
                    let value = self.variable_value(context, &value_name)?.ok_or_else(|| {
                        FunctionError::unsupported(format!(
                            "__RandomFromMultipleVars candidate variable {value_name} is unavailable"
                        ))
                    })?;
                    if values.len() == MAX_RANDOM_VALUES {
                        return Err(FunctionError::invalid_arguments(
                            "__RandomFromMultipleVars has too many candidate values",
                        ));
                    }
                    // A numbered JMeter variable may intentionally be empty;
                    // StringUtils.isEmpty is only used for the scalar
                    // fallback. Preserve the empty candidate in the random
                    // list instead of silently dropping it.
                    values.push(value);
                }
            } else if let Some(value) = self
                .variable_value(context, variable)?
                .filter(|value| !value.is_empty())
            {
                if values.len() == MAX_RANDOM_VALUES {
                    return Err(FunctionError::invalid_arguments(
                        "__RandomFromMultipleVars has too many candidate values",
                    ));
                }
                values.push(value);
            }
        }
        if values.is_empty() {
            set_optional_variable(self, context, arguments.get(1), "")?;
            return Ok(String::new());
        }
        let mut next = || self.next_random_u64(context);
        let index = uniform_below(&mut next, values.len() as u64)? as usize;
        let value = &values[index];
        set_optional_variable(self, context, arguments.get(1), value)?;
        Ok(value.clone())
    }

    fn random_string(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        check_count("__RandomString", arguments, 1, 3)?;
        ensure_optional_variable_mutation(self, context, arguments.get(2))?;
        let length = parse_usize("__RandomString", &arguments[0])?;
        if length > i32::MAX as usize {
            return Err(FunctionError::invalid_arguments(
                "__RandomString length exceeds JMeter's integer bound",
            ));
        }
        let chars = arguments
            .get(1)
            .map(|value| java_trim(value))
            .filter(|value| !value.is_empty());
        let max_character_bytes = chars.map_or(4, |value| {
            value.chars().map(char::len_utf8).max().unwrap_or(0)
        });
        if length > 0 && chars.is_some_and(|value| value.is_empty()) {
            return Err(FunctionError::invalid_arguments(
                "__RandomString character set must not be empty",
            ));
        }
        // Every Java character unit contributes at least one UTF-8 byte at
        // this boundary, so this lower-bound check rejects impossible sizes
        // without rejecting an ASCII result merely because a custom alphabet
        // could contain four-byte scalars.  The exact result is checked on
        // every append below.
        if length > context.max_output_bytes() {
            return Err(FunctionError::execution(
                "__RandomString result exceeds the expression output bound",
            ));
        }
        let mut value = String::with_capacity(
            length
                .saturating_mul(max_character_bytes)
                .min(context.max_output_bytes()),
        );
        let mut next = || self.next_random_u64(context);
        if let Some(chars) = chars {
            let units: Vec<u16> = chars.encode_utf16().collect();
            for _ in 0..length {
                let index = uniform_below(&mut next, units.len() as u64)? as usize;
                let character = char::from_u32(u32::from(units[index])).ok_or_else(|| {
                    FunctionError::unsupported(
                        "__RandomString selected a UTF-16 surrogate that Rust cannot represent",
                    )
                })?;
                if value
                    .len()
                    .checked_add(character.len_utf8())
                    .is_none_or(|length| length > context.max_output_bytes())
                {
                    return Err(FunctionError::execution(
                        "__RandomString result exceeds the expression output bound",
                    ));
                }
                value.push(character);
            }
        } else {
            let mut remaining = length;
            while remaining > 0 {
                let mut accepted = None;
                for _ in 0..MAX_RANDOM_REJECTIONS {
                    let code_point = uniform_below(&mut next, 0x10_FF_FF)? as u32;
                    let Some(character) = char::from_u32(code_point) else {
                        continue;
                    };
                    if is_disallowed_random_code_point(code_point)
                        || character.len_utf16() > remaining
                    {
                        continue;
                    }
                    accepted = Some(character);
                    break;
                }
                let Some(character) = accepted else {
                    return Err(FunctionError::execution(
                        "__RandomString random source rejection limit exceeded",
                    ));
                };
                if value
                    .len()
                    .checked_add(character.len_utf8())
                    .is_none_or(|length| length > context.max_output_bytes())
                {
                    return Err(FunctionError::execution(
                        "__RandomString result exceeds the expression output bound",
                    ));
                }
                value.push(character);
                remaining -= character.len_utf16();
            }
        }
        set_optional_variable(self, context, arguments.get(2), &value)?;
        Ok(value)
    }

    fn uuid(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        check_count("__UUID", arguments, 0, 0)?;
        let mut bytes = [0_u8; 16];
        for chunk in bytes.chunks_exact_mut(8) {
            chunk.copy_from_slice(&self.next_random_u64(context)?.to_be_bytes());
        }
        // RFC 4122 version 4 and variant bits.
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Ok(format_uuid(bytes))
    }

    fn counter(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        check_count("__counter", arguments, 1, 2)?;
        let per_user = parse_bool("__counter", &arguments[0])?;
        // Validate the optional write capability before touching the shared
        // counter state. A failed capability lookup must not consume a
        // counter value.
        ensure_optional_variable_mutation(self, context, arguments.get(1))?;
        let execution = context.execution_context().or(self.execution.as_deref());
        let iteration = execution
            .and_then(ExecutionContext::iteration_identity)
            .ok_or_else(|| {
                FunctionError::unsupported(
                    "__counter requires an explicit virtual-user iteration identity",
                )
            })?;
        let thread = if per_user {
            self.thread_num_value(context).map_err(|_| {
                FunctionError::unsupported("per-user counter requires execution thread identity")
            })?
        } else {
            0
        };
        let (group, lifecycle, thread) = if per_user {
            let group = execution
                .and_then(ExecutionContext::thread_group_name)
                .unwrap_or_default();
            if group.len() > MAX_COUNTER_GROUP_BYTES {
                return Err(FunctionError::resource_limit(
                    "__counter thread-group identity exceeds its byte bound",
                ));
            }
            (
                group,
                execution
                    .and_then(ExecutionContext::lifecycle_id)
                    .unwrap_or(0),
                thread,
            )
        } else {
            // IterationCounter's global AtomicInteger is shared by all
            // threads and groups for one function occurrence.  Do not leak
            // the caller's group/lifecycle into the global key.
            (String::new(), 0, 0)
        };
        let scope = (
            per_user,
            group,
            lifecycle,
            thread,
            context.function_occurrence().clone(),
        );
        let value = {
            let mut counters = self
                .counters
                .lock()
                .map_err(|_| FunctionError::poisoned("counter state lock is poisoned"))?;
            let cache_key = (scope.clone(), iteration);
            if let Some(value) = counters.cached_values.get(&cache_key) {
                *value
            } else {
                if !counters.next_values.contains_key(&scope)
                    && counters.next_values.len() >= MAX_COUNTER_ENTRIES
                {
                    return Err(FunctionError::resource_limit(
                        "__counter occurrence capacity exhausted",
                    ));
                }
                if counters.cached_values.len() >= MAX_COUNTER_ENTRIES {
                    return Err(FunctionError::resource_limit(
                        "__counter iteration cache capacity exhausted",
                    ));
                }
                let count = counters.next_values.entry(scope.clone()).or_insert(0);
                *count = count.wrapping_add(1);
                let value = *count;
                counters.cached_values.insert(cache_key, value);
                value
            }
        }
        .to_string();
        set_optional_variable(self, context, arguments.get(1), &value)?;
        Ok(value)
    }

    fn date_time_convert(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        check_count("__dateTimeConvert", arguments, 3, 4)?;
        ensure_optional_variable_mutation(self, context, arguments.get(3))?;
        self.require_clock(context)?;
        let locale = self.clock_locale(context)?;
        let offset = self.clock_offset(context);
        let source_format = arguments[1].as_str();
        let millis = if source_format.is_empty() {
            parse_i64("__dateTimeConvert", &arguments[0])?
        } else {
            parse_datetime_with_offset(source_format, &arguments[0], locale, offset)?
        };
        let value = format_datetime_with_offset(
            millis,
            &arguments[2],
            locale,
            offset,
            context.max_output_bytes(),
        )?;
        set_optional_variable(self, context, arguments.get(3), &value)?;
        Ok(value)
    }

    fn digest(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        check_count("__digest", arguments, 2, 5)?;
        ensure_optional_variable_mutation(self, context, arguments.get(4))?;
        // MessageDigest algorithm lookup is case-insensitive, but aliases
        // remain provider-defined. The JDK provider used by the pinned
        // JMeter release exposes SHA/SHA1 as aliases for SHA-1; it does not
        // expose the tempting SHA256/SHA512 spellings. Keep that boundary
        // explicit instead of accepting Rust-only aliases.
        let algorithm = arguments[0].as_str();
        let mut bytes = arguments[1].as_bytes().to_vec();
        if let Some(salt) = arguments.get(2).filter(|salt| !salt.is_empty()) {
            bytes.extend_from_slice(salt.as_bytes());
        }
        let digest = digest_bytes(algorithm, &bytes)?;
        let uppercase = arguments
            .get(3)
            .map_or(Ok(false), |value| parse_bool("__digest", value))?;
        let value = hex_bytes(&digest, uppercase);
        set_optional_variable(self, context, arguments.get(4), &value)?;
        Ok(value)
    }

    fn log(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
        empty_result: bool,
    ) -> Result<String, FunctionError> {
        check_count(
            if empty_result { "__logn" } else { "__log" },
            arguments,
            1,
            if empty_result { 3 } else { 4 },
        )?;
        let level = arguments.get(1).map_or_else(
            || "INFO".to_owned(),
            |value| {
                if value.is_empty() {
                    "INFO".to_owned()
                } else {
                    java_trim(value).to_ascii_uppercase()
                }
            },
        );
        // JMeter sends unrecognized priorities to DEBUG after trimming and
        // uppercasing; they are not invalid arguments.
        let level = match level.as_str() {
            "OUT" | "ERR" | "DEBUG" | "INFO" | "WARN" | "ERROR" | "TRACE" => level,
            _ => "DEBUG".to_owned(),
        };
        let throwable = if empty_result {
            arguments.get(2).map(String::as_str)
        } else {
            arguments
                .get(2)
                .filter(|value| !value.is_empty())
                .map(String::as_str)
        };
        let comment = if empty_result {
            None
        } else {
            arguments.get(3).map(String::as_str)
        };
        self.log_value(context, &level, &arguments[0], throwable, comment)?;
        if empty_result {
            Ok(String::new())
        } else {
            Ok(arguments[0].clone())
        }
    }

    fn machine_name(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        check_count("__machineName", arguments, 0, 1)?;
        ensure_optional_variable_mutation(self, context, arguments.first())?;
        let value = self.machine_name_value(context)?;
        set_optional_variable(self, context, arguments.first(), &value)?;
        Ok(value)
    }

    fn machine_ip(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        check_count("__machineIP", arguments, 0, 1)?;
        ensure_optional_variable_mutation(self, context, arguments.first())?;
        let value = self.machine_ip_value(context)?;
        set_optional_variable(self, context, arguments.first(), &value)?;
        Ok(value)
    }

    fn thread_num(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        check_count("__threadNum", arguments, 0, 0)?;
        Ok(self.thread_num_value(context)?.to_string())
    }

    fn thread_group_name(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        check_count("__threadGroupName", arguments, 0, 0)?;
        self.thread_group_name_value(context)
    }

    fn sampler_name(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        check_count("__samplerName", arguments, 0, 1)?;
        ensure_optional_variable_mutation(self, context, arguments.first())?;
        let value = self.sampler_name_value(context)?;
        set_optional_variable(self, context, arguments.first(), &value)?;
        Ok(value)
    }

    fn time(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        check_count("__time", arguments, 0, 2)?;
        ensure_optional_variable_mutation(self, context, arguments.get(1))?;
        let (millis, offset) = self.clock_values(context)?;
        let format = arguments.first().map_or("", String::as_str);
        let value = if format.is_empty() {
            millis.to_string()
        } else if let Some(divisor) = format.strip_prefix('/') {
            if divisor.is_empty() || !divisor.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(FunctionError::invalid_arguments(
                    "__time divisor must be decimal digits",
                ));
            }
            let divisor = divisor.parse::<i64>().map_err(|_| {
                FunctionError::invalid_arguments("__time divisor must be decimal digits")
            })?;
            if divisor == 0 {
                return Err(FunctionError::invalid_arguments(
                    "__time divisor must be non-zero",
                ));
            }
            millis
                .checked_div(divisor)
                .ok_or_else(|| FunctionError::execution("__time divisor overflowed epoch range"))?
                .to_string()
        } else {
            let format = time_alias(self, context, format)?;
            format_datetime_with_offset(
                millis,
                &format,
                self.clock_locale(context)?,
                offset,
                context.max_output_bytes(),
            )?
        };
        set_optional_variable(self, context, arguments.get(1), &value)?;
        Ok(value)
    }

    fn time_shift(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        // TimeShift's Java implementation requires the four positional
        // arguments (format, date, amount, variable), with a fifth locale
        // slot only when explicitly requested. Empty values are how callers
        // select the defaults; omitting the positions is not equivalent.
        check_count("__timeShift", arguments, 4, 5)?;
        let format = arguments.first().map_or("", |value| java_trim(value));
        let date = arguments.get(1).map_or("", |value| java_trim(value));
        let (locale_argument, variable_argument) = if arguments.len() == 4 {
            (None, arguments.get(3))
        } else {
            (arguments.get(3), arguments.get(4))
        };
        ensure_optional_variable_mutation(self, context, variable_argument)?;
        let locale = if locale_argument.is_none_or(|value| java_trim(value).is_empty()) {
            if format.is_empty() && !date.is_empty() {
                Locale::EnUs
            } else {
                self.clock_locale(context)?
            }
        } else {
            locale_from(locale_argument.map(String::as_str))?
        };
        if !format.is_empty() {
            self.require_clock(context)?;
        }
        let millis = if date.is_empty() {
            self.clock_values(context)?.0
        } else if format.is_empty() {
            parse_i64("__timeShift", date)?
        } else {
            parse_datetime_with_year_offset(
                format,
                date,
                locale,
                self.clock_offset(context),
                Some(self.clock_year(context)?),
            )?
        };
        let shift_argument = arguments.get(2).map_or("", |value| java_trim(value));
        let shift = if shift_argument.is_empty() {
            0
        } else {
            parse_duration_millis(shift_argument)?
        };
        let shifted = millis
            .checked_add(shift)
            .ok_or_else(|| FunctionError::execution("__timeShift overflowed epoch range"))?;
        let value = if format.is_empty() {
            shifted.to_string()
        } else {
            format_datetime_with_offset(
                shifted,
                format,
                locale,
                self.clock_offset(context),
                context.max_output_bytes(),
            )?
        };
        set_optional_variable(self, context, variable_argument, &value)?;
        Ok(value)
    }

    fn split(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        check_count("__split", arguments, 2, 3)?;
        ensure_variable_mutation_available(self, context)?;
        let delimiters = arguments
            .get(2)
            .filter(|value| !value.is_empty())
            .map_or(",", String::as_str);
        let parts = split_jmeter(&arguments[0], delimiters);
        let prefix = java_trim(&arguments[1]);
        if parts.len() > MAX_VARIABLE_UPDATES {
            return Err(FunctionError::resource_limit(
                "__split produced too many variable updates",
            ));
        }
        let count = parts.len().to_string();
        let count_name = format!("{prefix}_n");
        let mut names = Vec::with_capacity(parts.len() + 2);
        names.push(prefix.to_owned());
        names.push(count_name);
        names.extend((1..=parts.len()).map(|index| format!("{prefix}_{index}")));
        let mut updates = Vec::with_capacity(names.len());
        updates.push((names[0].as_str(), arguments[0].as_str()));
        updates.push((names[1].as_str(), count.as_str()));
        updates.extend(
            parts
                .iter()
                .zip(names.iter().skip(2))
                .map(|(part, name)| (name.as_str(), part.as_str())),
        );
        set_variables_atomically(self, context, &updates)?;
        self.remove_variable(context, &format!("{prefix}_{}", parts.len() + 1))?;
        Ok(arguments[0].clone())
    }

    fn file_to_string(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        check_count("__FileToString", arguments, 1, 3)?;
        ensure_optional_variable_mutation(self, context, arguments.get(2))?;
        let encoding = arguments
            .get(1)
            .map(|value| java_trim(value))
            .filter(|value| !value.is_empty());
        let value = match self.file_read_to_string(context, arguments[0].as_str(), encoding) {
            Ok(value) => value,
            Err(error) => file_read_error_or_err(error)?,
        };
        ensure_function_output_bound(context, &value)?;
        set_optional_variable(self, context, arguments.get(2), &value)?;
        Ok(value)
    }

    fn string_from_file(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        check_count("__StringFromFile", arguments, 1, 4)?;
        if let Some(variable_argument) = arguments.get(1) {
            ensure_optional_variable_mutation(self, context, Some(variable_argument))?;
        } else {
            ensure_variable_mutation_available(self, context)?;
        }
        let key = arguments
            .get(1)
            .map_or(DEFAULT_STRING_FROM_FILE_VARIABLE, |value| java_trim(value));
        let start_sequence =
            parse_optional_sequence("__StringFromFile", arguments.get(2), "start sequence")?;
        let end_sequence =
            parse_optional_sequence("__StringFromFile", arguments.get(3), "end sequence")?;
        let value = match self.file_read_line(
            context,
            arguments[0].as_str(),
            key,
            context.function_occurrence(),
            start_sequence,
            end_sequence,
        ) {
            Ok(value) => value,
            Err(error) => file_read_error_or_err(error)?,
        };
        ensure_function_output_bound(context, &value)?;
        let variable_name = match arguments.get(1) {
            None => Some(DEFAULT_STRING_FROM_FILE_VARIABLE.to_owned()),
            Some(value) => {
                let value = java_trim(value);
                (!value.is_empty()).then(|| value.to_owned())
            }
        };
        if let Some(variable_name) = variable_name {
            set_optional_variable(self, context, Some(&variable_name), &value)?;
        }
        Ok(value)
    }

    fn string_to_file(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        check_count("__StringToFile", arguments, 2, 4)?;
        let append = arguments.get(2).is_none_or(|value| {
            let value = java_trim(value);
            if value.is_empty() {
                true
            } else {
                // JMeter trims the argument before delegating to
                // Boolean.parseBoolean; every non-"true" value is false.
                parse_bool("__StringToFile", value).unwrap_or(false)
            }
        });
        // StringToFile's Java implementation turns the two-character sequence
        // backslash+n into the host line separator before writing.  The pure
        // expression boundary uses LF as its stable wire separator; platform
        // adapters may translate it when committing bytes.
        let value = arguments[1].replace("\\n", "\n");
        let path = java_trim(&arguments[0]);
        if path.is_empty() {
            return Ok("false".to_owned());
        }
        match self.file_write_string(
            context,
            path,
            &value,
            append,
            arguments
                .get(3)
                .map(String::as_str)
                .filter(|encoding| !encoding.is_empty()),
        ) {
            Ok(()) => Ok("true".to_owned()),
            Err(error) => file_write_error_or_false(error),
        }
    }

    fn csv_read(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        check_count("__CSVRead", arguments, 2, 2)?;
        let selector = arguments[1].as_str();
        let delimiter = self
            .property_value(context, "csvread.delimiter")?
            .and_then(|value| value.chars().next())
            .unwrap_or(',');
        match self.file_read_csv(context, &arguments[0], selector, delimiter) {
            Ok(value) => {
                ensure_function_output_bound(context, &value)?;
                Ok(value)
            }
            Err(error) => file_read_error_or_empty(error),
        }
    }

    fn xpath(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        check_count("__XPath", arguments, 2, 2)?;
        self.xpath_value(context, arguments)
    }

    fn regex_function(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<String, FunctionError> {
        check_count("__regexFunction", arguments, 2, 7)?;
        if arguments.get(5).is_some_and(|value| !value.is_empty()) {
            ensure_variable_mutation_available(self, context)?;
        }
        let (value, captures) = self.regex_value(context, arguments)?;
        if value.len() > context.max_output_bytes() {
            return Err(FunctionError::execution(
                "__regexFunction result exceeds the expression output bound",
            ));
        }
        if let Some(prefix) = arguments.get(5).filter(|value| !value.is_empty()) {
            if captures.len() + 1 > MAX_VARIABLE_UPDATES {
                return Err(FunctionError::resource_limit(
                    "__regexFunction produced too many variable updates",
                ));
            }
            let mut names = Vec::with_capacity(captures.len() + 1);
            let mut values = Vec::with_capacity(captures.len() + 1);
            names.push(prefix.clone());
            values.push(value);
            for (name, capture) in captures {
                let variable_name = format!("{prefix}{name}");
                names.push(variable_name);
                values.push(capture);
            }
            let updates = names
                .iter()
                .zip(values.iter())
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect::<Vec<_>>();
            set_variables_atomically(self, context, &updates)?;
            return Ok(values[0].clone());
        }
        Ok(value)
    }

    fn script(
        &self,
        arguments: &[String],
        context: &FunctionContext<'_>,
        name: &str,
    ) -> Result<String, FunctionError> {
        check_count(name, arguments, 1, 2)?;
        ensure_optional_variable_mutation(self, context, arguments.get(1))?;
        let value = self.script_value(context, name, arguments)?;
        set_optional_variable(self, context, arguments.get(1), &value)?;
        Ok(value)
    }
}

fn check_count(
    name: &str,
    arguments: &[String],
    minimum: usize,
    maximum: usize,
) -> Result<(), FunctionError> {
    if arguments.len() < minimum || arguments.len() > maximum {
        return Err(FunctionError::invalid_arguments(format!(
            "{name} expects {minimum}..={maximum} arguments, got {}",
            arguments.len()
        )));
    }
    Ok(())
}

fn append_bounded_function_text(
    output: &mut String,
    segment: &str,
    output_limit: usize,
) -> Result<(), FunctionError> {
    let actual = output
        .len()
        .checked_add(segment.len())
        .ok_or_else(|| FunctionError::execution("function result size overflowed"))?;
    if actual > output_limit {
        return Err(FunctionError::execution(
            "function result exceeds the expression output bound",
        ));
    }
    output.push_str(segment);
    Ok(())
}

fn push_bounded_function_char(
    output: &mut String,
    character: char,
    output_limit: usize,
) -> Result<(), FunctionError> {
    let mut encoded = [0_u8; 4];
    append_bounded_function_text(output, character.encode_utf8(&mut encoded), output_limit)
}

const DEFAULT_STRING_FROM_FILE_VARIABLE: &str = "StringFromFile_";

fn split_jmeter(input: &str, delimiters: &str) -> Vec<String> {
    // JOrphanUtils.split delegates to StringTokenizer with returnDelims=true.
    // The delimiter argument is therefore a character set, not a literal
    // substring, and adjacent/trailing delimiters become the supplied `?`
    // default while leading delimiters are ignored.
    if delimiters.is_empty() {
        return vec![input.to_owned()];
    }
    let delimiter_set: std::collections::BTreeSet<char> = delimiters.chars().collect();
    let mut parts = Vec::new();
    let mut last_was_delimiter = false;
    let mut token = String::new();
    for character in input.chars() {
        if delimiter_set.contains(&character) {
            if !token.is_empty() {
                parts.push(std::mem::take(&mut token));
            }
            if last_was_delimiter {
                parts.push("?".to_owned());
            }
            last_was_delimiter = true;
        } else {
            token.push(character);
            last_was_delimiter = false;
        }
    }
    if !token.is_empty() {
        parts.push(token);
    } else if last_was_delimiter {
        parts.push("?".to_owned());
    }
    parts
}

fn parse_i64(name: &str, value: &str) -> Result<i64, FunctionError> {
    java_trim(value).parse::<i64>().map_err(|_| {
        FunctionError::invalid_arguments(format!("{name} expects a signed 64-bit integer"))
    })
}

fn parse_usize(name: &str, value: &str) -> Result<usize, FunctionError> {
    // RandomString delegates directly to Integer.parseInt; unlike the
    // numeric functions that explicitly call String.trim(), its length
    // argument preserves surrounding whitespace and therefore rejects it.
    let value = value.parse::<i32>().map_err(|_| {
        FunctionError::invalid_arguments(format!("{name} expects a non-negative integer"))
    })?;
    usize::try_from(value).map_err(|_| {
        FunctionError::invalid_arguments(format!("{name} expects a non-negative integer"))
    })
}

fn sum_requires_variable(arguments: &[String], integer: bool) -> bool {
    let Some(last) = arguments.last() else {
        return false;
    };
    let last = java_trim(last);
    if integer {
        last.parse::<i32>().is_err()
    } else {
        !last.is_empty() && last.parse::<i64>().is_err()
    }
}

fn random_date_requires_clock(arguments: &[String]) -> bool {
    arguments
        .get(1)
        .is_none_or(|value| java_trim(value).is_empty())
        || !date_pattern_has_year(arguments.first().map_or("yyyy-MM-dd", |value| {
            let value = java_trim(value);
            if value.is_empty() {
                "yyyy-MM-dd"
            } else {
                value
            }
        }))
}

fn date_pattern_has_year(pattern: &str) -> bool {
    let mut quoted = false;
    let mut chars = pattern.chars().peekable();
    while let Some(character) = chars.next() {
        if character == '\'' {
            if chars.peek() == Some(&'\'') {
                chars.next();
            } else {
                quoted = !quoted;
            }
        } else if !quoted && matches!(character, 'y' | 'u') {
            return true;
        }
    }
    false
}

fn is_private_use_code_point(value: u32) -> bool {
    matches!(value, 0xE000..=0xF8FF | 0xF0000..=0xFFFFD | 0x100000..=0x10FFFD)
}

fn is_known_unassigned_code_point(value: u32) -> bool {
    JAVA17_UNASSIGNED_RANGES
        .binary_search_by(|(start, end)| {
            if value < *start {
                std::cmp::Ordering::Greater
            } else if value > *end {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

// Generated from Java 17's Character.getType(cp) == Character.UNASSIGNED for
// every code point in 0..=Character.MAX_CODE_POINT. The profile recommends
// Java 17; keeping this table explicit prevents the native generator from
// silently accepting a code point that Commons Lang would reject.
const JAVA17_UNASSIGNED_RANGES: &[(u32, u32)] = &[
    (0x000378, 0x000379),
    (0x000380, 0x000383),
    (0x00038b, 0x00038b),
    (0x00038d, 0x00038d),
    (0x0003a2, 0x0003a2),
    (0x000530, 0x000530),
    (0x000557, 0x000558),
    (0x00058b, 0x00058c),
    (0x000590, 0x000590),
    (0x0005c8, 0x0005cf),
    (0x0005eb, 0x0005ee),
    (0x0005f5, 0x0005ff),
    (0x00061d, 0x00061d),
    (0x00070e, 0x00070e),
    (0x00074b, 0x00074c),
    (0x0007b2, 0x0007bf),
    (0x0007fb, 0x0007fc),
    (0x00082e, 0x00082f),
    (0x00083f, 0x00083f),
    (0x00085c, 0x00085d),
    (0x00085f, 0x00085f),
    (0x00086b, 0x00089f),
    (0x0008b5, 0x0008b5),
    (0x0008c8, 0x0008d2),
    (0x000984, 0x000984),
    (0x00098d, 0x00098e),
    (0x000991, 0x000992),
    (0x0009a9, 0x0009a9),
    (0x0009b1, 0x0009b1),
    (0x0009b3, 0x0009b5),
    (0x0009ba, 0x0009bb),
    (0x0009c5, 0x0009c6),
    (0x0009c9, 0x0009ca),
    (0x0009cf, 0x0009d6),
    (0x0009d8, 0x0009db),
    (0x0009de, 0x0009de),
    (0x0009e4, 0x0009e5),
    (0x0009ff, 0x000a00),
    (0x000a04, 0x000a04),
    (0x000a0b, 0x000a0e),
    (0x000a11, 0x000a12),
    (0x000a29, 0x000a29),
    (0x000a31, 0x000a31),
    (0x000a34, 0x000a34),
    (0x000a37, 0x000a37),
    (0x000a3a, 0x000a3b),
    (0x000a3d, 0x000a3d),
    (0x000a43, 0x000a46),
    (0x000a49, 0x000a4a),
    (0x000a4e, 0x000a50),
    (0x000a52, 0x000a58),
    (0x000a5d, 0x000a5d),
    (0x000a5f, 0x000a65),
    (0x000a77, 0x000a80),
    (0x000a84, 0x000a84),
    (0x000a8e, 0x000a8e),
    (0x000a92, 0x000a92),
    (0x000aa9, 0x000aa9),
    (0x000ab1, 0x000ab1),
    (0x000ab4, 0x000ab4),
    (0x000aba, 0x000abb),
    (0x000ac6, 0x000ac6),
    (0x000aca, 0x000aca),
    (0x000ace, 0x000acf),
    (0x000ad1, 0x000adf),
    (0x000ae4, 0x000ae5),
    (0x000af2, 0x000af8),
    (0x000b00, 0x000b00),
    (0x000b04, 0x000b04),
    (0x000b0d, 0x000b0e),
    (0x000b11, 0x000b12),
    (0x000b29, 0x000b29),
    (0x000b31, 0x000b31),
    (0x000b34, 0x000b34),
    (0x000b3a, 0x000b3b),
    (0x000b45, 0x000b46),
    (0x000b49, 0x000b4a),
    (0x000b4e, 0x000b54),
    (0x000b58, 0x000b5b),
    (0x000b5e, 0x000b5e),
    (0x000b64, 0x000b65),
    (0x000b78, 0x000b81),
    (0x000b84, 0x000b84),
    (0x000b8b, 0x000b8d),
    (0x000b91, 0x000b91),
    (0x000b96, 0x000b98),
    (0x000b9b, 0x000b9b),
    (0x000b9d, 0x000b9d),
    (0x000ba0, 0x000ba2),
    (0x000ba5, 0x000ba7),
    (0x000bab, 0x000bad),
    (0x000bba, 0x000bbd),
    (0x000bc3, 0x000bc5),
    (0x000bc9, 0x000bc9),
    (0x000bce, 0x000bcf),
    (0x000bd1, 0x000bd6),
    (0x000bd8, 0x000be5),
    (0x000bfb, 0x000bff),
    (0x000c0d, 0x000c0d),
    (0x000c11, 0x000c11),
    (0x000c29, 0x000c29),
    (0x000c3a, 0x000c3c),
    (0x000c45, 0x000c45),
    (0x000c49, 0x000c49),
    (0x000c4e, 0x000c54),
    (0x000c57, 0x000c57),
    (0x000c5b, 0x000c5f),
    (0x000c64, 0x000c65),
    (0x000c70, 0x000c76),
    (0x000c8d, 0x000c8d),
    (0x000c91, 0x000c91),
    (0x000ca9, 0x000ca9),
    (0x000cb4, 0x000cb4),
    (0x000cba, 0x000cbb),
    (0x000cc5, 0x000cc5),
    (0x000cc9, 0x000cc9),
    (0x000cce, 0x000cd4),
    (0x000cd7, 0x000cdd),
    (0x000cdf, 0x000cdf),
    (0x000ce4, 0x000ce5),
    (0x000cf0, 0x000cf0),
    (0x000cf3, 0x000cff),
    (0x000d0d, 0x000d0d),
    (0x000d11, 0x000d11),
    (0x000d45, 0x000d45),
    (0x000d49, 0x000d49),
    (0x000d50, 0x000d53),
    (0x000d64, 0x000d65),
    (0x000d80, 0x000d80),
    (0x000d84, 0x000d84),
    (0x000d97, 0x000d99),
    (0x000db2, 0x000db2),
    (0x000dbc, 0x000dbc),
    (0x000dbe, 0x000dbf),
    (0x000dc7, 0x000dc9),
    (0x000dcb, 0x000dce),
    (0x000dd5, 0x000dd5),
    (0x000dd7, 0x000dd7),
    (0x000de0, 0x000de5),
    (0x000df0, 0x000df1),
    (0x000df5, 0x000e00),
    (0x000e3b, 0x000e3e),
    (0x000e5c, 0x000e80),
    (0x000e83, 0x000e83),
    (0x000e85, 0x000e85),
    (0x000e8b, 0x000e8b),
    (0x000ea4, 0x000ea4),
    (0x000ea6, 0x000ea6),
    (0x000ebe, 0x000ebf),
    (0x000ec5, 0x000ec5),
    (0x000ec7, 0x000ec7),
    (0x000ece, 0x000ecf),
    (0x000eda, 0x000edb),
    (0x000ee0, 0x000eff),
    (0x000f48, 0x000f48),
    (0x000f6d, 0x000f70),
    (0x000f98, 0x000f98),
    (0x000fbd, 0x000fbd),
    (0x000fcd, 0x000fcd),
    (0x000fdb, 0x000fff),
    (0x0010c6, 0x0010c6),
    (0x0010c8, 0x0010cc),
    (0x0010ce, 0x0010cf),
    (0x001249, 0x001249),
    (0x00124e, 0x00124f),
    (0x001257, 0x001257),
    (0x001259, 0x001259),
    (0x00125e, 0x00125f),
    (0x001289, 0x001289),
    (0x00128e, 0x00128f),
    (0x0012b1, 0x0012b1),
    (0x0012b6, 0x0012b7),
    (0x0012bf, 0x0012bf),
    (0x0012c1, 0x0012c1),
    (0x0012c6, 0x0012c7),
    (0x0012d7, 0x0012d7),
    (0x001311, 0x001311),
    (0x001316, 0x001317),
    (0x00135b, 0x00135c),
    (0x00137d, 0x00137f),
    (0x00139a, 0x00139f),
    (0x0013f6, 0x0013f7),
    (0x0013fe, 0x0013ff),
    (0x00169d, 0x00169f),
    (0x0016f9, 0x0016ff),
    (0x00170d, 0x00170d),
    (0x001715, 0x00171f),
    (0x001737, 0x00173f),
    (0x001754, 0x00175f),
    (0x00176d, 0x00176d),
    (0x001771, 0x001771),
    (0x001774, 0x00177f),
    (0x0017de, 0x0017df),
    (0x0017ea, 0x0017ef),
    (0x0017fa, 0x0017ff),
    (0x00180f, 0x00180f),
    (0x00181a, 0x00181f),
    (0x001879, 0x00187f),
    (0x0018ab, 0x0018af),
    (0x0018f6, 0x0018ff),
    (0x00191f, 0x00191f),
    (0x00192c, 0x00192f),
    (0x00193c, 0x00193f),
    (0x001941, 0x001943),
    (0x00196e, 0x00196f),
    (0x001975, 0x00197f),
    (0x0019ac, 0x0019af),
    (0x0019ca, 0x0019cf),
    (0x0019db, 0x0019dd),
    (0x001a1c, 0x001a1d),
    (0x001a5f, 0x001a5f),
    (0x001a7d, 0x001a7e),
    (0x001a8a, 0x001a8f),
    (0x001a9a, 0x001a9f),
    (0x001aae, 0x001aaf),
    (0x001ac1, 0x001aff),
    (0x001b4c, 0x001b4f),
    (0x001b7d, 0x001b7f),
    (0x001bf4, 0x001bfb),
    (0x001c38, 0x001c3a),
    (0x001c4a, 0x001c4c),
    (0x001c89, 0x001c8f),
    (0x001cbb, 0x001cbc),
    (0x001cc8, 0x001ccf),
    (0x001cfb, 0x001cff),
    (0x001dfa, 0x001dfa),
    (0x001f16, 0x001f17),
    (0x001f1e, 0x001f1f),
    (0x001f46, 0x001f47),
    (0x001f4e, 0x001f4f),
    (0x001f58, 0x001f58),
    (0x001f5a, 0x001f5a),
    (0x001f5c, 0x001f5c),
    (0x001f5e, 0x001f5e),
    (0x001f7e, 0x001f7f),
    (0x001fb5, 0x001fb5),
    (0x001fc5, 0x001fc5),
    (0x001fd4, 0x001fd5),
    (0x001fdc, 0x001fdc),
    (0x001ff0, 0x001ff1),
    (0x001ff5, 0x001ff5),
    (0x001fff, 0x001fff),
    (0x002065, 0x002065),
    (0x002072, 0x002073),
    (0x00208f, 0x00208f),
    (0x00209d, 0x00209f),
    (0x0020c0, 0x0020cf),
    (0x0020f1, 0x0020ff),
    (0x00218c, 0x00218f),
    (0x002427, 0x00243f),
    (0x00244b, 0x00245f),
    (0x002b74, 0x002b75),
    (0x002b96, 0x002b96),
    (0x002c2f, 0x002c2f),
    (0x002c5f, 0x002c5f),
    (0x002cf4, 0x002cf8),
    (0x002d26, 0x002d26),
    (0x002d28, 0x002d2c),
    (0x002d2e, 0x002d2f),
    (0x002d68, 0x002d6e),
    (0x002d71, 0x002d7e),
    (0x002d97, 0x002d9f),
    (0x002da7, 0x002da7),
    (0x002daf, 0x002daf),
    (0x002db7, 0x002db7),
    (0x002dbf, 0x002dbf),
    (0x002dc7, 0x002dc7),
    (0x002dcf, 0x002dcf),
    (0x002dd7, 0x002dd7),
    (0x002ddf, 0x002ddf),
    (0x002e53, 0x002e7f),
    (0x002e9a, 0x002e9a),
    (0x002ef4, 0x002eff),
    (0x002fd6, 0x002fef),
    (0x002ffc, 0x002fff),
    (0x003040, 0x003040),
    (0x003097, 0x003098),
    (0x003100, 0x003104),
    (0x003130, 0x003130),
    (0x00318f, 0x00318f),
    (0x0031e4, 0x0031ef),
    (0x00321f, 0x00321f),
    (0x009ffd, 0x009fff),
    (0x00a48d, 0x00a48f),
    (0x00a4c7, 0x00a4cf),
    (0x00a62c, 0x00a63f),
    (0x00a6f8, 0x00a6ff),
    (0x00a7c0, 0x00a7c1),
    (0x00a7cb, 0x00a7f4),
    (0x00a82d, 0x00a82f),
    (0x00a83a, 0x00a83f),
    (0x00a878, 0x00a87f),
    (0x00a8c6, 0x00a8cd),
    (0x00a8da, 0x00a8df),
    (0x00a954, 0x00a95e),
    (0x00a97d, 0x00a97f),
    (0x00a9ce, 0x00a9ce),
    (0x00a9da, 0x00a9dd),
    (0x00a9ff, 0x00a9ff),
    (0x00aa37, 0x00aa3f),
    (0x00aa4e, 0x00aa4f),
    (0x00aa5a, 0x00aa5b),
    (0x00aac3, 0x00aada),
    (0x00aaf7, 0x00ab00),
    (0x00ab07, 0x00ab08),
    (0x00ab0f, 0x00ab10),
    (0x00ab17, 0x00ab1f),
    (0x00ab27, 0x00ab27),
    (0x00ab2f, 0x00ab2f),
    (0x00ab6c, 0x00ab6f),
    (0x00abee, 0x00abef),
    (0x00abfa, 0x00abff),
    (0x00d7a4, 0x00d7af),
    (0x00d7c7, 0x00d7ca),
    (0x00d7fc, 0x00d7ff),
    (0x00fa6e, 0x00fa6f),
    (0x00fada, 0x00faff),
    (0x00fb07, 0x00fb12),
    (0x00fb18, 0x00fb1c),
    (0x00fb37, 0x00fb37),
    (0x00fb3d, 0x00fb3d),
    (0x00fb3f, 0x00fb3f),
    (0x00fb42, 0x00fb42),
    (0x00fb45, 0x00fb45),
    (0x00fbc2, 0x00fbd2),
    (0x00fd40, 0x00fd4f),
    (0x00fd90, 0x00fd91),
    (0x00fdc8, 0x00fdef),
    (0x00fdfe, 0x00fdff),
    (0x00fe1a, 0x00fe1f),
    (0x00fe53, 0x00fe53),
    (0x00fe67, 0x00fe67),
    (0x00fe6c, 0x00fe6f),
    (0x00fe75, 0x00fe75),
    (0x00fefd, 0x00fefe),
    (0x00ff00, 0x00ff00),
    (0x00ffbf, 0x00ffc1),
    (0x00ffc8, 0x00ffc9),
    (0x00ffd0, 0x00ffd1),
    (0x00ffd8, 0x00ffd9),
    (0x00ffdd, 0x00ffdf),
    (0x00ffe7, 0x00ffe7),
    (0x00ffef, 0x00fff8),
    (0x00fffe, 0x00ffff),
    (0x01000c, 0x01000c),
    (0x010027, 0x010027),
    (0x01003b, 0x01003b),
    (0x01003e, 0x01003e),
    (0x01004e, 0x01004f),
    (0x01005e, 0x01007f),
    (0x0100fb, 0x0100ff),
    (0x010103, 0x010106),
    (0x010134, 0x010136),
    (0x01018f, 0x01018f),
    (0x01019d, 0x01019f),
    (0x0101a1, 0x0101cf),
    (0x0101fe, 0x01027f),
    (0x01029d, 0x01029f),
    (0x0102d1, 0x0102df),
    (0x0102fc, 0x0102ff),
    (0x010324, 0x01032c),
    (0x01034b, 0x01034f),
    (0x01037b, 0x01037f),
    (0x01039e, 0x01039e),
    (0x0103c4, 0x0103c7),
    (0x0103d6, 0x0103ff),
    (0x01049e, 0x01049f),
    (0x0104aa, 0x0104af),
    (0x0104d4, 0x0104d7),
    (0x0104fc, 0x0104ff),
    (0x010528, 0x01052f),
    (0x010564, 0x01056e),
    (0x010570, 0x0105ff),
    (0x010737, 0x01073f),
    (0x010756, 0x01075f),
    (0x010768, 0x0107ff),
    (0x010806, 0x010807),
    (0x010809, 0x010809),
    (0x010836, 0x010836),
    (0x010839, 0x01083b),
    (0x01083d, 0x01083e),
    (0x010856, 0x010856),
    (0x01089f, 0x0108a6),
    (0x0108b0, 0x0108df),
    (0x0108f3, 0x0108f3),
    (0x0108f6, 0x0108fa),
    (0x01091c, 0x01091e),
    (0x01093a, 0x01093e),
    (0x010940, 0x01097f),
    (0x0109b8, 0x0109bb),
    (0x0109d0, 0x0109d1),
    (0x010a04, 0x010a04),
    (0x010a07, 0x010a0b),
    (0x010a14, 0x010a14),
    (0x010a18, 0x010a18),
    (0x010a36, 0x010a37),
    (0x010a3b, 0x010a3e),
    (0x010a49, 0x010a4f),
    (0x010a59, 0x010a5f),
    (0x010aa0, 0x010abf),
    (0x010ae7, 0x010aea),
    (0x010af7, 0x010aff),
    (0x010b36, 0x010b38),
    (0x010b56, 0x010b57),
    (0x010b73, 0x010b77),
    (0x010b92, 0x010b98),
    (0x010b9d, 0x010ba8),
    (0x010bb0, 0x010bff),
    (0x010c49, 0x010c7f),
    (0x010cb3, 0x010cbf),
    (0x010cf3, 0x010cf9),
    (0x010d28, 0x010d2f),
    (0x010d3a, 0x010e5f),
    (0x010e7f, 0x010e7f),
    (0x010eaa, 0x010eaa),
    (0x010eae, 0x010eaf),
    (0x010eb2, 0x010eff),
    (0x010f28, 0x010f2f),
    (0x010f5a, 0x010faf),
    (0x010fcc, 0x010fdf),
    (0x010ff7, 0x010fff),
    (0x01104e, 0x011051),
    (0x011070, 0x01107e),
    (0x0110c2, 0x0110cc),
    (0x0110ce, 0x0110cf),
    (0x0110e9, 0x0110ef),
    (0x0110fa, 0x0110ff),
    (0x011135, 0x011135),
    (0x011148, 0x01114f),
    (0x011177, 0x01117f),
    (0x0111e0, 0x0111e0),
    (0x0111f5, 0x0111ff),
    (0x011212, 0x011212),
    (0x01123f, 0x01127f),
    (0x011287, 0x011287),
    (0x011289, 0x011289),
    (0x01128e, 0x01128e),
    (0x01129e, 0x01129e),
    (0x0112aa, 0x0112af),
    (0x0112eb, 0x0112ef),
    (0x0112fa, 0x0112ff),
    (0x011304, 0x011304),
    (0x01130d, 0x01130e),
    (0x011311, 0x011312),
    (0x011329, 0x011329),
    (0x011331, 0x011331),
    (0x011334, 0x011334),
    (0x01133a, 0x01133a),
    (0x011345, 0x011346),
    (0x011349, 0x01134a),
    (0x01134e, 0x01134f),
    (0x011351, 0x011356),
    (0x011358, 0x01135c),
    (0x011364, 0x011365),
    (0x01136d, 0x01136f),
    (0x011375, 0x0113ff),
    (0x01145c, 0x01145c),
    (0x011462, 0x01147f),
    (0x0114c8, 0x0114cf),
    (0x0114da, 0x01157f),
    (0x0115b6, 0x0115b7),
    (0x0115de, 0x0115ff),
    (0x011645, 0x01164f),
    (0x01165a, 0x01165f),
    (0x01166d, 0x01167f),
    (0x0116b9, 0x0116bf),
    (0x0116ca, 0x0116ff),
    (0x01171b, 0x01171c),
    (0x01172c, 0x01172f),
    (0x011740, 0x0117ff),
    (0x01183c, 0x01189f),
    (0x0118f3, 0x0118fe),
    (0x011907, 0x011908),
    (0x01190a, 0x01190b),
    (0x011914, 0x011914),
    (0x011917, 0x011917),
    (0x011936, 0x011936),
    (0x011939, 0x01193a),
    (0x011947, 0x01194f),
    (0x01195a, 0x01199f),
    (0x0119a8, 0x0119a9),
    (0x0119d8, 0x0119d9),
    (0x0119e5, 0x0119ff),
    (0x011a48, 0x011a4f),
    (0x011aa3, 0x011abf),
    (0x011af9, 0x011bff),
    (0x011c09, 0x011c09),
    (0x011c37, 0x011c37),
    (0x011c46, 0x011c4f),
    (0x011c6d, 0x011c6f),
    (0x011c90, 0x011c91),
    (0x011ca8, 0x011ca8),
    (0x011cb7, 0x011cff),
    (0x011d07, 0x011d07),
    (0x011d0a, 0x011d0a),
    (0x011d37, 0x011d39),
    (0x011d3b, 0x011d3b),
    (0x011d3e, 0x011d3e),
    (0x011d48, 0x011d4f),
    (0x011d5a, 0x011d5f),
    (0x011d66, 0x011d66),
    (0x011d69, 0x011d69),
    (0x011d8f, 0x011d8f),
    (0x011d92, 0x011d92),
    (0x011d99, 0x011d9f),
    (0x011daa, 0x011edf),
    (0x011ef9, 0x011faf),
    (0x011fb1, 0x011fbf),
    (0x011ff2, 0x011ffe),
    (0x01239a, 0x0123ff),
    (0x01246f, 0x01246f),
    (0x012475, 0x01247f),
    (0x012544, 0x012fff),
    (0x01342f, 0x01342f),
    (0x013439, 0x0143ff),
    (0x014647, 0x0167ff),
    (0x016a39, 0x016a3f),
    (0x016a5f, 0x016a5f),
    (0x016a6a, 0x016a6d),
    (0x016a70, 0x016acf),
    (0x016aee, 0x016aef),
    (0x016af6, 0x016aff),
    (0x016b46, 0x016b4f),
    (0x016b5a, 0x016b5a),
    (0x016b62, 0x016b62),
    (0x016b78, 0x016b7c),
    (0x016b90, 0x016e3f),
    (0x016e9b, 0x016eff),
    (0x016f4b, 0x016f4e),
    (0x016f88, 0x016f8e),
    (0x016fa0, 0x016fdf),
    (0x016fe5, 0x016fef),
    (0x016ff2, 0x016fff),
    (0x0187f8, 0x0187ff),
    (0x018cd6, 0x018cff),
    (0x018d09, 0x01afff),
    (0x01b11f, 0x01b14f),
    (0x01b153, 0x01b163),
    (0x01b168, 0x01b16f),
    (0x01b2fc, 0x01bbff),
    (0x01bc6b, 0x01bc6f),
    (0x01bc7d, 0x01bc7f),
    (0x01bc89, 0x01bc8f),
    (0x01bc9a, 0x01bc9b),
    (0x01bca4, 0x01cfff),
    (0x01d0f6, 0x01d0ff),
    (0x01d127, 0x01d128),
    (0x01d1e9, 0x01d1ff),
    (0x01d246, 0x01d2df),
    (0x01d2f4, 0x01d2ff),
    (0x01d357, 0x01d35f),
    (0x01d379, 0x01d3ff),
    (0x01d455, 0x01d455),
    (0x01d49d, 0x01d49d),
    (0x01d4a0, 0x01d4a1),
    (0x01d4a3, 0x01d4a4),
    (0x01d4a7, 0x01d4a8),
    (0x01d4ad, 0x01d4ad),
    (0x01d4ba, 0x01d4ba),
    (0x01d4bc, 0x01d4bc),
    (0x01d4c4, 0x01d4c4),
    (0x01d506, 0x01d506),
    (0x01d50b, 0x01d50c),
    (0x01d515, 0x01d515),
    (0x01d51d, 0x01d51d),
    (0x01d53a, 0x01d53a),
    (0x01d53f, 0x01d53f),
    (0x01d545, 0x01d545),
    (0x01d547, 0x01d549),
    (0x01d551, 0x01d551),
    (0x01d6a6, 0x01d6a7),
    (0x01d7cc, 0x01d7cd),
    (0x01da8c, 0x01da9a),
    (0x01daa0, 0x01daa0),
    (0x01dab0, 0x01dfff),
    (0x01e007, 0x01e007),
    (0x01e019, 0x01e01a),
    (0x01e022, 0x01e022),
    (0x01e025, 0x01e025),
    (0x01e02b, 0x01e0ff),
    (0x01e12d, 0x01e12f),
    (0x01e13e, 0x01e13f),
    (0x01e14a, 0x01e14d),
    (0x01e150, 0x01e2bf),
    (0x01e2fa, 0x01e2fe),
    (0x01e300, 0x01e7ff),
    (0x01e8c5, 0x01e8c6),
    (0x01e8d7, 0x01e8ff),
    (0x01e94c, 0x01e94f),
    (0x01e95a, 0x01e95d),
    (0x01e960, 0x01ec70),
    (0x01ecb5, 0x01ed00),
    (0x01ed3e, 0x01edff),
    (0x01ee04, 0x01ee04),
    (0x01ee20, 0x01ee20),
    (0x01ee23, 0x01ee23),
    (0x01ee25, 0x01ee26),
    (0x01ee28, 0x01ee28),
    (0x01ee33, 0x01ee33),
    (0x01ee38, 0x01ee38),
    (0x01ee3a, 0x01ee3a),
    (0x01ee3c, 0x01ee41),
    (0x01ee43, 0x01ee46),
    (0x01ee48, 0x01ee48),
    (0x01ee4a, 0x01ee4a),
    (0x01ee4c, 0x01ee4c),
    (0x01ee50, 0x01ee50),
    (0x01ee53, 0x01ee53),
    (0x01ee55, 0x01ee56),
    (0x01ee58, 0x01ee58),
    (0x01ee5a, 0x01ee5a),
    (0x01ee5c, 0x01ee5c),
    (0x01ee5e, 0x01ee5e),
    (0x01ee60, 0x01ee60),
    (0x01ee63, 0x01ee63),
    (0x01ee65, 0x01ee66),
    (0x01ee6b, 0x01ee6b),
    (0x01ee73, 0x01ee73),
    (0x01ee78, 0x01ee78),
    (0x01ee7d, 0x01ee7d),
    (0x01ee7f, 0x01ee7f),
    (0x01ee8a, 0x01ee8a),
    (0x01ee9c, 0x01eea0),
    (0x01eea4, 0x01eea4),
    (0x01eeaa, 0x01eeaa),
    (0x01eebc, 0x01eeef),
    (0x01eef2, 0x01efff),
    (0x01f02c, 0x01f02f),
    (0x01f094, 0x01f09f),
    (0x01f0af, 0x01f0b0),
    (0x01f0c0, 0x01f0c0),
    (0x01f0d0, 0x01f0d0),
    (0x01f0f6, 0x01f0ff),
    (0x01f1ae, 0x01f1e5),
    (0x01f203, 0x01f20f),
    (0x01f23c, 0x01f23f),
    (0x01f249, 0x01f24f),
    (0x01f252, 0x01f25f),
    (0x01f266, 0x01f2ff),
    (0x01f6d8, 0x01f6df),
    (0x01f6ed, 0x01f6ef),
    (0x01f6fd, 0x01f6ff),
    (0x01f774, 0x01f77f),
    (0x01f7d9, 0x01f7df),
    (0x01f7ec, 0x01f7ff),
    (0x01f80c, 0x01f80f),
    (0x01f848, 0x01f84f),
    (0x01f85a, 0x01f85f),
    (0x01f888, 0x01f88f),
    (0x01f8ae, 0x01f8af),
    (0x01f8b2, 0x01f8ff),
    (0x01f979, 0x01f979),
    (0x01f9cc, 0x01f9cc),
    (0x01fa54, 0x01fa5f),
    (0x01fa6e, 0x01fa6f),
    (0x01fa75, 0x01fa77),
    (0x01fa7b, 0x01fa7f),
    (0x01fa87, 0x01fa8f),
    (0x01faa9, 0x01faaf),
    (0x01fab7, 0x01fabf),
    (0x01fac3, 0x01facf),
    (0x01fad7, 0x01faff),
    (0x01fb93, 0x01fb93),
    (0x01fbcb, 0x01fbef),
    (0x01fbfa, 0x01ffff),
    (0x02a6de, 0x02a6ff),
    (0x02b735, 0x02b73f),
    (0x02b81e, 0x02b81f),
    (0x02cea2, 0x02ceaf),
    (0x02ebe1, 0x02f7ff),
    (0x02fa1e, 0x02ffff),
    (0x03134b, 0x0e0000),
    (0x0e0002, 0x0e001f),
    (0x0e0080, 0x0e00ff),
    (0x0e01f0, 0x0effff),
    (0x0ffffe, 0x0fffff),
    (0x10fffe, 0x10ffff),
];

fn is_disallowed_random_code_point(value: u32) -> bool {
    // Commons Lang checks Character.getType and rejects only unassigned,
    // private-use, and surrogate code points.  Control characters are valid
    // candidates for RandomStringUtils.random(count), so do not apply an
    // ASCII-printability filter here.
    is_known_unassigned_code_point(value)
        || is_private_use_code_point(value)
        || matches!(value, 0xD800..=0xDFFF)
}

fn parse_bool(name: &str, value: &str) -> Result<bool, FunctionError> {
    // JMeter delegates these flags to java.lang.Boolean.parseBoolean:
    // comparison is case-insensitive and every non-"true" value is false.
    // Keep the name parameter for a stable call-site signature and diagnostics
    // should a stricter flag be introduced later.
    let _ = name;
    Ok(value.eq_ignore_ascii_case("true"))
}

fn ensure_function_output_bound(
    context: &FunctionContext<'_>,
    value: &str,
) -> Result<(), FunctionError> {
    if value.len() > context.max_output_bytes() {
        return Err(FunctionError::execution(
            "function result exceeds the expression output bound",
        ));
    }
    Ok(())
}

fn file_read_error_or_err(error: FunctionError) -> Result<String, FunctionError> {
    match error {
        // Capability and control-boundary failures must remain typed. Mapping
        // them to JMeter's ordinary I/O marker would silently turn an
        // unavailable/limited adapter into a successful-looking result.
        FunctionError::Unsupported(message) => Err(FunctionError::Unsupported(message)),
        FunctionError::StopThread(message) => Err(FunctionError::StopThread(message)),
        FunctionError::ResourceLimit(message) => Err(FunctionError::ResourceLimit(message)),
        FunctionError::Poisoned(message) => Err(FunctionError::Poisoned(message)),
        _ => Ok("**ERR**".to_owned()),
    }
}

fn file_read_error_or_empty(error: FunctionError) -> Result<String, FunctionError> {
    match error {
        FunctionError::Unsupported(message) => Err(FunctionError::Unsupported(message)),
        FunctionError::StopThread(message) => Err(FunctionError::StopThread(message)),
        FunctionError::ResourceLimit(message) => Err(FunctionError::ResourceLimit(message)),
        FunctionError::Poisoned(message) => Err(FunctionError::Poisoned(message)),
        _ => Ok(String::new()),
    }
}

fn file_write_error_or_false(error: FunctionError) -> Result<String, FunctionError> {
    match error {
        FunctionError::Unsupported(message) => Err(FunctionError::Unsupported(message)),
        FunctionError::StopThread(message) => Err(FunctionError::StopThread(message)),
        FunctionError::ResourceLimit(message) => Err(FunctionError::ResourceLimit(message)),
        FunctionError::Poisoned(message) => Err(FunctionError::Poisoned(message)),
        _ => Ok("false".to_owned()),
    }
}

fn set_optional_variable(
    registry: &BuiltinFunctions,
    context: &FunctionContext<'_>,
    name: Option<&String>,
    value: &str,
) -> Result<(), FunctionError> {
    if value.len() > context.max_output_bytes() {
        return Err(FunctionError::execution(
            "variable value exceeds the expression output bound",
        ));
    }
    ensure_optional_variable_mutation(registry, context, name)?;
    if let Some(name) = name {
        let name = java_trim(name);
        if !name.is_empty() {
            registry.set_variable(context, name, value)?;
        }
    }
    Ok(())
}

fn set_variables_atomically(
    registry: &BuiltinFunctions,
    context: &FunctionContext<'_>,
    values: &[(&str, &str)],
) -> Result<(), FunctionError> {
    if values.iter().any(|(name, value)| {
        name.len() > context.max_output_bytes() || value.len() > context.max_output_bytes()
    }) {
        return Err(FunctionError::execution(
            "variable mutation exceeds the expression output bound",
        ));
    }
    registry.set_variables_atomic(context, values)
}

fn ensure_optional_variable_mutation(
    registry: &BuiltinFunctions,
    context: &FunctionContext<'_>,
    name: Option<&String>,
) -> Result<(), FunctionError> {
    if name
        .map(|value| !java_trim(value).is_empty())
        .unwrap_or(false)
    {
        ensure_variable_mutation_available(registry, context)?;
    }
    Ok(())
}

fn ensure_variable_mutation_available(
    registry: &BuiltinFunctions,
    context: &FunctionContext<'_>,
) -> Result<(), FunctionError> {
    if registry.variable_setter.is_none() && !context.has_variable_setter() {
        return Err(FunctionError::unsupported(
            "variable mutation capability is unavailable",
        ));
    }
    Ok(())
}

fn uniform_below(
    next: &mut impl FnMut() -> Result<u64, FunctionError>,
    upper: u64,
) -> Result<u64, FunctionError> {
    if upper == 0 {
        return Err(FunctionError::execution("random source range is empty"));
    }
    let threshold = upper.wrapping_neg() % upper;
    const MAX_REJECTIONS: usize = 1024;
    for _ in 0..MAX_REJECTIONS {
        let value = next()?;
        if value >= threshold {
            return Ok(value % upper);
        }
    }
    Err(FunctionError::execution(
        "random source rejection limit exceeded",
    ))
}

fn uniform_inclusive(
    next: &mut impl FnMut() -> Result<u64, FunctionError>,
    minimum: i64,
    maximum: i64,
) -> Result<i64, FunctionError> {
    let span = (i128::from(maximum) - i128::from(minimum) + 1) as u128;
    let value = if span == 1_u128 << 64 {
        next()? as u128
    } else {
        uniform_below(next, span as u64)? as u128
    };
    let result = i128::from(minimum) + value as i128;
    i64::try_from(result).map_err(|_| FunctionError::execution("random source result overflowed"))
}

fn uniform_exclusive(
    next: &mut impl FnMut() -> Result<u64, FunctionError>,
    minimum: i64,
    maximum_exclusive: i64,
) -> Result<i64, FunctionError> {
    if minimum >= maximum_exclusive {
        return Err(FunctionError::invalid_arguments(
            "random exclusive range must be non-empty",
        ));
    }
    let span = (i128::from(maximum_exclusive) - i128::from(minimum)) as u128;
    let value = if span == 1_u128 << 64 {
        next()? as u128
    } else {
        uniform_below(next, span as u64)? as u128
    };
    let result = i128::from(minimum) + value as i128;
    i64::try_from(result).map_err(|_| FunctionError::execution("random source result overflowed"))
}

fn format_uuid(bytes: [u8; 16]) -> String {
    let mut result = String::with_capacity(36);
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            result.push('-');
        }
        result.push(hex_digit_lower(byte >> 4));
        result.push(hex_digit_lower(byte & 0x0f));
    }
    result
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Locale {
    EnUs,
    FrFr,
}

fn locale_from(value: Option<&str>) -> Result<Locale, FunctionError> {
    let value = java_trim(value.unwrap_or_default());
    if value.is_empty()
        || value.eq_ignore_ascii_case("en")
        || value.eq_ignore_ascii_case("en_us")
        || value.eq_ignore_ascii_case("en-us")
    {
        Ok(Locale::EnUs)
    } else if value.eq_ignore_ascii_case("fr")
        || value.eq_ignore_ascii_case("fr_fr")
        || value.eq_ignore_ascii_case("fr-fr")
    {
        Ok(Locale::FrFr)
    } else {
        Err(FunctionError::unsupported(format!(
            "date/time locale {value} is unavailable in the native evaluator"
        )))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DateFields {
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    millis: u32,
    offset_seconds: i32,
}

impl Default for DateFields {
    fn default() -> Self {
        Self {
            year: 1970,
            month: 1,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
            millis: 0,
            offset_seconds: 0,
        }
    }
}

fn parse_datetime_with_offset(
    format: &str,
    input: &str,
    locale: Locale,
    default_offset_seconds: i32,
) -> Result<i64, FunctionError> {
    parse_datetime_with_year_offset(format, input, locale, default_offset_seconds, None)
}

fn parse_datetime_with_year_offset(
    format: &str,
    input: &str,
    locale: Locale,
    default_offset_seconds: i32,
    default_year: Option<i64>,
) -> Result<i64, FunctionError> {
    if !format
        .chars()
        .any(|character| matches!(character, 'y' | 'u'))
        && default_year.is_none()
    {
        return Err(FunctionError::unsupported(
            "date patterns without an explicit year require a JVM clock/default-date adapter",
        ));
    }
    let mut fields = DateFields::default();
    if let Some(default_year) = default_year {
        fields.year = default_year;
    }
    fields.offset_seconds = default_offset_seconds;
    let mut input_index = 0usize;
    let pattern: Vec<char> = format.chars().collect();
    let mut pattern_index = 0usize;
    let mut am = None;
    let mut twelve_hour = None;
    while pattern_index < pattern.len() {
        let token = pattern[pattern_index];
        if token == '\'' {
            if pattern.get(pattern_index + 1) == Some(&'\'') {
                if input[input_index..].starts_with('\'') {
                    input_index += '\''.len_utf8();
                    pattern_index += 2;
                    continue;
                }
                return Err(FunctionError::invalid_arguments(
                    "date does not match a quoted apostrophe",
                ));
            }
            pattern_index += 1;
            let mut literal = String::new();
            while pattern_index < pattern.len() {
                if pattern[pattern_index] == '\'' {
                    if pattern.get(pattern_index + 1) == Some(&'\'') {
                        literal.push('\'');
                        pattern_index += 2;
                        continue;
                    }
                    break;
                }
                literal.push(pattern[pattern_index]);
                pattern_index += 1;
            }
            if pattern_index == pattern.len() {
                return Err(FunctionError::invalid_arguments(
                    "date format contains an unclosed quote",
                ));
            }
            if !input[input_index..].starts_with(&literal) {
                return Err(FunctionError::invalid_arguments(
                    "date does not match source format",
                ));
            }
            input_index += literal.len();
            pattern_index += 1;
            continue;
        }
        if token.is_ascii_alphabetic() {
            let token_start = pattern_index;
            while pattern_index < pattern.len() && pattern[pattern_index] == token {
                pattern_index += 1;
            }
            let width = pattern_index - token_start;
            let remaining = &input[input_index..];
            match token {
                'y' | 'u' => {
                    let (value, consumed) =
                        parse_decimal(remaining, if width == 2 { 2 } else { width }, width == 1)?;
                    fields.year = if width == 2 {
                        // java.time's reduced two-digit year parser uses a
                        // 2000 base for an `yy` pattern.
                        2000 + value
                    } else {
                        value
                    };
                    input_index += consumed;
                }
                'M' => {
                    if width >= 3 {
                        let (month, consumed) = parse_month_name(remaining, locale, width == 4)?;
                        fields.month = month;
                        input_index += consumed;
                    } else {
                        let (value, consumed) = parse_decimal(remaining, width, width == 1)?;
                        fields.month = u32::try_from(value).map_err(|_| {
                            FunctionError::invalid_arguments("month is outside the valid range")
                        })?;
                        input_index += consumed;
                    }
                }
                'd' => {
                    let (value, consumed) = parse_decimal(remaining, width, width == 1)?;
                    fields.day = u32::try_from(value).map_err(|_| {
                        FunctionError::invalid_arguments("day is outside the valid range")
                    })?;
                    input_index += consumed;
                }
                'H' => {
                    let (value, consumed) = parse_decimal(remaining, width, width == 1)?;
                    fields.hour = u32::try_from(value).map_err(|_| {
                        FunctionError::invalid_arguments("hour is outside the valid range")
                    })?;
                    input_index += consumed;
                }
                'k' => {
                    let (value, consumed) = parse_decimal(remaining, width, width == 1)?;
                    if !(1..=24).contains(&value) {
                        return Err(FunctionError::invalid_arguments(
                            "24-hour clock value is outside the valid range",
                        ));
                    }
                    fields.hour = if value == 24 { 0 } else { value as u32 };
                    input_index += consumed;
                }
                'h' => {
                    twelve_hour = Some(true);
                    let (value, consumed) = parse_decimal(remaining, width, width == 1)?;
                    fields.hour = u32::try_from(value).map_err(|_| {
                        FunctionError::invalid_arguments("hour is outside the valid range")
                    })?;
                    input_index += consumed;
                }
                'K' => {
                    twelve_hour = Some(false);
                    let (value, consumed) = parse_decimal(remaining, width, width == 1)?;
                    if !(0..=11).contains(&value) {
                        return Err(FunctionError::invalid_arguments(
                            "12-hour clock value is outside the valid range",
                        ));
                    }
                    fields.hour = value as u32;
                    input_index += consumed;
                }
                'm' => {
                    let (value, consumed) = parse_decimal(remaining, width, width == 1)?;
                    fields.minute = u32::try_from(value).map_err(|_| {
                        FunctionError::invalid_arguments("minute is outside the valid range")
                    })?;
                    input_index += consumed;
                }
                's' => {
                    let (value, consumed) = parse_decimal(remaining, width, width == 1)?;
                    fields.second = u32::try_from(value).map_err(|_| {
                        FunctionError::invalid_arguments("second is outside the valid range")
                    })?;
                    input_index += consumed;
                }
                'S' => {
                    if width > 3 {
                        return Err(FunctionError::unsupported(
                            "date format fractional seconds beyond milliseconds require a JVM time adapter",
                        ));
                    }
                    let (value, consumed) = parse_decimal(remaining, width, false)?;
                    let digits = u32::try_from(consumed)
                        .map_err(|_| FunctionError::invalid_arguments("fraction is too long"))?;
                    let fraction = u32::try_from(value)
                        .map_err(|_| FunctionError::invalid_arguments("fraction is too long"))?;
                    fields.millis = if digits <= 3 {
                        fraction * 10_u32.pow(3 - digits)
                    } else {
                        fraction / 10_u32.pow(digits - 3)
                    };
                    input_index += consumed;
                }
                'a' => {
                    let (meridiem, consumed) = parse_meridiem(remaining)?;
                    am = Some(meridiem);
                    input_index += consumed;
                }
                'E' => {
                    let consumed = parse_weekday(remaining, locale)?;
                    input_index += consumed;
                }
                'X' | 'x' | 'Z' => {
                    let (offset, consumed) = parse_offset(remaining, token, width)?;
                    fields.offset_seconds = offset;
                    input_index += consumed;
                }
                _ => {
                    return Err(FunctionError::unsupported(format!(
                        "unsupported date format token {token}"
                    )));
                }
            }
        } else {
            if !input[input_index..].starts_with(token) {
                return Err(FunctionError::invalid_arguments(
                    "date does not match source format",
                ));
            }
            input_index += token.len_utf8();
            pattern_index += 1;
        }
    }
    if input_index != input.len() {
        return Err(FunctionError::invalid_arguments(
            "date contains trailing input after source format",
        ));
    }
    if let Some(is_am) = am {
        if twelve_hour == Some(false) {
            if fields.hour > 11 {
                return Err(FunctionError::invalid_arguments(
                    "12-hour clock value is outside the valid range",
                ));
            }
            fields.hour = if is_am { fields.hour } else { fields.hour + 12 };
        } else if fields.hour > 12 || fields.hour == 0 {
            return Err(FunctionError::invalid_arguments(
                "12-hour clock value is outside the valid range",
            ));
        } else {
            fields.hour = match (is_am, fields.hour) {
                (true, 12) => 0,
                (false, 12) => 12,
                (false, hour) => hour + 12,
                (true, hour) => hour,
            };
        }
    } else if twelve_hour.is_some() {
        return Err(FunctionError::invalid_arguments(
            "12-hour date patterns require an AM/PM marker",
        ));
    }
    validate_date_fields(fields)?;
    let days = days_from_civil(fields.year, fields.month, fields.day);
    let local_millis = days
        .checked_mul(86_400_000)
        .and_then(|value| value.checked_add(i64::from(fields.hour) * 3_600_000))
        .and_then(|value| value.checked_add(i64::from(fields.minute) * 60_000))
        .and_then(|value| value.checked_add(i64::from(fields.second) * 1_000))
        .and_then(|value| value.checked_add(i64::from(fields.millis)))
        .ok_or_else(|| FunctionError::execution("date value overflowed epoch range"))?;
    local_millis
        .checked_sub(i64::from(fields.offset_seconds) * 1_000)
        .ok_or_else(|| FunctionError::execution("date offset overflowed epoch range"))
}

fn format_datetime(
    millis: i64,
    format: &str,
    locale: Locale,
    output_limit: usize,
) -> Result<String, FunctionError> {
    format_datetime_with_offset(millis, format, locale, 0, output_limit)
}

fn format_datetime_with_offset(
    millis: i64,
    format: &str,
    locale: Locale,
    offset_seconds: i32,
    output_limit: usize,
) -> Result<String, FunctionError> {
    let local_millis = millis
        .checked_add(i64::from(offset_seconds) * 1_000)
        .ok_or_else(|| FunctionError::execution("date value overflowed epoch range"))?;
    let (days, remainder) = div_mod_floor(local_millis, 86_400_000);
    let (year, month, day) = civil_from_days(days);
    let fields = DateFields {
        year,
        month,
        day,
        hour: (remainder / 3_600_000) as u32,
        minute: ((remainder / 60_000) % 60) as u32,
        second: ((remainder / 1_000) % 60) as u32,
        millis: (remainder % 1_000) as u32,
        offset_seconds,
    };
    let mut result = String::with_capacity(format.len().min(output_limit));
    let pattern: Vec<char> = format.chars().collect();
    let mut index = 0usize;
    while index < pattern.len() {
        let token = pattern[index];
        if token == '\'' {
            if pattern.get(index + 1) == Some(&'\'') {
                append_bounded_function_text(&mut result, "'", output_limit)?;
                index += 2;
                continue;
            }
            index += 1;
            let mut literal = String::new();
            while index < pattern.len() {
                if pattern[index] == '\'' {
                    if pattern.get(index + 1) == Some(&'\'') {
                        literal.push('\'');
                        index += 2;
                        continue;
                    }
                    break;
                }
                literal.push(pattern[index]);
                index += 1;
            }
            if index == pattern.len() {
                return Err(FunctionError::invalid_arguments(
                    "date format contains an unclosed quote",
                ));
            }
            append_bounded_function_text(&mut result, &literal, output_limit)?;
            index += 1;
            continue;
        }
        if token.is_ascii_alphabetic() {
            let start = index;
            while index < pattern.len() && pattern[index] == token {
                index += 1;
            }
            let width = index - start;
            let mut rendered = String::new();
            append_format_token(&mut rendered, token, width, fields, locale)?;
            append_bounded_function_text(&mut result, &rendered, output_limit)?;
        } else {
            let mut encoded = [0_u8; 4];
            append_bounded_function_text(
                &mut result,
                token.encode_utf8(&mut encoded),
                output_limit,
            )?;
            index += 1;
        }
    }
    if result.len() > output_limit {
        return Err(FunctionError::execution(
            "function result exceeds the expression output bound",
        ));
    }
    Ok(result)
}

fn parse_decimal(
    input: &str,
    width: usize,
    variable_width: bool,
) -> Result<(i64, usize), FunctionError> {
    let mut consumed = 0usize;
    let mut value = 0_i64;
    for character in input.chars() {
        if !character.is_ascii_digit() || (!variable_width && consumed == width) {
            break;
        }
        value = value
            .checked_mul(10)
            .and_then(|current| current.checked_add(i64::from(character as u8 - b'0')))
            .ok_or_else(|| FunctionError::invalid_arguments("date number is too large"))?;
        consumed += 1;
    }
    if consumed == 0 || (!variable_width && consumed != width) {
        return Err(FunctionError::invalid_arguments(
            "date format expected a decimal number",
        ));
    }
    Ok((value, consumed))
}

fn parse_month_name(
    input: &str,
    locale: Locale,
    long: bool,
) -> Result<(u32, usize), FunctionError> {
    let names = month_names(locale, long);
    names
        .iter()
        .enumerate()
        .find_map(|(index, name)| {
            input
                .get(..name.len())
                .filter(|prefix| prefix.eq_ignore_ascii_case(name))
                .map(|prefix| (index as u32 + 1, prefix.len()))
        })
        .ok_or_else(|| FunctionError::invalid_arguments("date format expected a month name"))
}

fn parse_meridiem(input: &str) -> Result<(bool, usize), FunctionError> {
    for value in ["AM", "PM"] {
        if input.len() >= value.len() && input[..value.len()].eq_ignore_ascii_case(value) {
            return Ok((value == "AM", value.len()));
        }
    }
    Err(FunctionError::invalid_arguments(
        "date format expected AM or PM",
    ))
}

fn parse_weekday(input: &str, locale: Locale) -> Result<usize, FunctionError> {
    let short = weekday_names(locale, true);
    let long = weekday_names(locale, false);
    short
        .iter()
        .chain(long.iter())
        .find_map(|name| {
            input
                .get(..name.len())
                .filter(|prefix| prefix.eq_ignore_ascii_case(name))
                .map(str::len)
        })
        .ok_or_else(|| FunctionError::invalid_arguments("date format expected a weekday"))
}

fn parse_offset(input: &str, token: char, width: usize) -> Result<(i32, usize), FunctionError> {
    if width > 3 {
        return Err(FunctionError::unsupported(
            "date offset patterns wider than three letters require a JVM time adapter",
        ));
    }
    if input.starts_with('Z') {
        return Ok((0, 1));
    }
    let sign = match input.chars().next() {
        Some('+') => 1,
        Some('-') => -1,
        _ => {
            return Err(FunctionError::invalid_arguments(
                "date format expected a UTC offset",
            ));
        }
    };
    let digits = &input[1..];
    let (hour, consumed_hour) = parse_decimal(digits, 2, false)?;
    let mut consumed = 1 + consumed_hour;
    let offset_chars: Vec<char> = digits.chars().collect();
    let minute = match (token, width) {
        ('X' | 'x', 1) => 0,
        ('X' | 'x', 2) | ('Z', 1..=3) => {
            if offset_chars.len() < 4 {
                return Err(FunctionError::invalid_arguments(
                    "date format expected a complete UTC offset",
                ));
            }
            let minute = parse_offset_digits(&offset_chars[2..4])?;
            consumed += 2;
            minute
        }
        ('X' | 'x', 3) => {
            if offset_chars.get(2) != Some(&':') || offset_chars.len() < 5 {
                return Err(FunctionError::invalid_arguments(
                    "date format expected a colon in its UTC offset",
                ));
            }
            let minute = parse_offset_digits(&offset_chars[3..5])?;
            consumed += 3;
            minute
        }
        _ => {
            return Err(FunctionError::unsupported(
                "date offset pattern requires a JVM time adapter",
            ));
        }
    };
    if hour > 23 || minute > 59 {
        return Err(FunctionError::invalid_arguments(
            "UTC offset is outside the valid range",
        ));
    }
    Ok((sign * (hour as i32 * 3_600 + minute as i32 * 60), consumed))
}

fn parse_offset_digits(digits: &[char]) -> Result<i64, FunctionError> {
    if digits.len() != 2 || !digits.iter().all(char::is_ascii_digit) {
        return Err(FunctionError::invalid_arguments(
            "date format expected two UTC offset minute digits",
        ));
    }
    Ok(i64::from(digits[0] as u8 - b'0') * 10 + i64::from(digits[1] as u8 - b'0'))
}

fn append_format_token(
    output: &mut String,
    token: char,
    width: usize,
    fields: DateFields,
    locale: Locale,
) -> Result<(), FunctionError> {
    match token {
        'y' | 'u' => {
            if width == 2 {
                output.push_str(&format!("{:02}", fields.year.rem_euclid(100)));
            } else {
                output.push_str(&format_number(fields.year, width));
            }
        }
        'M' => {
            if width >= 3 {
                let names = month_names(locale, width >= 4);
                output.push_str(names[(fields.month - 1) as usize]);
            } else {
                output.push_str(&format_number(i64::from(fields.month), width));
            }
        }
        'd' => output.push_str(&format_number(i64::from(fields.day), width)),
        'H' => output.push_str(&format_number(i64::from(fields.hour), width)),
        'k' => {
            let hour = if fields.hour == 0 { 24 } else { fields.hour };
            output.push_str(&format_number(i64::from(hour), width));
        }
        'h' => {
            let hour = match fields.hour % 12 {
                0 => 12,
                value => value,
            };
            output.push_str(&format_number(i64::from(hour), width));
        }
        'K' => output.push_str(&format_number(i64::from(fields.hour % 12), width)),
        'm' => output.push_str(&format_number(i64::from(fields.minute), width)),
        's' => output.push_str(&format_number(i64::from(fields.second), width)),
        'S' => {
            if width > 3 {
                return Err(FunctionError::unsupported(
                    "date format fractional seconds beyond milliseconds require a JVM time adapter",
                ));
            }
            let fraction = format!("{:03}", fields.millis);
            output.push_str(&fraction[..width.min(3)]);
            if width > 3 {
                output.push_str(&"0".repeat(width - 3));
            }
        }
        'a' => output.push_str(if fields.hour < 12 { "AM" } else { "PM" }),
        'E' => {
            let weekday = weekday_index(fields.year, fields.month, fields.day);
            output.push_str(weekday_names(locale, width < 4)[weekday as usize]);
        }
        'X' | 'x' | 'Z' => append_offset(output, fields.offset_seconds, token, width),
        _ => {
            return Err(FunctionError::unsupported(format!(
                "unsupported date format token {token}"
            )));
        }
    }
    Ok(())
}

fn format_number(value: i64, width: usize) -> String {
    if width <= 1 {
        value.to_string()
    } else {
        format!("{value:0width$}")
    }
}

fn append_offset(output: &mut String, offset: i32, token: char, width: usize) {
    if offset == 0 && token == 'X' {
        output.push('Z');
        return;
    }
    let sign = if offset < 0 { '-' } else { '+' };
    let absolute = offset.unsigned_abs();
    let hours = absolute / 3_600;
    let minutes = (absolute % 3_600) / 60;
    output.push(sign);
    output.push_str(&format!("{hours:02}"));
    if token == 'Z' || width >= 2 {
        if token == 'X' && width >= 3 {
            output.push(':');
        }
        output.push_str(&format!("{minutes:02}"));
    }
}

fn validate_date_fields(fields: DateFields) -> Result<(), FunctionError> {
    if !(1..=12).contains(&fields.month)
        || fields.day == 0
        || fields.day > days_in_month(fields.year, fields.month)
        || fields.hour > 23
        || fields.minute > 59
        || fields.second > 59
        || fields.millis > 999
    {
        return Err(FunctionError::invalid_arguments(
            "date value is outside the valid range",
        ));
    }
    Ok(())
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        2 if is_leap_year(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn is_leap_year(year: i64) -> bool {
    year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0)
}

fn local_epoch_day(millis: i64, offset_seconds: i32) -> Result<i64, FunctionError> {
    let local = millis
        .checked_add(i64::from(offset_seconds) * 1_000)
        .ok_or_else(|| FunctionError::execution("clock value overflowed local date range"))?;
    Ok(local.div_euclid(86_400_000))
}

fn div_mod_floor(value: i64, divisor: i64) -> (i64, i64) {
    let quotient = value.div_euclid(divisor);
    (quotient, value.rem_euclid(divisor))
}

// Howard Hinnant's civil-date conversion, adapted as arithmetic rather than
// a platform/time-zone call.  The formulas operate on the proleptic Gregorian
// calendar used by java.time for the range relevant to JMeter function input.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 }.div_euclid(400);
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let days = days + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 }.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    (year + i64::from(month <= 2), month as u32, day as u32)
}

fn weekday_index(year: i64, month: u32, day: u32) -> u32 {
    days_from_civil(year, month, day).rem_euclid(7) as u32
}

fn month_names(locale: Locale, long: bool) -> &'static [&'static str] {
    match (locale, long) {
        (Locale::EnUs, false) => &[
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ],
        (Locale::EnUs, true) => &[
            "January",
            "February",
            "March",
            "April",
            "May",
            "June",
            "July",
            "August",
            "September",
            "October",
            "November",
            "December",
        ],
        (Locale::FrFr, false) => &[
            "janv.", "févr.", "mars", "avr.", "mai", "juin", "juil.", "août", "sept.", "oct.",
            "nov.", "déc.",
        ],
        (Locale::FrFr, true) => &[
            "janvier",
            "février",
            "mars",
            "avril",
            "mai",
            "juin",
            "juillet",
            "août",
            "septembre",
            "octobre",
            "novembre",
            "décembre",
        ],
    }
}

fn weekday_names(locale: Locale, short: bool) -> &'static [&'static str] {
    match (locale, short) {
        (Locale::EnUs, true) => &["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"],
        (Locale::EnUs, false) => &[
            "Thursday",
            "Friday",
            "Saturday",
            "Sunday",
            "Monday",
            "Tuesday",
            "Wednesday",
        ],
        (Locale::FrFr, true) => &["jeu.", "ven.", "sam.", "dim.", "lun.", "mar.", "mer."],
        (Locale::FrFr, false) => &[
            "jeudi", "vendredi", "samedi", "dimanche", "lundi", "mardi", "mercredi",
        ],
    }
}

fn time_alias(
    registry: &BuiltinFunctions,
    context: &FunctionContext<'_>,
    format: &str,
) -> Result<String, FunctionError> {
    match format {
        "YMD" => registry
            .property_value(context, "time.YMD")
            .map(|value| value.unwrap_or_else(|| "yyyyMMdd".to_owned())),
        "HMS" => registry
            .property_value(context, "time.HMS")
            .map(|value| value.unwrap_or_else(|| "HHmmss".to_owned())),
        "YMDHMS" => registry
            .property_value(context, "time.YMDHMS")
            .map(|value| value.unwrap_or_else(|| "yyyyMMdd-HHmmss".to_owned())),
        "USER1" => registry
            .property_value(context, "time.USER1")
            .map(|value| value.unwrap_or_default()),
        "USER2" => registry
            .property_value(context, "time.USER2")
            .map(|value| value.unwrap_or_default()),
        value => Ok(value.to_owned()),
    }
}

fn parse_duration_millis(input: &str) -> Result<i64, FunctionError> {
    let input = java_trim(input);
    if input.is_empty() {
        return Ok(0);
    }
    let (negative, input) = input
        .strip_prefix('-')
        .map_or((false, input), |value| (true, value));
    let input = input
        .strip_prefix('P')
        .ok_or_else(|| FunctionError::invalid_arguments("duration must start with P"))?;
    let (date, time) = input.split_once('T').map_or((input, ""), |parts| parts);
    let mut date_rest = date;
    let had_date_component = !date_rest.is_empty();
    let days = if date_rest.is_empty() {
        0
    } else {
        let (value, rest) = parse_duration_integer(date_rest, 'D')?;
        date_rest = rest;
        value
    };
    if !date_rest.is_empty() {
        return Err(FunctionError::invalid_arguments(
            "duration contains an unsupported date component",
        ));
    }

    let mut time_rest = time;
    let mut components = 0usize;
    let hours = if let Some((value, rest)) = parse_optional_duration_integer(time_rest, 'H')? {
        components += 1;
        time_rest = rest;
        value
    } else {
        0
    };
    let minutes = if let Some((value, rest)) = parse_optional_duration_integer(time_rest, 'M')? {
        components += 1;
        time_rest = rest;
        value
    } else {
        0
    };
    let seconds = if !time_rest.is_empty() {
        let (value, rest) = parse_duration_seconds(time_rest)?;
        time_rest = rest;
        components += 1;
        value
    } else {
        0
    };
    if !time_rest.is_empty() || (!had_date_component && components == 0) {
        return Err(FunctionError::invalid_arguments(
            "duration contains no supported components",
        ));
    }
    let millis = (days as i128)
        .checked_mul(86_400_000)
        .and_then(|value| value.checked_add(hours as i128 * 3_600_000))
        .and_then(|value| value.checked_add(minutes as i128 * 60_000))
        .and_then(|value| value.checked_add(seconds as i128))
        .ok_or_else(|| FunctionError::invalid_arguments("duration is too large"))?;
    let millis = i64::try_from(millis)
        .map_err(|_| FunctionError::invalid_arguments("duration is too large"))?;
    if negative {
        millis
            .checked_neg()
            .ok_or_else(|| FunctionError::invalid_arguments("duration is too large"))
    } else {
        Ok(millis)
    }
}

fn parse_duration_integer(input: &str, marker: char) -> Result<(i64, &str), FunctionError> {
    let Some(position) = input.find(marker) else {
        return Err(FunctionError::invalid_arguments(
            "duration component is missing its designator",
        ));
    };
    let digits = &input[..position];
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(FunctionError::invalid_arguments(
            "duration component is not an integer",
        ));
    }
    let value = digits
        .parse::<i64>()
        .map_err(|_| FunctionError::invalid_arguments("duration component is too large"))?;
    Ok((value, &input[position + marker.len_utf8()..]))
}

fn parse_optional_duration_integer(
    input: &str,
    marker: char,
) -> Result<Option<(i64, &str)>, FunctionError> {
    if !input.contains(marker) {
        return Ok(None);
    }
    parse_duration_integer(input, marker).map(Some)
}

fn parse_duration_seconds(input: &str) -> Result<(i64, &str), FunctionError> {
    let Some(position) = input.find('S') else {
        return Err(FunctionError::invalid_arguments(
            "duration seconds are missing their designator",
        ));
    };
    let value = &input[..position];
    let (whole, fraction) = value.split_once('.').map_or((value, ""), |parts| parts);
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(FunctionError::invalid_arguments(
            "duration seconds are invalid",
        ));
    }
    if fraction.len() > 3 {
        return Err(FunctionError::unsupported(
            "duration fractions beyond milliseconds require a JVM time adapter",
        ));
    }
    let whole = whole
        .parse::<i64>()
        .map_err(|_| FunctionError::invalid_arguments("duration seconds are too large"))?;
    let fraction_value = if fraction.is_empty() {
        0
    } else {
        fraction
            .parse::<i64>()
            .map_err(|_| FunctionError::invalid_arguments("duration seconds are invalid"))?
            * 10_i64.pow(3 - fraction.len() as u32)
    };
    let millis = i128::from(whole)
        .checked_mul(1_000)
        .and_then(|value| value.checked_add(i128::from(fraction_value)))
        .and_then(|value| i64::try_from(value).ok())
        .ok_or_else(|| FunctionError::invalid_arguments("duration is too large"))?;
    if millis < 0 {
        return Err(FunctionError::invalid_arguments("duration is too large"));
    }
    Ok((millis, &input[position + 1..]))
}

fn digest_bytes(algorithm: &str, input: &[u8]) -> Result<Vec<u8>, FunctionError> {
    match algorithm.to_ascii_uppercase().as_str() {
        "MD2" => Ok(md2_digest(input).to_vec()),
        "MD5" => Ok(md5_digest(input).to_vec()),
        "SHA" | "SHA-1" | "SHA1" => Ok(sha1_digest(input).to_vec()),
        "SHA-224" => Ok(sha256_digest(input, Sha256Variant::Sha224).to_vec()),
        "SHA-256" => Ok(sha256_digest(input, Sha256Variant::Sha256).to_vec()),
        "SHA-384" => Ok(sha512_digest(input, Sha512Variant::Sha384).to_vec()),
        "SHA-512" => Ok(sha512_digest(input, Sha512Variant::Sha512).to_vec()),
        _ => Err(FunctionError::unsupported(format!(
            "digest algorithm {algorithm} is unavailable"
        ))),
    }
}

/// Computes MD2 as specified by RFC 1319.
///
/// This is a small, allocation-bounded one-shot implementation for the
/// legacy algorithm exposed by JMeter's `__digest` function.  It intentionally
/// keeps the 48-byte compression state and 16-byte checksum local to the
/// call; no shared or process-global cryptographic state is used.
fn md2_digest(input: &[u8]) -> [u8; 16] {
    // The fixed substitution table is the public algorithm constant from RFC
    // 1319, not a platform/provider lookup.
    const S: [u8; 256] = [
        0x29, 0x2e, 0x43, 0xc9, 0xa2, 0xd8, 0x7c, 0x01, 0x3d, 0x36, 0x54, 0xa1, 0xec, 0xf0, 0x06,
        0x13, 0x62, 0xa7, 0x05, 0xf3, 0xc0, 0xc7, 0x73, 0x8c, 0x98, 0x93, 0x2b, 0xd9, 0xbc, 0x4c,
        0x82, 0xca, 0x1e, 0x9b, 0x57, 0x3c, 0xfd, 0xd4, 0xe0, 0x16, 0x67, 0x42, 0x6f, 0x18, 0x8a,
        0x17, 0xe5, 0x12, 0xbe, 0x4e, 0xc4, 0xd6, 0xda, 0x9e, 0xde, 0x49, 0xa0, 0xfb, 0xf5, 0x8e,
        0xbb, 0x2f, 0xee, 0x7a, 0xa9, 0x68, 0x79, 0x91, 0x15, 0xb2, 0x07, 0x3f, 0x94, 0xc2, 0x10,
        0x89, 0x0b, 0x22, 0x5f, 0x21, 0x80, 0x7f, 0x5d, 0x9a, 0x5a, 0x90, 0x32, 0x27, 0x35, 0x3e,
        0xcc, 0xe7, 0xbf, 0xf7, 0x97, 0x03, 0xff, 0x19, 0x30, 0xb3, 0x48, 0xa5, 0xb5, 0xd1, 0xd7,
        0x5e, 0x92, 0x2a, 0xac, 0x56, 0xaa, 0xc6, 0x4f, 0xb8, 0x38, 0xd2, 0x96, 0xa4, 0x7d, 0xb6,
        0x76, 0xfc, 0x6b, 0xe2, 0x9c, 0x74, 0x04, 0xf1, 0x45, 0x9d, 0x70, 0x59, 0x64, 0x71, 0x87,
        0x20, 0x86, 0x5b, 0xcf, 0x65, 0xe6, 0x2d, 0xa8, 0x02, 0x1b, 0x60, 0x25, 0xad, 0xae, 0xb0,
        0xb9, 0xf6, 0x1c, 0x46, 0x61, 0x69, 0x34, 0x40, 0x7e, 0x0f, 0x55, 0x47, 0xa3, 0x23, 0xdd,
        0x51, 0xaf, 0x3a, 0xc3, 0x5c, 0xf9, 0xce, 0xba, 0xc5, 0xea, 0x26, 0x2c, 0x53, 0x0d, 0x6e,
        0x85, 0x28, 0x84, 0x09, 0xd3, 0xdf, 0xcd, 0xf4, 0x41, 0x81, 0x4d, 0x52, 0x6a, 0xdc, 0x37,
        0xc8, 0x6c, 0xc1, 0xab, 0xfa, 0x24, 0xe1, 0x7b, 0x08, 0x0c, 0xbd, 0xb1, 0x4a, 0x78, 0x88,
        0x95, 0x8b, 0xe3, 0x63, 0xe8, 0x6d, 0xe9, 0xcb, 0xd5, 0xfe, 0x3b, 0x00, 0x1d, 0x39, 0xf2,
        0xef, 0xb7, 0x0e, 0x66, 0x58, 0xd0, 0xe4, 0xa6, 0x77, 0x72, 0xf8, 0xeb, 0x75, 0x4b, 0x0a,
        0x31, 0x44, 0x50, 0xb4, 0x8f, 0xed, 0x1f, 0x1a, 0xdb, 0x99, 0x8d, 0x33, 0x9f, 0x11, 0x83,
        0x14,
    ];
    let padding = 16 - input.len() % 16;
    let mut padded = Vec::with_capacity(input.len() + padding);
    padded.extend_from_slice(input);
    padded.extend(std::iter::repeat_n(padding as u8, padding));

    let mut state = [0_u8; 48];
    let mut checksum = [0_u8; 16];
    for block in padded.chunks_exact(16) {
        md2_block(&mut state, &mut checksum, block, &S);
    }
    // The checksum is processed as one final block after the padded message.
    let checksum_block = checksum;
    md2_block(&mut state, &mut checksum, &checksum_block, &S);

    let mut digest = [0_u8; 16];
    digest.copy_from_slice(&state[..16]);
    digest
}

fn md2_block(state: &mut [u8; 48], checksum: &mut [u8; 16], block: &[u8], s: &[u8; 256]) {
    let mut previous = checksum[15];
    for index in 0..16 {
        state[index + 16] = block[index];
        state[index + 32] = block[index] ^ state[index];
        previous = checksum[index] ^ s[usize::from(block[index] ^ previous)];
        checksum[index] = previous;
    }

    let mut t = 0_u8;
    for round in 0..18_u8 {
        for value in state.iter_mut() {
            *value ^= s[usize::from(t)];
            t = *value;
        }
        t = t.wrapping_add(round);
    }
}

fn hex_bytes(bytes: &[u8], uppercase: bool) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let high = byte >> 4;
        let low = byte & 0x0f;
        if uppercase {
            result.push(b"0123456789ABCDEF"[high as usize] as char);
            result.push(b"0123456789ABCDEF"[low as usize] as char);
        } else {
            result.push(hex_digit_lower(high));
            result.push(hex_digit_lower(low));
        }
    }
    result
}

fn md5_digest(input: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76a_a478,
        0xe8c7_b756,
        0x2420_70db,
        0xc1bd_ceee,
        0xf57c_0faf,
        0x4787_c62a,
        0xa830_4613,
        0xfd46_9501,
        0x6980_98d8,
        0x8b44_f7af,
        0xffff_5bb1,
        0x895c_d7be,
        0x6b90_1122,
        0xfd98_7193,
        0xa679_438e,
        0x49b4_0821,
        0xf61e_2562,
        0xc040_b340,
        0x265e_5a51,
        0xe9b6_c7aa,
        0xd62f_105d,
        0x0244_1453,
        0xd8a1_e681,
        0xe7d3_fbc8,
        0x21e1_cde6,
        0xc337_07d6,
        0xf4d5_0d87,
        0x455a_14ed,
        0xa9e3_e905,
        0xfcef_a3f8,
        0x676f_02d9,
        0x8d2a_4c8a,
        0xfffa_3942,
        0x8771_f681,
        0x6d9d_6122,
        0xfde5_380c,
        0xa4be_ea44,
        0x4bde_cfa9,
        0xf6bb_4b60,
        0xbebf_bc70,
        0x289b_7ec6,
        0xeaa1_27fa,
        0xd4ef_3085,
        0x0488_1d05,
        0xd9d4_d039,
        0xe6db_99e5,
        0x1fa2_7cf8,
        0xc4ac_5665,
        0xf429_2244,
        0x432a_ff97,
        0xab94_23a7,
        0xfc93_a039,
        0x655b_59c3,
        0x8f0c_cc92,
        0xffef_f47d,
        0x8584_5dd1,
        0x6fa8_7e4f,
        0xfe2c_e6e0,
        0xa301_4314,
        0x4e08_11a1,
        0xf753_7e82,
        0xbd3a_f235,
        0x2ad7_d2bb,
        0xeb86_d391,
    ];
    let mut state = [0x6745_2301_u32, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
    for block in padded_blocks(input, 64, 8, true) {
        let mut words = [0_u32; 16];
        for (word, chunk) in words.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        let (mut a, mut b, mut c, mut d) = (state[0], state[1], state[2], state[3]);
        for index in 0..64 {
            let (mut f, g) = if index < 16 {
                ((b & c) | ((!b) & d), index)
            } else if index < 32 {
                ((d & b) | ((!d) & c), (5 * index + 1) % 16)
            } else if index < 48 {
                (b ^ c ^ d, (3 * index + 5) % 16)
            } else {
                (c ^ (b | !d), (7 * index) % 16)
            };
            f = f
                .wrapping_add(a)
                .wrapping_add(K[index])
                .wrapping_add(words[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(S[index]));
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }
    let mut output = [0_u8; 16];
    for (chunk, value) in output.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&value.to_le_bytes());
    }
    output
}

fn sha1_digest(input: &[u8]) -> [u8; 20] {
    const K: [u32; 4] = [0x5a82_7999, 0x6ed9_eba1, 0x8f1b_bcdc, 0xca62_c1d6];
    let mut state = [
        0x6745_2301_u32,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    for block in padded_blocks(input, 64, 8, false) {
        let mut words = [0_u32; 80];
        for (word, chunk) in words[..16].iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for index in 16..80 {
            words[index] =
                (words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16])
                    .rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) =
            (state[0], state[1], state[2], state[3], state[4]);
        for (index, word) in words.iter().enumerate() {
            let (f, k) = match index {
                0..=19 => ((b & c) | ((!b) & d), K[0]),
                20..=39 => (b ^ c ^ d, K[1]),
                40..=59 => ((b & c) | (b & d) | (c & d), K[2]),
                _ => (b ^ c ^ d, K[3]),
            };
            let temporary = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temporary;
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
    }
    let mut output = [0_u8; 20];
    for (chunk, value) in output.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&value.to_be_bytes());
    }
    output
}

#[derive(Clone, Copy)]
enum Sha256Variant {
    Sha224,
    Sha256,
}

fn sha256_digest(input: &[u8], variant: Sha256Variant) -> Vec<u8> {
    const K: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];
    let mut state: [u32; 8] = match variant {
        Sha256Variant::Sha224 => [
            0xc105_9ed8,
            0x367c_d507,
            0x3070_dd17,
            0xf70e_5939,
            0xffc0_0b31,
            0x6858_1511,
            0x64f9_8fa7,
            0xbefa_4fa4,
        ],
        Sha256Variant::Sha256 => [
            0x6a09_e667,
            0xbb67_ae85,
            0x3c6e_f372,
            0xa54f_f53a,
            0x510e_527f,
            0x9b05_688c,
            0x1f83_d9ab,
            0x5be0_cd19,
        ],
    };
    for block in padded_blocks(input, 64, 8, false) {
        let mut words = [0_u32; 64];
        for (word, chunk) in words[..16].iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for index in 16..64 {
            let small_sigma0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let small_sigma1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(small_sigma0)
                .wrapping_add(words[index - 7])
                .wrapping_add(small_sigma1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
            state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
        );
        for index in 0..64 {
            let big_sigma1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temporary1 = h
                .wrapping_add(big_sigma1)
                .wrapping_add(choose)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let big_sigma0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temporary2 = big_sigma0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temporary1);
            d = c;
            c = b;
            b = a;
            a = temporary1.wrapping_add(temporary2);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }
    let length = match variant {
        Sha256Variant::Sha224 => 7,
        Sha256Variant::Sha256 => 8,
    };
    state[..length]
        .iter()
        .flat_map(|value| value.to_be_bytes())
        .collect()
}

#[derive(Clone, Copy)]
enum Sha512Variant {
    Sha384,
    Sha512,
}

fn sha512_digest(input: &[u8], variant: Sha512Variant) -> Vec<u8> {
    const K: [u64; 80] = [
        0x428a_2f98_d728_ae22,
        0x7137_4491_23ef_65cd,
        0xb5c0_fbcf_ec4d_3b2f,
        0xe9b5_dba5_8189_dbbc,
        0x3956_c25b_f348_b538,
        0x59f1_11f1_b605_d019,
        0x923f_82a4_af19_4f9b,
        0xab1c_5ed5_da6d_8118,
        0xd807_aa98_a303_0242,
        0x1283_5b01_4570_6fbe,
        0x2431_85be_4ee4_b28c,
        0x550c_7dc3_d5ff_b4e2,
        0x72be_5d74_f27b_896f,
        0x80de_b1fe_3b16_96b1,
        0x9bdc_06a7_25c7_1235,
        0xc19b_f174_cf69_2694,
        0xe49b_69c1_9ef1_4ad2,
        0xefbe_4786_384f_25e3,
        0x0fc1_9dc6_8b8c_d5b5,
        0x240c_a1cc_77ac_9c65,
        0x2de9_2c6f_592b_0275,
        0x4a74_84aa_6ea6_e483,
        0x5cb0_a9dc_bd41_fbd4,
        0x76f9_88da_8311_53b5,
        0x983e_5152_ee66_dfab,
        0xa831_c66d_2db4_3210,
        0xb003_27c8_98fb_213f,
        0xbf59_7fc7_beef_0ee4,
        0xc6e0_0bf3_3da8_8fc2,
        0xd5a7_9147_930a_a725,
        0x06ca_6351_e003_826f,
        0x1429_2967_0a0e_6e70,
        0x27b7_0a85_46d2_2ffc,
        0x2e1b_2138_5c26_c926,
        0x4d2c_6dfc_5ac4_2aed,
        0x5338_0d13_9d95_b3df,
        0x650a_7354_8baf_63de,
        0x766a_0abb_3c77_b2a8,
        0x81c2_c92e_47ed_aee6,
        0x9272_2c85_1482_353b,
        0xa2bf_e8a1_4cf1_0364,
        0xa81a_664b_bc42_3001,
        0xc24b_8b70_d0f8_9791,
        0xc76c_51a3_0654_be30,
        0xd192_e819_d6ef_5218,
        0xd699_0624_5565_a910,
        0xf40e_3585_5771_202a,
        0x106a_a070_32bb_d1b8,
        0x19a4_c116_b8d2_d0c8,
        0x1e37_6c08_5141_ab53,
        0x2748_774c_df8e_eb99,
        0x34b0_bcb5_e19b_48a8,
        0x391c_0cb3_c5c9_5a63,
        0x4ed8_aa4a_e341_8acb,
        0x5b9c_ca4f_7763_e373,
        0x682e_6ff3_d6b2_b8a3,
        0x748f_82ee_5def_b2fc,
        0x78a5_636f_4317_2f60,
        0x84c8_7814_a1f0_ab72,
        0x8cc7_0208_1a64_39ec,
        0x90be_fffa_2363_1e28,
        0xa450_6ceb_de82_bde9,
        0xbef9_a3f7_b2c6_7915,
        0xc671_78f2_e372_532b,
        0xca27_3ece_ea26_619c,
        0xd186_b8c7_21c0_c207,
        0xeada_7dd6_cde0_eb1e,
        0xf57d_4f7f_ee6e_d178,
        0x06f0_67aa_7217_6fba,
        0x0a63_7dc5_a2c8_98a6,
        0x113f_9804_bef9_0dae,
        0x1b71_0b35_131c_471b,
        0x28db_77f5_2304_7d84,
        0x32ca_ab7b_40c7_2493,
        0x3c9e_be0a_15c9_bebc,
        0x431d_67c4_9c10_0d4c,
        0x4cc5_d4be_cb3e_42b6,
        0x597f_299c_fc65_7e2a,
        0x5fcb_6fab_3ad6_faec,
        0x6c44_198c_4a47_5817,
    ];
    let mut state: [u64; 8] = match variant {
        Sha512Variant::Sha384 => [
            0xcbbb_9d5d_c105_9ed8,
            0x629a_292a_367c_d507,
            0x9159_015a_3070_dd17,
            0x152f_ecd8_f70e_5939,
            0x6733_2667_ffc0_0b31,
            0x8eb4_4a87_6858_1511,
            0xdb0c_2e0d_64f9_8fa7,
            0x47b5_481d_befa_4fa4,
        ],
        Sha512Variant::Sha512 => [
            0x6a09_e667_f3bc_c908,
            0xbb67_ae85_84ca_a73b,
            0x3c6e_f372_fe94_f82b,
            0xa54f_f53a_5f1d_36f1,
            0x510e_527f_ade6_82d1,
            0x9b05_688c_2b3e_6c1f,
            0x1f83_d9ab_fb41_bd6b,
            0x5be0_cd19_137e_2179,
        ],
    };
    for block in padded_blocks(input, 128, 16, false) {
        let mut words = [0_u64; 80];
        for (word, chunk) in words[..16].iter_mut().zip(block.chunks_exact(8)) {
            *word = u64::from_be_bytes([
                chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
            ]);
        }
        for index in 16..80 {
            let small_sigma0 = words[index - 15].rotate_right(1)
                ^ words[index - 15].rotate_right(8)
                ^ (words[index - 15] >> 7);
            let small_sigma1 = words[index - 2].rotate_right(19)
                ^ words[index - 2].rotate_right(61)
                ^ (words[index - 2] >> 6);
            words[index] = words[index - 16]
                .wrapping_add(small_sigma0)
                .wrapping_add(words[index - 7])
                .wrapping_add(small_sigma1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
            state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
        );
        for index in 0..80 {
            let big_sigma1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let choose = (e & f) ^ ((!e) & g);
            let temporary1 = h
                .wrapping_add(big_sigma1)
                .wrapping_add(choose)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let big_sigma0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temporary2 = big_sigma0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temporary1);
            d = c;
            c = b;
            b = a;
            a = temporary1.wrapping_add(temporary2);
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = (*slot).wrapping_add(value);
        }
    }
    let length = match variant {
        Sha512Variant::Sha384 => 6,
        Sha512Variant::Sha512 => 8,
    };
    state[..length]
        .iter()
        .flat_map(|value| value.to_be_bytes())
        .collect()
}

fn padded_blocks(
    input: &[u8],
    block_size: usize,
    length_size: usize,
    little_endian_length: bool,
) -> Vec<Vec<u8>> {
    let bit_length = (input.len() as u128) * 8;
    let mut padded = input.to_vec();
    padded.push(0x80);
    while !(padded.len() + length_size).is_multiple_of(block_size) {
        padded.push(0);
    }
    let length_bytes = if little_endian_length {
        bit_length.to_le_bytes()
    } else {
        bit_length.to_be_bytes()
    };
    if length_size == 8 {
        if little_endian_length {
            padded.extend_from_slice(&length_bytes[..8]);
        } else {
            padded.extend_from_slice(&length_bytes[8..]);
        }
    } else {
        padded.extend_from_slice(&length_bytes);
    }
    padded
        .chunks(block_size)
        .map(|chunk| chunk.to_vec())
        .collect()
}

fn eval(arguments: &[String], context: &FunctionContext<'_>) -> Result<String, FunctionError> {
    check_count("__eval", arguments, 1, 1)?;
    context.evaluate_nested(&arguments[0])
}

fn char_function(
    arguments: &[String],
    context: &FunctionContext<'_>,
) -> Result<String, FunctionError> {
    if arguments.is_empty() {
        return Err(FunctionError::invalid_arguments(
            "__char expects at least one number",
        ));
    }
    // Java's implementation appends UTF-16 code units, not Rust Unicode
    // scalar values.  Keep those units losslessly until the result boundary;
    // a lone surrogate cannot be represented by the crate's UTF-8 API and is
    // therefore an explicit capability error rather than silent data loss.
    let mut units = Vec::with_capacity(arguments.len());
    for argument in arguments {
        let Ok(value) = decode_java_long(java_trim(argument)) else {
            // JMeter logs malformed values and continues with the remaining
            // arguments; it does not make one bad code unit fail the whole
            // function call.
            continue;
        };
        let code_unit = value as u16;
        units.push(code_unit);
    }
    let value = String::from_utf16(&units).map_err(|_| {
        FunctionError::unsupported(
            "__char produced a lone UTF-16 surrogate that the UTF-8 expression boundary cannot represent",
        )
    })?;
    if value.len() > context.max_output_bytes() {
        return Err(FunctionError::execution(
            "function result exceeds the expression output bound",
        ));
    }
    Ok(value)
}

fn java_trim(value: &str) -> &str {
    value.trim_matches(|character: char| character <= '\u{20}')
}

fn parse_optional_sequence(
    name: &str,
    value: Option<&String>,
    label: &str,
) -> Result<Option<i64>, FunctionError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_empty() {
        return Ok(None);
    }
    value.parse::<i32>().map(i64::from).map(Some).map_err(|_| {
        FunctionError::invalid_arguments(format!("{name} {label} must be a signed 32-bit integer"))
    })
}

fn capitalize(value: &str) -> Result<String, FunctionError> {
    let mut characters = value.chars();
    let Some(first) = characters.next() else {
        return Ok(String::new());
    };
    // Commons Lang delegates this operation to Java's single-code-point
    // Character.toTitleCase. Rust's Unicode mapping can expand one scalar
    // into several scalars (for example, a ligature); refusing that boundary
    // avoids returning a value with different Java semantics.
    let mut title = first.to_uppercase();
    let Some(title_first) = title.next() else {
        return Err(FunctionError::unsupported(
            "__changeCase CAPITALIZE has no Java title-case mapping",
        ));
    };
    if title.next().is_some() {
        return Err(FunctionError::unsupported(
            "__changeCase CAPITALIZE would require a multi-code-point Java title-case mapping",
        ));
    }
    let mut result = String::new();
    result.push(title_first);
    result.extend(characters);
    Ok(result)
}

fn decode_java_long(value: &str) -> Result<i64, ()> {
    if value.is_empty() {
        return Err(());
    }
    let (negative, value) = if let Some(rest) = value.strip_prefix('-') {
        (true, rest)
    } else if let Some(rest) = value.strip_prefix('+') {
        (false, rest)
    } else {
        (false, value)
    };
    let (radix, digits) = if let Some(rest) = value.strip_prefix("0x") {
        (16, rest)
    } else if let Some(rest) = value.strip_prefix("0X") {
        (16, rest)
    } else if let Some(rest) = value.strip_prefix('#') {
        (16, rest)
    } else if value.len() > 1 && value.starts_with('0') {
        (8, &value[1..])
    } else {
        (10, value)
    };
    if digits.is_empty() {
        return Err(());
    }
    let parsed = i128::from_str_radix(digits, radix).map_err(|_| ())?;
    let parsed = if negative { -parsed } else { parsed };
    i64::try_from(parsed).map_err(|_| ())
}

fn sum(
    arguments: &[String],
    context: &FunctionContext<'_>,
    registry: &BuiltinFunctions,
    integer: bool,
) -> Result<String, FunctionError> {
    let name = if integer { "__intSum" } else { "__longSum" };
    check_count(name, arguments, 2, usize::MAX)?;
    let last = arguments.last().map(String::as_str).unwrap_or_default();
    if integer {
        let mut total = 0_i32;
        for argument in &arguments[..arguments.len() - 1] {
            let value = argument.parse::<i32>().map_err(|_| {
                FunctionError::invalid_arguments(format!("{name} expects integer arguments"))
            })?;
            total = total.wrapping_add(value);
        }
        let variable_name = match java_trim(last).parse::<i32>() {
            Ok(value) => {
                total = total.wrapping_add(value);
                None
            }
            Err(_) => Some(java_trim(last)),
        };
        let value = total.to_string();
        if value.len() > context.max_output_bytes() {
            return Err(FunctionError::execution(
                "function result exceeds the expression output bound",
            ));
        }
        if let Some(variable_name) = variable_name {
            // IntSum preserves the upstream distinction between an omitted
            // numeric final argument and a non-numeric output-variable slot:
            // the Java implementation writes even an explicitly empty name.
            registry.set_variable(context, variable_name, &value)?;
        }
        Ok(value)
    } else {
        let mut total = 0_i64;
        for argument in &arguments[..arguments.len() - 1] {
            let value = argument.parse::<i64>().map_err(|_| {
                FunctionError::invalid_arguments(format!("{name} expects integer arguments"))
            })?;
            total = total.wrapping_add(value);
        }
        let variable_name = match java_trim(last).parse::<i64>() {
            Ok(value) => {
                total = total.wrapping_add(value);
                None
            }
            Err(_) => Some(java_trim(last)),
        };
        let value = total.to_string();
        if value.len() > context.max_output_bytes() {
            return Err(FunctionError::execution(
                "function result exceeds the expression output bound",
            ));
        }
        if let Some(variable_name) = variable_name.filter(|name| !name.is_empty()) {
            set_optional_variable(registry, context, Some(&variable_name.to_owned()), &value)?;
        }
        Ok(value)
    }
}

fn escape_html(
    arguments: &[String],
    context: &FunctionContext<'_>,
) -> Result<String, FunctionError> {
    check_count("__escapeHtml", arguments, 1, 1)?;
    escape_entities(&arguments[0], false, context.max_output_bytes())
}

fn escape_xml(
    arguments: &[String],
    context: &FunctionContext<'_>,
) -> Result<String, FunctionError> {
    check_count("__escapeXml", arguments, 1, 1)?;
    escape_entities(&arguments[0], true, context.max_output_bytes())
}

fn unescape_html(
    arguments: &[String],
    context: &FunctionContext<'_>,
) -> Result<String, FunctionError> {
    check_count("__unescapeHtml", arguments, 1, 1)?;
    unescape_entities(&arguments[0], context.max_output_bytes())
}

fn escape_entities(value: &str, xml: bool, output_limit: usize) -> Result<String, FunctionError> {
    let mut result = String::with_capacity(value.len().min(output_limit));
    for character in value.chars() {
        if xml {
            match character as u32 {
                0x00..=0x08 | 0x0B..=0x0C | 0x0E..=0x1F | 0xFFFE..=0xFFFF => continue,
                // Commons Text's XML 1.0 translator emits numeric entities
                // for C1 controls even though direct C1 bytes are not valid
                // XML 1.0 text.
                0x7F..=0x84 | 0x86..=0x9F => {
                    let numeric = format!("&#{};", character as u32);
                    append_bounded_function_text(&mut result, &numeric, output_limit)?;
                    continue;
                }
                _ => {}
            }
        }
        let replacement = match character {
            '&' => Some("&amp;"),
            '<' => Some("&lt;"),
            '>' => Some("&gt;"),
            '"' => Some("&quot;"),
            '\'' if xml => Some("&apos;"),
            _ if !xml => html_entity_for(character),
            _ => None,
        };
        if let Some(replacement) = replacement {
            append_bounded_function_text(&mut result, replacement, output_limit)?;
        } else {
            let mut encoded = [0_u8; 4];
            append_bounded_function_text(
                &mut result,
                character.encode_utf8(&mut encoded),
                output_limit,
            )?;
        }
    }
    Ok(result)
}

fn unescape_entities(value: &str, output_limit: usize) -> Result<String, FunctionError> {
    let mut result = String::with_capacity(value.len().min(output_limit));
    let mut rest = value;
    while let Some(ampersand) = rest.find('&') {
        append_bounded_function_text(&mut result, &rest[..ampersand], output_limit)?;
        let candidate = &rest[ampersand..];
        let Some(semicolon) = candidate.find(';') else {
            append_bounded_function_text(&mut result, candidate, output_limit)?;
            break;
        };
        let entity = &candidate[1..semicolon];
        if let Some(character) = decode_entity(entity)? {
            let mut encoded = [0_u8; 4];
            append_bounded_function_text(
                &mut result,
                character.encode_utf8(&mut encoded),
                output_limit,
            )?;
            rest = &candidate[semicolon + 1..];
        } else {
            append_bounded_function_text(&mut result, &candidate[..semicolon + 1], output_limit)?;
            rest = &candidate[semicolon + 1..];
        }
    }
    if !rest.is_empty() {
        append_bounded_function_text(&mut result, rest, output_limit)?;
    }
    Ok(result)
}

fn decode_entity(entity: &str) -> Result<Option<char>, FunctionError> {
    if let Some(value) = entity
        .strip_prefix("#x")
        .or_else(|| entity.strip_prefix("#X"))
    {
        return decode_numeric_entity(u32::from_str_radix(value, 16).ok());
    }
    if let Some(value) = entity.strip_prefix('#') {
        return decode_numeric_entity(value.parse::<u32>().ok());
    }
    let mut named = String::with_capacity(entity.len().saturating_add(2));
    named.push('&');
    named.push_str(entity);
    named.push(';');
    Ok(html_entity_character(&named))
}

fn decode_numeric_entity(value: Option<u32>) -> Result<Option<char>, FunctionError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if (0xD800..=0xDFFF).contains(&value) {
        return Err(FunctionError::unsupported(
            "HTML entity contains a UTF-16 surrogate that the UTF-8 expression boundary cannot represent",
        ));
    }
    Ok(char::from_u32(value))
}

fn html_entity_for(character: char) -> Option<&'static str> {
    HTML_ENTITIES
        .iter()
        .find_map(|(name, value)| (*value == character).then_some(*name))
}

fn html_entity_character(name: &str) -> Option<char> {
    HTML_ENTITIES
        .iter()
        .find_map(|(entity, value)| (*entity == name).then_some(*value))
}

// The table covers HTML 4's ISO-8859-1 entities and the frequently used
// punctuation/Greek names.  Unknown Unicode is intentionally left unchanged,
// matching Commons Text's escapeHtml4 behavior.
const HTML_ENTITIES: &[(&str, char)] = &[
    ("&quot;", '"'),
    ("&amp;", '&'),
    ("&lt;", '<'),
    ("&gt;", '>'),
    ("&nbsp;", '\u{00a0}'),
    ("&iexcl;", '\u{00a1}'),
    ("&cent;", '\u{00a2}'),
    ("&pound;", '\u{00a3}'),
    ("&curren;", '\u{00a4}'),
    ("&yen;", '\u{00a5}'),
    ("&brvbar;", '\u{00a6}'),
    ("&sect;", '\u{00a7}'),
    ("&uml;", '\u{00a8}'),
    ("&copy;", '\u{00a9}'),
    ("&ordf;", '\u{00aa}'),
    ("&laquo;", '\u{00ab}'),
    ("&not;", '\u{00ac}'),
    ("&shy;", '\u{00ad}'),
    ("&reg;", '\u{00ae}'),
    ("&macr;", '\u{00af}'),
    ("&deg;", '\u{00b0}'),
    ("&plusmn;", '\u{00b1}'),
    ("&sup2;", '\u{00b2}'),
    ("&sup3;", '\u{00b3}'),
    ("&acute;", '\u{00b4}'),
    ("&micro;", '\u{00b5}'),
    ("&para;", '\u{00b6}'),
    ("&middot;", '\u{00b7}'),
    ("&cedil;", '\u{00b8}'),
    ("&sup1;", '\u{00b9}'),
    ("&ordm;", '\u{00ba}'),
    ("&raquo;", '\u{00bb}'),
    ("&frac14;", '\u{00bc}'),
    ("&frac12;", '\u{00bd}'),
    ("&frac34;", '\u{00be}'),
    ("&iquest;", '\u{00bf}'),
    ("&Agrave;", '\u{00c0}'),
    ("&Aacute;", '\u{00c1}'),
    ("&Acirc;", '\u{00c2}'),
    ("&Atilde;", '\u{00c3}'),
    ("&Auml;", '\u{00c4}'),
    ("&Aring;", '\u{00c5}'),
    ("&AElig;", '\u{00c6}'),
    ("&Ccedil;", '\u{00c7}'),
    ("&Egrave;", '\u{00c8}'),
    ("&Eacute;", '\u{00c9}'),
    ("&Ecirc;", '\u{00ca}'),
    ("&Euml;", '\u{00cb}'),
    ("&Igrave;", '\u{00cc}'),
    ("&Iacute;", '\u{00cd}'),
    ("&Icirc;", '\u{00ce}'),
    ("&Iuml;", '\u{00cf}'),
    ("&ETH;", '\u{00d0}'),
    ("&Ntilde;", '\u{00d1}'),
    ("&Ograve;", '\u{00d2}'),
    ("&Oacute;", '\u{00d3}'),
    ("&Ocirc;", '\u{00d4}'),
    ("&Otilde;", '\u{00d5}'),
    ("&Ouml;", '\u{00d6}'),
    ("&times;", '\u{00d7}'),
    ("&Oslash;", '\u{00d8}'),
    ("&Ugrave;", '\u{00d9}'),
    ("&Uacute;", '\u{00da}'),
    ("&Ucirc;", '\u{00db}'),
    ("&Uuml;", '\u{00dc}'),
    ("&Yacute;", '\u{00dd}'),
    ("&THORN;", '\u{00de}'),
    ("&szlig;", '\u{00df}'),
    ("&agrave;", '\u{00e0}'),
    ("&aacute;", '\u{00e1}'),
    ("&acirc;", '\u{00e2}'),
    ("&atilde;", '\u{00e3}'),
    ("&auml;", '\u{00e4}'),
    ("&aring;", '\u{00e5}'),
    ("&aelig;", '\u{00e6}'),
    ("&ccedil;", '\u{00e7}'),
    ("&egrave;", '\u{00e8}'),
    ("&eacute;", '\u{00e9}'),
    ("&ecirc;", '\u{00ea}'),
    ("&euml;", '\u{00eb}'),
    ("&igrave;", '\u{00ec}'),
    ("&iacute;", '\u{00ed}'),
    ("&icirc;", '\u{00ee}'),
    ("&iuml;", '\u{00ef}'),
    ("&eth;", '\u{00f0}'),
    ("&ntilde;", '\u{00f1}'),
    ("&ograve;", '\u{00f2}'),
    ("&oacute;", '\u{00f3}'),
    ("&ocirc;", '\u{00f4}'),
    ("&otilde;", '\u{00f5}'),
    ("&ouml;", '\u{00f6}'),
    ("&divide;", '\u{00f7}'),
    ("&oslash;", '\u{00f8}'),
    ("&ugrave;", '\u{00f9}'),
    ("&uacute;", '\u{00fa}'),
    ("&ucirc;", '\u{00fb}'),
    ("&uuml;", '\u{00fc}'),
    ("&yacute;", '\u{00fd}'),
    ("&thorn;", '\u{00fe}'),
    ("&yuml;", '\u{00ff}'),
    ("&fnof;", '\u{0192}'),
    ("&bull;", '\u{2022}'),
    ("&hellip;", '\u{2026}'),
    ("&prime;", '\u{2032}'),
    ("&Prime;", '\u{2033}'),
    ("&trade;", '\u{2122}'),
    ("&larr;", '\u{2190}'),
    ("&uarr;", '\u{2191}'),
    ("&rarr;", '\u{2192}'),
    ("&darr;", '\u{2193}'),
    ("&harr;", '\u{2194}'),
    ("&euro;", '\u{20ac}'),
    ("&Alpha;", '\u{391}'),
    ("&Beta;", '\u{392}'),
    ("&Gamma;", '\u{393}'),
    ("&Delta;", '\u{394}'),
    ("&Epsilon;", '\u{395}'),
    ("&Zeta;", '\u{396}'),
    ("&Eta;", '\u{397}'),
    ("&Theta;", '\u{398}'),
    ("&Iota;", '\u{399}'),
    ("&Kappa;", '\u{39a}'),
    ("&Lambda;", '\u{39b}'),
    ("&Mu;", '\u{39c}'),
    ("&Nu;", '\u{39d}'),
    ("&Xi;", '\u{39e}'),
    ("&Omicron;", '\u{39f}'),
    ("&Pi;", '\u{3a0}'),
    ("&Rho;", '\u{3a1}'),
    ("&Sigma;", '\u{3a3}'),
    ("&Tau;", '\u{3a4}'),
    ("&Upsilon;", '\u{3a5}'),
    ("&Phi;", '\u{3a6}'),
    ("&Chi;", '\u{3a7}'),
    ("&Psi;", '\u{3a8}'),
    ("&Omega;", '\u{3a9}'),
    ("&alpha;", '\u{3b1}'),
    ("&beta;", '\u{3b2}'),
    ("&gamma;", '\u{3b3}'),
    ("&delta;", '\u{3b4}'),
    ("&epsilon;", '\u{3b5}'),
    ("&zeta;", '\u{3b6}'),
    ("&eta;", '\u{3b7}'),
    ("&theta;", '\u{3b8}'),
    ("&iota;", '\u{3b9}'),
    ("&kappa;", '\u{3ba}'),
    ("&lambda;", '\u{3bb}'),
    ("&mu;", '\u{3bc}'),
    ("&nu;", '\u{3bd}'),
    ("&xi;", '\u{3be}'),
    ("&omicron;", '\u{3bf}'),
    ("&pi;", '\u{3c0}'),
    ("&rho;", '\u{3c1}'),
    ("&sigmaf;", '\u{3c2}'),
    ("&sigma;", '\u{3c3}'),
    ("&tau;", '\u{3c4}'),
    ("&upsilon;", '\u{3c5}'),
    ("&phi;", '\u{3c6}'),
    ("&chi;", '\u{3c7}'),
    ("&psi;", '\u{3c8}'),
    ("&omega;", '\u{3c9}'),
    ("&thetasym;", '\u{3d1}'),
    ("&upsih;", '\u{3d2}'),
    ("&piv;", '\u{3d6}'),
    ("&oline;", '\u{203e}'),
    ("&frasl;", '\u{2044}'),
    ("&weierp;", '\u{2118}'),
    ("&image;", '\u{2111}'),
    ("&real;", '\u{211c}'),
    ("&alefsym;", '\u{2135}'),
    ("&crarr;", '\u{21b5}'),
    ("&lArr;", '\u{21d0}'),
    ("&uArr;", '\u{21d1}'),
    ("&rArr;", '\u{21d2}'),
    ("&dArr;", '\u{21d3}'),
    ("&hArr;", '\u{21d4}'),
    ("&forall;", '\u{2200}'),
    ("&part;", '\u{2202}'),
    ("&exist;", '\u{2203}'),
    ("&empty;", '\u{2205}'),
    ("&nabla;", '\u{2207}'),
    ("&isin;", '\u{2208}'),
    ("&notin;", '\u{2209}'),
    ("&ni;", '\u{220b}'),
    ("&prod;", '\u{220f}'),
    ("&sum;", '\u{2211}'),
    ("&minus;", '\u{2212}'),
    ("&lowast;", '\u{2217}'),
    ("&radic;", '\u{221a}'),
    ("&prop;", '\u{221d}'),
    ("&infin;", '\u{221e}'),
    ("&ang;", '\u{2220}'),
    ("&and;", '\u{2227}'),
    ("&or;", '\u{2228}'),
    ("&cap;", '\u{2229}'),
    ("&cup;", '\u{222a}'),
    ("&int;", '\u{222b}'),
    ("&there4;", '\u{2234}'),
    ("&sim;", '\u{223c}'),
    ("&cong;", '\u{2245}'),
    ("&asymp;", '\u{2248}'),
    ("&ne;", '\u{2260}'),
    ("&equiv;", '\u{2261}'),
    ("&le;", '\u{2264}'),
    ("&ge;", '\u{2265}'),
    ("&sub;", '\u{2282}'),
    ("&sup;", '\u{2283}'),
    ("&nsub;", '\u{2284}'),
    ("&sube;", '\u{2286}'),
    ("&supe;", '\u{2287}'),
    ("&oplus;", '\u{2295}'),
    ("&otimes;", '\u{2297}'),
    ("&perp;", '\u{22a5}'),
    ("&sdot;", '\u{22c5}'),
    ("&lceil;", '\u{2308}'),
    ("&rceil;", '\u{2309}'),
    ("&lfloor;", '\u{230a}'),
    ("&rfloor;", '\u{230b}'),
    ("&lang;", '\u{2329}'),
    ("&rang;", '\u{232a}'),
    ("&loz;", '\u{25ca}'),
    ("&spades;", '\u{2660}'),
    ("&clubs;", '\u{2663}'),
    ("&hearts;", '\u{2665}'),
    ("&diams;", '\u{2666}'),
    ("&OElig;", '\u{152}'),
    ("&oelig;", '\u{153}'),
    ("&Scaron;", '\u{160}'),
    ("&scaron;", '\u{161}'),
    ("&Yuml;", '\u{178}'),
    ("&circ;", '\u{2c6}'),
    ("&tilde;", '\u{2dc}'),
    ("&ensp;", '\u{2002}'),
    ("&emsp;", '\u{2003}'),
    ("&thinsp;", '\u{2009}'),
    ("&zwnj;", '\u{200c}'),
    ("&zwj;", '\u{200d}'),
    ("&lrm;", '\u{200e}'),
    ("&rlm;", '\u{200f}'),
    ("&ndash;", '\u{2013}'),
    ("&mdash;", '\u{2014}'),
    ("&lsquo;", '\u{2018}'),
    ("&rsquo;", '\u{2019}'),
    ("&sbquo;", '\u{201a}'),
    ("&ldquo;", '\u{201c}'),
    ("&rdquo;", '\u{201d}'),
    ("&bdquo;", '\u{201e}'),
    ("&dagger;", '\u{2020}'),
    ("&Dagger;", '\u{2021}'),
    ("&permil;", '\u{2030}'),
    ("&lsaquo;", '\u{2039}'),
    ("&rsaquo;", '\u{203a}'),
];

fn unescape_java(
    arguments: &[String],
    context: &FunctionContext<'_>,
) -> Result<String, FunctionError> {
    check_count("__unescape", arguments, 1, 1)?;
    let input = &arguments[0];
    let mut result = String::with_capacity(input.len().min(context.max_output_bytes()));
    let characters: Vec<char> = input.chars().collect();
    let mut index = 0;
    while index < characters.len() {
        if characters[index] != '\\' {
            push_bounded_function_char(&mut result, characters[index], context.max_output_bytes())?;
            index += 1;
            continue;
        }
        if index + 1 >= characters.len() {
            push_bounded_function_char(&mut result, '\\', context.max_output_bytes())?;
            break;
        }
        let next = characters[index + 1];
        let replacement = match next {
            'b' => Some('\u{0008}'),
            't' => Some('\t'),
            'n' => Some('\n'),
            'f' => Some('\u{000c}'),
            'r' => Some('\r'),
            '\'' => Some('\''),
            '"' => Some('"'),
            '\\' => Some('\\'),
            _ => None,
        };
        if let Some(replacement) = replacement {
            push_bounded_function_char(&mut result, replacement, context.max_output_bytes())?;
            index += 2;
            continue;
        }
        if next == 'u' {
            let (value, mut end) = parse_unicode_escape(&characters, index)?;
            if (0xD800..=0xDBFF).contains(&value) {
                let Some((low, low_end)) = characters
                    .get(end..)
                    .and_then(|remaining| parse_unicode_escape(remaining, 0).ok())
                else {
                    return Err(FunctionError::unsupported(
                        "__unescape produced an unpaired UTF-16 high surrogate that the UTF-8 expression boundary cannot represent",
                    ));
                };
                if !(0xDC00..=0xDFFF).contains(&low) {
                    return Err(FunctionError::unsupported(
                        "__unescape produced an unpaired UTF-16 high surrogate that the UTF-8 expression boundary cannot represent",
                    ));
                }
                let code_point = 0x1_0000 + ((value - 0xD800) << 10) + (low - 0xDC00);
                let character = char::from_u32(code_point)
                    .ok_or_else(|| FunctionError::execution("invalid UTF-16 surrogate pair"))?;
                push_bounded_function_char(&mut result, character, context.max_output_bytes())?;
                end += low_end;
            } else if (0xDC00..=0xDFFF).contains(&value) {
                return Err(FunctionError::unsupported(
                    "__unescape produced an unpaired UTF-16 low surrogate that the UTF-8 expression boundary cannot represent",
                ));
            } else {
                let character = char::from_u32(value)
                    .ok_or_else(|| FunctionError::execution("invalid Java Unicode escape"))?;
                push_bounded_function_char(&mut result, character, context.max_output_bytes())?;
            }
            index = end;
            continue;
        }
        if ('0'..='7').contains(&next) {
            let mut end = index + 2;
            let maximum = if next <= '3' { index + 4 } else { index + 3 };
            while end < maximum && end < characters.len() && ('0'..='7').contains(&characters[end])
            {
                end += 1;
            }
            let digits: String = characters[index + 1..end].iter().collect();
            let value = u32::from_str_radix(&digits, 8)
                .map_err(|_| FunctionError::execution("invalid Java octal escape"))?;
            if let Some(character) = char::from_u32(value) {
                push_bounded_function_char(&mut result, character, context.max_output_bytes())?;
                index = end;
                continue;
            }
        }
        // Commons Text's final lookup map contains a one-character `\\`
        // fallback which removes the slash before an otherwise unknown
        // escape.  Preserve the following character and consume the slash;
        // a trailing slash is consumed on its own.
        index += 1;
    }
    Ok(result)
}

fn parse_unicode_escape(characters: &[char], start: usize) -> Result<(u32, usize), FunctionError> {
    if characters.get(start) != Some(&'\\') || characters.get(start + 1) != Some(&'u') {
        return Err(FunctionError::invalid_arguments(
            "__unescape expected a Java Unicode escape",
        ));
    }
    let mut index = start + 2;
    while characters.get(index) == Some(&'u') {
        index += 1;
    }
    if characters.get(index) == Some(&'+') {
        index += 1;
    }
    if index + 4 > characters.len()
        || !characters[index..index + 4]
            .iter()
            .all(char::is_ascii_hexdigit)
    {
        return Err(FunctionError::invalid_arguments(
            "__unescape contains an invalid Java Unicode escape",
        ));
    }
    let digits: String = characters[index..index + 4].iter().collect();
    let value = u32::from_str_radix(&digits, 16)
        .map_err(|_| FunctionError::invalid_arguments("invalid Java Unicode escape"))?;
    Ok((value, index + 4))
}

fn url_encode(
    arguments: &[String],
    context: &FunctionContext<'_>,
) -> Result<String, FunctionError> {
    check_count("__urlencode", arguments, 1, 1)?;
    let input = arguments[0].as_bytes();
    // Percent encoding expands only the bytes that need escaping.  A blanket
    // three-bytes-per-input precheck would reject safe input such as `abc`
    // under a one-byte-at-a-time bound, so append each encoded segment through
    // the bounded helper instead.
    let mut result = String::with_capacity(input.len().min(context.max_output_bytes()));
    for byte in input {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'*') {
            append_bounded_function_text(
                &mut result,
                &(*byte as char).to_string(),
                context.max_output_bytes(),
            )?;
        } else if *byte == b' ' {
            append_bounded_function_text(&mut result, "+", context.max_output_bytes())?;
        } else {
            let encoded = format!("%{}{}", hex_digit(byte >> 4), hex_digit(byte & 0x0f));
            append_bounded_function_text(&mut result, &encoded, context.max_output_bytes())?;
        }
    }
    Ok(result)
}

fn url_decode(
    arguments: &[String],
    context: &FunctionContext<'_>,
) -> Result<String, FunctionError> {
    check_count("__urldecode", arguments, 1, 1)?;
    let bytes = arguments[0].as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len().min(context.max_output_bytes()));
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => decoded.push(b' '),
            b'%' if index + 2 < bytes.len() => {
                let high = hex_value(bytes[index + 1]).ok_or_else(|| {
                    FunctionError::invalid_arguments("__urldecode contains an invalid escape")
                })?;
                let low = hex_value(bytes[index + 2]).ok_or_else(|| {
                    FunctionError::invalid_arguments("__urldecode contains an invalid escape")
                })?;
                decoded.push((high << 4) | low);
                index += 2;
            }
            b'%' => {
                return Err(FunctionError::invalid_arguments(
                    "__urldecode contains an incomplete escape",
                ));
            }
            byte => decoded.push(byte),
        }
        index += 1;
    }
    let value = String::from_utf8_lossy(&decoded).into_owned();
    if value.len() > context.max_output_bytes() {
        return Err(FunctionError::execution(
            "function result exceeds the expression output bound",
        ));
    }
    Ok(value)
}

fn hex_digit(value: u8) -> char {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    HEX[value as usize] as char
}

fn hex_digit_lower(value: u8) -> char {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    HEX[value as usize] as char
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

/// A mutex-backed variable capability useful at runtime and in concurrent
/// tests.  Read-only expression references consult it through its owned
/// `get_variable` method; no borrowed lock guard escapes the capability.
pub struct MapVariableCapability {
    values: Mutex<BTreeMap<String, String>>,
}

impl Default for MapVariableCapability {
    fn default() -> Self {
        Self {
            values: Mutex::new(BTreeMap::new()),
        }
    }
}

impl fmt::Debug for MapVariableCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MapVariableCapability(..)")
    }
}

impl MapVariableCapability {
    /// Creates a capability from an ordered set of initial values.
    pub fn new<I, K, V>(values: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        Self {
            values: Mutex::new(
                values
                    .into_iter()
                    .map(|(key, value)| (key.into(), value.into()))
                    .collect(),
            ),
        }
    }

    /// Returns a deterministic snapshot of the current values.
    pub fn snapshot(&self) -> Result<BTreeMap<String, String>, FunctionError> {
        self.values
            .lock()
            .map(|values| values.clone())
            .map_err(|_| FunctionError::poisoned("variable capability lock is poisoned"))
    }
}

impl VariableSetter for MapVariableCapability {
    fn set_variable(&self, name: &str, value: &str) -> Result<(), FunctionError> {
        self.values
            .lock()
            .map_err(|_| FunctionError::poisoned("variable capability lock is poisoned"))?
            .insert(name.to_owned(), value.to_owned());
        Ok(())
    }

    fn set_variables_atomic(&self, values: &[(&str, &str)]) -> Result<(), FunctionError> {
        let mut stored = self
            .values
            .lock()
            .map_err(|_| FunctionError::poisoned("variable capability lock is poisoned"))?;
        for (name, value) in values {
            stored.insert((*name).to_owned(), (*value).to_owned());
        }
        Ok(())
    }

    fn get_variable(&self, name: &str) -> Option<String> {
        // The legacy optional getter cannot carry a typed poison error; new
        // evaluation paths use `get_variable_checked` below.
        match self.values.lock() {
            Ok(values) => values.get(name).cloned(),
            Err(_) => None,
        }
    }

    fn get_variable_checked(&self, name: &str) -> Result<Option<String>, FunctionError> {
        self.values
            .lock()
            .map(|values| values.get(name).cloned())
            .map_err(|_| FunctionError::poisoned("variable capability lock is poisoned"))
    }

    fn remove_variable(&self, name: &str) -> Result<(), FunctionError> {
        self.values
            .lock()
            .map_err(|_| FunctionError::poisoned("variable capability lock is poisoned"))?
            .remove(name);
        Ok(())
    }
}

/// A mutex-backed property capability useful at runtime and in concurrent
/// tests.
pub struct MapPropertyCapability {
    values: Mutex<BTreeMap<String, String>>,
}

impl Default for MapPropertyCapability {
    fn default() -> Self {
        Self {
            values: Mutex::new(BTreeMap::new()),
        }
    }
}

impl fmt::Debug for MapPropertyCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MapPropertyCapability(..)")
    }
}

impl MapPropertyCapability {
    /// Creates a capability from an ordered set of initial values.
    pub fn new<I, K, V>(values: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        Self {
            values: Mutex::new(
                values
                    .into_iter()
                    .map(|(key, value)| (key.into(), value.into()))
                    .collect(),
            ),
        }
    }

    /// Returns a deterministic snapshot of the current values.
    pub fn snapshot(&self) -> Result<BTreeMap<String, String>, FunctionError> {
        self.values
            .lock()
            .map(|values| values.clone())
            .map_err(|_| FunctionError::poisoned("property capability lock is poisoned"))
    }
}

impl PropertySetter for MapPropertyCapability {
    fn set_property(&self, name: &str, value: &str) -> Result<Option<String>, FunctionError> {
        Ok(self
            .values
            .lock()
            .map_err(|_| FunctionError::poisoned("property capability lock is poisoned"))?
            .insert(name.to_owned(), value.to_owned()))
    }

    fn get_property(&self, name: &str) -> Option<String> {
        // The legacy optional getter cannot carry a typed poison error; new
        // evaluation paths use `get_property_checked` below.
        match self.values.lock() {
            Ok(values) => values.get(name).cloned(),
            Err(_) => None,
        }
    }

    fn get_property_checked(&self, name: &str) -> Result<Option<String>, FunctionError> {
        self.values
            .lock()
            .map(|values| values.get(name).cloned())
            .map_err(|_| FunctionError::poisoned("property capability lock is poisoned"))
    }
}

/// A fixed test-plan-name capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticTestPlanName(Option<String>);

impl StaticTestPlanName {
    /// Creates a saved plan-name capability.
    pub fn new(name: impl Into<String>) -> Self {
        Self(Some(name.into()))
    }

    /// Creates an unsaved-plan capability.
    #[must_use]
    pub const fn unsaved() -> Self {
        Self(None)
    }
}

impl TestPlanNameResolver for StaticTestPlanName {
    fn test_plan_name(&self) -> Option<String> {
        self.0.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EvaluationCapabilities, Evaluator};
    use std::collections::{HashMap, VecDeque};
    use std::sync::{Arc, Mutex};
    use std::thread;

    fn mutex_snapshot<T: Clone>(mutex: &Mutex<T>) -> Option<T> {
        match mutex.lock() {
            Ok(value) => Some(value.clone()),
            Err(_) => None,
        }
    }

    #[derive(Clone, Copy)]
    struct FixedRandom(u64);

    impl RandomSource for FixedRandom {
        fn next_u64(&self) -> u64 {
            self.0
        }
    }

    struct SequenceRandom {
        values: Mutex<VecDeque<u64>>,
        fallback: u64,
    }

    impl SequenceRandom {
        fn new(values: impl IntoIterator<Item = u64>, fallback: u64) -> Self {
            Self {
                values: Mutex::new(values.into_iter().collect()),
                fallback,
            }
        }
    }

    impl RandomSource for SequenceRandom {
        fn next_u64(&self) -> u64 {
            self.values
                .lock()
                .ok()
                .and_then(|mut values| values.pop_front())
                .unwrap_or(self.fallback)
        }
    }

    struct TestClock {
        millis: i64,
        offset: i32,
        locale: Option<String>,
    }

    impl ClockSource for TestClock {
        fn now_millis(&self) -> Result<i64, FunctionError> {
            Ok(self.millis)
        }

        fn offset_seconds(&self) -> i32 {
            self.offset
        }

        fn locale(&self) -> Option<String> {
            self.locale.clone()
        }
    }

    struct CursorFiles {
        lines: BTreeMap<String, Vec<String>>,
        cursors: Mutex<BTreeMap<(String, u64), usize>>,
    }

    impl CursorFiles {
        fn new(lines: impl IntoIterator<Item = (&'static str, Vec<&'static str>)>) -> Self {
            Self {
                lines: lines
                    .into_iter()
                    .map(|(path, values)| {
                        (
                            path.to_owned(),
                            values.into_iter().map(str::to_owned).collect(),
                        )
                    })
                    .collect(),
                cursors: Mutex::new(BTreeMap::new()),
            }
        }
    }

    impl FileCapability for CursorFiles {
        fn read_to_string(
            &self,
            _path: &str,
            _encoding: Option<&str>,
        ) -> Result<String, FunctionError> {
            Err(FunctionError::execution("not used by this file fixture"))
        }

        fn read_line(
            &self,
            path: &str,
            key: &str,
            start_sequence: Option<i64>,
            end_sequence: Option<i64>,
        ) -> Result<String, FunctionError> {
            self.read_line_for_occurrence(path, key, 0, start_sequence, end_sequence)
        }

        fn read_line_for_occurrence(
            &self,
            path: &str,
            _key: &str,
            occurrence: u64,
            _start_sequence: Option<i64>,
            _end_sequence: Option<i64>,
        ) -> Result<String, FunctionError> {
            let mut cursors = self
                .cursors
                .lock()
                .map_err(|_| FunctionError::execution("cursor fixture lock poisoned"))?;
            let cursor = cursors.entry((path.to_owned(), occurrence)).or_default();
            let values = self
                .lines
                .get(path)
                .ok_or_else(|| FunctionError::execution("cursor fixture path is missing"))?;
            let Some(value) = values.get(*cursor) else {
                return Err(FunctionError::stop_thread("end of StringFromFile sequence"));
            };
            *cursor += 1;
            Ok(value.clone())
        }

        fn read_csv_field(
            &self,
            _path: &str,
            _selector: &str,
            _delimiter: char,
        ) -> Result<String, FunctionError> {
            Err(FunctionError::execution("not used by this file fixture"))
        }

        fn write_string(
            &self,
            _path: &str,
            _value: &str,
            _append: bool,
            _encoding: Option<&str>,
        ) -> Result<(), FunctionError> {
            Err(FunctionError::execution("not used by this file fixture"))
        }
    }

    type FileWrite = (String, String, bool, Option<String>);

    #[derive(Default)]
    struct WriteFiles {
        writes: Mutex<Vec<FileWrite>>,
    }

    struct ReadFiles {
        value: String,
        reads: Mutex<Vec<(String, Option<String>)>>,
    }

    impl ReadFiles {
        fn new(value: &str) -> Self {
            Self {
                value: value.to_owned(),
                reads: Mutex::new(Vec::new()),
            }
        }
    }

    impl FileCapability for ReadFiles {
        fn read_to_string(
            &self,
            path: &str,
            encoding: Option<&str>,
        ) -> Result<String, FunctionError> {
            self.reads
                .lock()
                .map_err(|_| FunctionError::execution("read fixture lock poisoned"))?
                .push((path.to_owned(), encoding.map(str::to_owned)));
            Ok(self.value.clone())
        }

        fn read_line(
            &self,
            _path: &str,
            _key: &str,
            _start_sequence: Option<i64>,
            _end_sequence: Option<i64>,
        ) -> Result<String, FunctionError> {
            Err(FunctionError::execution("not used by this read fixture"))
        }

        fn read_csv_field(
            &self,
            _path: &str,
            _selector: &str,
            _delimiter: char,
        ) -> Result<String, FunctionError> {
            Err(FunctionError::execution("not used by this read fixture"))
        }

        fn write_string(
            &self,
            _path: &str,
            _value: &str,
            _append: bool,
            _encoding: Option<&str>,
        ) -> Result<(), FunctionError> {
            Err(FunctionError::execution("not used by this read fixture"))
        }
    }

    type LogEntry = (String, String, Option<String>, Option<String>);

    #[derive(Default)]
    struct RecordingLog {
        entries: Mutex<Vec<LogEntry>>,
    }

    impl LogSink for RecordingLog {
        fn log(
            &self,
            level: &str,
            message: &str,
            throwable: Option<&str>,
            comment: Option<&str>,
        ) -> Result<(), FunctionError> {
            self.entries
                .lock()
                .map_err(|_| FunctionError::execution("log fixture lock poisoned"))?
                .push((
                    level.to_owned(),
                    message.to_owned(),
                    throwable.map(str::to_owned),
                    comment.map(str::to_owned),
                ));
            Ok(())
        }
    }

    struct FixedHost;

    impl HostResolver for FixedHost {
        fn machine_name(&self) -> Result<String, FunctionError> {
            Ok("fixture-host".to_owned())
        }

        fn machine_ip(&self) -> Result<String, FunctionError> {
            Ok("192.0.2.1".to_owned())
        }
    }

    impl FileCapability for WriteFiles {
        fn read_to_string(
            &self,
            _path: &str,
            _encoding: Option<&str>,
        ) -> Result<String, FunctionError> {
            Err(FunctionError::execution("not used by this write fixture"))
        }

        fn read_line(
            &self,
            _path: &str,
            _key: &str,
            _start_sequence: Option<i64>,
            _end_sequence: Option<i64>,
        ) -> Result<String, FunctionError> {
            Err(FunctionError::execution("not used by this write fixture"))
        }

        fn read_csv_field(
            &self,
            _path: &str,
            _selector: &str,
            _delimiter: char,
        ) -> Result<String, FunctionError> {
            Err(FunctionError::execution("CSV fixture failure"))
        }

        fn write_string(
            &self,
            path: &str,
            value: &str,
            append: bool,
            encoding: Option<&str>,
        ) -> Result<(), FunctionError> {
            self.writes
                .lock()
                .map_err(|_| FunctionError::execution("write fixture lock poisoned"))?
                .push((
                    path.to_owned(),
                    value.to_owned(),
                    append,
                    encoding.map(str::to_owned),
                ));
            Ok(())
        }
    }

    #[derive(Clone)]
    struct TestExecution {
        thread: u32,
        group: String,
        lifecycle: u64,
        iteration: u64,
    }

    impl ExecutionContext for TestExecution {
        fn thread_num(&self) -> Option<u32> {
            Some(self.thread)
        }

        fn thread_group_name(&self) -> Option<String> {
            Some(self.group.clone())
        }

        fn sampler_name(&self) -> Option<String> {
            Some("fixture-sampler".to_owned())
        }

        fn lifecycle_id(&self) -> Option<u64> {
            Some(self.lifecycle)
        }

        fn iteration_id(&self) -> Option<u64> {
            Some(self.iteration)
        }
    }

    #[derive(Default)]
    struct RecordingFiles {
        lines: Mutex<Vec<String>>,
    }

    impl FileCapability for RecordingFiles {
        fn read_to_string(
            &self,
            _path: &str,
            _encoding: Option<&str>,
        ) -> Result<String, FunctionError> {
            Err(FunctionError::execution("not used by this test"))
        }

        fn read_line(
            &self,
            path: &str,
            key: &str,
            start_sequence: Option<i64>,
            end_sequence: Option<i64>,
        ) -> Result<String, FunctionError> {
            let value = format!("{path}|{key}|{start_sequence:?}|{end_sequence:?}");
            self.lines
                .lock()
                .map_err(|_| FunctionError::execution("file test lock poisoned"))?
                .push(value.clone());
            Ok(value)
        }

        fn read_csv_field(
            &self,
            _path: &str,
            _selector: &str,
            _delimiter: char,
        ) -> Result<String, FunctionError> {
            Err(FunctionError::execution("not used by this test"))
        }

        fn write_string(
            &self,
            _path: &str,
            _value: &str,
            _append: bool,
            _encoding: Option<&str>,
        ) -> Result<(), FunctionError> {
            Err(FunctionError::execution("not used by this test"))
        }
    }

    #[test]
    fn one_golden_case_per_deterministic_function() {
        let variables = HashMap::from([
            ("NAME".to_owned(), "Ada".to_owned()),
            ("SQL".to_owned(), "select ${COLUMN}".to_owned()),
            ("COLUMN".to_owned(), "name".to_owned()),
        ]);
        let properties = HashMap::from([("region".to_owned(), "test".to_owned())]);
        let functions = BuiltinFunctions::new();
        let evaluator = Evaluator::new(&variables, &properties, &functions);
        let cases = [
            ("${__V(NAME)}", "Ada"),
            ("${__V(MISSING,default)}", "default"),
            ("${__V(MISSING,)}", ""),
            ("${__eval(${SQL})}", "select name"),
            ("${__evalVar(SQL)}", "select name"),
            ("${__property(region)}", "test"),
            ("${__property(missing,,fallback)}", "fallback"),
            ("${__P(missing)}", "1"),
            ("${__changeCase(hello,lower)}", "hello"),
            ("${__changeCase(hello,UPPER)}", "HELLO"),
            ("${__changeCase(hello)}", "HELLO"),
            ("${__changeCase(hello world,CAPITALIZE)}", "Hello world"),
            ("${__changeCase(MiXeD,INVALID)}", "MiXeD"),
            ("${__changeCase(hello,)}", "HELLO"),
            ("${__char(65,0102,0x43)}", "ABC"),
            ("${__escapeOroRegexpChars(a.b*)}", r"a\.b\*"),
            ("${__escapeHtml(<é &>) }", "&lt;&eacute; &amp;&gt;"),
            (
                "${__escapeXml(\"bread\" & 'butter')}",
                "&quot;bread&quot; &amp; &apos;butter&apos;",
            ),
            (r"${__unescape(\r\n)}", "\r\n"),
            (r"${__unescape(\q)}", "q"),
            ("${__unescapeHtml(&lt;Fran&ccedil;ais&gt;)}", "<Français>"),
            (
                "${__urlencode(Word \"school\" is \"école\")}",
                "Word+%22school%22+is+%22%C3%A9cole%22",
            ),
            (
                "${__urldecode(Word+%22school%22+is+%22%C3%A9cole%22)}",
                "Word \"school\" is \"école\"",
            ),
            ("${__intSum(2,5,7)}", "14"),
            ("${__longSum(2,5,7)}", "14"),
            ("${__isPropDefined(region)}", "true"),
            ("${__isVarDefined(NAME)}", "true"),
            ("${__digest(MD5,hello)}", "5d41402abc4b2a76b9719d911017c592"),
            (
                "${__digest(SHA-1,hello)}",
                "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
            ),
            (
                "${__digest(SHA-256,hello)}",
                "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(
                evaluator.evaluate(input),
                Ok(expected.to_owned()),
                "golden case {input}"
            );
        }
    }

    #[test]
    fn direct_native_capability_functions_have_observable_contracts() {
        let variables = HashMap::<String, String>::new();
        let properties = HashMap::<String, String>::new();
        let functions = BuiltinFunctions::new();
        let execution = TestExecution {
            thread: 7,
            group: "fixture-group".to_owned(),
            lifecycle: 1,
            iteration: 0,
        };
        let host = FixedHost;
        let log = RecordingLog::default();
        let files = ReadFiles::new("file contents");
        let variable_store = MapVariableCapability::default();
        let capabilities = EvaluationCapabilities::new()
            .with_execution_context(&execution)
            .with_host_resolver(&host)
            .with_log_sink(&log)
            .with_file_capability(&files)
            .with_variable_setter(&variable_store);
        let evaluator =
            Evaluator::with_capabilities(&variables, &properties, &functions, capabilities);

        assert_eq!(
            evaluator.evaluate("${__log(message,WARN,throwable,comment)}"),
            Ok("message".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("prefix${__logn(second,INFO)}suffix"),
            Ok("prefixsuffix".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__log(debug-fallback,unrecognized)}"),
            Ok("debug-fallback".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__log(space-fallback,   )}"),
            Ok("space-fallback".to_owned())
        );
        assert_eq!(
            evaluator
                .evaluate("${__machineName(HOST)}:${HOST}:${__machineIP(IP)}:${IP}:${__threadNum}"),
            Ok("fixture-host:fixture-host:192.0.2.1:192.0.2.1:7".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__samplerName}"),
            Ok("fixture-sampler".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__samplerName(SAMPLER)}:${SAMPLER}"),
            Ok("fixture-sampler:fixture-sampler".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__threadGroupName}"),
            Ok("fixture-group".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__FileToString(data.txt,UTF-8,CONTENT)}:${CONTENT}"),
            Ok("file contents:file contents".to_owned())
        );
        assert_eq!(
            mutex_snapshot(&log.entries),
            Some(vec![
                (
                    "WARN".to_owned(),
                    "message".to_owned(),
                    Some("throwable".to_owned()),
                    Some("comment".to_owned()),
                ),
                ("INFO".to_owned(), "second".to_owned(), None, None),
                ("DEBUG".to_owned(), "debug-fallback".to_owned(), None, None,),
                ("DEBUG".to_owned(), "space-fallback".to_owned(), None, None,),
            ])
        );
        assert_eq!(
            mutex_snapshot(&files.reads),
            Some(vec![("data.txt".to_owned(), Some("UTF-8".to_owned()))])
        );
    }

    #[test]
    fn registry_is_exhaustive_and_unknown_arguments_are_not_evaluated() {
        assert_eq!(KNOWN_FUNCTION_NAMES.len(), 49);
        let mut unique_names = KNOWN_FUNCTION_NAMES.to_vec();
        unique_names.sort_unstable();
        unique_names.dedup();
        assert_eq!(unique_names.len(), 49);
        assert!(
            KNOWN_FUNCTION_NAMES
                .iter()
                .chain(EXTENDED_FUNCTION_NAMES)
                .all(|name| BuiltinFunctions::is_registered(name))
        );
        let functions = BuiltinFunctions::new();
        assert!(functions.is_supported("__P"));
        assert!(!functions.is_supported("__Random"));
        assert_eq!(
            functions.support_status("__Random"),
            FunctionSupport::Registered
        );
        assert_eq!(
            functions.support_status("__not_a_jmeter_function"),
            FunctionSupport::Unknown
        );
        assert!(!functions.is_supported("__not_a_jmeter_function"));
        for plugin_name in [
            "__base64Encode",
            "__base64Decode",
            "__substring",
            "__strLen",
        ] {
            assert!(!BuiltinFunctions::is_registered(plugin_name));
            assert!(!functions.is_supported(plugin_name));
        }

        let variables = HashMap::<String, String>::new();
        let properties = HashMap::<String, String>::new();
        let property_store = MapPropertyCapability::default();
        let capabilities = EvaluationCapabilities::new().with_property_setter(&property_store);
        let evaluator =
            Evaluator::with_capabilities(&variables, &properties, &functions, capabilities);
        for source in [
            "${__not_a_jmeter_function(${__setProperty(side,effect)})}",
            "${__base64Encode(${__setProperty(side,effect)})}",
            "${__base64Decode(${__setProperty(side,effect)})}",
            "${__substring(${__setProperty(side,effect)},0,1)}",
            "${__strLen(${__setProperty(side,effect)})}",
        ] {
            assert_eq!(evaluator.evaluate(source), Ok(source.to_owned()));
        }
        assert_eq!(property_store.snapshot(), Ok(BTreeMap::new()));
    }

    #[test]
    fn invocation_requirements_are_argument_aware_and_side_effect_free() {
        let functions = BuiltinFunctions::new();
        let empty = EvaluationCapabilities::new();
        let files = CursorFiles::new([]);
        let random = FixedRandom(7);
        let execution = TestExecution {
            thread: 2,
            group: "fixture".to_owned(),
            lifecycle: 1,
            iteration: 0,
        };
        let file_capabilities = EvaluationCapabilities::new().with_file_capability(&files);
        let random_capabilities = EvaluationCapabilities::new().with_random_source(&random);
        let execution_capabilities =
            EvaluationCapabilities::new().with_execution_context(&execution);

        assert!(
            BuiltinFunctions::requirements_for_invocation(
                "__StringFromFile",
                &["data.txt".to_owned()],
            )
            .is_some_and(|requirements| {
                requirements.requires(FunctionCapability::Files)
                    && requirements.requires(FunctionCapability::VariableMutation)
            })
        );
        assert_eq!(
            functions.support_status_for_invocation(
                "__StringFromFile",
                &["data.txt".to_owned(), "".to_owned()],
                file_capabilities,
            ),
            FunctionSupport::Executable
        );
        assert_eq!(
            functions.support_status_for_invocation(
                "__StringFromFile",
                &["data.txt".to_owned()],
                file_capabilities,
            ),
            FunctionSupport::Registered
        );

        assert_eq!(
            functions.support_status_for_invocation(
                "__FileToString",
                &["data.txt".to_owned(), "UTF-8".to_owned(), "".to_owned()],
                file_capabilities,
            ),
            FunctionSupport::Executable
        );
        assert_eq!(
            functions.support_status_for_invocation(
                "__FileToString",
                &[
                    "data.txt".to_owned(),
                    "UTF-8".to_owned(),
                    "CONTENT".to_owned()
                ],
                file_capabilities,
            ),
            FunctionSupport::Registered
        );

        assert_eq!(
            functions.support_status_for_invocation(
                "__RandomDate",
                &[
                    "yyyy-MM-dd".to_owned(),
                    "2020-01-01".to_owned(),
                    "2020-01-03".to_owned(),
                ],
                random_capabilities,
            ),
            FunctionSupport::Executable
        );
        assert_eq!(
            functions.support_status_for_invocation(
                "__RandomDate",
                &[
                    "yyyy-MM-dd".to_owned(),
                    "".to_owned(),
                    "2020-01-03".to_owned()
                ],
                random_capabilities,
            ),
            FunctionSupport::Registered
        );
        let no_clock_variables = HashMap::<String, String>::new();
        let no_clock_properties = HashMap::<String, String>::new();
        let no_clock_random = Evaluator::with_capabilities(
            &no_clock_variables,
            &no_clock_properties,
            &functions,
            random_capabilities,
        );
        assert_eq!(
            no_clock_random.evaluate("${__RandomDate(yyyy-MM-dd,2020-01-01,2020-01-03,,)}"),
            Ok("2020-01-02".to_owned())
        );
        assert_eq!(
            functions.support_status_for_invocation(
                "__timeShift",
                &[
                    "yyyy-MM-dd".to_owned(),
                    "2020-01-01".to_owned(),
                    "P1D".to_owned(),
                    "".to_owned(),
                ],
                empty,
            ),
            FunctionSupport::Registered
        );
        assert_eq!(
            functions.support_status_for_invocation(
                "__timeShift",
                &[
                    "yyyy-MM-dd".to_owned(),
                    "".to_owned(),
                    "P1D".to_owned(),
                    "".to_owned()
                ],
                empty,
            ),
            FunctionSupport::Registered
        );

        let no_variables = HashMap::<String, String>::new();
        let no_properties = HashMap::<String, String>::new();
        let no_clock_evaluator = Evaluator::new(&no_variables, &no_properties, &functions);
        assert!(matches!(
            no_clock_evaluator.evaluate("${__timeShift(yyyy-MM-dd,2020-01-01,P1D,)}"),
            Err(crate::EvaluationError::Function {
                source: FunctionError::Unsupported(_),
                ..
            })
        ));

        assert_eq!(
            functions.support_status_for_invocation("__counter", &["false".to_owned()], empty,),
            FunctionSupport::Registered
        );
        assert_eq!(
            functions.support_status_for_invocation("__counter", &["true".to_owned()], empty,),
            FunctionSupport::Registered
        );
        assert_eq!(
            functions.support_status_for_invocation(
                "__counter",
                &["true".to_owned()],
                execution_capabilities,
            ),
            FunctionSupport::Executable
        );
        assert_eq!(
            functions.support_status_for_invocation(
                "__intSum",
                &["2".to_owned(), "output".to_owned()],
                empty,
            ),
            FunctionSupport::Registered
        );
        assert_eq!(
            functions.support_status_for_invocation(
                "__intSum",
                &["2".to_owned(), "7".to_owned()],
                empty,
            ),
            FunctionSupport::Executable
        );

        assert!(
            BuiltinFunctions::requirements_for_invocation("__escapeHtml", &["<value>".to_owned()],)
                .is_some_and(|requirements| requirements.is_pure())
        );
        assert_eq!(
            BuiltinFunctions::effect_class_for_invocation("__escapeHtml", &["<value>".to_owned()]),
            Some(EffectClass::Pure)
        );
        assert_eq!(
            BuiltinFunctions::effect_class_for_invocation(
                "__setProperty",
                &["name".to_owned(), "value".to_owned()],
            ),
            Some(EffectClass::JournaledNative)
        );
        assert_eq!(
            BuiltinFunctions::effect_class_for_invocation("__XPath", &["//value".to_owned()]),
            Some(EffectClass::TransactionalExternal)
        );
        assert_eq!(
            BuiltinFunctions::effect_class_for_invocation(
                "__StringToFile",
                &["out.txt".to_owned(), "value".to_owned()],
            ),
            Some(EffectClass::IrreversibleExternal)
        );
        assert_eq!(
            BuiltinFunctions::requirements_for_invocation("__not_a_jmeter_function", &[]),
            None
        );
    }

    #[test]
    fn java_char_conversion_preserves_pairs_and_rejects_lone_surrogates() {
        let variables = HashMap::<String, String>::new();
        let properties = HashMap::<String, String>::new();
        let functions = BuiltinFunctions::new();
        let evaluator = Evaluator::new(&variables, &properties, &functions);
        assert_eq!(
            evaluator.evaluate("${__char(0xD83D,0xDE00)}"),
            Ok("😀".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__char(+65,0102,0x43)}"),
            Ok("ABC".to_owned())
        );
        assert!(matches!(
            evaluator.evaluate("${__char(0x1F600,0xD800,not-a-number,65)}"),
            Err(crate::EvaluationError::Function {
                source: FunctionError::Unsupported(_),
                ..
            })
        ));
        assert!(matches!(
            evaluator.evaluate(r"${__unescape(\uD800)}"),
            Err(crate::EvaluationError::Function {
                source: FunctionError::Unsupported(_),
                ..
            })
        ));
    }

    #[test]
    fn integer_sums_use_java_width_wrapping() {
        let variables = HashMap::<String, String>::new();
        let properties = HashMap::<String, String>::new();
        let functions = BuiltinFunctions::new();
        let evaluator = Evaluator::new(&variables, &properties, &functions);
        assert_eq!(
            evaluator.evaluate("${__intSum(2147483647,1)}"),
            Ok("-2147483648".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__longSum(9223372036854775807,1)}"),
            Ok("-9223372036854775808".to_owned())
        );
    }

    #[test]
    fn random_rejection_is_bounded() {
        let variables = HashMap::<String, String>::new();
        let properties = HashMap::<String, String>::new();
        let functions = BuiltinFunctions::new();
        let random = FixedRandom(0);
        let capabilities = EvaluationCapabilities::new().with_random_source(&random);
        let evaluator =
            Evaluator::with_capabilities(&variables, &properties, &functions, capabilities);
        assert!(matches!(
            evaluator.evaluate("${__Random(0,10)}"),
            Err(crate::EvaluationError::Function {
                source: FunctionError::Execution(message),
                ..
            }) if message.contains("rejection limit")
        ));
        assert!(matches!(
            evaluator.evaluate("${__Random(0,9223372036854775807)}"),
            Err(crate::EvaluationError::Function {
                source: FunctionError::InvalidArguments(_),
                ..
            })
        ));
    }

    #[test]
    fn counter_state_is_scoped_by_occurrence_group_thread_and_lifecycle() {
        let variables = HashMap::<String, String>::new();
        let properties = HashMap::<String, String>::new();
        let functions = BuiltinFunctions::new();
        let no_iteration = Evaluator::new(&variables, &properties, &functions);
        assert!(matches!(
            no_iteration.evaluate("${__counter(true)}"),
            Err(crate::EvaluationError::Function {
                source: FunctionError::Unsupported(message),
                ..
            }) if message.contains("iteration identity")
        ));
        let first = TestExecution {
            thread: 1,
            group: "group-a".to_owned(),
            lifecycle: 10,
            iteration: 0,
        };
        let first_caps = EvaluationCapabilities::new().with_execution_context(&first);
        let first_eval =
            Evaluator::with_capabilities(&variables, &properties, &functions, first_caps);
        assert_eq!(
            first_eval.evaluate("${__counter(true)}"),
            Ok("1".to_owned())
        );
        assert_eq!(
            first_eval.evaluate("${__counter(true)}"),
            Ok("1".to_owned())
        );
        assert_eq!(
            first_eval.evaluate("x${__counter(true)}"),
            Ok("x1".to_owned())
        );
        let next_iteration = TestExecution {
            iteration: 1,
            ..first.clone()
        };
        let next_iteration_eval = Evaluator::with_capabilities(
            &variables,
            &properties,
            &functions,
            EvaluationCapabilities::new().with_execution_context(&next_iteration),
        );
        assert_eq!(
            next_iteration_eval.evaluate("${__counter(true)}"),
            Ok("2".to_owned())
        );

        let second_thread = TestExecution {
            thread: 2,
            group: "group-a".to_owned(),
            lifecycle: 10,
            iteration: 0,
        };
        let second_caps = EvaluationCapabilities::new().with_execution_context(&second_thread);
        let second_eval =
            Evaluator::with_capabilities(&variables, &properties, &functions, second_caps);
        assert_eq!(
            second_eval.evaluate("${__counter(true)}"),
            Ok("1".to_owned())
        );

        let second_lifecycle = TestExecution {
            thread: 1,
            group: "group-a".to_owned(),
            lifecycle: 11,
            iteration: 0,
        };
        let lifecycle_caps =
            EvaluationCapabilities::new().with_execution_context(&second_lifecycle);
        let lifecycle_eval =
            Evaluator::with_capabilities(&variables, &properties, &functions, lifecycle_caps);
        assert_eq!(
            lifecycle_eval.evaluate("${__counter(true)}"),
            Ok("1".to_owned())
        );

        let second_group = TestExecution {
            thread: 1,
            group: "group-b".to_owned(),
            lifecycle: 10,
            iteration: 0,
        };
        let group_caps = EvaluationCapabilities::new().with_execution_context(&second_group);
        let group_eval =
            Evaluator::with_capabilities(&variables, &properties, &functions, group_caps);
        assert_eq!(
            group_eval.evaluate("${__counter(true)}"),
            Ok("1".to_owned())
        );
    }

    #[test]
    fn nested_function_occurrences_use_collision_free_paths() {
        let variables = HashMap::from([("EXPR".to_owned(), "${__counter(false)}".to_owned())]);
        let properties = HashMap::<String, String>::new();
        let functions = BuiltinFunctions::new();
        let execution = TestExecution {
            thread: 1,
            group: "group-a".to_owned(),
            lifecycle: 10,
            iteration: 0,
        };
        let evaluator = Evaluator::with_capabilities(
            &variables,
            &properties,
            &functions,
            EvaluationCapabilities::new().with_execution_context(&execution),
        );

        assert_eq!(
            evaluator.evaluate("${__eval(${__counter(false)})}"),
            Ok("1".to_owned())
        );
        let next_execution = TestExecution {
            iteration: 1,
            ..execution.clone()
        };
        let next = Evaluator::with_capabilities(
            &variables,
            &properties,
            &functions,
            EvaluationCapabilities::new().with_execution_context(&next_execution),
        );
        assert_eq!(
            next.evaluate("${__counter(false)}"),
            Ok("1".to_owned()),
            "a top-level occurrence must not collide with a nested occurrence"
        );
        let functions = BuiltinFunctions::new();
        let evaluator = Evaluator::with_capabilities(
            &variables,
            &properties,
            &functions,
            EvaluationCapabilities::new().with_execution_context(&execution),
        );
        assert_eq!(evaluator.evaluate("${__evalVar(EXPR)}"), Ok("1".to_owned()));
        let next = Evaluator::with_capabilities(
            &variables,
            &properties,
            &functions,
            EvaluationCapabilities::new().with_execution_context(&next_execution),
        );
        assert_eq!(
            next.evaluate("${__counter(false)}"),
            Ok("1".to_owned()),
            "an indirection occurrence must not collide with a root occurrence"
        );
    }

    #[test]
    fn counter_capacity_is_fail_closed_without_eviction_or_reset() {
        let variables = HashMap::<String, String>::new();
        let properties = HashMap::<String, String>::new();
        let functions = BuiltinFunctions::new();
        let execution = TestExecution {
            thread: 1,
            group: "group-a".to_owned(),
            lifecycle: 10,
            iteration: 0,
        };
        let capabilities = EvaluationCapabilities::new().with_execution_context(&execution);
        for namespace in 0..MAX_COUNTER_ENTRIES as u64 {
            let evaluator = Evaluator::new(&variables, &properties, &functions)
                .with_function_capabilities(capabilities)
                .with_function_instance_namespace(namespace);
            assert_eq!(
                evaluator.evaluate("${__counter(false)}"),
                Ok("1".to_owned()),
                "namespace {namespace}"
            );
        }

        let exhausted = Evaluator::new(&variables, &properties, &functions)
            .with_function_capabilities(capabilities)
            .with_function_instance_namespace(MAX_COUNTER_ENTRIES as u64);
        assert!(matches!(
            exhausted.evaluate("${__counter(false)}"),
            Err(crate::EvaluationError::Function {
                source: FunctionError::ResourceLimit(message),
                ..
            }) if message.contains("capacity")
        ));
        let next_iteration = TestExecution {
            iteration: 1,
            ..execution
        };
        let next = Evaluator::new(&variables, &properties, &functions)
            .with_function_capabilities(
                EvaluationCapabilities::new().with_execution_context(&next_iteration),
            )
            .with_function_instance_namespace(0);
        assert!(matches!(
            next.evaluate("${__counter(false)}"),
            Err(crate::EvaluationError::Function {
                source: FunctionError::ResourceLimit(_),
                ..
            })
        ));
    }

    #[test]
    fn counter_rejects_unbounded_thread_group_identity() {
        let variables = HashMap::<String, String>::new();
        let properties = HashMap::<String, String>::new();
        let functions = BuiltinFunctions::new();
        let execution = TestExecution {
            thread: 1,
            group: "g".repeat(MAX_COUNTER_GROUP_BYTES + 1),
            lifecycle: 10,
            iteration: 0,
        };
        let evaluator = Evaluator::with_capabilities(
            &variables,
            &properties,
            &functions,
            EvaluationCapabilities::new().with_execution_context(&execution),
        );
        assert!(matches!(
            evaluator.evaluate("${__counter(true)}"),
            Err(crate::EvaluationError::Function {
                source: FunctionError::ResourceLimit(_),
                ..
            })
        ));
    }

    #[test]
    fn poisoned_counter_cleanup_is_visible_to_callers() {
        let functions = BuiltinFunctions::new();
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = match functions.counters.lock() {
                Ok(guard) => guard,
                Err(_) => std::panic::resume_unwind(Box::new(
                    "counter state was already poisoned before the regression test",
                )),
            };
            std::panic::resume_unwind(Box::new("poison counter state for cleanup regression"));
        }));
        assert!(poisoned.is_err());
        assert!(matches!(
            functions.clear_counters_for_lifecycle(10),
            Err(FunctionError::Poisoned(message))
                if message == "counter state lock is poisoned"
        ));
    }

    #[test]
    fn support_status_accounts_for_per_evaluation_mutation_capabilities() {
        let functions = BuiltinFunctions::new();
        assert_eq!(
            functions.support_status("__split"),
            FunctionSupport::Registered
        );
        assert_eq!(
            functions.support_status("__StringFromFile"),
            FunctionSupport::Registered
        );

        let variable_store = MapVariableCapability::default();
        let variable_caps = EvaluationCapabilities::new().with_variable_setter(&variable_store);
        assert_eq!(
            functions.support_status_with_capabilities("__split", variable_caps),
            FunctionSupport::Executable
        );
        let files = ReadFiles::new("value");
        let file_and_variable_caps = variable_caps.with_file_capability(&files);
        assert_eq!(
            functions.support_status_for("__StringFromFile", file_and_variable_caps),
            FunctionSupport::Executable
        );

        let property_store = MapPropertyCapability::default();
        assert_eq!(
            functions.support_status_with_capabilities(
                "__setProperty",
                EvaluationCapabilities::new().with_property_setter(&property_store),
            ),
            FunctionSupport::Executable
        );
    }

    #[test]
    fn split_matches_jmeter_character_set_and_clears_stale_values() {
        let variables = HashMap::<String, String>::new();
        let properties = HashMap::<String, String>::new();
        let variable_store = MapVariableCapability::new([("parts_4", "stale")]);
        let functions = BuiltinFunctions::new();
        let capabilities = EvaluationCapabilities::new().with_variable_setter(&variable_store);
        let evaluator =
            Evaluator::with_capabilities(&variables, &properties, &functions, capabilities);
        assert_eq!(
            evaluator.evaluate(
                "${__split(a|b;c,parts,|;)}:${parts_n}:${parts_1}:${parts_2}:${parts_3}:${parts_4}"
            ),
            Ok("a|b;c:3:a:b:c:${parts_4}".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__split(a\\,b,other)}:${other_n}:${other_1}:${other_2}"),
            Ok("a,b:2:a:b".to_owned())
        );
    }

    #[test]
    fn string_from_file_passes_sequences_and_uses_default_variable() {
        let variables = HashMap::<String, String>::new();
        let properties = HashMap::<String, String>::new();
        let files = RecordingFiles::default();
        let variable_store = MapVariableCapability::default();
        let functions = BuiltinFunctions::new();
        let capabilities = EvaluationCapabilities::new()
            .with_file_capability(&files)
            .with_variable_setter(&variable_store);
        let evaluator =
            Evaluator::with_capabilities(&variables, &properties, &functions, capabilities);
        assert_eq!(
            evaluator.evaluate("${__StringFromFile(file,OUT,2,7)}:${OUT}"),
            Ok("file|OUT|Some(2)|Some(7):file|OUT|Some(2)|Some(7)".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__StringFromFile(file)}"),
            Ok("file|StringFromFile_|None|None".to_owned())
        );
        assert!(matches!(
            evaluator.evaluate("${__StringFromFile(file,OUT,not-a-number,also-bad)}"),
            Err(crate::EvaluationError::Function {
                source: FunctionError::InvalidArguments(_),
                ..
            })
        ));
        assert_eq!(
            mutex_snapshot(&files.lines),
            Some(vec![
                "file|OUT|Some(2)|Some(7)".to_owned(),
                "file|StringFromFile_|None|None".to_owned(),
            ])
        );
        let snapshot = variable_store.snapshot();
        assert_eq!(
            snapshot
                .as_ref()
                .ok()
                .and_then(|values| values.get("StringFromFile_").map(String::as_str)),
            Some("file|StringFromFile_|None|None")
        );
        assert_eq!(
            snapshot
                .as_ref()
                .ok()
                .and_then(|values| values.get("OUT").map(String::as_str)),
            Some("file|OUT|Some(2)|Some(7)")
        );
    }

    #[test]
    fn test_plan_name_requires_an_explicit_capability() {
        let variables = HashMap::<String, String>::new();
        let properties = HashMap::<String, String>::new();
        let functions = BuiltinFunctions::new();
        let unavailable =
            Evaluator::new(&variables, &properties, &functions).evaluate("${__TestPlanName()}");
        assert!(matches!(
            unavailable,
            Err(crate::EvaluationError::Function {
                source: FunctionError::Unsupported(_),
                ..
            })
        ));

        let plan_name = StaticTestPlanName::new("plan.jmx");
        let capabilities = EvaluationCapabilities::new().with_test_plan_name(&plan_name);
        let evaluator =
            Evaluator::with_capabilities(&variables, &properties, &functions, capabilities);
        assert_eq!(
            evaluator.evaluate("${__TestPlanName}"),
            Ok("plan.jmx".to_owned())
        );
        let unsaved = StaticTestPlanName::unsaved();
        let capabilities = EvaluationCapabilities::new().with_test_plan_name(&unsaved);
        let evaluator =
            Evaluator::with_capabilities(&variables, &properties, &functions, capabilities);
        assert_eq!(
            evaluator.evaluate("${__TestPlanName()}"),
            Ok("Save Test plan before calling __TestPlanName function".to_owned())
        );
    }

    #[test]
    fn side_effects_are_explicit_and_visible_to_following_references() {
        let variables = HashMap::<String, String>::new();
        let properties = HashMap::<String, String>::new();
        let variable_store = MapVariableCapability::new([("OLD", "previous")]);
        let property_store = MapPropertyCapability::new([("existing", "before")]);
        let capabilities = EvaluationCapabilities::new()
            .with_variable_setter(&variable_store)
            .with_property_setter(&property_store);
        let functions = BuiltinFunctions::new();
        let evaluator =
            Evaluator::with_capabilities(&variables, &properties, &functions, capabilities);

        assert_eq!(
            evaluator.evaluate("${__changeCase(hello,UPPER,RESULT)}:${RESULT}"),
            Ok("HELLO:HELLO".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__setProperty(existing,after,true)}:${__P(existing)}"),
            Ok("before:after".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__property(existing,COPY)}:${COPY}"),
            Ok("after:after".to_owned())
        );
    }

    #[test]
    fn missing_mutation_capability_is_not_silently_ignored() {
        let variables = HashMap::<String, String>::new();
        let properties = HashMap::<String, String>::new();
        let functions = BuiltinFunctions::new();
        let evaluator = Evaluator::new(&variables, &properties, &functions);
        assert!(matches!(
            evaluator.evaluate("${__setProperty(name,value)}"),
            Err(crate::EvaluationError::Function {
                source: FunctionError::Unsupported(_),
                ..
            }),
        ));
        for input in [
            "${__property(name,RESULT)}",
            "${__changeCase(value,UPPER,RESULT)}",
            "${__escapeOroRegexpChars(value,RESULT)}",
            "${__timeShift(yyyy-MM-dd,2020-01-01,P1D,,RESULT)}",
        ] {
            assert!(
                matches!(
                    evaluator.evaluate(input),
                    Err(crate::EvaluationError::Function {
                        source: FunctionError::Unsupported(_),
                        ..
                    })
                ),
                "optional write {input}"
            );
        }
    }

    #[test]
    fn invalid_arguments_and_unknown_names_have_distinct_results() {
        let variables = HashMap::<String, String>::new();
        let properties = HashMap::<String, String>::new();
        let functions = BuiltinFunctions::new();
        let evaluator = Evaluator::new(&variables, &properties, &functions);
        assert_eq!(
            evaluator.evaluate("${__char(not-a-number)}"),
            Ok(String::new())
        );
        assert!(matches!(
            evaluator.evaluate("${__urlencode()}"),
            Err(crate::EvaluationError::Function {
                source: FunctionError::InvalidArguments(_),
                ..
            })
        ));
        assert!(matches!(
            evaluator.evaluate("${__samplerName(one,two)}"),
            Err(crate::EvaluationError::Function {
                source: FunctionError::InvalidArguments(_),
                ..
            })
        ));
        assert!(matches!(
            evaluator.evaluate("${__timeShift(a,b,c,d,e,f)}"),
            Err(crate::EvaluationError::Function {
                source: FunctionError::InvalidArguments(_),
                ..
            })
        ));
        assert!(matches!(
            evaluator.evaluate("${__Random(1,2)}"),
            Err(crate::EvaluationError::Function {
                source: FunctionError::Unsupported(_),
                ..
            })
        ));
        assert_eq!(
            evaluator.evaluate("${__digest(MD5,hello,,not-a-boolean)}"),
            Ok("5d41402abc4b2a76b9719d911017c592".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__random(1,2)}"),
            Ok("${__random(1,2)}".to_owned())
        );
    }

    #[test]
    fn codecs_reject_invalid_input_without_panicking() {
        let variables = HashMap::<String, String>::new();
        let properties = HashMap::<String, String>::new();
        let functions = BuiltinFunctions::new();
        let evaluator = Evaluator::new(&variables, &properties, &functions);
        for input in ["${__urldecode(%ZZ)}", "${__urldecode(%A)}"] {
            assert!(evaluator.evaluate(input).is_err(), "invalid case {input}");
        }

        let bounded = Evaluator::with_limits(
            &variables,
            &properties,
            &functions,
            crate::EvaluationLimits::new(100, 10, 10, 1),
        );
        assert_eq!(bounded.evaluate("${__urlencode(a)}"), Ok("a".to_owned()));
        assert!(matches!(
            bounded.evaluate("${__urlencode(%)}"),
            Err(crate::EvaluationError::Function {
                source: FunctionError::Execution(_),
                ..
            })
        ));
    }

    #[test]
    fn capability_stores_are_isolated_and_registry_is_thread_safe() {
        let first = MapVariableCapability::default();
        let second = MapVariableCapability::default();
        let properties = HashMap::<String, String>::new();
        let functions = Arc::new(BuiltinFunctions::new());
        let first_caps = EvaluationCapabilities::new().with_variable_setter(&first);
        let second_caps = EvaluationCapabilities::new().with_variable_setter(&second);
        let first_variables = HashMap::<String, String>::new();
        let second_variables = HashMap::<String, String>::new();
        let first_eval =
            Evaluator::with_capabilities(&first_variables, &properties, &*functions, first_caps);
        let second_eval =
            Evaluator::with_capabilities(&second_variables, &properties, &*functions, second_caps);
        assert_eq!(
            first_eval.evaluate("${__changeCase(first,UPPER,VALUE)}:${VALUE}"),
            Ok("FIRST:FIRST".to_owned())
        );
        assert_eq!(second_eval.evaluate("${VALUE}"), Ok("${VALUE}".to_owned()));

        thread::scope(|scope| {
            let mut workers = Vec::new();
            for _ in 0..8 {
                let functions = Arc::clone(&functions);
                workers.push(scope.spawn(move || {
                    let variables = HashMap::from([("x".to_owned(), "value".to_owned())]);
                    let properties = HashMap::<String, String>::new();
                    let evaluator = Evaluator::new(&variables, &properties, &*functions);
                    for _ in 0..100 {
                        assert_eq!(
                            evaluator.evaluate("${__changeCase(${x},UPPER)}"),
                            Ok("VALUE".to_owned())
                        );
                    }
                }));
            }
            for worker in workers {
                assert!(worker.join().is_ok());
            }
        });
    }

    #[test]
    fn digest_defaults_to_lowercase_and_uses_java_boolean_parsing() {
        let variables = HashMap::<String, String>::new();
        let properties = HashMap::<String, String>::new();
        let functions = BuiltinFunctions::new();
        let evaluator = Evaluator::new(&variables, &properties, &functions);
        assert_eq!(
            evaluator.evaluate("${__digest(MD5,hello)}"),
            Ok("5d41402abc4b2a76b9719d911017c592".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__digest(MD5,hello,,TrUe)}"),
            Ok("5D41402ABC4B2A76B9719D911017C592".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__digest(MD5,hello,,not-true)}"),
            Ok("5d41402abc4b2a76b9719d911017c592".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__digest(MD5,hello,,)}"),
            Ok("5d41402abc4b2a76b9719d911017c592".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__digest(SHA-224,hello)}"),
            Ok("ea09ae9cc6768c50fcee903ed054556e5bfc8347907f12598aa24193".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__digest(SHA-384,hello)}"),
            Ok("59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__digest(SHA-512,hello)}"),
            Ok("9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043".to_owned())
        );
    }

    #[test]
    fn digest_md2_matches_rfc1319_vectors_and_rejects_unknown_algorithms() {
        let variables = HashMap::<String, String>::new();
        let properties = HashMap::<String, String>::new();
        let functions = BuiltinFunctions::new();
        let evaluator = Evaluator::new(&variables, &properties, &functions);
        for (input, expected) in [
            ("${__digest(MD2,)}", "8350e5a3e24c153df2275c9f80692773"),
            ("${__digest(MD2,a)}", "32ec01ec4a6dac72c0ab96fb34c0b5d1"),
            ("${__digest(MD2,abc)}", "da853b0d3f88d99b30283a69e6ded6bb"),
            (
                "${__digest(md2,abc,,TrUe)}",
                "DA853B0D3F88D99B30283A69E6DED6BB",
            ),
        ] {
            assert_eq!(
                evaluator.evaluate(input),
                Ok(expected.to_owned()),
                "{input}"
            );
        }
        assert!(matches!(
            evaluator.evaluate("${__digest(SHA-999,abc)}"),
            Err(crate::EvaluationError::Function {
                source: FunctionError::Unsupported(_),
                ..
            })
        ));
        assert!(matches!(
            evaluator.evaluate("${__digest(SHA256,abc)}"),
            Err(crate::EvaluationError::Function {
                source: FunctionError::Unsupported(_),
                ..
            })
        ));
    }

    #[test]
    fn evaluator_occurrence_namespace_separates_identical_fields() {
        let variables = HashMap::<String, String>::new();
        let properties = HashMap::<String, String>::new();
        let functions = BuiltinFunctions::new();
        let execution = TestExecution {
            thread: 1,
            group: "group-a".to_owned(),
            lifecycle: 10,
            iteration: 0,
        };
        let capabilities = EvaluationCapabilities::new().with_execution_context(&execution);
        let first = Evaluator::new(&variables, &properties, &functions)
            .with_function_capabilities(capabilities)
            .with_function_instance_namespace(101);
        let second = Evaluator::new(&variables, &properties, &functions)
            .with_function_capabilities(capabilities)
            .with_function_instance_namespace(202);
        assert_eq!(first.evaluate("${__counter(false)}"), Ok("1".to_owned()));
        assert_eq!(second.evaluate("${__counter(false)}"), Ok("1".to_owned()));
        assert_eq!(first.evaluate("${__counter(false)}"), Ok("1".to_owned()));
        assert_eq!(second.evaluate("${__counter(false)}"), Ok("1".to_owned()));
        let next_execution = TestExecution {
            iteration: 1,
            ..execution
        };
        let next = Evaluator::new(&variables, &properties, &functions)
            .with_function_capabilities(
                EvaluationCapabilities::new().with_execution_context(&next_execution),
            )
            .with_function_instance_namespace(101);
        assert_eq!(next.evaluate("${__counter(false)}"), Ok("2".to_owned()));
    }

    #[test]
    fn counter_clone_is_independent_while_shared_registry_keeps_state() {
        let variables = HashMap::<String, String>::new();
        let properties = HashMap::<String, String>::new();
        let execution = TestExecution {
            thread: 1,
            group: "group-a".to_owned(),
            lifecycle: 10,
            iteration: 0,
        };
        let capabilities = EvaluationCapabilities::new().with_execution_context(&execution);

        let functions = BuiltinFunctions::new();
        let original =
            Evaluator::with_capabilities(&variables, &properties, &functions, capabilities);
        assert_eq!(original.evaluate("${__counter(true)}"), Ok("1".to_owned()));
        let cloned_functions = functions.clone();
        let cloned =
            Evaluator::with_capabilities(&variables, &properties, &cloned_functions, capabilities);
        assert_eq!(cloned.evaluate("${__counter(true)}"), Ok("1".to_owned()));
        assert_eq!(original.evaluate("${__counter(true)}"), Ok("1".to_owned()));

        let shared_functions = Arc::new(BuiltinFunctions::new());
        let shared_first =
            Evaluator::with_capabilities(&variables, &properties, &*shared_functions, capabilities);
        let shared_second =
            Evaluator::with_capabilities(&variables, &properties, &*shared_functions, capabilities);
        assert_eq!(
            shared_first.evaluate("${__counter(true)}"),
            Ok("1".to_owned())
        );
        assert_eq!(
            shared_second.evaluate("${__counter(true)}"),
            Ok("1".to_owned())
        );
    }

    #[test]
    fn uuid_is_lowercase_rfc4122_v4_with_injected_randomness() {
        let variables = HashMap::<String, String>::new();
        let properties = HashMap::<String, String>::new();
        let functions = BuiltinFunctions::new();
        let random = FixedRandom(u64::MAX);
        let capabilities = EvaluationCapabilities::new().with_random_source(&random);
        let evaluator =
            Evaluator::with_capabilities(&variables, &properties, &functions, capabilities);
        assert_eq!(
            evaluator.evaluate("${__UUID}"),
            Ok("ffffffff-ffff-4fff-bfff-ffffffffffff".to_owned())
        );
    }

    #[test]
    fn random_date_uses_an_exclusive_end_and_rejects_single_day_ranges() {
        let variables = HashMap::<String, String>::new();
        let properties = HashMap::<String, String>::new();
        let functions = BuiltinFunctions::new();
        let random = SequenceRandom::new([172_800_000 - 1], 0);
        let clock = TestClock {
            millis: 1_577_836_800_000,
            offset: 0,
            locale: Some("en_US".to_owned()),
        };
        let capabilities = EvaluationCapabilities::new()
            .with_random_source(&random)
            .with_clock(&clock);
        let evaluator =
            Evaluator::with_capabilities(&variables, &properties, &functions, capabilities);
        assert_eq!(
            evaluator.evaluate("${__RandomDate(yyyy-MM-dd,2020-01-01,2020-01-03,,)}"),
            Ok("2020-01-02".to_owned())
        );
        assert!(matches!(
            evaluator.evaluate("${__RandomDate(yyyy-MM-dd,2020-01-01,2020-01-01,,)}"),
            Err(crate::EvaluationError::Function {
                source: FunctionError::InvalidArguments(_),
                ..
            })
        ));
    }

    #[test]
    fn global_counter_is_one_sequence_per_occurrence_and_lifecycle_cleanup_is_bounded() {
        let variables = HashMap::<String, String>::new();
        let properties = HashMap::<String, String>::new();
        let functions = BuiltinFunctions::new();
        let first = TestExecution {
            thread: 1,
            group: "group-a".to_owned(),
            lifecycle: 41,
            iteration: 0,
        };
        let second = TestExecution {
            thread: 2,
            group: "group-b".to_owned(),
            lifecycle: 99,
            iteration: 0,
        };
        let first_eval = Evaluator::with_capabilities(
            &variables,
            &properties,
            &functions,
            EvaluationCapabilities::new().with_execution_context(&first),
        );
        let second_eval = Evaluator::with_capabilities(
            &variables,
            &properties,
            &functions,
            EvaluationCapabilities::new().with_execution_context(&second),
        );
        assert_eq!(
            first_eval.evaluate("${__counter(false)}"),
            Ok("1".to_owned())
        );
        assert_eq!(
            second_eval.evaluate("${__counter(false)}"),
            Ok("2".to_owned())
        );
        assert_eq!(
            first_eval.evaluate("${__counter(false)}:${__counter(false)}"),
            Ok("1:1".to_owned())
        );
        let first_next_iteration = TestExecution {
            iteration: 1,
            ..first.clone()
        };
        let first_next_iteration_eval = Evaluator::with_capabilities(
            &variables,
            &properties,
            &functions,
            EvaluationCapabilities::new().with_execution_context(&first_next_iteration),
        );
        assert_eq!(
            first_next_iteration_eval.evaluate("${__counter(false)}"),
            Ok("3".to_owned())
        );

        assert_eq!(
            first_eval.evaluate("${__counter(true)}"),
            Ok("1".to_owned())
        );
        assert!(functions.clear_counters_for_lifecycle(41).is_ok());
        assert_eq!(
            first_eval.evaluate("${__counter(true)}"),
            Ok("1".to_owned())
        );
    }

    #[test]
    fn string_from_file_has_occurrence_cursors_and_emits_stop_thread_at_eof() {
        let variables = HashMap::<String, String>::new();
        let properties = HashMap::<String, String>::new();
        let functions = BuiltinFunctions::new();
        let files = CursorFiles::new([("data.txt", vec!["one", "two"])]);
        let variable_store = MapVariableCapability::default();
        let evaluator = Evaluator::with_capabilities(
            &variables,
            &properties,
            &functions,
            EvaluationCapabilities::new()
                .with_file_capability(&files)
                .with_variable_setter(&variable_store),
        );
        assert_eq!(
            evaluator.evaluate("${__StringFromFile(data.txt,A)}:${__StringFromFile(data.txt,B)}"),
            Ok("one:one".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__StringFromFile(data.txt,A)}:${__StringFromFile(data.txt,B)}"),
            Ok("two:two".to_owned())
        );
        assert!(matches!(
            evaluator.evaluate("${__StringFromFile(data.txt,A)}"),
            Err(crate::EvaluationError::Function {
                source: FunctionError::StopThread(_),
                ..
            })
        ));
    }

    #[test]
    fn string_to_file_returns_boolean_and_preserves_jmeter_write_options() {
        let variables = HashMap::<String, String>::new();
        let properties = HashMap::<String, String>::new();
        let functions = BuiltinFunctions::new();
        let files = WriteFiles::default();
        let evaluator = Evaluator::with_capabilities(
            &variables,
            &properties,
            &functions,
            EvaluationCapabilities::new().with_file_capability(&files),
        );
        assert_eq!(
            evaluator.evaluate("${__StringToFile( output.txt ,first)}"),
            Ok("true".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__StringToFile(output.txt,empty,)}"),
            Ok("true".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__StringToFile(output.txt,raw, TRUE )}"),
            Ok("true".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__StringToFile(output.txt,second\\nline,FALSE, UTF-8 )}"),
            Ok("true".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__StringToFile(output.txt,third,TRUE)}"),
            Ok("true".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__StringToFile(   ,ignored)}"),
            Ok("false".to_owned())
        );
        let writes = mutex_snapshot(&files.writes);
        assert_eq!(
            writes,
            Some(vec![
                ("output.txt".to_owned(), "first".to_owned(), true, None),
                ("output.txt".to_owned(), "empty".to_owned(), true, None),
                ("output.txt".to_owned(), "raw".to_owned(), true, None),
                (
                    "output.txt".to_owned(),
                    "second\nline".to_owned(),
                    false,
                    Some(" UTF-8 ".to_owned())
                ),
                ("output.txt".to_owned(), "third".to_owned(), true, None),
            ])
        );
    }

    #[test]
    fn random_string_matches_trimmed_charset_and_checks_output_before_allocating() {
        let variables = HashMap::<String, String>::new();
        let properties = HashMap::<String, String>::new();
        let functions = BuiltinFunctions::new();
        let random = FixedRandom(u64::MAX);
        let capabilities = EvaluationCapabilities::new().with_random_source(&random);
        let evaluator =
            Evaluator::with_capabilities(&variables, &properties, &functions, capabilities);
        assert_eq!(
            evaluator.evaluate("${__RandomString(4, ab )}"),
            Ok("bbbb".to_owned())
        );
        assert!(
            matches!(
                evaluator.evaluate("${__RandomString( 4 , ab )}"),
                Err(crate::EvaluationError::Function {
                    source: FunctionError::InvalidArguments(_),
                    ..
                })
            ),
            "JMeter passes RandomString's length directly to Integer.parseInt"
        );
        let controls = Evaluator::with_capabilities(
            &variables,
            &properties,
            &functions,
            EvaluationCapabilities::new().with_random_source(&FixedRandom(0x10_FF_FF)),
        );
        assert_eq!(
            controls.evaluate("${__RandomString(1)}"),
            Ok("\0".to_owned())
        );
        let rejected = Evaluator::with_capabilities(
            &variables,
            &properties,
            &functions,
            EvaluationCapabilities::new().with_random_source(&FixedRandom(u64::MAX)),
        );
        assert!(matches!(
            rejected.evaluate("${__RandomString(1)}"),
            Err(crate::EvaluationError::Function {
                source: FunctionError::Execution(message),
                ..
            }) if message.contains("rejection limit")
        ));
        let tiny = Evaluator::with_limits_and_capabilities(
            &variables,
            &properties,
            &functions,
            crate::EvaluationLimits::new(100, 10, 10, 3),
            EvaluationCapabilities::new().with_random_source(&random),
        );
        assert!(matches!(
            tiny.evaluate("${__RandomString(4,ab)}"),
            Err(crate::EvaluationError::Function {
                source: FunctionError::Execution(message),
                ..
            }) if message.contains("output bound")
        ));
        let ascii_tiny = Evaluator::with_limits_and_capabilities(
            &variables,
            &properties,
            &functions,
            crate::EvaluationLimits::new(100, 10, 10, 3),
            EvaluationCapabilities::new().with_random_source(&random),
        );
        assert_eq!(
            ascii_tiny.evaluate("${__RandomString(2,a)}"),
            Ok("aa".to_owned())
        );
        assert!(matches!(
            evaluator.evaluate("${__RandomString(not-a-number,ab)}"),
            Err(crate::EvaluationError::Function {
                source: FunctionError::InvalidArguments(_),
                ..
            })
        ));
    }

    #[test]
    fn random_from_multiple_vars_preserves_names_handles_match_count_and_empty_results() {
        let variables = HashMap::<String, String>::new();
        let properties = HashMap::<String, String>::new();
        let variable_store = MapVariableCapability::new([
            ("A_matchNr", "2"),
            ("A_1", "first"),
            ("A_2", "second"),
            ("B", "third"),
        ]);
        let functions = BuiltinFunctions::new();
        let random = FixedRandom(3);
        let capabilities = EvaluationCapabilities::new()
            .with_random_source(&random)
            .with_variable_setter(&variable_store);
        let evaluator =
            Evaluator::with_capabilities(&variables, &properties, &functions, capabilities);
        assert_eq!(
            evaluator.evaluate("${__RandomFromMultipleVars( A | B ,PICK)}:${PICK}"),
            Ok(":".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__RandomFromMultipleVars(A|B,PICK)}:${PICK}"),
            Ok("first:first".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__RandomFromMultipleVars(MISSING,EMPTY)}:${EMPTY}"),
            Ok(":".to_owned())
        );
        let oversized =
            MapVariableCapability::new([("A_matchNr", (MAX_RANDOM_VALUES + 1).to_string())]);
        let empty_variables = HashMap::<String, String>::new();
        let evaluator = Evaluator::with_capabilities(
            &empty_variables,
            &properties,
            &functions,
            EvaluationCapabilities::new().with_variable_setter(&oversized),
        );
        assert!(matches!(
            evaluator.evaluate("${__RandomFromMultipleVars(A)}"),
            Err(crate::EvaluationError::Function {
                source: FunctionError::InvalidArguments(_),
                ..
            })
        ));

        let scalar_fallback = MapVariableCapability::new([("A_matchNr", "-1"), ("A", "scalar")]);
        let evaluator = Evaluator::with_capabilities(
            &empty_variables,
            &properties,
            &functions,
            EvaluationCapabilities::new()
                .with_random_source(&FixedRandom(0))
                .with_variable_setter(&scalar_fallback),
        );
        assert_eq!(
            evaluator.evaluate("${__RandomFromMultipleVars(A)}"),
            Ok("scalar".to_owned())
        );

        let untrimmed_match_nr = MapVariableCapability::new([
            ("A_matchNr", " 1 "),
            ("A", "scalar"),
            ("A_1", "numbered"),
        ]);
        let evaluator = Evaluator::with_capabilities(
            &empty_variables,
            &properties,
            &functions,
            EvaluationCapabilities::new()
                .with_random_source(&FixedRandom(0))
                .with_variable_setter(&untrimmed_match_nr),
        );
        assert!(matches!(
            evaluator.evaluate("${__RandomFromMultipleVars(A)}"),
            Err(crate::EvaluationError::Function {
                source: FunctionError::InvalidArguments(_),
                ..
            })
        ));
    }

    #[test]
    fn date_time_locale_and_external_capabilities_fail_closed() {
        let variables = HashMap::<String, String>::new();
        let properties = HashMap::<String, String>::new();
        let functions = BuiltinFunctions::new();
        let clock = TestClock {
            millis: 1_577_836_800_000,
            offset: 0,
            locale: Some("fr_FR".to_owned()),
        };
        let random = FixedRandom(u64::MAX);
        let evaluator = Evaluator::with_capabilities(
            &variables,
            &properties,
            &functions,
            EvaluationCapabilities::new()
                .with_clock(&clock)
                .with_random_source(&random),
        );
        let static_variables = HashMap::from([("__time".to_owned(), "static".to_owned())]);
        let static_evaluator = Evaluator::with_capabilities(
            &static_variables,
            &properties,
            &functions,
            EvaluationCapabilities::new().with_clock(&clock),
        );
        assert_eq!(
            static_evaluator.evaluate("${__time}"),
            Ok("static".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__RandomDate(dd MMMM yyyy,01 janvier 2020,02 janvier 2020,,)}"),
            Ok("01 janvier 2020".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__time(yyyy-MM-dd HH:mm)}"),
            Ok("2020-01-01 00:00".to_owned())
        );
        let narrow = Evaluator::with_limits_and_capabilities(
            &variables,
            &properties,
            &functions,
            crate::EvaluationLimits::new(100, 10, 10, 1),
            EvaluationCapabilities::new().with_clock(&clock),
        );
        assert_eq!(narrow.evaluate("${__time(-)}"), Ok("-".to_owned()));
        assert_eq!(
            evaluator.evaluate("${__timeShift(yyyy-MM-dd,2020-01-01,P1D,)}"),
            Ok("2020-01-02".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__timeShift(,,,)}"),
            Ok("1577836800000".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__timeShift(yyyy-MM-dd,,,)}"),
            Ok("2020-01-01".to_owned())
        );
        let shifted_variable = MapVariableCapability::default();
        let shifted_evaluator = Evaluator::with_capabilities(
            &variables,
            &properties,
            &functions,
            EvaluationCapabilities::new()
                .with_clock(&clock)
                .with_variable_setter(&shifted_variable),
        );
        assert_eq!(
            shifted_evaluator.evaluate("${__timeShift(yyyy-MM-dd,2020-01-01,P1D,,SHIFT)}:${SHIFT}"),
            Ok("2020-01-02:2020-01-02".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__timeShift(dd MMMM yyyy,21 février 2018,P2D,fr_FR,)}"),
            Ok("23 février 2018".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__timeShift(yyyy-MM-dd,2020-01-01,P1D,,)}"),
            Ok("2020-01-02".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__timeShift(yyyy-MM-dd,2020-01-01,PT0.5S,,)}"),
            Ok("2020-01-01".to_owned())
        );
        assert!(matches!(
            evaluator.evaluate("${__timeShift(yyyy-MM-dd,2020-01-01,not-a-duration,,)}"),
            Err(crate::EvaluationError::Function {
                source: FunctionError::InvalidArguments(_),
                ..
            })
        ));
        assert_eq!(
            evaluator.evaluate("${__dateTimeConvert(1577836800000,,yyyy-MM-dd)}"),
            Ok("2020-01-01".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__dateTimeConvert(1577836800000,,yyyy-MM-dd''X)}"),
            Ok("2020-01-01'Z".to_owned())
        );
        assert_eq!(evaluator.evaluate("${__time(USER1)}"), Ok(String::new()));
        assert!(matches!(
            evaluator.evaluate("${__time(ww)}"),
            Err(crate::EvaluationError::Function {
                source: FunctionError::Unsupported(_),
                ..
            })
        ));
        assert!(matches!(
            evaluator.evaluate("${__dateTimeConvert(1577836800123,,yyyy-MM-dd.SSSS)}"),
            Err(crate::EvaluationError::Function {
                source: FunctionError::Unsupported(_),
                ..
            })
        ));
        assert!(matches!(
            evaluator.evaluate("${__RandomDate(yyyy-MM-dd,2020-01-01,2020-01-02,de_DE,)}"),
            Err(crate::EvaluationError::Function {
                source: FunctionError::Unsupported(_),
                ..
            })
        ));
        for name in [
            "__BeanShell",
            "__groovy",
            "__javaScript",
            "__jexl2",
            "__jexl3",
        ] {
            let input = format!("${{{name}(1)}}");
            assert!(matches!(
                evaluator.evaluate(&input),
                Err(crate::EvaluationError::Function {
                    source: FunctionError::Unsupported(_),
                    ..
                })
            ));
        }
        for input in ["${__XPath(xml,path)}", "${__regexFunction(pat,1)}"] {
            assert!(matches!(
                evaluator.evaluate(input),
                Err(crate::EvaluationError::Function {
                    source: FunctionError::Unsupported(_),
                    ..
                })
            ));
        }
    }

    #[test]
    fn html_xml_oro_csv_and_nested_eval_follow_explicit_contracts() {
        let variables =
            HashMap::from([("EXPR".to_owned(), "${__changeCase(ok,UPPER)}".to_owned())]);
        let properties = HashMap::<String, String>::new();
        let functions = BuiltinFunctions::new();
        let evaluator = Evaluator::new(&variables, &properties, &functions);
        assert_eq!(
            evaluator.evaluate("${__escapeHtml(α & ™)}"),
            Ok("&alpha; &amp; &trade;".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__escapeXml(é & ' < > \" )}"),
            Ok("é &amp; &apos; &lt; &gt; &quot; ".to_owned())
        );
        let xml_controls = "${__escapeXml(a\u{0007}\u{007f}\u{0080}b)}";
        assert_eq!(
            evaluator.evaluate(xml_controls),
            Ok("a&#127;&#128;b".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__escapeOroRegexpChars(é a.b)}"),
            Ok("é\\ a\\.b".to_owned())
        );
        assert!(matches!(
            evaluator.evaluate("${__escapeOroRegexpChars(🦀)}"),
            Err(crate::EvaluationError::Function {
                source: FunctionError::Unsupported(_),
                ..
            })
        ));
        assert_eq!(
            evaluator.evaluate("${__unescapeHtml(&alpha; &unknown;)}"),
            Ok("α &unknown;".to_owned())
        );
        assert!(matches!(
            evaluator.evaluate("${__unescapeHtml(&#xD800;)}"),
            Err(crate::EvaluationError::Function {
                source: FunctionError::Unsupported(_),
                ..
            })
        ));
        let bounded = Evaluator::with_limits(
            &variables,
            &properties,
            &functions,
            crate::EvaluationLimits::new(100, 10, 10, 2),
        );
        assert!(matches!(
            bounded.evaluate("${__escapeHtml(&)}"),
            Err(crate::EvaluationError::Function {
                source: FunctionError::Execution(message),
                ..
            }) if message.contains("output bound")
        ));
        let shrinking = Evaluator::with_limits(
            &variables,
            &properties,
            &functions,
            crate::EvaluationLimits::new(100, 10, 10, 1),
        );
        assert_eq!(
            shrinking.evaluate(r"${__unescape(\\)}"),
            Ok("\\".to_owned())
        );
        assert_eq!(
            shrinking.evaluate(r"${__unescape(\u0041)}"),
            Ok("A".to_owned())
        );
        assert_eq!(
            evaluator.evaluate("${__evalVar(EXPR)}"),
            Ok("OK".to_owned())
        );
        let files = WriteFiles::default();
        let evaluator = Evaluator::with_capabilities(
            &variables,
            &properties,
            &functions,
            EvaluationCapabilities::new().with_file_capability(&files),
        );
        assert_eq!(
            evaluator.evaluate("${__CSVRead(data.csv,0)}"),
            Ok(String::new())
        );
        assert!(matches!(
            Evaluator::new(&variables, &properties, &functions)
                .evaluate("${__CSVRead(data.csv,0)}"),
            Err(crate::EvaluationError::Function {
                source: FunctionError::Unsupported(_),
                ..
            })
        ));
    }
}
