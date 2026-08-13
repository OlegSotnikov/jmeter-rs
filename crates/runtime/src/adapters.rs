// SPDX-License-Identifier: Apache-2.0
//! Small native component adapters and explicit external boundaries.
//!
//! These adapters are intentionally deterministic and local. They cover the
//! useful runtime seam for variable/configuration/listener tests; regular
//! expression, XPath, JSON, script, and plugin behavior remains an explicit
//! unsupported capability until a pinned engine is supplied.

use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use jmeter_rs_expr::FunctionResolver;
use jmeter_rs_results::{AssertionResult, SampleEvent};

use crate::{
    Assertion, ComponentError, ComponentFuture, Configuration, Listener, Phase, Postprocessor,
    Preprocessor, SampleContext,
};

/// Maximum UTF-8 bytes retained for an adapter capability or source field.
///
/// Adapter constructors intentionally retain a bounded diagnostic even when a
/// caller supplies invalid input.  This keeps an unsupported path observable
/// without allowing a malformed JMX/plugin value to become an unbounded
/// runtime allocation.
pub const MAX_ADAPTER_TEXT_BYTES: usize = 4_096;

/// Maximum number of invocations permitted by a deterministic fake adapter.
pub const MAX_FAKE_INVOCATIONS: usize = 65_536;

/// Maximum number of events retained by an in-memory listener adapter.
pub const MAX_CAPTURED_EVENTS: usize = 65_536;

/// Maximum number of bytes captured by the bounded literal extractor.
pub const MAX_LITERAL_CAPTURE_BYTES: usize = 4_096;

fn bounded_text(value: impl Into<String>, limit: usize) -> String {
    let mut value = value.into();
    if value.len() <= limit {
        return value;
    }
    let mut end = limit;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    value
}

fn bounded_identifier(value: impl Into<String>) -> String {
    bounded_text(value, MAX_ADAPTER_TEXT_BYTES)
}

fn validate_bounded_text(
    value: &str,
    field: &'static str,
) -> Result<(), AdapterConfigurationError> {
    if value.len() > MAX_ADAPTER_TEXT_BYTES {
        return Err(AdapterConfigurationError::TooLong {
            field,
            limit: MAX_ADAPTER_TEXT_BYTES,
        });
    }
    if value.chars().any(char::is_control) {
        return Err(AdapterConfigurationError::ControlCharacter { field });
    }
    Ok(())
}

fn validate_text(value: &str, field: &'static str) -> Result<(), AdapterConfigurationError> {
    if value.is_empty() {
        return Err(AdapterConfigurationError::Empty { field });
    }
    validate_bounded_text(value, field)
}

/// Stable construction failures for local adapter configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdapterConfigurationError {
    /// A required text field was empty.
    Empty {
        /// Name of the field which was empty.
        field: &'static str,
    },
    /// A text field exceeded the adapter bound.
    TooLong {
        /// Name of the field which exceeded its bound.
        field: &'static str,
        /// Maximum accepted UTF-8 byte length.
        limit: usize,
    },
    /// A text field contained a control character.
    ControlCharacter {
        /// Name of the field containing the control character.
        field: &'static str,
    },
    /// A numeric bound was outside the supported finite range.
    Limit {
        /// Name of the bounded numeric field.
        field: &'static str,
        /// Maximum accepted value.
        limit: usize,
    },
}

impl AdapterConfigurationError {
    /// Returns a stable machine-readable code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Empty { .. } => "runtime.adapter.config.empty",
            Self::TooLong { .. } => "runtime.adapter.config.too-long",
            Self::ControlCharacter { .. } => "runtime.adapter.config.control-character",
            Self::Limit { .. } => "runtime.adapter.config.limit",
        }
    }
}

impl fmt::Display for AdapterConfigurationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty { field } => write!(formatter, "{}: {field} is empty", self.code()),
            Self::TooLong { field, limit } => {
                write!(formatter, "{}: {field} exceeds {limit} bytes", self.code())
            }
            Self::ControlCharacter { field } => write!(
                formatter,
                "{}: {field} contains a control character",
                self.code()
            ),
            Self::Limit { field, limit } => {
                write!(formatter, "{}: {field} exceeds {limit}", self.code())
            }
        }
    }
}

impl std::error::Error for AdapterConfigurationError {}

/// The implementation path represented by an adapter descriptor.
///
/// `NativeFixture` is deliberately narrower than a JMeter compatibility
/// claim: it identifies the bounded Rust adapter below, not the corresponding
/// Java/provider element.  Java, service, and plugin behavior remains an
/// explicit compatibility-pack path or an unavailable path.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AdapterImplementationPath {
    /// A bounded, dependency-free Rust adapter is implemented.
    NativeFixture,
    /// Exact behavior requires the explicitly selected JVM compatibility pack.
    CompatibilityPackRequired,
    /// No implementation is available in this build/profile.
    Unavailable,
}

impl fmt::Display for AdapterImplementationPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NativeFixture => "native-fixture",
            Self::CompatibilityPackRequired => "compatibility-pack-required",
            Self::Unavailable => "unavailable",
        })
    }
}

/// A bounded capability descriptor used by local adapters and typed
/// unsupported boundaries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterCapability {
    capability_id: String,
    path: AdapterImplementationPath,
}

impl AdapterCapability {
    /// Creates a descriptor after validating the capability identifier.
    pub fn try_new(
        capability_id: impl Into<String>,
        path: AdapterImplementationPath,
    ) -> Result<Self, AdapterConfigurationError> {
        let capability_id = capability_id.into();
        validate_text(&capability_id, "capability_id")?;
        Ok(Self {
            capability_id,
            path,
        })
    }

    /// Creates a descriptor for a bounded native fixture adapter.
    ///
    /// This infallible constructor is retained for ergonomic adapter setup;
    /// invalid identifiers are represented by a bounded descriptor and are
    /// rejected by [`Self::validate`] before execution.
    #[must_use]
    pub fn native(capability_id: impl Into<String>) -> Self {
        Self {
            capability_id: bounded_identifier(capability_id),
            path: AdapterImplementationPath::NativeFixture,
        }
    }

    /// Creates a descriptor for a JVM/provider capability that is not
    /// available in the standalone executable.
    #[must_use]
    pub fn compatibility_pack(capability_id: impl Into<String>) -> Self {
        Self {
            capability_id: bounded_identifier(capability_id),
            path: AdapterImplementationPath::CompatibilityPackRequired,
        }
    }

    /// Creates a descriptor for an unavailable capability.
    #[must_use]
    pub fn unavailable(capability_id: impl Into<String>) -> Self {
        Self {
            capability_id: bounded_identifier(capability_id),
            path: AdapterImplementationPath::Unavailable,
        }
    }

    /// Validates the descriptor before use.
    pub fn validate(&self) -> Result<(), AdapterConfigurationError> {
        validate_text(&self.capability_id, "capability_id")
    }

    /// Returns the bounded capability identifier.
    #[must_use]
    pub fn capability_id(&self) -> &str {
        &self.capability_id
    }

    /// Returns the selected implementation path.
    #[must_use]
    pub const fn path(&self) -> AdapterImplementationPath {
        self.path
    }
}

/// Stable reason attached to an unavailable external adapter.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AdapterUnavailableReason {
    /// The optional JVM compatibility pack was not selected.
    CompatibilityPackNotSelected,
    /// A provider/driver/plugin is not present in the selected pack.
    ProviderUnavailable,
    /// A required external service is not declared/available.
    ServiceUnavailable,
    /// The capability is not implemented by this product projection.
    UnsupportedCapability,
}

impl fmt::Display for AdapterUnavailableReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CompatibilityPackNotSelected => "compatibility-pack-not-selected",
            Self::ProviderUnavailable => "provider-unavailable",
            Self::ServiceUnavailable => "service-unavailable",
            Self::UnsupportedCapability => "unsupported-capability",
        })
    }
}

/// A typed external/unavailable adapter path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterUnavailable {
    capability: AdapterCapability,
    reason: AdapterUnavailableReason,
}

impl AdapterUnavailable {
    /// Creates an unavailable adapter boundary after validating its identity.
    pub fn try_new(
        capability_id: impl Into<String>,
        reason: AdapterUnavailableReason,
    ) -> Result<Self, AdapterConfigurationError> {
        let path = match reason {
            AdapterUnavailableReason::UnsupportedCapability => {
                AdapterImplementationPath::Unavailable
            }
            AdapterUnavailableReason::CompatibilityPackNotSelected
            | AdapterUnavailableReason::ProviderUnavailable
            | AdapterUnavailableReason::ServiceUnavailable => {
                AdapterImplementationPath::CompatibilityPackRequired
            }
        };
        Ok(Self {
            capability: AdapterCapability::try_new(capability_id, path)?,
            reason,
        })
    }

    /// Creates an unavailable adapter boundary.
    #[must_use]
    pub fn new(capability_id: impl Into<String>, reason: AdapterUnavailableReason) -> Self {
        let capability = match reason {
            AdapterUnavailableReason::UnsupportedCapability => {
                AdapterCapability::unavailable(capability_id)
            }
            AdapterUnavailableReason::CompatibilityPackNotSelected
            | AdapterUnavailableReason::ProviderUnavailable
            | AdapterUnavailableReason::ServiceUnavailable => {
                AdapterCapability::compatibility_pack(capability_id)
            }
        };
        Self { capability, reason }
    }

    /// Returns the bounded capability descriptor.
    #[must_use]
    pub const fn capability(&self) -> &AdapterCapability {
        &self.capability
    }

    /// Returns the stable unavailable reason.
    #[must_use]
    pub const fn reason(&self) -> AdapterUnavailableReason {
        self.reason
    }

    /// Converts this boundary into the executor-neutral component error.
    #[must_use]
    pub fn component_error(&self, kind: &str) -> ComponentError {
        ComponentError::unsupported(format!(
            "{kind} capability {:?} is unavailable ({})",
            self.capability.capability_id(),
            self.reason
        ))
    }
}

/// The actual local adapter inventory.  Entries marked as compatibility-pack
/// required are intentionally not executable in this crate; this inventory is
/// therefore safe to use for preflight without implying Java/provider support.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdapterCapabilityRecord {
    /// Compatibility checklist ID covered by the capability boundary.
    pub feature_id: &'static str,
    /// Stable runtime capability identity.
    pub capability_id: &'static str,
    /// Actual implementation path in this product projection.
    pub path: AdapterImplementationPath,
}

/// Adapter capability inventory for the runtime edge.
///
/// This table covers the external/script/plugin rows owned by this module;
/// ELEM-003 through ELEM-007 are classified by their core runtime modules and
/// are intentionally not duplicated here.
pub const ADAPTER_CAPABILITIES: &[AdapterCapabilityRecord] = &[
    AdapterCapabilityRecord {
        feature_id: "ELEM-001",
        capability_id: "runtime.external.samplers",
        path: AdapterImplementationPath::CompatibilityPackRequired,
    },
    AdapterCapabilityRecord {
        feature_id: "ELEM-002",
        capability_id: "runtime.external.services-and-drivers",
        path: AdapterImplementationPath::CompatibilityPackRequired,
    },
    AdapterCapabilityRecord {
        feature_id: "ELEM-008",
        capability_id: "runtime.external.processors-and-extractors",
        path: AdapterImplementationPath::CompatibilityPackRequired,
    },
    AdapterCapabilityRecord {
        feature_id: "ELEM-009",
        capability_id: "runtime.legacy.external-aliases",
        path: AdapterImplementationPath::CompatibilityPackRequired,
    },
    AdapterCapabilityRecord {
        feature_id: "FUNC-003",
        capability_id: "runtime.jvm.scripting-functions",
        path: AdapterImplementationPath::CompatibilityPackRequired,
    },
    AdapterCapabilityRecord {
        feature_id: "SCRIPT-001",
        capability_id: "runtime.jvm.jsr223",
        path: AdapterImplementationPath::CompatibilityPackRequired,
    },
    AdapterCapabilityRecord {
        feature_id: "SCRIPT-002",
        capability_id: "runtime.jvm.user-classes",
        path: AdapterImplementationPath::CompatibilityPackRequired,
    },
    AdapterCapabilityRecord {
        feature_id: "PLUG-001",
        capability_id: "runtime.jvm.plugin-discovery",
        path: AdapterImplementationPath::CompatibilityPackRequired,
    },
    AdapterCapabilityRecord {
        feature_id: "PLUG-002",
        capability_id: "runtime.jvm.plugin-contract",
        path: AdapterImplementationPath::CompatibilityPackRequired,
    },
    AdapterCapabilityRecord {
        feature_id: "PLUG-003",
        capability_id: "runtime.jvm.plugin-unavailable-diagnostics",
        path: AdapterImplementationPath::Unavailable,
    },
];

/// Returns the static runtime adapter inventory.
#[must_use]
pub const fn adapter_capabilities() -> &'static [AdapterCapabilityRecord] {
    ADAPTER_CAPABILITIES
}

fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn next_invocation(counter: &AtomicUsize) -> usize {
    match counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
        Some(current.saturating_add(1))
    }) {
        Ok(previous) | Err(previous) => previous,
    }
}

/// A configuration adapter that evaluates one expression into a request field.
pub struct ExpressionConfiguration {
    field: String,
    expression: String,
    functions: Arc<dyn FunctionResolver + Send + Sync>,
    configuration_error: Option<AdapterConfigurationError>,
    capability: AdapterCapability,
}

impl ExpressionConfiguration {
    /// Creates an expression-backed configuration element.
    #[must_use]
    pub fn new(
        field: impl Into<String>,
        expression: impl Into<String>,
        functions: Arc<dyn FunctionResolver + Send + Sync>,
    ) -> Self {
        let field = field.into();
        let expression = expression.into();
        let configuration_error = validate_text(&field, "field")
            .err()
            .or_else(|| validate_bounded_text(&expression, "expression").err());
        Self {
            field: bounded_text(field, MAX_ADAPTER_TEXT_BYTES),
            expression: bounded_text(expression, MAX_ADAPTER_TEXT_BYTES),
            functions,
            configuration_error,
            capability: AdapterCapability::native("runtime.native.expression-configuration"),
        }
    }

    /// Creates an expression configuration after validating bounded inputs.
    pub fn try_new(
        field: impl Into<String>,
        expression: impl Into<String>,
        functions: Arc<dyn FunctionResolver + Send + Sync>,
    ) -> Result<Self, AdapterConfigurationError> {
        let field = field.into();
        let expression = expression.into();
        validate_text(&field, "field")?;
        validate_bounded_text(&expression, "expression")?;
        Ok(Self {
            field,
            expression,
            functions,
            configuration_error: None,
            capability: AdapterCapability::native("runtime.native.expression-configuration"),
        })
    }

    /// Returns the exact path implemented by this adapter.
    #[must_use]
    pub const fn capability(&self) -> &AdapterCapability {
        &self.capability
    }
}

impl Configuration for ExpressionConfiguration {
    fn apply<'a>(&'a self, context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, ()> {
        Box::pin(async move {
            if let Some(error) = &self.configuration_error {
                return Err(ComponentError::resource_limit(error.to_string()));
            }
            let value = context
                .execution()
                .evaluate_expression(&self.expression, self.functions.as_ref())
                .map_err(|error| ComponentError::failure(error.to_string()))?;
            context.record(Phase::Configuration, "expression")?;
            context.set_request_value(self.field.clone(), value);
            Ok(())
        })
    }
}

/// A preprocessor that evaluates an expression into a virtual-user variable.
pub struct ExpressionPreprocessor {
    variable: String,
    expression: String,
    functions: Arc<dyn FunctionResolver + Send + Sync>,
    configuration_error: Option<AdapterConfigurationError>,
    capability: AdapterCapability,
}

impl ExpressionPreprocessor {
    /// Creates an expression-backed variable preprocessor.
    #[must_use]
    pub fn new(
        variable: impl Into<String>,
        expression: impl Into<String>,
        functions: Arc<dyn FunctionResolver + Send + Sync>,
    ) -> Self {
        let variable = variable.into();
        let expression = expression.into();
        let configuration_error = validate_text(&variable, "variable")
            .err()
            .or_else(|| validate_bounded_text(&expression, "expression").err());
        Self {
            variable: bounded_text(variable, MAX_ADAPTER_TEXT_BYTES),
            expression: bounded_text(expression, MAX_ADAPTER_TEXT_BYTES),
            functions,
            configuration_error,
            capability: AdapterCapability::native("runtime.native.expression-preprocessor"),
        }
    }

    /// Creates an expression preprocessor after validating bounded inputs.
    pub fn try_new(
        variable: impl Into<String>,
        expression: impl Into<String>,
        functions: Arc<dyn FunctionResolver + Send + Sync>,
    ) -> Result<Self, AdapterConfigurationError> {
        let variable = variable.into();
        let expression = expression.into();
        validate_text(&variable, "variable")?;
        validate_bounded_text(&expression, "expression")?;
        Ok(Self {
            variable,
            expression,
            functions,
            configuration_error: None,
            capability: AdapterCapability::native("runtime.native.expression-preprocessor"),
        })
    }

    /// Returns the exact path implemented by this adapter.
    #[must_use]
    pub const fn capability(&self) -> &AdapterCapability {
        &self.capability
    }
}

impl Preprocessor for ExpressionPreprocessor {
    fn process<'a>(&'a self, context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, ()> {
        Box::pin(async move {
            if let Some(error) = &self.configuration_error {
                return Err(ComponentError::resource_limit(error.to_string()));
            }
            let value = context
                .execution()
                .evaluate_expression(&self.expression, self.functions.as_ref())
                .map_err(|error| ComponentError::failure(error.to_string()))?;
            context.record(Phase::Preprocessor, "expression")?;
            context
                .execution_mut()
                .set_variable(self.variable.clone(), value);
            Ok(())
        })
    }
}

/// A bounded literal response extractor for deterministic local fixtures.
///
/// This is deliberately not a regular-expression implementation. It selects
/// the first literal `needle` from UTF-8 response data and stores the text
/// following it up to `capture_bytes`. Plans needing JMeter's regex/XPath/JSON
/// engines must use the typed unsupported adapter until that engine is pinned.
pub struct LiteralExtractor {
    variable: String,
    needle: String,
    capture_bytes: usize,
    configuration_error: Option<AdapterConfigurationError>,
    capability: AdapterCapability,
}

impl LiteralExtractor {
    /// Creates a literal response extractor.
    #[must_use]
    pub fn new(
        variable: impl Into<String>,
        needle: impl Into<String>,
        capture_bytes: usize,
    ) -> Self {
        let variable = variable.into();
        let needle = needle.into();
        let configuration_error = validate_text(&variable, "variable")
            .err()
            .or_else(|| validate_bounded_text(&needle, "needle").err())
            .or_else(|| {
                (capture_bytes > MAX_LITERAL_CAPTURE_BYTES).then_some(
                    AdapterConfigurationError::Limit {
                        field: "capture_bytes",
                        limit: MAX_LITERAL_CAPTURE_BYTES,
                    },
                )
            });
        Self {
            variable: bounded_text(variable, MAX_ADAPTER_TEXT_BYTES),
            needle: bounded_text(needle, MAX_ADAPTER_TEXT_BYTES),
            capture_bytes: capture_bytes.min(MAX_LITERAL_CAPTURE_BYTES),
            configuration_error,
            capability: AdapterCapability::native("runtime.native.literal-extractor"),
        }
    }

    /// Creates a literal extractor after validating bounded inputs.
    pub fn try_new(
        variable: impl Into<String>,
        needle: impl Into<String>,
        capture_bytes: usize,
    ) -> Result<Self, AdapterConfigurationError> {
        let variable = variable.into();
        let needle = needle.into();
        validate_text(&variable, "variable")?;
        validate_bounded_text(&needle, "needle")?;
        if capture_bytes > MAX_LITERAL_CAPTURE_BYTES {
            return Err(AdapterConfigurationError::Limit {
                field: "capture_bytes",
                limit: MAX_LITERAL_CAPTURE_BYTES,
            });
        }
        Ok(Self {
            variable,
            needle,
            capture_bytes,
            configuration_error: None,
            capability: AdapterCapability::native("runtime.native.literal-extractor"),
        })
    }

    /// Returns the exact path implemented by this adapter.
    #[must_use]
    pub const fn capability(&self) -> &AdapterCapability {
        &self.capability
    }
}

impl Postprocessor for LiteralExtractor {
    fn process<'a>(&'a self, context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, ()> {
        Box::pin(async move {
            if let Some(error) = &self.configuration_error {
                return Err(ComponentError::resource_limit(error.to_string()));
            }
            let Some(result) = context.result() else {
                return Err(ComponentError::failure(
                    "literal extractor response is missing",
                ));
            };
            let Some(data) = result.response_data() else {
                return Err(ComponentError::failure(
                    "literal extractor response body is missing",
                ));
            };
            let text = std::str::from_utf8(data.as_bytes())
                .map_err(|_| ComponentError::failure("literal extractor requires UTF-8"))?;
            let Some(start) = text.find(&self.needle) else {
                context
                    .execution_mut()
                    .set_variable(self.variable.clone(), String::new());
                return Ok(());
            };
            let capture_start = start.saturating_add(self.needle.len());
            let remaining = text[capture_start..].to_owned();
            let mut end = remaining.len().min(self.capture_bytes);
            while end > 0 && !remaining.is_char_boundary(end) {
                end -= 1;
            }
            context
                .execution_mut()
                .set_variable(self.variable.clone(), remaining[..end].to_owned());
            Ok(())
        })
    }
}

/// A listener that snapshots every event into a bounded local vector.
#[derive(Clone, Debug)]
pub struct CapturingListener {
    events: Arc<Mutex<Vec<SampleEvent>>>,
    max_events: usize,
    configuration_error: Option<AdapterConfigurationError>,
    capability: AdapterCapability,
}

impl CapturingListener {
    /// Creates a bounded event collector.
    #[must_use]
    pub fn new(max_events: usize) -> Self {
        let configuration_error =
            (max_events > MAX_CAPTURED_EVENTS).then_some(AdapterConfigurationError::Limit {
                field: "max_events",
                limit: MAX_CAPTURED_EVENTS,
            });
        Self {
            events: Arc::new(Mutex::new(Vec::new())),
            max_events: max_events.min(MAX_CAPTURED_EVENTS),
            configuration_error,
            capability: AdapterCapability::native("runtime.native.capturing-listener"),
        }
    }

    /// Creates a listener after validating the finite event bound.
    pub fn try_new(max_events: usize) -> Result<Self, AdapterConfigurationError> {
        if max_events > MAX_CAPTURED_EVENTS {
            return Err(AdapterConfigurationError::Limit {
                field: "max_events",
                limit: MAX_CAPTURED_EVENTS,
            });
        }
        Ok(Self {
            events: Arc::new(Mutex::new(Vec::new())),
            max_events,
            configuration_error: None,
            capability: AdapterCapability::native("runtime.native.capturing-listener"),
        })
    }

    /// Returns the exact path implemented by this adapter.
    #[must_use]
    pub const fn capability(&self) -> &AdapterCapability {
        &self.capability
    }

    /// Returns a snapshot of captured events.
    #[must_use]
    pub fn events(&self) -> Vec<SampleEvent> {
        lock(&self.events).clone()
    }
}

impl Listener for CapturingListener {
    fn on_event<'a>(&'a self, event: &'a SampleEvent) -> ComponentFuture<'a, ()> {
        Box::pin(async move {
            if let Some(error) = &self.configuration_error {
                return Err(ComponentError::resource_limit(error.to_string()));
            }
            let mut events = lock(&self.events);
            if events.len() >= self.max_events {
                return Err(ComponentError::resource_limit("listener event capacity"));
            }
            events.push(event.clone());
            Ok(())
        })
    }
}

/// A deterministic sampler used by local runtime fixtures.
///
/// The fake does not perform I/O or emulate an external sampler.  It returns
/// the configured output until its finite invocation budget is exhausted, at
/// which point it returns a typed resource-limit error.
#[derive(Debug)]
pub struct BoundedFakeSampler {
    output: crate::SamplerOutput,
    max_invocations: usize,
    invocations: AtomicUsize,
    capability: AdapterCapability,
}

impl BoundedFakeSampler {
    /// Creates a fake sampler with a finite invocation budget.
    pub fn new(
        output: crate::SamplerOutput,
        max_invocations: usize,
    ) -> Result<Self, AdapterConfigurationError> {
        if max_invocations > MAX_FAKE_INVOCATIONS {
            return Err(AdapterConfigurationError::Limit {
                field: "max_invocations",
                limit: MAX_FAKE_INVOCATIONS,
            });
        }
        Ok(Self {
            output,
            max_invocations,
            invocations: AtomicUsize::new(0),
            capability: AdapterCapability::native("runtime.native.bounded-fake-sampler"),
        })
    }

    /// Returns the exact path implemented by this adapter.
    #[must_use]
    pub const fn capability(&self) -> &AdapterCapability {
        &self.capability
    }

    /// Returns the number of calls attempted so far.
    #[must_use]
    pub fn invocations(&self) -> usize {
        self.invocations.load(Ordering::Acquire)
    }
}

impl crate::Sampler for BoundedFakeSampler {
    fn sample<'a>(
        &'a self,
        _context: &'a mut SampleContext<'_>,
    ) -> ComponentFuture<'a, crate::SamplerOutput> {
        let invocation = next_invocation(&self.invocations);
        let output = self.output.clone();
        let max_invocations = self.max_invocations;
        Box::pin(async move {
            if invocation >= max_invocations {
                return Err(ComponentError::resource_limit(
                    "bounded fake sampler invocation capacity",
                ));
            }
            Ok(output)
        })
    }
}

/// A deterministic timer used by local runtime fixtures.
#[derive(Debug)]
pub struct BoundedFakeTimer {
    delay: Duration,
    max_invocations: usize,
    invocations: AtomicUsize,
    capability: AdapterCapability,
}

impl BoundedFakeTimer {
    /// Creates a fake timer with a finite invocation budget.
    pub fn new(delay: Duration, max_invocations: usize) -> Result<Self, AdapterConfigurationError> {
        if max_invocations > MAX_FAKE_INVOCATIONS {
            return Err(AdapterConfigurationError::Limit {
                field: "max_invocations",
                limit: MAX_FAKE_INVOCATIONS,
            });
        }
        Ok(Self {
            delay,
            max_invocations,
            invocations: AtomicUsize::new(0),
            capability: AdapterCapability::native("runtime.native.bounded-fake-timer"),
        })
    }

    /// Returns the exact path implemented by this adapter.
    #[must_use]
    pub const fn capability(&self) -> &AdapterCapability {
        &self.capability
    }

    /// Returns the number of calls attempted so far.
    #[must_use]
    pub fn invocations(&self) -> usize {
        self.invocations.load(Ordering::Acquire)
    }
}

impl crate::Timer for BoundedFakeTimer {
    fn delay<'a>(&'a self, _context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, Duration> {
        let invocation = next_invocation(&self.invocations);
        let delay = self.delay;
        let max_invocations = self.max_invocations;
        Box::pin(async move {
            if invocation >= max_invocations {
                return Err(ComponentError::resource_limit(
                    "bounded fake timer invocation capacity",
                ));
            }
            Ok(delay)
        })
    }
}

/// A typed unsupported boundary for regex/XPath/JSON extraction.
#[derive(Clone, Debug)]
pub struct UnsupportedExtractor {
    unavailable: AdapterUnavailable,
}

impl UnsupportedExtractor {
    /// Creates an external extractor marker.
    #[must_use]
    pub fn new(capability_id: impl Into<String>) -> Self {
        Self {
            unavailable: AdapterUnavailable::new(
                capability_id,
                AdapterUnavailableReason::CompatibilityPackNotSelected,
            ),
        }
    }

    /// Creates an extractor boundary with an explicit external reason.
    #[must_use]
    pub fn with_reason(capability_id: impl Into<String>, reason: AdapterUnavailableReason) -> Self {
        Self {
            unavailable: AdapterUnavailable::new(capability_id, reason),
        }
    }

    /// Returns the unavailable path descriptor.
    #[must_use]
    pub const fn unavailable(&self) -> &AdapterUnavailable {
        &self.unavailable
    }
}

impl Postprocessor for UnsupportedExtractor {
    fn process<'a>(&'a self, _context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, ()> {
        Box::pin(async move { Err(self.unavailable.component_error("extractor")) })
    }
}

/// A typed unsupported boundary for script/plugin preprocessors/processors.
#[derive(Clone, Debug)]
pub struct UnsupportedProcessor {
    unavailable: AdapterUnavailable,
}

impl UnsupportedProcessor {
    /// Creates an external processor marker.
    #[must_use]
    pub fn new(capability_id: impl Into<String>) -> Self {
        Self {
            unavailable: AdapterUnavailable::new(
                capability_id,
                AdapterUnavailableReason::CompatibilityPackNotSelected,
            ),
        }
    }

    /// Creates a processor boundary with an explicit external reason.
    #[must_use]
    pub fn with_reason(capability_id: impl Into<String>, reason: AdapterUnavailableReason) -> Self {
        Self {
            unavailable: AdapterUnavailable::new(capability_id, reason),
        }
    }

    /// Returns the unavailable path descriptor.
    #[must_use]
    pub const fn unavailable(&self) -> &AdapterUnavailable {
        &self.unavailable
    }
}

impl Preprocessor for UnsupportedProcessor {
    fn process<'a>(&'a self, _context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, ()> {
        Box::pin(async move { Err(self.unavailable.component_error("processor")) })
    }
}

impl Postprocessor for UnsupportedProcessor {
    fn process<'a>(&'a self, _context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, ()> {
        Box::pin(async move { Err(self.unavailable.component_error("processor")) })
    }
}

/// A typed unsupported boundary for JVM/plugin samplers.
#[derive(Clone, Debug)]
pub struct UnsupportedSampler {
    unavailable: AdapterUnavailable,
}

/// A typed unsupported boundary for JVM/plugin configuration elements.
#[derive(Clone, Debug)]
pub struct UnsupportedConfiguration {
    unavailable: AdapterUnavailable,
}

impl UnsupportedConfiguration {
    /// Creates an external configuration marker.
    #[must_use]
    pub fn new(capability_id: impl Into<String>) -> Self {
        Self {
            unavailable: AdapterUnavailable::new(
                capability_id,
                AdapterUnavailableReason::CompatibilityPackNotSelected,
            ),
        }
    }

    /// Creates a configuration boundary with an explicit external reason.
    #[must_use]
    pub fn with_reason(capability_id: impl Into<String>, reason: AdapterUnavailableReason) -> Self {
        Self {
            unavailable: AdapterUnavailable::new(capability_id, reason),
        }
    }

    /// Returns the unavailable path descriptor.
    #[must_use]
    pub const fn unavailable(&self) -> &AdapterUnavailable {
        &self.unavailable
    }
}

impl Configuration for UnsupportedConfiguration {
    fn apply<'a>(&'a self, _context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, ()> {
        Box::pin(async move { Err(self.unavailable.component_error("configuration")) })
    }
}

/// A typed unsupported boundary for JVM/plugin assertions.
#[derive(Clone, Debug)]
pub struct UnsupportedAssertion {
    unavailable: AdapterUnavailable,
}

impl UnsupportedAssertion {
    /// Creates an external assertion marker.
    #[must_use]
    pub fn new(capability_id: impl Into<String>) -> Self {
        Self {
            unavailable: AdapterUnavailable::new(
                capability_id,
                AdapterUnavailableReason::CompatibilityPackNotSelected,
            ),
        }
    }

    /// Creates an assertion boundary with an explicit external reason.
    #[must_use]
    pub fn with_reason(capability_id: impl Into<String>, reason: AdapterUnavailableReason) -> Self {
        Self {
            unavailable: AdapterUnavailable::new(capability_id, reason),
        }
    }

    /// Returns the unavailable path descriptor.
    #[must_use]
    pub const fn unavailable(&self) -> &AdapterUnavailable {
        &self.unavailable
    }
}

impl Assertion for UnsupportedAssertion {
    fn evaluate<'a>(
        &'a self,
        _context: &'a mut SampleContext<'_>,
    ) -> ComponentFuture<'a, AssertionResult> {
        Box::pin(async move { Err(self.unavailable.component_error("assertion")) })
    }
}

/// A typed unsupported boundary for listeners that need a JVM/plugin sink.
#[derive(Clone, Debug)]
pub struct UnsupportedListener {
    unavailable: AdapterUnavailable,
}

impl UnsupportedListener {
    /// Creates an external listener marker.
    #[must_use]
    pub fn new(capability_id: impl Into<String>) -> Self {
        Self {
            unavailable: AdapterUnavailable::new(
                capability_id,
                AdapterUnavailableReason::CompatibilityPackNotSelected,
            ),
        }
    }

    /// Creates a listener boundary with an explicit external reason.
    #[must_use]
    pub fn with_reason(capability_id: impl Into<String>, reason: AdapterUnavailableReason) -> Self {
        Self {
            unavailable: AdapterUnavailable::new(capability_id, reason),
        }
    }

    /// Returns the unavailable path descriptor.
    #[must_use]
    pub const fn unavailable(&self) -> &AdapterUnavailable {
        &self.unavailable
    }
}

impl Listener for UnsupportedListener {
    fn on_event<'a>(&'a self, _event: &'a SampleEvent) -> ComponentFuture<'a, ()> {
        Box::pin(async move { Err(self.unavailable.component_error("listener")) })
    }
}

impl UnsupportedSampler {
    /// Creates an external sampler marker.
    #[must_use]
    pub fn new(capability_id: impl Into<String>) -> Self {
        Self {
            unavailable: AdapterUnavailable::new(
                capability_id,
                AdapterUnavailableReason::CompatibilityPackNotSelected,
            ),
        }
    }

    /// Creates a sampler boundary with an explicit external reason.
    #[must_use]
    pub fn with_reason(capability_id: impl Into<String>, reason: AdapterUnavailableReason) -> Self {
        Self {
            unavailable: AdapterUnavailable::new(capability_id, reason),
        }
    }

    /// Returns the unavailable path descriptor.
    #[must_use]
    pub const fn unavailable(&self) -> &AdapterUnavailable {
        &self.unavailable
    }
}

impl crate::Sampler for UnsupportedSampler {
    fn sample<'a>(
        &'a self,
        _context: &'a mut SampleContext<'_>,
    ) -> ComponentFuture<'a, crate::SamplerOutput> {
        Box::pin(async move { Err(self.unavailable.component_error("sampler")) })
    }
}

/// A local assertion adapter for a response substring.
#[derive(Clone, Debug)]
pub struct ContainsAssertion {
    needle: String,
    configuration_error: Option<AdapterConfigurationError>,
    capability: AdapterCapability,
}

impl ContainsAssertion {
    /// Creates a response-body substring assertion.
    #[must_use]
    pub fn new(needle: impl Into<String>) -> Self {
        let needle = needle.into();
        let configuration_error = validate_bounded_text(&needle, "needle").err();
        Self {
            needle: bounded_text(needle, MAX_ADAPTER_TEXT_BYTES),
            configuration_error,
            capability: AdapterCapability::native("runtime.native.contains-assertion"),
        }
    }

    /// Creates a substring assertion after validating bounded input.
    pub fn try_new(needle: impl Into<String>) -> Result<Self, AdapterConfigurationError> {
        let needle = needle.into();
        validate_bounded_text(&needle, "needle")?;
        Ok(Self {
            needle,
            configuration_error: None,
            capability: AdapterCapability::native("runtime.native.contains-assertion"),
        })
    }

    /// Returns the exact path implemented by this adapter.
    #[must_use]
    pub const fn capability(&self) -> &AdapterCapability {
        &self.capability
    }
}

impl Assertion for ContainsAssertion {
    fn evaluate<'a>(
        &'a self,
        context: &'a mut SampleContext<'_>,
    ) -> ComponentFuture<'a, jmeter_rs_results::AssertionResult> {
        Box::pin(async move {
            if let Some(error) = &self.configuration_error {
                return Err(ComponentError::resource_limit(error.to_string()));
            }
            let present = context
                .result()
                .and_then(|result| result.response_data())
                .and_then(|data| std::str::from_utf8(data.as_bytes()).ok())
                .is_some_and(|text| text.contains(&self.needle));
            if present {
                Ok(jmeter_rs_results::AssertionResult::passed("contains"))
            } else {
                Ok(jmeter_rs_results::AssertionResult::failed(
                    "contains",
                    Some(self.needle.clone()),
                ))
            }
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "deterministic adapter fixtures")]
mod tests {
    use super::*;
    use std::future::Future;

    fn block_on<T>(future: impl Future<Output = T>) -> T {
        let waker = std::task::Waker::noop();
        let mut task_context = std::task::Context::from_waker(waker);
        let mut future = Box::pin(future);
        loop {
            match Future::poll(future.as_mut(), &mut task_context) {
                std::task::Poll::Ready(value) => return value,
                std::task::Poll::Pending => std::hint::spin_loop(),
            }
        }
    }

    #[test]
    fn inventory_keeps_external_rows_out_of_native_path() {
        for feature_id in [
            "ELEM-001",
            "ELEM-002",
            "ELEM-008",
            "ELEM-009",
            "FUNC-003",
            "SCRIPT-001",
            "SCRIPT-002",
            "PLUG-001",
            "PLUG-002",
            "PLUG-003",
        ] {
            assert!(
                adapter_capabilities()
                    .iter()
                    .any(|record| record.feature_id == feature_id),
                "missing adapter inventory row {feature_id}"
            );
        }
        for record in adapter_capabilities() {
            if record.feature_id.starts_with("ELEM-")
                || record.feature_id.starts_with("FUNC-")
                || record.feature_id.starts_with("SCRIPT-")
                || record.feature_id.starts_with("PLUG-")
            {
                assert_ne!(record.path, AdapterImplementationPath::NativeFixture);
            }
        }
        assert_eq!(
            adapter_capabilities()
                .iter()
                .filter(|record| record.path == AdapterImplementationPath::CompatibilityPackRequired)
                .count(),
            9
        );
    }

    #[test]
    fn capability_identity_validation_is_bounded_and_typed() {
        assert!(matches!(
            AdapterCapability::try_new("", AdapterImplementationPath::NativeFixture),
            Err(AdapterConfigurationError::Empty {
                field: "capability_id"
            })
        ));
        assert!(matches!(
            AdapterCapability::try_new("bad\nname", AdapterImplementationPath::NativeFixture),
            Err(AdapterConfigurationError::ControlCharacter {
                field: "capability_id"
            })
        ));
        let long = "x".repeat(MAX_ADAPTER_TEXT_BYTES + 1);
        assert!(matches!(
            AdapterCapability::try_new(long, AdapterImplementationPath::NativeFixture),
            Err(AdapterConfigurationError::TooLong { .. })
        ));
        assert!(matches!(
            AdapterUnavailable::try_new("", AdapterUnavailableReason::UnsupportedCapability),
            Err(AdapterConfigurationError::Empty {
                field: "capability_id"
            })
        ));

        let compatibility = AdapterUnavailable::new(
            "runtime.jvm.jsr223",
            AdapterUnavailableReason::CompatibilityPackNotSelected,
        );
        assert_eq!(
            compatibility.capability().path(),
            AdapterImplementationPath::CompatibilityPackRequired
        );
        let unavailable = AdapterUnavailable::new(
            "runtime.jvm.plugin",
            AdapterUnavailableReason::UnsupportedCapability,
        );
        assert_eq!(
            unavailable.capability().path(),
            AdapterImplementationPath::Unavailable
        );
    }

    #[test]
    fn bounded_capture_and_literal_inputs_reject_overflow_before_execution() {
        assert!(matches!(
            CapturingListener::try_new(MAX_CAPTURED_EVENTS + 1),
            Err(AdapterConfigurationError::Limit {
                field: "max_events",
                ..
            })
        ));
        assert!(matches!(
            LiteralExtractor::try_new("value", "needle", MAX_LITERAL_CAPTURE_BYTES + 1),
            Err(AdapterConfigurationError::Limit {
                field: "capture_bytes",
                ..
            })
        ));
        assert!(matches!(
            BoundedFakeSampler::new(crate::SamplerOutput::no_result(), MAX_FAKE_INVOCATIONS + 1),
            Err(AdapterConfigurationError::Limit {
                field: "max_invocations",
                ..
            })
        ));
        assert!(matches!(
            BoundedFakeTimer::new(Duration::ZERO, MAX_FAKE_INVOCATIONS + 1),
            Err(AdapterConfigurationError::Limit {
                field: "max_invocations",
                ..
            })
        ));
        assert!(ContainsAssertion::try_new("").is_ok());
    }

    #[test]
    fn fake_sampler_is_finite_and_does_not_fallback_after_exhaustion() {
        let sampler = Arc::new(
            BoundedFakeSampler::new(crate::SamplerOutput::no_result(), 1)
                .expect("finite fake sampler"),
        );
        assert_eq!(
            sampler.capability().path(),
            AdapterImplementationPath::NativeFixture
        );
        let package = crate::SamplePackage::new(
            jmeter_rs_model::NodeId::new(1),
            Arc::clone(&sampler) as Arc<dyn crate::Sampler>,
        );
        let mut execution = crate::ExecutionContext::new();

        assert!(block_on(package.execute(&mut execution)).is_ok());
        let error = block_on(package.execute(&mut execution)).expect_err("budget is exhausted");
        assert_eq!(error.code(), "runtime.sampler");
        assert_eq!(sampler.invocations(), 2);
    }

    #[test]
    fn fake_timer_is_finite_and_unsupported_sampler_has_no_fallback() {
        let timer = Arc::new(BoundedFakeTimer::new(Duration::ZERO, 1).expect("finite fake timer"));
        assert_eq!(
            timer.capability().path(),
            AdapterImplementationPath::NativeFixture
        );
        let package = crate::SamplePackage::new(
            jmeter_rs_model::NodeId::new(2),
            Arc::new(
                BoundedFakeSampler::new(crate::SamplerOutput::no_result(), 1)
                    .expect("finite fake sampler"),
            ),
        )
        .with_timers(vec![Arc::clone(&timer) as Arc<dyn crate::Timer>]);
        let mut execution = crate::ExecutionContext::new();

        assert!(block_on(package.execute(&mut execution)).is_ok());
        assert_eq!(timer.invocations(), 1);

        let unsupported = crate::SamplePackage::new(
            jmeter_rs_model::NodeId::new(3),
            Arc::new(UnsupportedSampler::with_reason(
                "runtime.jvm.jsr223",
                AdapterUnavailableReason::CompatibilityPackNotSelected,
            )),
        );
        let error = block_on(unsupported.execute(&mut execution)).expect_err("unsupported path");
        let message = error.to_string();
        assert!(message.contains("runtime.jvm.jsr223"));
        assert!(message.contains("compatibility-pack-not-selected"));
    }

    #[test]
    fn literal_extractor_reports_missing_response_body_instead_of_noop() {
        let package = crate::SamplePackage::new(
            jmeter_rs_model::NodeId::new(4),
            Arc::new(
                BoundedFakeSampler::new(
                    crate::SamplerOutput::result(jmeter_rs_results::SampleResult::new("fixture")),
                    1,
                )
                .expect("finite fake sampler"),
            ),
        )
        .with_postprocessors(vec![Arc::new(
            LiteralExtractor::try_new("value", "needle", 16).expect("valid extractor"),
        )]);
        let mut execution = crate::ExecutionContext::new();

        let error = block_on(package.execute(&mut execution)).expect_err("missing body");
        assert!(error.to_string().contains("response body is missing"));
    }
}
