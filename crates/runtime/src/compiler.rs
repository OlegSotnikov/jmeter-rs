// SPDX-License-Identifier: Apache-2.0
//! Ordered model-to-runtime scope compilation.
//!
//! The semantic model has already removed JMX's alternating `hashTree`
//! wrappers.  A node's ordered children therefore describe one lexical JMeter
//! scope: configuration, processor, timer, assertion, and listener siblings
//! apply to samplers selected below that branch.  This module turns those
//! ordered scopes into immutable metadata packages; concrete component
//! decoding remains an explicit factory/adapter seam.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

/// Bounds applied while decoding component properties.
///
/// The model retains unknown values losslessly, but a factory must not hand
/// unbounded source data to a native component.  These limits are deliberately
/// smaller than the whole-plan limits and match the bounded processor and
/// extractor fixtures in the active compatibility profile.
const MAX_FACTORY_PROPERTY_COUNT: usize = 256;
const MAX_FACTORY_PROPERTY_BYTES: usize = 4096;
const MAX_FACTORY_COLLECTION_ENTRIES: usize = 64;
const MAX_FACTORY_PROPERTY_DEPTH: usize = 16;
const MAX_FACTORY_PENDING_VALUES: usize = 16_384;

use jmeter_rs_model::{ElementTree, NodeId, PropertyValue, TestElement};

use crate::scope::{
    CompiledScopePlan, ComponentBinding, ComponentCategory, JMETER_ASSERTION_BINDINGS,
    ResultCollectorKind, ScopeCompileError, ScopeCompiler, ScopeComponent, ScopeFactoryError,
    ScopeLimits, ScopePlan, TimerBinding, UnsupportedComponent, builtin_timer_aliases,
};
use crate::{
    Assertion, CompiledPackages, ComponentError, Configuration, ConstantThroughputMode,
    ConstantThroughputTimer, ConstantTimer, DurationAssertion, GaussianRandomTimer, Listener,
    Md5HexAssertion, PoissonRandomTimer, Postprocessor, PreciseThroughputTimer, Preprocessor,
    ResponseAssertion, SamplePackage, Sampler, SizeAssertion, SynchronizingTimer, Timer,
    UniformRandomTimer, UnsupportedJsonAssertion, UnsupportedNativeAssertion, XPathAssertion,
    XPathOptions, XmlAssertion,
};

const DEFAULT_MAX_FACTORY_ENTRIES: usize = 1_024;
const MAX_FACTORY_CLASS_BYTES: usize = 4_096;

/// A decoded native component returned by a scope factory hook.
pub enum FactoryComponent {
    /// A configuration element.
    Configuration(Arc<dyn Configuration>),
    /// A preprocessor.
    Preprocessor(Arc<dyn Preprocessor>),
    /// A timer.
    Timer(Arc<dyn Timer>),
    /// A sampler.
    Sampler(Arc<dyn Sampler>),
    /// A postprocessor/extractor.
    Postprocessor(Arc<dyn Postprocessor>),
    /// An assertion.
    Assertion(Arc<dyn Assertion>),
    /// A scoped listener.
    Listener(Arc<dyn Listener>),
}

impl FactoryComponent {
    /// Returns the decoded component category.
    #[must_use]
    pub const fn category(&self) -> ComponentCategory {
        match self {
            Self::Configuration(_) => ComponentCategory::Configuration,
            Self::Preprocessor(_) => ComponentCategory::Preprocessor,
            Self::Timer(_) => ComponentCategory::Timer,
            Self::Sampler(_) => ComponentCategory::Sampler,
            Self::Postprocessor(_) => ComponentCategory::Postprocessor,
            Self::Assertion(_) => ComponentCategory::Assertion,
            Self::Listener(_) => ComponentCategory::Listener,
        }
    }
}

impl fmt::Debug for FactoryComponent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("FactoryComponent")
            .field(&self.category())
            .finish()
    }
}

/// Hook used to decode one exact source element into an executor-neutral
/// runtime component. Implementations must validate/interpret only their own
/// domain and return a typed factory error for unsupported properties.
pub trait ScopeComponentFactory: Send + Sync {
    /// Decodes one source component without performing I/O.
    fn create(&self, component: &ScopeComponent) -> Result<FactoryComponent, ScopeFactoryError>;

    /// Returns the exact class identity this hook was authored for, when the
    /// hook is not intentionally shared by several exact aliases.
    ///
    /// Registry lookup is always exact. This optional declaration adds a
    /// second invariant for factories that must never be reused for another
    /// source class; shared adapter hooks may retain the default `None` and
    /// perform their own source-specific validation in [`Self::create`].
    fn test_class(&self) -> Option<&str> {
        None
    }
}

/// Bounded class-to-factory registry for future native and adapter domains.
///
/// Lookup is exact and insertion order is not consulted. This makes aliases
/// explicit registry entries and prevents a central class-name match from
/// expanding as domains are implemented.
pub struct ComponentFactoryRegistry {
    max_entries: usize,
    entries: BTreeMap<String, Arc<dyn ScopeComponentFactory>>,
}

impl Default for ComponentFactoryRegistry {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_MAX_FACTORY_ENTRIES)
    }
}

impl fmt::Debug for ComponentFactoryRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComponentFactoryRegistry")
            .field("max_entries", &self.max_entries)
            .field("entry_count", &self.entries.len())
            .finish()
    }
}

impl ComponentFactoryRegistry {
    /// Creates a registry with an explicit finite entry bound.
    #[must_use]
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            max_entries,
            entries: BTreeMap::new(),
        }
    }

    /// Creates the native timer factory vocabulary for the pinned JMeter
    /// profile.  Script-backed aliases are intentionally absent: scope
    /// compilation classifies those aliases as external and returns a typed
    /// capability error before a factory can be selected.
    #[must_use]
    pub fn with_builtin_timers() -> Self {
        let mut registry = Self::default();
        for alias in builtin_timer_aliases() {
            if !alias.external {
                registry.entries.insert(
                    alias.alias.to_owned(),
                    Arc::new(BuiltinTimerFactory {
                        binding: alias.binding,
                    }),
                );
            }
        }
        registry
    }

    /// Creates the exact pinned assertion vocabulary, including typed
    /// unsupported markers for JSON/JMESPath and JVM/plugin-only families.
    /// Sampler and other component factories remain the caller's concern.
    #[must_use]
    pub fn with_builtin_assertions() -> Self {
        let mut registry = Self::default();
        for (alias, _) in JMETER_ASSERTION_BINDINGS {
            registry.entries.insert(
                (*alias).to_owned(),
                Arc::new(BuiltinAssertionFactory) as Arc<dyn ScopeComponentFactory>,
            );
        }
        registry
    }

    /// Creates the pinned native timer and assertion factories.
    #[must_use]
    pub fn builtins() -> Self {
        let mut registry = Self::with_builtin_timers();
        for (alias, _) in JMETER_ASSERTION_BINDINGS {
            registry.entries.insert(
                (*alias).to_owned(),
                Arc::new(BuiltinAssertionFactory) as Arc<dyn ScopeComponentFactory>,
            );
        }
        registry
    }

    /// Registers or replaces an exact test-class hook.
    pub fn register(
        &mut self,
        test_class: impl Into<String>,
        factory: Arc<dyn ScopeComponentFactory>,
    ) -> Result<(), ScopeFactoryError> {
        let test_class = test_class.into();
        if test_class.trim().is_empty() || test_class.chars().any(char::is_control) {
            return Err(ScopeFactoryError::InvalidRegistration {
                test_class,
                detail: "class name is empty or contains a control character".to_owned(),
            });
        }
        if test_class.len() > MAX_FACTORY_CLASS_BYTES {
            return Err(ScopeFactoryError::InvalidRegistration {
                test_class,
                detail: format!(
                    "class name exceeds the {}-byte registry bound",
                    MAX_FACTORY_CLASS_BYTES
                ),
            });
        }
        if !self.entries.contains_key(&test_class) && self.entries.len() >= self.max_entries {
            return Err(ScopeFactoryError::RegistryLimit {
                limit: self.max_entries,
            });
        }
        self.entries.insert(test_class, factory);
        Ok(())
    }

    /// Returns a registered exact class hook.
    #[must_use]
    pub fn get(&self, test_class: &str) -> Option<&Arc<dyn ScopeComponentFactory>> {
        self.entries.get(test_class)
    }

    /// Returns the number of registered class hooks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether no class hooks are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the finite entry bound.
    #[must_use]
    pub const fn max_entries(&self) -> usize {
        self.max_entries
    }
}

/// A decoder hook shared by the exact native timer aliases.
#[derive(Clone, Copy, Debug)]
struct BuiltinTimerFactory {
    binding: TimerBinding,
}

impl ScopeComponentFactory for BuiltinTimerFactory {
    fn create(&self, component: &ScopeComponent) -> Result<FactoryComponent, ScopeFactoryError> {
        if let Err(detail) = validate_factory_properties(component) {
            return Err(factory_decode_error(
                component,
                ComponentCategory::Timer,
                detail,
            ));
        }
        if self.binding == TimerBinding::ExternalScript {
            return Err(timer_decode_error(
                component,
                "script-backed timer requires the external JVM/plugin capability",
            ));
        }
        decode_builtin_timer(self.binding, component).map(FactoryComponent::Timer)
    }
}

/// Factory for JMeter's built-in assertion aliases.  The factory is kept
/// separate from [`ComponentRegistry`]: scope classification and concrete
/// package decoding are independent seams, and callers may replace one exact
/// alias with an adapter hook without changing the source tree.
#[derive(Clone, Copy, Debug, Default)]
struct BuiltinAssertionFactory;

impl ScopeComponentFactory for BuiltinAssertionFactory {
    fn create(&self, component: &ScopeComponent) -> Result<FactoryComponent, ScopeFactoryError> {
        if let Err(detail) = validate_factory_properties(component) {
            return Err(factory_decode_error(
                component,
                ComponentCategory::Assertion,
                detail,
            ));
        }
        let assertion =
            decode_builtin_assertion(component).map_err(|detail| ScopeFactoryError::Decode {
                node_id: component.node_id,
                path: component.path.clone(),
                test_class: component.binding.test_class.clone(),
                category: ComponentCategory::Assertion,
                detail: bounded(&detail),
            })?;
        Ok(FactoryComponent::Assertion(assertion))
    }
}

fn timer_decode_error(component: &ScopeComponent, detail: impl Into<String>) -> ScopeFactoryError {
    ScopeFactoryError::Decode {
        node_id: component.node_id,
        path: component.path.clone(),
        test_class: component.binding.test_class.clone(),
        category: ComponentCategory::Timer,
        detail: detail.into(),
    }
}

fn factory_decode_error(
    component: &ScopeComponent,
    category: ComponentCategory,
    detail: impl Into<String>,
) -> ScopeFactoryError {
    let detail = detail.into();
    ScopeFactoryError::Decode {
        node_id: component.node_id,
        path: component.path.clone(),
        test_class: component.binding.test_class.clone(),
        category,
        detail: bounded(&detail),
    }
}

/// Check source properties before a factory receives them.
///
/// The model validates whole plans, but factories are also a public seam and
/// may be called with a manually constructed component.  The iterative walk
/// keeps this seam bounded without consuming the Rust call stack on hostile
/// nested values.
fn validate_factory_properties(component: &ScopeComponent) -> Result<(), String> {
    let properties = &component.element.properties;
    if properties.len() > MAX_FACTORY_PROPERTY_COUNT {
        return Err(format!(
            "component has {} properties; maximum is {MAX_FACTORY_PROPERTY_COUNT}",
            properties.len()
        ));
    }

    let mut tasks = Vec::with_capacity(properties.len());
    let mut visited_values = 0usize;
    for entry in properties.as_slice().iter().rev() {
        if entry.name.len() > MAX_FACTORY_PROPERTY_BYTES {
            return Err(format!(
                "property name exceeds {MAX_FACTORY_PROPERTY_BYTES} bytes"
            ));
        }
        tasks.push((&entry.value, 0usize));
    }
    while let Some((value, depth)) = tasks.pop() {
        visited_values = visited_values
            .checked_add(1)
            .ok_or_else(|| "factory property value count overflowed".to_owned())?;
        if visited_values > MAX_FACTORY_PENDING_VALUES {
            return Err(format!(
                "factory property value count exceeds {MAX_FACTORY_PENDING_VALUES} values"
            ));
        }
        if depth > MAX_FACTORY_PROPERTY_DEPTH {
            return Err(format!(
                "property nesting exceeds {MAX_FACTORY_PROPERTY_DEPTH} levels"
            ));
        }
        match value {
            PropertyValue::String(value) => {
                if value.len() > MAX_FACTORY_PROPERTY_BYTES {
                    return Err(format!(
                        "string property exceeds {MAX_FACTORY_PROPERTY_BYTES} bytes"
                    ));
                }
            }
            PropertyValue::Collection(values) => {
                if values.len() > MAX_FACTORY_COLLECTION_ENTRIES {
                    return Err(format!(
                        "collection has {} entries; maximum is {MAX_FACTORY_COLLECTION_ENTRIES}",
                        values.len()
                    ));
                }
                if pending_values_exceed(tasks.len(), values.len()) {
                    return Err(format!(
                        "nested property expansion exceeds {MAX_FACTORY_PENDING_VALUES} values"
                    ));
                }
                tasks.extend(values.iter().rev().map(|value| (value, depth + 1)));
            }
            PropertyValue::NamedCollection(entries) | PropertyValue::Map(entries) => {
                if entries.len() > MAX_FACTORY_COLLECTION_ENTRIES {
                    return Err(format!(
                        "collection has {} entries; maximum is {MAX_FACTORY_COLLECTION_ENTRIES}",
                        entries.len()
                    ));
                }
                if pending_values_exceed(tasks.len(), entries.len()) {
                    return Err(format!(
                        "nested property expansion exceeds {MAX_FACTORY_PENDING_VALUES} values"
                    ));
                }
                for entry in entries.iter().rev() {
                    if entry.name.len() > MAX_FACTORY_PROPERTY_BYTES {
                        return Err(format!(
                            "collection entry name exceeds {MAX_FACTORY_PROPERTY_BYTES} bytes"
                        ));
                    }
                    tasks.push((&entry.value, depth + 1));
                }
            }
            PropertyValue::Element(element) => {
                if element.name.len() > MAX_FACTORY_PROPERTY_BYTES
                    || element
                        .class_name
                        .as_ref()
                        .is_some_and(|name| name.len() > MAX_FACTORY_PROPERTY_BYTES)
                {
                    return Err(format!(
                        "nested property metadata exceeds {MAX_FACTORY_PROPERTY_BYTES} bytes"
                    ));
                }
                if element.properties.len() > MAX_FACTORY_PROPERTY_COUNT {
                    return Err(format!(
                        "nested property has {} children; maximum is {MAX_FACTORY_PROPERTY_COUNT}",
                        element.properties.len()
                    ));
                }
                if pending_values_exceed(tasks.len(), element.properties.len()) {
                    return Err(format!(
                        "nested property expansion exceeds {MAX_FACTORY_PENDING_VALUES} values"
                    ));
                }
                for entry in element.properties.as_slice().iter().rev() {
                    if entry.name.len() > MAX_FACTORY_PROPERTY_BYTES {
                        return Err(format!(
                            "nested property name exceeds {MAX_FACTORY_PROPERTY_BYTES} bytes"
                        ));
                    }
                    tasks.push((&entry.value, depth + 1));
                }
                if element.opaque_extensions.len() > MAX_FACTORY_COLLECTION_ENTRIES {
                    return Err(format!(
                        "nested property has too many opaque extensions (maximum is {MAX_FACTORY_COLLECTION_ENTRIES})"
                    ));
                }
                for extension in &element.opaque_extensions {
                    if extension.type_name.len() > MAX_FACTORY_PROPERTY_BYTES
                        || extension.raw.len() > MAX_FACTORY_PROPERTY_BYTES
                    {
                        return Err(format!(
                            "nested opaque extension exceeds {MAX_FACTORY_PROPERTY_BYTES} bytes"
                        ));
                    }
                }
            }
            PropertyValue::Object(object) => {
                if object.raw.len() > MAX_FACTORY_PROPERTY_BYTES
                    || object
                        .class_name
                        .as_ref()
                        .is_some_and(|name| name.len() > MAX_FACTORY_PROPERTY_BYTES)
                {
                    return Err(format!(
                        "object property exceeds {MAX_FACTORY_PROPERTY_BYTES} bytes"
                    ));
                }
                if object.attributes.len() > MAX_FACTORY_COLLECTION_ENTRIES {
                    return Err(format!(
                        "object property has too many attributes (maximum is {MAX_FACTORY_COLLECTION_ENTRIES})"
                    ));
                }
                for attribute in &object.attributes {
                    if attribute.name.len() > MAX_FACTORY_PROPERTY_BYTES
                        || attribute.value.len() > MAX_FACTORY_PROPERTY_BYTES
                    {
                        return Err(format!(
                            "object property attribute exceeds {MAX_FACTORY_PROPERTY_BYTES} bytes"
                        ));
                    }
                }
            }
            PropertyValue::Opaque(value) => {
                if value.type_name.len() > MAX_FACTORY_PROPERTY_BYTES
                    || value.raw.len() > MAX_FACTORY_PROPERTY_BYTES
                {
                    return Err(format!(
                        "opaque property exceeds {MAX_FACTORY_PROPERTY_BYTES} bytes"
                    ));
                }
            }
            PropertyValue::Null
            | PropertyValue::Boolean(_)
            | PropertyValue::Integer(_)
            | PropertyValue::Long(_)
            | PropertyValue::Float(_)
            | PropertyValue::Double(_) => {}
        }
    }
    Ok(())
}

fn pending_values_exceed(current: usize, additional: usize) -> bool {
    current
        .checked_add(additional)
        .is_none_or(|total| total > MAX_FACTORY_PENDING_VALUES)
}

fn scalar_number(value: &PropertyValue, name: &str) -> Result<f64, String> {
    let result = match value {
        PropertyValue::String(value) => value
            .trim()
            .parse::<f64>()
            .map_err(|_| format!("timer property {name:?} is not a finite number")),
        PropertyValue::Integer(value) => Ok(f64::from(*value)),
        PropertyValue::Long(value) => Ok(*value as f64),
        PropertyValue::Float(value) => Ok(f64::from(*value)),
        PropertyValue::Double(value) => Ok(*value),
        _ => Err(format!("timer property {name:?} must be a scalar number")),
    }?;
    if result.is_finite() {
        Ok(result)
    } else {
        Err(format!("timer property {name:?} is not a finite number"))
    }
}

fn scalar_integer(value: &PropertyValue, name: &str) -> Result<i64, String> {
    match value {
        PropertyValue::String(value) => value
            .trim()
            .parse::<i64>()
            .map_err(|_| format!("timer property {name:?} is not an integer")),
        PropertyValue::Integer(value) => Ok(i64::from(*value)),
        PropertyValue::Long(value) => Ok(*value),
        _ => Err(format!("timer property {name:?} must be an integer")),
    }
}

fn duration_from_millis(value: f64, name: &str) -> Result<Duration, String> {
    if !value.is_finite() || value < 0.0 {
        return Err(format!(
            "timer property {name:?} must be finite and non-negative"
        ));
    }
    Duration::try_from_secs_f64(value / 1_000.0)
        .map_err(|_| format!("timer property {name:?} exceeds the duration bound"))
}

fn duration_from_seconds(value: f64, name: &str) -> Result<Duration, String> {
    if !value.is_finite() || value < 0.0 {
        return Err(format!(
            "timer property {name:?} must be finite and non-negative"
        ));
    }
    Duration::try_from_secs_f64(value)
        .map_err(|_| format!("timer property {name:?} exceeds the duration bound"))
}

fn optional_millis(
    component: &ScopeComponent,
    name: &str,
    default: Duration,
) -> Result<Duration, ScopeFactoryError> {
    component
        .element
        .property(name)
        .map(|value| {
            scalar_number(value, name)
                .and_then(|value| duration_from_millis(value, name))
                .map_err(|detail| timer_decode_error(component, detail))
        })
        .unwrap_or(Ok(default))
}

fn optional_seconds(
    component: &ScopeComponent,
    name: &str,
    default: Duration,
) -> Result<Duration, ScopeFactoryError> {
    component
        .element
        .property(name)
        .map(|value| {
            scalar_number(value, name)
                .and_then(|value| duration_from_seconds(value, name))
                .map_err(|detail| timer_decode_error(component, detail))
        })
        .unwrap_or(Ok(default))
}

fn optional_number(
    component: &ScopeComponent,
    name: &str,
    default: f64,
) -> Result<f64, ScopeFactoryError> {
    component
        .element
        .property(name)
        .map(|value| {
            scalar_number(value, name).map_err(|detail| timer_decode_error(component, detail))
        })
        .unwrap_or(Ok(default))
}

fn optional_integer(
    component: &ScopeComponent,
    name: &str,
    default: i64,
) -> Result<i64, ScopeFactoryError> {
    component
        .element
        .property(name)
        .map(|value| {
            scalar_integer(value, name).map_err(|detail| timer_decode_error(component, detail))
        })
        .unwrap_or(Ok(default))
}

fn reject_unknown_timer_properties(
    component: &ScopeComponent,
    allowed: &[&str],
) -> Result<(), ScopeFactoryError> {
    for name in component.element.properties.keys() {
        if !allowed.contains(&name) {
            return Err(timer_decode_error(
                component,
                format!("unsupported timer property {name:?}"),
            ));
        }
    }
    Ok(())
}

fn decode_builtin_timer(
    binding: TimerBinding,
    component: &ScopeComponent,
) -> Result<Arc<dyn Timer>, ScopeFactoryError> {
    match binding {
        TimerBinding::Constant => {
            reject_unknown_timer_properties(component, &["ConstantTimer.delay"])?;
            Ok(Arc::new(ConstantTimer::new(optional_millis(
                component,
                "ConstantTimer.delay",
                Duration::ZERO,
            )?)))
        }
        TimerBinding::UniformRandom => {
            reject_unknown_timer_properties(
                component,
                &["ConstantTimer.delay", "RandomTimer.range"],
            )?;
            let minimum = optional_millis(component, "ConstantTimer.delay", Duration::ZERO)?;
            let range = optional_millis(component, "RandomTimer.range", Duration::ZERO)?;
            let maximum = minimum.checked_add(range).ok_or_else(|| {
                timer_decode_error(
                    component,
                    "uniform timer interval exceeds the duration bound",
                )
            })?;
            Ok(Arc::new(UniformRandomTimer::new(minimum, maximum)))
        }
        TimerBinding::GaussianRandom => {
            reject_unknown_timer_properties(
                component,
                &["ConstantTimer.delay", "RandomTimer.range"],
            )?;
            let mean = optional_millis(component, "ConstantTimer.delay", Duration::ZERO)?;
            let deviation = optional_millis(component, "RandomTimer.range", Duration::ZERO)?;
            Ok(Arc::new(GaussianRandomTimer::new(mean, deviation)))
        }
        TimerBinding::PoissonRandom => {
            reject_unknown_timer_properties(
                component,
                &["ConstantTimer.delay", "RandomTimer.range"],
            )?;
            let base = optional_millis(component, "ConstantTimer.delay", Duration::ZERO)?;
            let range = optional_millis(component, "RandomTimer.range", Duration::ZERO)?;
            Ok(Arc::new(PoissonRandomTimer::with_base_and_range(
                base, range,
            )))
        }
        TimerBinding::ConstantThroughput => {
            reject_unknown_timer_properties(component, &["throughput", "calcMode"])?;
            let throughput = component
                .element
                .property("throughput")
                .map(|value| {
                    scalar_number(value, "throughput")
                        .map_err(|detail| timer_decode_error(component, detail))
                })
                .unwrap_or(Ok(1.0))?;
            let mode = component
                .element
                .property("calcMode")
                .map(|value| {
                    constant_throughput_mode_value(value)
                        .map_err(|detail| timer_decode_error(component, detail))
                })
                .unwrap_or(Ok(ConstantThroughputMode::ThisThreadOnly))?;
            ConstantThroughputTimer::new_with_mode(throughput, mode, None)
                .map(|timer| Arc::new(timer) as Arc<dyn Timer>)
                .map_err(|error| timer_component_error(component, error))
        }
        TimerBinding::PreciseThroughput => {
            reject_unknown_timer_properties(
                component,
                &[
                    "throughput",
                    "throughputPeriod",
                    "duration",
                    "batchSize",
                    "batchThreadDelay",
                    "exactLimit",
                    "allowedThroughputSurplus",
                    "randomSeed",
                ],
            )?;
            let throughput = optional_number(component, "throughput", 1.0)?;
            let period = optional_seconds(component, "throughputPeriod", Duration::from_secs(1))?;
            let duration = if component.element.property("duration").is_some() {
                let value = optional_seconds(component, "duration", Duration::ZERO)?;
                (!value.is_zero()).then_some(value)
            } else {
                None
            };
            let batch_size = optional_integer(component, "batchSize", 1)?;
            let batch_delay = optional_millis(component, "batchThreadDelay", Duration::ZERO)?;
            let exact_limit = optional_integer(component, "exactLimit", 0)?;
            let allowed_surplus = optional_number(component, "allowedThroughputSurplus", 1.0)?;
            let mut timer = PreciseThroughputTimer::with_duration(throughput, period, duration)
                .map_err(|error| timer_component_error(component, error))?
                .with_batch_size(u64::try_from(batch_size).map_err(|_| {
                    timer_decode_error(component, "precise timer batchSize must be non-negative")
                })?)
                .map_err(|error| timer_component_error(component, error))?
                .with_batch_thread_delay(batch_delay)
                .with_exact_limit(u64::try_from(exact_limit).map_err(|_| {
                    timer_decode_error(component, "precise timer exactLimit must be non-negative")
                })?)
                .map_err(|error| timer_component_error(component, error))?
                .with_allowed_throughput_surplus(allowed_surplus)
                .map_err(|error| timer_component_error(component, error))?;
            if let Some(seed) = component.element.property("randomSeed") {
                let seed = scalar_integer(seed, "randomSeed")
                    .and_then(|seed| {
                        u64::try_from(seed)
                            .map_err(|_| "randomSeed must be non-negative".to_owned())
                    })
                    .map_err(|detail| timer_decode_error(component, detail))?;
                timer = timer.with_random_seed(seed);
            }
            Ok(Arc::new(timer))
        }
        TimerBinding::Synchronizing => {
            reject_unknown_timer_properties(component, &["groupSize", "timeoutInMs"])?;
            let group_size = optional_integer(component, "groupSize", 1)?;
            let group_size = usize::try_from(group_size).map_err(|_| {
                timer_decode_error(component, "synchronizing timer groupSize must be positive")
            })?;
            let timeout = optional_millis(component, "timeoutInMs", Duration::ZERO)?;
            let name = if component.element.name().is_empty() {
                "SyncTimer"
            } else {
                component.element.name()
            };
            SynchronizingTimer::with_group(name, group_size, timeout)
                .map(|timer| Arc::new(timer) as Arc<dyn Timer>)
                .map_err(|error| timer_component_error(component, error))
        }
        TimerBinding::ExternalScript => Err(timer_decode_error(
            component,
            "script-backed timer requires the external JVM/plugin capability",
        )),
    }
}

fn constant_throughput_mode_value(value: &PropertyValue) -> Result<ConstantThroughputMode, String> {
    if let PropertyValue::String(value) = value {
        let value = value.trim();
        if let Some(mode) = constant_throughput_mode_name(value) {
            return Ok(mode);
        }
    }
    let mode = scalar_integer(value, "calcMode")?;
    match mode {
        0 => Ok(ConstantThroughputMode::ThisThreadOnly),
        1 => Ok(ConstantThroughputMode::AllActiveThreads),
        2 => Ok(ConstantThroughputMode::AllActiveThreadsInCurrentThreadGroup),
        3 => Ok(ConstantThroughputMode::AllActiveThreadsShared),
        4 => Ok(ConstantThroughputMode::AllActiveThreadsInCurrentThreadGroupShared),
        _ => Err(format!(
            "constant throughput calcMode {mode} is outside the JMeter mode range"
        )),
    }
}

fn constant_throughput_mode_name(value: &str) -> Option<ConstantThroughputMode> {
    Some(match value {
        // Canonical enum names used by the pinned JMeter Mode type.
        "ThisThreadOnly" => ConstantThroughputMode::ThisThreadOnly,
        "AllActiveThreads" => ConstantThroughputMode::AllActiveThreads,
        "AllActiveThreadsInCurrentThreadGroup" => {
            ConstantThroughputMode::AllActiveThreadsInCurrentThreadGroup
        }
        "AllActiveThreads_Shared" => ConstantThroughputMode::AllActiveThreadsShared,
        "AllActiveThreadsInCurrentThreadGroup_Shared" => {
            ConstantThroughputMode::AllActiveThreadsInCurrentThreadGroupShared
        }
        // Legacy StringProperty values from ConstantThroughputTimerResources
        // under the profile's en-US locale.
        "this thread only" => ConstantThroughputMode::ThisThreadOnly,
        "all active threads" => ConstantThroughputMode::AllActiveThreads,
        "all active threads in current thread group" => {
            ConstantThroughputMode::AllActiveThreadsInCurrentThreadGroup
        }
        "all active threads (shared)" => ConstantThroughputMode::AllActiveThreadsShared,
        "all active threads in current thread group (shared)" => {
            ConstantThroughputMode::AllActiveThreadsInCurrentThreadGroupShared
        }
        _ => return None,
    })
}

fn timer_component_error(component: &ScopeComponent, error: ComponentError) -> ScopeFactoryError {
    timer_decode_error(component, error.to_string())
}

/// One pending branch walk.  The explicit stack keeps hostile/deep plans away
/// from the Rust call stack.
struct ScopeTask {
    parent_id: Option<NodeId>,
    children: Vec<NodeId>,
    inherited: Vec<ScopeComponent>,
    controller_path: Vec<NodeId>,
    parent_path: Vec<NodeId>,
    replacement_chain: Vec<NodeId>,
    owner_category: Option<ComponentCategory>,
    run_level: bool,
    /// Whether this branch is being visited through a resolved replacement.
    ///
    /// Test Fragments and WorkBench nodes are source-only in a normal JMeter
    /// traversal. A Module/Include replacement may explicitly target one of
    /// those nodes, in which case its children become executable through the
    /// replacement edge. Keeping this bit on the walk frame prevents a source
    /// fragment from executing once on its own and once through the module.
    replacement_expansion: bool,
}

impl ScopeTask {
    #[allow(
        clippy::too_many_arguments,
        reason = "each explicit-stack branch carries its bounded lexical state"
    )]
    fn branch(
        parent_id: Option<NodeId>,
        children: Vec<NodeId>,
        inherited: Vec<ScopeComponent>,
        controller_path: Vec<NodeId>,
        parent_path: Vec<NodeId>,
        replacement_chain: Vec<NodeId>,
        owner_category: Option<ComponentCategory>,
        run_level: bool,
        replacement_expansion: bool,
    ) -> Self {
        Self {
            parent_id,
            children,
            inherited,
            controller_path,
            parent_path,
            replacement_chain,
            owner_category,
            run_level,
            replacement_expansion,
        }
    }
}

/// Compiles an ordered semantic tree into identity-keyed sampler scopes.
pub(crate) fn compile_scope(
    compiler: &ScopeCompiler,
    tree: &ElementTree,
) -> Result<CompiledScopePlan, ScopeCompileError> {
    validate_tree(tree, compiler.limits())?;
    if tree.is_empty() {
        return Ok(CompiledScopePlan {
            packages: BTreeMap::new(),
            disabled: BTreeSet::new(),
            replacements: BTreeMap::new(),
            run_collectors: Vec::new(),
        });
    }

    let mut packages = BTreeMap::new();
    let mut disabled = BTreeSet::new();
    let mut replacements = BTreeMap::new();
    let mut run_collectors = Vec::new();
    let mut tasks = vec![ScopeTask::branch(
        None,
        tree.root_ids().to_vec(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        true,
        false,
    )];

    while let Some(task) = tasks.pop() {
        let ScopeTask {
            parent_id,
            children,
            inherited,
            controller_path,
            parent_path,
            replacement_chain,
            owner_category,
            run_level,
            replacement_expansion,
        } = task;

        // A branch's scope is its enabled non-sampler lexical siblings.  It
        // is collected before children are walked so source order, including
        // same-category order, is deterministic and preserved.
        let mut branch_components = Vec::new();
        for child_id in &children {
            let child = tree
                .get(*child_id)
                .ok_or_else(|| ScopeCompileError::Tree(format!("missing node {child_id}")))?;
            let child_path = path_with(&parent_path, *child_id);
            if !child.value().enabled {
                mark_disabled(
                    tree,
                    *child_id,
                    &child_path,
                    compiler.limits().max_depth,
                    &mut disabled,
                )?;
                continue;
            }
            let binding = binding(compiler, *child_id, &child_path, child.value())?;
            validate_owner(
                owner_category,
                *child_id,
                parent_id,
                &child_path,
                binding.category,
            )?;
            if is_result_collector(child.value(), &binding) {
                let collector =
                    ScopeComponent::new(*child_id, &child_path, child.value(), &binding);
                reject_unsupported_collector(&collector)?;
                if !child.children().is_empty() {
                    return Err(ScopeCompileError::Topology {
                        node_id: Some(*child_id),
                        path: child_path,
                        detail: "result collector must be a leaf".to_owned(),
                    });
                }
                // Result collectors are run-owned regardless of where they
                // are placed. Non-root placement still contributes a
                // source-scope listener predicate to each affected sampler;
                // root placement is represented only by the run collector.
                run_collectors.push(collector.clone());
                if run_collectors.len() > compiler.limits().max_components {
                    return Err(ScopeCompileError::ComponentLimit {
                        count: run_collectors.len(),
                        limit: compiler.limits().max_components,
                    });
                }
                if !run_level {
                    branch_components.push(collector);
                }
            } else if is_non_executable_lifecycle(child.value(), &binding) && !replacement_expansion
            {
                // TestFragment and WorkBench are source containers. Their
                // subtrees are reached only through an explicit replacement
                // edge; never execute or silently classify their contents in
                // their preservation-only source position.
            } else if is_scope_category(binding.category) {
                branch_components.push(ScopeComponent::new(
                    *child_id,
                    &child_path,
                    child.value(),
                    &binding,
                ));
            }
        }

        let mut effective_scope = inherited;
        effective_scope.extend(branch_components.iter().cloned());
        if effective_scope.len() > compiler.limits().max_components {
            return Err(ScopeCompileError::ComponentLimit {
                count: effective_scope.len(),
                limit: compiler.limits().max_components,
            });
        }

        // Reverse-push preserves the model's lexical child order when the
        // explicit DFS stack pops the next task.
        for child_id in children.into_iter().rev() {
            let child = tree
                .get(child_id)
                .ok_or_else(|| ScopeCompileError::Tree(format!("missing node {child_id}")))?;
            if !child.value().enabled {
                continue;
            }
            let child_path = path_with(&parent_path, child_id);
            let child_binding = binding(compiler, child_id, &child_path, child.value())?;
            if run_level && is_result_collector(child.value(), &child_binding) {
                continue;
            }

            match child_binding.category {
                ComponentCategory::Sampler => {
                    compile_sampler(
                        compiler,
                        tree,
                        child_id,
                        child_path,
                        effective_scope.clone(),
                        controller_path.clone(),
                        replacement_chain.clone(),
                        &mut packages,
                        &mut disabled,
                        &mut run_collectors,
                    )?;
                }
                ComponentCategory::Replaceable => {
                    let target = replacement_target(child_id, child.value(), &child_path)?
                        .ok_or_else(|| ScopeCompileError::UnresolvedReplacement {
                            node_id: child_id,
                            test_class: bounded(child.value().test_class()),
                            path: child_path.clone(),
                        })?;
                    if tree.get(target).is_none() {
                        return Err(ScopeCompileError::OrphanReference {
                            node_id: child_id,
                            target,
                            path: child_path,
                        });
                    }
                    if target == child_id || replacement_chain.contains(&target) {
                        return Err(ScopeCompileError::ReplacementCycle {
                            node_id: child_id,
                            path: child_path,
                        });
                    }
                    replacements.insert(child_id, target);
                    let mut next_chain = replacement_chain.clone();
                    next_chain.push(child_id);
                    let mut next_controller_path = controller_path.clone();
                    next_controller_path.push(child_id);
                    tasks.push(ScopeTask::branch(
                        Some(child_id),
                        vec![target],
                        effective_scope.clone(),
                        next_controller_path,
                        child_path,
                        next_chain,
                        Some(ComponentCategory::Replaceable),
                        false,
                        true,
                    ));
                }
                ComponentCategory::Controller | ComponentCategory::Lifecycle => {
                    if is_non_executable_lifecycle(child.value(), &child_binding)
                        && !replacement_expansion
                    {
                        continue;
                    }
                    let mut next_controller_path = controller_path.clone();
                    if child_binding.category == ComponentCategory::Controller {
                        next_controller_path.push(child_id);
                    }
                    let child_run_level = child.value().test_class() == "TestPlan";
                    tasks.push(ScopeTask::branch(
                        Some(child_id),
                        child.children().to_vec(),
                        effective_scope.clone(),
                        next_controller_path,
                        child_path,
                        replacement_chain.clone(),
                        Some(child_binding.category),
                        child_run_level,
                        replacement_expansion,
                    ));
                }
                ComponentCategory::Configuration
                | ComponentCategory::Preprocessor
                | ComponentCategory::Timer
                | ComponentCategory::Postprocessor
                | ComponentCategory::Assertion
                | ComponentCategory::Listener => {
                    // A scope element is not an executable owner. If it has a
                    // child, walk it only to return a typed category misuse
                    // instead of silently dropping the malformed branch.
                    if !child.children().is_empty() {
                        tasks.push(ScopeTask::branch(
                            Some(child_id),
                            child.children().to_vec(),
                            effective_scope.clone(),
                            controller_path.clone(),
                            child_path,
                            replacement_chain.clone(),
                            Some(child_binding.category),
                            false,
                            replacement_expansion,
                        ));
                    }
                }
            }
        }
    }

    let mut run_collector_bytes = 0usize;
    for collector in &run_collectors {
        run_collector_bytes = checked_sum(
            &collector.path,
            "run collector metadata bytes",
            [run_collector_bytes, component_metadata_bytes(collector)?],
        )?;
    }
    if run_collector_bytes > compiler.limits().max_bytes {
        return Err(ScopeCompileError::ByteLimit {
            bytes: run_collector_bytes,
            limit: compiler.limits().max_bytes,
        });
    }

    Ok(CompiledScopePlan {
        packages,
        disabled,
        replacements,
        run_collectors,
    })
}

/// Compiles scope metadata and decodes every executable component through the
/// caller-owned factory registry.
pub(crate) fn compile_packages(
    compiler: &ScopeCompiler,
    tree: &ElementTree,
    factories: &ComponentFactoryRegistry,
) -> Result<CompiledPackages, ScopeCompileError> {
    let plan = compile_scope(compiler, tree)?;
    let packages = plan
        .iter()
        .map(|(_, scope)| decode_package(scope, factories))
        .collect::<Result<Vec<_>, _>>()?;
    CompiledPackages::from_packages(packages)
        .map_err(|source| ScopeCompileError::PackageAssembly { source })
}

fn decode_package(
    scope: &ScopePlan,
    factories: &ComponentFactoryRegistry,
) -> Result<SamplePackage, ScopeCompileError> {
    let sampler = decode(scope.sampler_node(), ComponentCategory::Sampler, factories)?;
    let sampler_category = sampler.category();
    let FactoryComponent::Sampler(sampler) = sampler else {
        return Err(ScopeCompileError::Factory {
            source: ScopeFactoryError::CategoryMismatch {
                node_id: scope.sampler_node().node_id,
                path: scope.sampler_node().path.clone(),
                expected: ComponentCategory::Sampler,
                actual: sampler_category,
            },
        });
    };
    let configurations = decode_many(
        scope.configuration_nodes(),
        ComponentCategory::Configuration,
        factories,
    )?
    .into_iter()
    .map(|component| match component {
        FactoryComponent::Configuration(value) => Ok(value),
        other => Err(other),
    })
    .collect::<Result<Vec<_>, _>>()
    .map_err(|other| category_mismatch(scope, ComponentCategory::Configuration, other))?;
    let preprocessors = decode_many(
        scope.preprocessor_nodes(),
        ComponentCategory::Preprocessor,
        factories,
    )?
    .into_iter()
    .map(|component| match component {
        FactoryComponent::Preprocessor(value) => Ok(value),
        other => Err(other),
    })
    .collect::<Result<Vec<_>, _>>()
    .map_err(|other| category_mismatch(scope, ComponentCategory::Preprocessor, other))?;
    let timers = decode_many(scope.timer_nodes(), ComponentCategory::Timer, factories)?
        .into_iter()
        .map(|component| match component {
            FactoryComponent::Timer(value) => Ok(value),
            other => Err(other),
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|other| category_mismatch(scope, ComponentCategory::Timer, other))?;
    let postprocessors = decode_many(
        scope.postprocessor_nodes(),
        ComponentCategory::Postprocessor,
        factories,
    )?
    .into_iter()
    .map(|component| match component {
        FactoryComponent::Postprocessor(value) => Ok(value),
        other => Err(other),
    })
    .collect::<Result<Vec<_>, _>>()
    .map_err(|other| category_mismatch(scope, ComponentCategory::Postprocessor, other))?;
    let assertions = decode_many(
        scope.assertion_nodes(),
        ComponentCategory::Assertion,
        factories,
    )?
    .into_iter()
    .map(|component| match component {
        FactoryComponent::Assertion(value) => Ok(value),
        other => Err(other),
    })
    .collect::<Result<Vec<_>, _>>()
    .map_err(|other| category_mismatch(scope, ComponentCategory::Assertion, other))?;
    let listeners = decode_many(
        scope.listener_nodes(),
        ComponentCategory::Listener,
        factories,
    )?
    .into_iter()
    .map(|component| match component {
        FactoryComponent::Listener(value) => Ok(value),
        other => Err(other),
    })
    .collect::<Result<Vec<_>, _>>()
    .map_err(|other| category_mismatch(scope, ComponentCategory::Listener, other))?;

    Ok(SamplePackage::builder(scope.sampler_id, sampler)
        .configurations(configurations)
        .preprocessors(preprocessors)
        .timers(timers)
        .postprocessors(postprocessors)
        .assertions(assertions)
        .listeners(listeners)
        .build())
}

fn decode_many(
    components: &[ScopeComponent],
    category: ComponentCategory,
    factories: &ComponentFactoryRegistry,
) -> Result<Vec<FactoryComponent>, ScopeCompileError> {
    components
        .iter()
        .map(|component| decode(component, category, factories))
        .collect()
}

fn decode(
    component: &ScopeComponent,
    expected: ComponentCategory,
    factories: &ComponentFactoryRegistry,
) -> Result<FactoryComponent, ScopeCompileError> {
    if let Err(detail) = validate_factory_properties(component) {
        return Err(ScopeCompileError::Factory {
            source: factory_decode_error(component, expected, detail),
        });
    }
    let Some(factory) = factories.get(&component.binding.test_class) else {
        return Err(ScopeCompileError::Factory {
            source: ScopeFactoryError::MissingFactory {
                node_id: component.node_id,
                path: component.path.clone(),
                test_class: component.binding.test_class.clone(),
                category: expected,
            },
        });
    };
    if let Some(identity) = factory.test_class()
        && identity != component.binding.test_class
    {
        return Err(ScopeCompileError::Factory {
            source: ScopeFactoryError::IdentityMismatch {
                node_id: component.node_id,
                path: component.path.clone(),
                expected: component.binding.test_class.clone(),
                actual: bounded(identity),
            },
        });
    }
    let product = factory
        .create(component)
        .map_err(|source| ScopeCompileError::Factory { source })?;
    if product.category() != expected {
        return Err(ScopeCompileError::Factory {
            source: ScopeFactoryError::CategoryMismatch {
                node_id: component.node_id,
                path: component.path.clone(),
                expected,
                actual: product.category(),
            },
        });
    }
    Ok(product)
}

/// Decodes the built-in assertion families without making callers register a
/// second, parallel class registry.  A caller-supplied hook still wins in
/// [`decode`], which keeps plugin/adaptor replacement explicit and testable.
fn decode_builtin_assertion(component: &ScopeComponent) -> Result<Arc<dyn Assertion>, String> {
    let element = &component.element;
    let name = element.name().to_owned();
    match element.test_class() {
        "ResponseAssertion" | "org.apache.jmeter.assertions.ResponseAssertion" => {
            reject_unknown_assertion_properties(
                element,
                &[
                    "Asserion.test_strings",
                    "Assertion.test_type",
                    "Assertion.test_field",
                    "Assertion.assume_success",
                    "Assertion.custom_message",
                    "Assertion.scope",
                    "Scope.variable",
                ],
            )?;
            reject_unsupported_assertion_scope(element)?;
            let field = required_string_property(element, "Assertion.test_field")?;
            let test_type = required_i32_property(element, "Assertion.test_type")?;
            let patterns = collection_strings(element, "Asserion.test_strings")?;
            let assume_success =
                optional_bool_property(element, "Assertion.assume_success", false)?;
            let custom_message = optional_string_property(element, "Assertion.custom_message")?;
            let assertion = ResponseAssertion::from_wire(
                name,
                field,
                test_type,
                patterns,
                assume_success,
                custom_message,
            )
            .map_err(|error| error.to_string())?;
            Ok(Arc::new(assertion))
        }
        "DurationAssertion" | "org.apache.jmeter.assertions.DurationAssertion" => {
            reject_unknown_assertion_properties(
                element,
                &[
                    "DurationAssertion.duration",
                    "Assertion.scope",
                    "Scope.variable",
                ],
            )?;
            reject_unsupported_assertion_scope(element)?;
            let value = required_string_property(element, "DurationAssertion.duration")?;
            Ok(Arc::new(DurationAssertion::from_wire(name, value)))
        }
        "SizeAssertion" | "org.apache.jmeter.assertions.SizeAssertion" => {
            reject_unknown_assertion_properties(
                element,
                &[
                    "Assertion.test_field",
                    "SizeAssertion.operator",
                    "SizeAssertion.size",
                    "Assertion.scope",
                    "Scope.variable",
                ],
            )?;
            reject_unsupported_assertion_scope(element)?;
            let field = required_string_property(element, "Assertion.test_field")?;
            let operator = required_i32_property(element, "SizeAssertion.operator")?;
            let size = required_string_property(element, "SizeAssertion.size")?;
            Ok(Arc::new(SizeAssertion::from_wire(
                name, field, operator, size,
            )))
        }
        "MD5HexAssertion" | "org.apache.jmeter.assertions.MD5HexAssertion" => {
            reject_unknown_assertion_properties(element, &["MD5HexAssertion.size"])?;
            let expected = required_string_property(element, "MD5HexAssertion.size")?;
            Ok(Arc::new(Md5HexAssertion::from_wire(name, expected)))
        }
        "XMLAssertion" | "org.apache.jmeter.assertions.XMLAssertion" => {
            reject_unknown_assertion_properties(element, &[])?;
            Ok(Arc::new(XmlAssertion::from_wire(name)))
        }
        "XPathAssertion" | "org.apache.jmeter.assertions.XPathAssertion" => {
            reject_unknown_assertion_properties(
                element,
                &[
                    "XPath.xpath",
                    "XPath.negate",
                    "XPath.whitespace",
                    "XPath.validate",
                    "XPath.namespace",
                    "XPath.tolerant",
                    "XPath.report_errors",
                    "XPath.show_warnings",
                    "XPath.quiet",
                    "XPath.download_dtds",
                    "Assertion.scope",
                    "Scope.variable",
                ],
            )?;
            reject_unsupported_assertion_scope(element)?;
            let expression = required_string_property(element, "XPath.xpath")?;
            let options = xpath_options(element)?;
            Ok(Arc::new(
                XPathAssertion::from_wire(name, expression)
                    .with_negate(options.negate)
                    .with_options(options.options),
            ))
        }
        "JSONPathAssertion" | "org.apache.jmeter.assertions.JSONPathAssertion" => {
            Ok(Arc::new(UnsupportedJsonAssertion::json(name)))
        }
        "JMESPathAssertion" | "org.apache.jmeter.assertions.jmespath.JMESPathAssertion" => {
            Ok(Arc::new(UnsupportedJsonAssertion::jmespath(name)))
        }
        class => {
            let capability_id = JMETER_ASSERTION_BINDINGS
                .iter()
                .find(|(alias, _)| *alias == class)
                .map_or_else(
                    || component.binding.capability_id.clone(),
                    |(_, capability_id)| (*capability_id).to_owned(),
                );
            Ok(Arc::new(UnsupportedNativeAssertion::new(
                name,
                capability_id,
            )))
        }
    }
}

fn reject_unknown_assertion_properties(
    element: &TestElement,
    allowed: &[&str],
) -> Result<(), String> {
    for name in element.properties.keys() {
        if !allowed.contains(&name) {
            return Err(format!("unsupported assertion property {name:?}"));
        }
    }
    Ok(())
}

fn reject_unsupported_assertion_scope(element: &TestElement) -> Result<(), String> {
    if let Some(scope) = element.property("Assertion.scope") {
        let scope = scope.as_str().map_err(|error| {
            format!("assertion property \"Assertion.scope\" must be a string: {error}")
        })?;
        let scope = scope.trim();
        if !scope.is_empty() && !scope.eq_ignore_ascii_case("parent") {
            return Err(format!(
                "assertion result scope {scope:?} requires an unsupported scope capability"
            ));
        }
    }
    if let Some(variable) = element.property("Scope.variable") {
        let variable = variable.as_str().map_err(|error| {
            format!("assertion property \"Scope.variable\" must be a string: {error}")
        })?;
        if !variable.trim().is_empty() {
            return Err(
                "assertion variable result scope requires an unsupported scope capability"
                    .to_owned(),
            );
        }
    }
    Ok(())
}

fn property<'a>(element: &'a TestElement, name: &str) -> Result<&'a PropertyValue, String> {
    element.property(name).ok_or_else(|| {
        format!(
            "required assertion property {name:?} is absent (absent is distinct from an empty value)"
        )
    })
}

fn required_string_property(element: &TestElement, name: &str) -> Result<String, String> {
    property(element, name)?
        .as_str()
        .map(str::to_owned)
        .map_err(|error| format!("assertion property {name:?} must be a string: {error}"))
}

fn required_i32_property(element: &TestElement, name: &str) -> Result<i32, String> {
    property(element, name)?
        .as_i32()
        .map_err(|error| format!("assertion property {name:?} must be an int: {error}"))
}

fn optional_string_property(element: &TestElement, name: &str) -> Result<Option<String>, String> {
    element
        .property(name)
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .map_err(|error| format!("assertion property {name:?} must be a string: {error}"))
        })
        .transpose()
}

fn optional_bool_property(
    element: &TestElement,
    name: &str,
    default: bool,
) -> Result<bool, String> {
    let Some(value) = element.property(name) else {
        return Ok(default);
    };
    match value {
        PropertyValue::Boolean(value) => Ok(*value),
        PropertyValue::String(value) => match value.as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(format!(
                "assertion property {name:?} must be true or false, not an empty/other string"
            )),
        },
        _ => Err(format!(
            "assertion property {name:?} must be a bool or boolean string"
        )),
    }
}

fn collection_strings(element: &TestElement, name: &str) -> Result<Vec<String>, String> {
    let Some(value) = element.property(name) else {
        return Ok(Vec::new());
    };
    match value {
        PropertyValue::Collection(values) => values
            .iter()
            .enumerate()
            .map(|(index, value)| {
                value.as_str().map(str::to_owned).map_err(|error| {
                    format!("assertion property {name:?} entry {index} must be a string: {error}")
                })
            })
            .collect(),
        PropertyValue::NamedCollection(entries) => entries
            .iter()
            .enumerate()
            .map(|(index, entry)| {
                entry.value.as_str().map(str::to_owned).map_err(|error| {
                    format!("assertion property {name:?} entry {index} must be a string: {error}")
                })
            })
            .collect(),
        _ => Err(format!(
            "assertion property {name:?} must be an ordered collection"
        )),
    }
}

struct XPathWireOptions {
    negate: bool,
    options: XPathOptions,
}

fn xpath_options(element: &TestElement) -> Result<XPathWireOptions, String> {
    Ok(XPathWireOptions {
        negate: optional_bool_property(element, "XPath.negate", false)?,
        options: XPathOptions {
            whitespace: optional_bool_property(element, "XPath.whitespace", false)?,
            validate: optional_bool_property(element, "XPath.validate", false)?,
            namespace: optional_bool_property(element, "XPath.namespace", false)?,
            tolerant: optional_bool_property(element, "XPath.tolerant", false)?,
            report_errors: optional_bool_property(element, "XPath.report_errors", false)?,
            show_warnings: optional_bool_property(element, "XPath.show_warnings", false)?,
            quiet: optional_bool_property(element, "XPath.quiet", false)?,
            download_dtds: optional_bool_property(element, "XPath.download_dtds", false)?,
        },
    })
}

fn category_mismatch(
    scope: &ScopePlan,
    expected: ComponentCategory,
    actual: FactoryComponent,
) -> ScopeCompileError {
    ScopeCompileError::Factory {
        source: ScopeFactoryError::CategoryMismatch {
            node_id: scope.sampler_id,
            path: scope.sampler_node().path.clone(),
            expected,
            actual: actual.category(),
        },
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "sampler compilation receives the explicit bounded walk state"
)]
fn compile_sampler(
    compiler: &ScopeCompiler,
    tree: &ElementTree,
    sampler_id: NodeId,
    sampler_path: Vec<NodeId>,
    mut scope: Vec<ScopeComponent>,
    controller_path: Vec<NodeId>,
    _replacement_chain: Vec<NodeId>,
    packages: &mut BTreeMap<NodeId, ScopePlan>,
    disabled: &mut BTreeSet<NodeId>,
    run_collectors: &mut Vec<ScopeComponent>,
) -> Result<(), ScopeCompileError> {
    let node = tree
        .get(sampler_id)
        .ok_or_else(|| ScopeCompileError::Tree(format!("missing node {sampler_id}")))?;
    let sampler_binding = binding(compiler, sampler_id, &sampler_path, node.value())?;
    let sampler_component =
        ScopeComponent::new(sampler_id, &sampler_path, node.value(), &sampler_binding);

    // A sampler's child hashTree is the innermost lexical scope. JMeter's
    // TestCompiler inspects every direct child there, not just the common
    // postprocessor/assertion/listener classes; configuration, preprocessor,
    // and timer siblings are therefore applicable too.
    let mut attached = Vec::new();
    for child_id in node.children() {
        let child = tree
            .get(*child_id)
            .ok_or_else(|| ScopeCompileError::Tree(format!("missing node {child_id}")))?;
        let child_path = path_with(&sampler_path, *child_id);
        if !child.value().enabled {
            mark_disabled(
                tree,
                *child_id,
                &child_path,
                compiler.limits().max_depth,
                disabled,
            )?;
            continue;
        }
        let child_binding = binding(compiler, *child_id, &child_path, child.value())?;
        if !is_scope_category(child_binding.category) {
            return Err(ScopeCompileError::CategoryMisuse {
                node_id: *child_id,
                category: child_binding.category,
                parent_id: Some(sampler_id),
                path: child_path,
            });
        }
        let child_component = ScopeComponent::new(
            *child_id,
            &path_with(&sampler_path, *child_id),
            child.value(),
            &child_binding,
        );
        reject_unsupported_collector(&child_component)?;
        if is_result_collector(child.value(), &child_binding) {
            // Collectors have run lifetime even when their source placement is
            // the sampler's attached hashTree. The component remains in the
            // package so the source-scope predicate is preserved as well.
            run_collectors.push(child_component.clone());
            if run_collectors.len() > compiler.limits().max_components {
                return Err(ScopeCompileError::ComponentLimit {
                    count: run_collectors.len(),
                    limit: compiler.limits().max_components,
                });
            }
        }
        if !child.children().is_empty() {
            return Err(ScopeCompileError::Topology {
                node_id: Some(*child_id),
                path: child_path,
                detail: "attached component must be a leaf".to_owned(),
            });
        }
        attached.push(child_component);
    }
    scope.extend(attached);

    let package_components = checked_sum(
        &sampler_path,
        "scope component count",
        [scope.len(), controller_path.len(), 1],
    )?;
    if package_components > compiler.limits().max_components {
        return Err(ScopeCompileError::ComponentLimit {
            count: package_components,
            limit: compiler.limits().max_components,
        });
    }
    let mut package_bytes = checked_sum(
        &sampler_path,
        "scope metadata bytes",
        [
            sampler_binding.test_class.len(),
            sampler_binding.capability_id.len(),
            node.value().name().len(),
        ],
    )?;
    for component in &scope {
        package_bytes = checked_sum(
            &sampler_path,
            "scope metadata bytes",
            [
                package_bytes,
                component.binding.test_class.len(),
                component.binding.capability_id.len(),
                component.element.name().len(),
            ],
        )?;
    }
    if package_bytes > compiler.limits().max_bytes {
        return Err(ScopeCompileError::ByteLimit {
            bytes: package_bytes,
            limit: compiler.limits().max_bytes,
        });
    }
    if packages.len() >= compiler.limits().max_packages {
        return Err(ScopeCompileError::PackageLimit {
            count: packages.len().checked_add(1).ok_or_else(|| {
                ScopeCompileError::ArithmeticOverflow {
                    path: sampler_path.clone(),
                    detail: "package count".to_owned(),
                }
            })?,
            limit: compiler.limits().max_packages,
        });
    }

    let mut package = ScopePlan {
        sampler_id,
        configurations: Vec::new(),
        preprocessors: Vec::new(),
        timers: Vec::new(),
        sampler: sampler_binding,
        postprocessors: Vec::new(),
        assertions: Vec::new(),
        listeners: Vec::new(),
        controller_path,
        configuration_components: Vec::new(),
        preprocessor_components: Vec::new(),
        timer_components: Vec::new(),
        sampler_component,
        postprocessor_components: Vec::new(),
        assertion_components: Vec::new(),
        listener_components: Vec::new(),
    };
    // The pinned TestCompiler walks the sampler path from the sampler toward
    // the root for configurations, timers, and listeners. That means the
    // nearest lexical scope wins, while siblings within one scope retain
    // source order. Processors and assertions are prepended during that walk
    // and therefore remain outermost-to-innermost.
    for component in ordered_scope_components(&scope, ComponentCategory::Configuration, true) {
        package.configurations.push(component.binding.clone());
        package.configuration_components.push(component);
    }
    for component in ordered_scope_components(&scope, ComponentCategory::Preprocessor, false) {
        package.preprocessors.push(component.binding.clone());
        package.preprocessor_components.push(component);
    }
    for component in ordered_scope_components(&scope, ComponentCategory::Timer, true) {
        package.timers.push(component.binding.clone());
        package.timer_components.push(component);
    }
    for component in ordered_scope_components(&scope, ComponentCategory::Postprocessor, false) {
        package.postprocessors.push(component.binding.clone());
        package.postprocessor_components.push(component);
    }
    for component in ordered_scope_components(&scope, ComponentCategory::Assertion, false) {
        package.assertions.push(component.binding.clone());
        package.assertion_components.push(component);
    }
    for component in ordered_scope_components(&scope, ComponentCategory::Listener, true) {
        package.listeners.push(component.binding.clone());
        package.listener_components.push(component);
    }
    if packages.insert(sampler_id, package).is_some() {
        return Err(ScopeCompileError::DuplicateSampler {
            sampler_id,
            path: sampler_path,
        });
    }
    Ok(())
}

/// Selects one category while preserving source sibling order. JMeter's
/// compiler uses nearest-first accumulation only for configuration, timer,
/// and listener categories; the other phases use the lexical outer-to-inner
/// order already represented by `scope`.
fn ordered_scope_components(
    scope: &[ScopeComponent],
    category: ComponentCategory,
    nearest_first: bool,
) -> Vec<ScopeComponent> {
    if !nearest_first {
        return scope
            .iter()
            .filter(|component| component.binding.category == category)
            .cloned()
            .collect();
    }
    let mut groups = BTreeMap::<usize, Vec<ScopeComponent>>::new();
    for component in scope
        .iter()
        .filter(|component| component.binding.category == category)
    {
        groups
            .entry(component.path.len())
            .or_default()
            .push(component.clone());
    }
    groups
        .into_iter()
        .rev()
        .flat_map(|(_, components)| components)
        .collect()
}

fn validate_tree(tree: &ElementTree, limits: ScopeLimits) -> Result<(), ScopeCompileError> {
    if tree.len() > limits.max_nodes {
        return Err(ScopeCompileError::NodeLimit {
            count: tree.len(),
            limit: limits.max_nodes,
        });
    }
    tree.validate()
        .map_err(|error| ScopeCompileError::Tree(error.to_string()))?;
    let mut pending = tree
        .root_ids()
        .iter()
        .rev()
        .map(|id| (*id, 0usize))
        .collect::<Vec<_>>();
    while let Some((id, depth)) = pending.pop() {
        if depth > limits.max_depth {
            return Err(ScopeCompileError::DepthLimit {
                depth,
                limit: limits.max_depth,
            });
        }
        let node = tree
            .get(id)
            .ok_or_else(|| ScopeCompileError::Tree(format!("missing node {id}")))?;
        for child in node.children().iter().rev() {
            let child_depth =
                depth
                    .checked_add(1)
                    .ok_or_else(|| ScopeCompileError::ArithmeticOverflow {
                        path: vec![*child],
                        detail: "source depth".to_owned(),
                    })?;
            pending.push((*child, child_depth));
        }
    }
    Ok(())
}

fn binding(
    compiler: &ScopeCompiler,
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
) -> Result<ComponentBinding, ScopeCompileError> {
    let class = element.test_class();
    if class.trim().is_empty() {
        return Err(ScopeCompileError::EmptyTestClass {
            node_id,
            path: path.to_vec(),
        });
    }
    if class.chars().any(char::is_control) {
        return Err(ScopeCompileError::InvalidTestClass {
            node_id,
            path: path.to_vec(),
            reason: "test class contains a control character".to_owned(),
        });
    }
    if class == "hashTree" {
        return Err(ScopeCompileError::Topology {
            node_id: Some(node_id),
            path: path.to_vec(),
            detail: "hashTree wrapper reached the semantic runtime boundary".to_owned(),
        });
    }
    if !element.opaque_extensions.is_empty() {
        return Err(ScopeCompileError::Unsupported(UnsupportedComponent {
            node_id,
            test_class: bounded(class),
            category: guess_category(class),
            capability_id: Some("runtime.plan.opaque-element-extension".to_owned()),
            external: false,
            path: path.to_vec(),
        }));
    }
    let Some(binding) = compiler.registry().get(class).cloned() else {
        return Err(ScopeCompileError::Unsupported(UnsupportedComponent {
            node_id,
            test_class: bounded(class),
            category: guess_category(class),
            capability_id: None,
            external: false,
            path: path.to_vec(),
        }));
    };
    if !binding.is_native() {
        return Err(ScopeCompileError::Unsupported(UnsupportedComponent {
            node_id,
            test_class: bounded(class),
            category: binding.category,
            capability_id: Some(binding.capability_id.clone()),
            external: binding.is_external(),
            path: path.to_vec(),
        }));
    }
    Ok(binding)
}

fn validate_owner(
    owner_category: Option<ComponentCategory>,
    node_id: NodeId,
    parent_id: Option<NodeId>,
    path: &[NodeId],
    category: ComponentCategory,
) -> Result<(), ScopeCompileError> {
    let Some(owner) = owner_category else {
        return Ok(());
    };
    let allowed = match owner {
        ComponentCategory::Sampler => matches!(
            category,
            ComponentCategory::Postprocessor
                | ComponentCategory::Assertion
                | ComponentCategory::Listener
        ),
        // The semantic tree also permits a configuration node to act as a
        // lexical scope owner.  This is the normalized representation used by
        // the standalone scope API (and by older callers that build trees
        // directly), while elementProp values remain embedded in the source
        // element.  The inherited configuration is carried exactly once as
        // the child branch is walked.
        ComponentCategory::Configuration => matches!(
            category,
            ComponentCategory::Configuration
                | ComponentCategory::Preprocessor
                | ComponentCategory::Timer
                | ComponentCategory::Sampler
                | ComponentCategory::Controller
                | ComponentCategory::Lifecycle
                | ComponentCategory::Replaceable
        ),
        ComponentCategory::Preprocessor | ComponentCategory::Timer => false,
        ComponentCategory::Postprocessor
        | ComponentCategory::Assertion
        | ComponentCategory::Listener => false,
        ComponentCategory::Controller
        | ComponentCategory::Lifecycle
        | ComponentCategory::Replaceable => true,
    };
    if allowed {
        Ok(())
    } else {
        Err(ScopeCompileError::CategoryMisuse {
            node_id,
            category,
            parent_id,
            path: path.to_vec(),
        })
    }
}

fn mark_disabled(
    tree: &ElementTree,
    id: NodeId,
    path: &[NodeId],
    max_depth: usize,
    disabled: &mut BTreeSet<NodeId>,
) -> Result<(), ScopeCompileError> {
    let mut pending = vec![(id, path.to_vec())];
    while let Some((current, current_path)) = pending.pop() {
        let depth = current_path.len().checked_sub(1).ok_or_else(|| {
            ScopeCompileError::ArithmeticOverflow {
                path: current_path.clone(),
                detail: "disabled branch depth".to_owned(),
            }
        })?;
        if depth > max_depth {
            return Err(ScopeCompileError::DepthLimit {
                depth,
                limit: max_depth,
            });
        }
        let node = tree
            .get(current)
            .ok_or_else(|| ScopeCompileError::Tree(format!("missing node {current}")))?;
        disabled.insert(current);
        for child in node.children().iter().rev() {
            pending.push((*child, path_with(&current_path, *child)));
        }
    }
    Ok(())
}

fn replacement_target(
    node_id: NodeId,
    element: &TestElement,
    path: &[NodeId],
) -> Result<Option<NodeId>, ScopeCompileError> {
    let Some(value) = element.temporary_properties.get("runtime.replacement-node") else {
        return Ok(None);
    };
    let target = value
        .as_i64()
        .map_err(|_| ScopeCompileError::InvalidTestClass {
            node_id,
            path: path.to_vec(),
            reason: "replacement reference must be a signed integer".to_owned(),
        })?;
    if target < 0 {
        return Err(ScopeCompileError::InvalidTestClass {
            node_id,
            path: path.to_vec(),
            reason: "replacement reference cannot be negative".to_owned(),
        });
    }
    Ok(Some(NodeId::new(target as u64)))
}

fn path_with(parent: &[NodeId], id: NodeId) -> Vec<NodeId> {
    let mut path = parent.to_vec();
    path.push(id);
    path
}

fn checked_sum<const N: usize>(
    path: &[NodeId],
    detail: &'static str,
    values: [usize; N],
) -> Result<usize, ScopeCompileError> {
    values.into_iter().try_fold(0usize, |total, value| {
        total
            .checked_add(value)
            .ok_or_else(|| ScopeCompileError::ArithmeticOverflow {
                path: path.to_vec(),
                detail: detail.to_owned(),
            })
    })
}

fn component_metadata_bytes(component: &ScopeComponent) -> Result<usize, ScopeCompileError> {
    checked_sum(
        &component.path,
        "scope metadata bytes",
        [
            component.binding.test_class.len(),
            component.binding.capability_id.len(),
            component.element.name().len(),
        ],
    )
}

fn bounded(value: &str) -> String {
    if value.len() <= 4_096 {
        value.to_owned()
    } else {
        let mut end = 4_096;
        while end > 0 && !value.is_char_boundary(end) {
            end -= 1;
        }
        value[..end].to_owned()
    }
}

fn is_scope_category(category: ComponentCategory) -> bool {
    matches!(
        category,
        ComponentCategory::Configuration
            | ComponentCategory::Preprocessor
            | ComponentCategory::Timer
            | ComponentCategory::Postprocessor
            | ComponentCategory::Assertion
            | ComponentCategory::Listener
    )
}

fn is_result_collector(element: &TestElement, binding: &ComponentBinding) -> bool {
    binding.category == ComponentCategory::Listener
        && matches!(
            element.test_class(),
            "ResultCollector" | "org.apache.jmeter.reporters.ResultCollector"
        )
}

fn is_non_executable_lifecycle(element: &TestElement, binding: &ComponentBinding) -> bool {
    binding.category == ComponentCategory::Lifecycle
        && matches!(
            element.test_class(),
            "TestFragmentController"
                | "org.apache.jmeter.control.TestFragmentController"
                | "WorkBench"
                | "org.apache.jmeter.testelement.WorkBench"
        )
}

fn reject_unsupported_collector(component: &ScopeComponent) -> Result<(), ScopeCompileError> {
    if component.result_collector_kind() == Some(ResultCollectorKind::Unsupported) {
        return Err(ScopeCompileError::Unsupported(UnsupportedComponent {
            node_id: component.node_id,
            test_class: bounded(component.element.test_class()),
            category: component.binding.category,
            capability_id: Some("runtime.result-collector.visualizer".to_owned()),
            external: false,
            path: component.path.clone(),
        }));
    }
    Ok(())
}

fn guess_category(test_class: &str) -> ComponentCategory {
    if test_class.contains("Sampler") {
        ComponentCategory::Sampler
    } else if test_class.contains("Timer") {
        ComponentCategory::Timer
    } else if test_class.contains("Assertion") {
        ComponentCategory::Assertion
    } else if test_class.contains("Listener") {
        ComponentCategory::Listener
    } else if test_class.contains("Pre") {
        ComponentCategory::Preprocessor
    } else if test_class.contains("Post") {
        ComponentCategory::Postprocessor
    } else if test_class.contains("Controller") {
        ComponentCategory::Controller
    } else {
        ComponentCategory::Configuration
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "deterministic compiler fixture setup")]
mod tests {
    use super::*;
    use crate::{
        ComponentFactoryRegistry, ComponentRegistry, FactoryComponent, ScopeCompiler, ScopeLimits,
        UnsupportedSampler,
    };
    use jmeter_rs_model::{ElementTree, OpaqueValue, PropertyValue, TestElement};
    use std::sync::Arc;

    fn component_tree() -> (ElementTree, NodeId) {
        let mut tree = ElementTree::new();
        let plan = tree
            .insert_root(TestElement::named("TestPlan", "Gui", "plan"))
            .expect("plan");
        let group = tree
            .insert_child(plan, TestElement::named("ThreadGroup", "Gui", "group"))
            .expect("group");
        tree.insert_child(group, TestElement::named("Arguments", "Gui", "config"))
            .expect("config");
        tree.insert_child(group, TestElement::named("ScopePreprocessor", "Gui", "pre"))
            .expect("preprocessor");
        tree.insert_child(group, TestElement::named("ConstantTimer", "Gui", "timer"))
            .expect("timer");
        let sampler = tree
            .insert_child(group, TestElement::named("DebugSampler", "Gui", "sample"))
            .expect("sampler");
        tree.insert_child(
            sampler,
            TestElement::named("ResponseAssertion", "Gui", "assertion"),
        )
        .expect("assertion");
        let collector = tree
            .insert_child(
                plan,
                TestElement::named("ResultCollector", "StatVisualizer", "jtl"),
            )
            .expect("collector");
        (tree, collector)
    }

    #[test]
    fn sibling_scope_and_attached_phases_are_lexical_and_ordered() {
        let (tree, collector) = component_tree();
        let mut registry = ComponentRegistry::builtins();
        registry.register_native(
            "ScopePreprocessor",
            ComponentCategory::Preprocessor,
            "runtime.test.preprocessor",
        );
        let plan = ScopeCompiler::new(registry, ScopeLimits::default())
            .compile(&tree)
            .expect("scope");
        let sampler = plan.iter().next().expect("sampler package").1;
        assert_eq!(sampler.configurations.len(), 1);
        assert_eq!(sampler.preprocessors.len(), 1);
        assert_eq!(sampler.timers.len(), 1);
        assert_eq!(sampler.assertions.len(), 1);
        assert!(sampler.postprocessors.is_empty());
        assert_eq!(plan.run_collectors().len(), 1);
        assert_eq!(plan.run_collectors()[0].node_id, collector);
        assert_eq!(sampler.configuration_nodes()[0].element.name(), "config");
        assert_eq!(sampler.sampler_node().path.last(), sampler_id(sampler));
    }

    #[test]
    fn nested_scope_order_matches_pinned_test_compiler_accumulation() {
        let mut tree = ElementTree::new();
        let plan = tree
            .insert_root(TestElement::named("TestPlan", "Gui", "plan"))
            .expect("plan");
        let group = tree
            .insert_child(plan, TestElement::named("ThreadGroup", "Gui", "group"))
            .expect("group");
        let _outer_config_a = tree
            .insert_child(
                group,
                TestElement::named("Arguments", "Gui", "outer config a"),
            )
            .expect("outer config a");
        let _outer_config_b = tree
            .insert_child(
                group,
                TestElement::named("Arguments", "Gui", "outer config b"),
            )
            .expect("outer config b");
        let _outer_pre = tree
            .insert_child(
                group,
                TestElement::named("ScopePreprocessor", "Gui", "outer pre"),
            )
            .expect("outer pre");
        let _outer_timer_a = tree
            .insert_child(
                group,
                TestElement::named("ConstantTimer", "Gui", "outer timer a"),
            )
            .expect("outer timer a");
        let _outer_timer_b = tree
            .insert_child(
                group,
                TestElement::named("ConstantTimer", "Gui", "outer timer b"),
            )
            .expect("outer timer b");
        let outer_listener_a = tree
            .insert_child(
                group,
                TestElement::named("ResultCollector", "SimpleDataWriter", "outer listener a"),
            )
            .expect("outer listener a");
        let outer_listener_b = tree
            .insert_child(
                group,
                TestElement::named("ResultCollector", "SimpleDataWriter", "outer listener b"),
            )
            .expect("outer listener b");
        let controller = tree
            .insert_child(
                group,
                TestElement::named("GenericController", "Gui", "controller"),
            )
            .expect("controller");
        let _inner_config = tree
            .insert_child(
                controller,
                TestElement::named("Arguments", "Gui", "inner config"),
            )
            .expect("inner config");
        let inner_pre = tree
            .insert_child(
                controller,
                TestElement::named("ScopePreprocessor", "Gui", "inner pre"),
            )
            .expect("inner pre");
        let _inner_timer = tree
            .insert_child(
                controller,
                TestElement::named("ConstantTimer", "Gui", "inner timer"),
            )
            .expect("inner timer");
        let inner_listener = tree
            .insert_child(
                controller,
                TestElement::named("ResultCollector", "SimpleDataWriter", "inner listener"),
            )
            .expect("inner listener");
        let inner_post = tree
            .insert_child(
                controller,
                TestElement::named("ScopePostprocessor", "Gui", "inner post"),
            )
            .expect("inner post");
        let inner_assertion = tree
            .insert_child(
                controller,
                TestElement::named("ScopeAssertion", "Gui", "inner assertion"),
            )
            .expect("inner assertion");
        let sampler = tree
            .insert_child(
                controller,
                TestElement::named("DebugSampler", "Gui", "sample"),
            )
            .expect("sampler");
        let attached_config = tree
            .insert_child(
                sampler,
                TestElement::named("Arguments", "Gui", "attached config"),
            )
            .expect("attached config");
        let _attached_pre = tree
            .insert_child(
                sampler,
                TestElement::named("ScopePreprocessor", "Gui", "attached pre"),
            )
            .expect("attached pre");
        let attached_timer = tree
            .insert_child(
                sampler,
                TestElement::named("ConstantTimer", "Gui", "attached timer"),
            )
            .expect("attached timer");
        let attached_post = tree
            .insert_child(
                sampler,
                TestElement::named("ScopePostprocessor", "Gui", "attached post"),
            )
            .expect("attached post");
        let attached_assertion = tree
            .insert_child(
                sampler,
                TestElement::named("ScopeAssertion", "Gui", "attached assertion"),
            )
            .expect("attached assertion");
        let attached_listener = tree
            .insert_child(
                sampler,
                TestElement::named("ResultCollector", "SimpleDataWriter", "attached listener"),
            )
            .expect("attached listener");

        let mut registry = ComponentRegistry::builtins();
        registry.register_native(
            "ScopePostprocessor",
            ComponentCategory::Postprocessor,
            "runtime.test.postprocessor",
        );
        registry.register_native(
            "ScopeAssertion",
            ComponentCategory::Assertion,
            "runtime.test.assertion",
        );
        registry.register_native(
            "ScopePreprocessor",
            ComponentCategory::Preprocessor,
            "runtime.test.preprocessor",
        );
        let scope = ScopeCompiler::new(registry, ScopeLimits::default())
            .compile(&tree)
            .expect("scope");
        let package = scope.get(sampler).expect("sampler package");

        let names = |components: &[ScopeComponent]| {
            components
                .iter()
                .map(|component| component.element.name().to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            names(package.configuration_nodes()),
            [
                "attached config",
                "inner config",
                "outer config a",
                "outer config b"
            ]
        );
        assert_eq!(
            names(package.preprocessor_nodes()),
            ["outer pre", "inner pre", "attached pre"]
        );
        assert_eq!(
            names(package.timer_nodes()),
            [
                "attached timer",
                "inner timer",
                "outer timer a",
                "outer timer b"
            ]
        );
        assert_eq!(
            names(package.postprocessor_nodes()),
            ["inner post", "attached post"]
        );
        assert_eq!(
            names(package.assertion_nodes()),
            ["inner assertion", "attached assertion"]
        );
        assert_eq!(
            names(package.listener_nodes()),
            [
                "attached listener",
                "inner listener",
                "outer listener a",
                "outer listener b"
            ]
        );
        assert_eq!(scope.run_collectors().len(), 4);
        assert!(
            scope
                .run_collectors()
                .iter()
                .any(|component| component.node_id == outer_listener_a)
        );
        assert!(
            scope
                .run_collectors()
                .iter()
                .any(|component| component.node_id == outer_listener_b)
        );
        assert!(
            scope
                .run_collectors()
                .iter()
                .any(|component| component.node_id == inner_listener)
        );
        assert!(
            scope
                .run_collectors()
                .iter()
                .any(|component| component.node_id == attached_listener)
        );
        assert_eq!(package.configuration_nodes()[0].node_id, attached_config);
        assert_eq!(package.preprocessor_nodes()[1].node_id, inner_pre);
        assert_eq!(package.timer_nodes()[0].node_id, attached_timer);
        assert_eq!(package.postprocessor_nodes()[0].node_id, inner_post);
        assert_eq!(package.postprocessor_nodes()[1].node_id, attached_post);
        assert_eq!(package.assertion_nodes()[0].node_id, inner_assertion);
        assert_eq!(package.assertion_nodes()[1].node_id, attached_assertion);
        assert_eq!(package.listener_nodes()[0].node_id, attached_listener);
    }

    fn sampler_id(scope: &ScopePlan) -> Option<&NodeId> {
        scope.sampler_node().path.last()
    }

    #[test]
    fn node_and_package_bounds_are_fail_closed() {
        let (tree, _) = component_tree();
        let compiler = ScopeCompiler::new(
            ComponentRegistry::builtins(),
            ScopeLimits::default().with_topology_limits(2, 1),
        );
        assert!(matches!(
            compiler.compile(&tree),
            Err(ScopeCompileError::NodeLimit { .. })
        ));

        let mut two = ElementTree::new();
        let root = two
            .insert_root(TestElement::named("TestPlan", "Gui", "plan"))
            .expect("root");
        two.insert_child(root, TestElement::named("DebugSampler", "Gui", "one"))
            .expect("one");
        two.insert_child(root, TestElement::named("DebugSampler", "Gui", "two"))
            .expect("two");
        let compiler = ScopeCompiler::new(
            ComponentRegistry::builtins(),
            ScopeLimits::default().with_topology_limits(32, 1),
        );
        assert!(matches!(
            compiler.compile(&two),
            Err(ScopeCompileError::PackageLimit { .. })
        ));
    }

    #[test]
    fn source_depth_bound_is_fail_closed() {
        let mut tree = ElementTree::new();
        let plan = tree
            .insert_root(TestElement::named("TestPlan", "Gui", "plan"))
            .expect("plan");
        let group = tree
            .insert_child(plan, TestElement::named("ThreadGroup", "Gui", "group"))
            .expect("group");
        tree.insert_child(group, TestElement::named("DebugSampler", "Gui", "sample"))
            .expect("sampler");
        let limits = ScopeLimits::new(32, 4_096, 1);
        let error = ScopeCompiler::new(ComponentRegistry::builtins(), limits)
            .compile(&tree)
            .expect_err("depth limit");
        assert!(matches!(
            error,
            ScopeCompileError::DepthLimit { depth: 2, .. }
        ));
    }

    #[test]
    fn disabled_unknown_subtree_is_retained_without_capability_failure() {
        let mut tree = ElementTree::new();
        let root = tree
            .insert_root(TestElement::named("TestPlan", "Gui", "plan"))
            .expect("root");
        let disabled = tree
            .insert_child(root, TestElement::named("UnknownPlugin", "Gui", "disabled"))
            .expect("disabled");
        let disabled_child = tree
            .insert_child(
                disabled,
                TestElement::named("UnknownNestedPlugin", "Gui", "nested"),
            )
            .expect("nested disabled");
        tree.get_mut(disabled)
            .expect("node")
            .value_mut()
            .set_enabled(false);
        let plan = ScopeCompiler::builtins()
            .compile(&tree)
            .expect("disabled plan");
        assert!(plan.disabled_ids().contains(&disabled));
        assert!(plan.disabled_ids().contains(&disabled_child));
        assert!(plan.is_empty());
    }

    #[test]
    fn disabled_ancestor_suppresses_unknown_enabled_descendants() {
        let mut tree = ElementTree::new();
        let plan = tree
            .insert_root(TestElement::named("TestPlan", "Gui", "plan"))
            .expect("plan");
        let controller = tree
            .insert_child(
                plan,
                TestElement::named("GenericController", "Gui", "disabled controller"),
            )
            .expect("controller");
        let unknown = tree
            .insert_child(
                controller,
                TestElement::named("com.example.PluginSampler", "PluginGui", "unknown"),
            )
            .expect("unknown descendant");
        tree.get_mut(controller)
            .expect("controller node")
            .value_mut()
            .set_enabled(false);

        let compiled = ScopeCompiler::builtins()
            .compile(&tree)
            .expect("disabled ancestor is a source-preserving branch");
        assert!(compiled.is_empty());
        assert!(compiled.disabled_ids().contains(&controller));
        assert!(compiled.disabled_ids().contains(&unknown));
    }

    #[test]
    fn enabled_opaque_element_is_preserved_but_not_made_transparently_executable() {
        let mut tree = ElementTree::new();
        let sampler = tree
            .insert_root(TestElement::named("DebugSampler", "Gui", "opaque sampler"))
            .expect("sampler");
        tree.get_mut(sampler)
            .expect("sampler node")
            .value_mut()
            .push_opaque_extension(OpaqueValue::new("plugin.extension", b"<raw/>".to_vec()));

        let error = ScopeCompiler::builtins()
            .compile(&tree)
            .expect_err("opaque executable element must fail closed");
        assert!(matches!(
            error,
            ScopeCompileError::Unsupported(UnsupportedComponent {
                node_id,
                capability_id: Some(capability_id),
                ..
            }) if node_id == sampler && capability_id == "runtime.plan.opaque-element-extension"
        ));
        let source = tree.get(sampler).expect("source sampler").value();
        assert_eq!(source.opaque_extensions.len(), 1);
        assert_eq!(source.opaque_extensions[0].raw, b"<raw/>".to_vec());
    }

    #[test]
    fn duplicate_sampler_identity_from_a_replacement_edge_is_rejected() {
        let mut tree = ElementTree::new();
        let plan = tree
            .insert_root(TestElement::named("TestPlan", "Gui", "plan"))
            .expect("plan");
        let sampler = tree
            .insert_child(plan, TestElement::named("DebugSampler", "Gui", "sample"))
            .expect("sampler");
        let module = tree
            .insert_child(
                plan,
                TestElement::named("ModuleController", "Gui", "module"),
            )
            .expect("module");
        tree.get_mut(module)
            .expect("module node")
            .value_mut()
            .set_temporary_property(
                "runtime.replacement-node",
                PropertyValue::long(sampler.as_u64() as i64),
            );

        let error = ScopeCompiler::builtins()
            .compile(&tree)
            .expect_err("same source sampler reached twice");
        assert!(matches!(
            error,
            ScopeCompileError::DuplicateSampler { sampler_id, .. } if sampler_id == sampler
        ));
    }

    #[test]
    fn deep_controller_tree_uses_bounded_explicit_walk_state() {
        let mut tree = ElementTree::new();
        let plan = tree
            .insert_root(TestElement::named("TestPlan", "Gui", "plan"))
            .expect("plan");
        let mut parent = plan;
        for depth in 0..512 {
            parent = tree
                .insert_child(
                    parent,
                    TestElement::named("GenericController", "Gui", format!("controller-{depth}")),
                )
                .expect("controller");
        }
        let sampler = tree
            .insert_child(parent, TestElement::named("DebugSampler", "Gui", "sample"))
            .expect("sampler");

        let limits = ScopeLimits::new(4_096, 1_000_000, 1_024);
        let compiled = ScopeCompiler::new(ComponentRegistry::builtins(), limits)
            .compile(&tree)
            .expect("deep controller tree");
        assert_eq!(compiled.len(), 1);
        assert_eq!(
            compiled.get(sampler).expect("deep package").sampler_id,
            sampler
        );
    }

    #[test]
    fn test_fragment_is_preservation_only_until_module_replacement_expands_it() {
        let mut tree = ElementTree::new();
        let plan = tree
            .insert_root(TestElement::named("TestPlan", "Gui", "plan"))
            .expect("plan");
        let fragment = tree
            .insert_child(
                plan,
                TestElement::named("TestFragmentController", "Gui", "fragment"),
            )
            .expect("fragment");
        let fragment_sampler = tree
            .insert_child(
                fragment,
                TestElement::named("DebugSampler", "Gui", "fragment sample"),
            )
            .expect("fragment sampler");
        let module = tree
            .insert_child(
                plan,
                TestElement::named("ModuleController", "Gui", "module"),
            )
            .expect("module");
        tree.get_mut(module)
            .expect("module node")
            .value_mut()
            .set_temporary_property(
                "runtime.replacement-node",
                PropertyValue::long(fragment.as_u64() as i64),
            );
        let plan = ScopeCompiler::builtins().compile(&tree).expect("scope");
        assert_eq!(plan.len(), 1);
        assert_eq!(
            plan.get(fragment_sampler)
                .expect("expanded sampler")
                .sampler_id,
            fragment_sampler
        );
        assert_eq!(plan.replacements().get(&module), Some(&fragment));
    }

    #[test]
    fn fragment_with_unknown_executable_content_is_not_scanned_in_source_position() {
        let mut tree = ElementTree::new();
        let fragment = tree
            .insert_root(TestElement::named(
                "TestFragmentController",
                "Gui",
                "fragment",
            ))
            .expect("fragment");
        tree.insert_child(
            fragment,
            TestElement::named("UnknownPluginSampler", "Gui", "opaque sample"),
        )
        .expect("unknown fragment child");
        let plan = ScopeCompiler::builtins()
            .compile(&tree)
            .expect("source-only fragment");
        assert!(plan.is_empty());
    }

    #[test]
    fn unsupported_result_collector_visualizer_is_typed_at_any_enabled_scope() {
        let mut tree = ElementTree::new();
        let plan = tree
            .insert_root(TestElement::named("TestPlan", "Gui", "plan"))
            .expect("plan");
        let sampler = tree
            .insert_child(plan, TestElement::named("DebugSampler", "Gui", "sample"))
            .expect("sampler");
        tree.insert_child(
            sampler,
            TestElement::named("ResultCollector", "FutureVisualizer", "listener"),
        )
        .expect("listener");
        let error = ScopeCompiler::builtins()
            .compile(&tree)
            .expect_err("unknown visualizer");
        assert!(matches!(
            error,
            ScopeCompileError::Unsupported(UnsupportedComponent {
                capability_id: Some(_),
                path,
                ..
            }) if path.len() == 3
        ));
    }

    #[test]
    fn fully_qualified_result_collector_keeps_run_sink_scope_identity() {
        let mut tree = ElementTree::new();
        let plan = tree
            .insert_root(TestElement::named("TestPlan", "Gui", "plan"))
            .expect("plan");
        let collector = tree
            .insert_child(
                plan,
                TestElement::named(
                    "org.apache.jmeter.reporters.ResultCollector",
                    "SimpleDataWriter",
                    "qualified listener",
                ),
            )
            .expect("qualified listener");
        tree.insert_child(plan, TestElement::named("DebugSampler", "Gui", "sample"))
            .expect("sampler");

        let compiled = ScopeCompiler::builtins()
            .compile(&tree)
            .expect("qualified collector");
        assert_eq!(compiled.run_collectors().len(), 1);
        assert_eq!(compiled.run_collectors()[0].node_id, collector);
    }

    #[test]
    fn run_owned_collectors_are_subject_to_metadata_limits() {
        let mut tree = ElementTree::new();
        let plan = tree
            .insert_root(TestElement::named("TestPlan", "Gui", "plan"))
            .expect("plan");
        tree.insert_child(
            plan,
            TestElement::named("ResultCollector", "SimpleDataWriter", "collector"),
        )
        .expect("collector");
        let compiler =
            ScopeCompiler::new(ComponentRegistry::builtins(), ScopeLimits::new(32, 1, 16));
        assert!(matches!(
            compiler.compile(&tree),
            Err(ScopeCompileError::ByteLimit { .. })
        ));
    }

    #[test]
    fn non_executable_listener_owner_cannot_hide_a_sampler() {
        let mut tree = ElementTree::new();
        let plan = tree
            .insert_root(TestElement::named("TestPlan", "Gui", "plan"))
            .expect("plan");
        let listener = tree
            .insert_child(
                plan,
                TestElement::named("CapturingListener", "Gui", "listener"),
            )
            .expect("listener");
        tree.insert_child(
            listener,
            TestElement::named("DebugSampler", "Gui", "sample"),
        )
        .expect("sampler");
        let mut components = ComponentRegistry::builtins();
        components.register_native(
            "CapturingListener",
            ComponentCategory::Listener,
            "runtime.listener.test",
        );
        let error = ScopeCompiler::new(components, ScopeLimits::default())
            .compile(&tree)
            .expect_err("listener cannot own a sampler");
        assert!(matches!(error, ScopeCompileError::CategoryMisuse { .. }));
    }

    #[test]
    fn missing_factory_is_a_typed_capability_error() {
        let mut tree = ElementTree::new();
        tree.insert_root(TestElement::named("DebugSampler", "Gui", "sample"))
            .expect("sampler");
        let error = ScopeCompiler::builtins()
            .compile_with_factories(&tree, &ComponentFactoryRegistry::default())
            .expect_err("missing factory");
        assert_eq!(error.code(), "runtime.scope.factory");
        assert!(matches!(
            error,
            ScopeCompileError::Factory {
                source: ScopeFactoryError::MissingFactory { .. }
            }
        ));
    }

    struct SamplerHook;

    impl ScopeComponentFactory for SamplerHook {
        fn create(
            &self,
            _component: &ScopeComponent,
        ) -> Result<FactoryComponent, ScopeFactoryError> {
            Ok(FactoryComponent::Sampler(Arc::new(
                UnsupportedSampler::new("test hook"),
            )))
        }
    }

    struct IdentityBoundSamplerHook;

    impl ScopeComponentFactory for IdentityBoundSamplerHook {
        fn create(
            &self,
            _component: &ScopeComponent,
        ) -> Result<FactoryComponent, ScopeFactoryError> {
            Ok(FactoryComponent::Sampler(Arc::new(
                UnsupportedSampler::new("identity test hook"),
            )))
        }

        fn test_class(&self) -> Option<&str> {
            Some("HTTPSamplerProxy")
        }
    }

    #[test]
    fn factory_registry_is_bounded_and_decodes_without_class_matching() {
        let mut registry = ComponentFactoryRegistry::with_capacity(1);
        registry
            .register("DebugSampler", Arc::new(SamplerHook))
            .expect("first hook");
        assert!(matches!(
            registry.register("OtherSampler", Arc::new(SamplerHook)),
            Err(ScopeFactoryError::RegistryLimit { limit: 1 })
        ));
        let mut tree = ElementTree::new();
        tree.insert_root(TestElement::named("DebugSampler", "Gui", "sample"))
            .expect("sampler");
        let packages = ScopeCompiler::builtins()
            .compile_with_factories(&tree, &registry)
            .expect("factory package");
        assert_eq!(packages.len(), 1);
    }

    #[test]
    fn registered_http_sampler_factory_is_selected_by_exact_class() {
        let mut tree = ElementTree::new();
        tree.insert_root(TestElement::named(
            "HTTPSamplerProxy",
            "HttpTestSampleGui",
            "http sample",
        ))
        .expect("http sampler");
        let mut factories = ComponentFactoryRegistry::default();
        factories
            .register("HTTPSamplerProxy", Arc::new(SamplerHook))
            .expect("http sampler factory");
        let packages = ScopeCompiler::builtins()
            .compile_with_factories(&tree, &factories)
            .expect("registered native sampler factory");
        assert_eq!(packages.len(), 1);
        let (sampler_id, package) = packages.iter().next().expect("http package");
        assert_eq!(package.sampler_id(), sampler_id);
        assert_eq!(
            tree.get(sampler_id)
                .expect("compiled sampler source")
                .value()
                .test_class(),
            "HTTPSamplerProxy"
        );
    }

    #[test]
    fn factory_identity_mismatch_is_rejected_before_component_creation() {
        let mut tree = ElementTree::new();
        let sampler = tree
            .insert_root(TestElement::named("DebugSampler", "Gui", "sample"))
            .expect("sampler");
        let mut factories = ComponentFactoryRegistry::default();
        factories
            .register("DebugSampler", Arc::new(IdentityBoundSamplerHook))
            .expect("identity-bound factory");
        let error = ScopeCompiler::builtins()
            .compile_with_factories(&tree, &factories)
            .expect_err("mismatched factory identity");
        assert!(matches!(
            error,
            ScopeCompileError::Factory {
                source: ScopeFactoryError::IdentityMismatch {
                    node_id,
                    expected,
                    actual,
                    ..
                }
            } if node_id == sampler
                && expected == "DebugSampler"
                && actual == "HTTPSamplerProxy"
        ));
    }

    #[test]
    fn factory_decoded_packages_do_not_share_components_across_users() {
        let mut tree = ElementTree::new();
        let sampler = tree
            .insert_root(TestElement::named("DebugSampler", "Gui", "sample"))
            .expect("sampler");
        let mut factories = ComponentFactoryRegistry::default();
        factories
            .register("DebugSampler", Arc::new(SamplerHook))
            .expect("sampler factory");
        let packages = ScopeCompiler::builtins()
            .compile_with_factories(&tree, &factories)
            .expect("factory package");
        let error = packages
            .clone_for_user()
            .expect_err("per-user factories must be explicit");
        assert!(matches!(
            error,
            crate::PackageCompileError::MissingFactory {
                sampler_id,
                component: "sampler"
            } if sampler_id == sampler
        ));
    }

    fn timer_tree(test_class: &str, properties: &[(&str, PropertyValue)]) -> ElementTree {
        let mut tree = ElementTree::new();
        let plan = tree
            .insert_root(TestElement::named("TestPlan", "Gui", "plan"))
            .expect("plan");
        let group = tree
            .insert_child(plan, TestElement::named("ThreadGroup", "Gui", "group"))
            .expect("group");
        let timer = tree
            .insert_child(
                group,
                TestElement::named(test_class, "TestBeanGUI", "timer"),
            )
            .expect("timer");
        let element = tree.get_mut(timer).expect("timer node").value_mut();
        for (name, value) in properties {
            element.set_property(*name, value.clone());
        }
        tree.insert_child(group, TestElement::named("DebugSampler", "Gui", "sample"))
            .expect("sampler");
        tree
    }

    fn timer_factories() -> ComponentFactoryRegistry {
        let mut factories = ComponentFactoryRegistry::with_builtin_timers();
        factories
            .register("DebugSampler", Arc::new(SamplerHook))
            .expect("sampler factory");
        factories
    }

    fn assertion_factories() -> ComponentFactoryRegistry {
        let mut factories = ComponentFactoryRegistry::with_builtin_assertions();
        factories
            .register("DebugSampler", Arc::new(SamplerHook))
            .expect("sampler factory");
        factories
    }

    #[test]
    fn builtin_timer_factory_decodes_precise_timer_without_losing_properties() {
        let tree = timer_tree(
            "PreciseThroughputTimer",
            &[
                ("throughput", PropertyValue::double(100.0)),
                ("throughputPeriod", PropertyValue::integer(1)),
                ("duration", PropertyValue::long(1)),
                ("batchSize", PropertyValue::integer(1)),
                ("batchThreadDelay", PropertyValue::long(0)),
                ("exactLimit", PropertyValue::integer(0)),
                ("allowedThroughputSurplus", PropertyValue::double(1.0)),
                ("randomSeed", PropertyValue::long(17)),
            ],
        );
        let plan = ScopeCompiler::builtins().compile(&tree).expect("scope");
        let sampler = plan.iter().next().expect("sampler").1;
        assert_eq!(
            sampler.timer_nodes()[0].binding.test_class,
            "PreciseThroughputTimer"
        );
        let packages = ScopeCompiler::builtins()
            .compile_with_factories(&tree, &timer_factories())
            .expect("precise timer factory");
        assert_eq!(packages.len(), 1);
    }

    #[test]
    fn all_constant_throughput_modes_decode_from_jmeter_calc_mode() {
        for mode in 0..=4 {
            let tree = timer_tree(
                "ConstantThroughputTimer",
                &[
                    ("throughput", PropertyValue::double(60.0)),
                    ("calcMode", PropertyValue::integer(mode)),
                ],
            );
            ScopeCompiler::builtins()
                .compile_with_factories(&tree, &timer_factories())
                .expect("constant throughput mode");
        }
    }

    #[test]
    fn constant_throughput_mode_accepts_pinned_enum_and_legacy_display_names() {
        let cases = [
            ("ThisThreadOnly", ConstantThroughputMode::ThisThreadOnly),
            ("AllActiveThreads", ConstantThroughputMode::AllActiveThreads),
            (
                "AllActiveThreadsInCurrentThreadGroup",
                ConstantThroughputMode::AllActiveThreadsInCurrentThreadGroup,
            ),
            (
                "AllActiveThreads_Shared",
                ConstantThroughputMode::AllActiveThreadsShared,
            ),
            (
                "AllActiveThreadsInCurrentThreadGroup_Shared",
                ConstantThroughputMode::AllActiveThreadsInCurrentThreadGroupShared,
            ),
            ("this thread only", ConstantThroughputMode::ThisThreadOnly),
            (
                "all active threads",
                ConstantThroughputMode::AllActiveThreads,
            ),
            (
                "all active threads in current thread group",
                ConstantThroughputMode::AllActiveThreadsInCurrentThreadGroup,
            ),
            (
                "all active threads (shared)",
                ConstantThroughputMode::AllActiveThreadsShared,
            ),
            (
                "all active threads in current thread group (shared)",
                ConstantThroughputMode::AllActiveThreadsInCurrentThreadGroupShared,
            ),
        ];
        for (value, expected) in cases {
            assert_eq!(
                constant_throughput_mode_value(&PropertyValue::string(value)),
                Ok(expected),
                "calcMode value {value:?}"
            );
        }
        for (value, expected) in (0..=4).zip([
            ConstantThroughputMode::ThisThreadOnly,
            ConstantThroughputMode::AllActiveThreads,
            ConstantThroughputMode::AllActiveThreadsInCurrentThreadGroup,
            ConstantThroughputMode::AllActiveThreadsShared,
            ConstantThroughputMode::AllActiveThreadsInCurrentThreadGroupShared,
        ]) {
            assert_eq!(
                constant_throughput_mode_value(&PropertyValue::integer(value)),
                Ok(expected),
                "numeric calcMode value {value}"
            );
        }
        assert!(constant_throughput_mode_value(&PropertyValue::string("unknown")).is_err());
    }

    #[test]
    fn timer_property_validation_is_typed_and_fail_closed() {
        let tree = timer_tree(
            "ConstantTimer",
            &[("ConstantTimer.delay", PropertyValue::string("-1"))],
        );
        let error = ScopeCompiler::builtins()
            .compile_with_factories(&tree, &timer_factories())
            .expect_err("negative timer delay");
        assert!(matches!(
            error,
            ScopeCompileError::Factory {
                source: ScopeFactoryError::Decode {
                    category: ComponentCategory::Timer,
                    test_class,
                    ..
                }
            } if test_class == "ConstantTimer"
        ));
    }

    #[test]
    fn constant_throughput_rejects_non_wire_property_alias() {
        let tree = timer_tree(
            "ConstantThroughputTimer",
            &[(
                "ConstantThroughputTimer.throughput",
                PropertyValue::double(60.0),
            )],
        );
        let error = ScopeCompiler::builtins()
            .compile_with_factories(&tree, &timer_factories())
            .expect_err("non-wire timer property alias");
        assert!(matches!(
            error,
            ScopeCompileError::Factory {
                source: ScopeFactoryError::Decode {
                    category: ComponentCategory::Timer,
                    ..
                }
            }
        ));
    }

    #[test]
    fn factory_property_value_bound_is_enforced_before_decode() {
        let oversized = "x".repeat(MAX_FACTORY_PROPERTY_BYTES + 1);
        let tree = timer_tree(
            "ConstantTimer",
            &[("ConstantTimer.delay", PropertyValue::string(oversized))],
        );
        let error = ScopeCompiler::builtins()
            .compile_with_factories(&tree, &timer_factories())
            .expect_err("oversized timer property");
        assert!(matches!(
            error,
            ScopeCompileError::Factory {
                source: ScopeFactoryError::Decode {
                    category: ComponentCategory::Timer,
                    detail,
                    ..
                }
            } if detail.contains("4096")
        ));
    }

    #[test]
    fn factory_property_walk_bounds_total_nested_values() {
        let mut tree = timer_tree("ConstantTimer", &[]);
        let timer = tree
            .get_mut(NodeId::new(3))
            .expect("timer node")
            .value_mut();
        for index in 0..MAX_FACTORY_PROPERTY_COUNT {
            timer.set_property(
                format!("nested.{index}"),
                PropertyValue::collection(
                    (0..MAX_FACTORY_COLLECTION_ENTRIES)
                        .map(|_| PropertyValue::Null)
                        .collect(),
                ),
            );
        }
        let error = ScopeCompiler::builtins()
            .compile_with_factories(&tree, &timer_factories())
            .expect_err("nested property value walk must be bounded");
        assert!(matches!(
            error,
            ScopeCompileError::Factory {
                source: ScopeFactoryError::Decode {
                    category: ComponentCategory::Timer,
                    detail,
                    ..
                }
            } if detail.contains("16384")
        ));
    }

    #[test]
    fn recognized_native_candidate_is_typed_unavailable_until_implemented() {
        let mut tree = ElementTree::new();
        let plan = tree
            .insert_root(TestElement::named("TestPlan", "Gui", "plan"))
            .expect("plan");
        let group = tree
            .insert_child(plan, TestElement::named("ThreadGroup", "Gui", "group"))
            .expect("group");
        tree.insert_child(
            group,
            TestElement::named("UserParameters", "Gui", "parameters"),
        )
        .expect("user parameters");
        tree.insert_child(group, TestElement::named("DebugSampler", "Gui", "sample"))
            .expect("sample");
        let error = ScopeCompiler::builtins()
            .compile(&tree)
            .expect_err("native candidate has no implemented factory");
        assert!(matches!(
            error,
            ScopeCompileError::Unsupported(UnsupportedComponent {
                capability_id: Some(capability_id),
                external: false,
                ..
            }) if capability_id == "runtime.UserParameters"
        ));
    }

    #[test]
    fn native_timer_aliases_preserve_source_order_in_scope() {
        let mut tree = ElementTree::new();
        let plan = tree
            .insert_root(TestElement::named("TestPlan", "Gui", "plan"))
            .expect("plan");
        let group = tree
            .insert_child(plan, TestElement::named("ThreadGroup", "Gui", "group"))
            .expect("group");
        for (class, name) in [
            ("ConstantTimer", "first"),
            ("PreciseThroughputTimer", "second"),
        ] {
            let id = tree
                .insert_child(group, TestElement::named(class, "Gui", name))
                .expect("timer");
            if class == "PreciseThroughputTimer" {
                tree.get_mut(id)
                    .expect("precise timer")
                    .value_mut()
                    .set_property("throughput", PropertyValue::double(1.0));
            }
        }
        tree.insert_child(group, TestElement::named("DebugSampler", "Gui", "sample"))
            .expect("sampler");
        let plan = ScopeCompiler::builtins().compile(&tree).expect("scope");
        let timers = &plan.iter().next().expect("sampler").1.timers;
        assert_eq!(
            timers
                .iter()
                .map(|timer| timer.test_class.as_str())
                .collect::<Vec<_>>(),
            vec!["ConstantTimer", "PreciseThroughputTimer"]
        );
    }

    #[test]
    fn replacement_reference_is_checked_without_wrapping_negative_ids() {
        let mut tree = ElementTree::new();
        let module = tree
            .insert_root(TestElement::named("ModuleController", "Gui", "module"))
            .expect("module");
        tree.get_mut(module)
            .expect("module node")
            .value_mut()
            .set_temporary_property("runtime.replacement-node", PropertyValue::long(-1));
        let error = ScopeCompiler::builtins()
            .compile(&tree)
            .expect_err("negative target");
        assert_eq!(error.code(), "runtime.scope.invalid-test-class");
    }

    #[test]
    fn replacement_orphans_and_cycles_are_typed() {
        let mut orphan_tree = ElementTree::new();
        let orphan = orphan_tree
            .insert_root(TestElement::named("ModuleController", "Gui", "orphan"))
            .expect("orphan");
        orphan_tree
            .get_mut(orphan)
            .expect("orphan node")
            .value_mut()
            .set_temporary_property("runtime.replacement-node", PropertyValue::long(99));
        assert!(matches!(
            ScopeCompiler::builtins().compile(&orphan_tree),
            Err(ScopeCompileError::OrphanReference { path, .. }) if path == vec![orphan]
        ));

        let mut cycle_tree = ElementTree::new();
        let first = cycle_tree
            .insert_root(TestElement::named("ModuleController", "Gui", "first"))
            .expect("first");
        let second = cycle_tree
            .insert_child(
                first,
                TestElement::named("IncludeController", "Gui", "second"),
            )
            .expect("second");
        cycle_tree
            .get_mut(first)
            .expect("first node")
            .value_mut()
            .set_temporary_property(
                "runtime.replacement-node",
                PropertyValue::long(second.as_u64() as i64),
            );
        cycle_tree
            .get_mut(second)
            .expect("second node")
            .value_mut()
            .set_temporary_property(
                "runtime.replacement-node",
                PropertyValue::long(first.as_u64() as i64),
            );
        assert!(matches!(
            ScopeCompiler::builtins().compile(&cycle_tree),
            Err(ScopeCompileError::ReplacementCycle { path, .. }) if path == vec![first, second]
        ));
    }

    fn assertion_tree() -> (ElementTree, NodeId, Vec<NodeId>) {
        let mut tree = ElementTree::new();
        let sampler = tree
            .insert_root(TestElement::named("DebugSampler", "TestBeanGUI", "sample"))
            .expect("sampler");
        let response = tree
            .insert_child(
                sampler,
                TestElement::named("ResponseAssertion", "AssertionGui", "response"),
            )
            .expect("response assertion");
        let duration = tree
            .insert_child(
                sampler,
                TestElement::named("DurationAssertion", "DurationAssertionGui", "duration"),
            )
            .expect("duration assertion");
        let size = tree
            .insert_child(
                sampler,
                TestElement::named("SizeAssertion", "SizeAssertionGui", "size"),
            )
            .expect("size assertion");
        tree.get_mut(response)
            .expect("response node")
            .value_mut()
            .set_property(
                "Asserion.test_strings",
                PropertyValue::named_collection(vec![jmeter_rs_model::PropertyEntry::new(
                    "-1000000000",
                    PropertyValue::string("needle"),
                )]),
            );
        tree.get_mut(response)
            .expect("response node")
            .value_mut()
            .set_property("Assertion.test_type", PropertyValue::integer(2));
        tree.get_mut(response)
            .expect("response node")
            .value_mut()
            .set_property(
                "Assertion.test_field",
                PropertyValue::string("Assertion.response_data"),
            );
        tree.get_mut(response)
            .expect("response node")
            .value_mut()
            .set_property("Assertion.assume_success", PropertyValue::string("false"));
        tree.get_mut(duration)
            .expect("duration node")
            .value_mut()
            .set_property("DurationAssertion.duration", PropertyValue::string("1000"));
        tree.get_mut(size)
            .expect("size node")
            .value_mut()
            .set_property("SizeAssertion.size", PropertyValue::string("5"));
        tree.get_mut(size)
            .expect("size node")
            .value_mut()
            .set_property("SizeAssertion.operator", PropertyValue::integer(1));
        tree.get_mut(size)
            .expect("size node")
            .value_mut()
            .set_property(
                "Assertion.test_field",
                PropertyValue::string("SizeAssertion.response_data"),
            );
        (tree, sampler, vec![response, duration, size])
    }

    #[test]
    fn assertion_scope_preserves_source_order_paths_and_absent_empty_properties() {
        let (mut tree, sampler, assertion_ids) = assertion_tree();
        tree.get_mut(assertion_ids[1])
            .expect("duration node")
            .value_mut()
            .set_property("Assertion.custom_message", PropertyValue::string(""));
        let plan = ScopeCompiler::builtins().compile(&tree).expect("scope");
        let package = plan.get(sampler).expect("sampler package");
        assert_eq!(
            package
                .assertion_nodes()
                .iter()
                .map(|component| component.element.test_class())
                .collect::<Vec<_>>(),
            vec!["ResponseAssertion", "DurationAssertion", "SizeAssertion"]
        );
        assert_eq!(
            package
                .assertion_nodes()
                .iter()
                .map(|component| component.path.clone())
                .collect::<Vec<_>>(),
            assertion_ids
                .iter()
                .map(|id| vec![sampler, *id])
                .collect::<Vec<_>>()
        );
        let response = &package.assertion_nodes()[0].element;
        assert!(matches!(
            response.property("Asserion.test_strings"),
            Some(PropertyValue::NamedCollection(values)) if values.len() == 1
        ));
        let duration = &package.assertion_nodes()[1].element;
        assert_eq!(
            duration.property("Assertion.custom_message"),
            Some(&PropertyValue::string(""))
        );
        assert!(
            package.assertion_nodes()[2]
                .element
                .property("Assertion.custom_message")
                .is_none(),
            "an absent property must not become an empty string"
        );
    }

    #[test]
    fn built_in_assertion_factories_decode_wire_properties_in_order() {
        let (tree, sampler, _) = assertion_tree();
        let factories = assertion_factories();
        let packages = ScopeCompiler::builtins()
            .compile_with_factories(&tree, &factories)
            .expect("native assertions decode");
        let package = packages.get(sampler).expect("compiled package");
        assert_eq!(package.assertions().len(), 3);
    }

    #[test]
    fn recognized_native_assertion_without_a_registered_factory_is_missing_capability() {
        let (tree, _sampler, _) = assertion_tree();
        let mut factories = ComponentFactoryRegistry::default();
        factories
            .register("DebugSampler", Arc::new(SamplerHook))
            .expect("sampler hook");
        let error = ScopeCompiler::builtins()
            .compile_with_factories(&tree, &factories)
            .expect_err("assertion factory must be explicit");
        assert!(matches!(
            error,
            ScopeCompileError::Factory {
                source: ScopeFactoryError::MissingFactory {
                    category: ComponentCategory::Assertion,
                    test_class,
                    ..
                }
            } if test_class == "ResponseAssertion"
        ));
    }

    #[test]
    fn disabled_assertion_is_retained_without_decoding_or_loss() {
        let (mut tree, sampler, assertion_ids) = assertion_tree();
        let disabled = tree
            .insert_child(
                sampler,
                TestElement::named("ResponseAssertion", "AssertionGui", "disabled"),
            )
            .expect("disabled assertion");
        tree.get_mut(disabled)
            .expect("disabled node")
            .value_mut()
            .set_enabled(false);
        tree.get_mut(disabled)
            .expect("disabled node")
            .value_mut()
            .set_property("Assertion.test_type", PropertyValue::string("not-an-int"));
        tree.get_mut(disabled)
            .expect("disabled node")
            .value_mut()
            .set_property("Asserion.test_strings", PropertyValue::string("opaque"));

        let factories = assertion_factories();
        let plan = ScopeCompiler::builtins()
            .compile(&tree)
            .expect("disabled assertion is retained");
        assert!(plan.disabled_ids().contains(&disabled));
        let packages = ScopeCompiler::builtins()
            .compile_with_factories(&tree, &factories)
            .expect("disabled assertion is not decoded");
        let package = packages.get(sampler).expect("compiled package");
        assert_eq!(package.assertions().len(), assertion_ids.len());
        assert!(
            tree.get(disabled)
                .expect("source node")
                .value()
                .property("Assertion.test_type")
                .is_some()
        );
    }

    #[test]
    fn malformed_enabled_assertion_is_a_typed_decode_error() {
        let (mut tree, sampler, assertion_ids) = assertion_tree();
        tree.get_mut(assertion_ids[0])
            .expect("response node")
            .value_mut()
            .set_property("Assertion.test_type", PropertyValue::integer(0));
        let factories = assertion_factories();
        let error = ScopeCompiler::builtins()
            .compile_with_factories(&tree, &factories)
            .expect_err("invalid test type");
        assert!(matches!(
            error,
            ScopeCompileError::Factory {
                source: ScopeFactoryError::Decode {
                    node_id,
                    path,
                    test_class,
                    category: ComponentCategory::Assertion,
                    ..
                }
            } if node_id == assertion_ids[0]
                && path == vec![sampler, assertion_ids[0]]
                && test_class == "ResponseAssertion"
        ));
    }

    #[test]
    fn unknown_or_unsupported_assertion_properties_fail_closed() {
        let (mut tree, sampler, assertion_ids) = assertion_tree();
        tree.get_mut(assertion_ids[1])
            .expect("duration node")
            .value_mut()
            .set_property(
                "DurationAssertion.plugin_extension",
                PropertyValue::string("x"),
            );
        let factories = assertion_factories();
        let error = ScopeCompiler::builtins()
            .compile_with_factories(&tree, &factories)
            .expect_err("unknown property");
        assert!(matches!(
            error,
            ScopeCompileError::Factory {
                source: ScopeFactoryError::Decode {
                    node_id,
                    category: ComponentCategory::Assertion,
                    ..
                }
            } if node_id == assertion_ids[1]
        ));

        tree.get_mut(assertion_ids[1])
            .expect("duration node")
            .value_mut()
            .properties
            .remove("DurationAssertion.plugin_extension");
        tree.get_mut(assertion_ids[0])
            .expect("response node")
            .value_mut()
            .set_property("Assertion.scope", PropertyValue::string("children"));
        let error = ScopeCompiler::builtins()
            .compile_with_factories(&tree, &factories)
            .expect_err("unsupported result scope");
        assert!(matches!(
            error,
            ScopeCompileError::Factory {
                source: ScopeFactoryError::Decode {
                    node_id,
                    category: ComponentCategory::Assertion,
                    ..
                }
            } if node_id == assertion_ids[0]
        ));
        assert_eq!(tree.get(sampler).expect("sampler").value().name(), "sample");
    }

    #[test]
    fn unsupported_assertion_families_are_typed_and_enabled_unknowns_fail_closed() {
        let mut tree = ElementTree::new();
        let sampler = tree
            .insert_root(TestElement::named("DebugSampler", "TestBeanGUI", "sample"))
            .expect("sampler");
        for class in [
            "JSONPathAssertion",
            "JMESPathAssertion",
            "BeanShellAssertion",
        ] {
            tree.insert_child(sampler, TestElement::named(class, "AssertionGui", class))
                .expect("assertion");
        }
        let error = ScopeCompiler::builtins()
            .compile(&tree)
            .expect_err("provider-backed assertions must remain external");
        assert!(matches!(
            error,
            ScopeCompileError::Unsupported(UnsupportedComponent {
                capability_id: Some(capability_id),
                external: true,
                ..
            }) if capability_id == "assertion.json"
        ));

        for id in [NodeId::new(2), NodeId::new(3), NodeId::new(4)] {
            tree.get_mut(id)
                .expect("provider assertion")
                .value_mut()
                .set_enabled(false);
        }

        let unknown = tree
            .insert_child(
                sampler,
                TestElement::named("com.example.PluginAssertion", "PluginGui", "plugin"),
            )
            .expect("unknown assertion");
        let error = ScopeCompiler::builtins()
            .compile(&tree)
            .expect_err("unknown enabled assertion");
        assert!(matches!(
            error,
            ScopeCompileError::Unsupported(UnsupportedComponent { node_id, path, .. })
                if node_id == unknown && path == vec![sampler, unknown]
        ));
    }

    #[test]
    fn assertion_components_count_toward_package_bounds() {
        let (tree, _, _) = assertion_tree();
        let compiler = ScopeCompiler::new(
            ComponentRegistry::builtins(),
            ScopeLimits::new(2, 4_096, 16),
        );
        assert!(matches!(
            compiler.compile(&tree),
            Err(ScopeCompileError::ComponentLimit { .. })
        ));
    }
}
