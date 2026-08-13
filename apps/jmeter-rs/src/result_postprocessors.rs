// SPDX-License-Identifier: Apache-2.0
//! Isolated native implementations for the pinned result postprocessors.
//!
//! This module is intentionally not registered by the application yet.  It is
//! the exact decoder/runtime seam for the ELEM-008 tranche: callers provide a
//! [`ScopeComponent`] and receive the DebugPostProcessor, which publishes only
//! typed [`jmeter_rs_runtime::InvocationDelta`] values.  No listener
//! implementation, global properties, system properties, or ambient sampler
//! state is inferred here.  The latter two DebugPostProcessor views must be
//! supplied explicitly by the caller and otherwise fail closed.  ResultAction
//! is retained as a decode-only wire vocabulary: the pinned JMeter class is a
//! `SampleListener`, so its ordered listener effects are intentionally pending
//! the separate listener architecture and are not exposed as a postprocessor.
//! The source comparison is pinned to Apache JMeter commit
//! `34a2785748e9e0b14702595e8682c387869deda3` (rel/v5.6.3).

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;
use std::future;
use std::sync::Arc;

use jmeter_rs_model::{PropertyValue, TestElement};
use jmeter_rs_results::{DataType, SampleData, SampleResult};
use jmeter_rs_runtime::{
    ComponentCategory, ComponentError, ComponentFuture, FactoryComponent, InvocationDelta,
    MutationError, MutationErrorCode, Postprocessor, PostprocessorFactory, ResultPatch,
    SampleContext, ScopeComponent, ScopeComponentFactory, ScopeFactoryError,
};

/// The short SaveService alias accepted for DebugPostProcessor.
pub const DEBUG_POSTPROCESSOR_SHORT_CLASS: &str = "DebugPostProcessor";
/// The fully-qualified class accepted for DebugPostProcessor.
pub const DEBUG_POSTPROCESSOR_CLASS: &str = "org.apache.jmeter.extractor.DebugPostProcessor";
/// The exact DebugPostProcessor test-class allowlist.
pub const DEBUG_POSTPROCESSOR_TEST_CLASSES: &[&str] =
    &[DEBUG_POSTPROCESSOR_SHORT_CLASS, DEBUG_POSTPROCESSOR_CLASS];
/// The exact short GUI alias accepted by the pinned source fixture.
pub const TEST_BEAN_GUI: &str = "TestBeanGUI";
/// The exact fully-qualified TestBeanGUI class accepted by native callers.
pub const TEST_BEAN_GUI_CLASS: &str = "org.apache.jmeter.testbeans.gui.TestBeanGUI";
/// The exact DebugPostProcessor GUI allowlist.
pub const DEBUG_POSTPROCESSOR_GUI_CLASSES: &[&str] = &[TEST_BEAN_GUI, TEST_BEAN_GUI_CLASS];

/// The short SaveService alias accepted for ResultAction.
pub const RESULT_ACTION_SHORT_CLASS: &str = "ResultAction";
/// The fully-qualified class accepted for ResultAction.
pub const RESULT_ACTION_CLASS: &str = "org.apache.jmeter.reporters.ResultAction";
/// The exact ResultAction test-class allowlist.
pub const RESULT_ACTION_TEST_CLASSES: &[&str] = &[RESULT_ACTION_SHORT_CLASS, RESULT_ACTION_CLASS];
/// The exact short ResultAction GUI alias.
pub const RESULT_ACTION_GUI: &str = "ResultActionGui";
/// The exact fully-qualified ResultAction GUI class.
pub const RESULT_ACTION_GUI_CLASS: &str = "org.apache.jmeter.reporters.gui.ResultActionGui";
/// The exact ResultAction GUI allowlist.
pub const RESULT_ACTION_GUI_CLASSES: &[&str] = &[RESULT_ACTION_GUI, RESULT_ACTION_GUI_CLASS];

/// DebugPostProcessor's supported persistent property names.
pub const DEBUG_PROPERTY_DISPLAY_JMETER_PROPERTIES: &str = "displayJMeterProperties";
/// DebugPostProcessor's supported persistent property name.
pub const DEBUG_PROPERTY_DISPLAY_JMETER_VARIABLES: &str = "displayJMeterVariables";
/// DebugPostProcessor's supported persistent property name.
pub const DEBUG_PROPERTY_DISPLAY_SYSTEM_PROPERTIES: &str = "displaySystemProperties";
/// DebugPostProcessor's supported persistent property name.
pub const DEBUG_PROPERTY_DISPLAY_SAMPLER_PROPERTIES: &str = "displaySamplerProperties";
/// ResultAction's exact upstream integer property name.
pub const RESULT_ACTION_PROPERTY: &str = "OnError.action";

const DEBUG_DEFAULT_MAX_ENTRIES: usize = 64;
const DEBUG_DEFAULT_MAX_VALUE_BYTES: usize = 4 * 1024;
const DEBUG_DEFAULT_MAX_OUTPUT_BYTES: usize = 4 * 1024;
const DEBUG_MAX_OUTPUT_BYTES: usize = 64 * 1024;

/// Stable errors produced while decoding the native Debug element or the
/// decode-only ResultAction wire vocabulary.
///
/// Variants intentionally carry no source values.  This keeps malformed
/// properties and class-spoofing diagnostics bounded and safe to log.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NativeProcessorDecodeError {
    /// The test class is not one of the exact accepted aliases.
    ClassMismatch,
    /// The GUI class is not one of the exact accepted aliases.
    GuiClassMismatch,
    /// The source component category is not postprocessor.
    CategoryMismatch,
    /// A property is not in the element's closed schema.
    UnknownProperty,
    /// A property has a type other than its exact upstream type.
    PropertyTypeMismatch,
    /// An integer action is outside the pinned upstream action set.
    InvalidAction,
    /// A label or source field is oversized or contains controls.
    InvalidText,
    /// A configured source exceeds a native bound.
    Limit,
}

impl NativeProcessorDecodeError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ClassMismatch => "app.processor.class-mismatch",
            Self::GuiClassMismatch => "app.processor.gui-class-mismatch",
            Self::CategoryMismatch => "app.processor.category-mismatch",
            Self::UnknownProperty => "app.processor.unknown-property",
            Self::PropertyTypeMismatch => "app.processor.property-type-mismatch",
            Self::InvalidAction => "app.processor.invalid-action",
            Self::InvalidText => "app.processor.invalid-text",
            Self::Limit => "app.processor.limit",
        }
    }
}

impl fmt::Display for NativeProcessorDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for NativeProcessorDecodeError {}

/// Finite bounds applied to every DebugPostProcessor source and output.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DebugLimits {
    max_entries: usize,
    max_value_bytes: usize,
    max_output_bytes: usize,
}

impl Default for DebugLimits {
    fn default() -> Self {
        Self {
            max_entries: DEBUG_DEFAULT_MAX_ENTRIES,
            max_value_bytes: DEBUG_DEFAULT_MAX_VALUE_BYTES,
            max_output_bytes: DEBUG_DEFAULT_MAX_OUTPUT_BYTES,
        }
    }
}

impl DebugLimits {
    /// Creates explicit finite bounds within the runtime's native ceilings.
    pub fn try_new(
        max_entries: usize,
        max_value_bytes: usize,
        max_output_bytes: usize,
    ) -> Result<Self, NativeProcessorDecodeError> {
        if max_entries == 0
            || max_entries > DEBUG_DEFAULT_MAX_ENTRIES
            || max_value_bytes == 0
            || max_value_bytes > DEBUG_DEFAULT_MAX_VALUE_BYTES
            || max_output_bytes == 0
            || max_output_bytes > DEBUG_MAX_OUTPUT_BYTES
        {
            return Err(NativeProcessorDecodeError::Limit);
        }
        Ok(Self {
            max_entries,
            max_value_bytes,
            max_output_bytes,
        })
    }

    /// Returns the maximum number of entries in one debug map.
    #[must_use]
    pub const fn max_entries(self) -> usize {
        self.max_entries
    }

    /// Returns the maximum UTF-8 byte length of one key or value.
    #[must_use]
    pub const fn max_value_bytes(self) -> usize {
        self.max_value_bytes
    }

    /// Returns the maximum UTF-8 byte length of the generated response.
    #[must_use]
    pub const fn max_output_bytes(self) -> usize {
        self.max_output_bytes
    }
}

/// One explicit name/value property supplied to a DebugPostProcessor view.
///
/// The value remains private to prevent accidental debug/log disclosure.
/// [`DebugPostProcessor`] renders the value in its compatibility result, which
/// is a JMeter-visible `SampleResult` field rather than a diagnostic log.
#[derive(Clone, Eq, PartialEq)]
pub struct DebugProperty {
    name: String,
    value: String,
}

impl fmt::Debug for DebugProperty {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DebugProperty")
            .field("name_bytes", &self.name.len())
            .field("value_bytes", &self.value.len())
            .finish()
    }
}

impl DebugProperty {
    /// Creates one bounded, control-free debug property.
    pub fn try_new(
        name: impl Into<String>,
        value: impl Into<String>,
        limits: DebugLimits,
    ) -> Result<Self, NativeProcessorDecodeError> {
        let name = name.into();
        let value = value.into();
        if name.len() > limits.max_value_bytes
            || value.len() > limits.max_value_bytes
            || name.chars().any(char::is_control)
            || value.chars().any(char::is_control)
        {
            return Err(
                if name.len() > limits.max_value_bytes || value.len() > limits.max_value_bytes {
                    NativeProcessorDecodeError::Limit
                } else {
                    NativeProcessorDecodeError::InvalidText
                },
            );
        }
        Ok(Self { name, value })
    }

    /// Returns the exact property name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the exact property value for explicit caller rendering.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// Explicit sampler and system-property views for DebugPostProcessor.
///
/// `None` is different from an empty list: it means the caller did not grant
/// the corresponding capability and a requested view must fail closed.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct DebugPostProcessorSources {
    sampler_properties: Option<Vec<DebugProperty>>,
    system_properties: Option<Vec<DebugProperty>>,
}

impl fmt::Debug for DebugPostProcessorSources {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DebugPostProcessorSources")
            .field(
                "sampler_property_count",
                &self.sampler_properties.as_ref().map(Vec::len),
            )
            .field(
                "system_property_count",
                &self.system_properties.as_ref().map(Vec::len),
            )
            .finish()
    }
}

impl DebugPostProcessorSources {
    /// Creates an empty capability view; requested unavailable views fail.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sampler_properties: None,
            system_properties: None,
        }
    }

    /// Supplies the explicit sampler-property view.
    pub fn with_sampler_properties(
        mut self,
        values: impl IntoIterator<Item = DebugProperty>,
        limits: DebugLimits,
    ) -> Result<Self, NativeProcessorDecodeError> {
        self.sampler_properties = Some(bounded_properties(values, limits)?);
        Ok(self)
    }

    /// Supplies the explicit system-property view.
    pub fn with_system_properties(
        mut self,
        values: impl IntoIterator<Item = DebugProperty>,
        limits: DebugLimits,
    ) -> Result<Self, NativeProcessorDecodeError> {
        self.system_properties = Some(bounded_properties(values, limits)?);
        Ok(self)
    }

    /// Returns the explicit sampler-property view, when granted.
    #[must_use]
    pub fn sampler_properties(&self) -> Option<&[DebugProperty]> {
        self.sampler_properties.as_deref()
    }

    /// Returns the explicit system-property view, when granted.
    #[must_use]
    pub fn system_properties(&self) -> Option<&[DebugProperty]> {
        self.system_properties.as_deref()
    }
}

fn bounded_properties(
    values: impl IntoIterator<Item = DebugProperty>,
    limits: DebugLimits,
) -> Result<Vec<DebugProperty>, NativeProcessorDecodeError> {
    let mut bounded = Vec::new();
    for value in values {
        if bounded.len() >= limits.max_entries {
            return Err(NativeProcessorDecodeError::Limit);
        }
        if value.name.len() > limits.max_value_bytes
            || value.value.len() > limits.max_value_bytes
            || value.name.chars().any(char::is_control)
            || value.value.chars().any(char::is_control)
        {
            return Err(
                if value.name.len() > limits.max_value_bytes
                    || value.value.len() > limits.max_value_bytes
                {
                    NativeProcessorDecodeError::Limit
                } else {
                    NativeProcessorDecodeError::InvalidText
                },
            );
        }
        bounded.push(value);
    }
    Ok(bounded)
}

/// Decoded DebugPostProcessor configuration.
#[derive(Clone, Eq, PartialEq)]
pub struct DebugPostProcessorConfig {
    label: String,
    display_jmeter_properties: bool,
    display_jmeter_variables: bool,
    display_system_properties: bool,
    display_sampler_properties: bool,
    limits: DebugLimits,
    sources: DebugPostProcessorSources,
}

impl fmt::Debug for DebugPostProcessorConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DebugPostProcessorConfig")
            .field("label_bytes", &self.label.len())
            .field("display_jmeter_properties", &self.display_jmeter_properties)
            .field("display_jmeter_variables", &self.display_jmeter_variables)
            .field("display_system_properties", &self.display_system_properties)
            .field(
                "display_sampler_properties",
                &self.display_sampler_properties,
            )
            .field("limits", &self.limits)
            .field("sources", &self.sources)
            .finish()
    }
}

impl DebugPostProcessorConfig {
    /// Creates the upstream-default configuration for one label.
    pub fn new(label: impl Into<String>) -> Result<Self, NativeProcessorDecodeError> {
        let label = label.into();
        let limits = DebugLimits::default();
        validate_text(&label, limits.max_value_bytes)?;
        Ok(Self {
            label,
            // These defaults match DebugPostProcessor's TestBean defaults.
            display_jmeter_properties: false,
            display_jmeter_variables: true,
            display_system_properties: false,
            display_sampler_properties: true,
            limits,
            sources: DebugPostProcessorSources::new(),
        })
    }

    /// Decodes an exact DebugPostProcessor TestElement.
    pub fn from_test_element(element: &TestElement) -> Result<Self, NativeProcessorDecodeError> {
        validate_element_identity(
            element,
            DEBUG_POSTPROCESSOR_TEST_CLASSES,
            DEBUG_POSTPROCESSOR_GUI_CLASSES,
        )?;
        let mut config = Self::new(element.name())?;
        for property in element.properties.iter() {
            let value = match property.name.as_str() {
                DEBUG_PROPERTY_DISPLAY_JMETER_PROPERTIES => property_bool(property.value.clone())?,
                DEBUG_PROPERTY_DISPLAY_JMETER_VARIABLES => property_bool(property.value.clone())?,
                DEBUG_PROPERTY_DISPLAY_SYSTEM_PROPERTIES => property_bool(property.value.clone())?,
                DEBUG_PROPERTY_DISPLAY_SAMPLER_PROPERTIES => property_bool(property.value.clone())?,
                _ => return Err(NativeProcessorDecodeError::UnknownProperty),
            };
            match property.name.as_str() {
                DEBUG_PROPERTY_DISPLAY_JMETER_PROPERTIES => {
                    config.display_jmeter_properties = value;
                }
                DEBUG_PROPERTY_DISPLAY_JMETER_VARIABLES => {
                    config.display_jmeter_variables = value;
                }
                DEBUG_PROPERTY_DISPLAY_SYSTEM_PROPERTIES => {
                    config.display_system_properties = value;
                }
                DEBUG_PROPERTY_DISPLAY_SAMPLER_PROPERTIES => {
                    config.display_sampler_properties = value;
                }
                _ => return Err(NativeProcessorDecodeError::UnknownProperty),
            }
        }
        Ok(config)
    }

    /// Returns the bounded display label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Returns the JMeter-property display flag.
    #[must_use]
    pub const fn display_jmeter_properties(&self) -> bool {
        self.display_jmeter_properties
    }

    /// Returns the JMeter-variable display flag.
    #[must_use]
    pub const fn display_jmeter_variables(&self) -> bool {
        self.display_jmeter_variables
    }

    /// Returns the system-property display flag.
    #[must_use]
    pub const fn display_system_properties(&self) -> bool {
        self.display_system_properties
    }

    /// Returns the sampler-property display flag.
    #[must_use]
    pub const fn display_sampler_properties(&self) -> bool {
        self.display_sampler_properties
    }

    /// Returns the configured output bounds.
    #[must_use]
    pub const fn limits(&self) -> DebugLimits {
        self.limits
    }

    /// Returns the explicit property capability view.
    #[must_use]
    pub fn sources(&self) -> &DebugPostProcessorSources {
        &self.sources
    }

    /// Replaces the finite output bounds.
    #[must_use]
    pub fn with_limits(mut self, limits: DebugLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Replaces the explicit sampler/system property capability view.
    #[must_use]
    pub fn with_sources(mut self, sources: DebugPostProcessorSources) -> Self {
        self.sources = sources;
        self
    }
}

fn property_bool(value: PropertyValue) -> Result<bool, NativeProcessorDecodeError> {
    match value {
        PropertyValue::Boolean(value) => Ok(value),
        _ => Err(NativeProcessorDecodeError::PropertyTypeMismatch),
    }
}

fn validate_text(value: &str, maximum: usize) -> Result<(), NativeProcessorDecodeError> {
    if value.len() > maximum {
        return Err(NativeProcessorDecodeError::Limit);
    }
    if value.chars().any(char::is_control) {
        return Err(NativeProcessorDecodeError::InvalidText);
    }
    Ok(())
}

fn validate_element_identity(
    element: &TestElement,
    classes: &[&str],
    guis: &[&str],
) -> Result<(), NativeProcessorDecodeError> {
    if !classes.contains(&element.test_class()) {
        return Err(NativeProcessorDecodeError::ClassMismatch);
    }
    if !guis.contains(&element.gui_class()) {
        return Err(NativeProcessorDecodeError::GuiClassMismatch);
    }
    Ok(())
}

/// A scope factory and per-user factory for DebugPostProcessor.
#[derive(Clone)]
pub struct DebugPostProcessorFactory {
    config: DebugPostProcessorConfig,
}

impl fmt::Debug for DebugPostProcessorFactory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DebugPostProcessorFactory")
            .field("config", &self.config)
            .finish()
    }
}

impl DebugPostProcessorFactory {
    /// Creates a factory from an already-decoded configuration.
    #[must_use]
    pub fn new(config: DebugPostProcessorConfig) -> Self {
        Self { config }
    }

    /// Decodes and creates a factory from one exact source element.
    pub fn from_test_element(element: &TestElement) -> Result<Self, NativeProcessorDecodeError> {
        DebugPostProcessorConfig::from_test_element(element).map(Self::new)
    }

    /// Returns the factory's immutable configuration template.
    #[must_use]
    pub fn config(&self) -> &DebugPostProcessorConfig {
        &self.config
    }
}

impl PostprocessorFactory for DebugPostProcessorFactory {
    fn create(&self) -> Arc<dyn Postprocessor> {
        Arc::new(DebugPostProcessor::new(self.config.clone()))
    }
}

impl ScopeComponentFactory for DebugPostProcessorFactory {
    fn create(&self, component: &ScopeComponent) -> Result<FactoryComponent, ScopeFactoryError> {
        if component.binding.category != ComponentCategory::Postprocessor {
            return Err(scope_decode(
                component,
                NativeProcessorDecodeError::CategoryMismatch,
            ));
        }
        if component.binding.test_class != component.element.test_class()
            || !DEBUG_POSTPROCESSOR_TEST_CLASSES.contains(&component.binding.test_class.as_str())
        {
            return Err(scope_decode(
                component,
                NativeProcessorDecodeError::ClassMismatch,
            ));
        }
        let mut config = DebugPostProcessorConfig::from_test_element(&component.element)
            .map_err(|error| scope_decode(component, error))?;
        config.limits = self.config.limits;
        config.sources = self.config.sources.clone();
        Ok(FactoryComponent::Postprocessor(Arc::new(
            DebugPostProcessor::new(config),
        )))
    }
}

/// A bounded native DebugPostProcessor implementation.
pub struct DebugPostProcessor {
    config: DebugPostProcessorConfig,
}

impl fmt::Debug for DebugPostProcessor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DebugPostProcessor")
            .field("config", &self.config)
            .finish()
    }
}

impl DebugPostProcessor {
    /// Creates one isolated processor instance.
    #[must_use]
    pub fn new(config: DebugPostProcessorConfig) -> Self {
        Self { config }
    }

    /// Returns the immutable processor configuration.
    #[must_use]
    pub fn config(&self) -> &DebugPostProcessorConfig {
        &self.config
    }
}

impl Postprocessor for DebugPostProcessor {
    fn process<'a>(&'a self, context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, ()> {
        Box::pin(future::ready(process_debug(&self.config, context)))
    }
}

fn process_debug(
    config: &DebugPostProcessorConfig,
    context: &mut SampleContext<'_>,
) -> Result<(), ComponentError> {
    let snapshot = context.snapshot_processor_invocation();
    let Some(parent) = snapshot.result().cloned() else {
        return Err(ComponentError::failure(
            "debug-postprocessor.result-required",
        ));
    };

    if config.display_sampler_properties && config.sources.sampler_properties.is_none() {
        return Err(ComponentError::unsupported(
            "debug-postprocessor.sampler-properties-unavailable",
        ));
    }
    if config.display_system_properties && config.sources.system_properties.is_none() {
        return Err(ComponentError::unsupported(
            "debug-postprocessor.system-properties-unavailable",
        ));
    }

    // JMeter starts the child result before collecting the requested views and
    // ends it after all fields have been populated.  The clock is injected so
    // this remains deterministic and never reads ambient wall time.
    let start = context.execution().capabilities().clock().now();
    let mut child = SampleResult::new(config.label.clone());
    child
        .sample_start_at(start.wall)
        .map_err(|_| ComponentError::failure("debug-postprocessor.child-timing"))?;
    let mut response = String::new();
    let mut sampler_data = String::new();
    if config.display_sampler_properties {
        append_section(
            &mut response,
            &mut sampler_data,
            "SamplerProperties",
            config.sources.sampler_properties.as_deref().unwrap_or(&[]),
            config.limits,
        )?;
    }
    if config.display_jmeter_variables {
        append_section_map(
            &mut response,
            &mut sampler_data,
            "JMeterVariables",
            snapshot.variables(),
            config.limits,
        )?;
    }
    if config.display_jmeter_properties {
        append_section_map(
            &mut response,
            &mut sampler_data,
            "JMeterProperties",
            snapshot.properties(),
            config.limits,
        )?;
    }
    if config.display_system_properties {
        append_section(
            &mut response,
            &mut sampler_data,
            "SystemProperties",
            config.sources.system_properties.as_deref().unwrap_or(&[]),
            config.limits,
        )?;
    }

    child.set_thread_name(Some(context.execution().thread().name().to_owned()));
    child.set_group_threads(parent.group_threads());
    child.set_all_threads(parent.all_threads());
    child.set_response_data(Some(SampleData::from(response.into_bytes())));
    child.set_data_type(Some(DataType::Text));
    child.set_sampler_data_text(sampler_data);
    child.set_response_code_text("200");
    child.set_response_message_text("OK");
    child.set_successful(true);
    let end = context.execution().capabilities().clock().now();
    child
        .sample_end_at(end.wall)
        .map_err(|_| ComponentError::failure("debug-postprocessor.child-timing"))?;

    let mut replacement = parent;
    replacement
        .append_sub_result(child)
        .map_err(|_| ComponentError::failure("debug-postprocessor.sub-result"))?;
    let mut delta = InvocationDelta::new(snapshot.generation());
    delta.set_result_patch(ResultPatch::replace(Some(replacement)));
    context
        .apply_invocation_delta(&delta)
        .map(|_| ())
        .map_err(|error| mutation_component_error(error, "debug-postprocessor.delta"))
}

fn append_section(
    response: &mut String,
    sampler_data: &mut String,
    label: &str,
    values: &[DebugProperty],
    limits: DebugLimits,
) -> Result<(), ComponentError> {
    append_text(response, label, limits.max_output_bytes())?;
    append_text(response, ":\n", limits.max_output_bytes())?;
    append_text(sampler_data, label, limits.max_output_bytes())?;
    append_text(sampler_data, "\n", limits.max_output_bytes())?;
    let entries = values
        .iter()
        .map(|value| (value.name.clone(), value.value.clone()));
    append_entries(response, entries, limits)?;
    append_text(response, "\n", limits.max_output_bytes())
}

fn append_section_map(
    response: &mut String,
    sampler_data: &mut String,
    label: &str,
    values: &BTreeMap<String, String>,
    limits: DebugLimits,
) -> Result<(), ComponentError> {
    append_text(response, label, limits.max_output_bytes())?;
    append_text(response, ":\n", limits.max_output_bytes())?;
    append_text(sampler_data, label, limits.max_output_bytes())?;
    append_text(sampler_data, "\n", limits.max_output_bytes())?;
    append_entries(
        response,
        values
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
        limits,
    )?;
    append_text(response, "\n", limits.max_output_bytes())
}

fn append_entries(
    response: &mut String,
    values: impl IntoIterator<Item = (String, String)>,
    limits: DebugLimits,
) -> Result<(), ComponentError> {
    let mut by_name = BTreeMap::new();
    let mut input_count = 0usize;
    for (name, value) in values {
        input_count = input_count
            .checked_add(1)
            .ok_or_else(|| ComponentError::resource_limit("debug-postprocessor.entry-overflow"))?;
        if input_count > limits.max_entries {
            return Err(ComponentError::resource_limit(
                "debug-postprocessor.entry-limit",
            ));
        }
        validate_text(&name, limits.max_value_bytes).map_err(debug_text_component_error)?;
        validate_text(&value, limits.max_value_bytes).map_err(debug_text_component_error)?;
        // DebugPostProcessor's property-iterator formatter first collapses
        // duplicate names through a map; the last source value wins.
        by_name.insert(name, value);
    }
    let mut entries: Vec<_> = by_name.into_iter().collect();
    let mut formatted_bytes = 0usize;
    for (name, value) in &entries {
        formatted_bytes = formatted_bytes
            .checked_add(name.len())
            .and_then(|size| size.checked_add(2))
            .and_then(|size| size.checked_add(value.len()))
            .ok_or_else(|| ComponentError::resource_limit("debug-postprocessor.output-overflow"))?;
        if formatted_bytes > limits.max_output_bytes() {
            return Err(ComponentError::resource_limit(
                "debug-postprocessor.output-limit",
            ));
        }
    }
    entries.sort_by(|left, right| alpha_numeric_cmp(&left.0, &right.0));
    for (name, value) in entries {
        append_text(response, &name, limits.max_output_bytes())?;
        append_text(response, "=", limits.max_output_bytes())?;
        append_text(response, &value, limits.max_output_bytes())?;
        append_text(response, "\n", limits.max_output_bytes())?;
    }
    Ok(())
}

fn append_text(target: &mut String, value: &str, maximum: usize) -> Result<(), ComponentError> {
    let next = target
        .len()
        .checked_add(value.len())
        .ok_or_else(|| ComponentError::resource_limit("debug-postprocessor.output-overflow"))?;
    if next > maximum {
        return Err(ComponentError::resource_limit(
            "debug-postprocessor.output-limit",
        ));
    }
    target.push_str(value);
    Ok(())
}

fn debug_text_component_error(error: NativeProcessorDecodeError) -> ComponentError {
    match error {
        NativeProcessorDecodeError::Limit => {
            ComponentError::resource_limit("debug-postprocessor.property-text-limit")
        }
        _ => ComponentError::failure("debug-postprocessor.property-text"),
    }
}

fn alpha_numeric_cmp(left: &str, right: &str) -> Ordering {
    let left_chunks = alpha_chunks(left);
    let right_chunks = alpha_chunks(right);
    for (left_chunk, right_chunk) in left_chunks.iter().zip(right_chunks.iter()) {
        let ordering = match (left_chunk.0, right_chunk.0) {
            (true, true) => compare_digit_chunks(left_chunk.1, right_chunk.1),
            (false, false) => java_string_cmp(left_chunk.1, right_chunk.1),
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
        };
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    left_chunks.len().cmp(&right_chunks.len())
}

fn java_string_cmp(left: &str, right: &str) -> Ordering {
    // `String.compareTo` in the pinned comparator compares UTF-16 code units;
    // Rust's byte-wise `str::cmp` differs for supplementary code points.
    left.encode_utf16().cmp(right.encode_utf16())
}

fn alpha_chunks(value: &str) -> Vec<(bool, &str)> {
    let mut chunks = Vec::new();
    let mut chars = value.char_indices();
    let Some((_, first)) = chars.next() else {
        return chunks;
    };
    let mut start = 0;
    let mut digit = first.is_ascii_digit();
    for (index, character) in chars {
        let character_digit = character.is_ascii_digit();
        if character_digit != digit {
            chunks.push((digit, &value[start..index]));
            start = index;
            digit = character_digit;
        }
    }
    chunks.push((digit, &value[start..]));
    chunks
}

fn compare_digit_chunks(left: &str, right: &str) -> Ordering {
    let left_trimmed = left.trim_start_matches('0');
    let right_trimmed = right.trim_start_matches('0');
    left_trimmed
        .len()
        .cmp(&right_trimmed.len())
        .then_with(|| left_trimmed.cmp(right_trimmed))
}

fn mutation_component_error(error: MutationError, detail: &'static str) -> ComponentError {
    match error.code() {
        MutationErrorCode::Limit | MutationErrorCode::Overflow => {
            ComponentError::resource_limit(detail)
        }
        MutationErrorCode::UnsupportedControl => ComponentError::unsupported(detail),
        _ => ComponentError::failure(detail),
    }
}

fn scope_decode(
    component: &ScopeComponent,
    error: NativeProcessorDecodeError,
) -> ScopeFactoryError {
    ScopeFactoryError::Decode {
        node_id: component.node_id,
        path: component.path.clone(),
        test_class: component.binding.test_class.clone(),
        category: component.binding.category,
        detail: error.code().to_owned(),
    }
}

/// ResultAction's exact pinned `OnError.action` values.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ResultActionKind {
    /// Continue after an unsuccessful sample.
    Continue,
    /// Stop the current virtual user thread.
    StopThread,
    /// Gracefully stop the test.
    StopTest,
    /// Immediately stop the test.
    StopTestNow,
    /// Start the next thread-group loop (execution pending listener order).
    StartNextThreadLoop,
    /// Start the next iteration of the innermost active controller loop.
    NextLoop,
    /// Break the current controller loop (execution pending listener order).
    BreakCurrentLoop,
}

impl ResultActionKind {
    /// Decodes one exact upstream integer action.
    pub fn from_wire(value: i32) -> Result<Self, NativeProcessorDecodeError> {
        match value {
            0 => Ok(Self::Continue),
            1 => Ok(Self::StopThread),
            2 => Ok(Self::StopTest),
            3 => Ok(Self::StopTestNow),
            4 => Ok(Self::StartNextThreadLoop),
            5 => Ok(Self::NextLoop),
            6 => Ok(Self::BreakCurrentLoop),
            _ => Err(NativeProcessorDecodeError::InvalidAction),
        }
    }

    /// Returns the exact upstream integer action.
    #[must_use]
    pub const fn wire_value(self) -> i32 {
        match self {
            Self::Continue => 0,
            Self::StopThread => 1,
            Self::StopTest => 2,
            Self::StopTestNow => 3,
            Self::StartNextThreadLoop => 4,
            Self::NextLoop => 5,
            Self::BreakCurrentLoop => 6,
        }
    }
}

/// Decode-only ResultAction configuration.
///
/// The pinned `ResultAction` class implements `SampleListener`, not
/// `PostProcessor`.  It is invoked by JMeter after postprocessors and
/// assertions, so this module deliberately exposes no executable factory,
/// postprocessor implementation, listener adapter, loop proof, or mutation
/// path for it.  Ordered listener effects belong to the separate listener
/// architecture.  This configuration only preserves the exact source
/// vocabulary for that future boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ResultActionConfig {
    action: ResultActionKind,
}

impl ResultActionConfig {
    /// Creates a decode-only configuration.
    #[must_use]
    pub const fn new(action: ResultActionKind) -> Self {
        Self { action }
    }

    /// Decodes one exact ResultAction TestElement.
    pub fn from_test_element(element: &TestElement) -> Result<Self, NativeProcessorDecodeError> {
        validate_element_identity(
            element,
            RESULT_ACTION_TEST_CLASSES,
            RESULT_ACTION_GUI_CLASSES,
        )?;
        let mut action = ResultActionKind::Continue;
        for property in element.properties.iter() {
            if property.name != RESULT_ACTION_PROPERTY {
                return Err(NativeProcessorDecodeError::UnknownProperty);
            }
            action = ResultActionKind::from_wire(match property.value {
                PropertyValue::Integer(value) => value,
                _ => return Err(NativeProcessorDecodeError::PropertyTypeMismatch),
            })?;
        }
        Ok(Self::new(action))
    }

    /// Returns the decoded action.
    #[must_use]
    pub const fn action(self) -> ResultActionKind {
        self.action
    }
}

/// ResultAction executable behavior is intentionally unavailable until the
/// ordered mutable listener boundary is implemented.
pub const RESULT_ACTION_NATIVE_STATUS: &str = "architecturally-pending-listener-order";

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    reason = "tests use fixed in-memory model values and explicit assertions"
)]
mod tests {
    use super::*;
    use jmeter_rs_model::{ElementMetadata, PropertyValue};

    fn element(class: &str, gui: &str) -> TestElement {
        TestElement::new(ElementMetadata::new(class, gui, "processor"))
    }

    #[test]
    fn debug_schema_defaults_and_unknowns_are_exact() {
        let config = DebugPostProcessorConfig::from_test_element(&element(
            DEBUG_POSTPROCESSOR_SHORT_CLASS,
            TEST_BEAN_GUI,
        ))
        .expect("default debug config");
        assert!(config.display_jmeter_variables());
        assert!(config.display_sampler_properties());
        assert!(!config.display_jmeter_properties());
        assert!(!config.display_system_properties());

        let mut all_views = element(DEBUG_POSTPROCESSOR_SHORT_CLASS, TEST_BEAN_GUI);
        for property in [
            DEBUG_PROPERTY_DISPLAY_JMETER_PROPERTIES,
            DEBUG_PROPERTY_DISPLAY_JMETER_VARIABLES,
            DEBUG_PROPERTY_DISPLAY_SYSTEM_PROPERTIES,
            DEBUG_PROPERTY_DISPLAY_SAMPLER_PROPERTIES,
        ] {
            all_views
                .properties
                .insert(property, PropertyValue::Boolean(true));
        }
        let all_views =
            DebugPostProcessorConfig::from_test_element(&all_views).expect("all exact debug flags");
        assert!(all_views.display_jmeter_properties());
        assert!(all_views.display_jmeter_variables());
        assert!(all_views.display_system_properties());
        assert!(all_views.display_sampler_properties());

        let mut wrong = element(DEBUG_POSTPROCESSOR_SHORT_CLASS, TEST_BEAN_GUI);
        wrong.properties.insert(
            "displayJMeterVariables",
            PropertyValue::String("secret".to_owned()),
        );
        assert_eq!(
            DebugPostProcessorConfig::from_test_element(&wrong),
            Err(NativeProcessorDecodeError::PropertyTypeMismatch)
        );

        let wrong_class = element("debugpostprocessor", TEST_BEAN_GUI);
        assert_eq!(
            DebugPostProcessorConfig::from_test_element(&wrong_class),
            Err(NativeProcessorDecodeError::ClassMismatch)
        );
        let wrong_gui = element(DEBUG_POSTPROCESSOR_SHORT_CLASS, "TestBeanGui");
        assert_eq!(
            DebugPostProcessorConfig::from_test_element(&wrong_gui),
            Err(NativeProcessorDecodeError::GuiClassMismatch)
        );
        let mut unknown = element(DEBUG_POSTPROCESSOR_SHORT_CLASS, TEST_BEAN_GUI);
        unknown
            .properties
            .insert("unknown", PropertyValue::Boolean(true));
        assert_eq!(
            DebugPostProcessorConfig::from_test_element(&unknown),
            Err(NativeProcessorDecodeError::UnknownProperty)
        );
    }

    #[test]
    fn result_action_wire_decoder_is_architecturally_pending() {
        assert_eq!(
            RESULT_ACTION_NATIVE_STATUS,
            "architecturally-pending-listener-order"
        );
        for (value, action) in [
            (0, ResultActionKind::Continue),
            (1, ResultActionKind::StopThread),
            (2, ResultActionKind::StopTest),
            (3, ResultActionKind::StopTestNow),
            (4, ResultActionKind::StartNextThreadLoop),
            (5, ResultActionKind::NextLoop),
            (6, ResultActionKind::BreakCurrentLoop),
        ] {
            assert_eq!(
                ResultActionKind::from_wire(value).expect("wire action"),
                action
            );
            assert_eq!(action.wire_value(), value);
        }
        assert_eq!(
            ResultActionKind::from_wire(7),
            Err(NativeProcessorDecodeError::InvalidAction)
        );

        let mut malformed = element(RESULT_ACTION_SHORT_CLASS, RESULT_ACTION_GUI);
        malformed.properties.insert(
            RESULT_ACTION_PROPERTY,
            PropertyValue::String("5".to_owned()),
        );
        assert_eq!(
            ResultActionConfig::from_test_element(&malformed),
            Err(NativeProcessorDecodeError::PropertyTypeMismatch)
        );
        let mut unknown = element(RESULT_ACTION_SHORT_CLASS, RESULT_ACTION_GUI);
        unknown.properties.insert(
            "TestLogicalAction",
            PropertyValue::String("BREAK_CURRENT_LOOP".to_owned()),
        );
        assert_eq!(
            ResultActionConfig::from_test_element(&unknown),
            Err(NativeProcessorDecodeError::UnknownProperty)
        );
    }

    #[test]
    fn debug_format_matches_pinned_sections_and_preserves_values() {
        let limits = DebugLimits::default();
        let values = [
            DebugProperty::try_new("key10", "ten", limits).expect("bounded value"),
            DebugProperty::try_new("key2", "first", limits).expect("bounded value"),
            DebugProperty::try_new("key2", "last", limits).expect("bounded value"),
            DebugProperty::try_new("password", "sensitive", limits).expect("bounded value"),
        ];
        let mut response = String::new();
        let mut sampler_data = String::new();
        append_section(
            &mut response,
            &mut sampler_data,
            "SamplerProperties",
            &values,
            limits,
        )
        .expect("bounded debug format");
        assert_eq!(
            response,
            "SamplerProperties:\nkey2=last\nkey10=ten\npassword=sensitive\n\n"
        );
        assert_eq!(sampler_data, "SamplerProperties\n");
    }

    #[test]
    fn debug_bounds_fail_closed_before_result_commit() {
        assert_eq!(
            DebugLimits::try_new(0, 1, 1),
            Err(NativeProcessorDecodeError::Limit)
        );
        let limits = DebugLimits::default();
        let oversized = "x".repeat(limits.max_value_bytes() + 1);
        assert_eq!(
            DebugProperty::try_new("key", oversized, limits),
            Err(NativeProcessorDecodeError::Limit)
        );
        let control = DebugProperty::try_new("key", "line\nvalue", limits)
            .expect_err("control-bearing value is rejected");
        assert_eq!(control, NativeProcessorDecodeError::InvalidText);
        assert!(!control.to_string().contains("line"));
        let properties = (0..=limits.max_entries())
            .map(|index| DebugProperty::try_new(format!("key{index}"), "value", limits))
            .collect::<Result<Vec<_>, _>>()
            .expect("individual values are bounded");
        assert_eq!(
            DebugPostProcessorSources::new().with_sampler_properties(properties, limits),
            Err(NativeProcessorDecodeError::Limit)
        );

        let output_limits = DebugLimits::try_new(1, 16, 8).expect("small output bound");
        let value = [DebugProperty::try_new("key", "value", output_limits)
            .expect("individual value is bounded")];
        let mut response = String::new();
        let mut sampler_data = String::new();
        let error = append_section(
            &mut response,
            &mut sampler_data,
            "SamplerProperties",
            &value,
            output_limits,
        )
        .expect_err("section output exceeds bound");
        assert!(
            error
                .to_string()
                .contains("debug-postprocessor.output-limit")
        );
    }

    #[test]
    fn alpha_numeric_sort_keeps_natural_numeric_order() {
        let mut values = vec!["key10", "key2", "key1"];
        values.sort_by(|left, right| alpha_numeric_cmp(left, right));
        assert_eq!(values, ["key1", "key2", "key10"]);
        // Java String.compareTo orders UTF-16 code units, not UTF-8 bytes.
        assert_eq!(
            alpha_numeric_cmp("𐀀", ""),
            Ordering::Less,
            "match AlphaNumericComparator's Java lexical ordering"
        );
        assert_eq!(alpha_numeric_cmp("é2", "é10"), Ordering::Less);
    }

    #[test]
    fn source_debug_does_not_reveal_values() {
        let limits = DebugLimits::default();
        let property = DebugProperty::try_new("password", "sensitive-value", limits)
            .expect("bounded property");
        let debug = format!("{property:?}");
        assert!(!debug.contains("sensitive-value"));
        assert!(!debug.contains("password"));

        let sources = DebugPostProcessorSources::new()
            .with_sampler_properties([property], limits)
            .expect("bounded source");
        let debug = format!("{sources:?}");
        assert!(!debug.contains("sensitive-value"));
        assert!(!debug.contains("password"));
    }
}
