// SPDX-License-Identifier: Apache-2.0
//! Bounded, lossless decoders for the two core Arguments-shaped elements.
//!
//! This module is intentionally standalone.  It is not registered by the
//! application crate.  The scope hook below deliberately fails closed after
//! decoding: a generic `Configuration` cannot know which sampler-specific
//! consumer should interpret an `Arguments` element.
//!
//! The source model is kept lossless at this boundary.  In particular, an
//! argument's property presence and order, duplicate entries, metadata, and
//! description are retained.  A first-wins ordered projection is exposed only
//! as raw decoder data; it is not applied to a generic runtime request map.
//! User-defined variables additionally expose an [`InitialVariables`]
//! projection, which is the only exact way to model JMeter's plan-start
//! user-variable lifecycle in this runtime.
//!
//! Expression text is retained verbatim.  The central lifecycle/compiler seam
//! owns the run's `Arc<BuiltinFunctions>` and the phase-specific timing; this
//! decoder never evaluates or rejects a function reference.
//!
//! Compatibility scope: `ELEM-005` for the ordered/lossless Arguments schema,
//! and `FUNC-001`/`FUNC-002` only for preserving expression source for the
//! central evaluator.  No profile conformance promotion is implied here.

#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

use std::collections::BTreeSet;
use std::fmt;

use jmeter_rs_model::{ElementProperty, PropertyKind, PropertyValue, TestElement};
use jmeter_rs_runtime::{
    ComponentCategory, FactoryComponent, InitialVariables, InitialVariablesError,
    MAX_ADAPTER_TEXT_BYTES, MAX_INITIAL_VARIABLE_NAME_BYTES, MAX_INITIAL_VARIABLE_TOTAL_BYTES,
    MAX_INITIAL_VARIABLE_VALUE_BYTES, MAX_INITIAL_VARIABLES, ScopeComponent, ScopeComponentFactory,
    ScopeFactoryError,
};

/// Short JMeter alias for the JMeter `Arguments` element.
pub const ARGUMENTS_ALIAS: &str = "Arguments";
/// Pinned JMeter class name for `Arguments`.
pub const ARGUMENTS_CLASS: &str = "org.apache.jmeter.config.Arguments";
/// Short JMeter alias for the JMeter `Argument` element.
pub const ARGUMENT_ALIAS: &str = "Argument";
/// Pinned JMeter class name for `Argument`.
pub const ARGUMENT_CLASS: &str = "org.apache.jmeter.config.Argument";
/// Profile-level classification alias retained for user-defined variables;
/// it is not a pinned executable JMeter class.
pub const USER_DEFINED_VARIABLES_ALIAS: &str = "UserDefinedVariables";
/// Profile-level fully qualified classification alias; not a pinned
/// executable JMeter class in the rel/v5.6.3 source tree.
pub const USER_DEFINED_VARIABLES_CLASS: &str = "org.apache.jmeter.config.UserDefinedVariables";

const ARGUMENTS_PROPERTY: &str = "Arguments.arguments";
const ARGUMENT_NAME_PROPERTY: &str = "Argument.name";
const ARGUMENT_VALUE_PROPERTY: &str = "Argument.value";
const ARGUMENT_METADATA_PROPERTY: &str = "Argument.metadata";
const ARGUMENT_DESCRIPTION_PROPERTY: &str = "Argument.desc";
// JMeter reads the complete Arguments source collection before its
// first-wins map projection.  Keep this source bound independent from the
// canonical InitialVariables map bound so duplicate entries cannot turn into
// an allocation-before-bound path.
const MAX_FACTORY_SOURCE_ENTRIES: usize = 65_536;
const MAX_FACTORY_CANONICAL_ENTRIES: usize = MAX_INITIAL_VARIABLES;
const MAX_FACTORY_PROPERTY_COUNT: usize = 16;
const MAX_DIAGNOSTIC_BYTES: usize = 1024;

/// Encoding used by the source model for `Arguments.arguments`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArgumentsCollectionEncoding {
    /// A normal ordered collection with unnamed entries.
    Collection,
    /// A collection whose entry names are retained by the model.
    NamedCollection,
    /// A map-shaped collection retained by the model.
    Map,
}

/// Field names in one nested `Argument` element, in source order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArgumentProperty {
    /// `Argument.name`.
    Name,
    /// `Argument.value`.
    Value,
    /// `Argument.metadata`.
    Metadata,
    /// `Argument.desc`.
    Description,
}

impl ArgumentProperty {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::Name => ARGUMENT_NAME_PROPERTY,
            Self::Value => ARGUMENT_VALUE_PROPERTY,
            Self::Metadata => ARGUMENT_METADATA_PROPERTY,
            Self::Description => ARGUMENT_DESCRIPTION_PROPERTY,
        }
    }
}

/// A decoded JMeter `Argument` retaining source presence and order.
#[derive(Clone, Eq, PartialEq)]
pub struct ArgumentEntry {
    element_name: String,
    element_type: Option<String>,
    name: Option<String>,
    value: Option<String>,
    metadata: Option<String>,
    description: Option<String>,
    property_order: Vec<ArgumentProperty>,
}

impl fmt::Debug for ArgumentEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArgumentEntry")
            .field("element_name_len", &self.element_name.len())
            .field("element_type_present", &self.element_type.is_some())
            .field("name_present", &self.name.is_some())
            .field("name_len", &self.name.as_ref().map(String::len))
            .field("value_present", &self.value.is_some())
            .field("value_len", &self.value.as_ref().map(String::len))
            .field("metadata_present", &self.metadata.is_some())
            .field("metadata_len", &self.metadata.as_ref().map(String::len))
            .field("description_present", &self.description.is_some())
            .field(
                "description_len",
                &self.description.as_ref().map(String::len),
            )
            .field("property_order", &self.property_order)
            .finish()
    }
}

impl ArgumentEntry {
    /// Returns the exact nested element name.
    #[must_use]
    pub fn element_name(&self) -> &str {
        &self.element_name
    }

    /// Returns the optional exact `elementType` attribute.
    #[must_use]
    pub fn element_type(&self) -> Option<&str> {
        self.element_type.as_deref()
    }

    /// Returns the optional `Argument.name` value, preserving absence.
    #[must_use]
    pub fn name_property(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Returns the optional `Argument.value` value, preserving absence.
    #[must_use]
    pub fn value_property(&self) -> Option<&str> {
        self.value.as_deref()
    }

    /// Returns the optional `Argument.metadata` value, preserving absence.
    #[must_use]
    pub fn metadata_property(&self) -> Option<&str> {
        self.metadata.as_deref()
    }

    /// Returns the optional `Argument.desc` value, preserving absence.
    #[must_use]
    pub fn description_property(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Returns nested property names in source order.
    #[must_use]
    pub fn property_order(&self) -> &[ArgumentProperty] {
        &self.property_order
    }

    /// Returns the effective name used by JMeter's Arguments map projection.
    #[must_use]
    pub fn effective_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.element_name)
    }

    /// Returns the effective value used by JMeter's Arguments map projection.
    #[must_use]
    pub fn effective_value(&self) -> &str {
        self.value.as_deref().unwrap_or_default()
    }
}

/// A decoded `Arguments` or `UserDefinedVariables` element.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArgumentsDefinition {
    class_name: String,
    arguments_property_present: bool,
    collection_encoding: ArgumentsCollectionEncoding,
    arguments: Vec<ArgumentEntry>,
}

impl ArgumentsDefinition {
    /// Returns the exact source class alias.
    #[must_use]
    pub fn class_name(&self) -> &str {
        &self.class_name
    }

    /// Returns whether `Arguments.arguments` was present in the source.
    #[must_use]
    pub const fn arguments_property_present(&self) -> bool {
        self.arguments_property_present
    }

    /// Returns the source collection encoding.
    #[must_use]
    pub const fn collection_encoding(&self) -> ArgumentsCollectionEncoding {
        self.collection_encoding
    }

    /// Returns decoded arguments in exact source order.
    #[must_use]
    pub fn arguments(&self) -> &[ArgumentEntry] {
        &self.arguments
    }

    /// Returns a first-wins ordered map projection matching the pinned
    /// `Arguments.getArgumentsAsMap` implementation.
    ///
    /// The pinned Apache implementation uses a `LinkedHashMap` and guards
    /// insertion with `containsKey`, so source order and the first duplicate
    /// value are observable.  This is raw decoder data only; sampler-specific
    /// consumers remain responsible for interpreting it.
    pub fn first_wins_map(&self) -> Vec<(String, String)> {
        let mut seen = BTreeSet::new();
        let mut result = Vec::with_capacity(self.arguments.len());
        for argument in &self.arguments {
            let name = argument.effective_name();
            if seen.insert(name) {
                result.push((name.to_owned(), argument.effective_value().to_owned()));
            }
        }
        result
    }

    fn validate_user_variable_metadata(&self) -> Result<(), ConfigurationDecodeError> {
        for (index, argument) in self.arguments.iter().enumerate() {
            if argument
                .metadata_property()
                .is_some_and(|metadata| metadata != "=")
            {
                return Err(ConfigurationDecodeError::NonDefaultMetadata { index });
            }
        }
        Ok(())
    }

    /// Converts raw, already-decoded user variables into the runtime's
    /// immutable plan-start seed.  Expressions remain source text, matching
    /// the existing `PlanCompiler` initial-variable representation.
    pub fn initial_variables(&self) -> Result<InitialVariables, ConfigurationDecodeError> {
        self.validate_user_variable_metadata()?;
        InitialVariables::try_from_jmeter_arguments(self.arguments.iter().map(|argument| {
            (
                argument.effective_name().to_owned(),
                argument.effective_value().to_owned(),
            )
        }))
        .map_err(ConfigurationDecodeError::initial_variables)
    }
}

/// Finite bounds applied while decoding an Arguments-shaped element.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigurationDecodeLimits {
    /// Maximum number of canonical argument names in the TestPlan
    /// `InitialVariables` projection.  Generic `Arguments` decoding is
    /// source-bounded and does not claim a consumer-specific map limit.
    pub max_arguments: usize,
    /// Maximum number of source collection entries before projection.
    pub max_source_entries: usize,
    /// Maximum bytes in one argument name or element name.
    pub max_name_bytes: usize,
    /// Maximum bytes in one argument value.
    pub max_value_bytes: usize,
    /// Maximum bytes in one metadata or description field.
    pub max_auxiliary_bytes: usize,
    /// Maximum aggregate bytes in names, values, and auxiliary fields.
    pub max_total_bytes: usize,
}

impl Default for ConfigurationDecodeLimits {
    fn default() -> Self {
        Self {
            max_arguments: MAX_FACTORY_CANONICAL_ENTRIES,
            max_source_entries: MAX_FACTORY_SOURCE_ENTRIES,
            max_name_bytes: MAX_INITIAL_VARIABLE_NAME_BYTES,
            max_value_bytes: MAX_INITIAL_VARIABLE_VALUE_BYTES,
            max_auxiliary_bytes: MAX_ADAPTER_TEXT_BYTES,
            max_total_bytes: MAX_INITIAL_VARIABLE_TOTAL_BYTES,
        }
    }
}

impl ConfigurationDecodeLimits {
    /// Creates limits after checking that every bound is nonzero and no larger
    /// than the corresponding runtime hard bound.
    pub fn new(
        max_arguments: usize,
        max_name_bytes: usize,
        max_value_bytes: usize,
        max_auxiliary_bytes: usize,
        max_total_bytes: usize,
    ) -> Result<Self, ConfigurationDecodeError> {
        let limits = Self {
            max_arguments,
            max_source_entries: MAX_FACTORY_SOURCE_ENTRIES,
            max_name_bytes,
            max_value_bytes,
            max_auxiliary_bytes,
            max_total_bytes,
        };
        limits.validate()?;
        Ok(limits)
    }

    /// Replaces the source-entry bound while retaining the other limits.
    pub fn with_max_source_entries(
        mut self,
        max_source_entries: usize,
    ) -> Result<Self, ConfigurationDecodeError> {
        self.max_source_entries = max_source_entries;
        self.validate()?;
        Ok(self)
    }

    fn validate(self) -> Result<(), ConfigurationDecodeError> {
        let valid = self.max_arguments > 0
            && self.max_arguments <= MAX_FACTORY_CANONICAL_ENTRIES
            && self.max_source_entries > 0
            && self.max_source_entries <= MAX_FACTORY_SOURCE_ENTRIES
            && self.max_name_bytes > 0
            && self.max_name_bytes <= MAX_INITIAL_VARIABLE_NAME_BYTES
            && self.max_value_bytes > 0
            && self.max_value_bytes <= MAX_INITIAL_VARIABLE_VALUE_BYTES
            && self.max_auxiliary_bytes > 0
            && self.max_auxiliary_bytes <= MAX_ADAPTER_TEXT_BYTES
            && self.max_total_bytes > 0
            && self.max_total_bytes <= MAX_INITIAL_VARIABLE_TOTAL_BYTES;
        valid
            .then_some(())
            .ok_or(ConfigurationDecodeError::InvalidLimits)
    }
}

/// Stable, redacted failure from Arguments-shaped decoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigurationDecodeError {
    /// Caller-supplied limits are zero or exceed runtime hard bounds.
    InvalidLimits,
    /// The source class alias is not one of this module's exact aliases.
    UnsupportedAlias { class_bytes: usize },
    /// The source element is not a configuration category.
    CategoryMismatch {
        /// Expected runtime category.
        expected: ComponentCategory,
        /// Category supplied by the scope binding.
        actual: ComponentCategory,
    },
    /// A required top-level property is absent.
    MissingProperty { property: &'static str },
    /// A top-level or nested property is not in the exact supported schema.
    UnsupportedProperty {
        /// Property nesting level (zero is the element itself).
        depth: usize,
        /// Exact bounded property name.
        property: &'static str,
    },
    /// A property has an unsupported model kind.
    InvalidPropertyType {
        /// Property nesting level.
        depth: usize,
        /// Exact bounded property name.
        property: &'static str,
        /// Actual model kind.
        actual: PropertyKind,
    },
    /// A collection has an unsupported shape.
    InvalidCollectionType { actual: PropertyKind },
    /// A nested collection entry is not an element property.
    InvalidArgumentEntry { index: usize, actual: PropertyKind },
    /// A nested element class is not `Argument`.
    ArgumentClassMismatch { index: usize, class_bytes: usize },
    /// An opaque extension would be lost by native decoding.
    OpaqueExtension { depth: usize },
    /// User-variable metadata is not the JMeter default separator.
    NonDefaultMetadata { index: usize },
    /// A source value exceeds a named finite bound.
    Limit {
        /// Bounded field classification.
        field: &'static str,
        /// Observed UTF-8 bytes or entry count.
        actual: usize,
        /// Maximum accepted amount.
        limit: usize,
    },
    /// The runtime initial-variable seed rejected an otherwise decoded map.
    InitialVariables {
        /// Stable seed-validation code without retaining the source name.
        code: &'static str,
    },
}

impl ConfigurationDecodeError {
    /// Returns a stable machine-readable code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidLimits => "app.configuration.invalid-limits",
            Self::UnsupportedAlias { .. } => "app.configuration.unsupported-alias",
            Self::CategoryMismatch { .. } => "app.configuration.category-mismatch",
            Self::MissingProperty { .. } => "app.configuration.missing-property",
            Self::UnsupportedProperty { .. } => "app.configuration.unsupported-property",
            Self::InvalidPropertyType { .. } => "app.configuration.invalid-property-type",
            Self::InvalidCollectionType { .. } => "app.configuration.invalid-collection",
            Self::InvalidArgumentEntry { .. } => "app.configuration.invalid-argument-entry",
            Self::ArgumentClassMismatch { .. } => "app.configuration.argument-class-mismatch",
            Self::OpaqueExtension { .. } => "app.configuration.opaque-extension",
            Self::NonDefaultMetadata { .. } => "app.configuration.metadata",
            Self::Limit { .. } => "app.configuration.limit",
            Self::InitialVariables { code } => code,
        }
    }

    fn initial_variables(error: InitialVariablesError) -> Self {
        Self::InitialVariables { code: error.code() }
    }
}

impl fmt::Display for ConfigurationDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str(self.code()),
            Self::UnsupportedAlias { class_bytes } => {
                write!(formatter, "{}: {class_bytes} class bytes", self.code())
            }
            Self::CategoryMismatch { expected, actual } => {
                write!(
                    formatter,
                    "{}: expected {expected:?}, got {actual:?}",
                    self.code()
                )
            }
            Self::MissingProperty { property } => {
                write!(formatter, "{}: {property}", self.code())
            }
            Self::UnsupportedProperty { depth, property } => {
                write!(formatter, "{}: depth {depth}, {property}", self.code())
            }
            Self::InvalidPropertyType {
                depth,
                property,
                actual,
            } => write!(
                formatter,
                "{}: depth {depth}, {property} is {actual}",
                self.code()
            ),
            Self::InvalidCollectionType { actual } => {
                write!(formatter, "{}: {actual}", self.code())
            }
            Self::InvalidArgumentEntry { index, actual } => {
                write!(formatter, "{}: entry {index} is {actual}", self.code())
            }
            Self::ArgumentClassMismatch { index, class_bytes } => write!(
                formatter,
                "{}: entry {index}, class metadata is {class_bytes} bytes",
                self.code()
            ),
            Self::OpaqueExtension { depth } => {
                write!(formatter, "{}: depth {depth}", self.code())
            }
            Self::NonDefaultMetadata { index } => {
                write!(formatter, "{}: entry {index}", self.code())
            }
            Self::Limit {
                field,
                actual,
                limit,
            } => write!(
                formatter,
                "{}: {field} {actual} exceeds {limit}",
                self.code()
            ),
            Self::InitialVariables { .. } => write!(formatter, "{}: seed rejected", self.code()),
        }
    }
}

impl std::error::Error for ConfigurationDecodeError {}

/// Decode an exact `Arguments` element without performing I/O or evaluation.
pub fn decode_arguments(
    element: &TestElement,
) -> Result<ArgumentsDefinition, ConfigurationDecodeError> {
    decode_arguments_with_limits(element, ConfigurationDecodeLimits::default())
}

/// Decode an exact `Arguments` element with explicit finite limits.
pub fn decode_arguments_with_limits(
    element: &TestElement,
    limits: ConfigurationDecodeLimits,
) -> Result<ArgumentsDefinition, ConfigurationDecodeError> {
    decode_element(element, limits, false)
}

/// Decode a `UserDefinedVariables`/TestPlan Arguments element with exact
/// initial-variable schema validation.  JMeter's empty-key and first-wins
/// duplicate projection is applied only by [`ArgumentsDefinition::initial_variables`].
pub fn decode_user_defined_variables(
    element: &TestElement,
) -> Result<ArgumentsDefinition, ConfigurationDecodeError> {
    decode_user_defined_variables_with_limits(element, ConfigurationDecodeLimits::default())
}

/// Decode user-defined variables with explicit finite limits.
pub fn decode_user_defined_variables_with_limits(
    element: &TestElement,
    limits: ConfigurationDecodeLimits,
) -> Result<ArgumentsDefinition, ConfigurationDecodeError> {
    decode_element(element, limits, true)
}

/// Decode the embedded `TestPlan.user_defined_variables` Arguments property.
///
/// The semantic model represents this JMX value as an [`ElementProperty`],
/// not as an executable `TestElement`.  An absent `elementType` is accepted
/// exactly as the canonical plan compiler accepts it; the source projection
/// still uses the pinned `Arguments` schema and never creates a sampler-time
/// component.
pub fn decode_user_defined_variables_property(
    element: &ElementProperty,
) -> Result<ArgumentsDefinition, ConfigurationDecodeError> {
    decode_user_defined_variables_property_with_limits(
        element,
        ConfigurationDecodeLimits::default(),
    )
}

/// Decode the embedded user-variable property with explicit finite limits.
pub fn decode_user_defined_variables_property_with_limits(
    element: &ElementProperty,
    limits: ConfigurationDecodeLimits,
) -> Result<ArgumentsDefinition, ConfigurationDecodeError> {
    limits.validate()?;
    if element.name.len() > limits.max_name_bytes {
        return Err(ConfigurationDecodeError::Limit {
            field: "element-name",
            actual: element.name.len(),
            limit: limits.max_name_bytes,
        });
    }
    if !element.opaque_extensions.is_empty() {
        return Err(ConfigurationDecodeError::OpaqueExtension { depth: 0 });
    }
    let class = element.class_name.as_deref().unwrap_or(ARGUMENTS_ALIAS);
    if class.len() > limits.max_name_bytes {
        return Err(ConfigurationDecodeError::Limit {
            field: "element-type",
            actual: class.len(),
            limit: limits.max_name_bytes,
        });
    }
    let mut wrapper = TestElement::named(class, "", element.name.clone());
    wrapper.properties = element.properties.clone();
    decode_user_defined_variables_with_limits(&wrapper, limits)
}

fn decode_element(
    element: &TestElement,
    limits: ConfigurationDecodeLimits,
    user_variables: bool,
) -> Result<ArgumentsDefinition, ConfigurationDecodeError> {
    limits.validate()?;
    // The pinned JMeter source has `Arguments`; user-defined variables are an
    // embedded Arguments property on TestPlan rather than a separate Java
    // executable class.  Profile aliases named `UserDefinedVariables` are
    // therefore rejected by this exact decoder and handled as an explicit
    // unsupported placement by the scope hook.
    let accepted_alias = matches!(element.test_class(), ARGUMENTS_ALIAS | ARGUMENTS_CLASS);
    if !accepted_alias {
        return Err(ConfigurationDecodeError::UnsupportedAlias {
            class_bytes: element.test_class().len(),
        });
    }
    if !element.opaque_extensions.is_empty() || !element.temporary_properties.is_empty() {
        return Err(ConfigurationDecodeError::OpaqueExtension { depth: 0 });
    }
    if element.properties.len() > MAX_FACTORY_PROPERTY_COUNT {
        return Err(ConfigurationDecodeError::Limit {
            field: "properties",
            actual: element.properties.len(),
            limit: MAX_FACTORY_PROPERTY_COUNT,
        });
    }
    let arguments = element.properties.get(ARGUMENTS_PROPERTY).ok_or(
        ConfigurationDecodeError::MissingProperty {
            property: ARGUMENTS_PROPERTY,
        },
    )?;
    for property in element.properties.keys() {
        if property != ARGUMENTS_PROPERTY {
            return Err(ConfigurationDecodeError::UnsupportedProperty {
                depth: 0,
                property: "unknown",
            });
        }
    }
    let (encoding, source_entry_count) = collection_shape(arguments)?;
    if source_entry_count > limits.max_source_entries {
        return Err(ConfigurationDecodeError::Limit {
            field: "source-entries",
            actual: source_entry_count,
            limit: limits.max_source_entries,
        });
    }
    if let PropertyValue::NamedCollection(entries) | PropertyValue::Map(entries) = arguments
        && let Some(entry) = entries
            .iter()
            .find(|entry| entry.name.len() > limits.max_name_bytes)
    {
        return Err(ConfigurationDecodeError::Limit {
            field: "collection-entry-name",
            actual: entry.name.len(),
            limit: limits.max_name_bytes,
        });
    }
    // This allocation occurs only after the source collection count has been
    // checked against the independent source-entry bound above.
    let values = collection_values(arguments)?;
    let mut decoded = Vec::with_capacity(values.len());
    let mut canonical_names = BTreeSet::new();
    let mut total_bytes = 0usize;
    for (index, value) in values.iter().enumerate() {
        let argument =
            value
                .as_element()
                .map_err(|_| ConfigurationDecodeError::InvalidArgumentEntry {
                    index,
                    actual: value.kind(),
                })?;
        let entry = decode_argument(argument, index, &limits, &mut total_bytes, user_variables)?;
        if user_variables && !canonical_names.contains(entry.effective_name()) {
            let actual =
                canonical_names
                    .len()
                    .checked_add(1)
                    .ok_or(ConfigurationDecodeError::Limit {
                        field: "arguments",
                        actual: usize::MAX,
                        limit: limits.max_arguments,
                    })?;
            if actual > limits.max_arguments {
                return Err(ConfigurationDecodeError::Limit {
                    field: "arguments",
                    actual,
                    limit: limits.max_arguments,
                });
            }
            canonical_names.insert(entry.effective_name().to_owned());
        }
        decoded.push(entry);
    }
    let definition = ArgumentsDefinition {
        class_name: element.test_class().to_owned(),
        arguments_property_present: true,
        collection_encoding: encoding,
        arguments: decoded,
    };
    if user_variables {
        definition.validate_user_variable_metadata()?;
    }
    Ok(definition)
}

fn collection_shape(
    value: &PropertyValue,
) -> Result<(ArgumentsCollectionEncoding, usize), ConfigurationDecodeError> {
    match value {
        PropertyValue::Collection(values) => {
            Ok((ArgumentsCollectionEncoding::Collection, values.len()))
        }
        PropertyValue::NamedCollection(entries) => {
            Ok((ArgumentsCollectionEncoding::NamedCollection, entries.len()))
        }
        PropertyValue::Map(entries) => Ok((ArgumentsCollectionEncoding::Map, entries.len())),
        other => Err(ConfigurationDecodeError::InvalidCollectionType {
            actual: other.kind(),
        }),
    }
}

fn collection_values(
    value: &PropertyValue,
) -> Result<Vec<&PropertyValue>, ConfigurationDecodeError> {
    match value {
        PropertyValue::Collection(values) => Ok(values.iter().collect()),
        PropertyValue::NamedCollection(entries) => {
            Ok(entries.iter().map(|entry| &entry.value).collect())
        }
        PropertyValue::Map(entries) => Ok(entries.iter().map(|entry| &entry.value).collect()),
        other => Err(ConfigurationDecodeError::InvalidCollectionType {
            actual: other.kind(),
        }),
    }
}

fn decode_argument(
    argument: &ElementProperty,
    index: usize,
    limits: &ConfigurationDecodeLimits,
    total_bytes: &mut usize,
    user_variables: bool,
) -> Result<ArgumentEntry, ConfigurationDecodeError> {
    if argument.name.len() > limits.max_name_bytes {
        return Err(ConfigurationDecodeError::Limit {
            field: "element-name",
            actual: argument.name.len(),
            limit: limits.max_name_bytes,
        });
    }
    if argument.properties.len() > MAX_FACTORY_PROPERTY_COUNT {
        return Err(ConfigurationDecodeError::Limit {
            field: "argument-properties",
            actual: argument.properties.len(),
            limit: MAX_FACTORY_PROPERTY_COUNT,
        });
    }
    if !argument.opaque_extensions.is_empty() {
        return Err(ConfigurationDecodeError::OpaqueExtension { depth: 1 });
    }
    if argument
        .class_name
        .as_deref()
        .is_some_and(|class| !matches!(class, ARGUMENT_ALIAS | ARGUMENT_CLASS))
    {
        return Err(ConfigurationDecodeError::ArgumentClassMismatch {
            index,
            class_bytes: argument.class_name.as_ref().map_or(0, String::len),
        });
    }
    let mut name = None;
    let mut value = None;
    let mut metadata = None;
    let mut description = None;
    let mut property_order = Vec::with_capacity(argument.properties.len());
    for entry in argument.properties.as_slice() {
        let field = match entry.name.as_str() {
            ARGUMENT_NAME_PROPERTY => ArgumentProperty::Name,
            ARGUMENT_VALUE_PROPERTY => ArgumentProperty::Value,
            ARGUMENT_METADATA_PROPERTY => ArgumentProperty::Metadata,
            ARGUMENT_DESCRIPTION_PROPERTY => ArgumentProperty::Description,
            _ => {
                return Err(ConfigurationDecodeError::UnsupportedProperty {
                    depth: 1,
                    property: "unknown",
                });
            }
        };
        if user_variables && field == ArgumentProperty::Description {
            return Err(ConfigurationDecodeError::UnsupportedProperty {
                depth: 1,
                property: ARGUMENT_DESCRIPTION_PROPERTY,
            });
        }
        let target_limit = match field {
            ArgumentProperty::Name => limits.max_name_bytes,
            ArgumentProperty::Value => limits.max_value_bytes,
            ArgumentProperty::Metadata | ArgumentProperty::Description => {
                limits.max_auxiliary_bytes
            }
        };
        let string = match &entry.value {
            PropertyValue::String(value) => value,
            other => {
                return Err(ConfigurationDecodeError::InvalidPropertyType {
                    depth: 1,
                    property: field.wire_name(),
                    actual: other.kind(),
                });
            }
        };
        if string.len() > target_limit {
            return Err(ConfigurationDecodeError::Limit {
                field: field.wire_name(),
                actual: string.len(),
                limit: target_limit,
            });
        }
        *total_bytes =
            total_bytes
                .checked_add(string.len())
                .ok_or(ConfigurationDecodeError::Limit {
                    field: "total-bytes",
                    actual: usize::MAX,
                    limit: limits.max_total_bytes,
                })?;
        if *total_bytes > limits.max_total_bytes {
            return Err(ConfigurationDecodeError::Limit {
                field: "total-bytes",
                actual: *total_bytes,
                limit: limits.max_total_bytes,
            });
        }
        property_order.push(field);
        match field {
            ArgumentProperty::Name => name = Some(string.to_owned()),
            ArgumentProperty::Value => value = Some(string.to_owned()),
            ArgumentProperty::Metadata => metadata = Some(string.to_owned()),
            ArgumentProperty::Description => description = Some(string.to_owned()),
        }
    }
    *total_bytes =
        total_bytes
            .checked_add(argument.name.len())
            .ok_or(ConfigurationDecodeError::Limit {
                field: "total-bytes",
                actual: usize::MAX,
                limit: limits.max_total_bytes,
            })?;
    if *total_bytes > limits.max_total_bytes {
        return Err(ConfigurationDecodeError::Limit {
            field: "total-bytes",
            actual: *total_bytes,
            limit: limits.max_total_bytes,
        });
    }
    Ok(ArgumentEntry {
        element_name: argument.name.clone(),
        element_type: argument.class_name.clone(),
        name,
        value,
        metadata,
        description,
        property_order,
    })
}

/// Scope hook for the Arguments-shaped aliases.
///
/// The hook validates and decodes the source, then returns an explicit
/// unsupported-placement error.  JMeter's `Arguments` is a general
/// `ConfigTestElement`; HTTP, Java, and other sampler consumers interpret its
/// properties differently.  The generic runtime has no consumer-specific
/// merge contract, so returning a request-map configuration here would claim
/// semantics that the pinned evidence does not establish.
#[derive(Clone, Copy, Debug, Default)]
pub struct ArgumentsFactory;

impl ScopeComponentFactory for ArgumentsFactory {
    fn create(&self, component: &ScopeComponent) -> Result<FactoryComponent, ScopeFactoryError> {
        if component.binding.category != ComponentCategory::Configuration {
            return Err(scope_decode(
                component,
                ConfigurationDecodeError::CategoryMismatch {
                    expected: ComponentCategory::Configuration,
                    actual: component.binding.category,
                },
            ));
        }
        if component.element.test_class() != component.binding.test_class {
            return Err(scope_decode_message(
                component,
                "source and scope binding aliases do not match",
            ));
        }
        if matches!(
            component.binding.test_class.as_str(),
            USER_DEFINED_VARIABLES_ALIAS | USER_DEFINED_VARIABLES_CLASS
        ) {
            return Err(scope_decode_message(
                component,
                "user-defined variables are TestPlan Arguments and require the plan-start InitialVariables seam",
            ));
        }
        decode_arguments(&component.element).map_err(|error| scope_decode(component, error))?;
        Err(scope_decode_message(
            component,
            "Arguments consumer placement is sampler-specific and unsupported by the generic scope factory",
        ))
    }

    fn test_class(&self) -> Option<&str> {
        None
    }
}

fn scope_decode(component: &ScopeComponent, error: ConfigurationDecodeError) -> ScopeFactoryError {
    scope_decode_message(component, &bounded_diagnostic(error.to_string()))
}

fn scope_decode_message(component: &ScopeComponent, detail: &str) -> ScopeFactoryError {
    ScopeFactoryError::Decode {
        node_id: component.node_id,
        path: component.path.clone(),
        test_class: bounded_diagnostic(component.binding.test_class.clone()),
        category: ComponentCategory::Configuration,
        detail: bounded_diagnostic(detail.to_owned()),
    }
}

fn bounded_diagnostic(mut text: String) -> String {
    if text.len() <= MAX_DIAGNOSTIC_BYTES {
        return text;
    }
    let mut end = MAX_DIAGNOSTIC_BYTES;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    text
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "configuration tests use fixed in-memory semantic model values"
)]
mod tests {
    use super::*;
    use jmeter_rs_model::{ElementMetadata, NodeId};
    use jmeter_rs_runtime::ComponentBinding;

    fn argument(name: &str, value: &str) -> PropertyValue {
        let mut element =
            ElementProperty::from_optional_class_name(name, Some(ARGUMENT_CLASS.to_owned()));
        element.properties.insert(
            ARGUMENT_NAME_PROPERTY,
            PropertyValue::String(name.to_owned()),
        );
        element.properties.insert(
            ARGUMENT_VALUE_PROPERTY,
            PropertyValue::String(value.to_owned()),
        );
        PropertyValue::Element(element)
    }

    fn element(class: &str, values: Vec<PropertyValue>) -> TestElement {
        let mut element = TestElement::new(ElementMetadata::new(class, "gui", "config"));
        element
            .properties
            .insert(ARGUMENTS_PROPERTY, PropertyValue::Collection(values));
        element
    }

    fn component(element: TestElement, class: &str) -> ScopeComponent {
        ScopeComponent {
            node_id: NodeId::new(4),
            path: vec![NodeId::new(1), NodeId::new(4)],
            element,
            binding: ComponentBinding::native(
                class,
                ComponentCategory::Configuration,
                "runtime.native.arguments",
            ),
        }
    }

    #[test]
    fn decode_retains_order_presence_and_first_duplicate_wins() {
        let mut first = ElementProperty::new("first");
        first.properties.insert(
            ARGUMENT_VALUE_PROPERTY,
            PropertyValue::String("one".to_owned()),
        );
        first.properties.insert(
            ARGUMENT_NAME_PROPERTY,
            PropertyValue::String("duplicate".to_owned()),
        );
        let definition = decode_arguments(&element(
            ARGUMENTS_ALIAS,
            vec![
                PropertyValue::Element(first),
                argument("second", "two"),
                argument("duplicate", "three"),
            ],
        ))
        .expect("arguments");
        assert_eq!(
            definition.arguments()[0].property_order(),
            &[ArgumentProperty::Value, ArgumentProperty::Name]
        );
        assert_eq!(definition.arguments()[0].element_name(), "first");
        assert_eq!(
            definition.arguments()[0].element_type(),
            None,
            "absent nested elementType remains absent"
        );
        assert!(definition.arguments_property_present());
        assert_eq!(
            definition.collection_encoding(),
            ArgumentsCollectionEncoding::Collection
        );
        assert_eq!(
            definition.first_wins_map(),
            vec![
                ("duplicate".to_owned(), "one".to_owned()),
                ("second".to_owned(), "two".to_owned()),
            ]
        );
    }

    #[test]
    fn duplicate_source_entries_are_distinct_from_canonical_bound() {
        let values = (0..=MAX_FACTORY_CANONICAL_ENTRIES)
            .map(|index| argument("same", &index.to_string()))
            .collect();
        let definition = decode_user_defined_variables(&element(ARGUMENTS_ALIAS, values))
            .expect("duplicate source entries fit the independent source bound");
        let seed = definition.initial_variables().expect("first-wins seed");
        assert_eq!(seed.len(), 1);
        assert_eq!(seed.get("same"), Some("0"));
    }

    #[test]
    fn generic_arguments_do_not_inherit_test_plan_seed_bound() {
        let values = (0..=MAX_FACTORY_CANONICAL_ENTRIES)
            .map(|index| argument(&format!("key-{index}"), "value"))
            .collect();
        let definition =
            decode_arguments(&element(ARGUMENTS_ALIAS, values)).expect("source-bounded Arguments");
        assert_eq!(
            definition.first_wins_map().len(),
            MAX_FACTORY_CANONICAL_ENTRIES + 1
        );
    }

    #[test]
    fn malformed_nested_collection_and_unknown_property_fail_closed() {
        let mut nested = ElementProperty::new("x");
        nested.properties.insert(
            ARGUMENT_VALUE_PROPERTY,
            PropertyValue::Collection(Vec::new()),
        );
        let source = element(ARGUMENTS_CLASS, vec![PropertyValue::Element(nested)]);
        let before = source.clone();
        let error = decode_arguments(&source).expect_err("nested collection must fail");
        assert_eq!(error.code(), "app.configuration.invalid-property-type");
        assert_eq!(
            source, before,
            "decode failure cannot partially mutate source"
        );

        let mut nested = ElementProperty::new("x");
        nested
            .properties
            .insert("Argument.unknown", PropertyValue::String("x".to_owned()));
        let error = decode_arguments(&element(
            ARGUMENTS_CLASS,
            vec![PropertyValue::Element(nested)],
        ))
        .expect_err("unknown property must fail");
        assert_eq!(error.code(), "app.configuration.unsupported-property");
    }

    #[test]
    fn user_variables_use_jmeter_first_wins_and_allow_empty_names() {
        let definition = decode_user_defined_variables(&element(
            ARGUMENTS_ALIAS,
            vec![
                argument("", "empty-value"),
                argument("same", "one"),
                argument("same", "discarded"),
            ],
        ))
        .expect("JMeter UDV source permits empty and duplicate names");
        let seed = definition
            .initial_variables()
            .expect("JMeter seed projection");
        assert_eq!(seed.get(""), Some("empty-value"));
        assert_eq!(seed.get("same"), Some("one"));
        assert_eq!(seed.len(), 2);

        let mut metadata = ElementProperty::new("metadata");
        metadata.properties.insert(
            ARGUMENT_NAME_PROPERTY,
            PropertyValue::String("metadata".to_owned()),
        );
        metadata.properties.insert(
            ARGUMENT_VALUE_PROPERTY,
            PropertyValue::String("value".to_owned()),
        );
        metadata.properties.insert(
            ARGUMENT_METADATA_PROPERTY,
            PropertyValue::String(";".to_owned()),
        );
        let error = decode_user_defined_variables(&element(
            ARGUMENTS_ALIAS,
            vec![PropertyValue::Element(metadata)],
        ))
        .expect_err("non-default metadata remains unsupported by the seed seam");
        assert_eq!(error.code(), "app.configuration.metadata");
    }

    #[test]
    fn empty_values_and_expression_capability_boundary_are_explicit() {
        let absent = decode_arguments(&element(
            ARGUMENTS_ALIAS,
            vec![PropertyValue::Element(ElementProperty::new("fallback"))],
        ))
        .expect("absent source properties are retained");
        assert_eq!(absent.arguments()[0].name_property(), None);
        assert_eq!(absent.arguments()[0].value_property(), None);
        assert_eq!(absent.arguments()[0].effective_name(), "fallback");
        assert_eq!(absent.arguments()[0].effective_value(), "");

        let empty = decode_arguments(&element(ARGUMENTS_ALIAS, vec![argument("empty", "")]))
            .expect("empty value is a present string");
        assert_eq!(empty.arguments()[0].value_property(), Some(""));
        let function = decode_arguments(&element(
            ARGUMENTS_ALIAS,
            vec![argument("function", "${__P(example,missing)}")],
        ))
        .expect("function expression is decoded without execution");
        assert_eq!(
            function.arguments()[0].value_property(),
            Some("${__P(example,missing)}")
        );
        let seed = decode_user_defined_variables(&element(
            ARGUMENTS_ALIAS,
            vec![argument("function", "${__P(example,missing)}")],
        ))
        .expect("function-valued user variable")
        .initial_variables()
        .expect("seed preserves expression source");
        assert_eq!(seed.get("function"), Some("${__P(example,missing)}"));
    }

    #[test]
    fn description_is_retained_for_arguments_but_not_initial_variables() {
        let mut described = ElementProperty::new("described");
        described.properties.insert(
            ARGUMENT_NAME_PROPERTY,
            PropertyValue::String("name".to_owned()),
        );
        described.properties.insert(
            ARGUMENT_VALUE_PROPERTY,
            PropertyValue::String("value".to_owned()),
        );
        described.properties.insert(
            ARGUMENT_DESCRIPTION_PROPERTY,
            PropertyValue::String("diagnostic only".to_owned()),
        );
        let generic = decode_arguments(&element(
            ARGUMENTS_ALIAS,
            vec![PropertyValue::Element(described.clone())],
        ))
        .expect("generic Arguments retains description");
        assert_eq!(
            generic.arguments()[0].description_property(),
            Some("diagnostic only")
        );
        let error = decode_user_defined_variables(&element(
            ARGUMENTS_ALIAS,
            vec![PropertyValue::Element(described)],
        ))
        .expect_err("initial-variable parser does not represent descriptions");
        assert_eq!(error.code(), "app.configuration.unsupported-property");
    }

    #[test]
    fn bounds_are_checked_before_factory_state_is_created() {
        let error =
            ConfigurationDecodeLimits::new(0, 1, 1, 1, 1).expect_err("zero limits are invalid");
        assert_eq!(error.code(), "app.configuration.invalid-limits");

        let limits = ConfigurationDecodeLimits::new(1, 16, 16, 16, 64).expect("small limits");
        let error = decode_user_defined_variables_with_limits(
            &element(
                ARGUMENTS_ALIAS,
                vec![argument("one", "1"), argument("two", "2")],
            ),
            limits,
        )
        .expect_err("argument count bound");
        assert_eq!(error.code(), "app.configuration.limit");

        let source_limits = ConfigurationDecodeLimits::default()
            .with_max_source_entries(1)
            .expect("source bound");
        let error = decode_user_defined_variables_with_limits(
            &element(
                ARGUMENTS_ALIAS,
                vec![argument("same", "one"), argument("same", "two")],
            ),
            source_limits,
        )
        .expect_err("source entries are bounded before projection");
        assert_eq!(
            error,
            ConfigurationDecodeError::Limit {
                field: "source-entries",
                actual: 2,
                limit: 1,
            }
        );
        assert!(
            ConfigurationDecodeLimits::default()
                .with_max_source_entries(0)
                .is_err()
        );
        assert!(
            ConfigurationDecodeLimits::default()
                .with_max_source_entries(MAX_FACTORY_SOURCE_ENTRIES + 1)
                .is_err()
        );

        let name_limits = ConfigurationDecodeLimits::new(1, 1, 16, 16, 64).expect("name bound");
        let error = decode_arguments_with_limits(
            &element(ARGUMENTS_ALIAS, vec![argument("name", "value")]),
            name_limits,
        )
        .expect_err("name byte bound");
        assert_eq!(error.code(), "app.configuration.limit");

        let value_limits = ConfigurationDecodeLimits::new(1, 16, 1, 16, 64).expect("value bound");
        let error = decode_arguments_with_limits(
            &element(ARGUMENTS_ALIAS, vec![argument("name", "value")]),
            value_limits,
        )
        .expect_err("value byte bound");
        assert_eq!(error.code(), "app.configuration.limit");

        let total_limits = ConfigurationDecodeLimits::new(1, 16, 16, 16, 1).expect("total bound");
        let error = decode_arguments_with_limits(
            &element(ARGUMENTS_ALIAS, vec![argument("n", "v")]),
            total_limits,
        )
        .expect_err("aggregate byte bound");
        assert_eq!(error.code(), "app.configuration.limit");
    }

    #[test]
    fn diagnostics_are_redacted() {
        let mut nested = ElementProperty::new("secret-name");
        nested
            .properties
            .insert(ARGUMENT_VALUE_PROPERTY, PropertyValue::Integer(4));
        let error = decode_arguments(&element(
            ARGUMENTS_ALIAS,
            vec![PropertyValue::Element(nested)],
        ))
        .expect_err("wrong scalar type");
        assert!(!error.to_string().contains("secret-name"));
        assert!(!error.to_string().contains("4"));
        assert!(!format!("{error:?}").contains("secret-name"));

        let duplicate = decode_user_defined_variables(&element(
            ARGUMENTS_ALIAS,
            vec![
                argument("sensitive-name", "one"),
                argument("sensitive-name", "two"),
            ],
        ))
        .expect("duplicate source entries are retained for JMeter projection");
        assert!(!format!("{duplicate:?}").contains("sensitive-name"));
        assert_eq!(
            duplicate
                .initial_variables()
                .expect("first-wins seed")
                .get("sensitive-name"),
            Some("one")
        );
    }

    #[test]
    fn source_alias_and_category_are_exact() {
        let factory = ArgumentsFactory;
        let wrong = ScopeComponent {
            binding: ComponentBinding::native(
                ARGUMENTS_CLASS,
                ComponentCategory::Timer,
                "runtime.native.arguments",
            ),
            ..component(
                element(ARGUMENTS_CLASS, vec![argument("a", "b")]),
                ARGUMENTS_CLASS,
            )
        };
        let error = ScopeComponentFactory::create(&factory, &wrong).expect_err("category mismatch");
        assert_eq!(error.code(), "runtime.scope.factory-decode");
        assert!(decode_arguments(&element("arguments", vec![argument("a", "b")])).is_err());
        let error = ScopeComponentFactory::create(
            &factory,
            &ScopeComponent {
                element: element(ARGUMENTS_CLASS, vec![argument("a", "b")]),
                binding: ComponentBinding::native(
                    ARGUMENTS_ALIAS,
                    ComponentCategory::Configuration,
                    "runtime.native.arguments",
                ),
                ..component(
                    element(ARGUMENTS_CLASS, vec![argument("a", "b")]),
                    ARGUMENTS_ALIAS,
                )
            },
        )
        .expect_err("source and binding aliases must match");
        if let ScopeFactoryError::Decode { detail, .. } = error {
            assert!(detail.contains("aliases do not match"));
        } else {
            panic!("expected alias mismatch decode error");
        }
        let error = ScopeComponentFactory::create(
            &factory,
            &component(
                element(ARGUMENTS_ALIAS, vec![argument("a", "b")]),
                ARGUMENTS_ALIAS,
            ),
        )
        .expect_err("generic Arguments placement");
        if let ScopeFactoryError::Decode {
            node_id,
            path,
            detail,
            ..
        } = error
        {
            assert_eq!(node_id, NodeId::new(4));
            assert_eq!(path, vec![NodeId::new(1), NodeId::new(4)]);
            assert!(detail.contains("consumer placement"));
        } else {
            panic!("expected bounded placement error");
        }
        let error = ScopeComponentFactory::create(
            &factory,
            &component(
                element(USER_DEFINED_VARIABLES_ALIAS, vec![argument("a", "b")]),
                USER_DEFINED_VARIABLES_ALIAS,
            ),
        )
        .expect_err("generic scope has no plan-start callback");
        assert_eq!(error.code(), "runtime.scope.factory-decode");
        if let ScopeFactoryError::Decode {
            node_id,
            path,
            detail,
            ..
        } = error
        {
            assert_eq!(node_id, NodeId::new(4));
            assert_eq!(path, vec![NodeId::new(1), NodeId::new(4)]);
            assert!(detail.contains("plan-start"));
        } else {
            panic!("expected bounded decode error");
        }
    }

    #[test]
    fn user_variables_project_to_the_canonical_plan_start_seed() {
        let definition = decode_user_defined_variables(&element(
            ARGUMENTS_ALIAS,
            vec![
                argument("seed", "value"),
                argument("derived", "${seed}-suffix"),
            ],
        ))
        .expect("user variables");
        let seed = definition.initial_variables().expect("seed");
        assert_eq!(seed.get("seed"), Some("value"));
        assert_eq!(seed.get("derived"), Some("${seed}-suffix"));
        assert_eq!(seed.len(), 2);
    }

    #[test]
    fn embedded_test_plan_arguments_accept_absent_element_type() {
        let mut embedded = ElementProperty::new("user-vars");
        embedded.properties.insert(
            ARGUMENTS_PROPERTY,
            PropertyValue::Collection(vec![argument("seed", "value")]),
        );
        let definition =
            decode_user_defined_variables_property(&embedded).expect("embedded TestPlan Arguments");
        assert_eq!(definition.class_name(), ARGUMENTS_ALIAS);
        assert_eq!(
            definition.initial_variables().expect("seed").get("seed"),
            Some("value")
        );
    }

    #[test]
    fn user_defined_variables_alias_is_not_a_pinned_executable_class() {
        let error = decode_user_defined_variables(&element(
            USER_DEFINED_VARIABLES_ALIAS,
            vec![argument("seed", "value")],
        ))
        .expect_err("profile alias is not the pinned embedded Arguments class");
        assert_eq!(error.code(), "app.configuration.unsupported-alias");

        let error = ScopeComponentFactory::create(
            &ArgumentsFactory,
            &component(
                element(
                    USER_DEFINED_VARIABLES_CLASS,
                    vec![argument("seed", "value")],
                ),
                USER_DEFINED_VARIABLES_CLASS,
            ),
        )
        .expect_err("separate UDV scope class must fail closed");
        assert_eq!(error.code(), "runtime.scope.factory-decode");
        assert!(error.to_string().contains("plan-start"));
    }
}
