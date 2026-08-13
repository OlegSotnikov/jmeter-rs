// SPDX-License-Identifier: Apache-2.0
//! Native, bounded Boundary Extractor support for the ELEM-008 application
//! edge.
//!
//! The decoder accepts only the two pinned JMeter 5.6.3 test-class aliases and
//! the exact BoundaryExtractor property names.  Runtime execution resolves a
//! body or raw-header projection through the executor-neutral response
//! capability and publishes one complete variable delta.  It never reads a
//! result-file path, or mutates a live variable map while an extraction is in
//! progress.  Java-compatible response decoding uses bounded replacement
//! semantics for malformed bytes; unsupported charset names remain typed
//! capability errors.

#![forbid(unsafe_code)]
#![allow(
    clippy::module_name_repetitions,
    reason = "the application boundary names its BoundaryExtractor types explicitly"
)]

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use jmeter_rs_model::{PropertyKind, PropertyValue, TestElement};
use jmeter_rs_runtime::{
    CapabilityError, ComponentError, ComponentFuture, ControlSignal, DEFAULT_MAX_MUTATIONS,
    DEFAULT_MAX_RESPONSE_BYTES, DEFAULT_MAX_VALUE_BYTES, InvocationDelta, MutationDiagnostic,
    MutationError, MutationErrorCode, MutationLimits, Postprocessor, PostprocessorFactory,
    Presence, RandomSource, ResponseDecodePolicy, ResponseInput, ResponseInputSetResolver,
    ResponseLimits, ResponseResolution, ResponseScope, ResponseSelection, ResponseTarget,
    SampleContext, ScopedResponseResolver, VariableMutation,
};

/// The short JMeter SaveService alias for BoundaryExtractor.
pub const BOUNDARY_EXTRACTOR_ALIAS: &str = "BoundaryExtractor";
/// The pinned Apache JMeter 5.6.3 BoundaryExtractor class name.
pub const BOUNDARY_EXTRACTOR_CLASS: &str = "org.apache.jmeter.extractor.BoundaryExtractor";
/// All exact test-class spellings accepted by this decoder.
pub const BOUNDARY_EXTRACTOR_TEST_CLASSES: &[&str] =
    &[BOUNDARY_EXTRACTOR_ALIAS, BOUNDARY_EXTRACTOR_CLASS];

const REFNAME_PROPERTY: &str = "BoundaryExtractor.refname";
const LEFT_BOUNDARY_PROPERTY: &str = "BoundaryExtractor.lboundary";
const RIGHT_BOUNDARY_PROPERTY: &str = "BoundaryExtractor.rboundary";
const MATCH_NUMBER_PROPERTY: &str = "BoundaryExtractor.match_number";
const DEFAULT_PROPERTY: &str = "BoundaryExtractor.default";
const DEFAULT_EMPTY_VALUE_PROPERTY: &str = "BoundaryExtractor.default_empty_value";
const USE_HEADERS_PROPERTY: &str = "BoundaryExtractor.useHeaders";
const SAMPLE_SCOPE_PROPERTY: &str = "Sample.scope";
const SCOPE_VARIABLE_PROPERTY: &str = "Scope.variable";
const MATCH_COUNT_SUFFIX: &str = "_matchNr";

const SCOPE_PARENT: &str = "parent";
const SCOPE_CHILDREN: &str = "children";
const SCOPE_ALL: &str = "all";
const SCOPE_VARIABLE: &str = "variable";

/// The source fixture's response and generated-value bounds.
pub const BOUNDARY_FIXTURE_MAX_INPUT_BYTES: usize = 4 * 1024;
/// The source fixture's maximum boundary length.
pub const BOUNDARY_FIXTURE_MAX_BOUNDARY_BYTES: usize = 4 * 1024;
/// The source fixture's maximum number of extracted matches.
pub const BOUNDARY_FIXTURE_MAX_MATCHES: usize = 32;
/// The source fixture's maximum generated variable value.
pub const BOUNDARY_FIXTURE_MAX_VALUE_BYTES: usize = 4 * 1024;
/// A finite hard ceiling for one decoder property.
pub const BOUNDARY_MAX_PROPERTY_BYTES: usize = 8 * 1024;
/// A finite hard ceiling for KMP search work in one invocation.
pub const BOUNDARY_MAX_SEARCH_STEPS: usize = 16 * 1024 * 1024;
/// A finite hard ceiling for one BoundaryExtractor property collection.
pub const BOUNDARY_MAX_PROPERTIES: usize = 16;
/// A finite cap for caller-supplied ordered sample inputs.
pub const BOUNDARY_MAX_INPUTS: usize = 64;

const DEFAULT_SEARCH_STEPS: usize = 64 * 1024;

/// Finite limits used by decoding and one extractor invocation.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BoundaryExtractorLimits {
    max_property_bytes: usize,
    max_input_bytes: usize,
    max_boundary_bytes: usize,
    max_matches: usize,
    max_value_bytes: usize,
    max_search_steps: usize,
}

impl fmt::Debug for BoundaryExtractorLimits {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundaryExtractorLimits")
            .field("max_property_bytes", &self.max_property_bytes)
            .field("max_input_bytes", &self.max_input_bytes)
            .field("max_boundary_bytes", &self.max_boundary_bytes)
            .field("max_matches", &self.max_matches)
            .field("max_value_bytes", &self.max_value_bytes)
            .field("max_search_steps", &self.max_search_steps)
            .finish()
    }
}

impl Default for BoundaryExtractorLimits {
    fn default() -> Self {
        Self {
            max_property_bytes: BOUNDARY_MAX_PROPERTY_BYTES,
            max_input_bytes: BOUNDARY_FIXTURE_MAX_INPUT_BYTES,
            max_boundary_bytes: BOUNDARY_FIXTURE_MAX_BOUNDARY_BYTES,
            max_matches: BOUNDARY_FIXTURE_MAX_MATCHES,
            max_value_bytes: BOUNDARY_FIXTURE_MAX_VALUE_BYTES,
            max_search_steps: DEFAULT_SEARCH_STEPS,
        }
    }
}

impl BoundaryExtractorLimits {
    /// Creates explicit limits.  Zero and over-ceiling values are rejected by
    /// [`Self::validate`].
    #[must_use]
    pub const fn new(
        max_property_bytes: usize,
        max_input_bytes: usize,
        max_boundary_bytes: usize,
        max_matches: usize,
        max_value_bytes: usize,
        max_search_steps: usize,
    ) -> Self {
        Self {
            max_property_bytes,
            max_input_bytes,
            max_boundary_bytes,
            max_matches,
            max_value_bytes,
            max_search_steps,
        }
    }

    /// Returns the standard bounded fixture limits.
    #[must_use]
    pub const fn fixture() -> Self {
        Self {
            max_property_bytes: BOUNDARY_MAX_PROPERTY_BYTES,
            max_input_bytes: BOUNDARY_FIXTURE_MAX_INPUT_BYTES,
            max_boundary_bytes: BOUNDARY_FIXTURE_MAX_BOUNDARY_BYTES,
            max_matches: BOUNDARY_FIXTURE_MAX_MATCHES,
            max_value_bytes: BOUNDARY_FIXTURE_MAX_VALUE_BYTES,
            max_search_steps: DEFAULT_SEARCH_STEPS,
        }
    }

    /// Returns the maximum bytes retained for one property value.
    #[must_use]
    pub const fn max_property_bytes(self) -> usize {
        self.max_property_bytes
    }

    /// Returns the maximum selected response bytes.
    #[must_use]
    pub const fn max_input_bytes(self) -> usize {
        self.max_input_bytes
    }

    /// Returns the maximum left/right boundary bytes.
    #[must_use]
    pub const fn max_boundary_bytes(self) -> usize {
        self.max_boundary_bytes
    }

    /// Returns the maximum number of extracted matches.
    #[must_use]
    pub const fn max_matches(self) -> usize {
        self.max_matches
    }

    /// Returns the maximum bytes in one generated variable value.
    #[must_use]
    pub const fn max_value_bytes(self) -> usize {
        self.max_value_bytes
    }

    /// Returns the maximum bounded search work per invocation.
    #[must_use]
    pub const fn max_search_steps(self) -> usize {
        self.max_search_steps
    }

    /// Validates that all limits are finite and within the production hard
    /// ceilings used by this module and the runtime mutation seam.
    pub fn validate(self) -> Result<(), BoundaryExtractorDecodeError> {
        if self.max_property_bytes == 0 || self.max_property_bytes > BOUNDARY_MAX_PROPERTY_BYTES {
            return Err(BoundaryExtractorDecodeError::InvalidLimits);
        }
        if self.max_input_bytes == 0 || self.max_input_bytes > DEFAULT_MAX_RESPONSE_BYTES {
            return Err(BoundaryExtractorDecodeError::InvalidLimits);
        }
        if self.max_boundary_bytes == 0
            || self.max_boundary_bytes > BOUNDARY_FIXTURE_MAX_BOUNDARY_BYTES
        {
            return Err(BoundaryExtractorDecodeError::InvalidLimits);
        }
        if self.max_matches == 0 || self.max_matches > BOUNDARY_FIXTURE_MAX_MATCHES {
            return Err(BoundaryExtractorDecodeError::InvalidLimits);
        }
        if self.max_value_bytes == 0 || self.max_value_bytes > DEFAULT_MAX_VALUE_BYTES {
            return Err(BoundaryExtractorDecodeError::InvalidLimits);
        }
        if self.max_search_steps == 0 || self.max_search_steps > BOUNDARY_MAX_SEARCH_STEPS {
            return Err(BoundaryExtractorDecodeError::InvalidLimits);
        }
        Ok(())
    }
}

/// Stable, redacted failure raised while decoding a BoundaryExtractor
/// TestElement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundaryExtractorDecodeError {
    /// The caller supplied an invalid resource limit.
    InvalidLimits,
    /// The test class is not one of the exact pinned aliases.
    UnsupportedAlias { class_bytes: usize },
    /// Opaque or temporary model data cannot be interpreted natively.
    OpaqueExtension,
    /// More properties than the bounded decoder admits were supplied.
    PropertyCountLimit { actual: usize, limit: usize },
    /// A property outside the exact schema was supplied.
    UnsupportedProperty { property_bytes: usize },
    /// A required property was absent.
    MissingProperty { property: &'static str },
    /// A property had a different model kind than its JMeter wire schema.
    InvalidPropertyType {
        property: &'static str,
        actual: PropertyKind,
    },
    /// A numeric property could not be parsed as a signed 32-bit integer.
    InvalidInteger { property: &'static str },
    /// A numeric property was outside the signed 32-bit range.
    IntegerRange { property: &'static str },
    /// A required reference name was present but empty.
    EmptyReferenceName,
    /// A textual field contained a control character or exceeded its bound.
    InvalidText { property: &'static str },
    /// The `useHeaders` wire value is outside the body/headers projection.
    UnsupportedInputSelection { value_bytes: usize },
    /// The `Sample.scope` wire value is not one of JMeter's four closed values.
    UnsupportedScope { property_bytes: usize },
}

impl BoundaryExtractorDecodeError {
    /// Returns a stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidLimits => "app.boundary-extractor.decode.limits",
            Self::UnsupportedAlias { .. } => "app.boundary-extractor.decode.alias",
            Self::OpaqueExtension => "app.boundary-extractor.decode.opaque",
            Self::PropertyCountLimit { .. } => "app.boundary-extractor.decode.property-count",
            Self::UnsupportedProperty { .. } => "app.boundary-extractor.decode.property",
            Self::MissingProperty { .. } => "app.boundary-extractor.decode.missing-property",
            Self::InvalidPropertyType { .. } => "app.boundary-extractor.decode.property-type",
            Self::InvalidInteger { .. } => "app.boundary-extractor.decode.integer",
            Self::IntegerRange { .. } => "app.boundary-extractor.decode.integer-range",
            Self::EmptyReferenceName => "app.boundary-extractor.decode.refname",
            Self::InvalidText { .. } => "app.boundary-extractor.decode.text",
            Self::UnsupportedInputSelection { .. } => {
                "app.boundary-extractor.decode.input-selection"
            }
            Self::UnsupportedScope { .. } => "app.boundary-extractor.decode.scope",
        }
    }
}

impl fmt::Display for BoundaryExtractorDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits | Self::OpaqueExtension | Self::EmptyReferenceName => {
                formatter.write_str(self.code())
            }
            Self::UnsupportedAlias { class_bytes }
            | Self::UnsupportedInputSelection {
                value_bytes: class_bytes,
            } => write!(formatter, "{}: {class_bytes} bytes", self.code()),
            Self::UnsupportedScope { property_bytes } => {
                write!(formatter, "{}: {property_bytes} bytes", self.code())
            }
            Self::PropertyCountLimit { actual, limit } => {
                write!(formatter, "{}: {actual} exceeds {limit}", self.code())
            }
            Self::UnsupportedProperty { property_bytes } => {
                write!(formatter, "{}: {property_bytes} bytes", self.code())
            }
            Self::MissingProperty { property }
            | Self::InvalidInteger { property }
            | Self::IntegerRange { property }
            | Self::InvalidText { property } => write!(formatter, "{}: {property}", self.code()),
            Self::InvalidPropertyType { property, actual } => {
                write!(formatter, "{}: {property} is {actual}", self.code())
            }
        }
    }
}

impl std::error::Error for BoundaryExtractorDecodeError {}

/// The exact decoded BoundaryExtractor configuration.
#[derive(Clone, Eq, PartialEq)]
pub struct BoundaryExtractorDefinition {
    class_name: String,
    ref_name: String,
    left_boundary: String,
    right_boundary: String,
    match_number: i32,
    default_value: String,
    default_empty_value: bool,
    use_headers: bool,
    scope: ResponseScope,
    limits: BoundaryExtractorLimits,
}

impl fmt::Debug for BoundaryExtractorDefinition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundaryExtractorDefinition")
            .field("class_name", &self.class_name)
            .field("ref_name_bytes", &self.ref_name.len())
            .field("left_boundary_bytes", &self.left_boundary.len())
            .field("right_boundary_bytes", &self.right_boundary.len())
            .field("match_number", &self.match_number)
            .field("default_value_bytes", &self.default_value.len())
            .field("default_empty_value", &self.default_empty_value)
            .field("use_headers", &self.use_headers)
            .field("scope", &self.scope)
            .field("limits", &self.limits)
            .finish()
    }
}

impl BoundaryExtractorDefinition {
    /// Constructs a definition with the standard fixture bounds.
    pub fn try_new(
        ref_name: impl Into<String>,
        left_boundary: impl Into<String>,
        right_boundary: impl Into<String>,
        match_number: i32,
        default_value: impl Into<String>,
        default_empty_value: bool,
        use_headers: bool,
    ) -> Result<Self, BoundaryExtractorDecodeError> {
        Self::try_new_with_limits(
            BOUNDARY_EXTRACTOR_ALIAS,
            ref_name,
            left_boundary,
            right_boundary,
            match_number,
            default_value,
            default_empty_value,
            use_headers,
            BoundaryExtractorLimits::default(),
        )
    }

    /// Constructs a definition with explicit finite limits and the short
    /// JMeter alias as its source class.
    // The argument list mirrors the seven persisted BoundaryExtractor fields
    // plus the source class and explicit limit policy at this API boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new_with_limits(
        class_name: impl Into<String>,
        ref_name: impl Into<String>,
        left_boundary: impl Into<String>,
        right_boundary: impl Into<String>,
        match_number: i32,
        default_value: impl Into<String>,
        default_empty_value: bool,
        use_headers: bool,
        limits: BoundaryExtractorLimits,
    ) -> Result<Self, BoundaryExtractorDecodeError> {
        Self::try_new_with_scope(
            class_name,
            ref_name,
            left_boundary,
            right_boundary,
            match_number,
            default_value,
            default_empty_value,
            use_headers,
            ResponseScope::Current,
            limits,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn try_new_with_scope(
        class_name: impl Into<String>,
        ref_name: impl Into<String>,
        left_boundary: impl Into<String>,
        right_boundary: impl Into<String>,
        match_number: i32,
        default_value: impl Into<String>,
        default_empty_value: bool,
        use_headers: bool,
        scope: ResponseScope,
        limits: BoundaryExtractorLimits,
    ) -> Result<Self, BoundaryExtractorDecodeError> {
        limits.validate()?;
        let class_name = class_name.into();
        if !is_supported_test_class(&class_name) {
            return Err(BoundaryExtractorDecodeError::UnsupportedAlias {
                class_bytes: class_name.len(),
            });
        }
        let ref_name = ref_name.into();
        let left_boundary = left_boundary.into();
        let right_boundary = right_boundary.into();
        let default_value = default_value.into();
        validate_text(&ref_name, REFNAME_PROPERTY, limits.max_property_bytes)?;
        if ref_name.is_empty() {
            return Err(BoundaryExtractorDecodeError::EmptyReferenceName);
        }
        validate_scope(&scope, limits.max_property_bytes)?;
        validate_text(
            &left_boundary,
            LEFT_BOUNDARY_PROPERTY,
            limits.max_boundary_bytes,
        )?;
        validate_text(
            &right_boundary,
            RIGHT_BOUNDARY_PROPERTY,
            limits.max_boundary_bytes,
        )?;
        validate_text(&default_value, DEFAULT_PROPERTY, limits.max_value_bytes)?;
        Ok(Self {
            class_name,
            ref_name,
            left_boundary,
            right_boundary,
            match_number,
            default_value,
            default_empty_value,
            use_headers,
            scope,
            limits,
        })
    }

    /// Returns the exact source test-class alias.
    #[must_use]
    pub fn class_name(&self) -> &str {
        &self.class_name
    }

    /// Returns the variable reference name.
    #[must_use]
    pub fn ref_name(&self) -> &str {
        &self.ref_name
    }

    /// Returns the left boundary, including an intentional empty boundary.
    #[must_use]
    pub fn left_boundary(&self) -> &str {
        &self.left_boundary
    }

    /// Returns the right boundary, including an intentional empty boundary.
    #[must_use]
    pub fn right_boundary(&self) -> &str {
        &self.right_boundary
    }

    /// Returns the signed JMeter match number.
    #[must_use]
    pub const fn match_number(&self) -> i32 {
        self.match_number
    }

    /// Returns the configured default value.
    #[must_use]
    pub fn default_value(&self) -> &str {
        &self.default_value
    }

    /// Returns whether an empty default must be materialized.
    #[must_use]
    pub const fn default_empty_value(&self) -> bool {
        self.default_empty_value
    }

    /// Returns whether the response source is raw response headers.
    #[must_use]
    pub const fn use_headers(&self) -> bool {
        self.use_headers
    }

    /// Returns the exact JMeter sample scope selected by this extractor.
    #[must_use]
    pub fn scope(&self) -> &ResponseScope {
        &self.scope
    }

    /// Returns a copy with an explicit, validated sample scope.
    pub fn with_scope(
        mut self,
        scope: ResponseScope,
    ) -> Result<Self, BoundaryExtractorDecodeError> {
        validate_scope(&scope, self.limits.max_property_bytes)?;
        self.scope = scope;
        Ok(self)
    }

    /// Returns the finite execution limits.
    #[must_use]
    pub const fn limits(&self) -> BoundaryExtractorLimits {
        self.limits
    }

    /// Returns whether the upstream default-value condition is active.
    #[must_use]
    pub fn has_materialized_default(&self) -> bool {
        self.default_empty_value || !is_blank(self.default_value.as_str())
    }

    /// Creates a per-user postprocessor factory using the default response
    /// resolver.
    #[must_use]
    pub fn factory(self) -> BoundaryExtractorFactory {
        BoundaryExtractorFactory::new(self)
    }
}

/// Decodes a BoundaryExtractor TestElement using the standard finite bounds.
pub fn decode_boundary_extractor(
    element: &TestElement,
) -> Result<BoundaryExtractorDefinition, BoundaryExtractorDecodeError> {
    decode_boundary_extractor_with_limits(element, BoundaryExtractorLimits::default())
}

/// Decodes a BoundaryExtractor TestElement using explicit finite bounds.
pub fn decode_boundary_extractor_with_limits(
    element: &TestElement,
    limits: BoundaryExtractorLimits,
) -> Result<BoundaryExtractorDefinition, BoundaryExtractorDecodeError> {
    limits.validate()?;
    if !is_supported_test_class(element.test_class()) {
        return Err(BoundaryExtractorDecodeError::UnsupportedAlias {
            class_bytes: element.test_class().len(),
        });
    }
    if !element.opaque_extensions.is_empty() || !element.temporary_properties.is_empty() {
        return Err(BoundaryExtractorDecodeError::OpaqueExtension);
    }
    if element.properties.len() > BOUNDARY_MAX_PROPERTIES {
        return Err(BoundaryExtractorDecodeError::PropertyCountLimit {
            actual: element.properties.len(),
            limit: BOUNDARY_MAX_PROPERTIES,
        });
    }
    for property in element.properties.keys() {
        if !is_supported_property(property) {
            return Err(BoundaryExtractorDecodeError::UnsupportedProperty {
                property_bytes: property.len(),
            });
        }
    }

    let ref_name = required_string_property(element, REFNAME_PROPERTY, &limits)?;
    let left_boundary = optional_string_property(
        element,
        LEFT_BOUNDARY_PROPERTY,
        "",
        limits.max_boundary_bytes,
        &limits,
    )?;
    let right_boundary = optional_string_property(
        element,
        RIGHT_BOUNDARY_PROPERTY,
        "",
        limits.max_boundary_bytes,
        &limits,
    )?;
    let default_value = optional_string_property(
        element,
        DEFAULT_PROPERTY,
        "",
        limits.max_value_bytes,
        &limits,
    )?;
    let match_number = optional_match_number(element, &limits)?;
    let default_empty_value = optional_bool_property(element, DEFAULT_EMPTY_VALUE_PROPERTY)?;
    let use_headers = optional_use_headers(element)?;
    let scope = optional_scope_property(element, &limits)?;
    BoundaryExtractorDefinition::try_new_with_scope(
        element.test_class(),
        ref_name,
        left_boundary,
        right_boundary,
        match_number,
        default_value,
        default_empty_value,
        use_headers,
        scope,
        limits,
    )
}

fn is_supported_test_class(value: &str) -> bool {
    BOUNDARY_EXTRACTOR_TEST_CLASSES.contains(&value)
}

fn is_supported_property(value: &str) -> bool {
    matches!(
        value,
        REFNAME_PROPERTY
            | LEFT_BOUNDARY_PROPERTY
            | RIGHT_BOUNDARY_PROPERTY
            | MATCH_NUMBER_PROPERTY
            | DEFAULT_PROPERTY
            | DEFAULT_EMPTY_VALUE_PROPERTY
            | USE_HEADERS_PROPERTY
            | SAMPLE_SCOPE_PROPERTY
            | SCOPE_VARIABLE_PROPERTY
    )
}

fn validate_scope(
    scope: &ResponseScope,
    maximum: usize,
) -> Result<(), BoundaryExtractorDecodeError> {
    if let ResponseScope::Variable { name } = scope {
        validate_text(name, SCOPE_VARIABLE_PROPERTY, maximum)?;
    }
    Ok(())
}

fn validate_text(
    value: &str,
    property: &'static str,
    maximum: usize,
) -> Result<(), BoundaryExtractorDecodeError> {
    if value.len() > maximum || value.chars().any(char::is_control) {
        return Err(BoundaryExtractorDecodeError::InvalidText { property });
    }
    Ok(())
}

fn required_string_property(
    element: &TestElement,
    property: &'static str,
    limits: &BoundaryExtractorLimits,
) -> Result<String, BoundaryExtractorDecodeError> {
    let value = element
        .property(property)
        .ok_or(BoundaryExtractorDecodeError::MissingProperty { property })?;
    let value = string_property(value, property)?;
    validate_text(value, property, limits.max_property_bytes)?;
    if value.is_empty() {
        return Err(BoundaryExtractorDecodeError::EmptyReferenceName);
    }
    Ok(value.to_owned())
}

fn optional_string_property(
    element: &TestElement,
    property: &'static str,
    default: &str,
    field_limit: usize,
    limits: &BoundaryExtractorLimits,
) -> Result<String, BoundaryExtractorDecodeError> {
    let Some(value) = element.property(property) else {
        return Ok(default.to_owned());
    };
    let value = string_property(value, property)?;
    validate_text(value, property, field_limit.min(limits.max_property_bytes))?;
    Ok(value.to_owned())
}

fn string_property<'a>(
    value: &'a PropertyValue,
    property: &'static str,
) -> Result<&'a str, BoundaryExtractorDecodeError> {
    value
        .as_string()
        .map_err(|_| BoundaryExtractorDecodeError::InvalidPropertyType {
            property,
            actual: value.kind(),
        })
}

fn optional_match_number(
    element: &TestElement,
    limits: &BoundaryExtractorLimits,
) -> Result<i32, BoundaryExtractorDecodeError> {
    let Some(value) = element.property(MATCH_NUMBER_PROPERTY) else {
        return Ok(0);
    };
    let number = match value {
        PropertyValue::String(value) => {
            value
                .parse::<i32>()
                .map_err(|_| BoundaryExtractorDecodeError::InvalidInteger {
                    property: MATCH_NUMBER_PROPERTY,
                })?
        }
        PropertyValue::Integer(value) => *value,
        PropertyValue::Long(value) => {
            i32::try_from(*value).map_err(|_| BoundaryExtractorDecodeError::IntegerRange {
                property: MATCH_NUMBER_PROPERTY,
            })?
        }
        _ => {
            return Err(BoundaryExtractorDecodeError::InvalidPropertyType {
                property: MATCH_NUMBER_PROPERTY,
                actual: value.kind(),
            });
        }
    };
    if number > 0
        && usize::try_from(number)
            .ok()
            .is_some_and(|value| value > limits.max_matches)
    {
        return Err(BoundaryExtractorDecodeError::IntegerRange {
            property: MATCH_NUMBER_PROPERTY,
        });
    }
    Ok(number)
}

fn optional_bool_property(
    element: &TestElement,
    property: &'static str,
) -> Result<bool, BoundaryExtractorDecodeError> {
    let Some(value) = element.property(property) else {
        return Ok(false);
    };
    match value {
        PropertyValue::Boolean(value) => Ok(*value),
        PropertyValue::String(value) if value.eq_ignore_ascii_case("true") => Ok(true),
        PropertyValue::String(value) if value.eq_ignore_ascii_case("false") => Ok(false),
        _ => Err(BoundaryExtractorDecodeError::InvalidPropertyType {
            property,
            actual: value.kind(),
        }),
    }
}

fn optional_use_headers(element: &TestElement) -> Result<bool, BoundaryExtractorDecodeError> {
    let Some(value) = element.property(USE_HEADERS_PROPERTY) else {
        return Ok(false);
    };
    match value {
        PropertyValue::Boolean(value) => Ok(*value),
        PropertyValue::String(value) if value.eq_ignore_ascii_case("true") => Ok(true),
        PropertyValue::String(value) if value.is_empty() || value.eq_ignore_ascii_case("false") => {
            Ok(false)
        }
        PropertyValue::String(value) => {
            Err(BoundaryExtractorDecodeError::UnsupportedInputSelection {
                value_bytes: value.len(),
            })
        }
        _ => Err(BoundaryExtractorDecodeError::InvalidPropertyType {
            property: USE_HEADERS_PROPERTY,
            actual: value.kind(),
        }),
    }
}

fn optional_scope_property(
    element: &TestElement,
    limits: &BoundaryExtractorLimits,
) -> Result<ResponseScope, BoundaryExtractorDecodeError> {
    let scope = match element.property(SAMPLE_SCOPE_PROPERTY) {
        None => SCOPE_PARENT,
        Some(value) => {
            let value = string_property(value, SAMPLE_SCOPE_PROPERTY)?;
            validate_text(value, SAMPLE_SCOPE_PROPERTY, limits.max_property_bytes)?;
            value
        }
    };
    match scope {
        SCOPE_PARENT => Ok(ResponseScope::Current),
        SCOPE_CHILDREN => Ok(ResponseScope::Subresults),
        SCOPE_ALL => Ok(ResponseScope::All),
        SCOPE_VARIABLE => {
            let variable = match element.property(SCOPE_VARIABLE_PROPERTY) {
                None => String::new(),
                Some(value) => {
                    let value = string_property(value, SCOPE_VARIABLE_PROPERTY)?;
                    validate_text(value, SCOPE_VARIABLE_PROPERTY, limits.max_property_bytes)?;
                    value.to_owned()
                }
            };
            Ok(ResponseScope::variable(variable))
        }
        _ => Err(BoundaryExtractorDecodeError::UnsupportedScope {
            property_bytes: scope.len(),
        }),
    }
}

/// Stable, redacted failure returned by the bounded pure boundary search.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundaryMatchError {
    /// The caller supplied a limit policy outside the production ceilings.
    InvalidLimits,
    /// An explicit search or value bound was exceeded.
    Limit { field: &'static str },
    /// A positive match number exceeded the configured match bound.
    MatchNumberLimit,
    /// Search arithmetic overflowed.
    Overflow,
}

impl BoundaryMatchError {
    /// Returns a stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidLimits => "app.boundary-extractor.search.limits",
            Self::Limit { .. } => "app.boundary-extractor.search.limit",
            Self::MatchNumberLimit => "app.boundary-extractor.search.match-number",
            Self::Overflow => "app.boundary-extractor.search.overflow",
        }
    }
}

impl fmt::Display for BoundaryMatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str(self.code()),
            Self::Limit { field } => write!(formatter, "{}: {field}", self.code()),
            Self::MatchNumberLimit | Self::Overflow => formatter.write_str(self.code()),
        }
    }
}

impl std::error::Error for BoundaryMatchError {}

/// Extracts boundary matches using the standard finite bounds.
pub fn extract_boundary_matches(
    left_boundary: &str,
    right_boundary: &str,
    input: &str,
    match_number: i32,
) -> Result<Vec<String>, BoundaryMatchError> {
    extract_boundary_matches_with_limits(
        left_boundary,
        right_boundary,
        input,
        match_number,
        BoundaryExtractorLimits::default(),
    )
}

/// Extracts matches from an already ordered stream of response strings.
///
/// The input iterator is already in JMeter's source order (parent/child/all
/// scope order is supplied by the runtime response resolver).  One bounded
/// search budget and one bounded match budget are shared across every record;
/// a later record cannot reset either resource counter.
pub fn extract_boundary_matches_from_inputs<'a, I>(
    left_boundary: &str,
    right_boundary: &str,
    inputs: I,
    match_number: i32,
    limits: BoundaryExtractorLimits,
) -> Result<Vec<String>, BoundaryMatchError>
where
    I: IntoIterator<Item = &'a str>,
{
    if limits.validate().is_err() {
        return Err(BoundaryMatchError::InvalidLimits);
    }
    if match_number > 0
        && usize::try_from(match_number)
            .ok()
            .is_some_and(|value| value > limits.max_matches)
    {
        return Err(BoundaryMatchError::MatchNumberLimit);
    }

    if left_boundary.len() > limits.max_boundary_bytes {
        return Err(BoundaryMatchError::Limit {
            field: "left-boundary-bytes",
        });
    }
    if right_boundary.len() > limits.max_boundary_bytes {
        return Err(BoundaryMatchError::Limit {
            field: "right-boundary-bytes",
        });
    }

    // BoundaryPattern allocates only after both boundary limits have been
    // checked.  The output starts empty and grows one bounded value at a time.
    let left = BoundaryPattern::new(left_boundary);
    let right = BoundaryPattern::new(right_boundary);
    let target = usize::try_from(match_number)
        .ok()
        .filter(|value| *value > 0);
    let mut matches = Vec::new();
    let mut found = 0usize;
    let mut steps = 0usize;
    for (input_index, input) in inputs.into_iter().enumerate() {
        if input_index >= BOUNDARY_MAX_INPUTS {
            return Err(BoundaryMatchError::Limit { field: "inputs" });
        }
        if input.len() > limits.max_input_bytes {
            return Err(BoundaryMatchError::Limit {
                field: "input-bytes",
            });
        }
        if scan_input(
            left_boundary,
            right_boundary,
            &left,
            &right,
            input,
            target,
            &mut found,
            &mut matches,
            &mut steps,
            limits,
        )? {
            return Ok(matches);
        }
    }
    Ok(matches)
}

/// Extracts boundary matches using explicit finite bounds.  The search uses a
/// bounded KMP scan and advances past each left boundary exactly as the pinned
/// JMeter loop does, so overlapping left boundaries are not re-used.
pub fn extract_boundary_matches_with_limits(
    left_boundary: &str,
    right_boundary: &str,
    input: &str,
    match_number: i32,
    limits: BoundaryExtractorLimits,
) -> Result<Vec<String>, BoundaryMatchError> {
    extract_boundary_matches_from_inputs(
        left_boundary,
        right_boundary,
        std::iter::once(input),
        match_number,
        limits,
    )
}

/// Scans one already bounded input and appends matches to the aggregate.
/// `found` is global to the invocation, so positive match numbers select by
/// flattened source order rather than restarting at each child result.
fn scan_input(
    left_boundary: &str,
    right_boundary: &str,
    left: &BoundaryPattern,
    right: &BoundaryPattern,
    input: &str,
    target: Option<usize>,
    found: &mut usize,
    matches: &mut Vec<String>,
    steps: &mut usize,
    limits: BoundaryExtractorLimits,
) -> Result<bool, BoundaryMatchError> {
    if is_blank(input) {
        return Ok(false);
    }

    let append = |value: &str, found: &mut usize| -> Result<bool, BoundaryMatchError> {
        *found = found.checked_add(1).ok_or(BoundaryMatchError::Overflow)?;
        if *found > limits.max_matches {
            return Err(BoundaryMatchError::Limit { field: "matches" });
        }
        ensure_value_bound(value, limits.max_value_bytes)?;
        if target == Some(*found) {
            matches.push(value.to_owned());
            return Ok(true);
        }
        if target.is_none() {
            if matches.len() >= limits.max_matches {
                return Err(BoundaryMatchError::Limit { field: "matches" });
            }
            matches.push(value.to_owned());
        }
        Ok(false)
    };

    if left_boundary.is_empty() && right_boundary.is_empty() {
        return append(input, found);
    }
    if left_boundary.is_empty() {
        let Some(end) = right.find_from(input.as_bytes(), 0, steps, limits.max_search_steps)?
        else {
            return Ok(false);
        };
        return append(&input[..end], found);
    }
    if right_boundary.is_empty() {
        let Some(start) = left.find_from(input.as_bytes(), 0, steps, limits.max_search_steps)?
        else {
            return Ok(false);
        };
        let value_start = start
            .checked_add(left_boundary.len())
            .ok_or(BoundaryMatchError::Overflow)?;
        return append(&input[value_start..], found);
    }

    // The upstream implementation advances by the left-boundary length,
    // intentionally permitting the right boundary to overlap the next
    // left-boundary search.
    let mut start_index = 0usize;
    while let Some(left_index) = left.find_from(
        input.as_bytes(),
        start_index,
        steps,
        limits.max_search_steps,
    )? {
        let after_left = left_index
            .checked_add(left_boundary.len())
            .ok_or(BoundaryMatchError::Overflow)?;
        let Some(right_index) =
            right.find_from(input.as_bytes(), after_left, steps, limits.max_search_steps)?
        else {
            break;
        };
        if append(&input[after_left..right_index], found)? {
            return Ok(true);
        }
        start_index = after_left;
    }
    Ok(false)
}

fn ensure_value_bound(value: &str, maximum: usize) -> Result<(), BoundaryMatchError> {
    if value.len() > maximum {
        return Err(BoundaryMatchError::Limit {
            field: "value-bytes",
        });
    }
    Ok(())
}

struct BoundaryPattern {
    bytes: Vec<u8>,
    prefix: Vec<usize>,
}

impl BoundaryPattern {
    fn new(value: &str) -> Self {
        let bytes = value.as_bytes().to_vec();
        let mut prefix = vec![0; bytes.len()];
        let mut length = 0usize;
        for index in 1..bytes.len() {
            while length > 0 && bytes[index] != bytes[length] {
                length = prefix[length - 1];
            }
            if bytes[index] == bytes[length] {
                length += 1;
            }
            prefix[index] = length;
        }
        Self { bytes, prefix }
    }

    fn find_from(
        &self,
        haystack: &[u8],
        start: usize,
        steps: &mut usize,
        maximum_steps: usize,
    ) -> Result<Option<usize>, BoundaryMatchError> {
        if self.bytes.is_empty() {
            return Ok(Some(start.min(haystack.len())));
        }
        if start >= haystack.len() {
            return Ok(None);
        }
        let mut matched = 0usize;
        for (index, byte) in haystack.iter().enumerate().skip(start) {
            while matched > 0 && *byte != self.bytes[matched] {
                bump_steps(steps, maximum_steps)?;
                matched = self.prefix[matched - 1];
            }
            bump_steps(steps, maximum_steps)?;
            if *byte == self.bytes[matched] {
                matched += 1;
                if matched == self.bytes.len() {
                    return Ok(index.checked_add(1).map(|end| end - self.bytes.len()));
                }
            }
        }
        Ok(None)
    }
}

fn bump_steps(steps: &mut usize, maximum: usize) -> Result<(), BoundaryMatchError> {
    *steps = steps.checked_add(1).ok_or(BoundaryMatchError::Overflow)?;
    if *steps > maximum {
        return Err(BoundaryMatchError::Limit {
            field: "search-steps",
        });
    }
    Ok(())
}

fn is_blank(value: &str) -> bool {
    value.is_empty() || value.chars().all(char::is_whitespace)
}

struct UnavailableResponseResolver {
    error: MutationError,
}

impl ScopedResponseResolver for UnavailableResponseResolver {
    fn resolve_scoped(
        &self,
        _current: Option<&jmeter_rs_results::SampleResult>,
        _variables: &BTreeMap<String, String>,
        _scope: &ResponseScope,
        _target: ResponseTarget,
        _decode_policy: &ResponseDecodePolicy,
    ) -> Result<ResponseResolution, MutationError> {
        Err(self.error)
    }
}

fn default_response_resolver(limits: BoundaryExtractorLimits) -> Arc<dyn ScopedResponseResolver> {
    let response_limits = ResponseLimits::default()
        .with_body_bytes(limits.max_input_bytes)
        .with_header_bytes(limits.max_input_bytes)
        .with_metadata_bytes(limits.max_property_bytes)
        .with_decoded_bytes(limits.max_input_bytes)
        .with_variable_bytes(limits.max_input_bytes)
        .with_items(BOUNDARY_MAX_INPUTS);
    match ResponseInputSetResolver::new(response_limits) {
        Ok(resolver) => Arc::new(resolver),
        Err(error) => Arc::new(UnavailableResponseResolver { error }),
    }
}

/// A per-user BoundaryExtractor factory.  `create` always constructs a fresh
/// postprocessor value; the immutable definition and response resolver are the
/// only shared state.
#[derive(Clone)]
pub struct BoundaryExtractorFactory {
    definition: Arc<BoundaryExtractorDefinition>,
    resolver: Arc<dyn ScopedResponseResolver>,
}

impl fmt::Debug for BoundaryExtractorFactory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundaryExtractorFactory")
            .field("definition", &self.definition)
            .field("resolver", &"<response-capability>")
            .finish()
    }
}

impl BoundaryExtractorFactory {
    /// Creates a factory with the default typed sample-result resolver.
    #[must_use]
    pub fn new(definition: BoundaryExtractorDefinition) -> Self {
        let limits = definition.limits;
        Self {
            definition: Arc::new(definition),
            resolver: default_response_resolver(limits),
        }
    }

    /// Installs an explicit response resolver capability.
    #[must_use]
    pub fn with_resolver(mut self, resolver: Arc<dyn ScopedResponseResolver>) -> Self {
        self.resolver = resolver;
        self
    }

    /// Returns the immutable decoded definition.
    #[must_use]
    pub fn definition(&self) -> &BoundaryExtractorDefinition {
        &self.definition
    }

    /// Creates one concrete postprocessor for a virtual user.
    #[must_use]
    pub fn postprocessor(&self) -> BoundaryExtractor {
        BoundaryExtractor {
            definition: Arc::clone(&self.definition),
            resolver: Arc::clone(&self.resolver),
        }
    }
}

impl PostprocessorFactory for BoundaryExtractorFactory {
    fn create(&self) -> Arc<dyn Postprocessor> {
        Arc::new(self.postprocessor())
    }
}

/// One per-user native BoundaryExtractor instance.
pub struct BoundaryExtractor {
    definition: Arc<BoundaryExtractorDefinition>,
    resolver: Arc<dyn ScopedResponseResolver>,
}

impl fmt::Debug for BoundaryExtractor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundaryExtractor")
            .field("definition", &self.definition)
            .field("resolver", &"<response-capability>")
            .finish()
    }
}

impl BoundaryExtractor {
    /// Creates a per-user instance with an explicit resolver.
    #[must_use]
    pub fn new(
        definition: BoundaryExtractorDefinition,
        resolver: Arc<dyn ScopedResponseResolver>,
    ) -> Self {
        Self {
            definition: Arc::new(definition),
            resolver,
        }
    }

    /// Returns the immutable decoded definition.
    #[must_use]
    pub fn definition(&self) -> &BoundaryExtractorDefinition {
        &self.definition
    }

    fn process_now(&self, context: &mut SampleContext<'_>) -> Result<(), ComponentError> {
        let signal = context.execution().control_signal();
        if signal != ControlSignal::Continue {
            return Err(ComponentError::Control(signal));
        }
        let target = if self.definition.use_headers {
            ResponseTarget::ResponseHeaders
        } else {
            ResponseTarget::Body
        };
        let decode_policy = ResponseDecodePolicy::declared_or_utf8();
        let variables = context.execution().variables();
        let resolution = self
            .resolver
            .resolve_scoped(
                context.result(),
                &variables,
                self.definition.scope(),
                target,
                &decode_policy,
            )
            .map_err(response_resolve_error)?;

        // A missing current result is a distinct resolution outcome.  JMeter
        // skips a postprocessor before it initializes defaults in this case;
        // do not turn it into an empty response or a default mutation.
        let matches = match resolution {
            ResponseResolution::NoCurrentResult => return Ok(()),
            ResponseResolution::Variable(value) => match value {
                Presence::Missing => Vec::new(),
                Presence::Present(value) => {
                    if value.len() > self.definition.limits.max_input_bytes {
                        return Err(ComponentError::resource_limit(
                            "app.boundary-extractor.response-variable",
                        ));
                    }
                    let value = decode_utf8_bounded(
                        value.as_bytes(),
                        self.definition.limits.max_input_bytes,
                    )
                    .map_err(decode_text_error)?;
                    extract_boundary_matches_with_limits(
                        self.definition.left_boundary(),
                        self.definition.right_boundary(),
                        &value,
                        self.definition.match_number(),
                        self.definition.limits,
                    )
                    .map_err(match_error)?
                }
            },
            ResponseResolution::Samples(inputs) => {
                let mut decoded = Vec::new();
                for (input_index, input) in inputs.items().iter().enumerate() {
                    if input_index >= BOUNDARY_MAX_INPUTS {
                        return Err(ComponentError::resource_limit(
                            "app.boundary-extractor.response-inputs",
                        ));
                    }
                    if let Some(value) =
                        selected_text(input, self.definition.limits, target, &decode_policy)?
                    {
                        decoded.push(value);
                    }
                }
                extract_boundary_matches_from_inputs(
                    self.definition.left_boundary(),
                    self.definition.right_boundary(),
                    decoded.iter().map(String::as_str),
                    self.definition.match_number(),
                    self.definition.limits,
                )
                .map_err(match_error)?
            }
        };
        drop(variables);

        // Extraction and mutation are intentionally kept in one candidate
        // delta.  Response/provider/decode/search failures return before this
        // point, so no configured default or stale-variable cleanup can leak
        // through an error path.
        let mut delta = InvocationDelta::new(context.context_generation());
        let variables = context.execution().variables();
        let count_key = match_count_key(self.definition.ref_name());
        let stale_count_malformed = variables
            .get(&count_key)
            .is_some_and(|value| parse_previous_count_with_status(value).1);
        let planned = plan_variable_mutations(
            &self.definition,
            &matches,
            &variables,
            context.execution().capabilities().random(),
        )?;
        drop(variables);
        if planned.len() > DEFAULT_MAX_MUTATIONS {
            return Err(ComponentError::resource_limit(
                "app.boundary-extractor.mutation-count",
            ));
        }
        for mutation in planned {
            let mutation = match mutation.value {
                PlannedValue::Set(value) => VariableMutation::set(mutation.key, value),
                PlannedValue::Remove => VariableMutation::remove(mutation.key),
            }
            .map_err(mutation_error)?;
            delta.add_variable(mutation).map_err(mutation_error)?;
        }
        if stale_count_malformed {
            let diagnostic = MutationDiagnostic::try_new(
                "app.boundary-extractor.stale-count",
                "malformed prior count treated as zero",
                MutationLimits::default(),
            )
            .map_err(mutation_error)?;
            delta.add_diagnostic(diagnostic).map_err(mutation_error)?;
        }
        match context.apply_invocation_delta(&delta) {
            Ok(_) => Ok(()),
            Err(error) if error.code() == MutationErrorCode::Cancelled => Err(
                ComponentError::Control(context.execution().control_signal()),
            ),
            Err(error) => Err(mutation_error(error)),
        }
    }
}

impl Postprocessor for BoundaryExtractor {
    fn process<'a>(&'a self, context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, ()> {
        Box::pin(async move { self.process_now(context) })
    }
}

fn response_resolve_error(error: MutationError) -> ComponentError {
    match error.code() {
        MutationErrorCode::ProviderUnavailable => {
            ComponentError::unsupported("app.boundary-extractor.response-capability")
        }
        MutationErrorCode::Limit => {
            ComponentError::resource_limit("app.boundary-extractor.response-limit")
        }
        _ => ComponentError::failure("app.boundary-extractor.response-resolve"),
    }
}

fn selected_text(
    input: &ResponseInput,
    limits: BoundaryExtractorLimits,
    _target: ResponseTarget,
    decode_policy: &ResponseDecodePolicy,
) -> Result<Option<String>, ComponentError> {
    let selection = match input.selected() {
        Presence::Missing => return Ok(None),
        Presence::Present(value) => value,
    };
    match selection {
        ResponseSelection::SourceText(value) => {
            if value.len() > limits.max_input_bytes {
                return Err(ComponentError::resource_limit(
                    "app.boundary-extractor.response-text",
                ));
            }
            // Headers, URL, code, message, and provider output are already
            // source text.  Their raw bytes remain in the runtime record; the
            // extractor only needs the bounded text projection here.
            decode_utf8_bounded(value.as_bytes(), limits.max_input_bytes)
                .map(Some)
                .map_err(decode_text_error)
        }
        ResponseSelection::Bytes(value) => {
            let encoding = match decode_policy {
                ResponseDecodePolicy::DeclaredOrDefault { default_encoding } => {
                    match &input.record().metadata.encoding {
                        Presence::Present(value) if !value.is_empty() => {
                            if value.len() > limits.max_property_bytes {
                                return Err(ComponentError::resource_limit(
                                    "app.boundary-extractor.encoding-name",
                                ));
                            }
                            value.to_string_lossy()
                        }
                        Presence::Missing | Presence::Present(_) => default_encoding.clone(),
                    }
                }
                ResponseDecodePolicy::Explicit { encoding } => encoding.clone(),
                ResponseDecodePolicy::Provider { .. } => {
                    return Err(ComponentError::unsupported(
                        "app.boundary-extractor.encoding-provider",
                    ));
                }
            };
            decode_text_with_limit(value.as_bytes(), &encoding, limits.max_input_bytes)
                .map(Some)
                .map_err(decode_text_error)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DecodeTextError {
    Limit,
    UnsupportedEncoding,
}

fn decode_text(bytes: &[u8], encoding: &str) -> Result<String, DecodeTextError> {
    decode_text_with_limit(bytes, encoding, DEFAULT_MAX_RESPONSE_BYTES)
}

fn decode_text_with_limit(
    bytes: &[u8],
    encoding: &str,
    maximum: usize,
) -> Result<String, DecodeTextError> {
    if maximum == 0 || bytes.len() > maximum || encoding.len() > BOUNDARY_MAX_PROPERTY_BYTES {
        return Err(DecodeTextError::Limit);
    }
    let normalized = encoding
        .bytes()
        .filter(|byte| !matches!(byte, b'-' | b'_' | b' '))
        .map(|byte| char::from(byte.to_ascii_uppercase()))
        .collect::<String>();
    match normalized.as_str() {
        "UTF8" => decode_utf8_bounded(bytes, maximum),
        "ASCII" | "USASCII" => decode_ascii_bounded(bytes, maximum),
        "ISO88591" | "LATIN1" | "L1" => decode_latin1_bounded(bytes, maximum),
        "WINDOWS1252" | "CP1252" => decode_windows_1252(bytes, maximum),
        "UTF16" => decode_utf16(bytes, None, maximum),
        "UTF16LE" => decode_utf16(bytes, Some(true), maximum),
        "UTF16BE" => decode_utf16(bytes, Some(false), maximum),
        _ => Err(DecodeTextError::UnsupportedEncoding),
    }
}

fn push_char_bounded(
    output: &mut String,
    value: char,
    maximum: usize,
) -> Result<(), DecodeTextError> {
    let mut encoded = [0_u8; 4];
    let encoded = value.encode_utf8(&mut encoded).as_bytes();
    let next = output
        .len()
        .checked_add(encoded.len())
        .ok_or(DecodeTextError::Limit)?;
    if next > maximum {
        return Err(DecodeTextError::Limit);
    }
    output.push(value);
    Ok(())
}

fn decode_utf8_bounded(bytes: &[u8], maximum: usize) -> Result<String, DecodeTextError> {
    let mut output = String::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        match std::str::from_utf8(&bytes[offset..]) {
            Ok(value) => {
                let next = output
                    .len()
                    .checked_add(value.len())
                    .ok_or(DecodeTextError::Limit)?;
                if next > maximum {
                    return Err(DecodeTextError::Limit);
                }
                output.push_str(value);
                break;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                if valid != 0 {
                    let next = output
                        .len()
                        .checked_add(valid)
                        .ok_or(DecodeTextError::Limit)?;
                    if next > maximum {
                        return Err(DecodeTextError::Limit);
                    }
                    let value = std::str::from_utf8(&bytes[offset..offset + valid])
                        .map_err(|_| DecodeTextError::UnsupportedEncoding)?;
                    output.push_str(value);
                }
                push_char_bounded(&mut output, '\u{fffd}', maximum)?;
                let invalid_len = error.error_len().unwrap_or(bytes.len() - offset - valid);
                offset = offset
                    .checked_add(valid)
                    .and_then(|value| value.checked_add(invalid_len))
                    .ok_or(DecodeTextError::Limit)?;
            }
        }
    }
    Ok(output)
}

fn decode_ascii_bounded(bytes: &[u8], maximum: usize) -> Result<String, DecodeTextError> {
    let mut output = String::new();
    for byte in bytes {
        let value = if byte.is_ascii() {
            char::from(*byte)
        } else {
            '\u{fffd}'
        };
        push_char_bounded(&mut output, value, maximum)?;
    }
    Ok(output)
}

fn decode_latin1_bounded(bytes: &[u8], maximum: usize) -> Result<String, DecodeTextError> {
    let mut output = String::new();
    for byte in bytes {
        push_char_bounded(&mut output, char::from(*byte), maximum)?;
    }
    Ok(output)
}

fn decode_windows_1252(bytes: &[u8], maximum: usize) -> Result<String, DecodeTextError> {
    const EXTENDED: [Option<char>; 32] = [
        Some('\u{20ac}'),
        None,
        Some('\u{201a}'),
        Some('\u{192}'),
        Some('\u{201e}'),
        Some('\u{2026}'),
        Some('\u{2020}'),
        Some('\u{2021}'),
        Some('\u{2c6}'),
        Some('\u{2030}'),
        Some('\u{160}'),
        Some('\u{2039}'),
        Some('\u{152}'),
        None,
        Some('\u{17d}'),
        None,
        None,
        Some('\u{2018}'),
        Some('\u{2019}'),
        Some('\u{201c}'),
        Some('\u{201d}'),
        Some('\u{2022}'),
        Some('\u{2013}'),
        Some('\u{2014}'),
        Some('\u{2dc}'),
        Some('\u{2122}'),
        Some('\u{161}'),
        Some('\u{203a}'),
        Some('\u{153}'),
        None,
        Some('\u{17e}'),
        Some('\u{178}'),
    ];
    let mut output = String::new();
    for byte in bytes {
        let value = match *byte {
            0x00..=0x7f | 0xa0..=0xff => char::from(*byte),
            value => EXTENDED[usize::from(value - 0x80)].unwrap_or('\u{fffd}'),
        };
        push_char_bounded(&mut output, value, maximum)?;
    }
    Ok(output)
}

fn decode_utf16(
    bytes: &[u8],
    little_endian: Option<bool>,
    maximum: usize,
) -> Result<String, DecodeTextError> {
    let (bytes, little_endian) = match (little_endian, bytes) {
        (None, [0xfe, 0xff, rest @ ..]) => (rest, false),
        (None, [0xff, 0xfe, rest @ ..]) => (rest, true),
        (None, _) => (bytes, false),
        (Some(little_endian), _) => (bytes, little_endian),
    };
    let mut output = String::new();
    let mut high_surrogate = None;
    for pair in bytes.chunks_exact(2) {
        let unit = if little_endian {
            u16::from_le_bytes([pair[0], pair[1]])
        } else {
            u16::from_be_bytes([pair[0], pair[1]])
        };
        match unit {
            0xd800..=0xdbff => {
                if high_surrogate.replace(unit).is_some() {
                    push_char_bounded(&mut output, '\u{fffd}', maximum)?;
                }
            }
            0xdc00..=0xdfff => {
                if let Some(high) = high_surrogate.take() {
                    let code_point =
                        0x1_0000 + (u32::from(high) - 0xd800) * 0x400 + (u32::from(unit) - 0xdc00);
                    push_char_bounded(
                        &mut output,
                        char::from_u32(code_point).unwrap_or('\u{fffd}'),
                        maximum,
                    )?;
                } else {
                    push_char_bounded(&mut output, '\u{fffd}', maximum)?;
                }
            }
            unit => {
                if high_surrogate.take().is_some() {
                    push_char_bounded(&mut output, '\u{fffd}', maximum)?;
                }
                push_char_bounded(
                    &mut output,
                    char::from_u32(u32::from(unit)).unwrap_or('\u{fffd}'),
                    maximum,
                )?;
            }
        }
    }
    if high_surrogate.take().is_some() {
        push_char_bounded(&mut output, '\u{fffd}', maximum)?;
    }
    if bytes.len() % 2 != 0 {
        push_char_bounded(&mut output, '\u{fffd}', maximum)?;
    }
    Ok(output)
}

fn decode_text_error(error: DecodeTextError) -> ComponentError {
    match error {
        DecodeTextError::Limit => {
            ComponentError::resource_limit("app.boundary-extractor.encoding-limit")
        }
        DecodeTextError::UnsupportedEncoding => {
            ComponentError::unsupported("app.boundary-extractor.encoding-unsupported")
        }
    }
}

fn match_error(error: BoundaryMatchError) -> ComponentError {
    match error {
        BoundaryMatchError::InvalidLimits => {
            ComponentError::resource_limit("app.boundary-extractor.search-limits")
        }
        BoundaryMatchError::Limit { .. }
        | BoundaryMatchError::MatchNumberLimit
        | BoundaryMatchError::Overflow => {
            ComponentError::resource_limit("app.boundary-extractor.search-limit")
        }
    }
}

fn mutation_error(error: MutationError) -> ComponentError {
    match error.code() {
        MutationErrorCode::Limit => {
            ComponentError::resource_limit("app.boundary-extractor.mutation-limit")
        }
        MutationErrorCode::ProviderUnavailable => {
            ComponentError::unsupported("app.boundary-extractor.mutation-provider")
        }
        MutationErrorCode::Cancelled => {
            ComponentError::failure("app.boundary-extractor.mutation-cancelled")
        }
        _ => ComponentError::failure("app.boundary-extractor.mutation-error"),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PlannedMutation {
    key: String,
    value: PlannedValue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PlannedValue {
    Set(String),
    Remove,
}

fn plan_variable_mutations(
    definition: &BoundaryExtractorDefinition,
    matches: &[String],
    variables: &BTreeMap<String, String>,
    random: &dyn RandomSource,
) -> Result<Vec<PlannedMutation>, ComponentError> {
    let count_key = match_count_key(definition.ref_name());
    let previous_count = match variables.get(&count_key) {
        None => 0,
        Some(value) => parse_previous_count(value),
    };
    if previous_count > definition.limits.max_matches {
        return Err(ComponentError::resource_limit(
            "app.boundary-extractor.stale-count-limit",
        ));
    }
    let mut planned = Vec::new();
    if definition.has_materialized_default() {
        plan_set(
            &mut planned,
            definition.ref_name().to_owned(),
            definition.default_value().to_owned(),
        );
    }
    match definition.match_number() {
        value if value < 0 => {
            plan_set(&mut planned, count_key.clone(), matches.len().to_string());
            for (index, value) in matches.iter().enumerate() {
                plan_set(
                    &mut planned,
                    indexed_name(definition.ref_name(), index + 1),
                    value.clone(),
                );
            }
            let first_stale = matches
                .len()
                .checked_add(1)
                .ok_or_else(|| ComponentError::resource_limit("app.boundary-extractor.index"))?;
            for index in first_stale..=previous_count {
                plan_remove(&mut planned, indexed_name(definition.ref_name(), index));
            }
        }
        0 => {
            plan_remove(&mut planned, count_key);
            for index in 1..=previous_count {
                plan_remove(&mut planned, indexed_name(definition.ref_name(), index));
            }
            if !matches.is_empty() {
                let random = select_random_match_with_source(matches, random)?;
                plan_set(&mut planned, definition.ref_name().to_owned(), random);
            }
        }
        _ => {
            plan_remove(&mut planned, count_key);
            for index in 1..=previous_count {
                plan_remove(&mut planned, indexed_name(definition.ref_name(), index));
            }
            if let Some(value) = matches.first() {
                plan_set(
                    &mut planned,
                    definition.ref_name().to_owned(),
                    value.clone(),
                );
            }
        }
    }
    if planned.len() > DEFAULT_MAX_MUTATIONS {
        return Err(ComponentError::resource_limit(
            "app.boundary-extractor.mutation-count",
        ));
    }
    Ok(planned)
}

#[allow(
    clippy::manual_unwrap_or_default,
    clippy::manual_unwrap_or,
    reason = "JMeter treats a malformed prior match count as zero after removing it"
)]
fn parse_previous_count(value: &str) -> usize {
    parse_previous_count_with_status(value).0
}

fn parse_previous_count_with_status(value: &str) -> (usize, bool) {
    match value.parse::<i32>() {
        Ok(count) if count >= 0 => match usize::try_from(count) {
            Ok(count) => (count, false),
            Err(_) => (0, true),
        },
        Ok(_) | Err(_) => (0, true),
    }
}

fn match_count_key(ref_name: &str) -> String {
    format!("{ref_name}{MATCH_COUNT_SUFFIX}")
}

fn indexed_name(ref_name: &str, index: usize) -> String {
    format!("{ref_name}_{index}")
}

fn plan_set(planned: &mut Vec<PlannedMutation>, key: String, value: String) {
    if let Some(existing) = planned.iter_mut().find(|item| item.key == key) {
        existing.value = PlannedValue::Set(value);
    } else {
        planned.push(PlannedMutation {
            key,
            value: PlannedValue::Set(value),
        });
    }
}

fn plan_remove(planned: &mut Vec<PlannedMutation>, key: String) {
    if let Some(existing) = planned.iter_mut().find(|item| item.key == key) {
        existing.value = PlannedValue::Remove;
    } else {
        planned.push(PlannedMutation {
            key,
            value: PlannedValue::Remove,
        });
    }
}

fn select_random_match_with_source(
    matches: &[String],
    random: &dyn jmeter_rs_runtime::RandomSource,
) -> Result<String, ComponentError> {
    if matches.is_empty() {
        return Err(ComponentError::failure(
            "app.boundary-extractor.random-empty",
        ));
    }
    let value = random.next_u64().map_err(random_error)?;
    let length = u64::try_from(matches.len())
        .map_err(|_| ComponentError::resource_limit("app.boundary-extractor.random-index"))?;
    let index = usize::try_from(value % length)
        .map_err(|_| ComponentError::resource_limit("app.boundary-extractor.random-index"))?;
    matches
        .get(index)
        .cloned()
        .ok_or_else(|| ComponentError::failure("app.boundary-extractor.random-index"))
}

fn random_error(error: CapabilityError) -> ComponentError {
    match error {
        CapabilityError::Unsupported(_) => {
            ComponentError::unsupported("app.boundary-extractor.random-unsupported")
        }
        CapabilityError::ResourceLimit(_) => {
            ComponentError::resource_limit("app.boundary-extractor.random-limit")
        }
        CapabilityError::Control(signal) => ComponentError::Control(signal),
        CapabilityError::Failure(_) => {
            ComponentError::failure("app.boundary-extractor.random-failure")
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;

    use jmeter_rs_model::NodeId;
    use jmeter_rs_results::{
        DataEncoding, HeaderBlock, SampleData, SampleResult, ValidationLimits,
    };
    use jmeter_rs_runtime::{
        ComponentFuture, ExecutionContext, PipelineError, RandomSource, SampleContext,
        SamplePackage, Sampler, SamplerOutput,
    };

    use super::*;

    struct FixedSampler {
        result: SampleResult,
    }

    impl Sampler for FixedSampler {
        fn sample<'a>(
            &'a self,
            _context: &'a mut SampleContext<'_>,
        ) -> ComponentFuture<'a, SamplerOutput> {
            Box::pin(std::future::ready(Ok(SamplerOutput::result(
                self.result.clone(),
            ))))
        }
    }

    struct NoResultSampler;

    impl Sampler for NoResultSampler {
        fn sample<'a>(
            &'a self,
            _context: &'a mut SampleContext<'_>,
        ) -> ComponentFuture<'a, SamplerOutput> {
            Box::pin(std::future::ready(Ok(SamplerOutput::no_result())))
        }
    }

    fn run_component(
        definition: BoundaryExtractorDefinition,
        result: SampleResult,
        mut execution: ExecutionContext,
    ) -> (Result<(), PipelineError>, ExecutionContext) {
        let package = SamplePackage::new(NodeId::new(1), Arc::new(FixedSampler { result }))
            .with_postprocessors(vec![Arc::new(definition.factory().postprocessor())]);
        let outcome = block_on(package.execute(&mut execution)).map(|_| ());
        (outcome, execution)
    }

    fn run_component_with_resolver(
        definition: BoundaryExtractorDefinition,
        result: SampleResult,
        mut execution: ExecutionContext,
        resolver: Arc<dyn ScopedResponseResolver>,
    ) -> (Result<(), PipelineError>, ExecutionContext) {
        let postprocessor = Arc::new(
            BoundaryExtractorFactory::new(definition)
                .with_resolver(resolver)
                .postprocessor(),
        );
        let package = SamplePackage::new(NodeId::new(1), Arc::new(FixedSampler { result }))
            .with_postprocessors(vec![postprocessor]);
        let outcome = block_on(package.execute(&mut execution)).map(|_| ());
        (outcome, execution)
    }

    fn run_without_result(
        definition: BoundaryExtractorDefinition,
        mut execution: ExecutionContext,
    ) -> (Result<(), PipelineError>, ExecutionContext) {
        let package = SamplePackage::new(NodeId::new(1), Arc::new(NoResultSampler))
            .with_postprocessors(vec![Arc::new(definition.factory().postprocessor())]);
        let outcome = block_on(package.execute(&mut execution)).map(|_| ());
        (outcome, execution)
    }

    #[derive(Clone, Copy)]
    struct UnavailableRandom;

    impl RandomSource for UnavailableRandom {
        fn next_u64(&self) -> Result<u64, CapabilityError> {
            Err(CapabilityError::unsupported("random-secret"))
        }

        fn clone_for_user(&self) -> Arc<dyn RandomSource> {
            Arc::new(Self)
        }
    }

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

    fn definition(match_number: i32) -> BoundaryExtractorDefinition {
        BoundaryExtractorDefinition::try_new(
            "capture",
            "[",
            "]",
            match_number,
            "DEFAULT",
            false,
            false,
        )
        .unwrap_or_else(|_| panic!("valid definition"))
    }

    #[test]
    fn exact_boundaries_cover_overlapping_and_empty_cases() {
        assert_eq!(
            extract_boundary_matches("[", "]", "[one][two]", -1).unwrap_or_default(),
            vec!["one", "two"]
        );
        assert_eq!(
            extract_boundary_matches("aa", "a", "aaaa", -1).unwrap_or_default(),
            vec![""]
        );
        assert_eq!(
            extract_boundary_matches("", "]", "one]tail", -1).unwrap_or_default(),
            vec!["one"]
        );
        assert_eq!(
            extract_boundary_matches("[", "", "head[tail", -1).unwrap_or_default(),
            vec!["tail"]
        );
        assert_eq!(
            extract_boundary_matches("", "", "whole", -1).unwrap_or_default(),
            vec!["whole"]
        );
    }

    #[test]
    fn match_modes_and_no_match_are_bounded() {
        assert_eq!(
            extract_boundary_matches("<", ">", "<a><b>", -1).unwrap_or_default(),
            vec!["a", "b"]
        );
        assert_eq!(
            extract_boundary_matches("<", ">", "<a><b>", 1).unwrap_or_default(),
            vec!["a"]
        );
        assert!(
            extract_boundary_matches("<", ">", "<a>", 2)
                .unwrap_or_default()
                .is_empty()
        );
        assert!(
            extract_boundary_matches("<", ">", "none", 0)
                .unwrap_or_default()
                .is_empty()
        );
        assert_eq!(
            extract_boundary_matches_from_inputs(
                "<",
                ">",
                ["parent <first>", "child <second>"],
                2,
                BoundaryExtractorLimits::default(),
            )
            .unwrap_or_default(),
            vec!["second"]
        );
        assert_eq!(
            extract_boundary_matches_from_inputs(
                "<",
                ">",
                ["parent <first>", "child <second>"],
                -1,
                BoundaryExtractorLimits::default(),
            )
            .unwrap_or_default(),
            vec!["first", "second"]
        );
        assert_eq!(
            extract_boundary_matches_from_inputs(
                "<",
                ">",
                ["<first>", "<second>"],
                2,
                BoundaryExtractorLimits::new(128, 64, 8, 4, 16, 64),
            )
            .unwrap_or_default(),
            vec!["second"]
        );
        assert_eq!(
            extract_boundary_matches_from_inputs(
                "<",
                ">",
                ["<first>", "<second>"],
                -1,
                BoundaryExtractorLimits::new(128, 64, 8, 4, 16, 8),
            )
            .unwrap_or_default(),
            vec!["first", "second"]
        );
        assert_eq!(
            extract_boundary_matches_from_inputs(
                "<",
                ">",
                ["<first>", "<second>"],
                -1,
                BoundaryExtractorLimits::new(128, 64, 8, 4, 16, 4),
            ),
            Err(BoundaryMatchError::Limit {
                field: "search-steps"
            })
        );
    }

    #[test]
    fn search_and_value_limits_fail_without_allocating_unbounded_output() {
        let limits = BoundaryExtractorLimits::new(128, 8, 4, 2, 2, 64);
        assert_eq!(
            extract_boundary_matches_with_limits("[", "]", "[one]", -1, limits),
            Err(BoundaryMatchError::Limit {
                field: "value-bytes"
            })
        );
        assert_eq!(
            extract_boundary_matches_with_limits(
                "[",
                "]",
                "[a][b]",
                -1,
                BoundaryExtractorLimits::new(128, 8, 4, 2, 2, 3),
            ),
            Err(BoundaryMatchError::Limit {
                field: "search-steps"
            })
        );
    }

    #[test]
    fn replacement_encoding_and_presence_distinctions_are_preserved() {
        let limits = BoundaryExtractorLimits::default();
        let resolver = ResponseInputSetResolver::new(ResponseLimits::default()).unwrap_or_default();
        let variables = BTreeMap::new();
        let mut missing_result = SampleResult::new("missing");
        let missing = resolver
            .resolve(
                Some(&missing_result),
                &variables,
                &ResponseScope::Current,
                ResponseTarget::Body,
                &ResponseDecodePolicy::default(),
            )
            .unwrap_or(ResponseResolution::NoCurrentResult);
        let missing = match missing {
            ResponseResolution::Samples(inputs) => inputs.items()[0].clone(),
            ResponseResolution::NoCurrentResult | ResponseResolution::Variable(_) => {
                panic!("sample resolution")
            }
        };
        assert_eq!(
            selected_text(
                &missing,
                limits,
                ResponseTarget::Body,
                &ResponseDecodePolicy::default()
            ),
            Ok(None)
        );

        missing_result.set_response_data(Some(SampleData::empty()));
        let empty = resolver
            .resolve(
                Some(&missing_result),
                &variables,
                &ResponseScope::Current,
                ResponseTarget::Body,
                &ResponseDecodePolicy::default(),
            )
            .unwrap_or(ResponseResolution::NoCurrentResult);
        let empty = match empty {
            ResponseResolution::Samples(inputs) => inputs.items()[0].clone(),
            ResponseResolution::NoCurrentResult | ResponseResolution::Variable(_) => {
                panic!("sample resolution")
            }
        };
        assert_eq!(
            selected_text(
                &empty,
                limits,
                ResponseTarget::Body,
                &ResponseDecodePolicy::default()
            )
            .unwrap_or_default(),
            Some(String::new())
        );
        assert_eq!(decode_text(&[0xff], "UTF-8"), Ok("�".to_owned()));
        assert_eq!(decode_text(&[0x00, 0xd8], "UTF-16LE"), Ok("�".to_owned()));
        assert_eq!(decode_text(&[0xe9], "ISO-8859-1"), Ok("é".to_owned()));
        assert_eq!(decode_text(&[0x41, 0x00], "UTF-16LE"), Ok("A".to_owned()));
        assert_eq!(
            decode_text(b"x", "x-unknown"),
            Err(DecodeTextError::UnsupportedEncoding)
        );
        let mut header_result = SampleResult::new("headers");
        header_result.set_response_headers_text("X: header");
        let headers = resolver
            .resolve(
                Some(&header_result),
                &variables,
                &ResponseScope::Current,
                ResponseTarget::ResponseHeaders,
                &ResponseDecodePolicy::default(),
            )
            .unwrap_or(ResponseResolution::NoCurrentResult);
        let headers = match headers {
            ResponseResolution::Samples(inputs) => inputs.items()[0].clone(),
            ResponseResolution::NoCurrentResult | ResponseResolution::Variable(_) => {
                panic!("sample resolution")
            }
        };
        assert_eq!(
            selected_text(
                &headers,
                limits,
                ResponseTarget::ResponseHeaders,
                &ResponseDecodePolicy::default(),
            )
            .unwrap_or_default(),
            Some("X: header".to_owned())
        );
        assert_eq!(
            extract_boundary_matches_with_limits(
                "[",
                "]",
                "[one]",
                -1,
                BoundaryExtractorLimits::new(0, 8, 4, 2, 2, 3),
            ),
            Err(BoundaryMatchError::InvalidLimits)
        );
    }

    #[test]
    fn definitions_reject_wrong_alias_unknown_properties_and_bad_match_numbers() {
        let mut element = TestElement::named(BOUNDARY_EXTRACTOR_ALIAS, "BoundaryExtractorGui", "x");
        element.set_property(REFNAME_PROPERTY, PropertyValue::string("capture"));
        element.set_property(MATCH_NUMBER_PROPERTY, PropertyValue::string("not-an-int"));
        assert!(matches!(
            decode_boundary_extractor(&element),
            Err(BoundaryExtractorDecodeError::InvalidInteger { .. })
        ));
        element.set_property(MATCH_NUMBER_PROPERTY, PropertyValue::string("0"));
        element.set_property("BoundaryExtractor.unknown", PropertyValue::string("secret"));
        assert!(matches!(
            decode_boundary_extractor(&element),
            Err(BoundaryExtractorDecodeError::UnsupportedProperty { .. })
        ));
        let wrong = TestElement::named("RegexExtractor", "RegexExtractorGui", "x");
        assert!(matches!(
            decode_boundary_extractor(&wrong),
            Err(BoundaryExtractorDecodeError::UnsupportedAlias { .. })
        ));
        let secret = "opaque-secret-property-value";
        element.remove_property("BoundaryExtractor.unknown");
        element.set_property(USE_HEADERS_PROPERTY, PropertyValue::string(secret));
        let error = decode_boundary_extractor(&element).expect_err("unsupported input selection");
        assert!(matches!(
            error,
            BoundaryExtractorDecodeError::UnsupportedInputSelection { .. }
        ));
        assert!(!error.to_string().contains(secret));

        let mut scoped =
            TestElement::named(BOUNDARY_EXTRACTOR_ALIAS, "BoundaryExtractorGui", "scope");
        scoped.set_property(REFNAME_PROPERTY, PropertyValue::string("capture"));
        scoped.set_property(SAMPLE_SCOPE_PROPERTY, PropertyValue::string("children"));
        let decoded = decode_boundary_extractor(&scoped).expect("children scope");
        assert_eq!(decoded.scope(), &ResponseScope::Subresults);
        scoped.set_property(SAMPLE_SCOPE_PROPERTY, PropertyValue::string("all"));
        assert_eq!(
            decode_boundary_extractor(&scoped)
                .expect("all scope")
                .scope(),
            &ResponseScope::All
        );
        scoped.set_property(SAMPLE_SCOPE_PROPERTY, PropertyValue::string("variable"));
        scoped.set_property(SCOPE_VARIABLE_PROPERTY, PropertyValue::string("source"));
        let decoded = decode_boundary_extractor(&scoped).expect("variable scope");
        assert_eq!(decoded.scope(), &ResponseScope::variable("source"));
        scoped.set_property(SAMPLE_SCOPE_PROPERTY, PropertyValue::string("unknown"));
        assert!(matches!(
            decode_boundary_extractor(&scoped),
            Err(BoundaryExtractorDecodeError::UnsupportedScope { .. })
        ));
    }

    #[test]
    fn variable_planning_cleans_stale_indexed_values_atomically() {
        let definition = definition(-1);
        let mut variables = BTreeMap::new();
        variables.insert("capture_matchNr".to_owned(), "3".to_owned());
        let planned = plan_variable_mutations(
            &definition,
            &["one".to_owned()],
            &variables,
            &jmeter_rs_runtime::ZeroRandom,
        )
        .unwrap_or_default();
        assert!(planned.iter().any(|item| {
            item.key == "capture_matchNr" && item.value == PlannedValue::Set("1".to_owned())
        }));
        assert!(
            planned
                .iter()
                .any(|item| { item.key == "capture_2" && item.value == PlannedValue::Remove })
        );
        assert!(
            planned
                .iter()
                .any(|item| { item.key == "capture_3" && item.value == PlannedValue::Remove })
        );

        let mut malformed = BTreeMap::new();
        malformed.insert("capture_matchNr".to_owned(), "not-an-integer".to_owned());
        let malformed_plan =
            plan_variable_mutations(&definition, &[], &malformed, &jmeter_rs_runtime::ZeroRandom)
                .unwrap_or_default();
        assert!(malformed_plan.iter().any(|item| {
            item.key == "capture_matchNr" && item.value == PlannedValue::Set("0".to_owned())
        }));
        assert!(
            !malformed_plan
                .iter()
                .any(|item| item.key == "capture_1" && item.value == PlannedValue::Remove)
        );
        let oversized_malformed =
            BTreeMap::from([("capture_matchNr".to_owned(), "2147483648".to_owned())]);
        let oversized_plan = plan_variable_mutations(
            &definition,
            &[],
            &oversized_malformed,
            &jmeter_rs_runtime::ZeroRandom,
        )
        .unwrap_or_default();
        assert!(oversized_plan.iter().any(|item| {
            item.key == "capture_matchNr" && item.value == PlannedValue::Set("0".to_owned())
        }));
    }

    #[test]
    fn random_planning_uses_capability_and_redacts_unsupported_errors() {
        let random = jmeter_rs_runtime::ZeroRandom;
        assert_eq!(
            select_random_match_with_source(&["one".to_owned(), "two".to_owned()], &random)
                .unwrap_or_default(),
            "one"
        );
        let error = random_error(CapabilityError::unsupported("random-secret"));
        assert_eq!(error.code(), "runtime.component.unsupported");
        assert!(!error.to_string().contains("random-secret"));
    }

    #[test]
    fn process_distinguishes_missing_and_present_empty_and_rolls_back_failures() {
        let definition =
            BoundaryExtractorDefinition::try_new("capture", "", "", -1, "", true, false)
                .unwrap_or_else(|_| panic!("valid definition"));
        let mut missing_execution = ExecutionContext::new();
        missing_execution.set_variable("capture", "before");
        let missing_result = SampleResult::new("missing");
        let (missing_outcome, missing_execution) =
            run_component(definition.clone(), missing_result, missing_execution);
        assert!(missing_outcome.is_ok());
        assert_eq!(missing_execution.variable("capture"), Some(String::new()));
        assert_eq!(
            missing_execution.variable("capture_matchNr"),
            Some("0".to_owned())
        );

        let mut empty_result = SampleResult::new("empty");
        empty_result.set_response_data(Some(SampleData::empty()));
        let (empty_outcome, empty_execution) =
            run_component(definition.clone(), empty_result, ExecutionContext::new());
        assert!(empty_outcome.is_ok());
        assert_eq!(empty_execution.variable("capture"), Some(String::new()));
        assert_eq!(
            empty_execution.variable("capture_matchNr"),
            Some("0".to_owned())
        );

        let fallback =
            BoundaryExtractorDefinition::try_new("capture", "[", "]", -1, "fallback", false, false)
                .unwrap_or_else(|_| panic!("valid fallback definition"));
        let mut fallback_execution = ExecutionContext::new();
        fallback_execution.set_variable("capture_matchNr", "2");
        fallback_execution.set_variable("capture_1", "stale-one");
        fallback_execution.set_variable("capture_2", "stale-two");
        let mut fallback_result = SampleResult::new("fallback");
        fallback_result.set_response_data(Some(SampleData::new(b"no-match".to_vec())));
        let (fallback_outcome, fallback_execution) =
            run_component(fallback, fallback_result, fallback_execution);
        assert!(fallback_outcome.is_ok());
        assert_eq!(
            fallback_execution.variable("capture"),
            Some("fallback".to_owned())
        );
        assert_eq!(
            fallback_execution.variable("capture_matchNr"),
            Some("0".to_owned())
        );
        assert_eq!(fallback_execution.variable("capture_1"), None);
        assert_eq!(fallback_execution.variable("capture_2"), None);

        let malformed_definition = BoundaryExtractorDefinition::try_new(
            "capture",
            "[",
            "]",
            -1,
            "malformed-fallback",
            false,
            false,
        )
        .unwrap_or_else(|_| panic!("valid malformed-count definition"));
        let mut malformed_execution = ExecutionContext::new();
        malformed_execution.set_variable("capture_matchNr", "not-an-integer");
        let mut malformed_result = SampleResult::new("malformed-count");
        malformed_result.set_response_data(Some(SampleData::new(b"none".to_vec())));
        let (malformed_outcome, malformed_execution) =
            run_component(malformed_definition, malformed_result, malformed_execution);
        assert!(malformed_outcome.is_ok());
        assert_eq!(
            malformed_execution.variable("capture_matchNr"),
            Some("0".to_owned())
        );
        assert_eq!(malformed_execution.mutation_diagnostics().len(), 1);
        assert_eq!(
            malformed_execution.mutation_diagnostics()[0].code(),
            "app.boundary-extractor.stale-count"
        );

        let random = BoundaryExtractorDefinition::try_new(
            "capture",
            "[",
            "]",
            0,
            "random-fallback",
            false,
            false,
        )
        .unwrap_or_else(|_| panic!("valid random fallback definition"));
        let mut random_execution = ExecutionContext::new();
        random_execution.set_variable("capture_matchNr", "1");
        random_execution.set_variable("capture_1", "stale");
        let mut random_result = SampleResult::new("random-no-match");
        random_result.set_response_data(Some(SampleData::new(b"none".to_vec())));
        let (random_outcome, random_execution) =
            run_component(random, random_result, random_execution);
        assert!(random_outcome.is_ok());
        assert_eq!(
            random_execution.variable("capture"),
            Some("random-fallback".to_owned())
        );
        assert_eq!(random_execution.variable("capture_matchNr"), None);
        assert_eq!(random_execution.variable("capture_1"), None);

        let replacement = BoundaryExtractorDefinition::try_new(
            "capture",
            "[",
            "]",
            -1,
            "encoding-fallback",
            false,
            false,
        )
        .unwrap_or_else(|_| panic!("valid encoding fallback definition"));
        let mut replacement_result = SampleResult::new("replacement");
        replacement_result.set_response_data(Some(SampleData::new(vec![0xff])));
        replacement_result.set_data_encoding(Some(DataEncoding::new("UTF-8")));
        let (replacement_outcome, replacement_execution) =
            run_component(replacement, replacement_result, ExecutionContext::new());
        assert!(replacement_outcome.is_ok());
        assert_eq!(
            replacement_execution.variable("capture"),
            Some("encoding-fallback".to_owned())
        );
        assert_eq!(
            replacement_execution.variable("capture_matchNr"),
            Some("0".to_owned())
        );

        let mut no_result_execution = ExecutionContext::new();
        no_result_execution.set_variable("capture", "before");
        let (no_result_outcome, no_result_execution) =
            run_without_result(definition, no_result_execution);
        assert!(no_result_outcome.is_ok());
        assert_eq!(
            no_result_execution.variable("capture"),
            Some("before".to_owned())
        );
    }

    #[test]
    fn process_selects_body_or_raw_headers_and_strict_random_capability() {
        let mut result = SampleResult::new("body-and-headers");
        result.set_response_data(Some(SampleData::new(b"[body]".to_vec())));
        result.set_response_headers(Some(HeaderBlock::new("[header]")));
        result.set_data_encoding(Some(DataEncoding::new("UTF-8")));
        let body = BoundaryExtractorDefinition::try_new("capture", "[", "]", 1, "", false, false)
            .unwrap_or_else(|_| panic!("valid body definition"));
        let (outcome, execution) = run_component(body, result.clone(), ExecutionContext::new());
        assert!(outcome.is_ok());
        assert_eq!(execution.variable("capture"), Some("body".to_owned()));

        let headers = BoundaryExtractorDefinition::try_new("capture", "[", "]", 1, "", false, true)
            .unwrap_or_else(|_| panic!("valid header definition"));
        let (outcome, execution) = run_component(headers, result.clone(), ExecutionContext::new());
        assert!(outcome.is_ok());
        assert_eq!(execution.variable("capture"), Some("header".to_owned()));

        let random = BoundaryExtractorDefinition::try_new("capture", "[", "]", 0, "", false, false)
            .unwrap_or_else(|_| panic!("valid random definition"));
        let capabilities = jmeter_rs_runtime::RuntimeCapabilities::default()
            .with_random(Arc::new(UnavailableRandom));
        let mut execution = ExecutionContext::with_capabilities(capabilities);
        execution.set_variable("capture", "before");
        let (outcome, execution) = run_component(random, result, execution);
        assert!(outcome.is_err());
        assert_eq!(execution.variable("capture"), Some("before".to_owned()));
    }

    #[test]
    fn process_resolves_each_sample_scope_and_flattens_source_order() {
        let mut root = SampleResult::new("root");
        root.set_response_data(Some(SampleData::new(b"[root]".to_vec())));
        root.set_response_headers_text("[root-header]");
        let mut first = SampleResult::new("first");
        first.set_response_data(Some(SampleData::new(b"[first]".to_vec())));
        first.set_response_headers_text("[first-header]");
        let mut nested = SampleResult::new("nested");
        nested.set_response_data(Some(SampleData::new(b"[nested]".to_vec())));
        nested.set_response_headers_text("[nested-header]");
        first
            .try_add_sub_result(nested, ValidationLimits::default())
            .unwrap_or_else(|_| panic!("nested result"));
        let mut second = SampleResult::new("second");
        second.set_response_data(Some(SampleData::new(b"[second]".to_vec())));
        second.set_response_headers_text("[second-header]");
        root.try_add_sub_result(first, ValidationLimits::default())
            .unwrap_or_else(|_| panic!("first result"));
        root.try_add_sub_result(second, ValidationLimits::default())
            .unwrap_or_else(|_| panic!("second result"));

        let parent = definition(-1)
            .with_scope(ResponseScope::Current)
            .unwrap_or_else(|_| panic!("parent scope"));
        let (_, execution) = run_component(parent, root.clone(), ExecutionContext::new());
        assert_eq!(execution.variable("capture_matchNr"), Some("1".to_owned()));
        assert_eq!(execution.variable("capture_1"), Some("root".to_owned()));

        let children = definition(-1)
            .with_scope(ResponseScope::Subresults)
            .unwrap_or_else(|_| panic!("children scope"));
        let (_, execution) = run_component(children, root.clone(), ExecutionContext::new());
        assert_eq!(execution.variable("capture_matchNr"), Some("2".to_owned()));
        assert_eq!(execution.variable("capture_1"), Some("first".to_owned()));
        assert_eq!(execution.variable("capture_2"), Some("second".to_owned()));

        let all = definition(-1)
            .with_scope(ResponseScope::All)
            .unwrap_or_else(|_| panic!("all scope"));
        let (_, execution) = run_component(all, root.clone(), ExecutionContext::new());
        assert_eq!(execution.variable("capture_matchNr"), Some("4".to_owned()));
        assert_eq!(execution.variable("capture_1"), Some("root".to_owned()));
        assert_eq!(execution.variable("capture_2"), Some("first".to_owned()));
        assert_eq!(execution.variable("capture_3"), Some("nested".to_owned()));
        assert_eq!(execution.variable("capture_4"), Some("second".to_owned()));

        let positive = definition(3)
            .with_scope(ResponseScope::All)
            .unwrap_or_else(|_| panic!("positive scope"));
        let (_, execution) = run_component(positive, root.clone(), ExecutionContext::new());
        assert_eq!(execution.variable("capture"), Some("nested".to_owned()));
        assert_eq!(execution.variable("capture_matchNr"), None);
        assert_eq!(execution.variable("capture_1"), None);

        let headers =
            BoundaryExtractorDefinition::try_new("capture", "[", "]", -1, "DEFAULT", false, true)
                .unwrap_or_else(|_| panic!("header definition"))
                .with_scope(ResponseScope::All)
                .unwrap_or_else(|_| panic!("header scope"));
        let (_, execution) = run_component(headers, root, ExecutionContext::new());
        assert_eq!(execution.variable("capture_matchNr"), Some("4".to_owned()));
        assert_eq!(
            execution.variable("capture_1"),
            Some("root-header".to_owned())
        );
        assert_eq!(
            execution.variable("capture_3"),
            Some("nested-header".to_owned())
        );
    }

    #[test]
    fn variable_scope_bypasses_sample_target_and_keeps_empty_present() {
        let definition = definition(-1)
            .with_scope(ResponseScope::variable("source"))
            .unwrap_or_else(|_| panic!("variable scope"));
        let mut execution = ExecutionContext::new();
        execution.set_variable("source", "[variable]");
        let mut result = SampleResult::new("ignored-sample");
        result.set_response_data(Some(SampleData::new(b"[sample]".to_vec())));
        let (_, execution) = run_component(definition, result, execution);
        assert_eq!(execution.variable("capture_matchNr"), Some("1".to_owned()));
        assert_eq!(execution.variable("capture_1"), Some("variable".to_owned()));

        let empty = BoundaryExtractorDefinition::try_new("capture", "[", "]", -1, "", true, false)
            .unwrap_or_else(|_| panic!("empty variable definition"))
            .with_scope(ResponseScope::variable("empty"))
            .unwrap_or_else(|_| panic!("empty variable scope"));
        let mut execution = ExecutionContext::new();
        execution.set_variable("empty", "");
        let (outcome, execution) = run_component(empty, SampleResult::new("sample"), execution);
        assert!(outcome.is_ok());
        assert_eq!(execution.variable("capture"), Some(String::new()));
        assert_eq!(execution.variable("capture_matchNr"), Some("0".to_owned()));
    }

    #[test]
    fn response_and_search_limits_abort_atomically() {
        let definition = definition(-1);
        let mut result = SampleResult::new("oversized");
        result.set_response_data(Some(SampleData::new(b"[too-long]".to_vec())));
        let resolver = ResponseInputSetResolver::new(ResponseLimits::default().with_body_bytes(4))
            .unwrap_or_default();
        let mut execution = ExecutionContext::new();
        execution.set_variable("capture", "before");
        let (outcome, execution) =
            run_component_with_resolver(definition.clone(), result, execution, Arc::new(resolver));
        assert!(outcome.is_err());
        assert_eq!(execution.variable("capture"), Some("before".to_owned()));
        assert_eq!(execution.variable("capture_matchNr"), None);

        let all = definition(-1)
            .with_scope(ResponseScope::All)
            .unwrap_or_else(|_| panic!("all scope"));
        let mut root = SampleResult::new("root");
        root.set_response_data(Some(SampleData::new(b"[root]".to_vec())));
        let mut child = SampleResult::new("child");
        child.set_response_data(Some(SampleData::new(b"[child]".to_vec())));
        child
            .try_add_sub_result(SampleResult::new("grandchild"), ValidationLimits::default())
            .unwrap_or_else(|_| panic!("grandchild"));
        root.try_add_sub_result(child, ValidationLimits::default())
            .unwrap_or_else(|_| panic!("child"));
        let depth_limited = ResponseInputSetResolver::new(ResponseLimits::default().with_depth(1))
            .unwrap_or_default();
        let mut execution = ExecutionContext::new();
        execution.set_variable("capture", "before");
        let (outcome, execution) = run_component_with_resolver(
            all.clone(),
            root.clone(),
            execution,
            Arc::new(depth_limited),
        );
        assert!(outcome.is_err());
        assert_eq!(execution.variable("capture"), Some("before".to_owned()));
        let item_limited = ResponseInputSetResolver::new(ResponseLimits::default().with_items(1))
            .unwrap_or_default();
        let mut execution = ExecutionContext::new();
        execution.set_variable("capture", "before");
        let (outcome, execution) =
            run_component_with_resolver(all, root, execution, Arc::new(item_limited));
        assert!(outcome.is_err());
        assert_eq!(execution.variable("capture"), Some("before".to_owned()));

        let search_limited = BoundaryExtractorDefinition::try_new_with_limits(
            BOUNDARY_EXTRACTOR_ALIAS,
            "capture",
            "[",
            "]",
            -1,
            "fallback",
            false,
            false,
            BoundaryExtractorLimits::new(128, 64, 4, 4, 16, 3),
        )
        .unwrap_or_else(|_| panic!("search definition"));
        let mut result = SampleResult::new("search");
        result.set_response_data(Some(SampleData::new(b"[one][two]".to_vec())));
        let mut execution = ExecutionContext::new();
        execution.set_variable("capture", "before");
        let (outcome, execution) = run_component(search_limited, result, execution);
        assert!(outcome.is_err());
        assert_eq!(execution.variable("capture"), Some("before".to_owned()));
        assert_eq!(execution.variable("capture_matchNr"), None);
    }

    #[test]
    fn unknown_encoding_and_provider_errors_never_apply_defaults() {
        let definition = definition(-1);
        let mut result = SampleResult::new("unknown-encoding");
        result.set_response_data(Some(SampleData::new(b"[value]".to_vec())));
        result.set_data_encoding(Some(DataEncoding::new("x-unknown")));
        let mut execution = ExecutionContext::new();
        execution.set_variable("capture", "before");
        let (outcome, execution) = run_component(definition, result, execution);
        assert!(outcome.is_err());
        assert_eq!(execution.variable("capture"), Some("before".to_owned()));
        assert_eq!(execution.variable("capture_matchNr"), None);

        let definition = definition(-1);
        let mut result = SampleResult::new("provider");
        result.set_response_data(Some(SampleData::new(b"[value]".to_vec())));
        let mut execution = ExecutionContext::new();
        execution.set_variable("capture", "before");
        let (outcome, execution) =
            run_component_with_resolver(definition, result, execution, Arc::new(FailingResolver));
        assert!(outcome.is_err());
        assert_eq!(execution.variable("capture"), Some("before".to_owned()));
        assert_eq!(execution.variable("capture_matchNr"), None);
    }

    struct FailingResolver;

    impl ScopedResponseResolver for FailingResolver {
        fn resolve_scoped(
            &self,
            _current: Option<&SampleResult>,
            _variables: &BTreeMap<String, String>,
            _scope: &ResponseScope,
            _target: ResponseTarget,
            _decode_policy: &ResponseDecodePolicy,
        ) -> Result<ResponseResolution, MutationError> {
            Err(MutationError::new(
                MutationErrorCode::ProviderUnavailable,
                "provider-test",
            ))
        }
    }
}
