// SPDX-License-Identifier: Apache-2.0
//! Native, bounded `UserParameters` and `RegExUserParameters` components.
//!
//! The decoder is deliberately kept at the application edge.  It accepts the
//! two short SaveService aliases and their exact Apache class names, retains
//! the source [`TestElement`], and exposes only typed projections needed by a
//! preprocessor factory.  Execution never writes a runtime map directly: one
//! complete [`InvocationDelta`] is validated and committed through
//! [`SampleContext::apply_invocation_delta`].
//!
//! JMeter's `UserParameters` implements both `PreProcessor` and
//! `LoopIterationListener`.  The runtime component trait has no lifecycle
//! callback, so the concrete native component exposes [`UserParameters::iteration_start`]
//! for the engine/lifecycle owner to call before the first preprocessor phase
//! of an iteration.  A per-iteration component fails closed when that callback
//! was not supplied; it does not lazily turn a preprocessor call into a
//! lifecycle event.

#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use jmeter_rs_model::{PropertyKind, PropertyValue, TestElement};
use jmeter_rs_runtime::{
    ComponentCategory, ComponentFuture, EncodedField, FactoryComponent, InvocationDelta,
    InvocationSnapshot, MutationError, MutationErrorCode, Preprocessor, PreprocessorFactory,
    Presence, QueryField, RequestPatch, SampleContext, ScopeComponent, ScopeComponentFactory,
    ScopeFactoryError, VariableMutation, DEFAULT_MAX_REQUEST_QUERY_FIELDS,
};

/// Short SaveService alias for JMeter's `UserParameters` element.
pub const USER_PARAMETERS_ALIAS: &str = "UserParameters";
/// Pinned Apache 5.6.3 class name for `UserParameters`.
pub const USER_PARAMETERS_CLASS: &str = "org.apache.jmeter.modifiers.UserParameters";
/// Short SaveService GUI alias for `UserParameters`.
pub const USER_PARAMETERS_GUI_ALIAS: &str = "UserParametersGui";
/// Pinned Apache 5.6.3 GUI class name for `UserParameters`.
pub const USER_PARAMETERS_GUI_CLASS: &str = "org.apache.jmeter.modifiers.gui.UserParametersGui";

/// Short SaveService alias for JMeter's `RegExUserParameters` element.
pub const REGEX_USER_PARAMETERS_ALIAS: &str = "RegExUserParameters";
/// Pinned Apache 5.6.3 class name for `RegExUserParameters`.
pub const REGEX_USER_PARAMETERS_CLASS: &str =
    "org.apache.jmeter.protocol.http.modifier.RegExUserParameters";
/// Short SaveService GUI alias for `RegExUserParameters`.
pub const REGEX_USER_PARAMETERS_GUI_ALIAS: &str = "RegExUserParametersGui";
/// Pinned Apache 5.6.3 GUI class name for `RegExUserParameters`.
pub const REGEX_USER_PARAMETERS_GUI_CLASS: &str =
    "org.apache.jmeter.protocol.http.modifier.gui.RegExUserParametersGui";

/// Exact case-sensitive `testclass` allowlist for `UserParameters`.
pub const USER_PARAMETERS_TEST_CLASSES: &[&str] = &[USER_PARAMETERS_ALIAS, USER_PARAMETERS_CLASS];
/// Exact case-sensitive `guiclass` allowlist for `UserParameters`.
pub const USER_PARAMETERS_GUI_CLASSES: &[&str] =
    &[USER_PARAMETERS_GUI_ALIAS, USER_PARAMETERS_GUI_CLASS];
/// Exact case-sensitive `testclass` allowlist for `RegExUserParameters`.
pub const REGEX_USER_PARAMETERS_TEST_CLASSES: &[&str] =
    &[REGEX_USER_PARAMETERS_ALIAS, REGEX_USER_PARAMETERS_CLASS];
/// Exact case-sensitive `guiclass` allowlist for `RegExUserParameters`.
pub const REGEX_USER_PARAMETERS_GUI_CLASSES: &[&str] = &[
    REGEX_USER_PARAMETERS_GUI_ALIAS,
    REGEX_USER_PARAMETERS_GUI_CLASS,
];

const USER_PARAMETERS_NAMES: &str = "UserParameters.names";
const USER_PARAMETERS_THREAD_VALUES: &str = "UserParameters.thread_values";
const USER_PARAMETERS_PER_ITERATION: &str = "UserParameters.per_iteration";
const REGEX_REF_NAME: &str = "RegExUserParameters.regex_ref_name";
const REGEX_PARAM_NAMES_GROUP: &str = "RegExUserParameters.param_names_gr_nr";
const REGEX_PARAM_VALUES_GROUP: &str = "RegExUserParameters.param_values_gr_nr";

/// The largest bounded text value accepted by this native processor.
pub const MAX_USER_PARAMETER_TEXT_BYTES: usize = 4 * 1024;
/// The largest number of variable names accepted by one element.
pub const MAX_USER_PARAMETER_NAMES: usize = 64;
/// The largest number of user rows accepted by one element.
pub const MAX_USER_PARAMETER_ROWS: usize = 64;
/// The largest number of values accepted in one user row.
pub const MAX_USER_PARAMETER_VALUES_PER_ROW: usize = 64;
/// The largest aggregate source/value byte count accepted by one element.
pub const MAX_USER_PARAMETER_TOTAL_BYTES: usize = 256 * 1024;
/// The largest regex match count consumed by this bounded adapter.
pub const MAX_REGEX_USER_PARAMETER_MATCHES: usize = 32;
/// The largest regex capture group number consumed by this bounded adapter.
pub const MAX_REGEX_USER_PARAMETER_CAPTURE_GROUP: usize = 8;

/// Explicit finite bounds for decoding and consuming both components.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserParametersLimits {
    /// Maximum number of names in `UserParameters.names`.
    pub max_names: usize,
    /// Maximum number of rows in `UserParameters.thread_values`.
    pub max_rows: usize,
    /// Maximum number of values in one row.
    pub max_values_per_row: usize,
    /// Maximum bytes in one name, value, or regex field.
    pub max_text_bytes: usize,
    /// Maximum aggregate bytes retained by one decoded element.
    pub max_total_bytes: usize,
    /// Maximum `matchNr` consumed by `RegExUserParameters`.
    pub max_matches: usize,
    /// Maximum capture-group number reserved by the shared ELEM-008 bounds;
    /// `RegExUserParameters` itself treats its configured group text as a
    /// literal suffix, as does pinned JMeter.
    pub max_capture_group: usize,
}

impl Default for UserParametersLimits {
    fn default() -> Self {
        Self {
            max_names: MAX_USER_PARAMETER_NAMES,
            max_rows: MAX_USER_PARAMETER_ROWS,
            max_values_per_row: MAX_USER_PARAMETER_VALUES_PER_ROW,
            max_text_bytes: MAX_USER_PARAMETER_TEXT_BYTES,
            max_total_bytes: MAX_USER_PARAMETER_TOTAL_BYTES,
            max_matches: MAX_REGEX_USER_PARAMETER_MATCHES,
            max_capture_group: MAX_REGEX_USER_PARAMETER_CAPTURE_GROUP,
        }
    }
}

impl UserParametersLimits {
    /// Creates bounds after checking every ceiling against the module's hard
    /// maximum.  A zero bound is never accepted.
    pub fn try_new(
        max_names: usize,
        max_rows: usize,
        max_values_per_row: usize,
        max_text_bytes: usize,
        max_total_bytes: usize,
        max_matches: usize,
        max_capture_group: usize,
    ) -> Result<Self, UserParametersDecodeError> {
        let limits = Self {
            max_names,
            max_rows,
            max_values_per_row,
            max_text_bytes,
            max_total_bytes,
            max_matches,
            max_capture_group,
        };
        limits.validate()?;
        Ok(limits)
    }

    fn validate(self) -> Result<(), UserParametersDecodeError> {
        let valid = self.max_names > 0
            && self.max_names <= MAX_USER_PARAMETER_NAMES
            && self.max_rows > 0
            && self.max_rows <= MAX_USER_PARAMETER_ROWS
            && self.max_values_per_row > 0
            && self.max_values_per_row <= MAX_USER_PARAMETER_VALUES_PER_ROW
            && self.max_text_bytes > 0
            && self.max_text_bytes <= MAX_USER_PARAMETER_TEXT_BYTES
            && self.max_total_bytes > 0
            && self.max_total_bytes <= MAX_USER_PARAMETER_TOTAL_BYTES
            && self.max_matches > 0
            && self.max_matches <= MAX_REGEX_USER_PARAMETER_MATCHES
            && self.max_capture_group > 0
            && self.max_capture_group <= MAX_REGEX_USER_PARAMETER_CAPTURE_GROUP;
        valid
            .then_some(())
            .ok_or(UserParametersDecodeError::InvalidLimits)
    }
}

/// The shape of a source collection.  The source `TestElement` is retained in
/// every decoded definition, so named entry identities remain lossless even
/// when the execution projection only needs their ordered values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectionEncoding {
    /// An unnamed ordered `collectionProp`.
    Collection,
    /// A named ordered collection.
    NamedCollection,
}

/// Source property order for `UserParameters`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserParametersProperty {
    /// `UserParameters.names`.
    Names,
    /// `UserParameters.thread_values`.
    ThreadValues,
    /// `UserParameters.per_iteration`.
    PerIteration,
}

/// Source property order for `RegExUserParameters`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegExUserParametersProperty {
    /// `RegExUserParameters.regex_ref_name`.
    RegexReferenceName,
    /// `RegExUserParameters.param_names_gr_nr`.
    ParameterNamesGroup,
    /// `RegExUserParameters.param_values_gr_nr`.
    ParameterValuesGroup,
}

/// Stable, redacted decoder failure for either native component.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UserParametersDecodeError {
    /// Bounds were zero or exceeded this module's hard maximum.
    InvalidLimits,
    /// The exact `testclass` allowlist rejected the source.
    UnsupportedTestClass { bytes: usize },
    /// The exact `guiclass` allowlist rejected the source.
    UnsupportedGuiClass { bytes: usize },
    /// A required property was absent.
    MissingProperty { property: &'static str },
    /// A source property was not part of the exact element schema.
    UnknownProperty { ordinal: usize },
    /// A property had the wrong typed model kind.
    InvalidPropertyType {
        property: &'static str,
        actual: PropertyKind,
    },
    /// A collection had the wrong shape.
    InvalidCollectionType {
        property: &'static str,
        actual: PropertyKind,
    },
    /// A collection entry had the wrong typed value.
    InvalidCollectionEntry {
        property: &'static str,
        index: usize,
        actual: PropertyKind,
    },
    /// A nested row was not a collection value.
    InvalidRowType { index: usize, actual: PropertyKind },
    /// An opaque extension would be lost by native decoding.
    OpaqueExtension,
    /// A temporary property would be lost by native decoding.
    TemporaryProperty,
    /// A finite source/value bound was exceeded.
    Limit {
        field: &'static str,
        actual: usize,
        limit: usize,
    },
}

impl UserParametersDecodeError {
    /// Returns a stable machine-readable code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidLimits => "app.user-parameters.invalid-limits",
            Self::UnsupportedTestClass { .. } => "app.user-parameters.testclass",
            Self::UnsupportedGuiClass { .. } => "app.user-parameters.guiclass",
            Self::MissingProperty { .. } => "app.user-parameters.missing-property",
            Self::UnknownProperty { .. } => "app.user-parameters.unknown-property",
            Self::InvalidPropertyType { .. } => "app.user-parameters.property-type",
            Self::InvalidCollectionType { .. } => "app.user-parameters.collection-type",
            Self::InvalidCollectionEntry { .. } => "app.user-parameters.collection-entry",
            Self::InvalidRowType { .. } => "app.user-parameters.row-type",
            Self::OpaqueExtension => "app.user-parameters.opaque-extension",
            Self::TemporaryProperty => "app.user-parameters.temporary-property",
            Self::Limit { .. } => "app.user-parameters.limit",
        }
    }
}

impl fmt::Display for UserParametersDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits | Self::OpaqueExtension | Self::TemporaryProperty => {
                formatter.write_str(self.code())
            }
            Self::UnsupportedTestClass { bytes } | Self::UnsupportedGuiClass { bytes } => {
                write!(formatter, "{}: {bytes} bytes", self.code())
            }
            Self::MissingProperty { property } => {
                write!(formatter, "{}: {property}", self.code())
            }
            Self::UnknownProperty { ordinal } => {
                write!(formatter, "{}: property ordinal {ordinal}", self.code())
            }
            Self::InvalidPropertyType { property, actual }
            | Self::InvalidCollectionType { property, actual } => {
                write!(formatter, "{}: {property} is {actual}", self.code())
            }
            Self::InvalidCollectionEntry {
                property,
                index,
                actual,
            } => write!(
                formatter,
                "{}: {property} entry {index} is {actual}",
                self.code()
            ),
            Self::InvalidRowType { index, actual } => {
                write!(formatter, "{}: row {index} is {actual}", self.code())
            }
            Self::Limit {
                field,
                actual,
                limit,
            } => write!(formatter, "{}: {field} {actual}/{limit}", self.code()),
        }
    }
}

impl std::error::Error for UserParametersDecodeError {}

/// A bounded failure returned by an injected expression capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpressionError {
    /// The resolver does not support the expression language/call.
    Unsupported,
    /// The expression is malformed.
    Invalid,
    /// The expression exceeded a resolver limit.
    Limit,
    /// The resolver rejected evaluation without exposing source text.
    Failed,
}

impl ExpressionError {
    /// Returns a stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unsupported => "app.user-parameters.expression-unsupported",
            Self::Invalid => "app.user-parameters.expression-invalid",
            Self::Limit => "app.user-parameters.expression-limit",
            Self::Failed => "app.user-parameters.expression-failed",
        }
    }
}

/// Explicit expression capability used by native processors.
///
/// The implementation owns the expression language and any required
/// provider.  The processor never consults ambient variables, properties,
/// environment, or a global registry.  The snapshot is immutable and is the
/// only state view supplied to the resolver.
pub trait ExpressionResolver: Send + Sync {
    /// Resolves one source value against one immutable invocation snapshot.
    fn resolve(
        &self,
        source: &str,
        snapshot: &InvocationSnapshot,
    ) -> Result<String, ExpressionError>;
}

/// Stable runtime failure from decoding, lifecycle, expression, or atomic
/// mutation validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UserParametersError {
    /// The source element could not be decoded.
    Decode(UserParametersDecodeError),
    /// A row-bearing component requires an explicit numeric thread identity.
    MissingThreadNumber,
    /// A per-iteration component requires an explicit iteration identity.
    MissingIterationIdentity,
    /// `UserParameters::iteration_start` was not called for the current
    /// iteration before `process`.
    IterationNotStarted,
    /// An expression source was supplied without an injected resolver.
    ExpressionCapabilityUnavailable { field: &'static str },
    /// An injected resolver rejected an expression.
    ExpressionRejected {
        field: &'static str,
        error: ExpressionError,
    },
    /// An empty source/resolved name cannot be represented by the runtime's
    /// validated `VariableMutation` key seam.  The source remains accepted;
    /// execution reports this explicit capability boundary rather than
    /// silently dropping the JMeter variable write.
    EmptyVariableNameUnsupported { index: usize },
    /// A resolved field exceeded a local bound.
    Limit {
        field: &'static str,
        actual: usize,
        limit: usize,
    },
    /// A regex `matchNr` variable was not a non-negative bounded integer.
    InvalidMatchCount,
    /// The request patch could not be built or committed.
    Mutation { code: MutationErrorCode },
}

impl UserParametersError {
    /// Returns a stable machine-readable code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Decode(error) => error.code(),
            Self::MissingThreadNumber => "app.user-parameters.thread-number",
            Self::MissingIterationIdentity => "app.user-parameters.iteration-identity",
            Self::IterationNotStarted => "app.user-parameters.iteration-not-started",
            Self::ExpressionCapabilityUnavailable { .. } => {
                "app.user-parameters.expression-capability"
            }
            Self::ExpressionRejected { error, .. } => error.code(),
            Self::EmptyVariableNameUnsupported { .. } => {
                "app.user-parameters.empty-name-unsupported"
            }
            Self::Limit { .. } => "app.user-parameters.limit",
            Self::InvalidMatchCount => "app.user-parameters.match-count",
            Self::Mutation { code } => code.as_str(),
        }
    }
}

impl fmt::Display for UserParametersError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => error.fmt(formatter),
            Self::MissingThreadNumber
            | Self::MissingIterationIdentity
            | Self::IterationNotStarted => formatter.write_str(self.code()),
            Self::ExpressionCapabilityUnavailable { field } => {
                write!(formatter, "{}: {field}", self.code())
            }
            Self::ExpressionRejected { field, error } => {
                write!(formatter, "{}: {field}: {}", self.code(), error.code())
            }
            Self::EmptyVariableNameUnsupported { index } => {
                write!(formatter, "{}: index {index}", self.code())
            }
            Self::Limit {
                field,
                actual,
                limit,
            } => write!(formatter, "{}: {field} {actual}/{limit}", self.code()),
            Self::InvalidMatchCount => formatter.write_str(self.code()),
            Self::Mutation { code } => formatter.write_str(code.as_str()),
        }
    }
}

impl std::error::Error for UserParametersError {}

/// A decoded, lossless `UserParameters` source element.
pub struct UserParametersDefinition {
    source: TestElement,
    names: Vec<String>,
    rows: Vec<Vec<String>>,
    names_encoding: CollectionEncoding,
    rows_encoding: CollectionEncoding,
    row_encodings: Vec<CollectionEncoding>,
    per_iteration: bool,
    property_order: Vec<UserParametersProperty>,
    limits: UserParametersLimits,
    /// Shared by all factory/definition clones, matching JMeter's clone-shared
    /// lock around expression evaluation and the complete variable update.
    lock: Arc<Mutex<()>>,
}

impl Clone for UserParametersDefinition {
    fn clone(&self) -> Self {
        Self {
            source: self.source.clone(),
            names: self.names.clone(),
            rows: self.rows.clone(),
            names_encoding: self.names_encoding,
            rows_encoding: self.rows_encoding,
            row_encodings: self.row_encodings.clone(),
            per_iteration: self.per_iteration,
            property_order: self.property_order.clone(),
            limits: self.limits,
            lock: Arc::clone(&self.lock),
        }
    }
}

impl PartialEq for UserParametersDefinition {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source
            && self.names == other.names
            && self.rows == other.rows
            && self.names_encoding == other.names_encoding
            && self.rows_encoding == other.rows_encoding
            && self.row_encodings == other.row_encodings
            && self.per_iteration == other.per_iteration
            && self.property_order == other.property_order
            && self.limits == other.limits
    }
}

impl fmt::Debug for UserParametersDefinition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UserParametersDefinition")
            .field("test_class_bytes", &self.source.test_class().len())
            .field("gui_class_bytes", &self.source.gui_class().len())
            .field("name_bytes", &self.source.name().len())
            .field("names_len", &self.names.len())
            .field("rows_len", &self.rows.len())
            .field("per_iteration", &self.per_iteration)
            .field("property_order", &self.property_order)
            .finish()
    }
}

impl UserParametersDefinition {
    /// Returns the exact retained source element, including property order
    /// and named collection entry identities.
    #[must_use]
    pub fn source(&self) -> &TestElement {
        &self.source
    }

    /// Returns ordered variable names after typed decoding.
    #[must_use]
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// Returns ordered per-user rows after typed decoding.
    #[must_use]
    pub fn rows(&self) -> &[Vec<String>] {
        &self.rows
    }

    /// Returns the `per_iteration` lifecycle flag.
    #[must_use]
    pub const fn per_iteration(&self) -> bool {
        self.per_iteration
    }

    /// Returns the source property order.
    #[must_use]
    pub fn property_order(&self) -> &[UserParametersProperty] {
        &self.property_order
    }

    /// Returns the source collection encodings for names and rows.
    #[must_use]
    pub const fn collection_encodings(&self) -> (CollectionEncoding, CollectionEncoding) {
        (self.names_encoding, self.rows_encoding)
    }

    /// Creates a per-user-isolated native factory.
    #[must_use]
    pub fn factory(&self, resolver: Option<Arc<dyn ExpressionResolver>>) -> UserParametersFactory {
        UserParametersFactory {
            definition: Arc::new(self.clone()),
            resolver,
        }
    }
}

/// A decoded, lossless `RegExUserParameters` source element.
#[derive(Clone, PartialEq)]
pub struct RegExUserParametersDefinition {
    source: TestElement,
    regex_reference_name: String,
    parameter_names_group: String,
    parameter_values_group: String,
    property_order: Vec<RegExUserParametersProperty>,
    limits: UserParametersLimits,
}

impl fmt::Debug for RegExUserParametersDefinition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegExUserParametersDefinition")
            .field("test_class_bytes", &self.source.test_class().len())
            .field("gui_class_bytes", &self.source.gui_class().len())
            .field("name_bytes", &self.source.name().len())
            .field(
                "regex_reference_name_bytes",
                &self.regex_reference_name.len(),
            )
            .field(
                "parameter_names_group_bytes",
                &self.parameter_names_group.len(),
            )
            .field(
                "parameter_values_group_bytes",
                &self.parameter_values_group.len(),
            )
            .field("property_order", &self.property_order)
            .finish()
    }
}

impl RegExUserParametersDefinition {
    /// Returns the exact retained source element.
    #[must_use]
    pub fn source(&self) -> &TestElement {
        &self.source
    }

    /// Returns the source regex-reference variable name.
    #[must_use]
    pub fn regex_reference_name(&self) -> &str {
        &self.regex_reference_name
    }

    /// Returns the source capture-group number for parameter names.
    #[must_use]
    pub fn parameter_names_group(&self) -> &str {
        &self.parameter_names_group
    }

    /// Returns the source capture-group number for parameter values.
    #[must_use]
    pub fn parameter_values_group(&self) -> &str {
        &self.parameter_values_group
    }

    /// Returns the source property order.
    #[must_use]
    pub fn property_order(&self) -> &[RegExUserParametersProperty] {
        &self.property_order
    }

    /// Creates a per-user-isolated native factory.
    #[must_use]
    pub fn factory(
        &self,
        resolver: Option<Arc<dyn ExpressionResolver>>,
    ) -> RegExUserParametersFactory {
        RegExUserParametersFactory {
            definition: Arc::new(self.clone()),
            resolver,
        }
    }
}

/// Decodes a `UserParameters` element with the profile-matched bounds.
pub fn decode_user_parameters(
    element: &TestElement,
) -> Result<UserParametersDefinition, UserParametersDecodeError> {
    decode_user_parameters_with_limits(element, UserParametersLimits::default())
}

/// Decodes a `UserParameters` element with explicit finite bounds.
pub fn decode_user_parameters_with_limits(
    element: &TestElement,
    limits: UserParametersLimits,
) -> Result<UserParametersDefinition, UserParametersDecodeError> {
    limits.validate()?;
    validate_element_identity(
        element,
        USER_PARAMETERS_TEST_CLASSES,
        USER_PARAMETERS_GUI_CLASSES,
        &limits,
    )?;
    reject_unretained_source(element)?;
    let property_order = property_order_user_parameters(element)?;
    let names_property = required_property(element, USER_PARAMETERS_NAMES)?;
    let rows_property = required_property(element, USER_PARAMETERS_THREAD_VALUES)?;
    let per_iteration_property = required_property(element, USER_PARAMETERS_PER_ITERATION)?;
    let (names_encoding, names) =
        decode_string_collection(names_property, USER_PARAMETERS_NAMES, &limits)?;
    let (rows_encoding, rows, row_encodings) = decode_rows(rows_property, &limits)?;
    let mut total_bytes = names.iter().try_fold(0usize, |total, value| {
        checked_add(total, value.len(), "total-bytes", limits.max_total_bytes)
    })?;
    for row in &rows {
        for value in row {
            total_bytes = checked_add(
                total_bytes,
                value.len(),
                "total-bytes",
                limits.max_total_bytes,
            )?;
        }
    }
    let per_iteration = per_iteration_property.as_boolean().map_err(|_| {
        UserParametersDecodeError::InvalidPropertyType {
            property: USER_PARAMETERS_PER_ITERATION,
            actual: per_iteration_property.kind(),
        }
    })?;
    Ok(UserParametersDefinition {
        source: element.clone(),
        names,
        rows,
        names_encoding,
        rows_encoding,
        row_encodings,
        per_iteration,
        property_order,
        limits,
        lock: Arc::new(Mutex::new(())),
    })
}

/// Decodes a `RegExUserParameters` element with profile-matched bounds.
pub fn decode_regex_user_parameters(
    element: &TestElement,
) -> Result<RegExUserParametersDefinition, UserParametersDecodeError> {
    decode_regex_user_parameters_with_limits(element, UserParametersLimits::default())
}

/// Decodes a `RegExUserParameters` element with explicit finite bounds.
pub fn decode_regex_user_parameters_with_limits(
    element: &TestElement,
    limits: UserParametersLimits,
) -> Result<RegExUserParametersDefinition, UserParametersDecodeError> {
    limits.validate()?;
    validate_element_identity(
        element,
        REGEX_USER_PARAMETERS_TEST_CLASSES,
        REGEX_USER_PARAMETERS_GUI_CLASSES,
        &limits,
    )?;
    reject_unretained_source(element)?;
    let property_order = property_order_regex(element)?;
    let reference = required_string_property(element, REGEX_REF_NAME, &limits)?;
    let names_group = required_string_property(element, REGEX_PARAM_NAMES_GROUP, &limits)?;
    let values_group = required_string_property(element, REGEX_PARAM_VALUES_GROUP, &limits)?;
    let total = checked_add(0, reference.len(), "total-bytes", limits.max_total_bytes)?;
    let total = checked_add(
        total,
        names_group.len(),
        "total-bytes",
        limits.max_total_bytes,
    )?;
    let _total = checked_add(
        total,
        values_group.len(),
        "total-bytes",
        limits.max_total_bytes,
    )?;
    Ok(RegExUserParametersDefinition {
        source: element.clone(),
        regex_reference_name: reference,
        parameter_names_group: names_group,
        parameter_values_group: values_group,
        property_order,
        limits,
    })
}

fn validate_element_identity(
    element: &TestElement,
    test_classes: &[&str],
    gui_classes: &[&str],
    limits: &UserParametersLimits,
) -> Result<(), UserParametersDecodeError> {
    if element.test_class().len() > limits.max_text_bytes {
        return Err(UserParametersDecodeError::Limit {
            field: "testclass",
            actual: element.test_class().len(),
            limit: limits.max_text_bytes,
        });
    }
    if element.gui_class().len() > limits.max_text_bytes {
        return Err(UserParametersDecodeError::Limit {
            field: "guiclass",
            actual: element.gui_class().len(),
            limit: limits.max_text_bytes,
        });
    }
    if element.name().len() > limits.max_text_bytes {
        return Err(UserParametersDecodeError::Limit {
            field: "testname",
            actual: element.name().len(),
            limit: limits.max_text_bytes,
        });
    }
    if !test_classes.contains(&element.test_class()) {
        return Err(UserParametersDecodeError::UnsupportedTestClass {
            bytes: element.test_class().len(),
        });
    }
    if !gui_classes.contains(&element.gui_class()) {
        return Err(UserParametersDecodeError::UnsupportedGuiClass {
            bytes: element.gui_class().len(),
        });
    }
    Ok(())
}

fn reject_unretained_source(element: &TestElement) -> Result<(), UserParametersDecodeError> {
    if !element.opaque_extensions.is_empty() {
        return Err(UserParametersDecodeError::OpaqueExtension);
    }
    if !element.temporary_properties.is_empty() {
        return Err(UserParametersDecodeError::TemporaryProperty);
    }
    Ok(())
}

fn required_property<'a>(
    element: &'a TestElement,
    property: &'static str,
) -> Result<&'a PropertyValue, UserParametersDecodeError> {
    element
        .property(property)
        .ok_or(UserParametersDecodeError::MissingProperty { property })
}

fn property_order_user_parameters(
    element: &TestElement,
) -> Result<Vec<UserParametersProperty>, UserParametersDecodeError> {
    // The native schema has exactly three persistent properties.  Bound the
    // diagnostic-order buffer before inspecting arbitrary source property
    // counts; an oversized unknown-property set must not become an allocation
    // request.
    let mut order = Vec::with_capacity(3);
    for (ordinal, property) in element.properties.keys().enumerate() {
        if ordinal >= 3 {
            return Err(UserParametersDecodeError::UnknownProperty { ordinal });
        }
        let value = match property {
            USER_PARAMETERS_NAMES => UserParametersProperty::Names,
            USER_PARAMETERS_THREAD_VALUES => UserParametersProperty::ThreadValues,
            USER_PARAMETERS_PER_ITERATION => UserParametersProperty::PerIteration,
            _ => return Err(UserParametersDecodeError::UnknownProperty { ordinal }),
        };
        order.push(value);
    }
    Ok(order)
}

fn property_order_regex(
    element: &TestElement,
) -> Result<Vec<RegExUserParametersProperty>, UserParametersDecodeError> {
    let mut order = Vec::with_capacity(3);
    for (ordinal, property) in element.properties.keys().enumerate() {
        if ordinal >= 3 {
            return Err(UserParametersDecodeError::UnknownProperty { ordinal });
        }
        let value = match property {
            REGEX_REF_NAME => RegExUserParametersProperty::RegexReferenceName,
            REGEX_PARAM_NAMES_GROUP => RegExUserParametersProperty::ParameterNamesGroup,
            REGEX_PARAM_VALUES_GROUP => RegExUserParametersProperty::ParameterValuesGroup,
            _ => return Err(UserParametersDecodeError::UnknownProperty { ordinal }),
        };
        order.push(value);
    }
    Ok(order)
}

fn required_string_property(
    element: &TestElement,
    property: &'static str,
    limits: &UserParametersLimits,
) -> Result<String, UserParametersDecodeError> {
    let value = required_property(element, property)?;
    let value = value
        .as_string()
        .map_err(|_| UserParametersDecodeError::InvalidPropertyType {
            property,
            actual: value.kind(),
        })?;
    validate_text(value, "property", limits)?;
    Ok(value.to_owned())
}

fn decode_string_collection(
    value: &PropertyValue,
    property: &'static str,
    limits: &UserParametersLimits,
) -> Result<(CollectionEncoding, Vec<String>), UserParametersDecodeError> {
    let (encoding, length) = match value {
        PropertyValue::Collection(entries) => (CollectionEncoding::Collection, entries.len()),
        PropertyValue::NamedCollection(entries) => {
            (CollectionEncoding::NamedCollection, entries.len())
        }
        other => {
            return Err(UserParametersDecodeError::InvalidCollectionType {
                property,
                actual: other.kind(),
            });
        }
    };
    if length > limits.max_names {
        return Err(UserParametersDecodeError::Limit {
            field: "names",
            actual: length,
            limit: limits.max_names,
        });
    }
    let mut values = Vec::with_capacity(length);
    if let PropertyValue::Collection(entries) = value {
        for (index, value) in entries.iter().enumerate() {
            values.push(decode_string_entry(value, property, index, limits)?);
        }
    } else if let PropertyValue::NamedCollection(entries) = value {
        for (index, entry) in entries.iter().enumerate() {
            values.push(decode_string_entry(&entry.value, property, index, limits)?);
        }
    } else {
        return Err(UserParametersDecodeError::InvalidCollectionType {
            property,
            actual: value.kind(),
        });
    }
    Ok((encoding, values))
}

fn decode_rows(
    value: &PropertyValue,
    limits: &UserParametersLimits,
) -> Result<DecodedRows, UserParametersDecodeError> {
    let (encoding, length) = match value {
        PropertyValue::Collection(entries) => (CollectionEncoding::Collection, entries.len()),
        PropertyValue::NamedCollection(entries) => {
            (CollectionEncoding::NamedCollection, entries.len())
        }
        other => {
            return Err(UserParametersDecodeError::InvalidCollectionType {
                property: USER_PARAMETERS_THREAD_VALUES,
                actual: other.kind(),
            });
        }
    };
    if length > limits.max_rows {
        return Err(UserParametersDecodeError::Limit {
            field: "rows",
            actual: length,
            limit: limits.max_rows,
        });
    }
    let mut rows = Vec::with_capacity(length);
    let mut row_encodings = Vec::with_capacity(length);
    if let PropertyValue::Collection(entries) = value {
        for (index, value) in entries.iter().enumerate() {
            let (row_encoding, row) = decode_row(value, index, limits)?;
            row_encodings.push(row_encoding);
            rows.push(row);
        }
    } else if let PropertyValue::NamedCollection(entries) = value {
        for (index, entry) in entries.iter().enumerate() {
            let (row_encoding, row) = decode_row(&entry.value, index, limits)?;
            row_encodings.push(row_encoding);
            rows.push(row);
        }
    } else {
        return Err(UserParametersDecodeError::InvalidCollectionType {
            property: USER_PARAMETERS_THREAD_VALUES,
            actual: value.kind(),
        });
    }
    Ok((encoding, rows, row_encodings))
}

type DecodedRows = (
    CollectionEncoding,
    Vec<Vec<String>>,
    Vec<CollectionEncoding>,
);

/// One typed projection of a regex match. `None` preserves a missing later
/// JMeter variable as far as the runtime's non-null string map permits.
type RegexParameter = (Option<String>, Option<String>);

fn decode_row(
    value: &PropertyValue,
    row_index: usize,
    limits: &UserParametersLimits,
) -> Result<(CollectionEncoding, Vec<String>), UserParametersDecodeError> {
    let (encoding, length) = match value {
        PropertyValue::Collection(entries) => (CollectionEncoding::Collection, entries.len()),
        PropertyValue::NamedCollection(entries) => {
            (CollectionEncoding::NamedCollection, entries.len())
        }
        other => {
            return Err(UserParametersDecodeError::InvalidRowType {
                index: row_index,
                actual: other.kind(),
            });
        }
    };
    if length > limits.max_values_per_row {
        return Err(UserParametersDecodeError::Limit {
            field: "row-values",
            actual: length,
            limit: limits.max_values_per_row,
        });
    }
    let mut row = Vec::with_capacity(length);
    if let PropertyValue::Collection(entries) = value {
        for (index, value) in entries.iter().enumerate() {
            row.push(decode_string_entry(
                value,
                USER_PARAMETERS_THREAD_VALUES,
                index,
                limits,
            )?);
        }
    } else if let PropertyValue::NamedCollection(entries) = value {
        for (index, entry) in entries.iter().enumerate() {
            row.push(decode_string_entry(
                &entry.value,
                USER_PARAMETERS_THREAD_VALUES,
                index,
                limits,
            )?);
        }
    } else {
        return Err(UserParametersDecodeError::InvalidRowType {
            index: row_index,
            actual: value.kind(),
        });
    }
    Ok((encoding, row))
}

fn decode_string_entry(
    value: &PropertyValue,
    property: &'static str,
    index: usize,
    limits: &UserParametersLimits,
) -> Result<String, UserParametersDecodeError> {
    let value =
        value
            .as_string()
            .map_err(|_| UserParametersDecodeError::InvalidCollectionEntry {
                property,
                index,
                actual: value.kind(),
            })?;
    validate_text(value, "value", limits)?;
    Ok(value.to_owned())
}

fn validate_text(
    value: &str,
    field: &'static str,
    limits: &UserParametersLimits,
) -> Result<(), UserParametersDecodeError> {
    if value.len() > limits.max_text_bytes {
        return Err(UserParametersDecodeError::Limit {
            field,
            actual: value.len(),
            limit: limits.max_text_bytes,
        });
    }
    Ok(())
}

fn checked_add(
    current: usize,
    value: usize,
    field: &'static str,
    limit: usize,
) -> Result<usize, UserParametersDecodeError> {
    let total = current
        .checked_add(value)
        .ok_or(UserParametersDecodeError::Limit {
            field,
            actual: usize::MAX,
            limit,
        })?;
    if total > limit {
        return Err(UserParametersDecodeError::Limit {
            field,
            actual: total,
            limit,
        });
    }
    Ok(total)
}

/// Returns whether a value contains an unescaped expression reference.
fn contains_expression(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0usize;
    while index + 1 < bytes.len() {
        if bytes[index] == b'$' && bytes[index + 1] == b'{' {
            let mut escaped = false;
            let mut cursor = index;
            while cursor > 0 && bytes[cursor - 1] == b'\\' {
                // Only slash parity matters. Toggling avoids arithmetic on
                // an untrusted source-length count.
                escaped = !escaped;
                cursor -= 1;
            }
            if !escaped {
                return true;
            }
        }
        index += 1;
    }
    false
}

fn map_mutation(error: MutationError) -> UserParametersError {
    UserParametersError::Mutation { code: error.code() }
}

fn map_component_error(error: UserParametersError) -> jmeter_rs_runtime::ComponentError {
    match error {
        UserParametersError::ExpressionCapabilityUnavailable { .. }
        | UserParametersError::EmptyVariableNameUnsupported { .. }
        | UserParametersError::ExpressionRejected {
            error: ExpressionError::Unsupported,
            ..
        } => jmeter_rs_runtime::ComponentError::unsupported(error.to_string()),
        UserParametersError::Limit { .. }
        | UserParametersError::Decode(UserParametersDecodeError::Limit { .. })
        | UserParametersError::Decode(UserParametersDecodeError::InvalidLimits) => {
            jmeter_rs_runtime::ComponentError::resource_limit(error.to_string())
        }
        _ => jmeter_rs_runtime::ComponentError::failure(error.to_string()),
    }
}

fn bounded_source_identity(value: &str) -> String {
    const LIMIT: usize = 256;
    if value.len() <= LIMIT {
        return value.to_owned();
    }
    let mut end = LIMIT;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn scope_decode(component: &ScopeComponent, error: UserParametersError) -> ScopeFactoryError {
    ScopeFactoryError::Decode {
        node_id: component.node_id,
        path: component.path.clone(),
        test_class: bounded_source_identity(&component.binding.test_class),
        category: ComponentCategory::Preprocessor,
        detail: bounded_source_identity(&error.to_string()),
    }
}

fn ensure_scope_component(component: &ScopeComponent) -> Result<(), ScopeFactoryError> {
    if component.binding.category != ComponentCategory::Preprocessor {
        return Err(ScopeFactoryError::CategoryMismatch {
            node_id: component.node_id,
            path: component.path.clone(),
            expected: ComponentCategory::Preprocessor,
            actual: component.binding.category,
        });
    }
    if component.binding.test_class != component.element.test_class() {
        return Err(ScopeFactoryError::IdentityMismatch {
            node_id: component.node_id,
            path: component.path.clone(),
            expected: bounded_source_identity(&component.binding.test_class),
            actual: bounded_source_identity(component.element.test_class()),
        });
    }
    Ok(())
}

/// A per-user `UserParameters` instance.
pub struct UserParameters {
    definition: Arc<UserParametersDefinition>,
    resolver: Option<Arc<dyn ExpressionResolver>>,
    limits: UserParametersLimits,
    lock: Arc<Mutex<()>>,
    started_iteration: Mutex<Option<u64>>,
}

impl fmt::Debug for UserParameters {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UserParameters")
            .field("source_name_bytes", &self.definition.source.name().len())
            .field("per_iteration", &self.definition.per_iteration)
            .field("resolver_injected", &self.resolver.is_some())
            .field("limits", &self.limits)
            .finish()
    }
}

impl UserParameters {
    /// Returns the immutable decoded definition used by this instance.
    #[must_use]
    pub fn definition(&self) -> &UserParametersDefinition {
        &self.definition
    }

    /// Applies the lifecycle callback for the current root iteration.
    ///
    /// The callback is a no-op for a non-per-iteration element, matching
    /// JMeter's listener registration behavior.  A successful callback marks
    /// the iteration only after the complete variable delta commits.
    pub fn iteration_start(
        &self,
        context: &mut SampleContext<'_>,
    ) -> Result<(), UserParametersError> {
        // Pinned UserParameters.clone() shares one lock between every thread
        // clone. Hold it across expression resolution and the complete atomic
        // delta commit, not merely around the lifecycle marker.
        let _shared_lock = lock_mutex(&self.lock);
        if !self.definition.per_iteration {
            return Ok(());
        }
        let iteration = context
            .execution()
            .iteration_id()
            .ok_or(UserParametersError::MissingIterationIdentity)?;
        let row = self.row_for_context(context)?;
        self.apply_row(context, row)?;
        *lock_mutex(&self.started_iteration) = Some(iteration);
        Ok(())
    }

    /// Runs the preprocessor synchronously through the atomic mutation seam.
    ///
    /// For `per_iteration == false`, pinned JMeter calls this method's
    /// equivalent on every preprocessor invocation.  The fresh instance from
    /// [`UserParametersFactory`] supplies per-user isolation; there is no
    /// component-local "first call" shortcut that would change later
    /// function/expression evaluations.  For `per_iteration == true`, the
    /// listener callback above owns the one mutation at iteration start and
    /// this method is a no-op after the callback succeeds.
    pub fn apply(&self, context: &mut SampleContext<'_>) -> Result<(), UserParametersError> {
        let _shared_lock = lock_mutex(&self.lock);
        if self.definition.per_iteration {
            let iteration = context
                .execution()
                .iteration_id()
                .ok_or(UserParametersError::MissingIterationIdentity)?;
            if *lock_mutex(&self.started_iteration) != Some(iteration) {
                return Err(UserParametersError::IterationNotStarted);
            }
            // JMeter's per-iteration listener owns the mutation.  The
            // preprocessor callback is deliberately a no-op after that
            // lifecycle event; applying the row again would be observable to
            // an injected resolver and would no longer match the pinned
            // listener/preprocessor split.
            return Ok(());
        }
        let row = self.row_for_context(context)?;
        self.apply_row(context, row)
    }

    fn row_for_context<'a>(
        &'a self,
        context: &SampleContext<'_>,
    ) -> Result<Option<&'a [String]>, UserParametersError> {
        if self.definition.rows.is_empty() {
            return Ok(None);
        }
        let thread = context
            .execution()
            .thread()
            .number()
            .ok_or(UserParametersError::MissingThreadNumber)?;
        let row = (thread % self.definition.rows.len() as u64) as usize;
        Ok(self.definition.rows.get(row).map(Vec::as_slice))
    }

    fn apply_row(
        &self,
        context: &mut SampleContext<'_>,
        row: Option<&[String]>,
    ) -> Result<(), UserParametersError> {
        let Some(row) = row else {
            return Ok(());
        };
        let snapshot = context.snapshot_processor_invocation();
        let mut resolved = BTreeMap::new();
        let mut total = 0usize;
        for (index, (name, value)) in self.definition.names.iter().zip(row).enumerate() {
            let name = resolve_text(
                name,
                "UserParameters.names",
                self.resolver.as_ref(),
                &snapshot,
            )?;
            let value = resolve_text(
                value,
                "UserParameters.thread_values",
                self.resolver.as_ref(),
                &snapshot,
            )?;
            if name.len() > self.limits.max_text_bytes || value.len() > self.limits.max_text_bytes {
                return Err(UserParametersError::Limit {
                    field: "resolved-value",
                    actual: name.len().max(value.len()),
                    limit: self.limits.max_text_bytes,
                });
            }
            total = total
                .checked_add(name.len())
                .and_then(|current| current.checked_add(value.len()))
                .ok_or(UserParametersError::Limit {
                    field: "resolved-total-bytes",
                    actual: usize::MAX,
                    limit: self.limits.max_total_bytes,
                })?;
            if total > self.limits.max_total_bytes {
                return Err(UserParametersError::Limit {
                    field: "resolved-total-bytes",
                    actual: total,
                    limit: self.limits.max_total_bytes,
                });
            }
            // JMeterVariables.put is map-like: duplicate names overwrite the
            // earlier value, and the final write wins. Keep the source index
            // only for a deterministic empty-name capability diagnostic.
            resolved.insert(name, (index, value));
        }
        let mut delta = InvocationDelta::new(snapshot.generation());
        for (name, (index, value)) in resolved {
            if name.is_empty() {
                // The runtime's validated VariableMutation key contract
                // rejects empty keys. Do not silently omit this JMeter write;
                // report the explicit seam limitation before any delta can
                // commit.
                return Err(UserParametersError::EmptyVariableNameUnsupported { index });
            }
            let mutation = VariableMutation::set(name, value).map_err(map_mutation)?;
            delta.add_variable(mutation).map_err(map_mutation)?;
        }
        context
            .apply_invocation_delta(&delta)
            .map_err(map_mutation)?;
        Ok(())
    }
}

impl Preprocessor for UserParameters {
    fn process<'a>(&'a self, context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, ()> {
        Box::pin(async move { self.apply(context).map_err(map_component_error) })
    }
}

/// A per-user-isolated factory for `UserParameters`.
#[derive(Clone)]
pub struct UserParametersFactory {
    definition: Arc<UserParametersDefinition>,
    resolver: Option<Arc<dyn ExpressionResolver>>,
}

impl fmt::Debug for UserParametersFactory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UserParametersFactory")
            .field(
                "definition_name_bytes",
                &self.definition.source.name().len(),
            )
            .field("resolver_injected", &self.resolver.is_some())
            .finish()
    }
}

impl UserParametersFactory {
    /// Constructs a factory from a decoded definition and optional explicit
    /// expression capability.
    #[must_use]
    pub fn new(
        definition: UserParametersDefinition,
        resolver: Option<Arc<dyn ExpressionResolver>>,
    ) -> Self {
        Self {
            definition: Arc::new(definition),
            resolver,
        }
    }

    /// Creates a fresh component whose lifecycle state is not shared with any
    /// other virtual user.
    #[must_use]
    pub fn create_instance(&self) -> Arc<UserParameters> {
        Arc::new(UserParameters {
            definition: Arc::clone(&self.definition),
            resolver: self.resolver.clone(),
            limits: self.definition.limits,
            lock: Arc::clone(&self.definition.lock),
            started_iteration: Mutex::new(None),
        })
    }
}

impl PreprocessorFactory for UserParametersFactory {
    fn create(&self) -> Arc<dyn Preprocessor> {
        self.create_instance()
    }
}

/// A decode-and-factory hook for later centralized scope registration.
#[derive(Clone)]
pub struct UserParametersScopeFactory {
    resolver: Option<Arc<dyn ExpressionResolver>>,
    limits: UserParametersLimits,
}

impl fmt::Debug for UserParametersScopeFactory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UserParametersScopeFactory")
            .field("resolver_injected", &self.resolver.is_some())
            .field("limits", &self.limits)
            .finish()
    }
}

impl UserParametersScopeFactory {
    /// Creates a scope hook with explicit expression capability and bounds.
    pub fn new(
        resolver: Option<Arc<dyn ExpressionResolver>>,
        limits: UserParametersLimits,
    ) -> Result<Self, UserParametersDecodeError> {
        limits.validate()?;
        Ok(Self { resolver, limits })
    }
}

impl ScopeComponentFactory for UserParametersScopeFactory {
    fn create(&self, component: &ScopeComponent) -> Result<FactoryComponent, ScopeFactoryError> {
        ensure_scope_component(component)?;
        let definition = decode_user_parameters_with_limits(&component.element, self.limits)
            .map_err(|error| scope_decode(component, UserParametersError::Decode(error)))?;
        let factory = definition.factory(self.resolver.clone());
        Ok(FactoryComponent::Preprocessor(factory.create_instance()))
    }
}

/// A per-user `RegExUserParameters` instance.
pub struct RegExUserParameters {
    definition: Arc<RegExUserParametersDefinition>,
    resolver: Option<Arc<dyn ExpressionResolver>>,
    limits: UserParametersLimits,
}

impl fmt::Debug for RegExUserParameters {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegExUserParameters")
            .field("source_name_bytes", &self.definition.source.name().len())
            .field("resolver_injected", &self.resolver.is_some())
            .field("limits", &self.limits)
            .finish()
    }
}

impl RegExUserParameters {
    /// Returns the immutable decoded definition used by this instance.
    #[must_use]
    pub fn definition(&self) -> &RegExUserParametersDefinition {
        &self.definition
    }

    /// Runs the preprocessor synchronously through the atomic mutation seam.
    pub fn apply(&self, context: &mut SampleContext<'_>) -> Result<(), UserParametersError> {
        let snapshot = context.snapshot_processor_invocation();
        if snapshot.request().query_fields().is_empty() {
            // The typed runtime projection is the only HTTP-argument proof
            // available here.  An absent/empty projection covers a
            // non-HTTP sampler and an HTTP sampler with no arguments; both
            // are pinned no-op outcomes before variable/config evaluation.
            return Ok(());
        }
        let reference = resolve_text(
            &self.definition.regex_reference_name,
            REGEX_REF_NAME,
            self.resolver.as_ref(),
            &snapshot,
        )?;
        let names_group = resolve_text(
            &self.definition.parameter_names_group,
            REGEX_PARAM_NAMES_GROUP,
            self.resolver.as_ref(),
            &snapshot,
        )?;
        let values_group = resolve_text(
            &self.definition.parameter_values_group,
            REGEX_PARAM_VALUES_GROUP,
            self.resolver.as_ref(),
            &snapshot,
        )?;
        let base = bounded_regex_base(&reference, &self.limits)?;
        let Some(parameters) =
            self.build_parameter_map(&snapshot, &base, &names_group, &values_group)?
        else {
            // Pinned Java behavior is an explicit no-op when the referenced
            // RegexExtractor variables are absent.
            return Ok(());
        };
        if parameters.is_empty() {
            return Ok(());
        }

        let query_fields = snapshot.request().query_fields();
        if query_fields.len() > DEFAULT_MAX_REQUEST_QUERY_FIELDS {
            return Err(UserParametersError::Limit {
                field: "request-query-fields",
                actual: query_fields.len(),
                limit: DEFAULT_MAX_REQUEST_QUERY_FIELDS,
            });
        }
        let current_query = query_fields.to_vec();
        let mut changed = false;
        let mut candidate_query = Vec::with_capacity(current_query.len());
        for field in current_query {
            let Some(name) = query_name(&field) else {
                candidate_query.push(field);
                continue;
            };
            let Some(value) = last_parameter_value(&parameters, name) else {
                candidate_query.push(field);
                continue;
            };
            let mut replacement = field;
            replacement.value =
                Presence::Present(EncodedField::raw(value.to_owned()).map_err(map_mutation)?);
            changed = true;
            candidate_query.push(replacement);
        }
        if !changed {
            return Ok(());
        }

        let mut delta = InvocationDelta::new(snapshot.generation());
        let patch = RequestPatch::new(snapshot.request().generation(), snapshot.request().digest());
        let mut patch = patch;
        patch.replace_query_fields(candidate_query);
        delta.set_request_patch(patch);
        context
            .apply_invocation_delta(&delta)
            .map_err(map_mutation)?;
        Ok(())
    }

    fn build_parameter_map(
        &self,
        snapshot: &InvocationSnapshot,
        base: &str,
        names_group: &str,
        values_group: &str,
    ) -> Result<Option<Vec<RegexParameter>>, UserParametersError> {
        let variables = snapshot.variables();
        let match_key = bounded_key(base, "matchNr", self.limits.max_text_bytes)?;
        let Some(match_value) = variables.get(&match_key) else {
            return Ok(None);
        };
        let first_name_key = bounded_group_key(base, 1, names_group, self.limits.max_text_bytes)?;
        let first_value_key = bounded_group_key(base, 1, values_group, self.limits.max_text_bytes)?;
        if !variables.contains_key(&first_name_key) || !variables.contains_key(&first_value_key) {
            return Ok(None);
        }
        let count = parse_java_match_count(match_value)?;
        if count < 0 {
            // Java constructs HashMap<>(n) before its loop. A negative
            // initial capacity throws, so preserve it as a typed failure.
            return Err(UserParametersError::InvalidMatchCount);
        }
        let count = count as usize;
        if count > self.limits.max_matches {
            return Err(UserParametersError::Limit {
                field: "match-count",
                actual: count,
                limit: self.limits.max_matches,
            });
        }
        let mut parameters = Vec::with_capacity(count);
        for index in 1..=count {
            let name_key = bounded_group_key(base, index, names_group, self.limits.max_text_bytes)?;
            let value_key =
                bounded_group_key(base, index, values_group, self.limits.max_text_bytes)?;
            let name = variables.get(&name_key).cloned();
            let value = variables.get(&value_key).cloned();
            if name
                .as_deref()
                .is_some_and(|name| name.len() > self.limits.max_text_bytes)
                || value
                    .as_deref()
                    .is_some_and(|value| value.len() > self.limits.max_text_bytes)
            {
                return Err(UserParametersError::Limit {
                    field: "regex-value",
                    actual: name
                        .as_deref()
                        .map_or(0, str::len)
                        .max(value.as_deref().map_or(0, str::len)),
                    limit: self.limits.max_text_bytes,
                });
            }
            // JMeterVariables has no typed null distinction in the runtime
            // snapshot. Missing later groups therefore become None, which is
            // observationally equivalent for request replacement: a null
            // map value causes `paramMap.get(argName) != null` to be false.
            parameters.push((name, value));
        }
        Ok(Some(parameters))
    }
}

impl Preprocessor for RegExUserParameters {
    fn process<'a>(&'a self, context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, ()> {
        Box::pin(async move { self.apply(context).map_err(map_component_error) })
    }
}

/// A per-user-isolated factory for `RegExUserParameters`.
#[derive(Clone)]
pub struct RegExUserParametersFactory {
    definition: Arc<RegExUserParametersDefinition>,
    resolver: Option<Arc<dyn ExpressionResolver>>,
}

impl fmt::Debug for RegExUserParametersFactory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegExUserParametersFactory")
            .field(
                "definition_name_bytes",
                &self.definition.source.name().len(),
            )
            .field("resolver_injected", &self.resolver.is_some())
            .finish()
    }
}

impl RegExUserParametersFactory {
    /// Constructs a factory from a decoded definition and optional expression
    /// capability.
    #[must_use]
    pub fn new(
        definition: RegExUserParametersDefinition,
        resolver: Option<Arc<dyn ExpressionResolver>>,
    ) -> Self {
        Self {
            definition: Arc::new(definition),
            resolver,
        }
    }

    /// Creates a fresh component.  No mutable state is shared between users.
    #[must_use]
    pub fn create_instance(&self) -> Arc<RegExUserParameters> {
        Arc::new(RegExUserParameters {
            definition: Arc::clone(&self.definition),
            resolver: self.resolver.clone(),
            limits: self.definition.limits,
        })
    }
}

impl PreprocessorFactory for RegExUserParametersFactory {
    fn create(&self) -> Arc<dyn Preprocessor> {
        self.create_instance()
    }
}

/// A decode-and-factory hook for later centralized scope registration.
#[derive(Clone)]
pub struct RegExUserParametersScopeFactory {
    resolver: Option<Arc<dyn ExpressionResolver>>,
    limits: UserParametersLimits,
}

impl fmt::Debug for RegExUserParametersScopeFactory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegExUserParametersScopeFactory")
            .field("resolver_injected", &self.resolver.is_some())
            .field("limits", &self.limits)
            .finish()
    }
}

impl RegExUserParametersScopeFactory {
    /// Creates a scope hook with explicit expression capability and bounds.
    pub fn new(
        resolver: Option<Arc<dyn ExpressionResolver>>,
        limits: UserParametersLimits,
    ) -> Result<Self, UserParametersDecodeError> {
        limits.validate()?;
        Ok(Self { resolver, limits })
    }
}

impl ScopeComponentFactory for RegExUserParametersScopeFactory {
    fn create(&self, component: &ScopeComponent) -> Result<FactoryComponent, ScopeFactoryError> {
        ensure_scope_component(component)?;
        let definition = decode_regex_user_parameters_with_limits(&component.element, self.limits)
            .map_err(|error| scope_decode(component, UserParametersError::Decode(error)))?;
        let factory = RegExUserParametersFactory {
            definition: Arc::new(definition),
            resolver: self.resolver.clone(),
        };
        Ok(FactoryComponent::Preprocessor(factory.create_instance()))
    }
}

fn resolve_text(
    source: &str,
    field: &'static str,
    resolver: Option<&Arc<dyn ExpressionResolver>>,
    snapshot: &InvocationSnapshot,
) -> Result<String, UserParametersError> {
    if !contains_expression(source) {
        return Ok(source.to_owned());
    }
    let resolver =
        resolver.ok_or(UserParametersError::ExpressionCapabilityUnavailable { field })?;
    resolver
        .resolve(source, snapshot)
        .map_err(|error| UserParametersError::ExpressionRejected { field, error })
}

fn parse_java_match_count(value: &str) -> Result<i32, UserParametersError> {
    // Integer.parseInt accepts an optional sign and ASCII decimal digits,
    // rejects whitespace/other text, and is bounded to signed 32-bit range.
    // Parse incrementally so an arbitrarily long source value cannot overflow
    // or allocate an intermediate integer/string.
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        return Err(UserParametersError::InvalidMatchCount);
    }
    let (negative, digits) = match bytes[0] {
        b'+' => (false, &bytes[1..]),
        b'-' => (true, &bytes[1..]),
        _ => (false, bytes),
    };
    if digits.is_empty() {
        return Err(UserParametersError::InvalidMatchCount);
    }
    let mut magnitude = 0u64;
    for digit in digits {
        if !digit.is_ascii_digit() {
            return Err(UserParametersError::InvalidMatchCount);
        }
        magnitude = magnitude
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(digit - b'0')))
            .ok_or(UserParametersError::InvalidMatchCount)?;
        let maximum = if negative {
            i32::MAX as u64 + 1
        } else {
            i32::MAX as u64
        };
        if magnitude > maximum {
            return Err(UserParametersError::InvalidMatchCount);
        }
    }
    if negative {
        if magnitude == i32::MAX as u64 + 1 {
            Ok(i32::MIN)
        } else {
            Ok(-(magnitude as i32))
        }
    } else {
        Ok(magnitude as i32)
    }
}

fn bounded_regex_base(
    reference: &str,
    limits: &UserParametersLimits,
) -> Result<String, UserParametersError> {
    if reference.len() > limits.max_text_bytes {
        return Err(UserParametersError::Limit {
            field: "regex-reference-name",
            actual: reference.len(),
            limit: limits.max_text_bytes,
        });
    }
    let capacity = reference
        .len()
        .checked_add(1)
        .ok_or(UserParametersError::Limit {
            field: "regex-reference-name",
            actual: usize::MAX,
            limit: limits.max_text_bytes,
        })?;
    let mut base = String::with_capacity(capacity);
    base.push_str(reference);
    base.push('_');
    if base.len() > limits.max_text_bytes {
        return Err(UserParametersError::Limit {
            field: "regex-reference-name",
            actual: base.len(),
            limit: limits.max_text_bytes,
        });
    }
    Ok(base)
}

fn bounded_key(base: &str, suffix: &str, limit: usize) -> Result<String, UserParametersError> {
    let length = base
        .len()
        .checked_add(suffix.len())
        .ok_or(UserParametersError::Limit {
            field: "regex-key",
            actual: usize::MAX,
            limit,
        })?;
    if length > limit {
        return Err(UserParametersError::Limit {
            field: "regex-key",
            actual: length,
            limit,
        });
    }
    let mut key = String::with_capacity(length);
    key.push_str(base);
    key.push_str(suffix);
    Ok(key)
}

fn bounded_group_key(
    base: &str,
    index: usize,
    group: &str,
    limit: usize,
) -> Result<String, UserParametersError> {
    let index = index.to_string();
    let suffix_length = index
        .len()
        .checked_add(2)
        .and_then(|length| length.checked_add(group.len()))
        .ok_or(UserParametersError::Limit {
            field: "regex-key",
            actual: usize::MAX,
            limit,
        })?;
    let total_length = base
        .len()
        .checked_add(suffix_length)
        .ok_or(UserParametersError::Limit {
            field: "regex-key",
            actual: usize::MAX,
            limit,
        })?;
    if total_length > limit {
        return Err(UserParametersError::Limit {
            field: "regex-key",
            actual: total_length,
            limit,
        });
    }
    let mut key = String::with_capacity(total_length);
    key.push_str(base);
    key.push_str(&index);
    key.push_str("_g");
    key.push_str(group);
    Ok(key)
}

fn query_name(field: &QueryField) -> Option<&str> {
    match &field.name.raw {
        Presence::Present(value) => Some(value.as_str()),
        Presence::Missing => match &field.name.encoded {
            Presence::Present(value) => Some(value.as_str()),
            Presence::Missing => None,
        },
    }
}

fn last_parameter_value<'a>(parameters: &'a [RegexParameter], name: &str) -> Option<&'a str> {
    parameters
        .iter()
        .rev()
        .find(|(parameter, _)| parameter.as_deref() == Some(name))
        .and_then(|(_, value)| value.as_deref())
}

fn lock_mutex<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // Poisoning means a previous component panicked while holding only this
    // private lifecycle ledger.  Treat it as an empty ledger rather than
    // exposing a panic to untrusted plan input.
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jmeter_rs_model::NodeId;
    use jmeter_rs_runtime::{
        ComponentFuture, ExecutionContext, RequestGeneration, RequestState, RequestStateParts,
        SamplePackage, Sampler, SamplerOutput,
    };
    use std::future::Future;

    fn user_element() -> TestElement {
        let mut element = TestElement::named(
            USER_PARAMETERS_ALIAS,
            USER_PARAMETERS_GUI_ALIAS,
            "bounded user parameters",
        );
        element.set_property(
            USER_PARAMETERS_NAMES,
            PropertyValue::collection(vec![
                PropertyValue::string("user"),
                PropertyValue::string("mode"),
            ]),
        );
        element.set_property(
            USER_PARAMETERS_THREAD_VALUES,
            PropertyValue::collection(vec![
                PropertyValue::collection(vec![
                    PropertyValue::string("alice"),
                    PropertyValue::string("local"),
                ]),
                PropertyValue::collection(vec![
                    PropertyValue::string("bob"),
                    PropertyValue::string("remote"),
                ]),
            ]),
        );
        element.set_property(USER_PARAMETERS_PER_ITERATION, PropertyValue::boolean(true));
        element
    }

    fn regex_element() -> TestElement {
        let mut element = TestElement::named(
            REGEX_USER_PARAMETERS_ALIAS,
            REGEX_USER_PARAMETERS_GUI_ALIAS,
            "regex parameters",
        );
        element.set_property(REGEX_REF_NAME, PropertyValue::string("fixture.regex"));
        element.set_property(REGEX_PARAM_NAMES_GROUP, PropertyValue::string("1"));
        element.set_property(REGEX_PARAM_VALUES_GROUP, PropertyValue::string("2"));
        element
    }

    #[derive(Debug)]
    struct NoopSampler;

    impl Sampler for NoopSampler {
        fn sample<'a>(
            &'a self,
            _context: &'a mut SampleContext<'_>,
        ) -> ComponentFuture<'a, SamplerOutput> {
            Box::pin(async { Ok(SamplerOutput::no_result()) })
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

    fn request_parts(query_fields: Vec<QueryField>) -> RequestStateParts {
        RequestStateParts {
            scheme: Presence::Missing,
            authority: Presence::Missing,
            path_segments: Vec::new(),
            query_fields,
            method: Presence::Missing,
            body: Presence::Missing,
            headers: Vec::new(),
        }
    }

    #[test]
    fn decode_retains_exact_source_and_ordered_rows() {
        let definition = decode_user_parameters(&user_element()).expect("valid definition");
        assert_eq!(definition.source().test_class(), USER_PARAMETERS_ALIAS);
        assert_eq!(definition.source().gui_class(), USER_PARAMETERS_GUI_ALIAS);
        assert_eq!(definition.names(), &["user", "mode"]);
        assert_eq!(definition.rows()[1], ["bob", "remote"]);
        assert!(definition.per_iteration());
        assert_eq!(
            definition.property_order(),
            &[
                UserParametersProperty::Names,
                UserParametersProperty::ThreadValues,
                UserParametersProperty::PerIteration,
            ]
        );
    }

    #[test]
    fn decode_accepts_pinned_fqcn_pair_and_rejects_case_drift() {
        let mut element = user_element();
        element.metadata.test_class = USER_PARAMETERS_CLASS.to_owned();
        element.metadata.gui_class = USER_PARAMETERS_GUI_CLASS.to_owned();
        assert!(decode_user_parameters(&element).is_ok());
        element.metadata.test_class = "userparameters".to_owned();
        let error = decode_user_parameters(&element).expect_err("case drift must fail closed");
        assert_eq!(error.code(), "app.user-parameters.testclass");
    }

    #[test]
    fn decode_accepts_short_and_long_rows_with_zip_semantics() {
        let mut element = user_element();
        element.set_property(
            USER_PARAMETERS_THREAD_VALUES,
            PropertyValue::collection(vec![PropertyValue::collection(vec![
                PropertyValue::string("only-one"),
            ])]),
        );
        let short = decode_user_parameters(&element).expect("short row is pinned zip input");
        assert_eq!(short.rows()[0], ["only-one"]);

        element.set_property(
            USER_PARAMETERS_THREAD_VALUES,
            PropertyValue::collection(vec![PropertyValue::collection(vec![
                PropertyValue::string("first"),
                PropertyValue::string("second"),
                PropertyValue::string("ignored-by-zip"),
            ])]),
        );
        let long = decode_user_parameters(&element).expect("long row is pinned zip input");
        assert_eq!(long.rows()[0], ["first", "second", "ignored-by-zip"]);
    }

    #[test]
    fn decode_accepts_duplicate_empty_and_control_names() {
        let mut element = user_element();
        element.set_property(
            USER_PARAMETERS_NAMES,
            PropertyValue::collection(vec![
                PropertyValue::string(""),
                PropertyValue::string("duplicate"),
                PropertyValue::string("duplicate"),
                PropertyValue::string("control\nname"),
            ]),
        );
        let definition = decode_user_parameters(&element).expect("JMeter accepts names verbatim");
        assert_eq!(
            definition.names(),
            &["", "duplicate", "duplicate", "control\nname"]
        );
    }

    #[test]
    fn decode_rejects_unknown_property_without_dropping_it() {
        let mut element = user_element();
        element.set_property("UserParameters.unknown", PropertyValue::string("opaque"));
        let error = decode_user_parameters(&element).expect_err("unknown property");
        assert!(matches!(
            error,
            UserParametersDecodeError::UnknownProperty { ordinal: 3 }
        ));
        assert_eq!(element.properties.len(), 4);
    }

    #[test]
    fn decode_rejects_outer_and_nested_collections_before_projection() {
        let mut outer_oversized = user_element();
        outer_oversized.set_property(
            USER_PARAMETERS_THREAD_VALUES,
            PropertyValue::collection(
                (0..=MAX_USER_PARAMETER_ROWS)
                    .map(|_| PropertyValue::collection(Vec::new()))
                    .collect(),
            ),
        );
        let error = decode_user_parameters(&outer_oversized).expect_err("row bound");
        assert_eq!(
            error,
            UserParametersDecodeError::Limit {
                field: "rows",
                actual: MAX_USER_PARAMETER_ROWS + 1,
                limit: MAX_USER_PARAMETER_ROWS,
            }
        );

        let mut nested_oversized = user_element();
        nested_oversized.set_property(
            USER_PARAMETERS_THREAD_VALUES,
            PropertyValue::collection(vec![PropertyValue::collection(
                (0..=MAX_USER_PARAMETER_VALUES_PER_ROW)
                    .map(|_| PropertyValue::string("bounded"))
                    .collect(),
            )]),
        );
        let error = decode_user_parameters(&nested_oversized).expect_err("row value bound");
        assert_eq!(
            error,
            UserParametersDecodeError::Limit {
                field: "row-values",
                actual: MAX_USER_PARAMETER_VALUES_PER_ROW + 1,
                limit: MAX_USER_PARAMETER_VALUES_PER_ROW,
            }
        );
    }

    #[test]
    fn decode_rejects_name_collection_limit_before_row_projection() {
        let mut element = user_element();
        element.set_property(
            USER_PARAMETERS_NAMES,
            PropertyValue::collection(
                (0..=MAX_USER_PARAMETER_NAMES)
                    .map(|index| PropertyValue::string(format!("name-{index}")))
                    .collect(),
            ),
        );
        let error = decode_user_parameters(&element).expect_err("name bound");
        assert_eq!(
            error,
            UserParametersDecodeError::Limit {
                field: "names",
                actual: MAX_USER_PARAMETER_NAMES + 1,
                limit: MAX_USER_PARAMETER_NAMES,
            }
        );
    }

    #[test]
    fn regex_decode_is_typed_and_bounded() {
        let mut element = regex_element();
        element.set_property(REGEX_REF_NAME, PropertyValue::string("fixture.regex"));
        element.set_property(
            REGEX_PARAM_NAMES_GROUP,
            PropertyValue::string("arbitrary-name-suffix"),
        );
        element.set_property(
            REGEX_PARAM_VALUES_GROUP,
            PropertyValue::string("arbitrary\u{0}value-suffix"),
        );
        let definition = decode_regex_user_parameters(&element).expect("regex definition");
        assert_eq!(definition.regex_reference_name(), "fixture.regex");
        assert_eq!(definition.parameter_names_group(), "arbitrary-name-suffix");
        assert_eq!(
            definition.parameter_values_group(),
            "arbitrary\u{0}value-suffix"
        );
        assert_eq!(
            definition.property_order(),
            &[
                RegExUserParametersProperty::RegexReferenceName,
                RegExUserParametersProperty::ParameterNamesGroup,
                RegExUserParametersProperty::ParameterValuesGroup,
            ]
        );
    }

    #[test]
    fn factory_instances_share_the_pinned_user_parameters_lock() {
        let definition = decode_user_parameters(&user_element()).expect("definition");
        let factory = definition.factory(None);
        let first = factory.create_instance();
        let second = factory.create_instance();
        assert!(Arc::ptr_eq(&first.lock, &second.lock));

        let cloned_definition = definition.clone();
        let cloned_factory = cloned_definition.factory(None);
        let third = cloned_factory.create_instance();
        assert!(Arc::ptr_eq(&first.lock, &third.lock));
    }

    #[test]
    fn match_count_parser_matches_java_int_range_and_signs() {
        assert_eq!(parse_java_match_count("+32"), Ok(32));
        assert_eq!(parse_java_match_count("0"), Ok(0));
        assert_eq!(parse_java_match_count("2147483647"), Ok(i32::MAX));
        assert_eq!(parse_java_match_count("-1"), Ok(-1));
        assert_eq!(
            parse_java_match_count("2147483648"),
            Err(UserParametersError::InvalidMatchCount)
        );
        assert_eq!(
            parse_java_match_count(" 1"),
            Err(UserParametersError::InvalidMatchCount)
        );
    }

    #[test]
    fn regex_group_keys_retain_literal_suffix_text() {
        assert_eq!(
            bounded_group_key("fixture_", 1, "capture-name", MAX_USER_PARAMETER_TEXT_BYTES)
                .expect("bounded key"),
            "fixture_1_gcapture-name"
        );
        assert_eq!(
            bounded_group_key("fixture_", 1, "", MAX_USER_PARAMETER_TEXT_BYTES)
                .expect("empty suffix is literal"),
            "fixture_1_g"
        );
    }

    #[test]
    fn regex_later_missing_value_suppresses_an_earlier_match() {
        let parameters = vec![
            (Some("id".to_owned()), Some("old".to_owned())),
            (Some("id".to_owned()), None),
        ];
        assert_eq!(last_parameter_value(&parameters, "id"), None);

        let parameters = vec![
            (Some("id".to_owned()), None),
            (Some("id".to_owned()), Some("new".to_owned())),
        ];
        assert_eq!(last_parameter_value(&parameters, "id"), Some("new"));
    }

    #[test]
    fn regex_no_request_projection_is_noop_before_match_count_parsing() {
        let definition = decode_regex_user_parameters(&regex_element()).expect("definition");
        let factory = definition.factory(None);
        let package = SamplePackage::builder(NodeId::new(1), Arc::new(NoopSampler))
            .preprocessor_factories(vec![Arc::new(factory)])
            .build();

        let mut execution = ExecutionContext::new();
        execution.set_variable("fixture.regex_matchNr", "not-an-int");
        block_on(package.execute(&mut execution)).expect("no request projection is a no-op");

        let query = QueryField::try_new(
            EncodedField::raw("id").expect("query name"),
            Presence::Present(EncodedField::raw("before").expect("query value")),
        )
        .expect("query field");
        let mut execution = ExecutionContext::new();
        execution
            .set_request_state(
                RequestState::try_from_parts(RequestGeneration::FIRST, request_parts(vec![query]))
                    .expect("request state"),
            )
            .expect("install request state");
        let digest = execution.request_state().digest();
        block_on(package.execute(&mut execution)).expect("absent first groups are a no-op");
        assert_eq!(execution.request_state().digest(), digest);
    }

    #[test]
    fn expression_detection_does_not_treat_escaped_reference_as_capability_use() {
        assert!(contains_expression("prefix ${VALUE}"));
        assert!(!contains_expression(r"prefix \${VALUE}"));
        assert!(!contains_expression("literal"));
    }
}
