// SPDX-License-Identifier: Apache-2.0
//! Stable, input-facing model errors.

use core::fmt;
use std::error::Error as StdError;

use crate::{NodeId, SourceLocation, SourceLocationError, ValidationLimitKind};

/// Maximum number of contextual wrappers traversed while formatting or
/// classifying an error.
///
/// Context is normally flattened by [`ModelError::with_context`]. The bound
/// also protects callers that construct the public wrapper variants directly
/// from pathological nesting: error reporting must remain bounded even for
/// hostile model data.
pub const MAX_ERROR_CONTEXT_DEPTH: usize = 16;

const REDACTED: &str = "<redacted>";

/// Stable, machine-readable codes emitted by the pure model.
///
/// The string returned by [`Self::as_str`] is the compatibility key.  Display
/// text is deliberately kept separate because names, source labels, and
/// other input-facing context are diagnostic data and must not become part of
/// a compatibility comparison.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ModelErrorCode {
    /// A requested tree node is absent.
    TreeNodeNotFound,
    /// A requested tree parent is absent.
    TreeParentNotFound,
    /// A tree node identity is already in use.
    TreeDuplicateNodeId,
    /// Automatic tree identity allocation is exhausted.
    TreeNodeIdExhausted,
    /// A leaf-only operation encountered children.
    TreeNodeHasChildren,
    /// A bounded tree traversal exceeded its event budget.
    TreeTraversalLimitExceeded,
    /// A bounded tree query exceeded its result budget.
    TreeQueryLimitExceeded,
    /// A tree identity was used below a different parent.
    TreeParentMismatch,
    /// An internal tree invariant failed.
    TreeInvariantViolation,
    /// A property name was inserted twice.
    PropertyDuplicateName,
    /// A requested property name is absent.
    PropertyNameNotFound,
    /// A property was requested as the wrong typed kind.
    PropertyTypeMismatch,
    /// Validation exceeded the node limit.
    ValidationLimitNodes,
    /// Validation exceeded the tree-depth limit.
    ValidationLimitTreeDepth,
    /// Validation exceeded the property-count limit.
    ValidationLimitProperties,
    /// Validation exceeded the nested-property-depth limit.
    ValidationLimitPropertyDepth,
    /// Validation exceeded the opaque-byte limit.
    ValidationLimitOpaqueBytes,
    /// Validation exceeded the aggregate string-byte limit.
    ValidationLimitStringBytes,
    /// Required element metadata was empty.
    ValidationEmptyMetadata,
    /// A source location failed validation.
    ValidationInvalidSourceLocation,
    /// A property collection contained duplicate names.
    ValidationDuplicatePropertyName,
    /// A source line coordinate was invalid.
    SourceInvalidLine,
    /// A source column coordinate was invalid.
    SourceInvalidColumn,
    /// A source label was empty.
    SourceEmpty,
    /// A source label or buffer exceeded its bound.
    SourceTooLong,
    /// A source path exceeded its component bound.
    SourceTooManyComponents,
    /// A source label contained NUL.
    SourceContainsNul,
    /// A source label contained a control character.
    SourceContainsControl,
    /// A source buffer was not UTF-8.
    SourceInvalidUtf8,
    /// A source byte offset exceeded its bound.
    SourceByteOffsetTooLarge,
    /// A source byte offset was outside the source buffer.
    SourceByteOffsetOutOfBounds,
    /// A source byte offset was not a UTF-8 boundary.
    SourceByteOffsetNotCharBoundary,
    /// A lossless wire operation belongs to the JMX boundary.
    CapabilityUnsupportedLosslessWire,
    /// Context nesting exceeded the diagnostic traversal bound.
    ContextLimit,
}

impl ModelErrorCode {
    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TreeNodeNotFound => "model.tree.node-not-found",
            Self::TreeParentNotFound => "model.tree.parent-not-found",
            Self::TreeDuplicateNodeId => "model.tree.duplicate-node-id",
            Self::TreeNodeIdExhausted => "model.tree.node-id-exhausted",
            Self::TreeNodeHasChildren => "model.tree.node-has-children",
            Self::TreeTraversalLimitExceeded => "model.tree.traversal-limit-exceeded",
            Self::TreeQueryLimitExceeded => "model.tree.query-limit-exceeded",
            Self::TreeParentMismatch => "model.tree.parent-mismatch",
            Self::TreeInvariantViolation => "model.tree.invariant-violation",
            Self::PropertyDuplicateName => "model.property.duplicate-name",
            Self::PropertyNameNotFound => "model.property.name-not-found",
            Self::PropertyTypeMismatch => "model.property.type-mismatch",
            Self::ValidationLimitNodes => "model.validation.limit-nodes",
            Self::ValidationLimitTreeDepth => "model.validation.limit-tree-depth",
            Self::ValidationLimitProperties => "model.validation.limit-properties",
            Self::ValidationLimitPropertyDepth => "model.validation.limit-property-depth",
            Self::ValidationLimitOpaqueBytes => "model.validation.limit-opaque-bytes",
            Self::ValidationLimitStringBytes => "model.validation.limit-string-bytes",
            Self::ValidationEmptyMetadata => "model.validation.empty-metadata",
            Self::ValidationInvalidSourceLocation => "model.validation.invalid-source-location",
            Self::ValidationDuplicatePropertyName => "model.validation.duplicate-property-name",
            Self::SourceInvalidLine => "model.source.invalid-line",
            Self::SourceInvalidColumn => "model.source.invalid-column",
            Self::SourceEmpty => "model.source.empty",
            Self::SourceTooLong => "model.source.too-long",
            Self::SourceTooManyComponents => "model.source.too-many-components",
            Self::SourceContainsNul => "model.source.contains-nul",
            Self::SourceContainsControl => "model.source.contains-control",
            Self::SourceInvalidUtf8 => "model.source.invalid-utf8",
            Self::SourceByteOffsetTooLarge => "model.source.byte-offset-too-large",
            Self::SourceByteOffsetOutOfBounds => "model.source.byte-offset-out-of-bounds",
            Self::SourceByteOffsetNotCharBoundary => "model.source.byte-offset-not-char-boundary",
            Self::CapabilityUnsupportedLosslessWire => "model.capability.unsupported-lossless-wire",
            Self::ContextLimit => "model.error.context-limit",
        }
    }

    /// Alias emphasizing that this value is the stable wire/log code.
    #[must_use]
    pub const fn stable_code(self) -> &'static str {
        self.as_str()
    }

    /// Returns whether this code represents a resource bound failure.
    #[must_use]
    pub const fn is_limit(self) -> bool {
        matches!(
            self,
            Self::TreeTraversalLimitExceeded
                | Self::TreeQueryLimitExceeded
                | Self::ValidationLimitNodes
                | Self::ValidationLimitTreeDepth
                | Self::ValidationLimitProperties
                | Self::ValidationLimitPropertyDepth
                | Self::ValidationLimitOpaqueBytes
                | Self::ValidationLimitStringBytes
                | Self::SourceTooLong
                | Self::SourceTooManyComponents
                | Self::SourceByteOffsetTooLarge
                | Self::SourceByteOffsetOutOfBounds
                | Self::ContextLimit
        )
    }
}

impl fmt::Display for ModelErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Errors raised while mutating or traversing an identity tree.
#[derive(Clone, Eq, PartialEq)]
pub enum TreeError {
    /// A requested node is not present in the tree.
    NodeNotFound {
        /// Missing node identity.
        id: NodeId,
    },
    /// An insertion referred to a parent that is not present.
    ParentNotFound {
        /// Missing parent identity.
        id: NodeId,
    },
    /// An imported ID is already used by another node.
    DuplicateNodeId {
        /// Identity that is already present.
        id: NodeId,
    },
    /// No further automatically allocated ID is available.
    NodeIdExhausted,
    /// A leaf-only operation was requested for a node with children.
    NodeHasChildren {
        /// Node identity whose children prevented a leaf-only operation.
        id: NodeId,
    },
    /// A bounded traversal reached its caller-provided event budget.
    TraversalLimitExceeded {
        /// Maximum number of events supplied by the caller.
        limit: usize,
    },
    /// A query would have returned more allocated values than its caller
    /// supplied budget.
    QueryLimitExceeded {
        /// Stable operation name used in diagnostics.
        operation: &'static str,
        /// Maximum number of values the caller allowed.
        limit: usize,
    },
    /// An identity key was reused under a different parent.
    ParentMismatch {
        /// Existing node identity.
        id: NodeId,
        /// Parent already associated with the identity.
        expected: Option<NodeId>,
        /// Parent requested by the merge/set operation.
        actual: Option<NodeId>,
    },
    /// The private tree representation failed an internal consistency check.
    InvariantViolation {
        /// Redacted static diagnostic for an internal invariant failure.
        detail: &'static str,
    },
}

impl fmt::Debug for TreeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("TreeError");
        match self {
            Self::NodeNotFound { id } => {
                debug.field("kind", &"NodeNotFound").field("id", id);
            }
            Self::ParentNotFound { id } => {
                debug.field("kind", &"ParentNotFound").field("id", id);
            }
            Self::DuplicateNodeId { id } => {
                debug.field("kind", &"DuplicateNodeId").field("id", id);
            }
            Self::NodeIdExhausted => {
                debug.field("kind", &"NodeIdExhausted");
            }
            Self::NodeHasChildren { id } => {
                debug.field("kind", &"NodeHasChildren").field("id", id);
            }
            Self::TraversalLimitExceeded { limit } => {
                debug
                    .field("kind", &"TraversalLimitExceeded")
                    .field("limit", limit);
            }
            Self::QueryLimitExceeded { operation, limit } => {
                debug
                    .field("kind", &"QueryLimitExceeded")
                    .field("operation", operation)
                    .field("limit", limit);
            }
            Self::ParentMismatch {
                id,
                expected,
                actual,
            } => {
                debug
                    .field("kind", &"ParentMismatch")
                    .field("id", id)
                    .field("expected", expected)
                    .field("actual", actual);
            }
            Self::InvariantViolation { .. } => {
                debug
                    .field("kind", &"InvariantViolation")
                    .field("detail", &REDACTED);
            }
        }
        debug.finish()
    }
}

impl TreeError {
    /// Returns the typed stable machine-readable code.
    #[must_use]
    pub const fn code_kind(&self) -> ModelErrorCode {
        match self {
            Self::NodeNotFound { .. } => ModelErrorCode::TreeNodeNotFound,
            Self::ParentNotFound { .. } => ModelErrorCode::TreeParentNotFound,
            Self::DuplicateNodeId { .. } => ModelErrorCode::TreeDuplicateNodeId,
            Self::NodeIdExhausted => ModelErrorCode::TreeNodeIdExhausted,
            Self::NodeHasChildren { .. } => ModelErrorCode::TreeNodeHasChildren,
            Self::TraversalLimitExceeded { .. } => ModelErrorCode::TreeTraversalLimitExceeded,
            Self::QueryLimitExceeded { .. } => ModelErrorCode::TreeQueryLimitExceeded,
            Self::ParentMismatch { .. } => ModelErrorCode::TreeParentMismatch,
            Self::InvariantViolation { .. } => ModelErrorCode::TreeInvariantViolation,
        }
    }

    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code_kind().as_str()
    }

    /// Alias emphasizing that this is the stable code, not display text.
    #[must_use]
    pub const fn stable_code(&self) -> &'static str {
        self.code()
    }
}

impl fmt::Display for TreeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NodeNotFound { id } => {
                write!(formatter, "{}: node {id} was not found", self.code())
            }
            Self::ParentNotFound { id } => {
                write!(formatter, "{}: parent node {id} was not found", self.code())
            }
            Self::DuplicateNodeId { id } => {
                write!(formatter, "{}: node ID {id} is already in use", self.code())
            }
            Self::NodeIdExhausted => write!(
                formatter,
                "{}: document-local node IDs are exhausted",
                self.code()
            ),
            Self::NodeHasChildren { id } => {
                write!(formatter, "{}: node {id} has children", self.code())
            }
            Self::TraversalLimitExceeded { limit } => {
                write!(
                    formatter,
                    "{}: tree traversal exceeded the event limit {limit}",
                    self.code()
                )
            }
            Self::QueryLimitExceeded { operation, limit } => {
                write!(
                    formatter,
                    "{}: tree query {operation} exceeded the allocation limit {limit}",
                    self.code()
                )
            }
            Self::ParentMismatch {
                id,
                expected,
                actual,
            } => write!(
                formatter,
                "{}: node {id} belongs under parent {expected:?}, not {actual:?}",
                self.code()
            ),
            Self::InvariantViolation { detail } => {
                let _ = detail;
                write!(
                    formatter,
                    "{}: identity tree invariant violated",
                    self.code()
                )
            }
        }
    }
}

impl std::error::Error for TreeError {}

/// Errors raised by ordered property collections.
#[derive(Clone, Eq, PartialEq)]
pub enum PropertyError {
    /// An insertion attempted to add a duplicate property name using the
    /// duplicate-rejecting API.
    DuplicateName {
        /// Exact duplicate property name.
        name: String,
    },
    /// A requested property name is absent.
    NameNotFound {
        /// Exact property name that was absent.
        name: String,
    },
}

impl fmt::Debug for PropertyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateName { name } => formatter
                .debug_struct("DuplicateName")
                .field("name", &"<redacted>")
                .field("name_len", &name.len())
                .finish(),
            Self::NameNotFound { name } => formatter
                .debug_struct("NameNotFound")
                .field("name", &"<redacted>")
                .field("name_len", &name.len())
                .finish(),
        }
    }
}

impl PropertyError {
    /// Returns the typed stable machine-readable code.
    #[must_use]
    pub const fn code_kind(&self) -> ModelErrorCode {
        match self {
            Self::DuplicateName { .. } => ModelErrorCode::PropertyDuplicateName,
            Self::NameNotFound { .. } => ModelErrorCode::PropertyNameNotFound,
        }
    }

    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code_kind().as_str()
    }

    /// Alias emphasizing that this is the stable code, not display text.
    #[must_use]
    pub const fn stable_code(&self) -> &'static str {
        self.code()
    }
}

impl fmt::Display for PropertyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateName { name } => {
                let _ = name;
                write!(
                    formatter,
                    "{}: property name is already present",
                    self.code()
                )
            }
            Self::NameNotFound { name } => {
                let _ = name;
                write!(formatter, "{}: property name was not found", self.code())
            }
        }
    }
}

impl std::error::Error for PropertyError {}

/// A typed error for requesting a property as the wrong value kind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PropertyTypeError {
    /// The kind requested by the caller.
    pub expected: crate::PropertyKind,
    /// The actual kind stored in the value.
    pub actual: crate::PropertyKind,
}

impl PropertyTypeError {
    /// Returns the typed stable machine-readable code.
    #[must_use]
    pub const fn code_kind(&self) -> ModelErrorCode {
        ModelErrorCode::PropertyTypeMismatch
    }

    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code_kind().as_str()
    }

    /// Alias emphasizing that this is the stable code, not display text.
    #[must_use]
    pub const fn stable_code(&self) -> &'static str {
        self.code()
    }
}

impl fmt::Display for PropertyTypeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}: property kind mismatch: expected {}, got {}",
            self.code(),
            self.expected,
            self.actual
        )
    }
}

impl std::error::Error for PropertyTypeError {}

/// The metadata field that failed direct model validation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MetadataField {
    /// The upstream `testclass` value.
    TestClass,
    /// The upstream `guiclass` value.
    GuiClass,
    /// The upstream `testname` value.
    Name,
}

impl MetadataField {
    /// Returns the upstream attribute name.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::TestClass => "testclass",
            Self::GuiClass => "guiclass",
            Self::Name => "testname",
        }
    }
}

/// Stable failures found by validation of directly constructed model values.
#[derive(Clone, Eq, PartialEq)]
pub enum ModelValidationError {
    /// A model resource exceeded its caller-provided bound.
    LimitExceeded {
        /// Resource dimension that exceeded its bound.
        kind: ValidationLimitKind,
        /// Caller-provided maximum.
        limit: usize,
        /// Bounded observed count (saturated on arithmetic overflow).
        actual: usize,
    },
    /// A required semantic element metadata value was empty.
    EmptyMetadata {
        /// Empty upstream attribute.
        field: MetadataField,
    },
    /// A source coordinate violated its one-based contract.
    InvalidSourceLocation {
        /// Coordinate error.
        error: SourceLocationError,
    },
    /// A property collection contains duplicate names.
    DuplicatePropertyName {
        /// Exact duplicate property name.
        name: String,
    },
}

impl fmt::Debug for ModelValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimitExceeded {
                kind,
                limit,
                actual,
            } => formatter
                .debug_struct("LimitExceeded")
                .field("kind", kind)
                .field("limit", limit)
                .field("actual", actual)
                .finish(),
            Self::EmptyMetadata { field } => formatter
                .debug_struct("EmptyMetadata")
                .field("field", field)
                .finish(),
            Self::InvalidSourceLocation { error } => formatter
                .debug_struct("InvalidSourceLocation")
                .field("error", error)
                .finish(),
            Self::DuplicatePropertyName { name } => formatter
                .debug_struct("DuplicatePropertyName")
                .field("name", &"<redacted>")
                .field("name_len", &name.len())
                .finish(),
        }
    }
}

impl ModelValidationError {
    /// Returns the typed stable machine-readable code.
    #[must_use]
    pub const fn code_kind(&self) -> ModelErrorCode {
        match self {
            Self::LimitExceeded { kind, .. } => validation_limit_code_kind(*kind),
            Self::EmptyMetadata { .. } => ModelErrorCode::ValidationEmptyMetadata,
            Self::InvalidSourceLocation { error } => source_error_code_kind(error),
            Self::DuplicatePropertyName { .. } => ModelErrorCode::ValidationDuplicatePropertyName,
        }
    }

    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code_kind().as_str()
    }

    /// Alias emphasizing that this is the stable code, not display text.
    #[must_use]
    pub const fn stable_code(&self) -> &'static str {
        self.code()
    }

    /// Returns whether this validation failure is a finite-resource limit.
    #[must_use]
    pub const fn is_limit(&self) -> bool {
        self.code_kind().is_limit()
    }
}

impl fmt::Display for ModelValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimitExceeded {
                kind: _,
                limit,
                actual,
            } => write!(
                formatter,
                "{}: model validation exceeded limit {limit} (observed {actual})",
                self.code()
            ),
            Self::EmptyMetadata { field } => {
                write!(
                    formatter,
                    "{}: required {} metadata is empty",
                    self.code(),
                    field.wire_name()
                )
            }
            Self::InvalidSourceLocation { error } => {
                write!(formatter, "{}: {error}", self.code())
            }
            Self::DuplicatePropertyName { name } => {
                let _ = name;
                write!(
                    formatter,
                    "{}: property name appears more than once",
                    self.code()
                )
            }
        }
    }
}

impl std::error::Error for ModelValidationError {}

/// A capability boundary error for conversions that require JMX wire sidecars.
///
/// The pure model retains typed semantics and opaque payload bytes, but does
/// not retain XML tags, source placement, lexical attributes, or unknown
/// subtree event order.  A caller asking the model alone for a lossless JMX
/// conversion must receive this typed error rather than a lossy success.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub enum ModelCapabilityError {
    /// Lossless wire data belongs to the JMX syntax/sidecar layer.
    UnsupportedLosslessWire {
        /// Static operation context safe to include in diagnostics.
        context: &'static str,
    },
}

impl fmt::Debug for ModelCapabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModelCapabilityError")
            .field("code", &self.code())
            .field("context", &REDACTED)
            .finish()
    }
}

impl ModelCapabilityError {
    /// Returns the typed stable machine-readable code.
    #[must_use]
    pub const fn code_kind(self) -> ModelErrorCode {
        ModelErrorCode::CapabilityUnsupportedLosslessWire
    }

    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.code_kind().as_str()
    }

    /// Alias emphasizing that this is the stable code, not display text.
    #[must_use]
    pub const fn stable_code(self) -> &'static str {
        self.code()
    }
}

impl fmt::Display for ModelCapabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedLosslessWire { context } => {
                let _ = context;
                write!(
                    formatter,
                    "{}: lossless wire conversion is unsupported in the pure model",
                    self.code()
                )
            }
        }
    }
}

impl std::error::Error for ModelCapabilityError {}

/// A common model error for callers that handle properties and trees together.
#[derive(Clone, Eq, PartialEq)]
pub enum ModelError {
    /// An identity-tree operation failed.
    Tree(TreeError),
    /// An ordered-property operation failed.
    Property(PropertyError),
    /// A typed property accessor failed.
    PropertyType(PropertyTypeError),
    /// Direct model validation failed.
    Validation(ModelValidationError),
    /// A conversion requires syntax-layer wire sidecars unavailable here.
    Capability(ModelCapabilityError),
    /// A model failure with bounded source/node context.
    ///
    /// Context is diagnostic only and never changes the stable code of the
    /// wrapped error.  The source label is redacted by [`Display`] and
    /// [`Debug`]; callers that need the original label must use the explicit
    /// [`Self::source_location`] accessor in trusted tooling.
    Context {
        /// The underlying typed failure.
        error: Box<ModelError>,
        /// Optional source location associated with the failure.
        source: Option<SourceLocation>,
        /// Optional document-local node identity associated with the failure.
        node_id: Option<NodeId>,
    },
}

impl fmt::Debug for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModelError")
            .field("code", &self.code())
            .field("source_present", &self.source_location().is_some())
            .field("node_id", &self.node_id())
            .finish()
    }
}

impl ModelError {
    const fn base_code_kind(&self) -> ModelErrorCode {
        match self {
            Self::Tree(error) => error.code_kind(),
            Self::Property(error) => error.code_kind(),
            Self::PropertyType(error) => error.code_kind(),
            Self::Validation(error) => error.code_kind(),
            Self::Capability(error) => error.code_kind(),
            Self::Context { .. } => ModelErrorCode::ContextLimit,
        }
    }

    /// Returns the typed stable machine-readable code.
    #[must_use]
    pub const fn code_kind(&self) -> ModelErrorCode {
        let mut current = self;
        let mut depth = 0;
        while depth < MAX_ERROR_CONTEXT_DEPTH {
            match current {
                Self::Context { error, .. } => current = error,
                _ => return current.base_code_kind(),
            }
            depth += 1;
        }
        ModelErrorCode::ContextLimit
    }

    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code_kind().as_str()
    }

    /// Alias emphasizing that this is the stable code, not display text.
    #[must_use]
    pub const fn stable_code(&self) -> &'static str {
        self.code()
    }

    /// Returns whether this error is a finite-resource limit failure.
    #[must_use]
    pub const fn is_limit(&self) -> bool {
        self.code_kind().is_limit()
    }

    /// Adds bounded source and node context to this error.
    ///
    /// Calling this repeatedly coalesces context into one wrapper, keeping
    /// formatting and source traversal bounded.  New fields take precedence
    /// over older fields; an omitted field preserves an existing value.
    #[must_use]
    pub fn with_context(self, source: Option<SourceLocation>, node_id: Option<NodeId>) -> Self {
        if source.is_none() && node_id.is_none() {
            return self;
        }
        match self {
            Self::Context {
                error,
                source: old_source,
                node_id: old_node_id,
            } => Self::Context {
                error,
                source: source.or(old_source),
                node_id: node_id.or(old_node_id),
            },
            error => Self::Context {
                error: Box::new(error),
                source,
                node_id,
            },
        }
    }

    /// Adds source context while retaining any existing node identity.
    #[must_use]
    pub fn with_source(self, source: SourceLocation) -> Self {
        self.with_context(Some(source), None)
    }

    /// Adds node context while retaining any existing source location.
    #[must_use]
    pub fn with_node_id(self, node_id: NodeId) -> Self {
        self.with_context(None, Some(node_id))
    }

    /// Returns the nearest attached source location, if any.
    #[must_use]
    pub fn source_location(&self) -> Option<&SourceLocation> {
        let mut current = self;
        for _ in 0..MAX_ERROR_CONTEXT_DEPTH {
            match current {
                Self::Context { source, error, .. } => {
                    if source.is_some() {
                        return source.as_ref();
                    }
                    current = error;
                }
                _ => return None,
            }
        }
        None
    }

    /// Returns the nearest attached node identity, if any.
    #[must_use]
    pub fn node_id(&self) -> Option<NodeId> {
        let mut current = self;
        for _ in 0..MAX_ERROR_CONTEXT_DEPTH {
            match current {
                Self::Context { node_id, error, .. } => {
                    if node_id.is_some() {
                        return *node_id;
                    }
                    current = error;
                }
                _ => return None,
            }
        }
        None
    }
}

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut current = self;
        for _ in 0..MAX_ERROR_CONTEXT_DEPTH {
            match current {
                Self::Context {
                    error,
                    source,
                    node_id,
                } => {
                    write!(formatter, "{}: ", self.code())?;
                    fmt_context(formatter, source.as_ref(), *node_id)?;
                    if source.is_some() || node_id.is_some() {
                        formatter.write_str(": ")?;
                    }
                    current = error;
                }
                _ => return current.fmt_base(formatter),
            }
        }
        write!(
            formatter,
            "{}: error context exceeded its bound",
            self.code()
        )
    }
}

impl ModelError {
    fn fmt_base(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tree(error) => fmt::Display::fmt(error, formatter),
            Self::Property(error) => fmt::Display::fmt(error, formatter),
            Self::PropertyType(error) => fmt::Display::fmt(error, formatter),
            Self::Validation(error) => fmt::Display::fmt(error, formatter),
            Self::Capability(error) => fmt::Display::fmt(error, formatter),
            Self::Context { .. } => formatter.write_str("error context wrapper"),
        }
    }
}

fn fmt_context(
    formatter: &mut fmt::Formatter<'_>,
    source: Option<&SourceLocation>,
    node_id: Option<NodeId>,
) -> fmt::Result {
    if let Some(source) = source {
        formatter.write_str("source ")?;
        if source.source_name().is_some() {
            formatter.write_str(REDACTED)?;
        } else {
            formatter.write_str("<unknown>")?;
        }
        if let Some(line) = source.line() {
            write!(formatter, ":{line}")?;
            if let Some(column) = source.column() {
                write!(formatter, ":{column}")?;
            }
        }
        if let Some(offset) = source.byte_offset() {
            write!(formatter, " (byte {offset})")?;
        }
    }
    if let Some(node_id) = node_id {
        if source.is_some() {
            formatter.write_str(", ")?;
        }
        write!(formatter, "node {node_id}")?;
    }
    Ok(())
}

impl StdError for ModelError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Tree(error) => Some(error),
            Self::Property(error) => Some(error),
            Self::PropertyType(error) => Some(error),
            Self::Validation(error) => Some(error),
            Self::Capability(error) => Some(error),
            Self::Context { error, .. } => Some(error.as_ref()),
        }
    }
}

impl From<TreeError> for ModelError {
    fn from(error: TreeError) -> Self {
        Self::Tree(error)
    }
}

impl From<PropertyError> for ModelError {
    fn from(error: PropertyError) -> Self {
        Self::Property(error)
    }
}

impl From<PropertyTypeError> for ModelError {
    fn from(error: PropertyTypeError) -> Self {
        Self::PropertyType(error)
    }
}

impl From<ModelValidationError> for ModelError {
    fn from(error: ModelValidationError) -> Self {
        Self::Validation(error)
    }
}

impl From<ModelCapabilityError> for ModelError {
    fn from(error: ModelCapabilityError) -> Self {
        Self::Capability(error)
    }
}

impl From<SourceLocationError> for ModelValidationError {
    fn from(error: SourceLocationError) -> Self {
        Self::InvalidSourceLocation { error }
    }
}

impl From<SourceLocationError> for ModelError {
    fn from(error: SourceLocationError) -> Self {
        Self::Validation(ModelValidationError::from(error))
    }
}

const fn validation_limit_code_kind(kind: ValidationLimitKind) -> ModelErrorCode {
    match kind {
        ValidationLimitKind::Nodes => ModelErrorCode::ValidationLimitNodes,
        ValidationLimitKind::TreeDepth => ModelErrorCode::ValidationLimitTreeDepth,
        ValidationLimitKind::Properties => ModelErrorCode::ValidationLimitProperties,
        ValidationLimitKind::PropertyDepth => ModelErrorCode::ValidationLimitPropertyDepth,
        ValidationLimitKind::OpaqueBytes => ModelErrorCode::ValidationLimitOpaqueBytes,
        ValidationLimitKind::StringBytes => ModelErrorCode::ValidationLimitStringBytes,
    }
}

const fn source_error_code_kind(error: &SourceLocationError) -> ModelErrorCode {
    match error {
        SourceLocationError::InvalidLine { .. } => ModelErrorCode::SourceInvalidLine,
        SourceLocationError::InvalidColumn { .. } => ModelErrorCode::SourceInvalidColumn,
        SourceLocationError::EmptySource => ModelErrorCode::SourceEmpty,
        SourceLocationError::SourceTooLong { .. } => ModelErrorCode::SourceTooLong,
        SourceLocationError::SourceTooManyComponents { .. } => {
            ModelErrorCode::SourceTooManyComponents
        }
        SourceLocationError::SourceContainsNul { .. } => ModelErrorCode::SourceContainsNul,
        SourceLocationError::SourceContainsControl { .. } => ModelErrorCode::SourceContainsControl,
        SourceLocationError::InvalidUtf8 { .. } => ModelErrorCode::SourceInvalidUtf8,
        SourceLocationError::ByteOffsetTooLarge { .. } => ModelErrorCode::SourceByteOffsetTooLarge,
        SourceLocationError::ByteOffsetOutOfBounds { .. } => {
            ModelErrorCode::SourceByteOffsetOutOfBounds
        }
        SourceLocationError::ByteOffsetNotCharBoundary { .. } => {
            ModelErrorCode::SourceByteOffsetNotCharBoundary
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "error tests use explicit assertion context"
)]
mod tests {
    use super::*;

    const SECRET: &str = "jmx-secret-property-or-plugin-payload";

    #[test]
    fn stable_codes_are_separate_from_diagnostic_text() {
        let error = PropertyError::DuplicateName {
            name: SECRET.to_owned(),
        };
        assert_eq!(error.code(), "model.property.duplicate-name");
        assert_eq!(error.code_kind().as_str(), error.code());
        assert!(!error.to_string().contains(SECRET));
        assert!(!format!("{error:?}").contains(SECRET));

        let validation = ModelValidationError::DuplicatePropertyName {
            name: SECRET.to_owned(),
        };
        assert_eq!(
            validation.code(),
            "model.validation.duplicate-property-name"
        );
        assert!(!validation.to_string().contains(SECRET));
        assert!(!format!("{validation:?}").contains(SECRET));

        let invariant = TreeError::InvariantViolation { detail: SECRET };
        assert_eq!(invariant.code(), "model.tree.invariant-violation");
        assert!(!invariant.to_string().contains(SECRET));
        assert!(!format!("{invariant:?}").contains(SECRET));

        let capability = ModelCapabilityError::UnsupportedLosslessWire { context: SECRET };
        assert_eq!(
            capability.code(),
            "model.capability.unsupported-lossless-wire"
        );
        assert!(!capability.to_string().contains(SECRET));
        assert!(!format!("{capability:?}").contains(SECRET));
    }

    #[test]
    fn source_and_node_context_is_redacted_but_queryable() {
        let source = SourceLocation::new(7, 3)
            .expect("positive source coordinates")
            .with_source(SECRET)
            .with_byte_offset(42);
        let error = ModelError::from(PropertyError::NameNotFound {
            name: SECRET.to_owned(),
        })
        .with_context(Some(source.clone()), Some(NodeId::new(9)));

        assert_eq!(error.code(), "model.property.name-not-found");
        assert_eq!(error.code_kind(), ModelErrorCode::PropertyNameNotFound);
        assert_eq!(error.source_location(), Some(&source));
        assert_eq!(error.node_id(), Some(NodeId::new(9)));
        assert!(error.source().is_some());
        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(display.contains("source <redacted>:7:3 (byte 42)"));
        assert!(display.contains("node 9"));
        assert!(!display.contains(SECRET));
        assert!(!debug.contains(SECRET));
        assert!(debug.contains("model.property.name-not-found"));
    }

    #[test]
    fn repeated_context_and_formatting_are_bounded() {
        let mut error = ModelError::from(TreeError::InvariantViolation { detail: SECRET });
        for index in 0..(MAX_ERROR_CONTEXT_DEPTH * 4) {
            error = ModelError::Context {
                error: Box::new(error),
                source: Some(SourceLocation::from_byte_offset(index as u64)),
                node_id: Some(NodeId::new(index as u64)),
            };
        }

        assert_eq!(error.code(), "model.error.context-limit");
        assert!(error.is_limit());
        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(display.len() < 8 * 1024);
        assert!(debug.len() < 256);
        assert!(!display.contains(SECRET));
        assert!(!debug.contains(SECRET));
        assert!(display.contains("context exceeded its bound"));
    }

    #[test]
    fn source_location_failures_keep_typed_codes_and_no_input_echo() {
        let accepted = SourceLocation::try_with_source(SourceLocation::unknown(), SECRET)
            .expect("bounded UTF-8 source labels are accepted");
        assert_eq!(accepted.source_name(), Some(SECRET));

        let error = SourceLocation::try_with_source(SourceLocation::unknown(), "")
            .expect_err("empty source labels are rejected");
        assert_eq!(error.code(), "model.source.empty");
        assert!(!error.to_string().contains(SECRET));
    }

    #[test]
    fn source_location_error_variants_keep_distinct_typed_codes() {
        let cases = [
            (
                SourceLocationError::InvalidLine { value: 0 },
                ModelErrorCode::SourceInvalidLine,
            ),
            (
                SourceLocationError::InvalidColumn { value: 0 },
                ModelErrorCode::SourceInvalidColumn,
            ),
            (
                SourceLocationError::EmptySource,
                ModelErrorCode::SourceEmpty,
            ),
            (
                SourceLocationError::SourceTooLong { bytes: 2, limit: 1 },
                ModelErrorCode::SourceTooLong,
            ),
            (
                SourceLocationError::SourceTooManyComponents {
                    components: 2,
                    limit: 1,
                },
                ModelErrorCode::SourceTooManyComponents,
            ),
            (
                SourceLocationError::SourceContainsNul { position: 0 },
                ModelErrorCode::SourceContainsNul,
            ),
            (
                SourceLocationError::SourceContainsControl { position: 0 },
                ModelErrorCode::SourceContainsControl,
            ),
            (
                SourceLocationError::InvalidUtf8 { position: 0 },
                ModelErrorCode::SourceInvalidUtf8,
            ),
            (
                SourceLocationError::ByteOffsetTooLarge {
                    offset: 2,
                    limit: 1,
                },
                ModelErrorCode::SourceByteOffsetTooLarge,
            ),
            (
                SourceLocationError::ByteOffsetOutOfBounds {
                    offset: 2,
                    source_len: 1,
                },
                ModelErrorCode::SourceByteOffsetOutOfBounds,
            ),
            (
                SourceLocationError::ByteOffsetNotCharBoundary { offset: 1 },
                ModelErrorCode::SourceByteOffsetNotCharBoundary,
            ),
        ];

        for (error, expected) in cases {
            let validation = ModelValidationError::from(error);
            assert_eq!(validation.code_kind(), expected);
            assert_eq!(validation.code(), expected.as_str());
        }
    }
}
