// SPDX-License-Identifier: Apache-2.0
//! Stable, input-facing model errors.

use core::fmt;

use crate::{NodeId, SourceLocationError, ValidationLimitKind};

/// Errors raised while mutating or traversing an identity tree.
#[derive(Clone, Debug, Eq, PartialEq)]
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

impl TreeError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NodeNotFound { .. } => "model.tree.node-not-found",
            Self::ParentNotFound { .. } => "model.tree.parent-not-found",
            Self::DuplicateNodeId { .. } => "model.tree.duplicate-node-id",
            Self::NodeIdExhausted => "model.tree.node-id-exhausted",
            Self::NodeHasChildren { .. } => "model.tree.node-has-children",
            Self::TraversalLimitExceeded { .. } => "model.tree.traversal-limit-exceeded",
            Self::QueryLimitExceeded { .. } => "model.tree.query-limit-exceeded",
            Self::ParentMismatch { .. } => "model.tree.parent-mismatch",
            Self::InvariantViolation { .. } => "model.tree.invariant-violation",
        }
    }
}

impl fmt::Display for TreeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NodeNotFound { id } => write!(formatter, "node {id} was not found"),
            Self::ParentNotFound { id } => write!(formatter, "parent node {id} was not found"),
            Self::DuplicateNodeId { id } => write!(formatter, "node ID {id} is already in use"),
            Self::NodeIdExhausted => formatter.write_str("document-local node IDs are exhausted"),
            Self::NodeHasChildren { id } => write!(formatter, "node {id} has children"),
            Self::TraversalLimitExceeded { limit } => {
                write!(formatter, "tree traversal exceeded the event limit {limit}")
            }
            Self::QueryLimitExceeded { operation, limit } => {
                write!(
                    formatter,
                    "tree query {operation} exceeded the allocation limit {limit}"
                )
            }
            Self::ParentMismatch {
                id,
                expected,
                actual,
            } => write!(
                formatter,
                "node {id} belongs under parent {expected:?}, not {actual:?}"
            ),
            Self::InvariantViolation { detail } => {
                write!(formatter, "identity tree invariant violated: {detail}")
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
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::DuplicateName { .. } => "model.property.duplicate-name",
            Self::NameNotFound { .. } => "model.property.name-not-found",
        }
    }
}

impl fmt::Display for PropertyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateName { name } => write!(formatter, "property {name:?} already exists"),
            Self::NameNotFound { name } => write!(formatter, "property {name:?} was not found"),
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
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        "model.property.type-mismatch"
    }
}

impl fmt::Display for PropertyTypeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "property kind mismatch: expected {}, got {}",
            self.expected, self.actual
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
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::LimitExceeded { kind, .. } => kind.code(),
            Self::EmptyMetadata { .. } => "model.validation.empty-metadata",
            Self::InvalidSourceLocation { error } => error.code(),
            Self::DuplicatePropertyName { .. } => "model.validation.duplicate-property-name",
        }
    }
}

impl fmt::Display for ModelValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimitExceeded {
                kind,
                limit,
                actual,
            } => write!(
                formatter,
                "model validation {} exceeded limit {limit} (observed {actual})",
                kind.code()
            ),
            Self::EmptyMetadata { field } => {
                write!(
                    formatter,
                    "required {} metadata is empty",
                    field.wire_name()
                )
            }
            Self::InvalidSourceLocation { error } => error.fmt(formatter),
            Self::DuplicatePropertyName { name } => {
                write!(formatter, "property {name:?} appears more than once")
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
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ModelCapabilityError {
    /// Lossless wire data belongs to the JMX syntax/sidecar layer.
    UnsupportedLosslessWire {
        /// Static operation context safe to include in diagnostics.
        context: &'static str,
    },
}

impl ModelCapabilityError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedLosslessWire { .. } => "model.capability.unsupported-lossless-wire",
        }
    }
}

impl fmt::Display for ModelCapabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedLosslessWire { context } => write!(
                formatter,
                "lossless wire conversion is unsupported in the pure model ({context})"
            ),
        }
    }
}

impl std::error::Error for ModelCapabilityError {}

/// A common model error for callers that handle properties and trees together.
#[derive(Clone, Debug, Eq, PartialEq)]
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
}

impl ModelError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Tree(error) => error.code(),
            Self::Property(error) => error.code(),
            Self::PropertyType(error) => error.code(),
            Self::Validation(error) => error.code(),
            Self::Capability(error) => error.code(),
        }
    }
}

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tree(error) => error.fmt(formatter),
            Self::Property(error) => error.fmt(formatter),
            Self::PropertyType(error) => error.fmt(formatter),
            Self::Validation(error) => error.fmt(formatter),
            Self::Capability(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ModelError {}

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
