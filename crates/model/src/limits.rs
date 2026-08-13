// SPDX-License-Identifier: Apache-2.0
//! Resource limits for directly constructed semantic model values.

/// Limits used when validating a model assembled without the JMX decoder.
///
/// The JMX boundary has its own syntax and semantic limits.  These limits are
/// the corresponding defense-in-depth API for callers that construct or
/// receive model values directly.  Validation is explicit so an importer can
/// choose a profile-specific budget without making the pure model depend on a
/// parser or a global configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidationLimits {
    /// Maximum number of nodes in one identity tree.
    pub max_nodes: usize,
    /// Maximum zero-based depth of one identity tree.
    ///
    /// A root is at depth zero, so a value of zero permits roots but rejects
    /// any child.  The bound is checked with an explicit heap-backed walk;
    /// validation never relies on the Rust call stack for hostile trees.
    pub max_tree_depth: usize,
    /// Maximum number of property values, including nested values, in one
    /// validated model instance.
    pub max_properties: usize,
    /// Maximum nested property depth.  Top-level properties have depth zero.
    pub max_property_depth: usize,
    /// Maximum aggregate bytes retained by opaque/object payloads.
    pub max_opaque_bytes: usize,
    /// Maximum aggregate bytes retained by model strings and names.
    pub max_string_bytes: usize,
}

impl Default for ValidationLimits {
    fn default() -> Self {
        Self {
            max_nodes: 100_000,
            max_tree_depth: 256,
            max_properties: 500_000,
            max_property_depth: 256,
            max_opaque_bytes: 8 * 1024 * 1024,
            max_string_bytes: 16 * 1024 * 1024,
        }
    }
}

impl ValidationLimits {
    /// A conservative budget for deterministic unit tests and small plans.
    pub const fn small() -> Self {
        Self {
            max_nodes: 1_000,
            max_tree_depth: 64,
            max_properties: 10_000,
            max_property_depth: 64,
            max_opaque_bytes: 512 * 1024,
            max_string_bytes: 2 * 1024 * 1024,
        }
    }
}

/// The resource dimension that caused model validation to stop.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ValidationLimitKind {
    /// The identity tree contains too many nodes.
    Nodes,
    /// A tree node exceeds the permitted zero-based depth.
    TreeDepth,
    /// The model contains too many property values.
    Properties,
    /// A nested property exceeds the permitted depth.
    PropertyDepth,
    /// Opaque/object payloads exceed the permitted aggregate bytes.
    OpaqueBytes,
    /// Model names and strings exceed the permitted aggregate bytes.
    StringBytes,
}

impl ValidationLimitKind {
    /// Returns the stable machine-readable error code suffix.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Nodes => "model.validation.limit-nodes",
            Self::TreeDepth => "model.validation.limit-tree-depth",
            Self::Properties => "model.validation.limit-properties",
            Self::PropertyDepth => "model.validation.limit-property-depth",
            Self::OpaqueBytes => "model.validation.limit-opaque-bytes",
            Self::StringBytes => "model.validation.limit-string-bytes",
        }
    }
}

/// Internal accounting state shared by bounded model validation.
pub(crate) struct ValidationState<'a> {
    limits: &'a ValidationLimits,
    properties: usize,
    opaque_bytes: usize,
    string_bytes: usize,
}

impl<'a> ValidationState<'a> {
    pub(crate) const fn new(limits: &'a ValidationLimits) -> Self {
        Self {
            limits,
            properties: 0,
            opaque_bytes: 0,
            string_bytes: 0,
        }
    }

    pub(crate) const fn limits(&self) -> &'a ValidationLimits {
        self.limits
    }

    pub(crate) fn add_property(&mut self) -> Result<(), crate::ModelValidationError> {
        self.properties = self.properties.saturating_add(1);
        if self.properties > self.limits.max_properties {
            return Err(crate::ModelValidationError::LimitExceeded {
                kind: ValidationLimitKind::Properties,
                limit: self.limits.max_properties,
                actual: self.properties,
            });
        }
        Ok(())
    }

    pub(crate) fn add_opaque_bytes(
        &mut self,
        bytes: usize,
    ) -> Result<(), crate::ModelValidationError> {
        self.opaque_bytes = self.opaque_bytes.saturating_add(bytes);
        if self.opaque_bytes > self.limits.max_opaque_bytes {
            return Err(crate::ModelValidationError::LimitExceeded {
                kind: ValidationLimitKind::OpaqueBytes,
                limit: self.limits.max_opaque_bytes,
                actual: self.opaque_bytes,
            });
        }
        Ok(())
    }

    pub(crate) fn add_string_bytes(
        &mut self,
        bytes: usize,
    ) -> Result<(), crate::ModelValidationError> {
        self.string_bytes = self.string_bytes.saturating_add(bytes);
        if self.string_bytes > self.limits.max_string_bytes {
            return Err(crate::ModelValidationError::LimitExceeded {
                kind: ValidationLimitKind::StringBytes,
                limit: self.limits.max_string_bytes,
                actual: self.string_bytes,
            });
        }
        Ok(())
    }
}
