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
    /// Creates a validated set of model limits.
    ///
    /// Every dimension is required to be finite and non-zero.  A zero depth
    /// remains a useful validation boundary (it permits a root and rejects
    /// its children), so callers that need that boundary can still construct
    /// a value with the public fields and pass it directly to validation.  A
    /// constructor intentionally rejects zero so parser/importer policies do
    /// not accidentally turn an omitted limit into an unbounded one.
    #[must_use]
    pub const fn new(
        max_nodes: usize,
        max_tree_depth: usize,
        max_properties: usize,
        max_property_depth: usize,
        max_opaque_bytes: usize,
        max_string_bytes: usize,
    ) -> Option<Self> {
        let limits = Self {
            max_nodes,
            max_tree_depth,
            max_properties,
            max_property_depth,
            max_opaque_bytes,
            max_string_bytes,
        };
        if limits.is_valid() {
            Some(limits)
        } else {
            None
        }
    }

    /// Alias for [`Self::new`] that makes validation explicit at call sites.
    #[must_use]
    pub const fn try_new(
        max_nodes: usize,
        max_tree_depth: usize,
        max_properties: usize,
        max_property_depth: usize,
        max_opaque_bytes: usize,
        max_string_bytes: usize,
    ) -> Option<Self> {
        Self::new(
            max_nodes,
            max_tree_depth,
            max_properties,
            max_property_depth,
            max_opaque_bytes,
            max_string_bytes,
        )
    }

    /// Returns whether all limit dimensions are finite and non-zero.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.max_nodes != 0
            && self.max_tree_depth != 0
            && self.max_properties != 0
            && self.max_property_depth != 0
            && self.max_opaque_bytes != 0
            && self.max_string_bytes != 0
    }

    /// Returns the conservative component-wise intersection of two policies.
    ///
    /// The result can never be wider than either input.  Invalid policies
    /// (including a policy with a zero dimension assembled through the public
    /// fields) do not produce a policy that could accidentally be accepted by
    /// an input-facing caller.
    #[must_use]
    pub const fn intersect(self, peer: Self) -> Option<Self> {
        let result = Self {
            max_nodes: const_min(self.max_nodes, peer.max_nodes),
            max_tree_depth: const_min(self.max_tree_depth, peer.max_tree_depth),
            max_properties: const_min(self.max_properties, peer.max_properties),
            max_property_depth: const_min(self.max_property_depth, peer.max_property_depth),
            max_opaque_bytes: const_min(self.max_opaque_bytes, peer.max_opaque_bytes),
            max_string_bytes: const_min(self.max_string_bytes, peer.max_string_bytes),
        };
        if result.is_valid() {
            Some(result)
        } else {
            None
        }
    }

    /// Tightens this policy component-wise when `peer` is valid.
    ///
    /// The receiver is unchanged when the requested policy is invalid.  A
    /// `false` result is therefore safe for callers to treat as a stable
    /// configuration rejection rather than continuing with a partially
    /// applied policy.
    pub fn tighten(&mut self, peer: Self) -> bool {
        let Some(narrowed) = self.intersect(peer) else {
            return false;
        };
        *self = narrowed;
        true
    }

    /// Returns whether this policy is no wider than `other` in every dimension.
    #[must_use]
    pub const fn is_at_least_as_tight_as(self, other: Self) -> bool {
        self.max_nodes <= other.max_nodes
            && self.max_tree_depth <= other.max_tree_depth
            && self.max_properties <= other.max_properties
            && self.max_property_depth <= other.max_property_depth
            && self.max_opaque_bytes <= other.max_opaque_bytes
            && self.max_string_bytes <= other.max_string_bytes
    }

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

const fn const_min(left: usize, right: usize) -> usize {
    if left < right { left } else { right }
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
        self.add_properties(1)
    }

    pub(crate) fn add_properties(
        &mut self,
        additional: usize,
    ) -> Result<(), crate::ModelValidationError> {
        let next = checked_total(
            self.properties,
            additional,
            self.limits.max_properties,
            ValidationLimitKind::Properties,
        )?;
        self.properties = next;
        Ok(())
    }

    pub(crate) fn add_opaque_bytes(
        &mut self,
        bytes: usize,
    ) -> Result<(), crate::ModelValidationError> {
        let next = checked_total(
            self.opaque_bytes,
            bytes,
            self.limits.max_opaque_bytes,
            ValidationLimitKind::OpaqueBytes,
        )?;
        self.opaque_bytes = next;
        Ok(())
    }

    pub(crate) fn add_string_bytes(
        &mut self,
        bytes: usize,
    ) -> Result<(), crate::ModelValidationError> {
        let next = checked_total(
            self.string_bytes,
            bytes,
            self.limits.max_string_bytes,
            ValidationLimitKind::StringBytes,
        )?;
        self.string_bytes = next;
        Ok(())
    }
}

/// Adds one bounded resource amount without wrapping or partially committing.
///
/// The observed value in [`crate::ModelValidationError`] is saturated at
/// `usize::MAX` when the mathematical sum is not representable.  The current
/// counter is left untouched on every error, which makes a failed validation
/// state safe to inspect or discard and prevents a failed probe from widening
/// a subsequent validation attempt.
fn checked_total(
    current: usize,
    additional: usize,
    limit: usize,
    kind: ValidationLimitKind,
) -> Result<usize, crate::ModelValidationError> {
    let Some(actual) = current.checked_add(additional) else {
        return Err(crate::ModelValidationError::LimitExceeded {
            kind,
            limit,
            actual: usize::MAX,
        });
    };
    if actual > limit {
        return Err(crate::ModelValidationError::LimitExceeded {
            kind,
            limit,
            actual,
        });
    }
    Ok(actual)
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "deterministic limit tests use expect to assert valid test setup"
)]
mod tests {
    use super::*;
    use crate::ModelValidationError;

    const VALID: ValidationLimits = ValidationLimits {
        max_nodes: 101,
        max_tree_depth: 17,
        max_properties: 103,
        max_property_depth: 19,
        max_opaque_bytes: 107,
        max_string_bytes: 109,
    };

    #[test]
    fn constructors_require_finite_nonzero_dimensions() {
        assert!(
            ValidationLimits::new(
                VALID.max_nodes,
                VALID.max_tree_depth,
                VALID.max_properties,
                VALID.max_property_depth,
                VALID.max_opaque_bytes,
                VALID.max_string_bytes,
            )
            .is_some()
        );
        assert!(
            ValidationLimits::try_new(
                0,
                VALID.max_tree_depth,
                VALID.max_properties,
                VALID.max_property_depth,
                VALID.max_opaque_bytes,
                VALID.max_string_bytes,
            )
            .is_none()
        );

        let fields = [
            VALID.max_nodes,
            VALID.max_tree_depth,
            VALID.max_properties,
            VALID.max_property_depth,
            VALID.max_opaque_bytes,
            VALID.max_string_bytes,
        ];
        for index in 0..fields.len() {
            let mut candidate = fields;
            candidate[index] = 0;
            assert!(
                !ValidationLimits {
                    max_nodes: candidate[0],
                    max_tree_depth: candidate[1],
                    max_properties: candidate[2],
                    max_property_depth: candidate[3],
                    max_opaque_bytes: candidate[4],
                    max_string_bytes: candidate[5],
                }
                .is_valid()
            );
        }

        assert!(ValidationLimits::default().is_valid());
        assert!(ValidationLimits::small().is_valid());
    }

    #[test]
    fn intersection_and_tightening_are_componentwise_and_monotonic() {
        let peer = ValidationLimits {
            max_nodes: 7,
            max_tree_depth: 23,
            max_properties: 97,
            max_property_depth: 11,
            max_opaque_bytes: 53,
            max_string_bytes: 127,
        };
        let narrowed = VALID.intersect(peer).expect("both policies are valid");
        assert!(narrowed.is_at_least_as_tight_as(VALID));
        assert!(narrowed.is_at_least_as_tight_as(peer));
        assert_eq!(narrowed.max_nodes, 7);
        assert_eq!(narrowed.max_tree_depth, 17);
        assert_eq!(narrowed.max_properties, 97);
        assert_eq!(narrowed.max_property_depth, 11);
        assert_eq!(narrowed.max_opaque_bytes, 53);
        assert_eq!(narrowed.max_string_bytes, 109);

        let mut tightened = VALID;
        assert!(tightened.tighten(peer));
        assert_eq!(tightened, narrowed);
        assert!(tightened.is_at_least_as_tight_as(VALID));

        let before_invalid = tightened;
        let invalid = ValidationLimits {
            max_nodes: 0,
            ..peer
        };
        assert!(!tightened.tighten(invalid));
        assert_eq!(tightened, before_invalid);
        assert!(VALID.intersect(invalid).is_none());
    }

    #[test]
    fn intersection_has_lattice_properties_for_valid_limit_vectors() {
        let vectors = [
            VALID,
            ValidationLimits {
                max_nodes: 2,
                max_tree_depth: 3,
                max_properties: 5,
                max_property_depth: 7,
                max_opaque_bytes: 11,
                max_string_bytes: 13,
            },
            ValidationLimits {
                max_nodes: 17,
                max_tree_depth: 19,
                max_properties: 23,
                max_property_depth: 29,
                max_opaque_bytes: 31,
                max_string_bytes: 37,
            },
            ValidationLimits {
                max_nodes: usize::MAX,
                max_tree_depth: usize::MAX - 1,
                max_properties: usize::MAX - 2,
                max_property_depth: usize::MAX - 3,
                max_opaque_bytes: usize::MAX - 4,
                max_string_bytes: usize::MAX - 5,
            },
        ];

        for left in vectors {
            assert_eq!(left.intersect(left), Some(left));
            for middle in vectors {
                let pair = left.intersect(middle).expect("valid vectors intersect");
                assert_eq!(Some(pair), middle.intersect(left));
                assert!(pair.is_at_least_as_tight_as(left));
                assert!(pair.is_at_least_as_tight_as(middle));
                for right in vectors {
                    let left_associated = left
                        .intersect(middle)
                        .and_then(|value| value.intersect(right));
                    let right_associated = middle
                        .intersect(right)
                        .and_then(|value| left.intersect(value));
                    assert_eq!(left_associated, right_associated);
                }
            }
        }
    }

    #[test]
    fn checked_accounting_rejects_limits_without_mutating_state() {
        let limits = ValidationLimits {
            max_nodes: 1,
            max_tree_depth: 1,
            max_properties: 3,
            max_property_depth: 1,
            max_opaque_bytes: 3,
            max_string_bytes: 3,
        };
        let mut state = ValidationState::new(&limits);
        assert!(state.add_properties(2).is_ok());
        let error = state
            .add_properties(2)
            .expect_err("property count boundary");
        assert_eq!(error.code(), "model.validation.limit-properties");
        assert_eq!(state.properties, 2);
        assert_eq!(
            error,
            ModelValidationError::LimitExceeded {
                kind: ValidationLimitKind::Properties,
                limit: 3,
                actual: 4,
            }
        );

        assert!(state.add_opaque_bytes(3).is_ok());
        let error = state.add_opaque_bytes(1).expect_err("opaque byte boundary");
        assert_eq!(error.code(), "model.validation.limit-opaque-bytes");
        assert_eq!(state.opaque_bytes, 3);

        assert!(state.add_string_bytes(3).is_ok());
        let error = state.add_string_bytes(1).expect_err("string byte boundary");
        assert_eq!(error.code(), "model.validation.limit-string-bytes");
        assert_eq!(state.string_bytes, 3);
    }

    #[test]
    fn checked_accounting_reports_overflow_as_a_stable_limit_error() {
        let limits = ValidationLimits {
            max_nodes: 1,
            max_tree_depth: 1,
            max_properties: usize::MAX,
            max_property_depth: 1,
            max_opaque_bytes: usize::MAX,
            max_string_bytes: usize::MAX,
        };
        let mut state = ValidationState::new(&limits);
        state.properties = usize::MAX - 1;
        state.opaque_bytes = usize::MAX - 1;
        state.string_bytes = usize::MAX - 1;

        let error = state
            .add_properties(2)
            .expect_err("property accounting must not wrap");
        assert_eq!(error.code(), "model.validation.limit-properties");
        assert_eq!(state.properties, usize::MAX - 1);

        let error = state
            .add_opaque_bytes(2)
            .expect_err("opaque accounting must not wrap");
        assert_eq!(error.code(), "model.validation.limit-opaque-bytes");
        assert_eq!(state.opaque_bytes, usize::MAX - 1);

        let error = state
            .add_string_bytes(2)
            .expect_err("string accounting must not wrap");
        assert_eq!(error.code(), "model.validation.limit-string-bytes");
        assert_eq!(state.string_bytes, usize::MAX - 1);
    }

    #[test]
    fn all_limit_error_codes_are_stable_and_distinct() {
        let kinds = [
            ValidationLimitKind::Nodes,
            ValidationLimitKind::TreeDepth,
            ValidationLimitKind::Properties,
            ValidationLimitKind::PropertyDepth,
            ValidationLimitKind::OpaqueBytes,
            ValidationLimitKind::StringBytes,
        ];
        for (index, kind) in kinds.iter().enumerate() {
            assert!(kind.code().starts_with("model.validation.limit-"));
            assert!(
                kinds[..index]
                    .iter()
                    .all(|previous| previous.code() != kind.code())
            );
        }
    }
}
