// SPDX-License-Identifier: Apache-2.0
//! Sealed purpose markers and policy selection.

use crate::error::{ErrorCategory, ErrorCode, SupervisionError};

/// Internal cleanup policy.  It is never parsed from caller strings.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum PolicyKind {
    /// Reviewed helpers that are forbidden from creating descendants.
    ExactChild,
    /// Java/JMeter/plugin/OS-process ownership with group/Job containment.
    ProcessTree,
}

impl PolicyKind {
    pub(crate) const fn requires_tree(self) -> bool {
        matches!(self, Self::ProcessTree)
    }

    pub(crate) fn validate_platform(self) -> Result<(), SupervisionError> {
        if self.requires_tree() && !crate::process_tree_supported() {
            return Err(SupervisionError::new(
                ErrorCode::UnsupportedPlatform,
                ErrorCategory::Unsupported,
                false,
                "process-tree containment evidence is unavailable on this target",
            ));
        }
        Ok(())
    }
}

mod sealed {
    pub trait Purpose {}
}

/// A purpose type is sealed so callers cannot create a weaker policy marker.
pub(crate) trait PurposeMarker: sealed::Purpose + Copy + Send + Sync + 'static {
    const KIND: PolicyKind;
}

/// Marker for the reviewed no-descendant exact-child allowlist.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub(crate) struct ExactChild;

impl sealed::Purpose for ExactChild {}
impl PurposeMarker for ExactChild {
    const KIND: PolicyKind = PolicyKind::ExactChild;
}

/// Marker for Java/JMeter/plugin/OS process-tree ownership.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub(crate) struct ProcessTree;

impl sealed::Purpose for ProcessTree {}
impl PurposeMarker for ProcessTree {
    const KIND: PolicyKind = PolicyKind::ProcessTree;
}
