// SPDX-License-Identifier: Apache-2.0
//! Document-local node identity.

use core::fmt;

/// A stable identity for one node in one semantic document.
///
/// IDs are intentionally small and opaque to callers.  They are unique only
/// within the tree that allocated them; they must not be used as a process-wide
/// identifier or as a substitute for an element's name.  A tree allocates IDs
/// monotonically starting at one.  [`NodeId::new`] is provided for restoring a
/// previously recorded document-local ID.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NodeId(u64);

impl NodeId {
    /// Creates a document-local ID from its raw representation.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the raw document-local representation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns the raw document-local representation.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Returns whether this ID is the zero value.
    ///
    /// Zero is accepted by [`NodeId::new`] because it is useful when importing
    /// externally assigned IDs.  Newly allocated tree IDs start at one.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl From<u64> for NodeId {
    fn from(raw: u64) -> Self {
        Self::new(raw)
    }
}

impl From<NodeId> for u64 {
    fn from(id: NodeId) -> Self {
        id.get()
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}
