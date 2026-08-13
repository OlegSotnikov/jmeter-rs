// SPDX-License-Identifier: Apache-2.0
//! Document-local node identity.

use core::fmt;
use core::num::NonZeroU64;
use core::str::FromStr;

/// Width of the canonical binary representation of a [`NodeId`].
pub const NODE_ID_WIRE_BYTES: usize = core::mem::size_of::<u64>();

/// A stable identity for one node in one semantic document.
///
/// IDs are intentionally small and opaque to callers.  They are unique only
/// within the tree that allocated them; they must not be used as a process-wide
/// identifier or as a substitute for an element's name.  A tree allocates IDs
/// monotonically starting at one.  [`NodeId::new`] is provided for restoring a
/// previously recorded document-local ID.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NodeId(u64);

impl NodeId {
    /// The first ID used by an automatically allocated tree node.
    pub const FIRST: Self = Self(1);

    /// The smallest nonzero ID accepted by a checked constructor.
    pub const MIN: Self = Self::FIRST;

    /// The largest representable document-local ID.
    pub const MAX: Self = Self(u64::MAX);

    /// Creates a document-local ID from its raw representation.
    ///
    /// This constructor is intentionally infallible for import and restore
    /// paths: a persisted document may contain the raw value zero.  New IDs
    /// created from untrusted or domain-bound input should use
    /// [`NodeId::try_new`] instead; it rejects zero rather than turning it
    /// into a sentinel or another ID.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Creates an assigned document-local ID, rejecting the unassigned value.
    ///
    /// `None` is deliberate here.  Callers that need to preserve a malformed
    /// or legacy raw value can still use [`NodeId::new`] and inspect
    /// [`NodeId::is_zero`], while a checked boundary cannot accidentally
    /// accept zero as a real node identity.
    #[must_use]
    pub const fn try_new(raw: u64) -> Option<Self> {
        if raw == 0 { None } else { Some(Self(raw)) }
    }

    /// Creates an ID from a [`NonZeroU64`] without losing its invariant.
    #[must_use]
    pub const fn from_nonzero(raw: NonZeroU64) -> Self {
        Self(raw.get())
    }

    /// Returns this ID as a [`NonZeroU64`] when it is assigned.
    #[must_use]
    pub const fn as_nonzero(self) -> Option<NonZeroU64> {
        NonZeroU64::new(self.0)
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

    /// Returns the fixed-width canonical big-endian wire representation.
    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; NODE_ID_WIRE_BYTES] {
        self.0.to_be_bytes()
    }

    /// Restores a raw ID from its fixed-width big-endian representation.
    ///
    /// This is the lossless counterpart to [`NodeId::to_be_bytes`].  It does
    /// not reinterpret zero; use [`NodeId::try_from_be_bytes`] when a wire
    /// boundary requires an assigned identity.
    #[must_use]
    pub const fn from_be_bytes(bytes: [u8; NODE_ID_WIRE_BYTES]) -> Self {
        Self::new(u64::from_be_bytes(bytes))
    }

    /// Restores an assigned ID from its canonical big-endian representation.
    #[must_use]
    pub const fn try_from_be_bytes(bytes: [u8; NODE_ID_WIRE_BYTES]) -> Option<Self> {
        Self::try_new(u64::from_be_bytes(bytes))
    }

    /// Adds an offset without wrapping into zero or beyond the ID space.
    ///
    /// The raw restore value zero remains representable by [`NodeId::new`],
    /// but checked arithmetic never returns it as an assigned ID.
    #[must_use]
    pub const fn checked_add(self, offset: u64) -> Option<Self> {
        match self.0.checked_add(offset) {
            Some(raw) => Self::try_new(raw),
            None => None,
        }
    }

    /// Returns the next ID without wrapping at `u64::MAX`.
    #[must_use]
    pub const fn checked_next(self) -> Option<Self> {
        self.checked_add(1)
    }

    /// Returns whether this ID is the zero value.
    ///
    /// Zero is accepted by [`NodeId::new`] because it is useful when importing
    /// externally assigned IDs.  Newly allocated tree IDs start at one.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Returns whether this ID is valid for a domain-bound node reference.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        !self.is_zero()
    }
}

impl From<NonZeroU64> for NodeId {
    fn from(raw: NonZeroU64) -> Self {
        Self::from_nonzero(raw)
    }
}

impl TryFrom<NodeId> for NonZeroU64 {
    type Error = ();

    fn try_from(id: NodeId) -> Result<Self, Self::Error> {
        id.as_nonzero().ok_or(())
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

impl FromStr for NodeId {
    type Err = <u64 as FromStr>::Err;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value.parse::<u64>().map(Self::new)
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "deterministic identity tests assert successful setup before inspecting values"
)]
mod tests {
    use super::{NODE_ID_WIRE_BYTES, NodeId};
    use core::num::NonZeroU64;
    use std::collections::HashSet;
    use std::str::FromStr;

    #[test]
    fn checked_construction_rejects_zero_without_rewriting_it() {
        let imported = NodeId::new(0);
        assert!(imported.is_zero());
        assert!(!imported.is_valid());
        assert!(NodeId::try_new(0).is_none());
        assert_eq!(NodeId::try_new(1), Some(NodeId::FIRST));

        let nonzero = NonZeroU64::new(9).expect("nonzero fixture");
        assert_eq!(NodeId::from_nonzero(nonzero), NodeId::new(9));
        assert_eq!(NodeId::new(9).as_nonzero(), Some(nonzero));
        assert_eq!(imported.as_nonzero(), None);
    }

    #[test]
    fn ordering_and_hashing_are_numeric_and_collision_free() {
        let mut ids = [NodeId::new(3), NodeId::new(1), NodeId::new(2)];
        ids.sort();
        assert_eq!(ids, [NodeId::new(1), NodeId::new(2), NodeId::new(3)]);

        let distinct = [NodeId::new(0), NodeId::new(1), NodeId::new(2)]
            .into_iter()
            .collect::<HashSet<_>>();
        assert_eq!(distinct.len(), 3);
        assert_ne!(NodeId::new(0), NodeId::new(1));
        assert_eq!(NodeId::new(2), NodeId::from(2_u64));
    }

    #[test]
    fn checked_arithmetic_is_bounded_and_does_not_wrap() {
        assert_eq!(NodeId::new(0).checked_next(), Some(NodeId::FIRST));
        assert_eq!(NodeId::new(1).checked_add(0), Some(NodeId::new(1)));
        assert_eq!(NodeId::new(u64::MAX - 1).checked_next(), Some(NodeId::MAX));
        assert_eq!(NodeId::MAX.checked_next(), None);
        assert_eq!(NodeId::MAX.checked_add(1), None);
        assert_eq!(NodeId::MAX.checked_add(u64::MAX), None);
    }

    #[test]
    fn canonical_wire_and_text_round_trips_preserve_raw_identity() {
        let id = NodeId::new(0x0102_0304_0506_0708);
        assert_eq!(NODE_ID_WIRE_BYTES, 8);
        assert_eq!(id.to_be_bytes(), [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(NodeId::from_be_bytes(id.to_be_bytes()), id);
        assert_eq!(NodeId::try_from_be_bytes(id.to_be_bytes()), Some(id));
        assert_eq!(
            NodeId::from_be_bytes([0; NODE_ID_WIRE_BYTES]),
            NodeId::new(0)
        );
        assert_eq!(NodeId::try_from_be_bytes([0; NODE_ID_WIRE_BYTES]), None);

        let text = id.to_string();
        assert_eq!(NodeId::from_str(&text), Ok(id));
        assert_eq!(NodeId::from_str("0"), Ok(NodeId::new(0)));
        assert!(NodeId::from_str("18446744073709551616").is_err());
        assert!(NodeId::from_str("not-an-id").is_err());
    }
}
