// SPDX-License-Identifier: Apache-2.0
//! Opaque extension payloads retained by the semantic model.
//!
//! These payload bytes are semantic/plugin data, not a second copy of the
//! source XML event stream.  The JMX crate owns unknown tags, attributes,
//! lexical spelling, source placement, and raw subtree sidecars required for
//! lossless wire output.

use core::fmt;

/// Data whose upstream type is not understood by the current profile.
///
/// `raw` is deliberately bytes rather than a parsed Rust value.  The JMX
/// boundary can therefore retain an unknown/plugin payload without guessing
/// its encoding or silently dropping it.  This type performs no I/O and does
/// not interpret the bytes.  Its [`Debug`] implementation reports the type
/// and payload lengths while redacting the bytes; callers that own a trusted
/// serialization boundary may still access [`OpaqueValue::raw`] explicitly.
#[derive(Clone, Default, Eq, Hash, PartialEq)]
pub struct OpaqueValue {
    /// The upstream or plugin type name, when one was available.
    pub type_name: String,
    /// The original payload bytes.
    pub raw: Vec<u8>,
}

impl fmt::Debug for OpaqueValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueValue")
            .field("type_name", &"<redacted>")
            .field("type_name_len", &self.type_name.len())
            .field("raw_len", &self.raw.len())
            .field("raw", &"<redacted>")
            .finish()
    }
}

impl OpaqueValue {
    /// Creates an opaque value from an upstream type name and raw bytes.
    #[must_use]
    pub fn new(type_name: impl Into<String>, raw: impl Into<Vec<u8>>) -> Self {
        Self {
            type_name: type_name.into(),
            raw: raw.into(),
        }
    }

    /// Creates an opaque value from textual payload while preserving UTF-8
    /// bytes exactly.
    #[must_use]
    pub fn text(type_name: impl Into<String>, text: impl Into<String>) -> Self {
        Self::new(type_name, text.into().into_bytes())
    }

    /// Returns the payload as UTF-8 when it is valid UTF-8.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        std::str::from_utf8(&self.raw).ok()
    }

    /// Returns the retained payload bytes for an explicitly trusted boundary.
    ///
    /// Ordinary diagnostics use the redacted [`Debug`](fmt::Debug)
    /// implementation instead of this lossless accessor.
    #[must_use]
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Alias for [`Self::raw_bytes`].
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        self.raw_bytes()
    }

    /// Returns the retained payload bytes by value for an explicitly trusted
    /// boundary.
    #[must_use]
    pub fn into_raw(self) -> Vec<u8> {
        self.raw
    }
}

/// Semantic alias for an opaque extension attached to an element.
pub type OpaqueExtension = OpaqueValue;

/// Semantic alias used when an unknown value is retained from an input plan.
pub type UnknownValue = OpaqueValue;

/// Semantic alias used by callers that store arbitrary opaque element data.
pub type OpaqueData = OpaqueValue;
