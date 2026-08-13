// SPDX-License-Identifier: Apache-2.0
//! Opaque extension payloads retained by the semantic model.
//!
//! These payload bytes are semantic/plugin data, not a second copy of the
//! source XML event stream.  The JMX crate owns unknown tags, attributes,
//! lexical spelling, source placement, and raw subtree sidecars required for
//! lossless wire output.  This module retains each payload as exact bytes and
//! keeps source-field presence separate from an explicitly empty field; the
//! owner collection is responsible for preserving the ordered sequence.

use core::fmt;

use crate::{ModelValidationError, ValidationLimits};

/// A hard per-value payload ceiling used by the fallible constructors.
///
/// Document decoders normally use their own profile-specific aggregate
/// budget.  This ceiling is the conservative default for callers that build
/// one value directly and want an allocation bound without first constructing
/// a full model.  It deliberately matches the profile's default aggregate
/// opaque-byte budget; callers with a smaller budget should use
/// [`OpaqueValue::try_new_with_limit`] or [`OpaqueValue::validate_with_limits`].
pub const DEFAULT_MAX_OPAQUE_VALUE_BYTES: usize = 8 * 1024 * 1024;

/// A failure while constructing one bounded opaque payload.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OpaqueValueError {
    /// The payload is larger than the caller's per-value budget.
    PayloadTooLarge {
        /// Maximum payload bytes accepted by the operation.
        limit: usize,
        /// Payload bytes supplied by the caller.
        actual: usize,
    },
}

impl OpaqueValueError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::PayloadTooLarge { .. } => "model.opaque.limit-bytes",
        }
    }
}

impl fmt::Display for OpaqueValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooLarge { limit, actual } => write!(
                formatter,
                "opaque payload exceeds limit {limit} bytes (observed {actual})"
            ),
        }
    }
}

impl std::error::Error for OpaqueValueError {}

/// Data whose upstream type is not understood by the current profile.
///
/// `raw` is deliberately bytes rather than a parsed Rust value.  The JMX
/// boundary can therefore retain an unknown/plugin payload without guessing
/// its encoding or silently dropping it.  This type performs no I/O and does
/// not interpret the bytes.  Its [`Debug`] implementation reports the type
/// and payload lengths while redacting the bytes; callers that own a trusted
/// serialization boundary may still access [`OpaqueValue::raw`] explicitly.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct OpaqueValue {
    /// The upstream or plugin type name, when one was available.
    pub type_name: String,
    /// The original payload bytes.
    pub raw: Vec<u8>,
    /// Whether the source carried a type-name field.
    ///
    /// The public `type_name` field remains a `String` for compatibility with
    /// existing model users.  This bit preserves the wire distinction between
    /// an absent field and a field present with an empty value.  Values made by
    /// [`OpaqueValue::new`] have this bit set; use
    /// [`OpaqueValue::from_optional_type_name`] when decoding a source where
    /// the distinction is observable.
    type_name_present: bool,
    /// Whether the source carried a payload field.
    ///
    /// An explicitly empty payload is present and is therefore different from
    /// an absent payload.  Values made by [`OpaqueValue::new`] have this bit
    /// set; use [`OpaqueValue::from_optional_raw`] for an absent source field.
    raw_present: bool,
}

impl fmt::Debug for OpaqueValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueValue")
            .field("type_name", &"<redacted>")
            .field("type_name_len", &self.type_name.len())
            .field("type_name_present", &self.type_name_present)
            .field("raw_len", &self.raw.len())
            .field("raw_present", &self.raw_present)
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
            type_name_present: true,
            raw_present: true,
        }
    }

    /// Creates an opaque value while preserving optional source presence.
    ///
    /// `Some(String::new())` and `None` are deliberately distinct.  The same
    /// distinction is retained for the payload: `Some(Vec::new())` means a
    /// present-but-empty payload, while `None` means the source field was
    /// absent.  No bytes are normalized, decoded, or silently discarded.
    #[must_use]
    pub fn from_optional_fields(type_name: Option<String>, raw: Option<Vec<u8>>) -> Self {
        let (type_name, type_name_present) = match type_name {
            Some(type_name) => (type_name, true),
            None => (String::new(), false),
        };
        let (raw, raw_present) = match raw {
            Some(raw) => (raw, true),
            None => (Vec::new(), false),
        };
        Self {
            type_name,
            raw,
            type_name_present,
            raw_present,
        }
    }

    /// Creates an opaque value with an optional source type name and a present
    /// payload, retaining an explicitly empty type name.
    #[must_use]
    pub fn from_optional_type_name(type_name: Option<String>, raw: impl Into<Vec<u8>>) -> Self {
        let raw = raw.into();
        let (type_name, type_name_present) = match type_name {
            Some(type_name) => (type_name, true),
            None => (String::new(), false),
        };
        Self {
            type_name,
            raw,
            type_name_present,
            raw_present: true,
        }
    }

    /// Creates an opaque value with a present type name and an optional source
    /// payload, retaining a present-but-empty payload.
    #[must_use]
    pub fn from_optional_raw(type_name: impl Into<String>, raw: Option<Vec<u8>>) -> Self {
        let type_name = type_name.into();
        let (raw, raw_present) = match raw {
            Some(raw) => (raw, true),
            None => (Vec::new(), false),
        };
        Self {
            type_name,
            raw,
            type_name_present: true,
            raw_present,
        }
    }

    /// Creates an opaque value, rejecting a payload larger than the supplied
    /// per-value budget before retaining it.
    pub fn try_new_with_limit(
        type_name: impl Into<String>,
        raw: impl Into<Vec<u8>>,
        max_payload_bytes: usize,
    ) -> Result<Self, OpaqueValueError> {
        let raw = raw.into();
        if raw.len() > max_payload_bytes {
            return Err(OpaqueValueError::PayloadTooLarge {
                limit: max_payload_bytes,
                actual: raw.len(),
            });
        }
        Ok(Self::new(type_name, raw))
    }

    /// Creates an opaque value from a borrowed byte slice, checking its size
    /// before allocating a retained copy.
    pub fn try_from_slice(
        type_name: impl Into<String>,
        raw: &[u8],
        max_payload_bytes: usize,
    ) -> Result<Self, OpaqueValueError> {
        if raw.len() > max_payload_bytes {
            return Err(OpaqueValueError::PayloadTooLarge {
                limit: max_payload_bytes,
                actual: raw.len(),
            });
        }
        Ok(Self::new(type_name, raw.to_vec()))
    }

    /// Creates an opaque value using [`DEFAULT_MAX_OPAQUE_VALUE_BYTES`] as the
    /// per-value payload budget.
    pub fn try_new(
        type_name: impl Into<String>,
        raw: impl Into<Vec<u8>>,
    ) -> Result<Self, OpaqueValueError> {
        Self::try_new_with_limit(type_name, raw, DEFAULT_MAX_OPAQUE_VALUE_BYTES)
    }

    /// Creates an opaque value from textual payload while preserving UTF-8
    /// bytes exactly.
    #[must_use]
    pub fn text(type_name: impl Into<String>, text: impl Into<String>) -> Self {
        Self::new(type_name, text.into().into_bytes())
    }

    /// Creates a bounded textual opaque value.
    pub fn try_text_with_limit(
        type_name: impl Into<String>,
        text: impl AsRef<str>,
        max_payload_bytes: usize,
    ) -> Result<Self, OpaqueValueError> {
        let text = text.as_ref();
        Self::try_from_slice(type_name, text.as_bytes(), max_payload_bytes)
    }

    /// Returns whether the source carried a type-name field.
    #[must_use]
    pub const fn type_name_present(&self) -> bool {
        self.type_name_present
    }

    /// Returns the optional source type-name field.
    #[must_use]
    pub fn optional_type_name(&self) -> Option<&str> {
        self.type_name_present.then_some(self.type_name.as_str())
    }

    /// Returns whether the source carried a payload field.
    #[must_use]
    pub const fn raw_present(&self) -> bool {
        self.raw_present
    }

    /// Returns the optional source payload field.
    #[must_use]
    pub fn optional_raw(&self) -> Option<&[u8]> {
        self.raw_present.then_some(self.raw.as_slice())
    }

    /// Replaces the optional source type-name field while preserving exact
    /// payload bytes and payload presence.
    #[must_use]
    pub fn with_optional_type_name(mut self, type_name: Option<String>) -> Self {
        (self.type_name, self.type_name_present) = match type_name {
            Some(type_name) => (type_name, true),
            None => (String::new(), false),
        };
        self
    }

    /// Replaces the optional source payload field while preserving exact type
    /// name bytes and type-name presence.
    #[must_use]
    pub fn with_optional_raw(mut self, raw: Option<Vec<u8>>) -> Self {
        (self.raw, self.raw_present) = match raw {
            Some(raw) => (raw, true),
            None => (Vec::new(), false),
        };
        self
    }

    /// Validates this opaque value against caller-provided model budgets.
    ///
    /// This operation is explicit because `new` is retained as a compatibility
    /// constructor for callers that already own an allocated byte vector.  It
    /// never truncates, replaces, or defaults a field: an excess is returned
    /// as a stable model validation error.
    pub fn validate_with_limits(
        &self,
        limits: &ValidationLimits,
    ) -> Result<(), ModelValidationError> {
        let mut state = crate::limits::ValidationState::new(limits);
        state.add_string_bytes(self.type_name.len())?;
        state.add_opaque_bytes(self.raw.len())
    }

    /// Returns the payload as UTF-8 when it is valid UTF-8.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        if !self.raw_present {
            return None;
        }
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

    /// Returns the optional retained payload by value.
    ///
    /// Unlike [`Self::into_raw`], this preserves the distinction between an
    /// absent payload and a present-but-empty payload for a consuming caller.
    #[must_use]
    pub fn into_optional_raw(self) -> Option<Vec<u8>> {
        self.raw_present.then_some(self.raw)
    }

    /// Returns the optional retained type name by value.
    ///
    /// Unlike reading the compatibility [`Self::type_name`] field directly,
    /// this preserves whether the source field was absent.
    #[must_use]
    pub fn into_optional_type_name(self) -> Option<String> {
        self.type_name_present.then_some(self.type_name)
    }
}

/// Semantic alias for an opaque extension attached to an element.
pub type OpaqueExtension = OpaqueValue;

/// Semantic alias used when an unknown value is retained from an input plan.
pub type UnknownValue = OpaqueValue;

/// Semantic alias used by callers that store arbitrary opaque element data.
pub type OpaqueData = OpaqueValue;

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "deterministic unit tests assert successful setup before inspecting values"
)]
mod tests {
    use super::*;

    #[test]
    fn optional_fields_preserve_absent_empty_and_nonempty_presence() {
        let absent = OpaqueValue::from_optional_fields(None, None);
        let empty = OpaqueValue::from_optional_fields(Some(String::new()), Some(Vec::<u8>::new()));
        let present = OpaqueValue::new("plugin.Value", vec![0, 255, 7]);

        assert!(!absent.type_name_present());
        assert_eq!(absent.optional_type_name(), None);
        assert!(!absent.raw_present());
        assert_eq!(absent.optional_raw(), None);
        assert_eq!(absent.as_text(), None);
        assert_eq!(absent.clone().into_optional_type_name(), None);
        assert_eq!(absent.clone().into_optional_raw(), None);

        assert!(empty.type_name_present());
        assert_eq!(empty.optional_type_name(), Some(""));
        assert!(empty.raw_present());
        assert_eq!(empty.optional_raw(), Some([].as_slice()));
        assert_eq!(empty.as_text(), Some(""));

        assert!(present.type_name_present());
        assert_eq!(present.optional_type_name(), Some("plugin.Value"));
        assert!(present.raw_present());
        assert_eq!(present.optional_raw(), Some([0, 255, 7].as_slice()));
        assert_ne!(absent, empty);
        assert_ne!(empty, present);
    }

    #[test]
    fn exact_bytes_and_order_survive_clone_access_and_consumption() {
        let first_bytes = b"<pluginProperty name=\"a\">&amp;\x00\xff</pluginProperty>";
        let second_bytes = b"<!-- exact comment -->\n<![CDATA[raw <x> bytes]]>";
        let values = vec![
            OpaqueValue::new("plugin.Property", first_bytes.to_vec()),
            OpaqueValue::new("xml:comment", second_bytes.to_vec()),
        ];

        assert_eq!(values[0].raw_bytes(), first_bytes);
        assert_eq!(values[1].raw_bytes(), second_bytes);
        assert_eq!(
            values[0].as_text(),
            None,
            "invalid UTF-8 must not be replaced"
        );
        assert_eq!(
            values[1].as_text(),
            Some("<!-- exact comment -->\n<![CDATA[raw <x> bytes]]>")
        );

        let cloned = values.clone();
        assert_eq!(cloned, values, "clone must retain the source sequence");
        assert_eq!(cloned[0].type_name, "plugin.Property");
        assert_eq!(cloned[1].type_name, "xml:comment");
        assert_eq!(cloned[0].clone().into_raw(), first_bytes);
        assert_eq!(cloned[1].clone().into_raw(), second_bytes);
    }

    #[test]
    fn bounded_construction_rejects_without_truncating_or_defaulting() {
        let oversized = OpaqueValue::try_new_with_limit("plugin.Value", b"1234", 3);
        assert_eq!(
            oversized,
            Err(OpaqueValueError::PayloadTooLarge {
                limit: 3,
                actual: 4,
            })
        );
        assert_eq!(
            OpaqueValue::try_new_with_limit("plugin.Value", b"123", 3)
                .expect("exactly bounded payload should be accepted")
                .raw,
            b"123"
        );
        assert_eq!(
            OpaqueValue::try_from_slice("plugin.Value", b"123", 3)
                .expect("exactly bounded borrowed payload should be accepted")
                .raw,
            b"123"
        );
        assert_eq!(
            OpaqueValue::try_from_slice("plugin.Value", b"1234", 3),
            Err(OpaqueValueError::PayloadTooLarge {
                limit: 3,
                actual: 4,
            })
        );
        assert_eq!(
            OpaqueValue::try_text_with_limit("plugin.Value", "text", 4)
                .expect("exactly bounded text should be accepted")
                .as_text(),
            Some("text")
        );
        assert_eq!(
            OpaqueValue::try_text_with_limit("plugin.Value", "text", 3),
            Err(OpaqueValueError::PayloadTooLarge {
                limit: 3,
                actual: 4,
            })
        );
        assert_eq!(
            OpaqueValue::try_text_with_limit("plugin.Value", "☃", 2),
            Err(OpaqueValueError::PayloadTooLarge {
                limit: 2,
                actual: 3,
            })
        );
        assert_eq!(
            OpaqueValueError::PayloadTooLarge {
                limit: 3,
                actual: 4,
            }
            .code(),
            "model.opaque.limit-bytes"
        );
    }

    #[test]
    fn model_validation_enforces_aggregate_string_and_opaque_limits() {
        let value = OpaqueValue::new("plugin.Type", vec![1, 2, 3]);
        let mut limits = ValidationLimits::small();

        limits.max_opaque_bytes = 3;
        assert!(value.validate_with_limits(&limits).is_ok());
        limits.max_opaque_bytes = 2;
        assert_eq!(
            value.validate_with_limits(&limits).unwrap_err().code(),
            "model.validation.limit-opaque-bytes"
        );

        limits.max_opaque_bytes = 3;
        limits.max_string_bytes = "plugin.Type".len();
        assert!(value.validate_with_limits(&limits).is_ok());
        limits.max_string_bytes = "plugin.Type".len() - 1;
        assert_eq!(
            value.validate_with_limits(&limits).unwrap_err().code(),
            "model.validation.limit-string-bytes"
        );
    }

    #[test]
    fn optional_field_editing_keeps_exact_payload_and_presence_distinct() {
        let original = OpaqueValue::new("plugin.Type", vec![0, 255]);
        let without_type = original.clone().with_optional_type_name(None);
        let empty_type = original
            .clone()
            .with_optional_type_name(Some(String::new()));
        let without_raw = original.clone().with_optional_raw(None);
        let empty_raw = original.with_optional_raw(Some(Vec::new()));

        assert_eq!(without_type.optional_type_name(), None);
        assert_eq!(empty_type.optional_type_name(), Some(""));
        assert_eq!(without_type.raw_bytes(), &[0, 255]);
        assert_eq!(empty_type.raw_bytes(), &[0, 255]);
        assert_eq!(without_raw.optional_raw(), None);
        assert_eq!(empty_raw.optional_raw(), Some([].as_slice()));
        assert_ne!(without_type, empty_type);
        assert_ne!(without_raw, empty_raw);
    }
}
