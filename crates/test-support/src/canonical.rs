// SPDX-License-Identifier: Apache-2.0
//! Small explicit canonicalizers for deterministic fixture assertions.
//!
//! Canonicalization is opt-in and intentionally narrow.  The helpers never
//! sort an ordered event stream, remove fields, normalize timestamps, inspect
//! host state, or reinterpret protocol bytes.  Callers select each permitted
//! text transformation and can keep the original value beside the result.
//! Text canonicalization requires explicit input and output bounds; the full
//! oracle manifest and its normalization policy remain owned by the oracle
//! harness rather than this in-memory helper.

use crate::error::{ErrorCode, StableError};
use std::fmt;

/// Explicit text transformations for a fixture comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalTextOptions {
    /// Convert CRLF and lone CR line endings to LF.
    pub normalize_line_endings: bool,
    /// Remove trailing ASCII spaces/tabs from each line.
    pub trim_trailing_whitespace: bool,
    /// Append one LF when the canonical output is non-empty and has none.
    pub ensure_final_newline: bool,
}

impl CanonicalTextOptions {
    /// Makes no changes.
    #[must_use]
    pub const fn preserve() -> Self {
        Self {
            normalize_line_endings: false,
            trim_trailing_whitespace: false,
            ensure_final_newline: false,
        }
    }

    /// Enables only line-ending normalization.
    #[must_use]
    pub const fn line_endings() -> Self {
        Self {
            normalize_line_endings: true,
            ..Self::preserve()
        }
    }

    /// Enables all transformations explicitly provided by this helper.
    #[must_use]
    pub const fn normalized_lines() -> Self {
        Self {
            normalize_line_endings: true,
            trim_trailing_whitespace: true,
            ensure_final_newline: true,
        }
    }
}

impl Default for CanonicalTextOptions {
    fn default() -> Self {
        Self::preserve()
    }
}

/// Which side of bounded text canonicalization exceeded its limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalTextDirection {
    /// The source text was too large to inspect.
    Input,
    /// The transformed text would exceed the retained-output bound.
    Output,
}

/// Explicit input and output bounds for [`canonicalize_text`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalTextLimits {
    /// Maximum UTF-8 bytes accepted from the source text.
    pub max_input_bytes: usize,
    /// Maximum UTF-8 bytes retained in the transformed text.
    pub max_output_bytes: usize,
}

impl CanonicalTextLimits {
    /// Creates explicit finite text bounds.
    #[must_use]
    pub const fn new(max_input_bytes: usize, max_output_bytes: usize) -> Self {
        Self {
            max_input_bytes,
            max_output_bytes,
        }
    }

    /// A useful finite bound for fixture comparisons.
    #[must_use]
    pub const fn default_bounded() -> Self {
        Self::new(4 * 1024 * 1024, 4 * 1024 * 1024)
    }
}

impl Default for CanonicalTextLimits {
    fn default() -> Self {
        Self::default_bounded()
    }
}

/// Canonicalizes text under explicitly selected transformations and bounds.
pub fn canonicalize_text(
    input: &str,
    options: CanonicalTextOptions,
    limits: CanonicalTextLimits,
) -> Result<String, CanonicalError> {
    if input.len() > limits.max_input_bytes {
        return Err(CanonicalError::TextTooLarge {
            direction: CanonicalTextDirection::Input,
            actual: input.len(),
            limit: limits.max_input_bytes,
        });
    }

    let mut text = if options.normalize_line_endings {
        let mut output = String::with_capacity(input.len().min(limits.max_output_bytes));
        let mut characters = input.chars().peekable();
        while let Some(character) = characters.next() {
            if character == '\r' {
                if characters.peek() == Some(&'\n') {
                    let _ = characters.next();
                }
                push_text(&mut output, "\n", limits.max_output_bytes)?;
            } else {
                let mut encoded = [0_u8; 4];
                push_text(
                    &mut output,
                    character.encode_utf8(&mut encoded),
                    limits.max_output_bytes,
                )?;
            }
        }
        output
    } else {
        let mut output = String::with_capacity(input.len().min(limits.max_output_bytes));
        push_text(&mut output, input, limits.max_output_bytes)?;
        output
    };

    if options.trim_trailing_whitespace {
        let mut output = String::with_capacity(text.len().min(limits.max_output_bytes));
        for (index, line) in text.split('\n').enumerate() {
            if index != 0 {
                push_text(&mut output, "\n", limits.max_output_bytes)?;
            }
            push_text(
                &mut output,
                line.trim_end_matches([' ', '\t']),
                limits.max_output_bytes,
            )?;
        }
        text = output;
    }

    if options.ensure_final_newline && !text.is_empty() && !text.ends_with('\n') {
        push_text(&mut text, "\n", limits.max_output_bytes)?;
    }
    Ok(text)
}

fn push_text(output: &mut String, value: &str, limit: usize) -> Result<(), CanonicalError> {
    let actual = output
        .len()
        .checked_add(value.len())
        .ok_or(CanonicalError::InvalidSize)?;
    if actual > limit {
        return Err(CanonicalError::TextTooLarge {
            direction: CanonicalTextDirection::Output,
            actual,
            limit,
        });
    }
    output.push_str(value);
    Ok(())
}

/// One named field in an ordered canonical record.
///
/// The raw name and value remain available for explicit fixture comparison;
/// diagnostic formatting uses [`CanonicalField::redacted`] so values cannot
/// accidentally enter logs or assertion output.
#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalField {
    /// Field name.
    pub name: String,
    /// Field value.
    pub value: String,
}

/// A redacted diagnostic view of one canonical field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalFieldDiagnostic {
    /// Field name retained for assertion correlation.
    pub name: String,
    /// Number of UTF-8 bytes in the raw field value.
    pub value_bytes: usize,
}

impl CanonicalField {
    /// Creates one field without sorting or normalization.
    #[must_use]
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    /// Returns an explicit redacted diagnostic projection.
    #[must_use]
    pub fn redacted(&self) -> CanonicalFieldDiagnostic {
        CanonicalFieldDiagnostic {
            name: self.name.clone(),
            value_bytes: self.value.len(),
        }
    }
}

impl fmt::Debug for CanonicalField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.redacted().fmt(formatter)
    }
}

/// Finite bounds for canonical records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalLimits {
    /// Maximum number of fields in a record.
    pub max_fields: usize,
    /// Maximum UTF-8 bytes in one field name plus value.
    pub max_field_bytes: usize,
    /// Maximum UTF-8 bytes across all fields.
    pub max_total_bytes: usize,
}

impl CanonicalLimits {
    /// Creates explicit finite record bounds.
    #[must_use]
    pub const fn new(max_fields: usize, max_field_bytes: usize, max_total_bytes: usize) -> Self {
        Self {
            max_fields,
            max_field_bytes,
            max_total_bytes,
        }
    }

    /// A useful finite bound for fixture comparisons.
    #[must_use]
    pub const fn default_bounded() -> Self {
        Self::new(4_096, 16 * 1024, 4 * 1024 * 1024)
    }
}

impl Default for CanonicalLimits {
    fn default() -> Self {
        Self::default_bounded()
    }
}

/// Errors returned by bounded canonical record and stream helpers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CanonicalError {
    /// Canonicalization input or output exceeded its explicit text bound.
    TextTooLarge {
        /// Which side of canonicalization exceeded its bound.
        direction: CanonicalTextDirection,
        /// Actual UTF-8 bytes.
        actual: usize,
        /// Configured byte bound.
        limit: usize,
    },
    /// A field exceeded the per-field byte bound.
    FieldTooLarge {
        /// Actual field bytes.
        actual: usize,
        /// Configured field limit.
        limit: usize,
    },
    /// A record exceeded its field-count or aggregate-byte bound.
    CapacityExceeded {
        /// Actual field count.
        field_count: usize,
        /// Actual aggregate bytes.
        total_bytes: usize,
        /// Configured field-count limit.
        field_limit: usize,
        /// Configured aggregate-byte limit.
        total_limit: usize,
    },
    /// A stream exceeded its event-count bound.
    EventCapacityExceeded {
        /// Actual event count.
        event_count: usize,
        /// Configured event-count limit.
        limit: usize,
    },
    /// One event exceeded the configured byte bound.
    EventTooLarge {
        /// Actual event bytes.
        actual: usize,
        /// Configured per-event limit.
        limit: usize,
    },
    /// Aggregate event bytes exceeded the configured stream bound.
    EventBytesCapacityExceeded {
        /// Actual event count after the attempted insertion.
        event_count: usize,
        /// Actual aggregate event bytes.
        total_bytes: usize,
        /// Configured aggregate-byte limit.
        limit: usize,
    },
    /// A size calculation overflowed before a bound check.
    InvalidSize,
}

impl CanonicalError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::TextTooLarge { .. } => ErrorCode::CanonicalTextTooLarge,
            Self::FieldTooLarge { .. } => ErrorCode::CanonicalFieldTooLarge,
            Self::CapacityExceeded { .. } | Self::InvalidSize => ErrorCode::CanonicalCapacity,
            Self::EventCapacityExceeded { .. } => ErrorCode::CanonicalEventCapacity,
            Self::EventTooLarge { .. } => ErrorCode::CanonicalEventTooLarge,
            Self::EventBytesCapacityExceeded { .. } => ErrorCode::CanonicalEventBytesCapacity,
        }
    }
}

impl fmt::Display for CanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TextTooLarge {
                direction,
                actual,
                limit,
            } => write!(
                formatter,
                "{}: {direction:?} text bytes {actual} exceed {limit}",
                self.code()
            ),
            Self::FieldTooLarge { actual, limit } => {
                write!(
                    formatter,
                    "{}: field bytes {actual} exceed {limit}",
                    self.code()
                )
            }
            Self::CapacityExceeded {
                field_count,
                total_bytes,
                field_limit,
                total_limit,
            } => write!(
                formatter,
                "{}: fields {field_count}/{field_limit}, bytes {total_bytes}/{total_limit}",
                self.code()
            ),
            Self::EventCapacityExceeded { event_count, limit } => write!(
                formatter,
                "{}: events {event_count} exceed {limit}",
                self.code()
            ),
            Self::EventTooLarge { actual, limit } => write!(
                formatter,
                "{}: event bytes {actual} exceed {limit}",
                self.code()
            ),
            Self::EventBytesCapacityExceeded {
                event_count,
                total_bytes,
                limit,
            } => write!(
                formatter,
                "{}: event count {event_count}, bytes {total_bytes} exceed {limit}",
                self.code()
            ),
            Self::InvalidSize => write!(formatter, "{}: canonical size overflow", self.code()),
        }
    }
}

impl std::error::Error for CanonicalError {}

impl StableError for CanonicalError {
    fn code(&self) -> ErrorCode {
        self.code()
    }
}

/// A redacted diagnostic view of an ordered canonical record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalRecordDiagnostic {
    /// Redacted fields in their original insertion order.
    pub fields: Vec<CanonicalFieldDiagnostic>,
    /// Aggregate raw field bytes.
    pub total_bytes: usize,
    /// A pending builder error, if one was retained.
    pub pending_error: Option<CanonicalError>,
}

impl fmt::Display for CanonicalRecordDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, field) in self.fields.iter().enumerate() {
            if index != 0 {
                formatter.write_str("\n")?;
            }
            write!(formatter, "{}=<{} bytes>", field.name, field.value_bytes)?;
        }
        if self.fields.is_empty() {
            formatter.write_str("<empty>")?;
        }
        Ok(())
    }
}

/// An ordered collection of named fields.
#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalRecord {
    limits: CanonicalLimits,
    fields: Vec<CanonicalField>,
    total_bytes: usize,
    pending_error: Option<CanonicalError>,
}

impl CanonicalRecord {
    /// Creates an empty record.
    #[must_use]
    pub const fn new() -> Self {
        Self::with_limits(CanonicalLimits::default_bounded())
    }

    /// Creates an empty record with explicit finite bounds.
    #[must_use]
    pub const fn with_limits(limits: CanonicalLimits) -> Self {
        Self {
            limits,
            fields: Vec::new(),
            total_bytes: 0,
            pending_error: None,
        }
    }

    /// Returns the configured record bounds.
    #[must_use]
    pub const fn limits(&self) -> CanonicalLimits {
        self.limits
    }

    /// Returns the retained field count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Returns whether no fields were retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Returns aggregate field bytes.
    #[must_use]
    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Returns a pending push error, if the builder-style API encountered one.
    #[must_use]
    pub fn error(&self) -> Option<&CanonicalError> {
        self.pending_error.as_ref()
    }

    /// Returns this record if all builder-style pushes succeeded.
    pub fn finish(self) -> Result<Self, CanonicalError> {
        match self.pending_error {
            Some(error) => Err(error),
            None => Ok(self),
        }
    }

    /// Appends a field while preserving insertion order and duplicates.
    #[must_use]
    pub fn push(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        if self.pending_error.is_none()
            && let Err(error) = self.try_push(name, value)
        {
            self.pending_error = Some(error);
        }
        self
    }

    /// Appends a pre-built field while preserving insertion order.
    #[must_use]
    pub fn push_field(mut self, field: CanonicalField) -> Self {
        if self.pending_error.is_none()
            && let Err(error) = self.try_push_field(field)
        {
            self.pending_error = Some(error);
        }
        self
    }

    /// Appends one field and returns a typed bound error immediately.
    pub fn try_push(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), CanonicalError> {
        self.try_push_field(CanonicalField::new(name, value))
    }

    /// Appends one pre-built field and returns a typed bound error immediately.
    pub fn try_push_field(&mut self, field: CanonicalField) -> Result<(), CanonicalError> {
        let field_bytes = field
            .name
            .len()
            .checked_add(field.value.len())
            .ok_or(CanonicalError::InvalidSize)?;
        if field_bytes > self.limits.max_field_bytes {
            return Err(CanonicalError::FieldTooLarge {
                actual: field_bytes,
                limit: self.limits.max_field_bytes,
            });
        }
        let field_count = self
            .fields
            .len()
            .checked_add(1)
            .ok_or(CanonicalError::InvalidSize)?;
        let total_bytes = self
            .total_bytes
            .checked_add(field_bytes)
            .ok_or(CanonicalError::InvalidSize)?;
        if field_count > self.limits.max_fields || total_bytes > self.limits.max_total_bytes {
            return Err(CanonicalError::CapacityExceeded {
                field_count,
                total_bytes,
                field_limit: self.limits.max_fields,
                total_limit: self.limits.max_total_bytes,
            });
        }
        self.fields.push(field);
        self.total_bytes = total_bytes;
        Ok(())
    }

    /// Returns fields in their current order.
    #[must_use]
    pub fn fields(&self) -> &[CanonicalField] {
        &self.fields
    }

    /// Returns an explicit redacted diagnostic projection.
    #[must_use]
    pub fn redacted(&self) -> CanonicalRecordDiagnostic {
        CanonicalRecordDiagnostic {
            fields: self.fields.iter().map(CanonicalField::redacted).collect(),
            total_bytes: self.total_bytes,
            pending_error: self.pending_error.clone(),
        }
    }

    /// Returns a copy sorted by field name, preserving duplicate relative
    /// order.  Callers should use this only where the source format defines
    /// map semantics.
    #[must_use]
    pub fn sorted_by_name(&self) -> Self {
        let mut fields = self.fields.clone();
        fields.sort_by(|left, right| left.name.cmp(&right.name));
        Self {
            limits: self.limits,
            fields,
            total_bytes: self.total_bytes,
            pending_error: self.pending_error.clone(),
        }
    }

    /// Returns a deterministic line representation without escaping or field
    /// removal.  The delimiter is supplied by the caller as part of the
    /// fixture's format contract.
    #[must_use]
    pub fn to_delimited(&self, delimiter: char) -> String {
        self.fields
            .iter()
            .map(|field| {
                format!(
                    "{}{}{}",
                    escape_component(&field.name, delimiter),
                    delimiter,
                    escape_component(&field.value, delimiter)
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl Default for CanonicalRecord {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for CanonicalRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.redacted().fmt(formatter)
    }
}

impl fmt::Display for CanonicalRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.redacted().fmt(formatter)
    }
}

/// Finite count and byte bounds for a canonical event stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalStreamLimits {
    /// Maximum events retained in the stream.
    pub max_events: usize,
    /// Maximum bytes in one event.
    pub max_event_bytes: usize,
    /// Maximum bytes retained by the stream.
    pub max_total_bytes: usize,
}

impl CanonicalStreamLimits {
    /// Creates an explicit finite event bound.
    #[must_use]
    pub const fn new(max_events: usize) -> Self {
        Self {
            max_events,
            max_event_bytes: 16 * 1024,
            max_total_bytes: 4 * 1024 * 1024,
        }
    }

    /// Creates explicit event-count and byte bounds.
    #[must_use]
    pub const fn with_byte_limits(
        max_events: usize,
        max_event_bytes: usize,
        max_total_bytes: usize,
    ) -> Self {
        Self {
            max_events,
            max_event_bytes,
            max_total_bytes,
        }
    }

    /// Sets the maximum bytes in one event.
    #[must_use]
    pub const fn with_event_bytes_limit(mut self, limit: usize) -> Self {
        self.max_event_bytes = limit;
        self
    }

    /// Sets the maximum aggregate bytes in the stream.
    #[must_use]
    pub const fn with_total_bytes_limit(mut self, limit: usize) -> Self {
        self.max_total_bytes = limit;
        self
    }

    /// A useful finite bound for deterministic traces.
    #[must_use]
    pub const fn default_bounded() -> Self {
        Self::new(16_384)
    }
}

impl Default for CanonicalStreamLimits {
    fn default() -> Self {
        Self::default_bounded()
    }
}

/// Canonicalizes one ordered event stream without sorting it.
///
/// Every pushed event uses [`CanonicalEventSize`] or an explicit size passed
/// to [`Self::try_push_with_size`], so aggregate retention is bounded without
/// inspecting ambient or serialized state.
#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalEventStream<T> {
    limits: CanonicalStreamLimits,
    events: Vec<T>,
    total_bytes: usize,
    pending_error: Option<CanonicalError>,
}

/// Supplies the deterministic byte size of a canonical event.
///
/// Generic event types that cannot implement this trait can use
/// [`CanonicalEventStream::try_push_with_size`] with an explicit size.
pub trait CanonicalEventSize {
    /// Returns the event's bounded representation size in bytes.
    fn canonical_event_bytes(&self) -> usize;
}

impl CanonicalEventSize for str {
    fn canonical_event_bytes(&self) -> usize {
        self.len()
    }
}

impl CanonicalEventSize for String {
    fn canonical_event_bytes(&self) -> usize {
        self.len()
    }
}

impl CanonicalEventSize for [u8] {
    fn canonical_event_bytes(&self) -> usize {
        self.len()
    }
}

impl CanonicalEventSize for Vec<u8> {
    fn canonical_event_bytes(&self) -> usize {
        self.len()
    }
}

impl<T> CanonicalEventSize for &T
where
    T: CanonicalEventSize + ?Sized,
{
    fn canonical_event_bytes(&self) -> usize {
        (*self).canonical_event_bytes()
    }
}

impl CanonicalEventSize for bool {
    fn canonical_event_bytes(&self) -> usize {
        1
    }
}

macro_rules! impl_fixed_event_size {
    ($($type:ty),+ $(,)?) => {
        $(
            impl CanonicalEventSize for $type {
                fn canonical_event_bytes(&self) -> usize {
                    std::mem::size_of::<$type>()
                }
            }
        )+
    };
}

impl_fixed_event_size!(
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize, f32, f64
);

impl<T> CanonicalEventStream<T> {
    /// Creates an empty stream.
    #[must_use]
    pub const fn new() -> Self {
        Self::with_limits(CanonicalStreamLimits::default_bounded())
    }

    /// Creates an empty stream with explicit finite bounds.
    #[must_use]
    pub const fn with_limits(limits: CanonicalStreamLimits) -> Self {
        Self {
            limits,
            events: Vec::new(),
            total_bytes: 0,
            pending_error: None,
        }
    }

    /// Returns configured stream bounds.
    #[must_use]
    pub const fn limits(&self) -> CanonicalStreamLimits {
        self.limits
    }

    /// Returns retained event count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Returns whether no events were retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Returns aggregate bytes retained by the stream.
    #[must_use]
    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Returns a pending push error, if one occurred.
    #[must_use]
    pub fn error(&self) -> Option<&CanonicalError> {
        self.pending_error.as_ref()
    }

    /// Returns this stream if all builder-style pushes succeeded.
    pub fn finish(self) -> Result<Self, CanonicalError> {
        match self.pending_error {
            Some(error) => Err(error),
            None => Ok(self),
        }
    }

    /// Appends one event, preserving order.
    #[must_use]
    pub fn push(mut self, event: T) -> Self
    where
        T: CanonicalEventSize,
    {
        if self.pending_error.is_none()
            && let Err(error) = self.try_push(event)
        {
            self.pending_error = Some(error);
        }
        self
    }

    /// Appends one event and returns a typed bound error immediately.
    pub fn try_push(&mut self, event: T) -> Result<(), CanonicalError>
    where
        T: CanonicalEventSize,
    {
        let event_bytes = event.canonical_event_bytes();
        self.try_push_with_size(event, event_bytes)
    }

    /// Appends an event with an explicit deterministic representation size.
    pub fn try_push_with_size(
        &mut self,
        event: T,
        event_bytes: usize,
    ) -> Result<(), CanonicalError> {
        let event_count = self
            .events
            .len()
            .checked_add(1)
            .ok_or(CanonicalError::InvalidSize)?;
        if event_count > self.limits.max_events {
            return Err(CanonicalError::EventCapacityExceeded {
                event_count,
                limit: self.limits.max_events,
            });
        }
        if event_bytes > self.limits.max_event_bytes {
            return Err(CanonicalError::EventTooLarge {
                actual: event_bytes,
                limit: self.limits.max_event_bytes,
            });
        }
        let total_bytes = self
            .total_bytes
            .checked_add(event_bytes)
            .ok_or(CanonicalError::InvalidSize)?;
        if total_bytes > self.limits.max_total_bytes {
            return Err(CanonicalError::EventBytesCapacityExceeded {
                event_count,
                total_bytes,
                limit: self.limits.max_total_bytes,
            });
        }
        self.events.push(event);
        self.total_bytes = total_bytes;
        Ok(())
    }

    /// Appends an event with an explicit size while preserving builder style.
    #[must_use]
    pub fn push_with_size(mut self, event: T, event_bytes: usize) -> Self {
        if self.pending_error.is_none()
            && let Err(error) = self.try_push_with_size(event, event_bytes)
        {
            self.pending_error = Some(error);
        }
        self
    }

    /// Returns events in their original order.
    #[must_use]
    pub fn events(&self) -> &[T] {
        &self.events
    }

    /// Consumes the wrapper and returns its ordered events.
    #[must_use]
    pub fn into_events(self) -> Vec<T> {
        self.events
    }
}

impl<T> Default for CanonicalEventStream<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> fmt::Debug for CanonicalEventStream<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalEventStream")
            .field("event_count", &self.events.len())
            .field("total_bytes", &self.total_bytes)
            .field("pending_error", &self.pending_error)
            .finish()
    }
}

fn escape_component(value: &str, delimiter: char) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            character if character == delimiter => {
                escaped.push('\\');
                escaped.push(character);
            }
            character => escaped.push(character),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn text_normalization_is_explicit() {
        let input = "a  \r\nb\r\nc";
        let limits = CanonicalTextLimits::new(input.len(), input.len() + 1);
        assert_eq!(
            canonicalize_text(input, CanonicalTextOptions::preserve(), limits).unwrap(),
            input
        );
        assert_eq!(
            canonicalize_text(input, CanonicalTextOptions::normalized_lines(), limits).unwrap(),
            "a\nb\nc\n"
        );
    }

    #[test]
    fn text_bounds_reject_input_and_output_without_partial_result() {
        let input_error = canonicalize_text(
            "1234",
            CanonicalTextOptions::preserve(),
            CanonicalTextLimits::new(3, 8),
        )
        .unwrap_err();
        assert_eq!(input_error.code(), ErrorCode::CanonicalTextTooLarge);
        assert!(matches!(
            input_error,
            CanonicalError::TextTooLarge {
                direction: CanonicalTextDirection::Input,
                actual: 4,
                limit: 3,
            }
        ));

        let output_error = canonicalize_text(
            "abc",
            CanonicalTextOptions {
                ensure_final_newline: true,
                ..CanonicalTextOptions::preserve()
            },
            CanonicalTextLimits::new(3, 3),
        )
        .unwrap_err();
        assert_eq!(output_error.code(), ErrorCode::CanonicalTextTooLarge);
        assert!(matches!(
            output_error,
            CanonicalError::TextTooLarge {
                direction: CanonicalTextDirection::Output,
                actual: 4,
                limit: 3,
            }
        ));
    }

    #[test]
    fn record_sorting_is_opt_in_and_duplicates_remain() {
        let record = CanonicalRecord::new()
            .push("b", "first")
            .push("a", "value")
            .push("b", "second");
        assert_eq!(record.fields()[0].name, "b");
        let sorted = record.sorted_by_name();
        assert_eq!(sorted.fields()[0], CanonicalField::new("a", "value"));
        assert_eq!(sorted.fields()[1].value, "first");
        assert_eq!(sorted.fields()[2].value, "second");
    }

    #[test]
    fn record_diagnostics_redact_sensitive_values() {
        let url = "https://user:password@example.test/path?token=url-secret";
        let cookie = "session=cookie-secret";
        let authorization = "Bearer auth-secret";
        let secret = "secret-value";
        let record = CanonicalRecord::new()
            .push("url", url)
            .push("cookie", cookie)
            .push("authorization", authorization)
            .push("secret", secret);

        let debug = format!("{record:?}");
        let display = format!("{record}");
        let field_debug = format!("{:?}", record.fields()[0]);
        for sensitive in [url, cookie, authorization, secret] {
            assert!(!debug.contains(sensitive), "debug leaked {sensitive}");
            assert!(!display.contains(sensitive), "display leaked {sensitive}");
            assert!(
                !field_debug.contains(sensitive),
                "field debug leaked {sensitive}"
            );
        }
        assert_eq!(record.fields()[0].value, url);
        assert_eq!(record.redacted().fields[0].value_bytes, url.len());
        assert!(record.to_delimited('~').contains(url));
    }

    #[test]
    fn event_stream_never_reorders() {
        let stream = CanonicalEventStream::new().push(3).push(1).push(2);
        assert_eq!(stream.events(), &[3, 1, 2]);
    }

    #[test]
    fn record_bounds_reject_without_partial_insertion() {
        let mut record = CanonicalRecord::with_limits(CanonicalLimits::new(1, 4, 4));
        record.try_push("a", "12").unwrap();
        assert_eq!(record.total_bytes(), 3);
        assert_eq!(
            record.try_push("b", "3").unwrap_err().code(),
            ErrorCode::CanonicalCapacity
        );
        assert_eq!(record.len(), 1);

        let error = CanonicalRecord::with_limits(CanonicalLimits::new(4, 3, 8))
            .push("name", "value")
            .finish()
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::CanonicalFieldTooLarge);
    }

    #[test]
    fn event_stream_bound_preserves_order_and_reports_capacity() {
        let mut stream = CanonicalEventStream::with_limits(CanonicalStreamLimits::new(1));
        stream.try_push("first").unwrap();
        assert_eq!(
            stream.try_push("second").unwrap_err().code(),
            ErrorCode::CanonicalEventCapacity
        );
        assert_eq!(stream.events(), &["first"]);
    }

    #[test]
    fn event_stream_byte_bounds_are_explicit_and_non_partial() {
        let limits = CanonicalStreamLimits::with_byte_limits(4, 3, 5);
        let mut stream = CanonicalEventStream::with_limits(limits);
        stream.try_push("abc").unwrap();
        assert_eq!(stream.total_bytes(), 3);
        assert_eq!(stream.try_push("de").unwrap(), ());
        assert_eq!(stream.total_bytes(), 5);
        assert_eq!(
            stream.try_push("f").unwrap_err().code(),
            ErrorCode::CanonicalEventBytesCapacity
        );
        assert_eq!(stream.len(), 2);

        let error = CanonicalEventStream::with_limits(
            CanonicalStreamLimits::new(2).with_event_bytes_limit(2),
        )
        .push("too-long")
        .finish()
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::CanonicalEventTooLarge);

        let mut explicit =
            CanonicalEventStream::with_limits(CanonicalStreamLimits::with_byte_limits(2, 4, 4));
        explicit.try_push_with_size(vec![1_u8, 2], 4).unwrap();
        assert_eq!(explicit.total_bytes(), 4);
    }

    #[test]
    fn delimited_records_escape_delimiter_and_escape_markers() {
        let record = CanonicalRecord::new().push("a=b", "line\nback\\slash\r");
        assert_eq!(record.to_delimited('='), "a\\=b=line\\nback\\\\slash\\r");
    }
}
