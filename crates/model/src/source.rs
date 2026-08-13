// SPDX-License-Identifier: Apache-2.0
//! Source locations retained for diagnostics and semantic nodes.
//!
//! A location is deliberately a small, owned value.  It retains a canonical
//! source label and coordinates, but never retains the document bytes.  The
//! JMX syntax layer owns the input buffer and is responsible for proving the
//! byte span against that buffer before constructing a location.  This keeps
//! the model independent of a parser, filesystem, process, or network while
//! still making source diagnostics precise for UTF-8 input.

use core::fmt;

/// Maximum number of UTF-8 bytes retained for a source/document label.
///
/// This is a diagnostic bound, not a bound on a JMX document.  A parser may
/// retain a much larger input document, but a location never needs to copy
/// more than this amount of identifying path/label data.
pub const MAX_SOURCE_NAME_BYTES: usize = 16 * 1024;

/// Maximum number of non-empty path components retained in a source label.
pub const MAX_SOURCE_PATH_COMPONENTS: usize = 128;

/// Maximum source byte offset represented by this pure model.
///
/// The syntax layer has its own input-size limit.  This additional finite
/// bound prevents a directly constructed model value from carrying an
/// obviously nonsensical unbounded offset when no source buffer is available
/// to validate it.
pub const MAX_SOURCE_BYTE_OFFSET: u64 = 64 * 1024 * 1024;

const REDACTED_SOURCE: &str = "<redacted>";
const UNKNOWN_SOURCE: &str = "<unknown>";
const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Errors raised when a source location violates its coordinate or source
/// label contract.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SourceLocationError {
    /// A present line number was zero.
    InvalidLine {
        /// Invalid zero value for a one-based line coordinate.
        value: u32,
    },
    /// A present column number was zero.
    InvalidColumn {
        /// Invalid zero value for a one-based column coordinate.
        value: u32,
    },
    /// A source label was empty.  An absent label is represented by `None`.
    EmptySource,
    /// A source label or source byte buffer exceeded its finite bound.
    SourceTooLong {
        /// Number of bytes observed before rejecting the value.
        bytes: usize,
        /// Maximum permitted number of bytes.
        limit: usize,
    },
    /// A source path contained more non-empty components than permitted.
    SourceTooManyComponents {
        /// Number of components observed before rejecting the value.
        components: usize,
        /// Maximum permitted number of components.
        limit: usize,
    },
    /// A source label contained a NUL byte.
    SourceContainsNul {
        /// Byte position of the NUL character.
        position: usize,
    },
    /// A source label contained a control character.
    SourceContainsControl {
        /// Byte position of the control character.
        position: usize,
    },
    /// The source byte buffer was not valid UTF-8.
    InvalidUtf8 {
        /// Byte position of the first invalid sequence.
        position: usize,
    },
    /// A byte offset exceeded the model's direct-construction bound.
    ByteOffsetTooLarge {
        /// Rejected zero-based byte offset.
        offset: u64,
        /// Maximum permitted offset.
        limit: u64,
    },
    /// A byte offset was outside the supplied source buffer.
    ByteOffsetOutOfBounds {
        /// Rejected zero-based byte offset.
        offset: u64,
        /// Source length in bytes.
        source_len: u64,
    },
    /// A byte offset pointed into the middle of a UTF-8 scalar value.
    ByteOffsetNotCharBoundary {
        /// Rejected zero-based byte offset.
        offset: u64,
    },
}

impl SourceLocationError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidLine { .. } => "model.source.invalid-line",
            Self::InvalidColumn { .. } => "model.source.invalid-column",
            Self::EmptySource => "model.source.empty",
            Self::SourceTooLong { .. } => "model.source.too-long",
            Self::SourceTooManyComponents { .. } => "model.source.too-many-components",
            Self::SourceContainsNul { .. } => "model.source.contains-nul",
            Self::SourceContainsControl { .. } => "model.source.contains-control",
            Self::InvalidUtf8 { .. } => "model.source.invalid-utf8",
            Self::ByteOffsetTooLarge { .. } => "model.source.byte-offset-too-large",
            Self::ByteOffsetOutOfBounds { .. } => "model.source.byte-offset-out-of-bounds",
            Self::ByteOffsetNotCharBoundary { .. } => "model.source.byte-offset-not-char-boundary",
        }
    }
}

impl fmt::Display for SourceLocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLine { value } => {
                write!(formatter, "source line must be one-based, got {value}")
            }
            Self::InvalidColumn { value } => {
                write!(formatter, "source column must be one-based, got {value}")
            }
            Self::EmptySource => formatter.write_str("source label must not be empty"),
            Self::SourceTooLong { bytes, limit } => write!(
                formatter,
                "source input is {bytes} bytes, exceeding the bound {limit}"
            ),
            Self::SourceTooManyComponents { components, limit } => write!(
                formatter,
                "source path has {components} components, exceeding the bound {limit}"
            ),
            Self::SourceContainsNul { position } => {
                write!(formatter, "source label contains NUL at byte {position}")
            }
            Self::SourceContainsControl { position } => write!(
                formatter,
                "source label contains a control character at byte {position}"
            ),
            Self::InvalidUtf8 { position } => {
                write!(formatter, "source is not valid UTF-8 at byte {position}")
            }
            Self::ByteOffsetTooLarge { offset, limit } => write!(
                formatter,
                "source byte offset {offset} exceeds the bound {limit}"
            ),
            Self::ByteOffsetOutOfBounds { offset, source_len } => write!(
                formatter,
                "source byte offset {offset} is outside the {source_len}-byte source"
            ),
            Self::ByteOffsetNotCharBoundary { offset } => write!(
                formatter,
                "source byte offset {offset} is not a UTF-8 character boundary"
            ),
        }
    }
}

impl std::error::Error for SourceLocationError {}

/// A best-effort location in an input document.
///
/// Line and column numbers are one-based.  Columns count Unicode scalar
/// values, matching the JMX syntax layer; they are not UTF-8 byte counts.
/// Byte offsets are zero-based offsets into the original UTF-8 byte stream.
/// Any component may be absent when an upstream parser does not provide it;
/// an unknown location is represented by [`SourceLocation::unknown`].
#[derive(Clone, Default, Eq, Hash, PartialEq)]
pub struct SourceLocation {
    /// Optional canonical source/document label supplied by the caller.
    source: Option<String>,
    /// Zero-based byte offset in the original UTF-8 source, when known.
    byte_offset: Option<u64>,
    /// One-based line number, when known.
    line: Option<u32>,
    /// One-based Unicode-scalar column number, when known.
    column: Option<u32>,
}

impl fmt::Debug for SourceLocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceLocation")
            .field("source_present", &self.source.is_some())
            .field("source", &self.source.as_ref().map(|_| REDACTED_SOURCE))
            .field("source_len", &self.source.as_ref().map(String::len))
            .field("byte_offset_present", &self.byte_offset.is_some())
            .field("line_present", &self.line.is_some())
            .field("column_present", &self.column.is_some())
            .finish()
    }
}

impl fmt::Display for SourceLocation {
    /// Formats only redacted diagnostic context.  The source label itself is
    /// intentionally never emitted; use [`Self::source_name`] only in a
    /// trusted, non-diagnostic path that explicitly needs the canonical label.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.source.is_some() {
            formatter.write_str(REDACTED_SOURCE)?;
        } else {
            formatter.write_str(UNKNOWN_SOURCE)?;
        }
        if let (Some(line), Some(column)) = (self.line, self.column) {
            write!(formatter, ":{line}:{column}")?;
        } else if let Some(line) = self.line {
            write!(formatter, ":{line}")?;
        }
        if let Some(offset) = self.byte_offset {
            write!(formatter, " (byte {offset})")?;
        }
        Ok(())
    }
}

impl SourceLocation {
    /// Maximum number of bytes retained by [`Self::with_source`].
    pub const MAX_SOURCE_NAME_BYTES: usize = MAX_SOURCE_NAME_BYTES;

    /// Maximum number of path components retained by [`Self::with_source`].
    pub const MAX_SOURCE_PATH_COMPONENTS: usize = MAX_SOURCE_PATH_COMPONENTS;

    /// Maximum byte offset accepted by direct model construction.
    pub const MAX_SOURCE_BYTE_OFFSET: u64 = MAX_SOURCE_BYTE_OFFSET;

    /// Creates an unknown source location.
    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            source: None,
            byte_offset: None,
            line: None,
            column: None,
        }
    }

    /// Creates a validated line-and-column location without a source label.
    ///
    /// Both coordinates are one-based.  Invalid zero values are rejected
    /// before a [`SourceLocation`] can be constructed.
    pub const fn new(line: u32, column: u32) -> Result<Self, SourceLocationError> {
        if line == 0 {
            return Err(SourceLocationError::InvalidLine { value: line });
        }
        if column == 0 {
            return Err(SourceLocationError::InvalidColumn { value: column });
        }
        Ok(Self::from_valid_line_column(line, column))
    }

    /// Explicit checked-construction alias for [`Self::new`].
    pub const fn try_new(line: u32, column: u32) -> Result<Self, SourceLocationError> {
        Self::new(line, column)
    }

    /// Alias for [`SourceLocation::new`].
    pub const fn at(line: u32, column: u32) -> Result<Self, SourceLocationError> {
        Self::new(line, column)
    }

    /// Creates a location containing only an unchecked zero-based byte offset.
    ///
    /// This constructor is retained for parser integrations that already have
    /// a bounded span.  Call [`Self::try_from_byte_offset`] when the caller
    /// wants this model to enforce the direct-construction offset bound, or
    /// [`Self::from_source_offset`] when a UTF-8 source buffer is available.
    #[must_use]
    pub const fn from_byte_offset(byte_offset: u64) -> Self {
        Self {
            source: None,
            byte_offset: Some(byte_offset),
            line: None,
            column: None,
        }
    }

    /// Creates a location from a bounded offset without a source buffer.
    pub const fn try_from_byte_offset(byte_offset: u64) -> Result<Self, SourceLocationError> {
        if byte_offset > MAX_SOURCE_BYTE_OFFSET {
            return Err(SourceLocationError::ByteOffsetTooLarge {
                offset: byte_offset,
                limit: MAX_SOURCE_BYTE_OFFSET,
            });
        }
        Ok(Self::from_byte_offset(byte_offset))
    }

    /// Alias for [`Self::try_from_byte_offset`].
    pub const fn at_byte_offset(byte_offset: u64) -> Result<Self, SourceLocationError> {
        Self::try_from_byte_offset(byte_offset)
    }

    /// Adds a source/document label using the compatibility builder API.
    ///
    /// Labels are canonicalized lexically, bounded, and checked for control
    /// characters.  This historical infallible builder cannot report a
    /// rejected label, so it fails closed by omitting only the unsafe label;
    /// coordinates already present on the location remain intact.  New code
    /// should use [`Self::try_with_source`] to receive the typed reason.
    #[must_use]
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        let source = source.into();
        if let Ok(canonical) = canonical_source_label(&source) {
            self.source = Some(canonical);
        } else {
            self.source = None;
        }
        self
    }

    /// Adds a canonical, bounded source/document label.
    pub fn try_with_source(mut self, source: impl AsRef<str>) -> Result<Self, SourceLocationError> {
        self.source = Some(canonical_source_label(source.as_ref())?);
        Ok(self)
    }

    /// Alias for [`Self::try_with_source`].
    pub fn try_with_source_name(
        self,
        source: impl AsRef<str>,
    ) -> Result<Self, SourceLocationError> {
        self.try_with_source(source)
    }

    /// Adds or replaces a zero-based byte offset without a source-buffer
    /// proof.  Use [`Self::with_byte_offset_in`] for UTF-8 validation.
    #[must_use]
    pub const fn with_byte_offset(mut self, byte_offset: u64) -> Self {
        self.byte_offset = Some(byte_offset);
        self
    }

    /// Adds or replaces a bounded zero-based byte offset.
    pub fn try_with_byte_offset(self, byte_offset: u64) -> Result<Self, SourceLocationError> {
        if byte_offset > MAX_SOURCE_BYTE_OFFSET {
            return Err(SourceLocationError::ByteOffsetTooLarge {
                offset: byte_offset,
                limit: MAX_SOURCE_BYTE_OFFSET,
            });
        }
        Ok(self.with_byte_offset(byte_offset))
    }

    /// Adds a byte offset after validating the complete source as UTF-8 and
    /// proving the offset is a scalar-value boundary.  Line and column are
    /// derived using one-based Unicode-scalar coordinates and CR/LF handling
    /// identical to the JMX syntax layer.
    pub fn with_byte_offset_in(
        mut self,
        source: &[u8],
        byte_offset: usize,
    ) -> Result<Self, SourceLocationError> {
        let (line, column, offset, _source_len) = checked_source_position(source, byte_offset)?;
        self.byte_offset = Some(offset);
        self.line = Some(line);
        self.column = Some(column);
        Ok(self)
    }

    /// Alias for [`Self::with_byte_offset_in`].
    pub fn with_offset_in(
        self,
        source: &[u8],
        byte_offset: usize,
    ) -> Result<Self, SourceLocationError> {
        self.with_byte_offset_in(source, byte_offset)
    }

    /// Creates a location from a UTF-8 source buffer and a zero-based byte
    /// offset.
    pub fn from_source_offset(
        source: &[u8],
        byte_offset: usize,
    ) -> Result<Self, SourceLocationError> {
        Self::unknown().with_byte_offset_in(source, byte_offset)
    }

    /// Alias for [`Self::from_source_offset`].
    pub fn from_source_bytes(
        source: &[u8],
        byte_offset: usize,
    ) -> Result<Self, SourceLocationError> {
        Self::from_source_offset(source, byte_offset)
    }

    /// Creates a location from a UTF-8 string and a zero-based byte offset.
    pub fn from_source_text(source: &str, byte_offset: usize) -> Result<Self, SourceLocationError> {
        Self::from_source_offset(source.as_bytes(), byte_offset)
    }

    /// Adds a canonical source label and proves a byte offset against the
    /// supplied source bytes in one operation.
    pub fn with_source_and_offset(
        self,
        source_name: impl AsRef<str>,
        source: &[u8],
        byte_offset: usize,
    ) -> Result<Self, SourceLocationError> {
        self.try_with_source(source_name)
            .and_then(|location| location.with_byte_offset_in(source, byte_offset))
    }

    /// Adds or replaces a validated one-based line and column pair.
    pub fn with_line_column(self, line: u32, column: u32) -> Result<Self, SourceLocationError> {
        if line == 0 {
            return Err(SourceLocationError::InvalidLine { value: line });
        }
        if column == 0 {
            return Err(SourceLocationError::InvalidColumn { value: column });
        }
        Ok(Self {
            line: Some(line),
            column: Some(column),
            ..self
        })
    }

    /// Explicit checked-construction alias for [`Self::with_line_column`].
    pub fn try_with_line_column(self, line: u32, column: u32) -> Result<Self, SourceLocationError> {
        self.with_line_column(line, column)
    }

    /// Returns the optional canonical source/document label.
    ///
    /// This is a trusted model accessor.  Diagnostics should use
    /// [`Self::redacted_source_name`] or the redacted [`Display`](fmt::Display)
    /// implementation instead.
    #[must_use]
    pub fn source_name(&self) -> Option<&str> {
        self.source.as_deref()
    }

    /// Returns a redacted source label suitable for ordinary diagnostics.
    #[must_use]
    pub fn redacted_source_name(&self) -> Option<&'static str> {
        self.source.as_ref().map(|_| REDACTED_SOURCE)
    }

    /// Returns the optional zero-based byte offset.
    #[must_use]
    pub const fn byte_offset(&self) -> Option<u64> {
        self.byte_offset
    }

    /// Returns the optional one-based line number.
    #[must_use]
    pub const fn line(&self) -> Option<u32> {
        self.line
    }

    /// Returns the optional one-based Unicode-scalar column number.
    #[must_use]
    pub const fn column(&self) -> Option<u32> {
        self.column
    }

    /// Validates all present coordinates and bounded offset evidence.
    pub const fn validate(&self) -> Result<(), SourceLocationError> {
        if let Some(line) = self.line
            && line == 0
        {
            return Err(SourceLocationError::InvalidLine { value: line });
        }
        if let Some(column) = self.column
            && column == 0
        {
            return Err(SourceLocationError::InvalidColumn { value: column });
        }
        if let Some(offset) = self.byte_offset
            && offset > MAX_SOURCE_BYTE_OFFSET
        {
            return Err(SourceLocationError::ByteOffsetTooLarge {
                offset,
                limit: MAX_SOURCE_BYTE_OFFSET,
            });
        }
        Ok(())
    }

    /// Returns whether no location component is known.
    #[must_use]
    pub fn is_unknown(&self) -> bool {
        self.source.is_none()
            && self.byte_offset.is_none()
            && self.line.is_none()
            && self.column.is_none()
    }

    /// Returns a stable, domain-local identity for this location.
    ///
    /// The identity is derived from the canonical label and coordinate
    /// presence bits.  It never exposes the label and distinguishes absent
    /// fields from zero-valued fields.  It is a compact diagnostic key, not a
    /// cryptographic digest and must not be used as an authorization token.
    #[must_use]
    pub fn canonical_identity(&self) -> u64 {
        let mut hash = FNV_OFFSET_BASIS;
        hash = fnv_update(hash, b"jmeter-rs.model.source-location.v1\0");
        hash = fnv_option_bytes(hash, self.source.as_deref().map(str::as_bytes));
        hash = fnv_option_u64(hash, self.byte_offset);
        hash = fnv_option_u32(hash, self.line);
        hash = fnv_option_u32(hash, self.column);
        if hash == 0 { 1 } else { hash }
    }

    /// Compatibility spelling for [`Self::canonical_identity`].
    #[must_use]
    pub fn identity(&self) -> u64 {
        self.canonical_identity()
    }

    const fn from_valid_line_column(line: u32, column: u32) -> Self {
        Self {
            source: None,
            byte_offset: None,
            line: Some(line),
            column: Some(column),
        }
    }
}

/// Canonicalizes a source label without consulting the filesystem.
fn canonical_source_label(source: &str) -> Result<String, SourceLocationError> {
    if source.is_empty() {
        return Err(SourceLocationError::EmptySource);
    }
    if source.len() > MAX_SOURCE_NAME_BYTES {
        return Err(SourceLocationError::SourceTooLong {
            bytes: source.len(),
            limit: MAX_SOURCE_NAME_BYTES,
        });
    }
    for (position, character) in source.char_indices() {
        if character == '\0' {
            return Err(SourceLocationError::SourceContainsNul { position });
        }
        if character.is_control() {
            return Err(SourceLocationError::SourceContainsControl { position });
        }
    }

    // Labels such as `<stdin>` and URI-like source references are identifiers,
    // not filesystem paths.  They are already stable without applying path
    // traversal rules.  Their bytes remain bounded and control-free above.
    if is_opaque_label(source) || looks_like_uri(source) {
        return Ok(source.to_owned());
    }

    // Normalize separators lexically.  This is intentionally not
    // `std::fs::canonicalize`: symlinks, current directories, and ambient
    // filesystem state must not affect semantic identity.
    let normalized = source.replace('\\', "/");
    let (prefix, rooted, drive_relative, rest) = path_prefix(&normalized);
    let mut components = Vec::new();
    for component in rest.split('/') {
        if component.is_empty() {
            continue;
        }
        if components.len() >= MAX_SOURCE_PATH_COMPONENTS {
            return Err(SourceLocationError::SourceTooManyComponents {
                components: components.len().saturating_add(1),
                limit: MAX_SOURCE_PATH_COMPONENTS,
            });
        }
        match component {
            "." => {}
            ".." if components.last().is_some_and(|last: &&str| *last != "..") => {
                components.pop();
            }
            ".." if !rooted => components.push(component),
            ".." => {}
            _ => components.push(component),
        }
    }

    let mut canonical = String::with_capacity(normalized.len());
    canonical.push_str(prefix);
    for component in components {
        let needs_separator = !canonical.is_empty()
            && !canonical.ends_with('/')
            && !(drive_relative && canonical.len() == 2);
        if needs_separator {
            canonical.push('/');
        }
        canonical.push_str(component);
    }
    if canonical.is_empty() {
        canonical.push(if rooted { '/' } else { '.' });
    }
    if canonical.len() > MAX_SOURCE_NAME_BYTES {
        return Err(SourceLocationError::SourceTooLong {
            bytes: canonical.len(),
            limit: MAX_SOURCE_NAME_BYTES,
        });
    }
    Ok(canonical)
}

fn is_opaque_label(source: &str) -> bool {
    source.starts_with('<') && source.ends_with('>') && source.len() >= 3
}

fn looks_like_uri(source: &str) -> bool {
    let Some(colon) = source.find(':') else {
        return false;
    };
    if colon == 0 || !source.as_bytes()[0].is_ascii_alphabetic() {
        return false;
    }
    if !source.as_bytes()[1..colon]
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
    {
        return false;
    }
    source[colon + 1..].starts_with("//")
}

fn path_prefix(path: &str) -> (&str, bool, bool, &str) {
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'/' && bytes[1] == b'/' {
        return ("//", true, false, path[2..].trim_start_matches('/'));
    }
    if bytes.first() == Some(&b'/') {
        return ("/", true, false, path[1..].trim_start_matches('/'));
    }
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        if bytes.get(2) == Some(&b'/') {
            return (&path[..2], true, false, path[3..].trim_start_matches('/'));
        }
        return (&path[..2], false, true, &path[2..]);
    }
    ("", false, false, path)
}

fn checked_source_position(
    source: &[u8],
    byte_offset: usize,
) -> Result<(u32, u32, u64, u64), SourceLocationError> {
    let max_source_bytes = MAX_SOURCE_BYTE_OFFSET as usize;
    if source.len() > max_source_bytes {
        return Err(SourceLocationError::SourceTooLong {
            bytes: source.len(),
            limit: max_source_bytes,
        });
    }
    let text = std::str::from_utf8(source).map_err(|error| SourceLocationError::InvalidUtf8 {
        position: error.valid_up_to(),
    })?;
    let offset =
        u64::try_from(byte_offset).map_err(|_| SourceLocationError::ByteOffsetTooLarge {
            offset: u64::MAX,
            limit: MAX_SOURCE_BYTE_OFFSET,
        })?;
    let source_len =
        u64::try_from(source.len()).map_err(|_| SourceLocationError::SourceTooLong {
            bytes: source.len(),
            limit: max_source_bytes,
        })?;
    if byte_offset > source.len() {
        return Err(SourceLocationError::ByteOffsetOutOfBounds { offset, source_len });
    }
    if offset > MAX_SOURCE_BYTE_OFFSET {
        return Err(SourceLocationError::ByteOffsetTooLarge {
            offset,
            limit: MAX_SOURCE_BYTE_OFFSET,
        });
    }
    if !text.is_char_boundary(byte_offset) {
        return Err(SourceLocationError::ByteOffsetNotCharBoundary { offset });
    }

    let mut line = 1_u32;
    let mut column = 1_u32;
    let mut cursor = 0;
    while cursor < byte_offset {
        match source[cursor] {
            b'\n' => {
                line = line.saturating_add(1);
                column = 1;
                cursor += 1;
            }
            b'\r' => {
                line = line.saturating_add(1);
                column = 1;
                cursor += 1;
                if cursor < byte_offset && source[cursor] == b'\n' {
                    cursor += 1;
                }
            }
            _ => {
                let Some(character) = text[cursor..byte_offset].chars().next() else {
                    return Err(SourceLocationError::ByteOffsetNotCharBoundary { offset });
                };
                column = column.saturating_add(1);
                cursor += character.len_utf8();
            }
        }
    }
    Ok((line, column, offset, source_len))
}

fn fnv_update(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn fnv_option_bytes(hash: u64, value: Option<&[u8]>) -> u64 {
    match value {
        Some(value) => fnv_update(fnv_update(hash, &[1]), value),
        None => fnv_update(hash, &[0]),
    }
}

fn fnv_option_u64(hash: u64, value: Option<u64>) -> u64 {
    match value {
        Some(value) => fnv_update(fnv_update(hash, &[1]), &value.to_be_bytes()),
        None => fnv_update(hash, &[0]),
    }
}

fn fnv_option_u32(hash: u64, value: Option<u32>) -> u64 {
    match value {
        Some(value) => fnv_update(fnv_update(hash, &[1]), &value.to_be_bytes()),
        None => fnv_update(hash, &[0]),
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "deterministic source-location tests assert setup before inspecting values"
)]
mod tests {
    use super::*;

    #[test]
    fn source_labels_are_bounded_canonical_and_cross_platform() {
        let left = SourceLocation::unknown()
            .try_with_source("./fixture\\nested/../plan.jmx")
            .expect("safe source label");
        let right = SourceLocation::unknown()
            .try_with_source("fixture/plan.jmx")
            .expect("safe source label");
        assert_eq!(left.source_name(), Some("fixture/plan.jmx"));
        assert_eq!(left, right);
        assert_eq!(left.canonical_identity(), right.canonical_identity());

        let too_long = "x".repeat(MAX_SOURCE_NAME_BYTES + 1);
        assert!(matches!(
            SourceLocation::unknown().try_with_source(&too_long),
            Err(SourceLocationError::SourceTooLong { .. })
        ));
        assert!(
            SourceLocation::unknown()
                .with_source(too_long)
                .source_name()
                .is_none(),
            "the infallible compatibility builder must not retain an oversized label"
        );
        assert!(matches!(
            SourceLocation::unknown().try_with_source("safe\nunsafe"),
            Err(SourceLocationError::SourceContainsControl { .. })
        ));
    }

    #[test]
    fn checked_offsets_use_utf8_bytes_and_unicode_scalar_columns() {
        let source = "a☃\r\né".as_bytes();
        let start = SourceLocation::from_source_offset(source, 0).expect("start offset");
        assert_eq!(start.byte_offset(), Some(0));
        assert_eq!(start.line(), Some(1));
        assert_eq!(start.column(), Some(1));
        let after_snowman = SourceLocation::from_source_offset(source, 4).expect("UTF-8 end");
        assert_eq!(after_snowman.line(), Some(1));
        assert_eq!(after_snowman.column(), Some(3));
        let after_crlf = SourceLocation::from_source_offset(source, 6).expect("CRLF end");
        assert_eq!(after_crlf.line(), Some(2));
        assert_eq!(after_crlf.column(), Some(1));
        assert_eq!(
            SourceLocation::from_source_offset(source, 2),
            Err(SourceLocationError::ByteOffsetNotCharBoundary { offset: 2 })
        );
        assert_eq!(
            SourceLocation::from_source_offset(source, source.len() + 1),
            Err(SourceLocationError::ByteOffsetOutOfBounds {
                offset: (source.len() + 1) as u64,
                source_len: source.len() as u64,
            })
        );
        assert_eq!(
            SourceLocation::from_source_offset(&[0xff], 0),
            Err(SourceLocationError::InvalidUtf8 { position: 0 })
        );
    }

    #[test]
    fn validation_rejects_unbounded_offsets_and_redacts_diagnostics() {
        let location = SourceLocation::from_byte_offset(MAX_SOURCE_BYTE_OFFSET + 1)
            .with_source("secret/private/plan.jmx");
        assert_eq!(
            location.validate(),
            Err(SourceLocationError::ByteOffsetTooLarge {
                offset: MAX_SOURCE_BYTE_OFFSET + 1,
                limit: MAX_SOURCE_BYTE_OFFSET,
            })
        );
        let valid = SourceLocation::new(7, 3)
            .expect("coordinates")
            .with_source("secret/private/plan.jmx")
            .with_byte_offset(42);
        let debug = format!("{valid:?}");
        let display = valid.to_string();
        assert!(!debug.contains("secret/private/plan.jmx"));
        assert!(!display.contains("secret/private/plan.jmx"));
        assert_eq!(valid.redacted_source_name(), Some(REDACTED_SOURCE));
        assert_ne!(valid.canonical_identity(), 0);
        assert_ne!(
            valid.canonical_identity(),
            valid.with_byte_offset(43).canonical_identity()
        );
    }

    #[test]
    fn checked_location_preserves_source_label_and_offset_together() {
        let location = SourceLocation::unknown()
            .with_source_and_offset("./fixture/plan.jmx", b"<a>\n\xE2\x98\x83</a>", 7)
            .expect("label and UTF-8 offset");
        assert_eq!(location.source_name(), Some("fixture/plan.jmx"));
        assert_eq!(location.byte_offset(), Some(7));
        assert_eq!(location.line(), Some(2));
        assert_eq!(location.column(), Some(2));
        assert!(location.validate().is_ok());
    }
}
