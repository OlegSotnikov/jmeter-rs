// SPDX-License-Identifier: Apache-2.0
//! Source locations retained for diagnostics and semantic nodes.

use core::fmt;

/// Errors raised when a source location violates its one-based coordinate
/// contract.
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
}

impl SourceLocationError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidLine { .. } => "model.source.invalid-line",
            Self::InvalidColumn { .. } => "model.source.invalid-column",
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
        }
    }
}

impl std::error::Error for SourceLocationError {}

/// A best-effort location in an input document.
///
/// Line and column numbers are one-based when present.  Byte offsets are
/// zero-based.  Any component may be absent when an upstream parser does not
/// provide it; an unknown location is represented by [`SourceLocation::unknown`].
#[derive(Clone, Default, Eq, Hash, PartialEq)]
pub struct SourceLocation {
    /// Optional source/document label supplied by the caller.
    source: Option<String>,
    /// Zero-based byte offset in `source`, when known.
    byte_offset: Option<u64>,
    /// One-based line number, when known.
    line: Option<u32>,
    /// One-based column number, when known.
    column: Option<u32>,
}

impl fmt::Debug for SourceLocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceLocation")
            .field("source_present", &self.source.is_some())
            .field("source", &self.source.as_ref().map(|_| "<redacted>"))
            .field("source_len", &self.source.as_ref().map(String::len))
            .field("byte_offset_present", &self.byte_offset.is_some())
            .field("line_present", &self.line.is_some())
            .field("column_present", &self.column.is_some())
            .finish()
    }
}

impl SourceLocation {
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

    /// Creates a location containing only a zero-based byte offset.
    #[must_use]
    pub const fn from_byte_offset(byte_offset: u64) -> Self {
        Self {
            source: None,
            byte_offset: Some(byte_offset),
            line: None,
            column: None,
        }
    }

    /// Adds a source/document label.
    #[must_use]
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// Adds or replaces a zero-based byte offset.
    #[must_use]
    pub const fn with_byte_offset(mut self, byte_offset: u64) -> Self {
        self.byte_offset = Some(byte_offset);
        self
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

    /// Returns the optional source/document label.
    #[must_use]
    pub fn source_name(&self) -> Option<&str> {
        self.source.as_deref()
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

    /// Returns the optional one-based column number.
    #[must_use]
    pub const fn column(&self) -> Option<u32> {
        self.column
    }

    /// Validates all present coordinates and returns a stable typed error.
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

    const fn from_valid_line_column(line: u32, column: u32) -> Self {
        Self {
            source: None,
            byte_offset: None,
            line: Some(line),
            column: Some(column),
        }
    }
}
