// SPDX-License-Identifier: Apache-2.0
//! Result payload, header, data-type, and encoding values.

use core::fmt;

/// The representation of a sampler response in JTL (`dt`).
#[derive(Clone, Default, Eq, Hash, PartialEq)]
pub enum DataType {
    /// Text response data.
    #[default]
    Text,
    /// Binary response data.
    Binary,
    /// A value introduced by a newer or extension writer.
    Other(String),
}

impl fmt::Debug for DataType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text => formatter.write_str("DataType::Text"),
            Self::Binary => formatter.write_str("DataType::Binary"),
            Self::Other(value) => formatter
                .debug_struct("DataType::Other")
                .field("wire_value_len", &value.len())
                .finish(),
        }
    }
}

impl DataType {
    /// Parses a wire value without discarding an unknown extension value.
    pub fn from_wire(value: impl Into<String>) -> Self {
        let value = value.into();
        match value.as_str() {
            "text" => Self::Text,
            "bin" | "binary" => Self::Binary,
            _ => Self::Other(value),
        }
    }

    /// Returns the JTL spelling for a known value, or the preserved extension
    /// spelling for [`DataType::Other`].
    pub fn as_wire(&self) -> &str {
        match self {
            Self::Text => "text",
            Self::Binary => "bin",
            Self::Other(value) => value,
        }
    }
}

impl From<String> for DataType {
    fn from(value: String) -> Self {
        Self::from_wire(value)
    }
}

impl From<&str> for DataType {
    fn from(value: &str) -> Self {
        Self::from_wire(value)
    }
}

impl fmt::Display for DataType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_wire())
    }
}

/// An encoding name attached to request or response data.
///
/// The value is intentionally not validated against the host's codec list;
/// JTL loading must preserve an encoding name even when this crate cannot
/// decode it.
#[derive(Clone, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DataEncoding(String);

impl fmt::Debug for DataEncoding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataEncoding")
            .field("name_len", &self.0.len())
            .finish()
    }
}

impl DataEncoding {
    /// Creates an encoding name. Empty names are valid and distinct from an
    /// absent encoding field.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the encoding name.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the wrapper and returns its name.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl From<String> for DataEncoding {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for DataEncoding {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl fmt::Display for DataEncoding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Request or response bytes. An empty value is a present, meaningful payload;
/// absence is represented by `Option<SampleData>` on [`crate::SampleResult`].
/// Its [`Debug`] representation reports only the byte length; callers that
/// explicitly need the payload must use [`SampleData::as_bytes`].
#[derive(Clone, Default, Eq, Hash, PartialEq)]
pub struct SampleData(Vec<u8>);

impl SampleData {
    /// Creates a payload from bytes.
    pub fn new(value: impl Into<Vec<u8>>) -> Self {
        Self(value.into())
    }

    /// Creates a payload containing no bytes.
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    /// Returns the payload bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the payload length.
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the payload is present but empty.
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consumes the payload and returns its bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for SampleData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SampleData")
            .field("len", &self.0.len())
            .finish()
    }
}

impl From<Vec<u8>> for SampleData {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

impl From<&[u8]> for SampleData {
    fn from(value: &[u8]) -> Self {
        Self::new(value.to_vec())
    }
}

impl From<String> for SampleData {
    fn from(value: String) -> Self {
        Self::new(value.into_bytes())
    }
}

impl From<&str> for SampleData {
    fn from(value: &str) -> Self {
        Self::new(value.as_bytes())
    }
}

/// Raw request or response headers. Its [`Debug`] representation reports only
/// the text length; callers that explicitly need the block must use
/// [`HeaderBlock::as_str`].
///
/// Header parsing and canonicalization belong to the HTTP and JTL codec
/// boundaries. Keeping the raw block here preserves duplicate names, order,
/// whitespace, and an explicitly empty block.
#[derive(Clone, Default, Eq, Hash, PartialEq)]
pub struct HeaderBlock(String);

impl HeaderBlock {
    /// Creates a raw header block. Empty text is retained as present data.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Creates an explicitly empty header block.
    pub const fn empty() -> Self {
        Self(String::new())
    }

    /// Returns the raw header block.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns whether the present header block is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consumes the block and returns its raw text.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Debug for HeaderBlock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeaderBlock")
            .field("len", &self.0.len())
            .finish()
    }
}

impl From<String> for HeaderBlock {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for HeaderBlock {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

/// Semantic alias for request data.
pub type RequestData = SampleData;
/// Semantic alias for response data.
pub type ResponseData = SampleData;
/// Semantic alias for request headers.
pub type RequestHeaders = HeaderBlock;
/// Semantic alias for response headers.
pub type ResponseHeaders = HeaderBlock;
