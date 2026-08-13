// SPDX-License-Identifier: Apache-2.0
//! Result payload, header, data-type, and encoding values.
//!
//! The JTL model deliberately keeps payloads separate from their metadata.
//! In particular, a missing body, a present empty body, and a response-file
//! reference are different wire states.  The unbounded constructors below
//! remain available for compatibility with the original model; protocol
//! boundaries should use the `try_*` constructors with an explicit
//! [`DataLimits`] value before allocating or retaining input data.

use core::fmt;

/// Hard maximum for one retained binary response/request payload.
pub const MAX_DATA_BINARY_BYTES: usize = 8 * 1024 * 1024;
/// Hard maximum for one retained UTF-8 response/request payload.
pub const MAX_DATA_TEXT_BYTES: usize = 8 * 1024 * 1024;
/// Hard maximum for one data-type or encoding spelling.
pub const MAX_DATA_ENCODING_BYTES: usize = 1024 * 1024;
/// Hard maximum for one raw request/response header block.
pub const MAX_DATA_HEADER_BYTES: usize = 8 * 1024 * 1024;
/// Hard maximum for one opaque response-file reference.
pub const MAX_DATA_FILE_REFERENCE_BYTES: usize = 64 * 1024;

/// Finite bounds for result data and metadata.
///
/// These limits apply to the UTF-8 byte length of text and metadata, and to
/// the raw byte length of binary payloads.  They are intentionally independent
/// so a large binary response cannot consume the text/header budget of an
/// event, and a long response-file name cannot consume a body budget.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DataLimits {
    max_binary_bytes: usize,
    max_text_bytes: usize,
    max_encoding_bytes: usize,
    max_header_bytes: usize,
    max_file_reference_bytes: usize,
}

impl DataLimits {
    /// Creates explicit finite data limits.
    #[must_use]
    pub const fn new(
        max_binary_bytes: usize,
        max_text_bytes: usize,
        max_encoding_bytes: usize,
        max_header_bytes: usize,
        max_file_reference_bytes: usize,
    ) -> Self {
        Self {
            max_binary_bytes,
            max_text_bytes,
            max_encoding_bytes,
            max_header_bytes,
            max_file_reference_bytes,
        }
    }

    /// A useful finite bound for local JTL/result boundaries.
    #[must_use]
    pub const fn default_bounded() -> Self {
        Self::new(
            4 * 1024 * 1024,
            4 * 1024 * 1024,
            256 * 1024,
            4 * 1024 * 1024,
            16 * 1024,
        )
    }

    /// Returns the maximum binary body size.
    pub const fn max_binary_bytes(self) -> usize {
        self.max_binary_bytes
    }

    /// Returns the maximum UTF-8 text size.
    pub const fn max_text_bytes(self) -> usize {
        self.max_text_bytes
    }

    /// Returns the maximum data-type/encoding metadata size.
    pub const fn max_encoding_bytes(self) -> usize {
        self.max_encoding_bytes
    }

    /// Returns the maximum raw header-block size.
    pub const fn max_header_bytes(self) -> usize {
        self.max_header_bytes
    }

    /// Returns the maximum response-file reference size.
    pub const fn max_file_reference_bytes(self) -> usize {
        self.max_file_reference_bytes
    }

    /// Validates that every bound is non-zero and within the hard retention
    /// ceiling for its field.
    pub fn validate(self) -> Result<(), DataError> {
        let fields = [
            (
                DataField::BinaryBody,
                self.max_binary_bytes,
                MAX_DATA_BINARY_BYTES,
            ),
            (
                DataField::TextBody,
                self.max_text_bytes,
                MAX_DATA_TEXT_BYTES,
            ),
            (
                DataField::Encoding,
                self.max_encoding_bytes,
                MAX_DATA_ENCODING_BYTES,
            ),
            (
                DataField::Headers,
                self.max_header_bytes,
                MAX_DATA_HEADER_BYTES,
            ),
            (
                DataField::FileReference,
                self.max_file_reference_bytes,
                MAX_DATA_FILE_REFERENCE_BYTES,
            ),
        ];
        for (field, maximum, hard_maximum) in fields {
            validate_maximum(field, maximum, hard_maximum)?;
        }
        Ok(())
    }
}

impl Default for DataLimits {
    fn default() -> Self {
        Self::default_bounded()
    }
}

/// A result-data field used in bounded construction errors.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DataField {
    /// A JTL `dt` value.
    DataType,
    /// A JTL `de` value.
    Encoding,
    /// A binary body.
    BinaryBody,
    /// A UTF-8 text body.
    TextBody,
    /// A raw request/response header block.
    Headers,
    /// A `responseFile` reference.
    FileReference,
}

impl fmt::Display for DataField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::DataType => "data type",
            Self::Encoding => "encoding",
            Self::BinaryBody => "binary body",
            Self::TextBody => "text body",
            Self::Headers => "headers",
            Self::FileReference => "file reference",
        };
        formatter.write_str(value)
    }
}

/// Stable categories for bounded result-data errors.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DataErrorCode {
    /// A limit was zero and therefore could not enforce a bound.
    InvalidLimit,
    /// A field exceeded its explicit byte limit.
    TooLarge,
    /// Bytes declared as text were not valid UTF-8.
    InvalidText,
}

impl DataErrorCode {
    /// Returns the stable machine-readable error code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidLimit => "results.data.invalid_limit",
            Self::TooLarge => "results.data.too_large",
            Self::InvalidText => "results.data.invalid_text",
        }
    }
}

impl fmt::Display for DataErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A bounded result-data construction error.
///
/// It carries sizes and field categories only.  The input value itself is
/// never copied into diagnostics, which keeps a malformed body or a secret
/// file reference out of `Debug` and `Display` output.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DataError {
    /// A configured field limit was zero or exceeded its hard ceiling.
    InvalidLimit {
        /// Field whose limit was invalid.
        field: DataField,
    },
    /// A field exceeded its configured byte limit.
    TooLarge {
        /// Field whose limit was exceeded.
        field: DataField,
        /// Observed UTF-8/raw byte count.
        actual: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// A byte sequence declared to be text was not valid UTF-8.
    InvalidText {
        /// Field containing invalid text bytes.
        field: DataField,
    },
}

impl DataError {
    /// Returns the stable machine-readable category.
    pub const fn code(self) -> DataErrorCode {
        match self {
            Self::InvalidLimit { .. } => DataErrorCode::InvalidLimit,
            Self::TooLarge { .. } => DataErrorCode::TooLarge,
            Self::InvalidText { .. } => DataErrorCode::InvalidText,
        }
    }

    /// Returns the stable machine-readable string code.
    pub const fn stable_code(self) -> &'static str {
        self.code().as_str()
    }
}

impl fmt::Display for DataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit { field } => write!(formatter, "{}: {field}", self.code()),
            Self::TooLarge {
                field,
                actual,
                maximum,
            } => write!(
                formatter,
                "{}: {field} bytes {actual} exceed {maximum}",
                self.code()
            ),
            Self::InvalidText { field } => write!(formatter, "{}: {field}", self.code()),
        }
    }
}

impl std::error::Error for DataError {}

fn validate_maximum(
    field: DataField,
    maximum: usize,
    hard_maximum: usize,
) -> Result<(), DataError> {
    if maximum == 0 || maximum > hard_maximum {
        return Err(DataError::InvalidLimit { field });
    }
    Ok(())
}

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

    /// Parses a borrowed wire value while checking its byte bound before
    /// retaining the value.
    pub fn try_from_wire(value: &str, maximum: usize) -> Result<Self, DataError> {
        validate_maximum(DataField::DataType, maximum, MAX_DATA_ENCODING_BYTES)?;
        if value.len() > maximum {
            return Err(DataError::TooLarge {
                field: DataField::DataType,
                actual: value.len(),
                maximum,
            });
        }
        Ok(Self::from_wire(value))
    }

    /// Parses a wire value using the metadata bound in `limits`.
    pub fn try_from_wire_with_limits(value: &str, limits: DataLimits) -> Result<Self, DataError> {
        limits.validate()?;
        Self::try_from_wire(value, limits.max_encoding_bytes)
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

    /// Returns whether this value denotes text data.
    pub const fn is_text(&self) -> bool {
        matches!(self, Self::Text)
    }

    /// Returns whether this value denotes binary data.
    pub const fn is_binary(&self) -> bool {
        matches!(self, Self::Binary)
    }

    /// Returns whether this is one of JMeter's known data types.
    pub const fn is_known(&self) -> bool {
        matches!(self, Self::Text | Self::Binary)
    }

    /// Returns a redacted metadata projection suitable for diagnostics.
    #[must_use]
    pub fn redacted(&self) -> DataTypeDiagnostic {
        DataTypeDiagnostic {
            wire_value_bytes: self.as_wire().len(),
            known: self.is_known(),
            binary: self.is_binary(),
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

/// A redacted projection of a data-type value.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DataTypeDiagnostic {
    /// Number of bytes in the exact wire spelling.
    pub wire_value_bytes: usize,
    /// Whether the value is `text` or `bin`.
    pub known: bool,
    /// Whether the value denotes binary data.
    pub binary: bool,
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

    /// Creates an encoding name after checking an explicit byte bound.
    pub fn try_new(value: impl AsRef<str>, maximum: usize) -> Result<Self, DataError> {
        let value = value.as_ref();
        validate_maximum(DataField::Encoding, maximum, MAX_DATA_ENCODING_BYTES)?;
        if value.len() > maximum {
            return Err(DataError::TooLarge {
                field: DataField::Encoding,
                actual: value.len(),
                maximum,
            });
        }
        Ok(Self::new(value))
    }

    /// Creates an encoding name using the metadata bound in `limits`.
    pub fn try_new_with_limits(
        value: impl AsRef<str>,
        limits: DataLimits,
    ) -> Result<Self, DataError> {
        limits.validate()?;
        Self::try_new(value, limits.max_encoding_bytes)
    }

    /// Returns the encoding name.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the UTF-8 byte length of the name.
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether this is a present empty encoding value.
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consumes the wrapper and returns its name.
    pub fn into_string(self) -> String {
        self.0
    }

    /// Returns a redacted metadata projection.
    #[must_use]
    pub fn redacted(&self) -> EncodingDiagnostic {
        EncodingDiagnostic {
            byte_len: self.len(),
            is_empty: self.is_empty(),
        }
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

/// A redacted projection of an encoding name.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EncodingDiagnostic {
    /// Number of UTF-8 bytes in the name.
    pub byte_len: usize,
    /// Whether the name is present but empty.
    pub is_empty: bool,
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

    /// Creates a payload from a borrowed byte slice after checking a bound.
    /// The length check occurs before the owned copy is made.
    pub fn try_from_slice(value: &[u8], maximum: usize) -> Result<Self, DataError> {
        validate_maximum(DataField::BinaryBody, maximum, MAX_DATA_BINARY_BYTES)?;
        if value.len() > maximum {
            return Err(DataError::TooLarge {
                field: DataField::BinaryBody,
                actual: value.len(),
                maximum,
            });
        }
        Ok(Self::new(value))
    }

    /// Creates a payload from a borrowed slice using the binary-body bound.
    pub fn try_from_slice_with_limits(value: &[u8], limits: DataLimits) -> Result<Self, DataError> {
        limits.validate()?;
        Self::try_from_slice(value, limits.max_binary_bytes)
    }

    /// Creates a payload from text bytes, checking UTF-8 and a text bound
    /// before copying.
    pub fn try_from_text_bytes(value: &[u8], maximum: usize) -> Result<Self, DataError> {
        validate_maximum(DataField::TextBody, maximum, MAX_DATA_TEXT_BYTES)?;
        if value.len() > maximum {
            return Err(DataError::TooLarge {
                field: DataField::TextBody,
                actual: value.len(),
                maximum,
            });
        }
        core::str::from_utf8(value).map_err(|_| DataError::InvalidText {
            field: DataField::TextBody,
        })?;
        Ok(Self::new(value))
    }

    /// Creates a text payload using the text-body bound in `limits`.
    pub fn try_from_text_bytes_with_limits(
        value: &[u8],
        limits: DataLimits,
    ) -> Result<Self, DataError> {
        limits.validate()?;
        Self::try_from_text_bytes(value, limits.max_text_bytes)
    }

    /// Creates a payload containing no bytes.
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    /// Returns the payload bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the payload as UTF-8 text when it is valid UTF-8.
    pub fn as_text(&self) -> Option<&str> {
        core::str::from_utf8(&self.0).ok()
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

    /// Returns a borrowed canonical projection containing exact bytes and
    /// presence-independent metadata.  The projection's `Debug` output is
    /// redacted, while [`SampleDataProjection::as_bytes`] remains available to
    /// an explicit codec or digest implementation.
    #[must_use]
    pub fn canonical_projection(&self) -> SampleDataProjection<'_> {
        SampleDataProjection {
            bytes: &self.0,
            is_utf8: self.as_text().is_some(),
        }
    }

    /// Returns a redacted payload projection suitable for diagnostics.
    #[must_use]
    pub fn redacted(&self) -> DataDiagnostic {
        DataDiagnostic {
            byte_len: self.len(),
            is_empty: self.is_empty(),
            is_utf8: self.as_text().is_some(),
        }
    }
}

impl fmt::Debug for SampleData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.redacted().fmt(formatter)
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

/// A redacted projection of raw sample bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DataDiagnostic {
    /// Number of raw payload bytes.
    pub byte_len: usize,
    /// Whether the payload is present but empty.
    pub is_empty: bool,
    /// Whether the bytes are valid UTF-8 (not a claim that they are JTL text).
    pub is_utf8: bool,
}

/// A borrowed canonical projection of raw sample bytes.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct SampleDataProjection<'a> {
    bytes: &'a [u8],
    is_utf8: bool,
}

impl<'a> SampleDataProjection<'a> {
    /// Returns the exact bytes for an explicit canonical encoder.
    pub fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the byte length.
    pub const fn len(self) -> usize {
        self.bytes.len()
    }

    /// Returns whether the payload is empty.
    pub const fn is_empty(self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns whether the bytes are valid UTF-8.
    pub const fn is_utf8(self) -> bool {
        self.is_utf8
    }
}

impl fmt::Debug for SampleDataProjection<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.redacted().fmt(formatter)
    }
}

impl<'a> SampleDataProjection<'a> {
    /// Returns a redacted projection of this canonical view.
    #[must_use]
    pub const fn redacted(self) -> DataDiagnostic {
        DataDiagnostic {
            byte_len: self.bytes.len(),
            is_empty: self.bytes.is_empty(),
            is_utf8: self.is_utf8,
        }
    }
}

/// Whether an explicitly typed body is text or binary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BodyKind {
    /// UTF-8 text body.
    Text,
    /// Opaque binary body.
    Binary,
}

impl BodyKind {
    /// Returns the canonical JTL data type.
    pub const fn data_type(self) -> DataType {
        match self {
            Self::Text => DataType::Text,
            Self::Binary => DataType::Binary,
        }
    }

    /// Returns whether this is a text body.
    pub const fn is_text(self) -> bool {
        matches!(self, Self::Text)
    }

    /// Returns whether this is a binary body.
    pub const fn is_binary(self) -> bool {
        matches!(self, Self::Binary)
    }
}

/// A body with its text/binary distinction attached to the bytes.
///
/// `SampleResult` retains the historical independent `DataType` and
/// `SampleData` fields for wire compatibility.  This type is the safer
/// construction boundary for new samplers and adapters: text is guaranteed
/// UTF-8, while binary remains opaque and is never coerced through lossy text.
#[derive(Clone, Eq, Hash, PartialEq)]
pub enum SampleBody {
    /// A UTF-8 text body.
    Text(String),
    /// An opaque binary body.
    Binary(SampleData),
}

impl fmt::Debug for SampleBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.redacted().fmt(formatter)
    }
}

impl SampleBody {
    /// Creates an unbounded text body.
    pub fn text(value: impl Into<String>) -> Self {
        Self::Text(value.into())
    }

    /// Creates an unbounded binary body.
    pub fn binary(value: impl Into<Vec<u8>>) -> Self {
        Self::Binary(SampleData::new(value))
    }

    /// Creates a bounded UTF-8 text body.
    pub fn try_text(value: &str, maximum: usize) -> Result<Self, DataError> {
        validate_maximum(DataField::TextBody, maximum, MAX_DATA_TEXT_BYTES)?;
        if value.len() > maximum {
            return Err(DataError::TooLarge {
                field: DataField::TextBody,
                actual: value.len(),
                maximum,
            });
        }
        Ok(Self::Text(value.to_owned()))
    }

    /// Creates a bounded binary body.
    pub fn try_binary(value: &[u8], maximum: usize) -> Result<Self, DataError> {
        SampleData::try_from_slice(value, maximum).map(Self::Binary)
    }

    /// Creates a bounded body using the corresponding `limits` field.
    pub fn try_text_with_limits(value: &str, limits: DataLimits) -> Result<Self, DataError> {
        limits.validate()?;
        Self::try_text(value, limits.max_text_bytes)
    }

    /// Creates a bounded binary body using the corresponding `limits` field.
    pub fn try_binary_with_limits(value: &[u8], limits: DataLimits) -> Result<Self, DataError> {
        limits.validate()?;
        Self::try_binary(value, limits.max_binary_bytes)
    }

    /// Returns the body's attached kind.
    pub const fn kind(&self) -> BodyKind {
        match self {
            Self::Text(_) => BodyKind::Text,
            Self::Binary(_) => BodyKind::Binary,
        }
    }

    /// Returns the canonical JTL data type.
    pub const fn data_type(&self) -> DataType {
        self.kind().data_type()
    }

    /// Returns the exact body bytes.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Text(value) => value.as_bytes(),
            Self::Binary(value) => value.as_bytes(),
        }
    }

    /// Returns text when this body is the typed text variant.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(value) => Some(value),
            Self::Binary(_) => None,
        }
    }

    /// Returns the body byte length.
    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }

    /// Returns whether the body is present but empty.
    pub fn is_empty(&self) -> bool {
        self.as_bytes().is_empty()
    }

    /// Returns a borrowed canonical body projection retaining kind and exact
    /// bytes without allowing debug formatting to expose them.
    #[must_use]
    pub fn canonical_projection(&self) -> BodyProjection<'_> {
        BodyProjection {
            kind: self.kind(),
            bytes: self.as_bytes(),
        }
    }

    /// Converts the body to the historical raw-byte model.
    pub fn into_sample_data(self) -> SampleData {
        match self {
            Self::Text(value) => SampleData::new(value.into_bytes()),
            Self::Binary(value) => value,
        }
    }

    /// Consumes the body and returns its exact bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.into_sample_data().into_bytes()
    }

    /// Returns a redacted body projection.
    #[must_use]
    pub fn redacted(&self) -> BodyDiagnostic {
        BodyDiagnostic {
            kind: self.kind(),
            byte_len: self.len(),
            is_empty: self.is_empty(),
        }
    }
}

/// A redacted projection of an explicitly typed body.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BodyDiagnostic {
    /// Text or binary body kind.
    pub kind: BodyKind,
    /// Number of raw body bytes.
    pub byte_len: usize,
    /// Whether the body is present but empty.
    pub is_empty: bool,
}

/// A borrowed canonical projection of an explicitly typed body.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct BodyProjection<'a> {
    kind: BodyKind,
    bytes: &'a [u8],
}

impl<'a> BodyProjection<'a> {
    /// Returns the body's kind.
    pub const fn kind(self) -> BodyKind {
        self.kind
    }

    /// Returns the exact body bytes.
    pub fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the body byte length.
    pub const fn len(self) -> usize {
        self.bytes.len()
    }

    /// Returns whether the body is empty.
    pub const fn is_empty(self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns a redacted diagnostic projection.
    #[must_use]
    pub const fn redacted(self) -> BodyDiagnostic {
        BodyDiagnostic {
            kind: self.kind,
            byte_len: self.bytes.len(),
            is_empty: self.bytes.is_empty(),
        }
    }
}

impl fmt::Debug for BodyProjection<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.redacted().fmt(formatter)
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

    /// Creates a header block after checking an explicit byte bound.
    pub fn try_new(value: impl AsRef<str>, maximum: usize) -> Result<Self, DataError> {
        let value = value.as_ref();
        validate_maximum(DataField::Headers, maximum, MAX_DATA_HEADER_BYTES)?;
        if value.len() > maximum {
            return Err(DataError::TooLarge {
                field: DataField::Headers,
                actual: value.len(),
                maximum,
            });
        }
        Ok(Self::new(value))
    }

    /// Creates a header block using the header bound in `limits`.
    pub fn try_new_with_limits(
        value: impl AsRef<str>,
        limits: DataLimits,
    ) -> Result<Self, DataError> {
        limits.validate()?;
        Self::try_new(value, limits.max_header_bytes)
    }

    /// Creates an explicitly empty header block.
    pub const fn empty() -> Self {
        Self(String::new())
    }

    /// Returns the raw header block.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the raw header bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Returns the UTF-8 byte length of the block.
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the present header block is empty.
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consumes the block and returns its raw text.
    pub fn into_string(self) -> String {
        self.0
    }

    /// Returns a redacted diagnostic projection.
    #[must_use]
    pub const fn redacted(&self) -> HeaderDiagnostic {
        HeaderDiagnostic {
            byte_len: self.0.len(),
            is_empty: self.0.is_empty(),
        }
    }
}

impl fmt::Debug for HeaderBlock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.redacted().fmt(formatter)
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

/// A redacted projection of a raw header block.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct HeaderDiagnostic {
    /// Number of UTF-8 bytes in the raw block.
    pub byte_len: usize,
    /// Whether the block is present but empty.
    pub is_empty: bool,
}

/// A response-file reference retained as opaque JTL text.
///
/// This is deliberately not a filesystem path and has no resolve/open method.
/// The application owns the source-directory capability and must decide
/// whether a reference may be resolved.  Keeping the wrapper in the pure
/// results crate prevents a nonempty `responseFile` field from becoming an
/// implicit file read.
#[derive(Clone, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FileReference(String);

impl FileReference {
    /// Creates an opaque, unbounded file reference.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Creates a file reference after checking an explicit byte bound.
    pub fn try_new(value: impl AsRef<str>, maximum: usize) -> Result<Self, DataError> {
        let value = value.as_ref();
        validate_maximum(
            DataField::FileReference,
            maximum,
            MAX_DATA_FILE_REFERENCE_BYTES,
        )?;
        if value.len() > maximum {
            return Err(DataError::TooLarge {
                field: DataField::FileReference,
                actual: value.len(),
                maximum,
            });
        }
        Ok(Self::new(value))
    }

    /// Creates a file reference using the bound in `limits`.
    pub fn try_new_with_limits(
        value: impl AsRef<str>,
        limits: DataLimits,
    ) -> Result<Self, DataError> {
        limits.validate()?;
        Self::try_new(value, limits.max_file_reference_bytes)
    }

    /// Creates an explicitly empty file reference.
    pub const fn empty() -> Self {
        Self(String::new())
    }

    /// Returns the exact opaque reference text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the UTF-8 byte length of the reference.
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the reference is present but empty.
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consumes the wrapper and returns the reference text.
    pub fn into_string(self) -> String {
        self.0
    }

    /// Returns an exact borrowed canonical projection.  It never resolves or
    /// normalizes the reference.
    #[must_use]
    pub fn canonical_projection(&self) -> FileReferenceProjection<'_> {
        FileReferenceProjection { value: &self.0 }
    }

    /// Returns a redacted diagnostic projection.
    #[must_use]
    pub const fn redacted(&self) -> FileReferenceDiagnostic {
        FileReferenceDiagnostic {
            byte_len: self.0.len(),
            is_empty: self.0.is_empty(),
        }
    }
}

impl fmt::Debug for FileReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.redacted().fmt(formatter)
    }
}

impl From<String> for FileReference {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for FileReference {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<FileReference> for String {
    fn from(value: FileReference) -> Self {
        value.into_string()
    }
}

/// Semantic alias for a JTL `responseFile` value.
pub type ResponseFileReference = FileReference;

/// A redacted projection of an opaque file reference.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FileReferenceDiagnostic {
    /// Number of UTF-8 bytes in the reference.
    pub byte_len: usize,
    /// Whether the reference is present but empty.
    pub is_empty: bool,
}

/// An exact borrowed projection of an opaque file reference.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct FileReferenceProjection<'a> {
    value: &'a str,
}

impl<'a> FileReferenceProjection<'a> {
    /// Returns the exact source spelling.
    pub fn as_str(self) -> &'a str {
        self.value
    }

    /// Returns the UTF-8 byte length.
    pub const fn len(self) -> usize {
        self.value.len()
    }

    /// Returns whether the reference is empty.
    pub const fn is_empty(self) -> bool {
        self.value.is_empty()
    }

    /// Returns a redacted diagnostic projection.
    #[must_use]
    pub const fn redacted(self) -> FileReferenceDiagnostic {
        FileReferenceDiagnostic {
            byte_len: self.value.len(),
            is_empty: self.value.is_empty(),
        }
    }
}

impl fmt::Debug for FileReferenceProjection<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.redacted().fmt(formatter)
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

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: DataLimits = DataLimits::new(4, 5, 3, 6, 7);

    #[test]
    fn bounded_values_reject_before_retaining_input() {
        assert_eq!(
            SampleData::try_from_slice(b"12345", LIMITS.max_binary_bytes()),
            Err(DataError::TooLarge {
                field: DataField::BinaryBody,
                actual: 5,
                maximum: 4,
            })
        );
        assert_eq!(
            SampleData::try_from_text_bytes(b"123456", LIMITS.max_text_bytes()),
            Err(DataError::TooLarge {
                field: DataField::TextBody,
                actual: 6,
                maximum: 5,
            })
        );
        assert_eq!(
            DataEncoding::try_new("UTF-8!", LIMITS.max_encoding_bytes()),
            Err(DataError::TooLarge {
                field: DataField::Encoding,
                actual: 6,
                maximum: 3,
            })
        );
        assert_eq!(
            HeaderBlock::try_new("1234567", LIMITS.max_header_bytes()),
            Err(DataError::TooLarge {
                field: DataField::Headers,
                actual: 7,
                maximum: 6,
            })
        );
        assert_eq!(
            FileReference::try_new("12345678", LIMITS.max_file_reference_bytes()),
            Err(DataError::TooLarge {
                field: DataField::FileReference,
                actual: 8,
                maximum: 7,
            })
        );
    }

    #[test]
    fn limits_reject_zero_without_an_unbounded_fallback() {
        let limits = DataLimits::new(0, 1, 1, 1, 1);
        assert_eq!(
            limits.validate(),
            Err(DataError::InvalidLimit {
                field: DataField::BinaryBody,
            })
        );
        assert_eq!(
            DataType::try_from_wire("text", 0),
            Err(DataError::InvalidLimit {
                field: DataField::DataType,
            })
        );
        assert_eq!(
            SampleBody::try_binary(b"", 0),
            Err(DataError::InvalidLimit {
                field: DataField::BinaryBody,
            })
        );
    }

    #[test]
    fn limits_reject_values_above_the_hard_retention_ceiling() {
        assert!(
            DataLimits::new(
                MAX_DATA_BINARY_BYTES,
                MAX_DATA_TEXT_BYTES,
                MAX_DATA_ENCODING_BYTES,
                MAX_DATA_HEADER_BYTES,
                MAX_DATA_FILE_REFERENCE_BYTES,
            )
            .validate()
            .is_ok()
        );
        let limits = DataLimits::new(
            MAX_DATA_BINARY_BYTES + 1,
            MAX_DATA_TEXT_BYTES,
            MAX_DATA_ENCODING_BYTES,
            MAX_DATA_HEADER_BYTES,
            MAX_DATA_FILE_REFERENCE_BYTES,
        );
        assert_eq!(
            limits.validate(),
            Err(DataError::InvalidLimit {
                field: DataField::BinaryBody,
            })
        );
    }

    #[test]
    fn text_and_binary_bodies_never_coerce_each_other() -> Result<(), DataError> {
        // Bounds are measured in UTF-8 bytes: `héllo` is six bytes even
        // though it contains five Unicode scalar values.
        let text = SampleBody::try_text("héllo", 6)?;
        assert_eq!(
            SampleBody::try_text("héllo", LIMITS.max_text_bytes()),
            Err(DataError::TooLarge {
                field: DataField::TextBody,
                actual: 6,
                maximum: 5,
            })
        );
        let binary = SampleBody::try_binary(&[0xff, 0x00], LIMITS.max_binary_bytes())?;
        assert_eq!(text.kind(), BodyKind::Text);
        assert_eq!(text.data_type(), DataType::Text);
        assert_eq!(text.as_text(), Some("héllo"));
        assert_eq!(text.as_bytes(), "héllo".as_bytes());
        assert_eq!(binary.kind(), BodyKind::Binary);
        assert_eq!(binary.data_type(), DataType::Binary);
        assert_eq!(binary.as_text(), None);
        assert_eq!(binary.as_bytes(), [0xff, 0x00]);
        assert_eq!(binary.clone().into_sample_data().as_bytes(), [0xff, 0x00]);
        assert_eq!(
            SampleData::try_from_text_bytes(&[0xff], LIMITS.max_text_bytes()),
            Err(DataError::InvalidText {
                field: DataField::TextBody,
            })
        );
        Ok(())
    }

    #[test]
    fn present_empty_values_remain_distinct_from_absence() {
        let empty_body = SampleBody::binary(Vec::<u8>::new());
        let empty_headers = HeaderBlock::empty();
        let empty_reference = FileReference::empty();
        let empty_encoding = DataEncoding::new("");
        assert!(empty_body.is_empty());
        assert!(empty_headers.is_empty());
        assert!(empty_reference.is_empty());
        assert!(empty_encoding.is_empty());
        assert!(Some(empty_body).is_some());
        assert!(Some(empty_headers).is_some());
        assert!(Some(empty_reference).is_some());
        assert!(Some(empty_encoding).is_some());
    }

    #[test]
    fn file_reference_is_opaque_and_canonical_projection_does_not_resolve_it() {
        let reference = FileReference::new("../secret/response.bin");
        let projection = reference.canonical_projection();
        assert_eq!(projection.as_str(), "../secret/response.bin");
        assert_eq!(projection.len(), "../secret/response.bin".len());
        assert!(!projection.is_empty());
        assert_eq!(
            format!("{reference:?}"),
            "FileReferenceDiagnostic { byte_len: 22, is_empty: false }"
        );
    }

    #[test]
    fn canonical_and_debug_projections_retain_shape_but_not_secrets() {
        let secret = b"Authorization: Bearer body-secret";
        let data = SampleData::new(secret);
        let projection = data.canonical_projection();
        assert_eq!(projection.as_bytes(), secret);
        assert_eq!(projection.len(), secret.len());
        assert!(projection.is_utf8());
        let debug = format!("{data:?} {:?}", projection);
        assert!(debug.contains("byte_len"));
        assert!(!debug.contains("body-secret"));

        let body = SampleBody::binary(secret);
        assert_eq!(body.canonical_projection().as_bytes(), secret);
        let body_debug = format!("{body:?} {:?}", body.canonical_projection());
        assert!(!body_debug.contains("body-secret"));
        assert!(body_debug.contains("Binary"));
    }

    #[test]
    fn unknown_data_type_is_retained_but_debug_is_redacted() {
        let extension = "vendor-secret-type";
        let value = DataType::from_wire(extension);
        assert_eq!(value.as_wire(), extension);
        assert!(!value.is_known());
        assert!(!value.is_binary());
        assert_eq!(value.redacted().wire_value_bytes, extension.len());
        assert!(!format!("{value:?}").contains(extension));
    }

    #[test]
    fn error_diagnostics_do_not_copy_input_values() -> Result<(), DataError> {
        let secret = "response-file-secret";
        let error = FileReference::try_new(secret, 1)
            .err()
            .ok_or(DataError::InvalidLimit {
                field: DataField::FileReference,
            })?;
        assert!(!format!("{error:?}").contains(secret));
        assert!(!error.to_string().contains(secret));
        assert_eq!(error.stable_code(), "results.data.too_large");
        Ok(())
    }
}
