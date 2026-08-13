// SPDX-License-Identifier: Apache-2.0
//! Bounded, executor-neutral processor mutation contracts.
//!
//! This module is deliberately independent of the HTTP, bridge, filesystem,
//! and executor crates.  It contains only value objects and a two-phase
//! snapshot/validate/commit state machine.  A caller may provide an explicit
//! file-capability resolver, but runtime itself never opens a path or infers
//! authority from a result filename.

#![allow(
    missing_docs,
    reason = "the mutation vocabulary is documented by this module"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::num::{NonZeroU16, NonZeroU64};
use std::sync::Arc;

use jmeter_rs_results::{
    AssertionResult, DataType, HeaderBlock, LogicalAction, SampleData, SampleResult,
    ValidationLimits,
};

use crate::capabilities::Digest32;
use crate::controllers::ControlSignal;

pub const DEFAULT_MAX_MUTATIONS: usize = 64;
pub const DEFAULT_MAX_VALUE_BYTES: usize = 4 * 1024;
pub const DEFAULT_MAX_RESULT_DEPTH: usize = 32;
pub const DEFAULT_MAX_RESULT_NODES: usize = 256;
pub const DEFAULT_MAX_REQUEST_BYTES: usize = 64 * 1024;
pub const DEFAULT_MAX_DIAGNOSTICS: usize = 32;
pub const DEFAULT_MAX_DIAGNOSTIC_BYTES: usize = 4 * 1024;
pub const DEFAULT_MAX_OUTPUTS: usize = 32;
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 64 * 1024;
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
pub const DEFAULT_MAX_RESPONSE_METADATA_BYTES: usize = 4 * 1024;
pub const DEFAULT_MAX_RESPONSE_HEADER_BYTES: usize = 64 * 1024;
pub const DEFAULT_MAX_RESPONSE_DECODED_BYTES: usize = 4 * 1024 * 1024;
pub const DEFAULT_MAX_RESPONSE_VARIABLE_BYTES: usize = 4 * 1024;
pub const DEFAULT_MAX_RESPONSE_ITEMS: usize = 256;
pub const DEFAULT_MAX_RESPONSE_DEPTH: usize = 32;
pub const DEFAULT_MAX_RESPONSE_FILE_BYTES: usize = 4 * 1024 * 1024;
pub const DEFAULT_MAX_RESPONSE_PROVIDER_INPUT_BYTES: usize = 4 * 1024 * 1024;
pub const DEFAULT_MAX_RESPONSE_PROVIDER_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
pub const DEFAULT_MAX_REQUEST_HEADERS: usize = 256;
pub const DEFAULT_MAX_REQUEST_PATH_SEGMENTS: usize = 256;
pub const DEFAULT_MAX_REQUEST_QUERY_FIELDS: usize = 512;

/// Presence is intentionally not represented by `Option`: present-empty is a
/// meaningful value for bodies, headers, metadata, and mutation values.
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Presence<T> {
    #[default]
    Missing,
    Present(T),
}

impl<T> Presence<T> {
    pub const fn is_missing(&self) -> bool {
        matches!(self, Self::Missing)
    }

    pub const fn is_present(&self) -> bool {
        matches!(self, Self::Present(_))
    }

    pub fn as_ref(&self) -> Presence<&T> {
        match self {
            Self::Missing => Presence::Missing,
            Self::Present(value) => Presence::Present(value),
        }
    }

    pub fn map<U>(self, map: impl FnOnce(T) -> U) -> Presence<U> {
        match self {
            Self::Missing => Presence::Missing,
            Self::Present(value) => Presence::Present(map(value)),
        }
    }
}

/// A bounded UTF-8 value whose debug/display output does not reveal content.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BoundedText(String);

impl BoundedText {
    pub fn try_new(value: impl Into<String>, maximum: usize) -> Result<Self, MutationError> {
        if maximum == 0 {
            return Err(MutationError::limit("text-limit"));
        }
        let value = value.into();
        if value.len() > maximum {
            return Err(MutationError::limit("text-bytes"));
        }
        if value.chars().any(char::is_control) {
            return Err(MutationError::invalid("text-control"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub const fn len(&self) -> usize {
        self.0.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Debug for BoundedText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedText")
            .field("byte_len", &self.0.len())
            .field("is_empty", &self.0.is_empty())
            .finish()
    }
}

impl fmt::Display for BoundedText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "<text:{} bytes>", self.0.len())
    }
}

/// A bounded opaque byte sequence.  Debug output contains only shape.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct BoundedBytes(Vec<u8>);

impl BoundedBytes {
    pub fn try_new(value: impl AsRef<[u8]>, maximum: usize) -> Result<Self, MutationError> {
        if maximum == 0 {
            return Err(MutationError::limit("bytes-limit"));
        }
        let value = value.as_ref();
        if value.len() > maximum {
            return Err(MutationError::limit("bytes"));
        }
        Ok(Self(value.to_vec()))
    }

    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub const fn len(&self) -> usize {
        self.0.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for BoundedBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedBytes")
            .field("byte_len", &self.0.len())
            .field("is_empty", &self.0.is_empty())
            .finish()
    }
}

/// Stable machine-readable mutation error categories.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MutationErrorCode {
    Invalid,
    Limit,
    Overflow,
    StaleGeneration,
    StaleDigest,
    RequestInvalid,
    RequestConflict,
    ResultInvalid,
    ProviderUnavailable,
    Cancelled,
    UnsupportedControl,
    AlreadyCommitted,
    PropertyConflict,
    Internal,
}

impl MutationErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Invalid => "runtime.mutation.invalid",
            Self::Limit => "runtime.mutation.limit",
            Self::Overflow => "runtime.mutation.overflow",
            Self::StaleGeneration => "runtime.mutation.stale-generation",
            Self::StaleDigest => "runtime.mutation.stale-digest",
            Self::RequestInvalid => "runtime.mutation.request-invalid",
            Self::RequestConflict => "runtime.mutation.request-conflict",
            Self::ResultInvalid => "runtime.mutation.result-invalid",
            Self::ProviderUnavailable => "runtime.mutation.provider-unavailable",
            Self::Cancelled => "runtime.mutation.cancelled",
            Self::UnsupportedControl => "runtime.mutation.unsupported-control",
            Self::AlreadyCommitted => "runtime.mutation.already-committed",
            Self::PropertyConflict => "runtime.mutation.property-conflict",
            Self::Internal => "runtime.mutation.internal",
        }
    }
}

/// A redacted typed mutation error.  Details are intentionally field labels,
/// never caller-provided values.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MutationError {
    code: MutationErrorCode,
    detail: &'static str,
}

impl MutationError {
    pub const fn new(code: MutationErrorCode, detail: &'static str) -> Self {
        Self { code, detail }
    }

    pub const fn invalid(detail: &'static str) -> Self {
        Self::new(MutationErrorCode::Invalid, detail)
    }

    pub const fn limit(detail: &'static str) -> Self {
        Self::new(MutationErrorCode::Limit, detail)
    }

    pub const fn overflow(detail: &'static str) -> Self {
        Self::new(MutationErrorCode::Overflow, detail)
    }

    pub const fn code(self) -> MutationErrorCode {
        self.code
    }

    pub const fn stable_code(self) -> &'static str {
        self.code.as_str()
    }

    pub const fn detail(self) -> &'static str {
        self.detail
    }
}

impl fmt::Debug for MutationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MutationError")
            .field("code", &self.code.as_str())
            .field("detail_len", &self.detail.len())
            .finish()
    }
}

impl fmt::Display for MutationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for MutationError {}

pub type ResponseResolveError = MutationError;
pub type RequestStateError = MutationError;
pub type RequestPatchError = MutationError;

/// An opaque application-issued file capability.  It contains no path and
/// cannot be dereferenced by runtime.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FileCapability {
    identity: NonZeroU64,
    byte_length: u64,
    digest: Digest32,
}

impl FileCapability {
    pub fn try_new(
        identity: u64,
        byte_length: u64,
        digest: Digest32,
    ) -> Result<Self, MutationError> {
        let identity = NonZeroU64::new(identity).ok_or(MutationError::invalid("file-identity"))?;
        if digest.is_zero() {
            return Err(MutationError::invalid("file-digest"));
        }
        Ok(Self {
            identity,
            byte_length,
            digest,
        })
    }

    pub const fn identity(self) -> NonZeroU64 {
        self.identity
    }

    pub const fn byte_length(self) -> u64 {
        self.byte_length
    }

    pub const fn digest(self) -> Digest32 {
        self.digest
    }
}

/// Which response projection a processor requested.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ResponseSource {
    Body,
    Headers,
    AllowlistedFile(FileCapability),
}

/// Bounded response metadata accompanying a selected response projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseMetadata {
    pub encoding: Presence<BoundedText>,
    pub data_type: Presence<DataType>,
    pub media_type: Presence<BoundedText>,
    pub response_code: Presence<BoundedText>,
    pub response_message: Presence<BoundedText>,
}

/// A presence-preserving body/header projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseView {
    pub source: ResponseSource,
    pub body: Presence<BoundedBytes>,
    pub raw_headers: Presence<BoundedBytes>,
    pub metadata: ResponseMetadata,
}

impl ResponseView {
    pub fn selected(&self) -> Presence<&BoundedBytes> {
        match self.source {
            ResponseSource::Headers => self.raw_headers.as_ref(),
            ResponseSource::Body | ResponseSource::AllowlistedFile(_) => self.body.as_ref(),
        }
    }

    pub fn selected_bytes(&self) -> Option<&[u8]> {
        match self.selected() {
            Presence::Missing => None,
            Presence::Present(value) => Some(value.as_bytes()),
        }
    }
}

/// Explicit file capability resolution supplied by an application edge.
/// Runtime only checks the returned bounded bytes against the handle.
pub trait AllowlistedFileResolver: Send + Sync {
    fn resolve_file(&self, capability: FileCapability) -> Result<BoundedBytes, MutationError>;
}

/// Executor-neutral, no-I/O response resolver capability.
pub trait ResponseResolver: Send + Sync {
    fn resolve(
        &self,
        result: &SampleResult,
        source: ResponseSource,
    ) -> Result<ResponseView, ResponseResolveError>;
}

/// Default resolver that derives body and headers only from the current typed
/// `SampleResult`; file resolution is unavailable unless explicitly injected.
#[derive(Clone)]
pub struct SampleResultResponseResolver {
    file_resolver: Option<Arc<dyn AllowlistedFileResolver>>,
    maximum_bytes: usize,
    maximum_metadata_bytes: usize,
    maximum_file_bytes: usize,
}

impl Default for SampleResultResponseResolver {
    fn default() -> Self {
        Self {
            file_resolver: None,
            maximum_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            maximum_metadata_bytes: DEFAULT_MAX_RESPONSE_METADATA_BYTES,
            maximum_file_bytes: DEFAULT_MAX_RESPONSE_FILE_BYTES,
        }
    }
}

impl fmt::Debug for SampleResultResponseResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SampleResultResponseResolver")
            .field("file_capability_injected", &self.file_resolver.is_some())
            .field("maximum_bytes", &self.maximum_bytes)
            .field("maximum_metadata_bytes", &self.maximum_metadata_bytes)
            .field("maximum_file_bytes", &self.maximum_file_bytes)
            .finish()
    }
}

impl SampleResultResponseResolver {
    pub fn new() -> Result<Self, MutationError> {
        Ok(Self::default())
    }

    pub fn with_limits(
        maximum_bytes: usize,
        maximum_metadata_bytes: usize,
    ) -> Result<Self, MutationError> {
        if maximum_bytes == 0 || maximum_metadata_bytes == 0 {
            return Err(MutationError::limit("response-limits"));
        }
        Ok(Self {
            file_resolver: None,
            maximum_bytes,
            maximum_metadata_bytes,
            maximum_file_bytes: DEFAULT_MAX_RESPONSE_FILE_BYTES,
        })
    }

    pub fn with_file_resolver(mut self, resolver: Arc<dyn AllowlistedFileResolver>) -> Self {
        self.file_resolver = Some(resolver);
        self
    }

    pub fn file_capability_enabled(&self) -> bool {
        self.file_resolver.is_some()
    }

    /// Sets the maximum capability length checked before a file resolver is
    /// called. The returned resolver remains executor-neutral.
    pub fn with_file_limit(mut self, maximum_file_bytes: usize) -> Result<Self, MutationError> {
        if maximum_file_bytes == 0 {
            return Err(MutationError::limit("file-limit"));
        }
        self.maximum_file_bytes = maximum_file_bytes;
        Ok(self)
    }
}

impl ResponseResolver for SampleResultResponseResolver {
    fn resolve(
        &self,
        result: &SampleResult,
        source: ResponseSource,
    ) -> Result<ResponseView, ResponseResolveError> {
        let metadata = response_metadata(result, self.maximum_metadata_bytes)?;
        let missing_body = || Presence::Missing;
        let missing_headers = || Presence::Missing;
        match source {
            ResponseSource::Body => Ok(ResponseView {
                source,
                body: sample_body(result, self.maximum_bytes)?,
                raw_headers: missing_headers(),
                metadata,
            }),
            ResponseSource::Headers => Ok(ResponseView {
                source,
                body: missing_body(),
                raw_headers: sample_headers(result, self.maximum_bytes)?,
                metadata,
            }),
            ResponseSource::AllowlistedFile(capability) => {
                let declared = usize::try_from(capability.byte_length())
                    .map_err(|_| MutationError::limit("file-length"))?;
                if declared > self.maximum_file_bytes {
                    return Err(MutationError::limit("file-pre-resolve"));
                }
                let resolver = self.file_resolver.as_ref().ok_or(MutationError::new(
                    MutationErrorCode::ProviderUnavailable,
                    "file-capability-resolver",
                ))?;
                let bytes = resolver.resolve_file(capability)?;
                if bytes.len() > self.maximum_file_bytes {
                    return Err(MutationError::limit("file-post-resolve"));
                }
                if u64::try_from(bytes.len()).ok() != Some(capability.byte_length())
                    || Digest32::sha256(bytes.as_bytes()) != capability.digest()
                {
                    return Err(MutationError::new(
                        MutationErrorCode::ProviderUnavailable,
                        "file-capability-integrity",
                    ));
                }
                Ok(ResponseView {
                    source,
                    body: Presence::Present(bytes),
                    raw_headers: missing_headers(),
                    metadata,
                })
            }
        }
    }
}

fn sample_body(
    result: &SampleResult,
    maximum: usize,
) -> Result<Presence<BoundedBytes>, MutationError> {
    match result.response_data() {
        None => Ok(Presence::Missing),
        Some(data) => Ok(Presence::Present(BoundedBytes::try_new(
            data.as_bytes(),
            maximum,
        )?)),
    }
}

fn sample_headers(
    result: &SampleResult,
    maximum: usize,
) -> Result<Presence<BoundedBytes>, MutationError> {
    match result.response_headers() {
        None => Ok(Presence::Missing),
        Some(headers) => Ok(Presence::Present(BoundedBytes::try_new(
            headers.as_bytes(),
            maximum,
        )?)),
    }
}

fn response_metadata(
    result: &SampleResult,
    maximum: usize,
) -> Result<ResponseMetadata, MutationError> {
    let encoding = match result.data_encoding() {
        None => Presence::Missing,
        Some(value) => Presence::Present(BoundedText::try_new(value.as_str(), maximum)?),
    };
    let data_type = match result.data_type() {
        None => Presence::Missing,
        Some(value) => {
            if value.as_wire().len() > maximum {
                return Err(MutationError::limit("response-data-type"));
            }
            Presence::Present(value.clone())
        }
    };
    let media_type = match result.content_type() {
        None => Presence::Missing,
        Some(value) => Presence::Present(BoundedText::try_new(value, maximum)?),
    };
    let response_code = match result.response_code() {
        None => Presence::Missing,
        Some(value) => Presence::Present(BoundedText::try_new(value, maximum)?),
    };
    let response_message = match result.response_message() {
        None => Presence::Missing,
        Some(value) => Presence::Present(BoundedText::try_new(value, maximum)?),
    };
    Ok(ResponseMetadata {
        encoding,
        data_type,
        media_type,
        response_code,
        response_message,
    })
}

/// A bounded raw source value. Unlike [`BoundedText`], this type deliberately
/// accepts controls, line endings, and invalid UTF-8. Response processors see
/// the exact source bytes captured by the sampler; configuration-text rules
/// must not be reused for response data.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BoundedSourceText(Vec<u8>);

impl BoundedSourceText {
    /// Copies source bytes only after checking the caller-supplied bound.
    pub fn try_from_bytes(value: &[u8], maximum: usize) -> Result<Self, MutationError> {
        if maximum == 0 || value.len() > maximum {
            return Err(MutationError::limit("response-source-bytes"));
        }
        Ok(Self(value.to_vec()))
    }

    /// Copies source text without rejecting controls or line endings.
    pub fn try_from_str(value: &str, maximum: usize) -> Result<Self, MutationError> {
        Self::try_from_bytes(value.as_bytes(), maximum)
    }

    /// Creates an empty, present source value.
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    /// Returns the exact source bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the source as UTF-8 when it is valid.
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    /// Returns replacement-decoded text for diagnostics or a provider that
    /// explicitly requests lossy UTF-8 presentation. Raw bytes remain
    /// available through [`Self::as_bytes`].
    pub fn to_string_lossy(&self) -> String {
        String::from_utf8_lossy(&self.0).into_owned()
    }

    /// Returns the number of source bytes.
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether this is present but empty.
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consumes the source value and returns its bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for BoundedSourceText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedSourceText")
            .field("byte_len", &self.0.len())
            .field("is_empty", &self.0.is_empty())
            .field("is_utf8", &std::str::from_utf8(&self.0).is_ok())
            .finish()
    }
}

/// The exact sample-relative scope used by result-dependent processors.
/// `Current` is the parent/default JMeter wire value; it is not an alias for
/// `Subresults` and it never implicitly falls back to a child.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ResponseScope {
    /// The current (parent) sample only.
    Current,
    /// Immediate children of the current sample only.
    Subresults,
    /// The current sample followed by all descendants in depth-first order.
    All,
    /// A variable value, independent of the current sample and target.
    Variable { name: String },
}

impl ResponseScope {
    /// Builds variable scope while retaining the exact variable name.
    pub fn variable(name: impl Into<String>) -> Self {
        Self::Variable { name: name.into() }
    }

    /// Returns the variable name for variable scope.
    pub fn variable_name(&self) -> Option<&str> {
        match self {
            Self::Variable { name } => Some(name),
            Self::Current | Self::Subresults | Self::All => None,
        }
    }
}

/// Closed response target vocabulary. The legacy [`ResponseSource`] remains
/// separate so an old caller cannot silently acquire request-header or
/// provider semantics.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ResponseTarget {
    /// Raw response body bytes.
    Body,
    /// Raw response headers from the captured sample result.
    ResponseHeaders,
    /// Raw request headers from the captured sample result.
    RequestHeaders,
    /// Captured sampler URL text.
    Url,
    /// Captured response code text.
    ResponseCode,
    /// Captured response message text.
    ResponseMessage,
    /// HTML4 unescape through an explicitly negotiated provider.
    BodyUnescapedHtml4,
    /// Document text extraction through an explicitly negotiated provider.
    BodyAsDocumentText,
    /// Bytes supplied by an explicit application file capability.
    AllowlistedFile(FileCapability),
}

impl ResponseTarget {
    /// Builds an explicit file target without consulting result metadata.
    pub const fn allowlisted_file(capability: FileCapability) -> Self {
        Self::AllowlistedFile(capability)
    }

    /// Returns the provider kind required by a transform target.
    pub const fn provider_kind(self) -> Option<ResponseProviderKind> {
        match self {
            Self::BodyUnescapedHtml4 => Some(ResponseProviderKind::Html4Unescape),
            Self::BodyAsDocumentText => Some(ResponseProviderKind::DocumentText),
            Self::Body
            | Self::ResponseHeaders
            | Self::RequestHeaders
            | Self::Url
            | Self::ResponseCode
            | Self::ResponseMessage
            | Self::AllowlistedFile(_) => None,
        }
    }
}

/// Provider identities are explicit data, not inferred from host libraries.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ResponseProviderKind {
    /// HTML4 unescape provider used by the JMeter HTML target.
    Html4Unescape,
    /// Tika/document-text provider used by document extraction.
    DocumentText,
    /// XPath provider request retained for a future registered provider.
    XPath,
    /// JSONPath provider request retained for a future registered provider.
    JsonPath,
    /// JMESPath provider request retained for a future registered provider.
    JmesPath,
    /// A preserved extension/provider identity with no native fallback.
    Unknown(BoundedText),
}

impl ResponseProviderKind {
    /// Returns a stable provider identity.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Html4Unescape => "html4-unescape",
            Self::DocumentText => "document-text",
            Self::XPath => "xpath",
            Self::JsonPath => "jsonpath",
            Self::JmesPath => "jmespath",
            Self::Unknown(value) => value.as_str(),
        }
    }
}

/// A typed request for a provider-backed response transformation. The
/// default runtime never executes one; a bridge/provider adapter must opt in.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ResponseProviderRequest {
    kind: ResponseProviderKind,
    input: BoundedSourceText,
}

impl ResponseProviderRequest {
    /// Creates a bounded provider request.
    pub fn try_new(
        kind: ResponseProviderKind,
        input: BoundedSourceText,
        maximum: usize,
    ) -> Result<Self, MutationError> {
        if maximum == 0 || input.len() > maximum {
            return Err(MutationError::limit("provider-input"));
        }
        Ok(Self { kind, input })
    }

    /// Returns the requested provider identity.
    pub fn kind(&self) -> &ResponseProviderKind {
        &self.kind
    }

    /// Returns the exact bounded provider input.
    pub fn input(&self) -> &BoundedSourceText {
        &self.input
    }
}

impl fmt::Debug for ResponseProviderRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResponseProviderRequest")
            .field("kind", &self.kind)
            .field("input", &self.input)
            .finish()
    }
}

/// An explicitly selected provider. Implementations belong to an application
/// or bridge boundary and must not use ambient filesystem/network access.
pub trait ResponseProvider: Send + Sync {
    /// Executes one typed request or returns an unavailable/typed error.
    fn transform(
        &self,
        request: &ResponseProviderRequest,
    ) -> Result<BoundedSourceText, MutationError>;
}

/// A typed decoder request for an encoding that is not implemented by the
/// executor-neutral core.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ResponseDecodeRequest {
    encoding: BoundedSourceText,
    input: BoundedBytes,
}

impl ResponseDecodeRequest {
    /// Creates a decoder request after checking provider input bounds.
    pub fn try_new(
        encoding: BoundedSourceText,
        input: BoundedBytes,
        maximum: usize,
    ) -> Result<Self, MutationError> {
        if maximum == 0 || input.len() > maximum {
            return Err(MutationError::limit("decoder-input"));
        }
        Ok(Self { encoding, input })
    }

    /// Returns the exact encoding name bytes.
    pub fn encoding(&self) -> &BoundedSourceText {
        &self.encoding
    }

    /// Returns the exact undecoded input bytes.
    pub fn input(&self) -> &BoundedBytes {
        &self.input
    }
}

impl fmt::Debug for ResponseDecodeRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResponseDecodeRequest")
            .field("encoding", &self.encoding)
            .field("input", &self.input)
            .finish()
    }
}

/// An explicitly selected decoder for an otherwise unknown charset.
pub trait ResponseDecoderProvider: Send + Sync {
    /// Decodes one bounded request without host-default fallback.
    fn decode(&self, request: &ResponseDecodeRequest) -> Result<BoundedSourceText, MutationError>;
}

/// Policy controlling how response bytes become provider/source text.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum ResponseDecodePolicy {
    /// Use a nonempty declared encoding, otherwise the explicit default.
    DeclaredOrDefault { default_encoding: String },
    /// Use this exact encoding name and do not inspect result metadata.
    Explicit { encoding: String },
    /// Send this encoding to the explicitly supplied decoder provider.
    Provider { encoding: String },
}

impl Default for ResponseDecodePolicy {
    fn default() -> Self {
        Self::DeclaredOrDefault {
            default_encoding: String::from("UTF-8"),
        }
    }
}

impl ResponseDecodePolicy {
    /// Uses declared encoding or UTF-8 when the declaration is absent/empty.
    pub fn declared_or_utf8() -> Self {
        Self::default()
    }

    /// Uses an explicit encoding name.
    pub fn explicit(encoding: impl Into<String>) -> Self {
        Self::Explicit {
            encoding: encoding.into(),
        }
    }

    /// Routes an encoding through an explicitly configured provider.
    pub fn provider(encoding: impl Into<String>) -> Self {
        Self::Provider {
            encoding: encoding.into(),
        }
    }
}

/// Presence-preserving raw metadata captured from one sample result.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ResponseMetadataRecord {
    /// Declared response encoding, including present-empty.
    pub encoding: Presence<BoundedSourceText>,
    /// JTL data type, retaining unknown wire values.
    pub data_type: Presence<DataType>,
    /// Full content type, including parameters and controls.
    pub media_type: Presence<BoundedSourceText>,
    /// Captured response code.
    pub response_code: Presence<BoundedSourceText>,
    /// Captured response message.
    pub response_message: Presence<BoundedSourceText>,
}

/// Opaque result-file metadata. It is retained for reporting/JTL behavior and
/// has no path-open or input conversion operation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OpaqueResultFileMetadata {
    reference: BoundedSourceText,
}

impl OpaqueResultFileMetadata {
    /// Creates opaque metadata after checking an explicit bound.
    pub fn try_new(value: &[u8], maximum: usize) -> Result<Self, MutationError> {
        Ok(Self {
            reference: BoundedSourceText::try_from_bytes(value, maximum)?,
        })
    }

    /// Returns exact retained reference bytes without resolving them.
    pub fn reference(&self) -> &BoundedSourceText {
        &self.reference
    }
}

/// All response fields needed by result-dependent processors. Raw fields use
/// source bytes so controls, CR/LF, and malformed payload bytes are retained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseRecord {
    /// Response body bytes.
    pub body: Presence<BoundedBytes>,
    /// Captured response headers.
    pub response_headers: Presence<BoundedSourceText>,
    /// Captured request headers.
    pub request_headers: Presence<BoundedSourceText>,
    /// Captured sampler URL text.
    pub url: Presence<BoundedSourceText>,
    /// Captured response code text.
    pub response_code: Presence<BoundedSourceText>,
    /// Captured response message text.
    pub response_message: Presence<BoundedSourceText>,
    /// Other response metadata.
    pub metadata: ResponseMetadataRecord,
    /// Opaque result-file reference metadata.
    pub result_file: Presence<OpaqueResultFileMetadata>,
}

impl ResponseRecord {
    /// Captures one result with independent response limits.
    pub fn try_from_sample_result(
        result: &SampleResult,
        limits: &ResponseLimits,
    ) -> Result<Self, MutationError> {
        limits.validate()?;
        let body = match result.response_data() {
            None => Presence::Missing,
            Some(value) => Presence::Present(BoundedBytes::try_new(
                value.as_bytes(),
                limits.max_body_bytes,
            )?),
        };
        let response_headers = source_presence(
            result.response_headers().map(HeaderBlock::as_bytes),
            limits.response_header_limit(),
            "response-headers",
        )?;
        let request_headers = source_presence(
            result.request_headers().map(HeaderBlock::as_bytes),
            limits.request_header_limit(),
            "request-headers",
        )?;
        let url = source_presence(
            result.url().map(str::as_bytes),
            limits.max_metadata_bytes,
            "url",
        )?;
        let response_code = source_presence(
            result.response_code().map(str::as_bytes),
            limits.max_metadata_bytes,
            "response-code",
        )?;
        let response_message = source_presence(
            result.response_message().map(str::as_bytes),
            limits.max_metadata_bytes,
            "response-message",
        )?;
        let encoding = source_presence(
            result
                .data_encoding()
                .map(|value| value.as_str().as_bytes()),
            limits.max_metadata_bytes,
            "encoding",
        )?;
        let media_type = source_presence(
            result.content_type().map(str::as_bytes),
            limits.max_metadata_bytes,
            "media-type",
        )?;
        let data_type = match result.data_type() {
            None => Presence::Missing,
            Some(value) => {
                if value.as_wire().len() > limits.max_metadata_bytes {
                    return Err(MutationError::limit("data-type"));
                }
                Presence::Present(value.clone())
            }
        };
        let metadata = ResponseMetadataRecord {
            encoding,
            data_type,
            media_type,
            response_code: response_code.clone(),
            response_message: response_message.clone(),
        };
        let metadata_bytes = total_bytes(
            [
                metadata_source_len(&metadata.encoding),
                metadata_source_len(&metadata.media_type),
                metadata_source_len(&metadata.response_code),
                metadata_source_len(&metadata.response_message),
                metadata_data_type_len(&metadata.data_type),
                result
                    .response_file_reference()
                    .map_or(0, |value| value.len()),
            ],
            "response-metadata-bytes",
        )?;
        if metadata_bytes > limits.max_metadata_bytes {
            return Err(MutationError::limit("response-metadata-bytes"));
        }
        let result_file = match result.response_file_reference() {
            None => Presence::Missing,
            Some(value) => Presence::Present(OpaqueResultFileMetadata::try_new(
                value.as_str().as_bytes(),
                limits.max_metadata_bytes,
            )?),
        };
        Ok(Self {
            body,
            response_headers,
            request_headers,
            url,
            response_code,
            response_message,
            metadata,
            result_file,
        })
    }

    /// Alias emphasizing the result boundary.
    pub fn try_from_result(
        result: &SampleResult,
        limits: &ResponseLimits,
    ) -> Result<Self, MutationError> {
        Self::try_from_sample_result(result, limits)
    }

    /// Convenience constructor retaining the checked-result naming used by
    /// callers that do not distinguish `try_from_*` from bounded parsing.
    pub fn from_sample_result(
        result: &SampleResult,
        limits: &ResponseLimits,
    ) -> Result<Self, MutationError> {
        Self::try_from_sample_result(result, limits)
    }

    /// Returns retained opaque result-file metadata.
    pub fn result_file_metadata(&self) -> &Presence<OpaqueResultFileMetadata> {
        &self.result_file
    }

    /// Returns the bounded raw body presence.
    pub fn body(&self) -> &Presence<BoundedBytes> {
        &self.body
    }

    /// Returns the bounded raw response-header presence.
    pub fn response_headers(&self) -> &Presence<BoundedSourceText> {
        &self.response_headers
    }

    /// Returns the bounded raw request-header presence.
    pub fn request_headers(&self) -> &Presence<BoundedSourceText> {
        &self.request_headers
    }

    /// Returns captured response metadata.
    pub fn metadata(&self) -> &ResponseMetadataRecord {
        &self.metadata
    }
}

fn source_presence(
    value: Option<&[u8]>,
    maximum: usize,
    field: &'static str,
) -> Result<Presence<BoundedSourceText>, MutationError> {
    match value {
        None => Ok(Presence::Missing),
        Some(value) => BoundedSourceText::try_from_bytes(value, maximum)
            .map(Presence::Present)
            .map_err(|error| {
                if error.code() == MutationErrorCode::Limit {
                    MutationError::limit(field)
                } else {
                    error
                }
            }),
    }
}

fn metadata_source_len(value: &Presence<BoundedSourceText>) -> usize {
    match value {
        Presence::Missing => 0,
        Presence::Present(value) => value.len(),
    }
}

fn metadata_data_type_len(value: &Presence<DataType>) -> usize {
    match value {
        Presence::Missing => 0,
        Presence::Present(value) => value.as_wire().len(),
    }
}

/// Independent bounds for response selection and provider inputs/outputs.
/// These limits are intentionally separate from [`MutationLimits`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponseLimits {
    /// Maximum raw body bytes per record.
    pub max_body_bytes: usize,
    /// Shared header bound used when target-specific bounds are unchanged.
    pub max_header_bytes: usize,
    /// Maximum response-header bytes per record.
    pub max_response_header_bytes: usize,
    /// Maximum request-header bytes per record.
    pub max_request_header_bytes: usize,
    /// Maximum aggregate metadata bytes per record.
    pub max_metadata_bytes: usize,
    /// Maximum decoded source-text bytes.
    pub max_decoded_bytes: usize,
    /// Maximum variable name/value bytes.
    pub max_variable_bytes: usize,
    /// Maximum selected records in one sample input set.
    pub max_items: usize,
    /// Maximum descendant depth. Root depth is zero; zero permits current only.
    pub max_depth: usize,
    /// Maximum file capability length, checked before resolution.
    pub max_file_bytes: usize,
    /// Maximum bytes sent to a decoder/provider.
    pub max_provider_input_bytes: usize,
    /// Maximum bytes returned by a decoder/provider.
    pub max_provider_output_bytes: usize,
}

/// Named constructor inputs for [`ResponseLimits`]. Keeping this vocabulary
/// separate from [`MutationLimitsParts`] prevents scalar mutation policy from
/// being reused for response input admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponseLimitsParts {
    /// Maximum raw body bytes per record.
    pub max_body_bytes: usize,
    /// Shared header bound.
    pub max_header_bytes: usize,
    /// Maximum response-header bytes.
    pub max_response_header_bytes: usize,
    /// Maximum request-header bytes.
    pub max_request_header_bytes: usize,
    /// Maximum aggregate metadata bytes.
    pub max_metadata_bytes: usize,
    /// Maximum decoded source bytes.
    pub max_decoded_bytes: usize,
    /// Maximum variable bytes.
    pub max_variable_bytes: usize,
    /// Maximum sample input count.
    pub max_items: usize,
    /// Maximum descendant depth.
    pub max_depth: usize,
    /// Maximum explicit file bytes.
    pub max_file_bytes: usize,
    /// Maximum decoder/provider input bytes.
    pub max_provider_input_bytes: usize,
    /// Maximum decoder/provider output bytes.
    pub max_provider_output_bytes: usize,
}

impl Default for ResponseLimits {
    fn default() -> Self {
        Self {
            max_body_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_header_bytes: DEFAULT_MAX_RESPONSE_HEADER_BYTES,
            max_response_header_bytes: DEFAULT_MAX_RESPONSE_HEADER_BYTES,
            max_request_header_bytes: DEFAULT_MAX_RESPONSE_HEADER_BYTES,
            max_metadata_bytes: DEFAULT_MAX_RESPONSE_METADATA_BYTES,
            max_decoded_bytes: DEFAULT_MAX_RESPONSE_DECODED_BYTES,
            max_variable_bytes: DEFAULT_MAX_RESPONSE_VARIABLE_BYTES,
            max_items: DEFAULT_MAX_RESPONSE_ITEMS,
            max_depth: DEFAULT_MAX_RESPONSE_DEPTH,
            max_file_bytes: DEFAULT_MAX_RESPONSE_FILE_BYTES,
            max_provider_input_bytes: DEFAULT_MAX_RESPONSE_PROVIDER_INPUT_BYTES,
            max_provider_output_bytes: DEFAULT_MAX_RESPONSE_PROVIDER_OUTPUT_BYTES,
        }
    }
}

impl ResponseLimits {
    /// Constructs and validates response limits from named inputs.
    pub fn try_new(parts: ResponseLimitsParts) -> Result<Self, MutationError> {
        let value = Self {
            max_body_bytes: parts.max_body_bytes,
            max_header_bytes: parts.max_header_bytes,
            max_response_header_bytes: parts.max_response_header_bytes,
            max_request_header_bytes: parts.max_request_header_bytes,
            max_metadata_bytes: parts.max_metadata_bytes,
            max_decoded_bytes: parts.max_decoded_bytes,
            max_variable_bytes: parts.max_variable_bytes,
            max_items: parts.max_items,
            max_depth: parts.max_depth,
            max_file_bytes: parts.max_file_bytes,
            max_provider_input_bytes: parts.max_provider_input_bytes,
            max_provider_output_bytes: parts.max_provider_output_bytes,
        };
        value.validate().map(|()| value)
    }

    /// Validates every response-specific bound.
    pub fn validate(&self) -> Result<(), MutationError> {
        if self.max_body_bytes == 0
            || self.max_header_bytes == 0
            || self.max_response_header_bytes == 0
            || self.max_request_header_bytes == 0
            || self.max_metadata_bytes == 0
            || self.max_decoded_bytes == 0
            || self.max_variable_bytes == 0
            || self.max_items == 0
            || self.max_file_bytes == 0
            || self.max_provider_input_bytes == 0
            || self.max_provider_output_bytes == 0
        {
            return Err(MutationError::limit("response-limits"));
        }
        Ok(())
    }

    /// Effective response-header limit, honoring both shared and specific
    /// fields so callers can tighten either one without silent widening.
    pub const fn response_header_limit(&self) -> usize {
        min_usize(self.max_header_bytes, self.max_response_header_bytes)
    }

    /// Effective request-header limit.
    pub const fn request_header_limit(&self) -> usize {
        min_usize(self.max_header_bytes, self.max_request_header_bytes)
    }

    /// Returns a copy with a different body bound.
    pub const fn with_body_bytes(mut self, value: usize) -> Self {
        self.max_body_bytes = value;
        self
    }

    /// Returns a copy with a shared header bound.
    pub const fn with_header_bytes(mut self, value: usize) -> Self {
        self.max_header_bytes = value;
        self.max_response_header_bytes = value;
        self.max_request_header_bytes = value;
        self
    }

    /// Returns a copy with a metadata bound.
    pub const fn with_metadata_bytes(mut self, value: usize) -> Self {
        self.max_metadata_bytes = value;
        self
    }

    /// Returns a copy with a decoded-text bound.
    pub const fn with_decoded_bytes(mut self, value: usize) -> Self {
        self.max_decoded_bytes = value;
        self
    }

    /// Returns a copy with a variable bound.
    pub const fn with_variable_bytes(mut self, value: usize) -> Self {
        self.max_variable_bytes = value;
        self
    }

    /// Returns a copy with an item-count bound.
    pub const fn with_items(mut self, value: usize) -> Self {
        self.max_items = value;
        self
    }

    /// Returns a copy with a depth bound.
    pub const fn with_depth(mut self, value: usize) -> Self {
        self.max_depth = value;
        self
    }

    /// Returns a copy with a file bound.
    pub const fn with_file_bytes(mut self, value: usize) -> Self {
        self.max_file_bytes = value;
        self
    }

    /// Returns a copy with provider input/output bounds.
    pub const fn with_provider_bytes(mut self, input: usize, output: usize) -> Self {
        self.max_provider_input_bytes = input;
        self.max_provider_output_bytes = output;
        self
    }
}

const fn min_usize(left: usize, right: usize) -> usize {
    if left < right { left } else { right }
}

/// One sample-relative input and its target projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseInput {
    /// Current or descendant origin, including depth-first path.
    pub origin: ResponseOrigin,
    /// Complete raw record, retained even when a target selects one field.
    pub record: ResponseRecord,
    /// Selected target value; missing remains distinct from present-empty.
    pub selected: Presence<ResponseSelection>,
}

impl ResponseInput {
    /// Returns the target projection.
    pub fn selected(&self) -> &Presence<ResponseSelection> {
        &self.selected
    }

    /// Returns the raw sample record.
    pub fn record(&self) -> &ResponseRecord {
        &self.record
    }
}

/// Stable origin of one selected sample input.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum ResponseOrigin {
    /// The current parent sample.
    Current,
    /// A descendant with zero-based child path and its depth.
    Descendant { depth: usize, path: Vec<usize> },
}

impl ResponseOrigin {
    /// Returns the origin depth.
    pub const fn depth(&self) -> usize {
        match self {
            Self::Current => 0,
            Self::Descendant { depth, .. } => *depth,
        }
    }

    /// Returns the descendant path, or an empty path for current.
    pub fn path(&self) -> &[usize] {
        match self {
            Self::Current => &[],
            Self::Descendant { path, .. } => path,
        }
    }
}

/// A raw record set in target order. Each item retains its complete record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseInputSet {
    target: ResponseTarget,
    items: Vec<ResponseInput>,
}

impl ResponseInputSet {
    fn new(target: ResponseTarget, items: Vec<ResponseInput>) -> Self {
        Self { target, items }
    }

    /// Returns the target used for each item.
    pub const fn target(&self) -> ResponseTarget {
        self.target
    }

    /// Returns items in current-plus-depth-first order.
    pub fn items(&self) -> &[ResponseInput] {
        &self.items
    }

    /// Alias for callers that describe this as records.
    pub fn records(&self) -> &[ResponseInput] {
        &self.items
    }

    /// Returns the number of selected records.
    pub const fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns whether the set is empty.
    pub const fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Iterates selected inputs without exposing mutable state.
    pub fn iter(&self) -> std::slice::Iter<'_, ResponseInput> {
        self.items.iter()
    }

    /// Consumes the set while retaining its explicit target ordering.
    pub fn into_items(self) -> Vec<ResponseInput> {
        self.items
    }
}

/// Result of a scope/target resolution. No current result is not an empty
/// response, and variable scope never manufactures a sample input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResponseResolution {
    /// The caller supplied no current result for a sample scope.
    NoCurrentResult,
    /// A variable value, bypassing sample target selection.
    Variable(Presence<BoundedSourceText>),
    /// Current/children/all sample inputs.
    Samples(ResponseInputSet),
}

impl ResponseResolution {
    /// Returns true only for no-current-result.
    pub const fn is_no_current_result(&self) -> bool {
        matches!(self, Self::NoCurrentResult)
    }

    /// Returns sample inputs when this is a sample scope.
    pub fn samples(&self) -> Option<&ResponseInputSet> {
        match self {
            Self::Samples(value) => Some(value),
            Self::NoCurrentResult | Self::Variable(_) => None,
        }
    }

    /// Returns variable presence when this is variable scope.
    pub fn variable(&self) -> Option<&Presence<BoundedSourceText>> {
        match self {
            Self::Variable(value) => Some(value),
            Self::NoCurrentResult | Self::Samples(_) => None,
        }
    }
}

/// Resolver for scoped response records and target projections. It has no
/// filesystem/network access; every external operation is an injected,
/// explicitly selected capability.
#[derive(Clone)]
pub struct ResponseInputSetResolver {
    limits: ResponseLimits,
    file_resolver: Option<Arc<dyn AllowlistedFileResolver>>,
    decoder_provider: Option<Arc<dyn ResponseDecoderProvider>>,
    provider: Option<Arc<dyn ResponseProvider>>,
}

impl fmt::Debug for ResponseInputSetResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResponseInputSetResolver")
            .field("limits", &self.limits)
            .field("file_capability_enabled", &self.file_resolver.is_some())
            .field("decoder_provider_enabled", &self.decoder_provider.is_some())
            .field("provider_enabled", &self.provider.is_some())
            .finish()
    }
}

impl Default for ResponseInputSetResolver {
    fn default() -> Self {
        Self::new(ResponseLimits::default()).unwrap_or_else(|_| Self {
            limits: ResponseLimits::default(),
            file_resolver: None,
            decoder_provider: None,
            provider: None,
        })
    }
}

impl ResponseInputSetResolver {
    /// Creates a resolver with independent response limits.
    pub fn new(limits: ResponseLimits) -> Result<Self, MutationError> {
        limits.validate()?;
        Ok(Self {
            limits,
            file_resolver: None,
            decoder_provider: None,
            provider: None,
        })
    }

    /// Returns the response limits in force.
    pub const fn limits(&self) -> ResponseLimits {
        self.limits
    }

    /// Injects the explicit file capability resolver.
    pub fn with_file_resolver(mut self, resolver: Arc<dyn AllowlistedFileResolver>) -> Self {
        self.file_resolver = Some(resolver);
        self
    }

    /// Injects an explicit unknown-encoding provider.
    pub fn with_decoder_provider(mut self, provider: Arc<dyn ResponseDecoderProvider>) -> Self {
        self.decoder_provider = Some(provider);
        self
    }

    /// Injects an explicit HTML/document/provider transform.
    pub fn with_provider(mut self, provider: Arc<dyn ResponseProvider>) -> Self {
        self.provider = Some(provider);
        self
    }

    /// Builds a typed provider request without executing it. This is the
    /// bridge/admission seam for HTML4/document/XPath/JSON providers; unknown
    /// or unavailable providers never fall back to a host parser.
    pub fn provider_request(
        &self,
        record: &ResponseRecord,
        target: ResponseTarget,
        decode_policy: &ResponseDecodePolicy,
    ) -> Result<Presence<ResponseProviderRequest>, MutationError> {
        let kind = target
            .provider_kind()
            .ok_or(MutationError::invalid("provider-target"))?;
        let body = match &record.body {
            Presence::Missing => return Ok(Presence::Missing),
            Presence::Present(value) => value,
        };
        let decoded = self.decode_body(record, body, decode_policy)?;
        Ok(Presence::Present(ResponseProviderRequest::try_new(
            kind,
            decoded,
            self.limits.max_provider_input_bytes,
        )?))
    }

    /// Resolves one scope, target, and decode policy against captured result
    /// data and an explicit variable map.
    pub fn resolve(
        &self,
        current: Option<&SampleResult>,
        variables: &BTreeMap<String, String>,
        scope: &ResponseScope,
        target: ResponseTarget,
        decode_policy: &ResponseDecodePolicy,
    ) -> Result<ResponseResolution, MutationError> {
        self.resolve_scoped(current, variables, scope, target, decode_policy)
    }

    /// Alias with the scope terminology used by the decision record.
    pub fn resolve_scoped(
        &self,
        current: Option<&SampleResult>,
        variables: &BTreeMap<String, String>,
        scope: &ResponseScope,
        target: ResponseTarget,
        decode_policy: &ResponseDecodePolicy,
    ) -> Result<ResponseResolution, MutationError> {
        if let ResponseScope::Variable { name } = scope {
            if name.len() > self.limits.max_variable_bytes {
                return Err(MutationError::limit("variable-name"));
            }
            return match variables.get(name) {
                None => Ok(ResponseResolution::Variable(Presence::Missing)),
                Some(value) => {
                    if value.len() > self.limits.max_variable_bytes {
                        return Err(MutationError::limit("variable-value"));
                    }
                    Ok(ResponseResolution::Variable(Presence::Present(
                        BoundedSourceText::try_from_str(value, self.limits.max_variable_bytes)?,
                    )))
                }
            };
        }
        let current = match current {
            None => return Ok(ResponseResolution::NoCurrentResult),
            Some(value) => value,
        };
        let origins = self.collect_origins(current, scope)?;
        let mut items = Vec::with_capacity(origins.len());
        for (origin, result) in origins {
            let record = ResponseRecord::try_from_sample_result(result, &self.limits)?;
            let selected = self.select_target(&record, target, decode_policy)?;
            items.push(ResponseInput {
                origin,
                record,
                selected,
            });
        }
        Ok(ResponseResolution::Samples(ResponseInputSet::new(
            target, items,
        )))
    }

    fn collect_origins<'a>(
        &self,
        current: &'a SampleResult,
        scope: &ResponseScope,
    ) -> Result<Vec<(ResponseOrigin, &'a SampleResult)>, MutationError> {
        let mut values = Vec::new();
        match scope {
            ResponseScope::Current => {
                values.push((ResponseOrigin::Current, current));
            }
            ResponseScope::Subresults => {
                for (index, child) in current.sub_results().iter().enumerate() {
                    self.check_depth(1)?;
                    self.push_origin(
                        &mut values,
                        ResponseOrigin::Descendant {
                            depth: 1,
                            path: vec![index],
                        },
                        child,
                    )?;
                }
            }
            ResponseScope::All => {
                values.push((ResponseOrigin::Current, current));
                let mut path = Vec::new();
                self.collect_descendants(current, &mut path, 0, &mut values)?;
            }
            ResponseScope::Variable { .. } => {}
        }
        Ok(values)
    }

    fn collect_descendants<'a>(
        &self,
        result: &'a SampleResult,
        path: &mut Vec<usize>,
        depth: usize,
        values: &mut Vec<(ResponseOrigin, &'a SampleResult)>,
    ) -> Result<(), MutationError> {
        for (index, child) in result.sub_results().iter().enumerate() {
            let next_depth = depth
                .checked_add(1)
                .ok_or(MutationError::overflow("response-depth"))?;
            self.check_depth(next_depth)?;
            path.push(index);
            self.push_origin(
                values,
                ResponseOrigin::Descendant {
                    depth: next_depth,
                    path: path.clone(),
                },
                child,
            )?;
            self.collect_descendants(child, path, next_depth, values)?;
            path.pop();
        }
        Ok(())
    }

    fn check_depth(&self, depth: usize) -> Result<(), MutationError> {
        if depth > self.limits.max_depth {
            return Err(MutationError::limit("response-depth"));
        }
        Ok(())
    }

    fn push_origin<'a>(
        &self,
        values: &mut Vec<(ResponseOrigin, &'a SampleResult)>,
        origin: ResponseOrigin,
        result: &'a SampleResult,
    ) -> Result<(), MutationError> {
        if values.len() >= self.limits.max_items {
            return Err(MutationError::limit("response-items"));
        }
        values.push((origin, result));
        Ok(())
    }

    fn select_target(
        &self,
        record: &ResponseRecord,
        target: ResponseTarget,
        decode_policy: &ResponseDecodePolicy,
    ) -> Result<Presence<ResponseSelection>, MutationError> {
        match target {
            ResponseTarget::Body => Ok(record
                .body
                .as_ref()
                .map(|value| ResponseSelection::Bytes(value.clone()))),
            ResponseTarget::ResponseHeaders => Ok(record
                .response_headers
                .as_ref()
                .map(|value| ResponseSelection::SourceText(value.clone()))),
            ResponseTarget::RequestHeaders => Ok(record
                .request_headers
                .as_ref()
                .map(|value| ResponseSelection::SourceText(value.clone()))),
            ResponseTarget::Url => Ok(record
                .url
                .as_ref()
                .map(|value| ResponseSelection::SourceText(value.clone()))),
            ResponseTarget::ResponseCode => Ok(record
                .response_code
                .as_ref()
                .map(|value| ResponseSelection::SourceText(value.clone()))),
            ResponseTarget::ResponseMessage => Ok(record
                .response_message
                .as_ref()
                .map(|value| ResponseSelection::SourceText(value.clone()))),
            ResponseTarget::BodyUnescapedHtml4 | ResponseTarget::BodyAsDocumentText => {
                let request = match self.provider_request(record, target, decode_policy)? {
                    Presence::Missing => return Ok(Presence::Missing),
                    Presence::Present(value) => value,
                };
                let provider = self.provider.as_ref().ok_or(MutationError::new(
                    MutationErrorCode::ProviderUnavailable,
                    "response-provider",
                ))?;
                let output = provider.transform(&request)?;
                if output.len() > self.limits.max_provider_output_bytes {
                    return Err(MutationError::limit("provider-output"));
                }
                Ok(Presence::Present(ResponseSelection::SourceText(output)))
            }
            ResponseTarget::AllowlistedFile(capability) => {
                let declared = usize::try_from(capability.byte_length())
                    .map_err(|_| MutationError::limit("file-length"))?;
                if declared > self.limits.max_file_bytes {
                    return Err(MutationError::limit("file-pre-resolve"));
                }
                let resolver = self.file_resolver.as_ref().ok_or(MutationError::new(
                    MutationErrorCode::ProviderUnavailable,
                    "file-capability-resolver",
                ))?;
                let bytes = resolver.resolve_file(capability)?;
                if bytes.len() > self.limits.max_file_bytes {
                    return Err(MutationError::limit("file-post-resolve"));
                }
                if u64::try_from(bytes.len()).ok() != Some(capability.byte_length()) {
                    return Err(MutationError::new(
                        MutationErrorCode::ProviderUnavailable,
                        "file-capability-length",
                    ));
                }
                if Digest32::sha256(bytes.as_bytes()) != capability.digest() {
                    return Err(MutationError::new(
                        MutationErrorCode::ProviderUnavailable,
                        "file-capability-integrity",
                    ));
                }
                Ok(Presence::Present(ResponseSelection::Bytes(bytes)))
            }
        }
    }

    fn decode_body(
        &self,
        record: &ResponseRecord,
        body: &BoundedBytes,
        policy: &ResponseDecodePolicy,
    ) -> Result<BoundedSourceText, MutationError> {
        if body.len() > self.limits.max_provider_input_bytes {
            return Err(MutationError::limit("decoder-input"));
        }
        let encoding = match policy {
            ResponseDecodePolicy::DeclaredOrDefault { default_encoding } => {
                match &record.metadata.encoding {
                    Presence::Present(value) if !value.is_empty() => value.to_string_lossy(),
                    Presence::Missing | Presence::Present(_) => default_encoding.clone(),
                }
            }
            ResponseDecodePolicy::Explicit { encoding }
            | ResponseDecodePolicy::Provider { encoding } => encoding.clone(),
        };
        let encoding_source =
            BoundedSourceText::try_from_str(&encoding, self.limits.max_metadata_bytes)?;
        if matches!(policy, ResponseDecodePolicy::Provider { .. }) {
            return self.decode_with_provider(encoding_source, body);
        }
        let normalized = encoding.to_ascii_lowercase();
        match normalized.trim() {
            "utf-8" | "utf8" => {
                decode_utf8_replacement(body.as_bytes(), self.limits.max_decoded_bytes)
            }
            "us-ascii" | "ascii" => {
                decode_ascii_replacement(body.as_bytes(), self.limits.max_decoded_bytes)
            }
            "iso-8859-1" | "iso8859-1" | "latin1" | "latin-1" => {
                decode_latin1(body.as_bytes(), self.limits.max_decoded_bytes)
            }
            "utf-16" | "utf16" | "utf-16le" | "utf16le" | "utf-16be" | "utf16be" => decode_utf16(
                body.as_bytes(),
                normalized.trim(),
                self.limits.max_decoded_bytes,
            ),
            _ => {
                let provider = self.decoder_provider.as_ref().ok_or(MutationError::new(
                    MutationErrorCode::ProviderUnavailable,
                    "encoding-provider",
                ))?;
                let request = ResponseDecodeRequest::try_new(
                    encoding_source,
                    body.clone(),
                    self.limits.max_provider_input_bytes,
                )?;
                let output = provider.decode(&request)?;
                if output.len() > self.limits.max_decoded_bytes {
                    return Err(MutationError::limit("decoded-bytes"));
                }
                Ok(output)
            }
        }
    }

    fn decode_with_provider(
        &self,
        encoding: BoundedSourceText,
        body: &BoundedBytes,
    ) -> Result<BoundedSourceText, MutationError> {
        let provider = self.decoder_provider.as_ref().ok_or(MutationError::new(
            MutationErrorCode::ProviderUnavailable,
            "encoding-provider",
        ))?;
        let request = ResponseDecodeRequest::try_new(
            encoding,
            body.clone(),
            self.limits.max_provider_input_bytes,
        )?;
        let output = provider.decode(&request)?;
        if output.len() > self.limits.max_decoded_bytes {
            return Err(MutationError::limit("decoded-bytes"));
        }
        Ok(output)
    }
}

/// Descriptive aliases for callers that name this capability by selection or
/// scope rather than by its bounded input-set representation.
pub type ResponseSelectionResolver = ResponseInputSetResolver;
pub type ScopedResponseInputResolver = ResponseInputSetResolver;

/// Trait projection for applications that keep the concrete resolver behind
/// a capability object.
pub trait ScopedResponseResolver: Send + Sync {
    /// Resolves a scoped response without granting ambient I/O.
    fn resolve_scoped(
        &self,
        current: Option<&SampleResult>,
        variables: &BTreeMap<String, String>,
        scope: &ResponseScope,
        target: ResponseTarget,
        decode_policy: &ResponseDecodePolicy,
    ) -> Result<ResponseResolution, MutationError>;
}

impl ScopedResponseResolver for ResponseInputSetResolver {
    fn resolve_scoped(
        &self,
        current: Option<&SampleResult>,
        variables: &BTreeMap<String, String>,
        scope: &ResponseScope,
        target: ResponseTarget,
        decode_policy: &ResponseDecodePolicy,
    ) -> Result<ResponseResolution, MutationError> {
        ResponseInputSetResolver::resolve_scoped(
            self,
            current,
            variables,
            scope,
            target,
            decode_policy,
        )
    }
}

/// A target projection selected for one response input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResponseSelection {
    /// Raw bytes (body or explicitly authorized file).
    Bytes(BoundedBytes),
    /// Raw source text (headers, URL, code, message, or provider output).
    SourceText(BoundedSourceText),
}

impl ResponseSelection {
    /// Returns raw bytes for byte selections.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(value) => Some(value.as_bytes()),
            Self::SourceText(_) => None,
        }
    }

    /// Returns source text for source selections.
    pub fn as_source_text(&self) -> Option<&BoundedSourceText> {
        match self {
            Self::Bytes(_) => None,
            Self::SourceText(value) => Some(value),
        }
    }
}

fn push_decoded_char(
    output: &mut Vec<u8>,
    value: char,
    maximum: usize,
    field: &'static str,
) -> Result<(), MutationError> {
    let mut encoded = [0_u8; 4];
    let bytes = value.encode_utf8(&mut encoded).as_bytes();
    let next = output
        .len()
        .checked_add(bytes.len())
        .ok_or(MutationError::overflow(field))?;
    if next > maximum {
        return Err(MutationError::limit(field));
    }
    output.extend_from_slice(bytes);
    Ok(())
}

fn decode_utf8_replacement(
    input: &[u8],
    maximum: usize,
) -> Result<BoundedSourceText, MutationError> {
    let mut output = Vec::with_capacity(maximum.min(input.len()));
    let mut offset = 0;
    while offset < input.len() {
        match std::str::from_utf8(&input[offset..]) {
            Ok(value) => {
                let next = output
                    .len()
                    .checked_add(value.len())
                    .ok_or(MutationError::overflow("decoded-bytes"))?;
                if next > maximum {
                    return Err(MutationError::limit("decoded-bytes"));
                }
                output.extend_from_slice(value.as_bytes());
                break;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                if valid != 0 {
                    let next = output
                        .len()
                        .checked_add(valid)
                        .ok_or(MutationError::overflow("decoded-bytes"))?;
                    if next > maximum {
                        return Err(MutationError::limit("decoded-bytes"));
                    }
                    output.extend_from_slice(&input[offset..offset + valid]);
                }
                push_decoded_char(&mut output, '\u{fffd}', maximum, "decoded-bytes")?;
                let invalid_len = error.error_len().unwrap_or(input.len() - offset - valid);
                offset = offset
                    .checked_add(valid)
                    .and_then(|value| value.checked_add(invalid_len))
                    .ok_or(MutationError::overflow("decoded-offset"))?;
            }
        }
    }
    Ok(BoundedSourceText(output))
}

fn decode_ascii_replacement(
    input: &[u8],
    maximum: usize,
) -> Result<BoundedSourceText, MutationError> {
    let mut output = Vec::with_capacity(maximum.min(input.len()));
    for value in input {
        push_decoded_char(
            &mut output,
            if *value < 0x80 {
                char::from(*value)
            } else {
                '\u{fffd}'
            },
            maximum,
            "decoded-bytes",
        )?;
    }
    Ok(BoundedSourceText(output))
}

fn decode_latin1(input: &[u8], maximum: usize) -> Result<BoundedSourceText, MutationError> {
    let mut output = Vec::with_capacity(maximum.min(input.len()));
    for value in input {
        push_decoded_char(
            &mut output,
            char::from_u32(u32::from(*value)).unwrap_or('\u{fffd}'),
            maximum,
            "decoded-bytes",
        )?;
    }
    Ok(BoundedSourceText(output))
}

fn decode_utf16(
    input: &[u8],
    normalized_encoding: &str,
    maximum: usize,
) -> Result<BoundedSourceText, MutationError> {
    let mut output = Vec::with_capacity(maximum.min(input.len()));
    let mut bytes = input;
    let mut little_endian = match normalized_encoding {
        "utf-16le" | "utf16le" => true,
        "utf-16be" | "utf16be" => false,
        _ => false,
    };
    if matches!(normalized_encoding, "utf-16" | "utf16") {
        if bytes.len() >= 2 && bytes[0] == 0xff && bytes[1] == 0xfe {
            little_endian = true;
            bytes = &bytes[2..];
        } else if bytes.len() >= 2 && bytes[0] == 0xfe && bytes[1] == 0xff {
            bytes = &bytes[2..];
        }
    }
    let mut index = 0;
    while index + 1 < bytes.len() {
        let first = if little_endian {
            u16::from_le_bytes([bytes[index], bytes[index + 1]])
        } else {
            u16::from_be_bytes([bytes[index], bytes[index + 1]])
        };
        index += 2;
        let character = if (0xd800..=0xdbff).contains(&first) {
            if index + 1 < bytes.len() {
                let second = if little_endian {
                    u16::from_le_bytes([bytes[index], bytes[index + 1]])
                } else {
                    u16::from_be_bytes([bytes[index], bytes[index + 1]])
                };
                if (0xdc00..=0xdfff).contains(&second) {
                    index += 2;
                    let high = u32::from(first) - 0xd800;
                    let low = u32::from(second) - 0xdc00;
                    char::from_u32(0x1_0000 + (high << 10) + low).unwrap_or('\u{fffd}')
                } else {
                    '\u{fffd}'
                }
            } else {
                '\u{fffd}'
            }
        } else if (0xdc00..=0xdfff).contains(&first) {
            '\u{fffd}'
        } else {
            char::from_u32(u32::from(first)).unwrap_or('\u{fffd}')
        };
        push_decoded_char(&mut output, character, maximum, "decoded-bytes")?;
    }
    if index < bytes.len() {
        push_decoded_char(&mut output, '\u{fffd}', maximum, "decoded-bytes")?;
    }
    Ok(BoundedSourceText(output))
}

/// A checked, nonzero invocation/context generation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContextGeneration(NonZeroU64);

impl ContextGeneration {
    pub const FIRST: Self = Self(NonZeroU64::MIN);

    pub fn try_new(value: u64) -> Result<Self, MutationError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(MutationError::invalid("context-generation"))
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }

    pub const fn checked_next(self) -> Option<Self> {
        match self.0.get().checked_add(1) {
            Some(value) => match NonZeroU64::new(value) {
                Some(value) => Some(Self(value)),
                None => None,
            },
            None => None,
        }
    }
}

impl Default for ContextGeneration {
    fn default() -> Self {
        Self::FIRST
    }
}

pub type InvocationGeneration = ContextGeneration;

/// A checked, nonzero generation owned by typed request state.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RequestGeneration(NonZeroU64);

impl RequestGeneration {
    pub const FIRST: Self = Self(NonZeroU64::MIN);

    pub fn try_new(value: u64) -> Result<Self, MutationError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(MutationError::invalid("request-generation"))
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }

    pub const fn checked_next(self) -> Option<Self> {
        match self.0.get().checked_add(1) {
            Some(value) => match NonZeroU64::new(value) {
                Some(value) => Some(Self(value)),
                None => None,
            },
            None => None,
        }
    }
}

impl Default for RequestGeneration {
    fn default() -> Self {
        Self::FIRST
    }
}

pub type RequestDigest = Digest32;

/// A raw/encoded field retaining both values and each value's presence.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EncodedField {
    pub raw: Presence<BoundedText>,
    pub encoded: Presence<BoundedText>,
}

impl EncodedField {
    pub fn try_new(
        raw: Presence<BoundedText>,
        encoded: Presence<BoundedText>,
    ) -> Result<Self, MutationError> {
        validate_text_presence(&raw, DEFAULT_MAX_VALUE_BYTES, "request-raw")?;
        validate_text_presence(&encoded, DEFAULT_MAX_VALUE_BYTES, "request-encoded")?;
        if raw.is_missing() && encoded.is_missing() {
            return Err(MutationError::invalid("request-field-presence"));
        }
        Ok(Self { raw, encoded })
    }

    pub fn raw(value: impl Into<String>) -> Result<Self, MutationError> {
        Ok(Self {
            raw: Presence::Present(BoundedText::try_new(value, DEFAULT_MAX_VALUE_BYTES)?),
            encoded: Presence::Missing,
        })
    }

    pub fn encoded(value: impl Into<String>) -> Result<Self, MutationError> {
        Ok(Self {
            raw: Presence::Missing,
            encoded: Presence::Present(BoundedText::try_new(value, DEFAULT_MAX_VALUE_BYTES)?),
        })
    }
}

/// One ordered query field.  A missing value (`flag`) differs from a present
/// empty value (`flag=`).
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct QueryField {
    pub name: EncodedField,
    pub value: Presence<EncodedField>,
}

impl QueryField {
    pub fn try_new(
        name: EncodedField,
        value: Presence<EncodedField>,
    ) -> Result<Self, MutationError> {
        validate_encoded_field(&name, "query-name")?;
        if let Presence::Present(value) = &value {
            validate_encoded_field(value, "query-value")?;
        }
        Ok(Self { name, value })
    }
}

/// Typed request authority.  A port is optional but, when present, nonzero.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RequestAuthority {
    pub host: BoundedText,
    pub port: Option<NonZeroU16>,
}

impl RequestAuthority {
    pub fn try_new(host: impl Into<String>, port: Option<u16>) -> Result<Self, MutationError> {
        let host = BoundedText::try_new(host, DEFAULT_MAX_VALUE_BYTES)?;
        if host.is_empty() {
            return Err(MutationError::invalid("request-host"));
        }
        let port = match port {
            None => None,
            Some(port) => {
                Some(NonZeroU16::new(port).ok_or(MutationError::invalid("request-port"))?)
            }
        };
        Ok(Self { host, port })
    }
}

/// One ordered request header.  Duplicate names are retained.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RequestHeader {
    pub name: BoundedText,
    pub value: BoundedText,
}

impl RequestHeader {
    pub fn try_new(
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, MutationError> {
        let name = BoundedText::try_new(name, DEFAULT_MAX_VALUE_BYTES)?;
        if name.is_empty() {
            return Err(MutationError::invalid("request-header-name"));
        }
        Ok(Self {
            name,
            value: BoundedText::try_new(value, DEFAULT_MAX_VALUE_BYTES)?,
        })
    }
}

/// An ordered add/remove request-header operation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HeaderOperation {
    Add(RequestHeader),
    Remove {
        name: BoundedText,
        value: Presence<BoundedText>,
    },
}

impl HeaderOperation {
    pub fn add(name: impl Into<String>, value: impl Into<String>) -> Result<Self, MutationError> {
        Ok(Self::Add(RequestHeader::try_new(name, value)?))
    }

    pub fn remove(name: impl Into<String>) -> Result<Self, MutationError> {
        let name = BoundedText::try_new(name, DEFAULT_MAX_VALUE_BYTES)?;
        if name.is_empty() {
            return Err(MutationError::invalid("request-header-name"));
        }
        Ok(Self::Remove {
            name,
            value: Presence::Missing,
        })
    }

    pub fn remove_exact(
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, MutationError> {
        let name = BoundedText::try_new(name, DEFAULT_MAX_VALUE_BYTES)?;
        if name.is_empty() {
            return Err(MutationError::invalid("request-header-name"));
        }
        Ok(Self::Remove {
            name,
            value: Presence::Present(BoundedText::try_new(value, DEFAULT_MAX_VALUE_BYTES)?),
        })
    }
}

/// A validated request state with no stringly URL replacement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestState {
    generation: RequestGeneration,
    scheme: Presence<BoundedText>,
    authority: Presence<RequestAuthority>,
    path_segments: Vec<EncodedField>,
    query_fields: Vec<QueryField>,
    method: Presence<BoundedText>,
    body: Presence<BoundedBytes>,
    headers: Vec<RequestHeader>,
}

/// Typed fields used to construct a request state without positional URL
/// arguments.  Keeping the fields named makes raw/encoded and presence
/// distinctions visible at the call site.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestStateParts {
    pub scheme: Presence<BoundedText>,
    pub authority: Presence<RequestAuthority>,
    pub path_segments: Vec<EncodedField>,
    pub query_fields: Vec<QueryField>,
    pub method: Presence<BoundedText>,
    pub body: Presence<BoundedBytes>,
    pub headers: Vec<RequestHeader>,
}

impl Default for RequestState {
    fn default() -> Self {
        Self {
            generation: RequestGeneration::FIRST,
            scheme: Presence::Missing,
            authority: Presence::Missing,
            path_segments: Vec::new(),
            query_fields: Vec::new(),
            method: Presence::Missing,
            body: Presence::Missing,
            headers: Vec::new(),
        }
    }
}

impl RequestState {
    pub fn new(
        generation: RequestGeneration,
        scheme: impl Into<String>,
        host: impl Into<String>,
        port: Option<u16>,
        method: impl Into<String>,
    ) -> Result<Self, MutationError> {
        Self::try_from_parts(
            generation,
            RequestStateParts {
                scheme: Presence::Present(BoundedText::try_new(scheme, DEFAULT_MAX_VALUE_BYTES)?),
                authority: Presence::Present(RequestAuthority::try_new(host, port)?),
                path_segments: Vec::new(),
                query_fields: Vec::new(),
                method: Presence::Present(BoundedText::try_new(method, DEFAULT_MAX_VALUE_BYTES)?),
                body: Presence::Missing,
                headers: Vec::new(),
            },
        )
    }

    pub fn try_from_parts(
        generation: RequestGeneration,
        parts: RequestStateParts,
    ) -> Result<Self, MutationError> {
        let state = Self {
            generation,
            scheme: parts.scheme,
            authority: parts.authority,
            path_segments: parts.path_segments,
            query_fields: parts.query_fields,
            method: parts.method,
            body: parts.body,
            headers: parts.headers,
        };
        state.validate().map(|()| state)
    }

    pub fn generation(&self) -> RequestGeneration {
        self.generation
    }

    pub fn scheme(&self) -> &Presence<BoundedText> {
        &self.scheme
    }

    pub fn authority(&self) -> &Presence<RequestAuthority> {
        &self.authority
    }

    pub fn path_segments(&self) -> &[EncodedField] {
        &self.path_segments
    }

    pub fn query_fields(&self) -> &[QueryField] {
        &self.query_fields
    }

    pub fn method(&self) -> &Presence<BoundedText> {
        &self.method
    }

    pub fn body(&self) -> &Presence<BoundedBytes> {
        &self.body
    }

    pub fn headers(&self) -> &[RequestHeader] {
        &self.headers
    }

    pub fn digest(&self) -> RequestDigest {
        Digest32::sha256(&canonical_request_bytes(self))
    }

    fn canonical_len(&self) -> usize {
        canonical_request_bytes(self).len()
    }

    pub fn validate(&self) -> Result<(), MutationError> {
        validate_text_presence(&self.scheme, DEFAULT_MAX_VALUE_BYTES, "request-scheme")?;
        if let Presence::Present(authority) = &self.authority
            && authority.host.is_empty()
        {
            return Err(MutationError::invalid("request-host"));
        }
        validate_text_presence(&self.method, DEFAULT_MAX_VALUE_BYTES, "request-method")?;
        if let Presence::Present(body) = &self.body
            && body.len() > DEFAULT_MAX_RESPONSE_BYTES
        {
            return Err(MutationError::limit("request-body"));
        }
        if self.path_segments.len() > DEFAULT_MAX_REQUEST_PATH_SEGMENTS {
            return Err(MutationError::limit("request-path-count"));
        }
        if self.query_fields.len() > DEFAULT_MAX_REQUEST_QUERY_FIELDS {
            return Err(MutationError::limit("request-query-count"));
        }
        if self.headers.len() > DEFAULT_MAX_REQUEST_HEADERS {
            return Err(MutationError::limit("request-header-count"));
        }
        for segment in &self.path_segments {
            validate_encoded_field(segment, "request-path")?;
        }
        for query in &self.query_fields {
            QueryField::try_new(query.name.clone(), query.value.clone())?;
        }
        for header in &self.headers {
            if header.name.is_empty() {
                return Err(MutationError::invalid("request-header-name"));
            }
        }
        if self.canonical_len() > DEFAULT_MAX_REQUEST_BYTES {
            return Err(MutationError::limit("request-canonical-bytes"));
        }
        Ok(())
    }

    pub fn apply_patch(&self, patch: &RequestPatch) -> Result<Self, MutationError> {
        patch.validate()?;
        if self.generation != patch.base_generation {
            return Err(MutationError::new(
                MutationErrorCode::StaleGeneration,
                "request-base-generation",
            ));
        }
        if self.digest() != patch.base_digest {
            return Err(MutationError::new(
                MutationErrorCode::StaleDigest,
                "request-base-digest",
            ));
        }
        let generation = self
            .generation
            .checked_next()
            .ok_or(MutationError::overflow("request-generation"))?;
        let mut candidate = self.clone();
        candidate.generation = generation;
        if let Some(value) = &patch.scheme {
            candidate.scheme = value.clone();
        }
        if let Some(value) = &patch.authority {
            candidate.authority = value.clone();
        }
        if let Some(value) = &patch.path_segments {
            candidate.path_segments = value.clone();
        }
        if let Some(value) = &patch.query_fields {
            candidate.query_fields = value.clone();
        }
        if let Some(value) = &patch.method {
            candidate.method = value.clone();
        }
        if let Some(value) = &patch.body {
            candidate.body = value.clone();
        }
        for operation in &patch.header_operations {
            apply_header_operation(&mut candidate.headers, operation)?;
        }
        candidate.validate()?;
        Ok(candidate)
    }
}

/// Typed request replacement operations bound to an exact base generation and
/// digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestPatch {
    base_generation: RequestGeneration,
    base_digest: RequestDigest,
    scheme: Option<Presence<BoundedText>>,
    authority: Option<Presence<RequestAuthority>>,
    path_segments: Option<Vec<EncodedField>>,
    query_fields: Option<Vec<QueryField>>,
    method: Option<Presence<BoundedText>>,
    body: Option<Presence<BoundedBytes>>,
    header_operations: Vec<HeaderOperation>,
}

impl RequestPatch {
    pub fn new(base_generation: RequestGeneration, base_digest: RequestDigest) -> Self {
        Self {
            base_generation,
            base_digest,
            scheme: None,
            authority: None,
            path_segments: None,
            query_fields: None,
            method: None,
            body: None,
            header_operations: Vec::new(),
        }
    }

    pub fn base_generation(&self) -> RequestGeneration {
        self.base_generation
    }

    pub fn base_digest(&self) -> RequestDigest {
        self.base_digest
    }

    pub fn set_scheme(&mut self, value: Presence<BoundedText>) {
        self.scheme = Some(value);
    }

    pub fn set_authority(&mut self, value: Presence<RequestAuthority>) {
        self.authority = Some(value);
    }

    pub fn replace_path_segments(&mut self, value: Vec<EncodedField>) {
        self.path_segments = Some(value);
    }

    pub fn replace_query_fields(&mut self, value: Vec<QueryField>) {
        self.query_fields = Some(value);
    }

    pub fn set_method(&mut self, value: Presence<BoundedText>) {
        self.method = Some(value);
    }

    pub fn set_body(&mut self, value: Presence<BoundedBytes>) {
        self.body = Some(value);
    }

    pub fn add_header_operation(
        &mut self,
        operation: HeaderOperation,
    ) -> Result<(), MutationError> {
        let next = self
            .header_operations
            .len()
            .checked_add(1)
            .ok_or(MutationError::overflow("request-header-operations"))?;
        if next > DEFAULT_MAX_REQUEST_HEADERS {
            return Err(MutationError::limit("request-header-operations"));
        }
        self.header_operations.push(operation);
        Ok(())
    }

    pub fn header_operations(&self) -> &[HeaderOperation] {
        &self.header_operations
    }

    pub fn validate(&self) -> Result<(), MutationError> {
        if self.base_digest.is_zero() {
            return Err(MutationError::invalid("request-base-digest"));
        }
        if let Some(value) = &self.scheme {
            validate_text_presence(value, DEFAULT_MAX_VALUE_BYTES, "request-scheme")?;
        }
        if let Some(Presence::Present(authority)) = &self.authority
            && authority.host.is_empty()
        {
            return Err(MutationError::invalid("request-host"));
        }
        if let Some(value) = &self.method {
            validate_text_presence(value, DEFAULT_MAX_VALUE_BYTES, "request-method")?;
        }
        if let Some(value) = &self.path_segments {
            if value.len() > DEFAULT_MAX_REQUEST_PATH_SEGMENTS {
                return Err(MutationError::limit("request-path-count"));
            }
            for segment in value {
                validate_encoded_field(segment, "request-path")?;
            }
        }
        if let Some(value) = &self.query_fields {
            if value.len() > DEFAULT_MAX_REQUEST_QUERY_FIELDS {
                return Err(MutationError::limit("request-query-count"));
            }
            for query in value {
                QueryField::try_new(query.name.clone(), query.value.clone())?;
            }
        }
        if let Some(Presence::Present(value)) = &self.body
            && value.len() > DEFAULT_MAX_RESPONSE_BYTES
        {
            return Err(MutationError::limit("request-body"));
        }
        if self.header_operations.len() > DEFAULT_MAX_REQUEST_HEADERS {
            return Err(MutationError::limit("request-header-operations"));
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        put_u64(&mut bytes, self.base_generation.get());
        put_digest(&mut bytes, self.base_digest);
        put_optional_presence_text(&mut bytes, self.scheme.as_ref());
        match &self.authority {
            None => bytes.push(0),
            Some(value) => {
                bytes.push(1);
                put_presence_authority(&mut bytes, value);
            }
        }
        put_optional_encoded_fields(&mut bytes, self.path_segments.as_ref());
        put_optional_query_fields(&mut bytes, self.query_fields.as_ref());
        put_optional_presence_text(&mut bytes, self.method.as_ref());
        put_optional_presence_bytes(&mut bytes, self.body.as_ref());
        put_u64(&mut bytes, self.header_operations.len() as u64);
        for operation in &self.header_operations {
            match operation {
                HeaderOperation::Add(header) => {
                    bytes.push(1);
                    put_text(&mut bytes, &header.name);
                    put_text(&mut bytes, &header.value);
                }
                HeaderOperation::Remove { name, value } => {
                    bytes.push(2);
                    put_text(&mut bytes, name);
                    put_presence_text(&mut bytes, value);
                }
            }
        }
        bytes
    }
}

fn validate_encoded_field(value: &EncodedField, field: &'static str) -> Result<(), MutationError> {
    EncodedField::try_new(value.raw.clone(), value.encoded.clone())?;
    if value.raw.as_ref().is_present() && value.encoded.as_ref().is_present() {
        // Both spellings are allowed and intentionally retained.
    }
    if value.raw.is_missing() && value.encoded.is_missing() {
        return Err(MutationError::invalid(field));
    }
    Ok(())
}

fn validate_text_presence(
    value: &Presence<BoundedText>,
    maximum: usize,
    field: &'static str,
) -> Result<(), MutationError> {
    if let Presence::Present(value) = value
        && value.len() > maximum
    {
        return Err(MutationError::limit(field));
    }
    Ok(())
}

fn apply_header_operation(
    headers: &mut Vec<RequestHeader>,
    operation: &HeaderOperation,
) -> Result<(), MutationError> {
    match operation {
        HeaderOperation::Add(header) => {
            if headers.len() >= DEFAULT_MAX_REQUEST_HEADERS {
                return Err(MutationError::limit("request-header-count"));
            }
            headers.push(header.clone());
        }
        HeaderOperation::Remove { name, value } => {
            headers.retain(|header| {
                if header.name != *name {
                    return true;
                }
                match value {
                    Presence::Missing => false,
                    Presence::Present(expected) => header.value != *expected,
                }
            });
        }
    }
    Ok(())
}

/// Limits for one mutation proposal and one context's retained mutation
/// output ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MutationLimits {
    pub max_mutations: usize,
    pub max_value_bytes: usize,
    pub max_result_depth: usize,
    pub max_result_nodes: usize,
    pub max_request_bytes: usize,
    pub max_diagnostics: usize,
    pub max_diagnostic_bytes: usize,
    pub max_outputs: usize,
    pub max_output_bytes: usize,
}

impl Default for MutationLimits {
    fn default() -> Self {
        Self {
            max_mutations: DEFAULT_MAX_MUTATIONS,
            max_value_bytes: DEFAULT_MAX_VALUE_BYTES,
            max_result_depth: DEFAULT_MAX_RESULT_DEPTH,
            max_result_nodes: DEFAULT_MAX_RESULT_NODES,
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            max_diagnostics: DEFAULT_MAX_DIAGNOSTICS,
            max_diagnostic_bytes: DEFAULT_MAX_DIAGNOSTIC_BYTES,
            max_outputs: DEFAULT_MAX_OUTPUTS,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
        }
    }
}

/// Named inputs for constructing bounded mutation limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MutationLimitsParts {
    pub max_mutations: usize,
    pub max_value_bytes: usize,
    pub max_result_depth: usize,
    pub max_result_nodes: usize,
    pub max_request_bytes: usize,
    pub max_diagnostics: usize,
    pub max_diagnostic_bytes: usize,
    pub max_outputs: usize,
    pub max_output_bytes: usize,
}

impl MutationLimits {
    pub fn try_new(parts: MutationLimitsParts) -> Result<Self, MutationError> {
        let value = Self {
            max_mutations: parts.max_mutations,
            max_value_bytes: parts.max_value_bytes,
            max_result_depth: parts.max_result_depth,
            max_result_nodes: parts.max_result_nodes,
            max_request_bytes: parts.max_request_bytes,
            max_diagnostics: parts.max_diagnostics,
            max_diagnostic_bytes: parts.max_diagnostic_bytes,
            max_outputs: parts.max_outputs,
            max_output_bytes: parts.max_output_bytes,
        };
        if parts.max_mutations == 0
            || parts.max_value_bytes == 0
            || parts.max_result_depth == 0
            || parts.max_result_nodes == 0
            || parts.max_request_bytes == 0
            || parts.max_diagnostics == 0
            || parts.max_diagnostic_bytes == 0
            || parts.max_outputs == 0
            || parts.max_output_bytes == 0
        {
            return Err(MutationError::limit("mutation-limits"));
        }
        Ok(value)
    }
}

/// One variable mutation. Variable keys may be empty, matching JMeter's
/// `JMeterVariables` map; Missing deletes a key and Present(empty) stores an
/// empty value.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VariableMutation {
    pub key: BoundedText,
    pub value: Presence<BoundedText>,
}

impl VariableMutation {
    pub fn set(key: impl Into<String>, value: impl Into<String>) -> Result<Self, MutationError> {
        Ok(Self {
            key: variable_key(key)?,
            value: Presence::Present(BoundedText::try_new(value, DEFAULT_MAX_VALUE_BYTES)?),
        })
    }

    pub fn remove(key: impl Into<String>) -> Result<Self, MutationError> {
        Ok(Self {
            key: variable_key(key)?,
            value: Presence::Missing,
        })
    }
}

/// One run-property mutation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PropertyMutation {
    pub key: BoundedText,
    pub value: Presence<BoundedText>,
}

impl PropertyMutation {
    pub fn set(key: impl Into<String>, value: impl Into<String>) -> Result<Self, MutationError> {
        Ok(Self {
            key: property_key(key)?,
            value: Presence::Present(BoundedText::try_new(value, DEFAULT_MAX_VALUE_BYTES)?),
        })
    }

    pub fn remove(key: impl Into<String>) -> Result<Self, MutationError> {
        Ok(Self {
            key: property_key(key)?,
            value: Presence::Missing,
        })
    }
}

fn property_key(key: impl Into<String>) -> Result<BoundedText, MutationError> {
    let key = BoundedText::try_new(key, DEFAULT_MAX_VALUE_BYTES)?;
    if key.is_empty() {
        return Err(MutationError::invalid("property-key"));
    }
    Ok(key)
}

fn variable_key(key: impl Into<String>) -> Result<BoundedText, MutationError> {
    BoundedText::try_new(key, DEFAULT_MAX_VALUE_BYTES)
}

/// Typed control proposal.  BreakCurrentLoop is intentionally unavailable in
/// this runtime foundation because `ControlSignal` cannot represent it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ControlPatch {
    Continue,
    NextLoop,
    BreakCurrentLoop,
    StopThread,
    StopTestGraceful,
    StopTestImmediate,
}

impl ControlPatch {
    fn apply(self) -> Result<ControlSignal, MutationError> {
        match self {
            Self::Continue => Ok(ControlSignal::Continue),
            Self::NextLoop => Ok(ControlSignal::NextLoop),
            Self::BreakCurrentLoop => Err(MutationError::new(
                MutationErrorCode::UnsupportedControl,
                "break-current-loop",
            )),
            Self::StopThread => Ok(ControlSignal::StopThread),
            Self::StopTestGraceful => Ok(ControlSignal::StopTestGraceful),
            Self::StopTestImmediate => Ok(ControlSignal::StopTestImmediate),
        }
    }
}

/// A bounded result/sub-result/assertion patch using only current result-model
/// operations.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResultPatch {
    replacement: Option<Option<SampleResult>>,
    label: Option<Presence<BoundedText>>,
    successful: Option<Presence<bool>>,
    assertions: Vec<AssertionResult>,
    sub_results: Vec<SampleResult>,
    stop_thread: Option<bool>,
    stop_test: Option<bool>,
    stop_test_now: Option<bool>,
    start_next_loop: Option<bool>,
    ignored: Option<bool>,
    logical_action: Option<Presence<LogicalAction>>,
    break_current_loop: Option<bool>,
}

impl ResultPatch {
    pub fn replace(result: Option<SampleResult>) -> Self {
        Self {
            replacement: Some(result),
            ..Self::default()
        }
    }

    pub fn clear() -> Self {
        Self::replace(None)
    }

    pub fn set_label(&mut self, value: Presence<BoundedText>) {
        self.label = Some(value);
    }

    pub fn set_successful(&mut self, value: Presence<bool>) {
        self.successful = Some(value);
    }

    pub fn add_assertion(&mut self, value: AssertionResult) -> Result<(), MutationError> {
        bounded_push(
            &mut self.assertions,
            value,
            DEFAULT_MAX_MUTATIONS,
            "assertions",
        )
    }

    pub fn add_sub_result(&mut self, value: SampleResult) -> Result<(), MutationError> {
        bounded_push(
            &mut self.sub_results,
            value,
            DEFAULT_MAX_MUTATIONS,
            "sub-results",
        )
    }

    pub fn set_stop_thread(&mut self, value: bool) {
        self.stop_thread = Some(value);
    }

    pub fn set_stop_test(&mut self, value: bool) {
        self.stop_test = Some(value);
    }

    pub fn set_stop_test_now(&mut self, value: bool) {
        self.stop_test_now = Some(value);
    }

    pub fn set_start_next_loop(&mut self, value: bool) {
        self.start_next_loop = Some(value);
    }

    pub fn set_ignored(&mut self, value: bool) {
        self.ignored = Some(value);
    }

    pub fn set_logical_action(&mut self, value: Presence<LogicalAction>) {
        self.logical_action = Some(value);
    }

    pub fn set_break_current_loop(&mut self, value: bool) {
        self.break_current_loop = Some(value);
    }

    fn validate(&self, limits: MutationLimits) -> Result<(), MutationError> {
        if self.assertions.len() > limits.max_mutations
            || self.sub_results.len() > limits.max_mutations
        {
            return Err(MutationError::limit("result-patch-count"));
        }
        if self.break_current_loop.is_some() {
            return Err(MutationError::new(
                MutationErrorCode::UnsupportedControl,
                "break-current-loop",
            ));
        }
        if let Some(Presence::Present(label)) = &self.label
            && label.len() > limits.max_value_bytes
        {
            return Err(MutationError::limit("result-label"));
        }
        Ok(())
    }

    fn apply(
        &self,
        result: &mut Option<SampleResult>,
        limits: MutationLimits,
    ) -> Result<(), MutationError> {
        self.validate(limits)?;
        let mut candidate = match &self.replacement {
            None => result.clone(),
            Some(value) => value.clone(),
        };
        if self.replacement.is_some()
            && self.label.is_none()
            && self.successful.is_none()
            && self.assertions.is_empty()
            && self.sub_results.is_empty()
            && self.stop_thread.is_none()
            && self.stop_test.is_none()
            && self.stop_test_now.is_none()
            && self.start_next_loop.is_none()
            && self.ignored.is_none()
            && self.logical_action.is_none()
        {
            *result = candidate;
            return Ok(());
        }
        if self.replacement.is_none()
            && self.label.is_none()
            && self.successful.is_none()
            && self.assertions.is_empty()
            && self.sub_results.is_empty()
            && self.stop_thread.is_none()
            && self.stop_test.is_none()
            && self.stop_test_now.is_none()
            && self.start_next_loop.is_none()
            && self.ignored.is_none()
            && self.logical_action.is_none()
        {
            *result = candidate;
            return Ok(());
        }
        let target = candidate.as_mut().ok_or(MutationError::new(
            MutationErrorCode::ResultInvalid,
            "result-missing",
        ))?;
        if let Some(value) = &self.label {
            match value {
                Presence::Missing => target.clear_label(),
                Presence::Present(value) => target.set_label(value.as_str()),
            }
        }
        if let Some(value) = &self.successful {
            target.set_success(match value {
                Presence::Missing => None,
                Presence::Present(value) => Some(*value),
            });
        }
        for assertion in &self.assertions {
            target
                .add_assertion(assertion.clone())
                .map_err(|_| MutationError::new(MutationErrorCode::ResultInvalid, "assertion"))?;
        }
        if !self.sub_results.is_empty() {
            target
                .try_add_sub_results_raw(
                    self.sub_results.clone(),
                    ValidationLimits::new(limits.max_result_depth, limits.max_result_nodes)
                        .map_err(|_| MutationError::limit("result-limits"))?,
                )
                .map_err(|_| MutationError::new(MutationErrorCode::ResultInvalid, "sub-results"))?;
        }
        if let Some(value) = self.stop_thread {
            target.set_stop_thread(value);
        }
        if let Some(value) = self.stop_test {
            target.set_stop_test(value);
        }
        if let Some(value) = self.stop_test_now {
            target.set_stop_test_now(value);
        }
        if let Some(value) = self.start_next_loop {
            target.set_start_next_loop(value);
        }
        if let Some(value) = self.ignored {
            target.set_ignored(value);
        }
        if let Some(value) = &self.logical_action {
            target.set_logical_action(match value {
                Presence::Missing => None,
                Presence::Present(value) => Some(*value),
            });
        }
        *result = candidate;
        Ok(())
    }
}

/// A redacted diagnostic attached to a proposal.
#[derive(Clone, Eq, PartialEq)]
pub struct MutationDiagnostic {
    code: BoundedText,
    detail: BoundedText,
}

impl MutationDiagnostic {
    pub fn try_new(
        code: impl Into<String>,
        detail: impl Into<String>,
        limits: MutationLimits,
    ) -> Result<Self, MutationError> {
        Ok(Self {
            code: BoundedText::try_new(code, limits.max_diagnostic_bytes)?,
            detail: BoundedText::try_new(detail, limits.max_diagnostic_bytes)?,
        })
    }

    pub fn code(&self) -> &str {
        self.code.as_str()
    }

    pub fn detail_byte_len(&self) -> usize {
        self.detail.len()
    }
}

impl fmt::Debug for MutationDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MutationDiagnostic")
            .field("code_len", &self.code.len())
            .field("detail_len", &self.detail.len())
            .finish()
    }
}

/// A bounded per-processor proposal.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InvocationDelta {
    base_generation: ContextGeneration,
    variables: Vec<VariableMutation>,
    properties: Vec<PropertyMutation>,
    request_patch: Option<RequestPatch>,
    result_patch: Option<ResultPatch>,
    control_patch: Option<ControlPatch>,
    outputs: Vec<BoundedBytes>,
    diagnostics: Vec<MutationDiagnostic>,
    after_state_digest: Option<Digest32>,
    proposal_digest: Option<Digest32>,
}

impl InvocationDelta {
    pub fn new(base_generation: ContextGeneration) -> Self {
        Self {
            base_generation,
            ..Self::default()
        }
    }

    pub fn base_generation(&self) -> ContextGeneration {
        self.base_generation
    }

    pub fn add_variable(&mut self, mutation: VariableMutation) -> Result<(), MutationError> {
        bounded_push(
            &mut self.variables,
            mutation,
            DEFAULT_MAX_MUTATIONS,
            "variables",
        )
    }

    pub fn add_property(&mut self, mutation: PropertyMutation) -> Result<(), MutationError> {
        bounded_push(
            &mut self.properties,
            mutation,
            DEFAULT_MAX_MUTATIONS,
            "properties",
        )
    }

    pub fn set_request_patch(&mut self, patch: RequestPatch) {
        self.request_patch = Some(patch);
    }

    pub fn set_result_patch(&mut self, patch: ResultPatch) {
        self.result_patch = Some(patch);
    }

    pub fn set_control_patch(&mut self, patch: ControlPatch) {
        self.control_patch = Some(patch);
    }

    pub fn add_output(&mut self, output: BoundedBytes) -> Result<(), MutationError> {
        bounded_push(&mut self.outputs, output, DEFAULT_MAX_OUTPUTS, "outputs")
    }

    pub fn add_diagnostic(&mut self, diagnostic: MutationDiagnostic) -> Result<(), MutationError> {
        bounded_push(
            &mut self.diagnostics,
            diagnostic,
            DEFAULT_MAX_DIAGNOSTICS,
            "diagnostics",
        )
    }

    pub fn with_after_state_digest(&mut self, digest: Digest32) {
        self.after_state_digest = Some(digest);
    }

    pub fn with_proposal_digest(&mut self, digest: Digest32) {
        self.proposal_digest = Some(digest);
    }

    pub fn variables(&self) -> &[VariableMutation] {
        &self.variables
    }

    pub fn properties(&self) -> &[PropertyMutation] {
        &self.properties
    }

    pub fn request_patch(&self) -> Option<&RequestPatch> {
        self.request_patch.as_ref()
    }

    pub fn result_patch(&self) -> Option<&ResultPatch> {
        self.result_patch.as_ref()
    }

    pub fn control_patch(&self) -> Option<ControlPatch> {
        self.control_patch
    }

    pub fn outputs(&self) -> &[BoundedBytes] {
        &self.outputs
    }

    pub fn diagnostics(&self) -> &[MutationDiagnostic] {
        &self.diagnostics
    }

    pub fn computed_proposal_digest(&self) -> Digest32 {
        Digest32::sha256(&self.canonical_bytes())
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        put_u64(&mut bytes, self.base_generation.get());
        put_u64(&mut bytes, self.variables.len() as u64);
        for mutation in &self.variables {
            put_text(&mut bytes, &mutation.key);
            put_presence_text(&mut bytes, &mutation.value);
        }
        put_u64(&mut bytes, self.properties.len() as u64);
        for mutation in &self.properties {
            put_text(&mut bytes, &mutation.key);
            put_presence_text(&mut bytes, &mutation.value);
        }
        match &self.request_patch {
            None => bytes.push(0),
            Some(patch) => {
                bytes.push(1);
                let digest = Digest32::sha256(&patch.canonical_bytes());
                put_digest(&mut bytes, digest);
            }
        }
        match &self.result_patch {
            None => bytes.push(0),
            Some(patch) => {
                bytes.push(1);
                canonical_result_patch(&mut bytes, patch);
            }
        }
        match self.control_patch {
            None => bytes.push(0),
            Some(value) => {
                bytes.push(1);
                bytes.push(value as u8);
            }
        }
        put_u64(&mut bytes, self.outputs.len() as u64);
        for output in &self.outputs {
            put_bytes(&mut bytes, output.as_bytes());
        }
        put_u64(&mut bytes, self.diagnostics.len() as u64);
        for diagnostic in &self.diagnostics {
            put_text(&mut bytes, &diagnostic.code);
            put_text(&mut bytes, &diagnostic.detail);
        }
        bytes
    }

    pub fn validate_and_stage(
        &self,
        snapshot: &InvocationSnapshot,
        limits: MutationLimits,
        cancellation: ControlSignal,
    ) -> Result<StagedInvocation, MutationError> {
        if cancellation != ControlSignal::Continue {
            return Err(MutationError::new(
                MutationErrorCode::Cancelled,
                "control-signal",
            ));
        }
        if self.base_generation != snapshot.generation {
            return Err(MutationError::new(
                MutationErrorCode::StaleGeneration,
                "context-base-generation",
            ));
        }
        snapshot.validate(limits)?;
        self.validate(limits)?;
        let generation = snapshot
            .generation
            .checked_next()
            .ok_or(MutationError::overflow("context-generation"))?;
        let mut candidate = snapshot.state.clone();
        let mut variable_keys = BTreeSet::new();
        for mutation in &self.variables {
            if !variable_keys.insert(mutation.key.clone()) {
                return Err(MutationError::invalid("duplicate-variable-key"));
            }
            apply_text_mutation(
                &mut candidate.variables,
                mutation.key.as_str(),
                &mutation.value,
            );
        }
        let mut property_keys = BTreeSet::new();
        let mut property_bases = BTreeMap::new();
        for mutation in &self.properties {
            if !property_keys.insert(mutation.key.clone()) {
                return Err(MutationError::invalid("duplicate-property-key"));
            }
            property_bases.insert(
                mutation.key.clone(),
                PropertyBase {
                    version: snapshot
                        .state
                        .property_versions
                        .get(mutation.key.as_str())
                        .copied(),
                    value: snapshot
                        .state
                        .properties
                        .get(mutation.key.as_str())
                        .cloned(),
                },
            );
            apply_text_mutation(
                &mut candidate.properties,
                mutation.key.as_str(),
                &mutation.value,
            );
        }
        if let Some(patch) = &self.request_patch {
            candidate.request = candidate.request.apply_patch(patch)?;
            if candidate.request.canonical_len() > limits.max_request_bytes {
                return Err(MutationError::limit("request-canonical-bytes"));
            }
        }
        if let Some(patch) = &self.result_patch {
            patch.apply(&mut candidate.result, limits)?;
        }
        let signal = match self.control_patch {
            None => ControlSignal::Continue,
            Some(value) => value.apply()?,
        };
        candidate.generation = generation;
        validate_state(&candidate, limits)?;
        let output_bytes = total_bytes(self.outputs.iter().map(BoundedBytes::len), "output-bytes")?;
        if self.outputs.len() > limits.max_outputs || output_bytes > limits.max_output_bytes {
            return Err(MutationError::limit("outputs"));
        }
        let diagnostic_bytes = total_bytes(
            self.diagnostics
                .iter()
                .map(|value| value.code.len() + value.detail.len()),
            "diagnostic-bytes",
        )?;
        if self.diagnostics.len() > limits.max_diagnostics
            || diagnostic_bytes > limits.max_diagnostic_bytes
        {
            return Err(MutationError::limit("diagnostics"));
        }
        if self.control_patch == Some(ControlPatch::BreakCurrentLoop) {
            return Err(MutationError::new(
                MutationErrorCode::UnsupportedControl,
                "break-current-loop",
            ));
        }
        let after_state_digest = candidate.digest();
        if let Some(expected) = self.after_state_digest
            && expected != after_state_digest
        {
            return Err(MutationError::new(
                MutationErrorCode::StaleDigest,
                "after-state-digest",
            ));
        }
        let proposal_digest = self.computed_proposal_digest();
        if let Some(expected) = self.proposal_digest
            && expected != proposal_digest
        {
            return Err(MutationError::new(
                MutationErrorCode::StaleDigest,
                "proposal-digest",
            ));
        }
        Ok(StagedInvocation {
            base_generation: snapshot.generation,
            candidate,
            property_bases,
            property_mutations: self.properties.clone(),
            outputs: self.outputs.clone(),
            diagnostics: self.diagnostics.clone(),
            signal,
            after_state_digest,
            proposal_digest,
            committed: false,
        })
    }

    fn validate(&self, limits: MutationLimits) -> Result<(), MutationError> {
        if self.variables.len() > limits.max_mutations
            || self.properties.len() > limits.max_mutations
        {
            return Err(MutationError::limit("mutation-count"));
        }
        for mutation in &self.variables {
            validate_variable_mutation(mutation.key.as_str(), &mutation.value, limits)?;
        }
        for mutation in &self.properties {
            validate_property_mutation(mutation.key.as_str(), &mutation.value, limits)?;
        }
        if let Some(patch) = &self.request_patch {
            patch.validate()?;
            if patch.canonical_bytes().len() > limits.max_request_bytes {
                return Err(MutationError::limit("request-patch-bytes"));
            }
        }
        if let Some(patch) = &self.result_patch {
            patch.validate(limits)?;
        }
        if self.outputs.len() > limits.max_outputs
            || self.diagnostics.len() > limits.max_diagnostics
        {
            return Err(MutationError::limit("mutation-output-count"));
        }
        Ok(())
    }
}

fn bounded_push<T>(
    values: &mut Vec<T>,
    value: T,
    maximum: usize,
    field: &'static str,
) -> Result<(), MutationError> {
    let next = values
        .len()
        .checked_add(1)
        .ok_or(MutationError::overflow(field))?;
    if next > maximum {
        return Err(MutationError::limit(field));
    }
    values.push(value);
    Ok(())
}

fn validate_variable_mutation(
    key: &str,
    value: &Presence<BoundedText>,
    limits: MutationLimits,
) -> Result<(), MutationError> {
    if key.len() > limits.max_value_bytes {
        return Err(MutationError::invalid("mutation-key"));
    }
    if let Presence::Present(value) = value
        && value.len() > limits.max_value_bytes
    {
        return Err(MutationError::limit("mutation-value"));
    }
    Ok(())
}

fn validate_property_mutation(
    key: &str,
    value: &Presence<BoundedText>,
    limits: MutationLimits,
) -> Result<(), MutationError> {
    if key.is_empty() || key.len() > limits.max_value_bytes {
        return Err(MutationError::invalid("mutation-key"));
    }
    if let Presence::Present(value) = value
        && value.len() > limits.max_value_bytes
    {
        return Err(MutationError::limit("mutation-value"));
    }
    Ok(())
}

fn apply_text_mutation(
    values: &mut BTreeMap<String, String>,
    key: &str,
    value: &Presence<BoundedText>,
) {
    match value {
        Presence::Missing => {
            values.remove(key);
        }
        Presence::Present(value) => {
            values.insert(key.to_owned(), value.as_str().to_owned());
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PropertyBase {
    pub(crate) version: Option<u64>,
    pub(crate) value: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MutationState {
    generation: ContextGeneration,
    variables: BTreeMap<String, String>,
    properties: BTreeMap<String, String>,
    property_versions: BTreeMap<String, u64>,
    request: RequestState,
    result: Option<SampleResult>,
}

impl MutationState {
    fn digest(&self) -> Digest32 {
        let mut bytes = Vec::new();
        put_u64(&mut bytes, self.generation.get());
        put_map(&mut bytes, &self.variables);
        put_map(&mut bytes, &self.properties);
        put_map_u64(&mut bytes, &self.property_versions);
        put_digest(&mut bytes, self.request.digest());
        put_optional_result(&mut bytes, self.result.as_ref());
        Digest32::sha256(&bytes)
    }
}

/// Immutable state captured before an invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvocationSnapshot {
    generation: ContextGeneration,
    state: MutationState,
}

impl InvocationSnapshot {
    pub(crate) fn from_parts(
        generation: ContextGeneration,
        variables: BTreeMap<String, String>,
        properties: BTreeMap<String, String>,
        property_versions: BTreeMap<String, u64>,
        request: RequestState,
        result: Option<SampleResult>,
    ) -> Self {
        Self {
            generation,
            state: MutationState {
                generation,
                variables,
                properties,
                property_versions,
                request,
                result,
            },
        }
    }

    pub fn generation(&self) -> ContextGeneration {
        self.generation
    }

    pub fn variables(&self) -> &BTreeMap<String, String> {
        &self.state.variables
    }

    pub fn properties(&self) -> &BTreeMap<String, String> {
        &self.state.properties
    }

    pub fn request(&self) -> &RequestState {
        &self.state.request
    }

    pub fn result(&self) -> Option<&SampleResult> {
        self.state.result.as_ref()
    }

    pub fn state_digest(&self) -> Digest32 {
        self.state.digest()
    }

    fn validate(&self, limits: MutationLimits) -> Result<(), MutationError> {
        validate_variable_map(&self.state.variables, limits, "snapshot-variables")?;
        validate_property_map(&self.state.properties, limits, "snapshot-properties")?;
        self.state.request.validate()?;
        if self.state.request.canonical_len() > limits.max_request_bytes {
            return Err(MutationError::limit("snapshot-request-bytes"));
        }
        if self.state.request.digest() == Digest32::from_bytes([0; 32]) {
            return Err(MutationError::internal("request-digest"));
        }
        if let Some(result) = &self.state.result {
            validate_result(result, limits)?;
        }
        Ok(())
    }
}

/// A complete candidate held separately from live context until commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedInvocation {
    base_generation: ContextGeneration,
    candidate: MutationState,
    property_bases: BTreeMap<BoundedText, PropertyBase>,
    property_mutations: Vec<PropertyMutation>,
    outputs: Vec<BoundedBytes>,
    diagnostics: Vec<MutationDiagnostic>,
    signal: ControlSignal,
    after_state_digest: Digest32,
    proposal_digest: Digest32,
    committed: bool,
}

impl StagedInvocation {
    pub fn base_generation(&self) -> ContextGeneration {
        self.base_generation
    }

    pub fn candidate_generation(&self) -> ContextGeneration {
        self.candidate.generation
    }

    pub fn candidate_variables(&self) -> &BTreeMap<String, String> {
        &self.candidate.variables
    }

    pub fn candidate_request(&self) -> &RequestState {
        &self.candidate.request
    }

    pub fn candidate_result(&self) -> Option<&SampleResult> {
        self.candidate.result.as_ref()
    }

    pub fn candidate_properties(&self) -> &BTreeMap<String, String> {
        &self.candidate.properties
    }

    pub fn outputs(&self) -> &[BoundedBytes] {
        &self.outputs
    }

    pub fn diagnostics(&self) -> &[MutationDiagnostic] {
        &self.diagnostics
    }

    pub fn signal(&self) -> ControlSignal {
        self.signal
    }

    pub fn after_state_digest(&self) -> Digest32 {
        self.after_state_digest
    }

    pub fn proposal_digest(&self) -> Digest32 {
        self.proposal_digest
    }

    pub fn is_committed(&self) -> bool {
        self.committed
    }

    pub(crate) fn property_bases(&self) -> &BTreeMap<BoundedText, PropertyBase> {
        &self.property_bases
    }

    pub(crate) fn property_mutations(&self) -> &[PropertyMutation] {
        &self.property_mutations
    }

    pub(crate) fn mark_committed(&mut self) {
        self.committed = true;
    }
}

/// A successful commit receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvocationCommit {
    pub generation: ContextGeneration,
    pub request_generation: RequestGeneration,
    pub after_state_digest: Digest32,
    pub proposal_digest: Digest32,
    pub output_count: usize,
    pub diagnostic_count: usize,
}

fn validate_state(state: &MutationState, limits: MutationLimits) -> Result<(), MutationError> {
    validate_variable_map(&state.variables, limits, "candidate-variables")?;
    validate_property_map(&state.properties, limits, "candidate-properties")?;
    state.request.validate()?;
    if state.request.canonical_len() > limits.max_request_bytes {
        return Err(MutationError::limit("candidate-request-bytes"));
    }
    if state.request.digest() == Digest32::from_bytes([0; 32]) {
        return Err(MutationError::internal("candidate-request-digest"));
    }
    if let Some(result) = &state.result {
        validate_result(result, limits)?;
    }
    Ok(())
}

fn validate_variable_map(
    values: &BTreeMap<String, String>,
    limits: MutationLimits,
    field: &'static str,
) -> Result<(), MutationError> {
    validate_map_with_policy(values, limits, field, true)
}

fn validate_property_map(
    values: &BTreeMap<String, String>,
    limits: MutationLimits,
    field: &'static str,
) -> Result<(), MutationError> {
    validate_map_with_policy(values, limits, field, false)
}

fn validate_map_with_policy(
    values: &BTreeMap<String, String>,
    limits: MutationLimits,
    field: &'static str,
    allow_empty_key: bool,
) -> Result<(), MutationError> {
    if values.len()
        > limits
            .max_mutations
            .checked_mul(16)
            .ok_or(MutationError::overflow(field))?
    {
        return Err(MutationError::limit(field));
    }
    for (key, value) in values {
        if (!allow_empty_key && key.is_empty())
            || key.len() > limits.max_value_bytes
            || value.len() > limits.max_value_bytes
        {
            return Err(MutationError::limit(field));
        }
    }
    Ok(())
}

fn validate_result(result: &SampleResult, limits: MutationLimits) -> Result<(), MutationError> {
    result
        .validate_with_limits(
            ValidationLimits::new(limits.max_result_depth, limits.max_result_nodes)
                .map_err(|_| MutationError::limit("result-limits"))?,
        )
        .map_err(|_| MutationError::new(MutationErrorCode::ResultInvalid, "result-tree"))?;
    validate_result_values(result, limits, 0)
}

fn validate_result_values(
    result: &SampleResult,
    limits: MutationLimits,
    depth: usize,
) -> Result<(), MutationError> {
    if depth >= limits.max_result_depth {
        return Err(MutationError::limit("result-depth"));
    }
    for value in [
        result.label_field(),
        result.response_code(),
        result.response_message(),
        result.failure_message(),
        result.content_type(),
        result.sampler_data(),
        result.url(),
    ] {
        if value.is_some_and(|value| value.len() > limits.max_value_bytes) {
            return Err(MutationError::limit("result-value"));
        }
    }
    if result
        .data_encoding()
        .is_some_and(|value| value.len() > limits.max_value_bytes)
        || result
            .response_file_reference()
            .is_some_and(|value| value.len() > limits.max_value_bytes)
        || result
            .response_data()
            .is_some_and(|value| value.len() > limits.max_value_bytes)
        || result
            .request_data()
            .is_some_and(|value| value.len() > limits.max_value_bytes)
        || result
            .response_headers()
            .is_some_and(|value| value.len() > limits.max_value_bytes)
        || result
            .request_headers()
            .is_some_and(|value| value.len() > limits.max_value_bytes)
    {
        return Err(MutationError::limit("result-value"));
    }
    for assertion in result.assertions() {
        if assertion.name().len() > limits.max_value_bytes
            || assertion
                .failure_message()
                .is_some_and(|value| value.len() > limits.max_value_bytes)
            || assertion
                .error_message()
                .is_some_and(|value| value.len() > limits.max_value_bytes)
        {
            return Err(MutationError::limit("assertion-value"));
        }
    }
    for child in result.sub_results() {
        validate_result_values(
            child,
            limits,
            depth
                .checked_add(1)
                .ok_or(MutationError::overflow("result-depth"))?,
        )?;
    }
    Ok(())
}

fn total_bytes<I>(values: I, field: &'static str) -> Result<usize, MutationError>
where
    I: IntoIterator<Item = usize>,
{
    values.into_iter().try_fold(0usize, |total, value| {
        total
            .checked_add(value)
            .ok_or(MutationError::overflow(field))
    })
}

fn canonical_result_patch(bytes: &mut Vec<u8>, patch: &ResultPatch) {
    match &patch.replacement {
        None => bytes.push(0),
        Some(None) => bytes.extend_from_slice(&[1, 0]),
        Some(Some(result)) => {
            bytes.extend_from_slice(&[1, 1]);
            canonical_result(bytes, result);
        }
    }
    put_optional_presence_text(bytes, patch.label.as_ref());
    put_optional_presence_bool(bytes, patch.successful.as_ref());
    put_u64(bytes, patch.assertions.len() as u64);
    for assertion in &patch.assertions {
        put_text_raw(bytes, assertion.name());
        bytes.push(assertion.is_failure() as u8);
        bytes.push(assertion.is_error() as u8);
        put_optional_text_raw(bytes, assertion.failure_message());
        put_optional_text_raw(bytes, assertion.error_message());
    }
    put_u64(bytes, patch.sub_results.len() as u64);
    for result in &patch.sub_results {
        canonical_result(bytes, result);
    }
    for value in [
        patch.stop_thread,
        patch.stop_test,
        patch.stop_test_now,
        patch.start_next_loop,
        patch.ignored,
        patch.break_current_loop,
    ] {
        put_optional_bool(bytes, value);
    }
    match patch.logical_action {
        None => bytes.push(0),
        Some(Presence::Missing) => bytes.extend_from_slice(&[1, 0]),
        Some(Presence::Present(value)) => {
            bytes.extend_from_slice(&[1, 1, value as u8]);
        }
    }
}

fn canonical_result(bytes: &mut Vec<u8>, result: &SampleResult) {
    put_optional_text_raw(bytes, result.label_field());
    put_optional_bool(bytes, result.success());
    put_optional_text_raw(bytes, result.response_code());
    put_optional_text_raw(bytes, result.response_message());
    put_optional_text_raw(bytes, result.failure_message());
    match result.data_type() {
        None => bytes.push(0),
        Some(value) => {
            bytes.push(1);
            put_text_raw(bytes, value.as_wire());
        }
    }
    match result.data_encoding() {
        None => bytes.push(0),
        Some(value) => {
            bytes.push(1);
            put_text_raw(bytes, value.as_str());
        }
    }
    put_optional_text_raw(bytes, result.content_type());
    put_optional_bytes(bytes, result.request_data().map(SampleData::as_bytes));
    put_optional_bytes(bytes, result.response_data().map(SampleData::as_bytes));
    put_optional_bytes(bytes, result.request_headers().map(HeaderBlock::as_bytes));
    put_optional_bytes(bytes, result.response_headers().map(HeaderBlock::as_bytes));
    put_optional_text_raw(bytes, result.sampler_data());
    put_optional_text_raw(bytes, result.response_file());
    put_optional_text_raw(bytes, result.url());
    put_optional_u64(bytes, result.headers_size().map(|value| value.as_u64()));
    put_optional_u64(bytes, result.body_size().map(|value| value.as_u64()));
    put_optional_u64(bytes, result.received_bytes().map(|value| value.as_u64()));
    put_optional_u64(bytes, result.sent_bytes().map(|value| value.as_u64()));
    put_optional_u64(bytes, result.sample_count().map(|value| value.as_u64()));
    put_optional_u64(bytes, result.error_count().map(|value| value.as_u64()));
    for value in [
        result.stop_thread(),
        result.stop_test(),
        result.stop_test_now(),
        result.start_next_loop(),
        result.break_current_loop(),
        result.ignored(),
    ] {
        bytes.push(value as u8);
    }
    match result.logical_action() {
        None => bytes.push(0),
        Some(value) => bytes.extend_from_slice(&[1, value as u8]),
    }
    put_u64(bytes, result.assertions().len() as u64);
    for assertion in result.assertions() {
        put_text_raw(bytes, assertion.name());
        bytes.push(assertion.is_failure() as u8);
        bytes.push(assertion.is_error() as u8);
        put_optional_text_raw(bytes, assertion.failure_message());
        put_optional_text_raw(bytes, assertion.error_message());
    }
    put_u64(bytes, result.sub_results().len() as u64);
    for child in result.sub_results() {
        canonical_result(bytes, child);
    }
}

fn put_optional_result(bytes: &mut Vec<u8>, result: Option<&SampleResult>) {
    match result {
        None => bytes.push(0),
        Some(result) => {
            bytes.push(1);
            canonical_result(bytes, result);
        }
    }
}

fn put_map(bytes: &mut Vec<u8>, values: &BTreeMap<String, String>) {
    put_u64(bytes, values.len() as u64);
    for (key, value) in values {
        put_text_raw(bytes, key);
        put_text_raw(bytes, value);
    }
}

fn put_map_u64(bytes: &mut Vec<u8>, values: &BTreeMap<String, u64>) {
    put_u64(bytes, values.len() as u64);
    for (key, value) in values {
        put_text_raw(bytes, key);
        put_u64(bytes, *value);
    }
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_digest(bytes: &mut Vec<u8>, digest: Digest32) {
    bytes.extend_from_slice(&digest.as_bytes());
}

fn put_text(bytes: &mut Vec<u8>, value: &BoundedText) {
    put_text_raw(bytes, value.as_str());
}

fn put_text_raw(bytes: &mut Vec<u8>, value: &str) {
    put_u64(bytes, value.len() as u64);
    bytes.extend_from_slice(value.as_bytes());
}

fn put_bytes(bytes: &mut Vec<u8>, value: &[u8]) {
    put_u64(bytes, value.len() as u64);
    bytes.extend_from_slice(value);
}

fn put_optional_text_raw(bytes: &mut Vec<u8>, value: Option<&str>) {
    match value {
        None => bytes.push(0),
        Some(value) => {
            bytes.push(1);
            put_text_raw(bytes, value);
        }
    }
}

fn put_optional_bytes(bytes: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        None => bytes.push(0),
        Some(value) => {
            bytes.push(1);
            put_bytes(bytes, value);
        }
    }
}

fn put_presence_text(bytes: &mut Vec<u8>, value: &Presence<BoundedText>) {
    match value {
        Presence::Missing => bytes.push(0),
        Presence::Present(value) => {
            bytes.push(1);
            put_text(bytes, value);
        }
    }
}

fn put_optional_presence_text(bytes: &mut Vec<u8>, value: Option<&Presence<BoundedText>>) {
    match value {
        None => bytes.push(0),
        Some(value) => {
            bytes.push(1);
            put_presence_text(bytes, value);
        }
    }
}

fn put_presence_bytes(bytes: &mut Vec<u8>, value: &Presence<BoundedBytes>) {
    match value {
        Presence::Missing => bytes.push(0),
        Presence::Present(value) => {
            bytes.push(1);
            put_bytes(bytes, value.as_bytes());
        }
    }
}

fn put_optional_presence_bytes(bytes: &mut Vec<u8>, value: Option<&Presence<BoundedBytes>>) {
    match value {
        None => bytes.push(0),
        Some(value) => {
            bytes.push(1);
            put_presence_bytes(bytes, value);
        }
    }
}

fn put_presence_bool(bytes: &mut Vec<u8>, value: &Presence<bool>) {
    match value {
        Presence::Missing => bytes.push(0),
        Presence::Present(value) => bytes.extend_from_slice(&[1, *value as u8]),
    }
}

fn put_optional_presence_bool(bytes: &mut Vec<u8>, value: Option<&Presence<bool>>) {
    match value {
        None => bytes.push(0),
        Some(value) => {
            bytes.push(1);
            put_presence_bool(bytes, value);
        }
    }
}

fn put_optional_bool(bytes: &mut Vec<u8>, value: Option<bool>) {
    match value {
        None => bytes.push(0),
        Some(value) => bytes.extend_from_slice(&[1, value as u8]),
    }
}

fn put_optional_u64(bytes: &mut Vec<u8>, value: Option<u64>) {
    match value {
        None => bytes.push(0),
        Some(value) => {
            bytes.push(1);
            put_u64(bytes, value);
        }
    }
}

fn put_encoded_field(bytes: &mut Vec<u8>, value: &EncodedField) {
    put_presence_text(bytes, &value.raw);
    put_presence_text(bytes, &value.encoded);
}

fn put_encoded_fields(bytes: &mut Vec<u8>, values: &[EncodedField]) {
    put_u64(bytes, values.len() as u64);
    for value in values {
        put_encoded_field(bytes, value);
    }
}

fn put_query_fields(bytes: &mut Vec<u8>, values: &[QueryField]) {
    put_u64(bytes, values.len() as u64);
    for value in values {
        put_encoded_field(bytes, &value.name);
        match &value.value {
            Presence::Missing => bytes.push(0),
            Presence::Present(value) => {
                bytes.push(1);
                put_encoded_field(bytes, value);
            }
        }
    }
}

fn put_optional_encoded_fields(bytes: &mut Vec<u8>, values: Option<&Vec<EncodedField>>) {
    match values {
        None => bytes.push(0),
        Some(values) => {
            bytes.push(1);
            put_encoded_fields(bytes, values);
        }
    }
}

fn put_optional_query_fields(bytes: &mut Vec<u8>, values: Option<&Vec<QueryField>>) {
    match values {
        None => bytes.push(0),
        Some(values) => {
            bytes.push(1);
            put_query_fields(bytes, values);
        }
    }
}

fn put_presence_authority(bytes: &mut Vec<u8>, value: &Presence<RequestAuthority>) {
    match value {
        Presence::Missing => bytes.push(0),
        Presence::Present(value) => {
            bytes.push(1);
            put_text(bytes, &value.host);
            put_optional_u64(bytes, value.port.map(|port| u64::from(port.get())));
        }
    }
}

fn canonical_request_bytes(request: &RequestState) -> Vec<u8> {
    let mut bytes = Vec::new();
    put_presence_text(&mut bytes, &request.scheme);
    put_presence_authority(&mut bytes, &request.authority);
    put_encoded_fields(&mut bytes, &request.path_segments);
    put_query_fields(&mut bytes, &request.query_fields);
    put_presence_text(&mut bytes, &request.method);
    put_presence_bytes(&mut bytes, &request.body);
    put_u64(&mut bytes, request.headers.len() as u64);
    for header in &request.headers {
        put_text(&mut bytes, &header.name);
        put_text(&mut bytes, &header.value);
    }
    bytes
}

#[cfg(test)]
fn canonical_result_patch_for_tests(patch: &ResultPatch) -> Digest32 {
    let mut bytes = Vec::new();
    canonical_result_patch(&mut bytes, patch);
    Digest32::sha256(&bytes)
}

impl MutationError {
    pub(crate) const fn internal(detail: &'static str) -> Self {
        Self::new(MutationErrorCode::Internal, detail)
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests construct bounded values and use explicit assertions"
)]
mod tests {
    use super::*;

    fn text(value: &str) -> BoundedText {
        BoundedText::try_new(value, DEFAULT_MAX_VALUE_BYTES).expect("bounded text")
    }

    fn bytes(value: &[u8]) -> BoundedBytes {
        BoundedBytes::try_new(value, DEFAULT_MAX_RESPONSE_BYTES).expect("bounded bytes")
    }

    fn request() -> RequestState {
        RequestState::new(
            RequestGeneration::FIRST,
            "http",
            "example.test",
            None,
            "GET",
        )
        .expect("request")
    }

    fn snapshot() -> InvocationSnapshot {
        InvocationSnapshot::from_parts(
            ContextGeneration::FIRST,
            BTreeMap::from([(String::from("before"), String::from("value"))]),
            BTreeMap::from([(String::from("peer"), String::from("old"))]),
            BTreeMap::from([(String::from("peer"), 1)]),
            request(),
            Some(SampleResult::new("sample")),
        )
    }

    #[test]
    fn missing_and_present_empty_are_distinct_for_response_body_and_headers() {
        let mut missing = SampleResult::new("missing");
        let resolver = SampleResultResponseResolver::new().expect("resolver");
        let body = resolver
            .resolve(&missing, ResponseSource::Body)
            .expect("body");
        assert!(body.body.is_missing());
        missing.set_response_data(Some(SampleData::empty()));
        missing.set_response_headers(Some(HeaderBlock::empty()));
        let body = resolver
            .resolve(&missing, ResponseSource::Body)
            .expect("body");
        let headers = resolver
            .resolve(&missing, ResponseSource::Headers)
            .expect("headers");
        assert!(matches!(body.body, Presence::Present(ref value) if value.is_empty()));
        assert!(matches!(headers.raw_headers, Presence::Present(ref value) if value.is_empty()));
    }

    #[test]
    fn response_source_selection_never_substitutes_headers_for_body() {
        let mut result = SampleResult::new("selection");
        result.set_response_headers_text("X: value");
        let resolver = SampleResultResponseResolver::new().expect("resolver");
        let body = resolver
            .resolve(&result, ResponseSource::Body)
            .expect("body");
        assert!(body.body.is_missing());
        assert!(body.raw_headers.is_missing());
        let headers = resolver
            .resolve(&result, ResponseSource::Headers)
            .expect("headers");
        assert!(headers.raw_headers.is_present());
    }

    struct FileResolver;

    impl AllowlistedFileResolver for FileResolver {
        fn resolve_file(&self, _capability: FileCapability) -> Result<BoundedBytes, MutationError> {
            Ok(bytes(b"file"))
        }
    }

    #[test]
    fn result_filename_does_not_infer_file_capability() {
        let mut result = SampleResult::new("file");
        result.set_result_file_name_text("secret.txt");
        let resolver = SampleResultResponseResolver::new().expect("resolver");
        let capability = FileCapability::try_new(1, 4, Digest32::sha256(b"file")).expect("cap");
        let error = resolver.resolve(&result, ResponseSource::AllowlistedFile(capability));
        assert_eq!(
            error.expect_err("must reject").code(),
            MutationErrorCode::ProviderUnavailable
        );
        let resolver = resolver.with_file_resolver(Arc::new(FileResolver));
        assert!(
            resolver
                .resolve(&result, ResponseSource::AllowlistedFile(capability))
                .is_ok()
        );
    }

    #[test]
    fn request_canonical_digest_preserves_order_and_presence() {
        let mut first = request();
        first
            .path_segments
            .push(EncodedField::raw("a").expect("segment"));
        first.query_fields.push(
            QueryField::try_new(
                EncodedField::raw("q").expect("name"),
                Presence::Present(EncodedField::raw("").expect("empty value")),
            )
            .expect("query"),
        );
        first.query_fields.push(
            QueryField::try_new(EncodedField::raw("r").expect("name"), Presence::Missing)
                .expect("query"),
        );
        let mut second = first.clone();
        second.query_fields.reverse();
        assert_ne!(first.digest(), second.digest());
        assert_ne!(first.digest(), request().digest());
    }

    #[test]
    fn stale_request_patch_is_atomic_and_generation_is_distinct() {
        let state = request();
        let mut patch = RequestPatch::new(state.generation(), state.digest());
        patch.set_method(Presence::Present(text("POST")));
        patch
            .add_header_operation(HeaderOperation::add("X", "one").expect("header"))
            .expect("operation");
        let changed = state.apply_patch(&patch).expect("patch");
        assert_eq!(changed.generation().get(), 2);
        assert_eq!(ContextGeneration::FIRST.get(), 1);
        let stale = changed.apply_patch(&patch).expect_err("stale");
        assert_eq!(stale.code(), MutationErrorCode::StaleGeneration);
        assert!(state.headers().is_empty());
    }

    #[test]
    fn ordered_duplicate_headers_and_query_values_are_retained() {
        let mut state = request();
        state
            .headers
            .push(RequestHeader::try_new("X", "a").expect("header"));
        state
            .headers
            .push(RequestHeader::try_new("X", "a").expect("header"));
        let mut patch = RequestPatch::new(state.generation(), state.digest());
        patch
            .add_header_operation(HeaderOperation::add("X", "b").expect("header"))
            .expect("operation");
        let changed = state.apply_patch(&patch).expect("patch");
        assert_eq!(changed.headers().len(), 3);
        assert_eq!(changed.headers()[0], changed.headers()[1]);
    }

    #[test]
    fn delta_rejects_duplicate_keys_and_preserves_state_on_failure() {
        let snapshot = snapshot();
        let mut delta = InvocationDelta::new(snapshot.generation());
        delta
            .add_variable(VariableMutation::set("x", "1").expect("mutation"))
            .expect("add");
        delta
            .add_variable(VariableMutation::set("x", "2").expect("mutation"))
            .expect("add");
        let error = delta
            .validate_and_stage(
                &snapshot,
                MutationLimits::default(),
                ControlSignal::Continue,
            )
            .expect_err("duplicate");
        assert_eq!(error.code(), MutationErrorCode::Invalid);
        assert_eq!(
            snapshot.variables().get("before").map(String::as_str),
            Some("value")
        );
    }

    #[test]
    fn empty_variable_set_and_remove_commit_with_candidate_receipts_and_digests() {
        let mut execution = crate::ExecutionContext::new();
        let mut set = InvocationDelta::new(execution.context_generation());
        set.add_variable(VariableMutation::set("", "value").expect("empty variable set"))
            .expect("add empty variable set");
        let proposal_digest = set.computed_proposal_digest();
        let mut staged = execution
            .validate_and_stage_invocation(&set)
            .expect("stage empty variable set");
        assert_eq!(
            staged.candidate_variables().get("").map(String::as_str),
            Some("value")
        );
        let after_state_digest = staged.after_state_digest();
        let receipt = execution
            .commit_staged_invocation(&mut staged)
            .expect("commit empty variable set");
        assert_eq!(execution.variable(""), Some(String::from("value")));
        assert_eq!(receipt.after_state_digest, after_state_digest);
        assert_eq!(receipt.proposal_digest, proposal_digest);
        assert_eq!(receipt.generation, execution.context_generation());
        assert!(staged.is_committed());

        let mut remove = InvocationDelta::new(execution.context_generation());
        remove
            .add_variable(VariableMutation::remove("").expect("empty variable remove"))
            .expect("add empty variable remove");
        let remove_proposal_digest = remove.computed_proposal_digest();
        let mut staged = execution
            .validate_and_stage_invocation(&remove)
            .expect("stage empty variable remove");
        assert!(!staged.candidate_variables().contains_key(""));
        let remove_after_state_digest = staged.after_state_digest();
        let receipt = execution
            .commit_staged_invocation(&mut staged)
            .expect("commit empty variable remove");
        assert_eq!(execution.variable(""), None);
        assert_eq!(receipt.after_state_digest, remove_after_state_digest);
        assert_eq!(receipt.proposal_digest, remove_proposal_digest);
        assert_eq!(receipt.generation, execution.context_generation());
    }

    #[test]
    fn duplicate_empty_variable_mutations_are_rejected_atomically() {
        let mut execution = crate::ExecutionContext::new();
        execution.set_variable("stable", "before");
        let generation = execution.context_generation();
        let digest = execution.snapshot_processor_invocation().state_digest();
        let mut delta = InvocationDelta::new(generation);
        delta
            .add_variable(VariableMutation::set("", "first").expect("empty variable set"))
            .expect("add empty variable set");
        delta
            .add_variable(VariableMutation::remove("").expect("empty variable remove"))
            .expect("add empty variable remove");

        let error = execution
            .validate_and_stage_invocation(&delta)
            .expect_err("duplicate empty variable key");
        assert_eq!(error.code(), MutationErrorCode::Invalid);
        assert_eq!(execution.context_generation(), generation);
        assert_eq!(execution.variable("stable"), Some(String::from("before")));
        assert_eq!(execution.variable(""), None);
        assert_eq!(
            execution.snapshot_processor_invocation().state_digest(),
            digest
        );
    }

    #[test]
    fn empty_property_keys_remain_rejected() {
        let error = PropertyMutation::set("", "value").expect_err("empty property key");
        assert_eq!(error.code(), MutationErrorCode::Invalid);
        let error = PropertyMutation::remove("").expect_err("empty property key");
        assert_eq!(error.code(), MutationErrorCode::Invalid);

        let empty_key = BoundedText::try_new("", DEFAULT_MAX_VALUE_BYTES).expect("empty text");
        let mut delta = InvocationDelta::new(ContextGeneration::FIRST);
        delta
            .add_property(PropertyMutation {
                key: empty_key,
                value: Presence::Present(text("value")),
            })
            .expect("bounded property mutation");
        let error = delta
            .validate_and_stage(
                &snapshot(),
                MutationLimits::default(),
                ControlSignal::Continue,
            )
            .expect_err("empty property key validation");
        assert_eq!(error.code(), MutationErrorCode::Invalid);
    }

    #[test]
    fn delta_commit_candidate_contains_result_and_subresult_bounds() {
        let snapshot = snapshot();
        let mut result_patch = ResultPatch::default();
        result_patch
            .add_sub_result(SampleResult::new("child"))
            .expect("child");
        let mut delta = InvocationDelta::new(snapshot.generation());
        delta.set_result_patch(result_patch);
        let staged = delta
            .validate_and_stage(
                &snapshot,
                MutationLimits::default(),
                ControlSignal::Continue,
            )
            .expect("stage");
        assert_eq!(
            staged
                .candidate_result()
                .expect("result")
                .sub_results()
                .len(),
            1
        );
    }

    #[test]
    fn property_peer_write_is_detected_without_overwrite() {
        let mut snapshot = snapshot();
        let mut delta = InvocationDelta::new(snapshot.generation());
        delta
            .add_property(PropertyMutation::set("peer", "component").expect("mutation"))
            .expect("add");
        let staged = delta
            .validate_and_stage(
                &snapshot,
                MutationLimits::default(),
                ControlSignal::Continue,
            )
            .expect("stage");
        snapshot
            .state
            .properties
            .insert(String::from("peer"), String::from("newer"));
        snapshot
            .state
            .property_versions
            .insert(String::from("peer"), 2);
        let base = staged.property_bases().get(&text("peer")).expect("base");
        assert_eq!(base.version, Some(1));
        assert_eq!(
            snapshot.properties().get("peer").map(String::as_str),
            Some("newer")
        );
    }

    #[test]
    fn cancellation_double_commit_and_unknown_control_are_typed() {
        let snapshot = snapshot();
        let mut delta = InvocationDelta::new(snapshot.generation());
        delta.set_control_patch(ControlPatch::BreakCurrentLoop);
        let error = delta
            .validate_and_stage(
                &snapshot,
                MutationLimits::default(),
                ControlSignal::Continue,
            )
            .expect_err("control");
        assert_eq!(error.code(), MutationErrorCode::UnsupportedControl);
        let mut delta = InvocationDelta::new(snapshot.generation());
        delta.add_output(bytes(b"output")).expect("output");
        let mut staged = delta
            .validate_and_stage(
                &snapshot,
                MutationLimits::default(),
                ControlSignal::Continue,
            )
            .expect("stage");
        staged.mark_committed();
        assert!(staged.is_committed());
        let cancelled = InvocationDelta::new(snapshot.generation())
            .validate_and_stage(
                &snapshot,
                MutationLimits::default(),
                ControlSignal::StopThread,
            )
            .expect_err("cancel");
        assert_eq!(cancelled.code(), MutationErrorCode::Cancelled);
    }

    #[test]
    fn diagnostic_debug_is_redacted() {
        let diagnostic =
            MutationDiagnostic::try_new("code", "secret-value", MutationLimits::default())
                .expect("diagnostic");
        let debug = format!("{diagnostic:?}");
        assert!(!debug.contains("secret-value"));
    }

    #[test]
    fn result_patch_digest_is_stable() {
        let patch = ResultPatch::replace(Some(SampleResult::new("sample")));
        assert_eq!(
            canonical_result_patch_for_tests(&patch),
            canonical_result_patch_for_tests(&patch)
        );
    }

    fn scoped_result(label: &str, body: Option<&[u8]>) -> SampleResult {
        let mut result = SampleResult::new(label);
        result.set_response_data(body.map(SampleData::from));
        result.set_response_headers_text("response\r\n\0header");
        result.set_request_headers_text("request\nheader");
        result.set_url_text("https://example.test/\r\n");
        result.set_response_code_text("200\0");
        result.set_response_message_text("OK\n");
        result.set_data_encoding_name("UTF-8");
        result.set_content_type_text("text/plain; charset=UTF-8");
        result
    }

    fn scoped_resolver() -> ResponseInputSetResolver {
        ResponseInputSetResolver::new(ResponseLimits::default()).expect("response resolver")
    }

    #[test]
    fn response_target_matrix_reads_only_the_requested_captured_field() {
        let mut result = scoped_result("target", Some(b"body"));
        result.set_response_file_text("opaque-result-file");
        let file_bytes = BoundedBytes::try_new(b"file", 32).expect("file bytes");
        let capability = FileCapability::try_new(
            7,
            file_bytes.len() as u64,
            Digest32::sha256(file_bytes.as_bytes()),
        )
        .expect("file capability");
        let resolver = scoped_resolver().with_file_resolver(Arc::new(FileResolver));
        let variables = BTreeMap::new();
        let policy = ResponseDecodePolicy::default();

        let body = resolver
            .resolve(
                Some(&result),
                &variables,
                &ResponseScope::Current,
                ResponseTarget::Body,
                &policy,
            )
            .expect("body")
            .samples()
            .expect("samples")
            .items()[0]
            .selected()
            .clone();
        assert!(
            matches!(body, Presence::Present(ResponseSelection::Bytes(value)) if value.as_bytes() == b"body")
        );

        let response_headers = resolver
            .resolve(
                Some(&result),
                &variables,
                &ResponseScope::Current,
                ResponseTarget::ResponseHeaders,
                &policy,
            )
            .expect("response headers")
            .samples()
            .expect("samples")
            .items()[0]
            .selected()
            .clone();
        assert!(
            matches!(response_headers, Presence::Present(ResponseSelection::SourceText(value)) if value.as_bytes().starts_with(b"response"))
        );

        for (target, expected) in [
            (
                ResponseTarget::RequestHeaders,
                b"request\nheader".as_slice(),
            ),
            (ResponseTarget::Url, b"https://example.test/\r\n".as_slice()),
            (ResponseTarget::ResponseCode, b"200\0".as_slice()),
            (ResponseTarget::ResponseMessage, b"OK\n".as_slice()),
        ] {
            let selected = resolver
                .resolve(
                    Some(&result),
                    &variables,
                    &ResponseScope::Current,
                    target,
                    &policy,
                )
                .expect("text target")
                .samples()
                .expect("samples")
                .items()[0]
                .selected()
                .clone();
            assert!(
                matches!(selected, Presence::Present(ResponseSelection::SourceText(value)) if value.as_bytes() == expected)
            );
        }

        let file = resolver
            .resolve(
                Some(&result),
                &variables,
                &ResponseScope::Current,
                ResponseTarget::AllowlistedFile(capability),
                &policy,
            )
            .expect("file")
            .samples()
            .expect("samples")
            .items()[0]
            .selected()
            .clone();
        assert!(
            matches!(file, Presence::Present(ResponseSelection::Bytes(value)) if value.as_bytes() == b"file")
        );

        let html_error = resolver
            .resolve(
                Some(&result),
                &variables,
                &ResponseScope::Current,
                ResponseTarget::BodyUnescapedHtml4,
                &policy,
            )
            .expect_err("provider must be explicit");
        assert_eq!(html_error.code(), MutationErrorCode::ProviderUnavailable);
    }

    #[test]
    fn scoped_body_and_headers_never_substitute_for_each_other() {
        let mut only_headers = SampleResult::new("headers");
        only_headers.set_response_headers_text("X: value");
        let resolver = scoped_resolver();
        let variables = BTreeMap::new();
        let body = resolver
            .resolve(
                Some(&only_headers),
                &variables,
                &ResponseScope::Current,
                ResponseTarget::Body,
                &ResponseDecodePolicy::default(),
            )
            .expect("body")
            .samples()
            .expect("samples")
            .items()[0]
            .selected()
            .clone();
        assert!(body.is_missing());
        let headers = resolver
            .resolve(
                Some(&only_headers),
                &variables,
                &ResponseScope::Current,
                ResponseTarget::ResponseHeaders,
                &ResponseDecodePolicy::default(),
            )
            .expect("headers")
            .samples()
            .expect("samples")
            .items()[0]
            .selected()
            .clone();
        assert!(headers.is_present());
    }

    #[test]
    fn scoped_missing_empty_and_no_current_are_distinct() {
        let missing = scoped_result("missing", None);
        let mut empty = scoped_result("empty", Some(b""));
        empty.set_response_headers(Some(HeaderBlock::empty()));
        let resolver = scoped_resolver();
        let variables = BTreeMap::new();
        let missing_value = resolver
            .resolve(
                Some(&missing),
                &variables,
                &ResponseScope::Current,
                ResponseTarget::Body,
                &ResponseDecodePolicy::default(),
            )
            .expect("missing")
            .samples()
            .expect("samples")
            .items()[0]
            .selected()
            .clone();
        assert!(missing_value.is_missing());
        let empty_value = resolver
            .resolve(
                Some(&empty),
                &variables,
                &ResponseScope::Current,
                ResponseTarget::Body,
                &ResponseDecodePolicy::default(),
            )
            .expect("empty")
            .samples()
            .expect("samples")
            .items()[0]
            .selected()
            .clone();
        assert!(
            matches!(empty_value, Presence::Present(ResponseSelection::Bytes(value)) if value.is_empty())
        );
        let no_current = resolver
            .resolve(
                None,
                &variables,
                &ResponseScope::Current,
                ResponseTarget::Body,
                &ResponseDecodePolicy::default(),
            )
            .expect("no current");
        assert!(no_current.is_no_current_result());
    }

    #[test]
    fn variable_scope_bypasses_sample_target_and_preserves_empty() {
        let resolver = scoped_resolver();
        let variables = BTreeMap::from([(String::from("empty"), String::new())]);
        let empty = resolver
            .resolve(
                None,
                &variables,
                &ResponseScope::variable("empty"),
                ResponseTarget::BodyUnescapedHtml4,
                &ResponseDecodePolicy::default(),
            )
            .expect("variable")
            .variable()
            .expect("variable value")
            .clone();
        assert!(matches!(empty, Presence::Present(value) if value.is_empty()));
        let missing = resolver
            .resolve(
                Some(&scoped_result("ignored", Some(b"sample"))),
                &variables,
                &ResponseScope::variable("missing"),
                ResponseTarget::AllowlistedFile(
                    FileCapability::try_new(8, 4, Digest32::sha256(b"file")).expect("cap"),
                ),
                &ResponseDecodePolicy::default(),
            )
            .expect("missing variable")
            .variable()
            .expect("variable result")
            .clone();
        assert!(missing.is_missing());
    }

    #[test]
    fn current_children_and_all_are_ordered_depth_first() {
        let mut root = scoped_result("root", Some(b"root"));
        let mut first = scoped_result("first", Some(b"first"));
        first
            .try_add_sub_result(
                scoped_result("first-child", Some(b"first-child")),
                ValidationLimits::default(),
            )
            .expect("first child");
        root.try_add_sub_result(first, ValidationLimits::default())
            .expect("first");
        root.try_add_sub_result(
            scoped_result("second", Some(b"second")),
            ValidationLimits::default(),
        )
        .expect("second");
        let resolver = scoped_resolver();
        let variables = BTreeMap::new();
        let labels = |scope: ResponseScope| {
            resolver
                .resolve(
                    Some(&root),
                    &variables,
                    &scope,
                    ResponseTarget::Body,
                    &ResponseDecodePolicy::default(),
                )
                .expect("scope")
                .samples()
                .expect("samples")
                .items()
                .iter()
                .map(|item| match item.selected() {
                    Presence::Present(ResponseSelection::Bytes(value)) => {
                        String::from_utf8(value.as_bytes().to_vec()).expect("label bytes")
                    }
                    Presence::Missing | Presence::Present(ResponseSelection::SourceText(_)) => {
                        String::new()
                    }
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(labels(ResponseScope::Current), vec![String::from("root")]);
        assert_eq!(
            labels(ResponseScope::Subresults),
            vec![String::from("first"), String::from("second")]
        );
        let all = resolver
            .resolve(
                Some(&root),
                &variables,
                &ResponseScope::All,
                ResponseTarget::Body,
                &ResponseDecodePolicy::default(),
            )
            .expect("all")
            .samples()
            .expect("samples")
            .clone();
        assert_eq!(all.items().len(), 4);
        assert_eq!(all.items()[0].origin.path(), &[]);
        assert_eq!(all.items()[1].origin.path(), &[0]);
        assert_eq!(all.items()[2].origin.path(), &[0, 0]);
        assert_eq!(all.items()[3].origin.path(), &[1]);
    }

    #[test]
    fn scope_depth_and_item_bounds_reject_without_truncating() {
        let mut root = scoped_result("root", Some(b"root"));
        let mut child = scoped_result("child", Some(b"child"));
        child
            .try_add_sub_result(
                scoped_result("grandchild", Some(b"grandchild")),
                ValidationLimits::default(),
            )
            .expect("grandchild");
        root.try_add_sub_result(child, ValidationLimits::default())
            .expect("child");
        root.try_add_sub_result(
            scoped_result("sibling", Some(b"sibling")),
            ValidationLimits::default(),
        )
        .expect("sibling");
        let variables = BTreeMap::new();
        let depth_limited =
            ResponseInputSetResolver::new(ResponseLimits::default().with_depth(1)).expect("limits");
        let error = depth_limited
            .resolve(
                Some(&root),
                &variables,
                &ResponseScope::All,
                ResponseTarget::Body,
                &ResponseDecodePolicy::default(),
            )
            .expect_err("grandchild depth");
        assert_eq!(error.code(), MutationErrorCode::Limit);
        let count_limited =
            ResponseInputSetResolver::new(ResponseLimits::default().with_items(2)).expect("limits");
        let error = count_limited
            .resolve(
                Some(&root),
                &variables,
                &ResponseScope::All,
                ResponseTarget::Body,
                &ResponseDecodePolicy::default(),
            )
            .expect_err("item count");
        assert_eq!(error.code(), MutationErrorCode::Limit);
    }

    #[test]
    fn known_malformed_encoding_replaces_and_unknown_encoding_is_typed() {
        let mut result = scoped_result("encoding", Some(&[0xff, b'a']));
        result.set_data_encoding_name("UTF-8");
        let resolver = scoped_resolver();
        let variables = BTreeMap::new();
        let selected = resolver
            .resolve(
                Some(&result),
                &variables,
                &ResponseScope::Current,
                ResponseTarget::BodyAsDocumentText,
                &ResponseDecodePolicy::default(),
            )
            .expect_err("document provider is unavailable after decoding");
        assert_eq!(selected.code(), MutationErrorCode::ProviderUnavailable);

        let record = ResponseRecord::try_from_sample_result(&result, &ResponseLimits::default())
            .expect("record");
        let request = match scoped_resolver()
            .provider_request(
                &record,
                ResponseTarget::BodyAsDocumentText,
                &ResponseDecodePolicy::default(),
            )
            .expect("provider request")
        {
            Presence::Present(value) => value,
            Presence::Missing => panic!("present body"),
        };
        assert_eq!(request.kind().as_str(), "document-text");
        assert_eq!(request.input().as_bytes(), "�a".as_bytes());

        let mut result = scoped_result("encoding", Some(&[0xff, b'a']));
        result.set_data_encoding_name("UTF-8");
        let resolver = scoped_resolver().with_provider(Arc::new(EchoProvider));
        let selected = resolver
            .resolve(
                Some(&result),
                &variables,
                &ResponseScope::Current,
                ResponseTarget::BodyAsDocumentText,
                &ResponseDecodePolicy::default(),
            )
            .expect("provider")
            .samples()
            .expect("samples")
            .items()[0]
            .selected()
            .clone();
        assert!(
            matches!(selected, Presence::Present(ResponseSelection::SourceText(value)) if value.as_bytes() == "�a".as_bytes())
        );

        let mut unknown = scoped_result("unknown", Some(b"bytes"));
        unknown.set_data_encoding_name("x-unknown");
        let error = scoped_resolver()
            .resolve(
                Some(&unknown),
                &variables,
                &ResponseScope::Current,
                ResponseTarget::BodyUnescapedHtml4,
                &ResponseDecodePolicy::default(),
            )
            .expect_err("unknown encoding");
        assert_eq!(error.code(), MutationErrorCode::ProviderUnavailable);
    }

    #[test]
    fn result_filename_is_metadata_only_and_file_checks_are_pre_and_post_bound() {
        let mut result = scoped_result("file", Some(b"body"));
        result.set_response_file_text("not-an-input");
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let resolver = ResponseInputSetResolver::new(ResponseLimits::default().with_file_bytes(3))
            .expect("limits")
            .with_file_resolver(Arc::new(CountingFileResolver {
                value: b"file".to_vec(),
                calls: Arc::clone(&calls),
            }));
        let capability = FileCapability::try_new(9, 4, Digest32::sha256(b"file")).expect("cap");
        let error = resolver
            .resolve(
                Some(&result),
                &BTreeMap::new(),
                &ResponseScope::Current,
                ResponseTarget::AllowlistedFile(capability),
                &ResponseDecodePolicy::default(),
            )
            .expect_err("pre-bound");
        assert_eq!(error.code(), MutationErrorCode::Limit);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);

        let capability =
            FileCapability::try_new(10, 8, Digest32::sha256(b"too-long")).expect("cap");
        let resolver = ResponseInputSetResolver::new(ResponseLimits::default().with_file_bytes(4))
            .expect("limits")
            .with_file_resolver(Arc::new(CountingFileResolver {
                value: b"too-long".to_vec(),
                calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            }));
        let error = resolver
            .resolve(
                Some(&result),
                &BTreeMap::new(),
                &ResponseScope::Current,
                ResponseTarget::AllowlistedFile(capability),
                &ResponseDecodePolicy::default(),
            )
            .expect_err("post-bound");
        assert_eq!(error.code(), MutationErrorCode::Limit);

        let resolver = scoped_resolver().with_file_resolver(Arc::new(CountingFileResolver {
            value: b"file".to_vec(),
            calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }));
        let bad_digest = FileCapability::try_new(11, 4, Digest32::sha256(b"other")).expect("cap");
        let error = resolver
            .resolve(
                Some(&result),
                &BTreeMap::new(),
                &ResponseScope::Current,
                ResponseTarget::AllowlistedFile(bad_digest),
                &ResponseDecodePolicy::default(),
            )
            .expect_err("digest");
        assert_eq!(error.code(), MutationErrorCode::ProviderUnavailable);
    }

    #[test]
    fn raw_source_accepts_controls_and_debug_is_redacted() {
        let source = BoundedSourceText::try_from_bytes(b"secret\r\n\0\xff", 64).expect("source");
        assert_eq!(source.as_bytes(), b"secret\r\n\0\xff");
        assert!(source.as_str().is_none());
        let debug = format!("{source:?}");
        assert!(!debug.contains("secret"));
        let record = ResponseRecord::try_from_sample_result(
            &scoped_result("raw", Some(b"secret\r\n\0\xff")),
            &ResponseLimits::default(),
        )
        .expect("record");
        let debug = format!("{record:?}");
        assert!(!debug.contains("secret"));
    }

    #[test]
    fn response_record_and_variable_bounds_reject_before_selection() {
        let oversized = scoped_result("oversized", Some(b"1234"));
        let resolver = ResponseInputSetResolver::new(ResponseLimits::default().with_body_bytes(3))
            .expect("limits");
        let error = resolver
            .resolve(
                Some(&oversized),
                &BTreeMap::new(),
                &ResponseScope::Current,
                ResponseTarget::Body,
                &ResponseDecodePolicy::default(),
            )
            .expect_err("body bound");
        assert_eq!(error.code(), MutationErrorCode::Limit);

        let resolver =
            ResponseInputSetResolver::new(ResponseLimits::default().with_variable_bytes(3))
                .expect("limits");
        let variables = BTreeMap::from([(String::from("value"), String::from("1234"))]);
        let error = resolver
            .resolve(
                None,
                &variables,
                &ResponseScope::variable("value"),
                ResponseTarget::Body,
                &ResponseDecodePolicy::default(),
            )
            .expect_err("variable bound");
        assert_eq!(error.code(), MutationErrorCode::Limit);

        let resolver =
            ResponseInputSetResolver::new(ResponseLimits::default().with_provider_bytes(2, 2))
                .expect("limits");
        let mut body = SampleResult::new("provider-input");
        body.set_response_data(Some(SampleData::from(b"123".as_slice())));
        let error = resolver
            .resolve(
                Some(&body),
                &BTreeMap::new(),
                &ResponseScope::Current,
                ResponseTarget::BodyAsDocumentText,
                &ResponseDecodePolicy::default(),
            )
            .expect_err("provider input bound");
        assert_eq!(error.code(), MutationErrorCode::Limit);
    }

    struct EchoProvider;

    impl ResponseProvider for EchoProvider {
        fn transform(
            &self,
            request: &ResponseProviderRequest,
        ) -> Result<BoundedSourceText, MutationError> {
            Ok(request.input().clone())
        }
    }

    struct CountingFileResolver {
        value: Vec<u8>,
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl AllowlistedFileResolver for CountingFileResolver {
        fn resolve_file(&self, _capability: FileCapability) -> Result<BoundedBytes, MutationError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            BoundedBytes::try_new(&self.value, DEFAULT_MAX_RESPONSE_BYTES)
        }
    }
}
