// SPDX-License-Identifier: Apache-2.0
//! HTTP method, body, and request construction.

use crate::{Headers, HttpError, Url};

/// Hard maximum for one materialized outbound HTTP entity.
///
/// This is the request-side ceiling from `http.parser-limits/1`. Client
/// configuration may select a lower limit, but a request constructor never
/// promises to retain an entity larger than this value.
pub const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024 * 1024;
/// Hard maximum for ordered request fields.
pub const MAX_REQUEST_HEADER_FIELDS: usize = 1_024;
/// Hard maximum for the estimated request-header wire bytes.
pub const MAX_REQUEST_HEADER_BYTES: usize = 1024 * 1024;
/// Hard maximum number of URL-encoded fields in one entity.
pub const MAX_FORM_FIELDS: usize = 4_096;
/// Hard maximum URL-encoded entity bytes.
pub const MAX_FORM_BYTES: usize = 1024 * 1024;
/// Hard maximum number of multipart parts in one entity.
pub const MAX_MULTIPART_PARTS: usize = 1_024;
/// Hard maximum multipart boundary bytes.
pub const MAX_MULTIPART_BOUNDARY_BYTES: usize = 256;
/// Hard maximum generated header bytes for one multipart part.
pub const MAX_MULTIPART_PART_HEADER_BYTES: usize = 256 * 1024;
/// Hard maximum bytes in one multipart part body.
pub const MAX_MULTIPART_PART_BODY_BYTES: usize = 256 * 1024 * 1024;
/// Hard maximum bytes in a configured content-encoding name.
pub const MAX_CONTENT_ENCODING_BYTES: usize = 256;
/// Deterministic chunk size used when a transport serializes a chunked body.
pub const CHUNKED_WIRE_CHUNK_BYTES: usize = 16 * 1024;

/// An HTTP request method, preserving extension methods.
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Method {
    /// GET requests retrieve a representation.
    #[default]
    Get,
    /// HEAD requests retrieve response metadata without a body.
    Head,
    /// POST requests submit a representation.
    Post,
    /// PUT requests replace a representation.
    Put,
    /// DELETE requests remove a representation.
    Delete,
    /// PATCH requests partially modify a representation.
    Patch,
    /// OPTIONS requests inspect server capabilities.
    Options,
    /// TRACE requests echo the request path.
    Trace,
    /// CONNECT requests establish a tunnel.
    Connect,
    /// An extension method not known by this crate.
    Custom(String),
}

impl Method {
    /// Parses a method name while preserving unknown token methods.
    pub fn parse(value: impl Into<String>) -> Result<Self, HttpError> {
        let value = value.into();
        if value.len() > 256 || value.is_empty() || !value.bytes().all(is_token_byte) {
            return Err(HttpError::InvalidMethod("invalid method token".to_owned()));
        }
        Ok(match value.to_ascii_uppercase().as_str() {
            "GET" => Self::Get,
            "HEAD" => Self::Head,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "DELETE" => Self::Delete,
            "PATCH" => Self::Patch,
            "OPTIONS" => Self::Options,
            "TRACE" => Self::Trace,
            "CONNECT" => Self::Connect,
            _ => Self::Custom(value),
        })
    }

    /// Returns the wire spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Patch => "PATCH",
            Self::Options => "OPTIONS",
            Self::Trace => "TRACE",
            Self::Connect => "CONNECT",
            Self::Custom(value) => value,
        }
    }

    /// Returns whether this method is safe to retry after a redirect.
    #[must_use]
    pub const fn is_idempotent(&self) -> bool {
        matches!(
            self,
            Self::Get | Self::Head | Self::Put | Self::Delete | Self::Options | Self::Trace
        )
    }

    /// Returns whether this generic request model can carry an entity.
    /// Provider adapters may apply a narrower method policy (for example,
    /// JMeter's Java implementation has no GET entity path); HEAD and TRACE
    /// remain non-entity methods in the pure model.
    #[must_use]
    pub const fn allows_body(&self) -> bool {
        !matches!(self, Self::Head | Self::Trace)
    }
}

impl std::fmt::Display for Method {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl TryFrom<&str> for Method {
    type Error = HttpError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

/// A bounded request body.
#[derive(Clone, Default, Eq, Hash, PartialEq)]
pub enum Body {
    /// No request payload.
    #[default]
    Empty,
    /// An opaque byte payload.
    Bytes(Vec<u8>),
}

impl std::fmt::Debug for Body {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Body")
            .field("bytes", &self.len())
            .field("present", &self.is_present())
            .finish()
    }
}

impl Body {
    /// Creates a byte body.
    #[must_use]
    pub fn bytes(value: impl Into<Vec<u8>>) -> Self {
        Self::Bytes(value.into())
    }

    /// Creates a byte body after applying the protocol hard maximum.
    pub fn try_bytes(value: impl Into<Vec<u8>>) -> Result<Self, HttpError> {
        let value = value.into();
        if value.len() > MAX_REQUEST_BODY_BYTES {
            return Err(HttpError::RequestBodyLimit {
                actual: value.len(),
                maximum: MAX_REQUEST_BODY_BYTES,
            });
        }
        Ok(Self::Bytes(value))
    }

    /// Creates a UTF-8 text body.
    #[must_use]
    pub fn text(value: impl Into<String>) -> Self {
        Self::Bytes(value.into().into_bytes())
    }

    /// Creates a UTF-8 text body after applying the protocol hard maximum.
    pub fn try_text(value: impl Into<String>) -> Result<Self, HttpError> {
        Self::try_bytes(value.into().into_bytes())
    }

    /// Returns the body bytes, or an empty slice for [`Body::Empty`].
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Empty => &[],
            Self::Bytes(value) => value,
        }
    }

    /// Returns the body length.
    #[must_use]
    pub const fn len(&self) -> usize {
        match self {
            Self::Empty => 0,
            Self::Bytes(value) => value.len(),
        }
    }

    /// Returns whether the body contains no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns whether this is a present byte body, including a zero-length one.
    #[must_use]
    pub const fn is_present(&self) -> bool {
        matches!(self, Self::Bytes(_))
    }

    /// Consumes the body and returns its bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            Self::Empty => Vec::new(),
            Self::Bytes(value) => value,
        }
    }
}

/// Request entity framing selected by a caller or transport adapter.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum RequestFraming {
    /// Add `Content-Length` for a present body unless transfer coding is
    /// explicitly supplied by the caller.
    #[default]
    Auto,
    /// Use a `Content-Length` field and reject transfer coding.
    ContentLength,
    /// Use `Transfer-Encoding: chunked` and reject `Content-Length`.
    Chunked,
}

/// An ordered URL-encoded field, retaining JMeter's `use_equals` distinction.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct FormField {
    name: String,
    value: String,
    use_equals: bool,
}

/// One JMeter `HTTPArgument` before it is projected into a request.
///
/// `metadata` is normally `=`, but it is retained because JMeter preserves
/// the separator independently from `use_equals`.  `always_encode=false`
/// means that the caller supplied an already encoded name/value (or a raw
/// body fragment); the pure core never guesses whether such bytes should be
/// repaired.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct HttpArgument {
    name: String,
    value: String,
    metadata: String,
    use_equals: bool,
    always_encode: bool,
    content_type: Option<String>,
}

impl std::fmt::Debug for HttpArgument {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpArgument")
            .field("name_bytes", &self.name.len())
            .field("value_bytes", &self.value.len())
            .field("metadata_bytes", &self.metadata.len())
            .field("use_equals", &self.use_equals)
            .field("always_encode", &self.always_encode)
            .field("content_type", &self.content_type.as_deref().map(str::len))
            .finish()
    }
}

impl HttpArgument {
    /// Creates the usual encoded `name=value` argument.
    #[must_use]
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            metadata: "=".to_owned(),
            use_equals: true,
            always_encode: true,
            content_type: None,
        }
    }

    /// Creates an argument with all wire-preserving JMeter flags explicit.
    #[must_use]
    pub fn with_options(
        name: impl Into<String>,
        value: impl Into<String>,
        metadata: impl Into<String>,
        use_equals: bool,
        always_encode: bool,
    ) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            metadata: metadata.into(),
            use_equals,
            always_encode,
            content_type: None,
        }
    }

    /// Creates a raw argument whose value is not URL-encoded.
    #[must_use]
    pub fn raw(value: impl Into<String>) -> Self {
        Self::with_options("", value, "=", false, false)
    }

    /// Returns a copy with explicit separator metadata.
    #[must_use]
    pub fn with_metadata(mut self, metadata: impl Into<String>) -> Self {
        self.metadata = metadata.into();
        self
    }

    /// Returns a copy with an explicit `use_equals` flag.
    #[must_use]
    pub fn with_use_equals(mut self, value: bool) -> Self {
        self.use_equals = value;
        // JMeter's HTTPArgument#setUseEquals keeps the serialized metadata
        // and the boolean property in lockstep.  Keep the fully explicit
        // `with_options` constructor for imported/unknown data, but make this
        // convenience mutator obey the upstream setter semantics.
        self.metadata = if value { "=" } else { "" }.to_owned();
        self
    }

    /// Returns a copy with an explicit URL-encoding flag.
    #[must_use]
    pub const fn with_always_encode(mut self, value: bool) -> Self {
        self.always_encode = value;
        self
    }

    /// Returns a copy with a multipart text-part media type.
    #[must_use]
    pub fn with_content_type(mut self, value: impl Into<String>) -> Self {
        self.content_type = Some(value.into());
        self
    }

    /// Returns the argument name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the argument value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Returns the separator metadata.
    #[must_use]
    pub fn metadata(&self) -> &str {
        &self.metadata
    }

    /// Returns whether JMeter's argument metadata is an equals separator.
    #[must_use]
    pub const fn use_equals(&self) -> bool {
        self.use_equals
    }

    /// Returns whether the name/value are URL-encoded before emission.
    #[must_use]
    pub const fn always_encode(&self) -> bool {
        self.always_encode
    }

    /// Returns the optional multipart text-part media type.
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }
}

impl From<FormField> for HttpArgument {
    fn from(field: FormField) -> Self {
        let use_equals = field.use_equals;
        Self {
            name: field.name,
            value: field.value,
            metadata: if use_equals {
                "=".to_owned()
            } else {
                String::new()
            },
            use_equals,
            always_encode: true,
            content_type: None,
        }
    }
}

/// A body input descriptor accepted by the pure sampler builder.
///
/// The pure HTTP core can only construct a replayable materialized request.
/// Files and one-shot streams remain capabilities at the adapter boundary;
/// they are represented here so accidentally dropping them becomes an
/// explicit error rather than a silent empty body.
#[derive(Clone, Default, Eq, Hash, PartialEq)]
pub enum RequestBodySource {
    /// No body is present.
    #[default]
    Empty,
    /// Already-authorized bytes, replayable by cloning the request.
    Bytes(Vec<u8>),
    /// A one-shot source that requires an adapter-owned streaming path.
    OneShot,
    /// A file capability whose bytes are not available to this pure crate.
    File {
        /// Whether the adapter could replay the capability.
        replayability: RequestReplayability,
    },
}

impl std::fmt::Debug for RequestBodySource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => formatter.write_str("Empty"),
            Self::Bytes(value) => formatter
                .debug_struct("Bytes")
                .field("bytes", &value.len())
                .finish(),
            Self::OneShot => formatter.write_str("OneShot(<reader>)"),
            Self::File { replayability } => formatter
                .debug_struct("File")
                .field("replayability", replayability)
                .finish(),
        }
    }
}

impl RequestBodySource {
    /// Creates a bounded materialized source.
    pub fn bytes(value: impl Into<Vec<u8>>) -> Result<Self, HttpError> {
        let value = value.into();
        if value.len() > MAX_REQUEST_BODY_BYTES {
            return Err(HttpError::RequestBodyLimit {
                actual: value.len(),
                maximum: MAX_REQUEST_BODY_BYTES,
            });
        }
        Ok(Self::Bytes(value))
    }

    /// Creates an explicit one-shot source marker.
    #[must_use]
    pub const fn one_shot() -> Self {
        Self::OneShot
    }

    /// Creates an explicit file-capability marker without accepting a path.
    #[must_use]
    pub const fn file(replayability: RequestReplayability) -> Self {
        Self::File { replayability }
    }

    /// Returns the source replayability.
    #[must_use]
    pub const fn replayability(&self) -> RequestReplayability {
        match self {
            Self::Empty | Self::Bytes(_) => RequestReplayability::Replayable,
            Self::OneShot => RequestReplayability::OneShot,
            Self::File { replayability } => *replayability,
        }
    }

    /// Projects the protocol-v1 body capability without opening or reading a
    /// file. Materialized bytes remain replayable; stream/file capabilities
    /// stay explicit and are rejected if passed to [`HttpSamplerRequest::build`].
    #[must_use]
    pub fn from_body_source(source: &crate::BodySource) -> Self {
        match source {
            crate::BodySource::Empty => Self::Empty,
            crate::BodySource::Bytes(value) => Self::Bytes(value.as_slice().to_vec()),
            crate::BodySource::File(value) => Self::File {
                replayability: match value.replayability {
                    crate::protocol_v1::Replayability::Replayable => {
                        RequestReplayability::Replayable
                    }
                    crate::protocol_v1::Replayability::OneShot => RequestReplayability::OneShot,
                },
            },
            crate::BodySource::OneShot(_) => Self::OneShot,
        }
    }
}

/// Replayability known at request construction time.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum RequestReplayability {
    /// The request can be cloned for a redirect or explicitly owned retry.
    #[default]
    Replayable,
    /// The body requires a one-shot adapter and cannot be materialized here.
    OneShot,
}

impl From<crate::protocol_v1::Replayability> for RequestReplayability {
    fn from(value: crate::protocol_v1::Replayability) -> Self {
        match value {
            crate::protocol_v1::Replayability::Replayable => Self::Replayable,
            crate::protocol_v1::Replayability::OneShot => Self::OneShot,
        }
    }
}

/// Effective HTTP sampler inputs after JMX/default/property resolution.
///
/// This descriptor intentionally contains no JMX, filesystem, environment,
/// randomness, or transport handles.  A caller resolves those concerns first,
/// supplies a deterministic multipart boundary when needed, and then invokes
/// [`Self::build`] to obtain a bounded [`Request`].
#[derive(Clone, Eq, PartialEq)]
pub struct HttpSamplerRequest {
    method: Method,
    url: Url,
    headers: Headers,
    arguments: Vec<HttpArgument>,
    multipart_parts: Vec<MultipartPart>,
    content_encoding: String,
    post_body_raw: bool,
    multipart: bool,
    boundary: Option<String>,
    body_source: RequestBodySource,
}

impl std::fmt::Debug for HttpSamplerRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpSamplerRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &self.headers)
            .field("argument_count", &self.arguments.len())
            .field("multipart_part_count", &self.multipart_parts.len())
            .field("content_encoding", &self.content_encoding)
            .field("post_body_raw", &self.post_body_raw)
            .field("multipart", &self.multipart)
            .field("boundary_bytes", &self.boundary.as_ref().map(String::len))
            .field("body_source", &self.body_source)
            .finish()
    }
}

impl HttpSamplerRequest {
    /// Creates an effective sampler descriptor with JMeter's UTF-8 default.
    #[must_use]
    pub fn new(method: Method, url: Url) -> Self {
        Self {
            method,
            url,
            headers: Headers::new(),
            arguments: Vec::new(),
            multipart_parts: Vec::new(),
            content_encoding: "UTF-8".to_owned(),
            post_body_raw: false,
            multipart: false,
            boundary: None,
            body_source: RequestBodySource::Empty,
        }
    }

    /// Parses an effective absolute URL and creates a descriptor.
    pub fn from_url(method: Method, url: impl Into<String>) -> Result<Self, HttpError> {
        Ok(Self::new(method, Url::parse(url)?))
    }

    /// Returns the effective sampler method.
    #[must_use]
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// Returns the effective sampler URL.
    #[must_use]
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Returns the effective sampler headers.
    #[must_use]
    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    /// Returns the ordered effective JMeter arguments.
    #[must_use]
    pub fn argument_list(&self) -> &[HttpArgument] {
        &self.arguments
    }

    /// Returns the ordered explicit multipart file/byte parts.
    #[must_use]
    pub fn multipart_part_list(&self) -> &[MultipartPart] {
        &self.multipart_parts
    }

    /// Returns the configured content encoding spelling.
    #[must_use]
    pub fn content_encoding_value(&self) -> &str {
        &self.content_encoding
    }

    /// Returns whether JMeter raw-body mode is enabled.
    #[must_use]
    pub const fn is_post_body_raw(&self) -> bool {
        self.post_body_raw
    }

    /// Returns whether JMeter multipart mode is enabled.
    #[must_use]
    pub const fn is_multipart(&self) -> bool {
        self.multipart
    }

    /// Returns the explicit multipart boundary, if configured.
    #[must_use]
    pub fn boundary(&self) -> Option<&str> {
        self.boundary.as_deref()
    }

    /// Returns the effective body capability descriptor.
    #[must_use]
    pub const fn body_source_ref(&self) -> &RequestBodySource {
        &self.body_source
    }

    /// Sets the content encoding used for text arguments and raw text.
    #[must_use]
    pub fn content_encoding(mut self, value: impl Into<String>) -> Self {
        self.content_encoding = value.into();
        self
    }

    /// Sets JMeter's `postBodyRaw` mode.
    #[must_use]
    pub const fn post_body_raw(mut self, value: bool) -> Self {
        self.post_body_raw = value;
        self
    }

    /// Enables multipart mode with an explicit deterministic boundary.
    #[must_use]
    pub fn multipart(mut self, boundary: impl Into<String>) -> Self {
        self.multipart = true;
        self.boundary = Some(boundary.into());
        self
    }

    /// Adds one ordered JMeter argument.
    #[must_use]
    pub fn argument(mut self, argument: impl Into<HttpArgument>) -> Self {
        self.arguments.push(argument.into());
        self
    }

    /// Replaces the ordered JMeter argument list.
    #[must_use]
    pub fn arguments(
        mut self,
        arguments: impl IntoIterator<Item = impl Into<HttpArgument>>,
    ) -> Self {
        self.arguments = arguments.into_iter().map(Into::into).collect();
        self
    }

    /// Replaces arguments while enforcing the URL/form hard count bound.
    pub fn try_arguments(
        mut self,
        arguments: impl IntoIterator<Item = impl Into<HttpArgument>>,
    ) -> Result<Self, HttpError> {
        self.arguments.clear();
        for argument in arguments {
            if self.arguments.len() >= MAX_FORM_FIELDS {
                return Err(HttpError::resource_limit("form field count"));
            }
            self.arguments.push(argument.into());
        }
        Ok(self)
    }

    /// Adds one already-authorized multipart file/byte part.
    #[must_use]
    pub fn multipart_part(mut self, part: MultipartPart) -> Self {
        self.multipart_parts.push(part);
        self.multipart = true;
        self
    }

    /// Replaces the explicit multipart file/byte parts.
    #[must_use]
    pub fn multipart_parts(mut self, parts: impl IntoIterator<Item = MultipartPart>) -> Self {
        self.multipart_parts = parts.into_iter().collect();
        self.multipart = true;
        self
    }

    /// Replaces explicit multipart parts while enforcing the part-count bound.
    pub fn try_multipart_parts(
        mut self,
        parts: impl IntoIterator<Item = MultipartPart>,
    ) -> Result<Self, HttpError> {
        self.multipart_parts.clear();
        for part in parts {
            if self.multipart_parts.len() >= MAX_MULTIPART_PARTS {
                return Err(HttpError::resource_limit("multipart part count"));
            }
            self.multipart_parts.push(part);
        }
        self.multipart = true;
        Ok(self)
    }

    /// Adds a header that is part of the effective sampler request.
    pub fn header(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, HttpError> {
        self.headers.insert(name, value)?;
        Ok(self)
    }

    /// Supplies an explicit body capability/materialization descriptor.
    #[must_use]
    pub fn body_source(mut self, source: RequestBodySource) -> Self {
        self.body_source = source;
        self
    }

    /// Supplies already-encoded raw request bytes.
    pub fn raw_body(mut self, value: impl Into<Vec<u8>>) -> Result<Self, HttpError> {
        self.body_source = RequestBodySource::bytes(value)?;
        self.post_body_raw = true;
        Ok(self)
    }

    /// Supplies a raw text body that is encoded with `content_encoding` at
    /// build time. This is equivalent to one `always_encode=false` argument.
    #[must_use]
    pub fn raw_text(mut self, value: impl Into<String>) -> Self {
        self.post_body_raw = true;
        self.arguments.push(HttpArgument::raw(value));
        self
    }

    /// Builds a bounded request from the effective sampler inputs.
    pub fn build(self) -> Result<Request, HttpError> {
        // Keep the pre-existing compatibility path stable for callers that
        // already compare against JMeter HttpClient4 request bytes. New
        // provider-neutral callers can opt into `build_generic` explicitly.
        build_sampler_request(self, SamplerBuildMode::HttpClient4)
    }

    /// Builds using generic JMeter sampler serialization rules.
    ///
    /// This does not select a Java runtime or an HTTP client library; those
    /// provider identities belong to the transport/application edge.
    pub fn build_generic(self) -> Result<Request, HttpError> {
        build_sampler_request(self, SamplerBuildMode::Generic)
    }

    /// Builds using the JMeter HttpClient4 entity serialization details.
    ///
    /// This explicit entry point is useful for an oracle comparison.  The
    /// default [`Self::build`] method remains a compatibility alias for
    /// this provider-specific projection.
    pub fn build_httpclient4(self) -> Result<Request, HttpError> {
        build_sampler_request(self, SamplerBuildMode::HttpClient4)
    }

    /// Builds using the JMeter Java implementation's query-string form
    /// projection.  The method does not open a URLConnection; methods whose
    /// entity path or multipart formatting policy is unavailable to that
    /// provider return an explicit unsupported error rather than dropping or
    /// rewriting the body.
    pub fn build_java(self) -> Result<Request, HttpError> {
        build_sampler_request(self, SamplerBuildMode::Java)
    }

    /// Alias emphasizing that this is the request-construction operation.
    pub fn build_request(self) -> Result<Request, HttpError> {
        self.build()
    }
}

/// Compatibility alias for callers that name the descriptor a request spec.
pub type HttpRequestSpec = HttpSamplerRequest;
/// Compatibility alias for callers that name sampler arguments directly.
pub type SamplerArgument = HttpArgument;

impl std::fmt::Debug for FormField {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FormField")
            .field("name_bytes", &self.name.len())
            .field("value_bytes", &self.value.len())
            .field("use_equals", &self.use_equals)
            .finish()
    }
}

impl FormField {
    /// Creates a normal `name=value` field.
    #[must_use]
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            use_equals: true,
        }
    }

    /// Creates a field without an `=` separator.
    #[must_use]
    pub fn without_equals(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: String::new(),
            use_equals: false,
        }
    }

    /// Returns the field name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the field value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Returns whether the encoded field includes `=`.
    #[must_use]
    pub const fn use_equals(&self) -> bool {
        self.use_equals
    }
}

/// One bounded multipart part. File parts are supplied as already-authorized
/// bytes by the application edge; this pure crate never opens a path.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct MultipartPart {
    name: String,
    body: Vec<u8>,
    filename: Option<String>,
    content_type: Option<String>,
}

impl std::fmt::Debug for MultipartPart {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MultipartPart")
            .field("name_bytes", &self.name.len())
            .field("body_bytes", &self.body.len())
            .field("filename_present", &self.filename.is_some())
            .field("content_type_present", &self.content_type.is_some())
            .finish()
    }
}

impl MultipartPart {
    /// Creates a UTF-8 text field part.
    pub fn field(name: impl Into<String>, value: impl Into<String>) -> Result<Self, HttpError> {
        Self::bytes(name, value.into().into_bytes())
    }

    /// Creates a binary field part without a filename.
    pub fn bytes(name: impl Into<String>, body: impl Into<Vec<u8>>) -> Result<Self, HttpError> {
        Self::new(name.into(), body.into(), None, None)
    }

    /// Creates a file-style part from bytes supplied by an application
    /// capability. No path is accepted, so construction cannot read ambient
    /// filesystem state.
    pub fn file(
        name: impl Into<String>,
        filename: impl Into<String>,
        body: impl Into<Vec<u8>>,
    ) -> Result<Self, HttpError> {
        Self::new(name.into(), body.into(), Some(filename.into()), None)
    }

    /// Creates a file-style part with an explicit media type.
    pub fn file_with_content_type(
        name: impl Into<String>,
        filename: impl Into<String>,
        body: impl Into<Vec<u8>>,
        content_type: impl Into<String>,
    ) -> Result<Self, HttpError> {
        Self::new(
            name.into(),
            body.into(),
            Some(filename.into()),
            Some(content_type.into()),
        )
    }

    fn new(
        name: String,
        body: Vec<u8>,
        filename: Option<String>,
        content_type: Option<String>,
    ) -> Result<Self, HttpError> {
        validate_multipart_parameter(&name, "multipart field name")?;
        if body.len() > MAX_MULTIPART_PART_BODY_BYTES {
            return Err(HttpError::resource_limit("multipart part body bytes"));
        }
        if let Some(filename) = &filename {
            validate_multipart_parameter(filename, "multipart filename")?;
        }
        if let Some(content_type) = &content_type {
            crate::HeaderValue::new(content_type.clone())?;
        }
        Ok(Self {
            name,
            body,
            filename,
            content_type,
        })
    }

    /// Returns the multipart field name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the part body bytes.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Returns the optional filename parameter.
    #[must_use]
    pub fn filename(&self) -> Option<&str> {
        self.filename.as_deref()
    }

    /// Returns the optional part media type.
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }
}

/// A fully constructed HTTP request passed to a transport.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct Request {
    method: Method,
    url: Url,
    headers: Headers,
    body: Body,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Request")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &self.headers)
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

impl Request {
    /// Builds a request from effective JMeter HTTP sampler inputs.
    pub fn from_sampler(sampler: HttpSamplerRequest) -> Result<Self, HttpError> {
        sampler.build()
    }

    /// Creates an empty request.
    #[must_use]
    pub fn new(method: Method, url: Url) -> Self {
        Self {
            method,
            url,
            headers: Headers::new(),
            body: Body::Empty,
        }
    }

    /// Creates a GET request from a URL string.
    pub fn get(url: impl Into<String>) -> Result<Self, HttpError> {
        Ok(Self::new(Method::Get, Url::parse(url)?))
    }

    /// Creates a POST request from a URL and byte body.
    pub fn post(url: impl Into<String>, body: impl Into<Vec<u8>>) -> Result<Self, HttpError> {
        let mut request = Self::new(Method::Post, Url::parse(url)?);
        request.body = Body::try_bytes(body)?;
        Ok(request)
    }

    /// Creates a HEAD request from a URL string.
    pub fn head(url: impl Into<String>) -> Result<Self, HttpError> {
        Ok(Self::new(Method::Head, Url::parse(url)?))
    }

    /// Creates an URL-encoded form POST from ordered field pairs.
    pub fn form_post(
        url: impl Into<String>,
        fields: impl IntoIterator<Item = (impl AsRef<str>, impl AsRef<str>)>,
    ) -> Result<Self, HttpError> {
        let fields = fields
            .into_iter()
            .map(|(name, value)| FormField::new(name.as_ref(), value.as_ref()));
        Self::form_post_fields(url, fields)
    }

    /// Creates a bounded URL-encoded POST from ordered fields.
    pub fn form_post_fields(
        url: impl Into<String>,
        fields: impl IntoIterator<Item = FormField>,
    ) -> Result<Self, HttpError> {
        let body = encode_form_fields(fields)?;
        let mut request = Self::post(url, body)?;
        request.add_header("Content-Type", "application/x-www-form-urlencoded")?;
        Ok(request)
    }

    /// Creates a bounded multipart/form-data POST using the supplied
    /// boundary. Boundary generation belongs to an application capability so
    /// this pure crate does not use ambient randomness.
    pub fn multipart_post(
        url: impl Into<String>,
        boundary: impl AsRef<str>,
        parts: impl IntoIterator<Item = MultipartPart>,
    ) -> Result<Self, HttpError> {
        let boundary = validate_boundary(boundary.as_ref())?;
        let body = encode_multipart(&boundary, parts)?;
        let mut request = Self::post(url, body)?;
        request.add_header(
            "Content-Type",
            format!("multipart/form-data; boundary={boundary}"),
        )?;
        Ok(request)
    }

    /// Returns the request method.
    #[must_use]
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// Returns the request URL.
    #[must_use]
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Returns the fragment-free origin-form target for transport adapters.
    /// URL fragments are retained on [`Url`] for client-side redirect/cache
    /// semantics but must never be emitted on the wire.
    #[must_use]
    pub fn wire_target(&self) -> &str {
        self.url.wire_target()
    }

    /// Returns the ordered request headers.
    #[must_use]
    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    /// Returns mutable ordered request headers.
    #[must_use]
    pub fn headers_mut(&mut self) -> &mut Headers {
        &mut self.headers
    }

    /// Returns the request body.
    #[must_use]
    pub fn body(&self) -> &Body {
        &self.body
    }

    /// Returns mutable request body.
    #[must_use]
    pub fn body_mut(&mut self) -> &mut Body {
        &mut self.body
    }

    /// Sets the request method.
    pub fn set_method(&mut self, method: Method) {
        self.method = method;
    }

    /// Sets the request URL.
    pub fn set_url(&mut self, url: Url) {
        self.url = url;
    }

    /// Sets a body, preserving an explicitly present empty body.
    pub fn set_body(&mut self, body: Body) {
        self.body = body;
    }

    /// Returns this request with one appended header.
    pub fn with_header(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, HttpError> {
        self.add_header(name, value)?;
        Ok(self)
    }

    /// Returns this request with a replacement body.
    #[must_use]
    pub fn with_body(mut self, body: Body) -> Self {
        self.set_body(body);
        self
    }

    /// Appends a validated header.
    pub fn add_header(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), HttpError> {
        self.headers.insert(name, value)
    }

    /// Removes every request header with this name.
    pub fn remove_header(&mut self, name: &str) -> usize {
        self.headers.remove(name)
    }

    /// Adds a deterministic `Content-Length` field when a caller did not
    /// supply one. Existing fields are preserved for adapter-specific framing.
    pub fn ensure_content_length(&mut self) -> Result<(), HttpError> {
        if self.headers.values("content-length").nth(1).is_some() {
            return Err(HttpError::InvalidHeader(
                "duplicate content-length fields".to_owned(),
            ));
        }
        if self.headers.values("transfer-encoding").nth(1).is_some() {
            return Err(HttpError::InvalidHeader(
                "duplicate transfer-encoding fields".to_owned(),
            ));
        }
        if self.headers.contains("transfer-encoding") {
            if !self
                .headers
                .get("transfer-encoding")
                .is_some_and(is_chunked_transfer_encoding)
            {
                return Err(HttpError::InvalidHeader(
                    "unsupported transfer encoding".to_owned(),
                ));
            }
            if self.headers.contains("content-length") {
                return Err(HttpError::InvalidHeader(
                    "content-length cannot accompany chunked transfer encoding".to_owned(),
                ));
            }
            return Ok(());
        }
        if !self.headers.contains("content-length") && self.body.is_present() {
            self.add_header("Content-Length", self.body.len().to_string())?;
        }
        if let Some(value) = self.headers.get("content-length") {
            let declared = parse_content_length(value)?;
            if declared != self.body.len() {
                return Err(HttpError::InvalidHeader(
                    "content-length does not match request body".to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// Validates explicit request framing and returns the resulting mode.
    pub fn framing(&self) -> Result<RequestFraming, HttpError> {
        let transfer = self.headers.get("transfer-encoding");
        let length = self.headers.get("content-length");
        if self.headers.values("content-length").nth(1).is_some() {
            return Err(HttpError::InvalidHeader(
                "duplicate content-length fields".to_owned(),
            ));
        }
        if self.headers.values("transfer-encoding").nth(1).is_some() {
            return Err(HttpError::InvalidHeader(
                "duplicate transfer-encoding fields".to_owned(),
            ));
        }
        if transfer.is_some() && length.is_some() {
            return Err(HttpError::InvalidHeader(
                "content-length cannot accompany transfer encoding".to_owned(),
            ));
        }
        if let Some(transfer) = transfer {
            if !is_chunked_transfer_encoding(transfer) {
                return Err(HttpError::InvalidHeader(
                    "unsupported transfer encoding".to_owned(),
                ));
            }
            return Ok(RequestFraming::Chunked);
        }
        if let Some(length) = length {
            if parse_content_length(length)? != self.body.len() {
                return Err(HttpError::InvalidHeader(
                    "content-length does not match request body".to_owned(),
                ));
            }
            return Ok(RequestFraming::ContentLength);
        }
        Ok(RequestFraming::Auto)
    }

    /// Validates an explicit `Host` field against this URL's authority.
    ///
    /// A missing field is valid: HTTP/1 transports may derive `Host` from the
    /// URL at the wire boundary.  When present, exactly one field is allowed
    /// and its normalized host/effective port must match the URL.  This check
    /// is intentionally separate from [`Self::validate`]: JMeter's Header
    /// Manager can intentionally supply a virtual-host value, while a native
    /// adapter that derives authority must opt into this strict check.
    pub fn validate_host_header(&self) -> Result<(), HttpError> {
        let mut values = self.headers.values("host");
        let Some(value) = values.next() else {
            return Ok(());
        };
        if values.next().is_some() {
            return Err(HttpError::InvalidHeader("duplicate Host fields".to_owned()));
        }
        if self.url.authority_matches(value).unwrap_or(false) {
            Ok(())
        } else {
            Err(HttpError::InvalidHeader(
                "Host conflicts with request authority".to_owned(),
            ))
        }
    }

    /// Validates request limits and method/body consistency.
    pub fn validate(
        &self,
        maximum_body_bytes: usize,
        maximum_headers: usize,
    ) -> Result<(), HttpError> {
        if self.body.len() > maximum_body_bytes {
            return Err(HttpError::RequestBodyLimit {
                actual: self.body.len(),
                maximum: maximum_body_bytes,
            });
        }
        if self.headers.len() > maximum_headers {
            return Err(HttpError::resource_limit("request header count"));
        }
        if self.headers.len() > MAX_REQUEST_HEADER_FIELDS {
            return Err(HttpError::resource_limit("request header count"));
        }
        if self.headers.checked_wire_len()? > MAX_REQUEST_HEADER_BYTES {
            return Err(HttpError::resource_limit("request header bytes"));
        }
        if maximum_body_bytes > MAX_REQUEST_BODY_BYTES {
            // The caller can choose a lower active bound, but never raise the
            // protocol hard ceiling through a `usize::MAX` convenience call.
            if self.body.len() > MAX_REQUEST_BODY_BYTES {
                return Err(HttpError::RequestBodyLimit {
                    actual: self.body.len(),
                    maximum: MAX_REQUEST_BODY_BYTES,
                });
            }
        }
        self.framing()?;
        if !self.method.allows_body() && self.body.is_present() {
            return Err(HttpError::InvalidMethod(format!(
                "{} request cannot carry a request body",
                self.method
            )));
        }
        Ok(())
    }

    /// Starts a checked builder.
    #[must_use]
    pub fn builder() -> RequestBuilder {
        RequestBuilder::default()
    }

    /// Moves the request's owned protocol parts to a caller that needs to
    /// retain a bounded request observation without cloning the body or
    /// ordered headers.
    pub(crate) fn into_parts(self) -> (Method, Url, Headers, Body) {
        (self.method, self.url, self.headers, self.body)
    }
}

/// Builder for a validated [`Request`].
#[derive(Clone, Default)]
pub struct RequestBuilder {
    method: Method,
    url: Option<Url>,
    headers: Headers,
    body: Body,
}

impl std::fmt::Debug for RequestBuilder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RequestBuilder")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &self.headers)
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

impl RequestBuilder {
    /// Sets the method.
    #[must_use]
    pub fn method(mut self, method: Method) -> Self {
        self.method = method;
        self
    }

    /// Parses and sets the method.
    pub fn method_name(mut self, method: impl Into<String>) -> Result<Self, HttpError> {
        self.method = Method::parse(method)?;
        Ok(self)
    }

    /// Parses and sets the absolute URL.
    pub fn url(mut self, url: impl Into<String>) -> Result<Self, HttpError> {
        self.url = Some(Url::parse(url)?);
        Ok(self)
    }

    /// Sets an already parsed URL.
    #[must_use]
    pub fn parsed_url(mut self, url: Url) -> Self {
        self.url = Some(url);
        self
    }

    /// Appends one header.
    pub fn header(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, HttpError> {
        self.headers.insert(name, value)?;
        Ok(self)
    }

    /// Sets a body.
    #[must_use]
    pub fn body(mut self, body: Body) -> Self {
        self.body = body;
        self
    }

    /// Builds the request and validates basic method/body rules.
    pub fn build(self) -> Result<Request, HttpError> {
        let url = self
            .url
            .ok_or_else(|| HttpError::InvalidUrl("request URL is missing".to_owned()))?;
        let request = Request {
            method: self.method,
            url,
            headers: self.headers,
            body: self.body,
        };
        request.validate(usize::MAX, usize::MAX)?;
        Ok(request)
    }
}

/// URL-encodes one form component using JMeter's UTF-8 `URLEncoder` rules.
///
/// Form encoding deliberately differs from URI query encoding: spaces become
/// `+`, `*` remains unescaped, and `~` is percent-encoded.
#[must_use]
pub fn form_encode(value: &str) -> String {
    percent_encode_bytes(value.as_bytes())
}

/// URL-encodes one form component using an explicit JMeter content encoding.
///
/// The pure core supports the deterministic built-in encodings listed by
/// [`RequestCharset`]. Unknown Java charset/provider names are rejected rather
/// than silently replaced with UTF-8.
pub fn form_encode_with_encoding(value: &str, content_encoding: &str) -> Result<String, HttpError> {
    let charset = RequestCharset::parse(content_encoding)?;
    Ok(percent_encode_bytes(&charset.encode(value)?))
}

fn percent_encode_bytes(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len());
    for &byte in bytes {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'*' | b'_' => {
                encoded.push(char::from(byte));
            }
            b' ' => encoded.push('+'),
            byte => {
                encoded.push('%');
                encoded.push(hex(byte >> 4));
                encoded.push(hex(byte & 0x0f));
            }
        }
    }
    encoded
}

/// Text encodings available without an ambient charset/provider capability.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RequestCharset {
    /// UTF-8, the JMeter 5.6.3 default.
    Utf8,
    /// Seven-bit US-ASCII.
    Ascii,
    /// ISO-8859-1 / Latin-1.
    Iso8859_1,
    /// Windows-1252, including its five common punctuation extensions.
    Windows1252,
}

impl RequestCharset {
    /// Parses common Java charset aliases without consulting process state.
    pub fn parse(value: &str) -> Result<Self, HttpError> {
        if value.len() > MAX_CONTENT_ENCODING_BYTES {
            return Err(HttpError::resource_limit("HTTP content encoding bytes"));
        }
        let normalized = value
            .bytes()
            .filter(|byte| !matches!(*byte, b'-' | b'_' | b' '))
            .map(|byte| byte.to_ascii_lowercase())
            .collect::<Vec<_>>();
        match normalized.as_slice() {
            [] if value.is_empty() => Ok(Self::Utf8),
            b"utf8" => Ok(Self::Utf8),
            b"ascii" | b"usascii" => Ok(Self::Ascii),
            b"iso88591" | b"latin1" | b"l1" => Ok(Self::Iso8859_1),
            b"windows1252" | b"cp1252" => Ok(Self::Windows1252),
            _ => Err(HttpError::Unsupported(
                "HTTP content encoding is unavailable in the pure core".to_owned(),
            )),
        }
    }

    /// Encodes text to the selected wire bytes.
    pub fn encode_text(self, value: &str) -> Result<Vec<u8>, HttpError> {
        self.encode(value)
    }

    fn encode(self, value: &str) -> Result<Vec<u8>, HttpError> {
        match self {
            Self::Utf8 => Ok(value.as_bytes().to_vec()),
            Self::Ascii => value
                .chars()
                .map(|character| {
                    let value = character as u32;
                    if value <= 0x7f {
                        Ok(value as u8)
                    } else {
                        Err(HttpError::InvalidHeader(
                            "HTTP content encoding cannot represent argument text".to_owned(),
                        ))
                    }
                })
                .collect(),
            Self::Iso8859_1 => value
                .chars()
                .map(|character| {
                    u8::try_from(character as u32).map_err(|_| {
                        HttpError::InvalidHeader(
                            "HTTP content encoding cannot represent argument text".to_owned(),
                        )
                    })
                })
                .collect(),
            Self::Windows1252 => value
                .chars()
                .map(encode_windows_1252)
                .collect::<Result<Vec<_>, _>>(),
        }
    }

    fn decode(self, value: &[u8]) -> Result<String, HttpError> {
        match self {
            Self::Utf8 => String::from_utf8(value.to_vec()).map_err(|_| {
                HttpError::InvalidHeader("HTTP content encoding contains invalid UTF-8".to_owned())
            }),
            Self::Ascii => value
                .iter()
                .map(|byte| {
                    if *byte > 0x7f {
                        Err(HttpError::InvalidHeader(
                            "HTTP content encoding cannot represent argument text".to_owned(),
                        ))
                    } else {
                        Ok(char::from(*byte))
                    }
                })
                .collect(),
            Self::Iso8859_1 => Ok(value.iter().map(|byte| char::from(*byte)).collect()),
            Self::Windows1252 => value
                .iter()
                .map(|byte| {
                    decode_windows_1252(*byte).ok_or_else(|| {
                        HttpError::InvalidHeader(
                            "HTTP content encoding cannot represent argument text".to_owned(),
                        )
                    })
                })
                .collect(),
        }
    }
}

fn decode_form_component(value: &str, charset: RequestCharset) -> Result<String, HttpError> {
    let mut decoded = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(character) = chars.next() {
        match character {
            '+' => decoded.push(' '),
            '%' => {
                let mut bytes = Vec::new();
                loop {
                    let Some(high) = chars.next() else {
                        return Err(HttpError::InvalidHeader(
                            "invalid percent-encoded argument".to_owned(),
                        ));
                    };
                    let Some(low) = chars.next() else {
                        return Err(HttpError::InvalidHeader(
                            "invalid percent-encoded argument".to_owned(),
                        ));
                    };
                    let Some(high) = hex_value(high) else {
                        return Err(HttpError::InvalidHeader(
                            "invalid percent-encoded argument".to_owned(),
                        ));
                    };
                    let Some(low) = hex_value(low) else {
                        return Err(HttpError::InvalidHeader(
                            "invalid percent-encoded argument".to_owned(),
                        ));
                    };
                    bytes.push((high << 4) | low);
                    if chars.peek() != Some(&'%') {
                        break;
                    }
                    chars.next();
                }
                decoded.push_str(&charset.decode(&bytes)?);
            }
            character => decoded.push(character),
        }
    }
    Ok(decoded)
}

fn hex_value(value: char) -> Option<u8> {
    match value {
        '0'..='9' => Some((value as u8) - b'0'),
        'a'..='f' => Some((value as u8) - b'a' + 10),
        'A'..='F' => Some((value as u8) - b'A' + 10),
        _ => None,
    }
}

fn encode_windows_1252(character: char) -> Result<u8, HttpError> {
    let value = character as u32;
    let byte = match value {
        0x00..=0x7f | 0xa0..=0xff => u8::try_from(value).ok(),
        0x20ac => Some(0x80),
        0x201a => Some(0x82),
        0x192 => Some(0x83),
        0x201e => Some(0x84),
        0x2026 => Some(0x85),
        0x2020 => Some(0x86),
        0x2021 => Some(0x87),
        0x2c6 => Some(0x88),
        0x2030 => Some(0x89),
        0x160 => Some(0x8a),
        0x2039 => Some(0x8b),
        0x152 => Some(0x8c),
        0x17d => Some(0x8e),
        0x2018 => Some(0x91),
        0x2019 => Some(0x92),
        0x201c => Some(0x93),
        0x201d => Some(0x94),
        0x2022 => Some(0x95),
        0x2013 => Some(0x96),
        0x2014 => Some(0x97),
        0x2dc => Some(0x98),
        0x2122 => Some(0x99),
        0x161 => Some(0x9a),
        0x203a => Some(0x9b),
        0x153 => Some(0x9c),
        0x17e => Some(0x9e),
        0x178 => Some(0x9f),
        _ => None,
    };
    byte.ok_or_else(|| {
        HttpError::InvalidHeader("HTTP content encoding cannot represent argument text".to_owned())
    })
}

fn decode_windows_1252(byte: u8) -> Option<char> {
    let value = match byte {
        0x00..=0x7f | 0xa0..=0xff => return Some(char::from(byte)),
        0x80 => 0x20ac,
        0x82 => 0x201a,
        0x83 => 0x192,
        0x84 => 0x201e,
        0x85 => 0x2026,
        0x86 => 0x2020,
        0x87 => 0x2021,
        0x88 => 0x2c6,
        0x89 => 0x2030,
        0x8a => 0x160,
        0x8b => 0x2039,
        0x8c => 0x152,
        0x8e => 0x17d,
        0x91 => 0x2018,
        0x92 => 0x2019,
        0x93 => 0x201c,
        0x94 => 0x201d,
        0x95 => 0x2022,
        0x96 => 0x2013,
        0x97 => 0x2014,
        0x98 => 0x2dc,
        0x99 => 0x2122,
        0x9a => 0x161,
        0x9b => 0x203a,
        0x9c => 0x153,
        0x9e => 0x17e,
        0x9f => 0x178,
        _ => return None,
    };
    char::from_u32(value)
}

fn hex(value: u8) -> char {
    char::from(b"0123456789ABCDEF"[usize::from(value)])
}

fn encode_form_fields(fields: impl IntoIterator<Item = FormField>) -> Result<Vec<u8>, HttpError> {
    let mut arguments = Vec::new();
    for field in fields {
        if arguments.len() >= MAX_FORM_FIELDS {
            return Err(HttpError::resource_limit("form field count"));
        }
        arguments.push(HttpArgument::from(field));
    }
    encode_http_arguments(
        &arguments,
        RequestCharset::Utf8,
        RequestCharset::Utf8,
        true,
        false,
        false,
        true,
    )
}

fn is_skippable_argument_name(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.is_empty() || (trimmed.starts_with("${") && value.ends_with('}'))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SamplerBuildMode {
    Generic,
    HttpClient4,
    Java,
}

fn build_sampler_request(
    sampler: HttpSamplerRequest,
    mode: SamplerBuildMode,
) -> Result<Request, HttpError> {
    // HTTPSamplerBase treats a blank content-encoding property as the UTF-8
    // URL-argument default. Keep the direct `RequestCharset::parse` helper
    // strict for callers that explicitly request a named charset, but apply
    // JMeter's blank-property rule at sampler construction.
    let charset = if sampler.content_encoding.trim().is_empty() {
        RequestCharset::Utf8
    } else {
        RequestCharset::parse(&sampler.content_encoding)?
    };
    if sampler.arguments.len() > MAX_FORM_FIELDS {
        return Err(HttpError::resource_limit("form field count"));
    }
    if sampler.multipart_parts.len() > MAX_MULTIPART_PARTS {
        return Err(HttpError::resource_limit("multipart part count"));
    }
    if sampler.multipart && sampler.boundary.is_none() {
        return Err(HttpError::InvalidHeader(
            "multipart boundary is required".to_owned(),
        ));
    }
    if sampler.multipart && !matches!(sampler.body_source, RequestBodySource::Empty) {
        return Err(HttpError::InvalidHeader(
            "multipart request body must be constructed from HTTP arguments".to_owned(),
        ));
    }
    if !sampler.multipart && !sampler.multipart_parts.is_empty() {
        return Err(HttpError::InvalidHeader(
            "multipart parts require multipart mode".to_owned(),
        ));
    }
    if mode == SamplerBuildMode::Java && sampler.multipart {
        return Err(HttpError::Unsupported(
            "JMeter Java multipart formatting requires an explicit provider policy".to_owned(),
        ));
    }

    let has_arguments = !sampler.arguments.is_empty();
    let has_explicit_source = !matches!(sampler.body_source, RequestBodySource::Empty);
    let send_parameter_values_as_post_body = sampler.post_body_raw
        || (has_arguments
            && sampler
                .arguments
                .iter()
                .all(|argument| argument.name().is_empty()));
    if has_arguments && has_explicit_source {
        return Err(HttpError::InvalidHeader(
            "request body source cannot accompany HTTP arguments".to_owned(),
        ));
    }

    let mut request = Request::new(sampler.method, sampler.url);
    for field in sampler.headers.iter() {
        request.add_header(field.name().as_str(), field.value().as_str())?;
    }

    let method_uses_query_arguments = matches!(
        request.method(),
        Method::Get | Method::Delete | Method::Options
    );
    if method_uses_query_arguments && has_arguments {
        let query = encode_query_arguments(&sampler.arguments, charset)?;
        request.set_url(append_query(&request.url, &query)?);
    }

    // JMeter's URL builder appends arguments only for GET, DELETE, and
    // OPTIONS. OPTIONS remains query-only. A GET with named arguments is
    // query-only as well, but HttpClient4's entity-enclosing GET path must
    // remain available for raw/nameless arguments and an explicit materialized
    // body source. Provider adapters can still reject that capability when
    // their selected implementation does not support GET entities.
    if matches!(request.method(), Method::Options)
        || (matches!(request.method(), Method::Get)
            && !send_parameter_values_as_post_body
            && !has_explicit_source
            && !sampler.multipart
            && sampler.multipart_parts.is_empty())
    {
        if has_explicit_source || sampler.multipart || !sampler.multipart_parts.is_empty() {
            return Err(HttpError::InvalidMethod(format!(
                "{} sampler cannot carry a request body",
                request.method()
            )));
        }
        request.validate(MAX_REQUEST_BODY_BYTES, MAX_REQUEST_HEADER_FIELDS)?;
        return Ok(request);
    }
    if matches!(request.method(), Method::Head | Method::Trace) {
        if has_explicit_source
            || sampler.multipart
            || !sampler.multipart_parts.is_empty()
            || has_arguments
        {
            return Err(HttpError::InvalidMethod(format!(
                "{} sampler cannot carry request data",
                request.method()
            )));
        }
        request.validate(MAX_REQUEST_BODY_BYTES, MAX_REQUEST_HEADER_FIELDS)?;
        return Ok(request);
    }

    // HTTPJavaImpl writes entity data only through its POST/PUT paths.  Keep
    // that provider distinction explicit; a Java-mode caller never receives
    // a silently dropped GET/DELETE/PATCH/extension body.
    if mode == SamplerBuildMode::Java
        && !matches!(request.method(), Method::Post | Method::Put)
        && (has_explicit_source
            || sampler.multipart
            || !sampler.multipart_parts.is_empty()
            || send_parameter_values_as_post_body
            || (has_arguments && !matches!(request.method(), Method::Get | Method::Options)))
    {
        return Err(HttpError::Unsupported(format!(
            "JMeter Java HTTP provider does not expose an entity path for {}",
            request.method()
        )));
    }

    let body = match sampler.body_source {
        RequestBodySource::Empty if sampler.multipart => {
            let boundary = sampler.boundary.as_deref().ok_or_else(|| {
                HttpError::InvalidHeader("multipart boundary is required".to_owned())
            })?;
            let boundary = validate_boundary(boundary)?;
            let mut parts = Vec::new();
            for argument in &sampler.arguments {
                if argument.name().len() > MAX_MULTIPART_PART_HEADER_BYTES
                    || argument.metadata().len() > MAX_MULTIPART_PART_HEADER_BYTES
                {
                    return Err(HttpError::resource_limit("multipart part header bytes"));
                }
                if argument.value().len() > MAX_MULTIPART_PART_BODY_BYTES {
                    return Err(HttpError::resource_limit("multipart part body bytes"));
                }
                if is_skippable_argument_name(argument.name()) {
                    continue;
                }
                if parts.len() >= MAX_MULTIPART_PARTS {
                    return Err(HttpError::resource_limit("multipart part count"));
                }
                parts.push(multipart_argument(argument, charset)?);
            }
            for part in &sampler.multipart_parts {
                if parts.len() >= MAX_MULTIPART_PARTS {
                    return Err(HttpError::resource_limit("multipart part count"));
                }
                parts.push(part.clone());
            }
            let body = encode_multipart(&boundary, parts)?;
            if matches!(mode, SamplerBuildMode::HttpClient4 | SamplerBuildMode::Java) {
                // Both selected JMeter providers install the entity's
                // boundary-bearing Content-Type. Keep this replacement behind
                // explicit provider modes so generic construction never drops
                // caller data.
                request.remove_header("content-type");
                request.add_header(
                    "Content-Type",
                    format!("multipart/form-data; boundary={boundary}"),
                )?;
            } else {
                let content_type_count = request.headers().values("content-type").count();
                if content_type_count > 1 {
                    return Err(HttpError::InvalidHeader(
                        "duplicate content-type fields for multipart body".to_owned(),
                    ));
                }
                match request.headers().get("content-type") {
                    Some(value) if !multipart_content_type_matches(value, &boundary) => {
                        return Err(HttpError::InvalidHeader(
                            "multipart body conflicts with Content-Type boundary".to_owned(),
                        ));
                    }
                    Some(_) => {}
                    None => request.add_header(
                        "Content-Type",
                        format!("multipart/form-data; boundary={boundary}"),
                    )?,
                }
            }
            Body::try_bytes(body)?
        }
        RequestBodySource::Empty if send_parameter_values_as_post_body => {
            let body = encode_raw_arguments(&sampler.arguments, charset)?;
            Body::try_bytes(body)?
        }
        RequestBodySource::Empty if has_arguments => {
            let body = match mode {
                SamplerBuildMode::HttpClient4 => {
                    encode_form_sampler_arguments(&sampler.arguments, charset)?
                }
                SamplerBuildMode::Generic | SamplerBuildMode::Java => {
                    encode_query_body_arguments(&sampler.arguments, charset)?
                }
            };
            Body::try_bytes(body)?
        }
        RequestBodySource::Empty => Body::Empty,
        RequestBodySource::Bytes(body) => Body::try_bytes(body)?,
        RequestBodySource::OneShot => {
            return Err(HttpError::Unsupported(
                "one-shot request body requires an explicit streaming adapter".to_owned(),
            ));
        }
        RequestBodySource::File { replayability } => {
            let detail = match replayability {
                RequestReplayability::Replayable => {
                    "replayable file request body requires an explicit file adapter"
                }
                RequestReplayability::OneShot => {
                    "one-shot file request body requires an explicit streaming adapter"
                }
            };
            return Err(HttpError::Unsupported(detail.to_owned()));
        }
    };
    request.set_body(body);
    request.validate(MAX_REQUEST_BODY_BYTES, MAX_REQUEST_HEADER_FIELDS)?;
    Ok(request)
}

fn encode_http_arguments(
    arguments: &[HttpArgument],
    name_charset: RequestCharset,
    value_charset: RequestCharset,
    decode_preencoded: bool,
    skip_empty_names: bool,
    skip_skippable_names: bool,
    include_metadata: bool,
) -> Result<Vec<u8>, HttpError> {
    if arguments.len() > MAX_FORM_FIELDS {
        return Err(HttpError::resource_limit("form field count"));
    }
    let mut encoded = Vec::new();
    let mut emitted = 0usize;
    for argument in arguments {
        if argument.name().len() > MAX_FORM_BYTES
            || argument.value().len() > MAX_FORM_BYTES
            || argument.metadata().len() > MAX_FORM_BYTES
        {
            return Err(HttpError::resource_limit("form argument bytes"));
        }
        // Query serialization skips only an empty encoded name. Entity
        // serialization additionally skips blank/missing-variable names via
        // Argument::isSkippable.
        if (skip_empty_names && argument.name().is_empty())
            || (skip_skippable_names && is_skippable_argument_name(argument.name()))
        {
            continue;
        }
        if emitted != 0 {
            append_bounded_byte(&mut encoded, b'&', MAX_FORM_BYTES)?;
        }
        emitted = emitted
            .checked_add(1)
            .ok_or_else(|| HttpError::resource_limit("form field count"))?;
        append_encoded_argument_piece(
            &mut encoded,
            argument.name(),
            argument.always_encode(),
            name_charset,
            MAX_FORM_BYTES,
            decode_preencoded,
        )?;
        if include_metadata {
            // JMeter's query serializer emits metadata and the value for
            // every non-empty-name argument. `setUseEquals(false)` is
            // represented by empty metadata; the value is still retained.
            append_argument_metadata(&mut encoded, argument.metadata(), MAX_FORM_BYTES)?;
        } else {
            // HttpClient4's UrlEncodedFormEntity always emits `=` between a
            // name and value; it does not consult HTTPArgument metadata.
            append_bounded_byte(&mut encoded, b'=', MAX_FORM_BYTES)?;
        }
        append_encoded_argument_piece(
            &mut encoded,
            argument.value(),
            argument.always_encode(),
            value_charset,
            MAX_FORM_BYTES,
            decode_preencoded,
        )?;
    }
    Ok(encoded)
}

fn encode_query_arguments(
    arguments: &[HttpArgument],
    charset: RequestCharset,
) -> Result<String, HttpError> {
    let encoded = encode_http_arguments(
        arguments,
        RequestCharset::Utf8,
        charset,
        false,
        true,
        false,
        true,
    )?;
    String::from_utf8(encoded)
        .map_err(|_| HttpError::InvalidUrl("query arguments are not ASCII-safe".to_owned()))
}

fn encode_query_body_arguments(
    arguments: &[HttpArgument],
    charset: RequestCharset,
) -> Result<Vec<u8>, HttpError> {
    let query = encode_query_arguments(arguments, charset)?;
    charset.encode_text(&query)
}

fn encode_raw_arguments(
    arguments: &[HttpArgument],
    charset: RequestCharset,
) -> Result<Vec<u8>, HttpError> {
    if arguments.len() > MAX_FORM_FIELDS {
        return Err(HttpError::resource_limit("raw argument count"));
    }
    let mut encoded = Vec::new();
    for argument in arguments {
        if argument.value().len() > MAX_REQUEST_BODY_BYTES {
            return Err(HttpError::resource_limit("raw argument bytes"));
        }
        append_encoded_argument_piece(
            &mut encoded,
            argument.value(),
            argument.always_encode(),
            charset,
            MAX_REQUEST_BODY_BYTES,
            false,
        )?;
    }
    Ok(encoded)
}

fn encode_form_sampler_arguments(
    arguments: &[HttpArgument],
    charset: RequestCharset,
) -> Result<Vec<u8>, HttpError> {
    encode_http_arguments(arguments, charset, charset, true, false, true, false)
}

fn append_encoded_argument_piece(
    destination: &mut Vec<u8>,
    value: &str,
    always_encode: bool,
    charset: RequestCharset,
    maximum: usize,
    decode_preencoded: bool,
) -> Result<(), HttpError> {
    let decoded;
    let value = if always_encode || !decode_preencoded {
        value
    } else {
        decoded = decode_form_component(value, charset)?;
        decoded.as_str()
    };
    let bytes = charset.encode(value)?;
    if always_encode || decode_preencoded {
        for byte in bytes {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'*' | b'_' => {
                    append_bounded_byte(destination, byte, maximum)?
                }
                b' ' => append_bounded_byte(destination, b'+', maximum)?,
                byte => {
                    append_bounded_byte(destination, b'%', maximum)?;
                    append_bounded_byte(destination, hex(byte >> 4) as u8, maximum)?;
                    append_bounded_byte(destination, hex(byte & 0x0f) as u8, maximum)?;
                }
            }
        }
    } else {
        let next = destination
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| HttpError::resource_limit("request body bytes"))?;
        if next > maximum {
            return Err(HttpError::RequestBodyLimit {
                actual: next,
                maximum,
            });
        }
        destination.extend_from_slice(&bytes);
    }
    Ok(())
}

fn append_argument_metadata(
    destination: &mut Vec<u8>,
    metadata: &str,
    maximum: usize,
) -> Result<(), HttpError> {
    let bytes = metadata.as_bytes();
    let next = destination
        .len()
        .checked_add(bytes.len())
        .ok_or_else(|| HttpError::resource_limit("form entity bytes"))?;
    if next > maximum {
        return Err(HttpError::RequestBodyLimit {
            actual: next,
            maximum,
        });
    }
    destination.extend_from_slice(bytes);
    Ok(())
}

fn append_bounded_byte(
    destination: &mut Vec<u8>,
    byte: u8,
    maximum: usize,
) -> Result<(), HttpError> {
    let next = destination
        .len()
        .checked_add(1)
        .ok_or_else(|| HttpError::resource_limit("request body bytes"))?;
    if next > maximum {
        return Err(HttpError::RequestBodyLimit {
            actual: next,
            maximum,
        });
    }
    destination.push(byte);
    Ok(())
}

fn multipart_argument(
    argument: &HttpArgument,
    charset: RequestCharset,
) -> Result<MultipartPart, HttpError> {
    if argument.value().len() > MAX_MULTIPART_PART_BODY_BYTES {
        return Err(HttpError::resource_limit("multipart part body bytes"));
    }
    // JMeter's HttpClient4 multipart path passes argument names and values to
    // `FormBodyPart`/`StringBody` directly; HTTPArgument's URL-encoding flag
    // applies to URL-encoded entities and raw-body mode, not multipart text.
    let body = charset.encode(argument.value())?;
    match argument.content_type() {
        Some(content_type) => MultipartPart::new(
            argument.name().to_owned(),
            body,
            None,
            Some(content_type.to_owned()),
        ),
        None => MultipartPart::bytes(argument.name().to_owned(), body),
    }
}

fn append_query(url: &Url, query: &str) -> Result<Url, HttpError> {
    if query.is_empty() {
        return Ok(url.clone());
    }
    let separator = if url.query().is_some() { '&' } else { '?' };
    let fragment = url
        .fragment()
        .map_or_else(String::new, |value| format!("#{value}"));
    Url::parse(format!(
        "{}://{}{}{}{}{}",
        url.scheme(),
        url.authority(),
        url.path_and_query(),
        separator,
        query,
        fragment
    ))
}

fn validate_boundary(value: &str) -> Result<String, HttpError> {
    if value.len() > MAX_MULTIPART_BOUNDARY_BYTES {
        return Err(HttpError::resource_limit("multipart boundary bytes"));
    }
    if value.is_empty() || !value.is_ascii() {
        return Err(HttpError::InvalidHeader(
            "invalid multipart boundary".to_owned(),
        ));
    }
    if value.bytes().any(|byte| {
        !(0x21..=0x7e).contains(&byte)
            || matches!(
                byte,
                0x22 | 0x28
                    | 0x29
                    | 0x2c
                    | 0x2f
                    | 0x3a
                    | 0x3b
                    | 0x3c
                    | 0x3d
                    | 0x3e
                    | 0x3f
                    | 0x40
                    | 0x5b
                    | 0x5c
                    | 0x5d
                    | 0x7b
                    | 0x7d
            )
    }) {
        return Err(HttpError::InvalidHeader(
            "invalid multipart boundary".to_owned(),
        ));
    }
    Ok(value.to_owned())
}

fn multipart_content_type_matches(value: &str, boundary: &str) -> bool {
    let mut pieces = value.split(';');
    let media_type = pieces.next().map(str::trim);
    if !media_type.is_some_and(|media_type| media_type.eq_ignore_ascii_case("multipart/form-data"))
    {
        return false;
    }
    pieces
        .map(str::trim)
        .filter_map(|parameter| parameter.split_once('='))
        .any(|(name, value)| {
            name.trim().eq_ignore_ascii_case("boundary")
                && value.trim().trim_matches('"') == boundary
        })
}

fn validate_multipart_parameter(value: &str, what: &str) -> Result<(), HttpError> {
    if value.len() > MAX_MULTIPART_PART_HEADER_BYTES {
        return Err(HttpError::resource_limit("multipart part header bytes"));
    }
    if value.is_empty() || value.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err(HttpError::InvalidHeader(what.to_owned()));
    }
    Ok(())
}

fn encode_multipart(
    boundary: &str,
    parts: impl IntoIterator<Item = MultipartPart>,
) -> Result<Vec<u8>, HttpError> {
    let mut encoded = Vec::new();
    let mut count = 0usize;
    for part in parts {
        count = count
            .checked_add(1)
            .ok_or_else(|| HttpError::resource_limit("multipart part count"))?;
        if count > MAX_MULTIPART_PARTS {
            return Err(HttpError::resource_limit("multipart part count"));
        }
        let disposition = if let Some(filename) = part.filename() {
            format!(
                "Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\n",
                quote_multipart_parameter(part.name()),
                quote_multipart_parameter(filename),
            )
        } else {
            format!(
                "Content-Disposition: form-data; name=\"{}\"\r\n",
                quote_multipart_parameter(part.name()),
            )
        };
        let mut headers = disposition.into_bytes();
        if let Some(content_type) = part.content_type() {
            headers.extend_from_slice(b"Content-Type: ");
            headers.extend_from_slice(content_type.as_bytes());
            headers.extend_from_slice(b"\r\n");
        }
        if headers.len() > MAX_MULTIPART_PART_HEADER_BYTES {
            return Err(HttpError::resource_limit("multipart part header bytes"));
        }
        let contribution = boundary
            .len()
            .checked_add(8)
            .and_then(|length| length.checked_add(headers.len()))
            .and_then(|length| length.checked_add(part.body().len()))
            .ok_or_else(|| HttpError::resource_limit("multipart body bytes"))?;
        let next = encoded
            .len()
            .checked_add(contribution)
            .and_then(|length| length.checked_add(boundary.len()))
            .and_then(|length| length.checked_add(6))
            .ok_or_else(|| HttpError::resource_limit("multipart body bytes"))?;
        if next > MAX_REQUEST_BODY_BYTES {
            return Err(HttpError::RequestBodyLimit {
                actual: next,
                maximum: MAX_REQUEST_BODY_BYTES,
            });
        }
        encoded.extend_from_slice(b"--");
        encoded.extend_from_slice(boundary.as_bytes());
        encoded.extend_from_slice(b"\r\n");
        encoded.extend_from_slice(&headers);
        encoded.extend_from_slice(b"\r\n");
        encoded.extend_from_slice(part.body());
        encoded.extend_from_slice(b"\r\n");
    }
    encoded.extend_from_slice(b"--");
    encoded.extend_from_slice(boundary.as_bytes());
    encoded.extend_from_slice(b"--\r\n");
    if encoded.len() > MAX_REQUEST_BODY_BYTES {
        return Err(HttpError::RequestBodyLimit {
            actual: encoded.len(),
            maximum: MAX_REQUEST_BODY_BYTES,
        });
    }
    Ok(encoded)
}

fn quote_multipart_parameter(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn parse_content_length(value: &str) -> Result<usize, HttpError> {
    let value = value.trim_matches(|byte| byte == ' ' || byte == '\t');
    if value.is_empty() || value.bytes().any(|byte| !byte.is_ascii_digit()) {
        return Err(HttpError::InvalidHeader(
            "invalid content-length".to_owned(),
        ));
    }
    let parsed = value
        .parse::<u64>()
        .map_err(|_| HttpError::resource_limit("content-length bytes"))?;
    let parsed =
        usize::try_from(parsed).map_err(|_| HttpError::resource_limit("content-length bytes"))?;
    if parsed > MAX_REQUEST_BODY_BYTES {
        return Err(HttpError::resource_limit("content-length bytes"));
    }
    Ok(parsed)
}

fn is_chunked_transfer_encoding(value: &str) -> bool {
    let mut codings = value.split(',').map(str::trim);
    matches!(
        (codings.next(), codings.next()),
        (Some(coding), None) if coding.eq_ignore_ascii_case("chunked")
    )
}

fn is_token_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'!'
            | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'0'..=b'9'
            | b'A'..=b'Z'
            | b'^'
            | b'_'
            | b'`'
            | b'a'..=b'z'
            | b'|'
            | b'~'
    )
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "request tests use expect only at fixed fixture assertion boundaries"
    )]

    use super::{
        FormField, HttpArgument, HttpSamplerRequest, MAX_FORM_FIELDS, MAX_REQUEST_BODY_BYTES,
        Method, MultipartPart, Request, RequestBodySource, RequestFraming, RequestReplayability,
        form_encode, form_encode_with_encoding,
    };
    use crate::HttpError;

    #[test]
    fn form_encode_matches_jmeter_url_encoder_reserved_set() {
        assert_eq!(form_encode("*~ "), "*%7E+");
        assert_eq!(form_encode("a+b"), "a%2Bb");
    }

    #[test]
    fn form_encode_uses_utf8_for_non_ascii_input() {
        assert_eq!(form_encode("café"), "caf%C3%A9");
    }

    #[test]
    fn form_fields_preserve_order_and_use_equals() {
        let request = Request::form_post_fields(
            "http://example.test/submit",
            [
                FormField::without_equals("flag"),
                FormField::new("a b", "c&d"),
            ],
        )
        .expect("bounded form");
        assert_eq!(request.body().as_bytes(), b"flag&a+b=c%26d");
        assert_eq!(
            request.headers().get("content-type"),
            Some("application/x-www-form-urlencoded")
        );

        let empty_name =
            Request::form_post_fields("http://example.test/submit", [FormField::new("", "value")])
                .expect("empty form name is a valid direct field");
        assert_eq!(empty_name.body().as_bytes(), b"=value");
    }

    #[test]
    fn effective_form_decodes_already_encoded_arguments_before_reencoding() {
        let request = HttpSamplerRequest::from_url(Method::Post, "http://example.test/submit")
            .expect("URL")
            .argument(HttpArgument::with_options(
                "a%20b", "c%26d+e", "=", true, false,
            ))
            .build()
            .expect("form request");
        assert_eq!(request.body().as_bytes(), b"a+b=c%26d+e");

        let skipped = HttpSamplerRequest::from_url(Method::Post, "http://example.test/submit")
            .expect("URL")
            .arguments([
                HttpArgument::new("   ", "blank"),
                HttpArgument::new("${missing}", "variable"),
                HttpArgument::new("kept", "value"),
            ])
            .build()
            .expect("skippable form arguments");
        assert_eq!(skipped.body().as_bytes(), b"kept=value");

        let metadata_is_entity_separator =
            HttpSamplerRequest::from_url(Method::Post, "http://example.test/submit")
                .expect("URL")
                .argument(HttpArgument::with_options(
                    "flag", "value", ":", false, true,
                ))
                .build_generic()
                .expect("form metadata");
        assert_eq!(
            metadata_is_entity_separator.body().as_bytes(),
            b"flag:value"
        );
        let httpclient4_metadata =
            HttpSamplerRequest::from_url(Method::Post, "http://example.test/submit")
                .expect("URL")
                .argument(HttpArgument::with_options(
                    "flag", "value", ":", false, true,
                ))
                .build_httpclient4()
                .expect("HttpClient4 form metadata");
        assert_eq!(httpclient4_metadata.body().as_bytes(), b"flag=value");

        let setter_updates_metadata = HttpArgument::new("flag", "value").with_use_equals(false);
        assert!(!setter_updates_metadata.use_equals());
        assert_eq!(setter_updates_metadata.metadata(), "");
    }

    #[test]
    fn query_preserves_already_encoded_arguments_and_skips_blank_names() {
        let request = HttpSamplerRequest::from_url(Method::Get, "http://example.test/submit")
            .expect("URL")
            .arguments([
                HttpArgument::with_options("a%20b", "c%26d+e", "=", true, false),
                HttpArgument::raw("ignored"),
            ])
            .build()
            .expect("query request");
        assert_eq!(request.wire_target(), "/submit?a%20b=c%26d+e");
    }

    #[test]
    fn multipart_body_is_ordered_and_has_explicit_boundary() {
        let request = Request::multipart_post(
            "http://example.test/upload",
            "boundary",
            [
                MultipartPart::field("part-one", "one").expect("part"),
                MultipartPart::field("part-two", "two").expect("part"),
            ],
        )
        .expect("bounded multipart");
        assert_eq!(
            request.body().as_bytes(),
            b"--boundary\r\nContent-Disposition: form-data; name=\"part-one\"\r\n\r\none\r\n--boundary\r\nContent-Disposition: form-data; name=\"part-two\"\r\n\r\ntwo\r\n--boundary--\r\n"
        );
        assert_eq!(
            request.headers().get("content-type"),
            Some("multipart/form-data; boundary=boundary")
        );
    }

    #[test]
    fn request_framing_rejects_conflicting_or_mismatched_fields() {
        let mut request = Request::post("http://example.test/", b"body".to_vec()).expect("request");
        request.add_header("Content-Length", " 3 ").expect("header");
        assert!(matches!(
            request.framing(),
            Err(HttpError::InvalidHeader(_))
        ));

        let mut request = Request::post("http://example.test/", b"body".to_vec()).expect("request");
        request.add_header("Content-Length", "4").expect("header");
        request
            .add_header("Transfer-Encoding", "chunked")
            .expect("header");
        assert!(matches!(
            request.framing(),
            Err(HttpError::InvalidHeader(_))
        ));

        let mut request = Request::post("http://example.test/", b"body".to_vec()).expect("request");
        request
            .add_header("Transfer-Encoding", "chunked")
            .expect("header");
        assert_eq!(request.framing().expect("chunked"), RequestFraming::Chunked);

        let mut whitespace =
            Request::post("http://example.test/", b"abc".to_vec()).expect("request");
        whitespace
            .add_header("Content-Length", "\t3 \t")
            .expect("header");
        assert_eq!(
            whitespace.framing().expect("OWS content length"),
            RequestFraming::ContentLength
        );

        let mut unsupported =
            Request::post("http://example.test/", b"body".to_vec()).expect("request");
        unsupported
            .add_header("Transfer-Encoding", "gzip, chunked")
            .expect("header");
        assert!(matches!(
            unsupported.framing(),
            Err(HttpError::InvalidHeader(_))
        ));
    }

    #[test]
    fn host_validation_is_explicit_and_normalizes_default_ports() {
        let mut matching = Request::get("http://Example.test/path").expect("request");
        matching
            .add_header("Host", "EXAMPLE.TEST:80")
            .expect("header");
        matching.validate_host_header().expect("matching host");

        let mut fully_qualified = Request::get("http://example.test./path").expect("request");
        fully_qualified
            .add_header("Host", "example.test")
            .expect("header");
        fully_qualified
            .validate_host_header()
            .expect("matching root-label host");

        let mut ipv6 = Request::get("https://[2001:DB8::1]/path").expect("request");
        ipv6.add_header("host", "[2001:db8::1]").expect("header");
        ipv6.validate_host_header().expect("matching IPv6 host");

        let mut conflict = Request::get("http://example.test/path").expect("request");
        conflict.add_header("Host", "other.test").expect("header");
        assert!(matches!(
            conflict.validate_host_header(),
            Err(HttpError::InvalidHeader(_))
        ));

        let mut duplicate = Request::get("http://example.test/path").expect("request");
        duplicate
            .add_header("Host", "example.test")
            .expect("header");
        duplicate
            .add_header("host", "example.test")
            .expect("header");
        assert!(matches!(
            duplicate.validate_host_header(),
            Err(HttpError::InvalidHeader(_))
        ));
    }

    #[test]
    fn ensure_content_length_distinguishes_absent_empty_and_chunked_bodies() {
        let mut absent = Request::get("http://example.test/").expect("request");
        absent.ensure_content_length().expect("absent body");
        assert!(!absent.headers().contains("content-length"));

        let mut present = Request::post("http://example.test/", Vec::<u8>::new()).expect("request");
        present.ensure_content_length().expect("present empty body");
        assert_eq!(present.headers().get("content-length"), Some("0"));

        let mut chunked = Request::post("http://example.test/", b"body".to_vec()).expect("request");
        chunked
            .add_header("Transfer-Encoding", "chunked")
            .expect("header");
        chunked.ensure_content_length().expect("chunked body");
        assert!(!chunked.headers().contains("content-length"));
    }

    #[test]
    fn request_hard_bounds_are_enforced_before_execution() {
        let fields = std::iter::repeat_with(|| FormField::new("x", "y")).take(MAX_FORM_FIELDS + 1);
        assert!(matches!(
            Request::form_post_fields("http://example.test/", fields),
            Err(HttpError::ResourceLimit(_))
        ));

        let request = Request::post("http://example.test/", b"123".to_vec()).expect("request");
        assert!(request.validate(2, 16).is_err());
        assert!(
            Request::multipart_post(
                "http://example.test/",
                "bad boundary",
                [MultipartPart::field("name", "value").expect("part")]
            )
            .is_err()
        );
        let oversized_boundary = "b".repeat(super::MAX_MULTIPART_BOUNDARY_BYTES + 1);
        assert!(matches!(
            Request::multipart_post(
                "http://example.test/",
                oversized_boundary,
                [MultipartPart::field("name", "value").expect("part")]
            ),
            Err(HttpError::ResourceLimit(_))
        ));

        let too_many_sampler_arguments =
            HttpSamplerRequest::from_url(Method::Post, "http://example.test/")
                .expect("URL")
                .arguments(
                    std::iter::repeat_with(|| HttpArgument::new("name", "value"))
                        .take(MAX_FORM_FIELDS + 1),
                );
        assert!(matches!(
            too_many_sampler_arguments.build(),
            Err(HttpError::ResourceLimit(_))
        ));
    }

    #[test]
    fn effective_sampler_builder_matches_raw_form_and_multipart_fixtures() {
        let raw = HttpSamplerRequest::from_url(Method::Post, "http://example.test/echo")
            .expect("URL")
            .post_body_raw(true)
            .argument(HttpArgument::with_options(
                "raw-body",
                "raw-body-alpha",
                "=",
                false,
                false,
            ))
            .build()
            .expect("raw request");
        assert_eq!(raw.body().as_bytes(), b"raw-body-alpha");

        let form = HttpSamplerRequest::from_url(Method::Post, "http://example.test/echo")
            .expect("URL")
            .arguments([
                HttpArgument::new("first", "alpha beta"),
                HttpArgument::new("second", "two"),
            ])
            .build()
            .expect("form request");
        assert_eq!(form.body().as_bytes(), b"first=alpha+beta&second=two");
        // JMeter's default `http.post_add_content_type_if_missing=false`
        // leaves the content type to an explicit Header Manager field.
        assert!(!form.headers().contains("content-type"));

        let form_with_header =
            HttpSamplerRequest::from_url(Method::Post, "http://example.test/echo")
                .expect("URL")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .expect("header")
                .arguments([
                    HttpArgument::new("first", "alpha beta"),
                    HttpArgument::new("second", "two"),
                ])
                .build()
                .expect("form request with explicit content type");
        assert_eq!(
            form_with_header.headers().get("content-type"),
            Some("application/x-www-form-urlencoded")
        );

        let multipart = HttpSamplerRequest::from_url(Method::Post, "http://example.test/echo")
            .expect("URL")
            .multipart("boundary")
            .arguments([
                HttpArgument::new("part-one", "one"),
                HttpArgument::new("part-two", "two"),
            ])
            .build()
            .expect("multipart request");
        assert_eq!(
            multipart.body().as_bytes(),
            b"--boundary\r\nContent-Disposition: form-data; name=\"part-one\"\r\n\r\none\r\n--boundary\r\nContent-Disposition: form-data; name=\"part-two\"\r\n\r\ntwo\r\n--boundary--\r\n"
        );
        assert_eq!(
            multipart.headers().get("content-type"),
            Some("multipart/form-data; boundary=boundary")
        );

        let file = HttpSamplerRequest::from_url(Method::Post, "http://example.test/echo")
            .expect("URL")
            .multipart("boundary")
            .multipart_part(
                MultipartPart::file_with_content_type(
                    "upload",
                    "fixture.bin",
                    b"file-bytes".to_vec(),
                    "application/octet-stream",
                )
                .expect("file part"),
            )
            .build()
            .expect("multipart file request");
        assert!(
            file.body()
                .as_bytes()
                .windows(10)
                .any(|window| window == b"file-bytes")
        );

        let typed = HttpSamplerRequest::from_url(Method::Post, "http://example.test/echo")
            .expect("URL")
            .multipart("boundary")
            .argument(HttpArgument::new("field", "value").with_content_type("text/plain"))
            .build()
            .expect("typed multipart request");
        assert!(
            typed
                .body()
                .as_bytes()
                .windows(b"Content-Type: text/plain\r\n".len())
                .any(|window| window == b"Content-Type: text/plain\r\n")
        );

        let multipart_wins = HttpSamplerRequest::from_url(Method::Post, "http://example.test/echo")
            .expect("URL")
            .multipart("boundary")
            .post_body_raw(true)
            .header("Content-Type", "multipart/form-data")
            .expect("header")
            .argument(HttpArgument::new("field", "value"))
            .build_httpclient4()
            .expect("multipart precedence");
        assert!(
            multipart_wins
                .body()
                .as_bytes()
                .starts_with(b"--boundary\r\n")
        );
        assert_eq!(
            multipart_wins.headers().get("content-type"),
            Some("multipart/form-data; boundary=boundary")
        );

        let generic_conflict =
            HttpSamplerRequest::from_url(Method::Post, "http://example.test/echo")
                .expect("URL")
                .multipart("boundary")
                .header("Content-Type", "text/plain")
                .expect("header")
                .argument(HttpArgument::new("field", "value"))
                .build_generic();
        assert!(matches!(generic_conflict, Err(HttpError::InvalidHeader(_))));
    }

    #[test]
    fn effective_sampler_builder_encodes_charset_and_query_arguments() {
        assert_eq!(
            form_encode_with_encoding("café", "ISO-8859-1").expect("latin-1"),
            "caf%E9"
        );
        assert!(form_encode_with_encoding("é", "US-ASCII").is_err());
        assert!(form_encode_with_encoding("€", "US-ASCII").is_err());
        assert!(form_encode_with_encoding("x", " ").is_err());

        let request = HttpSamplerRequest::from_url(
            Method::Get,
            "http://example.test/path?existing=1#fragment",
        )
        .expect("URL")
        .argument(HttpArgument::new("a b", "c&d"))
        .build()
        .expect("query request");
        assert_eq!(request.wire_target(), "/path?existing=1&a+b=c%26d");
        assert_eq!(request.url().fragment(), Some("fragment"));

        let latin_query = HttpSamplerRequest::from_url(Method::Get, "http://example.test/")
            .expect("URL")
            .content_encoding("ISO-8859-1")
            .argument(HttpArgument::new("café", "café"))
            .build()
            .expect("latin query");
        assert_eq!(latin_query.wire_target(), "/?caf%C3%A9=caf%E9");

        let blank_defaults = HttpSamplerRequest::from_url(Method::Post, "http://example.test/")
            .expect("URL")
            .content_encoding(" \t")
            .argument(HttpArgument::new("café", "café"))
            .build()
            .expect("blank content encoding defaults to UTF-8");
        assert_eq!(blank_defaults.body().as_bytes(), b"caf%C3%A9=caf%C3%A9");
    }

    #[test]
    fn sampler_method_query_and_entity_semantics_follow_jmeter() {
        let delete = HttpSamplerRequest::from_url(
            Method::Delete,
            "http://example.test/remove?existing=1#fragment",
        )
        .expect("URL")
        .argument(HttpArgument::new("id", "7"))
        .build()
        .expect("DELETE request");
        assert_eq!(delete.wire_target(), "/remove?existing=1&id=7");
        assert_eq!(delete.body().as_bytes(), b"id=7");

        let options = HttpSamplerRequest::from_url(Method::Options, "http://example.test/")
            .expect("URL")
            .argument(HttpArgument::new("mode", "cors"))
            .build()
            .expect("OPTIONS request");
        assert_eq!(options.wire_target(), "/?mode=cors");
        assert!(!options.body().is_present());

        let get_raw = HttpSamplerRequest::from_url(Method::Get, "http://example.test/raw")
            .expect("URL")
            .post_body_raw(true)
            .argument(HttpArgument::raw("get-body"))
            .build()
            .expect("GET entity request");
        assert_eq!(get_raw.body().as_bytes(), b"get-body");
        assert_eq!(get_raw.wire_target(), "/raw");

        let get_bytes = HttpSamplerRequest::from_url(Method::Get, "http://example.test/raw")
            .expect("URL")
            .body_source(RequestBodySource::bytes(b"explicit".to_vec()).expect("body"))
            .build()
            .expect("GET materialized entity");
        assert_eq!(get_bytes.body().as_bytes(), b"explicit");

        let get_nameless = HttpSamplerRequest::from_url(Method::Get, "http://example.test/raw")
            .expect("URL")
            .arguments([HttpArgument::raw("nameless")])
            .build()
            .expect("nameless GET entity request");
        assert_eq!(get_nameless.body().as_bytes(), b"nameless");

        assert!(matches!(
            HttpSamplerRequest::from_url(Method::Head, "http://example.test/")
                .expect("URL")
                .argument(HttpArgument::new("ignored", "value"))
                .build(),
            Err(HttpError::InvalidMethod(_))
        ));

        let no_raw_arguments =
            HttpSamplerRequest::from_url(Method::Post, "http://example.test/empty")
                .expect("URL")
                .post_body_raw(true)
                .build()
                .expect("empty raw sampler");
        assert!(no_raw_arguments.body().is_present());

        let head_present_empty = Request::head("http://example.test/")
            .expect("request")
            .with_body(super::Body::bytes(Vec::<u8>::new()));
        assert!(matches!(
            head_present_empty.validate(MAX_REQUEST_BODY_BYTES, super::MAX_REQUEST_HEADER_FIELDS),
            Err(HttpError::InvalidMethod(_))
        ));
    }

    #[test]
    fn effective_sampler_builder_rejects_unmaterialized_body_sources() {
        let one_shot = HttpSamplerRequest::from_url(Method::Post, "http://example.test/echo")
            .expect("URL")
            .body_source(RequestBodySource::one_shot())
            .build();
        assert!(matches!(one_shot, Err(HttpError::Unsupported(_))));

        let file = HttpSamplerRequest::from_url(Method::Post, "http://example.test/echo")
            .expect("URL")
            .body_source(RequestBodySource::file(RequestReplayability::Replayable))
            .build();
        assert!(matches!(file, Err(HttpError::Unsupported(_))));

        let java_get = HttpSamplerRequest::from_url(Method::Get, "http://example.test/echo")
            .expect("URL")
            .body_source(RequestBodySource::bytes(b"body".to_vec()).expect("body"))
            .build_java();
        assert!(matches!(java_get, Err(HttpError::Unsupported(_))));

        let java_form = HttpSamplerRequest::from_url(Method::Post, "http://example.test/echo")
            .expect("URL")
            .argument(HttpArgument::with_options(
                "flag", "value", ":", false, true,
            ))
            .build_java()
            .expect("Java query-string form");
        assert_eq!(java_form.body().as_bytes(), b"flag:value");

        let java_multipart = HttpSamplerRequest::from_url(Method::Post, "http://example.test/echo")
            .expect("URL")
            .multipart("boundary")
            .argument(HttpArgument::new("field", "value"))
            .build_java();
        assert!(matches!(java_multipart, Err(HttpError::Unsupported(_))));
    }

    #[test]
    fn body_source_projection_preserves_adapter_replayability() {
        let debug = format!("{:?}", RequestBodySource::Bytes(b"secret-body".to_vec()));
        assert!(!debug.contains("secret-body"));
        assert!(debug.contains("bytes"));

        let bytes = crate::BodySource::Bytes(
            crate::BoundedBytes::new(b"bytes".to_vec()).expect("bounded bytes"),
        );
        let projected = RequestBodySource::from_body_source(&bytes);
        assert_eq!(projected.replayability(), RequestReplayability::Replayable);

        let file = crate::BodySource::File(
            crate::FileCapability::new(
                [7; 16],
                64,
                crate::Presence::Absent,
                crate::Replayability::OneShot,
            )
            .expect("file capability"),
        );
        let projected = RequestBodySource::from_body_source(&file);
        assert_eq!(projected.replayability(), RequestReplayability::OneShot);
        assert!(matches!(
            HttpSamplerRequest::from_url(Method::Post, "http://example.test/echo")
                .expect("URL")
                .body_source(projected)
                .build(),
            Err(HttpError::Unsupported(_))
        ));
    }
}
