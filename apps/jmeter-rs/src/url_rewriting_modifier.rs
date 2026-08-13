// SPDX-License-Identifier: Apache-2.0
//! Native, bounded support for JMeter's URLRewritingModifier.
//!
//! This file is intentionally not registered by the application yet. It is
//! an isolated implementation seam for ELEM-008: callers must establish that
//! the enclosing sampler is an HTTP sampler before constructing an executable
//! component. The default scope factory therefore rejects an unproven
//! placement instead of guessing from a request URL or from a legacy request
//! map.
//!
//! The implementation works on the runtime's typed request fields. It never
//! renders a URL into an unconstrained URL parser, mutates HTTP-manager state,
//! or changes the order of non-matching query fields. A request change is
//! submitted as one generation/digest-bound InvocationDelta.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use jmeter_rs_model::{PropertyValue, TestElement};
use jmeter_rs_runtime::{
    BoundedText, ComponentCategory, ComponentError, ComponentFuture, EncodedField,
    FactoryComponent, InvocationDelta, MutationError, MutationErrorCode, Preprocessor,
    PreprocessorFactory, Presence, QueryField, RequestPatch, RequestState, ResponseDecodePolicy,
    ResponseInput, ResponseInputSetResolver, ResponseLimits, ResponseResolution, ResponseScope,
    ResponseSelection, ResponseTarget, SampleContext, ScopeComponent, ScopeComponentFactory,
    ScopeFactoryError, ScopedResponseResolver,
};

/// The short exact JMeter test-class alias.
pub const URL_REWRITING_MODIFIER_ALIAS: &str = "URLRewritingModifier";
/// The fully-qualified exact JMeter test-class alias.
pub const URL_REWRITING_MODIFIER_CLASS: &str =
    "org.apache.jmeter.protocol.http.modifier.URLRewritingModifier";

/// Maximum response bytes inspected by the bounded extractor.
pub const MAX_URL_REWRITING_RESPONSE_BYTES: usize = 4 * 1024;
/// Maximum captured token bytes.
pub const MAX_URL_REWRITING_TOKEN_BYTES: usize = 4 * 1024;
/// Maximum argument-name bytes accepted from source properties.
pub const MAX_URL_REWRITING_ARGUMENT_BYTES: usize = 256;
/// Maximum persistent properties admitted by this decoder.
pub const MAX_URL_REWRITING_PROPERTIES: usize = 16;

const PROPERTY_PATH_EXTENSION: &str = "path_extension";
const PROPERTY_PATH_EXTENSION_NO_QUESTIONMARK: &str = "path_extension_no_questionmark";
const PROPERTY_ARGUMENT_NAME: &str = "argument_name";
const PROPERTY_PATH_EXTENSION_NO_EQUALS: &str = "path_extension_no_equals";
const PROPERTY_CACHE_VALUE: &str = "cache_value";
const PROPERTY_ENCODE: &str = "encode";

/// Exact placement proof required before a modifier can execute.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UrlRewritingPlacement {
    /// No sampler identity was established by the caller.
    Unproven,
    /// The caller established that this modifier is scoped to an HTTP sampler.
    HttpSampler,
}

impl UrlRewritingPlacement {
    const fn is_proven(self) -> bool {
        matches!(self, Self::HttpSampler)
    }
}

/// Decoded, bounded URL-rewriting properties.
///
/// The argument name is held as a BoundedText so its debug output is redacted
/// in the same way as runtime request values.
#[derive(Clone, Eq, PartialEq)]
pub struct UrlRewritingModifierConfig {
    enabled: bool,
    path_extension: bool,
    path_extension_no_questionmark: bool,
    argument_name: BoundedText,
    path_extension_no_equals: bool,
    cache_value: bool,
    encode: bool,
}

impl fmt::Debug for UrlRewritingModifierConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UrlRewritingModifierConfig")
            .field("enabled", &self.enabled)
            .field("path_extension", &self.path_extension)
            .field(
                "path_extension_no_questionmark",
                &self.path_extension_no_questionmark,
            )
            .field("argument_name", &self.argument_name)
            .field("path_extension_no_equals", &self.path_extension_no_equals)
            .field("cache_value", &self.cache_value)
            .field("encode", &self.encode)
            .finish()
    }
}

impl UrlRewritingModifierConfig {
    /// Creates a source-independent configuration with JMeter's defaults.
    pub fn new(argument_name: impl Into<String>) -> Result<Self, UrlRewritingModifierDecodeError> {
        let argument_name = argument_name.into();
        let argument_name = bounded_argument_name(&argument_name)?;
        Ok(Self {
            enabled: true,
            path_extension: false,
            path_extension_no_questionmark: false,
            argument_name,
            path_extension_no_equals: false,
            cache_value: true,
            encode: false,
        })
    }

    /// Returns whether this source element is enabled.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the path-extension mode.
    #[must_use]
    pub const fn path_extension(&self) -> bool {
        self.path_extension
    }

    /// Returns the path-extension question-mark mode.
    #[must_use]
    pub const fn path_extension_no_questionmark(&self) -> bool {
        self.path_extension_no_questionmark
    }

    /// Returns the exact argument name.
    #[must_use]
    pub fn argument_name(&self) -> &str {
        self.argument_name.as_str()
    }

    /// Returns the path-extension equals mode.
    #[must_use]
    pub const fn path_extension_no_equals(&self) -> bool {
        self.path_extension_no_equals
    }

    /// Returns whether the last non-empty value is cached per component/user.
    #[must_use]
    pub const fn cache_value(&self) -> bool {
        self.cache_value
    }

    /// Returns JMeter's parameter value encoding flag.
    #[must_use]
    pub const fn encode(&self) -> bool {
        self.encode
    }

    /// Changes the source enabled state while retaining the bounded config.
    #[must_use]
    pub const fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Changes path-extension extraction.
    #[must_use]
    pub const fn with_path_extension(mut self, value: bool) -> Self {
        self.path_extension = value;
        self
    }

    /// Changes whether question marks terminate path-extension values.
    #[must_use]
    pub const fn with_path_extension_no_questionmark(mut self, value: bool) -> Self {
        self.path_extension_no_questionmark = value;
        self
    }

    /// Changes whether path-extension values omit equals.
    #[must_use]
    pub const fn with_path_extension_no_equals(mut self, value: bool) -> Self {
        self.path_extension_no_equals = value;
        self
    }

    /// Changes the per-user cache flag.
    #[must_use]
    pub const fn with_cache_value(mut self, value: bool) -> Self {
        self.cache_value = value;
        self
    }

    /// Changes JMeter's parameter encoding flag.
    #[must_use]
    pub const fn with_encode(mut self, value: bool) -> Self {
        self.encode = value;
        self
    }
}

/// Redacted source decoder errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UrlRewritingModifierDecodeError {
    /// The source class is not one of the two exact aliases.
    UnsupportedTestClass,
    /// The element's category is not a preprocessor.
    WrongCategory,
    /// A required argument-name property is absent.
    MissingArgumentName,
    /// A property has the wrong typed model value.
    InvalidPropertyType,
    /// The argument name is empty or contains an invalid bounded value.
    InvalidArgumentName,
    /// A source property or collection exceeded a local bound.
    Limit,
    /// A property is outside the pinned native surface.
    UnsupportedProperty,
    /// An opaque or temporary extension cannot be interpreted safely.
    OpaqueExtension,
}

impl UrlRewritingModifierDecodeError {
    /// Returns a stable diagnostic code without including source values.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedTestClass => "app.url-rewriting.decode-test-class",
            Self::WrongCategory => "app.url-rewriting.decode-category",
            Self::MissingArgumentName => "app.url-rewriting.decode-argument-name-missing",
            Self::InvalidPropertyType => "app.url-rewriting.decode-property-type",
            Self::InvalidArgumentName => "app.url-rewriting.decode-argument-name",
            Self::Limit => "app.url-rewriting.decode-limit",
            Self::UnsupportedProperty => "app.url-rewriting.decode-property-unsupported",
            Self::OpaqueExtension => "app.url-rewriting.decode-opaque-extension",
        }
    }
}

impl fmt::Display for UrlRewritingModifierDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for UrlRewritingModifierDecodeError {}

/// Runtime and extraction failures for one modifier invocation.
///
/// Variants deliberately contain only stable labels or redacted runtime error
/// codes. Response bodies, captured tokens, source property values, and
/// request URLs are never placed in diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UrlRewritingModifierError {
    /// The enclosing sampler was not proven to be HTTP.
    UnsupportedPlacement,
    /// The phase did not provide an explicit previous result.
    MissingPreviousResult,
    /// The previous result did not expose a body projection.
    MissingResponseBody,
    /// The bounded response body was not valid UTF-8 for this seam.
    InvalidResponseEncoding,
    /// Retained for stable API compatibility; the pinned HTTPArgument path
    /// carries malformed percent text through without rejecting it.
    MalformedEncoding,
    /// A token or request candidate exceeded a local bound.
    ResourceLimit,
    /// The resolver/provider was not available for the requested projection.
    ResponseUnavailable,
    /// A runtime generation, digest, request, cancellation, or control check
    /// rejected the atomic mutation.
    Mutation(MutationErrorCode),
}

impl UrlRewritingModifierError {
    /// Returns a stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedPlacement => "app.url-rewriting.placement-unsupported",
            Self::MissingPreviousResult => "app.url-rewriting.previous-result-missing",
            Self::MissingResponseBody => "app.url-rewriting.response-body-missing",
            Self::InvalidResponseEncoding => "app.url-rewriting.response-encoding",
            Self::MalformedEncoding => "app.url-rewriting.token-encoding",
            Self::ResourceLimit => "app.url-rewriting.resource-limit",
            Self::ResponseUnavailable => "app.url-rewriting.response-unavailable",
            Self::Mutation(code) => code.as_str(),
        }
    }
}

impl fmt::Display for UrlRewritingModifierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for UrlRewritingModifierError {}

/// One bounded proposal produced before the runtime transaction boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UrlRewritingProposal {
    patch: RequestPatch,
    extracted_value: BoundedText,
    effective_value: BoundedText,
}

impl UrlRewritingProposal {
    /// Returns the generation/digest-bound request patch.
    #[must_use]
    pub const fn patch(&self) -> &RequestPatch {
        &self.patch
    }

    /// Returns the value extracted from this response.
    #[must_use]
    pub fn extracted_value(&self) -> &str {
        self.extracted_value.as_str()
    }

    /// Returns the value selected after applying the cache policy.
    #[must_use]
    pub fn effective_value(&self) -> &str {
        self.effective_value.as_str()
    }
}

/// Extracts and proposes a typed request patch without committing it.
///
/// cached_value is an explicit per-user value. This function itself has no
/// ambient state, which makes it suitable for deterministic external harnesses
/// and for validating cache behavior before the runtime commit.
pub fn propose_url_rewriting_patch(
    config: &UrlRewritingModifierConfig,
    request: &RequestState,
    response: &ResponseResolution,
    cached_value: Option<&str>,
) -> Result<UrlRewritingProposal, UrlRewritingModifierError> {
    let extracted = extract_response_value(config, response)?;
    let effective = if config.cache_value() && extracted.is_empty() {
        let cached = cached_value.unwrap_or("");
        bounded_token(cached)?
    } else {
        extracted.clone()
    };
    let patch = build_request_patch(config, request, effective.as_str())?;
    Ok(UrlRewritingProposal {
        patch,
        extracted_value: extracted,
        effective_value: effective,
    })
}

/// Extracts one bounded value using the exact pinned flag family.
pub fn extract_response_value(
    config: &UrlRewritingModifierConfig,
    response: &ResponseResolution,
) -> Result<BoundedText, UrlRewritingModifierError> {
    let input = current_body_input(response)?;
    let text = decode_current_body(input)?;
    let token = if config.path_extension() {
        extract_path_extension(&text, config)
    } else {
        extract_parameter(&text, config.argument_name())
    };
    bounded_token(token.unwrap_or_default())
}

/// Returns the one current sample input selected by the rev3 response seam.
/// URL rewriting deliberately does not accept a child, variable, file, or
/// provider projection: those are distinct response capabilities and would
/// change the upstream component's source-selection semantics.
fn current_body_input(
    response: &ResponseResolution,
) -> Result<&ResponseInput, UrlRewritingModifierError> {
    let inputs = match response {
        ResponseResolution::NoCurrentResult => {
            return Err(UrlRewritingModifierError::MissingPreviousResult);
        }
        ResponseResolution::Variable(_) => {
            return Err(UrlRewritingModifierError::ResponseUnavailable);
        }
        ResponseResolution::Samples(inputs) => inputs,
    };
    if inputs.target() != ResponseTarget::Body || inputs.items().len() != 1 {
        return Err(UrlRewritingModifierError::ResponseUnavailable);
    }
    let input = inputs
        .items()
        .first()
        .ok_or(UrlRewritingModifierError::MissingPreviousResult)?;
    if !matches!(&input.origin, jmeter_rs_runtime::ResponseOrigin::Current) {
        return Err(UrlRewritingModifierError::ResponseUnavailable);
    }
    if !matches!(
        input.selected(),
        Presence::Missing | Presence::Present(ResponseSelection::Bytes(_))
    ) {
        return Err(UrlRewritingModifierError::ResponseUnavailable);
    }
    Ok(input)
}

/// Decodes the explicitly selected current body with its declared encoding,
/// falling back only to the explicit UTF-8 default. Known malformed sequences
/// use replacement semantics; unknown encodings fail closed because this
/// component has no implicit host codec/provider capability.
fn decode_current_body(input: &ResponseInput) -> Result<String, UrlRewritingModifierError> {
    let bytes = match input.selected() {
        Presence::Missing => return Ok(String::new()),
        Presence::Present(ResponseSelection::Bytes(value)) => value.as_bytes(),
        Presence::Present(ResponseSelection::SourceText(_)) => {
            return Err(UrlRewritingModifierError::ResponseUnavailable);
        }
    };
    if bytes.len() > MAX_URL_REWRITING_RESPONSE_BYTES {
        return Err(UrlRewritingModifierError::ResourceLimit);
    }
    if bytes.is_empty() {
        return Ok(String::new());
    }
    let encoding = match &input.record().metadata().encoding {
        Presence::Present(value) if !value.is_empty() => value.to_string_lossy(),
        Presence::Missing | Presence::Present(_) => String::from("UTF-8"),
    };
    decode_response_bytes(bytes, &encoding)
}

fn decode_response_bytes(
    input: &[u8],
    encoding: &str,
) -> Result<String, UrlRewritingModifierError> {
    if input.len() > MAX_URL_REWRITING_RESPONSE_BYTES {
        return Err(UrlRewritingModifierError::ResourceLimit);
    }
    let normalized = encoding.to_ascii_lowercase();
    match normalized.trim() {
        "utf-8" | "utf8" => decode_utf8_replacement(input),
        "us-ascii" | "ascii" => decode_ascii_replacement(input),
        "iso-8859-1" | "iso8859-1" | "latin1" | "latin-1" => decode_latin1(input),
        "utf-16" | "utf16" | "utf-16le" | "utf16le" | "utf-16be" | "utf16be" => {
            decode_utf16(input, normalized.trim())
        }
        _ => Err(UrlRewritingModifierError::ResponseUnavailable),
    }
}

fn push_decoded_char(output: &mut String, value: char) -> Result<(), UrlRewritingModifierError> {
    let width = value.len_utf8();
    let next = output
        .len()
        .checked_add(width)
        .ok_or(UrlRewritingModifierError::ResourceLimit)?;
    if next > MAX_URL_REWRITING_RESPONSE_BYTES {
        return Err(UrlRewritingModifierError::ResourceLimit);
    }
    output.push(value);
    Ok(())
}

fn push_decoded_bytes(output: &mut String, value: &[u8]) -> Result<(), UrlRewritingModifierError> {
    let next = output
        .len()
        .checked_add(value.len())
        .ok_or(UrlRewritingModifierError::ResourceLimit)?;
    if next > MAX_URL_REWRITING_RESPONSE_BYTES {
        return Err(UrlRewritingModifierError::ResourceLimit);
    }
    output.push_str(
        std::str::from_utf8(value)
            .map_err(|_| UrlRewritingModifierError::InvalidResponseEncoding)?,
    );
    Ok(())
}

fn decode_utf8_replacement(input: &[u8]) -> Result<String, UrlRewritingModifierError> {
    let mut output = String::with_capacity(input.len().min(MAX_URL_REWRITING_RESPONSE_BYTES));
    let mut offset = 0;
    while offset < input.len() {
        match std::str::from_utf8(&input[offset..]) {
            Ok(value) => {
                push_decoded_bytes(&mut output, value.as_bytes())?;
                break;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                if valid != 0 {
                    push_decoded_bytes(&mut output, &input[offset..offset + valid])?;
                }
                push_decoded_char(&mut output, '\u{fffd}')?;
                let invalid_len = error.error_len().unwrap_or(input.len() - offset - valid);
                offset = offset
                    .checked_add(valid)
                    .and_then(|value| value.checked_add(invalid_len))
                    .ok_or(UrlRewritingModifierError::ResourceLimit)?;
            }
        }
    }
    Ok(output)
}

fn decode_ascii_replacement(input: &[u8]) -> Result<String, UrlRewritingModifierError> {
    let mut output = String::with_capacity(input.len().min(MAX_URL_REWRITING_RESPONSE_BYTES));
    for value in input {
        push_decoded_char(
            &mut output,
            if *value < 0x80 {
                char::from(*value)
            } else {
                '\u{fffd}'
            },
        )?;
    }
    Ok(output)
}

fn decode_latin1(input: &[u8]) -> Result<String, UrlRewritingModifierError> {
    let mut output = String::with_capacity(input.len().min(MAX_URL_REWRITING_RESPONSE_BYTES));
    for value in input {
        push_decoded_char(&mut output, char::from(*value))?;
    }
    Ok(output)
}

fn decode_utf16(
    input: &[u8],
    normalized_encoding: &str,
) -> Result<String, UrlRewritingModifierError> {
    let mut output = String::with_capacity(input.len().min(MAX_URL_REWRITING_RESPONSE_BYTES));
    let mut bytes = input;
    let mut little_endian = matches!(normalized_encoding, "utf-16le" | "utf16le");
    if matches!(normalized_encoding, "utf-16" | "utf16") {
        if bytes.len() >= 2 && bytes[0] == 0xff && bytes[1] == 0xfe {
            little_endian = true;
            bytes = &bytes[2..];
        } else if bytes.len() >= 2 && bytes[0] == 0xfe && bytes[1] == 0xff {
            little_endian = false;
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
        push_decoded_char(&mut output, character)?;
    }
    if index < bytes.len() {
        push_decoded_char(&mut output, '\u{fffd}')?;
    }
    Ok(output)
}

/// Builds a generation/digest-bound patch while retaining non-matching field
/// order and each raw/encoded presence bit.
pub fn build_request_patch(
    config: &UrlRewritingModifierConfig,
    request: &RequestState,
    value: &str,
) -> Result<RequestPatch, UrlRewritingModifierError> {
    validate_request_bounds(request)?;
    let value = bounded_token(value)?;
    request.validate().map_err(map_mutation_error)?;
    let mut patch = RequestPatch::new(request.generation(), request.digest());
    if config.path_extension() {
        patch.replace_path_segments(rewrite_path_segments(
            config,
            request.path_segments(),
            &value,
        )?);
    } else {
        patch.replace_query_fields(rewrite_query_fields(
            config,
            request.query_fields(),
            &value,
        )?);
    }
    patch.validate().map_err(map_mutation_error)?;
    Ok(patch)
}

/// Checks request cardinality and canonical size before any request digest or
/// rewrite allocation. The runtime request types enforce the same limits at
/// their transaction boundary; this early check keeps this processor's own
/// admission independent and bounded.
fn validate_request_bounds(request: &RequestState) -> Result<(), UrlRewritingModifierError> {
    if request.path_segments().len() > jmeter_rs_runtime::DEFAULT_MAX_REQUEST_PATH_SEGMENTS
        || request.query_fields().len() > jmeter_rs_runtime::DEFAULT_MAX_REQUEST_QUERY_FIELDS
        || request.headers().len() > jmeter_rs_runtime::DEFAULT_MAX_REQUEST_HEADERS
    {
        return Err(UrlRewritingModifierError::ResourceLimit);
    }
    let canonical_bytes = request_canonical_len(request)?;
    if canonical_bytes > jmeter_rs_runtime::DEFAULT_MAX_REQUEST_BYTES {
        return Err(UrlRewritingModifierError::ResourceLimit);
    }
    Ok(())
}

fn request_canonical_len(request: &RequestState) -> Result<usize, UrlRewritingModifierError> {
    let mut total = 0usize;
    total = checked_add(total, presence_text_len(request.scheme()), "request-scheme")?;
    total = checked_add(
        total,
        presence_authority_len(request.authority())?,
        "request-authority",
    )?;
    total = checked_add(total, 8, "request-path-count")?;
    for field in request.path_segments() {
        total = checked_add(total, encoded_field_len(field)?, "request-path")?;
    }
    total = checked_add(total, 8, "request-query-count")?;
    for field in request.query_fields() {
        total = checked_add(total, query_field_len(field)?, "request-query")?;
    }
    total = checked_add(total, presence_text_len(request.method()), "request-method")?;
    total = checked_add(total, presence_bytes_len(request.body())?, "request-body")?;
    total = checked_add(total, 8, "request-header-count")?;
    for header in request.headers() {
        total = checked_add(
            total,
            checked_add(
                8 + header.name.len(),
                8 + header.value.len(),
                "request-header",
            )?,
            "request-headers",
        )?;
    }
    Ok(total)
}

fn checked_add(
    left: usize,
    right: usize,
    _field: &'static str,
) -> Result<usize, UrlRewritingModifierError> {
    left.checked_add(right)
        .ok_or(UrlRewritingModifierError::ResourceLimit)
}

fn presence_text_len(value: &Presence<BoundedText>) -> usize {
    match value {
        Presence::Missing => 1,
        Presence::Present(value) => 1 + 8 + value.len(),
    }
}

fn presence_bytes_len(
    value: &Presence<jmeter_rs_runtime::BoundedBytes>,
) -> Result<usize, UrlRewritingModifierError> {
    match value {
        Presence::Missing => Ok(1),
        Presence::Present(value) => checked_add(1 + 8, value.len(), "request-body"),
    }
}

fn presence_authority_len(
    value: &Presence<jmeter_rs_runtime::RequestAuthority>,
) -> Result<usize, UrlRewritingModifierError> {
    match value {
        Presence::Missing => Ok(1),
        Presence::Present(value) => {
            let port = if value.port.is_some() { 1 + 8 } else { 1 };
            checked_add(
                checked_add(1 + 8 + value.host.len(), port, "request-port")?,
                0,
                "request-authority",
            )
        }
    }
}

fn encoded_field_len(value: &EncodedField) -> Result<usize, UrlRewritingModifierError> {
    checked_add(
        presence_text_len(&value.raw),
        presence_text_len(&value.encoded),
        "request-field",
    )
}

fn query_field_len(value: &QueryField) -> Result<usize, UrlRewritingModifierError> {
    let name = encoded_field_len(&value.name)?;
    let value = match &value.value {
        Presence::Missing => 1,
        Presence::Present(value) => {
            checked_add(1, encoded_field_len(value)?, "request-query-value")?
        }
    };
    checked_add(name, value, "request-query")
}

/// A fresh per-user native modifier. It is intentionally not Clone: the cache
/// belongs to one virtual-user component instance.
pub struct UrlRewritingModifier {
    config: UrlRewritingModifierConfig,
    placement: UrlRewritingPlacement,
    resolver: Arc<dyn ScopedResponseResolver>,
    saved_value: Mutex<Option<BoundedText>>,
}

impl fmt::Debug for UrlRewritingModifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UrlRewritingModifier")
            .field("config", &self.config)
            .field("placement", &self.placement)
            .field("resolver", &"injected")
            .field("saved_value", &"redacted")
            .finish()
    }
}

impl UrlRewritingModifier {
    /// Creates an unproven component. Its generic Preprocessor seam is a
    /// pinned-behavior no-op until an HTTP placement and previous result are
    /// supplied explicitly.
    #[must_use]
    pub fn new(config: UrlRewritingModifierConfig) -> Self {
        Self::with_resolver(
            config,
            UrlRewritingPlacement::Unproven,
            bounded_response_resolver(),
        )
    }

    /// Creates a component after the caller has proved HTTP sampler placement.
    #[must_use]
    pub fn for_http_sampler(config: UrlRewritingModifierConfig) -> Self {
        Self::with_resolver(
            config,
            UrlRewritingPlacement::HttpSampler,
            bounded_response_resolver(),
        )
    }

    /// Creates a component with an explicit placement proof and response
    /// resolver. The resolver remains executor-neutral and performs no I/O.
    #[must_use]
    pub fn with_resolver(
        config: UrlRewritingModifierConfig,
        placement: UrlRewritingPlacement,
        resolver: Arc<dyn ScopedResponseResolver>,
    ) -> Self {
        Self {
            config,
            placement,
            resolver,
            saved_value: Mutex::new(None),
        }
    }

    /// Returns the decoded configuration.
    #[must_use]
    pub const fn config(&self) -> &UrlRewritingModifierConfig {
        &self.config
    }

    /// Returns the placement proof.
    #[must_use]
    pub const fn placement(&self) -> UrlRewritingPlacement {
        self.placement
    }

    /// Runs the processor synchronously at the generic runtime boundary.
    ///
    /// The generic preprocessor phase cannot identify the exact prior sampler
    /// result. JMeter's processor is a silent no-op when its current sampler
    /// is not HTTP or when no previous result exists, so this unregistered
    /// generic seam is also a no-op. Use process_previous_result_now or
    /// process_response_now at an application seam that carries that proof.
    pub fn process_now(
        &self,
        _context: &mut SampleContext<'_>,
    ) -> Result<(), UrlRewritingModifierError> {
        if !self.config.enabled() {
            return Ok(());
        }
        // The generic runtime preprocessor context has no previous-sampler
        // result slot and no current-sampler identity. In particular,
        // context.result() is the result produced by the current sampler and
        // is not the previous result JMeter exposes to this modifier. Do not
        // substitute it or an ambient result view. The exact pinned behavior
        // for an unproven/non-HTTP or missing-result seam is no observable
        // mutation and no error.
        Ok(())
    }

    /// Processes an explicitly supplied previous sampler result.
    ///
    /// The caller owns the proof that previous_result is the result JMeter
    /// exposes to this preprocessor. This method is the executable seam for an
    /// application pipeline that can provide that proof; the generic
    /// Preprocessor trait path remains a pinned no-op.
    pub fn process_previous_result_now(
        &self,
        context: &mut SampleContext<'_>,
        previous_result: &jmeter_rs_results::SampleResult,
    ) -> Result<(), UrlRewritingModifierError> {
        if !self.config.enabled() {
            return Ok(());
        }
        if !self.placement.is_proven() {
            return Err(UrlRewritingModifierError::UnsupportedPlacement);
        }
        let response = self
            .resolver
            .resolve_scoped(
                Some(previous_result),
                &BTreeMap::new(),
                &ResponseScope::Current,
                ResponseTarget::Body,
                &ResponseDecodePolicy::declared_or_utf8(),
            )
            .map_err(map_response_error)?;
        self.process_response_now(context, &response)
    }

    /// Processes an explicitly resolved current-body selection.
    ///
    /// This method performs the one atomic InvocationDelta commit and updates
    /// the per-user cache only after that commit succeeds. It is also the
    /// deterministic external-harness seam when a resolver/result bridge is
    /// unavailable.
    pub fn process_response_now(
        &self,
        context: &mut SampleContext<'_>,
        response: &ResponseResolution,
    ) -> Result<(), UrlRewritingModifierError> {
        if !self.config.enabled() {
            return Ok(());
        }
        if !self.placement.is_proven() {
            return Err(UrlRewritingModifierError::UnsupportedPlacement);
        }
        // A poisoned cache lock means the per-user state is no longer
        // trustworthy. Fail closed; recovering the inner value would silently
        // mix an uncertain cache with a valid invocation.
        let mut saved = self.saved_value.lock().map_err(|_| cache_lock_error())?;
        let cached_text = saved.as_ref().map(BoundedText::as_str);
        let proposal = propose_url_rewriting_patch(
            &self.config,
            context.request_state(),
            response,
            cached_text,
        )?;

        let mut delta = InvocationDelta::new(context.context_generation());
        delta.set_request_patch(proposal.patch.clone());
        context
            .apply_invocation_delta(&delta)
            .map_err(map_mutation_error)?;

        if self.config.cache_value() && !proposal.extracted_value.is_empty() {
            *saved = Some(proposal.extracted_value);
        }
        Ok(())
    }
}

impl Preprocessor for UrlRewritingModifier {
    fn process<'a>(&'a self, context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, ()> {
        Box::pin(async move { self.process_now(context).map_err(component_error) })
    }
}

/// Factory configuration for one exact source element. Calling new leaves
/// placement unproven; use for_http_sampler only where the application has an
/// explicit HTTP sampler binding.
pub struct UrlRewritingModifierFactory {
    config: UrlRewritingModifierConfig,
    placement: UrlRewritingPlacement,
    resolver: Arc<dyn ScopedResponseResolver>,
}

impl fmt::Debug for UrlRewritingModifierFactory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UrlRewritingModifierFactory")
            .field("config", &self.config)
            .field("placement", &self.placement)
            .field("resolver", &"injected")
            .finish()
    }
}

impl UrlRewritingModifierFactory {
    /// Creates an unproven factory for an already decoded source element.
    #[must_use]
    pub fn new(config: UrlRewritingModifierConfig) -> Self {
        Self::with_resolver(
            config,
            UrlRewritingPlacement::Unproven,
            bounded_response_resolver(),
        )
    }

    /// Creates a factory after the application has established HTTP placement.
    #[must_use]
    pub fn for_http_sampler(config: UrlRewritingModifierConfig) -> Self {
        Self::with_resolver(
            config,
            UrlRewritingPlacement::HttpSampler,
            bounded_response_resolver(),
        )
    }

    /// Creates a factory with an explicit response resolver and placement.
    #[must_use]
    pub fn with_resolver(
        config: UrlRewritingModifierConfig,
        placement: UrlRewritingPlacement,
        resolver: Arc<dyn ScopedResponseResolver>,
    ) -> Self {
        Self {
            config,
            placement,
            resolver,
        }
    }
}

impl PreprocessorFactory for UrlRewritingModifierFactory {
    fn create(&self) -> Arc<dyn Preprocessor> {
        Arc::new(UrlRewritingModifier::with_resolver(
            self.config.clone(),
            self.placement,
            Arc::clone(&self.resolver),
        ))
    }
}

impl ScopeComponentFactory for UrlRewritingModifierFactory {
    fn create(&self, component: &ScopeComponent) -> Result<FactoryComponent, ScopeFactoryError> {
        if component.binding.category != ComponentCategory::Preprocessor {
            return Err(scope_decode(
                component,
                UrlRewritingModifierDecodeError::WrongCategory,
            ));
        }
        if component.element.test_class() != component.binding.test_class {
            return Err(scope_decode(
                component,
                UrlRewritingModifierDecodeError::UnsupportedTestClass,
            ));
        }
        let config = decode_url_rewriting_modifier(&component.element)
            .map_err(|error| scope_decode(component, error))?;
        if !self.placement.is_proven() {
            return Err(scope_decode_message(
                component,
                "app.url-rewriting.placement-unsupported",
            ));
        }
        Ok(FactoryComponent::Preprocessor(Arc::new(
            UrlRewritingModifier::with_resolver(config, self.placement, Arc::clone(&self.resolver)),
        )))
    }
}

/// Decodes one exact source element and rejects unknown or opaque properties.
pub fn decode_url_rewriting_modifier(
    element: &TestElement,
) -> Result<UrlRewritingModifierConfig, UrlRewritingModifierDecodeError> {
    if !is_url_rewriting_alias(element.test_class()) {
        return Err(UrlRewritingModifierDecodeError::UnsupportedTestClass);
    }
    if element.properties.len() > MAX_URL_REWRITING_PROPERTIES {
        return Err(UrlRewritingModifierDecodeError::Limit);
    }
    if !element.temporary_properties.is_empty() || !element.opaque_extensions.is_empty() {
        return Err(UrlRewritingModifierDecodeError::OpaqueExtension);
    }

    let mut path_extension = false;
    let mut path_extension_no_questionmark = false;
    let mut argument_name: Option<BoundedText> = None;
    let mut path_extension_no_equals = false;
    let mut cache_value = true;
    let mut encode = false;

    for property in element.properties.iter() {
        match property.name.as_str() {
            PROPERTY_PATH_EXTENSION => {
                path_extension = property_bool(&property.value)?;
            }
            PROPERTY_PATH_EXTENSION_NO_QUESTIONMARK => {
                path_extension_no_questionmark = property_bool(&property.value)?;
            }
            PROPERTY_ARGUMENT_NAME => {
                let value = property
                    .value
                    .as_string()
                    .map_err(|_| UrlRewritingModifierDecodeError::InvalidPropertyType)?;
                argument_name = Some(bounded_argument_name(value)?);
            }
            PROPERTY_PATH_EXTENSION_NO_EQUALS => {
                path_extension_no_equals = property_bool(&property.value)?;
            }
            PROPERTY_CACHE_VALUE => {
                cache_value = property_bool(&property.value)?;
            }
            PROPERTY_ENCODE => {
                encode = property_bool(&property.value)?;
            }
            _ => return Err(UrlRewritingModifierDecodeError::UnsupportedProperty),
        }
    }

    let argument_name =
        argument_name.ok_or(UrlRewritingModifierDecodeError::MissingArgumentName)?;
    if argument_name.is_empty() {
        return Err(UrlRewritingModifierDecodeError::InvalidArgumentName);
    }
    Ok(UrlRewritingModifierConfig {
        enabled: element.is_enabled(),
        path_extension,
        path_extension_no_questionmark,
        argument_name,
        path_extension_no_equals,
        cache_value,
        encode,
    })
}

/// Returns whether a source class is one of the exact admitted aliases.
#[must_use]
pub fn is_url_rewriting_alias(test_class: &str) -> bool {
    matches!(
        test_class,
        URL_REWRITING_MODIFIER_ALIAS | URL_REWRITING_MODIFIER_CLASS
    )
}

fn property_bool(value: &PropertyValue) -> Result<bool, UrlRewritingModifierDecodeError> {
    value
        .as_boolean()
        .map_err(|_| UrlRewritingModifierDecodeError::InvalidPropertyType)
}

fn bounded_argument_name(value: &str) -> Result<BoundedText, UrlRewritingModifierDecodeError> {
    if value.len() > MAX_URL_REWRITING_ARGUMENT_BYTES {
        return Err(UrlRewritingModifierDecodeError::Limit);
    }
    let bounded = BoundedText::try_new(value.to_owned(), MAX_URL_REWRITING_ARGUMENT_BYTES)
        .map_err(|_| UrlRewritingModifierDecodeError::InvalidArgumentName)?;
    if bounded.is_empty() {
        return Err(UrlRewritingModifierDecodeError::InvalidArgumentName);
    }
    Ok(bounded)
}

fn bounded_token(value: &str) -> Result<BoundedText, UrlRewritingModifierError> {
    if value.len() > MAX_URL_REWRITING_TOKEN_BYTES {
        return Err(UrlRewritingModifierError::ResourceLimit);
    }
    BoundedText::try_new(value.to_owned(), MAX_URL_REWRITING_TOKEN_BYTES).map_err(|error| {
        match error.code() {
            MutationErrorCode::Limit => UrlRewritingModifierError::ResourceLimit,
            _ => UrlRewritingModifierError::MalformedEncoding,
        }
    })
}

fn bounded_response_resolver() -> Arc<dyn ScopedResponseResolver> {
    let limits = ResponseLimits::default()
        .with_body_bytes(MAX_URL_REWRITING_RESPONSE_BYTES)
        .with_header_bytes(MAX_URL_REWRITING_RESPONSE_BYTES)
        .with_metadata_bytes(MAX_URL_REWRITING_RESPONSE_BYTES)
        .with_decoded_bytes(MAX_URL_REWRITING_RESPONSE_BYTES)
        .with_file_bytes(MAX_URL_REWRITING_RESPONSE_BYTES)
        .with_items(1)
        .with_depth(0)
        .with_variable_bytes(MAX_URL_REWRITING_TOKEN_BYTES)
        .with_provider_bytes(
            MAX_URL_REWRITING_RESPONSE_BYTES,
            MAX_URL_REWRITING_RESPONSE_BYTES,
        );
    match ResponseInputSetResolver::new(limits) {
        Ok(resolver) => Arc::new(resolver),
        Err(_) => Arc::new(UnavailableResponseResolver),
    }
}

struct UnavailableResponseResolver;

impl ScopedResponseResolver for UnavailableResponseResolver {
    fn resolve_scoped(
        &self,
        _current: Option<&jmeter_rs_results::SampleResult>,
        _variables: &BTreeMap<String, String>,
        _scope: &ResponseScope,
        _target: ResponseTarget,
        _decode_policy: &ResponseDecodePolicy,
    ) -> Result<ResponseResolution, MutationError> {
        Err(MutationError::limit("url-rewriting-response-resolver"))
    }
}

fn map_mutation_error(error: MutationError) -> UrlRewritingModifierError {
    if error.code() == MutationErrorCode::Limit {
        UrlRewritingModifierError::ResourceLimit
    } else {
        UrlRewritingModifierError::Mutation(error.code())
    }
}

fn cache_lock_error() -> UrlRewritingModifierError {
    UrlRewritingModifierError::Mutation(MutationErrorCode::Internal)
}

fn map_response_error(error: MutationError) -> UrlRewritingModifierError {
    if error.code() == MutationErrorCode::Limit {
        UrlRewritingModifierError::ResourceLimit
    } else {
        UrlRewritingModifierError::ResponseUnavailable
    }
}

fn component_error(error: UrlRewritingModifierError) -> ComponentError {
    match error {
        UrlRewritingModifierError::ResourceLimit => ComponentError::resource_limit(error.code()),
        UrlRewritingModifierError::UnsupportedPlacement
        | UrlRewritingModifierError::MissingPreviousResult
        | UrlRewritingModifierError::MissingResponseBody
        | UrlRewritingModifierError::ResponseUnavailable => {
            ComponentError::unsupported(error.code())
        }
        UrlRewritingModifierError::InvalidResponseEncoding
        | UrlRewritingModifierError::MalformedEncoding
        | UrlRewritingModifierError::Mutation(_) => ComponentError::failure(error.code()),
    }
}

fn scope_decode(
    component: &ScopeComponent,
    error: UrlRewritingModifierDecodeError,
) -> ScopeFactoryError {
    scope_decode_message(component, error.code())
}

fn scope_decode_message(component: &ScopeComponent, detail: &str) -> ScopeFactoryError {
    ScopeFactoryError::Decode {
        node_id: component.node_id,
        path: component.path.clone(),
        test_class: bounded_diagnostic(component.element.test_class()),
        category: ComponentCategory::Preprocessor,
        detail: bounded_diagnostic(detail),
    }
}

fn bounded_diagnostic(value: &str) -> String {
    const MAX_DIAGNOSTIC_BYTES: usize = 256;
    let mut end = value.len().min(MAX_DIAGNOSTIC_BYTES);
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn extract_path_extension<'a>(
    text: &'a str,
    config: &UrlRewritingModifierConfig,
) -> Option<&'a str> {
    let argument = config.argument_name();
    let marker = bounded_join(&[";", argument]).ok()?;
    let mut cursor = 0;
    while let Some(relative) = text[cursor..].find(&marker) {
        let marker_index = cursor + relative;
        let value_start = marker_index + marker.len();
        if config.path_extension_no_equals() {
            return Some(capture_until(
                text,
                value_start,
                config.path_extension_no_questionmark(),
                true,
                false,
            ));
        }
        if text.as_bytes().get(value_start) == Some(&b'=') {
            return Some(capture_until(
                text,
                value_start + 1,
                config.path_extension_no_questionmark(),
                true,
                false,
            ));
        }
        cursor = value_start;
        if cursor >= text.len() {
            break;
        }
    }
    None
}

fn extract_parameter<'a>(text: &'a str, argument: &str) -> Option<&'a str> {
    let query = find_query_parameter(text, argument);
    let form_name_first = find_form_parameter(text, argument, true);
    let form_value_first = find_form_parameter(text, argument, false);
    [query, form_name_first, form_value_first]
        .into_iter()
        .flatten()
        .min_by_key(|(start, _)| *start)
        .map(|(_, value)| value)
}

fn find_query_parameter<'a>(text: &'a str, argument: &str) -> Option<(usize, &'a str)> {
    for (index, character) in text.char_indices() {
        if !matches!(character, ';' | '?' | '&')
            || !text[index + character.len_utf8()..].starts_with(argument)
        {
            continue;
        }
        let argument_end = index + character.len_utf8() + argument.len();
        if text.as_bytes().get(argument_end) != Some(&b'=') {
            continue;
        }
        let value_start = argument_end + 1;
        return Some((index, capture_until(text, value_start, false, true, true)));
    }
    None
}

fn find_form_parameter<'a>(
    text: &'a str,
    argument: &str,
    name_first: bool,
) -> Option<(usize, &'a str)> {
    for (start, character) in text.char_indices() {
        if !character.is_ascii_whitespace() {
            continue;
        }
        let first_start = start + character.len_utf8();
        if name_first {
            if let Some(first_end) =
                parse_form_literal_attribute(text, first_start, "name", argument)
            {
                let limit = text[first_end..]
                    .find('>')
                    .map_or(text.len(), |offset| first_end + offset);
                if let Some((_, value)) = find_last_form_value_attribute(text, first_end, limit) {
                    return Some((start, value));
                }
            }
        } else if let Some((value, first_end)) =
            parse_form_value_attribute(text, first_start, "value")
        {
            let limit = text[first_end..]
                .find('>')
                .map_or(text.len(), |offset| first_end + offset);
            if parse_last_form_literal_attribute(text, first_end, limit, "name", argument).is_some()
            {
                return Some((start, value));
            }
        }
    }
    None
}

fn ascii_token_at(text: &str, start: usize, token: &str) -> bool {
    text.get(start..start.saturating_add(token.len()))
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(token))
}

fn skip_ascii_whitespace(text: &str, mut cursor: usize) -> usize {
    while text
        .as_bytes()
        .get(cursor)
        .is_some_and(u8::is_ascii_whitespace)
    {
        cursor += 1;
    }
    cursor
}

fn parse_form_literal_attribute(
    text: &str,
    start: usize,
    attribute: &str,
    expected: &str,
) -> Option<usize> {
    if !ascii_token_at(text, start, attribute) {
        return None;
    }
    let mut cursor = skip_ascii_whitespace(text, start + attribute.len());
    if text.as_bytes().get(cursor) != Some(&b'=') {
        return None;
    }
    cursor = skip_ascii_whitespace(text, cursor + 1);
    let opening = *text.as_bytes().get(cursor)?;
    if opening != b'\'' && opening != b'"' {
        return None;
    }
    cursor += 1;
    if !text[cursor..].starts_with(expected) {
        return None;
    }
    cursor += expected.len();
    let closing = *text.as_bytes().get(cursor)?;
    if closing != b'\'' && closing != b'"' {
        return None;
    }
    Some(cursor + 1)
}

fn parse_form_value_attribute<'a>(
    text: &'a str,
    start: usize,
    attribute: &str,
) -> Option<(&'a str, usize)> {
    if !ascii_token_at(text, start, attribute) {
        return None;
    }
    let mut cursor = skip_ascii_whitespace(text, start + attribute.len());
    if text.as_bytes().get(cursor) != Some(&b'=') {
        return None;
    }
    cursor = skip_ascii_whitespace(text, cursor + 1);
    let opening = *text.as_bytes().get(cursor)?;
    if opening != b'\'' && opening != b'"' {
        return None;
    }
    cursor += 1;
    let value_start = cursor;
    for (relative, character) in text[cursor..].char_indices() {
        if character == '\'' || character == '"' {
            let end = cursor + relative;
            return Some((&text[value_start..end], end + 1));
        }
    }
    None
}

fn find_last_form_value_attribute(text: &str, start: usize, limit: usize) -> Option<(usize, &str)> {
    let mut result = None;
    for (relative, character) in text[start..limit].char_indices() {
        if !character.is_ascii_whitespace() {
            continue;
        }
        let candidate = start + relative + character.len_utf8();
        if let Some((value, _)) = parse_form_value_attribute(text, candidate, "value") {
            result = Some((candidate, value));
        }
    }
    result
}

fn parse_last_form_literal_attribute(
    text: &str,
    start: usize,
    limit: usize,
    attribute: &str,
    expected: &str,
) -> Option<usize> {
    let mut result = None;
    for (relative, character) in text[start..limit].char_indices() {
        if !character.is_ascii_whitespace() {
            continue;
        }
        let candidate = start + relative + character.len_utf8();
        if let Some(end) = parse_form_literal_attribute(text, candidate, attribute, expected) {
            result = Some(end);
        }
    }
    result
}

fn capture_until(
    text: &str,
    start: usize,
    stop_questionmark: bool,
    stop_semicolon: bool,
    stop_backslash: bool,
) -> &str {
    let mut end = start;
    for (relative, character) in text[start..].char_indices() {
        let stop = character.is_ascii_whitespace()
            || matches!(character, '"' | '\'' | '<' | '>' | '&')
            || (stop_semicolon && character == ';')
            || (stop_questionmark && character == '?')
            || (stop_backslash && character == '\\');
        if stop {
            break;
        }
        end = start + relative + character.len_utf8();
    }
    &text[start..end]
}

fn rewrite_query_fields(
    config: &UrlRewritingModifierConfig,
    fields: &[QueryField],
    value: &BoundedText,
) -> Result<Vec<QueryField>, UrlRewritingModifierError> {
    if fields.len() > jmeter_rs_runtime::DEFAULT_MAX_REQUEST_QUERY_FIELDS {
        return Err(UrlRewritingModifierError::ResourceLimit);
    }
    let matching = fields
        .iter()
        .filter(|field| query_name_matches(&field.name, config.argument_name()))
        .count();
    let retained = fields
        .len()
        .checked_sub(matching)
        .ok_or(UrlRewritingModifierError::ResourceLimit)?;
    let final_len = retained
        .checked_add(1)
        .ok_or(UrlRewritingModifierError::ResourceLimit)?;
    if final_len > jmeter_rs_runtime::DEFAULT_MAX_REQUEST_QUERY_FIELDS {
        return Err(UrlRewritingModifierError::ResourceLimit);
    }
    let replacement = query_value_field(config, value)?;
    let mut rewritten = Vec::with_capacity(final_len);
    for field in fields {
        if !query_name_matches(&field.name, config.argument_name()) {
            rewritten.push(field.clone());
        }
    }
    let name = EncodedField::raw(config.argument_name().to_owned()).map_err(map_mutation_error)?;
    let field =
        QueryField::try_new(name, Presence::Present(replacement)).map_err(map_mutation_error)?;
    rewritten.push(field);
    Ok(rewritten)
}

fn query_value_field(
    config: &UrlRewritingModifierConfig,
    value: &BoundedText,
) -> Result<EncodedField, UrlRewritingModifierError> {
    if config.encode() {
        EncodedField::raw(value.as_str().to_owned()).map_err(map_mutation_error)
    } else {
        EncodedField::encoded(value.as_str().to_owned()).map_err(map_mutation_error)
    }
}

fn query_name_matches(field: &EncodedField, argument: &str) -> bool {
    encoded_field_has(field, argument)
}

fn encoded_field_has(field: &EncodedField, expected: &str) -> bool {
    matches!(&field.raw, Presence::Present(value) if value.as_str() == expected)
        || matches!(&field.encoded, Presence::Present(value) if value.as_str() == expected)
}

fn rewrite_path_segments(
    config: &UrlRewritingModifierConfig,
    fields: &[EncodedField],
    value: &BoundedText,
) -> Result<Vec<EncodedField>, UrlRewritingModifierError> {
    if fields.len() > jmeter_rs_runtime::DEFAULT_MAX_REQUEST_PATH_SEGMENTS {
        return Err(UrlRewritingModifierError::ResourceLimit);
    }
    let suffix = if config.path_extension_no_equals() {
        bounded_join(&[";", config.argument_name(), value.as_str()])?
    } else {
        bounded_join(&[";", config.argument_name(), "=", value.as_str()])?
    };
    let marker = bounded_join(&[";", config.argument_name()])?;
    if let Some(marker_index) = fields
        .iter()
        .position(|field| encoded_field_has_marker(field, &marker))
    {
        // JMeter receives one full sampler path. A marker therefore truncates
        // the path at its first occurrence, preserves the first query tail,
        // and appends one suffix. In the typed representation this is one
        // replacement field; path fields after the marker are intentionally
        // discarded instead of being independently rewritten.
        let capacity = marker_index
            .checked_add(1)
            .ok_or(UrlRewritingModifierError::ResourceLimit)?;
        let mut rewritten = Vec::with_capacity(capacity);
        rewritten.extend_from_slice(&fields[..marker_index]);
        rewritten.push(rewrite_path_field_exact(
            &fields[marker_index],
            fields,
            &marker,
            &suffix,
        )?);
        Ok(rewritten)
    } else if let Some(index) = fields.len().checked_sub(1) {
        let mut rewritten = fields.to_vec();
        rewritten[index] = rewrite_path_field_append(&fields[index], &suffix)?;
        Ok(rewritten)
    } else {
        Ok(vec![EncodedField::raw(suffix).map_err(map_mutation_error)?])
    }
}

fn encoded_field_has_marker(field: &EncodedField, marker: &str) -> bool {
    matches!(&field.raw, Presence::Present(value) if value.as_str().contains(marker))
        || matches!(&field.encoded, Presence::Present(value) if value.as_str().contains(marker))
}

fn rewrite_path_field_exact(
    field: &EncodedField,
    fields: &[EncodedField],
    marker: &str,
    suffix: &str,
) -> Result<EncodedField, UrlRewritingModifierError> {
    let raw = rewrite_path_presence_exact(&field.raw, fields, marker, suffix, true)?;
    let encoded = rewrite_path_presence_exact(&field.encoded, fields, marker, suffix, false)?;
    EncodedField::try_new(raw, encoded).map_err(map_mutation_error)
}

fn rewrite_path_field_append(
    field: &EncodedField,
    suffix: &str,
) -> Result<EncodedField, UrlRewritingModifierError> {
    let raw = rewrite_path_presence_append(&field.raw, suffix)?;
    let encoded = rewrite_path_presence_append(&field.encoded, suffix)?;
    EncodedField::try_new(raw, encoded).map_err(map_mutation_error)
}

fn rewrite_path_presence_append(
    presence: &Presence<BoundedText>,
    suffix: &str,
) -> Result<Presence<BoundedText>, UrlRewritingModifierError> {
    match presence {
        Presence::Missing => Ok(Presence::Missing),
        Presence::Present(value) => {
            let text = bounded_join(&[value.as_str(), suffix])?;
            BoundedText::try_new(text, jmeter_rs_runtime::DEFAULT_MAX_VALUE_BYTES)
                .map(Presence::Present)
                .map_err(map_mutation_error)
        }
    }
}

fn rewrite_path_presence_exact(
    presence: &Presence<BoundedText>,
    fields: &[EncodedField],
    marker: &str,
    suffix: &str,
    raw: bool,
) -> Result<Presence<BoundedText>, UrlRewritingModifierError> {
    match presence {
        Presence::Missing => Ok(Presence::Missing),
        Presence::Present(value) => {
            let Some(marker_offset) = value.as_str().find(marker) else {
                return rewrite_path_presence_append(presence, suffix);
            };
            let question = first_path_question(fields, raw);
            let mut parts = Vec::with_capacity(
                fields
                    .len()
                    .checked_add(2)
                    .ok_or(UrlRewritingModifierError::ResourceLimit)?,
            );
            parts.push(&value.as_str()[..marker_offset]);
            if let Some((question_index, question_offset)) = question
                && let Presence::Present(question_value) =
                    path_presence(&fields[question_index], raw)
            {
                parts.push(&question_value.as_str()[question_offset..]);
                for field in fields.iter().skip(question_index + 1) {
                    if let Presence::Present(path_value) = path_presence(field, raw) {
                        parts.push(path_value.as_str());
                    }
                }
            }
            parts.push(suffix);
            let text = bounded_join(&parts)?;
            BoundedText::try_new(text, jmeter_rs_runtime::DEFAULT_MAX_VALUE_BYTES)
                .map(Presence::Present)
                .map_err(map_mutation_error)
        }
    }
}

fn path_presence(field: &EncodedField, raw: bool) -> &Presence<BoundedText> {
    if raw { &field.raw } else { &field.encoded }
}

fn first_path_question(fields: &[EncodedField], raw: bool) -> Option<(usize, usize)> {
    fields.iter().enumerate().find_map(|(index, field)| {
        let Presence::Present(value) = path_presence(field, raw) else {
            return None;
        };
        value.as_str().find('?').map(|offset| (index, offset))
    })
}

fn bounded_join(parts: &[&str]) -> Result<String, UrlRewritingModifierError> {
    let length = parts.iter().try_fold(0usize, |total, part| {
        total
            .checked_add(part.len())
            .ok_or(UrlRewritingModifierError::ResourceLimit)
    })?;
    if length > jmeter_rs_runtime::DEFAULT_MAX_VALUE_BYTES {
        return Err(UrlRewritingModifierError::ResourceLimit);
    }
    let mut joined = String::with_capacity(length);
    for part in parts {
        joined.push_str(part);
    }
    Ok(joined)
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests use fixed bounded in-memory model and runtime values"
)]
mod tests {
    use super::*;
    use jmeter_rs_model::{ElementMetadata, NodeId};
    use jmeter_rs_results::{SampleData, SampleResult};
    use jmeter_rs_runtime::{
        ComponentAvailability, ComponentBinding, ExecutionContext, ExecutionPipeline,
        RequestGeneration, RequestStateParts, SamplePackage, Sampler, SamplerOutput,
    };
    use std::future::Future;
    use std::pin::pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};

    fn config() -> UrlRewritingModifierConfig {
        UrlRewritingModifierConfig::new("token").expect("argument")
    }

    fn response(body: Option<&[u8]>) -> ResponseResolution {
        let mut result = SampleResult::new("response");
        result.set_response_data(body.map(|value| SampleData::new(value.to_vec())));
        resolve_response(result)
    }

    fn response_with_encoding(body: Option<&[u8]>, encoding: Option<&str>) -> ResponseResolution {
        let mut result = SampleResult::new("response");
        result.set_response_data(body.map(|value| SampleData::new(value.to_vec())));
        if let Some(encoding) = encoding {
            result.set_data_encoding_name(encoding);
        }
        resolve_response(result)
    }

    fn resolve_response(result: SampleResult) -> ResponseResolution {
        ResponseInputSetResolver::default()
            .resolve(
                Some(&result),
                &BTreeMap::new(),
                &ResponseScope::Current,
                ResponseTarget::Body,
                &ResponseDecodePolicy::declared_or_utf8(),
            )
            .expect("response projection")
    }

    fn request() -> RequestState {
        RequestState::try_from_parts(
            RequestGeneration::FIRST,
            RequestStateParts {
                scheme: Presence::Missing,
                authority: Presence::Missing,
                path_segments: vec![EncodedField::raw("/index").expect("path")],
                query_fields: Vec::new(),
                method: Presence::Missing,
                body: Presence::Missing,
                headers: Vec::new(),
            },
        )
        .expect("request")
    }

    struct NoopSampler;

    impl Sampler for NoopSampler {
        fn sample<'a>(
            &'a self,
            _context: &'a mut SampleContext<'_>,
        ) -> ComponentFuture<'a, SamplerOutput> {
            Box::pin(std::future::ready(Ok(SamplerOutput::no_result())))
        }
    }

    struct ExplicitResponsePreprocessor {
        modifier: Arc<UrlRewritingModifier>,
        response: Arc<Mutex<ResponseResolution>>,
        fail_commit: Arc<Mutex<bool>>,
    }

    impl Preprocessor for ExplicitResponsePreprocessor {
        fn process<'a>(&'a self, context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, ()> {
            let response = self
                .response
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            let fail_commit = *self
                .fail_commit
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let modifier = Arc::clone(&self.modifier);
            Box::pin(async move {
                if fail_commit {
                    context
                        .execution_mut()
                        .request_control(jmeter_rs_runtime::ControlSignal::StopThread);
                }
                modifier
                    .process_response_now(context, &response)
                    .map_err(component_error)
            })
        }
    }

    fn execute_noop_preprocessor(modifier: UrlRewritingModifier) -> ExecutionContext {
        let package = SamplePackage::new(NodeId::new(2), Arc::new(NoopSampler))
            .with_preprocessors(vec![Arc::new(modifier)]);
        let mut execution = ExecutionContext::new();
        {
            let future = ExecutionPipeline::execute(&package, &mut execution);
            let mut future = pin!(future);
            let waker = Waker::noop();
            let mut task_context = Context::from_waker(waker);
            match Future::poll(future.as_mut(), &mut task_context) {
                Poll::Ready(Ok(_)) => (),
                Poll::Ready(Err(error)) => panic!("no-op preprocessor failed: {error}"),
                Poll::Pending => panic!("no-op preprocessor unexpectedly blocked"),
            }
        }
        execution
    }

    #[test]
    fn alias_allowlist_is_exact() {
        assert!(is_url_rewriting_alias(URL_REWRITING_MODIFIER_ALIAS));
        assert!(is_url_rewriting_alias(URL_REWRITING_MODIFIER_CLASS));
        assert!(!is_url_rewriting_alias("urlrewritingmodifier"));
        assert!(!is_url_rewriting_alias("URLRewritingModifier "));
        assert!(!is_url_rewriting_alias(
            "org.apache.jmeter.protocol.http.modifier.URLRewritingModifierX"
        ));
    }

    #[test]
    fn generic_non_http_sampler_seam_is_silent_noop() {
        let execution = execute_noop_preprocessor(UrlRewritingModifier::new(config()));
        assert_eq!(execution.request_state(), &RequestState::default());
    }

    #[test]
    fn generic_missing_previous_result_seam_is_silent_noop() {
        let execution = execute_noop_preprocessor(UrlRewritingModifier::for_http_sampler(config()));
        assert_eq!(execution.request_state(), &RequestState::default());
    }

    #[test]
    fn cache_updates_after_commit_and_survives_failed_commit() {
        let modifier = Arc::new(UrlRewritingModifier::for_http_sampler(config()));
        let response_view = Arc::new(Mutex::new(response(Some(b"?token=first"))));
        let fail_commit = Arc::new(Mutex::new(false));
        let preprocessor = Arc::new(ExplicitResponsePreprocessor {
            modifier,
            response: Arc::clone(&response_view),
            fail_commit: Arc::clone(&fail_commit),
        });
        let package = SamplePackage::new(NodeId::new(3), Arc::new(NoopSampler))
            .with_preprocessors(vec![preprocessor]);

        let mut first = ExecutionContext::new();
        first.set_request_state(request()).expect("initial request");
        {
            let first_future = ExecutionPipeline::execute(&package, &mut first);
            let mut first_future = pin!(first_future);
            let waker = Waker::noop();
            let mut task_context = Context::from_waker(waker);
            assert!(matches!(
                Future::poll(first_future.as_mut(), &mut task_context),
                Poll::Ready(Ok(_))
            ));
        }
        assert_eq!(query_value(&first), Some("first"));

        *response_view
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = response(None);
        let mut cached = ExecutionContext::new();
        cached.set_request_state(request()).expect("cached request");
        {
            let cached_future = ExecutionPipeline::execute(&package, &mut cached);
            let mut cached_future = pin!(cached_future);
            let waker = Waker::noop();
            let mut task_context = Context::from_waker(waker);
            assert!(matches!(
                Future::poll(cached_future.as_mut(), &mut task_context),
                Poll::Ready(Ok(_))
            ));
        }
        assert_eq!(query_value(&cached), Some("first"));

        *response_view
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = response(Some(b"?token=second"));
        *fail_commit
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = true;
        let mut failed = ExecutionContext::new();
        failed.set_request_state(request()).expect("failed request");
        let failed_request_digest = failed.request_state().digest();
        {
            let failed_future = ExecutionPipeline::execute(&package, &mut failed);
            let mut failed_future = pin!(failed_future);
            let waker = Waker::noop();
            let mut task_context = Context::from_waker(waker);
            assert!(matches!(
                Future::poll(failed_future.as_mut(), &mut task_context),
                Poll::Ready(Err(_))
            ));
        }
        assert_eq!(failed.request_state().digest(), failed_request_digest);
        assert_eq!(
            failed.control_signal(),
            jmeter_rs_runtime::ControlSignal::StopThread
        );

        *response_view
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = response(None);
        *fail_commit
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = false;
        let mut after_failure = ExecutionContext::new();
        after_failure
            .set_request_state(request())
            .expect("after-failure request");
        {
            let after_failure_future = ExecutionPipeline::execute(&package, &mut after_failure);
            let mut after_failure_future = pin!(after_failure_future);
            let waker = Waker::noop();
            let mut task_context = Context::from_waker(waker);
            assert!(matches!(
                Future::poll(after_failure_future.as_mut(), &mut task_context),
                Poll::Ready(Ok(_))
            ));
        }
        assert_eq!(query_value(&after_failure), Some("first"));
    }

    #[test]
    fn poisoned_cache_lock_fails_closed_without_request_mutation() {
        let modifier = Arc::new(UrlRewritingModifier::for_http_sampler(config()));
        let poisoned = Arc::clone(&modifier);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _guard = poisoned.saved_value.lock().expect("unpoisoned cache");
            panic!("intentional cache poison");
        }));

        let response_view = Arc::new(Mutex::new(response(Some(b"?token=poisoned"))));
        let preprocessor = Arc::new(ExplicitResponsePreprocessor {
            modifier,
            response: response_view,
            fail_commit: Arc::new(Mutex::new(false)),
        });
        let package = SamplePackage::new(NodeId::new(4), Arc::new(NoopSampler))
            .with_preprocessors(vec![preprocessor]);
        let mut execution = ExecutionContext::new();
        execution.set_request_state(request()).expect("request");
        let before = execution.request_state().digest();
        let future = ExecutionPipeline::execute(&package, &mut execution);
        let mut future = pin!(future);
        let waker = Waker::noop();
        let mut task_context = Context::from_waker(waker);
        assert!(matches!(
            Future::poll(future.as_mut(), &mut task_context),
            Poll::Ready(Err(_))
        ));
        assert_eq!(execution.request_state().digest(), before);
    }

    #[test]
    fn response_error_stages_no_partial_request_mutation() {
        let modifier = Arc::new(UrlRewritingModifier::for_http_sampler(config()));
        let response_view = Arc::new(Mutex::new(response_with_encoding(
            Some(b"?token=value"),
            Some("x-unknown"),
        )));
        let preprocessor = Arc::new(ExplicitResponsePreprocessor {
            modifier,
            response: response_view,
            fail_commit: Arc::new(Mutex::new(false)),
        });
        let package = SamplePackage::new(NodeId::new(5), Arc::new(NoopSampler))
            .with_preprocessors(vec![preprocessor]);
        let mut execution = ExecutionContext::new();
        execution.set_request_state(request()).expect("request");
        let before = execution.request_state().digest();
        let future = ExecutionPipeline::execute(&package, &mut execution);
        let mut future = pin!(future);
        let waker = Waker::noop();
        let mut task_context = Context::from_waker(waker);
        assert!(matches!(
            Future::poll(future.as_mut(), &mut task_context),
            Poll::Ready(Err(_))
        ));
        assert_eq!(execution.request_state().digest(), before);
    }

    fn query_value(context: &ExecutionContext) -> Option<&str> {
        context
            .request_state()
            .query_fields()
            .last()
            .and_then(|field| match &field.value {
                Presence::Present(value) => match &value.encoded {
                    Presence::Present(value) => Some(value.as_str()),
                    Presence::Missing => None,
                },
                Presence::Missing => None,
            })
    }

    #[test]
    fn missing_and_present_empty_response_are_empty_tokens() {
        let missing = response(None);
        assert_eq!(
            extract_response_value(&config(), &missing)
                .expect("missing response data")
                .as_str(),
            ""
        );
        let empty = response(Some(b""));
        assert_eq!(
            extract_response_value(&config(), &empty)
                .expect("empty")
                .as_str(),
            ""
        );
    }

    #[test]
    fn rev3_selection_rejects_no_current_children_variables_and_file_targets() {
        assert_eq!(
            extract_response_value(&config(), &ResponseResolution::NoCurrentResult),
            Err(UrlRewritingModifierError::MissingPreviousResult)
        );

        let resolver = ResponseInputSetResolver::default();
        let mut root = SampleResult::new("root");
        root.set_response_data(Some(SampleData::from(b"?token=root".as_slice())));
        root.try_add_sub_result(
            SampleResult::new("child"),
            jmeter_rs_results::ValidationLimits::default(),
        )
        .expect("child");
        let all = resolver
            .resolve(
                Some(&root),
                &BTreeMap::new(),
                &ResponseScope::All,
                ResponseTarget::Body,
                &ResponseDecodePolicy::declared_or_utf8(),
            )
            .expect("all");
        assert_eq!(
            extract_response_value(&config(), &all),
            Err(UrlRewritingModifierError::ResponseUnavailable)
        );

        let variable = resolver
            .resolve(
                None,
                &BTreeMap::from([(String::from("token"), String::from("from-variable"))]),
                &ResponseScope::variable("token"),
                ResponseTarget::Body,
                &ResponseDecodePolicy::declared_or_utf8(),
            )
            .expect("variable");
        assert_eq!(
            extract_response_value(&config(), &variable),
            Err(UrlRewritingModifierError::ResponseUnavailable)
        );

        let mut file_only = SampleResult::new("file-only");
        file_only.set_response_file_text("opaque-result-file");
        let file_only = resolver
            .resolve(
                Some(&file_only),
                &BTreeMap::new(),
                &ResponseScope::Current,
                ResponseTarget::Body,
                &ResponseDecodePolicy::declared_or_utf8(),
            )
            .expect("file metadata is retained");
        assert_eq!(
            extract_response_value(&config(), &file_only)
                .expect("file metadata is not a body fallback")
                .as_str(),
            ""
        );
    }

    #[test]
    fn declared_encoding_uses_replacement_and_unknown_encoding_fails_closed() {
        let malformed = response_with_encoding(Some(b"\xff?token=value"), Some("UTF-8"));
        assert_eq!(
            extract_response_value(&config(), &malformed)
                .expect("replacement decoding")
                .as_str(),
            "value"
        );

        let default_encoding = response_with_encoding(Some(b"\xff?token=value"), Some(""));
        assert_eq!(
            extract_response_value(&config(), &default_encoding)
                .expect("explicit UTF-8 default")
                .as_str(),
            "value"
        );

        let empty_unknown = response_with_encoding(Some(b""), Some("x-unknown"));
        assert_eq!(
            extract_response_value(&config(), &empty_unknown)
                .expect("empty body does not require a decoder")
                .as_str(),
            ""
        );

        let unknown = response_with_encoding(Some(b"?token=value"), Some("x-unknown"));
        assert_eq!(
            extract_response_value(&config(), &unknown),
            Err(UrlRewritingModifierError::ResponseUnavailable)
        );
    }

    #[test]
    fn query_patch_removes_all_matching_names_and_appends_one() {
        let original = request();
        let before = QueryField::try_new(
            EncodedField::raw("before").expect("name"),
            Presence::Present(EncodedField::raw("one").expect("value")),
        )
        .expect("field");
        let first = QueryField::try_new(
            EncodedField::raw("token").expect("name"),
            Presence::Present(EncodedField::encoded("old").expect("value")),
        )
        .expect("field");
        let second =
            QueryField::try_new(EncodedField::raw("token").expect("name"), Presence::Missing)
                .expect("field");
        let encoded_name = QueryField::try_new(
            EncodedField::encoded("token").expect("encoded name"),
            Presence::Present(EncodedField::raw("encoded-duplicate").expect("value")),
        )
        .expect("field");
        let after = QueryField::try_new(
            EncodedField::raw("after").expect("name"),
            Presence::Present(EncodedField::raw("two").expect("value")),
        )
        .expect("field");
        let request = RequestState::try_from_parts(
            original.generation(),
            RequestStateParts {
                scheme: Presence::Missing,
                authority: Presence::Missing,
                path_segments: original.path_segments().to_vec(),
                query_fields: vec![before.clone(), first, second, encoded_name, after.clone()],
                method: Presence::Missing,
                body: Presence::Missing,
                headers: Vec::new(),
            },
        )
        .expect("request");
        let patch = build_request_patch(&config(), &request, "new%20value").expect("patch");
        let candidate = request.apply_patch(&patch).expect("candidate");
        assert_eq!(candidate.query_fields().len(), 3);
        assert_eq!(candidate.query_fields()[0], before);
        assert_eq!(candidate.query_fields()[1], after);
        let appended = QueryField::try_new(
            EncodedField::raw("token").expect("name"),
            Presence::Present(EncodedField::encoded("new%20value").expect("value")),
        )
        .expect("appended");
        assert_eq!(candidate.query_fields().last(), Some(&appended));
        assert!(matches!(
            candidate.query_fields()[2].value,
            Presence::Present(EncodedField {
                encoded: Presence::Present(_),
                ..
            })
        ));
    }

    #[test]
    fn all_path_flag_combinations_are_deterministic() {
        for no_questionmark in [false, true] {
            for no_equals in [false, true] {
                let candidate = config()
                    .with_path_extension(true)
                    .with_path_extension_no_questionmark(no_questionmark)
                    .with_path_extension_no_equals(no_equals);
                let value = extract_response_value(
                    &candidate,
                    &response(Some(b"href='/index;token=value?next'")),
                )
                .expect("path token");
                let expected = match (no_questionmark, no_equals) {
                    (false, false) => "value?next",
                    (true, false) => "value",
                    (false, true) => "=value?next",
                    (true, true) => "=value",
                };
                assert_eq!(value.as_str(), expected);
            }
        }
        for no_questionmark in [false, true] {
            for no_equals in [false, true] {
                let candidate = config()
                    .with_path_extension_no_questionmark(no_questionmark)
                    .with_path_extension_no_equals(no_equals);
                assert_eq!(
                    extract_response_value(&candidate, &response(Some(b"?token=value")))
                        .expect("query token")
                        .as_str(),
                    "value"
                );
            }
        }
    }

    #[test]
    fn path_patch_truncates_at_first_marker_preserves_query_tail_and_drops_later_path() {
        let candidate = config().with_path_extension(true);
        let request = RequestState::try_from_parts(
            RequestGeneration::FIRST,
            RequestStateParts {
                scheme: Presence::Missing,
                authority: Presence::Missing,
                path_segments: vec![
                    EncodedField::raw("/index;token=old?keep=1/tail;token=later").expect("path"),
                    EncodedField::raw("/never-rewritten").expect("path"),
                ],
                query_fields: vec![
                    QueryField::try_new(
                        EncodedField::raw("dup").expect("name"),
                        Presence::Present(EncodedField::raw("one").expect("value")),
                    )
                    .expect("query"),
                    QueryField::try_new(
                        EncodedField::raw("dup").expect("name"),
                        Presence::Present(EncodedField::raw("two").expect("value")),
                    )
                    .expect("query"),
                ],
                method: Presence::Missing,
                body: Presence::Missing,
                headers: Vec::new(),
            },
        )
        .expect("request");
        let patch = build_request_patch(&candidate, &request, "new").expect("patch");
        let rewritten = request.apply_patch(&patch).expect("rewritten");
        assert_eq!(
            match &rewritten.path_segments()[0].raw {
                Presence::Present(value) => value.as_str(),
                Presence::Missing => "",
            },
            "/index?keep=1/tail;token=later/never-rewritten;token=new"
        );
        assert_eq!(rewritten.path_segments().len(), 1);
        assert_eq!(rewritten.query_fields(), request.query_fields());

        let no_query_request = RequestState::try_from_parts(
            RequestGeneration::FIRST,
            RequestStateParts {
                scheme: Presence::Missing,
                authority: Presence::Missing,
                path_segments: vec![
                    EncodedField::raw("/first;token=old").expect("path"),
                    EncodedField::raw("/later;token=untouched").expect("path"),
                ],
                query_fields: Vec::new(),
                method: Presence::Missing,
                body: Presence::Missing,
                headers: Vec::new(),
            },
        )
        .expect("no-query request");
        let no_query_patch =
            build_request_patch(&candidate, &no_query_request, "new").expect("no-query patch");
        let no_query_rewritten = no_query_request
            .apply_patch(&no_query_patch)
            .expect("no-query rewritten");
        assert_eq!(no_query_rewritten.path_segments().len(), 1);
        assert_eq!(
            match &no_query_rewritten.path_segments()[0].raw {
                Presence::Present(value) => value.as_str(),
                Presence::Missing => "",
            },
            "/first;token=new"
        );
    }

    #[test]
    fn encode_flag_selects_raw_or_encoded_value_presence() {
        let encoded = build_request_patch(&config(), &request(), "a+b").expect("encoded patch");
        let encoded_state = request().apply_patch(&encoded).expect("encoded state");
        assert!(matches!(
            encoded_state.query_fields()[0].value,
            Presence::Present(EncodedField {
                raw: Presence::Missing,
                encoded: Presence::Present(_),
            })
        ));

        let raw_config = config().with_encode(true);
        let raw = build_request_patch(&raw_config, &request(), "a+b").expect("raw patch");
        let raw_state = request().apply_patch(&raw).expect("raw state");
        assert!(matches!(
            raw_state.query_fields()[0].value,
            Presence::Present(EncodedField {
                raw: Presence::Present(_),
                encoded: Presence::Missing,
            })
        ));
    }

    #[test]
    fn form_matching_accepts_case_and_attribute_order() {
        let body = b"<input VALUE='one' NAME = \"token\"><input name='other' value='two'>";
        assert_eq!(
            extract_response_value(&config(), &response(Some(body)))
                .expect("form token")
                .as_str(),
            "one"
        );
    }

    #[test]
    fn form_matching_scans_arbitrary_response_text_and_literal_names() {
        let body = b"prefix name = \"a+b.*\" text VALUE='one' suffix";
        let special = UrlRewritingModifierConfig::new("a+b.*").expect("argument");
        assert_eq!(
            extract_response_value(&special, &response(Some(body)))
                .expect("arbitrary-text form token")
                .as_str(),
            "one"
        );

        let unicode = UrlRewritingModifierConfig::new("\u{03c0}").expect("unicode argument");
        assert_eq!(
            extract_response_value(&unicode, &response(Some(b"?\xcf\x80=value")))
                .expect("unicode query token")
                .as_str(),
            "value"
        );
    }

    #[test]
    fn extractor_exclusions_empty_capture_and_union_order_match_pinned_regex() {
        assert_eq!(
            extract_response_value(
                &config(),
                &response(Some(b"?token=first\\second;token=next"))
            )
            .expect("query exclusion")
            .as_str(),
            "first"
        );
        let path = config().with_path_extension(true);
        assert_eq!(
            extract_response_value(&path, &response(Some(b"/x;token=first;token=next")))
                .expect("path semicolon exclusion")
                .as_str(),
            "first"
        );
        let path_without_question = path.with_path_extension_no_questionmark(true);
        assert_eq!(
            extract_response_value(
                &path_without_question,
                &response(Some(b"/x;token=first?query")),
            )
            .expect("path question exclusion")
            .as_str(),
            "first"
        );
        assert_eq!(
            extract_response_value(&config(), &response(Some(b"?token=")))
                .expect("empty query capture")
                .as_str(),
            ""
        );
        assert_eq!(
            extract_response_value(
                &config(),
                &response(Some(b" name='token' value='' later ?token=query")),
            )
            .expect("earliest empty form capture")
            .as_str(),
            ""
        );
        assert_eq!(
            extract_response_value(
                &config(),
                &response(Some(b" ?token=query later name='token' value='form'")),
            )
            .expect("earliest query alternative")
            .as_str(),
            "query"
        );
        assert_eq!(
            extract_response_value(&config(), &response(Some(b" name='Token' value='wrong'")))
                .expect("case-sensitive argument name")
                .as_str(),
            ""
        );
    }

    #[test]
    fn malformed_utf8_boundaries_do_not_panic_the_bounded_matcher() {
        let body = "prefix-🦀-<input value='one' name='token'>".as_bytes();
        assert_eq!(
            extract_response_value(&config(), &response(Some(body)))
                .expect("unicode prefix")
                .as_str(),
            "one"
        );
    }

    #[test]
    fn cache_true_uses_previous_nonempty_value_and_false_does_not() {
        let cached = Some("first");
        let proposal = propose_url_rewriting_patch(
            &config(),
            &request(),
            &response(Some(b"no token here")),
            cached,
        )
        .expect("proposal");
        assert_eq!(proposal.effective_value(), "first");

        let cache_false = config().with_cache_value(false);
        let proposal = propose_url_rewriting_patch(
            &cache_false,
            &request(),
            &response(Some(b"no token here")),
            cached,
        )
        .expect("proposal");
        assert_eq!(proposal.effective_value(), "");
    }

    #[test]
    fn malformed_percent_is_carried_through_without_patch_rejection() {
        let extracted = extract_response_value(&config(), &response(Some(b"?token=%ZZ")))
            .expect("malformed percent is carried");
        assert_eq!(extracted.as_str(), "%ZZ");
        let patch = build_request_patch(&config(), &request(), extracted.as_str())
            .expect("malformed percent patch");
        let candidate = request().apply_patch(&patch).expect("candidate");
        assert!(matches!(
            &candidate.query_fields()[0].value,
            Presence::Present(EncodedField {
                encoded: Presence::Present(value),
                ..
            }) if value.as_str() == "%ZZ"
        ));
    }

    #[test]
    fn stale_patch_is_rejected_atomically() {
        let request = request();
        let patch = build_request_patch(&config(), &request, "first").expect("patch");
        let candidate = request.apply_patch(&patch).expect("candidate");
        let error = candidate.apply_patch(&patch).expect_err("stale patch");
        assert_eq!(error.code(), MutationErrorCode::StaleGeneration);
        assert_ne!(candidate, request);
    }

    #[test]
    fn decoder_requires_exact_typed_properties_and_redacts_values() {
        let mut element = TestElement::named(
            URL_REWRITING_MODIFIER_ALIAS,
            "URLRewritingModifierGui",
            "modifier",
        );
        element.set_property(PROPERTY_ARGUMENT_NAME, PropertyValue::string("token"));
        element.set_property(PROPERTY_CACHE_VALUE, PropertyValue::boolean(true));
        let decoded = decode_url_rewriting_modifier(&element).expect("decode");
        assert_eq!(decoded.argument_name(), "token");
        assert!(!format!("{decoded:?}").contains("token"));
        element.set_property("untrusted", PropertyValue::string("secret"));
        assert_eq!(
            decode_url_rewriting_modifier(&element),
            Err(UrlRewritingModifierDecodeError::UnsupportedProperty)
        );
    }

    #[test]
    fn factory_rejects_unproven_placement_before_execution() {
        let factory = UrlRewritingModifierFactory::new(config());
        let mut element = TestElement::named(
            URL_REWRITING_MODIFIER_ALIAS,
            "URLRewritingModifierGui",
            "modifier",
        );
        element.set_property(PROPERTY_ARGUMENT_NAME, PropertyValue::string("token"));
        let component = ScopeComponent {
            node_id: NodeId::new(1),
            path: vec![NodeId::new(1)],
            element,
            binding: ComponentBinding {
                test_class: URL_REWRITING_MODIFIER_ALIAS.to_owned(),
                category: ComponentCategory::Preprocessor,
                capability_id: "runtime.URLRewritingModifier".to_owned(),
                external: false,
                availability: ComponentAvailability::Unavailable,
            },
        };
        let error = ScopeComponentFactory::create(&factory, &component).expect_err("placement");
        assert_eq!(error.code(), "runtime.scope.factory-decode");
    }

    #[test]
    fn bounds_and_redaction_are_explicit() {
        let oversized = "x".repeat(MAX_URL_REWRITING_RESPONSE_BYTES + 1);
        assert_eq!(
            extract_response_value(&config(), &response(Some(oversized.as_bytes()))),
            Err(UrlRewritingModifierError::ResourceLimit)
        );
        let error = UrlRewritingModifierError::Mutation(MutationErrorCode::StaleDigest);
        assert!(!format!("{error:?}").contains("secret"));
        assert!(!format!("{error}").contains("secret"));
        let _ = ElementMetadata::default();
    }
}
