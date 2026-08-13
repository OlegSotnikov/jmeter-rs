// SPDX-License-Identifier: Apache-2.0
//! Bounded native assertion adapters.
//!
//! The adapters in this module are deliberately JMX-neutral.  Scope
//! compilation is responsible for translating the wire properties emitted by
//! JMeter into these small domain values.  Evaluation only observes the
//! current [`SampleContext`] and never performs I/O.
//!
//! JMeter's response assertion uses the Apache ORO regular-expression engine.
//! Runtime does not currently carry that dependency, so this module contains
//! a small, explicitly bounded regular-expression subset.  A construct which
//! is not in that subset returns an explicit unsupported capability instead of
//! being silently interpreted as a different expression.  XML uses the same
//! policy: the syntax parser and a small XPath path subset are native, while
//! DTD fetching, Tidy, schema validation, namespace resolution, and JSON
//! engines remain explicit capability boundaries.

use jmeter_rs_results::{AssertionResult, SampleResult};

use crate::{Assertion, ComponentError, ComponentFuture, SampleContext};

/// Maximum number of patterns accepted by a response assertion by default.
pub const DEFAULT_MAX_ASSERTION_PATTERNS: usize = 64;
/// Maximum UTF-8 bytes in one pattern by default.
pub const DEFAULT_MAX_ASSERTION_PATTERN_BYTES: usize = 16 * 1024;
/// Maximum response/header bytes inspected by one assertion by default.
pub const DEFAULT_MAX_ASSERTION_RESPONSE_BYTES: usize = 1024 * 1024;
/// Maximum XML nesting depth by default.
pub const DEFAULT_MAX_ASSERTION_XML_DEPTH: usize = 128;
/// Maximum XML node count by default.
pub const DEFAULT_MAX_ASSERTION_XML_NODES: usize = 16 * 1024;
/// Maximum diagnostic bytes emitted by one assertion by default.
pub const DEFAULT_MAX_ASSERTION_DIAGNOSTIC_BYTES: usize = 4 * 1024;
/// Maximum regex evaluation steps by default.
pub const DEFAULT_MAX_ASSERTION_REGEX_STEPS: usize = 1_000_000;
/// Maximum regex parser nesting depth by default.
pub const DEFAULT_MAX_ASSERTION_REGEX_DEPTH: usize = 128;
/// Maximum XPath expression bytes by default.
pub const DEFAULT_MAX_ASSERTION_XPATH_BYTES: usize = 4 * 1024;

const JMETER_ASSERTION_ERROR_NAME: &str = "Assertion failed! See log file.";
const EQUALS_SECTION_DIFF_LEN: usize = 100;
const EQUALS_DIFF_TRUNCATION: &str = "...";
const EQUALS_DELTA_START: &str = "[[[";
const EQUALS_DELTA_END: &str = "]]]";
const EQUALS_RECEIVED_PREFIX: &str = "****** received  : ";
const EQUALS_COMPARISON_PREFIX: &str = "****** comparison: ";

/// Resource limits shared by native assertion adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssertionLimits {
    /// Maximum number of response patterns.
    pub max_patterns: usize,
    /// Maximum UTF-8 bytes in one response pattern.
    pub max_pattern_bytes: usize,
    /// Maximum response/header bytes inspected.
    pub max_response_bytes: usize,
    /// Maximum XML nesting depth, including the document element.
    pub max_xml_depth: usize,
    /// Maximum XML node count, including the document element.
    pub max_xml_nodes: usize,
    /// Maximum diagnostic message bytes.
    pub max_diagnostic_bytes: usize,
    /// Maximum regex parser/evaluator steps.
    pub max_regex_steps: usize,
    /// Maximum nested regex expression depth.
    pub max_regex_depth: usize,
    /// Maximum XPath expression bytes.
    pub max_xpath_bytes: usize,
}

impl Default for AssertionLimits {
    fn default() -> Self {
        Self {
            max_patterns: DEFAULT_MAX_ASSERTION_PATTERNS,
            max_pattern_bytes: DEFAULT_MAX_ASSERTION_PATTERN_BYTES,
            max_response_bytes: DEFAULT_MAX_ASSERTION_RESPONSE_BYTES,
            max_xml_depth: DEFAULT_MAX_ASSERTION_XML_DEPTH,
            max_xml_nodes: DEFAULT_MAX_ASSERTION_XML_NODES,
            max_diagnostic_bytes: DEFAULT_MAX_ASSERTION_DIAGNOSTIC_BYTES,
            max_regex_steps: DEFAULT_MAX_ASSERTION_REGEX_STEPS,
            max_regex_depth: DEFAULT_MAX_ASSERTION_REGEX_DEPTH,
            max_xpath_bytes: DEFAULT_MAX_ASSERTION_XPATH_BYTES,
        }
    }
}

impl AssertionLimits {
    /// Returns a limit set with all values replaced by `value` where that is
    /// meaningful for a caller constructing a deliberately tiny test bound.
    /// A zero value is retained and causes a typed resource error at use time;
    /// this method never panics or silently repairs a bound.
    #[must_use]
    pub const fn with_response_limit(mut self, value: usize) -> Self {
        self.max_response_bytes = value;
        self
    }

    /// Returns a limit set with a pattern-count bound.
    #[must_use]
    pub const fn with_pattern_limit(mut self, value: usize) -> Self {
        self.max_patterns = value;
        self
    }

    /// Returns a limit set with a pattern-byte bound.
    #[must_use]
    pub const fn with_pattern_bytes_limit(mut self, value: usize) -> Self {
        self.max_pattern_bytes = value;
        self
    }

    /// Returns a limit set with an XML depth bound.
    #[must_use]
    pub const fn with_xml_depth_limit(mut self, value: usize) -> Self {
        self.max_xml_depth = value;
        self
    }

    /// Returns a limit set with an XML node bound.
    #[must_use]
    pub const fn with_xml_node_limit(mut self, value: usize) -> Self {
        self.max_xml_nodes = value;
        self
    }

    /// Returns a limit set with a diagnostic-byte bound.
    #[must_use]
    pub const fn with_diagnostic_limit(mut self, value: usize) -> Self {
        self.max_diagnostic_bytes = value;
        self
    }

    /// Returns a limit set with a regex step bound.
    #[must_use]
    pub const fn with_regex_step_limit(mut self, value: usize) -> Self {
        self.max_regex_steps = value;
        self
    }

    /// Returns a limit set with a regular-expression nesting-depth bound.
    #[must_use]
    pub const fn with_regex_depth_limit(mut self, value: usize) -> Self {
        self.max_regex_depth = value;
        self
    }

    /// Returns a limit set with an XPath-byte bound.
    #[must_use]
    pub const fn with_xpath_limit(mut self, value: usize) -> Self {
        self.max_xpath_bytes = value;
        self
    }
}

fn bounded(value: impl Into<String>, limit: usize) -> String {
    let mut value = value.into();
    if value.len() <= limit {
        return value;
    }
    if limit == 0 {
        value.clear();
        return value;
    }
    let suffix = "...";
    let keep = limit.saturating_sub(suffix.len());
    let mut end = keep.min(value.len());
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    if end < limit {
        value.push_str(&suffix[..limit.saturating_sub(end).min(suffix.len())]);
    }
    value
}

fn bounded_failure(
    name: &str,
    message: impl Into<String>,
    limits: AssertionLimits,
) -> AssertionResult {
    AssertionResult::failed(
        name.to_owned(),
        Some(bounded(message, limits.max_diagnostic_bytes)),
    )
}

fn bounded_error(
    name: &str,
    message: impl Into<String>,
    limits: AssertionLimits,
) -> AssertionResult {
    // JMeter stores diagnostics for both failed and errored assertions in its
    // single `failureMessage` field.  Keep the typed error bit independent,
    // but do not move this user-visible wire diagnostic to the Rust-only
    // `errorMessage` extension.
    let mut result = AssertionResult::errored(name.to_owned(), None);
    result.set_failure_message(Some(bounded(message, limits.max_diagnostic_bytes)));
    result
}

fn bounded_jmeter_error(message: impl Into<String>, limits: AssertionLimits) -> AssertionResult {
    bounded_error(JMETER_ASSERTION_ERROR_NAME, message, limits)
}

fn number_format_error(value: &str) -> String {
    // This is the stable `NumberFormatException.toString()` shape emitted by
    // JMeter when a numeric assertion property is parsed during evaluation.
    // Keep the value bounded before storing the deferred parse diagnostic.
    let value = bounded(value.to_owned(), DEFAULT_MAX_ASSERTION_DIAGNOSTIC_BYTES);
    format!("java.lang.NumberFormatException: For input string: \"{value}\"")
}

fn truncate_utf16(units: &[u16], right: bool) -> Vec<u16> {
    if units.len() <= EQUALS_SECTION_DIFF_LEN {
        return units.to_vec();
    }
    let mut output = Vec::with_capacity(EQUALS_SECTION_DIFF_LEN + EQUALS_DIFF_TRUNCATION.len());
    let ellipsis = EQUALS_DIFF_TRUNCATION.encode_utf16().collect::<Vec<_>>();
    if right {
        output.extend_from_slice(&units[..EQUALS_SECTION_DIFF_LEN]);
        output.extend_from_slice(&ellipsis);
    } else {
        output.extend_from_slice(&ellipsis);
        output.extend_from_slice(&units[units.len() - EQUALS_SECTION_DIFF_LEN..]);
    }
    output
}

fn utf16_to_string(units: &[u16]) -> String {
    String::from_utf16_lossy(units)
}

/// Reproduces JMeter's equality diagnostic, whose diff algorithm operates on
/// Java UTF-16 code units rather than Rust Unicode scalar values.
fn equals_comparison_text(received: &str, comparison: &str) -> String {
    let received = received.encode_utf16().collect::<Vec<_>>();
    let comparison = comparison.encode_utf16().collect::<Vec<_>>();
    let min_length = received.len().min(comparison.len());
    let first_diff = (0..min_length)
        .find(|index| received[*index] != comparison[*index])
        .unwrap_or(min_length);

    let starting_equal = if first_diff == 0 {
        Vec::new()
    } else {
        truncate_utf16(&received[..first_diff], false)
    };

    // Java's indexes are signed here: an empty string has a last index of -1.
    let mut last_received_diff = received.len() as isize - 1;
    let mut last_comparison_diff = comparison.len() as isize - 1;
    while last_received_diff > first_diff as isize
        && last_comparison_diff > first_diff as isize
        && received[last_received_diff as usize] == comparison[last_comparison_diff as usize]
    {
        last_received_diff -= 1;
        last_comparison_diff -= 1;
    }

    let received_end = (last_received_diff + 1).max(0) as usize;
    let comparison_end = (last_comparison_diff + 1).max(0) as usize;
    let ending_equal = truncate_utf16(&received[received_end..], true);
    let (mut received_delta, mut comparison_delta) = if ending_equal.is_empty() {
        (
            truncate_utf16(&received[first_diff..], true),
            truncate_utf16(&comparison[first_diff..], true),
        )
    } else {
        (
            truncate_utf16(&received[first_diff..received_end], true),
            truncate_utf16(&comparison[first_diff..comparison_end], true),
        )
    };
    if received_delta.len() < comparison_delta.len() {
        received_delta.extend(std::iter::repeat_n(
            u16::from(b' '),
            comparison_delta.len() - received_delta.len(),
        ));
    } else if comparison_delta.len() < received_delta.len() {
        comparison_delta.extend(std::iter::repeat_n(
            u16::from(b' '),
            received_delta.len() - comparison_delta.len(),
        ));
    }

    format!(
        "\n\n{EQUALS_RECEIVED_PREFIX}{}{EQUALS_DELTA_START}{}{EQUALS_DELTA_END}{}\n\n{EQUALS_COMPARISON_PREFIX}{}{EQUALS_DELTA_START}{}{EQUALS_DELTA_END}{}\n\n",
        utf16_to_string(&starting_equal),
        utf16_to_string(&received_delta),
        utf16_to_string(&ending_equal),
        utf16_to_string(&starting_equal),
        utf16_to_string(&comparison_delta),
        utf16_to_string(&ending_equal),
    )
}

fn bounded_failure_and_error(
    name: &str,
    message: impl Into<String>,
    limits: AssertionLimits,
) -> AssertionResult {
    // XMLAssertion retains both wire flags for malformed documents. Keep the
    // diagnostic in JMeter's failureMessage field.
    let message = bounded(message, limits.max_diagnostic_bytes);
    match AssertionResult::from_flags(name.to_owned(), true, true, Some(message), None) {
        Ok(result) => result,
        Err(_) => bounded_error(
            name,
            "assertion result flags could not be represented",
            limits,
        ),
    }
}

fn bounded_unsupported(message: impl Into<String>) -> ComponentError {
    ComponentError::unsupported(message)
}

fn malformed_or_unmatched_class(source: &str) -> String {
    format!(
        "Bad test configuration org.apache.oro.text.MalformedCachePatternException: Invalid expression: {source} Unmatched [] in expression."
    )
}

fn response_field_bytes(
    result: &SampleResult,
    field: &ResponseField,
) -> Result<Option<usize>, ComponentError> {
    let bytes = match field {
        ResponseField::ResponseData => result.response_data().map(|data| data.len()),
        // JMeter's request-data target is SampleResult.samplerData. Keep the
        // typed request payload as a fallback for native protocol adapters.
        ResponseField::RequestData => result
            .sampler_data()
            .map(str::len)
            .or_else(|| result.request_data().map(|data| data.len())),
        ResponseField::ResponseCode => result.response_code().map(str::len),
        ResponseField::ResponseMessage => result.response_message().map(str::len),
        ResponseField::ResponseHeaders => result
            .response_headers()
            .map(|headers| headers.as_str().len()),
        ResponseField::RequestHeaders => result
            .request_headers()
            .map(|headers| headers.as_str().len()),
        ResponseField::Url => result.url().map(str::len),
        ResponseField::SampleLabel => Some(result.label().len()),
        ResponseField::Variable(_) => None,
        ResponseField::Unknown(value) => {
            return Err(bounded_unsupported(format!(
                "response assertion field {value:?} is not supported"
            )));
        }
        ResponseField::Document => {
            return Err(bounded_unsupported(
                "response assertion document field requires the pinned document adapter",
            ));
        }
    };
    Ok(bytes)
}

fn decode_utf16_bytes(bytes: &[u8], little_endian: bool) -> String {
    let mut units = Vec::with_capacity(bytes.len().div_ceil(2));
    for pair in bytes.chunks_exact(2) {
        let unit = if little_endian {
            u16::from_le_bytes([pair[0], pair[1]])
        } else {
            u16::from_be_bytes([pair[0], pair[1]])
        };
        units.push(unit);
    }
    if !bytes.chunks_exact(2).remainder().is_empty() {
        // Java's Charset decoder replaces an incomplete trailing code unit.
        units.push(0xfffd);
    }
    String::from_utf16_lossy(&units)
}

fn decode_windows_1252(bytes: &[u8]) -> String {
    const EXTENDED: [char; 32] = [
        '\u{20ac}', '\u{fffd}', '\u{201a}', '\u{192}', '\u{201e}', '\u{2026}', '\u{2020}',
        '\u{2021}', '\u{2c6}', '\u{2030}', '\u{160}', '\u{2039}', '\u{152}', '\u{fffd}', '\u{17d}',
        '\u{fffd}', '\u{fffd}', '\u{2018}', '\u{2019}', '\u{201c}', '\u{201d}', '\u{2022}',
        '\u{2013}', '\u{2014}', '\u{2dc}', '\u{2122}', '\u{161}', '\u{203a}', '\u{153}',
        '\u{fffd}', '\u{17e}', '\u{178}',
    ];
    bytes
        .iter()
        .map(|byte| match *byte {
            0x00..=0x7f | 0xa0..=0xff => char::from(*byte),
            value => EXTENDED[(value - 0x80) as usize],
        })
        .collect()
}

fn decode_response_bytes(result: &SampleResult, bytes: &[u8]) -> Result<String, ComponentError> {
    let encoding = result
        .data_encoding()
        .map(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("UTF-8");
    let normalized = encoding
        .bytes()
        .filter(|value| !matches!(value, b'-' | b'_' | b' '))
        .map(|value| char::from(value.to_ascii_uppercase()))
        .collect::<String>();
    let value = match normalized.as_str() {
        "UTF8" => String::from_utf8_lossy(bytes).into_owned(),
        "USASCII" | "ASCII" => bytes
            .iter()
            .map(|value| {
                if value.is_ascii() {
                    char::from(*value)
                } else {
                    '\u{fffd}'
                }
            })
            .collect(),
        "ISO88591" | "LATIN1" | "L1" => bytes.iter().map(|value| char::from(*value)).collect(),
        "WINDOWS1252" | "CP1252" => decode_windows_1252(bytes),
        "UTF16" => {
            let (bytes, little_endian) = match bytes {
                [0xfe, 0xff, rest @ ..] => (rest, false),
                [0xff, 0xfe, rest @ ..] => (rest, true),
                _ => (bytes, false),
            };
            decode_utf16_bytes(bytes, little_endian)
        }
        "UTF16LE" => decode_utf16_bytes(bytes, true),
        "UTF16BE" => decode_utf16_bytes(bytes, false),
        _ => {
            return Err(bounded_unsupported(format!(
                "response assertion encoding {encoding:?} is unsupported"
            )));
        }
    };
    Ok(value)
}

fn check_response_field_bytes(
    result: &SampleResult,
    field: &ResponseField,
    limits: AssertionLimits,
) -> Result<(), ComponentError> {
    if let Some(bytes) = response_field_bytes(result, field)?
        && bytes > limits.max_response_bytes
    {
        return Err(ComponentError::resource_limit(format!(
            "assertion {} bytes {bytes} exceed {}",
            field.display_name(),
            limits.max_response_bytes
        )));
    }
    Ok(())
}

fn sample_text(
    result: &SampleResult,
    field: &ResponseField,
) -> Result<Option<String>, ComponentError> {
    let value = match field {
        ResponseField::ResponseData => result
            .response_data()
            .map(|data| decode_response_bytes(result, data.as_bytes()))
            .transpose()?,
        ResponseField::RequestData => result.sampler_data().map(str::to_owned).or_else(|| {
            result
                .request_data()
                .map(|data| String::from_utf8_lossy(data.as_bytes()).into_owned())
        }),
        ResponseField::ResponseCode => result.response_code().map(str::to_owned),
        ResponseField::ResponseMessage => result.response_message().map(str::to_owned),
        ResponseField::ResponseHeaders => result
            .response_headers()
            .map(|headers| headers.as_str().to_owned()),
        ResponseField::RequestHeaders => result
            .request_headers()
            .map(|headers| headers.as_str().to_owned()),
        ResponseField::Url => result.url().map(str::to_owned),
        ResponseField::SampleLabel => Some(result.label().to_owned()),
        ResponseField::Unknown(value) => {
            return Err(bounded_unsupported(format!(
                "response assertion field {value:?} is not supported"
            )));
        }
        ResponseField::Document => {
            return Err(bounded_unsupported(
                "response assertion document field requires the pinned document adapter",
            ));
        }
        ResponseField::Variable(_) => None,
    };
    Ok(value)
}

/// Field inspected by a response assertion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResponseField {
    /// Sampler response body bytes decoded using the result's data encoding.
    ResponseData,
    /// Sampler request body text, with typed request bytes used only as a
    /// native fallback when sampler data is absent.
    RequestData,
    /// Sampler response code.
    ResponseCode,
    /// Sampler response message.
    ResponseMessage,
    /// Raw response headers.
    ResponseHeaders,
    /// Raw request headers.
    RequestHeaders,
    /// Sampled URL.
    Url,
    /// Sample-label-compatible field retained for callers that construct the
    /// neutral value directly.  JMeter's wire spelling maps this property to
    /// its sampled URL field, represented by [`Self::Url`] when decoded.
    SampleLabel,
    /// A thread-local JMeter variable.
    Variable(String),
    /// The document-text field, which requires Apache Tika in JMeter.
    Document,
    /// An unknown wire field retained for an explicit unsupported result.
    Unknown(String),
}

impl ResponseField {
    /// Decodes JMeter's `Assertion.test_field` wire spelling.
    #[must_use]
    pub fn from_wire(value: impl Into<String>) -> Self {
        let value = value.into();
        match value.as_str() {
            "Assertion.response_data" => Self::ResponseData,
            "Assertion.request_data" => Self::RequestData,
            "Assertion.response_code" => Self::ResponseCode,
            "Assertion.response_message" => Self::ResponseMessage,
            "Assertion.response_headers" => Self::ResponseHeaders,
            "Assertion.request_headers" => Self::RequestHeaders,
            // JMeter's `SAMPLE_URL` constant intentionally uses the
            // historical `Assertion.sample_label` property spelling.  The
            // runtime keeps the semantic field as URL rather than inventing
            // a separate sample-label assertion target.
            "Assertion.sample_label" => Self::Url,
            "Assertion.response_data_as_document" => Self::Document,
            "Assertion.url" | "Assertion.sample_url" => Self::Url,
            value if value.starts_with("Assertion.variable:") => {
                Self::Variable(value["Assertion.variable:".len()..].to_owned())
            }
            _ => Self::Unknown(value),
        }
    }

    /// Returns JMeter's canonical wire spelling where one exists.
    #[must_use]
    pub fn as_wire(&self) -> String {
        match self {
            Self::ResponseData => "Assertion.response_data".to_owned(),
            Self::RequestData => "Assertion.request_data".to_owned(),
            Self::ResponseCode => "Assertion.response_code".to_owned(),
            Self::ResponseMessage => "Assertion.response_message".to_owned(),
            Self::ResponseHeaders => "Assertion.response_headers".to_owned(),
            Self::RequestHeaders => "Assertion.request_headers".to_owned(),
            Self::SampleLabel => "Assertion.sample_label".to_owned(),
            Self::Document => "Assertion.response_data_as_document".to_owned(),
            Self::Url => "Assertion.sample_label".to_owned(),
            Self::Variable(name) => format!("Assertion.variable:{name}"),
            Self::Unknown(value) => value.clone(),
        }
    }

    fn display_name(&self) -> &'static str {
        match self {
            Self::ResponseData => "text",
            Self::Document => "document",
            Self::RequestData => "request data",
            Self::ResponseCode => "code",
            Self::ResponseMessage => "message",
            Self::ResponseHeaders => "headers",
            Self::RequestHeaders => "request headers",
            Self::Url => "URL",
            Self::SampleLabel => "sample label",
            Self::Variable(_) => "variable",
            Self::Unknown(_) => "unknown field",
        }
    }

    fn failure_display_name(&self) -> String {
        match self {
            Self::Variable(name) => format!("variable({name})"),
            _ => self.display_name().to_owned(),
        }
    }
}

/// Pattern comparison mode for a response assertion.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ResponsePatternMode {
    /// Search for a regular-expression match anywhere in the field.
    Contains,
    /// Require the regular expression to match the complete field.
    Matches,
    /// Compare the complete field as case-sensitive plain text.
    Equals,
    /// Search for a case-sensitive plain-text substring.
    Substring,
}

impl ResponsePatternMode {
    /// Decodes the low-level JMeter test-type value, excluding NOT and OR
    /// modifiers.
    pub fn from_wire_test_type(value: i32) -> Result<Self, ComponentError> {
        if value & !0x3f != 0 {
            return Err(ComponentError::failure(format!(
                "unsupported response assertion test type {value}"
            )));
        }
        let mode = value & 0x1f;
        match mode & 0x1b {
            0x01 => Ok(Self::Matches),
            0x02 => Ok(Self::Contains),
            0x08 => Ok(Self::Equals),
            0x10 => Ok(Self::Substring),
            _ => Err(ComponentError::failure(format!(
                "unsupported response assertion test type {value}"
            ))),
        }
    }

    /// Returns the canonical JMeter mode bits.
    #[must_use]
    pub const fn wire_bits(self) -> i32 {
        match self {
            Self::Matches => 0x01,
            Self::Contains => 0x02,
            Self::Equals => 0x08,
            Self::Substring => 0x10,
        }
    }
}

/// Native bounded implementation of JMeter's Response Assertion.
#[derive(Clone, Debug)]
pub struct ResponseAssertion {
    name: String,
    field: ResponseField,
    mode: ResponsePatternMode,
    patterns: Vec<String>,
    negate: bool,
    or: bool,
    assume_success: bool,
    custom_failure_message: Option<String>,
    limits: AssertionLimits,
}

impl ResponseAssertion {
    /// Creates a response assertion from neutral values.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        field: ResponseField,
        mode: ResponsePatternMode,
        patterns: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            name: name.into(),
            field,
            mode,
            patterns: patterns.into_iter().map(Into::into).collect(),
            negate: false,
            or: false,
            assume_success: false,
            custom_failure_message: None,
            limits: AssertionLimits::default(),
        }
    }

    /// Creates a single-pattern response assertion.
    #[must_use]
    pub fn single(
        name: impl Into<String>,
        field: ResponseField,
        mode: ResponsePatternMode,
        pattern: impl Into<String>,
    ) -> Self {
        Self::new(name, field, mode, [pattern])
    }

    /// Creates a response assertion from JMeter wire properties.
    pub fn from_wire(
        name: impl Into<String>,
        field: impl Into<String>,
        test_type: i32,
        patterns: impl IntoIterator<Item = impl Into<String>>,
        assume_success: bool,
        custom_failure_message: Option<String>,
    ) -> Result<Self, ComponentError> {
        let mode = ResponsePatternMode::from_wire_test_type(test_type)?;
        Ok(Self {
            name: name.into(),
            field: ResponseField::from_wire(field),
            mode,
            patterns: patterns.into_iter().map(Into::into).collect(),
            negate: test_type & 0x04 != 0,
            or: test_type & 0x20 != 0,
            assume_success,
            custom_failure_message,
            limits: AssertionLimits::default(),
        })
    }

    /// Creates a response assertion from JMeter's `Asserion.test_strings`
    /// collection and its `Assertion.*` properties.
    pub fn from_jmx(
        name: impl Into<String>,
        field: impl Into<String>,
        test_type: i32,
        patterns: impl IntoIterator<Item = impl Into<String>>,
        assume_success: bool,
        custom_failure_message: Option<String>,
    ) -> Result<Self, ComponentError> {
        Self::from_wire(
            name,
            field,
            test_type,
            patterns,
            assume_success,
            custom_failure_message,
        )
    }

    /// Replaces the assertion resource limits.
    #[must_use]
    pub const fn with_limits(mut self, limits: AssertionLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Sets JMeter's NOT modifier.
    #[must_use]
    pub const fn with_negate(mut self, value: bool) -> Self {
        self.negate = value;
        self
    }

    /// Sets JMeter's OR modifier.
    #[must_use]
    pub const fn with_or(mut self, value: bool) -> Self {
        self.or = value;
        self
    }

    /// Sets the ignore-status/assume-success option.
    #[must_use]
    pub const fn with_assume_success(mut self, value: bool) -> Self {
        self.assume_success = value;
        self
    }

    /// Sets a custom JMeter failure message.
    #[must_use]
    pub fn with_custom_failure_message(mut self, value: Option<String>) -> Self {
        self.custom_failure_message = value;
        self
    }

    /// Returns the neutral assertion name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the tested field.
    #[must_use]
    pub const fn field(&self) -> &ResponseField {
        &self.field
    }

    /// Returns the pattern mode.
    #[must_use]
    pub const fn mode(&self) -> ResponsePatternMode {
        self.mode
    }

    /// Returns patterns in source order.
    #[must_use]
    pub fn patterns(&self) -> &[String] {
        &self.patterns
    }

    /// Returns whether NOT is enabled.
    #[must_use]
    pub const fn is_negated(&self) -> bool {
        self.negate
    }

    /// Returns whether OR is enabled.
    #[must_use]
    pub const fn is_or(&self) -> bool {
        self.or
    }

    /// Returns JMeter's test-type bit representation.
    #[must_use]
    pub const fn test_type(&self) -> i32 {
        self.mode.wire_bits() | if self.negate { 0x04 } else { 0 } | if self.or { 0x20 } else { 0 }
    }

    fn validate_patterns(&self) -> Result<(), ComponentError> {
        if self.patterns.len() > self.limits.max_patterns {
            return Err(ComponentError::resource_limit(format!(
                "response assertion pattern count {} exceeds {}",
                self.patterns.len(),
                self.limits.max_patterns
            )));
        }
        for pattern in &self.patterns {
            if pattern.len() > self.limits.max_pattern_bytes {
                return Err(ComponentError::resource_limit(format!(
                    "response assertion pattern bytes {} exceed {}",
                    pattern.len(),
                    self.limits.max_pattern_bytes
                )));
            }
        }
        Ok(())
    }

    fn check_pattern(&self, text: &str, pattern: &str) -> Result<bool, PatternCheckError> {
        match self.mode {
            ResponsePatternMode::Equals => Ok(text == pattern),
            ResponsePatternMode::Substring => Ok(text.contains(pattern)),
            ResponsePatternMode::Contains | ResponsePatternMode::Matches => {
                let program = RegexProgram::compile(pattern, self.limits)?;
                program
                    .is_match(text, self.mode == ResponsePatternMode::Matches)
                    .map_err(PatternCheckError::Evaluation)
            }
        }
    }

    fn default_failure_message(&self, pattern: &str, value: &str) -> String {
        if self.or {
            // JMeter's getFailText switches on the complete test type.  OR is
            // a modifier bit, so the upstream diagnostic intentionally falls
            // through to this generic wording.
            let displayed_pattern = if self.mode == ResponsePatternMode::Equals {
                equals_comparison_text(value, pattern)
            } else {
                pattern.to_owned()
            };
            return format!(
                "Test failed: {} expected something using /{displayed_pattern}/",
                self.field.failure_display_name()
            );
        }
        let relation = match (self.mode, self.negate) {
            (ResponsePatternMode::Contains, false) | (ResponsePatternMode::Substring, false) => {
                "contain"
            }
            (ResponsePatternMode::Matches, false) => "match",
            (ResponsePatternMode::Equals, false) => "equal",
            (ResponsePatternMode::Contains, true) | (ResponsePatternMode::Substring, true) => {
                "not to contain"
            }
            (ResponsePatternMode::Matches, true) => "not to match",
            (ResponsePatternMode::Equals, true) => "not to equal",
        };
        let displayed_pattern = if self.mode == ResponsePatternMode::Equals {
            equals_comparison_text(value, pattern)
        } else {
            pattern.to_owned()
        };
        format!(
            "Test failed: {} expected to {relation} /{displayed_pattern}/",
            self.field.failure_display_name()
        )
    }

    fn failure_message(&self, pattern: &str, value: &str) -> String {
        self.custom_failure_message
            .as_deref()
            .filter(|message| !message.is_empty())
            .map_or_else(
                || self.default_failure_message(pattern, value),
                ToOwned::to_owned,
            )
    }
}

impl Assertion for ResponseAssertion {
    fn evaluate<'a>(
        &'a self,
        context: &'a mut SampleContext<'_>,
    ) -> ComponentFuture<'a, AssertionResult> {
        Box::pin(async move {
            self.validate_patterns()?;
            if self.assume_success
                && let Some(result) = context.result_mut()
            {
                result.set_successful(true);
            }
            let Some(result) = context.result() else {
                return Ok(bounded_error(
                    &self.name,
                    "response assertion received no sample result",
                    self.limits,
                ));
            };
            check_response_field_bytes(result, &self.field, self.limits)?;
            let value = match &self.field {
                ResponseField::Variable(name) => context.execution().variable(name),
                _ => sample_text(result, &self.field)?,
            };
            let Some(value) = value else {
                return if self.negate {
                    Ok(AssertionResult::passed(self.name.clone()))
                } else {
                    Ok(bounded_failure(
                        &self.name,
                        "Response was null",
                        self.limits,
                    ))
                };
            };
            // Non-variable fields were bounded from their original wire
            // representation above. Rechecking the lossy UTF-8 rendering can
            // reject a valid byte-bounded response when replacement characters
            // expand it; only variable text needs this post-resolution bound.
            if matches!(self.field, ResponseField::Variable(_))
                && value.len() > self.limits.max_response_bytes
            {
                return Err(ComponentError::resource_limit(format!(
                    "response assertion field bytes {} exceed {}",
                    value.len(),
                    self.limits.max_response_bytes
                )));
            }
            // JMeter treats an empty checked field as a null result. NOT
            // assertions are explicitly successful for that case; positive
            // assertions fail without attempting regex compilation.
            if value.is_empty() {
                return if self.negate {
                    Ok(AssertionResult::passed(self.name.clone()))
                } else {
                    Ok(bounded_failure(
                        &self.name,
                        "Response was null",
                        self.limits,
                    ))
                };
            }
            let mut matched = !self.or;
            let mut failed_pattern = None;
            let mut failed_messages = Vec::new();
            for pattern in &self.patterns {
                let raw = match self.check_pattern(&value, pattern) {
                    Ok(raw) => raw,
                    Err(PatternCheckError::Malformed(message)) => {
                        return Ok(bounded_error(&self.name, message, self.limits));
                    }
                    Err(PatternCheckError::Unsupported(message)) => {
                        return Err(bounded_unsupported(message));
                    }
                    Err(PatternCheckError::Evaluation(error)) => return Err(error),
                };
                let result = if self.negate { !raw } else { raw };
                if self.or {
                    matched |= result;
                    if result {
                        break;
                    }
                    failed_messages.push(self.default_failure_message(pattern, &value));
                } else {
                    matched &= result;
                    if !result {
                        failed_pattern = Some(pattern.as_str());
                        break;
                    }
                }
            }
            if matched {
                Ok(AssertionResult::passed(self.name.clone()))
            } else {
                let pattern = failed_pattern
                    .or_else(|| self.patterns.first().map(String::as_str))
                    .unwrap_or("");
                let message = if self.or {
                    if let Some(custom) = self
                        .custom_failure_message
                        .as_deref()
                        .filter(|message| !message.is_empty())
                    {
                        custom.to_owned()
                    } else if failed_messages.is_empty() {
                        // Java's joining(delimiter, prefix, suffix) emits the
                        // suffix for an empty OR collection.
                        "\t".to_owned()
                    } else {
                        format!("\t{}\t", failed_messages.join("\t"))
                    }
                } else {
                    self.failure_message(pattern, &value)
                };
                Ok(bounded_failure(&self.name, message, self.limits))
            }
        })
    }
}

/// Backwards-compatible alias for callers that use JMeter's field wording.
pub type ResponseAssertionField = ResponseField;
/// Backwards-compatible alias for callers that use JMeter's pattern wording.
pub type PatternMode = ResponsePatternMode;

#[derive(Debug)]
enum PatternCheckError {
    Malformed(String),
    Unsupported(String),
    Evaluation(ComponentError),
}

#[derive(Clone, Copy, Debug, Default)]
struct RegexFlags {
    case_insensitive: bool,
    dot_matches_newline: bool,
    multiline: bool,
}

#[derive(Clone, Debug)]
enum RegexNode {
    Empty,
    Literal(char),
    Any,
    Class {
        ranges: Vec<(char, char)>,
        negate: bool,
    },
    AnchorStart,
    AnchorEnd,
    Sequence(Vec<RegexNode>),
    Alternation(Vec<RegexNode>),
    Repeat {
        node: Box<RegexNode>,
        min: usize,
        max: Option<usize>,
    },
}

struct RegexParser<'a> {
    chars: Vec<char>,
    index: usize,
    flags: RegexFlags,
    nodes: usize,
    limits: AssertionLimits,
    source: &'a str,
}

impl<'a> RegexParser<'a> {
    fn new(source: &'a str, limits: AssertionLimits) -> Self {
        Self {
            chars: source.chars().collect(),
            index: 0,
            flags: RegexFlags {
                multiline: false,
                ..RegexFlags::default()
            },
            nodes: 0,
            limits,
            source,
        }
    }

    fn compile(mut self) -> Result<(RegexNode, RegexFlags), PatternCheckError> {
        self.parse_flags()?;
        let root = self.parse_alternation(0, None)?;
        if self.index != self.chars.len() {
            return Err(PatternCheckError::Malformed(format!(
                "invalid regular expression {:?}: unexpected {:?}",
                self.source,
                self.chars.get(self.index).copied().unwrap_or_default()
            )));
        }
        Ok((root, self.flags))
    }

    fn parse_flags(&mut self) -> Result<(), PatternCheckError> {
        if self.chars.len() < 4 || self.chars.first() != Some(&'(') {
            return Ok(());
        }
        let mut index = 0;
        while self.chars.get(index) == Some(&'(') && self.chars.get(index + 1) == Some(&'?') {
            let start = index;
            index += 2;
            let mut saw_flag = false;
            let mut enabling = true;
            while let Some(flag) = self.chars.get(index).copied() {
                match flag {
                    'i' => {
                        self.flags.case_insensitive = enabling;
                        saw_flag = true;
                    }
                    's' => {
                        self.flags.dot_matches_newline = enabling;
                        saw_flag = true;
                    }
                    'm' => {
                        self.flags.multiline = enabling;
                        saw_flag = true;
                    }
                    '-' if enabling => enabling = false,
                    ')' if saw_flag => {
                        index += 1;
                        self.index = index;
                        break;
                    }
                    _ => {
                        if start == 0 {
                            return Err(PatternCheckError::Unsupported(format!(
                                "regular-expression flag construct {:?} is unsupported",
                                self.source
                            )));
                        }
                        return Ok(());
                    }
                }
                index += 1;
            }
            if self.index == 0 {
                return Err(PatternCheckError::Malformed(format!(
                    "invalid regular-expression flags in {:?}",
                    self.source
                )));
            }
        }
        Ok(())
    }

    fn bump_node(&mut self) -> Result<(), PatternCheckError> {
        self.nodes = self.nodes.saturating_add(1);
        let max_nodes = self.limits.max_pattern_bytes.saturating_mul(4).max(64);
        if self.nodes > max_nodes {
            return Err(PatternCheckError::Unsupported(
                "regular-expression syntax exceeds the bounded expression node limit".to_owned(),
            ));
        }
        Ok(())
    }

    fn parse_alternation(
        &mut self,
        depth: usize,
        terminator: Option<char>,
    ) -> Result<RegexNode, PatternCheckError> {
        if depth > self.limits.max_regex_depth {
            return Err(PatternCheckError::Unsupported(
                "regular-expression nesting exceeds the bounded depth".to_owned(),
            ));
        }
        let mut branches = Vec::new();
        loop {
            branches.push(self.parse_sequence(depth, terminator)?);
            if self.chars.get(self.index) == Some(&'|') {
                self.index += 1;
                continue;
            }
            break;
        }
        if branches.len() == 1 {
            Ok(branches.pop().unwrap_or(RegexNode::Empty))
        } else {
            self.bump_node()?;
            Ok(RegexNode::Alternation(branches))
        }
    }

    fn parse_sequence(
        &mut self,
        depth: usize,
        terminator: Option<char>,
    ) -> Result<RegexNode, PatternCheckError> {
        let mut values = Vec::new();
        while let Some(value) = self.chars.get(self.index).copied() {
            if Some(value) == terminator || value == '|' {
                break;
            }
            values.push(self.parse_atom(depth)?);
        }
        if values.len() == 1 {
            Ok(values.pop().unwrap_or(RegexNode::Empty))
        } else {
            self.bump_node()?;
            Ok(RegexNode::Sequence(values))
        }
    }

    fn parse_atom(&mut self, depth: usize) -> Result<RegexNode, PatternCheckError> {
        let value = self.chars.get(self.index).copied().ok_or_else(|| {
            PatternCheckError::Malformed(format!("invalid regular expression {:?}", self.source))
        })?;
        let mut node = match value {
            '(' => {
                self.index += 1;
                if self.chars.get(self.index) == Some(&'?') {
                    return Err(PatternCheckError::Unsupported(
                        "look-around, named, or non-capturing regular-expression groups are unsupported"
                            .to_owned(),
                    ));
                }
                let value = self.parse_alternation(depth.saturating_add(1), Some(')'))?;
                if self.chars.get(self.index) != Some(&')') {
                    return Err(PatternCheckError::Malformed(format!(
                        "invalid regular expression {:?}: unmatched '('",
                        self.source
                    )));
                }
                self.index += 1;
                value
            }
            ')' => {
                return Err(PatternCheckError::Malformed(format!(
                    "invalid regular expression {:?}: unmatched ')'",
                    self.source
                )));
            }
            '[' => self.parse_class()?,
            '.' => {
                self.index += 1;
                self.bump_node()?;
                RegexNode::Any
            }
            '^' => {
                self.index += 1;
                self.bump_node()?;
                RegexNode::AnchorStart
            }
            '$' => {
                self.index += 1;
                self.bump_node()?;
                RegexNode::AnchorEnd
            }
            '*' | '+' | '?' | '{' => {
                return Err(PatternCheckError::Malformed(format!(
                    "invalid regular expression {:?}: quantifier has no atom",
                    self.source
                )));
            }
            '\\' => self.parse_escape(false)?,
            _ => {
                self.index += 1;
                self.bump_node()?;
                RegexNode::Literal(value)
            }
        };
        if let Some(quantifier) = self.chars.get(self.index).copied() {
            let (min, max) = match quantifier {
                '*' => {
                    self.index += 1;
                    (0, None)
                }
                '+' => {
                    self.index += 1;
                    (1, None)
                }
                '?' => {
                    self.index += 1;
                    (0, Some(1))
                }
                '{' => self.parse_braced_quantifier()?,
                _ => (1, Some(1)),
            };
            if min != 1 || max != Some(1) {
                if self.chars.get(self.index) == Some(&'?') {
                    return Err(PatternCheckError::Unsupported(
                        "lazy regular-expression quantifiers are unsupported".to_owned(),
                    ));
                }
                self.bump_node()?;
                node = RegexNode::Repeat {
                    node: Box::new(node),
                    min,
                    max,
                };
            }
        }
        Ok(node)
    }

    fn parse_braced_quantifier(&mut self) -> Result<(usize, Option<usize>), PatternCheckError> {
        self.index += 1;
        let min = self.parse_digits()?;
        let max = match self.chars.get(self.index).copied() {
            Some('}') => {
                self.index += 1;
                Some(min)
            }
            Some(',') => {
                self.index += 1;
                let max = if self.chars.get(self.index) == Some(&'}') {
                    None
                } else {
                    Some(self.parse_digits()?)
                };
                if self.chars.get(self.index) != Some(&'}') {
                    return Err(PatternCheckError::Malformed(
                        "regular-expression quantifier is missing '}'".to_owned(),
                    ));
                }
                self.index += 1;
                max
            }
            _ => {
                return Err(PatternCheckError::Malformed(
                    "regular-expression quantifier is missing '}'".to_owned(),
                ));
            }
        };
        if let Some(maximum) = max
            && maximum < min
        {
            return Err(PatternCheckError::Malformed(
                "regular-expression quantifier has a maximum below its minimum".to_owned(),
            ));
        }
        Ok((min, max))
    }

    fn parse_digits(&mut self) -> Result<usize, PatternCheckError> {
        let start = self.index;
        let mut value = 0_usize;
        while let Some(digit) = self.chars.get(self.index).copied() {
            if !digit.is_ascii_digit() {
                break;
            }
            self.index += 1;
            value = value
                .checked_mul(10)
                .and_then(|value| value.checked_add((digit as u8 - b'0') as usize))
                .ok_or_else(|| {
                    PatternCheckError::Unsupported(
                        "regular-expression quantifier overflows the bounded range".to_owned(),
                    )
                })?;
            if value > 1024 {
                return Err(PatternCheckError::Unsupported(
                    "regular-expression quantifier exceeds 1024 repetitions".to_owned(),
                ));
            }
        }
        if self.index == start {
            return Err(PatternCheckError::Malformed(
                "regular-expression quantifier requires digits".to_owned(),
            ));
        }
        Ok(value)
    }

    fn parse_escape(&mut self, _in_class: bool) -> Result<RegexNode, PatternCheckError> {
        self.index += 1;
        let escaped = self.chars.get(self.index).copied().ok_or_else(|| {
            PatternCheckError::Malformed(format!(
                "invalid regular expression {:?}: trailing escape",
                self.source
            ))
        })?;
        self.index += 1;
        let node = match escaped {
            'd' => RegexNode::Class {
                ranges: vec![('0', '9')],
                negate: false,
            },
            'D' => RegexNode::Class {
                ranges: vec![('0', '9')],
                negate: true,
            },
            'w' => RegexNode::Class {
                ranges: vec![('0', '9'), ('A', 'Z'), ('_', '_'), ('a', 'z')],
                negate: false,
            },
            'W' => RegexNode::Class {
                ranges: vec![('0', '9'), ('A', 'Z'), ('_', '_'), ('a', 'z')],
                negate: true,
            },
            's' => RegexNode::Class {
                ranges: vec![('\t', '\t'), ('\n', '\n'), ('\r', '\r'), (' ', ' ')],
                negate: false,
            },
            'S' => RegexNode::Class {
                ranges: vec![('\t', '\t'), ('\n', '\n'), ('\r', '\r'), (' ', ' ')],
                negate: true,
            },
            'n' => RegexNode::Literal('\n'),
            'r' => RegexNode::Literal('\r'),
            't' => RegexNode::Literal('\t'),
            'f' => RegexNode::Literal('\x0c'),
            'b' | 'B' => {
                return Err(PatternCheckError::Unsupported(
                    "regular-expression word-boundary escapes are unsupported".to_owned(),
                ));
            }
            'p' | 'P' | 'k' | 'Q' | 'E' | 'x' | 'u' => {
                return Err(PatternCheckError::Unsupported(format!(
                    "regular-expression escape \\{escaped} is unsupported"
                )));
            }
            value => RegexNode::Literal(value),
        };
        self.bump_node()?;
        Ok(node)
    }

    fn parse_class(&mut self) -> Result<RegexNode, PatternCheckError> {
        self.index += 1;
        let negate = if self.chars.get(self.index) == Some(&'^') {
            self.index += 1;
            true
        } else {
            false
        };
        let mut values = Vec::new();
        let mut closed = false;
        while let Some(value) = self.chars.get(self.index).copied() {
            if value == ']' && !values.is_empty() {
                self.index += 1;
                closed = true;
                break;
            }
            let first = if value == '\\' {
                let node = self.parse_escape(true)?;
                match node {
                    RegexNode::Literal(value) => vec![(value, value)],
                    RegexNode::Class {
                        ranges,
                        negate: false,
                    } => ranges,
                    RegexNode::Class { .. } => {
                        return Err(PatternCheckError::Unsupported(
                            "negated character classes inside a class are unsupported".to_owned(),
                        ));
                    }
                    _ => {
                        return Err(PatternCheckError::Unsupported(
                            "regular-expression class escape is unsupported".to_owned(),
                        ));
                    }
                }
            } else {
                self.index += 1;
                vec![(value, value)]
            };
            if self.chars.get(self.index) == Some(&'-')
                && self
                    .chars
                    .get(self.index + 1)
                    .is_some_and(|value| *value != ']')
            {
                self.index += 1;
                let second = if self.chars.get(self.index) == Some(&'\\') {
                    let node = self.parse_escape(true)?;
                    match node {
                        RegexNode::Literal(value) => value,
                        _ => {
                            return Err(PatternCheckError::Unsupported(
                                "regular-expression class ranges require literal endpoints"
                                    .to_owned(),
                            ));
                        }
                    }
                } else {
                    let value = self.chars.get(self.index).copied().ok_or_else(|| {
                        PatternCheckError::Malformed(
                            "regular-expression class range is incomplete".to_owned(),
                        )
                    })?;
                    self.index += 1;
                    value
                };
                if first.len() != 1 || first[0].0 > second {
                    return Err(PatternCheckError::Malformed(
                        "regular-expression class range is invalid".to_owned(),
                    ));
                }
                values.push((first[0].0, second));
            } else {
                values.extend(first);
            }
            if values.len() > 256 {
                return Err(PatternCheckError::Unsupported(
                    "regular-expression class exceeds the bounded range count".to_owned(),
                ));
            }
        }
        if !closed {
            return Err(PatternCheckError::Malformed(malformed_or_unmatched_class(
                self.source,
            )));
        }
        self.bump_node()?;
        Ok(RegexNode::Class {
            ranges: values,
            negate,
        })
    }
}

struct RegexProgram {
    root: RegexNode,
    flags: RegexFlags,
    limits: AssertionLimits,
}

impl RegexProgram {
    fn compile(source: &str, limits: AssertionLimits) -> Result<Self, PatternCheckError> {
        if source.len() > limits.max_pattern_bytes {
            return Err(PatternCheckError::Unsupported(
                "regular-expression pattern exceeds the configured byte bound".to_owned(),
            ));
        }
        let (root, flags) = RegexParser::new(source, limits).compile()?;
        Ok(Self {
            root,
            flags,
            limits,
        })
    }

    fn is_match(&self, text: &str, whole: bool) -> Result<bool, ComponentError> {
        if text.len() > self.limits.max_response_bytes {
            return Err(ComponentError::resource_limit(
                "regular-expression input exceeds the configured byte bound",
            ));
        }
        let chars: Vec<char> = text.chars().collect();
        let starts = if whole {
            vec![0]
        } else {
            (0..=chars.len()).collect()
        };
        let mut state = RegexMatchState {
            steps: 0,
            max_steps: self.limits.max_regex_steps,
        };
        for start in starts {
            let positions = match_node(&self.root, &chars, start, self.flags, &mut state)?;
            if positions
                .into_iter()
                .any(|position| !whole || position == chars.len())
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

struct RegexMatchState {
    steps: usize,
    max_steps: usize,
}

fn match_step(state: &mut RegexMatchState) -> Result<(), ComponentError> {
    state.steps = state.steps.saturating_add(1);
    if state.steps > state.max_steps {
        return Err(ComponentError::resource_limit(
            "regular-expression evaluation exceeded the configured step bound",
        ));
    }
    Ok(())
}

fn chars_equal(left: char, right: char, flags: RegexFlags) -> bool {
    if flags.case_insensitive {
        left.eq_ignore_ascii_case(&right)
    } else {
        left == right
    }
}

fn class_contains(value: char, ranges: &[(char, char)], negate: bool, flags: RegexFlags) -> bool {
    let found = ranges.iter().any(|(start, end)| {
        if flags.case_insensitive {
            value.eq_ignore_ascii_case(start)
                || value.eq_ignore_ascii_case(end)
                || (*start..=*end).any(|candidate| chars_equal(value, candidate, flags))
        } else {
            (*start..=*end).contains(&value)
        }
    });
    if negate { !found } else { found }
}

fn deduplicate(values: &mut Vec<usize>) {
    values.sort_unstable();
    values.dedup();
}

fn match_node(
    node: &RegexNode,
    text: &[char],
    position: usize,
    flags: RegexFlags,
    state: &mut RegexMatchState,
) -> Result<Vec<usize>, ComponentError> {
    match_step(state)?;
    match node {
        RegexNode::Empty => Ok(vec![position]),
        RegexNode::Literal(value) => Ok(text
            .get(position)
            .is_some_and(|candidate| chars_equal(*candidate, *value, flags))
            .then_some(position + 1)
            .into_iter()
            .collect()),
        RegexNode::Any => Ok(text
            .get(position)
            .is_some_and(|candidate| flags.dot_matches_newline || *candidate != '\n')
            .then_some(position + 1)
            .into_iter()
            .collect()),
        RegexNode::Class { ranges, negate } => Ok(text
            .get(position)
            .is_some_and(|candidate| class_contains(*candidate, ranges, *negate, flags))
            .then_some(position + 1)
            .into_iter()
            .collect()),
        RegexNode::AnchorStart => Ok((position == 0
            || (flags.multiline && position > 0 && text[position - 1] == '\n'))
            .then_some(position)
            .into_iter()
            .collect()),
        RegexNode::AnchorEnd => Ok((position == text.len()
            || (flags.multiline && text.get(position) == Some(&'\n')))
        .then_some(position)
        .into_iter()
        .collect()),
        RegexNode::Sequence(nodes) => {
            let mut positions = vec![position];
            for node in nodes {
                let mut next = Vec::new();
                for position in positions {
                    next.extend(match_node(node, text, position, flags, state)?);
                }
                deduplicate(&mut next);
                positions = next;
                if positions.is_empty() {
                    break;
                }
            }
            Ok(positions)
        }
        RegexNode::Alternation(nodes) => {
            let mut positions = Vec::new();
            for node in nodes {
                positions.extend(match_node(node, text, position, flags, state)?);
            }
            deduplicate(&mut positions);
            Ok(positions)
        }
        RegexNode::Repeat { node, min, max } => {
            let maximum = max.unwrap_or(text.len().saturating_add(1));
            let mut frontier = vec![position];
            let mut results = if *min == 0 {
                frontier.clone()
            } else {
                Vec::new()
            };
            for count in 1..=maximum {
                let mut next = Vec::new();
                for position in frontier {
                    next.extend(match_node(node, text, position, flags, state)?);
                }
                deduplicate(&mut next);
                if next.is_empty() {
                    break;
                }
                if count >= *min {
                    results.extend(next.iter().copied());
                }
                let made_progress = next.iter().any(|value| *value != position);
                frontier = next;
                if !made_progress {
                    break;
                }
            }
            deduplicate(&mut results);
            Ok(results)
        }
    }
}

/// Native implementation of JMeter's Duration Assertion.
#[derive(Clone, Debug)]
pub struct DurationAssertion {
    name: String,
    allowed_millis: Result<i64, String>,
    limits: AssertionLimits,
}

impl DurationAssertion {
    /// Creates a duration assertion from an integer threshold in milliseconds.
    #[must_use]
    pub fn new(name: impl Into<String>, allowed_millis: i64) -> Self {
        Self {
            name: name.into(),
            allowed_millis: Ok(allowed_millis),
            limits: AssertionLimits::default(),
        }
    }

    /// Creates a duration assertion from JMeter's string property.
    #[must_use]
    pub fn from_wire(name: impl Into<String>, value: impl Into<String>) -> Self {
        let value = value.into();
        let allowed_millis = value
            .parse::<i64>()
            .map_err(|_| number_format_error(&value));
        Self {
            name: name.into(),
            allowed_millis,
            limits: AssertionLimits::default(),
        }
    }

    /// Alias for [`DurationAssertion::from_wire`] used by JMX adapters.
    #[must_use]
    pub fn from_jmx(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self::from_wire(name, value)
    }

    /// Replaces assertion resource limits.
    #[must_use]
    pub const fn with_limits(mut self, limits: AssertionLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Returns the neutral assertion name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the configured duration when it was numeric.
    #[must_use]
    pub const fn allowed_millis(&self) -> Option<i64> {
        match self.allowed_millis {
            Ok(value) => Some(value),
            Err(_) => None,
        }
    }
}

impl Assertion for DurationAssertion {
    fn evaluate<'a>(
        &'a self,
        context: &'a mut SampleContext<'_>,
    ) -> ComponentFuture<'a, AssertionResult> {
        Box::pin(async move {
            let allowed = match &self.allowed_millis {
                Ok(value) => *value,
                Err(message) => return Ok(bounded_jmeter_error(message, self.limits)),
            };
            let Some(result) = context.result() else {
                return Ok(bounded_error(
                    &self.name,
                    "duration assertion received no sample result",
                    self.limits,
                ));
            };
            let elapsed = result.elapsed().map(|value| value.as_millis()).unwrap_or(0);
            // JMeter treats non-positive configured values as the disabled
            // boundary.  The GUI asks for positive values, but malformed JMX
            // can still carry zero or negative values and must not panic.
            if allowed <= 0 || elapsed <= allowed as u64 {
                return Ok(AssertionResult::passed(self.name.clone()));
            }
            Ok(bounded_failure(
                &self.name,
                format!(
                    "The operation lasted too long: It took {elapsed} milliseconds, but should not have lasted longer than {allowed} milliseconds."
                ),
                self.limits,
            ))
        })
    }
}

/// Size field used by JMeter's Size Assertion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SizeField {
    /// Response body byte count.
    ResponseBody,
    /// Response-header block byte count.
    ResponseHeaders,
    /// Response-code string size.
    ResponseCode,
    /// Response-message string size.
    ResponseMessage,
    /// Network byte count reported by the sampler.
    Network,
    /// Byte length of a thread-local variable.
    Variable(String),
    /// An unknown wire field retained for an explicit unsupported result.
    Unknown(String),
}

impl SizeField {
    /// Decodes JMeter's `Assertion.test_field`/size field spelling.
    #[must_use]
    pub fn from_wire(value: impl Into<String>) -> Self {
        let value = value.into();
        match value.as_str() {
            "SizeAssertion.response_data" => Self::ResponseBody,
            "SizeAssertion.response_headers" => Self::ResponseHeaders,
            "SizeAssertion.response_code" => Self::ResponseCode,
            "SizeAssertion.response_message" => Self::ResponseMessage,
            "SizeAssertion.response_network_size" => Self::Network,
            value if value.starts_with("SizeAssertion.variable:") => {
                Self::Variable(value["SizeAssertion.variable:".len()..].to_owned())
            }
            _ => Self::Unknown(value),
        }
    }

    /// Returns the canonical JMeter wire spelling.
    #[must_use]
    pub fn as_wire(&self) -> String {
        match self {
            Self::ResponseBody => "SizeAssertion.response_data".to_owned(),
            Self::ResponseHeaders => "SizeAssertion.response_headers".to_owned(),
            Self::ResponseCode => "SizeAssertion.response_code".to_owned(),
            Self::ResponseMessage => "SizeAssertion.response_message".to_owned(),
            Self::Network => "SizeAssertion.response_network_size".to_owned(),
            Self::Variable(name) => format!("SizeAssertion.variable:{name}"),
            Self::Unknown(value) => value.clone(),
        }
    }
}

/// Comparison operator used by JMeter's Size Assertion.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SizeComparison {
    /// Equal to the configured size (wire value 1).
    Equal,
    /// Not equal to the configured size (wire value 2).
    NotEqual,
    /// Greater than the configured size (wire value 3).
    Greater,
    /// Less than the configured size (wire value 4).
    Less,
    /// Greater than or equal to the configured size (wire value 5).
    GreaterOrEqual,
    /// Less than or equal to the configured size (wire value 6).
    LessOrEqual,
    /// An unknown wire value retained for an explicit failure.
    Unknown(i32),
}

impl SizeComparison {
    /// Decodes the JMeter operator integer.
    #[must_use]
    pub const fn from_wire(value: i32) -> Self {
        match value {
            1 => Self::Equal,
            2 => Self::NotEqual,
            3 => Self::Greater,
            4 => Self::Less,
            5 => Self::GreaterOrEqual,
            6 => Self::LessOrEqual,
            value => Self::Unknown(value),
        }
    }

    /// Returns the JMeter operator integer.
    #[must_use]
    pub const fn as_wire(self) -> i32 {
        match self {
            Self::Equal => 1,
            Self::NotEqual => 2,
            Self::Greater => 3,
            Self::Less => 4,
            Self::GreaterOrEqual => 5,
            Self::LessOrEqual => 6,
            Self::Unknown(value) => value,
        }
    }

    fn relation(self) -> &'static str {
        match self {
            Self::Equal => "been equal to",
            Self::NotEqual => "not been equal to",
            Self::Greater => "been greater than",
            Self::Less => "been less than",
            Self::GreaterOrEqual => "been greater or equal to",
            Self::LessOrEqual => "been less than or equal to",
            Self::Unknown(_) => "ERROR - invalid condition",
        }
    }
}

/// Native implementation of JMeter's Size Assertion.
#[derive(Clone, Debug)]
pub struct SizeAssertion {
    name: String,
    field: SizeField,
    comparison: SizeComparison,
    allowed_size: Result<i64, String>,
    limits: AssertionLimits,
}

impl SizeAssertion {
    /// Creates a size assertion from neutral values.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        field: SizeField,
        comparison: SizeComparison,
        allowed_size: i64,
    ) -> Self {
        Self {
            name: name.into(),
            field,
            comparison,
            allowed_size: Ok(allowed_size),
            limits: AssertionLimits::default(),
        }
    }

    /// Creates a size assertion from JMeter wire properties.
    #[must_use]
    pub fn from_wire(
        name: impl Into<String>,
        field: impl Into<String>,
        comparison: i32,
        allowed_size: impl Into<String>,
    ) -> Self {
        let allowed_size = allowed_size.into();
        let parsed = allowed_size
            .parse::<i64>()
            .map_err(|_| number_format_error(&allowed_size));
        Self {
            name: name.into(),
            field: SizeField::from_wire(field),
            comparison: SizeComparison::from_wire(comparison),
            allowed_size: parsed,
            limits: AssertionLimits::default(),
        }
    }

    /// Alias for [`SizeAssertion::from_wire`] used by JMX adapters.
    #[must_use]
    pub fn from_jmx(
        name: impl Into<String>,
        field: impl Into<String>,
        comparison: i32,
        allowed_size: impl Into<String>,
    ) -> Self {
        Self::from_wire(name, field, comparison, allowed_size)
    }

    /// Replaces assertion resource limits.
    #[must_use]
    pub const fn with_limits(mut self, limits: AssertionLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Returns the neutral assertion name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the tested size field.
    #[must_use]
    pub const fn field(&self) -> &SizeField {
        &self.field
    }

    /// Returns the comparison operator.
    #[must_use]
    pub const fn comparison(&self) -> SizeComparison {
        self.comparison
    }

    /// Returns the numeric threshold when the wire value was valid.
    #[must_use]
    pub const fn allowed_size(&self) -> Option<i64> {
        match self.allowed_size {
            Ok(value) => Some(value),
            Err(_) => None,
        }
    }

    fn measured_size(
        &self,
        result: &SampleResult,
        limits: AssertionLimits,
    ) -> Result<i128, ComponentError> {
        let measured = match &self.field {
            SizeField::ResponseBody => result
                .effective_body_size()
                .map_err(size_result_metadata_error)?
                .map_or(0_i128, |value| i128::from(value.as_u64())),
            SizeField::ResponseHeaders => result.headers_size().map_or_else(
                || {
                    result
                        .response_headers()
                        .map_or(Ok(0_i128), |value| checked_size(value.as_str().len()))
                },
                |value| Ok(i128::from(value.as_u64())),
            )?,
            SizeField::ResponseCode => result
                .response_code()
                .map_or(Ok(0_i128), |value| checked_size(java_utf16_len(value)))?,
            SizeField::ResponseMessage => result
                .response_message()
                .map_or(Ok(0_i128), |value| checked_size(java_utf16_len(value)))?,
            SizeField::Network => result
                .effective_received_bytes()
                .map_err(size_result_metadata_error)?
                .map_or(0_i128, |value| i128::from(value.as_u64())),
            SizeField::Variable(_) => {
                return Err(ComponentError::failure(
                    "size assertion variable must be parsed before measuring",
                ));
            }
            SizeField::Unknown(value) => {
                return Err(bounded_unsupported(format!(
                    "size assertion field {value:?} is not supported"
                )));
            }
        };
        let maximum = checked_size(limits.max_response_bytes)?;
        if measured > maximum {
            return Err(ComponentError::resource_limit(format!(
                "size assertion input bytes {measured} exceed {}",
                limits.max_response_bytes
            )));
        }
        Ok(measured)
    }
}

impl Assertion for SizeAssertion {
    fn evaluate<'a>(
        &'a self,
        context: &'a mut SampleContext<'_>,
    ) -> ComponentFuture<'a, AssertionResult> {
        Box::pin(async move {
            let allowed = match &self.allowed_size {
                Ok(value) => *value,
                Err(message) => return Ok(bounded_jmeter_error(message, self.limits)),
            };
            let Some(result) = context.result() else {
                return Ok(bounded_error(
                    &self.name,
                    "size assertion received no sample result",
                    self.limits,
                ));
            };
            let measured = match &self.field {
                SizeField::Variable(name) => {
                    let Some(value) = context.execution().variable(name) else {
                        return Ok(bounded_failure(
                            &self.name,
                            format!("Error parsing variable name: {name} value: null"),
                            self.limits,
                        ));
                    };
                    if value.len() > self.limits.max_response_bytes {
                        return Err(ComponentError::resource_limit(format!(
                            "size assertion variable bytes {} exceed {}",
                            value.len(),
                            self.limits.max_response_bytes
                        )));
                    }
                    match value.parse::<i64>() {
                        Ok(value) => i128::from(value),
                        Err(_) => {
                            return Ok(bounded_failure(
                                &self.name,
                                format!("Error parsing variable name: {name} value: {value}"),
                                self.limits,
                            ));
                        }
                    }
                }
                _ => self.measured_size(result, self.limits)?,
            };
            let allowed = i128::from(allowed);
            let matches = match self.comparison {
                SizeComparison::Equal => measured == allowed,
                SizeComparison::NotEqual => measured != allowed,
                SizeComparison::Greater => measured > allowed,
                SizeComparison::Less => measured < allowed,
                SizeComparison::GreaterOrEqual => measured >= allowed,
                SizeComparison::LessOrEqual => measured <= allowed,
                SizeComparison::Unknown(_) => false,
            };
            if matches {
                return Ok(AssertionResult::passed(self.name.clone()));
            }
            Ok(bounded_failure(
                &self.name,
                format!(
                    "The result was the wrong size: It was {measured} bytes, but should have {} {allowed} bytes.",
                    self.comparison.relation()
                ),
                self.limits,
            ))
        })
    }
}

fn java_utf16_len(value: &str) -> usize {
    value.encode_utf16().count()
}

fn checked_size(value: usize) -> Result<i128, ComponentError> {
    i128::try_from(value)
        .map_err(|_| ComponentError::resource_limit("size assertion measurement overflows"))
}

fn size_result_metadata_error(error: jmeter_rs_results::ResultError) -> ComponentError {
    let message = format!(
        "size assertion result metadata error {}",
        error.stable_code()
    );
    if error.is_limit() {
        ComponentError::resource_limit(message)
    } else {
        ComponentError::failure(message)
    }
}

/// Native implementation of JMeter's MD5Hex Assertion.
#[derive(Clone, Debug)]
pub struct Md5HexAssertion {
    name: String,
    expected: String,
    limits: AssertionLimits,
}

impl Md5HexAssertion {
    /// Creates an MD5 assertion from a case-insensitive hexadecimal digest.
    #[must_use]
    pub fn new(name: impl Into<String>, expected: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            expected: expected.into(),
            limits: AssertionLimits::default(),
        }
    }

    /// Creates an MD5 assertion from JMeter's property names.
    #[must_use]
    pub fn from_wire(name: impl Into<String>, expected: impl Into<String>) -> Self {
        Self::new(name, expected)
    }

    /// Alias for [`Md5HexAssertion::from_wire`] used by JMX adapters.
    #[must_use]
    pub fn from_jmx(name: impl Into<String>, expected: impl Into<String>) -> Self {
        Self::from_wire(name, expected)
    }

    /// Replaces assertion resource limits.
    #[must_use]
    pub const fn with_limits(mut self, limits: AssertionLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Returns the neutral assertion name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the expected digest text.
    #[must_use]
    pub fn expected(&self) -> &str {
        &self.expected
    }
}

impl Assertion for Md5HexAssertion {
    fn evaluate<'a>(
        &'a self,
        context: &'a mut SampleContext<'_>,
    ) -> ComponentFuture<'a, AssertionResult> {
        Box::pin(async move {
            let Some(result) = context.result() else {
                return Ok(bounded_failure(
                    &self.name,
                    "Response was null",
                    self.limits,
                ));
            };
            let Some(data) = result.response_data() else {
                return Ok(bounded_failure(
                    &self.name,
                    "Response was null",
                    self.limits,
                ));
            };
            if data.is_empty() {
                return Ok(bounded_failure(
                    &self.name,
                    "Response was null",
                    self.limits,
                ));
            }
            if data.len() > self.limits.max_response_bytes {
                return Err(ComponentError::resource_limit(format!(
                    "MD5 response bytes {} exceed {}",
                    data.len(),
                    self.limits.max_response_bytes
                )));
            }
            if self.expected.len() > self.limits.max_pattern_bytes {
                return Err(ComponentError::resource_limit(format!(
                    "MD5 expected digest bytes {} exceed {}",
                    self.expected.len(),
                    self.limits.max_pattern_bytes
                )));
            }
            if self.expected.is_empty() {
                return Ok(bounded_failure(
                    &self.name,
                    "MD5Hex to test against is empty",
                    self.limits,
                ));
            }
            let actual = md5_hex(data.as_bytes());
            if actual.eq_ignore_ascii_case(&self.expected) {
                Ok(AssertionResult::passed(self.name.clone()))
            } else {
                Ok(bounded_failure(
                    &self.name,
                    format!(
                        "Error asserting MD5 sum : got {actual} but should have been {}",
                        self.expected
                    ),
                    self.limits,
                ))
            }
        })
    }
}

// MD5 is retained here only because JMeter exposes MD5Hex Assertion and the
// Rust standard library has no digest implementation.  This is a compact,
// bounded implementation of RFC 1321's public-domain algorithm; it is not a
// security primitive for signatures or password storage.
fn md5_hex(input: &[u8]) -> String {
    const SHIFT: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const TABLE: [u32; 64] = [
        0xd76a_a478,
        0xe8c7_b756,
        0x2420_70db,
        0xc1bd_ceee,
        0xf57c_0faf,
        0x4787_c62a,
        0xa830_4613,
        0xfd46_9501,
        0x6980_98d8,
        0x8b44_f7af,
        0xffff_5bb1,
        0x895c_d7be,
        0x6b90_1122,
        0xfd98_7193,
        0xa679_438e,
        0x49b4_0821,
        0xf61e_2562,
        0xc040_b340,
        0x265e_5a51,
        0xe9b6_c7aa,
        0xd62f_105d,
        0x0244_1453,
        0xd8a1_e681,
        0xe7d3_fbc8,
        0x21e1_cde6,
        0xc337_07d6,
        0xf4d5_0d87,
        0x455a_14ed,
        0xa9e3_e905,
        0xfcef_a3f8,
        0x676f_02d9,
        0x8d2a_4c8a,
        0xfffa_3942,
        0x8771_f681,
        0x6d9d_6122,
        0xfde5_380c,
        0xa4be_ea44,
        0x4bde_cfa9,
        0xf6bb_4b60,
        0xbebf_bc70,
        0x289b_7ec6,
        0xeaa1_27fa,
        0xd4ef_3085,
        0x0488_1d05,
        0xd9d4_d039,
        0xe6db_99e5,
        0x1fa2_7cf8,
        0xc4ac_5665,
        0xf429_2244,
        0x432a_ff97,
        0xab94_23a7,
        0xfc93_a039,
        0x655b_59c3,
        0x8f0c_cc92,
        0xffef_f47d,
        0x8584_5dd1,
        0x6fa8_7e4f,
        0xfe2c_e6e0,
        0xa301_4314,
        0x4e08_11a1,
        0xf753_7e82,
        0xbd3a_f235,
        0x2ad7_d2bb,
        0xeb86_d391,
    ];
    let bit_len = (input.len() as u128).saturating_mul(8);
    let padded_len = input.len().saturating_add(1).saturating_add(8);
    let blocks = padded_len.saturating_add(63) / 64;
    let total_len = blocks.saturating_mul(64);
    let mut message = Vec::with_capacity(total_len);
    message.extend_from_slice(input);
    message.push(0x80);
    message.resize(total_len, 0);
    let bit_len = bit_len as u64;
    message[total_len - 8..].copy_from_slice(&bit_len.to_le_bytes());

    let mut a0 = 0x6745_2301_u32;
    let mut b0 = 0xefcd_ab89_u32;
    let mut c0 = 0x98ba_dcfe_u32;
    let mut d0 = 0x1032_5476_u32;
    for block in message.chunks_exact(64) {
        let mut words = [0_u32; 16];
        for (index, word) in words.iter_mut().enumerate() {
            let offset = index * 4;
            *word = u32::from_le_bytes([
                block[offset],
                block[offset + 1],
                block[offset + 2],
                block[offset + 3],
            ]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for index in 0..64 {
            let (function, word_index) = match index {
                0..=15 => ((b & c) | ((!b) & d), index),
                16..=31 => ((d & b) | ((!d) & c), (5 * index + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * index + 5) % 16),
                _ => (c ^ (b | !d), (7 * index) % 16),
            };
            let next = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                a.wrapping_add(function)
                    .wrapping_add(TABLE[index])
                    .wrapping_add(words[word_index])
                    .rotate_left(SHIFT[index]),
            );
            a = next;
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut output = String::with_capacity(32);
    for value in [a0, b0, c0, d0] {
        for byte in value.to_le_bytes() {
            output.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
            output.push(char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]));
        }
    }
    output
}

#[derive(Clone, Debug)]
struct XmlNode {
    name: String,
    attributes: Vec<(String, String)>,
    children: Vec<XmlNode>,
    text: String,
}

#[derive(Clone, Debug)]
struct XmlDocument {
    root: XmlNode,
}

#[derive(Debug)]
enum XmlParseError {
    Invalid(String),
    Unsupported(String),
    Limit(ComponentError),
}

struct XmlParser<'a> {
    input: &'a [u8],
    offset: usize,
    limits: AssertionLimits,
    nodes: usize,
}

impl<'a> XmlParser<'a> {
    fn new(input: &'a [u8], limits: AssertionLimits) -> Self {
        Self {
            input,
            offset: 0,
            limits,
            nodes: 0,
        }
    }

    fn parse(mut self) -> Result<XmlDocument, XmlParseError> {
        if self.input.starts_with(&[0xef, 0xbb, 0xbf]) {
            self.offset = 3;
        }
        self.skip_space();
        loop {
            if self
                .input
                .get(self.offset..)
                .is_some_and(|value| value.starts_with(b"<?"))
            {
                self.skip_processing_instruction()?;
                self.skip_space();
                continue;
            }
            if self
                .input
                .get(self.offset..)
                .is_some_and(|value| value.starts_with(b"<!--"))
            {
                self.skip_comment()?;
                self.skip_space();
                continue;
            }
            break;
        }
        if self
            .input
            .get(self.offset..)
            .is_some_and(|value| value.starts_with(b"<!DOCTYPE"))
        {
            return Err(XmlParseError::Unsupported(
                "XML external/internal DTD processing is unavailable".to_owned(),
            ));
        }
        let root = self.parse_element(1)?;
        self.skip_space();
        while self.offset < self.input.len() {
            if self.input[self.offset..].starts_with(b"<!--") {
                self.skip_comment()?;
            } else if self.input[self.offset..].starts_with(b"<?") {
                self.skip_processing_instruction()?;
            } else {
                return Err(XmlParseError::Invalid(
                    "XML has non-whitespace data after its root element".to_owned(),
                ));
            }
            self.skip_space();
        }
        Ok(XmlDocument { root })
    }

    fn parse_element(&mut self, depth: usize) -> Result<XmlNode, XmlParseError> {
        if depth > self.limits.max_xml_depth {
            return Err(XmlParseError::Limit(ComponentError::resource_limit(
                "XML assertion nesting exceeds the configured depth bound",
            )));
        }
        if !self.consume_byte(b'<') {
            return Err(XmlParseError::Invalid(
                "XML element must start with '<'".to_owned(),
            ));
        }
        if self.peek_byte() == Some(b'/') {
            return Err(XmlParseError::Invalid(
                "unexpected XML closing tag".to_owned(),
            ));
        }
        if self.peek_byte() == Some(b'!') || self.peek_byte() == Some(b'?') {
            return Err(XmlParseError::Invalid(
                "XML declaration is not an element".to_owned(),
            ));
        }
        let name = self.parse_name()?;
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > self.limits.max_xml_nodes {
            return Err(XmlParseError::Limit(ComponentError::resource_limit(
                "XML assertion node count exceeds the configured node bound",
            )));
        }
        let mut attributes = Vec::new();
        loop {
            self.skip_space();
            if self.consume_bytes(b"/>") {
                return Ok(XmlNode {
                    name,
                    attributes,
                    children: Vec::new(),
                    text: String::new(),
                });
            }
            if self.consume_byte(b'>') {
                break;
            }
            let attribute_name = self.parse_name()?;
            if attributes
                .iter()
                .any(|(existing, _): &(String, String)| existing == &attribute_name)
            {
                return Err(XmlParseError::Invalid(format!(
                    "XML element {name:?} repeats attribute {attribute_name:?}"
                )));
            }
            self.skip_space();
            if !self.consume_byte(b'=') {
                return Err(XmlParseError::Invalid(
                    "XML attribute is missing '='".to_owned(),
                ));
            }
            self.skip_space();
            let quote = self.peek_byte().ok_or_else(|| {
                XmlParseError::Invalid("XML attribute has no quoted value".to_owned())
            })?;
            if quote != b'\'' && quote != b'"' {
                return Err(XmlParseError::Invalid(
                    "XML attribute value must be quoted".to_owned(),
                ));
            }
            self.offset += 1;
            let start = self.offset;
            while self.offset < self.input.len() && self.input[self.offset] != quote {
                if self.input[self.offset] == b'<' {
                    return Err(XmlParseError::Invalid(
                        "XML attribute contains an unescaped '<'".to_owned(),
                    ));
                }
                self.offset += 1;
            }
            if self.offset >= self.input.len() {
                return Err(XmlParseError::Invalid(
                    "XML attribute quote is not closed".to_owned(),
                ));
            }
            let value = decode_xml_entities(&self.input[start..self.offset])?;
            self.offset += 1;
            attributes.push((attribute_name, value));
        }
        let mut children = Vec::new();
        let mut text = String::new();
        loop {
            if self.offset >= self.input.len() {
                return Err(XmlParseError::Invalid(format!(
                    "XML element {name:?} is not closed"
                )));
            }
            if self.input[self.offset..].starts_with(b"</") {
                self.offset += 2;
                let closing = self.parse_name()?;
                self.skip_space();
                if !self.consume_byte(b'>') {
                    return Err(XmlParseError::Invalid(
                        "XML closing tag is missing '>'".to_owned(),
                    ));
                }
                if closing != name {
                    return Err(XmlParseError::Invalid(format!(
                        "XML closing tag {closing:?} does not match {name:?}"
                    )));
                }
                return Ok(XmlNode {
                    name,
                    attributes,
                    children,
                    text,
                });
            }
            if self.input[self.offset..].starts_with(b"<!--") {
                self.skip_comment()?;
                continue;
            }
            if self.input[self.offset..].starts_with(b"<?") {
                self.skip_processing_instruction()?;
                continue;
            }
            if self.input[self.offset..].starts_with(b"<![CDATA[") {
                self.offset += b"<![CDATA[".len();
                let start = self.offset;
                let Some(end) = find_bytes(&self.input[self.offset..], b"]]>") else {
                    return Err(XmlParseError::Invalid(
                        "XML CDATA section is not closed".to_owned(),
                    ));
                };
                let end = self.offset + end;
                text.push_str(
                    std::str::from_utf8(&self.input[start..end])
                        .map_err(|_| XmlParseError::Invalid("XML CDATA is not UTF-8".to_owned()))?,
                );
                validate_xml_chars(&text)?;
                self.offset = end + 3;
                continue;
            }
            if self.peek_byte() == Some(b'<') {
                children.push(self.parse_element(depth.saturating_add(1))?);
                continue;
            }
            let start = self.offset;
            while self.offset < self.input.len() && self.input[self.offset] != b'<' {
                self.offset += 1;
            }
            text.push_str(&decode_xml_entities(&self.input[start..self.offset])?);
        }
    }

    fn parse_name(&mut self) -> Result<String, XmlParseError> {
        let start = self.offset;
        while let Some(value) = self.input.get(self.offset).copied() {
            if is_xml_name_byte(value) {
                self.offset += 1;
            } else {
                break;
            }
        }
        if self.offset == start {
            return Err(XmlParseError::Invalid(
                "XML name is empty or invalid".to_owned(),
            ));
        }
        let value = std::str::from_utf8(&self.input[start..self.offset])
            .map_err(|_| XmlParseError::Invalid("XML name is not UTF-8".to_owned()))?;
        if !value
            .as_bytes()
            .first()
            .is_some_and(|value| value.is_ascii_alphabetic() || *value == b'_' || *value == b':')
        {
            return Err(XmlParseError::Invalid(format!(
                "XML name {value:?} is invalid"
            )));
        }
        Ok(value.to_owned())
    }

    fn skip_comment(&mut self) -> Result<(), XmlParseError> {
        if !self.consume_bytes(b"<!--") {
            return Err(XmlParseError::Invalid("invalid XML comment".to_owned()));
        }
        let Some(end) = find_bytes(&self.input[self.offset..], b"-->") else {
            return Err(XmlParseError::Invalid(
                "XML comment is not closed".to_owned(),
            ));
        };
        if find_bytes(&self.input[self.offset..self.offset + end], b"--").is_some() {
            return Err(XmlParseError::Invalid(
                "XML comment contains the forbidden '--' sequence".to_owned(),
            ));
        }
        self.offset += end + 3;
        Ok(())
    }

    fn skip_processing_instruction(&mut self) -> Result<(), XmlParseError> {
        if !self.consume_bytes(b"<?") {
            return Err(XmlParseError::Invalid(
                "invalid XML processing instruction".to_owned(),
            ));
        }
        let Some(end) = find_bytes(&self.input[self.offset..], b"?>") else {
            return Err(XmlParseError::Invalid(
                "XML processing instruction is not closed".to_owned(),
            ));
        };
        self.offset += end + 2;
        Ok(())
    }

    fn skip_space(&mut self) {
        while self
            .input
            .get(self.offset)
            .is_some_and(|value| matches!(value, b' ' | b'\t' | b'\r' | b'\n'))
        {
            self.offset += 1;
        }
    }

    fn peek_byte(&self) -> Option<u8> {
        self.input.get(self.offset).copied()
    }

    fn consume_byte(&mut self, value: u8) -> bool {
        if self.peek_byte() == Some(value) {
            self.offset += 1;
            true
        } else {
            false
        }
    }

    fn consume_bytes(&mut self, value: &[u8]) -> bool {
        if self
            .input
            .get(self.offset..)
            .is_some_and(|input| input.starts_with(value))
        {
            self.offset += value.len();
            true
        } else {
            false
        }
    }
}

fn find_bytes(input: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    input
        .windows(needle.len())
        .position(|window| window == needle)
}

fn is_xml_name_byte(value: u8) -> bool {
    value.is_ascii_alphanumeric() || matches!(value, b'_' | b':' | b'-' | b'.')
}

fn decode_xml_entities(value: &[u8]) -> Result<String, XmlParseError> {
    let mut output = String::new();
    let mut offset = 0;
    while offset < value.len() {
        if value[offset] != b'&' {
            let start = offset;
            while offset < value.len() && value[offset] != b'&' {
                offset += 1;
            }
            output.push_str(
                std::str::from_utf8(&value[start..offset])
                    .map_err(|_| XmlParseError::Invalid("XML text is not UTF-8".to_owned()))?,
            );
            continue;
        }
        let start = offset + 1;
        let Some(end_offset) = value[start..].iter().position(|value| *value == b';') else {
            return Err(XmlParseError::Invalid(
                "XML entity is missing ';'".to_owned(),
            ));
        };
        let end = start + end_offset;
        let entity = std::str::from_utf8(&value[start..end])
            .map_err(|_| XmlParseError::Invalid("XML entity is not UTF-8".to_owned()))?;
        let decoded = match entity {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            value if value.starts_with("#x") || value.starts_with("#X") => {
                let number = u32::from_str_radix(&value[2..], 16).map_err(|_| {
                    XmlParseError::Invalid("XML hexadecimal entity is invalid".to_owned())
                })?;
                char::from_u32(number).ok_or_else(|| {
                    XmlParseError::Invalid("XML entity is not a Unicode scalar".to_owned())
                })?
            }
            value if value.starts_with('#') => {
                let number = value[1..].parse::<u32>().map_err(|_| {
                    XmlParseError::Invalid("XML decimal entity is invalid".to_owned())
                })?;
                char::from_u32(number).ok_or_else(|| {
                    XmlParseError::Invalid("XML entity is not a Unicode scalar".to_owned())
                })?
            }
            _ => {
                return Err(XmlParseError::Invalid(format!(
                    "XML entity &{entity}; is undefined"
                )));
            }
        };
        output.push(decoded);
        offset = end + 1;
    }
    validate_xml_chars(&output)?;
    Ok(output)
}

fn validate_xml_chars(value: &str) -> Result<(), XmlParseError> {
    if value.chars().all(|character| {
        matches!(
            character as u32,
            0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF
        )
    }) {
        Ok(())
    } else {
        Err(XmlParseError::Invalid(
            "XML text contains a forbidden control character".to_owned(),
        ))
    }
}

/// Native XML syntax assertion.  It checks well-formedness only; DTD/schema
/// validation and external entity resolution are intentionally unavailable.
#[derive(Clone, Debug)]
pub struct XmlAssertion {
    name: String,
    limits: AssertionLimits,
}

impl XmlAssertion {
    /// Creates a syntax-only XML assertion.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            limits: AssertionLimits::default(),
        }
    }

    /// Alias used by callers matching JMeter's class spelling.
    #[must_use]
    pub fn from_wire(name: impl Into<String>) -> Self {
        Self::new(name)
    }

    /// Replaces assertion resource limits.
    #[must_use]
    pub const fn with_limits(mut self, limits: AssertionLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Returns the neutral assertion name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Assertion for XmlAssertion {
    fn evaluate<'a>(
        &'a self,
        context: &'a mut SampleContext<'_>,
    ) -> ComponentFuture<'a, AssertionResult> {
        Box::pin(async move {
            let Some(result) = context.result() else {
                return Ok(bounded_failure(
                    &self.name,
                    "Response was null",
                    self.limits,
                ));
            };
            let Some(data) = result.response_data() else {
                return Ok(bounded_failure(
                    &self.name,
                    "Response was null",
                    self.limits,
                ));
            };
            if data.len() > self.limits.max_response_bytes {
                return Err(ComponentError::resource_limit(format!(
                    "XML response bytes {} exceed {}",
                    data.len(),
                    self.limits.max_response_bytes
                )));
            }
            if data.is_empty() {
                return Ok(bounded_failure(
                    &self.name,
                    "Response was null",
                    self.limits,
                ));
            }
            let decoded = decode_response_bytes(result, data.as_bytes())?;
            match XmlParser::new(decoded.as_bytes(), self.limits).parse() {
                Ok(_) => Ok(AssertionResult::passed(self.name.clone())),
                Err(XmlParseError::Invalid(message)) => {
                    Ok(bounded_failure_and_error(&self.name, message, self.limits))
                }
                Err(XmlParseError::Unsupported(message)) => Err(bounded_unsupported(message)),
                Err(XmlParseError::Limit(error)) => Err(error),
            }
        })
    }
}

/// Alias retaining the upstream all-caps acronym spelling.
#[allow(clippy::upper_case_acronyms)]
pub type XMLAssertion = XmlAssertion;

/// Alias retaining the upstream all-caps acronym spelling.
#[allow(clippy::upper_case_acronyms)]
pub type MD5HexAssertion = Md5HexAssertion;

/// XML parsing options for the native XPath assertion boundary.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XPathOptions {
    /// Whether a tolerant HTML/Tidy parser is requested.
    pub tolerant: bool,
    /// Whether DTD/schema validation is requested.
    pub validate: bool,
    /// Whether namespace-aware matching is requested.
    pub namespace: bool,
    /// Whether element whitespace should be ignored.
    pub whitespace: bool,
    /// Whether external DTDs should be fetched.
    pub download_dtds: bool,
    /// Whether parser warnings should be quiet.
    pub quiet: bool,
    /// Whether parser warnings should be reported.
    pub show_warnings: bool,
    /// Whether parser errors should be reported.
    pub report_errors: bool,
}

/// Native, bounded subset of JMeter's XPath Assertion.
#[derive(Clone, Debug)]
pub struct XPathAssertion {
    name: String,
    expression: String,
    negate: bool,
    options: XPathOptions,
    limits: AssertionLimits,
}

impl XPathAssertion {
    /// Creates an XPath assertion.  `/`, child/descendant paths, simple
    /// attribute/text predicates, `boolean(path)`, and `count(path)=N` are
    /// supported.
    #[must_use]
    pub fn new(name: impl Into<String>, expression: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            expression: expression.into(),
            negate: false,
            options: XPathOptions::default(),
            limits: AssertionLimits::default(),
        }
    }

    /// Alias used by callers matching JMeter's property terminology.
    #[must_use]
    pub fn from_wire(name: impl Into<String>, expression: impl Into<String>) -> Self {
        Self::new(name, expression)
    }

    /// Replaces assertion resource limits.
    #[must_use]
    pub const fn with_limits(mut self, limits: AssertionLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Sets JMeter's XPath negation flag.
    #[must_use]
    pub const fn with_negate(mut self, value: bool) -> Self {
        self.negate = value;
        self
    }

    /// Sets parser options.  Unsupported effectful options fail explicitly at
    /// evaluation instead of silently selecting a different XML parser.
    #[must_use]
    pub const fn with_options(mut self, value: XPathOptions) -> Self {
        self.options = value;
        self
    }

    /// Returns the neutral assertion name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the XPath expression.
    #[must_use]
    pub fn expression(&self) -> &str {
        &self.expression
    }

    /// Returns whether XPath result is inverted.
    #[must_use]
    pub const fn is_negated(&self) -> bool {
        self.negate
    }

    /// Returns parser options.
    #[must_use]
    pub const fn options(&self) -> XPathOptions {
        self.options
    }
}

impl Assertion for XPathAssertion {
    fn evaluate<'a>(
        &'a self,
        context: &'a mut SampleContext<'_>,
    ) -> ComponentFuture<'a, AssertionResult> {
        Box::pin(async move {
            if self.expression.len() > self.limits.max_xpath_bytes {
                return Err(ComponentError::resource_limit(
                    "XPath expression exceeds the configured byte bound",
                ));
            }
            if self.options.tolerant
                || self.options.validate
                || self.options.download_dtds
                || self.options.namespace
            {
                return Err(bounded_unsupported(
                    "XPath parser option requires the pinned XML/Xalan capability",
                ));
            }
            let Some(result) = context.result() else {
                return Ok(bounded_failure(
                    &self.name,
                    "Response was null",
                    self.limits,
                ));
            };
            let Some(data) = result.response_data() else {
                return Ok(bounded_failure(
                    &self.name,
                    "Response was null",
                    self.limits,
                ));
            };
            if data.len() > self.limits.max_response_bytes {
                return Err(ComponentError::resource_limit(format!(
                    "XPath response bytes {} exceed {}",
                    data.len(),
                    self.limits.max_response_bytes
                )));
            }
            if data.is_empty() {
                return Ok(bounded_failure(
                    &self.name,
                    "Response was null",
                    self.limits,
                ));
            }
            let raw = data.as_bytes();
            let decoded = match raw {
                [0xfe, 0xff, rest @ ..] => Some(decode_utf16_bytes(rest, false)),
                [0xff, 0xfe, rest @ ..] => Some(decode_utf16_bytes(rest, true)),
                _ => None,
            };
            let input = decoded.as_deref().map_or(raw, |value| value.as_bytes());
            let document = match XmlParser::new(input, self.limits).parse() {
                Ok(document) => document,
                Err(XmlParseError::Invalid(message)) => {
                    return Ok(bounded_error(&self.name, message, self.limits));
                }
                Err(XmlParseError::Unsupported(message)) => {
                    return Err(bounded_unsupported(message));
                }
                Err(XmlParseError::Limit(error)) => return Err(error),
            };
            let match_kind =
                match evaluate_xpath_kind(&document, &self.expression, self.options.whitespace) {
                    Ok(value) => value,
                    Err(XPathError::Invalid(message)) => {
                        return Ok(bounded_error(&self.name, message, self.limits));
                    }
                    Err(XPathError::Unsupported(message)) => {
                        return Err(bounded_unsupported(message));
                    }
                };
            let (matched, message) = match match_kind {
                XPathMatchKind::Nodes(value) => {
                    let matched = if self.negate { !value } else { value };
                    let message = if value {
                        self.negate.then_some(
                            "Specified XPath was found... Turn off negate if this is not desired"
                                .to_owned(),
                        )
                    } else {
                        Some(format!("No Nodes Matched {}", self.expression))
                    };
                    (matched, message)
                }
                XPathMatchKind::Boolean(value) => {
                    let matched = if self.negate { !value } else { value };
                    let message = Some(format!(
                        "{} for {}",
                        if self.negate {
                            "Nodes Matched"
                        } else {
                            "No Nodes Matched"
                        },
                        self.expression
                    ));
                    (matched, message)
                }
            };
            if matched {
                let mut result = AssertionResult::passed(self.name.clone());
                result.set_failure_message(Some(bounded(
                    message.unwrap_or_default(),
                    self.limits.max_diagnostic_bytes,
                )));
                Ok(result)
            } else {
                Ok(bounded_failure(
                    &self.name,
                    message.unwrap_or_else(|| format!("No Nodes Matched {}", self.expression)),
                    self.limits,
                ))
            }
        })
    }
}

#[derive(Debug)]
enum XPathError {
    Invalid(String),
    Unsupported(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum XPathMatchKind {
    Nodes(bool),
    Boolean(bool),
}

impl XPathMatchKind {
    #[cfg(test)]
    const fn matched(self) -> bool {
        match self {
            Self::Nodes(value) | Self::Boolean(value) => value,
        }
    }
}

#[derive(Clone, Debug)]
struct XPathPath {
    descendant: bool,
    steps: Vec<XPathStep>,
}

#[derive(Clone, Debug)]
struct XPathStep {
    name: String,
    predicate: Option<XPathPredicate>,
}

#[derive(Clone, Debug)]
enum XPathPredicate {
    TextEquals(String),
    AttributeEquals(String, String),
}

#[cfg(test)]
fn evaluate_xpath(
    document: &XmlDocument,
    expression: &str,
    ignore_whitespace: bool,
) -> Result<bool, XPathError> {
    evaluate_xpath_kind(document, expression, ignore_whitespace).map(XPathMatchKind::matched)
}

fn evaluate_xpath_kind(
    document: &XmlDocument,
    expression: &str,
    ignore_whitespace: bool,
) -> Result<XPathMatchKind, XPathError> {
    let expression = expression.trim();
    if expression.is_empty() {
        return Err(XPathError::Invalid("XPath expression is empty".to_owned()));
    }
    if expression == "/" {
        return Ok(XPathMatchKind::Nodes(true));
    }
    if let Some(rest) = expression.strip_prefix("count(") {
        let Some((path, expected)) = rest.rsplit_once('=') else {
            return Err(XPathError::Invalid(
                "XPath count expression must have the form count(path)=N".to_owned(),
            ));
        };
        let Some(path) = path.strip_suffix(')') else {
            return Err(XPathError::Invalid(
                "XPath count expression must have the form count(path)=N".to_owned(),
            ));
        };
        let expected = expected.trim().parse::<i128>().map_err(|_| {
            XPathError::Invalid("XPath count expected value is not an integer".to_owned())
        })?;
        let path = parse_xpath_path(path.trim())?;
        return Ok(XPathMatchKind::Boolean(
            i128::try_from(select_xpath_nodes(document, &path, ignore_whitespace).len())
                .is_ok_and(|count| count == expected),
        ));
    }
    if expression.starts_with("boolean(") {
        let Some(path) = expression
            .strip_prefix("boolean(")
            .and_then(|value| value.strip_suffix(')'))
        else {
            return Err(XPathError::Invalid(
                "XPath boolean expression must have the form boolean(path)".to_owned(),
            ));
        };
        let path = parse_xpath_path(path.trim())?;
        return Ok(XPathMatchKind::Boolean(
            !select_xpath_nodes(document, &path, ignore_whitespace).is_empty(),
        ));
    }
    let path = parse_xpath_path(expression)?;
    Ok(XPathMatchKind::Nodes(
        !select_xpath_nodes(document, &path, ignore_whitespace).is_empty(),
    ))
}

fn parse_xpath_path(expression: &str) -> Result<XPathPath, XPathError> {
    let descendant = expression.starts_with("//");
    let absolute = expression.starts_with('/');
    if !absolute {
        return Err(XPathError::Unsupported(
            "XPath expressions must be absolute paths".to_owned(),
        ));
    }
    let mut value = if descendant {
        &expression[2..]
    } else {
        &expression[1..]
    };
    if value.is_empty() {
        if descendant {
            return Err(XPathError::Invalid(
                "XPath descendant path requires a step".to_owned(),
            ));
        }
        return Ok(XPathPath {
            descendant,
            steps: Vec::new(),
        });
    }
    let mut steps = Vec::new();
    while !value.is_empty() {
        let next = value.find('/').unwrap_or(value.len());
        let step = &value[..next];
        if step.is_empty() {
            return Err(XPathError::Invalid(
                "XPath path contains an empty step".to_owned(),
            ));
        }
        steps.push(parse_xpath_step(step)?);
        value = value.get(next.saturating_add(1)..).unwrap_or_default();
    }
    Ok(XPathPath { descendant, steps })
}

fn parse_xpath_step(value: &str) -> Result<XPathStep, XPathError> {
    let (name, predicate) = if let Some(start) = value.find('[') {
        if !value.ends_with(']') || value[start + 1..value.len() - 1].contains('[') {
            return Err(XPathError::Invalid(
                "XPath predicate brackets are malformed".to_owned(),
            ));
        }
        let name = &value[..start];
        let predicate = &value[start + 1..value.len() - 1];
        let predicate = if let Some(rest) = predicate.strip_prefix("text()=") {
            XPathPredicate::TextEquals(parse_xpath_string(rest)?)
        } else if let Some(rest) = predicate.strip_prefix('@') {
            let (attribute, expected) = rest.split_once('=').ok_or_else(|| {
                XPathError::Invalid("XPath attribute predicate is missing '='".to_owned())
            })?;
            if attribute.is_empty() {
                return Err(XPathError::Invalid(
                    "XPath attribute predicate name is empty".to_owned(),
                ));
            }
            XPathPredicate::AttributeEquals(attribute.to_owned(), parse_xpath_string(expected)?)
        } else {
            return Err(XPathError::Unsupported(
                "XPath predicates support only text()= and @attribute= comparisons".to_owned(),
            ));
        };
        (name, Some(predicate))
    } else {
        (value, None)
    };
    if name.is_empty() || name == "*" {
        return Err(XPathError::Unsupported(
            "XPath wildcard steps are unsupported".to_owned(),
        ));
    }
    if !name
        .bytes()
        .all(|value| is_xml_name_byte(value) || value == b':')
    {
        return Err(XPathError::Invalid(format!(
            "XPath step name {name:?} is invalid"
        )));
    }
    if name.contains(':') {
        return Err(XPathError::Unsupported(
            "XPath namespace-qualified names require namespace resolution".to_owned(),
        ));
    }
    Ok(XPathStep {
        name: name.to_owned(),
        predicate,
    })
}

fn parse_xpath_string(value: &str) -> Result<String, XPathError> {
    let value = value.trim();
    if value.len() < 2 {
        return Err(XPathError::Invalid(
            "XPath string literal is not quoted".to_owned(),
        ));
    }
    let quote = value.as_bytes()[0];
    if (quote != b'\'' && quote != b'"') || value.as_bytes().last() != Some(&quote) {
        return Err(XPathError::Invalid(
            "XPath string literal quotes are malformed".to_owned(),
        ));
    }
    Ok(value[1..value.len() - 1].to_owned())
}

fn select_xpath_nodes<'a>(
    document: &'a XmlDocument,
    path: &XPathPath,
    ignore_whitespace: bool,
) -> Vec<&'a XmlNode> {
    if path.steps.is_empty() {
        return vec![&document.root];
    }
    let mut current = if path.descendant {
        let mut nodes = Vec::new();
        if document.root.name == path.steps[0].name {
            nodes.push(&document.root);
        }
        nodes.extend(descendants_named(&document.root, &path.steps[0].name));
        nodes
    } else if document.root.name == path.steps[0].name {
        vec![&document.root]
    } else {
        Vec::new()
    };
    current.retain(|node| {
        predicate_matches(node, path.steps[0].predicate.as_ref(), ignore_whitespace)
    });
    for step in path.steps.iter().skip(1) {
        let mut next = Vec::new();
        for node in current {
            next.extend(node.children.iter().filter(|child| {
                child.name == step.name
                    && predicate_matches(child, step.predicate.as_ref(), ignore_whitespace)
            }));
        }
        current = next;
    }
    current
}

fn descendants_named<'a>(node: &'a XmlNode, name: &str) -> Vec<&'a XmlNode> {
    let mut output = Vec::new();
    for child in &node.children {
        if child.name == name {
            output.push(child);
        }
        output.extend(descendants_named(child, name));
    }
    output
}

fn predicate_matches(
    node: &XmlNode,
    predicate: Option<&XPathPredicate>,
    ignore_whitespace: bool,
) -> bool {
    match predicate {
        None => true,
        Some(XPathPredicate::TextEquals(expected)) => {
            let actual = if ignore_whitespace {
                node.text.split_whitespace().collect::<Vec<_>>().join(" ")
            } else {
                node.text.clone()
            };
            actual == *expected
        }
        Some(XPathPredicate::AttributeEquals(name, expected)) => node
            .attributes
            .iter()
            .any(|(attribute, value)| attribute == name && value == expected),
    }
}

/// Native JSON/JMESPath is intentionally a typed unsupported boundary.  The
/// profile's JMeter dependency set uses Jayway JsonPath and jmespath-core;
/// neither is in the runtime manifest and a hand-written approximation would
/// change the contract.
#[derive(Clone, Debug)]
pub struct UnsupportedJsonAssertion {
    name: String,
    capability_id: String,
}

impl UnsupportedJsonAssertion {
    /// Creates an unavailable JSON/JMESPath assertion marker.
    #[must_use]
    pub fn new(name: impl Into<String>, capability_id: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            capability_id: capability_id.into(),
        }
    }

    /// Creates a marker for JMeter's JSON Assertion.
    #[must_use]
    pub fn json(name: impl Into<String>) -> Self {
        Self::new(name, "assertion.json")
    }

    /// Creates a marker for JMeter's JSON JMESPath Assertion.
    #[must_use]
    pub fn jmespath(name: impl Into<String>) -> Self {
        Self::new(name, "assertion.jmespath")
    }

    /// Returns the neutral assertion name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the stable capability identifier.
    #[must_use]
    pub fn capability_id(&self) -> &str {
        &self.capability_id
    }
}

impl Assertion for UnsupportedJsonAssertion {
    fn evaluate<'a>(
        &'a self,
        _context: &'a mut SampleContext<'_>,
    ) -> ComponentFuture<'a, AssertionResult> {
        Box::pin(async move {
            Err(bounded_unsupported(format!(
                "assertion {:?} capability {:?} requires a pinned JSON engine",
                self.name, self.capability_id
            )))
        })
    }
}

/// A typed unavailable marker for assertion families outside the native core.
#[derive(Clone, Debug)]
pub struct UnsupportedNativeAssertion {
    name: String,
    capability_id: String,
}

impl UnsupportedNativeAssertion {
    /// Creates an unavailable assertion marker.
    #[must_use]
    pub fn new(name: impl Into<String>, capability_id: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            capability_id: capability_id.into(),
        }
    }

    /// Returns the neutral assertion name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the stable capability identifier.
    #[must_use]
    pub fn capability_id(&self) -> &str {
        &self.capability_id
    }
}

impl Assertion for UnsupportedNativeAssertion {
    fn evaluate<'a>(
        &'a self,
        _context: &'a mut SampleContext<'_>,
    ) -> ComponentFuture<'a, AssertionResult> {
        Box::pin(async move {
            Err(bounded_unsupported(format!(
                "assertion {:?} requires capability {:?}",
                self.name, self.capability_id
            )))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_wire_flags_and_modes_are_decoded_without_loss() {
        let assertion = ResponseAssertion::from_wire(
            "response",
            "Assertion.response_code",
            0x02 | 0x04 | 0x20,
            ["200", "201"],
            false,
            None,
        )
        .unwrap_or_else(|error| panic!("assertion config: {error}"));
        assert_eq!(assertion.mode(), ResponsePatternMode::Contains);
        assert!(assertion.is_negated());
        assert!(assertion.is_or());
        assert_eq!(assertion.test_type(), 0x26);
        assert_eq!(
            ResponseField::from_wire("Assertion.response_code").as_wire(),
            "Assertion.response_code"
        );
    }

    #[test]
    fn regex_subset_supports_contains_matches_classes_and_limits() {
        let limits = AssertionLimits::default().with_regex_step_limit(1_000);
        let contains = RegexProgram::compile(r"^item-\d+$", limits)
            .unwrap_or_else(|_| panic!("regex should compile"));
        assert!(contains.is_match("item-42", true).is_ok_and(|value| value));
        assert!(!contains.is_match("xitem-42", true).is_ok_and(|value| value));
        let alternation = RegexProgram::compile("foo|bar", limits)
            .unwrap_or_else(|_| panic!("regex should compile"));
        assert!(
            alternation
                .is_match("xxbarxx", false)
                .is_ok_and(|value| value)
        );
        let unsupported = RegexProgram::compile("(?=x)", limits);
        assert!(matches!(
            unsupported,
            Err(PatternCheckError::Unsupported(_))
        ));
        let bounded = RegexProgram::compile("a*", limits.with_regex_step_limit(2));
        let bounded = bounded.unwrap_or_else(|_| panic!("regex should compile"));
        assert!(matches!(
            bounded.is_match("aaaa", false),
            Err(ComponentError::ResourceLimit(_))
        ));
    }

    #[test]
    fn response_diagnostics_use_jmeter_equals_diff_and_or_shape() {
        assert_eq!(
            equals_comparison_text("abc", "axc"),
            "\n\n****** received  : a[[[b]]]c\n\n****** comparison: a[[[x]]]c\n\n"
        );
        let assertion = ResponseAssertion::single(
            "equals",
            ResponseField::ResponseData,
            ResponsePatternMode::Equals,
            "axc",
        );
        assert_eq!(
            assertion.default_failure_message("axc", "abc"),
            "Test failed: text expected to equal /\n\n****** received  : a[[[b]]]c\n\n****** comparison: a[[[x]]]c\n\n/"
        );
        let or = assertion.with_or(true);
        assert!(
            or.default_failure_message("axc", "abc")
                .contains("expected something using /\n\n****** received")
        );
    }

    #[test]
    fn response_decoding_honors_explicit_charset_without_host_state() {
        let mut result = SampleResult::new("encoding");
        result.set_response_data_bytes(vec![0xe9]);
        result.set_data_encoding_name("ISO-8859-1");
        assert_eq!(
            sample_text(&result, &ResponseField::ResponseData)
                .unwrap_or_else(|error| panic!("encoding: {error}")),
            Some("é".to_owned())
        );

        let mut utf16 = SampleResult::new("utf16");
        utf16.set_response_data_bytes(vec![0xff, 0xfe, b'A', 0]);
        utf16.set_data_encoding_name("UTF-16");
        assert_eq!(
            sample_text(&utf16, &ResponseField::ResponseData)
                .unwrap_or_else(|error| panic!("encoding: {error}")),
            Some("A".to_owned())
        );
    }

    #[test]
    fn malformed_oro_class_and_numeric_errors_keep_wire_shape() {
        let error = match RegexProgram::compile("[", AssertionLimits::default()) {
            Err(error) => error,
            Ok(_) => panic!("unmatched class should be malformed"),
        };
        assert!(matches!(
            error,
            PatternCheckError::Malformed(message)
                if message == "Bad test configuration org.apache.oro.text.MalformedCachePatternException: Invalid expression: [ Unmatched [] in expression."
        ));
        assert_eq!(
            number_format_error("not-a-number"),
            "java.lang.NumberFormatException: For input string: \"not-a-number\""
        );
        assert_eq!(
            DurationAssertion::from_wire("duration", "not-a-duration").allowed_millis(),
            None
        );
        assert_eq!(
            SizeAssertion::from_wire("size", "SizeAssertion.response_data", 1, "not-a-size")
                .allowed_size(),
            None
        );
    }

    #[test]
    fn xpath_result_messages_distinguish_nodes_and_boolean_values() {
        let document = XmlParser::new(br#"<root><item/></root>"#, AssertionLimits::default())
            .parse()
            .unwrap_or_else(|_| panic!("XML should parse"));
        assert!(matches!(
            evaluate_xpath_kind(&document, "/root/missing", false),
            Ok(XPathMatchKind::Nodes(false))
        ));
        assert!(matches!(
            evaluate_xpath_kind(&document, "count(//item)=1", false),
            Ok(XPathMatchKind::Boolean(true))
        ));
        assert!(matches!(
            evaluate_xpath_kind(&document, "boolean(//item)", false),
            Ok(XPathMatchKind::Boolean(true))
        ));
        assert!(matches!(
            evaluate_xpath_kind(&document, "count(//item)=-1", false),
            Ok(XPathMatchKind::Boolean(false))
        ));
    }

    #[test]
    fn md5_xml_and_xpath_helpers_are_bounded_and_deterministic() {
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");

        let limits = AssertionLimits::default();
        let document = XmlParser::new(
            br#"<!-- before --><root><item id="x">value</item></root><!-- after -->"#,
            limits,
        )
        .parse()
        .unwrap_or_else(|_| panic!("XML should parse"));
        assert!(
            evaluate_xpath(&document, "//item[@id='x']", false)
                .unwrap_or_else(|_| panic!("XPath should parse"))
        );
        assert!(
            evaluate_xpath(&document, "count(//item)=1", false)
                .unwrap_or_else(|_| panic!("XPath should parse"))
        );

        let too_deep = AssertionLimits::default().with_xml_depth_limit(1);
        let error = XmlParser::new(br#"<root><child/></root>"#, too_deep).parse();
        assert!(matches!(error, Err(XmlParseError::Limit(_))));
        let too_many = AssertionLimits::default().with_xml_node_limit(1);
        let error = XmlParser::new(br#"<root><child/></root>"#, too_many).parse();
        assert!(matches!(error, Err(XmlParseError::Limit(_))));
    }

    #[test]
    fn json_boundary_is_typed_unsupported() {
        let assertion = UnsupportedJsonAssertion::json("json");
        assert_eq!(assertion.capability_id, "assertion.json");
    }
}
