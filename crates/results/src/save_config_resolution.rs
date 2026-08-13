// SPDX-License-Identifier: Apache-2.0
//! Bounded save-configuration provenance and precedence resolution.
//!
//! This module is deliberately independent from the CSV/XML codecs.  It keeps
//! the sources and operations that produced a save setting, applies only an
//! explicitly supplied precedence table, and never fills a missing setting
//! from a Rust or codec default.  The model is suitable for a later runtime or
//! application adapter to turn into [`crate::SampleSaveConfiguration`].

use core::fmt;
use std::collections::BTreeMap;

/// Hard upper bound for save-configuration fields retained by one resolver.
pub const MAX_SAVE_CONFIG_FIELDS: usize = 256;
/// Hard upper bound for operations retained for one field.
pub const MAX_SAVE_CONFIG_OPERATIONS_PER_FIELD: usize = 1024;
/// Hard upper bound for operations retained by one resolver.
pub const MAX_SAVE_CONFIG_OPERATIONS: usize = 8192;
/// Hard upper bound for ambiguity candidates retained by one error.
pub const MAX_SAVE_CONFIG_CANDIDATES: usize = 32;
/// Hard upper bound for one property name or Java value.
pub const MAX_SAVE_CONFIG_TEXT_BYTES: usize = 64 * 1024;
/// Hard upper bound for all Java-value bytes retained by one resolver.
pub const MAX_SAVE_CONFIG_TOTAL_VALUE_BYTES: usize = 4 * 1024 * 1024;
/// Hard upper bound for one canonical serialized resolution.
pub const MAX_SAVE_CONFIG_CANONICAL_BYTES: usize = 16 * 1024 * 1024;

const PRECEDENCE_SOURCE_COUNT: usize = 5;
const CANONICAL_VERSION: &[u8] = b"save-config-resolution/3";

/// A stable machine-readable save-configuration error category.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SaveConfigErrorCode {
    /// The supplied limits, field, source, or operation is invalid.
    InvalidConfiguration,
    /// An explicit resource bound was exceeded.
    Limit,
    /// More than one interpretation remains possible.
    Ambiguous,
    /// A source was not present in the supplied precedence table.
    MissingPrecedence,
    /// An unknown property was retained without a typed interpretation.
    Unresolved,
    /// A value does not have the Java type required by a known field.
    InvalidValue,
    /// Canonical serialization exceeded its explicit bound.
    Canonicalization,
}

impl SaveConfigErrorCode {
    /// Returns the stable machine-readable error code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidConfiguration => "save-config.invalid_configuration",
            Self::Limit => "save-config.limit",
            Self::Ambiguous => "save-config.ambiguous",
            Self::MissingPrecedence => "save-config.precedence_missing",
            Self::Unresolved => "save-config.unresolved",
            Self::InvalidValue => "save-config.invalid_value",
            Self::Canonicalization => "save-config.canonicalization",
        }
    }
}

impl fmt::Display for SaveConfigErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The bounded collection involved in a limit failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SaveConfigLimitKind {
    /// Number of distinct fields.
    Fields,
    /// Operations for one field.
    OperationsPerField,
    /// Operations for the complete resolver.
    Operations,
    /// Ambiguity candidates.
    Candidates,
    /// One field/property/value text length.
    TextBytes,
    /// Aggregate Java-value bytes.
    TotalValueBytes,
    /// Canonical serialized bytes.
    CanonicalBytes,
}

impl fmt::Display for SaveConfigLimitKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Fields => "fields",
            Self::OperationsPerField => "operations_per_field",
            Self::Operations => "operations",
            Self::Candidates => "candidates",
            Self::TextBytes => "text_bytes",
            Self::TotalValueBytes => "total_value_bytes",
            Self::CanonicalBytes => "canonical_bytes",
        };
        formatter.write_str(name)
    }
}

/// Why a source or precedence table was rejected.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SaveConfigConfigurationKind {
    /// A required collection was empty.
    Empty,
    /// A source was listed more than once.
    DuplicateSource,
    /// A source identity was invalid.
    InvalidSource,
    /// A field/property name exceeded the hard bound or was empty.
    InvalidName,
    /// A profile identity exceeded the hard bound or was empty.
    InvalidProfile,
    /// A precedence table exceeded the fixed source-category bound.
    TooManySources,
}

/// A stable error returned by the provenance model.
#[derive(Clone, Eq, Hash, PartialEq)]
pub enum SaveConfigError {
    /// A configured limit is zero or exceeds the hard bound.
    InvalidLimit {
        /// Which limit was invalid.
        kind: SaveConfigLimitKind,
        /// Supplied value.
        actual: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// A precedence table or source identity is malformed.
    InvalidConfiguration {
        /// Configuration category.
        kind: SaveConfigConfigurationKind,
    },
    /// A field count exceeded its configured bound.
    FieldLimitExceeded {
        /// Observed field count.
        actual: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// A field's ordered operation count exceeded its configured bound.
    OperationLimitExceeded {
        /// Field whose operations exceeded the bound.
        field: SaveField,
        /// Observed operation count.
        actual: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// The resolver's aggregate operation count exceeded its configured bound.
    TotalOperationLimitExceeded {
        /// Observed operation count.
        actual: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// A field/property/value text value exceeded its configured bound.
    TextLimitExceeded {
        /// Which field was affected, when known.
        field: Option<SaveField>,
        /// Observed byte length.
        actual: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// Aggregate Java-value bytes exceeded the configured bound.
    TotalValueLimitExceeded {
        /// Observed byte count.
        actual: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// A known field received a value with the wrong Java type.
    InvalidValue {
        /// Field receiving the value.
        field: SaveField,
        /// Expected Java value kind.
        expected: SaveValueKind,
        /// Actual Java value kind.
        actual: SaveValueKind,
    },
    /// A requested field has no operations and cannot be defaulted.
    MissingField {
        /// Field with no explicit source operation.
        field: SaveField,
    },
    /// A field cannot be resolved with the supplied source precedence or wire
    /// target.  Candidate values remain available through [`Self::candidates`]
    /// but are redacted by `Debug` and `Display`.
    Ambiguous {
        /// Field whose interpretation is ambiguous.
        field: SaveField,
        /// Bounded candidate interpretations.
        candidates: Vec<SaveConfigCandidate>,
        /// Whether candidates were truncated by the configured bound.
        truncated: bool,
    },
    /// Canonical serialization exceeded the hard canonical bound.
    CanonicalizationLimit {
        /// Observed serialized bytes.
        actual: usize,
        /// Hard maximum.
        maximum: usize,
    },
}

impl SaveConfigError {
    /// Returns the stable machine-readable category.
    pub const fn code(&self) -> SaveConfigErrorCode {
        match self {
            Self::InvalidLimit { .. }
            | Self::FieldLimitExceeded { .. }
            | Self::OperationLimitExceeded { .. }
            | Self::TotalOperationLimitExceeded { .. }
            | Self::TextLimitExceeded { .. }
            | Self::TotalValueLimitExceeded { .. } => SaveConfigErrorCode::Limit,
            Self::InvalidConfiguration { .. } => SaveConfigErrorCode::InvalidConfiguration,
            Self::InvalidValue { .. } => SaveConfigErrorCode::InvalidValue,
            Self::MissingField { .. } => SaveConfigErrorCode::Unresolved,
            Self::Ambiguous { .. } => SaveConfigErrorCode::Ambiguous,
            Self::CanonicalizationLimit { .. } => SaveConfigErrorCode::Canonicalization,
        }
    }

    /// Returns the stable machine-readable string code.
    pub const fn stable_code(&self) -> &'static str {
        self.code().as_str()
    }

    /// Returns bounded ambiguity candidates, if this is an ambiguity error.
    pub fn candidates(&self) -> &[SaveConfigCandidate] {
        match self {
            Self::Ambiguous { candidates, .. } => candidates,
            _ => &[],
        }
    }

    /// Returns whether the ambiguity candidate list was truncated.
    pub const fn candidates_truncated(&self) -> bool {
        match self {
            Self::Ambiguous { truncated, .. } => *truncated,
            _ => false,
        }
    }
}

impl fmt::Debug for SaveConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("SaveConfigError");
        debug.field("code", &self.stable_code());
        match self {
            Self::InvalidLimit {
                kind,
                actual,
                maximum,
            } => {
                debug
                    .field("kind", kind)
                    .field("actual", actual)
                    .field("maximum", maximum);
            }
            Self::InvalidConfiguration { kind } => {
                debug.field("kind", kind);
            }
            Self::FieldLimitExceeded {
                actual, maximum, ..
            }
            | Self::TotalOperationLimitExceeded {
                actual, maximum, ..
            }
            | Self::CanonicalizationLimit {
                actual, maximum, ..
            } => {
                debug.field("actual", actual).field("maximum", maximum);
            }
            Self::OperationLimitExceeded {
                field,
                actual,
                maximum,
            } => {
                debug
                    .field("field", &FieldDiagnostic(field))
                    .field("actual", actual)
                    .field("maximum", maximum);
            }
            Self::TextLimitExceeded {
                field,
                actual,
                maximum,
            } => {
                debug
                    .field("field", &field.as_ref().map(FieldDiagnostic))
                    .field("actual", actual)
                    .field("maximum", maximum);
            }
            Self::TotalValueLimitExceeded {
                actual, maximum, ..
            } => {
                debug.field("actual", actual).field("maximum", maximum);
            }
            Self::InvalidValue {
                field,
                expected,
                actual,
            } => {
                debug
                    .field("field", &FieldDiagnostic(field))
                    .field("expected", expected)
                    .field("actual", actual);
            }
            Self::MissingField { field } => {
                debug.field("field", &FieldDiagnostic(field));
            }
            Self::Ambiguous {
                field,
                candidates,
                truncated,
            } => {
                debug
                    .field("field", &FieldDiagnostic(field))
                    .field("candidate_count", &candidates.len())
                    .field("candidates_truncated", truncated)
                    .field("candidates", candidates);
            }
        }
        debug.finish()
    }
}

impl fmt::Display for SaveConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit {
                kind,
                actual,
                maximum,
            } => write!(
                formatter,
                "{}: {kind} {actual} exceeds {maximum}",
                self.stable_code()
            ),
            Self::InvalidConfiguration { kind } => {
                write!(formatter, "{}: {kind:?}", self.stable_code())
            }
            Self::FieldLimitExceeded { actual, maximum } => write!(
                formatter,
                "{}: field count {actual} exceeds {maximum}",
                self.stable_code()
            ),
            Self::OperationLimitExceeded {
                actual, maximum, ..
            } => write!(
                formatter,
                "{}: operation count {actual} exceeds {maximum}",
                self.stable_code()
            ),
            Self::TotalOperationLimitExceeded { actual, maximum } => write!(
                formatter,
                "{}: total operation count {actual} exceeds {maximum}",
                self.stable_code()
            ),
            Self::TextLimitExceeded {
                actual, maximum, ..
            } => write!(
                formatter,
                "{}: text length {actual} exceeds {maximum}",
                self.stable_code()
            ),
            Self::TotalValueLimitExceeded { actual, maximum } => write!(
                formatter,
                "{}: total value bytes {actual} exceeds {maximum}",
                self.stable_code()
            ),
            Self::InvalidValue {
                expected, actual, ..
            } => write!(
                formatter,
                "{}: expected {expected}, received {actual}",
                self.stable_code()
            ),
            Self::MissingField { .. } => {
                write!(
                    formatter,
                    "{}: no explicit field operation",
                    self.stable_code()
                )
            }
            Self::Ambiguous {
                candidates,
                truncated,
                ..
            } => write!(
                formatter,
                "{}: {} bounded candidates{}",
                self.stable_code(),
                candidates.len(),
                if *truncated { " (truncated)" } else { "" }
            ),
            Self::CanonicalizationLimit { actual, maximum } => write!(
                formatter,
                "{}: canonical bytes {actual} exceeds {maximum}",
                self.stable_code()
            ),
        }
    }
}

impl std::error::Error for SaveConfigError {}

/// Explicit resource bounds for one save-configuration resolution.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SaveConfigLimits {
    max_fields: usize,
    max_operations_per_field: usize,
    max_operations: usize,
    max_candidates: usize,
    max_text_bytes: usize,
    max_total_value_bytes: usize,
}

impl SaveConfigLimits {
    /// Creates bounds after checking both nonzero and hard maxima.
    pub fn new(
        max_fields: usize,
        max_operations_per_field: usize,
        max_operations: usize,
        max_candidates: usize,
        max_text_bytes: usize,
        max_total_value_bytes: usize,
    ) -> Result<Self, SaveConfigError> {
        let limits = Self {
            max_fields,
            max_operations_per_field,
            max_operations,
            max_candidates,
            max_text_bytes,
            max_total_value_bytes,
        };
        limits.validate()?;
        Ok(limits)
    }

    /// Validates bounds constructed by a struct update or copied value.
    pub fn validate(self) -> Result<(), SaveConfigError> {
        let values = [
            (
                SaveConfigLimitKind::Fields,
                self.max_fields,
                MAX_SAVE_CONFIG_FIELDS,
            ),
            (
                SaveConfigLimitKind::OperationsPerField,
                self.max_operations_per_field,
                MAX_SAVE_CONFIG_OPERATIONS_PER_FIELD,
            ),
            (
                SaveConfigLimitKind::Operations,
                self.max_operations,
                MAX_SAVE_CONFIG_OPERATIONS,
            ),
            (
                SaveConfigLimitKind::Candidates,
                self.max_candidates,
                MAX_SAVE_CONFIG_CANDIDATES,
            ),
            (
                SaveConfigLimitKind::TextBytes,
                self.max_text_bytes,
                MAX_SAVE_CONFIG_TEXT_BYTES,
            ),
            (
                SaveConfigLimitKind::TotalValueBytes,
                self.max_total_value_bytes,
                MAX_SAVE_CONFIG_TOTAL_VALUE_BYTES,
            ),
        ];
        for (kind, actual, maximum) in values {
            if actual == 0 || actual > maximum {
                return Err(SaveConfigError::InvalidLimit {
                    kind,
                    actual,
                    maximum,
                });
            }
        }
        if self.max_operations < self.max_operations_per_field {
            return Err(SaveConfigError::InvalidConfiguration {
                kind: SaveConfigConfigurationKind::Empty,
            });
        }
        Ok(())
    }

    /// Returns the maximum number of fields.
    pub const fn max_fields(self) -> usize {
        self.max_fields
    }

    /// Returns the maximum operations per field.
    pub const fn max_operations_per_field(self) -> usize {
        self.max_operations_per_field
    }

    /// Returns the maximum operations across all fields.
    pub const fn max_operations(self) -> usize {
        self.max_operations
    }

    /// Returns the maximum ambiguity candidates.
    pub const fn max_candidates(self) -> usize {
        self.max_candidates
    }

    /// Returns the maximum bytes in one name or value.
    pub const fn max_text_bytes(self) -> usize {
        self.max_text_bytes
    }

    /// Returns the aggregate Java-value byte bound.
    pub const fn max_total_value_bytes(self) -> usize {
        self.max_total_value_bytes
    }
}

/// A known save-service field in profile wire order.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SaveFieldId {
    /// Output format (`csv` or `xml`).
    OutputFormat,
    /// Timestamp format (`none`, `ms`, or a Java date pattern).
    TimestampFormat,
    /// Whether CSV field names are emitted.
    PrintFieldNames,
    /// CSV delimiter.
    Delimiter,
    /// Elapsed-time field switch.
    Time,
    /// Latency field switch.
    Latency,
    /// Connect-time field switch.
    ConnectTime,
    /// Timestamp field switch.
    Timestamp,
    /// Success field switch.
    Successful,
    /// Label field switch.
    Label,
    /// Response-code field switch.
    ResponseCode,
    /// Response-message field switch.
    ResponseMessage,
    /// Thread-name field switch.
    ThreadName,
    /// Data-type field switch.
    DataType,
    /// Encoding field switch.
    Encoding,
    /// Assertion output switch/cardinality.
    Assertions,
    /// Explicit assertion cardinality.
    AssertionResults,
    /// Nested sub-result switch.
    Subresults,
    /// Response-data switch.
    ResponseData,
    /// Response-data-on-error switch.
    ResponseDataOnError,
    /// Sampler-data switch.
    SamplerData,
    /// Response-header switch.
    ResponseHeaders,
    /// Request-header switch.
    RequestHeaders,
    /// Received-byte switch.
    Bytes,
    /// Sent-byte switch.
    SentBytes,
    /// URL switch.
    Url,
    /// Filename/response-file switch.
    Filename,
    /// Hostname switch.
    Hostname,
    /// Thread-count switch.
    ThreadCounts,
    /// Sample-count switch.
    SampleCount,
    /// Idle-time switch.
    IdleTime,
    /// Assertion-failure-message switch.
    AssertionFailureMessage,
    /// Configured sample-variable list.
    SampleVariables,
    /// Whether timestamps represent sample start.
    TimestampStart,
    /// Whether the runtime uses nano time.
    UseNanoTime,
    /// Nano-time refresh interval.
    NanoThreadSleep,
    /// Sub-result label-renaming switch.
    SubresultsDisableRenaming,
    /// Default response encoding.
    DefaultEncoding,
    /// Per-record flush switch.
    Autoflush,
    /// XML processing-instruction switch, retained for explicit policy.
    XmlPi,
    /// Save-service base-prefix policy, retained for explicit policy.
    BasePrefix,
    /// Explicit output line-ending policy.
    LineEnding,
}

impl SaveFieldId {
    /// Returns every known save field in stable property/declaration order.
    pub const fn all() -> [Self; 42] {
        [
            Self::OutputFormat,
            Self::TimestampFormat,
            Self::PrintFieldNames,
            Self::Delimiter,
            Self::Time,
            Self::Latency,
            Self::ConnectTime,
            Self::Timestamp,
            Self::Successful,
            Self::Label,
            Self::ResponseCode,
            Self::ResponseMessage,
            Self::ThreadName,
            Self::DataType,
            Self::Encoding,
            Self::Assertions,
            Self::AssertionResults,
            Self::Subresults,
            Self::ResponseData,
            Self::ResponseDataOnError,
            Self::SamplerData,
            Self::ResponseHeaders,
            Self::RequestHeaders,
            Self::Bytes,
            Self::SentBytes,
            Self::Url,
            Self::Filename,
            Self::Hostname,
            Self::ThreadCounts,
            Self::SampleCount,
            Self::IdleTime,
            Self::AssertionFailureMessage,
            Self::SampleVariables,
            Self::TimestampStart,
            Self::UseNanoTime,
            Self::NanoThreadSleep,
            Self::SubresultsDisableRenaming,
            Self::DefaultEncoding,
            Self::Autoflush,
            Self::XmlPi,
            Self::BasePrefix,
            Self::LineEnding,
        ]
    }

    /// Returns the exact recognized JMeter property spelling.
    pub const fn property_name(self) -> &'static str {
        match self {
            Self::OutputFormat => "jmeter.save.saveservice.output_format",
            Self::TimestampFormat => "jmeter.save.saveservice.timestamp_format",
            Self::PrintFieldNames => "jmeter.save.saveservice.print_field_names",
            Self::Delimiter => "jmeter.save.saveservice.default_delimiter",
            Self::Time => "jmeter.save.saveservice.time",
            Self::Latency => "jmeter.save.saveservice.latency",
            Self::ConnectTime => "jmeter.save.saveservice.connect_time",
            Self::Timestamp => "jmeter.save.saveservice.timestamp",
            Self::Successful => "jmeter.save.saveservice.successful",
            Self::Label => "jmeter.save.saveservice.label",
            Self::ResponseCode => "jmeter.save.saveservice.response_code",
            Self::ResponseMessage => "jmeter.save.saveservice.response_message",
            Self::ThreadName => "jmeter.save.saveservice.thread_name",
            Self::DataType => "jmeter.save.saveservice.data_type",
            Self::Encoding => "jmeter.save.saveservice.encoding",
            Self::Assertions => "jmeter.save.saveservice.assertions",
            Self::AssertionResults => "jmeter.save.saveservice.assertion_results",
            Self::Subresults => "jmeter.save.saveservice.subresults",
            Self::ResponseData => "jmeter.save.saveservice.response_data",
            Self::ResponseDataOnError => "jmeter.save.saveservice.response_data.on_error",
            Self::SamplerData => "jmeter.save.saveservice.samplerData",
            Self::ResponseHeaders => "jmeter.save.saveservice.responseHeaders",
            Self::RequestHeaders => "jmeter.save.saveservice.requestHeaders",
            Self::Bytes => "jmeter.save.saveservice.bytes",
            Self::SentBytes => "jmeter.save.saveservice.sent_bytes",
            Self::Url => "jmeter.save.saveservice.url",
            Self::Filename => "jmeter.save.saveservice.filename",
            Self::Hostname => "jmeter.save.saveservice.hostname",
            Self::ThreadCounts => "jmeter.save.saveservice.thread_counts",
            Self::SampleCount => "jmeter.save.saveservice.sample_count",
            Self::IdleTime => "jmeter.save.saveservice.idle_time",
            Self::AssertionFailureMessage => {
                "jmeter.save.saveservice.assertion_results_failure_message"
            }
            Self::SampleVariables => "sample_variables",
            Self::TimestampStart => "sampleresult.timestamp.start",
            Self::UseNanoTime => "sampleresult.useNanoTime",
            Self::NanoThreadSleep => "sampleresult.nanoThreadSleep",
            Self::SubresultsDisableRenaming => "subresults.disable_renaming",
            Self::DefaultEncoding => "sampleresult.default.encoding",
            Self::Autoflush => "jmeter.save.saveservice.autoflush",
            Self::XmlPi => "jmeter.save.saveservice.xml_pi",
            Self::BasePrefix => "jmeter.save.saveservice.base_prefix",
            Self::LineEnding => "line_ending",
        }
    }

    /// Returns profile-approved historical or integration aliases.
    pub const fn property_aliases(self) -> &'static [&'static str] {
        match self {
            Self::AssertionFailureMessage => &["jmeter.save.saveservice.failure_message"],
            Self::SampleVariables => &["jmeter.save.saveservice.sample_variables"],
            _ => &[],
        }
    }

    /// Resolves an exact canonical property or approved alias.
    pub fn from_property_name(name: &str) -> Option<Self> {
        Self::all()
            .into_iter()
            .find(|field| field.property_name() == name || field.property_aliases().contains(&name))
    }

    /// Returns the CSV header spelling, if this field is represented in CSV.
    pub const fn csv_header_name(self) -> Option<&'static str> {
        match self {
            Self::Timestamp => Some("timeStamp"),
            Self::Time => Some("elapsed"),
            Self::Label => Some("label"),
            Self::ResponseCode => Some("responseCode"),
            Self::ResponseMessage => Some("responseMessage"),
            Self::ThreadName => Some("threadName"),
            Self::DataType => Some("dataType"),
            Self::Successful => Some("success"),
            Self::AssertionFailureMessage => Some("failureMessage"),
            Self::Bytes => Some("bytes"),
            Self::SentBytes => Some("sentBytes"),
            Self::ThreadCounts => Some("grpThreads"),
            Self::Url => Some("URL"),
            Self::Filename => Some("Filename"),
            Self::Latency => Some("Latency"),
            Self::Encoding => Some("Encoding"),
            Self::SampleCount => Some("SampleCount"),
            Self::Hostname => Some("Hostname"),
            Self::IdleTime => Some("IdleTime"),
            Self::ConnectTime => Some("Connect"),
            _ => None,
        }
    }

    /// Returns the XML attribute spelling, if this field is represented in XML.
    pub const fn xml_attribute_name(self) -> Option<&'static str> {
        match self {
            Self::Time => Some("t"),
            Self::IdleTime => Some("it"),
            Self::Latency => Some("lt"),
            Self::ConnectTime => Some("ct"),
            Self::Timestamp => Some("ts"),
            Self::Successful => Some("s"),
            Self::Label => Some("lb"),
            Self::ResponseCode => Some("rc"),
            Self::ResponseMessage => Some("rm"),
            Self::ThreadName => Some("tn"),
            Self::DataType => Some("dt"),
            Self::Encoding => Some("de"),
            Self::Bytes => Some("by"),
            Self::SentBytes => Some("sby"),
            Self::SampleCount => Some("sc"),
            Self::ThreadCounts => Some("ng"),
            Self::Hostname => Some("hn"),
            _ => None,
        }
    }

    /// Returns the expected Java value kind for this known field.
    pub const fn value_kind(self) -> SaveValueKind {
        match self {
            Self::PrintFieldNames
            | Self::Time
            | Self::Latency
            | Self::ConnectTime
            | Self::Timestamp
            | Self::Successful
            | Self::Label
            | Self::ResponseCode
            | Self::ResponseMessage
            | Self::ThreadName
            | Self::DataType
            | Self::Encoding
            | Self::Subresults
            | Self::ResponseData
            | Self::ResponseDataOnError
            | Self::SamplerData
            | Self::ResponseHeaders
            | Self::RequestHeaders
            | Self::Bytes
            | Self::SentBytes
            | Self::Url
            | Self::Filename
            | Self::Hostname
            | Self::ThreadCounts
            | Self::SampleCount
            | Self::IdleTime
            | Self::AssertionFailureMessage
            | Self::TimestampStart
            | Self::UseNanoTime
            | Self::SubresultsDisableRenaming
            | Self::Autoflush => SaveValueKind::Boolean,
            Self::NanoThreadSleep => SaveValueKind::Long,
            Self::SampleVariables => SaveValueKind::StringList,
            Self::Delimiter => SaveValueKind::String,
            Self::OutputFormat
            | Self::TimestampFormat
            | Self::Assertions
            | Self::AssertionResults
            | Self::DefaultEncoding
            | Self::XmlPi
            | Self::BasePrefix
            | Self::LineEnding => SaveValueKind::String,
        }
    }

    fn wire_tag(self) -> u16 {
        self as u16
    }

    fn parse_raw(self, value: &str) -> Result<JavaValue, SaveConfigError> {
        validate_text(value.len(), Some(SaveField::Known(self)))?;
        match self.value_kind() {
            SaveValueKind::Boolean => {
                if value.eq_ignore_ascii_case("true") {
                    Ok(JavaValue::Boolean(true))
                } else if value.eq_ignore_ascii_case("false") {
                    Ok(JavaValue::Boolean(false))
                } else {
                    Err(SaveConfigError::InvalidValue {
                        field: SaveField::Known(self),
                        expected: SaveValueKind::Boolean,
                        actual: SaveValueKind::Raw,
                    })
                }
            }
            SaveValueKind::Long => value.parse::<i64>().map(JavaValue::Long).map_err(|_| {
                SaveConfigError::InvalidValue {
                    field: SaveField::Known(self),
                    expected: SaveValueKind::Long,
                    actual: SaveValueKind::Raw,
                }
            }),
            SaveValueKind::Integer => value.parse::<i64>().map(JavaValue::Integer).map_err(|_| {
                SaveConfigError::InvalidValue {
                    field: SaveField::Known(self),
                    expected: SaveValueKind::Integer,
                    actual: SaveValueKind::Raw,
                }
            }),
            SaveValueKind::String => {
                self.validate_string_value(value)?;
                JavaValue::string(value)
            }
            SaveValueKind::StringList => {
                if value.is_empty() {
                    JavaValue::string_list(core::iter::empty::<&str>())
                } else {
                    let values = value.split(',').collect::<Vec<_>>();
                    if values.iter().any(|item| item.is_empty()) {
                        return Err(SaveConfigError::InvalidValue {
                            field: SaveField::Known(self),
                            expected: SaveValueKind::StringList,
                            actual: SaveValueKind::Raw,
                        });
                    }
                    JavaValue::string_list(values)
                }
            }
            SaveValueKind::Raw => Ok(JavaValue::Raw(value.to_owned())),
        }
    }

    fn validate_string_value(self, value: &str) -> Result<(), SaveConfigError> {
        let valid = match self {
            Self::OutputFormat => matches!(value.to_ascii_lowercase().as_str(), "csv" | "xml"),
            Self::TimestampFormat => !value.is_empty(),
            Self::Delimiter => {
                let mut chars = value.chars();
                match (chars.next(), chars.next()) {
                    (Some('\t'), None) => true,
                    (Some(_), Some(_)) => matches!(value, "\\t" | "TAB" | "tab"),
                    (Some(character), None) => {
                        !character.is_ascii_alphanumeric()
                            && character != '"'
                            && (character.is_ascii_graphic() || character == ' ')
                    }
                    (None, _) => false,
                }
            }
            Self::Assertions => {
                matches_ignore_ascii_case(value, &["true", "false", "none", "first", "all"])
            }
            Self::AssertionResults => matches_ignore_ascii_case(value, &["none", "first", "all"]),
            Self::DefaultEncoding => !value.is_empty(),
            Self::XmlPi | Self::BasePrefix | Self::LineEnding => true,
            _ => true,
        };
        if valid {
            Ok(())
        } else {
            Err(SaveConfigError::InvalidValue {
                field: SaveField::Known(self),
                expected: SaveValueKind::String,
                actual: SaveValueKind::Raw,
            })
        }
    }
}

fn matches_ignore_ascii_case(value: &str, choices: &[&str]) -> bool {
    choices
        .iter()
        .any(|choice| value.eq_ignore_ascii_case(choice))
}

/// A known field or an exact unknown property name.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SaveField {
    /// A known profile field.
    Known(SaveFieldId),
    /// An unknown property retained without interpretation.
    Unknown(String),
}

impl SaveField {
    /// Creates a known field key.
    pub const fn known(field: SaveFieldId) -> Self {
        Self::Known(field)
    }

    /// Resolves a canonical property or approved alias, retaining an unknown
    /// property as an explicit unresolved field.
    pub fn from_property_name(name: &str) -> Result<Self, SaveConfigError> {
        match SaveFieldId::from_property_name(name) {
            Some(field) => Ok(Self::Known(field)),
            None => Self::unknown(name),
        }
    }

    /// Creates an unknown field after checking the hard name bound.
    pub fn unknown(name: impl AsRef<str>) -> Result<Self, SaveConfigError> {
        let name = name.as_ref();
        if name.is_empty() || name.len() > MAX_SAVE_CONFIG_TEXT_BYTES {
            return Err(SaveConfigError::InvalidConfiguration {
                kind: SaveConfigConfigurationKind::InvalidName,
            });
        }
        Ok(Self::Unknown(name.to_owned()))
    }

    /// Returns the known field, if this is not an unknown property.
    pub const fn known_id(&self) -> Option<SaveFieldId> {
        match self {
            Self::Known(field) => Some(*field),
            Self::Unknown(_) => None,
        }
    }

    /// Returns the exact unknown property name, if any.
    pub fn unknown_name(&self) -> Option<&str> {
        match self {
            Self::Known(_) => None,
            Self::Unknown(name) => Some(name),
        }
    }

    /// Returns the canonical property name for a known field.
    pub fn property_name(&self) -> Option<&str> {
        match self {
            Self::Known(field) => Some(field.property_name()),
            Self::Unknown(name) => Some(name),
        }
    }

    fn validate_name(&self) -> Result<(), SaveConfigError> {
        if self
            .property_name()
            .is_some_and(|name| name.is_empty() || name.len() > MAX_SAVE_CONFIG_TEXT_BYTES)
        {
            return Err(SaveConfigError::InvalidConfiguration {
                kind: SaveConfigConfigurationKind::InvalidName,
            });
        }
        Ok(())
    }
}

impl fmt::Debug for SaveField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Known(field) => formatter
                .debug_tuple("SaveField::Known")
                .field(field)
                .finish(),
            Self::Unknown(name) => formatter
                .debug_struct("SaveField::Unknown")
                .field("bytes", &name.len())
                .finish(),
        }
    }
}

impl fmt::Display for SaveField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Known(field) => formatter.write_str(field.property_name()),
            Self::Unknown(name) => write!(formatter, "<unknown property {} bytes>", name.len()),
        }
    }
}

/// The Java value kind expected by a known save field.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SaveValueKind {
    /// A Java boolean.
    Boolean,
    /// A Java integer.
    Integer,
    /// A Java long.
    Long,
    /// A Java string.
    String,
    /// A Java string-list property.
    StringList,
    /// An untyped raw value.
    Raw,
}

impl fmt::Display for SaveValueKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Boolean => "boolean",
            Self::Integer => "integer",
            Self::Long => "long",
            Self::String => "string",
            Self::StringList => "string-list",
            Self::Raw => "raw",
        })
    }
}

/// A typed Java-side configuration value.
#[derive(Clone, Eq, Hash, PartialEq)]
pub enum JavaValue {
    /// A Java string.
    String(String),
    /// A Java boolean.
    Boolean(bool),
    /// A Java integer represented without host narrowing.
    Integer(i64),
    /// A Java long.
    Long(i64),
    /// An ordered Java string-list property.
    StringList(Vec<String>),
    /// An unknown property value retained as raw text.
    Raw(String),
}

impl JavaValue {
    /// Creates a bounded Java string.
    pub fn string(value: impl AsRef<str>) -> Result<Self, SaveConfigError> {
        let value = value.as_ref();
        validate_text(value.len(), None)?;
        Ok(Self::String(value.to_owned()))
    }

    /// Creates a bounded raw value for an unknown property.
    pub fn raw(value: impl AsRef<str>) -> Result<Self, SaveConfigError> {
        let value = value.as_ref();
        validate_text(value.len(), None)?;
        Ok(Self::Raw(value.to_owned()))
    }

    /// Creates a Java boolean.
    pub const fn boolean(value: bool) -> Self {
        Self::Boolean(value)
    }

    /// Creates a Java integer.
    pub const fn integer(value: i64) -> Self {
        Self::Integer(value)
    }

    /// Creates a Java long.
    pub const fn long(value: i64) -> Self {
        Self::Long(value)
    }

    /// Creates a bounded ordered string list.
    pub fn string_list<I, S>(values: I) -> Result<Self, SaveConfigError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut result = Vec::new();
        let mut bytes = 0usize;
        for value in values {
            if result.len() >= MAX_SAVE_CONFIG_TEXT_BYTES {
                return Err(SaveConfigError::TextLimitExceeded {
                    field: None,
                    actual: result.len().saturating_add(1),
                    maximum: MAX_SAVE_CONFIG_TEXT_BYTES,
                });
            }
            let value = value.as_ref();
            bytes = bytes
                .checked_add(value.len())
                .and_then(|total| total.checked_add(usize::from(!result.is_empty())))
                .ok_or(SaveConfigError::TextLimitExceeded {
                    field: None,
                    actual: usize::MAX,
                    maximum: MAX_SAVE_CONFIG_TEXT_BYTES,
                })?;
            if bytes > MAX_SAVE_CONFIG_TEXT_BYTES {
                return Err(SaveConfigError::TextLimitExceeded {
                    field: None,
                    actual: bytes,
                    maximum: MAX_SAVE_CONFIG_TEXT_BYTES,
                });
            }
            result.push(value.to_owned());
        }
        Ok(Self::StringList(result))
    }

    /// Returns the value kind.
    pub const fn kind(&self) -> SaveValueKind {
        match self {
            Self::String(_) => SaveValueKind::String,
            Self::Boolean(_) => SaveValueKind::Boolean,
            Self::Integer(_) => SaveValueKind::Integer,
            Self::Long(_) => SaveValueKind::Long,
            Self::StringList(_) => SaveValueKind::StringList,
            Self::Raw(_) => SaveValueKind::Raw,
        }
    }

    /// Returns the aggregate encoded byte size of this value.
    pub fn byte_len(&self) -> usize {
        match self {
            Self::String(value) | Self::Raw(value) => value.len(),
            Self::Boolean(value) => {
                if *value {
                    "true".len()
                } else {
                    "false".len()
                }
            }
            Self::Integer(value) | Self::Long(value) => value.to_string().len(),
            Self::StringList(values) => {
                values
                    .iter()
                    .map(String::len)
                    .enumerate()
                    .fold(0usize, |total, (index, value)| {
                        total
                            .saturating_add(value)
                            .saturating_add(usize::from(index != 0))
                    })
            }
        }
    }

    /// Returns the value as a canonical JMeter property spelling.
    pub fn to_wire_string(&self) -> String {
        match self {
            Self::String(value) | Self::Raw(value) => value.clone(),
            Self::Boolean(value) => value.to_string(),
            Self::Integer(value) | Self::Long(value) => value.to_string(),
            Self::StringList(values) => values.join(","),
        }
    }
}

impl fmt::Debug for JavaValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String(value) => formatter
                .debug_struct("JavaValue::String")
                .field("bytes", &value.len())
                .finish(),
            Self::Raw(value) => formatter
                .debug_struct("JavaValue::Raw")
                .field("bytes", &value.len())
                .finish(),
            Self::Boolean(value) => formatter
                .debug_tuple("JavaValue::Boolean")
                .field(value)
                .finish(),
            Self::Integer(value) => formatter
                .debug_tuple("JavaValue::Integer")
                .field(value)
                .finish(),
            Self::Long(value) => formatter
                .debug_tuple("JavaValue::Long")
                .field(value)
                .finish(),
            Self::StringList(values) => formatter
                .debug_struct("JavaValue::StringList")
                .field("count", &values.len())
                .field(
                    "bytes",
                    &values
                        .iter()
                        .map(String::len)
                        .fold(0usize, usize::saturating_add),
                )
                .finish(),
        }
    }
}

/// The operation kind retained in source order.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SaveOperationKind {
    /// Apply a value from this source.
    Apply,
    /// Replace the prior value from this source.
    Replace,
    /// Explicitly remove the field.
    Remove,
    /// State that this source has no field declaration.
    Absent,
    /// State that this source supplied an empty value.
    PresentEmpty,
}

/// One explicit save-configuration operation.
#[derive(Clone, Eq, Hash, PartialEq)]
pub enum SaveConfigOperation {
    /// Apply a typed value.
    Apply(JavaValue),
    /// Replace the prior value from this source.
    Replace(JavaValue),
    /// Explicitly remove the field.
    Remove,
    /// Explicitly mark this source's field declaration absent.
    Absent,
    /// Explicitly retain a present-but-empty value.
    PresentEmpty,
}

/// Short alias for [`SaveConfigOperation`].
pub type SaveOperation = SaveConfigOperation;

impl SaveConfigOperation {
    /// Creates an apply operation.
    pub const fn apply(value: JavaValue) -> Self {
        Self::Apply(value)
    }

    /// Creates a replace operation.
    pub const fn replace(value: JavaValue) -> Self {
        Self::Replace(value)
    }

    /// Creates a remove operation.
    pub const fn remove() -> Self {
        Self::Remove
    }

    /// Creates an absent operation.
    pub const fn absent() -> Self {
        Self::Absent
    }

    /// Creates a present-empty operation.
    pub const fn present_empty() -> Self {
        Self::PresentEmpty
    }

    /// Parses an operation value using the known field's Java type. Unknown
    /// fields retain the raw value as an unresolved operation.
    pub fn apply_raw(field: &SaveField, value: &str) -> Result<Self, SaveConfigError> {
        let value = match field {
            SaveField::Known(field) => field.parse_raw(value)?,
            SaveField::Unknown(_) => JavaValue::raw(value)?,
        };
        Ok(Self::Apply(value))
    }

    /// Returns the operation kind.
    pub const fn kind(&self) -> SaveOperationKind {
        match self {
            Self::Apply(_) => SaveOperationKind::Apply,
            Self::Replace(_) => SaveOperationKind::Replace,
            Self::Remove => SaveOperationKind::Remove,
            Self::Absent => SaveOperationKind::Absent,
            Self::PresentEmpty => SaveOperationKind::PresentEmpty,
        }
    }

    /// Returns the operation's typed value, if it carries one.
    pub const fn value(&self) -> Option<&JavaValue> {
        match self {
            Self::Apply(value) | Self::Replace(value) => Some(value),
            Self::Remove | Self::Absent | Self::PresentEmpty => None,
        }
    }
}

impl fmt::Debug for SaveConfigOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Apply(value) => formatter.debug_tuple("Apply").field(value).finish(),
            Self::Replace(value) => formatter.debug_tuple("Replace").field(value).finish(),
            Self::Remove => formatter.write_str("Remove"),
            Self::Absent => formatter.write_str("Absent"),
            Self::PresentEmpty => formatter.write_str("PresentEmpty"),
        }
    }
}

/// A source category that can participate in profile precedence.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SaveConfigSourceKind {
    /// Plan-local nested `saveConfig` properties.
    PlanSaveConfig,
    /// Explicit `jmeter.save.saveservice.*` or related run properties.
    RunProperties,
    /// CLI-selected output/report mode.
    CliMode,
    /// Metadata read from a report/JTL input.
    ReportInputMetadata,
    /// Format-specific header/root observation.
    FormatObservation,
}

impl SaveConfigSourceKind {
    /// Returns every source kind in stable declaration order.
    pub const fn all() -> [Self; PRECEDENCE_SOURCE_COUNT] {
        [
            Self::PlanSaveConfig,
            Self::RunProperties,
            Self::CliMode,
            Self::ReportInputMetadata,
            Self::FormatObservation,
        ]
    }

    fn wire_tag(self) -> u8 {
        self as u8
    }
}

/// A CLI mode used as typed save-configuration provenance.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CliMode {
    /// Normal test execution.
    NormalRun,
    /// Report generation after a normal run.
    ReportAtEnd,
    /// Report-only mode reading an existing JTL.
    ReportOnly,
}

/// A JTL wire format used by metadata, observations, and explicit output
/// selection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SaveWireFormat {
    /// CSV JTL.
    Csv,
    /// XML JTL.
    Xml,
    /// A Java/property representation rather than a result file.
    Properties,
    /// No format metadata was supplied.
    Unknown,
}

impl SaveWireFormat {
    fn wire_tag(self) -> u8 {
        match self {
            Self::Csv => 0,
            Self::Xml => 1,
            Self::Properties => 2,
            Self::Unknown => 3,
        }
    }
}

/// Typed provenance identifying one source operation's origin.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SaveConfigSource {
    /// A plan-local save configuration at a nonzero node identity.
    PlanSaveConfig {
        /// Document-local plan node identity.
        node_id: u64,
    },
    /// A run-property occurrence, retained by source order.
    RunProperties {
        /// Property occurrence ordinal.
        ordinal: u32,
    },
    /// An explicit CLI mode.
    CliMode {
        /// Selected mode.
        mode: CliMode,
    },
    /// Metadata read from an input report/JTL.
    ReportInputMetadata {
        /// Declared or observed input format.
        format: SaveWireFormat,
    },
    /// A format-specific header/root observation.
    FormatObservation {
        /// Observed format.
        format: SaveWireFormat,
    },
}

impl SaveConfigSource {
    /// Returns the source category used for precedence lookup.
    pub const fn kind(self) -> SaveConfigSourceKind {
        match self {
            Self::PlanSaveConfig { .. } => SaveConfigSourceKind::PlanSaveConfig,
            Self::RunProperties { .. } => SaveConfigSourceKind::RunProperties,
            Self::CliMode { .. } => SaveConfigSourceKind::CliMode,
            Self::ReportInputMetadata { .. } => SaveConfigSourceKind::ReportInputMetadata,
            Self::FormatObservation { .. } => SaveConfigSourceKind::FormatObservation,
        }
    }

    fn validate(self) -> Result<(), SaveConfigError> {
        if matches!(self, Self::PlanSaveConfig { node_id: 0 }) {
            return Err(SaveConfigError::InvalidConfiguration {
                kind: SaveConfigConfigurationKind::InvalidSource,
            });
        }
        Ok(())
    }

    fn wire_tag(self) -> u8 {
        self.kind().wire_tag()
    }

    fn detail_u64(self) -> u64 {
        match self {
            Self::PlanSaveConfig { node_id } => node_id,
            Self::RunProperties { ordinal } => u64::from(ordinal),
            Self::CliMode { mode } => match mode {
                CliMode::NormalRun => 0,
                CliMode::ReportAtEnd => 1,
                CliMode::ReportOnly => 2,
            },
            Self::ReportInputMetadata { format } | Self::FormatObservation { format } => {
                u64::from(format.wire_tag())
            }
        }
    }
}

/// An explicit source precedence table supplied by a compatibility profile.
/// The first source has the highest precedence; omitted sources are never
/// assigned an inferred rank.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct SaveConfigPrecedence {
    profile_id: String,
    ordered_sources: Vec<SaveConfigSourceKind>,
}

impl SaveConfigPrecedence {
    /// Creates a bounded profile table with first-listed source highest.
    pub fn new<I, S>(profile_id: S, ordered_sources: I) -> Result<Self, SaveConfigError>
    where
        I: IntoIterator<Item = SaveConfigSourceKind>,
        S: AsRef<str>,
    {
        let profile_id = profile_id.as_ref();
        if profile_id.is_empty() || profile_id.len() > MAX_SAVE_CONFIG_TEXT_BYTES {
            return Err(SaveConfigError::InvalidConfiguration {
                kind: SaveConfigConfigurationKind::InvalidProfile,
            });
        }
        let mut sources = Vec::with_capacity(PRECEDENCE_SOURCE_COUNT);
        for source in ordered_sources {
            if sources.len() >= PRECEDENCE_SOURCE_COUNT || sources.contains(&source) {
                return Err(SaveConfigError::InvalidConfiguration {
                    kind: if sources.len() >= PRECEDENCE_SOURCE_COUNT {
                        SaveConfigConfigurationKind::TooManySources
                    } else {
                        SaveConfigConfigurationKind::DuplicateSource
                    },
                });
            }
            sources.push(source);
        }
        if sources.is_empty() {
            return Err(SaveConfigError::InvalidConfiguration {
                kind: SaveConfigConfigurationKind::Empty,
            });
        }
        Ok(Self {
            profile_id: profile_id.to_owned(),
            ordered_sources: sources,
        })
    }

    /// Returns the profile identity used by canonical serialization.
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    /// Returns source kinds in explicit precedence order.
    pub fn ordered_sources(&self) -> &[SaveConfigSourceKind] {
        &self.ordered_sources
    }

    /// Returns a source's explicit rank, or `None` when the profile omitted it.
    pub fn rank(&self, source: SaveConfigSourceKind) -> Option<usize> {
        self.ordered_sources
            .iter()
            .position(|candidate| *candidate == source)
    }
}

impl fmt::Debug for SaveConfigPrecedence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SaveConfigPrecedence")
            .field("profile_id_bytes", &self.profile_id.len())
            .field("ordered_sources", &self.ordered_sources)
            .finish()
    }
}

/// An operation with source provenance and a resolver-assigned source order.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct SaveFieldOperation {
    source: SaveConfigSource,
    operation: SaveConfigOperation,
    order: usize,
}

impl SaveFieldOperation {
    /// Creates an operation with an explicit order for test/support adapters.
    /// Production callers normally use [`SaveConfigResolver::push`], which
    /// assigns a monotonic order after checking all bounds.
    pub fn new(
        source: SaveConfigSource,
        operation: SaveConfigOperation,
        order: usize,
    ) -> Result<Self, SaveConfigError> {
        source.validate()?;
        Ok(Self {
            source,
            operation,
            order,
        })
    }

    /// Returns the typed source provenance.
    pub const fn source(&self) -> SaveConfigSource {
        self.source
    }

    /// Returns the retained operation.
    pub fn operation(&self) -> &SaveConfigOperation {
        &self.operation
    }

    /// Returns the resolver-assigned source order.
    pub const fn order(&self) -> usize {
        self.order
    }
}

impl fmt::Debug for SaveFieldOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SaveFieldOperation")
            .field("source", &self.source)
            .field("operation", &self.operation)
            .field("order", &self.order)
            .finish()
    }
}

/// Final presence of a known save field.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FieldPresence {
    /// No value is serialized or supplied.
    Absent,
    /// A value is explicitly present but empty.
    PresentEmpty,
    /// A non-empty or typed value is explicitly present.
    Present,
}

/// The selected wire representation of a resolved field.
#[derive(Clone, Eq, Hash, PartialEq)]
pub enum WireRepresentation {
    /// The selected format has no representation for this field, or the field
    /// is absent.
    Omitted {
        /// Explicit output format.
        format: SaveWireFormat,
    },
    /// A present-empty value with an exact wire name.
    Empty {
        /// Explicit output format.
        format: SaveWireFormat,
        /// Exact wire/header/property name.
        name: String,
    },
    /// A present value with an exact wire name and serialized value.
    Value {
        /// Explicit output format.
        format: SaveWireFormat,
        /// Exact wire/header/property name.
        name: String,
        /// Serialized value.
        value: String,
    },
}

impl WireRepresentation {
    /// Returns the target format.
    pub const fn format(&self) -> SaveWireFormat {
        match self {
            Self::Omitted { format } | Self::Empty { format, .. } | Self::Value { format, .. } => {
                *format
            }
        }
    }

    /// Returns the exact wire name, if represented.
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Omitted { .. } => None,
            Self::Empty { name, .. } | Self::Value { name, .. } => Some(name),
        }
    }

    /// Returns the serialized wire value, if represented.
    pub fn value(&self) -> Option<&str> {
        match self {
            Self::Omitted { .. } => None,
            Self::Empty { .. } => Some(""),
            Self::Value { value, .. } => Some(value),
        }
    }
}

impl fmt::Debug for WireRepresentation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Omitted { format } => formatter
                .debug_struct("WireRepresentation::Omitted")
                .field("format", format)
                .finish(),
            Self::Empty { format, name } => formatter
                .debug_struct("WireRepresentation::Empty")
                .field("format", format)
                .field("name_bytes", &name.len())
                .finish(),
            Self::Value {
                format,
                name,
                value,
            } => formatter
                .debug_struct("WireRepresentation::Value")
                .field("format", format)
                .field("name_bytes", &name.len())
                .field("value_bytes", &value.len())
                .finish(),
        }
    }
}

/// Final provenance of a selected field operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SaveConfigProvenance {
    /// Exact source identity.
    source: SaveConfigSource,
    /// Retained operation kind.
    operation: SaveOperationKind,
    /// Source-order operation ordinal.
    operation_order: usize,
    /// Precedence rank, when the profile explicitly supplied one.
    precedence_rank: Option<usize>,
}

impl SaveConfigProvenance {
    /// Returns the exact source identity.
    pub const fn source(self) -> SaveConfigSource {
        self.source
    }

    /// Returns the selected operation kind.
    pub const fn operation(self) -> SaveOperationKind {
        self.operation
    }

    /// Returns the source-order operation ordinal.
    pub const fn operation_order(self) -> usize {
        self.operation_order
    }

    /// Returns the profile precedence rank.
    pub const fn precedence_rank(self) -> Option<usize> {
        self.precedence_rank
    }
}

/// Why a field resolution is intentionally unresolved.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum UnresolvedReason {
    /// The field is an unknown property and has no typed mapping.
    UnknownProperty,
}

/// The resolved or unresolved result for one field.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct SaveFieldResolution {
    field: SaveField,
    operations: Vec<SaveFieldOperation>,
    state: SaveFieldResolutionState,
}

/// Resolution state retained by [`SaveFieldResolution`].
#[derive(Clone, Eq, Hash, PartialEq)]
pub enum SaveFieldResolutionState {
    /// A known field has an explicit final value and provenance.
    Resolved {
        /// Final presence state.
        presence: FieldPresence,
        /// Final typed Java value, absent only for final absence.
        java_value: Option<JavaValue>,
        /// Selected wire representation.
        wire: WireRepresentation,
        /// Winning source operation.
        provenance: SaveConfigProvenance,
    },
    /// An unknown field remains retained but unresolved.
    Unresolved {
        /// Why no typed resolution was attempted.
        reason: UnresolvedReason,
    },
}

impl SaveFieldResolution {
    /// Returns the field key.
    pub fn field(&self) -> &SaveField {
        &self.field
    }

    /// Returns all source operations in insertion order.
    pub fn operations(&self) -> &[SaveFieldOperation] {
        &self.operations
    }

    /// Returns the resolution state.
    pub fn state(&self) -> &SaveFieldResolutionState {
        &self.state
    }

    /// Returns final presence for a resolved field.
    pub fn final_presence(&self) -> Option<FieldPresence> {
        match &self.state {
            SaveFieldResolutionState::Resolved { presence, .. } => Some(*presence),
            SaveFieldResolutionState::Unresolved { .. } => None,
        }
    }

    /// Returns final Java value for a resolved field.
    pub fn java_value(&self) -> Option<&JavaValue> {
        match &self.state {
            SaveFieldResolutionState::Resolved { java_value, .. } => java_value.as_ref(),
            SaveFieldResolutionState::Unresolved { .. } => None,
        }
    }

    /// Returns the selected wire representation for a resolved field.
    pub fn wire_representation(&self) -> Option<&WireRepresentation> {
        match &self.state {
            SaveFieldResolutionState::Resolved { wire, .. } => Some(wire),
            SaveFieldResolutionState::Unresolved { .. } => None,
        }
    }

    /// Returns final source provenance for a resolved field.
    pub fn provenance(&self) -> Option<SaveConfigProvenance> {
        match &self.state {
            SaveFieldResolutionState::Resolved { provenance, .. } => Some(*provenance),
            SaveFieldResolutionState::Unresolved { .. } => None,
        }
    }

    /// Returns whether this field is explicitly unresolved.
    pub const fn is_unresolved(&self) -> bool {
        matches!(self.state, SaveFieldResolutionState::Unresolved { .. })
    }
}

impl fmt::Debug for SaveFieldResolution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SaveFieldResolution")
            .field("field", &FieldDiagnostic(&self.field))
            .field("operation_count", &self.operations.len())
            .field("state", &self.state)
            .finish()
    }
}

impl fmt::Debug for SaveFieldResolutionState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolved {
                presence,
                java_value,
                wire,
                provenance,
            } => formatter
                .debug_struct("Resolved")
                .field("presence", presence)
                .field("java_value", java_value)
                .field("wire", wire)
                .field("provenance", provenance)
                .finish(),
            Self::Unresolved { reason } => formatter
                .debug_struct("Unresolved")
                .field("reason", reason)
                .finish(),
        }
    }
}

/// A bounded candidate interpretation attached to an ambiguity error.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct SaveConfigCandidate {
    field: SaveField,
    source: Option<SaveConfigSource>,
    operation: Option<SaveOperationKind>,
    operation_order: Option<usize>,
    presence: Option<FieldPresence>,
    java_value: Option<JavaValue>,
    wire_format: Option<SaveWireFormat>,
}

impl SaveConfigCandidate {
    /// Returns the candidate field.
    pub fn field(&self) -> &SaveField {
        &self.field
    }

    /// Returns candidate source provenance, if source ambiguity caused it.
    pub const fn source(&self) -> Option<SaveConfigSource> {
        self.source
    }

    /// Returns candidate operation kind.
    pub const fn operation(&self) -> Option<SaveOperationKind> {
        self.operation
    }

    /// Returns candidate source-order operation ordinal.
    pub const fn operation_order(&self) -> Option<usize> {
        self.operation_order
    }

    /// Returns candidate presence, if it is a source candidate.
    pub const fn presence(&self) -> Option<FieldPresence> {
        self.presence
    }

    /// Returns candidate Java value explicitly to a caller that handles the
    /// ambiguity; diagnostic formatting never prints it.
    pub fn java_value(&self) -> Option<&JavaValue> {
        self.java_value.as_ref()
    }

    /// Returns candidate wire target, if wire metadata caused ambiguity.
    pub const fn wire_format(&self) -> Option<SaveWireFormat> {
        self.wire_format
    }
}

impl fmt::Debug for SaveConfigCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SaveConfigCandidate")
            .field("field", &FieldDiagnostic(&self.field))
            .field("source", &self.source)
            .field("operation", &self.operation)
            .field("operation_order", &self.operation_order)
            .field("presence", &self.presence)
            .field(
                "value_bytes",
                &self.java_value.as_ref().map(JavaValue::byte_len),
            )
            .field("wire_format", &self.wire_format)
            .finish()
    }
}

/// A complete deterministic save-configuration resolution.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct SaveConfigResolution {
    profile_id: String,
    precedence: SaveConfigPrecedence,
    wire_format: SaveWireFormat,
    limits: SaveConfigLimits,
    fields: Vec<SaveFieldResolution>,
}

impl SaveConfigResolution {
    /// Returns the profile identity used to resolve this configuration.
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    /// Returns the explicit precedence table.
    pub fn precedence(&self) -> &SaveConfigPrecedence {
        &self.precedence
    }

    /// Returns the explicit output wire target.
    pub const fn wire_format(&self) -> SaveWireFormat {
        self.wire_format
    }

    /// Returns fields in deterministic [`SaveField`] order.
    pub fn fields(&self) -> &[SaveFieldResolution] {
        &self.fields
    }

    /// Finds one field without changing its retained operation order.
    pub fn field(&self, field: &SaveField) -> Option<&SaveFieldResolution> {
        self.fields
            .binary_search_by(|candidate| candidate.field.cmp(field))
            .ok()
            .map(|index| &self.fields[index])
    }

    /// Returns unresolved unknown-property fields.
    pub fn unresolved_fields(&self) -> impl Iterator<Item = &SaveFieldResolution> {
        self.fields.iter().filter(|field| field.is_unresolved())
    }

    /// Serializes the resolution in a bounded canonical form suitable for a
    /// later append/output identity digest.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SaveConfigError> {
        let mut output = Vec::new();
        append_bytes(&mut output, CANONICAL_VERSION)?;
        append_string(&mut output, &self.profile_id)?;
        append_byte(&mut output, self.wire_format.wire_tag())?;
        append_u16(&mut output, self.precedence.ordered_sources.len())?;
        for source in self.precedence.ordered_sources() {
            append_byte(&mut output, source.wire_tag())?;
        }
        append_u16(&mut output, self.fields.len())?;
        for field in &self.fields {
            append_field(&mut output, &field.field)?;
            append_u32(&mut output, field.operations.len())?;
            for operation in &field.operations {
                append_operation(&mut output, operation)?;
            }
            append_state(&mut output, &field.state)?;
        }
        if output.len() > MAX_SAVE_CONFIG_CANONICAL_BYTES {
            return Err(SaveConfigError::CanonicalizationLimit {
                actual: output.len(),
                maximum: MAX_SAVE_CONFIG_CANONICAL_BYTES,
            });
        }
        Ok(output)
    }

    /// Returns a SHA-256 digest of the bounded canonical resolution bytes.
    pub fn canonical_digest(&self) -> Result<[u8; 32], SaveConfigError> {
        Ok(sha256(&self.canonical_bytes()?))
    }
}

impl fmt::Debug for SaveConfigResolution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SaveConfigResolution")
            .field("profile_id_bytes", &self.profile_id.len())
            .field("precedence", &self.precedence)
            .field("wire_format", &self.wire_format)
            .field("field_count", &self.fields.len())
            .field("fields", &self.fields)
            .finish()
    }
}

/// A bounded resolver that retains source operations before resolving them.
pub struct SaveConfigResolver {
    precedence: SaveConfigPrecedence,
    wire_format: SaveWireFormat,
    limits: SaveConfigLimits,
    fields: BTreeMap<SaveField, Vec<SaveFieldOperation>>,
    operation_count: usize,
    total_value_bytes: usize,
}

impl SaveConfigResolver {
    /// Creates a resolver.  The precedence table, wire target, and limits are
    /// all explicit; no codec or Rust default is consulted.
    pub fn new(
        precedence: SaveConfigPrecedence,
        wire_format: SaveWireFormat,
        limits: SaveConfigLimits,
    ) -> Result<Self, SaveConfigError> {
        limits.validate()?;
        Ok(Self {
            precedence,
            wire_format,
            limits,
            fields: BTreeMap::new(),
            operation_count: 0,
            total_value_bytes: 0,
        })
    }

    /// Returns the explicit resource limits.
    pub const fn limits(&self) -> SaveConfigLimits {
        self.limits
    }

    /// Returns the number of retained fields.
    pub fn field_count(&self) -> usize {
        self.fields.len()
    }

    /// Returns the number of retained operations.
    pub const fn operation_count(&self) -> usize {
        self.operation_count
    }

    /// Returns operations for one field in source order.
    pub fn operations(&self, field: &SaveField) -> Option<&[SaveFieldOperation]> {
        self.fields.get(field).map(Vec::as_slice)
    }

    /// Appends one bounded source operation and assigns its source order.
    pub fn push(
        &mut self,
        field: SaveField,
        source: SaveConfigSource,
        operation: SaveConfigOperation,
    ) -> Result<usize, SaveConfigError> {
        self.validate_push_capacity(&field, source)?;
        self.validate_operation(&field, &operation)?;
        let operation_bytes = operation.value().map_or(0, JavaValue::byte_len);
        let next_total_value_bytes = self.total_value_bytes.checked_add(operation_bytes).ok_or(
            SaveConfigError::TotalValueLimitExceeded {
                actual: usize::MAX,
                maximum: self.limits.max_total_value_bytes(),
            },
        )?;
        if next_total_value_bytes > self.limits.max_total_value_bytes() {
            return Err(SaveConfigError::TotalValueLimitExceeded {
                actual: next_total_value_bytes,
                maximum: self.limits.max_total_value_bytes(),
            });
        }
        let order = self.operation_count;
        self.fields
            .entry(field)
            .or_insert_with(|| Vec::with_capacity(1))
            .push(SaveFieldOperation {
                source,
                operation,
                order,
            });
        self.operation_count += 1;
        self.total_value_bytes = next_total_value_bytes;
        Ok(order)
    }

    fn validate_push_capacity(
        &self,
        field: &SaveField,
        source: SaveConfigSource,
    ) -> Result<(), SaveConfigError> {
        field.validate_name()?;
        let field_bytes = field.property_name().map_or(0, str::len);
        if field_bytes > self.limits.max_text_bytes() {
            return Err(SaveConfigError::TextLimitExceeded {
                field: Some(field.clone()),
                actual: field_bytes,
                maximum: self.limits.max_text_bytes(),
            });
        }
        source.validate()?;
        if self.operation_count >= self.limits.max_operations() {
            return Err(SaveConfigError::TotalOperationLimitExceeded {
                actual: self.operation_count.saturating_add(1),
                maximum: self.limits.max_operations(),
            });
        }
        let is_new_field = !self.fields.contains_key(field);
        if is_new_field && self.fields.len() >= self.limits.max_fields() {
            return Err(SaveConfigError::FieldLimitExceeded {
                actual: self.fields.len().saturating_add(1),
                maximum: self.limits.max_fields(),
            });
        }
        if let Some(operations) = self.fields.get(field)
            && operations.len() >= self.limits.max_operations_per_field()
        {
            return Err(SaveConfigError::OperationLimitExceeded {
                field: field.clone(),
                actual: operations.len().saturating_add(1),
                maximum: self.limits.max_operations_per_field(),
            });
        }
        Ok(())
    }

    /// Parses and appends a raw value using known-field typing rules.
    pub fn push_raw(
        &mut self,
        field: SaveField,
        source: SaveConfigSource,
        operation_kind: SaveOperationKind,
        value: &str,
    ) -> Result<usize, SaveConfigError> {
        self.validate_push_capacity(&field, source)?;
        if value.len() > self.limits.max_text_bytes() {
            return Err(SaveConfigError::TextLimitExceeded {
                field: Some(field.clone()),
                actual: value.len(),
                maximum: self.limits.max_text_bytes(),
            });
        }
        let operation = match operation_kind {
            SaveOperationKind::Apply => SaveConfigOperation::apply_raw(&field, value)?,
            SaveOperationKind::Replace => match &field {
                SaveField::Known(field) => SaveConfigOperation::Replace(field.parse_raw(value)?),
                SaveField::Unknown(_) => SaveConfigOperation::Replace(JavaValue::raw(value)?),
            },
            SaveOperationKind::Remove => SaveConfigOperation::Remove,
            SaveOperationKind::Absent => SaveConfigOperation::Absent,
            SaveOperationKind::PresentEmpty => SaveConfigOperation::PresentEmpty,
        };
        self.push(field, source, operation)
    }

    /// Resolves all retained fields in deterministic field order.
    pub fn resolve(&self) -> Result<SaveConfigResolution, SaveConfigError> {
        let mut fields = Vec::with_capacity(self.fields.len());
        for (field, operations) in &self.fields {
            fields.push(self.resolve_field_operations(field, operations)?);
        }
        Ok(SaveConfigResolution {
            profile_id: self.precedence.profile_id.clone(),
            precedence: self.precedence.clone(),
            wire_format: self.wire_format,
            limits: self.limits,
            fields,
        })
    }

    /// Resolves one retained field without resolving unrelated fields.
    pub fn resolve_field(&self, field: &SaveField) -> Result<SaveFieldResolution, SaveConfigError> {
        let operations = self
            .fields
            .get(field)
            .ok_or_else(|| SaveConfigError::MissingField {
                field: field.clone(),
            })?;
        self.resolve_field_operations(field, operations)
    }

    fn validate_operation(
        &self,
        field: &SaveField,
        operation: &SaveConfigOperation,
    ) -> Result<(), SaveConfigError> {
        let Some(value) = operation.value() else {
            return Ok(());
        };
        let bytes = value.byte_len();
        if bytes > self.limits.max_text_bytes() {
            return Err(SaveConfigError::TextLimitExceeded {
                field: Some(field.clone()),
                actual: bytes,
                maximum: self.limits.max_text_bytes(),
            });
        }
        if let JavaValue::StringList(values) = value
            && values.len() > MAX_SAVE_CONFIG_TEXT_BYTES
        {
            return Err(SaveConfigError::TextLimitExceeded {
                field: Some(field.clone()),
                actual: values.len(),
                maximum: MAX_SAVE_CONFIG_TEXT_BYTES,
            });
        }
        if let SaveField::Known(known) = field {
            let expected = known.value_kind();
            let actual = value.kind();
            let compatible = match expected {
                SaveValueKind::String => matches!(actual, SaveValueKind::String),
                SaveValueKind::StringList => matches!(actual, SaveValueKind::StringList),
                _ => expected == actual,
            };
            if !compatible {
                return Err(SaveConfigError::InvalidValue {
                    field: field.clone(),
                    expected,
                    actual,
                });
            }
            match value {
                JavaValue::String(value) => known.validate_string_value(value)?,
                JavaValue::StringList(values)
                    if matches!(expected, SaveValueKind::StringList)
                        && (values.iter().any(String::is_empty)
                            || values
                                .iter()
                                .enumerate()
                                .any(|(index, value)| values[..index].contains(value))) =>
                {
                    return Err(SaveConfigError::InvalidValue {
                        field: field.clone(),
                        expected: SaveValueKind::StringList,
                        actual: SaveValueKind::StringList,
                    });
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn resolve_field_operations(
        &self,
        field: &SaveField,
        operations: &[SaveFieldOperation],
    ) -> Result<SaveFieldResolution, SaveConfigError> {
        if matches!(field, SaveField::Unknown(_)) {
            return Ok(SaveFieldResolution {
                field: field.clone(),
                operations: operations.to_vec(),
                state: SaveFieldResolutionState::Unresolved {
                    reason: UnresolvedReason::UnknownProperty,
                },
            });
        }

        let mut source_states: BTreeMap<SaveConfigSourceKind, SourceState> = BTreeMap::new();
        for operation in operations {
            let state = source_states
                .entry(operation.source.kind())
                .or_insert_with(|| SourceState {
                    source: operation.source,
                    active: None,
                    absent: None,
                });
            state.source = operation.source;
            match operation.operation() {
                SaveConfigOperation::Apply(value) | SaveConfigOperation::Replace(value) => {
                    state.active = Some(ActiveState {
                        source: operation.source,
                        kind: operation.operation().kind(),
                        order: operation.order,
                        presence: FieldPresence::Present,
                        value: Some(value.clone()),
                    });
                }
                SaveConfigOperation::Remove => {
                    state.active = Some(ActiveState {
                        source: operation.source,
                        kind: SaveOperationKind::Remove,
                        order: operation.order,
                        presence: FieldPresence::Absent,
                        value: None,
                    });
                }
                SaveConfigOperation::PresentEmpty => {
                    state.active = Some(ActiveState {
                        source: operation.source,
                        kind: SaveOperationKind::PresentEmpty,
                        order: operation.order,
                        presence: FieldPresence::PresentEmpty,
                        value: Some(JavaValue::String(String::new())),
                    });
                }
                SaveConfigOperation::Absent => {
                    state.active = None;
                    state.absent = Some(ActiveState {
                        source: operation.source,
                        kind: SaveOperationKind::Absent,
                        order: operation.order,
                        presence: FieldPresence::Absent,
                        value: None,
                    });
                }
            }
        }

        let active = source_states
            .values()
            .filter_map(|state| state.active.as_ref())
            .collect::<Vec<_>>();
        let missing_precedence = active
            .iter()
            .any(|state| self.precedence.rank(state.source.kind()).is_none());
        if missing_precedence {
            return Err(self.ambiguous_source_error(field, &active));
        }

        let selected = active
            .iter()
            .min_by_key(|state| {
                self.precedence
                    .rank(state.source.kind())
                    .unwrap_or(usize::MAX)
            })
            .copied();
        let selected = match selected {
            Some(state) => state,
            None => {
                let absent = source_states
                    .values()
                    .filter_map(|state| state.absent.as_ref())
                    .max_by_key(|state| state.order)
                    .ok_or_else(|| SaveConfigError::MissingField {
                        field: field.clone(),
                    })?;
                return self.make_resolution(
                    field,
                    operations,
                    absent,
                    self.precedence.rank(absent.source.kind()),
                );
            }
        };
        self.make_resolution(
            field,
            operations,
            selected,
            self.precedence.rank(selected.source.kind()),
        )
    }

    fn make_resolution(
        &self,
        field: &SaveField,
        operations: &[SaveFieldOperation],
        selected: &ActiveState,
        precedence_rank: Option<usize>,
    ) -> Result<SaveFieldResolution, SaveConfigError> {
        let wire = self.wire_for(field, selected.presence, selected.value.as_ref())?;
        Ok(SaveFieldResolution {
            field: field.clone(),
            operations: operations.to_vec(),
            state: SaveFieldResolutionState::Resolved {
                presence: selected.presence,
                java_value: selected.value.clone(),
                wire,
                provenance: SaveConfigProvenance {
                    source: selected.source,
                    operation: selected.kind,
                    operation_order: selected.order,
                    precedence_rank,
                },
            },
        })
    }

    fn wire_for(
        &self,
        field: &SaveField,
        presence: FieldPresence,
        value: Option<&JavaValue>,
    ) -> Result<WireRepresentation, SaveConfigError> {
        if self.wire_format == SaveWireFormat::Unknown && presence != FieldPresence::Absent {
            return Err(self.ambiguous_wire_error(field));
        }
        let name = match field {
            SaveField::Known(field) => match self.wire_format {
                SaveWireFormat::Csv => field.csv_header_name(),
                SaveWireFormat::Xml => field.xml_attribute_name(),
                SaveWireFormat::Properties => Some(field.property_name()),
                SaveWireFormat::Unknown => None,
            },
            SaveField::Unknown(_) => None,
        };
        let Some(name) = name else {
            return Ok(WireRepresentation::Omitted {
                format: self.wire_format,
            });
        };
        match presence {
            FieldPresence::Absent => Ok(WireRepresentation::Omitted {
                format: self.wire_format,
            }),
            FieldPresence::PresentEmpty => Ok(WireRepresentation::Empty {
                format: self.wire_format,
                name: name.to_owned(),
            }),
            FieldPresence::Present => Ok(WireRepresentation::Value {
                format: self.wire_format,
                name: name.to_owned(),
                value: value.map(JavaValue::to_wire_string).unwrap_or_default(),
            }),
        }
    }

    fn ambiguous_source_error(
        &self,
        field: &SaveField,
        active: &[&ActiveState],
    ) -> SaveConfigError {
        let mut candidates = Vec::with_capacity(self.limits.max_candidates().min(active.len()));
        for state in active.iter().take(self.limits.max_candidates()) {
            candidates.push(SaveConfigCandidate {
                field: field.clone(),
                source: Some(state.source),
                operation: Some(state.kind),
                operation_order: Some(state.order),
                presence: Some(state.presence),
                java_value: state.value.clone(),
                wire_format: None,
            });
        }
        SaveConfigError::Ambiguous {
            field: field.clone(),
            truncated: active.len() > candidates.len(),
            candidates,
        }
    }

    fn ambiguous_wire_error(&self, field: &SaveField) -> SaveConfigError {
        let formats = [
            SaveWireFormat::Csv,
            SaveWireFormat::Xml,
            SaveWireFormat::Properties,
        ];
        let candidates = formats
            .into_iter()
            .take(self.limits.max_candidates())
            .map(|format| SaveConfigCandidate {
                field: field.clone(),
                source: None,
                operation: None,
                operation_order: None,
                presence: None,
                java_value: None,
                wire_format: Some(format),
            })
            .collect::<Vec<_>>();
        SaveConfigError::Ambiguous {
            field: field.clone(),
            truncated: formats.len() > candidates.len(),
            candidates,
        }
    }
}

struct SourceState {
    source: SaveConfigSource,
    active: Option<ActiveState>,
    absent: Option<ActiveState>,
}

#[derive(Clone)]
struct ActiveState {
    source: SaveConfigSource,
    kind: SaveOperationKind,
    order: usize,
    presence: FieldPresence,
    value: Option<JavaValue>,
}

struct FieldDiagnostic<'a>(&'a SaveField);

impl fmt::Debug for FieldDiagnostic<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            SaveField::Known(field) => field.fmt(formatter),
            SaveField::Unknown(name) => formatter
                .debug_struct("UnknownField")
                .field("bytes", &name.len())
                .finish(),
        }
    }
}

fn validate_text(bytes: usize, field: Option<SaveField>) -> Result<(), SaveConfigError> {
    if bytes > MAX_SAVE_CONFIG_TEXT_BYTES {
        return Err(SaveConfigError::TextLimitExceeded {
            field,
            actual: bytes,
            maximum: MAX_SAVE_CONFIG_TEXT_BYTES,
        });
    }
    Ok(())
}

fn append_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), SaveConfigError> {
    let next =
        output
            .len()
            .checked_add(value.len())
            .ok_or(SaveConfigError::CanonicalizationLimit {
                actual: usize::MAX,
                maximum: MAX_SAVE_CONFIG_CANONICAL_BYTES,
            })?;
    if next > MAX_SAVE_CONFIG_CANONICAL_BYTES {
        return Err(SaveConfigError::CanonicalizationLimit {
            actual: next,
            maximum: MAX_SAVE_CONFIG_CANONICAL_BYTES,
        });
    }
    output.extend_from_slice(value);
    Ok(())
}

fn append_byte(output: &mut Vec<u8>, value: u8) -> Result<(), SaveConfigError> {
    append_bytes(output, &[value])
}

fn append_u16(output: &mut Vec<u8>, value: usize) -> Result<(), SaveConfigError> {
    let value = u16::try_from(value).map_err(|_| SaveConfigError::CanonicalizationLimit {
        actual: value,
        maximum: usize::from(u16::MAX),
    })?;
    append_bytes(output, &value.to_be_bytes())
}

fn append_u32(output: &mut Vec<u8>, value: usize) -> Result<(), SaveConfigError> {
    let value = u32::try_from(value).map_err(|_| SaveConfigError::CanonicalizationLimit {
        actual: value,
        maximum: u32::MAX as usize,
    })?;
    append_bytes(output, &value.to_be_bytes())
}

fn append_u64(output: &mut Vec<u8>, value: u64) -> Result<(), SaveConfigError> {
    append_bytes(output, &value.to_be_bytes())
}

fn append_string(output: &mut Vec<u8>, value: &str) -> Result<(), SaveConfigError> {
    append_u32(output, value.len())?;
    append_bytes(output, value.as_bytes())
}

fn append_field(output: &mut Vec<u8>, field: &SaveField) -> Result<(), SaveConfigError> {
    match field {
        SaveField::Known(field) => {
            append_byte(output, 0)?;
            append_u16(output, usize::from(field.wire_tag()))?;
        }
        SaveField::Unknown(name) => {
            append_byte(output, 1)?;
            append_string(output, name)?;
        }
    }
    Ok(())
}

fn append_operation(
    output: &mut Vec<u8>,
    operation: &SaveFieldOperation,
) -> Result<(), SaveConfigError> {
    append_byte(output, operation.source.wire_tag())?;
    append_u64(output, operation.source.detail_u64())?;
    append_u64(output, operation.order as u64)?;
    append_byte(
        output,
        match operation.operation.kind() {
            SaveOperationKind::Apply => 0,
            SaveOperationKind::Replace => 1,
            SaveOperationKind::Remove => 2,
            SaveOperationKind::Absent => 3,
            SaveOperationKind::PresentEmpty => 4,
        },
    )?;
    if let Some(value) = operation.operation.value() {
        append_byte(output, 1)?;
        append_java_value(output, value)?;
    } else {
        append_byte(output, 0)?;
    }
    Ok(())
}

fn append_java_value(output: &mut Vec<u8>, value: &JavaValue) -> Result<(), SaveConfigError> {
    match value {
        JavaValue::String(value) => {
            append_byte(output, 0)?;
            append_string(output, value)?;
        }
        JavaValue::Boolean(value) => {
            append_byte(output, 1)?;
            append_byte(output, u8::from(*value))?;
        }
        JavaValue::Integer(value) => {
            append_byte(output, 2)?;
            append_bytes(output, &value.to_be_bytes())?;
        }
        JavaValue::Long(value) => {
            append_byte(output, 3)?;
            append_bytes(output, &value.to_be_bytes())?;
        }
        JavaValue::StringList(values) => {
            append_byte(output, 4)?;
            append_u32(output, values.len())?;
            for value in values {
                append_string(output, value)?;
            }
        }
        JavaValue::Raw(value) => {
            append_byte(output, 5)?;
            append_string(output, value)?;
        }
    }
    Ok(())
}

fn append_state(
    output: &mut Vec<u8>,
    state: &SaveFieldResolutionState,
) -> Result<(), SaveConfigError> {
    match state {
        SaveFieldResolutionState::Unresolved { reason } => {
            append_byte(output, 0)?;
            append_byte(
                output,
                match reason {
                    UnresolvedReason::UnknownProperty => 0,
                },
            )?;
        }
        SaveFieldResolutionState::Resolved {
            presence,
            java_value,
            wire,
            provenance,
        } => {
            append_byte(output, 1)?;
            append_byte(
                output,
                match presence {
                    FieldPresence::Absent => 0,
                    FieldPresence::PresentEmpty => 1,
                    FieldPresence::Present => 2,
                },
            )?;
            match java_value {
                Some(value) => {
                    append_byte(output, 1)?;
                    append_java_value(output, value)?;
                }
                None => append_byte(output, 0)?,
            }
            append_wire(output, wire)?;
            append_byte(output, provenance.source.wire_tag())?;
            append_u64(output, provenance.source.detail_u64())?;
            append_byte(
                output,
                match provenance.operation {
                    SaveOperationKind::Apply => 0,
                    SaveOperationKind::Replace => 1,
                    SaveOperationKind::Remove => 2,
                    SaveOperationKind::Absent => 3,
                    SaveOperationKind::PresentEmpty => 4,
                },
            )?;
            append_u64(output, provenance.operation_order as u64)?;
            match provenance.precedence_rank {
                Some(rank) => {
                    append_byte(output, 1)?;
                    append_u64(output, rank as u64)?;
                }
                None => append_byte(output, 0)?,
            }
        }
    }
    Ok(())
}

fn append_wire(output: &mut Vec<u8>, wire: &WireRepresentation) -> Result<(), SaveConfigError> {
    match wire {
        WireRepresentation::Omitted { format } => {
            append_byte(output, 0)?;
            append_byte(output, format.wire_tag())?;
        }
        WireRepresentation::Empty { format, name } => {
            append_byte(output, 1)?;
            append_byte(output, format.wire_tag())?;
            append_string(output, name)?;
        }
        WireRepresentation::Value {
            format,
            name,
            value,
        } => {
            append_byte(output, 2)?;
            append_byte(output, format.wire_tag())?;
            append_string(output, name)?;
            append_string(output, value)?;
        }
    }
    Ok(())
}

// SHA-256 is kept local so this pure crate does not acquire a crypto/native
// dependency solely for the canonical identity required by Decision 0003.
fn sha256(input: &[u8]) -> [u8; 32] {
    const INITIAL: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const ROUND: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let bit_len = (input.len() as u64).wrapping_mul(8);
    let padded_len = input.len().saturating_add(1).saturating_add(8);
    let block_len = (padded_len + 63) & !63;
    let mut padded = Vec::with_capacity(block_len);
    padded.extend_from_slice(input);
    padded.push(0x80);
    padded.resize(block_len - 8, 0);
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut state = INITIAL;
    for block in padded.chunks_exact(64) {
        let mut schedule = [0u32; 64];
        for (index, word) in schedule[..16].iter_mut().enumerate() {
            let offset = index * 4;
            *word = u32::from_be_bytes([
                block[offset],
                block[offset + 1],
                block[offset + 2],
                block[offset + 3],
            ]);
        }
        for index in 16..64 {
            let s0 = schedule[index - 15].rotate_right(7)
                ^ schedule[index - 15].rotate_right(18)
                ^ (schedule[index - 15] >> 3);
            let s1 = schedule[index - 2].rotate_right(17)
                ^ schedule[index - 2].rotate_right(19)
                ^ (schedule[index - 2] >> 10);
            schedule[index] = schedule[index - 16]
                .wrapping_add(s0)
                .wrapping_add(schedule[index - 7])
                .wrapping_add(s1);
        }
        let mut working = state;
        for index in 0..64 {
            let s1 = working[4].rotate_right(6)
                ^ working[4].rotate_right(11)
                ^ working[4].rotate_right(25);
            let choice = (working[4] & working[5]) ^ ((!working[4]) & working[6]);
            let temp1 = working[7]
                .wrapping_add(s1)
                .wrapping_add(choice)
                .wrapping_add(ROUND[index])
                .wrapping_add(schedule[index]);
            let s0 = working[0].rotate_right(2)
                ^ working[0].rotate_right(13)
                ^ working[0].rotate_right(22);
            let majority =
                (working[0] & working[1]) ^ (working[0] & working[2]) ^ (working[1] & working[2]);
            let temp2 = s0.wrapping_add(majority);
            working[7] = working[6];
            working[6] = working[5];
            working[5] = working[4];
            working[4] = working[3].wrapping_add(temp1);
            working[3] = working[2];
            working[2] = working[1];
            working[1] = working[0];
            working[0] = temp1.wrapping_add(temp2);
        }
        for (target, value) in state.iter_mut().zip(working) {
            *target = target.wrapping_add(value);
        }
    }
    let mut digest = [0u8; 32];
    for (index, value) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&value.to_be_bytes());
    }
    digest
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn limits() -> SaveConfigLimits {
        SaveConfigLimits::new(8, 8, 32, 4, 128, 1024).expect("limits")
    }

    fn precedence() -> SaveConfigPrecedence {
        SaveConfigPrecedence::new(
            "jmeter-5.6.3",
            [
                SaveConfigSourceKind::CliMode,
                SaveConfigSourceKind::RunProperties,
                SaveConfigSourceKind::PlanSaveConfig,
                SaveConfigSourceKind::ReportInputMetadata,
                SaveConfigSourceKind::FormatObservation,
            ],
        )
        .expect("precedence")
    }

    fn field() -> SaveField {
        SaveField::known(SaveFieldId::TimestampFormat)
    }

    fn source(kind: SaveConfigSourceKind) -> SaveConfigSource {
        match kind {
            SaveConfigSourceKind::PlanSaveConfig => SaveConfigSource::PlanSaveConfig { node_id: 1 },
            SaveConfigSourceKind::RunProperties => SaveConfigSource::RunProperties { ordinal: 0 },
            SaveConfigSourceKind::CliMode => SaveConfigSource::CliMode {
                mode: CliMode::NormalRun,
            },
            SaveConfigSourceKind::ReportInputMetadata => SaveConfigSource::ReportInputMetadata {
                format: SaveWireFormat::Csv,
            },
            SaveConfigSourceKind::FormatObservation => SaveConfigSource::FormatObservation {
                format: SaveWireFormat::Csv,
            },
        }
    }

    fn typed_value(field: SaveFieldId, index: usize) -> JavaValue {
        match field.value_kind() {
            SaveValueKind::Boolean => JavaValue::boolean(index.is_multiple_of(2)),
            SaveValueKind::Integer => JavaValue::integer(index as i64),
            SaveValueKind::Long => JavaValue::long(index as i64),
            SaveValueKind::String => {
                let value = match field {
                    SaveFieldId::OutputFormat => "csv".to_owned(),
                    SaveFieldId::Assertions | SaveFieldId::AssertionResults => "all".to_owned(),
                    SaveFieldId::Delimiter => ",".to_owned(),
                    SaveFieldId::DefaultEncoding => "UTF-8".to_owned(),
                    _ => format!("value-{index}"),
                };
                JavaValue::string(value).expect("bounded test value")
            }
            SaveValueKind::StringList => {
                JavaValue::string_list([format!("value-{index}")]).expect("bounded test list")
            }
            SaveValueKind::Raw => {
                JavaValue::raw(format!("value-{index}")).expect("bounded test raw value")
            }
        }
    }

    #[test]
    fn every_known_field_retains_every_ordered_operation_kind() {
        let limits = SaveConfigLimits::new(64, 32, 4096, 8, 128, 4096).expect("limits");
        let mut resolver =
            SaveConfigResolver::new(precedence(), SaveWireFormat::Properties, limits)
                .expect("resolver");
        let operation_kinds = [
            SaveOperationKind::Apply,
            SaveOperationKind::Replace,
            SaveOperationKind::Remove,
            SaveOperationKind::Absent,
            SaveOperationKind::PresentEmpty,
        ];
        for (index, field_id) in SaveFieldId::all().into_iter().enumerate() {
            let field = SaveField::known(field_id);
            for source_kind in SaveConfigSourceKind::all() {
                for operation_kind in operation_kinds {
                    let operation = match operation_kind {
                        SaveOperationKind::Apply => {
                            SaveConfigOperation::apply(typed_value(field_id, index))
                        }
                        SaveOperationKind::Replace => {
                            SaveConfigOperation::replace(typed_value(field_id, index))
                        }
                        SaveOperationKind::Remove => SaveConfigOperation::remove(),
                        SaveOperationKind::Absent => SaveConfigOperation::absent(),
                        SaveOperationKind::PresentEmpty => SaveConfigOperation::present_empty(),
                    };
                    resolver
                        .push(field.clone(), source(source_kind), operation)
                        .expect("operation retained");
                }
            }
        }
        let resolution = resolver.resolve().expect("all fields resolve");
        assert_eq!(resolution.fields().len(), SaveFieldId::all().len());
        assert!(resolution.fields().iter().all(|field| {
            field.final_presence() == Some(FieldPresence::PresentEmpty)
                && field.operations().len()
                    == operation_kinds.len() * SaveConfigSourceKind::all().len()
                && field.provenance().is_some_and(|provenance| {
                    provenance.source().kind() == SaveConfigSourceKind::CliMode
                        && provenance.operation() == SaveOperationKind::PresentEmpty
                })
        }));
    }

    #[test]
    fn ordered_repeats_choose_last_operation_within_highest_source() {
        let mut resolver =
            SaveConfigResolver::new(precedence(), SaveWireFormat::Properties, limits())
                .expect("resolver");
        resolver
            .push_raw(
                field(),
                source(SaveConfigSourceKind::PlanSaveConfig),
                SaveOperationKind::Apply,
                "plan",
            )
            .expect("plan");
        resolver
            .push_raw(
                field(),
                source(SaveConfigSourceKind::RunProperties),
                SaveOperationKind::Apply,
                "property",
            )
            .expect("property");
        resolver
            .push_raw(
                field(),
                source(SaveConfigSourceKind::RunProperties),
                SaveOperationKind::Replace,
                "replacement",
            )
            .expect("replacement");
        let resolution = resolver.resolve().expect("resolution");
        let result = resolution.field(&field()).expect("field");
        assert_eq!(result.final_presence(), Some(FieldPresence::Present));
        assert_eq!(
            result.java_value().and_then(|value| match value {
                JavaValue::String(value) => Some(value.as_str()),
                _ => None,
            }),
            Some("replacement")
        );
        assert_eq!(result.operations().len(), 3);
        assert_eq!(
            result.provenance().map(SaveConfigProvenance::operation),
            Some(SaveOperationKind::Replace)
        );
        assert_eq!(
            result
                .wire_representation()
                .and_then(WireRepresentation::value),
            Some("replacement")
        );
    }

    #[test]
    fn remove_and_absent_have_distinct_source_semantics() {
        let mut resolver =
            SaveConfigResolver::new(precedence(), SaveWireFormat::Properties, limits())
                .expect("resolver");
        resolver
            .push_raw(
                field(),
                source(SaveConfigSourceKind::PlanSaveConfig),
                SaveOperationKind::Apply,
                "plan",
            )
            .expect("plan");
        resolver
            .push(
                field(),
                source(SaveConfigSourceKind::RunProperties),
                SaveConfigOperation::Absent,
            )
            .expect("absent");
        let inherited = resolver.resolve().expect("inherited");
        assert_eq!(
            inherited
                .field(&field())
                .and_then(SaveFieldResolution::java_value)
                .and_then(|value| match value {
                    JavaValue::String(value) => Some(value.as_str()),
                    _ => None,
                }),
            Some("plan")
        );

        let mut removed =
            SaveConfigResolver::new(precedence(), SaveWireFormat::Properties, limits())
                .expect("resolver");
        removed
            .push_raw(
                field(),
                source(SaveConfigSourceKind::PlanSaveConfig),
                SaveOperationKind::Apply,
                "plan",
            )
            .expect("plan");
        removed
            .push(
                field(),
                source(SaveConfigSourceKind::RunProperties),
                SaveConfigOperation::Remove,
            )
            .expect("remove");
        let result = removed.resolve().expect("removed");
        assert_eq!(
            result
                .field(&field())
                .and_then(SaveFieldResolution::final_presence),
            Some(FieldPresence::Absent)
        );
        assert_eq!(
            result
                .field(&field())
                .and_then(SaveFieldResolution::wire_representation)
                .and_then(WireRepresentation::value),
            None
        );
    }

    #[test]
    fn present_empty_is_not_absent_and_is_emitted_as_empty_wire_value() {
        let mut resolver =
            SaveConfigResolver::new(precedence(), SaveWireFormat::Csv, limits()).expect("resolver");
        let field = SaveField::known(SaveFieldId::Label);
        resolver
            .push(
                field.clone(),
                source(SaveConfigSourceKind::PlanSaveConfig),
                SaveConfigOperation::PresentEmpty,
            )
            .expect("empty");
        let result = resolver.resolve().expect("resolution");
        let field = result.field(&field).expect("field");
        assert_eq!(field.final_presence(), Some(FieldPresence::PresentEmpty));
        assert_eq!(
            field.java_value().map(JavaValue::to_wire_string),
            Some(String::new())
        );
        assert_eq!(
            field
                .wire_representation()
                .and_then(WireRepresentation::name),
            Some("label")
        );
        assert_eq!(
            field
                .wire_representation()
                .and_then(WireRepresentation::value),
            Some("")
        );
    }

    #[test]
    fn missing_profile_source_returns_bounded_ambiguity() {
        let table =
            SaveConfigPrecedence::new("partial-profile", [SaveConfigSourceKind::PlanSaveConfig])
                .expect("partial table");
        let mut resolver =
            SaveConfigResolver::new(table, SaveWireFormat::Csv, limits()).expect("resolver");
        resolver
            .push_raw(
                field(),
                source(SaveConfigSourceKind::RunProperties),
                SaveOperationKind::Apply,
                "property",
            )
            .expect("property");
        let error = resolver.resolve().expect_err("ambiguity");
        assert_eq!(error.stable_code(), "save-config.ambiguous");
        assert_eq!(error.candidates().len(), 1);
        assert_eq!(
            error.candidates()[0]
                .java_value()
                .map(JavaValue::to_wire_string),
            Some("property".to_owned())
        );
        assert!(format!("{error:?}").contains("value_bytes"));
        assert!(!format!("{error:?}").contains("property"));
    }

    #[test]
    fn ambiguity_candidates_obey_the_configured_bound() {
        let limits = SaveConfigLimits::new(8, 8, 32, 1, 128, 1024).expect("limits");
        let table = SaveConfigPrecedence::new("only-plan", [SaveConfigSourceKind::PlanSaveConfig])
            .expect("partial table");
        let mut resolver =
            SaveConfigResolver::new(table, SaveWireFormat::Csv, limits).expect("resolver");
        resolver
            .push_raw(
                field(),
                source(SaveConfigSourceKind::RunProperties),
                SaveOperationKind::Apply,
                "property",
            )
            .expect("property");
        resolver
            .push_raw(
                field(),
                source(SaveConfigSourceKind::CliMode),
                SaveOperationKind::Apply,
                "cli",
            )
            .expect("cli");
        let error = resolver.resolve().expect_err("ambiguity");
        assert_eq!(error.candidates().len(), 1);
        assert!(error.candidates_truncated());
    }

    #[test]
    fn unknown_properties_remain_explicitly_unresolved() {
        let unknown = SaveField::unknown("jmeter.save.saveservice.future_switch").expect("name");
        let mut resolver =
            SaveConfigResolver::new(precedence(), SaveWireFormat::Properties, limits())
                .expect("resolver");
        resolver
            .push_raw(
                unknown.clone(),
                source(SaveConfigSourceKind::RunProperties),
                SaveOperationKind::Apply,
                "future-value",
            )
            .expect("unknown");
        let resolution = resolver.resolve().expect("resolution");
        let field = resolution.field(&unknown).expect("unknown field");
        assert!(field.is_unresolved());
        assert_eq!(field.operations().len(), 1);
        assert_eq!(resolution.unresolved_fields().count(), 1);
        assert!(!format!("{resolution:?}").contains("future-value"));
    }

    #[test]
    fn explicit_wire_target_is_required_and_not_inferred_from_value() {
        let mut resolver = SaveConfigResolver::new(precedence(), SaveWireFormat::Unknown, limits())
            .expect("resolver");
        resolver
            .push_raw(
                field(),
                source(SaveConfigSourceKind::RunProperties),
                SaveOperationKind::Apply,
                "value",
            )
            .expect("value");
        let error = resolver.resolve().expect_err("wire ambiguity");
        assert_eq!(error.stable_code(), "save-config.ambiguous");
        assert_eq!(error.candidates().len(), 3);
        assert!(
            error
                .candidates()
                .iter()
                .all(|candidate| candidate.source().is_none())
        );
    }

    #[test]
    fn bounds_reject_before_operation_or_field_growth() {
        let limits = SaveConfigLimits::new(1, 1, 2, 1, 64, 4).expect("limits");
        let mut resolver =
            SaveConfigResolver::new(precedence(), SaveWireFormat::Csv, limits).expect("resolver");
        resolver
            .push_raw(
                field(),
                source(SaveConfigSourceKind::PlanSaveConfig),
                SaveOperationKind::Apply,
                "one",
            )
            .expect("first");
        let operation_error = resolver
            .push_raw(
                field(),
                source(SaveConfigSourceKind::PlanSaveConfig),
                SaveOperationKind::Apply,
                "two",
            )
            .expect_err("operation bound");
        assert!(matches!(
            operation_error,
            SaveConfigError::OperationLimitExceeded { .. }
        ));
        let field_error = resolver
            .push_raw(
                SaveField::known(SaveFieldId::Encoding),
                source(SaveConfigSourceKind::PlanSaveConfig),
                SaveOperationKind::Apply,
                "true",
            )
            .expect_err("field bound");
        assert!(matches!(
            field_error,
            SaveConfigError::FieldLimitExceeded { .. }
        ));
        let value_error = resolver
            .push_raw(
                field(),
                source(SaveConfigSourceKind::PlanSaveConfig),
                SaveOperationKind::Apply,
                "toolong",
            )
            .expect_err("value bound");
        assert!(matches!(
            value_error,
            SaveConfigError::TextLimitExceeded { .. }
                | SaveConfigError::OperationLimitExceeded { .. }
        ));
    }

    #[test]
    fn typed_operations_reject_wrong_public_values_and_missing_fields_do_not_default() {
        let limits = limits();
        let mut resolver =
            SaveConfigResolver::new(precedence(), SaveWireFormat::Properties, limits)
                .expect("resolver");
        let bool_field = SaveField::known(SaveFieldId::Time);
        let wrong = resolver.push(
            bool_field.clone(),
            source(SaveConfigSourceKind::RunProperties),
            SaveConfigOperation::apply(JavaValue::string("true").expect("bounded string value")),
        );
        assert!(matches!(
            wrong,
            Err(SaveConfigError::InvalidValue {
                expected: SaveValueKind::Boolean,
                actual: SaveValueKind::String,
                ..
            })
        ));
        let missing = resolver
            .resolve_field(&bool_field)
            .expect_err("missing field");
        assert_eq!(missing.stable_code(), "save-config.unresolved");
        assert!(
            resolver
                .resolve()
                .expect("empty resolution")
                .fields()
                .is_empty()
        );

        let list_field = SaveField::known(SaveFieldId::SampleVariables);
        let empty = resolver
            .push_raw(
                list_field,
                source(SaveConfigSourceKind::RunProperties),
                SaveOperationKind::Apply,
                "",
            )
            .expect("empty list");
        assert_eq!(empty, 0);
        let resolution = resolver.resolve().expect("list resolution");
        assert!(matches!(
            resolution
                .fields()
                .first()
                .and_then(SaveFieldResolution::java_value),
            Some(JavaValue::StringList(values)) if values.is_empty()
        ));
    }

    #[test]
    fn known_property_and_wire_names_are_not_normalized() {
        assert_eq!(
            SaveFieldId::ResponseDataOnError.property_name(),
            "jmeter.save.saveservice.response_data.on_error"
        );
        assert_eq!(
            SaveFieldId::SamplerData.property_name(),
            "jmeter.save.saveservice.samplerData"
        );
        assert_eq!(SaveFieldId::Timestamp.csv_header_name(), Some("timeStamp"));
        assert_eq!(SaveFieldId::Url.csv_header_name(), Some("URL"));
        assert_eq!(SaveFieldId::Timestamp.xml_attribute_name(), Some("ts"));
        assert_eq!(SaveFieldId::ResponseCode.xml_attribute_name(), Some("rc"));
        assert_eq!(SaveFieldId::SampleVariables.csv_header_name(), None);
        assert_eq!(
            SaveFieldId::from_property_name("jmeter.save.saveservice.failure_message"),
            Some(SaveFieldId::AssertionFailureMessage)
        );
        assert_eq!(
            SaveField::from_property_name("jmeter.save.saveservice.sample_variables")
                .expect("approved alias")
                .known_id(),
            Some(SaveFieldId::SampleVariables)
        );
        assert!(
            SaveField::from_property_name("jmeter.save.saveservice.future")
                .is_ok_and(|field| field.known_id().is_none())
        );
        assert!(
            SaveFieldId::all()
                .into_iter()
                .all(|field| !field.property_name().is_empty())
        );
    }

    #[test]
    fn malformed_known_string_values_return_redacted_typed_errors() {
        let mut resolver =
            SaveConfigResolver::new(precedence(), SaveWireFormat::Properties, limits())
                .expect("resolver");
        for (field, value) in [
            (SaveFieldId::OutputFormat, "json"),
            (SaveFieldId::Assertions, "sometimes"),
            (SaveFieldId::AssertionResults, "many"),
            (SaveFieldId::Delimiter, "ab"),
            (SaveFieldId::DefaultEncoding, ""),
        ] {
            let error = resolver
                .push_raw(
                    SaveField::known(field),
                    source(SaveConfigSourceKind::RunProperties),
                    SaveOperationKind::Apply,
                    value,
                )
                .expect_err("invalid known value");
            assert_eq!(error.stable_code(), "save-config.invalid_value");
            if !value.is_empty() {
                assert!(!format!("{error:?}").contains(value));
            }
        }
        let error = resolver
            .push_raw(
                SaveField::known(SaveFieldId::SampleVariables),
                source(SaveConfigSourceKind::RunProperties),
                SaveOperationKind::Apply,
                "case_id,case_id",
            )
            .expect_err("duplicate variable");
        assert_eq!(error.stable_code(), "save-config.invalid_value");
    }

    #[test]
    fn precedence_and_limit_constructors_reject_unbounded_or_ambiguous_tables() {
        assert!(matches!(
            SaveConfigLimits::new(0, 1, 1, 1, 1, 1),
            Err(SaveConfigError::InvalidLimit { .. })
        ));
        assert!(matches!(
            SaveConfigLimits::new(2, 3, 2, 1, 1, 1),
            Err(SaveConfigError::InvalidConfiguration { .. })
        ));
        assert!(matches!(
            SaveConfigPrecedence::new("profile", [SaveConfigSourceKind::RunProperties; 2]),
            Err(SaveConfigError::InvalidConfiguration {
                kind: SaveConfigConfigurationKind::DuplicateSource
            })
        ));
        assert!(matches!(
            SaveConfigPrecedence::new("profile", core::iter::empty()),
            Err(SaveConfigError::InvalidConfiguration {
                kind: SaveConfigConfigurationKind::Empty
            })
        ));
    }

    #[test]
    fn canonical_digest_is_stable_and_sha256_is_checked() {
        let mut first =
            SaveConfigResolver::new(precedence(), SaveWireFormat::Csv, limits()).expect("resolver");
        first
            .push_raw(
                field(),
                source(SaveConfigSourceKind::RunProperties),
                SaveOperationKind::Apply,
                "stable",
            )
            .expect("value");
        let first = first.resolve().expect("resolution");
        let first_digest = first.canonical_digest().expect("digest");
        let second_digest = first.canonical_digest().expect("digest");
        assert_eq!(first_digest, second_digest);

        let mut changed =
            SaveConfigResolver::new(precedence(), SaveWireFormat::Csv, limits()).expect("resolver");
        changed
            .push_raw(
                field(),
                source(SaveConfigSourceKind::RunProperties),
                SaveOperationKind::Replace,
                "stable",
            )
            .expect("value");
        assert_ne!(
            first_digest,
            changed
                .resolve()
                .expect("resolution")
                .canonical_digest()
                .expect("digest")
        );
        assert_eq!(
            sha256(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }
}
