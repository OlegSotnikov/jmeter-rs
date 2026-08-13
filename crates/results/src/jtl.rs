// SPDX-License-Identifier: Apache-2.0
//! Common configuration, limits, and errors for the JTL codecs.
//!
//! The codecs deliberately live in this crate rather than in the execution
//! runtime.  They consume immutable [`crate::SampleEvent`] snapshots and use only
//! `std::io::{Read, Write}` capabilities supplied by their caller.

use core::fmt;
use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::io::{self, Read};

use crate::ResultError;

/// Hard upper bound for the number of events retained by a convenience
/// `decode_all` call.
///
/// Streaming callers should prefer [`crate::CsvDecoder::next_event`] or
/// [`crate::XmlDecoder::next_event`] and apply their own sink/back-pressure
/// policy.  The bound is independent of [`JtlLimits::max_samples`] so a
/// caller cannot accidentally turn a collection helper into an unbounded
/// allocation by supplying a very large parser limit.
pub const MAX_DECODE_ALL_EVENTS: usize = 100_000;

/// Absolute product ceiling for bytes accepted from one JTL input stream.
///
/// Callers may select a lower bound for a particular run, but a public limits
/// value must never raise this protocol ceiling.  Keeping the ceiling in this
/// module makes every CSV/XML entry point apply the same policy.
pub const MAX_JTL_INPUT_BYTES: usize = 64 * 1024 * 1024;
/// Absolute product ceiling for bytes emitted by one JTL encoder.
pub const MAX_JTL_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
/// Absolute product ceiling for one CSV record or XML text fragment.
pub const MAX_JTL_RECORD_BYTES: usize = 16 * 1024 * 1024;
/// Absolute product ceiling for one XML attribute value.
pub const MAX_JTL_ATTRIBUTE_BYTES: usize = 4 * 1024 * 1024;
/// Absolute product ceiling for CSV columns in one record.
pub const MAX_JTL_COLUMNS: usize = 4_096;
/// Absolute product ceiling for XML nesting depth.
pub const MAX_JTL_DEPTH: usize = 512;
/// Absolute product ceiling for XML nodes/sample results in one document.
pub const MAX_JTL_NODES: usize = 1_000_000;
/// Absolute product ceiling for decoded or encoded result events.
pub const MAX_JTL_SAMPLES: usize = 1_000_000;
/// Absolute product ceiling for XML attributes on one element.
pub const MAX_JTL_ATTRIBUTES: usize = 4_096;
/// Compatibility name for the per-attribute payload ceiling.
pub const MAX_JTL_PAYLOAD_BYTES: usize = MAX_JTL_ATTRIBUTE_BYTES;
/// Compatibility name for the CSV field-count ceiling.
pub const MAX_JTL_FIELDS: usize = MAX_JTL_COLUMNS;

/// Policy applied to bytes emitted by a JTL encoder.
///
/// The ordinary codec constructors use [`Self::BoundedAggregate`], preserving
/// the finite aggregate limit used by the convenience helpers.  A caller
/// which owns a persistent result sink can opt into [`Self::Streaming`]:
/// events are still fully validated and staged under `max_event_bytes`, but a
/// stream is not rejected merely because its cumulative size grows beyond the
/// bounded convenience limit.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum JtlOutputPolicy {
    /// Reject output once the configured aggregate byte limit is reached.
    #[default]
    BoundedAggregate,
    /// Stage each event under a finite bound while allowing the persistent
    /// output stream to grow for as long as the checked counter can represent
    /// it.
    Streaming {
        /// Maximum bytes retained while staging one event.  This includes any
        /// header emitted as part of that first event.
        max_event_bytes: usize,
    },
}

impl JtlOutputPolicy {
    /// Returns a streaming policy with the crate's default finite staging
    /// bound.  The default is deliberately the same size as the default
    /// aggregate limit, but it is not an aggregate stream ceiling.
    pub const fn streaming_default() -> Self {
        Self::Streaming {
            max_event_bytes: 16 * 1024 * 1024,
        }
    }

    /// Validates a policy against the absolute product bound.
    pub fn validate(self) -> Result<(), JtlError> {
        if let Self::Streaming { max_event_bytes } = self {
            validate_jtl_bound("max_event_bytes", max_event_bytes, MAX_JTL_OUTPUT_BYTES)?;
        }
        Ok(())
    }

    /// Returns the finite per-event staging bound, if this policy is
    /// streaming.  Bounded aggregate encoders use their configured aggregate
    /// limit for staging instead.
    pub const fn max_event_bytes(self) -> Option<usize> {
        match self {
            Self::BoundedAggregate => None,
            Self::Streaming { max_event_bytes } => Some(max_event_bytes),
        }
    }
}

/// The output format selected by a JMeter save configuration.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum JtlFormat {
    /// Comma/delimiter separated result rows.
    #[default]
    Csv,
    /// JMeter's `testResults version="1.2"` XML format.
    Xml,
}

impl JtlFormat {
    /// Returns the canonical property spelling for this format.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Csv => "csv",
            Self::Xml => "xml",
        }
    }

    /// Parses a JMeter output-format value.
    ///
    /// Format selection is intentionally closed.  In particular, the
    /// historical `db` value is not mapped to either text codec, and unknown
    /// values do not silently fall back to CSV.
    pub fn parse(value: &str) -> Result<Self, JtlError> {
        match value.to_ascii_lowercase().as_str() {
            "csv" => Ok(Self::Csv),
            "xml" => Ok(Self::Xml),
            _ => Err(JtlError::InvalidConfiguration {
                field: "output_format",
                detail: format!("unsupported output format {value:?}"),
            }),
        }
    }
}

impl fmt::Display for JtlFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::str::FromStr for JtlFormat {
    type Err = JtlError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Timestamp representation used by CSV output and input.
///
/// JMeter accepts a Java `SimpleDateFormat` pattern in addition to the
/// special `ms` and `none` values.  Rust's standard library has no date
/// formatter, so the pattern is retained as a structured value and a caller
/// can provide a [`JavaDateFormatProvider`] to the bounded codecs.
#[derive(Clone, Default, Eq, Hash, PartialEq)]
pub enum TimestampFormat {
    /// Do not include a timestamp column/attribute.
    None,
    /// Milliseconds since the Unix epoch (`ms`).
    #[default]
    Milliseconds,
    /// A Java `SimpleDateFormat` pattern supplied by a profile adapter.
    JavaDateFormat(String),
}

impl fmt::Debug for TimestampFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => formatter.write_str("TimestampFormat::None"),
            Self::Milliseconds => formatter.write_str("TimestampFormat::Milliseconds"),
            Self::JavaDateFormat(pattern) => formatter
                .debug_struct("TimestampFormat::JavaDateFormat")
                .field("pattern_len", &pattern.len())
                .finish(),
        }
    }
}

impl TimestampFormat {
    /// Constructs a Java-date-pattern mode, retaining the pattern exactly.
    pub fn java(pattern: impl Into<String>) -> Self {
        Self::JavaDateFormat(pattern.into())
    }

    /// Returns whether the format writes a timestamp field.
    pub const fn is_enabled(&self) -> bool {
        !matches!(self, Self::None)
    }

    /// Returns the Java pattern, if this is [`TimestampFormat::JavaDateFormat`].
    pub fn pattern(&self) -> Option<&str> {
        match self {
            Self::JavaDateFormat(pattern) => Some(pattern),
            Self::None | Self::Milliseconds => None,
        }
    }
}

/// A caller-owned adapter for Java `SimpleDateFormat` patterns.
///
/// The trait is intentionally small and object-safe.  An application that
/// already has a Java worker can delegate these operations to it; tests can
/// provide a deterministic implementation without introducing a date/time
/// dependency into the pure results crate.
pub trait JavaDateFormatProvider {
    /// Formats Unix epoch milliseconds using `pattern`.
    fn format(&self, epoch_millis: i64, pattern: &str) -> Result<String, JtlError>;

    /// Parses a timestamp using `pattern` into Unix epoch milliseconds.
    fn parse(&self, value: &str, pattern: &str) -> Result<i64, JtlError>;
}

/// Alias retained for callers that use the shorter extension-point name.
pub use JavaDateFormatProvider as DateFormatProvider;

/// A deterministic line ending for CSV and XML writers.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum LineEnding {
    /// Unix line feed (`\n`).
    #[default]
    Lf,
    /// Windows carriage-return/line-feed (`\r\n`).
    CrLf,
    /// Classic Mac carriage return (`\r`).
    Cr,
}

impl LineEnding {
    /// Returns the wire spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lf => "\n",
            Self::CrLf => "\r\n",
            Self::Cr => "\r",
        }
    }

    /// Parses the explicit line-ending spellings accepted by the save
    /// configuration adapter.
    pub fn parse(value: &str) -> Result<Self, JtlError> {
        match value.to_ascii_lowercase().as_str() {
            "lf" | "\\n" => Ok(Self::Lf),
            "crlf" | "\\r\\n" => Ok(Self::CrLf),
            "cr" | "\\r" => Ok(Self::Cr),
            _ => Err(JtlError::InvalidConfiguration {
                field: "line_ending",
                detail: format!("unsupported line ending {value:?}"),
            }),
        }
    }
}

impl fmt::Display for LineEnding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::str::FromStr for LineEnding {
    type Err = JtlError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Which assertion rows XML should contain.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum AssertionResults {
    /// Do not write assertion results.
    None,
    /// Write only the first assertion result.
    First,
    /// Write every assertion result.
    #[default]
    All,
}

/// The XML element spelling used for a sample result.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum XmlSampleElement {
    /// Use the generic `<sample>` spelling.
    #[default]
    Sample,
    /// Use JMeter's HTTP alias `<httpSample>`.
    HttpSample,
}

/// The canonical CSV field vocabulary used by JMeter 5.6.3.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CsvField {
    /// Timestamp (`timeStamp`).
    Timestamp,
    /// Elapsed time (`elapsed`).
    Elapsed,
    /// Sample label (`label`).
    Label,
    /// Response code (`responseCode`).
    ResponseCode,
    /// Response message (`responseMessage`).
    ResponseMessage,
    /// Thread name (`threadName`).
    ThreadName,
    /// Data type (`dataType`).
    DataType,
    /// Successful flag (`success`).
    Success,
    /// First assertion failure (`failureMessage`).
    FailureMessage,
    /// Received bytes (`bytes`).
    Bytes,
    /// Sent bytes (`sentBytes`).
    SentBytes,
    /// Active threads in the group (`grpThreads`).
    GroupThreads,
    /// Active threads in all groups (`allThreads`).
    AllThreads,
    /// URL (`URL`).
    Url,
    /// Result file (`Filename`).
    Filename,
    /// Latency (`Latency`).
    Latency,
    /// Data encoding (`Encoding`).
    Encoding,
    /// Sample count (`SampleCount`).
    SampleCount,
    /// Error count (`ErrorCount`).
    ErrorCount,
    /// Hostname (`Hostname`).
    Hostname,
    /// Idle time (`IdleTime`).
    IdleTime,
    /// Connection time (`Connect`).
    Connect,
}

impl CsvField {
    /// Returns JMeter's exact header spelling.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Timestamp => "timeStamp",
            Self::Elapsed => "elapsed",
            Self::Label => "label",
            Self::ResponseCode => "responseCode",
            Self::ResponseMessage => "responseMessage",
            Self::ThreadName => "threadName",
            Self::DataType => "dataType",
            Self::Success => "success",
            Self::FailureMessage => "failureMessage",
            Self::Bytes => "bytes",
            Self::SentBytes => "sentBytes",
            Self::GroupThreads => "grpThreads",
            Self::AllThreads => "allThreads",
            Self::Url => "URL",
            Self::Filename => "Filename",
            Self::Latency => "Latency",
            Self::Encoding => "Encoding",
            Self::SampleCount => "SampleCount",
            Self::ErrorCount => "ErrorCount",
            Self::Hostname => "Hostname",
            Self::IdleTime => "IdleTime",
            Self::Connect => "Connect",
        }
    }

    /// Parses a canonical JMeter field name.
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "timeStamp" => Self::Timestamp,
            "elapsed" => Self::Elapsed,
            "label" => Self::Label,
            "responseCode" => Self::ResponseCode,
            "responseMessage" => Self::ResponseMessage,
            "threadName" => Self::ThreadName,
            "dataType" => Self::DataType,
            "success" => Self::Success,
            "failureMessage" => Self::FailureMessage,
            "bytes" => Self::Bytes,
            "sentBytes" => Self::SentBytes,
            "grpThreads" => Self::GroupThreads,
            "allThreads" => Self::AllThreads,
            "URL" => Self::Url,
            "Filename" => Self::Filename,
            "Latency" => Self::Latency,
            "Encoding" => Self::Encoding,
            "SampleCount" => Self::SampleCount,
            "ErrorCount" => Self::ErrorCount,
            "Hostname" => Self::Hostname,
            "IdleTime" => Self::IdleTime,
            "Connect" => Self::Connect,
            _ => return None,
        })
    }

    /// Returns this field's position in the canonical JMeter order.
    pub const fn order(self) -> usize {
        match self {
            Self::Timestamp => 0,
            Self::Elapsed => 1,
            Self::Label => 2,
            Self::ResponseCode => 3,
            Self::ResponseMessage => 4,
            Self::ThreadName => 5,
            Self::DataType => 6,
            Self::Success => 7,
            Self::FailureMessage => 8,
            Self::Bytes => 9,
            Self::SentBytes => 10,
            Self::GroupThreads => 11,
            Self::AllThreads => 12,
            Self::Url => 13,
            Self::Filename => 14,
            Self::Latency => 15,
            Self::Encoding => 16,
            Self::SampleCount => 17,
            Self::ErrorCount => 18,
            Self::Hostname => 19,
            Self::IdleTime => 20,
            Self::Connect => 21,
        }
    }
}

/// A CSV column, including a selected sample variable.
#[derive(Clone, Eq, Hash, PartialEq)]
pub enum CsvColumn {
    /// One of JMeter's built-in columns.
    Field(CsvField),
    /// A variable selected by `sample_variables`.
    Variable(String),
}

impl fmt::Debug for CsvColumn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Field(field) => formatter
                .debug_tuple("CsvColumn::Field")
                .field(field)
                .finish(),
            Self::Variable(name) => formatter
                .debug_struct("CsvColumn::Variable")
                .field("name_len", &name.len())
                .finish(),
        }
    }
}

impl CsvColumn {
    /// Returns the exact header token before CSV quoting.
    pub fn name(&self) -> &str {
        match self {
            Self::Field(field) => field.name(),
            Self::Variable(name) => name,
        }
    }
}

/// Bounds applied before allocating parser-owned strings or hierarchy nodes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct JtlLimits {
    /// Maximum bytes read from one input stream.
    pub max_input_bytes: usize,
    /// Maximum aggregate bytes emitted by a bounded encoder.
    ///
    /// This is separate from [`Self::max_record_bytes`]. The latter bounds
    /// one CSV record or XML output fragment; this bound prevents a
    /// long-lived bounded sink from producing an unbounded result stream. A
    /// [`JtlOutputPolicy::Streaming`] encoder uses its own finite
    /// `max_event_bytes` staging bound and does not apply this field to the
    /// cumulative persistent stream.
    pub max_output_bytes: usize,
    /// Maximum bytes in one CSV record or XML text node.
    pub max_record_bytes: usize,
    /// Maximum bytes in one XML attribute value.
    pub max_attribute_bytes: usize,
    /// Maximum CSV columns in one record.
    pub max_columns: usize,
    /// Maximum XML nesting depth, including the root.
    pub max_depth: usize,
    /// Maximum XML nodes/sample results in one document.
    pub max_nodes: usize,
    /// Maximum result events yielded by one decoder.
    pub max_samples: usize,
    /// Maximum XML attributes on one element.
    pub max_attributes: usize,
}

impl Default for JtlLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 16 * 1024 * 1024,
            max_output_bytes: 16 * 1024 * 1024,
            max_record_bytes: 4 * 1024 * 1024,
            max_attribute_bytes: 256 * 1024,
            max_columns: 512,
            max_depth: 128,
            max_nodes: 100_000,
            max_samples: 100_000,
            max_attributes: 256,
        }
    }
}

impl JtlLimits {
    /// Creates a limits value, rejecting zero bounds and values above the
    /// product ceilings declared by this module.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        max_input_bytes: usize,
        max_record_bytes: usize,
        max_attribute_bytes: usize,
        max_columns: usize,
        max_depth: usize,
        max_nodes: usize,
        max_samples: usize,
        max_attributes: usize,
    ) -> Result<Self, JtlError> {
        // `new` predates the aggregate output bound. Keep its stable
        // constructor shape and use the same finite default as the default
        // limits value; callers needing a smaller output bound can use
        // `with_max_output_bytes` or a struct update.
        let limits = Self {
            max_input_bytes,
            max_output_bytes: 16 * 1024 * 1024,
            max_record_bytes,
            max_attribute_bytes,
            max_columns,
            max_depth,
            max_nodes,
            max_samples,
            max_attributes,
        };
        limits.validate().map(|()| limits)
    }

    /// Validates a limits value constructed through a struct literal.
    ///
    /// Every dimension is finite, non-zero, and no wider than its absolute
    /// product ceiling.  This validation is called by all public CSV/XML
    /// constructors before they allocate parser or encoder state; an
    /// over-wide caller value is rejected rather than clamped.
    pub fn validate(self) -> Result<(), JtlError> {
        validate_jtl_bound("max_input_bytes", self.max_input_bytes, MAX_JTL_INPUT_BYTES)?;
        validate_jtl_bound(
            "max_output_bytes",
            self.max_output_bytes,
            MAX_JTL_OUTPUT_BYTES,
        )?;
        validate_jtl_bound(
            "max_record_bytes",
            self.max_record_bytes,
            MAX_JTL_RECORD_BYTES,
        )?;
        validate_jtl_bound(
            "max_attribute_bytes",
            self.max_attribute_bytes,
            MAX_JTL_ATTRIBUTE_BYTES,
        )?;
        validate_jtl_bound("max_columns", self.max_columns, MAX_JTL_COLUMNS)?;
        validate_jtl_bound("max_depth", self.max_depth, MAX_JTL_DEPTH)?;
        validate_jtl_bound("max_nodes", self.max_nodes, MAX_JTL_NODES)?;
        validate_jtl_bound("max_samples", self.max_samples, MAX_JTL_SAMPLES)?;
        validate_jtl_bound("max_attributes", self.max_attributes, MAX_JTL_ATTRIBUTES)?;
        Ok(())
    }

    /// Returns a copy with a caller-selected aggregate output bound.
    pub fn with_max_output_bytes(mut self, maximum: usize) -> Result<Self, JtlError> {
        self.max_output_bytes = maximum;
        self.validate()?;
        Ok(self)
    }
}

fn validate_jtl_bound(field: &'static str, value: usize, maximum: usize) -> Result<(), JtlError> {
    if value == 0 {
        return Err(JtlError::InvalidConfiguration {
            field,
            detail: "limit must be non-zero".to_owned(),
        });
    }
    if value > maximum {
        return Err(JtlError::InvalidConfiguration {
            field,
            detail: format!("limit {value} exceeds product maximum {maximum}"),
        });
    }
    Ok(())
}

/// A checked counter used by a JTL encoder.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum JtlCounter {
    /// Cumulative bytes published to the caller's writer.
    OutputBytes,
    /// Root result rows/events accepted by an encoder.
    Samples,
    /// XML nodes accepted by an encoder.
    Nodes,
}

impl JtlCounter {
    /// Returns the redacted diagnostic spelling for this counter.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OutputBytes => "output-bytes",
            Self::Samples => "samples",
            Self::Nodes => "nodes",
        }
    }
}

pub(crate) fn checked_counter_add(
    current: usize,
    increment: usize,
    counter: JtlCounter,
) -> Result<usize, JtlError> {
    current
        .checked_add(increment)
        .ok_or(JtlError::CounterOverflow { counter })
}

/// Error returned by CSV/XML result codecs.
pub enum JtlError {
    /// An underlying reader or writer failed.
    Io {
        /// The operation being performed.
        operation: &'static str,
        /// The platform error text, retained without exposing an `io::Error`
        /// in the pure public error shape.
        message: String,
    },
    /// A save configuration or limits value is invalid.
    InvalidConfiguration {
        /// Configuration member name.
        field: &'static str,
        /// Human-readable diagnostic detail.
        detail: String,
    },
    /// CSV syntax or field conversion failed.
    Csv {
        /// One-based record number when known.
        record: usize,
        /// Human-readable diagnostic detail.
        detail: String,
    },
    /// XML syntax or semantic conversion failed.
    Xml {
        /// Byte offset when known.
        offset: usize,
        /// Human-readable diagnostic detail.
        detail: String,
    },
    /// A valid JTL construct is outside this codec's lossless model.
    Unsupported {
        /// Stable capability name.
        feature: &'static str,
        /// Input spelling or explanatory value.
        value: String,
    },
    /// A checked output or hierarchy counter cannot represent its next value.
    CounterOverflow {
        /// Counter that would overflow.
        counter: JtlCounter,
    },
    /// The domain result model rejected parsed values or hierarchy limits.
    Model(ResultError),
}

/// A diagnostic marker which intentionally exposes only the size of dynamic
/// input.  CSV cells, XML attributes, file paths, and platform I/O messages
/// can contain credentials or response data, so neither `Debug` nor
/// `Display` may copy those strings into logs.
struct RedactedDiagnostic(usize);

impl fmt::Debug for RedactedDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "<redacted {} bytes>", self.0)
    }
}

impl fmt::Display for RedactedDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "<redacted {} bytes>", self.0)
    }
}

impl fmt::Debug for JtlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, message } => formatter
                .debug_struct("JtlError::Io")
                .field("code", &self.stable_code())
                .field("operation", operation)
                .field("message", &RedactedDiagnostic(message.len()))
                .finish(),
            Self::InvalidConfiguration { field, detail } => formatter
                .debug_struct("JtlError::InvalidConfiguration")
                .field("code", &self.stable_code())
                .field("field", field)
                .field("detail", &RedactedDiagnostic(detail.len()))
                .finish(),
            Self::Csv { record, detail } => formatter
                .debug_struct("JtlError::Csv")
                .field("code", &self.stable_code())
                .field("record", record)
                .field("detail", &RedactedDiagnostic(detail.len()))
                .finish(),
            Self::Xml { offset, detail } => formatter
                .debug_struct("JtlError::Xml")
                .field("code", &self.stable_code())
                .field("offset", offset)
                .field("detail", &RedactedDiagnostic(detail.len()))
                .finish(),
            Self::Unsupported { feature, value } => formatter
                .debug_struct("JtlError::Unsupported")
                .field("code", &self.stable_code())
                .field("feature", feature)
                .field("value", &RedactedDiagnostic(value.len()))
                .finish(),
            Self::CounterOverflow { counter } => formatter
                .debug_struct("JtlError::CounterOverflow")
                .field("code", &self.stable_code())
                .field("counter", counter)
                .finish(),
            Self::Model(error) => formatter
                .debug_struct("JtlError::Model")
                .field("code", &self.stable_code())
                .field("error", error)
                .finish(),
        }
    }
}

impl JtlError {
    /// Returns the stable machine-readable code.
    pub fn stable_code(&self) -> &'static str {
        match self {
            Self::Io { .. } => "results.jtl.io",
            Self::InvalidConfiguration { .. } => "results.jtl.invalid_configuration",
            Self::Csv { .. } => "results.jtl.csv",
            Self::Xml { .. } => "results.jtl.xml",
            Self::Unsupported { .. } => "results.jtl.unsupported",
            Self::CounterOverflow { .. } => "results.jtl.counter_overflow",
            Self::Model(error) => error.stable_code(),
        }
    }
}

impl fmt::Display for JtlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, message } => {
                write!(
                    formatter,
                    "{}: {operation}: {}",
                    self.stable_code(),
                    RedactedDiagnostic(message.len())
                )
            }
            Self::InvalidConfiguration { field, detail } => {
                write!(
                    formatter,
                    "{}: {field}: {}",
                    self.stable_code(),
                    RedactedDiagnostic(detail.len())
                )
            }
            Self::Csv { record, detail } => {
                write!(
                    formatter,
                    "{}: record {record}: {}",
                    self.stable_code(),
                    RedactedDiagnostic(detail.len())
                )
            }
            Self::Xml { offset, detail } => {
                write!(
                    formatter,
                    "{}: byte {offset}: {}",
                    self.stable_code(),
                    RedactedDiagnostic(detail.len())
                )
            }
            Self::Unsupported { feature, value } => {
                write!(
                    formatter,
                    "{}: {feature}: {}",
                    self.stable_code(),
                    RedactedDiagnostic(value.len())
                )
            }
            Self::CounterOverflow { counter } => {
                write!(formatter, "{}: {}", self.stable_code(), counter.as_str())
            }
            Self::Model(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for JtlError {}

impl From<ResultError> for JtlError {
    fn from(value: ResultError) -> Self {
        Self::Model(value)
    }
}

impl From<io::Error> for JtlError {
    fn from(value: io::Error) -> Self {
        Self::Io {
            operation: "I/O",
            message: value.to_string(),
        }
    }
}

/// Output configuration corresponding to JMeter's `SampleSaveConfiguration`.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct SampleSaveConfiguration {
    format: JtlFormat,
    timestamp_format: TimestampFormat,
    print_field_names: bool,
    delimiter: char,
    line_ending: LineEnding,
    save_time: bool,
    save_latency: bool,
    save_connect_time: bool,
    save_timestamp: bool,
    save_success: bool,
    save_label: bool,
    save_response_code: bool,
    save_response_message: bool,
    save_thread_name: bool,
    save_data_type: bool,
    save_encoding: bool,
    /// JMeter's boolean `assertions` switch is independent from the
    /// cardinality hint carried by `assertion_results`.  Keeping the switch
    /// separate is necessary because JMeter 5.6.3's XML converter consults
    /// `saveAssertions()` and writes every assertion when that switch is
    /// enabled, even when the cardinality hint is `none`.
    save_assertions_enabled: bool,
    save_assertions: AssertionResults,
    save_subresults: bool,
    save_response_data: bool,
    response_data_on_error: bool,
    /// Whether the result timestamp represents the sample start rather than
    /// the sample end.  The actual clock selection belongs to the runtime;
    /// retaining this property here keeps save configuration lossless.
    timestamp_start: bool,
    /// Whether the runtime may use a monotonic nano-time source for result
    /// timing.  Result codecs only retain the setting for the caller.
    use_nano_time: bool,
    /// Background nano-time offset refresh interval, in milliseconds.
    nano_thread_sleep: i64,
    /// Whether JMeter's sub-result label renaming policy is disabled.
    subresults_disable_renaming: bool,
    /// Optional default response-data encoding used by the runtime when a
    /// sampler does not provide one.
    default_encoding: Option<String>,
    /// Flush each completed record when requested by the save service.
    autoflush: bool,
    save_sampler_data: bool,
    save_response_headers: bool,
    save_request_headers: bool,
    save_bytes: bool,
    save_sent_bytes: bool,
    save_url: bool,
    save_filename: bool,
    save_hostname: bool,
    save_thread_counts: bool,
    /// JMeter's one save-service switch controls both `SampleCount` and
    /// `ErrorCount` wire fields. The result model retains the two typed
    /// counters independently; only their output selection is coupled here.
    save_sample_count: bool,
    save_idle_time: bool,
    save_assertion_failure_message: bool,
    sample_variables: Vec<String>,
    xml_sample_element: XmlSampleElement,
}

impl fmt::Debug for SampleSaveConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SampleSaveConfiguration")
            .field("format", &self.format)
            .field("timestamp_format", &self.timestamp_format)
            .field("print_field_names", &self.print_field_names)
            .field("delimiter", &self.delimiter)
            .field("line_ending", &self.line_ending)
            .field("save_time", &self.save_time)
            .field("save_latency", &self.save_latency)
            .field("save_connect_time", &self.save_connect_time)
            .field("save_timestamp", &self.save_timestamp)
            .field("save_success", &self.save_success)
            .field("save_label", &self.save_label)
            .field("save_response_code", &self.save_response_code)
            .field("save_response_message", &self.save_response_message)
            .field("save_thread_name", &self.save_thread_name)
            .field("save_data_type", &self.save_data_type)
            .field("save_encoding", &self.save_encoding)
            .field("save_assertions_enabled", &self.save_assertions_enabled)
            .field("save_assertions", &self.save_assertions)
            .field("save_subresults", &self.save_subresults)
            .field("save_response_data", &self.save_response_data)
            .field("response_data_on_error", &self.response_data_on_error)
            .field("timestamp_start", &self.timestamp_start)
            .field("use_nano_time", &self.use_nano_time)
            .field("nano_thread_sleep", &self.nano_thread_sleep)
            .field(
                "subresults_disable_renaming",
                &self.subresults_disable_renaming,
            )
            .field(
                "default_encoding_len",
                &self.default_encoding.as_ref().map(String::len),
            )
            .field("autoflush", &self.autoflush)
            .field("save_sampler_data", &self.save_sampler_data)
            .field("save_response_headers", &self.save_response_headers)
            .field("save_request_headers", &self.save_request_headers)
            .field("save_bytes", &self.save_bytes)
            .field("save_sent_bytes", &self.save_sent_bytes)
            .field("save_url", &self.save_url)
            .field("save_filename", &self.save_filename)
            .field("save_hostname", &self.save_hostname)
            .field("save_thread_counts", &self.save_thread_counts)
            .field("save_sample_count_and_error_count", &self.save_sample_count)
            .field("save_idle_time", &self.save_idle_time)
            .field(
                "save_assertion_failure_message",
                &self.save_assertion_failure_message,
            )
            .field("sample_variable_count", &self.sample_variables.len())
            .field("xml_sample_element", &self.xml_sample_element)
            .finish()
    }
}

impl Default for SampleSaveConfiguration {
    fn default() -> Self {
        Self {
            format: JtlFormat::Csv,
            timestamp_format: TimestampFormat::Milliseconds,
            print_field_names: true,
            delimiter: ',',
            line_ending: LineEnding::Lf,
            save_time: true,
            save_latency: true,
            save_connect_time: true,
            save_timestamp: true,
            save_success: true,
            save_label: true,
            save_response_code: true,
            save_response_message: true,
            save_thread_name: true,
            save_data_type: true,
            save_encoding: false,
            // JMeter's static boolean `assertions` switch defaults to true.
            // The separate cardinality hint defaults to `none`, but the
            // 5.6.3 XML converter does not consult that hint when deciding
            // whether to write assertion rows.
            save_assertions_enabled: true,
            save_assertions: AssertionResults::None,
            save_subresults: true,
            save_response_data: false,
            response_data_on_error: false,
            // The pinned JMeter 5.6.3 `bin/jmeter.properties` enables
            // `sampleresult.timestamp.start`; retain that property-level
            // default while still allowing callers to opt into end-time.
            timestamp_start: true,
            use_nano_time: true,
            nano_thread_sleep: 5_000,
            subresults_disable_renaming: false,
            default_encoding: Some("UTF-8".to_owned()),
            autoflush: false,
            save_sampler_data: false,
            save_response_headers: false,
            save_request_headers: false,
            save_bytes: true,
            save_sent_bytes: true,
            save_url: true,
            save_filename: false,
            save_hostname: false,
            save_thread_counts: true,
            save_sample_count: false,
            save_idle_time: true,
            save_assertion_failure_message: true,
            sample_variables: Vec::new(),
            xml_sample_element: XmlSampleElement::Sample,
        }
    }
}

impl SampleSaveConfiguration {
    /// Creates JMeter's default CSV save configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a default XML configuration.
    pub fn xml() -> Self {
        Self {
            format: JtlFormat::Xml,
            ..Self::default()
        }
    }

    /// Creates a default CSV configuration.
    pub fn csv() -> Self {
        Self::default()
    }

    /// Builds a save configuration from JMeter property names.
    ///
    /// Unrelated JMeter properties are ignored; malformed values for a
    /// recognized save-service property return a typed configuration error.
    pub fn from_properties<I, K, V>(properties: I) -> Result<Self, JtlError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let mut configuration = Self::default();
        for (key, value) in properties {
            configuration.apply_property(key.as_ref(), value.as_ref())?;
        }
        configuration.validate()?;
        Ok(configuration)
    }

    /// Builds a save configuration from an ordered property map.
    pub fn from_property_map(properties: &BTreeMap<String, String>) -> Result<Self, JtlError> {
        Self::from_properties(properties.iter())
    }

    fn apply_property(&mut self, key: &str, value: &str) -> Result<(), JtlError> {
        let bool_value = || {
            if value.eq_ignore_ascii_case("true") {
                Ok(true)
            } else if value.eq_ignore_ascii_case("false") {
                Ok(false)
            } else {
                Err(JtlError::InvalidConfiguration {
                    field: "save-service-property",
                    detail: format!("{key} must be true or false, got {value:?}"),
                })
            }
        };
        match key {
            "jmeter.save.saveservice.output_format" => {
                self.format = JtlFormat::parse(value)?;
            }
            "jmeter.save.saveservice.timestamp_format" => {
                self.timestamp_format = match value.to_ascii_lowercase().as_str() {
                    "none" => TimestampFormat::None,
                    "ms" => TimestampFormat::Milliseconds,
                    _ => TimestampFormat::JavaDateFormat(value.to_owned()),
                };
            }
            "jmeter.save.saveservice.default_delimiter" => self.set_delimiter_str(value)?,
            "jmeter.save.saveservice.print_field_names" => self.print_field_names = bool_value()?,
            "jmeter.save.saveservice.time" => self.save_time = bool_value()?,
            "jmeter.save.saveservice.latency" => self.save_latency = bool_value()?,
            "jmeter.save.saveservice.connect_time" => self.save_connect_time = bool_value()?,
            "jmeter.save.saveservice.timestamp" => self.save_timestamp = bool_value()?,
            "jmeter.save.saveservice.successful" => self.save_success = bool_value()?,
            "jmeter.save.saveservice.label" => self.save_label = bool_value()?,
            "jmeter.save.saveservice.response_code" => self.save_response_code = bool_value()?,
            "jmeter.save.saveservice.response_message" => {
                self.save_response_message = bool_value()?
            }
            "jmeter.save.saveservice.thread_name" => self.save_thread_name = bool_value()?,
            "jmeter.save.saveservice.data_type" => self.save_data_type = bool_value()?,
            "jmeter.save.saveservice.encoding" => self.save_encoding = bool_value()?,
            // JMeter 5.6.3 still accepts the boolean `assertions` switch in
            // addition to the newer `assertion_results` cardinality setting.
            // A true switch enables all results unless a cardinality was
            // explicitly selected; a false switch disables them.
            "jmeter.save.saveservice.assertions" => match value.to_ascii_lowercase().as_str() {
                "true" => {
                    self.save_assertions_enabled = true;
                }
                "false" | "none" => {
                    self.save_assertions_enabled = false;
                    self.save_assertions = AssertionResults::None;
                }
                "first" => {
                    self.save_assertions_enabled = true;
                    self.save_assertions = AssertionResults::First;
                }
                "all" => {
                    self.save_assertions_enabled = true;
                    self.save_assertions = AssertionResults::All;
                }
                _ => {
                    return Err(JtlError::InvalidConfiguration {
                        field: "assertions",
                        detail: format!("expected true, false, none, first, or all, got {value:?}"),
                    });
                }
            },
            "jmeter.save.saveservice.assertion_results" => {
                self.save_assertions = match value.to_ascii_lowercase().as_str() {
                    "none" => {
                        self.save_assertions_enabled = false;
                        AssertionResults::None
                    }
                    "first" => AssertionResults::First,
                    "all" => AssertionResults::All,
                    _ => {
                        return Err(JtlError::InvalidConfiguration {
                            field: "assertion_results",
                            detail: format!("expected none, first, or all, got {value:?}"),
                        });
                    }
                };
            }
            "jmeter.save.saveservice.subresults" => self.save_subresults = bool_value()?,
            "jmeter.save.saveservice.response_data" => self.save_response_data = bool_value()?,
            "jmeter.save.saveservice.response_data.on_error" => {
                self.response_data_on_error = bool_value()?
            }
            "jmeter.save.saveservice.samplerData" => self.save_sampler_data = bool_value()?,
            "jmeter.save.saveservice.responseHeaders" => self.save_response_headers = bool_value()?,
            "jmeter.save.saveservice.requestHeaders" => self.save_request_headers = bool_value()?,
            "jmeter.save.saveservice.bytes" => self.save_bytes = bool_value()?,
            "jmeter.save.saveservice.sent_bytes" => self.save_sent_bytes = bool_value()?,
            "jmeter.save.saveservice.url" => self.save_url = bool_value()?,
            "jmeter.save.saveservice.filename" => self.save_filename = bool_value()?,
            "jmeter.save.saveservice.hostname" => self.save_hostname = bool_value()?,
            "jmeter.save.saveservice.thread_counts" => self.save_thread_counts = bool_value()?,
            "jmeter.save.saveservice.sample_count" => self.save_sample_count = bool_value()?,
            // 5.6.3 has no independent save-service error-count property. Do
            // not turn an unknown property into a wire shape JMeter cannot
            // emit; callers select both fields with `sample_count`.
            "jmeter.save.saveservice.error_count" => {
                return Err(JtlError::Unsupported {
                    feature: "jtl-save-property",
                    value: key.to_owned(),
                });
            }
            "jmeter.save.saveservice.idle_time" => self.save_idle_time = bool_value()?,
            "jmeter.save.saveservice.assertion_results_failure_message" => {
                self.save_assertion_failure_message = bool_value()?
            }
            "jmeter.save.saveservice.failure_message" => {
                self.save_assertion_failure_message = bool_value()?
            }
            "sampleresult.timestamp.start" => self.timestamp_start = bool_value()?,
            "sampleresult.useNanoTime" => self.use_nano_time = bool_value()?,
            "sampleresult.nanoThreadSleep" => {
                self.nano_thread_sleep = value.parse::<i64>().map_err(|_| {
                    JtlError::InvalidConfiguration {
                        field: "sampleresult.nanoThreadSleep",
                        detail: format!(
                            "sampleresult.nanoThreadSleep must be a signed integer, got {value:?}"
                        ),
                    }
                })?;
            }
            "subresults.disable_renaming" => self.subresults_disable_renaming = bool_value()?,
            "sampleresult.default.encoding" => {
                self.default_encoding = Some(value.to_owned());
            }
            "jmeter.save.saveservice.autoflush" => self.autoflush = bool_value()?,
            "line_ending" => self.line_ending = LineEnding::parse(value)?,
            // These properties require an external path/document policy that
            // the pure results crate cannot infer.  Recognize them and fail
            // explicitly instead of silently dropping the setting.
            "jmeter.save.saveservice.xml_pi" => {
                return Err(JtlError::Unsupported {
                    feature: "xml-processing-instruction",
                    value: value.to_owned(),
                });
            }
            "jmeter.save.saveservice.base_prefix" => {
                return Err(JtlError::Unsupported {
                    feature: "jtl-base-prefix",
                    value: value.to_owned(),
                });
            }
            // JMeter's properties reference uses the unprefixed key, while
            // some save-service integrations expose it alongside the other
            // `jmeter.save.saveservice.*` entries.  Accept both spellings;
            // the resulting column list is identical.
            "sample_variables" | "jmeter.save.saveservice.sample_variables" => {
                let variables = if value.is_empty() {
                    Vec::new()
                } else {
                    value.split(',').collect::<Vec<_>>()
                };
                self.set_sample_variables(variables)?;
            }
            key if key.starts_with("jmeter.save.saveservice.") => {
                return Err(JtlError::Unsupported {
                    feature: "jtl-save-property",
                    value: key.to_owned(),
                });
            }
            _ => {}
        }
        Ok(())
    }

    /// Returns the selected format.
    pub const fn format(&self) -> JtlFormat {
        self.format
    }

    /// Validates this configuration for a particular codec dispatch.
    ///
    /// The concrete CSV/XML constructors predate the format marker and can
    /// still be used independently. The dispatch API is stricter: a caller
    /// selecting XML cannot accidentally route an XML configuration to the
    /// CSV writer (or vice versa).
    pub fn validate_for_format(&self, expected: JtlFormat) -> Result<(), JtlError> {
        self.validate()?;
        if self.format != expected {
            return Err(JtlError::InvalidConfiguration {
                field: "output_format",
                detail: format!(
                    "configuration selects {}, but the requested codec is {}",
                    self.format, expected
                ),
            });
        }
        Ok(())
    }

    /// Sets the selected format.
    pub const fn set_format(&mut self, format: JtlFormat) {
        self.format = format;
    }

    /// Returns the timestamp mode.
    pub fn timestamp_format(&self) -> &TimestampFormat {
        &self.timestamp_format
    }

    /// Sets the timestamp mode.
    pub fn set_timestamp_format(&mut self, format: TimestampFormat) {
        self.timestamp_format = format;
    }

    /// Builder-style timestamp mode setter.
    pub fn with_timestamp_format(mut self, format: TimestampFormat) -> Self {
        self.set_timestamp_format(format);
        self
    }

    /// Returns whether the timestamp setting is enabled and not `none`.
    pub fn timestamp_column_enabled(&self) -> bool {
        self.save_timestamp && self.timestamp_format.is_enabled()
    }

    /// Returns whether serialized timestamps are configured as sample-start
    /// timestamps.  The runtime is responsible for selecting the actual
    /// timestamp value before constructing a result event.
    pub const fn timestamp_start(&self) -> bool {
        self.timestamp_start
    }

    /// Sets whether serialized timestamps represent sample start.
    pub const fn set_timestamp_start(&mut self, value: bool) {
        self.timestamp_start = value;
    }

    /// Returns whether a runtime nano-time source is enabled.
    pub const fn use_nano_time(&self) -> bool {
        self.use_nano_time
    }

    /// Sets whether a runtime nano-time source is enabled.
    pub const fn set_use_nano_time(&mut self, value: bool) {
        self.use_nano_time = value;
    }

    /// Returns the configured nano-time offset refresh interval.
    pub const fn nano_thread_sleep(&self) -> i64 {
        self.nano_thread_sleep
    }

    /// Sets the nano-time offset refresh interval.
    pub const fn set_nano_thread_sleep(&mut self, value: i64) {
        self.nano_thread_sleep = value;
    }

    /// Returns whether sub-result label renaming is disabled.
    pub const fn subresults_disable_renaming(&self) -> bool {
        self.subresults_disable_renaming
    }

    /// Sets whether sub-result label renaming is disabled.
    pub const fn set_subresults_disable_renaming(&mut self, value: bool) {
        self.subresults_disable_renaming = value;
    }

    /// Returns the optional runtime default response-data encoding.
    pub fn default_encoding(&self) -> Option<&str> {
        self.default_encoding.as_deref()
    }

    /// Sets the optional runtime default response-data encoding.
    pub fn set_default_encoding(&mut self, value: Option<String>) {
        self.default_encoding = value;
    }

    /// Returns whether each completed output record is flushed immediately.
    pub const fn autoflush(&self) -> bool {
        self.autoflush
    }

    /// Sets immediate output flushing.
    pub const fn set_autoflush(&mut self, value: bool) {
        self.autoflush = value;
    }

    /// Returns whether CSV field names are written/read.
    pub const fn print_field_names(&self) -> bool {
        self.print_field_names
    }

    /// Sets whether CSV field names are written.
    pub const fn set_print_field_names(&mut self, value: bool) {
        self.print_field_names = value;
    }

    /// Alias matching the JMeter save-configuration vocabulary.
    pub const fn save_field_names(&self) -> bool {
        self.print_field_names()
    }

    /// Sets whether CSV field names are written.
    pub const fn set_field_names(&mut self, value: bool) {
        self.set_print_field_names(value);
    }

    /// Returns the delimiter character.
    pub const fn delimiter(&self) -> char {
        self.delimiter
    }

    /// Sets and validates the delimiter character.
    pub fn set_delimiter(&mut self, delimiter: char) -> Result<(), JtlError> {
        validate_delimiter(delimiter)?;
        self.delimiter = delimiter;
        Ok(())
    }

    /// Sets a delimiter from JMeter's property spelling (`\t` is accepted).
    pub fn set_delimiter_str(&mut self, delimiter: &str) -> Result<(), JtlError> {
        let delimiter = match delimiter {
            "\\t" | "TAB" | "tab" => '\t',
            value => {
                let mut chars = value.chars();
                let Some(character) = chars.next() else {
                    return Err(JtlError::InvalidConfiguration {
                        field: "delimiter",
                        detail: "delimiter must not be empty".to_owned(),
                    });
                };
                if chars.next().is_some() {
                    return Err(JtlError::InvalidConfiguration {
                        field: "delimiter",
                        detail: "delimiter must be one character or \\t".to_owned(),
                    });
                }
                character
            }
        };
        self.set_delimiter(delimiter)
    }

    /// Builder-style delimiter setter.
    pub fn with_delimiter(mut self, delimiter: char) -> Result<Self, JtlError> {
        self.set_delimiter(delimiter)?;
        Ok(self)
    }

    /// Returns the selected JTL text line ending used by CSV and XML output.
    pub const fn line_ending(&self) -> LineEnding {
        self.line_ending
    }

    /// Sets the JTL text line ending used by CSV and XML output.
    pub const fn set_line_ending(&mut self, value: LineEnding) {
        self.line_ending = value;
    }

    /// Returns the XML sample element spelling.
    pub const fn xml_sample_element(&self) -> XmlSampleElement {
        self.xml_sample_element
    }

    /// Sets the XML sample element spelling.
    pub const fn set_xml_sample_element(&mut self, value: XmlSampleElement) {
        self.xml_sample_element = value;
    }

    /// Returns selected sample variables in configured order.
    pub fn sample_variables(&self) -> &[String] {
        &self.sample_variables
    }

    /// Replaces selected sample variables, rejecting empty/duplicate names.
    pub fn set_sample_variables<I, S>(&mut self, variables: I) -> Result<(), JtlError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut values = Vec::new();
        for variable in variables {
            let variable = variable.into();
            if variable.is_empty() {
                return Err(JtlError::InvalidConfiguration {
                    field: "sample_variables",
                    detail: "variable names must not be empty".to_owned(),
                });
            }
            // Validate at the setter boundary as well as in `validate`, so a
            // malformed name cannot remain in an otherwise mutable config.
            xml_attribute_name(&variable)?;
            if values.iter().any(|existing: &String| existing == &variable) {
                return Err(JtlError::InvalidConfiguration {
                    field: "sample_variables",
                    detail: format!("duplicate variable {variable:?}"),
                });
            }
            values.push(variable);
        }
        self.sample_variables = values;
        Ok(())
    }

    /// Builder-style selected-variable setter.
    pub fn with_sample_variables<I, S>(mut self, variables: I) -> Result<Self, JtlError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.set_sample_variables(variables)?;
        Ok(self)
    }

    /// Returns the configured assertion selection.
    pub const fn assertion_results(&self) -> AssertionResults {
        self.save_assertions
    }

    /// Sets the configured assertion selection.
    pub const fn set_assertion_results(&mut self, value: AssertionResults) {
        self.save_assertions_enabled = !matches!(value, AssertionResults::None);
        self.save_assertions = value;
    }

    /// Alias for setting assertion selection.
    pub const fn set_assertions(&mut self, value: AssertionResults) {
        self.set_assertion_results(value);
    }

    /// Returns whether assertions are saved at all.
    pub const fn save_assertions(&self) -> bool {
        self.save_assertions_enabled
    }

    /// Returns the assertion cardinality used by the XML converter.
    ///
    /// A default JMeter configuration has `assertions=true` and a separate
    /// cardinality hint of `none`; the 5.6.3 converter writes all assertions
    /// in that state.  Explicit API/property disablement is represented by
    /// `save_assertions_enabled=false`.
    pub(crate) const fn assertion_selection(&self) -> AssertionResults {
        if !self.save_assertions_enabled {
            AssertionResults::None
        } else {
            match self.save_assertions {
                AssertionResults::None => AssertionResults::All,
                selection => selection,
            }
        }
    }

    /// Returns whether sub-results are saved.
    pub const fn save_subresults(&self) -> bool {
        self.save_subresults
    }

    /// Sets whether nested sub-results are saved.
    pub const fn set_subresults(&mut self, value: bool) {
        self.save_subresults = value;
    }

    /// Returns whether response data is saved.
    pub const fn save_response_data(&self) -> bool {
        self.save_response_data
    }

    /// Returns whether response data/sampler data is saved for failed samples.
    pub const fn save_response_data_on_error(&self) -> bool {
        self.response_data_on_error
    }

    /// Returns whether sampler data is saved.
    pub const fn save_sampler_data(&self) -> bool {
        self.save_sampler_data
    }

    /// Returns whether response headers are saved.
    pub const fn save_response_headers(&self) -> bool {
        self.save_response_headers
    }

    /// Returns whether request headers are saved.
    pub const fn save_request_headers(&self) -> bool {
        self.save_request_headers
    }

    /// Returns whether a given CSV/XML field is enabled.
    pub fn saves(&self, field: CsvField) -> bool {
        match field {
            CsvField::Timestamp => self.timestamp_column_enabled(),
            CsvField::Elapsed => self.save_time,
            CsvField::Label => self.save_label,
            CsvField::ResponseCode => self.save_response_code,
            CsvField::ResponseMessage => self.save_response_message,
            CsvField::ThreadName => self.save_thread_name,
            CsvField::DataType => self.save_data_type,
            CsvField::Success => self.save_success,
            CsvField::FailureMessage => self.save_assertion_failure_message,
            CsvField::Bytes => self.save_bytes,
            CsvField::SentBytes => self.save_sent_bytes,
            CsvField::GroupThreads | CsvField::AllThreads => self.save_thread_counts,
            CsvField::Url => self.save_url,
            CsvField::Filename => self.save_filename,
            CsvField::Latency => self.save_latency,
            CsvField::Encoding => self.save_encoding,
            CsvField::SampleCount | CsvField::ErrorCount => self.save_sample_count,
            CsvField::Hostname => self.save_hostname,
            CsvField::IdleTime => self.save_idle_time,
            CsvField::Connect => self.save_connect_time,
        }
    }

    /// Counts the columns that [`Self::columns`] would materialize without
    /// allocating the returned vector.  Decoders use this to reject an
    /// oversized configured layout before constructing it.
    pub(crate) fn column_count(&self) -> Result<usize, JtlError> {
        let fields = [
            CsvField::Timestamp,
            CsvField::Elapsed,
            CsvField::Label,
            CsvField::ResponseCode,
            CsvField::ResponseMessage,
            CsvField::ThreadName,
            CsvField::DataType,
            CsvField::Success,
            CsvField::FailureMessage,
            CsvField::Bytes,
            CsvField::SentBytes,
            CsvField::GroupThreads,
            CsvField::AllThreads,
            CsvField::Url,
            CsvField::Filename,
            CsvField::Latency,
            CsvField::Encoding,
            CsvField::SampleCount,
            CsvField::ErrorCount,
            CsvField::Hostname,
            CsvField::IdleTime,
            CsvField::Connect,
        ];
        let enabled = fields.iter().filter(|field| self.saves(**field)).count();
        enabled
            .checked_add(self.sample_variables.len())
            .ok_or_else(|| JtlError::Unsupported {
                feature: "csv-column-limit",
                value: "configured column count overflow".to_owned(),
            })
    }

    /// Returns the canonical enabled columns, followed by sample variables.
    pub fn columns(&self) -> Vec<CsvColumn> {
        let fields = [
            CsvField::Timestamp,
            CsvField::Elapsed,
            CsvField::Label,
            CsvField::ResponseCode,
            CsvField::ResponseMessage,
            CsvField::ThreadName,
            CsvField::DataType,
            CsvField::Success,
            CsvField::FailureMessage,
            CsvField::Bytes,
            CsvField::SentBytes,
            CsvField::GroupThreads,
            CsvField::AllThreads,
            CsvField::Url,
            CsvField::Filename,
            CsvField::Latency,
            CsvField::Encoding,
            CsvField::SampleCount,
            CsvField::ErrorCount,
            CsvField::Hostname,
            CsvField::IdleTime,
            CsvField::Connect,
        ];
        let mut columns = fields
            .into_iter()
            .filter(|field| self.saves(*field))
            .map(CsvColumn::Field)
            .collect::<Vec<_>>();
        columns.extend(
            self.sample_variables
                .iter()
                .cloned()
                .map(CsvColumn::Variable),
        );
        columns
    }

    /// Enables/disables elapsed time (`time`).
    pub const fn set_time(&mut self, value: bool) {
        self.save_time = value;
    }
    /// Returns whether elapsed time is enabled.
    pub const fn save_time(&self) -> bool {
        self.save_time
    }
    /// Alias for [`SampleSaveConfiguration::save_time`].
    pub const fn time(&self) -> bool {
        self.save_time()
    }
    /// Enables/disables latency.
    pub const fn set_latency(&mut self, value: bool) {
        self.save_latency = value;
    }
    /// Returns whether latency is enabled.
    pub const fn save_latency(&self) -> bool {
        self.save_latency
    }
    /// Enables/disables connection time.
    pub const fn set_connect_time(&mut self, value: bool) {
        self.save_connect_time = value;
    }
    /// Returns whether connection time is enabled.
    pub const fn save_connect_time(&self) -> bool {
        self.save_connect_time
    }
    /// Enables/disables timestamp.
    pub const fn set_timestamp(&mut self, value: bool) {
        self.save_timestamp = value;
    }
    /// Returns whether timestamp is enabled before timestamp-mode filtering.
    pub const fn save_timestamp(&self) -> bool {
        self.save_timestamp
    }
    /// Enables/disables success.
    pub const fn set_success(&mut self, value: bool) {
        self.save_success = value;
    }
    /// Returns whether success is enabled.
    pub const fn save_success(&self) -> bool {
        self.save_success
    }
    /// Enables/disables labels.
    pub const fn set_label(&mut self, value: bool) {
        self.save_label = value;
    }
    /// Returns whether labels are enabled.
    pub const fn save_label(&self) -> bool {
        self.save_label
    }
    /// Enables/disables response codes.
    pub const fn set_response_code(&mut self, value: bool) {
        self.save_response_code = value;
    }
    /// Returns whether response codes are enabled.
    pub const fn save_response_code(&self) -> bool {
        self.save_response_code
    }
    /// Enables/disables response messages.
    pub const fn set_response_message(&mut self, value: bool) {
        self.save_response_message = value;
    }
    /// Returns whether response messages are enabled.
    pub const fn save_response_message(&self) -> bool {
        self.save_response_message
    }
    /// Enables/disables thread names.
    pub const fn set_thread_name(&mut self, value: bool) {
        self.save_thread_name = value;
    }
    /// Returns whether thread names are enabled.
    pub const fn save_thread_name(&self) -> bool {
        self.save_thread_name
    }
    /// Enables/disables data type.
    pub const fn set_data_type(&mut self, value: bool) {
        self.save_data_type = value;
    }
    /// Returns whether data type is enabled.
    pub const fn save_data_type(&self) -> bool {
        self.save_data_type
    }
    /// Enables/disables encoding.
    pub const fn set_encoding(&mut self, value: bool) {
        self.save_encoding = value;
    }
    /// Returns whether encoding is enabled.
    pub const fn save_encoding(&self) -> bool {
        self.save_encoding
    }
    /// Enables/disables assertion failure message field.
    pub const fn set_assertion_results_failure_message(&mut self, value: bool) {
        self.save_assertion_failure_message = value;
    }
    /// Returns whether assertion failure message is enabled.
    pub const fn save_assertion_results_failure_message(&self) -> bool {
        self.save_assertion_failure_message
    }
    /// Enables/disables response data.
    pub const fn set_response_data(&mut self, value: bool) {
        self.save_response_data = value;
    }
    /// Enables/disables response data on error.
    pub const fn set_response_data_on_error(&mut self, value: bool) {
        self.response_data_on_error = value;
    }
    /// Enables/disables sampler data.
    pub const fn set_sampler_data(&mut self, value: bool) {
        self.save_sampler_data = value;
    }
    /// Enables/disables response headers.
    pub const fn set_response_headers(&mut self, value: bool) {
        self.save_response_headers = value;
    }
    /// Enables/disables request headers.
    pub const fn set_request_headers(&mut self, value: bool) {
        self.save_request_headers = value;
    }
    /// Enables/disables received bytes.
    pub const fn set_bytes(&mut self, value: bool) {
        self.save_bytes = value;
    }
    /// Returns whether received bytes are enabled.
    pub const fn save_bytes(&self) -> bool {
        self.save_bytes
    }
    /// Enables/disables sent bytes.
    pub const fn set_sent_bytes(&mut self, value: bool) {
        self.save_sent_bytes = value;
    }
    /// Returns whether sent bytes are enabled.
    pub const fn save_sent_bytes(&self) -> bool {
        self.save_sent_bytes
    }
    /// Enables/disables URL.
    pub const fn set_url(&mut self, value: bool) {
        self.save_url = value;
    }
    /// Returns whether URL is enabled.
    pub const fn save_url(&self) -> bool {
        self.save_url
    }
    /// Enables/disables result filename.
    pub const fn set_filename(&mut self, value: bool) {
        self.save_filename = value;
    }
    /// Returns whether filename is enabled.
    pub const fn save_filename(&self) -> bool {
        self.save_filename
    }
    /// Alias using JMeter's `FileName` spelling.
    pub const fn set_file_name(&mut self, value: bool) {
        self.set_filename(value);
    }
    /// Alias using JMeter's `FileName` spelling.
    pub const fn save_file_name(&self) -> bool {
        self.save_filename()
    }
    /// Enables/disables hostname.
    pub const fn set_hostname(&mut self, value: bool) {
        self.save_hostname = value;
    }
    /// Returns whether hostname is enabled.
    pub const fn save_hostname(&self) -> bool {
        self.save_hostname
    }
    /// Enables/disables thread counts.
    pub const fn set_thread_counts(&mut self, value: bool) {
        self.save_thread_counts = value;
    }
    /// Returns whether thread counts are enabled.
    pub const fn save_thread_counts(&self) -> bool {
        self.save_thread_counts
    }
    /// Enables/disables sample/error counts.
    pub const fn set_sample_count(&mut self, value: bool) {
        self.save_sample_count = value;
    }
    /// Returns whether sample/error counts are enabled.
    pub const fn save_sample_count(&self) -> bool {
        self.save_sample_count
    }

    /// Enables/disables the JMeter `SampleCount` and `ErrorCount` columns
    /// together. The method name is retained as a source-compatible alias;
    /// JMeter 5.6.3 does not expose an independent error-count switch.
    pub const fn set_error_count(&mut self, value: bool) {
        self.save_sample_count = value;
    }

    /// Returns whether the coupled `SampleCount`/`ErrorCount` columns are
    /// enabled. This is a source-compatible alias for
    /// [`SampleSaveConfiguration::save_sample_count`].
    pub const fn save_error_count(&self) -> bool {
        self.save_sample_count
    }
    /// Enables/disables idle time.
    pub const fn set_idle_time(&mut self, value: bool) {
        self.save_idle_time = value;
    }
    /// Returns whether idle time is enabled.
    pub const fn save_idle_time(&self) -> bool {
        self.save_idle_time
    }
    /// Returns whether a failed sample should emit response data.
    pub fn should_save_response_data(&self, result_success: Option<bool>) -> bool {
        self.save_response_data || (self.response_data_on_error && result_success == Some(false))
    }

    /// Returns whether sampler/request data is emitted for a result.
    ///
    /// JMeter applies `response_data.on_error` to both `responseData` and
    /// `samplerData`; the latter is easy to miss because it is controlled by
    /// a separate save-service switch when the sample succeeds.
    pub fn should_save_sampler_data(&self, result_success: Option<bool>) -> bool {
        self.save_sampler_data || (self.response_data_on_error && result_success == Some(false))
    }

    /// Validates all configuration constraints used by both codecs.
    pub fn validate(&self) -> Result<(), JtlError> {
        validate_delimiter(self.delimiter)?;
        if matches!(self.format, JtlFormat::Csv)
            && (self.save_response_data || self.response_data_on_error)
        {
            return Err(JtlError::Unsupported {
                feature: "csv-response-data",
                value: "response_data is not supported for CSV output".to_owned(),
            });
        }
        if self.default_encoding.as_deref().is_some_and(str::is_empty) {
            return Err(JtlError::InvalidConfiguration {
                field: "default_encoding",
                detail: "default encoding must not be empty".to_owned(),
            });
        }
        if let TimestampFormat::JavaDateFormat(pattern) = &self.timestamp_format
            && pattern.is_empty()
        {
            return Err(JtlError::InvalidConfiguration {
                field: "timestamp_format",
                detail: "Java date format pattern must not be empty".to_owned(),
            });
        }
        let mut xml_names = Vec::new();
        let reserved_xml_names = [
            "t", "it", "lt", "ct", "ts", "s", "lb", "rc", "rs", "rm", "tn", "dt", "de", "by",
            "sby", "sc", "ec", "ng", "na", "hn",
        ];
        for variable in &self.sample_variables {
            // JMeter writes configured sample-variable names literally as XML
            // attributes.  Validate the exact wire spelling here; do not
            // apply the old doubled-underscore extension transform.
            let encoded = xml_attribute_name(variable)?;
            if reserved_xml_names.contains(&encoded.as_str()) {
                return Err(JtlError::InvalidConfiguration {
                    field: "sample_variables",
                    detail: format!(
                        "sample variable {variable:?} collides with XML attribute {encoded:?}"
                    ),
                });
            }
            if xml_names.iter().any(|name: &String| name == &encoded) {
                return Err(JtlError::InvalidConfiguration {
                    field: "sample_variables",
                    detail: format!("XML attribute name collision for {variable:?}"),
                });
            }
            xml_names.push(encoded);
        }
        Ok(())
    }
}

/// A format-dispatching JTL encoder with explicit bounded or streaming output
/// policy.
///
/// This adapter is intentionally small: the format-specific codecs retain
/// their independent wire contracts, while callers that select a format from
/// save-service configuration get one fail-closed entry point. Java date
/// formatting remains an explicit provider capability on the CSV variant.
pub enum JtlEncoder<'a, W> {
    /// CSV encoder selected by [`JtlFormat::Csv`].
    Csv(Box<crate::csv::CsvEncoder<'a, W>>),
    /// XML encoder selected by [`JtlFormat::Xml`].
    Xml(Box<crate::xml::XmlEncoder<W>>),
}

impl<'a, W: io::Write> JtlEncoder<'a, W> {
    /// Creates a format-dispatching encoder under the default bounds.
    pub fn new(writer: W, configuration: SampleSaveConfiguration) -> Result<Self, JtlError> {
        match configuration.format() {
            JtlFormat::Csv => {
                configuration.validate_for_format(JtlFormat::Csv)?;
                Ok(Self::Csv(Box::new(crate::csv::CsvEncoder::new(
                    writer,
                    configuration,
                )?)))
            }
            JtlFormat::Xml => {
                configuration.validate_for_format(JtlFormat::Xml)?;
                Ok(Self::Xml(Box::new(crate::xml::XmlEncoder::new(
                    writer,
                    configuration,
                )?)))
            }
        }
    }

    /// Creates a streaming encoder with the default finite per-event staging
    /// bound.  Unlike [`Self::new`], this constructor does not apply the
    /// aggregate `JtlLimits::max_output_bytes` ceiling to the persistent
    /// stream.
    pub fn streaming(writer: W, configuration: SampleSaveConfiguration) -> Result<Self, JtlError> {
        Self::new(writer, configuration)?.with_output_policy(JtlOutputPolicy::streaming_default())
    }

    /// Creates a streaming encoder with an explicit finite per-event staging
    /// bound.
    pub fn streaming_with_event_limit(
        writer: W,
        configuration: SampleSaveConfiguration,
        max_event_bytes: usize,
    ) -> Result<Self, JtlError> {
        Self::new(writer, configuration)?
            .with_output_policy(JtlOutputPolicy::Streaming { max_event_bytes })
    }

    /// Replaces parser/output bounds on the selected format.
    pub fn with_limits(self, limits: JtlLimits) -> Result<Self, JtlError> {
        match self {
            Self::Csv(encoder) => Ok(Self::Csv(Box::new((*encoder).with_limits(limits)?))),
            Self::Xml(encoder) => Ok(Self::Xml(Box::new((*encoder).with_limits(limits)?))),
        }
    }

    /// Selects the output policy for the chosen codec.
    pub fn with_output_policy(self, policy: JtlOutputPolicy) -> Result<Self, JtlError> {
        policy.validate()?;
        match self {
            Self::Csv(encoder) => Ok(Self::Csv(Box::new((*encoder).with_output_policy(policy)?))),
            Self::Xml(encoder) => Ok(Self::Xml(Box::new((*encoder).with_output_policy(policy)?))),
        }
    }

    /// Returns the output policy currently applied to the chosen codec.
    pub fn output_policy(&self) -> JtlOutputPolicy {
        match self {
            Self::Csv(encoder) => encoder.output_policy(),
            Self::Xml(encoder) => encoder.output_policy(),
        }
    }

    /// Returns the checked number of bytes published so far.
    pub fn bytes_written(&self) -> usize {
        match self {
            Self::Csv(encoder) => encoder.bytes_written(),
            Self::Xml(encoder) => encoder.bytes_written(),
        }
    }

    /// Returns the checked number of result rows/events published so far.
    pub fn samples_written(&self) -> usize {
        match self {
            Self::Csv(encoder) => encoder.samples_written(),
            Self::Xml(encoder) => encoder.samples_written(),
        }
    }

    /// Installs a Java-date-format provider on the CSV variant.
    pub fn with_date_provider(self, provider: &'a dyn DateFormatProvider) -> Self {
        match self {
            Self::Csv(encoder) => Self::Csv(Box::new((*encoder).with_date_provider(provider))),
            Self::Xml(encoder) => Self::Xml(encoder),
        }
    }

    /// Writes the format header/root start.
    pub fn write_header(&mut self) -> Result<(), JtlError> {
        match self {
            Self::Csv(encoder) => encoder.write_header(),
            Self::Xml(encoder) => encoder.write_header(),
        }
    }

    /// Writes one immutable event without flattening or dropping fields.
    pub fn write_event(&mut self, event: &crate::SampleEvent) -> Result<(), JtlError> {
        match self {
            Self::Csv(encoder) => encoder.write_event(event),
            Self::Xml(encoder) => encoder.write_event(event),
        }
    }

    /// Flushes/finalizes the selected codec and returns its writer.
    pub fn finish(self) -> Result<W, JtlError> {
        match self {
            Self::Csv(encoder) => (*encoder).finish(),
            Self::Xml(encoder) => (*encoder).finish(),
        }
    }
}

/// A bounded format-dispatching JTL decoder.
pub enum JtlDecoder<R> {
    /// CSV decoder selected by [`JtlFormat::Csv`].
    Csv(Box<crate::csv::CsvDecoder<R>>),
    /// XML decoder selected by [`JtlFormat::Xml`].
    Xml(Box<crate::xml::XmlDecoder<R>>),
}

impl<R: Read> JtlDecoder<R> {
    /// Creates a format-dispatching decoder under explicit bounds.
    pub fn new(
        reader: R,
        configuration: SampleSaveConfiguration,
        limits: JtlLimits,
    ) -> Result<Self, JtlError> {
        match configuration.format() {
            JtlFormat::Csv => {
                configuration.validate_for_format(JtlFormat::Csv)?;
                Ok(Self::Csv(Box::new(crate::csv::CsvDecoder::with_limits(
                    reader,
                    configuration,
                    limits,
                )?)))
            }
            JtlFormat::Xml => {
                configuration.validate_for_format(JtlFormat::Xml)?;
                let xml_configuration = crate::xml::XmlDecodeConfiguration::new()
                    .with_sample_variables(configuration.sample_variables())?;
                Ok(Self::Xml(Box::new(
                    crate::xml::XmlDecoder::with_configuration(reader, limits, xml_configuration)?,
                )))
            }
        }
    }

    /// Installs a Java-date-format provider on the CSV variant.
    pub fn with_date_provider(self, provider: Box<dyn DateFormatProvider>) -> Self {
        match self {
            Self::Csv(decoder) => Self::Csv(Box::new((*decoder).with_date_provider(provider))),
            Self::Xml(decoder) => Self::Xml(decoder),
        }
    }

    /// Reads the next event, or `None` at the bounded input's EOF.
    pub fn next_event(&mut self) -> Result<Option<crate::SampleEvent>, JtlError> {
        match self {
            Self::Csv(decoder) => decoder.next_event(),
            Self::Xml(decoder) => decoder.next_event(),
        }
    }

    /// Decodes all remaining events under the crate-wide aggregate cap.
    pub fn decode_all(self) -> Result<Vec<crate::SampleEvent>, JtlError> {
        self.decode_all_with_limit(MAX_DECODE_ALL_EVENTS)
    }

    /// Decodes all remaining events under an explicit aggregate event cap.
    pub fn decode_all_with_limit(
        self,
        maximum_events: usize,
    ) -> Result<Vec<crate::SampleEvent>, JtlError> {
        match self {
            Self::Csv(decoder) => (*decoder).decode_all_with_limit(maximum_events),
            Self::Xml(decoder) => (*decoder).decode_all_with_limit(maximum_events),
        }
    }
}

impl<R: Read> Iterator for JtlDecoder<R> {
    type Item = Result<crate::SampleEvent, JtlError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_event() {
            Ok(Some(event)) => Some(Ok(event)),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        }
    }
}

/// Encodes events using the format selected by `configuration`.
pub fn encode_jtl<W, I>(
    writer: W,
    events: I,
    configuration: SampleSaveConfiguration,
) -> Result<W, JtlError>
where
    W: io::Write,
    I: IntoIterator,
    I::Item: Borrow<crate::SampleEvent>,
{
    let mut encoder = JtlEncoder::new(writer, configuration)?;
    for event in events {
        encoder.write_event(event.borrow())?;
    }
    encoder.finish()
}

/// Decodes a bounded JTL stream using the format selected by `configuration`.
pub fn decode_jtl<R: Read>(
    reader: R,
    configuration: SampleSaveConfiguration,
    limits: JtlLimits,
) -> Result<Vec<crate::SampleEvent>, JtlError> {
    JtlDecoder::new(reader, configuration, limits)?.decode_all()
}

/// Decodes a bounded JTL stream into a collection with an explicit event cap.
pub fn decode_jtl_with_limit<R: Read>(
    reader: R,
    configuration: SampleSaveConfiguration,
    limits: JtlLimits,
    maximum_events: usize,
) -> Result<Vec<crate::SampleEvent>, JtlError> {
    JtlDecoder::new(reader, configuration, limits)?.decode_all_with_limit(maximum_events)
}

/// Alias for [`encode_jtl`].
pub fn write_jtl<W, I>(
    writer: W,
    events: I,
    configuration: SampleSaveConfiguration,
) -> Result<W, JtlError>
where
    W: io::Write,
    I: IntoIterator,
    I::Item: Borrow<crate::SampleEvent>,
{
    encode_jtl(writer, events, configuration)
}

/// Alias for [`decode_jtl`].
pub fn read_jtl<R: Read>(
    reader: R,
    configuration: SampleSaveConfiguration,
    limits: JtlLimits,
) -> Result<Vec<crate::SampleEvent>, JtlError> {
    decode_jtl(reader, configuration, limits)
}

/// Validates a JMeter delimiter.
pub fn validate_delimiter(delimiter: char) -> Result<(), JtlError> {
    if delimiter.is_ascii_alphanumeric() || delimiter == '"' {
        return Err(JtlError::InvalidConfiguration {
            field: "delimiter",
            detail: "delimiter must not be alphanumeric or a quote".to_owned(),
        });
    }
    if delimiter != '\t' && !delimiter.is_ascii_graphic() && delimiter != ' ' {
        return Err(JtlError::InvalidConfiguration {
            field: "delimiter",
            detail: "delimiter must be TAB or an ASCII printable character".to_owned(),
        });
    }
    Ok(())
}

/// Escapes a sample-variable name using the legacy doubled-underscore XML
/// extension spelling accepted by the decoder.  The JMeter 5.6.3 writer emits
/// the configured name exactly and does not call this helper.
pub fn sanitize_xml_attribute_name(value: &str) -> Result<String, JtlError> {
    if value.is_empty() {
        return Err(JtlError::InvalidConfiguration {
            field: "sample_variables",
            detail: "variable names must not be empty".to_owned(),
        });
    }
    let mut result = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch == '_' {
            result.push('_');
            result.push('_');
        } else {
            result.push(ch);
        }
    }
    if !is_xml_name(&result) {
        return Err(JtlError::InvalidConfiguration {
            field: "sample_variables",
            detail: format!("invalid XML attribute name {value:?}"),
        });
    }
    Ok(result)
}

/// Validates and returns a configured XML sample-variable name exactly as it
/// appears on the JMeter wire.
///
/// JMeter's `SampleResultConverter` does not escape underscores in configured
/// variable names.  The doubled-underscore transform remains available only
/// through [`sanitize_xml_attribute_name`] for the explicit Rust extension
/// reader path.
pub(crate) fn xml_attribute_name(value: &str) -> Result<String, JtlError> {
    if value.is_empty() {
        return Err(JtlError::InvalidConfiguration {
            field: "sample_variables",
            detail: "variable names must not be empty".to_owned(),
        });
    }
    if !is_xml_name(value) {
        return Err(JtlError::InvalidConfiguration {
            field: "sample_variables",
            detail: format!("invalid XML attribute name {value:?}"),
        });
    }
    Ok(value.to_owned())
}

/// Reverses [`sanitize_xml_attribute_name`] for the legacy doubled-underscore
/// extension spelling.
pub fn desanitize_xml_attribute_name(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch == '_' {
            if let Some(next) = chars.next() {
                if next == '_' {
                    result.push('_');
                } else {
                    result.push('_');
                    result.push(next);
                }
            } else {
                result.push('_');
            }
        } else {
            result.push(ch);
        }
    }
    result
}

/// Returns whether a string is a conservative XML 1.0 name.
pub(crate) fn is_xml_name(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first == ':' || first.is_alphabetic()) {
        return false;
    }
    chars.all(|ch| ch == '_' || ch == ':' || ch == '-' || ch == '.' || ch.is_alphanumeric())
}

/// Escapes XML text or attribute content.
pub(crate) fn escape_xml(value: &str, attribute: bool) -> String {
    let mut output = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' if attribute => output.push_str("&quot;"),
            '\'' if attribute => output.push_str("&apos;"),
            _ => output.push(ch),
        }
    }
    output
}

/// Rejects code points that XML 1.0 cannot represent.  Escaping markup does
/// not make control characters legal, so codecs call this before writing text
/// or attribute values.
pub(crate) fn validate_xml_characters(value: &str) -> Result<(), JtlError> {
    if value.chars().all(is_valid_xml_character) {
        return Ok(());
    }
    Err(JtlError::Unsupported {
        feature: "xml-invalid-character",
        value: "text contains a code point forbidden by XML 1.0".to_owned(),
    })
}

fn is_valid_xml_character(value: char) -> bool {
    matches!(value, '\u{9}' | '\u{a}' | '\u{d}')
        || ('\u{20}'..='\u{d7ff}').contains(&value)
        || ('\u{e000}'..='\u{fffd}').contains(&value)
        || ('\u{10000}'..='\u{10ffff}').contains(&value)
}

/// Parses a strict lower-case boolean used by the JTL wire format.
pub(crate) fn parse_bool(value: &str, field: &str) -> Result<bool, JtlError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(JtlError::InvalidConfiguration {
            field: "boolean",
            detail: format!("{field} must be true or false, got {value:?}"),
        }),
    }
}

/// Parses an optional unsigned decimal field. Empty fields represent an
/// absent optional domain value; non-empty values are strict decimal.
pub(crate) fn parse_optional_u64(
    value: &str,
    field: &'static str,
    record: usize,
) -> Result<Option<u64>, JtlError> {
    if value.is_empty() {
        return Ok(None);
    }
    parse_unsigned_decimal(value)
        .map(Some)
        .ok_or_else(|| JtlError::Csv {
            record,
            detail: format!("{field} must be an unsigned decimal, got {value:?}"),
        })
}

/// Parses a required unsigned decimal field in XML.
pub(crate) fn parse_xml_u64(
    value: &str,
    field: &'static str,
    offset: usize,
) -> Result<u64, JtlError> {
    parse_unsigned_decimal(value).ok_or_else(|| JtlError::Xml {
        offset,
        detail: format!("{field} must be an unsigned decimal, got {value:?}"),
    })
}

fn parse_unsigned_decimal(value: &str) -> Option<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse::<u64>().ok()
}

/// Parses an optional XML unsigned field.
pub(crate) fn parse_xml_optional_u64(
    value: Option<&str>,
    field: &'static str,
    offset: usize,
) -> Result<Option<u64>, JtlError> {
    match value {
        None => Ok(None),
        Some("") => Ok(None),
        Some(value) => parse_xml_u64(value, field, offset).map(Some),
    }
}

/// Parses an optional XML signed timestamp.
pub(crate) fn parse_xml_optional_i64(
    value: Option<&str>,
    field: &'static str,
    offset: usize,
) -> Result<Option<i64>, JtlError> {
    match value {
        None => Ok(None),
        Some("") => Ok(None),
        Some(value) => {
            let digits = value.strip_prefix('-').unwrap_or(value);
            if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(JtlError::Xml {
                    offset,
                    detail: format!("{field} must be a signed decimal, got {value:?}"),
                });
            }
            value.parse::<i64>().map(Some).map_err(|_| JtlError::Xml {
                offset,
                detail: format!("{field} is outside the signed 64-bit range"),
            })
        }
    }
}

/// Returns the first assertion failure/error message, matching JMeter's CSV
/// `failureMessage` projection.
pub(crate) fn first_failure_message(result: &crate::SampleResult) -> Option<&str> {
    result
        .assertions()
        .iter()
        // JMeter's CSV projection calls SampleResult#getFirstAssertionFailureMessage,
        // which reads only AssertionResult.failureMessage.  The Rust model
        // retains a separate error_message extension for XML no-drop paths;
        // it is not a CSV failureMessage source.
        .find_map(|assertion| assertion.failure_message())
        .or_else(|| result.failure_message())
}

/// Creates a typed timing object from wire values without mutating a result in
/// a partially parsed state.
pub(crate) fn timing_from_wire(
    timestamp: Option<i64>,
    elapsed: Option<u64>,
    latency: Option<u64>,
    connect: Option<u64>,
    idle: Option<u64>,
) -> Result<crate::SampleTiming, JtlError> {
    Ok(crate::SampleTiming::from_wire_parts(
        timestamp.map(crate::WallTimestamp::from_millis),
        None,
        None,
        elapsed.map(crate::ElapsedTime::from_millis),
        latency.map(crate::Latency::from_millis),
        connect.map(crate::ConnectTime::from_millis),
        idle.map(crate::IdleTime::from_millis),
    ))
}

/// Maps a `std::io::Write` error to a stable operation-specific error.
pub(crate) fn write_all<W: io::Write>(
    writer: &mut W,
    bytes: &[u8],
    operation: &'static str,
) -> Result<(), JtlError> {
    writer.write_all(bytes).map_err(|error| JtlError::Io {
        operation,
        message: error.to_string(),
    })
}

/// Converts XML response text to bytes using JMeter's selected data
/// encoding, without touching a responseFile.
///
/// XML itself is UTF-8, but `SampleResultConverter` stores a parsed
/// `responseData` child by calling `String#getBytes(getDataEncodingWithDefault())`.
/// Keep the small deterministic charset set supported by the writer in this
/// pure codec and reject other charsets explicitly rather than silently
/// re-encoding them as UTF-8.
pub(crate) fn response_text_bytes(
    text: String,
    encoding: Option<&str>,
) -> Result<crate::SampleData, JtlError> {
    let bytes = match encoding {
        None => text.into_bytes(),
        Some(charset)
            if charset.eq_ignore_ascii_case("utf-8") || charset.eq_ignore_ascii_case("utf8") =>
        {
            text.into_bytes()
        }
        Some(charset)
            if charset.eq_ignore_ascii_case("ascii")
                || charset.eq_ignore_ascii_case("us-ascii") =>
        {
            if !text.is_ascii() {
                return Err(JtlError::Unsupported {
                    feature: "xml-response-encoding",
                    value: charset.to_owned(),
                });
            }
            text.into_bytes()
        }
        Some(charset)
            if charset.eq_ignore_ascii_case("iso-8859-1")
                || charset.eq_ignore_ascii_case("iso8859-1")
                || charset.eq_ignore_ascii_case("latin-1")
                || charset.eq_ignore_ascii_case("latin1") =>
        {
            let mut bytes = Vec::with_capacity(text.len());
            for character in text.chars() {
                let byte =
                    u8::try_from(u32::from(character)).map_err(|_| JtlError::Unsupported {
                        feature: "xml-response-encoding",
                        value: charset.to_owned(),
                    })?;
                bytes.push(byte);
            }
            bytes
        }
        Some(charset) => {
            return Err(JtlError::Unsupported {
                feature: "xml-response-encoding",
                value: charset.to_owned(),
            });
        }
    };
    Ok(crate::SampleData::new(bytes))
}

// Test fixtures use `expect` at setup/assertion boundaries so failures retain
// the operation name; production codec paths remain explicitly fallible.
#[allow(clippy::expect_used)]
#[cfg(test)]
mod tests {
    use std::io::{self, Write};

    use super::*;
    use crate::{SampleEvent, SampleResult, ThreadIdentity, VariableSnapshot};

    #[derive(Debug, Default)]
    struct CountingWriter {
        bytes: usize,
        fail_after: Option<usize>,
    }

    impl Write for CountingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if let Some(limit) = self.fail_after {
                if self.bytes >= limit {
                    return Err(io::Error::other("synthetic writer failure"));
                }
                let remaining = limit - self.bytes;
                let accepted = bytes.len().min(remaining);
                self.bytes = self.bytes.saturating_add(accepted);
                return Ok(accepted);
            }
            self.bytes = self
                .bytes
                .checked_add(bytes.len())
                .ok_or_else(|| io::Error::other("counter overflow"))?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn event() -> SampleEvent {
        SampleEvent::new(
            SampleResult::new("dispatch"),
            "run",
            ThreadIdentity::new("thread"),
            "host",
            VariableSnapshot::new(),
        )
    }

    #[test]
    fn format_and_line_ending_parsers_are_closed() {
        assert_eq!(JtlFormat::parse("CSV").ok(), Some(JtlFormat::Csv));
        assert_eq!(JtlFormat::parse("xml").ok(), Some(JtlFormat::Xml));
        assert!(matches!(
            JtlFormat::parse("db"),
            Err(JtlError::InvalidConfiguration {
                field: "output_format",
                ..
            })
        ));
        assert_eq!(LineEnding::parse("\\r\\n").ok(), Some(LineEnding::CrLf));
        assert_eq!(LineEnding::parse("LF").ok(), Some(LineEnding::Lf));
        assert!(matches!(
            LineEnding::parse("native"),
            Err(JtlError::InvalidConfiguration {
                field: "line_ending",
                ..
            })
        ));
    }

    #[test]
    fn line_ending_property_is_retained_and_invalid_values_fail_closed() {
        let configuration = SampleSaveConfiguration::from_properties([("line_ending", "crlf")])
            .expect("line ending property");
        assert_eq!(configuration.line_ending(), LineEnding::CrLf);
        assert!(matches!(
            SampleSaveConfiguration::from_properties([("line_ending", "native")]),
            Err(JtlError::InvalidConfiguration {
                field: "line_ending",
                ..
            })
        ));
    }

    #[test]
    fn dispatch_round_trips_csv_and_xml_without_format_crossing() {
        let csv_configuration = SampleSaveConfiguration::csv();
        let csv_bytes = encode_jtl(
            Vec::new(),
            std::iter::once(event()),
            csv_configuration.clone(),
        )
        .expect("CSV dispatch");
        let csv_events = decode_jtl(
            csv_bytes.as_slice(),
            csv_configuration,
            JtlLimits::default(),
        )
        .expect("CSV decode dispatch");
        assert_eq!(csv_events.len(), 1);
        assert_eq!(csv_events[0].result().label(), "dispatch");

        let xml_configuration = SampleSaveConfiguration::xml();
        let xml_bytes = encode_jtl(
            Vec::new(),
            std::iter::once(event()),
            xml_configuration.clone(),
        )
        .expect("XML dispatch");
        let xml_events = decode_jtl(
            xml_bytes.as_slice(),
            xml_configuration,
            JtlLimits::default(),
        )
        .expect("XML decode dispatch");
        assert_eq!(xml_events.len(), 1);
        assert_eq!(xml_events[0].result().label(), "dispatch");
    }

    #[test]
    fn dispatch_rejects_a_requested_codec_that_does_not_match_config() {
        let configuration = SampleSaveConfiguration::xml();
        assert!(matches!(
            configuration.validate_for_format(JtlFormat::Csv),
            Err(JtlError::InvalidConfiguration {
                field: "output_format",
                ..
            })
        ));
    }

    #[test]
    fn dispatch_decode_collection_limit_is_bounded() {
        let configuration = SampleSaveConfiguration::csv();
        let bytes = encode_jtl(Vec::new(), [event(), event()], configuration.clone())
            .expect("CSV dispatch");
        assert!(matches!(
            decode_jtl_with_limit(bytes.as_slice(), configuration, JtlLimits::default(), 1),
            Err(JtlError::Unsupported {
                feature: "decode-all-event-limit",
                ..
            })
        ));
    }

    #[test]
    fn streaming_csv_exceeds_aggregate_ceiling_without_retaining_output() {
        let label = "x".repeat(4 * 1024);
        let event = SampleEvent::new(
            SampleResult::new(label),
            "run",
            ThreadIdentity::new("thread"),
            "host",
            VariableSnapshot::new(),
        );
        let iterations = MAX_JTL_OUTPUT_BYTES / 4_096 + 32;
        let mut encoder =
            JtlEncoder::streaming(CountingWriter::default(), SampleSaveConfiguration::csv())
                .expect("streaming CSV encoder");
        for _ in 0..iterations {
            encoder.write_event(&event).expect("streaming event");
        }
        let writer = encoder.finish().expect("streaming CSV finish");
        assert!(writer.bytes > MAX_JTL_OUTPUT_BYTES);
    }

    #[test]
    fn streaming_xml_exceeds_aggregate_ceiling_without_retaining_output() {
        let label = "x".repeat(4 * 1024);
        let event = SampleEvent::new(
            SampleResult::new(label),
            "run",
            ThreadIdentity::new("thread"),
            "host",
            VariableSnapshot::new(),
        );
        let iterations = MAX_JTL_OUTPUT_BYTES / 4_096 + 32;
        let mut encoder =
            JtlEncoder::streaming(CountingWriter::default(), SampleSaveConfiguration::xml())
                .expect("streaming XML encoder");
        for _ in 0..iterations {
            encoder.write_event(&event).expect("streaming event");
        }
        let writer = encoder.finish().expect("streaming XML finish");
        assert!(writer.bytes > MAX_JTL_OUTPUT_BYTES);
    }

    #[test]
    fn streaming_framing_is_emitted_once_per_format() {
        let event = event();
        let mut csv_configuration = SampleSaveConfiguration::csv();
        csv_configuration.set_print_field_names(true);
        let mut csv = JtlEncoder::streaming(Vec::new(), csv_configuration).expect("CSV encoder");
        csv.write_event(&event).expect("CSV event");
        csv.write_event(&event).expect("CSV event");
        let csv = String::from_utf8(csv.finish().expect("CSV finish")).expect("CSV UTF-8");
        assert_eq!(csv.matches("timeStamp").count(), 1);

        let mut xml =
            JtlEncoder::streaming(Vec::new(), SampleSaveConfiguration::xml()).expect("XML encoder");
        xml.write_event(&event).expect("XML event");
        xml.write_event(&event).expect("XML event");
        let xml = String::from_utf8(xml.finish().expect("XML finish")).expect("XML UTF-8");
        assert_eq!(xml.matches("<?xml").count(), 1);
        assert_eq!(xml.matches("<testResults").count(), 1);
        assert_eq!(xml.matches("</testResults>").count(), 1);
    }

    #[test]
    fn streaming_event_staging_limit_is_finite_and_typed() {
        let mut encoder =
            JtlEncoder::streaming_with_event_limit(Vec::new(), SampleSaveConfiguration::csv(), 64)
                .expect("streaming encoder");
        let event = SampleEvent::new(
            SampleResult::new("event larger than staging bound"),
            "run",
            ThreadIdentity::new("thread"),
            "host",
            VariableSnapshot::new(),
        );
        assert!(matches!(
            encoder.write_event(&event),
            Err(JtlError::Unsupported {
                feature: "csv-event-staging-limit",
                ..
            })
        ));
    }

    #[test]
    fn streaming_writer_failure_is_reported_as_typed_io() {
        let mut encoder = JtlEncoder::streaming(
            CountingWriter {
                fail_after: Some(0),
                ..CountingWriter::default()
            },
            SampleSaveConfiguration::csv(),
        )
        .expect("streaming encoder");
        assert!(matches!(
            encoder.write_event(&event()),
            Err(JtlError::Io { operation, .. }) if operation == "write CSV event"
        ));
    }

    #[test]
    fn streaming_output_counter_overflow_is_typed() {
        let mut encoder = JtlEncoder::streaming(Vec::new(), SampleSaveConfiguration::csv())
            .expect("streaming encoder");
        assert!(matches!(&encoder, JtlEncoder::Csv(_)));
        if let JtlEncoder::Csv(encoder) = &mut encoder {
            encoder.set_output_bytes_for_test(usize::MAX);
        }
        assert!(matches!(
            encoder.write_event(&event()),
            Err(JtlError::CounterOverflow {
                counter: JtlCounter::OutputBytes
            })
        ));
    }

    #[test]
    fn streaming_policy_rejects_an_unbounded_or_zero_event_limit() {
        assert!(matches!(
            JtlEncoder::streaming_with_event_limit(Vec::new(), SampleSaveConfiguration::csv(), 0,),
            Err(JtlError::InvalidConfiguration {
                field: "max_event_bytes",
                ..
            })
        ));
        assert!(matches!(
            JtlEncoder::streaming_with_event_limit(
                Vec::new(),
                SampleSaveConfiguration::csv(),
                MAX_JTL_OUTPUT_BYTES + 1,
            ),
            Err(JtlError::InvalidConfiguration {
                field: "max_event_bytes",
                ..
            })
        ));
    }

    fn assert_limit_boundary<F>(field: &'static str, maximum: usize, set: F)
    where
        F: Fn(JtlLimits, usize) -> JtlLimits,
    {
        let exact = set(JtlLimits::default(), maximum);
        assert!(
            exact.validate().is_ok(),
            "exact {field} bound must be valid"
        );

        let over = set(JtlLimits::default(), maximum + 1);
        assert!(matches!(
            over.validate(),
            Err(JtlError::InvalidConfiguration {
                field: observed,
                ..
            }) if observed == field
        ));
    }

    #[test]
    fn product_limit_boundaries_are_exact_and_fail_closed() {
        assert_limit_boundary("max_input_bytes", MAX_JTL_INPUT_BYTES, |limits, value| {
            JtlLimits {
                max_input_bytes: value,
                ..limits
            }
        });
        assert_limit_boundary("max_output_bytes", MAX_JTL_OUTPUT_BYTES, |limits, value| {
            JtlLimits {
                max_output_bytes: value,
                ..limits
            }
        });
        assert_limit_boundary("max_record_bytes", MAX_JTL_RECORD_BYTES, |limits, value| {
            JtlLimits {
                max_record_bytes: value,
                ..limits
            }
        });
        assert_limit_boundary(
            "max_attribute_bytes",
            MAX_JTL_ATTRIBUTE_BYTES,
            |limits, value| JtlLimits {
                max_attribute_bytes: value,
                ..limits
            },
        );
        assert_limit_boundary("max_columns", MAX_JTL_COLUMNS, |limits, value| JtlLimits {
            max_columns: value,
            ..limits
        });
        assert_limit_boundary("max_depth", MAX_JTL_DEPTH, |limits, value| JtlLimits {
            max_depth: value,
            ..limits
        });
        assert_limit_boundary("max_nodes", MAX_JTL_NODES, |limits, value| JtlLimits {
            max_nodes: value,
            ..limits
        });
        assert_limit_boundary("max_samples", MAX_JTL_SAMPLES, |limits, value| JtlLimits {
            max_samples: value,
            ..limits
        });
        assert_limit_boundary("max_attributes", MAX_JTL_ATTRIBUTES, |limits, value| {
            JtlLimits {
                max_attributes: value,
                ..limits
            }
        });
    }
}
