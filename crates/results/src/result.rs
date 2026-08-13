// SPDX-License-Identifier: Apache-2.0
//! Sample-result hierarchy and aggregation primitives.

use core::fmt;

use crate::data::{DataEncoding, DataType, HeaderBlock, SampleData};
use crate::error::{HierarchyLimit, InputField, ResultError, ResultField};
use crate::timing::SampleTiming;

pub use crate::timing::{ConnectTime, ElapsedTime, IdleTime, Latency};

/// Compatibility alias for the timing portion of a sample result.
pub type SampleResultTiming = SampleTiming;

macro_rules! count_type {
    ($(#[$meta:meta])* $name:ident, $field:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(u64);

        impl $name {
            /// Creates a non-negative count.
            pub const fn from_u64(value: u64) -> Self {
                Self(value)
            }

            /// Returns the count.
            pub const fn as_u64(self) -> u64 {
                self.0
            }

            /// Adds two counts without wrapping.
            pub fn checked_add(self, other: Self) -> crate::Result<Self> {
                self.0.checked_add(other.0).map(Self).ok_or(ResultError::Overflow {
                    field: ResultField::$field,
                })
            }

            /// Converts a signed wire value, rejecting negative counts.
            pub fn try_from_i64(value: i64) -> crate::Result<Self> {
                u64::try_from(value).map(Self).map_err(|_| ResultError::InvalidInput {
                    field: InputField::NegativeNumber(ResultField::$field),
                })
            }
        }

        impl TryFrom<i64> for $name {
            type Error = ResultError;

            fn try_from(value: i64) -> Result<Self, Self::Error> {
                Self::try_from_i64(value)
            }
        }

        impl From<u64> for $name {
            fn from(value: u64) -> Self {
                Self::from_u64(value)
            }
        }
    };
}

count_type!(
    /// Number of bytes received by a sampler.
    ByteCount,
    ReceivedBytes
);
count_type!(
    /// Number of active threads.
    ThreadCount,
    ThreadCount
);
count_type!(
    /// Number of samples represented by a result.
    SampleCount,
    SampleCount
);
count_type!(
    /// Number of errors represented by a result.
    ErrorCount,
    ErrorCount
);

impl ByteCount {
    /// Creates a byte count and is equivalent to [`ByteCount::from_u64`].
    pub const fn new(value: u64) -> Self {
        Self::from_u64(value)
    }
}

impl ThreadCount {
    /// Creates a thread count and is equivalent to [`ThreadCount::from_u64`].
    pub const fn new(value: u64) -> Self {
        Self::from_u64(value)
    }
}

impl SampleCount {
    /// A single sample.
    pub const ONE: Self = Self(1);

    /// Creates a sample count and is equivalent to [`SampleCount::from_u64`].
    pub const fn new(value: u64) -> Self {
        Self::from_u64(value)
    }
}

impl ErrorCount {
    /// No errors.
    pub const ZERO: Self = Self(0);

    /// Creates an error count and is equivalent to [`ErrorCount::from_u64`].
    pub const fn new(value: u64) -> Self {
        Self::from_u64(value)
    }
}

/// The projected outcome of an assertion.
///
/// JMeter carries failure and evaluation-error as independent wire flags, so
/// an [`AssertionResult`] can have both flags set.  This legacy three-way
/// projection returns [`AssertionOutcome::Error`] for that combination; use
/// [`AssertionResult::is_failure`] and [`AssertionResult::is_error`] when wire
/// fidelity matters.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AssertionOutcome {
    /// The assertion passed.
    Passed,
    /// The assertion evaluated and failed.
    Failure,
    /// The assertion could not be evaluated.
    Error,
}

/// Opaque XML extension content retained by the result codecs.  The model
/// intentionally keeps the element tree separate from known JTL fields so a
/// plugin child can be re-emitted without pretending to understand it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct XmlOpaqueChild {
    pub(crate) name: String,
    pub(crate) attributes: Vec<(String, String)>,
    pub(crate) content: Vec<XmlOpaquePart>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum XmlOpaquePart {
    Text(String),
    Child(XmlOpaqueChild),
}

impl XmlOpaqueChild {
    pub(crate) fn new(name: String, attributes: Vec<(String, String)>) -> Self {
        Self {
            name,
            attributes,
            content: Vec::new(),
        }
    }

    pub(crate) fn push_text(&mut self, value: String) {
        self.content.push(XmlOpaquePart::Text(value));
    }

    pub(crate) fn push_child(&mut self, child: XmlOpaqueChild) {
        self.content.push(XmlOpaquePart::Child(child));
    }
}

impl AssertionOutcome {
    /// Returns whether this outcome is a failure.
    pub const fn is_failure(self) -> bool {
        matches!(self, Self::Failure)
    }

    /// Returns whether this outcome is an evaluation error.
    pub const fn is_error(self) -> bool {
        matches!(self, Self::Error)
    }

    /// Returns whether this outcome passed.
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Passed)
    }
}

/// One assertion attached to a sample result.
#[derive(Clone, Eq, PartialEq)]
pub struct AssertionResult {
    name: String,
    failure: bool,
    error: bool,
    failure_message: Option<String>,
    error_message: Option<String>,
    wire_xml_attributes: Vec<(String, String)>,
    wire_xml_children: Vec<XmlOpaqueChild>,
}

impl AssertionResult {
    /// Creates an assertion with an explicit outcome.
    pub fn new(name: impl Into<String>, outcome: AssertionOutcome) -> Self {
        let (failure, error) = match outcome {
            AssertionOutcome::Passed => (false, false),
            AssertionOutcome::Failure => (true, false),
            AssertionOutcome::Error => (false, true),
        };
        Self {
            name: name.into(),
            failure,
            error,
            failure_message: None,
            error_message: None,
            wire_xml_attributes: Vec::new(),
            wire_xml_children: Vec::new(),
        }
    }

    /// Creates a passing assertion.
    pub fn passed(name: impl Into<String>) -> Self {
        Self::new(name, AssertionOutcome::Passed)
    }

    /// Creates a failed assertion, retaining an optional message.
    pub fn failed(name: impl Into<String>, message: Option<String>) -> Self {
        let mut result = Self::new(name, AssertionOutcome::Failure);
        result.failure_message = message;
        result
    }

    /// Creates an assertion-evaluation error, retaining an optional message.
    pub fn errored(name: impl Into<String>, message: Option<String>) -> Self {
        let mut result = Self::new(name, AssertionOutcome::Error);
        result.error_message = message;
        result
    }

    /// Creates an assertion from JMeter's separate failure and error flags.
    pub fn from_flags(
        name: impl Into<String>,
        failure: bool,
        error: bool,
        failure_message: Option<String>,
        error_message: Option<String>,
    ) -> crate::Result<Self> {
        let result = Self {
            name: name.into(),
            failure,
            error,
            failure_message,
            error_message,
            wire_xml_attributes: Vec::new(),
            wire_xml_children: Vec::new(),
        };
        result.validate()?;
        Ok(result)
    }

    /// Returns the assertion name. Empty names are retained.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the assertion outcome.
    pub const fn outcome(&self) -> AssertionOutcome {
        match (self.failure, self.error) {
            (_, true) => AssertionOutcome::Error,
            (true, false) => AssertionOutcome::Failure,
            (false, false) => AssertionOutcome::Passed,
        }
    }

    /// Returns whether the assertion failed.
    pub const fn is_failure(&self) -> bool {
        self.failure
    }

    /// Returns whether assertion evaluation errored.
    pub const fn is_error(&self) -> bool {
        self.error
    }

    /// Returns the optional failure message. Present-empty and absent remain
    /// distinct.
    pub fn failure_message(&self) -> Option<&str> {
        self.failure_message.as_deref()
    }

    /// Returns the optional evaluation-error message.
    pub fn error_message(&self) -> Option<&str> {
        self.error_message.as_deref()
    }

    pub(crate) fn wire_xml_attributes(&self) -> &[(String, String)] {
        &self.wire_xml_attributes
    }

    pub(crate) fn set_wire_xml_attributes(&mut self, attributes: Vec<(String, String)>) {
        self.wire_xml_attributes = attributes;
    }

    pub(crate) fn wire_xml_children(&self) -> &[XmlOpaqueChild] {
        &self.wire_xml_children
    }

    pub(crate) fn add_wire_xml_child(&mut self, child: XmlOpaqueChild) {
        self.wire_xml_children.push(child);
    }

    /// Sets the assertion outcome.
    pub fn set_outcome(&mut self, outcome: AssertionOutcome) {
        (self.failure, self.error) = match outcome {
            AssertionOutcome::Passed => (false, false),
            AssertionOutcome::Failure => (true, false),
            AssertionOutcome::Error => (false, true),
        };
    }

    /// Sets the optional failure message.
    pub fn set_failure_message(&mut self, value: Option<String>) {
        self.failure_message = value;
    }

    /// Sets the optional evaluation-error message.
    pub fn set_error_message(&mut self, value: Option<String>) {
        self.error_message = value;
    }

    /// Validates the assertion's internal outcome representation.
    pub fn validate(&self) -> crate::Result<()> {
        // Failure and evaluation-error are independent JMeter wire flags.
        // Both may be present at once and must survive XML round-trips.
        Ok(())
    }
}

impl fmt::Debug for AssertionResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AssertionResult")
            .field("name_len", &self.name.len())
            .field("failure", &self.failure)
            .field("error", &self.error)
            .field(
                "failure_message_len",
                &self.failure_message.as_ref().map(String::len),
            )
            .field(
                "error_message_len",
                &self.error_message.as_ref().map(String::len),
            )
            .field("wire_xml_attributes", &self.wire_xml_attributes.len())
            .field("wire_xml_children", &self.wire_xml_children.len())
            .finish()
    }
}

/// Independent stop, logical-action, and ignore controls attached to a sample.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SampleFlags {
    stop_thread: bool,
    stop_test: bool,
    stop_test_now: bool,
    start_next_loop: bool,
    logical_action: Option<LogicalAction>,
    ignored: bool,
}

impl SampleFlags {
    /// Returns whether the current thread should stop after this sample.
    pub const fn stop_thread(&self) -> bool {
        self.stop_thread
    }

    /// Returns whether the test should stop gracefully.
    pub const fn stop_test(&self) -> bool {
        self.stop_test
    }

    /// Returns whether the test should stop immediately.
    pub const fn stop_test_now(&self) -> bool {
        self.stop_test_now
    }

    /// Returns whether the next thread-loop iteration should begin.
    pub const fn start_next_loop(&self) -> bool {
        self.start_next_loop
    }

    /// Returns the optional logical action.
    pub const fn logical_action(&self) -> Option<LogicalAction> {
        self.logical_action
    }

    /// Returns whether this result is ignored by result consumers.
    pub const fn ignored(&self) -> bool {
        self.ignored
    }

    /// Sets the stop-thread flag.
    pub const fn set_stop_thread(&mut self, value: bool) {
        self.stop_thread = value;
    }

    /// Sets the graceful-stop-test flag.
    pub const fn set_stop_test(&mut self, value: bool) {
        self.stop_test = value;
    }

    /// Sets the immediate-stop-test flag.
    pub const fn set_stop_test_now(&mut self, value: bool) {
        self.stop_test_now = value;
    }

    /// Sets the start-next-loop flag.
    pub const fn set_start_next_loop(&mut self, value: bool) {
        self.start_next_loop = value;
    }

    /// Sets or clears the logical action.
    pub const fn set_logical_action(&mut self, value: Option<LogicalAction>) {
        self.logical_action = value;
    }

    /// Sets the ignored flag.
    pub const fn set_ignored(&mut self, value: bool) {
        self.ignored = value;
    }
}

/// A logical action separate from stop flags and assertion success.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LogicalAction {
    /// Continue the current flow.
    Continue,
    /// Start the next loop iteration.
    StartNextIteration,
    /// Stop the current thread.
    StopThread,
    /// Gracefully stop the test.
    StopTest,
    /// Immediately stop the test.
    StopTestNow,
}

/// Bounds used when validating or aggregating nested results.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ValidationLimits {
    max_depth: usize,
    max_nodes: usize,
}

impl ValidationLimits {
    /// Creates finite, non-zero hierarchy limits.
    pub fn new(max_depth: usize, max_nodes: usize) -> crate::Result<Self> {
        if max_depth == 0 || max_nodes == 0 {
            return Err(ResultError::InvalidInput {
                field: InputField::EmptyLimit,
            });
        }
        Ok(Self {
            max_depth,
            max_nodes,
        })
    }

    /// Returns the maximum permitted depth, including the root node.
    pub const fn max_depth(self) -> usize {
        self.max_depth
    }

    /// Returns the maximum permitted node count, including the root node.
    pub const fn max_nodes(self) -> usize {
        self.max_nodes
    }
}

impl Default for ValidationLimits {
    fn default() -> Self {
        Self {
            max_depth: 128,
            max_nodes: 100_000,
        }
    }
}

impl From<&ValidationLimits> for ValidationLimits {
    fn from(value: &ValidationLimits) -> Self {
        *value
    }
}

/// A full JMeter-like sample result, including nested sub-results.
///
/// Optional fields model absent JTL attributes or child elements. A present
/// empty string/byte payload is represented by `Some(empty_value)`.
#[derive(Eq, PartialEq)]
pub struct SampleResult {
    label: Option<String>,
    timing: SampleTiming,
    success: Option<bool>,
    response_code: Option<String>,
    response_message: Option<String>,
    failure_message: Option<String>,
    data_type: Option<DataType>,
    data_encoding: Option<DataEncoding>,
    request_data: Option<SampleData>,
    response_data: Option<SampleData>,
    request_headers: Option<HeaderBlock>,
    response_headers: Option<HeaderBlock>,
    sampler_data: Option<String>,
    response_file: Option<String>,
    url: Option<String>,
    received_bytes: Option<ByteCount>,
    sent_bytes: Option<ByteCount>,
    group_threads: Option<ThreadCount>,
    all_threads: Option<ThreadCount>,
    sample_count: Option<SampleCount>,
    error_count: Option<ErrorCount>,
    assertions: Vec<AssertionResult>,
    sub_results: Vec<SampleResult>,
    flags: SampleFlags,
    /// Per-node JTL metadata retained by XML readers.  Runtime-created
    /// results leave these fields absent/empty and inherit event metadata when
    /// serialized.
    wire_thread_name: Option<String>,
    wire_host: Option<String>,
    wire_variables: crate::VariableSnapshot,
    wire_xml_sample_element: Option<crate::XmlSampleElement>,
    wire_xml_attributes: Vec<(String, String)>,
    wire_xml_children: Vec<crate::result::XmlOpaqueChild>,
    wire_xml_root_attributes: Vec<(String, String)>,
    wire_xml_root_children: Vec<crate::result::XmlOpaqueChild>,
    wire_xml_root_children_after: Vec<crate::result::XmlOpaqueChild>,
}

impl Default for SampleResult {
    fn default() -> Self {
        Self::new("")
    }
}

impl fmt::Debug for SampleResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let data_type = self.data_type.as_ref().map(|value| match value {
            DataType::Text => "text",
            DataType::Binary => "binary",
            DataType::Other(_) => "<other>",
        });
        formatter
            .debug_struct("SampleResult")
            .field("label_len", &self.label.as_ref().map(String::len))
            .field("timing", &self.timing)
            .field("success", &self.success)
            .field("response_code_present", &self.response_code.is_some())
            .field("response_message_present", &self.response_message.is_some())
            .field("failure_message_present", &self.failure_message.is_some())
            .field("data_type", &data_type)
            .field(
                "data_encoding_len",
                &self
                    .data_encoding
                    .as_ref()
                    .map(|value| value.as_str().len()),
            )
            .field(
                "request_data_len",
                &self.request_data.as_ref().map(SampleData::len),
            )
            .field(
                "response_data_len",
                &self.response_data.as_ref().map(SampleData::len),
            )
            .field(
                "request_headers_len",
                &self
                    .request_headers
                    .as_ref()
                    .map(HeaderBlock::as_str)
                    .map(str::len),
            )
            .field(
                "response_headers_len",
                &self
                    .response_headers
                    .as_ref()
                    .map(HeaderBlock::as_str)
                    .map(str::len),
            )
            .field(
                "sampler_data_len",
                &self.sampler_data.as_ref().map(String::len),
            )
            .field(
                "response_file_len",
                &self.response_file.as_ref().map(String::len),
            )
            .field("url_len", &self.url.as_ref().map(String::len))
            .field("received_bytes", &self.received_bytes)
            .field("sent_bytes", &self.sent_bytes)
            .field("group_threads", &self.group_threads)
            .field("all_threads", &self.all_threads)
            .field("sample_count", &self.sample_count)
            .field("error_count", &self.error_count)
            .field("assertions", &self.assertions.len())
            .field("sub_results", &self.sub_results.len())
            .field("flags", &self.flags)
            .field(
                "wire_thread_name_len",
                &self.wire_thread_name.as_ref().map(String::len),
            )
            .field("wire_host_len", &self.wire_host.as_ref().map(String::len))
            .field("wire_variables", &self.wire_variables.len())
            .field("wire_xml_sample_element", &self.wire_xml_sample_element)
            .field("wire_xml_attributes", &self.wire_xml_attributes.len())
            .field("wire_xml_children", &self.wire_xml_children.len())
            .field(
                "wire_xml_root_attributes",
                &self.wire_xml_root_attributes.len(),
            )
            .field("wire_xml_root_children", &self.wire_xml_root_children.len())
            .field(
                "wire_xml_root_children_after",
                &self.wire_xml_root_children_after.len(),
            )
            .finish()
    }
}

impl SampleResult {
    /// Creates an empty result with the supplied (possibly empty) label.
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: Some(label.into()),
            timing: SampleTiming::default(),
            success: None,
            response_code: None,
            response_message: None,
            failure_message: None,
            data_type: None,
            data_encoding: None,
            request_data: None,
            response_data: None,
            request_headers: None,
            response_headers: None,
            sampler_data: None,
            response_file: None,
            url: None,
            received_bytes: None,
            sent_bytes: None,
            group_threads: None,
            all_threads: None,
            sample_count: None,
            error_count: None,
            assertions: Vec::new(),
            sub_results: Vec::new(),
            flags: SampleFlags::default(),
            wire_thread_name: None,
            wire_host: None,
            wire_variables: crate::VariableSnapshot::new(),
            wire_xml_sample_element: None,
            wire_xml_attributes: Vec::new(),
            wire_xml_children: Vec::new(),
            wire_xml_root_attributes: Vec::new(),
            wire_xml_root_children: Vec::new(),
            wire_xml_root_children_after: Vec::new(),
        }
    }

    /// Creates a result whose wire label field is absent.
    pub fn without_label() -> Self {
        let mut result = Self::new("");
        result.clear_label();
        result
    }

    /// Returns the sample label.
    pub fn label(&self) -> &str {
        self.label.as_deref().unwrap_or("")
    }

    /// Returns the optional wire label field, preserving absent versus present
    /// empty labels.
    pub fn label_field(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// Returns whether the wire label field is present.
    pub const fn has_label(&self) -> bool {
        self.label.is_some()
    }

    /// Sets the sample label, retaining empty labels.
    pub fn set_label(&mut self, value: impl Into<String>) {
        self.label = Some(value.into());
    }

    /// Clears the wire label field while retaining an empty semantic label for
    /// convenience access through [`SampleResult::label`].
    pub fn clear_label(&mut self) {
        self.label = None;
    }

    /// Returns the timing fields.
    pub fn timing(&self) -> &SampleTiming {
        &self.timing
    }

    /// Returns mutable timing access through the checked timing setters.
    pub fn timing_mut(&mut self) -> &mut SampleTiming {
        &mut self.timing
    }

    /// Replaces timing fields after validation.
    pub fn set_timing(&mut self, value: SampleTiming) -> crate::Result<()> {
        value.validate()?;
        self.timing = value;
        Ok(())
    }

    /// Replaces timing fields read from a wire format without imposing
    /// execution-time component inequalities.
    pub fn set_timing_from_wire(&mut self, value: SampleTiming) {
        self.timing = value;
    }

    /// Returns the optional serialized wall timestamp.
    pub const fn timestamp(&self) -> Option<crate::WallTimestamp> {
        self.timing.timestamp()
    }

    /// Sets the optional serialized wall timestamp.
    pub fn set_timestamp(&mut self, value: Option<crate::WallTimestamp>) {
        self.timing.set_timestamp(value);
    }

    /// Returns the optional sample start timestamp.
    pub fn start_time(&self) -> Option<crate::WallTimestamp> {
        self.timing.start()
    }

    /// Returns the optional sample end timestamp.
    pub fn end_time(&self) -> Option<crate::WallTimestamp> {
        self.timing.end()
    }

    /// Returns the optional elapsed duration.
    pub fn elapsed(&self) -> Option<ElapsedTime> {
        self.timing.elapsed()
    }

    /// Returns the optional latency duration.
    pub fn latency(&self) -> Option<Latency> {
        self.timing.latency()
    }

    /// Returns the optional connect duration.
    pub fn connect_time(&self) -> Option<ConnectTime> {
        self.timing.connect()
    }

    /// Returns the optional idle duration.
    pub fn idle_time(&self) -> Option<IdleTime> {
        self.timing.idle()
    }

    /// Sets the optional sample start timestamp.
    pub fn set_start_time(&mut self, value: Option<crate::WallTimestamp>) -> crate::Result<()> {
        self.timing.set_start(value)
    }

    /// Sets the optional sample end timestamp.
    pub fn set_end_time(&mut self, value: Option<crate::WallTimestamp>) -> crate::Result<()> {
        self.timing.set_end(value)
    }

    /// Sets the optional elapsed duration.
    pub fn set_elapsed(&mut self, value: Option<ElapsedTime>) -> crate::Result<()> {
        self.timing.set_elapsed(value)
    }

    /// Sets the optional latency duration.
    pub fn set_latency(&mut self, value: Option<Latency>) -> crate::Result<()> {
        self.timing.set_latency(value)
    }

    /// Sets the optional connect duration.
    pub fn set_connect_time(&mut self, value: Option<ConnectTime>) -> crate::Result<()> {
        self.timing.set_connect(value)
    }

    /// Sets the optional idle duration.
    pub fn set_idle_time(&mut self, value: Option<IdleTime>) -> crate::Result<()> {
        self.timing.set_idle(value)
    }

    /// Returns the optional success field.
    pub const fn success(&self) -> Option<bool> {
        self.success
    }

    /// Returns success with an absent field treated as false for execution
    /// convenience. Use [`SampleResult::success`] to preserve wire presence.
    pub fn is_successful(&self) -> bool {
        self.success.unwrap_or(false)
    }

    /// Sets the optional success field.
    pub const fn set_success(&mut self, value: Option<bool>) {
        self.success = value;
    }

    /// Sets a present success value.
    pub const fn set_successful(&mut self, value: bool) {
        self.success = Some(value);
    }

    /// Returns the optional response code.
    pub fn response_code(&self) -> Option<&str> {
        self.response_code.as_deref()
    }

    /// Sets the optional response code.
    pub fn set_response_code(&mut self, value: Option<String>) {
        self.response_code = value;
    }

    /// Sets a present response code.
    pub fn set_response_code_text(&mut self, value: impl Into<String>) {
        self.response_code = Some(value.into());
    }

    /// Returns the optional response message.
    pub fn response_message(&self) -> Option<&str> {
        self.response_message.as_deref()
    }

    /// Sets the optional response message.
    pub fn set_response_message(&mut self, value: Option<String>) {
        self.response_message = value;
    }

    /// Sets a present response message.
    pub fn set_response_message_text(&mut self, value: impl Into<String>) {
        self.response_message = Some(value.into());
    }

    /// Returns the optional failure message.
    pub fn failure_message(&self) -> Option<&str> {
        self.failure_message.as_deref()
    }

    /// Sets the optional sample-level failure message.
    pub fn set_failure_message(&mut self, value: Option<String>) {
        self.failure_message = value;
    }

    /// Returns the optional data type.
    pub fn data_type(&self) -> Option<&DataType> {
        self.data_type.as_ref()
    }

    /// Sets the optional data type.
    pub fn set_data_type(&mut self, value: Option<DataType>) {
        self.data_type = value;
    }

    /// Sets a present data type from its wire spelling.
    pub fn set_data_type_wire(&mut self, value: impl Into<String>) {
        self.data_type = Some(DataType::from_wire(value));
    }

    /// Returns the optional data encoding.
    pub fn data_encoding(&self) -> Option<&DataEncoding> {
        self.data_encoding.as_ref()
    }

    /// Sets the optional data encoding.
    pub fn set_data_encoding(&mut self, value: Option<DataEncoding>) {
        self.data_encoding = value;
    }

    /// Sets a present data encoding name.
    pub fn set_data_encoding_name(&mut self, value: impl Into<String>) {
        self.data_encoding = Some(DataEncoding::new(value));
    }

    /// Returns optional request bytes.
    pub fn request_data(&self) -> Option<&SampleData> {
        self.request_data.as_ref()
    }

    /// Sets optional request bytes.
    pub fn set_request_data(&mut self, value: Option<SampleData>) {
        self.request_data = value;
    }

    /// Sets a present request payload.
    pub fn set_request_data_bytes(&mut self, value: impl Into<SampleData>) {
        self.request_data = Some(value.into());
    }

    /// Returns optional response bytes.
    pub fn response_data(&self) -> Option<&SampleData> {
        self.response_data.as_ref()
    }

    /// Sets optional response bytes.
    pub fn set_response_data(&mut self, value: Option<SampleData>) {
        self.response_data = value;
    }

    /// Sets a present response payload.
    pub fn set_response_data_bytes(&mut self, value: impl Into<SampleData>) {
        self.response_data = Some(value.into());
    }

    /// Returns optional request headers.
    pub fn request_headers(&self) -> Option<&HeaderBlock> {
        self.request_headers.as_ref()
    }

    /// Sets optional request headers.
    pub fn set_request_headers(&mut self, value: Option<HeaderBlock>) {
        self.request_headers = value;
    }

    /// Sets a present raw request-header block.
    pub fn set_request_headers_text(&mut self, value: impl Into<String>) {
        self.request_headers = Some(HeaderBlock::new(value));
    }

    /// Returns optional response headers.
    pub fn response_headers(&self) -> Option<&HeaderBlock> {
        self.response_headers.as_ref()
    }

    /// Sets optional response headers.
    pub fn set_response_headers(&mut self, value: Option<HeaderBlock>) {
        self.response_headers = value;
    }

    /// Sets a present raw response-header block.
    pub fn set_response_headers_text(&mut self, value: impl Into<String>) {
        self.response_headers = Some(HeaderBlock::new(value));
    }

    /// Returns optional sampler data text.
    pub fn sampler_data(&self) -> Option<&str> {
        self.sampler_data.as_deref()
    }

    /// Sets optional sampler data text.
    pub fn set_sampler_data(&mut self, value: Option<String>) {
        self.sampler_data = value;
    }

    /// Sets present sampler data text.
    pub fn set_sampler_data_text(&mut self, value: impl Into<String>) {
        self.sampler_data = Some(value.into());
    }

    /// Returns optional response-file reference.
    pub fn response_file(&self) -> Option<&str> {
        self.response_file.as_deref()
    }

    /// Sets optional response-file reference.
    pub fn set_response_file(&mut self, value: Option<String>) {
        self.response_file = value;
    }

    /// Sets a present response-file reference.
    pub fn set_response_file_text(&mut self, value: impl Into<String>) {
        self.response_file = Some(value.into());
    }

    /// Returns optional sampler URL text.
    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    /// Sets optional sampler URL text.
    pub fn set_url(&mut self, value: Option<String>) {
        self.url = value;
    }

    /// Sets a present sampler URL text.
    pub fn set_url_text(&mut self, value: impl Into<String>) {
        self.url = Some(value.into());
    }

    /// Returns optional received byte count.
    pub const fn received_bytes(&self) -> Option<ByteCount> {
        self.received_bytes
    }

    /// Sets optional received byte count.
    pub const fn set_received_bytes(&mut self, value: Option<ByteCount>) {
        self.received_bytes = value;
    }

    /// Returns optional sent byte count.
    pub const fn sent_bytes(&self) -> Option<ByteCount> {
        self.sent_bytes
    }

    /// Sets optional sent byte count.
    pub const fn set_sent_bytes(&mut self, value: Option<ByteCount>) {
        self.sent_bytes = value;
    }

    /// Returns optional active-thread count for the group.
    pub const fn group_threads(&self) -> Option<ThreadCount> {
        self.group_threads
    }

    /// Sets optional active-thread count for the group.
    pub const fn set_group_threads(&mut self, value: Option<ThreadCount>) {
        self.group_threads = value;
    }

    /// Returns optional active-thread count across all groups.
    pub const fn all_threads(&self) -> Option<ThreadCount> {
        self.all_threads
    }

    /// Sets optional active-thread count across all groups.
    pub const fn set_all_threads(&mut self, value: Option<ThreadCount>) {
        self.all_threads = value;
    }

    /// Returns optional represented sample count.
    pub const fn sample_count(&self) -> Option<SampleCount> {
        self.sample_count
    }

    /// Sets optional represented sample count.
    pub const fn set_sample_count(&mut self, value: Option<SampleCount>) {
        self.sample_count = value;
    }

    /// Returns the represented error count.
    ///
    /// Ordinary JMeter samples derive this value from the sample outcome: a
    /// successful sample represents zero errors and an unsuccessful sample
    /// represents one.  Aggregated/statistical results retain their explicit
    /// count in `error_count`, so a supplied count always takes precedence.
    /// An absent success value remains absent until execution establishes the
    /// sample outcome.
    pub const fn error_count(&self) -> Option<ErrorCount> {
        match self.error_count {
            Some(value) => Some(value),
            None => match self.success {
                Some(true) => Some(ErrorCount::ZERO),
                Some(false) => Some(ErrorCount::new(1)),
                None => None,
            },
        }
    }

    /// Sets optional represented error count.
    pub const fn set_error_count(&mut self, value: Option<ErrorCount>) {
        self.error_count = value;
    }

    /// Returns assertion results in insertion order.
    pub fn assertions(&self) -> &[AssertionResult] {
        &self.assertions
    }

    /// Adds an assertion after checking its invariant.
    pub fn try_add_assertion(&mut self, assertion: AssertionResult) -> crate::Result<()> {
        assertion.validate()?;
        self.assertions.push(assertion);
        Ok(())
    }

    /// Alias for [`SampleResult::try_add_assertion`].
    pub fn add_assertion(&mut self, assertion: AssertionResult) -> crate::Result<()> {
        self.try_add_assertion(assertion)
    }

    /// Returns the XML wire thread name retained for this node, if any.
    pub(crate) fn wire_thread_name(&self) -> Option<&str> {
        self.wire_thread_name.as_deref()
    }

    /// Returns the XML wire host retained for this node, if any.
    pub(crate) fn wire_host(&self) -> Option<&str> {
        self.wire_host.as_deref()
    }

    /// Returns per-node wire variables, if the parser supplied any.
    pub(crate) fn wire_variables(&self) -> &crate::VariableSnapshot {
        &self.wire_variables
    }

    /// Returns the XML sample/httpSample spelling retained for this node.
    pub(crate) const fn wire_xml_sample_element(&self) -> Option<crate::XmlSampleElement> {
        self.wire_xml_sample_element
    }

    /// Retains XML node metadata without changing execution aggregation.
    pub(crate) fn set_wire_metadata(
        &mut self,
        thread_name: Option<String>,
        host: Option<String>,
        variables: crate::VariableSnapshot,
        element: crate::XmlSampleElement,
    ) {
        // Keep `None` distinct from `Some("")`: JTL XML omits an attribute
        // when it is absent, but emits an empty attribute when the wire value
        // is present and empty.
        self.wire_thread_name = thread_name;
        self.wire_host = host;
        self.wire_variables = variables;
        self.wire_xml_sample_element = Some(element);
    }

    pub(crate) fn wire_xml_attributes(&self) -> &[(String, String)] {
        &self.wire_xml_attributes
    }

    pub(crate) fn set_wire_xml_attributes(&mut self, attributes: Vec<(String, String)>) {
        self.wire_xml_attributes = attributes;
    }

    pub(crate) fn wire_xml_children(&self) -> &[crate::result::XmlOpaqueChild] {
        &self.wire_xml_children
    }

    pub(crate) fn add_wire_xml_child(&mut self, child: crate::result::XmlOpaqueChild) {
        self.wire_xml_children.push(child);
    }

    pub(crate) fn wire_xml_root_attributes(&self) -> &[(String, String)] {
        &self.wire_xml_root_attributes
    }

    pub(crate) fn set_wire_xml_root_metadata(
        &mut self,
        attributes: Vec<(String, String)>,
        children: Vec<crate::result::XmlOpaqueChild>,
    ) {
        self.wire_xml_root_attributes = attributes;
        self.wire_xml_root_children = children;
    }

    pub(crate) fn wire_xml_root_children(&self) -> &[crate::result::XmlOpaqueChild] {
        &self.wire_xml_root_children
    }

    pub(crate) fn wire_xml_root_children_after(&self) -> &[crate::result::XmlOpaqueChild] {
        &self.wire_xml_root_children_after
    }

    pub(crate) fn add_wire_xml_root_children_after(
        &mut self,
        children: impl IntoIterator<Item = crate::result::XmlOpaqueChild>,
    ) {
        self.wire_xml_root_children_after.extend(children);
    }

    /// Returns nested sub-results in insertion order.
    pub fn sub_results(&self) -> &[SampleResult] {
        &self.sub_results
    }

    /// Returns independent stop, logical-action, and ignore controls.
    pub fn flags(&self) -> &SampleFlags {
        &self.flags
    }

    /// Mutates independent stop, logical-action, and ignore controls.
    pub fn flags_mut(&mut self) -> &mut SampleFlags {
        &mut self.flags
    }

    /// Replaces the independent result-control flags.
    pub fn set_flags(&mut self, flags: SampleFlags) {
        self.flags = flags;
    }

    /// Returns whether this result is ignored.
    pub const fn ignored(&self) -> bool {
        self.flags.ignored()
    }

    /// Alias for [`SampleResult::ignored`].
    pub const fn is_ignored(&self) -> bool {
        self.ignored()
    }

    /// Sets whether this result is ignored.
    pub const fn set_ignored(&mut self, value: bool) {
        self.flags.set_ignored(value);
    }

    /// Alias for [`SampleResult::set_ignored`].
    pub const fn set_ignore(&mut self, value: bool) {
        self.set_ignored(value);
    }

    /// Returns whether this result requests stopping the current thread.
    pub const fn stop_thread(&self) -> bool {
        self.flags.stop_thread()
    }

    /// Sets whether this result requests stopping the current thread.
    pub const fn set_stop_thread(&mut self, value: bool) {
        self.flags.set_stop_thread(value);
    }

    /// Returns whether this result requests a graceful test stop.
    pub const fn stop_test(&self) -> bool {
        self.flags.stop_test()
    }

    /// Sets whether this result requests a graceful test stop.
    pub const fn set_stop_test(&mut self, value: bool) {
        self.flags.set_stop_test(value);
    }

    /// Returns whether this result requests an immediate test stop.
    pub const fn stop_test_now(&self) -> bool {
        self.flags.stop_test_now()
    }

    /// Sets whether this result requests an immediate test stop.
    pub const fn set_stop_test_now(&mut self, value: bool) {
        self.flags.set_stop_test_now(value);
    }

    /// Returns whether this result requests starting the next loop.
    pub const fn start_next_loop(&self) -> bool {
        self.flags.start_next_loop()
    }

    /// Sets whether this result requests starting the next loop.
    pub const fn set_start_next_loop(&mut self, value: bool) {
        self.flags.set_start_next_loop(value);
    }

    /// Returns the optional logical action.
    pub const fn logical_action(&self) -> Option<LogicalAction> {
        self.flags.logical_action()
    }

    /// Sets the optional logical action.
    pub const fn set_logical_action(&mut self, value: Option<LogicalAction>) {
        self.flags.set_logical_action(value);
    }

    /// Validates this result hierarchy with default finite limits.
    pub fn validate(&self) -> crate::Result<()> {
        self.validate_with_limits(ValidationLimits::default())
    }

    /// Validates timing, assertion, and hierarchy invariants iteratively.
    pub fn validate_with_limits(&self, limits: impl Into<ValidationLimits>) -> crate::Result<()> {
        let limits = limits.into();
        self.tree_stats(limits).map(|_| ())
    }

    /// Validates a wire-loaded result without applying execution-time timing
    /// inequalities.  All hierarchy, assertion, and resource-limit checks
    /// remain active.
    pub fn validate_wire_with_limits(
        &self,
        limits: impl Into<ValidationLimits>,
    ) -> crate::Result<()> {
        let limits = limits.into();
        self.tree_stats_internal(limits, false).map(|_| ())
    }

    /// Alias for [`SampleResult::validate_with_limits`].
    pub fn validate_hierarchy(&self, limits: impl Into<ValidationLimits>) -> crate::Result<()> {
        self.validate_with_limits(limits)
    }

    /// Adds a child result after validating hierarchy limits, timing, and all
    /// checked aggregate counters. The operation does not partially mutate the
    /// parent when a check fails.
    pub fn try_add_sub_result(
        &mut self,
        child: SampleResult,
        limits: impl Into<ValidationLimits>,
    ) -> crate::Result<()> {
        let limits = limits.into();
        let parent_stats = self.tree_stats(limits)?;
        let child_stats = child.tree_stats(limits)?;
        let total_nodes =
            parent_stats
                .nodes
                .checked_add(child_stats.nodes)
                .ok_or(ResultError::Overflow {
                    field: ResultField::SubResults,
                })?;
        if total_nodes > limits.max_nodes() {
            return Err(ResultError::HierarchyLimitExceeded {
                limit: HierarchyLimit::Nodes,
                actual: total_nodes,
                maximum: limits.max_nodes(),
            });
        }
        let child_depth = child_stats
            .max_depth
            .checked_add(1)
            .ok_or(ResultError::Overflow {
                field: ResultField::SubResults,
            })?;
        let max_depth = parent_stats.max_depth.max(child_depth);
        if max_depth > limits.max_depth() {
            return Err(ResultError::HierarchyLimitExceeded {
                limit: HierarchyLimit::Depth,
                actual: max_depth,
                maximum: limits.max_depth(),
            });
        }

        let mut candidate_timing = self.timing.clone();
        candidate_timing.aggregate_child(&child.timing)?;
        let received_bytes = checked_optional_sum(
            self.received_bytes,
            child.received_bytes,
            ResultField::ReceivedBytes,
        )?;
        let sent_bytes =
            checked_optional_sum(self.sent_bytes, child.sent_bytes, ResultField::SentBytes)?;
        let sample_count = checked_optional_sum(
            self.sample_count,
            child.sample_count,
            ResultField::SampleCount,
        )?;
        let error_count =
            checked_optional_sum(self.error_count, child.error_count, ResultField::ErrorCount)?;

        self.timing = candidate_timing;
        self.received_bytes = received_bytes;
        self.sent_bytes = sent_bytes;
        self.sample_count = sample_count;
        self.error_count = error_count;
        if child.success == Some(false) {
            self.success = Some(false);
        } else if self.success.is_none() {
            self.success = child.success;
        }
        self.sub_results.push(child);
        Ok(())
    }

    /// Adds a parsed child without applying JMeter's execution-time aggregate
    /// updates to the parent.
    ///
    /// JTL XML restoration stores the values written on the wire verbatim;
    /// unlike execution-time `addSubResult`, loading a child must not rewrite
    /// the parent's byte counters, timing, or sample counts.  The hierarchy
    /// and child invariants are still checked against the supplied bounds.
    pub fn try_add_sub_result_raw(
        &mut self,
        child: SampleResult,
        limits: impl Into<ValidationLimits>,
    ) -> crate::Result<()> {
        self.try_add_sub_results_raw([child], limits)
    }

    /// Adds several parsed children in one bounded, atomic hierarchy update.
    ///
    /// Existing and incoming trees are validated before `self` is mutated, so
    /// a node/depth failure leaves the parent unchanged.  Batch validation
    /// avoids recomputing the complete parent tree for every child when a
    /// protocol decoder receives a length-prefixed child list.
    pub fn try_add_sub_results_raw<I>(
        &mut self,
        children: I,
        limits: impl Into<ValidationLimits>,
    ) -> crate::Result<()>
    where
        I: IntoIterator<Item = SampleResult>,
    {
        let limits = limits.into();
        let parent_stats = self.tree_stats_internal(limits, false)?;
        let mut incoming = Vec::new();
        let mut incoming_nodes = 0usize;
        let mut incoming_depth = 0usize;
        for child in children {
            let child_stats = child.tree_stats_internal(limits, false)?;
            incoming_nodes =
                incoming_nodes
                    .checked_add(child_stats.nodes)
                    .ok_or(ResultError::Overflow {
                        field: ResultField::SubResults,
                    })?;
            let total_nodes =
                parent_stats
                    .nodes
                    .checked_add(incoming_nodes)
                    .ok_or(ResultError::Overflow {
                        field: ResultField::SubResults,
                    })?;
            if total_nodes > limits.max_nodes() {
                return Err(ResultError::HierarchyLimitExceeded {
                    limit: HierarchyLimit::Nodes,
                    actual: total_nodes,
                    maximum: limits.max_nodes(),
                });
            }
            let child_depth =
                child_stats
                    .max_depth
                    .checked_add(1)
                    .ok_or(ResultError::Overflow {
                        field: ResultField::SubResults,
                    })?;
            let max_depth = parent_stats.max_depth.max(incoming_depth.max(child_depth));
            if max_depth > limits.max_depth() {
                return Err(ResultError::HierarchyLimitExceeded {
                    limit: HierarchyLimit::Depth,
                    actual: max_depth,
                    maximum: limits.max_depth(),
                });
            }
            incoming_depth = incoming_depth.max(child_depth);
            incoming.push(child);
        }
        let total_nodes =
            parent_stats
                .nodes
                .checked_add(incoming_nodes)
                .ok_or(ResultError::Overflow {
                    field: ResultField::SubResults,
                })?;
        if total_nodes > limits.max_nodes() {
            return Err(ResultError::HierarchyLimitExceeded {
                limit: HierarchyLimit::Nodes,
                actual: total_nodes,
                maximum: limits.max_nodes(),
            });
        }
        let max_depth = parent_stats.max_depth.max(incoming_depth);
        if max_depth > limits.max_depth() {
            return Err(ResultError::HierarchyLimitExceeded {
                limit: HierarchyLimit::Depth,
                actual: max_depth,
                maximum: limits.max_depth(),
            });
        }
        self.sub_results.extend(incoming);
        Ok(())
    }

    /// Adds a cloned child result, retaining ownership of the caller's value.
    pub fn try_add_sub_result_ref(
        &mut self,
        child: &SampleResult,
        limits: impl Into<ValidationLimits>,
    ) -> crate::Result<()> {
        self.try_add_sub_result(child.clone(), limits)
    }

    /// Alias for [`SampleResult::try_add_sub_result`].
    pub fn add_sub_result(
        &mut self,
        child: SampleResult,
        limits: impl Into<ValidationLimits>,
    ) -> crate::Result<()> {
        self.try_add_sub_result(child, limits)
    }

    /// Explicitly named alias for checked sub-result aggregation.
    pub fn add_sub_result_with_limits(
        &mut self,
        child: SampleResult,
        limits: impl Into<ValidationLimits>,
    ) -> crate::Result<()> {
        self.try_add_sub_result(child, limits)
    }

    /// Adds a child using the crate's finite default hierarchy limits.
    pub fn append_sub_result(&mut self, child: SampleResult) -> crate::Result<()> {
        self.try_add_sub_result(child, ValidationLimits::default())
    }

    /// Alias for [`SampleResult::try_add_sub_result`].
    pub fn add_sub_result_checked(
        &mut self,
        child: SampleResult,
        limits: impl Into<ValidationLimits>,
    ) -> crate::Result<()> {
        self.try_add_sub_result(child, limits)
    }

    fn tree_stats(&self, limits: ValidationLimits) -> crate::Result<TreeStats> {
        self.tree_stats_internal(limits, true)
    }

    fn tree_stats_internal(
        &self,
        limits: ValidationLimits,
        validate_timing: bool,
    ) -> crate::Result<TreeStats> {
        let mut stack: Vec<(&SampleResult, usize)> = vec![(self, 1)];
        let mut nodes = 0usize;
        let mut max_depth = 0usize;
        let mut pending = 1usize;

        while let Some((node, depth)) = stack.pop() {
            pending = pending.saturating_sub(1);
            if depth > limits.max_depth() {
                return Err(ResultError::HierarchyLimitExceeded {
                    limit: HierarchyLimit::Depth,
                    actual: depth,
                    maximum: limits.max_depth(),
                });
            }
            nodes = nodes.checked_add(1).ok_or(ResultError::Overflow {
                field: ResultField::SubResults,
            })?;
            if nodes > limits.max_nodes() {
                return Err(ResultError::HierarchyLimitExceeded {
                    limit: HierarchyLimit::Nodes,
                    actual: nodes,
                    maximum: limits.max_nodes(),
                });
            }
            max_depth = max_depth.max(depth);
            if validate_timing {
                node.timing.validate()?;
            }
            for assertion in &node.assertions {
                assertion.validate()?;
            }
            for child in node.sub_results.iter().rev() {
                let child_depth = depth.checked_add(1).ok_or(ResultError::Overflow {
                    field: ResultField::SubResults,
                })?;
                pending = pending.checked_add(1).ok_or(ResultError::Overflow {
                    field: ResultField::SubResults,
                })?;
                if nodes
                    .checked_add(pending)
                    .is_some_and(|count| count > limits.max_nodes())
                {
                    return Err(ResultError::HierarchyLimitExceeded {
                        limit: HierarchyLimit::Nodes,
                        actual: nodes.saturating_add(pending),
                        maximum: limits.max_nodes(),
                    });
                }
                stack.push((child, child_depth));
            }
        }
        Ok(TreeStats { nodes, max_depth })
    }

    fn clone_shallow(&self) -> Self {
        Self {
            label: self.label.clone(),
            timing: self.timing.clone(),
            success: self.success,
            response_code: self.response_code.clone(),
            response_message: self.response_message.clone(),
            failure_message: self.failure_message.clone(),
            data_type: self.data_type.clone(),
            data_encoding: self.data_encoding.clone(),
            request_data: self.request_data.clone(),
            response_data: self.response_data.clone(),
            request_headers: self.request_headers.clone(),
            response_headers: self.response_headers.clone(),
            sampler_data: self.sampler_data.clone(),
            response_file: self.response_file.clone(),
            url: self.url.clone(),
            received_bytes: self.received_bytes,
            sent_bytes: self.sent_bytes,
            group_threads: self.group_threads,
            all_threads: self.all_threads,
            sample_count: self.sample_count,
            error_count: self.error_count,
            assertions: self.assertions.clone(),
            sub_results: Vec::new(),
            flags: self.flags.clone(),
            wire_thread_name: self.wire_thread_name.clone(),
            wire_host: self.wire_host.clone(),
            wire_variables: self.wire_variables.clone(),
            wire_xml_sample_element: self.wire_xml_sample_element,
            wire_xml_attributes: self.wire_xml_attributes.clone(),
            wire_xml_children: self.wire_xml_children.clone(),
            wire_xml_root_attributes: self.wire_xml_root_attributes.clone(),
            wire_xml_root_children: self.wire_xml_root_children.clone(),
            wire_xml_root_children_after: self.wire_xml_root_children_after.clone(),
        }
    }
}

impl Clone for SampleResult {
    fn clone(&self) -> Self {
        struct CloneFrame<'a> {
            source: &'a SampleResult,
            next_child: usize,
            value: SampleResult,
        }

        let mut stack = vec![CloneFrame {
            source: self,
            next_child: 0,
            value: self.clone_shallow(),
        }];

        loop {
            let child = match stack.last_mut() {
                Some(frame) if frame.next_child < frame.source.sub_results.len() => {
                    let child = &frame.source.sub_results[frame.next_child];
                    frame.next_child += 1;
                    Some(child)
                }
                _ => None,
            };
            if let Some(source) = child {
                stack.push(CloneFrame {
                    source,
                    next_child: 0,
                    value: source.clone_shallow(),
                });
                continue;
            }

            let completed = match stack.pop() {
                Some(frame) => frame.value,
                // The root frame is installed before the loop and is only
                // removed in this branch. This fallback is therefore
                // unreachable for a valid CloneFrame stack.
                None => return self.clone_shallow(),
            };
            if let Some(parent) = stack.last_mut() {
                parent.value.sub_results.push(completed);
            } else {
                return completed;
            }
        }
    }
}

impl Drop for SampleResult {
    fn drop(&mut self) {
        // A malformed/untrusted result can be deeply nested. Drain children
        // iteratively so dropping it does not recurse once per hierarchy node.
        let mut pending = Vec::new();
        pending.append(&mut self.sub_results);
        while let Some(mut node) = pending.pop() {
            pending.append(&mut node.sub_results);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TreeStats {
    nodes: usize,
    max_depth: usize,
}

fn checked_optional_sum<T>(
    parent: Option<T>,
    child: Option<T>,
    field: ResultField,
) -> crate::Result<Option<T>>
where
    T: Copy + CheckedAdd,
{
    match (parent, child) {
        (Some(parent), Some(child)) => parent.checked_add_value(child, field).map(Some),
        (Some(value), None) | (None, Some(value)) => Ok(Some(value)),
        (None, None) => Ok(None),
    }
}

trait CheckedAdd: Copy {
    fn checked_add_value(self, other: Self, field: ResultField) -> crate::Result<Self>;
}

macro_rules! checked_add_impl {
    ($($name:ty),+ $(,)?) => {
        $(
            impl CheckedAdd for $name {
                fn checked_add_value(self, other: Self, field: ResultField) -> crate::Result<Self> {
                    self.checked_add(other).map_err(|_| ResultError::Overflow { field })
                }
            }
        )+
    };
}

checked_add_impl!(ByteCount, SampleCount, ErrorCount, ThreadCount);

#[cfg(test)]
mod tests {
    use super::{ErrorCount, SampleResult};

    #[test]
    fn ordinary_error_count_derives_from_success() {
        let mut result = SampleResult::new("ordinary");
        assert_eq!(result.error_count(), None);

        result.set_successful(true);
        assert_eq!(result.error_count(), Some(ErrorCount::ZERO));

        result.set_successful(false);
        assert_eq!(result.error_count(), Some(ErrorCount::new(1)));
    }

    #[test]
    fn explicit_aggregate_error_count_is_preserved() {
        let mut result = SampleResult::new("aggregate");
        result.set_successful(false);
        result.set_error_count(Some(ErrorCount::new(3)));

        assert_eq!(result.error_count(), Some(ErrorCount::new(3)));
    }
}
