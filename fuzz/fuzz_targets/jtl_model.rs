#![no_main]

//! Generated-model JTL lane.
//!
//! This target is deliberately separate from `jtl_csv` and `jtl_xml`: those
//! targets start with arbitrary wire bytes, while this one starts with a
//! bounded, independently generated `SampleEvent` tree.  The source model is
//! projected to the values each format is expected to retain before decoding;
//! the decoded model is then compared to that source-side inventory.  No
//! expectation is obtained by decoding the bytes first.
//!
//! Compatibility scope: JTL-001..JTL-005, REPORT-001, and TEST-003.  The
//! report-listener ID is represented here by the aggregate event/result model;
//! no listener or runtime process is started by this lane.
//!
//! Invariants:
//! * `TEST-003-JTL-MODEL-001` checks the generated CSV wire projection,
//!   including configured variables and absent/present-empty normalization.
//! * `TEST-003-JTL-MODEL-002` checks the generated XML tree, assertions,
//!   payload children, save switches, and nested results.
//! * `TEST-003-JTL-MODEL-003` injects one bounded unknown XML child and checks
//!   that its marker is conserved through decode and re-encode.
//! * `TEST-003-JTL-MODEL-LIMIT-001` keeps model depth, node, text, input, and
//!   codec resource bounds finite and in-memory only.
//!
//! Source-side coverage: generated event fields, presence states, variables,
//! assertions, nested children, and the injected opaque marker form the model
//! inventory before either decoder is called.
//! I/O policy: none; all model, codec, and output buffers stay in memory.

use std::fmt::Display;

use jmeter_rs_results::{
    AssertionResult, AssertionResults, ByteCount, CsvColumn, CsvDecoder, CsvEncoder, CsvField,
    DataEncoding, DataType, ElapsedTime, ErrorCount, HeaderBlock, HostIdentity, IdleTime,
    JtlLimits, Latency, LineEnding, SampleCount, SampleData, SampleEvent, SampleResult,
    SampleSaveConfiguration, SampleTiming, ThreadCount, ThreadIdentity, TimestampFormat,
    ValidationLimits, VariableSnapshot, VariableValue, WallTimestamp, XmlDecodeConfiguration,
    XmlDecoder, XmlEncoder, XmlSampleElement,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 256 * 1024;
const MAX_TEXT_BYTES: usize = 48;
const MAX_RESULT_DEPTH: usize = 4;
const MAX_RESULT_NODES: usize = 64;
const MAX_ASSERTIONS: usize = 3;
const MAX_CHILDREN: usize = 2;

fn limits() -> JtlLimits {
    JtlLimits::new(MAX_INPUT_BYTES, 16 * 1024, 4 * 1024, 64, 16, 512, 128, 64)
        .expect("fuzz target constants must define non-zero limits")
}

fn validation_limits() -> ValidationLimits {
    ValidationLimits::new(8, MAX_RESULT_NODES)
        .expect("fuzz target hierarchy constants must be valid")
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Presence {
    Absent,
    Present(String),
}

impl Presence {
    fn present(value: impl Display) -> Self {
        Self::Present(value.to_string())
    }

    fn from_option<T>(value: Option<T>) -> Self
    where
        T: Display,
    {
        value.map_or(Self::Absent, Self::present)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CsvInventory {
    columns: Vec<Presence>,
    defaults: [Presence; 3],
    thread: String,
    host: String,
    variables: Vec<Presence>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AssertionInventory {
    name: String,
    failure: bool,
    error: bool,
    failure_message: Presence,
    error_message: Presence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct XmlResultInventory {
    label: Presence,
    timestamp: Presence,
    elapsed: Presence,
    idle: Presence,
    latency: Presence,
    connect: Presence,
    success: Presence,
    response_code: Presence,
    response_message: Presence,
    data_type: Presence,
    encoding: Presence,
    received_bytes: Presence,
    sent_bytes: Presence,
    sample_count: Presence,
    error_count: Presence,
    group_threads: Presence,
    all_threads: Presence,
    response_headers: Presence,
    request_headers: Presence,
    response_data: Presence,
    response_file: Presence,
    sampler_data: Presence,
    url: Presence,
    assertions: Vec<AssertionInventory>,
    children: Vec<XmlResultInventory>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct XmlInventory {
    result: XmlResultInventory,
    thread: Presence,
    host: Presence,
    variables: Vec<Presence>,
}

struct ByteCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn next(&mut self) -> u8 {
        if self.bytes.is_empty() {
            return 0;
        }
        let value = self.bytes[self.offset % self.bytes.len()];
        self.offset = self.offset.saturating_add(1);
        value
    }

    fn bool(&mut self) -> bool {
        self.next() & 1 == 1
    }

    fn bounded(&mut self, maximum: usize) -> usize {
        if maximum == 0 {
            return 0;
        }
        usize::from(self.next()) % (maximum + 1)
    }

    fn signed_millis(&mut self) -> i64 {
        let magnitude = i64::from(self.next()) % 10_000;
        if self.next() & 3 == 0 {
            -magnitude
        } else {
            magnitude
        }
    }

    fn non_negative(&mut self) -> u64 {
        u64::from(self.next()) % 10_000
    }

    fn text(&mut self, prefix: &str) -> String {
        let length = self.bounded(MAX_TEXT_BYTES.min(12));
        let mut value = String::with_capacity(prefix.len() + length);
        value.push_str(prefix);
        for _ in 0..length {
            let character = match self.next() % 16 {
                0 => ',',
                1 => '"',
                2 => '&',
                3 => '<',
                4 => '>',
                5 => '\n',
                6 => ' ',
                value => char::from(b'a' + value),
            };
            value.push(character);
        }
        value
    }

    fn identifier(&mut self, prefix: &str) -> String {
        let mut value = String::with_capacity(prefix.len() + 4);
        value.push_str(prefix);
        for _ in 0..3 {
            value.push(char::from(b'a' + self.next() % 26));
        }
        value
    }
}

fn optional_text(cursor: &mut ByteCursor<'_>, prefix: &str) -> Option<String> {
    match cursor.next() % 3 {
        0 => None,
        1 => Some(String::new()),
        _ => Some(cursor.text(prefix)),
    }
}

fn optional_data(cursor: &mut ByteCursor<'_>, prefix: &str) -> Option<SampleData> {
    match cursor.next() % 3 {
        0 => None,
        1 => Some(SampleData::empty()),
        _ => Some(SampleData::from(cursor.text(prefix))),
    }
}

fn optional_header(cursor: &mut ByteCursor<'_>, prefix: &str) -> Option<HeaderBlock> {
    optional_text(cursor, prefix).map(HeaderBlock::new)
}

fn generate_assertion(cursor: &mut ByteCursor<'_>, index: usize) -> AssertionResult {
    let failure = cursor.bool();
    let error = cursor.bool();
    AssertionResult::from_flags(
        cursor.text(&format!("assertion-{index}-")),
        failure,
        error,
        optional_text(cursor, "failure-"),
        optional_text(cursor, "error-"),
    )
    .expect("generated assertion flags and bounded text are valid")
}

fn generate_result(cursor: &mut ByteCursor<'_>, depth: usize) -> SampleResult {
    let mut result = if cursor.bool() {
        SampleResult::new(cursor.text("label-"))
    } else {
        SampleResult::without_label()
    };

    let timestamp = if cursor.bool() {
        Some(WallTimestamp::from_millis(cursor.signed_millis()))
    } else {
        None
    };
    let start = if cursor.bool() {
        Some(WallTimestamp::from_millis(cursor.signed_millis()))
    } else {
        None
    };
    let end = start.map(|value| {
        value
            .checked_add_millis(i64::try_from(cursor.non_negative()).unwrap_or(0))
            .unwrap_or(value)
    });
    let timing = SampleTiming::from_wire_parts(
        timestamp,
        start,
        end,
        cursor
            .bool()
            .then(|| ElapsedTime::from_millis(cursor.non_negative())),
        cursor
            .bool()
            .then(|| Latency::from_millis(cursor.non_negative())),
        cursor
            .bool()
            .then(|| jmeter_rs_results::ConnectTime::from_millis(cursor.non_negative())),
        cursor
            .bool()
            .then(|| IdleTime::from_millis(cursor.non_negative())),
    );
    result.set_timing_from_wire(timing);
    result.set_success(match cursor.next() % 3 {
        0 => None,
        1 => Some(false),
        _ => Some(true),
    });
    result.set_response_code(optional_text(cursor, "code-"));
    result.set_response_message(optional_text(cursor, "message-"));
    result.set_failure_message(optional_text(cursor, "sample-failure-"));

    let data_type = match cursor.next() % 4 {
        0 => None,
        1 => Some(DataType::Text),
        2 => Some(DataType::Other(cursor.identifier("data-"))),
        _ => Some(DataType::Binary),
    };
    result.set_data_type(data_type.clone());
    result.set_data_encoding(match cursor.next() % 3 {
        0 => None,
        1 => Some(DataEncoding::new(String::new())),
        _ => Some(DataEncoding::new(cursor.identifier("enc-"))),
    });

    result.set_request_data(optional_data(cursor, "request-"));
    let response_data = optional_data(cursor, "response-");
    // XML responseData is text in this pure codec.  A binary result may still
    // carry an explicitly present empty payload, but not arbitrary bytes.
    if matches!(data_type, Some(DataType::Binary))
        && response_data.as_ref().is_some_and(|data| !data.is_empty())
    {
        result.set_response_data(Some(SampleData::empty()));
    } else {
        result.set_response_data(response_data);
    }
    result.set_request_headers(optional_header(cursor, "request-header-"));
    result.set_response_headers(optional_header(cursor, "response-header-"));
    result.set_sampler_data(optional_text(cursor, "sampler-"));
    result.set_response_file(optional_text(cursor, "file-"));
    result.set_url(optional_text(cursor, "https://example.invalid/"));
    result.set_received_bytes(cursor.bool().then(|| ByteCount::new(cursor.non_negative())));
    result.set_sent_bytes(cursor.bool().then(|| ByteCount::new(cursor.non_negative())));
    result.set_group_threads(
        cursor
            .bool()
            .then(|| ThreadCount::new(cursor.non_negative())),
    );
    result.set_all_threads(
        cursor
            .bool()
            .then(|| ThreadCount::new(cursor.non_negative())),
    );
    result.set_sample_count(
        cursor
            .bool()
            .then(|| SampleCount::new(cursor.non_negative())),
    );
    result.set_error_count(
        cursor
            .bool()
            .then(|| ErrorCount::new(cursor.non_negative())),
    );

    let assertion_count = cursor.bounded(MAX_ASSERTIONS);
    for index in 0..assertion_count {
        result
            .add_assertion(generate_assertion(cursor, index))
            .expect("generated assertions are valid");
    }

    if depth < MAX_RESULT_DEPTH && cursor.bool() {
        let child_count = cursor.bounded(MAX_CHILDREN);
        for _ in 0..child_count {
            result
                .try_add_sub_result_raw(generate_result(cursor, depth + 1), validation_limits())
                .expect("generated result tree stays within explicit limits");
        }
    }
    result
}

fn sample_variables() -> [&'static str; 2] {
    ["case_id", "region"]
}

fn generate_event(cursor: &mut ByteCursor<'_>) -> SampleEvent {
    let mut variables = VariableSnapshot::new();
    for name in sample_variables() {
        match cursor.next() % 3 {
            0 => {
                variables.insert_absent(name);
            }
            1 => {
                variables.insert(name, VariableValue::present(String::new()));
            }
            _ => {
                variables.insert(name, VariableValue::present(cursor.text("variable-")));
            }
        }
    }
    SampleEvent::new(
        generate_result(cursor, 0),
        cursor.identifier("run-"),
        ThreadIdentity::with_group(
            cursor.text("thread-"),
            optional_text(cursor, "group-"),
            cursor.bool().then(|| u64::from(cursor.next())),
        ),
        HostIdentity::new(cursor.text("host-")),
        variables,
    )
}

fn configure_csv(cursor: &mut ByteCursor) -> SampleSaveConfiguration {
    let mut configuration = SampleSaveConfiguration::csv();
    configuration.set_timestamp_format(if cursor.bool() {
        TimestampFormat::Milliseconds
    } else {
        TimestampFormat::None
    });
    configuration.set_print_field_names(cursor.bool());
    configuration.set_timestamp(cursor.bool());
    configuration.set_time(cursor.bool());
    configuration.set_latency(cursor.bool());
    configuration.set_connect_time(cursor.bool());
    configuration.set_idle_time(cursor.bool());
    configuration.set_success(cursor.bool());
    configuration.set_label(cursor.bool());
    configuration.set_response_code(cursor.bool());
    configuration.set_response_message(cursor.bool());
    configuration.set_thread_name(cursor.bool());
    configuration.set_data_type(cursor.bool());
    configuration.set_encoding(cursor.bool());
    configuration.set_assertion_results(AssertionResults::None);
    configuration.set_bytes(cursor.bool());
    configuration.set_sent_bytes(cursor.bool());
    configuration.set_thread_counts(cursor.bool());
    configuration.set_url(cursor.bool());
    configuration.set_filename(cursor.bool());
    configuration.set_sample_count(cursor.bool());
    configuration.set_hostname(cursor.bool());
    configuration.set_subresults(false);
    configuration.set_default_encoding(if cursor.bool() {
        Some("UTF-8".to_owned())
    } else {
        None
    });
    configuration
        .set_sample_variables(sample_variables())
        .expect("static sample-variable names are valid");
    configuration
        .set_delimiter(match cursor.next() % 3 {
            0 => ',',
            1 => '\t',
            _ => ';',
        })
        .expect("static CSV delimiters are valid");
    configuration.set_line_ending(match cursor.next() % 3 {
        0 => LineEnding::Lf,
        1 => LineEnding::CrLf,
        _ => LineEnding::Cr,
    });
    configuration
}

fn configure_xml(cursor: &mut ByteCursor) -> SampleSaveConfiguration {
    let mut configuration = SampleSaveConfiguration::xml();
    configuration.set_timestamp(cursor.bool());
    configuration.set_timestamp_start(cursor.bool());
    configuration.set_time(cursor.bool());
    configuration.set_idle_time(cursor.bool());
    configuration.set_latency(cursor.bool());
    configuration.set_connect_time(cursor.bool());
    configuration.set_success(cursor.bool());
    configuration.set_label(cursor.bool());
    configuration.set_response_code(cursor.bool());
    configuration.set_response_message(cursor.bool());
    configuration.set_thread_name(cursor.bool());
    configuration.set_data_type(cursor.bool());
    configuration.set_encoding(cursor.bool());
    configuration.set_bytes(cursor.bool());
    configuration.set_sent_bytes(cursor.bool());
    configuration.set_sample_count(cursor.bool());
    configuration.set_thread_counts(cursor.bool());
    configuration.set_hostname(cursor.bool());
    configuration.set_filename(cursor.bool());
    configuration.set_response_headers(cursor.bool());
    configuration.set_request_headers(cursor.bool());
    configuration.set_sampler_data(cursor.bool());
    // Keep responseData selected so both absent and present-empty payloads
    // have an explicit XML wire representation.  The error-only switch is
    // still varied below as part of save-configuration coverage.
    configuration.set_response_data(true);
    configuration.set_response_data_on_error(cursor.bool());
    configuration.set_assertion_results(match cursor.next() % 3 {
        0 => AssertionResults::None,
        1 => AssertionResults::First,
        _ => AssertionResults::All,
    });
    configuration.set_assertion_results_failure_message(cursor.bool());
    configuration.set_subresults(true);
    configuration.set_subresults_disable_renaming(true);
    configuration.set_default_encoding(Some("UTF-8".to_owned()));
    configuration
        .set_sample_variables(sample_variables())
        .expect("static sample-variable names are valid");
    configuration.set_xml_sample_element(if cursor.bool() {
        XmlSampleElement::HttpSample
    } else {
        XmlSampleElement::Sample
    });
    configuration.set_line_ending(match cursor.next() % 3 {
        0 => LineEnding::Lf,
        1 => LineEnding::CrLf,
        _ => LineEnding::Cr,
    });
    configuration
}

fn optional_string(value: Option<&str>) -> Presence {
    value.map_or(Presence::Absent, |value| {
        Presence::Present(value.to_owned())
    })
}

fn csv_expected_column(
    event: &SampleEvent,
    result: &SampleResult,
    configuration: &SampleSaveConfiguration,
    column: &CsvColumn,
) -> Presence {
    match column {
        CsvColumn::Variable(name) => Presence::Present(
            event
                .variables()
                .get(name)
                .and_then(VariableValue::as_str)
                .unwrap_or_default()
                .to_owned(),
        ),
        CsvColumn::Field(field) => match field {
            CsvField::Timestamp => Presence::present(
                result
                    .timestamp()
                    .map(WallTimestamp::as_millis)
                    .unwrap_or(0),
            ),
            CsvField::Elapsed => {
                Presence::present(result.elapsed().map(ElapsedTime::as_millis).unwrap_or(0))
            }
            CsvField::Label => Presence::Present(result.label().to_owned()),
            CsvField::ResponseCode => {
                Presence::Present(result.response_code().unwrap_or_default().to_owned())
            }
            CsvField::ResponseMessage => {
                Presence::Present(result.response_message().unwrap_or_default().to_owned())
            }
            CsvField::ThreadName => Presence::Present(event.thread().name().to_owned()),
            CsvField::DataType => Presence::Present(
                result
                    .data_type()
                    .map(DataType::as_wire)
                    .unwrap_or("text")
                    .to_owned(),
            ),
            CsvField::Success => Presence::present(result.success().unwrap_or(true)),
            CsvField::FailureMessage => Presence::Present(first_failure_message(result)),
            CsvField::Bytes => {
                Presence::present(result.received_bytes().map(ByteCount::as_u64).unwrap_or(0))
            }
            CsvField::SentBytes => {
                Presence::present(result.sent_bytes().map(ByteCount::as_u64).unwrap_or(0))
            }
            CsvField::GroupThreads => {
                Presence::present(result.group_threads().map(ThreadCount::as_u64).unwrap_or(0))
            }
            CsvField::AllThreads => {
                Presence::present(result.all_threads().map(ThreadCount::as_u64).unwrap_or(0))
            }
            CsvField::Url => result.url().map_or(Presence::Absent, |value| {
                Presence::Present(value.to_owned())
            }),
            CsvField::Filename => {
                Presence::Present(result.response_file().unwrap_or_default().to_owned())
            }
            CsvField::Latency => {
                Presence::present(result.latency().map(Latency::as_millis).unwrap_or(0))
            }
            CsvField::Encoding => Presence::Present(
                result
                    .data_encoding()
                    .map(DataEncoding::as_str)
                    .or_else(|| configuration.default_encoding())
                    .unwrap_or_default()
                    .to_owned(),
            ),
            CsvField::SampleCount => {
                Presence::present(result.sample_count().map(SampleCount::as_u64).unwrap_or(1))
            }
            CsvField::ErrorCount => {
                Presence::present(result.error_count().map(ErrorCount::as_u64).unwrap_or(0))
            }
            CsvField::Hostname => Presence::Present(event.host().as_str().to_owned()),
            CsvField::IdleTime => {
                Presence::present(result.idle_time().map(IdleTime::as_millis).unwrap_or(0))
            }
            CsvField::Connect => Presence::present(
                result
                    .connect_time()
                    .map(jmeter_rs_results::ConnectTime::as_millis)
                    .unwrap_or(0),
            ),
        },
    }
}

fn csv_actual_column(event: &SampleEvent, result: &SampleResult, column: &CsvColumn) -> Presence {
    match column {
        CsvColumn::Variable(name) => {
            Presence::from_option(event.variables().get(name).and_then(VariableValue::as_str))
        }
        CsvColumn::Field(field) => match field {
            CsvField::Timestamp => {
                Presence::from_option(result.timestamp().map(WallTimestamp::as_millis))
            }
            CsvField::Elapsed => {
                Presence::from_option(result.elapsed().map(ElapsedTime::as_millis))
            }
            CsvField::Label => optional_string(result.label_field()),
            CsvField::ResponseCode => optional_string(result.response_code()),
            CsvField::ResponseMessage => optional_string(result.response_message()),
            CsvField::ThreadName => Presence::Present(event.thread().name().to_owned()),
            CsvField::DataType => Presence::from_option(result.data_type().map(DataType::as_wire)),
            CsvField::Success => Presence::from_option(result.success()),
            CsvField::FailureMessage => optional_string(result.failure_message()),
            CsvField::Bytes => {
                Presence::from_option(result.received_bytes().map(ByteCount::as_u64))
            }
            CsvField::SentBytes => {
                Presence::from_option(result.sent_bytes().map(ByteCount::as_u64))
            }
            CsvField::GroupThreads => {
                Presence::from_option(result.group_threads().map(ThreadCount::as_u64))
            }
            CsvField::AllThreads => {
                Presence::from_option(result.all_threads().map(ThreadCount::as_u64))
            }
            CsvField::Url => optional_string(result.url()),
            CsvField::Filename => optional_string(result.response_file()),
            CsvField::Latency => Presence::from_option(result.latency().map(Latency::as_millis)),
            CsvField::Encoding => {
                Presence::from_option(result.data_encoding().map(DataEncoding::as_str))
            }
            CsvField::SampleCount => {
                Presence::from_option(result.sample_count().map(SampleCount::as_u64))
            }
            CsvField::ErrorCount => {
                Presence::from_option(result.error_count().map(ErrorCount::as_u64))
            }
            CsvField::Hostname => Presence::Present(event.host().as_str().to_owned()),
            CsvField::IdleTime => {
                Presence::from_option(result.idle_time().map(IdleTime::as_millis))
            }
            CsvField::Connect => Presence::from_option(
                result
                    .connect_time()
                    .map(jmeter_rs_results::ConnectTime::as_millis),
            ),
        },
    }
}

fn first_failure_message(result: &SampleResult) -> String {
    result
        .assertions()
        .iter()
        .find_map(|assertion| assertion.failure_message().or(assertion.error_message()))
        .or_else(|| result.failure_message())
        .unwrap_or_default()
        .to_owned()
}

fn csv_source_inventory(
    event: &SampleEvent,
    configuration: &SampleSaveConfiguration,
) -> CsvInventory {
    let result = event.result();
    let success_default = if configuration.save_success() {
        result.success().unwrap_or(true)
    } else {
        true
    };
    let data_type_default = if configuration.save_data_type() {
        result
            .data_type()
            .map(DataType::as_wire)
            .unwrap_or("text")
            .to_owned()
    } else {
        "text".to_owned()
    };
    let encoding_default = if configuration.save_encoding() {
        Presence::Present(
            result
                .data_encoding()
                .map(|value| value.as_str().to_owned())
                .or_else(|| configuration.default_encoding().map(str::to_owned))
                .unwrap_or_default(),
        )
    } else {
        configuration
            .default_encoding()
            .map_or(Presence::Absent, |value| {
                Presence::Present(value.to_owned())
            })
    };
    let columns = configuration
        .columns()
        .iter()
        .map(|column| csv_expected_column(event, result, configuration, column))
        .collect();
    let defaults = [
        Presence::present(success_default),
        Presence::Present(data_type_default),
        encoding_default,
    ];
    CsvInventory {
        columns,
        defaults,
        thread: if configuration.save_thread_name() {
            event.thread().name().to_owned()
        } else {
            String::new()
        },
        host: if configuration.save_hostname() {
            event.host().as_str().to_owned()
        } else {
            String::new()
        },
        variables: configuration
            .sample_variables()
            .iter()
            .map(|name| {
                Presence::Present(
                    event
                        .variables()
                        .get(name)
                        .and_then(VariableValue::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                )
            })
            .collect(),
    }
}

fn csv_decoded_inventory(
    event: &SampleEvent,
    configuration: &SampleSaveConfiguration,
) -> CsvInventory {
    let columns = configuration
        .columns()
        .iter()
        .map(|column| csv_actual_column(event, event.result(), column))
        .collect();
    CsvInventory {
        columns,
        defaults: [
            Presence::from_option(event.result().success()),
            Presence::from_option(event.result().data_type().map(DataType::as_wire)),
            Presence::from_option(event.result().data_encoding().map(DataEncoding::as_str)),
        ],
        thread: event.thread().name().to_owned(),
        host: event.host().as_str().to_owned(),
        variables: configuration
            .sample_variables()
            .iter()
            .map(|name| {
                Presence::from_option(event.variables().get(name).and_then(VariableValue::as_str))
            })
            .collect(),
    }
}

fn xml_timestamp(result: &SampleResult, configuration: &SampleSaveConfiguration) -> Presence {
    if !configuration.save_timestamp() {
        return Presence::Absent;
    }
    let value = if configuration.timestamp_start() {
        result.start_time().or_else(|| result.timestamp())
    } else {
        result.end_time().or_else(|| result.timestamp())
    }
    .map(WallTimestamp::as_millis)
    .unwrap_or(0);
    Presence::present(value)
}

fn xml_assertions(
    result: &SampleResult,
    configuration: &SampleSaveConfiguration,
) -> Vec<AssertionInventory> {
    let count = match configuration.assertion_results() {
        AssertionResults::None => 0,
        AssertionResults::First => result.assertions().len().min(1),
        AssertionResults::All => result.assertions().len(),
    };
    result
        .assertions()
        .iter()
        .take(count)
        .map(|assertion| AssertionInventory {
            name: assertion.name().to_owned(),
            failure: assertion.is_failure(),
            error: assertion.is_error(),
            failure_message: optional_string(assertion.failure_message()),
            error_message: optional_string(assertion.error_message()),
        })
        .collect()
}

fn xml_source_result_inventory(
    result: &SampleResult,
    configuration: &SampleSaveConfiguration,
) -> XmlResultInventory {
    let children = if configuration.save_subresults() {
        result
            .sub_results()
            .iter()
            .map(|child| xml_source_result_inventory(child, configuration))
            .collect()
    } else {
        Vec::new()
    };
    XmlResultInventory {
        label: if configuration.save_label() {
            Presence::Present(result.label().to_owned())
        } else {
            Presence::Absent
        },
        timestamp: xml_timestamp(result, configuration),
        elapsed: if configuration.save_time() {
            Presence::present(result.elapsed().map(ElapsedTime::as_millis).unwrap_or(0))
        } else {
            Presence::Absent
        },
        idle: if configuration.save_idle_time() {
            Presence::present(result.idle_time().map(IdleTime::as_millis).unwrap_or(0))
        } else {
            Presence::Absent
        },
        latency: if configuration.save_latency() {
            Presence::present(result.latency().map(Latency::as_millis).unwrap_or(0))
        } else {
            Presence::Absent
        },
        connect: if configuration.save_connect_time() {
            Presence::present(
                result
                    .connect_time()
                    .map(jmeter_rs_results::ConnectTime::as_millis)
                    .unwrap_or(0),
            )
        } else {
            Presence::Absent
        },
        success: if configuration.save_success() {
            Presence::present(result.success().unwrap_or(true))
        } else {
            Presence::Absent
        },
        response_code: if configuration.save_response_code() {
            Presence::Present(result.response_code().unwrap_or_default().to_owned())
        } else {
            Presence::Absent
        },
        response_message: if configuration.save_response_message() {
            Presence::Present(result.response_message().unwrap_or_default().to_owned())
        } else {
            Presence::Absent
        },
        data_type: if configuration.save_data_type() {
            Presence::Present(
                result
                    .data_type()
                    .map(DataType::as_wire)
                    .unwrap_or("text")
                    .to_owned(),
            )
        } else {
            Presence::Absent
        },
        encoding: if configuration.save_encoding() {
            result
                .data_encoding()
                .map(|value| Presence::Present(value.as_str().to_owned()))
                .or_else(|| {
                    configuration
                        .default_encoding()
                        .map(|value| Presence::Present(value.to_owned()))
                })
                .unwrap_or(Presence::Absent)
        } else {
            Presence::Absent
        },
        received_bytes: if configuration.save_bytes() {
            Presence::present(result.received_bytes().map(ByteCount::as_u64).unwrap_or(0))
        } else {
            Presence::Absent
        },
        sent_bytes: if configuration.save_sent_bytes() {
            Presence::present(result.sent_bytes().map(ByteCount::as_u64).unwrap_or(0))
        } else {
            Presence::Absent
        },
        sample_count: if configuration.save_sample_count() {
            Presence::present(result.sample_count().map(SampleCount::as_u64).unwrap_or(1))
        } else {
            Presence::Absent
        },
        error_count: if configuration.save_error_count() {
            Presence::present(result.error_count().map(ErrorCount::as_u64).unwrap_or(0))
        } else {
            Presence::Absent
        },
        group_threads: if configuration.save_thread_counts() {
            Presence::present(result.group_threads().map(ThreadCount::as_u64).unwrap_or(0))
        } else {
            Presence::Absent
        },
        all_threads: if configuration.save_thread_counts() {
            Presence::present(result.all_threads().map(ThreadCount::as_u64).unwrap_or(0))
        } else {
            Presence::Absent
        },
        response_headers: if configuration.save_response_headers() {
            Presence::Present(
                result
                    .response_headers()
                    .map(HeaderBlock::as_str)
                    .unwrap_or_default()
                    .to_owned(),
            )
        } else {
            Presence::Absent
        },
        request_headers: if configuration.save_request_headers() {
            Presence::Present(
                result
                    .request_headers()
                    .map(HeaderBlock::as_str)
                    .unwrap_or_default()
                    .to_owned(),
            )
        } else {
            Presence::Absent
        },
        response_data: Presence::Present(
            result
                .response_data()
                .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
                .unwrap_or_default(),
        ),
        response_file: if configuration.save_filename() {
            Presence::Present(result.response_file().unwrap_or_default().to_owned())
        } else {
            Presence::Absent
        },
        sampler_data: if configuration.save_sampler_data() {
            optional_string(result.sampler_data())
        } else {
            Presence::Absent
        },
        url: if configuration.save_url() {
            optional_string(result.url())
        } else {
            Presence::Absent
        },
        assertions: xml_assertions(result, configuration),
        children,
    }
}

fn xml_actual_result_inventory(
    result: &SampleResult,
    configuration: &SampleSaveConfiguration,
) -> XmlResultInventory {
    XmlResultInventory {
        label: if configuration.save_label() {
            optional_string(result.label_field())
        } else {
            Presence::Absent
        },
        timestamp: Presence::from_option(result.timestamp().map(WallTimestamp::as_millis)),
        elapsed: if configuration.save_time() {
            Presence::from_option(result.elapsed().map(ElapsedTime::as_millis))
        } else {
            Presence::Absent
        },
        idle: if configuration.save_idle_time() {
            Presence::from_option(result.idle_time().map(IdleTime::as_millis))
        } else {
            Presence::Absent
        },
        latency: if configuration.save_latency() {
            Presence::from_option(result.latency().map(Latency::as_millis))
        } else {
            Presence::Absent
        },
        connect: if configuration.save_connect_time() {
            Presence::from_option(
                result
                    .connect_time()
                    .map(jmeter_rs_results::ConnectTime::as_millis),
            )
        } else {
            Presence::Absent
        },
        success: if configuration.save_success() {
            Presence::from_option(result.success())
        } else {
            Presence::Absent
        },
        response_code: if configuration.save_response_code() {
            optional_string(result.response_code())
        } else {
            Presence::Absent
        },
        response_message: if configuration.save_response_message() {
            optional_string(result.response_message())
        } else {
            Presence::Absent
        },
        data_type: if configuration.save_data_type() {
            Presence::from_option(result.data_type().map(DataType::as_wire))
        } else {
            Presence::Absent
        },
        encoding: if configuration.save_encoding() {
            Presence::from_option(result.data_encoding().map(DataEncoding::as_str))
        } else {
            Presence::Absent
        },
        received_bytes: if configuration.save_bytes() {
            Presence::from_option(result.received_bytes().map(ByteCount::as_u64))
        } else {
            Presence::Absent
        },
        sent_bytes: if configuration.save_sent_bytes() {
            Presence::from_option(result.sent_bytes().map(ByteCount::as_u64))
        } else {
            Presence::Absent
        },
        sample_count: if configuration.save_sample_count() {
            Presence::from_option(result.sample_count().map(SampleCount::as_u64))
        } else {
            Presence::Absent
        },
        error_count: if configuration.save_error_count() {
            Presence::from_option(result.error_count().map(ErrorCount::as_u64))
        } else {
            Presence::Absent
        },
        group_threads: if configuration.save_thread_counts() {
            Presence::from_option(result.group_threads().map(ThreadCount::as_u64))
        } else {
            Presence::Absent
        },
        all_threads: if configuration.save_thread_counts() {
            Presence::from_option(result.all_threads().map(ThreadCount::as_u64))
        } else {
            Presence::Absent
        },
        response_headers: if configuration.save_response_headers() {
            optional_string(result.response_headers().map(HeaderBlock::as_str))
        } else {
            Presence::Absent
        },
        request_headers: if configuration.save_request_headers() {
            optional_string(result.request_headers().map(HeaderBlock::as_str))
        } else {
            Presence::Absent
        },
        response_data: if configuration.save_response_data() {
            Presence::from_option(
                result
                    .response_data()
                    .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned()),
            )
        } else {
            Presence::Absent
        },
        response_file: if configuration.save_filename() {
            optional_string(result.response_file())
        } else {
            Presence::Absent
        },
        sampler_data: if configuration.save_sampler_data() {
            optional_string(result.sampler_data())
        } else {
            Presence::Absent
        },
        url: if configuration.save_url() {
            optional_string(result.url())
        } else {
            Presence::Absent
        },
        assertions: xml_assertions(result, configuration),
        children: if configuration.save_subresults() {
            result
                .sub_results()
                .iter()
                .map(|child| xml_actual_result_inventory(child, configuration))
                .collect()
        } else {
            Vec::new()
        },
    }
}

fn xml_source_inventory(
    event: &SampleEvent,
    configuration: &SampleSaveConfiguration,
) -> XmlInventory {
    XmlInventory {
        result: xml_source_result_inventory(event.result(), configuration),
        thread: if configuration.save_thread_name() {
            Presence::Present(event.thread().name().to_owned())
        } else {
            Presence::Present(String::new())
        },
        host: if configuration.save_hostname() {
            Presence::Present(event.host().as_str().to_owned())
        } else {
            Presence::Present(String::new())
        },
        variables: configuration
            .sample_variables()
            .iter()
            .map(|name| match event.variables().get(name) {
                Some(VariableValue::Present(value)) => Presence::Present(value.to_owned()),
                Some(VariableValue::Absent) | None => Presence::Absent,
            })
            .collect(),
    }
}

fn xml_actual_inventory(
    event: &SampleEvent,
    configuration: &SampleSaveConfiguration,
) -> XmlInventory {
    XmlInventory {
        result: xml_actual_result_inventory(event.result(), configuration),
        thread: if configuration.save_thread_name() {
            Presence::Present(event.thread().name().to_owned())
        } else {
            Presence::Present(String::new())
        },
        host: if configuration.save_hostname() {
            Presence::Present(event.host().as_str().to_owned())
        } else {
            Presence::Present(String::new())
        },
        variables: configuration
            .sample_variables()
            .iter()
            .map(|name| match event.variables().get(name) {
                Some(VariableValue::Present(value)) => Presence::Present(value.to_owned()),
                Some(VariableValue::Absent) | None => Presence::Absent,
            })
            .collect(),
    }
}

fn inject_unknown_child(
    bytes: &[u8],
    configuration: &SampleSaveConfiguration,
    marker: &str,
) -> Vec<u8> {
    let closing = match configuration.xml_sample_element() {
        XmlSampleElement::Sample => b"</sample>".as_slice(),
        XmlSampleElement::HttpSample => b"</httpSample>".as_slice(),
    };
    let position = bytes
        .windows(closing.len())
        .rposition(|window| window == closing)
        .expect("generated XML must contain one sample close");
    let fragment =
        format!("<fuzzOpaque marker=\"{marker}\"><nested>{marker}</nested></fuzzOpaque>");
    let mut output = Vec::with_capacity(bytes.len().saturating_add(fragment.len()));
    output.extend_from_slice(&bytes[..position]);
    output.extend_from_slice(fragment.as_bytes());
    output.extend_from_slice(&bytes[position..]);
    output
}

fn count_marker(bytes: &[u8], marker: &str) -> usize {
    let marker = marker.as_bytes();
    if marker.is_empty() {
        return 0;
    }
    bytes
        .windows(marker.len())
        .filter(|window| *window == marker)
        .count()
}

fn csv_round_trip(event: &SampleEvent, configuration: &SampleSaveConfiguration, limits: JtlLimits) {
    let expected = csv_source_inventory(event, configuration);
    let mut encoder = CsvEncoder::new(Vec::new(), configuration.clone())
        .expect("generated CSV configuration must validate")
        .with_limits(limits)
        .expect("generated CSV limits must validate");
    encoder
        .write_event(event)
        .expect("generated CSV model must encode");
    let bytes = encoder.finish().expect("generated CSV output must finish");
    let decoded = CsvDecoder::with_limits(bytes.as_slice(), configuration.clone(), limits)
        .expect("generated CSV output must initialize the decoder")
        .decode_all_with_limit(1)
        .expect("generated CSV output must decode");
    assert_eq!(
        decoded.len(),
        1,
        "one generated event must remain one CSV row"
    );
    let actual = csv_decoded_inventory(&decoded[0], configuration);
    assert_eq!(actual, expected, "CSV source wire inventory changed");
}

fn xml_round_trip(
    event: &SampleEvent,
    configuration: &SampleSaveConfiguration,
    limits: JtlLimits,
    marker: &str,
) {
    let expected = xml_source_inventory(event, configuration);
    let mut encoder = XmlEncoder::new(Vec::new(), configuration.clone())
        .expect("generated XML configuration must validate")
        .with_limits(limits)
        .expect("generated XML limits must validate");
    encoder
        .write_event(event)
        .expect("generated XML model must encode");
    let plain = encoder.finish().expect("generated XML output must finish");
    let bytes = inject_unknown_child(&plain, configuration, marker);
    assert_eq!(
        count_marker(&bytes, marker),
        2,
        "injected XML marker must be bounded"
    );

    let decode_configuration = XmlDecodeConfiguration::new()
        .with_sample_variables(sample_variables())
        .expect("static XML sample-variable names are valid");
    let decoded = XmlDecoder::with_configuration(bytes.as_slice(), limits, decode_configuration)
        .expect("generated XML output must initialize the decoder")
        .decode_all_with_limit(1)
        .expect("generated XML output must decode");
    assert_eq!(
        decoded.len(),
        1,
        "one generated event must remain one XML event"
    );
    let actual = xml_actual_inventory(&decoded[0], configuration);
    assert_eq!(actual, expected, "XML source wire inventory changed");

    let mut reencoder = XmlEncoder::new(Vec::new(), configuration.clone())
        .expect("generated XML configuration must validate after decode")
        .with_limits(limits)
        .expect("generated XML limits must validate after decode");
    reencoder
        .write_event(&decoded[0])
        .expect("decoded XML model must re-encode");
    let retained = reencoder
        .finish()
        .expect("re-encoded XML output must finish");
    assert_eq!(
        count_marker(&retained, marker),
        2,
        "unknown XML marker must survive decode and re-encode"
    );
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    let mut cursor = ByteCursor::new(data);
    let event = generate_event(&mut cursor);
    event
        .result()
        .validate_wire_with_limits(validation_limits())
        .expect("generated SampleResult tree must satisfy wire limits");
    let csv_configuration = configure_csv(&mut cursor);
    let xml_configuration = configure_xml(&mut cursor);
    let marker = cursor.identifier("marker-");
    let codec_limits = limits();
    csv_round_trip(&event, &csv_configuration, codec_limits);
    xml_round_trip(&event, &xml_configuration, codec_limits, &marker);
});
