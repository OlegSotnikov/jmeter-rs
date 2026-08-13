#![no_main]

//! Bounded JTL CSV decoder/encoder target.
//!
//! The target enables every CSV field and two selected variables, then
//! compares the decoded event projection before and after encoding.  The
//! comparison is deliberately at the CSV wire projection: fields that CSV
//! cannot represent (XML payloads, assertions, and result hierarchy) are not
//! claimed as CSV coverage, while every configured column is checked.
//!
//! Invariants: `JTL-CSV-PROJECTION-001` compares every configured wire column
//! after re-encode/decode; `JTL-CSV-UNKNOWN-HEADER-001` derives the bounded
//! variable configuration from detected headers so unknown columns are
//! exercised through a lossless round trip and an independent raw header/value
//! inventory; and `JTL-CSV-LIMIT-001` keeps input, record, column, sample,
//! reader-failure, and output-atomicity limits explicit.
//! Source-side coverage: the independent raw header/record/unknown-value
//! inventory is compared with encoded output before typed projection checks.
//! I/O policy: none; reader failures are synthetic in-memory `Read` errors.

use std::io::{self, ErrorKind, Read};

use jmeter_rs_results::{
    AssertionResults, CsvColumn, CsvDecoder, CsvEncoder, CsvField, DataType, HostIdentity,
    JtlError, JtlLimits, SampleEvent, SampleResult, SampleSaveConfiguration, ThreadIdentity,
    TimestampFormat, VariableSnapshot,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 256 * 1024;

fn limits() -> JtlLimits {
    JtlLimits::new(MAX_INPUT_BYTES, 16 * 1024, 4 * 1024, 64, 16, 512, 128, 64)
        .expect("fuzz target constants must define non-zero limits")
}

fn oversized_probe() -> Vec<u8> {
    // Keep every record below the record bound while making the complete
    // stream exceed the input bound before the sample bound is reached.
    let mut input = Vec::with_capacity(MAX_INPUT_BYTES + 64 * 1024);
    input.extend_from_slice(b"label\n");
    for _ in 0..40 {
        input.extend(std::iter::repeat_n(b'a', 8 * 1024));
        input.push(b'\n');
    }
    input
}

fn configuration() -> SampleSaveConfiguration {
    let mut configuration = SampleSaveConfiguration::csv();
    configuration.set_timestamp_format(TimestampFormat::Milliseconds);
    configuration.set_print_field_names(true);
    configuration.set_timestamp(true);
    configuration.set_time(true);
    configuration.set_label(true);
    configuration.set_response_code(true);
    configuration.set_response_message(true);
    configuration.set_thread_name(true);
    configuration.set_data_type(true);
    configuration.set_success(true);
    configuration.set_assertion_results(AssertionResults::All);
    configuration.set_assertion_results_failure_message(true);
    configuration.set_bytes(true);
    configuration.set_sent_bytes(true);
    configuration.set_thread_counts(true);
    configuration.set_url(true);
    configuration.set_filename(true);
    configuration.set_latency(true);
    configuration.set_encoding(true);
    configuration.set_sample_count(true);
    configuration.set_hostname(true);
    configuration.set_idle_time(true);
    configuration.set_connect_time(true);
    // CSV has no hierarchy wire representation; disabling subresults makes
    // the projection explicit instead of silently flattening child results.
    configuration.set_subresults(false);
    configuration
        .set_sample_variables(["case_id", "region"])
        .expect("static sample-variable names are valid");
    configuration
}

fn first_failure_message(result: &SampleResult) -> Option<&str> {
    result
        .assertions()
        .iter()
        .find_map(|assertion| assertion.failure_message().or(assertion.error_message()))
        .or_else(|| result.failure_message())
}

fn value_for_column(event: &SampleEvent, result: &SampleResult, column: &CsvColumn) -> String {
    match column {
        CsvColumn::Variable(name) => event
            .variables()
            .get(name)
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_owned(),
        CsvColumn::Field(field) => match field {
            CsvField::Timestamp => result
                .timestamp()
                .map(|value| value.as_millis().to_string())
                .unwrap_or_else(|| "0".to_owned()),
            CsvField::Elapsed => result
                .elapsed()
                .map(|value| value.as_millis().to_string())
                .unwrap_or_else(|| "0".to_owned()),
            CsvField::Label => result.label().to_owned(),
            CsvField::ResponseCode => result.response_code().unwrap_or_default().to_owned(),
            CsvField::ResponseMessage => result.response_message().unwrap_or_default().to_owned(),
            CsvField::ThreadName => event.thread().name().to_owned(),
            CsvField::DataType => result
                .data_type()
                .map(DataType::as_wire)
                .unwrap_or("text")
                .to_owned(),
            CsvField::Success => result.success().unwrap_or(true).to_string(),
            CsvField::FailureMessage => {
                first_failure_message(result).unwrap_or_default().to_owned()
            }
            CsvField::Bytes => result
                .received_bytes()
                .map(|value| value.as_u64().to_string())
                .unwrap_or_else(|| "0".to_owned()),
            CsvField::SentBytes => result
                .sent_bytes()
                .map(|value| value.as_u64().to_string())
                .unwrap_or_else(|| "0".to_owned()),
            CsvField::GroupThreads => result
                .group_threads()
                .map(|value| value.as_u64().to_string())
                .unwrap_or_else(|| "0".to_owned()),
            CsvField::AllThreads => result
                .all_threads()
                .map(|value| value.as_u64().to_string())
                .unwrap_or_else(|| "0".to_owned()),
            CsvField::Url => result.url().unwrap_or("null").to_owned(),
            CsvField::Filename => result.response_file().unwrap_or_default().to_owned(),
            CsvField::Latency => result
                .latency()
                .map(|value| value.as_millis().to_string())
                .unwrap_or_else(|| "0".to_owned()),
            CsvField::Encoding => result
                .data_encoding()
                .map(|value| value.as_str())
                .or(Some("UTF-8"))
                .unwrap_or_default()
                .to_owned(),
            CsvField::SampleCount => result
                .sample_count()
                .map(|value| value.as_u64().to_string())
                .unwrap_or_else(|| "1".to_owned()),
            CsvField::ErrorCount => result
                .error_count()
                .map(|value| value.as_u64().to_string())
                .unwrap_or_else(|| "0".to_owned()),
            CsvField::Hostname => event.host().as_str().to_owned(),
            CsvField::IdleTime => result
                .idle_time()
                .map(|value| value.as_millis().to_string())
                .unwrap_or_else(|| "0".to_owned()),
            CsvField::Connect => result
                .connect_time()
                .map(|value| value.as_millis().to_string())
                .unwrap_or_else(|| "0".to_owned()),
        },
    }
}

fn wire_projection(events: &[SampleEvent], columns: &[CsvColumn]) -> Vec<Vec<String>> {
    events
        .iter()
        .map(|event| {
            columns
                .iter()
                .map(|column| value_for_column(event, event.result(), column))
                .collect()
        })
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawCsvToken {
    value: String,
    quoted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawCsvInventory {
    header: Vec<RawCsvToken>,
    rows: Vec<Vec<RawCsvToken>>,
}

/// A small independent CSV scanner used only for the source-side invariant.
/// It deliberately does not call the production decoder: a dropped unknown
/// header/value must remain observable even if both decode and re-encode agree
/// on the same reduced model.
fn raw_csv_inventory(input: &[u8], max_input_bytes: usize) -> Option<RawCsvInventory> {
    if input.len() > max_input_bytes {
        return None;
    }
    let mut offset = if input.starts_with(b"\xef\xbb\xbf") {
        3
    } else {
        0
    };
    let delimiter = raw_csv_delimiter(&input[offset..]);
    let mut records = Vec::new();
    while offset < input.len() {
        let (record, next) = raw_csv_record(input, offset, delimiter, max_input_bytes)?;
        records.push(record);
        offset = next;
    }
    if records.is_empty() {
        return None;
    }
    let header = records.remove(0);
    if header.is_empty() || header.len() > limits().max_columns {
        return None;
    }
    if records.iter().any(|record| record.len() != header.len()) {
        return None;
    }
    Some(RawCsvInventory {
        header,
        rows: records,
    })
}

fn raw_csv_delimiter(input: &[u8]) -> u8 {
    let end = input
        .iter()
        .position(|byte| *byte == b'\n' || *byte == b'\r')
        .unwrap_or(input.len());
    let line = &input[..end];
    if line.contains(&b'\t') && !line.contains(&b',') {
        let has_known_field = line.split(|byte| *byte == b'\t').any(|token| {
            let token = token.strip_prefix(b"\"").unwrap_or(token);
            let token = token.strip_suffix(b"\"").unwrap_or(token);
            std::str::from_utf8(token)
                .ok()
                .and_then(CsvField::parse)
                .is_some()
        });
        if has_known_field {
            return b'\t';
        }
    }
    b','
}

fn raw_csv_record(
    input: &[u8],
    mut offset: usize,
    delimiter: u8,
    max_input_bytes: usize,
) -> Option<(Vec<RawCsvToken>, usize)> {
    let mut record = Vec::new();
    let mut field = Vec::new();
    let mut quoted = false;
    let mut was_quoted = false;
    let mut closed_quote = false;
    let mut at_field_start = true;
    let mut record_bytes = 0usize;
    loop {
        let byte = input.get(offset).copied();
        let Some(byte) = byte else {
            if quoted {
                return None;
            }
            if field.is_empty() && record.is_empty() && !was_quoted && !closed_quote {
                return None;
            }
            raw_csv_push_field(&mut record, &mut field, was_quoted)?;
            return Some((record, offset));
        };
        offset = offset.checked_add(1)?;
        record_bytes = record_bytes.checked_add(1)?;
        if record_bytes > limits().max_record_bytes || offset > max_input_bytes {
            return None;
        }
        if quoted {
            match byte {
                b'"' if input.get(offset) == Some(&b'"') => {
                    offset = offset.checked_add(1)?;
                    record_bytes = record_bytes.checked_add(1)?;
                    if record_bytes > limits().max_record_bytes || offset > max_input_bytes {
                        return None;
                    }
                    field.push(b'"');
                }
                b'"' => {
                    quoted = false;
                    closed_quote = true;
                }
                _ => field.push(byte),
            }
            continue;
        }
        if closed_quote && byte != delimiter && byte != b'\n' && byte != b'\r' {
            return None;
        }
        match byte {
            b'"' if at_field_start => {
                quoted = true;
                was_quoted = true;
                at_field_start = false;
            }
            byte if byte == delimiter => {
                raw_csv_push_field(&mut record, &mut field, was_quoted)?;
                was_quoted = false;
                closed_quote = false;
                at_field_start = true;
            }
            b'\n' | b'\r' => {
                if byte == b'\r' && input.get(offset) == Some(&b'\n') {
                    offset = offset.checked_add(1)?;
                    record_bytes = record_bytes.checked_add(1)?;
                    if record_bytes > limits().max_record_bytes || offset > max_input_bytes {
                        return None;
                    }
                }
                raw_csv_push_field(&mut record, &mut field, was_quoted)?;
                return Some((record, offset));
            }
            _ => {
                field.push(byte);
                at_field_start = false;
            }
        }
    }
}

fn raw_csv_push_field(
    record: &mut Vec<RawCsvToken>,
    field: &mut Vec<u8>,
    quoted: bool,
) -> Option<()> {
    if record.len() >= limits().max_columns {
        return None;
    }
    let value = String::from_utf8(std::mem::take(field)).ok()?;
    record.push(RawCsvToken { value, quoted });
    Some(())
}

fn csv_unknown_header_indices(header: &[RawCsvToken]) -> Vec<usize> {
    header
        .iter()
        .enumerate()
        .filter_map(|(index, token)| {
            (token.quoted || CsvField::parse(&token.value).is_none()).then_some(index)
        })
        .collect()
}

fn assert_raw_csv_inventory(
    source: &RawCsvInventory,
    encoded: &RawCsvInventory,
    decoded_events: usize,
) {
    if source.rows.len() != decoded_events || encoded.rows.len() != decoded_events {
        panic!(
            "CSV source/output record count changed: source {}, decoded {}, encoded {}",
            source.rows.len(),
            decoded_events,
            encoded.rows.len()
        );
    }
    for (record_number, record) in source.rows.iter().enumerate() {
        if record.len() != source.header.len() {
            panic!(
                "CSV source record {} changed arity: expected {}, found {}",
                record_number + 2,
                source.header.len(),
                record.len()
            );
        }
    }
    for (record_number, record) in encoded.rows.iter().enumerate() {
        if record.len() != encoded.header.len() {
            panic!(
                "CSV encoded record {} changed arity: expected {}, found {}",
                record_number + 2,
                encoded.header.len(),
                record.len()
            );
        }
    }

    // The encoder may emit configured built-in fields absent from the source
    // header.  Those are checked by the typed projection; this independent
    // inventory specifically requires every source unknown header/value to
    // remain present and ordered in the canonical output header.
    let source_unknown = csv_unknown_header_indices(&source.header);
    let encoded_unknown = csv_unknown_header_indices(&encoded.header);
    let mut encoded_positions = Vec::with_capacity(source_unknown.len());
    let mut search_from = 0usize;
    for source_index in source_unknown {
        let source_name = &source.header[source_index].value;
        let Some(relative) = encoded_unknown[search_from..]
            .iter()
            .position(|index| encoded.header[*index].value == *source_name)
        else {
            panic!("CSV unknown header was dropped or reordered");
        };
        let encoded_index = encoded_unknown[search_from + relative];
        encoded_positions.push(encoded_index);
        search_from = search_from + relative + 1;
    }
    for (row_index, (source_row, encoded_row)) in source.rows.iter().zip(&encoded.rows).enumerate()
    {
        for (source_index, encoded_index) in csv_unknown_header_indices(&source.header)
            .into_iter()
            .zip(&encoded_positions)
        {
            if source_row[source_index].value != encoded_row[*encoded_index].value {
                panic!("CSV unknown value changed at row {}", row_index + 2);
            }
        }
    }
}

struct FaultReader<'a> {
    input: &'a [u8],
    offset: usize,
    fail_at: usize,
    kind: ErrorKind,
    failed: bool,
}

impl<'a> FaultReader<'a> {
    fn new(input: &'a [u8], fail_at: usize, kind: ErrorKind) -> Self {
        Self {
            input,
            offset: 0,
            fail_at,
            kind,
            failed: false,
        }
    }
}

impl Read for FaultReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if !self.failed && self.offset >= self.fail_at {
            self.failed = true;
            return Err(io::Error::new(self.kind, "bounded fuzz reader fault"));
        }
        if self.offset >= self.input.len() {
            return Ok(0);
        }
        let remaining_before_fault = self.fail_at.saturating_sub(self.offset);
        let amount = buffer
            .len()
            .min(self.input.len() - self.offset)
            .min(remaining_before_fault.max(1));
        buffer[..amount].copy_from_slice(&self.input[self.offset..self.offset + amount]);
        self.offset += amount;
        Ok(amount)
    }
}

fn assert_csv_reader_fault(input: &[u8]) {
    if input.is_empty() {
        return;
    }
    let fail_at = input.len() / 2;
    for kind in [ErrorKind::Interrupted, ErrorKind::Other] {
        let result = CsvDecoder::with_limits(
            FaultReader::new(input, fail_at, kind),
            configuration(),
            limits(),
        )
        .and_then(CsvDecoder::decode_all);
        if !matches!(result, Err(JtlError::Io { .. })) {
            panic!("CSV reader fault was not surfaced as a bounded I/O error");
        }
    }
}

fn fixed_output_limit_probe() {
    let event = SampleEvent::new(
        SampleResult::new("csv-output-limit"),
        "run",
        ThreadIdentity::new("thread"),
        HostIdentity::new("host"),
        VariableSnapshot::new(),
    );
    let probe_configuration = configuration();
    let mut baseline = CsvEncoder::new(Vec::new(), probe_configuration.clone())
        .expect("CSV output-limit probe configuration")
        .with_limits(limits())
        .expect("CSV output-limit probe limits");
    baseline
        .write_event(&event)
        .expect("CSV output-limit baseline event");
    let baseline_bytes = baseline.into_inner();
    let mut bounded = limits();
    bounded.max_output_bytes = baseline_bytes.len().saturating_add(1);
    let mut encoder = CsvEncoder::new(Vec::new(), probe_configuration)
        .expect("CSV output-limit bounded configuration")
        .with_limits(bounded)
        .expect("CSV output-limit bounded limits");
    encoder
        .write_event(&event)
        .expect("CSV output-limit first event");
    if !matches!(
        encoder.write_event(&event),
        Err(JtlError::Unsupported {
            feature: "output-limit",
            ..
        })
    ) {
        panic!("CSV output limit did not reject the second event");
    }
    if encoder.into_inner() != baseline_bytes {
        panic!("CSV output-limit rejection published partial bytes");
    }
}

fuzz_target!(|data: &[u8]| {
    fixed_output_limit_probe();
    if data.len() > MAX_INPUT_BYTES {
        let oversized = oversized_probe();
        let result = CsvDecoder::with_limits(oversized.as_slice(), configuration(), limits())
            .and_then(CsvDecoder::decode_all);
        match result {
            Err(JtlError::Unsupported {
                feature: "input-size-limit",
                ..
            }) => {}
            Err(error) => panic!("oversized JTL CSV returned the wrong error: {error}"),
            Ok(_) => panic!("oversized JTL CSV was accepted instead of rejected"),
        }
        return;
    }

    let configuration = configuration();
    let Ok(decoder) = CsvDecoder::with_limits(data, configuration.clone(), limits()) else {
        return;
    };
    let columns = decoder.columns().to_vec();
    let Ok(events) = decoder.decode_all() else {
        return;
    };
    let Some(source_inventory) = raw_csv_inventory(data, MAX_INPUT_BYTES) else {
        panic!("accepted CSV input could not be independently inventoried");
    };
    assert_csv_reader_fault(data);
    // Header variables are part of the wire schema even when they were not
    // present in the static property configuration.  Add every detected
    // variable to the encoder configuration before it emits a canonical
    // header; otherwise an accepted unknown column would be silently lost.
    let mut roundtrip_configuration = configuration.clone();
    let mut variables = roundtrip_configuration.sample_variables().to_vec();
    for column in &columns {
        if let CsvColumn::Variable(name) = column
            && !variables.iter().any(|existing| existing == name)
        {
            variables.push(name.clone());
        }
    }
    if roundtrip_configuration
        .set_sample_variables(variables)
        .is_err()
    {
        return;
    }
    let roundtrip_columns = roundtrip_configuration.columns();
    let expected = wire_projection(&events, &roundtrip_columns);

    let Ok(mut encoder) = CsvEncoder::new(Vec::new(), roundtrip_configuration.clone())
        .and_then(|encoder| encoder.with_limits(limits()))
    else {
        return;
    };
    for event in &events {
        if encoder.write_event(event).is_err() {
            return;
        }
    }
    let Ok(encoded) = encoder.finish() else {
        return;
    };
    if encoded.len() > MAX_INPUT_BYTES.saturating_mul(2) {
        return;
    }
    let Some(encoded_inventory) = raw_csv_inventory(&encoded, MAX_INPUT_BYTES.saturating_mul(2))
    else {
        panic!("encoded CSV output could not be independently inventoried");
    };
    assert_raw_csv_inventory(&source_inventory, &encoded_inventory, events.len());

    let Ok(reparsed_decoder) = CsvDecoder::with_limits(
        encoded.as_slice(),
        roundtrip_configuration.clone(),
        limits(),
    ) else {
        panic!("encoded JTL CSV was not parseable");
    };
    let reparsed_columns = reparsed_decoder.columns().to_vec();
    let Ok(reparsed) = reparsed_decoder.decode_all() else {
        panic!("encoded JTL CSV could not be decoded");
    };
    if reparsed_columns != roundtrip_columns {
        panic!("CSV header dropped or reordered an unknown column");
    }
    if wire_projection(&reparsed, &roundtrip_columns) != expected {
        panic!("CSV wire projection dropped or changed a configured field");
    }
});
