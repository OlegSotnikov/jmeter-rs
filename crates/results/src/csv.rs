// SPDX-License-Identifier: Apache-2.0
//! Bounded JTL CSV codec.

use std::borrow::Borrow;
use std::collections::VecDeque;
use std::io::{Read, Write};

use crate::jtl::{
    CsvColumn, CsvField, DateFormatProvider, JtlCounter, JtlError, JtlLimits, JtlOutputPolicy,
    MAX_DECODE_ALL_EVENTS, SampleSaveConfiguration, TimestampFormat, checked_counter_add,
    first_failure_message, parse_optional_u64, timing_from_wire,
};
use crate::{
    DataEncoding, DataType, HostIdentity, SampleEvent, SampleResult, ThreadIdentity,
    TimestampSource, VariableSnapshot, WallTimestamp,
};

/// One decoded CSV field, retaining whether the source token was quoted.
#[derive(Clone, Debug, Eq, PartialEq)]
struct CsvToken {
    value: String,
    quoted: bool,
}

/// A bounded CSV writer for JMeter result events.
pub struct CsvEncoder<'a, W> {
    writer: W,
    configuration: SampleSaveConfiguration,
    limits: JtlLimits,
    date_provider: Option<&'a dyn DateFormatProvider>,
    wrote_header: bool,
    finished: bool,
    written_samples: usize,
    output_bytes: usize,
    output_policy: JtlOutputPolicy,
    /// True only for the private per-event scratch encoder.  A scratch
    /// encoder applies the streaming policy to its event-local byte count;
    /// the caller-owned encoder never applies that bound to its persistent
    /// stream.
    staging: bool,
}

/// Compatibility name for [`CsvEncoder`].
pub type CsvWriter<'a, W> = CsvEncoder<'a, W>;

impl<'a, W: Write> CsvEncoder<'a, W> {
    /// Creates a CSV encoder and validates its configuration.
    pub fn new(writer: W, configuration: SampleSaveConfiguration) -> Result<Self, JtlError> {
        configuration.validate()?;
        Ok(Self {
            writer,
            configuration,
            limits: JtlLimits::default(),
            date_provider: None,
            wrote_header: false,
            finished: false,
            written_samples: 0,
            output_bytes: 0,
            output_policy: JtlOutputPolicy::default(),
            staging: false,
        })
    }

    /// Replaces parser/output bounds.
    pub fn with_limits(mut self, limits: JtlLimits) -> Result<Self, JtlError> {
        limits.validate()?;
        self.limits = limits;
        Ok(self)
    }

    /// Creates a CSV encoder in streaming mode with the default finite
    /// per-event staging bound.
    pub fn streaming(writer: W, configuration: SampleSaveConfiguration) -> Result<Self, JtlError> {
        Self::new(writer, configuration)?.with_output_policy(JtlOutputPolicy::streaming_default())
    }

    /// Selects the output policy for this encoder.
    pub fn with_output_policy(mut self, policy: JtlOutputPolicy) -> Result<Self, JtlError> {
        policy.validate()?;
        self.output_policy = policy;
        Ok(self)
    }

    /// Returns the policy currently applied to output bytes.
    pub const fn output_policy(&self) -> JtlOutputPolicy {
        self.output_policy
    }

    /// Returns the checked number of bytes published so far.
    pub const fn bytes_written(&self) -> usize {
        self.output_bytes
    }

    /// Returns the checked number of result rows published so far.
    pub const fn samples_written(&self) -> usize {
        self.written_samples
    }

    /// Installs a Java-date-format adapter for `TimestampFormat::JavaDateFormat`.
    pub fn with_date_provider(mut self, provider: &'a dyn DateFormatProvider) -> Self {
        self.date_provider = Some(provider);
        self
    }

    /// Returns the configuration used by this writer.
    pub fn configuration(&self) -> &SampleSaveConfiguration {
        &self.configuration
    }

    /// Writes the header once, if configured.
    pub fn write_header(&mut self) -> Result<(), JtlError> {
        if self.wrote_header {
            return Ok(());
        }
        if self.configuration.print_field_names() {
            let column_count = self.configuration.column_count()?;
            if column_count > self.limits.max_columns {
                return Err(JtlError::Unsupported {
                    feature: "csv-column-limit",
                    value: format!(
                        "{column_count} configured columns exceeds {}",
                        self.limits.max_columns
                    ),
                });
            }
            let columns = self.configuration.columns();
            let mut values = Vec::with_capacity(columns.len());
            for column in columns {
                let token = match column {
                    CsvColumn::Field(field) => field.name().to_owned(),
                    CsvColumn::Variable(ref name) => name.clone(),
                };
                let mut serialized = String::new();
                // JMeter quotes every configured sample-variable name. This
                // also keeps a variable named `label` unambiguous.
                if matches!(column, CsvColumn::Variable(_)) {
                    serialized.push('"');
                    serialized.push_str(&token.replace('"', "\"\""));
                    serialized.push('"');
                } else {
                    append_csv_token(&mut serialized, &token, self.configuration.delimiter());
                }
                values.push(serialized);
            }
            self.write_record_raw(&values.join(&self.configuration.delimiter().to_string()))?;
        }
        self.wrote_header = true;
        Ok(())
    }

    /// Writes one immutable sample event.
    pub fn write_event(&mut self, event: &SampleEvent) -> Result<(), JtlError> {
        event.validate_wire(self.configuration_limits())?;
        let rows = result_node_count(event.result(), self.configuration.save_subresults())?;
        let total = checked_counter_add(self.written_samples, rows, JtlCounter::Samples)?;
        if total > self.limits.max_samples {
            return Err(JtlError::Unsupported {
                feature: "csv-sample-limit",
                value: format!("{total} samples exceeds {}", self.limits.max_samples),
            });
        }

        // Render into a bounded scratch buffer first. A result hierarchy is a
        // single listener event: a later child validation/resource failure
        // must not leave the root row (or an XML-like header) in the sink.
        let mut staged = CsvEncoder::new(Vec::new(), self.configuration.clone())?;
        staged.limits = self.limits;
        staged.date_provider = self.date_provider;
        staged.output_policy = self.output_policy;
        staged.staging = true;
        staged.wrote_header = self.wrote_header;
        staged.written_samples = self.written_samples;
        staged.output_bytes = match self.output_policy {
            JtlOutputPolicy::BoundedAggregate => self.output_bytes,
            JtlOutputPolicy::Streaming { .. } => 0,
        };
        staged.write_event_parts(event)?;
        let bytes = staged.writer;
        self.write_bytes(&bytes, "write CSV event")?;
        self.wrote_header = staged.wrote_header;
        self.written_samples = staged.written_samples;
        if self.configuration.autoflush() {
            self.writer.flush().map_err(|error| JtlError::Io {
                operation: "flush CSV output",
                message: error.to_string(),
            })?;
        }
        Ok(())
    }

    fn write_event_parts(&mut self, event: &SampleEvent) -> Result<(), JtlError> {
        event.validate_wire(self.configuration_limits())?;
        let rows = result_node_count(event.result(), self.configuration.save_subresults())?;
        let total = checked_counter_add(self.written_samples, rows, JtlCounter::Samples)?;
        if total > self.limits.max_samples {
            return Err(JtlError::Unsupported {
                feature: "csv-sample-limit",
                value: format!("{total} samples exceeds {}", self.limits.max_samples),
            });
        }
        self.write_header()?;
        self.write_result_row(event, event.result(), None, true)?;
        self.written_samples = checked_counter_add(self.written_samples, 1, JtlCounter::Samples)?;
        if self.configuration.save_subresults() {
            self.write_subresult_rows(event, event.result())?;
        }
        Ok(())
    }

    /// Writes one result with empty run/host/variable metadata.
    pub fn write_result(&mut self, result: &SampleResult) -> Result<(), JtlError> {
        let variables = VariableSnapshot::new();
        let event = SampleEvent::new(result.clone(), "", ThreadIdentity::new(""), "", variables);
        self.write_event(&event)
    }

    /// Flushes the writer and returns the underlying writer.
    pub fn finish(mut self) -> Result<W, JtlError> {
        if !self.finished {
            self.write_header()?;
            self.writer.flush().map_err(|error| JtlError::Io {
                operation: "flush CSV output",
                message: error.to_string(),
            })?;
            self.finished = true;
        }
        Ok(self.writer)
    }

    /// Returns the underlying writer without flushing.
    pub fn into_inner(self) -> W {
        self.writer
    }

    #[cfg(test)]
    pub(crate) fn set_output_bytes_for_test(&mut self, value: usize) {
        self.output_bytes = value;
    }

    fn configuration_limits(&self) -> crate::ValidationLimits {
        crate::ValidationLimits::new(self.limits.max_depth, self.limits.max_nodes)
            .unwrap_or_default()
    }

    fn write_result_row(
        &mut self,
        event: &SampleEvent,
        result: &SampleResult,
        label_override: Option<&str>,
        allow_event_variables: bool,
    ) -> Result<(), JtlError> {
        let record =
            self.record_for_result(event, result, label_override, allow_event_variables)?;
        self.write_record(&record)
    }

    fn write_subresult_rows(
        &mut self,
        event: &SampleEvent,
        root: &SampleResult,
    ) -> Result<(), JtlError> {
        let mut pending = Vec::new();
        for (index, child) in root.sub_results().iter().enumerate().rev() {
            pending.push((child, root.label().to_owned(), index));
        }
        while let Some((result, parent_label, index)) = pending.pop() {
            let label = if self.configuration.subresults_disable_renaming() {
                None
            } else {
                Some(format!("{parent_label}-{index}"))
            };
            // CSVSaveService passes the same SampleEvent to every flattened
            // sub-result row, so configured event variables are available on
            // root and nested rows alike.  A sub-result's wire snapshot still
            // takes precedence when present.
            self.write_result_row(event, result, label.as_deref(), true)?;
            self.written_samples =
                checked_counter_add(self.written_samples, 1, JtlCounter::Samples)?;
            let current_label = label
                .as_deref()
                .unwrap_or_else(|| result.label())
                .to_owned();
            for (child_index, child) in result.sub_results().iter().enumerate().rev() {
                pending.push((child, current_label.clone(), child_index));
            }
        }
        Ok(())
    }

    fn record_for_result(
        &self,
        event: &SampleEvent,
        result: &SampleResult,
        label_override: Option<&str>,
        allow_event_variables: bool,
    ) -> Result<Vec<String>, JtlError> {
        let column_count = self.configuration.column_count()?;
        if column_count > self.limits.max_columns {
            return Err(JtlError::Unsupported {
                feature: "csv-column-limit",
                value: format!(
                    "{column_count} configured columns exceeds {}",
                    self.limits.max_columns
                ),
            });
        }
        let columns = self.configuration.columns();
        columns
            .iter()
            .map(|column| {
                self.value_for_column(event, result, column, label_override, allow_event_variables)
            })
            .collect()
    }

    fn value_for_column(
        &self,
        event: &SampleEvent,
        result: &SampleResult,
        column: &CsvColumn,
        label_override: Option<&str>,
        allow_event_variables: bool,
    ) -> Result<String, JtlError> {
        let value = match column {
            CsvColumn::Variable(name) => {
                let value = result
                    .wire_variables()
                    .get(name)
                    .or_else(|| {
                        allow_event_variables
                            .then(|| event.variables().get(name))
                            .flatten()
                    })
                    .and_then(|value| value.as_str())
                    .unwrap_or_default();
                value.to_owned()
            }
            CsvColumn::Field(field) => match field {
                CsvField::Timestamp => {
                    let source = if self.configuration.timestamp_start() {
                        TimestampSource::Start
                    } else {
                        TimestampSource::End
                    };
                    self.format_timestamp(result.timing().timestamp_for(source))?
                }
                CsvField::Elapsed => result
                    .elapsed()
                    .map(|value| value.as_millis().to_string())
                    .unwrap_or_else(|| "0".to_owned()),
                CsvField::Label => label_override.unwrap_or_else(|| result.label()).to_owned(),
                CsvField::ResponseCode => result.response_code().unwrap_or_default().to_owned(),
                CsvField::ResponseMessage => {
                    result.response_message().unwrap_or_default().to_owned()
                }
                CsvField::ThreadName => result
                    .wire_thread_name()
                    .unwrap_or_else(|| event.thread().name())
                    .to_owned(),
                CsvField::DataType => result
                    .data_type()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| DataType::Text.to_string()),
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
                // JMeter's String.valueOf(URL) writes "null" for no URL.
                CsvField::Url => result.url().unwrap_or("null").to_owned(),
                CsvField::Filename => result.response_file().unwrap_or_default().to_owned(),
                CsvField::Latency => result
                    .latency()
                    .map(|value| value.as_millis().to_string())
                    .unwrap_or_else(|| "0".to_owned()),
                CsvField::Encoding => result
                    .data_encoding()
                    .map(|value| value.as_str())
                    .or_else(|| self.configuration.default_encoding())
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
                CsvField::Hostname => result
                    .wire_host()
                    .unwrap_or_else(|| event.host().as_str())
                    .to_owned(),
                CsvField::IdleTime => result
                    .idle_time()
                    .map(|value| value.as_millis().to_string())
                    .unwrap_or_else(|| "0".to_owned()),
                CsvField::Connect => result
                    .connect_time()
                    .map(|value| value.as_millis().to_string())
                    .unwrap_or_else(|| "0".to_owned()),
            },
        };
        Ok(value)
    }

    fn format_timestamp(&self, timestamp: Option<WallTimestamp>) -> Result<String, JtlError> {
        let value = timestamp.map(WallTimestamp::as_millis).unwrap_or(0);
        match self.configuration.timestamp_format() {
            TimestampFormat::None | TimestampFormat::Milliseconds => Ok(value.to_string()),
            TimestampFormat::JavaDateFormat(pattern) => self
                .date_provider
                .ok_or_else(|| JtlError::Unsupported {
                    feature: "java-date-format",
                    value: pattern.clone(),
                })?
                .format(value, pattern),
        }
    }

    fn write_record(&mut self, values: &[String]) -> Result<(), JtlError> {
        let mut line = String::new();
        for (index, value) in values.iter().enumerate() {
            if index > 0 {
                line.push(self.configuration.delimiter());
            }
            append_csv_token(&mut line, value, self.configuration.delimiter());
        }
        self.write_record_raw(&line)
    }

    fn write_record_raw(&mut self, value: &str) -> Result<(), JtlError> {
        let line_ending = self.configuration.line_ending().as_str();
        let output_length =
            value
                .len()
                .checked_add(line_ending.len())
                .ok_or_else(|| JtlError::Unsupported {
                    feature: "csv-record-limit",
                    value: "record length overflow".to_owned(),
                })?;
        if output_length > self.limits.max_record_bytes {
            return Err(JtlError::Unsupported {
                feature: "csv-record-limit",
                value: format!(
                    "{} bytes exceeds {}",
                    output_length, self.limits.max_record_bytes
                ),
            });
        }
        let mut record = Vec::with_capacity(output_length);
        record.extend_from_slice(value.as_bytes());
        record.extend_from_slice(line_ending.as_bytes());
        self.write_bytes(&record, "write CSV record")
    }

    fn write_bytes(&mut self, bytes: &[u8], operation: &'static str) -> Result<(), JtlError> {
        let total = checked_counter_add(self.output_bytes, bytes.len(), JtlCounter::OutputBytes)?;
        if self.staging {
            match self.output_policy {
                JtlOutputPolicy::BoundedAggregate if total > self.limits.max_output_bytes => {
                    return Err(JtlError::Unsupported {
                        feature: "output-limit",
                        value: format!(
                            "{total} output bytes exceeds {}",
                            self.limits.max_output_bytes
                        ),
                    });
                }
                JtlOutputPolicy::Streaming { max_event_bytes } if total > max_event_bytes => {
                    return Err(JtlError::Unsupported {
                        feature: "csv-event-staging-limit",
                        value: format!("{total} event bytes exceeds {max_event_bytes}"),
                    });
                }
                _ => {}
            }
        } else if matches!(self.output_policy, JtlOutputPolicy::BoundedAggregate)
            && total > self.limits.max_output_bytes
        {
            return Err(JtlError::Unsupported {
                feature: "output-limit",
                value: format!(
                    "{total} output bytes exceeds {}",
                    self.limits.max_output_bytes
                ),
            });
        }
        crate::jtl::write_all(&mut self.writer, bytes, operation)?;
        self.output_bytes = total;
        Ok(())
    }
}

/// A bounded streaming CSV decoder.
///
/// The decoder reads directly from `R` and retains only the current bounded
/// record and one-byte look-ahead state. It does not materialize the complete
/// input stream before yielding the first event.
pub struct CsvDecoder<R = std::io::Empty> {
    reader: R,
    lookahead: Option<u8>,
    prefix: VecDeque<u8>,
    bom_checked: bool,
    input_bytes: usize,
    eof: bool,
    configuration: SampleSaveConfiguration,
    columns: Vec<CsvColumn>,
    limits: JtlLimits,
    date_provider: Option<Box<dyn DateFormatProvider>>,
    record_number: usize,
    yielded: usize,
    pending_record: Option<Vec<CsvToken>>,
}

/// Compatibility name for [`CsvDecoder`].
pub type CsvReader<R = std::io::Empty> = CsvDecoder<R>;

impl<R: Read> CsvDecoder<R> {
    /// Creates a streaming decoder and initializes its column layout.
    pub fn new(reader: R, configuration: SampleSaveConfiguration) -> Result<Self, JtlError> {
        Self::with_limits(reader, configuration, JtlLimits::default())
    }

    /// Creates a streaming decoder with explicit resource limits.
    pub fn with_limits(
        reader: R,
        configuration: SampleSaveConfiguration,
        limits: JtlLimits,
    ) -> Result<Self, JtlError> {
        configuration.validate()?;
        limits.validate()?;
        let column_count = configuration.column_count()?;
        if column_count > limits.max_columns {
            return Err(JtlError::Unsupported {
                feature: "csv-column-limit",
                value: format!(
                    "{column_count} configured columns exceeds {}",
                    limits.max_columns
                ),
            });
        }
        let mut decoder = Self {
            reader,
            lookahead: None,
            prefix: VecDeque::new(),
            bom_checked: false,
            input_bytes: 0,
            eof: false,
            columns: configuration.columns(),
            configuration,
            limits,
            date_provider: None,
            record_number: 0,
            yielded: 0,
            pending_record: None,
        };
        decoder.prime_delimiter()?;
        if decoder.configuration.print_field_names() {
            let header = decoder.next_record()?.ok_or(JtlError::Csv {
                record: 1,
                detail: "CSV header is missing".to_owned(),
            })?;
            match parse_header(&header, decoder.limits.max_columns) {
                Ok(columns) => decoder.columns = columns,
                Err(error) if is_fatal_header_error(&error) => return Err(error),
                Err(_) => {
                    // CSVSaveService treats an unrecognised header as data:
                    // it resets to the configured save layout and replays the
                    // first record. This also avoids guessing a field mapping
                    // for out-of-order or duplicate labels.
                    decoder.pending_record = Some(header);
                }
            }
        } else if let Some(first) = decoder.next_record()? {
            // JMeter's reader accepts a field-name row even when the writer
            // switch is disabled.  Detect only canonical headers; ordinary
            // data rows remain pending and are decoded with configured
            // columns.
            let parsed = parse_header(&first, decoder.limits.max_columns).ok();
            match parsed {
                Some(columns) if looks_like_header(&first, &columns, &decoder.columns) => {
                    decoder.columns = columns;
                }
                _ => decoder.pending_record = Some(first),
            }
        }
        if decoder.columns.len() > decoder.limits.max_columns {
            return Err(JtlError::Unsupported {
                feature: "csv-column-limit",
                value: format!(
                    "{} columns exceeds {}",
                    decoder.columns.len(),
                    decoder.limits.max_columns
                ),
            });
        }
        Ok(decoder)
    }

    /// Installs a Java-date-format adapter for configured timestamp patterns.
    pub fn with_date_provider(mut self, provider: Box<dyn DateFormatProvider>) -> Self {
        self.date_provider = Some(provider);
        self
    }

    /// Returns the columns detected from the header or configuration.
    pub fn columns(&self) -> &[CsvColumn] {
        &self.columns
    }

    /// Decodes the next sample event, or `None` at EOF.
    pub fn next_event(&mut self) -> Result<Option<SampleEvent>, JtlError> {
        let record = if let Some(record) = self.pending_record.take() {
            Some(record)
        } else {
            self.next_record()?
        };
        let Some(record) = record else {
            return Ok(None);
        };
        if self.yielded >= self.limits.max_samples {
            return Err(JtlError::Unsupported {
                feature: "csv-sample-limit",
                value: format!(
                    "{} samples exceeds {}",
                    self.yielded + 1,
                    self.limits.max_samples
                ),
            });
        }
        self.yielded += 1;
        let event = self.decode_record(&record)?;
        Ok(Some(event))
    }

    /// Decodes all remaining events, retaining bounded result values in the
    /// caller's collection.
    ///
    /// This convenience method has a hard event-count cap.  Use
    /// [`Self::next_event`] for a caller-owned streaming sink.
    pub fn decode_all(self) -> Result<Vec<SampleEvent>, JtlError> {
        self.decode_all_with_limit(MAX_DECODE_ALL_EVENTS)
    }

    /// Decodes at most `maximum_events` remaining events into a collection.
    ///
    /// The caller may choose a lower bound, but cannot raise the crate-wide
    /// hard cap.  The parser's input, record, and hierarchy limits continue
    /// to apply independently.
    pub fn decode_all_with_limit(
        mut self,
        maximum_events: usize,
    ) -> Result<Vec<SampleEvent>, JtlError> {
        if maximum_events == 0 || maximum_events > MAX_DECODE_ALL_EVENTS {
            return Err(JtlError::InvalidConfiguration {
                field: "decode_all_event_limit",
                detail: format!(
                    "event limit must be between 1 and {MAX_DECODE_ALL_EVENTS}, got {maximum_events}"
                ),
            });
        }
        let capacity = maximum_events.min(self.limits.max_samples);
        let mut events = Vec::with_capacity(capacity);
        while let Some(event) = self.next_event()? {
            if events.len() >= maximum_events {
                return Err(JtlError::Unsupported {
                    feature: "decode-all-event-limit",
                    value: format!(
                        "collection limit {maximum_events} reached before the next event"
                    ),
                });
            }
            events.push(event);
        }
        Ok(events)
    }

    fn prime_delimiter(&mut self) -> Result<(), JtlError> {
        self.ensure_bom()?;
        if self.configuration.delimiter() != ',' {
            return Ok(());
        }
        let mut first_record = VecDeque::new();
        while let Some(byte) = self.take_byte()? {
            first_record.push_back(byte);
            if first_record.len() > self.limits.max_record_bytes {
                return Err(JtlError::Unsupported {
                    feature: "csv-record-limit",
                    value: format!("record exceeds {} bytes", self.limits.max_record_bytes),
                });
            }
            if byte == b'\n' || byte == b'\r' {
                break;
            }
        }
        let suggested_delimiter =
            header_suggests_delimiter(first_record.make_contiguous(), self.limits.max_columns);
        self.prefix = first_record;
        if let Some(delimiter) = suggested_delimiter {
            self.configuration.set_delimiter(delimiter)?;
        }
        Ok(())
    }

    fn ensure_bom(&mut self) -> Result<(), JtlError> {
        if self.bom_checked {
            return Ok(());
        }
        let mut bytes = Vec::with_capacity(3);
        while bytes.len() < 3 {
            let Some(byte) = self.read_byte_raw()? else {
                break;
            };
            bytes.push(byte);
        }
        if bytes != [0xef, 0xbb, 0xbf] {
            self.prefix.extend(bytes);
        }
        self.bom_checked = true;
        Ok(())
    }

    fn read_byte_raw(&mut self) -> Result<Option<u8>, JtlError> {
        if self.eof {
            return Ok(None);
        }
        let mut byte = [0_u8; 1];
        let read = self.reader.read(&mut byte).map_err(|error| JtlError::Io {
            operation: "read CSV input",
            message: error.to_string(),
        })?;
        if read == 0 {
            self.eof = true;
            return Ok(None);
        }
        self.input_bytes =
            self.input_bytes
                .checked_add(read)
                .ok_or_else(|| JtlError::Unsupported {
                    feature: "input-size",
                    value: "input length overflow".to_owned(),
                })?;
        if self.input_bytes > self.limits.max_input_bytes {
            return Err(JtlError::Unsupported {
                feature: "input-size-limit",
                value: format!(
                    "{} bytes exceeds {}",
                    self.input_bytes, self.limits.max_input_bytes
                ),
            });
        }
        Ok(Some(byte[0]))
    }

    fn peek_byte(&mut self) -> Result<Option<u8>, JtlError> {
        self.ensure_bom()?;
        if self.lookahead.is_none() {
            self.lookahead = if let Some(byte) = self.prefix.pop_front() {
                Some(byte)
            } else {
                self.read_byte_raw()?
            };
        }
        Ok(self.lookahead)
    }

    fn take_byte(&mut self) -> Result<Option<u8>, JtlError> {
        self.ensure_bom()?;
        if let Some(byte) = self.lookahead.take() {
            return Ok(Some(byte));
        }
        if let Some(byte) = self.prefix.pop_front() {
            return Ok(Some(byte));
        }
        self.read_byte_raw()
    }

    fn next_record(&mut self) -> Result<Option<Vec<CsvToken>>, JtlError> {
        let mut record = Vec::new();
        let mut field = Vec::new();
        let mut record_bytes = 0usize;
        let mut quoted = false;
        let mut was_quoted = false;
        let mut closed_quote = false;
        let mut at_field_start = true;
        let mut saw_any = false;

        loop {
            let Some(byte) = self.take_byte()? else {
                if quoted {
                    return Err(JtlError::Csv {
                        record: self.record_number + 1,
                        detail: "unterminated quoted field".to_owned(),
                    });
                }
                if !saw_any {
                    return Ok(None);
                }
                self.push_field(&mut record, &mut field, was_quoted)?;
                self.record_number += 1;
                return Ok(Some(record));
            };
            saw_any = true;
            self.bump_record_bytes(&mut record_bytes, 1)?;

            if quoted {
                match byte {
                    b'"' => {
                        if self.peek_byte()? == Some(b'"') {
                            let _ = self.take_byte()?;
                            self.bump_record_bytes(&mut record_bytes, 1)?;
                            field.push(b'"');
                        } else {
                            quoted = false;
                            closed_quote = true;
                        }
                    }
                    _ => field.push(byte),
                }
                continue;
            }

            if closed_quote
                && byte != self.configuration.delimiter() as u8
                && byte != b'\n'
                && byte != b'\r'
            {
                return Err(JtlError::Csv {
                    record: self.record_number + 1,
                    detail: "characters after a closing quote are not allowed".to_owned(),
                });
            }
            match byte {
                b'"' if at_field_start => {
                    quoted = true;
                    was_quoted = true;
                    at_field_start = false;
                }
                byte if byte == self.configuration.delimiter() as u8 => {
                    self.push_field(&mut record, &mut field, was_quoted)?;
                    was_quoted = false;
                    closed_quote = false;
                    at_field_start = true;
                }
                b'\n' | b'\r' => {
                    if byte == b'\r' && self.peek_byte()? == Some(b'\n') {
                        let _ = self.take_byte()?;
                        self.bump_record_bytes(&mut record_bytes, 1)?;
                    }
                    self.push_field(&mut record, &mut field, was_quoted)?;
                    self.record_number += 1;
                    return Ok(Some(record));
                }
                _ => {
                    field.push(byte);
                    at_field_start = false;
                }
            }
        }
    }

    fn bump_record_bytes(&self, current: &mut usize, amount: usize) -> Result<(), JtlError> {
        *current = current
            .checked_add(amount)
            .ok_or_else(|| JtlError::Unsupported {
                feature: "csv-record-limit",
                value: "record length overflow".to_owned(),
            })?;
        if *current > self.limits.max_record_bytes {
            return Err(JtlError::Unsupported {
                feature: "csv-record-limit",
                value: format!("record exceeds {} bytes", self.limits.max_record_bytes),
            });
        }
        Ok(())
    }

    fn push_field(
        &self,
        record: &mut Vec<CsvToken>,
        field: &mut Vec<u8>,
        quoted: bool,
    ) -> Result<(), JtlError> {
        let value = String::from_utf8(std::mem::take(field)).map_err(|_| JtlError::Csv {
            record: self.record_number + 1,
            detail: "field is not valid UTF-8".to_owned(),
        })?;
        record.push(CsvToken { value, quoted });
        if record.len() > self.limits.max_columns {
            return Err(JtlError::Unsupported {
                feature: "csv-column-limit",
                value: format!(
                    "{} columns exceeds {}",
                    record.len(),
                    self.limits.max_columns
                ),
            });
        }
        Ok(())
    }

    fn decode_record(&self, record: &[CsvToken]) -> Result<SampleEvent, JtlError> {
        if record.len() < self.columns.len() {
            return Err(JtlError::Csv {
                record: self.record_number,
                detail: format!(
                    "expected at least {} columns, got {}",
                    self.columns.len(),
                    record.len()
                ),
            });
        }
        // CSVSaveService.makeResultFromDelimitedString consumes the enabled
        // columns and logs that trailing fields were ignored. Keep the same
        // compatibility behavior; unknown *named* columns remain represented
        // by CsvColumn::Variable when present in a valid header.
        let mut result = SampleResult::without_label();
        if !self
            .columns
            .iter()
            .any(|column| matches!(column, CsvColumn::Field(CsvField::Success)))
        {
            result.set_success(Some(true));
        }
        if !self
            .columns
            .iter()
            .any(|column| matches!(column, CsvColumn::Field(CsvField::DataType)))
        {
            result.set_data_type(Some(DataType::Text));
        }
        if !self
            .columns
            .iter()
            .any(|column| matches!(column, CsvColumn::Field(CsvField::Encoding)))
            && let Some(encoding) = self.configuration.default_encoding()
        {
            result.set_data_encoding(Some(DataEncoding::new(encoding.to_owned())));
        }
        let mut thread_name = String::new();
        let mut host = String::new();
        let mut variables = VariableSnapshot::new();
        let mut timestamp = None;
        let mut elapsed = None;
        let mut latency = None;
        let mut connect = None;
        let mut idle = None;
        for (column, token) in self.columns.iter().zip(record) {
            match column {
                CsvColumn::Variable(name) => {
                    variables.insert(name.clone(), token.value.clone());
                }
                CsvColumn::Field(field) => match field {
                    CsvField::Timestamp => {
                        timestamp = if token.value.is_empty() {
                            None
                        } else {
                            Some(self.parse_timestamp(&token.value)?)
                        };
                    }
                    CsvField::Elapsed => {
                        elapsed = parse_optional_u64(&token.value, "elapsed", self.record_number)?
                    }
                    CsvField::Label => result.set_label(token.value.clone()),
                    CsvField::ResponseCode => result.set_response_code(Some(token.value.clone())),
                    CsvField::ResponseMessage => {
                        result.set_response_message(Some(token.value.clone()))
                    }
                    CsvField::ThreadName => thread_name = token.value.clone(),
                    CsvField::DataType => {
                        result.set_data_type(Some(DataType::from_wire(token.value.clone())))
                    }
                    CsvField::Success => {
                        result.set_success(if token.value.is_empty() {
                            None
                        } else {
                            Some(parse_csv_bool(&token.value, "success", self.record_number)?)
                        });
                    }
                    CsvField::FailureMessage => {
                        result.set_failure_message(Some(token.value.clone()))
                    }
                    CsvField::Bytes => {
                        result.set_received_bytes(
                            parse_optional_u64(&token.value, "bytes", self.record_number)?
                                .map(crate::ByteCount::new),
                        );
                    }
                    CsvField::SentBytes => {
                        result.set_sent_bytes(
                            parse_optional_u64(&token.value, "sentBytes", self.record_number)?
                                .map(crate::ByteCount::new),
                        );
                    }
                    CsvField::GroupThreads => {
                        result.set_group_threads(
                            parse_optional_u64(&token.value, "grpThreads", self.record_number)?
                                .map(crate::ThreadCount::new),
                        );
                    }
                    CsvField::AllThreads => {
                        result.set_all_threads(
                            parse_optional_u64(&token.value, "allThreads", self.record_number)?
                                .map(crate::ThreadCount::new),
                        );
                    }
                    CsvField::Url => {
                        result.set_url(if token.value == "null" {
                            None
                        } else {
                            Some(token.value.clone())
                        });
                    }
                    CsvField::Filename => {
                        // Filename is a reference, not a request to resolve
                        // or read a filesystem path in the pure codec.
                        result.set_response_file(Some(token.value.clone()));
                    }
                    CsvField::Latency => {
                        latency = parse_optional_u64(&token.value, "Latency", self.record_number)?
                    }
                    CsvField::Encoding => {
                        result.set_data_encoding(Some(DataEncoding::new(token.value.clone())))
                    }
                    CsvField::SampleCount => {
                        result.set_sample_count(
                            parse_optional_u64(&token.value, "SampleCount", self.record_number)?
                                .map(crate::SampleCount::new),
                        );
                    }
                    CsvField::ErrorCount => {
                        result.set_error_count(
                            parse_optional_u64(&token.value, "ErrorCount", self.record_number)?
                                .map(crate::ErrorCount::new),
                        );
                    }
                    CsvField::Hostname => host = token.value.clone(),
                    CsvField::IdleTime => {
                        idle = parse_optional_u64(&token.value, "IdleTime", self.record_number)?
                    }
                    CsvField::Connect => {
                        connect = parse_optional_u64(&token.value, "Connect", self.record_number)?
                    }
                },
            }
        }
        let timing = timing_from_wire(timestamp, elapsed, latency, connect, idle)?;
        result.set_timing_from_wire(timing);
        result.validate_wire_with_limits(self.configuration_limits())?;
        Ok(SampleEvent::new(
            result,
            "",
            ThreadIdentity::new(thread_name),
            HostIdentity::new(host),
            variables,
        ))
    }

    fn parse_timestamp(&self, value: &str) -> Result<i64, JtlError> {
        match self.configuration.timestamp_format() {
            TimestampFormat::None | TimestampFormat::Milliseconds => {
                let numeric = {
                    let digits = value.strip_prefix('-').unwrap_or(value);
                    (!digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()))
                        .then(|| value.parse::<i64>().ok())
                        .flatten()
                };
                match numeric {
                    Some(value) => Ok(value),
                    None => parse_legacy_timestamp(value).ok_or_else(|| JtlError::Csv {
                        record: self.record_number,
                        detail: format!("timestamp must be milliseconds or a recognized legacy date, got {value:?}"),
                    }),
                }
            }
            TimestampFormat::JavaDateFormat(pattern) => self
                .date_provider
                .as_ref()
                .ok_or_else(|| JtlError::Unsupported {
                    feature: "java-date-format",
                    value: pattern.clone(),
                })?
                .parse(value, pattern),
        }
    }

    fn configuration_limits(&self) -> crate::ValidationLimits {
        crate::ValidationLimits::new(self.limits.max_depth, self.limits.max_nodes)
            .unwrap_or_default()
    }
}

fn parse_csv_bool(value: &str, field: &str, record: usize) -> Result<bool, JtlError> {
    if value.eq_ignore_ascii_case("true") {
        return Ok(true);
    }
    if value.eq_ignore_ascii_case("false") {
        return Ok(false);
    }
    Err(JtlError::Csv {
        record,
        detail: format!("{field} must be true or false, got {value:?}"),
    })
}

fn result_node_count(result: &SampleResult, include_subresults: bool) -> Result<usize, JtlError> {
    if !include_subresults {
        return Ok(1);
    }
    let mut count = 0usize;
    let mut pending = vec![result];
    while let Some(node) = pending.pop() {
        count = checked_counter_add(count, 1, JtlCounter::Samples)?;
        pending.extend(node.sub_results().iter());
    }
    Ok(count)
}

impl<R: Read> Iterator for CsvDecoder<R> {
    type Item = Result<SampleEvent, JtlError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_event() {
            Ok(Some(event)) => Some(Ok(event)),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        }
    }
}

/// Encodes a bounded iterator of events as CSV.
pub fn encode_csv<W, I>(
    writer: W,
    events: I,
    configuration: SampleSaveConfiguration,
) -> Result<W, JtlError>
where
    W: Write,
    I: IntoIterator,
    I::Item: std::borrow::Borrow<SampleEvent>,
{
    let mut encoder = CsvEncoder::new(writer, configuration)?;
    for event in events {
        encoder.write_event(event.borrow())?;
    }
    encoder.finish()
}

/// Decodes a bounded CSV stream using the supplied configuration.
pub fn decode_csv<R: Read>(
    reader: R,
    configuration: SampleSaveConfiguration,
) -> Result<Vec<SampleEvent>, JtlError> {
    CsvDecoder::new(reader, configuration)?.decode_all()
}

/// Decodes a CSV stream into a bounded collection with an explicit aggregate
/// event limit.  For unbounded or very large streams, use [`CsvDecoder`]
/// directly and consume [`CsvDecoder::next_event`].
pub fn decode_csv_with_limit<R: Read>(
    reader: R,
    configuration: SampleSaveConfiguration,
    maximum_events: usize,
) -> Result<Vec<SampleEvent>, JtlError> {
    CsvDecoder::new(reader, configuration)?.decode_all_with_limit(maximum_events)
}

/// Alias for [`encode_csv`].
pub fn write_csv<W, I>(
    writer: W,
    events: I,
    configuration: SampleSaveConfiguration,
) -> Result<W, JtlError>
where
    W: Write,
    I: IntoIterator,
    I::Item: std::borrow::Borrow<SampleEvent>,
{
    encode_csv(writer, events, configuration)
}

/// Alias for [`decode_csv`].
pub fn read_csv<R: Read>(
    reader: R,
    configuration: SampleSaveConfiguration,
) -> Result<Vec<SampleEvent>, JtlError> {
    decode_csv(reader, configuration)
}

fn append_csv_token(output: &mut String, value: &str, delimiter: char) {
    if value.chars().any(|character| {
        character == delimiter || character == '"' || character == '\n' || character == '\r'
    }) {
        output.push('"');
        for character in value.chars() {
            if character == '"' {
                output.push('"');
            }
            output.push(character);
        }
        output.push('"');
    } else {
        output.push_str(value);
    }
}

fn parse_header(record: &[CsvToken], maximum: usize) -> Result<Vec<CsvColumn>, JtlError> {
    if record.len() > maximum {
        return Err(JtlError::Unsupported {
            feature: "csv-column-limit",
            value: format!("{} columns exceeds {maximum}", record.len()),
        });
    }
    let mut columns = Vec::with_capacity(record.len());
    let mut previous_order = None;
    let mut in_variables = false;
    for token in record {
        // JMeter quotes every configured sample-variable name in the header.
        // A variable is allowed to have the same spelling as a built-in field
        // (for example `label`), so quoting is significant here.
        if !token.quoted
            && let Some(field) = CsvField::parse(&token.value)
        {
            if in_variables {
                return Err(JtlError::Csv {
                    record: 1,
                    detail: format!(
                        "built-in field {} appears after sample variables",
                        field.name()
                    ),
                });
            }
            if columns
                .iter()
                .any(|column| matches!(column, CsvColumn::Field(existing) if *existing == field))
            {
                return Err(JtlError::Csv {
                    record: 1,
                    detail: format!("duplicate field {}", field.name()),
                });
            }
            if previous_order.is_some_and(|previous| field.order() <= previous) {
                return Err(JtlError::Csv {
                    record: 1,
                    detail: format!("field {} is out of canonical order", field.name()),
                });
            }
            previous_order = Some(field.order());
            columns.push(CsvColumn::Field(field));
        } else {
            if token.value.is_empty() {
                return Err(JtlError::Csv {
                    record: 1,
                    detail: "sample variable column name must not be empty".to_owned(),
                });
            }
            in_variables = true;
            if columns.iter().any(
                |column| matches!(column, CsvColumn::Variable(existing) if existing == &token.value),
            ) {
                return Err(JtlError::Csv {
                    record: 1,
                    detail: format!("duplicate sample variable {:?}", token.value),
                });
            }
            columns.push(CsvColumn::Variable(token.value.clone()));
        }
    }
    Ok(columns)
}

/// Returns whether a header failure is itself malformed input rather than a
/// compatibility layout mismatch.  JMeter accepts older/out-of-order headers
/// by replaying the first row with the configured layout, but an empty or
/// duplicate column cannot identify a deterministic layout and must fail
/// before any sample is yielded.
fn is_fatal_header_error(error: &JtlError) -> bool {
    matches!(
        error,
        JtlError::Csv { detail, .. }
            if detail.contains("duplicate") || detail.contains("must not be empty")
    )
}

/// Infers an alternate delimiter from a header-shaped first record.
///
/// JMeter first tries the configured delimiter and then uses the header to
/// discover a single non-word separator. Candidate counting is quote-aware,
/// so punctuation in a quoted sample-variable name cannot be mistaken for
/// the separator. Requiring at least two built-ins (or one built-in and a
/// quoted variable) prevents a headerless data row such as `label|200` from
/// changing the delimiter.
fn header_suggests_delimiter(input: &[u8], maximum: usize) -> Option<char> {
    let end = input
        .iter()
        .position(|byte| *byte == b'\n' || *byte == b'\r')
        .unwrap_or(input.len());
    let line = &input[..end];
    let mut counts = [0usize; 128];
    let mut quoted = false;
    let mut index = 0usize;
    while index < line.len() {
        let byte = line[index];
        if quoted {
            if byte == b'"' {
                if line.get(index + 1) == Some(&b'"') {
                    index += 2;
                    continue;
                }
                quoted = false;
            }
            index += 1;
            continue;
        }
        if byte == b'"' {
            quoted = true;
        } else if is_header_delimiter_candidate(byte) {
            counts[usize::from(byte)] += 1;
        }
        index += 1;
    }
    if quoted {
        return None;
    }

    let mut best = None;
    for byte in 0_u8..=127 {
        let count = counts[usize::from(byte)];
        if count == 0 {
            continue;
        }
        let Some(tokens) = split_header_candidate(line, byte, maximum) else {
            continue;
        };
        let Ok(columns) = parse_header(&tokens, maximum) else {
            continue;
        };
        let built_in_count = columns
            .iter()
            .filter(|column| matches!(column, CsvColumn::Field(_)))
            .count();
        let quoted_variable_count = tokens
            .iter()
            .zip(&columns)
            .filter(|(token, column)| token.quoted && matches!(column, CsvColumn::Variable(_)))
            .count();
        if !(built_in_count >= 2 || (built_in_count >= 1 && quoted_variable_count >= 1)) {
            continue;
        }
        if best.is_none_or(|(best_count, best_byte)| {
            count > best_count || (count == best_count && byte < best_byte)
        }) {
            best = Some((count, byte));
        }
    }
    best.map(|(_, byte)| char::from(byte))
}

fn is_header_delimiter_candidate(byte: u8) -> bool {
    byte == b'\t'
        || byte == b' '
        || (byte.is_ascii_graphic() && !byte.is_ascii_alphanumeric() && byte != b'"')
}

/// Splits one physical header line with a candidate delimiter using the same
/// quote rules as the streaming parser. It is bounded by the configured
/// column limit because this runs before the normal record parser.
fn split_header_candidate(input: &[u8], delimiter: u8, maximum: usize) -> Option<Vec<CsvToken>> {
    let mut record = Vec::new();
    let mut field = Vec::new();
    let mut quoted = false;
    let mut was_quoted = false;
    let mut closed_quote = false;
    let mut at_field_start = true;
    let mut index = 0usize;
    while index < input.len() {
        let byte = input[index];
        if quoted {
            if byte == b'"' {
                if input.get(index + 1) == Some(&b'"') {
                    field.push(b'"');
                    index += 2;
                    continue;
                }
                quoted = false;
                closed_quote = true;
            } else {
                field.push(byte);
            }
            index += 1;
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
                record.push(CsvToken {
                    value: String::from_utf8(std::mem::take(&mut field)).ok()?,
                    quoted: was_quoted,
                });
                if record.len() > maximum {
                    return None;
                }
                was_quoted = false;
                closed_quote = false;
                at_field_start = true;
            }
            _ => {
                field.push(byte);
                at_field_start = false;
            }
        }
        index += 1;
    }
    if quoted {
        return None;
    }
    record.push(CsvToken {
        value: String::from_utf8(field).ok()?,
        quoted: was_quoted,
    });
    (record.len() <= maximum).then_some(record)
}

fn looks_like_header(record: &[CsvToken], columns: &[CsvColumn], configured: &[CsvColumn]) -> bool {
    if columns == configured {
        return true;
    }
    let built_in_count = columns
        .iter()
        .filter(|column| matches!(column, CsvColumn::Field(_)))
        .count();
    built_in_count >= 2
        && record
            .iter()
            .zip(columns)
            .all(|(token, column)| match column {
                CsvColumn::Field(field) => {
                    !token.quoted && CsvField::parse(&token.value) == Some(*field)
                }
                CsvColumn::Variable(_) => token.quoted || is_header_identifier(&token.value),
            })
}

fn is_header_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

// Java's SimpleDateFormat fallback list used by JMeter's CSV reader. The
// implementation is deliberately UTC because the compatibility profile fixes
// TZ=UTC; a profile with a different zone can supply a JavaDateFormatProvider.
fn parse_legacy_timestamp(value: &str) -> Option<i64> {
    let patterns = [
        ("yyyy/MM/dd HH:mm:ss.SSS", true),
        ("yyyy/MM/dd HH:mm:ss", false),
        ("yyyy-MM-dd HH:mm:ss.SSS", true),
        ("yyyy-MM-dd HH:mm:ss", false),
        ("MM/dd/yy HH:mm:ss", false),
    ];
    patterns
        .into_iter()
        .find_map(|(pattern, millis)| parse_legacy_with_pattern(value, pattern, millis))
}

fn parse_legacy_with_pattern(value: &str, pattern: &str, has_millis: bool) -> Option<i64> {
    let separator = if pattern.contains('/') { '/' } else { '-' };
    let (date, time) = value.split_once(' ')?;
    let date_parts = date.split(separator).collect::<Vec<_>>();
    let time_parts = time.split(':').collect::<Vec<_>>();
    if date_parts.len() != 3 || time_parts.len() != 3 {
        return None;
    }
    let (mut year, month, day) = if pattern.starts_with("MM") {
        (
            date_parts[2].parse::<i32>().ok()?,
            date_parts[0].parse::<u32>().ok()?,
            date_parts[1].parse::<u32>().ok()?,
        )
    } else {
        (
            date_parts[0].parse::<i32>().ok()?,
            date_parts[1].parse::<u32>().ok()?,
            date_parts[2].parse::<u32>().ok()?,
        )
    };
    if pattern.starts_with("MM") {
        year += if year < 70 { 2000 } else { 1900 };
    }
    let hour = time_parts[0].parse::<u32>().ok()?;
    let minute = time_parts[1].parse::<u32>().ok()?;
    let (second, millis) = if has_millis {
        let (seconds, fraction) = time_parts[2].split_once('.')?;
        (seconds.parse::<u32>().ok()?, fraction.parse::<u32>().ok()?)
    } else {
        (time_parts[2].parse::<u32>().ok()?, 0)
    };
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days_in_month = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => 0,
    };
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month
        || hour > 23
        || minute > 59
        || second > 59
        || millis > 999
    {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(i64::from(hour) * 3_600)?
        .checked_add(i64::from(minute) * 60)?
        .checked_add(i64::from(second))?;
    seconds.checked_mul(1_000)?.checked_add(i64::from(millis))
}

fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    // Howard Hinnant's proleptic Gregorian conversion, checked for the
    // arithmetic needed by the bounded parser.
    let year = i64::from(year) - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day = i64::from(day);
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era.checked_mul(146_097)?
        .checked_add(day_of_era)?
        .checked_sub(719_468)
}

// Test fixtures use `expect` at setup/assertion boundaries so failures retain
// the operation name; production codec paths remain explicitly fallible.
#[allow(clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AssertionResult, ByteCount, ErrorCount, SampleCount, ThreadCount};

    fn fixture_event() -> SampleEvent {
        let mut result = SampleResult::new("comma,label");
        result.set_successful(true);
        result.set_response_code_text("200");
        result.set_response_message_text("OK");
        result.set_data_type_wire("text");
        result.set_data_encoding_name("US-ASCII");
        result
            .set_elapsed(Some(crate::ElapsedTime::from_millis(12)))
            .expect("timing");
        result
            .set_latency(Some(crate::Latency::from_millis(2)))
            .expect("timing");
        result
            .set_connect_time(Some(crate::ConnectTime::from_millis(1)))
            .expect("timing");
        result
            .set_idle_time(Some(crate::IdleTime::from_millis(0)))
            .expect("timing");
        result.set_received_bytes(Some(ByteCount::new(3)));
        result.set_sent_bytes(Some(ByteCount::new(4)));
        result.set_group_threads(Some(ThreadCount::new(1)));
        result.set_all_threads(Some(ThreadCount::new(2)));
        result.set_sample_count(Some(SampleCount::ONE));
        result.set_error_count(Some(ErrorCount::ZERO));
        result
            .add_assertion(AssertionResult::failed(
                "assert",
                Some("line\n\"x".to_owned()),
            ))
            .expect("assertion");
        let mut variables = VariableSnapshot::new();
        variables.insert("case_id", "jtl-fields");
        variables.insert("comma_value", "left,right");
        SampleEvent::new(
            result,
            "run",
            ThreadIdentity::new("thread"),
            "host",
            variables,
        )
    }

    fn no_field_config() -> SampleSaveConfiguration {
        let mut config = SampleSaveConfiguration::default();
        config.set_print_field_names(false);
        config.set_timestamp(false);
        config.set_time(false);
        config.set_latency(false);
        config.set_connect_time(false);
        config.set_idle_time(false);
        config.set_success(false);
        config.set_label(false);
        config.set_response_code(false);
        config.set_response_message(false);
        config.set_thread_name(false);
        config.set_data_type(false);
        config.set_encoding(false);
        config.set_assertion_results_failure_message(false);
        config.set_bytes(false);
        config.set_sent_bytes(false);
        config.set_thread_counts(false);
        config.set_url(false);
        config.set_filename(false);
        config.set_sample_count(false);
        config.set_hostname(false);
        config
    }

    #[test]
    fn canonical_header_and_quotes_round_trip() {
        let mut config = SampleSaveConfiguration::default();
        config.set_timestamp_format(TimestampFormat::None);
        config.set_encoding(true);
        config.set_sample_count(true);
        config.set_assertion_results_failure_message(true);
        config
            .set_sample_variables(["case_id", "comma_value"])
            .expect("vars");
        let event = fixture_event();
        let mut bytes = Vec::new();
        let mut encoder = CsvEncoder::new(&mut bytes, config.clone()).expect("encoder");
        encoder.write_event(&event).expect("write");
        encoder.finish().expect("finish");
        let text = String::from_utf8(bytes).expect("utf8");
        assert!(text.starts_with("elapsed,label,responseCode"));
        assert!(text.contains("\"left,right\""));
        let decoded = CsvDecoder::new(text.as_bytes(), config)
            .expect("decoder")
            .decode_all()
            .expect("decode");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].result().label(), "comma,label");
        assert_eq!(
            decoded[0]
                .variables()
                .get("comma_value")
                .and_then(|value| value.as_str()),
            Some("left,right")
        );
    }

    #[test]
    fn timestamp_column_uses_the_configured_sample_endpoint() {
        let mut result = SampleResult::new("endpoint");
        result
            .set_start_time(Some(crate::WallTimestamp::from_millis(100)))
            .expect("start");
        result
            .set_end_time(Some(crate::WallTimestamp::from_millis(107)))
            .expect("end");
        result.set_timestamp(Some(crate::WallTimestamp::from_millis(999)));
        let event = SampleEvent::new(
            result,
            "run",
            ThreadIdentity::new("thread"),
            "host",
            VariableSnapshot::new(),
        );

        let mut end_config = no_field_config();
        end_config.set_print_field_names(false);
        end_config.set_timestamp(true);
        end_config.set_timestamp_start(false);
        let mut output = Vec::new();
        let mut encoder = CsvEncoder::new(&mut output, end_config).expect("end encoder");
        encoder.write_event(&event).expect("end write");
        encoder.finish().expect("end finish");
        assert_eq!(String::from_utf8(output).expect("UTF-8"), "107\n");

        let mut start_config = no_field_config();
        start_config.set_print_field_names(false);
        start_config.set_timestamp(true);
        start_config.set_timestamp_start(true);
        let mut output = Vec::new();
        let mut encoder = CsvEncoder::new(&mut output, start_config).expect("start encoder");
        encoder.write_event(&event).expect("start write");
        encoder.finish().expect("start finish");
        assert_eq!(String::from_utf8(output).expect("UTF-8"), "100\n");
    }

    #[test]
    fn decode_all_with_limit_bounds_retained_event_count() {
        let mut config = no_field_config();
        config.set_label(true);
        let input = b"first\nsecond\n";
        let error = CsvDecoder::new(input.as_slice(), config.clone())
            .expect("decoder")
            .decode_all_with_limit(1);
        assert!(matches!(
            error,
            Err(JtlError::Unsupported {
                feature: "decode-all-event-limit",
                ..
            })
        ));
        assert!(matches!(
            CsvDecoder::new(input.as_slice(), config.clone())
                .expect("decoder")
                .decode_all_with_limit(0),
            Err(JtlError::InvalidConfiguration {
                field: "decode_all_event_limit",
                ..
            })
        ));
        assert!(matches!(
            CsvDecoder::new(input.as_slice(), config)
                .expect("decoder")
                .decode_all_with_limit(MAX_DECODE_ALL_EVENTS + 1),
            Err(JtlError::InvalidConfiguration {
                field: "decode_all_event_limit",
                ..
            })
        ));
    }

    #[test]
    fn tab_delimiter_and_newline_are_quoted() {
        let mut config = SampleSaveConfiguration::default();
        config.set_delimiter('\t').expect("delimiter");
        config.set_print_field_names(false);
        config.set_sample_variables(["v"]).expect("vars");
        let event = fixture_event();
        let mut output = Vec::new();
        let mut encoder = CsvEncoder::new(&mut output, config).expect("encoder");
        encoder.write_event(&event).expect("write");
        encoder.finish().expect("finish");
        let text = String::from_utf8(output).expect("utf8");
        assert!(text.contains("\n"));
        assert!(text.contains("\"line\n\"\"x\""));
    }

    #[test]
    fn tab_delimiter_is_inferred_from_canonical_header() {
        let mut config = no_field_config();
        config.set_label(true);
        config.set_response_code(true);
        let input = b"elapsed\tlabel\tresponseCode\n12\t\"tab label\"\t500\n";
        let events = CsvDecoder::new(input.as_slice(), config)
            .expect("decoder")
            .decode_all()
            .expect("tab header");
        assert_eq!(events[0].result().label(), "tab label");
        assert_eq!(events[0].result().response_code(), Some("500"));
    }

    #[test]
    fn alternate_header_delimiters_are_inferred_and_values_are_quoted() {
        for delimiter in ['\t', '|', ';'] {
            let mut writer_config = no_field_config();
            writer_config.set_print_field_names(true);
            writer_config.set_label(true);
            writer_config.set_response_code(true);
            writer_config.set_delimiter(delimiter).expect("delimiter");
            let mut result = SampleResult::new(format!("left{delimiter}right"));
            result.set_response_code_text("200");
            let event = SampleEvent::new(
                result,
                "run",
                ThreadIdentity::new("thread"),
                "host",
                VariableSnapshot::new(),
            );
            let mut output = Vec::new();
            let mut encoder = CsvEncoder::new(&mut output, writer_config).expect("encoder");
            encoder.write_event(&event).expect("write");
            encoder.finish().expect("finish");

            // The reader starts with JMeter's comma default. Header inference
            // must select the actual separator before parsing the first row.
            let events = CsvDecoder::new(output.as_slice(), no_field_config())
                .expect("decoder")
                .decode_all()
                .expect("alternate delimiter");
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].result().label(), format!("left{delimiter}right"));
            assert_eq!(events[0].result().response_code(), Some("200"));
        }
    }

    #[test]
    fn unknown_header_columns_are_retained_as_variables() {
        let mut config = no_field_config();
        config.set_print_field_names(true);
        config.set_timestamp(true);
        config.set_time(true);
        config.set_label(true);
        let events = CsvDecoder::new(
            b"timeStamp,elapsed,label,pluginField\n1700000000000,1,sample,opaque\n".as_slice(),
            config,
        )
        .expect("decoder")
        .decode_all()
        .expect("unknown CSV column");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].result().label(), "sample");
        assert_eq!(
            events[0]
                .variables()
                .get("pluginField")
                .and_then(|value| value.as_str()),
            Some("opaque")
        );
    }

    #[test]
    fn jmeter_default_header_order_is_canonical() {
        let mut configuration = SampleSaveConfiguration::default();
        configuration.set_filename(true);
        configuration.set_encoding(true);
        configuration.set_sample_count(true);
        configuration.set_hostname(true);
        let names = configuration
            .columns()
            .into_iter()
            .map(|column| match column {
                CsvColumn::Field(field) => field.name().to_owned(),
                CsvColumn::Variable(name) => name,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                "timeStamp",
                "elapsed",
                "label",
                "responseCode",
                "responseMessage",
                "threadName",
                "dataType",
                "success",
                "failureMessage",
                "bytes",
                "sentBytes",
                "grpThreads",
                "allThreads",
                "URL",
                "Filename",
                "Latency",
                "Encoding",
                "SampleCount",
                "ErrorCount",
                "Hostname",
                "IdleTime",
                "Connect",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>()
        );
    }

    #[test]
    fn trailing_row_fields_are_ignored_like_jmeter() {
        let mut config = no_field_config();
        config.set_print_field_names(true);
        config.set_label(true);
        config.set_response_code(true);
        let events = CsvDecoder::new(
            b"label,responseCode\nsample,200,field-from-newer-writer\n".as_slice(),
            config,
        )
        .expect("decoder")
        .decode_all()
        .expect("JMeter ignores trailing fields");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].result().label(), "sample");
        assert_eq!(events[0].result().response_code(), Some("200"));
    }

    #[test]
    fn invalid_header_falls_back_to_configured_layout_without_remapping_rows() {
        let mut config = no_field_config();
        config.set_print_field_names(true);
        config.set_label(true);
        config.set_response_code(true);
        // responseCode before label is not canonical. JMeter warns, resets to
        // the configured layout, and replays the first line as data.
        let events = CsvDecoder::new(b"responseCode,label\nactual,200\n".as_slice(), config)
            .expect("decoder")
            .decode_all()
            .expect("fallback layout");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].result().label(), "responseCode");
        assert_eq!(events[0].result().response_code(), Some("label"));
        assert_eq!(events[1].result().label(), "actual");
        assert_eq!(events[1].result().response_code(), Some("200"));
    }

    #[test]
    fn duplicate_or_empty_header_columns_are_strict_errors() {
        for input in [
            b"label,label\nsample,200\n".as_slice(),
            b"label,,responseCode\nsample,,200\n".as_slice(),
            b"\"sampleVar\",\"sampleVar\"\nvalue,value\n".as_slice(),
        ] {
            let mut config = no_field_config();
            config.set_print_field_names(true);
            config.set_label(true);
            config.set_response_code(true);
            assert!(
                matches!(
                    CsvDecoder::new(input, config),
                    Err(JtlError::Csv { detail, .. })
                        if detail.contains("duplicate") || detail.contains("must not be empty")
                ),
                "unexpected header result for {input:?}"
            );
        }
    }

    #[test]
    fn short_rows_remain_an_explicit_csv_error() {
        let mut config = no_field_config();
        config.set_print_field_names(true);
        config.set_label(true);
        config.set_response_code(true);
        assert!(matches!(
            CsvDecoder::new(b"label,responseCode\nsample\n".as_slice(), config)
                .expect("decoder")
                .decode_all(),
            Err(JtlError::Csv { .. })
        ));
    }

    #[test]
    fn legacy_timestamp_patterns_are_utc_and_strict() {
        let expected = 1_700_000_000_000;
        assert_eq!(
            parse_legacy_timestamp("2023/11/14 22:13:20"),
            Some(expected)
        );
        assert_eq!(
            parse_legacy_timestamp("2023/11/14 22:13:20.123"),
            Some(expected + 123)
        );
        assert_eq!(
            parse_legacy_timestamp("2023-11-14 22:13:20"),
            Some(expected)
        );
        assert_eq!(
            parse_legacy_timestamp("2023-11-14 22:13:20.123"),
            Some(expected + 123)
        );
        assert_eq!(parse_legacy_timestamp("11/14/23 22:13:20"), Some(expected));
        assert_eq!(parse_legacy_timestamp("2023/02/29 22:13:20"), None);
        assert_eq!(parse_legacy_timestamp("2023/11/14 22:13:20x"), None);
    }

    #[test]
    fn literal_crlf_fixture_round_trips_as_crlf_records() {
        let mut config = no_field_config();
        config.set_print_field_names(true);
        config.set_label(true);
        config.set_response_code(true);
        config.set_line_ending(crate::LineEnding::CrLf);
        let fixture = b"label,responseCode\r\n\"line,one\",200\r\n";

        let events = CsvDecoder::new(fixture.as_slice(), config.clone())
            .expect("decoder")
            .decode_all()
            .expect("CRLF fixture");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].result().label(), "line,one");
        assert_eq!(events[0].result().response_code(), Some("200"));

        let mut output = Vec::new();
        let mut encoder = CsvEncoder::new(&mut output, config).expect("encoder");
        encoder.write_event(&events[0]).expect("write");
        encoder.finish().expect("finish");
        assert_eq!(output, fixture);
    }

    #[test]
    fn classic_cr_line_endings_are_records_not_data_bytes() {
        let mut config = no_field_config();
        config.set_print_field_names(true);
        config.set_label(true);
        config.set_response_code(true);
        let events = CsvDecoder::new(b"label,responseCode\rsample,200\r".as_slice(), config)
            .expect("decoder")
            .decode_all()
            .expect("CR records");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].result().label(), "sample");
        assert_eq!(events[0].result().response_code(), Some("200"));
    }

    #[test]
    fn malformed_boolean_and_numeric_are_rejected() {
        let mut config = SampleSaveConfiguration::default();
        config.set_print_field_names(false);
        config.set_time(false);
        config.set_timestamp(false);
        config.set_label(false);
        config.set_response_code(false);
        config.set_response_message(false);
        config.set_thread_name(false);
        config.set_data_type(false);
        config.set_assertion_results_failure_message(false);
        config.set_bytes(false);
        config.set_sent_bytes(false);
        config.set_thread_counts(false);
        config.set_url(false);
        config.set_filename(false);
        config.set_latency(false);
        config.set_encoding(false);
        config.set_sample_count(false);
        config.set_hostname(false);
        config.set_idle_time(false);
        config.set_connect_time(false);
        config.set_success(true);
        let error = CsvDecoder::new("not-bool\n".as_bytes(), config)
            .expect("decoder")
            .decode_all();
        assert!(matches!(error, Err(JtlError::Csv { .. })));
    }

    #[test]
    fn trailing_quote_and_subresult_switch_are_strict() {
        let mut config = SampleSaveConfiguration::default();
        config.set_print_field_names(false);
        assert!(matches!(
            CsvDecoder::new("\"quoted\"tail\n".as_bytes(), config.clone()),
            Err(JtlError::Csv { .. })
        ));

        let mut parent = SampleResult::new("parent");
        parent.set_successful(true);
        let child = SampleResult::new("child");
        parent
            .add_sub_result(child, crate::ValidationLimits::default())
            .expect("child");
        let event = SampleEvent::new(
            parent,
            "run",
            ThreadIdentity::new("thread"),
            "host",
            VariableSnapshot::new(),
        );
        let mut output = Vec::new();
        let mut encoder = CsvEncoder::new(&mut output, config.clone()).expect("encoder");
        encoder.write_event(&event).expect("write");
        encoder.finish().expect("finish");
        assert_eq!(String::from_utf8(output).expect("utf8").lines().count(), 2);

        config.set_subresults(false);
        let mut output = Vec::new();
        let mut encoder = CsvEncoder::new(&mut output, config).expect("encoder");
        encoder.write_event(&event).expect("write");
        encoder.finish().expect("finish");
        assert_eq!(String::from_utf8(output).expect("utf8").lines().count(), 1);
    }

    #[test]
    fn legacy_timestamp_fallback_is_utc() {
        assert_eq!(parse_legacy_timestamp("1970/01/01 00:00:00.001"), Some(1));
        assert_eq!(parse_legacy_timestamp("01/01/70 00:00:00"), Some(0));
    }

    #[test]
    fn wire_timing_keeps_independent_components() {
        let mut config = no_field_config();
        config.set_time(true);
        config.set_label(true);
        config.set_latency(true);
        config.set_connect_time(true);
        config.set_idle_time(true);
        let input = b"1,wire,2,4,3\n";
        let events = CsvDecoder::new(input.as_slice(), config)
            .expect("decoder")
            .decode_all()
            .expect("wire timing is accepted");
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].result().elapsed().map(|value| value.as_millis()),
            Some(1)
        );
        assert_eq!(
            events[0].result().latency().map(|value| value.as_millis()),
            Some(2)
        );
        assert_eq!(
            events[0]
                .result()
                .connect_time()
                .map(|value| value.as_millis()),
            Some(3)
        );
        assert_eq!(
            events[0]
                .result()
                .idle_time()
                .map(|value| value.as_millis()),
            Some(4)
        );
        let mut output = Vec::new();
        let mut encoder =
            CsvEncoder::new(output, SampleSaveConfiguration::default()).expect("encoder");
        encoder.write_event(&events[0]).expect("wire round-trip");
        output = encoder.finish().expect("finish");
        assert!(String::from_utf8(output).expect("UTF-8").contains("wire"));
    }

    #[test]
    fn absent_status_fields_get_jmeter_defaults() {
        let mut config = no_field_config();
        config.set_label(true);
        config.set_response_code(true);
        let events = CsvDecoder::new(b"wire,200\n".as_slice(), config.clone())
            .expect("decoder")
            .decode_all()
            .expect("decode");
        let result = events[0].result();
        assert_eq!(result.success(), Some(true));
        assert_eq!(result.data_type(), Some(&DataType::Text));
        assert_eq!(
            result.data_encoding().map(DataEncoding::as_str),
            Some("UTF-8")
        );

        let mut explicit_empty = SampleResult::new("empty-encoding");
        explicit_empty.set_data_encoding(Some(DataEncoding::new("")));
        let explicit_event = SampleEvent::new(
            explicit_empty,
            "",
            ThreadIdentity::new(""),
            "",
            VariableSnapshot::new(),
        );
        let mut encoding_config = config.clone();
        encoding_config.set_encoding(true);
        let mut output = Vec::new();
        let mut writer = CsvEncoder::new(&mut output, encoding_config).expect("writer");
        writer.write_event(&explicit_event).expect("write");
        writer.finish().expect("finish");
        assert_eq!(
            String::from_utf8(output).expect("UTF-8"),
            "empty-encoding,,\n"
        );
    }

    #[test]
    fn header_is_detected_when_print_switch_is_disabled() {
        let mut writer_config = SampleSaveConfiguration::default();
        writer_config.set_timestamp_format(TimestampFormat::None);
        let event = fixture_event();
        let mut bytes = Vec::new();
        let mut writer = CsvEncoder::new(&mut bytes, writer_config.clone()).expect("writer");
        writer.write_event(&event).expect("write");
        writer.finish().expect("finish");
        writer_config.set_print_field_names(false);
        let events = CsvDecoder::new(bytes.as_slice(), writer_config)
            .expect("decoder")
            .decode_all()
            .expect("header detection");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].result().label(), "comma,label");
    }

    #[test]
    fn data_row_is_not_mistaken_for_header_when_print_is_disabled() {
        let mut config = no_field_config();
        config.set_label(true);
        config.set_response_code(true);
        let events = CsvDecoder::new(b"label,200\n".as_slice(), config)
            .expect("decoder")
            .decode_all()
            .expect("data row");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].result().label(), "label");
        assert_eq!(events[0].result().response_code(), Some("200"));
    }

    #[test]
    fn utf8_bom_is_accepted_before_csv_header() {
        let mut config = no_field_config();
        config.set_print_field_names(true);
        config.set_label(true);
        config.set_response_code(true);
        config.set_success(true);
        let input = b"\xef\xbb\xbfelapsed,label,responseCode,success\n1,bom,200,true\n";
        let events = CsvDecoder::new(input.as_slice(), config)
            .expect("decoder")
            .decode_all()
            .expect("BOM");
        assert_eq!(events[0].result().label(), "bom");
    }

    #[test]
    fn max_samples_allows_exact_eof() {
        let mut config = no_field_config();
        config.set_label(true);
        let limits = JtlLimits {
            max_samples: 1,
            ..JtlLimits::default()
        };
        let mut decoder =
            CsvDecoder::with_limits(b"one\n".as_slice(), config, limits).expect("decoder");
        assert!(decoder.next_event().expect("sample").is_some());
        assert!(decoder.next_event().expect("EOF").is_none());
    }

    #[test]
    fn streaming_input_is_rejected_at_configured_bound() {
        let mut config = no_field_config();
        config.set_label(true);
        let limits = JtlLimits {
            max_input_bytes: 3,
            ..JtlLimits::default()
        };
        assert!(matches!(
            CsvDecoder::with_limits(b"four\n".as_slice(), config, limits),
            Err(JtlError::Unsupported {
                feature: "input-size-limit",
                ..
            })
        ));

        let mut config = no_field_config();
        config.set_label(true);
        let limits = JtlLimits {
            max_record_bytes: 3,
            ..JtlLimits::default()
        };
        assert!(matches!(
            CsvDecoder::with_limits(b"1234\n".as_slice(), config, limits),
            Err(JtlError::Unsupported {
                feature: "csv-record-limit",
                ..
            })
        ));
    }

    #[test]
    fn configured_column_bound_is_checked_before_decoder_layout_allocation() {
        let mut config = no_field_config();
        config.set_label(true);
        config.set_response_code(true);
        let limits = JtlLimits {
            max_columns: 1,
            ..JtlLimits::default()
        };
        assert!(matches!(
            CsvDecoder::with_limits(b"".as_slice(), config, limits),
            Err(JtlError::Unsupported {
                feature: "csv-column-limit",
                ..
            })
        ));
    }

    #[test]
    fn csv_event_output_is_atomic_when_a_nested_row_exceeds_record_limit() {
        let mut config = no_field_config();
        config.set_print_field_names(true);
        config.set_label(true);
        let mut root = SampleResult::new("root");
        root.add_sub_result(
            SampleResult::new("nested-row-too-long"),
            crate::ValidationLimits::default(),
        )
        .expect("nested result");
        let event = SampleEvent::new(
            root,
            "run",
            ThreadIdentity::new("thread"),
            "host",
            VariableSnapshot::new(),
        );
        let limits = JtlLimits {
            max_record_bytes: 6,
            ..JtlLimits::default()
        };
        let mut output = Vec::new();
        let mut encoder = CsvEncoder::new(&mut output, config)
            .expect("encoder")
            .with_limits(limits)
            .expect("limits");
        assert!(matches!(
            encoder.write_event(&event),
            Err(JtlError::Unsupported {
                feature: "csv-record-limit",
                ..
            })
        ));
        assert!(
            output.is_empty(),
            "header/root rows must not survive a nested-row failure"
        );
    }

    #[test]
    fn csv_aggregate_output_limit_preserves_prior_events_without_partial_next_row() {
        let mut config = no_field_config();
        config.set_label(true);
        let first = SampleEvent::new(
            SampleResult::new("a"),
            "run",
            ThreadIdentity::new("thread"),
            "host",
            VariableSnapshot::new(),
        );
        let second = SampleEvent::new(
            SampleResult::new("b"),
            "run",
            ThreadIdentity::new("thread"),
            "host",
            VariableSnapshot::new(),
        );
        let limits = JtlLimits {
            max_output_bytes: 2,
            ..JtlLimits::default()
        };
        let mut encoder = CsvEncoder::new(Vec::new(), config)
            .expect("encoder")
            .with_limits(limits)
            .expect("limits");
        encoder.write_event(&first).expect("first event");
        assert!(matches!(
            encoder.write_event(&second),
            Err(JtlError::Unsupported {
                feature: "output-limit",
                ..
            })
        ));
        let output = encoder.finish().expect("finish");
        assert_eq!(output, b"a\n");
    }

    #[test]
    fn response_file_reference_is_retained_without_filesystem_access() {
        let mut config = no_field_config();
        config.set_filename(true);
        let result = CsvDecoder::new(b"/tmp/result.bin\n".as_slice(), config)
            .expect("decoder")
            .decode_all();
        let events = result.expect("decode");
        assert_eq!(events[0].result().response_file(), Some("/tmp/result.bin"));
    }

    #[test]
    fn response_data_switches_are_rejected_for_csv_instead_of_dropped() {
        let mut config = SampleSaveConfiguration::csv();
        config.set_response_data(true);
        assert!(matches!(
            CsvEncoder::new(Vec::new(), config.clone()),
            Err(JtlError::Unsupported {
                feature: "csv-response-data",
                ..
            })
        ));
        assert!(matches!(
            CsvDecoder::new(b"".as_slice(), config),
            Err(JtlError::Unsupported {
                feature: "csv-response-data",
                ..
            })
        ));

        let mut config = SampleSaveConfiguration::csv();
        config.set_response_data_on_error(true);
        assert!(matches!(
            CsvEncoder::new(Vec::new(), config),
            Err(JtlError::Unsupported {
                feature: "csv-response-data",
                ..
            })
        ));
    }

    #[test]
    fn subresult_renaming_is_configurable_and_iterative() {
        let mut root = SampleResult::new("root");
        root.add_sub_result(
            SampleResult::new("first"),
            crate::ValidationLimits::default(),
        )
        .expect("first");
        root.add_sub_result(
            SampleResult::new("second"),
            crate::ValidationLimits::default(),
        )
        .expect("second");
        let event = SampleEvent::new(
            root,
            "run",
            ThreadIdentity::new("thread"),
            "host",
            VariableSnapshot::new(),
        );
        let mut config = no_field_config();
        config.set_label(true);
        let mut output = Vec::new();
        let mut writer = CsvEncoder::new(&mut output, config.clone()).expect("writer");
        writer.write_event(&event).expect("write");
        writer.finish().expect("finish");
        let labels = String::from_utf8(output).expect("UTF-8");
        assert_eq!(
            labels.lines().collect::<Vec<_>>(),
            ["root", "root-0", "root-1"]
        );

        config.set_subresults_disable_renaming(true);
        let mut output = Vec::new();
        let mut writer = CsvEncoder::new(&mut output, config).expect("writer");
        writer.write_event(&event).expect("write");
        writer.finish().expect("finish");
        let labels = String::from_utf8(output).expect("UTF-8");
        assert_eq!(
            labels.lines().collect::<Vec<_>>(),
            ["root", "first", "second"]
        );
    }

    #[test]
    fn nested_csv_variables_use_the_same_event_scope_as_jmeter() {
        let mut root = SampleResult::new("root");
        root.add_sub_result(
            SampleResult::new("child"),
            crate::ValidationLimits::default(),
        )
        .expect("child");
        let mut variables = VariableSnapshot::new();
        variables.insert("shared", "root-value");
        let event = SampleEvent::new(
            root,
            "run",
            ThreadIdentity::new("thread"),
            "host",
            variables,
        );
        let mut configuration = no_field_config();
        configuration.set_label(true);
        configuration
            .set_sample_variables(["shared"])
            .expect("variables");
        let mut output = Vec::new();
        let mut encoder = CsvEncoder::new(&mut output, configuration).expect("encoder");
        encoder.write_event(&event).expect("write");
        let output = String::from_utf8(encoder.finish().expect("finish").to_vec()).expect("UTF-8");
        let rows = output.lines().collect::<Vec<_>>();
        assert_eq!(rows, ["root,root-value", "root-0,root-value"]);
    }
}
