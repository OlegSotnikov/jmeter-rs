// SPDX-License-Identifier: Apache-2.0
//! Bounded JTL XML 1.2 codec.
//!
//! This module implements the small, fixed vocabulary used by JMeter's
//! `SampleResultConverter` directly.  It intentionally does not resolve
//! entities, dereference URLs, or read `responseFile`: parsing a result file
//! is a pure operation and file access belongs to an explicit caller
//! capability.
//!
//! Decoding is driven directly from the caller's [`Read`] implementation.  A
//! decoder retains only the current bounded token, hierarchy frames, and the
//! event currently being yielded; it does not first materialize the complete
//! input or event list.

use std::borrow::Borrow;
use std::collections::VecDeque;
use std::io::{Read, Write};

use crate::jtl::{
    CsvField, JtlError, JtlLimits, MAX_DECODE_ALL_EVENTS, SampleSaveConfiguration,
    XmlSampleElement, escape_xml, parse_bool, parse_xml_optional_i64, parse_xml_optional_u64,
    response_text_bytes, sanitize_xml_attribute_name, timing_from_wire, validate_xml_characters,
};
use crate::result::{XmlOpaqueChild, XmlOpaquePart};
use crate::{
    AssertionResult, DataEncoding, DataType, HeaderBlock, HostIdentity, SampleEvent, SampleResult,
    ThreadIdentity, VariableSnapshot,
};

const ROOT_NAME: &str = "testResults";

/// A bounded XML result writer.
pub struct XmlEncoder<W> {
    writer: W,
    configuration: SampleSaveConfiguration,
    limits: JtlLimits,
    started: bool,
    finished: bool,
    /// Number of XML elements already emitted, including the root element.
    node_count: usize,
    /// Number of root sample events already emitted.
    written_samples: usize,
    root_metadata_written: bool,
    /// Aggregate bytes already emitted, including declaration and root.
    output_bytes: usize,
}

struct XmlWriteFrame<'a> {
    result: &'a SampleResult,
    depth: usize,
    label_override: Option<String>,
    element: XmlSampleElement,
    next_child: usize,
    opened: bool,
    payload_written: bool,
}

/// Compatibility name for [`XmlEncoder`].
pub type XmlWriter<W> = XmlEncoder<W>;

impl<W: Write> XmlEncoder<W> {
    /// Creates an encoder and validates its configuration.
    pub fn new(writer: W, configuration: SampleSaveConfiguration) -> Result<Self, JtlError> {
        configuration.validate()?;
        Ok(Self {
            writer,
            configuration,
            limits: JtlLimits::default(),
            started: false,
            finished: false,
            node_count: 0,
            written_samples: 0,
            root_metadata_written: false,
            output_bytes: 0,
        })
    }

    /// Replaces hierarchy and output bounds.
    pub fn with_limits(mut self, limits: JtlLimits) -> Result<Self, JtlError> {
        limits.validate()?;
        self.limits = limits;
        Ok(self)
    }

    /// Returns the configuration used by this writer.
    pub fn configuration(&self) -> &SampleSaveConfiguration {
        &self.configuration
    }

    /// Writes the XML declaration and root start tag once.
    pub fn write_header(&mut self) -> Result<(), JtlError> {
        if self.started {
            return Ok(());
        }
        let mut staged = XmlEncoder::new(Vec::new(), self.configuration.clone())?;
        staged.limits = self.limits;
        staged.output_bytes = self.output_bytes;
        staged.write_header_with_attributes(&[])?;
        let bytes = staged.writer;
        self.commit_bytes(&bytes, "write XML header")?;
        self.started = staged.started;
        self.node_count = staged.node_count;
        self.output_bytes = staged.output_bytes;
        Ok(())
    }

    fn write_header_with_attributes(
        &mut self,
        root_attributes: &[(String, String)],
    ) -> Result<(), JtlError> {
        if self.started {
            if !root_attributes.is_empty() {
                // Once the root start tag is published there is no XML-safe
                // place to append attributes.  Returning a typed error keeps
                // a public `write_header` call from silently dropping root
                // metadata supplied by the first event.
                return Err(JtlError::Unsupported {
                    feature: "xml-root-attributes-after-header",
                    value: format!(
                        "{} root attributes cannot be emitted after the header",
                        root_attributes.len()
                    ),
                });
            }
            return Ok(());
        }
        let root_attribute_count =
            root_attributes
                .len()
                .checked_add(1)
                .ok_or_else(|| JtlError::Unsupported {
                    feature: "xml-attribute-limit",
                    value: "root attribute count overflow".to_owned(),
                })?;
        if root_attribute_count > self.limits.max_attributes {
            return Err(JtlError::Unsupported {
                feature: "xml-attribute-limit",
                value: format!(
                    "{root_attribute_count} attributes exceeds {}",
                    self.limits.max_attributes
                ),
            });
        }
        let line_ending = self.line_ending();
        let header = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>{line_ending}");
        self.ensure_output_bound(header.len())?;
        let mut root = String::from("<testResults version=\"1.2\"");
        for (name, value) in root_attributes {
            if !crate::jtl::is_xml_name(name) || name == "version" {
                return Err(JtlError::Unsupported {
                    feature: "xml-root-attribute",
                    value: name.clone(),
                });
            }
            validate_xml_characters(value)?;
            root.push(' ');
            root.push_str(name);
            root.push_str("=\"");
            root.push_str(&escape_xml(value, true));
            root.push('"');
        }
        root.push('>');
        root.push_str(line_ending);
        // Validate the complete header before committing either declaration
        // or root. This keeps public header writes resource/validation atomic.
        self.ensure_output_bound(root.len())?;
        let mut bytes = Vec::with_capacity(header.len().saturating_add(root.len()));
        bytes.extend_from_slice(header.as_bytes());
        bytes.extend_from_slice(root.as_bytes());
        self.write_bytes(&bytes, "write XML header")?;
        self.started = true;
        self.node_count = 1;
        Ok(())
    }

    /// Writes one event and all nested sample results.
    pub fn write_event(&mut self, event: &SampleEvent) -> Result<(), JtlError> {
        event
            .validate_wire(
                crate::ValidationLimits::new(self.limits.max_depth, self.limits.max_nodes)
                    .map_err(|_| JtlError::InvalidConfiguration {
                        field: "limits",
                        detail: "invalid hierarchy limits".to_owned(),
                    })?,
            )
            .map_err(JtlError::from)?;
        if self.written_samples >= self.limits.max_samples {
            return Err(JtlError::Unsupported {
                feature: "xml-sample-limit",
                value: format!(
                    "{} root samples exceeds {}",
                    self.written_samples + 1,
                    self.limits.max_samples
                ),
            });
        }

        // Render the complete root event into a bounded scratch sink. XML
        // output is hierarchical, so validating a child only after its
        // parent has been written would otherwise publish a partial event.
        let mut staged = XmlEncoder::new(Vec::new(), self.configuration.clone())?;
        staged.limits = self.limits;
        staged.started = self.started;
        staged.finished = self.finished;
        staged.node_count = self.node_count;
        staged.written_samples = self.written_samples;
        staged.root_metadata_written = self.root_metadata_written;
        staged.output_bytes = self.output_bytes;
        staged.write_event_parts(event)?;
        let bytes = staged.writer;
        self.commit_bytes(&bytes, "write XML event")?;
        self.started = staged.started;
        self.finished = staged.finished;
        self.node_count = staged.node_count;
        self.written_samples = staged.written_samples;
        self.root_metadata_written = staged.root_metadata_written;
        self.output_bytes = staged.output_bytes;
        if self.configuration.autoflush() {
            self.writer.flush().map_err(|error| JtlError::Io {
                operation: "flush XML output",
                message: error.to_string(),
            })?;
        }
        Ok(())
    }

    fn write_event_parts(&mut self, event: &SampleEvent) -> Result<(), JtlError> {
        event
            .validate_wire(
                crate::ValidationLimits::new(self.limits.max_depth, self.limits.max_nodes)
                    .map_err(|_| JtlError::InvalidConfiguration {
                        field: "limits",
                        detail: "invalid hierarchy limits".to_owned(),
                    })?,
            )
            .map_err(JtlError::from)?;
        if self.written_samples >= self.limits.max_samples {
            return Err(JtlError::Unsupported {
                feature: "xml-sample-limit",
                value: format!(
                    "{} root samples exceeds {}",
                    self.written_samples + 1,
                    self.limits.max_samples
                ),
            });
        }
        let result_stats = xml_result_node_stats(
            event.result(),
            self.configuration.save_subresults(),
            self.configuration.assertion_results(),
            &self.configuration,
        )?;
        let root_before_stats = opaque_node_stats(event.result().wire_xml_root_children(), 2)?;
        let root_after_stats = opaque_node_stats(event.result().wire_xml_root_children_after(), 2)?;
        let root_extra = root_before_stats
            .nodes
            .checked_add(root_after_stats.nodes)
            .ok_or_else(|| JtlError::Unsupported {
                feature: "xml-node-limit",
                value: "node count overflow".to_owned(),
            })?;
        let base_nodes = if self.started { self.node_count } else { 1 };
        let total_nodes = base_nodes
            .checked_add(root_extra)
            .ok_or_else(|| JtlError::Unsupported {
                feature: "xml-node-limit",
                value: "node count overflow".to_owned(),
            })?
            .checked_add(result_stats.nodes)
            .ok_or_else(|| JtlError::Unsupported {
                feature: "xml-node-limit",
                value: "node count overflow".to_owned(),
            })?;
        if total_nodes > self.limits.max_nodes {
            return Err(JtlError::Unsupported {
                feature: "xml-node-limit",
                value: format!("{total_nodes} nodes exceeds {}", self.limits.max_nodes),
            });
        }
        let max_depth = result_stats
            .max_depth
            .max(root_before_stats.max_depth)
            .max(root_after_stats.max_depth);
        if max_depth > self.limits.max_depth {
            return Err(JtlError::Unsupported {
                feature: "xml-depth-limit",
                value: format!("depth {max_depth} exceeds {}", self.limits.max_depth),
            });
        }
        self.write_header_with_attributes(event.result().wire_xml_root_attributes())?;
        if !self.root_metadata_written {
            self.root_metadata_written = true;
        }
        if !event.result().wire_xml_root_children().is_empty() {
            self.write_opaque_children(event.result().wire_xml_root_children(), 2)?;
        }
        self.write_sample_tree(event, event.result())?;
        if !event.result().wire_xml_root_children_after().is_empty() {
            self.write_opaque_children(event.result().wire_xml_root_children_after(), 2)?;
        }
        self.written_samples += 1;
        Ok(())
    }

    /// Writes one result with empty event metadata.
    pub fn write_result(&mut self, result: &SampleResult) -> Result<(), JtlError> {
        let event = SampleEvent::new(
            result.clone(),
            "",
            ThreadIdentity::new(""),
            "",
            VariableSnapshot::new(),
        );
        self.write_event(&event)
    }

    /// Closes the root, flushes, and returns the underlying writer.
    pub fn finish(mut self) -> Result<W, JtlError> {
        if !self.finished {
            let mut staged = XmlEncoder::new(Vec::new(), self.configuration.clone())?;
            staged.limits = self.limits;
            staged.started = self.started;
            staged.node_count = self.node_count;
            staged.written_samples = self.written_samples;
            staged.root_metadata_written = self.root_metadata_written;
            staged.output_bytes = self.output_bytes;
            staged.write_header_with_attributes(&[])?;
            let closing = format!("</testResults>{}", staged.line_ending());
            staged.ensure_output_bound(closing.len())?;
            staged.write_bytes(&closing.into_bytes(), "write XML root close")?;
            let bytes = staged.writer;
            self.commit_bytes(&bytes, "write XML finish")?;
            self.started = staged.started;
            self.node_count = staged.node_count;
            self.written_samples = staged.written_samples;
            self.root_metadata_written = staged.root_metadata_written;
            self.output_bytes = staged.output_bytes;
            self.writer.flush().map_err(|error| JtlError::Io {
                operation: "flush XML output",
                message: error.to_string(),
            })?;
            self.finished = true;
        }
        Ok(self.writer)
    }

    /// Returns the writer without closing or flushing it.
    pub fn into_inner(self) -> W {
        self.writer
    }

    fn write_sample_tree(
        &mut self,
        event: &SampleEvent,
        root: &SampleResult,
    ) -> Result<(), JtlError> {
        let mut pending = vec![XmlWriteFrame {
            result: root,
            depth: 2,
            label_override: None,
            element: root
                .wire_xml_sample_element()
                .unwrap_or(self.configuration.xml_sample_element()),
            next_child: 0,
            opened: false,
            payload_written: false,
        }];
        while let Some(frame) = pending.last_mut() {
            if !frame.opened {
                self.reserve_node(frame.depth)?;
                self.write_sample_open(
                    event,
                    frame.result,
                    frame.label_override.as_deref(),
                    frame.element,
                    frame.depth == 2,
                )?;
                let child_depth =
                    frame
                        .depth
                        .checked_add(1)
                        .ok_or_else(|| JtlError::Unsupported {
                            feature: "xml-depth-limit",
                            value: "depth overflow".to_owned(),
                        })?;
                self.write_sample_assertions(frame.result, child_depth)?;
                frame.opened = true;
                continue;
            }

            if self.configuration.save_subresults()
                && frame.next_child < frame.result.sub_results().len()
            {
                let index = frame.next_child;
                frame.next_child += 1;
                let child = &frame.result.sub_results()[index];
                let child_label = if self.configuration.subresults_disable_renaming() {
                    None
                } else {
                    let parent_label = frame
                        .label_override
                        .as_deref()
                        .unwrap_or_else(|| frame.result.label());
                    Some(format!("{parent_label}-{index}"))
                };
                let depth = frame
                    .depth
                    .checked_add(1)
                    .ok_or_else(|| JtlError::Unsupported {
                        feature: "xml-depth-limit",
                        value: "depth overflow".to_owned(),
                    })?;
                pending.push(XmlWriteFrame {
                    result: child,
                    depth,
                    label_override: child_label,
                    element: child
                        .wire_xml_sample_element()
                        .unwrap_or(self.configuration.xml_sample_element()),
                    next_child: 0,
                    opened: false,
                    payload_written: false,
                });
                continue;
            }

            if !frame.payload_written {
                let child_depth =
                    frame
                        .depth
                        .checked_add(1)
                        .ok_or_else(|| JtlError::Unsupported {
                            feature: "xml-depth-limit",
                            value: "depth overflow".to_owned(),
                        })?;
                self.write_sample_payload(frame.result, child_depth)?;
                frame.payload_written = true;
                continue;
            }

            let closing_name = match frame.element {
                XmlSampleElement::Sample => "sample",
                XmlSampleElement::HttpSample => "httpSample",
            };
            let closing = format!("</{closing_name}>{}", self.line_ending());
            self.ensure_output_bound(closing.len())?;
            self.write_bytes(closing.as_bytes(), "write XML sample close")?;
            pending.pop();
        }
        Ok(())
    }

    fn write_sample_open(
        &mut self,
        event: &SampleEvent,
        result: &SampleResult,
        label_override: Option<&str>,
        element: XmlSampleElement,
        allow_event_variables: bool,
    ) -> Result<(), JtlError> {
        let attribute_count =
            sample_attribute_count(&self.configuration, event, result, allow_event_variables);
        if attribute_count > self.limits.max_attributes {
            return Err(JtlError::Unsupported {
                feature: "xml-attribute-limit",
                value: format!(
                    "{} attributes exceeds {}",
                    attribute_count, self.limits.max_attributes
                ),
            });
        }
        let name = match element {
            XmlSampleElement::Sample => "sample",
            XmlSampleElement::HttpSample => "httpSample",
        };
        let mut output = String::new();
        output.push('<');
        output.push_str(name);
        let attr = |output: &mut String, key: &str, value: &str| {
            output.push(' ');
            output.push_str(key);
            output.push_str("=\"");
            output.push_str(&escape_xml(value, true));
            output.push('"');
        };
        if self.configuration.saves(CsvField::Elapsed) {
            attr(
                &mut output,
                "t",
                &result
                    .elapsed()
                    .map(|value| value.as_millis())
                    .unwrap_or(0)
                    .to_string(),
            );
        }
        if self.configuration.saves(CsvField::IdleTime) {
            attr(
                &mut output,
                "it",
                &result
                    .idle_time()
                    .map(|value| value.as_millis())
                    .unwrap_or(0)
                    .to_string(),
            );
        }
        if self.configuration.saves(CsvField::Latency) {
            attr(
                &mut output,
                "lt",
                &result
                    .latency()
                    .map(|value| value.as_millis())
                    .unwrap_or(0)
                    .to_string(),
            );
        }
        if self.configuration.saves(CsvField::Connect) {
            attr(
                &mut output,
                "ct",
                &result
                    .connect_time()
                    .map(|value| value.as_millis())
                    .unwrap_or(0)
                    .to_string(),
            );
        }
        // XML save-service output always writes milliseconds when timestamps
        // are enabled.  CSV's timestamp_format must not suppress or format
        // this XML attribute.
        if self.configuration.save_timestamp() {
            let timestamp = if self.configuration.timestamp_start() {
                result.start_time().or_else(|| result.timestamp())
            } else {
                result.end_time().or_else(|| result.timestamp())
            };
            attr(
                &mut output,
                "ts",
                &timestamp
                    .map(|value| value.as_millis())
                    .unwrap_or(0)
                    .to_string(),
            );
        }
        if self.configuration.saves(CsvField::Success) {
            attr(
                &mut output,
                "s",
                &result.success().unwrap_or(true).to_string(),
            );
        }
        if self.configuration.saves(CsvField::Label) {
            attr(
                &mut output,
                "lb",
                label_override.unwrap_or_else(|| result.label()),
            );
        }
        if self.configuration.saves(CsvField::ResponseCode) {
            attr(
                &mut output,
                "rc",
                result.response_code().unwrap_or_default(),
            );
        }
        if self.configuration.saves(CsvField::ResponseMessage) {
            attr(
                &mut output,
                "rm",
                result.response_message().unwrap_or_default(),
            );
        }
        if self.configuration.saves(CsvField::ThreadName) {
            let value = match result.wire_xml_sample_element() {
                // Parsed XML samples retain whether `tn` was present.  Do
                // not synthesize an attribute for an absent wire value.
                Some(_) => result.wire_thread_name(),
                // Runtime-created results have no wire metadata and use the
                // event identity as the normal JTL output value.
                None => Some(event.thread().name()),
            };
            if let Some(value) = value {
                attr(&mut output, "tn", value);
            }
        }
        if self.configuration.saves(CsvField::DataType) {
            attr(
                &mut output,
                "dt",
                result
                    .data_type()
                    .map(ToString::to_string)
                    .as_deref()
                    .unwrap_or("text"),
            );
        }
        if self.configuration.saves(CsvField::Encoding)
            && let Some(value) = result
                .data_encoding()
                .map(|value| value.as_str())
                .or_else(|| self.configuration.default_encoding())
        {
            attr(&mut output, "de", value);
        }
        if self.configuration.saves(CsvField::Bytes) {
            attr(
                &mut output,
                "by",
                &result
                    .received_bytes()
                    .map(|value| value.as_u64())
                    .unwrap_or(0)
                    .to_string(),
            );
        }
        if self.configuration.saves(CsvField::SentBytes) {
            attr(
                &mut output,
                "sby",
                &result
                    .sent_bytes()
                    .map(|value| value.as_u64())
                    .unwrap_or(0)
                    .to_string(),
            );
        }
        if self.configuration.saves(CsvField::SampleCount) {
            attr(
                &mut output,
                "sc",
                &result
                    .sample_count()
                    .map(|value| value.as_u64())
                    .unwrap_or(1)
                    .to_string(),
            );
        }
        if self.configuration.saves(CsvField::ErrorCount) {
            attr(
                &mut output,
                "ec",
                &result
                    .error_count()
                    .map(|value| value.as_u64())
                    .unwrap_or(0)
                    .to_string(),
            );
        }
        if self.configuration.saves(CsvField::GroupThreads) {
            attr(
                &mut output,
                "ng",
                &result
                    .group_threads()
                    .map(|value| value.as_u64())
                    .unwrap_or(0)
                    .to_string(),
            );
            attr(
                &mut output,
                "na",
                &result
                    .all_threads()
                    .map(|value| value.as_u64())
                    .unwrap_or(0)
                    .to_string(),
            );
        }
        if self.configuration.saves(CsvField::Hostname) {
            let value = match result.wire_xml_sample_element() {
                // As with `tn`, retain absent versus present-empty `hn`.
                Some(_) => result.wire_host(),
                None => Some(event.host().as_str()),
            };
            if let Some(value) = value {
                attr(&mut output, "hn", value);
            }
        }
        for variable in self.configuration.sample_variables() {
            // JMeter 5.6.3 writes configured sample-variable names exactly as
            // supplied.  The decoder still accepts the doubled-underscore
            // spelling used by an older Rust extension variant, but that
            // compatibility alias must not be emitted by the JTL writer.
            if !crate::jtl::is_xml_name(variable) {
                return Err(JtlError::InvalidConfiguration {
                    field: "sample_variables",
                    detail: format!("invalid XML attribute name {variable:?}"),
                });
            }
            let value = sample_variable_value(event, result, variable, allow_event_variables);
            if let Some(value) = value {
                attr(&mut output, variable, value);
            }
        }
        for (name, value) in result.wire_xml_attributes() {
            if !crate::jtl::is_xml_name(name) {
                return Err(JtlError::Unsupported {
                    feature: "xml-sample-attribute",
                    value: name.clone(),
                });
            }
            validate_xml_characters(value)?;
            attr(&mut output, name, value);
        }
        output.push('>');
        output.push_str(self.line_ending());
        validate_xml_characters(&output)?;
        self.ensure_output_bound(output.len())?;
        self.write_bytes(output.as_bytes(), "write XML sample open")
    }

    fn ensure_output_bound(&self, length: usize) -> Result<(), JtlError> {
        if length > self.limits.max_record_bytes {
            return Err(JtlError::Unsupported {
                feature: "xml-record-limit",
                value: format!(
                    "{} output bytes exceeds {}",
                    length, self.limits.max_record_bytes
                ),
            });
        }
        Ok(())
    }

    fn write_bytes(&mut self, bytes: &[u8], operation: &'static str) -> Result<(), JtlError> {
        self.ensure_output_bound(bytes.len())?;
        self.commit_bytes(bytes, operation)
    }

    /// Publishes bytes that were rendered and record-validated in a scratch
    /// encoder.  The aggregate bound still applies, but the combined event
    /// may contain many individually valid XML fragments whose total size is
    /// larger than `max_record_bytes`.
    fn commit_bytes(&mut self, bytes: &[u8], operation: &'static str) -> Result<(), JtlError> {
        let total =
            self.output_bytes
                .checked_add(bytes.len())
                .ok_or_else(|| JtlError::Unsupported {
                    feature: "output-limit",
                    value: "aggregate output length overflow".to_owned(),
                })?;
        if total > self.limits.max_output_bytes {
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

    fn reserve_node(&mut self, depth: usize) -> Result<(), JtlError> {
        if depth > self.limits.max_depth {
            return Err(JtlError::Unsupported {
                feature: "xml-depth-limit",
                value: format!("depth {depth} exceeds {}", self.limits.max_depth),
            });
        }
        self.node_count = self
            .node_count
            .checked_add(1)
            .ok_or_else(|| JtlError::Unsupported {
                feature: "xml-node-limit",
                value: "node count overflow".to_owned(),
            })?;
        if self.node_count > self.limits.max_nodes {
            return Err(JtlError::Unsupported {
                feature: "xml-node-limit",
                value: format!(
                    "{} nodes exceeds {}",
                    self.node_count, self.limits.max_nodes
                ),
            });
        }
        Ok(())
    }

    fn write_sample_assertions(
        &mut self,
        result: &SampleResult,
        depth: usize,
    ) -> Result<(), JtlError> {
        if !matches!(
            self.configuration.assertion_results(),
            crate::AssertionResults::None
        ) {
            let count = match self.configuration.assertion_results() {
                crate::AssertionResults::None => 0,
                crate::AssertionResults::First => result.assertions().len().min(1),
                crate::AssertionResults::All => result.assertions().len(),
            };
            for assertion in result.assertions().iter().take(count) {
                self.write_assertion(assertion, depth)?;
            }
        }
        Ok(())
    }

    fn write_sample_payload(
        &mut self,
        result: &SampleResult,
        depth: usize,
    ) -> Result<(), JtlError> {
        if self.configuration.save_response_headers() {
            self.write_text_element(
                "responseHeader",
                result
                    .response_headers()
                    .map(HeaderBlock::as_str)
                    .unwrap_or_default(),
                true,
                depth,
            )?;
        }
        if self.configuration.save_request_headers() {
            self.write_text_element(
                "requestHeader",
                result
                    .request_headers()
                    .map(HeaderBlock::as_str)
                    .unwrap_or_default(),
                true,
                depth,
            )?;
        }
        if self
            .configuration
            .should_save_response_data(result.success())
        {
            if matches!(result.data_type(), Some(DataType::Binary))
                && result.response_data().is_some_and(|data| !data.is_empty())
            {
                return Err(JtlError::Unsupported {
                    feature: "xml-binary-response-data",
                    value: "binary responseData requires an explicit binary adapter".to_owned(),
                });
            }
            let value = match result.response_data() {
                Some(data) => std::str::from_utf8(data.as_bytes()).map_err(|_| {
                    JtlError::Unsupported {
                        feature: "xml-binary-response-data",
                        value: "responseData is not valid UTF-8; use responseFile or an explicit binary adapter".to_owned(),
                    }
                })?,
                None => "",
            };
            self.write_text_element("responseData", value, true, depth)?;
        }
        if self.configuration.save_file_name() {
            self.write_text_element(
                "responseFile",
                result.response_file().unwrap_or_default(),
                true,
                depth,
            )?;
        }
        if self.configuration.save_sampler_data()
            && let Some(value) = result.sampler_data()
        {
            self.write_text_element("samplerData", value, true, depth)?;
        }
        if self.configuration.save_url()
            && let Some(value) = result.url()
        {
            self.write_text_element("java.net.URL", value, false, depth)?;
        }
        self.write_opaque_children(result.wire_xml_children(), depth)?;
        Ok(())
    }

    fn write_opaque_children(
        &mut self,
        children: &[XmlOpaqueChild],
        initial_depth: usize,
    ) -> Result<(), JtlError> {
        struct Frame<'a> {
            node: &'a XmlOpaqueChild,
            next: usize,
            opened: bool,
            depth: usize,
        }
        let mut pending = children
            .iter()
            .rev()
            .map(|node| Frame {
                node,
                next: 0,
                opened: false,
                depth: initial_depth,
            })
            .collect::<Vec<_>>();
        while let Some(frame) = pending.last_mut() {
            if !frame.opened {
                self.reserve_node(frame.depth)?;
                if frame.node.attributes.len() > self.limits.max_attributes {
                    return Err(JtlError::Unsupported {
                        feature: "xml-attribute-limit",
                        value: format!(
                            "{} attributes exceeds {}",
                            frame.node.attributes.len(),
                            self.limits.max_attributes
                        ),
                    });
                }
                let mut output = String::new();
                output.push('<');
                output.push_str(&frame.node.name);
                for (name, value) in &frame.node.attributes {
                    if !crate::jtl::is_xml_name(name) {
                        return Err(JtlError::Unsupported {
                            feature: "xml-attribute",
                            value: name.clone(),
                        });
                    }
                    validate_xml_characters(value)?;
                    output.push(' ');
                    output.push_str(name);
                    output.push_str("=\"");
                    output.push_str(&escape_xml(value, true));
                    output.push('\"');
                }
                if frame.node.content.is_empty() {
                    output.push_str("/>");
                    output.push_str(self.line_ending());
                    self.ensure_output_bound(output.len())?;
                    self.write_bytes(output.as_bytes(), "write XML opaque child")?;
                    pending.pop();
                } else {
                    output.push('>');
                    output.push_str(self.line_ending());
                    self.ensure_output_bound(output.len())?;
                    self.write_bytes(output.as_bytes(), "write XML opaque child")?;
                    frame.opened = true;
                }
                continue;
            }
            if frame.next < frame.node.content.len() {
                let part = &frame.node.content[frame.next];
                frame.next += 1;
                match part {
                    XmlOpaquePart::Text(value) => {
                        validate_xml_characters(value)?;
                        let output = escape_xml(value, false);
                        self.ensure_output_bound(output.len())?;
                        self.write_bytes(output.as_bytes(), "write XML opaque text")?;
                    }
                    XmlOpaquePart::Child(child) => {
                        let depth =
                            frame
                                .depth
                                .checked_add(1)
                                .ok_or_else(|| JtlError::Unsupported {
                                    feature: "xml-depth-limit",
                                    value: "depth overflow".to_owned(),
                                })?;
                        pending.push(Frame {
                            node: child,
                            next: 0,
                            opened: false,
                            depth,
                        });
                    }
                }
            } else {
                let output = format!("</{}>{}", frame.node.name, self.line_ending());
                self.ensure_output_bound(output.len())?;
                self.write_bytes(output.as_bytes(), "write XML opaque close")?;
                pending.pop();
            }
        }
        Ok(())
    }

    fn write_assertion(
        &mut self,
        assertion: &AssertionResult,
        depth: usize,
    ) -> Result<(), JtlError> {
        self.reserve_node(depth)?;
        if assertion.wire_xml_attributes().len() > self.limits.max_attributes {
            return Err(JtlError::Unsupported {
                feature: "xml-attribute-limit",
                value: format!(
                    "{} attributes exceeds {}",
                    assertion.wire_xml_attributes().len(),
                    self.limits.max_attributes
                ),
            });
        }
        validate_xml_characters(assertion.name())?;
        if let Some(value) = assertion.failure_message() {
            validate_xml_characters(value)?;
        }
        if let Some(value) = assertion.error_message() {
            validate_xml_characters(value)?;
        }
        let child_depth = depth.checked_add(1).ok_or_else(|| JtlError::Unsupported {
            feature: "xml-depth-limit",
            value: "depth overflow".to_owned(),
        })?;
        let mut output = String::from("<assertionResult");
        for (name, value) in assertion.wire_xml_attributes() {
            if !crate::jtl::is_xml_name(name) {
                return Err(JtlError::Unsupported {
                    feature: "xml-attribute",
                    value: name.clone(),
                });
            }
            validate_xml_characters(value)?;
            output.push(' ');
            output.push_str(name);
            output.push_str("=\"");
            output.push_str(&escape_xml(value, true));
            output.push('"');
        }
        output.push('>');
        output.push_str(self.line_ending());
        for _ in 0..3 {
            self.reserve_node(child_depth)?;
        }
        if assertion.failure_message().is_some() {
            self.reserve_node(child_depth)?;
        }
        if assertion.error_message().is_some() {
            self.reserve_node(child_depth)?;
        }
        write_text_to_with_class(
            &mut output,
            "name",
            assertion.name(),
            false,
            self.line_ending(),
        );
        write_text_to_with_class(
            &mut output,
            "failure",
            if assertion.is_failure() {
                "true"
            } else {
                "false"
            },
            false,
            self.line_ending(),
        );
        write_text_to_with_class(
            &mut output,
            "error",
            if assertion.is_error() {
                "true"
            } else {
                "false"
            },
            false,
            self.line_ending(),
        );
        // XML assertion messages are independent of the CSV failureMessage
        // column switch.  Preserve both message kinds and their wire order.
        if let Some(value) = assertion.failure_message() {
            write_text_to_with_class(
                &mut output,
                "failureMessage",
                value,
                true,
                self.line_ending(),
            );
        }
        if let Some(value) = assertion.error_message() {
            write_text_to_with_class(&mut output, "errorMessage", value, true, self.line_ending());
        }
        self.ensure_output_bound(output.len())?;
        self.write_bytes(output.as_bytes(), "write XML assertion")?;
        self.write_opaque_children(assertion.wire_xml_children(), child_depth)?;
        let closing = format!("</assertionResult>{}", self.line_ending());
        self.ensure_output_bound(closing.len())?;
        self.write_bytes(closing.as_bytes(), "write XML assertion close")
    }

    fn write_text_element(
        &mut self,
        name: &str,
        value: &str,
        with_class: bool,
        depth: usize,
    ) -> Result<(), JtlError> {
        self.reserve_node(depth)?;
        validate_xml_characters(name)?;
        validate_xml_characters(value)?;
        let mut output = String::new();
        write_text_to_with_class(&mut output, name, value, with_class, self.line_ending());
        self.ensure_output_bound(output.len())?;
        self.write_bytes(output.as_bytes(), "write XML child")
    }

    fn line_ending(&self) -> &'static str {
        self.configuration.line_ending().as_str()
    }
}

fn sample_attribute_count(
    configuration: &SampleSaveConfiguration,
    event: &SampleEvent,
    result: &SampleResult,
    allow_event_variables: bool,
) -> usize {
    let mut count = 0usize;
    for field in [
        CsvField::Elapsed,
        CsvField::IdleTime,
        CsvField::Latency,
        CsvField::Connect,
        CsvField::Success,
        CsvField::Label,
        CsvField::ResponseCode,
        CsvField::ResponseMessage,
        CsvField::ThreadName,
        CsvField::DataType,
        CsvField::Encoding,
        CsvField::Bytes,
        CsvField::SentBytes,
        CsvField::GroupThreads,
        CsvField::AllThreads,
        CsvField::Hostname,
    ] {
        let wire_value_present = match field {
            CsvField::ThreadName => {
                result.wire_xml_sample_element().is_none() || result.wire_thread_name().is_some()
            }
            CsvField::Hostname => {
                result.wire_xml_sample_element().is_none() || result.wire_host().is_some()
            }
            _ => true,
        };
        if configuration.saves(field)
            && wire_value_present
            && (field != CsvField::Encoding
                || result.data_encoding().is_some()
                || configuration.default_encoding().is_some())
        {
            count = count.saturating_add(1);
        }
    }
    if configuration.save_timestamp() {
        count = count.saturating_add(1);
    }
    if configuration.saves(CsvField::SampleCount) {
        count = count.saturating_add(1);
    }
    if configuration.saves(CsvField::ErrorCount) {
        count = count.saturating_add(1);
    }
    count
        .saturating_add(
            configuration
                .sample_variables()
                .iter()
                .filter(|variable| {
                    sample_variable_value(event, result, variable, allow_event_variables).is_some()
                })
                .count(),
        )
        .saturating_add(result.wire_xml_attributes().len())
}

fn sample_variable_value<'a>(
    event: &'a SampleEvent,
    result: &'a SampleResult,
    variable: &str,
    allow_event_variables: bool,
) -> Option<&'a str> {
    if let Some(value) = result.wire_variables().get(variable) {
        return value.as_str();
    }
    if allow_event_variables {
        return event
            .variables()
            .get(variable)
            .and_then(|value| value.as_str());
    }
    None
}

/// A bounded streaming XML decoder exposing parsed events one at a time.
pub struct XmlDecoder<R = std::io::Empty> {
    scanner: XmlStreamScanner<R>,
    stack: Vec<OpenFrame>,
    configuration: XmlDecodeConfiguration,
    limits: JtlLimits,
    saw_root: bool,
    node_count: usize,
    yielded: usize,
    finished: bool,
    /// One-event lookahead lets root-level opaque children appearing after a
    /// sample be attached to the preceding event before it is yielded.  This
    /// keeps the decoder streaming while avoiding silent extension loss.
    pending_event: Option<SampleEvent>,
}

/// Input-side XML policy for sample-variable attributes and extensions.
///
/// The decoder accepts exact configured variable names and the doubled-
/// underscore spelling used by an older Rust extension variant.  It cannot
/// safely infer the original name from an arbitrary attribute, because that
/// transform is not injective over unknown plugin attributes.  Unknown
/// attributes are preserved opaquely by default; callers that need a strict
/// schema can explicitly enable rejection.
#[derive(Clone, Default, Eq, Hash, PartialEq)]
pub struct XmlDecodeConfiguration {
    sample_variables: Vec<String>,
    reject_unknown_attributes: bool,
}

impl std::fmt::Debug for XmlDecodeConfiguration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("XmlDecodeConfiguration")
            .field("sample_variable_count", &self.sample_variables.len())
            .field("reject_unknown_attributes", &self.reject_unknown_attributes)
            .finish()
    }
}

impl XmlDecodeConfiguration {
    /// Creates a decoder policy with no configured sample variables.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns configured variable names in wire-decoding order.
    pub fn sample_variables(&self) -> &[String] {
        &self.sample_variables
    }

    /// Replaces configured sample-variable names after validating XML
    /// spellings and collisions.
    pub fn set_sample_variables<I, S>(&mut self, variables: I) -> Result<(), JtlError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut values = Vec::new();
        let mut encoded = Vec::new();
        for variable in variables {
            let variable = variable.into();
            let wire_name = sanitize_xml_attribute_name(&variable)?;
            if [
                "t", "it", "lt", "ct", "ts", "s", "lb", "rc", "rs", "rm", "tn", "dt", "de", "by",
                "sby", "sc", "ec", "ng", "na", "hn",
            ]
            .contains(&wire_name.as_str())
            {
                return Err(JtlError::InvalidConfiguration {
                    field: "xml_sample_variables",
                    detail: format!("variable {variable:?} collides with a sample attribute"),
                });
            }
            if values.iter().any(|existing: &String| {
                existing == &variable
                    || existing == &wire_name
                    || sanitize_xml_attribute_name(existing)
                        .is_ok_and(|encoded| encoded == wire_name)
            }) || encoded
                .iter()
                .any(|existing: &String| existing == &wire_name || *existing == variable)
            {
                return Err(JtlError::InvalidConfiguration {
                    field: "xml_sample_variables",
                    detail: format!("variable name collision for {variable:?}"),
                });
            }
            values.push(variable);
            encoded.push(wire_name);
        }
        self.sample_variables = values;
        Ok(())
    }

    /// Builder-style sample-variable configuration.
    pub fn with_sample_variables<I, S>(mut self, variables: I) -> Result<Self, JtlError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.set_sample_variables(variables)?;
        Ok(self)
    }

    /// Returns whether unconfigured sample attributes are rejected.
    pub const fn reject_unknown_attributes(&self) -> bool {
        self.reject_unknown_attributes
    }

    /// Enables or disables rejection of unconfigured sample attributes.
    /// When disabled, exact wire attributes are retained opaquely.
    pub const fn set_reject_unknown_attributes(&mut self, value: bool) {
        self.reject_unknown_attributes = value;
    }

    /// Builder-style extension policy setter.
    pub const fn with_reject_unknown_attributes(mut self, value: bool) -> Self {
        self.set_reject_unknown_attributes(value);
        self
    }
}

/// Compatibility name for [`XmlDecoder`].
pub type XmlReader<R = std::io::Empty> = XmlDecoder<R>;

impl<R: Read> XmlDecoder<R> {
    /// Creates a streaming decoder over a bounded XML input.
    pub fn new(reader: R, limits: JtlLimits) -> Result<Self, JtlError> {
        Self::with_configuration(reader, limits, XmlDecodeConfiguration::default())
    }

    /// Creates a streaming decoder under an explicit input policy.
    pub fn with_configuration(
        reader: R,
        limits: JtlLimits,
        configuration: XmlDecodeConfiguration,
    ) -> Result<Self, JtlError> {
        limits.validate()?;
        Ok(Self {
            scanner: XmlStreamScanner::new(reader, limits),
            stack: Vec::new(),
            configuration,
            limits,
            saw_root: false,
            node_count: 0,
            yielded: 0,
            finished: false,
            pending_event: None,
        })
    }

    /// Reads XML with configured JMeter sample-variable names.
    pub fn with_sample_variables<I, S>(
        reader: R,
        limits: JtlLimits,
        variables: I,
    ) -> Result<Self, JtlError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let configuration = XmlDecodeConfiguration::default().with_sample_variables(variables)?;
        Self::with_configuration(reader, limits, configuration)
    }

    /// Creates a decoder using default bounds.
    pub fn with_defaults(reader: R) -> Result<Self, JtlError> {
        Self::new(reader, JtlLimits::default())
    }

    /// Returns the next event, reading only as much input as needed.
    pub fn next_event(&mut self) -> Result<Option<SampleEvent>, JtlError> {
        if self.finished {
            return Ok(None);
        }
        loop {
            let token = self.scanner.next()?;
            let Some(token) = token else {
                if !self.stack.is_empty() {
                    return Err(JtlError::Xml {
                        offset: self.scanner.offset,
                        detail: "truncated XML element".to_owned(),
                    });
                }
                if !self.saw_root {
                    return Err(JtlError::Xml {
                        offset: 0,
                        detail: "JTL root testResults is missing".to_owned(),
                    });
                }
                if let Some(event) = self.pending_event.take() {
                    return self.yield_event(event);
                }
                self.finished = true;
                return Ok(None);
            };
            let mut events = Vec::new();
            match token {
                XmlToken::Text(value) => {
                    if value.len() > self.limits.max_record_bytes {
                        return Err(JtlError::Unsupported {
                            feature: "xml-text-limit",
                            value: format!(
                                "{} bytes exceeds {}",
                                value.len(),
                                self.limits.max_record_bytes
                            ),
                        });
                    }
                    if let Some(OpenFrame::Text(frame)) = self.stack.last_mut() {
                        let next = frame.value.len().checked_add(value.len()).ok_or_else(|| {
                            JtlError::Unsupported {
                                feature: "xml-text-limit",
                                value: "text length overflow".to_owned(),
                            }
                        })?;
                        if next > self.limits.max_record_bytes {
                            return Err(JtlError::Unsupported {
                                feature: "xml-text-limit",
                                value: format!(
                                    "{} bytes exceeds {}",
                                    next, self.limits.max_record_bytes
                                ),
                            });
                        }
                        frame.value.push_str(&value);
                    } else if let Some(OpenFrame::Opaque(frame)) = self.stack.last_mut() {
                        frame.node.push_text(value);
                    } else if !value.trim().is_empty() {
                        return Err(JtlError::Xml {
                            offset: self.scanner.offset,
                            detail: "non-whitespace text outside a JTL child".to_owned(),
                        });
                    }
                }
                XmlToken::Start {
                    name,
                    attributes,
                    empty,
                } => {
                    self.node_count =
                        self.node_count
                            .checked_add(1)
                            .ok_or_else(|| JtlError::Unsupported {
                                feature: "xml-node-limit",
                                value: "node count overflow".to_owned(),
                            })?;
                    if self.node_count > self.limits.max_nodes {
                        return Err(JtlError::Unsupported {
                            feature: "xml-node-limit",
                            value: format!(
                                "{} nodes exceeds {}",
                                self.node_count, self.limits.max_nodes
                            ),
                        });
                    }
                    if self.stack.len() + 1 > self.limits.max_depth {
                        return Err(JtlError::Unsupported {
                            feature: "xml-depth-limit",
                            value: format!(
                                "depth {} exceeds {}",
                                self.stack.len() + 1,
                                self.limits.max_depth
                            ),
                        });
                    }
                    start_node(
                        &mut self.stack,
                        &mut events,
                        &mut self.saw_root,
                        name,
                        attributes,
                        empty,
                        self.limits,
                        &self.configuration,
                        self.scanner.offset,
                    )?;
                }
                XmlToken::End(name) => {
                    let root_children = if name == ROOT_NAME
                        && matches!(self.stack.last(), Some(OpenFrame::Root(_)))
                    {
                        match self.stack.last_mut() {
                            Some(OpenFrame::Root(root)) => std::mem::take(&mut root.children),
                            _ => Vec::new(),
                        }
                    } else {
                        Vec::new()
                    };
                    close_node(
                        &mut self.stack,
                        &mut events,
                        &mut self.saw_root,
                        &name,
                        self.limits,
                        self.scanner.offset,
                    )?;
                    if !root_children.is_empty() {
                        let Some(event) = self.pending_event.as_mut() else {
                            return Err(JtlError::Unsupported {
                                feature: "xml-root-extension-without-sample",
                                value:
                                    "root-level XML children cannot be retained without a sample"
                                        .to_owned(),
                            });
                        };
                        // These nodes occur after the final root sample.  Keep
                        // their position explicit so the writer does not move
                        // them before that sample on a round trip.
                        event.add_wire_xml_root_children_after(root_children);
                    }
                }
            }
            if let Some(event) = events.pop() {
                if let Some(previous) = self.pending_event.replace(event) {
                    return self.yield_event(previous);
                }
            } else if self.stack.is_empty()
                && self.saw_root
                && let Some(event) = self.pending_event.take()
            {
                return self.yield_event(event);
            }
        }
    }

    fn yield_event(&mut self, event: SampleEvent) -> Result<Option<SampleEvent>, JtlError> {
        if self.yielded >= self.limits.max_samples {
            return Err(JtlError::Unsupported {
                feature: "xml-sample-limit",
                value: format!(
                    "{} root samples exceeds {}",
                    self.yielded + 1,
                    self.limits.max_samples
                ),
            });
        }
        self.yielded += 1;
        Ok(Some(event))
    }

    /// Returns the parsed root events as a bounded collection.
    ///
    /// This convenience method has a hard event-count cap.  Use
    /// [`Self::next_event`] for a caller-owned streaming sink.
    pub fn decode_all(self) -> Result<Vec<SampleEvent>, JtlError> {
        self.decode_all_with_limit(MAX_DECODE_ALL_EVENTS)
    }

    /// Decodes at most `maximum_events` root events into a collection.
    ///
    /// The caller may choose a lower bound, but cannot raise the crate-wide
    /// hard cap.  Input, XML depth, node, and sample limits continue to apply
    /// independently.
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
}

impl<R: Read> Iterator for XmlDecoder<R> {
    type Item = Result<SampleEvent, JtlError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_event() {
            Ok(Some(event)) => Some(Ok(event)),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        }
    }
}

/// Encodes an iterator of events as JMeter XML 1.2.
pub fn encode_xml<W, I>(
    writer: W,
    events: I,
    configuration: SampleSaveConfiguration,
) -> Result<W, JtlError>
where
    W: Write,
    I: IntoIterator,
    I::Item: std::borrow::Borrow<SampleEvent>,
{
    let mut encoder = XmlEncoder::new(writer, configuration)?;
    for event in events {
        encoder.write_event(event.borrow())?;
    }
    encoder.finish()
}

/// Decodes bounded JMeter XML 1.2 events.
pub fn decode_xml<R: Read>(reader: R, limits: JtlLimits) -> Result<Vec<SampleEvent>, JtlError> {
    XmlDecoder::new(reader, limits)?.decode_all()
}

/// Decodes XML into a bounded collection with an explicit aggregate event
/// limit.  For unbounded or very large streams, use [`XmlDecoder`] directly
/// and consume [`XmlDecoder::next_event`].
pub fn decode_xml_with_limit<R: Read>(
    reader: R,
    limits: JtlLimits,
    maximum_events: usize,
) -> Result<Vec<SampleEvent>, JtlError> {
    XmlDecoder::new(reader, limits)?.decode_all_with_limit(maximum_events)
}

/// Decodes XML under an explicit input-side policy.
pub fn decode_xml_with_configuration<R: Read>(
    reader: R,
    limits: JtlLimits,
    configuration: XmlDecodeConfiguration,
) -> Result<Vec<SampleEvent>, JtlError> {
    XmlDecoder::with_configuration(reader, limits, configuration)?.decode_all()
}

/// Alias for [`encode_xml`].
pub fn write_xml<W, I>(
    writer: W,
    events: I,
    configuration: SampleSaveConfiguration,
) -> Result<W, JtlError>
where
    W: Write,
    I: IntoIterator,
    I::Item: std::borrow::Borrow<SampleEvent>,
{
    encode_xml(writer, events, configuration)
}

/// Alias for [`decode_xml`].
pub fn read_xml<R: Read>(reader: R, limits: JtlLimits) -> Result<Vec<SampleEvent>, JtlError> {
    decode_xml(reader, limits)
}

fn write_text_to_with_class(
    output: &mut String,
    name: &str,
    value: &str,
    with_class: bool,
    line_ending: &str,
) {
    output.push('<');
    output.push_str(name);
    if with_class {
        output.push_str(" class=\"java.lang.String\"");
    }
    output.push('>');
    output.push_str(&escape_xml(value, false));
    output.push_str("</");
    output.push_str(name);
    output.push('>');
    output.push_str(line_ending);
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct XmlNodeStats {
    nodes: usize,
    max_depth: usize,
}

impl XmlNodeStats {
    fn add_node(&mut self, depth: usize) -> Result<(), JtlError> {
        self.nodes = self
            .nodes
            .checked_add(1)
            .ok_or_else(|| JtlError::Unsupported {
                feature: "xml-node-limit",
                value: "node count overflow".to_owned(),
            })?;
        self.max_depth = self.max_depth.max(depth);
        Ok(())
    }

    fn combine(&mut self, other: Self) -> Result<(), JtlError> {
        self.nodes = self
            .nodes
            .checked_add(other.nodes)
            .ok_or_else(|| JtlError::Unsupported {
                feature: "xml-node-limit",
                value: "node count overflow".to_owned(),
            })?;
        self.max_depth = self.max_depth.max(other.max_depth);
        Ok(())
    }
}

fn xml_result_node_stats(
    result: &SampleResult,
    include_subresults: bool,
    assertion_results: crate::AssertionResults,
    configuration: &SampleSaveConfiguration,
) -> Result<XmlNodeStats, JtlError> {
    let mut stats = XmlNodeStats::default();
    let mut pending = vec![(result, 2usize)];
    while let Some((node, depth)) = pending.pop() {
        stats.add_node(depth)?;
        let child_depth = depth.checked_add(1).ok_or_else(|| JtlError::Unsupported {
            feature: "xml-depth-limit",
            value: "depth overflow".to_owned(),
        })?;

        let assertion_count = match assertion_results {
            crate::AssertionResults::None => 0,
            crate::AssertionResults::First => node.assertions().len().min(1),
            crate::AssertionResults::All => node.assertions().len(),
        };
        for assertion in node.assertions().iter().take(assertion_count) {
            stats.combine(xml_assertion_node_stats(assertion, child_depth)?)?;
        }

        for _ in 0..known_payload_count(configuration, node) {
            stats.add_node(child_depth)?;
        }
        stats.combine(opaque_node_stats(node.wire_xml_children(), child_depth)?)?;

        if include_subresults {
            pending.extend(
                node.sub_results()
                    .iter()
                    .rev()
                    .map(|child| (child, child_depth)),
            );
        }
    }
    Ok(stats)
}

fn xml_assertion_node_stats(
    assertion: &AssertionResult,
    depth: usize,
) -> Result<XmlNodeStats, JtlError> {
    let mut stats = XmlNodeStats::default();
    stats.add_node(depth)?;
    let child_depth = depth.checked_add(1).ok_or_else(|| JtlError::Unsupported {
        feature: "xml-depth-limit",
        value: "depth overflow".to_owned(),
    })?;
    // name, failure, and error are always emitted for a serialized assertion.
    for _ in 0..3 {
        stats.add_node(child_depth)?;
    }
    if assertion.failure_message().is_some() {
        stats.add_node(child_depth)?;
    }
    if assertion.error_message().is_some() {
        stats.add_node(child_depth)?;
    }
    stats.combine(opaque_node_stats(
        assertion.wire_xml_children(),
        child_depth,
    )?)?;
    Ok(stats)
}

fn known_payload_count(configuration: &SampleSaveConfiguration, result: &SampleResult) -> usize {
    let mut count = 0usize;
    if configuration.save_response_headers() {
        count = count.saturating_add(1);
    }
    if configuration.save_request_headers() {
        count = count.saturating_add(1);
    }
    if configuration.should_save_response_data(result.success()) {
        count = count.saturating_add(1);
    }
    if configuration.save_file_name() {
        count = count.saturating_add(1);
    }
    if configuration.save_sampler_data() && result.sampler_data().is_some() {
        count = count.saturating_add(1);
    }
    if configuration.save_url() && result.url().is_some() {
        count = count.saturating_add(1);
    }
    count
}

fn opaque_node_stats(
    children: &[XmlOpaqueChild],
    initial_depth: usize,
) -> Result<XmlNodeStats, JtlError> {
    let mut stats = XmlNodeStats::default();
    let mut pending = children
        .iter()
        .map(|child| (child, initial_depth))
        .collect::<Vec<_>>();
    while let Some((child, depth)) = pending.pop() {
        stats.add_node(depth)?;
        let child_depth = depth.checked_add(1).ok_or_else(|| JtlError::Unsupported {
            feature: "xml-depth-limit",
            value: "depth overflow".to_owned(),
        })?;
        pending.extend(child.content.iter().filter_map(|part| match part {
            XmlOpaquePart::Child(nested) => Some((nested, child_depth)),
            XmlOpaquePart::Text(_) => None,
        }));
    }
    Ok(stats)
}

#[derive(Clone, Debug)]
enum XmlToken {
    Start {
        name: String,
        attributes: Vec<(String, String)>,
        empty: bool,
    },
    End(String),
    Text(String),
}

#[cfg(test)]
#[allow(dead_code)]
struct XmlScanner<'a> {
    input: &'a [u8],
    offset: usize,
    limits: JtlLimits,
}

#[cfg(test)]
#[allow(dead_code)]
impl<'a> XmlScanner<'a> {
    fn new(input: &'a str, limits: JtlLimits) -> Self {
        Self {
            input: input.as_bytes(),
            offset: 0,
            limits,
        }
    }

    fn next(&mut self) -> Result<Option<XmlToken>, JtlError> {
        loop {
            if self.offset >= self.input.len() {
                return Ok(None);
            }
            if self.input[self.offset..].starts_with(b"<!--") {
                self.skip_until(b"-->", "unterminated XML comment")?;
                continue;
            }
            if self.input[self.offset..].starts_with(b"<?") {
                self.skip_until(b"?>", "unterminated XML processing instruction")?;
                continue;
            }
            return self.next_token();
        }
    }

    fn next_token(&mut self) -> Result<Option<XmlToken>, JtlError> {
        if self.offset >= self.input.len() {
            return Ok(None);
        }
        if self.input[self.offset] != b'<' {
            let start = self.offset;
            while self.offset < self.input.len() && self.input[self.offset] != b'<' {
                self.offset += 1;
            }
            let raw = std::str::from_utf8(&self.input[start..self.offset])
                .map_err(|_| self.error("invalid UTF-8 text"))?;
            if !raw.chars().all(is_valid_xml_char) {
                return Err(self.error("XML text contains a character forbidden by XML 1.0"));
            }
            if raw.len() > self.limits.max_record_bytes {
                return Err(self.error("XML text node exceeds configured bound"));
            }
            let value = decode_entities(raw).map_err(|detail| self.error(&detail))?;
            if !value.chars().all(is_valid_xml_char) {
                return Err(
                    self.error("decoded XML text contains a character forbidden by XML 1.0")
                );
            }
            if value.len() > self.limits.max_record_bytes {
                return Err(self.error("decoded XML text node exceeds configured bound"));
            }
            return Ok(Some(XmlToken::Text(value)));
        }
        if self.input[self.offset..].starts_with(b"<![CDATA[") {
            self.offset += 9;
            let start = self.offset;
            let end = find_bytes(&self.input[self.offset..], b"]]>")
                .ok_or_else(|| self.error("unterminated CDATA section"))?;
            self.offset += end;
            let value = std::str::from_utf8(&self.input[start..self.offset])
                .map_err(|_| self.error("invalid UTF-8 CDATA"))?;
            if !value.chars().all(is_valid_xml_char) {
                return Err(self.error("CDATA contains a character forbidden by XML 1.0"));
            }
            self.offset += 3;
            if value.len() > self.limits.max_record_bytes {
                return Err(self.error("XML CDATA exceeds configured bound"));
            }
            return Ok(Some(XmlToken::Text(value.to_owned())));
        }
        if self.input[self.offset..].starts_with(b"<!DOCTYPE")
            || self.input[self.offset..].starts_with(b"<!ENTITY")
        {
            return Err(JtlError::Unsupported {
                feature: "xml-external-entity",
                value: "DOCTYPE/ENTITY declarations are not accepted".to_owned(),
            });
        }
        self.offset += 1;
        if self.input.get(self.offset) == Some(&b'/') {
            self.offset += 1;
            let name = self.parse_name()?;
            self.skip_space();
            self.expect(b'>')?;
            return Ok(Some(XmlToken::End(name)));
        }
        let name = self.parse_name()?;
        let mut attributes = Vec::new();
        let mut empty = false;
        loop {
            self.skip_space();
            if self.input.get(self.offset) == Some(&b'>') {
                self.offset += 1;
                break;
            }
            if self.input.get(self.offset) == Some(&b'/') {
                self.offset += 1;
                self.expect(b'>')?;
                empty = true;
                break;
            }
            if attributes.len() >= self.limits.max_attributes {
                return Err(self.error("XML attribute count exceeds configured bound"));
            }
            let attribute_name = self.parse_name()?;
            if attributes.iter().any(|(name, _)| name == &attribute_name) {
                return Err(self.error("duplicate XML attribute"));
            }
            self.skip_space();
            self.expect(b'=')?;
            self.skip_space();
            let quote = *self
                .input
                .get(self.offset)
                .ok_or_else(|| self.error("missing XML attribute quote"))?;
            if quote != b'"' && quote != b'\'' {
                return Err(self.error("XML attributes must use single or double quotes"));
            }
            self.offset += 1;
            let start = self.offset;
            while self.offset < self.input.len() && self.input[self.offset] != quote {
                self.offset += 1;
            }
            if self.offset >= self.input.len() {
                return Err(self.error("unterminated XML attribute"));
            }
            let raw = std::str::from_utf8(&self.input[start..self.offset])
                .map_err(|_| self.error("invalid UTF-8 attribute"))?;
            self.offset += 1;
            if raw.len() > self.limits.max_attribute_bytes {
                return Err(self.error("XML attribute exceeds configured bound"));
            }
            let value = decode_entities(raw).map_err(|detail| self.error(&detail))?;
            if !value.chars().all(is_valid_xml_char) {
                return Err(
                    self.error("decoded XML attribute contains a character forbidden by XML 1.0")
                );
            }
            if value.len() > self.limits.max_attribute_bytes {
                return Err(self.error("decoded XML attribute exceeds configured bound"));
            }
            attributes.push((attribute_name, value));
        }
        Ok(Some(XmlToken::Start {
            name,
            attributes,
            empty,
        }))
    }

    fn parse_name(&mut self) -> Result<String, JtlError> {
        let start = self.offset;
        while let Some(byte) = self.input.get(self.offset) {
            if byte.is_ascii_whitespace() || *byte == b'=' || *byte == b'>' || *byte == b'/' {
                break;
            }
            self.offset += 1;
        }
        if self.offset == start {
            return Err(self.error("expected XML name"));
        }
        let value = std::str::from_utf8(&self.input[start..self.offset])
            .map_err(|_| self.error("invalid UTF-8 XML name"))?;
        if !crate::jtl::is_xml_name(value) && value != "java.net.URL" {
            return Err(self.error("invalid XML name"));
        }
        Ok(value.to_owned())
    }

    fn skip_space(&mut self) {
        while self
            .input
            .get(self.offset)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.offset += 1;
        }
    }

    fn expect(&mut self, value: u8) -> Result<(), JtlError> {
        if self.input.get(self.offset) != Some(&value) {
            return Err(self.error("malformed XML delimiter"));
        }
        self.offset += 1;
        Ok(())
    }

    fn skip_until(&mut self, marker: &[u8], detail: &str) -> Result<(), JtlError> {
        let start = self.offset;
        let Some(end) = find_bytes(&self.input[self.offset..], marker) else {
            return Err(self.error(detail));
        };
        let raw = std::str::from_utf8(&self.input[start..start + end])
            .map_err(|_| self.error("invalid UTF-8 XML declaration/comment"))?;
        if !raw.chars().all(is_valid_xml_char) {
            return Err(
                self.error("XML declaration/comment contains a character forbidden by XML 1.0")
            );
        }
        self.offset = start + end + marker.len();
        Ok(())
    }

    fn error(&self, detail: &str) -> JtlError {
        JtlError::Xml {
            offset: self.offset,
            detail: detail.to_owned(),
        }
    }
}

/// Incremental XML token scanner.  The small `lookahead` queue is populated
/// directly from the reader and is bounded by the marker/name currently being
/// recognized; text and attribute values are bounded independently by the
/// configured record/attribute limits.
struct XmlStreamScanner<R> {
    reader: R,
    pending: VecDeque<u8>,
    offset: usize,
    limits: JtlLimits,
    eof: bool,
    bom_checked: bool,
}

impl<R: Read> XmlStreamScanner<R> {
    fn new(reader: R, limits: JtlLimits) -> Self {
        Self {
            reader,
            pending: VecDeque::new(),
            offset: 0,
            limits,
            eof: false,
            bom_checked: false,
        }
    }

    fn read_raw(&mut self) -> Result<Option<u8>, JtlError> {
        if self.eof {
            return Ok(None);
        }
        let mut byte = [0_u8; 1];
        let read = self.reader.read(&mut byte).map_err(|error| JtlError::Io {
            operation: "read XML input",
            message: error.to_string(),
        })?;
        if read == 0 {
            self.eof = true;
            return Ok(None);
        }
        self.offset = self
            .offset
            .checked_add(read)
            .ok_or_else(|| JtlError::Unsupported {
                feature: "input-size",
                value: "input length overflow".to_owned(),
            })?;
        if self.offset > self.limits.max_input_bytes {
            return Err(JtlError::Unsupported {
                feature: "input-size-limit",
                value: format!(
                    "{} bytes exceeds {}",
                    self.offset, self.limits.max_input_bytes
                ),
            });
        }
        Ok(Some(byte[0]))
    }

    fn ensure_bom(&mut self) -> Result<(), JtlError> {
        if self.bom_checked {
            return Ok(());
        }
        let mut prefix = Vec::with_capacity(3);
        while prefix.len() < 3 {
            let Some(byte) = self.read_raw()? else {
                break;
            };
            prefix.push(byte);
        }
        if prefix != [0xef, 0xbb, 0xbf] {
            self.pending.extend(prefix);
        }
        self.bom_checked = true;
        Ok(())
    }

    fn fill(&mut self, length: usize) -> Result<(), JtlError> {
        self.ensure_bom()?;
        while self.pending.len() < length && !self.eof {
            let Some(byte) = self.read_raw()? else {
                break;
            };
            self.pending.push_back(byte);
        }
        Ok(())
    }

    fn starts_with(&mut self, marker: &[u8]) -> Result<bool, JtlError> {
        self.fill(marker.len())?;
        Ok(self
            .pending
            .iter()
            .take(marker.len())
            .copied()
            .eq(marker.iter().copied()))
    }

    fn peek(&mut self) -> Result<Option<u8>, JtlError> {
        self.fill(1)?;
        Ok(self.pending.front().copied())
    }

    fn take(&mut self) -> Result<Option<u8>, JtlError> {
        self.fill(1)?;
        Ok(self.pending.pop_front())
    }

    fn expect(&mut self, expected: u8) -> Result<(), JtlError> {
        if self.take()? != Some(expected) {
            return Err(self.error("malformed XML delimiter"));
        }
        Ok(())
    }

    fn skip_space(&mut self) -> Result<(), JtlError> {
        while self.peek()?.is_some_and(|byte| byte.is_ascii_whitespace()) {
            let _ = self.take()?;
        }
        Ok(())
    }

    fn parse_name(&mut self) -> Result<String, JtlError> {
        let mut bytes = Vec::new();
        while let Some(byte) = self.peek()? {
            if byte.is_ascii_whitespace() || matches!(byte, b'=' | b'>' | b'/') {
                break;
            }
            bytes.push(
                self.take()?
                    .ok_or_else(|| self.error("truncated XML name"))?,
            );
            if bytes.len() > self.limits.max_attribute_bytes {
                return Err(self.error("XML name exceeds configured bound"));
            }
        }
        if bytes.is_empty() {
            return Err(self.error("expected XML name"));
        }
        let value = String::from_utf8(bytes).map_err(|_| self.error("invalid UTF-8 XML name"))?;
        if !crate::jtl::is_xml_name(&value) && value != "java.net.URL" {
            return Err(self.error("invalid XML name"));
        }
        Ok(value)
    }

    fn parse_attribute(&mut self) -> Result<(String, String), JtlError> {
        let name = self.parse_name()?;
        self.skip_space()?;
        self.expect(b'=')?;
        self.skip_space()?;
        let quote = self
            .take()?
            .ok_or_else(|| self.error("missing XML attribute quote"))?;
        if quote != b'"' && quote != b'\'' {
            return Err(self.error("XML attributes must use single or double quotes"));
        }
        let mut raw = Vec::new();
        loop {
            let byte = self
                .take()?
                .ok_or_else(|| self.error("unterminated XML attribute"))?;
            if byte == quote {
                break;
            }
            raw.push(byte);
            if raw.len() > self.limits.max_attribute_bytes {
                return Err(self.error("XML attribute exceeds configured bound"));
            }
        }
        let raw = String::from_utf8(raw).map_err(|_| self.error("invalid UTF-8 attribute"))?;
        let value = decode_entities(&raw).map_err(|detail| self.error(&detail))?;
        if !value.chars().all(is_valid_xml_char) {
            return Err(
                self.error("decoded XML attribute contains a character forbidden by XML 1.0")
            );
        }
        if value.len() > self.limits.max_attribute_bytes {
            return Err(self.error("decoded XML attribute exceeds configured bound"));
        }
        Ok((name, value))
    }

    fn skip_until(&mut self, marker: &[u8], detail: &str) -> Result<(), JtlError> {
        let mut content = Vec::new();
        loop {
            let byte = self.take()?.ok_or_else(|| self.error(detail))?;
            content.push(byte);
            if content.ends_with(marker) {
                content.truncate(content.len().saturating_sub(marker.len()));
                let value = String::from_utf8(content)
                    .map_err(|_| self.error("invalid UTF-8 XML declaration/comment"))?;
                if !value.chars().all(is_valid_xml_char) {
                    return Err(self.error(
                        "XML declaration/comment contains a character forbidden by XML 1.0",
                    ));
                }
                return Ok(());
            }
            if content.len() > self.limits.max_record_bytes.saturating_add(marker.len()) {
                return Err(self.error("XML declaration/comment exceeds configured bound"));
            }
        }
    }

    fn next(&mut self) -> Result<Option<XmlToken>, JtlError> {
        loop {
            if self.peek()?.is_none() {
                return Ok(None);
            }
            if self.starts_with(b"<!--")? {
                self.skip_until(b"-->", "unterminated XML comment")?;
                continue;
            }
            if self.starts_with(b"<?")? {
                self.skip_until(b"?>", "unterminated XML processing instruction")?;
                continue;
            }
            return self.next_token();
        }
    }

    fn next_token(&mut self) -> Result<Option<XmlToken>, JtlError> {
        let Some(first) = self.peek()? else {
            return Ok(None);
        };
        if first != b'<' {
            let mut raw = Vec::new();
            while let Some(byte) = self.peek()? {
                if byte == b'<' {
                    break;
                }
                raw.push(
                    self.take()?
                        .ok_or_else(|| self.error("truncated XML text"))?,
                );
                if raw.len() > self.limits.max_record_bytes {
                    return Err(self.error("XML text node exceeds configured bound"));
                }
            }
            let raw = String::from_utf8(raw).map_err(|_| self.error("invalid UTF-8 text"))?;
            if !raw.chars().all(is_valid_xml_char) {
                return Err(self.error("XML text contains a character forbidden by XML 1.0"));
            }
            let value = decode_entities(&raw).map_err(|detail| self.error(&detail))?;
            if !value.chars().all(is_valid_xml_char) {
                return Err(
                    self.error("decoded XML text contains a character forbidden by XML 1.0")
                );
            }
            if value.len() > self.limits.max_record_bytes {
                return Err(self.error("decoded XML text node exceeds configured bound"));
            }
            return Ok(Some(XmlToken::Text(value)));
        }
        if self.starts_with(b"<![CDATA[")? {
            for _ in 0..9 {
                let _ = self.take()?;
            }
            let mut value = Vec::new();
            loop {
                if self.starts_with(b"]]>")? {
                    for _ in 0..3 {
                        let _ = self.take()?;
                    }
                    break;
                }
                let byte = self
                    .take()?
                    .ok_or_else(|| self.error("unterminated CDATA section"))?;
                value.push(byte);
                if value.len() > self.limits.max_record_bytes {
                    return Err(self.error("XML CDATA exceeds configured bound"));
                }
            }
            let value = String::from_utf8(value).map_err(|_| self.error("invalid UTF-8 CDATA"))?;
            if !value.chars().all(is_valid_xml_char) {
                return Err(self.error("CDATA contains a character forbidden by XML 1.0"));
            }
            return Ok(Some(XmlToken::Text(value)));
        }
        if self.starts_with(b"<!DOCTYPE")? || self.starts_with(b"<!ENTITY")? {
            return Err(JtlError::Unsupported {
                feature: "xml-external-entity",
                value: "DOCTYPE/ENTITY declarations are not accepted".to_owned(),
            });
        }
        self.expect(b'<')?;
        if self.peek()? == Some(b'/') {
            let _ = self.take()?;
            let name = self.parse_name()?;
            self.skip_space()?;
            self.expect(b'>')?;
            return Ok(Some(XmlToken::End(name)));
        }
        let name = self.parse_name()?;
        let mut attributes = Vec::new();
        let mut empty = false;
        loop {
            self.skip_space()?;
            match self.peek()? {
                Some(b'>') => {
                    let _ = self.take()?;
                    break;
                }
                Some(b'/') => {
                    let _ = self.take()?;
                    self.expect(b'>')?;
                    empty = true;
                    break;
                }
                Some(_) => {
                    if attributes.len() >= self.limits.max_attributes {
                        return Err(self.error("XML attribute count exceeds configured bound"));
                    }
                    let attribute = self.parse_attribute()?;
                    if attributes.iter().any(|(key, _)| key == &attribute.0) {
                        return Err(self.error("duplicate XML attribute"));
                    }
                    attributes.push(attribute);
                }
                None => return Err(self.error("unterminated XML start element")),
            }
        }
        Ok(Some(XmlToken::Start {
            name,
            attributes,
            empty,
        }))
    }

    fn error(&self, detail: &str) -> JtlError {
        JtlError::Xml {
            offset: self.offset,
            detail: detail.to_owned(),
        }
    }
}

#[derive(Clone, Debug)]
struct SampleFrame {
    name: String,
    result: SampleResult,
    thread_name: Option<String>,
    host: Option<String>,
    variables: VariableSnapshot,
    seen_text: Vec<TextKind>,
    last_child_rank: Option<u8>,
}

#[derive(Clone, Debug)]
struct AssertionFrame {
    name: Option<String>,
    failure: Option<bool>,
    error: Option<bool>,
    failure_message: Option<String>,
    error_message: Option<String>,
    unknown_attributes: Vec<(String, String)>,
    unknown_children: Vec<XmlOpaqueChild>,
    last_child_rank: Option<u8>,
}

#[derive(Clone, Debug)]
struct TextFrame {
    kind: TextKind,
    name: String,
    value: String,
}

#[derive(Clone, Debug)]
struct OpaqueFrame {
    node: XmlOpaqueChild,
}

#[derive(Clone, Debug)]
struct RootFrame {
    attributes: Vec<(String, String)>,
    children: Vec<XmlOpaqueChild>,
    metadata_attached: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TextKind {
    ResponseHeader,
    RequestHeader,
    ResponseData,
    ResponseFile,
    SamplerData,
    Url,
    AssertionName,
    AssertionFailure,
    AssertionError,
    AssertionFailureMessage,
    AssertionErrorMessage,
}

#[derive(Clone, Debug)]
enum OpenFrame {
    Root(RootFrame),
    Sample(Box<SampleFrame>),
    Assertion(AssertionFrame),
    Text(TextFrame),
    Opaque(OpaqueFrame),
}

#[cfg(test)]
#[allow(dead_code)]
fn parse_document(
    text: &str,
    limits: JtlLimits,
    configuration: &XmlDecodeConfiguration,
) -> Result<Vec<SampleEvent>, JtlError> {
    let mut scanner = XmlScanner::new(text, limits);
    let mut stack = Vec::<OpenFrame>::new();
    let mut events = Vec::new();
    let mut node_count = 0usize;
    let mut saw_root = false;
    while let Some(token) = scanner.next()? {
        match token {
            XmlToken::Text(value) => {
                if value.len() > limits.max_record_bytes {
                    return Err(JtlError::Unsupported {
                        feature: "xml-text-limit",
                        value: format!("{} bytes exceeds {}", value.len(), limits.max_record_bytes),
                    });
                }
                if let Some(OpenFrame::Text(frame)) = stack.last_mut() {
                    let next = frame.value.len().checked_add(value.len()).ok_or_else(|| {
                        JtlError::Unsupported {
                            feature: "xml-text-limit",
                            value: "text length overflow".to_owned(),
                        }
                    })?;
                    if next > limits.max_record_bytes {
                        return Err(JtlError::Unsupported {
                            feature: "xml-text-limit",
                            value: format!("{} bytes exceeds {}", next, limits.max_record_bytes),
                        });
                    }
                    frame.value.push_str(&value);
                } else if !value.trim().is_empty() {
                    return Err(JtlError::Xml {
                        offset: scanner.offset,
                        detail: "non-whitespace text outside a JTL child".to_owned(),
                    });
                }
            }
            XmlToken::Start {
                name,
                attributes,
                empty,
            } => {
                node_count = node_count
                    .checked_add(1)
                    .ok_or_else(|| JtlError::Unsupported {
                        feature: "xml-node-limit",
                        value: "node count overflow".to_owned(),
                    })?;
                if node_count > limits.max_nodes {
                    return Err(JtlError::Unsupported {
                        feature: "xml-node-limit",
                        value: format!("{} nodes exceeds {}", node_count, limits.max_nodes),
                    });
                }
                if stack.len() + 1 > limits.max_depth {
                    return Err(JtlError::Unsupported {
                        feature: "xml-depth-limit",
                        value: format!("depth {} exceeds {}", stack.len() + 1, limits.max_depth),
                    });
                }
                start_node(
                    &mut stack,
                    &mut events,
                    &mut saw_root,
                    name,
                    attributes,
                    empty,
                    limits,
                    configuration,
                    scanner.offset,
                )?;
            }
            XmlToken::End(name) => {
                close_node(
                    &mut stack,
                    &mut events,
                    &mut saw_root,
                    &name,
                    limits,
                    scanner.offset,
                )?;
            }
        }
    }
    if !stack.is_empty() {
        return Err(JtlError::Xml {
            offset: scanner.offset,
            detail: "truncated XML element".to_owned(),
        });
    }
    if !saw_root {
        return Err(JtlError::Xml {
            offset: 0,
            detail: "JTL root testResults is missing".to_owned(),
        });
    }
    if events.len() > limits.max_samples {
        return Err(JtlError::Unsupported {
            feature: "xml-sample-limit",
            value: format!(
                "{} root samples exceeds {}",
                events.len(),
                limits.max_samples
            ),
        });
    }
    Ok(events)
}

// The scanner passes document state explicitly so malformed input cannot
// mutate hidden global parser state; keep this narrow lint exception at the
// parser boundary.
#[allow(clippy::too_many_arguments)]
fn start_node(
    stack: &mut Vec<OpenFrame>,
    events: &mut Vec<SampleEvent>,
    saw_root: &mut bool,
    name: String,
    attributes: Vec<(String, String)>,
    empty: bool,
    limits: JtlLimits,
    configuration: &XmlDecodeConfiguration,
    offset: usize,
) -> Result<(), JtlError> {
    if !*saw_root {
        if name != ROOT_NAME {
            return Err(JtlError::Xml {
                offset,
                detail: format!("expected <{ROOT_NAME}>, got <{name}>"),
            });
        }
        let Some(version) = attr(&attributes, "version") else {
            return Err(JtlError::Xml {
                offset,
                detail: "testResults root is missing required version".to_owned(),
            });
        };
        if version != "1.2" {
            return Err(JtlError::Unsupported {
                feature: "xml-version",
                value: version.to_owned(),
            });
        }
        let root_attributes = attributes
            .iter()
            .filter(|(key, _)| key != "version")
            .cloned()
            .collect();
        *saw_root = true;
        if empty {
            return Err(JtlError::Xml {
                offset,
                detail: "testResults root cannot be empty".to_owned(),
            });
        }
        stack.push(OpenFrame::Root(RootFrame {
            attributes: root_attributes,
            children: Vec::new(),
            metadata_attached: false,
        }));
        return Ok(());
    }

    if matches!(stack.last(), Some(OpenFrame::Opaque(_))) {
        let node = XmlOpaqueChild::new(name.clone(), attributes);
        if empty {
            return attach_opaque(stack, node, offset);
        }
        stack.push(OpenFrame::Opaque(OpaqueFrame { node }));
        return Ok(());
    }
    let parent_is_sample = matches!(stack.last(), Some(OpenFrame::Sample(_)));
    let parent_is_assertion = matches!(stack.last(), Some(OpenFrame::Assertion(_)));
    if parent_is_sample {
        record_sample_child_order(stack, &name, offset)?;
    } else if parent_is_assertion {
        record_assertion_child_order(stack, &name, offset)?;
    }
    let Some(parent) = stack.last() else {
        return Err(JtlError::Xml {
            offset,
            detail: "element appears after testResults close".to_owned(),
        });
    };
    match name.as_str() {
        "sample" | "httpSample" => {
            if !matches!(parent, OpenFrame::Root(_) | OpenFrame::Sample(_)) {
                return Err(JtlError::Xml {
                    offset,
                    detail: "sample must be nested under testResults or another sample".to_owned(),
                });
            }
            let (result, thread_name, host, variables, unknown_attributes) =
                parse_sample_attributes(&attributes, offset, configuration)?;
            let element = if name == "httpSample" {
                XmlSampleElement::HttpSample
            } else {
                XmlSampleElement::Sample
            };
            let mut result = result;
            result.set_wire_metadata(
                thread_name.clone(),
                host.clone(),
                variables.clone(),
                element,
            );
            result.set_wire_xml_attributes(unknown_attributes);
            let close_name = name.clone();
            let frame = SampleFrame {
                name,
                result,
                thread_name,
                host,
                variables,
                seen_text: Vec::new(),
                last_child_rank: None,
            };
            stack.push(OpenFrame::Sample(Box::new(frame)));
            if empty {
                close_node(stack, events, saw_root, &close_name, limits, offset)
            } else {
                Ok(())
            }
        }
        "assertionResult" => {
            if !matches!(parent, OpenFrame::Sample(_)) {
                return Err(JtlError::Xml {
                    offset,
                    detail: "assertionResult must be inside a sample".to_owned(),
                });
            }
            let frame = AssertionFrame {
                name: attr(&attributes, "name").map(str::to_owned),
                failure: attr(&attributes, "failure")
                    .map(|value| parse_bool(value, "failure"))
                    .transpose()
                    .map_err(|error| match error {
                        JtlError::InvalidConfiguration { detail, .. } => {
                            JtlError::Xml { offset, detail }
                        }
                        other => other,
                    })?,
                error: attr(&attributes, "error")
                    .map(|value| parse_bool(value, "error"))
                    .transpose()
                    .map_err(|error| match error {
                        JtlError::InvalidConfiguration { detail, .. } => {
                            JtlError::Xml { offset, detail }
                        }
                        other => other,
                    })?,
                failure_message: attr(&attributes, "failureMessage").map(str::to_owned),
                error_message: attr(&attributes, "errorMessage").map(str::to_owned),
                unknown_attributes: attributes
                    .iter()
                    .filter(|(name, _)| {
                        !["name", "failure", "error", "failureMessage", "errorMessage"]
                            .contains(&name.as_str())
                    })
                    .cloned()
                    .collect(),
                unknown_children: Vec::new(),
                last_child_rank: None,
            };
            stack.push(OpenFrame::Assertion(frame));
            if empty {
                close_node(stack, events, saw_root, "assertionResult", limits, offset)
            } else {
                Ok(())
            }
        }
        "responseHeader" => push_text(
            stack,
            TextKind::ResponseHeader,
            &attributes,
            empty,
            limits,
            offset,
        ),
        "requestHeader" => push_text(
            stack,
            TextKind::RequestHeader,
            &attributes,
            empty,
            limits,
            offset,
        ),
        "responseData" => push_text(
            stack,
            TextKind::ResponseData,
            &attributes,
            empty,
            limits,
            offset,
        ),
        "responseFile" => push_text(
            stack,
            TextKind::ResponseFile,
            &attributes,
            empty,
            limits,
            offset,
        ),
        "samplerData" => push_text(
            stack,
            TextKind::SamplerData,
            &attributes,
            empty,
            limits,
            offset,
        ),
        "java.net.URL" => push_text(stack, TextKind::Url, &attributes, empty, limits, offset),
        // Older hand-written/JMeter-adjacent JTL files use the short URL
        // spelling.  Keep the source close name so alias input round-trips
        // without a mismatched closing-element diagnostic.
        "url" => push_text_named(
            stack,
            TextKind::Url,
            "url",
            &attributes,
            empty,
            limits,
            offset,
        ),
        "name" => push_assertion_text(
            stack,
            TextKind::AssertionName,
            &attributes,
            empty,
            limits,
            offset,
        ),
        "failure" => push_assertion_text(
            stack,
            TextKind::AssertionFailure,
            &attributes,
            empty,
            limits,
            offset,
        ),
        "error" => push_assertion_text(
            stack,
            TextKind::AssertionError,
            &attributes,
            empty,
            limits,
            offset,
        ),
        "failureMessage" => push_assertion_text(
            stack,
            TextKind::AssertionFailureMessage,
            &attributes,
            empty,
            limits,
            offset,
        ),
        "errorMessage" => push_assertion_text(
            stack,
            TextKind::AssertionErrorMessage,
            &attributes,
            empty,
            limits,
            offset,
        ),
        _ => {
            if matches!(
                parent,
                OpenFrame::Root(_) | OpenFrame::Sample(_) | OpenFrame::Assertion(_)
            ) {
                let node = XmlOpaqueChild::new(name, attributes);
                if empty {
                    attach_opaque(stack, node, offset)
                } else {
                    stack.push(OpenFrame::Opaque(OpaqueFrame { node }));
                    Ok(())
                }
            } else {
                Err(JtlError::Unsupported {
                    feature: "xml-child",
                    value: name,
                })
            }
        }
    }
}

fn close_node(
    stack: &mut Vec<OpenFrame>,
    events: &mut Vec<SampleEvent>,
    saw_root: &mut bool,
    name: &str,
    limits: JtlLimits,
    offset: usize,
) -> Result<(), JtlError> {
    let frame = stack.pop().ok_or_else(|| JtlError::Xml {
        offset,
        detail: format!("unexpected closing </{name}>"),
    })?;
    match frame {
        OpenFrame::Root(_) => {
            if name != ROOT_NAME {
                return Err(JtlError::Xml {
                    offset,
                    detail: format!("expected </{ROOT_NAME}>, got </{name}>"),
                });
            }
            if stack.is_empty() {
                *saw_root = true;
            }
            Ok(())
        }
        OpenFrame::Sample(sample) => {
            if name != sample.name {
                return Err(JtlError::Xml {
                    offset,
                    detail: format!("mismatched sample close </{name}>"),
                });
            }
            sample.result.validate_wire_with_limits(
                crate::ValidationLimits::new(limits.max_depth, limits.max_nodes).map_err(|_| {
                    JtlError::InvalidConfiguration {
                        field: "limits",
                        detail: "invalid hierarchy limits".to_owned(),
                    }
                })?,
            )?;
            if matches!(sample.result.data_type(), Some(DataType::Binary))
                && sample
                    .result
                    .response_data()
                    .is_some_and(|data| !data.is_empty())
            {
                return Err(JtlError::Unsupported {
                    feature: "xml-binary-response-data",
                    value: "binary responseData requires an explicit binary adapter".to_owned(),
                });
            }
            if let Some(OpenFrame::Sample(parent)) = stack.last_mut() {
                parent
                    .result
                    .try_add_sub_result_raw(
                        sample.result,
                        crate::ValidationLimits::new(limits.max_depth, limits.max_nodes).map_err(
                            |_| JtlError::InvalidConfiguration {
                                field: "limits",
                                detail: "invalid hierarchy limits".to_owned(),
                            },
                        )?,
                    )
                    .map_err(JtlError::from)?;
            } else if matches!(stack.last(), Some(OpenFrame::Root(_))) {
                let root_metadata = match stack.last_mut() {
                    Some(OpenFrame::Root(root)) => {
                        let attributes = if root.metadata_attached {
                            Vec::new()
                        } else {
                            root.metadata_attached = true;
                            root.attributes.clone()
                        };
                        let children = std::mem::take(&mut root.children);
                        Some((attributes, children))
                    }
                    _ => None,
                };
                sample.result.validate_wire_with_limits(
                    crate::ValidationLimits::new(limits.max_depth, limits.max_nodes).map_err(
                        |_| JtlError::InvalidConfiguration {
                            field: "limits",
                            detail: "invalid hierarchy limits".to_owned(),
                        },
                    )?,
                )?;
                let mut result = sample.result;
                if let Some((attributes, children)) = root_metadata {
                    result.set_wire_xml_root_metadata(attributes, children);
                }
                let event = SampleEvent::new(
                    result,
                    "",
                    ThreadIdentity::new(sample.thread_name.unwrap_or_default()),
                    HostIdentity::new(sample.host.unwrap_or_default()),
                    sample.variables,
                );
                events.push(event);
            } else {
                return Err(JtlError::Xml {
                    offset,
                    detail: "sample closed outside testResults".to_owned(),
                });
            }
            Ok(())
        }
        OpenFrame::Assertion(assertion_frame) => {
            if name != "assertionResult" {
                return Err(JtlError::Xml {
                    offset,
                    detail: format!("mismatched assertion close </{name}>"),
                });
            }
            let mut assertion = AssertionResult::from_flags(
                assertion_frame.name.unwrap_or_default(),
                assertion_frame.failure.unwrap_or(false),
                assertion_frame.error.unwrap_or(false),
                assertion_frame.failure_message,
                assertion_frame.error_message,
            )
            .map_err(JtlError::from)?;
            assertion.set_wire_xml_attributes(assertion_frame.unknown_attributes);
            for child in assertion_frame.unknown_children {
                assertion.add_wire_xml_child(child);
            }
            match stack.last_mut() {
                Some(OpenFrame::Sample(sample)) => sample
                    .result
                    .try_add_assertion(assertion)
                    .map_err(JtlError::from),
                _ => Err(JtlError::Xml {
                    offset,
                    detail: "assertionResult closed outside sample".to_owned(),
                }),
            }
        }
        OpenFrame::Opaque(opaque) => {
            if name != opaque.node.name {
                return Err(JtlError::Xml {
                    offset,
                    detail: format!("mismatched opaque close </{name}>"),
                });
            }
            attach_opaque(stack, opaque.node, offset)
        }
        OpenFrame::Text(text) => {
            if name != text.name {
                return Err(JtlError::Xml {
                    offset,
                    detail: format!(
                        "mismatched XML text close </{name}>, expected </{}>",
                        text.name
                    ),
                });
            }
            let Some(parent) = stack.last_mut() else {
                return Err(JtlError::Xml {
                    offset,
                    detail: format!("text element </{name}> has no parent"),
                });
            };
            attach_text(parent, text.kind, text.value, name, offset)
        }
    }
}

fn attach_opaque(
    stack: &mut [OpenFrame],
    child: XmlOpaqueChild,
    offset: usize,
) -> Result<(), JtlError> {
    let Some(parent) = stack.last_mut() else {
        return Err(JtlError::Xml {
            offset,
            detail: "opaque XML child has no parent".to_owned(),
        });
    };
    match parent {
        OpenFrame::Sample(sample) => {
            sample.result.add_wire_xml_child(child);
            Ok(())
        }
        OpenFrame::Assertion(assertion) => {
            assertion.unknown_children.push(child);
            Ok(())
        }
        OpenFrame::Opaque(opaque) => {
            opaque.node.push_child(child);
            Ok(())
        }
        OpenFrame::Root(root) => {
            root.children.push(child);
            Ok(())
        }
        _ => Err(JtlError::Xml {
            offset,
            detail: "opaque XML child has an invalid parent".to_owned(),
        }),
    }
}

fn record_sample_child_order(
    stack: &mut [OpenFrame],
    name: &str,
    offset: usize,
) -> Result<(), JtlError> {
    let rank = match name {
        "assertionResult" => 0,
        "sample" | "httpSample" => 1,
        "responseHeader" => 2,
        "requestHeader" => 3,
        "responseData" => 4,
        "responseFile" => 5,
        "samplerData" => 6,
        "java.net.URL" | "url" => 7,
        _ => 8,
    };
    let Some(OpenFrame::Sample(sample)) = stack.last_mut() else {
        return Ok(());
    };
    if sample
        .last_child_rank
        .is_some_and(|previous| rank < previous)
    {
        return Err(JtlError::Unsupported {
            feature: "xml-child-order",
            value: format!("sample child <{name}> is out of canonical order at byte {offset}"),
        });
    }
    sample.last_child_rank = Some(rank);
    Ok(())
}

fn record_assertion_child_order(
    stack: &mut [OpenFrame],
    name: &str,
    offset: usize,
) -> Result<(), JtlError> {
    let rank = match name {
        "name" => 0,
        "failure" => 1,
        "error" => 2,
        "failureMessage" => 3,
        "errorMessage" => 4,
        _ => 5,
    };
    let Some(OpenFrame::Assertion(assertion)) = stack.last_mut() else {
        return Ok(());
    };
    if assertion
        .last_child_rank
        .is_some_and(|previous| rank < previous)
    {
        return Err(JtlError::Unsupported {
            feature: "xml-child-order",
            value: format!("assertion child <{name}> is out of canonical order at byte {offset}"),
        });
    }
    assertion.last_child_rank = Some(rank);
    Ok(())
}

fn push_text(
    stack: &mut Vec<OpenFrame>,
    kind: TextKind,
    attributes: &[(String, String)],
    empty: bool,
    _limits: JtlLimits,
    offset: usize,
) -> Result<(), JtlError> {
    push_text_named(
        stack,
        kind,
        text_kind_name(kind),
        attributes,
        empty,
        _limits,
        offset,
    )
}

fn push_text_named(
    stack: &mut Vec<OpenFrame>,
    kind: TextKind,
    element_name: &str,
    attributes: &[(String, String)],
    empty: bool,
    _limits: JtlLimits,
    offset: usize,
) -> Result<(), JtlError> {
    if !matches!(
        stack.last(),
        Some(OpenFrame::Sample(_) | OpenFrame::Assertion(_))
    ) {
        return Err(JtlError::Xml {
            offset,
            detail: "JTL text child must be inside a sample/assertion".to_owned(),
        });
    }
    check_text_attributes(attributes, offset)?;
    mark_text_seen(stack, kind, offset)?;
    if empty {
        let parent = stack.last_mut().ok_or_else(|| JtlError::Xml {
            offset,
            detail: "empty text child has no parent".to_owned(),
        })?;
        return attach_text(parent, kind, String::new(), "text", offset);
    }
    stack.push(OpenFrame::Text(TextFrame {
        kind,
        name: element_name.to_owned(),
        value: String::new(),
    }));
    Ok(())
}

fn mark_text_seen(stack: &mut [OpenFrame], kind: TextKind, offset: usize) -> Result<(), JtlError> {
    match stack.last_mut() {
        Some(OpenFrame::Sample(sample)) => {
            if sample.seen_text.contains(&kind) {
                return Err(JtlError::Xml {
                    offset,
                    detail: format!("duplicate <{}> child", text_kind_name(kind)),
                });
            }
            sample.seen_text.push(kind);
            Ok(())
        }
        Some(OpenFrame::Assertion(assertion)) => {
            let duplicate = match kind {
                TextKind::AssertionName => assertion.name.is_some(),
                TextKind::AssertionFailure => assertion.failure.is_some(),
                TextKind::AssertionError => assertion.error.is_some(),
                TextKind::AssertionFailureMessage => assertion.failure_message.is_some(),
                TextKind::AssertionErrorMessage => assertion.error_message.is_some(),
                _ => true,
            };
            if duplicate {
                return Err(JtlError::Xml {
                    offset,
                    detail: format!("duplicate <{}> child", text_kind_name(kind)),
                });
            }
            Ok(())
        }
        _ => Err(JtlError::Xml {
            offset,
            detail: "text child has an invalid parent".to_owned(),
        }),
    }
}

fn check_text_attributes(attributes: &[(String, String)], offset: usize) -> Result<(), JtlError> {
    for (name, value) in attributes {
        if name != "class" {
            return Err(JtlError::Unsupported {
                feature: "xml-attribute",
                value: format!("{name} at byte {offset}"),
            });
        }
        if value != "java.lang.String" {
            return Err(JtlError::Unsupported {
                feature: "xml-text-class",
                value: value.clone(),
            });
        }
    }
    Ok(())
}

fn text_kind_name(kind: TextKind) -> &'static str {
    match kind {
        TextKind::ResponseHeader => "responseHeader",
        TextKind::RequestHeader => "requestHeader",
        TextKind::ResponseData => "responseData",
        TextKind::ResponseFile => "responseFile",
        TextKind::SamplerData => "samplerData",
        TextKind::Url => "java.net.URL",
        TextKind::AssertionName => "name",
        TextKind::AssertionFailure => "failure",
        TextKind::AssertionError => "error",
        TextKind::AssertionFailureMessage => "failureMessage",
        TextKind::AssertionErrorMessage => "errorMessage",
    }
}

fn push_assertion_text(
    stack: &mut Vec<OpenFrame>,
    kind: TextKind,
    attributes: &[(String, String)],
    empty: bool,
    limits: JtlLimits,
    offset: usize,
) -> Result<(), JtlError> {
    if !matches!(stack.last(), Some(OpenFrame::Assertion(_))) {
        return Err(JtlError::Xml {
            offset,
            detail: "assertion text child must be inside assertionResult".to_owned(),
        });
    }
    push_text(stack, kind, attributes, empty, limits, offset)
}

fn attach_text(
    parent: &mut OpenFrame,
    kind: TextKind,
    value: String,
    name: &str,
    offset: usize,
) -> Result<(), JtlError> {
    match parent {
        OpenFrame::Sample(sample) => {
            match kind {
                TextKind::ResponseHeader => sample
                    .result
                    .set_response_headers(Some(HeaderBlock::new(value))),
                TextKind::RequestHeader => sample
                    .result
                    .set_request_headers(Some(HeaderBlock::new(value))),
                TextKind::ResponseData => sample
                    .result
                    .set_response_data(Some(response_text_bytes(value))),
                TextKind::ResponseFile => sample.result.set_response_file(Some(value)),
                TextKind::SamplerData => sample.result.set_sampler_data(Some(value)),
                TextKind::Url => sample.result.set_url(Some(value)),
                _ => {
                    return Err(JtlError::Xml {
                        offset,
                        detail: format!("<{name}> is not valid inside a sample"),
                    });
                }
            }
            Ok(())
        }
        OpenFrame::Assertion(assertion) => {
            match kind {
                TextKind::AssertionName => assertion.name = Some(value),
                TextKind::AssertionFailure => {
                    assertion.failure =
                        Some(parse_bool(&value, "failure").map_err(|error| match error {
                            JtlError::InvalidConfiguration { detail, .. } => {
                                JtlError::Xml { offset, detail }
                            }
                            other => other,
                        })?)
                }
                TextKind::AssertionError => {
                    assertion.error =
                        Some(parse_bool(&value, "error").map_err(|error| match error {
                            JtlError::InvalidConfiguration { detail, .. } => {
                                JtlError::Xml { offset, detail }
                            }
                            other => other,
                        })?)
                }
                TextKind::AssertionFailureMessage => assertion.failure_message = Some(value),
                TextKind::AssertionErrorMessage => assertion.error_message = Some(value),
                _ => {
                    return Err(JtlError::Xml {
                        offset,
                        detail: format!("<{name}> is not valid inside assertionResult"),
                    });
                }
            }
            Ok(())
        }
        _ => Err(JtlError::Xml {
            offset,
            detail: "text child has an invalid parent".to_owned(),
        }),
    }
}

type ParsedSampleAttributes = (
    SampleResult,
    Option<String>,
    Option<String>,
    VariableSnapshot,
    Vec<(String, String)>,
);

fn parse_sample_attributes(
    attributes: &[(String, String)],
    offset: usize,
    configuration: &XmlDecodeConfiguration,
) -> Result<ParsedSampleAttributes, JtlError> {
    if attr(attributes, "rc").is_some() && attr(attributes, "rs").is_some() {
        return Err(JtlError::Unsupported {
            feature: "xml-sample-attribute-collision",
            value: "rc and legacy rs response-code aliases are both present".to_owned(),
        });
    }
    let result = match attr(attributes, "lb") {
        Some(value) => SampleResult::new(value),
        None => SampleResult::without_label(),
    };
    let timestamp = parse_xml_optional_i64(attr(attributes, "ts"), "ts", offset)?;
    let elapsed = parse_xml_optional_u64(attr(attributes, "t"), "t", offset)?;
    let idle = parse_xml_optional_u64(attr(attributes, "it"), "it", offset)?;
    let latency = parse_xml_optional_u64(attr(attributes, "lt"), "lt", offset)?;
    let connect = parse_xml_optional_u64(attr(attributes, "ct"), "ct", offset)?;
    let timing = timing_from_wire(timestamp, elapsed, latency, connect, idle)?;
    let mut result = result;
    result.set_timing_from_wire(timing);
    result.set_success(match attr(attributes, "s") {
        Some(value) => Some(parse_bool(value, "s").map_err(|error| match error {
            JtlError::InvalidConfiguration { detail, .. } => JtlError::Xml { offset, detail },
            other => other,
        })?),
        None => None,
    });
    result.set_response_code(
        attr(attributes, "rs")
            .or_else(|| attr(attributes, "rc"))
            .map(str::to_owned),
    );
    result.set_response_message(attr(attributes, "rm").map(str::to_owned));
    result.set_data_type(attr(attributes, "dt").map(|value| DataType::from_wire(value.to_owned())));
    result
        .set_data_encoding(attr(attributes, "de").map(|value| DataEncoding::new(value.to_owned())));
    result.set_received_bytes(
        parse_xml_optional_u64(attr(attributes, "by"), "by", offset)?.map(crate::ByteCount::new),
    );
    result.set_sent_bytes(
        parse_xml_optional_u64(attr(attributes, "sby"), "sby", offset)?.map(crate::ByteCount::new),
    );
    result.set_sample_count(
        parse_xml_optional_u64(attr(attributes, "sc"), "sc", offset)?.map(crate::SampleCount::new),
    );
    result.set_error_count(
        parse_xml_optional_u64(attr(attributes, "ec"), "ec", offset)?.map(crate::ErrorCount::new),
    );
    result.set_group_threads(
        parse_xml_optional_u64(attr(attributes, "ng"), "ng", offset)?.map(crate::ThreadCount::new),
    );
    result.set_all_threads(
        parse_xml_optional_u64(attr(attributes, "na"), "na", offset)?.map(crate::ThreadCount::new),
    );

    let known = [
        "t", "it", "lt", "ct", "ts", "s", "lb", "rc", "rs", "rm", "tn", "dt", "de", "by", "sby",
        "sc", "ec", "ng", "na", "hn",
    ];
    let mut variables = VariableSnapshot::new();
    let mut unknown_attributes = Vec::new();
    for variable in configuration.sample_variables() {
        variables.insert_absent(variable.clone());
    }
    for (name, value) in attributes {
        if !known.contains(&name.as_str()) {
            let configured = configuration.sample_variables().iter().find(|variable| {
                variable.as_str() == name
                    || sanitize_xml_attribute_name(variable)
                        .is_ok_and(|wire_name| wire_name == *name)
            });
            let variable = match configured {
                Some(variable) => variable.clone(),
                None if configuration.reject_unknown_attributes() => {
                    return Err(JtlError::Unsupported {
                        feature: "xml-sample-attribute",
                        value: name.clone(),
                    });
                }
                None => {
                    // Preserve the exact extension spelling for re-emission;
                    // never guess through the lossy underscore transform.
                    unknown_attributes.push((name.clone(), value.clone()));
                    name.clone()
                }
            };
            if variables
                .get(&variable)
                .is_some_and(|value| !matches!(value, crate::VariableValue::Absent))
            {
                return Err(JtlError::Unsupported {
                    feature: "xml-sample-variable-collision",
                    value: variable,
                });
            }
            variables.insert(variable, value.clone());
        }
    }
    Ok((
        result,
        attr(attributes, "tn").map(str::to_owned),
        attr(attributes, "hn").map(str::to_owned),
        variables,
        unknown_attributes,
    ))
}

fn attr<'a>(attributes: &'a [(String, String)], name: &str) -> Option<&'a str> {
    attributes
        .iter()
        .find_map(|(key, value)| (key == name).then_some(value.as_str()))
}

fn decode_entities(value: &str) -> Result<String, String> {
    if !value.contains('&') {
        return Ok(value.to_owned());
    }
    let mut output = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(index) = rest.find('&') {
        output.push_str(&rest[..index]);
        let after = &rest[index + 1..];
        let end = after
            .find(';')
            .ok_or_else(|| "unterminated XML entity".to_owned())?;
        let entity = &after[..end];
        match entity {
            "amp" => output.push('&'),
            "lt" => output.push('<'),
            "gt" => output.push('>'),
            "quot" => output.push('"'),
            "apos" => output.push('\''),
            _ if entity.starts_with("#x") || entity.starts_with("#X") => {
                let value = u32::from_str_radix(&entity[2..], 16)
                    .map_err(|_| "invalid hexadecimal XML entity".to_owned())?;
                let character = char::from_u32(value)
                    .filter(|character| is_valid_xml_char(*character))
                    .ok_or_else(|| "invalid XML code point".to_owned())?;
                output.push(character);
            }
            _ if entity.starts_with('#') => {
                let value = entity[1..]
                    .parse::<u32>()
                    .map_err(|_| "invalid decimal XML entity".to_owned())?;
                let character = char::from_u32(value)
                    .filter(|character| is_valid_xml_char(*character))
                    .ok_or_else(|| "invalid XML code point".to_owned())?;
                output.push(character);
            }
            _ => return Err(format!("unsupported XML entity &{entity};")),
        }
        rest = &after[end + 1..];
    }
    output.push_str(rest);
    Ok(output)
}

fn is_valid_xml_char(value: char) -> bool {
    matches!(value, '\u{9}' | '\u{a}' | '\u{d}')
        || ('\u{20}'..='\u{d7ff}').contains(&value)
        || ('\u{e000}'..='\u{fffd}').contains(&value)
        || ('\u{10000}'..='\u{10ffff}').contains(&value)
}

#[cfg(test)]
#[allow(dead_code)]
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

// Test fixtures use `expect` at setup/assertion boundaries so failures retain
// the operation name; production codec paths remain explicitly fallible.
#[allow(clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AssertionOutcome, ByteCount, ElapsedTime, Latency, LineEnding, SampleData};

    fn event() -> SampleEvent {
        let mut result = SampleResult::new("xml & <sample>");
        result.set_successful(true);
        result.set_response_code_text("200");
        result.set_response_message_text("OK");
        result.set_data_type_wire("text");
        result.set_data_encoding_name("UTF-8");
        result
            .set_elapsed(Some(ElapsedTime::from_millis(10)))
            .expect("elapsed");
        result
            .set_latency(Some(Latency::from_millis(2)))
            .expect("latency");
        result.set_received_bytes(Some(ByteCount::new(5)));
        result.set_response_data(Some(SampleData::from("héllo")));
        result.set_response_headers(Some(HeaderBlock::new("X-Test: yes\n")));
        result.set_request_headers(Some(HeaderBlock::empty()));
        result.set_sampler_data_text("request\nline");
        result.set_response_file_text("not-read.bin");
        result.set_url_text("https://example.invalid/a?x=1&y=2");
        result
            .add_assertion(AssertionResult::new(
                "Known value",
                AssertionOutcome::Passed,
            ))
            .expect("assertion");
        let mut child = SampleResult::new("child");
        child.set_successful(false);
        child
            .set_elapsed(Some(ElapsedTime::from_millis(1)))
            .expect("child");
        result
            .add_sub_result(child, crate::ValidationLimits::default())
            .expect("child");
        let mut vars = VariableSnapshot::new();
        vars.insert("case_id", "jtl-fields");
        vars.insert("comma_value", "left,right");
        SampleEvent::new(result, "run", ThreadIdentity::new("thread"), "host", vars)
    }

    #[test]
    fn xml_aliases_attributes_children_and_entities_round_trip() {
        let mut config = SampleSaveConfiguration::xml();
        config.set_encoding(true);
        config.set_response_data(true);
        config.set_sampler_data(true);
        config.set_response_headers(true);
        config.set_request_headers(true);
        config.set_filename(true);
        config.set_sample_count(true);
        config
            .set_sample_variables(["case_id", "comma_value"])
            .expect("vars");
        config.set_xml_sample_element(XmlSampleElement::HttpSample);
        let source = event();
        let mut bytes = Vec::new();
        let mut encoder = XmlEncoder::new(&mut bytes, config.clone()).expect("encoder");
        encoder.write_event(&source).expect("write");
        encoder.finish().expect("finish");
        let text = String::from_utf8(bytes).expect("utf8");
        assert!(text.contains("<testResults version=\"1.2\">"));
        assert!(text.contains("<httpSample"));
        assert!(text.contains("case_id=\"jtl-fields\""));
        assert!(!text.contains("case__id=\"jtl-fields\""));
        assert!(text.contains("&amp;"));
        let decoded = XmlDecoder::with_sample_variables(
            text.as_bytes(),
            JtlLimits::default(),
            ["case_id", "comma_value"],
        )
        .expect("decoder")
        .decode_all()
        .expect("decode");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].result().sub_results().len(), 1);
        assert_eq!(
            decoded[0]
                .result()
                .response_data()
                .map(|value| value.as_bytes()),
            Some("héllo".as_bytes())
        );
        assert_eq!(
            decoded[0]
                .variables()
                .get("comma_value")
                .and_then(|value| value.as_str()),
            Some("left,right")
        );
    }

    #[test]
    fn xml_line_ending_policy_controls_every_generated_boundary() {
        for line_ending in [LineEnding::Lf, LineEnding::CrLf, LineEnding::Cr] {
            let mut configuration = SampleSaveConfiguration::xml();
            configuration.set_line_ending(line_ending);
            let mut output = Vec::new();
            let mut encoder = XmlEncoder::new(&mut output, configuration).expect("encoder");
            encoder.write_event(&event()).expect("write");
            encoder.finish().expect("finish");

            match line_ending {
                LineEnding::Lf => {
                    assert!(output.contains(&b'\n'));
                    assert!(!output.contains(&b'\r'));
                }
                LineEnding::CrLf => {
                    assert!(output.windows(2).any(|bytes| bytes == b"\r\n"));
                    assert!(
                        output
                            .windows(2)
                            .filter(|bytes| bytes[1] == b'\n')
                            .all(|bytes| bytes[0] == b'\r')
                    );
                }
                LineEnding::Cr => {
                    assert!(output.contains(&b'\r'));
                    assert!(!output.contains(&b'\n'));
                }
            }
            assert!(output.starts_with(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
            assert!(output.ends_with(format!("</testResults>{}", line_ending.as_str()).as_bytes()));
        }
    }

    #[test]
    fn legacy_rs_response_code_is_accepted() {
        let input = br#"<?xml version="1.0"?><testResults version="1.2"><sample rs="201" s="false"/></testResults>"#;
        let events = decode_xml(input.as_slice(), JtlLimits::default()).expect("decode");
        assert_eq!(events[0].result().response_code(), Some("201"));
        let both = br#"<testResults version="1.2"><sample rc="200" rs="201"/></testResults>"#;
        assert!(matches!(
            decode_xml(both.as_slice(), JtlLimits::default()),
            Err(JtlError::Unsupported {
                feature: "xml-sample-attribute-collision",
                ..
            })
        ));
    }

    #[test]
    fn short_url_child_alias_is_accepted() {
        let input = br#"<testResults version="1.2"><sample><url>https://example.invalid/a?x=1&amp;y=2</url></sample></testResults>"#;
        let events = decode_xml(input.as_slice(), JtlLimits::default()).expect("decode");
        assert_eq!(
            events[0].result().url(),
            Some("https://example.invalid/a?x=1&y=2")
        );
    }

    #[test]
    fn save_switches_emit_configured_empty_nodes_and_omit_children() {
        let mut root = SampleResult::new("root");
        root.set_successful(true);
        root.add_sub_result(
            SampleResult::new("child"),
            crate::ValidationLimits::default(),
        )
        .expect("child");
        let event = SampleEvent::new(
            root,
            "run",
            ThreadIdentity::new("thread"),
            "host",
            VariableSnapshot::new(),
        );
        let mut config = SampleSaveConfiguration::xml();
        config.set_response_data(true);
        config.set_filename(true);
        config.set_subresults(false);
        let mut output = Vec::new();
        let mut encoder = XmlEncoder::new(&mut output, config).expect("encoder");
        encoder.write_event(&event).expect("write");
        encoder.finish().expect("finish");
        let text = String::from_utf8(output).expect("utf8");
        assert!(text.contains("<responseData class=\"java.lang.String\"></responseData>"));
        assert!(text.contains("<responseFile class=\"java.lang.String\"></responseFile>"));
        assert!(!text.contains("lb=\"child\""));
    }

    #[test]
    fn xml_variables_preserve_absent_vs_present_empty() {
        let mut variables = VariableSnapshot::new();
        variables.insert_absent("missing");
        variables.insert("empty", "");
        let event = SampleEvent::new(
            SampleResult::new("variables"),
            "",
            ThreadIdentity::new(""),
            "",
            variables,
        );
        let mut configuration = SampleSaveConfiguration::xml();
        configuration
            .set_sample_variables(["missing", "empty"])
            .expect("variables");
        let mut output = Vec::new();
        let mut encoder = XmlEncoder::new(&mut output, configuration.clone()).expect("encoder");
        encoder.write_event(&event).expect("write");
        encoder.finish().expect("finish");
        let text = String::from_utf8(output).expect("UTF-8");
        assert!(!text.contains("missing=\"\""));
        assert!(text.contains("empty=\"\""));
        let decode_configuration = XmlDecodeConfiguration::default()
            .with_sample_variables(["missing", "empty"])
            .expect("decode variables");
        let decoded = decode_xml_with_configuration(
            text.as_bytes(),
            JtlLimits::default(),
            decode_configuration,
        )
        .expect("decode");
        assert_eq!(
            decoded[0].variables().get("missing"),
            Some(&crate::VariableValue::Absent)
        );
        assert_eq!(
            decoded[0]
                .variables()
                .get("empty")
                .and_then(|value| value.as_str()),
            Some("")
        );
    }

    #[test]
    fn xml_writer_enforces_attribute_limit_before_sample_output() {
        let mut variables = VariableSnapshot::new();
        variables.insert("first", "one");
        variables.insert("second", "two");
        let event = SampleEvent::new(
            SampleResult::new("limited"),
            "",
            ThreadIdentity::new(""),
            "",
            variables,
        );
        let mut configuration = SampleSaveConfiguration::xml();
        configuration
            .set_sample_variables(["first", "second"])
            .expect("variables");
        let limits = JtlLimits {
            max_attributes: 1,
            ..JtlLimits::default()
        };
        let mut output = Vec::new();
        let mut encoder = XmlEncoder::new(&mut output, configuration)
            .expect("encoder")
            .with_limits(limits)
            .expect("limits");
        assert!(matches!(
            encoder.write_event(&event),
            Err(JtlError::Unsupported {
                feature: "xml-attribute-limit",
                ..
            })
        ));
    }

    #[test]
    fn xml_node_and_depth_bounds_include_assertion_elements() {
        let mut result = SampleResult::new("assertion-flood");
        result
            .add_assertion(AssertionResult::passed("one"))
            .expect("assertion");
        let event = SampleEvent::new(
            result,
            "run",
            ThreadIdentity::new("thread"),
            "host",
            VariableSnapshot::new(),
        );
        let mut configuration = SampleSaveConfiguration::xml();
        configuration.set_assertion_results(crate::AssertionResults::All);
        let limits = JtlLimits {
            max_nodes: 2,
            ..JtlLimits::default()
        };
        let mut output = Vec::new();
        let mut encoder = XmlEncoder::new(&mut output, configuration.clone())
            .expect("encoder")
            .with_limits(limits)
            .expect("limits");
        assert!(matches!(
            encoder.write_event(&event),
            Err(JtlError::Unsupported {
                feature: "xml-node-limit",
                ..
            })
        ));
        assert!(output.is_empty());

        let limits = JtlLimits {
            max_depth: 3,
            ..JtlLimits::default()
        };
        let mut output = Vec::new();
        let mut encoder = XmlEncoder::new(&mut output, configuration)
            .expect("encoder")
            .with_limits(limits)
            .expect("limits");
        assert!(matches!(
            encoder.write_event(&event),
            Err(JtlError::Unsupported {
                feature: "xml-depth-limit",
                ..
            })
        ));
        assert!(output.is_empty());
    }

    #[test]
    fn xml_node_and_depth_bounds_include_known_payload_elements() {
        let mut result = SampleResult::new("payload-flood");
        result.set_response_data(Some(SampleData::from("body")));
        result.set_response_headers(Some(HeaderBlock::new("response")));
        result.set_request_headers(Some(HeaderBlock::new("request")));
        result.set_response_file_text("response.bin");
        result.set_sampler_data_text("request body");
        result.set_url_text("https://example.invalid/");
        let event = SampleEvent::new(
            result,
            "run",
            ThreadIdentity::new("thread"),
            "host",
            VariableSnapshot::new(),
        );
        let mut configuration = SampleSaveConfiguration::xml();
        configuration.set_response_data(true);
        configuration.set_response_headers(true);
        configuration.set_request_headers(true);
        configuration.set_filename(true);
        configuration.set_sampler_data(true);
        configuration.set_url(true);

        let limits = JtlLimits {
            max_nodes: 2,
            ..JtlLimits::default()
        };
        let mut output = Vec::new();
        let mut encoder = XmlEncoder::new(&mut output, configuration.clone())
            .expect("encoder")
            .with_limits(limits)
            .expect("limits");
        assert!(matches!(
            encoder.write_event(&event),
            Err(JtlError::Unsupported {
                feature: "xml-node-limit",
                ..
            })
        ));
        assert!(output.is_empty());

        let limits = JtlLimits {
            max_depth: 2,
            ..JtlLimits::default()
        };
        let mut output = Vec::new();
        let mut encoder = XmlEncoder::new(&mut output, configuration)
            .expect("encoder")
            .with_limits(limits)
            .expect("limits");
        assert!(matches!(
            encoder.write_event(&event),
            Err(JtlError::Unsupported {
                feature: "xml-depth-limit",
                ..
            })
        ));
        assert!(output.is_empty());
    }

    #[test]
    fn response_file_and_unknown_children_are_retained_without_filesystem_access() {
        let input = br#"<testResults version="1.2" profile="plugin-profile"><sample><responseFile>/no/such/file</responseFile></sample></testResults>"#;
        let events = decode_xml(input.as_slice(), JtlLimits::default()).expect("responseFile");
        assert_eq!(events[0].result().response_file(), Some("/no/such/file"));
        let mut root_output = Vec::new();
        let mut root_encoder =
            XmlEncoder::new(&mut root_output, SampleSaveConfiguration::xml()).expect("encoder");
        root_encoder
            .write_event(&events[0])
            .expect("write root attr");
        root_encoder.finish().expect("finish root attr");
        assert!(
            String::from_utf8(root_output)
                .expect("UTF-8")
                .contains("profile=\"plugin-profile\"")
        );
        let unknown = br#"<testResults version="1.2"><sample><pluginData/></sample></testResults>"#;
        let events = decode_xml(unknown.as_slice(), JtlLimits::default()).expect("unknown child");
        let mut output = Vec::new();
        let mut encoder =
            XmlEncoder::new(&mut output, SampleSaveConfiguration::xml()).expect("encoder");
        encoder
            .write_event(&events[0])
            .expect("write unknown child");
        encoder.finish().expect("finish");
        assert!(
            String::from_utf8(output)
                .expect("UTF-8")
                .contains("<pluginData/>")
        );

        let root_extensions = br#"<testResults version="1.2" profile="plugin-profile"><before/><sample lb="first"/><between flag="yes"><nested>text</nested></between><sample lb="second"/><after/></testResults>"#;
        let events =
            decode_xml(root_extensions.as_slice(), JtlLimits::default()).expect("root extensions");
        assert_eq!(events.len(), 2);
        let mut output = Vec::new();
        let mut encoder =
            XmlEncoder::new(&mut output, SampleSaveConfiguration::xml()).expect("encoder");
        for event in &events {
            encoder.write_event(event).expect("write root extensions");
        }
        encoder.finish().expect("finish root extensions");
        let output = String::from_utf8(output).expect("UTF-8");
        assert!(output.contains("profile=\"plugin-profile\""));
        assert!(output.contains("<between flag=\"yes\">"));
        assert!(output.contains("<nested>"));
        assert!(output.contains("text"));
        assert!(output.contains("</nested>"));
        assert!(output.contains("</between>"));
        assert!(output.contains("<after/>") || output.contains("<after></after>"));
        let before = output.find("<before").expect("before extension");
        let first = output.find("lb=\"first\"").expect("first sample");
        let between = output.find("<between").expect("between extension");
        let second = output.find("lb=\"second\"").expect("second sample");
        let after = output.find("<after").expect("after extension");
        assert!(before < first && first < between && between < second && second < after);
    }

    #[test]
    fn root_version_is_required() {
        let input = br#"<testResults><sample/></testResults>"#;
        assert!(matches!(
            decode_xml(input.as_slice(), JtlLimits::default()),
            Err(JtlError::Xml { detail, .. }) if detail.contains("missing required version")
        ));
    }

    #[test]
    fn root_only_extension_reports_typed_unsupported_detail() {
        let input = br#"<testResults version="1.2"><pluginRoot/></testResults>"#;
        let error = decode_xml(input.as_slice(), JtlLimits::default()).expect_err("extension");
        assert!(matches!(
            error,
            JtlError::Unsupported {
                feature: "xml-root-extension-without-sample",
                value,
            } if value == "root-level XML children cannot be retained without a sample"
        ));
    }

    #[test]
    fn decode_all_with_limit_bounds_retained_event_count() {
        let input = br#"<testResults version="1.2"><sample/><sample/></testResults>"#;
        let error = XmlDecoder::new(input.as_slice(), JtlLimits::default())
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
            XmlDecoder::new(input.as_slice(), JtlLimits::default())
                .expect("decoder")
                .decode_all_with_limit(0),
            Err(JtlError::InvalidConfiguration {
                field: "decode_all_event_limit",
                ..
            })
        ));
        assert!(matches!(
            XmlDecoder::new(input.as_slice(), JtlLimits::default())
                .expect("decoder")
                .decode_all_with_limit(MAX_DECODE_ALL_EVENTS + 1),
            Err(JtlError::InvalidConfiguration {
                field: "decode_all_event_limit",
                ..
            })
        ));
    }

    #[test]
    fn max_samples_allows_exact_xml_eof() {
        let input = br#"<testResults version="1.2"><sample/></testResults>"#;
        let limits = JtlLimits {
            max_samples: 1,
            ..JtlLimits::default()
        };
        let mut decoder = XmlDecoder::new(input.as_slice(), limits).expect("decoder");
        assert!(decoder.next_event().expect("sample").is_some());
        assert!(decoder.next_event().expect("EOF").is_none());
    }

    #[test]
    fn empty_http_sample_closes_and_preserves_absent_optional_fields() {
        let input = br#"<testResults version="1.2"><httpSample/></testResults>"#;
        let events = decode_xml(input.as_slice(), JtlLimits::default()).expect("decode");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].result().success(), None);
        assert_eq!(events[0].result().data_type(), None);
    }

    #[test]
    fn wire_timing_accepts_independent_inequalities() {
        let input =
            br#"<testResults version="1.2"><sample t="1" lt="2" ct="3" it="4"/></testResults>"#;
        let events = decode_xml(input.as_slice(), JtlLimits::default()).expect("decode");
        let result = events[0].result();
        assert_eq!(result.elapsed().map(|value| value.as_millis()), Some(1));
        assert_eq!(result.latency().map(|value| value.as_millis()), Some(2));
        assert_eq!(
            result.connect_time().map(|value| value.as_millis()),
            Some(3)
        );
        assert_eq!(result.idle_time().map(|value| value.as_millis()), Some(4));
        let mut output = Vec::new();
        let mut encoder =
            XmlEncoder::new(&mut output, SampleSaveConfiguration::xml()).expect("encoder");
        encoder.write_event(&events[0]).expect("wire round-trip");
        encoder.finish().expect("finish");
        assert!(
            String::from_utf8(output)
                .expect("UTF-8")
                .contains("t=\"1\"")
        );
    }

    #[test]
    fn unknown_attributes_are_opaque_and_configured_names_are_not_rewritten() {
        let unknown = br#"<testResults version="1.2"><sample plugin__value="x"/></testResults>"#;
        let events = decode_xml(unknown.as_slice(), JtlLimits::default()).expect("unknown attr");
        let mut output = Vec::new();
        let mut encoder =
            XmlEncoder::new(&mut output, SampleSaveConfiguration::xml()).expect("encoder");
        encoder.write_event(&events[0]).expect("write unknown attr");
        encoder.finish().expect("finish");
        assert!(
            String::from_utf8(output)
                .expect("UTF-8")
                .contains("plugin__value=\"x\"")
        );
        let configuration = XmlDecodeConfiguration::default()
            .with_sample_variables(["plugin_value"])
            .expect("configuration");
        let events =
            decode_xml_with_configuration(unknown.as_slice(), JtlLimits::default(), configuration)
                .expect("configured variable");
        assert_eq!(
            events[0]
                .variables()
                .get("plugin_value")
                .and_then(|value| value.as_str()),
            Some("x")
        );

        let legacy_spelling =
            br#"<testResults version="1.2"><sample plugin_value="legacy"/></testResults>"#;
        let events = XmlDecoder::with_sample_variables(
            legacy_spelling.as_slice(),
            JtlLimits::default(),
            ["plugin_value"],
        )
        .expect("legacy configured spelling")
        .decode_all()
        .expect("decode legacy spelling");
        assert_eq!(
            events[0]
                .variables()
                .get("plugin_value")
                .and_then(|value| value.as_str()),
            Some("legacy")
        );

        let extension_configuration =
            XmlDecodeConfiguration::new().with_reject_unknown_attributes(false);
        let events = decode_xml_with_configuration(
            unknown.as_slice(),
            JtlLimits::default(),
            extension_configuration,
        )
        .expect("exact extension attribute");
        assert_eq!(
            events[0]
                .variables()
                .get("plugin__value")
                .and_then(|value| value.as_str()),
            Some("x")
        );

        let assertion = br#"<testResults version="1.2"><sample><assertionResult class="plugin.Assertion"><name>check</name><failure>false</failure><error>false</error></assertionResult></sample></testResults>"#;
        let events = decode_xml(assertion.as_slice(), JtlLimits::default()).expect("assertion");
        let mut configuration = SampleSaveConfiguration::xml();
        configuration.set_assertion_results(crate::AssertionResults::All);
        let mut output = Vec::new();
        let mut encoder = XmlEncoder::new(&mut output, configuration).expect("encoder");
        encoder.write_event(&events[0]).expect("write assertion");
        encoder.finish().expect("finish assertion");
        assert!(
            String::from_utf8(output)
                .expect("UTF-8")
                .contains("class=\"plugin.Assertion\"")
        );
    }

    #[test]
    fn duplicate_singleton_children_and_assertion_fields_are_rejected() {
        let duplicate = br#"<testResults version="1.2"><sample><responseData/><responseData/></sample></testResults>"#;
        assert!(matches!(
            decode_xml(duplicate.as_slice(), JtlLimits::default()),
            Err(JtlError::Xml { detail, .. }) if detail.contains("duplicate")
        ));
        let duplicate_assertion = br#"<testResults version="1.2"><sample><assertionResult failure="false"><failure>true</failure></assertionResult></sample></testResults>"#;
        assert!(matches!(
            decode_xml(duplicate_assertion.as_slice(), JtlLimits::default()),
            Err(JtlError::Xml { detail, .. }) if detail.contains("duplicate")
        ));
    }

    #[test]
    fn noncanonical_known_and_opaque_child_order_is_rejected() {
        let sample_order =
            br#"<testResults version="1.2"><sample><responseData/><assertionResult/></sample></testResults>"#;
        assert!(matches!(
            decode_xml(sample_order.as_slice(), JtlLimits::default()),
            Err(JtlError::Unsupported {
                feature: "xml-child-order",
                ..
            })
        ));

        let assertion_order = br#"<testResults version="1.2"><sample><assertionResult><error>false</error><name>late</name></assertionResult></sample></testResults>"#;
        assert!(matches!(
            decode_xml(assertion_order.as_slice(), JtlLimits::default()),
            Err(JtlError::Unsupported {
                feature: "xml-child-order",
                ..
            })
        ));

        let opaque_order = br#"<testResults version="1.2"><sample><pluginData/><responseData/></sample></testResults>"#;
        assert!(matches!(
            decode_xml(opaque_order.as_slice(), JtlLimits::default()),
            Err(JtlError::Unsupported {
                feature: "xml-child-order",
                ..
            })
        ));
    }

    #[test]
    fn invalid_controls_and_binary_response_data_are_explicit_errors() {
        let invalid = b"<testResults version=\"1.2\"><sample lb=\"bad\x01value\"/></testResults>";
        assert!(matches!(
            decode_xml(invalid.as_slice(), JtlLimits::default()),
            Err(JtlError::Xml { .. })
        ));
        let mut result = SampleResult::new("binary");
        result.set_response_data(Some(SampleData::new(vec![0xff])));
        let event = SampleEvent::new(
            result,
            "run",
            ThreadIdentity::new("thread"),
            "host",
            VariableSnapshot::new(),
        );
        let mut configuration = SampleSaveConfiguration::xml();
        configuration.set_response_data(true);
        let mut output = Vec::new();
        let mut encoder = XmlEncoder::new(&mut output, configuration).expect("encoder");
        assert!(matches!(
            encoder.write_event(&event),
            Err(JtlError::Unsupported {
                feature: "xml-binary-response-data",
                ..
            })
        ));
        let binary_input = br#"<testResults version="1.2"><sample dt="bin"><responseData>not-a-binary-adapter</responseData></sample></testResults>"#;
        assert!(matches!(
            decode_xml(binary_input.as_slice(), JtlLimits::default()),
            Err(JtlError::Unsupported {
                feature: "xml-binary-response-data",
                ..
            })
        ));
    }

    #[test]
    fn assertion_failure_and_error_flags_round_trip() {
        let input = br#"<testResults version="1.2"><sample><assertionResult failure="true" error="true"/></sample></testResults>"#;
        let events = decode_xml(input.as_slice(), JtlLimits::default()).expect("decode");
        let assertion = &events[0].result().assertions()[0];
        assert!(assertion.is_failure());
        assert!(assertion.is_error());
        let mut configuration = SampleSaveConfiguration::xml();
        configuration.set_assertion_results(crate::AssertionResults::All);
        let mut output = Vec::new();
        let mut encoder = XmlEncoder::new(&mut output, configuration).expect("encoder");
        encoder.write_event(&events[0]).expect("write");
        encoder.finish().expect("finish");
        let text = String::from_utf8(output).expect("UTF-8");
        assert!(text.contains("<failure>true</failure>"));
        assert!(text.contains("<error>true</error>"));
    }

    #[test]
    fn assertion_children_are_ordered_and_messages_ignore_csv_switch() {
        let mut result = SampleResult::new("assertion");
        result
            .add_assertion(
                AssertionResult::from_flags(
                    "name",
                    true,
                    true,
                    Some("failure message".to_owned()),
                    Some("error message".to_owned()),
                )
                .expect("assertion"),
            )
            .expect("assertion");
        let event = SampleEvent::new(
            result,
            "run",
            ThreadIdentity::new("thread"),
            "host",
            VariableSnapshot::new(),
        );
        let mut config = SampleSaveConfiguration::xml();
        config.set_assertion_results(crate::AssertionResults::All);
        config.set_assertion_results_failure_message(false);
        let mut output = Vec::new();
        let mut encoder = XmlEncoder::new(&mut output, config).expect("encoder");
        encoder.write_event(&event).expect("write");
        encoder.finish().expect("finish");
        let text = String::from_utf8(output).expect("UTF-8");
        let name = text.find("<name>name</name>").expect("name");
        let failure = text.find("<failure>true</failure>").expect("failure");
        let error = text.find("<error>true</error>").expect("error");
        let failure_message = text.find("<failureMessage").expect("failure message");
        let error_message = text.find("<errorMessage").expect("error message");
        assert!(name < failure && failure < error && error < failure_message);
        assert!(failure_message < error_message);
    }

    #[test]
    fn xml_timestamp_is_millisecond_and_uses_start_switch() {
        let mut result = SampleResult::new("timestamp");
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
        let mut config = SampleSaveConfiguration::xml();
        config.set_timestamp_start(true);
        config.set_timestamp_format(crate::TimestampFormat::None);
        let mut output = Vec::new();
        let mut encoder = XmlEncoder::new(&mut output, config).expect("encoder");
        encoder.write_event(&event).expect("write");
        encoder.finish().expect("finish");
        assert!(
            String::from_utf8(output)
                .expect("UTF-8")
                .contains("ts=\"100\"")
        );
    }

    #[test]
    fn xml_sample_and_error_count_switches_are_coupled() {
        let mut result = SampleResult::new("counts");
        result.set_sample_count(Some(crate::SampleCount::from_u64(2)));
        result.set_error_count(Some(crate::ErrorCount::from_u64(1)));
        let event = SampleEvent::new(
            result,
            "run",
            ThreadIdentity::new("thread"),
            "host",
            VariableSnapshot::new(),
        );
        let mut configuration = SampleSaveConfiguration::xml();
        configuration.set_sample_count(false);
        configuration.set_error_count(true);
        let mut output = Vec::new();
        let mut encoder = XmlEncoder::new(&mut output, configuration).expect("encoder");
        encoder.write_event(&event).expect("write");
        encoder.finish().expect("finish");
        let text = String::from_utf8(output).expect("UTF-8");
        assert!(text.contains(" sc=\"2\""));
        assert!(text.contains(" ec=\"1\""));
    }

    #[test]
    fn xml_count_switch_is_counted_for_both_attributes() {
        let mut result = SampleResult::new("error-count");
        result.set_error_count(Some(crate::ErrorCount::from_u64(1)));
        let event = SampleEvent::new(
            result,
            "run",
            ThreadIdentity::new("thread"),
            "host",
            VariableSnapshot::new(),
        );
        let mut configuration = SampleSaveConfiguration::xml();
        configuration.set_sample_count(false);
        configuration.set_error_count(true);
        configuration.set_time(false);
        configuration.set_idle_time(false);
        configuration.set_latency(false);
        configuration.set_connect_time(false);
        configuration.set_timestamp(false);
        configuration.set_success(false);
        configuration.set_label(false);
        configuration.set_response_code(false);
        configuration.set_response_message(false);
        configuration.set_thread_name(false);
        configuration.set_data_type(false);
        configuration.set_bytes(false);
        configuration.set_sent_bytes(false);
        configuration.set_thread_counts(false);
        configuration.set_hostname(false);
        let limits = JtlLimits {
            max_attributes: 1,
            ..JtlLimits::default()
        };
        let mut output = Vec::new();
        let mut encoder = XmlEncoder::new(&mut output, configuration)
            .expect("encoder")
            .with_limits(limits)
            .expect("limits");
        assert!(matches!(
            encoder.write_event(&event),
            Err(JtlError::Unsupported {
                feature: "xml-attribute-limit",
                ..
            })
        ));
        assert!(output.is_empty());
    }

    #[test]
    fn xml_sample_close_is_checked_against_output_bound() {
        let event = SampleEvent::new(
            SampleResult::new("ignored-by-switches"),
            "run",
            ThreadIdentity::new("thread"),
            "host",
            VariableSnapshot::new(),
        );
        let mut configuration = SampleSaveConfiguration::xml();
        configuration.set_time(false);
        configuration.set_idle_time(false);
        configuration.set_latency(false);
        configuration.set_connect_time(false);
        configuration.set_timestamp(false);
        configuration.set_success(false);
        configuration.set_label(false);
        configuration.set_response_code(false);
        configuration.set_response_message(false);
        configuration.set_thread_name(false);
        configuration.set_data_type(false);
        configuration.set_encoding(false);
        configuration.set_bytes(false);
        configuration.set_sent_bytes(false);
        configuration.set_thread_counts(false);
        configuration.set_hostname(false);
        configuration.set_sample_count(false);
        configuration.set_error_count(false);
        let mut output = Vec::new();
        let mut encoder = XmlEncoder::new(&mut output, configuration).expect("encoder");
        encoder.write_header().expect("header");
        let limits = JtlLimits {
            max_record_bytes: 9,
            ..JtlLimits::default()
        };
        let mut encoder = encoder.with_limits(limits).expect("limits");
        assert!(matches!(
            encoder.write_event(&event),
            Err(JtlError::Unsupported {
                feature: "xml-record-limit",
                ..
            })
        ));
    }

    #[test]
    fn xml_event_output_is_atomic_when_nested_payload_exceeds_record_limit() {
        let mut root = SampleResult::new("root");
        let mut child = SampleResult::new("child");
        child.set_response_data(Some(SampleData::from("payload-too-long")));
        root.add_sub_result(child, crate::ValidationLimits::default())
            .expect("nested result");
        let event = SampleEvent::new(
            root,
            "run",
            ThreadIdentity::new("thread"),
            "host",
            VariableSnapshot::new(),
        );
        let mut configuration = SampleSaveConfiguration::xml();
        configuration.set_time(false);
        configuration.set_idle_time(false);
        configuration.set_latency(false);
        configuration.set_connect_time(false);
        configuration.set_timestamp(false);
        configuration.set_success(false);
        configuration.set_label(true);
        configuration.set_response_code(false);
        configuration.set_response_message(false);
        configuration.set_thread_name(false);
        configuration.set_data_type(false);
        configuration.set_encoding(false);
        configuration.set_bytes(false);
        configuration.set_sent_bytes(false);
        configuration.set_thread_counts(false);
        configuration.set_hostname(false);
        configuration.set_sample_count(false);
        configuration.set_response_data(true);
        let limits = JtlLimits {
            max_record_bytes: 32,
            ..JtlLimits::default()
        };
        let mut output = Vec::new();
        let mut encoder = XmlEncoder::new(&mut output, configuration)
            .expect("encoder")
            .with_limits(limits)
            .expect("limits");
        assert!(matches!(
            encoder.write_event(&event),
            Err(JtlError::Unsupported {
                feature: "xml-record-limit",
                ..
            })
        ));
        assert!(
            output.is_empty(),
            "declaration/root/sample prefixes must not survive event failure"
        );
    }

    #[test]
    fn xml_aggregate_output_limit_rejects_event_before_commit() {
        let event = SampleEvent::new(
            SampleResult::new("root"),
            "run",
            ThreadIdentity::new("thread"),
            "host",
            VariableSnapshot::new(),
        );
        let mut configuration = SampleSaveConfiguration::xml();
        configuration.set_time(false);
        configuration.set_idle_time(false);
        configuration.set_latency(false);
        configuration.set_connect_time(false);
        configuration.set_timestamp(false);
        configuration.set_success(false);
        configuration.set_label(true);
        configuration.set_response_code(false);
        configuration.set_response_message(false);
        configuration.set_thread_name(false);
        configuration.set_data_type(false);
        configuration.set_encoding(false);
        configuration.set_bytes(false);
        configuration.set_sent_bytes(false);
        configuration.set_thread_counts(false);
        configuration.set_hostname(false);
        configuration.set_sample_count(false);
        let mut encoder = XmlEncoder::new(Vec::new(), configuration).expect("encoder");
        encoder.write_header().expect("header");
        let header_len = encoder.writer.len();
        let limits = JtlLimits {
            max_output_bytes: header_len + 1,
            ..JtlLimits::default()
        };
        encoder = encoder.with_limits(limits).expect("limits");
        assert!(matches!(
            encoder.write_event(&event),
            Err(JtlError::Unsupported {
                feature: "output-limit",
                ..
            })
        ));
        let output = encoder.into_inner();
        assert_eq!(output.len(), header_len);
    }

    #[test]
    fn nested_wire_metadata_and_aliases_survive_xml_round_trip() {
        let input = br#"<testResults version="1.2"><httpSample tn="root-thread" hn="root-host" root__var="root"><sample tn="child-thread" hn="child-host" child__var="child"/></httpSample></testResults>"#;
        let decode_configuration = XmlDecodeConfiguration::new()
            .with_sample_variables(["root_var", "child_var"])
            .expect("decode variables");
        let events = decode_xml_with_configuration(
            input.as_slice(),
            JtlLimits::default(),
            decode_configuration,
        )
        .expect("decode");
        let mut config = SampleSaveConfiguration::xml();
        config.set_xml_sample_element(XmlSampleElement::Sample);
        config.set_thread_name(true);
        config.set_hostname(true);
        config
            .set_sample_variables(["root_var", "child_var"])
            .expect("variables");
        let mut output = Vec::new();
        let mut encoder = XmlEncoder::new(&mut output, config).expect("encoder");
        encoder.write_event(&events[0]).expect("write");
        encoder.finish().expect("finish");
        let text = String::from_utf8(output).expect("UTF-8");
        assert!(text.contains("<httpSample"));
        assert!(text.contains("tn=\"child-thread\""));
        assert!(text.contains("hn=\"child-host\""));
        assert!(text.contains("child_var=\"child\""));
    }

    #[test]
    fn xml_thread_and_host_attributes_preserve_absent_vs_present_empty() {
        let input = br#"<testResults version="1.2"><sample/><sample tn="" hn=""/></testResults>"#;
        let events = decode_xml(input.as_slice(), JtlLimits::default()).expect("decode");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].result().wire_thread_name(), None);
        assert_eq!(events[0].result().wire_host(), None);
        assert_eq!(events[1].result().wire_thread_name(), Some(""));
        assert_eq!(events[1].result().wire_host(), Some(""));

        let mut output = Vec::new();
        let mut configuration = SampleSaveConfiguration::xml();
        configuration.set_thread_name(true);
        configuration.set_hostname(true);
        let mut encoder = XmlEncoder::new(&mut output, configuration).expect("encoder");
        for event in &events {
            encoder.write_event(event).expect("write");
        }
        encoder.finish().expect("finish");
        let text = String::from_utf8(output).expect("UTF-8");
        let sample_lines = text
            .lines()
            .filter(|line| line.starts_with("<sample"))
            .collect::<Vec<_>>();
        assert_eq!(sample_lines.len(), 2);
        assert!(!sample_lines[0].contains(" tn="));
        assert!(!sample_lines[0].contains(" hn="));
        assert!(sample_lines[1].contains(" tn=\"\""));
        assert!(sample_lines[1].contains(" hn=\"\""));
    }

    #[test]
    fn public_xml_header_rejects_later_root_metadata_instead_of_dropping_it() {
        let mut result = SampleResult::new("root-metadata");
        result.set_wire_xml_root_metadata(
            vec![("pluginRoot".to_owned(), "retained".to_owned())],
            Vec::new(),
        );
        let event = SampleEvent::new(
            result,
            "run",
            ThreadIdentity::new("thread"),
            "host",
            VariableSnapshot::new(),
        );
        let mut output = Vec::new();
        let mut encoder =
            XmlEncoder::new(&mut output, SampleSaveConfiguration::xml()).expect("encoder");
        encoder.write_header().expect("header");
        assert!(matches!(
            encoder.write_event(&event),
            Err(JtlError::Unsupported {
                feature: "xml-root-attributes-after-header",
                ..
            })
        ));
        assert!(
            !output
                .windows(b"pluginRoot".len())
                .any(|window| window == b"pluginRoot")
        );
    }

    #[test]
    fn nested_xml_variables_do_not_fall_back_to_root_event_scope() {
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
        let mut configuration = SampleSaveConfiguration::xml();
        configuration
            .set_sample_variables(["shared"])
            .expect("variables");
        let mut output = Vec::new();
        let mut encoder = XmlEncoder::new(&mut output, configuration).expect("encoder");
        encoder.write_event(&event).expect("write");
        encoder.finish().expect("finish");
        let text = String::from_utf8(output).expect("UTF-8");
        assert_eq!(text.matches("shared=\"root-value\"").count(), 1);
        let child = text.find("lb=\"root-0\"").expect("child");
        assert!(!text[child..].contains("shared=\"root-value\""));
    }

    #[test]
    fn response_data_on_error_does_not_enable_sampler_data() {
        let mut result = SampleResult::new("failed");
        result.set_successful(false);
        result.set_response_data(Some(SampleData::from("body")));
        result.set_sampler_data_text("request");
        let event = SampleEvent::new(
            result,
            "run",
            ThreadIdentity::new("thread"),
            "host",
            VariableSnapshot::new(),
        );
        let mut config = SampleSaveConfiguration::xml();
        config.set_response_data_on_error(true);
        config.set_sampler_data(false);
        let mut output = Vec::new();
        let mut encoder = XmlEncoder::new(&mut output, config).expect("encoder");
        encoder.write_event(&event).expect("write");
        encoder.finish().expect("finish");
        let text = String::from_utf8(output).expect("UTF-8");
        assert!(text.contains("<responseData"));
        assert!(!text.contains("<samplerData"));
    }

    #[test]
    fn xml_subresult_renaming_and_deep_write_are_bounded() {
        let mut root = SampleResult::new("root");
        root.add_sub_result(
            SampleResult::new("child"),
            crate::ValidationLimits::default(),
        )
        .expect("child");
        let event = SampleEvent::new(
            root,
            "run",
            ThreadIdentity::new("thread"),
            "host",
            VariableSnapshot::new(),
        );
        let mut configuration = SampleSaveConfiguration::xml();
        configuration.set_subresults_disable_renaming(false);
        let mut output = Vec::new();
        let mut encoder = XmlEncoder::new(&mut output, configuration.clone()).expect("encoder");
        encoder.write_event(&event).expect("write");
        encoder.finish().expect("finish");
        let text = String::from_utf8(output).expect("UTF-8");
        assert!(text.contains("lb=\"root-0\""));

        configuration.set_subresults_disable_renaming(true);
        let limits = JtlLimits {
            max_depth: 300,
            max_nodes: 512,
            ..JtlLimits::default()
        };
        let validation = crate::ValidationLimits::new(300, 512).expect("limits");
        let mut leaf = SampleResult::new("leaf");
        for index in 0..256 {
            let mut parent = SampleResult::new(format!("node-{index}"));
            parent
                .try_add_sub_result_raw(leaf, validation)
                .expect("nested result");
            leaf = parent;
        }
        let event = SampleEvent::new(
            leaf,
            "run",
            ThreadIdentity::new("thread"),
            "host",
            VariableSnapshot::new(),
        );
        let mut output = Vec::new();
        let mut encoder = XmlEncoder::new(&mut output, configuration)
            .expect("encoder")
            .with_limits(limits)
            .expect("limits");
        encoder.write_event(&event).expect("deep write");
        encoder.finish().expect("finish");
        assert_eq!(
            String::from_utf8(output)
                .expect("UTF-8")
                .matches("<sample")
                .count(),
            257
        );
    }

    #[test]
    fn malformed_xml_and_limits_are_rejected() {
        let malformed = br#"<testResults version="1.2"><sample></testResults>"#;
        assert!(matches!(
            decode_xml(malformed.as_slice(), JtlLimits::default()),
            Err(JtlError::Xml { .. })
        ));
        let limits = JtlLimits {
            max_depth: 1,
            ..JtlLimits::default()
        };
        let deep = br#"<testResults version="1.2"><sample><sample/></sample></testResults>"#;
        assert!(matches!(
            decode_xml(deep.as_slice(), limits),
            Err(JtlError::Unsupported {
                feature: "xml-depth-limit",
                ..
            })
        ));
        let limits = JtlLimits {
            max_input_bytes: 16,
            ..JtlLimits::default()
        };
        let oversized = br#"<testResults version="1.2"></testResults>"#;
        assert!(matches!(
            decode_xml(oversized.as_slice(), limits),
            Err(JtlError::Unsupported {
                feature: "input-size-limit",
                ..
            })
        ));
        let limits = JtlLimits {
            max_record_bytes: 4,
            ..JtlLimits::default()
        };
        let long_text =
            br#"<testResults version="1.2"><sample><responseData>12345</responseData></sample></testResults>"#;
        assert!(matches!(
            decode_xml(long_text.as_slice(), limits),
            Err(JtlError::Xml { detail, .. }) if detail.contains("text node exceeds")
        ));
    }
}
