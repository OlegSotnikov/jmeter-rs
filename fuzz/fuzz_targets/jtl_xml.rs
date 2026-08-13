#![no_main]

//! Bounded JTL XML decoder/encoder target.
//!
//! Every XML sample attribute and supported payload child is enabled.  A
//! typed projection of the resulting XML wire model is compared before and
//! after encode/decode, including assertion flags, text children, variables,
//! and nested results.  XML-only fields are intentionally kept separate from
//! CSV projections so an omitted field cannot hide behind a generic equality
//! check.  A canonical wire serialization check additionally covers retained
//! XML attributes/children, assertion extension trees, sample element
//! identity, nested per-node metadata, and absent-versus-present-empty
//! fields.  It normalizes only bare line-ending boundaries that the current
//! encoder adds around opaque children; all other bytes remain compared.
//!
//! Invariants: `JTL-XML-PROJECTION-001` compares every enabled XML attribute,
//! payload child, assertion, variable, and nested result; `JTL-XML-WIRE-001`
//! compares the configured wire projection and canonical XML structure
//! (including opaque XML metadata); its focused source sub-probe,
//! `JTL-XML-WIRE-PROBE-001`, fixes
//! sample-child order, root extension placement, recursive unknown trees, and
//! absent-versus-present-empty fields.  The source-side inventory independently
//! checks opaque attributes/trees, sample identity, and ordering, while a
//! bounded failing-reader probe covers interrupted/I/O input.  Finally,
//! `JTL-XML-LIMIT-001` retains the bounded input, record, depth, node, and
//! sample policy.
//! Source-side coverage: raw XML opaque attributes/trees, sample identity, and
//! child order are inventoried before decoder projection or re-encoding.
//! I/O policy: none; interrupted readers are synthetic in-memory fixtures.

use std::io::{self, ErrorKind, Read};

use jmeter_rs_results::{
    AssertionResults, CsvField, JtlLimits, SampleEvent, SampleResult, SampleSaveConfiguration,
    XmlDecodeConfiguration, XmlDecoder, XmlEncoder,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 256 * 1024;

fn limits() -> JtlLimits {
    JtlLimits::new(MAX_INPUT_BYTES, 16 * 1024, 4 * 1024, 64, 16, 512, 128, 64)
        .expect("fuzz target constants must define non-zero limits")
}

fn oversized_probe() -> Vec<u8> {
    // Each sample remains within the attribute bound; the stream crosses the
    // input bound while staying below the node and sample limits.
    let mut input = Vec::with_capacity(MAX_INPUT_BYTES + 16 * 1024);
    input.extend_from_slice(b"<testResults version=\"1.2\">");
    for _ in 0..128 {
        input.extend_from_slice(b"<sample lb=\"");
        input.extend(std::iter::repeat_n(b'a', 2 * 1024));
        input.extend_from_slice(b"\"/>");
    }
    input.extend_from_slice(b"</testResults>");
    input
}

fn configuration() -> SampleSaveConfiguration {
    let mut configuration = SampleSaveConfiguration::xml();
    configuration.set_timestamp(true);
    configuration.set_time(true);
    configuration.set_label(true);
    configuration.set_response_code(true);
    configuration.set_response_message(true);
    configuration.set_thread_name(true);
    configuration.set_data_type(true);
    configuration.set_encoding(true);
    configuration.set_success(true);
    configuration.set_assertion_results(AssertionResults::All);
    configuration.set_assertion_results_failure_message(true);
    configuration.set_response_data(true);
    configuration.set_response_data_on_error(true);
    configuration.set_sampler_data(true);
    configuration.set_response_headers(true);
    configuration.set_request_headers(true);
    configuration.set_bytes(true);
    configuration.set_sent_bytes(true);
    configuration.set_url(true);
    configuration.set_filename(true);
    configuration.set_hostname(true);
    configuration.set_thread_counts(true);
    configuration.set_sample_count(true);
    configuration.set_latency(true);
    configuration.set_idle_time(true);
    configuration.set_connect_time(true);
    // XML has a native hierarchy.  Keep labels as supplied so the projection
    // checks result identity rather than JMeter's optional child renaming.
    configuration.set_subresults(true);
    configuration.set_subresults_disable_renaming(true);
    configuration
        .set_sample_variables(["case_id", "region"])
        .expect("static sample-variable names are valid");
    configuration
}

fn decode_configuration() -> XmlDecodeConfiguration {
    XmlDecodeConfiguration::new()
        .with_sample_variables(["case_id", "region"])
        .expect("static sample-variable names are valid")
}

fn wire_probe_configuration() -> SampleSaveConfiguration {
    // Keep the fixed wire probe focused on opaque XML and optional-state
    // fidelity.  Disabling default save columns avoids manufacturing fields
    // that were absent from the source fixture while still exercising sample
    // identity, per-node metadata, assertions, sub-results, variables, and
    // present-empty sampler data.
    let mut configuration = SampleSaveConfiguration::xml();
    configuration.set_time(false);
    configuration.set_latency(false);
    configuration.set_connect_time(false);
    configuration.set_timestamp(false);
    configuration.set_success(false);
    configuration.set_label(true);
    configuration.set_response_code(false);
    configuration.set_response_message(false);
    configuration.set_thread_name(true);
    configuration.set_data_type(false);
    configuration.set_encoding(false);
    configuration.set_response_data(false);
    configuration.set_response_data_on_error(false);
    configuration.set_sampler_data(true);
    configuration.set_response_headers(false);
    configuration.set_request_headers(false);
    configuration.set_bytes(false);
    configuration.set_sent_bytes(false);
    configuration.set_url(false);
    configuration.set_filename(false);
    configuration.set_hostname(true);
    configuration.set_thread_counts(false);
    configuration.set_sample_count(false);
    configuration.set_idle_time(false);
    configuration.set_assertion_results(AssertionResults::All);
    configuration.set_assertion_results_failure_message(true);
    configuration.set_subresults(true);
    configuration.set_subresults_disable_renaming(true);
    configuration
        .set_sample_variables(["case_id", "region"])
        .expect("static sample-variable names are valid");
    configuration
}

fn assert_wire_markers_in_order(text: &str, markers: &[&str]) {
    if markers.is_empty() {
        return;
    }
    let actual = text
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .filter(|line| markers.contains(line))
        .collect::<Vec<_>>();
    if actual.as_slice() == markers {
        return;
    }
    let mismatch = actual
        .iter()
        .zip(markers)
        .position(|(found, expected)| found != expected)
        .unwrap_or(actual.len().min(markers.len()));
    panic!(
        "fixed JTL probe changed marker order or count at position {mismatch}: expected {:?}, found {:?}",
        markers.get(mismatch),
        actual.get(mismatch)
    );
}

fn canonical_xml_layout(bytes: &[u8]) -> Vec<u8> {
    // XmlEncoder emits bare line-ending boundaries around opaque children.
    // Those formatting-only boundaries are normalized while all other bytes
    // (including indentation and whitespace text) remain compared.
    let mut canonical = Vec::with_capacity(bytes.len());
    for line in bytes.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        // The writer contributes bare line endings around opaque children.
        // Drop only those empty lines; indentation or whitespace text carried
        // by an opaque node remains part of the compared wire content.
        if line.is_empty() {
            continue;
        }
        if !canonical.is_empty() {
            canonical.push(b'\n');
        }
        canonical.extend_from_slice(line);
    }
    canonical
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawXmlNode {
    name: String,
    attributes: Vec<(String, String)>,
    content: Vec<RawXmlPart>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RawXmlPart {
    Text(String),
    Child(RawXmlNode),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawXmlInventory {
    root_attributes: Vec<(String, String)>,
    root_order: Vec<RawXmlRootItem>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RawXmlRootItem {
    Sample(RawXmlSample),
    Opaque(RawXmlNode),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawXmlSample {
    element: String,
    variables: Vec<(String, String)>,
    unknown_attributes: Vec<(String, String)>,
    children: Vec<RawXmlSampleChild>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RawXmlSampleChild {
    Assertion(RawXmlAssertion),
    Sample(RawXmlSample),
    Opaque(RawXmlNode),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawXmlAssertion {
    unknown_attributes: Vec<(String, String)>,
    children: Vec<RawXmlAssertionChild>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RawXmlAssertionChild {
    Opaque(RawXmlNode),
}

#[derive(Clone, Debug)]
enum RawXmlToken {
    Start {
        name: String,
        attributes: Vec<(String, String)>,
        empty: bool,
    },
    End(String),
    Text(String),
}

struct RawXmlParser<'a> {
    input: &'a [u8],
    offset: usize,
    max_record_bytes: usize,
    max_attribute_bytes: usize,
    max_depth: usize,
    max_nodes: usize,
    nodes: usize,
}

impl<'a> RawXmlParser<'a> {
    fn new(input: &'a [u8], max_input_bytes: usize) -> Option<Self> {
        if input.len() > max_input_bytes {
            return None;
        }
        let bounds = limits();
        Some(Self {
            input,
            offset: if input.starts_with(b"\xef\xbb\xbf") {
                3
            } else {
                0
            },
            max_record_bytes: bounds.max_record_bytes,
            max_attribute_bytes: bounds.max_attribute_bytes,
            max_depth: bounds.max_depth,
            max_nodes: bounds.max_nodes,
            nodes: 0,
        })
    }

    fn parse(mut self) -> Option<RawXmlNode> {
        let mut stack = Vec::<RawXmlNode>::new();
        let mut root = None;
        while let Some(token) = self.next().ok()? {
            match token {
                RawXmlToken::Start {
                    name,
                    attributes,
                    empty,
                } => {
                    self.nodes = self.nodes.checked_add(1)?;
                    if self.nodes > self.max_nodes || stack.len() + 1 > self.max_depth {
                        return None;
                    }
                    let node = RawXmlNode {
                        name,
                        attributes,
                        content: Vec::new(),
                    };
                    if empty {
                        Self::attach(&mut stack, &mut root, node)?;
                    } else {
                        stack.push(node);
                    }
                }
                RawXmlToken::End(name) => {
                    let node = stack.pop()?;
                    if node.name != name {
                        return None;
                    }
                    Self::attach(&mut stack, &mut root, node)?;
                }
                RawXmlToken::Text(value) => {
                    if let Some(parent) = stack.last_mut() {
                        parent.content.push(RawXmlPart::Text(value));
                    } else if !value.trim().is_empty() {
                        return None;
                    }
                }
            }
        }
        if !stack.is_empty() {
            return None;
        }
        let mut root = root?;
        if root.name != "testResults"
            || !root
                .attributes
                .iter()
                .any(|(name, value)| name == "version" && value == "1.2")
        {
            return None;
        }
        normalize_raw_xml_node(&mut root);
        Some(root)
    }

    fn attach(
        stack: &mut [RawXmlNode],
        root: &mut Option<RawXmlNode>,
        node: RawXmlNode,
    ) -> Option<()> {
        if let Some(parent) = stack.last_mut() {
            parent.content.push(RawXmlPart::Child(node));
            return Some(());
        }
        if root.is_some() {
            return None;
        }
        *root = Some(node);
        Some(())
    }

    fn next(&mut self) -> Result<Option<RawXmlToken>, ()> {
        loop {
            if self.offset >= self.input.len() {
                return Ok(None);
            }
            if self.input[self.offset..].starts_with(b"<!--") {
                self.skip_until(b"-->")?;
                continue;
            }
            if self.input[self.offset..].starts_with(b"<?") {
                self.skip_until(b"?>")?;
                continue;
            }
            return self.next_token().map(Some);
        }
    }

    fn next_token(&mut self) -> Result<RawXmlToken, ()> {
        if self.input[self.offset..].starts_with(b"<![CDATA[") {
            self.offset = self.offset.checked_add(9).ok_or(())?;
            let end = find_bytes(&self.input[self.offset..], b"]]>").ok_or(())?;
            let value =
                std::str::from_utf8(&self.input[self.offset..self.offset + end]).map_err(|_| ())?;
            if value.len() > self.max_record_bytes {
                return Err(());
            }
            self.offset = self.offset.checked_add(end + 3).ok_or(())?;
            return Ok(RawXmlToken::Text(value.to_owned()));
        }
        if self.input[self.offset..].starts_with(b"<!DOCTYPE")
            || self.input[self.offset..].starts_with(b"<!ENTITY")
        {
            return Err(());
        }
        if self.input[self.offset] != b'<' {
            let start = self.offset;
            while self.offset < self.input.len() && self.input[self.offset] != b'<' {
                self.offset += 1;
            }
            let raw = std::str::from_utf8(&self.input[start..self.offset]).map_err(|_| ())?;
            if raw.len() > self.max_record_bytes {
                return Err(());
            }
            return Ok(RawXmlToken::Text(decode_xml_entities(raw)?));
        }
        self.offset = self.offset.checked_add(1).ok_or(())?;
        if self.input.get(self.offset) == Some(&b'/') {
            self.offset = self.offset.checked_add(1).ok_or(())?;
            let name = self.parse_name()?;
            self.skip_space();
            self.expect(b'>')?;
            return Ok(RawXmlToken::End(name));
        }
        let name = self.parse_name()?;
        let mut attributes = Vec::new();
        let empty;
        loop {
            self.skip_space();
            if self.input.get(self.offset) == Some(&b'>') {
                self.offset += 1;
                empty = false;
                break;
            }
            if self.input.get(self.offset) == Some(&b'/') {
                self.offset += 1;
                self.expect(b'>')?;
                empty = true;
                break;
            }
            if attributes.len() >= limits().max_attributes {
                return Err(());
            }
            let attribute_name = self.parse_name()?;
            if attributes
                .iter()
                .any(|(name, _): &(String, String)| name == &attribute_name)
            {
                return Err(());
            }
            self.skip_space();
            self.expect(b'=')?;
            self.skip_space();
            let quote = *self.input.get(self.offset).ok_or(())?;
            if quote != b'\'' && quote != b'"' {
                return Err(());
            }
            self.offset += 1;
            let start = self.offset;
            while self.offset < self.input.len() && self.input[self.offset] != quote {
                self.offset += 1;
            }
            if self.offset >= self.input.len() {
                return Err(());
            }
            let raw = std::str::from_utf8(&self.input[start..self.offset]).map_err(|_| ())?;
            self.offset += 1;
            if raw.len() > self.max_attribute_bytes {
                return Err(());
            }
            let value = decode_xml_entities(raw)?;
            if value.len() > self.max_attribute_bytes {
                return Err(());
            }
            attributes.push((attribute_name, value));
        }
        Ok(RawXmlToken::Start {
            name,
            attributes,
            empty,
        })
    }

    fn parse_name(&mut self) -> Result<String, ()> {
        let start = self.offset;
        while let Some(byte) = self.input.get(self.offset) {
            if byte.is_ascii_whitespace() || *byte == b'=' || *byte == b'>' || *byte == b'/' {
                break;
            }
            self.offset += 1;
        }
        if self.offset == start {
            return Err(());
        }
        std::str::from_utf8(&self.input[start..self.offset])
            .map(str::to_owned)
            .map_err(|_| ())
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

    fn expect(&mut self, byte: u8) -> Result<(), ()> {
        if self.input.get(self.offset) != Some(&byte) {
            return Err(());
        }
        self.offset += 1;
        Ok(())
    }

    fn skip_until(&mut self, marker: &[u8]) -> Result<(), ()> {
        let end = find_bytes(&self.input[self.offset..], marker).ok_or(())?;
        self.offset = self.offset.checked_add(end + marker.len()).ok_or(())?;
        Ok(())
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn decode_xml_entities(value: &str) -> Result<String, ()> {
    if !value.contains('&') {
        return Ok(value.to_owned());
    }
    let mut output = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(index) = rest.find('&') {
        output.push_str(&rest[..index]);
        let after = &rest[index + 1..];
        let end = after.find(';').ok_or(())?;
        let entity = &after[..end];
        match entity {
            "amp" => output.push('&'),
            "lt" => output.push('<'),
            "gt" => output.push('>'),
            "quot" => output.push('"'),
            "apos" => output.push('\''),
            value if value.starts_with("#x") || value.starts_with("#X") => {
                let code = u32::from_str_radix(&value[2..], 16).map_err(|_| ())?;
                output.push(char::from_u32(code).ok_or(())?);
            }
            value if value.starts_with('#') => {
                let code = value[1..].parse::<u32>().map_err(|_| ())?;
                output.push(char::from_u32(code).ok_or(())?);
            }
            _ => return Err(()),
        }
        rest = &after[end + 1..];
    }
    output.push_str(rest);
    Some(output)
        .filter(|value| value.chars().all(is_valid_xml_char))
        .ok_or(())
}

fn is_valid_xml_char(value: char) -> bool {
    matches!(value, '\u{9}' | '\u{a}' | '\u{d}')
        || ('\u{20}'..='\u{d7ff}').contains(&value)
        || ('\u{e000}'..='\u{fffd}').contains(&value)
        || ('\u{10000}'..='\u{10ffff}').contains(&value)
}

fn normalize_raw_xml_node(node: &mut RawXmlNode) {
    let mut normalized = Vec::with_capacity(node.content.len());
    for part in std::mem::take(&mut node.content) {
        match part {
            RawXmlPart::Text(value) => {
                if let Some(RawXmlPart::Text(previous)) = normalized.last_mut() {
                    previous.push_str(&value);
                } else {
                    normalized.push(RawXmlPart::Text(value));
                }
            }
            RawXmlPart::Child(mut child) => {
                normalize_raw_xml_node(&mut child);
                normalized.push(RawXmlPart::Child(child));
            }
        }
    }
    node.content = normalized;
}

fn normalize_opaque_xml_node(node: &mut RawXmlNode) {
    normalize_raw_xml_node(node);
    match node.content.first_mut() {
        Some(RawXmlPart::Text(value)) if value.starts_with('\n') => {
            value.remove(0);
        }
        _ => {}
    }
    match node.content.last_mut() {
        Some(RawXmlPart::Text(value)) if value.ends_with('\n') => {
            value.pop();
        }
        _ => {}
    }
    for part in &mut node.content {
        if let RawXmlPart::Child(child) = part {
            normalize_opaque_xml_node(child);
        }
    }
    normalize_raw_xml_node(node);
    node.content
        .retain(|part| !matches!(part, RawXmlPart::Text(value) if value.is_empty()));
}

fn raw_xml_inventory(input: &[u8], max_input_bytes: usize) -> Option<RawXmlInventory> {
    let root = RawXmlParser::new(input, max_input_bytes)?.parse()?;
    let root_attributes = root
        .attributes
        .iter()
        .filter(|(name, _)| name != "version")
        .cloned()
        .collect();
    let mut root_order = Vec::new();
    for part in root.content {
        let RawXmlPart::Child(child) = part else {
            continue;
        };
        if matches!(child.name.as_str(), "sample" | "httpSample") {
            root_order.push(RawXmlRootItem::Sample(raw_xml_sample(&child)?));
        } else {
            let mut child = child;
            normalize_opaque_xml_node(&mut child);
            root_order.push(RawXmlRootItem::Opaque(child));
        }
    }
    Some(RawXmlInventory {
        root_attributes,
        root_order,
    })
}

fn raw_xml_sample(node: &RawXmlNode) -> Option<RawXmlSample> {
    if !matches!(node.name.as_str(), "sample" | "httpSample") {
        return None;
    }
    let mut variables = Vec::new();
    let mut unknown_attributes = Vec::new();
    for (name, value) in &node.attributes {
        if let Some(canonical) = configured_xml_variable(name) {
            variables.push((canonical.to_owned(), value.clone()));
        } else if !known_sample_attribute(name) {
            unknown_attributes.push((name.clone(), value.clone()));
        }
    }
    let mut children = Vec::new();
    for part in &node.content {
        let RawXmlPart::Child(child) = part else {
            continue;
        };
        match child.name.as_str() {
            "sample" | "httpSample" => {
                children.push(RawXmlSampleChild::Sample(raw_xml_sample(child)?));
            }
            "assertionResult" => {
                children.push(RawXmlSampleChild::Assertion(raw_xml_assertion(child)?));
            }
            "responseHeader" | "requestHeader" | "responseData" | "responseFile"
            | "samplerData" | "java.net.URL" | "url" => {}
            _ => {
                let mut child = child.clone();
                normalize_opaque_xml_node(&mut child);
                children.push(RawXmlSampleChild::Opaque(child));
            }
        }
    }
    Some(RawXmlSample {
        element: node.name.clone(),
        variables,
        unknown_attributes,
        children,
    })
}

fn raw_xml_assertion(node: &RawXmlNode) -> Option<RawXmlAssertion> {
    if node.name != "assertionResult" {
        return None;
    }
    let unknown_attributes = node
        .attributes
        .iter()
        .filter(|(name, _)| {
            !matches!(
                name.as_str(),
                "name" | "failure" | "error" | "failureMessage" | "errorMessage"
            )
        })
        .cloned()
        .collect();
    let mut children = Vec::new();
    for part in &node.content {
        let RawXmlPart::Child(child) = part else {
            continue;
        };
        match child.name.as_str() {
            "name" | "failure" | "error" | "failureMessage" | "errorMessage" => {}
            _ => {
                let mut child = child.clone();
                normalize_opaque_xml_node(&mut child);
                children.push(RawXmlAssertionChild::Opaque(child));
            }
        }
    }
    Some(RawXmlAssertion {
        unknown_attributes,
        children,
    })
}

fn configured_xml_variable(name: &str) -> Option<&'static str> {
    match name {
        "case_id" | "case__id" => Some("case_id"),
        "region" => Some("region"),
        _ => None,
    }
}

fn known_sample_attribute(name: &str) -> bool {
    matches!(
        name,
        "t" | "it"
            | "lt"
            | "ct"
            | "ts"
            | "s"
            | "lb"
            | "rc"
            | "rs"
            | "rm"
            | "tn"
            | "dt"
            | "de"
            | "by"
            | "sby"
            | "sc"
            | "ec"
            | "ng"
            | "na"
            | "hn"
    ) || configured_xml_variable(name).is_some()
}

fn assert_raw_xml_inventory(source: &RawXmlInventory, encoded: &RawXmlInventory) {
    if source != encoded {
        panic!("XML source opaque inventory, sample identity, or child order changed");
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

fn assert_xml_reader_fault(input: &[u8]) {
    if input.is_empty() {
        return;
    }
    let fail_at = input.len() / 2;
    for kind in [ErrorKind::Interrupted, ErrorKind::Other] {
        let result = XmlDecoder::with_configuration(
            FaultReader::new(input, fail_at, kind),
            limits(),
            decode_configuration(),
        )
        .and_then(XmlDecoder::decode_all);
        if !matches!(result, Err(jmeter_rs_results::JtlError::Io { .. })) {
            panic!("XML reader fault was not surfaced as a bounded I/O error");
        }
    }
}

fn encode_events(
    events: &[SampleEvent],
    configuration: SampleSaveConfiguration,
    limits: JtlLimits,
) -> Vec<u8> {
    let mut encoder = XmlEncoder::new(Vec::new(), configuration)
        .expect("accepted JTL XML events must provide a valid encoder")
        .with_limits(limits)
        .expect("accepted JTL XML events must fit valid limits");
    for event in events {
        encoder
            .write_event(event)
            .expect("accepted JTL XML events must re-encode");
    }
    encoder
        .finish()
        .expect("accepted JTL XML events must finish encoding")
}

fn fixed_malformed_boundary_probe() {
    let truncated = br#"<testResults version="1.2"><sample lb="truncated">"#;
    if !matches!(
        XmlDecoder::with_configuration(truncated.as_slice(), limits(), decode_configuration())
            .and_then(XmlDecoder::decode_all),
        Err(jmeter_rs_results::JtlError::Xml { .. })
    ) {
        panic!("truncated JTL XML was not rejected at the decoder boundary");
    }

    let duplicate_attribute =
        br#"<testResults version="1.2"><sample lb="first" lb="second"/></testResults>"#;
    if !matches!(
        XmlDecoder::with_configuration(
            duplicate_attribute.as_slice(),
            limits(),
            decode_configuration(),
        )
        .and_then(XmlDecoder::decode_all),
        Err(jmeter_rs_results::JtlError::Xml { detail, .. })
            if detail.contains("duplicate XML attribute")
    ) {
        panic!("duplicate JTL XML attributes were not rejected at the decoder boundary");
    }

    let duplicate_child = br#"<testResults version="1.2"><sample><responseData/><responseData/></sample></testResults>"#;
    if !matches!(
        XmlDecoder::with_configuration(duplicate_child.as_slice(), limits(), decode_configuration())
            .and_then(XmlDecoder::decode_all),
        Err(jmeter_rs_results::JtlError::Xml { detail, .. })
            if detail.contains("duplicate <responseData> child")
    ) {
        panic!("duplicate JTL XML children were not rejected at the decoder boundary");
    }

    let root_only_extension = br#"<testResults version="1.2"><rootAfter/></testResults>"#;
    if !matches!(
        XmlDecoder::with_configuration(
            root_only_extension.as_slice(),
            limits(),
            decode_configuration(),
        )
        .and_then(XmlDecoder::decode_all),
        Err(jmeter_rs_results::JtlError::Unsupported {
            feature: "xml-root-extension-without-sample",
            ..
        })
    ) {
        panic!("root-only JTL XML extensions were not rejected at the decoder boundary");
    }
}

fn fixed_atomic_output_probe(event: &SampleEvent) {
    let bounded_limits = limits()
        .with_max_output_bytes(64)
        .expect("fixed atomic JTL probe output limit must be non-zero");
    let mut encoder = XmlEncoder::new(Vec::new(), wire_probe_configuration())
        .expect("fixed atomic JTL probe encoder")
        .with_limits(bounded_limits)
        .expect("fixed atomic JTL probe limits");
    if !matches!(
        encoder.write_event(event),
        Err(jmeter_rs_results::JtlError::Unsupported {
            feature: "output-limit",
            ..
        })
    ) {
        panic!("JTL XML output limit did not reject the event atomically");
    }
    if !encoder.into_inner().is_empty() {
        panic!("JTL XML output-limit rejection published partial bytes");
    }
}

fn fixed_wire_probe() {
    let input = br#"<testResults version="1.2" rootAttr="">
<rootBefore flag=""><nested><deep attr="">text</deep></nested></rootBefore>
<httpSample lb="first" tn="root-thread" hn="root-host" case_id="" pluginAttr="">
  <assertionResult extAttr="">
    <name>assertion</name><failure>false</failure><error>false</error>
    <failureMessage></failureMessage>
    <assertionA order="1"><nestedA><deepA/></nestedA></assertionA>
    <assertionB order="2"><nestedB><deepB/></nestedB></assertionB>
  </assertionResult>
  <sample lb="child" tn="child-thread" hn="child-host" childAttr="">
    <childA order="1"><nestedA><leafA/></nestedA></childA>
    <childB order="2"><nestedB><leafB/></nestedB></childB>
  </sample>
  <samplerData class="java.lang.String"></samplerData>
  <pluginA order="1"><nestedA><deepA/></nestedA></pluginA>
  <pluginB order="2"><nestedB><deepB/></nestedB></pluginB>
</httpSample>
<rootBetween flag="yes"><nested><deep/></nested></rootBetween>
<sample lb="second" tn="second-thread" hn="second-host">
  <pluginSecond><nested><leaf/></nested></pluginSecond>
</sample>
<rootAfter><nested><leaf/></nested></rootAfter>
</testResults>"#;
    let limits = limits();
    let decoder_configuration = decode_configuration();
    let events = XmlDecoder::with_configuration(&input[..], limits, decoder_configuration.clone())
        .expect("fixed JTL XML probe must configure")
        .decode_all()
        .expect("fixed JTL XML probe must decode");
    if events.len() != 2 {
        panic!("fixed JTL XML probe expected two root samples");
    }
    let first = &events[0];
    let second = &events[1];
    if !first.result().sampler_data().is_some_and(str::is_empty)
        || second.result().sampler_data().is_some()
    {
        panic!("fixed JTL XML probe changed absent-versus-present-empty sampler data");
    }
    if !first
        .variables()
        .get("case_id")
        .is_some_and(|value| value.is_present_empty())
        || !second
            .variables()
            .get("region")
            .is_some_and(|value| value.as_str().is_none())
    {
        panic!("fixed JTL XML probe changed absent-versus-present-empty variables");
    }
    if first.result().sub_results().len() != 1
        || first.result().assertions().len() != 1
        || second.result().sub_results().iter().next().is_some()
    {
        panic!("fixed JTL XML probe lost sample hierarchy or assertions");
    }

    fixed_atomic_output_probe(first);

    let configuration = wire_probe_configuration();
    let mut encoder = XmlEncoder::new(Vec::new(), configuration)
        .expect("fixed JTL XML probe encoder")
        .with_limits(limits)
        .expect("fixed JTL XML probe limits");
    for event in &events {
        encoder
            .write_event(event)
            .expect("fixed JTL XML probe must encode");
    }
    let encoded = encoder.finish().expect("fixed JTL XML probe must finish");
    let encoded_text = String::from_utf8(encoded.clone()).expect("fixed JTL XML probe is UTF-8");
    assert_wire_markers_in_order(
        &encoded_text,
        &[
            "<rootBefore flag=\"\">",
            "<nested>",
            "<deep attr=\"\">",
            "<httpSample lb=\"first\" tn=\"root-thread\" hn=\"root-host\" case_id=\"\" pluginAttr=\"\">",
            "<assertionResult extAttr=\"\">",
            "<assertionA order=\"1\">",
            "<nestedA>",
            "<deepA/>",
            "<assertionB order=\"2\">",
            "<nestedB>",
            "<deepB/>",
            "<sample lb=\"child\" tn=\"child-thread\" hn=\"child-host\" childAttr=\"\">",
            "<childA order=\"1\">",
            "<nestedA>",
            "<leafA/>",
            "<childB order=\"2\">",
            "<nestedB>",
            "<leafB/>",
            "<samplerData class=\"java.lang.String\"></samplerData>",
            "<pluginA order=\"1\">",
            "<nestedA>",
            "<deepA/>",
            "<pluginB order=\"2\">",
            "<nestedB>",
            "<deepB/>",
            "<rootBetween flag=\"yes\">",
            "<nested>",
            "<deep/>",
            "<sample lb=\"second\" tn=\"second-thread\" hn=\"second-host\">",
            "<pluginSecond>",
            "<nested>",
            "<leaf/>",
            "<rootAfter>",
            "<nested>",
            "<leaf/>",
        ],
    );
    let source_inventory =
        raw_xml_inventory(input, MAX_INPUT_BYTES).expect("fixed JTL XML source inventory");
    let encoded_inventory = raw_xml_inventory(&encoded, MAX_INPUT_BYTES.saturating_mul(2))
        .expect("fixed JTL XML encoded inventory");
    assert_raw_xml_inventory(&source_inventory, &encoded_inventory);

    let reparsed =
        XmlDecoder::with_configuration(encoded.as_slice(), limits, decoder_configuration)
            .expect("re-encoded fixed JTL XML probe must configure")
            .decode_all()
            .expect("re-encoded fixed JTL XML probe must decode");
    let reparsed_encoded = encode_events(&reparsed, wire_probe_configuration(), limits);
    if canonical_xml_layout(&encoded) != canonical_xml_layout(&reparsed_encoded) {
        panic!("fixed JTL XML probe changed non-formatting wire content or ordering");
    }
    if wire_projection(&reparsed, &wire_probe_configuration())
        != wire_projection(&events, &wire_probe_configuration())
    {
        panic!("fixed JTL XML probe changed a configured wire projection");
    }

    fixed_malformed_boundary_probe();
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AssertionProjection {
    name: String,
    failure: bool,
    error: bool,
    failure_message: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResultProjection {
    attributes: Vec<(String, String)>,
    payload: Vec<(String, Vec<u8>)>,
    assertions: Vec<AssertionProjection>,
    sub_results: Vec<ResultProjection>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EventProjection {
    thread: String,
    host: String,
    variables: Vec<(String, String)>,
    result: ResultProjection,
}

fn result_projection(
    result: &SampleResult,
    event: &SampleEvent,
    configuration: &SampleSaveConfiguration,
    include_event_metadata: bool,
) -> ResultProjection {
    let mut attributes = Vec::new();
    if configuration.saves(CsvField::Elapsed) {
        attributes.push((
            "t".to_owned(),
            result
                .elapsed()
                .map(|value| value.as_millis().to_string())
                .unwrap_or_else(|| "0".to_owned()),
        ));
    }
    if configuration.saves(CsvField::IdleTime) {
        attributes.push((
            "it".to_owned(),
            result
                .idle_time()
                .map(|value| value.as_millis().to_string())
                .unwrap_or_else(|| "0".to_owned()),
        ));
    }
    if configuration.saves(CsvField::Latency) {
        attributes.push((
            "lt".to_owned(),
            result
                .latency()
                .map(|value| value.as_millis().to_string())
                .unwrap_or_else(|| "0".to_owned()),
        ));
    }
    if configuration.saves(CsvField::Connect) {
        attributes.push((
            "ct".to_owned(),
            result
                .connect_time()
                .map(|value| value.as_millis().to_string())
                .unwrap_or_else(|| "0".to_owned()),
        ));
    }
    if configuration.timestamp_column_enabled() {
        attributes.push((
            "ts".to_owned(),
            result
                .timestamp()
                .map(|value| value.as_millis().to_string())
                .unwrap_or_else(|| "0".to_owned()),
        ));
    }
    if configuration.saves(CsvField::Success) {
        attributes.push(("s".to_owned(), result.success().unwrap_or(true).to_string()));
    }
    if configuration.saves(CsvField::Label) {
        attributes.push(("lb".to_owned(), result.label().to_owned()));
    }
    if configuration.saves(CsvField::ResponseCode) {
        attributes.push((
            "rc".to_owned(),
            result.response_code().unwrap_or_default().to_owned(),
        ));
    }
    if configuration.saves(CsvField::ResponseMessage) {
        attributes.push((
            "rm".to_owned(),
            result.response_message().unwrap_or_default().to_owned(),
        ));
    }
    if include_event_metadata && configuration.saves(CsvField::ThreadName) {
        attributes.push(("tn".to_owned(), event.thread().name().to_owned()));
    }
    if configuration.saves(CsvField::DataType) {
        attributes.push((
            "dt".to_owned(),
            result
                .data_type()
                .map(|value| value.as_wire().to_owned())
                .unwrap_or_else(|| "text".to_owned()),
        ));
    }
    if configuration.saves(CsvField::Encoding) {
        attributes.push((
            "de".to_owned(),
            result
                .data_encoding()
                .map(|value| value.as_str())
                .or_else(|| configuration.default_encoding())
                .unwrap_or_default()
                .to_owned(),
        ));
    }
    if configuration.saves(CsvField::Bytes) {
        attributes.push((
            "by".to_owned(),
            result
                .received_bytes()
                .map(|value| value.as_u64().to_string())
                .unwrap_or_else(|| "0".to_owned()),
        ));
    }
    if configuration.saves(CsvField::SentBytes) {
        attributes.push((
            "sby".to_owned(),
            result
                .sent_bytes()
                .map(|value| value.as_u64().to_string())
                .unwrap_or_else(|| "0".to_owned()),
        ));
    }
    if configuration.saves(CsvField::SampleCount) {
        attributes.push((
            "sc".to_owned(),
            result
                .sample_count()
                .map(|value| value.as_u64().to_string())
                .unwrap_or_else(|| "1".to_owned()),
        ));
        attributes.push((
            "ec".to_owned(),
            result
                .error_count()
                .map(|value| value.as_u64().to_string())
                .unwrap_or_else(|| "0".to_owned()),
        ));
    }
    if configuration.saves(CsvField::GroupThreads) {
        attributes.push((
            "ng".to_owned(),
            result
                .group_threads()
                .map(|value| value.as_u64().to_string())
                .unwrap_or_else(|| "0".to_owned()),
        ));
        attributes.push((
            "na".to_owned(),
            result
                .all_threads()
                .map(|value| value.as_u64().to_string())
                .unwrap_or_else(|| "0".to_owned()),
        ));
    }
    if include_event_metadata && configuration.saves(CsvField::Hostname) {
        attributes.push(("hn".to_owned(), event.host().as_str().to_owned()));
    }
    if include_event_metadata {
        for variable in configuration.sample_variables() {
            attributes.push((
                variable.clone(),
                event
                    .variables()
                    .get(variable)
                    .and_then(|value| value.as_str())
                    .unwrap_or_default()
                    .to_owned(),
            ));
        }
    }

    let mut payload = Vec::new();
    if configuration.save_response_headers() {
        payload.push((
            "responseHeader".to_owned(),
            result
                .response_headers()
                .map(|value| value.as_str().as_bytes().to_vec())
                .unwrap_or_default(),
        ));
    }
    if configuration.save_request_headers() {
        payload.push((
            "requestHeader".to_owned(),
            result
                .request_headers()
                .map(|value| value.as_str().as_bytes().to_vec())
                .unwrap_or_default(),
        ));
    }
    if configuration.should_save_response_data(result.success()) {
        payload.push((
            "responseData".to_owned(),
            result
                .response_data()
                .map(|value| value.as_bytes().to_vec())
                .unwrap_or_default(),
        ));
    }
    if configuration.save_file_name() {
        payload.push((
            "responseFile".to_owned(),
            result
                .response_file()
                .unwrap_or_default()
                .as_bytes()
                .to_vec(),
        ));
    }
    if let (true, Some(value)) = (configuration.save_sampler_data(), result.sampler_data()) {
        payload.push(("samplerData".to_owned(), value.as_bytes().to_vec()));
    }
    if let (true, Some(value)) = (configuration.save_url(), result.url()) {
        payload.push(("java.net.URL".to_owned(), value.as_bytes().to_vec()));
    }

    let assertion_limit = match configuration.assertion_results() {
        AssertionResults::None => 0,
        AssertionResults::First => 1,
        AssertionResults::All => usize::MAX,
    };
    let assertions = result
        .assertions()
        .iter()
        .take(assertion_limit)
        .map(|assertion| AssertionProjection {
            name: assertion.name().to_owned(),
            failure: assertion.is_failure(),
            error: assertion.is_error(),
            failure_message: configuration
                .save_assertion_results_failure_message()
                .then(|| {
                    assertion
                        .failure_message()
                        .or_else(|| assertion.error_message())
                        .map(str::to_owned)
                })
                .flatten(),
        })
        .collect();

    let sub_results = if configuration.save_subresults() {
        result
            .sub_results()
            .iter()
            .map(|child| result_projection(child, event, configuration, false))
            .collect()
    } else {
        Vec::new()
    };
    ResultProjection {
        attributes,
        payload,
        assertions,
        sub_results,
    }
}

fn wire_projection(
    events: &[SampleEvent],
    configuration: &SampleSaveConfiguration,
) -> Vec<EventProjection> {
    events
        .iter()
        .map(|event| EventProjection {
            thread: event.thread().name().to_owned(),
            host: event.host().as_str().to_owned(),
            variables: configuration
                .sample_variables()
                .iter()
                .map(|name| {
                    (
                        name.clone(),
                        event
                            .variables()
                            .get(name)
                            .and_then(|value| value.as_str())
                            .unwrap_or_default()
                            .to_owned(),
                    )
                })
                .collect(),
            result: result_projection(event.result(), event, configuration, true),
        })
        .collect()
}

fuzz_target!(|data: &[u8]| {
    fixed_wire_probe();
    if data.len() > MAX_INPUT_BYTES {
        let oversized = oversized_probe();
        let result =
            XmlDecoder::with_configuration(oversized.as_slice(), limits(), decode_configuration())
                .and_then(XmlDecoder::decode_all);
        match result {
            Err(jmeter_rs_results::JtlError::Unsupported {
                feature: "input-size-limit",
                ..
            }) => {}
            Err(error) => panic!("oversized JTL XML returned the wrong error: {error}"),
            Ok(_) => panic!("oversized JTL XML was accepted instead of rejected"),
        }
        return;
    }

    let configuration = configuration();
    let decoder_configuration = decode_configuration();
    let Ok(decoder) = XmlDecoder::with_configuration(data, limits(), decoder_configuration.clone())
    else {
        return;
    };
    let Ok(events) = decoder.decode_all() else {
        return;
    };
    let Some(source_inventory) = raw_xml_inventory(data, MAX_INPUT_BYTES) else {
        panic!("accepted XML input could not be independently inventoried");
    };
    assert_xml_reader_fault(data);
    let expected = wire_projection(&events, &configuration);

    let Ok(mut encoder) = XmlEncoder::new(Vec::new(), configuration.clone())
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
    let Some(encoded_inventory) = raw_xml_inventory(&encoded, MAX_INPUT_BYTES.saturating_mul(2))
    else {
        panic!("encoded XML output could not be independently inventoried");
    };
    assert_raw_xml_inventory(&source_inventory, &encoded_inventory);

    let Ok(reparsed_decoder) =
        XmlDecoder::with_configuration(encoded.as_slice(), limits(), decoder_configuration)
    else {
        panic!("encoded JTL XML was not parseable");
    };
    let Ok(reparsed) = reparsed_decoder.decode_all() else {
        panic!("encoded JTL XML could not be decoded");
    };
    if wire_projection(&reparsed, &configuration) != expected {
        panic!("XML wire projection dropped or changed a configured field");
    }
    let reparsed_encoded = encode_events(&reparsed, configuration, limits());
    if canonical_xml_layout(&encoded) != canonical_xml_layout(&reparsed_encoded) {
        panic!("XML wire content or ordering changed beyond formatting-only whitespace");
    }
});
