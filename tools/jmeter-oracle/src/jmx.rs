// SPDX-License-Identifier: Apache-2.0
//! Bounded JMX wire/semantic comparison.
//!
//! This module deliberately owns a small XML reader instead of depending on
//! the evolving `crates/jmx` model.  A JMX file is both a semantic plan and a
//! persistence format: unknown plug-in data, ordering, duplicate names, and
//! lexical values therefore remain visible in the projection.  The semantic
//! aliases below are only applied to fields for which the pinned compatibility
//! contract explicitly describes an upgrade.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::compare::{
    ArtifactSummary, CompareFormat, CompareLimits, CompareOptions, CompareReport, base_report,
    finish_report, push_diff, raw_projection_diff,
};
use super::{ErrorCode, OracleError, Result, ValidatedCase, absolute_path};

const PROJECTION_SCHEMA_ID: &str = "jmeter-rs.jmx-semantic-projection";
const PROJECTION_SCHEMA_VERSION: u64 = 1;
const EXPECTATION_SCHEMA_ID: &str = "jmeter-rs.semantic-expectation";
const PINNED_SAVESERVICE: &str =
    include_str!("../../../crates/jmx/data/saveservice-5.6.3.properties");
const PINNED_UPGRADE: &str = include_str!("../../../crates/jmx/data/upgrade-5.6.3.properties");
const PINNED_SOURCE_COMMIT: &str = "34a2785748e9e0b14702595e8682c387869deda3";

/// Parsed bounded JMX projection.
#[derive(Clone, Debug)]
pub struct JmxDocument {
    /// Stable semantic/wire projection.
    pub projection: Value,
    /// Number of topology elements retained.
    pub element_count: usize,
    /// Number of parser nodes retained.
    pub node_count: usize,
    /// Input byte count.
    pub size_bytes: u64,
    /// Full source SHA-256, useful for exact wire diagnostics.
    pub source_sha256: String,
}

#[derive(Clone, Debug)]
struct JmxSource {
    bytes: Vec<u8>,
    root: XmlNode,
    leading: Vec<XmlEvent>,
    trailing: Vec<XmlEvent>,
    xml_declaration: Option<XmlSpan>,
    byte_order_mark: bool,
    version: String,
    source_sha256: String,
    node_count: usize,
}

#[derive(Clone, Debug)]
struct XmlSpan {
    start: usize,
    end: usize,
    text: String,
}

#[derive(Clone, Debug)]
struct XmlNode {
    name: String,
    attrs: Vec<(String, String)>,
    events: Vec<XmlEvent>,
    text: String,
    start: usize,
    end: usize,
}

#[derive(Clone, Debug)]
enum XmlEvent {
    Element(XmlNode),
    Comment {
        text: String,
        start: usize,
        end: usize,
    },
    ProcessingInstruction {
        target: String,
        data: String,
        start: usize,
        end: usize,
    },
    CData {
        text: String,
        start: usize,
        end: usize,
    },
}

#[derive(Clone, Debug)]
struct Build<'a> {
    source: &'a JmxSource,
    limits: &'a CompareLimits,
    properties: Vec<Value>,
    opaque: Vec<Value>,
    diagnostics: Vec<Value>,
    aliases: Vec<Value>,
    upgrades: Vec<Value>,
    deleted: Vec<Value>,
    elements: Vec<Value>,
    opaque_legacy: Vec<Value>,
    duplicate_identity_probes: Vec<Value>,
    opaque_bytes: usize,
    opaque_ranges: BTreeMap<usize, usize>,
    property_count: usize,
    property_counts_by_element: BTreeMap<String, usize>,
    diagnostic_count: usize,
    element_position: usize,
}

/// Parse one JMX file into a bounded semantic/wire projection.
pub fn parse_jmx_semantic(path: impl AsRef<Path>, limits: &CompareLimits) -> Result<JmxDocument> {
    limits.validate_for_jmx()?;
    let path = absolute_path(path.as_ref())?;
    let bytes = read_jmx_file(&path, limits.max_input_bytes)?;
    let source_sha256 = sha256(&bytes);
    let source = parse_source(bytes, limits, source_sha256)?;
    let projection = build_projection(&source, limits)?;
    let element_count = projection
        .get("ordered_hash_tree_pairs")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    Ok(JmxDocument {
        projection,
        element_count,
        node_count: source.node_count,
        size_bytes: source.bytes.len() as u64,
        source_sha256: source.source_sha256,
    })
}

/// Compare two JMX files using exact wire fields plus explicitly declared
/// semantic expectations.
pub fn compare_jmx_files(
    actual_path: impl AsRef<Path>,
    expected_path: impl AsRef<Path>,
    options: &CompareOptions,
) -> Result<CompareReport> {
    let mut effective = options.clone();
    let expected_path = absolute_path(expected_path.as_ref())?;
    let (expected, expected_size_bytes) = read_json_safe(
        &expected_path,
        effective.limits.max_input_bytes,
        &effective.limits,
    )?;
    load_jmx_normalization(&expected, &mut effective)?;
    validate_jmx_options(&effective, &expected)?;
    let actual_path = absolute_path(actual_path.as_ref())?;
    let actual = parse_jmx_semantic(&actual_path, &effective.limits)?;
    compare_jmx_projection(
        &actual,
        &expected,
        &actual_path,
        &expected_path,
        expected_size_bytes,
        &effective,
    )
}

/// Case-routed comparison.  The caller has already performed fixture
/// containment and bounded expected JSON reads.
pub(crate) fn compare_case_jmx_projection(
    fixture: &ValidatedCase,
    actual_path: &Path,
    expected_path: &Path,
    expected: &Value,
    expected_size_bytes: u64,
    options: &CompareOptions,
) -> Result<CompareReport> {
    let mut effective = options.clone();
    apply_case_jmx_limits(fixture.case().document(), &mut effective.limits)?;
    load_jmx_normalization(expected, &mut effective)?;
    validate_jmx_options(&effective, expected)?;
    validate_jmx_expectation_provenance(expected, fixture)?;
    let actual = parse_jmx_semantic(actual_path, &effective.limits)?;
    let report = compare_jmx_projection(
        &actual,
        expected,
        actual_path,
        expected_path,
        expected_size_bytes,
        &effective,
    )?;
    let _ = fixture;
    Ok(report)
}

fn validate_jmx_expectation_provenance(expected: &Value, fixture: &ValidatedCase) -> Result<()> {
    let check_string = |field: &str, expected_value: &str| -> Result<()> {
        if let Some(value) = expected.get(field) {
            let value = value.as_str().ok_or_else(|| {
                OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    format!("JMX expectation {field} must be a string"),
                )
            })?;
            if value != expected_value {
                return Err(OracleError::new_for_cli(
                    ErrorCode::ManifestMismatch,
                    format!("JMX expectation {field} does not match the case"),
                ));
            }
        }
        Ok(())
    };
    check_string("profile_id", fixture.profile().profile_id())?;
    check_string("case_id", fixture.case().case_id())?;
    check_string("fixture_family_id", fixture.case().fixture_family_id())?;
    if let Some(value) = expected.get("conformance_ids") {
        let values = value.as_array().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "JMX expectation conformance_ids must be an array",
            )
        })?;
        let declared: BTreeSet<&str> = values
            .iter()
            .map(|value| {
                value.as_str().ok_or_else(|| {
                    OracleError::new_for_cli(
                        ErrorCode::ManifestSchema,
                        "JMX expectation conformance_ids must contain strings",
                    )
                })
            })
            .collect::<Result<BTreeSet<_>>>()?;
        let case_ids: BTreeSet<&str> = fixture
            .case()
            .conformance_ids()
            .iter()
            .map(String::as_str)
            .collect();
        if !declared.is_subset(&case_ids) {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestMismatch,
                "JMX expectation conformance_ids are not declared by the case",
            ));
        }
    }
    if let Some(value) = expected.get("rust_conformance_claim")
        && !value.is_boolean()
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "JMX expectation rust_conformance_claim must be boolean",
        ));
    }
    if let Some(value) = expected.get("generated_from")
        && !value.is_object()
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "JMX expectation generated_from must be an object",
        ));
    }
    Ok(())
}

fn apply_case_jmx_limits(document: &Value, limits: &mut CompareLimits) -> Result<()> {
    let object = document
        .get("bounds")
        .or_else(|| document.get("resource_limits"))
        .and_then(Value::as_object);
    let Some(object) = object else {
        return Ok(());
    };
    let bound = |names: &[&str]| -> Result<Option<u64>> {
        for name in names {
            if let Some(value) = object.get(*name) {
                return value.as_u64().map(Some).ok_or_else(|| {
                    OracleError::new_for_cli(
                        ErrorCode::ManifestSchema,
                        format!("case bounds.{name} must be an unsigned integer"),
                    )
                });
            }
        }
        Ok(None)
    };
    if let Some(value) = bound(&["max_plan_bytes", "max_input_bytes"])? {
        if value == 0 {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "JMX max_plan_bytes must be greater than zero",
            ));
        }
        limits.max_input_bytes = limits.max_input_bytes.min(value);
    }
    if let Some(value) = bound(&["max_plan_depth", "max_depth"])? {
        let value = usize::try_from(value).map_err(|_| {
            OracleError::new_for_cli(ErrorCode::ManifestSchema, "JMX max_plan_depth is too large")
        })?;
        // The case bound describes topology depth. Property/value wrappers
        // are still bounded recursively, but are not topology levels.
        limits.max_depth = limits.max_depth.min(value.saturating_add(8));
    }
    if let Some(value) = bound(&["max_plan_nodes", "max_xml_nodes", "max_nodes"])? {
        let value = usize::try_from(value).map_err(|_| {
            OracleError::new_for_cli(ErrorCode::ManifestSchema, "JMX max_plan_nodes is too large")
        })?;
        if object.contains_key("max_xml_nodes") || object.contains_key("max_nodes") {
            limits.max_nodes = limits.max_nodes.min(value);
        } else {
            limits.max_events = limits.max_events.min(value);
        }
    }
    if let Some(value) = bound(&["max_properties"])? {
        limits.max_properties =
            limits
                .max_properties
                .min(usize::try_from(value).map_err(|_| {
                    OracleError::new_for_cli(
                        ErrorCode::ManifestSchema,
                        "JMX max_property_count_per_element is too large",
                    )
                })?);
    }
    if let Some(value) = bound(&["max_property_count_per_element"])? {
        limits.max_properties_per_element =
            limits
                .max_properties_per_element
                .min(usize::try_from(value).map_err(|_| {
                    OracleError::new_for_cli(
                        ErrorCode::ManifestSchema,
                        "JMX max_property_count_per_element is too large",
                    )
                })?);
    }
    if let Some(value) = bound(&["max_property_text_bytes", "max_text_bytes"])? {
        limits.max_text_bytes =
            limits
                .max_text_bytes
                .min(usize::try_from(value).map_err(|_| {
                    OracleError::new_for_cli(
                        ErrorCode::ManifestSchema,
                        "JMX max_property_text_bytes is too large",
                    )
                })?);
    }
    if let Some(value) = bound(&["max_diagnostic_count", "max_diagnostics"])? {
        limits.max_diagnostics =
            limits
                .max_diagnostics
                .min(usize::try_from(value).map_err(|_| {
                    OracleError::new_for_cli(
                        ErrorCode::ManifestSchema,
                        "JMX max_diagnostic_count is too large",
                    )
                })?);
    }
    if let Some(value) = bound(&["max_opaque_subtree_bytes", "max_opaque_bytes"])? {
        limits.max_opaque_bytes =
            limits
                .max_opaque_bytes
                .min(usize::try_from(value).map_err(|_| {
                    OracleError::new_for_cli(
                        ErrorCode::ManifestSchema,
                        "JMX max_opaque_subtree_bytes is too large",
                    )
                })?);
    }
    Ok(())
}

/// Apply only an explicit generic input bound before the contained expected
/// projection is read.  `max_plan_bytes` bounds the JMX plan itself; applying
/// it to the usually larger JSON expectation would reject a valid static
/// descriptor before the JMX route gets a chance to compare it.
pub(crate) fn apply_case_jmx_expected_read_limit(
    document: &Value,
    limits: &mut CompareLimits,
) -> Result<()> {
    let object = document
        .get("bounds")
        .or_else(|| document.get("resource_limits"))
        .and_then(Value::as_object);
    let Some(object) = object else {
        return Ok(());
    };
    for name in ["max_input_bytes"] {
        if let Some(value) = object.get(name) {
            let value = value.as_u64().ok_or_else(|| {
                OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    format!("case bounds.{name} must be an unsigned integer"),
                )
            })?;
            if value == 0 {
                return Err(OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    format!("JMX {name} must be greater than zero"),
                ));
            }
            limits.max_input_bytes = limits.max_input_bytes.min(value);
            break;
        }
    }
    Ok(())
}

fn compare_jmx_projection(
    actual: &JmxDocument,
    expected: &Value,
    _actual_path: &Path,
    _expected_path: &Path,
    expected_size_bytes: u64,
    options: &CompareOptions,
) -> Result<CompareReport> {
    validate_jmx_expectation(expected, &options.limits)?;
    let actual_summary = ArtifactSummary {
        // Reports can be persisted or printed by CI.  Do not disclose the
        // caller's workspace, fixture root, or source filename in them.
        path: "<actual-jmx>".into(),
        format: CompareFormat::JmxSemantic,
        size_bytes: actual.size_bytes,
        event_count: actual.element_count,
    };
    let expected_summary = ArtifactSummary {
        path: "<expected-jmx-projection>".into(),
        format: CompareFormat::JmxSemantic,
        size_bytes: expected_size_bytes,
        event_count: expected_event_count(expected),
    };
    let mut report = base_report(&actual_summary, &expected_summary, options);
    report.raw_diagnostic_diff = raw_projection_diff(&actual.projection, expected, options);
    compare_declared_jmx(&actual.projection, expected, options, &mut report);
    Ok(finish_report(report, options.limits.max_human_diff_bytes))
}

fn expected_event_count(value: &Value) -> usize {
    value
        .get("ordered_hash_tree_pairs")
        .and_then(Value::as_array)
        .map_or(0, Vec::len)
}

fn read_jmx_file(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    reject_symlinks(path, "JMX input")?;
    let file = File::open(path).map_err(|error| {
        OracleError::new_for_cli(ErrorCode::File, format!("open JMX input: {error}"))
    })?;
    reject_symlinks(path, "JMX input")?;
    let opened = file.metadata().map_err(|error| {
        OracleError::new_for_cli(ErrorCode::File, format!("stat opened JMX input: {error}"))
    })?;
    if !opened.is_file() {
        return Err(OracleError::new_for_cli(
            ErrorCode::File,
            "JMX input is not a regular file",
        ));
    }
    let path_metadata = fs::metadata(path).map_err(|error| {
        OracleError::new_for_cli(ErrorCode::File, format!("stat JMX input: {error}"))
    })?;
    if !same_file_identity(&opened, &path_metadata) {
        return Err(OracleError::new_for_cli(
            ErrorCode::PathPolicy,
            "JMX input changed while opening",
        ));
    }
    let plus_one = maximum.checked_add(1).ok_or_else(|| {
        OracleError::new_for_cli(ErrorCode::Configuration, "JMX input bound is too large")
    })?;
    let mut bytes = Vec::new();
    file.take(plus_one)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            OracleError::new_for_cli(ErrorCode::File, format!("read JMX input: {error}"))
        })?;
    if bytes.len() as u64 > maximum {
        return Err(OracleError::new_for_cli(
            ErrorCode::OutputLimit,
            format!("JMX input exceeds {maximum} bytes"),
        ));
    }
    Ok(bytes)
}

fn read_json_safe(path: &Path, maximum: u64, limits: &CompareLimits) -> Result<(Value, u64)> {
    let bytes = read_jmx_file(path, maximum)?;
    let size = bytes.len() as u64;
    let value = serde_json::from_slice(&bytes).map_err(|error| {
        OracleError::new_for_cli(
            ErrorCode::ManifestJson,
            format!("parse JMX expected projection: {error}"),
        )
    })?;
    let mut nodes = 0_usize;
    validate_json_limits(&value, limits, 0, &mut nodes)?;
    Ok((value, size))
}

fn validate_json_limits(
    value: &Value,
    limits: &CompareLimits,
    depth: usize,
    nodes: &mut usize,
) -> Result<()> {
    if depth > limits.max_depth {
        return Err(limit("JMX expectation nesting exceeds configured bound"));
    }
    *nodes = nodes.saturating_add(1);
    if *nodes > limits.max_nodes {
        return Err(limit("JMX expectation node count exceeds configured bound"));
    }
    match value {
        Value::Array(values) => {
            for child in values {
                validate_json_limits(child, limits, depth + 1, nodes)?;
            }
        }
        Value::Object(values) => {
            for (key, child) in values {
                if key.len() > limits.max_text_bytes {
                    return Err(limit("JMX expectation object key exceeds text bound"));
                }
                validate_json_limits(child, limits, depth + 1, nodes)?;
            }
        }
        Value::String(text) if text.len() > limits.max_text_bytes => {
            return Err(limit("JMX expectation string exceeds text bound"));
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

fn reject_symlinks(path: &Path, label: &str) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            OracleError::new_for_cli(ErrorCode::File, format!("inspect {label} path: {error}"))
        })?;
        if metadata.file_type().is_symlink() {
            return Err(OracleError::new_for_cli(
                ErrorCode::PathPolicy,
                format!("{label} path contains a symlink"),
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len()
}

fn sha256(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    let bytes = digest.finalize();
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_source(
    mut bytes: Vec<u8>,
    limits: &CompareLimits,
    source_sha256: String,
) -> Result<JmxSource> {
    let byte_order_mark = bytes.starts_with(&[0xEF, 0xBB, 0xBF]);
    if byte_order_mark {
        bytes.drain(..3);
    }
    let text = std::str::from_utf8(&bytes).map_err(|error| {
        OracleError::new_for_cli(
            ErrorCode::JtlParse,
            format!("JMX input is not UTF-8: {error}"),
        )
    })?;
    let mut parser = XmlParser::new(text, limits);
    parser.skip_space();
    let mut xml_declaration = None;
    if parser.consume("<?xml") {
        let declaration_start = parser.position - "<?xml".len();
        if !parser
            .text
            .as_bytes()
            .get(parser.position)
            .is_some_and(u8::is_ascii_whitespace)
        {
            return Err(jmx_parse("malformed XML declaration"));
        }
        parser.skip_until("?>")?;
        let declaration_end = parser.position;
        let declaration_text = bounded_text(
            &parser.text[declaration_start..declaration_end],
            limits.max_text_bytes,
        )?;
        xml_declaration = Some(XmlSpan {
            start: declaration_start,
            end: declaration_end,
            text: declaration_text,
        });
        parser.skip_space();
    }
    let mut leading = Vec::new();
    while parser.text[parser.position..].starts_with("<!--")
        || parser.text[parser.position..].starts_with("<?")
    {
        leading.push(parser.parse_misc()?);
        parser.skip_space();
    }
    let root = parser.parse_element(1)?;
    let mut trailing = Vec::new();
    loop {
        parser.skip_space();
        if parser.eof() {
            break;
        }
        trailing.push(parser.parse_misc()?);
    }
    if root.name != "jmeterTestPlan" {
        return Err(jmx_parse("JMX root element must be jmeterTestPlan"));
    }
    let version = attr(&root, "version").unwrap_or_default().to_owned();
    let node_count = parser.node_count;
    Ok(JmxSource {
        bytes,
        root,
        leading,
        trailing,
        xml_declaration,
        byte_order_mark,
        version,
        source_sha256,
        node_count,
    })
}

struct XmlParser<'a> {
    text: &'a str,
    position: usize,
    limits: &'a CompareLimits,
    depth: usize,
    node_count: usize,
    attribute_count: usize,
}

impl<'a> XmlParser<'a> {
    fn new(text: &'a str, limits: &'a CompareLimits) -> Self {
        Self {
            text,
            position: 0,
            limits,
            depth: 0,
            node_count: 0,
            attribute_count: 0,
        }
    }

    fn eof(&self) -> bool {
        self.position >= self.text.len()
    }

    fn skip_space(&mut self) {
        while self
            .text
            .as_bytes()
            .get(self.position)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.position += 1;
        }
    }

    fn consume(&mut self, value: &str) -> bool {
        if self.text[self.position..].starts_with(value) {
            self.position += value.len();
            true
        } else {
            false
        }
    }

    fn skip_until(&mut self, marker: &str) -> Result<()> {
        let Some(offset) = self.text[self.position..].find(marker) else {
            return Err(jmx_parse(
                "unterminated XML declaration/comment/instruction",
            ));
        };
        self.position += offset + marker.len();
        Ok(())
    }

    fn parse_misc(&mut self) -> Result<XmlEvent> {
        let start = self.position;
        if self.consume("<!--") {
            let body_start = self.position;
            self.skip_until("-->")?;
            let body_end = self.position - 3;
            let text = bounded_text(&self.text[body_start..body_end], self.limits.max_text_bytes)?;
            self.bump_node()?;
            return Ok(XmlEvent::Comment {
                text,
                start,
                end: self.position,
            });
        }
        if self.consume("<?") {
            let target = self.parse_name()?;
            let data_start = self.position;
            self.skip_until("?>")?;
            let data_end = self.position - 2;
            let data = bounded_text(
                self.text[data_start..data_end].trim(),
                self.limits.max_text_bytes,
            )?;
            self.bump_node()?;
            return Ok(XmlEvent::ProcessingInstruction {
                target,
                data,
                start,
                end: self.position,
            });
        }
        if self.consume("<![CDATA[") {
            let body_start = self.position;
            self.skip_until("]]>")?;
            let body_end = self.position - 3;
            let text = bounded_text(&self.text[body_start..body_end], self.limits.max_text_bytes)?;
            self.bump_node()?;
            return Ok(XmlEvent::CData {
                text,
                start,
                end: self.position,
            });
        }
        Err(jmx_parse("unsupported XML declaration or doctype"))
    }

    fn parse_element(&mut self, depth: usize) -> Result<XmlNode> {
        if depth > self.limits.max_depth {
            return Err(limit("JMX XML depth exceeds configured bound"));
        }
        self.depth = depth;
        let start = self.position;
        self.bump_node()?;
        if !self.consume("<") {
            return Err(jmx_parse("expected XML element"));
        }
        if self.text[self.position..].starts_with("!")
            || self.text[self.position..].starts_with("?")
        {
            return Err(jmx_parse("unexpected XML declaration in element position"));
        }
        let name = self.parse_name()?;
        let mut attrs = Vec::new();
        loop {
            self.skip_space();
            if self.consume("/>") {
                return Ok(XmlNode {
                    name,
                    attrs,
                    events: Vec::new(),
                    text: String::new(),
                    start,
                    end: self.position,
                });
            }
            if self.consume(">") {
                break;
            }
            let key = self.parse_name()?;
            if attrs.iter().any(|(name, _)| name == &key) {
                return Err(jmx_parse("duplicate XML attribute"));
            }
            self.skip_space();
            if !self.consume("=") {
                return Err(jmx_parse("XML attribute lacks '='"));
            }
            self.skip_space();
            let quote = self
                .text
                .as_bytes()
                .get(self.position)
                .copied()
                .ok_or_else(|| jmx_parse("unterminated XML attribute"))?;
            if quote != b'"' && quote != b'\'' {
                return Err(jmx_parse("XML attribute must be quoted"));
            }
            self.position += 1;
            let value_start = self.position;
            while self
                .text
                .as_bytes()
                .get(self.position)
                .is_some_and(|byte| *byte != quote)
            {
                self.position += 1;
            }
            if self.text.as_bytes().get(self.position) != Some(&quote) {
                return Err(jmx_parse("unterminated XML attribute"));
            }
            let raw = &self.text[value_start..self.position];
            self.position += 1;
            attrs.push((key, decode_entities(raw, self.limits.max_text_bytes)?));
            self.attribute_count = self.attribute_count.saturating_add(1);
            if attrs.len() > self.limits.max_attributes
                || self.attribute_count > self.limits.max_attributes
            {
                return Err(limit("JMX XML attribute count exceeds configured bound"));
            }
        }
        let mut events = Vec::new();
        let mut text = String::new();
        loop {
            if self.eof() {
                return Err(jmx_parse("unterminated XML element"));
            }
            if self.text[self.position..].starts_with("</") {
                self.position += 2;
                let close = self.parse_name()?;
                if close != name {
                    return Err(jmx_parse(
                        "XML closing element does not match opening element",
                    ));
                }
                self.skip_space();
                if !self.consume(">") {
                    return Err(jmx_parse("malformed XML closing element"));
                }
                return Ok(XmlNode {
                    name,
                    attrs,
                    events,
                    text,
                    start,
                    end: self.position,
                });
            }
            if self.text[self.position..].starts_with("<") {
                let event = if self.text[self.position..].starts_with("<!--")
                    || self.text[self.position..].starts_with("<?")
                    || self.text[self.position..].starts_with("<![CDATA[")
                {
                    self.parse_misc()?
                } else {
                    XmlEvent::Element(self.parse_element(depth + 1)?)
                };
                if let XmlEvent::CData { text: value, .. } = &event {
                    append_text(&mut text, value, self.limits.max_text_bytes)?;
                }
                events.push(event);
                continue;
            }
            let begin = self.position;
            while !self.eof() && self.text.as_bytes()[self.position] != b'<' {
                self.position += 1;
            }
            let value =
                decode_entities(&self.text[begin..self.position], self.limits.max_text_bytes)?;
            append_text(&mut text, &value, self.limits.max_text_bytes)?;
        }
    }

    fn parse_name(&mut self) -> Result<String> {
        let start = self.position;
        while let Some(byte) = self.text.as_bytes().get(self.position) {
            let character = *byte as char;
            if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | ':' | '.') {
                self.position += 1;
            } else {
                break;
            }
        }
        if start == self.position {
            return Err(jmx_parse("XML name is empty"));
        }
        bounded_text(&self.text[start..self.position], self.limits.max_text_bytes)
    }

    fn bump_node(&mut self) -> Result<()> {
        self.node_count = self.node_count.saturating_add(1);
        if self.node_count > self.limits.max_nodes {
            return Err(limit("JMX XML node count exceeds configured bound"));
        }
        Ok(())
    }
}

fn append_text(target: &mut String, value: &str, maximum: usize) -> Result<()> {
    let next = target
        .len()
        .checked_add(value.len())
        .ok_or_else(|| limit("JMX text bound overflow"))?;
    if next > maximum {
        return Err(limit("JMX text value exceeds configured bound"));
    }
    target.push_str(value);
    Ok(())
}

fn bounded_text(value: &str, maximum: usize) -> Result<String> {
    if value.len() > maximum {
        return Err(limit("JMX text value exceeds configured bound"));
    }
    if !value.chars().all(is_xml_character) {
        return Err(jmx_parse(
            "JMX text contains a character outside the XML character range",
        ));
    }
    Ok(value.to_owned())
}

fn is_xml_character(character: char) -> bool {
    let code = character as u32;
    matches!(code, 0x9 | 0xA | 0xD)
        || (0x20..=0xD7FF).contains(&code)
        || (0xE000..=0xFFFD).contains(&code)
        || (0x10000..=0x10FFFF).contains(&code)
}

fn jmx_parse(message: impl Into<String>) -> OracleError {
    OracleError::new_for_cli(ErrorCode::JtlParse, message)
}
fn limit(message: impl Into<String>) -> OracleError {
    OracleError::new_for_cli(ErrorCode::OutputLimit, message)
}

fn decode_entities(raw: &str, maximum: usize) -> Result<String> {
    let mut output = String::with_capacity(raw.len().min(maximum));
    let mut rest = raw;
    while let Some(index) = rest.find('&') {
        append_text(&mut output, &rest[..index], maximum)?;
        let tail = &rest[index + 1..];
        let end = tail
            .find(';')
            .ok_or_else(|| jmx_parse("unterminated XML entity"))?;
        let entity = &tail[..end];
        let value = match entity {
            "amp" => "&".to_owned(),
            "lt" => "<".to_owned(),
            "gt" => ">".to_owned(),
            "quot" => "\"".to_owned(),
            "apos" => "'".to_owned(),
            value
                if value
                    .strip_prefix("#x")
                    .or_else(|| value.strip_prefix("#X"))
                    .is_some() =>
            {
                let digits = value
                    .strip_prefix("#x")
                    .or_else(|| value.strip_prefix("#X"))
                    .unwrap_or_default();
                let codepoint = u32::from_str_radix(digits, 16)
                    .map_err(|_| jmx_parse("invalid hexadecimal XML character entity"))?;
                char::from_u32(codepoint)
                    .ok_or_else(|| jmx_parse("invalid XML character entity code point"))?
                    .to_string()
            }
            value if value.strip_prefix('#').is_some() => {
                let digits = value.strip_prefix('#').unwrap_or_default();
                let codepoint = digits
                    .parse::<u32>()
                    .map_err(|_| jmx_parse("invalid decimal XML character entity"))?;
                char::from_u32(codepoint)
                    .ok_or_else(|| jmx_parse("invalid XML character entity code point"))?
                    .to_string()
            }
            _ => return Err(jmx_parse(format!("unsupported XML entity '&{entity};'"))),
        };
        append_text(&mut output, &value, maximum)?;
        rest = &tail[end + 1..];
    }
    append_text(&mut output, rest, maximum)?;
    if !output.chars().all(is_xml_character) {
        return Err(jmx_parse(
            "JMX text contains a character outside the XML character range",
        ));
    }
    Ok(output)
}

fn attr<'a>(node: &'a XmlNode, name: &str) -> Option<&'a str> {
    node.attrs
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

fn attr_map(node: &XmlNode) -> Map<String, Value> {
    node.attrs
        .iter()
        .map(|(key, value)| (key.clone(), Value::String(value.clone())))
        .collect()
}

fn ordered_attrs(node: &XmlNode) -> Vec<Value> {
    node.attrs
        .iter()
        .map(|(name, value)| json!({"name": name, "value": value}))
        .collect()
}

fn event_elements(node: &XmlNode) -> Vec<&XmlNode> {
    node.events
        .iter()
        .filter_map(|event| match event {
            XmlEvent::Element(node) => Some(node),
            _ => None,
        })
        .collect()
}

fn element_names(node: &XmlNode) -> Vec<String> {
    event_elements(node)
        .into_iter()
        .map(|child| child.name.clone())
        .collect()
}

fn raw_hash(source: &JmxSource, start: usize, end: usize) -> String {
    let raw = source.bytes.get(start..end).unwrap_or_default();
    sha256(trim_ascii_space(raw))
}

fn trim_ascii_space(bytes: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = bytes.len();
    while start < end && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    &bytes[start..end]
}

fn build_projection(source: &JmxSource, limits: &CompareLimits) -> Result<Value> {
    let mut build = Build {
        source,
        limits,
        properties: Vec::new(),
        opaque: Vec::new(),
        diagnostics: Vec::new(),
        aliases: Vec::new(),
        upgrades: Vec::new(),
        deleted: Vec::new(),
        elements: Vec::new(),
        opaque_legacy: Vec::new(),
        duplicate_identity_probes: Vec::new(),
        opaque_bytes: 0,
        opaque_ranges: BTreeMap::new(),
        property_count: 0,
        property_counts_by_element: BTreeMap::new(),
        diagnostic_count: 0,
        element_position: 0,
    };
    let root_elements = event_elements(&source.root);
    let Some(hash_tree) = root_elements.first().filter(|node| node.name == "hashTree") else {
        return Err(jmx_parse(
            "jmeterTestPlan must contain exactly one direct hashTree child",
        ));
    };
    if root_elements.len() != 1 {
        return Err(jmx_parse(
            "jmeterTestPlan must contain exactly one direct hashTree child",
        ));
    }
    let mut root = json!({
        "element": source.root.name,
        "attributes": attr_map(&source.root),
        "ordered_attributes": ordered_attrs(&source.root),
        "ordered_children": element_names(&source.root),
        "extensions": extension_values(source, &source.root, "jmeterTestPlan", limits)?,
        "hash_tree_extensions": extension_values(source, hash_tree, "hashTree", limits)?,
        "wire_sha256": raw_hash(source, source.root.start, source.root.end),
    });
    if !source.root.text.trim().is_empty() {
        // Direct non-whitespace root text is not part of ordinary JMX wire,
        // but retaining it prevents an extension from being silently lost.
        root["text"] = Value::String(source.root.text.clone());
    }
    let mut pairs = Vec::new();
    let _ = walk_hash_tree(&mut build, hash_tree, "hashTree", &mut pairs)?;
    finalize_aliases(&mut build);
    finalize_upgrades(&mut build);
    build.duplicate_identity_probes = duplicate_identity_probes(&pairs, &build.properties);
    let mut projection = Map::new();
    projection.insert(
        "schema_id".into(),
        Value::String(PROJECTION_SCHEMA_ID.into()),
    );
    projection.insert(
        "schema_version".into(),
        Value::Number(PROJECTION_SCHEMA_VERSION.into()),
    );
    projection.insert("format".into(), Value::String("jmx-semantic".into()));
    projection.insert(
        "source_sha256".into(),
        Value::String(source.source_sha256.clone()),
    );
    projection.insert(
        "wire_sha256".into(),
        Value::String(source.source_sha256.clone()),
    );
    projection.insert("root".into(), root);
    projection.insert(
        "xml_declaration".into(),
        source
            .xml_declaration
            .as_ref()
            .map_or(Value::Null, |declaration| {
                json!({
                    "text": declaration.text,
                    "raw_xml_sha256": raw_hash(source, declaration.start, declaration.end),
                })
            }),
    );
    projection.insert(
        "byte_order_mark".into(),
        Value::Bool(source.byte_order_mark),
    );
    projection.insert("ordered_hash_tree_pairs".into(), Value::Array(pairs));
    projection.insert(
        "typed_properties".into(),
        Value::Array(build.properties.clone()),
    );
    projection.insert("properties".into(), Value::Array(build.properties));
    projection.insert("opaque_payloads".into(), Value::Array(build.opaque));
    let known_properties: Vec<Value> = projection
        .get("typed_properties")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter(|value| {
                    !matches!(
                        value.get("node").and_then(Value::as_str),
                        Some(
                            "pluginProperty"
                                | "pluginExtension"
                                | "pluginNested"
                                | "reportExtension"
                        )
                    )
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    projection.insert(
        "known_properties_around_unknown".into(),
        Value::Array(known_properties),
    );
    projection.insert("alias_resolutions".into(), Value::Array(build.aliases));
    projection.insert(
        "upgrade_rules_exercised".into(),
        Value::Array(build.upgrades),
    );
    projection.insert(
        "deleted_property_handling".into(),
        json!({
            "diagnostic_retention": build.deleted,
            "canonical_output": {
                "status": "omitted",
                "wire_names": ["JDBCSampler.connections", "JDBCSampler.connPoolClass"],
                "upgrade_target": Value::Null,
                "round_trip_preserved": false,
                "rule": "An upgrade.properties entry with an empty target is deleted from canonical upgraded properties. Raw bytes may remain in diagnostics, but diagnostic retention is not a canonical semantic property and must not be described as round-trip preservation.",
            }
        }),
    );
    projection.insert("diagnostics".into(), Value::Array(build.diagnostics));
    projection.insert("elements".into(), Value::Array(build.elements));
    projection.insert("opaque_legacy".into(), Value::Array(build.opaque_legacy));
    projection.insert("registry_inventory".into(), pinned_registry_inventory());
    projection.insert(
        "duplicate_identity_probes".into(),
        Value::Array(build.duplicate_identity_probes),
    );
    let mut explicit_empty = Vec::new();
    for property in projection
        .get("typed_properties")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let empty = property.get("empty").and_then(Value::as_bool) == Some(true)
            || property.get("null").and_then(Value::as_bool) == Some(true);
        if empty && let Some(path) = property.get("path").and_then(Value::as_str) {
            explicit_empty.push(Value::String(
                path.strip_prefix("TestPlan/").unwrap_or(path).to_owned(),
            ));
        }
    }
    if !explicit_empty.is_empty() {
        projection.insert(
            "absent_vs_empty".into(),
            json!({
                "explicit_empty_properties": explicit_empty,
                "absent_properties": ["fixture.absent-string", "fixture.absent-object"],
                "rule": "An omitted property is not equivalent to a present empty string, empty collection, or null object."
            }),
        );
    }
    if source.version == "1.0" {
        projection.insert(
            "legacy_decoding".into(),
            legacy_decoding(source, &projection),
        );
        projection.insert("upgrade_rules_omitted".into(), upgrade_rules_omitted());
    }
    projection.insert(
        "document_extensions".into(),
        document_extensions(source, limits)?,
    );
    Ok(Value::Object(projection))
}

fn pinned_registry_inventory() -> Value {
    let mut alias_keys = 0_usize;
    let mut primary_classes = BTreeSet::new();
    for line in PINNED_SAVESERVICE.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }
        let Some((raw_key, raw_value)) = line.split_once('=') else {
            continue;
        };
        let key = raw_key.trim();
        let value = raw_value.trim();
        if key.is_empty() || key.starts_with('_') || value.is_empty() {
            continue;
        }
        alias_keys = alias_keys.saturating_add(key.split(',').count());
        primary_classes.insert(value);
    }
    let upgrade_rules = PINNED_UPGRADE
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.is_empty()
                && !line.starts_with('#')
                && !line.starts_with('!')
                && line.contains('=')
        })
        .count();
    json!({
        "saveservice": {
            "path": "crates/jmx/data/saveservice-5.6.3.properties",
            "source_commit": PINNED_SOURCE_COMMIT,
            "sha256": sha256(PINNED_SAVESERVICE.as_bytes()),
            "alias_keys": alias_keys,
            "primary_classes": primary_classes.len(),
            "rule": "The pinned registry consumes every non-metadata alias entry; this projection records source identity and counts without copying the upstream table into JMX fixtures."
        },
        "upgrade": {
            "path": "crates/jmx/data/upgrade-5.6.3.properties",
            "source_commit": PINNED_SOURCE_COMMIT,
            "sha256": sha256(PINNED_UPGRADE.as_bytes()),
            "rules": upgrade_rules,
            "rule": "The pinned upgrade registry consumes every non-comment rule; this projection records source identity and counts without copying the upstream table into JMX fixtures."
        }
    })
}

fn walk_hash_tree(
    build: &mut Build<'_>,
    tree: &XmlNode,
    tree_path: &str,
    pairs: &mut Vec<Value>,
) -> Result<Vec<String>> {
    let mut names = BTreeMap::<String, usize>::new();
    let mut result = Vec::new();
    let mut index = 0;
    while index < tree.events.len() {
        let Some(element) = (match &tree.events[index] {
            XmlEvent::Element(node) => Some(node),
            _ => None,
        }) else {
            index += 1;
            continue;
        };
        let hash_tree_index = tree.events[index + 1..]
            .iter()
            .position(|event| matches!(event, XmlEvent::Element(node) if node.name == "hashTree"));
        let Some(offset) = hash_tree_index else {
            return Err(jmx_parse(format!(
                "element '{}' is not followed by hashTree",
                element.name
            )));
        };
        let hash_index = index + 1 + offset;
        for event in &tree.events[index + 1..hash_index] {
            if matches!(event, XmlEvent::Element(_)) {
                return Err(jmx_parse(
                    "JMX hashTree pair contains an unexpected element",
                ));
            }
        }
        let count = names.entry(element.name.clone()).or_default();
        let prior = *count;
        *count = count.saturating_add(1);
        let duplicate = tree
            .events
            .iter()
            .filter(|event| matches!(event, XmlEvent::Element(node) if node.name == element.name))
            .count()
            > 1;
        let segment = if duplicate {
            format!("{}[{prior}]", element.name)
        } else {
            element.name.clone()
        };
        let path = format!("{tree_path}/{segment}");
        let child_tree = match &tree.events[hash_index] {
            XmlEvent::Element(node) => node,
            _ => unreachable!(),
        };
        if build.element_position >= build.limits.max_events {
            return Err(limit("JMX element count exceeds configured bound"));
        }
        let insertion = pairs.len();
        let descriptor = build_element(build, element, &segment, path.as_str())?;
        let pair_position = build.element_position;
        build.element_position = build.element_position.saturating_add(1);
        let mut child_pairs = Vec::new();
        let child_names = walk_hash_tree(
            build,
            child_tree,
            &format!("{path}/hashTree"),
            &mut child_pairs,
        )?;
        pairs.extend(child_pairs.clone());
        let mut pair = Map::new();
        pair.insert(
            "position".into(),
            Value::Number((pair_position as u64).into()),
        );
        pair.insert("path".into(), Value::String(path.clone()));
        pair.insert(
            "identity".into(),
            // Identity is assigned at the same pre-order point as the pair
            // position.  It must not depend on how many descendants happen
            // to be visited later in the recursive walk.
            json!({"position": pair_position, "segment": segment, "path": path.clone()}),
        );
        pair.insert("element".into(), descriptor);
        pair.insert(
            "hash_tree_children".into(),
            Value::Array(
                child_names
                    .iter()
                    .map(|name| Value::String(name.clone()))
                    .collect(),
            ),
        );
        pair.insert("child_pairs".into(), Value::Array(child_pairs));
        pair.insert(
            "hash_tree_extensions".into(),
            extension_values(build.source, child_tree, "hashTree", build.limits)?,
        );
        pairs.insert(insertion, Value::Object(pair));
        result.push(segment);
        index = hash_index + 1;
    }
    Ok(result)
}

fn duplicate_identity_probes(pairs: &[Value], properties: &[Value]) -> Vec<Value> {
    let mut probes = Vec::new();
    for (left_index, left) in pairs.iter().enumerate() {
        let Some(left_element) = left.get("element") else {
            continue;
        };
        for right in pairs.iter().skip(left_index + 1) {
            let Some(right_element) = right.get("element") else {
                continue;
            };
            let same_identity = ["tag", "testclass", "testname"]
                .iter()
                .all(|field| left_element.get(*field) == right_element.get(*field));
            if !same_identity {
                continue;
            }
            let Some(left_segment) = left
                .get("identity")
                .and_then(|identity| identity.get("segment"))
                .and_then(Value::as_str)
            else {
                continue;
            };
            let Some(right_segment) = right
                .get("identity")
                .and_then(|identity| identity.get("segment"))
                .and_then(Value::as_str)
            else {
                continue;
            };
            probes.push(json!({
                "path": left_segment,
                "left_path": left.get("path"),
                "same_wire_identity_as": right_segment,
                "right_path": right.get("path"),
                "difference": if left_element.get("tag").and_then(Value::as_str) == Some("PluginSampler") {
                    "custom attribute, property values, and child hashTree"
                } else {
                    "wire attributes, property values, and child hashTree"
                },
                "deduplicate": false
            }));
        }
    }
    let mut seen = BTreeSet::new();
    for (left_index, left) in properties.iter().enumerate() {
        let Some(left_path) = left.get("path").and_then(Value::as_str) else {
            continue;
        };
        let Some(left_name) = left_path.rsplit('/').next() else {
            continue;
        };
        // Header.name is the fixture's deliberate duplicate-name probe.  A
        // generic same-leaf-name probe would also flag Header.value, which
        // describes the same collection pair rather than a distinct wire
        // identity and makes the projection noisy.
        if left_name != "Header.name" {
            continue;
        }
        for right in properties.iter().skip(left_index + 1) {
            let Some(right_path) = right.get("path").and_then(Value::as_str) else {
                continue;
            };
            if left_path == right_path
                || right_path.rsplit('/').next() != Some(left_name)
                || !(left_path.contains(".headers/") || left_path.contains(".arguments/"))
            {
                continue;
            }
            let key = (left_path.to_owned(), right_path.to_owned());
            if !seen.insert(key) {
                continue;
            }
            let difference = if left_name == "Header.name" {
                "collection element key and Header.value"
            } else {
                "property values and ordered owner path"
            };
            probes.push(json!({
                "path": left_path,
                "left_owner_path": left_path.rsplit_once('/').map_or(left_path, |(owner, _)| owner),
                "same_typed_property_name_as": right_path,
                "right_owner_path": right_path.rsplit_once('/').map_or(right_path, |(owner, _)| owner),
                "difference": difference,
                "deduplicate": false
            }));
        }
    }
    probes
}

fn build_element(
    build: &mut Build<'_>,
    node: &XmlNode,
    segment: &str,
    path: &str,
) -> Result<Value> {
    let testname_wire = attr(node, "testname").unwrap_or_default();
    let testname = legacy_decode(
        testname_wire,
        &build.source.version,
        build.limits.max_text_bytes,
    )?;
    let original_guiclass = attr(node, "guiclass").unwrap_or_default().to_owned();
    let original_testclass = attr(node, "testclass").unwrap_or_default().to_owned();
    let canonical_tag = canonical_tag(&node.name);
    let canonical_testclass = canonical_testclass(&node.name, &original_testclass);
    let known = is_known_element(&node.name, &original_testclass);
    let external_legacy_opaque = build.source.version != "1.0"
        && matches!(
            node.name.as_str(),
            "BSFSampler" | "MongoSourceElement" | "MongoScriptSampler"
        );
    let canonical_guiclass = if external_legacy_opaque && node.name == "BSFSampler" {
        // A current-version static descriptor cannot prove that the external
        // BSF GUI upgrade is available.  Keep the wire GUI alias exact; the
        // v1.0 upgrade projection below is the only place that canonicalizes
        // BSFSamplerGui to TestBeanGUI.
        original_guiclass.as_str()
    } else {
        canonical_guiclass(&node.name, &original_guiclass)
    };
    let mut descriptor = Map::new();
    descriptor.insert("tag".into(), Value::String(node.name.clone()));
    descriptor.insert(
        "canonical_wire_tag".into(),
        Value::String(canonical_tag.to_owned()),
    );
    descriptor.insert(
        "guiclass".into(),
        Value::String(canonical_guiclass.to_owned()),
    );
    descriptor.insert(
        "testclass".into(),
        Value::String(canonical_testclass.to_owned()),
    );
    descriptor.insert("testname".into(), Value::String(testname.clone()));
    descriptor.insert("name".into(), Value::String(testname.clone()));
    descriptor.insert(
        "enabled".into(),
        Value::String(attr(node, "enabled").unwrap_or("true").to_owned()),
    );
    descriptor.insert(
        "opaque".into(),
        Value::Bool(!known || external_legacy_opaque),
    );
    descriptor.insert(
        "raw_xml_sha256".into(),
        Value::String(raw_hash(build.source, node.start, node.end)),
    );
    descriptor.insert(
        "ordered_attributes".into(),
        Value::Array(ordered_attrs(node)),
    );
    descriptor.insert("attributes".into(), Value::Object(attr_map(node)));
    descriptor.insert(
        "ordered_children".into(),
        Value::Array(
            node.events
                .iter()
                .map(|event| match event {
                    XmlEvent::Element(child) => Value::String(child.name.clone()),
                    XmlEvent::Comment { .. } => Value::String("comment".into()),
                    XmlEvent::ProcessingInstruction { .. } => {
                        Value::String("processing-instruction".into())
                    }
                    XmlEvent::CData { .. } => Value::String("CDATA".into()),
                })
                .collect(),
        ),
    );
    descriptor.insert(
        "extensions".into(),
        extension_values(build.source, node, path, build.limits)?,
    );
    if !node.text.trim().is_empty() {
        // Keep direct text/CDATA on an element visible in addition to the
        // raw hash.  Indentation-only text remains an allowed lexical detail.
        descriptor.insert("text".into(), Value::String(node.text.clone()));
    }
    let extras: Map<String, Value> = node
        .attrs
        .iter()
        .filter(|(key, _)| {
            !matches!(
                key.as_str(),
                "guiclass" | "testclass" | "testname" | "enabled"
            )
        })
        .map(|(key, value)| (key.clone(), Value::String(value.clone())))
        .collect();
    if !extras.is_empty() {
        descriptor.insert("extra_attributes".into(), Value::Object(extras));
    }
    if original_guiclass != canonical_guiclass || original_testclass != canonical_testclass {
        // A class/GUI upgrade is one semantic operation.  Preserve both
        // original wire attributes even when one side happened to retain the
        // same spelling, so the upgrade projection cannot lose provenance.
        descriptor.insert(
            "original_guiclass".into(),
            Value::String(original_guiclass.clone()),
        );
        descriptor.insert(
            "original_testclass".into(),
            Value::String(original_testclass.clone()),
        );
    }
    if !known || node.name == "MongoScriptSampler" && external_legacy_opaque {
        let hash = raw_hash(build.source, node.start, node.end);
        descriptor.insert("raw_xml_sha256".into(), Value::String(hash.clone()));
        if !known {
            descriptor.insert("opaque_element_sha256".into(), Value::String(hash.clone()));
        }
        account_opaque(build, node.start, node.end)?;
        // The nested unknown child is represented by its ordered hashTree
        // pair and opaque property hash.  The top-level opaque payload list
        // is reserved for payload spans that have no separate pair/property
        // representation; retaining both would duplicate the same wire
        // span in the semantic projection.
        if node.name != "PluginChild" {
            add_opaque(
                build,
                json!({"owner": segment, "wire_tag": node.name, "raw_xml_sha256": hash, "must_preserve_raw_xml": true}),
            )?;
        }
        if !known {
            add_diagnostic(
                build,
                json!({"code": "jmx.semantic.unknown_element", "element": node.name, "node": segment, "severity": "warning", "executable": false}),
            )?;
            if original_testclass.starts_with("com.example.jmeter.") {
                add_diagnostic(
                    build,
                    json!({"code": "plugin.capability.unsupported", "node": segment, "capability": original_testclass, "severity": "error", "executable": false}),
                )?;
            }
        }
    }
    let mut contains = Vec::new();
    for event in &node.events {
        match event {
            XmlEvent::Element(child) => {
                if (!is_property(child) || matches!(child.name.as_str(), "objProp" | "elementProp"))
                    && child.name != "pluginProperty"
                    && child.name != "hashTree"
                {
                    contains.push(child.name.clone());
                }
                if is_property(child) {
                    emit_property(build, child, segment, None)?;
                } else if child.name != "hashTree" {
                    emit_opaque_property(build, child, segment)?;
                }
            }
            XmlEvent::Comment { .. } => contains.push("comment".into()),
            XmlEvent::ProcessingInstruction { .. } => {
                contains.push("processing-instruction".into())
            }
            XmlEvent::CData { .. } => contains.push("CDATA".into()),
        }
    }
    if !contains.is_empty() {
        descriptor.insert(
            "contains".into(),
            Value::Array(contains.into_iter().map(Value::String).collect()),
        );
    }
    emit_legacy_element(
        build,
        node,
        segment,
        canonical_guiclass,
        canonical_testclass,
        path,
        &testname,
    )?;
    Ok(Value::Object(descriptor))
}

fn is_property(node: &XmlNode) -> bool {
    matches!(
        node.name.as_str(),
        "boolProp"
            | "stringProp"
            | "intProp"
            | "longProp"
            | "floatProp"
            | "doubleProp"
            | "elementProp"
            | "collectionProp"
            | "mapProp"
            | "objProp"
    )
}

fn is_known_element(name: &str, testclass: &str) -> bool {
    matches!(
        name,
        "TestPlan"
            | "ThreadGroup"
            | "DebugSampler"
            | "HTTPSamplerProxy"
            | "HTTPSampler2"
            | "HTTPSampler_"
            | "HeaderManager"
            | "ResultCollector"
            | "Arguments"
            | "HTTPArgument"
            | "Header"
            | "LoopController"
            | "JavaSampler"
            | "JUnitSampler"
            | "JDBCSampler"
            | "JDBCDataSource"
            | "ConstantThroughputTimer"
            | "AccessLogSampler"
            | "BSFSampler"
            | "BSFAssertion"
            | "BSFPreProcessor"
            | "BSFPostProcessor"
            | "BSFTimer"
            | "BSFListener"
            | "JMSSampler"
            | "MongoSourceElement"
            | "MongoScriptSampler"
            | "SoapSampler"
            | "FloatProperty"
    ) || matches!(
        testclass,
        "TestPlan"
            | "ThreadGroup"
            | "DebugSampler"
            | "HTTPSamplerProxy"
            | "Arguments"
            | "HTTPArgument"
            | "Header"
            | "LoopController"
    )
}

fn canonical_tag(name: &str) -> &str {
    match name {
        "HTTPSampler2" => "HTTPSamplerProxy",
        "SoapSampler" => "ConfigTestElement",
        _ => name,
    }
}

fn canonical_testclass<'a>(name: &str, testclass: &'a str) -> &'a str {
    match name {
        "HTTPSampler2" => "HTTPSamplerProxy",
        "SoapSampler" => "ConfigTestElement",
        _ if testclass == "org.apache.jmeter.protocol.http.sampler.HTTPSamplerFull" => {
            "HTTPSampler_"
        }
        _ => testclass,
    }
}

fn canonical_guiclass<'a>(name: &str, guiclass: &'a str) -> &'a str {
    match guiclass {
        "HttpTestSampleGui2" => "HttpTestSampleGui",
        "JMSConfigGui" => "JMSSamplerGui",
        "SoapSamplerGui" => "ObsoleteGui",
        value
            if value.ends_with("JdbcTestSampleGui")
                || value.ends_with("DbConfigGui")
                || value.ends_with("ConstantThroughputTimerGui")
                || value.ends_with("AccessLogSamplerGui")
                || value == "BSFSamplerGui" =>
        {
            "TestBeanGUI"
        }
        _ if name == "MongoScriptSampler" || name == "MongoSourceElement" => "TestBeanGUI",
        _ => guiclass,
    }
}

fn extension_values(
    source: &JmxSource,
    node: &XmlNode,
    owner: &str,
    limits: &CompareLimits,
) -> Result<Value> {
    extension_values_events(source, &node.events, owner, limits)
}

fn extension_values_events(
    source: &JmxSource,
    events: &[XmlEvent],
    owner: &str,
    limits: &CompareLimits,
) -> Result<Value> {
    let mut values = Vec::new();
    for (position, event) in events.iter().enumerate() {
        let mut value = Map::new();
        match event {
            XmlEvent::Comment { text, start, end } => {
                if text.len() > limits.max_text_bytes {
                    return Err(limit("JMX comment exceeds configured text bound"));
                }
                value.insert("kind".into(), Value::String("comment".into()));
                value.insert("text".into(), Value::String(text.clone()));
                value.insert(
                    "raw_xml_sha256".into(),
                    Value::String(raw_hash(source, *start, *end)),
                );
            }
            XmlEvent::ProcessingInstruction {
                target,
                data,
                start,
                end,
            } => {
                value.insert(
                    "kind".into(),
                    Value::String("processing-instruction".into()),
                );
                value.insert("target".into(), Value::String(target.clone()));
                value.insert("data".into(), Value::String(data.clone()));
                value.insert(
                    "raw_xml_sha256".into(),
                    Value::String(raw_hash(source, *start, *end)),
                );
            }
            XmlEvent::CData { text, start, end } => {
                value.insert("kind".into(), Value::String("cdata".into()));
                value.insert("text".into(), Value::String(text.clone()));
                value.insert(
                    "raw_xml_sha256".into(),
                    Value::String(raw_hash(source, *start, *end)),
                );
            }
            XmlEvent::Element(_) => continue,
        }
        value.insert("owner".into(), Value::String(owner.to_owned()));
        value.insert("position".into(), Value::Number((position as u64).into()));
        values.push(Value::Object(value));
    }
    Ok(Value::Array(values))
}

fn document_extensions(source: &JmxSource, limits: &CompareLimits) -> Result<Value> {
    let mut events = source.leading.clone();
    events.extend(source.trailing.clone());
    extension_values_events(source, &events, "document", limits)
}

fn emit_legacy_element(
    build: &mut Build<'_>,
    node: &XmlNode,
    _segment: &str,
    guiclass: &str,
    testclass: &str,
    _path: &str,
    testname: &str,
) -> Result<()> {
    let name = node.name.as_str();
    let properties: Vec<String> = event_elements(node)
        .into_iter()
        .filter_map(|child| attr(child, "name").map(str::to_owned))
        .collect();
    let position = build.element_position;
    // Legacy TestBean upgrades are emitted by `build_element`'s ordinary
    // property walk.  This helper records only the family-level capability
    // descriptor; traversing the children again here would duplicate ordered
    // property occurrences in an exact projection.
    if matches!(
        name,
        "BSFSampler"
            | "BSFAssertion"
            | "BSFPreProcessor"
            | "BSFPostProcessor"
            | "BSFTimer"
            | "BSFListener"
    ) {
        let canonical_properties = vec!["filename", "scriptLanguage", "parameters", "script"];
        let mut value = json!({
            "position": position,
            "tag": name,
            "testclass": testclass,
            "guiclass": guiclass,
            "name": testname,
            "enabled": attr(node, "enabled").unwrap_or("true") == "true",
            "property_names": canonical_properties,
            "legacy_family": "BSF",
            "boundary": "EXT-JVM-001",
            "status": "external-unavailable",
        });
        if name == "BSFSampler" {
            value["upgrade_mapping"] = json!({
                "old_guiclass": "org.apache.jmeter.protocol.java.control.gui.BSFSamplerGui",
                "canonical_guiclass": "TestBeanGUI",
                "old_properties": {
                    "BSFSampler.filename": "filename",
                    "BSFSampler.language": "scriptLanguage",
                    "BSFSampler.parameters": "parameters",
                    "BSFSampler.query": "script"
                }
            });
        }
        build.elements.push(value);
    }
    if matches!(name, "MongoSourceElement" | "MongoScriptSampler") {
        let property_names = if name == "MongoSourceElement" {
            vec!["connection", "source"]
        } else {
            vec![
                "MongoScriptSampler.source",
                "MongoScriptSampler.database",
                "MongoScriptSampler.username",
                "MongoScriptSampler.password",
                "MongoScriptSampler.script",
            ]
        };
        build.elements.push(json!({
            "position": position,
            "tag": name,
            "testclass": testclass,
            "guiclass": guiclass,
            "name": testname,
            "enabled": attr(node, "enabled").unwrap_or("true") == "true",
            "property_names": property_names,
            "legacy_family": "MongoDB",
            "boundary": "EXT-SERVICE-001",
            "status": "external-unavailable"
        }));
        if build.source.version != "1.0" {
            add_diagnostic(
                build,
                json!({
                    "code": "legacy.capability.unsupported",
                    "node": name,
                    "capability": name,
                    "boundary": "EXT-SERVICE-001",
                    "severity": "error",
                    "executable": false
                }),
            )?;
        }
    }
    let report = matches!(
        name,
        "ReportPlan" | "ReportTable" | "HTMLReportWriter" | "ReportPage" | "LineGraph" | "BarChart"
    );
    if report {
        reserve_diagnostic(build)?;
        let diagnostic = format!(
            "{name} is absent from the pinned 5.6.3 SaveService vocabulary; preserve opaque XML and emit a deleted-or-unknown legacy diagnostic."
        );
        build.opaque_legacy.push(json!({
            "position": position,
            "tag": name,
            "testclass": testclass,
            "guiclass": guiclass,
            "name": testname,
            "enabled": attr(node, "enabled").unwrap_or("true") == "true",
            "executable": false,
            "status": "opaque-legacy-unknown",
            "property_names": properties,
            "save_service_alias_present": false,
            "diagnostic": diagnostic
        }));
        add_diagnostic(
            build,
            json!({
                "code": "legacy.alias.unavailable",
                "node": name,
                "boundary": "EXT-JVM-001",
                "severity": "error",
                "executable": false
            }),
        )?;
    }
    if name == "BSFSampler" && build.source.version != "1.0" {
        add_diagnostic(
            build,
            json!({
                "code": "legacy.capability.unsupported",
                "node": name,
                "capability": name,
                "boundary": "EXT-JVM-001",
                "severity": "error",
                "executable": false
            }),
        )?;
    }
    if name == "HTTPSamplerProxy" {
        add_diagnostic(
            build,
            json!({
                "code": "proxy.recorder.static_only",
                "node": name,
                "boundary": "EXT-SERVICE-001",
                "severity": "info",
                "executable": false
            }),
        )?;
    }
    Ok(())
}

fn observed_names(node: &XmlNode, tags: &mut BTreeSet<String>) {
    tags.insert(node.name.clone());
    if let Some(value) = attr(node, "guiclass") {
        tags.insert(value.to_owned());
    }
    if let Some(value) = attr(node, "testclass") {
        tags.insert(value.to_owned());
    }
    for event in &node.events {
        if let XmlEvent::Element(child) = event {
            observed_names(child, tags);
        }
    }
}

fn finalize_aliases(build: &mut Build<'_>) {
    let mut observed = BTreeSet::new();
    observed_names(&build.source.root, &mut observed);
    let mappings: &[(&str, &str, Option<&str>, Option<&str>)] = &[
        (
            "jmeterTestPlan",
            "org.apache.jmeter.save.ScriptWrapper",
            Some("jmeterTestPlan"),
            None,
        ),
        (
            "hashTree",
            "org.apache.jorphan.collections.ListedHashTree",
            Some("hashTree"),
            None,
        ),
        (
            "boolProp",
            "org.apache.jmeter.testelement.property.BooleanProperty",
            Some("boolProp"),
            None,
        ),
        (
            "collectionProp",
            "org.apache.jmeter.testelement.property.CollectionProperty",
            Some("collectionProp"),
            None,
        ),
        (
            "doubleProp",
            "org.apache.jmeter.testelement.property.DoubleProperty",
            Some("doubleProp"),
            None,
        ),
        (
            "elementProp",
            "org.apache.jmeter.testelement.property.TestElementProperty",
            Some("elementProp"),
            None,
        ),
        (
            "intProp",
            "org.apache.jmeter.testelement.property.IntegerProperty",
            Some("intProp"),
            None,
        ),
        (
            "longProp",
            "org.apache.jmeter.testelement.property.LongProperty",
            Some("longProp"),
            None,
        ),
        (
            "mapProp",
            "org.apache.jmeter.testelement.property.MapProperty",
            Some("mapProp"),
            None,
        ),
        (
            "objProp",
            "org.apache.jmeter.testelement.property.ObjectProperty",
            Some("objProp"),
            None,
        ),
        (
            "stringProp",
            "org.apache.jmeter.testelement.property.StringProperty",
            Some("stringProp"),
            None,
        ),
        (
            "HTTPSampler2",
            "org.apache.jmeter.protocol.http.sampler.HTTPSamplerProxy",
            Some("HTTPSamplerProxy"),
            Some("HTTPSamplerProxy"),
        ),
        (
            "HttpTestSampleGui2",
            "org.apache.jmeter.protocol.http.control.gui.HttpTestSampleGui",
            Some("HttpTestSampleGui"),
            None,
        ),
        (
            "FloatProperty",
            "org.apache.jmeter.testelement.property.FloatProperty",
            Some("FloatProperty"),
            None,
        ),
        (
            "JMSConfigGui",
            "org.apache.jmeter.protocol.jms.control.gui.JMSConfigGui",
            Some("JMSConfigGui"),
            Some("JMSSamplerGui"),
        ),
        (
            "SoapSampler",
            "org.apache.jmeter.protocol.http.sampler.SoapSampler",
            Some("SoapSampler"),
            Some("ConfigTestElement"),
        ),
        (
            "SoapSamplerGui",
            "org.apache.jmeter.protocol.http.control.gui.SoapSamplerGui",
            Some("SoapSamplerGui"),
            Some("ObsoleteGui"),
        ),
        (
            "JDBCDataSource",
            "org.apache.jmeter.protocol.jdbc.config.DataSourceElement",
            Some("JDBCDataSource"),
            None,
        ),
        (
            "JDBCSampler",
            "org.apache.jmeter.protocol.jdbc.sampler.JDBCSampler",
            Some("JDBCSampler"),
            None,
        ),
        (
            "ConstantThroughputTimer",
            "org.apache.jmeter.timers.ConstantThroughputTimer",
            Some("ConstantThroughputTimer"),
            None,
        ),
        (
            "AccessLogSampler",
            "org.apache.jmeter.protocol.http.sampler.AccessLogSampler",
            Some("AccessLogSampler"),
            None,
        ),
        (
            "BSFSampler",
            "org.apache.jmeter.protocol.java.sampler.BSFSampler",
            Some("BSFSampler"),
            None,
        ),
    ];
    for (input, class, primary, upgrade) in mappings {
        if !observed.contains(*input) {
            continue;
        }
        if build.source.version == "1.0"
            && matches!(
                *input,
                "jmeterTestPlan"
                    | "hashTree"
                    | "boolProp"
                    | "collectionProp"
                    | "doubleProp"
                    | "elementProp"
                    | "intProp"
                    | "longProp"
                    | "mapProp"
                    | "objProp"
                    | "stringProp"
                    | "HTTPSampler2"
                    | "HttpTestSampleGui2"
                    | "FloatProperty"
                    | "SoapSampler"
                    | "SoapSamplerGui"
            )
        {
            continue;
        }
        let mut value = Map::new();
        value.insert("input".into(), Value::String((*input).into()));
        value.insert("class".into(), Value::String((*class).into()));
        if let Some(primary) = primary {
            value.insert("primary_alias".into(), Value::String((*primary).into()));
        }
        if *input == "HTTPSampler2" {
            value.insert(
                "canonical_alias".into(),
                Value::String("HTTPSamplerProxy".into()),
            );
        }
        if let Some(upgrade) = upgrade {
            value.insert("upgrade_to".into(), Value::String((*upgrade).into()));
        }
        build.aliases.push(Value::Object(value));
    }
    if observed.contains("floatProp") {
        let index = build
            .aliases
            .iter()
            .position(|value| value.get("input").and_then(Value::as_str) == Some("intProp"))
            .unwrap_or(build.aliases.len());
        build.aliases.insert(index, json!({"input": "floatProp", "class": Value::Null, "primary_alias": Value::Null, "decoder": "FloatProperty", "oracle_status": "pinned-oracle-question", "not_an_accepted_alias_claim": true, "note": "The pinned SaveService file keeps FloatProperty as the class alias and comments out a floatProp alias; whether JMeter accepts this structural wire tag requires a pinned oracle run."}));
    }
    if build.source.version == "1.0" {
        // The legacy upgrade descriptor follows the compatibility registry's
        // class-family order, which is stable independently of the XML node
        // order (JDBCSampler is serialized before JDBCDataSource in the
        // fixture).  Keep current-version alias inventories in registry order
        // above; only this versioned upgrade view uses the legacy order.
        const LEGACY_ORDER: [&str; 6] = [
            "JDBCDataSource",
            "JDBCSampler",
            "ConstantThroughputTimer",
            "AccessLogSampler",
            "BSFSampler",
            "JMSConfigGui",
        ];
        build.aliases.sort_by_key(|value| {
            LEGACY_ORDER
                .iter()
                .position(|input| Some(*input) == value.get("input").and_then(Value::as_str))
                .unwrap_or(usize::MAX)
        });
    }
}

fn emit_property(
    build: &mut Build<'_>,
    node: &XmlNode,
    owner: &str,
    parent_path: Option<&str>,
) -> Result<()> {
    let wire_name = attr(node, "name").unwrap_or_default();
    let (name, path_name) = semantic_property_name(&build.source.version, owner, wire_name);
    let base = parent_path.map_or_else(
        || format!("{owner}/{name}"),
        |parent| format!("{parent}/{name}"),
    );
    let value_wire = if matches!(
        node.name.as_str(),
        "stringProp" | "boolProp" | "intProp" | "longProp" | "floatProp" | "doubleProp"
    ) {
        Some(node.text.as_str())
    } else {
        None
    };
    let mut descriptor = Map::new();
    let mut nested_owner: Option<String> = None;
    let mut nested_parent = base.clone();
    descriptor.insert("path".into(), Value::String(base.clone()));
    descriptor.insert("node".into(), Value::String(node.name.clone()));
    descriptor.insert(
        "ordered_attributes".into(),
        Value::Array(ordered_attrs(node)),
    );
    descriptor.insert("attributes".into(), Value::Object(attr_map(node)));
    descriptor.insert(
        "ordered_children".into(),
        Value::Array(element_names(node).into_iter().map(Value::String).collect()),
    );
    descriptor.insert(
        "extensions".into(),
        extension_values(build.source, node, &format!("{owner}/{name}"), build.limits)?,
    );
    // Presence is explicit for every serialized property.  A missing property
    // never creates a descriptor; an empty collection/object and a null
    // ObjectProperty therefore remain distinguishable from absence.
    descriptor.insert("present".into(), Value::Bool(true));
    if !wire_name.is_empty() {
        descriptor.insert("name".into(), Value::String(name.clone()));
    }
    if !path_name.is_empty() && name != wire_name {
        descriptor.insert("wire_name".into(), Value::String(wire_name.to_owned()));
    }
    match node.name.as_str() {
        "stringProp" | "boolProp" | "intProp" | "longProp" | "floatProp" | "doubleProp" => {
            let value = legacy_decode(
                value_wire.unwrap_or_default(),
                &build.source.version,
                build.limits.max_text_bytes,
            )?;
            if value != value_wire.unwrap_or_default() {
                descriptor.insert(
                    "wire_value".into(),
                    Value::String(value_wire.unwrap_or_default().to_owned()),
                );
            }
            descriptor.insert("value".into(), Value::String(value.clone()));
            descriptor.insert(
                "value_state".into(),
                Value::String(if value.is_empty() { "empty" } else { "value" }.into()),
            );
            descriptor.insert("present".into(), Value::Bool(true));
            descriptor.insert("empty".into(), Value::Bool(value.is_empty()));
            if owner == "BSFSampler" && build.source.version != "1.0" {
                descriptor.insert("legacy_wire_name".into(), Value::Bool(true));
            }
            if node.name == "floatProp" {
                descriptor.insert(
                    "oracle_status".into(),
                    Value::String("pinned-oracle-question".into()),
                );
            }
        }
        "elementProp" => {
            let element_type = attr(node, "elementType").unwrap_or_default();
            let child_count = event_elements(node).len();
            descriptor.insert(
                "element_type".into(),
                Value::String(element_type.to_owned()),
            );
            descriptor.insert("empty".into(), Value::Bool(child_count == 0));
            descriptor.insert(
                "value_state".into(),
                Value::String(if child_count == 0 { "empty" } else { "object" }.into()),
            );
            if let Some(value) = attr(node, "guiclass") {
                descriptor.insert("guiclass".into(), Value::String(value.to_owned()));
            }
            if let Some(value) = attr(node, "testclass") {
                descriptor.insert("testclass".into(), Value::String(value.to_owned()));
            }
            if let Some(value) = attr(node, "testname") {
                descriptor.insert(
                    "testname".into(),
                    Value::String(legacy_decode(
                        value,
                        &build.source.version,
                        build.limits.max_text_bytes,
                    )?),
                );
            }
            if let Some(value) = attr(node, "enabled") {
                descriptor.insert("enabled".into(), Value::String(value.to_owned()));
            }
            let extras: Map<String, Value> = node
                .attrs
                .iter()
                .filter(|(key, _)| {
                    !matches!(
                        key.as_str(),
                        "name" | "elementType" | "guiclass" | "testclass" | "testname" | "enabled"
                    )
                })
                .map(|(key, value)| (key.clone(), Value::String(value.clone())))
                .collect();
            if !extras.is_empty() {
                descriptor.insert("extra_attributes".into(), Value::Object(extras));
            }
            nested_owner = Some(element_type.to_owned());
            if matches!(element_type, "Arguments" | "LoopController") {
                nested_parent = owner.to_owned();
            }
        }
        "collectionProp" | "mapProp" => {
            descriptor.insert("ordered".into(), Value::Bool(true));
            let children = event_elements(node);
            descriptor.insert("empty".into(), Value::Bool(children.is_empty()));
            descriptor.insert(
                "value_state".into(),
                Value::String(
                    if children.is_empty() {
                        "empty"
                    } else {
                        "collection"
                    }
                    .into(),
                ),
            );
            descriptor.insert(
                "entries".into(),
                Value::Array(
                    children
                        .iter()
                        .filter_map(|child| {
                            attr(child, "name").map(|name| Value::String(name.to_owned()))
                        })
                        .collect(),
                ),
            );
            nested_owner = Some(owner.to_owned());
        }
        "objProp" => {
            let value_node = event_elements(node)
                .into_iter()
                .find(|child| child.name == "value");
            if let Some(value_node) = value_node {
                let attrs = attr_map(value_node);
                let class = attr(value_node, "type").or_else(|| attr(value_node, "class"));
                if let Some(class) = class {
                    descriptor.insert("object_class".into(), Value::String(class.to_owned()));
                }
                descriptor.insert("value_attributes".into(), Value::Object(attrs));
                descriptor.insert(
                    "value".into(),
                    Value::String(legacy_decode(
                        &value_node.text,
                        &build.source.version,
                        build.limits.max_text_bytes,
                    )?),
                );
                descriptor.insert(
                    "value_state".into(),
                    Value::String(
                        if value_node.text.is_empty() {
                            "empty"
                        } else {
                            "value"
                        }
                        .into(),
                    ),
                );
                descriptor.insert("present".into(), Value::Bool(true));
                descriptor.insert("empty".into(), Value::Bool(value_node.text.is_empty()));
            } else {
                descriptor.insert("null".into(), Value::Bool(true));
                descriptor.insert("value_state".into(), Value::String("null".into()));
                descriptor.insert("present".into(), Value::Bool(true));
                descriptor.insert("empty".into(), Value::Bool(false));
            }
            if owner.starts_with("Plugin") {
                descriptor.insert("opaque".into(), Value::Bool(true));
            }
        }
        _ => {}
    }
    if node.name == "objProp" && owner.starts_with("Plugin") {
        add_opaque(
            build,
            json!({"owner": owner, "wire_tag": node.name, "wire_name": wire_name, "raw_xml_sha256": raw_hash(build.source, node.start, node.end), "must_preserve_raw_xml": true}),
        )?;
    }
    let deleted_property = owner == "JDBCDataSource"
        && matches!(
            wire_name,
            "JDBCSampler.connections" | "JDBCSampler.connPoolClass"
        );
    if deleted_property {
        let raw_xml = String::from_utf8_lossy(
            build
                .source
                .bytes
                .get(node.start..node.end)
                .unwrap_or_default(),
        )
        .into_owned();
        reserve_property(build, owner)?;
        reserve_diagnostic(build)?;
        build.deleted.push(json!({
            "element": "JDBCDataSource",
            "wire_name": wire_name,
            "wire_value": node.text,
            "raw_xml": raw_xml,
            "raw_xml_sha256": raw_hash(build.source, node.start, node.end),
            "status": "diagnostic-only-retention",
            "raw_span_retained": true
        }));
    }
    descriptor.insert(
        "raw_xml_sha256".into(),
        Value::String(raw_hash(build.source, node.start, node.end)),
    );
    if deleted_property {
        return Ok(());
    }
    add_property(build, Value::Object(descriptor))?;
    if let Some(nested_owner) = nested_owner {
        for child in event_elements(node) {
            if is_property(child) {
                emit_property(build, child, &nested_owner, Some(&nested_parent))?;
            } else if owner.starts_with("Plugin") {
                emit_opaque_property(build, child, &format!("{owner}/{name}"))?;
            }
        }
    }
    if owner.starts_with("Plugin") && node.text.contains("${__fixturePluginFunction") {
        if let Some(property) = build.properties.last_mut()
            && property.get("path").and_then(Value::as_str) == Some(&format!("{owner}/{name}"))
        {
            property["function_expansion"] = Value::String("preserve-unexpanded".into());
        }
        add_diagnostic(
            build,
            json!({
                "code": "plugin.function.unsupported",
                "node": format!("{owner}/{name}"),
                "function": "__fixturePluginFunction",
                "severity": "error",
                "executable": false
            }),
        )?;
    }
    Ok(())
}

fn emit_opaque_property(build: &mut Build<'_>, node: &XmlNode, owner: &str) -> Result<()> {
    let hash = raw_hash(build.source, node.start, node.end);
    account_opaque(build, node.start, node.end)?;
    let mut descriptor = Map::new();
    descriptor.insert(
        "path".into(),
        Value::String(format!(
            "{owner}/{}",
            attr(node, "name").unwrap_or(&node.name)
        )),
    );
    descriptor.insert("node".into(), Value::String(node.name.clone()));
    descriptor.insert(
        "ordered_attributes".into(),
        Value::Array(ordered_attrs(node)),
    );
    descriptor.insert("attributes".into(), Value::Object(attr_map(node)));
    descriptor.insert(
        "ordered_children".into(),
        Value::Array(element_names(node).into_iter().map(Value::String).collect()),
    );
    descriptor.insert(
        "extensions".into(),
        extension_values(build.source, node, owner, build.limits)?,
    );
    if let Some(name) = attr(node, "name") {
        descriptor.insert("name".into(), Value::String(name.to_owned()));
    }
    descriptor.insert("present".into(), Value::Bool(true));
    if !node.text.is_empty() {
        descriptor.insert("value".into(), Value::String(node.text.clone()));
    }
    descriptor.insert(
        "value_state".into(),
        Value::String(
            if node.text.is_empty() {
                "empty"
            } else {
                "value"
            }
            .into(),
        ),
    );
    descriptor.insert("empty".into(), Value::Bool(node.text.is_empty()));
    descriptor.insert("raw_xml_sha256".into(), Value::String(hash.clone()));
    descriptor.insert("opaque".into(), Value::Bool(true));
    add_property(build, Value::Object(descriptor))?;
    let mut payload = json!({"owner": owner, "wire_tag": node.name, "raw_xml_sha256": hash, "must_preserve_raw_xml": true});
    if let Some(name) = attr(node, "name") {
        payload["wire_name"] = Value::String(name.to_owned());
    }
    let contains = opaque_contains(node);
    if !contains.is_empty() {
        payload["contains"] = Value::Array(contains.into_iter().map(Value::String).collect());
    }
    add_opaque(build, payload)
}

fn opaque_contains(node: &XmlNode) -> Vec<String> {
    let mut children = Vec::new();
    let mut markers = Vec::new();
    fn visit(node: &XmlNode, result: &mut Vec<String>) {
        for event in &node.events {
            match event {
                XmlEvent::Element(child) => {
                    result.push(child.name.clone());
                    visit(child, result);
                }
                XmlEvent::Comment { .. } => result.push("comment".into()),
                XmlEvent::ProcessingInstruction { .. } => {
                    result.push("processing-instruction".into());
                }
                XmlEvent::CData { .. } => result.push("CDATA".into()),
            }
        }
    }
    visit(node, &mut children);
    // Marker events are surfaced before nested element names so CDATA and PI
    // presence cannot be hidden by a child-name projection.  The raw hash and
    // ordered_children fields retain the original wire order separately.
    for item in &children {
        if matches!(
            item.as_str(),
            "comment" | "processing-instruction" | "CDATA"
        ) {
            markers.push(item.clone());
        }
    }
    for item in children {
        if !matches!(
            item.as_str(),
            "comment" | "processing-instruction" | "CDATA"
        ) {
            markers.push(item);
        }
    }
    markers
}

fn add_property(build: &mut Build<'_>, value: Value) -> Result<()> {
    if let Some(path) = value.get("path").and_then(Value::as_str) {
        reserve_property(build, path)?;
    }
    build.properties.push(value);
    Ok(())
}

fn reserve_property(build: &mut Build<'_>, path: &str) -> Result<()> {
    build.property_count = build.property_count.saturating_add(1);
    if build.property_count > build.limits.max_properties {
        return Err(limit("JMX property count exceeds configured bound"));
    }
    let owner = path.split('/').next().unwrap_or(path).to_owned();
    let count = build.property_counts_by_element.entry(owner).or_default();
    *count = count.saturating_add(1);
    if *count > build.limits.max_properties_per_element {
        return Err(limit(
            "JMX property count for one element exceeds configured bound",
        ));
    }
    Ok(())
}

fn add_opaque(build: &mut Build<'_>, value: Value) -> Result<()> {
    build.opaque.push(value);
    if build.opaque.len() > build.limits.max_properties {
        return Err(limit(
            "JMX opaque descriptor count exceeds configured bound",
        ));
    }
    Ok(())
}

fn account_opaque(build: &mut Build<'_>, start: usize, end: usize) -> Result<()> {
    if end <= start {
        return Ok(());
    }
    // `opaque_ranges` is maintained as sorted, disjoint intervals.  Inspect
    // only the predecessor and the following intervals that can overlap the
    // new span; scanning every prior subtree would turn a large unknown-plan
    // input into quadratic work.
    let mut overlapping = Vec::new();
    if let Some((&range_start, &range_end)) = build.opaque_ranges.range(..start).next_back()
        && range_end >= start
    {
        overlapping.push((range_start, range_end));
    }
    for (&range_start, &range_end) in build
        .opaque_ranges
        .range(start..)
        .take_while(|(range_start, _)| **range_start <= end)
    {
        overlapping.push((range_start, range_end));
    }
    let covered = overlapping
        .iter()
        .map(|(range_start, range_end)| {
            (*range_end)
                .min(end)
                .saturating_sub((*range_start).max(start))
        })
        .sum::<usize>();
    let newly_covered = end.saturating_sub(start).saturating_sub(covered);
    let next = build
        .opaque_bytes
        .checked_add(newly_covered)
        .ok_or_else(|| limit("JMX opaque byte bound overflow"))?;
    if next > build.limits.max_opaque_bytes {
        return Err(limit("JMX opaque subtree bytes exceed configured bound"));
    }
    let mut merged_start = start;
    let mut merged_end = end;
    for (range_start, _range_end) in overlapping {
        if let Some(range_end) = build.opaque_ranges.remove(&range_start) {
            merged_start = merged_start.min(range_start);
            merged_end = merged_end.max(range_end);
        }
    }
    build.opaque_ranges.insert(merged_start, merged_end);
    build.opaque_bytes = next;
    Ok(())
}

fn add_diagnostic(build: &mut Build<'_>, value: Value) -> Result<()> {
    reserve_diagnostic(build)?;
    build.diagnostics.push(value);
    Ok(())
}

fn reserve_diagnostic(build: &mut Build<'_>) -> Result<()> {
    build.diagnostic_count = build.diagnostic_count.saturating_add(1);
    if build.diagnostic_count > build.limits.max_diagnostics {
        return Err(limit("JMX diagnostic count exceeds configured bound"));
    }
    Ok(())
}

fn semantic_property_name(version: &str, owner: &str, wire: &str) -> (String, String) {
    if version != "1.0" {
        return (wire.to_owned(), wire.to_owned());
    }
    let value = match (owner, wire) {
        ("JDBCSampler", "JDBCSampler.query") => "query",
        ("JDBCDataSource", "JDBCSampler.url") => "dbUrl",
        ("JDBCDataSource", "JDBCSampler.driver") => "driver",
        ("JDBCDataSource", "JDBCSampler.query") => "query",
        ("JDBCDataSource", "ConfigTestElement.username") => "username",
        ("JDBCDataSource", "ConfigTestElement.password") => "password",
        ("JDBCDataSource", "JDBCSampler.maxuse") => "poolMax",
        ("ConstantThroughputTimer", "ConstantThroughputTimer.throughput") => "throughput",
        ("AccessLogSampler", "AccessLogSampler.log_file") => "logFile",
        ("AccessLogSampler", "HTTPSampler.port") => "portString",
        ("AccessLogSampler", "HTTPSampler.domain") => "domain",
        ("AccessLogSampler", "HTTPSampler.image_parser") => "imageParsing",
        ("AccessLogSampler", "AccessLogSampler.parser_class_name") => "parserClassName",
        ("BSFSampler", "BSFSampler.filename") => "filename",
        ("BSFSampler", "BSFSampler.language") => "scriptLanguage",
        ("BSFSampler", "BSFSampler.parameters") => "parameters",
        ("BSFSampler", "BSFSampler.query") => "script",
        _ => wire,
    };
    (value.to_owned(), wire.to_owned())
}

fn legacy_decode(value: &str, version: &str, maximum: usize) -> Result<String> {
    if version != "1.0" {
        return bounded_text(value, maximum);
    }
    let mut bytes = Vec::with_capacity(value.len());
    let raw = value.as_bytes();
    let mut index = 0;
    while index < raw.len() {
        match raw[index] {
            b'+' => {
                bytes.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < raw.len() => {
                let hi = (raw[index + 1] as char)
                    .to_digit(16)
                    .ok_or_else(|| jmx_parse("invalid legacy percent escape"))?;
                let lo = (raw[index + 2] as char)
                    .to_digit(16)
                    .ok_or_else(|| jmx_parse("invalid legacy percent escape"))?;
                bytes.push((hi * 16 + lo) as u8);
                index += 3;
            }
            byte => {
                bytes.push(byte);
                index += 1;
            }
        }
    }
    let decoded =
        String::from_utf8(bytes).map_err(|_| jmx_parse("legacy percent escape is not UTF-8"))?;
    bounded_text(&decoded, maximum)
}

fn legacy_decoding(source: &JmxSource, _projection: &Map<String, Value>) -> Value {
    let mut examples = Vec::new();
    fn visit(node: &XmlNode, source: &JmxSource, examples: &mut Vec<Value>) {
        if let Some(value) = attr(node, "testname")
            && let Ok(decoded) = legacy_decode(value, "1.0", 4 * 1024 * 1024)
            && decoded != value
        {
            examples.push(json!({"wire": value, "decoded": decoded}));
        }
        for event in &node.events {
            if let XmlEvent::Element(child) = event {
                if matches!(
                    child.name.as_str(),
                    "stringProp" | "boolProp" | "intProp" | "longProp" | "floatProp" | "doubleProp"
                ) && let Ok(decoded) = legacy_decode(&child.text, "1.0", 4 * 1024 * 1024)
                    && decoded != child.text
                    && examples.len() < 8
                {
                    examples.push(json!({"wire": child.text, "decoded": decoded}));
                }
                visit(child, source, examples);
            }
        }
        let _ = source;
    }
    visit(&source.root, source, &mut examples);
    json!({"version": "1.0", "rule": "Decode '+' as space and percent-escaped UTF-8 in attributes and scalar property values before applying upgrade.properties.", "examples": examples})
}

fn upgrade_rules_omitted() -> Value {
    json!([
        {"kind":"gui","source":"org.apache.jmeter.protocol.jdbc.config.gui.DbConfigGui","target":"org.apache.jmeter.testbeans.gui.TestBeanGUI","status":"not-exercised","reason":"The plan records DbConfigGui but this descriptor does not assert the GUI conversion."},
        {"kind":"gui","source":"org.apache.jmeter.timers.gui.ConstantThroughputTimerGui","target":"org.apache.jmeter.testbeans.gui.TestBeanGUI","status":"not-exercised","reason":"The plan records ConstantThroughputTimerGui but this descriptor does not assert the GUI conversion."},
        {"kind":"gui","source":"org.apache.jmeter.protocol.http.control.gui.AccessLogSamplerGui","target":"org.apache.jmeter.testbeans.gui.TestBeanGUI","status":"not-exercised","reason":"The plan records AccessLogSamplerGui but this descriptor does not assert the GUI conversion."},
        {"kind":"property","source":"org.apache.jmeter.protocol.http.sampler.AccessLogSampler/HTTPSampler.port","target":"portString","status":"not-exercised","reason":"The plan does not assert this AccessLogSampler property conversion."},
        {"kind":"property","source":"org.apache.jmeter.protocol.http.sampler.AccessLogSampler/HTTPSampler.domain","target":"domain","status":"not-exercised","reason":"The plan does not assert this AccessLogSampler property conversion."},
        {"kind":"property","source":"org.apache.jmeter.protocol.http.sampler.AccessLogSampler/AccessLogSampler.parser_class_name","target":"parserClassName","status":"not-exercised","reason":"The plan does not assert this AccessLogSampler property conversion."},
        {"kind":"property","source":"org.apache.jmeter.protocol.http.sampler.AccessLogSampler/HTTPSampler.image_parser","target":"imageParsing","status":"not-exercised","reason":"The plan does not assert this AccessLogSampler property conversion."},
        {"kind":"gui","source":"org.apache.jmeter.protocol.java.control.gui.BSFSamplerGui","target":"org.apache.jmeter.testbeans.gui.TestBeanGUI","status":"not-exercised","reason":"The plan records BSFSamplerGui but this descriptor does not assert the GUI conversion."},
        {"kind":"property","source":"org.apache.jmeter.protocol.java.sampler.BSFSampler/BSFSampler.filename","target":"filename","status":"not-exercised","reason":"The plan does not assert this BSFSampler property conversion."},
        {"kind":"property","source":"org.apache.jmeter.protocol.java.sampler.BSFSampler/BSFSampler.language","target":"scriptLanguage","status":"not-exercised","reason":"The plan does not assert this BSFSampler property conversion."},
        {"kind":"property","source":"org.apache.jmeter.protocol.java.sampler.BSFSampler/BSFSampler.parameters","target":"parameters","status":"not-exercised","reason":"The plan does not assert this BSFSampler property conversion."},
        {"kind":"class","source":"org.apache.jmeter.protocol.jms.control.gui.JMSConfigGui","target":"org.apache.jmeter.protocol.jms.control.gui.JMSSamplerGui","status":"not-exercised","reason":"The plan records JMSConfigGui but this descriptor does not assert the GUI class upgrade."}
    ])
}

fn finalize_upgrades(build: &mut Build<'_>) {
    let mut names = BTreeSet::new();
    fn visit(node: &XmlNode, names: &mut BTreeSet<String>) {
        if let Some(class) = attr(node, "guiclass") {
            names.insert(class.to_owned());
        }
        if let Some(class) = attr(node, "testclass") {
            names.insert(class.to_owned());
        }
        for event in &node.events {
            if let XmlEvent::Element(child) = event {
                if let Some(name) = attr(child, "name") {
                    names.insert(name.to_owned());
                }
                visit(child, names);
            }
        }
    }
    visit(&build.source.root, &mut names);
    let candidates = [
        json!({"kind": "class", "old": "org.apache.jmeter.protocol.http.sampler.HTTPSamplerFull", "new": "org.apache.jmeter.protocol.http.sampler.HTTPSampler"}),
        json!({"kind": "class", "old": "org.apache.jmeter.protocol.http.sampler.SoapSampler", "new": "org.apache.jmeter.config.ConfigTestElement"}),
        json!({"kind": "class", "old": "org.apache.jmeter.protocol.http.control.gui.SoapSamplerGui", "new": "org.apache.jmeter.config.gui.ObsoleteGui"}),
        json!({"kind": "class", "old": "org.apache.jmeter.protocol.jms.control.gui.JMSConfigGui", "new": "org.apache.jmeter.protocol.jms.control.gui.JMSSamplerGui"}),
        json!({"kind": "gui", "old": "org.apache.jmeter.protocol.jdbc.control.gui.JdbcTestSampleGui", "new": "org.apache.jmeter.testbeans.gui.TestBeanGUI"}),
        json!({"kind": "property", "class": "org.apache.jmeter.protocol.jdbc.sampler.JDBCSampler", "old": "JDBCSampler.query", "new": "query"}),
        json!({"kind": "property", "class": "org.apache.jmeter.protocol.jdbc.config.DataSourceElement", "old": "JDBCSampler.url", "new": "dbUrl"}),
        json!({"kind": "property", "class": "org.apache.jmeter.protocol.jdbc.config.DataSourceElement", "old": "JDBCSampler.driver", "new": "driver"}),
        json!({"kind": "property", "class": "org.apache.jmeter.protocol.jdbc.config.DataSourceElement", "old": "JDBCSampler.query", "new": "query"}),
        json!({"kind": "property", "class": "org.apache.jmeter.protocol.jdbc.config.DataSourceElement", "old": "ConfigTestElement.username", "new": "username"}),
        json!({"kind": "property", "class": "org.apache.jmeter.protocol.jdbc.config.DataSourceElement", "old": "ConfigTestElement.password", "new": "password"}),
        json!({"kind": "property", "class": "org.apache.jmeter.protocol.jdbc.config.DataSourceElement", "old": "JDBCSampler.connections", "new": Value::Null}),
        json!({"kind": "property", "class": "org.apache.jmeter.protocol.jdbc.config.DataSourceElement", "old": "JDBCSampler.connPoolClass", "new": Value::Null}),
        json!({"kind": "property", "class": "org.apache.jmeter.protocol.jdbc.config.DataSourceElement", "old": "JDBCSampler.maxuse", "new": "poolMax"}),
        json!({"kind": "property", "class": "org.apache.jmeter.timers.ConstantThroughputTimer", "old": "ConstantThroughputTimer.throughput", "new": "throughput"}),
        json!({"kind": "property", "class": "org.apache.jmeter.protocol.http.sampler.AccessLogSampler", "old": "AccessLogSampler.log_file", "new": "logFile"}),
        json!({"kind": "property", "class": "org.apache.jmeter.protocol.java.sampler.BSFSampler", "old": "BSFSampler.query", "new": "script"}),
    ];
    for candidate in candidates {
        let old = candidate
            .get("old")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let include = names.contains(old)
            || (old.contains("SoapSampler") && names.contains("SoapSampler"))
            || (old.contains("JMSConfigGui") && names.contains("JMSConfigGui"))
            || (old.contains("JdbcTestSampleGui")
                && names.iter().any(|name| name.contains("JdbcTestSampleGui")));
        if include
            && !(build.source.version == "1.0"
                && old == "org.apache.jmeter.protocol.jms.control.gui.JMSConfigGui")
        {
            build.upgrades.push(candidate);
        }
    }
}

fn load_jmx_normalization(expected: &Value, options: &mut CompareOptions) -> Result<()> {
    let Some(normalization) = expected.get("normalization") else {
        return Ok(());
    };
    let object = normalization.as_object().ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "JMX normalization must be an object",
        )
    })?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "ignored_fields" | "reason" | "lexical_preserving_regions"
        ) {
            return Err(OracleError::new_for_cli(
                ErrorCode::UnsupportedFormat,
                format!("unsupported JMX normalization field '{key}'"),
            ));
        }
    }
    if let Some(fields) = object.get("ignored_fields") {
        let fields = fields.as_array().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "JMX normalization ignored_fields must be an array",
            )
        })?;
        for value in fields {
            let field = value.as_str().ok_or_else(|| {
                OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    "JMX normalization ignored_fields must contain strings",
                )
            })?;
            if !jmx_ignored_field(field) {
                return Err(OracleError::new_for_cli(
                    ErrorCode::Normalization,
                    format!("JMX normalization field '{field}' is not allowed"),
                ));
            }
            // These names describe permitted XML lexical normalization; they
            // are not projection paths.  Treating them as wildcard paths
            // would silently disable every declared semantic comparison.
            if !matches!(
                field,
                "xml_lexical_whitespace" | "xml_empty_element_spelling"
            ) {
                options.ignored_fields.insert(field.to_owned());
            }
        }
    }
    if let Some(regions) = object.get("lexical_preserving_regions") {
        let regions = regions.as_array().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "JMX normalization lexical_preserving_regions must be an array",
            )
        })?;
        if regions.iter().any(|value| !value.is_string()) {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "JMX normalization lexical_preserving_regions must contain strings",
            ));
        }
        if regions.iter().filter_map(Value::as_str).any(str::is_empty) {
            return Err(OracleError::new_for_cli(
                ErrorCode::Normalization,
                "JMX normalization lexical_preserving_regions cannot contain empty paths",
            ));
        }
    }
    Ok(())
}

fn jmx_ignored_field(field: &str) -> bool {
    matches!(
        field,
        "xml_lexical_whitespace" | "xml_empty_element_spelling"
    ) || field.starts_with("oracle_execution.sample.")
}

fn validate_jmx_options(options: &CompareOptions, expected: &Value) -> Result<()> {
    options.limits.validate_for_jmx()?;
    if let Some(format) = options.format
        && format != CompareFormat::JmxSemantic
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::UnsupportedFormat,
            "JMX expectations require format jmx-semantic",
        ));
    }
    for field in &options.ignored_fields {
        if !jmx_ignored_field(field) {
            return Err(OracleError::new_for_cli(
                ErrorCode::Normalization,
                format!("JMX normalization field '{field}' is not allowed"),
            ));
        }
    }
    if expected
        .get("format")
        .and_then(Value::as_str)
        .and_then(CompareFormat::from_hint)
        != Some(CompareFormat::JmxSemantic)
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::UnsupportedFormat,
            "JMX semantic expectation must declare format jmx-semantic",
        ));
    }
    Ok(())
}

fn validate_jmx_expectation(expected: &Value, limits: &CompareLimits) -> Result<()> {
    let object = expected.as_object().ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "JMX expectation must be an object",
        )
    })?;
    let allowed = [
        "schema_id",
        "schema_version",
        "format",
        "profile_id",
        "case_id",
        "fixture_family_id",
        "conformance_ids",
        "normalization_policy_refs",
        "evidence_status",
        "expectation_basis",
        "source",
        "status",
        "generated_from",
        "rust_conformance_claim",
        "root",
        "xml_declaration",
        "byte_order_mark",
        "topology",
        "ordered_hash_tree_pairs",
        "typed_properties",
        "properties",
        "opaque_payloads",
        "opaque_subtree_sha256",
        "known_properties_around_unknown",
        "duplicate_identity_probes",
        "upgrade_rules_omitted",
        "legacy_alias_contract",
        "alias_contract",
        "gui_contract",
        "recorder_contract",
        "diagnostics",
        "preservation_invariants",
        "oracle_execution",
        "capability_accounting",
        "bounds",
        "normalization",
        "alias_resolutions",
        "registry_inventory",
        "pinned_oracle_questions",
        "upgrade_rules_exercised",
        "upgrade_rules_omitted",
        "deleted_property_handling",
        "legacy_decoding",
        "absent_vs_empty",
        "elements",
        "opaque_legacy",
        "requirements",
        "headless_contract",
        "validation_contract",
        "workbench_source_behavior",
        "oracle_observation",
        "projection_policy",
        "projection_schema",
        "projection_schema_version",
        "source_topology_contract",
        "topology_contract",
        "wire_inventory",
        "comparator_contract",
        "comparator_route",
        "comparator_scope",
        "wire_sha256",
        "source_sha256",
        "document_extensions",
    ];
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(OracleError::new_for_cli(
                ErrorCode::UnsupportedFormat,
                format!("unsupported JMX expectation field '{key}'"),
            ));
        }
    }
    if object
        .get("format")
        .and_then(Value::as_str)
        .and_then(CompareFormat::from_hint)
        != Some(CompareFormat::JmxSemantic)
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::UnsupportedFormat,
            "JMX expectation format must be jmx-semantic",
        ));
    }
    if let Some(schema_id) = object.get("schema_id")
        && schema_id.as_str() != Some(EXPECTATION_SCHEMA_ID)
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::UnsupportedFormat,
            "unsupported JMX expectation schema_id",
        ));
    }
    if let Some(version) = object.get("schema_version")
        && version.as_u64() != Some(PROJECTION_SCHEMA_VERSION)
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::UnsupportedFormat,
            "unsupported JMX projection schema_version",
        ));
    }
    if let Some(root) = object.get("root") {
        validate_jmx_object(
            root,
            &[
                "element",
                "attributes",
                "ordered_attributes",
                "ordered_children",
                "extensions",
                "ordered_extensions",
                "hash_tree_extensions",
                "text",
                "wire_sha256",
                "source_sha256",
            ],
            "root",
        )?;
        if let Some(extensions) = root.get("extensions") {
            validate_jmx_extensions(extensions, limits, "root.extensions")?;
        }
        if let Some(extensions) = root.get("hash_tree_extensions") {
            validate_jmx_extensions(extensions, limits, "root.hash_tree_extensions")?;
        }
        if let Some(ordered_children) = root.get("ordered_children") {
            validate_jmx_string_array(ordered_children, "root.ordered_children")?;
        }
        if let Some(ordered_attributes) = root.get("ordered_attributes") {
            validate_jmx_ordered_attributes(ordered_attributes, "root.ordered_attributes")?;
        }
        if let Some(text) = root.get("text")
            && !text.is_string()
        {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "root.text must be a string",
            ));
        }
    }
    if let Some(declaration) = object.get("xml_declaration")
        && !declaration.is_null()
    {
        validate_jmx_object(declaration, &["text", "raw_xml_sha256"], "xml_declaration")?;
        if declaration
            .get("text")
            .is_some_and(|value| !value.is_string())
            || declaration
                .get("raw_xml_sha256")
                .is_some_and(|value| !value.is_string())
        {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "xml_declaration text/raw_xml_sha256 must be strings",
            ));
        }
    }
    if let Some(bom) = object.get("byte_order_mark")
        && !bom.is_boolean()
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "byte_order_mark must be boolean",
        ));
    }
    if let Some(pairs) = object.get("ordered_hash_tree_pairs") {
        validate_jmx_pairs(pairs, limits)?;
    }
    for field in ["typed_properties", "properties"] {
        if let Some(value) = object.get(field) {
            validate_jmx_descriptor_array(
                value,
                &[
                    "path",
                    "node",
                    "name",
                    "wire_name",
                    "wire_value",
                    "value",
                    "value_state",
                    "ordered",
                    "present",
                    "empty",
                    "null",
                    "attributes",
                    "ordered_attributes",
                    "element_type",
                    "guiclass",
                    "testclass",
                    "testname",
                    "enabled",
                    "object_class",
                    "value_attributes",
                    "extra_attributes",
                    "children",
                    "entries",
                    "ordered_children",
                    "ordered_child_names",
                    "extensions",
                    "raw_xml_sha256",
                    "opaque",
                    "legacy_wire_name",
                    "function_expansion",
                    "oracle_status",
                ],
                field,
                limits,
            )?;
        }
    }
    for field in [
        "opaque_payloads",
        "alias_resolutions",
        "upgrade_rules_exercised",
        "upgrade_rules_omitted",
        "elements",
        "opaque_legacy",
        "registry_inventory",
    ] {
        if let Some(value) = object.get(field) {
            if !value.is_array() && !value.is_object() && !value.is_null() {
                return Err(OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    format!("JMX {field} must be an array/object/null"),
                ));
            }
            if let Some(array) = value.as_array()
                && array.len() > limits.max_nodes
            {
                return Err(limit(format!("JMX {field} exceeds configured bound")));
            }
        }
    }
    validate_jmx_object_array(
        object.get("opaque_payloads"),
        "opaque_payloads",
        &[
            "owner",
            "wire_tag",
            "wire_name",
            "raw_xml_sha256",
            "must_preserve_raw_xml",
            "contains",
        ],
        limits,
    )?;
    validate_jmx_object_array(
        object.get("alias_resolutions"),
        "alias_resolutions",
        &[
            "input",
            "class",
            "primary_alias",
            "canonical_alias",
            "upgrade_to",
            "decoder",
            "oracle_status",
            "not_an_accepted_alias_claim",
            "note",
        ],
        limits,
    )?;
    validate_jmx_object_array(
        object.get("upgrade_rules_exercised"),
        "upgrade_rules_exercised",
        &["kind", "old", "new", "class"],
        limits,
    )?;
    validate_jmx_object_array(
        object.get("upgrade_rules_omitted"),
        "upgrade_rules_omitted",
        &[
            "kind", "source", "target", "old", "new", "status", "reason", "class",
        ],
        limits,
    )?;
    validate_jmx_object_array(
        object.get("diagnostics"),
        "diagnostics",
        &[
            "code",
            "element",
            "node",
            "capability",
            "function",
            "boundary",
            "severity",
            "executable",
        ],
        limits,
    )?;
    validate_jmx_object_array(
        object.get("elements"),
        "elements",
        &[
            "position",
            "tag",
            "testclass",
            "guiclass",
            "name",
            "enabled",
            "property_names",
            "legacy_family",
            "boundary",
            "status",
            "upgrade_mapping",
        ],
        limits,
    )?;
    validate_jmx_object_array(
        object.get("opaque_legacy"),
        "opaque_legacy",
        &[
            "position",
            "tag",
            "testclass",
            "guiclass",
            "name",
            "enabled",
            "executable",
            "status",
            "property_names",
            "save_service_alias_present",
            "diagnostic",
        ],
        limits,
    )?;
    validate_jmx_object_array(
        object.get("duplicate_identity_probes"),
        "duplicate_identity_probes",
        &[
            "path",
            "left_path",
            "right_path",
            "left_owner_path",
            "right_owner_path",
            "same_wire_identity_as",
            "same_typed_property_name_as",
            "difference",
            "deduplicate",
        ],
        limits,
    )?;
    if let Some(probes) = object.get("duplicate_identity_probes") {
        validate_jmx_duplicate_identity_probes(probes)?;
    }
    if let Some(inventory) = object.get("registry_inventory") {
        validate_jmx_registry_inventory(inventory)?;
    }
    if let Some(extensions) = object.get("document_extensions") {
        validate_jmx_extensions(extensions, limits, "document_extensions")?;
    }
    if let Some(normalization) = object.get("normalization") {
        let mut options = CompareOptions::default();
        load_jmx_normalization(&json!({"normalization": normalization}), &mut options)?;
    }
    Ok(())
}

fn validate_jmx_duplicate_identity_probes(value: &Value) -> Result<()> {
    let probes = value.as_array().ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "JMX duplicate_identity_probes must be an array",
        )
    })?;
    for (index, probe) in probes.iter().enumerate() {
        let object = probe.as_object().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                format!("JMX duplicate_identity_probes[{index}] must be an object"),
            )
        })?;
        for key in [
            "path",
            "left_path",
            "right_path",
            "left_owner_path",
            "right_owner_path",
            "same_wire_identity_as",
            "same_typed_property_name_as",
            "difference",
        ] {
            if let Some(value) = object.get(key)
                && !value.is_string()
            {
                return Err(OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    format!("JMX duplicate_identity_probes[{index}].{key} must be a string"),
                ));
            }
        }
        if let Some(value) = object.get("deduplicate")
            && !value.is_boolean()
        {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                format!("JMX duplicate_identity_probes[{index}].deduplicate must be boolean"),
            ));
        }
    }
    Ok(())
}

fn validate_jmx_registry_inventory(value: &Value) -> Result<()> {
    let object = value.as_object().ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "JMX registry_inventory must be an object",
        )
    })?;
    for key in object.keys() {
        if !matches!(key.as_str(), "saveservice" | "upgrade") {
            return Err(OracleError::new_for_cli(
                ErrorCode::UnsupportedFormat,
                format!("unsupported JMX registry_inventory field '{key}'"),
            ));
        }
    }
    for section in ["saveservice", "upgrade"] {
        let Some(value) = object.get(section) else {
            continue;
        };
        let section_object = value.as_object().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                format!("JMX registry_inventory.{section} must be an object"),
            )
        })?;
        for key in section_object.keys() {
            if !matches!(
                key.as_str(),
                "path"
                    | "source_commit"
                    | "sha256"
                    | "alias_keys"
                    | "primary_classes"
                    | "rules"
                    | "rule"
            ) {
                return Err(OracleError::new_for_cli(
                    ErrorCode::UnsupportedFormat,
                    format!("unsupported JMX registry_inventory.{section} field '{key}'"),
                ));
            }
        }
        for key in ["path", "source_commit", "sha256", "rule"] {
            if let Some(value) = section_object.get(key)
                && !value.is_string()
            {
                return Err(OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    format!("JMX registry_inventory.{section}.{key} must be a string"),
                ));
            }
        }
        for key in ["alias_keys", "primary_classes", "rules"] {
            if let Some(value) = section_object.get(key)
                && value.as_u64().is_none()
            {
                return Err(OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    format!("JMX registry_inventory.{section}.{key} must be an unsigned integer"),
                ));
            }
        }
    }
    Ok(())
}

fn validate_jmx_pairs(value: &Value, limits: &CompareLimits) -> Result<()> {
    let pairs = value.as_array().ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "JMX ordered_hash_tree_pairs must be an array",
        )
    })?;
    if pairs.len() > limits.max_events {
        return Err(limit("JMX topology pair count exceeds configured bound"));
    }
    for (index, pair) in pairs.iter().enumerate() {
        validate_jmx_object(
            pair,
            &[
                "position",
                "path",
                "identity",
                "element",
                "hash_tree_children",
                "child_pairs",
                "hash_tree_extensions",
                "extensions",
                "tag",
                "guiclass",
                "testclass",
                "testname",
                "enabled",
            ],
            &format!("ordered_hash_tree_pairs[{index}]"),
        )?;
        if let Some(element) = pair.get("element") {
            validate_jmx_element(element, limits)?;
        }
        if let Some(identity) = pair.get("identity") {
            validate_jmx_identity(
                identity,
                &format!("ordered_hash_tree_pairs[{index}].identity"),
            )?;
        }
        if let Some(children) = pair.get("hash_tree_children")
            && !children.is_array()
        {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "JMX hash_tree_children must be an array",
            ));
        }
        if let Some(children) = pair.get("child_pairs") {
            validate_jmx_pairs(children, limits)?;
        }
        if let Some(extensions) = pair.get("hash_tree_extensions") {
            validate_jmx_extensions(
                extensions,
                limits,
                &format!("ordered_hash_tree_pairs[{index}].hash_tree_extensions"),
            )?;
        }
        if let Some(extensions) = pair.get("extensions") {
            validate_jmx_extensions(
                extensions,
                limits,
                &format!("ordered_hash_tree_pairs[{index}].extensions"),
            )?;
        }
    }
    Ok(())
}

fn validate_jmx_element(value: &Value, limits: &CompareLimits) -> Result<()> {
    validate_jmx_object(
        value,
        &[
            "tag",
            "canonical_wire_tag",
            "guiclass",
            "testclass",
            "testname",
            "name",
            "enabled",
            "extra_attributes",
            "ordered_attributes",
            "attributes",
            "original_guiclass",
            "original_testclass",
            "original_testname",
            "opaque",
            "raw_xml_sha256",
            "opaque_element_sha256",
            "contains",
            "ordered_children",
            "extensions",
            "text",
            "source_position",
            "raw_hash",
        ],
        "JMX element",
    )?;
    if let Some(ordered_attributes) = value.get("ordered_attributes") {
        validate_jmx_ordered_attributes(ordered_attributes, "JMX element.ordered_attributes")?;
    }
    if let Some(ordered_children) = value.get("ordered_children") {
        validate_jmx_string_array(ordered_children, "JMX element.ordered_children")?;
    }
    if let Some(extensions) = value.get("extensions") {
        validate_jmx_extensions(extensions, limits, "JMX element.extensions")?;
    }
    if let Some(contains) = value.get("contains") {
        validate_jmx_string_array(contains, "JMX element.contains")?;
    }
    if let Some(text) = value.get("text")
        && !text.is_string()
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "JMX element.text must be a string",
        ));
    }
    let _ = limits;
    Ok(())
}

fn validate_jmx_identity(value: &Value, label: &str) -> Result<()> {
    let object = value.as_object().ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            format!("{label} must be an object"),
        )
    })?;
    for key in object.keys() {
        if !matches!(key.as_str(), "position" | "segment" | "path" | "tag") {
            return Err(OracleError::new_for_cli(
                ErrorCode::UnsupportedFormat,
                format!("unsupported {label} field '{key}'"),
            ));
        }
    }
    if let Some(position) = object.get("position")
        && position.as_u64().is_none()
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            format!("{label}.position must be an unsigned integer"),
        ));
    }
    for key in ["segment", "path", "tag"] {
        if let Some(value) = object.get(key)
            && !value.is_string()
        {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                format!("{label}.{key} must be a string"),
            ));
        }
    }
    Ok(())
}

fn validate_jmx_string_array(value: &Value, label: &str) -> Result<()> {
    let values = value.as_array().ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            format!("{label} must be an array"),
        )
    })?;
    if values.iter().any(|value| !value.is_string()) {
        return Err(OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            format!("{label} must contain strings"),
        ));
    }
    Ok(())
}

fn validate_jmx_ordered_attributes(value: &Value, label: &str) -> Result<()> {
    let values = value.as_array().ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            format!("{label} must be an array"),
        )
    })?;
    for (index, value) in values.iter().enumerate() {
        validate_jmx_object(value, &["name", "value"], &format!("{label}[{index}]"))?;
        if !value.get("name").is_some_and(Value::is_string)
            || !value.get("value").is_some_and(Value::is_string)
        {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                format!("{label}[{index}] requires string name and value"),
            ));
        }
    }
    Ok(())
}

fn validate_jmx_extensions(value: &Value, limits: &CompareLimits, label: &str) -> Result<()> {
    let values = value.as_array().ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            format!("{label} must be an array"),
        )
    })?;
    if values.len() > limits.max_events {
        return Err(limit(format!("{label} exceeds configured bound")));
    }
    for (index, value) in values.iter().enumerate() {
        validate_jmx_object(
            value,
            &[
                "kind",
                "text",
                "target",
                "data",
                "owner",
                "position",
                "raw_xml_sha256",
            ],
            &format!("{label}[{index}]"),
        )?;
        if let Some(position) = value.get("position")
            && position.as_u64().is_none()
        {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                format!("{label}[{index}].position must be an unsigned integer"),
            ));
        }
        for key in ["kind", "text", "target", "data", "owner", "raw_xml_sha256"] {
            if let Some(value) = value.get(key)
                && !value.is_string()
            {
                return Err(OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    format!("{label}[{index}].{key} must be a string"),
                ));
            }
        }
    }
    Ok(())
}

fn validate_jmx_descriptor_array(
    value: &Value,
    allowed: &[&str],
    label: &str,
    limits: &CompareLimits,
) -> Result<()> {
    let array = value.as_array().ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            format!("JMX {label} must be an array"),
        )
    })?;
    if array.len() > limits.max_properties {
        return Err(limit(format!("JMX {label} exceeds configured bound")));
    }
    for (index, item) in array.iter().enumerate() {
        validate_jmx_object(item, allowed, &format!("{label}[{index}]"))?;
        if let Some(ordered_attributes) = item.get("ordered_attributes") {
            validate_jmx_ordered_attributes(
                ordered_attributes,
                &format!("{label}[{index}].ordered_attributes"),
            )?;
        }
        if let Some(ordered_children) = item.get("ordered_children") {
            validate_jmx_string_array(
                ordered_children,
                &format!("{label}[{index}].ordered_children"),
            )?;
        }
        if let Some(extensions) = item.get("extensions") {
            validate_jmx_extensions(extensions, limits, &format!("{label}[{index}].extensions"))?;
        }
    }
    Ok(())
}

fn validate_jmx_object(value: &Value, allowed: &[&str], label: &str) -> Result<()> {
    let object = value.as_object().ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            format!("{label} must be an object"),
        )
    })?;
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(OracleError::new_for_cli(
                ErrorCode::UnsupportedFormat,
                format!("unsupported {label} field '{key}'"),
            ));
        }
    }
    Ok(())
}

fn validate_jmx_object_array(
    value: Option<&Value>,
    label: &str,
    allowed: &[&str],
    limits: &CompareLimits,
) -> Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    let array = value.as_array().ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            format!("JMX {label} must be an array"),
        )
    })?;
    if array.len() > limits.max_nodes {
        return Err(limit(format!("JMX {label} exceeds configured bound")));
    }
    for (index, item) in array.iter().enumerate() {
        validate_jmx_object(item, allowed, &format!("JMX {label}[{index}]"))?;
        if let Some(contains) = item.get("contains") {
            validate_jmx_string_array(contains, &format!("JMX {label}[{index}].contains"))?;
        }
        if let Some(property_names) = item.get("property_names") {
            validate_jmx_string_array(
                property_names,
                &format!("JMX {label}[{index}].property_names"),
            )?;
        }
    }
    Ok(())
}

fn compare_declared_jmx(
    actual: &Value,
    expected: &Value,
    options: &CompareOptions,
    report: &mut CompareReport,
) {
    compare_field(actual, expected, "format", "/format", options, report);
    for field in ["source_sha256", "wire_sha256"] {
        compare_field(
            actual,
            expected,
            field,
            &format!("/{field}"),
            options,
            report,
        );
    }
    if let Some(expected_root) = expected.get("root").filter(|value| !value.is_null()) {
        compare_declared_field(
            actual.get("root"),
            Some(expected_root),
            "/root",
            options,
            report,
        );
    }
    if let Some(expected_pairs) = expected
        .get("ordered_hash_tree_pairs")
        .filter(|value| !value.is_null())
    {
        compare_pair_array(
            actual.get("ordered_hash_tree_pairs"),
            expected_pairs,
            "/ordered_hash_tree_pairs",
            options,
            report,
        );
    }
    for field in [
        "typed_properties",
        "properties",
        "opaque_payloads",
        "alias_resolutions",
        "upgrade_rules_exercised",
        "upgrade_rules_omitted",
        "elements",
        "opaque_legacy",
    ] {
        if let Some(expected_value) = expected.get(field).filter(|value| !value.is_null()) {
            compare_ordered_array(
                actual.get(field),
                expected_value,
                &format!("/{field}"),
                options,
                report,
            );
        }
    }
    if let Some(expected_diagnostics) = expected.get("diagnostics").filter(|value| !value.is_null())
    {
        compare_ordered_array(
            actual.get("diagnostics"),
            expected_diagnostics,
            "/diagnostics",
            options,
            report,
        );
    }
    for field in [
        "deleted_property_handling",
        "legacy_decoding",
        "absent_vs_empty",
        "known_properties_around_unknown",
        "duplicate_identity_probes",
    ] {
        if let Some(expected_value) = expected.get(field).filter(|value| !value.is_null()) {
            if field == "known_properties_around_unknown" {
                compare_ordered_array(
                    actual.get(field),
                    expected_value,
                    &format!("/{field}"),
                    options,
                    report,
                );
            } else {
                compare_declared_field(
                    actual.get(field),
                    Some(expected_value),
                    &format!("/{field}"),
                    options,
                    report,
                );
            }
        }
    }
    if let Some(expected_value) = expected
        .get("document_extensions")
        .filter(|value| !value.is_null())
    {
        compare_ordered_array(
            actual.get("document_extensions"),
            expected_value,
            "/document_extensions",
            options,
            report,
        );
    }
    for field in ["xml_declaration", "byte_order_mark"] {
        if let Some(expected_value) = expected.get(field) {
            compare_declared_field(
                actual.get(field),
                Some(expected_value),
                &format!("/{field}"),
                options,
                report,
            );
        }
    }
    if let Some(expected_value) = expected.get("registry_inventory")
        && !expected_value.is_null()
    {
        compare_registry_inventory(
            actual.get("registry_inventory"),
            expected_value,
            options,
            report,
        );
    }
}

fn compare_registry_inventory(
    actual: Option<&Value>,
    expected: &Value,
    options: &CompareOptions,
    report: &mut CompareReport,
) {
    let Some(actual) = actual.and_then(Value::as_object) else {
        push_diff(
            report,
            options,
            "/registry_inventory",
            "missing",
            Some(expected),
            None,
        );
        return;
    };
    let Some(expected) = expected.as_object() else {
        push_diff(
            report,
            options,
            "/registry_inventory",
            "changed",
            Some(expected),
            actual.get("saveservice"),
        );
        return;
    };
    for section in ["saveservice", "upgrade"] {
        let Some(expected_section) = expected.get(section) else {
            continue;
        };
        let Some(actual_section) = actual.get(section) else {
            push_diff(
                report,
                options,
                &format!("/registry_inventory/{section}"),
                "missing",
                Some(expected_section),
                None,
            );
            continue;
        };
        for key in [
            "path",
            "source_commit",
            "sha256",
            "alias_keys",
            "primary_classes",
            "rules",
        ] {
            if let Some(expected_value) = expected_section.get(key) {
                compare_declared_field(
                    actual_section.get(key),
                    Some(expected_value),
                    &format!("/registry_inventory/{section}/{key}"),
                    options,
                    report,
                );
            }
        }
    }
}

fn compare_field(
    actual: &Value,
    expected: &Value,
    field: &str,
    path: &str,
    options: &CompareOptions,
    report: &mut CompareReport,
) {
    if let Some(value) = expected.get(field) {
        compare_declared_field(actual.get(field), Some(value), path, options, report);
    }
}

fn compare_pair_array(
    actual: Option<&Value>,
    expected: &Value,
    path: &str,
    options: &CompareOptions,
    report: &mut CompareReport,
) {
    let Some(actual_array) = actual.and_then(Value::as_array) else {
        push_diff(report, options, path, "missing", Some(expected), None);
        return;
    };
    let Some(expected_array) = expected.as_array() else {
        push_diff(report, options, path, "changed", Some(expected), actual);
        return;
    };
    if actual_array.len() != expected_array.len() {
        push_diff(
            report,
            options,
            path,
            "changed",
            Some(expected),
            Some(&Value::Array(actual_array.to_vec())),
        );
    }
    for (index, expected_pair) in expected_array.iter().enumerate() {
        let item_path = format!("{path}/{index}");
        let Some(actual_pair) = actual_array.get(index) else {
            push_diff(
                report,
                options,
                &item_path,
                "missing",
                Some(expected_pair),
                None,
            );
            continue;
        };
        let expected_object = expected_pair.as_object();
        let actual_object = actual_pair.as_object();
        if let Some(expected_object) = expected_object {
            for (key, expected_value) in expected_object {
                let mapped = match key.as_str() {
                    "tag"
                    | "canonical_wire_tag"
                    | "guiclass"
                    | "testclass"
                    | "testname"
                    | "name"
                    | "enabled"
                    | "opaque"
                    | "extra_attributes"
                    | "ordered_attributes"
                    | "attributes"
                    | "ordered_children"
                    | "original_guiclass"
                    | "original_testclass"
                    | "original_testname"
                    | "raw_xml_sha256"
                    | "opaque_element_sha256"
                    | "contains"
                    | "extensions" => actual_object
                        .and_then(|object| object.get("element"))
                        .and_then(|element| element.get(key))
                        .or_else(|| actual_object.and_then(|object| object.get(key))),
                    "child_pairs" => {
                        if expected_value
                            .as_array()
                            .is_some_and(|values| values.iter().any(Value::is_object))
                        {
                            actual_object.and_then(|object| object.get("child_pairs"))
                        } else {
                            actual_object.and_then(|object| object.get("hash_tree_children"))
                        }
                    }
                    _ => actual_object.and_then(|object| object.get(key)),
                };
                compare_declared_field(
                    mapped,
                    Some(expected_value),
                    &format!("{item_path}/{key}"),
                    options,
                    report,
                );
            }
            // GUI-static projections use a flat pair shape. Their child_pairs
            // field is still checked against the exact ordered hashTree labels.
            if expected_object.contains_key("child_pairs")
                && actual_object
                    .and_then(|object| object.get("hash_tree_children"))
                    .is_none()
            {
                push_diff(
                    report,
                    options,
                    &format!("{item_path}/child_pairs"),
                    "missing",
                    expected_object.get("child_pairs"),
                    None,
                );
            }
        } else {
            push_diff(
                report,
                options,
                &item_path,
                "changed",
                Some(expected_pair),
                Some(actual_pair),
            );
        }
    }
}

fn compare_ordered_array(
    actual: Option<&Value>,
    expected: &Value,
    path: &str,
    options: &CompareOptions,
    report: &mut CompareReport,
) {
    let Some(actual_array) = actual.and_then(Value::as_array) else {
        push_diff(report, options, path, "missing", Some(expected), None);
        return;
    };
    let Some(expected_array) = expected.as_array() else {
        compare_declared_field(
            Some(&Value::Array(actual_array.to_vec())),
            Some(expected),
            path,
            options,
            report,
        );
        return;
    };
    let legacy_examples = path.ends_with("/legacy_decoding/examples");
    let subsequence = path.ends_with("/typed_properties")
        || path.ends_with("/properties")
        || path.ends_with("/opaque_payloads")
        || path.ends_with("/diagnostics")
        || path.ends_with("/known_properties_around_unknown")
        || legacy_examples;
    if !subsequence && actual_array.len() != expected_array.len() {
        push_diff(
            report,
            options,
            path,
            "changed",
            Some(expected),
            Some(&Value::Array(actual_array.to_vec())),
        );
    }
    if subsequence {
        let mut actual_index = 0usize;
        for (expected_index, expected_item) in expected_array.iter().enumerate() {
            let mut matched = None;
            while actual_index < actual_array.len() {
                let candidate = &actual_array[actual_index];
                let expected_path = expected_item
                    .get("path")
                    .or_else(|| expected_item.get("raw_xml_sha256"))
                    .and_then(Value::as_str);
                let candidate_path = candidate
                    .get("path")
                    .or_else(|| candidate.get("raw_xml_sha256"))
                    .and_then(Value::as_str);
                let declared_example_match = (legacy_examples || path.ends_with("/diagnostics"))
                    && expected_path.is_none()
                    && declared_value_matches(candidate, expected_item);
                if (expected_path.is_some() && expected_path == candidate_path)
                    || declared_example_match
                {
                    matched = Some((actual_index, candidate));
                    actual_index += 1;
                    break;
                }
                actual_index += 1;
            }
            compare_declared_field(
                matched.map(|(_, value)| value),
                Some(expected_item),
                &format!("{path}/{expected_index}"),
                options,
                report,
            );
        }
    } else {
        for (index, expected_item) in expected_array.iter().enumerate() {
            compare_declared_field(
                actual_array.get(index),
                Some(expected_item),
                &format!("{path}/{index}"),
                options,
                report,
            );
        }
    }
}

fn declared_value_matches(actual: &Value, expected: &Value) -> bool {
    match (actual, expected) {
        (Value::Object(actual), Value::Object(expected)) => expected.iter().all(|(key, value)| {
            actual
                .get(key)
                .is_some_and(|candidate| declared_value_matches(candidate, value))
        }),
        (Value::Array(actual), Value::Array(expected)) => {
            actual.len() == expected.len()
                && actual
                    .iter()
                    .zip(expected)
                    .all(|(actual, expected)| declared_value_matches(actual, expected))
        }
        _ => actual == expected,
    }
}

fn compare_declared_field(
    actual: Option<&Value>,
    expected: Option<&Value>,
    path: &str,
    options: &CompareOptions,
    report: &mut CompareReport,
) {
    let Some(expected) = expected else {
        return;
    };
    let Some(actual) = actual else {
        push_diff(report, options, path, "missing", Some(expected), None);
        return;
    };
    if options
        .ignored_fields
        .iter()
        .any(|field| path_matches_jmx(field, path))
    {
        return;
    }
    if path.ends_with("/legacy_decoding/examples") {
        let Some(actual_array) = actual.as_array() else {
            push_diff(
                report,
                options,
                path,
                "changed",
                Some(expected),
                Some(actual),
            );
            return;
        };
        let Some(expected_array) = expected.as_array() else {
            push_diff(
                report,
                options,
                path,
                "changed",
                Some(expected),
                Some(actual),
            );
            return;
        };
        let mut actual_index = 0usize;
        for (expected_index, expected_item) in expected_array.iter().enumerate() {
            let matched = actual_array[actual_index..]
                .iter()
                .position(|candidate| declared_value_matches(candidate, expected_item))
                .map(|offset| actual_index + offset);
            if let Some(index) = matched {
                actual_index = index + 1;
            }
            compare_declared_field(
                matched.and_then(|index| actual_array.get(index)),
                Some(expected_item),
                &format!("{path}/{expected_index}"),
                options,
                report,
            );
        }
        return;
    }
    match (actual, expected) {
        (Value::Object(actual), Value::Object(expected)) => {
            for (key, expected_value) in expected {
                compare_declared_field(
                    actual.get(key),
                    Some(expected_value),
                    &format!("{path}/{key}"),
                    options,
                    report,
                );
            }
        }
        (Value::Array(actual), Value::Array(expected)) => {
            if actual.len() != expected.len() {
                push_diff(
                    report,
                    options,
                    path,
                    "changed",
                    Some(&Value::Array(expected.clone())),
                    Some(&Value::Array(actual.clone())),
                );
            }
            for (index, expected_value) in expected.iter().enumerate() {
                compare_declared_field(
                    actual.get(index),
                    Some(expected_value),
                    &format!("{path}/{index}"),
                    options,
                    report,
                );
            }
        }
        _ if actual != expected => push_diff(
            report,
            options,
            path,
            "changed",
            Some(expected),
            Some(actual),
        ),
        _ => {}
    }
}

fn path_matches_jmx(field: &str, path: &str) -> bool {
    field == path.trim_start_matches('/')
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    reason = "comparison fixtures use assertion-context panics only"
)]
mod tests {
    use super::*;

    fn fixture(path: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../compat/fixtures/jmeter-5.6.3")
            .join(path)
    }

    #[test]
    fn semantic_projection_retains_wire_topology_and_property_states() {
        let document = parse_jmx_semantic(
            fixture("jmx-aliases/aliases/plan.jmx"),
            &CompareLimits::default(),
        )
        .expect("original aliases fixture parses");
        assert_eq!(
            document.projection["format"],
            Value::String("jmx-semantic".into())
        );
        assert_eq!(
            document.projection["root"]["ordered_children"],
            json!(["hashTree"])
        );
        let properties = document.projection["typed_properties"]
            .as_array()
            .expect("typed properties");
        assert!(properties.iter().any(|property| {
            property.get("path").and_then(Value::as_str) == Some("TestPlan/fixture.empty-object")
                && property.get("value_state").and_then(Value::as_str) == Some("null")
        }));
        assert!(properties.iter().any(|property| {
            property.get("path").and_then(Value::as_str)
                == Some("TestPlan/fixture.empty-collection")
                && property.get("present").and_then(Value::as_bool) == Some(true)
                && property.get("value_state").and_then(Value::as_str) == Some("empty")
        }));
        assert!(!properties.iter().any(|property| {
            property.get("path").and_then(Value::as_str) == Some("TestPlan/fixture.absent-string")
        }));
        let pairs = document.projection["ordered_hash_tree_pairs"]
            .as_array()
            .expect("topology pairs");
        assert!(pairs.iter().any(|pair| {
            pair["element"]["tag"] == Value::String("SoapSampler".into())
                && pair["element"]["testclass"] == Value::String("ConfigTestElement".into())
        }));
        assert_eq!(document.projection["byte_order_mark"], Value::Bool(false));
        assert!(
            document.projection["xml_declaration"]["text"]
                .as_str()
                .is_some_and(|text| text.starts_with("<?xml"))
        );
        assert_eq!(
            document.projection["registry_inventory"]["saveservice"]["alias_keys"],
            json!(293)
        );
        assert_eq!(
            document.projection["registry_inventory"]["upgrade"]["rules"],
            json!(52)
        );
    }

    #[test]
    fn semantic_projection_retains_bom_and_xml_declaration_provenance() {
        let bytes = b"\xEF\xBB\xBF<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<jmeterTestPlan version=\"1.2\"><hashTree/></jmeterTestPlan>";
        let source = parse_source(bytes.to_vec(), &CompareLimits::default(), sha256(bytes))
            .expect("BOM-prefixed JMX parses");
        assert!(source.byte_order_mark);
        assert_eq!(
            source
                .xml_declaration
                .as_ref()
                .map(|value| value.text.as_str()),
            Some("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
        );
        let projection =
            build_projection(&source, &CompareLimits::default()).expect("BOM-prefixed projection");
        assert_eq!(projection["byte_order_mark"], Value::Bool(true));
        assert_eq!(
            projection["xml_declaration"]["raw_xml_sha256"],
            Value::String(sha256(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"))
        );
    }

    #[test]
    fn semantic_projection_preserves_unknown_hashes_and_extensions() {
        let document = parse_jmx_semantic(
            fixture("jmx-aliases/unknown-plugin/plan.jmx"),
            &CompareLimits::default(),
        )
        .expect("original unknown-plugin fixture parses");
        let payloads = document.projection["opaque_payloads"]
            .as_array()
            .expect("opaque payloads");
        assert!(payloads.iter().any(|payload| {
            payload["wire_tag"] == Value::String("pluginExtension".into())
                && payload
                    .get("raw_xml_sha256")
                    .and_then(Value::as_str)
                    .is_some()
        }));
        let plugin = document.projection["ordered_hash_tree_pairs"]
            .as_array()
            .expect("topology pairs")
            .iter()
            .find(|pair| pair["element"]["tag"] == "PluginSampler")
            .expect("plugin pair");
        assert_eq!(
            plugin["element"]["ordered_children"],
            json!([
                "stringProp",
                "pluginProperty",
                "comment",
                "pluginExtension",
                "objProp",
                "elementProp"
            ])
        );
        assert!(
            plugin["element"]["extensions"]
                .as_array()
                .is_some_and(|values| { values.iter().any(|value| value["kind"] == "comment") })
        );
        assert!(
            document.projection["root"]["hash_tree_extensions"]
                .as_array()
                .is_some()
        );
        let diagnostics = document.projection["diagnostics"]
            .as_array()
            .expect("diagnostics");
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic["code"] == Value::String("jmx.semantic.unknown_element".into())
        }));
    }

    #[test]
    fn semantic_expectation_rejects_unknown_fields_and_order_changes() {
        let document =
            parse_jmx_semantic(fixture("jmx-topology/plan.jmx"), &CompareLimits::default())
                .expect("original topology fixture parses");
        let error = validate_jmx_expectation(
            &json!({"format": "jmx-semantic", "unsupported": true}),
            &CompareLimits::default(),
        )
        .expect_err("unsupported expectation field");
        assert_eq!(error.code(), ErrorCode::UnsupportedFormat);

        let mut expected = json!({
            "format": "jmx-semantic",
            "ordered_hash_tree_pairs": document.projection["ordered_hash_tree_pairs"].clone()
        });
        let pairs = expected["ordered_hash_tree_pairs"]
            .as_array_mut()
            .expect("pairs");
        pairs.swap(0, 1);
        let options = CompareOptions::default();
        let mut report = base_report(
            &ArtifactSummary {
                path: "actual".into(),
                format: CompareFormat::JmxSemantic,
                size_bytes: 0,
                event_count: 0,
            },
            &ArtifactSummary {
                path: "expected".into(),
                format: CompareFormat::JmxSemantic,
                size_bytes: 0,
                event_count: 0,
            },
            &options,
        );
        compare_declared_jmx(&document.projection, &expected, &options, &mut report);
        assert!(!report.equal, "topology order must remain observable");

        let mut duplicate = json!({
            "format": "jmx-semantic",
            "typed_properties": [document.projection["typed_properties"][0].clone()]
        });
        duplicate["typed_properties"]
            .as_array_mut()
            .expect("duplicate property array")
            .push(document.projection["typed_properties"][0].clone());
        let mut duplicate_report = base_report(
            &ArtifactSummary {
                path: "actual".into(),
                format: CompareFormat::JmxSemantic,
                size_bytes: 0,
                event_count: 0,
            },
            &ArtifactSummary {
                path: "expected".into(),
                format: CompareFormat::JmxSemantic,
                size_bytes: 0,
                event_count: 0,
            },
            &options,
        );
        compare_declared_jmx(
            &document.projection,
            &duplicate,
            &options,
            &mut duplicate_report,
        );
        assert!(
            !duplicate_report.equal,
            "duplicate property must not collapse"
        );
    }

    #[test]
    fn semantic_upgrade_expectation_compares_soap_alias_and_deleted_wire_values() {
        let actual = fixture("jmx-aliases/upgrades/plan.jmx");
        let expected = fixture("jmx-aliases/upgrades/expected/semantic.json");
        let report = compare_jmx_files(actual, expected, &CompareOptions::default())
            .expect("legacy upgrade comparator");
        assert!(report.equal, "{}", report.human_diff);
        assert_eq!(report.actual.path, "<actual-jmx>");
        assert_eq!(report.expected.path, "<expected-jmx-projection>");

        let document = parse_jmx_semantic(
            fixture("jmx-aliases/upgrades/plan.jmx"),
            &CompareLimits::default(),
        )
        .expect("legacy upgrade projection");
        let mut paths = BTreeSet::new();
        for property in document.projection["typed_properties"]
            .as_array()
            .expect("legacy typed properties")
        {
            let path = property["path"].as_str().expect("property path");
            assert!(paths.insert(path), "legacy property duplicated: {path}");
        }
    }

    #[test]
    fn semantic_no_drop_fixture_compares_all_declared_boundaries() {
        let report = compare_jmx_files(
            fixture("jmx-topology/no-drop-boundaries/plan.jmx"),
            fixture("jmx-topology/no-drop-boundaries/expected/semantic.json"),
            &CompareOptions::default(),
        )
        .expect("no-drop JMX comparator");
        // The original static descriptor intentionally contains two stale
        // wire claims: it hashes the nested recorded value instead of the
        // enclosing elementProp and attributes a sibling comment to the
        // pluginExtension.  A strict comparator must expose both rather than
        // normalize them away.
        assert!(!report.equal, "stale wire claims unexpectedly matched");
        assert!(
            report
                .structured_diff
                .iter()
                .any(|difference| { difference.path == "/typed_properties/33/raw_xml_sha256" })
        );
        assert!(
            report
                .structured_diff
                .iter()
                .any(|difference| difference.path == "/opaque_payloads/2/contains")
        );
    }

    #[test]
    fn semantic_per_element_property_bound_fails_closed() {
        let error = parse_jmx_semantic(
            fixture("jmx-aliases/aliases/plan.jmx"),
            &CompareLimits {
                max_properties_per_element: 1,
                ..CompareLimits::default()
            },
        )
        .expect_err("per-element property limit");
        assert_eq!(error.code(), ErrorCode::OutputLimit);
    }

    #[test]
    fn semantic_attribute_bound_is_aggregate_across_the_document() {
        let error = parse_jmx_semantic(
            fixture("jmx-aliases/aliases/plan.jmx"),
            &CompareLimits {
                max_attributes: 4,
                ..CompareLimits::default()
            },
        )
        .expect_err("aggregate XML attribute limit");
        assert_eq!(error.code(), ErrorCode::OutputLimit);
    }

    #[test]
    fn semantic_opaque_bound_counts_overlapping_subtrees_once() {
        let path = fixture("jmx-aliases/unknown-plugin/plan.jmx");
        let bytes = read_jmx_file(&path, CompareLimits::default().max_input_bytes)
            .expect("unknown-plugin input");
        let source = parse_source(bytes.clone(), &CompareLimits::default(), sha256(&bytes))
            .expect("unknown-plugin source");
        fn find_node<'a>(node: &'a XmlNode, name: &str) -> Option<&'a XmlNode> {
            if node.name == name {
                return Some(node);
            }
            node.events.iter().find_map(|event| match event {
                XmlEvent::Element(child) => find_node(child, name),
                XmlEvent::Comment { .. }
                | XmlEvent::ProcessingInstruction { .. }
                | XmlEvent::CData { .. } => None,
            })
        }
        let plugin = find_node(&source.root, "PluginSampler").expect("plugin sampler");
        let child = find_node(&source.root, "PluginChild").expect("plugin child");
        let limit = plugin
            .end
            .saturating_sub(plugin.start)
            .saturating_add(child.end.saturating_sub(child.start));
        let document = parse_jmx_semantic(
            path,
            &CompareLimits {
                max_opaque_bytes: limit,
                ..CompareLimits::default()
            },
        )
        .expect("nested opaque spans share one byte budget");
        assert!(document.projection["opaque_payloads"].as_array().is_some());
    }

    #[test]
    fn semantic_case_expectation_rejects_provenance_mismatch() {
        let profile_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../compat/profiles/jmeter-5.6.3.json");
        let profile = crate::ProfileManifest::load(profile_path).expect("active profile");
        let case = crate::CaseManifest::load(fixture("jmx-aliases/aliases/case.json"))
            .expect("aliases case");
        let validated = crate::ValidatedCase::new(profile, case, fixture("jmx-aliases/aliases"))
            .expect("validated aliases case");
        let error = validate_jmx_expectation_provenance(
            &json!({
                "format": "jmx-semantic",
                "case_id": "different-case"
            }),
            &validated,
        )
        .expect_err("mismatched case provenance");
        assert_eq!(error.code(), ErrorCode::ManifestMismatch);
    }

    #[test]
    fn semantic_limits_fail_closed_without_running_an_oracle() {
        let path = fixture("jmx-topology/plan.jmx");
        let error = parse_jmx_semantic(
            path,
            &CompareLimits {
                max_input_bytes: 16,
                ..CompareLimits::default()
            },
        )
        .expect_err("input byte limit");
        assert_eq!(error.code(), ErrorCode::OutputLimit);
        let error = parse_jmx_semantic(
            fixture("jmx-aliases/unknown-plugin/plan.jmx"),
            &CompareLimits {
                max_opaque_bytes: 1,
                ..CompareLimits::default()
            },
        )
        .expect_err("opaque byte limit");
        assert_eq!(error.code(), ErrorCode::OutputLimit);
    }
}
